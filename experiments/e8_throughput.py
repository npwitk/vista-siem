"""Journal v3: sustained EE ingest throughput at 2048-bit Paillier, and the per-event cost.

Part A  unit costs (median of --iters): Paillier randomizer r^N mod N^2 (the offline part of an
        encryption), the online part with a precomputed randomizer, a full encryption, AES-GCM of a
        payload, a PRF token, a hash.
Part B  sustained ingest: N worker processes in {1, 2, 4, 8} (capped at the core count), each an
        independent EE shard running Phases 1-2 of the real pipeline (tokens, AES-GCM, HE features
        and realness indicator, decoy padding, MMR, index root, checkpoint) on its own synthetic
        stream of --events events. All workers start together (barrier); throughput = real events
        of all workers / wall time from the common start to the last finish.
          online   randomizers precomputed before the start (the offline pool is full)
          online+offline   randomizers computed inside the timed region (in-process, one core
                   per worker): what a deployment without spare offline time sustains
        Note: the in-process Cloud SIEM stores each record inside the EE loop, so the timed region
        includes the cloud's dict inserts (a few microseconds per record).
Part C  per-real-event cost of J2R (k = 5) with offline work, one core:
          measured  (t_online + t_offline) / real events from Part B at N = 1
          derived   HE encryptions per real event (3 (1 + delta): two features plus realness, for
                    every real and decoy record) x full-encryption time + symmetric work, which is
                    how the paper's 50.7 ms was computed (D31: 5.10 HE enc x 9.93 ms on m7i.2xlarge).
                    delta is measured here on the synthetic stream; the AIT-LDSv2 delta of J2R
                    (1.69, D30) is shown too, since it is larger.
        and the cores needed for 10^4 events/s = 10^4 / (per-core sustained events/s).

Usage:  python experiments/e8_throughput.py [--quick] [--bits 2048] [--events 1500] [--workers 1,2,4,8]
                                            [--systems J2R,S] [--iters 50]
Writes results/e8_throughput.csv, e8_units.csv and e8_throughput.md.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import multiprocessing as mp
import os
import platform
import statistics
import sys
import time
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import RESULTS, SynthConfig, config, generate, write_csv  # noqa: E402

# one epoch; brute-force and coordinated attacks need >= 2 epochs in the generator, so they are off
DATA = SynthConfig(epochs=1, events_per_epoch=1500, n_users=200, n_brute_force=0, n_low_and_slow=2, n_exfil=1,
                   n_coordinated=0)
AIT_DELTA_J2R = 1.69  # D30: decoys per real record of J2R on AIT-LDSv2 (k = 5)
TARGET = 10_000       # events per second


def units(bits: int, iters: int) -> dict[str, float]:
    import gmpy2
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    from vista_siem.crypto import paillier

    pk, _ = paillier.keygen(bits)
    he = paillier.Paillier(pk)

    def med(fn, n):
        xs = []
        for _ in range(n):
            t0 = time.perf_counter()
            fn()
            xs.append(time.perf_counter() - t0)
        return statistics.median(xs) * 1e6

    rn = he._randomizer()
    n, n2 = pk.n, pk.n2
    u = dict(randomizer_us=med(he._randomizer, iters),
             enc_online_us=med(lambda: (1 + gmpy2.mpz(12345) % n * n) * rn % n2, iters * 20))
    u["enc_full_us"] = u["randomizer_us"] + u["enc_online_us"]
    key = AESGCM(AESGCM.generate_key(256))
    payload = os.urandom(120)
    u["aes_payload_us"] = med(lambda: key.encrypt(os.urandom(12), payload, b"ad"), iters * 20)
    kk, blob = os.urandom(32), os.urandom(64)
    u["prf_us"] = med(lambda: hmac.new(kk, blob, "sha256").digest(), iters * 20)
    u["hash_us"] = med(lambda: hashlib.sha256(blob).digest(), iters * 20)
    return u


def _worker(system: str, bits: int, sc: SynthConfig, seed: int, mode: str, barrier, out) -> None:
    try:
        _work(system, bits, sc, seed, mode, barrier, out)
    except BaseException as exc:  # report instead of leaving the parent waiting
        barrier.abort()
        out.put(dict(error=repr(exc)))
        raise


def _work(system: str, bits: int, sc: SynthConfig, seed: int, mode: str, barrier, out) -> None:
    from vista_siem.data.synth import default_profiles_and_contexts
    from vista_siem.system import VistaSIEM

    events, _ = generate(replace(sc, seed=seed))
    profiles, contexts = default_profiles_and_contexts()
    s = VistaSIEM(config(system, paillier_bits=bits, seed=seed, precompute_workers=1), profiles, contexts)
    if mode == "online":  # fill the pool generously (untimed): every record of the epoch, padding included
        s.ee.precompute(len(events) * 3 * 4)
        s.ee.stats["t_offline"] = 0.0
    try:
        barrier.wait()
    except Exception:  # another worker failed and aborted the barrier
        out.put(dict(error="barrier aborted"))
        return
    t0 = time.time()
    s.ee.start_epoch(1)
    for ev in events:
        s.ee.ingest(ev)
    s.ee.end_epoch()
    t1 = time.time()
    st = s.ee.stats
    out.put(dict(start=t0, end=t1, real=st["real"], decoy=st["decoy"], he_enc=st["he_enc"],
                 t_online=st["t_online"], t_offline=st["t_offline"], t_index=st["t_index"],
                 online_randomizers=s.ee.he.online_randomizers))
    s.close()


def sustained(system: str, bits: int, sc: SynthConfig, n_workers: int, mode: str) -> dict:
    ctx = mp.get_context("spawn")
    barrier, out = ctx.Barrier(n_workers), ctx.Queue()
    procs = [ctx.Process(target=_worker, args=(system, bits, sc, 100 + i, mode, barrier, out)) for i in range(n_workers)]
    for p in procs:
        p.start()
    res = [out.get() for _ in procs]
    for p in procs:
        p.join()
    errs = [r["error"] for r in res if "error" in r]
    if errs:
        raise RuntimeError(f"worker failed: {errs[0]}")
    wall = max(r["end"] for r in res) - min(r["start"] for r in res)
    real = sum(r["real"] for r in res)
    busy = sum(r["end"] - r["start"] for r in res)
    return dict(system=system, mode=mode, workers=n_workers, bits=bits, real_events=real,
                decoys=sum(r["decoy"] for r in res), delta=sum(r["decoy"] for r in res) / real,
                he_enc_per_real=sum(r["he_enc"] for r in res) / real, wall_s=wall,
                events_per_s=real / wall, events_per_s_per_worker=real / wall / n_workers,
                ms_per_real_event_core=1e3 * busy / real,
                t_online_s=sum(r["t_online"] for r in res), t_offline_s=sum(r["t_offline"] for r in res),
                online_randomizers=sum(r["online_randomizers"] for r in res))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--bits", type=int, default=2048)
    ap.add_argument("--events", type=int, default=1500, help="events per worker")
    ap.add_argument("--workers", default="1,2,4,8")
    ap.add_argument("--systems", default="J2R,S")
    ap.add_argument("--iters", type=int, default=50)
    a = ap.parse_args()
    if a.quick:
        a.events, a.iters = 150, 10
    cores = os.cpu_count() or 1
    ws = [w for w in (int(x) for x in a.workers.split(",")) if w <= cores]
    sc = replace(DATA, events_per_epoch=a.events, n_users=max(40, min(200, a.events // 8)))
    t0 = time.time()
    u = units(a.bits, a.iters)
    write_csv("e8_units.csv", [dict(unit=k, us=v) for k, v in u.items()])
    print(u, flush=True)
    rows = []
    for system in a.systems.split(","):
        for mode in ("online", "online+offline"):
            for w in ws:
                rows.append(sustained(system, a.bits, sc, w, mode))
                print(rows[-1], flush=True)
    write_csv("e8_throughput.csv", rows)

    md = [f"# Journal v3: EE ingest throughput ({platform.node()}, {platform.platform()}, {cores} cores)", "",
          f"Paillier {a.bits} bits; {a.events} synthetic events per worker (one epoch, its own EE shard and keys).", "",
          "## A. Unit costs (median)", "", "| Unit | µs |", "|---|---|"]
    md += [f"| {k[:-3]} | {v:,.2f} |" for k, v in u.items()]
    md += ["", "## B. Sustained ingest (real events per second, all workers)", "",
           "| System | Mode | Workers | δ | HE enc / real event | events/s | events/s per worker | core-ms / real event |",
           "|---|---|---|---|---|---|---|---|"]
    md += [f"| {r['system']} | {r['mode']} | {r['workers']} | {r['delta']:.2f} | {r['he_enc_per_real']:.2f} | "
           f"{r['events_per_s']:,.1f} | {r['events_per_s_per_worker']:,.1f} | {r['ms_per_real_event_core']:,.2f} |"
           for r in rows]
    md += ["", "## C. Per-real-event cost of the EE with offline work (one core) and cores for 10^4 events/s", "",
           "| System | δ | HE enc / real | measured ms / real event (N = 1) | derived ms (enc x full enc + symmetric) | "
           "cores for 10^4 ev/s (online+offline) |", "|---|---|---|---|---|---|"]
    sym_ms = (u["aes_payload_us"] + 4 * u["prf_us"] + 3 * u["hash_us"]) / 1e3
    for system in a.systems.split(","):
        one = next((r for r in rows if r["system"] == system and r["mode"] == "online+offline" and r["workers"] == 1), None)
        full = [r for r in rows if r["system"] == system and r["mode"] == "online+offline"]
        if not one:
            continue
        derived = one["he_enc_per_real"] * u["enc_full_us"] / 1e3 + sym_ms
        top = max(full, key=lambda r: r["workers"])  # per-core rate under the most parallel load measured
        md.append(f"| {system} | {one['delta']:.2f} | {one['he_enc_per_real']:.2f} | {one['ms_per_real_event_core']:.2f} | "
                  f"{derived:.2f} | {TARGET / one['events_per_s_per_worker']:,.0f} at the N = 1 rate, "
                  f"{TARGET / top['events_per_s_per_worker']:,.0f} at the N = {top['workers']} rate |")
    he_ait = 3 * (1 + AIT_DELTA_J2R)
    md += ["", f"Derivation of the paper's figure: (HE encryptions per real event) x (full 2048-bit encryption) + "
           f"symmetric work. Here a full encryption costs {u['enc_full_us'] / 1e3:.2f} ms "
           f"({u['randomizer_us'] / 1e3:.2f} ms randomizer + {u['enc_online_us']:.1f} µs online) and the symmetric "
           f"work {sym_ms * 1e3:.1f} µs. D31 used 5.10 HE enc x 9.93 ms (m7i.2xlarge) = 50.7 ms. With the AIT-LDSv2 "
           f"delta of J2R ({AIT_DELTA_J2R}), {he_ait:.2f} HE enc per real event give "
           f"{he_ait * u['enc_full_us'] / 1e3 + sym_ms:.1f} ms on this machine "
           f"({he_ait * 9.93:.1f} ms at the m7i unit cost).",
           "Without offline work (randomizers precomputed on spare cores or ahead of time) the online part is "
           f"{u['enc_online_us']:.1f} µs per encryption; see the online rows of Part B.",
           f"\nTotal time {time.time() - t0:.0f}s"]
    (RESULTS / "e8_throughput.md").write_text("\n".join(md) + "\n")
    print("\n".join(md))


if __name__ == "__main__":
    main()
