"""Journal v3: how the work and the storage split between the EE and the Cloud SIEM.

J2R (ACL + D29 cohorts and padding + D30) runs on a synthetic stream, optionally with the e3_aqrs
hunting workload, one epoch at a time. Per epoch we record

  EE time      online (tokens, AES-GCM, HE encryption with precomputed randomizers, MMR),
               offline (Paillier randomizers, one in-process core: precompute_workers = 1),
               index (R^IDX and checkpoint), ACL verify (Phase 3, alg:acl incl. hunts),
               graph verify (Phase 4 C_G check), scoring (rest of Phase 5)
  cloud time   store (record and EPII insert), retrieve (authenticated EPII lookup, candidate sets,
               index multiproofs), aggregate (SG-HEF HE additions), commit (C_chi, C_Q, C_A),
               graph (Phase 4 contraction and C_G)
  EE memory    serialized size of what the EE must keep at the end of the epoch (the epoch's
               HE ciphertexts and index entries for ACL, D23; MMR peaks; trusted history state;
               screening sketches), and the process peak RSS (EE + cloud + KA simulated in one
               process, so an upper bound)
  storage      bytes the EE retains for one epoch vs the bytes the cloud stores (cumulative)

All times are wall-clock seconds of single-threaded code (one core). Serialized sizes use the
bus's size model (ciphertext = |N^2| bytes).

Usage:  python experiments/e7_split.py [--quick] [--seeds 3] [--bits 2048] [--no-hunts] [--workers 3]
Writes results/e7_split.csv and e7_split.md.
"""

from __future__ import annotations

import argparse
import resource
import statistics
import sys
import time
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import RESULTS, SynthConfig, config, generate, write_csv  # noqa: E402

from vista_siem.bus import size_of  # noqa: E402
from vista_siem.data.synth import default_profiles_and_contexts  # noqa: E402
from vista_siem.system import VistaSIEM  # noqa: E402

DATA = SynthConfig(epochs=8, events_per_epoch=1500, n_users=200, n_low_and_slow=2, n_exfil=1, n_coordinated=1)
QUICK = replace(DATA, epochs=3, events_per_epoch=200, n_users=60)
EE_KEYS = ("ee_online", "ee_offline", "ee_index", "ee_acl_verify", "ee_graph_verify", "ee_scoring")
CLOUD_KEYS = ("cloud_store", "cloud_retrieve", "cloud_aggregate", "cloud_commit", "cloud_graph")


def _timed(obj, name: str, acc: Counter, key: str) -> None:
    fn = getattr(obj, name)

    def wrapped(*a, **kw):
        t0 = time.perf_counter()
        try:
            return fn(*a, **kw)
        finally:
            acc[key] += time.perf_counter() - t0

    setattr(obj, name, wrapped)


def ee_retained_bytes(s: VistaSIEM) -> dict:
    ee, ct = s.ee, s.bus.ct_bytes
    out = dict(ee_ct_bytes=size_of(ee.epoch_X, ct), ee_entries_bytes=size_of(ee.epoch_entries, ct),
               ee_mmr_bytes=32 * len(ee.mmr.peaks()),  # peaks suffice to append and to sign the root
               ee_state_bytes=sum(size_of(st.h) + 8 + 32 + 16 * len(st.prov) for st in ee.state.values()),
               ee_sketch_bytes=ee.cms_cur.table.nbytes + ee.cms_base.table.nbytes)
    out["ee_retained_bytes"] = sum(out.values())
    return out


def trial(seed: int, bits: int, sc: SynthConfig, hunts: bool) -> list[dict]:
    from e3_aqrs import workload

    events, truth = generate(replace(sc, seed=seed))
    profiles, contexts = default_profiles_and_contexts()
    s = VistaSIEM(config("J2R", paillier_bits=bits, seed=seed, precompute_workers=1), profiles, contexts)
    if hunts:
        wl = workload(events, truth, s.cfg.epoch_len, seed)
        s.hunter = lambda e: wl.get(e, [])
    cl = Counter()
    _timed(s.cloud, "receive_record", cl, "cloud_store")
    _timed(s.cloud, "auth_candidates", cl, "cloud_retrieve")
    _timed(s.cloud, "aggregate", cl, "cloud_aggregate")
    _timed(s.cloud, "acl_request", cl, "_acl_request")
    _timed(s.cloud, "contract", cl, "cloud_graph")
    by_epoch: dict[int, list] = {}
    for ev in events:
        by_epoch.setdefault(s.epoch_of(ev.ts), []).append(ev)
    rows, cum_cloud = [], 0
    for e in sorted(by_epoch):
        st0, tm0, cl0 = Counter(s.ee.stats), Counter(s.timing), Counter(cl)
        n_log = len(s.ee.acl_log)
        rec0 = s.ee.stats["real"] + s.ee.stats["decoy"]
        b0 = s.bus.total("ee", "cloud")
        s.run_epoch(e, by_epoch[e])
        st, tm = s.ee.stats, s.timing
        new = s.ee.acl_log[n_log:]
        d = {k: cl[k] - cl0[k] for k in cl}
        acl3 = sum(r["seconds"] for r in new if r["kind"] == "phase3")
        acl4 = sum(r["seconds"] for r in new if r["kind"] == "phase4")
        row = dict(seed=seed, epoch=e, bits=bits, hunts=int(hunts), events=len(by_epoch[e]),
                   records=st["real"] + st["decoy"] - rec0, decoys=st["decoy"] - st0["decoy"],
                   ee_online=st["t_online"] - st0["t_online"], ee_offline=st["t_offline"] - st0["t_offline"],
                   ee_index=st["t_index"] - st0["t_index"], ee_acl_verify=acl3, ee_graph_verify=acl4,
                   ee_scoring=max(0.0, tm["phase5"] - tm0["phase5"] - acl4),
                   cloud_store=d.get("cloud_store", 0.0), cloud_retrieve=d.get("cloud_retrieve", 0.0),
                   cloud_aggregate=d.get("cloud_aggregate", 0.0),
                   cloud_commit=max(0.0, d.get("_acl_request", 0.0) - d.get("cloud_retrieve", 0.0)
                                    - d.get("cloud_aggregate", 0.0)),
                   cloud_graph=d.get("cloud_graph", 0.0))
        row["ee_total"] = sum(row[k] for k in EE_KEYS)
        row["cloud_total"] = sum(row[k] for k in CLOUD_KEYS)
        cum_cloud += s.bus.total("ee", "cloud") - b0
        row.update(ee_retained_bytes(s))
        row["cloud_stored_bytes_cum"] = cum_cloud
        row["cloud_stored_bytes_epoch"] = s.bus.total("ee", "cloud") - b0
        row["peak_rss_mb"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / (1 << 20 if sys.platform == "darwin" else 1 << 10)
        rows.append(row)
        print(f"  seed {seed} epoch {e}: EE {row['ee_total']:.2f}s cloud {row['cloud_total']:.2f}s", flush=True)
    s.close()
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--seeds", type=int, default=3)
    ap.add_argument("--bits", type=int, default=2048)
    ap.add_argument("--no-hunts", action="store_true", help="without the e3_aqrs hunting workload")
    ap.add_argument("--workers", type=int, default=3)
    a = ap.parse_args()
    sc = QUICK if a.quick else DATA
    seeds = list(range(1, (min(a.seeds, 1) if a.quick else a.seeds) + 1))
    t0 = time.time()
    with ProcessPoolExecutor(a.workers) as ex:
        rows = [r for rs in ex.map(trial, seeds, [a.bits] * len(seeds), [sc] * len(seeds),
                                   [not a.no_hunts] * len(seeds)) for r in rs]
    write_csv("e7_split.csv", rows)

    def m(k, sel=rows):
        return statistics.mean(r[k] for r in sel)

    real = m("events")
    md = ["# Journal v3: EE / cloud resource split (J2R, synthetic)", "",
          f"{len(seeds)} seed(s), {sc.epochs} epochs x {sc.events_per_epoch} events, {sc.n_users} users, "
          f"Paillier {a.bits} bits, hunting workload {'off' if a.no_hunts else 'on (e3_aqrs)'}; "
          f"decoys per real event {m('decoys') / real:.2f}. Mean per epoch; single-core wall seconds.", "",
          "| Party | Component | s / epoch | ms / real event | share of party |", "|---|---|---|---|---|"]
    for party, keys, tot in (("EE", EE_KEYS, "ee_total"), ("Cloud", CLOUD_KEYS, "cloud_total")):
        T = m(tot)
        for k in keys:
            md.append(f"| {party} | {k.split('_', 1)[1]} | {m(k):.3f} | {1e3 * m(k) / real:.3f} | "
                      f"{m(k) / T if T else 0:.1%} |")
        md.append(f"| {party} | **total** | **{T:.3f}** | **{1e3 * T / real:.3f}** | |")
    last = [r for r in rows if r["epoch"] == max(x["epoch"] for x in rows)]
    md += ["", "| Storage / memory | value |", "|---|---|",
           f"| EE retained at epoch end (mean / max over epochs) | {m('ee_retained_bytes') / 1e6:.2f} / "
           f"{max(r['ee_retained_bytes'] for r in rows) / 1e6:.2f} MB |",
           f"| of which epoch HE ciphertexts (D23) | {m('ee_ct_bytes') / 1e6:.2f} MB |",
           f"| of which epoch index entries | {m('ee_entries_bytes') / 1e6:.2f} MB |",
           f"| of which trusted history state | {m('ee_state_bytes') / 1e3:.1f} kB |",
           f"| Cloud stored, one epoch (mean) | {m('cloud_stored_bytes_epoch') / 1e6:.2f} MB |",
           f"| Cloud stored, cumulative after {last[0]['epoch']} epochs | {m('cloud_stored_bytes_cum', last) / 1e6:.2f} MB |",
           f"| Process peak RSS (EE + cloud + KA in one process; upper bound) | {max(r['peak_rss_mb'] for r in rows):,.0f} MB |",
           "", f"EE share of total compute: {m('ee_total') / (m('ee_total') + m('cloud_total')):.1%} "
           f"(offline randomizers are {m('ee_offline') / m('ee_total'):.1%} of the EE's time).",
           f"\nTotal time {time.time() - t0:.0f}s"]
    (RESULTS / "e7_split.md").write_text("\n".join(md) + "\n")
    print("\n".join(md))


if __name__ == "__main__":
    main()
