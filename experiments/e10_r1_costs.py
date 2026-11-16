"""Journal r1: what the fixes of the second pre-submission review cost.

J2R runs on a synthetic stream (2048-bit keys by default). After the run, the same hunts are
issued under four verification settings and two epochs, and the alerts are investigated twice:

  hunts          aqrs_verify in {"real" (journal v2/v3: only the real member), "all" (r1: every
                 member alike, whole cohort rejected on any failure)} x acl_sample in {1, 0.1} x
                 epoch in {"current" (the EE's own ciphertexts), "historical" (epoch 1: records
                 fetched from the cloud with an MMR multiproof against the signed root)}.
                 Per hunt: EE verification time (all members), HE additions and hashes at the EE,
                 cohort size, records fetched.
  investigation  inv_cohort in {False (alerted entity only), True (r1: whole group per epoch)}.
                 Per alert: queries issued, records verified, records decrypted, provenance
                 fetched by reference, bytes cloud -> SA, wall time.

Usage:  python experiments/e10_r1_costs.py [--quick] [--seeds 3] [--bits 2048] [--hunts 20] [--workers 3]
Writes results/e10_r1_hunts.csv, e10_r1_inv.csv and e10_r1_costs.md.
"""

from __future__ import annotations

import argparse
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

from vista_siem.aqrs import Spec  # noqa: E402
from vista_siem.data.synth import default_profiles_and_contexts  # noqa: E402
from vista_siem.system import VistaSIEM  # noqa: E402

DATA = SynthConfig(epochs=4, events_per_epoch=600, n_users=100, n_low_and_slow=2, n_exfil=1, n_coordinated=1)
QUICK = replace(DATA, epochs=3, events_per_epoch=200, n_users=40)


def one_seed(seed: int, bits: int, n_hunts: int, quick: bool) -> tuple[list[dict], list[dict]]:
    sc = replace(QUICK if quick else DATA, seed=seed)
    events, _ = generate(sc)
    profiles, contexts = default_profiles_and_contexts()
    cfg = config("J2R", seed=seed, paillier_bits=bits)
    s = VistaSIEM(cfg, profiles, contexts)
    s.run(events)
    users = [u for u, _ in Counter(ev.user for ev in events).most_common(n_hunts)]
    hunts = []
    for verify in ("real", "all"):
        for f in (1.0, 0.1):
            s.ee.cfg = replace(cfg, aqrs_verify=verify, acl_sample=f)
            for mode, epoch in (("current", None), ("historical", 1)):
                for u in users:
                    n0, l0, fetched0 = len(s.ee.hunt_log), len(s.ee.acl_log), s.ee.stats["hist_records_fetched"]
                    s.ee.hunt([Spec("U", u, None)], epoch=epoch)
                    h = s.ee.hunt_log[n0]
                    logs = s.ee.acl_log[l0:]
                    hunts.append(dict(seed=seed, bits=bits, verify=verify, f=f, epoch=mode, k=len(h["members"]),
                                      ok=int(h["ok"]), verify_ms=1e3 * h["verify_seconds"],
                                      ee_he_adds=sum(x["he_adds"] for x in logs),
                                      ee_hashes=sum(x["hashes"] for x in logs),
                                      members_checked=len(logs), real_q=h["real_size"],
                                      cohort_q=h["retrieved"],
                                      fetched=s.ee.stats["hist_records_fetched"] - fetched0))
    s.ee.cfg = cfg
    invs = []
    alerts = [d for d in s.sa.alerts if d.attack]
    for d in alerts:
        for cohort in (False, True):
            s.sa.inv_cohort = cohort
            b0 = s.bus.total(src="cloud", dst="sa")
            t0 = time.perf_counter()
            inv = s.investigate(d)
            dt = time.perf_counter() - t0
            invs.append(dict(seed=seed, bits=bits, inv_cohort=int(cohort), window=len(inv.window),
                             queries=inv.group_queries, verified=inv.verified_records, decrypted=inv.decrypted,
                             own=inv.own_records, prov_by_ref=inv.prov_by_ref,
                             bytes_cloud_sa=s.bus.total(src="cloud", dst="sa") - b0, ms=1e3 * dt,
                             failed=len(inv.failed_epochs) + len(inv.index_failed_epochs),
                             identity_ok=int(inv.identity is not None)))
    s.close()
    return hunts, invs


def _med(xs):
    return statistics.median(xs) if xs else float("nan")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--seeds", type=int, default=3)
    ap.add_argument("--bits", type=int, default=2048)
    ap.add_argument("--hunts", type=int, default=20)
    ap.add_argument("--workers", type=int, default=3)
    a = ap.parse_args()
    seeds = list(range(1, (1 if a.quick else a.seeds) + 1))
    bits = 512 if a.quick else a.bits
    t0 = time.time()
    with ProcessPoolExecutor(max_workers=max(1, min(a.workers, len(seeds)))) as ex:
        res = list(ex.map(one_seed, seeds, [bits] * len(seeds), [a.hunts] * len(seeds), [a.quick] * len(seeds)))
    hunts = [r for h, _ in res for r in h]
    invs = [r for _, i in res for r in i]
    write_csv("e10_r1_hunts.csv", hunts)
    write_csv("e10_r1_inv.csv", invs)

    md = [f"# Journal r1: cost of the second-review fixes ({bits}-bit Paillier, seeds {seeds})\n",
          "## Hunts: EE verification per hunt (median over hunts and seeds)\n",
          "| Verify | f | Epoch | k | members checked | EE ms | EE HE adds | EE hashes | records fetched | all ok |",
          "|---|---|---|---|---|---|---|---|---|---|"]
    for verify in ("real", "all"):
        for f in (1.0, 0.1):
            for mode in ("current", "historical"):
                sel = [h for h in hunts if h["verify"] == verify and h["f"] == f and h["epoch"] == mode]
                if not sel:
                    continue
                md.append(f"| {verify} | {f} | {mode} | {_med([h['k'] for h in sel]):.0f} | "
                          f"{_med([h['members_checked'] for h in sel]):.0f} | {_med([h['verify_ms'] for h in sel]):.2f} | "
                          f"{_med([h['ee_he_adds'] for h in sel]):.0f} | {_med([h['ee_hashes'] for h in sel]):.0f} | "
                          f"{_med([h['fetched'] for h in sel]):.0f} | {all(h['ok'] for h in sel)} |")
    md += ["", "## Investigation per alert (median over alerts and seeds)\n",
           "| Scope | alerts | window | queries | verified | decrypted | prov. by ref | kB cloud->SA | ms | failures |",
           "|---|---|---|---|---|---|---|---|---|---|"]
    for c, name in ((0, "alerted entity only (v2/v3)"), (1, "whole group (r1)")):
        sel = [i for i in invs if i["inv_cohort"] == c]
        if not sel:
            continue
        md.append(f"| {name} | {len(sel)} | {_med([i['window'] for i in sel]):.0f} | {_med([i['queries'] for i in sel]):.0f} | "
                  f"{_med([i['verified'] for i in sel]):.0f} | {_med([i['decrypted'] for i in sel]):.0f} | "
                  f"{sum(i['prov_by_ref'] for i in sel)} total | {_med([i['bytes_cloud_sa'] for i in sel]) / 1e3:.1f} | "
                  f"{_med([i['ms'] for i in sel]):.1f} | {sum(i['failed'] for i in sel)} |")
    md.append(f"\nTotal time {time.time() - t0:.0f}s")
    (RESULTS / "e10_r1_costs.md").write_text("\n".join(md) + "\n")
    print("\n".join(md))


if __name__ == "__main__":
    main()
