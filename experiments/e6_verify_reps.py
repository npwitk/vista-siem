"""Journal v3, Exp 6 verification table with repetitions (TCC revision 1).

Reruns the measured part of e_baselines.py Part B (S multiproof, B7 EVSEB, B8 MK-Tree) for
r_tau in {10, 1000} records out of n_tau in {10^3, 10^4, 10^5}, with --reps independent draws
(seeds 1..reps), and reports median / IQR / mean. B9 and the priced 2025 baselines are cost
formulas, not timings, and are not rerun here.

    python experiments/e6_verify_reps.py --reps 10        -> e6_verify_reps.csv, e6_verify_reps.md
"""
from __future__ import annotations

import argparse
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import RESULTS, write_csv  # noqa: E402
from e_baselines import verification  # noqa: E402

SYSTEMS = ("S", "B7 EVSEB", "B8 MK-Tree")


def _iqr(xs: list[float]) -> float:
    if len(xs) < 2:
        return 0.0
    q = statistics.quantiles(xs, n=4)
    return q[2] - q[0]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=10)
    ap.add_argument("--quick", action="store_true")
    args = ap.parse_args()
    ns = [1_000, 10_000] if args.quick else [1_000, 10_000, 100_000]
    reps = 2 if args.quick else args.reps
    t0 = time.time()
    rows = []
    for n in ns:
        for k in (10, 1000):
            if k > n:
                continue
            for seed in range(1, reps + 1):
                for r in verification(n, k, seed, None):
                    rows.append(dict(r, seed=seed))
    write_csv("e6_verify_reps.csv", rows)
    md = [f"# Exp 6: verifying r_tau of n_tau records, {reps} repetitions (seeds 1..{reps})\n",
          "Cells: median ms [IQR] (mean). All verifications accepted: "
          f"{all(r['ok'] for r in rows)}.\n",
          "| n | r | " + " | ".join(f"{s} ms" for s in SYSTEMS) + " | S hashes |",
          "|---|---|" + "---|" * (len(SYSTEMS) + 1)]
    for n in ns:
        for k in (10, 1000):
            sel = [r for r in rows if r["n"] == n and r["k"] == k]
            if not sel:
                continue
            cells = []
            for s in SYSTEMS:
                xs = [r["verify_ms"] for r in sel if r["system"] == s]
                cells.append(f"{statistics.median(xs):.2f} [{_iqr(xs):.2f}] ({statistics.mean(xs):.2f})")
            hs = [r["hashes"] for r in sel if r["system"] == "S"]
            md.append(f"| {n:,} | {k:,} | " + " | ".join(cells) + f" | {statistics.median(hs):,.0f} |")
    md.append(f"\nTotal time {time.time() - t0:.0f}s")
    (RESULTS / "e6_verify_reps.md").write_text("\n".join(md) + "\n")


if __name__ == "__main__":
    main()
