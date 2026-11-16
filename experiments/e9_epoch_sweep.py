"""Journal v3: epoch length sweep, Delta_e in {300, 900, 3600} s: detection F1 and delay.

Synthetic part (always): per system and Delta_e, weights are learned and Theta calibrated on the
E1 development stream at that Delta_e, then frozen and tested on the E1 test streams (attacks
generated in hours and remapped to epochs, common.remap_truth). The benign alert budget is kept per
hour, not per (entity, epoch): target FPR x Delta_e / 3600, so a shorter epoch does not get more
false alerts per day. Reported per class: F1, recall, precision, detection delay in epochs and in
hours (delay x Delta_e / 3600), and threshold-free AUC.

AIT part (--ait): ait_eval.py --parts e1 --epoch-len Delta_e --tag dt<Delta_e> per value (output
files ait_dt<Delta_e>_*), then the same summary from its CSVs (real chains: F1 per class and delay;
injected low-and-slow: recall and delay in hours). --ait-args passes extra arguments through.

Usage:  python experiments/e9_epoch_sweep.py [--quick] [--seeds 5] [--workers 8] [--systems J2R,S]
                                             [--epochs 300,900,3600] [--ait] [--ait-args "..."]
Writes results/e9_epoch_sweep.csv and e9_epoch_sweep.md.
"""

from __future__ import annotations

import argparse
import csv
import shlex
import statistics
import subprocess
import sys
import time
from concurrent.futures import ProcessPoolExecutor
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import (  # noqa: E402
    RESULTS,
    calibrate,
    config,
    generate,
    learn_weights,
    remap_truth,
    run,
    score_alerts,
    vista_siem_alerts,
    vista_siem_scores,
    threshold_free,
    write_csv,
)
from e1_accuracy import CLASSES, DEV, TARGET_FPR, TEST  # noqa: E402


def prepare(system: str, dt: float):
    cfg = config(system, epoch_len=dt)
    return calibrate(cfg, DEV, TARGET_FPR * dt / 3600.0, profiles=learn_weights(cfg, DEV))


def evaluate(system: str, dt: float, profiles, seed: int) -> list[dict]:
    cfg = config(system, epoch_len=dt, seed=seed)
    sc = replace(TEST, seed=seed)
    events, truth = generate(sc)
    truth = remap_truth(truth, sc.epoch_len, cfg.epoch_len)
    s = run(cfg, events, profiles)
    alerts, _ = vista_siem_alerts(s)
    scores, _ = score_alerts(alerts, truth, CLASSES)
    tf = threshold_free(vista_siem_scores(s), truth, CLASSES)
    return [dict(source="synthetic", system=system, epoch_len=dt, seed=seed, attack_class=c, incidents=x.incidents,
                 detected=x.detected, precision=x.precision, recall=x.recall, f1=x.f1, delay=x.mean_delay,
                 delay_h=None if x.mean_delay is None else x.mean_delay * dt / 3600.0, auc=tf[c]["auc"])
            for c, x in scores.items()]


def _f(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


def _mean(xs):
    xs = [x for x in xs if x is not None and x == x]
    return statistics.mean(xs) if xs else None


def _cell(x, fmt="{:.2f}"):
    return "-" if x is None else fmt.format(x)


def ait_part(dts, systems, quick: bool, extra: str) -> list[dict]:
    rows = []
    for dt in dts:
        tag = f"dt{int(dt)}"
        cmd = [sys.executable, str(Path(__file__).parent / "ait_eval.py"), "--parts", "e1", "--epoch-len", str(dt),
               "--tag", tag, "--systems", ",".join(systems), "--rules", ""] + (["--quick"] if quick else [])
        cmd += shlex.split(extra)
        print("  " + " ".join(cmd), flush=True)
        subprocess.run(cmd, check=True)
        with (RESULTS / f"ait_{tag}_e1_main.csv").open() as f:
            for r in csv.DictReader(f):
                rows.append(dict(source="ait-chains", system=r["system"], epoch_len=dt, seed=r["scenario"],
                                 attack_class=r["attack_class"], incidents=int(r["incidents"]),
                                 detected=int(r["detected"]), precision=_f(r["precision"]), recall=_f(r["recall"]),
                                 f1=_f(r["f1"]), delay=_f(r["delay"]), delay_h=_f(r.get("delay_h")), auc=_f(r["auc"])))
        p = RESULTS / f"ait_{tag}_e1_inject.csv"
        if p.exists():
            with p.open() as f:
                for r in csv.DictReader(f):
                    rows.append(dict(source="ait-inject", system=r["system"], epoch_len=dt, seed=r["seed"],
                                     attack_class=f"{r['family']} r={r['rate']}/h span={r['span']}h",
                                     recall=_f(r["recall"]), delay=_f(r["delay"]), delay_h=_f(r.get("delay_h")),
                                     false_entities=_f(r["false_entities"]), recall_at_fp2=_f(r["recall_at_fp2"])))
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--seeds", type=int, default=5)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--systems", default="J2R,S")
    ap.add_argument("--epochs", default="300,900,3600", help="Delta_e values in seconds (multiples of 300)")
    ap.add_argument("--ait", action="store_true", help="also run ait_eval.py --parts e1 per Delta_e")
    ap.add_argument("--ait-args", default="", help="extra arguments for ait_eval.py")
    a = ap.parse_args()
    systems = a.systems.split(",")
    dts = [float(x) for x in a.epochs.split(",")]
    seeds = list(range(1, (2 if a.quick else a.seeds) + 1))
    t0 = time.time()
    keys = [(sy, dt) for sy in systems for dt in dts]
    with ProcessPoolExecutor(a.workers) as ex:
        params = dict(zip(keys, ex.map(prepare, *zip(*keys))))
        jobs = [(sy, dt, params[(sy, dt)], sd) for sy, dt in keys for sd in seeds]
        rows = [r for rs in ex.map(evaluate, *zip(*jobs)) for r in rs]
    print(f"synthetic done in {time.time() - t0:.0f}s", flush=True)
    if a.ait:
        rows += ait_part(dts, systems, a.quick, a.ait_args)
    write_csv("e9_epoch_sweep.csv", rows)

    md = ["# Journal v3: epoch length sweep", "",
          f"Systems {', '.join(systems)}; Delta_e in {', '.join(f'{d:.0f}' for d in dts)} s. Synthetic: {len(seeds)} "
          "test seeds, alert budget per hour held constant. Delay = first alert epoch - first attack epoch, "
          "in hours.", ""]
    for src, title in (("synthetic", "Synthetic (E1 test streams)"), ("ait-chains", "AIT-LDSv2 real chains"),
                       ("ait-inject", "AIT-LDSv2 injected low-and-slow")):
        sel = [r for r in rows if r["source"] == src]
        if not sel:
            continue
        classes = list(dict.fromkeys(r["attack_class"] for r in sel))
        metric = ("recall", "recall") if src == "ait-inject" else ("f1", "F1")
        md += [f"## {title}: {metric[1]} / delay (h)", "",
               "| System | Delta_e (s) | " + " | ".join(classes) + (" | macro F1 |" if src != "ait-inject" else " |"),
               "|---|---|" + "---|" * (len(classes) + (src != "ait-inject"))]
        for sy in systems:
            for dt in dts:
                cells, f1s = [], []
                for c in classes:
                    rs = [r for r in sel if r["system"] == sy and r["epoch_len"] == dt and r["attack_class"] == c]
                    m = _mean([r[metric[0]] for r in rs])
                    f1s.append(m)
                    cells.append(f"{_cell(m)} / {_cell(_mean([r['delay_h'] for r in rs]))}")
                macro = f" | {_cell(_mean(f1s))}" if src != "ait-inject" else ""
                md.append(f"| {sy} | {dt:.0f} | " + " | ".join(cells) + macro + " |")
        md.append("")
    md.append(f"Total time {time.time() - t0:.0f}s")
    (RESULTS / "e9_epoch_sweep.md").write_text("\n".join(md) + "\n")
    print("\n".join(md))


if __name__ == "__main__":
    main()
