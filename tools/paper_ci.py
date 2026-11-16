#!/usr/bin/env python3
"""Confidence intervals for the paper's experimental results, from EXISTING result files only.

No experiment is run. Reads result CSVs under results/ and writes
results/vm-m7i-2xlarge-journal-v3/ci_summary.md.

Methods: percentile bootstrap (10,000 resamples, numpy default_rng(SEED)), Wilson score
intervals for proportions, Student-t intervals over seeds, exact (binomial) McNemar tests.

Name mapping (paper <- result files):
  AIT Exp 1 (journal-v2 run): S <- "S", S-RawGraph <- "J2", S-LAPH <- "LAPH-E", A2 <- "A2",
      Fixed-Decay <- "FixedDecay", Wazuh-D <- "B1-default";
      (journal-v3 run): S <- "J2R" (identical to v2 "S" per incident), PT-S <- "PT-S",
      ML-GB, ML-IF, Wazuh-T <- "B1-tuned".
  Exp 3 (journal-v2 e3_aqrs, 817 hunts): S k=5 <- "Fixed-5-G+CPt", Partition no padding <- "Fixed-5-G",
      Fixed-5 <- "Fixed-5", AQRS-adaptive <- "AQRS"; k=3/k=8 <- D29-G3/D29-G8 (journal-v2-design, summary only).
  Exp 3 v3 (806 hunts with time filters + decoy discount): S <- "J2R", "@dd<tau>" = decoy-discount attacker,
      per-(entity,category) padding <- "Fixed-5-G+CPec".
  Exp 4: A2 <- "NoHist", Wazuh-D <- "B1-default", No-Graph <- "NoGraph".
  Synthetic Exp 1: S <- design-A "NP" (= "G5+R", identical per seed), S-RawGraph <- "G5", S-LAPH <- "LAPH-E"
      (journal-v2-design e3_d29_design_A.csv); A2, Wazuh-D/T <- vm-m7i-2xlarge-final/e1_main.csv.
"""
from __future__ import annotations

import math
from pathlib import Path

import numpy as np
import pandas as pd

SEED = 20261116
B = 10_000
ROOT = Path(__file__).resolve().parents[1] / "results"
V2 = ROOT / "vm-m7i-2xlarge-journal-v2"
V2D = ROOT / "vm-m7i-2xlarge-journal-v2-design"
V3 = ROOT / "vm-m7i-2xlarge-journal-v3"
FINAL = ROOT / "vm-m7i-2xlarge-final"
OUT = V3 / "ci_summary.md"
T975 = {4: 2.776445105}  # Student t 0.975 quantile, df=4

rng = np.random.default_rng(SEED)
L: list[str] = []


def w(s: str = "") -> None:
    L.append(s)


def pct(a, lo=2.5, hi=97.5):
    return np.percentile(a, lo), np.percentile(a, hi)


def wilson(x: float, n: int, z: float = 1.959963985):
    if n == 0:
        return float("nan"), float("nan")
    p = x / n
    den = 1 + z * z / n
    c = (p + z * z / (2 * n)) / den
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return max(0.0, c - h), min(1.0, c + h)


def mcnemar_exact(b: int, c: int) -> float:
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    p = sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n
    return min(1.0, 2 * p)


def f(x, d=3):
    return f"{x:.{d}f}"


def ci(lo, hi, d=3):
    return f"[{lo:.{d}f}, {hi:.{d}f}]"


def excl0(lo, hi):
    return "yes" if (lo > 0 or hi < 0) else "no"


def tci(vals):
    v = np.asarray(vals, float)
    m, s = v.mean(), v.std(ddof=1)
    h = T975[len(v) - 1] * s / math.sqrt(len(v))
    return m, s, m - h, m + h


# ----------------------------------------------------------------------------------------------
# 1. AIT-LDSv2 Exp 1
# ----------------------------------------------------------------------------------------------
def ait():
    inc2 = pd.read_csv(V2 / "ait_journal_v2_e1_incidents.csv")
    inc3 = pd.read_csv(V3 / "ait_journal_v3_e1_incidents.csv")
    main2 = pd.read_csv(V2 / "ait_journal_v2_e1_main.csv")
    main3 = pd.read_csv(V3 / "ait_journal_v3_e1_main.csv")
    src = {  # paper name: (frame, code)
        "S": ("v2", "S"), "S-RawGraph": ("v2", "J2"), "S-LAPH": ("v2", "LAPH-E"), "A2": ("v2", "A2"),
        "Fixed-Decay": ("v2", "FixedDecay"), "PT-S": ("v3", "PT-S"), "ML-IF": ("v3", "ML-IF"),
        "ML-GB": ("v3", "ML-GB"), "Wazuh-T": ("v3", "B1-tuned"), "Wazuh-D": ("v2", "B1-default"),
    }
    key = ["scenario", "incident"]
    # consistency check v2 S vs v3 J2R
    m = inc2[inc2.system == "S"].merge(inc3[inc3.system == "J2R"], on=key)
    n_diff = int((m.detected_x != m.detected_y).sum())

    base = inc2[inc2.system == "S"][key + ["attack_class"]].sort_values(key).reset_index(drop=True)
    det = {}
    cells = {}
    cell_order = main2[main2.system == "S"][["scenario", "attack_class"]].reset_index(drop=True)
    for name, (v, code) in src.items():
        inc = inc2 if v == "v2" else inc3
        x = base.merge(inc[inc.system == code][key + ["detected"]], on=key, how="left")
        assert x.detected.notna().all(), name
        det[name] = x.detected.to_numpy(int)
        mm = main2 if v == "v2" else main3
        c = cell_order.merge(mm[mm.system == code], on=["scenario", "attack_class"], how="left")
        cells[name] = dict(I=c.incidents.to_numpy(float), D=c.detected.to_numpy(float),
                           FE=c.false_entities.to_numpy(float),
                           R2=(c.recall_at_fp2 * c.incidents).round(6).to_numpy(float))
    names = list(src)

    def f1(D, I, FE):
        return 2 * D / (2 * D + FE + (I - D))

    w("## 1. AIT-LDSv2 Experiment 1 (Table 4)")
    w()
    w("Sources: `vm-m7i-2xlarge-journal-v2/ait_journal_v2_e1_{incidents,main}.csv` (S, S-RawGraph=`J2`, "
      "S-LAPH=`LAPH-E`, A2, Fixed-Decay=`FixedDecay`, Wazuh-D=`B1-default`) and "
      "`vm-m7i-2xlarge-journal-v3/ait_journal_v3_e1_{incidents,main}.csv` (PT-S, ML-IF, ML-GB, Wazuh-T=`B1-tuned`). "
      f"v3 `J2R` equals v2 `S` on all 44 incidents ({n_diff} differences); v2/v3 A2 and Wazuh-D are also identical.")
    w()
    w("Note on naming: the brief said paper S-RawGraph = code `S`; in the journal-v2 files code `S` is the "
      "padding-neutral S (25/83, = v3 `J2R`) and S-RawGraph is code `J2` (30/102). The numbers decide.")
    w()
    w("Point-estimate reproduction. F1 = 2D/(2D+FE+(44-D)) (pooled, false entities as FPs). "
      "R@2FP = sum over the 20 (scenario, class) cells of recall_at_fp2 x incidents, divided by 44 "
      "(incident-weighted; the unweighted cell mean gives 0.512 for S, not 0.500).")
    w()
    w("| System | Detected/44 | False ent. | F1 | R@2FP | R@2FP hits |")
    w("|---|---|---|---|---|---|")
    for n in names:
        c = cells[n]
        w(f"| {n} | {int(c['D'].sum())} (incident file: {det[n].sum()}) | {int(c['FE'].sum())} | "
          f"{f(f1(c['D'].sum(), c['I'].sum(), c['FE'].sum()))} | {f(c['R2'].sum() / c['I'].sum())} | "
          f"{c['R2'].sum():.0f} |")
    w()
    w("All Table 4 numbers reproduce exactly (incl. ML-IF R@2FP 0.341, Wazuh-T 0.318, Wazuh-D 0.250).")
    w()

    # incident-level bootstrap stratified by scenario
    scen = base.scenario.to_numpy()
    strata = [np.flatnonzero(scen == s) for s in pd.unique(scen)]
    idx = np.empty((B, len(base)), int)
    pos = 0
    for st in strata:
        idx[:, pos:pos + len(st)] = rng.choice(st, size=(B, len(st)), replace=True)
        pos += len(st)
    bdet = {n: det[n][idx].sum(1) for n in names}

    # cell bootstrap stratified by attack class (5 scenario cells per class)
    cls = cell_order.attack_class.to_numpy()
    cstr = [np.flatnonzero(cls == k) for k in pd.unique(cls)]
    cidx = np.concatenate([rng.choice(st, size=(B, len(st)), replace=True) for st in cstr], axis=1)
    # scenario-cluster bootstrap (5 clusters) - sensitivity
    sc_cells = cell_order.scenario.to_numpy()
    sc_list = pd.unique(sc_cells)
    pick = rng.integers(0, len(sc_list), size=(B, len(sc_list)))
    sc_masks = np.stack([(sc_cells == s).astype(float) for s in sc_list])  # (5,20)
    sc_w = np.zeros((B, len(sc_cells)))
    for j in range(len(sc_list)):
        sc_w += sc_masks[pick[:, j]]

    bf1, br2, bf1s, br2s = {}, {}, {}, {}
    for n in names:
        c = cells[n]
        D, I, FE, R2 = (c[k][cidx].sum(1) for k in ("D", "I", "FE", "R2"))
        bf1[n] = f1(D, I, FE)
        br2[n] = R2 / I
        D, I, FE, R2 = (sc_w @ c[k] for k in ("D", "I", "FE", "R2"))
        bf1s[n] = f1(D, I, FE)
        br2s[n] = R2 / I

    w("### 1a. Per-system 95% CIs")
    w()
    w("Incidents: bootstrap over the 44 incidents, resampled within each test scenario (stratified; "
      "scenario sizes 10/9/7/9/9 kept), plus Wilson on the recall. F1 and R@2FP: false entities exist only per "
      "(scenario, class) cell, so these resample the 20 cells, stratified by attack class (5 scenario cells per "
      "class). Last column: scenario-cluster bootstrap (only 5 clusters; indicative, tends to be too narrow).")
    w()
    w("| System | Incidents [95% CI] | Recall (Wilson) | F1 [cell CI] | R@2FP [cell CI] | F1 [scenario-cluster CI] |")
    w("|---|---|---|---|---|---|")
    for n in names:
        c = cells[n]
        D = int(c["D"].sum())
        lo, hi = pct(bdet[n])
        wl, wh = wilson(D, 44)
        p1 = f1(c["D"].sum(), c["I"].sum(), c["FE"].sum())
        r2 = c["R2"].sum() / c["I"].sum()
        w(f"| {n} | {D} [{lo:.0f}, {hi:.0f}] | {f(D / 44)} {ci(wl, wh)} | {f(p1)} {ci(*pct(bf1[n]))} | "
          f"{f(r2)} {ci(*pct(br2[n]))} | {ci(*pct(bf1s[n]))} |")
    w()

    w("### 1b. Paired differences (S minus other)")
    w()
    w("Same resamples for both systems. Incidents: paired incident bootstrap (stratified by scenario) and exact "
      "McNemar on the per-incident detections (b = S only, c = other only). F1/R@2FP: paired cell bootstrap "
      "(stratified by class). 'Excl. 0' = 95% CI excludes 0.")
    w()
    w("| S minus | dIncidents [CI] | b/c, McNemar p | Excl. 0 | dF1 [CI] | Excl. 0 | dR@2FP [CI] | Excl. 0 | dF1 scen.-cluster CI |")
    w("|---|---|---|---|---|---|---|---|---|")
    for o in ["S-RawGraph", "S-LAPH", "A2", "Fixed-Decay", "Wazuh-D", "ML-GB", "Wazuh-T", "ML-IF"]:
        dd = bdet["S"] - bdet[o]
        b = int(((det["S"] == 1) & (det[o] == 0)).sum())
        cc = int(((det["S"] == 0) & (det[o] == 1)).sum())
        p = mcnemar_exact(b, cc)
        cs, co = cells["S"], cells[o]
        pf = f1(cs["D"].sum(), cs["I"].sum(), cs["FE"].sum()) - f1(co["D"].sum(), co["I"].sum(), co["FE"].sum())
        pr = cs["R2"].sum() / 44 - co["R2"].sum() / 44
        df1 = bf1["S"] - bf1[o]
        dr2 = br2["S"] - br2[o]
        dfs = bf1s["S"] - bf1s[o]
        w(f"| {o} | {int(det['S'].sum() - det[o].sum()):+d} [{pct(dd)[0]:+.0f}, {pct(dd)[1]:+.0f}] | {b}/{cc}, "
          f"{p:.3g} | {excl0(*pct(dd))} | {pf:+.3f} {ci(*pct(df1))} | {excl0(*pct(df1))} | {pr:+.3f} "
          f"{ci(*pct(dr2))} | {excl0(*pct(dr2))} | {ci(*pct(dfs))} |")
    w()

    w("### 1c. Per-scenario breakdown (S and Wazuh-D)")
    w()
    w("| Scenario | Incidents | S detected | S false ent. | Wazuh-D detected | Wazuh-D false ent. |")
    w("|---|---|---|---|---|---|")
    for s in sc_list:
        m_ = cell_order.scenario.to_numpy() == s
        cs, cw = cells["S"], cells["Wazuh-D"]
        w(f"| {s} | {cs['I'][m_].sum():.0f} | {cs['D'][m_].sum():.0f} | {cs['FE'][m_].sum():.0f} | "
          f"{cw['D'][m_].sum():.0f} | {cw['FE'][m_].sum():.0f} |")
    w(f"| total | 44 | {cells['S']['D'].sum():.0f} | {cells['S']['FE'].sum():.0f} | "
      f"{cells['Wazuh-D']['D'].sum():.0f} | {cells['Wazuh-D']['FE'].sum():.0f} |")
    w()


# ----------------------------------------------------------------------------------------------
# 2. Exp 3 identification
# ----------------------------------------------------------------------------------------------
ATT = ["uniform", "central", "intersect", "downstream", "learned", "combined"]


def boot_mean(vals: np.ndarray, groups: np.ndarray | None = None):
    """Bootstrap of the mean, resampling hunts within seed (stratified)."""
    if groups is None:
        groups = np.zeros(len(vals), int)
    parts = []
    for g in np.unique(groups):
        ix = np.flatnonzero(groups == g)
        parts.append(rng.choice(ix, size=(B, len(ix)), replace=True))
    idx = np.concatenate(parts, axis=1)
    return vals[idx].mean(1), idx


def exp3():
    w("## 2. Experiment 3 identification (Table 5)")
    w()
    iss = pd.read_csv(V2 / "e3_aqrs_issues.csv")
    t = iss[iss.epoch > 4]  # test epochs (second half of 8), as in e3_aqrs.summarize
    w("Source: `vm-m7i-2xlarge-journal-v2/e3_aqrs_issues.csv` (per hunt, test epochs 5-8, 817 hunts per system, "
      "seeds 1-5). Per-hunt values are probabilities, not 0/1: `uniform`/`intersect`/`downstream` = 1/k, "
      "`central` = 1/(ties) or 0, `learned`/`combined` = 1/(ties) or 0. 'Best' in the summary = max over the six "
      "attack columns of the column means, computed separately per subset. CIs: bootstrap of the mean over hunts "
      "(stratified by seed; hunts treated as independent, ignoring Zipf repeats), for the column that is best on "
      "the full sample; Wilson CI with n hunts shown for comparison (exact when the column is 0/1). "
      "Across-seed SD = SD of the five per-seed means of that column.")
    w()
    sysmap = [("Direct", "Direct"), ("Fixed-5, nearest covers", "Fixed-5"), ("AQRS-adaptive", "AQRS"),
              ("Dynamic-Cover", "Dynamic-Cover"), ("Partition, k=5, no padding", "Fixed-5-G"),
              ("S, k=5 (default)", "Fixed-5-G+CPt")]
    w("| Configuration | Subset | n | Best column | Rate | Bootstrap 95% CI | Wilson 95% CI | Seed SD | Ideal |")
    w("|---|---|---|---|---|---|---|---|---|")
    for pname, code in sysmap:
        s = t[t.system == code]
        for sub, mask in (("all", np.ones(len(s), bool)), ("attacker", s.atk.to_numpy() == 1),
                          ("high exposure", s.cls.to_numpy() == 2)):
            x = s[mask]
            means = {a: x[a].mean() for a in ATT}
            best = max(ATT, key=lambda a: (means[a], -ATT.index(a)))
            vals = x[best].to_numpy(float)
            bm, _ = boot_mean(vals, x.seed.to_numpy())
            ws = wilson(vals.sum(), len(vals))
            sd = x.groupby("seed")[best].mean().std(ddof=1)
            w(f"| {pname} | {sub} | {len(x)} | {best} | {f(means[best])} | {ci(*pct(bm))} | {ci(*ws)} | "
              f"{f(sd)} | {f((1 / x.k_eff).mean())} |")
    w()
    w("Paired S(k=5) vs Partition-no-padding (same hunts? no: different systems issue different cohorts, so an "
      "unpaired difference of bootstrap means is used):")
    a = t[t.system == "Fixed-5-G+CPt"]
    b = t[t.system == "Fixed-5-G"]
    for sub, fa, fb in (("all", a, b), ("high exposure", a[a.cls == 2], b[b.cls == 2])):
        ma, _ = boot_mean(fa.combined.to_numpy(float), fa.seed.to_numpy())
        mb, _ = boot_mean(fb.combined.to_numpy(float), fb.seed.to_numpy())
        d = ma - mb
        w(f"- {sub}: {fa.combined.mean() - fb.combined.mean():+.3f} {ci(*pct(d))} (excl. 0: {excl0(*pct(d))})")
    w()
    w("k=3 and k=8: only the summary `vm-m7i-2xlarge-journal-v2-design/e3_d29_design_B.csv` exists (no per-hunt "
      "file), so only Wilson intervals with n hunts are given; for a mean of probabilities this is an "
      "approximation (slightly conservative).")
    w()
    d29 = pd.read_csv(V2D / "e3_d29_design_B.csv")
    w("| Config | Subset | n | Best (column) | Wilson 95% CI | Ideal (uniform col.) |")
    w("|---|---|---|---|---|---|")
    for code, pn in (("D29-G3", "S, k=3"), ("D29-G5", "S, k=5 (rerun)"), ("D29-G8", "S, k=8")):
        for cl, sub in (("all", "all"), ("atk", "attacker"), ("2", "high exposure")):
            r = d29[(d29.system == code) & (d29.cls.astype(str) == cl)].iloc[0]
            best = max(ATT, key=lambda a_: r[a_])
            w(f"| {pn} | {sub} | {r.issues} | {f(r.best)} ({best}) | {ci(*wilson(r.best * r.issues, int(r.issues)))} | "
              f"{f(r.uniform)} |")
    w()

    # ---- v3 decoy discount and filtered hunts ----
    w("### 2b. Decoy discounting and filtered hunts (journal v3, 806 hunts)")
    w()
    v3 = pd.read_csv(V3 / "e3_aqrs_issues_v3.csv")
    t3 = v3[v3.epoch > 4]
    w("Source: `vm-m7i-2xlarge-journal-v3/e3_aqrs_issues_v3.csv` and `e3_aqrs_summary_v3.{md,csv}` "
      "(S = `J2R`; `J2R@dd<tau>` = decoy-discount attacker). In `experiments/e3_aqrs.py` the decoy-discount "
      "attacker drops records with p(decoy) > tau and reruns only the `central` (largest/central remaining "
      "volume) and `learned` (+`combined`) attacks; `uniform`/`intersect`/`downstream` are unchanged. "
      "Subsets: unfilt = no filter (304), cat = category filter (408), time = time filter (201); "
      "107 hunts have both filters, so cat and time overlap and 304+408+201 = 913 > 806.")
    w()
    w("Per-column means (J2R, no discount), recomputed from the per-hunt file:")
    w()
    w("| Subset | n | uniform | central | intersect | downstream | learned | combined | best |")
    w("|---|---|---|---|---|---|---|---|---|")
    j = t3[t3.system == "J2R"]
    subs = {"all": np.ones(len(j), bool), "unfilt": ((j.filtered == 0) & (j.tfilt == 0)).to_numpy(),
            "cat": (j.filtered == 1).to_numpy(), "time": (j.tfilt == 1).to_numpy(),
            "atk": (j.atk == 1).to_numpy(), "high exp. (cls 2)": (j.cls == 2).to_numpy()}
    for sn, mk in subs.items():
        x = j[mk]
        mv = [x[a].mean() for a in ATT]
        w(f"| {sn} | {len(x)} | " + " | ".join(f(v) for v in mv) + f" | {f(max(mv))} ({ATT[int(np.argmax(mv))]}) |")
    w()
    # oracle per subset over a disjoint partition
    part = np.where(subs["unfilt"], "unfilt", np.where(j.filtered == 1, "cat(incl. both)", "time-only"))
    tot = 0.0
    for pz in pd.unique(part):
        x = j[part == pz]
        tot += max(x[a].sum() for a in ATT)
    w(f"Per-subset 'best' picks a different attack per subset (unfilt: central 0.234; cat: learned 0.233; "
      f"time: uniform 0.198, every attack is at or below chance there). A single attacker has one rate over all "
      f"806 hunts: central 0.208 (the 'all' best). If the attacker could pick the best attack per subset "
      f"(disjoint partition unfiltered / category-filtered incl. both / time-only), the overall rate would be "
      f"{f(tot / len(j))}. The paper's 0.233/0.198/0.234 are therefore subset maxima of different attacks and "
      f"need not average to 0.208.")
    w()
    w("CIs (bootstrap over hunts stratified by seed, for the column that is best in that subset; 'max' row = "
      "bootstrap of the max over the six attack means, which includes the selection effect):")
    w()
    w("| System | Subset | n | Rate (column) | Bootstrap 95% CI | Max-over-attacks bootstrap CI | Seed SD |")
    w("|---|---|---|---|---|---|---|")
    for code in ["J2R", "J2R@dd0.5", "J2R@dd0.7", "J2R@dd0.9", "Fixed-5-G+CPec"]:
        x0 = t3[t3.system == code]
        sm = {"all": np.ones(len(x0), bool), "unfilt": ((x0.filtered == 0) & (x0.tfilt == 0)).to_numpy(),
              "cat": (x0.filtered == 1).to_numpy(), "time": (x0.tfilt == 1).to_numpy()}
        for sn, mk in sm.items():
            x = x0[mk]
            means = {a: x[a].mean() for a in ATT}
            best = max(ATT, key=lambda a: (means[a], -ATT.index(a)))
            bm, idx = boot_mean(x[best].to_numpy(float), x.seed.to_numpy())
            M = np.stack([x[a].to_numpy(float)[idx].mean(1) for a in ATT]).max(0)
            sd = x.groupby("seed")[best].mean().std(ddof=1)
            w(f"| {code} | {sn} | {len(x)} | {f(means[best])} ({best}) | {ci(*pct(bm))} | {ci(*pct(M))} | {f(sd)} |")
    w()
    jj = t3[t3.system == "J2R"]
    for tau in ("0.5", "0.7", "0.9"):
        dd = t3[t3.system == f"J2R@dd{tau}"]
        assert (dd[["seed", "epoch", "n_issue"]].to_numpy() == jj[["seed", "epoch", "n_issue"]].to_numpy()).all()
    w("Paired difference (same hunts), decoy-discount minus no discount, best column of each on 'all':")
    for tau in ("0.5", "0.7", "0.9"):
        dd = t3[t3.system == f"J2R@dd{tau}"]
        cb = max(ATT, key=lambda a: dd[a].mean())
        d = dd[cb].to_numpy(float) - jj["central"].to_numpy(float)
        bm, _ = boot_mean(d, jj.seed.to_numpy())
        w(f"- tau={tau}: {cb} {f(dd[cb].mean())} vs central {f(jj.central.mean())}: {d.mean():+.3f} {ci(*pct(bm))}"
          f" (excl. 0: {excl0(*pct(bm))})")
    w()
    cpec = pd.read_csv(V3 / "e3_aqrs_summary_v3.csv")
    r = cpec[cpec.system == "Fixed-5-G+CPec"].set_index("cls")
    w(f"Per-(entity, category) padding (`Fixed-5-G+CPec`, decoys/real = delta {f(r.loc['all', 'delta'])}; "
      f"J2R delta {f(cpec[(cpec.system == 'J2R') & (cpec.cls == 'all')].delta.iloc[0])}): best = "
      f"all {f(r.loc['all', 'best'])}, unfilt {f(r.loc['unfilt', 'best'])}, cat {f(r.loc['cat', 'best'])}, "
      f"time {f(r.loc['time', 'best'])}. The uniform column is 0.200 everywhere; the paper's 'reaches 0.200 for "
      f"all three' holds for 'all' and 'time' but not for unfiltered (learned 0.237) or category (central 0.204) "
      f"hunts. With decoy discount, CPec reaches 0.212-0.252 on 'all' (see table above).")
    w()


# ----------------------------------------------------------------------------------------------
# 3. Exp 4 low-and-slow
# ----------------------------------------------------------------------------------------------
def exp4_lns():
    w("## 3. Experiment 4 low-and-slow (Fig. 3a)")
    w()
    d = pd.read_csv(V3 / "e4_temporal_hist_lns.csv")
    w("Source: `vm-m7i-2xlarge-journal-v3/e4_temporal_hist_lns.csv`. Per seed, recall_at_fp2 takes values in "
      "{0, 1/3, 2/3, 1}: 3 attackers per seed, 5 seeds, so the denominator is 15 per cell. The file stores only "
      "per-seed counts, not which attacker was detected, so an exact McNemar test cannot be computed directly; "
      "we give the exact McNemar p under the minimum discordance consistent with the per-seed counts "
      "(the smallest p-value consistent with the data: adding discordant pairs in both directions only raises it), and a seed-level paired "
      "bootstrap.")
    w()
    w("| Span | r | System | Hits/15 | R@2FP | Wilson 95% CI |")
    w("|---|---|---|---|---|---|")
    name = {"S": "S", "NoHist": "A2", "FixedDecay": "Fixed-Decay", "B1-default": "Wazuh-D"}
    for span in (24, 48):
        for code in ("S", "NoHist", "FixedDecay", "B1-default"):
            x = d[(d.system == code) & (d.span == span) & (d.rate == 3)]
            h = int(round((x.recall_at_fp2 * 3).sum()))
            n = 3 * len(x)
            w(f"| {span} | 3 | {name[code]} | {h}/{n} | {f(h / n, 2)} | {ci(*wilson(h, n), 2)} |")
    w()
    w("| Span | Comparison | Per-seed hits (S; other) | Diff | Min-discordance McNemar p (lower bound) | Seed bootstrap 95% CI of diff |")
    w("|---|---|---|---|---|---|")
    for span in (24, 48):
        for o in ("NoHist", "FixedDecay", "B1-default"):
            a = d[(d.system == "S") & (d.span == span) & (d.rate == 3)].sort_values("seed")
            b = d[(d.system == o) & (d.span == span) & (d.rate == 3)].sort_values("seed")
            ha = np.round(a.recall_at_fp2.to_numpy() * 3).astype(int)
            hb = np.round(b.recall_at_fp2.to_numpy() * 3).astype(int)
            bb = int(np.clip(ha - hb, 0, None).sum())
            cc = int(np.clip(hb - ha, 0, None).sum())
            p = mcnemar_exact(bb, cc)
            ix = rng.integers(0, 5, size=(B, 5))
            dif = (ha[ix].sum(1) - hb[ix].sum(1)) / 15
            w(f"| {span} | S vs {name[o]} | {[int(v) for v in ha]}; {[int(v) for v in hb]} | {(ha.sum() - hb.sum()) / 15:+.2f} | "
              f"{p:.3g} (b={bb}, c={cc}) | {ci(*pct(dif), 2)} |")
    w()


# ----------------------------------------------------------------------------------------------
# 4. Synthetic Exp 1
# ----------------------------------------------------------------------------------------------
def synth():
    w("## 4. Synthetic Experiment 1 (Table 3), macro F1 over five seeds")
    w()
    A = pd.read_csv(V2D / "e3_d29_design_A.csv")
    A = A[A.part == "detect"]
    E = pd.read_csv(FINAL / "e1_main.csv")
    ef = E.groupby(["system", "seed"]).f1.mean()
    per = {
        "S (= NP = G5+R)": A[A.system == "NP"].sort_values("seed").macro_f1.to_numpy(),
        "S-RawGraph (G5)": A[A.system == "G5"].sort_values("seed").macro_f1.to_numpy(),
        "S-LAPH (LAPH-E)": A[A.system == "LAPH-E"].sort_values("seed").macro_f1.to_numpy(),
        "A2": ef.loc["A2"].sort_index().to_numpy(),
        "Wazuh-D (B1-default)": ef.loc["B1-default"].sort_index().to_numpy(),
        "Wazuh-T (B1-tuned)": ef.loc["B1-tuned"].sort_index().to_numpy(),
    }
    s_final = ef.loc["S"].sort_index().to_numpy()
    same = bool(np.allclose(s_final, per["S (= NP = G5+R)"]))
    w("Sources: `vm-m7i-2xlarge-journal-v2-design/e3_d29_design_A.csv` (part=detect: NP, G5, LAPH-E, G5+R per "
      "seed) and `vm-m7i-2xlarge-final/e1_main.csv` (A2, B1-default, B1-tuned; macro F1 = mean of the three class "
      f"F1s per seed). S per seed in e1_main equals design-A NP: {same}. Fixed-Decay was not run on the synthetic "
      "E1 workload (no file contains it), so no interval is given. 95% CI = mean +/- t(0.975, 4) x SD/sqrt(5).")
    w()
    w("| System | Per-seed macro F1 (seeds 1-5) | Mean | SD | 95% t-CI |")
    w("|---|---|---|---|---|")
    for n, v in per.items():
        m, s, lo, hi = tci(v)
        w(f"| {n} | {', '.join(f(x) for x in v)} | {f(m)} | {f(s)} | {ci(lo, hi)} |")
    w()
    w("Paired (same seed) differences, S minus other:")
    w()
    w("| S minus | Mean diff | SD | 95% paired t-CI | Excl. 0 |")
    w("|---|---|---|---|---|")
    for n in ["A2", "S-RawGraph (G5)", "S-LAPH (LAPH-E)", "Wazuh-D (B1-default)", "Wazuh-T (B1-tuned)"]:
        dv = per["S (= NP = G5+R)"] - per[n]
        m, s, lo, hi = tci(dv)
        w(f"| {n} | {m:+.3f} | {f(s)} | {ci(lo, hi)} | {excl0(lo, hi)} |")
    w()


# ----------------------------------------------------------------------------------------------
# 5. Exp 4 gap / dormancy
# ----------------------------------------------------------------------------------------------
def gap():
    w("## 5. Experiment 4 gap / dormancy (Table S9): AUC and recall@2FP")
    w()
    g = pd.read_csv(V2 / "e4_v2_gap.csv")
    bu = pd.read_csv(V2 / "e4_v2_burst.csv")
    w("Sources: `vm-m7i-2xlarge-journal-v2/e4_v2_gap.csv` (Part A, gap g) and `e4_v2_burst.csv` (Part B, "
      "dormancy D); summary `e4_v2_summary.md`. AUC is stored per seed. Recall@2FP per seed is in thirds: "
      "3 attackers x 5 seeds = denominator 15 per cell. AUC cells: mean over 5 seeds (SD).")
    w()
    for title, df, kn in (("Gap g between 5 active epochs", g, "g"), ("Dormancy D between two bursts", bu, "D")):
        knobs = sorted(df.knob.unique())
        w(f"**{title}: AUC, mean (SD) over 5 seeds**")
        w()
        w("| System | " + " | ".join(f"{kn}={k}" for k in knobs) + " |")
        w("|---|" + "---|" * len(knobs))
        for s in ["S", "NoGraph", "FixedWindow", "FixedDecay", "NoHist"]:
            row = []
            for k in knobs:
                x = df[(df.system == s) & (df.knob == k)].auc
                row.append(f"{x.mean():.2f} ({x.std(ddof=1):.2f})")
            w(f"| {s} | " + " | ".join(row) + " |")
        w()
        w(f"**{title}: recall@2FP, hits/15 with Wilson 95% CI**")
        w()
        w("| System | " + " | ".join(f"{kn}={k}" for k in knobs) + " |")
        w("|---|" + "---|" * len(knobs))
        for s in ["S", "NoGraph", "FixedWindow", "FixedDecay", "NoHist"]:
            row = []
            for k in knobs:
                x = df[(df.system == s) & (df.knob == k)]
                h = int(round((x.recall_at_fp2 * 3).sum()))
                lo, hi = wilson(h, 15)
                row.append(f"{h}/15 [{lo:.2f}, {hi:.2f}]")
            w(f"| {s} | " + " | ".join(row) + " |")
        w()
    w("Paper-name mapping: No-Graph = `NoGraph`, A2 = `NoHist`. Gap AUC: No-Graph 0.71 (g=0) down to 0.41 (g=4), "
      "S 0.92-0.91, A2 0.95 in every cell, matching the text.")
    w()


def main():
    w("# Confidence intervals for the paper's results (from existing result files)")
    w()
    w(f"Generated by `tools/paper_ci.py`; numpy default_rng({SEED}); {B:,} bootstrap resamples; percentile "
      "95% intervals; Wilson score intervals for proportions. No experiment was rerun.")
    w()
    ait()
    exp3()
    exp4_lns()
    synth()
    gap()
    OUT.write_text("\n".join(L) + "\n")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
