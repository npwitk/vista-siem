"""Journal Experiments 2 and 5 (figures): authenticated retrieval and ACL scalability.

One outsourced epoch of N protected records (2048-bit Paillier ciphertexts, |J| = 2 features
plus the realness indicator), indexed by four token dimensions plus buckets. A query selects
q = |Q_q| records through one category token. Per query we time, separately:
  retrieve   cloud: posting lookup, candidate set and index multiproof (Authenticated EPII)
  aggregate  cloud: SG-HEF aggregates over the candidates
  verify_idx EE: VerifyIDX against R^IDX and candidate recomputation
  acl        EE: complete verify-before-release (VerifyIDX + candidate recomputation +
             commitments + scoped HE recomputation), i.e. Algorithm alg:acl
  full       EE: re-execution over the whole epoch (predicate check + aggregation over all N
             records), the alternative ACL avoids
plus hashes, HE additions and the bytes of the posting lists and proof sent to the EE.
Ciphertexts are random elements of Z_{N^2}^*: homomorphic additions cost the same as on
real ciphertexts, and nothing is decrypted.

Sweeps: (a) N fixed, selectivity q/N in {0.1%, 0.5%, 1%, 5%, 10%, 25%};
        (b) q fixed, N growing; index construction time per N (EE, end of epoch);
        (c) journal v2: N and q fixed, j_q = |J_q| aggregated features in {1, 2, 4, 8};
        (d) journal v2 (--ns): q/N = 1%, N over the given list (default 10^4 .. 10^7). Records
            draw their ciphertexts from a shared pool (--pool), so 10^7 records fit in memory;
            an HE addition costs the same whatever the ciphertext. Full recompute (S-FullHE)
            is timed once per N above 10^6.
        (e) journal v3 spot-check ACL: the EE recomputes a Phase 3 aggregate (and re-contracts a
            Phase 4 entity) with probability f in {1, 0.5, 0.2, 0.1, 0.05}; the hash checks (VerifyIDX,
            C_Q, C_A, drift) stay unconditional. Cost: mean EE verification time per query over a
            batch of --batch queries at N, q (--bits keys). Detection: J2R runs on the e5_acl stream
            in which a consistent cheating cloud modifies t in {1, 2, 4, 8} HE aggregates
            (e5_acl.d_modify_aggregate); detected = at least one rejection; --tamper-trials seeds
            per (f, t) at 512 bits, next to the analytic 1 - (1 - f)^t.

Usage:  python experiments/e2_acl_scale.py [--quick] [--n 100000] [--q 1000] [--reps 5]
                                           [--ns 10000,100000,1000000,10000000] [--parts abcd]
                                           [--tamper-trials 200] [--workers 8]
Writes results/e2_acl_scale.csv and e2_acl_scale.md (part e: e2_acl_spot_cost.csv,
e2_acl_spot_detect.csv and a section of e2_acl_scale.md).
"""

from __future__ import annotations

import argparse
import os
import random
import statistics
import sys
import time
from pathlib import Path

import gmpy2

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import RESULTS, write_csv  # noqa: E402

from vista_siem import lineage  # noqa: E402
from vista_siem.crypto import paillier  # noqa: E402
from vista_siem.crypto.mmr import HashCounter  # noqa: E402
from vista_siem.model import Policy  # noqa: E402
from vista_siem.protocol import IndexEntry  # noqa: E402

FEATS = ("count", "bytes")
FI = {f: j for j, f in enumerate(FEATS)}


class Repo:
    """One epoch: entries, ciphertexts, index and checkpoint."""

    def __init__(self, N: int, q: int, pk, rng: random.Random, feats: tuple = None, pool: int = 0):
        self.N = N
        self.feats = feats = feats or FEATS
        tok = lambda: os.urandom(32)  # noqa: E731
        users = [tok() for _ in range(max(N // 50, 10))]
        res = [tok() for _ in range(max(N // 200, 10))]
        cats = [tok() for _ in range(40)]
        srcs = [tok() for _ in range(4)]
        self.target = tok()
        hit = set(rng.sample(range(N), q))
        n2 = pk.n2

        def ct():
            return gmpy2.mpz(rng.getrandbits(n2.bit_length() - 1))

        shared = [(tuple(ct() for _ in feats), ct()) for _ in range(pool)] if pool else None
        self.entries, self.X = {}, {}
        for i in range(N):
            c = self.target if i in hit else rng.choice(cats)
            self.entries[i] = IndexEntry((rng.choice(users), rng.choice(res), c, rng.choice(srcs)), i // 500, 1, i)
            self.X[i] = shared[i % pool] if shared else (tuple(ct() for _ in feats), ct())
        t0 = time.perf_counter()
        self.index = lineage.build_index(self.entries.values())
        self.t_build = time.perf_counter() - t0
        self.postings = lineage.postings_of(self.entries.values())
        self.cp = (1, os.urandom(32), self.index.root(), os.urandom(32), N)
        self.q = dict(qid="q", attack="a", epoch=1, slot=0, tokens={"C": frozenset({self.target})}, feats=feats,
                      source_weights={}, policy=Policy.VALUE, threshold=0.0)


def bench(repo: Repo, he, reps: int, full_reps: int | None = None) -> dict:
    q, cp = repo.q, repo.cp
    FEATS = repo.feats
    FI = {f: j for j, f in enumerate(FEATS)}
    adds = [0]

    def summer(cts):
        acc = None
        for c in cts:
            acc = c if acc is None else he.add(acc, c)
            adds[0] += 1
        return acc

    src = lambda i: repo.entries[i].tokens[3]  # noqa: E731
    out = {k: [] for k in ("retrieve", "aggregate", "verify_idx", "acl", "full", "fullhe")}
    for _ in range(reps):
        # cloud: authenticated retrieval
        t0 = time.perf_counter()
        keys = lineage.query_keys(q["tokens"])
        P = {k: repo.postings[k] for k in keys if k in repo.postings}
        proof = repo.index.prove([lineage.posting_key(d, T) for d, T in keys])
        Q = lineage.candidates_from(q["tokens"], P, repo.N)
        out["retrieve"].append(time.perf_counter() - t0)
        # cloud: aggregation and commitments
        t0 = time.perf_counter()
        aggs, real = lineage.aggregate(q, Q, repo.X.__getitem__, src, FI, he, summer)
        chi = lineage.c_chi(q, cp)
        cq = lineage.c_q(chi, Q)
        ca = lineage.c_a(cq, FEATS, aggs, real)
        out["aggregate"].append(time.perf_counter() - t0)
        # EE: VerifyIDX + candidate recomputation
        hc = HashCounter()
        t0 = time.perf_counter()
        assert lineage.verify_postings(cp[2], q["tokens"], P, proof, hc)
        Q2 = lineage.candidates_from(q["tokens"], P, repo.N)
        t_idx = time.perf_counter() - t0
        out["verify_idx"].append(t_idx)
        # EE: rest of Algorithm alg:acl
        a0 = adds[0]
        t0 = time.perf_counter()
        assert Q2 == Q and lineage.c_q(lineage.c_chi(q, cp, hc), Q2, hc) == cq
        aggs2, real2 = lineage.aggregate(q, Q2, repo.X.__getitem__, src, FI, he, summer)
        assert all(aggs2[f] == aggs[f] for f in FEATS) and real2 == real
        assert lineage.c_a(cq, FEATS, aggs2, real2, hc) == ca
        lineage.acl_record(chi, cq, ca, hc)
        out["acl"].append(t_idx + time.perf_counter() - t0)
        acl_adds = adds[0] - a0
        # EE: full re-execution over the epoch
        if full_reps is not None and len(out["full"]) >= full_reps:
            continue
        t0 = time.perf_counter()
        Qf = {i for i, ent in repo.entries.items() if ent.tokens[2] in q["tokens"]["C"]}
        lineage.aggregate(q, Qf, repo.X.__getitem__, src, FI, he, summer)
        out["full"].append(time.perf_counter() - t0)
        # S-FullHE: no EPII scoping, the cloud aggregates every record of the epoch (masked
        # slots, B3), j_q + 1 sums over N ciphertexts
        t0 = time.perf_counter()
        for j in range(len(FEATS)):
            summer(repo.X[i][0][j] for i in range(repo.N))
        summer(repo.X[i][1] for i in range(repo.N))
        out["fullhe"].append(time.perf_counter() - t0)
    ct_bytes = (int(he.pk.n2.bit_length()) + 7) // 8
    row = {}
    for k, v in out.items():  # median (as before), plus IQR and mean over the reps (journal v3)
        if v:
            row.update(dist_ms(f"{k}_ms", v))
    row.update(N=repo.N, q=len(Q), selectivity=len(Q) / repo.N, acl_hashes=hc.count, acl_he_adds=acl_adds,
               proof_hashes=proof.size(), ee_bytes=32 * proof.size() + 8 * sum(len(v) for v in P.values())
               + 2 * 32 * len(proof.entries) + ct_bytes * (len(FEATS) + 1) + 3 * 32,
               index_build_ms=repo.t_build * 1e3, index_keys=repo.index.n)
    return row


# ============================================================================ (e) spot-check ACL
SPOT_F = [1.0, 0.5, 0.2, 0.1, 0.05]
SPOT_T = [0, 1, 2, 4, 8]  # t = 0: honest cloud (false rejections)


def spot_cost(repo: Repo, he, f: float, batch: int, reps: int, seed: int) -> dict:
    """EE cost of verifying a batch of Phase 3 requests when the HE recomputation is sampled with
    probability f (the hash checks always run). Mean per query, distribution over reps."""
    q, cp, feats = repo.q, repo.cp, repo.feats
    fi = {f_: j for j, f_ in enumerate(feats)}
    adds = [0]

    def summer(cts):
        acc = None
        for c in cts:
            acc = c if acc is None else he.add(acc, c)
            adds[0] += 1
        return acc

    src = lambda i: repo.entries[i].tokens[3]  # noqa: E731
    keys = lineage.query_keys(q["tokens"])
    P = {k: repo.postings[k] for k in keys if k in repo.postings}
    proof = repo.index.prove([lineage.posting_key(d, T) for d, T in keys])
    Q = lineage.candidates_from(q["tokens"], P, repo.N)
    aggs, real = lineage.aggregate(q, Q, repo.X.__getitem__, src, fi, he, summer)
    cq = lineage.c_q(lineage.c_chi(q, cp), Q)
    ca = lineage.c_a(cq, feats, aggs, real)
    rng = random.Random(seed)
    per, sampled, a0 = [], 0, adds[0]
    for _ in range(reps):
        t0 = time.perf_counter()
        for _ in range(batch):
            hc = HashCounter()
            assert lineage.verify_postings(cp[2], q["tokens"], P, proof, hc)
            Q2 = lineage.candidates_from(q["tokens"], P, repo.N)
            chi = lineage.c_chi(q, cp, hc)
            assert Q2 == Q and lineage.c_q(chi, Q2, hc) == cq
            if f >= 1.0 or rng.random() < f:
                sampled += 1
                aggs2, real2 = lineage.aggregate(q, Q2, repo.X.__getitem__, src, fi, he, summer)
                assert all(aggs2[x] == aggs[x] for x in feats) and real2 == real
            assert lineage.c_a(cq, feats, aggs, real, hc) == ca
            lineage.acl_record(chi, cq, ca, hc)
        per.append((time.perf_counter() - t0) / batch)
    return dict(f=f, N=repo.N, q=len(Q), batch=batch, reps=reps, **dist_ms("ee_ms_per_query", per),
                sampled_share=sampled / (batch * reps), he_adds_per_query=(adds[0] - a0) / (batch * reps))


def spot_detect(f: float, t: int, seed: int, variant: str = "J2R") -> dict:
    """One J2R run on the e5_acl stream; a consistent cheating cloud modifies t of its Phase 3
    aggregates (chosen at random among the run's requests) and recommits to them."""
    from dataclasses import replace

    from e5_acl import DATA, d_modify_aggregate

    from common import config, generate
    from vista_siem.data.synth import default_profiles_and_contexts
    from vista_siem.system import VistaSIEM

    events, _ = generate(replace(DATA, seed=seed))
    profiles, contexts = default_profiles_and_contexts()
    s = VistaSIEM(config(variant, seed=seed, acl_sample=f), profiles, contexts)
    n_req = len({int(ev.ts // s.cfg.epoch_len) for ev in events}) * len(contexts)
    rng = random.Random(seed * 1009 + t)
    bad = set(rng.sample(range(n_req), min(t, n_req)))
    _, tamper = d_modify_aggregate(s, rng)
    orig = s.cloud.acl_request
    n = {"calls": 0, "tampered": 0}

    def wrapped(q, fi):
        i = n["calls"]
        n["calls"] += 1
        if i in bad:
            n["tampered"] += 1
            return tamper(q, fi)
        return orig(q, fi)

    s.cloud.acl_request = wrapped
    s.run(events)
    st, log = s.ee.stats, s.ee.acl_log
    return dict(f=f, t=t, seed=seed, requests=n["calls"], tampered=n["tampered"],
                rejected=st["acl_reject"], detected=int(st["acl_reject"] > 0),
                false_reject=st["acl_reject"] if t == 0 else 0,
                he_sampled=st["acl_sampled"], he_skipped=st["acl_skipped"],
                graph_sampled=st["graph_sampled"], graph_skipped=st["graph_skipped"],
                phase3_verify_s=sum(r["seconds"] for r in log if r["kind"] == "phase3"),
                phase4_verify_s=sum(r["seconds"] for r in log if r["kind"] == "phase4"),
                phase3_he_adds=sum(r["he_adds"] for r in log if r["kind"] == "phase3"))


def dist_ms(name: str, xs: list[float]) -> dict:
    """Median, IQR (q3 - q1) and mean of a list of seconds, in ms."""
    xs = sorted(xs)
    if len(xs) >= 2:
        q1, _, q3 = statistics.quantiles(xs, n=4, method="inclusive")
    else:
        q1 = q3 = xs[0]
    return {f"{name}": statistics.median(xs) * 1e3, f"{name}_iqr": (q3 - q1) * 1e3,
            f"{name}_mean": statistics.mean(xs) * 1e3}


def spot_section(cost: list[dict], det: list[dict], bits: int) -> list[str]:
    md = ["\n## (e) Spot-check ACL: EE cost and tamper detection vs sampling rate f\n",
          f"Cost: EE verification per Phase 3 request at N = {cost[0]['N']:,}, q = {cost[0]['q']:,} "
          f"({bits}-bit keys), batch of {cost[0]['batch']} requests, {cost[0]['reps']} reps "
          "(median [IQR], mean). The hash checks (VerifyIDX, C_Q, C_A) always run.\n" if cost else "",
          "| f | EE ms / request (median) | IQR | mean | share recomputed | HE adds / request | vs f = 1 |",
          "|---|---|---|---|---|---|---|"]
    base = next((r["ee_ms_per_query_mean"] for r in cost if r["f"] == 1.0), None)
    for r in cost:
        md.append(f"| {r['f']} | {r['ee_ms_per_query']:,.2f} | {r['ee_ms_per_query_iqr']:,.2f} | "
                  f"{r['ee_ms_per_query_mean']:,.2f} | {r['sampled_share']:.2f} | {r['he_adds_per_query']:,.0f} | "
                  f"{r['ee_ms_per_query_mean'] / base:.2f}x |" if base else "")
    if det:
        fs = sorted({r["f"] for r in det}, reverse=True)
        ts = sorted({r["t"] for r in det if r["t"] > 0})
        n = len({r["seed"] for r in det})
        md += ["", f"Detection: J2R on the e5_acl stream, a consistent cheating cloud modifies t HE aggregates "
               f"(of {det[0]['requests']} Phase 3 requests per run); {n} seeds per cell at 512 bits. "
               "Empirical rate of runs with at least one rejection / analytic 1 - (1 - f)^t.", "",
               "| f | " + " | ".join(f"t={t}" for t in ts) + " | false rejections (t=0) | EE verify s / run (P3 + P4) |",
               "|---|" + "---|" * (len(ts) + 2)]
        for f in fs:
            cells = []
            for t in ts:
                sel = [r for r in det if r["f"] == f and r["t"] == t]
                emp = statistics.mean(r["detected"] for r in sel) if sel else float("nan")
                cells.append(f"{emp:.3f} / {1 - (1 - f) ** t:.3f}")
            hon = [r for r in det if r["f"] == f and r["t"] == 0]
            ver = [r["phase3_verify_s"] + r["phase4_verify_s"] for r in det if r["f"] == f]
            md.append(f"| {f} | " + " | ".join(cells) + f" | {sum(r['false_reject'] for r in hon)} | "
                      f"{statistics.mean(ver):.3f} |")
    return md


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--n", type=int, default=100_000)
    ap.add_argument("--q", type=int, default=1_000)
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--bits", type=int, default=2048)
    ap.add_argument("--ns", default="10000,100000,1000000,10000000")
    ap.add_argument("--pool", type=int, default=100_000)
    ap.add_argument("--parts", default="abcd")
    ap.add_argument("--batch", type=int, default=20, help="(e) requests per timed batch")
    ap.add_argument("--tamper-trials", type=int, default=200, help="(e) seeds per (f, t) cell")
    ap.add_argument("--workers", type=int, default=8, help="(e) processes for the detection runs")
    args = ap.parse_args()
    if args.quick:
        args.n, args.q, args.reps, args.ns, args.pool = 10_000, 100, 2, "1000,10000,50000", 1000
        args.batch, args.tamper_trials = 10, min(args.tamper_trials, 20)
    t0 = time.time()
    pk, _ = paillier.keygen(args.bits)
    he = paillier.Paillier(pk)
    rng = random.Random(0)
    rows = []
    sels = [0.001, 0.005, 0.01, 0.05, 0.10, 0.25] if "a" in args.parts else []
    for sel in sels:
        repo = Repo(args.n, max(1, int(sel * args.n)), pk, rng)
        rows.append(dict(sweep="selectivity", **bench(repo, he, args.reps)))
        print(rows[-1], flush=True)
    Ns = [args.n // 10, args.n // 4, args.n // 2, args.n, args.n * 2] if "b" in args.parts else []
    for N in Ns:
        repo = Repo(N, args.q, pk, rng)
        rows.append(dict(sweep="repository", **bench(repo, he, args.reps)))
        print(rows[-1], flush=True)
    for j in ((1, 2, 4, 8) if "c" in args.parts else ()):
        feats = tuple(f"f{i}" for i in range(j))
        repo = Repo(args.n, args.q, pk, rng, feats)
        rows.append(dict(sweep="features", j_q=j, **bench(repo, he, args.reps)))
        print(rows[-1], flush=True)
    for N in ([int(x) for x in args.ns.split(",")] if "d" in args.parts else ()):
        repo = Repo(N, max(1, N // 100), pk, rng, pool=args.pool)
        big = N > 1_000_000
        rows.append(dict(sweep="scale", **bench(repo, he, 2 if big else args.reps, 1 if big else None)))
        print(rows[-1], flush=True)
        del repo
    cost, det = [], []
    if "e" in args.parts:
        repo = Repo(args.n, args.q, pk, rng)
        for f in SPOT_F:
            cost.append(spot_cost(repo, he, f, args.batch, args.reps, seed=int(f * 1000)))
            print(cost[-1], flush=True)
        del repo
        from concurrent.futures import ProcessPoolExecutor
        jobs = [(f, t, sd) for f in SPOT_F for t in SPOT_T for sd in range(1, args.tamper_trials + 1)]
        with ProcessPoolExecutor(args.workers) as ex:
            det = list(ex.map(spot_detect, *zip(*jobs), chunksize=4))
        write_csv("e2_acl_spot_cost.csv", cost)
        write_csv("e2_acl_spot_detect.csv", det)
    if rows:
        write_csv("e2_acl_scale.csv", rows)
    import platform
    md = [f"# Authenticated retrieval and ACL scalability ({platform.node()}, {args.bits}-bit Paillier, "
          f"|J| = {len(FEATS)} + realness, median of {args.reps}; IQR = q3 - q1 over the reps)\n"]
    cols = [("q", "q"), ("selectivity", "q/N"), ("retrieve_ms", "EPII retrieve (ms)"),
            ("aggregate_ms", "SG-HEF aggregate (ms)"), ("aggregate_ms_iqr", "aggregate IQR"),
            ("verify_idx_ms", "VerifyIDX (ms)"), ("acl_ms", "ACL total (ms)"), ("acl_ms_iqr", "ACL IQR"),
            ("acl_ms_mean", "ACL mean"),
            ("full_ms", "Full recompute (ms)"), ("fullhe_ms", "S-FullHE aggregate (ms)"), ("acl_hashes", "ACL hashes"), ("acl_he_adds", "ACL HE adds"),
            ("ee_bytes", "Bytes to EE")]
    for sweep, title, first in (("selectivity", f"(a) N = {args.n:,}, varying selectivity", None),
                                ("repository", f"(b) q = {args.q:,}, varying N", ("N", "N")),
                                ("features", f"(c) N = {args.n:,}, q = {args.q:,}, varying j_q", ("j_q", "j_q")),
                                ("scale", "(d) q/N = 1%, N up to 10^7 (shared ciphertext pool)", ("N", "N"))):
        if not any(r["sweep"] == sweep for r in rows):
            continue
        cs = ([first] if first else [("N", "N")]) + cols
        md += [f"\n## {title}\n", "| " + " | ".join(c[1] for c in cs) + " | Index build (ms) |",
               "|" + "---|" * (len(cs) + 1)]
        for r in rows:
            if r["sweep"] != sweep:
                continue
            cells = []
            for k, _ in cs:
                v = r.get(k, float("nan"))
                cells.append(f"{v:.2%}" if k == "selectivity" else (f"{v:,.2f}" if isinstance(v, float) else f"{v:,}"))
            md.append("| " + " | ".join(cells) + f" | {r['index_build_ms']:,.0f} |")
    if cost or det:
        md += spot_section(cost, det, args.bits)
    md.append(f"\nTotal time {time.time() - t0:.0f}s")
    (RESULTS / "e2_acl_scale.md").write_text("\n".join(md) + "\n")
    print("\n".join(md))


if __name__ == "__main__":
    main()
