"""PT-S (journal v3 baseline): the VistaSIEM scorer on plaintext features.

Same contexts, release policy (k_min, VALUE / DECISION / HIDE), attack-aware graph contraction
(lineage.contract), drift, trusted history, adaptive decay, weights and thresholds as S, but the
features are computed directly from the plaintext events: no tokens, no encryption, no padding,
no KA, no cloud. Phase 5 is the EE's own code (EdgeEncryptor.phase5), driven with plaintext
"tokens" (the UTF-8 values), so any difference between PT-S and S can only come from the
protected pipeline. Label-free screening is not run (it does not affect classified alerts).

Exposes .ee, .sa, .reports like VistaSIEM, so common.vista_siem_alerts / vista_siem_scores work.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import replace

from . import lineage
from .model import AttackProfile, Config, Context, Event, Policy
from .protocol import IndexEntry
from .system import VistaSIEM


def _b(x: str) -> bytes:
    return x.encode()


class PlainTwin:
    def __init__(self, cfg: Config, profiles: list[AttackProfile], contexts: list[Context]):
        # the protected system is built only to reuse the EE's Phase 5 (no record is ever encrypted)
        base = replace(cfg, acl=False, graph_real_only=False, gamma=1.0, padding="dummy", screening=False,
                       precompute_workers=0)
        self._sys = VistaSIEM(base, profiles, contexts)
        self.cfg, self.ee, self.sa = base, self._sys.ee, self._sys.sa
        self.contexts = contexts
        self.profiles = {p.name: p for p in profiles}
        self.mu_prev = None
        self.reports: list = []

    def epoch_of(self, ts: float) -> int:
        return int(ts // self.cfg.epoch_len) + 1

    def _release(self, c: Context, evs: list[Event]):
        """Plaintext twin of the KA release over the context's matching records."""
        fp = self.ee.fp
        support = len(evs)
        eff = Policy.DECISION if c.policy is Policy.VALUE and support < self.cfg.k_min else c.policy
        y = {}
        for f in c.feats:
            if eff is Policy.HIDE:
                y[f] = None
                continue
            if c.source_weights:
                tot = sum(fp.encode(ev.feats.get(f, 0)) * c.source_weights.get(ev.src, 0) for ev in evs)
            else:
                tot = sum(fp.encode(ev.feats.get(f, 0)) for ev in evs)
            v = fp.decode(tot % fp.n) if self.cfg.frac_bits else fp.decode_int(tot % fp.n)
            y[f] = v if eff is Policy.VALUE else int(v >= c.threshold)
        return y

    def run_epoch(self, e: int, events: list[Event]) -> list:
        bl = self.cfg.bucket_len
        entries = {i: IndexEntry((_b(ev.user), _b(ev.res), _b(ev.cat), _b(ev.src)), int(ev.ts // bl), e, i)
                   for i, ev in enumerate(events)}
        Z = []
        for c in self.contexts:
            idx = [i for i, ev in enumerate(events)
                   if (not c.users or ev.user in c.users) and (not c.resources or ev.res in c.resources)
                   and (not c.categories or ev.cat in c.categories) and (not c.sources or ev.src in c.sources)]
            Z.append(dict(qid=c.qid, attack=c.attack, epoch=e, Q={(e, i) for i in idx},
                          y=self._release(c, [events[i] for i in idx])))
        profiles = {a: frozenset(_b(x) for x in p.categories) for a, p in self.profiles.items()}
        updates, mu = lineage.contract(Z, lambda rid: entries[rid[1]], profiles, None)
        drift = lineage.drift(mu, self.mu_prev)
        self.mu_prev = mu
        self.ee.epoch = e
        self.ee.user_of[e] = {_b(ev.user): ev.user for ev in events}
        alerts = self.ee.phase5(updates, drift)
        self.reports.append((e, len(events), drift, alerts))
        return alerts

    def run(self, events: list[Event]) -> list:
        by_epoch: dict[int, list[Event]] = defaultdict(list)
        for ev in sorted(events, key=lambda x: x.ts):
            by_epoch[self.epoch_of(ev.ts)].append(ev)
        for e in sorted(by_epoch):
            self.run_epoch(e, by_epoch[e])
        self._sys.close()
        return self.reports
