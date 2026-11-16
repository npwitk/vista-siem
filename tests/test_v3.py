"""Journal v3 switches: defaults keep the old behaviour; new mechanisms do what they claim."""

import random
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "experiments"))

from common import config  # noqa: E402

from vista_siem import lineage  # noqa: E402
from vista_siem.data.synth import SynthConfig, default_profiles_and_contexts, generate  # noqa: E402
from vista_siem.system import VistaSIEM  # noqa: E402

SC = SynthConfig(epochs=3, events_per_epoch=300, n_users=40, seed=4, n_low_and_slow=2, lns_epochs=3)


def _run(variant, sc=SC, **over):
    events, _ = generate(sc)
    profiles, contexts = default_profiles_and_contexts()
    s = VistaSIEM(config(variant, seed=4, **over), profiles, contexts)
    s.run(events)
    return s


def _log(s):
    return sorted(s.ee.score_log)  # token order varies with the random epoch keys; values are exact


# ============================================================================ spot-check ACL
@pytest.mark.parametrize("variant", ["S", "A2", "J2R"])
def test_acl_sample_one_is_bit_identical(variant):
    a, b = _run(variant), _run(variant, acl_sample=1.0)
    assert _log(a) == _log(b)
    assert a.ee.stats["acl_skipped"] == b.ee.stats["acl_skipped"] == 0


def test_spot_check_honest_run_scores_unchanged_and_no_rejections():
    full, spot = _run("J2R"), _run("J2R", acl_sample=0.3)
    assert _log(full) == _log(spot)
    st = spot.ee.stats
    assert st["acl_reject"] == st["graph_reject"] == st["graph_omitted"] == st["drift_reject"] == 0
    assert st["acl_skipped"] > 0 and st["graph_skipped"] > 0


def test_spot_check_graph_sample_gives_identical_updates():
    """Contracting the evidence restricted to sampled entities yields exactly their updates."""
    s = _run("J2R")
    Z = list(s.ee.accepted.values())
    entry_of = lambda rid: s.ee.epoch_entries[rid[1]]  # noqa: E731
    profiles = {a: frozenset(s.ee.token("C", c) for c in p.categories) for a, p in s.ee.profiles.items()}
    full, _ = lineage.contract(Z, entry_of, profiles)
    ents = sorted({u[0] for u in full})
    chosen = set(ents[::3])
    Zs = [dict(z, Q={r for r in z["Q"] if entry_of(r).tokens[0] in chosen}) for z in Z]
    part, _ = lineage.contract(Zs, entry_of, profiles)
    assert sorted((u[0], u[1], u[4]) for u in part) == sorted((u[0], u[1], u[4]) for u in full if u[0] in chosen)


def test_spot_check_detection_rate_matches_analytic():
    """A modified aggregate is rejected with probability f per request, so t modified requests
    are caught with probability 1 - (1 - f)^t."""
    f, n = 0.3, 600
    s = _run("J2R", acl_sample=f)
    fi = {x: j for j, x in enumerate(s.cfg.agg_features)}
    q = next(q for q in s.ee.make_queries() if s.cloud.auth_candidates(q["epoch"], q["tokens"])[0])
    good = s.cloud.acl_request(q, fi)
    bad = dict(good)
    x = q["feats"][0]
    bad["aggs"] = {**good["aggs"], x: s.cloud.he.add(good["aggs"][x], s.cloud.he.encrypt(1))}
    bad["C_A"] = lineage.c_a(good["C_Q"], q["feats"], bad["aggs"], good["realness"], spec=lineage.c_spec(q))

    def release(req):
        s.ka._released.clear()  # the KA releases a context once per epoch; the test replays it
        return s.ee.acl_release(q, req)

    caught = [release(bad) is None for _ in range(n)]
    rate = sum(caught) / n
    assert abs(rate - f) < 4 * (f * (1 - f) / n) ** 0.5
    t = 3
    groups = [any(caught[i:i + t]) for i in range(0, n - t + 1, t)]
    p = 1 - (1 - f) ** t
    assert abs(sum(groups) / len(groups) - p) < 4 * (p * (1 - p) / len(groups)) ** 0.5
    # the unmodified request is always accepted
    assert all(release(good) is not None for _ in range(50))


# ============================================================================ PT-S
@pytest.mark.parametrize("variant", ["S", "A2"])
def test_plaintext_twin_scores_equal_protected_scores(variant):
    """PT-S (plaintext features, same scorer and weights) scores exactly like S without padding."""
    from vista_siem.plaintext import PlainTwin

    events, _ = generate(SC)
    profiles, contexts = default_profiles_and_contexts()
    s = _run(variant)
    pt = PlainTwin(config(variant, seed=4), profiles, contexts)
    pt.run(events)
    assert len(pt.ee.score_log) == len(s.ee.score_log) > 0
    assert sorted(pt.ee.score_log) == _log(s)
    from common import vista_siem_alerts
    assert vista_siem_alerts(pt)[0] == vista_siem_alerts(s)[0]


# ============================================================================ filtered hunts
def _hunt_run(**over):
    from collections import Counter

    from vista_siem.aqrs import Spec

    events, truth = generate(SC)
    profiles, contexts = default_profiles_and_contexts()
    cfg = config("J2R", seed=4, **over)
    s = VistaSIEM(cfg, profiles, contexts)
    nb = int(cfg.epoch_len // cfg.bucket_len)
    users = [u for u, _ in Counter(ev.user for ev in events).most_common(12)]

    def hunter(e):
        b = (e - 1) * nb
        return ([Spec("U", u, frozenset({"auth_fail"})) for u in users[:4]]
                + [Spec("U", u, None, frozenset({b + 2, b + 3})) for u in users[4:8]]
                + [Spec("U", u, None) for u in users[8:]])

    s.hunter = hunter
    s.run(events)
    return s


def test_time_filtered_hunts_are_authenticated_and_scoped():
    s = _hunt_run()
    assert s.ee.stats["acl_reject"] == 0
    timed = [h for h in s.ee.hunt_log if h["spec"].buckets is not None]
    assert timed and all(h["ok"] for h in timed)
    # a time-filtered hunt retrieves only records of its buckets
    cohorts = [obj for _, kind, obj in s.bus.cloud_view if kind == "cohort"]
    for c in cohorts:
        for q in c["queries"]:
            if "B" in q["tokens"]:
                Q = s.cloud.candidates(c["epoch"], q["tokens"])
                assert all(s.cloud.entries[r].bucket in q["tokens"]["B"] for r in Q)


def test_entity_cat_padding_equalizes_category_cohorts():
    s = _hunt_run(cpad_mode="entity_cat")
    assert s.ee.stats["acl_reject"] == 0 and s.ee.stats["decoy"] > 0
    cohorts = [obj for _, kind, obj in s.bus.cloud_view if kind == "cohort"]
    checked = 0
    for c in cohorts:
        qs = c["queries"]
        if len(qs) > 1 and "C" in qs[0]["tokens"] and "B" not in qs[0]["tokens"]:
            n = {len(s.cloud.candidates(c["epoch"], q["tokens"])) for q in qs}
            live = [x for x in n if x > 0]
            assert len(set(live)) <= 1  # every active member of a category group has the same volume
            checked += 1
    assert checked > 0
