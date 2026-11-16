"""Journal r1 (second pre-submission review): uniform cohort verification, historical hunts
verified against the MMR, the encrypted partition in the checkpoint, and group-wide investigation."""

import sys
from collections import Counter
from dataclasses import replace
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "experiments"))

from common import config  # noqa: E402

from vista_siem import lineage  # noqa: E402
from vista_siem.aqrs import Spec  # noqa: E402
from vista_siem.crypto.primitives import H  # noqa: E402
from vista_siem.data.synth import SynthConfig, default_profiles_and_contexts, generate  # noqa: E402
from vista_siem.system import VistaSIEM  # noqa: E402

SC = SynthConfig(epochs=3, events_per_epoch=300, n_users=40, seed=4, n_low_and_slow=2, lns_epochs=3)


def _run(**over):
    events, _ = generate(SC)
    profiles, contexts = default_profiles_and_contexts()
    s = VistaSIEM(config("J2R", seed=4, **over), profiles, contexts)
    users = [u for u, _ in Counter(ev.user for ev in events).most_common(8)]
    s.hunter = lambda e: [Spec("U", u, None) for u in users]
    s.run(events)
    s.users = users
    return s


@pytest.fixture(scope="module")
def run():
    return _run()


def _real_token(s, user, epoch=None):
    keys = s.ka.epoch_keys(epoch) if epoch is not None else None
    return s.ee.token("U", user, epoch, keys)


def _tamper(s, user, which, epoch=None):
    """Make the cloud consistently alter one member's aggregate (aggs and C_A recomputed, so only
    the EE's recomputation catches it). which: "real" or "cover"."""
    orig = s.cloud.cohort
    tok = _real_token(s, user, epoch)

    def cohort(order, fi):
        reqs = orig(order, fi)
        is_real = [tok in q["tokens"]["U"] for q in order]
        q = order[is_real.index(True)] if which == "real" else order[is_real.index(False)]
        r = reqs[q["qid"]]
        aggs = {f: s.cloud.he.add(c, c) for f, c in r["aggs"].items()}  # doubles the encrypted sum
        r["aggs"] = aggs
        r["C_A"] = lineage.c_a(r["C_Q"], q["feats"], aggs, r["realness"], spec=lineage.c_spec(q))
        return reqs

    s.cloud.cohort = cohort
    return orig


# ============================================================================ partition commitment
def test_partition_is_bound_in_checkpoint_and_recoverable(run):
    s = run
    for tau in range(1, s.ee.epoch + 1):
        cp, _ = s.cloud.checkpoints[tau]
        iv, ct = s.cloud.partitions[tau]
        assert len(cp) == 6 and H(iv + ct) == cp[5]
    keys = s.ka.epoch_keys(1)
    groups = s.ee._hist_groups(1, keys, s.ee._verified_cp(1))
    assert groups and all(len(g) >= 5 for (d, _), (g, _) in groups.items() if d == "U")


def test_tampered_partition_is_rejected():
    s = _run()
    iv, ct = s.cloud.partitions[1]
    s.cloud.partitions[1] = (iv, ct[:-1] + bytes([ct[-1] ^ 1]))
    assert s.ee._hist_groups(1, s.ka.epoch_keys(1), s.ee._verified_cp(1)) is None


# ============================================================================ uniform cohort verification
def test_honest_hunts_verify_every_member(run):
    s = run
    covers = [a for a in s.ee.acl_log if a["kind"] == "phase3_cover"]
    assert covers and all(a["ok"] for a in covers)
    assert all(h["ok"] and h["cohort_ok"] for h in s.ee.hunt_log)
    # every cohort member was verified: covers per hunt = cohort size - 1
    assert len(covers) == sum(len(h["members"]) - 1 for h in s.ee.hunt_log)


@pytest.mark.parametrize("which", ["real", "cover"])
def test_altered_member_rejects_whole_cohort(which):
    s = _run()
    user = s.users[0]
    _tamper(s, user, which)
    assert s.ee.hunt([Spec("U", user, None)]) == []  # same reaction whichever member was altered
    assert not s.ee.hunt_log[-1]["cohort_ok"] or which == "real"


def test_real_only_verification_leaks_which_member_is_real():
    """The journal v2/v3 behaviour the review flagged: an altered cover passes unnoticed while an
    altered real member is rejected, so the EE's reaction tells the cloud which member is real."""
    s = _run(aqrs_verify="real")
    user = s.users[0]
    _tamper(s, user, "cover")
    assert len(s.ee.hunt([Spec("U", user, None)])) == 1
    s2 = _run(aqrs_verify="real")
    _tamper(s2, user, "real")
    assert s2.ee.hunt([Spec("U", user, None)]) == []


# ============================================================================ historical hunts
def test_historical_hunt_is_verified_against_the_mmr():
    s = _run()
    user = s.users[0]
    z = s.ee.hunt([Spec("U", user, None)], epoch=1)
    assert len(z) == 1 and z[0]["epoch"] == 1 and z[0]["Q"]
    hist = [a for a in s.ee.acl_log if a.get("historical")]
    assert hist and all(a["ok"] for a in hist)
    assert s.ee.stats["hist_records_fetched"] > 0
    assert s.ee.hunt_log[-1]["k_eff"] >= 5  # cohort rebuilt from the encrypted partition of epoch 1
    # a cloud that substitutes a stored ciphertext of epoch 1 (and aggregates over it) is caught by the MMR
    rid = sorted(z[0]["Q"])[0]
    rec = s.cloud.records[rid]
    s.cloud.records[rid] = replace(rec, X=(s.cloud.he.add(rec.X[0], rec.X[0]),) + tuple(rec.X[1:]))
    assert s.ee.hunt([Spec("U", user, None)], epoch=1) == []


# ============================================================================ group-wide investigation
def test_group_investigation_keeps_the_evidence_and_queries_the_whole_group(run):
    s = run
    alerts = [d for d in s.sa.alerts if d.attack]
    if not alerts:
        pytest.skip("no attack alert in this small run")
    d = alerts[0]
    a = s.investigate(d)
    s.sa.inv_cohort = False
    b = s.investigate(d)
    s.sa.inv_cohort = True
    assert a.identity == b.identity
    assert sorted(a.plaintexts) == sorted(b.plaintexts)  # same evidence, same disclosure
    assert a.group_queries >= 5 * len(a.window) > b.group_queries == len(b.window)
    assert a.verified_records >= b.verified_records
    assert a.decrypted == b.decrypted <= a.verified_records
    assert not a.failed_epochs and not a.index_failed_epochs
