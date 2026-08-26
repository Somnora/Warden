"""The tamper-evidence property is the product claim. Test it directly."""

from dataclasses import asdict

import pytest

from warden.ledger.chain import GENESIS, Record, append, digest_args, verify
from warden.ledger.store import _verify_checkpoint


def mk(seq_hint: str, **kw) -> Record:
    base = dict(
        seq=0, ts="2026-08-20T12:00:00Z", fleet="test", run_id="r1",
        actor="provisioner", tool="launch_gpu", disposition="allow",
        reason=seq_hint, rules=("tools.launch_gpu=allow",),
        args_digest=digest_args({"region": "us-west1"}),
    )
    base.update(kw)
    return Record(**base)


def build(n: int) -> list[Record]:
    chain: list[Record] = []
    for i in range(n):
        chain.append(append(chain, mk(f"action-{i}")))
    return chain


def test_genesis_record_anchors_to_zero():
    chain = build(1)
    assert chain[0].seq == 0
    assert chain[0].prev_hash == GENESIS
    assert chain[0].entry_hash == chain[0].compute_hash()


def test_clean_chain_verifies():
    v = verify(build(5))
    assert v.ok, v.detail
    assert v.checked == 5


def test_editing_a_record_is_detected():
    chain = build(5)
    tampered = Record(**{**asdict(chain[2]), "reason": "silently changed"})
    chain[2] = tampered
    v = verify(chain)
    assert not v.ok
    assert v.broken_at == 2
    assert "altered" in v.detail


def test_deleting_a_record_is_detected():
    chain = build(5)
    del chain[2]
    v = verify(chain)
    assert not v.ok
    assert "removed or replaced" in v.detail


def test_reordering_is_detected():
    chain = build(5)
    chain[3], chain[4] = chain[4], chain[3]
    v = verify(chain)
    assert not v.ok


def test_reseal_after_edit_still_breaks_the_chain():
    """The interesting case: an attacker who edits AND re-hashes.

    Re-sealing fixes the record's own digest, so a naive checker passes. The
    chain still breaks, because the next record commits to the old hash.
    """
    chain = build(5)
    edited = Record(**{**asdict(chain[2]), "cost_usd": 0.0}).sealed()
    assert edited.compute_hash() == edited.entry_hash  # self-consistent now
    chain[2] = edited
    v = verify(chain)
    assert not v.ok
    assert v.broken_at == 3


def test_args_are_committed_but_not_stored():
    d1 = digest_args({"region": "us-west1", "secret": "hunter2"})
    d2 = digest_args({"secret": "hunter2", "region": "us-west1"})
    assert d1 == d2, "digest must be key-order independent"
    assert "hunter2" not in d1
    assert d1 != digest_args({"region": "us-central1", "secret": "hunter2"})


def test_durable_checkpoint_detects_tail_deletion():
    chain = build(3)
    checkpoint = {
        "checkpoint_version": 1,
        "tip_seq": chain[-1].seq,
        "tip_hash": chain[-1].entry_hash,
        "record_count": len(chain),
    }
    assert _verify_checkpoint(chain, checkpoint).ok
    truncated = chain[:-1]
    assert verify(truncated).ok, "a bare hash chain cannot detect tail truncation"
    verdict = _verify_checkpoint(truncated, checkpoint)
    assert not verdict.ok
    assert "checkpoint" in verdict.detail
