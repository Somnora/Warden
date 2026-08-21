"""The audit chain.

Every governed action becomes one record. Each record commits to the one
before it by hash, so the ledger detects edits and deletions rather than
merely discouraging them. This module is pure -- no Firestore, no clock, no
randomness -- so the tamper-evidence property can be tested directly.

The chain answers one question an auditor actually asks: "is this the same
history you showed me last week?"
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any, Iterable, Sequence

GENESIS = "0" * 64


@dataclass(frozen=True)
class Record:
    """One governed action.

    `seq` is the position in the chain, `prev_hash` commits to history, and
    `entry_hash` commits to this record's own content. Nothing in here is
    optional -- a record that cannot be hashed cannot be appended.
    """

    seq: int
    ts: str                     # RFC3339, supplied by the caller
    fleet: str
    run_id: str
    actor: str                  # which agent in the fleet
    tool: str
    disposition: str            # allow | approve | deny
    reason: str
    rules: tuple[str, ...] = field(default_factory=tuple)
    args_digest: str = ""       # digest of arguments, never the arguments
    redactions: tuple[str, ...] = field(default_factory=tuple)
    approver: str | None = None
    outcome: str | None = None  # ok | error | refused
    cost_usd: float | None = None
    prev_hash: str = GENESIS
    entry_hash: str = ""

    def payload(self) -> dict[str, Any]:
        """The subset that is hashed. `entry_hash` excludes itself."""
        d = asdict(self)
        d.pop("entry_hash", None)
        d["rules"] = list(self.rules)
        d["redactions"] = list(self.redactions)
        return d

    def compute_hash(self) -> str:
        # sort_keys + compact separators so the digest is stable across
        # Python versions and across the Firestore round trip.
        blob = json.dumps(self.payload(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def sealed(self) -> "Record":
        return replace_hash(self, self.compute_hash())


def replace_hash(rec: Record, digest: str) -> Record:
    d = asdict(rec)
    d["rules"] = tuple(rec.rules)
    d["redactions"] = tuple(rec.redactions)
    d["entry_hash"] = digest
    return Record(**d)


def digest_args(args: dict[str, Any] | None) -> str:
    """Commit to the arguments without storing them.

    The ledger has to prove which call was made without becoming a second
    copy of whatever the call carried.
    """
    blob = json.dumps(args or {}, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def append(chain: Sequence[Record], rec: Record) -> Record:
    """Seal `rec` onto the end of `chain`."""
    tip = chain[-1] if chain else None
    d = asdict(rec)
    d["rules"] = tuple(rec.rules)
    d["redactions"] = tuple(rec.redactions)
    d["seq"] = (tip.seq + 1) if tip else 0
    d["prev_hash"] = tip.entry_hash if tip else GENESIS
    staged = Record(**d)
    return staged.sealed()


@dataclass(frozen=True)
class Verdict:
    ok: bool
    checked: int
    broken_at: int | None = None
    detail: str = ""


def verify(chain: Iterable[Record]) -> Verdict:
    """Walk the chain and report the first break.

    Catches three distinct failures: a record whose content was edited (its
    own hash no longer matches), a record spliced out (prev_hash mismatch),
    and a reordering (seq discontinuity).
    """
    prev: Record | None = None
    n = 0
    for rec in chain:
        n += 1
        if rec.compute_hash() != rec.entry_hash:
            return Verdict(False, n, rec.seq, f"record {rec.seq} content was altered")

        expected_prev = prev.entry_hash if prev else GENESIS
        if rec.prev_hash != expected_prev:
            return Verdict(
                False, n, rec.seq,
                f"record {rec.seq} does not follow {prev.seq if prev else 'genesis'}"
                " -- a record was removed or replaced",
            )

        expected_seq = (prev.seq + 1) if prev else 0
        if rec.seq != expected_seq:
            return Verdict(
                False, n, rec.seq,
                f"record out of order: expected seq {expected_seq}, found {rec.seq}",
            )
        prev = rec
    return Verdict(True, n, None, f"{n} records verified")
