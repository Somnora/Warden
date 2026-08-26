"""Ledger storage.

Two backends behind one interface. `MemoryLedger` is what the tests and the
mock demo use; `FirestoreLedger` is the real one. Both enforce the same
invariant: appends are sealed against the current tip, and nothing else can
write.

Firestore is the Google Cloud infrastructure service backing the audit trail.
It is a deliberate choice over a local file: the point of an audit ledger is
that it outlives the laptop that produced it and can be read by someone who
does not trust the person who ran the fleet.
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict
from typing import Any, Protocol

from warden.ledger.chain import Record, Verdict, append, verify

_CHECKPOINT_VERSION = 1


class LedgerCorruptionError(RuntimeError):
    """Raised when the durable checkpoint and stored chain disagree."""


class LedgerStore(Protocol):
    async def append(self, rec: Record) -> Record: ...
    async def read(self) -> list[Record]: ...
    async def verify(self) -> Verdict: ...


class MemoryLedger:
    """In-process ledger. Same sealing rules, no durability."""

    def __init__(self) -> None:
        self._chain: list[Record] = []
        self._lock = asyncio.Lock()

    async def append(self, rec: Record) -> Record:
        async with self._lock:
            sealed = append(self._chain, rec)
            self._chain.append(sealed)
            return sealed

    async def read(self) -> list[Record]:
        return list(self._chain)

    async def verify(self) -> Verdict:
        return verify(self._chain)


class FirestoreLedger:
    """Append-only chain in Firestore.

    Records live at {collection}/{run_id}/records/{seq:08d}. The zero-padded
    document id makes Firestore's lexical ordering the same as sequence
    ordering, so reads come back in chain order without a sort index.

    Concurrency: the seal has to see the true tip, so the read-modify-write is
    done inside a Firestore transaction. Two agents launching at once cannot
    both claim the same seq -- the loser retries against the new tip.
    """

    def __init__(self, project: str, run_id: str, *, collection: str = "warden_ledger"):
        from google.cloud import firestore  # imported lazily; tests don't need it

        self._fs = firestore.AsyncClient(project=project)
        self._firestore = firestore
        self.run_id = run_id
        self._root = self._fs.collection(collection).document(run_id)
        self._records = self._root.collection("records")

    async def append(self, rec: Record) -> Record:
        transaction = self._fs.transaction()
        return await self._append_txn(transaction, rec)

    async def _append_txn(self, transaction: Any, rec: Record) -> Record:
        firestore = self._firestore

        @firestore.async_transactional
        async def _txn(txn: Any) -> Record:
            # The parent checkpoint makes tail deletion detectable and also
            # serializes concurrent appenders on one transactionally-read doc.
            root_snapshot = await self._root.get(transaction=txn)
            checkpoint = root_snapshot.to_dict() if root_snapshot.exists else None
            chain_tip: list[Record]
            if checkpoint and checkpoint.get("checkpoint_version") == _CHECKPOINT_VERSION:
                tip_seq = checkpoint.get("tip_seq")
                tip_hash = checkpoint.get("tip_hash")
                if not isinstance(tip_seq, int) or not isinstance(tip_hash, str):
                    raise LedgerCorruptionError("ledger checkpoint is malformed")
                tip_snapshot = await self._records.document(f"{tip_seq:08d}").get(transaction=txn)
                if not tip_snapshot.exists:
                    raise LedgerCorruptionError(
                        f"ledger checkpoint references missing tail record {tip_seq}"
                    )
                tip = _from_doc(tip_snapshot.to_dict())
                if tip.seq != tip_seq or tip.entry_hash != tip_hash or tip.compute_hash() != tip.entry_hash:
                    raise LedgerCorruptionError("ledger tail does not match its checkpoint")
                chain_tip = [tip]
            else:
                # One-time migration path for ledgers written before durable
                # checkpoints were introduced.
                tip_q = self._records.order_by(
                    "seq", direction=firestore.Query.DESCENDING
                ).limit(1)
                tip_docs = [d async for d in tip_q.stream(transaction=txn)]
                chain_tip = [_from_doc(tip_docs[0].to_dict())] if tip_docs else []

            sealed = append(chain_tip, rec)
            txn.set(self._records.document(f"{sealed.seq:08d}"), _to_doc(sealed))
            txn.set(
                self._root,
                {
                    "checkpoint_version": _CHECKPOINT_VERSION,
                    "tip_seq": sealed.seq,
                    "tip_hash": sealed.entry_hash,
                    "record_count": sealed.seq + 1,
                },
                merge=True,
            )
            return sealed

        return await _txn(transaction)

    async def read(self) -> list[Record]:
        q = self._records.order_by("seq")
        return [_from_doc(d.to_dict()) async for d in q.stream()]

    async def verify(self) -> Verdict:
        transaction = self._fs.transaction()

        @self._firestore.async_transactional
        async def verify_snapshot(txn: Any) -> Verdict:
            # Read the records and checkpoint from one Firestore snapshot so a
            # concurrent append cannot produce a transient false tamper alert.
            snapshot = await self._root.get(transaction=txn)
            checkpoint = snapshot.to_dict() if snapshot.exists else None
            query = self._records.order_by("seq")
            chain = [_from_doc(doc.to_dict()) async for doc in query.stream(transaction=txn)]
            chain_verdict = verify(chain)
            if not chain_verdict.ok:
                return chain_verdict
            return _verify_checkpoint(chain, checkpoint)

        return await verify_snapshot(transaction)


def _to_doc(rec: Record) -> dict[str, Any]:
    d = asdict(rec)
    d["rules"] = list(rec.rules)
    d["redactions"] = list(rec.redactions)
    return d


def _from_doc(d: dict[str, Any]) -> Record:
    d = dict(d)
    d["rules"] = tuple(d.get("rules") or ())
    d["redactions"] = tuple(d.get("redactions") or ())
    return Record(**d)


def _verify_checkpoint(
    chain: list[Record], checkpoint: dict[str, Any] | None
) -> Verdict:
    """Verify the durable tip commitment after the hash-chain walk succeeds."""
    if not chain:
        if not checkpoint or checkpoint.get("tip_seq") is None:
            return Verdict(True, 0, None, "0 records verified")
        return Verdict(False, 0, 0, "checkpoint exists but the ledger is empty")

    tip = chain[-1]
    if not checkpoint or checkpoint.get("checkpoint_version") != _CHECKPOINT_VERSION:
        return Verdict(
            False,
            len(chain),
            tip.seq,
            "ledger records exist without a durable tail checkpoint",
        )
    if checkpoint.get("record_count") != len(chain):
        return Verdict(
            False,
            len(chain),
            tip.seq,
            "checkpoint record count does not match the stored chain",
        )
    if checkpoint.get("tip_seq") != tip.seq or checkpoint.get("tip_hash") != tip.entry_hash:
        return Verdict(
            False,
            len(chain),
            tip.seq,
            "stored chain tip does not match the durable checkpoint",
        )
    return Verdict(True, len(chain), None, f"{len(chain)} records and durable checkpoint verified")
