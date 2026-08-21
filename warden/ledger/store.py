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
            tip_q = self._records.order_by(
                "seq", direction=firestore.Query.DESCENDING
            ).limit(1)
            tip_docs = [d async for d in tip_q.stream(transaction=txn)]
            chain_tip = [_from_doc(tip_docs[0].to_dict())] if tip_docs else []

            sealed = append(chain_tip, rec)
            txn.set(self._records.document(f"{sealed.seq:08d}"), _to_doc(sealed))
            return sealed

        return await _txn(transaction)

    async def read(self) -> list[Record]:
        q = self._records.order_by("seq")
        return [_from_doc(d.to_dict()) async for d in q.stream()]

    async def verify(self) -> Verdict:
        return verify(await self.read())


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
