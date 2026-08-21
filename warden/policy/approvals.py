"""Human approval gate.

A gated tool call parks here until a person decides. The agent is never handed
a way to approve itself: `request` and `check` are all the fleet can reach,
while `grant` and `deny` are only exposed on the operator surface (the Cloud
Run /approvals endpoints and the CLI). That split is the point.

Approvals are keyed by (run_id, tool, args_digest), so approving one launch
does not silently approve a second, different launch later in the same run.
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Protocol

from warden.ledger.chain import digest_args


class ApprovalState(str, Enum):
    PENDING = "pending"
    GRANTED = "granted"
    DENIED = "denied"
    CONSUMED = "consumed"


@dataclass(frozen=True)
class Approval:
    status: ApprovalState
    approver: str | None = None
    note: str | None = None


@dataclass
class Ticket:
    approval_id: str
    run_id: str
    tool: str
    args_digest: str
    actor: str
    reason: str
    requested_at: str
    status: ApprovalState = ApprovalState.PENDING
    approver: str | None = None
    note: str | None = None
    preflight: dict[str, Any] = field(default_factory=dict)


def _key(run_id: str, tool: str, args: dict[str, Any]) -> str:
    return f"{run_id}:{tool}:{digest_args(args)[:16]}"


class ApprovalStore(Protocol):
    async def check(self, *, run_id: str, tool: str, args: dict[str, Any]) -> Approval: ...
    async def claim(self, *, run_id: str, tool: str, args: dict[str, Any]) -> Approval: ...
    async def request(
        self, *, run_id: str, tool: str, args: dict[str, Any], actor: str, reason: str,
        preflight: dict[str, Any] | None = None,
    ) -> str: ...


class MemoryApprovals:
    """In-process approvals, used by tests and the single-process demo."""

    def __init__(self, *, auto_grant: bool = False, auto_approver: str = "auto") -> None:
        # auto_grant exists ONLY for unattended test runs. It is never set by
        # the Cloud Run service; see warden.server.
        self._auto = auto_grant
        self._auto_approver = auto_approver
        self._tickets: dict[str, Ticket] = {}
        self._lock = asyncio.Lock()

    async def check(self, *, run_id: str, tool: str, args: dict[str, Any]) -> Approval:
        k = _key(run_id, tool, args)
        async with self._lock:
            t = self._tickets.get(k)
            if t is None:
                if self._auto:
                    return Approval(ApprovalState.GRANTED, self._auto_approver, "auto-grant")
                return Approval(ApprovalState.PENDING)
            return Approval(t.status, t.approver, t.note)

    async def request(
        self, *, run_id: str, tool: str, args: dict[str, Any], actor: str, reason: str,
        preflight: dict[str, Any] | None = None,
    ) -> str:
        k = _key(run_id, tool, args)
        async with self._lock:
            if k in self._tickets:
                return self._tickets[k].approval_id
            t = Ticket(
                approval_id=k,
                run_id=run_id,
                tool=tool,
                args_digest=digest_args(args),
                actor=actor,
                reason=reason,
                requested_at=datetime.now(timezone.utc)
                .isoformat(timespec="seconds")
                .replace("+00:00", "Z"),
                preflight=preflight or {},
            )
            self._tickets[k] = t
            return t.approval_id

    async def claim(self, *, run_id: str, tool: str, args: dict[str, Any]) -> Approval:
        """Atomically consume a human grant for one exact tool invocation."""
        k = _key(run_id, tool, args)
        async with self._lock:
            t = self._tickets.get(k)
            if t is None:
                if self._auto:
                    return Approval(ApprovalState.GRANTED, self._auto_approver, "auto-grant")
                return Approval(ApprovalState.PENDING)
            if t.status is ApprovalState.GRANTED:
                t.status = ApprovalState.CONSUMED
                return Approval(ApprovalState.GRANTED, t.approver, t.note)
            return Approval(t.status, t.approver, t.note)

    # -- operator surface (not reachable from an agent) --------------------

    async def pending(self) -> list[Ticket]:
        async with self._lock:
            return [t for t in self._tickets.values() if t.status is ApprovalState.PENDING]

    async def decide(
        self, approval_id: str, *, granted: bool, approver: str, note: str | None = None
    ) -> Ticket:
        async with self._lock:
            t = self._tickets.get(approval_id)
            if t is None:
                raise KeyError(approval_id)
            if t.status is not ApprovalState.PENDING:
                raise ValueError(f"approval {approval_id} already {t.status.value}")
            t.status = ApprovalState.GRANTED if granted else ApprovalState.DENIED
            t.approver = approver
            t.note = note
            return t


class FirestoreApprovals:
    """Transactional, one-time approvals shared by all Cloud Run instances."""

    def __init__(self, project: str, *, collection: str = "warden_approvals") -> None:
        from google.cloud import firestore

        self._fs = firestore.AsyncClient(project=project)
        self._firestore = firestore
        self._tickets = self._fs.collection(collection)

    async def check(self, *, run_id: str, tool: str, args: dict[str, Any]) -> Approval:
        snapshot = await self._tickets.document(_key(run_id, tool, args)).get()
        if not snapshot.exists:
            return Approval(ApprovalState.PENDING)
        ticket = _ticket_from_doc(snapshot.to_dict())
        return Approval(ticket.status, ticket.approver, ticket.note)

    async def request(
        self, *, run_id: str, tool: str, args: dict[str, Any], actor: str, reason: str,
        preflight: dict[str, Any] | None = None,
    ) -> str:
        approval_id = _key(run_id, tool, args)
        ref = self._tickets.document(approval_id)
        transaction = self._fs.transaction()

        @self._firestore.async_transactional
        async def create_if_absent(txn: Any) -> str:
            snapshot = await ref.get(transaction=txn)
            if snapshot.exists:
                return approval_id
            ticket = Ticket(
                approval_id=approval_id, run_id=run_id, tool=tool,
                args_digest=digest_args(args), actor=actor, reason=reason,
                requested_at=_timestamp(), preflight=preflight or {},
            )
            txn.set(ref, _ticket_doc(ticket))
            return approval_id

        return await create_if_absent(transaction)

    async def claim(self, *, run_id: str, tool: str, args: dict[str, Any]) -> Approval:
        ref = self._tickets.document(_key(run_id, tool, args))
        transaction = self._fs.transaction()

        @self._firestore.async_transactional
        async def consume_grant(txn: Any) -> Approval:
            snapshot = await ref.get(transaction=txn)
            if not snapshot.exists:
                return Approval(ApprovalState.PENDING)
            ticket = _ticket_from_doc(snapshot.to_dict())
            if ticket.status is ApprovalState.GRANTED:
                txn.update(ref, {"status": ApprovalState.CONSUMED.value})
                return Approval(ApprovalState.GRANTED, ticket.approver, ticket.note)
            return Approval(ticket.status, ticket.approver, ticket.note)

        return await consume_grant(transaction)

    async def pending(self) -> list[Ticket]:
        query = self._tickets.where("status", "==", ApprovalState.PENDING.value).order_by("requested_at")
        return [_ticket_from_doc(snapshot.to_dict()) async for snapshot in query.stream()]

    async def decide(
        self, approval_id: str, *, granted: bool, approver: str, note: str | None = None
    ) -> Ticket:
        ref = self._tickets.document(approval_id)
        transaction = self._fs.transaction()

        @self._firestore.async_transactional
        async def decide_once(txn: Any) -> Ticket:
            snapshot = await ref.get(transaction=txn)
            if not snapshot.exists:
                raise KeyError(approval_id)
            ticket = _ticket_from_doc(snapshot.to_dict())
            if ticket.status is not ApprovalState.PENDING:
                raise ValueError(f"approval {approval_id} already {ticket.status.value}")
            ticket.status = ApprovalState.GRANTED if granted else ApprovalState.DENIED
            ticket.approver = approver
            ticket.note = note
            txn.set(ref, _ticket_doc(ticket))
            return ticket

        return await decide_once(transaction)


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _ticket_doc(ticket: Ticket) -> dict[str, Any]:
    data = asdict(ticket)
    data["status"] = ticket.status.value
    return data


def _ticket_from_doc(data: dict[str, Any]) -> Ticket:
    value = dict(data)
    value["status"] = ApprovalState(value.get("status", ApprovalState.PENDING.value))
    value["preflight"] = value.get("preflight") or {}
    return Ticket(**value)
