"""Human approval gate.

A gated tool call parks here until a person decides. The agent is never handed
a way to approve itself: the fleet reaches only `request` and the atomic
single-use `claim`, while `decide` is exposed only on the operator surface
(the Cloud Run approval endpoint and CLI). That split is the point.

Approvals are keyed by (run_id, tool, args_digest), so approving one launch
does not silently approve a second, different launch later in the same run.
"""

from __future__ import annotations

import asyncio
import hashlib
import math
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Protocol

from warden.identity import role_satisfies
from warden.ledger.chain import digest_args


class ApprovalState(str, Enum):
    PENDING = "pending"
    GRANTED = "granted"
    DENIED = "denied"
    CONSUMED = "consumed"
    EXPIRED = "expired"


@dataclass(frozen=True)
class Approval:
    status: ApprovalState
    approver: str | None = None
    note: str | None = None


@dataclass(frozen=True)
class ApprovalRequirement:
    """Threshold and separation rules for one exact governed action."""

    required_approvals: int = 1
    minimum_role: str = "approver"
    require_separation_from_requester: bool = True

    def __post_init__(self) -> None:
        _validate_requirement(self)


@dataclass(frozen=True)
class ApprovalVote:
    principal: str
    role: str
    granted: bool
    note: str | None
    decided_at: str


@dataclass
class Ticket:
    approval_id: str
    run_id: str
    tool: str
    args_digest: str
    actor: str
    reason: str
    requested_at: str
    expires_at: str | None = None
    status: ApprovalState = ApprovalState.PENDING
    approver: str | None = None
    note: str | None = None
    preflight: dict[str, Any] = field(default_factory=dict)
    requested_by: str | None = None
    required_approvals: int = 1
    minimum_role: str = "approver"
    require_separation_from_requester: bool = True
    votes: list[ApprovalVote] = field(default_factory=list)


def _key(run_id: str, tool: str, args: dict[str, Any], actor: str) -> str:
    """Return a fixed-size, Firestore-safe identifier for one exact action.

    Hashing the complete composite avoids raw slashes in document IDs and
    avoids the 64-bit collision surface of a truncated argument digest.
    Length-prefixing prevents ambiguous concatenations.
    """
    material = "".join(
        f"{len(value)}:{value}"
        for value in (str(run_id), str(actor), str(tool), digest_args(args))
    )
    return f"approval-{hashlib.sha256(material.encode('utf-8')).hexdigest()}"


class ApprovalStore(Protocol):
    async def check(
        self, *, run_id: str, tool: str, args: dict[str, Any], actor: str
    ) -> Approval: ...
    async def claim(
        self, *, run_id: str, tool: str, args: dict[str, Any], actor: str
    ) -> Approval: ...
    async def request(
        self, *, run_id: str, tool: str, args: dict[str, Any], actor: str, reason: str,
        preflight: dict[str, Any] | None = None,
        requirement: ApprovalRequirement | None = None, requester: str | None = None,
    ) -> str: ...


class MemoryApprovals:
    """In-process approvals, used by tests and the single-process demo."""

    def __init__(
        self, *, auto_grant: bool = False, auto_approver: str = "auto",
        ttl_seconds: float = 900,
    ) -> None:
        # auto_grant exists ONLY for unattended test runs. It is never set by
        # the Cloud Run service; see warden.server.
        self._auto = auto_grant
        self._auto_approver = auto_approver
        if (
            isinstance(ttl_seconds, bool)
            or not isinstance(ttl_seconds, (int, float))
            or not math.isfinite(ttl_seconds)
            or ttl_seconds < 0
        ):
            raise ValueError("approval ttl_seconds must be non-negative")
        self._ttl_seconds = ttl_seconds
        self._tickets: dict[str, Ticket] = {}
        self._auto_claimed: set[str] = set()
        self._lock = asyncio.Lock()

    async def check(
        self, *, run_id: str, tool: str, args: dict[str, Any], actor: str
    ) -> Approval:
        k = _key(run_id, tool, args, actor)
        async with self._lock:
            t = self._tickets.get(k)
            if t is None:
                if self._auto:
                    state = ApprovalState.CONSUMED if k in self._auto_claimed else ApprovalState.GRANTED
                    return Approval(state, self._auto_approver, "auto-grant")
                return Approval(ApprovalState.PENDING)
            if _is_expired(t):
                t.status = ApprovalState.EXPIRED
            return Approval(t.status, t.approver, t.note)

    async def request(
        self, *, run_id: str, tool: str, args: dict[str, Any], actor: str, reason: str,
        preflight: dict[str, Any] | None = None,
        requirement: ApprovalRequirement | None = None, requester: str | None = None,
    ) -> str:
        k = _key(run_id, tool, args, actor)
        async with self._lock:
            if k in self._tickets:
                return self._tickets[k].approval_id
            req = requirement or ApprovalRequirement()
            _validate_requirement(req)
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
                expires_at=_expires_at(self._ttl_seconds),
                preflight=preflight or {},
                requested_by=requester,
                required_approvals=req.required_approvals,
                minimum_role=req.minimum_role,
                require_separation_from_requester=req.require_separation_from_requester,
            )
            self._tickets[k] = t
            return t.approval_id

    async def claim(
        self, *, run_id: str, tool: str, args: dict[str, Any], actor: str
    ) -> Approval:
        """Atomically consume a human grant for one exact tool invocation."""
        k = _key(run_id, tool, args, actor)
        async with self._lock:
            t = self._tickets.get(k)
            if t is None:
                if self._auto:
                    if k in self._auto_claimed:
                        return Approval(ApprovalState.CONSUMED, self._auto_approver, "auto-grant")
                    self._auto_claimed.add(k)
                    return Approval(ApprovalState.GRANTED, self._auto_approver, "auto-grant")
                return Approval(ApprovalState.PENDING)
            if _is_expired(t):
                t.status = ApprovalState.EXPIRED
                return Approval(ApprovalState.EXPIRED, t.approver, t.note)
            if t.status is ApprovalState.GRANTED:
                t.status = ApprovalState.CONSUMED
                return Approval(ApprovalState.GRANTED, t.approver, t.note)
            return Approval(t.status, t.approver, t.note)

    # -- operator surface (not reachable from an agent) --------------------

    async def pending(self) -> list[Ticket]:
        async with self._lock:
            for ticket in self._tickets.values():
                if ticket.status is ApprovalState.PENDING and _is_expired(ticket):
                    ticket.status = ApprovalState.EXPIRED
            return [
                _copy_ticket(t)
                for t in self._tickets.values()
                if t.status is ApprovalState.PENDING
            ]

    async def decide(
        self, approval_id: str, *, granted: bool, approver: str, note: str | None = None,
        approver_role: str = "administrator",
    ) -> Ticket:
        async with self._lock:
            t = self._tickets.get(approval_id)
            if t is None:
                raise KeyError(approval_id)
            if _is_expired(t):
                t.status = ApprovalState.EXPIRED
                raise ValueError(f"approval {approval_id} already expired")
            _apply_vote(t, granted=granted, approver=approver, approver_role=approver_role, note=note)
            return _copy_ticket(t)


class FirestoreApprovals:
    """Transactional, one-time approvals shared by all Cloud Run instances."""

    def __init__(
        self, project: str, *, collection: str = "warden_approvals",
        ttl_seconds: float = 900,
    ) -> None:
        from google.cloud import firestore

        self._fs = firestore.AsyncClient(project=project)
        self._firestore = firestore
        self._tickets = self._fs.collection(collection)
        if (
            isinstance(ttl_seconds, bool)
            or not isinstance(ttl_seconds, (int, float))
            or not math.isfinite(ttl_seconds)
            or ttl_seconds < 0
        ):
            raise ValueError("approval ttl_seconds must be non-negative")
        self._ttl_seconds = ttl_seconds

    async def check(
        self, *, run_id: str, tool: str, args: dict[str, Any], actor: str
    ) -> Approval:
        snapshot = await self._tickets.document(_key(run_id, tool, args, actor)).get()
        if not snapshot.exists:
            return Approval(ApprovalState.PENDING)
        ticket = _ticket_from_doc(snapshot.to_dict())
        if _is_expired(ticket):
            return Approval(ApprovalState.EXPIRED, ticket.approver, ticket.note)
        return Approval(ticket.status, ticket.approver, ticket.note)

    async def request(
        self, *, run_id: str, tool: str, args: dict[str, Any], actor: str, reason: str,
        preflight: dict[str, Any] | None = None,
        requirement: ApprovalRequirement | None = None, requester: str | None = None,
    ) -> str:
        approval_id = _key(run_id, tool, args, actor)
        ref = self._tickets.document(approval_id)
        transaction = self._fs.transaction()

        @self._firestore.async_transactional
        async def create_if_absent(txn: Any) -> str:
            snapshot = await ref.get(transaction=txn)
            if snapshot.exists:
                return approval_id
            req = requirement or ApprovalRequirement()
            _validate_requirement(req)
            ticket = Ticket(
                approval_id=approval_id, run_id=run_id, tool=tool,
                args_digest=digest_args(args), actor=actor, reason=reason,
                requested_at=_timestamp(), expires_at=_expires_at(self._ttl_seconds),
                preflight=preflight or {},
                requested_by=requester,
                required_approvals=req.required_approvals,
                minimum_role=req.minimum_role,
                require_separation_from_requester=req.require_separation_from_requester,
            )
            txn.set(ref, _ticket_doc(ticket))
            return approval_id

        return await create_if_absent(transaction)

    async def claim(
        self, *, run_id: str, tool: str, args: dict[str, Any], actor: str
    ) -> Approval:
        ref = self._tickets.document(_key(run_id, tool, args, actor))
        transaction = self._fs.transaction()

        @self._firestore.async_transactional
        async def consume_grant(txn: Any) -> Approval:
            snapshot = await ref.get(transaction=txn)
            if not snapshot.exists:
                return Approval(ApprovalState.PENDING)
            ticket = _ticket_from_doc(snapshot.to_dict())
            if _is_expired(ticket):
                txn.update(ref, {"status": ApprovalState.EXPIRED.value})
                return Approval(ApprovalState.EXPIRED, ticket.approver, ticket.note)
            if ticket.status is ApprovalState.GRANTED:
                txn.update(ref, {"status": ApprovalState.CONSUMED.value})
                return Approval(ApprovalState.GRANTED, ticket.approver, ticket.note)
            return Approval(ticket.status, ticket.approver, ticket.note)

        return await consume_grant(transaction)

    async def pending(self) -> list[Ticket]:
        query = self._tickets.where("status", "==", ApprovalState.PENDING.value).order_by("requested_at")
        tickets = [_ticket_from_doc(snapshot.to_dict()) async for snapshot in query.stream()]
        return [ticket for ticket in tickets if not _is_expired(ticket)]

    async def decide(
        self, approval_id: str, *, granted: bool, approver: str, note: str | None = None,
        approver_role: str = "administrator",
    ) -> Ticket:
        ref = self._tickets.document(approval_id)
        transaction = self._fs.transaction()

        @self._firestore.async_transactional
        async def decide_once(txn: Any) -> Ticket:
            snapshot = await ref.get(transaction=txn)
            if not snapshot.exists:
                raise KeyError(approval_id)
            ticket = _ticket_from_doc(snapshot.to_dict())
            if _is_expired(ticket):
                raise ValueError(f"approval {approval_id} already expired")
            _apply_vote(
                ticket, granted=granted, approver=approver,
                approver_role=approver_role, note=note,
            )
            txn.set(ref, _ticket_doc(ticket))
            return ticket

        return await decide_once(transaction)


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _validate_requirement(requirement: ApprovalRequirement) -> None:
    if (
        isinstance(requirement.required_approvals, bool)
        or not isinstance(requirement.required_approvals, int)
        or not 1 <= requirement.required_approvals <= 10
    ):
        raise ValueError("required_approvals must be an integer between 1 and 10")
    if not isinstance(requirement.require_separation_from_requester, bool):
        raise ValueError("require_separation_from_requester must be boolean")
    if not isinstance(requirement.minimum_role, str):
        raise ValueError("minimum_role must be a role name")
    # Calls role_satisfies to validate the configured role as well as its
    # hierarchy semantics, without granting any authority here.
    role_satisfies("administrator", requirement.minimum_role)


def _apply_vote(
    ticket: Ticket, *, granted: bool, approver: str, approver_role: str, note: str | None
) -> None:
    """Apply one durable vote, enforcing threshold, hierarchy, and separation."""
    if ticket.status is not ApprovalState.PENDING:
        expected = ApprovalState.GRANTED if granted else ApprovalState.DENIED
        if ticket.status is expected and any(vote.principal == approver for vote in ticket.votes):
            return
        raise ValueError(f"approval {ticket.approval_id} already {ticket.status.value}")
    if not role_satisfies(approver_role, ticket.minimum_role):
        raise ValueError(
            f"{ticket.minimum_role} role is required to decide approval {ticket.approval_id}"
        )
    if (
        ticket.require_separation_from_requester
        and ticket.requested_by
        and approver == ticket.requested_by
    ):
        raise ValueError("requester may not approve their own governed action")
    previous = next((vote for vote in ticket.votes if vote.principal == approver), None)
    if previous is not None:
        if previous.granted == granted:
            return
        raise ValueError("an approver may not change a recorded approval decision")
    ticket.votes.append(ApprovalVote(
        principal=approver, role=approver_role, granted=granted, note=note,
        decided_at=_timestamp(),
    ))
    if not granted:
        ticket.status = ApprovalState.DENIED
        ticket.approver = approver
        ticket.note = note
        return
    granted_votes = [vote for vote in ticket.votes if vote.granted]
    if len(granted_votes) >= ticket.required_approvals:
        ticket.status = ApprovalState.GRANTED
        ticket.approver = ", ".join(vote.principal for vote in granted_votes)
        ticket.note = note


def _expires_at(ttl_seconds: float) -> str:
    return (
        datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
    ).isoformat(timespec="seconds").replace("+00:00", "Z")


def _is_expired(ticket: Ticket) -> bool:
    if not ticket.expires_at or ticket.status in {
        ApprovalState.DENIED, ApprovalState.CONSUMED, ApprovalState.EXPIRED
    }:
        return ticket.status is ApprovalState.EXPIRED
    try:
        expires = datetime.fromisoformat(ticket.expires_at.replace("Z", "+00:00"))
    except ValueError:
        # A malformed durable expiry is not safe to treat as an unlimited grant.
        return True
    if expires.tzinfo is None:
        return True
    return datetime.now(timezone.utc) >= expires


def _ticket_doc(ticket: Ticket) -> dict[str, Any]:
    data = asdict(ticket)
    data["status"] = ticket.status.value
    return data


def _ticket_from_doc(data: dict[str, Any]) -> Ticket:
    value = dict(data)
    value["status"] = ApprovalState(value.get("status", ApprovalState.PENDING.value))
    value["preflight"] = value.get("preflight") or {}
    value["votes"] = [
        vote if isinstance(vote, ApprovalVote) else ApprovalVote(**vote)
        for vote in value.get("votes") or []
        if isinstance(vote, (dict, ApprovalVote))
    ]
    if "expires_at" not in value:
        try:
            requested = datetime.fromisoformat(str(value["requested_at"]).replace("Z", "+00:00"))
            value["expires_at"] = (
                requested + timedelta(seconds=900)
            ).isoformat(timespec="seconds").replace("+00:00", "Z")
        except (KeyError, ValueError):
            value["expires_at"] = _timestamp()
    return Ticket(**value)


def _copy_ticket(ticket: Ticket) -> Ticket:
    return _ticket_from_doc(_ticket_doc(ticket))
