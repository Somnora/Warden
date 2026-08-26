"""Task-local workflow metadata shared by the fleet runner and policy plugin."""

from __future__ import annotations

from contextvars import ContextVar, Token

from warden.ledger.chain import digest_args


_approval_ids: ContextVar[list[str] | None] = ContextVar("warden_approval_ids", default=None)
_run_id: ContextVar[str | None] = ContextVar("warden_run_id", default=None)
_mission_id: ContextVar[str | None] = ContextVar("warden_mission_id", default=None)
_requester_id: ContextVar[str | None] = ContextVar("warden_requester_id", default=None)
_tool_reservations: ContextVar[dict[str, str] | None] = ContextVar(
    "warden_tool_reservations", default=None
)


def begin_workflow(
    run_id: str | None = None, mission_id: str | None = None, requester_id: str | None = None,
) -> tuple[
    Token[list[str] | None], Token[str | None], Token[str | None], Token[str | None],
    Token[dict[str, str] | None],
]:
    """Start collecting approval tickets for one async fleet invocation."""
    return (
        _approval_ids.set([]), _run_id.set(run_id), _mission_id.set(mission_id), _requester_id.set(requester_id),
        _tool_reservations.set({}),
    )


def record_approval(approval_id: str) -> None:
    tickets = _approval_ids.get()
    if tickets is not None and approval_id not in tickets:
        tickets.append(approval_id)


def finish_workflow(
    tokens: tuple[
        Token[list[str] | None], Token[str | None], Token[str | None], Token[str | None],
        Token[dict[str, str] | None],
    ]
) -> list[str]:
    tickets = _approval_ids.get() or []
    approval_token, run_token, mission_token, requester_token, reservation_token = tokens
    _approval_ids.reset(approval_token)
    _run_id.reset(run_token)
    _mission_id.reset(mission_token)
    _requester_id.reset(requester_token)
    _tool_reservations.reset(reservation_token)
    return tickets


def active_run_id(default: str) -> str:
    return _run_id.get() or default


def active_mission_id() -> str | None:
    """Return the server-bound Mission for this turn, never model input."""
    return _mission_id.get()


def active_requester_id() -> str | None:
    """Bound operator identity for separation-of-duties approval checks."""
    return _requester_id.get()


def record_tool_reservation(tool: str, args: dict[str, object], reservation_id: str) -> None:
    reservations = _tool_reservations.get()
    if reservations is not None:
        reservations[_reservation_key(tool, args)] = reservation_id


def tool_reservation(tool: str, args: dict[str, object]) -> str | None:
    reservations = _tool_reservations.get()
    return reservations.get(_reservation_key(tool, args)) if reservations else None


def _reservation_key(tool: str, args: dict[str, object]) -> str:
    return f"{tool}:{digest_args(args)}"
