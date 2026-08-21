"""Task-local workflow metadata shared by the fleet runner and policy plugin."""

from __future__ import annotations

from contextvars import ContextVar, Token


_approval_ids: ContextVar[list[str] | None] = ContextVar("warden_approval_ids", default=None)
_run_id: ContextVar[str | None] = ContextVar("warden_run_id", default=None)


def begin_workflow(run_id: str | None = None) -> tuple[Token[list[str] | None], Token[str | None]]:
    """Start collecting approval tickets for one async fleet invocation."""
    return _approval_ids.set([]), _run_id.set(run_id)


def record_approval(approval_id: str) -> None:
    tickets = _approval_ids.get()
    if tickets is not None and approval_id not in tickets:
        tickets.append(approval_id)


def finish_workflow(tokens: tuple[Token[list[str] | None], Token[str | None]]) -> list[str]:
    tickets = _approval_ids.get() or []
    approval_token, run_token = tokens
    _approval_ids.reset(approval_token)
    _run_id.reset(run_token)
    return tickets


def active_run_id(default: str) -> str:
    return _run_id.get() or default
