"""The Warden plugin: policy enforcement wired into the ADK run loop.

This is the only place where an agent's intent becomes an action. ADK invokes
`before_tool_callback` for every tool call any agent in the fleet makes; if we
return a dict, the tool never executes and the dict becomes the model's
observation. That is the whole enforcement mechanism -- a denial is not a
prompt instruction the model can be talked out of, it is a function that
declines to call the tool.

Design note: the plugin sits at the Runner level, not on an individual agent.
Sub-agents added later inherit governance automatically instead of having to
remember to opt in.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from google.adk.plugins import BasePlugin

from warden.ledger.chain import Record, digest_args
from warden.ledger.store import LedgerStore
from warden.policy.approvals import ApprovalStore, ApprovalState
from warden.policy.engine import Decision, Disposition, Policy, SpendSnapshot
from warden.workflow_context import active_run_id, record_approval

log = logging.getLogger("warden.plugin")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class WardenPlugin(BasePlugin):
    """Policy + audit for every tool call in the fleet."""

    def __init__(
        self,
        *,
        policy: Policy,
        ledger: LedgerStore,
        approvals: ApprovalStore,
        run_id: str,
        spend: SpendSnapshot | None = None,
    ):
        super().__init__(name="warden")
        self.policy = policy
        self.ledger = ledger
        self.approvals = approvals
        self.run_id = run_id
        self._spend = spend or SpendSnapshot()

    # -- spend tracking ---------------------------------------------------

    @property
    def spend(self) -> SpendSnapshot:
        return self._spend

    @spend.setter
    def spend(self, value: SpendSnapshot) -> None:
        self._spend = value

    def charge(self, usd: float, *, instances_delta: int = 0) -> None:
        self._spend = SpendSnapshot(
            run_usd=self._spend.run_usd + usd,
            day_usd=self._spend.day_usd + usd,
            live_instances=max(0, self._spend.live_instances + instances_delta),
        )

    # -- the gate ---------------------------------------------------------

    async def before_tool_callback(
        self, *, tool: Any, tool_args: dict[str, Any], tool_context: Any
    ) -> dict[str, Any] | None:
        actor = _actor_of(tool_context)
        run_id = active_run_id(self.run_id)
        decision = self.policy.evaluate(tool.name, tool_args, spend=self._spend)

        if decision.disposition is Disposition.DENY:
            await self._record(actor, tool.name, tool_args, decision, outcome="refused")
            return _refusal(decision)

        if decision.disposition is Disposition.APPROVE:
            # Claim is atomic. A human grant authorizes one provider call, not
            # an unlimited replay of identical arguments.
            state = await self.approvals.claim(
                run_id=run_id, tool=tool.name, args=tool_args
            )
            if state.status is ApprovalState.GRANTED:
                # Reserve the quoted upper-bound before the call reaches the
                # provider. This is intentionally conservative: a failed
                # provider call may leave a reservation behind, but it can
                # never turn a hard budget ceiling into a best-effort one.
                estimated_cost = _estimate_cost(tool.name, tool_args)
                if estimated_cost is not None:
                    self.charge(estimated_cost, instances_delta=_instance_delta(tool.name))
                await self._record(
                    actor, tool.name, tool_args, decision,
                    outcome="approved", approver=state.approver, cost_usd=estimated_cost,
                )
                return None  # proceed

            if state.status is ApprovalState.DENIED:
                await self._record(
                    actor, tool.name, tool_args, decision,
                    outcome="refused", approver=state.approver,
                )
                return {
                    "warden": "denied_by_human",
                    "tool": tool.name,
                    "approver": state.approver,
                    "message": (
                        f"A human reviewed and declined this {tool.name} call"
                        f"{': ' + state.note if state.note else '.'} Do not retry it. "
                        "Report the refusal and stop."
                    ),
                }

            if state.status is ApprovalState.CONSUMED:
                await self._record(
                    actor, tool.name, tool_args, decision,
                    outcome="refused", approver=state.approver,
                )
                return {
                    "warden": "approval_already_consumed",
                    "tool": tool.name,
                    "approver": state.approver,
                    "message": (
                        f"The human approval for this exact {tool.name} call was already used. "
                        "Do not retry it; request a new approval for a new action."
                    ),
                }

            # Pending: register the request and hand the model a clear stop.
            ticket = await self.approvals.request(
                run_id=run_id, tool=tool.name, args=tool_args,
                actor=actor, reason=decision.reason,
                preflight=_preflight(tool.name, tool_args, decision),
            )
            record_approval(ticket)
            await self._record(
                actor, tool.name, tool_args, decision, outcome="pending_approval"
            )
            return {
                "warden": "awaiting_human_approval",
                "tool": tool.name,
                "approval_id": ticket,
                "message": (
                    f"{tool.name} is gated by policy '{self.policy.fleet}' and is "
                    f"waiting on a human decision (approval {ticket}). This is not "
                    "an error and there is no alternate path. Stop, and report that "
                    "the action is pending approval."
                ),
            }

        await self._record(actor, tool.name, tool_args, decision, outcome="allowed")
        return None

    # -- outcome ----------------------------------------------------------

    async def after_tool_callback(
        self, *, tool: Any, tool_args: dict[str, Any], tool_context: Any, result: Any
    ) -> dict[str, Any] | None:
        cleaned, fired = _redact_result(self.policy, result)
        if not fired:
            return None
        # Something in the tool output matched a credential pattern. Replace
        # the observation before it reaches Gemini, and note that it happened.
        await self._record(
            _actor_of(tool_context), tool.name, tool_args,
            Decision(Disposition.ALLOW, tool.name, "egress redaction applied",
                     tuple(f"egress.{f}" for f in fired)),
            outcome="redacted", redactions=fired,
        )
        log.warning("warden: redacted %s from %s output", fired, tool.name)
        return {"warden": "redacted", "patterns": list(fired), "result": cleaned}

    async def on_tool_error_callback(
        self, *, tool: Any, tool_args: dict[str, Any], tool_context: Any, error: Exception
    ) -> dict[str, Any] | None:
        safe, fired = self.policy.redact(str(error))
        await self._record(
            _actor_of(tool_context), tool.name, tool_args,
            Decision(Disposition.ALLOW, tool.name, f"tool error: {safe}", ()),
            outcome="error",
        )
        if fired:
            # Do not let a credential embedded in an exception become the
            # model's observation through ADK's normal error path.
            return {"warden": "tool_error", "message": safe}
        return None  # let ADK handle ordinary errors normally

    # -- ledger -----------------------------------------------------------

    async def _record(
        self,
        actor: str,
        tool: str,
        args: dict[str, Any],
        decision: Decision,
        *,
        outcome: str,
        approver: str | None = None,
        redactions: tuple[str, ...] = (),
        cost_usd: float | None = None,
    ) -> None:
        rec = Record(
            seq=0,  # assigned on append
            ts=_now(),
            fleet=self.policy.fleet,
            run_id=active_run_id(self.run_id),
            actor=actor,
            tool=tool,
            disposition=decision.disposition.value,
            reason=decision.reason,
            rules=decision.rules,
            args_digest=digest_args(args),
            redactions=redactions,
            approver=approver,
            outcome=outcome,
            cost_usd=cost_usd,
        )
        await self.ledger.append(rec)


def _refusal(decision: Decision) -> dict[str, Any]:
    return {
        "warden": "denied_by_policy",
        "tool": decision.tool,
        "reason": decision.reason,
        "rules": list(decision.rules),
        "message": (
            f"Policy refused {decision.tool}: {decision.reason}. This is a hard "
            "control-plane denial, not a suggestion -- retrying, rewording, or "
            "routing through another tool will not change it. Report the refusal "
            "and its reason, then stop."
        ),
    }


def _actor_of(tool_context: Any) -> str:
    for attr in ("agent_name", "agent"):
        v = getattr(tool_context, attr, None)
        if isinstance(v, str):
            return v
        if v is not None and hasattr(v, "name"):
            return str(v.name)
    inv = getattr(tool_context, "invocation_context", None)
    agent = getattr(inv, "agent", None)
    return str(getattr(agent, "name", "unknown"))


def _estimate_cost(tool: str, args: dict[str, Any]) -> float | None:
    """Return the pre-approved cost reservation for a spending action."""
    if tool not in {"launch_gpu", "launch_cluster"}:
        return None
    # Policy validation runs immediately before this function.
    return float(args["estimated_usd"])


def _instance_delta(tool: str) -> int:
    return 1 if tool == "launch_gpu" else 0


def _preflight(tool: str, args: dict[str, Any], decision: Decision) -> dict[str, Any]:
    """Expose only decision-relevant, non-secret facts to the operator UI."""
    placement = {
        key: _safe_display(args[key])
        for key in ("provider", "region", "zone", "machine_type", "instance_type")
        if args.get(key) is not None
    }
    estimated = args.get("estimated_usd")
    lifetime = args.get("max_lifetime_minutes")
    if lifetime is None and args.get("max_lifetime_seconds") is not None:
        lifetime = args["max_lifetime_seconds"] / 60
    return {
        "policy_rules": list(decision.rules),
        "placement": placement,
        "estimated_usd": estimated,
        "max_lifetime_minutes": lifetime,
        "rollback_plan": _rollback_plan(tool),
    }


def _safe_display(value: Any) -> str:
    """Bound a non-secret field before it is persisted for dashboard display."""
    return str(value)[:120]


def _rollback_plan(tool: str) -> str:
    if tool == "launch_gpu":
        return "Rollback: Warden enforces the requested TTL; terminate_instance remains human-gated."
    if tool == "launch_cluster":
        return "Rollback: Warden enforces the requested TTL; terminate_cluster remains human-gated."
    if tool in {"terminate_instance", "terminate_cluster", "delete_template"}:
        return "This is destructive and cannot be automatically rolled back. Verify ownership first."
    if tool == "create_filesystem":
        return "Persistent storage remains until a separately approved cleanup action."
    return "A separate governed lifecycle action is required for rollback."


def _redact_result(policy: Policy, result: Any) -> tuple[Any, tuple[str, ...]]:
    """Redact a JSON-shaped tool result without turning it into a string.

    Function-tool results are normally dictionaries/lists. Preserving that
    shape keeps the model's tool contract intact while still applying the
    textual DLP patterns to every string field.
    """
    fired: list[str] = []

    def visit(value: Any) -> Any:
        if isinstance(value, str):
            clean, matches = policy.redact(value)
            fired.extend(matches)
            return clean
        if isinstance(value, dict):
            cleaned: dict[Any, Any] = {}
            for key, item in value.items():
                field = str(key).lower()
                if field in {"private_key", "access_token", "refresh_token", "id_token"}:
                    pattern = "gcp_service_account_key" if field == "private_key" else "bearer_token"
                    fired.append(pattern)
                    cleaned[key] = f"[REDACTED:{pattern}]"
                else:
                    cleaned[key] = visit(item)
            return cleaned
        if isinstance(value, list):
            return [visit(item) for item in value]
        if isinstance(value, tuple):
            return tuple(visit(item) for item in value)
        return value

    cleaned = visit(result)
    return cleaned, tuple(dict.fromkeys(fired))
