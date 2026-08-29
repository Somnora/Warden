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

import asyncio
import logging
import math
from datetime import datetime, timezone
from typing import Any

from google.adk.plugins import BasePlugin

from warden.ledger.chain import Record, digest_args
from warden.ledger.store import LedgerStore
from warden.policy.approvals import ApprovalStore, ApprovalState
from warden.policy.engine import Decision, Disposition, Policy, SpendSnapshot
from warden.missions import MissionStore
from warden.spend import SpendControlError, SpendLimits, SpendStore, reservation_key
from warden.workflow_context import (
    active_mission_id,
    active_requester_id,
    active_run_id,
    record_approval,
    record_tool_reservation,
    tool_reservation,
)

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
        missions: MissionStore | None = None,
        spend_store: SpendStore | None = None,
    ):
        super().__init__(name="warden")
        self.policy = policy
        self.ledger = ledger
        self.approvals = approvals
        self.run_id = run_id
        self.missions = missions
        self.spend_store = spend_store
        self._spend = spend or SpendSnapshot()
        # Policy evaluation, approval claim, and cost reservation are one
        # critical section. Without this, two different approved launches can
        # both observe the same remaining budget and over-reserve it.
        self._gate_lock = asyncio.Lock()

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

    async def spend_summary(self, run_id: str) -> SpendSnapshot:
        """Refresh the authoritative snapshot when a distributed store exists."""
        if self.spend_store is not None:
            self._spend = (await self.spend_store.summary(run_id)).snapshot
        return self._spend

    # -- the gate ---------------------------------------------------------

    async def before_tool_callback(
        self, *, tool: Any, tool_args: dict[str, Any], tool_context: Any
    ) -> dict[str, Any] | None:
        try:
            async with self._gate_lock:
                return await self._before_tool_callback_locked(
                    tool=tool, tool_args=tool_args, tool_context=tool_context
                )
        except Exception:
            # A broken policy, approval store, or audit store must fail closed.
            # Returning a result from before_tool_callback prevents ADK from
            # invoking the provider and gives the model a safe observation.
            log.exception("warden: control-plane failure while gating %s", getattr(tool, "name", "unknown"))
            return {
                "warden": "control_plane_error",
                "tool": str(getattr(tool, "name", "unknown")),
                "message": (
                    "Warden could not complete policy and audit checks, so the tool call "
                    "was blocked fail-closed. An operator must inspect the control plane."
                ),
            }

    async def _before_tool_callback_locked(
        self, *, tool: Any, tool_args: dict[str, Any], tool_context: Any
    ) -> dict[str, Any] | None:
        actor = _actor_of(tool_context)
        run_id = active_run_id(self.run_id)
        current_spend = await self.spend_summary(run_id)
        decision = self.policy.evaluate(tool.name, tool_args, spend=current_spend)

        if decision.disposition is Disposition.DENY:
            await self._record(actor, tool.name, tool_args, decision, outcome="refused")
            return _refusal(decision)

        if decision.disposition is Disposition.APPROVE:
            # A reusable envelope is checked before an exact-action ticket.
            # It is bound to server-side workflow context, so the model cannot
            # opt itself into a Mission by adding an argument to the tool call.
            envelope_reason: str | None = None
            mission_id = active_mission_id()
            estimated_cost = _estimate_cost(self.policy, tool.name, tool_args)
            if mission_id and self.missions is not None:
                authorization = await self.missions.authorize(
                    mission_id=mission_id,
                    run_id=run_id,
                    tool=tool.name,
                    args=tool_args,
                    cost_usd=estimated_cost,
                )
                if authorization.granted:
                    reservation_error = await self._reserve_spend(
                        run_id, actor, tool.name, tool_args, estimated_cost,
                        idempotency_key=authorization.spend_key,
                    )
                    if reservation_error is not None:
                        await self._record(
                            actor, tool.name, tool_args, decision, outcome="refused"
                        )
                        return _spend_refusal(tool.name, reservation_error)
                    await self._record(
                        actor, tool.name, tool_args, decision,
                        outcome="envelope_authorized",
                        approver=authorization.approver,
                        cost_usd=estimated_cost,
                    )
                    return None
                envelope_reason = authorization.reason

            # Claim is atomic. A human grant authorizes one provider call, not
            # an unlimited replay of identical arguments.
            state = await self.approvals.claim(
                run_id=run_id, tool=tool.name, args=tool_args, actor=actor
            )
            if state.status is ApprovalState.GRANTED:
                # Reserve the quoted upper-bound before the call reaches the
                # provider. This is intentionally conservative: a failed
                # provider call may leave a reservation behind, but it can
                # never turn a hard budget ceiling into a best-effort one.
                estimated_cost = _estimate_cost(self.policy, tool.name, tool_args)
                reservation_error = await self._reserve_spend(
                    run_id, actor, tool.name, tool_args, estimated_cost
                )
                if reservation_error is not None:
                    await self._record(
                        actor, tool.name, tool_args, decision,
                        outcome="refused", approver=state.approver,
                    )
                    return _spend_refusal(tool.name, reservation_error)
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

            if state.status is ApprovalState.EXPIRED:
                await self._record(
                    actor, tool.name, tool_args, decision,
                    outcome="refused", approver=state.approver,
                )
                return {
                    "warden": "approval_expired",
                    "tool": tool.name,
                    "approver": state.approver,
                    "message": (
                        f"The approval for this exact {tool.name} call expired before use. "
                        "The action was blocked; start a new workflow for fresh human review."
                    ),
                }

            # Pending: register the request and hand the model a clear stop.
            ticket = await self.approvals.request(
                run_id=run_id, tool=tool.name, args=tool_args,
                actor=actor,
                requester=active_requester_id(),
                requirement=self.policy.approval_requirement(tool.name),
                reason=(
                    f"{decision.reason}; Mission envelope did not authorize: {envelope_reason}"
                    if envelope_reason else decision.reason
                ),
                preflight=_preflight(
                    tool.name, tool_args, decision, policy=self.policy,
                    envelope_reason=envelope_reason,
                ),
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

    async def _reserve_spend(
        self,
        run_id: str,
        actor: str,
        tool: str,
        args: dict[str, Any],
        cost_usd: float | None,
        *,
        idempotency_key: str | None = None,
    ) -> str | None:
        """Atomically reserve globally shared budget/capacity before execution."""
        instances = _instance_delta(tool, args)
        if self.spend_store is None:
            if cost_usd is not None or instances:
                self.charge(cost_usd or 0.0, instances_delta=instances)
            return None
        if cost_usd is None and not instances:
            return None
        limits_doc = self.policy.doc.get("budget", {})
        limits = SpendLimits(
            max_usd_per_run=limits_doc.get("max_usd_per_run"),
            max_usd_per_day=limits_doc.get("max_usd_per_day"),
            max_concurrent_instances=limits_doc.get("max_concurrent_instances"),
        )
        try:
            reservation, summary = await self.spend_store.reserve(
                idempotency_key=idempotency_key or reservation_key(
                    run_id, actor, tool, digest_args(args)
                ),
                run_id=run_id,
                cost_usd=cost_usd or 0.0,
                instances=instances,
                limits=limits,
            )
        except SpendControlError as exc:
            return str(exc)
        self._spend = summary.snapshot
        record_tool_reservation(tool, args, reservation.reservation_id)
        return None

    # -- outcome ----------------------------------------------------------

    async def after_tool_callback(
        self, *, tool: Any, tool_args: dict[str, Any], tool_context: Any, result: Any
    ) -> dict[str, Any] | None:
        try:
            cleaned, fired = _redact_result(self.policy, result)
        except Exception:
            # Never let an unexpected provider result bypass DLP through an
            # exception path. The original observation is deliberately dropped.
            log.exception("warden: unable to inspect %s output", getattr(tool, "name", "unknown"))
            return {
                "warden": "egress_inspection_error",
                "tool": str(getattr(tool, "name", "unknown")),
                "message": "Tool output was withheld because Warden could not inspect it safely.",
            }
        mission_id = active_mission_id()
        if mission_id and self.missions is not None:
            try:
                # Mission outcome metadata is derived only from the sanitized
                # result and an allowlist of identifiers/status fields.
                await self.missions.record_tool_result(
                    mission_id=mission_id, tool=tool.name, args=tool_args, result=cleaned
                )
            except Exception:
                # Artifact/timeline projection must never change whether the
                # already-governed provider result reaches the agent.
                log.exception("warden: failed to project Mission outcome for %s", tool.name)
        await self._reconcile_spend_result(tool.name, tool_args, cleaned, _actor_of(tool_context))
        if not fired:
            return None
        # Something in the tool output matched a credential pattern. Replace
        # the observation before it reaches Gemini, and note that it happened.
        try:
            await self._record(
                _actor_of(tool_context), tool.name, tool_args,
                Decision(Disposition.ALLOW, tool.name, "egress redaction applied",
                         tuple(f"egress.{f}" for f in fired)),
                outcome="redacted", redactions=fired,
            )
        except Exception:
            # The sanitized observation is still safe to return. Logging the
            # audit outage avoids re-exposing the original credential.
            log.exception("warden: failed to audit redaction for %s", getattr(tool, "name", "unknown"))
        log.warning("warden: redacted %s from %s output", fired, tool.name)
        return {"warden": "redacted", "patterns": list(fired), "result": cleaned}

    async def on_tool_error_callback(
        self, *, tool: Any, tool_args: dict[str, Any], tool_context: Any, error: Exception
    ) -> dict[str, Any] | None:
        try:
            safe, fired = self.policy.redact(str(error))
        except Exception:
            log.exception("warden: failed to inspect tool error")
            return {"warden": "tool_error", "message": "Tool failed; details were withheld by Warden."}
        reservation_id = tool_reservation(tool.name, tool_args)
        if reservation_id and self.spend_store is not None and tool.name in {"launch_gpu", "launch_cluster"}:
            try:
                summary = await self.spend_store.mark_uncertain(
                    reservation_id, reason="provider raised before launch outcome could be verified"
                )
                self._spend = summary.snapshot
            except Exception:
                # Retaining a reservation is safer than assuming a failed
                # provider call created no infrastructure.
                log.exception("warden: failed to mark spend reservation uncertain")
        try:
            await self._record(
                _actor_of(tool_context), tool.name, tool_args,
                Decision(Disposition.ALLOW, tool.name, f"tool error: {safe}", ()),
                outcome="error",
            )
        except Exception:
            log.exception("warden: failed to audit tool error for %s", getattr(tool, "name", "unknown"))
        if fired:
            # Do not let a credential embedded in an exception become the
            # model's observation through ADK's normal error path.
            return {"warden": "tool_error", "message": safe}
        return None  # let ADK handle ordinary errors normally

    async def _reconcile_spend_result(
        self, tool: str, args: dict[str, Any], result: Any, actor: str
    ) -> None:
        """Settle successful launches and release capacity after verified teardown."""
        if self.spend_store is None or not isinstance(result, dict):
            return
        try:
            if tool in {"launch_gpu", "launch_cluster"}:
                reservation_id = tool_reservation(tool, args)
                if not reservation_id:
                    return
                status = str(result.get("status") or result.get("phase") or "").lower()
                resource_ids = _resource_ids(tool, result)
                if _provider_result_failed(status):
                    summary = await self.spend_store.release(
                        reservation_id,
                        reason=f"provider returned {status or 'unsuccessful'}",
                        release_cost=True,
                    )
                    self._spend = summary.snapshot
                    await self._record(
                        actor, tool, args,
                        Decision(Disposition.ALLOW, tool, "durable spend reservation released", ("spend.released",)),
                        outcome="spend_released",
                    )
                    return
                if not resource_ids:
                    summary = await self.spend_store.mark_uncertain(
                        reservation_id,
                        reason="provider reported success without a resource identifier",
                    )
                    self._spend = summary.snapshot
                    await self._record(
                        actor, tool, args,
                        Decision(Disposition.ALLOW, tool, "spend reservation requires reconciliation", ("spend.uncertain",)),
                        outcome="spend_uncertain",
                    )
                    return
                summary = await self.spend_store.settle(reservation_id, resource_ids=resource_ids)
                self._spend = summary.snapshot
                await self._record(
                    actor, tool, args,
                    Decision(Disposition.ALLOW, tool, "durable spend reservation settled", ("spend.settled",)),
                    outcome="spend_settled",
                )
                if result.get("cleanup_verified") is True:
                    for resource_id in resource_ids:
                        released = await self.spend_store.release_resource(
                            resource_id, reason="provider lifecycle returned verified cleanup"
                        )
                        if released is not None:
                            self._spend = released.snapshot
                    await self._record(
                        actor, tool, args,
                        Decision(
                            Disposition.ALLOW,
                            tool,
                            "provider lifecycle verified resource absence",
                            ("spend.capacity_released", "cleanup.verified"),
                        ),
                        outcome="spend_capacity_released",
                    )
            elif tool in {"terminate_instance", "terminate_cluster"} and _teardown_verified(result):
                resource_id = _teardown_resource_id(tool, args, result)
                if resource_id:
                    summary = await self.spend_store.release_resource(
                        resource_id, reason=f"verified by {tool}"
                    )
                    if summary is not None:
                        self._spend = summary.snapshot
                        await self._record(
                            actor, tool, args,
                            Decision(Disposition.ALLOW, tool, "durable capacity released", ("spend.capacity_released",)),
                            outcome="spend_capacity_released",
                        )
        except Exception:
            # A result reconciliation outage must leave the original spend
            # reservation in place rather than accidentally reopening budget.
            log.exception("warden: durable spend reconciliation failed for %s", tool)

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


def _spend_refusal(tool: str, reason: str) -> dict[str, Any]:
    return {
        "warden": "denied_by_spend_control",
        "tool": tool,
        "reason": reason,
        "message": (
            f"Warden refused {tool} because the shared durable spend control could not "
            f"reserve budget and capacity: {reason}. No provider call was made."
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


def _estimate_cost(policy: Policy, tool: str, args: dict[str, Any]) -> float | None:
    """Return the rate-card reservation, never the model's self-reported estimate."""
    return policy.quote_usd(tool, args)


def _instance_delta(tool: str, args: dict[str, Any]) -> int:
    if tool == "launch_gpu":
        return 1
    if tool == "launch_cluster":
        raw = args.get("node_count", 2)
        return raw if isinstance(raw, int) and not isinstance(raw, bool) and raw > 0 else 0
    return 0


def _resource_ids(tool: str, result: dict[str, Any]) -> list[str]:
    keys = ("instance_id", "id", "launch_id") if tool == "launch_gpu" else ("cluster_id", "id", "launch_id")
    return [str(result[key]) for key in keys if isinstance(result.get(key), (str, int)) and str(result[key])]


def _provider_result_failed(status: str) -> bool:
    return status in {"failed", "error", "rejected", "cancelled", "canceled", "not_found", "not found"}


def _teardown_verified(result: dict[str, Any]) -> bool:
    return str(result.get("status") or "").lower() in {
        "terminated", "deleted", "not_found", "not found", "absent", "completed", "success"
    }


def _teardown_resource_id(tool: str, args: dict[str, Any], result: dict[str, Any]) -> str | None:
    arg_key = "instance_id" if tool == "terminate_instance" else "cluster_id"
    value = args.get(arg_key) or result.get(arg_key) or result.get("id")
    return str(value) if isinstance(value, (str, int)) and str(value) else None


def _preflight(
    tool: str,
    args: dict[str, Any],
    decision: Decision,
    *,
    policy: Policy,
    envelope_reason: str | None = None,
) -> dict[str, Any]:
    """Expose only decision-relevant, non-secret facts to the operator UI."""
    placement = {
        key: _safe_display(args[key])
        for key in ("provider", "region", "zone", "machine_type", "instance_type")
        if args.get(key) is not None
    }
    quoted = policy.quote_usd(tool, args)
    agent_estimate = _finite_nonnegative(args.get("estimated_usd"))
    lifetime = _finite_nonnegative(args.get("max_lifetime_minutes"))
    if lifetime is None and args.get("max_lifetime_seconds") is not None:
        seconds = _finite_nonnegative(args.get("max_lifetime_seconds"))
        lifetime = seconds / 60.0 if seconds is not None else None
    requirement = policy.approval_requirement(tool)
    return {
        "policy_rules": list(decision.rules),
        "placement": placement,
        "estimated_usd": quoted,
        "quote_source": "MACHINE_HOURLY_RATES" if quoted is not None else None,
        "agent_estimated_usd": agent_estimate,
        "agent_estimate_valid": agent_estimate is not None,
        "max_lifetime_minutes": lifetime,
        "rollback_plan": _rollback_plan(tool),
        "envelope_deviation": envelope_reason,
        "approval_requirement": {
            "required_approvals": requirement.required_approvals,
            "minimum_role": requirement.minimum_role,
            "require_separation_from_requester": requirement.require_separation_from_requester,
        },
    }


def _safe_display(value: Any) -> str:
    """Bound a non-secret field before it is persisted for dashboard display."""
    return str(value)[:120]


def _finite_nonnegative(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        numeric = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return numeric if math.isfinite(numeric) and numeric >= 0 else None


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
    ancestors: set[int] = set()
    sensitive_fields = {
        "private_key": "gcp_service_account_key",
        "access_token": "oauth_access_token",
        "refresh_token": "oauth_access_token",
        "id_token": "jwt_token",
        "client_secret": "oauth_client_secret",
        "api_key": "gcp_api_key",
        "authorization": "authorization_credential",
    }

    def visit(value: Any, depth: int = 0) -> Any:
        if depth > 32:
            fired.append("output_depth_limit")
            return "[REDACTED:output_depth_limit]"
        if isinstance(value, str):
            clean, matches = policy.redact(value)
            fired.extend(matches)
            return clean
        if isinstance(value, (bytes, bytearray)):
            clean, matches = policy.redact(bytes(value).decode("utf-8", errors="replace"))
            fired.extend(matches)
            return clean if matches else value
        if isinstance(value, dict):
            identity = id(value)
            if identity in ancestors:
                fired.append("output_cycle")
                return "[REDACTED:output_cycle]"
            ancestors.add(identity)
            cleaned: dict[Any, Any] = {}
            try:
                for key, item in value.items():
                    field = str(key).strip().lower().replace("-", "_")
                    pattern = sensitive_fields.get(field)
                    if pattern is not None and item is not None:
                        fired.append(pattern)
                        cleaned[key] = f"[REDACTED:{pattern}]"
                    else:
                        cleaned[key] = visit(item, depth + 1)
                return cleaned
            finally:
                ancestors.remove(identity)
        if isinstance(value, (list, tuple)):
            identity = id(value)
            if identity in ancestors:
                fired.append("output_cycle")
                return "[REDACTED:output_cycle]"
            ancestors.add(identity)
            try:
                items = [visit(item, depth + 1) for item in value]
                return tuple(items) if isinstance(value, tuple) else items
            finally:
                ancestors.remove(identity)
        if value is not None and not isinstance(value, (bool, int, float)):
            rendered = str(value)
            clean, matches = policy.redact(rendered)
            fired.extend(matches)
            return clean if matches else value
        return value

    cleaned = visit(result)
    return cleaned, tuple(dict.fromkeys(fired))
