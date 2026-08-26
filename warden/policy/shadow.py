"""Observational shadow replay of a recorded fleet transcript.

Point Warden at tool calls that already happened (or a bundled fixture) and
ask what live policy would have done. Enforcement stays off: no provider
calls, no ledger writes, no spend reservations. Fail-closed does not apply;
a scoring error is recorded as an observation, not a denial.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

from warden.policy.engine import Disposition, Policy, SpendSnapshot

DEFAULT_FIXTURE_PATH = Path(__file__).with_name("fixtures") / "shadow_transcript.json"

_WOULD_HAVE = {
    Disposition.ALLOW: "allowed",
    Disposition.APPROVE: "parked",
    Disposition.DENY: "denied",
}

_DISPLAY_ARG_KEYS = (
    "provider", "region", "zone", "machine_type", "instance_type",
    "max_lifetime_minutes", "max_lifetime_seconds", "node_count",
    "cluster_id", "instance_id", "command", "cmd", "force",
)


@dataclass(frozen=True)
class ShadowCall:
    tool: str
    args: dict[str, Any] = field(default_factory=dict)
    actor: str | None = None


@dataclass(frozen=True)
class ShadowCallResult:
    index: int
    tool: str
    actor: str | None
    would_have: str
    reason: str
    quoted_usd: float | None
    quote_source: str | None
    stopped_usd: float
    parked_usd: float
    rules: tuple[str, ...]
    display_args: dict[str, str]

    def payload(self) -> dict[str, Any]:
        data = asdict(self)
        data["rules"] = list(self.rules)
        return data


@dataclass(frozen=True)
class ShadowReport:
    title: str
    source: str
    enforcement: str
    fail_closed: bool
    calls_scored: int
    allowed: int
    parked: int
    denied: int
    observed_errors: int
    allowed_usd: float
    parked_usd: float
    stopped_usd: float
    headline: str
    note: str
    examples: tuple[dict[str, Any], ...]
    calls: tuple[ShadowCallResult, ...]

    def payload(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "source": self.source,
            "enforcement": self.enforcement,
            "fail_closed": self.fail_closed,
            "calls_scored": self.calls_scored,
            "allowed": self.allowed,
            "parked": self.parked,
            "denied": self.denied,
            "observed_errors": self.observed_errors,
            "allowed_usd": self.allowed_usd,
            "parked_usd": self.parked_usd,
            "stopped_usd": self.stopped_usd,
            "headline": self.headline,
            "note": self.note,
            "examples": list(self.examples),
            "calls": [call.payload() for call in self.calls],
        }


def load_transcript(path: Path | str | None = None) -> dict[str, Any]:
    """Load a recorded transcript. Arguments stay in memory for scoring only."""
    target = Path(path) if path else DEFAULT_FIXTURE_PATH
    doc = json.loads(target.read_text(encoding="utf-8"))
    if not isinstance(doc, dict):
        raise ValueError("shadow transcript must be a JSON object")
    calls = doc.get("calls")
    if not isinstance(calls, list) or not calls:
        raise ValueError("shadow transcript needs a non-empty calls list")
    return doc


def calls_from_transcript(doc: dict[str, Any]) -> list[ShadowCall]:
    calls: list[ShadowCall] = []
    for index, raw in enumerate(doc.get("calls") or []):
        if not isinstance(raw, dict):
            raise ValueError(f"transcript call {index} must be an object")
        tool = raw.get("tool")
        if not isinstance(tool, str) or not tool.strip():
            raise ValueError(f"transcript call {index} needs a tool name")
        args = raw.get("args") or {}
        if not isinstance(args, dict):
            raise ValueError(f"transcript call {index} args must be an object")
        actor = raw.get("actor")
        calls.append(ShadowCall(
            tool=tool.strip(),
            args=args,
            actor=actor.strip() if isinstance(actor, str) and actor.strip() else None,
        ))
    return calls


def replay(
    policy: Policy,
    calls: Iterable[ShadowCall],
    *,
    title: str = "Shadow replay",
    source: str = "transcript",
    note: str = "",
    initial_spend: SpendSnapshot | None = None,
) -> ShadowReport:
    """Score each recorded call. Observational only — state is never mutated."""
    spend = initial_spend or SpendSnapshot()
    scored: list[ShadowCallResult] = []
    allowed = parked = denied = errors = 0
    allowed_usd = parked_usd = stopped_usd = 0.0

    for index, call in enumerate(calls):
        result = _score_call(policy, call, index, spend)
        scored.append(result)
        if result.would_have == "allowed":
            allowed += 1
            allowed_usd = round(allowed_usd + (result.quoted_usd or 0.0), 4)
            spend = _project_allowed(spend, call.tool, call.args, result.quoted_usd)
        elif result.would_have == "parked":
            parked += 1
            parked_usd = round(parked_usd + result.parked_usd, 4)
        elif result.would_have == "denied":
            denied += 1
            stopped_usd = round(stopped_usd + result.stopped_usd, 4)
        else:
            errors += 1

    headline = (
        f"{allowed} allowed, {parked} parked, {denied} denied. "
        f"Warden would have stopped ${stopped_usd:.2f} before it reached a provider."
    )
    if errors:
        headline += f" {errors} call{'s' if errors != 1 else ''} could not be scored."
    examples = _pick_examples(scored)
    return ShadowReport(
        title=title,
        source=source,
        enforcement="off",
        fail_closed=False,
        calls_scored=len(scored),
        allowed=allowed,
        parked=parked,
        denied=denied,
        observed_errors=errors,
        allowed_usd=round(allowed_usd, 4),
        parked_usd=round(parked_usd, 4),
        stopped_usd=round(stopped_usd, 4),
        headline=headline,
        note=note or (
            "Enforcement was off. These are would-have outcomes against live policy, "
            "quoted from the server-side rate card, not model-supplied USD."
        ),
        examples=examples,
        calls=tuple(scored),
    )


def replay_fixture(policy: Policy, *, path: Path | str | None = None) -> ShadowReport:
    doc = load_transcript(path)
    return replay(
        policy,
        calls_from_transcript(doc),
        title=str(doc.get("title") or "Shadow replay"),
        source=str(doc.get("source") or "fixture"),
        note=str(doc.get("note") or ""),
    )


def _score_call(
    policy: Policy, call: ShadowCall, index: int, spend: SpendSnapshot
) -> ShadowCallResult:
    quoted: float | None = None
    quote_source: str | None = None
    try:
        quoted = policy.quote_usd(call.tool, call.args)
        if quoted is not None:
            quote_source = "MACHINE_HOURLY_RATES"
        # Fail-closed does not apply: a thrown evaluator is an observation.
        decision = policy.evaluate(call.tool, call.args, spend=spend)
        would_have = _WOULD_HAVE[decision.disposition]
        reason = decision.reason
        rules = decision.rules
    except Exception as exc:
        would_have = "observed_error"
        reason = f"shadow scoring error ({type(exc).__name__}); call was not denied fail-closed"
        rules = ()
        quoted = None
        quote_source = None

    stopped = 0.0
    parked_amount = 0.0
    if would_have == "denied" and quoted:
        stopped = quoted
    elif would_have == "parked" and quoted:
        parked_amount = quoted

    return ShadowCallResult(
        index=index,
        tool=call.tool,
        actor=call.actor,
        would_have=would_have,
        reason=reason,
        quoted_usd=quoted,
        quote_source=quote_source,
        stopped_usd=stopped,
        parked_usd=parked_amount,
        rules=rules,
        display_args=_display_args(call.args),
    )


def _project_allowed(
    spend: SpendSnapshot, tool: str, args: dict[str, Any], quote: float | None
) -> SpendSnapshot:
    if tool not in {"launch_gpu", "launch_cluster"}:
        return spend
    instances = 1 if tool == "launch_gpu" else args.get("node_count", 2)
    if not isinstance(instances, int) or isinstance(instances, bool) or instances < 1:
        instances = 0
    cost = quote or 0.0
    return SpendSnapshot(
        run_usd=round(spend.run_usd + cost, 4),
        day_usd=round(spend.day_usd + cost, 4),
        live_instances=spend.live_instances + instances,
    )


def _display_args(args: dict[str, Any]) -> dict[str, str]:
    shown: dict[str, str] = {}
    for key in _DISPLAY_ARG_KEYS:
        if key not in args or args[key] is None:
            continue
        shown[key] = str(args[key])[:80]
    return shown


def _pick_examples(scored: list[ShadowCallResult], *, limit: int = 4) -> tuple[dict[str, Any], ...]:
    def rank(result: ShadowCallResult) -> tuple[int, float]:
        if result.would_have == "denied" and result.stopped_usd:
            return (0, -result.stopped_usd)
        if result.would_have == "denied":
            return (1, 0.0)
        if result.would_have == "parked" and result.parked_usd:
            return (2, -result.parked_usd)
        if result.would_have == "parked":
            return (3, 0.0)
        if result.would_have == "observed_error":
            return (4, 0.0)
        return (5, 0.0)

    picked = sorted(scored, key=rank)[:limit]
    examples = []
    for result in picked:
        verb = {
            "allowed": "Would have allowed",
            "parked": "Would have parked for a human",
            "denied": "Would have denied",
            "observed_error": "Could not score (observational)",
        }.get(result.would_have, result.would_have)
        dollars = ""
        if result.stopped_usd:
            dollars = f" Stopped ${result.stopped_usd:.2f} on the rate card."
        elif result.parked_usd:
            dollars = f" ${result.parked_usd:.2f} would wait on Approve."
        placement = " · ".join(
            f"{key}={value}" for key, value in result.display_args.items()
        )
        examples.append({
            "tool": result.tool,
            "would_have": result.would_have,
            "summary": f"{verb} {result.tool}.{dollars}".strip(),
            "reason": result.reason,
            "placement": placement,
            "quoted_usd": result.quoted_usd,
        })
    return tuple(examples)
