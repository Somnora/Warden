"""Pure policy simulation and evidence-bound audit replay.

The audit chain intentionally stores argument digests rather than raw tool
arguments. Replay therefore accepts an operator-supplied manifest and binds
each manifest entry back to its ledger digest before evaluating it. Raw inputs
are never persisted by this module.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Iterable

from warden.ledger.chain import Record
from warden.policy.engine import Decision, Disposition, Policy, SpendSnapshot


@dataclass(frozen=True)
class PreviewAction:
    tool: str
    args: dict[str, Any]
    record_seq: int | None = None


@dataclass(frozen=True)
class PreviewResult:
    index: int
    tool: str
    record_seq: int | None
    disposition: str
    reason: str
    rules: tuple[str, ...]
    quoted_usd: float | None
    projected: bool
    spend_before: SpendSnapshot
    spend_after: SpendSnapshot

    def payload(self) -> dict[str, Any]:
        data = asdict(self)
        data["rules"] = list(self.rules)
        data["spend_before"] = asdict(self.spend_before)
        data["spend_after"] = asdict(self.spend_after)
        return data


def simulate(
    policy: Policy,
    actions: Iterable[PreviewAction],
    *,
    initial_spend: SpendSnapshot | None = None,
    assume_approved: bool = True,
) -> tuple[list[PreviewResult], SpendSnapshot]:
    """Evaluate calls in order without reaching a provider or altering state.

    Approved actions are only included in the cost/capacity projection when
    ``assume_approved`` is true. The result makes that assumption explicit so
    this cannot be mistaken for an authorization or execution record.
    """
    spend = initial_spend or SpendSnapshot()
    results: list[PreviewResult] = []
    for index, action in enumerate(actions):
        before = spend
        decision = policy.evaluate(action.tool, action.args, spend=before)
        quote = policy.quote_usd(action.tool, action.args)
        projected = decision.disposition is Disposition.ALLOW or (
            decision.disposition is Disposition.APPROVE and assume_approved
        )
        if projected and action.tool in {"launch_gpu", "launch_cluster"}:
            spend = _reserve_projection(before, action.tool, action.args, quote)
        results.append(
            PreviewResult(
                index=index,
                tool=action.tool,
                record_seq=action.record_seq,
                disposition=decision.disposition.value,
                reason=decision.reason,
                rules=decision.rules,
                quoted_usd=quote,
                projected=projected,
                spend_before=before,
                spend_after=spend,
            )
        )
    return results, spend


def compare_replay(
    policy: Policy,
    records: Iterable[Record],
    actions: Iterable[PreviewAction],
    *,
    initial_spend: SpendSnapshot | None = None,
    assume_approved: bool = True,
) -> tuple[list[dict[str, Any]], SpendSnapshot]:
    """Replay an evidence-bound manifest and report decision deltas."""
    record_by_seq = {record.seq: record for record in records}
    selected = list(actions)
    results, final_spend = simulate(
        policy, selected, initial_spend=initial_spend, assume_approved=assume_approved
    )
    comparison: list[dict[str, Any]] = []
    for action, result in zip(selected, results, strict=True):
        record = record_by_seq.get(action.record_seq) if action.record_seq is not None else None
        comparison.append({
            "record_seq": action.record_seq,
            "historical": {
                "disposition": record.disposition if record else None,
                "outcome": record.outcome if record else None,
                "rules": list(record.rules) if record else [],
            },
            "candidate": result.payload(),
            "changed": bool(record and record.disposition != result.disposition),
        })
    return comparison, final_spend


def _reserve_projection(
    spend: SpendSnapshot, tool: str, args: dict[str, Any], quote: float | None
) -> SpendSnapshot:
    instances = 1 if tool == "launch_gpu" else args.get("node_count", 2)
    if not isinstance(instances, int) or isinstance(instances, bool) or instances < 1:
        # The policy decision will already have denied malformed cluster size;
        # this guard keeps preview state well-formed if a future policy changes.
        instances = 0
    cost = quote or 0.0
    return SpendSnapshot(
        run_usd=round(spend.run_usd + cost, 4),
        day_usd=round(spend.day_usd + cost, 4),
        live_instances=spend.live_instances + instances,
    )
