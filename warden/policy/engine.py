"""Policy evaluation.

Pure functions over a loaded policy document. No I/O, no Google Cloud, no ADK
imports -- so the whole decision surface is unit-testable without a network or
a billing account. The plugin in warden.policy.plugin is what wires this to a
live agent run.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import yaml

DEFAULT_POLICY_PATH = Path(__file__).with_name("policy.yaml")


class Disposition(str, Enum):
    ALLOW = "allow"
    APPROVE = "approve"
    DENY = "deny"


@dataclass(frozen=True)
class Decision:
    """The outcome of evaluating one tool call against policy."""

    disposition: Disposition
    tool: str
    reason: str
    # Rules that fired, in evaluation order. Carried into the ledger so an
    # auditor can reconstruct *why*, not just *what*.
    rules: tuple[str, ...] = field(default_factory=tuple)

    @property
    def allowed(self) -> bool:
        return self.disposition is Disposition.ALLOW

    @property
    def needs_human(self) -> bool:
        return self.disposition is Disposition.APPROVE


class PolicyError(RuntimeError):
    pass


class Policy:
    def __init__(self, doc: dict[str, Any]):
        if doc.get("version") != 1:
            raise PolicyError(f"unsupported policy version: {doc.get('version')!r}")
        self.doc = doc
        self.fleet: str = doc.get("fleet", "unnamed")
        self._tools: dict[str, str] = doc.get("tools", {}) or {}
        self._budget: dict[str, Any] = doc.get("budget", {}) or {}
        self._placement: dict[str, Any] = doc.get("placement", {}) or {}
        self._redactors = [
            (r["name"], re.compile(r["pattern"]))
            for r in (doc.get("egress", {}) or {}).get("redact_patterns", []) or []
        ]

    @classmethod
    def load(cls, path: Path | str | None = None) -> "Policy":
        p = Path(path) if path else DEFAULT_POLICY_PATH
        return cls(yaml.safe_load(p.read_text()))

    # -- tool disposition ------------------------------------------------

    def evaluate(
        self,
        tool: str,
        args: dict[str, Any] | None = None,
        *,
        spend: "SpendSnapshot | None" = None,
    ) -> Decision:
        """Decide what happens to one tool call.

        Order matters. An explicit deny always wins; then placement, then
        budget, then the tool's declared disposition. A tool absent from the
        policy is denied -- there is no implicit allow anywhere in this path.
        """
        args = args or {}
        rules: list[str] = []

        declared = self._tools.get(tool)
        if declared is None:
            return Decision(
                Disposition.DENY,
                tool,
                f"UNGOVERNED: '{tool}' has no rule in policy '{self.fleet}'",
                ("tools.<missing>",),
            )

        if declared == Disposition.DENY.value:
            return Decision(
                Disposition.DENY, tool, f"tool '{tool}' is denied by policy",
                (f"tools.{tool}=deny",),
            )

        placement = self._check_placement(args)
        if placement is not None:
            rule, why = placement
            return Decision(Disposition.DENY, tool, why, (rule,))
        if args:
            rules.append("placement.ok")

        if spend is not None:
            budget = self._check_budget(tool, args, spend)
            if budget is not None:
                rule, why = budget
                return Decision(Disposition.DENY, tool, why, tuple(rules) + (rule,))
            rules.append("budget.ok")

        lifetime = self._check_lifetime(tool, args)
        if lifetime is not None:
            rule, why = lifetime
            return Decision(Disposition.DENY, tool, why, tuple(rules) + (rule,))

        disp = Disposition(declared)
        reason = (
            f"tool '{tool}' requires human approval"
            if disp is Disposition.APPROVE
            else f"tool '{tool}' permitted by policy"
        )
        return Decision(disp, tool, reason, tuple(rules) + (f"tools.{tool}={declared}",))

    # -- individual checks -----------------------------------------------

    def _check_placement(self, args: dict[str, Any]) -> tuple[str, str] | None:
        provider = args.get("provider")
        if provider is not None:
            allowed = self._placement.get("allowed_providers", [])
            if provider not in allowed:
                return (
                    "placement.allowed_providers",
                    f"provider '{provider}' not in {allowed}",
                )

        region = args.get("region") or args.get("zone")
        if region is not None:
            allowed = self._placement.get("allowed_regions", [])
            # A zone (us-west1-a) satisfies a region rule (us-west1).
            if not any(str(region).startswith(r) for r in allowed):
                return (
                    "placement.allowed_regions",
                    f"region '{region}' not in {allowed}",
                )

        machine = args.get("machine_type") or args.get("instance_type")
        if machine is not None:
            allowed = self._placement.get("allowed_machine_types", [])
            if machine not in allowed:
                return (
                    "placement.allowed_machine_types",
                    f"machine type '{machine}' not in {allowed}",
                )
        return None

    def _check_budget(
        self, tool: str, args: dict[str, Any], spend: "SpendSnapshot"
    ) -> tuple[str, str] | None:
        if not _is_spending_tool(tool):
            return None

        cap_run = self._budget.get("max_usd_per_run")
        if cap_run is not None and spend.run_usd >= cap_run:
            return (
                "budget.max_usd_per_run",
                f"run has spent ${spend.run_usd:.2f} of ${cap_run:.2f} ceiling",
            )

        cap_day = self._budget.get("max_usd_per_day")
        if cap_day is not None and spend.day_usd >= cap_day:
            return (
                "budget.max_usd_per_day",
                f"today has spent ${spend.day_usd:.2f} of ${cap_day:.2f} ceiling",
            )

        cap_n = self._budget.get("max_concurrent_instances")
        if cap_n is not None and spend.live_instances >= cap_n:
            return (
                "budget.max_concurrent_instances",
                f"{spend.live_instances} instances already live, ceiling is {cap_n}",
            )

        # A launch whose own estimate would breach the run ceiling is refused
        # before it starts, not after it has burned the difference.
        est = args.get("estimated_usd")
        if tool in _ESTIMATE_REQUIRED_TOOLS and est is None:
            return (
                "budget.require_estimated_usd",
                f"{tool} requires estimated_usd so the budget can be enforced before launch",
            )

        if est is not None:
            try:
                estimate = float(est)
            except (TypeError, ValueError):
                return (
                    "budget.estimated_usd",
                    f"estimated_usd={est!r} is not a valid number",
                )
            if not math.isfinite(estimate) or estimate < 0:
                return (
                    "budget.estimated_usd",
                    "estimated_usd must be a finite, non-negative number",
                )
        else:
            estimate = None

        if estimate is not None and cap_run is not None and spend.run_usd + estimate > cap_run:
            return (
                "budget.max_usd_per_run",
                f"estimate ${estimate:.2f} would take the run past ${cap_run:.2f}",
            )
        return None

    def _check_lifetime(self, tool: str, args: dict[str, Any]) -> tuple[str, str] | None:
        if tool not in _LIFETIME_TOOLS:
            return None
        if not self._budget.get("require_max_lifetime_minutes"):
            return None

        ttl = args.get("max_lifetime_minutes")
        if ttl is None and args.get("max_lifetime_seconds") is not None:
            ttl = int(args["max_lifetime_seconds"]) // 60

        if ttl is None:
            return (
                "budget.require_max_lifetime_minutes",
                "launch carries no max_lifetime_minutes; an instance with no "
                "teardown deadline is how the overnight bill happens",
            )
        try:
            lifetime = float(ttl)
        except (TypeError, ValueError):
            return (
                "budget.max_lifetime_ceiling_minutes",
                "max_lifetime_minutes must be a positive number",
            )
        if not math.isfinite(lifetime) or lifetime <= 0:
            return (
                "budget.max_lifetime_ceiling_minutes",
                "max_lifetime_minutes must be a positive number",
            )

        ceiling = self._budget.get("max_lifetime_ceiling_minutes")
        if ceiling is not None and lifetime > float(ceiling):
            return (
                "budget.max_lifetime_ceiling_minutes",
                f"max_lifetime_minutes={ttl} exceeds ceiling {ceiling}",
            )
        return None

    # -- egress ----------------------------------------------------------

    def redact(self, text: str) -> tuple[str, tuple[str, ...]]:
        """Strip secrets before text reaches a model or the ledger.

        Returns the cleaned text and the names of the patterns that fired, so
        the ledger can record that a redaction happened without recording what
        was redacted.
        """
        fired: list[str] = []
        out = text
        for name, rx in self._redactors:
            out, n = rx.subn(f"[REDACTED:{name}]", out)
            if n:
                fired.append(name)
        return out, tuple(fired)


@dataclass(frozen=True)
class SpendSnapshot:
    """What the fleet has already cost, as of now."""

    run_usd: float = 0.0
    day_usd: float = 0.0
    live_instances: int = 0


_SPENDING_TOOLS = frozenset(
    {"launch_gpu", "launch_cluster", "run_job", "create_filesystem", "set_keep_alive"}
)

_LIFETIME_TOOLS = frozenset({"launch_gpu", "launch_cluster"})
_ESTIMATE_REQUIRED_TOOLS = _LIFETIME_TOOLS


def _is_spending_tool(tool: str) -> bool:
    return tool in _SPENDING_TOOLS
