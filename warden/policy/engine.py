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

from warden.policy.approvals import ApprovalRequirement

DEFAULT_POLICY_PATH = Path(__file__).with_name("policy.yaml")

# Authoritative GCP list prices used for budget math. Model-supplied
# estimated_usd is never trusted for a ceiling check.
MACHINE_HOURLY_RATES: dict[str, float] = {
    "g2-standard-8": 0.85,     # 1x L4 GPU
    "g2-standard-12": 1.25,    # 1x L4 GPU + extra vCPU
    "a2-highgpu-1g": 3.67,     # 1x A100 (40GB)
    "a2-megagpu-16g": 58.72,   # 16x A100 (80GB)
}

# Inspection-only commands that may run after a blessed launch without a
# second ticket. Anything else on a shell/job tool requires approval.
SAFE_READONLY_COMMANDS: frozenset[str] = frozenset(
    {
        "nvidia-smi",
        "python -V",
        "python --version",
        "cat output.log",
    }
)


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
        if not isinstance(doc, dict):
            raise PolicyError("policy document must be a mapping")
        if doc.get("version") != 1:
            raise PolicyError(f"unsupported policy version: {doc.get('version')!r}")
        _validate_policy_document(doc)
        self.doc = doc
        self.fleet: str = doc.get("fleet", "unnamed")
        self._tools: dict[str, str] = doc.get("tools", {}) or {}
        self._budget: dict[str, Any] = doc.get("budget", {}) or {}
        self._placement: dict[str, Any] = doc.get("placement", {}) or {}
        self._rates: dict[str, Any] = doc.get("rates", {}) or {}
        self._approval: dict[str, Any] = doc.get("approval", {}) or {}
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
        if args is None:
            args = {}
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

        if not isinstance(args, dict) or any(not isinstance(key, str) for key in args):
            return Decision(
                Disposition.DENY,
                tool,
                "tool arguments must be a JSON object with string field names",
                ("arguments.json_object",),
            )

        alias_error = _check_conflicting_aliases(args)
        if alias_error is not None:
            return Decision(
                Disposition.DENY,
                tool,
                alias_error,
                ("arguments.conflicting_aliases",),
            )

        placement = self._check_placement(args)
        if placement is not None:
            rule, why = placement
            return Decision(Disposition.DENY, tool, why, (rule,))
        if args:
            rules.append("placement.ok")

        lifetime = self._check_lifetime(tool, args)
        if lifetime is not None:
            rule, why = lifetime
            return Decision(Disposition.DENY, tool, why, tuple(rules) + (rule,))

        if spend is not None:
            budget = self._check_budget(tool, args, spend)
            if budget is not None:
                rule, why = budget
                return Decision(Disposition.DENY, tool, why, tuple(rules) + (rule,))
            rules.append("budget.ok")

        if tool in _COMMAND_TOOLS and declared == Disposition.APPROVE.value:
            if _command_is_readonly_allowlisted(args):
                return Decision(
                    Disposition.ALLOW,
                    tool,
                    f"tool '{tool}' permitted by read-only command allowlist",
                    tuple(rules) + ("command.allowlist", f"tools.{tool}=approve"),
                )

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
            if not isinstance(provider, str) or provider not in allowed:
                return (
                    "placement.allowed_providers",
                    f"provider '{provider}' not in {allowed}",
                )

        region = args.get("region")
        zone = args.get("zone")
        location = region if region is not None else zone
        if location is not None:
            allowed = self._placement.get("allowed_regions", [])
            # A zone (us-west1-a) satisfies a region rule (us-west1).
            allowed_location = (
                isinstance(location, str)
                and any(
                    location == allowed_region
                    or (region is None and _zone_belongs_to(location, allowed_region))
                    for allowed_region in allowed
                )
            )
            if not allowed_location:
                return (
                    "placement.allowed_regions",
                    f"region '{location}' not in {allowed}",
                )

        machine = args.get("machine_type") or args.get("instance_type")
        if machine is not None:
            allowed = self._placement.get("allowed_machine_types", [])
            if not isinstance(machine, str) or machine not in allowed:
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

        snapshot_error = _validate_spend_snapshot(spend)
        if snapshot_error is not None:
            return "budget.snapshot", snapshot_error

        requested_instances, instance_error = _requested_instances(tool, args)
        if instance_error is not None:
            return instance_error

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
        if (
            cap_n is not None
            and requested_instances
            and spend.live_instances + requested_instances > cap_n
        ):
            return (
                "budget.max_concurrent_instances",
                f"{spend.live_instances} instances already live and this action requests "
                f"{requested_instances}; ceiling is {cap_n}",
            )

        quoted, quote_error = self.quote_launch(tool, args)
        if quote_error is not None:
            return quote_error

        if quoted is not None and cap_run is not None and spend.run_usd + quoted > cap_run:
            return (
                "budget.max_usd_per_run",
                f"rate-card quote ${quoted:.2f} would take the run past ${cap_run:.2f}",
            )
        if quoted is not None and cap_day is not None and spend.day_usd + quoted > cap_day:
            return (
                "budget.max_usd_per_day",
                f"rate-card quote ${quoted:.2f} would take today past ${cap_day:.2f}",
            )
        return None

    def quote_launch(self, tool: str, args: dict[str, Any]) -> tuple[float | None, tuple[str, str] | None]:
        """Price a launch from MACHINE_HOURLY_RATES, ignoring agent estimates."""
        if tool not in _LIFETIME_TOOLS:
            return None, None
        machine = args.get("machine_type") or args.get("instance_type")
        if machine is None:
            return None, (
                "budget.rate_card",
                f"{tool} requires machine_type so Warden can quote cost independently of the model",
            )
        hourly = MACHINE_HOURLY_RATES.get(str(machine))
        if hourly is None:
            return None, (
                "budget.rate_card",
                f"machine type '{machine}' has no hourly rate in MACHINE_HOURLY_RATES",
            )
        minutes = _lifetime_minutes(args)
        if minutes is None:
            return None, (
                "budget.require_max_lifetime_minutes",
                "launch carries no max_lifetime_minutes; an instance with no "
                "teardown deadline is how the overnight bill happens",
            )
        instances, instance_error = _requested_instances(tool, args)
        if instance_error is not None:
            return None, instance_error
        return round(float(hourly) * (minutes / 60.0) * instances, 4), None

    def quote_usd(self, tool: str, args: dict[str, Any]) -> float | None:
        quoted, error = self.quote_launch(tool, args)
        return None if error else quoted

    def approval_requirement(self, tool: str) -> ApprovalRequirement:
        """Return the durable human threshold for a tool's exact-action ticket."""
        defaults = self._approval.get("default", {})
        tool_overrides = (self._approval.get("tools", {}) or {}).get(tool, {})
        if not isinstance(defaults, dict) or not isinstance(tool_overrides, dict):
            # Construction validates this, but fail closed if a caller mutates
            # a loaded document after initialization.
            raise PolicyError("approval configuration is malformed")
        merged = defaults | tool_overrides
        return ApprovalRequirement(
            required_approvals=merged.get("required_approvals", 1),
            minimum_role=merged.get("minimum_role", "approver"),
            require_separation_from_requester=merged.get(
                "require_separation_from_requester", True
            ),
        )

    def _check_lifetime(self, tool: str, args: dict[str, Any]) -> tuple[str, str] | None:
        if tool not in _LIFETIME_TOOLS:
            return None
        if not self._budget.get("require_max_lifetime_minutes"):
            return None

        ttl = _lifetime_minutes(args)

        if ttl is None:
            return (
                "budget.require_max_lifetime_minutes",
                "launch carries no max_lifetime_minutes; an instance with no "
                "teardown deadline is how the overnight bill happens",
            )
        if isinstance(ttl, bool):
            return (
                "budget.max_lifetime_ceiling_minutes",
                "max_lifetime_minutes must be a positive number",
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
_COMMAND_TOOLS = frozenset({"run_command", "run_job", "run_detached"})


def _command_is_readonly_allowlisted(args: dict[str, Any]) -> bool:
    raw = args.get("command") or args.get("cmd")
    if not isinstance(raw, str):
        return False
    return " ".join(raw.strip().split()) in SAFE_READONLY_COMMANDS


def _is_spending_tool(tool: str) -> bool:
    return tool in _SPENDING_TOOLS


def _lifetime_minutes(args: dict[str, Any]) -> float | None:
    ttl = args.get("max_lifetime_minutes")
    if ttl is None and args.get("max_lifetime_seconds") is not None:
        if isinstance(args["max_lifetime_seconds"], bool):
            return None
        try:
            return float(args["max_lifetime_seconds"]) / 60.0
        except (TypeError, ValueError):
            return None
    if ttl is None:
        return None
    if isinstance(ttl, bool):
        return None
    try:
        lifetime = float(ttl)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(lifetime) or lifetime <= 0:
        return None
    return lifetime


def _zone_belongs_to(zone: str, region: str) -> bool:
    """Match a GCP zone to its exact region, not a loose string prefix."""
    return re.fullmatch(rf"{re.escape(region)}-[a-z]", zone) is not None


def _check_conflicting_aliases(args: dict[str, Any]) -> str | None:
    machine = args.get("machine_type")
    instance = args.get("instance_type")
    if machine is not None and instance is not None and machine != instance:
        return "machine_type and instance_type disagree"

    region = args.get("region")
    zone = args.get("zone")
    if region is not None and zone is not None:
        if not isinstance(region, str) or not isinstance(zone, str) or not _zone_belongs_to(zone, region):
            return "region and zone disagree"

    minutes = args.get("max_lifetime_minutes")
    seconds = args.get("max_lifetime_seconds")
    if minutes is not None and seconds is not None:
        if isinstance(minutes, bool) or isinstance(seconds, bool):
            return "max_lifetime_minutes and max_lifetime_seconds must be numeric"
        try:
            agree = math.isclose(float(minutes) * 60.0, float(seconds), rel_tol=0.0, abs_tol=1e-9)
        except (TypeError, ValueError, OverflowError):
            agree = False
        if not agree:
            return "max_lifetime_minutes and max_lifetime_seconds disagree"

    command = args.get("command")
    cmd = args.get("cmd")
    if command is not None and cmd is not None and command != cmd:
        return "command and cmd disagree"
    return None


def _requested_instances(
    tool: str, args: dict[str, Any]
) -> tuple[int, tuple[str, str] | None]:
    if tool == "launch_gpu":
        return 1, None
    if tool != "launch_cluster":
        return 0, None

    raw = args.get("node_count", 2)
    if isinstance(raw, bool) or not isinstance(raw, int) or raw <= 0:
        return 0, (
            "budget.node_count",
            "launch_cluster node_count must be a positive integer",
        )
    return raw, None


def _validate_spend_snapshot(spend: SpendSnapshot) -> str | None:
    for name in ("run_usd", "day_usd"):
        value = getattr(spend, name)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return f"{name} must be finite and non-negative"
        numeric = float(value)
        if not math.isfinite(numeric) or numeric < 0:
            return f"{name} must be finite and non-negative"
    if (
        isinstance(spend.live_instances, bool)
        or not isinstance(spend.live_instances, int)
        or spend.live_instances < 0
    ):
        return "live_instances must be a non-negative integer"
    return None


def _validate_policy_document(doc: dict[str, Any]) -> None:
    tools = doc.get("tools")
    if not isinstance(tools, dict) or any(not isinstance(name, str) for name in tools):
        raise PolicyError("policy tools must be a mapping with string names")
    invalid = {name: value for name, value in tools.items() if value not in {d.value for d in Disposition}}
    if invalid:
        raise PolicyError(f"invalid tool dispositions: {invalid!r}")

    for section in ("budget", "placement", "rates", "egress", "approval"):
        value = doc.get(section, {})
        if value is not None and not isinstance(value, dict):
            raise PolicyError(f"policy {section} must be a mapping")

    budget = doc.get("budget") or {}
    for name in ("max_usd_per_run", "max_usd_per_day", "max_lifetime_ceiling_minutes"):
        value = budget.get(name)
        if value is not None and (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
            or value <= 0
        ):
            raise PolicyError(f"budget.{name} must be a positive finite number")
    cap_instances = budget.get("max_concurrent_instances")
    if cap_instances is not None and (
        isinstance(cap_instances, bool) or not isinstance(cap_instances, int) or cap_instances <= 0
    ):
        raise PolicyError("budget.max_concurrent_instances must be a positive integer")

    placement = doc.get("placement") or {}
    for name in ("allowed_providers", "allowed_regions", "allowed_machine_types"):
        value = placement.get(name, [])
        if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
            raise PolicyError(f"placement.{name} must be a list of non-empty strings")

    rates = doc.get("rates") or {}
    documented_rates = rates.get("machine_usd_per_hour")
    if documented_rates is not None:
        if not isinstance(documented_rates, dict):
            raise PolicyError("rates.machine_usd_per_hour must be a mapping")
        try:
            normalized_rates = {
                str(machine): float(hourly)
                for machine, hourly in documented_rates.items()
            }
        except (TypeError, ValueError, OverflowError) as exc:
            raise PolicyError("rate-card values must be finite positive numbers") from exc
        if any(not math.isfinite(rate) or rate <= 0 for rate in normalized_rates.values()):
            raise PolicyError("rate-card values must be finite positive numbers")
        if normalized_rates != MACHINE_HOURLY_RATES:
            raise PolicyError(
                "policy rate-card documentation does not match authoritative MACHINE_HOURLY_RATES"
            )

    redactors = ((doc.get("egress") or {}).get("redact_patterns", []))
    if not isinstance(redactors, list):
        raise PolicyError("egress.redact_patterns must be a list")
    for redactor in redactors:
        if (
            not isinstance(redactor, dict)
            or not isinstance(redactor.get("name"), str)
            or not isinstance(redactor.get("pattern"), str)
        ):
            raise PolicyError("each egress redactor requires string name and pattern")

    approval = doc.get("approval") or {}
    default_requirement = approval.get("default", {})
    tool_requirements = approval.get("tools", {})
    if not isinstance(default_requirement, dict) or not isinstance(tool_requirements, dict):
        raise PolicyError("approval.default and approval.tools must be mappings")
    if any(not isinstance(tool, str) or not tool for tool in tool_requirements):
        raise PolicyError("approval.tools keys must be non-empty tool names")
    for label, requirement in [("approval.default", default_requirement), *(
        (f"approval.tools.{tool}", value) for tool, value in tool_requirements.items()
    )]:
        if not isinstance(requirement, dict):
            raise PolicyError(f"{label} must be a mapping")
        try:
            ApprovalRequirement(
                required_approvals=requirement.get("required_approvals", 1),
                minimum_role=requirement.get("minimum_role", "approver"),
                require_separation_from_requester=requirement.get(
                    "require_separation_from_requester", True
                ),
            )
        except (TypeError, ValueError) as exc:
            raise PolicyError(f"{label} is invalid: {exc}") from exc
