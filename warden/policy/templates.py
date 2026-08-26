"""Versioned, reviewable policy starting points.

Templates are immutable application assets, not live policy mutation endpoints.
Operators can inspect, simulate, and replay a template before changing the
deployed policy through their normal reviewed delivery process.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from hashlib import sha256
import json
from typing import Any

from warden.policy.engine import Policy


@dataclass(frozen=True)
class PolicyTemplate:
    template_id: str
    version: str
    name: str
    audience: str
    description: str
    policy: dict[str, Any]

    @property
    def fingerprint(self) -> str:
        blob = json.dumps(self.policy, sort_keys=True, separators=(",", ":"))
        return sha256(blob.encode("utf-8")).hexdigest()

    def summary(self) -> dict[str, Any]:
        budget = self.policy.get("budget", {})
        placement = self.policy.get("placement", {})
        return {
            "template_id": self.template_id,
            "version": self.version,
            "name": self.name,
            "audience": self.audience,
            "description": self.description,
            "fingerprint": self.fingerprint,
            "budget": {
                key: budget.get(key)
                for key in (
                    "max_usd_per_run", "max_usd_per_day", "max_concurrent_instances",
                    "max_lifetime_ceiling_minutes",
                )
            },
            "placement": {
                key: placement.get(key, [])
                for key in ("allowed_providers", "allowed_regions", "allowed_machine_types")
            },
        }


def _template_doc(*, fleet: str, budget: dict[str, Any], machines: list[str] | None = None) -> dict[str, Any]:
    base = deepcopy(Policy.load().doc)
    base["fleet"] = fleet
    base["budget"].update(budget)
    if machines is not None:
        base["placement"]["allowed_machine_types"] = machines
    # Validate at construction time. A broken template must never be exposed
    # as a plausible production policy.
    Policy(base)
    return base


_TEMPLATES: tuple[PolicyTemplate, ...] = (
    PolicyTemplate(
        template_id="creator-safe",
        version="2026.08.1",
        name="Creator Safe",
        audience="Single producers and small studios",
        description="One low-cost L4 at a time with short, mandatory teardown windows.",
        policy=_template_doc(
            fleet="warden-creator-safe",
            budget={
                "max_usd_per_run": 8.0,
                "max_usd_per_day": 25.0,
                "max_concurrent_instances": 1,
                "max_lifetime_ceiling_minutes": 90,
            },
            machines=["g2-standard-8"],
        ),
    ),
    PolicyTemplate(
        template_id="studio-burst",
        version="2026.08.1",
        name="Studio Burst",
        audience="Production teams with bounded render or training bursts",
        description="The balanced Warden default: two concurrent governed instances and a $25 run ceiling.",
        policy=_template_doc(
            fleet="warden-studio-burst",
            budget={
                "max_usd_per_run": 25.0,
                "max_usd_per_day": 100.0,
                "max_concurrent_instances": 2,
                "max_lifetime_ceiling_minutes": 180,
            },
        ),
    ),
    PolicyTemplate(
        template_id="enterprise-production",
        version="2026.08.1",
        name="Enterprise Production",
        audience="Central platform and enterprise teams",
        description="Higher approved capacity while preserving explicit approval, placement, TTL, DLP, and audit controls.",
        policy=_template_doc(
            fleet="warden-enterprise-production",
            budget={
                "max_usd_per_run": 250.0,
                "max_usd_per_day": 1000.0,
                "max_concurrent_instances": 10,
                "max_lifetime_ceiling_minutes": 180,
            },
        ),
    ),
)


def list_templates() -> list[PolicyTemplate]:
    return list(_TEMPLATES)


def get_template(template_id: str) -> PolicyTemplate | None:
    return next((template for template in _TEMPLATES if template.template_id == template_id), None)


def policy_from_template(template_id: str) -> Policy:
    template = get_template(template_id)
    if template is None:
        raise KeyError(template_id)
    return Policy(deepcopy(template.policy))
