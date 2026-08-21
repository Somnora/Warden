"""Versioned registry for the approved agents in a Warden fleet.

The registry is intentionally derived from the running ADK hierarchy and the
declarative policy, so the catalog a department sees cannot drift from the
agents that are actually allowed to run.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


CATALOG_VERSION = "0.2.0"


@dataclass(frozen=True)
class AgentRecord:
    name: str
    version: str
    owner: str
    purpose: str
    access_tier: str
    lifecycle: str
    capabilities: tuple[str, ...]

    def payload(self) -> dict[str, Any]:
        data = asdict(self)
        data["capabilities"] = list(self.capabilities)
        return data


_METADATA: dict[str, dict[str, Any]] = {
    "fleet_lead": {
        "purpose": "Plans governed infrastructure work and delegates only to cataloged specialists.",
        "access_tier": "orchestrator / no direct infrastructure privilege",
        "lifecycle": "approved",
        "capabilities": ("planning", "delegation", "approval-aware orchestration"),
    },
    "resource_auditor": {
        "purpose": "Inspects fleet health, spend, topology, and work logs.",
        "access_tier": "read-only",
        "lifecycle": "approved",
        "capabilities": ("telemetry", "cost inspection", "resource inventory"),
    },
    "infrastructure_provisioner": {
        "purpose": "Prepares GPU, cluster, and job provisioning intents for policy review.",
        "access_tier": "human-gated execution",
        "lifecycle": "approved",
        "capabilities": ("GPU provisioning", "job launch", "preflight estimation"),
    },
    "lifecycle_manager": {
        "purpose": "Plans teardown and cleanup while keeping destructive actions human-gated.",
        "access_tier": "human-gated destructive",
        "lifecycle": "approved",
        "capabilities": ("teardown planning", "TTL enforcement", "cleanup"),
    },
}


def catalog_for(runtime: Any) -> list[dict[str, Any]]:
    """Return discoverable, versioned records for the active ADK hierarchy."""
    agents = [runtime.lead_agent, *runtime.lead_agent.sub_agents]
    records: list[dict[str, Any]] = []
    for agent in agents:
        metadata = _METADATA.get(agent.name, {})
        record = AgentRecord(
            name=agent.name,
            version=CATALOG_VERSION,
            owner="Warden Platform Engineering",
            purpose=metadata.get("purpose", "Governed fleet specialist."),
            access_tier=metadata.get("access_tier", "policy enforced"),
            lifecycle=metadata.get("lifecycle", "approved"),
            capabilities=tuple(metadata.get("capabilities", ())),
        )
        records.append(record.payload())
    return records
