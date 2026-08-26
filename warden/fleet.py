"""Warden Multi-Agent Fleet built with Google Agent Development Kit (ADK).

Defines the specialized agent hierarchy:
  - FleetLead: Coordinator and task planner
  - Auditor: Read-only resource observer and spend monitor
  - Provisioner: Compute deployer and job executor (spend gated)
  - LifecycleManager: Teardown and cluster cleaner (destroy gated)

All agent actions are governed at the Runner level by WardenPlugin.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from google.adk.agents import Agent
from google.adk.agents.context_cache_config import ContextCacheConfig
from google.adk.apps import App, ResumabilityConfig
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService, BaseSessionService
from google.adk.tools import BaseTool, FunctionTool
from google.genai import types

from warden.ledger.chain import Record, Verdict
from warden.ledger.store import LedgerStore, MemoryLedger
from warden.policy.approvals import ApprovalStore, MemoryApprovals, Ticket
from warden.policy.engine import Policy, SpendSnapshot
from warden.policy.plugin import WardenPlugin
from warden.tools.factory import create_toolset
from warden.tools.definitions import InfrastructureBackend
from warden.models import DEFAULT_MODEL, resolve_model
from warden.missions import MissionStore
from warden.spend import SpendStore
from warden.telemetry import configure_cloud_trace
from warden.workflow_context import begin_workflow, finish_workflow

log = logging.getLogger("warden.fleet")


def create_auditor_agent(
    tools: list[BaseTool] | None = None,
    *,
    model: str = DEFAULT_MODEL,
) -> Agent:
    """Create the Resource Auditor agent responsible for read-only fleet inspection."""
    return Agent(
        name="resource_auditor",
        model=model,
        instruction=(
            "You are the Resource Auditor in the Warden Enterprise Fleet. "
            "Your responsibility is to inspect running instances, check current spend "
            "against budget limits, review cluster topology, and examine recent work logs. "
            "All your operations are read-only and free from spend risk."
        ),
        tools=tools or [],
    )


def create_provisioner_agent(
    tools: list[BaseTool] | None = None,
    *,
    model: str = DEFAULT_MODEL,
) -> Agent:
    """Create the Infrastructure Provisioner agent responsible for GPU/cluster deployments."""
    return Agent(
        name="infrastructure_provisioner",
        model=model,
        instruction=(
            "You are the Infrastructure Provisioner in the Warden Enterprise Fleet. "
            "Your responsibility is to provision GPU compute instances, launch clusters, "
            "and submit batch jobs according to workload requirements. "
            "MANDATORY POLICY: Always include max_lifetime_minutes and machine_type. "
            "Warden quotes cost from the policy rate card; do not invent a cheaper estimated_usd "
            "to bypass budget. Never attempt to launch resources in unapproved regions. "
            "Be aware that spending tools require human approval before execution."
        ),
        tools=tools or [],
    )


def create_lifecycle_agent(
    tools: list[BaseTool] | None = None,
    *,
    model: str = DEFAULT_MODEL,
) -> Agent:
    """Create the Lifecycle Manager agent responsible for resource teardown."""
    return Agent(
        name="lifecycle_manager",
        model=model,
        instruction=(
            "You are the Lifecycle Manager in the Warden Enterprise Fleet. "
            "Your responsibility is to terminate finished GPU instances, tear down "
            "clusters, and clean up templates. "
            "POLICY NOTE: Destruction of state is gated by human approval to prevent "
            "unrecoverable data loss."
        ),
        tools=tools or [],
    )


def create_fleet_lead_agent(
    sub_agents: list[Agent] | None = None,
    tools: list[BaseTool] | None = None,
    *,
    model: str = DEFAULT_MODEL,
) -> Agent:
    """Create the Fleet Orchestrator agent that leads the team."""
    return Agent(
        name="fleet_lead",
        model=model,
        instruction=(
            "You are the Fleet Orchestrator of Warden, a fortified control plane for "
            "Google Cloud infrastructure. "
            "You coordinate specialized sub-agents: "
            "  1. resource_auditor: Use for inspecting active instances, checking spend, and reading logs. "
            "  2. infrastructure_provisioner: Use for launching GPUs, creating clusters, and running jobs. "
            "  3. lifecycle_manager: Use for terminating instances and cleaning up resources. "
            "Plan and delegate requests carefully. If an action is denied by policy or parked for "
            "human approval, explain the exact reason clearly to the user without hallucinating workarounds."
        ),
        sub_agents=sub_agents or [],
        tools=tools or [],
    )


@dataclass
class WardenFleetRuntime:
    """Encapsulates the complete governed fleet runtime."""

    policy: Policy
    ledger: LedgerStore
    approvals: ApprovalStore
    plugin: WardenPlugin
    lead_agent: Agent
    runner: Runner
    session_service: BaseSessionService
    run_id: str
    toolsets: dict[str, list[FunctionTool]] = field(default_factory=dict)
    app: App | None = None
    cloud_trace_enabled: bool = False
    model: str = DEFAULT_MODEL


def initialize_fleet_runtime(
    *,
    policy: Policy | None = None,
    ledger: LedgerStore | None = None,
    approvals: ApprovalStore | None = None,
    backend: InfrastructureBackend | None = None,
    mode: str = "mock",
    run_id: str = "fleet-run-001",
    model: str | None = None,
    session_service: BaseSessionService | None = None,
    manifold_url: str | None = None,
    api_token: str | None = None,
    missions: MissionStore | None = None,
    spend_store: SpendStore | None = None,
) -> WardenFleetRuntime:
    """Initialize a complete governed Warden fleet runtime."""
    cloud_trace_enabled = configure_cloud_trace()
    resolved_model = resolve_model(model)
    pol = policy or Policy.load()
    led = ledger or MemoryLedger()
    appr = approvals or MemoryApprovals()
    sess = session_service or InMemorySessionService()

    toolsets = create_toolset(
        backend=backend, mode=mode, manifold_url=manifold_url, api_token=api_token
    )

    plugin = WardenPlugin(
        policy=pol,
        ledger=led,
        approvals=appr,
        run_id=run_id,
        spend=SpendSnapshot(run_usd=0.0, day_usd=4.50, live_instances=1),
        missions=missions,
        spend_store=spend_store,
    )

    lead, app, runner = _assemble_adk(
        policy=pol,
        plugin=plugin,
        toolsets=toolsets,
        model=resolved_model,
        session_service=sess,
    )

    return WardenFleetRuntime(
        policy=pol,
        ledger=led,
        approvals=appr,
        plugin=plugin,
        lead_agent=lead,
        runner=runner,
        session_service=sess,
        run_id=run_id,
        toolsets=toolsets,
        app=app,
        cloud_trace_enabled=cloud_trace_enabled,
        model=resolved_model,
    )


def apply_model(runtime: WardenFleetRuntime, model: str) -> str:
    """Rebuild the ADK hierarchy onto a different cataloged Gemini model."""
    resolved = resolve_model(model)
    lead, app, runner = _assemble_adk(
        policy=runtime.policy,
        plugin=runtime.plugin,
        toolsets=runtime.toolsets,
        model=resolved,
        session_service=runtime.session_service,
    )
    runtime.lead_agent = lead
    runtime.app = app
    runtime.runner = runner
    runtime.model = resolved
    return resolved


def _assemble_adk(
    *,
    policy: Policy,
    plugin: WardenPlugin,
    toolsets: dict[str, list[FunctionTool]],
    model: str,
    session_service: BaseSessionService,
) -> tuple[Agent, App, Runner]:
    auditor = create_auditor_agent(tools=toolsets["auditor"], model=model)
    provisioner = create_provisioner_agent(tools=toolsets["provisioner"], model=model)
    lifecycle = create_lifecycle_agent(tools=toolsets["lifecycle"], model=model)
    lead = create_fleet_lead_agent(
        sub_agents=[auditor, provisioner, lifecycle],
        tools=toolsets["security_test"],
        model=model,
    )
    app = App(
        name=f"warden-{policy.fleet}",
        root_agent=lead,
        plugins=[plugin],
        context_cache_config=ContextCacheConfig(
            cache_intervals=10,
            ttl_seconds=1800,
            min_tokens=4096,
        ),
        resumability_config=ResumabilityConfig(is_resumable=True),
    )
    runner = Runner(
        app=app,
        session_service=session_service,
        auto_create_session=True,
    )
    return lead, app, runner


@dataclass
class FleetTurnResult:
    """Summary of one executed turn in the fleet."""

    response_text: str
    events_count: int
    records: list[Record] = field(default_factory=list)
    pending_approvals: list[Ticket] = field(default_factory=list)
    pending_approval_ids: list[str] = field(default_factory=list)
    verdict: Verdict | None = None


async def execute_turn(
    runtime: WardenFleetRuntime,
    prompt: str,
    *,
    user_id: str = "operator-01",
    session_id: str = "session-001",
    run_id: str | None = None,
    mission_id: str | None = None,
    resume: bool = False,
) -> FleetTurnResult:
    """Execute one user interaction with the fleet and capture governance artifacts."""
    if resume:
        prompt = (
            "Resume the previously parked workflow. The human approval is now granted. "
            "Continue the original request using only the exact already-approved action; "
            "do not request a duplicate approval or invent an alternate path.\n\n"
            f"Original request:\n{prompt}"
        )
    content = types.Content(
        role="user",
        parts=[types.Part.from_text(text=prompt)],
    )

    events_count = 0
    final_text_parts: list[str] = []

    effective_run_id = run_id or runtime.run_id
    approval_token = begin_workflow(effective_run_id, mission_id, user_id)
    try:
        # Run the ADK runner async event loop
        async for event in runtime.runner.run_async(
            user_id=user_id,
            session_id=session_id,
            new_message=content,
        ):
            events_count += 1
            if event.message and event.message.parts:
                for part in event.message.parts:
                    if getattr(part, "text", None):
                        final_text_parts.append(part.text)
    finally:
        pending_approval_ids = finish_workflow(approval_token)

    # Gather audit records & pending approvals
    all_records = await runtime.ledger.read()
    records = [record for record in all_records if record.run_id == effective_run_id]
    verdict = await runtime.ledger.verify()
    pending: list[Ticket] = []
    pending_method = getattr(runtime.approvals, "pending", None)
    if pending_method is not None:
        pending = [
            ticket
            for ticket in await pending_method()
            if ticket.approval_id in pending_approval_ids
        ]

    return FleetTurnResult(
        response_text="\n".join(final_text_parts).strip(),
        events_count=events_count,
        records=records,
        pending_approvals=pending,
        pending_approval_ids=pending_approval_ids,
        verdict=verdict,
    )
