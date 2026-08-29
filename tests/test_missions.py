"""Mission contracts and reusable approval-envelope enforcement."""

import asyncio
import pytest

from warden.fleet import initialize_fleet_runtime
from warden.missions import (
    EnvelopeState,
    MemoryMissionStore,
    MissionContract,
    MissionState,
)
from warden.workflow_context import begin_workflow, finish_workflow


def contract(**overrides):
    values = {
        "allowed_tools": ("launch_gpu",),
        "allowed_providers": ("gcp",),
        "allowed_regions": ("us-west1",),
        "allowed_machine_types": ("g2-standard-8",),
        "max_cost_usd": 2.0,
        "max_lifetime_minutes": 60.0,
        "max_actions": 2,
        "max_instances_per_action": 1,
    }
    values.update(overrides)
    return MissionContract(**values)


@pytest.mark.asyncio
async def test_envelope_is_run_bound_and_reserves_limits_atomically():
    store = MemoryMissionStore()
    mission = await store.create(
        objective="Render two clips", created_by="producer@example.com",
        contract=contract(), model="gemini-3.5-flash",
    )
    approved = await store.approve(mission.mission_id, approved_by="producer@example.com", ttl_minutes=60)
    assert approved.state is MissionState.APPROVED

    args = {
        "provider": "gcp", "region": "us-west1", "machine_type": "g2-standard-8",
        "max_lifetime_minutes": 60,
    }
    wrong_run = await store.authorize(
        mission_id=mission.mission_id, run_id="attacker-run", tool="launch_gpu",
        args=args, cost_usd=0.85,
    )
    assert not wrong_run.granted

    first = await store.authorize(
        mission_id=mission.mission_id, run_id=mission.run_id, tool="launch_gpu",
        args=args, cost_usd=0.85,
    )
    second = await store.authorize(
        mission_id=mission.mission_id, run_id=mission.run_id, tool="launch_gpu",
        args=args, cost_usd=0.85,
    )
    assert first.granted and second.granted
    exhausted = await store.get(mission.mission_id)
    assert exhausted is not None and exhausted.envelope is not None
    assert exhausted.envelope.actions_used == 2
    assert exhausted.envelope.reserved_usd == 1.7
    assert exhausted.envelope.status is EnvelopeState.EXHAUSTED


@pytest.mark.asyncio
async def test_out_of_scope_action_does_not_consume_envelope():
    store = MemoryMissionStore()
    mission = await store.create(
        objective="One bounded launch", created_by="operator",
        contract=contract(max_actions=1), model="gemini-3.5-flash",
    )
    await store.approve(mission.mission_id, approved_by="approver", ttl_minutes=60)
    denied = await store.authorize(
        mission_id=mission.mission_id, run_id=mission.run_id, tool="launch_gpu",
        args={
            "provider": "gcp", "region": "us-central1", "machine_type": "g2-standard-8",
            "max_lifetime_minutes": 60,
        },
        cost_usd=0.85,
    )
    assert not denied.granted
    assert "outside" in denied.reason
    current = await store.get(mission.mission_id)
    assert current is not None and current.envelope is not None
    assert current.envelope.actions_used == 0
    assert current.envelope.status is EnvelopeState.ACTIVE


@pytest.mark.asyncio
async def test_plugin_uses_envelope_then_falls_back_for_deviation():
    missions = MemoryMissionStore()
    mission = await missions.create(
        objective="Launch safely", created_by="operator", contract=contract(),
        model="gemini-3.5-flash",
    )
    await missions.approve(mission.mission_id, approved_by="human@example.com", ttl_minutes=60)
    runtime = initialize_fleet_runtime(run_id="control", missions=missions)
    tool = next(t for t in runtime.toolsets["provisioner"] if t.name == "launch_gpu")

    class Context:
        agent_name = "infrastructure_provisioner"

    in_scope = {
        "provider": "gcp", "region": "us-west1", "machine_type": "g2-standard-8",
        "max_lifetime_minutes": 60,
    }
    tokens = begin_workflow(mission.run_id, mission.mission_id)
    try:
        assert await runtime.plugin.before_tool_callback(
            tool=tool, tool_args=in_scope, tool_context=Context()
        ) is None
    finally:
        finish_workflow(tokens)
    records = await runtime.ledger.read()
    assert records[-1].outcome == "envelope_authorized"
    assert records[-1].approver == "human@example.com"

    # us-central1 is legal under fleet policy, but outside this Mission. It
    # therefore receives a fresh exact-action ticket rather than broad access.
    runtime.plugin.spend = type(runtime.plugin.spend)(run_usd=0, day_usd=0, live_instances=0)
    tokens = begin_workflow(mission.run_id, mission.mission_id)
    try:
        result = await runtime.plugin.before_tool_callback(
            tool=tool, tool_args={**in_scope, "region": "us-central1"}, tool_context=Context()
        )
    finally:
        finish_workflow(tokens)
    assert result is not None and result["warden"] == "awaiting_human_approval"
    ticket = (await runtime.approvals.pending())[0]
    assert "outside the envelope" in ticket.preflight["envelope_deviation"]


@pytest.mark.asyncio
async def test_cancel_revokes_unused_authority():
    store = MemoryMissionStore()
    mission = await store.create(
        objective="Cancel me", created_by="operator", contract=contract(),
        model="gemini-3.5-flash",
    )
    await store.approve(mission.mission_id, approved_by="operator", ttl_minutes=60)
    cancelled = await store.cancel(mission.mission_id)
    assert cancelled.state is MissionState.CANCELLED
    assert cancelled.envelope is not None
    assert cancelled.envelope.status is EnvelopeState.REVOKED


@pytest.mark.asyncio
async def test_mission_start_is_exactly_once():
    store = MemoryMissionStore()
    mission = await store.create(
        objective="Start once", created_by="operator", contract=contract(),
        model="gemini-3.5-flash",
    )
    await store.approve(mission.mission_id, approved_by="operator", ttl_minutes=60)
    results = await asyncio.gather(
        store.start(mission.mission_id, "wf-1"),
        store.start(mission.mission_id, "wf-2"),
        return_exceptions=True,
    )
    assert sum(not isinstance(result, Exception) for result in results) == 1
    assert sum(isinstance(result, ValueError) for result in results) == 1


@pytest.mark.asyncio
async def test_outcomes_capture_resources_artifacts_and_cleanup_receipts():
    store = MemoryMissionStore()
    mission = await store.create(
        objective="Render and clean up", created_by="operator", contract=contract(),
        model="gemini-3.5-flash",
    )
    await store.approve(mission.mission_id, approved_by="operator", ttl_minutes=60)
    await store.start(mission.mission_id, "wf-outcomes")
    launch_args = {
        "provider": "gcp", "region": "us-west1", "machine_type": "g2-standard-8",
        "max_lifetime_minutes": 60,
    }
    await store.record_tool_result(
        mission_id=mission.mission_id, tool="launch_gpu", args=launch_args,
        result={"id": "inst-render-01", "status": "RUNNING", "stdout": "must not persist"},
    )
    await store.record_tool_result(
        mission_id=mission.mission_id, tool="sync_outputs",
        args={"instance_id": "inst-render-01"},
        result={"status": "synced", "files_copied": 3},
    )
    await store.record_tool_result(
        mission_id=mission.mission_id, tool="terminate_instance",
        args={"instance_id": "inst-render-01"},
        result={"status": "terminated", "instance_id": "inst-render-01"},
    )
    complete = await store.get(mission.mission_id)
    assert complete is not None
    assert complete.resources[0].expires_at is not None
    assert complete.resources[0].status == "cleaned"
    assert complete.artifacts[0].kind == "output_bundle"
    assert complete.artifacts[0].metadata == {"files_copied": 3}
    assert complete.cleanup_receipts[0].status == "verified_absent"
    assert any(event.kind == "cleanup_receipt" for event in complete.events)
    assert "stdout" not in str(complete)


@pytest.mark.asyncio
async def test_launch_result_can_project_provider_verified_cleanup_directly():
    store = MemoryMissionStore()
    mission = await store.create(
        objective="Create one proof VM then delete it",
        created_by="operator",
        contract=contract(max_lifetime_minutes=5),
        model="gemini-3.5-flash",
    )
    await store.record_tool_result(
        mission_id=mission.mission_id,
        tool="launch_gpu",
        args={
            "provider": "gcp",
            "region": "us-west1",
            "machine_type": "g2-standard-8",
            "max_lifetime_minutes": 5,
        },
        result={
            "id": "warden-dashboard-proof",
            "status": "CLEANED",
            "cleanup_verified": True,
        },
    )
    current = await store.get(mission.mission_id)
    assert current is not None
    assert current.resources[0].status == "cleaned"
    assert current.resources[0].cleaned_at is not None
    assert current.cleanup_receipts[0].resource_id == "warden-dashboard-proof"
    assert current.cleanup_receipts[0].status == "verified_absent"
