"""Tests for the Warden ADK Multi-Agent Fleet and Governance Plugin."""

import asyncio
import pytest
from warden.fleet import DEFAULT_MODEL, initialize_fleet_runtime
from warden.ledger.chain import Record, verify
from warden.models import resolve_model
from warden.policy.approvals import ApprovalState, MemoryApprovals
from warden.policy.engine import Disposition, SpendSnapshot
from warden.spend import MemorySpendStore
from warden.tools.mock_provider import MockInfrastructureProvider
from warden.workflow_context import begin_workflow, finish_workflow


@pytest.fixture
def runtime():
    mock_backend = MockInfrastructureProvider()
    approvals = MemoryApprovals()
    return initialize_fleet_runtime(backend=mock_backend, approvals=approvals, run_id="test-run-fleet")


def test_fleet_agent_hierarchy(runtime):
    assert DEFAULT_MODEL == "gemini-3.5-flash"
    assert resolve_model("3.7") == "gemini-3.7-flash"
    assert resolve_model("gemini-2.5-flash-lite") == "gemini-2.5-flash-lite"
    lead = runtime.lead_agent
    assert lead.name == "fleet_lead"
    assert len(lead.sub_agents) == 3
    names = {sa.name for sa in lead.sub_agents}
    assert names == {"resource_auditor", "infrastructure_provisioner", "lifecycle_manager"}


def test_toolset_assignment(runtime):
    assert "auditor" in runtime.toolsets
    assert "provisioner" in runtime.toolsets
    assert "lifecycle" in runtime.toolsets

    auditor_names = {t.name for t in runtime.toolsets["auditor"]}
    assert "list_instances" in auditor_names
    assert "get_spend" in auditor_names

    provisioner_names = {t.name for t in runtime.toolsets["provisioner"]}
    assert "launch_gpu" in provisioner_names
    assert "run_job" in provisioner_names

    lifecycle_names = {t.name for t in runtime.toolsets["lifecycle"]}
    assert "terminate_instance" in lifecycle_names


@pytest.mark.asyncio
async def test_plugin_allows_read_only_tool(runtime):
    plugin = runtime.plugin
    tool = [t for t in runtime.toolsets["auditor"] if t.name == "list_instances"][0]
    assert tool.name == "list_instances"

    class DummyContext:
        agent_name = "resource_auditor"

    # Evaluate before_tool_callback
    result = await plugin.before_tool_callback(
        tool=tool,
        tool_args={"note": "check running nodes"},
        tool_context=DummyContext(),
    )
    # Allowed tools return None so the tool executes normally
    assert result is None

    # Check ledger recorded the action
    records = await runtime.ledger.read()
    assert len(records) == 1
    assert records[0].tool == "list_instances"
    assert records[0].actor == "resource_auditor"
    assert records[0].outcome == "allowed"

    v = await runtime.ledger.verify()
    assert v.ok


@pytest.mark.asyncio
async def test_plugin_gates_spending_tool_with_ticket(runtime):
    plugin = runtime.plugin
    tool = [t for t in runtime.toolsets["provisioner"] if t.name == "launch_gpu"][0]

    class DummyContext:
        agent_name = "infrastructure_provisioner"

    args = {
        "provider": "gcp",
        "region": "us-west1",
        "machine_type": "g2-standard-8",
        "max_lifetime_minutes": 60,
        "estimated_usd": 2.50,
    }

    # First call: pending human approval
    result = await plugin.before_tool_callback(
        tool=tool,
        tool_args=args,
        tool_context=DummyContext(),
    )
    assert result is not None
    assert result.get("warden") == "awaiting_human_approval"
    ticket_id = result.get("approval_id")
    assert ticket_id is not None

    pending = await runtime.approvals.pending()
    assert len(pending) == 1
    assert pending[0].approval_id == ticket_id
    assert pending[0].preflight["estimated_usd"] == 0.85
    assert pending[0].preflight["quote_source"] == "MACHINE_HOURLY_RATES"
    assert pending[0].preflight["agent_estimated_usd"] == 2.50
    assert pending[0].preflight["placement"]["region"] == "us-west1"
    assert "rollback" in pending[0].preflight["rollback_plan"].lower()

    # Simulate human operator approving the ticket
    await runtime.approvals.decide(ticket_id, granted=True, approver="alice@enterprise.com", note="Approved for ML benchmark")

    # Second call after human approval: permitted to execute
    result_after = await plugin.before_tool_callback(
        tool=tool,
        tool_args=args,
        tool_context=DummyContext(),
    )
    assert result_after is None  # None means proceed with tool execution

    records = await runtime.ledger.read()
    assert len(records) == 2
    assert records[0].outcome == "pending_approval"
    assert records[1].outcome == "approved"
    assert records[1].approver == "alice@enterprise.com"
    assert records[1].cost_usd == 0.85
    assert plugin.spend.run_usd == 0.85
    assert plugin.spend.live_instances == 2

    # A human sign-off is valid for exactly one provider invocation.
    # Reset the independent spend guard so this assertion reaches the ticket
    # replay protection rather than the concurrent-instance ceiling first.
    plugin.spend = SpendSnapshot(run_usd=0.0, day_usd=0.0, live_instances=1)
    replay = await plugin.before_tool_callback(
        tool=tool,
        tool_args=args,
        tool_context=DummyContext(),
    )
    assert replay is not None
    assert replay["warden"] == "approval_already_consumed"

    v = await runtime.ledger.verify()
    assert v.ok


@pytest.mark.asyncio
async def test_plugin_settles_shared_spend_then_releases_verified_teardown_capacity():
    backend = MockInfrastructureProvider()
    spend_store = MemorySpendStore()
    runtime = initialize_fleet_runtime(
        backend=backend,
        approvals=MemoryApprovals(),
        run_id="distributed-spend-run",
        spend_store=spend_store,
    )
    launch = next(t for t in runtime.toolsets["provisioner"] if t.name == "launch_gpu")
    terminate = next(t for t in runtime.toolsets["lifecycle"] if t.name == "terminate_instance")
    provisioner = type("Provisioner", (), {"agent_name": "infrastructure_provisioner"})()
    lifecycle = type("Lifecycle", (), {"agent_name": "lifecycle_manager"})()
    launch_args = {
        "provider": "gcp", "region": "us-west1", "machine_type": "g2-standard-8",
        "max_lifetime_minutes": 60,
    }

    tokens = begin_workflow(runtime.run_id)
    try:
        pending = await runtime.plugin.before_tool_callback(
            tool=launch, tool_args=launch_args, tool_context=provisioner
        )
        await runtime.approvals.decide(
            pending["approval_id"], granted=True, approver="operator@example.com"
        )
        assert await runtime.plugin.before_tool_callback(
            tool=launch, tool_args=launch_args, tool_context=provisioner
        ) is None
        assert await runtime.plugin.after_tool_callback(
            tool=launch, tool_args=launch_args, tool_context=provisioner,
            result={"status": "RUNNING", "id": "instance-durable-1"},
        ) is None

        settled = await spend_store.summary(runtime.run_id)
        assert settled.run_usd == pytest.approx(0.85)
        assert settled.settled_usd == pytest.approx(0.85)
        assert settled.live_instances == 1

        terminate_args = {"instance_id": "instance-durable-1"}
        pending = await runtime.plugin.before_tool_callback(
            tool=terminate, tool_args=terminate_args, tool_context=lifecycle
        )
        await runtime.approvals.decide(
            pending["approval_id"], granted=True, approver="operator@example.com"
        )
        assert await runtime.plugin.before_tool_callback(
            tool=terminate, tool_args=terminate_args, tool_context=lifecycle
        ) is None
        assert await runtime.plugin.after_tool_callback(
            tool=terminate, tool_args=terminate_args, tool_context=lifecycle,
            result={"status": "terminated", "instance_id": "instance-durable-1"},
        ) is None
    finally:
        finish_workflow(tokens)

    released = await spend_store.summary(runtime.run_id)
    assert released.live_instances == 0
    assert released.settled_usd == pytest.approx(0.85)


@pytest.mark.asyncio
async def test_plugin_hard_denies_policy_violation(runtime):
    plugin = runtime.plugin
    tool = [t for t in runtime.toolsets["provisioner"] if t.name == "launch_gpu"][0]

    class DummyContext:
        agent_name = "infrastructure_provisioner"

    # Region not in allowed_regions (europe-west4)
    args = {
        "provider": "gcp",
        "region": "europe-west4",
        "machine_type": "g2-standard-8",
        "max_lifetime_minutes": 60,
    }

    result = await plugin.before_tool_callback(
        tool=tool,
        tool_args=args,
        tool_context=DummyContext(),
    )
    assert result is not None
    assert result.get("warden") == "denied_by_policy"
    assert "europe-west4" in result.get("reason", "")

    records = await runtime.ledger.read()
    assert len(records) == 1
    assert records[0].outcome == "refused"
    assert records[0].disposition == "deny"


@pytest.mark.asyncio
async def test_plugin_egress_redaction(runtime):
    plugin = runtime.plugin
    tool = [t for t in runtime.toolsets["provisioner"] if t.name == "run_command"][0]

    class DummyContext:
        agent_name = "infrastructure_provisioner"

    raw_output = {
        "stdout": "GCP_KEY=AIzaSyA12345678901234567890123456789012 status=done",
        "exit_code": 0,
    }

    redacted_result = await plugin.after_tool_callback(
        tool=tool,
        tool_args={"command": "env"},
        tool_context=DummyContext(),
        result=raw_output,
    )
    assert redacted_result is not None
    assert redacted_result.get("warden") == "redacted"
    assert "gcp_api_key" in redacted_result.get("patterns", [])
    cleaned = redacted_result.get("result", {})
    assert isinstance(cleaned, dict)
    assert "AIzaSy" not in cleaned["stdout"]
    assert "[REDACTED:gcp_api_key]" in cleaned["stdout"]


@pytest.mark.asyncio
async def test_plugin_redaction_preserves_structured_tool_result(runtime):
    plugin = runtime.plugin
    tool = [t for t in runtime.toolsets["provisioner"] if t.name == "run_command"][0]

    class DummyContext:
        agent_name = "infrastructure_provisioner"

    redacted_result = await plugin.after_tool_callback(
        tool=tool,
        tool_args={"command": "env"},
        tool_context=DummyContext(),
        result={"private_key": "-----BEGIN PRIVATE KEY-----secret"},
    )
    assert redacted_result is not None
    assert redacted_result["result"] == {"private_key": "[REDACTED:gcp_service_account_key]"}


@pytest.mark.asyncio
async def test_plugin_gates_arbitrary_shell_until_ticket_granted(runtime):
    plugin = runtime.plugin
    tool = [t for t in runtime.toolsets["provisioner"] if t.name == "run_command"][0]

    class DummyContext:
        agent_name = "infrastructure_provisioner"

    args = {"instance_id": "gpu-1", "command": "curl http://metadata/"}
    parked = await plugin.before_tool_callback(tool=tool, tool_args=args, tool_context=DummyContext())
    assert parked is not None
    assert parked["warden"] == "awaiting_human_approval"
    await runtime.approvals.decide(parked["approval_id"], granted=True, approver="sre@example.com")
    released = await plugin.before_tool_callback(tool=tool, tool_args=args, tool_context=DummyContext())
    assert released is None


@pytest.mark.asyncio
async def test_plugin_allows_readonly_inspection_command(runtime):
    plugin = runtime.plugin
    tool = [t for t in runtime.toolsets["provisioner"] if t.name == "run_command"][0]

    class DummyContext:
        agent_name = "infrastructure_provisioner"

    result = await plugin.before_tool_callback(
        tool=tool,
        tool_args={"instance_id": "gpu-1", "command": "nvidia-smi"},
        tool_context=DummyContext(),
    )
    assert result is None


@pytest.mark.asyncio
async def test_approval_claim_is_single_use_under_concurrency():
    approvals = MemoryApprovals()
    args = {"region": "us-west1"}
    ticket = await approvals.request(
        run_id="run/with/slashes", tool="launch_gpu", args=args,
        actor="provisioner", reason="test",
    )
    assert ticket.startswith("approval-") and "/" not in ticket
    await approvals.decide(ticket, granted=True, approver="operator@example.com")
    thief = await approvals.claim(
        run_id="run/with/slashes", tool="launch_gpu", args=args, actor="lifecycle_manager"
    )
    assert thief.status is ApprovalState.PENDING
    claims = await asyncio.gather(
        approvals.claim(
            run_id="run/with/slashes", tool="launch_gpu", args=args, actor="provisioner"
        ),
        approvals.claim(
            run_id="run/with/slashes", tool="launch_gpu", args=args, actor="provisioner"
        ),
    )
    assert sorted(claim.status.value for claim in claims) == ["consumed", "granted"]


@pytest.mark.asyncio
async def test_expired_approval_cannot_be_decided_or_claimed():
    approvals = MemoryApprovals(ttl_seconds=0)
    args = {"region": "us-west1"}
    ticket = await approvals.request(
        run_id="expired-run", tool="launch_gpu", args=args,
        actor="provisioner", reason="test",
    )
    with pytest.raises(ValueError, match="expired"):
        await approvals.decide(ticket, granted=True, approver="operator@example.com")
    claim = await approvals.claim(
        run_id="expired-run", tool="launch_gpu", args=args, actor="provisioner"
    )
    assert claim.status is ApprovalState.EXPIRED
    assert await approvals.pending() == []


@pytest.mark.asyncio
async def test_concurrent_approved_launches_cannot_race_budget(runtime):
    plugin = runtime.plugin
    tool = next(t for t in runtime.toolsets["provisioner"] if t.name == "launch_gpu")

    class DummyContext:
        agent_name = "infrastructure_provisioner"

    common = {
        "provider": "gcp", "machine_type": "a2-highgpu-1g",
        "max_lifetime_minutes": 180,
    }
    calls = [{**common, "region": "us-west1"}, {**common, "region": "us-central1"}]
    for args in calls:
        parked = await plugin.before_tool_callback(
            tool=tool, tool_args=args, tool_context=DummyContext()
        )
        await runtime.approvals.decide(
            parked["approval_id"], granted=True, approver="operator@example.com"
        )

    plugin.spend = SpendSnapshot(run_usd=10.0, day_usd=10.0, live_instances=0)
    results = await asyncio.gather(*(
        plugin.before_tool_callback(tool=tool, tool_args=args, tool_context=DummyContext())
        for args in calls
    ))
    assert sum(result is None for result in results) == 1
    refused = next(result for result in results if result is not None)
    assert refused["warden"] == "denied_by_policy"
    assert plugin.spend.run_usd == pytest.approx(21.01)


@pytest.mark.asyncio
async def test_callback_failures_block_provider_fail_closed(runtime):
    class BrokenLedger:
        async def append(self, rec):
            raise RuntimeError("firestore unavailable")

    runtime.plugin.ledger = BrokenLedger()
    tool = next(t for t in runtime.toolsets["auditor"] if t.name == "list_instances")
    result = await runtime.plugin.before_tool_callback(
        tool=tool, tool_args={}, tool_context=type("Context", (), {"agent_name": "auditor"})()
    )
    assert result["warden"] == "control_plane_error"


@pytest.mark.asyncio
async def test_malformed_callback_args_and_cyclic_output_are_safely_blocked(runtime):
    tool = next(t for t in runtime.toolsets["auditor"] if t.name == "list_instances")
    context = type("Context", (), {"agent_name": "auditor"})()
    blocked = await runtime.plugin.before_tool_callback(
        tool=tool, tool_args=["bad"], tool_context=context  # type: ignore[arg-type]
    )
    assert blocked["warden"] == "denied_by_policy"

    cyclic: list[object] = []
    cyclic.append(cyclic)
    cleaned = await runtime.plugin.after_tool_callback(
        tool=tool, tool_args={}, tool_context=context, result=cyclic
    )
    assert cleaned["warden"] == "redacted"
    assert cleaned["result"] == ["[REDACTED:output_cycle]"]
