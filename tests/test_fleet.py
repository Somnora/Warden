"""Tests for the Warden ADK Multi-Agent Fleet and Governance Plugin."""

import pytest
from warden.fleet import DEFAULT_MODEL, initialize_fleet_runtime
from warden.ledger.chain import Record, verify
from warden.policy.approvals import ApprovalState, MemoryApprovals
from warden.policy.engine import Disposition, SpendSnapshot
from warden.tools.mock_provider import MockInfrastructureProvider


@pytest.fixture
def runtime():
    mock_backend = MockInfrastructureProvider()
    approvals = MemoryApprovals()
    return initialize_fleet_runtime(backend=mock_backend, approvals=approvals, run_id="test-run-fleet")


def test_fleet_agent_hierarchy(runtime):
    assert DEFAULT_MODEL == "gemini-3.7-flash"
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
    assert pending[0].preflight["estimated_usd"] == 2.50
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
    assert records[1].cost_usd == 2.50
    assert plugin.spend.run_usd == 2.50
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
