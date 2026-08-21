"""Tests for the Manifold HTTP & MCP Tool Bridge and Governance Interception."""

import pytest
import httpx
from warden.fleet import initialize_fleet_runtime
from warden.policy.approvals import MemoryApprovals
from warden.tools.manifold_bridge import ManifoldInfrastructureBridge
from warden.tools.factory import create_mcp_toolset, create_toolset


@pytest.fixture
def bridge():
    return ManifoldInfrastructureBridge(base_url="http://mock-manifold:8000", api_token="test-secret-token")


def test_bridge_headers(bridge):
    headers = bridge._headers()
    assert headers["Authorization"] == "Bearer test-secret-token"
    assert headers["Content-Type"] == "application/json"


@pytest.mark.asyncio
async def test_bridge_unreachable_handling():
    # Attempting to contact an unreachable local port should return unreachable error dict cleanly
    bridge_unreachable = ManifoldInfrastructureBridge(base_url="http://127.0.0.1:59999", timeout=1.0)
    res = await bridge_unreachable.list_instances()
    assert isinstance(res, dict)
    assert res.get("unreachable") is True
    assert "hint" in res


def test_mcp_toolset_factory():
    toolset = create_mcp_toolset(
        command="python",
        args=["-m", "backend.app.mcp_server"],
        tool_filter=["list_instances", "launch_gpu"],
    )
    assert toolset is not None
    assert toolset.require_confirmation is False


@pytest.mark.asyncio
async def test_privilege_escalation_decide_approval_denied():
    runtime = initialize_fleet_runtime(run_id="test-privilege-escalation")
    plugin = runtime.plugin

    # Find the decide_approval tool
    sec_tools = runtime.toolsets["security_test"]
    decide_tool = [t for t in sec_tools if t.name == "decide_approval"][0]

    class AgentContext:
        agent_name = "infrastructure_provisioner"

    # Agent attempts to approve a ticket autonomously
    result = await plugin.before_tool_callback(
        tool=decide_tool,
        tool_args={"approval_id": "ticket-123", "approve": True},
        tool_context=AgentContext(),
    )

    # Must be hard-denied by Warden policy
    assert result is not None
    assert result.get("warden") == "denied_by_policy"
    assert "decide_approval" in result.get("reason", "")

    # Check ledger committed the denial
    records = await runtime.ledger.read()
    assert len(records) == 1
    assert records[0].tool == "decide_approval"
    assert records[0].outcome == "refused"


@pytest.mark.asyncio
async def test_secret_vault_exfiltration_denied():
    runtime = initialize_fleet_runtime(run_id="test-vault-protection")
    plugin = runtime.plugin

    sec_tools = runtime.toolsets["security_test"]
    get_key_tool = [t for t in sec_tools if t.name == "get_research_key"][0]

    class AgentContext:
        agent_name = "infrastructure_provisioner"

    # Agent attempts to exfiltrate a secret API key into context
    result = await plugin.before_tool_callback(
        tool=get_key_tool,
        tool_args={"name": "gcp_service_account", "purpose": "training"},
        tool_context=AgentContext(),
    )

    # Must be hard-denied by Warden policy
    assert result is not None
    assert result.get("warden") == "denied_by_policy"
    assert "get_research_key" in result.get("reason", "")


@pytest.mark.asyncio
async def test_storage_provisioning_approval_gated():
    runtime = initialize_fleet_runtime(run_id="test-storage-gated")
    plugin = runtime.plugin

    prov_tools = runtime.toolsets["provisioner"]
    fs_tool = [t for t in prov_tools if t.name == "create_filesystem"][0]

    class AgentContext:
        agent_name = "infrastructure_provisioner"

    # Creating filesystem incurs spend, so it requires human approval
    result = await plugin.before_tool_callback(
        tool=fs_tool,
        tool_args={"name": "scratch-nfs", "region": "us-west1"},
        tool_context=AgentContext(),
    )

    assert result is not None
    assert result.get("warden") == "awaiting_human_approval"
    assert "approval_id" in result
