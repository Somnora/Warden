"""Factory to create ADK FunctionTools and McpToolset instances wired to infrastructure."""

from __future__ import annotations

import os
from typing import Any
from google.adk.tools import FunctionTool, McpToolset, BaseTool
from mcp import StdioServerParameters

from warden.tools.definitions import InfrastructureBackend
from warden.tools.mock_provider import MockInfrastructureProvider
from warden.tools.manifold_bridge import ManifoldInfrastructureBridge


def create_toolset(
    backend: InfrastructureBackend | None = None,
    *,
    mode: str = "mock",
    manifold_url: str | None = None,
    api_token: str | None = None,
) -> dict[str, list[FunctionTool]]:
    """Generate categorized ADK FunctionTools backed by the chosen provider.

    Returns a dictionary of toolsets for different agent roles:
      - 'auditor': Read-only observation tools
      - 'provisioner': Compute, job, and storage provisioning tools
      - 'lifecycle': Teardown and cleanup tools
      - 'security_test': Ungoverned/prohibited actions to test policy denial
      - 'all': Complete fleet toolset
    """
    if backend is None:
        if mode == "live":
            backend = ManifoldInfrastructureBridge(base_url=manifold_url, api_token=api_token)
        else:
            backend = MockInfrastructureProvider()

    # -- Read-only observation functions --
    async def get_skill(note: str = "") -> str:
        """Get the onboarding playbook and rules."""
        return await backend.get_skill(note=note)

    async def get_work_log(limit: int = 20, note: str = "") -> Any:
        """Get recent settled jobs, runs, and costs from the fleet audit log."""
        return await backend.get_work_log(limit=limit, note=note)

    async def list_instances(note: str = "") -> Any:
        """List all active and recent GPU compute instances."""
        return await backend.list_instances(note=note)

    async def list_launch_options(provider: str = "gcp", note: str = "") -> Any:
        """List available GPU machine types, availability, and hourly rates."""
        return await backend.list_launch_options(provider=provider, note=note)

    async def get_launch_status(launch_id: str, note: str = "") -> dict[str, Any]:
        """Check status of an asynchronous GPU launch."""
        return await backend.get_launch_status(launch_id=launch_id, note=note)

    async def wait_for_launch(launch_id: str, timeout: float = 45.0, note: str = "") -> dict[str, Any]:
        """Wait for an asynchronous GPU launch to settle."""
        return await backend.wait_for_launch(launch_id=launch_id, timeout=timeout, note=note)

    async def get_spend(note: str = "") -> dict[str, Any]:
        """Get current spend summary and budget usage for the fleet."""
        return await backend.get_spend(note=note)

    async def get_spend_breakdown(by: str = "created_by", days: int = 30, note: str = "") -> dict[str, Any]:
        """Get detailed breakdown of infrastructure spend by service and region."""
        return await backend.get_spend_breakdown(by=by, days=days, note=note)

    async def list_templates(note: str = "") -> Any:
        """List available container job templates."""
        return await backend.list_templates(note=note)

    async def get_job_status(task_id: str, note: str = "") -> dict[str, Any]:
        """Get status and output artifacts of a batch task."""
        return await backend.get_job_status(task_id=task_id, note=note)

    async def get_job_logs(task_id: str, tail: int = 100, note: str = "") -> dict[str, Any]:
        """Get recent logs from a running or completed task."""
        return await backend.get_job_logs(task_id=task_id, tail=tail, note=note)

    async def list_filesystems(note: str = "") -> Any:
        """List persistent cloud NFS filesystems."""
        return await backend.list_filesystems(note=note)

    async def list_volumes(note: str = "") -> Any:
        """List persistent disk volumes."""
        return await backend.list_volumes(note=note)

    async def list_persistent_files(prefix: str = "", filesystem: str | None = None, note: str = "") -> dict[str, Any]:
        """List files in persistent storage mount."""
        return await backend.list_persistent_files(prefix=prefix, filesystem=filesystem, note=note)

    async def list_clusters(note: str = "") -> Any:
        """List multi-node compute clusters."""
        return await backend.list_clusters(note=note)

    async def get_cluster_details(cluster_id: str, note: str = "") -> dict[str, Any]:
        """Get status and node topology for a GPU compute cluster."""
        return await backend.get_cluster_details(cluster_id=cluster_id, note=note)

    # -- Provisioning & Execution functions --
    async def launch_gpu(
        instance_type: str = "g2-standard-8",
        region: str = "us-west1",
        filesystem: str = "default",
        purpose: str = "general",
        name: str = "",
        max_lifetime_seconds: float = 3600.0,
        provider: str = "gcp",
        estimated_usd: float = 2.50,
        note: str = "",
        machine_type: str | None = None,
        max_lifetime_minutes: int | None = None,
    ) -> dict[str, Any]:
        """Provision a single GPU instance. Requires region, instance_type, and max_lifetime_seconds."""
        canonical_type = machine_type or instance_type
        canonical_ttl = (
            max_lifetime_minutes * 60
            if max_lifetime_minutes is not None
            else max_lifetime_seconds
        )
        return await backend.launch_gpu(
            instance_type=canonical_type,
            region=region,
            filesystem=filesystem,
            purpose=purpose,
            name=name,
            max_lifetime_seconds=canonical_ttl,
            provider=provider,
            estimated_usd=estimated_usd,
            note=note,
        )

    async def launch_cluster(
        instance_type: str = "g2-standard-8",
        region: str = "us-west1",
        filesystem: str = "default",
        node_count: int = 2,
        name: str = "",
        max_lifetime_seconds: float = 3600.0,
        provider: str = "gcp",
        estimated_usd: float = 5.00,
        note: str = "",
        cluster_name: str | None = None,
        machine_type: str | None = None,
        max_lifetime_minutes: int | None = None,
    ) -> dict[str, Any]:
        """Provision a multi-node GPU compute cluster. Gated by human approval."""
        canonical_type = machine_type or instance_type
        canonical_ttl = (
            max_lifetime_minutes * 60
            if max_lifetime_minutes is not None
            else max_lifetime_seconds
        )
        return await backend.launch_cluster(
            instance_type=canonical_type,
            region=region,
            filesystem=filesystem,
            node_count=node_count,
            name=cluster_name or name,
            max_lifetime_seconds=canonical_ttl,
            provider=provider,
            estimated_usd=estimated_usd,
            note=note,
        )

    async def create_filesystem(name: str, region: str = "us-west1", note: str = "") -> dict[str, Any]:
        """Create a regional persistent filesystem. Gated by human approval."""
        return await backend.create_filesystem(name=name, region=region, note=note)

    async def run_command(instance_id: str, command: str, timeout: float = 45.0, note: str = "") -> dict[str, Any]:
        """Run an execution command or script on a running compute instance."""
        return await backend.run_command(instance_id=instance_id, command=command, timeout=timeout, note=note)

    async def run_job(
        template: str = "",
        parameters: dict[str, Any] | None = None,
        depends_on: list[str] | None = None,
        note: str = "",
        template_name: str | None = None,
        instance_id: str = "",
    ) -> dict[str, Any]:
        """Execute a batch job template on available compute."""
        return await backend.run_job(
            template=template or template_name or "",
            parameters=parameters,
            depends_on=depends_on,
            note=note,
            template_name=template_name,
            instance_id=instance_id,
        )

    async def sync_outputs(instance_id: str, note: str = "") -> dict[str, Any]:
        """Backup ephemeral outputs to persistent filesystem."""
        return await backend.sync_outputs(instance_id=instance_id, note=note)

    # -- Lifecycle & Teardown functions --
    async def terminate_instance(
        instance_id: str,
        force: bool = False,
        confirm_owner: str = "",
        note: str = "",
    ) -> dict[str, Any]:
        """Terminate and destroy a compute instance. Gated by human approval."""
        return await backend.terminate_instance(instance_id=instance_id, force=force, confirm_owner=confirm_owner, note=note)

    async def terminate_cluster(cluster_id: str, force: bool = False, note: str = "") -> dict[str, Any]:
        """Tear down and destroy a GPU cluster. Gated by human approval."""
        return await backend.terminate_cluster(cluster_id=cluster_id, force=force, note=note)

    async def delete_template(name: str = "", note: str = "", template_id: str | None = None) -> dict[str, Any]:
        """Delete a custom template. Gated by human approval."""
        return await backend.delete_template(name=name or template_id or "", note=note, template_id=template_id)

    # -- Prohibited / Security Test functions --
    async def set_research_key(name: str = "", value: str = "", purpose: str = "", note: str = "", key_name: str | None = None, key_value: str | None = None) -> dict[str, Any]:
        """Set a shared credential key. (Prohibited by enterprise policy)."""
        return await backend.set_research_key(name=name or key_name or "", value=value or key_value or "", purpose=purpose, note=note)

    async def get_research_key(name: str, purpose: str = "", note: str = "") -> dict[str, Any]:
        """Retrieve a shared credential key. (Prohibited by enterprise policy)."""
        return await backend.get_research_key(name=name, purpose=purpose, note=note)

    async def deregister_endpoint(instance_id: str = "", port: int = 8000, note: str = "", endpoint_url: str = "") -> dict[str, Any]:
        """Deregister an inference endpoint. (Prohibited by enterprise policy)."""
        return await backend.deregister_endpoint(instance_id=instance_id, port=port, note=note, endpoint_url=endpoint_url)

    async def decide_approval(approval_id: str, approve: bool, note: str = "") -> dict[str, Any]:
        """Decide an approval ticket. (Prohibited for autonomous agents)."""
        return await backend.decide_approval(approval_id=approval_id, approve=approve, note=note)

    auditor_tools = [
        FunctionTool(get_skill),
        FunctionTool(get_work_log),
        FunctionTool(list_instances),
        FunctionTool(list_launch_options),
        FunctionTool(get_launch_status),
        FunctionTool(wait_for_launch),
        FunctionTool(get_spend),
        FunctionTool(get_spend_breakdown),
        FunctionTool(list_templates),
        FunctionTool(get_job_status),
        FunctionTool(get_job_logs),
        FunctionTool(list_filesystems),
        FunctionTool(list_volumes),
        FunctionTool(list_persistent_files),
        FunctionTool(list_clusters),
        FunctionTool(get_cluster_details),
    ]

    provisioner_tools = [
        FunctionTool(launch_gpu),
        FunctionTool(launch_cluster),
        FunctionTool(create_filesystem),
        FunctionTool(run_command),
        FunctionTool(run_job),
        FunctionTool(sync_outputs),
    ]

    lifecycle_tools = [
        FunctionTool(terminate_instance),
        FunctionTool(terminate_cluster),
        FunctionTool(delete_template),
    ]

    security_test_tools = [
        FunctionTool(set_research_key),
        FunctionTool(get_research_key),
        FunctionTool(deregister_endpoint),
        FunctionTool(decide_approval),
    ]

    all_tools = auditor_tools + provisioner_tools + lifecycle_tools + security_test_tools

    return {
        "auditor": auditor_tools,
        "provisioner": provisioner_tools,
        "lifecycle": lifecycle_tools,
        "security_test": security_test_tools,
        "all": all_tools,
    }


def create_mcp_toolset(
    *,
    command: str = "uv",
    args: list[str] | None = None,
    env: dict[str, str] | None = None,
    tool_filter: list[str] | None = None,
) -> McpToolset:
    """Create a native Google ADK McpToolset connecting over stdio to an MCP server."""
    server_args = args or ["run", "manifold-mcp"]
    server_env = env or dict(os.environ)

    params = StdioServerParameters(
        command=command,
        args=server_args,
        env=server_env,
    )

    return McpToolset(
        connection_params=params,
        tool_filter=tool_filter,
        tool_list_cache_ttl_seconds=300.0,
        require_confirmation=False,  # Out-of-band governed by WardenPlugin
    )
