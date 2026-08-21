"""Tool definitions and protocols for the Warden governed fleet.

Every tool exposed to Gemini or ADK agents is typed and documented here.
Protocol methods reflect the exact contract of Manifold's compute engine.
"""

from __future__ import annotations

from typing import Any, Protocol


class InfrastructureBackend(Protocol):
    """Protocol satisfied by both MockInfrastructureProvider and ManifoldInfrastructureBridge."""

    async def get_skill(self, note: str = "") -> str: ...
    async def get_work_log(self, limit: int = 20, note: str = "") -> list[dict[str, Any]] | dict[str, Any]: ...
    async def list_instances(self, note: str = "") -> list[dict[str, Any]] | dict[str, Any]: ...
    async def list_launch_options(self, provider: str = "gcp", note: str = "") -> list[dict[str, Any]] | dict[str, Any]: ...
    async def get_launch_status(self, launch_id: str, note: str = "") -> dict[str, Any]: ...
    async def wait_for_launch(self, launch_id: str, timeout: float = 45.0, note: str = "") -> dict[str, Any]: ...
    async def get_spend(self, note: str = "") -> dict[str, Any]: ...
    async def get_spend_breakdown(self, by: str = "created_by", days: int = 30, note: str = "") -> dict[str, Any]: ...
    async def list_templates(self, note: str = "") -> list[dict[str, Any]] | dict[str, Any]: ...
    async def get_job_status(self, task_id: str, note: str = "") -> dict[str, Any]: ...
    async def get_job_logs(self, task_id: str, tail: int = 100, note: str = "") -> dict[str, Any]: ...
    async def list_filesystems(self, note: str = "") -> list[dict[str, Any]] | dict[str, Any]: ...
    async def list_volumes(self, note: str = "") -> list[dict[str, Any]] | dict[str, Any]: ...
    async def list_persistent_files(self, prefix: str = "", filesystem: str | None = None, note: str = "") -> dict[str, Any]: ...
    async def list_clusters(self, note: str = "") -> list[dict[str, Any]] | dict[str, Any]: ...
    async def get_cluster_details(self, cluster_id: str, note: str = "") -> dict[str, Any]: ...

    async def launch_gpu(
        self,
        instance_type: str = "g2-standard-8",
        region: str = "us-west1",
        filesystem: str = "default",
        purpose: str = "general",
        name: str = "",
        max_lifetime_seconds: float | None = 3600.0,
        provider: str = "gcp",
        estimated_usd: float = 2.50,
        note: str = "",
    ) -> dict[str, Any]: ...

    async def launch_cluster(
        self,
        instance_type: str = "g2-standard-8",
        region: str = "us-west1",
        filesystem: str = "default",
        node_count: int = 2,
        name: str = "",
        max_lifetime_seconds: float | None = 3600.0,
        provider: str = "gcp",
        estimated_usd: float = 5.00,
        note: str = "",
    ) -> dict[str, Any]: ...

    async def create_filesystem(
        self,
        name: str,
        region: str = "us-west1",
        note: str = "",
    ) -> dict[str, Any]: ...

    async def run_command(
        self,
        instance_id: str,
        command: str,
        timeout: float = 45.0,
        note: str = "",
    ) -> dict[str, Any]: ...

    async def run_job(
        self,
        template: str,
        parameters: dict[str, Any] | None = None,
        depends_on: list[str] | None = None,
        note: str = "",
    ) -> dict[str, Any]: ...

    async def sync_outputs(
        self,
        instance_id: str,
        note: str = "",
    ) -> dict[str, Any]: ...

    async def terminate_instance(
        self,
        instance_id: str,
        force: bool = False,
        confirm_owner: str = "",
        note: str = "",
    ) -> dict[str, Any]: ...

    async def terminate_cluster(
        self,
        cluster_id: str,
        force: bool = False,
        note: str = "",
    ) -> dict[str, Any]: ...

    async def delete_template(
        self,
        name: str,
        note: str = "",
    ) -> dict[str, Any]: ...

    async def set_research_key(
        self,
        name: str,
        value: str,
        purpose: str = "",
        note: str = "",
    ) -> dict[str, Any]: ...

    async def get_research_key(
        self,
        name: str,
        purpose: str,
        note: str = "",
    ) -> dict[str, Any]: ...

    async def deregister_endpoint(
        self,
        instance_id: str,
        port: int,
        note: str = "",
    ) -> dict[str, Any]: ...

    async def decide_approval(
        self,
        approval_id: str,
        approve: bool,
        note: str = "",
    ) -> dict[str, Any]: ...
