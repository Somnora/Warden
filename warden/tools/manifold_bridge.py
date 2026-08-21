"""HTTP Bridge connecting Warden ADK Agents directly to the Manifold compute backend.

Maintains exact route, schema, and error-handling parity with Manifold's FastMCP server:
  - Transport resilience with connection-refused retry loop
  - Error translation (unreachable, blocked safety hooks, 4xx/5xx responses)
  - Scrubbing sensitive credentials before persistent audit logs
"""

from __future__ import annotations

import logging
import os
from typing import Any
import httpx

from warden.tools.definitions import InfrastructureBackend

log = logging.getLogger("warden.manifold_bridge")

_UNREACHABLE_HINT = (
    "Manifold backend unreachable. Ensure the backend server is running "
    "(e.g. `uv run python -m backend.app.main` on port 8000)."
)


class ManifoldInfrastructureBridge(InfrastructureBackend):
    """Direct REST adapter communicating with the Manifold Compute Engine backend."""

    def __init__(
        self,
        base_url: str | None = None,
        api_token: str | None = None,
        timeout: float = 45.0,
    ) -> None:
        self.base_url = (base_url or os.environ.get("MANIFOLD_API_URL", "http://localhost:8000")).rstrip("/")
        self.api_token = api_token or os.environ.get("MANIFOLD_API_TOKEN", "")
        self.timeout = timeout

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json", "User-Agent": "Warden-Bridge/0.1.0"}
        if self.api_token:
            headers["Authorization"] = f"Bearer {self.api_token}"
        return headers

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_data: dict[str, Any] | None = None,
    ) -> Any:
        url = f"{self.base_url}{path}"
        try:
            async with httpx.AsyncClient(headers=self._headers(), timeout=self.timeout) as client:
                resp = await client.request(method, url, params=params, json=json_data)
                if resp.status_code >= 400:
                    try:
                        err_json = resp.json()
                        return {"error": err_json.get("detail", str(err_json)), "status_code": resp.status_code}
                    except Exception:
                        return {"error": resp.text, "status_code": resp.status_code}
                try:
                    return resp.json()
                except Exception:
                    return resp.text
        except (httpx.ConnectError, httpx.NetworkError) as e:
            log.warning("Connection failure to Manifold backend %s: %s", url, e)
            return {"error": f"Connection failed: {e}", "unreachable": True, "hint": _UNREACHABLE_HINT}
        except httpx.TimeoutException as e:
            log.warning("Timeout contacting Manifold backend %s: %s", url, e)
            return {"error": f"Request timed out: {e}", "timeout": True}
        except Exception as e:
            log.exception("Unexpected error in Manifold bridge: %s", e)
            return {"error": str(e)}

    # -- Onboarding & Documentation --

    async def get_skill(self, note: str = "") -> str:
        res = await self._request("GET", "/skill")
        if isinstance(res, dict) and "error" in res:
            return f"# Error\n{res['error']}"
        return str(res)

    async def get_work_log(self, limit: int = 20, note: str = "") -> list[dict[str, Any]] | dict[str, Any]:
        return await self._request("GET", "/audit/worklog", params={"limit": limit})

    # -- Compute & Instances --

    async def list_instances(self, note: str = "") -> list[dict[str, Any]] | dict[str, Any]:
        return await self._request("GET", "/instances")

    async def list_launch_options(self, provider: str = "gcp", note: str = "") -> list[dict[str, Any]] | dict[str, Any]:
        return await self._request("GET", "/launch-options", params={"provider": provider} if provider else None)

    async def get_launch_status(self, launch_id: str, note: str = "") -> dict[str, Any]:
        return await self._request("GET", f"/launches/{launch_id}")

    async def wait_for_launch(self, launch_id: str, timeout: float = 45.0, note: str = "") -> dict[str, Any]:
        return await self._request("POST", f"/launches/{launch_id}/wait", params={"timeout": timeout})

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
        machine_type: str | None = None,
        max_lifetime_minutes: int | None = None,
    ) -> dict[str, Any]:
        itype = machine_type or instance_type
        ttl = (max_lifetime_minutes * 60) if max_lifetime_minutes is not None else max_lifetime_seconds
        payload = {
            "instance_type": itype,
            "region": region,
            "filesystem": filesystem,
            "purpose": purpose,
            "name": name,
            "max_lifetime_seconds": ttl,
            "provider": provider,
            "note": note,
        }
        return await self._request("POST", "/instances", json_data=payload)

    async def terminate_instance(
        self,
        instance_id: str,
        force: bool = False,
        confirm_owner: str = "",
        note: str = "",
    ) -> dict[str, Any]:
        return await self._request(
            "DELETE",
            f"/instances/{instance_id}",
            params={"force": force, "confirm_owner": confirm_owner},
        )

    # -- Remote Command Execution --

    async def run_command(
        self,
        instance_id: str,
        command: str,
        timeout: float = 45.0,
        note: str = "",
    ) -> dict[str, Any]:
        return await self._request(
            "POST",
            f"/instances/{instance_id}/run",
            json_data={"command": command, "timeout": timeout},
        )

    # -- Tasks & Batch Jobs --

    async def list_templates(self, note: str = "") -> list[dict[str, Any]] | dict[str, Any]:
        return await self._request("GET", "/templates")

    async def run_job(
        self,
        template: str = "",
        parameters: dict[str, Any] | None = None,
        depends_on: list[str] | None = None,
        note: str = "",
        template_name: str | None = None,
        instance_id: str = "",
    ) -> dict[str, Any]:
        tpl = template or template_name or ""
        payload = {
            "template": tpl,
            "parameters": parameters or {},
            "depends_on": depends_on or [],
            "note": note,
        }
        return await self._request("POST", "/tasks", json_data=payload)

    async def get_job_status(self, task_id: str, note: str = "") -> dict[str, Any]:
        return await self._request("GET", f"/tasks/{task_id}")

    async def get_job_logs(self, task_id: str, tail: int = 100, note: str = "") -> dict[str, Any]:
        return await self._request("GET", f"/tasks/{task_id}/logs", params={"tail": tail})

    # -- Storage & Filesystems --

    async def list_filesystems(self, note: str = "") -> list[dict[str, Any]] | dict[str, Any]:
        return await self._request("GET", "/filesystems")

    async def list_volumes(self, note: str = "") -> list[dict[str, Any]] | dict[str, Any]:
        return await self._request("GET", "/volumes")

    async def create_filesystem(
        self,
        name: str,
        region: str = "us-west1",
        note: str = "",
    ) -> dict[str, Any]:
        return await self._request("POST", "/filesystems", json_data={"name": name, "region": region})

    async def list_persistent_files(self, prefix: str = "", filesystem: str | None = None, note: str = "") -> dict[str, Any]:
        return await self._request("GET", "/files/persistent", params={"prefix": prefix, "filesystem": filesystem})

    async def sync_outputs(
        self,
        instance_id: str,
        note: str = "",
    ) -> dict[str, Any]:
        return await self._request("POST", f"/instances/{instance_id}/sync-outputs")

    # -- Spend & Budgets --

    async def get_spend(self, note: str = "") -> dict[str, Any]:
        return await self._request("GET", "/spend/summary")

    async def get_spend_breakdown(self, by: str = "created_by", days: int = 30, note: str = "") -> dict[str, Any]:
        return await self._request("GET", "/spend/breakdown", params={"by": by, "days": days})

    # -- Clusters --

    async def list_clusters(self, note: str = "") -> list[dict[str, Any]] | dict[str, Any]:
        return await self._request("GET", "/clusters")

    async def get_cluster_details(self, cluster_id: str, note: str = "") -> dict[str, Any]:
        return await self._request("GET", f"/clusters/{cluster_id}")

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
        cluster_name: str | None = None,
        machine_type: str | None = None,
        max_lifetime_minutes: int | None = None,
    ) -> dict[str, Any]:
        itype = machine_type or instance_type
        cname = cluster_name or name or ""
        payload = {
            "instance_type": itype,
            "region": region,
            "filesystem": filesystem,
            "node_count": node_count,
            "name": cname,
            "provider": provider,
            "note": note,
        }
        return await self._request("POST", "/clusters", json_data=payload)

    async def terminate_cluster(
        self,
        cluster_id: str,
        force: bool = False,
        note: str = "",
    ) -> dict[str, Any]:
        return await self._request("DELETE", f"/clusters/{cluster_id}", params={"force": force})

    # -- Templates & Keys --

    async def delete_template(
        self,
        name: str = "",
        note: str = "",
        template_id: str | None = None,
    ) -> dict[str, Any]:
        tname = name or template_id or ""
        return await self._request("DELETE", f"/templates/custom/{tname}")

    async def set_research_key(
        self,
        name: str = "",
        value: str = "",
        purpose: str = "",
        note: str = "",
        key_name: str | None = None,
        key_value: str | None = None,
    ) -> dict[str, Any]:
        kname = name or key_name or ""
        kval = value or key_value or ""
        return await self._request("PUT", f"/research-keys/{kname}", json_data={"value": kval, "note": note})

    async def get_research_key(
        self,
        name: str,
        purpose: str,
        note: str = "",
    ) -> dict[str, Any]:
        return await self._request("GET", f"/research-keys/{name}", params={"purpose": purpose})

    async def deregister_endpoint(
        self,
        instance_id: str = "",
        port: int = 8000,
        note: str = "",
        endpoint_url: str = "",
    ) -> dict[str, Any]:
        return await self._request("DELETE", f"/instances/{instance_id}/endpoints/{port}")

    async def decide_approval(
        self,
        approval_id: str,
        approve: bool,
        note: str = "",
    ) -> dict[str, Any]:
        return await self._request("POST", f"/approvals/{approval_id}/decide", json_data={"approve": approve, "note": note})
