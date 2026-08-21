"""Deterministic mock infrastructure provider for testing and offline execution."""

from __future__ import annotations

import time
import uuid
from typing import Any
from warden.tools.definitions import InfrastructureBackend


class MockInfrastructureProvider(InfrastructureBackend):
    """Simulates GCP compute, storage, jobs, and spend tracking."""

    def __init__(self) -> None:
        self.instances: dict[str, dict[str, Any]] = {
            "inst-g2-001": {
                "id": "inst-g2-001",
                "name": "eval-worker-01",
                "instance_type": "g2-standard-8",
                "gpu_type": "NVIDIA L4",
                "region": "us-west1",
                "status": "RUNNING",
                "created_at": time.time() - 1800,
                "hourly_usd": 0.85,
                "purpose": "evaluation",
            }
        }
        self.clusters: dict[str, dict[str, Any]] = {}
        self.filesystems: dict[str, dict[str, Any]] = {
            "default": {"name": "default", "region": "us-west1", "status": "AVAILABLE"}
        }
        self.jobs: dict[str, dict[str, Any]] = {}
        self.keys: dict[str, str] = {}
        self.work_log: list[dict[str, Any]] = [
            {
                "task_id": "job-pre-01",
                "template": "lora-train",
                "status": "COMPLETED",
                "cost_usd": 1.25,
                "duration_s": 420,
            }
        ]

    async def get_skill(self, note: str = "") -> str:
        return "# Warden Playbook\nGoverned operations on Google Cloud compute fleets."

    async def get_work_log(self, limit: int = 20, note: str = "") -> list[dict[str, Any]]:
        return self.work_log[:limit]

    async def list_instances(self, note: str = "") -> list[dict[str, Any]]:
        return list(self.instances.values())

    async def list_launch_options(self, provider: str = "gcp", note: str = "") -> list[dict[str, Any]]:
        return [
            {
                "instance_type": "g2-standard-8",
                "gpu": "1x NVIDIA L4 (24GB)",
                "region": "us-west1",
                "hourly_usd": 0.85,
                "available": True,
            },
            {
                "instance_type": "g2-standard-12",
                "gpu": "1x NVIDIA L4 (24GB)",
                "region": "us-central1",
                "hourly_usd": 1.15,
                "available": True,
            },
            {
                "instance_type": "a2-highgpu-1g",
                "gpu": "1x NVIDIA A100 (40GB)",
                "region": "us-central1",
                "hourly_usd": 3.67,
                "available": True,
            },
        ]

    async def get_launch_status(self, launch_id: str, note: str = "") -> dict[str, Any]:
        return {"id": launch_id, "phase": "active", "settled": True, "boot_elapsed_seconds": 32.0}

    async def wait_for_launch(self, launch_id: str, timeout: float = 45.0, note: str = "") -> dict[str, Any]:
        return {"id": launch_id, "phase": "active", "settled": True}

    async def get_spend(self, note: str = "") -> dict[str, Any]:
        return {
            "today": 4.50,
            "week": 28.20,
            "month": 112.50,
            "burn_rate_usd_hr": 0.85 * len(self.instances),
            "live_instances": len(self.instances),
        }

    async def get_spend_breakdown(self, by: str = "created_by", days: int = 30, note: str = "") -> dict[str, Any]:
        return {
            "by": by,
            "days": days,
            "breakdown": [
                {"group": "infrastructure_provisioner", "total_usd": 24.50, "count": 6},
                {"group": "batch_runner", "total_usd": 3.70, "count": 2},
            ],
        }

    async def list_templates(self, note: str = "") -> list[dict[str, Any]]:
        return [
            {"name": "axolotl-lora", "image": "ghcr.io/axolotl:latest", "description": "Axolotl LoRA fine-tuning"},
            {"name": "vllm-inference", "image": "vllm/vllm-openai:latest", "description": "vLLM high-throughput engine"},
        ]

    async def get_job_status(self, task_id: str, note: str = "") -> dict[str, Any]:
        job = self.jobs.get(task_id, {"status": "NOT_FOUND"})
        return job

    async def get_job_logs(self, task_id: str, tail: int = 100, note: str = "") -> dict[str, Any]:
        return {"task_id": task_id, "lines": [f"[INFO] Step {i}: Loss {1.0/(i+1):.4f}" for i in range(min(5, tail))]}

    async def list_filesystems(self, note: str = "") -> list[dict[str, Any]]:
        return list(self.filesystems.values())

    async def list_volumes(self, note: str = "") -> list[dict[str, Any]]:
        return [{"name": "data-disk-01", "zone": "us-west1-b", "size_gb": 500, "attached_to": "inst-g2-001"}]

    async def list_persistent_files(self, prefix: str = "", filesystem: str | None = None, note: str = "") -> dict[str, Any]:
        return {
            "filesystem": filesystem or "default",
            "entries": [
                {"name": "dataset.jsonl", "is_dir": False, "size_bytes": 1048576},
                {"name": "checkpoints/", "is_dir": True, "size_bytes": 0},
            ],
        }

    async def list_clusters(self, note: str = "") -> list[dict[str, Any]]:
        return list(self.clusters.values())

    async def get_cluster_details(self, cluster_id: str, note: str = "") -> dict[str, Any]:
        cluster = self.clusters.get(cluster_id, {"id": cluster_id, "status": "NOT_FOUND"})
        return cluster

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
        # Compatibility kwargs
        machine_type: str | None = None,
        max_lifetime_minutes: int | None = None,
    ) -> dict[str, Any]:
        itype = machine_type or instance_type
        inst_id = f"inst-{itype[:2]}-{uuid.uuid4().hex[:6]}"
        entry = {
            "id": inst_id,
            "name": name or f"node-{inst_id}",
            "instance_type": itype,
            "gpu_type": "NVIDIA L4",
            "region": region,
            "status": "RUNNING",
            "created_at": time.time(),
            "hourly_usd": 0.85,
            "purpose": purpose,
            "max_lifetime_seconds": max_lifetime_seconds,
        }
        self.instances[inst_id] = entry
        return {
            "id": inst_id,
            "status": "RUNNING",
            "instance_type": itype,
            "region": region,
            "message": f"Successfully launched {itype} in {region} (ID: {inst_id})",
        }

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
        # Compatibility kwargs
        cluster_name: str | None = None,
        machine_type: str | None = None,
        max_lifetime_minutes: int | None = None,
    ) -> dict[str, Any]:
        itype = machine_type or instance_type
        cname = cluster_name or name or f"cluster-{uuid.uuid4().hex[:6]}"
        cid = f"cl-{uuid.uuid4().hex[:6]}"
        cluster = {
            "id": cid,
            "name": cname,
            "node_count": node_count,
            "instance_type": itype,
            "region": region,
            "status": "ACTIVE",
            "head_node": f"inst-head-{cid}",
            "workers": [f"inst-worker-{cid}-{i}" for i in range(node_count - 1)],
        }
        self.clusters[cid] = cluster
        return cluster

    async def create_filesystem(
        self,
        name: str,
        region: str = "us-west1",
        note: str = "",
    ) -> dict[str, Any]:
        self.filesystems[name] = {"name": name, "region": region, "status": "AVAILABLE"}
        return {"name": name, "region": region, "status": "created"}

    async def run_command(
        self,
        instance_id: str,
        command: str,
        timeout: float = 45.0,
        note: str = "",
    ) -> dict[str, Any]:
        if "env" in command:
            return {
                "exit_code": 0,
                "stdout": "USER=root\nCLOUD_PROVIDER=gcp\nAPI_KEY=AIzaSyB98765432109876543210987654321098\nSTATUS=OK",
                "stderr": "",
            }
        return {"exit_code": 0, "stdout": f"Executed '{command}' on {instance_id}\n", "stderr": ""}

    async def run_job(
        self,
        template: str = "",
        parameters: dict[str, Any] | None = None,
        depends_on: list[str] | None = None,
        note: str = "",
        # Compatibility kwargs
        template_name: str | None = None,
        instance_id: str = "",
    ) -> dict[str, Any]:
        tpl = template or template_name or "batch-job"
        task_id = f"task-{uuid.uuid4().hex[:8]}"
        job = {
            "task_id": task_id,
            "template": tpl,
            "status": "RUNNING",
            "started_at": time.time(),
        }
        self.jobs[task_id] = job
        return job

    async def sync_outputs(
        self,
        instance_id: str,
        note: str = "",
    ) -> dict[str, Any]:
        return {"status": "synced", "instance_id": instance_id, "files_copied": 3}

    async def terminate_instance(
        self,
        instance_id: str,
        force: bool = False,
        confirm_owner: str = "",
        note: str = "",
    ) -> dict[str, Any]:
        if instance_id in self.instances:
            del self.instances[instance_id]
            return {"status": "terminated", "instance_id": instance_id}
        return {"status": "not_found", "instance_id": instance_id}

    async def terminate_cluster(
        self,
        cluster_id: str,
        force: bool = False,
        note: str = "",
    ) -> dict[str, Any]:
        if cluster_id in self.clusters:
            del self.clusters[cluster_id]
            return {"status": "terminated", "cluster_id": cluster_id}
        return {"status": "not_found", "cluster_id": cluster_id}

    async def delete_template(
        self,
        name: str = "",
        note: str = "",
        # Compatibility kwargs
        template_id: str | None = None,
    ) -> dict[str, Any]:
        tname = name or template_id or ""
        return {"status": "deleted", "template": tname}

    async def set_research_key(
        self,
        name: str = "",
        value: str = "",
        purpose: str = "",
        note: str = "",
        # Compatibility kwargs
        key_name: str | None = None,
        key_value: str | None = None,
    ) -> dict[str, Any]:
        kname = name or key_name or ""
        kval = value or key_value or ""
        self.keys[kname] = kval
        return {"name": kname, "status": "saved"}

    async def get_research_key(
        self,
        name: str,
        purpose: str,
        note: str = "",
    ) -> dict[str, Any]:
        val = self.keys.get(name, "secret-mock-value")
        return {"name": name, "value": val}

    async def deregister_endpoint(
        self,
        instance_id: str = "",
        port: int = 8000,
        note: str = "",
        # Compatibility kwargs
        endpoint_url: str = "",
    ) -> dict[str, Any]:
        return {"status": "deregistered", "instance_id": instance_id, "port": port}

    async def decide_approval(
        self,
        approval_id: str,
        approve: bool,
        note: str = "",
    ) -> dict[str, Any]:
        return {"approval_id": approval_id, "status": "granted" if approve else "denied"}
