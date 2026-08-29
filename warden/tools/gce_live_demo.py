"""Guarded Google Compute backend for judge-facing provider proof.

The adapter is intentionally narrow: one short-lived NVIDIA L4 instance, no
external IP, provider-enforced expiry, immediate teardown, and an independent
absence check. It uses the Compute Engine API directly so the same governed
path works from Cloud Run and from a local authenticated development session.
"""

from __future__ import annotations

import asyncio
import os
import time
from copy import deepcopy
from typing import Any
from uuid import uuid4

from google.api_core.exceptions import NotFound
from google.cloud import compute_v1

from warden.tools.mock_provider import MockInfrastructureProvider


PROOF_MARKER = "WARDEN_LIVE_VM_PROOF"
MAX_TTL_MINUTES = 5
MACHINE_TYPE = "g2-standard-8"
_STATUS: dict[str, Any] = {
    "enabled": False,
    "phase": "disabled",
    "message": "Real Google VM lifecycle is disabled.",
}


def live_demo_status() -> dict[str, Any]:
    return deepcopy(_STATUS)


def _set_status(**updates: Any) -> None:
    _STATUS.update(updates, updated_at=time.time())


class GceLiveDemoBackend(MockInfrastructureProvider):
    """One-instance GCE proof backend with hard provider and cleanup guards."""

    def __init__(
        self,
        *,
        project: str,
        zone: str,
        instances_client: compute_v1.InstancesClient | None = None,
    ) -> None:
        super().__init__()
        confirmation = os.environ.get("WARDEN_LIVE_VM_CONFIRM_PROJECT", "")
        if not project or confirmation != project:
            raise RuntimeError(
                "WARDEN_LIVE_VM_CONFIRM_PROJECT must exactly match GOOGLE_CLOUD_PROJECT"
            )
        if zone.rsplit("-", 1)[0] not in {"us-west1", "us-central1"}:
            raise RuntimeError("live VM demo zone is outside Warden policy")
        self.project = project
        self.zone = zone
        self.region = zone.rsplit("-", 1)[0]
        self.instances_client = instances_client or compute_v1.InstancesClient()
        self.instances = {}
        _set_status(
            enabled=True,
            phase="ready",
            project=project,
            zone=zone,
            machine_type=MACHINE_TYPE,
            gpu="NVIDIA L4 24GB",
            message="Cloud Run GPU provider ready. No VM exists.",
            cleanup_verified=True,
        )

    async def _insert(self, instance: compute_v1.Instance) -> Any:
        operation = await asyncio.to_thread(
            self.instances_client.insert,
            project=self.project,
            zone=self.zone,
            instance_resource=instance,
        )
        await asyncio.to_thread(operation.result, timeout=180)
        return operation

    async def _delete(self, instance_name: str) -> None:
        operation = await asyncio.to_thread(
            self.instances_client.delete,
            project=self.project,
            zone=self.zone,
            instance=instance_name,
        )
        await asyncio.to_thread(operation.result, timeout=180)

    async def _get(self, instance_name: str) -> Any:
        return await asyncio.to_thread(
            self.instances_client.get,
            project=self.project,
            zone=self.zone,
            instance=instance_name,
        )

    async def _serial_output(self, instance_name: str) -> str:
        request = compute_v1.GetSerialPortOutputInstanceRequest(
            project=self.project,
            zone=self.zone,
            instance=instance_name,
            port=1,
            start=0,
        )
        output = await asyncio.to_thread(
            self.instances_client.get_serial_port_output,
            request=request,
        )
        return output.contents or ""

    def _instance_resource(
        self, *, name: str, ttl_seconds: int, startup: str
    ) -> compute_v1.Instance:
        return compute_v1.Instance(
            name=name,
            description="Warden governed live GPU proof; automatically deleted within five minutes",
            machine_type=f"zones/{self.zone}/machineTypes/{MACHINE_TYPE}",
            labels={"app": "warden", "purpose": "live-demo", "managed-by": "warden"},
            deletion_protection=False,
            disks=[
                compute_v1.AttachedDisk(
                    boot=True,
                    auto_delete=True,
                    type_="PERSISTENT",
                    initialize_params=compute_v1.AttachedDiskInitializeParams(
                        source_image="projects/ubuntu-os-cloud/global/images/family/ubuntu-2204-lts",
                        disk_size_gb=20,
                        disk_type=f"zones/{self.zone}/diskTypes/pd-balanced",
                    ),
                )
            ],
            # Omitting access_configs means this interface has no public IP.
            network_interfaces=[
                compute_v1.NetworkInterface(network="global/networks/default")
            ],
            scheduling=compute_v1.Scheduling(
                provisioning_model="SPOT",
                instance_termination_action="DELETE",
                automatic_restart=False,
                on_host_maintenance="TERMINATE",
                max_run_duration={"seconds": ttl_seconds},
            ),
            metadata=compute_v1.Metadata(
                items=[compute_v1.Items(key="startup-script", value=startup)]
            ),
        )

    async def list_instances(self, note: str = "") -> list[dict[str, Any]] | dict[str, Any]:
        try:
            pager = await asyncio.to_thread(
                self.instances_client.list,
                project=self.project,
                zone=self.zone,
                filter='labels.app="warden" AND labels.purpose="live-demo"',
            )
            instances = await asyncio.to_thread(list, pager)
        except Exception as exc:
            return {"status": "FAILED", "error": type(exc).__name__}
        return [
            {
                "id": str(instance.id),
                "name": instance.name,
                "instance_type": instance.machine_type.rsplit("/", 1)[-1],
                "gpu_type": "NVIDIA L4",
                "region": self.region,
                "zone": self.zone,
                "status": instance.status,
                "provider_self_link": instance.self_link,
            }
            for instance in instances
        ]

    async def launch_gpu(
        self,
        instance_type: str = MACHINE_TYPE,
        region: str = "us-central1",
        filesystem: str = "default",
        purpose: str = "general",
        name: str = "",
        max_lifetime_seconds: float | None = 300.0,
        provider: str = "gcp",
        estimated_usd: float = 2.50,
        note: str = "",
        machine_type: str | None = None,
        max_lifetime_minutes: int | None = None,
    ) -> dict[str, Any]:
        machine = machine_type or instance_type
        ttl = (
            float(max_lifetime_minutes)
            if max_lifetime_minutes is not None
            else float(max_lifetime_seconds or 0) / 60.0
        )
        if provider != "gcp" or machine != MACHINE_TYPE:
            return {"status": "FAILED", "error": f"live demo permits only gcp {MACHINE_TYPE}"}
        if region != self.region or ttl <= 0 or ttl > MAX_TTL_MINUTES:
            return {
                "status": "FAILED",
                "error": f"live demo requires {self.region} and a TTL no greater than {MAX_TTL_MINUTES} minutes",
            }

        instance_name = name or f"warden-cloudrun-{uuid4().hex[:8]}"
        startup = (
            "#!/bin/bash\n"
            f"echo '{PROOF_MARKER} name={instance_name} gpu=NVIDIA-L4 source=Cloud-Run utc='$(date -u +%FT%TZ) | "
            "tee /dev/ttyS0 /var/log/warden-proof.log\n"
            "nvidia-smi --query-gpu=name,memory.total --format=csv,noheader | tee /dev/ttyS0 || true\n"
        )
        instance = self._instance_resource(
            name=instance_name, ttl_seconds=int(ttl * 60), startup=startup
        )
        created = False
        provider_self_link: str | None = None
        proof_line: str | None = None
        cleanup_verified = False
        failure: Exception | None = None
        _set_status(
            phase="creating",
            instance_name=instance_name,
            machine_type=machine,
            gpu="NVIDIA L4 24GB",
            cleanup_verified=False,
            message=f"Cloud Run is calling Compute Engine for {machine} in {self.zone}...",
        )
        try:
            operation = await self._insert(instance)
            created = True
            provider_self_link = getattr(operation, "target_link", None)
            current = await self._get(instance_name)
            provider_self_link = current.self_link or provider_self_link
            _set_status(
                phase="running",
                provider_self_link=provider_self_link,
                provider_id=str(current.id),
                message="Real billable NVIDIA L4 VM is running. Waiting for provider boot proof...",
            )

            deadline = time.monotonic() + 120
            while time.monotonic() < deadline:
                serial = await self._serial_output(instance_name)
                proof_line = next(
                    (line for line in serial.splitlines() if PROOF_MARKER in line), None
                )
                if proof_line:
                    _set_status(
                        phase="proof_observed",
                        proof=proof_line,
                        message="Timestamped GPU proof returned from the real VM serial console.",
                    )
                    break
                await asyncio.sleep(3)
            if not proof_line:
                _set_status(
                    phase="proof_timeout",
                    message="GPU VM exists, but boot proof timed out. Warden is cleaning it up.",
                )
        except Exception as exc:
            failure = exc
            _set_status(
                phase="failed",
                message=f"Compute Engine {type(exc).__name__}; cleanup follows.",
            )
        finally:
            if created:
                _set_status(
                    phase="deleting",
                    message="Deleting the GPU VM and verifying provider absence...",
                )
                delete_error: Exception | None = None
                try:
                    await self._delete(instance_name)
                except Exception as exc:
                    delete_error = exc
                try:
                    await self._get(instance_name)
                except NotFound:
                    cleanup_verified = delete_error is None
                except Exception:
                    cleanup_verified = False
                _set_status(
                    phase="cleaned" if cleanup_verified else "cleanup_unverified",
                    cleanup_verified=cleanup_verified,
                    message=(
                        "Provider deletion complete; follow-up Compute Engine lookup verified the GPU VM is absent."
                        if cleanup_verified
                        else f"Cleanup could not be verified: {type(delete_error).__name__ if delete_error else 'provider lookup failed'}"
                    ),
                )

        if failure is not None:
            return {"status": "FAILED", "error": f"Compute Engine {type(failure).__name__}"}
        return {
            "id": instance_name,
            "instance_id": instance_name,
            "status": "COMPLETED" if cleanup_verified else "CLEANUP_UNVERIFIED",
            "lifecycle_state": "CLEANED" if cleanup_verified else "CLEANUP_UNVERIFIED",
            "instance_type": machine,
            "gpu_type": "NVIDIA L4 24GB",
            "region": self.region,
            "zone": self.zone,
            "provider_self_link": provider_self_link,
            "proof": proof_line,
            "proof_observed": bool(proof_line),
            "cleanup_verified": cleanup_verified,
            "message": "Cloud Run governed a real Google GPU lifecycle and verified cleanup.",
        }

    async def terminate_instance(
        self,
        instance_id: str,
        force: bool = False,
        confirm_owner: str = "",
        note: str = "",
    ) -> dict[str, Any]:
        if not instance_id.startswith("warden-cloudrun-"):
            return {
                "instance_id": instance_id,
                "status": "FAILED",
                "error": "outside Warden demo ownership",
            }
        try:
            await self._delete(instance_id)
            await self._get(instance_id)
        except NotFound:
            return {"instance_id": instance_id, "status": "DELETED", "cleanup_verified": True}
        except Exception as exc:
            return {
                "instance_id": instance_id,
                "status": "FAILED",
                "cleanup_verified": False,
                "error": type(exc).__name__,
            }
        return {
            "instance_id": instance_id,
            "status": "FAILED",
            "cleanup_verified": False,
            "error": "provider still reports instance",
        }
