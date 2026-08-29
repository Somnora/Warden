"""Guardrails and lifecycle behavior for the dashboard's real-GCE adapter."""

from types import SimpleNamespace

import pytest
from google.api_core.exceptions import NotFound

from warden.tools.gce_live_demo import GceLiveDemoBackend, PROOF_MARKER


def _confirm(monkeypatch: pytest.MonkeyPatch, project: str = "demo-project") -> None:
    monkeypatch.setenv("WARDEN_LIVE_VM_CONFIRM_PROJECT", project)


def test_backend_requires_exact_project_confirmation(monkeypatch):
    monkeypatch.setenv("WARDEN_LIVE_VM_CONFIRM_PROJECT", "other-project")
    with pytest.raises(RuntimeError, match="exactly match"):
        GceLiveDemoBackend(project="demo-project", zone="us-central1-a")


def test_backend_rejects_zone_outside_policy(monkeypatch):
    _confirm(monkeypatch)
    with pytest.raises(RuntimeError, match="outside Warden policy"):
        GceLiveDemoBackend(project="demo-project", zone="europe-west4-a")


@pytest.mark.asyncio
async def test_lifecycle_creates_reads_proof_deletes_and_verifies(monkeypatch):
    _confirm(monkeypatch)
    calls: list[tuple[str, dict]] = []

    class Operation:
        target_link = "https://compute/instance/demo"

        def result(self, timeout):
            calls.append(("wait", {"timeout": timeout}))

    class Client:
        deleted = False

        def insert(self, **kwargs):
            calls.append(("insert", kwargs))
            return Operation()

        def get(self, **kwargs):
            calls.append(("get", kwargs))
            if self.deleted:
                raise NotFound("absent")
            return SimpleNamespace(
                id=123,
                self_link="https://compute/instance/demo",
                status="RUNNING",
            )

        def get_serial_port_output(self, request):
            assert request.project == "demo-project"
            assert request.zone == "us-central1-a"
            assert request.port == 1
            assert request.start == 0
            calls.append(("serial", {"request": request}))
            return SimpleNamespace(
                contents=f"booting\n{PROOF_MARKER} name=demo utc=2026-08-28T00:00:00Z\n"
            )

        def delete(self, **kwargs):
            calls.append(("delete", kwargs))
            self.deleted = True
            return Operation()

    backend = GceLiveDemoBackend(
        project="demo-project", zone="us-central1-a", instances_client=Client()
    )
    result = await backend.launch_gpu(
        provider="gcp",
        region="us-central1",
        machine_type="g2-standard-8",
        max_lifetime_minutes=5,
    )

    assert result["status"] == "COMPLETED"
    assert result["lifecycle_state"] == "CLEANED"
    assert result["proof_observed"] is True
    assert result["cleanup_verified"] is True
    insert = next(kwargs for name, kwargs in calls if name == "insert")
    resource = insert["instance_resource"]
    assert resource.scheduling.provisioning_model == "SPOT"
    assert resource.scheduling.instance_termination_action == "DELETE"
    assert resource.scheduling.max_run_duration.seconds == 300
    assert list(resource.network_interfaces[0].access_configs) == []
    assert any(name == "delete" for name, _ in calls)
    assert sum(name == "get" for name, _ in calls) == 2


@pytest.mark.asyncio
async def test_lifecycle_rejects_expansive_request_before_gcloud(monkeypatch):
    _confirm(monkeypatch)

    class Client:
        def insert(self, **kwargs):
            raise AssertionError("Compute Engine must not be called for an out-of-envelope request")

    backend = GceLiveDemoBackend(
        project="demo-project", zone="us-central1-a", instances_client=Client()
    )
    result = await backend.launch_gpu(
        provider="gcp",
        region="us-central1",
        machine_type="g2-standard-8",
        max_lifetime_minutes=6,
    )
    assert result["status"] == "FAILED"
    assert "no greater than 5" in result["error"]
