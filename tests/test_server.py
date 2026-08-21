"""Tests for the Warden Operator Control Plane FastAPI Server."""

import pytest
from fastapi.testclient import TestClient
import warden.server as server
from warden.fleet import FleetTurnResult, initialize_fleet_runtime
from warden.ledger.chain import Verdict
from warden.server import app, set_runtime


@pytest.fixture
def client():
    runtime = initialize_fleet_runtime(run_id="test-server-run")
    set_runtime(runtime)
    return TestClient(app)


def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["fleet"] == "warden-demo"
    assert len(data["subagents"]) == 3
    assert data["ledger"] == "MemoryLedger"
    assert data["approval_store"] == "MemoryApprovals"
    assert data["deployment"] == "local"
    assert data["workflow_store"] == "MemoryWorkflowStore"
    assert data["context_cache"]["min_tokens"] == 4096
    assert data["agent_catalog_version"] == "0.2.0"
    assert data["cloud_trace"] == "not_configured"
    assert data["model_armor"] == "not_configured"
    assert client.get("/static/dashboard.css").status_code == 200


def test_policy_endpoint(client):
    response = client.get("/policy")
    assert response.status_code == 200
    data = response.json()
    assert data["version"] == 1
    assert "budget" in data
    assert "tools" in data


def test_spend_endpoint(client):
    response = client.get("/spend")
    assert response.status_code == 200
    data = response.json()
    assert "run_usd" in data
    assert "budget_limits" in data


def test_audit_verify_endpoint(client):
    response = client.get("/audit/verify")
    assert response.status_code == 200
    data = response.json()
    assert data["ok"] is True
    assert data["checked_records"] == 0


def test_approval_lifecycle_endpoints(client):
    # Retrieve pending approvals
    response = client.get("/approvals/pending")
    assert response.status_code == 200
    assert response.json() == []

    # Inject an approval into runtime
    from warden.server import get_runtime
    runtime = get_runtime()
    import asyncio
    ticket_id = asyncio.run(
        runtime.approvals.request(
            run_id=runtime.run_id,
            tool="launch_gpu",
            args={"region": "us-west1"},
            actor="infrastructure_provisioner",
            reason="spending tool requires approval",
        )
    )

    # Check pending list
    resp2 = client.get("/approvals/pending")
    assert resp2.status_code == 200
    items = resp2.json()
    assert len(items) == 1
    assert items[0]["approval_id"] == ticket_id

    # Decide approval
    resp3 = client.post(
        f"/approvals/{ticket_id}/decide",
        json={"granted": True, "note": "Budget pre-cleared"},
        headers={"X-Warden-Operator": "lead-sre@company.com"},
    )
    assert resp3.status_code == 200
    dec = resp3.json()
    assert dec["status"] == "granted"
    assert dec["approver"] == "lead-sre@company.com"


def test_decision_rejects_client_supplied_approver(client):
    response = client.post(
        "/approvals/does-not-matter/decide",
        json={"granted": True, "approver": "spoofed@company.com"},
    )
    assert response.status_code == 422

    # Verify no longer pending
    resp4 = client.get("/approvals/pending")
    assert resp4.json() == []


def test_live_mode_rejects_unverified_operator_and_task_calls(client, monkeypatch):
    monkeypatch.setenv("WARDEN_MODE", "live")
    monkeypatch.setenv("WARDEN_SERVICE_URL", "https://warden.example.run.app")
    monkeypatch.setenv("WARDEN_TASK_SERVICE_ACCOUNT", "warden-worker@example.iam.gserviceaccount.com")

    operator = client.post("/approvals/not-a-ticket/decide", json={"granted": True})
    assert operator.status_code == 401

    worker = client.post("/internal/workflows/not-a-workflow/resume")
    assert worker.status_code == 401


def test_approved_workflow_is_resumed_asynchronously(client, monkeypatch):
    """The API persists → parks → queues → resumes one governed workflow."""
    import asyncio

    runtime = server.get_runtime()
    calls: list[bool] = []

    async def fake_execute_turn(runtime_arg, prompt, *, user_id, session_id, run_id, resume=False):
        calls.append(resume)
        if not resume:
            ticket_id = await runtime_arg.approvals.request(
                run_id=run_id,
                tool="launch_gpu",
                args={"region": "us-west1"},
                actor="infrastructure_provisioner",
                reason="human approval required",
                preflight={"estimated_usd": 2.5, "max_lifetime_minutes": 60},
            )
            return FleetTurnResult(
                response_text="Awaiting sign-off", events_count=1,
                pending_approval_ids=[ticket_id], verdict=Verdict(True, 0),
            )
        return FleetTurnResult(response_text="GPU launched", events_count=1, verdict=Verdict(True, 0))

    async def dont_background_resume(workflow_id: str) -> None:
        return None

    monkeypatch.setattr(server, "execute_turn", fake_execute_turn)
    monkeypatch.setattr(server, "_enqueue_resume", dont_background_resume)

    initial = client.post("/fleet/run", json={"prompt": "Launch a GPU"})
    assert initial.status_code == 200
    workflow = initial.json()["workflow"]
    assert workflow["state"] == "waiting_for_approval"
    ticket_id = workflow["approval_ids"][0]
    pending = client.get("/approvals/pending").json()
    assert pending[0]["workflow_id"] == workflow["workflow_id"]

    decision = client.post(
        f"/approvals/{ticket_id}/decide",
        json={"granted": True},
        headers={"X-Warden-Operator": "sre@example.com"},
    )
    assert decision.status_code == 200
    assert decision.json()["resume_enqueued"] is True

    resumed = client.post(f"/internal/workflows/{workflow['workflow_id']}/resume")
    assert resumed.status_code == 200
    assert resumed.json()["workflow"]["state"] == "completed"
    assert resumed.json()["workflow"]["resume_count"] == 1
    assert calls == [False, True]

    teardown = client.post(f"/workflows/{workflow['workflow_id']}/teardown-plan")
    assert teardown.status_code == 200
    assert teardown.json()["workflow"]["state"] == "waiting_for_approval"
    assert calls == [False, True, False]
