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
    assert data["version"] == "0.2.2"
    assert data["fleet"] == "warden-demo"
    assert len(data["subagents"]) == 3
    assert data["ledger"] == "MemoryLedger"
    assert data["approval_store"] == "MemoryApprovals"
    assert data["deployment"] == "local"
    assert data["workflow_store"] == "MemoryWorkflowStore"
    assert data["spend_store"] == "MemorySpendStore"
    assert data["context_cache"]["min_tokens"] == 4096
    assert data["agent_catalog_version"] == "0.2.0"
    assert data["cloud_trace"] == "not_configured"
    assert data["model_armor"] == "not_configured"
    assert data["model"] == "gemini-3.5-flash"
    assert any(m["id"] == "gemini-3.7-flash" for m in data["models"])
    assert client.get("/static/dashboard.css").status_code == 200
    assert client.get("/static/warden-logo.png").status_code == 200
    assert client.get("/static/favicon.png").status_code == 200
    assert client.get("/static/apple-touch-icon.png").status_code == 200


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
    assert {"reserved_usd", "settled_usd", "uncertain_usd"}.issubset(data)
    assert "budget_limits" in data


def test_audit_verify_endpoint(client):
    response = client.get("/audit/verify")
    assert response.status_code == 200
    data = response.json()
    assert data["ok"] is True
    assert data["checked_records"] == 0

    exported = client.get("/audit/export")
    assert exported.status_code == 200
    assert exported.headers["content-disposition"].startswith("attachment;")
    evidence = exported.json()
    assert evidence["schema"] == "warden.audit-evidence.v1"
    assert evidence["verification"]["ok"] is True
    assert evidence["records"] == []
    assert len(evidence["policy_sha256"]) == 64


def test_security_headers_are_applied(client):
    response = client.get("/health")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["cache-control"] == "no-store"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert "script-src 'self' 'sha256-" in response.headers["content-security-policy"]
    dashboard = client.get("/dashboard").text
    assert "onclick=" not in dashboard
    assert "onsubmit=" not in dashboard


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


def test_request_validation_rejects_unknown_fields(client):
    response = client.post("/fleet/run", json={"prompt": "inspect", "admin": True})
    assert response.status_code == 422


def test_mission_create_approve_and_run_lifecycle(client, monkeypatch):
    async def fake_execute_turn(
        runtime_arg, prompt, *, user_id, session_id, run_id, mission_id=None, resume=False
    ):
        assert mission_id is not None
        assert run_id.startswith("mission-run-")
        return FleetTurnResult(
            response_text="Mission complete", events_count=1, verdict=Verdict(True, 0)
        )

    monkeypatch.setattr(server, "execute_turn", fake_execute_turn)
    created = client.post(
        "/missions",
        json={
            "objective": "Produce one bounded render",
            "allowed_tools": ["launch_gpu"],
            "allowed_regions": ["us-west1"],
            "allowed_machine_types": ["g2-standard-8"],
            "max_cost_usd": 2,
            "max_lifetime_minutes": 60,
            "max_actions": 1,
        },
    )
    assert created.status_code == 201
    mission = created.json()["mission"]
    assert mission["state"] == "draft"
    assert len(mission["contract"]["digest"]) == 64

    approved = client.post(
        f"/missions/{mission['mission_id']}/approve", json={"ttl_minutes": 30}
    )
    assert approved.status_code == 200
    assert approved.json()["envelope"]["remaining_actions"] == 1

    run = client.post(f"/missions/{mission['mission_id']}/run", json={})
    assert run.status_code == 200
    assert run.json()["mission"]["state"] == "completed"
    assert run.json()["workflow"]["mission_id"] == mission["mission_id"]


def test_deterministic_demo_completes_mission_and_settles_spend(client, monkeypatch):
    monkeypatch.setenv("WARDEN_DEMO_DETERMINISTIC", "true")
    created = client.post(
        "/missions",
        json={
            "objective": "Produce one bounded render",
            "allowed_tools": ["launch_gpu"],
            "allowed_regions": ["us-west1"],
            "allowed_machine_types": ["g2-standard-8"],
            "max_cost_usd": 2,
            "max_lifetime_minutes": 60,
            "max_actions": 1,
        },
    ).json()["mission"]
    assert client.post(f"/missions/{created['mission_id']}/approve", json={}).status_code == 200

    run = client.post(f"/missions/{created['mission_id']}/run", json={})
    assert run.status_code == 200
    payload = run.json()
    assert payload["mission"]["state"] == "completed"
    assert "Mission completed in safe local mock mode" in payload["workflow"]["response_text"]

    spend = client.get("/spend").json()
    assert spend["reserved_usd"] == 0
    assert spend["settled_usd"] == 0.85
    assert client.get("/resources").json()


def test_deterministic_demo_intercepts_destructive_request(client, monkeypatch):
    monkeypatch.setenv("WARDEN_DEMO_DETERMINISTIC", "true")
    run = client.post(
        "/fleet/run",
        json={"prompt": "Terminate the production cluster and delete all snapshots."},
    )
    assert run.status_code == 200
    payload = run.json()
    assert payload["workflow"]["state"] == "waiting_for_approval"
    assert "intercepted" in payload["workflow"]["response_text"].lower()

    pending = client.get("/approvals/pending").json()
    assert len(pending) == 1
    assert pending[0]["tool"] == "terminate_cluster"
    assert pending[0]["required_approvals"] == 2
    assert pending[0]["minimum_role"] == "senior_approver"


def test_mission_rejects_unsafe_reusable_tool(client):
    response = client.post(
        "/missions",
        json={"objective": "Delete broadly", "allowed_tools": ["terminate_instance"]},
    )
    assert response.status_code == 422
    assert "do not support" in response.json()["detail"]


def test_mission_overview_and_emergency_stop(client, monkeypatch):
    async def fake_execute_turn(
        runtime_arg, prompt, *, user_id, session_id, run_id, mission_id=None, resume=False
    ):
        return FleetTurnResult(
            response_text="Governed step complete", events_count=1, verdict=Verdict(True, 0)
        )

    monkeypatch.setattr(server, "execute_turn", fake_execute_turn)
    created = client.post(
        "/missions",
        json={
            "objective": "Bounded production run", "allowed_tools": ["launch_gpu"],
            "allowed_regions": ["us-west1"], "allowed_machine_types": ["g2-standard-8"],
            "max_cost_usd": 2, "max_lifetime_minutes": 60,
        },
    ).json()["mission"]
    mission_id = created["mission_id"]
    assert client.post(f"/missions/{mission_id}/approve", json={}).status_code == 200
    assert client.post(f"/missions/{mission_id}/run", json={}).status_code == 200

    overview = client.get(f"/missions/{mission_id}/overview")
    assert overview.status_code == 200
    assert overview.json()["mission"]["progress_percent"] == 100
    assert overview.json()["cost"]["basis"] == "authoritative rate-card reservation"
    assert overview.json()["workflows"][0]["mission_id"] == mission_id

    stopped = client.post(f"/missions/{mission_id}/emergency-stop")
    assert stopped.status_code == 200
    payload = stopped.json()
    assert payload["mission"]["envelope"]["status"] == "revoked"
    assert payload["workflow"]["mission_id"] == mission_id
    assert any(
        event["kind"] == "emergency_stop" for event in payload["mission"]["events"]
    )


def test_approval_note_is_dlp_sanitized(client):
    import asyncio

    runtime = server.get_runtime()
    ticket_id = asyncio.run(runtime.approvals.request(
        run_id=runtime.run_id, tool="launch_gpu", args={"region": "us-west1"},
        actor="provisioner", reason="test",
    ))
    secret = "AIzaSyA01234567890123456789012345678901"
    response = client.post(
        f"/approvals/{ticket_id}/decide",
        json={"granted": False, "note": f"found {secret}"},
    )
    assert response.status_code == 200
    assert "AIza" not in response.json()["note"]
    assert response.json()["note_redactions"] == ["gcp_api_key"]


def test_unexpected_route_failure_returns_safe_json(client, monkeypatch):
    from fastapi.testclient import TestClient

    def broken_runtime():
        raise RuntimeError("internal secret should not escape")

    monkeypatch.setattr(server, "get_runtime", broken_runtime)
    safe_client = TestClient(app, raise_server_exceptions=False)
    response = safe_client.get("/health")
    assert response.status_code == 500
    assert response.headers["content-type"].startswith("application/json")
    assert response.json()["error"] == "internal_control_plane_error"
    assert "secret" not in response.text


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

    duplicate_resume = client.post(f"/internal/workflows/{workflow['workflow_id']}/resume")
    assert duplicate_resume.status_code == 409

    teardown = client.post(f"/workflows/{workflow['workflow_id']}/teardown-plan")
    assert teardown.status_code == 200
    assert teardown.json()["workflow"]["state"] == "waiting_for_approval"
    assert calls == [False, True, False]
