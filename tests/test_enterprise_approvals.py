"""Enterprise role hierarchy and multi-party approval controls."""

import asyncio

import pytest
from fastapi.testclient import TestClient

import warden.server as server
from warden.fleet import initialize_fleet_runtime
from warden.policy.approvals import (
    ApprovalRequirement,
    ApprovalState,
    MemoryApprovals,
)
from warden.server import app, set_runtime


@pytest.fixture
def client():
    runtime = initialize_fleet_runtime(run_id="test-enterprise-approval-run")
    set_runtime(runtime)
    return TestClient(app)


@pytest.mark.asyncio
async def test_threshold_requires_distinct_senior_approvers_and_separation_of_duties():
    approvals = MemoryApprovals()
    args = {"cluster_id": "cluster-1"}
    ticket_id = await approvals.request(
        run_id="enterprise-run", tool="terminate_cluster", args=args,
        actor="lifecycle_manager", requester="requester@example.com", reason="high blast radius",
        requirement=ApprovalRequirement(required_approvals=2, minimum_role="senior_approver"),
    )

    with pytest.raises(ValueError, match="senior_approver"):
        await approvals.decide(
            ticket_id, granted=True, approver="junior@example.com", approver_role="approver"
        )
    with pytest.raises(ValueError, match="requester may not"):
        await approvals.decide(
            ticket_id, granted=True, approver="requester@example.com", approver_role="senior_approver"
        )

    first = await approvals.decide(
        ticket_id, granted=True, approver="alice@example.com", approver_role="senior_approver"
    )
    assert first.status is ApprovalState.PENDING
    assert len(first.votes) == 1
    # Duplicate delivery is idempotent and cannot satisfy the threshold twice.
    assert (await approvals.decide(
        ticket_id, granted=True, approver="alice@example.com", approver_role="senior_approver"
    )).status is ApprovalState.PENDING

    granted = await approvals.decide(
        ticket_id, granted=True, approver="bob@example.com", approver_role="administrator"
    )
    assert granted.status is ApprovalState.GRANTED
    assert len(granted.votes) == 2
    assert (await approvals.claim(
        run_id="enterprise-run", tool="terminate_cluster", args=args, actor="lifecycle_manager"
    )).status is ApprovalState.GRANTED
    assert (await approvals.claim(
        run_id="enterprise-run", tool="terminate_cluster", args=args, actor="lifecycle_manager"
    )).status is ApprovalState.CONSUMED


def test_identity_hierarchy_and_multi_party_api_progress(client):
    identity = client.get(
        "/identity/me", headers={"X-Warden-Operator": "alice@example.com", "X-Warden-Roles": "approver"}
    )
    assert identity.status_code == 200
    assert identity.json()["effective_role"] == "approver"

    viewer = client.post(
        "/fleet/run", json={"prompt": "inspect"}, headers={"X-Warden-Roles": "viewer"}
    )
    assert viewer.status_code == 403

    runtime = server.get_runtime()
    ticket_id = asyncio.run(runtime.approvals.request(
        run_id=runtime.run_id,
        tool="terminate_cluster",
        args={"cluster_id": "cluster-1"},
        actor="lifecycle_manager",
        requester="requester@example.com",
        reason="requires two reviewers",
        requirement=ApprovalRequirement(required_approvals=2, minimum_role="senior_approver"),
    ))
    pending = client.get("/approvals/pending", headers={"X-Warden-Roles": "viewer"})
    assert pending.status_code == 403

    first = client.post(
        f"/approvals/{ticket_id}/decide", json={"granted": True},
        headers={"X-Warden-Operator": "alice@example.com", "X-Warden-Roles": "senior_approver"},
    )
    assert first.status_code == 200
    assert first.json()["status"] == "pending"
    assert first.json()["approvals_remaining"] == 1
    assert first.json()["resume_enqueued"] is False

    second = client.post(
        f"/approvals/{ticket_id}/decide", json={"granted": True},
        headers={"X-Warden-Operator": "bob@example.com", "X-Warden-Roles": "administrator"},
    )
    assert second.status_code == 200
    assert second.json()["status"] == "granted"
    assert second.json()["approvals_remaining"] == 0


def test_mission_envelopes_cannot_bypass_multi_party_cluster_policy(client):
    response = client.post(
        "/missions",
        json={"objective": "Create a cluster", "allowed_tools": ["launch_cluster"]},
    )
    assert response.status_code == 422
    assert "multi-party" in response.json()["detail"]


def test_mock_demo_attack_uses_real_plugin_and_never_executes(client):
    response = client.post(
        "/demo/scenarios/destructive-approval",
        headers={"X-Warden-Operator": "demo-requester", "X-Warden-Roles": "operator"},
    )
    assert response.status_code == 201
    assert response.json()["synthetic"] is True
    assert response.json()["executed"] is False
    assert response.json()["intercept"]["warden"] == "awaiting_human_approval"

    pending = client.get("/approvals/pending").json()
    ticket = next(item for item in pending if item["approval_id"] in response.json()["approval_ids"])
    assert ticket["tool"] == "terminate_cluster"
    assert ticket["requested_by"] == "demo-requester"
    assert ticket["required_approvals"] == 2
    assert ticket["minimum_role"] == "senior_approver"
