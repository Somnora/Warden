"""Policy template, simulation, and evidence-bound replay behavior."""

import asyncio

import pytest
from fastapi.testclient import TestClient

from warden.fleet import initialize_fleet_runtime
from warden.ledger.chain import Record, digest_args
from warden.policy.engine import Disposition, SpendSnapshot
from warden.policy.preview import PreviewAction, simulate
from warden.policy.templates import get_template, list_templates, policy_from_template
from warden.server import app, set_runtime


LAUNCH = {
    "provider": "gcp",
    "region": "us-west1",
    "machine_type": "g2-standard-8",
    "max_lifetime_minutes": 60,
}


@pytest.fixture
def client():
    runtime = initialize_fleet_runtime(run_id="test-policy-preview-run")
    set_runtime(runtime)
    return TestClient(app)


def test_templates_are_versioned_and_creator_template_is_narrower():
    templates = {template.template_id: template for template in list_templates()}
    assert set(templates) == {"creator-safe", "studio-burst", "enterprise-production"}
    assert len(templates["creator-safe"].fingerprint) == 64

    creator = policy_from_template("creator-safe")
    assert creator.evaluate("launch_gpu", LAUNCH).disposition is Disposition.APPROVE
    denied = creator.evaluate("launch_gpu", {**LAUNCH, "machine_type": "g2-standard-12"})
    assert denied.disposition is Disposition.DENY
    assert "placement.allowed_machine_types" in denied.rules
    assert get_template("missing") is None


def test_simulation_projects_approved_launch_then_blocks_capacity_without_side_effects():
    policy = policy_from_template("creator-safe")
    results, final_spend = simulate(
        policy,
        [PreviewAction("launch_gpu", LAUNCH), PreviewAction("launch_gpu", LAUNCH)],
        initial_spend=SpendSnapshot(),
    )

    assert results[0].disposition == "approve"
    assert results[0].projected is True
    assert results[0].spend_after.live_instances == 1
    assert results[1].disposition == "deny"
    assert "budget.max_concurrent_instances" in results[1].rules
    assert final_spend.run_usd == pytest.approx(0.85)
    assert final_spend.live_instances == 1


def test_simulation_can_model_unapproved_actions_without_reserving_budget():
    policy = policy_from_template("creator-safe")
    results, final_spend = simulate(
        policy, [PreviewAction("launch_gpu", LAUNCH)], assume_approved=False
    )

    assert results[0].disposition == "approve"
    assert results[0].projected is False
    assert final_spend == SpendSnapshot()


def test_template_and_simulation_endpoints(client):
    templates = client.get("/policy/templates")
    assert templates.status_code == 200
    assert templates.json()["activation"] == "review_only"
    assert templates.json()["templates"][0]["fingerprint"]

    simulated = client.post(
        "/policy/simulate",
        json={"template_id": "creator-safe", "actions": [{"tool": "launch_gpu", "args": LAUNCH}]},
    )
    assert simulated.status_code == 200
    payload = simulated.json()
    assert payload["simulation"] == "no_provider_calls_no_state_changes"
    assert payload["actions"][0]["disposition"] == "approve"
    assert payload["final_projected_spend"]["run_usd"] == pytest.approx(0.85)


def test_replay_requires_ledger_bound_arguments_and_reports_policy_delta(client):
    import warden.server as server

    args = {**LAUNCH, "machine_type": "g2-standard-12"}
    runtime = server.get_runtime()
    asyncio.run(runtime.ledger.append(Record(
        seq=0,
        ts="2026-08-22T00:00:00Z",
        fleet="historical",
        run_id=runtime.run_id,
        actor="provisioner",
        tool="launch_gpu",
        disposition="approve",
        reason="historically approved",
        args_digest=digest_args(args),
        outcome="approved",
    )))

    manifest = client.get("/policy/replay/manifest")
    assert manifest.status_code == 200
    assert manifest.json()["records"][-1]["args_digest"] == digest_args(args)

    replay = client.post(
        "/policy/replay",
        json={
            "template_id": "creator-safe",
            "actions": [{"record_seq": 0, "tool": "launch_gpu", "args": args}],
        },
    )
    assert replay.status_code == 200
    change = replay.json()["changes"][0]
    assert change["changed"] is True
    assert change["candidate"]["disposition"] == "deny"

    tampered = client.post(
        "/policy/replay",
        json={
            "template_id": "creator-safe",
            "actions": [{"record_seq": 0, "tool": "launch_gpu", "args": LAUNCH}],
        },
    )
    assert tampered.status_code == 422
    assert "digest" in tampered.json()["detail"]
