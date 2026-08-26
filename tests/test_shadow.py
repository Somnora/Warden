"""Observational shadow replay: would-have outcomes without enforcement."""

import pytest
from fastapi.testclient import TestClient

from warden.fleet import initialize_fleet_runtime
from warden.policy.engine import Policy, SpendSnapshot
from warden.policy.shadow import ShadowCall, replay, replay_fixture
from warden.server import app, set_runtime


LAUNCH = {
    "provider": "gcp",
    "region": "us-west1",
    "machine_type": "g2-standard-8",
    "max_lifetime_minutes": 60,
    "estimated_usd": 0.01,
}


@pytest.fixture
def client():
    runtime = initialize_fleet_runtime(run_id="test-shadow-run")
    set_runtime(runtime)
    return TestClient(app)


def test_fixture_replay_uses_rate_card_not_model_quote():
    policy = Policy.load()
    report = replay_fixture(policy)

    assert report.enforcement == "off"
    assert report.fail_closed is False
    assert report.calls_scored == 7
    assert report.allowed == 1
    assert report.parked >= 2
    assert report.denied >= 2

    by_tool = {}
    for call in report.calls:
        by_tool.setdefault(call.tool, []).append(call)

    legal = by_tool["launch_gpu"][0]
    assert legal.would_have == "parked"
    assert legal.quoted_usd == pytest.approx(0.85)
    assert legal.quote_source == "MACHINE_HOURLY_RATES"
    assert legal.parked_usd == pytest.approx(0.85)

    east = by_tool["launch_gpu"][1]
    assert east.would_have == "denied"
    assert "us-east1" in east.reason
    assert east.stopped_usd == pytest.approx(0.85)

    monster = by_tool["launch_gpu"][2]
    assert monster.would_have == "denied"
    assert monster.quoted_usd == pytest.approx(58.72)
    assert monster.stopped_usd == pytest.approx(58.72)
    assert monster.quoted_usd != 4.00

    assert by_tool["ungoverned_shell"][0].would_have == "denied"
    assert report.stopped_usd == pytest.approx(0.85 + 58.72)
    assert "stopped $" in report.headline.lower()
    assert report.examples
    assert "yaml" not in report.headline.lower()


def test_fail_closed_does_not_apply_when_evaluator_raises():
    policy = Policy.load()
    original = policy.evaluate

    def boom(*_args, **_kwargs):
        raise RuntimeError("control plane on fire")

    policy.evaluate = boom  # type: ignore[method-assign]
    try:
        report = replay(policy, [ShadowCall("launch_gpu", LAUNCH)])
    finally:
        policy.evaluate = original  # type: ignore[method-assign]

    assert report.denied == 0
    assert report.observed_errors == 1
    assert report.calls[0].would_have == "observed_error"
    assert "fail-closed" in report.calls[0].reason
    assert report.fail_closed is False


def test_shadow_does_not_mutate_spend_or_require_network():
    policy = Policy.load()
    before = SpendSnapshot()
    report = replay(policy, [ShadowCall("list_instances", {})], initial_spend=before)
    assert report.allowed == 1
    assert before == SpendSnapshot()
    assert report.calls[0].would_have == "allowed"


def test_shadow_api_runs_fixture_without_gemini(client):
    fixture = client.get("/shadow/fixture")
    assert fixture.status_code == 200
    assert fixture.json()["enforcement"] == "off"
    assert fixture.json()["fail_closed"] is False
    assert len(fixture.json()["calls"]) == 7

    replayed = client.post("/shadow/replay", json={})
    assert replayed.status_code == 200
    payload = replayed.json()
    assert payload["enforcement"] == "off"
    assert payload["fail_closed"] is False
    assert payload["quote_source"] == "MACHINE_HOURLY_RATES"
    assert payload["stopped_usd"] == pytest.approx(59.57)
    assert payload["headline"]
    assert payload["examples"]
    assert payload["denied"] >= 2
    assert "estimated_usd" not in str(payload["examples"])


def test_shadow_api_scores_supplied_transcript(client):
    response = client.post(
        "/shadow/replay",
        json={
            "source": "body",
            "calls": [
                {"tool": "list_instances", "args": {}},
                {"tool": "launch_gpu", "args": LAUNCH, "actor": "provisioner"},
            ],
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["source"] == "body"
    assert payload["allowed"] == 1
    assert payload["parked"] == 1
    assert payload["calls"][1]["quoted_usd"] == pytest.approx(0.85)
