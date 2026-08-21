"""Tests for track-specific registry, memory, and Model Armor behaviors."""

import pytest
from fastapi.testclient import TestClient

from warden.fleet import initialize_fleet_runtime
from warden.memory import MemoryMemoryBank, context_for, subject_key
from warden.model_armor import ModelArmor, _decision_from_response
from warden.server import app, set_runtime


@pytest.fixture
def client():
    runtime = initialize_fleet_runtime(run_id="test-enterprise-run")
    set_runtime(runtime)
    return TestClient(app)


def test_registry_exposes_only_active_approved_agents(client):
    response = client.get("/registry/agents")
    assert response.status_code == 200
    payload = response.json()
    assert payload["catalog_version"] == "0.2.0"
    assert {agent["name"] for agent in payload["agents"]} == {
        "fleet_lead", "resource_auditor", "infrastructure_provisioner", "lifecycle_manager",
    }
    assert all(agent["lifecycle"] == "approved" for agent in payload["agents"])


def test_memory_is_identity_scoped_and_dlp_sanitized(client):
    secret = "AIza" + "a" * 35
    saved = client.post(
        "/memory", json={"content": f"Use the west region. Key: {secret}"},
        headers={"X-Warden-Operator": "owner@example.com"},
    )
    assert saved.status_code == 200
    assert saved.json()["redactions"] == ["gcp_api_key"]

    owner_items = client.get("/memory", headers={"X-Warden-Operator": "owner@example.com"}).json()["items"]
    other_items = client.get("/memory", headers={"X-Warden-Operator": "other@example.com"}).json()["items"]
    assert "[REDACTED:gcp_api_key]" in owner_items[0]["content"]
    assert other_items == []


@pytest.mark.asyncio
async def test_memory_context_is_bounded_and_subjects_are_hashed():
    bank = MemoryMemoryBank()
    await bank.remember("owner@example.com", "Prefer us-west1 for research jobs.")
    item = (await bank.list("owner@example.com"))[0]
    assert item.subject_hash == subject_key("owner@example.com")
    assert "owner@example.com" not in item.subject_hash
    assert "us-west1" in await context_for(bank, "owner@example.com")


def test_model_armor_result_blocks_matches_and_is_optional_without_template():
    blocked = _decision_from_response({
        "sanitizationResult": {"invocationResult": "SUCCESS", "filterMatchState": "MATCH_FOUND"}
    })
    clean = _decision_from_response({
        "sanitizationResult": {"invocationResult": "SUCCESS", "filterMatchState": "NO_MATCH_FOUND"}
    })
    assert blocked.allowed is False
    assert clean.allowed is True
    assert ModelArmor(project="", template="").enabled is False
