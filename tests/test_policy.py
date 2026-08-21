"""Policy is the thing standing between an agent and the billing account."""

import pytest

from warden.policy.engine import Disposition, Policy, SpendSnapshot

@pytest.fixture
def policy() -> Policy:
    return Policy.load()


def test_unknown_tool_is_denied_not_allowed(policy):
    d = policy.evaluate("rm_rf_everything")
    assert d.disposition is Disposition.DENY
    assert "UNGOVERNED" in d.reason


def test_readonly_tool_allowed(policy):
    assert policy.evaluate("list_instances").allowed


def test_spending_tool_requires_human(policy):
    d = policy.evaluate(
        "launch_gpu",
        {"provider": "gcp", "region": "us-west1",
         "machine_type": "g2-standard-8", "max_lifetime_minutes": 60},
    )
    assert d.disposition is Disposition.APPROVE
    assert d.needs_human


def test_explicit_deny_cannot_be_argued_with(policy):
    assert policy.evaluate("set_research_key").disposition is Disposition.DENY


def test_disallowed_region_is_denied(policy):
    d = policy.evaluate(
        "launch_gpu",
        {"provider": "gcp", "region": "europe-west4",
         "machine_type": "g2-standard-8", "max_lifetime_minutes": 60},
    )
    assert d.disposition is Disposition.DENY
    assert "europe-west4" in d.reason


def test_zone_satisfies_region_rule(policy):
    d = policy.evaluate(
        "launch_gpu",
        {"provider": "gcp", "zone": "us-west1-a",
         "machine_type": "g2-standard-8", "max_lifetime_minutes": 60},
    )
    assert d.disposition is Disposition.APPROVE


def test_launch_without_teardown_deadline_is_denied(policy):
    d = policy.evaluate(
        "launch_gpu",
        {"provider": "gcp", "region": "us-west1", "machine_type": "g2-standard-8"},
    )
    assert d.disposition is Disposition.DENY
    assert "max_lifetime_minutes" in d.reason


def test_lifetime_above_ceiling_is_denied(policy):
    d = policy.evaluate(
        "launch_gpu",
        {"provider": "gcp", "region": "us-west1",
         "machine_type": "g2-standard-8", "max_lifetime_minutes": 9999},
    )
    assert d.disposition is Disposition.DENY
    assert "ceiling" in d.reason


def test_run_budget_ceiling_blocks_launch(policy):
    d = policy.evaluate(
        "launch_gpu",
        {"provider": "gcp", "region": "us-west1",
         "machine_type": "g2-standard-8", "max_lifetime_minutes": 60},
        spend=SpendSnapshot(run_usd=25.0, day_usd=25.0, live_instances=0),
    )
    assert d.disposition is Disposition.DENY
    assert "ceiling" in d.reason


def test_estimate_that_would_breach_is_refused_upfront(policy):
    d = policy.evaluate(
        "launch_gpu",
        {"provider": "gcp", "region": "us-west1", "machine_type": "g2-standard-8",
         "max_lifetime_minutes": 60, "estimated_usd": 20.0},
        spend=SpendSnapshot(run_usd=10.0, day_usd=10.0, live_instances=0),
    )
    assert d.disposition is Disposition.DENY


def test_launch_without_estimate_is_refused_upfront(policy):
    d = policy.evaluate(
        "launch_gpu",
        {"provider": "gcp", "region": "us-west1", "machine_type": "g2-standard-8",
         "max_lifetime_minutes": 60},
        spend=SpendSnapshot(),
    )
    assert d.disposition is Disposition.DENY
    assert "estimated_usd" in d.reason


@pytest.mark.parametrize("estimate", ["not-a-number", -1, float("inf")])
def test_invalid_estimate_is_refused_upfront(policy, estimate):
    d = policy.evaluate(
        "launch_gpu",
        {"provider": "gcp", "region": "us-west1", "machine_type": "g2-standard-8",
         "max_lifetime_minutes": 60, "estimated_usd": estimate},
        spend=SpendSnapshot(),
    )
    assert d.disposition is Disposition.DENY


@pytest.mark.parametrize("ttl", [0, -1, "forever"])
def test_invalid_lifetime_is_refused(policy, ttl):
    d = policy.evaluate(
        "launch_gpu",
        {"provider": "gcp", "region": "us-west1", "machine_type": "g2-standard-8",
         "max_lifetime_minutes": ttl, "estimated_usd": 1},
        spend=SpendSnapshot(),
    )
    assert d.disposition is Disposition.DENY


def test_concurrency_ceiling(policy):
    d = policy.evaluate(
        "launch_gpu",
        {"provider": "gcp", "region": "us-west1",
         "machine_type": "g2-standard-8", "max_lifetime_minutes": 60},
        spend=SpendSnapshot(live_instances=2),
    )
    assert d.disposition is Disposition.DENY
    assert "already live" in d.reason


def test_readonly_tool_unaffected_by_exhausted_budget(policy):
    d = policy.evaluate("get_spend", spend=SpendSnapshot(run_usd=999.0, day_usd=999.0))
    assert d.allowed, "observation must survive budget exhaustion"


@pytest.mark.parametrize(
    "secret",
    [
        '{"private_key": "-----BEGIN PRIVATE KEY-----abc"}',
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "Authorization: Bearer ya29.abcdefghijklmnopqrstuvwxyz0123",
        "key=AIzaSyA01234567890123456789012345678901",  # 39 chars, real GCP key shape
    ],
)
def test_redaction_strips_credentials(policy, secret):
    out, fired = policy.redact(f"log line {secret} tail")
    assert fired, f"nothing fired for {secret!r}"
    assert "REDACTED" in out
    assert "BEGIN PRIVATE KEY-----abc" not in out


def test_redaction_leaves_clean_text_alone(policy):
    out, fired = policy.redact("launched g2-standard-8 in us-west1")
    assert not fired
    assert out == "launched g2-standard-8 in us-west1"
