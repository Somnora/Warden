"""Policy is the thing standing between an agent and the billing account."""

import pytest

from warden.policy.engine import Disposition, Policy, PolicyError, SpendSnapshot

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


def test_zone_prefix_spoof_is_denied(policy):
    d = policy.evaluate(
        "launch_gpu",
        {"zone": "us-west1-attack", "machine_type": "g2-standard-8", "max_lifetime_minutes": 60},
    )
    assert d.disposition is Disposition.DENY
    assert "placement.allowed_regions" in d.rules


@pytest.mark.parametrize(
    "args",
    [
        {"region": "us-west1", "zone": "us-central1-a"},
        {"machine_type": "g2-standard-8", "instance_type": "a2-highgpu-1g"},
        {"max_lifetime_minutes": 60, "max_lifetime_seconds": 7200},
    ],
)
def test_conflicting_aliases_fail_closed(policy, args):
    base = {"region": "us-west1", "machine_type": "g2-standard-8", "max_lifetime_minutes": 60}
    base.update(args)
    d = policy.evaluate("launch_gpu", base, spend=SpendSnapshot())
    assert d.disposition is Disposition.DENY
    assert d.rules == ("arguments.conflicting_aliases",)


@pytest.mark.parametrize("args", [["not", "an", "object"], {1: "non-string-key"}])
def test_malformed_tool_arguments_fail_closed(policy, args):
    d = policy.evaluate("list_instances", args)  # type: ignore[arg-type]
    assert d.disposition is Disposition.DENY
    assert d.rules == ("arguments.json_object",)


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
        spend=SpendSnapshot(run_usd=24.50, day_usd=24.50, live_instances=0),
    )
    assert d.disposition is Disposition.DENY
    assert "rate-card quote" in d.reason


def test_underquoted_estimate_cannot_bypass_rate_card(policy):
    """A $2.00 model quote must not bless a 16x A100 that the rate card prices at $58.72."""
    d = policy.evaluate(
        "launch_gpu",
        {
            "provider": "gcp",
            "region": "us-west1",
            "machine_type": "a2-megagpu-16g",
            "max_lifetime_minutes": 60,
            "estimated_usd": 2.00,
        },
        spend=SpendSnapshot(),
    )
    assert d.disposition is Disposition.DENY
    assert "rate-card quote" in d.reason
    quoted, err = policy.quote_launch(
        "launch_gpu",
        {"machine_type": "a2-megagpu-16g", "max_lifetime_minutes": 60},
    )
    assert err is None
    assert quoted == 58.72


def test_model_estimate_is_display_hint_only(policy):
    d = policy.evaluate(
        "launch_gpu",
        {
            "provider": "gcp",
            "region": "us-west1",
            "machine_type": "g2-standard-8",
            "max_lifetime_minutes": 60,
            "estimated_usd": 0.01,
        },
        spend=SpendSnapshot(),
    )
    assert d.disposition is Disposition.APPROVE
    assert policy.quote_usd(
        "launch_gpu",
        {"machine_type": "g2-standard-8", "max_lifetime_minutes": 60},
    ) == 0.85


def test_launch_without_estimate_is_quoted_from_rate_card(policy):
    d = policy.evaluate(
        "launch_gpu",
        {"provider": "gcp", "region": "us-west1", "machine_type": "g2-standard-8",
         "max_lifetime_minutes": 60},
        spend=SpendSnapshot(),
    )
    assert d.disposition is Disposition.APPROVE
    assert "estimated_usd" not in d.reason


def test_unknown_machine_has_no_authoritative_quote(policy):
    quote, error = policy.quote_launch(
        "launch_gpu", {"machine_type": "future-unpriced-gpu", "max_lifetime_minutes": 60}
    )
    assert quote is None
    assert error and error[0] == "budget.rate_card"


def test_policy_rejects_rate_card_documentation_drift(policy):
    doc = {**policy.doc, "rates": {"machine_usd_per_hour": {"g2-standard-8": 0.01}}}
    with pytest.raises(PolicyError, match="does not match"):
        Policy(doc)


@pytest.mark.parametrize("estimate", ["not-a-number", -1, float("inf")])
def test_invalid_estimate_is_ignored_in_favor_of_rate_card(policy, estimate):
    d = policy.evaluate(
        "launch_gpu",
        {"provider": "gcp", "region": "us-west1", "machine_type": "g2-standard-8",
         "max_lifetime_minutes": 60, "estimated_usd": estimate},
        spend=SpendSnapshot(),
    )
    assert d.disposition is Disposition.APPROVE


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


def test_cluster_quote_and_concurrency_use_node_count(policy):
    args = {
        "provider": "gcp", "region": "us-west1", "machine_type": "g2-standard-8",
        "max_lifetime_minutes": 60, "node_count": 2,
    }
    assert policy.quote_usd("launch_cluster", args) == 1.70
    denied = policy.evaluate(
        "launch_cluster", {**args, "node_count": 3}, spend=SpendSnapshot(live_instances=0)
    )
    assert denied.disposition is Disposition.DENY
    assert "budget.max_concurrent_instances" in denied.rules


@pytest.mark.parametrize("node_count", [0, -1, 1.5, True, "2"])
def test_malformed_cluster_node_count_is_denied(policy, node_count):
    d = policy.evaluate(
        "launch_cluster",
        {"region": "us-west1", "machine_type": "g2-standard-8",
         "max_lifetime_minutes": 60, "node_count": node_count},
        spend=SpendSnapshot(),
    )
    assert d.disposition is Disposition.DENY
    assert "budget.node_count" in d.rules


def test_prospective_daily_budget_is_enforced(policy):
    d = policy.evaluate(
        "launch_gpu",
        {"region": "us-west1", "machine_type": "g2-standard-8", "max_lifetime_minutes": 60},
        spend=SpendSnapshot(run_usd=0, day_usd=99.50, live_instances=0),
    )
    assert d.disposition is Disposition.DENY
    assert "budget.max_usd_per_day" in d.rules


@pytest.mark.parametrize(
    "snapshot",
    [
        SpendSnapshot(run_usd=float("nan")),
        SpendSnapshot(run_usd="1.0"),  # type: ignore[arg-type]
        SpendSnapshot(day_usd=-1),
        SpendSnapshot(live_instances=-1),
    ],
)
def test_invalid_spend_snapshot_fails_closed(policy, snapshot):
    d = policy.evaluate(
        "launch_gpu",
        {"region": "us-west1", "machine_type": "g2-standard-8", "max_lifetime_minutes": 60},
        spend=snapshot,
    )
    assert d.disposition is Disposition.DENY
    assert d.rules[-1] == "budget.snapshot"


def test_readonly_inspection_command_is_allowed(policy):
    d = policy.evaluate("run_command", {"command": "nvidia-smi"})
    assert d.allowed
    assert "allowlist" in d.reason


def test_arbitrary_shell_command_requires_approval(policy):
    d = policy.evaluate("run_command", {"command": "rm -rf /"})
    assert d.disposition is Disposition.APPROVE
    assert d.needs_human


def test_dispatch_local_subagent_requires_approval(policy):
    d = policy.evaluate("dispatch_local_subagent", {"prompt": "train forever"})
    assert d.disposition is Disposition.APPROVE


def test_run_detached_requires_approval(policy):
    d = policy.evaluate("run_detached", {"command": "python train.py"})
    assert d.disposition is Disposition.APPROVE


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


def test_redaction_removes_complete_pem_body_and_escaped_service_account_key(policy):
    pem = "-----BEGIN PRIVATE KEY-----\nSUPERSECRETKEYMATERIAL\n-----END PRIVATE KEY-----"
    escaped = '{"private_key": "-----BEGIN PRIVATE KEY-----\\nESCAPEDSECRET\\n-----END PRIVATE KEY-----"}'
    out, fired = policy.redact(f"{pem}\n{escaped}")
    assert fired
    assert "SUPERSECRETKEYMATERIAL" not in out
    assert "ESCAPEDSECRET" not in out


def test_redaction_handles_raw_oauth_and_jwt_but_not_clean_prose(policy):
    jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlMTIz"
    text = f"access=ya29.abcdefghijklmnopqrstuvwxyz012345 jwt={jwt}"
    out, fired = policy.redact(text)
    assert {"oauth_access_token", "jwt_token"}.issubset(fired)
    assert "ya29." not in out and "eyJ" not in out
    clean = "A bearer is a person carrying something; AIza is a name fragment."
    assert policy.redact(clean) == (clean, ())
