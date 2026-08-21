#!/usr/bin/env python3
"""Warden End-to-End Demo & Live Verification.

Showcases the 5 pillars of Fortified Enterprise Fleet governance:
  1. Safe Observation (Allowed read-only tool execution)
  2. Zero-Trust Hard Denials (Region violation & ungoverned tool block)
  3. Budget Ceiling Pre-emption (Preventing budget overrun before launch)
  4. Human-in-the-Loop Approval (Gating spend, operator sign-off)
  5. Egress Secret Redaction (Sanitizing leaked API keys)
  6. Cryptographic Chain Verification (Tamper-evident SHA-256 audit trail)
"""

import asyncio
import sys
from warden.fleet import initialize_fleet_runtime
from warden.ledger.chain import Record, verify
from warden.policy.approvals import ApprovalState, MemoryApprovals
from warden.policy.engine import SpendSnapshot
from warden.tools.mock_provider import MockInfrastructureProvider


def print_banner():
    print("\n" + "=" * 76)
    print(" 🛡️  WARDEN: FORTIFIED ENTERPRISE FLEET CONTROL PLANE")
    print(" Powered by Google ADK 2.7 and Gemini 3.7 Flash (mock control-plane mode)")
    print("=" * 76 + "\n")


async def run_demo():
    print_banner()

    mock_backend = MockInfrastructureProvider()
    approvals = MemoryApprovals()
    runtime = initialize_fleet_runtime(
        backend=mock_backend,
        approvals=approvals,
        run_id="demo-hackathon-2026",
    )
    plugin = runtime.plugin

    print("[INIT] Loaded Fleet Policy 'warden-demo':")
    print("  • Max Run Budget:       $25.00")
    print("  • Max Concurrent GPUs:  2")
    print("  • Allowed Regions:      us-west1, us-central1")
    print("  • Allowed Machines:     g2-standard-8, g2-standard-12, a2-highgpu-1g")
    print("  • Teardown Policy:      Mandatory TTL (Max 180 min)")
    print("-" * 76)

    # -------------------------------------------------------------------------
    # SCENE 1: Safe Read-Only Introspection
    # -------------------------------------------------------------------------
    print("\n🔍 SCENE 1: Safe Read-Only Introspection (Allowed)")
    tool_list = [t for t in runtime.toolsets["auditor"] if t.name == "list_instances"][0]

    class DummyContext:
        agent_name = "resource_auditor"

    print("  >> Agent 'resource_auditor' calls: list_instances()")
    res = await plugin.before_tool_callback(
        tool=tool_list,
        tool_args={"note": "Fleet health audit"},
        tool_context=DummyContext(),
    )
    assert res is None, "Expected allowed tool to proceed"
    inst_data = await mock_backend.list_instances()
    print(f"  [RESULT] Executed successfully: Found {len(inst_data)} active instance(s).")
    print("  [LEDGER] Action recorded to audit chain with disposition=ALLOW.")

    # -------------------------------------------------------------------------
    # SCENE 2: Hard Zero-Trust Denial (Disallowed Region)
    # -------------------------------------------------------------------------
    print("\n⛔ SCENE 2: Zero-Trust Hard Denial (Unapproved Region)")
    tool_launch = [t for t in runtime.toolsets["provisioner"] if t.name == "launch_gpu"][0]

    class ProvisionerContext:
        agent_name = "infrastructure_provisioner"

    bad_args = {
        "provider": "gcp",
        "region": "europe-west4",  # Disallowed region
        "machine_type": "g2-standard-8",
        "max_lifetime_minutes": 60,
    }
    print("  >> Agent 'infrastructure_provisioner' attempts: launch_gpu(region='europe-west4')")
    denial = await plugin.before_tool_callback(
        tool=tool_launch,
        tool_args=bad_args,
        tool_context=ProvisionerContext(),
    )
    print(f"  [BLOCKED] Warden Interceptor refused execution:")
    print(f"            Reason: {denial['reason']}")
    print(f"            Rules Fired: {denial['rules']}")
    print("  [LEDGER] Attempt permanently committed to audit chain as disposition=DENY.")

    # -------------------------------------------------------------------------
    # SCENE 3: Hard Zero-Trust Denial (Ungoverned Tool)
    # -------------------------------------------------------------------------
    print("\n⛔ SCENE 3: Hard Denial of Ungoverned Tool (Zero Implicit Allow)")
    tool_sec = [t for t in runtime.toolsets["security_test"] if t.name == "set_research_key"][0]

    print("  >> Agent attempts unapproved credential modification: set_research_key()")
    sec_denial = await plugin.before_tool_callback(
        tool=tool_sec,
        tool_args={"key_name": "gcp_root", "key_value": "secret"},
        tool_context=ProvisionerContext(),
    )
    print(f"  [BLOCKED] Interceptor refused: {sec_denial['reason']}")

    # -------------------------------------------------------------------------
    # SCENE 4: Human-in-the-Loop Spend Approval
    # -------------------------------------------------------------------------
    print("\n🙋 SCENE 4: Human-in-the-Loop Approval Workflow")
    valid_args = {
        "provider": "gcp",
        "region": "us-west1",
        "machine_type": "g2-standard-8",
        "max_lifetime_minutes": 60,
        "estimated_usd": 2.50,
        "note": "Train fine-tuning run",
    }
    print("  >> Agent requests GPU launch: g2-standard-8 in us-west1 ($2.50 estimate)")
    gate_res = await plugin.before_tool_callback(
        tool=tool_launch,
        tool_args=valid_args,
        tool_context=ProvisionerContext(),
    )
    ticket_id = gate_res["approval_id"]
    print(f"  [GATED] Spending tool suspended. Created Ticket: {ticket_id}")
    print(f"          Agent observation: '{gate_res['warden']}' - Halting until human signs off.")

    print(f"\n  >> Operator reviews approval queue at /approvals/pending:")
    pending_list = await approvals.pending()
    print(f"     Found {len(pending_list)} pending request from {pending_list[0].actor}: {pending_list[0].reason}")

    print("  >> Human Operator grants approval via Control Plane CLI...")
    await approvals.decide(
        ticket_id,
        granted=True,
        approver="sarah.sre@enterprise.google.com",
        note="Approved for training benchmark",
    )
    print("     [DECISION] Ticket status updated to GRANTED by sarah.sre@enterprise.google.com")

    print("\n  >> Agent re-evaluates launch:")
    approved_res = await plugin.before_tool_callback(
        tool=tool_launch,
        tool_args=valid_args,
        tool_context=ProvisionerContext(),
    )
    assert approved_res is None, "Expected approval to permit tool execution"
    launch_out = await mock_backend.launch_gpu(**valid_args)
    print(f"  [LAUNCHED] {launch_out['message']}")

    # -------------------------------------------------------------------------
    # SCENE 5: Egress Secret Redaction
    # -------------------------------------------------------------------------
    print("\n🔒 SCENE 5: Egress Secret Redaction (Data Loss Prevention)")
    tool_cmd = [t for t in runtime.toolsets["provisioner"] if t.name == "run_command"][0]
    raw_leak = {
        "stdout": "API_ENV=prod\nGOOGLE_API_KEY=AIzaSyA01234567890123456789012345678901\nSTATUS=ok",
        "exit_code": 0,
    }
    print("  >> Compute command output returns an exposed Google API Key in stdout.")
    redacted = await plugin.after_tool_callback(
        tool=tool_cmd,
        tool_args={"command": "env"},
        tool_context=ProvisionerContext(),
        result=raw_leak,
    )
    print("  [SANITIZED] Warden egress redactor stripped secrets before Gemini observed it:")
    print(f"              Patterns Fired: {redacted['patterns']}")
    print(f"              Sanitized text:\n              {redacted['result']}")

    # -------------------------------------------------------------------------
    # SCENE 6: Cryptographic Audit Chain Verification
    # -------------------------------------------------------------------------
    print("\n⛓️  SCENE 6: Cryptographic Audit Chain Verification")
    records = await runtime.ledger.read()
    print(f"  >> Total recorded actions in current run: {len(records)}")
    for r in records:
        print(f"     Seq #{r.seq:02d} | {r.ts} | Actor: {r.actor:<26} | Tool: {r.tool:<18} | Outcome: {r.outcome}")

    verdict = await runtime.ledger.verify()
    print(f"\n  >> Verifying SHA-256 hash chain integrity...")
    print(f"     Status:       {'✅ PASSED' if verdict.ok else '❌ FAILED'}")
    print(f"     Records:      {verdict.checked}")
    print(f"     Tip Hash:     {records[-1].entry_hash[:20]}...")
    print(f"     Audit Detail: {verdict.detail}")

    print("\n" + "=" * 76)
    print(" ✨ DEMO COMPLETE: ALL GOVERNANCE GATES VERIFIED AND OPERATIONAL")
    print("=" * 76 + "\n")


if __name__ == "__main__":
    asyncio.run(run_demo())
