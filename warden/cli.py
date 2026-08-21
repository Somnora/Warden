"""Warden Operator CLI - Command line interface for fleet governance."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import httpx
import uvicorn


DEFAULT_SERVER_URL = os.environ.get("WARDEN_SERVER_URL", "http://127.0.0.1:8000")


def cmd_server(args: argparse.Namespace) -> None:
    """Start the FastAPI Operator Control Plane server."""
    print(f"🚀 Starting Warden Operator Control Plane on {args.host}:{args.port}...")
    uvicorn.run("warden.server:app", host=args.host, port=args.port, reload=args.reload)


def _request_headers(extra: dict[str, str] | None = None) -> dict[str, str]:
    """Use an identity token for private Cloud Run, plus mock-only extras."""
    headers = dict(extra or {})
    if token := os.environ.get("WARDEN_ID_TOKEN"):
        headers["Authorization"] = f"Bearer {token}"
    return headers


async def _get(path: str, url: str = DEFAULT_SERVER_URL) -> dict | list:
    async with httpx.AsyncClient(base_url=url, timeout=10.0) as client:
        r = await client.get(path, headers=_request_headers())
        r.raise_for_status()
        return r.json()


async def _post(
    path: str, body: dict, url: str = DEFAULT_SERVER_URL, *, headers: dict[str, str] | None = None
) -> dict | list:
    async with httpx.AsyncClient(base_url=url, timeout=30.0) as client:
        r = await client.post(path, json=body, headers=_request_headers(headers))
        r.raise_for_status()
        return r.json()


def cmd_status(args: argparse.Namespace) -> None:
    """Check fleet status and health."""
    try:
        data = asyncio.run(_get("/health", args.url))
        spend = asyncio.run(_get("/spend", args.url))
        print("🛡️  Warden Fleet Health & Status")
        print("=" * 45)
        print(f"  Fleet:       {data.get('fleet')}")
        print(f"  Status:      {data.get('status')}")
        print(f"  Subagents:   {', '.join(data.get('subagents', []))}")
        print(f"  Today Spend: ${spend.get('day_usd', 0.0):.2f}")
        print(f"  Live Nodes:  {spend.get('live_instances', 0)}")
    except Exception as e:
        print(f"❌ Error contacting server: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_pending(args: argparse.Namespace) -> None:
    """List pending human approval tickets."""
    try:
        items = asyncio.run(_get("/approvals/pending", args.url))
        if not items:
            print("✨ No pending approval tickets. Fleet is idle.")
            return

        print(f"🙋 Found {len(items)} pending approval ticket(s):")
        print("=" * 70)
        for it in items:
            print(f"  Ticket ID: {it['approval_id']}")
            print(f"  Actor:     {it['actor']}")
            print(f"  Tool:      {it['tool']}")
            print(f"  Reason:    {it['reason']}")
            print(f"  Created:   {it['requested_at']}")
            print("-" * 70)
    except Exception as e:
        print(f"❌ Error contacting server: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_decide(args: argparse.Namespace) -> None:
    """Decide on a pending approval ticket (grant or deny)."""
    try:
        body = {
            "granted": args.granted,
            "note": args.note or "",
        }
        # The control plane ignores this header in live mode and takes the
        # verified Cloud Run identity instead. It keeps local mock demos
        # convenient without reintroducing a client-supplied JSON approver.
        headers = {"X-Warden-Operator": args.approver or os.environ.get("USER", "local-operator")}
        res = asyncio.run(_post(f"/approvals/{args.ticket_id}/decide", body, args.url, headers=headers))
        action = "GRANTED ✅" if args.granted else "DENIED ⛔"
        print(f"Ticket {args.ticket_id} {action}")
        print(f"Approver: {res.get('approver')}")
    except Exception as e:
        print(f"❌ Error deciding ticket: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_verify(args: argparse.Namespace) -> None:
    """Verify cryptographic SHA-256 audit chain integrity."""
    try:
        res = asyncio.run(_get("/audit/verify", args.url))
        ok = res.get("ok", False)
        print("⛓️  Cryptographic Audit Chain Integrity Verification")
        print("=" * 55)
        print(f"  Status:          {'✅ VALID' if ok else '❌ CORRUPTED'}")
        print(f"  Records Checked: {res.get('checked_records')}")
        print(f"  Detail:          {res.get('detail')}")
    except Exception as e:
        print(f"❌ Error verifying ledger: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_run(args: argparse.Namespace) -> None:
    """Execute a prompt against the fleet."""
    try:
        body = {"prompt": args.prompt, "user_id": args.user_id, "session_id": args.session_id}
        print(f"🚀 Submitting task to fleet: \"{args.prompt}\"...")
        res = asyncio.run(_post(
            "/fleet/run", body, args.url,
            headers={"X-Warden-Operator": args.user_id},
        ))
        print("\n🤖 Fleet Response:")
        print("-" * 60)
        print(res.get("response", "(No text output)"))
        print("-" * 60)
        print(f"Events: {res.get('events_count')} | Pending: {res.get('pending_approvals_count')} | Ledger: {res.get('audit_records_count')} records")
    except Exception as e:
        print(f"❌ Error executing task: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_redteam(args: argparse.Namespace) -> None:
    """Run automated adversarial red-team penetration test against Warden."""
    try:
        from warden.security.redteam import run_redteam_benchmark
        report = asyncio.run(run_redteam_benchmark())
        print("\n🛡️  WARDEN ADVERSARIAL RED-TEAM PENETRATION TEST")
        print("=" * 65)
        print(f"  Security Grade:   GRADE {report.grade} 🏆")
        print(f"  Deflected Rate:   {report.deflected_count}/{report.total_vectors} ({report.deflection_rate})")
        print("-" * 65)
        for r in report.results:
            status = "✅ DEFLECTED" if r.deflected else "❌ BREACHED"
            print(f"  [{r.vector_id}] {r.vector_name:<38} {status}")
            print(f"      └─ {r.detail}")
        print("=" * 65)
    except Exception as e:
        print(f"❌ Error running red team test: {e}", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(prog="warden", description="Warden Operator Control Plane CLI")
    parser.add_argument("--url", default=DEFAULT_SERVER_URL, help="Control Plane API URL")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # Server subcommand
    p_server = subparsers.add_parser("server", help="Start FastAPI control plane server")
    p_server.add_argument("--host", default="0.0.0.0", help="Host address")
    p_server.add_argument("--port", type=int, default=8000, help="Port number")
    p_server.add_argument("--reload", action="store_true", help="Enable reload")
    p_server.set_defaults(func=cmd_server)

    # Status subcommand
    p_status = subparsers.add_parser("status", help="Inspect fleet health & spend")
    p_status.set_defaults(func=cmd_status)

    # Pending approvals subcommand
    p_pending = subparsers.add_parser("pending", help="List pending approval tickets")
    p_pending.set_defaults(func=cmd_pending)

    # Approve subcommand
    p_approve = subparsers.add_parser("approve", help="Approve a pending ticket")
    p_approve.add_argument("ticket_id", help="Approval Ticket ID")
    p_approve.add_argument("--approver", help="Local/mock operator ID (live mode uses verified Cloud Run identity)")
    p_approve.add_argument("--note", help="Reason or notes")
    p_approve.set_defaults(func=cmd_decide, granted=True)

    # Deny subcommand
    p_deny = subparsers.add_parser("deny", help="Deny a pending ticket")
    p_deny.add_argument("ticket_id", help="Approval Ticket ID")
    p_deny.add_argument("--approver", help="Local/mock operator ID (live mode uses verified Cloud Run identity)")
    p_deny.add_argument("--note", help="Reason or notes")
    p_deny.set_defaults(func=cmd_decide, granted=False)

    # Verify subcommand
    p_verify = subparsers.add_parser("verify", help="Verify cryptographic audit chain")
    p_verify.set_defaults(func=cmd_verify)

    # Run subcommand
    p_run = subparsers.add_parser("run", help="Dispatch a task to the fleet")
    p_run.add_argument("prompt", help="Instruction for the agent fleet")
    p_run.add_argument("--user-id", default="operator-01", help="User ID")
    p_run.add_argument("--session-id", default="default-session", help="Session ID")
    p_run.set_defaults(func=cmd_run)

    # Red-Team subcommand
    p_redteam = subparsers.add_parser("redteam", help="Run automated adversarial red-team penetration test")
    p_redteam.set_defaults(func=cmd_redteam)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
