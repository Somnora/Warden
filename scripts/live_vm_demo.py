#!/usr/bin/env python3
"""Run a bounded, billable Warden demo against a real Google Compute VM.

The default invocation is preflight-only. A real launch requires both
``--execute`` and an exact ``--confirm-project`` value. The VM is a Spot L4
instance with a Google Cloud enforced maximum run duration and DELETE as its
termination action. A best-effort cleanup also runs locally in ``finally``.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import uuid
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Sequence

from warden.ledger.chain import Record, append, digest_args, verify
from warden.policy.engine import Disposition, Policy, SpendSnapshot


DEFAULT_PROJECT = "somnora-dev-01"
DEFAULT_ZONE = "us-west1-a"
DEFAULT_MACHINE = "g2-standard-8"
DEFAULT_TTL_MINUTES = 5
PROOF_MARKER = "WARDEN_LIVE_VM_PROOF"


def gcloud_command(
    project: str,
    zone: str,
    name: str,
    machine_type: str,
    ttl_minutes: int,
) -> list[str]:
    startup = (
        "#!/bin/bash\n"
        f"echo '{PROOF_MARKER} name={name} utc='$(date -u +%FT%TZ) | "
        "tee /dev/ttyS0 /var/log/warden-proof.log\n"
    )
    return [
        "gcloud", "compute", "instances", "create", name,
        "--project", project,
        "--zone", zone,
        "--machine-type", machine_type,
        "--provisioning-model", "SPOT",
        "--instance-termination-action", "DELETE",
        "--max-run-duration", f"{ttl_minutes * 60}s",
        "--maintenance-policy", "TERMINATE",
        "--image-family", "ubuntu-2204-lts",
        "--image-project", "ubuntu-os-cloud",
        "--boot-disk-size", "20GB",
        "--boot-disk-type", "pd-balanced",
        "--no-address",
        "--no-restart-on-failure",
        "--labels", "app=warden,purpose=live-demo,managed-by=warden",
        "--metadata", f"startup-script={startup}",
        "--format=json",
    ]


def run(command: Sequence[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=check, text=True, capture_output=True)


def record(
    chain: list[Record],
    *,
    run_id: str,
    tool: str,
    disposition: str,
    reason: str,
    rules: tuple[str, ...],
    args: dict[str, object],
    outcome: str | None = None,
    cost_usd: float | None = None,
    approver: str | None = None,
) -> None:
    item = Record(
        seq=0,
        ts=datetime.now(UTC).isoformat(),
        fleet="warden-live-demo",
        run_id=run_id,
        actor="infrastructure_provisioner",
        tool=tool,
        disposition=disposition,
        reason=reason,
        rules=rules,
        args_digest=digest_args(args),
        approver=approver,
        outcome=outcome,
        cost_usd=cost_usd,
    )
    chain.append(append(chain, item))


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--project", default=DEFAULT_PROJECT)
    p.add_argument("--zone", default=DEFAULT_ZONE)
    p.add_argument("--machine-type", default=DEFAULT_MACHINE)
    p.add_argument("--ttl-minutes", type=int, default=DEFAULT_TTL_MINUTES)
    p.add_argument("--execute", action="store_true", help="Create a real billable VM")
    p.add_argument(
        "--confirm-project",
        default="",
        help="Required with --execute; must exactly match --project",
    )
    p.add_argument("--evidence", type=Path, default=Path("artifacts/live-vm-evidence.json"))
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args_ns = parser().parse_args(argv)
    region = args_ns.zone.rsplit("-", 1)[0]
    instance_name = f"warden-live-demo-{uuid.uuid4().hex[:8]}"
    launch_args: dict[str, object] = {
        "provider": "gcp",
        "region": region,
        "zone": args_ns.zone,
        "machine_type": args_ns.machine_type,
        "max_lifetime_minutes": args_ns.ttl_minutes,
        "name": instance_name,
    }

    policy = Policy.load()
    decision = policy.evaluate("launch_gpu", launch_args, spend=SpendSnapshot())
    quote = policy.quote_usd("launch_gpu", launch_args)
    print(f"Project: {args_ns.project}")
    print(f"Target:  {instance_name} ({args_ns.machine_type}, {args_ns.zone})")
    print(f"TTL:     {args_ns.ttl_minutes} minutes; Google Cloud action: DELETE")
    print(f"Ceiling: ${quote:.4f} using Warden's conservative on-demand rate card")
    print(f"Policy:  {decision.disposition.value.upper()} - {decision.reason}")

    if decision.disposition is not Disposition.APPROVE:
        print("Warden refused the launch before any provider call.", file=sys.stderr)
        return 2
    if not args_ns.execute:
        print("PREFLIGHT ONLY: no VM created and no billable provider call made.")
        print("Add --execute --confirm-project <project> for the bounded real run.")
        return 0
    if args_ns.confirm_project != args_ns.project:
        print("Refusing: --confirm-project must exactly match --project.", file=sys.stderr)
        return 2

    chain: list[Record] = []
    run_id = f"live-demo-{uuid.uuid4()}"
    record(
        chain,
        run_id=run_id,
        tool="launch_gpu",
        disposition="approve",
        reason=decision.reason,
        rules=decision.rules,
        args=launch_args,
        approver="local-operator-confirmation",
    )

    created = False
    provider: dict[str, object] | None = None
    serial_output = ""
    cleanup = "not-needed"
    try:
        print("Calling Google Compute Engine. This creates a real billable VM...")
        result = run(
            gcloud_command(
                args_ns.project,
                args_ns.zone,
                instance_name,
                args_ns.machine_type,
                args_ns.ttl_minutes,
            )
        )
        provider = json.loads(result.stdout)[0]
        created = True
        record(
            chain,
            run_id=run_id,
            tool="launch_gpu",
            disposition="allow",
            reason="exact action approved; provider reported a resource identifier",
            rules=decision.rules + ("approval.exact_action", "provider.gce"),
            args=launch_args,
            outcome="ok",
            cost_usd=quote,
            approver="local-operator-confirmation",
        )
        print(f"RUNNING: {provider.get('selfLink', instance_name)}")

        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            serial = run(
                [
                    "gcloud", "compute", "instances", "get-serial-port-output", instance_name,
                    "--project", args_ns.project, "--zone", args_ns.zone,
                    "--port", "1", "--start", "0",
                ],
                check=False,
            )
            serial_output = serial.stdout
            if PROOF_MARKER in serial_output:
                print(next(line for line in serial_output.splitlines() if PROOF_MARKER in line))
                break
            time.sleep(5)
        else:
            print("VM exists, but the startup proof marker was not observed before timeout.")
    except subprocess.CalledProcessError as exc:
        message = (exc.stderr or exc.stdout or str(exc)).strip()
        print(f"Provider call failed: {message}", file=sys.stderr)
        record(
            chain,
            run_id=run_id,
            tool="launch_gpu",
            disposition="allow",
            reason="approved provider call returned an error",
            rules=decision.rules + ("approval.exact_action", "provider.gce"),
            args=launch_args,
            outcome="error",
            cost_usd=quote,
            approver="local-operator-confirmation",
        )
        return 1
    finally:
        if created:
            print("Deleting the VM and verifying cleanup...")
            deleted = run(
                [
                    "gcloud", "compute", "instances", "delete", instance_name,
                    "--project", args_ns.project, "--zone", args_ns.zone, "--quiet",
                ],
                check=False,
            )
            check_absent = run(
                [
                    "gcloud", "compute", "instances", "describe", instance_name,
                    "--project", args_ns.project, "--zone", args_ns.zone,
                ],
                check=False,
            )
            cleanup = "verified-absent" if deleted.returncode == 0 and check_absent.returncode != 0 else "unverified"
            record(
                chain,
                run_id=run_id,
                tool="terminate_instance",
                disposition="allow",
                reason="bounded live demo cleanup",
                rules=("cleanup.finally", "provider.max_run_duration_delete"),
                args={"instance_id": instance_name, "zone": args_ns.zone},
                outcome="ok" if cleanup == "verified-absent" else "error",
            )

        verdict = verify(chain)
        evidence = {
            "schema": "warden.live-vm-evidence.v1",
            "project": args_ns.project,
            "zone": args_ns.zone,
            "instance_name": instance_name,
            "machine_type": args_ns.machine_type,
            "ttl_minutes": args_ns.ttl_minutes,
            "quoted_cost_ceiling_usd": quote,
            "real_provider_call": True,
            "billing_enabled": True,
            "cleanup": cleanup,
            "serial_proof_observed": PROOF_MARKER in serial_output,
            "provider_self_link": provider.get("selfLink") if provider else None,
            "ledger_verdict": asdict(verdict),
            "ledger": [asdict(item) for item in chain],
        }
        args_ns.evidence.parent.mkdir(parents=True, exist_ok=True)
        args_ns.evidence.write_text(json.dumps(evidence, indent=2) + "\n")
        print(f"Evidence: {args_ns.evidence}")
        print(f"Cleanup:  {cleanup}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
