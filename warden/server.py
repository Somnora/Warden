"""Warden Operator Control Plane - FastAPI Service for Google Cloud Run.

Exposes REST endpoints and interactive Web Dashboard for:
  - Policy inspection and fleet health
  - Human approval management (list, grant, deny)
  - Cryptographic audit ledger verification
  - Fleet task execution
  - Automated Red-Team adversarial security benchmark
"""

from __future__ import annotations

import os
import asyncio
import json
import logging
from uuid import uuid4
from pathlib import Path
from dataclasses import asdict, dataclass
from typing import Any
from pydantic import BaseModel, ConfigDict, Field
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware

from warden.fleet import initialize_fleet_runtime, execute_turn, WardenFleetRuntime
from warden.ledger.store import FirestoreLedger
from warden.policy.approvals import FirestoreApprovals, MemoryApprovals
from warden.policy.engine import Policy
from warden.security.redteam import run_redteam_benchmark
from warden.workflows import (
    FirestoreWorkflowStore,
    MemoryWorkflowStore,
    Workflow,
    WorkflowState,
    WorkflowStore,
)


app = FastAPI(
    title="Warden Operator Control Plane",
    description="Governed control plane for Gemini-powered infrastructure fleets on Google Cloud",
    version="0.1.0",
)
log = logging.getLogger("warden.server")

_cors_origins = [
    origin.strip()
    for origin in os.environ.get(
        "WARDEN_CORS_ORIGINS", "http://localhost:8000,http://127.0.0.1:8000"
    ).split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global runtime instance
_runtime: WardenFleetRuntime | None = None
_workflows: WorkflowStore | None = None
_background_resumes: set[asyncio.Task[object]] = set()
_TEMPLATE_DIR = Path(__file__).parent / "templates"


def get_runtime() -> WardenFleetRuntime:
    global _runtime, _workflows
    if _runtime is None:
        mode = os.environ.get("WARDEN_MODE", "mock")
        manifold_url = os.environ.get("MANIFOLD_API_URL", "http://localhost:8000")
        api_token = os.environ.get("MANIFOLD_API_TOKEN", "")
        # The ledger root is stable across Cloud Run instances. Individual
        # workflows receive their own run IDs below, preventing approval reuse.
        run_id = os.environ.get(
            "WARDEN_LEDGER_ID",
            "warden-control-plane" if mode == "live" else f"service-{uuid4().hex}",
        )
        ledger = None
        approvals = None
        if mode == "live":
            project = os.environ.get("GOOGLE_CLOUD_PROJECT")
            if not project:
                raise RuntimeError("GOOGLE_CLOUD_PROJECT is required when WARDEN_MODE=live")
            ledger = FirestoreLedger(project=project, run_id=run_id)
            approvals = FirestoreApprovals(project=project)
            _workflows = FirestoreWorkflowStore(project=project)
        elif _workflows is None:
            _workflows = MemoryWorkflowStore()
        _runtime = initialize_fleet_runtime(
            mode=mode,
            manifold_url=manifold_url,
            api_token=api_token,
            run_id=run_id,
            ledger=ledger,
            approvals=approvals,
        )
    return _runtime


def set_runtime(runtime: WardenFleetRuntime, workflows: WorkflowStore | None = None) -> None:
    global _runtime, _workflows
    _runtime = runtime
    _workflows = workflows or MemoryWorkflowStore()


def get_workflow_store() -> WorkflowStore:
    get_runtime()
    assert _workflows is not None
    return _workflows


# -- Models --

class DecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    granted: bool = Field(..., description="Whether to grant or deny the approval")
    note: str | None = Field(default=None, description="Optional reasoning or notes")


class RunRequest(BaseModel):
    prompt: str = Field(..., description="Prompt or infrastructure request for the fleet")
    user_id: str = Field(default="operator-01", description="ID of user submitting the request")
    session_id: str = Field(default="default-session", description="Session ID")


@dataclass(frozen=True)
class Operator:
    principal: str
    auth_source: str


async def get_operator(request: Request) -> Operator:
    """Resolve a trusted operator identity; mock mode stays frictionless."""
    if os.environ.get("WARDEN_MODE", "mock") != "live":
        return Operator(request.headers.get("X-Warden-Operator", "local-operator"), "local")

    if os.environ.get("WARDEN_TRUST_IAP_HEADERS") == "true":
        identity = request.headers.get("X-Goog-Authenticated-User-Email", "")
        if identity:
            return Operator(identity.removeprefix("accounts.google.com:"), "iap")

    audience = os.environ.get("WARDEN_SERVICE_URL")
    if not audience:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="WARDEN_SERVICE_URL is not configured")
    try:
        return Operator(await _verified_oidc_principal(request, audience), "cloud_run_oidc")
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid operator identity") from exc


async def _verified_oidc_principal(request: Request, audience: str) -> str:
    """Verify a Google-signed OIDC token and return its stable caller identity."""
    authorization = request.headers.get("Authorization", "")
    if not authorization.startswith("Bearer "):
        raise ValueError("Bearer identity token required")
    from google.auth.transport.requests import Request as GoogleRequest
    from google.oauth2 import id_token

    claims = await asyncio.to_thread(
        id_token.verify_oauth2_token, authorization.removeprefix("Bearer "), GoogleRequest(), audience
    )
    identity = claims.get("email") or claims.get("sub")
    if not identity:
        raise ValueError("identity token has no email or subject")
    return str(identity)


def _ticket_payload(ticket: Any) -> dict[str, Any]:
    return {
        "approval_id": ticket.approval_id,
        "run_id": ticket.run_id,
        "tool": ticket.tool,
        "actor": ticket.actor,
        "reason": ticket.reason,
        "requested_at": ticket.requested_at,
        "status": ticket.status.value,
        "preflight": ticket.preflight,
    }


def _workflow_payload(workflow: Workflow) -> dict[str, Any]:
    payload = asdict(workflow)
    payload["state"] = workflow.state.value
    return payload


async def _run_workflow(workflow_id: str, *, resume: bool = False) -> tuple[Any, Workflow]:
    """Run/re-run a persisted intent and persist its terminal or parked state."""
    workflows = get_workflow_store()
    workflow = await workflows.get(workflow_id)
    if workflow is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Workflow not found")
    if workflow.state in {WorkflowState.COMPLETED, WorkflowState.DENIED, WorkflowState.FAILED}:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Workflow is {workflow.state.value}")

    workflow = await workflows.update(
        workflow_id, state=WorkflowState.RUNNING, increment_resume=resume
    )
    try:
        result = await execute_turn(
            get_runtime(),
            workflow.prompt,
            user_id=workflow.user_id,
            session_id=workflow.session_id,
            run_id=workflow.run_id,
            resume=resume,
        )
    except Exception as exc:
        await workflows.update(workflow_id, state=WorkflowState.FAILED, error=str(exc))
        raise

    if result.pending_approval_ids:
        workflow = await workflows.attach_approvals(workflow_id, result.pending_approval_ids)
    else:
        workflow = await workflows.update(
            workflow_id, state=WorkflowState.COMPLETED, response_text=result.response_text
        )
    return result, workflow


async def _enqueue_resume(workflow_id: str) -> None:
    """Use Cloud Tasks in Cloud Run; keep a useful local async fallback."""
    if _cloud_tasks_configured():
        await _enqueue_cloud_task(workflow_id)
        return

    task = asyncio.create_task(_resume_in_process(workflow_id))
    _background_resumes.add(task)
    task.add_done_callback(_background_resumes.discard)


async def _resume_in_process(workflow_id: str) -> None:
    try:
        await _run_workflow(workflow_id, resume=True)
    except Exception:
        log.exception("in-process workflow resume failed: %s", workflow_id)


def _cloud_tasks_configured() -> bool:
    return all(
        os.environ.get(name)
        for name in ("GOOGLE_CLOUD_PROJECT", "WARDEN_TASK_QUEUE", "WARDEN_SERVICE_URL", "WARDEN_TASK_SERVICE_ACCOUNT")
    )


async def _enqueue_cloud_task(workflow_id: str) -> None:
    """Enqueue an OIDC-authenticated POST to the private Cloud Run worker route."""
    try:
        from google.cloud import tasks_v2
    except ImportError as exc:
        raise RuntimeError("google-cloud-tasks must be installed for Cloud Tasks resume") from exc

    project = os.environ["GOOGLE_CLOUD_PROJECT"]
    location = os.environ.get("WARDEN_TASK_LOCATION", "us-central1")
    queue = os.environ["WARDEN_TASK_QUEUE"]
    service_url = os.environ["WARDEN_SERVICE_URL"].rstrip("/")
    headers = {"Content-Type": "application/json"}
    task = tasks_v2.Task(
        http_request=tasks_v2.HttpRequest(
            http_method=tasks_v2.HttpMethod.POST,
            url=f"{service_url}/internal/workflows/{workflow_id}/resume",
            headers=headers,
            body=json.dumps({"workflow_id": workflow_id}).encode(),
            oidc_token=tasks_v2.OidcToken(
                service_account_email=os.environ["WARDEN_TASK_SERVICE_ACCOUNT"],
                audience=service_url,
            ),
        )
    )
    client = tasks_v2.CloudTasksClient()
    parent = client.queue_path(project, location, queue)
    await asyncio.to_thread(client.create_task, parent=parent, task=task)


# -- Routes --

@app.get("/", response_class=HTMLResponse)
@app.get("/dashboard", response_class=HTMLResponse)
async def serve_dashboard() -> HTMLResponse:
    dashboard_file = _TEMPLATE_DIR / "dashboard.html"
    if dashboard_file.exists():
        return HTMLResponse(content=dashboard_file.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>Warden Operator Control Plane</h1><p>Dashboard template not found.</p>")


@app.get("/health")
async def health_check() -> dict[str, Any]:
    runtime = get_runtime()
    return {
        "status": "healthy",
        "fleet": runtime.policy.fleet,
        "run_id": runtime.run_id,
        "mode": os.environ.get("WARDEN_MODE", "mock"),
        "ledger": type(runtime.ledger).__name__,
        "approval_store": type(runtime.approvals).__name__,
        "workflow_store": type(get_workflow_store()).__name__,
        "resume_transport": "cloud_tasks" if _cloud_tasks_configured() else "in_process",
        "context_cache": runtime.app.context_cache_config.model_dump() if runtime.app else None,
        "subagents": [sa.name for sa in runtime.lead_agent.sub_agents],
    }


@app.get("/policy")
async def get_policy() -> dict[str, Any]:
    runtime = get_runtime()
    return runtime.policy.doc


@app.get("/spend")
async def get_spend() -> dict[str, Any]:
    runtime = get_runtime()
    sp = runtime.plugin.spend
    return {
        "run_usd": sp.run_usd,
        "day_usd": sp.day_usd,
        "live_instances": sp.live_instances,
        "budget_limits": runtime.policy.doc.get("budget", {}),
    }


@app.get("/approvals/pending")
async def list_pending_approvals() -> list[dict[str, Any]]:
    runtime = get_runtime()
    pending = getattr(runtime.approvals, "pending", None)
    if pending is None:
        return []
    workflows = get_workflow_store()
    items: list[dict[str, Any]] = []
    for ticket in await pending():
        item = _ticket_payload(ticket)
        workflow = await workflows.find_by_approval(ticket.approval_id)
        item["workflow_id"] = workflow.workflow_id if workflow else None
        items.append(item)
    return items


@app.post("/approvals/{approval_id}/decide")
async def decide_approval(
    approval_id: str, body: DecisionRequest, operator: Operator = Depends(get_operator)
) -> dict[str, Any]:
    runtime = get_runtime()
    decide = getattr(runtime.approvals, "decide", None)
    if decide is None:
        raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="Approval store does not support direct decision")
    try:
        ticket = await decide(
            approval_id,
            granted=body.granted,
            approver=operator.principal,
            note=body.note,
        )
    except KeyError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Approval ticket not found")
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    workflow = await get_workflow_store().find_by_approval(approval_id)
    if workflow is not None:
        if body.granted:
            await get_workflow_store().update(workflow.workflow_id, state=WorkflowState.QUEUED)
            await _enqueue_resume(workflow.workflow_id)
        else:
            await get_workflow_store().update(workflow.workflow_id, state=WorkflowState.DENIED)
    return {
        "approval_id": ticket.approval_id,
        "status": ticket.status.value,
        "approver": ticket.approver,
        "note": ticket.note,
        "workflow_id": workflow.workflow_id if workflow else None,
        "resume_enqueued": bool(workflow and body.granted),
    }


@app.get("/audit")
async def get_audit_records() -> list[dict[str, Any]]:
    runtime = get_runtime()
    records = await runtime.ledger.read()
    return [r.payload() | {"seq": r.seq, "prev_hash": r.prev_hash, "entry_hash": r.entry_hash} for r in records]


@app.get("/audit/verify")
async def verify_audit_chain() -> dict[str, Any]:
    runtime = get_runtime()
    verdict = await runtime.ledger.verify()
    return {
        "ok": verdict.ok,
        "checked_records": verdict.checked,
        "broken_at": verdict.broken_at,
        "detail": verdict.detail,
    }


@app.post("/fleet/run")
async def run_fleet_turn(body: RunRequest, operator: Operator = Depends(get_operator)) -> dict[str, Any]:
    runtime = get_runtime()
    workflow = await get_workflow_store().create(
        prompt=body.prompt,
        user_id=operator.principal,
        session_id=f"{operator.principal}:{body.session_id}",
        requested_by=operator.principal,
        run_id=f"workflow-{uuid4().hex}",
    )
    result, workflow = await _run_workflow(workflow.workflow_id)
    return {
        "response": result.response_text,
        "events_count": result.events_count,
        "pending_approvals_count": len(result.pending_approvals),
        "audit_records_count": len(result.records),
        "chain_integrity": result.verdict.ok if result.verdict else True,
        "workflow": _workflow_payload(workflow),
    }


@app.get("/workflows/{workflow_id}")
async def get_workflow(workflow_id: str, _: Operator = Depends(get_operator)) -> dict[str, Any]:
    workflow = await get_workflow_store().get(workflow_id)
    if workflow is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Workflow not found")
    return _workflow_payload(workflow)


@app.post("/workflows/{workflow_id}/teardown-plan")
async def create_teardown_plan(
    workflow_id: str, operator: Operator = Depends(get_operator)
) -> dict[str, Any]:
    """Create a separate governed cleanup workflow; this never auto-deletes."""
    source = await get_workflow_store().get(workflow_id)
    if source is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Workflow not found")
    runtime = get_runtime()
    workflow = await get_workflow_store().create(
        prompt=(
            f"Prepare a governed teardown plan for resources associated with Warden workflow {source.workflow_id}. "
            "Inspect current resources first. Do not terminate or delete anything without creating a "
            "new, separately reviewed human approval ticket."
        ),
        user_id=operator.principal,
        session_id=f"{operator.principal}:teardown:{uuid4().hex}",
        requested_by=operator.principal,
        run_id=f"workflow-{uuid4().hex}",
    )
    result, workflow = await _run_workflow(workflow.workflow_id)
    return {
        "response": result.response_text,
        "workflow": _workflow_payload(workflow),
        "message": "Teardown planning started; any destructive step remains separately human-gated.",
    }


@app.post("/internal/workflows/{workflow_id}/resume")
async def resume_workflow(workflow_id: str, request: Request) -> dict[str, Any]:
    """Cloud Tasks target. Cloud Run IAM authenticates task calls in production."""
    if os.environ.get("WARDEN_MODE", "mock") == "live":
        audience = os.environ.get("WARDEN_SERVICE_URL")
        expected_worker = os.environ.get("WARDEN_TASK_SERVICE_ACCOUNT")
        if not audience or not expected_worker:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Cloud Tasks worker identity is not configured",
            )
        try:
            principal = await _verified_oidc_principal(request, audience)
        except Exception as exc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid task identity") from exc
        if principal != expected_worker:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="task worker identity is not authorized")
    result, workflow = await _run_workflow(workflow_id, resume=True)
    return {
        "workflow": _workflow_payload(workflow),
        "events_count": result.events_count,
        "pending_approvals_count": len(result.pending_approval_ids),
    }


@app.get("/redteam/run")
async def execute_redteam_benchmark() -> dict[str, Any]:
    runtime = get_runtime()
    report = await run_redteam_benchmark(runtime)
    return report.to_dict()
