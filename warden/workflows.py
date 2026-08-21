"""Durable workflow state for asynchronous, human-gated fleet runs."""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Protocol
from uuid import uuid4


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class WorkflowState(str, Enum):
    RUNNING = "running"
    WAITING_FOR_APPROVAL = "waiting_for_approval"
    QUEUED = "queued"
    COMPLETED = "completed"
    DENIED = "denied"
    FAILED = "failed"


@dataclass
class Workflow:
    workflow_id: str
    prompt: str
    user_id: str
    session_id: str
    requested_by: str
    run_id: str
    state: WorkflowState = WorkflowState.RUNNING
    approval_ids: list[str] = field(default_factory=list)
    resume_count: int = 0
    response_text: str = ""
    error: str | None = None
    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)


class WorkflowStore(Protocol):
    async def create(
        self, *, prompt: str, user_id: str, session_id: str, requested_by: str, run_id: str
    ) -> Workflow: ...
    async def get(self, workflow_id: str) -> Workflow | None: ...
    async def attach_approvals(self, workflow_id: str, approval_ids: list[str]) -> Workflow: ...
    async def find_by_approval(self, approval_id: str) -> Workflow | None: ...
    async def update(
        self,
        workflow_id: str,
        *,
        state: WorkflowState,
        response_text: str | None = None,
        error: str | None = None,
        increment_resume: bool = False,
    ) -> Workflow: ...


class MemoryWorkflowStore:
    """Durable-workflow API backed by memory for the local demo and tests."""

    def __init__(self) -> None:
        self._workflows: dict[str, Workflow] = {}
        self._lock = asyncio.Lock()

    async def create(
        self, *, prompt: str, user_id: str, session_id: str, requested_by: str, run_id: str
    ) -> Workflow:
        workflow = Workflow(
            workflow_id=f"wf-{uuid4().hex}", prompt=prompt, user_id=user_id,
            session_id=session_id, requested_by=requested_by, run_id=run_id,
        )
        async with self._lock:
            self._workflows[workflow.workflow_id] = workflow
        return workflow

    async def get(self, workflow_id: str) -> Workflow | None:
        async with self._lock:
            return self._copy(self._workflows.get(workflow_id))

    async def attach_approvals(self, workflow_id: str, approval_ids: list[str]) -> Workflow:
        async with self._lock:
            workflow = self._require(workflow_id)
            workflow.approval_ids = list(dict.fromkeys(workflow.approval_ids + approval_ids))
            workflow.state = WorkflowState.WAITING_FOR_APPROVAL
            workflow.updated_at = _now()
            return self._copy(workflow)

    async def find_by_approval(self, approval_id: str) -> Workflow | None:
        async with self._lock:
            for workflow in self._workflows.values():
                if approval_id in workflow.approval_ids:
                    return self._copy(workflow)
        return None

    async def update(
        self,
        workflow_id: str,
        *,
        state: WorkflowState,
        response_text: str | None = None,
        error: str | None = None,
        increment_resume: bool = False,
    ) -> Workflow:
        async with self._lock:
            workflow = self._require(workflow_id)
            workflow.state = state
            if response_text is not None:
                workflow.response_text = response_text
            workflow.error = error
            if increment_resume:
                workflow.resume_count += 1
            workflow.updated_at = _now()
            return self._copy(workflow)

    def _require(self, workflow_id: str) -> Workflow:
        workflow = self._workflows.get(workflow_id)
        if workflow is None:
            raise KeyError(workflow_id)
        return workflow

    @staticmethod
    def _copy(workflow: Workflow | None) -> Workflow | None:
        return Workflow(**asdict(workflow)) if workflow else None


class FirestoreWorkflowStore:
    """Firestore-backed workflow state shared across Cloud Run instances."""

    def __init__(self, project: str, *, collection: str = "warden_workflows") -> None:
        from google.cloud import firestore

        self._fs = firestore.AsyncClient(project=project)
        self._firestore = firestore
        self._workflows = self._fs.collection(collection)

    async def create(
        self, *, prompt: str, user_id: str, session_id: str, requested_by: str, run_id: str
    ) -> Workflow:
        workflow = Workflow(
            workflow_id=f"wf-{uuid4().hex}", prompt=prompt, user_id=user_id,
            session_id=session_id, requested_by=requested_by, run_id=run_id,
        )
        await self._workflows.document(workflow.workflow_id).set(_workflow_doc(workflow))
        return workflow

    async def get(self, workflow_id: str) -> Workflow | None:
        snapshot = await self._workflows.document(workflow_id).get()
        return _workflow_from_doc(snapshot.to_dict()) if snapshot.exists else None

    async def attach_approvals(self, workflow_id: str, approval_ids: list[str]) -> Workflow:
        workflow = await self._must_get(workflow_id)
        workflow.approval_ids = list(dict.fromkeys(workflow.approval_ids + approval_ids))
        workflow.state = WorkflowState.WAITING_FOR_APPROVAL
        workflow.updated_at = _now()
        await self._workflows.document(workflow_id).set(_workflow_doc(workflow))
        return workflow

    async def find_by_approval(self, approval_id: str) -> Workflow | None:
        query = self._workflows.where("approval_ids", "array_contains", approval_id).limit(1)
        async for snapshot in query.stream():
            return _workflow_from_doc(snapshot.to_dict())
        return None

    async def update(
        self,
        workflow_id: str,
        *,
        state: WorkflowState,
        response_text: str | None = None,
        error: str | None = None,
        increment_resume: bool = False,
    ) -> Workflow:
        workflow = await self._must_get(workflow_id)
        workflow.state = state
        if response_text is not None:
            workflow.response_text = response_text
        workflow.error = error
        if increment_resume:
            workflow.resume_count += 1
        workflow.updated_at = _now()
        await self._workflows.document(workflow_id).set(_workflow_doc(workflow))
        return workflow

    async def _must_get(self, workflow_id: str) -> Workflow:
        workflow = await self.get(workflow_id)
        if workflow is None:
            raise KeyError(workflow_id)
        return workflow


def _workflow_doc(workflow: Workflow) -> dict[str, Any]:
    data = asdict(workflow)
    data["state"] = workflow.state.value
    return data


def _workflow_from_doc(data: dict[str, Any] | None) -> Workflow:
    if not data:
        raise ValueError("workflow document is empty")
    value = dict(data)
    value["state"] = WorkflowState(value["state"])
    return Workflow(**value)
