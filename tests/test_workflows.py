"""Durable workflow-state tests independent of a live Gemini credential."""

import asyncio
import pytest

from warden.workflows import MemoryWorkflowStore, WorkflowState


@pytest.mark.asyncio
async def test_workflow_persists_approval_and_resume_state():
    store = MemoryWorkflowStore()
    workflow = await store.create(
        prompt="Launch a governed GPU", user_id="operator@example.com",
        session_id="operator:demo", requested_by="operator@example.com", run_id="run-1",
    )
    assert workflow.state is WorkflowState.RUNNING

    parked = await store.attach_approvals(workflow.workflow_id, ["run-1:launch_gpu:abc"])
    assert parked.state is WorkflowState.WAITING_FOR_APPROVAL
    assert await store.find_by_approval("run-1:launch_gpu:abc") == parked

    queued = await store.update(
        workflow.workflow_id, state=WorkflowState.QUEUED, increment_resume=True
    )
    assert queued.resume_count == 1

    complete = await store.update(
        workflow.workflow_id, state=WorkflowState.COMPLETED, response_text="Launch completed"
    )
    assert complete.response_text == "Launch completed"
    assert complete.state is WorkflowState.COMPLETED


@pytest.mark.asyncio
async def test_resume_claim_is_exactly_once():
    store = MemoryWorkflowStore()
    workflow = await store.create(
        prompt="resume", user_id="operator", session_id="session",
        requested_by="operator", run_id="run-2", model="gemini-3.7-flash",
    )
    assert workflow.model == "gemini-3.7-flash"
    await store.update(workflow.workflow_id, state=WorkflowState.QUEUED)

    results = await asyncio.gather(
        store.claim_resume(workflow.workflow_id),
        store.claim_resume(workflow.workflow_id),
        return_exceptions=True,
    )
    assert sum(not isinstance(result, Exception) for result in results) == 1
    assert sum(isinstance(result, ValueError) for result in results) == 1
    claimed = next(result for result in results if not isinstance(result, Exception))
    assert claimed.state is WorkflowState.RUNNING
    assert claimed.resume_count == 1
