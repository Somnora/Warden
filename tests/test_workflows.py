"""Durable workflow-state tests independent of a live Gemini credential."""

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
