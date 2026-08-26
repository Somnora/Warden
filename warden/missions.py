"""Bounded Mission contracts and reusable human approval envelopes.

A Mission is operator intent plus explicit authority limits.  Its approval
envelope can authorize several in-scope provider calls without turning one
human click into blanket permission: every call is checked transactionally
against tool, placement, lifetime, action-count, run binding, and cost bounds.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Protocol
from uuid import uuid4


ENVELOPE_SUPPORTED_TOOLS: frozenset[str] = frozenset({"launch_gpu", "launch_cluster"})


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _future(minutes: float) -> str:
    return (
        datetime.now(timezone.utc) + timedelta(minutes=minutes)
    ).isoformat(timespec="seconds").replace("+00:00", "Z")


class MissionState(str, Enum):
    DRAFT = "draft"
    APPROVED = "approved"
    RUNNING = "running"
    COMPLETED = "completed"
    DENIED = "denied"
    CANCELLED = "cancelled"
    EXPIRED = "expired"
    STOPPING = "stopping"


class EnvelopeState(str, Enum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"
    EXHAUSTED = "exhausted"


@dataclass(frozen=True)
class MissionContract:
    allowed_tools: tuple[str, ...]
    allowed_providers: tuple[str, ...]
    allowed_regions: tuple[str, ...]
    allowed_machine_types: tuple[str, ...]
    max_cost_usd: float
    max_lifetime_minutes: float
    max_actions: int
    max_instances_per_action: int = 1

    @property
    def digest(self) -> str:
        blob = json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()


@dataclass
class ApprovalEnvelope:
    envelope_id: str
    mission_id: str
    run_id: str
    contract_digest: str
    approved_by: str
    approved_at: str
    expires_at: str
    status: EnvelopeState = EnvelopeState.ACTIVE
    actions_used: int = 0
    reserved_usd: float = 0.0


@dataclass
class MissionEvent:
    event_id: str
    ts: str
    kind: str
    summary: str
    tool: str | None = None
    status: str | None = None
    cost_usd: float | None = None


@dataclass
class MissionArtifact:
    artifact_id: str
    name: str
    kind: str
    source_tool: str
    created_at: str
    uri: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class MissionResource:
    resource_id: str
    resource_type: str
    provider: str
    region: str | None
    status: str
    created_at: str
    expires_at: str | None = None
    cleaned_at: str | None = None


@dataclass
class CleanupReceipt:
    receipt_id: str
    resource_id: str
    resource_type: str
    tool: str
    status: str
    verified_at: str


@dataclass
class Mission:
    mission_id: str
    run_id: str
    objective: str
    created_by: str
    contract: MissionContract
    state: MissionState = MissionState.DRAFT
    model: str = "gemini-3.5-flash"
    envelope: ApprovalEnvelope | None = None
    workflow_ids: list[str] = field(default_factory=list)
    events: list[MissionEvent] = field(default_factory=list)
    artifacts: list[MissionArtifact] = field(default_factory=list)
    resources: list[MissionResource] = field(default_factory=list)
    cleanup_receipts: list[CleanupReceipt] = field(default_factory=list)
    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)


@dataclass(frozen=True)
class EnvelopeAuthorization:
    granted: bool
    reason: str
    envelope_id: str | None = None
    approver: str | None = None
    spend_key: str | None = None


class MissionStore(Protocol):
    async def create(
        self, *, objective: str, created_by: str, contract: MissionContract, model: str
    ) -> Mission: ...
    async def get(self, mission_id: str) -> Mission | None: ...
    async def list(self, *, created_by: str | None = None) -> list[Mission]: ...
    async def approve(
        self, mission_id: str, *, approved_by: str, ttl_minutes: float
    ) -> Mission: ...
    async def authorize(
        self, *, mission_id: str, run_id: str, tool: str,
        args: dict[str, Any], cost_usd: float | None,
    ) -> EnvelopeAuthorization: ...
    async def set_state(self, mission_id: str, state: MissionState) -> Mission: ...
    async def start(self, mission_id: str, workflow_id: str) -> Mission: ...
    async def attach_workflow(self, mission_id: str, workflow_id: str) -> Mission: ...
    async def cancel(self, mission_id: str) -> Mission: ...
    async def stop(self, mission_id: str) -> Mission: ...
    async def record_tool_result(
        self, *, mission_id: str, tool: str, args: dict[str, Any], result: Any
    ) -> Mission: ...


class MemoryMissionStore:
    def __init__(self) -> None:
        self._missions: dict[str, Mission] = {}
        self._lock = asyncio.Lock()

    async def create(
        self, *, objective: str, created_by: str, contract: MissionContract, model: str
    ) -> Mission:
        mission = Mission(
            mission_id=f"mission-{uuid4().hex}", run_id=f"mission-run-{uuid4().hex}",
            objective=objective, created_by=created_by, contract=contract, model=model,
        )
        _append_event(mission, "created", "Mission contract created", status=mission.state.value)
        async with self._lock:
            self._missions[mission.mission_id] = mission
            return _copy_mission(mission)

    async def get(self, mission_id: str) -> Mission | None:
        async with self._lock:
            mission = self._missions.get(mission_id)
            return _copy_mission(mission) if mission else None

    async def list(self, *, created_by: str | None = None) -> list[Mission]:
        async with self._lock:
            missions = [
                _copy_mission(m) for m in self._missions.values()
                if created_by is None or m.created_by == created_by
            ]
        return sorted(missions, key=lambda m: m.created_at, reverse=True)

    async def approve(
        self, mission_id: str, *, approved_by: str, ttl_minutes: float
    ) -> Mission:
        async with self._lock:
            mission = self._require(mission_id)
            if mission.state is not MissionState.DRAFT:
                raise ValueError(f"Mission is {mission.state.value}")
            mission.envelope = _new_envelope(mission, approved_by, ttl_minutes)
            mission.state = MissionState.APPROVED
            _append_event(
                mission, "approved", f"Approval envelope granted by {approved_by}",
                status=mission.state.value,
            )
            mission.updated_at = _now()
            return _copy_mission(mission)

    async def authorize(
        self, *, mission_id: str, run_id: str, tool: str,
        args: dict[str, Any], cost_usd: float | None,
    ) -> EnvelopeAuthorization:
        async with self._lock:
            mission = self._missions.get(mission_id)
            if mission is None:
                return EnvelopeAuthorization(False, "mission does not exist")
            before = _mission_doc(mission)
            result = _authorize(mission, run_id=run_id, tool=tool, args=args, cost_usd=cost_usd)
            if _mission_doc(mission) != before:
                mission.updated_at = _now()
            return result

    async def set_state(self, mission_id: str, state: MissionState) -> Mission:
        async with self._lock:
            mission = self._require(mission_id)
            changed = mission.state is not state
            mission.state = state
            if changed:
                _append_event(
                    mission, "state", f"Mission moved to {state.value}", status=state.value
                )
            mission.updated_at = _now()
            return _copy_mission(mission)

    async def start(self, mission_id: str, workflow_id: str) -> Mission:
        async with self._lock:
            mission = self._require(mission_id)
            if mission.state is not MissionState.APPROVED:
                raise ValueError(f"Mission is {mission.state.value}")
            mission.state = MissionState.RUNNING
            if workflow_id not in mission.workflow_ids:
                mission.workflow_ids.append(workflow_id)
            _append_event(
                mission, "started", "Mission execution started", status=mission.state.value
            )
            mission.updated_at = _now()
            return _copy_mission(mission)

    async def attach_workflow(self, mission_id: str, workflow_id: str) -> Mission:
        async with self._lock:
            mission = self._require(mission_id)
            if workflow_id not in mission.workflow_ids:
                mission.workflow_ids.append(workflow_id)
            mission.updated_at = _now()
            return _copy_mission(mission)

    async def cancel(self, mission_id: str) -> Mission:
        async with self._lock:
            mission = self._require(mission_id)
            if mission.state in {MissionState.COMPLETED, MissionState.DENIED, MissionState.CANCELLED}:
                raise ValueError(f"Mission is {mission.state.value}")
            mission.state = MissionState.CANCELLED
            if mission.envelope:
                mission.envelope.status = EnvelopeState.REVOKED
            _append_event(
                mission, "cancelled", "Unused Mission authority revoked",
                status=mission.state.value,
            )
            mission.updated_at = _now()
            return _copy_mission(mission)

    async def stop(self, mission_id: str) -> Mission:
        async with self._lock:
            mission = self._require(mission_id)
            if mission.state in {MissionState.DENIED, MissionState.CANCELLED, MissionState.EXPIRED}:
                raise ValueError(f"Mission is {mission.state.value}")
            mission.state = MissionState.STOPPING
            if mission.envelope:
                mission.envelope.status = EnvelopeState.REVOKED
            _append_event(
                mission, "emergency_stop",
                "Emergency stop revoked authority; governed cleanup started",
                status=mission.state.value,
            )
            mission.updated_at = _now()
            return _copy_mission(mission)

    async def record_tool_result(
        self, *, mission_id: str, tool: str, args: dict[str, Any], result: Any
    ) -> Mission:
        async with self._lock:
            mission = self._require(mission_id)
            _record_tool_result(mission, tool=tool, args=args, result=result)
            mission.updated_at = _now()
            return _copy_mission(mission)

    def _require(self, mission_id: str) -> Mission:
        mission = self._missions.get(mission_id)
        if mission is None:
            raise KeyError(mission_id)
        return mission


class FirestoreMissionStore:
    """Mission document and envelope counters updated in one transaction."""

    def __init__(self, project: str, *, collection: str = "warden_missions") -> None:
        from google.cloud import firestore

        self._fs = firestore.AsyncClient(project=project)
        self._firestore = firestore
        self._missions = self._fs.collection(collection)

    async def create(
        self, *, objective: str, created_by: str, contract: MissionContract, model: str
    ) -> Mission:
        mission = Mission(
            mission_id=f"mission-{uuid4().hex}", run_id=f"mission-run-{uuid4().hex}",
            objective=objective, created_by=created_by, contract=contract, model=model,
        )
        _append_event(mission, "created", "Mission contract created", status=mission.state.value)
        await self._missions.document(mission.mission_id).set(_mission_doc(mission))
        return mission

    async def get(self, mission_id: str) -> Mission | None:
        snapshot = await self._missions.document(mission_id).get()
        return _mission_from_doc(snapshot.to_dict()) if snapshot.exists else None

    async def list(self, *, created_by: str | None = None) -> list[Mission]:
        query: Any = self._missions
        if created_by is not None:
            query = query.where("created_by", "==", created_by)
        missions = [_mission_from_doc(s.to_dict()) async for s in query.stream()]
        return sorted(missions, key=lambda m: m.created_at, reverse=True)

    async def approve(
        self, mission_id: str, *, approved_by: str, ttl_minutes: float
    ) -> Mission:
        ref = self._missions.document(mission_id)
        transaction = self._fs.transaction()

        @self._firestore.async_transactional
        async def approve_once(txn: Any) -> Mission:
            snapshot = await ref.get(transaction=txn)
            if not snapshot.exists:
                raise KeyError(mission_id)
            mission = _mission_from_doc(snapshot.to_dict())
            if mission.state is not MissionState.DRAFT:
                raise ValueError(f"Mission is {mission.state.value}")
            mission.envelope = _new_envelope(mission, approved_by, ttl_minutes)
            mission.state = MissionState.APPROVED
            _append_event(
                mission, "approved", f"Approval envelope granted by {approved_by}",
                status=mission.state.value,
            )
            mission.updated_at = _now()
            txn.set(ref, _mission_doc(mission))
            return mission

        return await approve_once(transaction)

    async def authorize(
        self, *, mission_id: str, run_id: str, tool: str,
        args: dict[str, Any], cost_usd: float | None,
    ) -> EnvelopeAuthorization:
        ref = self._missions.document(mission_id)
        transaction = self._fs.transaction()

        @self._firestore.async_transactional
        async def reserve_once(txn: Any) -> EnvelopeAuthorization:
            snapshot = await ref.get(transaction=txn)
            if not snapshot.exists:
                return EnvelopeAuthorization(False, "mission does not exist")
            mission = _mission_from_doc(snapshot.to_dict())
            before = _mission_doc(mission)
            result = _authorize(mission, run_id=run_id, tool=tool, args=args, cost_usd=cost_usd)
            if _mission_doc(mission) != before:
                mission.updated_at = _now()
                txn.set(ref, _mission_doc(mission))
            return result

        return await reserve_once(transaction)

    async def set_state(self, mission_id: str, state: MissionState) -> Mission:
        ref = self._missions.document(mission_id)
        transaction = self._fs.transaction()

        @self._firestore.async_transactional
        async def update_once(txn: Any) -> Mission:
            snapshot = await ref.get(transaction=txn)
            if not snapshot.exists:
                raise KeyError(mission_id)
            mission = _mission_from_doc(snapshot.to_dict())
            changed = mission.state is not state
            mission.state = state
            if changed:
                _append_event(
                    mission, "state", f"Mission moved to {state.value}", status=state.value
                )
            mission.updated_at = _now()
            txn.set(ref, _mission_doc(mission))
            return mission

        return await update_once(transaction)

    async def start(self, mission_id: str, workflow_id: str) -> Mission:
        ref = self._missions.document(mission_id)
        transaction = self._fs.transaction()

        @self._firestore.async_transactional
        async def start_once(txn: Any) -> Mission:
            snapshot = await ref.get(transaction=txn)
            if not snapshot.exists:
                raise KeyError(mission_id)
            mission = _mission_from_doc(snapshot.to_dict())
            if mission.state is not MissionState.APPROVED:
                raise ValueError(f"Mission is {mission.state.value}")
            mission.state = MissionState.RUNNING
            if workflow_id not in mission.workflow_ids:
                mission.workflow_ids.append(workflow_id)
            _append_event(
                mission, "started", "Mission execution started", status=mission.state.value
            )
            mission.updated_at = _now()
            txn.set(ref, _mission_doc(mission))
            return mission

        return await start_once(transaction)

    async def attach_workflow(self, mission_id: str, workflow_id: str) -> Mission:
        ref = self._missions.document(mission_id)
        transaction = self._fs.transaction()

        @self._firestore.async_transactional
        async def attach_once(txn: Any) -> Mission:
            snapshot = await ref.get(transaction=txn)
            if not snapshot.exists:
                raise KeyError(mission_id)
            mission = _mission_from_doc(snapshot.to_dict())
            if workflow_id not in mission.workflow_ids:
                mission.workflow_ids.append(workflow_id)
            mission.updated_at = _now()
            txn.set(ref, _mission_doc(mission))
            return mission

        return await attach_once(transaction)

    async def cancel(self, mission_id: str) -> Mission:
        ref = self._missions.document(mission_id)
        transaction = self._fs.transaction()

        @self._firestore.async_transactional
        async def revoke_once(txn: Any) -> Mission:
            snapshot = await ref.get(transaction=txn)
            if not snapshot.exists:
                raise KeyError(mission_id)
            mission = _mission_from_doc(snapshot.to_dict())
            if mission.state in {MissionState.COMPLETED, MissionState.DENIED, MissionState.CANCELLED}:
                raise ValueError(f"Mission is {mission.state.value}")
            mission.state = MissionState.CANCELLED
            if mission.envelope:
                mission.envelope.status = EnvelopeState.REVOKED
            _append_event(
                mission, "cancelled", "Unused Mission authority revoked",
                status=mission.state.value,
            )
            mission.updated_at = _now()
            txn.set(ref, _mission_doc(mission))
            return mission

        return await revoke_once(transaction)

    async def stop(self, mission_id: str) -> Mission:
        ref = self._missions.document(mission_id)
        transaction = self._fs.transaction()

        @self._firestore.async_transactional
        async def stop_once(txn: Any) -> Mission:
            snapshot = await ref.get(transaction=txn)
            if not snapshot.exists:
                raise KeyError(mission_id)
            mission = _mission_from_doc(snapshot.to_dict())
            if mission.state in {MissionState.DENIED, MissionState.CANCELLED, MissionState.EXPIRED}:
                raise ValueError(f"Mission is {mission.state.value}")
            mission.state = MissionState.STOPPING
            if mission.envelope:
                mission.envelope.status = EnvelopeState.REVOKED
            _append_event(
                mission, "emergency_stop",
                "Emergency stop revoked authority; governed cleanup started",
                status=mission.state.value,
            )
            mission.updated_at = _now()
            txn.set(ref, _mission_doc(mission))
            return mission

        return await stop_once(transaction)

    async def record_tool_result(
        self, *, mission_id: str, tool: str, args: dict[str, Any], result: Any
    ) -> Mission:
        ref = self._missions.document(mission_id)
        transaction = self._fs.transaction()

        @self._firestore.async_transactional
        async def record_once(txn: Any) -> Mission:
            snapshot = await ref.get(transaction=txn)
            if not snapshot.exists:
                raise KeyError(mission_id)
            mission = _mission_from_doc(snapshot.to_dict())
            _record_tool_result(mission, tool=tool, args=args, result=result)
            mission.updated_at = _now()
            txn.set(ref, _mission_doc(mission))
            return mission

        return await record_once(transaction)

    async def _must_get(self, mission_id: str) -> Mission:
        mission = await self.get(mission_id)
        if mission is None:
            raise KeyError(mission_id)
        return mission


def _new_envelope(mission: Mission, approved_by: str, ttl_minutes: float) -> ApprovalEnvelope:
    if not math.isfinite(ttl_minutes) or ttl_minutes <= 0:
        raise ValueError("envelope ttl must be a positive number")
    return ApprovalEnvelope(
        envelope_id=f"envelope-{uuid4().hex}", mission_id=mission.mission_id,
        run_id=mission.run_id, contract_digest=mission.contract.digest,
        approved_by=approved_by, approved_at=_now(), expires_at=_future(ttl_minutes),
    )


def _authorize(
    mission: Mission, *, run_id: str, tool: str, args: dict[str, Any], cost_usd: float | None,
) -> EnvelopeAuthorization:
    envelope = mission.envelope
    if envelope is None:
        return EnvelopeAuthorization(False, "mission has no approved envelope")
    base = {"envelope_id": envelope.envelope_id, "approver": envelope.approved_by}
    if mission.state not in {MissionState.APPROVED, MissionState.RUNNING}:
        return EnvelopeAuthorization(False, f"mission is {mission.state.value}", **base)
    if envelope.status is not EnvelopeState.ACTIVE:
        return EnvelopeAuthorization(False, f"envelope is {envelope.status.value}", **base)
    if _expired(envelope.expires_at):
        envelope.status = EnvelopeState.EXPIRED
        mission.state = MissionState.EXPIRED
        return EnvelopeAuthorization(False, "envelope expired", **base)
    if run_id != mission.run_id or envelope.run_id != run_id:
        return EnvelopeAuthorization(False, "envelope is bound to a different run", **base)
    if envelope.contract_digest != mission.contract.digest:
        envelope.status = EnvelopeState.REVOKED
        return EnvelopeAuthorization(False, "mission contract changed after approval", **base)
    if tool not in mission.contract.allowed_tools:
        return EnvelopeAuthorization(False, f"tool '{tool}' is outside the envelope", **base)
    if tool not in ENVELOPE_SUPPORTED_TOOLS:
        return EnvelopeAuthorization(False, f"tool '{tool}' cannot use a reusable envelope", **base)
    scope_error = _scope_error(mission.contract, tool, args)
    if scope_error:
        return EnvelopeAuthorization(False, scope_error, **base)
    cost = 0.0 if cost_usd is None else cost_usd
    if not isinstance(cost, (int, float)) or isinstance(cost, bool) or not math.isfinite(cost) or cost < 0:
        return EnvelopeAuthorization(False, "action has no valid authoritative cost quote", **base)
    if envelope.actions_used >= mission.contract.max_actions:
        envelope.status = EnvelopeState.EXHAUSTED
        return EnvelopeAuthorization(False, "envelope action limit exhausted", **base)
    if envelope.reserved_usd + cost > mission.contract.max_cost_usd:
        return EnvelopeAuthorization(False, "action would exceed the envelope cost ceiling", **base)

    envelope.actions_used += 1
    envelope.reserved_usd = round(envelope.reserved_usd + cost, 4)
    _append_event(
        mission,
        "envelope_action",
        f"{tool} authorized inside Mission envelope",
        tool=tool,
        status="authorized",
        cost_usd=cost,
    )
    if envelope.actions_used >= mission.contract.max_actions:
        envelope.status = EnvelopeState.EXHAUSTED
    return EnvelopeAuthorization(
        True,
        "action is inside the approved Mission envelope",
        spend_key=f"mission-{envelope.envelope_id}-{envelope.actions_used}",
        **base,
    )


def _scope_error(contract: MissionContract, tool: str, args: dict[str, Any]) -> str | None:
    provider = args.get("provider")
    if provider is not None and provider not in contract.allowed_providers:
        return f"provider '{provider}' is outside the envelope"
    region = args.get("region")
    zone = args.get("zone")
    location = region if region is not None else zone
    if location is not None and not any(
        location == allowed or (region is None and str(location).startswith(f"{allowed}-"))
        for allowed in contract.allowed_regions
    ):
        return f"location '{location}' is outside the envelope"
    machine = args.get("machine_type") or args.get("instance_type")
    if machine is not None and machine not in contract.allowed_machine_types:
        return f"machine type '{machine}' is outside the envelope"
    lifetime = args.get("max_lifetime_minutes")
    if lifetime is None and args.get("max_lifetime_seconds") is not None:
        seconds = args.get("max_lifetime_seconds")
        lifetime = seconds / 60 if isinstance(seconds, (int, float)) and not isinstance(seconds, bool) else None
    if not isinstance(lifetime, (int, float)) or isinstance(lifetime, bool) or not math.isfinite(lifetime):
        return "action has no valid lifetime bound"
    if lifetime <= 0 or lifetime > contract.max_lifetime_minutes:
        return "action lifetime is outside the envelope"
    instances = 1 if tool == "launch_gpu" else args.get("node_count", 2)
    if not isinstance(instances, int) or isinstance(instances, bool) or instances <= 0:
        return "action has an invalid instance count"
    if instances > contract.max_instances_per_action:
        return "action instance count is outside the envelope"
    return None


def _expired(value: str) -> bool:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return True
    return parsed.tzinfo is None or datetime.now(timezone.utc) >= parsed


def _append_event(
    mission: Mission,
    kind: str,
    summary: str,
    *,
    tool: str | None = None,
    status: str | None = None,
    cost_usd: float | None = None,
) -> None:
    mission.events.append(
        MissionEvent(
            event_id=f"event-{uuid4().hex}", ts=_now(), kind=kind,
            summary=summary[:300], tool=tool, status=status, cost_usd=cost_usd,
        )
    )
    mission.events[:] = mission.events[-200:]


def _record_tool_result(
    mission: Mission, *, tool: str, args: dict[str, Any], result: Any
) -> None:
    """Persist only allowlisted operational metadata, never raw tool output."""
    data = result if isinstance(result, dict) else {}
    result_status = str(data.get("status") or data.get("phase") or "completed")[:80]
    _append_event(
        mission, "tool_result", f"{tool} returned {result_status}",
        tool=tool, status=result_status,
    )

    if tool in {"launch_gpu", "launch_cluster"}:
        resource_type = "instance" if tool == "launch_gpu" else "cluster"
        resource_id = _first_string(
            data, "instance_id", "cluster_id", "id", "launch_id"
        )
        if resource_id:
            existing = next(
                (resource for resource in mission.resources if resource.resource_id == resource_id),
                None,
            )
            if existing is None:
                mission.resources.append(
                    MissionResource(
                        resource_id=resource_id,
                        resource_type=resource_type,
                        provider=str(args.get("provider") or "gcp")[:80],
                        region=_optional_string(args.get("region") or args.get("zone")),
                        status=result_status,
                        created_at=_now(),
                        expires_at=_resource_expiry(args),
                    )
                )
            else:
                existing.status = result_status
        mission.resources[:] = mission.resources[-100:]

    if tool in {"sync_outputs", "download_file"}:
        source = _optional_string(args.get("instance_id")) or "mission"
        uri = _first_string(data, "uri", "url", "path", "local_path", "destination")
        metadata: dict[str, Any] = {}
        files_copied = data.get("files_copied")
        if isinstance(files_copied, int) and not isinstance(files_copied, bool):
            metadata["files_copied"] = files_copied
        mission.artifacts.append(
            MissionArtifact(
                artifact_id=f"artifact-{uuid4().hex}",
                name=(
                    str(data.get("name") or data.get("filename"))[:160]
                    if data.get("name") or data.get("filename")
                    else f"Outputs from {source}"
                ),
                kind="download" if tool == "download_file" else "output_bundle",
                source_tool=tool,
                created_at=_now(),
                uri=uri,
                metadata=metadata,
            )
        )
        mission.artifacts[:] = mission.artifacts[-100:]

    if tool in {"terminate_instance", "terminate_cluster"}:
        resource_type = "instance" if tool == "terminate_instance" else "cluster"
        argument_key = "instance_id" if resource_type == "instance" else "cluster_id"
        resource_id = _optional_string(args.get(argument_key)) or _first_string(
            data, argument_key, "id"
        )
        if resource_id:
            normalized = result_status.lower()
            verified = normalized in {
                "terminated", "deleted", "not_found", "not found", "absent", "completed", "success"
            }
            verified_at = _now()
            resource = next(
                (item for item in mission.resources if item.resource_id == resource_id), None
            )
            if resource:
                resource.status = "cleaned" if verified else result_status
                resource.cleaned_at = verified_at if verified else None
            mission.cleanup_receipts.append(
                CleanupReceipt(
                    receipt_id=f"cleanup-{uuid4().hex}", resource_id=resource_id,
                    resource_type=resource_type, tool=tool,
                    status="verified_absent" if verified else "unverified",
                    verified_at=verified_at,
                )
            )
            mission.cleanup_receipts[:] = mission.cleanup_receipts[-100:]
            _append_event(
                mission, "cleanup_receipt",
                f"Cleanup {'verified' if verified else 'could not be verified'} for {resource_id}",
                tool=tool, status="verified" if verified else "unverified",
            )


def _first_string(data: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = _optional_string(data.get(key))
        if value:
            return value
    return None


def _optional_string(value: Any) -> str | None:
    return str(value)[:500] if isinstance(value, (str, int)) and not isinstance(value, bool) else None


def _resource_expiry(args: dict[str, Any]) -> str | None:
    minutes = args.get("max_lifetime_minutes")
    if minutes is None and args.get("max_lifetime_seconds") is not None:
        seconds = args.get("max_lifetime_seconds")
        minutes = seconds / 60 if isinstance(seconds, (int, float)) and not isinstance(seconds, bool) else None
    if not isinstance(minutes, (int, float)) or isinstance(minutes, bool) or not math.isfinite(minutes):
        return None
    return _future(float(minutes))


def _mission_doc(mission: Mission) -> dict[str, Any]:
    data = asdict(mission)
    data["state"] = mission.state.value
    if mission.envelope:
        data["envelope"]["status"] = mission.envelope.status.value
    return data


def _mission_from_doc(data: dict[str, Any] | None) -> Mission:
    if not data:
        raise ValueError("mission document is empty")
    value = dict(data)
    value["state"] = MissionState(value["state"])
    contract = dict(value["contract"])
    for key in (
        "allowed_tools", "allowed_providers", "allowed_regions", "allowed_machine_types"
    ):
        contract[key] = tuple(contract[key])
    value["contract"] = MissionContract(**contract)
    if value.get("envelope"):
        envelope = dict(value["envelope"])
        envelope["status"] = EnvelopeState(envelope["status"])
        value["envelope"] = ApprovalEnvelope(**envelope)
    value.setdefault("workflow_ids", [])
    value["events"] = [MissionEvent(**event) for event in value.get("events", [])]
    value["artifacts"] = [MissionArtifact(**artifact) for artifact in value.get("artifacts", [])]
    value["resources"] = [MissionResource(**resource) for resource in value.get("resources", [])]
    value["cleanup_receipts"] = [
        CleanupReceipt(**receipt) for receipt in value.get("cleanup_receipts", [])
    ]
    return Mission(**value)


def _copy_mission(mission: Mission) -> Mission:
    return _mission_from_doc(_mission_doc(mission))
