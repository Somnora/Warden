"""Distributed, idempotent spend reservations for governed provider actions.

The policy engine remains the readable first-line evaluator. This module is
the authoritative second line: it atomically reserves cost and live capacity
across every Cloud Run instance before a provider call may begin.
"""

from __future__ import annotations

import asyncio
import hashlib
import math
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Protocol

from warden.policy.engine import SpendSnapshot


class SpendControlError(RuntimeError):
    """A reservation cannot be safely created or reconciled."""


class ReservationStatus(str, Enum):
    RESERVED = "reserved"
    SETTLED = "settled"
    UNCERTAIN = "uncertain"
    RELEASED = "released"


@dataclass(frozen=True)
class SpendLimits:
    max_usd_per_run: float | None = None
    max_usd_per_day: float | None = None
    max_concurrent_instances: int | None = None


@dataclass
class SpendReservation:
    reservation_id: str
    idempotency_key: str
    run_id: str
    cost_usd: float
    instances: int
    status: ReservationStatus
    created_at: str
    resource_ids: list[str]
    reason: str | None = None


@dataclass(frozen=True)
class SpendSummary:
    run_usd: float = 0.0
    day_usd: float = 0.0
    live_instances: int = 0
    reserved_usd: float = 0.0
    settled_usd: float = 0.0
    uncertain_usd: float = 0.0

    @property
    def snapshot(self) -> SpendSnapshot:
        return SpendSnapshot(
            run_usd=self.run_usd, day_usd=self.day_usd, live_instances=self.live_instances
        )


class SpendStore(Protocol):
    async def summary(self, run_id: str) -> SpendSummary: ...
    async def aggregate(self) -> SpendSummary: ...
    async def reserve(
        self, *, idempotency_key: str, run_id: str, cost_usd: float,
        instances: int, limits: SpendLimits,
    ) -> tuple[SpendReservation, SpendSummary]: ...
    async def settle(self, reservation_id: str, *, resource_ids: list[str]) -> SpendSummary: ...
    async def release(
        self, reservation_id: str, *, reason: str, release_cost: bool,
    ) -> SpendSummary: ...
    async def release_resource(self, resource_id: str, *, reason: str) -> SpendSummary | None: ...
    async def mark_uncertain(self, reservation_id: str, *, reason: str) -> SpendSummary: ...


def reservation_key(run_id: str, actor: str, tool: str, args_digest: str) -> str:
    """Stable key: transport retries cannot reserve the same action twice."""
    material = "".join(f"{len(value)}:{value}" for value in (run_id, actor, tool, args_digest))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _day() -> str:
    return datetime.now(timezone.utc).date().isoformat()


def _validate_request(cost_usd: float, instances: int, limits: SpendLimits) -> None:
    if not isinstance(cost_usd, (int, float)) or isinstance(cost_usd, bool) or not math.isfinite(cost_usd) or cost_usd < 0:
        raise SpendControlError("reservation cost must be a finite non-negative number")
    if not isinstance(instances, int) or isinstance(instances, bool) or instances < 0:
        raise SpendControlError("reservation instances must be a non-negative integer")
    for name, value in asdict(limits).items():
        if value is None:
            continue
        if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value) or value < 0:
            raise SpendControlError(f"{name} must be a finite non-negative number")


def _empty_totals() -> dict[str, Any]:
    return {
        "day_key": _day(), "day_usd": 0.0, "live_instances": 0,
        "reserved_usd": 0.0, "settled_usd": 0.0, "uncertain_usd": 0.0,
    }


def _empty_run() -> dict[str, float]:
    return {"run_usd": 0.0, "reserved_usd": 0.0, "settled_usd": 0.0, "uncertain_usd": 0.0}


def _reset_day_if_needed(totals: dict[str, Any]) -> None:
    if totals.get("day_key") != _day():
        totals["day_key"] = _day()
        totals["day_usd"] = 0.0


def _summary(totals: dict[str, Any], run: dict[str, Any]) -> SpendSummary:
    return SpendSummary(
        run_usd=float(run.get("run_usd", 0.0)),
        day_usd=float(totals.get("day_usd", 0.0)),
        live_instances=int(totals.get("live_instances", 0)),
        reserved_usd=float(run.get("reserved_usd", 0.0)),
        settled_usd=float(run.get("settled_usd", 0.0)),
        uncertain_usd=float(run.get("uncertain_usd", 0.0)),
    )


class MemorySpendStore:
    """Lock-protected equivalent of Firestore spend transactions for tests/demo."""

    def __init__(self) -> None:
        self._totals = _empty_totals()
        self._runs: dict[str, dict[str, float]] = {}
        self._reservations: dict[str, SpendReservation] = {}
        self._resource_index: dict[str, str] = {}
        self._lock = asyncio.Lock()

    async def summary(self, run_id: str) -> SpendSummary:
        async with self._lock:
            _reset_day_if_needed(self._totals)
            return _summary(self._totals, self._runs.get(run_id, _empty_run()))

    async def aggregate(self) -> SpendSummary:
        """Return control-plane totals across every workflow run."""
        async with self._lock:
            _reset_day_if_needed(self._totals)
            return SpendSummary(
                run_usd=float(self._totals.get("day_usd", 0.0)),
                day_usd=float(self._totals.get("day_usd", 0.0)),
                live_instances=int(self._totals.get("live_instances", 0)),
                reserved_usd=float(self._totals.get("reserved_usd", 0.0)),
                settled_usd=float(self._totals.get("settled_usd", 0.0)),
                uncertain_usd=float(self._totals.get("uncertain_usd", 0.0)),
            )

    async def reserve(
        self, *, idempotency_key: str, run_id: str, cost_usd: float,
        instances: int, limits: SpendLimits,
    ) -> tuple[SpendReservation, SpendSummary]:
        _validate_request(cost_usd, instances, limits)
        async with self._lock:
            _reset_day_if_needed(self._totals)
            existing = self._reservations.get(idempotency_key)
            if existing:
                if existing.run_id != run_id or existing.cost_usd != cost_usd or existing.instances != instances:
                    raise SpendControlError("idempotency key does not match its original reservation")
                if existing.status is ReservationStatus.RELEASED:
                    raise SpendControlError("previous reservation was released; a new approval is required")
                if existing.status is ReservationStatus.UNCERTAIN:
                    raise SpendControlError(
                        "previous provider outcome is uncertain; reconcile it before retrying"
                    )
                return _copy_reservation(existing), _summary(self._totals, self._runs.get(run_id, _empty_run()))
            run = self._runs.setdefault(run_id, _empty_run())
            _enforce_limits(self._totals, run, cost_usd, instances, limits)
            reservation = SpendReservation(
                reservation_id=f"spend-{idempotency_key}", idempotency_key=idempotency_key,
                run_id=run_id, cost_usd=round(cost_usd, 4), instances=instances,
                status=ReservationStatus.RESERVED, created_at=_now(), resource_ids=[],
            )
            self._reservations[idempotency_key] = reservation
            _apply_reserve(self._totals, run, reservation)
            return _copy_reservation(reservation), _summary(self._totals, run)

    async def settle(self, reservation_id: str, *, resource_ids: list[str]) -> SpendSummary:
        async with self._lock:
            reservation = self._require(reservation_id)
            run = self._runs[reservation.run_id]
            if reservation.status is ReservationStatus.RELEASED:
                raise SpendControlError("released reservation cannot be settled")
            clean_ids = _clean_resource_ids(resource_ids)
            for resource_id in clean_ids:
                self._resource_index[resource_id] = reservation.idempotency_key
            reservation.resource_ids = list(dict.fromkeys(reservation.resource_ids + clean_ids))
            if reservation.status is ReservationStatus.RESERVED:
                reservation.status = ReservationStatus.SETTLED
                run["reserved_usd"] -= reservation.cost_usd
                run["settled_usd"] += reservation.cost_usd
                self._totals["reserved_usd"] -= reservation.cost_usd
                self._totals["settled_usd"] += reservation.cost_usd
            return _summary(self._totals, run)

    async def release(self, reservation_id: str, *, reason: str, release_cost: bool) -> SpendSummary:
        async with self._lock:
            reservation = self._require(reservation_id)
            run = self._runs[reservation.run_id]
            if reservation.status is ReservationStatus.RELEASED:
                return _summary(self._totals, run)
            _apply_release(self._totals, run, reservation, release_cost)
            reservation.status = ReservationStatus.RELEASED
            reservation.reason = reason[:500]
            return _summary(self._totals, run)

    async def release_resource(self, resource_id: str, *, reason: str) -> SpendSummary | None:
        async with self._lock:
            key = self._resource_index.get(resource_id)
            if not key:
                return None
            reservation = self._reservations[key]
            run = self._runs[reservation.run_id]
            if reservation.status is ReservationStatus.RELEASED:
                return _summary(self._totals, run)
            _apply_release(self._totals, run, reservation, release_cost=False)
            reservation.status = ReservationStatus.RELEASED
            reservation.reason = reason[:500]
            return _summary(self._totals, run)

    async def mark_uncertain(self, reservation_id: str, *, reason: str) -> SpendSummary:
        async with self._lock:
            reservation = self._require(reservation_id)
            run = self._runs[reservation.run_id]
            if reservation.status is ReservationStatus.RESERVED:
                reservation.status = ReservationStatus.UNCERTAIN
                run["reserved_usd"] -= reservation.cost_usd
                run["uncertain_usd"] += reservation.cost_usd
                self._totals["reserved_usd"] -= reservation.cost_usd
                self._totals["uncertain_usd"] += reservation.cost_usd
            reservation.reason = reason[:500]
            return _summary(self._totals, run)

    def _require(self, reservation_id: str) -> SpendReservation:
        key = reservation_id.removeprefix("spend-")
        reservation = self._reservations.get(key)
        if reservation is None:
            raise SpendControlError("spend reservation does not exist")
        return reservation


class FirestoreSpendStore:
    """Firestore transactions shared by every control-plane instance."""

    def __init__(self, project: str, *, collection: str = "warden_spend", namespace: str = "control-plane") -> None:
        from google.cloud import firestore

        self._fs = firestore.AsyncClient(project=project)
        self._firestore = firestore
        self._root = self._fs.collection(collection).document(namespace)
        self._reservations = self._root.collection("reservations")
        self._runs = self._root.collection("runs")
        self._resources = self._root.collection("resources")

    async def summary(self, run_id: str) -> SpendSummary:
        totals_snapshot, run_snapshot = await asyncio.gather(
            self._root.get(), self._runs.document(_run_doc_id(run_id)).get()
        )
        totals = dict(totals_snapshot.to_dict() or _empty_totals())
        _reset_day_if_needed(totals)
        return _summary(totals, dict(run_snapshot.to_dict() or _empty_run()))

    async def aggregate(self) -> SpendSummary:
        """Return transactionally maintained totals across every workflow run."""
        snapshot = await self._root.get()
        totals = dict(snapshot.to_dict() or _empty_totals())
        _reset_day_if_needed(totals)
        return SpendSummary(
            run_usd=float(totals.get("day_usd", 0.0)),
            day_usd=float(totals.get("day_usd", 0.0)),
            live_instances=int(totals.get("live_instances", 0)),
            reserved_usd=float(totals.get("reserved_usd", 0.0)),
            settled_usd=float(totals.get("settled_usd", 0.0)),
            uncertain_usd=float(totals.get("uncertain_usd", 0.0)),
        )

    async def reserve(
        self, *, idempotency_key: str, run_id: str, cost_usd: float,
        instances: int, limits: SpendLimits,
    ) -> tuple[SpendReservation, SpendSummary]:
        _validate_request(cost_usd, instances, limits)
        reservation_ref = self._reservations.document(idempotency_key)
        run_ref = self._runs.document(_run_doc_id(run_id))
        transaction = self._fs.transaction()

        @self._firestore.async_transactional
        async def reserve_once(txn: Any) -> tuple[SpendReservation, SpendSummary]:
            total_snapshot = await self._root.get(transaction=txn)
            run_snapshot = await run_ref.get(transaction=txn)
            existing_snapshot = await reservation_ref.get(transaction=txn)
            totals = dict(total_snapshot.to_dict() or _empty_totals())
            run = dict(run_snapshot.to_dict() or _empty_run())
            _reset_day_if_needed(totals)
            if existing_snapshot.exists:
                existing = _reservation_from_doc(existing_snapshot.to_dict())
                if existing.run_id != run_id or existing.cost_usd != round(cost_usd, 4) or existing.instances != instances:
                    raise SpendControlError("idempotency key does not match its original reservation")
                if existing.status is ReservationStatus.RELEASED:
                    raise SpendControlError("previous reservation was released; a new approval is required")
                if existing.status is ReservationStatus.UNCERTAIN:
                    raise SpendControlError(
                        "previous provider outcome is uncertain; reconcile it before retrying"
                    )
                return existing, _summary(totals, run)
            _enforce_limits(totals, run, cost_usd, instances, limits)
            reservation = SpendReservation(
                reservation_id=f"spend-{idempotency_key}", idempotency_key=idempotency_key,
                run_id=run_id, cost_usd=round(cost_usd, 4), instances=instances,
                status=ReservationStatus.RESERVED, created_at=_now(), resource_ids=[],
            )
            _apply_reserve(totals, run, reservation)
            txn.set(self._root, totals, merge=True)
            txn.set(run_ref, run, merge=True)
            txn.set(reservation_ref, _reservation_doc(reservation))
            return reservation, _summary(totals, run)

        return await reserve_once(transaction)

    async def settle(self, reservation_id: str, *, resource_ids: list[str]) -> SpendSummary:
        key = _reservation_key_from_id(reservation_id)
        reservation_ref = self._reservations.document(key)
        transaction = self._fs.transaction()

        @self._firestore.async_transactional
        async def settle_once(txn: Any) -> SpendSummary:
            reservation_snapshot = await reservation_ref.get(transaction=txn)
            if not reservation_snapshot.exists:
                raise SpendControlError("spend reservation does not exist")
            reservation = _reservation_from_doc(reservation_snapshot.to_dict())
            run_ref = self._runs.document(_run_doc_id(reservation.run_id))
            total_snapshot = await self._root.get(transaction=txn)
            run_snapshot = await run_ref.get(transaction=txn)
            totals = dict(total_snapshot.to_dict() or _empty_totals())
            run = dict(run_snapshot.to_dict() or _empty_run())
            _reset_day_if_needed(totals)
            if reservation.status is ReservationStatus.RELEASED:
                raise SpendControlError("released reservation cannot be settled")
            clean_ids = _clean_resource_ids(resource_ids)
            reservation.resource_ids = list(dict.fromkeys(reservation.resource_ids + clean_ids))
            if reservation.status is ReservationStatus.RESERVED:
                reservation.status = ReservationStatus.SETTLED
                run["reserved_usd"] -= reservation.cost_usd
                run["settled_usd"] += reservation.cost_usd
                totals["reserved_usd"] -= reservation.cost_usd
                totals["settled_usd"] += reservation.cost_usd
            txn.set(self._root, totals, merge=True)
            txn.set(run_ref, run, merge=True)
            txn.set(reservation_ref, _reservation_doc(reservation))
            for resource_id in clean_ids:
                txn.set(self._resources.document(_resource_doc_id(resource_id)), {"reservation_key": key})
            return _summary(totals, run)

        return await settle_once(transaction)

    async def release(self, reservation_id: str, *, reason: str, release_cost: bool) -> SpendSummary:
        key = _reservation_key_from_id(reservation_id)
        return await self._release_key(key, reason=reason, release_cost=release_cost)

    async def release_resource(self, resource_id: str, *, reason: str) -> SpendSummary | None:
        index = await self._resources.document(_resource_doc_id(resource_id)).get()
        if not index.exists:
            return None
        key = (index.to_dict() or {}).get("reservation_key")
        if not isinstance(key, str):
            raise SpendControlError("resource spend index is malformed")
        return await self._release_key(key, reason=reason, release_cost=False)

    async def mark_uncertain(self, reservation_id: str, *, reason: str) -> SpendSummary:
        key = _reservation_key_from_id(reservation_id)
        reservation_ref = self._reservations.document(key)
        transaction = self._fs.transaction()

        @self._firestore.async_transactional
        async def uncertain_once(txn: Any) -> SpendSummary:
            reservation_snapshot = await reservation_ref.get(transaction=txn)
            if not reservation_snapshot.exists:
                raise SpendControlError("spend reservation does not exist")
            reservation = _reservation_from_doc(reservation_snapshot.to_dict())
            run_ref = self._runs.document(_run_doc_id(reservation.run_id))
            total_snapshot = await self._root.get(transaction=txn)
            run_snapshot = await run_ref.get(transaction=txn)
            totals = dict(total_snapshot.to_dict() or _empty_totals())
            run = dict(run_snapshot.to_dict() or _empty_run())
            _reset_day_if_needed(totals)
            if reservation.status is ReservationStatus.RESERVED:
                reservation.status = ReservationStatus.UNCERTAIN
                run["reserved_usd"] -= reservation.cost_usd
                run["uncertain_usd"] += reservation.cost_usd
                totals["reserved_usd"] -= reservation.cost_usd
                totals["uncertain_usd"] += reservation.cost_usd
            reservation.reason = reason[:500]
            txn.set(self._root, totals, merge=True)
            txn.set(run_ref, run, merge=True)
            txn.set(reservation_ref, _reservation_doc(reservation))
            return _summary(totals, run)

        return await uncertain_once(transaction)

    async def _release_key(self, key: str, *, reason: str, release_cost: bool) -> SpendSummary:
        reservation_ref = self._reservations.document(key)
        transaction = self._fs.transaction()

        @self._firestore.async_transactional
        async def release_once(txn: Any) -> SpendSummary:
            reservation_snapshot = await reservation_ref.get(transaction=txn)
            if not reservation_snapshot.exists:
                raise SpendControlError("spend reservation does not exist")
            reservation = _reservation_from_doc(reservation_snapshot.to_dict())
            run_ref = self._runs.document(_run_doc_id(reservation.run_id))
            total_snapshot = await self._root.get(transaction=txn)
            run_snapshot = await run_ref.get(transaction=txn)
            totals = dict(total_snapshot.to_dict() or _empty_totals())
            run = dict(run_snapshot.to_dict() or _empty_run())
            _reset_day_if_needed(totals)
            if reservation.status is not ReservationStatus.RELEASED:
                _apply_release(totals, run, reservation, release_cost)
                reservation.status = ReservationStatus.RELEASED
                reservation.reason = reason[:500]
                txn.set(self._root, totals, merge=True)
                txn.set(run_ref, run, merge=True)
                txn.set(reservation_ref, _reservation_doc(reservation))
            return _summary(totals, run)

        return await release_once(transaction)


def _enforce_limits(
    totals: dict[str, Any], run: dict[str, Any], cost_usd: float, instances: int, limits: SpendLimits
) -> None:
    if limits.max_usd_per_run is not None and float(run["run_usd"]) + cost_usd > limits.max_usd_per_run:
        raise SpendControlError("reservation would exceed the run spending ceiling")
    if limits.max_usd_per_day is not None and float(totals["day_usd"]) + cost_usd > limits.max_usd_per_day:
        raise SpendControlError("reservation would exceed the daily spending ceiling")
    if limits.max_concurrent_instances is not None and int(totals["live_instances"]) + instances > limits.max_concurrent_instances:
        raise SpendControlError("reservation would exceed the concurrent-instance ceiling")


def _apply_reserve(totals: dict[str, Any], run: dict[str, Any], reservation: SpendReservation) -> None:
    totals["day_usd"] = round(float(totals["day_usd"]) + reservation.cost_usd, 4)
    totals["live_instances"] = int(totals["live_instances"]) + reservation.instances
    totals["reserved_usd"] = round(float(totals["reserved_usd"]) + reservation.cost_usd, 4)
    run["run_usd"] = round(float(run["run_usd"]) + reservation.cost_usd, 4)
    run["reserved_usd"] = round(float(run["reserved_usd"]) + reservation.cost_usd, 4)


def _apply_release(
    totals: dict[str, Any], run: dict[str, Any], reservation: SpendReservation, release_cost: bool
) -> None:
    totals["live_instances"] = max(0, int(totals["live_instances"]) - reservation.instances)
    if not release_cost:
        return
    totals["day_usd"] = round(max(0.0, float(totals["day_usd"]) - reservation.cost_usd), 4)
    run["run_usd"] = round(max(0.0, float(run["run_usd"]) - reservation.cost_usd), 4)
    bucket = "settled_usd" if reservation.status is ReservationStatus.SETTLED else (
        "uncertain_usd" if reservation.status is ReservationStatus.UNCERTAIN else "reserved_usd"
    )
    totals[bucket] = round(max(0.0, float(totals[bucket]) - reservation.cost_usd), 4)
    run[bucket] = round(max(0.0, float(run[bucket]) - reservation.cost_usd), 4)


def _copy_reservation(reservation: SpendReservation) -> SpendReservation:
    return SpendReservation(**asdict(reservation))


def _clean_resource_ids(resource_ids: list[str]) -> list[str]:
    return list(dict.fromkeys(value[:500] for value in resource_ids if isinstance(value, str) and value))[:100]


def _run_doc_id(run_id: str) -> str:
    return hashlib.sha256(run_id.encode("utf-8")).hexdigest()


def _resource_doc_id(resource_id: str) -> str:
    return hashlib.sha256(resource_id.encode("utf-8")).hexdigest()


def _reservation_key_from_id(reservation_id: str) -> str:
    if not reservation_id.startswith("spend-"):
        raise SpendControlError("invalid spend reservation identifier")
    return reservation_id.removeprefix("spend-")


def _reservation_doc(reservation: SpendReservation) -> dict[str, Any]:
    data = asdict(reservation)
    data["status"] = reservation.status.value
    return data


def _reservation_from_doc(data: dict[str, Any]) -> SpendReservation:
    value = dict(data)
    value["status"] = ReservationStatus(value["status"])
    value["resource_ids"] = value.get("resource_ids") or []
    return SpendReservation(**value)
