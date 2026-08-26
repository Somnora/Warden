"""Durable, distributed spend controls."""

import asyncio

import pytest

from warden.spend import (
    MemorySpendStore,
    ReservationStatus,
    SpendControlError,
    SpendLimits,
)


LIMITS = SpendLimits(
    max_usd_per_run=2.0,
    max_usd_per_day=3.0,
    max_concurrent_instances=1,
)


@pytest.mark.asyncio
async def test_reservation_is_idempotent_but_cannot_be_reused_after_release():
    store = MemorySpendStore()
    first, initial = await store.reserve(
        idempotency_key="launch-1", run_id="producer-run", cost_usd=0.85,
        instances=1, limits=LIMITS,
    )
    retry, retried = await store.reserve(
        idempotency_key="launch-1", run_id="producer-run", cost_usd=0.85,
        instances=1, limits=LIMITS,
    )

    assert retry.reservation_id == first.reservation_id
    assert initial == retried
    assert retried.run_usd == pytest.approx(0.85)
    assert retried.live_instances == 1

    await store.release(first.reservation_id, reason="provider declined launch", release_cost=True)
    with pytest.raises(SpendControlError, match="new approval"):
        await store.reserve(
            idempotency_key="launch-1", run_id="producer-run", cost_usd=0.85,
            instances=1, limits=LIMITS,
        )


@pytest.mark.asyncio
async def test_concurrent_reservations_cannot_overbook_shared_capacity():
    store = MemorySpendStore()

    results = await asyncio.gather(
        store.reserve(
            idempotency_key="launch-west", run_id="run-west", cost_usd=0.85,
            instances=1, limits=LIMITS,
        ),
        store.reserve(
            idempotency_key="launch-central", run_id="run-central", cost_usd=0.85,
            instances=1, limits=LIMITS,
        ),
        return_exceptions=True,
    )

    assert sum(not isinstance(result, Exception) for result in results) == 1
    rejected = next(result for result in results if isinstance(result, Exception))
    assert isinstance(rejected, SpendControlError)
    assert "concurrent-instance" in str(rejected)
    summary = await store.summary("run-west")
    assert summary.day_usd == pytest.approx(0.85)
    assert summary.live_instances == 1


@pytest.mark.asyncio
async def test_settlement_preserves_cost_and_verified_teardown_releases_capacity():
    store = MemorySpendStore()
    reservation, _ = await store.reserve(
        idempotency_key="launch-1", run_id="producer-run", cost_usd=0.85,
        instances=1, limits=LIMITS,
    )

    settled = await store.settle(reservation.reservation_id, resource_ids=["instance-123"])
    assert settled.settled_usd == pytest.approx(0.85)
    assert settled.reserved_usd == 0

    released = await store.release_resource("instance-123", reason="verified termination")
    assert released is not None
    assert released.live_instances == 0
    assert released.run_usd == pytest.approx(0.85)
    assert released.day_usd == pytest.approx(0.85)
    assert released.settled_usd == pytest.approx(0.85)


@pytest.mark.asyncio
async def test_unknown_provider_outcome_stays_booked_and_blocks_retry():
    store = MemorySpendStore()
    reservation, _ = await store.reserve(
        idempotency_key="launch-unknown", run_id="producer-run", cost_usd=0.85,
        instances=1, limits=LIMITS,
    )

    uncertain = await store.mark_uncertain(
        reservation.reservation_id, reason="network disconnected before outcome"
    )
    assert uncertain.uncertain_usd == pytest.approx(0.85)
    assert uncertain.live_instances == 1

    with pytest.raises(SpendControlError, match="uncertain"):
        await store.reserve(
            idempotency_key="launch-unknown", run_id="producer-run", cost_usd=0.85,
            instances=1, limits=LIMITS,
        )


@pytest.mark.asyncio
async def test_known_failed_launch_releases_cost_and_capacity():
    store = MemorySpendStore()
    reservation, _ = await store.reserve(
        idempotency_key="launch-failed", run_id="producer-run", cost_usd=0.85,
        instances=1, limits=LIMITS,
    )

    released = await store.release(
        reservation.reservation_id, reason="provider returned failed", release_cost=True
    )
    assert released.run_usd == 0
    assert released.day_usd == 0
    assert released.live_instances == 0
    assert released.reserved_usd == 0
    assert store._reservations["launch-failed"].status is ReservationStatus.RELEASED
