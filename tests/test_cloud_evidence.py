"""Cloud drift, security, finance, and immutable evidence integration tests."""

from dataclasses import asdict

import pytest
from fastapi.testclient import TestClient

from warden.cloud_evidence import (
    ArchiveReceipt,
    AssetState,
    FinanceLine,
    MemoryEvidenceStore,
    MockCloudSignalCollector,
    SecurityFinding,
    collect_cloud_evidence,
    verify_evidence,
)
from warden.fleet import initialize_fleet_runtime
from warden.server import app, set_runtime


class LockedArchive:
    async def write(self, snapshot):
        return ArchiveReceipt(
            uri=f"gs://locked-evidence/{snapshot.snapshot_id}.json",
            generation=str(snapshot.seq + 1),
            retention_locked=True,
        )


class FailingFinanceCollector(MockCloudSignalCollector):
    async def finance(self, scope: str):
        raise RuntimeError("billing dataset unavailable and must not leak details")


class ChangedCollector(MockCloudSignalCollector):
    async def assets(self, scope: str):
        original = await super().assets(scope)
        return [
            AssetState(
                name=original[0].name,
                asset_type=original[0].asset_type,
                location=original[0].location,
                config_sha256="f" * 64,
            ),
            AssetState(
                name=f"//compute.googleapis.com/{scope}/zones/us-west1-a/instances/render-02",
                asset_type="compute.googleapis.com/Instance",
                location="us-west1-a",
                config_sha256="a" * 64,
            ),
        ]


@pytest.mark.asyncio
async def test_collection_seals_all_sources_and_retention_locked_receipt():
    store = MemoryEvidenceStore()
    snapshot = await collect_cloud_evidence(
        collector=MockCloudSignalCollector(), store=store, archive=LockedArchive(),
        scope="projects/example-project", collected_by="auditor@example.com",
    )

    assert snapshot.payload["schema"] == "warden.cloud-evidence.v1"
    assert snapshot.payload["drift"]["count"] == 0
    assert snapshot.payload["security"]["counts_by_severity"] == {"MEDIUM": 1}
    assert snapshot.payload["finance"]["net_cost_30d"] == pytest.approx(4.5)
    assert snapshot.archive is not None and snapshot.archive.retention_locked
    assert (await store.verify()).ok


@pytest.mark.asyncio
async def test_second_snapshot_detects_added_removed_and_changed_assets():
    store = MemoryEvidenceStore()
    first = await collect_cloud_evidence(
        collector=MockCloudSignalCollector(), store=store, archive=None,
        scope="projects/example-project", collected_by="auditor",
    )
    second = await collect_cloud_evidence(
        collector=ChangedCollector(), store=store, archive=None,
        scope="projects/example-project", collected_by="auditor",
    )

    drift = second.payload["drift"]
    assert drift["baseline"] is True
    assert drift["count"] == 3
    assert len(drift["added"]) == len(drift["removed"]) == len(drift["changed"]) == 1
    assert second.previous_hash == first.evidence_hash
    assert (await store.verify()).checked == 2


@pytest.mark.asyncio
async def test_source_outage_is_explicit_and_does_not_break_evidence_chain():
    store = MemoryEvidenceStore()
    snapshot = await collect_cloud_evidence(
        collector=FailingFinanceCollector(), store=store, archive=None,
        scope="projects/example-project", collected_by="auditor",
    )

    billing = snapshot.payload["source_status"]["billing_export"]
    assert billing == {"status": "error", "error_type": "RuntimeError"}
    assert "unavailable" not in str(snapshot.payload)
    assert (await store.verify()).ok


@pytest.mark.asyncio
async def test_payload_tampering_is_detected():
    store = MemoryEvidenceStore()
    await collect_cloud_evidence(
        collector=MockCloudSignalCollector(), store=store, archive=None,
        scope="projects/example-project", collected_by="auditor",
    )
    snapshots = list(reversed(await store.list()))
    snapshots[0].payload["finance"]["net_cost_30d"] = 0
    verdict = verify_evidence(snapshots)
    assert not verdict.ok
    assert "payload" in verdict.detail


def test_evidence_api_requires_approver_to_collect_and_exposes_verification():
    store = MemoryEvidenceStore()
    runtime = initialize_fleet_runtime(run_id="cloud-evidence-api")
    set_runtime(
        runtime,
        evidence_store=store,
        cloud_collector=MockCloudSignalCollector(),
        evidence_archive=LockedArchive(),
    )
    client = TestClient(app)

    viewer = client.post(
        "/integrations/cloud/evidence/collect",
        headers={"X-Warden-Roles": "viewer"},
    )
    assert viewer.status_code == 403

    collected = client.post(
        "/integrations/cloud/evidence/collect",
        headers={
            "X-Warden-Operator": "security@example.com",
            "X-Warden-Roles": "approver",
        },
    )
    assert collected.status_code == 201
    evidence = collected.json()["evidence"]
    assert evidence["immutable_archived"] is True
    assert evidence["asset_count"] == 2
    assert evidence["security_findings_count"] == 1

    listed = client.get(
        "/integrations/cloud/evidence", headers={"X-Warden-Roles": "viewer"}
    )
    assert listed.status_code == 200
    assert listed.json()["verification"]["ok"] is True
    assert listed.json()["snapshots"][0]["evidence_hash"] == evidence["evidence_hash"]

    latest = client.get(
        "/integrations/cloud/evidence/latest", headers={"X-Warden-Roles": "viewer"}
    )
    assert latest.status_code == 200
    assert latest.json()["verification"] == {"payload_matches": True, "seal_matches": True}
    anchor = latest.json()["payload"]["control_plane_anchor"]
    assert anchor["ledger_verification"]["ok"] is True
    assert len(anchor["policy_sha256"]) == 64
