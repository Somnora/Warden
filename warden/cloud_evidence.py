"""Cloud posture collection and tamper-evident evidence snapshots.

The collection path is read-only against cloud inventory, Security Command
Center, and billing exports. Normalized results are sealed into a hash chain;
live deployments can additionally archive each sealed record to a
retention-locked Cloud Storage bucket.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import os
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol
from uuid import uuid4


EVIDENCE_GENESIS = "0" * 64
_BILLING_TABLE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_$-]+$")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _bounded(value: Any, limit: int = 500) -> str:
    return str(value or "")[:limit]


@dataclass(frozen=True)
class AssetState:
    name: str
    asset_type: str
    location: str | None
    config_sha256: str


@dataclass(frozen=True)
class SecurityFinding:
    finding_id: str
    category: str
    severity: str
    resource: str
    event_time: str | None


@dataclass(frozen=True)
class FinanceLine:
    usage_date: str
    project_id: str
    service: str
    net_cost: float
    currency: str


@dataclass(frozen=True)
class ArchiveReceipt:
    uri: str
    generation: str
    retention_locked: bool


@dataclass
class EvidenceSnapshot:
    snapshot_id: str
    seq: int
    captured_at: str
    scope: str
    collected_by: str
    payload: dict[str, Any]
    payload_sha256: str
    previous_hash: str
    evidence_hash: str
    archive: ArchiveReceipt | None = None

    def hash_payload(self) -> dict[str, Any]:
        return {
            "snapshot_id": self.snapshot_id,
            "seq": self.seq,
            "captured_at": self.captured_at,
            "scope": self.scope,
            "collected_by": self.collected_by,
            "payload_sha256": self.payload_sha256,
            "previous_hash": self.previous_hash,
        }

    def compute_hash(self) -> str:
        return _digest(self.hash_payload())


@dataclass(frozen=True)
class EvidenceVerdict:
    ok: bool
    checked: int
    broken_at: int | None = None
    detail: str = ""


class CloudSignalCollector(Protocol):
    async def assets(self, scope: str) -> list[AssetState]: ...
    async def findings(self, scope: str) -> list[SecurityFinding]: ...
    async def finance(self, scope: str) -> list[FinanceLine]: ...


class EvidenceStore(Protocol):
    async def append(self, *, scope: str, collected_by: str, payload: dict[str, Any]) -> EvidenceSnapshot: ...
    async def attach_archive(self, snapshot_id: str, receipt: ArchiveReceipt) -> EvidenceSnapshot: ...
    async def latest(self) -> EvidenceSnapshot | None: ...
    async def list(self, *, limit: int = 20) -> list[EvidenceSnapshot]: ...
    async def verify(self) -> EvidenceVerdict: ...


class EvidenceArchive(Protocol):
    async def write(self, snapshot: EvidenceSnapshot) -> ArchiveReceipt: ...


class MemoryEvidenceStore:
    def __init__(self) -> None:
        self._snapshots: list[EvidenceSnapshot] = []
        self._lock = asyncio.Lock()

    async def append(
        self, *, scope: str, collected_by: str, payload: dict[str, Any]
    ) -> EvidenceSnapshot:
        async with self._lock:
            previous = self._snapshots[-1] if self._snapshots else None
            snapshot = _seal_snapshot(
                seq=len(self._snapshots), scope=scope, collected_by=collected_by,
                payload=payload, previous_hash=previous.evidence_hash if previous else EVIDENCE_GENESIS,
            )
            self._snapshots.append(snapshot)
            return _copy_snapshot(snapshot)

    async def attach_archive(
        self, snapshot_id: str, receipt: ArchiveReceipt
    ) -> EvidenceSnapshot:
        async with self._lock:
            snapshot = next((item for item in self._snapshots if item.snapshot_id == snapshot_id), None)
            if snapshot is None:
                raise KeyError(snapshot_id)
            if snapshot.archive is not None and snapshot.archive != receipt:
                raise ValueError("evidence snapshot already has a different archive receipt")
            snapshot.archive = receipt
            return _copy_snapshot(snapshot)

    async def latest(self) -> EvidenceSnapshot | None:
        async with self._lock:
            return _copy_snapshot(self._snapshots[-1]) if self._snapshots else None

    async def list(self, *, limit: int = 20) -> list[EvidenceSnapshot]:
        async with self._lock:
            return [_copy_snapshot(item) for item in reversed(self._snapshots[-limit:])]

    async def verify(self) -> EvidenceVerdict:
        async with self._lock:
            return verify_evidence(self._snapshots)


class FirestoreEvidenceStore:
    """Transactional evidence chain shared across Cloud Run instances."""

    def __init__(
        self, project: str, *, collection: str = "warden_cloud_evidence",
        namespace: str = "control-plane",
    ) -> None:
        from google.cloud import firestore

        self._fs = firestore.AsyncClient(project=project)
        self._firestore = firestore
        self._root = self._fs.collection(collection).document(namespace)
        self._snapshots = self._root.collection("snapshots")

    async def append(
        self, *, scope: str, collected_by: str, payload: dict[str, Any]
    ) -> EvidenceSnapshot:
        transaction = self._fs.transaction()

        @self._firestore.async_transactional
        async def append_once(txn: Any) -> EvidenceSnapshot:
            root_snapshot = await self._root.get(transaction=txn)
            checkpoint = root_snapshot.to_dict() if root_snapshot.exists else {}
            seq = int((checkpoint or {}).get("record_count", 0))
            previous_hash = str((checkpoint or {}).get("tip_hash", EVIDENCE_GENESIS))
            snapshot = _seal_snapshot(
                seq=seq, scope=scope, collected_by=collected_by,
                payload=payload, previous_hash=previous_hash,
            )
            txn.set(self._snapshots.document(f"{seq:08d}"), _snapshot_doc(snapshot))
            txn.set(self._root, {
                "record_count": seq + 1,
                "tip_hash": snapshot.evidence_hash,
                "tip_seq": seq,
                "latest_snapshot_id": snapshot.snapshot_id,
            }, merge=True)
            return snapshot

        return await append_once(transaction)

    async def attach_archive(
        self, snapshot_id: str, receipt: ArchiveReceipt
    ) -> EvidenceSnapshot:
        query = self._snapshots.where("snapshot_id", "==", snapshot_id).limit(1)
        docs = [doc async for doc in query.stream()]
        if not docs:
            raise KeyError(snapshot_id)
        ref = docs[0].reference
        snapshot = _snapshot_from_doc(docs[0].to_dict())
        if snapshot.archive is not None and snapshot.archive != receipt:
            raise ValueError("evidence snapshot already has a different archive receipt")
        await ref.update({"archive": asdict(receipt)})
        snapshot.archive = receipt
        return snapshot

    async def latest(self) -> EvidenceSnapshot | None:
        root = await self._root.get()
        checkpoint = root.to_dict() if root.exists else {}
        seq = (checkpoint or {}).get("tip_seq")
        if not isinstance(seq, int):
            return None
        snapshot = await self._snapshots.document(f"{seq:08d}").get()
        return _snapshot_from_doc(snapshot.to_dict()) if snapshot.exists else None

    async def list(self, *, limit: int = 20) -> list[EvidenceSnapshot]:
        query = self._snapshots.order_by("seq", direction=self._firestore.Query.DESCENDING).limit(limit)
        return [_snapshot_from_doc(doc.to_dict()) async for doc in query.stream()]

    async def verify(self) -> EvidenceVerdict:
        transaction = self._fs.transaction()

        @self._firestore.async_transactional
        async def verify_snapshot(txn: Any) -> EvidenceVerdict:
            root = await self._root.get(transaction=txn)
            query = self._snapshots.order_by("seq")
            documents = [doc async for doc in query.stream(transaction=txn)]
            snapshots = [_snapshot_from_doc(doc.to_dict()) for doc in documents]
            verdict = verify_evidence(snapshots)
            if not verdict.ok:
                return verdict
            checkpoint = root.to_dict() if root.exists else {}
            if snapshots:
                tip = snapshots[-1]
                if (
                    (checkpoint or {}).get("record_count") != len(snapshots)
                    or (checkpoint or {}).get("tip_seq") != tip.seq
                    or (checkpoint or {}).get("tip_hash") != tip.evidence_hash
                ):
                    return EvidenceVerdict(
                        False, len(snapshots), tip.seq,
                        "durable evidence checkpoint mismatch",
                    )
            elif (checkpoint or {}).get("record_count", 0) != 0:
                return EvidenceVerdict(False, 0, 0, "checkpoint exists but evidence chain is empty")
            return verdict

        return await verify_snapshot(transaction)


class NoopEvidenceArchive:
    async def write(self, snapshot: EvidenceSnapshot) -> ArchiveReceipt:
        return ArchiveReceipt(
            uri=f"memory://{snapshot.snapshot_id}.json",
            generation="1",
            retention_locked=False,
        )


class GcsEvidenceArchive:
    """Write sealed snapshots to a preconfigured retention-locked bucket."""

    def __init__(self, project: str, bucket: str, *, require_locked: bool = True) -> None:
        self.project = project
        self.bucket_name = bucket
        self.require_locked = require_locked

    async def write(self, snapshot: EvidenceSnapshot) -> ArchiveReceipt:
        return await asyncio.to_thread(self._write_sync, snapshot)

    def _write_sync(self, snapshot: EvidenceSnapshot) -> ArchiveReceipt:
        from google.cloud import storage

        bucket = storage.Client(project=self.project).bucket(self.bucket_name)
        bucket.reload()
        locked = bool(getattr(bucket, "retention_policy_locked", False))
        if self.require_locked and not locked:
            raise RuntimeError("evidence bucket retention policy is not locked")
        blob = bucket.blob(f"warden-evidence/{snapshot.seq:08d}-{snapshot.snapshot_id}.json")
        blob.upload_from_string(
            _canonical(_snapshot_doc(snapshot)),
            content_type="application/json",
            if_generation_match=0,
        )
        return ArchiveReceipt(
            uri=f"gs://{self.bucket_name}/{blob.name}",
            generation=str(blob.generation),
            retention_locked=locked,
        )


class MockCloudSignalCollector:
    """Deterministic local signals for the dashboard and integration tests."""

    async def assets(self, scope: str) -> list[AssetState]:
        return [
            AssetState(
                name=f"//compute.googleapis.com/{scope}/zones/us-west1-a/instances/render-01",
                asset_type="compute.googleapis.com/Instance", location="us-west1-a",
                config_sha256=_digest({"machineType": "g2-standard-8", "shielded": True}),
            ),
            AssetState(
                name=f"//storage.googleapis.com/{scope}/buckets/warden-artifacts",
                asset_type="storage.googleapis.com/Bucket", location="US",
                config_sha256=_digest({"publicAccessPrevention": "enforced"}),
            ),
        ]

    async def findings(self, scope: str) -> list[SecurityFinding]:
        return [
            SecurityFinding(
                finding_id="mock-scc-001", category="PUBLIC_IP_ADDRESS",
                severity="MEDIUM", resource="render-01", event_time=_now(),
            )
        ]

    async def finance(self, scope: str) -> list[FinanceLine]:
        return [
            FinanceLine(
                usage_date=datetime.now(timezone.utc).date().isoformat(),
                project_id=scope.removeprefix("projects/"), service="Compute Engine",
                net_cost=4.5, currency="USD",
            )
        ]


class GoogleCloudSignalCollector:
    """Read-only Google Cloud Asset, SCC, and BigQuery billing integration."""

    def __init__(self, project: str, *, billing_table: str | None = None) -> None:
        self.project = project
        self.billing_table = billing_table or os.environ.get("WARDEN_BILLING_EXPORT_TABLE")

    async def assets(self, scope: str) -> list[AssetState]:
        return await asyncio.to_thread(self._assets_sync, scope)

    def _assets_sync(self, scope: str) -> list[AssetState]:
        from google.cloud import asset_v1
        from google.protobuf.json_format import MessageToDict

        client = asset_v1.AssetServiceClient()
        pager = client.list_assets(request={
            "parent": scope,
            "content_type": asset_v1.ContentType.RESOURCE,
            "page_size": 500,
        })
        assets: list[AssetState] = []
        for asset in pager:
            resource = MessageToDict(asset.resource._pb) if asset.resource else {}
            assets.append(AssetState(
                name=_bounded(asset.name), asset_type=_bounded(asset.asset_type, 200),
                location=_bounded(resource.get("location"), 200) or None,
                config_sha256=_digest(resource),
            ))
        return sorted(assets, key=lambda item: item.name)[:500]

    async def findings(self, scope: str) -> list[SecurityFinding]:
        return await asyncio.to_thread(self._findings_sync, scope)

    def _findings_sync(self, scope: str) -> list[SecurityFinding]:
        from google.cloud import securitycenter_v1

        client = securitycenter_v1.SecurityCenterClient()
        iterator = client.list_findings(request={
            "parent": f"{scope}/sources/-",
            "filter": 'state="ACTIVE"',
            "page_size": 500,
        })
        findings: list[SecurityFinding] = []
        for result in iterator:
            finding = result.finding
            findings.append(SecurityFinding(
                finding_id=_bounded(finding.name), category=_bounded(finding.category, 200),
                severity=_bounded(getattr(finding.severity, "name", finding.severity), 50).upper(),
                resource=_bounded(finding.resource_name),
                event_time=finding.event_time.isoformat() if finding.event_time else None,
            ))
        return sorted(findings, key=lambda item: item.finding_id)[:500]

    async def finance(self, scope: str) -> list[FinanceLine]:
        if not self.billing_table:
            raise RuntimeError("WARDEN_BILLING_EXPORT_TABLE is not configured")
        if not _BILLING_TABLE.fullmatch(self.billing_table):
            raise RuntimeError("WARDEN_BILLING_EXPORT_TABLE is malformed")
        return await asyncio.to_thread(self._finance_sync, scope)

    def _finance_sync(self, scope: str) -> list[FinanceLine]:
        from google.cloud import bigquery

        project_id = scope.removeprefix("projects/") if scope.startswith("projects/") else None
        query = f"""
            SELECT DATE(usage_start_time) AS usage_date,
                   COALESCE(project.id, 'unassigned') AS project_id,
                   service.description AS service,
                   ROUND(SUM(cost + IFNULL((SELECT SUM(c.amount) FROM UNNEST(credits) c), 0)), 4) AS net_cost,
                   ANY_VALUE(currency) AS currency
            FROM `{self.billing_table}`
            WHERE usage_start_time >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 30 DAY)
              AND (@project_id IS NULL OR project.id = @project_id)
            GROUP BY usage_date, project_id, service
            ORDER BY usage_date DESC, net_cost DESC
            LIMIT 1000
        """
        job_config = bigquery.QueryJobConfig(query_parameters=[
            bigquery.ScalarQueryParameter("project_id", "STRING", project_id)
        ])
        rows = bigquery.Client(project=self.project).query(query, job_config=job_config).result()
        return [FinanceLine(
            usage_date=str(row.usage_date), project_id=_bounded(row.project_id, 200),
            service=_bounded(row.service, 300), net_cost=_finite_cost(row.net_cost),
            currency=_bounded(row.currency, 20) or "USD",
        ) for row in rows]


async def collect_cloud_evidence(
    *, collector: CloudSignalCollector, store: EvidenceStore,
    archive: EvidenceArchive | None, scope: str, collected_by: str,
    control_plane_anchor: dict[str, Any] | None = None,
) -> EvidenceSnapshot:
    """Collect independent sources, seal their status, and archive the result."""
    previous = await store.latest()
    results = await asyncio.gather(
        collector.assets(scope), collector.findings(scope), collector.finance(scope),
        return_exceptions=True,
    )
    source_names = ("asset_inventory", "security_command_center", "billing_export")
    status = {
        name: {
            "status": "error" if isinstance(result, Exception) else "ready",
            "error_type": type(result).__name__ if isinstance(result, Exception) else None,
        }
        for name, result in zip(source_names, results, strict=True)
    }
    assets = [] if isinstance(results[0], Exception) else results[0]
    findings = [] if isinstance(results[1], Exception) else results[1]
    finance = [] if isinstance(results[2], Exception) else results[2]
    baseline_assets = (
        _assets_from_payload(previous.payload)
        if previous is not None and previous.scope == scope
        else []
    )
    drift = _asset_drift(baseline_assets, assets) if status["asset_inventory"]["status"] == "ready" else {
        "baseline": bool(baseline_assets), "added": [], "removed": [], "changed": [], "count": 0,
    }
    payload = {
        "schema": "warden.cloud-evidence.v1",
        "source_status": status,
        "assets": [asdict(item) for item in assets],
        "drift": drift,
        "security": {
            "findings": [asdict(item) for item in findings],
            "counts_by_severity": _severity_counts(findings),
        },
        "finance": {
            "lines": [asdict(item) for item in finance],
            "net_cost_30d": round(sum(item.net_cost for item in finance), 4),
            "currency": finance[0].currency if finance else None,
        },
        "baseline_snapshot_id": previous.snapshot_id if previous else None,
        "control_plane_anchor": control_plane_anchor or {},
    }
    snapshot = await store.append(scope=scope, collected_by=collected_by, payload=payload)
    if archive is not None:
        try:
            receipt = await archive.write(snapshot)
            snapshot = await store.attach_archive(snapshot.snapshot_id, receipt)
        except Exception:
            # The durable chain remains honest and verifiable; the absent
            # receipt visibly signals that immutable off-store archiving failed.
            pass
    return snapshot


def verify_evidence(snapshots: list[EvidenceSnapshot]) -> EvidenceVerdict:
    previous_hash = EVIDENCE_GENESIS
    for expected_seq, snapshot in enumerate(snapshots):
        if snapshot.seq != expected_seq:
            return EvidenceVerdict(False, expected_seq + 1, snapshot.seq, "evidence sequence discontinuity")
        if snapshot.payload_sha256 != _digest(snapshot.payload):
            return EvidenceVerdict(False, expected_seq + 1, snapshot.seq, "evidence payload was altered")
        if snapshot.previous_hash != previous_hash:
            return EvidenceVerdict(False, expected_seq + 1, snapshot.seq, "evidence predecessor mismatch")
        if snapshot.evidence_hash != snapshot.compute_hash():
            return EvidenceVerdict(False, expected_seq + 1, snapshot.seq, "evidence seal was altered")
        previous_hash = snapshot.evidence_hash
    return EvidenceVerdict(True, len(snapshots), None, f"{len(snapshots)} evidence snapshots verified")


def snapshot_payload(snapshot: EvidenceSnapshot) -> dict[str, Any]:
    data = _snapshot_doc(snapshot)
    data["verification"] = {
        "payload_matches": snapshot.payload_sha256 == _digest(snapshot.payload),
        "seal_matches": snapshot.evidence_hash == snapshot.compute_hash(),
    }
    return data


def _seal_snapshot(
    *, seq: int, scope: str, collected_by: str, payload: dict[str, Any], previous_hash: str
) -> EvidenceSnapshot:
    snapshot = EvidenceSnapshot(
        snapshot_id=f"evidence-{uuid4().hex}", seq=seq, captured_at=_now(),
        scope=_bounded(scope, 300), collected_by=_bounded(collected_by, 300),
        payload=payload, payload_sha256=_digest(payload), previous_hash=previous_hash,
        evidence_hash="",
    )
    snapshot.evidence_hash = snapshot.compute_hash()
    return snapshot


def _asset_drift(previous: list[AssetState], current: list[AssetState]) -> dict[str, Any]:
    if not previous:
        return {"baseline": False, "added": [], "removed": [], "changed": [], "count": 0}
    before = {item.name: item for item in previous}
    after = {item.name: item for item in current}
    added = sorted(after.keys() - before.keys())
    removed = sorted(before.keys() - after.keys())
    changed = sorted(
        name for name in before.keys() & after.keys()
        if before[name].config_sha256 != after[name].config_sha256
    )
    return {
        "baseline": bool(previous), "added": added, "removed": removed,
        "changed": changed, "count": len(added) + len(removed) + len(changed),
    }


def _assets_from_payload(payload: dict[str, Any]) -> list[AssetState]:
    try:
        return [AssetState(**item) for item in payload.get("assets", []) if isinstance(item, dict)]
    except (TypeError, ValueError):
        return []


def _severity_counts(findings: list[SecurityFinding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        severity = finding.severity.upper() or "UNSPECIFIED"
        counts[severity] = counts.get(severity, 0) + 1
    return dict(sorted(counts.items()))


def _finite_cost(value: Any) -> float:
    numeric = float(value or 0.0)
    if not math.isfinite(numeric):
        raise ValueError("billing result contains a non-finite cost")
    return round(numeric, 4)


def _snapshot_doc(snapshot: EvidenceSnapshot) -> dict[str, Any]:
    data = asdict(snapshot)
    return data


def _snapshot_from_doc(data: dict[str, Any]) -> EvidenceSnapshot:
    value = dict(data)
    archive = value.get("archive")
    value["archive"] = ArchiveReceipt(**archive) if isinstance(archive, dict) else None
    return EvidenceSnapshot(**value)


def _copy_snapshot(snapshot: EvidenceSnapshot) -> EvidenceSnapshot:
    return _snapshot_from_doc(_snapshot_doc(snapshot))
