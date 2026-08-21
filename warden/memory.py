"""Secure, bounded cross-session operator context for long-running fleets."""

from __future__ import annotations

import asyncio
import hashlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Protocol
from uuid import uuid4


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _expires_at() -> str:
    return (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(timespec="seconds").replace("+00:00", "Z")


def subject_key(subject: str) -> str:
    """Never use a raw operator identity as a Firestore document identifier."""
    return hashlib.sha256(subject.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class MemoryItem:
    memory_id: str
    subject_hash: str
    content: str
    classification: str = "internal"
    provenance: str = "operator_supplied"
    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)
    expires_at: str = field(default_factory=_expires_at)


class MemoryBank(Protocol):
    async def remember(self, subject: str, content: str, *, classification: str = "internal") -> MemoryItem: ...
    async def list(self, subject: str, *, limit: int = 6) -> list[MemoryItem]: ...


class MemoryMemoryBank:
    """Local implementation used by the desktop app, tests, and offline demo."""

    def __init__(self) -> None:
        self._items: dict[str, list[MemoryItem]] = {}
        self._lock = asyncio.Lock()

    async def remember(self, subject: str, content: str, *, classification: str = "internal") -> MemoryItem:
        item = MemoryItem(
            memory_id=f"mem-{uuid4().hex}", subject_hash=subject_key(subject),
            content=_bounded(content), classification=classification,
        )
        async with self._lock:
            self._items.setdefault(item.subject_hash, []).append(item)
        return item

    async def list(self, subject: str, *, limit: int = 6) -> list[MemoryItem]:
        async with self._lock:
            items = self._items.get(subject_key(subject), [])
            return list(reversed(items[-limit:]))


class FirestoreMemoryBank:
    """Firestore-backed, identity-partitioned Memory Bank for live deployment."""

    def __init__(self, project: str, *, collection: str = "warden_memory") -> None:
        from google.cloud import firestore

        self._fs = firestore.AsyncClient(project=project)
        self._firestore = firestore
        self._collection = self._fs.collection(collection)

    async def remember(self, subject: str, content: str, *, classification: str = "internal") -> MemoryItem:
        item = MemoryItem(
            memory_id=f"mem-{uuid4().hex}", subject_hash=subject_key(subject),
            content=_bounded(content), classification=classification,
        )
        await self._collection.document(item.subject_hash).collection("items").document(item.memory_id).set(asdict(item))
        return item

    async def list(self, subject: str, *, limit: int = 6) -> list[MemoryItem]:
        query = self._collection.document(subject_key(subject)).collection("items").order_by(
            "updated_at", direction=self._firestore.Query.DESCENDING
        ).limit(limit)
        return [MemoryItem(**snapshot.to_dict()) async for snapshot in query.stream()]


async def context_for(bank: MemoryBank, subject: str, *, max_characters: int = 2400) -> str:
    """Format bounded context for a model without leaking another user's state."""
    fragments: list[str] = []
    used = 0
    for item in reversed(await bank.list(subject)):
        fragment = item.content.strip()
        if not fragment:
            continue
        remaining = max_characters - used
        if remaining <= 0:
            break
        fragments.append(fragment[:remaining])
        used += len(fragment)
    return "\n".join(f"- {fragment}" for fragment in fragments)


def _bounded(content: str) -> str:
    return content.strip()[:1200]
