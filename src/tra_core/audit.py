"""Append-only, hash-chained audit log.

Each event stores the hash of the previous one, so deleting or editing a record
breaks the chain and `verify` reports where. Sinks decide where events land: a
local JSONL file here, immutable object or blob storage in the platform adapters.
"""

from __future__ import annotations

import hashlib
import json
import random
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal, Protocol

from pydantic import BaseModel, Field

from tra_core.identity import Principal
from tra_core.schemas import utcnow

GENESIS = "0" * 64

EventType = Literal[
    "tra_created",
    "artefact_read",
    "model_call",
    "tool_call",
    "agent_output",
    "validation_failed",
    "stage_changed",
    "gate_requested",
    "gate_decision",
    "gate_refused",
    "export",
]


class AuditEvent(BaseModel):
    seq: int
    at: str = Field(default_factory=lambda: utcnow().isoformat())
    tra_id: str
    tra_version: int
    stage: str | None
    event_type: EventType
    actor: str  # workload or user subject
    on_behalf_of: str | None = None
    classification: str = "OFFICIAL_SENSITIVE"
    detail: dict[str, Any] = Field(default_factory=dict)
    prev_hash: str
    hash: str = ""

    def compute_hash(self) -> str:
        body = self.model_dump(mode="json", exclude={"hash"})
        return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()


REMOTE_EVENT_TYPES = frozenset({"model_call", "tool_call", "agent_output", "validation_failed"})


class SequenceTaken(Exception):
    """Another writer already appended an event with this sequence number."""


class AuditSink(Protocol):
    """Where events land. `append` raises `SequenceTaken` if the sequence number is already used.

    A sink may also offer `tail() -> AuditEvent | None` so a new log can find
    the head of a long chain without reading all of it.
    """

    def append(self, event: AuditEvent) -> None: ...
    def read_all(self) -> list[AuditEvent]: ...


class MemoryAuditSink:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def append(self, event: AuditEvent) -> None:
        self.events.append(event)

    def read_all(self) -> list[AuditEvent]:
        return list(self.events)


class JsonlAuditSink:
    """Local development sink. Production uses immutable storage in a separate account."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, event: AuditEvent) -> None:
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(event.model_dump_json() + "\n")

    def read_all(self) -> list[AuditEvent]:
        if not self.path.exists():
            return []
        lines = self.path.read_text(encoding="utf-8").splitlines()
        return [AuditEvent.model_validate_json(line) for line in lines if line.strip()]


def digest(value: str | bytes) -> str:
    data = value.encode() if isinstance(value, str) else value
    return hashlib.sha256(data).hexdigest()


class AuditLog:
    def __init__(self, sink: AuditSink) -> None:
        self.sink = sink
        self._lock = threading.Lock()
        self._resync()

    def _resync(self) -> None:
        tail = getattr(self.sink, "tail", None)
        last = tail() if tail else (self.sink.read_all() or [None])[-1]
        self._seq = last.seq if last else 0
        self._last_hash = last.hash if last else GENESIS

    def _append(self, build: Callable[[int, str], AuditEvent]) -> AuditEvent:
        """Append at the head. If another writer got there first, move to the new head and try again."""
        for attempt in range(20):
            event = build(self._seq + 1, self._last_hash)
            event.hash = event.compute_hash()
            try:
                self.sink.append(event)
            except SequenceTaken:
                time.sleep(random.uniform(0, 0.005 * (attempt + 1)))  # noqa: S311 - jitter, not crypto
                self._resync()
                continue
            self._seq, self._last_hash = event.seq, event.hash
            return event
        raise SequenceTaken("audit chain is too contended to append")

    def record(
        self,
        *,
        tra_id: str,
        tra_version: int,
        stage: str | None,
        event_type: EventType,
        actor: Principal,
        detail: dict[str, Any] | None = None,
        classification: str = "OFFICIAL_SENSITIVE",
    ) -> AuditEvent:
        with self._lock:
            return self._append(
                lambda seq, prev: AuditEvent(
                    seq=seq,
                    tra_id=tra_id,
                    tra_version=tra_version,
                    stage=stage,
                    event_type=event_type,
                    actor=actor.subject,
                    on_behalf_of=actor.acting_for,
                    classification=classification,
                    detail=detail or {},
                    prev_hash=prev,
                )
            )

    def ingest(self, events: list[dict[str, Any]], origin: str) -> None:
        """Append events recorded by a remote specialist, re-chained into this log.

        A specialist host keeps its own short in-memory chain per request and
        returns it with the result; the orchestrator owns the durable chain.
        The remote chain is checked first so tampering in transit is caught.
        """
        remote = [AuditEvent.model_validate(e) for e in events]
        if problems := verify(remote):
            raise ValueError(f"audit events from {origin} failed verification: {problems[:3]}")
        # A specialist can only report its own work. Gate decisions, exports and
        # the like are recorded by the orchestrator, so a compromised specialist
        # cannot forge an approval into the evidence.
        for r in remote:
            if r.event_type not in REMOTE_EVENT_TYPES or r.actor != origin:
                raise ValueError(f"{origin} may not record {r.event_type!r} events as {r.actor!r}")
        with self._lock:
            for r in remote:
                detail = {**r.detail, "origin": origin, "origin_hash": r.hash}
                self._append(lambda seq, prev, r=r, detail=detail: r.model_copy(
                    update={"seq": seq, "prev_hash": prev, "detail": detail}
                ))

    def events_for(self, tra_id: str) -> list[AuditEvent]:
        return [e for e in self.sink.read_all() if e.tra_id == tra_id]


def verify(events: list[AuditEvent]) -> list[str]:
    """Return a list of problems; empty means the chain is intact."""
    problems = []
    prev = GENESIS
    for i, event in enumerate(events):
        if event.prev_hash != prev:
            problems.append(f"event {event.seq}: prev_hash does not match event {events[i - 1].seq if i else 'genesis'}")
        if event.compute_hash() != event.hash:
            problems.append(f"event {event.seq}: content does not match its hash")
        prev = event.hash
    return problems
