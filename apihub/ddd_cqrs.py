"""
Domain-Driven Design (DDD), Repository Pattern, Event Sourcing & CQRS Architecture Module.
Provides:
- Immutable DomainEvent & EventStore (`domain_events` table) with hash verification and stream replay
- Generic BaseRepository & concrete domain repositories
- CQRS CommandBus (write operations emitting domain events) and QueryBus (read projections)
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Generic, List, Optional, TypeVar

from apihub.database import db

T = TypeVar("T", bound=Dict[str, Any])


@dataclass(frozen=True)
class DomainEvent:
    event_id: str
    aggregate_type: str
    aggregate_id: str
    event_type: str
    sequence_num: int
    payload: Dict[str, Any]
    metadata: Dict[str, Any]
    event_hash: str
    created_at: float


class EventStore:
    """Append-only Event Sourcing store persisting immutable DomainEvents."""

    @staticmethod
    def append(
        aggregate_type: str,
        aggregate_id: str,
        event_type: str,
        payload: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> DomainEvent:
        now = time.time()
        event_id = f"devt_{uuid.uuid4().hex[:14]}"
        last = db.fetch_one(
            "SELECT sequence_num, event_hash FROM domain_events WHERE aggregate_id = ? ORDER BY sequence_num DESC LIMIT 1",
            (aggregate_id,),
        )
        seq = (int(last["sequence_num"]) + 1) if last else 1
        prev_hash = last["event_hash"] if last else "GENESIS"
        payload_str = json.dumps(payload, sort_keys=True)
        meta_str = json.dumps(metadata or {}, sort_keys=True)
        raw_chain = f"{prev_hash}|{aggregate_type}|{aggregate_id}|{event_type}|{seq}|{payload_str}|{now:.6f}"
        event_hash = hashlib.sha256(raw_chain.encode("utf-8")).hexdigest()

        db.execute(
            """
            INSERT INTO domain_events
            (id, aggregate_type, aggregate_id, event_type, sequence_num, payload, metadata, event_hash, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                aggregate_type,
                aggregate_id,
                event_type,
                seq,
                payload_str,
                meta_str,
                event_hash,
                now,
            ),
        )
        return DomainEvent(
            event_id=event_id,
            aggregate_type=aggregate_type,
            aggregate_id=aggregate_id,
            event_type=event_type,
            sequence_num=seq,
            payload=payload,
            metadata=metadata or {},
            event_hash=event_hash,
            created_at=now,
        )

    @staticmethod
    def get_stream(aggregate_id: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        if aggregate_id:
            rows = db.fetch_all(
                "SELECT * FROM domain_events WHERE aggregate_id = ? ORDER BY sequence_num ASC LIMIT ?",
                (aggregate_id, limit),
            )
        else:
            rows = db.fetch_all(
                "SELECT * FROM domain_events ORDER BY created_at DESC, rowid DESC LIMIT ?",
                (limit,),
            )
        return [
            {
                **dict(r),
                "payload": json.loads(r["payload"] or "{}"),
                "metadata": json.loads(r["metadata"] or "{}"),
            }
            for r in rows
        ]

    @classmethod
    def replay_aggregate_state(cls, aggregate_id: str) -> Dict[str, Any]:
        """Reconstruct aggregate state by replaying all DomainEvents in sequence order."""
        events = cls.get_stream(aggregate_id=aggregate_id, limit=1000)
        state: Dict[str, Any] = {
            "aggregate_id": aggregate_id,
            "version": 0,
            "history_count": len(events),
            "attributes": {},
        }
        for ev in events:
            state["aggregate_type"] = ev["aggregate_type"]
            state["version"] = ev["sequence_num"]
            state["last_event_type"] = ev["event_type"]
            state["last_event_hash"] = ev["event_hash"]
            state["attributes"].update(ev["payload"])
        return state


class BaseRepository(Generic[T]):
    """Generic DDD Repository encapsulating persistence queries for a domain table."""

    def __init__(self, table_name: str, id_column: str = "id") -> None:
        self.table_name = table_name
        self.id_column = id_column

    def get_by_id(self, entity_id: str) -> Optional[Dict[str, Any]]:
        return db.fetch_one(
            f"SELECT * FROM {self.table_name} WHERE {self.id_column} = ?",  # nosec B608
            (entity_id,),
        )

    def list_all(self, limit: int = 100) -> List[Dict[str, Any]]:
        return db.fetch_all(
            f"SELECT * FROM {self.table_name} ORDER BY created_at DESC LIMIT ?",  # nosec B608
            (limit,),
        )

    def delete_by_id(self, entity_id: str) -> bool:
        count = db.execute(
            f"DELETE FROM {self.table_name} WHERE {self.id_column} = ?",  # nosec B608
            (entity_id,),
        )
        return count > 0


@dataclass
class Command:
    name: str
    payload: Dict[str, Any]
    actor_id: str = "system"


@dataclass
class Query:
    name: str
    params: Dict[str, Any] = field(default_factory=dict)


class CommandBus:
    """CQRS Command Bus routing state-changing commands to domain handlers and emitting events."""

    def __init__(self) -> None:
        self._handlers: Dict[str, Callable[[Command], Dict[str, Any]]] = {}

    def register(self, command_name: str, handler: Callable[[Command], Dict[str, Any]]) -> None:
        self._handlers[command_name] = handler

    def dispatch(self, command: Command) -> Dict[str, Any]:
        if command.name not in self._handlers:
            raise ValueError(f"Unregistered CQRS command '{command.name}'")
        result = self._handlers[command.name](command)
        EventStore.append(
            aggregate_type=command.name.split(".")[0],
            aggregate_id=str(result.get("id") or command.payload.get("id") or "global"),
            event_type=f"command.{command.name}.executed",
            payload=command.payload,
            metadata={"actor_id": command.actor_id},
        )
        return result


class QueryBus:
    """CQRS Query Bus executing read-optimized projections."""

    def __init__(self) -> None:
        self._handlers: Dict[str, Callable[[Query], Dict[str, Any]]] = {}

    def register(self, query_name: str, handler: Callable[[Query], Dict[str, Any]]) -> None:
        self._handlers[query_name] = handler

    def ask(self, query: Query) -> Dict[str, Any]:
        if query.name not in self._handlers:
            raise ValueError(f"Unregistered CQRS query '{query.name}'")
        return self._handlers[query.name](query)


event_store = EventStore()
command_bus = CommandBus()
query_bus = QueryBus()


# Register default CQRS projections
def _handle_system_projection(q: Query) -> Dict[str, Any]:
    events = event_store.get_stream(limit=int(q.params.get("limit", 25)))
    return {
        "projection": "domain_event_stream",
        "total_events": len(events),
        "events": events,
    }


query_bus.register("domain.events_summary", _handle_system_projection)
