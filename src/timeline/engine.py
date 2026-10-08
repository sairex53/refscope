"""Offline object timeline reconstruction for saved RefScope events.

This module deliberately models observed operations, not kernel ownership or
actual refcounts. It does not pair individual GETs with PUTs.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
from typing import Any, Iterable, Iterator


_ALLOWED_TYPES = {"CREATE", "GET", "PUT", "FREE", "CALL_RETURN"}


def _address(value: Any) -> int:
    if isinstance(value, bool):
        raise ValueError("object address must be an integer or hex string")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise ValueError("event object is required")


def _hex(value: int) -> str:
    return f"0x{value:x}"


def _unique_append(items: list[Any], value: Any) -> None:
    if value is not None and value not in items:
        items.append(value)


def _stack_fingerprint(event: dict[str, Any]) -> str | None:
    explicit = event.get("stack_fingerprint")
    if explicit is not None:
        return str(explicit)
    stack = event.get("stack")
    if isinstance(stack, list):
        parts: list[str] = []
        for frame in stack:
            if isinstance(frame, dict):
                symbol = frame.get("symbol", "?")
                offset = frame.get("offset", 0)
                source = frame.get("file")
                line = frame.get("line")
                suffix = f"+{offset}"
                if source is not None and line is not None:
                    suffix += f"@{source}:{line}"
                parts.append(f"{symbol}{suffix}")
            else:
                parts.append(str(frame))
        return "stack:" + "|".join(parts)
    stack_id = event.get("stack_id")
    if isinstance(stack_id, int) and stack_id >= 0:
        return f"stack_id:{stack_id}"
    return None


@dataclass
class ObjectGeneration:
    address: int
    generation: int
    origin: str
    state: str = "UNKNOWN"
    first_seen: int | None = None
    last_seen: int | None = None
    create_event: dict[str, Any] | None = None
    free_event: dict[str, Any] | None = None
    observed_gets: int = 0
    observed_puts: int = 0
    actual_refcount: int | None = None
    actual_refcount_available: bool = False
    active_reasons: list[Any] = field(default_factory=list)
    tasks: list[dict[str, int | None]] = field(default_factory=list)
    cpus: list[int] = field(default_factory=list)
    stack_fingerprints: list[str] = field(default_factory=list)
    targets: list[Any] = field(default_factory=list)
    events: list[dict[str, Any]] = field(default_factory=list)
    suspicion_flags: list[str] = field(default_factory=list)

    @property
    def observed_balance(self) -> int:
        return self.observed_gets - self.observed_puts

    def flag(self, name: str) -> None:
        if name not in self.suspicion_flags:
            self.suspicion_flags.append(name)

    def finish(self) -> None:
        if self.observed_balance != 0:
            self.flag("UNBALANCED_OBSERVED_OPS")
        if self.actual_refcount_available and self.actual_refcount != 0:
            self.flag("REFCOUNT_NONZERO_AT_END")
        if self.state == "UNKNOWN":
            self.state = "LIVE"

    def as_dict(self) -> dict[str, Any]:
        self.finish()
        return {
            "object": _hex(self.address),
            "generation": self.generation,
            "origin": self.origin,
            "state": self.state,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "create_event": self.create_event,
            "free_event": self.free_event,
            "observed_gets": self.observed_gets,
            "observed_puts": self.observed_puts,
            "observed_balance": self.observed_balance,
            "actual_refcount": self.actual_refcount,
            "active_reasons": list(self.active_reasons),
            "tasks": list(self.tasks),
            "cpus": list(self.cpus),
            "stack_fingerprints": list(self.stack_fingerprints),
            "targets": list(self.targets),
            "suspicion_flags": list(self.suspicion_flags),
            "events": list(self.events),
        }


class Timeline:
    """Build per-(object address, generation) timelines from saved event dicts."""

    def __init__(self) -> None:
        self._generations: dict[int, list[ObjectGeneration]] = {}
        self._current: dict[int, ObjectGeneration] = {}
        self._event_index = 0

    def _new_generation(self, address: int, origin: str) -> ObjectGeneration:
        generation = len(self._generations.get(address, [])) + 1
        obj = ObjectGeneration(address, generation, origin)
        self._generations.setdefault(address, []).append(obj)
        self._current[address] = obj
        return obj

    def _ensure_generation(self, address: int, event_type: str) -> tuple[ObjectGeneration, bool]:
        current = self._current.get(address)
        if current is None:
            return (
                self._new_generation(
                    address, "explicit" if event_type == "CREATE" else "partial"
                ),
                False,
            )
        if current.state == "DEAD":
            if event_type == "CREATE":
                return self._new_generation(address, "explicit"), False
            obj = self._new_generation(address, "partial")
            obj.flag("ADDRESS_REUSE_AMBIGUOUS")
            obj.flag("EVENT_AFTER_FREE")
            return obj, True
        if event_type == "CREATE":
            current.flag("ADDRESS_REUSE_AMBIGUOUS")
            obj = self._new_generation(address, "partial")
            obj.flag("ADDRESS_REUSE_AMBIGUOUS")
            return obj, False
        return current, False

    def process_event(self, event: dict[str, Any]) -> ObjectGeneration | None:
        if event.get("record", "event") != "event":
            return None
        event_type = str(event.get("type", "")).upper()
        if event_type not in _ALLOWED_TYPES:
            raise ValueError(f"unsupported timeline event type: {event_type!r}")
        address = _address(event.get("object"))
        obj, _ = self._ensure_generation(address, event_type)
        self._event_index += 1
        event_copy = dict(event)
        event_copy["timeline_index"] = self._event_index
        event_copy["generation"] = obj.generation
        event_copy["object"] = _hex(address)
        obj.events.append(event_copy)

        ts = event.get("ts_ns")
        if isinstance(ts, int):
            if obj.first_seen is None:
                obj.first_seen = ts
            obj.last_seen = ts
        cpu = event.get("cpu")
        if isinstance(cpu, int):
            _unique_append(obj.cpus, cpu)
        pid = event.get("pid")
        tid = event.get("tid")
        if isinstance(pid, int) or isinstance(tid, int):
            task = {"pid": pid if isinstance(pid, int) else None,
                    "tid": tid if isinstance(tid, int) else None}
            _unique_append(obj.tasks, task)
        if "reason" in event and event["reason"] is not None:
            _unique_append(obj.active_reasons, event["reason"])
        target = event.get("target_id", event.get("function"))
        _unique_append(obj.targets, target)
        fingerprint = _stack_fingerprint(event)
        _unique_append(obj.stack_fingerprints, fingerprint)

        if event_type == "CREATE":
            obj.state = "LIVE"
            obj.create_event = event_copy
        elif event_type == "GET":
            if obj.state == "UNKNOWN":
                obj.state = "LIVE"
            obj.observed_gets += 1
        elif event_type == "PUT":
            if obj.observed_balance <= 0:
                obj.flag("PUT_WITHOUT_PRIOR_GET")
            obj.observed_puts += 1
        elif event_type == "FREE":
            obj.state = "DEAD"
            obj.free_event = event_copy
        elif event_type == "CALL_RETURN":
            # Return observations add path context without changing ownership balance.
            pass

        explicit_refcount = event.get("actual_refcount")
        if explicit_refcount is None:
            explicit_refcount = event.get("kernel_refcount")
        if explicit_refcount is not None:
            if not isinstance(explicit_refcount, int):
                raise ValueError("actual_refcount must be an integer when present")
            obj.actual_refcount = explicit_refcount
            obj.actual_refcount_available = True
        return obj

    def process(self, events: Iterable[dict[str, Any]]) -> "Timeline":
        for event in events:
            self.process_event(event)
        return self

    def generations(self) -> Iterator[ObjectGeneration]:
        for address in sorted(self._generations):
            yield from self._generations[address]

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "model": "(object address, generation)",
            "refcount_semantics": {
                "observed_balance": "observed_gets - observed_puts",
                "actual_refcount": "unavailable unless explicitly captured",
            },
            "objects": [obj.as_dict() for obj in self.generations()],
        }

    def write_json(self, path: str | Path) -> None:
        Path(path).write_text(
            json.dumps(self.as_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )


def read_jsonl(path: str | Path) -> Timeline:
    timeline = Timeline()
    with Path(path).open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSONL at line {line_number}") from exc
            if isinstance(record, dict):
                timeline.process_event(record)
    return timeline
