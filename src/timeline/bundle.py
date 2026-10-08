"""Reproducible offline run-bundle support for timeline inputs."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import platform
from pathlib import Path
import re
import subprocess
import sys
from typing import Any

from diagnosis.input import make_diagnosis_manifest


REFSCOPE_VERSION = "v0.0.2-dev"


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: str | Path) -> str:
    return _sha256_bytes(Path(path).read_bytes())


def _int_value(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    return 0


def stack_fingerprint(frames: list[Any], lookup_failed: bool = False) -> str | None:
    """Fingerprint symbols and relative/source positions, never raw IP addresses."""
    if lookup_failed:
        return None
    parts: list[str] = []
    for frame in frames:
        if not isinstance(frame, dict):
            parts.append(str(frame))
            continue
        symbol = str(frame.get("symbol", frame.get("name", "<unknown>")))
        offset = _int_value(frame.get("offset", 0))
        source = frame.get("source_file", frame.get("file"))
        line = frame.get("source_line", frame.get("line"))
        location = f"@{source}:{line}" if source is not None and line is not None else ""
        parts.append(f"{symbol}+{offset}{location}")
    if not parts:
        return None
    return "sha256:" + _sha256_bytes("\n".join(parts).encode("utf-8"))


def _build_id(path: str | Path | None) -> str | None:
    if not path:
        return None
    try:
        result = subprocess.run(
            ["readelf", "-n", str(path)],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return None
    match = re.search(r"Build ID:\s*([0-9a-fA-F]+)", result.stdout)
    return match.group(1).lower() if match else None


def read_records(path: str | Path):
    events: list[dict[str, Any]] = []
    stacks: list[dict[str, Any]] = []
    capture_summary: dict[str, Any] | None = None
    with Path(path).open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSONL at line {line_number}") from exc
            if not isinstance(record, dict):
                raise ValueError(f"JSONL line {line_number} is not an object")
            kind = record.get("record")
            if kind == "event":
                events.append(record)
            elif kind == "stack":
                record = dict(record)
                record["fingerprint"] = stack_fingerprint(
                    record.get("frames", []),
                    bool(record.get("lookup_failed")),
                )
                stacks.append(record)
            elif kind == "summary":
                capture_summary = record
    stack_by_id = {
        record.get("stack_id"): record
        for record in stacks
        if record.get("stack_id") is not None
    }
    normalized_events: list[dict[str, Any]] = []
    for event in events:
        normalized = dict(event)
        stack_id = normalized.get("stack_id")
        stack = stack_by_id.get(stack_id)
        if stack is not None:
            normalized["stack_fingerprint"] = stack.get("fingerprint")
            if stack.get("lookup_failed"):
                normalized["stack_lookup_failed"] = True
        normalized_events.append(normalized)
    return normalized_events, stacks, capture_summary




def _timeline_with_unknown_events(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Keep unknown event records in a generation without treating them as GETs."""
    from timeline.engine import Timeline

    timeline = Timeline()
    supported = {"CREATE", "GET", "PUT", "FREE", "CALL_RETURN"}
    for event in events:
        event_type = str(event.get("type", "")).upper()
        if event_type in supported:
            timeline.process_event(event)
            continue
        placeholder = dict(event)
        placeholder["type"] = "CALL_RETURN"
        generation = timeline.process_event(placeholder)
        if generation is None:
            continue
        retained = generation.events[-1]
        retained["type"] = event_type or "UNKNOWN"
        retained["unknown_event_type"] = event_type or "UNKNOWN"
    return timeline.as_dict()

def _write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def build_bundle(
    input_path: str | Path,
    bundle_dir: str | Path,
    *,
    target_spec: str | Path | None = None,
    vmlinux: str | Path | None = None,
    command_line: list[str] | None = None,
    label: str = "unlabeled",
) -> dict[str, Any]:
    source = Path(input_path)
    destination = Path(bundle_dir)
    destination.mkdir(parents=True, exist_ok=True)
    events, stacks, capture_summary = read_records(source)

    events_path = destination / "events.jsonl"
    with events_path.open("w", encoding="utf-8") as stream:
        for event in events:
            stream.write(json.dumps(event, sort_keys=True) + "\n")
    _write_json(destination / "stacks.json", {
        "schema_version": 1,
        "stacks": stacks,
    })

    timeline = _timeline_with_unknown_events(events)
    _write_json(destination / "summary.json", {
        "schema_version": 1,
        "timeline": timeline,
        "capture_summary": capture_summary,
    })

    target_hash = sha256_file(target_spec) if target_spec else None
    vmlinux_path = str(vmlinux) if vmlinux else None
    vmlinux_id = _build_id(vmlinux)
    meta = {
        "schema_version": 1,
        "kernel_release": platform.release(),
        "architecture": platform.machine(),
        "kernel_build_id": (vmlinux_id if vmlinux else _build_id(Path("/boot/vmlinux-" + platform.release())) if Path("/boot/vmlinux-" + platform.release()).is_file() else None),
        "vmlinux_build_id": vmlinux_id,
        "vmlinux_path": vmlinux_path,
        "refscope_version": REFSCOPE_VERSION,
        "target_spec_hash": target_hash,
        "command_line": list(command_line or sys.argv),
        "capture_capabilities": {
            "offline": True,
            "bpf_attach": False,
            "event_records": len(events),
            "stack_records": len(stacks),
            "stack_lookup_failures": sum(
                1 for stack in stacks if stack.get("lookup_failed")
            ),
            "capture_summary_present": capture_summary is not None,
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "input_hashes": {
            "source_jsonl": sha256_file(source),
            "bundle_events_jsonl": sha256_file(events_path),
        },
    }
    meta["diagnosis"] = make_diagnosis_manifest(
        label=label,
        input_hashes=meta["input_hashes"],
        target_spec_hash=target_hash,
        refscope_version=REFSCOPE_VERSION,
        capture_summary=capture_summary,
        timeline=timeline,
        stacks=stacks,
    )
    _write_json(destination / "meta.json", meta)
    return meta
