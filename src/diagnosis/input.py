"""Versioned, deterministic offline diagnosis input and semantic tokenization."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
_LABELS = {"good", "bad", "unlabeled"}
_OPS = {"GET", "PUT", "CREATE", "FREE", "CALL_RETURN"}
_SUFFIX = re.compile(r"(?:\.(?:isra|constprop|part|cold)\.\d+|\+0x[0-9a-fA-F]+)$")


class BundleError(ValueError):
    """A diagnosis bundle is missing or violates its versioned contract."""


def _json(path: Path, name: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise BundleError(f"missing {name}: {path}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise BundleError(f"invalid {name}: {path}: {exc}") from exc


def _hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _stable_run_id(input_hashes: dict[str, Any], target_spec_hash: str | None,
                   refscope_version: str) -> str:
    canonical = json.dumps({"input_hashes": input_hashes,
                            "target_spec_hash": target_spec_hash,
                            "refscope_version": refscope_version},
                           sort_keys=True, separators=(",", ":"))
    return "run-" + hashlib.sha256(canonical.encode()).hexdigest()[:24]


def _capture_quality(summary: dict[str, Any] | None,
                     timeline: dict[str, Any], stacks: list[dict[str, Any]]) -> dict[str, Any]:
    warnings: list[str] = []
    if summary is None:
        warnings.append("capture_summary_unavailable")
        incomplete = True
        attempted = captured = dropped = loss_known = None
        stack_errors = lookup_errors = None
    else:
        incomplete = summary.get("incomplete") is True
        attempted = summary.get("attempted")
        captured = summary.get("captured")
        dropped = summary.get("dropped")
        loss_known = summary.get("loss_counters_known")
        stack_errors = summary.get("stack_errors")
        lookup_errors = summary.get("userspace_stack_lookup_errors")
        if summary.get("incomplete") is None:
            warnings.append("incomplete_flag_unavailable")
            incomplete = True
        if loss_known is not True:
            warnings.append("loss_accounting_unknown")
        if isinstance(dropped, int) and dropped > 0:
            warnings.append("events_dropped")
            incomplete = True
        if loss_known is not True:
            incomplete = True
        if stack_errors is None or lookup_errors is None:
            warnings.append("stack_error_counts_unknown")
        elif stack_errors > 0 or lookup_errors > 0:
            warnings.append("stack_capture_incomplete")
        if incomplete:
            warnings.append("capture_marked_incomplete")
    ambiguous = sum("ADDRESS_REUSE_AMBIGUOUS" in obj.get("suspicion_flags", [])
                    for obj in timeline.get("objects", []))
    unknown_events = sum(
        1 for obj in timeline.get("objects", [])
        for event in obj.get("events", [])
        if str(event.get("type", "")).upper() not in _OPS
    )
    if unknown_events:
        warnings.append("unknown_event_types_present")
    null_stacks = sum(1 for stack in stacks if stack.get("fingerprint") is None)
    if ambiguous:
        warnings.append("ambiguous_generation_present")
    if null_stacks:
        warnings.append("stack_fingerprint_unavailable")
    return {
        "capture_incomplete": incomplete,
        "loss_counters_known": loss_known,
        "attempted": attempted,
        "captured": captured,
        "dropped": dropped,
        "stack_errors": stack_errors,
        "userspace_stack_lookup_errors": lookup_errors,
        "ambiguous_generations": ambiguous,
        "unknown_event_count": unknown_events,
        "null_stack_fingerprints": null_stacks,
        "warnings": sorted(set(warnings)),
    }


def make_diagnosis_manifest(*, label: str, input_hashes: dict[str, Any],
                            target_spec_hash: str | None, refscope_version: str,
                            capture_summary: dict[str, Any] | None,
                            timeline: dict[str, Any],
                            stacks: list[dict[str, Any]]) -> dict[str, Any]:
    if label not in _LABELS:
        raise BundleError("label must be good, bad, or unlabeled")
    run_id = _stable_run_id(input_hashes, target_spec_hash, refscope_version)
    tokens = tokenize_timeline(timeline, stacks, {})
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "label": label,
        "input_hashes": dict(input_hashes),
        "capture_quality": _capture_quality(capture_summary, timeline, stacks),
        "lifetime_count": len(timeline.get("objects", [])),
        "token_count": sum(len(item["tokens"]) for item in tokens),
        "absence_semantics": "No token means no observed event in this run; absence is inferred only by comparing runs.",
    }


def _normal_function(value: Any) -> str | None:
    if value is None:
        return None
    name = str(value).strip()
    if not name:
        return None
    return _SUFFIX.sub("", name)


def _reason(event: dict[str, Any]) -> dict[str, Any]:
    if "reason" not in event or event.get("reason") is None:
        return {"state": "absent", "value": None}
    value = event["reason"]
    # Numeric enum values have no stable semantic name unless the capture supplied
    # an explicit reason_name. Preserve the raw value while marking it unknown.
    named = event.get("reason_name")
    if isinstance(named, str) and named:
        return {"state": "known", "value": named}
    if isinstance(value, str):
        return {"state": "known", "value": value}
    return {"state": "unknown", "value": value}


def _return_class(event: dict[str, Any], op_type: str) -> str | None:
    if op_type != "CALL_RETURN":
        return None
    explicit = event.get("return_class")
    if explicit is not None:
        return str(explicit)
    value = event.get("retval", event.get("return_value"))
    if isinstance(value, int):
        if value < 0:
            return "error"
        return "success" if value == 0 else "positive"
    return "unknown"


def _stack_by_id(stacks: list[dict[str, Any]]) -> dict[Any, dict[str, Any]]:
    return {item.get("stack_id"): item for item in stacks if item.get("stack_id") is not None}


def tokenize_timeline(timeline: dict[str, Any], stacks: list[dict[str, Any]],
                      meta: dict[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(timeline, dict) or not isinstance(timeline.get("objects"), list):
        raise BundleError("summary timeline objects must be an array")
    by_id = _stack_by_id(stacks)
    lifetimes = []
    for obj in timeline["objects"]:
        if not isinstance(obj, dict):
            raise BundleError("lifetime entry must be an object")
        generation = obj.get("generation")
        if not isinstance(generation, int) or isinstance(generation, bool) or generation <= 0:
            raise BundleError("missing or invalid generation")
        address = obj.get("object")
        if not isinstance(address, (str, int)):
            raise BundleError("lifetime object address is missing")
        tokens = []
        raw_events = obj.get("events", [])
        object_class = obj.get("object_class", meta.get("object_class"))
        reference_ids = [event.get("reference_id") if isinstance(event, dict) else None
                         for event in raw_events]
        exact_identity = bool(reference_ids) and all(
            isinstance(value, (str, int)) and not isinstance(value, bool)
            for value in reference_ids
        ) and len({str(value) for value in reference_ids}) == 1
        for event in raw_events:
            if not isinstance(event, dict):
                raise BundleError("lifetime event must be an object")
            event_generation = event.get("generation", generation)
            if event_generation != generation:
                raise BundleError("event generation conflicts with lifetime generation")
            raw_type = str(event.get("type", "UNKNOWN")).upper()
            op_type = raw_type if raw_type in _OPS else "UNKNOWN"
            function = _normal_function(event.get("function"))
            stack = event.get("stack_fingerprint")
            if stack is None:
                stack_record = by_id.get(event.get("stack_id"))
                stack = stack_record.get("fingerprint") if stack_record else None
            source_locations = []
            stack_record = by_id.get(event.get("stack_id"))
            if stack_record:
                for frame in stack_record.get("frames", []):
                    if isinstance(frame, dict) and frame.get("source_file") and frame.get("source_line") is not None:
                        source_locations.append({"file": frame["source_file"], "line": frame["source_line"]})
            if object_class is None and event.get("object_class") is not None:
                object_class = event["object_class"]
            token = {
                "op_type": op_type,
                "normalized_function": function,
                "normalized_stack": stack,
                "reason": _reason(event),
                "return_class": _return_class(event, op_type),
                "return_value": event.get("retval", event.get("return_value")),
                "return_name": event.get("return_name"),
                "source_function": function,
                "source_locations": source_locations,
                "generation": generation,
                "object_class": event.get("object_class", object_class),
                "target_type": event.get("target_type", object_class),
            }
            if op_type == "UNKNOWN":
                token["unknown_event_type"] = raw_type
            tokens.append(token)
        identity_key = str(reference_ids[0]) if exact_identity else None
        lifetimes.append({
            "object": str(address),
            "generation": generation,
            "origin": obj.get("origin", "partial"),
            "object_class": object_class,
            "target_type": obj.get("target_type", object_class),
            "identity_evidence": "explicit-reference-id" if exact_identity else (
                "explicit-lifecycle-boundaries" if obj.get("origin") == "explicit"
                and "ADDRESS_REUSE_AMBIGUOUS" not in obj.get("suspicion_flags", [])
                else "partial-or-ambiguous"
            ),
            "exact_identity_proven": exact_identity,
            "identity_key": identity_key,
            "actual_refcount": obj.get("actual_refcount"),
            "observed_balance": obj.get("observed_balance"),
            "suspicion_flags": list(obj.get("suspicion_flags", [])),
            "tokens": tokens,
        })
    return lifetimes


def load_bundle(bundle_dir: str | Path, *, require_labeled: bool = True) -> dict[str, Any]:
    root = Path(bundle_dir)
    meta = _json(root / "meta.json", "metadata")
    if not isinstance(meta, dict) or meta.get("schema_version") != 1:
        raise BundleError("unsupported or missing bundle schema_version")
    summary = _json(root / "summary.json", "summary")
    stacks_doc = _json(root / "stacks.json", "stacks")
    if not isinstance(summary, dict) or summary.get("schema_version") != 1:
        raise BundleError("unsupported or missing summary schema_version")
    if not isinstance(summary.get("timeline"), dict):
        raise BundleError("summary timeline is missing")
    if not isinstance(stacks_doc, dict) or stacks_doc.get("schema_version") != 1 or not isinstance(stacks_doc.get("stacks"), list):
        raise BundleError("unsupported or malformed stacks schema")
    diagnosis = meta.get("diagnosis")
    if not isinstance(diagnosis, dict):
        raise BundleError("diagnosis metadata is missing")
    if diagnosis.get("schema_version") != SCHEMA_VERSION:
        raise BundleError("unsupported diagnosis schema_version")
    label = diagnosis.get("label")
    if label not in _LABELS or (require_labeled and label == "unlabeled"):
        raise BundleError("bundle label must be good or bad")
    run_id = diagnosis.get("run_id")
    if not isinstance(run_id, str) or not run_id.startswith("run-"):
        raise BundleError("stable run_id is missing or invalid")
    expected_run_id = _stable_run_id(
        diagnosis.get("input_hashes", {}),
        meta.get("target_spec_hash"),
        str(meta.get("refscope_version", "")),
    )
    input_hashes = diagnosis.get("input_hashes")
    if not isinstance(input_hashes, dict) or not input_hashes:
        raise BundleError("original input hashes are missing")
    if input_hashes != meta.get("input_hashes"):
        raise BundleError("diagnosis and bundle input hashes disagree")
    events_path = root / "events.jsonl"
    if not events_path.is_file():
        raise BundleError(f"missing events: {events_path}")
    expected = meta.get("input_hashes", {}).get("bundle_events_jsonl")
    if not isinstance(expected, str) or expected != _hash(events_path):
        raise BundleError("bundle events hash mismatch")
    quality = diagnosis.get("capture_quality")
    if not isinstance(quality, dict):
        raise BundleError("capture-quality metadata is missing")
    if not isinstance(quality.get("capture_incomplete"), bool):
        raise BundleError("capture completeness must be explicit")
    if run_id != expected_run_id:
        raise BundleError("run_id does not match bundle input identity")
    lifetimes = tokenize_timeline(summary["timeline"], stacks_doc["stacks"], meta)
    if diagnosis.get("lifetime_count") != len(lifetimes):
        raise BundleError("diagnosis lifetime_count mismatch")
    token_count = sum(len(item["tokens"]) for item in lifetimes)
    if diagnosis.get("token_count") != token_count:
        raise BundleError("diagnosis token_count mismatch")
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "label": label,
        "input_hashes": input_hashes,
        "capture_quality": quality,
        "target_type": meta.get("target_type") or meta.get("object_class"),
        "object_class": meta.get("object_class"),
        "lifetimes": lifetimes,
    }
