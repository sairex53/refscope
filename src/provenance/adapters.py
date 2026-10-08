"""Conservative offline adapters for optional kernel reference evidence."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from typing import Any, Iterable, Mapping

from .model import (
    Confidence, EvidenceClaim, EvidenceResolution, EvidenceSource,
    ReferenceEvent, ReferenceEvidence, resolve_claims,
)


@dataclass(frozen=True)
class AdapterReport:
    source: EvidenceSource
    available: bool
    mode: str
    observations: tuple[dict[str, Any], ...] = ()
    claims: tuple[EvidenceClaim, ...] = ()
    edges: tuple[ReferenceEvidence, ...] = ()
    warnings: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1, "evidence_source": self.source.value,
            "available": self.available, "mode": self.mode,
            "observations": list(self.observations),
            "claims": [{"value": c.value, "confidence": c.confidence.value,
                        "evidence_source": c.evidence_source.value} for c in self.claims],
            "edges": [e.to_dict() for e in self.edges], "warnings": list(self.warnings),
        }


def discover_native_tracepoints(events_root: str | Path = "/sys/kernel/tracing/events") -> AdapterReport:
    """Read registered tracepoint formats; never enable or consume them."""
    root = Path(events_root)
    try:
        systems = sorted((p for p in root.iterdir() if p.is_dir()), key=lambda p: p.name)
    except OSError as exc:
        return AdapterReport(EvidenceSource.NATIVE_TRACEPOINT, False, "manual",
                             warnings=(f"tracefs discovery unavailable: {exc}",
                                       "native tracepoints not enabled; manual mode"))
    found, warnings = [], []
    for system in systems:
        try:
            events = sorted((p for p in system.iterdir() if p.is_dir()), key=lambda p: p.name)
        except OSError as exc:
            warnings.append(f"cannot enumerate {system}: {exc}")
            continue
        for event in events:
            path = event / "format"
            try:
                text = path.read_text(encoding="utf-8")
            except OSError as exc:
                warnings.append(f"cannot read {path}: {exc}")
                continue
            fields = []
            for line in text.splitlines():
                match = re.match(r"\s*field:[^;]+\s+([A-Za-z_]\w*)\s*(?:\[[^]]+\])?;", line)
                if match:
                    fields.append(match.group(1))
            found.append({"system": system.name, "event": event.name, "fields": fields,
                          "format_path": str(path),
                          "evidence_source": EvidenceSource.NATIVE_TRACEPOINT.value,
                          "confidence": Confidence.STRONG.value,
                          "object_identity_field": None, "semantic_reason_field": None,
                          "actual_refcount_field": None,
                          "warning": "format discovery alone proves no semantic fields"})
    if not found:
        warnings.append("no readable runtime tracepoint formats; manual mode")
    return AdapterReport(EvidenceSource.NATIVE_TRACEPOINT, True,
                         "inspected" if found else "manual",
                         observations=tuple(found), warnings=tuple(warnings))


def adapt_native_tracepoint_record(record: Mapping[str, Any], field_map: Mapping[str, str],
                                   available_fields: Iterable[str]) -> dict[str, Any]:
    """Use only explicitly mapped fields from a discovered tracepoint format."""
    if not isinstance(record, Mapping) or not isinstance(field_map, Mapping):
        raise ValueError("native record and field_map must be mappings")
    known = set(available_fields)
    unknown = set(field_map.values()) - known
    if unknown:
        raise ValueError(f"field_map fields absent from format: {sorted(unknown)}")
    allowed = {"object_identity", "semantic_reason", "actual_refcount"}
    if set(field_map) - allowed:
        raise ValueError("unsupported native tracepoint field role")
    values = {role: record.get(field) for role, field in field_map.items()}
    warnings = []
    if values.get("object_identity") is None:
        warnings.append("object identity unavailable")
    if values.get("semantic_reason") is None:
        warnings.append("semantic reason unavailable; not inferred")
    refcount = values.get("actual_refcount")
    if refcount is None:
        warnings.append("actual refcount unavailable")
    elif isinstance(refcount, bool) or not isinstance(refcount, int):
        raise ValueError("actual_refcount must be an integer")
    claims = []
    if values.get("semantic_reason") is not None:
        claims.append(EvidenceClaim(values["semantic_reason"],
                                    EvidenceSource.NATIVE_TRACEPOINT, Confidence.STRONG))
    return {"evidence_source": EvidenceSource.NATIVE_TRACEPOINT.value,
            "confidence": Confidence.STRONG.value,
            "object_identity": values.get("object_identity"),
            "semantic_reason": values.get("semantic_reason"),
            "actual_refcount": refcount,
            "source": {"system": record.get("system"), "tracepoint": record.get("tracepoint"),
                       "format_fields": sorted(known)},
            "claims": [c.value for c in claims], "warnings": warnings}


def adapt_ref_tracker_records(records: Iterable[Mapping[str, Any]]) -> AdapterReport:
    """Pair exclusively on direct unique tracker-token identity."""
    events = []
    for index, item in enumerate(records):
        if not isinstance(item, Mapping):
            raise ValueError(f"tracker record {index} must be a mapping")
        event_id, operation, token = item.get("event_id"), item.get("operation"), item.get("token_id")
        role = {"acquire": "acquisition", "release": "release"}.get(operation)
        if not isinstance(event_id, str) or not event_id:
            raise ValueError(f"tracker record {index} requires event_id")
        if role is None:
            raise ValueError(f"tracker record {index} operation must be acquire or release")
        if token is not None and (not isinstance(token, str) or not token):
            raise ValueError(f"tracker record {index} token_id must be nonempty or null")
        events.append(ReferenceEvent(
            event_id, role, EvidenceSource.REF_TRACKER,
            Confidence.EXACT if token is not None else Confidence.INFERRED,
            token_id=token, semantic_reason=item.get("semantic_reason"),
            stack=item.get("stack"), source_location=item.get("source_location")))

    acquisitions = [e for e in events if e.role == "acquisition"]
    releases = [e for e in events if e.role == "release"]
    edges, warnings, used = [], [], set()
    for acq in acquisitions:
        token = acq.token_id
        if token is None:
            edges.append(ReferenceEvidence(
                EvidenceSource.REF_TRACKER, Confidence.INFERRED,
                acquisition_event=acq.event_id, semantic_reason=acq.semantic_reason,
                acquisition_stack=acq.stack, source_location=acq.source_location,
                unresolved_reason="TOKEN_ID_UNAVAILABLE"))
            warnings.append(f"acquisition {acq.event_id} has no tracker token")
            continue
        same_acqs = [e for e in acquisitions if e.token_id == token]
        matches = [e for e in releases if e.token_id == token]
        if len(same_acqs) != 1 or len(matches) > 1:
            edges.append(ReferenceEvidence(
                EvidenceSource.REF_TRACKER, Confidence.INFERRED,
                acquisition_event=acq.event_id, token_id=token,
                semantic_reason=acq.semantic_reason, acquisition_stack=acq.stack,
                source_location=acq.source_location, unresolved_reason="AMBIGUOUS_PAIRING",
                candidate_release_events=tuple(sorted(e.event_id for e in matches))))
            warnings.append(f"tracker token {token} has ambiguous acquisition/release identity")
        elif len(matches) == 1:
            rel = matches[0]
            edges.append(ReferenceEvidence(
                EvidenceSource.REF_TRACKER, Confidence.EXACT,
                acquisition_event=acq.event_id, release_event=rel.event_id,
                semantic_reason=acq.semantic_reason, token_id=token,
                acquisition_stack=acq.stack, release_stack=rel.stack,
                source_location=acq.source_location))
            used.add(rel.event_id)
        else:
            edges.append(ReferenceEvidence(
                EvidenceSource.REF_TRACKER, Confidence.INFERRED,
                acquisition_event=acq.event_id, token_id=token,
                semantic_reason=acq.semantic_reason, acquisition_stack=acq.stack,
                source_location=acq.source_location, unresolved_reason="MISSING_RELEASE"))
    for rel in releases:
        if rel.event_id in used:
            continue
        has_acq = rel.token_id is not None and any(a.token_id == rel.token_id for a in acquisitions)
        if not has_acq:
            edges.append(ReferenceEvidence(
                EvidenceSource.REF_TRACKER, Confidence.INFERRED,
                release_event=rel.event_id, token_id=rel.token_id,
                semantic_reason=rel.semantic_reason, release_stack=rel.stack,
                source_location=rel.source_location,
                unresolved_reason="TOKEN_ID_UNAVAILABLE" if rel.token_id is None
                                  else "MISSING_ACQUISITION"))
            warnings.append(f"release {rel.event_id} has no matched acquisition")
    return AdapterReport(EvidenceSource.REF_TRACKER, bool(events),
                         "inspected" if events else "manual",
                         edges=tuple(edges), warnings=tuple(warnings))


def adapt_btf_kfunc_metadata(metadata: Mapping[str, Any] | None) -> AdapterReport:
    """Require registration and BPF-visible object applicability; BTF alone is not enough."""
    if not isinstance(metadata, Mapping) or metadata.get("available") is not True:
        return AdapterReport(EvidenceSource.BTF_KFUNC, False, "manual",
                             warnings=("BTF/kfunc metadata unavailable; manual mode",))
    claims, warnings = [], []
    for index, item in enumerate(metadata.get("kfuncs", [])):
        if not isinstance(item, Mapping):
            warnings.append(f"kfunc metadata item {index} is malformed")
            continue
        name, tag = item.get("function"), item.get("tag")
        if item.get("registered") is not True or not item.get("bpf_visible_object"):
            warnings.append(f"{name or 'unnamed kfunc'} ignored: registration/applicability unproven")
            continue
        role = {"KF_ACQUIRE": "acquire", "KF_RELEASE": "release"}.get(tag)
        if role is None or not isinstance(name, str) or not name:
            warnings.append(f"{name or 'unnamed kfunc'} ignored: unsupported tag or function")
            continue
        claims.append(EvidenceClaim({"function": name, "role": role,
                                     "object_type": item["bpf_visible_object"], "tag": tag},
                                    EvidenceSource.BTF_KFUNC, Confidence.STRONG))
    if not claims:
        warnings.append("no applicable registered BPF kfunc metadata; manual mode")
    return AdapterReport(EvidenceSource.BTF_KFUNC, True,
                         "inspected" if claims else "manual",
                         claims=tuple(claims), warnings=tuple(warnings))


def resolve_adapter_claims(claims: Iterable[EvidenceClaim]) -> tuple[EvidenceResolution, tuple[str, ...]]:
    resolution = resolve_claims(claims)
    warnings = ()
    if resolution.unresolved_reason == "CONFLICTING_EVIDENCE_SOURCES":
        warnings = ("conflicting equal-priority sources retained: " +
                    ", ".join(s.value for s in resolution.conflicting_sources),)
    elif resolution.conflicting_sources:
        warnings = ("lower-priority sources disagree: " +
                    ", ".join(s.value for s in resolution.conflicting_sources),)
    return resolution, warnings
