"""Versioned provenance evidence model and conservative reference pairing."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import json
from typing import Any, Iterable

SCHEMA_VERSION = 1


class EvidenceSource(str, Enum):
    EXPLICIT_TARGET = "explicit_target"
    NATIVE_TRACEPOINT = "native_tracepoint"
    REF_TRACKER = "ref_tracker"
    BTF_KFUNC = "btf_kfunc"
    SOURCE_ANALYSIS = "source_analysis"
    NAME_HEURISTIC = "name_heuristic"


class Confidence(str, Enum):
    EXACT = "EXACT"
    STRONG = "STRONG"
    INFERRED = "INFERRED"
    UNKNOWN = "UNKNOWN"


# Lower numbers are more authoritative. Explicit target semantics and native
# semantic tracepoints share the top tier; ties that disagree remain unresolved.
EVIDENCE_SOURCE_PRIORITY = {
    EvidenceSource.EXPLICIT_TARGET: 0,
    EvidenceSource.NATIVE_TRACEPOINT: 0,
    EvidenceSource.REF_TRACKER: 1,
    EvidenceSource.BTF_KFUNC: 2,
    EvidenceSource.SOURCE_ANALYSIS: 3,
    EvidenceSource.NAME_HEURISTIC: 4,
}

_CONFIDENCE_RANK = {
    Confidence.UNKNOWN: 0,
    Confidence.INFERRED: 1,
    Confidence.STRONG: 2,
    Confidence.EXACT: 3,
}
_RANK_CONFIDENCE = {rank: confidence for confidence, rank in _CONFIDENCE_RANK.items()}
_SOURCE_CONFIDENCE_CAP = {
    EvidenceSource.EXPLICIT_TARGET: Confidence.STRONG,
    EvidenceSource.NATIVE_TRACEPOINT: Confidence.STRONG,
    EvidenceSource.REF_TRACKER: Confidence.EXACT,
    EvidenceSource.BTF_KFUNC: Confidence.STRONG,
    EvidenceSource.SOURCE_ANALYSIS: Confidence.INFERRED,
    EvidenceSource.NAME_HEURISTIC: Confidence.INFERRED,
}


def _enum(value: Any, enum_type: type[Enum], field: str) -> Any:
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"unknown {field}: {value!r}") from exc


def _cap_confidence(confidence: Confidence, source: EvidenceSource,
                    *, direct_identity: bool = False,
                    unresolved: bool = False) -> Confidence:
    cap = _SOURCE_CONFIDENCE_CAP[source]
    if source is EvidenceSource.REF_TRACKER and not direct_identity:
        cap = Confidence.STRONG
    rank = min(_CONFIDENCE_RANK[confidence], _CONFIDENCE_RANK[cap])
    if unresolved:
        rank = min(rank, _CONFIDENCE_RANK[Confidence.INFERRED])
    return _RANK_CONFIDENCE[rank]


def _cap_pairing_confidence(confidence: Confidence, method: str,
                            *, unresolved: bool = False) -> Confidence:
    cap = Confidence.STRONG if method == "semantic_reason" else Confidence.INFERRED
    rank = min(_CONFIDENCE_RANK[confidence], _CONFIDENCE_RANK[cap])
    if unresolved:
        rank = min(rank, _CONFIDENCE_RANK[Confidence.INFERRED])
    return _RANK_CONFIDENCE[rank]


def downgrade_confidence(confidence: Confidence | str, steps: int = 1) -> Confidence:
    """Lower confidence conservatively; UNKNOWN is a floor."""
    current = _enum(confidence, Confidence, "confidence")
    if isinstance(steps, bool) or not isinstance(steps, int) or steps < 0:
        raise ValueError("confidence downgrade steps must be a nonnegative integer")
    return _RANK_CONFIDENCE[max(0, _CONFIDENCE_RANK[current] - steps)]


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


@dataclass(frozen=True)
class EvidenceClaim:
    """One source's claim about a semantic field; confidence belongs to the claim."""

    value: Any
    evidence_source: EvidenceSource | str
    confidence: Confidence | str

    def __post_init__(self) -> None:
        source = _enum(self.evidence_source, EvidenceSource, "evidence source")
        confidence = _enum(self.confidence, Confidence, "confidence")
        object.__setattr__(self, "evidence_source", source)
        object.__setattr__(self, "confidence",
                           _cap_confidence(confidence, source))


@dataclass(frozen=True)
class EvidenceResolution:
    value: Any
    evidence_source: EvidenceSource | None
    confidence: Confidence
    unresolved_reason: str | None = None
    supporting_sources: tuple[EvidenceSource, ...] = ()
    conflicting_sources: tuple[EvidenceSource, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "evidence_source": self.evidence_source.value if self.evidence_source else None,
            "confidence": self.confidence.value,
            "unresolved_reason": self.unresolved_reason,
            "supporting_sources": [source.value for source in self.supporting_sources],
            "conflicting_sources": [source.value for source in self.conflicting_sources],
        }


def resolve_claims(claims: Iterable[EvidenceClaim]) -> EvidenceResolution:
    """Select the highest-priority evidence without concealing equal-tier conflict.

    A lower-priority contradiction cannot override a stronger source, but it does
    lower the selected confidence by one level and remains listed in the result.
    Conflicting claims at the same best priority are explicitly unresolved.
    """
    items = list(claims)
    if not items:
        return EvidenceResolution(None, None, Confidence.UNKNOWN,
                                  unresolved_reason="NO_EVIDENCE")

    best_priority = min(EVIDENCE_SOURCE_PRIORITY[item.evidence_source]
                        for item in items)
    leaders = [item for item in items
               if EVIDENCE_SOURCE_PRIORITY[item.evidence_source] == best_priority]
    leader_values = {_canonical(item.value) for item in leaders}
    if len(leader_values) > 1:
        sources = tuple(sorted({item.evidence_source for item in leaders},
                               key=lambda source: source.value))
        return EvidenceResolution(
            None, None, Confidence.INFERRED,
            unresolved_reason="CONFLICTING_EVIDENCE_SOURCES",
            supporting_sources=sources,
            conflicting_sources=sources,
        )

    selected_value = leaders[0].value
    selected_source = min((item.evidence_source for item in leaders),
                          key=lambda source: source.value)
    confidence = max((item.confidence for item in leaders),
                     key=lambda level: _CONFIDENCE_RANK[level])
    lower_conflicts = [item for item in items
                       if EVIDENCE_SOURCE_PRIORITY[item.evidence_source] > best_priority
                       and _canonical(item.value) != _canonical(selected_value)]
    if lower_conflicts:
        confidence = downgrade_confidence(confidence)
    supporting = tuple(sorted({item.evidence_source for item in items
                               if _canonical(item.value) == _canonical(selected_value)},
                              key=lambda source: source.value))
    conflicting = tuple(sorted({item.evidence_source for item in lower_conflicts},
                               key=lambda source: source.value))
    return EvidenceResolution(selected_value, selected_source, confidence,
                              supporting_sources=supporting,
                              conflicting_sources=conflicting)


@dataclass(frozen=True)
class ReferenceEvent:
    event_id: str
    role: str
    evidence_source: EvidenceSource | str
    confidence: Confidence | str = Confidence.UNKNOWN
    token_id: str | None = None
    semantic_reason: Any = None
    stack: Any = None
    source_location: dict[str, Any] | None = None
    path_signature: str | None = None
    sequence_index: int | None = None
    thread_id: int | str | None = None
    cpu: int | None = None
    function: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.event_id, str) or not self.event_id:
            raise ValueError("event_id must be a nonempty string")
        if self.role not in {"acquisition", "release", "transfer"}:
            raise ValueError("event role must be acquisition, release, or transfer")
        source = _enum(self.evidence_source, EvidenceSource, "evidence source")
        confidence = _enum(self.confidence, Confidence, "confidence")
        object.__setattr__(self, "evidence_source", source)
        object.__setattr__(self, "confidence",
                           _cap_confidence(confidence, source,
                                           direct_identity=(source is EvidenceSource.REF_TRACKER
                                                            and self.token_id is not None)))
        if self.token_id is not None and (not isinstance(self.token_id, str)
                                          or not self.token_id):
            raise ValueError("token_id must be a nonempty string when present")
        if self.source_location is not None and not isinstance(self.source_location, dict):
            raise ValueError("source_location must be an object when present")
        if self.path_signature is not None and (not isinstance(self.path_signature, str)
                                                or not self.path_signature):
            raise ValueError("path_signature must be a nonempty string when present")
        if self.sequence_index is not None and (isinstance(self.sequence_index, bool)
                                                or not isinstance(self.sequence_index, int)):
            raise ValueError("sequence_index must be an integer when present")
        if self.cpu is not None and (isinstance(self.cpu, bool) or not isinstance(self.cpu, int)
                                     or self.cpu < 0):
            raise ValueError("cpu must be a nonnegative integer when present")
        if self.function is not None and (not isinstance(self.function, str) or not self.function):
            raise ValueError("function must be a nonempty string when present")


@dataclass(frozen=True)
class ReferenceEvidence:
    """Versioned provenance edge; endpoints may remain unresolved/ambiguous."""

    evidence_source: EvidenceSource | str
    confidence: Confidence | str
    acquisition_event: str | None = None
    release_event: str | None = None
    semantic_reason: Any = None
    token_id: str | None = None
    acquisition_stack: Any = None
    release_stack: Any = None
    source_location: dict[str, Any] | None = None
    unresolved_reason: str | None = None
    candidate_release_events: tuple[str, ...] = ()
    pairing_method: str | None = None
    ambiguous: bool = False
    candidate_hypotheses: tuple[dict[str, Any], ...] = ()
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if isinstance(self.schema_version, bool) or self.schema_version != SCHEMA_VERSION:
            raise ValueError(f"unsupported ReferenceEvidence schema_version: {self.schema_version!r}")
        source = _enum(self.evidence_source, EvidenceSource, "evidence source")
        confidence = _enum(self.confidence, Confidence, "confidence")
        object.__setattr__(self, "evidence_source", source)
        if self.pairing_method not in {None, "tracker_token", "semantic_reason",
                                       "stable_stack_path", "differential_sequence"}:
            raise ValueError(f"unknown pairing_method: {self.pairing_method!r}")
        if not isinstance(self.ambiguous, bool):
            raise ValueError("ambiguous must be a boolean")
        if self.acquisition_event is not None and (not isinstance(self.acquisition_event, str)
                                                    or not self.acquisition_event):
            raise ValueError("acquisition_event must be a nonempty event id when present")
        if self.release_event is not None and (not isinstance(self.release_event, str)
                                                or not self.release_event):
            raise ValueError("release_event must be a nonempty event id when present")
        if self.token_id is not None and (not isinstance(self.token_id, str) or not self.token_id):
            raise ValueError("token_id must be a nonempty string when present")
        if self.source_location is not None and not isinstance(self.source_location, dict):
            raise ValueError("source_location must be an object when present")

        reason = self.unresolved_reason
        if self.release_event is None and reason is None:
            if len(self.candidate_release_events) > 1:
                reason = "AMBIGUOUS_PAIRING"
            elif self.acquisition_event is not None:
                reason = "MISSING_RELEASE"
            else:
                reason = "MISSING_ACQUISITION_AND_RELEASE"
        elif self.acquisition_event is None and reason is None:
            reason = "MISSING_ACQUISITION"
        object.__setattr__(self, "unresolved_reason", reason)

        candidates = tuple(self.candidate_release_events)
        if any(not isinstance(item, str) or not item for item in candidates):
            raise ValueError("candidate release event ids must be nonempty strings")
        if len(set(candidates)) != len(candidates):
            raise ValueError("candidate release event ids must be unique")
        object.__setattr__(self, "candidate_release_events", candidates)
        if any(not isinstance(item, dict) for item in self.candidate_hypotheses):
            raise ValueError("candidate hypotheses must be mappings")
        hypotheses = tuple(dict(item) for item in self.candidate_hypotheses)
        if any(not isinstance(item.get("release_event"), str) or not item["release_event"]
               for item in hypotheses):
            raise ValueError("candidate hypotheses must identify a release_event")
        object.__setattr__(self, "candidate_hypotheses", hypotheses)
        object.__setattr__(self, "ambiguous", self.ambiguous or len(hypotheses) > 1 or
                           (reason == "AMBIGUOUS_PAIRING" and len(candidates) > 1))
        direct_identity = (source is EvidenceSource.REF_TRACKER
                           and self.token_id is not None
                           and self.acquisition_event is not None
                           and self.release_event is not None
                           and reason is None)
        if self.pairing_method in {"semantic_reason", "stable_stack_path", "differential_sequence"}:
            confidence = _cap_pairing_confidence(confidence, self.pairing_method,
                                                 unresolved=reason is not None)
        else:
            confidence = _cap_confidence(confidence, source,
                                         direct_identity=direct_identity,
                                         unresolved=reason is not None)
        object.__setattr__(self, "confidence", confidence)

    @property
    def identity_is_exact(self) -> bool:
        return (self.evidence_source is EvidenceSource.REF_TRACKER
                and self.token_id is not None
                and self.acquisition_event is not None
                and self.release_event is not None
                and self.unresolved_reason is None
                and self.confidence is Confidence.EXACT)

    @property
    def resolved(self) -> bool:
        return (self.acquisition_event is not None and self.release_event is not None
                and self.unresolved_reason is None)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "acquisition_event": self.acquisition_event,
            "release_event": self.release_event,
            "semantic_reason": self.semantic_reason,
            "token_id": self.token_id,
            "acquisition_stack": self.acquisition_stack,
            "release_stack": self.release_stack,
            "source_location": self.source_location,
            "evidence_source": self.evidence_source.value,
            "confidence": self.confidence.value,
            "unresolved_reason": self.unresolved_reason,
            "candidate_release_events": list(self.candidate_release_events),
            "pairing_method": self.pairing_method,
            "ambiguous": self.ambiguous,
            "candidate_hypotheses": list(self.candidate_hypotheses),
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ReferenceEvidence":
        if not isinstance(value, dict):
            raise ValueError("ReferenceEvidence must be an object")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise ValueError(f"unsupported ReferenceEvidence schema_version: {value.get('schema_version')!r}")
        allowed = {
            "schema_version", "acquisition_event", "release_event", "semantic_reason",
            "token_id", "acquisition_stack", "release_stack", "source_location",
            "evidence_source", "confidence", "unresolved_reason", "candidate_release_events",
            "pairing_method", "ambiguous", "candidate_hypotheses",
        }
        unknown = set(value) - allowed
        if unknown:
            raise ValueError(f"unknown ReferenceEvidence fields: {sorted(unknown)}")
        if "evidence_source" not in value:
            raise ValueError("missing evidence_source")
        if "confidence" not in value:
            raise ValueError("missing confidence")
        fields = dict(value)
        fields.setdefault("candidate_release_events", ())
        fields.setdefault("candidate_hypotheses", ())
        return cls(**fields)


def pair_reference_events(acquisition: ReferenceEvent,
                          release_candidates: Iterable[ReferenceEvent]) -> ReferenceEvidence:
    """Pair by evidence priority; inferred compatibility is not ownership proof."""
    if acquisition.role != "acquisition":
        raise ValueError("acquisition event must have role='acquisition'")
    releases = [event for event in release_candidates if event.role == "release"]
    exact_matches = []
    if (acquisition.evidence_source is EvidenceSource.REF_TRACKER
            and acquisition.token_id is not None):
        exact_matches = [event for event in releases
                         if event.evidence_source is EvidenceSource.REF_TRACKER
                         and event.token_id == acquisition.token_id]
    if len(exact_matches) == 1:
        release = exact_matches[0]
        return ReferenceEvidence(
            evidence_source=EvidenceSource.REF_TRACKER,
            confidence=Confidence.EXACT,
            acquisition_event=acquisition.event_id,
            release_event=release.event_id,
            semantic_reason=acquisition.semantic_reason,
            token_id=acquisition.token_id,
            acquisition_stack=acquisition.stack,
            release_stack=release.stack,
            source_location=acquisition.source_location,
            pairing_method="tracker_token",
        )
    if len(exact_matches) > 1:
        candidates = tuple(sorted(event.event_id for event in exact_matches))
        return ReferenceEvidence(
            evidence_source=EvidenceSource.REF_TRACKER,
            confidence=Confidence.INFERRED,
            acquisition_event=acquisition.event_id,
            token_id=acquisition.token_id,
            semantic_reason=acquisition.semantic_reason,
            acquisition_stack=acquisition.stack,
            source_location=acquisition.source_location,
            unresolved_reason="AMBIGUOUS_PAIRING",
            candidate_release_events=candidates,
            pairing_method="tracker_token", ambiguous=True,
            candidate_hypotheses=tuple({"release_event": event.event_id,
                                        "support": "same_tracker_token"}
                                       for event in sorted(exact_matches, key=lambda item: item.event_id)),
        )
    if (acquisition.evidence_source is EvidenceSource.REF_TRACKER
            and acquisition.token_id is not None and not exact_matches):
        return ReferenceEvidence(
            evidence_source=EvidenceSource.REF_TRACKER, confidence=Confidence.INFERRED,
            acquisition_event=acquisition.event_id, semantic_reason=acquisition.semantic_reason,
            token_id=acquisition.token_id, acquisition_stack=acquisition.stack,
            source_location=acquisition.source_location, unresolved_reason="TOKEN_ID_MISMATCH",
            candidate_release_events=tuple(sorted(event.event_id for event in releases)),
            pairing_method="tracker_token",
        )

    def unresolved(matches: list[ReferenceEvent], method: str) -> ReferenceEvidence:
        ordered = sorted(matches, key=lambda item: item.event_id)
        return ReferenceEvidence(
            evidence_source=acquisition.evidence_source, confidence=Confidence.INFERRED,
            acquisition_event=acquisition.event_id, semantic_reason=acquisition.semantic_reason,
            token_id=acquisition.token_id, acquisition_stack=acquisition.stack,
            source_location=acquisition.source_location, unresolved_reason="AMBIGUOUS_PAIRING",
            candidate_release_events=tuple(item.event_id for item in ordered),
            pairing_method=method, ambiguous=True,
            candidate_hypotheses=tuple({"release_event": item.event_id, "support": method}
                                       for item in ordered),
        )

    def resolved(release: ReferenceEvent, method: str, level: Confidence) -> ReferenceEvidence:
        return ReferenceEvidence(
            evidence_source=acquisition.evidence_source, confidence=level,
            acquisition_event=acquisition.event_id, release_event=release.event_id,
            semantic_reason=acquisition.semantic_reason, token_id=acquisition.token_id,
            acquisition_stack=acquisition.stack, release_stack=release.stack,
            source_location=acquisition.source_location, pairing_method=method,
        )

    if acquisition.semantic_reason is not None:
        reason_matches = [event for event in releases if event.semantic_reason is not None
                          and _canonical(event.semantic_reason) == _canonical(acquisition.semantic_reason)]
        if len(reason_matches) == 1:
            return resolved(reason_matches[0], "semantic_reason", Confidence.STRONG)
        if len(reason_matches) > 1:
            return unresolved(reason_matches, "semantic_reason")

    signature = acquisition.path_signature
    if signature is None and isinstance(acquisition.stack, dict):
        signature = acquisition.stack.get("fingerprint")
    if signature:
        stack_matches = []
        for event in releases:
            candidate = event.path_signature
            if candidate is None and isinstance(event.stack, dict):
                candidate = event.stack.get("fingerprint")
            if candidate == signature:
                stack_matches.append(event)
        if len(stack_matches) == 1:
            return resolved(stack_matches[0], "stable_stack_path", Confidence.INFERRED)
        if len(stack_matches) > 1:
            return unresolved(stack_matches, "stable_stack_path")

    if acquisition.sequence_index is not None:
        later = [(event.sequence_index - acquisition.sequence_index, event) for event in releases
                 if event.sequence_index is not None and event.sequence_index > acquisition.sequence_index]
        if later:
            nearest = min(distance for distance, _event in later)
            matches = [event for distance, event in later if distance == nearest]
            if len(matches) == 1:
                return resolved(matches[0], "differential_sequence", Confidence.INFERRED)
            return unresolved(matches, "differential_sequence")

    candidates = tuple(sorted(event.event_id for event in releases))
    if not candidates:
        reason = "MISSING_RELEASE"
    elif len(candidates) > 1:
        reason = "AMBIGUOUS_PAIRING"
    else:
        reason = "INSUFFICIENT_IDENTITY_EVIDENCE"
    return ReferenceEvidence(
        evidence_source=acquisition.evidence_source,
        confidence=downgrade_confidence(acquisition.confidence),
        acquisition_event=acquisition.event_id,
        semantic_reason=acquisition.semantic_reason,
        token_id=acquisition.token_id,
        acquisition_stack=acquisition.stack,
        source_location=acquisition.source_location,
        unresolved_reason=reason,
        candidate_release_events=candidates,
    )


@dataclass(frozen=True)
class ReferenceTransfer:
    """Offline transfer evidence; a transfer annotation is not ownership proof."""
    transfer_id: str
    kind: str
    key: str
    sending_acquisition_event: str | None = None
    transfer_event: str | None = None
    receiving_acquisition_event: str | None = None
    receiving_release_event: str | None = None
    confidence: Confidence | str = Confidence.UNKNOWN
    unresolved_reason: str | None = None
    warnings: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in ("transfer_id", "kind", "key"):
            if not isinstance(getattr(self, name), str) or not getattr(self, name):
                raise ValueError(f"{name} must be a nonempty string")
        confidence = _enum(self.confidence, Confidence, "confidence")
        confidence = _cap_confidence(confidence, EvidenceSource.EXPLICIT_TARGET)
        if self.transfer_event and not self.receiving_acquisition_event:
            warning = "MISSING_RECEIVE_SIDE_ACQUISITION"
            object.__setattr__(self, "warnings", tuple(dict.fromkeys((*self.warnings, warning))))
            object.__setattr__(self, "unresolved_reason", self.unresolved_reason or warning)
            confidence = downgrade_confidence(confidence)
        elif self.unresolved_reason is not None:
            confidence = downgrade_confidence(confidence)
        object.__setattr__(self, "confidence", confidence)

    @property
    def resolved(self) -> bool:
        return (self.sending_acquisition_event is not None and self.transfer_event is not None
                and self.receiving_acquisition_event is not None
                and self.receiving_release_event is not None and self.unresolved_reason is None)

    def to_dict(self) -> dict[str, Any]:
        return {"transfer_id": self.transfer_id, "kind": self.kind, "key": self.key,
                "sending_acquisition_event": self.sending_acquisition_event,
                "transfer_event": self.transfer_event,
                "receiving_acquisition_event": self.receiving_acquisition_event,
                "receiving_release_event": self.receiving_release_event,
                "confidence": self.confidence.value, "unresolved_reason": self.unresolved_reason,
                "warnings": list(self.warnings), "ownership_proven": False}


def resolve_transfer(annotation: dict[str, Any], events: Iterable[ReferenceEvent]) -> ReferenceTransfer:
    """Resolve from/to annotations without requiring same task or CPU."""
    if not isinstance(annotation, dict) or any(not isinstance(annotation.get(key), str)
                                                or not annotation[key]
                                                for key in ("from", "to", "key", "kind")):
        raise ValueError("transfer annotation requires nonempty from, to, key, and kind")
    items = list(events)
    sender = [e for e in items if e.function == annotation["from"] and e.role == "acquisition"]
    transfer = [e for e in items if e.function == annotation["from"] and e.role == "transfer"]
    receiver_get = [e for e in items if e.function == annotation["to"] and e.role == "acquisition"]
    receiver_put = [e for e in items if e.function == annotation["to"] and e.role == "release"]
    identity = annotation["from"] + "->" + annotation["to"]
    if any(len(group) > 1 for group in (sender, transfer, receiver_get, receiver_put)):
        return ReferenceTransfer(identity, annotation["kind"], annotation["key"],
                                 unresolved_reason="AMBIGUOUS_TRANSFER_EVENTS",
                                 warnings=("AMBIGUOUS_TRANSFER_EVENTS",))
    reason = None
    if not sender:
        reason = "MISSING_SENDING_SIDE_ACQUISITION"
    elif not transfer:
        reason = "MISSING_TRANSFER_EVENT"
    elif not receiver_get:
        reason = "MISSING_RECEIVE_SIDE_ACQUISITION"
    elif not receiver_put:
        reason = "MISSING_RECEIVE_SIDE_RELEASE"
    warnings = (reason,) if reason == "MISSING_RECEIVE_SIDE_ACQUISITION" else ()
    return ReferenceTransfer(identity, annotation["kind"], annotation["key"],
                             sender[0].event_id if sender else None,
                             transfer[0].event_id if transfer else None,
                             receiver_get[0].event_id if receiver_get else None,
                             receiver_put[0].event_id if receiver_put else None,
                             Confidence.STRONG,
                             reason, warnings)
