#!/usr/bin/env python3
"""Unit tests for v0.2 versioned reference provenance."""
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))
from provenance.model import (
    Confidence, EvidenceClaim, EvidenceSource, ReferenceEvent, ReferenceEvidence,
    ReferenceTransfer, downgrade_confidence, pair_reference_events, resolve_claims,
    resolve_transfer,
)


def ref_event(event_id, role, source=EvidenceSource.REF_TRACKER,
              token_id=None, reason="WORK", confidence=Confidence.STRONG):
    return ReferenceEvent(
        event_id=event_id, role=role, evidence_source=source,
        confidence=confidence, token_id=token_id, semantic_reason=reason,
        stack={"fingerprint": f"stack:{event_id}"},
        source_location={"file": "rxrpc.c", "line": 17},
    )


def test_exact_token_identity_and_round_trip():
    acquisition = ref_event("event-a", "acquisition", token_id="tracker-42",
                            confidence=Confidence.EXACT)
    release = ref_event("event-r", "release", token_id="tracker-42",
                        confidence=Confidence.EXACT)
    edge = pair_reference_events(acquisition, [release])
    assert edge.schema_version == 1
    assert edge.acquisition_event == "event-a"
    assert edge.release_event == "event-r"
    assert edge.token_id == "tracker-42"
    assert edge.identity_is_exact and edge.confidence is Confidence.EXACT
    assert edge.to_dict()["evidence_source"] == "ref_tracker"
    assert ReferenceEvidence.from_dict(edge.to_dict()) == edge

    # A unique semantic reason may infer a strong pair but never exact identity.
    no_token = pair_reference_events(
        ref_event("event-a2", "acquisition", source=EvidenceSource.EXPLICIT_TARGET,
                  token_id=None),
        [ref_event("event-r2", "release", source=EvidenceSource.EXPLICIT_TARGET,
                   token_id=None)],
    )
    assert no_token.release_event == "event-r2"
    assert no_token.confidence is Confidence.STRONG
    assert no_token.pairing_method == "semantic_reason"
    assert no_token.identity_is_exact is False
    assert no_token.unresolved_reason is None


def test_missing_release_is_explicit():
    acquisition = ref_event("event-a", "acquisition", source=EvidenceSource.NATIVE_TRACEPOINT)
    edge = pair_reference_events(acquisition, [])
    assert edge.acquisition_event == "event-a"
    assert edge.release_event is None
    assert edge.unresolved_reason == "MISSING_RELEASE"
    assert edge.resolved is False
    assert edge.confidence is Confidence.INFERRED


def test_unknown_source_is_rejected():
    value = {
        "schema_version": 1,
        "acquisition_event": "event-a",
        "release_event": "event-r",
        "evidence_source": "guessed_from_magic",
        "confidence": "STRONG",
    }
    try:
        ReferenceEvidence.from_dict(value)
    except ValueError as exc:
        assert "unknown evidence source" in str(exc)
    else:
        raise AssertionError("unknown evidence source was accepted")


def test_ambiguous_pairing_stays_unresolved():
    acquisition = ref_event("event-a", "acquisition",
                            source=EvidenceSource.EXPLICIT_TARGET)
    releases = [
        ref_event("event-r1", "release", source=EvidenceSource.EXPLICIT_TARGET),
        ref_event("event-r2", "release", source=EvidenceSource.EXPLICIT_TARGET),
    ]
    edge = pair_reference_events(acquisition, releases)
    assert edge.release_event is None
    assert edge.candidate_release_events == ("event-r1", "event-r2")
    assert edge.unresolved_reason == "AMBIGUOUS_PAIRING"
    assert edge.resolved is False
    assert edge.identity_is_exact is False
    assert edge.ambiguous is True
    assert [item["release_event"] for item in edge.candidate_hypotheses] == ["event-r1", "event-r2"]


def test_unique_reason_is_strong_and_multiple_same_reason_remains_ambiguous():
    acquisition = ref_event("a", "acquisition", source=EvidenceSource.NATIVE_TRACEPOINT,
                            reason={"reason": "owner_release"})
    unique = ref_event("r1", "release", source=EvidenceSource.NATIVE_TRACEPOINT,
                       reason={"reason": "owner_release"})
    edge = pair_reference_events(acquisition, [unique])
    assert edge.release_event == "r1" and edge.pairing_method == "semantic_reason"
    assert edge.confidence is Confidence.STRONG and not edge.identity_is_exact

    tied = [unique, ref_event("r2", "release", source=EvidenceSource.NATIVE_TRACEPOINT,
                              reason={"reason": "owner_release"})]
    ambiguous = pair_reference_events(acquisition, tied)
    assert ambiguous.release_event is None and ambiguous.ambiguous
    assert ambiguous.unresolved_reason == "AMBIGUOUS_PAIRING"
    assert {item["release_event"] for item in ambiguous.candidate_hypotheses} == {"r1", "r2"}
    assert ambiguous.confidence is Confidence.INFERRED

    mismatched_tracker = pair_reference_events(
        ref_event("a-token", "acquisition", token_id="token-A"),
        [ref_event("r-token", "release", token_id="token-B")],
    )
    assert mismatched_tracker.release_event is None
    assert mismatched_tracker.unresolved_reason == "TOKEN_ID_MISMATCH"


def test_stable_path_precedes_sequence_and_sequence_is_last_resort():
    acquisition = ReferenceEvent("a", "acquisition", EvidenceSource.SOURCE_ANALYSIS,
                                 stack={"fingerprint": "logical:path"}, sequence_index=3)
    path_release = ReferenceEvent("r-path", "release", EvidenceSource.SOURCE_ANALYSIS,
                                  stack={"fingerprint": "logical:path"}, sequence_index=9)
    next_release = ReferenceEvent("r-next", "release", EvidenceSource.SOURCE_ANALYSIS,
                                  stack={"fingerprint": "other"}, sequence_index=4)
    edge = pair_reference_events(acquisition, [next_release, path_release])
    assert edge.release_event == "r-path" and edge.pairing_method == "stable_stack_path"
    assert edge.confidence is Confidence.INFERRED

    no_stack = ReferenceEvent("a2", "acquisition", EvidenceSource.SOURCE_ANALYSIS,
                              sequence_index=3)
    sequence = pair_reference_events(no_stack, [next_release, path_release])
    assert sequence.release_event == "r-next"
    assert sequence.pairing_method == "differential_sequence"
    assert sequence.confidence is Confidence.INFERRED


def test_pairing_ignores_cpu_and_thread_for_async_lifetime():
    acquisition = ReferenceEvent("send-get", "acquisition", EvidenceSource.NATIVE_TRACEPOINT,
                                 semantic_reason="async-work", thread_id=101, cpu=0)
    release = ReferenceEvent("worker-put", "release", EvidenceSource.NATIVE_TRACEPOINT,
                             semantic_reason="async-work", thread_id=202, cpu=3)
    edge = pair_reference_events(acquisition, [release])
    assert edge.release_event == "worker-put" and edge.confidence is Confidence.STRONG


def test_transfer_models_all_stages_and_missing_receive_warning():
    annotation = {"from": "foo_queue_work", "to": "foo_work_handler",
                  "key": "arg0", "kind": "workqueue"}
    events = [
        ReferenceEvent("send-get", "acquisition", EvidenceSource.EXPLICIT_TARGET,
                       function="foo_queue_work", thread_id=1, cpu=0),
        ReferenceEvent("queue", "transfer", EvidenceSource.EXPLICIT_TARGET,
                       function="foo_queue_work", thread_id=1, cpu=0),
        ReferenceEvent("worker-get", "acquisition", EvidenceSource.EXPLICIT_TARGET,
                       function="foo_work_handler", thread_id=2, cpu=3),
        ReferenceEvent("worker-put", "release", EvidenceSource.EXPLICIT_TARGET,
                       function="foo_work_handler", thread_id=2, cpu=3),
    ]
    transfer = resolve_transfer(annotation, events)
    assert transfer.resolved and transfer.confidence is Confidence.STRONG
    assert transfer.to_dict()["ownership_proven"] is False
    assert transfer.sending_acquisition_event == "send-get"
    assert transfer.receiving_acquisition_event == "worker-get"
    assert transfer.receiving_release_event == "worker-put"

    missing = resolve_transfer(annotation, events[:2] + events[3:])
    assert not missing.resolved
    assert missing.unresolved_reason == "MISSING_RECEIVE_SIDE_ACQUISITION"
    assert "MISSING_RECEIVE_SIDE_ACQUISITION" in missing.warnings
    assert missing.confidence is Confidence.INFERRED


def test_conflicting_evidence_sources_and_priority():
    # Explicit target and native semantic tracepoint share the strongest tier;
    # conflicting role claims cannot be silently selected.
    tied_conflict = resolve_claims([
        EvidenceClaim("acquire", EvidenceSource.EXPLICIT_TARGET, Confidence.STRONG),
        EvidenceClaim("release", EvidenceSource.NATIVE_TRACEPOINT, Confidence.STRONG),
    ])
    assert tied_conflict.value is None
    assert tied_conflict.evidence_source is None
    assert tied_conflict.unresolved_reason == "CONFLICTING_EVIDENCE_SOURCES"
    assert tied_conflict.confidence is Confidence.INFERRED

    # The explicit semantic claim wins over a lower-priority name guess, while
    # the contradiction remains visible and lowers confidence.
    prioritized = resolve_claims([
        EvidenceClaim("acquire", EvidenceSource.EXPLICIT_TARGET, Confidence.STRONG),
        EvidenceClaim("release", EvidenceSource.NAME_HEURISTIC, Confidence.INFERRED),
    ])
    assert prioritized.value == "acquire"
    assert prioritized.evidence_source is EvidenceSource.EXPLICIT_TARGET
    assert prioritized.conflicting_sources == (EvidenceSource.NAME_HEURISTIC,)
    assert prioritized.confidence is Confidence.INFERRED


def test_confidence_downgrade_and_source_caps():
    assert downgrade_confidence(Confidence.EXACT) is Confidence.STRONG
    assert downgrade_confidence(Confidence.STRONG, 1) is Confidence.INFERRED
    guessed = EvidenceClaim("acquire", EvidenceSource.NAME_HEURISTIC, Confidence.STRONG)
    assert guessed.confidence is Confidence.INFERRED
    heuristic_edge = ReferenceEvidence(
        evidence_source=EvidenceSource.NAME_HEURISTIC,
        confidence=Confidence.STRONG,
        acquisition_event="event-a",
        release_event="event-r",
    )
    assert heuristic_edge.confidence is Confidence.INFERRED

    tracker_acq = ref_event("event-a", "acquisition", token_id="tracker-7",
                            confidence=Confidence.EXACT)
    duplicate_releases = [
        ref_event("event-r1", "release", token_id="tracker-7"),
        ref_event("event-r2", "release", token_id="tracker-7"),
    ]
    ambiguous = pair_reference_events(tracker_acq, duplicate_releases)
    assert ambiguous.unresolved_reason == "AMBIGUOUS_PAIRING"
    assert ambiguous.confidence is Confidence.INFERRED
    assert ambiguous.identity_is_exact is False


def test_source_priority_order_is_strict():
    sources = [EvidenceSource.EXPLICIT_TARGET, EvidenceSource.NATIVE_TRACEPOINT,
               EvidenceSource.REF_TRACKER, EvidenceSource.BTF_KFUNC,
               EvidenceSource.SOURCE_ANALYSIS, EvidenceSource.NAME_HEURISTIC]
    claims = [EvidenceClaim("candidate", source, Confidence.STRONG) for source in sources]
    resolved = resolve_claims(claims)
    assert resolved.evidence_source is EvidenceSource.EXPLICIT_TARGET
    assert resolved.confidence is Confidence.STRONG
    assert resolved.supporting_sources == tuple(sorted(
        sources, key=lambda item: item.value))


def main():
    tests = [
        test_exact_token_identity_and_round_trip,
        test_missing_release_is_explicit,
        test_unknown_source_is_rejected,
        test_ambiguous_pairing_stays_unresolved,
        test_unique_reason_is_strong_and_multiple_same_reason_remains_ambiguous,
        test_stable_path_precedes_sequence_and_sequence_is_last_resort,
        test_pairing_ignores_cpu_and_thread_for_async_lifetime,
        test_transfer_models_all_stages_and_missing_receive_warning,
        test_conflicting_evidence_sources_and_priority,
        test_confidence_downgrade_and_source_caps,
        test_source_priority_order_is_strict,
    ]
    for test in tests:
        test()
    print(f"Reference provenance model tests: {len(tests)} passed")


if __name__ == "__main__":
    main()
