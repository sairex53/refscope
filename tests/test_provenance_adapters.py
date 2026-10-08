#!/usr/bin/env python3
"""Tests for conservative native tracepoint, ref_tracker and BTF adapters."""
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from provenance.adapters import (
    adapt_btf_kfunc_metadata, adapt_native_tracepoint_record,
    adapt_ref_tracker_records, discover_native_tracepoints, resolve_adapter_claims,
)
from provenance.model import (
    Confidence, EvidenceClaim, EvidenceSource, ReferenceEvidence,
)


def test_native_tracepoint_precedes_name_heuristic_and_maps_observed_fields():
    record = adapt_native_tracepoint_record(
        {"obj": 0x1234, "why": "RXRPC_CALL", "refs": 7,
         "system": "rxrpc", "tracepoint": "rxrpc_ref"},
        {"object_identity": "obj", "semantic_reason": "why", "actual_refcount": "refs"},
        {"obj", "why", "refs"})
    assert record["object_identity"] == 0x1234
    assert record["semantic_reason"] == "RXRPC_CALL"
    assert record["actual_refcount"] == 7
    resolved, warnings = resolve_adapter_claims([
        EvidenceClaim("put", EvidenceSource.NATIVE_TRACEPOINT, Confidence.STRONG),
        EvidenceClaim("get", EvidenceSource.NAME_HEURISTIC, Confidence.INFERRED),
    ])
    assert resolved.value == "put"
    assert resolved.evidence_source is EvidenceSource.NATIVE_TRACEPOINT
    assert resolved.confidence is Confidence.INFERRED
    assert warnings


def test_native_tracepoint_does_not_invent_actual_refcount():
    record = adapt_native_tracepoint_record(
        {"obj": 0x44}, {"object_identity": "obj"}, {"obj"})
    assert record["actual_refcount"] is None
    assert any("actual refcount unavailable" in warning for warning in record["warnings"])


def test_ref_tracker_exact_token_precedes_stack_inference():
    report = adapt_ref_tracker_records([
        {"event_id": "a1", "operation": "acquire", "token_id": "token-9",
         "semantic_reason": "owner", "stack": "acquire-stack"},
        {"event_id": "r1", "operation": "release", "token_id": "token-9",
         "stack": "release-stack"},
    ])
    edge = report.edges[0]
    assert edge.identity_is_exact and edge.confidence is Confidence.EXACT
    resolved, _ = resolve_adapter_claims([
        EvidenceClaim("stack guess", EvidenceSource.SOURCE_ANALYSIS, Confidence.INFERRED),
        EvidenceClaim("token identity", EvidenceSource.REF_TRACKER, Confidence.STRONG),
    ])
    assert resolved.value == "token identity"
    assert resolved.evidence_source is EvidenceSource.REF_TRACKER


def test_ref_tracker_unresolved_and_ambiguous_tokens_are_visible():
    missing = adapt_ref_tracker_records([
        {"event_id": "a", "operation": "acquire", "token_id": None},
        {"event_id": "r", "operation": "release", "token_id": "orphan"},
    ])
    assert {edge.unresolved_reason for edge in missing.edges} == {
        "TOKEN_ID_UNAVAILABLE", "MISSING_ACQUISITION"}
    duplicate = adapt_ref_tracker_records([
        {"event_id": "a1", "operation": "acquire", "token_id": "same"},
        {"event_id": "a2", "operation": "acquire", "token_id": "same"},
        {"event_id": "r", "operation": "release", "token_id": "same"},
    ])
    assert all(edge.unresolved_reason == "AMBIGUOUS_PAIRING" for edge in duplicate.edges[:2])
    assert not any(edge.identity_is_exact for edge in duplicate.edges)


def test_btf_metadata_never_creates_false_exact():
    report = adapt_btf_kfunc_metadata({
        "available": True,
        "kfuncs": [{"function": "bpf_obj_get", "tag": "KF_ACQUIRE",
                    "registered": True, "bpf_visible_object": "struct bpf_obj"}],
    })
    assert report.mode == "inspected"
    assert report.claims[0].confidence is Confidence.STRONG
    edge = ReferenceEvidence(EvidenceSource.BTF_KFUNC, Confidence.EXACT,
                             acquisition_event="a", release_event="r")
    assert edge.confidence is Confidence.STRONG
    assert not edge.identity_is_exact

    ordinary_btf = adapt_btf_kfunc_metadata({
        "available": True,
        "kfuncs": [{"function": "ordinary_get", "tag": "KF_ACQUIRE"}],
    })
    assert ordinary_btf.mode == "manual"
    assert not ordinary_btf.claims
    assert any("registration/applicability unproven" in w for w in ordinary_btf.warnings)


def test_equal_priority_conflict_is_preserved_as_warning():
    resolution, warnings = resolve_adapter_claims([
        EvidenceClaim("acquire", EvidenceSource.NATIVE_TRACEPOINT, Confidence.STRONG),
        EvidenceClaim("release", EvidenceSource.NATIVE_TRACEPOINT, Confidence.STRONG),
    ])
    assert resolution.value is None
    assert resolution.unresolved_reason == "CONFLICTING_EVIDENCE_SOURCES"
    assert resolution.conflicting_sources == (EvidenceSource.NATIVE_TRACEPOINT,)
    assert warnings and "conflicting equal-priority" in warnings[0]


def test_native_discovery_reads_formats_without_enabling_tracepoints():
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary) / "events"
        fmt = root / "demo" / "ref" / "format"
        fmt.parent.mkdir(parents=True)
        fmt.write_text("name: ref\nID: 9\nfield:unsigned long obj;\noffset:8;\n"
                       "field:int reason;\noffset:16;\n")
        report = discover_native_tracepoints(root)
        assert report.available and report.mode == "inspected"
        assert report.observations[0]["fields"] == ["obj", "reason"]
        assert report.observations[0]["actual_refcount_field"] is None


def test_missing_optional_sources_degrade_to_manual_without_breaking_cli():
    native = discover_native_tracepoints("/this/path/does/not/exist")
    btf = adapt_btf_kfunc_metadata(None)
    assert native.mode == "manual" and not native.available
    assert btf.mode == "manual" and not btf.available
    binary = ROOT / "build/refscope"
    result = subprocess.run([str(binary), "--help"], text=True, capture_output=True, check=False)
    assert result.returncode == 0
    assert "Usage: refscope trace" in result.stdout


def main():
    tests = [value for name, value in sorted(globals().items())
             if name.startswith("test_") and callable(value)]
    for test in tests:
        test()
    print(f"Provenance adapter tests: {len(tests)} passed")


if __name__ == "__main__":
    main()
