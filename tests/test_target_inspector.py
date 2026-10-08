#!/usr/bin/env python3
"""Offline target-inspector fixture tests."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))
from provenance.inspector import (analyze_target, _merge_btf_candidates, _source_vmlinux_relation, _yaml_target)
from provenance.target_adapter import target_arguments, translate

FIXTURES = ROOT / "tests/fixtures/target_inspector"
BINARY = ROOT / "build/refscope"


def by_name(report, function):
    return next(item for item in report["all_candidates"] if item["function"] == function)

def analyze_fixture(name):
    with tempfile.TemporaryDirectory() as temp:
        shutil.copyfile(FIXTURES / name, Path(temp) / name)
        return analyze_target("struct foo", Path(temp))



def test_exact_wrapper_uses_body_evidence_not_name():
    report = analyze_fixture("exact_wrapper.c")
    get = by_name(report, "foo_get")
    put = by_name(report, "foo_put")
    assert get["role"] == "acquire" and get["evidence_source"] == "source_analysis"
    assert put["role"] == "release" and put["evidence_source"] == "source_analysis"
    assert get["object_argument"] == "arg0" and get["object_field"] == "refs"
    assert get["confidence"] != "EXACT" and put["confidence"] != "EXACT"


def test_kref_wrapper_candidates():
    report = analyze_fixture("kref_wrapper.c")
    get = by_name(report, "foo_kref_get")
    put = by_name(report, "foo_kref_put")
    assert get["role"] == "acquire" and put["role"] == "release"
    assert get["object_field"] == "ref" and put["object_field"] == "ref"
    assert get["evidence_source"] == "source_analysis"


def test_name_only_is_inferred_heuristic():
    report = analyze_fixture("name_only.c")
    acquire = by_name(report, "foo_hold")
    release = by_name(report, "foo_release_hint")
    assert acquire["role"] == "acquire" and release["role"] == "release"
    assert acquire["evidence_source"] == "name_heuristic"
    assert acquire["confidence"] == "INFERRED"
    assert acquire["confidence"] != "EXACT"


def test_no_btf_and_no_source_tree_manual_mode():
    with tempfile.TemporaryDirectory() as temp:
        empty = Path(temp)
        report = analyze_target("struct absent", empty, None)
    assert report["mode"] == "manual"
    assert report["candidate_acquire_apis"] == []
    assert any("manual mode" in item for item in report["warnings"])
    assert report["btf_kfunc_evidence"]["available"] is False


def test_conflicting_candidates_are_visible_and_downgraded():
    report = analyze_fixture("conflicting.c")
    conflict = by_name(report, "foo_put")
    assert conflict["role"] == "acquire"  # source operation outranks name guess
    assert conflict["confidence"] in {"INFERRED", "UNKNOWN"}
    assert any("conflict" in warning.lower() for warning in conflict["warnings"])
    assert any("conflicting" in warning.lower() for warning in report["warnings"])


def test_ref_tracker_priority_over_source_and_name():
    report = analyze_fixture("ref_tracker_priority.c")
    candidate = by_name(report, "foo_put_tracker")
    assert candidate["role"] == "acquire"
    assert candidate["evidence_source"] == "ref_tracker"
    assert candidate["confidence"] != "EXACT"
    assert report["ref_tracker_evidence"]

def test_btf_kfunc_priority_and_conflict_warning():
    candidate = {
        "function": "foo_put", "role": "release", "object_argument": "arg0",
        "object_field": "refs", "evidence_source": "source_analysis",
        "confidence": "INFERRED", "reasons": ["source wrapper suggests release"],
        "source_location": {"file": "foo.c", "line": 4}, "warnings": [],
    }
    merged = _merge_btf_candidates([candidate], {
        "kfuncs": [{"function": "foo_put", "tag": "KF_ACQUIRE",
                    "registered": True, "bpf_visible_object": "struct foo"}],
    })[0]
    assert merged["role"] == "acquire"
    assert merged["evidence_source"] == "btf_kfunc"
    assert merged["confidence"] != "EXACT"
    assert any("BTF/source role conflict" in warning for warning in merged["warnings"])

    unverified_btf = {"kfuncs": [{"function": "foo_put", "tag": "KF_ACQUIRE"}]}
    unverified = _merge_btf_candidates([{
        "function": "foo_put", "role": "release", "object_argument": "arg0",
        "object_field": "refs", "evidence_source": "source_analysis",
        "confidence": "INFERRED", "reasons": [], "warnings": [],
    }], unverified_btf)[0]
    assert unverified["evidence_source"] == "source_analysis"
    assert unverified["role"] == "release"
    assert any("unproven" in warning for warning in unverified_btf["warnings"])


def test_generated_yaml_is_editable_and_maps_to_capture_options():
    report = analyze_fixture("exact_wrapper.c")
    document = _yaml_target(report, FIXTURES, None)
    operations = document["operations"]
    assert document["transfers"] == []
    args = target_arguments(document)
    assert "--get" in args and "foo_get:obj=arg0" in args
    assert "--put" in args and "foo_put:obj=arg0" in args
    assert document["metadata"]["manual_review_required"] is True
    assert any("manually" in comment for comment in document["comments"])
    assert any("do not prove ownership" in comment for comment in document["comments"])
    assert all(operation["confidence"] != "EXACT" for operation in operations)
    with tempfile.TemporaryDirectory() as temp:
        path = Path(temp) / "target.yaml"
        import yaml
        path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
        translated = translate(["trace", "--target-spec", str(path), "--dry-run"])
        assert translated[0] == "trace" and translated[-1] == "--dry-run"
        assert translated.count("--get") >= 1
        cli = subprocess.run(
            [str(BINARY), "trace", "--target-spec", str(path), "--help"],
            text=True, capture_output=True, check=False,
        )
        assert cli.returncode == 0 and "Usage: refscope trace" in cli.stdout, cli.stderr


def test_target_transfer_annotations_are_preserved_offline_and_validated():
    document = _yaml_target(analyze_fixture("exact_wrapper.c"), FIXTURES, None)
    transfer = {"from": "foo_queue_work", "to": "foo_work_handler",
                "key": "arg0", "kind": "workqueue"}
    document["transfers"] = [transfer]
    args = target_arguments(document)
    assert "--get" in args and "--put" in args
    assert "foo_queue_work" not in args and "foo_work_handler" not in args
    document["transfers"][0]["key"] = "field:pointer"
    try:
        target_arguments(document)
    except ValueError as exc:
        assert "key must be arg0..arg4" in str(exc)
    else:
        raise AssertionError("unsupported transfer key was accepted")



def test_binary_inspector_json_and_yaml_cli():
    if not BINARY.is_file():
        raise AssertionError("make test must build build/refscope first")
    with tempfile.TemporaryDirectory() as temp:
        target = Path(temp) / "generated/foo.yaml"
        result = subprocess.run(
            [str(BINARY), "inspect-target", "--type", "struct foo",
             "--kernel-tree", str(FIXTURES), "--write-target", str(target), "--format", "json"],
            text=True, capture_output=True, check=False,
        )
        assert result.returncode == 0, result.stderr
        report = json.loads(result.stdout)
        assert report["target_type"] == "struct foo"
        assert report["written_target"] == str(target)
        assert target.is_file()
        # Refuse destructive overwrite of a user-edited target.
        again = subprocess.run(
            [str(BINARY), "inspect-target", "--type", "struct foo",
             "--kernel-tree", str(FIXTURES), "--write-target", str(target)],
            text=True, capture_output=True, check=False,
        )
        assert again.returncode == 2 and "refusing to overwrite" in again.stderr


def test_source_index_handles_primitives_inline_macros_helpers_and_ambiguity():
    report = analyze_fixture("source_pass.c")
    inline = by_name(report, "foo_inline_get")
    assert inline["role"] == "acquire"
    assert inline["object_argument"] == "arg0" and inline["object_field"] == "refs"
    assert inline["source_refcount_op"] is True and inline["name_heuristic"] is True

    expected = {
        "foo_dec": ("release", "refs"),
        "foo_kref_hold": ("acquire", "ref"),
        "foo_kref_drop": ("release", "ref"),
        "foo_percpu_get": ("acquire", "percpu"),
        "foo_percpu_put": ("release", "percpu"),
    }
    for name, (role, field) in expected.items():
        candidate = by_name(report, name)
        assert (candidate["role"], candidate["object_field"]) == (role, field)
        assert candidate["confidence"] != "EXACT"

    helper = by_name(report, "foo_get_via_helper")
    assert helper["role"] == "acquire" and helper["object_argument"] == "arg0"
    assert helper["object_fields"] == ["refs"]
    assert any("one level" in warning for warning in helper["warnings"])

    multiple_fields = by_name(report, "foo_multiple_fields")
    assert multiple_fields["object_field"] is None
    assert multiple_fields["object_fields"] == ["refs", "secondary"]
    assert multiple_fields["ambiguous_data_flow"] is True

    ambiguous = by_name(report, "foo_ambiguous_get")
    assert ambiguous["object_argument"] is None
    assert ambiguous["object_arguments"] == ["arg0", "arg1"]
    assert any("AMBIGUOUS_OBJECT_ARGUMENT" in warning for warning in ambiguous["warnings"])

    unrelated = by_name(report, "foo_global_get")
    assert unrelated["object_argument"] is None
    assert unrelated["object_arguments"] == []
    assert unrelated["ambiguous_data_flow"] is True

    macro = by_name(report, "foo_macro_get")
    assert macro["kind"] == "macro" and macro["role"] == "acquire"
    assert macro["confidence"] == "INFERRED"
    assert any("not an attachable" in warning for warning in macro["warnings"])
    assert all(candidate["confidence"] != "EXACT" for candidate in report["all_candidates"])


def test_generated_yaml_marks_evidence_and_excludes_ambiguous_or_macro_candidates():
    report = analyze_fixture("source_pass.c")
    document = _yaml_target(report, FIXTURES, None)
    operations = {item["function"]: item for item in document["operations"]}
    assert "foo_inline_get" in operations
    assert operations["foo_inline_get"]["confidence"] == "inferred"
    assert operations["foo_inline_get"]["evidence"] == {
        "source_refcount_op": True, "name_heuristic": True}
    assert "foo_macro_get" not in operations
    assert "foo_multiple_fields" not in operations
    assert "foo_ambiguous_get" not in operations
    assert "foo_global_get" not in operations
    assert document["metadata"]["runtime_probes_auto_attached"] is False
    assert any("never auto-attached" in comment for comment in document["comments"])

    # A contradictory low-confidence name/source candidate is not emitted as
    # an executable operation in a combined source index.
    combined = analyze_target("struct foo", FIXTURES)
    combined_yaml = _yaml_target(combined, FIXTURES, None)
    assert all(op["confidence"] != "unknown" for op in combined_yaml["operations"])
    assert all(op["function"] != "foo_put" for op in combined_yaml["operations"])


def test_missing_and_stripped_source_degrade_to_manual():
    missing = analyze_target("struct foo", Path("/no/such/refscope-kernel-tree"), None)
    assert missing["source_analysis"]["available"] is False
    assert missing["mode"] == "manual"
    with tempfile.TemporaryDirectory() as temp:
        stripped = Path(temp)
        (stripped / "vmlinux").write_bytes((ROOT / "build/refscope").read_bytes())
        report = analyze_target("struct foo", stripped, None)
    assert report["source_analysis"]["available"] is False
    assert report["mode"] == "manual"


def test_vmlinux_source_tree_build_id_mismatch_is_reported_and_not_merged():
    with tempfile.TemporaryDirectory() as temp:
        tree = Path(temp) / "tree"
        tree.mkdir()
        shutil.copyfile(FIXTURES / "exact_wrapper.c", tree / "fixture.c")
        shutil.copyfile(ROOT / "build/refscope", tree / "vmlinux")
        mismatch = Path(temp) / "other-vmlinux"
        shutil.copyfile(ROOT / "build/test-target", mismatch)
        matching = _source_vmlinux_relation(tree, tree / "vmlinux")
        assert matching["status"] == "matched"
        relation = _source_vmlinux_relation(tree, mismatch)
        assert relation["status"] == "mismatch"
        report = analyze_target("struct foo", tree, mismatch)
        assert report["source_vmlinux_relation"]["status"] == "mismatch"
        assert any("build ID" in warning for warning in report["warnings"])
        assert all(item["evidence_source"] != "btf_kfunc"
                   for item in report["all_candidates"])


def test_source_tree_without_matching_elf_cannot_claim_btf_match():
    with tempfile.TemporaryDirectory() as temp:
        tree = Path(temp)
        shutil.copyfile(FIXTURES / "exact_wrapper.c", tree / "fixture.c")
        relation = _source_vmlinux_relation(tree, ROOT / "build/refscope")
        assert relation["status"] == "unverified"
        report = analyze_target("struct foo", tree, ROOT / "build/refscope")
        assert report["source_vmlinux_relation"]["status"] == "unverified"
        assert any("not verified" in warning for warning in report["warnings"])


def main():
    tests = [
        test_exact_wrapper_uses_body_evidence_not_name,
        test_kref_wrapper_candidates,
        test_name_only_is_inferred_heuristic,
        test_no_btf_and_no_source_tree_manual_mode,
        test_conflicting_candidates_are_visible_and_downgraded,
        test_ref_tracker_priority_over_source_and_name,
        test_btf_kfunc_priority_and_conflict_warning,
        test_generated_yaml_is_editable_and_maps_to_capture_options,
        test_target_transfer_annotations_are_preserved_offline_and_validated,
        test_binary_inspector_json_and_yaml_cli,
        test_source_index_handles_primitives_inline_macros_helpers_and_ambiguity,
        test_generated_yaml_marks_evidence_and_excludes_ambiguous_or_macro_candidates,
        test_missing_and_stripped_source_degrade_to_manual,
        test_vmlinux_source_tree_build_id_mismatch_is_reported_and_not_merged,
        test_source_tree_without_matching_elf_cannot_claim_btf_match,
    ]
    for test in tests:
        test()
    print(f"Target inspector tests: {len(tests)} passed")


if __name__ == "__main__":
    main()
