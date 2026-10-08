#!/usr/bin/env python3
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))
from diagnosis.input import BundleError, load_bundle
from timeline.bundle import build_bundle


def fixture(root, label="good", incomplete=False, dropped=0):
    root.mkdir(parents=True, exist_ok=True)
    source = root / "capture.jsonl"
    source.write_text("\n".join(json.dumps(row, sort_keys=True) for row in [
        {"record": "event", "type": "CREATE", "object": "0x1000", "ts_ns": 1, "function": "foo_create.isra.3", "object_class": "struct foo", "stack_id": 1},
        {"record": "event", "type": "GET", "object": "0x1000", "ts_ns": 2, "function": "foo_get+0x20", "reason": "WORK", "stack_id": 1},
        {"record": "event", "type": "CALL_RETURN", "object": "0x1000", "ts_ns": 3, "function": "foo_fail.constprop.2", "retval": -12, "stack_id": 1},
        {"record": "event", "type": "FREE", "object": "0x1000", "ts_ns": 4, "function": "foo_free", "stack_id": 2},
        {"record": "stack", "stack_id": 1, "frames": [{"ip": "0xffff0010", "symbol": "foo_get", "offset": 8, "source_file": "foo.c", "source_line": 40}]},
        {"record": "stack", "stack_id": 2, "lookup_failed": True, "frames": []},
        {"record": "summary", "schema_version": 1, "attempted": 4 + dropped, "captured": 4, "dropped": dropped, "loss_counters_known": True, "stack_errors": 0, "userspace_stack_lookup_errors": 0, "incomplete": incomplete},
    ]) + "\n", encoding="utf-8")
    bundle = root / label
    build_bundle(source, bundle, label=label)
    return bundle


def test_tokens_and_stable_run_id(root):
    first = fixture(root / "a", "good")
    second = fixture(root / "b", "good")
    a, b = load_bundle(first), load_bundle(second)
    assert a["schema_version"] == 1 and a["label"] == "good"
    assert a["run_id"] == b["run_id"]
    life = a["lifetimes"][0]
    assert life["generation"] == 1 and life["object_class"] == "struct foo"
    assert life["exact_identity_proven"] is False
    assert life["identity_key"] is None
    assert life["identity_evidence"] == "explicit-lifecycle-boundaries"
    tokens = life["tokens"]
    assert [t["op_type"] for t in tokens] == ["CREATE", "GET", "CALL_RETURN", "FREE"]
    assert tokens[0]["normalized_function"] == "foo_create"
    assert tokens[1]["reason"] == {"state": "known", "value": "WORK"}
    assert tokens[1]["normalized_stack"].startswith("sha256:")
    assert tokens[1]["source_locations"] == [{"file": "foo.c", "line": 40}]
    assert tokens[2]["return_class"] == "error"
    assert tokens[2]["return_value"] == -12
    assert tokens[2]["source_function"] == "foo_fail"
    assert tokens[3]["normalized_stack"] is None
    assert a["capture_quality"]["capture_incomplete"] is False
    assert "stack_fingerprint_unavailable" in a["capture_quality"]["warnings"]
    assert a["input_hashes"]["source_jsonl"]
    meta = json.loads((first / "meta.json").read_text())
    assert meta["diagnosis"]["absence_semantics"].startswith("No token means")

    identity_bundle = fixture(root / "identity-proof", "good")
    identity_summary_path = identity_bundle / "summary.json"
    identity_summary = json.loads(identity_summary_path.read_text())
    raw_events = identity_summary["timeline"]["objects"][0]["events"]
    raw_events[0]["reference_id"] = "same-ref"
    identity_summary_path.write_text(json.dumps(identity_summary, sort_keys=True))
    partial_identity = load_bundle(identity_bundle)["lifetimes"][0]
    assert partial_identity["exact_identity_proven"] is False
    assert partial_identity["identity_key"] is None
    raw_events = identity_summary["timeline"]["objects"][0]["events"]
    for event in raw_events:
        event["reference_id"] = "same-ref"
    identity_summary_path.write_text(json.dumps(identity_summary, sort_keys=True))
    exact_identity = load_bundle(identity_bundle)["lifetimes"][0]
    assert exact_identity["exact_identity_proven"] is True
    assert exact_identity["identity_key"] == "same-ref"


def test_bad_bundle_errors(root):
    missing_meta = root / "no-meta"
    missing_meta.mkdir()
    try:
        load_bundle(missing_meta)
        raise AssertionError("missing metadata accepted")
    except BundleError as exc:
        assert "missing metadata" in str(exc)

    missing_summary = fixture(root / "missing-summary-src", "bad")
    (missing_summary / "summary.json").unlink()
    try:
        load_bundle(missing_summary)
        raise AssertionError("missing summary accepted")
    except BundleError as exc:
        assert "missing summary" in str(exc)

    incomplete = fixture(root / "incomplete", "bad", incomplete=True)
    loaded = load_bundle(incomplete)
    assert loaded["capture_quality"]["capture_incomplete"] is True
    assert "capture_marked_incomplete" in loaded["capture_quality"]["warnings"]
    dropped_run = fixture(root / "dropped", "bad", incomplete=True, dropped=2)
    quality = load_bundle(dropped_run)["capture_quality"]
    assert quality["dropped"] == 2 and quality["loss_counters_known"] is True
    assert quality["capture_incomplete"] is True
    assert "events_dropped" in quality["warnings"]

    null_stack = loaded["lifetimes"][0]["tokens"][-1]
    assert null_stack["normalized_stack"] is None

    unknown_reason = fixture(root / "reason", "good")
    meta_path = unknown_reason / "meta.json"
    # Numeric reason values have no semantic name, so retain value and mark unknown.
    summary_path = unknown_reason / "summary.json"
    summary = json.loads(summary_path.read_text())
    summary["timeline"]["objects"][0]["events"][1]["reason"] = 73
    summary_path.write_text(json.dumps(summary, sort_keys=True))
    assert load_bundle(unknown_reason)["lifetimes"][0]["tokens"][1]["reason"]["state"] == "unknown"

    missing_generation = fixture(root / "generation", "good")
    summary_path = missing_generation / "summary.json"
    summary = json.loads(summary_path.read_text())
    del summary["timeline"]["objects"][0]["generation"]
    summary_path.write_text(json.dumps(summary, sort_keys=True))
    try:
        load_bundle(missing_generation)
        raise AssertionError("missing generation accepted")
    except BundleError as exc:
        assert "generation" in str(exc)

    unknown_root = root / "unknown-event-src"
    unknown_bundle = fixture(unknown_root, "good")
    source = unknown_root / "capture.jsonl"
    rows = [json.loads(line) for line in source.read_text().splitlines()]
    rows.insert(2, {"record": "event", "type": "NEW_KERNEL_EVENT", "object": "0x1000",
                    "ts_ns": 25, "function": "future_hook", "stack_id": 1})
    summary_record = rows[-1]
    summary_record["attempted"] += 1
    summary_record["captured"] += 1
    source.write_text("\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n")
    from timeline.bundle import build_bundle
    unknown_bundle = root / "unknown-event-bundle"
    build_bundle(source, unknown_bundle, label="good")
    unknown_token = load_bundle(unknown_bundle)["lifetimes"][0]["tokens"][2]
    assert unknown_token["op_type"] == "UNKNOWN"
    assert unknown_token["unknown_event_type"] == "NEW_KERNEL_EVENT"
    assert load_bundle(unknown_bundle)["capture_quality"]["unknown_event_count"] == 1

    wrong_version = fixture(root / "version", "good")
    meta_path = wrong_version / "meta.json"
    meta = json.loads(meta_path.read_text())
    meta["diagnosis"]["schema_version"] = 99
    meta_path.write_text(json.dumps(meta, sort_keys=True))
    try:
        load_bundle(wrong_version)
        raise AssertionError("unsupported schema accepted")
    except BundleError as exc:
        assert "diagnosis schema_version" in str(exc)


def test_diagnose_cli(root):
    good_source_bundle = fixture(root / "good-run", "good")
    fixture(root / "bad-run", "bad", incomplete=True)
    import subprocess
    cli_bundle = root / "cli-created-good"
    command = [str(ROOT / "build/refscope"), "timeline", "--input",
               str(good_source_bundle.parent / "capture.jsonl"), "--format", "json",
               "--bundle", str(cli_bundle), "--label", "good"]
    created = subprocess.run(command, cwd=ROOT, text=True, capture_output=True)
    assert created.returncode == 0, created.stderr
    assert load_bundle(cli_bundle)["label"] == "good"
    result = subprocess.run(
        [str(ROOT / "build/refscope"), "diagnose", str(root), "--format", "json"],
        cwd=ROOT, text=True, capture_output=True,
    )
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["ranking_performed"] is True
    assert report["mode"] == "offline-explicit-candidate-rules"
    assert isinstance(report["candidate_rules"], list)
    assert isinstance(report["candidates"], list)
    assert report["run_count"] == 3
    assert {run["label"] for run in report["runs"]} == {"good", "bad"}
    assert all(run["run_id"].startswith("run-") for run in report["runs"])
    assert any(run["capture_quality"]["capture_incomplete"] for run in report["runs"])


def main():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        test_tokens_and_stable_run_id(root)
        test_bad_bundle_errors(root)
        test_diagnose_cli(root / "cli")
    print("Diagnosis input contract tests: passed")


if __name__ == "__main__":
    main()
