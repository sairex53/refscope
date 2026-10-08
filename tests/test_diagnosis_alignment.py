#!/usr/bin/env python3
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))
from diagnosis.align import compare_lifetimes, compare_runs, cohort_id


def tok(op, function=None, stack="stack-acq", reason=None, ret=None, cpu=0, tid=10):
    return {"op_type": op, "normalized_function": function or op.lower(),
            "source_function": function or op.lower(), "normalized_stack": stack,
            "reason": {"state": "known", "value": reason} if reason else {"state": "absent", "value": None},
            "return_class": ret, "cpu": cpu, "tid": tid, "timestamp": 999999 - cpu}


def life(tokens, address="0x1000", generation=1, origin="explicit", target="struct foo"):
    return {"object": address, "generation": generation, "origin": origin,
            "target_type": target, "object_class": target, "tokens": tokens}


def run(label, run_id, lifetimes):
    return {"label": label, "run_id": run_id, "target_type": "struct foo", "lifetimes": lifetimes}


def aligned(good_tokens, bad_tokens):
    return compare_lifetimes(run("good", "run-good", []), run("bad", "run-bad", []),
                             life(good_tokens), life(bad_tokens))


def test_identical_and_repeatable():
    seq = [tok("CREATE", "foo_create", "stack-create"),
           tok("GET", "foo_get", reason="WORK"), tok("PUT", "foo_put", reason="WORK"),
           tok("FREE", "foo_free")]
    first, second = aligned(seq, seq), aligned(seq, seq)
    assert first["earliest_meaningful_divergence"] is None
    assert len(first["matched_tokens"]) == 4
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
    assert first["good_run_id"] == "run-good" and first["bad_run_id"] == "run-bad"


def test_extra_missing_put_and_early_free():
    base = [tok("CREATE", "foo_create", "stack-create"),
            tok("GET", "foo_get", reason="WORK"), tok("PUT", "foo_put", reason="WORK"),
            tok("FREE", "foo_free")]
    extra = aligned(base, base[:3] + [tok("PUT", "foo_put", reason="WORK"), base[3]])
    assert len(extra["bad_only_tokens"]) == 1
    assert extra["earliest_meaningful_divergence"]["kind"] == "unmatched-bad-token"
    missing = aligned(base, [base[0], base[1], base[3]])
    assert len(missing["good_only_tokens"]) == 1
    early = aligned(base, [base[0], base[1], base[3], base[2]])
    assert early["earliest_meaningful_divergence"] is not None
    assert len(early["context_window"]["good"]) <= 7
    assert len(early["context_window"]["bad"]) <= 7


def test_return_class_and_unrelated_interleaving():
    base = [tok("CREATE", "foo_create", "stack-create"),
            tok("GET", "foo_get", reason="WORK"),
            tok("CALL_RETURN", "foo_call", stack="stack-call", ret="success"),
            tok("PUT", "foo_put", reason="WORK"), tok("FREE", "foo_free")]
    changed = list(base)
    changed[2] = tok("CALL_RETURN", "foo_call", stack="stack-call", ret="error")
    mismatch = aligned(base, changed)
    assert mismatch["earliest_meaningful_divergence"]["kind"] == "semantic-token-mismatch"
    assert "return_class" in mismatch["earliest_meaningful_divergence"]["fields"]
    interleaved = base[:3] + [tok("GET", "unrelated_work", stack="other-stack")] + base[3:]
    result = aligned(base, interleaved)
    assert len(result["bad_only_tokens"]) == 1
    assert len(result["matched_tokens"]) == len(base)


def test_cpu_tid_ignored_and_pointer_generations_separate():
    seq = [tok("CREATE", "foo_create", "stack-create"),
           tok("GET", "foo_get", reason="WORK"), tok("PUT", "foo_put", reason="WORK")]
    same = [tok(x["op_type"], x["source_function"], x["normalized_stack"],
                x["reason"].get("value"), x["return_class"], cpu=7, tid=991) for x in seq]
    a, b = life(seq, "0x1000", 1), life(same, "0xffff", 1)
    aid, _ = cohort_id(a, run("good", "g", []))
    bid, _ = cohort_id(b, run("bad", "b", []))
    assert aid == bid
    reused = life(seq, "0x1000", 2)
    reused_id, _ = cohort_id(reused, run("bad", "b", []))
    assert aid != reused_id
    report = compare_runs(run("good", "g", [a, reused]), run("bad", "b", [b]))
    assert len(report["comparisons"]) == 2
    assert len({item["cohort_id"] for item in report["comparisons"]}) == 2

    ambiguous = compare_runs(run("good", "g2", [a, b]), run("bad", "b2", [b]))
    repeated = next(item for item in ambiguous["comparisons"]
                    if item["cohort_id"] == aid)
    assert repeated["status"] == "ambiguous-cohort-membership"
    assert "matched_tokens" not in repeated


def test_unrelated_objects_do_not_merge():
    left = life([tok("GET", "foo_get", "acquire-A", "WORK"),
                 tok("PUT", "foo_put", "release-A", "WORK")], "0x1")
    right = life([tok("GET", "foo_get", "acquire-B", "REFRESH"),
                  tok("PUT", "foo_put", "release-B", "REFRESH")], "0x2")
    aid, _ = cohort_id(left, run("good", "g", []))
    bid, _ = cohort_id(right, run("bad", "b", []))
    assert aid != bid


def main():
    test_identical_and_repeatable()
    test_extra_missing_put_and_early_free()
    test_return_class_and_unrelated_interleaving()
    test_cpu_tid_ignored_and_pointer_generations_separate()
    test_unrelated_objects_do_not_merge()
    print("Diagnosis alignment tests: passed")


if __name__ == "__main__":
    main()
