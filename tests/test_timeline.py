#!/usr/bin/env python3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from timeline.engine import Timeline


def event(kind, address="0x1000", ts=1, **extra):
    result = {
        "record": "event",
        "type": kind,
        "object": address,
        "ts_ns": ts,
        "cpu": 0,
        "pid": 10,
        "tid": 10,
        "function": "target_a",
        "stack_id": 7,
    }
    result.update(extra)
    return result


def one(timeline):
    objects = timeline.as_dict()["objects"]
    assert len(objects) == 1, objects
    return objects[0]


def test_deterministic_correct_lifetime():
    obj = one(Timeline().process([
        event("CREATE", ts=10, reason="origin"),
        event("GET", ts=20, reason="work"),
        event("GET", ts=30, reason="timer"),
        event("PUT", ts=40, reason="timer"),
        event("PUT", ts=50, reason="work"),
        event("FREE", ts=60),
    ]))
    assert (obj["generation"], obj["state"], obj["origin"]) == (1, "DEAD", "explicit")
    assert obj["observed_balance"] == 0
    assert obj["suspicion_flags"] == []
    assert obj["active_reasons"] == ["origin", "work", "timer"]
    assert obj["cpus"] == [0]
    assert obj["tasks"] == [{"pid": 10, "tid": 10}]
    assert obj["stack_fingerprints"] == ["stack_id:7"]
    assert obj["targets"] == ["target_a"]


def test_missing_put():
    obj = one(Timeline().process([event("CREATE"), event("GET")]))
    assert obj["observed_balance"] == 1
    assert obj["actual_refcount"] is None
    assert "UNBALANCED_OBSERVED_OPS" in obj["suspicion_flags"]
    assert "REFCOUNT_NONZERO_AT_END" not in obj["suspicion_flags"]


def test_double_put():
    obj = one(Timeline().process([event("CREATE"), event("GET"), event("PUT"), event("PUT")]))
    assert obj["observed_balance"] == -1
    assert "PUT_WITHOUT_PRIOR_GET" in obj["suspicion_flags"]
    assert "UNBALANCED_OBSERVED_OPS" in obj["suspicion_flags"]


def test_partial_origin_get_without_create():
    obj = one(Timeline().process([event("GET", ts=22)]))
    assert obj["origin"] == "partial"
    assert obj["state"] == "LIVE"
    assert obj["create_event"] is None


def test_free_then_new_create_is_new_generation():
    objects = Timeline().process([
        event("CREATE", ts=1),
        event("GET", ts=2),
        event("PUT", ts=3),
        event("FREE", ts=4),
        event("CREATE", ts=5),
        event("GET", ts=6),
        event("FREE", ts=7),
    ]).as_dict()["objects"]
    assert len(objects) == 2
    assert [obj["generation"] for obj in objects] == [1, 2]
    assert all(obj["state"] == "DEAD" for obj in objects)
    assert [obj["origin"] for obj in objects] == ["explicit", "explicit"]
    assert objects[0]["events"][-1]["generation"] == 1
    assert objects[1]["events"][0]["generation"] == 2


def test_two_events_after_free_are_not_merged():
    objects = Timeline().process([
        event("CREATE", ts=1),
        event("FREE", ts=2),
        event("GET", ts=3, reason="late"),
        event("PUT", ts=4, reason="late"),
    ]).as_dict()["objects"]
    assert len(objects) == 2
    assert objects[0]["state"] == "DEAD"
    reused = objects[1]
    assert reused["generation"] == 2
    assert reused["origin"] == "partial"
    assert reused["state"] == "LIVE"
    assert "EVENT_AFTER_FREE" in reused["suspicion_flags"]
    assert "ADDRESS_REUSE_AMBIGUOUS" in reused["suspicion_flags"]
    assert reused["observed_balance"] == 0
    assert all(item["generation"] == 2 for item in reused["events"])


def test_ambiguous_reuse_without_sufficient_data():
    objects = Timeline().process([
        event("CREATE", ts=1),
        event("FREE", ts=2),
        event("GET", ts=3),
    ]).as_dict()["objects"]
    assert len(objects) == 2
    assert objects[1]["origin"] == "partial"
    assert "ADDRESS_REUSE_AMBIGUOUS" in objects[1]["suspicion_flags"]


def test_multiple_targets_same_object():
    objects = Timeline().process([
        event("CREATE", ts=1, target_id=1, function="create_target", cpu=0, tid=11),
        event("GET", ts=2, target_id=2, function="get_target", cpu=1, tid=12),
        event("PUT", ts=3, target_id=3, function="put_target", cpu=2, tid=13),
        event("FREE", ts=4, target_id=4, function="free_target", cpu=1, tid=12),
    ]).as_dict()["objects"]
    assert len(objects) == 1
    assert objects[0]["targets"] == [1, 2, 3, 4]
    assert objects[0]["cpus"] == [0, 1, 2]
    assert objects[0]["tasks"] == [
        {"pid": 10, "tid": 11},
        {"pid": 10, "tid": 12},
        {"pid": 10, "tid": 13},
    ]


def test_actual_refcount_flag_only_when_captured():
    known = one(Timeline().process([
        event("CREATE"),
        event("GET", actual_refcount=2),
        event("FREE"),
    ]))
    assert known["actual_refcount"] == 2
    assert "REFCOUNT_NONZERO_AT_END" in known["suspicion_flags"]

    unknown = one(Timeline().process([event("CREATE"), event("GET", value=99)]))
    assert unknown["actual_refcount"] is None
    assert "REFCOUNT_NONZERO_AT_END" not in unknown["suspicion_flags"]


def main():
    tests = [
        test_deterministic_correct_lifetime,
        test_missing_put,
        test_double_put,
        test_partial_origin_get_without_create,
        test_free_then_new_create_is_new_generation,
        test_two_events_after_free_are_not_merged,
        test_ambiguous_reuse_without_sufficient_data,
        test_multiple_targets_same_object,
        test_actual_refcount_flag_only_when_captured,
    ]
    for test in tests:
        test()
    print("Timeline generation tests: passed")


if __name__ == "__main__":
    main()
