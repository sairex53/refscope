#!/usr/bin/env python3
import sys
from pathlib import Path
ROOT=Path(__file__).parents[1]
sys.path.insert(0,str(ROOT/"src"))
from diagnosis.rules import generate_candidates

def token(op,function=None,reason=None,ret=None,stack="stack-acquire",line=10):
    why={"state":"known","value":reason} if reason else {"state":"absent","value":None}
    return {"op_type":op,"normalized_function":function or op.lower(),
            "source_function":function or op.lower(),"normalized_stack":stack,
            "reason":why,"return_class":ret,
            "source_locations":[{"file":"foo.c","line":line}]}

def life(tokens,address="0x1",generation=1,origin="explicit",
         actual_refcount=None,observed_balance=None,exact=False,identity=None):
    return {"object":address,"generation":generation,"origin":origin,
            "target_type":"struct foo","object_class":"struct foo",
            "exact_identity_proven":exact,"identity_key":identity,
            "actual_refcount":actual_refcount,"observed_balance":observed_balance,
            "suspicion_flags":[],"tokens":tokens}

def run(label,rid,lifetime,warnings=None):
    return {"label":label,"run_id":rid,"target_type":"struct foo",
            "lifetimes":[lifetime],
            "capture_quality":{"capture_incomplete":False,"dropped":0,
                               "warnings":warnings or []}}

def candidate(rule,good_tokens,bad_tokens,warnings=None,good_args=None,bad_args=None):
    good=run("good","good-1",life(good_tokens,**(good_args or {})))
    bad=run("bad","bad-1",life(bad_tokens,**(bad_args or {})),warnings)
    found=generate_candidates([good],[bad])
    item=next((x for x in found if x["rule"]==rule),None)
    assert item is not None, f"missing {rule}; got {[x['rule'] for x in found]}"
    required={"candidate_id","rule","score","score_components","confidence","run_ids",
              "cohort_ids","divergence_window","source_locations","warnings"}
    assert required <= item.keys()
    assert item["root_cause_proven"] is False
    return item

def test_unmatched_acquisition():
    good=[token("CREATE","foo_create",stack="stack-create"),token("GET","foo_get","WORK"),
          token("PUT","foo_put","WORK"),token("FREE","foo_free")]
    bad=[token("CREATE","foo_create",stack="stack-create"),token("GET","foo_get","WORK"),
         token("FREE","foo_free")]
    item=candidate("unmatched_acquisition",good,bad)
    assert item["score_components"]["good_pattern_present_over_80_percent"]==3
    assert item["confidence"]=="INFERRED"
    assert item["score_components"]["actual_refcount_confirms_imbalance"]==0
    assert item["actual_refcount_available"] is False
    observed_only=candidate("unmatched_acquisition",good,bad,
                            good_args={"observed_balance":0},
                            bad_args={"observed_balance":1})
    assert observed_only["score_components"]["actual_refcount_confirms_imbalance"]==0
    captured=candidate("unmatched_acquisition",good,bad,
                       good_args={"actual_refcount":0},
                       bad_args={"actual_refcount":1})
    assert captured["score_components"]["actual_refcount_confirms_imbalance"]==2

def test_extra_release():
    good=[token("CREATE","foo_create",stack="stack-create"),token("GET","foo_get","WORK"),
          token("PUT","foo_put","WORK"),token("FREE","foo_free")]
    bad=[token("CREATE","foo_create",stack="stack-create"),token("GET","foo_get","WORK"),
         token("PUT","foo_put","WORK"),token("PUT","foo_put","WORK"),token("FREE","foo_free")]
    item=candidate("extra_release",good,bad)
    assert item["score_components"]["unique_operation_mismatch"]==3

def test_early_final_release():
    good=[token("CREATE","foo_create",stack="stack-create"),token("GET","foo_get","WORK"),
          token("GET","foo_use","WORK"),token("FREE","foo_free")]
    bad=[token("CREATE","foo_create",stack="stack-create"),token("GET","foo_get","WORK"),
         token("FREE","foo_free"),token("GET","foo_use","WORK")]
    item=candidate("early_final_release",good,bad)
    assert item["evidence"][0]["evidence_kind"]=="use-after-free-event-order"

def test_ownership_transfer_divergence():
    good=[token("CREATE","foo_create",stack="stack-create"),token("GET","foo_get","WORK"),
          token("PUT","foo_queue","ASYNC_HANDOFF"),
          token("GET","foo_receive","ASYNC_RECEIVE"),
          token("PUT","foo_put","ASYNC_RECEIVE"),token("FREE","foo_free")]
    bad=[token("CREATE","foo_create",stack="stack-create"),token("GET","foo_get","WORK"),
         token("PUT","foo_queue","ASYNC_HANDOFF"),token("PUT","foo_put","WORK"),
         token("FREE","foo_free")]
    item=candidate("ownership_transfer_divergence",good,bad)
    assert item["evidence"][0]["bad_receive_get_missing"] is True

def test_error_path_divergence():
    good=[token("CREATE","foo_create",stack="stack-create"),token("GET","foo_get","WORK"),
          token("CALL_RETURN","foo_alloc",ret="success"),token("PUT","foo_put","WORK"),
          token("FREE","foo_free")]
    bad=[token("CREATE","foo_create",stack="stack-create"),token("GET","foo_get","WORK"),
         token("CALL_RETURN","foo_alloc",ret="error"),token("FREE","foo_free")]
    item=candidate("error_path_divergence",good,bad)
    assert item["score_components"]["adjacent_error_return"]==2

def test_identity_and_capture_confidence():
    good=[token("CREATE","foo_create",stack="stack-create"),token("GET","foo_get","WORK"),
          token("PUT","foo_put","WORK"),token("FREE","foo_free")]
    bad=[token("CREATE","foo_create",stack="stack-create"),token("GET","foo_get","WORK"),
         token("FREE","foo_free")]
    item=candidate("unmatched_acquisition",good,bad)
    assert item["confidence"]!="EXACT"
    assert item["source_locations"]
    warned=candidate("unmatched_acquisition",good,bad,warnings=["events_dropped"])
    assert warned["warnings"]==["events_dropped"]
    assert warned["confidence"]=="INFERRED"
    exact_args={"exact":True,"identity":"shared-ref-1"}
    exact=candidate("unmatched_acquisition",good,bad,good_args=exact_args,bad_args=exact_args)
    assert exact["confidence"]=="EXACT"
    mismatched_identity=candidate(
        "unmatched_acquisition",good,bad,
        good_args={"exact":True,"identity":"reference-A"},
        bad_args={"exact":True,"identity":"reference-B"})
    assert mismatched_identity["confidence"]!="EXACT"

def test_good_pattern_threshold():
    good_pattern=[token("CREATE","foo_create",stack="stack-create"),token("GET","foo_get","WORK"),
                  token("PUT","foo_put","WORK"),token("FREE","foo_free")]
    no_release=[token("CREATE","foo_create",stack="stack-create"),token("GET","foo_get","WORK"),
                token("FREE","foo_free")]
    bad=run("bad","bad-1",life(no_release))
    goods=[run("good",f"good-{i}",life(good_pattern if i<4 else no_release,
                                         address=f"0x{i+1}")) for i in range(5)]
    item=next(x for x in generate_candidates(goods,[bad])
              if x["rule"]=="unmatched_acquisition")
    assert item["good_pattern_recurrence"]=={"present":4,"eligible":5,"ratio":0.8}
    assert item["score_components"]["good_pattern_present_over_80_percent"]==0

def test_strong_requires_repeatable_good_runs():
    good_pattern=[token("CREATE","foo_create",stack="stack-create"),token("GET","foo_get","WORK"),
                  token("PUT","foo_put","WORK"),token("FREE","foo_free")]
    bad_pattern=[token("CREATE","foo_create",stack="stack-create"),token("GET","foo_get","WORK"),
                 token("FREE","foo_free")]
    goods=[run("good",f"good-repeat-{i}",life(good_pattern,address=f"0x{i+1}"))
           for i in range(2)]
    bad=run("bad","bad-repeat",life(bad_pattern))
    item=next(x for x in generate_candidates(goods,[bad])
              if x["rule"]=="unmatched_acquisition")
    assert item["good_pattern_recurrence"]=={"present":2,"eligible":2,"ratio":1.0}
    assert item["confidence"]=="STRONG"

def main():
    test_unmatched_acquisition()
    test_extra_release()
    test_early_final_release()
    test_ownership_transfer_divergence()
    test_error_path_divergence()
    test_identity_and_capture_confidence()
    test_good_pattern_threshold()
    test_strong_requires_repeatable_good_runs()
    print("Diagnosis explicit candidate-rule tests: passed")

if __name__=="__main__":
    main()
