#!/usr/bin/env python3
"""End-to-end synthetic accuracy gates for offline differential diagnosis."""
from __future__ import annotations
import argparse, hashlib, json, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))
from timeline.bundle import build_bundle

BINARY = ROOT / "build/refscope"
REPEATS = 10
CASES = {
    "missing_put_error": {"rule":"unmatched_acquisition","top":1,"confidence_max":"STRONG","warnings":[]},
    "double_put": {"rule":"extra_release","top":1,"confidence_max":"STRONG","warnings":[]},
    "early_free": {"rule":"early_final_release","top":3,"confidence_max":"STRONG","warnings":[]},
    "missing_receive_get": {"rule":"ownership_transfer_divergence","top":3,"confidence_max":"STRONG","warnings":[]},
    "noisy_object": {"rule":"unmatched_acquisition","top":3,"confidence_max":"STRONG","warnings":[]},
    "pointer_reuse": {"rule":"unmatched_acquisition","top":3,"confidence_max":"STRONG","warnings":[]},
    "unrelated_work": {"rule":"unmatched_acquisition","top":3,"confidence_max":"STRONG","warnings":[]},
    "event_drop": {"rule":"unmatched_acquisition","top":3,"confidence_max":"INFERRED","warnings":["capture_marked_incomplete","events_dropped"]},
}

def ev(kind, fn, reason=None, retval=None, obj="0x1000", stack_id=1, ts=1, repeat=0):
    row={"record":"event","type":kind,"object":obj,"ts_ns":ts+repeat*100,
         "function":fn,"object_class":"struct foo","stack_id":stack_id,
         "cpu":ts%4,"pid":1000+ts+repeat*100,"tid":2000+ts+repeat*100}
    if reason is not None: row["reason"]=reason
    if retval is not None: row["retval"]=retval
    return row

def events_for(case, side, repeat):
    e=lambda *a,**kw: ev(*a,repeat=repeat,**kw)
    if case in ("missing_put_error","noisy_object","unrelated_work"):
        rows=[e("CREATE","foo_create"),e("GET","foo_get","WORK",ts=2),e("CALL_RETURN","foo_fail",retval=-12,ts=3)]
        if side=="good": rows.append(e("PUT","foo_put","WORK",ts=4))
        rows.append(e("FREE","foo_free",ts=5))
        if case=="noisy_object":
            rows += [e("CREATE","bar_create",obj="0x2000",stack_id=2,ts=6),e("GET","bar_get","NOISE",obj="0x2000",stack_id=2,ts=7),e("PUT","bar_put","NOISE",obj="0x2000",stack_id=2,ts=8),e("FREE","bar_free",obj="0x2000",stack_id=2,ts=9)]
        if case=="unrelated_work":
            rows[2:2]=[e("CREATE","noise_create",obj="0x3000",stack_id=2,ts=20),e("GET","noise_get","UNRELATED",obj="0x3000",stack_id=2,ts=21),e("PUT","noise_put","UNRELATED",obj="0x3000",stack_id=2,ts=22),e("FREE","noise_free",obj="0x3000",stack_id=2,ts=23)]
    elif case=="double_put":
        rows=[e("CREATE","foo_create"),e("GET","foo_get","WORK",ts=2),e("PUT","foo_put","WORK",ts=3)]
        if side=="bad": rows.append(e("PUT","foo_put","WORK",ts=4))
        rows.append(e("FREE","foo_free",ts=5))
    elif case=="early_free":
        rows=[e("CREATE","foo_create"),e("GET","foo_get","WORK",ts=2)]
        if side=="good": rows.append(e("GET","foo_use","WORK",ts=3))
        rows.append(e("FREE","foo_free",ts=4))
    elif case=="missing_receive_get":
        rows=[e("CREATE","foo_create"),e("GET","foo_get","WORK",ts=2),e("PUT","foo_queue","ASYNC_HANDOFF",ts=3)]
        if side=="good": rows.append(e("GET","foo_receive","ASYNC_RECEIVE",ts=4))
        rows += [e("PUT","foo_release","ASYNC_RECEIVE",ts=5),e("FREE","foo_free",ts=6)]
    elif case=="pointer_reuse":
        rows=[e("CREATE","foo_create"),e("GET","foo_get","WORK",ts=2),e("PUT","foo_put","WORK",ts=3),e("FREE","foo_free",ts=4),e("CREATE","foo_create",ts=5),e("GET","foo_get","WORK",ts=6)]
        if side=="good": rows.append(e("PUT","foo_put","WORK",ts=7))
        rows.append(e("FREE","foo_free",ts=8))
    elif case=="event_drop":
        rows=[e("CREATE","foo_create"),e("GET","foo_get","WORK",ts=2)]
        if side=="good": rows.append(e("PUT","foo_put","WORK",ts=3))
        rows.append(e("FREE","foo_free",ts=4))
    else: raise AssertionError(case)
    return rows

def build_one(dest,label,rows,dropped=0):
    dest.mkdir(parents=True)
    source=dest/"capture.jsonl"
    records=list(rows)+[
        {"record":"stack","stack_id":1,"frames":[{"symbol":"foo_get","offset":4,"source_file":"foo.c","source_line":40}]},
        {"record":"stack","stack_id":2,"frames":[{"symbol":"bar_get","offset":8,"source_file":"bar.c","source_line":70}]},
        {"record":"summary","schema_version":1,"attempted":len(rows)+dropped,"captured":len(rows),"dropped":dropped,"loss_counters_known":True,"stack_errors":0,"userspace_stack_lookup_errors":0,"incomplete":dropped>0}]
    source.write_text("".join(json.dumps(row,sort_keys=True)+"\n" for row in records))
    return build_bundle(source,dest/"bundle",label=label)

def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()

def run_case(name,case_dir):
    spec=CASES[name]
    trial_results=[]
    for repeat in range(REPEATS):
        trial_root=case_dir/"trials"/f"{repeat:02d}"
        for side in ("good","bad"):
            dropped=1 if name=="event_drop" and side=="bad" else 0
            build_one(trial_root/side,side,events_for(name,side,repeat),dropped)
        trial_command=[str(BINARY),"diagnose",str(trial_root),"--format","json"]
        trial=subprocess.run(trial_command,cwd=ROOT,text=True,capture_output=True)
        (trial_root/"diagnose.stdout").write_text(trial.stdout)
        (trial_root/"diagnose.stderr").write_text(trial.stderr)
        (trial_root/"exit-code.txt").write_text(str(trial.returncode)+"\n")
        assert trial.returncode==0,f"{name} repeat {repeat}: {trial.stderr}"
        trial_candidates=json.loads(trial.stdout)["candidates"]
        trial_rank=next((i+1 for i,c in enumerate(trial_candidates) if c["rule"]==spec["rule"]),None)
        assert trial_rank is not None and trial_rank<=spec["top"],f"{name} repeat {repeat}: expected top-{spec['top']}; actual {[(c['rule'],c['score']) for c in trial_candidates]}"
        assert all(c["confidence"]!="EXACT" for c in trial_candidates),f"false EXACT: {name} repeat {repeat}"
        trial_candidate=next(c for c in trial_candidates if c["rule"]==spec["rule"])
        assert trial_candidate["warnings"]==spec["warnings"],f"{name} repeat {repeat}: unexpected warnings {trial_candidate['warnings']}"
        if name=="pointer_reuse":
            c=next(c for c in trial_candidates if c["rule"]==spec["rule"])
            generations={t.get("generation") for side in ("good","bad") for t in c["divergence_window"][side]}
            assert generations=={2},f"pointer reuse mixed generations in repeat {repeat}: {generations}"
        if name=="event_drop":
            c=next(c for c in trial_candidates if c["rule"]==spec["rule"])
            assert c["confidence"]=="INFERRED" and "events_dropped" in c["warnings"]
        trial_results.append({"repeat":repeat,"rank":trial_rank,"top1":trial_rank==1,
                              "stdout_sha256":hashlib.sha256(trial.stdout.encode()).hexdigest()})
    command=[str(BINARY),"diagnose",str(case_dir),"--format","json"]
    result=subprocess.run(command,cwd=ROOT,text=True,capture_output=True)
    for file,value in (("command.txt",json.dumps(command)+"\n"),("diagnose.stdout",result.stdout),("diagnose.stderr",result.stderr),("exit-code.txt",str(result.returncode)+"\n")):
        (case_dir/file).write_text(value)
    assert result.returncode==0,f"{name}: {result.stderr}"
    report=json.loads(result.stdout); candidates=report["candidates"]
    assert all(c["confidence"]!="EXACT" for c in candidates),f"false EXACT: {name} aggregate"
    rank=next((i+1 for i,c in enumerate(candidates) if c["rule"]==spec["rule"]),None)
    assert rank is not None and rank<=spec["top"],f"{name}: expected top-{spec['top']} {spec['rule']}; actual {[(c['rule'],c['score']) for c in candidates]}"
    candidate=next(c for c in candidates if c["rule"]==spec["rule"])
    conf={"INFERRED":0,"STRONG":1,"EXACT":2}
    assert conf[candidate["confidence"]]<=conf[spec["confidence_max"]],name
    assert candidate["confidence"]!="EXACT",f"false EXACT: {name}"
    assert candidate["warnings"]==spec["warnings"],(name,candidate["warnings"])
    assert len(candidate["run_ids"]["good"])==REPEATS and len(candidate["run_ids"]["bad"])==REPEATS
    if name=="pointer_reuse":
        generations={t.get("generation") for side in ("good","bad") for t in candidate["divergence_window"][side]}
        assert generations=={2},f"pointer reuse mixed generations: {generations}"
    if name=="event_drop":
        assert candidate["confidence"]=="INFERRED" and candidate["score_components"]["dropped_events"]<0
    repeated=subprocess.run(command,cwd=ROOT,text=True,capture_output=True)
    assert repeated.returncode==0 and repeated.stdout==result.stdout,f"nondeterministic: {name}"
    breakdown={k:candidate[k] for k in ("candidate_id","rule","score","score_components","evidence","run_ids","cohort_ids","confidence","warnings","divergence_window","capture_quality")}; breakdown["rank"]=rank
    (case_dir/"score-breakdown.json").write_text(json.dumps(breakdown,indent=2,sort_keys=True)+"\n")
    return {"scenario":name,"expected_rule":spec["rule"],"rank":rank,"top1":rank==1,"top3":rank<=3,"repeat_top1_rate":sum(x["top1"] for x in trial_results)/REPEATS,"repeat_top3_rate":sum(x["rank"]<=3 for x in trial_results)/REPEATS,"repeat_results":trial_results,"confidence":candidate["confidence"],"confidence_max":spec["confidence_max"],"warnings":candidate["warnings"],"candidate_id":candidate["candidate_id"],"input_bundle_count":2*REPEATS,"report_sha256":sha(case_dir/"diagnose.stdout"),"score":candidate["score"],"score_components":candidate["score_components"]}

def main():
    if not BINARY.is_file(): raise SystemExit("build/refscope is missing; build the project first")
    parser=argparse.ArgumentParser(); parser.add_argument("--output-dir",type=Path); args=parser.parse_args()
    temp=None
    if args.output_dir:
        out=args.output_dir; out.mkdir(parents=True,exist_ok=False); run_root=out/"scenarios"
    else:
        temp=tempfile.TemporaryDirectory(prefix="refscope-synthetic-accuracy-"); run_root=Path(temp.name)/"scenarios"
    run_root.mkdir(parents=True)
    results=[run_case(name,run_root/name) for name in CASES]
    assert next(x for x in results if x["scenario"]=="missing_put_error")["repeat_top1_rate"]>=.8
    assert next(x for x in results if x["scenario"]=="double_put")["repeat_top1_rate"]>=.8
    assert all(x["repeat_top3_rate"]==1.0 and x["top3"] for x in results)
    summary={"repeats_per_scenario":REPEATS,"scenario_count":len(results),"missing_put_top1":"100%","double_put_top1":"100%","all_scenarios_top3":"100%","false_exact":0,"pointer_reuse_generations_separated":True,"dropped_input_confidence_reduced":True,"results":results}
    if args.output_dir:
        (args.output_dir/"accuracy-summary.json").write_text(json.dumps(summary,indent=2,sort_keys=True)+"\n")
        (args.output_dir/"expected.json").write_text(json.dumps(CASES,indent=2,sort_keys=True)+"\n")
        source_files=[ROOT/"Makefile",ROOT/"src/diagnosis/align.py",ROOT/"src/diagnosis/input.py",ROOT/"src/diagnosis/rules.py",ROOT/"src/diagnosis/cli.py",ROOT/"tests/test_diagnosis_synthetic_accuracy.py",ROOT/"tests/test_diagnosis_cli.py"]
        provenance={str(path.relative_to(ROOT)):sha(path) for path in source_files}
        provenance["build/refscope"]=sha(BINARY)
        (args.output_dir/"source-and-binary-hashes.json").write_text(json.dumps(provenance,indent=2,sort_keys=True)+"\n")
        hashes={}
        for path in sorted(args.output_dir.rglob("meta.json")):
            hashes[str(path.relative_to(args.output_dir))]={"meta.json":sha(path)}
            for name in ("events.jsonl","summary.json","stacks.json"):
                file=path.parent/name
                hashes[str(path.relative_to(args.output_dir))][name]=sha(file)
        (args.output_dir/"input-hashes.json").write_text(json.dumps(hashes,indent=2,sort_keys=True)+"\n")
    print(json.dumps(summary,sort_keys=True))
    if temp: temp.cleanup()

if __name__=="__main__": main()
