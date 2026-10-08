#!/usr/bin/env python3
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT=Path(__file__).parents[1]
sys.path.insert(0,str(ROOT/"src"))
sys.path.insert(0,str(ROOT/"tests"))
from test_diagnosis_input import fixture
from timeline.bundle import build_bundle

BINARY=ROOT/"build/refscope"

def make_bundle(parent,label,with_put=False,incomplete=False,ts_delta=0):
    bundle=fixture(parent,label,incomplete=incomplete)
    source=parent/"capture.jsonl"
    rows=[json.loads(line) for line in source.read_text().splitlines()]
    if with_put:
        free=next(i for i,row in enumerate(rows)
                  if row.get("record")=="event" and row.get("type")=="FREE")
        rows.insert(free,{"record":"event","type":"PUT","object":"0x1000","ts_ns":4,
                          "function":"foo_put","reason":"WORK",
                          "object_class":"struct foo","stack_id":1})
        for row in rows:
            if row.get("record")=="summary":
                row["attempted"]+=1
                row["captured"]+=1
    if ts_delta:
        for row in rows:
            if row.get("record")=="event":
                row["ts_ns"]+=ts_delta
    source.write_text("\n".join(json.dumps(row,sort_keys=True) for row in rows)+"\n")
    return build_bundle(source,bundle,label=label)


def make_pair(root,incomplete=False,multiple=1):
    for i in range(multiple):
        make_bundle(root/f"good-src-{i}","good",with_put=True,ts_delta=i)
        make_bundle(root/f"bad-src-{i}","bad",incomplete=incomplete,ts_delta=i+100)


def invoke(root,*args):
    return subprocess.run([str(BINARY),"diagnose",str(root),*args],
                          cwd=ROOT,text=True,capture_output=True)


def test_top_card_json_equivalence_output_path(root):
    make_pair(root)
    # A second, genuinely independent lower-score divergence verifies that JSON
    # returns a ranked list rather than relying on a duplicate error-path rule.
    for side in ("good", "bad"):
        source=root/f"{side}-src-0"/"capture.jsonl"
        rows=[json.loads(line) for line in source.read_text().splitlines()]
        summary=next(row for row in rows if row.get("record")=="summary")
        rows.remove(summary)
        rows.extend([
            {"record":"event","type":"CREATE","object":"0x2000","ts_ns":20,
             "function":"bar_create","object_class":"struct bar"},
            {"record":"event","type":"GET","object":"0x2000","ts_ns":21,
             "function":"bar_get","object_class":"struct bar"},
        ])
        if side=="good":
            rows.append({"record":"event","type":"PUT","object":"0x2000","ts_ns":22,
                         "function":"bar_put","object_class":"struct bar"})
        rows.append({"record":"event","type":"FREE","object":"0x2000","ts_ns":23,
                     "function":"bar_free","object_class":"struct bar"})
        summary["attempted"]+=4 if side=="good" else 3
        summary["captured"]+=4 if side=="good" else 3
        rows.append(summary)
        source.write_text("".join(json.dumps(row,sort_keys=True)+"\n" for row in rows))
        build_bundle(source,source.parent/side,label=side)
    output=root/"nested"/"report.json"
    result=invoke(root,"--format","json","--output",str(output))
    assert result.returncode==0,result.stderr
    assert output.read_text()==result.stdout
    repeated=invoke(root,"--format","json")
    assert repeated.returncode==0 and repeated.stdout==result.stdout
    report=json.loads(result.stdout)
    assert len(report["candidates"])>=2
    top=report["candidates"][0]
    assert top["capture_quality"]["good"] and top["capture_quality"]["bad"]
    assert top["run_ids"]["good"] and top["run_ids"]["bad"]
    assert top["cohort_ids"] and top["divergence_window"]["good"]
    assert top["score_components"] and top["evidence"]
    text_result=invoke(root,"--format","text")
    assert text_result.returncode==0,text_result.stderr
    text=text_result.stdout
    assert len(text.splitlines())<=30
    assert f"Candidate ID: {top['candidate_id']}" in text
    assert f"Confidence: {top['confidence']}" in text
    assert f"Score: {top['score']}" in text
    assert json.dumps(top["score_components"],sort_keys=True) in text
    assert "Good runs:" in text and "Bad runs:" in text
    assert "return -12 (foo_fail)" in text
    assert "Candidate only; root cause is not proven." in text
    for candidate in report["candidates"]:
        assert (f"Candidate ID: {candidate['candidate_id']}" in text
                or f"id={candidate['candidate_id']}" in text)
    text_path=root/"report.txt"
    saved_text=invoke(root,"--format","text","--output",str(text_path))
    assert saved_text.returncode==0 and text_path.read_text()==saved_text.stdout
    assert invoke(root,"--format","text").stdout==saved_text.stdout


def test_multiple_runs_and_filters(root):
    make_pair(root,multiple=2)
    result=invoke(root,"--format","json","--target","struct foo",
                  "--object","0x1000","--generation","0x1")
    assert result.returncode==0,result.stderr
    report=json.loads(result.stdout)
    assert report["run_count"]==4
    assert report["filters"]=={"target":"struct foo","object":"0x1000","generation":1}
    assert report["candidates"]
    assert report["candidates"][0]["good_pattern_recurrence"]=={
        "present":2,"eligible":2,"ratio":1.0}
    assert report["candidates"][0]["bad_pattern_recurrence"]=={
        "present":2,"eligible":2,"ratio":1.0}
    assert invoke(root,"--object","0xdead").returncode==2
    assert "filters matched no good runs" in invoke(root,"--object","0xdead").stderr
    assert invoke(root,"--generation","2").returncode==2
    assert "filters matched no good runs" in invoke(root,"--generation","2").stderr
    assert invoke(root,"--generation","0").returncode==2


def test_missing_labels_invalid_and_incomplete(root):
    only_good=root/"only-good"
    make_bundle(only_good/"good-source","good",with_put=True)
    missing_bad=invoke(only_good)
    assert missing_bad.returncode==2 and "no bad runs found" in missing_bad.stderr
    only_bad=root/"only-bad"
    make_bundle(only_bad/"bad-source","bad")
    missing_good=invoke(only_bad)
    assert missing_good.returncode==2 and "no good runs found" in missing_good.stderr
    invalid=root/"invalid"
    invalid.mkdir()
    no_runs=invoke(invalid)
    assert no_runs.returncode==2 and "no run bundles found" in no_runs.stderr
    absent=invoke(root/"does-not-exist")
    assert absent.returncode==2 and "directory not found" in absent.stderr

    incomplete=root/"all-incomplete"
    make_pair(incomplete,incomplete=True)
    result=invoke(incomplete,"--format","json")
    assert result.returncode==0,result.stderr
    report=json.loads(result.stdout)
    assert report["candidates"]
    candidate=report["candidates"][0]
    assert candidate["confidence"]=="INFERRED"
    assert any("capture_marked_incomplete" in quality["warnings"]
               for quality in candidate["capture_quality"]["bad"].values())


def test_malformed_bundle(root):
    make_pair(root)
    bundle=next(root.rglob("meta.json")).parent
    (bundle/"summary.json").unlink()
    result=invoke(root,"--format","json")
    assert result.returncode==2
    assert "missing summary" in result.stderr


def main():
    with tempfile.TemporaryDirectory() as directory:
        root=Path(directory)
        test_top_card_json_equivalence_output_path(root/"valid")
        test_multiple_runs_and_filters(root/"multiple")
        test_missing_labels_invalid_and_incomplete(root/"edge")
        test_malformed_bundle(root/"malformed")
    print("Diagnosis CLI/report tests: passed")

if __name__=="__main__":
    main()
