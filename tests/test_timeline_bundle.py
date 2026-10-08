#!/usr/bin/env python3
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).parents[1]
BINARY = ROOT / "build/refscope"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        input_path = root / "events.jsonl"
        target = root / "targets.yaml"
        bundle = root / "run"
        target.write_text("name: fixture\n", encoding="utf-8")
        records = [
            {"record": "event", "type": "CREATE", "object": "0x1000", "ts_ns": 1_000_000_000, "stack_id": 7},
            {"record": "event", "type": "GET", "object": "0x1000", "ts_ns": 2_000_000_000, "stack_id": 7},
            {"record": "event", "type": "FREE", "object": "0x1000", "ts_ns": 3_000_000_000, "stack_id": 8},
            {
                "record": "stack",
                "stack_id": 7,
                "frames": [
                    {"ip": "0xffff0001", "symbol": "foo", "offset": 16, "source_file": "foo.c", "source_line": 10},
                    {"ip": "0xffff0002", "symbol": "bar", "offset": 4, "source_file": "bar.c", "source_line": 20},
                ],
            },
            {
                "record": "stack",
                "stack_id": 8,
                "frames": [
                    {"ip": "0x11110001", "symbol": "foo", "offset": 16, "source_file": "foo.c", "source_line": 11},
                    {"ip": "0x11110002", "symbol": "bar", "offset": 4, "source_file": "bar.c", "source_line": 20},
                ],
            },
            {"record": "stack", "stack_id": 9, "lookup_failed": True, "frames": []},
            {"record": "summary", "captured": 3},
        ]
        input_path.write_text(
            "\n".join(json.dumps(record, sort_keys=True) for record in records) + "\n",
            encoding="utf-8",
        )

        command = [
            str(BINARY), "timeline", "--input", str(input_path),
            "--format", "json", "--bundle", str(bundle),
            "--target-spec", str(target),
        ]
        first = subprocess.run(command, cwd=ROOT, text=True, capture_output=True)
        assert first.returncode == 0, first.stderr

        for name in ("meta.json", "events.jsonl", "stacks.json", "summary.json"):
            assert (bundle / name).is_file(), name

        meta = json.loads((bundle / "meta.json").read_text())
        assert meta["kernel_release"]
        assert meta["architecture"]
        assert meta["refscope_version"]
        assert meta["target_spec_hash"] == sha(target)
        assert meta["command_line"][0] == "refscope"
        assert meta["capture_capabilities"]["offline"] is True
        assert meta["capture_capabilities"]["bpf_attach"] is False
        assert meta["input_hashes"]["source_jsonl"] == sha(input_path)

        stacks = json.loads((bundle / "stacks.json").read_text())["stacks"]
        fp7 = next(stack["fingerprint"] for stack in stacks if stack["stack_id"] == 7)
        fp8 = next(stack["fingerprint"] for stack in stacks if stack["stack_id"] == 8)
        assert fp7 != fp8, (fp7, fp8)
        assert next(stack for stack in stacks if stack["stack_id"] == 9)["fingerprint"] is None

        summary = json.loads((bundle / "summary.json").read_text())
        obj = summary["timeline"]["objects"][0]
        assert obj["stack_fingerprints"] == [fp7, fp8]
        assert obj["events"][1]["stack_fingerprint"] == fp7
        assert obj["events"][2]["stack_fingerprint"] == fp8

        stable_names = ("events.jsonl", "stacks.json", "summary.json")
        first_hashes = {name: sha(bundle / name) for name in stable_names}
        second = subprocess.run(command, cwd=ROOT, text=True, capture_output=True)
        assert second.returncode == 0, second.stderr
        second_hashes = {name: sha(bundle / name) for name in stable_names}
        assert first_hashes == second_hashes

        rendered = subprocess.run(
            [str(BINARY), "timeline", "--input", str(bundle / "events.jsonl"), "--format", "json"],
            cwd=ROOT, text=True, capture_output=True,
        )
        assert rendered.returncode == 0, rendered.stderr
        rerun = json.loads(rendered.stdout)
        assert rerun["objects"][0]["stack_fingerprints"] == [fp7, fp8]

    print("Timeline bundle tests: passed")


if __name__ == "__main__":
    main()
