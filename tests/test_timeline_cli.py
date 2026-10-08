#!/usr/bin/env python3
import json
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).parents[1]
BINARY = ROOT / "build/refscope"


def run(*args):
    return subprocess.run(
        [str(BINARY), "timeline", *args],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )


def write(path, text):
    path.write_text(text, encoding="utf-8")


def main():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        events = root / "events.jsonl"
        write(
            events,
            "\n".join(
                [
                    json.dumps({"record": "event", "type": "CREATE", "object": "0x1000", "ts_ns": 1_000_000_000}),
                    json.dumps({"record": "event", "type": "GET", "object": "0x1000", "ts_ns": 2_000_000_000, "reason": "WORK"}),
                    json.dumps({"record": "event", "type": "PUT", "object": "0x1000", "ts_ns": 3_000_000_000}),
                    json.dumps({"record": "event", "type": "FREE", "object": "0x1000", "ts_ns": 4_000_000_000}),
                    json.dumps({"record": "event", "type": "CREATE", "object": "0x1000", "ts_ns": 5_000_000_000}),
                    json.dumps({"record": "event", "type": "GET", "object": "0x1000", "ts_ns": 6_000_000_000}),
                    json.dumps({"record": "event", "type": "CREATE", "object": "0x2000", "ts_ns": 7_000_000_000}),
                ]
            )
            + "\n",
        )

        text = run("--input", str(events), "--format", "text")
        assert text.returncode == 0, text.stderr
        assert "Object 0x1000 generation=1" in text.stdout
        assert "Object 0x1000 generation=2" in text.stdout
        assert "+1.000000 GET reason=WORK" in text.stdout
        assert "observed balance: 0" in text.stdout

        machine = run("--input", str(events), "--format", "json")
        assert machine.returncode == 0, machine.stderr
        document = json.loads(machine.stdout)
        assert len(document["objects"]) == 3
        assert document["objects"][0]["observed_balance"] == 0
        assert document["objects"][1]["generation"] == 2
        assert document["objects"][1]["actual_refcount"] is None

        filtered_object = run("--input", str(events), "--format", "json", "--object", "0x2000")
        assert filtered_object.returncode == 0
        assert [obj["object"] for obj in json.loads(filtered_object.stdout)["objects"]] == ["0x2000"]

        filtered_generation = run(
            "--input", str(events), "--format", "json",
            "--object", "0x1000", "--generation", "2",
        )
        assert filtered_generation.returncode == 0
        objects = json.loads(filtered_generation.stdout)["objects"]
        assert len(objects) == 1 and objects[0]["generation"] == 2

        malformed = root / "malformed.jsonl"
        write(malformed, '{"record":"event"\n')
        result = run("--input", str(malformed), "--format", "json")
        assert result.returncode == 2
        assert "timeline input error" in result.stderr

        unknown = root / "unknown.jsonl"
        write(unknown, json.dumps({"record": "event", "type": "BOGUS", "object": "0x1"}) + "\n")
        result = run("--input", str(unknown), "--format", "json")
        assert result.returncode == 2
        assert "unsupported timeline event type" in result.stderr

        missing = root / "missing.jsonl"
        write(missing, json.dumps({"record": "event", "type": "GET"}) + "\n")
        result = run("--input", str(missing), "--format", "json")
        assert result.returncode == 2
        assert "event object is required" in result.stderr

        result = run("--input", str(events), "--format", "json", "--object", "not-a-pointer")
        assert result.returncode == 2
        assert "object must be a nonzero hexadecimal or decimal pointer" in result.stderr

        result = run("--input", str(events), "--format", "json", "--generation", "0")
        assert result.returncode == 2
        assert "generation must be a positive integer" in result.stderr

    print("Timeline CLI tests: passed")


if __name__ == "__main__":
    main()
