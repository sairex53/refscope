#!/usr/bin/env python3

import json
import subprocess

result = subprocess.run(
    ["./build/test-json"],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    check=True,
)

lines = result.stdout.splitlines()

assert len(lines) == 3, lines

decoded = [
    json.loads(line.decode("utf-8"))
    for line in lines
]

assert decoded[0] == "Привет", decoded[0]
assert decoded[1] == 'quote" slash\\ tab\t', repr(decoded[1])
assert decoded[2] == "AÿB", decoded[2]

# Invalid raw 0xff must not leak into JSON output.
assert b"\xff" not in lines[2], lines[2]
assert b"\\u00ff" in lines[2].lower(), lines[2]

print("JSON escaping: passed")
