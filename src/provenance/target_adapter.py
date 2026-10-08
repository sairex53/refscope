#!/usr/bin/env python3
"""Translate an editable generated YAML target into the existing capture CLI."""
from __future__ import annotations

import os
from pathlib import Path
import re
import sys
from typing import Any

try:
    import yaml
except ImportError:
    yaml = None

ROLE_OPTIONS = {
    "acquire": "--get",
    "release": "--put",
    "create": "--create",
    "free": "--free",
}


def target_arguments(document: dict[str, Any]) -> list[str]:
    if document.get("schema_version") != 1:
        raise ValueError("unsupported target schema_version")
    operations = document.get("operations")
    transfers = document.get("transfers", [])
    if not isinstance(transfers, list):
        raise ValueError("target transfers must be a list")
    for index, transfer in enumerate(transfers):
        if not isinstance(transfer, dict):
            raise ValueError(f"transfer {index} must be a mapping")
        for field in ("from", "to", "key", "kind"):
            if not isinstance(transfer.get(field), str) or not transfer[field]:
                raise ValueError(f"transfer {index} requires nonempty {field}")
        for field in ("from", "to"):
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", transfer[field]):
                raise ValueError(f"transfer {index} has invalid {field} function")
        if not re.fullmatch(r"arg[0-4]", transfer["key"]):
            raise ValueError(f"transfer {index} key must be arg0..arg4")
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", transfer["kind"]):
            raise ValueError(f"transfer {index} has invalid kind")
    if not isinstance(operations, list) or not operations:
        raise ValueError("target has no operations; edit its YAML and add reviewed operations")
    result: list[str] = []
    for index, operation in enumerate(operations):
        if not isinstance(operation, dict):
            raise ValueError(f"operation {index} must be a mapping")
        role = operation.get("role")
        option = ROLE_OPTIONS.get(role)
        if option is None:
            raise ValueError(f"operation {index} has unsupported role: {role!r}")
        function = operation.get("function")
        if not isinstance(function, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", function):
            raise ValueError(f"operation {index} has invalid function name")
        obj = operation.get("object")
        match = re.fullmatch(r"arg([0-4])", obj or "")
        if not match:
            raise ValueError(
                f"operation {index} object must be arg0..arg4; field-offset capture is not supported"
            )
        spec = f"{function}:obj={obj}"
        reason = operation.get("reason")
        if reason is not None:
            reason_match = re.fullmatch(r"arg([0-4])", reason) if isinstance(reason, str) else None
            if not reason_match:
                raise ValueError(f"operation {index} reason must be arg0..arg4")
            spec += f",reason={reason}"
        result.extend([option, spec])
    return result


def translate(argv: list[str]) -> list[str]:
    if not argv or argv[0] != "trace":
        raise ValueError("YAML target adapter is only valid with refscope trace")
    rest = argv[1:]
    target_path = None
    forwarded = []
    index = 0
    while index < len(rest):
        item = rest[index]
        if item == "--target-spec":
            if target_path is not None or index + 1 >= len(rest):
                raise ValueError("--target-spec requires exactly one path")
            target_path = rest[index + 1]
            index += 2
            continue
        if item.startswith("--target-spec="):
            if target_path is not None:
                raise ValueError("--target-spec may be specified only once")
            target_path = item.split("=", 1)[1]
            index += 1
            continue
        forwarded.append(item)
        index += 1
    if not target_path:
        raise ValueError("--target-spec path is required")
    if yaml is None:
        raise ValueError("PyYAML is required to load a target specification")
    path = Path(target_path)
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"cannot read target specification {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ValueError(f"invalid target YAML: {exc}") from exc
    if not isinstance(document, dict):
        raise ValueError("target YAML root must be a mapping")
    return ["trace", *target_arguments(document), *forwarded]


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] != "trace":
        args.insert(0, "trace")
    try:
        translated = translate(args)
    except ValueError as exc:
        print(f"refscope: target specification error: {exc}", file=sys.stderr)
        return 2
    project = Path(__file__).resolve().parents[2]
    binary = project / "build/refscope"
    if not binary.is_file():
        print(f"refscope: capture executable not found: {binary}", file=sys.stderr)
        return 2
    os.execv(str(binary), [str(binary), *translated])
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
