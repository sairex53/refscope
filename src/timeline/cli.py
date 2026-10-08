#!/usr/bin/env python3
"""User-facing offline timeline renderer and run-bundle writer."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from timeline.bundle import build_bundle, read_records
from timeline.engine import Timeline, read_jsonl


def _parse_object(value: str) -> int:
    try:
        result = int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "object must be a nonzero hexadecimal or decimal pointer"
        ) from exc
    if result <= 0:
        raise argparse.ArgumentTypeError("object must be a nonzero pointer")
    return result


def _parse_generation(value: str) -> int:
    try:
        result = int(value, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("generation must be a positive integer") from exc
    if result <= 0:
        raise argparse.ArgumentTypeError("generation must be a positive integer")
    return result


def _selected(document: dict[str, Any], address: int | None, generation: int | None):
    selected = []
    for obj in document["objects"]:
        if address is not None and int(obj["object"], 0) != address:
            continue
        if generation is not None and obj["generation"] != generation:
            continue
        selected.append(obj)
    return selected


def _delta(ts: Any, first: Any) -> str:
    if not isinstance(ts, int) or not isinstance(first, int):
        return "unknown"
    return f"{(ts - first) / 1_000_000_000:.6f}"


def _event_text(event: dict[str, Any], first: Any) -> str:
    fields = [event["type"]]
    if "function" in event:
        fields.append(str(event["function"]))
    if event.get("reason") is not None:
        fields.append(f"reason={event['reason']}")
    if event.get("stack_id") is not None:
        fields.append(f"stack={event['stack_id']}")
    if event.get("stack_fingerprint") is not None:
        fields.append(f"fingerprint={event['stack_fingerprint']}")
    return f"+{_delta(event.get('ts_ns'), first)} " + " ".join(fields)


def render_text(document: dict[str, Any]) -> str:
    lines: list[str] = []
    for obj in document["objects"]:
        lines.extend([
            f"Object {obj['object']} generation={obj['generation']}",
            "",
        ])
        for event in obj["events"]:
            lines.append(_event_text(event, obj["first_seen"]))
        lines.extend([
            "",
            "END STATE:",
            f"  origin: {obj['origin']}",
            f"  observed gets: {obj['observed_gets']}",
            f"  observed puts: {obj['observed_puts']}",
            f"  observed balance: {obj['observed_balance']}",
            f"  actual refcount: {obj['actual_refcount'] if obj['actual_refcount'] is not None else 'null'}",
            "  suspicion flags: " + (
                ", ".join(obj["suspicion_flags"]) if obj["suspicion_flags"] else "none"
            ),
            "",
        ])
    return "\n".join(lines).rstrip() + ("\n" if lines else "")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="refscope timeline")
    result.add_argument("--input", required=True, help="saved event JSONL path")
    result.add_argument("--format", choices=("text", "json"), default="text")
    result.add_argument("--object", type=_parse_object)
    result.add_argument("--generation", type=_parse_generation)
    result.add_argument("--bundle", help="write a reproducible offline run bundle")
    result.add_argument("--label", choices=("good", "bad", "unlabeled"), help="manual run class stored in a bundle")
    result.add_argument("--target-spec", help="target specification used for the capture")
    result.add_argument("--vmlinux", help="vmlinux used for source resolution")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.label is not None and not args.bundle:
        parser().error("--label requires --bundle")
    try:
        if args.bundle:
            events, _, _ = read_records(args.input)
            document = Timeline().process(events).as_dict()
            build_bundle(
                args.input,
                args.bundle,
                target_spec=args.target_spec,
                vmlinux=args.vmlinux,
                command_line=["refscope", "timeline"] + list(argv or sys.argv[1:]),
                label=args.label or "unlabeled",
            )
        else:
            document = read_jsonl(args.input).as_dict()
    except FileNotFoundError:
        print(f"refscope: timeline input not found: {args.input}", file=sys.stderr)
        return 2
    except (OSError, ValueError) as exc:
        print(f"refscope: timeline input error: {exc}", file=sys.stderr)
        return 2

    document["objects"] = _selected(document, args.object, args.generation)
    if args.format == "json":
        json.dump(document, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        sys.stdout.write(render_text(document))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
