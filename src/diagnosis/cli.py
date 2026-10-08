#!/usr/bin/env python3
"""Offline good/bad diagnosis CLI with deterministic text and JSON reports."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from diagnosis.align import compare_runs
from diagnosis.input import BundleError, load_bundle
from diagnosis.rules import generate_candidates


def _generation(value: str) -> int:
    try:
        parsed = int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("generation must be a positive integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("generation must be a positive integer")
    return parsed


def _object_key(value: Any) -> tuple[str, Any]:
    if isinstance(value, bool):
        return ("string", str(value).casefold())
    if isinstance(value, int):
        return ("number", value)
    text = str(value).strip()
    try:
        return ("number", int(text, 0))
    except ValueError:
        return ("string", text.casefold())


def _filtered_runs(runs: list[dict[str, Any]], args: argparse.Namespace) -> list[dict[str, Any]]:
    filtered = []
    for run in runs:
        lifetimes = []
        for lifetime in run.get("lifetimes", []):
            target = (lifetime.get("target_type") or lifetime.get("object_class")
                      or run.get("target_type") or run.get("object_class"))
            if args.target and str(target or "").casefold() != args.target.casefold():
                continue
            if args.object and _object_key(lifetime.get("object")) != _object_key(args.object):
                continue
            if args.generation is not None and lifetime.get("generation") != args.generation:
                continue
            lifetimes.append(lifetime)
        if lifetimes:
            item = dict(run)
            item["lifetimes"] = lifetimes
            filtered.append(item)
    return filtered


def _token_text(token: dict[str, Any]) -> str:
    op = token.get("op_type", "UNKNOWN")
    function = token.get("source_function") or token.get("normalized_function") or "?"
    if op == "CALL_RETURN":
        value = token.get("return_name") or token.get("return_value")
        rendered = value if value is not None else (token.get("return_class") or "unknown")
        return f"return {rendered} ({function})"
    return f"{op} {function}(...)"


def _context_tokens(tokens: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if len(tokens) <= 3:
        return tokens
    important = [token for token in tokens
                 if token.get("op_type") in {"GET", "PUT", "FREE", "CALL_RETURN"}]
    if len(important) <= 3:
        return important
    middle = len(important) // 2
    return important[max(0, middle - 1):middle + 2]


def _rule_label(rule: str) -> str:
    return {
        "unmatched_acquisition": "unmatched acquisition",
        "extra_release": "extra release",
        "early_final_release": "early final release",
        "ownership_transfer_divergence": "ownership transfer divergence",
        "error_path_divergence": "error-path divergence",
    }.get(rule, rule.replace("_", " "))


def _candidate_text(candidate: dict[str, Any]) -> list[str]:
    good_runs = candidate.get("good_pattern_recurrence", {})
    bad_runs = candidate.get("bad_pattern_recurrence", {})
    lines = [
        "Likely reference-lifetime divergence",
        "",
        f"Object class: {candidate.get('target_type') or 'unknown'}",
        f"Confidence: {candidate['confidence']}",
        f"Rule: {_rule_label(candidate['rule'])}",
        f"Score: {candidate['score']}",
        f"Candidate ID: {candidate['candidate_id']}",
        "",
        f"Good runs: {good_runs.get('present', 0)}/{good_runs.get('eligible', 0)}",
        f"Bad runs: {bad_runs.get('present', 0)}/{bad_runs.get('eligible', 0)}",
        "",
        "Divergence:",
    ]
    window = candidate.get("divergence_window", {})
    for side in ("good", "bad"):
        tokens = _context_tokens(window.get(side, []))
        if tokens:
            lines.append(f"  {side}: " + " | ".join(_token_text(token) for token in tokens))
    lines.extend([
        "",
        "Candidate:",
        f"  {candidate['description']}",
        "  Score components: " + json.dumps(candidate["score_components"], sort_keys=True),
    ])
    sources = candidate.get("source_locations", [])
    if sources:
        source_line = "  Source: " + ", ".join(
            f"{item['file']}:{item['line']}" for item in sources[:3])
        if len(sources) > 3:
            source_line += f" (+{len(sources) - 3} more)"
        lines.append(source_line)
    warnings = candidate.get("warnings", [])
    if warnings:
        lines.append("Warnings:")
        lines.extend(f"  - {warning}" for warning in warnings[:4])
        if len(warnings) > 4:
            lines.append(f"  - ... {len(warnings) - 4} more; see JSON report")
    lines.append("  Candidate only; root cause is not proven.")
    return lines


def _render_text(result: dict[str, Any]) -> str:
    candidates = result["candidates"]
    if not candidates:
        lines = ["No candidate rule matched the selected good/bad runs."]
        for run in result["runs"]:
            warnings = run["capture_quality"].get("warnings", [])
            if warnings:
                lines.append(f"{run['label']} {run['run_id']} warnings: {', '.join(warnings)}")
        return "\n".join(lines) + "\n"
    lines = _candidate_text(candidates[0])
    if len(candidates) > 1:
        lines.extend(["", "Other candidates:"])
        for candidate in candidates[1:4]:
            lines.append(f"  {_rule_label(candidate['rule'])}: score={candidate['score']} "
                         f"confidence={candidate['confidence']} id={candidate['candidate_id']}")
        if len(candidates) > 4:
            lines.append(f"  ... {len(candidates) - 4} more; use --format json for the complete report")
    return "\n".join(lines) + "\n"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="refscope diagnose")
    parser.add_argument("runs", help="directory containing labeled run bundles")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--target", help="filter by target/object type")
    parser.add_argument("--object", help="filter by object address, for example 0xffff...")
    parser.add_argument("--generation", type=_generation, help="filter by lifetime generation")
    parser.add_argument("--output", help="write the selected report format to this path")
    return parser


def main(argv=None):
    parser = _build_parser()
    args = parser.parse_args(argv)
    root = Path(args.runs)
    if not root.is_dir():
        print(f"refscope: diagnosis runs directory not found: {root}", file=sys.stderr)
        return 2
    try:
        bundle_dirs = sorted({path.parent for path in root.rglob("meta.json")})
        runs = [load_bundle(path) for path in bundle_dirs]
        if not runs:
            raise BundleError("no run bundles found")
        good_all = [run for run in runs if run["label"] == "good"]
        bad_all = [run for run in runs if run["label"] == "bad"]
        if not good_all:
            raise BundleError("no good runs found")
        if not bad_all:
            raise BundleError("no bad runs found")
        selected = _filtered_runs(runs, args)
        good_runs = sorted((run for run in selected if run["label"] == "good"),
                           key=lambda run: run["run_id"])
        bad_runs = sorted((run for run in selected if run["label"] == "bad"),
                          key=lambda run: run["run_id"])
        if not good_runs:
            raise BundleError("filters matched no good runs")
        if not bad_runs:
            raise BundleError("filters matched no bad runs")
    except (BundleError, OSError) as exc:
        print(f"refscope: diagnosis input error: {exc}", file=sys.stderr)
        return 2

    alignments = [compare_runs(good, bad) for good in good_runs for bad in bad_runs]
    candidates = generate_candidates(good_runs, bad_runs)
    result = {
        "schema_version": 1,
        "mode": "offline-explicit-candidate-rules",
        "ranking_performed": True,
        "root_cause_proven": False,
        "alignment_algorithm": "weighted-lcs-v1",
        "candidate_rules": ["unmatched_acquisition", "extra_release",
                            "early_final_release", "ownership_transfer_divergence",
                            "error_path_divergence"],
        "filters": {"target": args.target, "object": args.object,
                    "generation": args.generation},
        "alignments": alignments,
        "candidates": candidates,
        "run_count": len(selected),
        "runs": [{"run_id": run["run_id"], "label": run["label"],
                  "lifetime_count": len(run["lifetimes"]),
                  "token_count": sum(len(item["tokens"]) for item in run["lifetimes"]),
                  "capture_quality": run["capture_quality"]} for run in selected],
    }
    rendered = (json.dumps(result, indent=2, sort_keys=True) + "\n"
                if args.format == "json" else _render_text(result))
    if args.output:
        try:
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(rendered, encoding="utf-8")
        except OSError as exc:
            print(f"refscope: cannot write report {args.output}: {exc}", file=sys.stderr)
            return 2
    sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
