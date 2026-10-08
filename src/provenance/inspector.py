#!/usr/bin/env python3
"""Offline, evidence-ranked target discovery; suggestions are never semantic proof."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any

try:
    import yaml
except ImportError:
    yaml = None

from provenance.model import (
    Confidence, EvidenceClaim, EvidenceSource, resolve_claims,
)
from provenance.source_index import index_source_tree

INSPECTOR_VERSION = "0.2.0"
NAME_ROLE = (
    (re.compile(r"(?:^|_)(?:get|acquire|hold|grab|lookup|tryget)(?:_|$)"), "acquire"),
    (re.compile(r"(?:^|_)(?:put|release|drop|unref|free)(?:_|$)"), "release"),
)
PRIMITIVE_ROLES = {
    "refcount_inc": "acquire", "refcount_inc_not_zero": "acquire",
    "atomic_inc": "acquire", "atomic_inc_not_zero": "acquire",
    "kref_get": "acquire", "kref_get_unless_zero": "acquire",
    "percpu_ref_get": "acquire", "percpu_ref_tryget_live": "acquire",
    "ref_tracker_alloc": "acquire",
    "refcount_dec": "release", "refcount_dec_and_test": "release",
    "atomic_dec": "release", "atomic_dec_and_test": "release",
    "kref_put": "release", "percpu_ref_put": "release",
    "ref_tracker_free": "release",
}
FUNC_RE = re.compile(
    r"(?m)^[ \t]*(?:(?:static|inline|__always_inline|noinline)\s+)*"
    r"[\w\s\*]+?\b([A-Za-z_]\w*)\s*\(([^;{}]*)\)\s*\{"
)


def _sha256(path: Path) -> str | None:
    try:
        h = hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                h.update(block)
        return h.hexdigest()
    except OSError:
        return None


def _type_tag(type_name: str) -> str:
    return type_name.removeprefix("struct ").removeprefix("union ").strip()


def _functions(text: str):
    for match in FUNC_RE.finditer(text):
        depth, end = 1, match.end()
        while end < len(text) and depth:
            if text[end] == "{":
                depth += 1
            elif text[end] == "}":
                depth -= 1
            end += 1
        if depth == 0:
            yield match.group(1), match.group(2), text[match.end():end - 1], match.start()


def _parameters(signature: str) -> list[str]:
    # Kernel wrapper signatures used here are ordinary C prototype arguments;
    # this split deliberately does not pretend to parse arbitrary C declarators.
    values, current, depth = [], [], 0
    for char in signature:
        if char == "," and depth == 0:
            values.append("".join(current).strip())
            current = []
            continue
        current.append(char)
        if char in "([":
            depth += 1
        elif char in ")]":
            depth = max(0, depth - 1)
    if current:
        values.append("".join(current).strip())
    if values == ["void"] or values == [""]:
        return []
    return values


def _arg_for_type(signature: str, type_name: str) -> tuple[str | None, int | None]:
    for index, param in enumerate(_parameters(signature)):
        if type_name not in param:
            continue
        identifiers = re.findall(r"[A-Za-z_]\w*", param)
        if identifiers:
            name = identifiers[-1]
            if name in {"const", "volatile", "struct", "union"}:
                name = None
            return (f"arg{index}", index) if name else (None, index)
    return None, None


def _role_from_name(name: str) -> str | None:
    for pattern, role in NAME_ROLE:
        if pattern.search(name):
            return role
    return None


def _field_from_expr(expr: str, param_name: str | None) -> str | None:
    if not param_name:
        return None
    match = re.search(r"\b" + re.escape(param_name) + r"\s*(?:->|\.)\s*([A-Za-z_]\w*)", expr)
    return match.group(1) if match else None


def _source_candidates(type_name: str, tree: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]], bool]:
    return index_source_tree(type_name, tree)


def _btf_info(vmlinux: Path | None, type_name: str) -> dict[str, Any]:
    result: dict[str, Any] = {"available": False, "type_found": False,
                              "fields": [], "kfuncs": [], "warning": None}
    if vmlinux is None:
        result["warning"] = "no vmlinux provided; BTF/kfunc inspection unavailable"
        return result
    tool = shutil.which("bpftool")
    if not tool:
        result["warning"] = "bpftool unavailable; BTF/kfunc inspection unavailable"
        return result
    try:
        proc = subprocess.run(
            [tool, "btf", "dump", "file", str(vmlinux), "format", "raw"],
            text=True, capture_output=True, timeout=60, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        result["warning"] = f"could not inspect vmlinux BTF: {exc}"
        return result
    if proc.returncode:
        result["warning"] = "vmlinux has no readable embedded BTF"
        return result
    result["available"] = True
    lines = proc.stdout.splitlines()
    tag = _type_tag(type_name)
    for index, line in enumerate(lines):
        match = re.search(r"\]\s+(?:STRUCT|UNION)\s+'([^']+)'", line)
        if not match or match.group(1) != tag:
            continue
        result["type_found"] = True
        for member in lines[index + 1:]:
            if re.match(r"\s*\[\d+\]\s+", member):
                break
            field = re.search(r"'([^']+)'\s+type_id=", member)
            if field:
                result["fields"].append(field.group(1))
        break
    # BTF usually contains function prototypes, not the kernel's registered
    # kfunc set. Only explicit acquire/release declaration tags are reported.
    by_id: dict[str, str] = {}
    tags = []
    for line in lines:
        item = re.search(r"\[(\d+)\]\s+FUNC\s+'([^']+)'", line)
        if item:
            by_id[item.group(1)] = item.group(2)
        tag_match = re.search(r"\[(\d+)\]\s+DECL_TAG\s+'([^']*(?:KF_ACQUIRE|KF_RELEASE)[^']*)'\s+type_id=(\d+)", line)
        if tag_match:
            tags.append((tag_match.group(2), tag_match.group(3)))
    result["kfuncs"] = [
        {"function": by_id.get(target_id), "tag": tag}
        for tag, target_id in tags if by_id.get(target_id)
    ]
    if not result["kfuncs"]:
        result["warning"] = (
            "BTF is available, but no function-linked KF_ACQUIRE/KF_RELEASE tags were found; "
            "the runtime registered kfunc set cannot be inferred from ordinary vmlinux BTF"
        )
    return result


def _merge_btf_candidates(candidates: list[dict[str, Any]],
                          btf: dict[str, Any],
                          type_name: str | None = None) -> list[dict[str, Any]]:
    by_name = {item["function"]: item for item in candidates}
    btf.setdefault("warnings", [])
    for evidence in btf.get("kfuncs", []):
        name = evidence.get("function")
        tag = evidence.get("tag", "")
        object_type = evidence.get("bpf_visible_object")
        if evidence.get("registered") is not True or not object_type:
            btf["warnings"].append(
                f"{name or 'unnamed function'} BTF tag ignored: runtime registration and BPF-visible object applicability are unproven"
            )
            continue
        if type_name and object_type != type_name:
            btf["warnings"].append(
                f"{name} kfunc object type {object_type!r} does not match {type_name!r}"
            )
            continue
        if not name:
            continue
        role = "acquire" if "KF_ACQUIRE" in tag else "release" if "KF_RELEASE" in tag else None
        if role is None:
            continue
        claim = EvidenceClaim(role, EvidenceSource.BTF_KFUNC, Confidence.STRONG)
        existing = by_name.get(name)
        if existing is None:
            existing = {
                "function": name, "role": role, "object_argument": None,
                "object_field": None, "evidence_source": EvidenceSource.BTF_KFUNC.value,
                "confidence": claim.confidence.value,
                "reasons": [f"BTF declaration tag {tag}"],
                "source_location": None,
                "warnings": ["BTF tag supplies semantics but no object argument was resolved"],
            }
            candidates.append(existing)
            by_name[name] = existing
            continue
        resolution = resolve_claims([
            EvidenceClaim(existing["role"], existing["evidence_source"], existing["confidence"]),
            claim,
        ])
        existing["role"] = resolution.value or existing["role"]
        existing["evidence_source"] = (
            resolution.evidence_source.value if resolution.evidence_source
            else existing["evidence_source"]
        )
        existing["confidence"] = resolution.confidence.value
        existing["reasons"].append(f"BTF declaration tag {tag}")
        if resolution.conflicting_sources:
            existing["warnings"].append(
                "BTF/source role conflict: " + ", ".join(
                    source.value for source in resolution.conflicting_sources
                )
            )
    return candidates
def _tracepoints(type_name: str, tree: Path | None) -> list[dict[str, str]]:
    found: dict[tuple[str, str], dict[str, str]] = {}
    roots = []
    for path in (Path("/sys/kernel/tracing/events"), Path("/sys/kernel/debug/tracing/events")):
        if path.is_dir():
            roots.append(path)
    if tree:
        roots.extend([tree / "include/trace/events", tree / "include/trace"])
    tag = _type_tag(type_name).lower()
    for root in roots:
        if not root.exists():
            continue
        if root.name == "events":
            for system in sorted(root.iterdir()):
                if not system.is_dir():
                    continue
                for event in sorted(system.iterdir()):
                    if event.is_dir() and (tag in system.name.lower() or tag in event.name.lower()
                                           or "ref" in event.name.lower()):
                        found[(system.name, event.name)] = {
                            "system": system.name, "event": event.name,
                            "evidence": "runtime tracefs registration",
                            "availability": "available_runtime",
                        }
        else:
            for path in sorted(root.rglob("*.h")):
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if tag not in text.lower() and "ref" not in path.name.lower():
                    continue
                for match in re.finditer(r"\bTRACE_EVENT(?:_FN|_CONDITION)?\s*\(\s*([A-Za-z_]\w*)", text):
                    name = match.group(1)
                    if tag in name.lower() or "ref" in name.lower() or tag in text[match.start():match.start()+400].lower():
                        found[(path.stem, name)] = {
                            "system": path.stem, "event": name,
                            "evidence": f"trace event declaration in {path}",
                            "availability": "declared_only_runtime_unverified",
                        }
    return list(found.values())


def _elf_build_id(path: Path) -> str | None:
    tool = shutil.which("readelf")
    if not tool:
        return None
    try:
        proc = subprocess.run([tool, "-n", str(path)], text=True, capture_output=True,
                              timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    match = re.search(r"Build ID:\s*([0-9a-fA-F]+)", proc.stdout) if proc.returncode == 0 else None
    return match.group(1).lower() if match else None


def _source_vmlinux_relation(kernel_tree: Path | None,
                             vmlinux: Path | None) -> dict[str, Any]:
    if not kernel_tree or not vmlinux:
        return {"status": "not_comparable", "tree_elf": None,
                "tree_build_id": None, "vmlinux_build_id": _elf_build_id(vmlinux) if vmlinux else None}
    candidates = [kernel_tree / "vmlinux", kernel_tree / "vmlinux.debug",
                  kernel_tree / "build/vmlinux"]
    tree_elf = next((item for item in candidates if item.is_file()), None)
    supplied_id = _elf_build_id(vmlinux)
    tree_id = _elf_build_id(tree_elf) if tree_elf else None
    status = "matched" if tree_id and supplied_id and tree_id == supplied_id else (
        "mismatch" if tree_id and supplied_id else "unverified")
    return {"status": status, "tree_elf": str(tree_elf) if tree_elf else None,
            "tree_build_id": tree_id, "vmlinux_build_id": supplied_id}


def analyze_target(type_name: str, kernel_tree: Path | None = None,
                   vmlinux: Path | None = None) -> dict[str, Any]:
    if not re.fullmatch(r"(?:struct|union)\s+[A-Za-z_]\w*", type_name):
        raise ValueError("--type must be 'struct NAME' or 'union NAME'")
    source_candidates, tracker, source_available = (
        _source_candidates(type_name, kernel_tree) if kernel_tree and kernel_tree.is_dir()
        else ([], [], False)
    )
    btf = _btf_info(vmlinux, type_name)
    source_vmlinux_relation = _source_vmlinux_relation(kernel_tree, vmlinux)
    if kernel_tree and vmlinux and source_vmlinux_relation["status"] != "matched":
        btf.setdefault("warnings", []).append(
            "vmlinux/source-tree build identity is not verified; BTF claims were not merged into source candidates"
        )
    else:
        source_candidates = _merge_btf_candidates(source_candidates, btf, type_name)
    tracepoints = _tracepoints(type_name, kernel_tree)
    mode = "inspected" if source_candidates else "manual"
    warnings = []
    if not source_available:
        warnings.append("kernel source tree unavailable; source analysis disabled")
    if not btf["available"]:
        warnings.append(btf["warning"] or "BTF unavailable")
    if btf.get("warning"):
        warnings.append(btf["warning"])
    warnings.extend(btf.get("warnings", []))
    if kernel_tree and vmlinux and source_vmlinux_relation["status"] != "matched":
        warnings.append("vmlinux does not have a verified matching build ID in the source tree")
    if mode == "manual":
        warnings.append("manual mode: no acquire/release API semantics were resolved; review and fill operations")
    if not tracepoints:
        warnings.append("no matching tracepoints were discovered; absence is not proof none exist")
    if any(item["warnings"] for item in source_candidates):
        warnings.append("one or more API candidates have conflicting or unresolved role evidence")
    for item in source_candidates:
        if item["confidence"] == "EXACT":
            item["confidence"] = "STRONG"
            item["warnings"].append("inspector never promotes API candidates to EXACT")
    if source_available and not source_candidates:
        warnings.append("source tree scanned, but no matching candidate API was identified")
    return {
        "target_type": type_name,
        "mode": mode,
        "source_vmlinux_relation": source_vmlinux_relation,
        "candidate_acquire_apis": [item for item in source_candidates if item["role"] == "acquire"],
        "candidate_release_apis": [item for item in source_candidates if item["role"] == "release"],
        "all_candidates": source_candidates,
        "object_locations": [
            {"function": item["function"], "argument": item["object_argument"],
             "arguments": item.get("object_arguments", []),
             "field": item["object_field"], "fields": item.get("object_fields", []),
             "ambiguous_data_flow": item.get("ambiguous_data_flow", False),
             "evidence_source": item["evidence_source"],
             "confidence": item["confidence"]}
            for item in source_candidates
        ],
        "available_tracepoints": tracepoints,
        "ref_tracker_evidence": tracker,
        "btf_kfunc_evidence": btf,
        "source_analysis": {
            "available": source_available,
            "candidate_count": len(source_candidates),
            "evidence_source": EvidenceSource.SOURCE_ANALYSIS.value,
        },
        "confidence": {
            "strongest_candidate": max(
                (item["confidence"] for item in source_candidates),
                key={"UNKNOWN": 0, "INFERRED": 1, "STRONG": 2, "EXACT": 3}.get,
                default="UNKNOWN",
            ),
            "policy": "name-only evidence is INFERRED; no API candidate is EXACT",
        },
        "warnings": warnings,
    }


def _yaml_target(report: dict[str, Any], kernel_tree: Path | None,
                 vmlinux: Path | None) -> dict[str, Any]:
    operations = []
    for candidate in report["all_candidates"]:
        if (candidate.get("kind", "function") != "function"
                or candidate["role"] not in {"acquire", "release"}
                or candidate["confidence"] == "UNKNOWN"
                or not candidate["object_argument"] or candidate.get("ambiguous_data_flow")):
            continue
        op = {
            "function": candidate["function"],
            "role": candidate["role"],
            "object": candidate["object_argument"],
            "evidence_source": candidate["evidence_source"],
            "confidence": candidate["confidence"].lower(),
            "evidence": {
                "source_refcount_op": candidate.get("source_refcount_op", False),
                "name_heuristic": candidate.get("name_heuristic", False),
            },
            "comments": "; ".join(candidate["reasons"]),
        }
        if candidate.get("object_fields"):
            op["object_fields"] = candidate["object_fields"]
        if candidate["object_field"]:
            op["object_field"] = candidate["object_field"]
        operations.append(op)
    return {
        "schema_version": 1,
        "name": report["target_type"],
        "type": report["target_type"],
        "mode": report["mode"],
        "operations": operations,
        "transfers": [],
        "object_locations": report["object_locations"],
        "available_tracepoints": report["available_tracepoints"],
        "evidence": {
            "ref_tracker": report["ref_tracker_evidence"],
            "btf_kfunc": report["btf_kfunc_evidence"],
            "source_analysis": report["source_analysis"],
        },
        "metadata": {
            "inspector_version": INSPECTOR_VERSION,
            "kernel_tree": str(kernel_tree) if kernel_tree else None,
            "kernel_makefile_sha256": _sha256(kernel_tree / "Makefile") if kernel_tree and (kernel_tree / "Makefile").is_file() else None,
            "vmlinux": str(vmlinux) if vmlinux else None,
            "vmlinux_sha256": _sha256(vmlinux) if vmlinux else None,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "manual_review_required": True,
            "runtime_probes_auto_attached": False,
            "source_vmlinux_relation": report.get("source_vmlinux_relation"),
        },
        "comments": [
            "Generated suggestions only; review every operation and object location manually.",
            "Function names alone never establish acquire/release semantics or EXACT identity.",
            "Source-analysis candidates are inferred suggestions; runtime probes are never auto-attached.",
            "Edit this file manually; capture supports only object: arg0..arg4 and reason: arg0..arg4.",
            "Transfers are offline annotations; they do not prove ownership or auto-attach probes.",
        ],
        "warnings": report["warnings"],
    }


def render_text(report: dict[str, Any]) -> str:
    lines = [
        f"Target: {report['target_type']}",
        f"Mode: {report['mode']}",
        "",
        "Candidate acquire APIs:",
    ]
    for item in report["candidate_acquire_apis"]:
        lines.append(f"  {item['function']}({item['object_argument'] or 'object unknown'})  {item['confidence']} [{item['evidence_source']}]")
        lines.append(f"    reason: {'; '.join(item['reasons'])}")
    if not report["candidate_acquire_apis"]:
        lines.append("  none discovered")
    lines.extend(["", "Candidate release APIs:"])
    for item in report["candidate_release_apis"]:
        lines.append(f"  {item['function']}({item['object_argument'] or 'object unknown'})  {item['confidence']} [{item['evidence_source']}]")
        lines.append(f"    reason: {'; '.join(item['reasons'])}")
    if not report["candidate_release_apis"]:
        lines.append("  none discovered")
    lines.extend(["", "Object argument/field candidates:"])
    for item in report["object_locations"]:
        lines.append(f"  {item['function']}: {item['argument']}" +
                     (f".{item['field']}" if item["field"] else "") +
                     f" [{item['evidence_source']}, {item['confidence']}]")
    lines.extend(["", "Available tracepoints:"])
    lines.extend([f"  {item['system']}:{item['event']} ({item['availability']}; {item['evidence']})"
                  for item in report["available_tracepoints"]] or ["  none discovered"])
    lines.extend(["", "ref_tracker evidence:"])
    lines.extend([f"  {item['function']}: {', '.join(item['operations'])} [{item['confidence']}]"
                  for item in report["ref_tracker_evidence"]] or ["  none discovered"])
    lines.extend(["", "BTF/kfunc evidence:"])
    btf = report["btf_kfunc_evidence"]
    lines.append(f"  BTF available: {'yes' if btf['available'] else 'no'}; target type found: {'yes' if btf['type_found'] else 'no'}")
    lines.extend([f"  {item['function']}: {item['tag']}" for item in btf["kfuncs"]] or ["  no tagged kfunc semantics discovered"])
    lines.extend(["", "Warnings:"])
    lines.extend([f"  - {warning}" for warning in report["warnings"]] or ["  none"])
    return "\n".join(lines) + "\n"


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="refscope inspect-target")
    p.add_argument("--type", required=True, help="kernel object type, e.g. 'struct foo'")
    p.add_argument("--kernel-tree", type=Path)
    p.add_argument("--vmlinux", type=Path)
    p.add_argument("--write-target", type=Path)
    p.add_argument("--format", choices=("text", "json"), default="text")
    return p


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.kernel_tree and not args.kernel_tree.is_dir():
        print(f"refscope: kernel source tree not found: {args.kernel_tree}", file=sys.stderr)
        return 2
    if args.vmlinux and not args.vmlinux.is_file():
        print(f"refscope: vmlinux not found: {args.vmlinux}", file=sys.stderr)
        return 2
    try:
        report = analyze_target(args.type, args.kernel_tree, args.vmlinux)
        if args.write_target:
            if args.write_target.exists():
                print(f"refscope: refusing to overwrite target file: {args.write_target}", file=sys.stderr)
                return 2
            if yaml is None:
                print("refscope: PyYAML is required for --write-target", file=sys.stderr)
                return 2
            target = _yaml_target(report, args.kernel_tree, args.vmlinux)
            args.write_target.parent.mkdir(parents=True, exist_ok=True)
            args.write_target.write_text(
                yaml.safe_dump(target, sort_keys=False, allow_unicode=True),
                encoding="utf-8",
            )
            report["written_target"] = str(args.write_target)
    except (OSError, ValueError) as exc:
        print(f"refscope: target inspection failed: {exc}", file=sys.stderr)
        return 2
    if args.format == "json":
        json.dump(report, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        sys.stdout.write(render_text(report))
        if args.write_target:
            print(f"Generated editable target: {args.write_target}")
            print("Manual review is required before capture.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
