"""Small, conservative C source index for target API suggestions."""
from __future__ import annotations

import os
from pathlib import Path
import re
from typing import Any

from .model import Confidence, EvidenceClaim, EvidenceSource, resolve_claims

_FUNC_RE = re.compile(
    r"(?m)^[ \t]*(?:(?:static|inline|__always_inline|noinline)\s+)*"
    r"[\w\s\*]+?\b([A-Za-z_]\w*)\s*\(([^;{}]*)\)\s*\{"
)
_CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
_NAME_ROLE = (
    (re.compile(r"(?:^|_)(?:get|acquire|hold|grab|lookup|tryget)(?:_|$)"), "acquire"),
    (re.compile(r"(?:^|_)(?:put|release|drop|unref|free)(?:_|$)"), "release"),
)


def _type_tag(type_name: str) -> str:
    return type_name.removeprefix("struct ").removeprefix("union ").strip()


def _split_args(text: str) -> list[str]:
    args, part, depth = [], [], 0
    for char in text:
        if char == "," and depth == 0:
            args.append("".join(part).strip())
            part = []
            continue
        part.append(char)
        if char in "([{" :
            depth += 1
        elif char in ")]}":
            depth = max(0, depth - 1)
    if part:
        args.append("".join(part).strip())
    return [] if args in ([""], ["void"]) else args


def _functions(text: str):
    for match in _FUNC_RE.finditer(text):
        depth, end = 1, match.end()
        while end < len(text) and depth:
            if text[end] == "{":
                depth += 1
            elif text[end] == "}":
                depth -= 1
            end += 1
        if depth == 0:
            yield match.group(1), _split_args(match.group(2)), text[match.end():end - 1], match.start()


def _role(primitive: str) -> str | None:
    if primitive.startswith(("refcount_inc", "kref_get", "percpu_ref_get")):
        return "acquire"
    if primitive.startswith(("refcount_dec", "kref_put", "percpu_ref_put")):
        return "release"
    if primitive in {"atomic_inc", "atomic_inc_not_zero", "percpu_ref_tryget_live",
                     "ref_tracker_alloc"}:
        return "acquire"
    if primitive in {"atomic_dec", "atomic_dec_and_test", "ref_tracker_free"}:
        return "release"
    return None


def _calls(body: str) -> list[tuple[str, list[str], str]]:
    result = []
    for match in _CALL_RE.finditer(body):
        name = match.group(1)
        if not (name.startswith(("refcount_inc", "refcount_dec", "kref_get", "kref_put",
                                 "percpu_ref_get", "percpu_ref_put", "atomic_inc",
                                 "atomic_dec", "ref_tracker_alloc", "ref_tracker_free"))):
            continue
        start = match.end()
        depth, end = 1, start
        while end < len(body) and depth:
            if body[end] == "(":
                depth += 1
            elif body[end] == ")":
                depth -= 1
            end += 1
        if depth:
            continue
        args = _split_args(body[start:end - 1])
        if args:
            result.append((name, args, _role(name) or "unknown"))
    return result


def _arg_names(params: list[str], type_name: str) -> list[tuple[int, str]]:
    result = []
    for index, param in enumerate(params):
        if type_name not in param:
            continue
        names = re.findall(r"[A-Za-z_]\w*", param)
        name = names[-1] if names else ""
        if name not in {"const", "volatile", "struct", "union"}:
            result.append((index, name))
    return result


def _fields(expr: str, names: list[str]) -> set[str]:
    result = set()
    for name in names:
        result.update(re.findall(r"\b" + re.escape(name) +
                                 r"\s*(?:->|\.)\s*([A-Za-z_]\w*)", expr))
    return result


def _name_role(name: str) -> str | None:
    for pattern, role in _NAME_ROLE:
        if pattern.search(name):
            return role
    return None


def _source_files(tree: Path) -> list[Path]:
    files = []
    for root, dirs, names in os.walk(tree):
        dirs[:] = sorted(d for d in dirs if d not in {".git", "build", "out"})
        files.extend(Path(root) / name for name in names if name.endswith((".c", ".h")))
    return sorted(files)


def _macro_records(path: Path, text: str, type_tag: str) -> list[dict[str, Any]]:
    # Join C line continuations while retaining the macro's starting line.
    logical, pending, start_line = [], "", 0
    for line_no, line in enumerate(text.splitlines(), 1):
        if not pending:
            start_line = line_no
        pending += line.rstrip().removesuffix("\\").rstrip() + " "
        if line.rstrip().endswith("\\"):
            continue
        logical.append((start_line, pending))
        pending = ""
    records = []
    for line_no, line in logical:
        match = re.match(r"\s*#\s*define\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s*(.*)", line)
        if not match:
            continue
        name, raw_params, body = match.groups()
        if not (name.startswith(type_tag + "_") or re.search(r"\bstruct\s+" +
                                                               re.escape(type_tag) + r"\b", body)):
            continue
        calls = _calls(body)
        roles = {role for _, _, role in calls}
        if not calls:
            continue
        role = next(iter(roles)) if len(roles) == 1 else "unknown"
        params = [item.strip() for item in raw_params.split(",") if item.strip()]
        fields = set()
        used = set()
        for _, args, call_role in calls:
            if call_role == role and args:
                fields.update(_fields(args[0], params))
                for index, param in enumerate(params):
                    if re.search(r"\b" + re.escape(param) + r"\b", args[0]):
                        used.add(index)
        obj = f"arg{next(iter(used))}" if len(used) == 1 else None
        records.append({
            "function": name, "kind": "macro", "role": role,
            "object_argument": obj, "object_arguments": [f"arg{i}" for i in sorted(used)],
            "object_field": next(iter(fields)) if len(fields) == 1 else None,
            "object_fields": sorted(fields), "ambiguous_data_flow": role == "unknown" or
                len(used) != 1 or len(fields) > 1,
            "source_refcount_op": True, "name_heuristic": _name_role(name) is not None,
            "evidence_source": EvidenceSource.SOURCE_ANALYSIS.value,
            "confidence": Confidence.INFERRED.value,
            "reasons": ["macro body contains " + ", ".join(sorted(n for n, _, _ in calls))],
            "source_location": {"file": str(path), "line": line_no},
            "warnings": ["macro is a source candidate, not an attachable runtime function"],
        })
    return records


def index_source_tree(type_name: str, tree: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]], bool]:
    """Return reviewed-style candidates; no result is treated as ground truth."""
    files = _source_files(tree)
    if not files:
        return [], [], False
    type_tag = _type_tag(type_name)
    functions = []
    contents = {}
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        contents[path] = text
        for name, params, body, offset in _functions(text):
            functions.append({"name": name, "params": params, "body": body,
                              "path": path, "text": text, "offset": offset,
                              "calls": _calls(body)})
    by_name: dict[str, list[dict[str, Any]]] = {}
    for function in functions:
        by_name.setdefault(function["name"], []).append(function)

    candidates: list[dict[str, Any]] = []
    tracker: list[dict[str, Any]] = []
    for function in functions:
        name, params, body, calls = (function[k] for k in ("name", "params", "body", "calls"))
        typed_args = _arg_names(params, type_name)
        if not typed_args and not (name.startswith(type_tag + "_") or name == type_tag):
            continue
        indirect = []
        # One-hop helper propagation only when its typed object parameter is
        # passed as a bare caller parameter; all other flows remain ambiguous.
        for call in _CALL_RE.finditer(body):
            helper_name = call.group(1)
            if helper_name not in by_name or helper_name == name:
                continue
            depth, end = 1, call.end()
            while end < len(body) and depth:
                if body[end] == "(":
                    depth += 1
                elif body[end] == ")":
                    depth -= 1
                end += 1
            if depth:
                continue
            call_args = _split_args(body[call.end():end - 1])
            for helper in by_name[helper_name]:
                helper_typed = _arg_names(helper["params"], type_name)
                if len(helper_typed) != 1 or not helper["calls"]:
                    continue
                helper_index, _ = helper_typed[0]
                if helper_index >= len(call_args):
                    continue
                passed = call_args[helper_index].strip()
                caller_names = {param_name: index for index, param_name in typed_args}
                bare = re.fullmatch(r"&?\s*([A-Za-z_]\w*)\s*", passed)
                mapped_index = caller_names.get(bare.group(1)) if bare else None
                if mapped_index is None:
                    continue
                indirect.extend((primitive, args, role, mapped_index, helper)
                                for primitive, args, role in helper["calls"])
        operations = [(primitive, args, role, None) for primitive, args, role in calls]
        operations.extend((primitive, args, role, mapped) for primitive, args, role, mapped, _ in indirect)
        role_set = {role for _, _, role, _ in operations}
        heuristic = _name_role(name)
        source_role = next(iter(role_set)) if len(role_set) == 1 else None
        calls_for_role = [entry for entry in operations if entry[2] == source_role] if source_role else []
        fields, used_args, primitives = set(), set(), set()
        for primitive, args, _, mapped_index in calls_for_role:
            primitives.add(primitive)
            if mapped_index is not None:
                used_args.add(mapped_index)
                helper = next((h for _, _, _, mapped, h in indirect if mapped == mapped_index
                               and any(c[0] == primitive for c in h["calls"])), None)
                if helper:
                    helper_names = [n for _, call_args, r in helper["calls"] if r == source_role
                                    for n in _fields(call_args[0], [helper_name for _, helper_name in
                                        _arg_names(helper["params"], type_name)])]
                    fields.update(helper_names)
            elif args:
                for index, param_name in typed_args:
                    if re.search(r"\b" + re.escape(param_name) + r"\b", args[0]):
                        used_args.add(index)
                        fields.update(_fields(args[0], [param_name]))
        ambiguous_role = len(role_set) > 1
        object_args = (sorted(used_args) if used_args else
                       [i for i, _ in typed_args] if not operations else [])
        object_arg = f"arg{object_args[0]}" if len(object_args) == 1 else None
        claims = []
        tracker_roles = {role for primitive, _, role, _ in operations
                         if primitive.startswith("ref_tracker_")}
        tracker_role = next(iter(tracker_roles)) if len(tracker_roles) == 1 else None
        if source_role:
            claims.append(EvidenceClaim(source_role, EvidenceSource.SOURCE_ANALYSIS,
                                        Confidence.STRONG))
        if tracker_role:
            claims.append(EvidenceClaim(tracker_role, EvidenceSource.REF_TRACKER,
                                        Confidence.STRONG))
        if heuristic:
            claims.append(EvidenceClaim(heuristic, EvidenceSource.NAME_HEURISTIC,
                                        Confidence.INFERRED))
        resolution = resolve_claims(claims)
        role = resolution.value if resolution.value in {"acquire", "release"} else "unknown"
        if ambiguous_role:
            role = heuristic or "unknown"
        source = (EvidenceSource.REF_TRACKER if tracker_role == role else
                  EvidenceSource.SOURCE_ANALYSIS if calls_for_role else
                  EvidenceSource.NAME_HEURISTIC if heuristic else EvidenceSource.SOURCE_ANALYSIS)
        line = function["text"].count("\n", 0, function["offset"]) + 1
        warnings = []
        if ambiguous_role:
            warnings.append("AMBIGUOUS_OPERATION_ROLE: body contains acquire and release operations")
        if len(object_args) != 1:
            warnings.append("AMBIGUOUS_OBJECT_ARGUMENT: object data flow is not unique")
        if len(fields) > 1:
            warnings.append("AMBIGUOUS_OBJECT_FIELD: multiple fields are modified")
        if resolution.conflicting_sources:
            warnings.append("role claims conflict: " + ", ".join(s.value for s in resolution.conflicting_sources))
        if indirect:
            warnings.append("helper semantics propagated one level; review argument data flow")
        candidate = {
            "function": name, "kind": "function", "role": role,
            "object_argument": object_arg, "object_arguments": [f"arg{i}" for i in object_args],
            "object_field": next(iter(fields)) if len(fields) == 1 else None,
            "object_fields": sorted(fields), "ambiguous_data_flow":
                ambiguous_role or len(object_args) != 1 or len(fields) > 1,
            "source_refcount_op": bool(calls or indirect),
            "name_heuristic": heuristic is not None,
            "evidence_source": source.value,
            "confidence": resolution.confidence.value if claims else Confidence.UNKNOWN.value,
            "reasons": (["source body calls " + ", ".join(sorted(primitives))] if calls_for_role else
                        ["candidate found by name only"]),
            "source_location": {"file": str(function["path"]), "line": line},
            "warnings": warnings,
        }
        candidates.append(candidate)
        tracker_calls = [primitive for primitive, _, _ in calls if primitive.startswith("ref_tracker_")]
        if tracker_calls:
            tracker.append({"function": name, "operations": tracker_calls,
                            "source_location": candidate["source_location"],
                            "confidence": "STRONG",
                            "warning": "source usage found; runtime token identity is not established by inspection"})

    for path, text in contents.items():
        candidates.extend(_macro_records(path, text, type_tag))

    definitions: dict[str, list[dict[str, Any]]] = {}
    for candidate in candidates:
        if candidate.get("kind") == "function":
            definitions.setdefault(candidate["function"], []).append(candidate)
    for function_name, variants in definitions.items():
        locations = {item["source_location"]["file"] for item in variants}
        if len(locations) > 1:
            for item in variants:
                item["role"] = "unknown"
                item["confidence"] = Confidence.UNKNOWN.value
                item["object_argument"] = None
                item["ambiguous_data_flow"] = True
                item["warnings"].append(
                    "AMBIGUOUS_DUPLICATE_FUNCTION_DEFINITION: source tree has multiple definitions"
                )
    return candidates, tracker, True
