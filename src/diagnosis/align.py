"""Deterministic cohort construction and semantic-token sequence alignment."""
from __future__ import annotations

import hashlib
import json
from typing import Any

SCHEMA_VERSION = 1
ALGORITHM = "weighted-lcs-v1"
_FEATURE_WEIGHTS = {
    "operation_type": 64,
    "semantic_reason": 16,
    "normalized_stack": 8,
    "source_function": 4,
    "return_class": 2,
}
_GAP_COST = 24


class CohortMismatch(ValueError):
    """Lifetimes do not have the same cohort signature."""


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _reason_value(token: dict[str, Any]) -> Any:
    reason = token.get("reason") or {"state": "absent", "value": None}
    if reason.get("state") == "absent":
        return None
    return {"state": reason.get("state"), "value": reason.get("value")}


def _token_context(token: dict[str, Any]) -> dict[str, Any]:
    return {
        "op_type": token.get("op_type"),
        "function": token.get("normalized_function"),
        "reason": _reason_value(token),
        "return_class": token.get("return_class"),
    }


def _reasons(tokens: list[dict[str, Any]]) -> list[Any]:
    # Cohort identity uses the initial acquisition reason only. Reasons on later
    # operations remain sequence evidence; including them here would split a
    # cohort precisely when a later handoff/error-path reason diverges.
    anchor = next((token for token in tokens if token.get("op_type") == "GET"), None)
    if anchor is None:
        anchor = next((token for token in tokens if token.get("op_type") == "CREATE"), None)
    value = _reason_value(anchor) if anchor else None
    return [value] if value is not None else []


def cohort_signature(lifetime: dict[str, Any], run: dict[str, Any]) -> dict[str, Any]:
    tokens = lifetime.get("tokens", [])
    creation = next((t for t in tokens if t.get("op_type") == "CREATE"), None)
    acquisition = next((t for t in tokens if t.get("op_type") == "GET"), None)
    pivot = tokens.index(acquisition) if acquisition is not None else (
        tokens.index(creation) if creation is not None else 0
    )
    # Context is acquisition-side only; later behavior belongs in alignment.
    context = [_token_context(token) for token in tokens[max(0, pivot - 2):pivot + 1]]
    return {
        "target_type": lifetime.get("target_type") or run.get("target_type")
                       or lifetime.get("object_class") or run.get("object_class"),
        "initial_acquisition_stack": acquisition.get("normalized_stack") if acquisition else (
            creation.get("normalized_stack") if creation else (
                tokens[0].get("normalized_stack") if tokens else None
            )
        ),
        "creation_stack": creation.get("normalized_stack") if creation else None,
        "semantic_reason_set": _reasons(tokens),
        "generation": lifetime.get("generation"),
        "origin": lifetime.get("origin", "partial"),
        "approximate_context": context,
    }


def cohort_id(lifetime: dict[str, Any], run: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    signature = cohort_signature(lifetime, run)
    digest = hashlib.sha256(_canonical(signature).encode("utf-8")).hexdigest()[:24]
    return "cohort-" + digest, signature


def group_lifetimes(run: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for lifetime in run.get("lifetimes", []):
        identifier, signature = cohort_id(lifetime, run)
        item = dict(lifetime)
        item["cohort_id"] = identifier
        item["cohort_signature"] = signature
        groups.setdefault(identifier, []).append(item)
    for items in groups.values():
        items.sort(key=lambda item: (str(item.get("object", "")), item.get("generation", 0)))
    return groups


def _pair_components(left: dict[str, Any], right: dict[str, Any]) -> dict[str, int]:
    if left.get("op_type") != right.get("op_type"):
        return {}
    components = {"operation_type": _FEATURE_WEIGHTS["operation_type"]}
    fields = (
        ("semantic_reason", _reason_value(left), _reason_value(right)),
        ("normalized_stack", left.get("normalized_stack"), right.get("normalized_stack")),
        ("source_function", left.get("source_function", left.get("normalized_function")),
         right.get("source_function", right.get("normalized_function"))),
        ("return_class", left.get("return_class"), right.get("return_class")),
    )
    for name, a, b in fields:
        if a is not None and a == b:
            components[name] = _FEATURE_WEIGHTS[name]
    return components


def _meaningful_differences(left: dict[str, Any], right: dict[str, Any]) -> list[str]:
    fields = (
        ("operation_type", left.get("op_type"), right.get("op_type")),
        ("semantic_reason", _reason_value(left), _reason_value(right)),
        ("normalized_stack", left.get("normalized_stack"), right.get("normalized_stack")),
        ("source_function", left.get("source_function", left.get("normalized_function")),
         right.get("source_function", right.get("normalized_function"))),
        ("return_class", left.get("return_class"), right.get("return_class")),
    )
    return [name for name, a, b in fields if a != b]


def align_sequences(good_tokens: list[dict[str, Any]],
                    bad_tokens: list[dict[str, Any]]) -> dict[str, Any]:
    """Weighted LCS. Only equal operation types can pair; timestamps are ignored."""
    m, n = len(good_tokens), len(bad_tokens)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    choice = [[None] * (n + 1) for _ in range(m + 1)]
    for i in range(1, m + 1):
        dp[i][0] = dp[i - 1][0] - _GAP_COST
        choice[i][0] = "good_only"
    for j in range(1, n + 1):
        dp[0][j] = dp[0][j - 1] - _GAP_COST
        choice[0][j] = "bad_only"

    for i in range(1, m + 1):
        for j in range(1, n + 1):
            candidates = [
                (dp[i - 1][j] - _GAP_COST, 1, "good_only"),
                (dp[i][j - 1] - _GAP_COST, 0, "bad_only"),
            ]
            components = _pair_components(good_tokens[i - 1], bad_tokens[j - 1])
            if components:
                candidates.append((dp[i - 1][j - 1] + sum(components.values()),
                                   2, "matched"))
            score, _, selected = max(candidates, key=lambda item: (item[0], item[1]))
            dp[i][j], choice[i][j] = score, selected

    steps = []
    i, j = m, n
    while i or j:
        selected = choice[i][j]
        if selected == "matched":
            left, right = good_tokens[i - 1], bad_tokens[j - 1]
            components = _pair_components(left, right)
            steps.append({
                "kind": "matched",
                "good_index": i - 1,
                "bad_index": j - 1,
                "good_token": left,
                "bad_token": right,
                "components": components,
                "differences": _meaningful_differences(left, right),
            })
            i -= 1
            j -= 1
        elif selected == "good_only":
            steps.append({"kind": "good_only", "good_index": i - 1,
                          "bad_index": j, "good_token": good_tokens[i - 1]})
            i -= 1
        else:
            steps.append({"kind": "bad_only", "good_index": i,
                          "bad_index": j - 1, "bad_token": bad_tokens[j - 1]})
            j -= 1
    steps.reverse()

    divergence = None
    for position, step in enumerate(steps):
        if step["kind"] != "matched":
            divergence = {
                "kind": "unmatched-" + step["kind"].removesuffix("_only") + "-token",
                "alignment_step": position,
                "good_index": step["good_index"],
                "bad_index": step["bad_index"],
                "good_token": step.get("good_token"),
                "bad_token": step.get("bad_token"),
            }
            break
        if step["differences"]:
            divergence = {
                "kind": "semantic-token-mismatch",
                "alignment_step": position,
                "good_index": step["good_index"],
                "bad_index": step["bad_index"],
                "fields": step["differences"],
                "good_token": step["good_token"],
                "bad_token": step["bad_token"],
            }
            break

    good_only = [step for step in steps if step["kind"] == "good_only"]
    bad_only = [step for step in steps if step["kind"] == "bad_only"]
    matched = [step for step in steps if step["kind"] == "matched"]
    context = {"good": [], "bad": []}
    if divergence is not None:
        radius = 3
        gi, bi = divergence["good_index"], divergence["bad_index"]
        good_start, bad_start = max(0, gi - radius), max(0, bi - radius)
        good_end, bad_end = min(m, gi + radius + 1), min(n, bi + radius + 1)
        context = {
            "radius": radius,
            "good_start": good_start,
            "bad_start": bad_start,
            "good": good_tokens[good_start:good_end],
            "bad": bad_tokens[bad_start:bad_end],
        }
    return {
        "algorithm": ALGORITHM,
        "score_weights": dict(_FEATURE_WEIGHTS),
        "gap_cost": _GAP_COST,
        "steps": steps,
        "matched_tokens": matched,
        "good_only_tokens": good_only,
        "bad_only_tokens": bad_only,
        "earliest_meaningful_divergence": divergence,
        "context_window": context,
    }


def compare_lifetimes(good_run: dict[str, Any], bad_run: dict[str, Any],
                      good_lifetime: dict[str, Any],
                      bad_lifetime: dict[str, Any]) -> dict[str, Any]:
    good_id, good_sig = cohort_id(good_lifetime, good_run)
    bad_id, bad_sig = cohort_id(bad_lifetime, bad_run)
    if good_id != bad_id:
        raise CohortMismatch("lifetime cohort signatures differ")
    return {
        "cohort_id": good_id,
        "cohort_signature": good_sig,
        "good_run_id": good_run["run_id"],
        "bad_run_id": bad_run["run_id"],
        "good_lifetime": {"object": good_lifetime.get("object"),
                           "generation": good_lifetime.get("generation")},
        "bad_lifetime": {"object": bad_lifetime.get("object"),
                          "generation": bad_lifetime.get("generation")},
        "good_lifetime_evidence": {
            "exact_identity_proven": good_lifetime.get("exact_identity_proven") is True,
            "identity_key": good_lifetime.get("identity_key"),
            "actual_refcount": good_lifetime.get("actual_refcount"),
            "origin": good_lifetime.get("origin"),
            "suspicion_flags": good_lifetime.get("suspicion_flags", []),
        },
        "bad_lifetime_evidence": {
            "exact_identity_proven": bad_lifetime.get("exact_identity_proven") is True,
            "identity_key": bad_lifetime.get("identity_key"),
            "actual_refcount": bad_lifetime.get("actual_refcount"),
            "origin": bad_lifetime.get("origin"),
            "suspicion_flags": bad_lifetime.get("suspicion_flags", []),
        },
        "good_tokens": good_lifetime.get("tokens", []),
        "bad_tokens": bad_lifetime.get("tokens", []),
        **align_sequences(good_lifetime.get("tokens", []), bad_lifetime.get("tokens", [])),
    }


def compare_runs(good_run: dict[str, Any], bad_run: dict[str, Any]) -> dict[str, Any]:
    if good_run.get("label") != "good" or bad_run.get("label") != "bad":
        raise ValueError("compare_runs requires one good run and one bad run")
    good_groups, bad_groups = group_lifetimes(good_run), group_lifetimes(bad_run)
    comparisons = []
    for identifier in sorted(set(good_groups) | set(bad_groups)):
        good_items, bad_items = good_groups.get(identifier, []), bad_groups.get(identifier, [])
        signature = (good_items or bad_items)[0]["cohort_signature"]
        if len(good_items) > 1 or len(bad_items) > 1:
            comparisons.append({
                "status": "ambiguous-cohort-membership",
                "cohort_id": identifier,
                "cohort_signature": signature,
                "good_run_id": good_run["run_id"],
                "bad_run_id": bad_run["run_id"],
                "good_lifetimes": [{"object": x.get("object"), "generation": x.get("generation")} for x in good_items],
                "bad_lifetimes": [{"object": x.get("object"), "generation": x.get("generation")} for x in bad_items],
            })
        elif good_items and bad_items:
            comparisons.append({"status": "aligned", **compare_lifetimes(
                good_run, bad_run, good_items[0], bad_items[0])})
        else:
            present = good_items or bad_items
            side = "good" if good_items else "bad"
            item = present[0]
            divergence = {
                "kind": "lifetime-only-in-" + side,
                "good_index": 0 if good_items else 0,
                "bad_index": 0,
                "good_token": item["tokens"][0] if good_items and item["tokens"] else None,
                "bad_token": item["tokens"][0] if bad_items and item["tokens"] else None,
            }
            comparisons.append({
                "status": "lifetime-only-in-" + side,
                "cohort_id": identifier,
                "cohort_signature": signature,
                "good_run_id": good_run["run_id"],
                "bad_run_id": bad_run["run_id"],
                "good_only_tokens": item["tokens"] if good_items else [],
                "bad_only_tokens": item["tokens"] if bad_items else [],
                "earliest_meaningful_divergence": divergence,
                "context_window": {"good": item["tokens"][:7] if good_items else [],
                                    "bad": item["tokens"][:7] if bad_items else []},
            })
    return {
        "schema_version": SCHEMA_VERSION,
        "good_run_id": good_run["run_id"],
        "bad_run_id": bad_run["run_id"],
        "algorithm": ALGORITHM,
        "comparisons": comparisons,
    }
