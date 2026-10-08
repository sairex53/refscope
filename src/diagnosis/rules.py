"""Transparent, deterministic candidate rules for offline good/bad runs."""
from __future__ import annotations

import hashlib
import json
from typing import Any

from diagnosis.align import compare_runs

_TRANSFER_WORDS = ("async", "handoff", "transfer", "queue", "defer")
_USE_OPS = {"GET", "CALL_RETURN"}
_CHANGE_OPS = {"GET", "PUT"}


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _token_reason(token: dict[str, Any]) -> str:
    reason = token.get("reason") or {}
    value = reason.get("value") if isinstance(reason, dict) else reason
    return str(value or "").casefold()


def _is_transfer(token: dict[str, Any]) -> bool:
    return any(word in _token_reason(token) for word in _TRANSFER_WORDS)


def _ops(tokens: list[dict[str, Any]], op: str) -> list[int]:
    return [i for i, token in enumerate(tokens) if token.get("op_type") == op]


def _warning_set(comparison: dict[str, Any]) -> set[str]:
    warnings: set[str] = set()
    for side in ("good", "bad"):
        quality = comparison.get(side + "_capture_quality") or {}
        warnings.update(str(item) for item in quality.get("warnings", []))
        if quality.get("capture_incomplete") is True:
            warnings.add("capture_marked_incomplete")
        if isinstance(quality.get("dropped"), int) and quality["dropped"] > 0:
            warnings.add("events_dropped")
    return warnings


def _make_proposal(rule: str, comparison: dict[str, Any], evidence: dict[str, Any],
                   reason: str) -> dict[str, Any]:
    divergence = comparison.get("earliest_meaningful_divergence")
    return {
        "rule": rule,
        "reason": reason,
        "cohort_id": comparison["cohort_id"],
        "good_run_id": comparison["good_run_id"],
        "bad_run_id": comparison["bad_run_id"],
        "good_lifetime": comparison.get("good_lifetime_evidence", {}),
        "bad_lifetime": comparison.get("bad_lifetime_evidence", {}),
        "cohort_signature": comparison.get("cohort_signature", {}),
        "divergence_window": comparison.get("context_window", {"good": [], "bad": []}),
        "divergence": divergence,
        "evidence": evidence,
        "warnings": sorted(_warning_set(comparison)),
        "capture_quality": {
            "good": comparison.get("good_capture_quality", {}),
            "bad": comparison.get("bad_capture_quality", {}),
        },
    }


def _rule_proposals(comparison: dict[str, Any]) -> list[dict[str, Any]]:
    if comparison.get("status") != "aligned":
        return []
    good = comparison.get("good_tokens", [])
    bad = comparison.get("bad_tokens", [])
    steps = comparison.get("steps", [])
    proposals: list[dict[str, Any]] = []

    # Rule 1: an acquisition is visible on both sides; good releases it,
    # while bad reaches lifetime end without a later PUT.
    for gi in _ops(good, "GET"):
        good_puts = [i for i in _ops(good, "PUT") if i > gi]
        if not good_puts:
            continue
        matched_get = next((step for step in steps if step.get("kind") == "matched"
                            and step.get("good_index") == gi
                            and step.get("good_token", {}).get("op_type") == "GET"), None)
        if not matched_get:
            continue
        bi = matched_get["bad_index"]
        if not any(i > bi for i in _ops(bad, "PUT")):
            proposals.append(_make_proposal(
                "unmatched_acquisition", comparison,
                {"good_get_index": gi, "good_put_index": good_puts[0],
                 "bad_get_index": bi, "bad_lifetime_has_later_put": False},
                "good releases an observed acquisition; bad lifetime ends without release"))
            break

    # Rule 2: a release has no counterpart in good.
    for step in steps:
        if step.get("kind") == "bad_only" and step.get("bad_token", {}).get("op_type") == "PUT":
            proposals.append(_make_proposal(
                "extra_release", comparison,
                {"bad_put_index": step["bad_index"], "good_counterpart": False},
                "bad contains an additional PUT absent from the aligned good sequence"))
            break

    # Rule 3: bad frees before a subsequent use that remains within the good lifetime,
    # or itself observes a use after FREE.
    bad_frees = _ops(bad, "FREE")
    for bi in bad_frees:
        post_free_use = next((i for i in _ops(bad, "GET") if i > bi), None)
        if post_free_use is not None:
            proposals.append(_make_proposal(
                "early_final_release", comparison,
                {"bad_free_index": bi, "bad_subsequent_use_index": post_free_use,
                 "evidence_kind": "use-after-free-event-order"},
                "bad FREE precedes a later observed use"))
            break
        free_step = next((step for step in steps if step.get("kind") == "matched"
                          and step.get("bad_index") == bi
                          and step.get("bad_token", {}).get("op_type") == "FREE"), None)
        if free_step:
            gi = free_step["good_index"]
            free_position = steps.index(free_step)
            unmatched_good_use = next((step for step in steps[:free_position]
                                       if step.get("kind") == "good_only"
                                       and step.get("good_token", {}).get("op_type") in _USE_OPS
                                       and step.get("good_index", 0) < gi
                                       and any(prior.get("kind") == "matched"
                                               and prior.get("good_token", {}).get("op_type") == "GET"
                                               and prior.get("bad_token", {}).get("op_type") == "GET"
                                               and prior.get("good_index", 0) < step.get("good_index", 0)
                                               and prior.get("bad_index", 0) < bi
                                               for prior in steps[:free_position])), None)
            if unmatched_good_use:
                use_i = unmatched_good_use["good_index"]
                proposals.append(_make_proposal(
                    "early_final_release", comparison,
                    {"bad_free_index": bi, "good_free_index": gi,
                     "good_subsequent_use_index": use_i,
                     "evidence_kind": "good-use-before-good-free-missing-before-bad-free"},
                    "bad reaches FREE before a later use observed in the still-live good lifetime"))
                break
            later_use = next((i for i in range(gi + 1, len(good))
                              if good[i].get("op_type") in _USE_OPS), None)
            later_good_free = next((i for i in _ops(good, "FREE") if i > (later_use or gi)), None)
            if later_use is not None and later_good_free is not None:
                proposals.append(_make_proposal(
                    "early_final_release", comparison,
                    {"bad_free_index": bi, "good_free_index": gi,
                     "good_subsequent_use_index": later_use,
                     "evidence_kind": "good-use-after-bad-free"},
                    "bad reaches FREE before a use observed while good remains live"))
                break

    # Rule 4: explicit semantic transfer marker in good is followed by a receiving
    # GET; the bad side has no corresponding receiving-side GET.
    transfer_positions = [i for i, token in enumerate(good) if _is_transfer(token)]
    for transfer_i in transfer_positions:
        receive_i = next((i for i in _ops(good, "GET")
                          if i > transfer_i and _is_transfer(good[i])), None)
        if receive_i is None:
            continue
        transfer_reason = _token_reason(good[transfer_i])
        bad_has_receive = any(token.get("op_type") == "GET" and _is_transfer(token)
                              and _token_reason(token) == _token_reason(good[receive_i])
                              for token in bad)
        if not bad_has_receive:
            proposals.append(_make_proposal(
                "ownership_transfer_divergence", comparison,
                {"good_transfer_index": transfer_i, "good_receive_get_index": receive_i,
                 "transfer_reason": transfer_reason, "bad_receive_get_missing": True},
                "good observes asynchronous handoff and receiving GET; bad lacks receiving GET"))
            break

    # Rule 5: a negative return precedes an operation mismatch affecting GET/PUT balance.
    divergence = comparison.get("earliest_meaningful_divergence") or {}
    affected_boundaries = []
    for step in steps:
        if step.get("kind") == "good_only" and step.get("good_token", {}).get("op_type") in _CHANGE_OPS:
            affected_boundaries.extend((("good", step.get("good_index", 0)),
                                        ("bad", step.get("bad_index", 0))))
        if step.get("kind") == "bad_only" and step.get("bad_token", {}).get("op_type") in _CHANGE_OPS:
            affected_boundaries.extend((("good", step.get("good_index", 0)),
                                        ("bad", step.get("bad_index", 0))))
    for side, seq in (("good", good), ("bad", bad)):
        error_i = next((i for i, token in enumerate(seq)
                        if token.get("op_type") == "CALL_RETURN"
                        and token.get("return_class") == "error"), None)
        if error_i is None:
            continue
        paired_return = next((step for step in steps
                              if step.get("kind") == "matched"
                              and step.get(f"{side}_index") == error_i
                              and step.get(f"{side}_token", {}).get("op_type") == "CALL_RETURN"), None)
        if paired_return:
            other_side = "bad" if side == "good" else "good"
            if paired_return.get(f"{other_side}_token", {}).get("return_class") == "error":
                # A shared negative return is not differential error-path evidence.
                continue
        side_change = next((index for which, index in affected_boundaries
                            if which == side and index > error_i), None)
        if side_change is None:
            continue
        proposals.append(_make_proposal(
            "error_path_divergence", comparison,
            {"side": side, "error_return_index": error_i,
             "balance_change_index": side_change,
             "return_class": "error"},
            "negative return precedes an unmatched GET/PUT balance change"))
        break
    return proposals


def _identity_is_exact(proposal: dict[str, Any]) -> bool:
    good = proposal.get("good_lifetime", {})
    bad = proposal.get("bad_lifetime", {})
    key = good.get("identity_key")
    return bool(key) and key == bad.get("identity_key") \
        and good.get("exact_identity_proven") is True \
        and bad.get("exact_identity_proven") is True


def _source_locations(proposal: dict[str, Any]) -> list[dict[str, Any]]:
    locations = {}
    for side in ("good", "bad"):
        for token in proposal["divergence_window"].get(side, []):
            for location in token.get("source_locations", []):
                if isinstance(location, dict) and location.get("file") and location.get("line") is not None:
                    locations[_canonical(location)] = location
    return [locations[key] for key in sorted(locations)]


def _actual_refcount_confirms(proposal: dict[str, Any]) -> bool:
    good = proposal.get("good_lifetime", {}).get("actual_refcount")
    bad = proposal.get("bad_lifetime", {}).get("actual_refcount")
    return (isinstance(good, int) and not isinstance(good, bool)
            and isinstance(bad, int) and not isinstance(bad, bool)
            and bad > 0 and bad != good)


def _stable_stack(proposal: dict[str, Any]) -> bool:
    return bool(proposal.get("cohort_signature", {}).get("initial_acquisition_stack"))


def generate_candidates(good_runs: list[dict[str, Any]],
                        bad_runs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Apply explicit rules to aligned cohort pairs; aggregate deterministically."""
    proposals = []
    cohort_good_presence: dict[str, set[str]] = {}
    cohort_bad_presence: dict[str, set[str]] = {}
    from diagnosis.align import cohort_id
    for run, presence in [(item, cohort_good_presence) for item in good_runs] + [
            (item, cohort_bad_presence) for item in bad_runs]:
        for life in run.get("lifetimes", []):
            identifier, _ = cohort_id(life, run)
            presence.setdefault(identifier, set()).add(run["run_id"])

    for good_run in sorted(good_runs, key=lambda item: item["run_id"]):
        for bad_run in sorted(bad_runs, key=lambda item: item["run_id"]):
            comparison = compare_runs(good_run, bad_run)
            good_quality = good_run.get("capture_quality", {})
            bad_quality = bad_run.get("capture_quality", {})
            for item in comparison["comparisons"]:
                if item.get("status") != "aligned":
                    continue
                item["good_capture_quality"] = good_quality
                item["bad_capture_quality"] = bad_quality
                proposals.extend(_rule_proposals(item))

    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for proposal in proposals:
        grouped.setdefault((proposal["rule"], proposal["cohort_id"]), []).append(proposal)

    # Equivalent candidates across distinct cohorts are explicitly penalized.
    descriptor_counts: dict[tuple[str, str], set[str]] = {}
    for (rule, cohort), group in grouped.items():
        descriptor = group[0]["reason"]
        descriptor_counts.setdefault((rule, descriptor), set()).add(cohort)

    candidates = []
    for (rule, cohort), group in sorted(grouped.items()):
        first = sorted(group, key=lambda item: (item["good_run_id"], item["bad_run_id"]))[0]
        good_ids = sorted({item["good_run_id"] for item in group})
        bad_ids = sorted({item["bad_run_id"] for item in group})
        denominator = len(cohort_good_presence.get(cohort, set()))
        recurrence = len(good_ids) / denominator if denominator else 0.0
        bad_denominator = len(cohort_bad_presence.get(cohort, set()))
        bad_recurrence = len(bad_ids) / bad_denominator if bad_denominator else 0.0
        warnings = sorted({warning for item in group for warning in item["warnings"]})
        if any(item["bad_lifetime"].get("origin") != "explicit"
               or "ADDRESS_REUSE_AMBIGUOUS" in item["bad_lifetime"].get("suspicion_flags", [])
               for item in group):
            warnings.append("generation_identity_uncertain")
            warnings = sorted(set(warnings))
        components = {
            "unique_operation_mismatch": 3 if len(descriptor_counts.get((rule, first["reason"]), set())) == 1 else 0,
            "good_pattern_present_over_80_percent": 3 if recurrence > 0.8 else 0,
            "stable_acquisition_stack": 2 if _stable_stack(first) else 0,
            "adjacent_error_return": 2 if any(item["evidence"].get("return_class") == "error"
                                              for item in group) else 0,
            "actual_refcount_confirms_imbalance": 2 if any(_actual_refcount_confirms(item) for item in group) else 0,
            "matching_semantic_reason": 2 if first["cohort_signature"].get("semantic_reason_set") else 0,
            "dropped_events": -2 if "events_dropped" in warnings or any(
                "loss_accounting_unknown" in item["warnings"] for item in group) else 0,
            "uncertain_generation": -2 if any(
                item["bad_lifetime"].get("origin") != "explicit"
                or "ADDRESS_REUSE_AMBIGUOUS" in item["bad_lifetime"].get("suspicion_flags", [])
                for item in group) else 0,
            "multiple_equivalent_candidates": -3 if len(
                descriptor_counts.get((rule, first["reason"]), set())) > 1 else 0,
        }
        score = sum(components.values())
        exact = all(_identity_is_exact(item) for item in group)
        if exact and not warnings:
            confidence = "EXACT"
        elif len(good_ids) >= 2 and recurrence > 0.8 and score >= 8 and not warnings:
            confidence = "STRONG"
        else:
            confidence = "INFERRED"
        divergence_window = first["divergence_window"]
        candidate_identity = _canonical({
            "rule": rule, "cohort_id": cohort, "reason": first["reason"],
        })
        candidate_id = "candidate-" + hashlib.sha256(candidate_identity.encode()).hexdigest()[:24]
        candidates.append({
            "candidate_id": candidate_id,
            "rule": rule,
            "description": first["reason"],
            "score": score,
            "score_components": components,
            "confidence": confidence,
            "run_ids": {"good": good_ids, "bad": bad_ids},
            "cohort_ids": [cohort],
            "divergence_window": divergence_window,
            "source_locations": _source_locations(first),
            "warnings": warnings,
            "evidence": [item["evidence"] for item in group],
            "good_pattern_recurrence": {"present": len(good_ids), "eligible": denominator,
                                        "ratio": recurrence},
            "bad_pattern_recurrence": {"present": len(bad_ids), "eligible": bad_denominator,
                                       "ratio": bad_recurrence},
            "capture_quality": {
                "good": {item["good_run_id"]: item["capture_quality"]["good"] for item in group},
                "bad": {item["bad_run_id"]: item["capture_quality"]["bad"] for item in group},
            },
            "target_type": first["cohort_signature"].get("target_type"),
            "root_cause_proven": False,
            "actual_refcount_available": any(
                item["bad_lifetime"].get("actual_refcount") is not None for item in group),
        })
    return sorted(candidates, key=lambda item: (-item["score"], item["candidate_id"]))
