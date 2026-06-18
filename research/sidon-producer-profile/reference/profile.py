#!/usr/bin/env python3
"""Normative reference operations for the Vela Sidon Producer Profile v1."""
from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from canonical import content_id, digest, sha256_bytes
from kernel import (
    Presentation,
    active_environments,
    active_view_root,
    compile_gamma,
    evaluator_digest,
    is_hitting_set,
    lineage_root,
    minimal_environments,
    repair_completes_environment,
)
from packets import signed_packet
from sidon import (
    RULE_ATOM,
    append_verified_route,
    best_bounds,
    bound_cell,
    claim,
    register_bound_metadata,
    validate_shape,
    verify_base3_sort,
    verify_pairsum_set,
)

FRONTIER_ID = "vfr_496956067dc5ad79"
EVALUATOR_ID = "vela.sidon.best-lower-bound.v1"
VIEW_POLICY_ID = "vela.view.public.v1"
PROFILE_ID = "vela.sidon-producer-profile.v1"
ROOT = Path(__file__).resolve().parents[1]


def fixture_time(step: int) -> str:
    return f"2026-06-18T14:{step:02d}:00+00:00"


def state_commitment(observation: dict[str, Any]) -> dict[str, Any]:
    return {
        "observation_id": observation["packet_id"],
        "presentation_root": observation["presentation_root"],
        "circuit_root": observation["circuit_root"],
        "lineage_root": observation["lineage_root"],
        "active_view_root": observation["active_view_root"],
        "evaluator_id": observation["evaluator_id"],
        "evaluator_inputs_digest": digest(observation["evaluator_inputs"]),
        "canonical_output_digest": digest(observation["canonical_output"]),
    }


def current_bound(observation: dict[str, Any], n: int) -> int:
    for row in observation["canonical_output"]["bounds"]:
        if row["n"] == n:
            return int(row["best_lower_bound"])
    raise ValueError(f"observation has no bound for n={n}")


def make_task(
    observation: dict[str, Any],
    *,
    n: int,
    objective_kind: str,
    key: Ed25519PrivateKey,
    actor: str,
    step: int,
) -> dict[str, Any]:
    current = current_bound(observation, n)
    objective = {
        "kind": objective_kind,
        "current": current,
        "required_minimum": current + 1 if objective_kind == "strict_improvement" else current,
    }
    fields = {
        "frontier_id": observation["frontier_id"],
        "base_state": state_commitment(observation),
        "task_id": content_id("vtsk_", {
            "frontier_id": observation["frontier_id"],
            "base_observation_id": observation["packet_id"],
            "n": n,
            "objective": objective,
        }),
        "cell_target": {"sequence": "oeis:A309370", "n": n},
        "objective": objective,
        "verifier_contract": "vela.sidon.gate.v1",
        "required_result_schema": "vela.sidon-witness.v1",
        "lease": {"state_effect": "none", "required": False},
        "created_at": fixture_time(step),
    }
    return signed_packet("task", fields, key, actor)


def make_result(
    task: dict[str, Any],
    witness: dict[str, Any],
    *,
    key: Ed25519PrivateKey,
    actor: str,
    step: int,
) -> dict[str, Any]:
    n, points = validate_shape(witness)
    if n != task["cell_target"]["n"]:
        raise ValueError("witness dimension does not match task")
    k = len(points)
    claim_obj = claim(n, k)
    fields = {
        "frontier_id": task["frontier_id"],
        "task_id": task["task_id"],
        "base_state": task["base_state"],
        "producer_actor": actor,
        "claim": claim_obj,
        "claim_digest": digest(claim_obj),
        "artifact": witness,
        "artifact_digest": digest(witness),
        "certificate_kind": "sidon-witness-v1",
        "created_at": fixture_time(step),
    }
    return signed_packet("result", fields, key, actor)


def _run_verifier(script: Path, witness: dict[str, Any]) -> dict[str, Any]:
    # The reference fixture executes the two algorithms in-process so the full
    # conformance suite stays fast. `conformance/check_verifier_executables.py`
    # separately proves that the two packaged executables accept the same input
    # contract and return the same decisions.
    if script.name == "sidon_pairsum_set.py":
        passed, detail = verify_pairsum_set(witness)
        method_family = "pair-sum-hash-set"
    elif script.name == "sidon_base3_sort.py":
        passed, detail = verify_base3_sort(witness)
        method_family = "base3-encode-sort"
    else:
        raise RuntimeError(f"unknown verifier executable: {script}")
    return {
        "method_family": method_family,
        "passed": passed,
        "detail": detail,
        "executable_digest": "sha256:" + sha256_bytes(script.read_bytes()),
        "executable_id": f"python:{script.name}",
    }


def _single_bit_collision_mutation(witness: dict[str, Any]) -> dict[str, Any] | None:
    n, points = validate_shape(witness)
    originals = set(points)
    for i, point in enumerate(points):
        for bit in range(n):
            candidate = list(point)
            candidate[bit] = 1 - candidate[bit]
            cand_t = tuple(candidate)
            if cand_t in originals - {point}:
                continue
            mutated = copy.deepcopy(witness)
            mutated["points"][i] = candidate
            ok_a, _ = verify_pairsum_set(mutated)
            ok_b, _ = verify_base3_sort(mutated)
            if not ok_a and not ok_b:
                return mutated
    return None


def _probe_suite(result: dict[str, Any], verifier_scripts: list[Path]) -> list[dict[str, Any]]:
    witness = result["artifact"]
    probes: list[tuple[str, dict[str, Any]]] = []

    duplicate = copy.deepcopy(witness)
    duplicate["points"].append(copy.deepcopy(duplicate["points"][0]))
    duplicate["claimed_size"] += 1
    probes.append(("duplicate-point-v1", duplicate))

    wrong_size = copy.deepcopy(witness)
    wrong_size["claimed_size"] += 1
    probes.append(("claimed-size-mismatch-v1", wrong_size))

    semantic = _single_bit_collision_mutation(witness)
    if semantic is not None:
        probes.append(("single-bit-pairsum-collision-v1", semantic))

    out: list[dict[str, Any]] = []
    for mutation_id, mutated in probes:
        verifier_results = []
        for script in verifier_scripts:
            response = _run_verifier(script, mutated)
            verifier_results.append({
                "method_family": response["method_family"],
                "executable_digest": response["executable_digest"],
                "accepted_mutation": response["passed"],
                "detail": response["detail"],
            })
        body = {
            "mutation_id": mutation_id,
            "original_artifact_digest": result["artifact_digest"],
            "mutated_artifact_digest": digest(mutated),
            "verifier_results": verifier_results,
            "passed": all(not row["accepted_mutation"] for row in verifier_results),
        }
        out.append({"probe_id": content_id("vprobe_", body), **body})
    return out


def make_gate_receipt(
    result: dict[str, Any],
    *,
    key: Ed25519PrivateKey,
    actor: str,
    step: int,
) -> dict[str, Any]:
    scripts = [
        ROOT / "verifiers" / "sidon_pairsum_set.py",
        ROOT / "verifiers" / "sidon_base3_sort.py",
    ]
    attachments = []
    for script in scripts:
        response = _run_verifier(script, result["artifact"])
        body = {
            "result_packet_id": result["packet_id"],
            "method_family": response["method_family"],
            "executable_id": response["executable_id"],
            "executable_digest": response["executable_digest"],
            "claim_digest": result["claim_digest"],
            "artifact_digest": result["artifact_digest"],
            "passed": response["passed"],
            "detail": response["detail"],
        }
        attachments.append({"receipt_id": content_id("vva_", body), **body})

    diversity = {
        "distinct_method_families": len({a["method_family"] for a in attachments}) >= 2,
        "distinct_executable_digests": len({a["executable_digest"] for a in attachments}) >= 2,
        "interpretation": "algorithmic diversity; not a claim of statistical or organizational independence",
    }
    claim_match = {
        "claim_digest_matches": all(a["claim_digest"] == result["claim_digest"] for a in attachments),
        "artifact_digest_matches": all(a["artifact_digest"] == result["artifact_digest"] for a in attachments),
    }
    probes = _probe_suite(result, scripts)
    semantic_probe_present = any(p["mutation_id"] == "single-bit-pairsum-collision-v1" for p in probes)
    verified = (
        all(a["passed"] for a in attachments)
        and diversity["distinct_method_families"]
        and diversity["distinct_executable_digests"]
        and all(claim_match.values())
        and semantic_probe_present
        and all(p["passed"] for p in probes)
    )
    fields = {
        "frontier_id": result["frontier_id"],
        "result_packet_id": result["packet_id"],
        "base_state": result["base_state"],
        "claim_digest": result["claim_digest"],
        "artifact_digest": result["artifact_digest"],
        "attachments": attachments,
        "verification_diversity": diversity,
        "claim_match_check": claim_match,
        "adversarial_probes": probes,
        "gate_status": "verified" if verified else "needs_verification",
        "created_at": fixture_time(step),
    }
    return signed_packet("gate_receipt", fields, key, actor)


def make_acceptance(
    result: dict[str, Any],
    gate: dict[str, Any],
    current_observation: dict[str, Any],
    *,
    key: Ed25519PrivateKey,
    actor: str,
    step: int,
    allow_confirmation: bool,
) -> dict[str, Any]:
    if gate["gate_status"] != "verified":
        raise ValueError("cannot accept an unverified result")
    if gate["result_packet_id"] != result["packet_id"]:
        raise ValueError("gate/result mismatch")
    n = int(result["claim"]["n"])
    k = int(result["claim"]["value"])
    current = current_bound(current_observation, n)
    fresh = result["base_state"]["observation_id"] == current_observation["packet_id"]
    if fresh:
        resolution = "fresh"
    elif k > current:
        resolution = "stale_revalidated_as_improvement"
    elif k == current and allow_confirmation:
        resolution = "stale_revalidated_as_confirmation"
    else:
        raise ValueError("stale result is neither a current improvement nor an allowed confirmation")

    event_core = {
        "result_packet_id": result["packet_id"],
        "gate_receipt_id": gate["packet_id"],
        "parent_presentation_root": current_observation["presentation_root"],
        "reviewer_actor": actor,
        "staleness_resolution": resolution,
    }
    event_id = content_id("vev_", event_core)
    fields = {
        "frontier_id": result["frontier_id"],
        "result_packet_id": result["packet_id"],
        "gate_receipt_id": gate["packet_id"],
        "reviewer_actor": actor,
        "result_base_state": result["base_state"],
        "decision_state": state_commitment(current_observation),
        "staleness_resolution": resolution,
        "accepted_event_id": event_id,
        "decision": "accepted",
        "append_contract": {
            "profile_id": PROFILE_ID,
            "witness_cell_rank": 0,
            "bound_cell_rank": 1,
            "rule_atom": RULE_ATOM,
        },
        "reason": "Exact gate passed and the result was evaluated against the current observation root.",
        "created_at": fixture_time(step),
    }
    return signed_packet("acceptance", fields, key, actor)


def append_acceptance(
    presentation: Presentation,
    result: dict[str, Any],
    gate: dict[str, Any],
    acceptance: dict[str, Any],
) -> tuple[str, str]:
    n = int(result["claim"]["n"])
    k = int(result["claim"]["value"])
    register_bound_metadata(presentation, n, k)
    verification_atoms = [
        *["verifier:" + a["receipt_id"] for a in gate["attachments"]],
        *["probe:" + p["probe_id"] for p in gate["adversarial_probes"]],
        "claim-match:" + content_id("vcm_", gate["claim_match_check"]),
        "gate:" + gate["packet_id"],
    ]
    return append_verified_route(
        presentation,
        n=n,
        k=k,
        artifact_digest=result["artifact_digest"],
        claim_digest=result["claim_digest"],
        verification_atoms=verification_atoms,
        accepted_event_id=acceptance["accepted_event_id"],
    )


def make_support_function(
    presentation: Presentation,
    disabled_atoms: set[str],
    *,
    cell_id: str,
    key: Ed25519PrivateKey,
    actor: str,
    step: int,
) -> dict[str, Any]:
    gamma = compile_gamma(presentation)
    historical = minimal_environments(gamma[cell_id])
    active = active_environments(gamma[cell_id], disabled_atoms)
    fields = {
        "frontier_id": FRONTIER_ID,
        "cell_id": cell_id,
        "presentation_root": presentation.presentation_root(),
        "circuit_root": presentation.circuit_root(),
        "historical_lineage_root": lineage_root(gamma),
        "active_view_root": active_view_root(disabled_atoms, VIEW_POLICY_ID),
        "historical_minimal_environments": historical,
        "active_minimal_environments": active,
        "support_function_digest": digest({"cell_id": cell_id, "historical": historical}),
        "created_at": fixture_time(step),
    }
    return signed_packet("support_function", fields, key, actor)


def make_observation(
    presentation: Presentation,
    disabled_atoms: set[str],
    support_packets: list[dict[str, Any]],
    *,
    caused_by_event_id: str | None,
    key: Ed25519PrivateKey,
    actor: str,
    step: int,
) -> dict[str, Any]:
    gamma = compile_gamma(presentation)
    roots = {
        "presentation_root": presentation.presentation_root(),
        "circuit_root": presentation.circuit_root(),
        "lineage_root": lineage_root(gamma),
        "active_view_root": active_view_root(disabled_atoms, VIEW_POLICY_ID),
    }
    evaluator_inputs = {
        "sequence": "oeis:A309370",
        "support_policy": "positive-existence-under-active-view",
        "selection": "maximum-k-per-n",
        "view_policy_id": VIEW_POLICY_ID,
    }
    output = {
        "sequence": "oeis:A309370",
        "bounds": best_bounds(presentation, disabled_atoms),
        "support_function_packet_ids": sorted(p["packet_id"] for p in support_packets),
    }
    replay_core = {
        **roots,
        "evaluator_id": EVALUATOR_ID,
        "evaluator_inputs": evaluator_inputs,
        "canonical_output": output,
    }
    fields = {
        "frontier_id": FRONTIER_ID,
        **roots,
        "evaluator_id": EVALUATOR_ID,
        "evaluator_inputs": evaluator_inputs,
        "canonical_output": output,
        "replay_receipt": {
            "receipt_id": content_id("vor_", replay_core),
            "input_roots_digest": digest(roots),
            "evaluator_digest": evaluator_digest(EVALUATOR_ID, "max supported lower-bound cell per n"),
            "output_digest": digest(output),
            "caused_by_event_id": caused_by_event_id,
            "circuit_semantics": "expanded-lineage-equals-ranked-circuit-on-this-fixture",
        },
        "created_at": fixture_time(step),
    }
    return signed_packet("observation", fields, key, actor)


def make_challenge(
    observation: dict[str, Any],
    support_packet: dict[str, Any],
    disabled_atoms: list[str],
    *,
    key: Ed25519PrivateKey,
    actor: str,
    step: int,
) -> dict[str, Any]:
    active = support_packet["active_minimal_environments"]
    kills = is_hitting_set(active, disabled_atoms)
    fields = {
        "frontier_id": observation["frontier_id"],
        "base_state": state_commitment(observation),
        "target_cell_id": support_packet["cell_id"],
        "support_function_packet_id": support_packet["packet_id"],
        "proposed_disabled_atoms": sorted(set(disabled_atoms)),
        "hitting_set_receipt": {
            "active_environment_count": len(active),
            "hits_every_active_environment": kills,
        },
        "proposed_kill": kills,
        "state_effect": "none_until_view_decision",
        "reason": "Challenge one named verifier receipt in every active derivation route.",
        "challenger_actor": actor,
        "created_at": fixture_time(step),
    }
    return signed_packet("challenge", fields, key, actor)


def make_view_decision(
    observation: dict[str, Any],
    challenge: dict[str, Any],
    current_disabled_atoms: set[str],
    *,
    key: Ed25519PrivateKey,
    actor: str,
    step: int,
) -> tuple[dict[str, Any], set[str]]:
    if challenge["base_state"]["observation_id"] != observation["packet_id"]:
        raise ValueError("challenge is stale and requires explicit re-evaluation")
    if not challenge["proposed_kill"]:
        raise ValueError("challenge does not satisfy its claimed hitting-set condition")
    resulting = set(current_disabled_atoms).union(challenge["proposed_disabled_atoms"])
    fields = {
        "frontier_id": observation["frontier_id"],
        "base_state": state_commitment(observation),
        "challenge_packet_id": challenge["packet_id"],
        "reviewer_actor": actor,
        "decision": "accepted",
        "view_policy_id": VIEW_POLICY_ID,
        "prior_disabled_atoms": sorted(current_disabled_atoms),
        "resulting_disabled_atoms": sorted(resulting),
        "resulting_active_view_root": active_view_root(resulting, VIEW_POLICY_ID),
        "reason": "Human reviewer accepted the named atom restrictions into the public view.",
        "created_at": fixture_time(step),
    }
    return signed_packet("view_decision", fields, key, actor), resulting


def make_repair(
    prior_observation: dict[str, Any],
    repaired_observation: dict[str, Any],
    prior_support: dict[str, Any],
    repaired_support: dict[str, Any],
    *,
    key: Ed25519PrivateKey,
    actor: str,
    step: int,
) -> dict[str, Any]:
    disabled = set()
    # The active view is committed by root. The packet carries the actual active
    # environments, so restoration is checked by comparing support packets.
    restored = (not prior_support["active_minimal_environments"]) and bool(repaired_support["active_minimal_environments"])
    new_envs = [
        env for env in repaired_support["active_minimal_environments"]
        if env not in prior_support["active_minimal_environments"]
    ]
    fields = {
        "frontier_id": repaired_observation["frontier_id"],
        "prior_observation_id": prior_observation["packet_id"],
        "repaired_observation_id": repaired_observation["packet_id"],
        "target_cell_id": repaired_support["cell_id"],
        "prior_support_function_packet_id": prior_support["packet_id"],
        "repaired_support_function_packet_id": repaired_support["packet_id"],
        "repair_kind": "accepted_alternative_route",
        "new_active_environments": new_envs,
        "restores_target": restored,
        "state_effect": "none; append acceptance already changed historical lineage",
        "created_at": fixture_time(step),
    }
    return signed_packet("repair", fields, key, actor)


def verify_observation_replay(
    observation: dict[str, Any],
    presentation: Presentation,
    disabled_atoms: set[str],
) -> None:
    gamma = compile_gamma(presentation)
    expected_roots = {
        "presentation_root": presentation.presentation_root(),
        "circuit_root": presentation.circuit_root(),
        "lineage_root": lineage_root(gamma),
        "active_view_root": active_view_root(disabled_atoms, VIEW_POLICY_ID),
    }
    for key, value in expected_roots.items():
        if observation[key] != value:
            raise AssertionError(f"observation {key} does not replay")
    expected_output = {
        "sequence": "oeis:A309370",
        "bounds": best_bounds(presentation, disabled_atoms),
        "support_function_packet_ids": observation["canonical_output"]["support_function_packet_ids"],
    }
    if observation["canonical_output"] != expected_output:
        raise AssertionError("observation output does not replay")
    if observation["replay_receipt"]["output_digest"] != digest(expected_output):
        raise AssertionError("observation output digest mismatch")
    if observation["replay_receipt"]["input_roots_digest"] != digest(expected_roots):
        raise AssertionError("observation input roots digest mismatch")
