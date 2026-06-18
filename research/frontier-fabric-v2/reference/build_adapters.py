#!/usr/bin/env python3
from __future__ import annotations
import json
from pathlib import Path
from adapters import adapter_id, validate_adapter

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "adapters"
OUT.mkdir(exist_ok=True)


def manifest(
    name: str,
    domain_profile_id: str,
    evidence_class: str,
    context_dimensions: list[str],
    verifier_profiles: list[dict],
    obligation_generators: list[dict],
    candidate_generators: list[dict],
    transfer_lanes: list[str],
    observation_evaluators: list[dict],
    capabilities: list[str],
) -> dict:
    body = {
        "schema_version": "vela.domain-adapter.v2",
        "name": name,
        "domain_profile_id": domain_profile_id,
        "evidence_class": evidence_class,
        "context_dimensions": context_dimensions,
        "compiler_id": f"vela.compiler.{domain_profile_id}.v2",
        "verifier_profiles": verifier_profiles,
        "obligation_generators": obligation_generators,
        "candidate_generators": candidate_generators,
        "transfer_lanes": transfer_lanes,
        "observation_evaluators": observation_evaluators,
        "capabilities": capabilities,
    }
    result = {"adapter_id": adapter_id(body), **body}
    validate_adapter(result)
    return result


common_observe = [{"evaluator_id": "vela.support-and-environments.v2", "authoritative": True}]
none_generator = [{"generator_id": "human-or-external", "model_class": "none", "state_effect": "none"}]

adapters = {
    "formal_math": manifest(
        "Formal mathematics", "formal-math", "exact",
        ["theory", "statement", "formal_system", "library_version"],
        [{"verifier_profile_id": "lean-kernel", "receipt_kinds": ["kernel_check"]}],
        [{"generator_id": "open-goal-generator", "kind": "missing_proof", "targets": ["open_goal"], "discharge_evaluator_id": "vela.support-exists.v1", "verifier_profile_id": "lean-kernel", "rationale": "a declared theorem cell lacks an accepted proof route"}],
        none_generator + [{"generator_id": "formal-agent", "model_class": "language_model", "state_effect": "none"}],
        ["certified", "target_checked", "exploratory"], common_observe,
        ["compile_proof_receipts", "generate_open_goals", "certified_transfers", "export_lean"],
    ),
    "exact_combinatorics": manifest(
        "Exact combinatorics", "exact-combinatorics", "exact",
        ["problem", "parameter", "bound_kind", "verifier_version"],
        [{"verifier_profile_id": "exact-witness", "receipt_kinds": ["exact_certificate"]}],
        [{"generator_id": "frontier-bound-generator", "kind": "unimproved_bound", "targets": ["next_bound"], "discharge_evaluator_id": "vela.support-exists.v1", "verifier_profile_id": "exact-witness", "rationale": "the next declared frontier bound lacks an accepted witness"}],
        none_generator + [{"generator_id": "search-agent", "model_class": "generative_model", "state_effect": "none"}],
        ["certified", "target_checked", "exploratory"], common_observe,
        ["compile_witnesses", "generate_bound_obligations", "poll_frontier", "export_oeis"],
    ),
    "software": manifest(
        "Software and code validation", "software", "replay",
        ["repository", "commit", "toolchain", "platform", "test_suite"],
        [{"verifier_profile_id": "reproducible-build", "receipt_kinds": ["bitwise_replay", "test_receipt"]}],
        [{"generator_id": "failing-check-generator", "kind": "failing_check", "targets": ["validated_implementation"], "discharge_evaluator_id": "vela.support-exists.v1", "verifier_profile_id": "reproducible-build", "rationale": "an implementation claim lacks a passing replay route"}],
        none_generator + [{"generator_id": "coding-agent", "model_class": "language_model", "state_effect": "none"}],
        ["certified", "target_checked", "exploratory"], common_observe,
        ["compile_ci_receipts", "track_regressions", "export_git"],
    ),
    "numerical_simulation": manifest(
        "Reproducible numerical simulation", "numerical-simulation", "replay",
        ["equations", "parameters", "initial_conditions", "mesh", "solver", "tolerance"],
        [{"verifier_profile_id": "semantic-replay", "receipt_kinds": ["semantic_replay", "residual_check"]}],
        [
            {"generator_id": "parameter-coverage-alpha-02", "kind": "uncovered_parameter_regime", "targets": ["heat_alpha_02"], "discharge_evaluator_id": "vela.support-exists.v1", "verifier_profile_id": "semantic-replay", "rationale": "the next actionable parameter regime lacks a replay-confirmed solution route"},
            {"generator_id": "parameter-coverage-alpha-03", "kind": "uncovered_parameter_regime", "targets": ["heat_alpha_03"], "dependencies": ["heat_alpha_02"], "discharge_evaluator_id": "vela.support-exists.v1", "verifier_profile_id": "semantic-replay", "rationale": "the successor regime becomes actionable after alpha=0.2 is replay-confirmed"},
        ],
        none_generator + [{"generator_id": "neural-operator", "model_class": "neural_operator", "state_effect": "none"}],
        ["target_checked", "exploratory"], common_observe,
        ["compile_replay_receipts", "generate_parameter_gaps", "operator_candidates", "export_ro_crate"],
    ),
    "model_evaluation": manifest(
        "Scientific model evaluation", "model-evaluation", "replay",
        ["model", "weights", "training_data", "evaluation_suite", "domain_of_validity"],
        [{"verifier_profile_id": "evaluation-suite", "receipt_kinds": ["benchmark_replay", "calibration_report", "ood_report"]}],
        [{"generator_id": "evaluation-gap-generator", "kind": "missing_evaluation", "targets": ["model_validated"], "discharge_evaluator_id": "vela.support-exists.v1", "verifier_profile_id": "evaluation-suite", "rationale": "a declared model capability lacks a target-domain evaluation route"}],
        [{"generator_id": "foundation-model", "model_class": "graph_model", "state_effect": "none"}, {"generator_id": "natural-law-model", "model_class": "natural_law_model", "state_effect": "none"}],
        ["target_checked", "exploratory"], common_observe,
        ["compile_model_receipts", "track_domain_shift", "generate_candidate_hypotheses"],
    ),
    "experimental_trace": manifest(
        "Experimental execution trace", "experimental-trace", "trace",
        ["protocol", "sample_lineage", "instrument", "calibration", "operator", "time"],
        [{"verifier_profile_id": "trace-validator", "receipt_kinds": ["instrument_trace", "calibration_receipt"]}],
        [{"generator_id": "replication-gap-generator", "kind": "missing_replication", "targets": ["replicated_observation"], "discharge_evaluator_id": "vela.support-exists.v1", "verifier_profile_id": "trace-validator", "rationale": "a declared replication obligation lacks an independent trace route"}],
        none_generator + [{"generator_id": "experiment-planner", "model_class": "natural_law_model", "state_effect": "none"}],
        ["target_checked", "exploratory"], common_observe,
        ["compile_body_traces", "generate_replication_gaps", "rank_experiments"],
    ),
    "observational_estimate": manifest(
        "Observational estimate", "observational-estimate", "estimate",
        ["population", "estimand", "data_root", "analysis", "assumptions", "valid_time"],
        [{"verifier_profile_id": "analysis-replay", "receipt_kinds": ["analysis_replay", "uncertainty_report"]}],
        [{"generator_id": "estimand-gap-generator", "kind": "missing_estimate", "targets": ["registered_estimand"], "discharge_evaluator_id": "vela.support-exists.v1", "verifier_profile_id": "analysis-replay", "rationale": "a registered estimand lacks an accepted estimate route"}],
        none_generator + [{"generator_id": "causal-model", "model_class": "graph_model", "state_effect": "none"}],
        ["target_checked", "exploratory"], common_observe,
        ["compile_estimands", "track_assumptions", "generate_analysis_candidates"],
    ),
    "human_attestation": manifest(
        "Human statement and interpretation attestation", "human-attestation", "attestation",
        ["statement", "scope", "reviewer_role", "policy_epoch"],
        [{"verifier_profile_id": "signature-policy", "receipt_kinds": ["statement_attestation"]}],
        [{"generator_id": "review-gap-generator", "kind": "missing_review", "targets": ["reviewed_statement"], "discharge_evaluator_id": "vela.support-exists.v1", "verifier_profile_id": "signature-policy", "rationale": "a declared interpretation lacks an eligible human attestation"}],
        none_generator,
        ["exploratory"], common_observe,
        ["compile_attestations", "track_statement_faithfulness"],
    ),
}

for name, value in adapters.items():
    (OUT / f"{name}.adapter.json").write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
print(f"wrote {len(adapters)} adapters")
