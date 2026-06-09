import Vela.CoreTheorems

/-!
# Axiom audit

Emits one machine-parseable line per registered theorem:

    AXIOMS <decl> | axiom1, axiom2, ...

This is consumed by `vela lean verify-all --axioms-report`. The CLI classifies
each axiom set against the frozen TCB policy: a proof closed by `native_decide`
surfaces `Lean.ofReduceBool` (+ `Lean.trustCompiler`) and is demoted to
`compiler_checked`; a `sorry` surfaces `sorryAx` and fails; a proof depending
only on `{propext, Classical.choice, Quot.sound}` is kernel-clean.

`theoremsToAudit` is written with double-backtick name literals, so the file
FAILS TO COMPILE if any decl is missing or renamed — there is no silent gap.
Keep it in lockstep with the Rust `THEOREMS` registry
(`crates/vela-protocol/src/lean_anchors.rs`).
-/

open Lean Elab Command

/-- The registered theorem declarations, in registry order. Double-backtick
literals resolve against the imported environment, so a typo is a build error. -/
def theoremsToAudit : List Name :=
  [``replay_convergence_same_finite_log,
   ``retraction_monotone,
   ``status_provenance_sound_t,
   ``frontier_upward_closed,
   ``changed_core_changes_id,
   ``theorem6_signature_stable_under_flip,
   ``theorem7_index_maintenance_under_append,
   ``theorem8_egz_two,
   ``theorem9_canonical_event_id_injective,
   ``theorem10_signature_uniqueness_under_canonical,
   ``theorem11a_distinctness,
   ``theorem12_concurrent_replay_commutes,
   ``theorem13_frontier_id_injective,
   ``theorem14_accept_idempotent,
   ``theorem15_confidence_update_bounded,
   ``theorem16_governed_quorum_sound,
   ``theorem17_search_index_deterministic,
   ``theorem18_chain_monotone_single_step,
   ``theorem19_registry_root_injective,
   ``theorem20_empty_log_replay_identity,
   ``theorem21_canonical_sequence_length,
   ``theorem22_replay_append,
   ``theorem23_scientific_diff_pack_id_injective,
   ``theorem24_agent_attestation_id_injective,
   ``theorem25_tool_descriptor_id_injective,
   ``theorem26_diff_pack_verdict_atomicity,
   ``theorem27_evaluation_record_id_injective,
   ``theorem28_tool_descriptor_composition,
   ``theorem29_released_pack_accumulation,
   ``theorem30_diff_pack_federation_soundness,
   ``theorem31_verdict_conflict_id_injective,
   ``theorem32_verdict_conflict_accumulation,
   ``theorem33_released_pack_replay,
   ``theorem34_eval_descriptor_composition_eval_first]

run_cmd do
  for declName in theoremsToAudit do
    let axs ← liftCoreM (Lean.collectAxioms declName)
    let names := axs.toList.map (fun n => n.toString)
    IO.println s!"AXIOMS {declName} | {String.intercalate ", " names}"
