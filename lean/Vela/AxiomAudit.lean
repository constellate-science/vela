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
  [``Vela.Log.replay_convergence_same_finite_log,
   ``Vela.Core.retraction_monotone,
   ``Vela.Core.status_provenance_sound_t,
   ``Vela.Core.frontier_upward_closed,
   ``Vela.Log.changed_core_changes_id,
   ``Vela.Signing.theorem6_signature_stable_under_flip,
   ``Vela.ReplayIndex.theorem7_index_maintenance_under_append,
   ``Vela.EGZ.theorem8_egz_two,
   ``Vela.CanonicalEventId.theorem9_canonical_event_id_injective,
   ``Vela.SignatureUniqueness.theorem10_signature_uniqueness_under_canonical,
   ``Vela.MultiSigThreshold.theorem11a_distinctness,
   ``Vela.ConcurrentReplay.theorem12_concurrent_replay_commutes,
   ``Vela.FrontierIdDeterminism.theorem13_frontier_id_injective,
   ``Vela.ProposalIdempotency.theorem14_accept_idempotent,
   ``Vela.ConfidenceUpdate.theorem15_confidence_update_bounded,
   ``Vela.GovernedQuorumSoundness.theorem16_governed_quorum_sound,
   ``Vela.SearchIndexDeterminism.theorem17_search_index_deterministic,
   ``Vela.OwnerEpochChainMonotonicity.theorem18_chain_monotone_single_step,
   ``Vela.CheckpointRootInjectivity.theorem19_registry_root_injective,
   ``Vela.EmptyLogReplay.theorem20_empty_log_replay_identity,
   ``Vela.CanonicalSequenceLength.theorem21_canonical_sequence_length,
   ``Vela.ReplayAppend.theorem22_replay_append,
   ``Vela.ScientificDiffPackId.theorem23_scientific_diff_pack_id_injective,
   ``Vela.AgentAttestationInjectivity.theorem24_agent_attestation_id_injective,
   ``Vela.ToolDescriptorInjectivity.theorem25_tool_descriptor_id_injective,
   ``Vela.DiffPackVerdictAtomicity.theorem26_diff_pack_verdict_atomicity,
   ``Vela.EvaluationRecordInjectivity.theorem27_evaluation_record_id_injective,
   ``Vela.ToolDescriptorComposition.theorem28_tool_descriptor_composition,
   ``Vela.ReleasedDiffPackAccumulation.theorem29_released_pack_accumulation,
   ``Vela.DiffPackFederationSoundness.theorem30_diff_pack_federation_soundness,
   ``Vela.VerdictConflictResolution.theorem31_verdict_conflict_id_injective,
   ``Vela.VerdictConflictAccumulation.theorem32_verdict_conflict_accumulation,
   ``Vela.ReleasedDiffPackReplay.theorem33_released_pack_replay,
   ``Vela.EvaluationDescriptorComposition.theorem34_eval_descriptor_composition_eval_first,
   ``Vela.transfer_sound]

run_cmd do
  for declName in theoremsToAudit do
    let axs ← liftCoreM (Lean.collectAxioms declName)
    let names := axs.toList.map (fun n => n.toString)
    -- Print the SHORT decl name (matches the unqualified `decl` the anchor
    -- registry uses) so `verify-all --axioms-report` can join by decl.
    IO.println s!"AXIOMS {declName.getString!} | {String.intercalate ", " names}"
