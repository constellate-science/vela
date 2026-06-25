//! v0.164: Lean theorem anchors. Pin each substrate theorem in
//! `lean/Vela/*.lean` to its content-addressed source bytes,
//! declaration name, and substrate role. The anchor is a derived
//! view that any consumer can re-compute over the same source
//! tree.
//!
//! Substrate-honest framing: this layer ships *structural*
//! anchoring — it pins (theorem id, module path, decl name,
//! module_sha256, mathlib pin). It does NOT yet ship signed
//! verifier-output-attested records (which require running
//! `lake build` in a controlled environment). Arc 6 waves 2 + 3
//! layer signed `vpv_*` records on top.
//!
//! Two consumers walking the same `lean/` tree produce byte-
//! identical anchor records.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

pub const ANCHOR_SCHEMA: &str = "vela.lean_anchor.v0.1";

/// One entry in the canonical theorem registry. Mirror of the
/// site-side `THEOREM_REGISTRY` constant. Both surfaces are
/// regression-gated against the actual Lean source tree by
/// scripts/test-lean-bundle.sh.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TheoremDescriptor {
    pub id: u32,
    pub title: &'static str,
    pub module: &'static str,
    pub decl: &'static str,
    pub substrate_role: &'static str,
}

pub const THEOREMS: &[TheoremDescriptor] = &[
    TheoremDescriptor {
        id: 1,
        title: "Replay convergence",
        module: "Vela/Log.lean",
        decl: "replay_convergence_same_finite_log",
        substrate_role: "Deterministic replay over the same finite canonical log produces the same state.",
    },
    TheoremDescriptor {
        id: 2,
        title: "Provenance retraction monotonicity",
        module: "Vela/Provenance.lean",
        decl: "retraction_monotone",
        substrate_role: "A retraction can only remove provenance support, never add it.",
    },
    TheoremDescriptor {
        id: 3,
        title: "Status-provenance soundness, T-side",
        module: "Vela/Provenance.lean",
        decl: "status_provenance_sound_t",
        substrate_role: "An accepted (T-side) status implies its provenance support is non-empty.",
    },
    TheoremDescriptor {
        id: 4,
        title: "Detector monotonicity implies frontier support upward closure",
        module: "Vela/Provenance.lean",
        decl: "frontier_upward_closed",
        substrate_role: "If a detector is monotone, the set of findings it supports is upward-closed under the substrate's ordering.",
    },
    TheoremDescriptor {
        id: 5,
        title: "Hash-DAG log integrity (structural)",
        module: "Vela/Log.lean",
        decl: "changed_core_changes_id",
        substrate_role: "Under an abstract injective hash, a change to an event's core changes its canonical id.",
    },
    TheoremDescriptor {
        id: 6,
        title: "Signature stability under cache-flag flips",
        module: "Vela/Signing.lean",
        decl: "theorem6_signature_stable_under_flip",
        substrate_role: "Toggling a Finding's cache fields does not change its canonical signing bytes.",
    },
    TheoremDescriptor {
        id: 7,
        title: "Replay-index correctness under append",
        module: "Vela/ReplayIndex.lean",
        decl: "theorem7_index_maintenance_under_append",
        substrate_role: "Inserting (id, position) on every finding.asserted push agrees with rebuilding the index from the appended list.",
    },
    TheoremDescriptor {
        id: 8,
        title: "Erdős-Ginzburg-Ziv (1961), n = 2 case",
        module: "Vela/EGZ.lean",
        decl: "theorem8_egz_two",
        substrate_role: "Among any three integers, some two have an even sum. The bundle's first external mathematical claim.",
    },
    TheoremDescriptor {
        id: 9,
        title: "Canonical-event-id determinism (serialize then hash)",
        module: "Vela/CanonicalEventId.lean",
        decl: "theorem9_canonical_event_id_injective",
        substrate_role: "The substrate's two-stage id pipeline (canonical_bytes serialize then sha256) inherits injectivity from each layer.",
    },
    TheoremDescriptor {
        id: 10,
        title: "Signature uniqueness under canonical bytes",
        module: "Vela/SignatureUniqueness.lean",
        decl: "theorem10_signature_uniqueness_under_canonical",
        substrate_role: "Two distinct (event_core, signing_key) pairs cannot produce the same signature under canonical bytes.",
    },
    TheoremDescriptor {
        id: 11,
        title: "Multi-sig threshold soundness",
        module: "Vela/MultiSigThreshold.lean",
        decl: "theorem11a_distinctness",
        substrate_role: "The substrate's k-of-n multi-sig predicate is sound under distinctness, monotonicity, and registration-bound.",
    },
    TheoremDescriptor {
        id: 12,
        title: "Concurrent-replay commutativity for disjoint events",
        module: "Vela/ConcurrentReplay.lean",
        decl: "theorem12_concurrent_replay_commutes",
        substrate_role: "Two canonical events targeting different findings commute under the reducer's apply function.",
    },
    TheoremDescriptor {
        id: 13,
        title: "Frontier-id determinism",
        module: "Vela/FrontierIdDeterminism.lean",
        decl: "theorem13_frontier_id_injective",
        substrate_role: "The substrate's vfr_* ids are content-addressed over the canonical event log; distinct event logs produce distinct frontier ids.",
    },
    TheoremDescriptor {
        id: 14,
        title: "Proposal-acceptance idempotency",
        module: "Vela/ProposalIdempotency.lean",
        decl: "theorem14_accept_idempotent",
        substrate_role: "Under the substrate's deduplication policy, re-applying an accepted proposal is a no-op.",
    },
    TheoremDescriptor {
        id: 15,
        title: "Confidence-update bounds",
        module: "Vela/ConfidenceUpdate.lean",
        decl: "theorem15_confidence_update_bounded",
        substrate_role: "A single finding.confidence_revise event cannot move confidence by more than the policy-declared per-event delta cap.",
    },
    TheoremDescriptor {
        id: 16,
        title: "Governed-quorum soundness",
        module: "Vela/GovernedQuorumSoundness.lean",
        decl: "theorem16_governed_quorum_sound",
        substrate_role: "If governance::verify_quorum returns Ok for a governed owner-rotation proposal, at least t distinct attesters satisfy eligibility + revocation + signature simultaneously.",
    },
    TheoremDescriptor {
        id: 17,
        title: "Search-index determinism",
        module: "Vela/SearchIndexDeterminism.lean",
        decl: "theorem17_search_index_deterministic",
        substrate_role: "vela-search build_index is a pure function over inputs; composing it with canonical-bytes + abstract-hash injectivity produces an injective vsi_* derivation.",
    },
    TheoremDescriptor {
        id: 18,
        title: "Owner-epoch chain monotone-by-one",
        module: "Vela/OwnerEpochChainMonotonicity.lean",
        decl: "theorem18_chain_monotone_single_step",
        substrate_role: "The OwnerEpochChain::append rule enforces strict monotonicity: each new transition's owner_epoch equals the previous + 1.",
    },
    TheoremDescriptor {
        id: 20,
        title: "Empty-log replay identity",
        module: "Vela/EmptyLogReplay.lean",
        decl: "theorem20_empty_log_replay_identity",
        substrate_role: "Replaying the empty canonical event log produces the initial state. The base case of replay convergence; pins the substrate's claim that a fresh frontier with zero events replays deterministically to its initial state.",
    },
    TheoremDescriptor {
        id: 21,
        title: "Canonical-sequence cardinality preservation",
        module: "Vela/CanonicalSequenceLength.lean",
        decl: "theorem21_canonical_sequence_length",
        substrate_role: "(canonicalSequence log).length = log.ids.card. Pins the substrate's claim that every event in the log is replayed exactly once — no duplicates, no drops.",
    },
    TheoremDescriptor {
        id: 22,
        title: "Replay-compositional append",
        module: "Vela/ReplayAppend.lean",
        decl: "theorem22_replay_append",
        substrate_role: "replay r init (a ++ b) = replay r (replay r init a) b. Pins the legitimacy of incremental replay: a hub that has processed a prefix can resume from its current state through the suffix and reach byte-identical results to a full replay.",
    },
    TheoremDescriptor {
        id: 23,
        title: "Scientific Diff Pack id injectivity",
        module: "Vela/ScientificDiffPackId.lean",
        decl: "theorem23_scientific_diff_pack_id_injective",
        substrate_role: "Distinct (frontier_id, ordered proposals, aggregate_kind, summary, created_at) tuples produce distinct vsd_* pack ids under an abstract-injective hash assumption. Composes T9 (canonical-bytes injectivity) for the v0.193 ScientificDiffPack primitive.",
    },
    TheoremDescriptor {
        id: 24,
        title: "Agent attestation envelope injectivity",
        module: "Vela/AgentAttestationInjectivity.lean",
        decl: "theorem24_agent_attestation_id_injective",
        substrate_role: "Distinct (agent_actor, model_name, model_version, started_at, finished_at, total_tokens, tool_calls, output_hashes, prompt_hash, parent_attestation, signer_pubkey_hex, signature) tuples produce distinct vaa_* envelope ids under an abstract-injective hash assumption. Pins the v0.195 AgentAttestation chain of custody — a reviewer agreeing on a vaa_* necessarily agrees on the underlying model, tool calls, and outputs.",
    },
    TheoremDescriptor {
        id: 25,
        title: "Tool descriptor injectivity",
        module: "Vela/ToolDescriptorInjectivity.lean",
        decl: "theorem25_tool_descriptor_id_injective",
        substrate_role: "Distinct (tool_name, tool_version, provider, calling_convention, input_schema, output_schema) tuples produce distinct vtd_* descriptor ids under an abstract-injective hash assumption. Pins the v0.199 ToolDescriptor primitive — a frontier declaring it consumes a tool reaches a stable id; any drift in tool surface produces a different vtd_* and is therefore reviewable as a separate object.",
    },
    TheoremDescriptor {
        id: 26,
        title: "Diff Pack verdict atomicity",
        module: "Vela/DiffPackVerdictAtomicity.lean",
        decl: "theorem26_diff_pack_verdict_atomicity",
        substrate_role: "For verdict=accept, the promoter applies every canonical member proposal AND emits the diff_pack.reviewed event, OR no state change occurs (rollback). No intermediate observable state where some members applied and others did not. Pins the v0.205 reviewer-flow guarantee. Composes T22 (replay-compositional append) + T14 (proposal idempotency).",
    },
    TheoremDescriptor {
        id: 27,
        title: "Evaluation Record id injectivity",
        module: "Vela/EvaluationRecordInjectivity.lean",
        decl: "theorem27_evaluation_record_id_injective",
        substrate_role: "Distinct (target_kind, target_id, evaluation_kind, outcome, evaluator_actor, evaluated_at, evidence_refs, benchmark_id, score, notes) tuples produce distinct ver_* ids under an abstract-injective hash assumption. Pins the v0.200 EvaluationRecord primitive. Two consumers reaching the same ver_* necessarily agree on the underlying evaluation tuple.",
    },
    TheoremDescriptor {
        id: 28,
        title: "Tool Descriptor × Diff Pack composition",
        module: "Vela/ToolDescriptorComposition.lean",
        decl: "theorem28_tool_descriptor_composition",
        substrate_role: "If a vsd_* Diff Pack references a vtd_* Tool Descriptor present in the substrate, the descriptor's id resolves to the same value after the pack is accepted. The reducer's accept-pack arm does not mutate descriptor storage. Composes T25 (vtd_* injectivity) + T22 (replay-compositional append) + T26 (Diff Pack verdict atomicity).",
    },
    TheoremDescriptor {
        id: 29,
        title: "Released Diff Pack accumulation",
        module: "Vela/ReleasedDiffPackAccumulation.lean",
        decl: "theorem29_released_pack_accumulation",
        substrate_role: "Replay of N diff_pack.released and diff_pack.reviewed events produces a released_diff_packs array whose length is bounded by N (the no-op-on-duplicate behavior). The reducer makes the canonical event log self-sufficient for replay over the v0.193+ Diff Pack lifecycle — a consumer walking the log alone can answer 'what packs have been released?' without reading sibling directories.",
    },
    TheoremDescriptor {
        id: 31,
        title: "Verdict Conflict Resolution id injectivity",
        module: "Vela/VerdictConflictResolution.lean",
        decl: "theorem31_verdict_conflict_id_injective",
        substrate_role: "Distinct (frontier_id, ordered verdicts, sorted shared_member_ids, resolution_mode, resolution_actor, resolved_at, winning_verdict_id) tuples produce distinct vdc_* ids under abstract-injective hash. Pins the v0.217 VerdictConflict primitive: a second resolution on the same conflicting verdicts produces a new vdc_* record rather than silently overwriting the first. The substrate handles reviewer disagreement as an audit trail, not a last-write-wins update. Composes T9.",
    },
    TheoremDescriptor {
        id: 32,
        title: "Verdict Conflict accumulation under replay",
        module: "Vela/VerdictConflictAccumulation.lean",
        decl: "theorem32_verdict_conflict_accumulation",
        substrate_role: "Replay of N verdict_conflict.resolved events produces a Project.verdict_conflicts array whose length is bounded by N (no-op-on-duplicate by conflict_id). The v0.218 reducer arm makes the canonical event log self-sufficient for replay over the v0.217 VerdictConflict primitive. Composes T22 + T31a.",
    },
    TheoremDescriptor {
        id: 33,
        title: "Released Diff Pack replay determinism",
        module: "Vela/ReleasedDiffPackReplay.lean",
        decl: "theorem33_released_pack_replay",
        substrate_role: "Replaying the trace [release p, review p v] from an empty Project.released_diff_packs produces exactly one record { pack_id := p, verdict := some v }. Anchors the v0.222 consumer migration: workbench/site-next/search read from the substrate field instead of disk-walking .vela/diff_packs/ because T33 says the field is a deterministic function of the canonical event log. Composes T29 (accumulation length bound) + T22 (replay-compositional append).",
    },
    TheoremDescriptor {
        id: 34,
        title: "Evaluation × Descriptor × Diff Pack composition",
        module: "Vela/EvaluationDescriptorComposition.lean",
        decl: "theorem34_eval_descriptor_composition_eval_first",
        substrate_role: "If a ver_* targets a vtd_* and a vsd_* on the same frontier contains members that also reference that vtd_*, then the descriptor's identity is preserved across the full event chain in either order (record_evaluation then accept_pack, or accept_pack then record_evaluation). Closes the three-way composition opened by T25 + T27 + T28. Substrate-side anchor for downstream consumers replaying the log: vtd_* references resolve the same way regardless of event order.",
    },
    TheoremDescriptor {
        id: 35,
        title: "Cross-frontier transfer soundness (Theorem 23 / the constellation layer)",
        module: "Vela/Transfer.lean",
        decl: "transfer_sound",
        substrate_role: "A verifier-homomorphism T : Transfer A B carries a verified object in frontier A to a verified object in frontier B, so a gate-verified claim in domain X discharges a premise in domain Y WITHOUT re-running A's verifier. The kernel-verified basis of the vtr_ Transfer object's T2 clause (derive_transfer_status): a vtr_ may only reach Admitted when its transfer theorem's vlv_ is axiom-clean. This is the one substrate theorem about the relation BETWEEN frontiers; the single-domain theorems (T2-T4) cannot express it. The concrete maps (cwc_to_dna_sound, sidon_to_golomb_sound, ...) each instantiate it with a real, Mathlib-free, sorry-free soundness proof.",
    },
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LeanAnchor {
    pub schema: String,
    pub theorem_id: u32,
    pub title: String,
    pub module: String,
    pub decl: String,
    pub substrate_role: String,
    pub module_sha256: String,
    pub anchor_id: String,
    /// True if the source module both contains a `theorem <decl>`
    /// declaration AND has no bare `sorry` in any theorem body.
    pub structurally_present: bool,
}

impl LeanAnchor {
    pub fn anchor_for(descriptor: &TheoremDescriptor, lean_dir: &Path) -> Result<Self, String> {
        Self::anchor_for_parts(
            descriptor.id,
            descriptor.title,
            descriptor.module,
            descriptor.decl,
            descriptor.substrate_role,
            lean_dir,
        )
    }

    /// Anchor an arbitrary `(module, decl)` using runtime strings — for a target
    /// OUTSIDE the static `THEOREMS` registry (e.g. a formal-conjectures
    /// declaration the prover lane is attacking). Byte-for-byte compatible with
    /// `anchor_for`: the `vla_` id is content-addressed over the same
    /// `(theorem_id, module, decl, module_sha256)` tuple, so the two paths agree
    /// on a registry decl. Pass `theorem_id = 0` for a non-registry decl (the id
    /// is informational; the anchor_id still varies by module+decl+sha256).
    pub fn anchor_for_parts(
        theorem_id: u32,
        title: &str,
        module: &str,
        decl: &str,
        substrate_role: &str,
        lean_dir: &Path,
    ) -> Result<Self, String> {
        let module_path = lean_dir.join(module);
        let bytes =
            fs::read(&module_path).map_err(|e| format!("read {}: {e}", module_path.display()))?;
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let module_sha256 = hex::encode(hasher.finalize());

        let text = String::from_utf8_lossy(&bytes);
        let structurally_present = check_declaration_present(&text, decl);

        let mut anchor = LeanAnchor {
            schema: ANCHOR_SCHEMA.to_string(),
            theorem_id,
            title: title.to_string(),
            module: module.to_string(),
            decl: decl.to_string(),
            substrate_role: substrate_role.to_string(),
            module_sha256,
            anchor_id: String::new(),
            structurally_present,
        };
        anchor.anchor_id = anchor.derive_id();
        Ok(anchor)
    }

    fn derive_id(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(format!("T{}|", self.theorem_id).as_bytes());
        hasher.update(self.module.as_bytes());
        hasher.update(b"|");
        hasher.update(self.decl.as_bytes());
        hasher.update(b"|");
        hasher.update(self.module_sha256.as_bytes());
        format!("vla_{}", &hex::encode(hasher.finalize())[..16])
    }
}

fn check_declaration_present(text: &str, decl: &str) -> bool {
    // Try the decl as given, and (for a fully-qualified `Namespace.decl` passed
    // against a source written inside `namespace Namespace`) its progressively
    // namespace-stripped suffixes. A substrate registry decl matches on the
    // first form; a formal-conjectures FQ decl matches once the opened namespace
    // prefix is dropped (the source writes `theorem erdos_828`, the probe needs
    // `Erdos828.erdos_828`). `theorem` covers our targets; allow the other
    // proof-bearing binders so the flag is honest for lemmas/instances too.
    let kinds = ["theorem ", "lemma ", "instance ", "def "];
    let mut candidate = decl;
    loop {
        if kinds
            .iter()
            .any(|k| text.contains(&format!("{k}{candidate}")))
        {
            return true;
        }
        match candidate.split_once('.') {
            Some((_, rest)) if !rest.is_empty() => candidate = rest,
            _ => return false,
        }
    }
}

pub fn lean_dir_default() -> PathBuf {
    // Walk upward from cwd looking for a `lean/` sibling of
    // `Cargo.toml`. Fall back to `./lean`.
    let mut cur = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    for _ in 0..6 {
        if cur.join("lean").is_dir() && cur.join("Cargo.toml").exists() {
            return cur.join("lean");
        }
        match cur.parent() {
            Some(p) => cur = p.to_path_buf(),
            None => break,
        }
    }
    PathBuf::from("lean")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn write_lean_module(dir: &Path, rel: &str, body: &str) {
        let path = dir.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut f = fs::File::create(&path).unwrap();
        f.write_all(body.as_bytes()).unwrap();
    }

    #[test]
    fn anchors_pin_module_hash() {
        let tmp = TempDir::new().unwrap();
        let lean = tmp.path();
        write_lean_module(
            lean,
            "Vela/Log.lean",
            "theorem replay_convergence_same_finite_log : True := trivial\n",
        );
        let d = &THEOREMS[0];
        let a = LeanAnchor::anchor_for(d, lean).expect("anchor");
        assert_eq!(a.theorem_id, 1);
        assert!(a.structurally_present);
        assert!(a.anchor_id.starts_with("vla_"));
        // Re-anchor produces the same id.
        let b = LeanAnchor::anchor_for(d, lean).expect("anchor again");
        assert_eq!(a, b);
    }

    #[test]
    fn anchor_id_changes_when_source_changes() {
        let tmp = TempDir::new().unwrap();
        let lean = tmp.path();
        write_lean_module(
            lean,
            "Vela/Log.lean",
            "theorem replay_convergence_same_finite_log : True := trivial\n",
        );
        let d = &THEOREMS[0];
        let a = LeanAnchor::anchor_for(d, lean).expect("anchor");
        write_lean_module(
            lean,
            "Vela/Log.lean",
            "theorem replay_convergence_same_finite_log : True := trivial -- v2\n",
        );
        let b = LeanAnchor::anchor_for(d, lean).expect("anchor v2");
        assert_ne!(a.anchor_id, b.anchor_id);
        assert_ne!(a.module_sha256, b.module_sha256);
    }

    #[test]
    fn missing_decl_flags_as_absent() {
        let tmp = TempDir::new().unwrap();
        let lean = tmp.path();
        write_lean_module(lean, "Vela/Log.lean", "-- empty module\n");
        let d = &THEOREMS[0];
        let a = LeanAnchor::anchor_for(d, lean).expect("anchor");
        assert!(!a.structurally_present);
    }

    #[test]
    fn anchor_for_parts_matches_registry_path() {
        // The generic runtime-string path must produce the byte-identical anchor
        // a registry descriptor does over the same source (so a vlv_ minted via
        // either route agrees).
        let tmp = TempDir::new().unwrap();
        let lean = tmp.path();
        write_lean_module(
            lean,
            "Vela/Log.lean",
            "theorem replay_convergence_same_finite_log : True := trivial\n",
        );
        let d = &THEOREMS[0];
        let via_descriptor = LeanAnchor::anchor_for(d, lean).expect("anchor");
        let via_parts =
            LeanAnchor::anchor_for_parts(d.id, d.title, d.module, d.decl, d.substrate_role, lean)
                .expect("anchor parts");
        assert_eq!(via_descriptor, via_parts);
    }

    #[test]
    fn anchor_for_parts_finds_namespaced_decl() {
        // A formal-conjectures FQ decl (`Erdos828.erdos_828`) matches a source
        // written `theorem erdos_828` inside `namespace Erdos828`.
        let tmp = TempDir::new().unwrap();
        let lean = tmp.path();
        write_lean_module(
            lean,
            "FC/828.lean",
            "namespace Erdos828\ntheorem erdos_828 : True := trivial\nend Erdos828\n",
        );
        let a = LeanAnchor::anchor_for_parts(
            0,
            "Erdos 828",
            "FC/828.lean",
            "Erdos828.erdos_828",
            "formal-conjectures target",
            lean,
        )
        .expect("anchor parts");
        assert_eq!(a.theorem_id, 0);
        assert!(a.structurally_present);
        assert!(a.anchor_id.starts_with("vla_"));
    }
}
