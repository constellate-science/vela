//! Stage 5: ASSEMBLE — build the project with stats and metadata.

use std::collections::{HashMap, HashSet};

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::bundle::{ConfidenceUpdate, FindingBundle, ReviewEvent};
use crate::events::StateEvent;
use crate::proposals::{ProofState, StateProposal};
use crate::sign::{ActorRecord, SignedEnvelope};
use crate::sources::{ConditionRecord, EvidenceAtom, SourceRecord};

/// A dependency on another project (like a Cargo dependency for science).
///
/// v0.8 extends this with three optional fields that turn it into a
/// **cross-frontier dependency**: when `vfr_id` is set, the entry pins
/// a remote frontier by its content-addressed id and a snapshot hash.
/// `Link.target` values of the form `vf_<id>@vfr_<id>` resolve through
/// here. Without `vfr_id`, the entry behaves as a pre-v0.8 compile-time
/// dependency record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProjectDependency {
    pub name: String,
    pub source: String,
    pub version: Option<String>,
    pub pinned_hash: Option<String>,
    /// v0.8: content-addressed id of the dependent frontier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vfr_id: Option<String>,
    /// v0.8: where to fetch the dependent frontier file from
    /// (typically an `https://…` URL pointing at raw JSON).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locator: Option<String>,
    /// v0.8: SHA-256 of the canonical snapshot the dependent commits
    /// to. Strict pull verifies the fetched dependency's actual
    /// `snapshot_hash` matches this value before satisfying any link.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pinned_snapshot_hash: Option<String>,
}

impl ProjectDependency {
    /// True if this entry declares a cross-frontier dependency
    /// (`vfr_id` is set). Pre-v0.8 entries return `false`.
    pub fn is_cross_frontier(&self) -> bool {
        self.vfr_id.is_some()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Project {
    pub vela_version: String,
    pub schema: String,
    /// Stable Vela-addressable frontier ID, derived from a `frontier.created`
    /// genesis event hash. Optional for backward compatibility with v0.2
    /// frontiers; new v0.3 frontiers populate it on `assemble()`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frontier_id: Option<String>,
    #[serde(rename = "frontier")]
    pub project: ProjectMeta,
    pub stats: ProjectStats,
    pub findings: Vec<FindingBundle>,
    /// Source artifacts that produced evidence-bearing units.
    #[serde(default)]
    pub sources: Vec<SourceRecord>,
    /// Materialized source-grounded evidence units linked to findings.
    #[serde(default)]
    pub evidence_atoms: Vec<EvidenceAtom>,
    /// Materialized condition boundaries used to avoid claim overgeneralization.
    #[serde(default)]
    pub condition_records: Vec<ConditionRecord>,
    /// Append-only log of review events (content-addressed).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub review_events: Vec<ReviewEvent>,
    /// Append-only log of confidence updates.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub confidence_updates: Vec<ConfidenceUpdate>,
    /// Canonical append-only event log for replayable frontier state.
    #[serde(default)]
    pub events: Vec<StateEvent>,
    /// Portable pending/applied proposal records for proposal-first writes.
    #[serde(default)]
    pub proposals: Vec<StateProposal>,
    /// Frontier-local proof freshness projection.
    #[serde(default)]
    pub proof_state: ProofState,
    /// Cryptographic signatures for findings (Ed25519).
    #[serde(default)]
    pub signatures: Vec<SignedEnvelope>,
    /// Registered actor identities, mapping a stable actor.id to an
    /// Ed25519 public key. Phase M (v0.4): once an actor is registered,
    /// any canonical event referencing that actor.id under
    /// `--strict` must carry a verifiable Ed25519 signature.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actors: Vec<ActorRecord>,
    /// Generic content-addressed artifacts: protocols, trial registry
    /// records, supplements, notebooks, source files, and dataset
    /// manifests that need a durable byte or pointer commitment.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<crate::bundle::Artifact>,
    /// v0.213: Released Diff Pack tracking — first-class replay
    /// state for the v0.201 `diff_pack.released` and v0.205
    /// `diff_pack.reviewed` event arms. Prior cycles left these
    /// arms metadata-only (Ok(()) returns); v0.213 makes them
    /// mutate this array so a consumer walking the canonical
    /// event log can answer "which packs have been released on
    /// this frontier?" without reading sibling directories.
    ///
    /// Replay invariant: the array is append-only on
    /// `diff_pack.released` events (idempotent on pack_id) and
    /// updated in place on `diff_pack.reviewed` events. Theorem
    /// 29 pins the accumulation algebra.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub released_diff_packs: Vec<crate::released_diff_pack::ReleasedDiffPackRecord>,
    /// v0.218: Verdict-conflict resolutions on this frontier. The
    /// `verdict_conflict.resolved` reducer arm appends to this
    /// array (idempotent on conflict_id). Theorem 32 pins the
    /// accumulation algebra. Audit-trail semantics: every
    /// resolution stays here, even when a later resolution
    /// supersedes an earlier one — the substrate is honest about
    /// the full disagreement history, not just the latest verdict.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verdict_conflicts: Vec<crate::verdict_conflict::VerdictConflict>,
    /// T7: reviewed Contradiction objects (`vcx_`). Holds only
    /// contradictions a reviewer has acted on (under-review or
    /// adjudicated) — candidates are derived from the graph on demand
    /// and are not canonical state. Latest resolution per id wins;
    /// see `apply_contradiction_resolved`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contradictions: Vec<crate::contradiction::Contradiction>,
    /// verifier attachments bound to findings (target = `vf_…`). Sidecar
    /// collection (not a field on FindingBundle) so finding-state replay
    /// digests are unaffected. Per-finding trust-gate status is DERIVED from
    /// these on read, never stored. See `verifier_attachment`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verifier_attachments: Vec<crate::verifier_attachment::VerifierAttachment>,
    /// Signed banked attempts (`vat_`). Immutable deposits; the verified
    /// status is DERIVED from the gate + attempt_resolutions on read, never
    /// stored. See `apply_attempt_deposited`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attempts: Vec<crate::attempt::Attempt>,
    /// Append-only lifecycle transitions on attempts (`vre_`). Idempotent by
    /// id; the head per attempt is the latest by `at`. See
    /// `apply_attempt_resolved` and `Project::head_resolution`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attempt_resolutions: Vec<crate::attempt::ResolutionEvent>,
    /// Signed cross-domain transfers (`vtr_`). Immutable deposits; admission
    /// (whether the link is sound) is DERIVED via `derive_transfer_status` on
    /// read, never stored. See `apply_transfer_deposited`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transfers: Vec<crate::transfer::Transfer>,
    /// Signed significance endorsements (`ven_`). Stored as individual records,
    /// NEVER aggregated into a score — significance is social and uncomputed by
    /// design. See `apply_endorsement_deposited` and `docs/SIGNIFICANCE_SLOT.md`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endorsements: Vec<crate::endorsement::Endorsement>,
    /// Statement-faithfulness attestations (`vsa_`): signed human
    /// judgments that a formal statement encodes its informal problem.
    /// Events-only storage (the replay loader grafts them).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub statement_attestations: Vec<crate::statement_attestation::StatementAttestation>,
    /// Math-atlas anchor links: signed, retractable `val_` assertions that a
    /// claim carries an external-catalogue anchor (OEIS / Erdős / mathlib / ...).
    /// Events-only storage (the replay loader grafts them); the cross-frontier
    /// identity join reads these. See `crate::anchor`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub anchor_links: Vec<crate::anchor::AnchorLink>,
    /// Active obligation leases (events-only; replay-grafted). Expiry is
    /// computed at read time from claimed_at + ttl.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attempt_claims: Vec<AttemptClaim>,
    /// Priority registrations: content-addressed statement hashes with
    /// their log timestamps (events-only; replay-grafted).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub statement_registrations: Vec<StatementRegistration>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProjectMeta {
    pub name: String,
    pub description: String,
    pub compiled_at: String,
    pub compiler: String,
    pub papers_processed: usize,
    pub errors: usize,
    #[serde(default)]
    pub dependencies: Vec<ProjectDependency>,
}

/// serde `skip_serializing_if` predicate: a zero-valued `usize` stat is
/// omitted so a frontier that predates the field round-trips and
/// snapshot-hashes byte-identically to the pre-field serialization.
/// Without this, adding a stat field silently breaks `registry pull`
/// verification of every frontier published by an older binary.
fn stat_is_zero(n: &usize) -> bool {
    *n == 0
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ProjectStats {
    pub findings: usize,
    pub links: usize,
    pub replicated: usize,
    pub unreplicated: usize,
    pub avg_confidence: f64,
    pub gaps: usize,
    pub negative_space: usize,
    pub contested: usize,
    pub categories: HashMap<String, usize>,
    pub link_types: HashMap<String, usize>,
    pub human_reviewed: usize,
    /// Findings whose review came from an agent/bot actor, counted
    /// separately so `human_reviewed` never overstates human review.
    /// Skipped when zero so frontiers published before this field
    /// existed snapshot-hash identically (registry-pull back-compat).
    #[serde(default, skip_serializing_if = "stat_is_zero")]
    pub agent_reviewed: usize,
    /// Number of review events in this frontier.
    #[serde(default)]
    pub review_event_count: usize,
    /// Number of confidence updates in this frontier.
    #[serde(default)]
    pub confidence_update_count: usize,
    /// Number of canonical state events in this frontier.
    #[serde(default)]
    pub event_count: usize,
    /// Number of source records in the frontier source registry.
    #[serde(default)]
    pub source_count: usize,
    /// Number of materialized evidence atoms in the frontier.
    #[serde(default)]
    pub evidence_atom_count: usize,
    /// Number of materialized condition records in the frontier.
    #[serde(default)]
    pub condition_record_count: usize,
    /// Number of persisted proposals in the frontier.
    #[serde(default)]
    pub proposal_count: usize,
    pub confidence_distribution: ConfidenceDistribution,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ConfidenceDistribution {
    pub high_gt_80: usize,
    pub medium_60_80: usize,
    pub low_lt_60: usize,
}

/// Schema and compiler defaults for the current Vela protocol release.
pub const VELA_SCHEMA_URL: &str = "https://vela.science/schema/finding-bundle/v0.10.0";
pub const VELA_SCHEMA_VERSION: &str = "0.10.0";
pub const VELA_COMPILER_VERSION: &str = concat!("vela/", env!("CARGO_PKG_VERSION"));

/// Derive a `vfr_<hash>` frontier ID from frontier metadata. Used as a
/// fallback for legacy frontiers without a `frontier.created` genesis
/// event; v0.4+ frontiers derive from the genesis event itself via
/// `frontier_id_from_genesis`.
#[must_use]
pub fn derive_frontier_id_from_meta(meta: &ProjectMeta) -> String {
    let preimage = serde_json::json!({
        "name": meta.name,
        "compiled_at": meta.compiled_at,
        "compiler": meta.compiler,
    });
    let bytes = crate::canonical::to_canonical_bytes(&preimage).unwrap_or_default();
    use sha2::{Digest, Sha256};
    format!("vfr_{}", &hex::encode(Sha256::digest(bytes))[..16])
}

/// Derive a `vfr_<hash>` frontier ID from the canonical hash of the
/// `frontier.created` genesis event. Returns `None` if `events[0]` is
/// absent or not a `frontier.created` event (legacy frontiers fall back
/// to meta-derivation via `derive_frontier_id_from_meta`).
///
/// The preimage shape matches `event_id` exactly so the same canonical
/// rule produces both the event's `vev_…` and the frontier's `vfr_…`
/// from the same logical content. Doctrine line: a frontier IS what the
/// `frontier.created` event creates.
#[must_use]
pub fn frontier_id_from_genesis(events: &[crate::events::StateEvent]) -> Option<String> {
    let genesis = events.first()?;
    if genesis.kind != "frontier.created" {
        return None;
    }
    let preimage = serde_json::json!({
        "schema": genesis.schema,
        "kind": genesis.kind,
        "target": genesis.target,
        "actor": genesis.actor,
        "timestamp": genesis.timestamp,
        "reason": genesis.reason,
        "before_hash": genesis.before_hash,
        "after_hash": genesis.after_hash,
        "payload": genesis.payload,
        "caveats": genesis.caveats,
    });
    let bytes = crate::canonical::to_canonical_bytes(&preimage).ok()?;
    use sha2::{Digest, Sha256};
    Some(format!("vfr_{}", &hex::encode(Sha256::digest(bytes))[..16]))
}

/// Construct the `frontier.created` canonical event for a freshly
/// compiled frontier. The event becomes `events[0]` and the frontier_id
/// derives from its canonical hash.
///
/// Targets `frontier:<name>` (not `finding:…`) so replay's orphan-target
/// detection does not flag it; the genesis event carries identity, not a
/// finding mutation.
fn build_genesis_event(name: &str, compiled_at: &str, creator: &str) -> crate::events::StateEvent {
    use crate::events::{EVENT_SCHEMA, NULL_HASH, StateActor, StateEvent, StateTarget};
    let mut event = StateEvent {
        schema: EVENT_SCHEMA.to_string(),
        id: String::new(),
        kind: "frontier.created".into(),
        target: StateTarget {
            r#type: "frontier".to_string(),
            id: name.to_string(),
        },
        actor: StateActor {
            id: creator.to_string(),
            r#type: "frontier".to_string(),
        },
        timestamp: compiled_at.to_string(),
        reason: "frontier compiled".to_string(),
        before_hash: NULL_HASH.to_string(),
        after_hash: NULL_HASH.to_string(),
        payload: serde_json::json!({
            "name": name,
            "creator": creator,
            "schema_version": VELA_SCHEMA_VERSION,
            "compiled_at": compiled_at,
        }),
        caveats: vec![],
        signature: None,
        schema_artifact_id: None,
    };
    event.id = crate::events::compute_event_id(&event);
    event
}

pub fn assemble(
    name: &str,
    bundles: Vec<FindingBundle>,
    papers_processed: usize,
    errors: usize,
    description: &str,
) -> Project {
    let compiled_at = Utc::now().to_rfc3339();
    let meta = ProjectMeta {
        name: name.to_string(),
        description: description.to_string(),
        compiled_at: compiled_at.clone(),
        compiler: VELA_COMPILER_VERSION.to_string(),
        papers_processed,
        errors,
        dependencies: Vec::new(),
    };
    // Phase J (v0.4): emit a `frontier.created` canonical event as
    // events[0] and derive frontier_id from its canonical hash. The
    // address primitive becomes doctrine-grounded — a frontier IS what
    // the genesis event creates, not a convenience over its metadata.
    let genesis = build_genesis_event(name, &compiled_at, VELA_COMPILER_VERSION);
    let frontier_id = frontier_id_from_genesis(std::slice::from_ref(&genesis));
    let mut project = Project {
        vela_version: VELA_SCHEMA_VERSION.to_string(),
        schema: VELA_SCHEMA_URL.to_string(),
        frontier_id,
        project: meta,
        stats: ProjectStats::default(),
        findings: bundles,
        sources: Vec::new(),
        evidence_atoms: Vec::new(),
        condition_records: Vec::new(),
        review_events: Vec::new(),
        confidence_updates: Vec::new(),
        events: vec![genesis],
        proposals: Vec::new(),
        proof_state: ProofState::default(),
        signatures: Vec::new(),
        actors: Vec::new(),
        artifacts: Vec::new(),
        released_diff_packs: Vec::new(),
        verdict_conflicts: Vec::new(),
        contradictions: Vec::new(),
        verifier_attachments: Vec::new(),
        attempts: Vec::new(),
        attempt_resolutions: Vec::new(),
        transfers: Vec::new(),
        endorsements: Vec::new(),
        statement_attestations: Vec::new(),
        anchor_links: Vec::new(),
        attempt_claims: Vec::new(),
        statement_registrations: Vec::new(),
    };
    crate::sources::materialize_project(&mut project);
    project
}

impl Project {
    /// The head (latest by `at`) lifecycle resolution for an attempt, or
    /// `None` if the attempt is still an unresolved candidate. Computed on
    /// read from the append-only `attempt_resolutions`, never stored.
    #[must_use]
    pub fn head_resolution(&self, attempt_id: &str) -> Option<&crate::attempt::ResolutionEvent> {
        self.attempt_resolutions
            .iter()
            .filter(|r| r.attempt_id == attempt_id)
            .max_by(|a, b| a.at.cmp(&b.at))
    }

    /// Return the stable Vela-addressable frontier ID. Prefers the stored
    /// field; if absent, derives from the `frontier.created` genesis
    /// event in `events[0]`; if no genesis event is present, falls back
    /// to meta-derivation (legacy v0.3 frontiers).
    #[must_use]
    pub fn frontier_id(&self) -> String {
        if let Some(id) = self.frontier_id.clone() {
            return id;
        }
        if let Some(id) = frontier_id_from_genesis(&self.events) {
            return id;
        }
        derive_frontier_id_from_meta(&self.project)
    }

    /// v0.8: iterate the cross-frontier dependencies (those with
    /// `vfr_id` set). Pre-v0.8 compile-time deps without `vfr_id`
    /// are filtered out.
    pub fn cross_frontier_deps(&self) -> impl Iterator<Item = &ProjectDependency> {
        self.project
            .dependencies
            .iter()
            .filter(|d| d.is_cross_frontier())
    }

    /// v0.8: look up the dependency record for a specific `vfr_id`.
    /// Returns `None` if no matching cross-frontier dep is declared.
    pub fn dep_for_vfr(&self, vfr_id: &str) -> Option<&ProjectDependency> {
        self.cross_frontier_deps()
            .find(|d| d.vfr_id.as_deref() == Some(vfr_id))
    }

    /// v0.49.3: build a reverse-dependency index from the forward
    /// `links: Vec<Link>` data on each finding. The forward direction
    /// (which findings does this finding depend on?) is O(1) per
    /// finding because it's just `f.links`. The reverse direction
    /// (which findings depend on this finding?) previously required
    /// scanning every finding for every query — O(N×L). This index
    /// flips that to O(1) lookup once built.
    ///
    /// Cost to build: O(N×L) one-time scan over all findings × links.
    /// At 48 findings × ~3 links each (the legacy BBB proof fixture),
    /// that's ~150 hash-insert operations and microseconds. At
    /// 100K findings × 10 links, it's still well under a second.
    ///
    /// Used by retraction-impact queries (serve.rs), cascade
    /// computation, and any consumer that needs to walk the dependent
    /// graph rather than the dependency graph. The index is not
    /// serialized — it's a derived structure that callers build when
    /// they need it and drop when they don't.
    #[must_use]
    pub fn build_reverse_dep_index(&self) -> ReverseDepIndex {
        let mut map: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::with_capacity(self.findings.len());
        for f in &self.findings {
            for link in &f.links {
                map.entry(link.target.clone())
                    .or_default()
                    .push(f.id.clone());
            }
        }
        // Stable sort each dependent list so two implementations of the
        // index agree on ordering for any downstream serialization.
        for v in map.values_mut() {
            v.sort();
            v.dedup();
        }
        ReverseDepIndex { map }
    }
}

/// v0.49.3: reverse-dependency index built from a Project's forward
/// `links` graph. Maps `finding_id → [dependent_finding_id, …]` so a
/// "what depends on X?" lookup is O(1) instead of O(N×L).
///
/// Construct via `Project::build_reverse_dep_index`. The index is a
/// snapshot — it does not auto-update if the Project mutates after.
/// For long-lived consumers that mutate state, rebuild after each
/// reduce step.
#[derive(Debug, Clone, Default)]
pub struct ReverseDepIndex {
    map: std::collections::HashMap<String, Vec<String>>,
}

impl ReverseDepIndex {
    /// Findings whose forward `links` list a target with this id.
    /// Empty slice if nothing depends on this finding (or if the id
    /// isn't in the index at all).
    #[must_use]
    pub fn dependents_of(&self, finding_id: &str) -> &[String] {
        self.map
            .get(finding_id)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Total number of dependent edges in the index. Useful for
    /// quick sanity checks and metric reporting.
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.map.values().map(Vec::len).sum()
    }

    /// Number of distinct findings that have at least one dependent.
    #[must_use]
    pub fn target_count(&self) -> usize {
        self.map.len()
    }

    /// Iterate `(target_finding_id, dependents)` pairs. Order is
    /// HashMap-iteration-order, not stable across runs; sort if a
    /// consumer needs determinism.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &Vec<String>)> {
        self.map.iter()
    }
}

#[cfg(test)]
mod cross_frontier_dep_tests {
    use super::*;

    fn dep_local(name: &str) -> ProjectDependency {
        ProjectDependency {
            name: name.into(),
            source: "local".into(),
            version: None,
            pinned_hash: None,
            vfr_id: None,
            locator: None,
            pinned_snapshot_hash: None,
        }
    }

    fn dep_cross(vfr: &str) -> ProjectDependency {
        ProjectDependency {
            name: "ext".into(),
            source: "vela.hub".into(),
            version: None,
            pinned_hash: None,
            vfr_id: Some(vfr.into()),
            locator: Some(format!("https://example.test/{vfr}.json")),
            pinned_snapshot_hash: Some("a".repeat(64)),
        }
    }

    #[test]
    fn is_cross_frontier_only_when_vfr_id_set() {
        assert!(!dep_local("x").is_cross_frontier());
        assert!(dep_cross("vfr_abc").is_cross_frontier());
    }

    #[test]
    fn dep_serializes_byte_identical_when_v0_8_fields_absent() {
        // Backward compat: a pre-v0.8 dep round-trips through serde
        // without emitting any of the new optional v0.8 fields.
        let d = dep_local("legacy");
        let s = serde_json::to_string(&d).unwrap();
        assert!(!s.contains("vfr_id"));
        assert!(!s.contains("locator"));
        assert!(!s.contains("pinned_snapshot_hash"));
    }
}

#[cfg(test)]
pub(crate) mod reverse_dep_index_tests {
    use super::*;
    use crate::bundle::{
        Assertion, Author, Conditions, Confidence, ConfidenceKind, ConfidenceMethod, Evidence,
        Extraction, FindingBundle, Flags, Link, Provenance,
    };

    pub(crate) fn synth_finding(idx: usize, links: Vec<Link>) -> FindingBundle {
        let assertion = Assertion {
            text: format!("Synthetic finding {idx}"),
            assertion_type: "mechanism".into(),
            entities: vec![],
            relation: None,
            direction: None,
            causal_claim: None,
            causal_evidence_grade: None,
        };
        let evidence = Evidence {
            evidence_type: "experimental".into(),
            model_system: "test".into(),
            method: "test".into(),
            replicated: false,
            replication_count: None,
            evidence_spans: vec![],
        };
        let conditions = Conditions {
            text: "test".into(),
            duration: None,
        };
        let confidence = Confidence {
            kind: ConfidenceKind::FrontierEpistemic,
            score: 0.5,
            basis: "test".into(),
            method: ConfidenceMethod::LlmInitial,
            components: None,
            extraction_confidence: 0.9,
        };
        let provenance = Provenance {
            source_type: "published_paper".into(),
            doi: Some(format!("10.0000/reverse-dep-index-test.{idx:04}")),
            url: None,
            title: format!("Synthetic test paper {idx}"),
            authors: vec![Author {
                name: "T".into(),
                orcid: None,
            }],
            year: None,
            license: None,
            publisher: None,
            funders: vec![],
            extraction: Extraction::default(),
            review: None,
        };
        let flags = Flags::default();
        let mut bundle = FindingBundle::new(
            assertion, evidence, conditions, confidence, provenance, flags,
        );
        bundle.links = links;
        bundle
    }

    pub(crate) fn link_to(target: &str) -> Link {
        Link {
            target: target.into(),
            link_type: "supports".into(),
            note: "test".into(),
            inferred_by: "test".into(),
            created_at: "2026-05-02T00:00:00Z".into(),
            mechanism: None,
        }
    }

    /// Build a chain: 0 → 1 → 2 → 3 (each finding supports the next).
    /// Then dependents_of(2) should return [1], dependents_of(1) → [0],
    /// dependents_of(3) → [2], dependents_of(0) → [] (root, nothing
    /// depends on it).
    #[test]
    fn dependents_of_returns_correct_set_for_simple_chain() {
        let f3 = synth_finding(3, vec![]);
        let f2 = synth_finding(2, vec![link_to(&f3.id)]);
        let f1 = synth_finding(1, vec![link_to(&f2.id)]);
        let f0 = synth_finding(0, vec![link_to(&f1.id)]);

        let mut project = assemble("chain", vec![], 0, 0, "test");
        project.findings = vec![f0.clone(), f1.clone(), f2.clone(), f3.clone()];

        let idx = project.build_reverse_dep_index();
        assert_eq!(idx.dependents_of(&f3.id), &[f2.id.clone()]);
        assert_eq!(idx.dependents_of(&f2.id), &[f1.id.clone()]);
        assert_eq!(idx.dependents_of(&f1.id), &[f0.id.clone()]);
        assert!(idx.dependents_of(&f0.id).is_empty());
        // Edge count = 3 (one per non-root link).
        assert_eq!(idx.edge_count(), 3);
        // Target count = 3 (f1, f2, f3 each have a dependent).
        assert_eq!(idx.target_count(), 3);
    }

    /// Multiple findings depending on the same target should produce a
    /// sorted, deduped dependent list.
    #[test]
    fn dependents_of_dedups_and_sorts() {
        let target = synth_finding(99, vec![]);
        let target_id = target.id.clone();
        // f1, f2, f3 all link to target. Plus f1 has TWO links to
        // target (to test dedup).
        let f1 = synth_finding(1, vec![link_to(&target_id), link_to(&target_id)]);
        let f2 = synth_finding(2, vec![link_to(&target_id)]);
        let f3 = synth_finding(3, vec![link_to(&target_id)]);

        let mut project = assemble("multi-dependents", vec![], 0, 0, "test");
        project.findings = vec![target, f1.clone(), f2.clone(), f3.clone()];

        let idx = project.build_reverse_dep_index();
        let mut expected = vec![f1.id.clone(), f2.id.clone(), f3.id.clone()];
        expected.sort();
        assert_eq!(idx.dependents_of(&target_id), expected.as_slice());
    }

    /// A finding id with no dependents — and an id that doesn't exist
    /// in the project at all — both return an empty slice.
    #[test]
    fn dependents_of_unknown_or_orphan_returns_empty() {
        let lonely = synth_finding(7, vec![]);
        let mut project = assemble("orphan", vec![], 0, 0, "test");
        project.findings = vec![lonely.clone()];

        let idx = project.build_reverse_dep_index();
        assert!(idx.dependents_of(&lonely.id).is_empty());
        assert!(idx.dependents_of("vf_does_not_exist").is_empty());
    }

    /// Empty project → empty index.
    #[test]
    fn empty_project_yields_empty_index() {
        let project = assemble("empty", vec![], 0, 0, "test");
        let idx = project.build_reverse_dep_index();
        assert_eq!(idx.edge_count(), 0);
        assert_eq!(idx.target_count(), 0);
    }
}

/// Recompute derived frontier statistics after mechanical edits.
pub fn recompute_stats(project: &mut Project) {
    let total_links: usize = project.findings.iter().map(|b| b.links.len()).sum();

    let mut link_types: HashMap<String, usize> = HashMap::new();
    for b in &project.findings {
        for l in &b.links {
            *link_types.entry(l.link_type.clone()).or_default() += 1;
        }
    }

    let mut categories: HashMap<String, usize> = HashMap::new();
    for b in &project.findings {
        *categories
            .entry(b.assertion.assertion_type.clone())
            .or_default() += 1;
    }

    // Count findings with a successful replication, read from the
    // scalar `evidence.replicated` field.
    let replicated = project
        .findings
        .iter()
        .filter(|b| b.evidence.replicated)
        .count();
    let avg_confidence = if project.findings.is_empty() {
        0.0
    } else {
        (project
            .findings
            .iter()
            .map(|b| b.confidence.score)
            .sum::<f64>()
            / project.findings.len() as f64
            * 1000.0)
            .round()
            / 1000.0
    };

    project.stats.findings = project.findings.len();
    project.stats.links = total_links;
    project.stats.replicated = replicated;
    project.stats.unreplicated = project.findings.len().saturating_sub(replicated);
    project.stats.avg_confidence = avg_confidence;
    project.stats.gaps = project.findings.iter().filter(|b| b.flags.gap).count();
    project.stats.negative_space = project
        .findings
        .iter()
        .filter(|b| b.flags.negative_space)
        .count();
    project.stats.contested = project
        .findings
        .iter()
        .filter(|b| b.flags.contested)
        .count();
    project.stats.categories = categories;
    project.stats.link_types = link_types;
    // Provenance honesty: a finding is human-reviewed only if a
    // human-classified actor reviewed it. Agent/bot review is counted
    // separately so `human_reviewed` never overstates human review
    // (an `agent:`/`-bot` reviewer used to inflate this count).
    let finding_ids: HashSet<&str> = project.findings.iter().map(|b| b.id.as_str()).collect();
    let mut human_reviewed_ids: HashSet<String> = HashSet::new();
    let mut agent_reviewed_ids: HashSet<String> = HashSet::new();
    for b in &project.findings {
        if let Some(r) = b.provenance.review.as_ref().filter(|r| r.reviewed) {
            let kind = r
                .reviewer
                .as_deref()
                .map(crate::events::actor_kind)
                .unwrap_or("human");
            if kind == "human" {
                human_reviewed_ids.insert(b.id.clone());
            } else {
                agent_reviewed_ids.insert(b.id.clone());
            }
        }
    }
    for event in project.events.iter().filter(|event| {
        matches!(
            event.kind.as_str(),
            "finding.reviewed"
                | "finding.noted"
                | "finding.caveated"
                | "finding.confidence_revised"
                | "finding.rejected"
                | "finding.retracted"
        ) && finding_ids.contains(event.target.id.as_str())
    }) {
        if crate::events::actor_kind(&event.actor.id) == "human" {
            human_reviewed_ids.insert(event.target.id.clone());
        } else {
            agent_reviewed_ids.insert(event.target.id.clone());
        }
    }
    // Disjoint: a finding with any human review is human-reviewed; one
    // touched only by agents is agent-reviewed.
    let agent_only = agent_reviewed_ids.difference(&human_reviewed_ids).count();
    project.stats.human_reviewed = human_reviewed_ids.len();
    project.stats.agent_reviewed = agent_only;
    let canonical_review_events = project
        .events
        .iter()
        .filter(|event| {
            matches!(
                event.kind.as_str(),
                "finding.reviewed"
                    | "finding.noted"
                    | "finding.caveated"
                    | "finding.rejected"
                    | "finding.retracted"
                    | "finding.asserted"
                    | "source_text.reviewed"
            )
        })
        .count();
    project.stats.review_event_count = canonical_review_events + project.review_events.len();
    project.stats.confidence_update_count = project
        .events
        .iter()
        .filter(|event| event.kind == "finding.confidence_revised")
        .count()
        + project.confidence_updates.len();
    project.stats.event_count = project.events.len();
    project.stats.source_count = project.sources.len();
    project.stats.evidence_atom_count = project.evidence_atoms.len();
    project.stats.condition_record_count = project.condition_records.len();
    project.stats.proposal_count = project.proposals.len();
    project.stats.confidence_distribution = ConfidenceDistribution {
        high_gt_80: project
            .findings
            .iter()
            .filter(|b| b.confidence.score > 0.8)
            .count(),
        medium_60_80: project
            .findings
            .iter()
            .filter(|b| (0.6..=0.8).contains(&b.confidence.score))
            .count(),
        low_lt_60: project
            .findings
            .iter()
            .filter(|b| b.confidence.score < 0.6)
            .count(),
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::*;

    fn make_finding(
        id: &str,
        score: f64,
        assertion_type: &str,
        replicated: bool,
        gap: bool,
    ) -> FindingBundle {
        FindingBundle {
            id: id.into(),
            version: 1,
            previous_version: None,
            assertion: Assertion {
                text: format!("Finding {id}"),
                assertion_type: assertion_type.into(),
                entities: vec![],
                relation: None,
                direction: None,
                causal_claim: None,
                causal_evidence_grade: None,
            },
            evidence: Evidence {
                evidence_type: "experimental".into(),
                model_system: String::new(),
                method: String::new(),
                replicated,
                replication_count: None,
                evidence_spans: vec![],
            },
            conditions: Conditions {
                text: String::new(),
                duration: None,
            },
            confidence: Confidence::raw(score, "seeded prior", 0.85),
            provenance: Provenance {
                source_type: "published_paper".into(),
                doi: None,
                url: None,
                title: "Test".into(),
                authors: vec![],
                year: Some(2024),
                license: None,
                publisher: None,
                funders: vec![],
                extraction: Extraction::default(),
                review: None,
            },
            flags: Flags {
                gap,
                negative_space: false,
                contested: false,
                retracted: false,
                declining: false,
                gravity_well: false,
                review_state: None,
                superseded: false,
                signature_threshold: None,
                jointly_accepted: false,
            },
            links: vec![],
            annotations: vec![],
            attachments: vec![],
            created: String::new(),
            updated: None,

            access_tier: crate::access_tier::AccessTier::Public,
        }
    }

    #[test]
    fn empty_frontier() {
        let c = assemble("test", vec![], 0, 0, "empty");
        assert_eq!(c.stats.findings, 0);
        assert_eq!(c.stats.links, 0);
        assert_eq!(c.stats.avg_confidence, 0.0);
        assert_eq!(c.stats.replicated, 0);
        assert_eq!(c.stats.unreplicated, 0);
        assert_eq!(c.project.name, "test");
        assert_eq!(c.project.description, "empty");
    }

    #[test]
    fn findings_count() {
        let bundles = vec![
            make_finding("f1", 0.8, "mechanism", false, false),
            make_finding("f2", 0.6, "therapeutic", true, false),
            make_finding("f3", 0.9, "mechanism", false, true),
        ];
        let c = assemble("test", bundles, 5, 1, "desc");
        assert_eq!(c.stats.findings, 3);
        assert_eq!(c.project.papers_processed, 5);
        assert_eq!(c.project.errors, 1);
    }

    #[test]
    fn replicated_unreplicated_counts() {
        let bundles = vec![
            make_finding("f1", 0.8, "mechanism", true, false),
            make_finding("f2", 0.6, "mechanism", true, false),
            make_finding("f3", 0.9, "mechanism", false, false),
        ];
        let c = assemble("test", bundles, 3, 0, "desc");
        assert_eq!(c.stats.replicated, 2);
        assert_eq!(c.stats.unreplicated, 1);
    }

    #[test]
    fn category_counts() {
        let bundles = vec![
            make_finding("f1", 0.8, "mechanism", false, false),
            make_finding("f2", 0.6, "mechanism", false, false),
            make_finding("f3", 0.9, "therapeutic", false, false),
        ];
        let c = assemble("test", bundles, 3, 0, "desc");
        assert_eq!(*c.stats.categories.get("mechanism").unwrap(), 2);
        assert_eq!(*c.stats.categories.get("therapeutic").unwrap(), 1);
    }

    #[test]
    fn link_counting() {
        let mut f1 = make_finding("f1", 0.8, "mechanism", false, false);
        f1.add_link("f2", "extends", "shared entity");
        f1.add_link("f3", "contradicts", "opposite direction");
        let f2 = make_finding("f2", 0.7, "mechanism", false, false);
        let c = assemble("test", vec![f1, f2], 2, 0, "desc");
        assert_eq!(c.stats.links, 2);
        assert_eq!(*c.stats.link_types.get("extends").unwrap(), 1);
        assert_eq!(*c.stats.link_types.get("contradicts").unwrap(), 1);
    }

    #[test]
    fn avg_confidence() {
        let bundles = vec![
            make_finding("f1", 0.8, "mechanism", false, false),
            make_finding("f2", 0.6, "mechanism", false, false),
        ];
        let c = assemble("test", bundles, 2, 0, "desc");
        assert!((c.stats.avg_confidence - 0.7).abs() < 0.01);
    }

    #[test]
    fn confidence_distribution_buckets() {
        let bundles = vec![
            make_finding("f1", 0.9, "mechanism", false, false), // high
            make_finding("f2", 0.85, "mechanism", false, false), // high
            make_finding("f3", 0.7, "mechanism", false, false), // medium
            make_finding("f4", 0.6, "mechanism", false, false), // medium (0.6 is in 0.6..=0.8)
            make_finding("f5", 0.4, "mechanism", false, false), // low
        ];
        let c = assemble("test", bundles, 5, 0, "desc");
        assert_eq!(c.stats.confidence_distribution.high_gt_80, 2);
        assert_eq!(c.stats.confidence_distribution.medium_60_80, 2);
        assert_eq!(c.stats.confidence_distribution.low_lt_60, 1);
    }

    #[test]
    fn gaps_counted() {
        let bundles = vec![
            make_finding("f1", 0.8, "mechanism", false, true),
            make_finding("f2", 0.6, "mechanism", false, false),
            make_finding("f3", 0.9, "mechanism", false, true),
        ];
        let c = assemble("test", bundles, 3, 0, "desc");
        assert_eq!(c.stats.gaps, 2);
    }

    #[test]
    fn metadata_preserved() {
        let c = assemble("my frontier", vec![], 10, 2, "A description");
        assert_eq!(c.project.name, "my frontier");
        assert_eq!(c.project.description, "A description");
        assert_eq!(c.project.papers_processed, 10);
        assert_eq!(c.project.errors, 2);
        assert_eq!(c.vela_version, VELA_SCHEMA_VERSION);
        assert!(!c.project.compiled_at.is_empty());
    }
}

/// An active (or expired — expiry is a read-time computation) lease on
/// an open obligation. One live lease per obligation; the reducer
/// rejects a second claim while a prior one is unexpired.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AttemptClaim {
    pub obligation_id: String,
    pub claimant_actor: String,
    pub claimant_pubkey: String,
    pub claimed_at: String,
    pub lease_ttl_seconds: u64,
}

/// A registered statement hash: the priority timestamp primitive.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct StatementRegistration {
    pub statement_hash: String,
    pub informal_ref: String,
    pub registered_by: String,
    pub registered_at: String,
    /// The canonical finding-to-registration edge (STATE_PLANE_MEMO
    /// appendix gap 5): the `vf_` id this registration timestamps, when
    /// the registrant declared one. Carried as an optional payload
    /// field on the existing `statement.registered` kind — old events
    /// (and old serialized state) parse unchanged via the serde
    /// default; `None` serializes to nothing, so pre-edge state stays
    /// byte-identical.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finding_id: Option<String>,
}
