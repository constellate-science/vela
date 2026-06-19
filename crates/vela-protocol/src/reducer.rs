//! Pure separable reducer over canonical events.
//!
//! `apply_event` is the deterministic state-transition function: given a
//! `Project` and a `StateEvent`, it produces the next `Project`. It does
//! not construct events, validate proposals, or call into network code.
//! It is the inverse pole of `proposals::apply_proposal`, which prepares
//! an event from a proposal and a current state.
//!
//! Why this matters: v0 doctrine says "proposal → canonical event →
//! reducer → replayable frontier state." Until v0.3, the reducer step was
//! implicit inside `apply_proposal` — replay was hash-walking, not
//! reduction. Phase C of the v0.3 focusing run pulls the reducer out so a
//! second implementation can independently reduce a canonical event log
//! and produce byte-identical state.
//!
//! Replay verification (`replay_from_genesis` + `verify_replay`) is the
//! check that turns "state was claimed to result from these events" into
//! "state demonstrably results from these events when re-derived from
//! scratch."

use std::collections::HashMap;

use serde_json::Value;

use crate::bundle::{Annotation, ConfidenceMethod};
use crate::events::{self, EventKind, StateEvent};
use crate::project::{self, Project};

/// v0.105: per-replay finding-id index. Keys are content-addressed
/// finding ids; values are positions into `state.findings`. Replay
/// builds this once from genesis state and updates it in lockstep
/// with `finding.asserted` pushes. Per-kind apply functions look up
/// their target via `idx.get(...)` instead of an O(N) linear scan.
/// findings are append-only in the substrate (no removals), so the
/// index never goes stale; positions remain valid for the life of
/// a replay.
pub type FindingIndex = HashMap<String, usize>;

/// Build the finding-id index from the current state. O(N) once.
#[must_use]
pub fn build_finding_index(state: &Project) -> FindingIndex {
    state
        .findings
        .iter()
        .enumerate()
        .map(|(i, f)| (f.id.clone(), i))
        .collect()
}

/// Single source of truth for the event kinds whose mutations the
/// reducer enforces. The no-op anchor `frontier.created` is excluded
/// because it does not mutate state. Used by:
///   - the dispatch table in `apply_event` (validated by
///     `dispatch_handles_every_declared_kind` below)
///   - the cross-implementation fixture coverage assertion in
///     `crates/vela-protocol/tests/cross_impl_reducer_fixtures.rs`
///
/// If you add a new reducer arm, add it here too. CI will fail if the
/// dispatch table and this constant disagree, and the cross-impl
/// fixture coverage test will fail if the new kind isn't exercised by
/// at least one fixture builder. The hand-maintained mirror is gone.
pub const REDUCER_MUTATION_KINDS: &[&str] = &[
    "finding.asserted",
    "finding.reviewed",
    "finding.noted",
    "finding.caveated",
    "finding.confidence_revised",
    "finding.rejected",
    "finding.retracted",
    "finding.dependency_invalidated",
    // Generic artifacts: protocol files, trial registry records, source
    // files, notebooks, and other byte or pointer commitments.
    "artifact.asserted",
    "artifact.reviewed",
    "artifact.retracted",
    // v0.51: tier.set re-classifies the access_tier on a finding
    // or artifact. Mutates the matched object's
    // access_tier field. Replay reproduces the current tier from the
    // canonical event log alone, no out-of-band classification
    // table.
    "tier.set",
    // v0.56: evidence_atom.locator_repaired sets `locator` on a single
    // evidence atom and clears the "missing evidence locator" caveat.
    // Mutates `state.evidence_atoms[i].locator` only. Cross-impl
    // reducer fixtures whose post-replay digest covers `findings[]`
    // only treat this as a no-op on finding state. The Rust reducer
    // still has an explicit arm because skipping unknown kinds would
    // silently drop the repair from a fresh replay.
    "evidence_atom.locator_repaired",
    // v0.57: finding.span_repaired appends one `{section, text}` span
    // to `state.findings[i].evidence.evidence_spans`. Idempotent under
    // identical re-application (refuses to append an equal span twice).
    "finding.span_repaired",
    // v0.213: Released Diff Pack tracking. Both arms mutate
    // `state.released_diff_packs`:
    //   * `diff_pack.released` appends a new ReleasedDiffPackRecord
    //     (idempotent on pack_id).
    //   * `diff_pack.reviewed` updates the matching record's verdict
    //     + verdict_event_id + applied_members + sdk_only_members.
    "diff_pack.released",
    "diff_pack.reviewed",
    // v0.218: Verdict Conflict Resolution. Appends a VerdictConflict
    // to state.verdict_conflicts (idempotent on conflict_id). T32
    // pins the accumulation algebra.
    "verdict_conflict.resolved",
    // T7: a reviewer's decision on a Contradiction object. Upserts the
    // resolved Contradiction into state.contradictions (latest per id).
    "contradiction.resolved",
    // Supersession flips `flags.superseded` on the *old* finding (the
    // replacement enters via genesis seeding from the accepted proposal's
    // payload — the event itself is thin).
    "finding.superseded",
    // Causal re-grading replays `assertion.causal_claim` /
    // `causal_evidence_grade` from the event's `payload.after`.
    "assertion.reinterpreted_causal",
    // Statement-faithfulness attestation: upserts a signed vsa_ record
    // into state.statement_attestations (idempotent by id; the record's
    // own Ed25519 signature is re-verified on apply).
    "statement.attested",
    // Obligation lease: one live lease per obligation; a second claim
    // while a prior is unexpired is a reducer error. Expiry is computed
    // against the NEW event's timestamp (the log's own clock), never
    // wall time — replay stays deterministic.
    "attempt.claimed",
    // Priority registration: append a content-addressed statement hash
    // (idempotent on hash).
    "statement.registered",
    // Math-atlas anchor link: upsert/remove a signed val_ record into
    // state.anchor_links (idempotent by id; signature re-verified on apply).
    "anchor.attached",
    "anchor.retracted",
];

/// Apply one canonical event to `state`, mutating it in place.
///
/// The function dispatches on `event.kind` and performs the same
/// mutations that `proposals::apply_*` performs when constructing the
/// event. Two implementations of the reducer must therefore agree on the
/// mutation rules per kind. Those rules are documented in
/// `docs/PROTOCOL.md` §6 and pinned via canonical hashing.
pub fn apply_event(state: &mut Project, event: &StateEvent) -> Result<(), String> {
    let mut idx = build_finding_index(state);
    apply_event_indexed(state, event, &mut idx)
}

/// v0.105: indexed dispatch. Used by `replay_from_genesis` so the
/// finding-id index gets built once and reused across every event.
/// `apply_event` builds the index lazily for one-off callers.
pub fn apply_event_indexed(
    state: &mut Project,
    event: &StateEvent,
    idx: &mut FindingIndex,
) -> Result<(), String> {
    match &event.kind {
        // Phase J: `frontier.created` is the genesis event. It carries
        // identity (its canonical hash IS the frontier_id) but does not
        // mutate finding state. Replay treats it as a structural
        // anchor — the chain begins here.
        EventKind::FrontierCreated => Ok(()),
        EventKind::FindingAsserted => apply_finding_asserted(state, event, idx),
        EventKind::FindingReviewed => apply_finding_reviewed(state, event, idx),
        EventKind::FindingNoted => apply_finding_annotation(state, event, "noted", idx),
        EventKind::FindingCaveated => apply_finding_annotation(state, event, "caveated", idx),
        EventKind::SourceTextReviewed => Ok(()),
        EventKind::FindingConfidenceRevised => apply_finding_confidence_revised(state, event, idx),
        EventKind::FindingRejected => apply_finding_rejected(state, event, idx),
        EventKind::FindingRetracted => apply_finding_retracted(state, event, idx),
        // Phase L: per-dependent cascade event. Replay marks the
        // dependent as contested and records the upstream chain in an
        // annotation so a fresh reduce reproduces the post-cascade
        // state without re-running the propagator.
        EventKind::FindingDependencyInvalidated => apply_finding_dependency_invalidated(state, event, idx),
        EventKind::ArtifactAsserted => apply_artifact_asserted(state, event),
        EventKind::VerifierAttachmentAdded => apply_verifier_attachment_added(state, event),
        EventKind::ArtifactReviewed => apply_artifact_reviewed(state, event),
        EventKind::ArtifactRetracted => apply_artifact_retracted(state, event),
        // v0.51: tier re-classification.
        EventKind::TierSet => apply_tier_set(state, event),
        // v0.56: mechanical evidence-atom locator repair.
        EventKind::EvidenceAtomLocatorRepaired => apply_evidence_atom_locator_repaired(state, event),
        // v0.57: mechanical finding-level span repair.
        EventKind::FindingSpanRepaired => apply_finding_span_repaired(state, event, idx),
        // v0.79.4: per-event attestation. No-op on findings;
        // attestations live as append-only canonical events
        // pointing at a target event id.
        EventKind::AttestationRecorded => Ok(()),
        // v0.201: a `vsd_*` Scientific Diff Pack was signed, applied,
        // and is now federated. The event is a metadata-only handle —
        // its payload references the pack id; replay does not mutate
        // project state because the pack's member proposals already
        // applied through their own `proposal.accepted` arms. The arm
        // exists so the event is a first-class federation handle that
        // hubs can index by `vsd_*`.
        EventKind::DiffPackReleased => apply_diff_pack_released(state, event),
        // v0.205: a reviewer issued a verdict on a `vsd_*` Diff Pack.
        // The event payload carries (pack_id, verdict, reviewer_actor,
        // reason). Like `diff_pack.released`, this arm is metadata-
        // only — member proposals mutate state through their own
        // existing acceptance paths (proposals.rs). The arm exists
        // so the verdict is a first-class canonical event the log
        // pins. Theorem 26 (Diff Pack verdict atomicity) pins the
        // promoter-side guarantee that accept either applies every
        // member or none.
        EventKind::DiffPackReviewed => apply_diff_pack_reviewed(state, event),
        // v0.218: a verdict-conflict resolution lands on the log.
        // Append the VerdictConflict record to state.verdict_conflicts
        // (idempotent on conflict_id).
        EventKind::VerdictConflictResolved => apply_verdict_conflict_resolved(state, event),
        // T7: a contradiction resolution lands on the log. Upsert the
        // resolved Contradiction into state.contradictions by id.
        EventKind::ContradictionResolved => apply_contradiction_resolved(state, event),
        // Attempt lifecycle: a signed deposit, then append-only resolutions.
        EventKind::AttemptDeposited => apply_attempt_deposited(state, event),
        EventKind::TransferDeposited => apply_transfer_deposited(state, event),
        EventKind::EndorsementDeposited => apply_endorsement_deposited(state, event),
        EventKind::AttemptResolved => apply_attempt_resolved(state, event),
        EventKind::StatementAttested => apply_statement_attested(state, event),
        EventKind::AnchorAttached => apply_anchor_attached(state, event),
        EventKind::AnchorRetracted => apply_anchor_retracted(state, event),
        EventKind::AttemptClaimed => apply_attempt_claimed(state, event),
        EventKind::StatementRegistered => apply_statement_registered(state, event),
        // Supersession: the event targets the *old* finding and flips its
        // `flags.superseded`. The replacement finding's body lives in the
        // accepted proposal's `payload.new_finding` and enters replay via
        // genesis seeding (`repo::seed_genesis`), not via this arm — the
        // event payload is deliberately thin ({proposal_id, new_finding_id}).
        EventKind::FindingSuperseded => apply_finding_superseded(state, event, idx),
        // Causal re-grading (`vela finding causal-set`): replays the
        // claim/grade mutation from the event's `payload.after`.
        EventKind::AssertionReinterpretedCausal => apply_assertion_reinterpreted_causal(state, event, idx),
        // Audit-only / writerless kinds. Each is validated at emit time and
        // appended to the log, but mutates no projected state on replay:
        // their consumers read the events directly. The threshold,
        // correction-return, research-trace, and prediction-expiry kinds had
        // their CLI writers removed in the v0.700 surface cut (zero such
        // events exist in any live log); `frontier.observation_reviewed` and
        // `key.revoke` are audit records (authoritative revocation lives in
        // the hub's append-only revocation table). Explicit arms so a
        // historical log containing any of them replays instead of erroring.
        // A reviewer-tier key's recommend-accept: audit record consumed by
        // owner/maintainer keys; no projected-state mutation.
        EventKind::ProposalRecommended
        | EventKind::FrontierObservationReviewed
        | EventKind::CorrectionReturnReview
        | EventKind::ResearchTraceReview
        | EventKind::KeyRevoke
        // Reviewer decision records. Audit-only on the FINDING projection:
        // the accept's effect on state is the domain event it produced
        // (finding.asserted, …), already replayed by its own arm; the
        // review.* event records WHO decided and HOW. Proposal `status` is
        // a separate projection over these events, verified by
        // `proposals::verify_proposal_decision_parity` — not reconstructed
        // here, so verify_replay's finding hashes are untouched.
        | EventKind::ReviewAccepted
        | EventKind::ReviewRejected
        | EventKind::ReviewRevisionRequested => Ok(()),
        EventKind::Other(other) => Err(format!("reducer: unsupported event kind '{other}'")),
    }
}

/// Replay an entire event log from genesis state.
///
/// `genesis` is the bootstrap finding set (the state of the frontier at
/// the moment of compile, before any reviewed transitions). `events` is
/// the full canonical event log. Returns the materialized `Project` after
/// applying every event in sequence.
pub fn replay_from_genesis(
    genesis: Vec<crate::bundle::FindingBundle>,
    events: Vec<StateEvent>,
    name: &str,
    description: &str,
    compiled_at: &str,
    compiler: &str,
) -> Result<Project, String> {
    let mut state = Project {
        vela_version: project::VELA_SCHEMA_VERSION.to_string(),
        schema: project::VELA_SCHEMA_URL.to_string(),
        frontier_id: None,
        project: project::ProjectMeta {
            name: name.to_string(),
            description: description.to_string(),
            compiled_at: compiled_at.to_string(),
            compiler: compiler.to_string(),
            papers_processed: 0,
            errors: 0,
            dependencies: Vec::new(),
        },
        stats: project::ProjectStats::default(),
        findings: genesis,
        sources: Vec::new(),
        evidence_atoms: Vec::new(),
        condition_records: Vec::new(),
        review_events: Vec::new(),
        confidence_updates: Vec::new(),
        events: Vec::new(),
        proposals: Vec::new(),
        proof_state: crate::proposals::ProofState::default(),
        signatures: Vec::new(),
        actors: Vec::new(),
        datasets: Vec::new(),
        code_artifacts: Vec::new(),
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
    crate::sources::materialize_project(&mut state);
    // v0.105: build the finding-id index once, reuse across every
    // event. Replay is the hot path and was previously O(N^2) (each
    // per-kind apply linear-scanned state.findings); with the index
    // it is O(N).
    let mut idx = build_finding_index(&state);
    // v0.106.6: take events by value and move each one into
    // state.events instead of cloning. Pre-v0.106.6 the input was
    // &[StateEvent] and the loop did event.clone() on every
    // iteration, which walked the heap-allocated payload Value tree
    // for each event. At N=20k events this was the next bottleneck
    // after the v0.105 O(N^2) scan was removed.
    for event in events {
        apply_event_indexed(&mut state, &event, &mut idx)?;
        state.events.push(event);
    }
    project::recompute_stats(&mut state);
    Ok(state)
}

/// Canonical replay order: (timestamp, id). This is the same order
/// `events::replay_report` uses for chain verification. Timestamps are
/// RFC3339 with microseconds; the content-addressed id is the
/// deterministic tiebreak.
pub fn sorted_for_replay(events: &[StateEvent]) -> Vec<StateEvent> {
    let mut sorted: Vec<StateEvent> = events.to_vec();
    sorted.sort_by(|a, b| a.timestamp.cmp(&b.timestamp).then_with(|| a.id.cmp(&b.id)));
    sorted
}

/// Synthesize the genesis finding set from the event log plus the
/// proposal payload store. The protocol's `finding.asserted` events are
/// deliberately thin (`{proposal_id}`); the asserted body lives in the
/// accepted proposal's `payload.finding` (or `payload.new_finding` for a
/// supersession) and is cryptographically pinned: the assert event's
/// `after_hash` is `finding_hash` of the body pushed at accept time.
/// Every hydration is verified against that hash — a tampered or missing
/// proposal becomes a diagnostic, never a silently wrong finding.
///
/// Events whose payload carries `finding` inline (v0.3 genesis form) are
/// NOT seeded here: the reducer's `finding.asserted` arm applies them
/// during replay.
pub fn seed_genesis(
    events_sorted: &[StateEvent],
    proposals: &[crate::proposals::StateProposal],
) -> (Vec<crate::bundle::FindingBundle>, Vec<String>) {
    use crate::bundle::FindingBundle;
    let by_id: HashMap<&str, &crate::proposals::StateProposal> =
        proposals.iter().map(|p| (p.id.as_str(), p)).collect();
    let mut genesis: Vec<FindingBundle> = Vec::new();
    let mut diagnostics: Vec<String> = Vec::new();
    for ev in events_sorted {
        let (payload_key, is_supersede) = match ev.kind.as_str() {
            "finding.asserted" => ("finding", false),
            "finding.superseded" => ("new_finding", true),
            _ => continue,
        };
        if !is_supersede && ev.payload.get("finding").is_some() {
            // Inline (v0.3 genesis) form: the reducer arm applies it.
            continue;
        }
        let Some(pid) = ev.payload.get("proposal_id").and_then(Value::as_str) else {
            diagnostics.push(format!(
                "{}: {} carries neither an inline body nor a proposal_id",
                ev.id, ev.kind
            ));
            continue;
        };
        let Some(proposal) = by_id.get(pid) else {
            diagnostics.push(format!(
                "{}: {} references proposal {pid}, which is not in the proposal store",
                ev.id, ev.kind
            ));
            continue;
        };
        let Some(body) = proposal.payload.get(payload_key) else {
            diagnostics.push(format!(
                "{}: proposal {pid} has no payload.{payload_key} to hydrate from",
                ev.id
            ));
            continue;
        };
        let finding: FindingBundle = match serde_json::from_value(body.clone()) {
            Ok(f) => f,
            Err(e) => {
                diagnostics.push(format!(
                    "{}: proposal {pid} payload.{payload_key} does not deserialize: {e}",
                    ev.id
                ));
                continue;
            }
        };
        // The pin: the assert event's after_hash is finding_hash of the
        // body as pushed (links excluded from the hash, so the writer's
        // auto-injected supersedes link cannot break it). For
        // finding.superseded the after_hash covers the OLD finding, so
        // the new body is hydrated unverified-by-hash but is still
        // confined to the signed, content-addressed proposal store.
        if !is_supersede {
            let h = events::finding_hash(&finding);
            if h != ev.after_hash {
                diagnostics.push(format!(
                    "{}: hydrated body hash {h} != event after_hash {} (proposal {pid} tampered or stale)",
                    ev.id, ev.after_hash
                ));
                continue;
            }
        }
        if genesis.iter().any(|g| g.id == finding.id) {
            continue; // idempotent under duplicate asserts
        }
        genesis.push(finding);
    }
    (genesis, diagnostics)
}

/// One full reducer replay of a loaded project's own event log: sort a
/// copy of the events into canonical replay order, seed genesis from the
/// proposal payload store, and run `replay_from_genesis`. The loader
/// grafts every event-derived collection from the result — this is the
/// single code path that makes "loader = reducer" true. Hydration
/// diagnostics are not fatal here (a finding that fails to hydrate is
/// simply absent from the replayed copy); `verify_replay` is where they
/// become check failures.
pub fn replayed_projection(state: &Project) -> Result<Project, String> {
    let sorted = sorted_for_replay(&state.events);
    let (genesis, _diagnostics, _remnants) = seed_genesis_with_remnants(state, &sorted);
    replay_from_genesis(
        genesis,
        sorted,
        &state.project.name,
        &state.project.description,
        &state.project.compiled_at,
        &state.project.compiler,
    )
}

/// Genesis = hydrated asserts (from the proposal payload store) plus
/// *genesis remnants*: cached findings with no assert/supersede event
/// anywhere in the log. Remnants predate the event-first discipline (or
/// were assembled directly, as in tests); they cannot be replayed into
/// existence, but later events may target them, so both the loader and
/// the verifier must seed them or replay would reject their own log.
/// Returns (genesis, hydration diagnostics, remnant count).
pub fn seed_genesis_with_remnants(
    state: &Project,
    events_sorted: &[StateEvent],
) -> (Vec<crate::bundle::FindingBundle>, Vec<String>, usize) {
    let (mut genesis, diagnostics) = seed_genesis(events_sorted, &state.proposals);
    let evented_ids: std::collections::HashSet<&str> = events_sorted
        .iter()
        .filter(|e| matches!(e.kind.as_str(), "finding.asserted" | "finding.superseded"))
        .flat_map(|e| {
            let mut ids = vec![e.target.id.as_str()];
            if let Some(nid) = e.payload.get("new_finding_id").and_then(Value::as_str) {
                ids.push(nid);
            }
            ids
        })
        .collect();
    let mut remnants = 0usize;
    for f in &state.findings {
        if !evented_ids.contains(f.id.as_str()) && !genesis.iter().any(|g| g.id == f.id) {
            genesis.push(f.clone());
            remnants += 1;
        }
    }
    (genesis, diagnostics, remnants)
}

/// Order-independent digest over a finding set (ids sorted, links
/// excluded via `finding_hash`). This is the comparison surface of
/// `verify_replay`: the full `snapshot_hash` covers loader-only state
/// (proposals, actors, stats) that a pure replay can never reproduce,
/// so replayed-vs-materialized equality is only meaningful over the
/// findings themselves.
fn findings_digest(findings: &[crate::bundle::FindingBundle]) -> String {
    let mut pairs: Vec<(String, String)> = findings
        .iter()
        .map(|f| (f.id.clone(), events::finding_hash(f)))
        .collect();
    pairs.sort();
    let joined = pairs
        .iter()
        .map(|(id, h)| format!("{id}:{h}"))
        .collect::<Vec<_>>()
        .join("\n");
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(joined.as_bytes()))
}

/// Verify that the materialized `state` is reproducible from its own
/// event log: seed genesis from the proposal payload store, replay every
/// event through the one reducer, and compare per-finding
/// `finding_hash` between the replayed and materialized findings.
///
/// This is the load-bearing check that turns Vela's replay claim into a
/// verifiable invariant — the loader and the reducer can no longer
/// drift apart silently.
pub fn verify_replay(state: &Project) -> ReplayVerification {
    if state.events.is_empty() {
        let d = findings_digest(&state.findings);
        return ReplayVerification {
            ok: true,
            replayed_snapshot_hash: d.clone(),
            materialized_snapshot_hash: d,
            diffs: Vec::new(),
            note: "no events; replay is identity".to_string(),
        };
    }
    let sorted = sorted_for_replay(&state.events);
    let (genesis, mut diffs, remnants) = seed_genesis_with_remnants(state, &sorted);
    let replayed = match replay_from_genesis(
        genesis,
        sorted,
        &state.project.name,
        &state.project.description,
        &state.project.compiled_at,
        &state.project.compiler,
    ) {
        Ok(p) => p,
        Err(e) => {
            return ReplayVerification {
                ok: false,
                replayed_snapshot_hash: String::new(),
                materialized_snapshot_hash: findings_digest(&state.findings),
                diffs: vec![format!("replay failed: {e}")],
                note: "event log does not replay through the reducer".to_string(),
            };
        }
    };
    let replayed_by_id: HashMap<&str, &crate::bundle::FindingBundle> = replayed
        .findings
        .iter()
        .map(|f| (f.id.as_str(), f))
        .collect();
    for cached in &state.findings {
        match replayed_by_id.get(cached.id.as_str()) {
            None => diffs.push(format!(
                "finding {} is materialized but absent from replay (no assert event hydrates it)",
                cached.id
            )),
            Some(rep) => {
                let ch = events::finding_hash(cached);
                let rh = events::finding_hash(rep);
                if ch != rh {
                    diffs.push(format!(
                        "finding {} diverges: materialized {ch} vs replayed {rh}",
                        cached.id
                    ));
                }
            }
        }
    }
    for rep in &replayed.findings {
        if !state.findings.iter().any(|c| c.id == rep.id) {
            diffs.push(format!(
                "finding {} is replayable from the log but absent from the materialized state",
                rep.id
            ));
        }
    }
    let ok = diffs.is_empty();
    ReplayVerification {
        ok,
        replayed_snapshot_hash: findings_digest(&replayed.findings),
        materialized_snapshot_hash: findings_digest(&state.findings),
        diffs,
        note: if ok {
            format!(
                "replayed {} event(s) over {} seeded finding(s) ({} genesis remnant(s)); materialized state reproduced",
                state.events.len(),
                replayed.findings.len(),
                remnants
            )
        } else {
            "materialized state is NOT reproducible from the event log".to_string()
        },
    }
}

#[derive(Debug, Clone)]
pub struct ReplayVerification {
    pub ok: bool,
    pub replayed_snapshot_hash: String,
    pub materialized_snapshot_hash: String,
    pub diffs: Vec<String>,
    pub note: String,
}

// --- per-kind reducer rules ---------------------------------------------------

fn apply_finding_asserted(
    state: &mut Project,
    event: &StateEvent,
    idx: &mut FindingIndex,
) -> Result<(), String> {
    // For a v0.3 frontier emitting genesis events, finding.asserted carries
    // the full finding in payload.finding; for legacy frontiers replay is
    // a no-op (the finding was already materialized at genesis).
    if let Some(finding_value) = event.payload.get("finding") {
        let finding: crate::bundle::FindingBundle =
            serde_json::from_value(finding_value.clone())
                .map_err(|e| format!("reducer: invalid finding.asserted payload.finding: {e}"))?;
        if idx.contains_key(&finding.id) {
            return Ok(());
        }
        let position = state.findings.len();
        idx.insert(finding.id.clone(), position);
        state.findings.push(finding);
    }
    Ok(())
}

fn apply_finding_reviewed(
    state: &mut Project,
    event: &StateEvent,
    index: &mut FindingIndex,
) -> Result<(), String> {
    let id = event.target.id.as_str();
    let status = event
        .payload
        .get("status")
        .and_then(Value::as_str)
        .ok_or("reducer: finding.reviewed missing payload.status")?;
    let idx = *index
        .get(id)
        .ok_or_else(|| format!("reducer: finding.reviewed targets unknown finding {id}"))?;
    use crate::bundle::ReviewState;
    let new_state = match status {
        "accepted" | "approved" => ReviewState::Accepted,
        "contested" => ReviewState::Contested,
        "needs_revision" => ReviewState::NeedsRevision,
        "rejected" => ReviewState::Rejected,
        other => return Err(format!("reducer: unsupported review status '{other}'")),
    };
    state.findings[idx].flags.contested = new_state.implies_contested();
    state.findings[idx].flags.review_state = Some(new_state);
    Ok(())
}

fn apply_finding_annotation(
    state: &mut Project,
    event: &StateEvent,
    _kind_label: &str,
    index: &mut FindingIndex,
) -> Result<(), String> {
    let id = event.target.id.as_str();
    let text = event
        .payload
        .get("text")
        .and_then(Value::as_str)
        .ok_or("reducer: annotation event missing payload.text")?;
    let annotation_id = event
        .payload
        .get("annotation_id")
        .and_then(Value::as_str)
        .ok_or("reducer: annotation event missing payload.annotation_id")?;
    let idx = *index
        .get(id)
        .ok_or_else(|| format!("reducer: annotation event targets unknown finding {id}"))?;
    if state.findings[idx]
        .annotations
        .iter()
        .any(|a| a.id == annotation_id)
    {
        return Ok(());
    }
    // Phase β (v0.6): pass through optional structured provenance from
    // the event payload to the materialized annotation. The validator in
    // `events::validate_event_payload` already rejected all-empty
    // provenance objects, so deserialization here is best-effort —
    // unknown shapes silently drop to None rather than failing the
    // whole reduce.
    let provenance = event
        .payload
        .get("provenance")
        .and_then(|v| serde_json::from_value::<crate::bundle::ProvenanceRef>(v.clone()).ok());
    state.findings[idx].annotations.push(Annotation {
        id: annotation_id.to_string(),
        text: text.to_string(),
        author: event.actor.id.clone(),
        timestamp: event.timestamp.clone(),
        provenance,
    });
    Ok(())
}

fn apply_finding_confidence_revised(
    state: &mut Project,
    event: &StateEvent,
    index: &mut FindingIndex,
) -> Result<(), String> {
    let id = event.target.id.as_str();
    let new_score = event
        .payload
        .get("new_score")
        .and_then(Value::as_f64)
        .ok_or("reducer: finding.confidence_revised missing payload.new_score")?;
    let previous = event
        .payload
        .get("previous_score")
        .and_then(Value::as_f64)
        .unwrap_or(0.0);
    let idx = *index
        .get(id)
        .ok_or_else(|| format!("reducer: confidence_revised targets unknown finding {id}"))?;
    let updated_at = event
        .payload
        .get("updated_at")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| event.timestamp.clone());
    state.findings[idx].confidence.score = new_score;
    state.findings[idx].confidence.basis = format!(
        "expert revision from {:.3} to {:.3}: {}",
        previous, new_score, event.reason
    );
    state.findings[idx].confidence.method = ConfidenceMethod::ExpertJudgment;
    state.findings[idx].updated = Some(updated_at);
    Ok(())
}

fn apply_finding_rejected(
    state: &mut Project,
    event: &StateEvent,
    index: &mut FindingIndex,
) -> Result<(), String> {
    let id = event.target.id.as_str();
    let idx = *index
        .get(id)
        .ok_or_else(|| format!("reducer: finding.rejected targets unknown finding {id}"))?;
    state.findings[idx].flags.contested = true;
    Ok(())
}

fn apply_finding_retracted(
    state: &mut Project,
    event: &StateEvent,
    index: &mut FindingIndex,
) -> Result<(), String> {
    let id = event.target.id.as_str();
    let idx = *index
        .get(id)
        .ok_or_else(|| format!("reducer: finding.retracted targets unknown finding {id}"))?;
    state.findings[idx].flags.retracted = true;
    Ok(())
}

/// `finding.superseded` targets the OLD finding and flips its
/// `flags.superseded` (idempotent). The replacement finding is NOT
/// applied here: the event payload is thin (`{proposal_id,
/// new_finding_id}`) and the replacement's body lives in the accepted
/// proposal's `payload.new_finding`, entering replay as a genesis seed.
/// Note: the writer (`proposals::apply_supersede`) also auto-injects a
/// `supersedes` link into the replacement; links are excluded from
/// `finding_hash`, so replay verification is unaffected by that
/// injection.
fn apply_finding_superseded(
    state: &mut Project,
    event: &StateEvent,
    index: &mut FindingIndex,
) -> Result<(), String> {
    let id = event.target.id.as_str();
    let idx = *index
        .get(id)
        .ok_or_else(|| format!("reducer: finding.superseded targets unknown finding {id}"))?;
    state.findings[idx].flags.superseded = true;
    Ok(())
}

/// `assertion.reinterpreted_causal` replays the causal re-grading from
/// the event's `payload.after` (`{claim, grade}`), mirroring the writer
/// in `state::causal_set`. Invalid vocabulary is an error — the payload
/// was validated at emit time, so a mismatch here means a corrupted log.
fn apply_assertion_reinterpreted_causal(
    state: &mut Project,
    event: &StateEvent,
    index: &mut FindingIndex,
) -> Result<(), String> {
    use crate::bundle::{CausalClaim, CausalEvidenceGrade};
    let id = event.target.id.as_str();
    let idx = *index.get(id).ok_or_else(|| {
        format!("reducer: assertion.reinterpreted_causal targets unknown finding {id}")
    })?;
    let after = event
        .payload
        .get("after")
        .ok_or("reducer: assertion.reinterpreted_causal missing payload.after")?;
    let claim = after
        .get("claim")
        .and_then(Value::as_str)
        .ok_or("reducer: assertion.reinterpreted_causal missing payload.after.claim")?;
    let parsed_claim = match claim {
        "correlation" => CausalClaim::Correlation,
        "mediation" => CausalClaim::Mediation,
        "intervention" => CausalClaim::Intervention,
        other => return Err(format!("reducer: invalid causal claim '{other}'")),
    };
    let parsed_grade = match after.get("grade").and_then(Value::as_str) {
        None => None,
        Some("rct") => Some(CausalEvidenceGrade::Rct),
        Some("quasi_experimental") => Some(CausalEvidenceGrade::QuasiExperimental),
        Some("observational") => Some(CausalEvidenceGrade::Observational),
        Some("theoretical") => Some(CausalEvidenceGrade::Theoretical),
        Some(other) => return Err(format!("reducer: invalid causal evidence grade '{other}'")),
    };
    state.findings[idx].assertion.causal_claim = Some(parsed_claim);
    if let Some(g) = parsed_grade {
        state.findings[idx].assertion.causal_evidence_grade = Some(g);
    }
    Ok(())
}

fn apply_finding_dependency_invalidated(
    state: &mut Project,
    event: &StateEvent,
    index: &mut FindingIndex,
) -> Result<(), String> {
    let id = event.target.id.as_str();
    let upstream = event
        .payload
        .get("upstream_finding_id")
        .and_then(Value::as_str)
        .unwrap_or("?");
    let depth = event
        .payload
        .get("depth")
        .and_then(Value::as_u64)
        .unwrap_or(1);
    let idx = *index.get(id).ok_or_else(|| {
        format!("reducer: finding.dependency_invalidated targets unknown finding {id}")
    })?;
    state.findings[idx].flags.contested = true;
    let annotation_id = format!("ann_dep_{}_{}", &event.id[4..], depth);
    if !state.findings[idx]
        .annotations
        .iter()
        .any(|a| a.id == annotation_id)
    {
        state.findings[idx].annotations.push(Annotation {
            id: annotation_id,
            text: format!("Upstream {upstream} retracted (cascade depth {depth})."),
            author: event.actor.id.clone(),
            timestamp: event.timestamp.clone(),
            provenance: None,
        });
    }
    Ok(())
}

fn apply_artifact_asserted(state: &mut Project, event: &StateEvent) -> Result<(), String> {
    let artifact_value = event
        .payload
        .get("artifact")
        .ok_or("reducer: artifact.asserted missing payload.artifact")?;
    let artifact: crate::bundle::Artifact = serde_json::from_value(artifact_value.clone())
        .map_err(|e| format!("reducer: invalid artifact.asserted payload: {e}"))?;
    if state.artifacts.iter().any(|a| a.id == artifact.id) {
        return Ok(());
    }
    state.artifacts.push(artifact);
    Ok(())
}

/// Append a verifier attachment (target = `vf_…`) to the sidecar collection.
/// Idempotent on the content-addressed `vva_` id. The per-finding trust-gate
/// status is derived from these on read (export), never stored here.
fn apply_verifier_attachment_added(state: &mut Project, event: &StateEvent) -> Result<(), String> {
    let value = event
        .payload
        .get("attachment")
        .ok_or("reducer: verifier_attachment.added missing payload.attachment")?;
    let att: crate::verifier_attachment::VerifierAttachment = serde_json::from_value(value.clone())
        .map_err(|e| format!("reducer: invalid verifier_attachment.added payload: {e}"))?;
    if state.verifier_attachments.iter().any(|a| a.id == att.id) {
        return Ok(());
    }
    state.verifier_attachments.push(att);
    Ok(())
}

fn apply_artifact_reviewed(state: &mut Project, event: &StateEvent) -> Result<(), String> {
    let id = event.target.id.as_str();
    let status = event
        .payload
        .get("status")
        .and_then(Value::as_str)
        .ok_or("reducer: artifact.reviewed missing payload.status")?;
    use crate::bundle::ReviewState;
    let new_state = match status {
        "accepted" | "approved" => ReviewState::Accepted,
        "contested" => ReviewState::Contested,
        "needs_revision" => ReviewState::NeedsRevision,
        "rejected" => ReviewState::Rejected,
        other => return Err(format!("reducer: unsupported review status '{other}'")),
    };
    let idx = state
        .artifacts
        .iter()
        .position(|a| a.id == id)
        .ok_or_else(|| format!("reducer: artifact.reviewed targets unknown artifact {id}"))?;
    state.artifacts[idx].review_state = Some(new_state);
    Ok(())
}

fn apply_artifact_retracted(state: &mut Project, event: &StateEvent) -> Result<(), String> {
    let id = event.target.id.as_str();
    let idx = state
        .artifacts
        .iter()
        .position(|a| a.id == id)
        .ok_or_else(|| format!("reducer: artifact.retracted targets unknown artifact {id}"))?;
    state.artifacts[idx].retracted = true;
    Ok(())
}

/// v0.51: Apply a `tier.set` event. Re-classifies the access_tier on
/// the matched finding / artifact. The validator
/// has already checked the object_type and tier strings; here we
/// just locate the object and mutate.
fn apply_tier_set(state: &mut Project, event: &StateEvent) -> Result<(), String> {
    let object_type = event
        .payload
        .get("object_type")
        .and_then(Value::as_str)
        .ok_or("reducer: tier.set missing payload.object_type")?;
    let object_id = event
        .payload
        .get("object_id")
        .and_then(Value::as_str)
        .ok_or("reducer: tier.set missing payload.object_id")?;
    let new_tier_str = event
        .payload
        .get("new_tier")
        .and_then(Value::as_str)
        .ok_or("reducer: tier.set missing payload.new_tier")?;
    let new_tier = crate::access_tier::AccessTier::parse(new_tier_str)
        .map_err(|e| format!("reducer: tier.set {e}"))?;
    match object_type {
        "finding" => {
            let idx = state
                .findings
                .iter()
                .position(|f| f.id == object_id)
                .ok_or_else(|| format!("reducer: tier.set targets unknown finding {object_id}"))?;
            state.findings[idx].access_tier = new_tier;
        }
        "artifact" => {
            let idx = state
                .artifacts
                .iter()
                .position(|a| a.id == object_id)
                .ok_or_else(|| format!("reducer: tier.set targets unknown artifact {object_id}"))?;
            state.artifacts[idx].access_tier = new_tier;
        }
        other => {
            return Err(format!(
                "reducer: tier.set object_type '{other}' must be one of finding, artifact"
            ));
        }
    }
    Ok(())
}

/// v0.213: append a ReleasedDiffPackRecord to
/// `state.released_diff_packs` when a `diff_pack.released` event
/// lands on the canonical log. Idempotent on pack_id — re-applying
/// the same released event is a no-op so federation re-sync stays
/// clean. Theorem 29 pins the accumulation algebra.
fn apply_diff_pack_released(state: &mut Project, event: &StateEvent) -> Result<(), String> {
    use crate::released_diff_pack::ReleasedDiffPackRecord;

    let pack_id = event
        .payload
        .get("pack_id")
        .and_then(Value::as_str)
        .ok_or("diff_pack.released event missing payload.pack_id")?;
    if !pack_id.starts_with("vsd_") {
        return Err(format!(
            "diff_pack.released event payload.pack_id must start with `vsd_`, got `{pack_id}`"
        ));
    }
    if state
        .released_diff_packs
        .iter()
        .any(|r| r.pack_id == pack_id)
    {
        return Ok(());
    }
    let frontier_id = event
        .payload
        .get("frontier_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let summary = event
        .payload
        .get("summary")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let aggregate_kind = event
        .payload
        .get("aggregate_kind")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    state
        .released_diff_packs
        .push(ReleasedDiffPackRecord::from_released_event(
            pack_id.to_string(),
            frontier_id,
            summary,
            aggregate_kind,
            event.timestamp.clone(),
            event.id.clone(),
        ));
    Ok(())
}

/// v0.213: update the matching ReleasedDiffPackRecord when a
/// `diff_pack.reviewed` event lands. Sets verdict +
/// verdict_event_id + reviewer_actor + applied_members +
/// sdk_only_members from the payload. Idempotent under
/// re-application: re-applying the same verdict to the same
/// record produces no further change.
///
/// If no ReleasedDiffPackRecord exists for the pack_id yet (the
/// release event has not been replayed, or the pack was promoted
/// without first emitting `diff_pack.released`), the function
/// creates a record on the fly from the verdict event's payload
/// so the log stays self-sufficient.
fn apply_diff_pack_reviewed(state: &mut Project, event: &StateEvent) -> Result<(), String> {
    use crate::released_diff_pack::{ReleasedDiffPackRecord, ReleasedVerdict};

    let pack_id = event
        .payload
        .get("pack_id")
        .and_then(Value::as_str)
        .ok_or("diff_pack.reviewed event missing payload.pack_id")?
        .to_string();
    if !pack_id.starts_with("vsd_") {
        return Err(format!(
            "diff_pack.reviewed event payload.pack_id must start with `vsd_`, got `{pack_id}`"
        ));
    }
    let verdict_str = event
        .payload
        .get("verdict")
        .and_then(Value::as_str)
        .ok_or("diff_pack.reviewed event missing payload.verdict")?;
    let verdict = ReleasedVerdict::from_str_ci(verdict_str).ok_or_else(|| {
        format!(
            "diff_pack.reviewed event payload.verdict must be accept|reject|revise, got `{verdict_str}`"
        )
    })?;
    let reviewer_actor = event
        .payload
        .get("reviewer_actor")
        .and_then(Value::as_str)
        .unwrap_or(&event.actor.id)
        .to_string();
    let applied: Vec<String> = event
        .payload
        .get("applied_members")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let sdk_only: Vec<String> = event
        .payload
        .get("sdk_only_members")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    if let Some(rec) = state
        .released_diff_packs
        .iter_mut()
        .find(|r| r.pack_id == pack_id)
    {
        rec.verdict = Some(verdict);
        rec.verdict_event_id = Some(event.id.clone());
        rec.reviewer_actor = Some(reviewer_actor);
        rec.applied_members = applied;
        rec.sdk_only_members = sdk_only;
    } else {
        // No prior `diff_pack.released` event for this pack. Create
        // a record from the verdict event so the log stays self-
        // sufficient. The promoter typically emits the release event
        // before the verdict, but a hub that receives only the
        // verdict (e.g., a federation peer that missed the release)
        // can still reconstruct a sensible record.
        let mut rec = ReleasedDiffPackRecord::from_released_event(
            pack_id,
            event
                .payload
                .get("frontier_id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            String::new(),
            String::new(),
            event.timestamp.clone(),
            String::new(),
        );
        rec.verdict = Some(verdict);
        rec.verdict_event_id = Some(event.id.clone());
        rec.reviewer_actor = Some(reviewer_actor);
        rec.applied_members = applied;
        rec.sdk_only_members = sdk_only;
        state.released_diff_packs.push(rec);
    }
    Ok(())
}

/// v0.218: append a VerdictConflict record to
/// `state.verdict_conflicts` when a `verdict_conflict.resolved`
/// event lands. The full conflict body lives in the event payload
/// under `conflict`. Idempotent on conflict_id — re-applying the
/// same resolution is a no-op. T32 pins the bounded-length
/// accumulation algebra.
fn apply_verdict_conflict_resolved(state: &mut Project, event: &StateEvent) -> Result<(), String> {
    use crate::verdict_conflict::VerdictConflict;

    let conflict_value = event
        .payload
        .get("conflict")
        .ok_or("verdict_conflict.resolved event missing payload.conflict")?
        .clone();
    let conflict: VerdictConflict = serde_json::from_value(conflict_value)
        .map_err(|e| format!("verdict_conflict.resolved payload parse: {e}"))?;
    conflict
        .verify()
        .map_err(|e| format!("verdict_conflict.resolved body did not verify: {e}"))?;
    if state
        .verdict_conflicts
        .iter()
        .any(|c| c.conflict_id == conflict.conflict_id)
    {
        return Ok(());
    }
    state.verdict_conflicts.push(conflict);
    Ok(())
}

/// T7: upsert a resolved Contradiction into `state.contradictions`
/// when a `contradiction.resolved` event lands. The full object lives
/// in the event payload under `contradiction`. Integrity check: the
/// object's `contradiction_id` must equal the content address of its
/// own (frontier_id, finding pair), so a forged or mismatched id is
/// rejected. Latest resolution per id wins — re-applying the same
/// event is a no-op; a later transition replaces the earlier record.
fn apply_contradiction_resolved(state: &mut Project, event: &StateEvent) -> Result<(), String> {
    use crate::contradiction::Contradiction;

    let value = event
        .payload
        .get("contradiction")
        .ok_or("contradiction.resolved event missing payload.contradiction")?
        .clone();
    let contradiction: Contradiction = serde_json::from_value(value)
        .map_err(|e| format!("contradiction.resolved payload parse: {e}"))?;

    let expected = Contradiction::content_address(
        &contradiction.frontier_id,
        &contradiction.finding_a,
        &contradiction.finding_b,
    );
    if contradiction.contradiction_id != expected {
        return Err(format!(
            "contradiction.resolved id '{}' does not match its pair (expected '{expected}')",
            contradiction.contradiction_id
        ));
    }

    if let Some(slot) = state
        .contradictions
        .iter_mut()
        .find(|c| c.contradiction_id == contradiction.contradiction_id)
    {
        *slot = contradiction;
    } else {
        state.contradictions.push(contradiction);
    }
    Ok(())
}

/// Idempotent upsert into a content-addressed collection: replace the element
/// that matches `item` by `same`, or append it. The shared shape behind the
/// attempt/resolution reducer arms.
fn upsert_by<T>(vec: &mut Vec<T>, item: T, same: impl Fn(&T, &T) -> bool) {
    if let Some(slot) = vec.iter_mut().find(|x| same(x, &item)) {
        *slot = item;
    } else {
        vec.push(item);
    }
}

/// Upsert a signed banked attempt into `state.attempts` when an
/// `attempt.deposited` event lands. The full object lives in
/// `payload.attempt`. Integrity: the object must `verify()` (id re-derives,
/// signature checks, claim_digest matches) — a forged or hand-edited deposit
/// is rejected. Idempotent by `vat_` id.
/// `statement.attested`: upsert the signed attestation from
/// `payload.attestation`. The record's own signature + content address
/// are re-verified on every apply — a tampered attestation cannot
/// re-enter through replay.
/// `attempt.claimed`: append/refresh an obligation lease. The
/// determinism rule: a prior lease is "expired" relative to THIS
/// event's timestamp (parse both RFC3339 instants; if claimed_at + ttl
/// <= new event's timestamp, the old lease is dead and the claim
/// succeeds). Same claimant refreshing their own live lease is allowed.
fn apply_attempt_claimed(state: &mut Project, event: &StateEvent) -> Result<(), String> {
    let p = &event.payload;
    let obligation_id = p
        .get("obligation_id")
        .and_then(Value::as_str)
        .ok_or("attempt.claimed missing payload.obligation_id")?;
    let ttl = p
        .get("lease_ttl_seconds")
        .and_then(Value::as_u64)
        .ok_or("attempt.claimed missing payload.lease_ttl_seconds")?;
    let claimant_actor = p
        .get("claimant_actor")
        .and_then(Value::as_str)
        .unwrap_or(&event.actor.id)
        .to_string();
    let claimant_pubkey = p
        .get("claimant_pubkey")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let parse = |t: &str| chrono::DateTime::parse_from_rfc3339(t).map(|d| d.timestamp());
    let now_s = parse(&event.timestamp)
        .map_err(|e| format!("attempt.claimed: bad event timestamp: {e}"))?;
    if let Some(existing) = state
        .attempt_claims
        .iter()
        .find(|c| c.obligation_id == obligation_id)
    {
        let exp = parse(&existing.claimed_at)
            .map(|t| t + existing.lease_ttl_seconds as i64)
            .unwrap_or(i64::MIN);
        let live = exp > now_s;
        if live && existing.claimant_actor != claimant_actor {
            return Err(format!(
                "obligation {obligation_id} is leased by {} until +{}s; route around it or wait for expiry",
                existing.claimant_actor, existing.lease_ttl_seconds
            ));
        }
    }
    state
        .attempt_claims
        .retain(|c| c.obligation_id != obligation_id);
    state.attempt_claims.push(crate::project::AttemptClaim {
        obligation_id: obligation_id.to_string(),
        claimant_actor,
        claimant_pubkey,
        claimed_at: event.timestamp.clone(),
        lease_ttl_seconds: ttl,
    });
    Ok(())
}

/// `statement.registered`: append a priority registration (idempotent
/// on statement_hash).
fn apply_statement_registered(state: &mut Project, event: &StateEvent) -> Result<(), String> {
    let p = &event.payload;
    let hash = p
        .get("statement_hash")
        .and_then(Value::as_str)
        .ok_or("statement.registered missing payload.statement_hash")?;
    if hash.len() != 64 || hex::decode(hash).is_err() {
        return Err("statement_hash must be 32 bytes of hex".to_string());
    }
    if state
        .statement_registrations
        .iter()
        .any(|r| r.statement_hash == hash)
    {
        return Ok(());
    }
    state
        .statement_registrations
        .push(crate::project::StatementRegistration {
            statement_hash: hash.to_string(),
            informal_ref: p
                .get("informal_ref")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            registered_by: event.actor.id.clone(),
            registered_at: event.timestamp.clone(),
            // Gap 5 (STATE_PLANE_MEMO appendix): the optional
            // finding-to-registration edge. Old events carry no
            // payload.finding_id and store None.
            finding_id: p
                .get("finding_id")
                .and_then(Value::as_str)
                .map(str::to_string),
        });
    Ok(())
}

fn apply_statement_attested(state: &mut Project, event: &StateEvent) -> Result<(), String> {
    use crate::statement_attestation::StatementAttestation;
    let value = event
        .payload
        .get("attestation")
        .ok_or("statement.attested event missing payload.attestation")?
        .clone();
    let att: StatementAttestation = serde_json::from_value(value)
        .map_err(|e| format!("statement.attested payload parse: {e}"))?;
    att.verify()
        .map_err(|e| format!("statement.attested rejected: {e}"))?;
    if let Some(existing) = state
        .statement_attestations
        .iter_mut()
        .find(|a| a.id == att.id)
    {
        *existing = att;
    } else {
        state.statement_attestations.push(att);
    }
    Ok(())
}

/// `anchor.attached`: upsert a signed `val_` anchor link from
/// `payload.anchor_link`. The link's own signature + content address are
/// re-verified on every apply, so a tampered anchor cannot enter state.
fn apply_anchor_attached(state: &mut Project, event: &StateEvent) -> Result<(), String> {
    use crate::anchor::AnchorLink;
    let value = event
        .payload
        .get("anchor_link")
        .ok_or("anchor.attached event missing payload.anchor_link")?
        .clone();
    let link: AnchorLink =
        serde_json::from_value(value).map_err(|e| format!("anchor.attached payload parse: {e}"))?;
    link.verify()
        .map_err(|e| format!("anchor.attached rejected: {e}"))?;
    if let Some(existing) = state.anchor_links.iter_mut().find(|a| a.id == link.id) {
        *existing = link;
    } else {
        state.anchor_links.push(link);
    }
    Ok(())
}

/// `anchor.retracted`: remove the anchor link named by
/// `payload.anchor_link_id`. Anchor attachment is fallible and therefore
/// retractable (frontier-calculus Law 22). Retracting an absent id is a
/// no-op, so replay stays idempotent.
fn apply_anchor_retracted(state: &mut Project, event: &StateEvent) -> Result<(), String> {
    let id = event
        .payload
        .get("anchor_link_id")
        .and_then(|v| v.as_str())
        .ok_or("anchor.retracted event missing payload.anchor_link_id")?;
    state.anchor_links.retain(|a| a.id != id);
    Ok(())
}

fn apply_attempt_deposited(state: &mut Project, event: &StateEvent) -> Result<(), String> {
    use crate::attempt::Attempt;

    let value = event
        .payload
        .get("attempt")
        .ok_or("attempt.deposited event missing payload.attempt")?
        .clone();
    let attempt: Attempt = serde_json::from_value(value)
        .map_err(|e| format!("attempt.deposited payload parse: {e}"))?;
    attempt
        .verify()
        .map_err(|e| format!("attempt.deposited rejected: {e}"))?;

    upsert_by(&mut state.attempts, attempt, |a, b| {
        a.attempt_id == b.attempt_id
    });
    Ok(())
}

/// Upsert a signed cross-domain transfer into `state.transfers` when a
/// `transfer.deposited` event lands. The full object lives in
/// `payload.transfer`. Integrity: the object must `verify()` (id re-derives,
/// signature checks) — a forged or hand-edited transfer is rejected. Admission
/// (whether the link is sound) is NOT decided here; it is derived on read via
/// `transfer::derive_transfer_status`. Idempotent by `vtr_` id.
fn apply_transfer_deposited(state: &mut Project, event: &StateEvent) -> Result<(), String> {
    use crate::transfer::Transfer;

    let value = event
        .payload
        .get("transfer")
        .ok_or("transfer.deposited event missing payload.transfer")?
        .clone();
    let transfer: Transfer = serde_json::from_value(value)
        .map_err(|e| format!("transfer.deposited payload parse: {e}"))?;
    transfer
        .verify()
        .map_err(|e| format!("transfer.deposited rejected: {e}"))?;

    upsert_by(&mut state.transfers, transfer, |a, b| {
        a.transfer_id == b.transfer_id
    });
    Ok(())
}

/// Upsert a signed significance endorsement into `state.endorsements` when an
/// `endorsement.deposited` event lands. The object lives in
/// `payload.endorsement`. Integrity: it must `verify()` (id re-derives,
/// signature checks). Idempotent by `ven_` id. There is deliberately NO
/// aggregation here — endorsements accumulate as individual records and are
/// never folded into a significance score.
fn apply_endorsement_deposited(state: &mut Project, event: &StateEvent) -> Result<(), String> {
    use crate::endorsement::Endorsement;

    let value = event
        .payload
        .get("endorsement")
        .ok_or("endorsement.deposited event missing payload.endorsement")?
        .clone();
    let endorsement: Endorsement = serde_json::from_value(value)
        .map_err(|e| format!("endorsement.deposited payload parse: {e}"))?;
    endorsement
        .verify()
        .map_err(|e| format!("endorsement.deposited rejected: {e}"))?;

    upsert_by(&mut state.endorsements, endorsement, |a, b| {
        a.endorsement_id == b.endorsement_id
    });
    Ok(())
}

/// Append a lifecycle transition into `state.attempt_resolutions` when an
/// `attempt.resolved` event lands. The [`crate::attempt::ResolutionEvent`]
/// lives in `payload.resolution`. Integrity: the object must `verify()`
/// (`vre_` id re-derives). Idempotent by `vre_` id; the head per attempt is
/// the latest by `at`, computed on read (`Project::head_resolution`).
fn apply_attempt_resolved(state: &mut Project, event: &StateEvent) -> Result<(), String> {
    use crate::attempt::ResolutionEvent;

    let value = event
        .payload
        .get("resolution")
        .ok_or("attempt.resolved event missing payload.resolution")?
        .clone();
    let resolution: ResolutionEvent = serde_json::from_value(value)
        .map_err(|e| format!("attempt.resolved payload parse: {e}"))?;
    resolution
        .verify()
        .map_err(|e| format!("attempt.resolved rejected: {e}"))?;

    upsert_by(&mut state.attempt_resolutions, resolution, |a, b| {
        a.resolution_id == b.resolution_id
    });
    Ok(())
}

/// v0.57: Apply a `finding.span_repaired` event. Appends a
/// `{section, text}` span object to
/// `state.findings[i].evidence.evidence_spans`. Idempotent:
/// applying twice with the same (section, text) pair is a no-op.
fn apply_finding_span_repaired(
    state: &mut Project,
    event: &StateEvent,
    index: &mut FindingIndex,
) -> Result<(), String> {
    if event.target.r#type != "finding" {
        return Err(format!(
            "reducer: finding.span_repaired target.type must be 'finding', got '{}'",
            event.target.r#type
        ));
    }
    let finding_id = event.target.id.as_str();
    let section = event
        .payload
        .get("section")
        .and_then(Value::as_str)
        .ok_or("reducer: finding.span_repaired missing payload.section")?;
    let text = event
        .payload
        .get("text")
        .and_then(Value::as_str)
        .ok_or("reducer: finding.span_repaired missing payload.text")?;
    let idx = *index.get(finding_id).ok_or_else(|| {
        format!("reducer: finding.span_repaired targets unknown finding {finding_id}")
    })?;
    let span_value = serde_json::json!({"section": section, "text": text});
    let already_present = state.findings[idx]
        .evidence
        .evidence_spans
        .iter()
        .any(|existing| {
            existing.get("section").and_then(Value::as_str) == Some(section)
                && existing.get("text").and_then(Value::as_str) == Some(text)
        });
    if !already_present {
        state.findings[idx].evidence.evidence_spans.push(span_value);
    }
    Ok(())
}

/// v0.56: Apply an `evidence_atom.locator_repaired` event. Sets
/// `locator` on the named atom and removes the "missing evidence
/// locator" caveat if present. Idempotent: applying twice with the
/// same locator is a no-op. Mismatched locator values fail the reduce
/// rather than silently overwriting, since divergent locators on the
/// same atom are a chain-integrity issue, not a repair.
fn apply_evidence_atom_locator_repaired(
    state: &mut Project,
    event: &StateEvent,
) -> Result<(), String> {
    if event.target.r#type != "evidence_atom" {
        return Err(format!(
            "reducer: evidence_atom.locator_repaired target.type must be 'evidence_atom', got '{}'",
            event.target.r#type
        ));
    }
    let atom_id = event.target.id.as_str();
    let locator = event
        .payload
        .get("locator")
        .and_then(Value::as_str)
        .ok_or("reducer: evidence_atom.locator_repaired missing payload.locator")?;
    let idx = state
        .evidence_atoms
        .iter()
        .position(|atom| atom.id == atom_id)
        .ok_or_else(|| {
            format!("reducer: evidence_atom.locator_repaired targets unknown atom {atom_id}")
        })?;
    if let Some(existing) = &state.evidence_atoms[idx].locator
        && existing != locator
    {
        return Err(format!(
            "reducer: evidence_atom {atom_id} already has locator '{existing}', refusing to overwrite with '{locator}'"
        ));
    }
    state.evidence_atoms[idx].locator = Some(locator.to_string());
    state.evidence_atoms[idx]
        .caveats
        .retain(|c| c != "missing evidence locator");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::{Assertion, Conditions, Confidence, Evidence, Flags, Provenance};
    use crate::events::{FindingEventInput, NULL_HASH, StateActor, StateTarget};
    use chrono::Utc;
    use serde_json::json;

    fn finding(id: &str) -> crate::bundle::FindingBundle {
        crate::bundle::FindingBundle::new(
            Assertion {
                text: format!("test finding {id}"),
                assertion_type: "mechanism".to_string(),
                entities: Vec::new(),
                relation: None,
                direction: None,
                causal_claim: None,
                causal_evidence_grade: None,
            },
            Evidence {
                evidence_type: "experimental".to_string(),
                model_system: String::new(),
                method: "test".to_string(),
                replicated: false,
                replication_count: None,
                evidence_spans: Vec::new(),
            },
            Conditions {
                text: "test".to_string(),
                duration: None,
            },
            Confidence::raw(0.5, "test", 0.8),
            Provenance {
                source_type: "published_paper".to_string(),
                doi: Some(format!("10.1/test-{id}")),
                url: None,
                title: format!("Source for {id}"),
                authors: Vec::new(),
                year: Some(2026),
                license: None,
                publisher: None,
                funders: Vec::new(),
                extraction: crate::bundle::Extraction::default(),
                review: None,
            },
            Flags {
                gap: false,
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
        )
    }

    #[test]
    fn replay_with_no_events_is_identity() {
        let state = project::assemble("test", vec![finding("a")], 0, 0, "test");
        let v = verify_replay(&state);
        assert!(v.ok, "diffs: {:?} note: {}", v.diffs, v.note);
        assert_eq!(v.replayed_snapshot_hash, v.materialized_snapshot_hash);
    }

    #[test]
    fn reducer_marks_finding_contested() {
        let f = finding("a");
        let mut state = project::assemble("test", vec![f.clone()], 0, 0, "test");
        let event = events::new_finding_event(FindingEventInput {
            kind: "finding.reviewed",
            finding_id: &f.id,
            actor_id: "reviewer:test",
            actor_type: "human",
            reason: "test",
            before_hash: &events::finding_hash(&f),
            after_hash: NULL_HASH,
            payload: json!({"status": "contested"}),
            caveats: vec![],
            timestamp: None,
        });
        apply_event(&mut state, &event).unwrap();
        assert!(state.findings[0].flags.contested);
    }

    #[test]
    fn reducer_retracts_finding() {
        let f = finding("a");
        let mut state = project::assemble("test", vec![f.clone()], 0, 0, "test");
        let event = StateEvent {
            schema: events::EVENT_SCHEMA.to_string(),
            id: "vev_test".to_string(),
            kind: "finding.retracted".into(),
            target: StateTarget {
                r#type: "finding".to_string(),
                id: f.id.clone(),
            },
            actor: StateActor {
                id: "reviewer:test".to_string(),
                r#type: "human".to_string(),
            },
            timestamp: Utc::now().to_rfc3339(),
            reason: "test retraction".to_string(),
            before_hash: events::finding_hash(&f),
            after_hash: NULL_HASH.to_string(),
            payload: json!({"proposal_id": "vpr_x"}),
            caveats: vec![],
            signature: None,
            schema_artifact_id: None,
        };
        apply_event(&mut state, &event).unwrap();
        assert!(state.findings[0].flags.retracted);
    }

    #[test]
    fn confidence_revision_replay_uses_event_payload_timestamp() {
        let f = finding("a");
        let mut expected = f.clone();
        let updated_at = "2026-05-07T23:30:00Z";
        let reason = "lower confidence after review";
        expected.confidence.score = 0.42;
        expected.confidence.basis = format!(
            "expert revision from {:.3} to {:.3}: {}",
            f.confidence.score, 0.42, reason
        );
        expected.confidence.method = ConfidenceMethod::ExpertJudgment;
        expected.updated = Some(updated_at.to_string());
        let mut state = project::assemble("test", vec![f.clone()], 0, 0, "test");
        let event = StateEvent {
            schema: events::EVENT_SCHEMA.to_string(),
            id: "vev_confidence".to_string(),
            kind: "finding.confidence_revised".into(),
            target: StateTarget {
                r#type: "finding".to_string(),
                id: f.id.clone(),
            },
            actor: StateActor {
                id: "reviewer:test".to_string(),
                r#type: "human".to_string(),
            },
            timestamp: "2026-05-07T23:31:00Z".to_string(),
            reason: reason.to_string(),
            before_hash: events::finding_hash(&f),
            after_hash: events::finding_hash(&expected),
            payload: json!({
                "previous_score": f.confidence.score,
                "new_score": 0.42,
                "updated_at": updated_at,
            }),
            caveats: vec![],
            signature: None,
            schema_artifact_id: None,
        };

        apply_event(&mut state, &event).unwrap();

        assert_eq!(state.findings[0].updated.as_deref(), Some(updated_at));
        assert_eq!(events::finding_hash(&state.findings[0]), event.after_hash);
    }

    #[test]
    fn reducer_rejects_unknown_kind() {
        let mut state = project::assemble("test", vec![], 0, 0, "test");
        let event = StateEvent {
            schema: events::EVENT_SCHEMA.to_string(),
            id: "vev_test".to_string(),
            kind: "finding.unknown_kind".into(),
            target: StateTarget {
                r#type: "finding".to_string(),
                id: "vf_x".to_string(),
            },
            actor: StateActor {
                id: "x".to_string(),
                r#type: "human".to_string(),
            },
            timestamp: Utc::now().to_rfc3339(),
            reason: "x".to_string(),
            before_hash: NULL_HASH.to_string(),
            after_hash: NULL_HASH.to_string(),
            payload: Value::Null,
            caveats: vec![],
            signature: None,
            schema_artifact_id: None,
        };
        let r = apply_event(&mut state, &event);
        assert!(r.is_err());
    }

    /// v0.49.3: the dispatch table in `apply_event` and the
    /// `REDUCER_MUTATION_KINDS` constant must agree. Adding a new
    /// match arm without updating the constant (or vice versa) makes
    /// CI fail loudly here, which then makes the cross-impl fixture
    /// coverage assertion fail correctly downstream. This is the
    /// single source of truth that retires the hand-maintained mirror.
    #[test]
    fn dispatch_handles_every_declared_kind() {
        for kind in REDUCER_MUTATION_KINDS {
            let mut state = project::assemble("test", vec![], 0, 0, "test");
            // Dummy event with the declared kind. The handler may
            // reject the payload (it's empty), but it MUST NOT reject
            // the kind itself with "unsupported event kind" — that
            // would prove the dispatch table is missing an arm for
            // a kind the constant declares.
            let event = StateEvent {
                schema: events::EVENT_SCHEMA.to_string(),
                id: "vev_dispatch_check".to_string(),
                kind: (*kind).into(),
                target: StateTarget {
                    r#type: "finding".to_string(),
                    id: "vf_x".to_string(),
                },
                actor: StateActor {
                    id: "x".to_string(),
                    r#type: "human".to_string(),
                },
                timestamp: Utc::now().to_rfc3339(),
                reason: String::new(),
                before_hash: NULL_HASH.to_string(),
                after_hash: NULL_HASH.to_string(),
                payload: Value::Null,
                caveats: vec![],
                signature: None,
                schema_artifact_id: None,
            };
            let r = apply_event(&mut state, &event);
            if let Err(e) = r {
                assert!(
                    !e.contains("unsupported event kind"),
                    "kind {kind:?} declared in REDUCER_MUTATION_KINDS \
                     but rejected by apply_event dispatch: {e}"
                );
            }
        }
    }

    /// The writer/reducer seam invariant: every kind the protocol can
    /// emit or store (`events::KNOWN_EVENT_KINDS` — the writer-side
    /// universe) must be handled by the dispatch, either with a real arm
    /// or an explicit no-op. A new writer kind without a reducer arm
    /// fails here instead of erroring on the next replay of a live log.
    /// (This is the test that would have caught `finding.superseded`
    /// being emittable-but-unreplayable.)
    #[test]
    fn every_known_kind_reduces() {
        for kind in events::KNOWN_EVENT_KINDS {
            let mut state = project::assemble("test", vec![], 0, 0, "test");
            let event = StateEvent {
                schema: events::EVENT_SCHEMA.to_string(),
                id: "vev_known_kind_check".to_string(),
                kind: (*kind).into(),
                target: StateTarget {
                    r#type: "finding".to_string(),
                    id: "vf_x".to_string(),
                },
                actor: StateActor {
                    id: "x".to_string(),
                    r#type: "human".to_string(),
                },
                timestamp: Utc::now().to_rfc3339(),
                reason: String::new(),
                before_hash: NULL_HASH.to_string(),
                after_hash: NULL_HASH.to_string(),
                payload: Value::Null,
                caveats: vec![],
                signature: None,
                schema_artifact_id: None,
            };
            if let Err(e) = apply_event(&mut state, &event) {
                assert!(
                    !e.contains("unsupported event kind"),
                    "kind {kind:?} is in events::KNOWN_EVENT_KINDS (a writer \
                     can emit it) but the reducer dispatch rejects it: {e}"
                );
            }
        }
    }

    fn project_with_one_atom(missing_locator: bool) -> Project {
        // `project::assemble` calls `sources::materialize_project`,
        // which derives one evidence atom per finding. The hand-built
        // atom below is appended after materialization with a distinct
        // id (`vea_test_atom`), so it survives alongside the derived
        // atom. Tests look up atoms by id via `atom_by_id`.
        let mut state = project::assemble("test-locator", vec![finding("a")], 0, 0, "test");
        state.sources.push(crate::sources::SourceRecord {
            id: "vs_test_source".to_string(),
            source_type: "paper".to_string(),
            locator: "doi:10.1/test-source".to_string(),
            content_hash: None,
            title: "Test source".to_string(),
            authors: Vec::new(),
            year: Some(2026),
            doi: Some("10.1/test-source".to_string()),
            pmid: None,
            imported_at: "2026-01-01T00:00:00Z".to_string(),
            extraction_mode: "manual".to_string(),
            source_quality: "declared".to_string(),
            caveats: Vec::new(),
            finding_ids: vec![state.findings[0].id.clone()],
        });
        state.evidence_atoms.push(crate::sources::EvidenceAtom {
            id: "vea_test_atom".to_string(),
            source_id: "vs_test_source".to_string(),
            finding_id: state.findings[0].id.clone(),
            locator: if missing_locator {
                None
            } else {
                Some("doi:10.1/already-set".to_string())
            },
            evidence_type: "experimental".to_string(),
            measurement_or_claim: "test claim".to_string(),
            supports_or_challenges: "supports".to_string(),
            condition_refs: Vec::new(),
            extraction_method: "manual".to_string(),
            human_verified: false,
            caveats: if missing_locator {
                vec!["missing evidence locator".to_string()]
            } else {
                Vec::new()
            },
        });
        state
    }

    fn atom_by_id<'a>(state: &'a Project, id: &str) -> &'a crate::sources::EvidenceAtom {
        state
            .evidence_atoms
            .iter()
            .find(|atom| atom.id == id)
            .expect("atom exists")
    }

    #[test]
    fn evidence_atom_locator_repaired_sets_locator_and_clears_caveat() {
        let mut state = project_with_one_atom(true);
        assert!(state.evidence_atoms[0].locator.is_none());
        let event = StateEvent {
            schema: crate::events::EVENT_SCHEMA.to_string(),
            id: "vev_test".to_string(),
            kind: "evidence_atom.locator_repaired".into(),
            target: StateTarget {
                r#type: "evidence_atom".to_string(),
                id: "vea_test_atom".to_string(),
            },
            actor: StateActor {
                id: "agent:test".to_string(),
                r#type: "agent".to_string(),
            },
            timestamp: Utc::now().to_rfc3339(),
            reason: "Mechanical repair from parent source".to_string(),
            before_hash: NULL_HASH.to_string(),
            after_hash: NULL_HASH.to_string(),
            payload: json!({
                "proposal_id": "vpr_test",
                "source_id": "vs_test_source",
                "locator": "doi:10.1/test-source",
            }),
            caveats: vec![],
            signature: None,
            schema_artifact_id: None,
        };
        apply_event(&mut state, &event).expect("apply locator_repaired");
        let atom = atom_by_id(&state, "vea_test_atom");
        assert_eq!(atom.locator.as_deref(), Some("doi:10.1/test-source"));
        assert!(atom.caveats.is_empty());
    }

    #[test]
    fn evidence_atom_locator_repaired_is_idempotent() {
        let mut state = project_with_one_atom(true);
        let event = StateEvent {
            schema: crate::events::EVENT_SCHEMA.to_string(),
            id: "vev_test".to_string(),
            kind: "evidence_atom.locator_repaired".into(),
            target: StateTarget {
                r#type: "evidence_atom".to_string(),
                id: "vea_test_atom".to_string(),
            },
            actor: StateActor {
                id: "agent:test".to_string(),
                r#type: "agent".to_string(),
            },
            timestamp: Utc::now().to_rfc3339(),
            reason: "Mechanical repair from parent source".to_string(),
            before_hash: NULL_HASH.to_string(),
            after_hash: NULL_HASH.to_string(),
            payload: json!({
                "proposal_id": "vpr_test",
                "source_id": "vs_test_source",
                "locator": "doi:10.1/test-source",
            }),
            caveats: vec![],
            signature: None,
            schema_artifact_id: None,
        };
        apply_event(&mut state, &event).expect("first apply");
        apply_event(&mut state, &event).expect("second apply is a no-op when locator matches");
        let atom = atom_by_id(&state, "vea_test_atom");
        assert_eq!(atom.locator.as_deref(), Some("doi:10.1/test-source"));
    }

    #[test]
    fn evidence_atom_locator_repaired_refuses_divergent_overwrite() {
        let mut state = project_with_one_atom(false);
        let event = StateEvent {
            schema: crate::events::EVENT_SCHEMA.to_string(),
            id: "vev_test".to_string(),
            kind: "evidence_atom.locator_repaired".into(),
            target: StateTarget {
                r#type: "evidence_atom".to_string(),
                id: "vea_test_atom".to_string(),
            },
            actor: StateActor {
                id: "agent:test".to_string(),
                r#type: "agent".to_string(),
            },
            timestamp: Utc::now().to_rfc3339(),
            reason: "Different repair".to_string(),
            before_hash: NULL_HASH.to_string(),
            after_hash: NULL_HASH.to_string(),
            payload: json!({
                "proposal_id": "vpr_test",
                "source_id": "vs_test_source",
                "locator": "doi:10.1/different",
            }),
            caveats: vec![],
            signature: None,
            schema_artifact_id: None,
        };
        let r = apply_event(&mut state, &event);
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("already has locator"));
    }

    #[test]
    fn evidence_atom_locator_repaired_does_not_mutate_findings() {
        // Cross-impl conformance: this event mutates evidence_atoms only.
        let mut state = project_with_one_atom(true);
        let hashes_before: Vec<String> = state
            .findings
            .iter()
            .map(crate::events::finding_hash)
            .collect();
        let event = StateEvent {
            schema: crate::events::EVENT_SCHEMA.to_string(),
            id: "vev_test".to_string(),
            kind: "evidence_atom.locator_repaired".into(),
            target: StateTarget {
                r#type: "evidence_atom".to_string(),
                id: "vea_test_atom".to_string(),
            },
            actor: StateActor {
                id: "agent:test".to_string(),
                r#type: "agent".to_string(),
            },
            timestamp: Utc::now().to_rfc3339(),
            reason: "Mechanical repair".to_string(),
            before_hash: NULL_HASH.to_string(),
            after_hash: NULL_HASH.to_string(),
            payload: json!({
                "proposal_id": "vpr_test",
                "source_id": "vs_test_source",
                "locator": "doi:10.1/test-source",
            }),
            caveats: vec![],
            signature: None,
            schema_artifact_id: None,
        };
        apply_event(&mut state, &event).expect("apply ok");
        let hashes_after: Vec<String> = state
            .findings
            .iter()
            .map(crate::events::finding_hash)
            .collect();
        assert_eq!(hashes_before, hashes_after);
    }

    #[test]
    fn attempt_deposit_and_resolution_roundtrip() {
        use crate::attempt::{Attempt, AttemptDraft, AttemptResolution, ResolutionEvent};
        use ed25519_dalek::SigningKey;
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let mut state = project::assemble("test", vec![], 0, 0, "test");

        let att = Attempt::build(
            AttemptDraft {
                problem: 309,
                kind: "lower_bound".into(),
                claim: "a(8) >= 33".to_string(),
                ..Default::default()
            },
            &key,
        )
        .unwrap();
        let dep = att.deposit_event("agent:opus", "agent", "bank attempt");
        apply_event(&mut state, &dep).unwrap();
        assert_eq!(state.attempts.len(), 1);
        assert_eq!(state.attempts[0].attempt_id, att.attempt_id);
        // Idempotent: re-applying the same deposit is a no-op.
        apply_event(&mut state, &dep).unwrap();
        assert_eq!(state.attempts.len(), 1);
        // No resolution yet -> still a candidate.
        assert!(state.head_resolution(&att.attempt_id).is_none());

        let res = ResolutionEvent::new(
            &att.attempt_id,
            AttemptResolution::Verified {
                gate_ref: "gate@vva_x".to_string(),
            },
            "reviewer:will-blair",
            "2026-06-09T00:00:00Z",
            "two independent methods",
        )
        .unwrap();
        apply_event(&mut state, &res.to_state_event("reviewer", "verified")).unwrap();
        assert_eq!(
            state
                .head_resolution(&att.attempt_id)
                .unwrap()
                .resolution
                .as_str(),
            "verified"
        );

        // A later refutation becomes the head (latest by `at`); history kept.
        let res2 = ResolutionEvent::new(
            &att.attempt_id,
            AttemptResolution::Refuted {
                by_probe: "case_b".to_string(),
            },
            "reviewer:skeptic",
            "2026-06-10T00:00:00Z",
            "Case B breaks it",
        )
        .unwrap();
        apply_event(&mut state, &res2.to_state_event("reviewer", "refuted")).unwrap();
        assert_eq!(
            state
                .head_resolution(&att.attempt_id)
                .unwrap()
                .resolution
                .as_str(),
            "refuted"
        );
        assert_eq!(state.attempt_resolutions.len(), 2);
    }

    #[test]
    fn forged_attempt_deposit_is_rejected_by_reducer() {
        use crate::attempt::{Attempt, AttemptDraft};
        use ed25519_dalek::SigningKey;
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let mut state = project::assemble("test", vec![], 0, 0, "test");
        let att = Attempt::build(
            AttemptDraft {
                problem: 1,
                kind: "k".into(),
                claim: "c".to_string(),
                ..Default::default()
            },
            &key,
        )
        .unwrap();
        let mut dep = att.deposit_event("agent:opus", "agent", "x");
        // Hand-edit the embedded attempt: the signature no longer verifies.
        dep.payload["attempt"]["claim"] = serde_json::json!("tampered");
        assert!(apply_event(&mut state, &dep).is_err());
        assert_eq!(state.attempts.len(), 0);
    }
}
