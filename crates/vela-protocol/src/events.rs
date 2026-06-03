//! Canonical replayable frontier events.
//!
//! Events are the authoritative record for user-visible state transitions in
//! the finding-centered v0 kernel. Frontier snapshots remain the convenient
//! materialized state, but checks and proof packets can validate the event log.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::bundle::FindingBundle;
use crate::canonical;
use crate::project::Project;

pub const EVENT_SCHEMA: &str = "vela.event.v0.1";
pub const NULL_HASH: &str = "sha256:null";

/// v0.49: explicit event kind for actor-key revocation. Coalition
/// governance promises that key compromise is handled by a signed
/// `RevocationEvent` that names the key, the moment of compromise,
/// and the recommended replacement. This constant pairs with
/// `RevocationPayload` and `new_revocation_event` below.
///
/// Existing signed history stays valid as a record of what was
/// signed when; clients that re-verify against the post-revocation
/// actor list flag any signature whose `signed_at` is after the
/// `revoked_at` moment. The hub is transport, not authority — it
/// stores the revocation alongside the entries that referenced the
/// revoked key, lets readers decide.
pub const EVENT_KIND_KEY_REVOKE: &str = "key.revoke";

/// v0.49: NegativeResult lifecycle event kinds. Pair with the
/// `NegativeResult` first-class object in `bundle.rs`. The substrate
/// records nulls through the same proposal -> canonical event ->
/// reducer pipeline as findings, so an underpowered Phase III readout
/// and a confirmatory replication-failure both leave the same kind of
/// auditable trace.
pub const EVENT_KIND_NEGATIVE_RESULT_ASSERTED: &str = "negative_result.asserted";
pub const EVENT_KIND_NEGATIVE_RESULT_REVIEWED: &str = "negative_result.reviewed";
pub const EVENT_KIND_NEGATIVE_RESULT_RETRACTED: &str = "negative_result.retracted";

/// v0.50: Trajectory lifecycle event kinds. Pair with the
/// `Trajectory` first-class object in `bundle.rs`. The substrate
/// records search paths through the same proposal -> canonical event
/// -> reducer pipeline as findings, so an agent that explored five
/// branches before arriving at a finding leaves a step-by-step audit
/// the next agent can read instead of re-deriving.
pub const EVENT_KIND_TRAJECTORY_CREATED: &str = "trajectory.created";
pub const EVENT_KIND_TRAJECTORY_STEP_APPENDED: &str = "trajectory.step_appended";
pub const EVENT_KIND_TRAJECTORY_REVIEWED: &str = "trajectory.reviewed";
pub const EVENT_KIND_TRAJECTORY_RETRACTED: &str = "trajectory.retracted";

/// Generic artifact lifecycle. Carries the full `Artifact` inline on
/// `payload.artifact` so protocol snapshots can be replayed without
/// resolving a sidecar file first.
pub const EVENT_KIND_ARTIFACT_ASSERTED: &str = "artifact.asserted";
pub const EVENT_KIND_ARTIFACT_REVIEWED: &str = "artifact.reviewed";
pub const EVENT_KIND_ARTIFACT_RETRACTED: &str = "artifact.retracted";

/// v0.51: Re-classify a finding/negative_result/trajectory's read-side
/// access tier. Audit-trail event for the dual-use channel: the
/// fact that an object's tier changed (and who changed it, when, with
/// what reason) is itself part of the substrate's accountability
/// surface and must replay deterministically.
pub const EVENT_KIND_TIER_SET: &str = "tier.set";

/// v0.56: Mechanical evidence-atom locator repair. Targets a single
/// evidence atom by id and sets its `locator` field to the value
/// resolved from the parent source's locator. Carries the resolved
/// locator string and the source id it was derived from on the event
/// payload so a fresh replay reconstructs the atom's locator without
/// needing to re-resolve the source.
///
/// This event mutates `state.evidence_atoms[i].locator` and clears the
/// "missing evidence locator" caveat on the same atom. It does not
/// touch `state.findings`, so cross-impl reducer fixtures whose
/// post-replay digest covers `findings[]` only treat this event as a
/// no-op on finding state. The Rust reducer still has an explicit arm
/// to avoid silently dropping the repair from a fresh replay.
pub const EVENT_KIND_EVIDENCE_ATOM_LOCATOR_REPAIRED: &str = "evidence_atom.locator_repaired";

/// v0.57: Mechanical evidence-span repair on a finding. Appends one
/// `{section, text}` span to `state.findings[i].evidence.evidence_spans`.
/// Required payload: `{proposal_id, section, text}`. The reducer arm
/// is idempotent under identical re-application (refuses to append an
/// equal span twice on the same finding).
pub const EVENT_KIND_FINDING_SPAN_REPAIRED: &str = "finding.span_repaired";

/// v0.57: Entity resolution on a finding. Sets the canonical_id,
/// resolution_method, resolution_provenance, and resolution_confidence
/// fields on a single entity inside `state.findings[i].assertion.entities`,
/// and clears the entity's `needs_review` flag.
/// Required payload: `{proposal_id, entity_name, source, id, confidence}`
/// plus optional `matched_name`, `resolution_method`, `resolution_provenance`.
pub const EVENT_KIND_FINDING_ENTITY_RESOLVED: &str = "finding.entity_resolved";

/// v0.79.4: Per-event attestation. The substrate's existing
/// frontier-wide signing path (`vela attest <frontier>`) is
/// coarse-grained: it signs every unsigned finding under one key.
/// Per-event attestation lets a reviewer or external verifier
/// attest one specific canonical event (`vev_*`) by emitting a
/// new `attestation.recorded` event that points at it.
///
/// Required payload: `{target_event_id, attester_id, scope_note}`.
/// Optional: `scopes`, `reviewer_role`, `orcid`, `ror`,
/// `attestation_id`, `signature` (Ed25519 over the target event's
/// preimage), `proof_id` (`vpf_*` from the v0.75 Carina Proof
/// primitive when the attestation is backed by a proof-assistant
/// verification), `signed_at` (RFC3339).
///
/// Reducer arm: no-op on findings. Attestations live as
/// append-only canonical events; consumers (Workbench, audit
/// scripts, hub mirrors) project them per-event by reading the
/// log.
pub const EVENT_KIND_ATTESTATION_RECORDED: &str = "attestation.recorded";

/// v0.79: Add a new entity to a finding's `assertion.entities` after
/// the finding was first asserted. Closes the v0.78.4 honest gap: the
/// substrate previously could only attach entities at finding-creation
/// time, so reviewers had to append new findings to add tags.
///
/// `finding.entity_added` is append-only: the new entity is added to
/// the list, never replacing or mutating existing entries. Entity
/// resolution (assigning a canonical id) is still done via
/// `finding.entity_resolved` after the fact.
///
/// Required payload: `{proposal_id, entity_name, entity_type, reason}`.
/// Optional: `entity_role`, `provenance` (source paper / reviewer
/// context for why this entity belongs).
///
/// Reducer arm: pushes a new `Entity{name, type, ...}` onto
/// `Project.findings[id].assertion.entities`. Idempotent on
/// `(finding_id, entity_name)`: re-applying with the same name + type
/// is a no-op, so federation re-sync stays clean.
pub const EVENT_KIND_FINDING_ENTITY_ADDED: &str = "finding.entity_added";

/// v0.70: Replication deposit. The substrate has had `Replication`
/// as a first-class kernel object since v0.32 + `vela replicate`
/// CLI, but the side-table mutation happened via direct file write.
/// v0.70 makes the deposit event-driven so federation sync can
/// propagate it. Reducer arm appends to `Project.replications` if
/// the `vrep_*` id is not already present (idempotent under
/// re-application). The CLI + Workbench paths emit this event;
/// raw `vrep_<id>` entries on `Project.replications` from
/// pre-v0.70 frontiers continue to load without an event.
/// Required payload: `{replication}` (the full Replication record).
pub const EVENT_KIND_REPLICATION_DEPOSITED: &str = "replication.deposited";

/// v0.70: Prediction deposit. Same shape as `replication.deposited`
/// for `Project.predictions`. Deposits a `Prediction` record onto
/// the frontier; reducer arm appends if `vpred_*` id is new.
/// Required payload: `{prediction}` (the full Prediction record).
pub const EVENT_KIND_PREDICTION_DEPOSITED: &str = "prediction.deposited";

/// v0.67: Bridge review verdict. A reviewer confirms or refutes a
/// `vbr_*` cross-frontier bridge by emitting this canonical event,
/// which the reducer applies by setting the bridge's status field.
/// Pre-v0.67 bridge status was mutated by file write only; v0.67
/// makes the verdict an immutable canonical event so federation
/// sync propagates it. Required payload: `{bridge_id, status,
/// note}`. `status` must be one of `confirmed` or `refuted`.
pub const EVENT_KIND_BRIDGE_REVIEWED: &str = "bridge.reviewed";

/// Review verdict over non-mutating frontier observation material,
/// such as research traces and correction returns. This records what
/// entered the review ledger without asserting a finding by itself.
pub const EVENT_KIND_FRONTIER_OBSERVATION_REVIEWED: &str = "frontier.observation_reviewed";

/// v0.59: Federation conflict resolution. Pairs with the existing
/// `frontier.conflict_detected` event. The conflict event itself
/// stays in the log unchanged (immutable history); the resolved
/// event records the reviewer's verdict, the conflict it pertains
/// to, and an optional pointer at the winning proposal.
///
/// Like its sibling `frontier.conflict_detected` and
/// `frontier.synced_with_peer`, this is a frontier-level
/// observation, not a finding-state mutation: the reducer arm is
/// a no-op on `Project.findings`. Consumers (Workbench inbox,
/// audit scripts, hub mirrors) pair a `conflict_detected` with
/// its `conflict_resolved` by matching `conflict_event_id` to the
/// detected event's id on read.
///
/// Required payload: `{conflict_event_id, resolved_by,
/// resolution_note}`. Optional: `winning_proposal_id`.
pub const EVENT_KIND_FRONTIER_CONFLICT_RESOLVED: &str = "frontier.conflict_resolved";

/// T7: a reviewer's decision on a Contradiction object (`vcx_`). The
/// event carries the full resolved `Contradiction` in
/// `payload.contradiction`; the reducer upserts it into
/// `Project.contradictions` (latest resolution per id wins). This is
/// the only canonical state a contradiction accrues — candidates are
/// derived from the graph and never written. Honest by construction:
/// the stored object's status records a *named reviewer's* judgment,
/// never platform-adjudicated truth.
pub const EVENT_KIND_CONTRADICTION_RESOLVED: &str = "contradiction.resolved";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateTarget {
    pub r#type: String,
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateActor {
    pub id: String,
    pub r#type: String,
}

/// Canonical actor classification. Provenance must never claim more
/// than is true: an `agent:`-prefixed id, or one whose handle ends in
/// `-bot` / `-sim`, is a machine actor, never `human`. This is the one
/// classifier used at event construction and in review-count stats so
/// an agent or bot is never recorded or counted as human review.
pub fn actor_kind(id: &str) -> &'static str {
    let id = id.trim();
    let handle = id.split(':').next_back().unwrap_or(id);
    if id.starts_with("agent:")
        || id.starts_with("sim:")
        || handle.ends_with("-bot")
        || handle.ends_with("-sim")
    {
        "agent"
    } else {
        "human"
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateEvent {
    #[serde(default = "default_schema")]
    pub schema: String,
    pub id: String,
    pub kind: String,
    pub target: StateTarget,
    pub actor: StateActor,
    pub timestamp: String,
    pub reason: String,
    pub before_hash: String,
    pub after_hash: String,
    #[serde(default)]
    pub payload: Value,
    #[serde(default)]
    pub caveats: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// v0.89: optional reference to a content-addressed schema /
    /// reducer artifact in a [`crate::schema_registry::SchemaRegistry`].
    /// When present, replay tooling can verify the artifact exists
    /// before applying the event (per docs/THEORY.md §5.1 / §5.5).
    /// **Not** part of the canonical event-id preimage: setting
    /// or clearing this field does NOT change `event.id`. Pre-v0.89
    /// events default to `None` and serialize byte-identically.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_artifact_id: Option<String>,
}

pub struct FindingEventInput<'a> {
    pub kind: &'a str,
    pub finding_id: &'a str,
    pub actor_id: &'a str,
    pub actor_type: &'a str,
    pub reason: &'a str,
    pub before_hash: &'a str,
    pub after_hash: &'a str,
    pub payload: Value,
    pub caveats: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventLogSummary {
    pub count: usize,
    pub kinds: BTreeMap<String, usize>,
    pub first_timestamp: Option<String>,
    pub last_timestamp: Option<String>,
    pub duplicate_ids: Vec<String>,
    pub orphan_targets: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayReport {
    pub ok: bool,
    pub status: String,
    pub event_log: EventLogSummary,
    pub source_hash: String,
    pub event_log_hash: String,
    pub replayed_hash: String,
    pub current_hash: String,
    pub conflicts: Vec<String>,
}

fn default_schema() -> String {
    EVENT_SCHEMA.to_string()
}

pub fn new_finding_event(input: FindingEventInput<'_>) -> StateEvent {
    let timestamp = Utc::now().to_rfc3339();
    let mut event = StateEvent {
        schema: EVENT_SCHEMA.to_string(),
        id: String::new(),
        kind: input.kind.to_string(),
        target: StateTarget {
            r#type: "finding".to_string(),
            id: input.finding_id.to_string(),
        },
        actor: StateActor {
            id: input.actor_id.to_string(),
            r#type: input.actor_type.to_string(),
        },
        timestamp,
        reason: input.reason.to_string(),
        before_hash: input.before_hash.to_string(),
        after_hash: input.after_hash.to_string(),
        payload: input.payload,
        caveats: input.caveats,
        signature: None,
        schema_artifact_id: None,
    };
    event.id = event_id(&event);
    event
}

/// Payload of an `EVENT_KIND_KEY_REVOKE` event. Carries the
/// revoked Ed25519 pubkey (hex-encoded), the moment compromise was
/// detected (ISO-8601), an optional replacement pubkey the actor is
/// migrating to, and a free-form reason string. Stored on the event's
/// `payload` field; the event's `actor` is the actor whose key is
/// being revoked, and the event itself must be signed by a key that
/// was authoritative *before* the revocation (typically a co-signer
/// or the actor's prior key — never the revoked key itself).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevocationPayload {
    /// The Ed25519 pubkey being revoked, hex-encoded (64 chars).
    pub revoked_pubkey: String,
    /// ISO-8601 moment when compromise was detected. Signatures
    /// whose `signed_at` falls after this should be flagged on
    /// re-verification.
    pub revoked_at: String,
    /// Optional replacement pubkey the actor is now signing with,
    /// hex-encoded. Reviewers re-verifying signed history use this
    /// to walk forward to the new key.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub replacement_pubkey: String,
    /// Free-form reason — "key file leaked", "stolen device",
    /// "scheduled rotation", etc. Reviewer-facing only; the
    /// substrate doesn't enumerate.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
}

/// Construct a signed-shape `key.revoke` event for the given actor.
/// Mirrors `new_finding_event` in shape but targets an actor and
/// carries a `RevocationPayload` in `payload`. The returned event is
/// unsigned (caller signs it); `event.id` is the canonical content
/// address of the unsigned shape.
pub fn new_revocation_event(
    actor_id: &str,
    actor_type: &str,
    payload: RevocationPayload,
    reason: &str,
    before_hash: &str,
    after_hash: &str,
) -> StateEvent {
    let timestamp = Utc::now().to_rfc3339();
    let payload_value =
        serde_json::to_value(&payload).expect("RevocationPayload serializes to a JSON object");
    let mut event = StateEvent {
        schema: EVENT_SCHEMA.to_string(),
        id: String::new(),
        kind: EVENT_KIND_KEY_REVOKE.to_string(),
        target: StateTarget {
            r#type: "actor".to_string(),
            id: actor_id.to_string(),
        },
        actor: StateActor {
            id: actor_id.to_string(),
            r#type: actor_type.to_string(),
        },
        timestamp,
        reason: reason.to_string(),
        before_hash: before_hash.to_string(),
        after_hash: after_hash.to_string(),
        payload: payload_value,
        caveats: Vec::new(),
        signature: None,
        schema_artifact_id: None,
    };
    event.id = event_id(&event);
    event
}

/// Construct an `evidence_atom.locator_repaired` event targeting an
/// evidence atom by id. The payload carries the resolved locator and
/// the parent source id so a fresh replay can both apply the repair
/// and reconstruct its derivation. Returned event is unsigned; the
/// caller signs it before persisting.
pub fn new_evidence_atom_locator_repair_event(
    atom_id: &str,
    actor_id: &str,
    actor_type: &str,
    reason: &str,
    before_hash: &str,
    after_hash: &str,
    payload: Value,
    caveats: Vec<String>,
) -> StateEvent {
    let timestamp = Utc::now().to_rfc3339();
    let mut event = StateEvent {
        schema: EVENT_SCHEMA.to_string(),
        id: String::new(),
        kind: EVENT_KIND_EVIDENCE_ATOM_LOCATOR_REPAIRED.to_string(),
        target: StateTarget {
            r#type: "evidence_atom".to_string(),
            id: atom_id.to_string(),
        },
        actor: StateActor {
            id: actor_id.to_string(),
            r#type: actor_type.to_string(),
        },
        timestamp,
        reason: reason.to_string(),
        before_hash: before_hash.to_string(),
        after_hash: after_hash.to_string(),
        payload,
        caveats,
        signature: None,
        schema_artifact_id: None,
    };
    event.id = event_id(&event);
    event
}

/// v0.59: build a `frontier.conflict_resolved` event. Frontier-level
/// observation; the target is the conflict's frontier_id (same
/// shape as `frontier.synced_with_peer` and
/// `frontier.conflict_detected`).
pub fn new_frontier_conflict_resolved_event(
    frontier_id: &str,
    actor_id: &str,
    actor_type: &str,
    reason: &str,
    payload: Value,
    caveats: Vec<String>,
) -> StateEvent {
    let timestamp = Utc::now().to_rfc3339();
    let mut event = StateEvent {
        schema: EVENT_SCHEMA.to_string(),
        id: String::new(),
        kind: EVENT_KIND_FRONTIER_CONFLICT_RESOLVED.to_string(),
        target: StateTarget {
            r#type: "frontier_observation".to_string(),
            id: frontier_id.to_string(),
        },
        actor: StateActor {
            id: actor_id.to_string(),
            r#type: actor_type.to_string(),
        },
        timestamp,
        reason: reason.to_string(),
        before_hash: NULL_HASH.to_string(),
        after_hash: NULL_HASH.to_string(),
        payload,
        caveats,
        signature: None,
        schema_artifact_id: None,
    };
    event.id = event_id(&event);
    event
}

/// v0.67: build a `bridge.reviewed` event. Target is the bridge's
/// content-addressed id (`vbr_*`). Reducer arm projects the verdict
/// onto the bridge's status field on read.
pub fn new_bridge_reviewed_event(
    bridge_id: &str,
    actor_id: &str,
    actor_type: &str,
    reason: &str,
    payload: Value,
    caveats: Vec<String>,
) -> StateEvent {
    let timestamp = Utc::now().to_rfc3339();
    let mut event = StateEvent {
        schema: EVENT_SCHEMA.to_string(),
        id: String::new(),
        kind: EVENT_KIND_BRIDGE_REVIEWED.to_string(),
        target: StateTarget {
            r#type: "bridge".to_string(),
            id: bridge_id.to_string(),
        },
        actor: StateActor {
            id: actor_id.to_string(),
            r#type: actor_type.to_string(),
        },
        timestamp,
        reason: reason.to_string(),
        before_hash: NULL_HASH.to_string(),
        after_hash: NULL_HASH.to_string(),
        payload,
        caveats,
        signature: None,
        schema_artifact_id: None,
    };
    event.id = event_id(&event);
    event
}

/// T7: build a `contradiction.resolved` event. Target is the
/// contradiction's content-addressed id (`vcx_*`); the full resolved
/// object travels in `payload.contradiction`. The reducer arm upserts
/// it into `Project.contradictions`.
pub fn new_contradiction_resolved_event(
    contradiction_id: &str,
    actor_id: &str,
    actor_type: &str,
    reason: &str,
    payload: Value,
    caveats: Vec<String>,
) -> StateEvent {
    let timestamp = Utc::now().to_rfc3339();
    let mut event = StateEvent {
        schema: EVENT_SCHEMA.to_string(),
        id: String::new(),
        kind: EVENT_KIND_CONTRADICTION_RESOLVED.to_string(),
        target: StateTarget {
            r#type: "contradiction".to_string(),
            id: contradiction_id.to_string(),
        },
        actor: StateActor {
            id: actor_id.to_string(),
            r#type: actor_type.to_string(),
        },
        timestamp,
        reason: reason.to_string(),
        before_hash: NULL_HASH.to_string(),
        after_hash: NULL_HASH.to_string(),
        payload,
        caveats,
        signature: None,
        schema_artifact_id: None,
    };
    event.id = event_id(&event);
    event
}

/// Canonical hash of one evidence atom. Mirrors `finding_hash` for the
/// before/after pair on locator-repair events so a chain validator can
/// confirm that exactly the named atom changed and exactly the named
/// repair was applied.
pub fn evidence_atom_hash(atom: &crate::sources::EvidenceAtom) -> String {
    let bytes = canonical::to_canonical_bytes(atom).unwrap_or_default();
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

pub fn evidence_atom_hash_by_id(frontier: &Project, atom_id: &str) -> String {
    frontier
        .evidence_atoms
        .iter()
        .find(|atom| atom.id == atom_id)
        .map(evidence_atom_hash)
        .unwrap_or_else(|| NULL_HASH.to_string())
}

pub fn finding_hash(finding: &FindingBundle) -> String {
    // Per Protocol §5, links are "review surfaces" — typed relationships
    // between findings inferred at compile or review time, NOT part of the
    // finding's content commitment. They are mutable: `vela link add`
    // appends links without emitting a state-event (links don't change
    // what the finding asserts; they change which findings know about
    // each other). For event-replay validity the finding hash must therefore
    // exclude `links`, otherwise any CLI-added link breaks the asserted-event
    // chain. v0.12: hash a links-cleared copy. State-changing events
    // (caveat/note/review/revise/retract) still mutate annotations/flags/
    // confidence — those remain in the hash and chain through events properly.
    let mut hashable = finding.clone();
    hashable.links.clear();
    let bytes = canonical::to_canonical_bytes(&hashable).unwrap_or_default();
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

pub fn finding_hash_by_id(frontier: &Project, finding_id: &str) -> String {
    frontier
        .findings
        .iter()
        .find(|finding| finding.id == finding_id)
        .map(finding_hash)
        .unwrap_or_else(|| NULL_HASH.to_string())
}

pub fn event_log_hash(events: &[StateEvent]) -> String {
    let bytes = canonical::to_canonical_bytes(events).unwrap_or_default();
    hex::encode(Sha256::digest(bytes))
}

pub fn snapshot_hash(frontier: &Project) -> String {
    let value = serde_json::to_value(frontier).unwrap_or(Value::Null);
    let mut value = value;
    if let Value::Object(map) = &mut value {
        map.remove("events");
        map.remove("signatures");
        map.remove("proof_state");
    }
    let bytes = canonical::to_canonical_bytes(&value).unwrap_or_default();
    hex::encode(Sha256::digest(bytes))
}

pub fn events_for_finding<'a>(frontier: &'a Project, finding_id: &str) -> Vec<&'a StateEvent> {
    frontier
        .events
        .iter()
        .filter(|event| event.target.r#type == "finding" && event.target.id == finding_id)
        .collect()
}

pub fn replay_report(frontier: &Project) -> ReplayReport {
    let event_log = summarize(frontier);
    let mut conflicts = Vec::new();

    if frontier.events.is_empty() {
        let current_hash = snapshot_hash(frontier);
        return ReplayReport {
            ok: true,
            status: "no_events".to_string(),
            event_log,
            source_hash: current_hash.clone(),
            event_log_hash: event_log_hash(&frontier.events),
            replayed_hash: current_hash.clone(),
            current_hash,
            conflicts,
        };
    }

    for duplicate in &event_log.duplicate_ids {
        conflicts.push(format!("duplicate event id: {duplicate}"));
    }
    for orphan in &event_log.orphan_targets {
        conflicts.push(format!("orphan event target: {orphan}"));
    }

    let mut chains = BTreeMap::<String, Vec<&StateEvent>>::new();
    for event in &frontier.events {
        if event.schema != EVENT_SCHEMA {
            conflicts.push(format!(
                "unsupported event schema for {}: {}",
                event.id, event.schema
            ));
        }
        if event.reason.trim().is_empty() {
            conflicts.push(format!("event {} has empty reason", event.id));
        }
        if event.before_hash.trim().is_empty() || event.after_hash.trim().is_empty() {
            conflicts.push(format!("event {} has empty hash boundary", event.id));
        }
        // Phase E: per-kind payload schema validation. Each event kind has
        // a normative payload shape documented in `docs/PROTOCOL.md` §6;
        // payloads that don't match are conformance failures, not just
        // "weird optional content."
        if let Err(err) = validate_event_payload(&event.kind, &event.payload) {
            conflicts.push(format!("event {} payload invalid: {err}", event.id));
        }
        chains
            .entry(format!("{}:{}", event.target.r#type, event.target.id))
            .or_default()
            .push(event);
    }

    for (target, events) in chains {
        let mut sorted = events;
        sorted.sort_by(|a, b| a.timestamp.cmp(&b.timestamp).then(a.id.cmp(&b.id)));
        for pair in sorted.windows(2) {
            let previous = pair[0];
            let next = pair[1];
            if previous.after_hash != next.before_hash {
                conflicts.push(format!(
                    "event chain break for {target}: {} after_hash does not match {} before_hash",
                    previous.id, next.id
                ));
            }
        }
        if let Some(last) = sorted.last()
            && last.target.r#type == "finding"
        {
            let current = finding_hash_by_id(frontier, &last.target.id);
            if current != last.after_hash {
                conflicts.push(format!(
                    "materialized finding {} hash does not match last event {}",
                    last.target.id, last.id
                ));
            }
        }
    }

    let current_hash = snapshot_hash(frontier);
    let ok = conflicts.is_empty();
    ReplayReport {
        ok,
        status: if ok { "ok" } else { "conflict" }.to_string(),
        event_log,
        source_hash: current_hash.clone(),
        event_log_hash: event_log_hash(&frontier.events),
        replayed_hash: if ok {
            current_hash.clone()
        } else {
            "unavailable".to_string()
        },
        current_hash,
        conflicts,
    }
}

pub fn replay_report_json(frontier: &Project) -> Value {
    serde_json::to_value(replay_report(frontier)).unwrap_or_else(|_| json!({"ok": false}))
}

pub fn summarize(frontier: &Project) -> EventLogSummary {
    let mut kinds = BTreeMap::<String, usize>::new();
    let mut seen = BTreeSet::<String>::new();
    let mut duplicate_ids = BTreeSet::<String>::new();
    let finding_ids = frontier
        .findings
        .iter()
        .map(|finding| finding.id.as_str())
        .collect::<BTreeSet<_>>();
    let mut orphan_targets = BTreeSet::<String>::new();
    let mut timestamps = Vec::<String>::new();

    for event in &frontier.events {
        *kinds.entry(event.kind.clone()).or_default() += 1;
        if !seen.insert(event.id.clone()) {
            duplicate_ids.insert(event.id.clone());
        }
        if event.target.r#type == "finding"
            && !finding_ids.contains(event.target.id.as_str())
            && event.kind != "finding.retracted"
        {
            orphan_targets.insert(event.target.id.clone());
        }
        timestamps.push(event.timestamp.clone());
    }
    timestamps.sort();

    EventLogSummary {
        count: frontier.events.len(),
        kinds,
        first_timestamp: timestamps.first().cloned(),
        last_timestamp: timestamps.last().cloned(),
        duplicate_ids: duplicate_ids.into_iter().collect(),
        orphan_targets: orphan_targets.into_iter().collect(),
    }
}

/// Validate a canonical event's payload against its per-kind schema.
///
/// Each event kind has a normative payload shape. Phase E pins those
/// shapes so a second implementation can reject malformed events
/// without per-kind ad-hoc parsing. The schemas are documented in
/// `docs/PROTOCOL.md` §6 and conformance-checked at the v0.3 level.
///
/// Unknown kinds are rejected so future-event-kind reads from older
/// implementations fail fast rather than silently accepting opaque
/// content.
fn validate_sha256_commitment(field: &str, value: &str) -> Result<(), String> {
    let hex = value.strip_prefix("sha256:").unwrap_or(value);
    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("{field} must be sha256:<64hex>"));
    }
    Ok(())
}

pub fn validate_event_payload(kind: &str, payload: &Value) -> Result<(), String> {
    let object = payload.as_object().ok_or_else(|| {
        if matches!(payload, Value::Null) {
            "payload must be a JSON object (got null)".to_string()
        } else {
            "payload must be a JSON object".to_string()
        }
    })?;
    let require_str = |key: &str| -> Result<&str, String> {
        object
            .get(key)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("missing required string field '{key}'"))
    };
    let require_f64 = |key: &str| -> Result<f64, String> {
        object
            .get(key)
            .and_then(Value::as_f64)
            .ok_or_else(|| format!("missing required number field '{key}'"))
    };
    match kind {
        "finding.asserted" => {
            // proposal_id required; optional `finding` for v0.3 genesis
            // events that carry the bootstrap finding inline.
            require_str("proposal_id")?;
        }
        "finding.reviewed" => {
            require_str("proposal_id")?;
            let status = require_str("status")?;
            if !matches!(
                status,
                "accepted" | "approved" | "contested" | "needs_revision" | "rejected"
            ) {
                return Err(format!("invalid review status '{status}'"));
            }
        }
        "diff_pack.released" => {
            let pack_id = require_str("pack_id")?;
            if !pack_id.starts_with("vsd_") {
                return Err(format!(
                    "payload.pack_id must start with 'vsd_', got '{pack_id}'"
                ));
            }
            let frontier_id = require_str("frontier_id")?;
            if !frontier_id.starts_with("vfr_") {
                return Err(format!(
                    "payload.frontier_id must start with 'vfr_', got '{frontier_id}'"
                ));
            }
            let summary = require_str("summary")?;
            if summary.trim().is_empty() {
                return Err("payload.summary must be non-empty".to_string());
            }
            let aggregate_kind = require_str("aggregate_kind")?;
            if aggregate_kind.trim().is_empty() {
                return Err("payload.aggregate_kind must be non-empty".to_string());
            }
        }
        "diff_pack.reviewed" => {
            let pack_id = require_str("pack_id")?;
            if !pack_id.starts_with("vsd_") {
                return Err(format!(
                    "payload.pack_id must start with 'vsd_', got '{pack_id}'"
                ));
            }
            let verdict = require_str("verdict")?;
            if !matches!(verdict, "accept" | "reject" | "revise") {
                return Err(format!(
                    "payload.verdict must be accept|reject|revise, got '{verdict}'"
                ));
            }
            let reviewer = require_str("reviewer_actor")?;
            if reviewer.trim().is_empty() {
                return Err("payload.reviewer_actor must be non-empty".to_string());
            }
            let reason = require_str("reason")?;
            if reason.trim().is_empty() {
                return Err("payload.reason must be non-empty".to_string());
            }
            if let Some(applied) = object.get("applied_members") {
                applied
                    .as_array()
                    .ok_or("payload.applied_members must be an array when present")?;
            }
            if let Some(sdk_only) = object.get("sdk_only_members") {
                sdk_only
                    .as_array()
                    .ok_or("payload.sdk_only_members must be an array when present")?;
            }
        }
        "finding.noted" | "finding.caveated" => {
            require_str("proposal_id")?;
            require_str("annotation_id")?;
            let text = require_str("text")?;
            if text.trim().is_empty() {
                return Err("payload.text must be non-empty".to_string());
            }
            // Phase β (v0.6): optional structured `provenance` block.
            // When present, MUST be an object and MUST carry at least one
            // identifying field (doi/pmid/title). An all-empty
            // `provenance: {}` is a contract violation, not a tolerable
            // default — agents that pass the field are expected to mean it.
            if let Some(prov) = object.get("provenance") {
                let prov_obj = prov
                    .as_object()
                    .ok_or("payload.provenance must be a JSON object when present")?;
                let has_id = prov_obj
                    .get("doi")
                    .and_then(Value::as_str)
                    .is_some_and(|s| !s.trim().is_empty())
                    || prov_obj
                        .get("pmid")
                        .and_then(Value::as_str)
                        .is_some_and(|s| !s.trim().is_empty())
                    || prov_obj
                        .get("title")
                        .and_then(Value::as_str)
                        .is_some_and(|s| !s.trim().is_empty());
                if !has_id {
                    return Err(
                        "payload.provenance must include at least one of doi/pmid/title"
                            .to_string(),
                    );
                }
            }
        }
        "source_text.reviewed" => {
            require_str("proposal_id")?;
            let status = require_str("status")?;
            if !matches!(status, "accepted" | "approved") {
                return Err(format!("invalid source text review status '{status}'"));
            }
            let promotion_id = require_str("source_text_promotion_id")?;
            if !promotion_id.starts_with("vslaketxtprom_") {
                return Err(format!(
                    "payload.source_text_promotion_id must start with 'vslaketxtprom_', got '{promotion_id}'"
                ));
            }
            let source_lake_record_id = require_str("source_lake_record_id")?;
            if !source_lake_record_id.starts_with("vslake_") {
                return Err(format!(
                    "payload.source_lake_record_id must start with 'vslake_', got '{source_lake_record_id}'"
                ));
            }
            require_str("lane_id")?;
            require_str("locator")?;
            require_str("materialized_from")?;
        }
        "finding.confidence_revised" => {
            require_str("proposal_id")?;
            let new_score = require_f64("new_score")?;
            if !(0.0..=1.0).contains(&new_score) {
                return Err(format!("new_score {new_score} out of [0.0, 1.0]"));
            }
            let _ = require_f64("previous_score")?;
        }
        "finding.rejected" => {
            require_str("proposal_id")?;
        }
        "finding.superseded" => {
            require_str("proposal_id")?;
            require_str("new_finding_id")?;
        }
        "finding.retracted" => {
            require_str("proposal_id")?;
            // affected and cascade are summary fields; optional but if
            // present, affected must be a non-negative integer.
            if let Some(affected) = object.get("affected") {
                let _ = affected
                    .as_u64()
                    .ok_or("affected must be a non-negative integer")?;
            }
        }
        // Phase L: per-dependent cascade events. Each one names the
        // upstream retraction it descends from, the cascade depth, and
        // the canonical event ID of the source retraction so a replay
        // can reconstruct the cascade without trusting summary fields.
        "finding.dependency_invalidated" => {
            require_str("upstream_finding_id")?;
            require_str("upstream_event_id")?;
            let depth = object
                .get("depth")
                .and_then(Value::as_u64)
                .ok_or("missing required positive integer 'depth'")?;
            if depth == 0 {
                return Err("depth must be >= 1 (genesis is the source retraction)".to_string());
            }
            // proposal_id present for cascade-source traceability.
            require_str("proposal_id")?;
        }
        // Phase H will introduce frontier.created. For v0.3 it accepts
        // a name + creator pair; left here for forward compatibility.
        "frontier.created" => {
            require_str("name")?;
            require_str("creator")?;
        }
        // v0.40.1: prediction expired without resolution. Emitted by
        // `calibration::expire_overdue_predictions` when a prediction's
        // `resolves_by` is in the past and no Resolution targets it.
        // Closing the prediction this way does not generate a
        // synthesized Resolution — the predictor failed to commit
        // either way, and calibration tracks it as a separate count.
        "prediction.expired_unresolved" => {
            require_str("prediction_id")?;
            require_str("resolves_by")?;
            require_str("expired_at")?;
        }
        // v0.39: federation events. Both record interactions with a
        // peer hub registered in `Project.peers`. The actual sync
        // runtime (HTTP fetch + manifest verification) ships in
        // v0.39.1+; v0.39.0 only validates the event schema so a
        // hand-emitted sync record can already be replay-checked.
        "frontier.synced_with_peer" => {
            require_str("peer_id")?;
            require_str("peer_snapshot_hash")?;
            require_str("our_snapshot_hash")?;
            let _ = object
                .get("divergence_count")
                .and_then(Value::as_u64)
                .ok_or("missing required non-negative integer 'divergence_count'")?;
        }
        "frontier.conflict_detected" => {
            require_str("peer_id")?;
            require_str("finding_id")?;
            let kind = require_str("kind")?;
            // The conflict kind is open-ended for now; v0.39.1+ will
            // tighten this enum once the sync runtime lands. For
            // v0.39.0 we only require it to be non-empty so a replay
            // can group conflicts by category.
            if kind.trim().is_empty() {
                return Err("payload.kind must be a non-empty string".to_string());
            }
        }
        // v0.59: paired resolution event for a previously emitted
        // `frontier.conflict_detected`. The conflict event itself
        // remains in the log; this is an append-only verdict trail.
        "frontier.conflict_resolved" => {
            let conflict_event_id = require_str("conflict_event_id")?;
            if conflict_event_id.trim().is_empty() {
                return Err("payload.conflict_event_id must be a non-empty string".to_string());
            }
            let resolved_by = require_str("resolved_by")?;
            if resolved_by.trim().is_empty() {
                return Err("payload.resolved_by must be a non-empty string".to_string());
            }
            let note = require_str("resolution_note")?;
            if note.trim().is_empty() {
                return Err("payload.resolution_note must be a non-empty string".to_string());
            }
            // winning_proposal_id is optional; some conflicts resolve
            // by reviewer judgment without picking a specific proposal
            // (for example "neither side is the canonical wording").
            if let Some(value) = object.get("winning_proposal_id")
                && !value.is_null()
                && !value.is_string()
            {
                return Err("payload.winning_proposal_id must be a string when present".to_string());
            }
        }
        // v0.70: Replication deposit. Required payload field
        // `replication` is the full Replication record (object).
        // The reducer + apply layer enforce content-addressing
        // and idempotency.
        "replication.deposited" => {
            let rep = object
                .get("replication")
                .ok_or("payload.replication is required")?;
            if !rep.is_object() {
                return Err("payload.replication must be an object".to_string());
            }
            let id = rep
                .get("id")
                .and_then(Value::as_str)
                .ok_or("payload.replication.id is required (vrep_<hex>)")?;
            if !id.starts_with("vrep_") {
                return Err(format!(
                    "payload.replication.id must start with 'vrep_', got '{id}'"
                ));
            }
        }
        // v0.70: Prediction deposit. Same pattern as
        // replication.deposited; payload field `prediction`.
        "prediction.deposited" => {
            let pred = object
                .get("prediction")
                .ok_or("payload.prediction is required")?;
            if !pred.is_object() {
                return Err("payload.prediction must be an object".to_string());
            }
            let id = pred
                .get("id")
                .and_then(Value::as_str)
                .ok_or("payload.prediction.id is required (vpred_<hex>)")?;
            if !id.starts_with("vpred_") {
                return Err(format!(
                    "payload.prediction.id must start with 'vpred_', got '{id}'"
                ));
            }
        }
        // v0.67: Bridge review verdict. Confirms or refutes a
        // cross-frontier bridge identified by `vbr_*`. Reducer arm
        // sets `Bridge.status` to the named status. Status must be
        // one of "confirmed" or "refuted"; "derived" is the genesis
        // state and can not be re-asserted via this event (use
        // bridges derive instead). Note is optional but encouraged.
        "bridge.reviewed" => {
            let bridge_id = require_str("bridge_id")?;
            if !bridge_id.starts_with("vbr_") {
                return Err(format!(
                    "payload.bridge_id must start with 'vbr_', got '{bridge_id}'"
                ));
            }
            let status = require_str("status")?;
            if !matches!(status, "confirmed" | "refuted") {
                return Err(format!(
                    "payload.status must be 'confirmed' or 'refuted', got '{status}'"
                ));
            }
            // note is optional; if present, must be a string.
            if let Some(value) = object.get("note")
                && !value.is_null()
                && !value.is_string()
            {
                return Err("payload.note must be a string when present".to_string());
            }
        }
        "frontier.observation_reviewed" => {
            require_str("proposal_id")?;
            let proposal_kind = require_str("proposal_kind")?;
            if !matches!(
                proposal_kind,
                "research_trace.review" | "correction_return.review"
            ) {
                return Err(format!(
                    "payload.proposal_kind must be research_trace.review or correction_return.review, got '{proposal_kind}'"
                ));
            }
            let status = require_str("status")?;
            if status != "accepted" {
                return Err(format!("payload.status must be 'accepted', got '{status}'"));
            }
            if let Some(value) = object.get("decision_reason")
                && value.as_str().is_none_or(|reason| reason.trim().is_empty())
            {
                return Err(
                    "payload.decision_reason must be a non-empty string when present".to_string(),
                );
            }
        }
        // v0.38: causal-typing reinterpretation. The substrate doesn't
        // erase the prior reading; it appends a new event recording who
        // re-graded the claim and why. `before` and `after` payloads
        // each carry `claim` (correlation|mediation|intervention) and
        // optionally `grade` (rct|quasi_experimental|observational|
        // theoretical). Pre-v0.38 findings carried neither, so a
        // reinterpretation may originate from a block with both fields
        // absent or null.
        "assertion.reinterpreted_causal" => {
            require_str("proposal_id")?;
            let check_block = |block_name: &str| -> Result<(), String> {
                let block = object
                    .get(block_name)
                    .and_then(Value::as_object)
                    .ok_or_else(|| format!("payload.{block_name} must be an object"))?;
                if let Some(claim) = block.get("claim").and_then(Value::as_str)
                    && !crate::bundle::VALID_CAUSAL_CLAIMS.contains(&claim)
                {
                    return Err(format!(
                        "{block_name}.claim '{claim}' not in {:?}",
                        crate::bundle::VALID_CAUSAL_CLAIMS
                    ));
                }
                if let Some(grade) = block.get("grade").and_then(Value::as_str)
                    && !crate::bundle::VALID_CAUSAL_EVIDENCE_GRADES.contains(&grade)
                {
                    return Err(format!(
                        "{block_name}.grade '{grade}' not in {:?}",
                        crate::bundle::VALID_CAUSAL_EVIDENCE_GRADES
                    ));
                }
                Ok(())
            };
            check_block("before")?;
            check_block("after")?;
        }
        // v0.37: multi-sig kernel events. `threshold_set` records the
        // policy attached to a finding (k unique valid signatures
        // required); `threshold_met` records the moment the k-th
        // signature lands. Both are content-addressed under the same
        // canonical-JSON discipline as every other event kind.
        "finding.threshold_set" => {
            let threshold = object
                .get("threshold")
                .and_then(Value::as_u64)
                .ok_or("missing required positive integer 'threshold'")?;
            if threshold == 0 {
                return Err("threshold must be >= 1".to_string());
            }
        }
        "finding.threshold_met" => {
            let count = object
                .get("signature_count")
                .and_then(Value::as_u64)
                .ok_or("missing required positive integer 'signature_count'")?;
            let threshold = object
                .get("threshold")
                .and_then(Value::as_u64)
                .ok_or("missing required positive integer 'threshold'")?;
            if count < threshold {
                return Err(format!(
                    "signature_count {count} below threshold {threshold}"
                ));
            }
        }
        // v0.49: key revocation event. Carries the revoked Ed25519
        // pubkey (hex-encoded 64 chars), the ISO-8601 moment compromise
        // was detected, and an optional replacement pubkey + reason.
        // Validating here keeps a hand-emitted or peer-fetched
        // revocation honest at the event-pipeline boundary so a
        // malformed revocation can't slip through replay and silently
        // re-trust the compromised key.
        EVENT_KIND_KEY_REVOKE => {
            let revoked = require_str("revoked_pubkey")?;
            if revoked.len() != 64 || !revoked.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(format!(
                    "revoked_pubkey must be 64 hex chars (Ed25519 pubkey), got {} chars",
                    revoked.len()
                ));
            }
            let revoked_at = require_str("revoked_at")?;
            if revoked_at.trim().is_empty() {
                return Err("revoked_at must be a non-empty ISO-8601 timestamp".to_string());
            }
            // v0.49.1: parse as RFC-3339 / ISO-8601 so a typo'd value
            // ("yesterday", "x", "2026-13-99T...") fails at the
            // validator boundary rather than poisoning re-verification
            // of post-revocation signatures further downstream.
            if DateTime::parse_from_rfc3339(revoked_at).is_err() {
                return Err(format!(
                    "revoked_at must parse as RFC-3339/ISO-8601, got {revoked_at:?}"
                ));
            }
            // replacement_pubkey is optional but if present must be a
            // valid hex pubkey of the same shape — a typo here would
            // strand the actor's identity at the wrong forward key.
            if let Some(replacement) = object.get("replacement_pubkey")
                && let Some(rep_str) = replacement.as_str()
                && !rep_str.is_empty()
                && (rep_str.len() != 64 || !rep_str.chars().all(|c| c.is_ascii_hexdigit()))
            {
                return Err(format!(
                    "replacement_pubkey must be 64 hex chars when present, got {} chars",
                    rep_str.len()
                ));
            }
            // The revoked key cannot also be the replacement; that
            // would be a self-rotation that revokes nothing.
            if let Some(replacement) = object.get("replacement_pubkey").and_then(Value::as_str)
                && !replacement.is_empty()
                && replacement.eq_ignore_ascii_case(revoked)
            {
                return Err("replacement_pubkey must differ from revoked_pubkey".to_string());
            }
        }
        // v0.49: NegativeResult deposit. Carries the full inline
        // negative_result object on payload.negative_result so a fresh
        // replay reconstructs state from the event log alone. Validation
        // here is the boundary check: kind-specific required fields,
        // power on [0,1], n_enrolled non-negative. The full deserialize
        // is reducer-side (apply_negative_result_asserted) so a malformed
        // shape fails replay loudly rather than silently dropping the
        // deposit.
        EVENT_KIND_NEGATIVE_RESULT_ASSERTED => {
            require_str("proposal_id")?;
            let nr = object
                .get("negative_result")
                .and_then(Value::as_object)
                .ok_or("payload.negative_result must be a JSON object")?;
            let nr_kind = nr
                .get("kind")
                .and_then(|k| k.as_object())
                .and_then(|k| k.get("kind"))
                .and_then(Value::as_str)
                .ok_or(
                    "payload.negative_result.kind.kind must be 'registered_trial' or 'exploratory'",
                )?;
            match nr_kind {
                "registered_trial" => {
                    let kind_obj = nr
                        .get("kind")
                        .and_then(Value::as_object)
                        .expect("checked above");
                    for k in ["endpoint", "intervention", "comparator", "population"] {
                        let v = kind_obj
                            .get(k)
                            .and_then(Value::as_str)
                            .ok_or_else(|| format!("registered_trial.{k} must be a string"))?;
                        if v.trim().is_empty() {
                            return Err(format!("registered_trial.{k} must be non-empty"));
                        }
                    }
                    let _ = kind_obj
                        .get("n_enrolled")
                        .and_then(Value::as_u64)
                        .ok_or("registered_trial.n_enrolled must be a non-negative integer")?;
                    let power = kind_obj
                        .get("power")
                        .and_then(Value::as_f64)
                        .ok_or("registered_trial.power must be a number on [0, 1]")?;
                    if !(0.0..=1.0).contains(&power) {
                        return Err(format!("registered_trial.power {power} out of [0.0, 1.0]"));
                    }
                    let ci = kind_obj
                        .get("effect_size_ci")
                        .and_then(Value::as_array)
                        .ok_or("registered_trial.effect_size_ci must be a 2-element array [lower, upper]")?;
                    if ci.len() != 2 {
                        return Err(format!(
                            "registered_trial.effect_size_ci must have length 2, got {}",
                            ci.len()
                        ));
                    }
                    let lower = ci[0]
                        .as_f64()
                        .ok_or("registered_trial.effect_size_ci[0] must be a number")?;
                    let upper = ci[1]
                        .as_f64()
                        .ok_or("registered_trial.effect_size_ci[1] must be a number")?;
                    if upper < lower {
                        return Err(format!(
                            "registered_trial.effect_size_ci upper {upper} below lower {lower}"
                        ));
                    }
                }
                "exploratory" => {
                    let kind_obj = nr
                        .get("kind")
                        .and_then(Value::as_object)
                        .expect("checked above");
                    for k in ["reagent", "observation"] {
                        let v = kind_obj
                            .get(k)
                            .and_then(Value::as_str)
                            .ok_or_else(|| format!("exploratory.{k} must be a string"))?;
                        if v.trim().is_empty() {
                            return Err(format!("exploratory.{k} must be non-empty"));
                        }
                    }
                    let attempts = kind_obj
                        .get("attempts")
                        .and_then(Value::as_u64)
                        .ok_or("exploratory.attempts must be a positive integer")?;
                    if attempts == 0 {
                        return Err("exploratory.attempts must be >= 1".to_string());
                    }
                }
                other => {
                    return Err(format!(
                        "negative_result.kind.kind '{other}' must be 'registered_trial' or 'exploratory'"
                    ));
                }
            }
            let depositor = nr
                .get("deposited_by")
                .and_then(Value::as_str)
                .ok_or("payload.negative_result.deposited_by must be a non-empty string")?;
            if depositor.trim().is_empty() {
                return Err("payload.negative_result.deposited_by must be non-empty".to_string());
            }
        }
        EVENT_KIND_NEGATIVE_RESULT_REVIEWED => {
            require_str("proposal_id")?;
            let status = require_str("status")?;
            if !matches!(
                status,
                "accepted" | "approved" | "contested" | "needs_revision" | "rejected"
            ) {
                return Err(format!("invalid review status '{status}'"));
            }
        }
        EVENT_KIND_NEGATIVE_RESULT_RETRACTED => {
            require_str("proposal_id")?;
        }
        // v0.50: Trajectory lifecycle. trajectory.created carries the
        // initial Trajectory inline on payload.trajectory (with empty
        // steps). trajectory.step_appended carries the new step on
        // payload.step plus parent_trajectory_id. trajectory.reviewed
        // and trajectory.retracted target an existing vtr_*.
        EVENT_KIND_TRAJECTORY_CREATED => {
            require_str("proposal_id")?;
            let traj = object
                .get("trajectory")
                .and_then(Value::as_object)
                .ok_or("payload.trajectory must be a JSON object")?;
            let depositor = traj
                .get("deposited_by")
                .and_then(Value::as_str)
                .ok_or("payload.trajectory.deposited_by must be a non-empty string")?;
            if depositor.trim().is_empty() {
                return Err("payload.trajectory.deposited_by must be non-empty".to_string());
            }
            let id = traj
                .get("id")
                .and_then(Value::as_str)
                .ok_or("payload.trajectory.id must be a vtr_<hex>")?;
            if !id.starts_with("vtr_") {
                return Err(format!(
                    "payload.trajectory.id must start with 'vtr_', got '{id}'"
                ));
            }
        }
        EVENT_KIND_TRAJECTORY_STEP_APPENDED => {
            require_str("proposal_id")?;
            let parent = require_str("parent_trajectory_id")?;
            if !parent.starts_with("vtr_") {
                return Err(format!(
                    "parent_trajectory_id must start with 'vtr_', got '{parent}'"
                ));
            }
            let step = object
                .get("step")
                .and_then(Value::as_object)
                .ok_or("payload.step must be a JSON object")?;
            let kind_str = step.get("kind").and_then(Value::as_str).ok_or(
                "payload.step.kind must be one of hypothesis|tried|ruled_out|observed|refined",
            )?;
            if !matches!(
                kind_str,
                "hypothesis" | "tried" | "ruled_out" | "observed" | "refined"
            ) {
                return Err(format!(
                    "payload.step.kind '{kind_str}' must be one of hypothesis|tried|ruled_out|observed|refined"
                ));
            }
            let description = step
                .get("description")
                .and_then(Value::as_str)
                .ok_or("payload.step.description must be a non-empty string")?;
            if description.trim().is_empty() {
                return Err("payload.step.description must be non-empty".to_string());
            }
            let actor = step
                .get("actor")
                .and_then(Value::as_str)
                .ok_or("payload.step.actor must be a non-empty string")?;
            if actor.trim().is_empty() {
                return Err("payload.step.actor must be non-empty".to_string());
            }
        }
        EVENT_KIND_TRAJECTORY_REVIEWED => {
            require_str("proposal_id")?;
            let status = require_str("status")?;
            if !matches!(
                status,
                "accepted" | "approved" | "contested" | "needs_revision" | "rejected"
            ) {
                return Err(format!("invalid review status '{status}'"));
            }
        }
        EVENT_KIND_TRAJECTORY_RETRACTED => {
            require_str("proposal_id")?;
        }
        EVENT_KIND_ARTIFACT_ASSERTED => {
            require_str("proposal_id")?;
            let artifact = object
                .get("artifact")
                .and_then(Value::as_object)
                .ok_or("payload.artifact must be a JSON object")?;
            let id = artifact
                .get("id")
                .and_then(Value::as_str)
                .ok_or("payload.artifact.id must be a va_<hex>")?;
            if !id.starts_with("va_") {
                return Err(format!(
                    "payload.artifact.id must start with 'va_', got '{id}'"
                ));
            }
            let id_hex = id.trim_start_matches("va_");
            if id_hex.len() != 16 || !id_hex.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err("payload.artifact.id must be va_<16hex>".to_string());
            }
            let kind = artifact
                .get("kind")
                .and_then(Value::as_str)
                .ok_or("payload.artifact.kind must be a string")?;
            if !crate::bundle::valid_artifact_kind(kind) {
                return Err(format!("payload.artifact.kind '{kind}' is not supported"));
            }
            for key in ["name", "content_hash", "storage_mode"] {
                let value = artifact
                    .get(key)
                    .and_then(Value::as_str)
                    .ok_or_else(|| format!("payload.artifact.{key} must be a string"))?;
                if value.trim().is_empty() {
                    return Err(format!("payload.artifact.{key} must be non-empty"));
                }
            }
            let content_hash = artifact
                .get("content_hash")
                .and_then(Value::as_str)
                .expect("content_hash checked above");
            validate_sha256_commitment("payload.artifact.content_hash", content_hash)?;
        }
        EVENT_KIND_ARTIFACT_REVIEWED => {
            require_str("proposal_id")?;
            let status = require_str("status")?;
            if !matches!(
                status,
                "accepted" | "approved" | "contested" | "needs_revision" | "rejected"
            ) {
                return Err(format!("invalid review status '{status}'"));
            }
        }
        EVENT_KIND_ARTIFACT_RETRACTED => {
            require_str("proposal_id")?;
        }
        // v0.51: Re-classify an object's read-side access tier.
        // Validates target.r#type up front so a `tier.set` event for
        // a non-tiered kernel object (replication, dataset, etc.)
        // fails at the validator boundary rather than silently
        // succeeding under the reducer's match-or-noop.
        EVENT_KIND_TIER_SET => {
            require_str("proposal_id")?;
            let object_type = require_str("object_type")?;
            if !matches!(
                object_type,
                "finding" | "negative_result" | "trajectory" | "artifact"
            ) {
                return Err(format!(
                    "tier.set object_type '{object_type}' must be one of finding, negative_result, trajectory, artifact"
                ));
            }
            require_str("object_id")?;
            let new_tier = require_str("new_tier")?;
            crate::access_tier::AccessTier::parse(new_tier)?;
            // previous_tier is optional but if present must parse to
            // a valid tier so a stale or hand-edited event log can't
            // smuggle in `"prev"` strings the reducer would later
            // reject.
            if let Some(prev) = object.get("previous_tier").and_then(Value::as_str) {
                crate::access_tier::AccessTier::parse(prev)?;
            }
        }
        // v0.56: Mechanical evidence-atom locator repair. Required
        // payload shape: {proposal_id, source_id, locator}. The locator
        // string lands on the atom's `locator` field and the source_id
        // is recorded for traceability so a reader can reconstruct the
        // derivation without re-resolving the source registry.
        EVENT_KIND_EVIDENCE_ATOM_LOCATOR_REPAIRED => {
            require_str("proposal_id")?;
            let source_id = require_str("source_id")?;
            if source_id.trim().is_empty() {
                return Err("payload.source_id must be non-empty".to_string());
            }
            let locator = require_str("locator")?;
            if locator.trim().is_empty() {
                return Err("payload.locator must be non-empty".to_string());
            }
        }
        // v0.57: Append a `{section, text}` span to a finding's
        // evidence_spans. Required payload: {proposal_id, section, text}.
        EVENT_KIND_FINDING_SPAN_REPAIRED => {
            require_str("proposal_id")?;
            let section = require_str("section")?;
            if section.trim().is_empty() {
                return Err("payload.section must be non-empty".to_string());
            }
            let text = require_str("text")?;
            if text.trim().is_empty() {
                return Err("payload.text must be non-empty".to_string());
            }
        }
        // v0.57: Set canonical_id + resolution metadata on a single
        // entity inside finding.assertion.entities. Required payload:
        // {proposal_id, entity_name, source, id, confidence}.
        EVENT_KIND_FINDING_ENTITY_RESOLVED => {
            require_str("proposal_id")?;
            let entity_name = require_str("entity_name")?;
            if entity_name.trim().is_empty() {
                return Err("payload.entity_name must be non-empty".to_string());
            }
            let source = require_str("source")?;
            if source.trim().is_empty() {
                return Err("payload.source must be non-empty".to_string());
            }
            let id = require_str("id")?;
            if id.trim().is_empty() {
                return Err("payload.id must be non-empty".to_string());
            }
            let confidence = require_f64("confidence")?;
            if !(0.0..=1.0).contains(&confidence) {
                return Err(format!("payload.confidence {confidence} out of [0.0, 1.0]"));
            }
        }
        // v0.79.4: Per-event attestation. Required payload:
        // `{target_event_id, attester_id, scope_note}`. Optional:
        // `scopes`, `reviewer_role`, `orcid`, `ror`,
        // `attestation_id`, `signature`, `proof_id` (vpf_*),
        // `signed_at`.
        EVENT_KIND_ATTESTATION_RECORDED => {
            let target_id = require_str("target_event_id")?;
            if !target_id.starts_with("vev_") {
                return Err(format!(
                    "payload.target_event_id must start with 'vev_', got '{target_id}'"
                ));
            }
            let attester = require_str("attester_id")?;
            if attester.trim().is_empty() {
                return Err("payload.attester_id must be non-empty".to_string());
            }
            let scope = require_str("scope_note")?;
            if scope.trim().is_empty() {
                return Err("payload.scope_note must be non-empty".to_string());
            }
            // Optional fields: type-check when present.
            if let Some(sig) = object.get("signature")
                && !sig.is_null()
                && !sig.is_string()
            {
                return Err("payload.signature must be a string when present".to_string());
            }
            if let Some(scopes) = object.get("scopes") {
                let Some(items) = scopes.as_array() else {
                    return Err("payload.scopes must be an array when present".to_string());
                };
                for scope in items {
                    let Some(scope) = scope.as_str() else {
                        return Err("payload.scopes entries must be strings".to_string());
                    };
                    match scope {
                        "source_extraction"
                        | "method_review"
                        | "statistical_review"
                        | "domain_relevance"
                        | "translation_clarity"
                        | "policy_approval" => {}
                        other => {
                            return Err(format!("payload.scopes contains unknown scope `{other}`"));
                        }
                    }
                }
            }
            for field in [
                "reviewer_role",
                "orcid",
                "ror",
                "attestation_id",
                "signed_at",
            ] {
                if let Some(value) = object.get(field)
                    && !value.is_null()
                    && !value.is_string()
                {
                    return Err(format!("payload.{field} must be a string when present"));
                }
            }
            if let Some(proof) = object.get("proof_id")
                && !proof.is_null()
                && let Some(s) = proof.as_str()
                && !s.starts_with("vpf_")
            {
                return Err(format!(
                    "payload.proof_id must start with 'vpf_' when present, got '{s}'"
                ));
            }
        }
        // v0.79: Add a new entity tag to an existing finding. The
        // valid `entity_type` values are the same as `validate_entities`
        // accepts at finding-creation time
        // (gene/protein/compound/disease/cell_type/organism/pathway/
        //  assay/anatomical_structure/particle/instrument/dataset/
        //  quantity/other).
        EVENT_KIND_FINDING_ENTITY_ADDED => {
            require_str("proposal_id")?;
            let entity_name = require_str("entity_name")?;
            if entity_name.trim().is_empty() {
                return Err("payload.entity_name must be non-empty".to_string());
            }
            let entity_type = require_str("entity_type")?;
            const VALID_ENTITY_TYPES: &[&str] = &[
                "gene",
                "protein",
                "compound",
                "disease",
                "cell_type",
                "organism",
                "pathway",
                "assay",
                "anatomical_structure",
                "particle",
                "instrument",
                "dataset",
                "quantity",
                "other",
            ];
            if !VALID_ENTITY_TYPES.contains(&entity_type) {
                return Err(format!(
                    "payload.entity_type '{entity_type}' not in {VALID_ENTITY_TYPES:?}"
                ));
            }
            let reason = require_str("reason")?;
            if reason.trim().is_empty() {
                return Err("payload.reason must be non-empty".to_string());
            }
        }
        other => return Err(format!("unknown event kind '{other}'")),
    }
    Ok(())
}

/// v0.73: state-aware tightening of the `bridge.reviewed` validator.
///
/// `validate_event_payload` is signature-pure; it rejects bad payload
/// shapes but cannot verify that the target bridge actually exists in
/// the frontier's bridge table. This second pass closes that gap. It
/// takes the payload and a slice of `vbr_*` ids known to the local
/// frontier, and rejects events whose `payload.bridge_id` is not
/// present.
///
/// Call sites:
/// - CLI `vela bridges confirm` / `bridges refute` before emission.
/// - Federation intake paths that ingest `bridge.reviewed` events from
///   peers.
///
/// The function is intentionally separate from `validate_event_payload`
/// so the shape-only validator stays project-agnostic and can be
/// reused by tooling that does not have a frontier in hand.
pub fn validate_bridge_reviewed_against_state(
    payload: &Value,
    known_bridge_ids: &[String],
) -> Result<(), String> {
    let object = payload
        .as_object()
        .ok_or_else(|| "payload must be a JSON object".to_string())?;
    let bridge_id = object
        .get("bridge_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing required string field 'bridge_id'".to_string())?;
    if !known_bridge_ids.iter().any(|id| id == bridge_id) {
        return Err(format!(
            "bridge_id '{bridge_id}' not present on this frontier (no matching .vela/bridges/<id>.json)"
        ));
    }
    Ok(())
}

/// Public form of `event_id` so callers building non-finding events
/// (e.g. the `frontier.created` genesis event in `project::assemble`)
/// can compute the canonical event ID with the same canonical-JSON
/// preimage shape as `new_finding_event`.
pub fn compute_event_id(event: &StateEvent) -> String {
    event_id(event)
}

fn event_id(event: &StateEvent) -> String {
    let content = json!({
        "schema": event.schema,
        "kind": event.kind,
        "target": event.target,
        "actor": event.actor,
        "timestamp": event.timestamp,
        "reason": event.reason,
        "before_hash": event.before_hash,
        "after_hash": event.after_hash,
        "payload": event.payload,
        "caveats": event.caveats,
    });
    let bytes = canonical::to_canonical_bytes(&content).unwrap_or_default();
    format!("vev_{}", &hex::encode(Sha256::digest(bytes))[..16])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::{
        Assertion, Conditions, Confidence, Evidence, Extraction, FindingBundle, Flags, Provenance,
    };
    use crate::project;

    fn finding() -> FindingBundle {
        FindingBundle::new(
            Assertion {
                text: "LRP1 clears amyloid beta at the BBB".to_string(),
                assertion_type: "mechanism".to_string(),
                entities: Vec::new(),
                relation: None,
                direction: None,
                causal_claim: None,
                causal_evidence_grade: None,
            },
            Evidence {
                evidence_type: "experimental".to_string(),
                model_system: "mouse".to_string(),
                species: Some("Mus musculus".to_string()),
                method: "assay".to_string(),
                sample_size: None,
                effect_size: None,
                p_value: None,
                replicated: false,
                replication_count: None,
                evidence_spans: Vec::new(),
            },
            Conditions {
                text: "mouse model".to_string(),
                species_verified: Vec::new(),
                species_unverified: Vec::new(),
                in_vitro: false,
                in_vivo: true,
                human_data: false,
                clinical_trial: false,
                concentration_range: None,
                duration: None,
                age_group: None,
                cell_type: None,
            },
            Confidence::raw(0.6, "test", 0.8),
            Provenance {
                source_type: "published_paper".to_string(),
                doi: None,
                pmid: None,
                pmc: None,
                openalex_id: None,
                url: None,
                title: "Test source".to_string(),
                authors: Vec::new(),
                year: Some(2026),
                journal: None,
                license: None,
                publisher: None,
                funders: Vec::new(),
                extraction: Extraction::default(),
                review: None,
                citation_count: None,
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
    fn event_id_is_deterministic_for_content() {
        let event = new_finding_event(FindingEventInput {
            kind: "finding.reviewed",
            finding_id: "vf_test",
            actor_id: "reviewer",
            actor_type: "human",
            reason: "checked",
            before_hash: NULL_HASH,
            after_hash: "sha256:abc",
            payload: json!({"status": "accepted", "proposal_id": "vpr_test"}),
            caveats: vec![],
        });
        let mut same = event.clone();
        same.id = String::new();
        same.id = super::event_id(&same);
        assert_eq!(event.id, same.id);
    }

    #[test]
    fn genesis_only_event_log_replays_ok() {
        // Phase J: assemble() emits a `frontier.created` genesis event,
        // so a freshly compiled frontier never has an empty event log.
        // Replay over genesis-only must succeed with status "ok" and the
        // single event accounted for.
        let frontier = project::assemble("test", Vec::new(), 0, 0, "test");
        let report = replay_report(&frontier);
        assert!(report.ok, "{:?}", report.conflicts);
        assert_eq!(report.event_log.count, 1);
        assert_eq!(report.event_log.kinds.get("frontier.created"), Some(&1));
    }

    #[test]
    fn replay_detects_duplicate_event_ids() {
        let finding = finding();
        let after_hash = finding_hash(&finding);
        let event = new_finding_event(FindingEventInput {
            kind: "finding.reviewed",
            finding_id: &finding.id,
            actor_id: "reviewer",
            actor_type: "human",
            reason: "checked",
            before_hash: &after_hash,
            after_hash: &after_hash,
            payload: json!({"status": "accepted", "proposal_id": "vpr_test"}),
            caveats: vec![],
        });
        let mut frontier = project::assemble("test", vec![finding], 0, 0, "test");
        frontier.events = vec![event.clone(), event];

        let report = replay_report(&frontier);
        assert!(!report.ok);
        assert_eq!(report.status, "conflict");
        assert!(!report.event_log.duplicate_ids.is_empty());
    }

    #[test]
    fn replay_detects_orphan_targets() {
        let mut frontier = project::assemble("test", Vec::new(), 0, 0, "test");
        frontier.events.push(new_finding_event(FindingEventInput {
            kind: "finding.reviewed",
            finding_id: "vf_missing",
            actor_id: "reviewer",
            actor_type: "human",
            reason: "checked",
            before_hash: NULL_HASH,
            after_hash: "sha256:abc",
            payload: json!({"status": "accepted", "proposal_id": "vpr_test"}),
            caveats: vec![],
        }));

        let report = replay_report(&frontier);
        assert!(!report.ok);
        assert_eq!(report.event_log.orphan_targets, vec!["vf_missing"]);
    }

    #[test]
    fn replay_accepts_current_hash_boundary() {
        let finding = finding();
        let hash = finding_hash(&finding);
        let event = new_finding_event(FindingEventInput {
            kind: "finding.reviewed",
            finding_id: &finding.id,
            actor_id: "reviewer",
            actor_type: "human",
            reason: "checked",
            before_hash: &hash,
            after_hash: &hash,
            payload: json!({"status": "accepted", "proposal_id": "vpr_test"}),
            caveats: vec![],
        });
        let mut frontier = project::assemble("test", vec![finding], 0, 0, "test");
        frontier.events.push(event);

        let report = replay_report(&frontier);
        assert!(report.ok, "{:?}", report.conflicts);
        assert_eq!(report.status, "ok");
    }

    // v0.39 — federation event validation
    #[test]
    fn validates_synced_with_peer_payload() {
        // OK: full payload.
        assert!(
            validate_event_payload(
                "frontier.synced_with_peer",
                &json!({
                    "peer_id": "hub:peer",
                    "peer_snapshot_hash": "abc",
                    "our_snapshot_hash": "def",
                    "divergence_count": 3,
                }),
            )
            .is_ok()
        );
        // FAIL: missing divergence_count.
        assert!(
            validate_event_payload(
                "frontier.synced_with_peer",
                &json!({
                    "peer_id": "hub:peer",
                    "peer_snapshot_hash": "abc",
                    "our_snapshot_hash": "def",
                }),
            )
            .is_err()
        );
        // FAIL: missing peer_id.
        assert!(
            validate_event_payload(
                "frontier.synced_with_peer",
                &json!({
                    "peer_snapshot_hash": "abc",
                    "our_snapshot_hash": "def",
                    "divergence_count": 0,
                }),
            )
            .is_err()
        );
    }

    #[test]
    fn validates_conflict_detected_payload() {
        // OK: full payload.
        assert!(
            validate_event_payload(
                "frontier.conflict_detected",
                &json!({
                    "peer_id": "hub:peer",
                    "finding_id": "vf_xyz",
                    "kind": "different_review_verdict",
                }),
            )
            .is_ok()
        );
        // FAIL: empty kind.
        assert!(
            validate_event_payload(
                "frontier.conflict_detected",
                &json!({
                    "peer_id": "hub:peer",
                    "finding_id": "vf_xyz",
                    "kind": "  ",
                }),
            )
            .is_err()
        );
        // FAIL: missing finding_id.
        assert!(
            validate_event_payload(
                "frontier.conflict_detected",
                &json!({
                    "peer_id": "hub:peer",
                    "kind": "missing_in_peer",
                }),
            )
            .is_err()
        );
    }

    #[test]
    fn validates_diff_pack_lifecycle_payloads() {
        assert!(
            validate_event_payload(
                "diff_pack.released",
                &json!({
                    "pack_id": "vsd_1234567890abcdef",
                    "frontier_id": "vfr_1234567890abcdef",
                    "summary": "Review bounded proposed changes.",
                    "aggregate_kind": "clinical_translation.review_set",
                }),
            )
            .is_ok()
        );
        assert!(
            validate_event_payload(
                "diff_pack.reviewed",
                &json!({
                    "pack_id": "vsd_1234567890abcdef",
                    "verdict": "revise",
                    "reviewer_actor": "reviewer:test",
                    "reason": "Needs source locator repair before acceptance.",
                    "applied_members": [],
                    "sdk_only_members": ["vpr_sdk_only"],
                }),
            )
            .is_ok()
        );
        assert!(
            validate_event_payload(
                "diff_pack.released",
                &json!({
                    "pack_id": "bad",
                    "frontier_id": "vfr_1234567890abcdef",
                    "summary": "Review bounded proposed changes.",
                    "aggregate_kind": "clinical_translation.review_set",
                }),
            )
            .is_err()
        );
        assert!(
            validate_event_payload(
                "diff_pack.reviewed",
                &json!({
                    "pack_id": "vsd_1234567890abcdef",
                    "verdict": "maybe",
                    "reviewer_actor": "reviewer:test",
                    "reason": "Needs source locator repair before acceptance.",
                }),
            )
            .is_err()
        );
    }

    #[test]
    fn validates_artifact_asserted_payload() {
        let good_hash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert!(
            validate_event_payload(
                EVENT_KIND_ARTIFACT_ASSERTED,
                &json!({
                    "proposal_id": "vpr_test",
                    "artifact": {
                        "id": "va_1234567890abcdef",
                        "kind": "clinical_trial_record",
                        "name": "NCT test record",
                        "content_hash": good_hash,
                        "storage_mode": "embedded",
                    },
                }),
            )
            .is_ok()
        );
        assert!(
            validate_event_payload(
                EVENT_KIND_ARTIFACT_ASSERTED,
                &json!({
                    "proposal_id": "vpr_test",
                    "artifact": {
                        "id": "va_123",
                        "kind": "clinical_trial_record",
                        "name": "NCT test record",
                        "content_hash": good_hash,
                        "storage_mode": "embedded",
                    },
                }),
            )
            .is_err()
        );
        assert!(
            validate_event_payload(
                EVENT_KIND_ARTIFACT_ASSERTED,
                &json!({
                    "proposal_id": "vpr_test",
                    "artifact": {
                        "id": "va_1234567890abcdef",
                        "kind": "clinical_trial_record",
                        "name": "NCT test record",
                        "content_hash": "sha256:not-a-real-hash",
                        "storage_mode": "embedded",
                    },
                }),
            )
            .is_err()
        );
    }

    // v0.38 — causal-typing event validation
    #[test]
    fn validates_reinterpreted_causal_payload() {
        // OK: missing claim/grade is fine (None means no prior reading).
        assert!(
            validate_event_payload(
                "assertion.reinterpreted_causal",
                &json!({
                    "proposal_id": "vpr_test",
                    "before": {},
                    "after": { "claim": "intervention", "grade": "rct" },
                }),
            )
            .is_ok()
        );
        // OK: pure claim revision, no grade.
        assert!(
            validate_event_payload(
                "assertion.reinterpreted_causal",
                &json!({
                    "proposal_id": "vpr_test",
                    "before": { "claim": "correlation" },
                    "after": { "claim": "mediation" },
                }),
            )
            .is_ok()
        );
        // FAIL: invalid claim.
        assert!(
            validate_event_payload(
                "assertion.reinterpreted_causal",
                &json!({
                    "proposal_id": "vpr_test",
                    "before": {},
                    "after": { "claim": "magic" },
                }),
            )
            .is_err()
        );
        // FAIL: invalid grade.
        assert!(
            validate_event_payload(
                "assertion.reinterpreted_causal",
                &json!({
                    "proposal_id": "vpr_test",
                    "before": {},
                    "after": { "claim": "intervention", "grade": "vibes" },
                }),
            )
            .is_err()
        );
        // FAIL: missing proposal_id.
        assert!(
            validate_event_payload(
                "assertion.reinterpreted_causal",
                &json!({
                    "before": {},
                    "after": { "claim": "intervention" },
                }),
            )
            .is_err()
        );
    }

    /// v0.49: a `key.revoke` event names the revoked pubkey, the
    /// moment of compromise, and (optionally) the replacement key.
    /// Empty optional fields skip canonical-JSON serialization so
    /// existing event logs round-trip byte-identically.
    #[test]
    fn revocation_event_canonical_shape() {
        use crate::canonical;
        let payload = RevocationPayload {
            revoked_pubkey: "4892f93877e637b5f59af31d9ec6704814842fb278cacb0eb94704baef99455e"
                .to_string(),
            revoked_at: "2026-05-01T17:00:00Z".to_string(),
            replacement_pubkey: "8891a2ab35ca2ed2182ed4e46b6567ce8dacc9985eb496d895578201272a1cd9"
                .to_string(),
            reason: "key file leaked from CI cache".to_string(),
        };
        let event = new_revocation_event(
            "reviewer:will-blair",
            "human",
            payload,
            "rotating compromised key",
            NULL_HASH,
            NULL_HASH,
        );
        assert_eq!(event.kind, EVENT_KIND_KEY_REVOKE);
        assert_eq!(event.target.r#type, "actor");
        assert!(event.id.starts_with("vev_"));
        let bytes = canonical::to_canonical_bytes(&event).unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(
            s.contains("\"revoked_pubkey\""),
            "canonical bytes missing revoked_pubkey: {s}"
        );
        assert!(
            s.contains("\"revoked_at\""),
            "canonical bytes missing revoked_at: {s}"
        );
        assert!(
            s.contains("\"replacement_pubkey\""),
            "canonical bytes missing replacement_pubkey: {s}"
        );

        // Empty replacement_pubkey skips serialization.
        let payload_minimal = RevocationPayload {
            revoked_pubkey: "a".repeat(64),
            revoked_at: "2026-05-01T17:00:00Z".to_string(),
            replacement_pubkey: String::new(),
            reason: String::new(),
        };
        let minimal_event = new_revocation_event(
            "reviewer:will-blair",
            "human",
            payload_minimal,
            "scheduled rotation",
            NULL_HASH,
            NULL_HASH,
        );
        let minimal_bytes = canonical::to_canonical_bytes(&minimal_event).unwrap();
        let minimal_s = std::str::from_utf8(&minimal_bytes).unwrap();
        assert!(
            !minimal_s.contains("\"replacement_pubkey\""),
            "empty replacement_pubkey leaked into canonical JSON: {minimal_s}"
        );
        assert!(
            !minimal_s.contains("\"reason\":\"\""),
            "empty payload reason leaked into canonical JSON: {minimal_s}"
        );
    }

    /// v0.49: validate_event_payload now recognises `key.revoke`.
    /// Tests cover the four real failure modes plus the happy path.
    #[test]
    fn revocation_payload_validation() {
        let good_pubkey = "4892f93877e637b5f59af31d9ec6704814842fb278cacb0eb94704baef99455e";
        let other_pubkey = "8891a2ab35ca2ed2182ed4e46b6567ce8dacc9985eb496d895578201272a1cd9";

        // OK: minimal valid payload.
        assert!(
            validate_event_payload(
                EVENT_KIND_KEY_REVOKE,
                &json!({
                    "revoked_pubkey": good_pubkey,
                    "revoked_at": "2026-05-01T17:00:00Z",
                }),
            )
            .is_ok()
        );

        // OK: full payload with replacement and reason.
        assert!(
            validate_event_payload(
                EVENT_KIND_KEY_REVOKE,
                &json!({
                    "revoked_pubkey": good_pubkey,
                    "revoked_at": "2026-05-01T17:00:00Z",
                    "replacement_pubkey": other_pubkey,
                    "reason": "key file leaked",
                }),
            )
            .is_ok()
        );

        // FAIL: revoked_pubkey wrong length (32 bytes ASCII, not 64 hex).
        assert!(
            validate_event_payload(
                EVENT_KIND_KEY_REVOKE,
                &json!({
                    "revoked_pubkey": "abc123",
                    "revoked_at": "2026-05-01T17:00:00Z",
                }),
            )
            .is_err()
        );

        // FAIL: revoked_pubkey contains non-hex chars.
        assert!(
            validate_event_payload(
                EVENT_KIND_KEY_REVOKE,
                &json!({
                    "revoked_pubkey": "ZZ".repeat(32),
                    "revoked_at": "2026-05-01T17:00:00Z",
                }),
            )
            .is_err()
        );

        // FAIL: missing revoked_at.
        assert!(
            validate_event_payload(
                EVENT_KIND_KEY_REVOKE,
                &json!({
                    "revoked_pubkey": good_pubkey,
                }),
            )
            .is_err()
        );

        // FAIL: replacement_pubkey wrong length.
        assert!(
            validate_event_payload(
                EVENT_KIND_KEY_REVOKE,
                &json!({
                    "revoked_pubkey": good_pubkey,
                    "revoked_at": "2026-05-01T17:00:00Z",
                    "replacement_pubkey": "deadbeef",
                }),
            )
            .is_err()
        );

        // FAIL: replacement equals revoked (no-op rotation).
        assert!(
            validate_event_payload(
                EVENT_KIND_KEY_REVOKE,
                &json!({
                    "revoked_pubkey": good_pubkey,
                    "revoked_at": "2026-05-01T17:00:00Z",
                    "replacement_pubkey": good_pubkey,
                }),
            )
            .is_err()
        );

        // FAIL: revoked_at is non-empty but not a valid ISO-8601 stamp.
        // The v0.49.1 validator parses it as RFC-3339 so typos can't
        // reach replay verification.
        // chrono's parse_from_rfc3339 is intentionally lenient on the
        // `T` vs space separator (RFC-3339 §5.6), so we don't include
        // that case here — chronologically nonsensical strings still
        // fail, which is the bar we care about.
        for bad in [
            "yesterday",
            "2026-13-01T00:00:00Z", // month 13
            "2026-05-01",           // date only, no time
            "x",
        ] {
            assert!(
                validate_event_payload(
                    EVENT_KIND_KEY_REVOKE,
                    &json!({
                        "revoked_pubkey": good_pubkey,
                        "revoked_at": bad,
                    }),
                )
                .is_err(),
                "expected revoked_at {bad:?} to fail validation"
            );
        }
    }

    /// v0.79.4: per-event attestation validator. Required
    /// payload: target_event_id (must start with vev_),
    /// attester_id (non-empty), scope_note (non-empty). Optional
    /// signature (string), proof_id (vpf_*).
    #[test]
    fn attestation_recorded_validator() {
        // PASS: minimal good payload.
        let good = json!({
            "target_event_id": "vev_abc",
            "attester_id": "reviewer:will-blair",
            "scope_note": "Independent re-verification of the Stupp protocol finding."
        });
        assert!(validate_event_payload(EVENT_KIND_ATTESTATION_RECORDED, &good).is_ok());

        // PASS: with optional signature + proof_id.
        let with_proof = json!({
            "target_event_id": "vev_abc",
            "attester_id": "reviewer:will-blair",
            "scope_note": "Lean-formalized.",
            "scopes": ["domain_relevance", "method_review"],
            "reviewer_role": "domain_reviewer",
            "orcid": "https://orcid.org/0000-0000-0000-000X",
            "ror": "https://ror.org/03yrm5c26",
            "attestation_id": "vatt_demo",
            "signature": "ed25519:cafebabe",
            "proof_id": "vpf_demo"
        });
        assert!(validate_event_payload(EVENT_KIND_ATTESTATION_RECORDED, &with_proof).is_ok());

        // FAIL: target_event_id without vev_ prefix.
        let bad_target = json!({
            "target_event_id": "something_else",
            "attester_id": "reviewer:x",
            "scope_note": "x"
        });
        assert!(validate_event_payload(EVENT_KIND_ATTESTATION_RECORDED, &bad_target).is_err());

        // FAIL: empty attester_id.
        let no_attester = json!({
            "target_event_id": "vev_abc",
            "attester_id": "",
            "scope_note": "x"
        });
        assert!(validate_event_payload(EVENT_KIND_ATTESTATION_RECORDED, &no_attester).is_err());

        // FAIL: proof_id without vpf_ prefix.
        let bad_proof = json!({
            "target_event_id": "vev_abc",
            "attester_id": "reviewer:x",
            "scope_note": "x",
            "proof_id": "not_a_vpf"
        });
        assert!(validate_event_payload(EVENT_KIND_ATTESTATION_RECORDED, &bad_proof).is_err());
    }

    /// v0.79: finding.entity_added validator pins the entity_type
    /// to the same allowlist `validate_entities` enforces at
    /// finding-creation time.
    #[test]
    fn finding_entity_added_validator() {
        // PASS: well-formed payload.
        let good = json!({
            "proposal_id": "vpr_demo",
            "entity_name": "claudin-5",
            "entity_type": "protein",
            "reason": "Cardinal BBB tight-junction protein; cited in finding source paper."
        });
        assert!(validate_event_payload(EVENT_KIND_FINDING_ENTITY_ADDED, &good).is_ok());

        // FAIL: missing reason.
        let no_reason = json!({
            "proposal_id": "vpr_demo",
            "entity_name": "claudin-5",
            "entity_type": "protein"
        });
        assert!(validate_event_payload(EVENT_KIND_FINDING_ENTITY_ADDED, &no_reason).is_err());

        // FAIL: bad entity_type.
        let bad_type = json!({
            "proposal_id": "vpr_demo",
            "entity_name": "claudin-5",
            "entity_type": "fancy_new_thing",
            "reason": "x"
        });
        assert!(validate_event_payload(EVENT_KIND_FINDING_ENTITY_ADDED, &bad_type).is_err());

        // FAIL: empty entity_name.
        let empty_name = json!({
            "proposal_id": "vpr_demo",
            "entity_name": "",
            "entity_type": "protein",
            "reason": "x"
        });
        assert!(validate_event_payload(EVENT_KIND_FINDING_ENTITY_ADDED, &empty_name).is_err());
    }

    /// v0.73: state-aware bridge.reviewed tightening. The
    /// signature-pure validator only checks payload shape; this
    /// second-pass function rejects events whose bridge_id is not
    /// present on the local frontier.
    #[test]
    fn bridge_reviewed_state_aware_rejects_unknown_id() {
        let known: Vec<String> = vec!["vbr_aaaaaaaaaaaaaaaa".to_string()];

        // PASS: bridge_id matches a known bridge.
        assert!(
            validate_bridge_reviewed_against_state(
                &json!({
                    "bridge_id": "vbr_aaaaaaaaaaaaaaaa",
                    "status": "confirmed",
                }),
                &known,
            )
            .is_ok()
        );

        // FAIL: bridge_id is well-formed but absent from the frontier.
        let err = validate_bridge_reviewed_against_state(
            &json!({
                "bridge_id": "vbr_bbbbbbbbbbbbbbbb",
                "status": "confirmed",
            }),
            &known,
        )
        .expect_err("expected unknown bridge_id to be rejected");
        assert!(
            err.contains("not present on this frontier"),
            "error should explain the gap: {err}"
        );

        // FAIL: missing bridge_id (defensive; signature-pure layer
        // catches this too, but the state-aware layer must not panic
        // on malformed input).
        assert!(
            validate_bridge_reviewed_against_state(
                &json!({
                    "status": "confirmed",
                }),
                &known,
            )
            .is_err()
        );

        // FAIL: empty known list. Real frontiers may have zero
        // bridges; an event referencing any id must be rejected.
        assert!(
            validate_bridge_reviewed_against_state(
                &json!({
                    "bridge_id": "vbr_aaaaaaaaaaaaaaaa",
                    "status": "confirmed",
                }),
                &[],
            )
            .is_err()
        );
    }
}
