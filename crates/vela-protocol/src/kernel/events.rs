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

/// Generic artifact lifecycle. Carries the full `Artifact` inline on
/// `payload.artifact` so protocol snapshots can be replayed without
/// resolving a sidecar file first.
pub const EVENT_KIND_ARTIFACT_ASSERTED: &str = "artifact.asserted";
pub const EVENT_KIND_ARTIFACT_REVIEWED: &str = "artifact.reviewed";
pub const EVENT_KIND_ARTIFACT_RETRACTED: &str = "artifact.retracted";

/// A verifier attachment was bound to a finding (target = vf_…). The attachment
/// travels in payload.attachment; the reducer appends it to the sidecar
/// verifier_attachments collection. Per-finding trust status is derived on read.
pub const EVENT_KIND_VERIFIER_ATTACHMENT_ADDED: &str = "verifier_attachment.added";

/// v0.51: Re-classify a finding or artifact's read-side
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

/// v0.79.4: Per-event attestation. The substrate's existing
/// frontier-wide signing path (`vela review <frontier>`) is
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

/// Review verdict over non-mutating frontier observation material,
/// such as research traces and correction returns. This records what
/// entered the review ledger without asserting a finding by itself.
pub const EVENT_KIND_FRONTIER_OBSERVATION_REVIEWED: &str = "frontier.observation_reviewed";

/// T7: a reviewer's decision on a Contradiction object (`vcx_`). The
/// event carries the full resolved `Contradiction` in
/// `payload.contradiction`; the reducer upserts it into
/// `Project.contradictions` (latest resolution per id wins). This is
/// the only canonical state a contradiction accrues — candidates are
/// derived from the graph and never written. Honest by construction:
/// the stored object's status records a *named reviewer's* judgment,
/// never platform-adjudicated truth.
pub const EVENT_KIND_CONTRADICTION_RESOLVED: &str = "contradiction.resolved";

/// A signed banked attempt (`vat_`) is deposited into the frontier. The full
/// [`crate::attempt::Attempt`] travels in `payload.attempt`; the reducer
/// verifies its id + signature and upserts it into `Project.attempts`.
pub const EVENT_KIND_ATTEMPT_DEPOSITED: &str = "attempt.deposited";

/// A signed cross-domain [`crate::transfer::Transfer`] is deposited. The full
/// object travels in `payload.transfer`; the reducer verifies its id +
/// signature and upserts it into `Project.transfers`. Admission (whether the
/// link is sound) is derived on read, never stored.
pub const EVENT_KIND_TRANSFER_DEPOSITED: &str = "transfer.deposited";

/// A signed significance [`crate::endorsement::Endorsement`] is deposited. The
/// object travels in `payload.endorsement`; the reducer verifies and upserts
/// into `Project.endorsements`. Endorsements are stored individually and NEVER
/// aggregated into a score.
pub const EVENT_KIND_ENDORSEMENT_DEPOSITED: &str = "endorsement.deposited";

/// An append-only lifecycle transition on an attempt. The
/// [`crate::attempt::ResolutionEvent`] travels in `payload.resolution`; the
/// reducer upserts it into `Project.attempt_resolutions` (idempotent by
/// `vre_` id; the head per attempt is the latest by `at`).
pub const EVENT_KIND_ATTEMPT_RESOLVED: &str = "attempt.resolved";

/// A signed statement-faithfulness attestation rides in
/// `payload.attestation`; the reducer upserts it (idempotent by vsa_ id).
pub const EVENT_KIND_STATEMENT_ATTESTED: &str = "statement.attested";

/// A TTL lease on an open obligation: fleet coordination so producers
/// route around in-flight work (the ETP ran 22M-implication crowd+AI
/// coordination on GitHub-issue leases; this is that primitive, signed).
/// Expiry is computed at READ time from event timestamp + ttl — the
/// reducer never reads a clock.
pub const EVENT_KIND_ATTEMPT_CLAIMED: &str = "attempt.claimed";

/// Priority registration: a content-addressed statement hash with a hub
/// receipt timestamp. External anchoring rides the release-archive
/// chain (every Zenodo/GH bundle embeds the event log), so the time
/// claim does not depend on trusting the hub.
pub const EVENT_KIND_STATEMENT_REGISTERED: &str = "statement.registered";

/// A reviewer's decision on a proposal, recorded as a first-class,
/// signed, append-only event. Before these existed, an accept graduated
/// into a signed domain event (`finding.asserted`, …) but a REJECT
/// mutated only the proposal file's `status` field — leaving no
/// tamper-evident, replayable trace of the decision. That asymmetry was
/// the silent-drop vector (THREAT_MODEL A11): a maintainer could suppress
/// an outside producer's proposal with no signed record. These three
/// kinds close it: every decision a key-registered reviewer makes is now
/// a side-table event (`before_hash == after_hash == NULL_HASH`, so it is
/// transparent to the per-finding hash chain) targeting the proposal,
/// signed by the reviewer key. Proposal `status` becomes a projection of
/// these events, verified against the stored field by the parity gate
/// (`verify_proposal_decision_parity`).
pub const EVENT_KIND_REVIEW_ACCEPTED: &str = "review.accepted";
pub const EVENT_KIND_REVIEW_REJECTED: &str = "review.rejected";
pub const EVENT_KIND_REVIEW_REVISION_REQUESTED: &str = "review.revision_requested";

/// Deterministic machine-verified admission (Phase 1A). Emitted, UNSIGNED, when a
/// proposal clears the exact-lane auto-admission predicate (kernel-clean, >=2
/// independent attachments derive `Verified`, a present-and-Survived
/// FormalismFidelity probe, Sound method integrity, no synthetic-source block, no
/// frontier contradiction). The trust is the frozen verifier + the audited
/// deterministic predicate, never a model and never a human rubber stamp; this
/// materializes the `machine_verified` tier, distinct from `review.accepted`
/// (human, signed, = significance/release). `before_hash == after_hash` (no
/// finding mutation): it is an audit record of the admission decision, binding
/// (proposal_id, attachment_ids, signal_status, policy_version).
pub const EVENT_KIND_POLICY_AUTO_ADMITTED: &str = "policy.auto_admitted";

/// The complete registry of event kinds the protocol can emit or store.
/// This is the writer-side universe; the reducer must handle every kind
/// here (a real arm or an explicit no-op) — `reducer::every_known_kind_reduces`
/// pins that invariant, so a new kind added to a writer without a reducer
/// arm fails CI instead of erroring on the next replay. If you add a kind
/// anywhere, add it here.
pub const KNOWN_EVENT_KINDS: &[&str] = &[
    "frontier.created",
    "finding.asserted",
    "finding.reviewed",
    "finding.noted",
    "finding.caveated",
    "finding.confidence_revised",
    "finding.rejected",
    "finding.retracted",
    "finding.superseded",
    "finding.dependency_invalidated",
    "finding.span_repaired",
    "assertion.reinterpreted_causal",
    "source_text.reviewed",
    "artifact.asserted",
    "artifact.reviewed",
    "artifact.retracted",
    "verifier_attachment.added",
    "tier.set",
    "evidence_atom.locator_repaired",
    "attestation.recorded",
    "frontier.observation_reviewed",
    "diff_pack.released",
    "diff_pack.reviewed",
    "verdict_conflict.resolved",
    "contradiction.resolved",
    "attempt.deposited",
    "attempt.resolved",
    "transfer.deposited",
    "endorsement.deposited",
    "statement.attested",
    "attempt.claimed",
    "statement.registered",
    "anchor.attached",
    "anchor.retracted",
    "proposal.recommended",
    "correction_return.review",
    "research_trace.review",
    "key.revoke",
    "review.accepted",
    "review.rejected",
    "review.revision_requested",
    "policy.auto_admitted",
];

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
        || id.starts_with("ci:")
        || handle.ends_with("-bot")
        || handle.ends_with("-sim")
    {
        "agent"
    } else {
        "human"
    }
}

/// The kind of a canonical state event: a typed enum over the wire strings.
///
/// It serializes to, and deserializes from, the exact `"domain.verb"` string the
/// log has always used, so canonical bytes and event ids are unchanged. The
/// difference is upstream: the reducer dispatches on this enum, so a removed or
/// mistyped handler is a compile error rather than a silent fall-through (the old
/// `match event.kind.as_str()` over bare string literals could drop a typo'd kind
/// into the default arm). `Other` round-trips any kind a future build does not
/// know, keeping the log forward-compatible. Single source of truth: the
/// `event_kinds!` table below generates `as_str` and `From<&str>` together, so
/// they cannot drift.
macro_rules! event_kinds {
    ($($variant:ident => $wire:literal),+ $(,)?) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum EventKind {
            $($variant,)+
            /// A kind not known to this build; holds its original wire string.
            Other(String),
        }

        impl EventKind {
            /// The canonical wire string (what serializes into the log).
            pub fn as_str(&self) -> &str {
                match self {
                    $(EventKind::$variant => $wire,)+
                    EventKind::Other(s) => s.as_str(),
                }
            }
        }

        impl From<&str> for EventKind {
            fn from(s: &str) -> Self {
                match s {
                    $($wire => EventKind::$variant,)+
                    other => EventKind::Other(other.to_string()),
                }
            }
        }
    };
}

event_kinds! {
    FrontierCreated => "frontier.created",
    FindingAsserted => "finding.asserted",
    FindingReviewed => "finding.reviewed",
    FindingNoted => "finding.noted",
    FindingCaveated => "finding.caveated",
    SourceTextReviewed => "source_text.reviewed",
    FindingConfidenceRevised => "finding.confidence_revised",
    FindingRejected => "finding.rejected",
    FindingRetracted => "finding.retracted",
    FindingDependencyInvalidated => "finding.dependency_invalidated",
    ArtifactAsserted => "artifact.asserted",
    VerifierAttachmentAdded => "verifier_attachment.added",
    ArtifactReviewed => "artifact.reviewed",
    ArtifactRetracted => "artifact.retracted",
    TierSet => "tier.set",
    EvidenceAtomLocatorRepaired => "evidence_atom.locator_repaired",
    FindingSpanRepaired => "finding.span_repaired",
    AttestationRecorded => "attestation.recorded",
    DiffPackReleased => "diff_pack.released",
    DiffPackReviewed => "diff_pack.reviewed",
    VerdictConflictResolved => "verdict_conflict.resolved",
    ContradictionResolved => "contradiction.resolved",
    AttemptDeposited => "attempt.deposited",
    TransferDeposited => "transfer.deposited",
    EndorsementDeposited => "endorsement.deposited",
    AttemptResolved => "attempt.resolved",
    StatementAttested => "statement.attested",
    AnchorAttached => "anchor.attached",
    AnchorRetracted => "anchor.retracted",
    AttemptClaimed => "attempt.claimed",
    StatementRegistered => "statement.registered",
    FindingSuperseded => "finding.superseded",
    AssertionReinterpretedCausal => "assertion.reinterpreted_causal",
    ProposalRecommended => "proposal.recommended",
    FrontierObservationReviewed => "frontier.observation_reviewed",
    CorrectionReturnReview => "correction_return.review",
    ResearchTraceReview => "research_trace.review",
    KeyRevoke => "key.revoke",
    ReviewAccepted => "review.accepted",
    ReviewRejected => "review.rejected",
    ReviewRevisionRequested => "review.revision_requested",
    PolicyAutoAdmitted => "policy.auto_admitted",
}

impl From<String> for EventKind {
    fn from(s: String) -> Self {
        EventKind::from(s.as_str())
    }
}

impl std::fmt::Display for EventKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// Ergonomic comparisons so the many `event.kind == "domain.verb"` and
// `event.kind == EVENT_KIND_X` (a `&str`) call sites keep compiling unchanged.
impl PartialEq<str> for EventKind {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}
impl PartialEq<&str> for EventKind {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

// Wire form is the bare string: `"kind":"finding.asserted"`, byte-identical to
// the pre-migration `String` field, so event ids and canonical hashes are stable.
impl Serialize for EventKind {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}
impl<'de> Deserialize<'de> for EventKind {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(EventKind::from(s.as_str()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateEvent {
    #[serde(default = "default_schema")]
    pub schema: String,
    pub id: String,
    pub kind: EventKind,
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
    /// reducer artifact (a content-addressed schema/reducer id).
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
    /// When the writer has already stamped a clock into the FINDING
    /// (annotation timestamp, confidence updated_at), it MUST pass that
    /// same instant here — the reducer reconstructs those fields from
    /// `event.timestamp`, and two clock reads diverge the replay hash
    /// by microseconds (caught live by verify_replay on the first
    /// replayed finding.noted events). None = stamp now.
    pub timestamp: Option<&'a str>,
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
    let timestamp = input
        .timestamp
        .map(|t| t.to_string())
        .unwrap_or_else(|| Utc::now().to_rfc3339());
    let mut event = StateEvent {
        schema: EVENT_SCHEMA.to_string(),
        id: String::new(),
        kind: input.kind.into(),
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
        kind: EVENT_KIND_KEY_REVOKE.into(),
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

/// Payload of a `review.accepted` / `review.rejected` /
/// `review.revision_requested` event. Records WHICH proposal was decided
/// and HOW, binding the decision to the exact proposal by its
/// content-addressed id (`vpr_…`). The event's `actor` is the deciding
/// reviewer; the event's `signature` (set by the caller) is the
/// non-repudiable proof the key holder made the call. `applied_event_id`
/// is set only for accepts and points at the domain event the accept
/// graduated into.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReviewDecisionPayload {
    /// The proposal this decision applies to (`vpr_…`, content-addressed).
    pub proposal_id: String,
    /// The proposal's kind (e.g. `finding.add`), copied for legibility so
    /// a reviewer reading the log need not cross-reference the proposal.
    pub proposal_kind: String,
    /// `accepted` | `rejected` | `revision_requested`. Redundant with the
    /// event kind but explicit in the payload so consumers that index by
    /// payload need not parse the kind string.
    pub verdict: String,
    /// For accepts: the domain event id (`vev_…`) the accept produced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applied_event_id: Option<String>,
}

/// Construct an unsigned `review.*` event for a proposal decision. The
/// event is a side-table record (`before_hash == after_hash ==
/// NULL_HASH`), so it is transparent to the per-finding hash chain. The
/// caller signs it (under the reviewer key) before persisting; `event.id`
/// is the content address of the unsigned shape, so signing never changes
/// the id. `verdict` must be one of `accepted` / `rejected` /
/// `revision_requested` and selects the event kind.
pub fn new_review_decision_event(
    proposal_id: &str,
    proposal_kind: &str,
    verdict: &str,
    applied_event_id: Option<String>,
    reviewer_id: &str,
    reason: &str,
    timestamp: Option<&str>,
) -> Result<StateEvent, String> {
    let kind = match verdict {
        "accepted" => EVENT_KIND_REVIEW_ACCEPTED,
        "rejected" => EVENT_KIND_REVIEW_REJECTED,
        "revision_requested" => EVENT_KIND_REVIEW_REVISION_REQUESTED,
        other => return Err(format!("unknown review verdict '{other}'")),
    };
    let payload = ReviewDecisionPayload {
        proposal_id: proposal_id.to_string(),
        proposal_kind: proposal_kind.to_string(),
        verdict: verdict.to_string(),
        applied_event_id,
    };
    let payload_value =
        serde_json::to_value(&payload).expect("ReviewDecisionPayload serializes to a JSON object");
    let timestamp = timestamp
        .map(|t| t.to_string())
        .unwrap_or_else(|| Utc::now().to_rfc3339());
    let mut event = StateEvent {
        schema: EVENT_SCHEMA.to_string(),
        id: String::new(),
        kind: kind.into(),
        target: StateTarget {
            r#type: "proposal".to_string(),
            id: proposal_id.to_string(),
        },
        actor: StateActor {
            id: reviewer_id.to_string(),
            r#type: actor_kind(reviewer_id).to_string(),
        },
        timestamp,
        reason: reason.to_string(),
        before_hash: NULL_HASH.to_string(),
        after_hash: NULL_HASH.to_string(),
        payload: payload_value,
        caveats: Vec::new(),
        signature: None,
        schema_artifact_id: None,
    };
    event.id = event_id(&event);
    Ok(event)
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
        kind: EVENT_KIND_EVIDENCE_ATOM_LOCATOR_REPAIRED.into(),
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
        kind: EVENT_KIND_CONTRADICTION_RESOLVED.into(),
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

/// Shared builder for the attempt-lifecycle events (`attempt.deposited` /
/// `attempt.resolved`): both target an attempt's `vat_` id and differ only in
/// `kind` and the payload they carry.
fn new_attempt_event(
    kind: &str,
    attempt_id: &str,
    actor_id: &str,
    actor_type: &str,
    reason: &str,
    payload: Value,
    caveats: Vec<String>,
) -> StateEvent {
    let mut event = StateEvent {
        schema: EVENT_SCHEMA.to_string(),
        id: String::new(),
        kind: kind.into(),
        target: StateTarget {
            r#type: "attempt".to_string(),
            id: attempt_id.to_string(),
        },
        actor: StateActor {
            id: actor_id.to_string(),
            r#type: actor_type.to_string(),
        },
        timestamp: Utc::now().to_rfc3339(),
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

/// Build an `attempt.deposited` event. The full signed object travels in
/// `payload.attempt`; the reducer verifies it and upserts into
/// `Project.attempts`.
pub fn new_attempt_deposited_event(
    attempt_id: &str,
    actor_id: &str,
    actor_type: &str,
    reason: &str,
    payload: Value,
    caveats: Vec<String>,
) -> StateEvent {
    new_attempt_event(
        EVENT_KIND_ATTEMPT_DEPOSITED,
        attempt_id,
        actor_id,
        actor_type,
        reason,
        payload,
        caveats,
    )
}

/// Build a `transfer.deposited` event. The full signed [`crate::transfer::Transfer`]
/// travels in `payload.transfer`; the reducer verifies it and upserts into
/// `Project.transfers`.
pub fn new_transfer_deposited_event(
    transfer_id: &str,
    actor_id: &str,
    actor_type: &str,
    reason: &str,
    payload: Value,
    caveats: Vec<String>,
) -> StateEvent {
    let mut event = StateEvent {
        schema: EVENT_SCHEMA.to_string(),
        id: String::new(),
        kind: EVENT_KIND_TRANSFER_DEPOSITED.into(),
        target: StateTarget {
            r#type: "transfer".to_string(),
            id: transfer_id.to_string(),
        },
        actor: StateActor {
            id: actor_id.to_string(),
            r#type: actor_type.to_string(),
        },
        timestamp: Utc::now().to_rfc3339(),
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

/// Build an `endorsement.deposited` event. The signed
/// [`crate::endorsement::Endorsement`] travels in `payload.endorsement`; the
/// reducer verifies it and upserts into `Project.endorsements`.
pub fn new_endorsement_deposited_event(
    endorsement_id: &str,
    actor_id: &str,
    actor_type: &str,
    reason: &str,
    payload: Value,
    caveats: Vec<String>,
) -> StateEvent {
    let mut event = StateEvent {
        schema: EVENT_SCHEMA.to_string(),
        id: String::new(),
        kind: EVENT_KIND_ENDORSEMENT_DEPOSITED.into(),
        target: StateTarget {
            r#type: "endorsement".to_string(),
            id: endorsement_id.to_string(),
        },
        actor: StateActor {
            id: actor_id.to_string(),
            r#type: actor_type.to_string(),
        },
        timestamp: Utc::now().to_rfc3339(),
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

/// Build an `attempt.resolved` event. The [`crate::attempt::ResolutionEvent`]
/// travels in `payload.resolution`; the reducer upserts it into
/// `Project.attempt_resolutions` (idempotent by `vre_` id).
pub fn new_attempt_resolved_event(
    attempt_id: &str,
    actor_id: &str,
    actor_type: &str,
    reason: &str,
    payload: Value,
    caveats: Vec<String>,
) -> StateEvent {
    new_attempt_event(
        EVENT_KIND_ATTEMPT_RESOLVED,
        attempt_id,
        actor_id,
        actor_type,
        reason,
        payload,
        caveats,
    )
}

/// Canonical hash of one evidence atom. Mirrors `finding_hash` for the
/// before/after pair on locator-repair events so a chain validator can
/// confirm that exactly the named atom changed and exactly the named
/// repair was applied.
pub fn evidence_atom_hash(atom: &crate::sources::EvidenceAtom) -> String {
    let bytes = canonical::to_canonical_bytes(atom).unwrap_or_default();
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
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

/// The integrity commitment over an event log.
///
/// Canonical order is the content-addressed event `id`, so the hash is
/// INDEPENDENT of how the events were loaded: the packet path (authored
/// array order), the `.vela/events/` directory path (filename
/// `vev_<id>.json`, i.e. id order), and a future one-file-per-event git
/// layout all canonicalize to the same sequence. This is the property the
/// git-backed migration needs (ADR 0001): committing events as individual
/// files must not redefine the hash. Sorting by `id` (rather than the
/// causal `(timestamp, id)` replay order) is also what keeps existing
/// signed locks byte-stable, because the directory loader already yields
/// id order. Causal REPLAY order is enforced separately in
/// `reducer::sorted_for_replay`; this function is only the commitment.
pub fn event_log_hash(events: &[StateEvent]) -> String {
    let mut sorted: Vec<&StateEvent> = events.iter().collect();
    sorted.sort_by(|a, b| a.id.cmp(&b.id));
    // Content-only: the log hash binds what the events SAY, not who signed them.
    // The `signature` field is stripped before hashing, so re-signing (the v0->v1
    // flip, a key rotation) never perturbs `event_log_hash`. Signing is therefore
    // orthogonal to content-addressing, the same discipline `snapshot_hash`
    // already follows (it removes the top-level `signatures` key). The signatures
    // still live on the events on disk; they are simply not part of this digest.
    let stripped: Vec<serde_json::Value> = sorted
        .iter()
        .map(|event| {
            let mut value = serde_json::to_value(event).unwrap_or(serde_json::Value::Null);
            if let serde_json::Value::Object(map) = &mut value {
                map.remove("signature");
            }
            value
        })
        .collect();
    let bytes = canonical::to_canonical_bytes(&stripped).unwrap_or_default();
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
        if let Err(err) = validate_event_payload(event.kind.as_str(), &event.payload) {
            conflicts.push(format!("event {} payload invalid: {err}", event.id));
        }
        // Side-table events (statement.registered, attempt.deposited, …)
        // are minted with before_hash == after_hash == NULL_HASH: they
        // record activity against a finding without transitioning its
        // state, so they are transparent to the per-finding hash chain.
        // Including them would break the chain between the real
        // transitions on either side.
        if event.before_hash == NULL_HASH && event.after_hash == NULL_HASH {
            continue;
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
        *kinds.entry(event.kind.to_string()).or_default() += 1;
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
        // Reviewer decision events. The proposal id binds the decision to
        // content (it is content-addressed); verdict must agree with the
        // kind so a consumer indexing by either field reads the same call.
        EVENT_KIND_REVIEW_ACCEPTED
        | EVENT_KIND_REVIEW_REJECTED
        | EVENT_KIND_REVIEW_REVISION_REQUESTED => {
            let proposal_id = require_str("proposal_id")?;
            if !proposal_id.starts_with("vpr_") {
                return Err(format!(
                    "payload.proposal_id must start with 'vpr_', got '{proposal_id}'"
                ));
            }
            require_str("proposal_kind")?;
            let verdict = require_str("verdict")?;
            let expected = match kind {
                EVENT_KIND_REVIEW_ACCEPTED => "accepted",
                EVENT_KIND_REVIEW_REJECTED => "rejected",
                _ => "revision_requested",
            };
            if verdict != expected {
                return Err(format!(
                    "review event kind '{kind}' requires verdict '{expected}', got '{verdict}'"
                ));
            }
            // applied_event_id only makes sense on an accept, and must be a
            // vev_ when present.
            if let Some(ev) = object.get("applied_event_id").and_then(Value::as_str) {
                if kind != EVENT_KIND_REVIEW_ACCEPTED {
                    return Err(format!(
                        "applied_event_id is only valid on '{EVENT_KIND_REVIEW_ACCEPTED}'"
                    ));
                }
                if !ev.starts_with("vev_") {
                    return Err(format!(
                        "payload.applied_event_id must start with 'vev_', got '{ev}'"
                    ));
                }
            }
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
        // a non-tiered kernel object (dataset, source, etc.)
        // fails at the validator boundary rather than silently
        // succeeding under the reducer's match-or-noop.
        EVENT_KIND_TIER_SET => {
            require_str("proposal_id")?;
            let object_type = require_str("object_type")?;
            if !matches!(object_type, "finding" | "artifact") {
                return Err(format!(
                    "tier.set object_type '{object_type}' must be one of finding, artifact"
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
        "verifier_attachment.added" => {
            // `proposal_id` is present when the attachment came through the
            // propose/accept flow, and absent when a verifier (e.g. CI) directly
            // signs its own evidence event. Evidence carries no signer-authority
            // claim, so it needs no human accept. Either way the embedded
            // attachment object is the load-bearing payload, and the reducer
            // re-verifies its content-addressed id on apply.
            if let Some(v) = object.get("proposal_id")
                && !v.is_string()
            {
                return Err(
                    "verifier_attachment.added payload.proposal_id must be a string when present"
                        .to_string(),
                );
            }
            if !object.get("attachment").is_some_and(|v| v.is_object()) {
                return Err(
                    "verifier_attachment.added payload.attachment must be an object".to_string(),
                );
            }
        }
        // Loader=reducer parity: every kind the reducer replays must
        // also pass payload validation, or `vela check`'s event-replay
        // verdict reports valid history as conflict. These arms are
        // signature-pure shape checks; the reducer arms re-verify the
        // embedded objects' own ids/signatures on apply.
        "verdict_conflict.resolved" => {
            if !object.get("conflict").is_some_and(|v| v.is_object()) {
                return Err(
                    "verdict_conflict.resolved payload.conflict must be an object".to_string(),
                );
            }
        }
        "contradiction.resolved" => {
            if !object.get("contradiction").is_some_and(|v| v.is_object()) {
                return Err(
                    "contradiction.resolved payload.contradiction must be an object".to_string(),
                );
            }
        }
        EVENT_KIND_ATTEMPT_DEPOSITED => {
            if !object.get("attempt").is_some_and(|v| v.is_object()) {
                return Err("attempt.deposited payload.attempt must be an object".to_string());
            }
        }
        EVENT_KIND_TRANSFER_DEPOSITED => {
            if !object.get("transfer").is_some_and(|v| v.is_object()) {
                return Err("transfer.deposited payload.transfer must be an object".to_string());
            }
        }
        EVENT_KIND_ENDORSEMENT_DEPOSITED => {
            if !object.get("endorsement").is_some_and(|v| v.is_object()) {
                return Err(
                    "endorsement.deposited payload.endorsement must be an object".to_string(),
                );
            }
        }
        EVENT_KIND_ATTEMPT_RESOLVED => {
            if !object.get("resolution").is_some_and(|v| v.is_object()) {
                return Err("attempt.resolved payload.resolution must be an object".to_string());
            }
        }
        EVENT_KIND_STATEMENT_ATTESTED => {
            if !object.get("attestation").is_some_and(|v| v.is_object()) {
                return Err("statement.attested payload.attestation must be an object".to_string());
            }
        }
        EVENT_KIND_ATTEMPT_CLAIMED => {
            let obligation_id = require_str("obligation_id")?;
            if obligation_id.trim().is_empty() {
                return Err("payload.obligation_id must be non-empty".to_string());
            }
            if !object
                .get("lease_ttl_seconds")
                .is_some_and(|v| v.as_u64().is_some())
            {
                return Err(
                    "attempt.claimed payload.lease_ttl_seconds must be a non-negative integer"
                        .to_string(),
                );
            }
        }
        EVENT_KIND_STATEMENT_REGISTERED => {
            let hash = require_str("statement_hash")?;
            if hash.len() != 64 || hex::decode(hash).is_err() {
                return Err(
                    "payload.statement_hash must be 32 bytes of hex (64 hex chars)".to_string(),
                );
            }
            if let Some(finding) = object.get("finding_id")
                && !finding.is_null()
                && !finding.is_string()
            {
                return Err("payload.finding_id must be a string when present".to_string());
            }
        }
        "proposal.recommended" => {
            require_str("proposal_id")?;
        }
        "anchor.attached" => {
            if !payload.get("anchor_link").is_some_and(Value::is_object) {
                return Err("anchor.attached payload.anchor_link must be an object".to_string());
            }
        }
        "anchor.retracted" => {
            if !payload
                .get("anchor_link_id")
                .and_then(Value::as_str)
                .is_some_and(|s| !s.trim().is_empty())
            {
                return Err("anchor.retracted payload.anchor_link_id must be non-empty".to_string());
            }
        }
        // Historical audit-record kinds: the reducer replays them as
        // no-ops; the payload shape is whatever the retired surface
        // minted. Object-ness is already enforced above.
        "correction_return.review" | "research_trace.review" => {}

        // policy.auto_admitted (Phase 1A): deterministic machine-verified admission
        // audit record. The audit record is the only accountability artifact for
        // a human-free admit (checklist #10), so the binding fields are mandatory
        // and well-formed: the proposal it admitted, the claim digest the gate
        // matched, the frozen policy version, and the frozen verifier-env hash —
        // these let an auditor re-derive a FLOOR admission (reproduce the witness
        // under `verifier_env_hash` + check `claim_digest` against the assertion)
        // independently of attachments. `attachment_ids` lists the corroborating
        // attachments and MAY be empty: a floor-sufficient exact-lane admit has
        // none — the frozen verifier + faithful binding is itself the proof.
        "policy.auto_admitted" => {
            require_str("proposal_id")?;
            require_str("claim_digest")?;
            require_str("policy_version")?;
            require_str("verifier_env_hash")?;
            match payload.get("attachment_ids") {
                Some(serde_json::Value::Array(ids)) => {
                    if !ids.iter().all(|v| v.is_string()) {
                        return Err(
                            "policy.auto_admitted: attachment_ids must be strings".to_string()
                        );
                    }
                }
                _ => {
                    return Err("policy.auto_admitted: attachment_ids must be an array".to_string());
                }
            }
        }

        other => return Err(format!("unknown event kind '{other}'")),
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

/// The canonical content-address preimage bytes of an event — the exact bytes
/// hashed to form its `vev_` id. Deliberately EXCLUDES the event's own `id`,
/// `signature`, and `schema_artifact_id`, so the preimage is stable under
/// legitimate re-signing/co-signing. Shared by `event_id` and the Merkle
/// transparency log (`crate::merkle`) so a log leaf is exactly the event's
/// content address — immune to re-signing and reproducible by any independent
/// implementation. Changing this shape is a protocol break.
pub fn event_content_preimage_bytes(event: &StateEvent) -> Vec<u8> {
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
    canonical::to_canonical_bytes(&content).unwrap_or_default()
}

pub fn event_id(event: &StateEvent) -> String {
    format!(
        "vev_{}",
        &hex::encode(Sha256::digest(event_content_preimage_bytes(event)))[..16]
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::{
        Assertion, Conditions, Confidence, Evidence, Extraction, FindingBundle, Flags, Provenance,
    };
    use crate::project;

    #[test]
    fn snapshot_hash_exclusion_keys_exist_on_project() {
        // snapshot_hash removes "events"/"signatures"/"proof_state" by string
        // key from the serialized Project so the derived/mutable plane is
        // excluded from the hash. If a future serde rename or field rename made
        // one of these keys stop existing, the remove() would silently no-op and
        // snapshot_hash would begin covering the event log — a global byte-parity
        // break with NO compiler error. This pins the contract cheaply.
        let project = project::assemble("guard", vec![finding()], 0, 0, "guard");
        let value = serde_json::to_value(&project).expect("serialize Project");
        let map = value.as_object().expect("Project serializes as an object");
        for key in ["events", "signatures", "proof_state"] {
            assert!(
                map.contains_key(key),
                "snapshot_hash excludes `{key}` by string key, but it is absent from \
                 serde_json::to_value(Project) — the exclusion would silently no-op"
            );
        }
    }

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
                method: "assay".to_string(),
                replicated: false,
                replication_count: None,
                evidence_spans: Vec::new(),
            },
            Conditions {
                text: "mouse model".to_string(),
                duration: None,
            },
            Confidence::raw(0.6, "test", 0.8),
            Provenance {
                source_type: "published_paper".to_string(),
                doi: None,
                url: None,
                title: "Test source".to_string(),
                authors: Vec::new(),
                year: Some(2026),
                license: None,
                publisher: None,
                funders: Vec::new(),
                extraction: Extraction::default(),
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
            timestamp: None,
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
            timestamp: None,
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
            timestamp: None,
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
            timestamp: None,
        });
        let mut frontier = project::assemble("test", vec![finding], 0, 0, "test");
        frontier.events.push(event);

        let report = replay_report(&frontier);
        assert!(report.ok, "{:?}", report.conflicts);
        assert_eq!(report.status, "ok");
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
    }

    #[test]
    fn validates_policy_auto_admitted_payload() {
        // PASS: all binding fields present + well-formed.
        let good = json!({
            "proposal_id": "vpr_abc",
            "claim_digest": "deadbeefdeadbeef",
            "attachment_ids": ["vva_a", "vva_b"],
            "policy_version": "exact-lane.v1",
            "verifier_env_hash": "sha256:cafe"
        });
        assert!(validate_event_payload(EVENT_KIND_POLICY_AUTO_ADMITTED, &good).is_ok());

        // FAIL: the pre-hardening minimal payload (proposal_id only) is now rejected.
        let minimal = json!({ "proposal_id": "vpr_abc" });
        assert!(validate_event_payload(EVENT_KIND_POLICY_AUTO_ADMITTED, &minimal).is_err());

        // PASS: empty attachment_ids — a floor-sufficient admit has no
        // attachments; the frozen verifier + faithful binding is the proof, and
        // claim_digest + verifier_env_hash are the accountability.
        let floor_admit = json!({
            "proposal_id": "vpr_abc",
            "claim_digest": "deadbeef",
            "attachment_ids": [],
            "policy_version": "exact-lane.v1",
            "verifier_env_hash": "sha256:cafe"
        });
        assert!(validate_event_payload(EVENT_KIND_POLICY_AUTO_ADMITTED, &floor_admit).is_ok());

        // FAIL: a missing claim_digest (the floor accountability) still rejects.
        let no_digest = json!({
            "proposal_id": "vpr_abc",
            "attachment_ids": [],
            "policy_version": "exact-lane.v1",
            "verifier_env_hash": "sha256:cafe"
        });
        assert!(validate_event_payload(EVENT_KIND_POLICY_AUTO_ADMITTED, &no_digest).is_err());

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

    #[test]
    fn event_log_hash_is_independent_of_input_order() {
        // ADR 0001 Phase 0a: the integrity commitment must not depend on how
        // the events were loaded (packet authored-order vs `.vela/events/`
        // filename-order vs a future git per-file layout). event_log_hash
        // canonicalizes on the content-addressed event id, so any permutation
        // of the same events hashes identically.
        let mk = |id: &str, ts: &str| StateEvent {
            schema: EVENT_SCHEMA.to_string(),
            id: id.to_string(),
            kind: "note.added".into(),
            target: StateTarget {
                r#type: "finding".to_string(),
                id: "vf_x".to_string(),
            },
            actor: StateActor {
                id: "reviewer:t".to_string(),
                r#type: "human".to_string(),
            },
            timestamp: ts.to_string(),
            reason: "t".to_string(),
            before_hash: String::new(),
            after_hash: String::new(),
            payload: Value::Null,
            caveats: vec![],
            signature: None,
            schema_artifact_id: None,
        };
        // ids deliberately NOT in timestamp order: proves the canonical order
        // is id-sort (load-path stable), not (timestamp, id) replay order.
        let a = mk("vev_c", "2026-01-01T00:00:03Z");
        let b = mk("vev_a", "2026-01-01T00:00:01Z");
        let c = mk("vev_b", "2026-01-01T00:00:02Z");
        let forward = vec![a.clone(), b.clone(), c.clone()];
        let shuffled = vec![c, a.clone(), b];
        assert_eq!(
            event_log_hash(&forward),
            event_log_hash(&shuffled),
            "event_log_hash must be independent of input order"
        );
        let mut reversed = forward.clone();
        reversed.reverse();
        assert_eq!(event_log_hash(&forward), event_log_hash(&reversed));
        // sanity: it is NOT the trivial empty hash
        assert_ne!(event_log_hash(&forward), event_log_hash(&[]));
    }
}
