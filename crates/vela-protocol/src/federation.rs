//! v0.39: Hub federation — peer registry + conflict detection.
//!
//! Pre-v0.39, every Vela frontier had exactly one source of truth: the
//! single hub it was published to (`hub.constellate.science`). The substrate
//! claimed the kernel was content-addressed and signed, but the
//! distribution layer was centralized — there was no way for a second
//! hub to mirror a frontier and detect when its view diverged from
//! the original.
//!
//! v0.39.0 lands the *schema layer* of federation. A frontier can now
//! register peer hubs (id + URL + public key) in `Project.peers`, and
//! the kernel knows two new event kinds:
//!
//! - `frontier.synced_with_peer` — append-only record of a sync pass:
//!   what we exchanged, what hash we ended up agreeing on, how many
//!   findings differed.
//! - `frontier.conflict_detected` — emitted per finding when our view
//!   and the peer's view disagree on a substantive field (review
//!   verdict, confidence, retraction, presence).
//!
//! The actual sync runtime (HTTP fetch, manifest verification,
//! conflict-resolution proposal emission) ships in v0.39.1+. Same
//! staging discipline as v0.32 (Replication object) → v0.36.1
//! (Project.replications becomes authoritative) and v0.38.0 (causal
//! schema) → v0.38.1 (causal math).
//!
//! Doctrine for v0.39.0:
//! - The peer registry is a frontier-local declaration. Adding a peer
//!   does not yet trust their state; it just establishes who we know
//!   about.
//! - Peer signatures still verify under the same Ed25519 discipline
//!   as `actors`. A peer's `frontier.merged` event signed by their
//!   key can be replayed locally only when their pubkey is in our
//!   `peers` registry.
//! - Conflicts are recorded, not auto-resolved. v0.39.1+ will surface
//!   them through proposals so a human reviewer chooses which side
//!   to accept.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::events::{
    EVENT_SCHEMA, NULL_HASH, StateActor, StateEvent, StateTarget, compute_event_id, snapshot_hash,
};
use crate::project::Project;

/// v0.39: A registered peer hub the local frontier knows about.
/// Content-addressed by `(id, public_key)` so two registry entries
/// for the same peer with different keys can be detected as a
/// material change rather than silent overwrite.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerHub {
    /// Stable, namespaced identifier — the equivalent of an
    /// `actor.id` for hub-scale identities. Recommended form
    /// `hub:<short-name>` (e.g. `hub:vela-mirror-eu`).
    pub id: String,
    /// HTTPS URL where the peer publishes signed manifests. The
    /// expected shape is `<base>/manifest/<vfr_id>.json` with a
    /// detached signature at `<base>/manifest/<vfr_id>.sig`.
    pub url: String,
    /// Hex-encoded Ed25519 public key (64 hex chars) the peer signs
    /// their manifests with. Used to verify any
    /// `frontier.merged` event coming from them.
    pub public_key: String,
    /// ISO 8601 timestamp of when the peer was added to this
    /// frontier's registry.
    pub added_at: String,
    /// Optional human-readable note: "EU mirror, run by lab Z."
    /// Doesn't enter any content address; stored verbatim.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,
}

impl PeerHub {
    /// Validate the structural shape of a `PeerHub` before insertion.
    /// Specifically: id must be non-empty, url must be HTTPS, and
    /// public_key must be 64 hex chars.
    pub fn validate(&self) -> Result<(), String> {
        if self.id.trim().is_empty() {
            return Err("peer id must be non-empty".into());
        }
        if !self.url.starts_with("https://") {
            return Err(format!(
                "peer url must start with `https://` (got `{}`)",
                self.url
            ));
        }
        let trimmed = self.public_key.trim();
        if trimmed.len() != 64 {
            return Err(format!(
                "peer public_key must be 64 hex chars (got {})",
                trimmed.len()
            ));
        }
        if hex::decode(trimmed).is_err() {
            return Err("peer public_key must be valid hex".into());
        }
        Ok(())
    }
}

/// v0.39.1: Conflict taxonomy. The kinds of disagreement two hubs can
/// have over the same `vfr_id`. v0.39.0 left `kind` as an open string;
/// v0.39.1 pins it to this closed set, derived from auditing every
/// substantive field-level disagreement we expect to see.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictKind {
    /// Finding present in our frontier, absent in the peer's.
    MissingInPeer,
    /// Finding present in the peer's frontier, absent in ours.
    MissingLocally,
    /// Same `vf_id`, score differs by more than 0.05. Below the
    /// threshold it's noise from confidence recompute drift.
    ConfidenceDiverged,
    /// Same `vf_id`, one side has it retracted, the other doesn't.
    RetractedDiverged,
    /// Same `vf_id`, different `flags.review_state`.
    ReviewStateDiverged,
    /// Same `vf_id`, one side has it superseded, the other doesn't.
    SupersededDiverged,
    /// Same `vf_id`, different assertion text. This is a serious
    /// signal — `vf_id` is content-addressed over the assertion, so
    /// matching id with diverging text means a content-address
    /// collision or signing-bytes mismatch between implementations.
    AssertionTextDiverged,
    /// v0.41.0: peer's registry entry resolves but its
    /// `network_locator` returns 4xx/5xx. The peer hub is healthy and
    /// signed the entry, but the manifest URL the entry points at is
    /// dead. Common when frontiers move repos (e.g. v0.34.1 split
    /// `vela-science/vela` → `vela-science/vela-frontiers`) and the
    /// peer's published entry was never refreshed. Surfaces the
    /// stale-locator failure mode that "peer is reachable but
    /// content isn't" produces — distinct from a missing finding.
    BrokenLocator,
    /// v0.41.0: peer's registry entry exists but its signature does
    /// not verify against the registered owner pubkey. Either the
    /// signature is corrupt or the owner pubkey we registered for
    /// this peer is wrong. Halts content sync — the kernel won't
    /// trust unsigned-or-misverified state.
    UnverifiedPeerEntry,
}

impl ConflictKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ConflictKind::MissingInPeer => "missing_in_peer",
            ConflictKind::MissingLocally => "missing_locally",
            ConflictKind::ConfidenceDiverged => "confidence_diverged",
            ConflictKind::RetractedDiverged => "retracted_diverged",
            ConflictKind::ReviewStateDiverged => "review_state_diverged",
            ConflictKind::SupersededDiverged => "superseded_diverged",
            ConflictKind::AssertionTextDiverged => "assertion_text_diverged",
            ConflictKind::BrokenLocator => "broken_locator",
            ConflictKind::UnverifiedPeerEntry => "unverified_peer_entry",
        }
    }
}

/// One per-finding disagreement detected during sync.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Conflict {
    pub finding_id: String,
    pub kind: ConflictKind,
    /// Free-form context for the rendering layer ("our: 0.82, peer:
    /// 0.65"). Not part of any content address.
    pub detail: String,
}

/// Result of one `sync_with_peer` pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncReport {
    pub peer_id: String,
    pub our_snapshot_hash: String,
    pub peer_snapshot_hash: String,
    pub conflicts: Vec<Conflict>,
    /// Number of `StateEvent`s appended to our project (1 sync event +
    /// N conflict events).
    pub events_appended: usize,
}

/// v0.39.1: Diff two frontiers and produce a list of conflicts. Pure
/// function, no I/O. The peer's state is passed in directly so the
/// sync orchestrator can be unit-tested without HTTP.
///
/// Confidence diff threshold is 0.05 — below that it's recompute drift
/// (the v0.36.1 formula change moved scores by < 0.001 on real data).
#[must_use]
pub fn diff_frontiers(ours: &Project, theirs: &Project) -> Vec<Conflict> {
    use std::collections::HashMap;

    let our_by_id: HashMap<&str, &crate::bundle::FindingBundle> =
        ours.findings.iter().map(|f| (f.id.as_str(), f)).collect();
    let their_by_id: HashMap<&str, &crate::bundle::FindingBundle> =
        theirs.findings.iter().map(|f| (f.id.as_str(), f)).collect();

    let mut conflicts = Vec::new();

    // Findings only in ours.
    for id in our_by_id.keys() {
        if !their_by_id.contains_key(id) {
            conflicts.push(Conflict {
                finding_id: (*id).to_string(),
                kind: ConflictKind::MissingInPeer,
                detail: "present locally, absent in peer".to_string(),
            });
        }
    }
    // Findings only in theirs.
    for id in their_by_id.keys() {
        if !our_by_id.contains_key(id) {
            conflicts.push(Conflict {
                finding_id: (*id).to_string(),
                kind: ConflictKind::MissingLocally,
                detail: "present in peer, absent locally".to_string(),
            });
        }
    }
    // Findings in both — check field-level disagreements.
    for (id, ours_f) in &our_by_id {
        let Some(theirs_f) = their_by_id.get(id) else {
            continue;
        };
        if (ours_f.confidence.score - theirs_f.confidence.score).abs() > 0.05 {
            conflicts.push(Conflict {
                finding_id: (*id).to_string(),
                kind: ConflictKind::ConfidenceDiverged,
                detail: format!(
                    "ours: {:.3}, peer: {:.3}",
                    ours_f.confidence.score, theirs_f.confidence.score
                ),
            });
        }
        if ours_f.flags.retracted != theirs_f.flags.retracted {
            conflicts.push(Conflict {
                finding_id: (*id).to_string(),
                kind: ConflictKind::RetractedDiverged,
                detail: format!(
                    "ours: {}, peer: {}",
                    ours_f.flags.retracted, theirs_f.flags.retracted
                ),
            });
        }
        if ours_f.flags.review_state != theirs_f.flags.review_state {
            conflicts.push(Conflict {
                finding_id: (*id).to_string(),
                kind: ConflictKind::ReviewStateDiverged,
                detail: format!(
                    "ours: {:?}, peer: {:?}",
                    ours_f.flags.review_state, theirs_f.flags.review_state
                ),
            });
        }
        if ours_f.flags.superseded != theirs_f.flags.superseded {
            conflicts.push(Conflict {
                finding_id: (*id).to_string(),
                kind: ConflictKind::SupersededDiverged,
                detail: format!(
                    "ours: {}, peer: {}",
                    ours_f.flags.superseded, theirs_f.flags.superseded
                ),
            });
        }
        if ours_f.assertion.text.trim() != theirs_f.assertion.text.trim() {
            conflicts.push(Conflict {
                finding_id: (*id).to_string(),
                kind: ConflictKind::AssertionTextDiverged,
                detail:
                    "matching id but diverging assertion text — possible content-address collision"
                        .to_string(),
            });
        }
    }

    conflicts.sort_by(|a, b| {
        a.finding_id
            .cmp(&b.finding_id)
            .then_with(|| a.kind.as_str().cmp(b.kind.as_str()))
    });
    conflicts
}

/// v0.41.0: Record a single broken-locator conflict against a peer.
/// Emits one `frontier.synced_with_peer` event with `divergence_count
/// = 1` plus one `frontier.conflict_detected` event of kind
/// `broken_locator`. Used when the peer hub is reachable, its
/// registry entry signature verifies, but the locator URL the entry
/// points at returns 4xx/5xx — common for stale published locators
/// after a repo move.
pub fn record_locator_failure(
    project: &mut Project,
    peer_id: &str,
    vfr_id: &str,
    locator: &str,
    status: u16,
) -> SyncReport {
    let now = Utc::now().to_rfc3339();
    let our_hash = snapshot_hash(project);
    let frontier_id = project.frontier_id();
    let detail = format!("locator {locator} returned HTTP {status}");

    let synced_event = StateEvent {
        schema: EVENT_SCHEMA.to_string(),
        id: String::new(),
        kind: "frontier.synced_with_peer".to_string(),
        target: StateTarget {
            r#type: "frontier_observation".to_string(),
            id: frontier_id.clone(),
        },
        actor: StateActor {
            id: "federation".to_string(),
            r#type: "system".to_string(),
        },
        timestamp: now.clone(),
        reason: format!("synced with peer {peer_id} (broken locator)"),
        before_hash: NULL_HASH.to_string(),
        after_hash: NULL_HASH.to_string(),
        payload: json!({
            "peer_id": peer_id,
            "peer_snapshot_hash": "",
            "our_snapshot_hash": our_hash,
            "divergence_count": 1,
        }),
        caveats: Vec::new(),
        signature: None,
        schema_artifact_id: None,
    };
    let mut sync_ev = synced_event;
    sync_ev.id = compute_event_id(&sync_ev);

    let conflict_ev = StateEvent {
        schema: EVENT_SCHEMA.to_string(),
        id: String::new(),
        kind: "frontier.conflict_detected".to_string(),
        target: StateTarget {
            r#type: "frontier_observation".to_string(),
            id: frontier_id.clone(),
        },
        actor: StateActor {
            id: "federation".to_string(),
            r#type: "system".to_string(),
        },
        timestamp: now.clone(),
        reason: format!("peer={peer_id} kind=broken_locator {detail}"),
        before_hash: NULL_HASH.to_string(),
        after_hash: NULL_HASH.to_string(),
        payload: json!({
            "peer_id": peer_id,
            "finding_id": vfr_id,
            "kind": "broken_locator",
            "detail": detail,
        }),
        caveats: Vec::new(),
        signature: None,
        schema_artifact_id: None,
    };
    let mut conflict_ev = conflict_ev;
    conflict_ev.id = compute_event_id(&conflict_ev);

    project.events.push(sync_ev);
    project.events.push(conflict_ev);

    SyncReport {
        peer_id: peer_id.to_string(),
        our_snapshot_hash: our_hash,
        peer_snapshot_hash: String::new(),
        conflicts: vec![Conflict {
            finding_id: vfr_id.to_string(),
            kind: ConflictKind::BrokenLocator,
            detail,
        }],
        events_appended: 2,
    }
}

/// v0.41.0: Record an unverified-peer-entry conflict. Same shape as
/// `record_locator_failure` but for when the peer's registry entry
/// signature did not verify against the registered owner pubkey.
/// Sync halts before any content is fetched — the kernel won't trust
/// unsigned-or-misverified state.
pub fn record_unverified_entry(
    project: &mut Project,
    peer_id: &str,
    vfr_id: &str,
    reason: &str,
) -> SyncReport {
    let now = Utc::now().to_rfc3339();
    let our_hash = snapshot_hash(project);
    let frontier_id = project.frontier_id();

    let mut sync_ev = StateEvent {
        schema: EVENT_SCHEMA.to_string(),
        id: String::new(),
        kind: "frontier.synced_with_peer".to_string(),
        target: StateTarget {
            r#type: "frontier_observation".to_string(),
            id: frontier_id.clone(),
        },
        actor: StateActor {
            id: "federation".to_string(),
            r#type: "system".to_string(),
        },
        timestamp: now.clone(),
        reason: format!("synced with peer {peer_id} (unverified entry; halted)"),
        before_hash: NULL_HASH.to_string(),
        after_hash: NULL_HASH.to_string(),
        payload: json!({
            "peer_id": peer_id,
            "peer_snapshot_hash": "",
            "our_snapshot_hash": our_hash,
            "divergence_count": 1,
        }),
        caveats: Vec::new(),
        signature: None,
        schema_artifact_id: None,
    };
    sync_ev.id = compute_event_id(&sync_ev);

    let mut conflict_ev = StateEvent {
        schema: EVENT_SCHEMA.to_string(),
        id: String::new(),
        kind: "frontier.conflict_detected".to_string(),
        target: StateTarget {
            r#type: "frontier_observation".to_string(),
            id: frontier_id.clone(),
        },
        actor: StateActor {
            id: "federation".to_string(),
            r#type: "system".to_string(),
        },
        timestamp: now.clone(),
        reason: format!("peer={peer_id} kind=unverified_peer_entry {reason}"),
        before_hash: NULL_HASH.to_string(),
        after_hash: NULL_HASH.to_string(),
        payload: json!({
            "peer_id": peer_id,
            "finding_id": vfr_id,
            "kind": "unverified_peer_entry",
            "detail": reason,
        }),
        caveats: Vec::new(),
        signature: None,
        schema_artifact_id: None,
    };
    conflict_ev.id = compute_event_id(&conflict_ev);

    project.events.push(sync_ev);
    project.events.push(conflict_ev);

    SyncReport {
        peer_id: peer_id.to_string(),
        our_snapshot_hash: our_hash,
        peer_snapshot_hash: String::new(),
        conflicts: vec![Conflict {
            finding_id: vfr_id.to_string(),
            kind: ConflictKind::UnverifiedPeerEntry,
            detail: reason.to_string(),
        }],
        events_appended: 2,
    }
}

/// v0.85: Classify the merge action for a peer event set against
/// our local event log. Pure event-level algebra: takes peer event
/// summaries (id, parents) and our local pool, and decides whether
/// merge can proceed or whether ancestors must be fetched first.
///
/// Implements the federation half of `docs/THEORY.md` §5.2 / §5.3:
/// only causally down-closed event sets are valid replay inputs;
/// when ancestors are missing, merge is undefined until they are
/// fetched or an explicit fork policy is invoked.
///
/// Returns:
/// - [`AncestorAction::Proceed`] if every parent referenced by the
///   peer's events is already present in `our_events ∪ peer_events`.
///   Caller can safely apply [`sync_with_peer`] after persisting
///   the new events.
/// - [`AncestorAction::Fetch`] with the list of missing ancestor
///   ids, otherwise. Caller should fetch and re-classify before
///   applying sync.
///
/// This function only reads event ids and parent links; it does
/// not require the full event payloads. Suitable for event-summary
/// gossip and for federation flows that stream events incrementally
/// rather than synchronizing whole Projects.
pub fn classify_peer_event_set(
    our_events: &[StateEvent],
    peer_events: &[StateEvent],
) -> crate::ancestor_closure::AncestorAction {
    use crate::ancestor_closure::classify_ancestor_action;
    // Combine local and peer events into the candidate post-merge
    // set. Each event is represented as (id, parents). For the
    // current substrate, StateEvent does not yet carry an explicit
    // parents field (see THEORY.md target v0.7 in the schema column
    // of the current/target table); in v0.85 we treat empty parents
    // as the conservative default. Hubs that adopt explicit parents
    // wire them through here.
    let combined: Vec<(String, Vec<String>)> = our_events
        .iter()
        .chain(peer_events.iter())
        .map(|e| (e.id.clone(), event_parents(e)))
        .collect();
    classify_ancestor_action(combined)
}

/// Extract parent event ids from an event. v0.85: parents are
/// optional; events without explicit parents return an empty list.
/// When schema/reducer artifacts gain explicit parent fields
/// (target v0.7 per docs/THEORY.md §5.1), this function reads them
/// without changing callers.
fn event_parents(e: &StateEvent) -> Vec<String> {
    e.payload
        .get("parents")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|p| p.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// v0.39.1: Run a full sync pass against a peer's already-fetched
/// frontier state. Diffs, emits one `frontier.synced_with_peer`
/// event recording the pass, and one `frontier.conflict_detected`
/// event per disagreement. Returns the report; caller persists the
/// project.
///
/// Splitting fetch from sync this way lets the sync logic be
/// fully unit-testable without HTTP — the CLI pipes a real fetch
/// into this function.
pub fn sync_with_peer(project: &mut Project, peer_id: &str, peer: &Project) -> SyncReport {
    let our_hash = snapshot_hash(project);
    let peer_hash = snapshot_hash(peer);
    let conflicts = diff_frontiers(project, peer);

    let now = Utc::now().to_rfc3339();
    let frontier_id = project.frontier_id().clone();

    // v0.39.1 fix: federation events are frontier-level *observations*,
    // not finding-level state changes. Target the frontier (vfr_id)
    // with `target.type = "frontier_observation"` so:
    //   - replay's per-finding chain validator skips them (chain
    //     only runs on `target.type == "finding"`);
    //   - the orphan check skips them (orphan check only flags
    //     finding-targeted events whose finding_id is unknown).
    // The `finding_id` of each conflict still lives in the payload
    // for downstream queries; only the canonical event target is the
    // frontier.
    let synced_reason = format!("synced with peer {peer_id}");
    let mut synced_event = StateEvent {
        schema: EVENT_SCHEMA.to_string(),
        id: String::new(),
        kind: "frontier.synced_with_peer".to_string(),
        target: StateTarget {
            r#type: "frontier_observation".to_string(),
            id: frontier_id.clone(),
        },
        actor: StateActor {
            id: "federation".to_string(),
            r#type: "system".to_string(),
        },
        timestamp: now.clone(),
        reason: synced_reason,
        before_hash: NULL_HASH.to_string(),
        after_hash: NULL_HASH.to_string(),
        payload: json!({
            "peer_id": peer_id,
            "peer_snapshot_hash": peer_hash,
            "our_snapshot_hash": our_hash,
            "divergence_count": conflicts.len(),
        }),
        caveats: Vec::new(),
        signature: None,
        schema_artifact_id: None,
    };
    synced_event.id = compute_event_id(&synced_event);

    let mut conflict_events: Vec<StateEvent> = Vec::with_capacity(conflicts.len());
    for c in &conflicts {
        let reason = format!("peer={peer_id} kind={} {}", c.kind.as_str(), c.detail);
        let mut ev = StateEvent {
            schema: EVENT_SCHEMA.to_string(),
            id: String::new(),
            kind: "frontier.conflict_detected".to_string(),
            target: StateTarget {
                r#type: "frontier_observation".to_string(),
                id: frontier_id.clone(),
            },
            actor: StateActor {
                id: "federation".to_string(),
                r#type: "system".to_string(),
            },
            timestamp: now.clone(),
            reason,
            before_hash: NULL_HASH.to_string(),
            after_hash: NULL_HASH.to_string(),
            payload: json!({
                "peer_id": peer_id,
                "finding_id": c.finding_id,
                "kind": c.kind.as_str(),
                "detail": c.detail,
            }),
            caveats: Vec::new(),
            signature: None,
            schema_artifact_id: None,
        };
        ev.id = compute_event_id(&ev);
        conflict_events.push(ev);
    }

    let events_appended = 1 + conflict_events.len();
    project.events.push(synced_event);
    project.events.extend(conflict_events);

    SyncReport {
        peer_id: peer_id.to_string(),
        our_snapshot_hash: our_hash,
        peer_snapshot_hash: peer_hash,
        conflicts,
        events_appended,
    }
}

/// v0.41.0: Result of trying to discover a peer's frontier through
/// the hub's `/entries/<vfr_id>` endpoint. The runtime needs to
/// distinguish three failure modes — peer unreachable, registry
/// entry signature invalid, and locator URL dead — because each one
/// has a different remediation.
#[derive(Debug)]
pub enum DiscoveryResult {
    /// Hub returned a valid entry, signature verified, locator
    /// fetched, manifest parsed. Includes the project for
    /// downstream diff.
    Resolved(Project),
    /// Hub /entries/<vfr_id> returned 4xx/5xx — peer doesn't claim
    /// to know this vfr_id.
    EntryNotFound { vfr_id: String, status: u16 },
    /// Hub returned an entry but its signature does not verify
    /// against the registered peer pubkey. Halts content sync.
    UnverifiedEntry { vfr_id: String, reason: String },
    /// Hub entry verifies, but its `network_locator` URL returns
    /// 4xx/5xx. Stale-locator failure mode.
    BrokenLocator {
        vfr_id: String,
        locator: String,
        status: u16,
    },
    /// Network error to the hub itself or to the locator.
    Unreachable { url: String, error: String },
}

/// v0.41.0: Discover a peer frontier by routing through the hub's
/// `/entries/<vfr_id>` endpoint. Verifies the registry entry's
/// signature against `expected_owner_pubkey`, then follows
/// `entry.network_locator` to fetch the actual manifest.
///
/// This is the "real federation" path: hubs publish signed registry
/// entries pointing at content URLs; sync fetches both, verifying the
/// signature chain end-to-end. If any step fails, the failure mode
/// is captured as a typed result so the calling sync runtime can
/// emit the appropriate `Conflict` (BrokenLocator, UnverifiedEntry,
/// etc.) rather than blackhole'ing the error.
pub fn discover_peer_frontier(
    hub_url: &str,
    vfr_id: &str,
    expected_owner_pubkey: Option<&str>,
) -> DiscoveryResult {
    let hub = hub_url.trim_end_matches('/').to_string();
    let entries_url = format!("{hub}/entries/{vfr_id}");
    let vfr_owned = vfr_id.to_string();
    let expected = expected_owner_pubkey.map(|s| s.to_string());

    std::thread::spawn(move || -> DiscoveryResult {
        let resp = match reqwest::blocking::get(&entries_url) {
            Ok(r) => r,
            Err(e) => {
                return DiscoveryResult::Unreachable {
                    url: entries_url.clone(),
                    error: e.to_string(),
                };
            }
        };
        let status = resp.status();
        if status.as_u16() == 404 {
            return DiscoveryResult::EntryNotFound {
                vfr_id: vfr_owned,
                status: status.as_u16(),
            };
        }
        if !status.is_success() {
            return DiscoveryResult::Unreachable {
                url: entries_url.clone(),
                error: format!("hub returned HTTP {status}"),
            };
        }
        let body = match resp.text() {
            Ok(b) => b,
            Err(e) => {
                return DiscoveryResult::Unreachable {
                    url: entries_url.clone(),
                    error: format!("read body: {e}"),
                };
            }
        };
        let entry: crate::registry::RegistryEntry = match serde_json::from_str(&body) {
            Ok(e) => e,
            Err(e) => {
                return DiscoveryResult::UnverifiedEntry {
                    vfr_id: vfr_owned,
                    reason: format!("parse registry entry: {e}"),
                };
            }
        };

        // Verify signature.
        match crate::registry::verify_entry(&entry) {
            Ok(true) => {}
            Ok(false) => {
                return DiscoveryResult::UnverifiedEntry {
                    vfr_id: vfr_owned,
                    reason: "registry entry signature does not verify against entry.owner_pubkey"
                        .to_string(),
                };
            }
            Err(e) => {
                return DiscoveryResult::UnverifiedEntry {
                    vfr_id: vfr_owned,
                    reason: format!("signature verification error: {e}"),
                };
            }
        }
        // Cross-check expected pubkey if the caller supplied one.
        if let Some(want) = expected.as_deref()
            && entry.owner_pubkey != want
        {
            return DiscoveryResult::UnverifiedEntry {
                vfr_id: vfr_owned,
                reason: format!(
                    "entry owner_pubkey {} != expected peer pubkey {}",
                    &entry.owner_pubkey[..16],
                    &want[..16]
                ),
            };
        }

        // Follow locator to fetch the manifest.
        let locator = entry.network_locator.clone();
        let mresp = match reqwest::blocking::get(&locator) {
            Ok(r) => r,
            Err(e) => {
                return DiscoveryResult::BrokenLocator {
                    vfr_id: vfr_owned,
                    locator,
                    status: 0,
                }
                .with_error(e.to_string());
            }
        };
        let mstatus = mresp.status();
        if !mstatus.is_success() {
            return DiscoveryResult::BrokenLocator {
                vfr_id: vfr_owned,
                locator,
                status: mstatus.as_u16(),
            };
        }
        let mbody = match mresp.text() {
            Ok(b) => b,
            Err(e) => {
                return DiscoveryResult::BrokenLocator {
                    vfr_id: vfr_owned,
                    locator,
                    status: 0,
                }
                .with_error(e.to_string());
            }
        };
        match serde_json::from_str::<Project>(&mbody) {
            Ok(p) => DiscoveryResult::Resolved(p),
            Err(e) => DiscoveryResult::BrokenLocator {
                vfr_id: vfr_owned,
                locator,
                status: 0,
            }
            .with_error(format!("manifest parse: {e}")),
        }
    })
    .join()
    .unwrap_or(DiscoveryResult::Unreachable {
        url: hub_url.to_string(),
        error: "discovery thread panicked".to_string(),
    })
}

impl DiscoveryResult {
    fn with_error(self, _ctx: String) -> Self {
        // BrokenLocator already carries status; reserved hook for
        // richer diagnostics later.
        self
    }
}

/// v0.39.1: Fetch a peer's frontier JSON over HTTP. The URL is
/// expected to serve a JSON-serialized `Project`. Blocking call —
/// `vela federation sync` is a one-shot CLI verb, not a service.
///
/// Implementation note: the CLI top-level dispatcher runs inside a
/// tokio runtime, but `reqwest::blocking` panics if dropped inside
/// an async context. We escape into a dedicated OS thread that owns
/// its own runtime, making the call safe to issue from sync code
/// regardless of who's calling it.
///
/// Verification of peer signatures (and registry entries) is a
/// separate concern, addressed in v0.39.2+. v0.39.1 trusts the
/// transport so the sync diff/event-emission machinery can be
/// validated against real peer state first.
pub fn fetch_peer_frontier(url: &str) -> Result<Project, String> {
    let url_owned = url.to_string();
    let handle = std::thread::spawn(move || -> Result<Project, String> {
        let resp = reqwest::blocking::get(&url_owned)
            .map_err(|e| format!("HTTP GET {url_owned} failed: {e}"))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(format!("peer returned HTTP {status}"));
        }
        let body = resp
            .text()
            .map_err(|e| format!("read body from {url_owned}: {e}"))?;
        serde_json::from_str(&body)
            .map_err(|e| format!("parse peer frontier from {url_owned}: {e}"))
    });
    handle
        .join()
        .map_err(|_| "fetch thread panicked".to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good() -> PeerHub {
        PeerHub {
            id: "hub:test".into(),
            url: "https://example.invalid/".into(),
            public_key: "00".repeat(32),
            added_at: "2026-04-27T00:00:00Z".into(),
            note: String::new(),
        }
    }

    #[test]
    fn validates_correct_shape() {
        assert!(good().validate().is_ok());
    }

    #[test]
    fn rejects_empty_id() {
        let mut p = good();
        p.id = "  ".into();
        assert!(p.validate().is_err());
    }

    #[test]
    fn rejects_http_url() {
        let mut p = good();
        p.url = "http://insecure.example/".into();
        assert!(p.validate().is_err());
    }

    #[test]
    fn rejects_short_pubkey() {
        let mut p = good();
        p.public_key = "abcd".into();
        assert!(p.validate().is_err());
    }

    #[test]
    fn rejects_non_hex_pubkey() {
        let mut p = good();
        p.public_key = "z".repeat(64);
        assert!(p.validate().is_err());
    }

    // ── v0.39.1 sync runtime tests ───────────────────────────────────

    use crate::bundle::{
        Assertion, Conditions, Confidence, Evidence, Extraction, FindingBundle, Flags, Provenance,
        ReviewState,
    };
    use crate::project::{self, Project};

    fn finding(id: &str, score: f64) -> FindingBundle {
        let mut b = FindingBundle::new(
            Assertion {
                text: format!("claim {id}"),
                assertion_type: "mechanism".into(),
                entities: vec![],
                relation: None,
                direction: None,
                causal_claim: None,
                causal_evidence_grade: None,
            },
            Evidence {
                evidence_type: "experimental".into(),
                model_system: String::new(),
                species: None,
                method: String::new(),
                sample_size: Some("n=30".into()),
                effect_size: None,
                p_value: None,
                replicated: false,
                replication_count: None,
                evidence_spans: vec![],
            },
            Conditions {
                text: String::new(),
                species_verified: vec![],
                species_unverified: vec![],
                in_vitro: false,
                in_vivo: false,
                human_data: false,
                clinical_trial: false,
                concentration_range: None,
                duration: None,
                age_group: None,
                cell_type: None,
            },
            Confidence::raw(score, "test", 0.85),
            Provenance {
                source_type: "published_paper".into(),
                doi: None,
                pmid: None,
                pmc: None,
                openalex_id: None,
                url: None,
                title: "Test".into(),
                authors: vec![],
                year: Some(2025),
                journal: None,
                license: None,
                publisher: None,
                funders: vec![],
                extraction: Extraction::default(),
                review: None,
                citation_count: None,
            },
            Flags::default(),
        );
        b.id = id.to_string();
        b
    }

    fn assemble(name: &str, findings: Vec<FindingBundle>) -> Project {
        project::assemble(name, findings, 1, 0, "test")
    }

    #[test]
    fn diff_identical_frontiers_returns_no_conflicts() {
        let f = finding("vf_001", 0.7);
        let ours = assemble("ours", vec![f.clone()]);
        let theirs = assemble("theirs", vec![f]);
        let conflicts = diff_frontiers(&ours, &theirs);
        assert_eq!(conflicts.len(), 0);
    }

    #[test]
    fn diff_detects_missing_in_peer_and_locally() {
        let f1 = finding("vf_001", 0.7);
        let f2 = finding("vf_002", 0.7);
        let ours = assemble("ours", vec![f1.clone()]);
        let theirs = assemble("theirs", vec![f2.clone()]);
        let conflicts = diff_frontiers(&ours, &theirs);
        let kinds: Vec<&str> = conflicts.iter().map(|c| c.kind.as_str()).collect();
        assert!(kinds.contains(&"missing_in_peer"));
        assert!(kinds.contains(&"missing_locally"));
    }

    #[test]
    fn diff_detects_confidence_divergence_above_threshold() {
        let mut f_ours = finding("vf_001", 0.85);
        let mut f_theirs = finding("vf_001", 0.55);
        // Force same id by aligning content; here they share id by construction.
        f_ours.id = "vf_001".into();
        f_theirs.id = "vf_001".into();
        let ours = assemble("ours", vec![f_ours]);
        let theirs = assemble("theirs", vec![f_theirs]);
        let conflicts = diff_frontiers(&ours, &theirs);
        assert!(
            conflicts
                .iter()
                .any(|c| c.kind == ConflictKind::ConfidenceDiverged),
            "expected confidence_diverged in {conflicts:?}"
        );
    }

    #[test]
    fn diff_ignores_confidence_drift_below_threshold() {
        let mut f_ours = finding("vf_001", 0.700);
        let mut f_theirs = finding("vf_001", 0.730);
        f_ours.id = "vf_001".into();
        f_theirs.id = "vf_001".into();
        let ours = assemble("ours", vec![f_ours]);
        let theirs = assemble("theirs", vec![f_theirs]);
        let conflicts = diff_frontiers(&ours, &theirs);
        assert!(
            !conflicts
                .iter()
                .any(|c| c.kind == ConflictKind::ConfidenceDiverged),
            "0.03 drift should not flag: {conflicts:?}"
        );
    }

    #[test]
    fn diff_detects_retracted_divergence() {
        let mut f_ours = finding("vf_001", 0.7);
        let mut f_theirs = finding("vf_001", 0.7);
        f_ours.id = "vf_001".into();
        f_theirs.id = "vf_001".into();
        f_theirs.flags.retracted = true;
        let ours = assemble("ours", vec![f_ours]);
        let theirs = assemble("theirs", vec![f_theirs]);
        let conflicts = diff_frontiers(&ours, &theirs);
        assert!(
            conflicts
                .iter()
                .any(|c| c.kind == ConflictKind::RetractedDiverged)
        );
    }

    #[test]
    fn diff_detects_review_state_divergence() {
        let mut f_ours = finding("vf_001", 0.7);
        let mut f_theirs = finding("vf_001", 0.7);
        f_ours.id = "vf_001".into();
        f_theirs.id = "vf_001".into();
        f_theirs.flags.review_state = Some(ReviewState::Contested);
        let ours = assemble("ours", vec![f_ours]);
        let theirs = assemble("theirs", vec![f_theirs]);
        let conflicts = diff_frontiers(&ours, &theirs);
        assert!(
            conflicts
                .iter()
                .any(|c| c.kind == ConflictKind::ReviewStateDiverged)
        );
    }

    #[test]
    fn diff_detects_assertion_text_divergence() {
        let mut f_ours = finding("vf_001", 0.7);
        let mut f_theirs = finding("vf_001", 0.7);
        f_ours.id = "vf_001".into();
        f_theirs.id = "vf_001".into();
        f_theirs.assertion.text = "different claim".into();
        let ours = assemble("ours", vec![f_ours]);
        let theirs = assemble("theirs", vec![f_theirs]);
        let conflicts = diff_frontiers(&ours, &theirs);
        assert!(
            conflicts
                .iter()
                .any(|c| c.kind == ConflictKind::AssertionTextDiverged)
        );
    }

    #[test]
    fn sync_appends_one_synced_event_plus_one_per_conflict() {
        let mut f_ours = finding("vf_001", 0.7);
        let mut f_theirs = finding("vf_001", 0.7);
        f_ours.id = "vf_001".into();
        f_theirs.id = "vf_001".into();
        f_theirs.flags.retracted = true;
        let mut ours = assemble("ours", vec![f_ours]);
        let theirs = assemble("theirs", vec![f_theirs]);
        let events_before = ours.events.len();
        let report = sync_with_peer(&mut ours, "hub:test-peer", &theirs);
        assert_eq!(report.conflicts.len(), 1);
        assert_eq!(report.events_appended, 2); // 1 sync + 1 conflict
        assert_eq!(ours.events.len() - events_before, 2);
        // The first appended event is the sync record.
        let sync_ev = &ours.events[events_before];
        assert_eq!(sync_ev.kind, "frontier.synced_with_peer");
        assert_eq!(sync_ev.payload["divergence_count"].as_u64(), Some(1));
        // The second is the conflict.
        let conf_ev = &ours.events[events_before + 1];
        assert_eq!(conf_ev.kind, "frontier.conflict_detected");
        assert_eq!(conf_ev.payload["kind"], "retracted_diverged");
    }

    #[test]
    fn sync_with_clean_diff_emits_zero_divergence_event() {
        let f = finding("vf_001", 0.7);
        let mut ours = assemble("ours", vec![f.clone()]);
        let theirs = assemble("theirs", vec![f]);
        let report = sync_with_peer(&mut ours, "hub:test-peer", &theirs);
        assert_eq!(report.conflicts.len(), 0);
        assert_eq!(report.events_appended, 1);
        let last = ours.events.last().unwrap();
        assert_eq!(last.kind, "frontier.synced_with_peer");
        assert_eq!(last.payload["divergence_count"].as_u64(), Some(0));
    }

    fn make_event(id: &str, parents: &[&str]) -> StateEvent {
        StateEvent {
            schema: EVENT_SCHEMA.to_string(),
            id: id.to_string(),
            kind: "test.event".to_string(),
            target: StateTarget {
                r#type: "frontier_observation".to_string(),
                id: "vfr_test".to_string(),
            },
            actor: StateActor {
                id: "test".to_string(),
                r#type: "system".to_string(),
            },
            timestamp: "2026-05-09T00:00:00Z".to_string(),
            reason: "test".to_string(),
            before_hash: NULL_HASH.to_string(),
            after_hash: NULL_HASH.to_string(),
            payload: json!({"parents": parents}),
            caveats: vec![],
            signature: None,
            schema_artifact_id: None,
        }
    }

    #[test]
    fn classify_returns_proceed_when_peer_set_is_complete() {
        // Local has e1; peer has e2 with parent e1. Combined set
        // is causally down-closed: Proceed.
        let our_events = vec![make_event("e1", &[])];
        let peer_events = vec![make_event("e2", &["e1"])];
        let action = classify_peer_event_set(&our_events, &peer_events);
        assert!(matches!(
            action,
            crate::ancestor_closure::AncestorAction::Proceed
        ));
    }

    #[test]
    fn classify_returns_fetch_when_peer_references_missing_ancestor() {
        // Peer sends e3 with parent e2; we don't have e2.
        // Expected action: Fetch with missing=[e2].
        let our_events = vec![make_event("e1", &[])];
        let peer_events = vec![make_event("e3", &["e2"])];
        let action = classify_peer_event_set(&our_events, &peer_events);
        match action {
            crate::ancestor_closure::AncestorAction::Fetch { missing } => {
                assert_eq!(missing, vec!["e2"]);
            }
            other => panic!("expected Fetch, got {other:?}"),
        }
    }

    #[test]
    fn classify_handles_events_without_explicit_parents() {
        // Events without `parents` payload key: treated as having
        // no parents. Trivially down-closed.
        let our_events = vec![StateEvent {
            schema: EVENT_SCHEMA.to_string(),
            id: "e1".to_string(),
            kind: "test.event".to_string(),
            target: StateTarget {
                r#type: "frontier_observation".to_string(),
                id: "vfr_test".to_string(),
            },
            actor: StateActor {
                id: "test".to_string(),
                r#type: "system".to_string(),
            },
            timestamp: "2026-05-09T00:00:00Z".to_string(),
            reason: "test".to_string(),
            before_hash: NULL_HASH.to_string(),
            after_hash: NULL_HASH.to_string(),
            payload: json!({}),
            caveats: vec![],
            signature: None,
            schema_artifact_id: None,
        }];
        let peer_events = vec![];
        let action = classify_peer_event_set(&our_events, &peer_events);
        assert!(matches!(
            action,
            crate::ancestor_closure::AncestorAction::Proceed
        ));
    }
}
