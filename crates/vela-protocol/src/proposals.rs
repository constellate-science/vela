//! Proposal-first frontier writes and proof freshness tracking.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::bundle::{Annotation, Artifact, ConfidenceMethod, FindingBundle};
use crate::canonical;
use crate::events::{self, NULL_HASH, StateActor, StateEvent, StateTarget};
use crate::project::{self, Project};
use crate::propagate::{self, PropagationAction};
use crate::repo;

pub const PROPOSAL_SCHEMA: &str = "vela.proposal.v0.1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateProposal {
    #[serde(default = "default_schema")]
    pub schema: String,
    pub id: String,
    pub kind: String,
    pub target: StateTarget,
    pub actor: StateActor,
    pub created_at: String,
    /// v0.67: when an agent drafts a proposal long before the
    /// reviewer accepts it, `drafted_at` records the draft moment.
    /// `created_at` records the moment the proposal entered the
    /// canonical store. The throughput dashboard reads against
    /// `drafted_at` when present, falling back to `created_at`,
    /// so the "median proposal-to-event latency" surfaces real
    /// reviewer queue time rather than zero.
    /// Backward-compatible: pre-v0.67 proposals load with `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drafted_at: Option<String>,
    pub reason: String,
    #[serde(default)]
    pub payload: Value,
    #[serde(default)]
    pub source_refs: Vec<String>,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewed_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applied_event_id: Option<String>,
    #[serde(default)]
    pub caveats: Vec<String>,
    /// v0.22 (Agent Inbox): when a proposal originates from a scoped
    /// agent run (e.g. Literature Scout reading a PDF folder), this
    /// captures the model, the run id, and the wall-clock window.
    /// The substrate stays dumb — it does not know whether the
    /// proposer was a human, a Claude run, a GPT run, or a lab
    /// pipeline; this is informational provenance only, surfaced in
    /// the Workbench Inbox so reviewers can judge what they're
    /// looking at. Optional + skip-if-none so existing frontiers
    /// without proposals serialize byte-identically.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_run: Option<AgentRun>,
}

/// Agent provenance attached to a `StateProposal`.
///
/// Doctrine: the substrate stays model-agnostic. Agents — Literature
/// Scout, Notes Compiler, Code Analyst, etc. — sit in the
/// `vela-scientist` crate (or external code) and write proposals into
/// a frontier through the existing protocol. This struct is the
/// reviewer-facing record of *who proposed what, with what model,
/// during which run* — never used as access control or trust
/// assignment.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentRun {
    /// Stable agent name (e.g. "literature-scout"). Pairs with the
    /// proposal's `actor.id == "agent:literature-scout"`.
    pub agent: String,
    /// Model identifier (e.g. "claude-sonnet-4-6"). Free-form so the
    /// substrate never has to enumerate model names.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub model: String,
    /// Run identifier — typically a UUID or short hash. Lets the
    /// reviewer group multiple proposals that came out of the same
    /// agent invocation.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub run_id: String,
    /// ISO-8601 wall-clock start of the run.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub started_at: String,
    /// ISO-8601 wall-clock end. Optional because some agents stream.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<String>,
    /// Free-form context the reviewer should see — e.g. the input
    /// folder path, the count of papers processed, the prompt
    /// version. Kept as a flat string map so it round-trips cleanly
    /// through canonical JSON without imposing a schema.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub context: BTreeMap<String, String>,
    /// v0.49: explicit tool-call traces from this run. Each entry
    /// records one tool invocation by content-addressable summary
    /// (tool name + input hash + output hash + duration). Lets a
    /// reviewer see what the agent actually called without bloating
    /// the bundle with raw payloads. Optional + skip-if-empty so
    /// existing frontiers round-trip byte-identically.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tool_calls: Vec<ToolCallTrace>,
    /// v0.49: declared permission state for this run. Lists the
    /// data sources the agent had read access to and the tools it
    /// could invoke. Reviewers compare this declaration against
    /// `tool_calls` to spot drift. Optional + skip-if-empty so
    /// existing frontiers round-trip byte-identically.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<PermissionState>,
}

/// One tool invocation made during an `AgentRun`. Stored as a
/// content-addressable summary, never the raw payload — keeps the
/// bundle bounded while preserving "did this happen, with what
/// inputs, returning what outputs" for reviewer audit. v0.49.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolCallTrace {
    /// Tool identifier (e.g. "pubmed_search", "arxiv_fetch", "compile").
    pub tool: String,
    /// SHA-256 hex of the canonical-JSON input. 64-char.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub input_sha256: String,
    /// SHA-256 hex of the canonical-JSON output. 64-char. Optional
    /// for tools whose output is opaque (a side effect, a navigation,
    /// etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_sha256: Option<String>,
    /// ISO-8601 wall-clock start of the call.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub at: String,
    /// Wall-clock duration in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u32>,
    /// Optional non-error status string (e.g. "ok", "rate_limited",
    /// "partial"). Kept free-form so a tool layer can emit whatever
    /// taxonomy it wants without protocol bumps.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub status: String,
    /// Optional human-readable error detail when `status` indicates a
    /// failure. Free-form so tool layers can carry a stack frame, an
    /// HTTP response body, or a one-line summary — whatever a
    /// reviewer needs to audit what went wrong without re-running the
    /// agent. Skipped when empty so successful calls round-trip
    /// byte-identically.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error_message: String,
}

/// Declared permission boundary for an `AgentRun`. Lists what the
/// agent could read and which tools it could call. Reviewers can
/// diff this against `tool_calls` to spot scope creep. v0.49.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PermissionState {
    /// Data sources the agent had read access to. Free-form URIs:
    /// `pubmed:`, `dataset:`, `frontier:vfr_…`, `path:./papers/…`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub data_access: Vec<String>,
    /// Tool identifiers the agent was allowed to call. Should be the
    /// allow-list `tool_calls[*].tool` is checked against by the
    /// runtime.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tool_access: Vec<String>,
    /// Optional human-readable note explaining the scope (e.g.
    /// "read-only access to BBB Flagship; can call pubmed search
    /// and arxiv fetch only"). Reviewer affordance only.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProposalSummary {
    pub total: usize,
    pub pending_review: usize,
    pub accepted: usize,
    pub rejected: usize,
    pub applied: usize,
    #[serde(default)]
    pub by_kind: BTreeMap<String, usize>,
    #[serde(default)]
    pub duplicate_ids: Vec<String>,
    #[serde(default)]
    pub invalid_targets: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofState {
    #[serde(default)]
    pub latest_packet: ProofPacketState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_event_at_export: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stale_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofPacketState {
    pub generated_at: Option<String>,
    pub snapshot_hash: Option<String>,
    pub event_log_hash: Option<String>,
    pub packet_manifest_hash: Option<String>,
    pub status: String,
}

impl Default for ProofPacketState {
    fn default() -> Self {
        Self {
            generated_at: None,
            snapshot_hash: None,
            event_log_hash: None,
            packet_manifest_hash: None,
            status: "never_exported".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CreateProposalResult {
    pub proposal_id: String,
    pub finding_id: String,
    pub status: String,
    pub applied_event_id: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ImportProposalReport {
    pub imported: usize,
    pub applied: usize,
    pub rejected: usize,
    pub duplicates: usize,
    pub wrote_to: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProposalValidationReport {
    pub ok: bool,
    pub checked: usize,
    pub valid: usize,
    pub invalid: usize,
    #[serde(default)]
    pub errors: Vec<String>,
    #[serde(default)]
    pub proposal_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProposalPreview {
    pub proposal_id: String,
    pub kind: String,
    pub target: StateTarget,
    pub reviewer: String,
    #[serde(default)]
    pub changed_findings: Vec<String>,
    /// Field-level before/after for each changed finding (assertion text, type,
    /// and confidence), so a reviewer reads what the change asserts, not only a
    /// count delta. Confidence is a formatted string to keep this struct `Eq`.
    #[serde(default)]
    pub changed_finding_details: Vec<ChangedFindingDetail>,
    #[serde(default)]
    pub changed_artifacts: Vec<String>,
    #[serde(default)]
    pub new_event_ids: Vec<String>,
    #[serde(default)]
    pub event_kinds: Vec<String>,
    pub findings_before: usize,
    pub findings_after: usize,
    pub findings_delta: isize,
    pub artifacts_before: usize,
    pub artifacts_after: usize,
    pub artifacts_delta: isize,
    pub events_before: usize,
    pub events_after: usize,
    pub events_delta: isize,
    pub proof_would_be_stale: bool,
    pub applied_event_id: String,
}

/// Field-level before/after for one changed finding. All fields are optional:
/// a `finding.add` has no `before`, a retract no `after`. Confidence is a
/// formatted string so the containing `ProposalPreview` can stay `Eq`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChangedFindingDetail {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assertion_before: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assertion_after: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assertion_type_before: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assertion_type_after: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence_before: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence_after: Option<String>,
}

/// Build the field-level detail for each changed finding by looking it up in the
/// before and after states. Both lookups can miss (add/retract), so each side is
/// optional.
fn build_changed_finding_details(
    before: &Project,
    after: &Project,
    ids: &[String],
) -> Vec<ChangedFindingDetail> {
    ids.iter()
        .map(|id| {
            let fa = before.findings.iter().find(|f| &f.id == id);
            let fb = after.findings.iter().find(|f| &f.id == id);
            ChangedFindingDetail {
                id: id.clone(),
                assertion_before: fa.map(|f| f.assertion.text.clone()),
                assertion_after: fb.map(|f| f.assertion.text.clone()),
                assertion_type_before: fa.map(|f| f.assertion.assertion_type.clone()),
                assertion_type_after: fb.map(|f| f.assertion.assertion_type.clone()),
                confidence_before: fa.map(|f| format!("{:.2}", f.confidence.score)),
                confidence_after: fb.map(|f| format!("{:.2}", f.confidence.score)),
            }
        })
        .collect()
}

#[derive(Debug, Clone)]
pub struct ProofPacketRecord {
    pub generated_at: String,
    pub snapshot_hash: String,
    pub event_log_hash: String,
    pub packet_manifest_hash: String,
}

fn default_schema() -> String {
    PROPOSAL_SCHEMA.to_string()
}

#[allow(clippy::too_many_arguments)]
pub fn new_proposal(
    kind: impl Into<String>,
    target: StateTarget,
    actor_id: impl Into<String>,
    actor_type: impl Into<String>,
    reason: impl Into<String>,
    payload: Value,
    source_refs: Vec<String>,
    caveats: Vec<String>,
) -> StateProposal {
    let created_at = Utc::now().to_rfc3339();
    let mut proposal = StateProposal {
        schema: PROPOSAL_SCHEMA.to_string(),
        id: String::new(),
        kind: kind.into(),
        target,
        actor: StateActor {
            id: actor_id.into(),
            r#type: actor_type.into(),
        },
        created_at,
        drafted_at: None,
        reason: reason.into(),
        payload,
        source_refs,
        status: "pending_review".to_string(),
        reviewed_by: None,
        reviewed_at: None,
        decision_reason: None,
        applied_event_id: None,
        caveats,
        agent_run: None,
    };
    proposal.id = proposal_id(&proposal);
    proposal
}

/// Phase P (v0.5): `vpr_…` is content-addressed over the *logical* proposal
/// content only — `created_at` is excluded from the preimage. Identical
/// logical proposals (same actor, target, kind, reason, payload) deterministically
/// produce the same proposal_id regardless of when they were constructed.
///
/// This is the substrate property that makes agent retries idempotent.
/// `created_at` stays on the proposal as non-canonical metadata; replay-attack
/// detection layers on the signed envelope, not the content hash.
pub fn proposal_id(proposal: &StateProposal) -> String {
    let preimage = json!({
        "schema": proposal.schema,
        "kind": proposal.kind,
        "target": proposal.target,
        "actor": proposal.actor,
        "reason": proposal.reason,
        "payload": proposal.payload,
        "source_refs": proposal.source_refs,
        "caveats": proposal.caveats,
    });
    let bytes = canonical::to_canonical_bytes(&preimage).unwrap_or_default();
    format!("vpr_{}", &hex::encode(Sha256::digest(bytes))[..16])
}

pub fn is_placeholder_reviewer(value: &str) -> bool {
    let normalized = value.trim().to_ascii_lowercase();
    normalized.is_empty()
        || normalized == "local-reviewer"
        || normalized == "local-user"
        || normalized == "reviewer"
        || normalized == "user"
        || normalized == "unknown"
        || normalized.starts_with("local-")
}

pub fn validate_reviewer_identity(value: &str) -> Result<(), String> {
    if is_placeholder_reviewer(value) {
        return Err(format!(
            "Reviewer identity '{}' is missing or placeholder. Use a stable named reviewer id.",
            value
        ));
    }
    Ok(())
}

/// v0.128: the canonical action verb signed over the accept preimage.
/// A reviewer's accept signature commits to this verb so a captured
/// signature can never be repurposed as a different action.
pub const PROPOSAL_ACCEPT_ACTION: &str = "proposal.accept";

/// v0.128: structured outcome of [`authorize_proposal_accept`]. Carries
/// the resolved, non-revoked reviewer `ActorRecord` so the caller hands
/// the *registry-canonical* `actor.id` (not the wire pubkey) to
/// `accept_proposal_in_frontier`, keeping the persisted `reviewed_by`
/// honest.
#[derive(Debug, Clone)]
pub struct AcceptAuthorization {
    /// The registered reviewer whose key signed the decision. Borrow
    /// `actor.id` as the reviewer for the canonical accept path.
    pub actor: crate::sign::ActorRecord,
}

/// v0.128: true iff an actor carries *reviewer* authority for the public
/// accept boundary. Doctrine: accept authority is the `reviewer:`
/// namespace and only that namespace — a non-placeholder
/// `reviewer:<name>` id. The v0.6 `auto-notes` write tier (and any other
/// tier) does NOT grant accept authority; tier gates one-call note
/// auto-apply, never reviewer decisions. This is deliberately stricter
/// than `validate_reviewer_identity` (which only rejects placeholders):
/// here an `agent:` or bare id is refused outright.
#[must_use]
pub fn actor_has_reviewer_authority(actor: &crate::sign::ActorRecord) -> bool {
    let id = actor.id.trim();
    id.to_ascii_lowercase().starts_with("reviewer:") && !is_placeholder_reviewer(id)
}

/// v0.128: canonical signing bytes for a detached proposal-accept
/// decision. Binds the action verb, the target frontier, the exact
/// proposal, the reviewer's resolved identity, and the decision reason
/// into one preimage. Because `proposal_id` and `reviewer_id` are both
/// inside the preimage, a signature captured for one proposal cannot be
/// replayed against another, nor by another reviewer, nor under a
/// different reason. Mirrors `proposal_signing_bytes`' canonical-JSON
/// discipline (`canonical::to_canonical_bytes`, sorted keys).
pub fn accept_preimage_bytes(
    vfr_id: &str,
    proposal_id: &str,
    reviewer_id: &str,
    reason: &str,
) -> Result<Vec<u8>, String> {
    let preimage = json!({
        "action": PROPOSAL_ACCEPT_ACTION,
        "vfr_id": vfr_id,
        "proposal_id": proposal_id,
        "reviewer_id": reviewer_id,
        "reason": reason,
    });
    canonical::to_canonical_bytes(&preimage)
}

/// v0.128: protocol-side authority gate for the public accept boundary.
///
/// This closes the gap `publish_entry` leaves open:
/// open submission is fine because a self-signature *is* the bind, but a
/// reviewer **accept** must additionally prove the signer is a
/// registered, non-revoked actor on this frontier carrying reviewer
/// authority. Given an in-memory `Project` (the materialized frontier),
/// the signer's hex pubkey, a detached hex signature, the target
/// `proposal`, and the decision `reason`, this returns
/// `Ok(AcceptAuthorization)` **only if every** condition holds — in the
/// same fail-fast order the hub boundary enforces:
///
///   1. `reason` is non-empty (an accept must carry a decision reason).
///   2. AUTHORITY: `signer_pubkey` resolves to a registered
///      `ActorRecord` on `project.actors` (case-insensitive hex match).
///      No match → rejected (this is the check `publish_entry` lacks).
///   3. REVOCATION: the actor is not revoked as of `now`
///      (`ActorRecord::is_revoked_at`).
///   4. REVIEWER AUTHORITY: the actor carries reviewer authority
///      (`reviewer:` namespace, non-placeholder; the write `tier` does
///      NOT qualify).
///   5. SIGNATURE: the detached signature verifies (via the generic
///      `verify_action_signature`) over the canonical accept preimage
///      rebuilt with `reviewer_id = actor.id` — the *resolved* identity,
///      never client-supplied — binding (action, vfr_id, proposal_id,
///      reviewer_id, reason).
///
/// `vfr_id` is the frontier id from the boundary (the route path
/// parameter), bound into the signed preimage alongside the proposal so
/// a signature is non-transferable across frontiers. It is passed
/// explicitly rather than read from `proposal.target.id` because a
/// proposal targets a finding/artifact, not the frontier, and the
/// materialized `Project.frontier_id` may be `None` in a projection.
///
/// `now` is the caller's current RFC-3339 timestamp (e.g.
/// `Utc::now().to_rfc3339()`), injected so the revocation check is
/// testable and the function stays pure.
///
/// This function performs **no mutation** and does **not** weaken
/// `accept_proposal_in_frontier` or the Engine gate — it is purely the
/// per-reviewer-key authority predicate that must pass *before* the
/// caller runs the strict-mode canonical accept. The caller should use
/// the returned `actor.id` as the reviewer for that accept.
pub fn authorize_proposal_accept(
    project: &Project,
    vfr_id: &str,
    signer_pubkey_hex: &str,
    signature_hex: &str,
    proposal: &StateProposal,
    reason: &str,
    now: &str,
) -> Result<AcceptAuthorization, String> {
    if reason.trim().is_empty() {
        return Err("Decision reason must be non-empty".to_string());
    }

    // 2. AUTHORITY: resolve the signer pubkey to a registered actor.
    let actor = project
        .actors
        .iter()
        .find(|a| a.public_key.eq_ignore_ascii_case(signer_pubkey_hex))
        .cloned()
        .ok_or_else(|| {
            format!("signer pubkey {signer_pubkey_hex} is not a registered actor on this frontier")
        })?;

    // 3. REVOCATION: reject a key revoked/retired as of now.
    if actor.is_revoked_at(now) {
        return Err(format!(
            "reviewer key for actor '{}' is revoked as of {now}",
            actor.id
        ));
    }

    // 4. REVIEWER AUTHORITY: the actor must carry reviewer authority. A
    //    write tier (auto-notes) never grants accept authority.
    if !actor_has_reviewer_authority(&actor) {
        return Err(format!(
            "actor '{}' does not carry reviewer authority (accept requires a non-placeholder \
             reviewer: identity; the write tier does not qualify)",
            actor.id
        ));
    }

    // 5. SIGNATURE: verify the detached decision signature over the
    //    canonical accept preimage, rebuilt with the *resolved*
    //    reviewer_id so a client cannot substitute a different identity.
    let preimage = accept_preimage_bytes(vfr_id, &proposal.id, &actor.id, reason)?;
    let verified =
        crate::sign::verify_action_signature(&preimage, signature_hex, &actor.public_key)?;
    if !verified {
        return Err(format!(
            "accept signature does not verify for actor '{}' over the canonical accept preimage",
            actor.id
        ));
    }

    Ok(AcceptAuthorization { actor })
}

pub fn summary(frontier: &Project) -> ProposalSummary {
    let mut out = ProposalSummary::default();
    let mut seen = BTreeSet::new();
    let finding_ids = frontier
        .findings
        .iter()
        .map(|finding| finding.id.as_str())
        .collect::<BTreeSet<_>>();
    let artifact_ids = frontier
        .artifacts
        .iter()
        .map(|artifact| artifact.id.as_str())
        .collect::<BTreeSet<_>>();
    for proposal in &frontier.proposals {
        out.total += 1;
        *out.by_kind.entry(proposal.kind.clone()).or_default() += 1;
        match proposal.status.as_str() {
            "pending_review" => out.pending_review += 1,
            "accepted" => out.accepted += 1,
            "rejected" => out.rejected += 1,
            "applied" => out.applied += 1,
            _ => {}
        }
        if !seen.insert(proposal.id.clone()) {
            out.duplicate_ids.push(proposal.id.clone());
        }
        let target_known = match proposal.target.r#type.as_str() {
            "finding" => {
                proposal.kind == "finding.add" || finding_ids.contains(proposal.target.id.as_str())
            }
            "artifact" => {
                proposal.kind == "artifact.assert"
                    || artifact_ids.contains(proposal.target.id.as_str())
            }
            _ => true,
        };
        if !target_known {
            out.invalid_targets.push(proposal.target.id.clone());
        }
    }
    out.duplicate_ids.sort();
    out.duplicate_ids.dedup();
    out.invalid_targets.sort();
    out.invalid_targets.dedup();
    out
}

pub fn proposals_for_finding<'a>(
    frontier: &'a Project,
    finding_id: &str,
) -> Vec<&'a StateProposal> {
    frontier
        .proposals
        .iter()
        .filter(|proposal| proposal.target.r#type == "finding" && proposal.target.id == finding_id)
        .collect()
}

/// Phase P (v0.5): upsert by content address. If a proposal with the same
/// `vpr_…` already exists in the frontier, return the existing record instead
/// of inserting a duplicate. Combined with the `created_at`-free preimage,
/// this makes agent retries idempotent at the substrate level.
///
/// `apply` semantics are also idempotent: if the same proposal+reviewer pair
/// has already been applied (proposal.applied_event_id is set), return the
/// existing event_id rather than emitting a duplicate canonical event.
pub fn create_or_apply(
    path: &Path,
    proposal: StateProposal,
    apply: bool,
) -> Result<CreateProposalResult, String> {
    let mut frontier = repo::load_from_path(path)?;
    let finding_id = proposal.target.id.clone();
    let proposal_id = proposal.id.clone();

    // Idempotent insert: if a proposal with this content-addressed id already
    // exists, skip insertion and treat the existing record as authoritative.
    let existing_idx = frontier
        .proposals
        .iter()
        .position(|existing| existing.id == proposal_id);
    if existing_idx.is_none() {
        validate_new_proposal(&frontier, &proposal)?;
        frontier.proposals.push(proposal);
    }

    let applied_event_id = if apply {
        // Idempotent apply: if the existing record was already applied, return
        // its event_id rather than emitting a duplicate event.
        if let Some(idx) = existing_idx
            && let Some(existing_event) = frontier.proposals[idx].applied_event_id.clone()
        {
            Some(existing_event)
        } else {
            let reviewer = frontier
                .proposals
                .iter()
                .find(|proposal| proposal.id == proposal_id)
                .map(|proposal| proposal.actor.id.clone())
                .ok_or_else(|| format!("Proposal not found after insertion: {proposal_id}"))?;
            Some(accept_proposal_in_frontier(
                &mut frontier,
                &proposal_id,
                &reviewer,
                "Applied locally from proposal creation",
            )?)
        }
    } else {
        existing_idx.and_then(|idx| frontier.proposals[idx].applied_event_id.clone())
    };

    // v0.13: materialize source/evidence/condition projections after every
    // applied proposal so the lint surface stops emitting `missing_source_record`
    // for findings whose provenance derives a SourceRecord that wasn't yet in
    // `frontier.sources`. Pre-v0.13, `vela normalize --write` was the only path
    // to populate these — but normalize refuses on event-ful frontiers, so any
    // frontier built via CLI proposals could never reach proof-ready state.
    // Materializing inline at apply time keeps source_records in lockstep with
    // findings; when no finding state changed (caveat/note/review on existing
    // findings) the projection is idempotent and bytes don't churn.
    if applied_event_id.is_some() {
        crate::sources::materialize_project(&mut frontier);
    } else {
        project::recompute_stats(&mut frontier);
    }
    repo::save_to_path(path, &frontier)?;
    Ok(CreateProposalResult {
        proposal_id,
        finding_id,
        status: applied_event_id
            .as_ref()
            .map_or_else(|| "pending_review".to_string(), |_| "applied".to_string()),
        applied_event_id,
    })
}

pub fn list(frontier: &Project, status: Option<&str>) -> Vec<StateProposal> {
    let mut proposals = frontier
        .proposals
        .iter()
        .filter(|proposal| status.is_none_or(|wanted| proposal.status == wanted))
        .cloned()
        .collect::<Vec<_>>();
    proposals.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)));
    proposals
}

pub fn show<'a>(frontier: &'a Project, proposal_id: &str) -> Result<&'a StateProposal, String> {
    frontier
        .proposals
        .iter()
        .find(|proposal| proposal.id == proposal_id)
        .ok_or_else(|| format!("Proposal not found: {proposal_id}"))
}

pub fn preview_at_path(
    path: &Path,
    proposal_id: &str,
    reviewer: &str,
) -> Result<ProposalPreview, String> {
    validate_reviewer_identity(reviewer)?;
    let frontier = repo::load_from_path(path)?;
    preview_in_frontier(&frontier, proposal_id, reviewer)
}

pub fn preview_in_frontier(
    frontier: &Project,
    proposal_id: &str,
    reviewer: &str,
) -> Result<ProposalPreview, String> {
    validate_reviewer_identity(reviewer)?;
    let proposal = frontier
        .proposals
        .iter()
        .find(|proposal| proposal.id == proposal_id)
        .ok_or_else(|| format!("Proposal not found: {proposal_id}"))?
        .clone();
    if proposal.status == "applied" {
        let applied_event_id = proposal
            .applied_event_id
            .clone()
            .ok_or_else(|| format!("Proposal {} is applied but has no event id", proposal.id))?;
        return Ok(ProposalPreview {
            proposal_id: proposal.id,
            kind: proposal.kind,
            changed_findings: changed_targets_for_type(frontier, &proposal.target, "finding"),
            changed_finding_details: Vec::new(),
            changed_artifacts: changed_targets_for_type(frontier, &proposal.target, "artifact"),
            new_event_ids: vec![applied_event_id.clone()],
            event_kinds: frontier
                .events
                .iter()
                .find(|event| event.id == applied_event_id)
                .map(|event| vec![event.kind.to_string()])
                .unwrap_or_default(),
            target: proposal.target,
            reviewer: reviewer.to_string(),
            findings_before: frontier.findings.len(),
            findings_after: frontier.findings.len(),
            findings_delta: 0,
            artifacts_before: frontier.artifacts.len(),
            artifacts_after: frontier.artifacts.len(),
            artifacts_delta: 0,
            events_before: frontier.events.len(),
            events_after: frontier.events.len(),
            events_delta: 0,
            proof_would_be_stale: false,
            applied_event_id,
        });
    }
    if !matches!(proposal.status.as_str(), "pending_review" | "accepted") {
        return Err(format!(
            "Proposal {} cannot be previewed from status {}",
            proposal.id, proposal.status
        ));
    }
    let mut preview_state: Project = serde_json::from_value(
        serde_json::to_value(frontier).map_err(|e| format!("serialize frontier preview: {e}"))?,
    )
    .map_err(|e| format!("clone frontier preview: {e}"))?;
    let finding_ids_before = preview_state
        .findings
        .iter()
        .map(|finding| finding.id.clone())
        .collect::<BTreeSet<_>>();
    let artifact_ids_before = preview_state
        .artifacts
        .iter()
        .map(|artifact| artifact.id.clone())
        .collect::<BTreeSet<_>>();
    let findings_before = preview_state.findings.len();
    let artifacts_before = preview_state.artifacts.len();
    let events_before = preview_state.events.len();
    let event_id = apply_proposal(
        &mut preview_state,
        &proposal,
        reviewer,
        "Preview proposal application",
    )?;
    let findings_after = preview_state.findings.len();
    let artifacts_after = preview_state.artifacts.len();
    let events_after = preview_state.events.len();
    let new_events = preview_state
        .events
        .iter()
        .skip(events_before)
        .cloned()
        .collect::<Vec<_>>();
    let changed_findings = changed_finding_ids(&preview_state, &finding_ids_before, &new_events);
    let changed_finding_details =
        build_changed_finding_details(frontier, &preview_state, &changed_findings);
    Ok(ProposalPreview {
        proposal_id: proposal.id,
        kind: proposal.kind,
        target: proposal.target,
        reviewer: reviewer.to_string(),
        changed_findings,
        changed_finding_details,
        changed_artifacts: changed_artifact_ids(&preview_state, &artifact_ids_before, &new_events),
        new_event_ids: new_events.iter().map(|event| event.id.clone()).collect(),
        event_kinds: new_events
            .iter()
            .map(|event| event.kind.to_string())
            .collect(),
        findings_before,
        findings_after,
        findings_delta: findings_after as isize - findings_before as isize,
        artifacts_before,
        artifacts_after,
        artifacts_delta: artifacts_after as isize - artifacts_before as isize,
        events_before,
        events_after,
        events_delta: events_after as isize - events_before as isize,
        proof_would_be_stale: true,
        applied_event_id: event_id,
    })
}

fn changed_targets_for_type(
    frontier: &Project,
    target: &StateTarget,
    target_type: &str,
) -> Vec<String> {
    let known = match target_type {
        "finding" => frontier
            .findings
            .iter()
            .any(|finding| finding.id == target.id),
        "artifact" => frontier
            .artifacts
            .iter()
            .any(|artifact| artifact.id == target.id),
        _ => false,
    };
    if target.r#type == target_type && known {
        vec![target.id.clone()]
    } else {
        Vec::new()
    }
}

fn changed_finding_ids(
    preview_state: &Project,
    finding_ids_before: &BTreeSet<String>,
    new_events: &[StateEvent],
) -> Vec<String> {
    let mut ids = preview_state
        .findings
        .iter()
        .filter(|finding| !finding_ids_before.contains(&finding.id))
        .map(|finding| finding.id.clone())
        .collect::<BTreeSet<_>>();
    for event in new_events {
        if event.target.r#type == "finding" {
            ids.insert(event.target.id.clone());
        }
    }
    ids.into_iter().collect()
}

fn changed_artifact_ids(
    preview_state: &Project,
    artifact_ids_before: &BTreeSet<String>,
    new_events: &[StateEvent],
) -> Vec<String> {
    let mut ids = preview_state
        .artifacts
        .iter()
        .filter(|artifact| !artifact_ids_before.contains(&artifact.id))
        .map(|artifact| artifact.id.clone())
        .collect::<BTreeSet<_>>();
    for event in new_events {
        if event.target.r#type == "artifact" {
            ids.insert(event.target.id.clone());
        }
    }
    ids.into_iter().collect()
}

pub fn import_from_path(path: &Path, source: &Path) -> Result<ImportProposalReport, String> {
    let mut frontier = repo::load_from_path(path)?;
    let proposals = load_proposals(source)?;
    let wrote_to = path.display().to_string();
    let mut report = ImportProposalReport {
        wrote_to,
        ..ImportProposalReport::default()
    };
    for proposal in proposals {
        if frontier
            .proposals
            .iter()
            .any(|existing| existing.id == proposal.id)
        {
            report.duplicates += 1;
            continue;
        }
        validate_new_proposal(&frontier, &proposal)?;
        frontier.proposals.push(proposal.clone());
        report.imported += 1;
        match proposal.status.as_str() {
            "accepted" => {
                let reviewer = proposal
                    .reviewed_by
                    .as_deref()
                    .ok_or_else(|| {
                        format!("Accepted proposal {} missing reviewed_by", proposal.id)
                    })?
                    .to_string();
                let reason = proposal
                    .decision_reason
                    .clone()
                    .unwrap_or_else(|| "Imported accepted proposal".to_string());
                let _ =
                    accept_proposal_in_frontier(&mut frontier, &proposal.id, &reviewer, &reason)?;
                report.applied += 1;
            }
            "applied" => {
                let reviewer = proposal
                    .reviewed_by
                    .as_deref()
                    .ok_or_else(|| format!("Applied proposal {} missing reviewed_by", proposal.id))?
                    .to_string();
                let reason = proposal
                    .decision_reason
                    .clone()
                    .unwrap_or_else(|| "Imported applied proposal".to_string());
                let _ =
                    accept_proposal_in_frontier(&mut frontier, &proposal.id, &reviewer, &reason)?;
                report.applied += 1;
            }
            "rejected" => report.rejected += 1,
            _ => {}
        }
    }
    project::recompute_stats(&mut frontier);
    repo::save_to_path(path, &frontier)?;
    Ok(report)
}

pub fn validate_source(source: &Path) -> Result<ProposalValidationReport, String> {
    let proposals = load_proposals(source)?;
    let mut report = ProposalValidationReport {
        checked: proposals.len(),
        ..ProposalValidationReport::default()
    };
    let scratch = project::assemble("proposal-validation", Vec::new(), 0, 0, "validate");
    let mut seen = BTreeSet::new();
    for proposal in proposals {
        if !seen.insert(proposal.id.clone()) {
            report.invalid += 1;
            report
                .errors
                .push(format!("Duplicate proposal id {}", proposal.id));
            continue;
        }
        report.proposal_ids.push(proposal.id.clone());
        match validate_standalone_proposal(&scratch, &proposal) {
            Ok(()) => report.valid += 1,
            Err(err) => {
                report.invalid += 1;
                report.errors.push(format!("{}: {}", proposal.id, err));
            }
        }
    }
    report.ok = report.invalid == 0;
    Ok(report)
}

pub fn export_to_path(
    frontier_path: &Path,
    output: &Path,
    status: Option<&str>,
) -> Result<usize, String> {
    let frontier = repo::load_from_path(frontier_path)?;
    let proposals = list(&frontier, status);
    let json = serde_json::to_string_pretty(&proposals)
        .map_err(|e| format!("Failed to serialize proposals for export: {e}"))?;
    std::fs::write(output, json).map_err(|e| {
        format!(
            "Failed to write proposal export '{}': {e}",
            output.display()
        )
    })?;
    Ok(proposals.len())
}

pub fn accept_at_path(
    path: &Path,
    proposal_id: &str,
    reviewer: &str,
    reason: &str,
) -> Result<String, String> {
    accept_at_path_signed(path, proposal_id, reviewer, reason, None)
}

pub fn accept_at_path_signed(
    path: &Path,
    proposal_id: &str,
    reviewer: &str,
    reason: &str,
    signing_key: Option<&ed25519_dalek::SigningKey>,
) -> Result<String, String> {
    let mut frontier = repo::load_from_path(path)?;
    let event_id = accept_proposal_in_frontier_signed(
        &mut frontier,
        proposal_id,
        reviewer,
        reason,
        signing_key,
    )?;
    project::recompute_stats(&mut frontier);
    repo::save_to_path(path, &frontier)?;
    Ok(event_id)
}

/// How the Engine treats the Evidence CI delta a candidate acceptance
/// introduces.
#[derive(Debug, Clone, Default)]
pub struct AcceptOptions {
    /// Also block on *new* review warnings, not just new release-blocking
    /// failures. Off by default — Evidence CI is review-readiness, not a
    /// truth oracle, so warnings inform by default and gate only on demand.
    pub strict: bool,
    /// Override the gate. The override is recorded in the proposal's
    /// decision reason so the forced acceptance is auditable.
    pub force: bool,
    /// The reviewer's Ed25519 private key. REQUIRED when the reviewer is
    /// registered with a public key (key custody is the accept
    /// authority); the accept event is signed with it.
    pub signing_key: Option<ed25519_dalek::SigningKey>,
    /// Set by a boundary that has ALREADY proven key possession another
    /// way — the hub verifies a detached Ed25519 signature over the
    /// canonical accept request against the registered key before it
    /// ever reaches this path. Never set this from a local CLI flow.
    pub custody_verified: bool,
}

/// The Engine's read on an acceptance: what Evidence CI says about the
/// state the change would produce. Recomputable at any time from
/// `evidence_ci::run_project`; this captures the *delta* a single
/// acceptance introduces, which is what a reviewer (or the gate) acts on.
#[derive(Debug, Clone, Serialize)]
pub struct EngineVerdict {
    /// `pass` (clean), `warn` (new review warnings), `blocked` (would be
    /// gated; only seen on the preview/error path), or `forced` (gated but
    /// overridden with --force and persisted).
    pub status: String,
    /// Release-blocking checks newly failing because of this change.
    pub new_blocking: Vec<String>,
    /// Review-readiness warnings this change introduces.
    pub new_warnings: Vec<String>,
    /// Whether a gate was overridden with --force.
    pub forced: bool,
    /// Whether warnings were treated as blocking (--strict).
    pub strict: bool,
    /// Post-accept Evidence CI counts, for context in the readout.
    pub release_blocking_failed: usize,
    pub warnings: usize,
}

/// The acceptance result plus the Engine verdict that gated it.
#[derive(Debug, Clone)]
pub struct AcceptOutcome {
    pub event_id: String,
    pub verdict: EngineVerdict,
}

/// A proposal kind is truth-bearing when accepting it changes what the
/// frontier asserts about the world. Process/provenance records and
/// mechanical repairs are not — this mirrors the bounded safe set the
/// agent self-accept policy already trusts, keeping the Engine gate and
/// that policy consistent.
fn is_truth_bearing_kind(kind: &str) -> bool {
    !(AGENT_SELF_APPLIABLE_PROCESS_KINDS.contains(&kind) || TRUSTED_REPAIR_KINDS.contains(&kind))
}

/// Accept a proposal under the Engine: run Evidence CI on the current and
/// the post-accept state, and gate the acceptance on the *regression* the
/// change introduces. A truth-bearing claim that adds a new release-
/// blocking failure (or, under `--strict`, a new review warning) is
/// blocked unless `--force` is given. The accepted event is itself the
/// record that the gate passed — Evidence CI is a recomputable projection,
/// so the verdict is surfaced, not persisted as a separate canonical object.
pub fn accept_at_path_engine(
    path: &Path,
    proposal_id: &str,
    reviewer: &str,
    reason: &str,
    opts: AcceptOptions,
) -> Result<AcceptOutcome, String> {
    let mut frontier = repo::load_from_path(path)?;

    // The kind decides whether the gate applies; read it before the apply
    // mutates proposal status.
    let kind = frontier
        .proposals
        .iter()
        .find(|p| p.id == proposal_id)
        .map(|p| p.kind.clone())
        .ok_or_else(|| format!("Proposal not found: {proposal_id}"))?;

    let before = crate::evidence_ci::run_project(&frontier, path);
    let before_blocking = crate::evidence_ci::release_blocking_failures(&before);
    let before_warn = crate::evidence_ci::review_warnings(&before);

    // Apply via the sole canonical path; this mutates `frontier` in memory.
    let event_id = accept_proposal_in_frontier_with_custody(
        &mut frontier,
        proposal_id,
        reviewer,
        reason,
        opts.signing_key.as_ref(),
        opts.custody_verified,
    )?;

    let after = crate::evidence_ci::run_project(&frontier, path);
    let new_blocking: Vec<String> = crate::evidence_ci::release_blocking_failures(&after)
        .difference(&before_blocking)
        .cloned()
        .collect();
    let new_warnings: Vec<String> = crate::evidence_ci::review_warnings(&after)
        .difference(&before_warn)
        .cloned()
        .collect();

    let truth_bearing = is_truth_bearing_kind(&kind);
    let would_block =
        truth_bearing && (!new_blocking.is_empty() || (opts.strict && !new_warnings.is_empty()));

    if would_block && !opts.force {
        // Gate: return without saving. The in-memory mutation is discarded,
        // so no canonical state changes on a blocked accept.
        let why = if !new_blocking.is_empty() {
            format!(
                "introduces {} new release-blocking failure(s): {}",
                new_blocking.len(),
                new_blocking.join(", ")
            )
        } else {
            format!(
                "--strict: introduces {} new review warning(s): {}",
                new_warnings.len(),
                new_warnings.join(", ")
            )
        };
        return Err(format!(
            "Engine gate blocked accept of {proposal_id}: {why}. Re-run with --force to \
             override (the override is recorded in the decision reason), or resolve the checks first."
        ));
    }

    let forced = would_block && opts.force;
    if forced {
        // Make the override auditable in the persisted proposal record.
        if let Some(p) = frontier.proposals.iter_mut().find(|p| p.id == proposal_id) {
            let note = format!(
                " [engine: --force past {} new blocking / {} new warning(s)]",
                new_blocking.len(),
                new_warnings.len()
            );
            p.decision_reason = Some(match p.decision_reason.take() {
                Some(r) => format!("{r}{note}"),
                None => note.trim_start().to_string(),
            });
        }
    }

    let status = if forced {
        "forced"
    } else if !new_warnings.is_empty() {
        "warn"
    } else {
        "pass"
    }
    .to_string();

    let verdict = EngineVerdict {
        status,
        new_blocking,
        new_warnings,
        forced,
        strict: opts.strict,
        release_blocking_failed: after.summary.release_blocking_failed,
        warnings: after.summary.warnings,
    };

    project::recompute_stats(&mut frontier);
    repo::save_to_path(path, &frontier)?;
    Ok(AcceptOutcome { event_id, verdict })
}

/// What a batch acceptance did. Counts are over the whole batch; the
/// single `verdict` is the Engine's read on the *aggregate* delta the
/// batch introduces (one CI pair for the whole batch, not one per
/// proposal — that is the entire scale point). `event_ids` is parallel to
/// `accepted_proposal_ids`.
#[derive(Debug, Clone)]
pub struct BatchAcceptReport {
    /// Proposals applied this run (excludes ones that were already
    /// applied — those are counted in `already_applied`).
    pub accepted_proposal_ids: Vec<String>,
    /// The canonical event id each accepted proposal produced.
    pub event_ids: Vec<String>,
    /// Proposals that `accept_proposal_in_frontier` short-circuited
    /// because they were already applied (idempotent re-accept).
    pub already_applied: usize,
    /// Proposals that failed to apply (id, error) — e.g. not found, or a
    /// reducer/validation error. A per-proposal failure does NOT abort the
    /// batch; the failures are reported and the rest proceed.
    pub failed: Vec<(String, String)>,
    /// The aggregate Engine verdict over the whole batch.
    pub verdict: EngineVerdict,
    /// True when the batch was gated (would_block && !force): nothing was
    /// persisted, the in-memory mutation discarded. The accepted/event
    /// lists reflect what *would* have applied so the caller can report it.
    pub gated: bool,
    /// True when this was a preview (`dry_run`): the batch applied + gated
    /// in memory, the verdict is real, but nothing was written to disk.
    pub dry_run: bool,
}

/// Accept a *batch* of proposals against an on-disk frontier in a single
/// load → apply-all → save pass. This is the scale-capable accept path.
///
/// The single-proposal [`accept_at_path_engine`] does load-whole →
/// accept-one → run Evidence CI (whole frontier) → save-whole on every
/// call. Accepting `N` proposals that way is `N` loads, `N` CI runs, and
/// `N` whole-frontier re-serializations — O(N²) work for an O(N) logical
/// change, the exact failure the scale-architecture plan names. This runs
/// the frontier once: load once, CI once before, apply every proposal in
/// memory (the sole canonical [`accept_proposal_in_frontier`] path, no
/// per-accept CI), CI once after, gate on the *aggregate* delta, and
/// `save_to_path` once.
///
/// Gate semantics mirror the single accept but at batch granularity: the
/// batch is all-or-nothing at the Engine gate. If the batch as a whole
/// introduces a new release-blocking failure (or, under `--strict`, a new
/// review warning) and `force` is not set, NOTHING is persisted — the
/// in-memory mutation is discarded exactly as a blocked single accept
/// discards its. `force` overrides and records the override note on each
/// forced proposal. Per-proposal *apply* failures (not-found, reducer
/// error) are collected in the report and do not abort the rest.
///
/// `dry_run` does everything except the final save: a real preview of the
/// aggregate verdict and the accept/skip/fail breakdown with zero
/// on-disk effect.
///
/// Note on persistence cost: this still calls `repo::save_to_path` once,
/// which re-serializes the frontier a single time — correct and O(frontier)
/// for the bulk case (the whole spine into a small frontier). Driving the
/// persist through `incremental_ingest::append_batch` (write only the new
/// finding/event files, touch only the flipped proposal files) is the
/// next layer, for appending a small batch into an already-large frontier;
/// it is intentionally not coupled here because `save_to_path` also
/// reconciles proposal-status, proof-state, and stats that the append
/// primitive deliberately leaves alone.
pub fn accept_batch_at_path(
    path: &Path,
    proposal_ids: &[String],
    reviewer: &str,
    reason: &str,
    opts: AcceptOptions,
    dry_run: bool,
) -> Result<BatchAcceptReport, String> {
    let mut frontier = repo::load_from_path(path)?;

    // CI once, before any apply.
    let before = crate::evidence_ci::run_project(&frontier, path);
    let before_blocking = crate::evidence_ci::release_blocking_failures(&before);
    let before_warn = crate::evidence_ci::review_warnings(&before);

    // Apply every proposal in memory via the sole canonical path. No
    // per-accept CI and no save here — that is what makes the batch O(N).
    let mut accepted_proposal_ids = Vec::new();
    let mut event_ids = Vec::new();
    let mut failed = Vec::new();
    let mut already_applied = 0usize;
    let mut any_truth_bearing = false;
    for pid in proposal_ids {
        // Read the kind + prior applied state before the apply mutates it.
        let (kind, was_applied) = match frontier.proposals.iter().find(|p| &p.id == pid) {
            Some(p) => (p.kind.clone(), p.applied_event_id.is_some()),
            None => {
                failed.push((pid.clone(), format!("Proposal not found: {pid}")));
                continue;
            }
        };
        // Batch accepts stay keyless: on a frontier whose reviewer is
        // registered with a key, each accept must be individually signed
        // (`vela accept --key`) — bulk acceptance under a typed name is
        // exactly what key custody exists to prevent.
        match accept_proposal_in_frontier(&mut frontier, pid, reviewer, reason) {
            Ok(event_id) => {
                if was_applied {
                    already_applied += 1;
                } else {
                    if is_truth_bearing_kind(&kind) {
                        any_truth_bearing = true;
                    }
                    accepted_proposal_ids.push(pid.clone());
                    event_ids.push(event_id);
                }
            }
            Err(e) => failed.push((pid.clone(), e)),
        }
    }

    // CI once, after all applies. The gate acts on the aggregate delta.
    let after = crate::evidence_ci::run_project(&frontier, path);
    let new_blocking: Vec<String> = crate::evidence_ci::release_blocking_failures(&after)
        .difference(&before_blocking)
        .cloned()
        .collect();
    let new_warnings: Vec<String> = crate::evidence_ci::review_warnings(&after)
        .difference(&before_warn)
        .cloned()
        .collect();

    let would_block = any_truth_bearing
        && (!new_blocking.is_empty() || (opts.strict && !new_warnings.is_empty()));

    if would_block && !opts.force {
        // Discard: never save. Report what would have applied + why blocked.
        let verdict = EngineVerdict {
            status: "blocked".to_string(),
            new_blocking,
            new_warnings,
            forced: false,
            strict: opts.strict,
            release_blocking_failed: after.summary.release_blocking_failed,
            warnings: after.summary.warnings,
        };
        return Ok(BatchAcceptReport {
            accepted_proposal_ids,
            event_ids,
            already_applied,
            failed,
            verdict,
            gated: true,
            dry_run,
        });
    }

    let forced = would_block && opts.force;
    if forced {
        // Record the override on each forced proposal so it stays auditable.
        let note = format!(
            " [engine: batch --force past {} new blocking / {} new warning(s)]",
            new_blocking.len(),
            new_warnings.len()
        );
        for pid in &accepted_proposal_ids {
            if let Some(p) = frontier.proposals.iter_mut().find(|p| &p.id == pid) {
                p.decision_reason = Some(match p.decision_reason.take() {
                    Some(r) => format!("{r}{note}"),
                    None => note.trim_start().to_string(),
                });
            }
        }
    }

    let status = if forced {
        "forced"
    } else if !new_warnings.is_empty() {
        "warn"
    } else {
        "pass"
    }
    .to_string();

    let verdict = EngineVerdict {
        status,
        new_blocking,
        new_warnings,
        forced,
        strict: opts.strict,
        release_blocking_failed: after.summary.release_blocking_failed,
        warnings: after.summary.warnings,
    };

    if !dry_run {
        project::recompute_stats(&mut frontier);
        repo::save_to_path(path, &frontier)?;
        // A batch of in-memory accepts leaves the visible snapshot + lock
        // computed from the *accumulated in-memory* order, which can diverge
        // from a fresh canonical load+materialize (the load-time
        // `materialize_*_from_events` re-derivation differs from incremental
        // accumulation). Reseal from disk so `frontier.json`/`vela.lock`
        // match the materialized state and `vela integrity` stays clean. The
        // single-accept path gets this for free by reloading per accept; the
        // batch pays one canonical reseal at the end. Only meaningful for a
        // split `.vela/` repo — a flat project-file has no lock to reseal.
        if path.join(".vela").is_dir() {
            crate::frontier_repo::materialize(path)?;
        }
    }

    Ok(BatchAcceptReport {
        accepted_proposal_ids,
        event_ids,
        already_applied,
        failed,
        verdict,
        gated: false,
        dry_run,
    })
}

/// v0.128: in-memory twin of [`accept_at_path_engine`] for callers that
/// hold a materialized `Project` rather than an on-disk frontier — the
/// public accept boundary on the hub being the motivating case. Same
/// strict-gate contract, byte-for-byte the same kernel calls
/// (`evidence_ci::run_project` before/after the sole canonical
/// `accept_proposal_in_frontier` path, gated on the *regression*), but it
/// mutates `frontier` in place and never touches the filesystem. The
/// caller persists the mutated project (and the emitted canonical event)
/// itself, under whatever transaction it owns.
///
/// On a blocked gate the function returns [`Err(EngineGateBlocked)`] and
/// the caller MUST discard the (now partially-mutated) `frontier` without
/// persisting it — exactly as `accept_at_path_engine` discards its
/// in-memory mutation by never calling `save_to_path`. `Project` is
/// deliberately not `Clone`, so the discard is the caller's
/// responsibility: the hub loads a throwaway `Project` for the accept and
/// only writes it back on `Ok`. The returned [`EngineGateBlocked`]
/// carries the full [`EngineVerdict`] so the boundary can surface it
/// (e.g. as a 422 body) without re-running CI.
///
/// `frontier_path` is read solely for static policy documents and to
/// label the Evidence CI report (see [`evidence_ci::run_project`]); the
/// hub passes a non-existent path, which surfaces a missing-policy check
/// rather than reading any frontier state from disk.
pub fn accept_in_frontier_engine(
    frontier: &mut Project,
    frontier_path: &Path,
    proposal_id: &str,
    reviewer: &str,
    reason: &str,
    opts: AcceptOptions,
) -> Result<AcceptOutcome, AcceptEngineError> {
    let kind = frontier
        .proposals
        .iter()
        .find(|p| p.id == proposal_id)
        .map(|p| p.kind.clone())
        .ok_or_else(|| AcceptEngineError::Failed(format!("Proposal not found: {proposal_id}")))?;

    let before = crate::evidence_ci::run_project(frontier, frontier_path);
    let before_blocking = crate::evidence_ci::release_blocking_failures(&before);
    let before_warn = crate::evidence_ci::review_warnings(&before);

    // Apply via the sole canonical path; this mutates `frontier` in memory.
    // `accept_proposal_in_frontier` short-circuits to the existing
    // applied_event_id when the proposal is already applied, so a
    // re-accept is a no-op that returns the original event id (the
    // before/after Evidence CI delta is empty, the gate passes, and the
    // caller re-persists deterministically).
    let event_id = accept_proposal_in_frontier_with_custody(
        frontier,
        proposal_id,
        reviewer,
        reason,
        opts.signing_key.as_ref(),
        opts.custody_verified,
    )
    .map_err(AcceptEngineError::Failed)?;

    let after = crate::evidence_ci::run_project(frontier, frontier_path);
    let new_blocking: Vec<String> = crate::evidence_ci::release_blocking_failures(&after)
        .difference(&before_blocking)
        .cloned()
        .collect();
    let new_warnings: Vec<String> = crate::evidence_ci::review_warnings(&after)
        .difference(&before_warn)
        .cloned()
        .collect();

    let truth_bearing = is_truth_bearing_kind(&kind);
    let would_block =
        truth_bearing && (!new_blocking.is_empty() || (opts.strict && !new_warnings.is_empty()));

    if would_block && !opts.force {
        // Gate: the caller discards `frontier` (never persisted), so no
        // canonical state changes on a blocked accept. We surface the
        // verdict so the boundary can return it verbatim.
        let verdict = EngineVerdict {
            status: "blocked".to_string(),
            new_blocking,
            new_warnings,
            forced: false,
            strict: opts.strict,
            release_blocking_failed: after.summary.release_blocking_failed,
            warnings: after.summary.warnings,
        };
        return Err(AcceptEngineError::Blocked(Box::new(verdict)));
    }

    let forced = would_block && opts.force;
    if forced && let Some(p) = frontier.proposals.iter_mut().find(|p| p.id == proposal_id) {
        let note = format!(
            " [engine: --force past {} new blocking / {} new warning(s)]",
            new_blocking.len(),
            new_warnings.len()
        );
        p.decision_reason = Some(match p.decision_reason.take() {
            Some(r) => format!("{r}{note}"),
            None => note.trim_start().to_string(),
        });
    }

    let status = if forced {
        "forced"
    } else if !new_warnings.is_empty() {
        "warn"
    } else {
        "pass"
    }
    .to_string();

    let verdict = EngineVerdict {
        status,
        new_blocking,
        new_warnings,
        forced,
        strict: opts.strict,
        release_blocking_failed: after.summary.release_blocking_failed,
        warnings: after.summary.warnings,
    };

    project::recompute_stats(frontier);
    Ok(AcceptOutcome { event_id, verdict })
}

/// v0.128: error outcome of [`accept_in_frontier_engine`]. `Blocked`
/// distinguishes the strict-gate refusal (which carries the full
/// [`EngineVerdict`] for the boundary to surface as a 422) from any other
/// `Failed` accept error (proposal-not-found, validation, etc.) the
/// caller maps to a different status. Boxed so the `Ok` variant of the
/// surrounding `Result` stays small.
#[derive(Debug, Clone)]
pub enum AcceptEngineError {
    /// The strict Engine gate refused the accept; no state should be
    /// persisted. Carries the verdict that explains the regression.
    Blocked(Box<EngineVerdict>),
    /// Any other accept failure (not the gate).
    Failed(String),
}

impl std::fmt::Display for AcceptEngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Blocked(v) => write!(
                f,
                "Engine gate blocked accept: {} new blocking, {} new warning(s)",
                v.new_blocking.len(),
                v.new_warnings.len()
            ),
            Self::Failed(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for AcceptEngineError {}

/// Compute the Engine verdict a candidate acceptance *would* produce,
/// without persisting anything. Drives the review-time preview ("what
/// would CI say if I accept this?") on the CLI and the Workbench.
pub fn preview_engine_verdict(path: &Path, proposal_id: &str) -> Result<EngineVerdict, String> {
    let mut frontier = repo::load_from_path(path)?;
    let kind = frontier
        .proposals
        .iter()
        .find(|p| p.id == proposal_id)
        .map(|p| p.kind.clone())
        .ok_or_else(|| format!("Proposal not found: {proposal_id}"))?;

    let before = crate::evidence_ci::run_project(&frontier, path);
    let before_blocking = crate::evidence_ci::release_blocking_failures(&before);
    let before_warn = crate::evidence_ci::review_warnings(&before);

    // Apply on this in-memory copy under a synthetic reviewer; never saved.
    accept_proposal_in_frontier(
        &mut frontier,
        proposal_id,
        "reviewer:engine-preview",
        "engine ci preview",
    )?;

    let after = crate::evidence_ci::run_project(&frontier, path);
    let new_blocking: Vec<String> = crate::evidence_ci::release_blocking_failures(&after)
        .difference(&before_blocking)
        .cloned()
        .collect();
    let new_warnings: Vec<String> = crate::evidence_ci::review_warnings(&after)
        .difference(&before_warn)
        .cloned()
        .collect();

    let status = if is_truth_bearing_kind(&kind) && !new_blocking.is_empty() {
        "blocked"
    } else if !new_warnings.is_empty() {
        "warn"
    } else {
        "pass"
    }
    .to_string();

    Ok(EngineVerdict {
        status,
        new_blocking,
        new_warnings,
        forced: false,
        strict: false,
        release_blocking_failed: after.summary.release_blocking_failed,
        warnings: after.summary.warnings,
    })
}

pub fn reject_at_path(
    path: &Path,
    proposal_id: &str,
    reviewer: &str,
    reason: &str,
) -> Result<(), String> {
    reject_at_path_signed(path, proposal_id, reviewer, reason, None)
}

/// Reject a proposal, signing the resulting `review.rejected` event under
/// the reviewer key when supplied. Mirrors `accept_at_path_signed`: if the
/// reviewer is registered with a pubkey, the key is required.
pub fn reject_at_path_signed(
    path: &Path,
    proposal_id: &str,
    reviewer: &str,
    reason: &str,
    signing_key: Option<&ed25519_dalek::SigningKey>,
) -> Result<(), String> {
    let mut frontier = repo::load_from_path(path)?;
    reject_proposal_in_frontier_signed(
        &mut frontier,
        proposal_id,
        reviewer,
        reason,
        signing_key,
        false,
    )?;
    project::recompute_stats(&mut frontier);
    repo::save_to_path(path, &frontier)?;
    Ok(())
}

pub fn request_revision_at_path(
    path: &Path,
    proposal_id: &str,
    reviewer: &str,
    reason: &str,
) -> Result<(), String> {
    request_revision_at_path_signed(path, proposal_id, reviewer, reason, None)
}

/// Request revision on a proposal, signing the resulting
/// `review.revision_requested` event under the reviewer key when supplied.
pub fn request_revision_at_path_signed(
    path: &Path,
    proposal_id: &str,
    reviewer: &str,
    reason: &str,
    signing_key: Option<&ed25519_dalek::SigningKey>,
) -> Result<(), String> {
    let mut frontier = repo::load_from_path(path)?;
    request_revision_in_frontier_signed(
        &mut frontier,
        proposal_id,
        reviewer,
        reason,
        signing_key,
        false,
    )?;
    project::recompute_stats(&mut frontier);
    repo::save_to_path(path, &frontier)?;
    Ok(())
}

/// Load a frontier, backfill legacy review events for already-decided
/// proposals lacking one, and save only if anything was synthesized.
/// Returns the number of events added. Idempotent: a second run adds zero.
pub fn backfill_reviews_at_path(path: &Path) -> Result<usize, String> {
    let mut frontier = repo::load_from_path(path)?;
    let count = backfill_legacy_review_events(&mut frontier)?;
    if count > 0 {
        project::recompute_stats(&mut frontier);
        repo::save_to_path(path, &frontier)?;
    }
    Ok(count)
}

pub fn record_proof_export(frontier: &mut Project, record: ProofPacketRecord) {
    frontier.proof_state.latest_packet = ProofPacketState {
        generated_at: Some(record.generated_at),
        snapshot_hash: Some(record.snapshot_hash),
        event_log_hash: Some(record.event_log_hash),
        packet_manifest_hash: Some(record.packet_manifest_hash),
        status: "current".to_string(),
    };
    frontier.proof_state.last_event_at_export =
        frontier.events.last().map(|event| event.timestamp.clone());
    frontier.proof_state.stale_reason = None;
}

pub fn mark_proof_stale(frontier: &mut Project, reason: String) {
    if frontier.proof_state.latest_packet.status != "never_exported" {
        frontier.proof_state.latest_packet.status = "stale".to_string();
        frontier.proof_state.stale_reason = Some(reason);
    }
}

pub fn proof_state_json(proof_state: &ProofState) -> Value {
    serde_json::to_value(proof_state).unwrap_or_else(|_| json!({"status": "never_exported"}))
}

pub fn proposal_state_hash(proposals: &[StateProposal]) -> String {
    let bytes = canonical::to_canonical_bytes(proposals).unwrap_or_default();
    hex::encode(Sha256::digest(bytes))
}

fn load_proposals(source: &Path) -> Result<Vec<StateProposal>, String> {
    if source.is_file() {
        let data = std::fs::read_to_string(source)
            .map_err(|e| format!("Failed to read proposal file '{}': {e}", source.display()))?;
        if let Ok(proposals) = serde_json::from_str::<Vec<StateProposal>>(&data) {
            return Ok(proposals);
        }
        let proposal = serde_json::from_str::<StateProposal>(&data)
            .map_err(|e| format!("Failed to parse proposal JSON '{}': {e}", source.display()))?;
        return Ok(vec![proposal]);
    }
    if source.is_dir() {
        let mut entries = std::fs::read_dir(source)
            .map_err(|e| format!("Failed to read proposal dir '{}': {e}", source.display()))?
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
            .collect::<Vec<_>>();
        entries.sort();
        let mut proposals = Vec::new();
        for path in entries {
            proposals.extend(load_proposals(&path)?);
        }
        return Ok(proposals);
    }
    Err(format!(
        "Proposal source does not exist: {}",
        source.display()
    ))
}

fn validate_new_proposal(frontier: &Project, proposal: &StateProposal) -> Result<(), String> {
    if proposal.schema != PROPOSAL_SCHEMA {
        return Err(format!("Unsupported proposal schema '{}'", proposal.schema));
    }
    if frontier
        .proposals
        .iter()
        .any(|existing| existing.id == proposal.id)
    {
        return Err(format!("Duplicate proposal id {}", proposal.id));
    }
    validate_proposal_shape(frontier, proposal)?;
    validate_decision_state(proposal)
}

fn validate_proposal_shape(frontier: &Project, proposal: &StateProposal) -> Result<(), String> {
    // v0.52: relax the finding-only constraint so the agent inbox
    // can deposit nulls and trajectories through the same review-
    // gated flow as findings. The proposal-kind dispatch below
    // enforces that target.type matches the kind family.
    if !matches!(
        proposal.target.r#type.as_str(),
        "finding" | "artifact" | "evidence_atom" | "frontier_observation"
    ) {
        return Err(format!(
            "Unsupported proposal target type '{}'; valid: finding, artifact, evidence_atom, frontier_observation",
            proposal.target.r#type
        ));
    }
    if proposal.reason.trim().is_empty() {
        return Err("Proposal reason must be non-empty".to_string());
    }
    if !matches!(
        proposal.status.as_str(),
        "pending_review" | "accepted" | "rejected" | "applied"
    ) {
        return Err(format!("Unsupported proposal status '{}'", proposal.status));
    }
    match proposal.kind.as_str() {
        "finding.add" => {
            let finding_value = proposal
                .payload
                .get("finding")
                .ok_or("finding.add proposal missing payload.finding")?
                .clone();
            let finding: FindingBundle = serde_json::from_value(finding_value)
                .map_err(|e| format!("Invalid finding.add payload: {e}"))?;
            if finding.id != proposal.target.id {
                return Err(format!(
                    "finding.add target {} does not match payload finding {}",
                    proposal.target.id, finding.id
                ));
            }
            if frontier
                .findings
                .iter()
                .any(|existing| existing.id == proposal.target.id)
            {
                return Err(format!(
                    "Refusing to add duplicate finding with existing finding ID {}",
                    proposal.target.id
                ));
            }
        }
        "finding.review" => {
            require_existing_finding(frontier, &proposal.target.id)?;
            let status = proposal
                .payload
                .get("status")
                .and_then(Value::as_str)
                .ok_or("finding.review proposal missing payload.status")?;
            if !matches!(
                status,
                "accepted" | "approved" | "contested" | "needs_revision" | "rejected"
            ) {
                return Err(format!("Unsupported review proposal status '{status}'"));
            }
        }
        "finding.caveat" => {
            require_existing_finding(frontier, &proposal.target.id)?;
            let text = proposal
                .payload
                .get("text")
                .and_then(Value::as_str)
                .ok_or("finding.caveat proposal missing payload.text")?;
            if text.trim().is_empty() {
                return Err("finding.caveat payload.text must be non-empty".to_string());
            }
        }
        "finding.note" => {
            require_existing_finding(frontier, &proposal.target.id)?;
            let text = proposal
                .payload
                .get("text")
                .and_then(Value::as_str)
                .ok_or("finding.note proposal missing payload.text")?;
            if text.trim().is_empty() {
                return Err("finding.note payload.text must be non-empty".to_string());
            }
        }
        "finding.confidence_revise" => {
            require_existing_finding(frontier, &proposal.target.id)?;
            let score = proposal
                .payload
                .get("confidence")
                .and_then(Value::as_f64)
                .ok_or("finding.confidence_revise proposal missing payload.confidence")?;
            if !(0.0..=1.0).contains(&score) {
                return Err(
                    "finding.confidence_revise confidence must be between 0.0 and 1.0".to_string(),
                );
            }
        }
        "finding.reject" => {
            require_existing_finding(frontier, &proposal.target.id)?;
        }
        "finding.retract" => {
            let idx = require_existing_finding(frontier, &proposal.target.id)?;
            if frontier.findings[idx].flags.retracted {
                return Err(format!(
                    "Finding {} is already retracted",
                    proposal.target.id
                ));
            }
        }
        "finding.supersede" => {
            let idx = require_existing_finding(frontier, &proposal.target.id)?;
            if frontier.findings[idx].flags.superseded {
                return Err(format!(
                    "Finding {} is already superseded",
                    proposal.target.id
                ));
            }
            let new_finding_value = proposal
                .payload
                .get("new_finding")
                .ok_or("finding.supersede proposal missing payload.new_finding")?
                .clone();
            let new_finding: FindingBundle = serde_json::from_value(new_finding_value)
                .map_err(|e| format!("Invalid finding.supersede payload.new_finding: {e}"))?;
            if new_finding.id == proposal.target.id {
                return Err(
                    "finding.supersede new_finding has same content address as the superseded target — change assertion text, type, or provenance to derive a distinct vf_…".to_string(),
                );
            }
            if frontier
                .findings
                .iter()
                .any(|existing| existing.id == new_finding.id)
            {
                return Err(format!(
                    "Refusing to add superseding finding with existing finding ID {}",
                    new_finding.id
                ));
            }
        }
        "artifact.assert" => {
            if proposal.target.r#type != "artifact" {
                return Err(format!(
                    "artifact.assert proposal target.type must be 'artifact', got '{}'",
                    proposal.target.r#type
                ));
            }
            let artifact_value = proposal
                .payload
                .get("artifact")
                .ok_or("artifact.assert proposal missing payload.artifact")?
                .clone();
            let artifact: Artifact = serde_json::from_value(artifact_value)
                .map_err(|e| format!("Invalid artifact.assert payload: {e}"))?;
            if artifact.id != proposal.target.id {
                return Err(format!(
                    "artifact.assert target {} does not match payload id {}",
                    proposal.target.id, artifact.id
                ));
            }
            if frontier.artifacts.iter().any(|a| a.id == artifact.id) {
                return Err(format!(
                    "Refusing to add duplicate artifact with existing id {}",
                    artifact.id
                ));
            }
        }
        "verifier.attach" => {
            if proposal.target.r#type != "finding" {
                return Err(format!(
                    "verifier.attach proposal target.type must be 'finding', got '{}'",
                    proposal.target.r#type
                ));
            }
            let value = proposal
                .payload
                .get("attachment")
                .ok_or("verifier.attach proposal missing payload.attachment")?
                .clone();
            let att: crate::verifier_attachment::VerifierAttachment = serde_json::from_value(value)
                .map_err(|e| format!("Invalid verifier.attach payload: {e}"))?;
            att.verify()
                .map_err(|e| format!("verifier.attach attachment malformed: {e}"))?;
            if att.target != proposal.target.id {
                return Err(format!(
                    "verifier.attach attachment.target {} does not match proposal target {}",
                    att.target, proposal.target.id
                ));
            }
        }
        // v0.57: Mechanical finding-level span repair. Appends a
        // `{section, text}` span to the finding's evidence_spans.
        "finding.span_repair" => {
            if proposal.target.r#type != "finding" {
                return Err(format!(
                    "finding.span_repair target.type must be 'finding', got '{}'",
                    proposal.target.r#type
                ));
            }
            require_existing_finding(frontier, &proposal.target.id)?;
            let section = proposal
                .payload
                .get("section")
                .and_then(Value::as_str)
                .ok_or("finding.span_repair proposal missing payload.section")?;
            if section.trim().is_empty() {
                return Err("finding.span_repair payload.section must be non-empty".to_string());
            }
            let text = proposal
                .payload
                .get("text")
                .and_then(Value::as_str)
                .ok_or("finding.span_repair proposal missing payload.text")?;
            if text.trim().is_empty() {
                return Err("finding.span_repair payload.text must be non-empty".to_string());
            }
        }
        // v0.56: Mechanical evidence-atom locator repair. Targets one
        // evidence atom by id; payload carries the resolved locator
        // string and the parent source id it was derived from. The
        // proposal is mechanical: the locator is already present on
        // `frontier.sources[atom.source_id].locator`. Reviewer accepts
        // (or auto-accepts) and the canonical event lands the locator
        // on the atom while preserving the derivation in the payload.
        "evidence_atom.locator_repair" => {
            if proposal.target.r#type != "evidence_atom" {
                return Err(format!(
                    "evidence_atom.locator_repair target.type must be 'evidence_atom', got '{}'",
                    proposal.target.r#type
                ));
            }
            let atom_id = proposal.target.id.as_str();
            let atom = frontier
                .evidence_atoms
                .iter()
                .find(|atom| atom.id == atom_id)
                .ok_or_else(|| {
                    format!("evidence_atom.locator_repair targets unknown atom {atom_id}")
                })?;
            let locator = proposal
                .payload
                .get("locator")
                .and_then(Value::as_str)
                .ok_or("evidence_atom.locator_repair proposal missing payload.locator")?;
            if locator.trim().is_empty() {
                return Err(
                    "evidence_atom.locator_repair payload.locator must be non-empty".to_string(),
                );
            }
            let source_id = proposal
                .payload
                .get("source_id")
                .and_then(Value::as_str)
                .ok_or("evidence_atom.locator_repair proposal missing payload.source_id")?;
            if source_id.trim().is_empty() {
                return Err(
                    "evidence_atom.locator_repair payload.source_id must be non-empty".to_string(),
                );
            }
            if atom.source_id != source_id {
                return Err(format!(
                    "evidence_atom.locator_repair payload.source_id '{source_id}' does not match atom.source_id '{}'",
                    atom.source_id
                ));
            }
            // Refuse a no-op repair so the curation pipeline doesn't
            // emit empty events. An atom that already carries the same
            // locator should be filtered upstream.
            if let Some(existing) = &atom.locator
                && existing == locator
            {
                return Err(format!(
                    "evidence_atom {atom_id} already carries locator '{existing}'"
                ));
            }
            // Refuse a divergent overwrite. A different existing
            // locator is a chain-integrity issue, not a repair.
            if let Some(existing) = &atom.locator
                && existing != locator
            {
                return Err(format!(
                    "evidence_atom {atom_id} already carries locator '{existing}'; refusing to overwrite with '{locator}'"
                ));
            }
        }
        "research_trace.review" => {
            validate_research_trace_review_payload(proposal)?;
        }
        "correction_return.review" => {
            validate_correction_return_review_payload(proposal)?;
        }
        other => {
            return Err(format!("Unsupported proposal kind '{other}'"));
        }
    }
    Ok(())
}

fn validate_decision_state(proposal: &StateProposal) -> Result<(), String> {
    match proposal.status.as_str() {
        "pending_review" => Ok(()),
        "accepted" | "applied" | "rejected" => {
            let reviewer = proposal
                .reviewed_by
                .as_deref()
                .ok_or_else(|| format!("Proposal {} missing reviewed_by", proposal.id))?;
            validate_reviewer_identity(reviewer)?;
            if proposal
                .decision_reason
                .as_deref()
                .is_none_or(|reason| reason.trim().is_empty())
            {
                return Err(format!("Proposal {} missing decision_reason", proposal.id));
            }
            if proposal.status == "applied" && proposal.applied_event_id.is_none() {
                return Err(format!(
                    "Applied proposal {} missing applied_event_id",
                    proposal.id
                ));
            }
            Ok(())
        }
        other => Err(format!("Unsupported proposal status '{}'", other)),
    }
}

fn validate_standalone_proposal(
    _frontier: &Project,
    proposal: &StateProposal,
) -> Result<(), String> {
    if proposal.schema != PROPOSAL_SCHEMA {
        return Err(format!("Unsupported proposal schema '{}'", proposal.schema));
    }
    if !matches!(
        proposal.target.r#type.as_str(),
        "finding" | "evidence_atom" | "frontier_observation"
    ) {
        return Err(
            "Only finding, evidence_atom, and frontier_observation proposals are supported in v0"
                .to_string(),
        );
    }
    if proposal.reason.trim().is_empty() {
        return Err("Proposal reason must be non-empty".to_string());
    }
    match proposal.kind.as_str() {
        "finding.add" => {
            let finding_value = proposal
                .payload
                .get("finding")
                .ok_or("finding.add proposal missing payload.finding")?
                .clone();
            let finding: FindingBundle = serde_json::from_value(finding_value)
                .map_err(|e| format!("Invalid finding.add payload: {e}"))?;
            if finding.id != proposal.target.id {
                return Err(format!(
                    "finding.add target {} does not match payload finding {}",
                    proposal.target.id, finding.id
                ));
            }
        }
        "finding.review" => {
            let status = proposal
                .payload
                .get("status")
                .and_then(Value::as_str)
                .ok_or("finding.review proposal missing payload.status")?;
            if !matches!(
                status,
                "accepted" | "approved" | "contested" | "needs_revision" | "rejected"
            ) {
                return Err(format!("Unsupported review proposal status '{status}'"));
            }
        }
        "finding.caveat" => {
            let text = proposal
                .payload
                .get("text")
                .and_then(Value::as_str)
                .ok_or("finding.caveat proposal missing payload.text")?;
            if text.trim().is_empty() {
                return Err("finding.caveat payload.text must be non-empty".to_string());
            }
        }
        "finding.note" => {
            let text = proposal
                .payload
                .get("text")
                .and_then(Value::as_str)
                .ok_or("finding.note proposal missing payload.text")?;
            if text.trim().is_empty() {
                return Err("finding.note payload.text must be non-empty".to_string());
            }
        }
        "finding.confidence_revise" => {
            let score = proposal
                .payload
                .get("confidence")
                .and_then(Value::as_f64)
                .ok_or("finding.confidence_revise proposal missing payload.confidence")?;
            if !(0.0..=1.0).contains(&score) {
                return Err(
                    "finding.confidence_revise confidence must be between 0.0 and 1.0".to_string(),
                );
            }
        }
        "finding.reject" | "finding.retract" => {}
        "finding.supersede" => {
            let new_finding_value = proposal
                .payload
                .get("new_finding")
                .ok_or("finding.supersede proposal missing payload.new_finding")?
                .clone();
            let new_finding: FindingBundle = serde_json::from_value(new_finding_value)
                .map_err(|e| format!("Invalid finding.supersede payload.new_finding: {e}"))?;
            if new_finding.id == proposal.target.id {
                return Err(
                    "finding.supersede new_finding has same content address as the superseded target"
                        .to_string(),
                );
            }
        }
        // v0.57: standalone validation of finding span-repair.
        "finding.span_repair" => {
            if proposal.target.r#type != "finding" {
                return Err(format!(
                    "finding.span_repair target.type must be 'finding', got '{}'",
                    proposal.target.r#type
                ));
            }
            let section = proposal
                .payload
                .get("section")
                .and_then(Value::as_str)
                .ok_or("finding.span_repair proposal missing payload.section")?;
            if section.trim().is_empty() {
                return Err("finding.span_repair payload.section must be non-empty".to_string());
            }
            let text = proposal
                .payload
                .get("text")
                .and_then(Value::as_str)
                .ok_or("finding.span_repair proposal missing payload.text")?;
            if text.trim().is_empty() {
                return Err("finding.span_repair payload.text must be non-empty".to_string());
            }
        }
        // v0.56: standalone validation of an evidence-atom locator
        // repair. Mirrors the contextual validator in
        // `validate_proposal_shape`, except without frontier-side
        // existence checks (the standalone validator runs over an
        // exported proposal before it is loaded into a frontier).
        "evidence_atom.locator_repair" => {
            if proposal.target.r#type != "evidence_atom" {
                return Err(format!(
                    "evidence_atom.locator_repair target.type must be 'evidence_atom', got '{}'",
                    proposal.target.r#type
                ));
            }
            let locator = proposal
                .payload
                .get("locator")
                .and_then(Value::as_str)
                .ok_or("evidence_atom.locator_repair proposal missing payload.locator")?;
            if locator.trim().is_empty() {
                return Err(
                    "evidence_atom.locator_repair payload.locator must be non-empty".to_string(),
                );
            }
            let source_id = proposal
                .payload
                .get("source_id")
                .and_then(Value::as_str)
                .ok_or("evidence_atom.locator_repair proposal missing payload.source_id")?;
            if source_id.trim().is_empty() {
                return Err(
                    "evidence_atom.locator_repair payload.source_id must be non-empty".to_string(),
                );
            }
        }
        "research_trace.review" => {
            validate_research_trace_review_payload(proposal)?;
        }
        "correction_return.review" => {
            validate_correction_return_review_payload(proposal)?;
        }
        other => return Err(format!("Unsupported proposal kind '{other}'")),
    }
    validate_decision_state(proposal)
}

fn validate_research_trace_review_payload(proposal: &StateProposal) -> Result<(), String> {
    if proposal.target.r#type != "frontier_observation" {
        return Err(format!(
            "research_trace.review target.type must be 'frontier_observation', got '{}'",
            proposal.target.r#type
        ));
    }
    let trace_id = proposal
        .payload
        .get("trace_id")
        .and_then(Value::as_str)
        .ok_or("research_trace.review proposal missing payload.trace_id")?;
    if !trace_id.starts_with("vrt_") {
        return Err("research_trace.review payload.trace_id must start with `vrt_`".to_string());
    }
    let output_kind = proposal
        .payload
        .get("output_kind")
        .and_then(Value::as_str)
        .ok_or("research_trace.review proposal missing payload.output_kind")?;
    if !matches!(output_kind, "candidate_finding" | "open_need") {
        return Err(format!(
            "research_trace.review payload.output_kind must be candidate_finding or open_need, got '{output_kind}'"
        ));
    }
    if output_kind == "candidate_finding" && proposal.payload.get("candidate").is_none() {
        return Err(
            "research_trace.review candidate_finding missing payload.candidate".to_string(),
        );
    }
    if output_kind == "open_need" && proposal.payload.get("open_need").is_none() {
        return Err("research_trace.review open_need missing payload.open_need".to_string());
    }
    if proposal.payload.get("authority_boundary").is_none() {
        return Err("research_trace.review missing payload.authority_boundary".to_string());
    }
    if proposal.payload.get("formalization_fidelity").is_none() {
        return Err("research_trace.review missing payload.formalization_fidelity".to_string());
    }
    if !proposal
        .source_refs
        .iter()
        .any(|source_ref| source_ref == trace_id)
    {
        return Err(format!(
            "research_trace.review source_refs must include trace_id {trace_id}"
        ));
    }
    Ok(())
}

fn validate_correction_return_review_payload(proposal: &StateProposal) -> Result<(), String> {
    if proposal.target.r#type != "frontier_observation" {
        return Err(format!(
            "correction_return.review target.type must be 'frontier_observation', got '{}'",
            proposal.target.r#type
        ));
    }
    let correction = proposal
        .payload
        .get("correction")
        .ok_or("correction_return.review proposal missing payload.correction")?;
    for field in [
        "target_id",
        "issue",
        "proposed_change",
        "source_locator",
        "evidence_span",
    ] {
        let value = correction
            .get(field)
            .and_then(Value::as_str)
            .ok_or_else(|| {
                format!("correction_return.review payload.correction.{field} is required")
            })?;
        if value.trim().is_empty() {
            return Err(format!(
                "correction_return.review payload.correction.{field} must be non-empty"
            ));
        }
    }
    let verification_runs = correction
        .get("verification_run")
        .and_then(Value::as_array)
        .ok_or("correction_return.review payload.correction.verification_run must be an array")?;
    if verification_runs.is_empty() {
        return Err(
            "correction_return.review payload.correction.verification_run must be non-empty"
                .to_string(),
        );
    }
    let boundary = proposal
        .payload
        .get("claim_boundary")
        .and_then(Value::as_object)
        .ok_or("correction_return.review missing payload.claim_boundary")?;
    for field in [
        "claims_clinical_validity",
        "claims_external_adoption",
        "claims_external_validation",
        "claims_lab_validation",
        "claims_scientific_discovery",
        "claims_target_validation",
        "claims_treatment_advice",
    ] {
        match boundary.get(field).and_then(Value::as_bool) {
            Some(false) => {}
            Some(true) => {
                return Err(format!(
                    "correction_return.review payload.claim_boundary.{field} must be false"
                ));
            }
            None => {
                return Err(format!(
                    "correction_return.review payload.claim_boundary.{field} is required"
                ));
            }
        }
    }
    if !proposal.source_refs.iter().any(|source_ref| {
        source_ref == "correction-return.template.json"
            || (source_ref.starts_with("correction-return.") && source_ref.ends_with(".json"))
    }) {
        return Err(
            "correction_return.review source_refs must include correction-return.template.json or a correction-return.*.json file"
                .to_string(),
        );
    }
    Ok(())
}

fn require_existing_finding(frontier: &Project, finding_id: &str) -> Result<usize, String> {
    frontier
        .findings
        .iter()
        .position(|finding| finding.id == finding_id)
        .ok_or_else(|| format!("Finding not found: {finding_id}"))
}

// ── v0.339: the bounded trusted-reviewer-agent accept policy ──────────
//
// `accept_proposal_in_frontier` is the *sole* path that mutates canonical
// frontier state. Prior to v0.339 it accepted under any non-placeholder
// reviewer id — including an `agent:*` actor accepting its own proposal
// via `create_or_apply(apply = true)`. The "agents cannot auto-accept
// truth" rule therefore lived only in doctrine and maintainer habit, not
// in code. v0.339 closes that hole and opens a narrow, machine-checkable
// set of self-appliable work so a fleet can promote *verified* and
// *non-truth-bearing* work without a human in the inner loop, while every
// truth-bearing claim stays human-gated:
//
//   • Any agent may self-apply non-truth-bearing PROCESS/PROVENANCE kinds
//     (trajectories, content-addressed artifacts) and mechanical,
//     truth-preserving REPAIR kinds (span/locator repair). These record
//     process, store content, or attach provenance — they assert no claim
//     about the world. Gated by kind, not by a privileged actor.
//   • `agent:replicator` (and only it) may accept a claim-asserting proposal
//     (`finding.add` / `finding.review`) IFF its payload carries a
//     `replication_attestation` that passes `replication_attestation_passes`.
//     The gate trusts the recorded replication numbers, not the agent —
//     two reviewers computing the predicate get the same answer. This is
//     the computational accept gate for the mechanistic-interpretability
//     flagship (adversarial replication as the verifier).
//
// Every other agent acceptance — a truth-bearing claim without a passing
// attestation, or by a non-replicator agent — is rejected: the reviewer
// must be a named human. The gate is a no-op for non-agent reviewers, so
// existing human-authored flows are unaffected. Fail-closed by construction.

/// Minimum independent replications an `agent:replicator` attestation must
/// record before the substrate will let an agent promote a claim.
const MIN_INDEPENDENT_REPLICATIONS: u64 = 3;

/// Minimum surviving effect size (e.g. induction score, patched-logit
/// delta) across the replication set. Matches the breadth-sweep cutoff the
/// flagship harness uses so that what survives to accept is non-marginal.
const MIN_REPLICATION_EFFECT: f64 = 0.30;

/// Claim-asserting kinds an `agent:replicator` is allowed to auto-accept.
/// Deliberately excludes destructive/lifecycle kinds (retract, supersede,
/// confidence_revise, reject) — those always need a human.
const TRUSTED_REPLICATOR_KINDS: &[&str] = &["finding.add", "finding.review"];

/// Mechanical, truth-preserving repair kinds any agent may auto-accept.
/// These attach resolved provenance pointers (a source locator, an evidence
/// span) without changing what a finding asserts, so they are gated by kind
/// rather than by a privileged actor.
const TRUSTED_REPAIR_KINDS: &[&str] = &["finding.span_repair", "evidence_atom.locator_repair"];

/// Non-truth-bearing provenance kinds any agent may self-apply:
/// content-addressed artifact registration. These *store content* — they
/// assert no scientific claim about the world, and a content-addressed
/// artifact cannot misrepresent (its id is the hash of its bytes). They
/// fall outside the human-gated truth boundary, so a fleet need not block
/// on a human to store what it produced. Anything truth-bearing (a claim
/// about the world, including a null result) stays gated.
const AGENT_SELF_APPLIABLE_PROCESS_KINDS: &[&str] = &["artifact.assert", "artifact.add"];

/// Pure, deterministic check over a proposal payload's
/// `replication_attestation` object. Returns true only when the recorded
/// evidence shows the claim survived independent adversarial replication:
/// enough independent runs, all passing, on held-out prompts, confirmed on
/// a second model, with at least one CPU-verified run (MPS can be silently
/// wrong), and a non-marginal minimum effect. Trust is in the numbers, not
/// the agent, so the predicate is reproducible by any reviewer.
fn replication_attestation_passes(payload: &Value) -> bool {
    let Some(att) = payload.get("replication_attestation") else {
        return false;
    };
    let reps = att
        .get("independent_replications")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let all_passed = att
        .get("all_replications_passed")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let held_out = att
        .get("held_out_prompts")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let second_model = att
        .get("second_model_confirmed")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let cpu_verified = att
        .get("cpu_verified")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let min_effect = att
        .get("min_effect_size")
        .and_then(Value::as_f64)
        .unwrap_or(0.0);
    reps >= MIN_INDEPENDENT_REPLICATIONS
        && all_passed
        && held_out
        && second_model
        && cpu_verified
        && min_effect >= MIN_REPLICATION_EFFECT
}

/// Proposal-level guards for exact-lane auto-admission (Phase 1A, the
/// de-human-gate). Returns `(admit, reasons)`; `reasons` is non-empty exactly
/// when refused. Pure and deterministic, so two implementations agree.
///
/// IMPORTANT — this is NOT the whole gate. The un-forgeable floor (a fresh
/// `vela reproduce` over the witness AND `vela_verify::claim_witness_faithful`
/// binding the parsed assertion to the witness structure) is applied by the
/// CLI command BEFORE this is called, because it needs the `vela-verify`
/// binary and the witness file, which the protocol crate does not see. This
/// function adds the protocol-level guards a human reviewer applies and then
/// delegates to the attachment corroboration predicate
/// [`crate::verifier_attachment::exact_lane_attachment_admit`]. See
/// `docs/VERIFICATION.md` for why the corroboration predicate alone is
/// insufficient (a `VerifierAttachment` is unsigned self-asserted data the
/// producing agent can author).
///
/// Fail-closed guard order:
///   1. kind allowlist: `finding.add` only.
///   2. target binding: target is this finding.
///   3. content-address drift-pin: the loaded finding body must content-address
///      to its own id (closes assertion-text edits after the id was minted).
///   4. lifecycle: the finding is neither retracted nor superseded.
///   5. synthetic: no `synthetic_source_requires_review` signal (caller-derived).
///   6. contradiction: no live open contradiction names this finding
///      (caller-derived, including freshly derived candidates).
///   7. producer != verifier: the proposing actor differs from every matched
///      attachment's `verifier_actor` (the producer cannot be its own
///      corroborator at the actor level).
///   8. delegate to the attachment predicate over the matched attachments.
pub fn exact_lane_auto_admit(
    proposal: &StateProposal,
    finding: &crate::bundle::FindingBundle,
    attachments: &[crate::verifier_attachment::VerifierAttachment],
    open_contradiction_finding_ids: &BTreeSet<String>,
    synthetic_unreviewed_finding_ids: &BTreeSet<String>,
    floor_sufficient: bool,
) -> (bool, Vec<String>) {
    let mut reasons = Vec::new();

    // 1. kind allowlist.
    if proposal.kind != "finding.add" {
        reasons.push(format!(
            "exact-lane: proposal kind '{}' is not 'finding.add'",
            proposal.kind
        ));
        return (false, reasons);
    }

    // 2. target binding.
    if proposal.target.r#type != "finding" || proposal.target.id != finding.id {
        reasons.push("exact-lane: proposal target does not bind to this finding".to_string());
        return (false, reasons);
    }

    // 3. content-address drift-pin: the body must hash to its own id.
    let recomputed =
        crate::bundle::FindingBundle::content_address(&finding.assertion, &finding.provenance);
    if recomputed != finding.id {
        reasons.push(format!(
            "exact-lane: finding body does not content-address to its id (drift): {} != {}",
            recomputed, finding.id
        ));
        return (false, reasons);
    }

    // 4. lifecycle.
    if finding.flags.retracted || finding.flags.superseded {
        reasons.push("exact-lane: finding is retracted or superseded".to_string());
        return (false, reasons);
    }

    // 5. synthetic-source signal.
    if synthetic_unreviewed_finding_ids.contains(&finding.id) {
        reasons.push(
            "exact-lane: finding carries a synthetic_source_requires_review signal".to_string(),
        );
        return (false, reasons);
    }

    // 6. live open contradiction.
    if open_contradiction_finding_ids.contains(&finding.id) {
        reasons.push("exact-lane: a live open contradiction names this finding".to_string());
        return (false, reasons);
    }

    // The matched attachments (those bound to this finding).
    let matched: Vec<crate::verifier_attachment::VerifierAttachment> = attachments
        .iter()
        .filter(|a| a.target == finding.id)
        .cloned()
        .collect();

    // 7. producer != verifier: the proposing actor cannot also be a corroborator.
    let producer = proposal.actor.id.trim();
    if !producer.is_empty()
        && let Some(bad) = matched.iter().find(|a| a.verifier_actor.trim() == producer)
    {
        reasons.push(format!(
            "exact-lane: the proposing actor '{}' is also a verifier_actor on attachment '{}' \
             (producer cannot corroborate itself)",
            producer, bad.id
        ));
        return (false, reasons);
    }

    // 8. corroboration. When `floor_sufficient` (the caller established the
    // un-forgeable floor: a fresh frozen `vela reproduce` over the witness AND
    // `claim_witness_faithful` binding the parsed assertion to it), the FLOOR is
    // itself the proof of an exact lower-bound / size claim, so the
    // >=2-independent-attachment requirement (the GENERAL gate's bar, for claims
    // with no single frozen verifier) is waived — attachments become optional
    // corroboration. Otherwise the attachment predicate must derive Verified.
    if !floor_sufficient {
        let digest = crate::verifier_attachment::claim_digest(&finding.assertion.text);
        let (admit, att_reasons) =
            crate::verifier_attachment::exact_lane_attachment_admit(&digest, &matched);
        if !admit {
            reasons.extend(att_reasons);
            return (false, reasons);
        }
    }

    (true, reasons)
}

/// The verification trust tier of a finding (Phase 1A). An ordered ladder;
/// the machine advances the lower rungs, a human key-custody accept is the
/// only path to `Accepted`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustTier {
    Candidate,
    SchemaChecked,
    MachineVerified,
    Accepted,
}

impl TrustTier {
    pub fn as_str(&self) -> &'static str {
        match self {
            TrustTier::Candidate => "candidate",
            TrustTier::SchemaChecked => "schema_checked",
            TrustTier::MachineVerified => "machine_verified",
            TrustTier::Accepted => "accepted",
        }
    }
}

/// Project a finding's verification trust tier from canonical state + the
/// immutable log + live attachments (Phase 1A). A read-only projection, never
/// a stored field: recomputed fresh so a forged `policy.auto_admitted` event
/// cannot by itself raise the tier, and a later-weakened attachment set
/// silently lowers it.
///
/// - `Accepted`: the finding is landed in canonical state (`frontier.findings`)
///   and not retracted/superseded. Landing runs only through the key-custody
///   accept ceremony, so canonical membership IS the human-accept signal (no
///   reliance on which event kind the ceremony emitted). Strictly highest; the
///   machine never reaches it.
/// - `MachineVerified`: the finding is a PENDING `finding.add` proposal carrying
///   a `policy.auto_admitted` marker whose gate, recomputed LIVE from the
///   proposal's finding text + the current matched attachments, is `Verified`.
///   Machine-verified state is a separate queryable layer over pending
///   proposals; it is NEVER landed in `frontier.findings` (that is the human
///   tier), which preserves the charter boundary.
/// - `SchemaChecked`: at least one passing matched attachment, not yet Verified.
/// - `Candidate`: everything else, including retracted/superseded.
pub fn derive_trust_tier(frontier: &Project, finding_id: &str) -> TrustTier {
    use crate::verifier_attachment::{AttachmentOutcome, GateStatus, derive_gate_status};

    // Landed in canonical accepted state?
    if let Some(f) = frontier.findings.iter().find(|f| f.id == finding_id) {
        if f.flags.retracted || f.flags.superseded {
            return TrustTier::Candidate;
        }
        return TrustTier::Accepted;
    }

    let matched: Vec<crate::verifier_attachment::VerifierAttachment> = frontier
        .verifier_attachments
        .iter()
        .filter(|a| a.target == finding_id)
        .cloned()
        .collect();

    // A pending finding.add proposal for this finding, carrying an auto-admit.
    let pending = frontier.proposals.iter().find(|p| {
        p.kind == "finding.add"
            && p.applied_event_id.is_none()
            && (p.target.id == finding_id
                || p.payload
                    .get("finding")
                    .and_then(|f| f.get("id"))
                    .and_then(|i| i.as_str())
                    == Some(finding_id))
    });
    if let Some(p) = pending {
        let admitted = frontier.events.iter().any(|e| {
            e.kind.as_str() == "policy.auto_admitted"
                && e.payload.get("proposal_id").and_then(|v| v.as_str()) == Some(p.id.as_str())
        });
        if admitted
            && let Some(finding_val) = p.payload.get("finding")
            && let Ok(fb) =
                serde_json::from_value::<crate::bundle::FindingBundle>(finding_val.clone())
        {
            let digest = crate::verifier_attachment::claim_digest(&fb.assertion.text);
            if derive_gate_status(&digest, &matched).status == GateStatus::Verified {
                return TrustTier::MachineVerified;
            }
        }
    }

    if matched
        .iter()
        .any(|a| a.outcome == AttachmentOutcome::Passed)
    {
        return TrustTier::SchemaChecked;
    }
    TrustTier::Candidate
}

/// Emit the unsigned `policy.auto_admitted` audit event for an exact-lane
/// machine admission (Phase 1A). IDEMPOTENT: if one already targets this
/// proposal, returns its id with `false` and writes nothing, so re-running
/// `--apply` yields a byte-identical log (closes the duplicate-mint hole — the
/// event id embeds a timestamp, so the parity guarantee is replay-stable, not
/// mint-deterministic). The event is a no-op on every finding digest
/// (`before == after == NULL_HASH`), so reproduce/materialize stay
/// byte-identical. UNSIGNED and mechanically un-signable: the trust is the
/// frozen predicate + frozen verifier, never a key. The caller MUST have
/// already established the YES verdict (the un-forgeable floor + the
/// proposal-level guards); this only records it.
pub fn emit_policy_auto_admitted(
    path: &Path,
    proposal_id: &str,
    claim_digest: &str,
    attachment_ids: &[String],
    policy_version: &str,
    verifier_env_hash: &str,
) -> Result<(String, bool), String> {
    let mut frontier = repo::load_from_path(path)?;
    // Idempotency: an existing admit for this proposal is authoritative.
    if let Some(existing) = frontier.events.iter().find(|e| {
        e.kind.as_str() == events::EVENT_KIND_POLICY_AUTO_ADMITTED
            && e.payload.get("proposal_id").and_then(|v| v.as_str()) == Some(proposal_id)
    }) {
        return Ok((existing.id.clone(), false));
    }
    let mut event = StateEvent {
        schema: events::EVENT_SCHEMA.to_string(),
        id: String::new(),
        kind: events::EVENT_KIND_POLICY_AUTO_ADMITTED.into(),
        target: StateTarget {
            r#type: "proposal".to_string(),
            id: proposal_id.to_string(),
        },
        actor: StateActor {
            id: "policy:exact-lane".to_string(),
            r#type: "agent".to_string(),
        },
        timestamp: Utc::now().to_rfc3339(),
        reason: format!("exact-lane auto-admit: frozen predicate {policy_version}"),
        before_hash: NULL_HASH.to_string(),
        after_hash: NULL_HASH.to_string(),
        payload: json!({
            "proposal_id": proposal_id,
            "claim_digest": claim_digest,
            "attachment_ids": attachment_ids,
            "policy_version": policy_version,
            "verifier_env_hash": verifier_env_hash,
        }),
        caveats: Vec::new(),
        signature: None,
        schema_artifact_id: None,
    };
    events::validate_event_payload(event.kind.as_str(), &event.payload)?;
    event.id = events::compute_event_id(&event);
    let id = event.id.clone();
    // Replay through the reducer (a verified no-op) before recording, exactly
    // as the loader will on the next materialize.
    crate::reducer::apply_event(&mut frontier, &event)?;
    frontier.events.push(event);
    repo::save_to_path(path, &frontier)?;
    Ok((id, true))
}

/// The bounded trusted-reviewer-agent gate. A no-op for non-agent
/// reviewers; for agent reviewers it permits the kind-gated low-risk set
/// (process/provenance + mechanical repairs) and replication-verified
/// finding claims, and is fail-closed for everything else truth-bearing.
fn enforce_trusted_agent_accept_policy(
    proposal: &StateProposal,
    reviewer: &str,
) -> Result<(), String> {
    let reviewer = reviewer.trim();
    if !reviewer.to_ascii_lowercase().starts_with("agent:") {
        // Human / named-reviewer authority: unchanged. The gate never
        // tightens the human path.
        return Ok(());
    }
    let kind = proposal.kind.as_str();
    // The bounded low-risk set any agent may self-apply: non-truth-bearing
    // provenance (a content-addressed artifact stores what the agent
    // produced, not a claim about the world) and mechanical,
    // truth-preserving repairs (a span/locator repair attaches provenance
    // without changing what the finding asserts). Repairs are gated by KIND,
    // not by a privileged actor — the named `agent:repair` role is one
    // convention, not a requirement.
    if AGENT_SELF_APPLIABLE_PROCESS_KINDS.contains(&kind) || TRUSTED_REPAIR_KINDS.contains(&kind) {
        return Ok(());
    }
    // The one truth-bearing exception: `agent:replicator` may auto-accept a
    // finding claim, and only when it carries a passing replication_attestation.
    if reviewer == "agent:replicator" && TRUSTED_REPLICATOR_KINDS.contains(&kind) {
        return if replication_attestation_passes(&proposal.payload) {
            Ok(())
        } else {
            Err(format!(
                "agent:replicator may only auto-accept a claim carrying a passing \
                 replication_attestation (>= {MIN_INDEPENDENT_REPLICATIONS} independent \
                 replications, all passed, held-out prompts, second-model confirmation, a \
                 CPU-verified run, and min_effect_size >= {MIN_REPLICATION_EFFECT}); \
                 proposal {} does not qualify",
                proposal.id
            ))
        };
    }
    Err(format!(
        "agent reviewer '{reviewer}' may not auto-accept proposal {} (kind '{kind}'): \
         truth-bearing claims require a named human reviewer. Agents may self-apply only \
         process/provenance kinds, mechanical repairs, or — as agent:replicator — a finding \
         claim carrying a passing replication_attestation.",
        proposal.id
    ))
}

/// Key custody for a reviewer decision (accept / reject / request-revision).
///
/// If the named reviewer is registered in the frontier's actor table WITH
/// a public key, the decision REQUIRES the matching private key: the typed
/// reviewer string is not authority, possession of the key is. Reviewers
/// without a registered key keep the keyless bootstrap behavior (a new
/// frontier must be usable before any keys exist). `custody_verified`
/// short-circuits the check when possession was already proved out of band
/// (the hub verifies a detached signature before calling in).
///
/// This is the mechanization of "an AI never signs a decision": an agent
/// can type any reviewer name, but it cannot produce a signature with a key
/// it does not hold — and now that applies symmetrically to rejects, not
/// just accepts.
fn enforce_reviewer_key_custody(
    frontier: &Project,
    reviewer: &str,
    signing_key: Option<&ed25519_dalek::SigningKey>,
    custody_verified: bool,
) -> Result<(), String> {
    let registered_pubkey = frontier
        .actors
        .iter()
        .find(|a| a.id == reviewer && !a.public_key.trim().is_empty())
        .map(|a| a.public_key.clone());
    if let Some(expected) = &registered_pubkey
        && !custody_verified
    {
        let Some(key) = signing_key else {
            return Err(format!(
                "reviewer {reviewer} is registered with a key ({}…); decisions under this identity require --key <path-to-private-key> — key custody, not the typed name, is the review authority",
                &expected[..expected.len().min(12)]
            ));
        };
        let derived = hex::encode(key.verifying_key().to_bytes());
        if &derived != expected {
            return Err(format!(
                "the supplied key derives pubkey {}…, which does not match {reviewer}'s registered key {}…",
                &derived[..12],
                &expected[..expected.len().min(12)]
            ));
        }
    }
    Ok(())
}

fn accept_proposal_in_frontier(
    frontier: &mut Project,
    proposal_id: &str,
    reviewer: &str,
    reason: &str,
) -> Result<String, String> {
    accept_proposal_in_frontier_signed(frontier, proposal_id, reviewer, reason, None)
}

/// The one canonical accept path, with key-custody enforcement.
///
/// If the named reviewer is registered in the frontier's actor table
/// WITH a public key, the accept REQUIRES the matching private key: the
/// typed reviewer string is not authority, possession of the key is.
/// The resulting canonical event is signed with that key, so the accept
/// is non-repudiable. Reviewers without a registered key keep the
/// keyless bootstrap behavior (a brand-new frontier must be usable
/// before any keys exist); `vela check --strict` flags unsigned accepts
/// once keys are registered.
///
/// This is the mechanization of "an AI never signs an accept": an agent
/// can type any reviewer name, but it cannot produce a signature with a
/// key it does not hold.
pub fn accept_proposal_in_frontier_signed(
    frontier: &mut Project,
    proposal_id: &str,
    reviewer: &str,
    reason: &str,
    signing_key: Option<&ed25519_dalek::SigningKey>,
) -> Result<String, String> {
    accept_proposal_in_frontier_with_custody(
        frontier,
        proposal_id,
        reviewer,
        reason,
        signing_key,
        false,
    )
}

pub fn accept_proposal_in_frontier_with_custody(
    frontier: &mut Project,
    proposal_id: &str,
    reviewer: &str,
    reason: &str,
    signing_key: Option<&ed25519_dalek::SigningKey>,
    custody_verified: bool,
) -> Result<String, String> {
    validate_reviewer_identity(reviewer)?;
    if reason.trim().is_empty() {
        return Err("Decision reason must be non-empty".to_string());
    }
    // Key custody: a reviewer registered with a pubkey must prove
    // possession. Derive the pubkey from the supplied key and compare.
    enforce_reviewer_key_custody(frontier, reviewer, signing_key, custody_verified)?;
    let index = frontier
        .proposals
        .iter()
        .position(|proposal| proposal.id == proposal_id)
        .ok_or_else(|| format!("Proposal not found: {proposal_id}"))?;
    let status = frontier.proposals[index].status.clone();
    if status == "rejected" {
        return Err(format!("Cannot accept rejected proposal {}", proposal_id));
    }
    if status == "applied" {
        return frontier.proposals[index]
            .applied_event_id
            .clone()
            .ok_or_else(|| format!("Proposal {} is applied but has no event id", proposal_id));
    }
    let proposal = frontier.proposals[index].clone();
    validate_proposal_shape(frontier, &proposal)?;
    // v0.339: the only place agent self-acceptance is allowed, and only for
    // verified work. Runs after shape validation, before any mutation.
    enforce_trusted_agent_accept_policy(&proposal, reviewer)?;
    frontier.proposals[index].status = "accepted".to_string();
    frontier.proposals[index].reviewed_by = Some(reviewer.to_string());
    frontier.proposals[index].reviewed_at = Some(Utc::now().to_rfc3339());
    frontier.proposals[index].decision_reason = Some(reason.to_string());
    let event_id = apply_proposal(frontier, &proposal, reviewer, reason)?;
    frontier.proposals[index].status = "applied".to_string();
    frontier.proposals[index].applied_event_id = Some(event_id.clone());
    // Sign the accept event under the reviewer's key: the signature is
    // over the canonical event bytes (signature field excluded), so the
    // content-addressed id is unchanged and the accept is attributable
    // by cryptography, not by string.
    if let Some(key) = signing_key
        && let Some(ev) = frontier.events.iter_mut().find(|e| e.id == event_id)
    {
        ev.signature = Some(crate::sign::sign_event(ev, key)?);
    }
    Ok(event_id)
}

/// Build, sign, and append a `review.*` decision event to the log. The
/// event is the tamper-evident, replayable record of the decision — the
/// thing a reject previously lacked entirely. Signed under the reviewer
/// key when present (custody is enforced by the caller before this runs),
/// so the decision is non-repudiable; the content-addressed id is over the
/// unsigned shape, so signing never changes it. `decided_at` is reused for
/// both the event timestamp and the proposal's `reviewed_at`, so the two
/// never diverge by a second clock read.
fn push_signed_review_event(
    frontier: &mut Project,
    proposal_id: &str,
    proposal_kind: &str,
    verdict: &str,
    applied_event_id: Option<String>,
    reviewer: &str,
    reason: &str,
    decided_at: &str,
    signing_key: Option<&ed25519_dalek::SigningKey>,
) -> Result<(), String> {
    let mut event = events::new_review_decision_event(
        proposal_id,
        proposal_kind,
        verdict,
        applied_event_id,
        reviewer,
        reason,
        Some(decided_at),
        false,
    )?;
    if let Some(key) = signing_key {
        event.signature = Some(crate::sign::sign_event(&event, key)?);
    }
    frontier.events.push(event);
    mark_proof_stale(
        frontier,
        format!("Recorded review decision on proposal {proposal_id} after latest proof export"),
    );
    Ok(())
}

/// Reject a proposal, recording a signed `review.rejected` event. This is
/// the half of the lifecycle that used to leave no trace: a reject is now
/// as accountable as an accept — same key custody, same append-only signed
/// event, same replayability.
pub fn reject_proposal_in_frontier_signed(
    frontier: &mut Project,
    proposal_id: &str,
    reviewer: &str,
    reason: &str,
    signing_key: Option<&ed25519_dalek::SigningKey>,
    custody_verified: bool,
) -> Result<(), String> {
    validate_reviewer_identity(reviewer)?;
    if reason.trim().is_empty() {
        return Err("Decision reason must be non-empty".to_string());
    }
    enforce_reviewer_key_custody(frontier, reviewer, signing_key, custody_verified)?;
    let index = frontier
        .proposals
        .iter()
        .position(|proposal| proposal.id == proposal_id)
        .ok_or_else(|| format!("Proposal not found: {proposal_id}"))?;
    match frontier.proposals[index].status.as_str() {
        "pending_review" | "accepted" | "needs_revision" => {}
        "rejected" => {
            return Err(format!("Proposal {} is already rejected", proposal_id));
        }
        "applied" => {
            return Err(format!("Proposal {} is already applied", proposal_id));
        }
        other => {
            return Err(format!("Unsupported proposal status '{}'", other));
        }
    }
    let decided_at = Utc::now().to_rfc3339();
    let proposal_kind = frontier.proposals[index].kind.clone();
    frontier.proposals[index].status = "rejected".to_string();
    frontier.proposals[index].reviewed_by = Some(reviewer.to_string());
    frontier.proposals[index].reviewed_at = Some(decided_at.clone());
    frontier.proposals[index].decision_reason = Some(reason.to_string());
    push_signed_review_event(
        frontier,
        proposal_id,
        &proposal_kind,
        "rejected",
        None,
        reviewer,
        reason,
        &decided_at,
        signing_key,
    )?;
    Ok(())
}

/// Send a proposal back for revision, recording a signed
/// `review.revision_requested` event. Same accountability contract as
/// reject.
pub fn request_revision_in_frontier_signed(
    frontier: &mut Project,
    proposal_id: &str,
    reviewer: &str,
    reason: &str,
    signing_key: Option<&ed25519_dalek::SigningKey>,
    custody_verified: bool,
) -> Result<(), String> {
    validate_reviewer_identity(reviewer)?;
    if reason.trim().is_empty() {
        return Err("Decision reason must be non-empty".to_string());
    }
    enforce_reviewer_key_custody(frontier, reviewer, signing_key, custody_verified)?;
    let index = frontier
        .proposals
        .iter()
        .position(|proposal| proposal.id == proposal_id)
        .ok_or_else(|| format!("Proposal not found: {proposal_id}"))?;
    match frontier.proposals[index].status.as_str() {
        "pending_review" => {}
        "needs_revision" => {
            return Err(format!("Proposal {} already needs revision", proposal_id));
        }
        "rejected" => {
            return Err(format!("Proposal {} is already rejected", proposal_id));
        }
        "applied" => {
            return Err(format!("Proposal {} is already applied", proposal_id));
        }
        other => {
            return Err(format!("Unsupported proposal status '{}'", other));
        }
    }
    let decided_at = Utc::now().to_rfc3339();
    let proposal_kind = frontier.proposals[index].kind.clone();
    frontier.proposals[index].status = "needs_revision".to_string();
    frontier.proposals[index].reviewed_by = Some(reviewer.to_string());
    frontier.proposals[index].reviewed_at = Some(decided_at.clone());
    frontier.proposals[index].decision_reason = Some(reason.to_string());
    push_signed_review_event(
        frontier,
        proposal_id,
        &proposal_kind,
        "revision_requested",
        None,
        reviewer,
        reason,
        &decided_at,
        signing_key,
    )?;
    Ok(())
}

pub(crate) fn apply_proposal(
    frontier: &mut Project,
    proposal: &StateProposal,
    reviewer: &str,
    decision_reason: &str,
) -> Result<String, String> {
    // Phase L: retraction emits a fan of events — one for the source
    // and one `finding.dependency_invalidated` per dependent in BFS
    // order. apply_retract is responsible for pushing all of them in
    // sequence; this branch only assigns the primary event ID.
    if proposal.kind.as_str() == "finding.retract" {
        let events = apply_retract(frontier, proposal, reviewer, decision_reason)?;
        let primary_id = events
            .first()
            .map(|event| event.id.clone())
            .ok_or_else(|| "apply_retract returned no events".to_string())?;
        for event in events {
            frontier.events.push(event);
        }
        mark_proof_stale(
            frontier,
            format!("Applied proposal {} after latest proof export", proposal.id),
        );
        return Ok(primary_id);
    }
    // v0.55: confidence_revise can also fan out a cascade when the new
    // score crosses below the 0.5 propagation threshold. Same fan-out
    // pattern as retract.
    if proposal.kind.as_str() == "finding.confidence_revise" {
        let events = apply_confidence_revise(frontier, proposal, reviewer, decision_reason)?;
        let primary_id = events
            .first()
            .map(|event| event.id.clone())
            .ok_or_else(|| "apply_confidence_revise returned no events".to_string())?;
        for event in events {
            frontier.events.push(event);
        }
        mark_proof_stale(
            frontier,
            format!("Applied proposal {} after latest proof export", proposal.id),
        );
        return Ok(primary_id);
    }
    let event = match proposal.kind.as_str() {
        "finding.add" => apply_add(frontier, proposal, reviewer, decision_reason)?,
        "finding.review" => apply_review(frontier, proposal, reviewer, decision_reason)?,
        "research_trace.review" | "correction_return.review" => {
            apply_frontier_observation_review(proposal, reviewer, decision_reason)?
        }
        "finding.caveat" => apply_caveat(frontier, proposal, reviewer, decision_reason)?,
        "finding.note" => apply_note(frontier, proposal, reviewer, decision_reason)?,
        "finding.reject" => apply_reject(frontier, proposal, reviewer, decision_reason)?,
        "finding.supersede" => apply_supersede(frontier, proposal, reviewer, decision_reason)?,
        "artifact.assert" => apply_artifact_assert(frontier, proposal, reviewer, decision_reason)?,
        "verifier.attach" => apply_verifier_attach(frontier, proposal, reviewer, decision_reason)?,
        // v0.56: mechanical evidence-atom locator repair.
        "evidence_atom.locator_repair" => {
            apply_evidence_atom_locator_repair(frontier, proposal, reviewer, decision_reason)?
        }
        // v0.57: mechanical finding-level span repair.
        "finding.span_repair" => {
            apply_finding_span_repair(frontier, proposal, reviewer, decision_reason)?
        }
        other => return Err(format!("Unsupported proposal kind '{other}'")),
    };
    let event_id = event.id.clone();
    frontier.events.push(event);
    mark_proof_stale(
        frontier,
        format!("Applied proposal {} after latest proof export", proposal.id),
    );
    Ok(event_id)
}

fn apply_frontier_observation_review(
    proposal: &StateProposal,
    reviewer: &str,
    decision_reason: &str,
) -> Result<StateEvent, String> {
    match proposal.kind.as_str() {
        "research_trace.review" => validate_research_trace_review_payload(proposal)?,
        "correction_return.review" => validate_correction_return_review_payload(proposal)?,
        other => {
            return Err(format!(
                "Unsupported frontier observation proposal kind '{other}'"
            ));
        }
    }
    let mut event = StateEvent {
        schema: events::EVENT_SCHEMA.to_string(),
        id: String::new(),
        kind: events::EVENT_KIND_FRONTIER_OBSERVATION_REVIEWED.into(),
        target: proposal.target.clone(),
        actor: StateActor {
            id: reviewer.to_string(),
            r#type: "human".to_string(),
        },
        timestamp: Utc::now().to_rfc3339(),
        reason: proposal.reason.clone(),
        before_hash: NULL_HASH.to_string(),
        after_hash: NULL_HASH.to_string(),
        payload: json!({
            "proposal_id": proposal.id,
            "proposal_kind": proposal.kind,
            "status": "accepted",
            "decision_reason": decision_reason,
            "reviewed_payload": proposal.payload,
            "source_refs": proposal.source_refs,
        }),
        caveats: proposal.caveats.clone(),
        signature: None,
        schema_artifact_id: None,
    };
    events::validate_event_payload(event.kind.as_str(), &event.payload)?;
    event.id = events::compute_event_id(&event);
    Ok(event)
}

/// v0.14: `finding.supersede` — first-class flow for *changing a claim's text*.
///
/// Until v0.14 the only way to update a finding was to stack caveats/notes
/// on top, because the assertion text is part of the content address. The
/// substrate-correct path for a real correction is a *new* content-addressed
/// finding that explicitly supersedes the old one. This proposal kind:
///
/// 1. Validates the old finding exists and is not already superseded.
/// 2. Adds the new finding bundle (a fresh `vf_…` content address) to
///    `frontier.findings`.
/// 3. Auto-injects a `supersedes` link from the new finding's `links` to the
///    old finding's id (if not already present in the payload).
/// 4. Sets `flags.superseded = true` on the old finding.
/// 5. Emits a `finding.superseded` canonical event targeting the *old*
///    finding (since that's the state change). The new finding's existence
///    is recorded in the event payload as `new_finding_id`.
///
/// Both findings remain queryable; readers walk the supersedes chain via
/// the link or via the `flags.superseded` marker.
fn apply_supersede(
    frontier: &mut Project,
    proposal: &StateProposal,
    reviewer: &str,
    _decision_reason: &str,
) -> Result<StateEvent, String> {
    use crate::bundle::Link;

    let old_id = proposal.target.id.clone();
    let new_finding_value = proposal
        .payload
        .get("new_finding")
        .ok_or("finding.supersede proposal missing payload.new_finding")?
        .clone();
    let mut new_finding: FindingBundle = serde_json::from_value(new_finding_value)
        .map_err(|e| format!("Invalid finding.supersede payload.new_finding: {e}"))?;

    // Locate the old finding before mutating; capture before_hash for the event.
    let old_idx = find_finding_index(frontier, &old_id)?;
    if frontier.findings[old_idx].flags.superseded {
        return Err(format!(
            "Refusing to supersede already-superseded finding {old_id}"
        ));
    }
    if new_finding.id == old_id {
        return Err(
            "Refusing to supersede with a finding that has the same content address as the old finding (assertion / type / provenance_id are unchanged)".to_string(),
        );
    }
    if frontier
        .findings
        .iter()
        .any(|existing| existing.id == new_finding.id)
    {
        return Err(format!(
            "Refusing to add superseding finding with existing finding ID {}",
            new_finding.id
        ));
    }
    let before_hash = events::finding_hash(&frontier.findings[old_idx]);

    // Auto-inject the supersedes link if the caller didn't already include it.
    let already_links_old = new_finding
        .links
        .iter()
        .any(|l| l.target == old_id && l.link_type == "supersedes");
    if !already_links_old {
        new_finding.links.push(Link {
            target: old_id.clone(),
            link_type: "supersedes".to_string(),
            note: format!(
                "Supersedes {old_id} via finding.supersede proposal {}.",
                proposal.id
            ),
            inferred_by: "reviewer".to_string(),
            created_at: Utc::now().to_rfc3339(),
            mechanism: None,
        });
    }

    let new_finding_id = new_finding.id.clone();
    frontier.findings.push(new_finding);
    frontier.findings[old_idx].flags.superseded = true;
    let after_hash = events::finding_hash(&frontier.findings[old_idx]);

    Ok(events::new_finding_event(events::FindingEventInput {
        kind: "finding.superseded",
        finding_id: &old_id,
        actor_id: reviewer,
        actor_type: events::actor_kind(reviewer),
        reason: &proposal.reason,
        before_hash: &before_hash,
        after_hash: &after_hash,
        payload: json!({
            "proposal_id": proposal.id,
            "new_finding_id": new_finding_id,
        }),
        caveats: proposal.caveats.clone(),
        timestamp: None,
    }))
}

fn apply_add(
    frontier: &mut Project,
    proposal: &StateProposal,
    reviewer: &str,
    _decision_reason: &str,
) -> Result<StateEvent, String> {
    let finding_value = proposal
        .payload
        .get("finding")
        .ok_or("finding.add proposal missing payload.finding")?
        .clone();
    let finding: FindingBundle = serde_json::from_value(finding_value)
        .map_err(|e| format!("Invalid finding.add payload: {e}"))?;
    let finding_id = finding.id.clone();
    // Activity is not state: an accepted finding may not depend on an
    // activity-plane id (`vac_`/`vrr_`). A search/trace/retrieval is recorded in
    // the activity plane and referenced by content address, never admitted as
    // accepted lineage (the `activity::assert_not_in_lineage` law, at the write).
    if let Some(l) = finding
        .links
        .iter()
        .find(|l| crate::activity::is_activity_id(&l.target))
    {
        return Err(format!(
            "finding.add refused: link target `{}` is an activity-plane id; activity is non-authoritative and cannot enter lineage",
            l.target
        ));
    }
    if frontier
        .findings
        .iter()
        .any(|existing| existing.id == finding_id)
    {
        return Err(format!(
            "Refusing to add duplicate finding with existing finding ID {finding_id}"
        ));
    }
    // Prior-art collision: an EXACT duplicate of an accepted finding's
    // statement is refused unless the proposal names what it supersedes
    // (the Sakana rediscovery failure mode, made mechanical).
    {
        let new_hash = crate::canonical::normalized_statement_hash(&finding.assertion.text);
        let declares_supersession = proposal.payload.get("supersedes").is_some()
            || proposal.payload.get("improves_on").is_some();
        if !declares_supersession
            && let Some(dup) = frontier.findings.iter().find(|f| {
                crate::canonical::normalized_statement_hash(&f.assertion.text) == new_hash
            })
        {
            return Err(format!(
                "prior-art collision: statement duplicates accepted finding {} — name it via payload.supersedes/improves_on or change the claim",
                dup.id
            ));
        }
    }
    frontier.findings.push(finding);
    let after_hash = events::finding_hash_by_id(frontier, &finding_id);
    Ok(events::new_finding_event(events::FindingEventInput {
        kind: "finding.asserted",
        finding_id: &finding_id,
        actor_id: reviewer,
        actor_type: events::actor_kind(reviewer),
        reason: &proposal.reason,
        before_hash: NULL_HASH,
        after_hash: &after_hash,
        payload: json!({
            "proposal_id": proposal.id,
        }),
        caveats: proposal.caveats.clone(),
        timestamp: None,
    }))
}

fn apply_artifact_assert(
    frontier: &mut Project,
    proposal: &StateProposal,
    reviewer: &str,
    _decision_reason: &str,
) -> Result<StateEvent, String> {
    let artifact_value = proposal
        .payload
        .get("artifact")
        .ok_or("artifact.assert proposal missing payload.artifact")?
        .clone();
    let artifact: Artifact = serde_json::from_value(artifact_value)
        .map_err(|e| format!("Invalid artifact.assert payload: {e}"))?;
    let artifact_id = artifact.id.clone();
    if frontier
        .artifacts
        .iter()
        .any(|existing| existing.id == artifact_id)
    {
        return Err(format!(
            "Refusing to add duplicate artifact with existing id {artifact_id}"
        ));
    }
    frontier.artifacts.push(artifact.clone());
    let mut event = StateEvent {
        schema: events::EVENT_SCHEMA.to_string(),
        id: String::new(),
        kind: events::EVENT_KIND_ARTIFACT_ASSERTED.into(),
        target: StateTarget {
            r#type: "artifact".to_string(),
            id: artifact_id,
        },
        actor: StateActor {
            id: reviewer.to_string(),
            r#type: if reviewer.starts_with("agent:") {
                "agent"
            } else {
                "human"
            }
            .to_string(),
        },
        timestamp: Utc::now().to_rfc3339(),
        reason: proposal.reason.clone(),
        before_hash: NULL_HASH.to_string(),
        after_hash: NULL_HASH.to_string(),
        payload: json!({
            "proposal_id": proposal.id,
            "artifact": artifact,
        }),
        caveats: proposal.caveats.clone(),
        signature: None,
        schema_artifact_id: None,
    };
    events::validate_event_payload(event.kind.as_str(), &event.payload)?;
    event.id = events::compute_event_id(&event);
    Ok(event)
}

/// Bind a verifier attachment to a finding (`target.type == "finding"`). Appends
/// to the sidecar `verifier_attachments` collection and emits
/// `verifier_attachment.added`. Per-finding trust-gate status is derived on read.
fn apply_verifier_attach(
    frontier: &mut Project,
    proposal: &StateProposal,
    reviewer: &str,
    _decision_reason: &str,
) -> Result<StateEvent, String> {
    if proposal.target.r#type != "finding" {
        return Err(format!(
            "verifier.attach target.type must be 'finding', got '{}'",
            proposal.target.r#type
        ));
    }
    let value = proposal
        .payload
        .get("attachment")
        .ok_or("verifier.attach proposal missing payload.attachment")?
        .clone();
    let att: crate::verifier_attachment::VerifierAttachment = serde_json::from_value(value)
        .map_err(|e| format!("Invalid verifier.attach payload: {e}"))?;
    att.verify()
        .map_err(|e| format!("verifier.attach attachment malformed: {e}"))?;
    if att.target != proposal.target.id {
        return Err(format!(
            "verifier.attach attachment.target {} does not match proposal target {}",
            att.target, proposal.target.id
        ));
    }
    // Activity is not state: a verifier gate may not attach to, or claim
    // independence from, an activity-plane id (`vac_`/`vrr_`).
    if crate::activity::is_activity_id(&att.target) {
        return Err(format!(
            "verifier.attach refused: target `{}` is an activity-plane id (activity is not lineage)",
            att.target
        ));
    }
    if let Some(indep) = att
        .independent_of
        .iter()
        .find(|i| crate::activity::is_activity_id(i))
    {
        return Err(format!(
            "verifier.attach refused: independent_of `{indep}` is an activity-plane id"
        ));
    }
    if !frontier.verifier_attachments.iter().any(|a| a.id == att.id) {
        frontier.verifier_attachments.push(att.clone());
    }
    Ok(events::new_finding_event(events::FindingEventInput {
        kind: events::EVENT_KIND_VERIFIER_ATTACHMENT_ADDED,
        finding_id: &proposal.target.id,
        actor_id: reviewer,
        actor_type: events::actor_kind(reviewer),
        reason: &proposal.reason,
        before_hash: NULL_HASH,
        after_hash: NULL_HASH,
        payload: json!({ "proposal_id": proposal.id, "attachment": att }),
        caveats: proposal.caveats.clone(),
        timestamp: None,
    }))
}

fn apply_review(
    frontier: &mut Project,
    proposal: &StateProposal,
    reviewer: &str,
    _decision_reason: &str,
) -> Result<StateEvent, String> {
    let finding_id = proposal.target.id.as_str();
    let idx = find_finding_index(frontier, finding_id)?;
    let before_hash = events::finding_hash(&frontier.findings[idx]);
    let status = proposal
        .payload
        .get("status")
        .and_then(Value::as_str)
        .ok_or("finding.review proposal missing payload.status")?;
    use crate::bundle::ReviewState;
    let new_state = match status {
        "accepted" | "approved" => ReviewState::Accepted,
        "contested" => ReviewState::Contested,
        "needs_revision" => ReviewState::NeedsRevision,
        "rejected" => ReviewState::Rejected,
        other => return Err(format!("Unknown review proposal status '{other}'")),
    };
    frontier.findings[idx].flags.contested = new_state.implies_contested();
    frontier.findings[idx].flags.review_state = Some(new_state);
    let after_hash = events::finding_hash(&frontier.findings[idx]);
    Ok(events::new_finding_event(events::FindingEventInput {
        kind: "finding.reviewed",
        finding_id,
        actor_id: reviewer,
        actor_type: events::actor_kind(reviewer),
        reason: &proposal.reason,
        before_hash: &before_hash,
        after_hash: &after_hash,
        payload: json!({
            "status": status,
            "proposal_id": proposal.id,
        }),
        caveats: proposal.caveats.clone(),
        timestamp: None,
    }))
}

fn apply_caveat(
    frontier: &mut Project,
    proposal: &StateProposal,
    reviewer: &str,
    _decision_reason: &str,
) -> Result<StateEvent, String> {
    let finding_id = proposal.target.id.as_str();
    let idx = find_finding_index(frontier, finding_id)?;
    let before_hash = events::finding_hash(&frontier.findings[idx]);
    let now = Utc::now().to_rfc3339();
    let text = proposal
        .payload
        .get("text")
        .and_then(Value::as_str)
        .ok_or("finding.caveat proposal missing payload.text")?;
    let provenance = extract_annotation_provenance(&proposal.payload);
    let annotation_id = annotation_id(finding_id, text, reviewer, &now);
    frontier.findings[idx].annotations.push(Annotation {
        id: annotation_id.clone(),
        text: text.to_string(),
        author: reviewer.to_string(),
        timestamp: now.clone(),
        provenance: provenance.clone(),
    });
    let after_hash = events::finding_hash(&frontier.findings[idx]);
    let mut payload = json!({
        "annotation_id": annotation_id,
        "text": text,
        "proposal_id": proposal.id,
    });
    if let Some(prov) = &provenance {
        payload["provenance"] = serde_json::to_value(prov).unwrap_or(Value::Null);
    }
    Ok(events::new_finding_event(events::FindingEventInput {
        kind: "finding.caveated",
        finding_id,
        actor_id: reviewer,
        actor_type: events::actor_kind(reviewer),
        reason: text,
        before_hash: &before_hash,
        after_hash: &after_hash,
        payload,
        caveats: proposal.caveats.clone(),
        timestamp: Some(&now),
    }))
}

fn apply_note(
    frontier: &mut Project,
    proposal: &StateProposal,
    reviewer: &str,
    _decision_reason: &str,
) -> Result<StateEvent, String> {
    let finding_id = proposal.target.id.as_str();
    let idx = find_finding_index(frontier, finding_id)?;
    let before_hash = events::finding_hash(&frontier.findings[idx]);
    let now = Utc::now().to_rfc3339();
    let text = proposal
        .payload
        .get("text")
        .and_then(Value::as_str)
        .ok_or("finding.note proposal missing payload.text")?;
    let provenance = extract_annotation_provenance(&proposal.payload);
    let annotation_id = annotation_id(finding_id, text, reviewer, &now);
    frontier.findings[idx].annotations.push(Annotation {
        id: annotation_id.clone(),
        text: text.to_string(),
        author: reviewer.to_string(),
        timestamp: now.clone(),
        provenance: provenance.clone(),
    });
    let after_hash = events::finding_hash(&frontier.findings[idx]);
    let mut payload = json!({
        "annotation_id": annotation_id,
        "text": text,
        "proposal_id": proposal.id,
    });
    if let Some(prov) = &provenance {
        payload["provenance"] = serde_json::to_value(prov).unwrap_or(Value::Null);
    }
    Ok(events::new_finding_event(events::FindingEventInput {
        kind: "finding.noted",
        finding_id,
        actor_id: reviewer,
        actor_type: events::actor_kind(reviewer),
        reason: text,
        before_hash: &before_hash,
        after_hash: &after_hash,
        payload,
        caveats: proposal.caveats.clone(),
        timestamp: Some(&now),
    }))
}

/// v0.57: Apply a `finding.span_repair` proposal. Appends a
/// `{section, text}` span to `state.findings[i].evidence.evidence_spans`
/// and emits one signed `finding.span_repaired` event.
fn apply_finding_span_repair(
    frontier: &mut Project,
    proposal: &StateProposal,
    reviewer: &str,
    _decision_reason: &str,
) -> Result<StateEvent, String> {
    let finding_id = proposal.target.id.as_str();
    let section = proposal
        .payload
        .get("section")
        .and_then(Value::as_str)
        .ok_or("finding.span_repair proposal missing payload.section")?
        .to_string();
    let text = proposal
        .payload
        .get("text")
        .and_then(Value::as_str)
        .ok_or("finding.span_repair proposal missing payload.text")?
        .to_string();
    let idx = find_finding_index(frontier, finding_id)?;
    let already_present = frontier.findings[idx]
        .evidence
        .evidence_spans
        .iter()
        .any(|existing| {
            existing.get("section").and_then(Value::as_str) == Some(section.as_str())
                && existing.get("text").and_then(Value::as_str) == Some(text.as_str())
        });
    if already_present {
        return Err(format!(
            "finding {finding_id} already carries an identical (section, text) span"
        ));
    }
    let before_hash = events::finding_hash(&frontier.findings[idx]);
    let span_value = json!({"section": section, "text": text});
    frontier.findings[idx]
        .evidence
        .evidence_spans
        .push(span_value);
    let after_hash = events::finding_hash(&frontier.findings[idx]);
    let payload = json!({
        "proposal_id": proposal.id,
        "section": section,
        "text": text,
    });
    Ok(events::new_finding_event(events::FindingEventInput {
        kind: "finding.span_repaired",
        finding_id,
        actor_id: reviewer,
        actor_type: events::actor_kind(reviewer),
        reason: &proposal.reason,
        before_hash: &before_hash,
        after_hash: &after_hash,
        payload,
        caveats: proposal.caveats.clone(),
        timestamp: None,
    }))
}

/// v0.56: Apply an `evidence_atom.locator_repair` proposal. Sets
/// `locator` on the named evidence atom, removes the
/// "missing evidence locator" caveat, and emits one signed
/// `evidence_atom.locator_repaired` canonical event. The before/after
/// hashes are over the canonical bytes of the named atom only, so a
/// chain validator can confirm the exact atom changed and exactly the
/// named repair was applied.
fn apply_evidence_atom_locator_repair(
    frontier: &mut Project,
    proposal: &StateProposal,
    reviewer: &str,
    _decision_reason: &str,
) -> Result<StateEvent, String> {
    let atom_id = proposal.target.id.as_str();
    let locator = proposal
        .payload
        .get("locator")
        .and_then(Value::as_str)
        .ok_or("evidence_atom.locator_repair proposal missing payload.locator")?
        .to_string();
    let source_id = proposal
        .payload
        .get("source_id")
        .and_then(Value::as_str)
        .ok_or("evidence_atom.locator_repair proposal missing payload.source_id")?
        .to_string();

    let idx = frontier
        .evidence_atoms
        .iter()
        .position(|atom| atom.id == atom_id)
        .ok_or_else(|| format!("evidence_atom.locator_repair targets unknown atom {atom_id}"))?;
    if frontier.evidence_atoms[idx].source_id != source_id {
        return Err(format!(
            "evidence_atom.locator_repair payload.source_id '{source_id}' does not match atom.source_id '{}'",
            frontier.evidence_atoms[idx].source_id
        ));
    }
    if let Some(existing) = &frontier.evidence_atoms[idx].locator {
        if existing == &locator {
            return Err(format!(
                "evidence_atom {atom_id} already carries locator '{existing}'"
            ));
        }
        return Err(format!(
            "evidence_atom {atom_id} already carries locator '{existing}'; refusing to overwrite with '{locator}'"
        ));
    }

    let before_hash = events::evidence_atom_hash(&frontier.evidence_atoms[idx]);
    frontier.evidence_atoms[idx].locator = Some(locator.clone());
    frontier.evidence_atoms[idx]
        .caveats
        .retain(|c| c != "missing evidence locator");
    let after_hash = events::evidence_atom_hash(&frontier.evidence_atoms[idx]);

    let payload = json!({
        "proposal_id": proposal.id,
        "locator": locator,
        "source_id": source_id,
    });

    Ok(events::new_evidence_atom_locator_repair_event(
        atom_id,
        reviewer,
        "human",
        &proposal.reason,
        &before_hash,
        &after_hash,
        payload,
        proposal.caveats.clone(),
    ))
}

/// Phase β (v0.6): pull optional structured provenance off a note/caveat
/// proposal payload. The propose-* tools accept it; the validator gates
/// it; this helper threads it through to the materialized annotation
/// and the canonical event payload.
fn extract_annotation_provenance(payload: &Value) -> Option<crate::bundle::ProvenanceRef> {
    let prov = payload.get("provenance")?;
    let parsed: crate::bundle::ProvenanceRef = serde_json::from_value(prov.clone()).ok()?;
    if parsed.has_identifier() {
        Some(parsed)
    } else {
        None
    }
}

fn apply_confidence_revise(
    frontier: &mut Project,
    proposal: &StateProposal,
    reviewer: &str,
    _decision_reason: &str,
) -> Result<Vec<StateEvent>, String> {
    let finding_id = proposal.target.id.as_str();
    let idx = find_finding_index(frontier, finding_id)?;
    let now = Utc::now().to_rfc3339();
    let previous = frontier.findings[idx].confidence.score;
    let new_score = proposal
        .payload
        .get("confidence")
        .and_then(Value::as_f64)
        .ok_or("finding.confidence_revise proposal missing payload.confidence")?;

    // v0.55: when the revised confidence crosses the propagation threshold
    // (previous >= 0.5, new < 0.5), invoke the same cascade pattern that
    // `apply_retract` uses — emit `finding.dependency_invalidated` events for
    // each downstream supports/depends finding at depth ≤ MAX_DEPTH. Pre-v0.55
    // this path silently mutated confidence without firing the cascade, which
    // forced callers to chase a separate `vela propagate --reduce-confidence`
    // command for the substrate's signature feature.
    let cascade_threshold_crossed = previous >= 0.5 && new_score < 0.5;

    let pre_cascade_hashes: std::collections::HashMap<String, String> = if cascade_threshold_crossed
    {
        frontier
            .findings
            .iter()
            .map(|finding| (finding.id.clone(), events::finding_hash(finding)))
            .collect()
    } else {
        std::collections::HashMap::new()
    };

    let before_hash = events::finding_hash(&frontier.findings[idx]);

    // Apply the local mutation first so propagate_correction sees the new
    // confidence on the source finding.
    frontier.findings[idx].confidence.score = new_score;
    frontier.findings[idx].confidence.basis = format!(
        "expert revision from {:.3} to {:.3}: {}",
        previous, new_score, proposal.reason
    );
    frontier.findings[idx].confidence.method = ConfidenceMethod::ExpertJudgment;
    frontier.findings[idx].updated = Some(now.clone());

    let cascade = if cascade_threshold_crossed {
        Some(propagate::propagate_correction(
            frontier,
            finding_id,
            PropagationAction::ConfidenceReduced { new_score },
        ))
    } else {
        None
    };

    let after_hash = events::finding_hash(&frontier.findings[idx]);

    let source_event = events::new_finding_event(events::FindingEventInput {
        kind: "finding.confidence_revised",
        finding_id,
        actor_id: reviewer,
        actor_type: events::actor_kind(reviewer),
        reason: &proposal.reason,
        before_hash: &before_hash,
        after_hash: &after_hash,
        payload: json!({
            "previous_score": previous,
            "new_score": new_score,
            "updated_at": now,
            "proposal_id": proposal.id,
            "cascade_fired": cascade_threshold_crossed,
            "affected": cascade.as_ref().map(|c| c.affected).unwrap_or(0),
        }),
        caveats: proposal.caveats.clone(),
        timestamp: Some(&now),
    });

    let source_event_id = source_event.id.clone();
    let mut emitted = vec![source_event];

    if let Some(cascade) = cascade {
        // Mirror apply_retract's per-dependent dependency_invalidated emission:
        // each affected dep at each depth gets a canonical event with the
        // before/after hash boundary so chain validation works downstream.
        for (depth_idx, level) in cascade.cascade.iter().enumerate() {
            let depth = (depth_idx as u32) + 1;
            for dep_id in level {
                let before = pre_cascade_hashes
                    .get(dep_id)
                    .cloned()
                    .unwrap_or_else(|| events::NULL_HASH.to_string());
                let after = events::finding_hash_by_id(frontier, dep_id);
                emitted.push(events::new_finding_event(events::FindingEventInput {
                    kind: "finding.dependency_invalidated",
                    finding_id: dep_id,
                    actor_id: reviewer,
                    actor_type: events::actor_kind(reviewer),
                    reason: &format!(
                        "Upstream finding {finding_id} confidence reduced to {new_score:.2}; cascade depth {depth}"
                    ),
                    before_hash: &before,
                    after_hash: &after,
                    payload: json!({
                        "upstream_finding_id": finding_id,
                        "upstream_event_id": source_event_id,
                        "depth": depth,
                        "new_score": new_score,
                        "previous_score": previous,
                        "proposal_id": proposal.id,
                    }),
                    caveats: vec![],
                    timestamp: None,
                }));
            }
        }
    }

    Ok(emitted)
}

fn apply_reject(
    frontier: &mut Project,
    proposal: &StateProposal,
    reviewer: &str,
    _decision_reason: &str,
) -> Result<StateEvent, String> {
    let finding_id = proposal.target.id.as_str();
    let idx = find_finding_index(frontier, finding_id)?;
    let before_hash = events::finding_hash(&frontier.findings[idx]);
    frontier.findings[idx].flags.contested = true;
    let after_hash = events::finding_hash(&frontier.findings[idx]);
    Ok(events::new_finding_event(events::FindingEventInput {
        kind: "finding.rejected",
        finding_id,
        actor_id: reviewer,
        actor_type: events::actor_kind(reviewer),
        reason: &proposal.reason,
        before_hash: &before_hash,
        after_hash: &after_hash,
        payload: json!({
            "proposal_id": proposal.id,
            "status": "rejected",
        }),
        caveats: proposal.caveats.clone(),
        timestamp: None,
    }))
}

fn apply_retract(
    frontier: &mut Project,
    proposal: &StateProposal,
    reviewer: &str,
    _decision_reason: &str,
) -> Result<Vec<StateEvent>, String> {
    let finding_id = proposal.target.id.as_str();
    let idx = find_finding_index(frontier, finding_id)?;
    if frontier.findings[idx].flags.retracted {
        return Err(format!("Finding {finding_id} is already retracted"));
    }
    // Phase L: capture every finding's pre-cascade hash so each emitted
    // `finding.dependency_invalidated` event can name a real before_hash
    // that matches whatever event last touched that dep.
    let pre_cascade_hashes: std::collections::HashMap<String, String> = frontier
        .findings
        .iter()
        .map(|finding| (finding.id.clone(), events::finding_hash(finding)))
        .collect();

    let before_hash = events::finding_hash(&frontier.findings[idx]);
    let cascade =
        propagate::propagate_correction(frontier, finding_id, PropagationAction::Retracted);
    let after_hash = events::finding_hash_by_id(frontier, finding_id);

    let source_event = events::new_finding_event(events::FindingEventInput {
        kind: "finding.retracted",
        finding_id,
        actor_id: reviewer,
        actor_type: events::actor_kind(reviewer),
        reason: &proposal.reason,
        before_hash: &before_hash,
        after_hash: &after_hash,
        payload: json!({
            "proposal_id": proposal.id,
            "affected": cascade.affected,
            "cascade": cascade.cascade,
        }),
        caveats: vec!["Retraction impact is simulated over declared dependency links.".to_string()],
        timestamp: None,
    });
    let source_event_id = source_event.id.clone();

    let mut emitted = vec![source_event];

    // Phase L: emit one canonical `finding.dependency_invalidated`
    // event per affected dependent, in BFS depth order. Each event
    // carries the before/after hash boundary for that specific dep so
    // chain validation works downstream.
    for (depth_idx, level) in cascade.cascade.iter().enumerate() {
        let depth = (depth_idx as u32) + 1;
        for dep_id in level {
            let before = pre_cascade_hashes
                .get(dep_id)
                .cloned()
                .unwrap_or_else(|| events::NULL_HASH.to_string());
            let after = events::finding_hash_by_id(frontier, dep_id);
            emitted.push(events::new_finding_event(events::FindingEventInput {
                kind: "finding.dependency_invalidated",
                finding_id: dep_id,
                actor_id: reviewer,
                actor_type: events::actor_kind(reviewer),
                reason: &format!("Upstream finding {finding_id} retracted; cascade depth {depth}"),
                before_hash: &before,
                after_hash: &after,
                payload: json!({
                    "upstream_finding_id": finding_id,
                    "upstream_event_id": source_event_id,
                    "depth": depth,
                    "proposal_id": proposal.id,
                }),
                caveats: vec![],
                timestamp: None,
            }));
        }
    }

    Ok(emitted)
}

fn find_finding_index(frontier: &Project, finding_id: &str) -> Result<usize, String> {
    frontier
        .findings
        .iter()
        .position(|finding| finding.id == finding_id)
        .ok_or_else(|| format!("Finding not found: {finding_id}"))
}

fn annotation_id(finding_id: &str, text: &str, author: &str, timestamp: &str) -> String {
    let hash = Sha256::digest(format!("{finding_id}|{text}|{author}|{timestamp}").as_bytes());
    format!("ann_{}", &hex::encode(hash)[..16])
}

pub fn manifest_hash(path: &Path) -> Result<String, String> {
    let bytes = std::fs::read(path)
        .map_err(|e| format!("Failed to read manifest '{}': {e}", path.display()))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

pub fn repo_proposals_dir(root: &Path) -> PathBuf {
    root.join(".vela/proposals")
}

// ── Review-decision projection + parity (status derived from the log) ──
//
// A proposal's decision state is no longer a free-floating mutable field:
// it is a PROJECTION of the signed `review.*` events (and, for accepts,
// the domain event the accept produced). The stored `status` is a cache
// of that projection. `verify_proposal_decision_parity` is the gate that
// pins the cache to the log — if someone hand-edits a `status` field, or a
// decision exists with no signed event behind it, parity fails. That is
// the tamper-evidence the mutable field never had.

/// A decision reconstructed from the event log for one proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedDecision {
    /// `applied` | `rejected` | `needs_revision`.
    pub status: String,
    /// The reviewer that made the latest decision.
    pub reviewer: String,
    /// The latest decision event's timestamp.
    pub decided_at: String,
    /// The `review.*` event id that carried the decision, when one exists.
    /// `None` for an accept whose only trace is its domain event (the
    /// pre-`review.accepted` accept path; see module note).
    pub review_event_id: Option<String>,
    /// True when the backing review event is a legacy (unsigned) backfill.
    pub legacy: bool,
}

/// Reduce the event log to the current decision for a single proposal.
///
/// Folds, in timestamp order:
///   - `review.rejected` → rejected
///   - `review.revision_requested` → needs_revision
///   - `review.accepted` → applied
///   - any domain event produced by an accept of this proposal
///     (matched via the proposal's `applied_event_id`) → applied
///
/// The latest decision wins. Returns `None` when no decision event exists
/// (the proposal is pending).
pub fn proposal_status_from_log(
    frontier: &Project,
    proposal_id: &str,
    applied_event_id: Option<&str>,
) -> Option<DerivedDecision> {
    let mut decisions: Vec<DerivedDecision> = Vec::new();
    for event in &frontier.events {
        let is_review_for_this = event.target.r#type == "proposal"
            && event.target.id == proposal_id
            && matches!(
                event.kind.as_str(),
                events::EVENT_KIND_REVIEW_ACCEPTED
                    | events::EVENT_KIND_REVIEW_REJECTED
                    | events::EVENT_KIND_REVIEW_REVISION_REQUESTED
            );
        if is_review_for_this {
            let status = match event.kind.as_str() {
                events::EVENT_KIND_REVIEW_ACCEPTED => "applied",
                events::EVENT_KIND_REVIEW_REJECTED => "rejected",
                _ => "needs_revision",
            };
            let legacy = event
                .payload
                .get("legacy_backfill")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            decisions.push(DerivedDecision {
                status: status.to_string(),
                reviewer: event.actor.id.clone(),
                decided_at: event.timestamp.clone(),
                review_event_id: Some(event.id.clone()),
                legacy,
            });
            continue;
        }
        // An accept's domain event is its decision trace when no explicit
        // review.accepted exists (the historical accept path).
        if let Some(applied) = applied_event_id
            && event.id == applied
        {
            decisions.push(DerivedDecision {
                status: "applied".to_string(),
                reviewer: event.actor.id.clone(),
                decided_at: event.timestamp.clone(),
                review_event_id: None,
                legacy: false,
            });
        }
    }
    decisions.sort_by(|a, b| a.decided_at.cmp(&b.decided_at));
    decisions.pop()
}

/// Verify that every proposal's stored decision state is backed by the
/// event log, and vice versa. Returns a list of human-readable conflicts
/// (empty == parity holds). This is the invariant the conformance gate
/// runs: it makes the mutable `status` field a verifiable projection
/// rather than an unconstrained side-table.
///
/// Checks, per proposal:
///   - a decided status (`applied` / `rejected` / `needs_revision`) MUST
///     have a backing event in the log (a `review.*` event, or for
///     `applied` the referenced domain event);
///   - the stored status MUST equal the status derived from the log;
///   - `pending_review` MUST NOT have a decision event.
/// And globally:
///   - every `review.*` event MUST reference a proposal that exists.
pub fn verify_proposal_decision_parity(frontier: &Project) -> Vec<String> {
    let mut conflicts = Vec::new();
    let proposal_ids: BTreeSet<&str> = frontier.proposals.iter().map(|p| p.id.as_str()).collect();

    for proposal in &frontier.proposals {
        let derived =
            proposal_status_from_log(frontier, &proposal.id, proposal.applied_event_id.as_deref());
        match proposal.status.as_str() {
            "pending_review" => {
                if let Some(d) = derived {
                    conflicts.push(format!(
                        "proposal {} is stored pending_review but the log carries a {} decision ({})",
                        proposal.id,
                        d.status,
                        d.review_event_id.as_deref().unwrap_or("domain event")
                    ));
                }
            }
            "accepted" => {
                // Transient in-memory state only; never persisted.
                conflicts.push(format!(
                    "proposal {} is stored in transient 'accepted' state (should be 'applied')",
                    proposal.id
                ));
            }
            stored @ ("applied" | "rejected" | "needs_revision") => match derived {
                None => conflicts.push(format!(
                    "proposal {} is stored '{}' but NO decision event backs it in the log \
                     — a decision with no signed, replayable record (the silent-drop vector)",
                    proposal.id, stored
                )),
                Some(d) if d.status != stored => conflicts.push(format!(
                    "proposal {} is stored '{}' but the log's latest decision is '{}'",
                    proposal.id, stored, d.status
                )),
                Some(_) => {}
            },
            other => conflicts.push(format!(
                "proposal {} has unknown status '{}'",
                proposal.id, other
            )),
        }
    }

    for event in &frontier.events {
        if matches!(
            event.kind.as_str(),
            events::EVENT_KIND_REVIEW_ACCEPTED
                | events::EVENT_KIND_REVIEW_REJECTED
                | events::EVENT_KIND_REVIEW_REVISION_REQUESTED
        ) && !proposal_ids.contains(event.target.id.as_str())
        {
            conflicts.push(format!(
                "review event {} targets proposal {} which does not exist in the frontier",
                event.id, event.target.id
            ));
        }
    }

    conflicts
}

/// Backfill signed-review history for a frontier whose decisions predate
/// `review.*` events. For every proposal that is already `rejected` or
/// `needs_revision` but has no backing review event, synthesize an
/// UNSIGNED legacy event (`legacy_backfill: true`) so parity holds and the
/// decision is at least replayable. Legacy events are honest about
/// provenance: they are unsigned because no signature was ever produced
/// for these pre-feature decisions, and `legacy_backfill` exempts them
/// from the strict "decided proposals must be signed" check.
///
/// `applied` proposals are NOT backfilled: their accept already produced a
/// domain event in the log, which `proposal_status_from_log` recognizes as
/// the decision trace. Returns the number of events synthesized.
pub fn backfill_legacy_review_events(frontier: &mut Project) -> Result<usize, String> {
    // Collect the work first (immutable borrow), then mutate.
    let mut to_add: Vec<(String, String, String, String, String)> = Vec::new();
    for proposal in &frontier.proposals {
        let verdict = match proposal.status.as_str() {
            "rejected" => "rejected",
            "needs_revision" => "revision_requested",
            _ => continue,
        };
        let already = proposal_status_from_log(frontier, &proposal.id, None).is_some();
        if already {
            continue;
        }
        let reviewer = proposal
            .reviewed_by
            .clone()
            .unwrap_or_else(|| "reviewer:unknown".to_string());
        let decided_at = proposal
            .reviewed_at
            .clone()
            .unwrap_or_else(|| proposal.created_at.clone());
        let reason = proposal
            .decision_reason
            .clone()
            .filter(|r| !r.trim().is_empty())
            .unwrap_or_else(|| "legacy decision (backfilled; reason not recorded)".to_string());
        to_add.push((
            proposal.id.clone(),
            proposal.kind.clone(),
            verdict.to_string(),
            reviewer,
            format!("{decided_at}\u{0}{reason}"),
        ));
    }
    let count = to_add.len();
    for (proposal_id, proposal_kind, verdict, reviewer, packed) in to_add {
        let (decided_at, reason) = packed.split_once('\u{0}').unwrap_or((&packed, ""));
        let event = events::new_review_decision_event(
            &proposal_id,
            &proposal_kind,
            &verdict,
            None,
            &reviewer,
            reason,
            Some(decided_at),
            true, // legacy_backfill
        )?;
        frontier.events.push(event);
    }
    if count > 0 {
        mark_proof_stale(
            frontier,
            format!("Backfilled {count} legacy review events after latest proof export"),
        );
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::{
        Assertion, Conditions, Confidence, ConfidenceKind, ConfidenceMethod, Entity, Evidence,
        Extraction, Flags, Provenance,
    };
    use crate::project;
    use tempfile::TempDir;

    fn finding(id: &str) -> FindingBundle {
        FindingBundle {
            id: id.to_string(),
            version: 1,
            previous_version: None,
            assertion: Assertion {
                text: format!("Test finding {id}"),
                assertion_type: "mechanism".to_string(),
                entities: vec![Entity {
                    name: "LRP1".to_string(),
                    entity_type: "protein".to_string(),
                    identifiers: serde_json::Map::new(),
                    canonical_id: None,
                    candidates: Vec::new(),
                    aliases: Vec::new(),
                    resolution_provenance: None,
                    resolution_confidence: 1.0,
                    resolution_method: None,
                    species_context: None,
                    needs_review: false,
                }],
                relation: None,
                direction: None,
                causal_claim: None,
                causal_evidence_grade: None,
            },
            evidence: Evidence {
                evidence_type: "experimental".to_string(),
                model_system: String::new(),
                method: "manual".to_string(),
                replicated: false,
                replication_count: None,
                evidence_spans: Vec::new(),
            },
            conditions: Conditions {
                text: "mouse".to_string(),
                duration: None,
            },
            confidence: Confidence {
                kind: ConfidenceKind::FrontierEpistemic,
                score: 0.7,
                basis: "test".to_string(),
                method: ConfidenceMethod::ExpertJudgment,
                components: None,
                extraction_confidence: 1.0,
            },
            provenance: Provenance {
                source_type: "published_paper".to_string(),
                doi: None,
                url: None,
                title: "Test".to_string(),
                authors: Vec::new(),
                year: Some(2024),
                license: None,
                publisher: None,
                funders: Vec::new(),
                extraction: Extraction::default(),
                review: None,
            },
            flags: Flags {
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
            links: Vec::new(),
            annotations: Vec::new(),
            attachments: Vec::new(),
            created: "2026-04-23T00:00:00Z".to_string(),
            updated: None,

            access_tier: crate::access_tier::AccessTier::Public,
        }
    }

    #[test]
    fn pending_review_proposal_does_not_mutate_frontier() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("frontier.json");
        let frontier = project::assemble("test", vec![finding("vf_test")], 0, 0, "test");
        repo::save_to_path(&path, &frontier).unwrap();
        let proposal = new_proposal(
            "finding.review",
            StateTarget {
                r#type: "finding".to_string(),
                id: "vf_test".to_string(),
            },
            "reviewer:test",
            "human",
            "Mouse-only evidence",
            json!({"status": "contested"}),
            Vec::new(),
            Vec::new(),
        );
        create_or_apply(&path, proposal, false).unwrap();
        let loaded = repo::load_from_path(&path).unwrap();
        assert_eq!(loaded.events.len(), 1); // genesis only (proposal pending)
        assert_eq!(loaded.proposals.len(), 1);
        assert!(!loaded.findings[0].flags.contested);
    }

    #[test]
    fn applied_proposal_emits_event_and_stales_proof() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("frontier.json");
        let mut frontier = project::assemble("test", vec![finding("vf_test")], 0, 0, "test");
        record_proof_export(
            &mut frontier,
            ProofPacketRecord {
                generated_at: "2026-04-23T00:00:00Z".to_string(),
                snapshot_hash: "a".repeat(64),
                event_log_hash: "b".repeat(64),
                packet_manifest_hash: "c".repeat(64),
            },
        );
        repo::save_to_path(&path, &frontier).unwrap();
        let proposal = new_proposal(
            "finding.review",
            StateTarget {
                r#type: "finding".to_string(),
                id: "vf_test".to_string(),
            },
            "reviewer:test",
            "human",
            "Mouse-only evidence",
            json!({"status": "contested"}),
            Vec::new(),
            Vec::new(),
        );
        create_or_apply(&path, proposal, true).unwrap();
        let loaded = repo::load_from_path(&path).unwrap();
        assert_eq!(loaded.events.len(), 2); // genesis + applied
        assert!(loaded.findings[0].flags.contested);
        assert_eq!(loaded.proposals[0].status, "applied");
        assert_eq!(loaded.proof_state.latest_packet.status, "stale");
    }

    // ── v0.339: bounded trusted-reviewer-agent accept policy ──────────

    fn full_replication_attestation() -> Value {
        json!({
            "independent_replications": 4,
            "all_replications_passed": true,
            "held_out_prompts": true,
            "second_model_confirmed": true,
            "cpu_verified": true,
            "min_effect_size": 0.62
        })
    }

    fn agent_proposal(reviewer_actor: &str, kind: &str, payload: Value) -> StateProposal {
        new_proposal(
            kind,
            StateTarget {
                r#type: "finding".to_string(),
                id: "vf_claim".to_string(),
            },
            reviewer_actor,
            "agent",
            "from experiment fleet",
            payload,
            Vec::new(),
            Vec::new(),
        )
    }

    #[test]
    fn replication_attestation_passes_only_when_fully_verified() {
        assert!(replication_attestation_passes(
            &json!({"replication_attestation": full_replication_attestation()})
        ));
        // absent entirely
        assert!(!replication_attestation_passes(&json!({})));
        // too few independent replications
        let mut att = full_replication_attestation();
        att["independent_replications"] = json!(2);
        assert!(!replication_attestation_passes(
            &json!({"replication_attestation": att})
        ));
        // a replication failed
        let mut att = full_replication_attestation();
        att["all_replications_passed"] = json!(false);
        assert!(!replication_attestation_passes(
            &json!({"replication_attestation": att})
        ));
        // only confirmed on one model
        let mut att = full_replication_attestation();
        att["second_model_confirmed"] = json!(false);
        assert!(!replication_attestation_passes(
            &json!({"replication_attestation": att})
        ));
        // never CPU-verified (MPS can be silently wrong)
        let mut att = full_replication_attestation();
        att["cpu_verified"] = json!(false);
        assert!(!replication_attestation_passes(
            &json!({"replication_attestation": att})
        ));
        // marginal effect under threshold
        let mut att = full_replication_attestation();
        att["min_effect_size"] = json!(0.10);
        assert!(!replication_attestation_passes(
            &json!({"replication_attestation": att})
        ));
    }

    #[test]
    fn human_reviewer_is_unaffected_by_agent_policy() {
        // The gate is a strict no-op for non-agent reviewers, even for a
        // destructive kind carrying no attestation.
        let p = agent_proposal("reviewer:will-blair", "finding.retract", json!({}));
        assert!(enforce_trusted_agent_accept_policy(&p, "reviewer:will-blair").is_ok());
    }

    #[test]
    fn replicator_accepts_verified_claim_only() {
        let verified = agent_proposal(
            "agent:replicator",
            "finding.add",
            json!({"replication_attestation": full_replication_attestation()}),
        );
        assert!(enforce_trusted_agent_accept_policy(&verified, "agent:replicator").is_ok());

        // same role, no attestation -> denied
        let unverified = agent_proposal("agent:replicator", "finding.add", json!({}));
        assert!(enforce_trusted_agent_accept_policy(&unverified, "agent:replicator").is_err());

        // verified but destructive/lifecycle kind -> denied (needs a human)
        let destructive = agent_proposal(
            "agent:replicator",
            "finding.retract",
            json!({"replication_attestation": full_replication_attestation()}),
        );
        assert!(enforce_trusted_agent_accept_policy(&destructive, "agent:replicator").is_err());
    }

    #[test]
    fn repair_agent_accepts_only_mechanical_kinds() {
        let span = agent_proposal("agent:repair", "finding.span_repair", json!({}));
        assert!(enforce_trusted_agent_accept_policy(&span, "agent:repair").is_ok());
        let locator = agent_proposal("agent:repair", "evidence_atom.locator_repair", json!({}));
        assert!(enforce_trusted_agent_accept_policy(&locator, "agent:repair").is_ok());
        // a claim is not a mechanical repair -> denied
        let claim = agent_proposal(
            "agent:repair",
            "finding.add",
            json!({"replication_attestation": full_replication_attestation()}),
        );
        assert!(enforce_trusted_agent_accept_policy(&claim, "agent:repair").is_err());
    }

    #[test]
    fn untrusted_agent_reviewer_cannot_accept_even_verified_work() {
        let p = agent_proposal(
            "agent:literature-scout",
            "finding.add",
            json!({"replication_attestation": full_replication_attestation()}),
        );
        assert!(enforce_trusted_agent_accept_policy(&p, "agent:literature-scout").is_err());
    }

    #[test]
    fn replicator_can_apply_verified_review_end_to_end() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("frontier.json");
        let frontier = project::assemble("test", vec![finding("vf_test")], 0, 0, "test");
        repo::save_to_path(&path, &frontier).unwrap();
        let proposal = new_proposal(
            "finding.review",
            StateTarget {
                r#type: "finding".to_string(),
                id: "vf_test".to_string(),
            },
            "agent:replicator",
            "agent",
            "survived adversarial replication on held-out prompts + second model",
            json!({"status": "accepted", "replication_attestation": full_replication_attestation()}),
            Vec::new(),
            Vec::new(),
        );
        // apply = true accepts under the proposal actor (agent:replicator).
        create_or_apply(&path, proposal, true).unwrap();
        let loaded = repo::load_from_path(&path).unwrap();
        assert_eq!(loaded.proposals[0].status, "applied");
        assert_eq!(
            loaded.proposals[0].reviewed_by.as_deref(),
            Some("agent:replicator")
        );
    }

    #[test]
    fn replicator_cannot_apply_unverified_review_end_to_end() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("frontier.json");
        let frontier = project::assemble("test", vec![finding("vf_test")], 0, 0, "test");
        repo::save_to_path(&path, &frontier).unwrap();
        let proposal = new_proposal(
            "finding.review",
            StateTarget {
                r#type: "finding".to_string(),
                id: "vf_test".to_string(),
            },
            "agent:replicator",
            "agent",
            "no replication evidence",
            json!({"status": "accepted"}),
            Vec::new(),
            Vec::new(),
        );
        let result = create_or_apply(&path, proposal, true);
        assert!(
            result.is_err(),
            "agent:replicator must not auto-apply a claim without a passing attestation"
        );
        // Fail-closed and atomic: the apply errors before the frontier is
        // saved, so nothing is persisted at all.
        let loaded = repo::load_from_path(&path).unwrap();
        assert!(loaded.proposals.is_empty());
        assert!(!loaded.findings[0].flags.contested);
    }

    #[test]
    fn preview_reports_changed_objects_and_event_kind_without_mutation() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("frontier.json");
        let frontier = project::assemble("test", vec![finding("vf_test")], 0, 0, "test");
        repo::save_to_path(&path, &frontier).unwrap();
        let proposal = new_proposal(
            "finding.review",
            StateTarget {
                r#type: "finding".to_string(),
                id: "vf_test".to_string(),
            },
            "reviewer:test",
            "human",
            "Mouse-only evidence",
            json!({"status": "contested"}),
            Vec::new(),
            Vec::new(),
        );
        let proposal_id = create_or_apply(&path, proposal, false).unwrap().proposal_id;

        let preview = preview_at_path(&path, &proposal_id, "reviewer:test").unwrap();

        assert_eq!(preview.changed_findings, vec!["vf_test"]);
        assert!(preview.changed_artifacts.is_empty());
        assert_eq!(preview.event_kinds, vec!["finding.reviewed"]);
        assert_eq!(
            preview.new_event_ids,
            vec![preview.applied_event_id.clone()]
        );
        assert_eq!(preview.events_delta, 1);
        let loaded = repo::load_from_path(&path).unwrap();
        assert_eq!(loaded.events.len(), 1, "preview must not mutate events");
        assert_eq!(
            loaded.proposals[0].status, "pending_review",
            "preview must not accept the proposal"
        );
    }

    #[test]
    fn pending_note_proposal_does_not_mutate_annotations() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("frontier.json");
        let frontier = project::assemble("test", vec![finding("vf_test")], 0, 0, "test");
        repo::save_to_path(&path, &frontier).unwrap();
        let proposal = new_proposal(
            "finding.note",
            StateTarget {
                r#type: "finding".to_string(),
                id: "vf_test".to_string(),
            },
            "reviewer:test",
            "human",
            "Track mouse-only evidence",
            json!({"text": "Track mouse-only evidence"}),
            Vec::new(),
            Vec::new(),
        );
        create_or_apply(&path, proposal, false).unwrap();
        let loaded = repo::load_from_path(&path).unwrap();
        assert_eq!(loaded.events.len(), 1); // genesis only
        assert_eq!(loaded.proposals.len(), 1);
        assert!(loaded.findings[0].annotations.is_empty());
        assert_eq!(loaded.proposals[0].kind, "finding.note");
    }

    #[test]
    fn applied_note_emits_noted_event_and_stales_proof() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("frontier.json");
        let mut frontier = project::assemble("test", vec![finding("vf_test")], 0, 0, "test");
        record_proof_export(
            &mut frontier,
            ProofPacketRecord {
                generated_at: "2026-04-23T00:00:00Z".to_string(),
                snapshot_hash: "a".repeat(64),
                event_log_hash: "b".repeat(64),
                packet_manifest_hash: "c".repeat(64),
            },
        );
        repo::save_to_path(&path, &frontier).unwrap();
        let proposal = new_proposal(
            "finding.note",
            StateTarget {
                r#type: "finding".to_string(),
                id: "vf_test".to_string(),
            },
            "reviewer:test",
            "human",
            "Track mouse-only evidence",
            json!({"text": "Track mouse-only evidence"}),
            Vec::new(),
            Vec::new(),
        );
        let result = create_or_apply(&path, proposal, true).unwrap();
        let loaded = repo::load_from_path(&path).unwrap();
        assert_eq!(loaded.events.len(), 2); // genesis + finding.noted
        assert_eq!(loaded.events[1].kind, "finding.noted");
        assert_eq!(loaded.findings[0].annotations.len(), 1);
        assert_eq!(loaded.proposals[0].status, "applied");
        assert_eq!(
            loaded.proposals[0].applied_event_id,
            result.applied_event_id
        );
        assert_eq!(loaded.proof_state.latest_packet.status, "stale");
    }

    #[test]
    fn retract_emits_per_dependent_cascade_events() {
        // Phase L: a retraction must emit one canonical
        // `finding.dependency_invalidated` event per affected dependent
        // in BFS depth order. Build a tiny dependency chain:
        //   src  <-supports- dep1  <-depends- dep2
        // and assert that retracting `src` produces three events:
        // [retracted(src), dep_invalidated(dep1, depth=1),
        //  dep_invalidated(dep2, depth=2)] all carrying the source's
        // canonical event ID as `upstream_event_id`.
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("frontier.json");
        let mut src = finding("vf_src");
        let mut dep1 = finding("vf_dep1");
        let mut dep2 = finding("vf_dep2");
        src.assertion.text = "src finding".into();
        dep1.assertion.text = "dep1 finding".into();
        dep2.assertion.text = "dep2 finding".into();
        // BFS edges flow from dependent → upstream via `target`.
        dep1.add_link("vf_src", "supports", "");
        dep2.add_link("vf_dep1", "depends", "");
        let frontier = project::assemble("test", vec![src, dep1, dep2], 0, 0, "test");
        repo::save_to_path(&path, &frontier).unwrap();

        let proposal = new_proposal(
            "finding.retract",
            StateTarget {
                r#type: "finding".to_string(),
                id: "vf_src".to_string(),
            },
            "reviewer:test",
            "human",
            "Source paper retracted by publisher",
            json!({}),
            Vec::new(),
            Vec::new(),
        );
        create_or_apply(&path, proposal, true).unwrap();
        let loaded = repo::load_from_path(&path).unwrap();

        // genesis + 1 source retract + 2 cascade events = 4 total.
        assert_eq!(loaded.events.len(), 4, "{:?}", loaded.events);
        let kinds: Vec<&str> = loaded.events.iter().map(|e| e.kind.as_str()).collect();
        assert_eq!(kinds[0], "frontier.created");
        assert_eq!(kinds[1], "finding.retracted");
        assert_eq!(kinds[2], "finding.dependency_invalidated");
        assert_eq!(kinds[3], "finding.dependency_invalidated");

        let source_event_id = loaded.events[1].id.clone();
        let dep1_event = &loaded.events[2];
        let dep2_event = &loaded.events[3];
        assert_eq!(dep1_event.target.id, "vf_dep1");
        assert_eq!(dep2_event.target.id, "vf_dep2");
        assert_eq!(
            dep1_event
                .payload
                .get("upstream_event_id")
                .and_then(|v| v.as_str()),
            Some(source_event_id.as_str())
        );
        assert_eq!(
            dep1_event.payload.get("depth").and_then(|v| v.as_u64()),
            Some(1)
        );
        assert_eq!(
            dep2_event.payload.get("depth").and_then(|v| v.as_u64()),
            Some(2)
        );
        // Both dependents must end up contested in materialized state.
        let dep1 = loaded.findings.iter().find(|f| f.id == "vf_dep1").unwrap();
        let dep2 = loaded.findings.iter().find(|f| f.id == "vf_dep2").unwrap();
        assert!(dep1.flags.contested);
        assert!(dep2.flags.contested);
        let src = loaded.findings.iter().find(|f| f.id == "vf_src").unwrap();
        assert!(src.flags.retracted);
    }

    #[test]
    fn proposal_id_is_content_addressed_independent_of_created_at() {
        // Phase P (v0.5): identical logical proposals constructed at different
        // times must produce the same `vpr_…`. This is the substrate property
        // that makes agent retries idempotent.
        let target = StateTarget {
            r#type: "finding".to_string(),
            id: "vf_test".to_string(),
        };
        let mut a = new_proposal(
            "finding.review",
            target.clone(),
            "reviewer:test",
            "human",
            "scope narrower than claim",
            json!({"status": "contested"}),
            Vec::new(),
            Vec::new(),
        );
        let mut b = new_proposal(
            "finding.review",
            target,
            "reviewer:test",
            "human",
            "scope narrower than claim",
            json!({"status": "contested"}),
            Vec::new(),
            Vec::new(),
        );
        // Force divergent timestamps; the IDs must still match.
        a.created_at = "2026-04-25T00:00:00Z".to_string();
        b.created_at = "2026-09-12T17:32:00Z".to_string();
        a.id = proposal_id(&a);
        b.id = proposal_id(&b);
        assert_eq!(a.id, b.id, "vpr_… must not depend on created_at");
    }

    #[test]
    fn create_or_apply_is_idempotent_under_repeated_calls() {
        // Phase P: invoking create_or_apply twice with identical content must
        // not duplicate the proposal nor emit two events. The second call
        // returns the same proposal_id and applied_event_id as the first.
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("frontier.json");
        let frontier = project::assemble("test", vec![finding("vf_test")], 0, 0, "test");
        repo::save_to_path(&path, &frontier).unwrap();

        let make = || {
            new_proposal(
                "finding.review",
                StateTarget {
                    r#type: "finding".to_string(),
                    id: "vf_test".to_string(),
                },
                "reviewer:test",
                "human",
                "agent retry test",
                json!({"status": "contested"}),
                Vec::new(),
                Vec::new(),
            )
        };

        let first = create_or_apply(&path, make(), true).unwrap();
        let second = create_or_apply(&path, make(), true).unwrap();

        assert_eq!(first.proposal_id, second.proposal_id);
        assert_eq!(first.applied_event_id, second.applied_event_id);

        let loaded = repo::load_from_path(&path).unwrap();
        assert_eq!(
            loaded.proposals.len(),
            1,
            "second create_or_apply must not insert a duplicate proposal"
        );
        // genesis + 1 applied review event = 2; not 3.
        assert_eq!(
            loaded.events.len(),
            2,
            "second create_or_apply must not emit a duplicate event"
        );
    }

    #[test]
    fn accepting_applied_proposal_is_idempotent() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("frontier.json");
        let frontier = project::assemble("test", vec![finding("vf_test")], 0, 0, "test");
        repo::save_to_path(&path, &frontier).unwrap();
        let proposal = new_proposal(
            "finding.review",
            StateTarget {
                r#type: "finding".to_string(),
                id: "vf_test".to_string(),
            },
            "reviewer:test",
            "human",
            "Mouse-only evidence",
            json!({"status": "contested"}),
            Vec::new(),
            Vec::new(),
        );
        let created = create_or_apply(&path, proposal, true).unwrap();
        let first_event = created.applied_event_id.clone().unwrap();
        let second_event =
            accept_at_path(&path, &created.proposal_id, "reviewer:test", "same").unwrap();
        assert_eq!(first_event, second_event);
    }

    #[test]
    fn verifier_attach_accepts_and_derives_verified() {
        use crate::verifier_attachment::{
            AdversarialProbe, AttachmentDraft, AttachmentOutcome, MatchToClaim, ProbeKind,
            ProbeResult, VerifierAttachment, VerifierMethod, derive_gate_status,
        };
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("frontier.json");
        let frontier = project::assemble("test", vec![finding("vf_test")], 0, 0, "test");
        repo::save_to_path(&path, &frontier).unwrap();
        let cd = crate::verifier_attachment::claim_digest("Test finding");
        let mk = |method: VerifierMethod, solver: &str, indep: Vec<String>| {
            VerifierAttachment::build(AttachmentDraft {
                target: "vf_test".to_string(),
                claim_digest: cd.clone(),
                verifier_method: method,
                solver_id: solver.to_string(),
                independent_of: indep,
                match_to_claim: MatchToClaim {
                    matches: true,
                    checker_actor: "opus".to_string(),
                },
                adversarial_probes: vec![AdversarialProbe {
                    kind: ProbeKind::CounterexampleSearch,
                    result: ProbeResult::Survived,
                    note: String::new(),
                }],
                outcome: AttachmentOutcome::Passed,
                verifier_actor: "opus".to_string(),
                note: String::new(),
            })
            .unwrap()
        };
        let a1 = mk(VerifierMethod::ExactArithmeticRecompute, "solver-a", vec![]);
        let a2 = mk(
            VerifierMethod::LiteratureCorroboration,
            "solver-b",
            vec![a1.id.clone()],
        );
        for att in [&a1, &a2] {
            let proposal = new_proposal(
                "verifier.attach",
                StateTarget {
                    r#type: "finding".to_string(),
                    id: "vf_test".to_string(),
                },
                "reviewer:test",
                "human",
                "attach verifier evidence",
                json!({ "attachment": att }),
                Vec::new(),
                Vec::new(),
            );
            create_or_apply(&path, proposal, true).unwrap();
        }
        let reloaded = repo::load_from_path(&path).unwrap();
        assert_eq!(
            reloaded.verifier_attachments.len(),
            2,
            "both attachments stored in the sidecar collection"
        );
        // Per-finding gate status is DERIVED on read, never stored.
        let outcome = derive_gate_status(&cd, &reloaded.verifier_attachments);
        assert!(
            outcome.is_verified(),
            "two independent matched surviving-probe attachments must derive Verified"
        );
    }

    // ---- exact-lane proposal-level wrapper (Phase 1A) ----

    fn admit_ready_fixture() -> (
        StateProposal,
        crate::bundle::FindingBundle,
        Vec<crate::verifier_attachment::VerifierAttachment>,
    ) {
        use crate::verifier_attachment::{
            AdversarialProbe, AttachmentDraft, AttachmentOutcome, MatchToClaim, MethodIntegrity,
            ProbeKind, ProbeResult, VerifierAttachment, VerifierMethod,
        };
        // A finding whose id is its real content-address (the drift-pin passes).
        let mut finding = crate::test_support::make_finding("vf_placeholder", 1.0, "measurement");
        finding.id =
            crate::bundle::FindingBundle::content_address(&finding.assertion, &finding.provenance);
        let cd = crate::verifier_attachment::claim_digest(&finding.assertion.text);
        // Build genuinely id-valid attachments: integrity and implementation_id
        // are set through the re-deriving builders (post-build field mutation
        // would leave the stored id no longer content-addressing the body, which
        // the gate's G4 id-integrity check now excludes). Independence is
        // one-directional (a2 names a1); a mutual 2-cycle is unconstructable.
        let mk = |method: VerifierMethod, solver: &str, impl_id: &str, independent_of: Vec<String>| {
            VerifierAttachment::build(AttachmentDraft {
                target: finding.id.clone(),
                claim_digest: cd.clone(),
                verifier_method: method,
                solver_id: solver.to_string(),
                independent_of,
                match_to_claim: MatchToClaim {
                    matches: true,
                    checker_actor: "checker".to_string(),
                },
                adversarial_probes: vec![AdversarialProbe {
                    kind: ProbeKind::FormalismFidelity,
                    result: ProbeResult::Survived,
                    note: String::new(),
                }],
                outcome: AttachmentOutcome::Passed,
                verifier_actor: "verifier:vela-verify".to_string(),
                note: String::new(),
            })
            .unwrap()
            .with_method_integrity(MethodIntegrity::Sound)
            .unwrap()
            .with_implementation_id(impl_id)
            .unwrap()
        };
        // a1 is built first so its id is final before a2 references it.
        let a1 = mk(VerifierMethod::ComputationalSearch, "cp-sat", "impl-a", vec![]);
        let a2 = mk(
            VerifierMethod::ExactArithmeticRecompute,
            "pari",
            "impl-b",
            vec![a1.id.clone()],
        );
        let proposal = new_proposal(
            "finding.add",
            StateTarget {
                r#type: "finding".to_string(),
                id: finding.id.clone(),
            },
            "producer:campaign", // != every verifier_actor
            "agent",
            "campaign finding",
            json!({ "finding": finding.clone() }),
            Vec::new(),
            Vec::new(),
        );
        (proposal, finding, vec![a1, a2])
    }

    #[test]
    fn exact_lane_wrapper_happy_path() {
        let (p, f, atts) = admit_ready_fixture();
        let (admit, reasons) =
            exact_lane_auto_admit(&p, &f, &atts, &BTreeSet::new(), &BTreeSet::new(), false);
        assert!(admit, "should admit, refused for: {reasons:?}");
    }

    #[test]
    fn exact_lane_wrapper_rejects_wrong_kind() {
        let (mut p, f, atts) = admit_ready_fixture();
        p.kind = "verifier.attach".to_string();
        let (admit, reasons) =
            exact_lane_auto_admit(&p, &f, &atts, &BTreeSet::new(), &BTreeSet::new(), false);
        assert!(!admit);
        assert!(reasons.iter().any(|r| r.contains("finding.add")));
    }

    #[test]
    fn exact_lane_wrapper_rejects_target_mismatch() {
        let (mut p, f, atts) = admit_ready_fixture();
        p.target.id = "vf_other".to_string();
        let (admit, _r) =
            exact_lane_auto_admit(&p, &f, &atts, &BTreeSet::new(), &BTreeSet::new(), false);
        assert!(!admit);
    }

    // ATTACK: the assertion text is edited after the id was minted.
    #[test]
    fn exact_lane_wrapper_rejects_content_address_drift() {
        let (p, mut f, atts) = admit_ready_fixture();
        f.assertion.text = "a tampered, inflated claim".to_string();
        let (admit, reasons) =
            exact_lane_auto_admit(&p, &f, &atts, &BTreeSet::new(), &BTreeSet::new(), false);
        assert!(!admit);
        assert!(reasons.iter().any(|r| r.contains("drift")));
    }

    #[test]
    fn exact_lane_wrapper_rejects_retracted_or_superseded() {
        let (p, mut f, atts) = admit_ready_fixture();
        f.flags.retracted = true;
        let (admit, _r) =
            exact_lane_auto_admit(&p, &f, &atts, &BTreeSet::new(), &BTreeSet::new(), false);
        assert!(!admit);
        let (p2, mut f2, atts2) = admit_ready_fixture();
        f2.flags.superseded = true;
        let (admit2, _r2) =
            exact_lane_auto_admit(&p2, &f2, &atts2, &BTreeSet::new(), &BTreeSet::new(), false);
        assert!(!admit2);
    }

    #[test]
    fn exact_lane_wrapper_rejects_synthetic_signal() {
        let (p, f, atts) = admit_ready_fixture();
        let synthetic = BTreeSet::from([f.id.clone()]);
        let (admit, reasons) =
            exact_lane_auto_admit(&p, &f, &atts, &BTreeSet::new(), &synthetic, false);
        assert!(!admit);
        assert!(reasons.iter().any(|r| r.contains("synthetic")));
    }

    #[test]
    fn exact_lane_wrapper_rejects_open_contradiction() {
        let (p, f, atts) = admit_ready_fixture();
        let contradictions = BTreeSet::from([f.id.clone()]);
        let (admit, reasons) =
            exact_lane_auto_admit(&p, &f, &atts, &contradictions, &BTreeSet::new(), false);
        assert!(!admit);
        assert!(reasons.iter().any(|r| r.contains("contradiction")));
    }

    // ATTACK: the producer is also a corroborator (same actor).
    #[test]
    fn exact_lane_wrapper_rejects_producer_equals_verifier() {
        let (p, f, mut atts) = admit_ready_fixture();
        atts[0].verifier_actor = "producer:campaign".to_string(); // == proposal.actor.id
        let (admit, reasons) =
            exact_lane_auto_admit(&p, &f, &atts, &BTreeSet::new(), &BTreeSet::new(), false);
        assert!(!admit);
        assert!(reasons.iter().any(|r| r.contains("corroborate itself")));
    }

    // The attachment predicate still gates: a single attachment fails.
    #[test]
    fn exact_lane_wrapper_delegates_to_attachment_predicate() {
        let (p, f, atts) = admit_ready_fixture();
        let single = vec![atts[0].clone()];
        let (admit, _r) =
            exact_lane_auto_admit(&p, &f, &single, &BTreeSet::new(), &BTreeSet::new(), false);
        assert!(!admit);
    }

    // floor_sufficient: the exact-lane FLOOR is the proof, so the lane admits
    // on the floor alone (NO attachments) — the >=2-attachment bar is waived.
    #[test]
    fn exact_lane_wrapper_floor_sufficient_admits_without_attachments() {
        let (p, f, _atts) = admit_ready_fixture();
        let (admit, reasons) =
            exact_lane_auto_admit(&p, &f, &[], &BTreeSet::new(), &BTreeSet::new(), true);
        assert!(
            admit,
            "floor-sufficient should admit with no attachments: {reasons:?}"
        );
    }

    // ...but floor_sufficient never bypasses the proposal-level guards.
    #[test]
    fn exact_lane_wrapper_floor_sufficient_still_honors_guards() {
        let (p, mut f, _atts) = admit_ready_fixture();
        f.flags.retracted = true;
        let (admit, _r) =
            exact_lane_auto_admit(&p, &f, &[], &BTreeSet::new(), &BTreeSet::new(), true);
        assert!(
            !admit,
            "retracted finding refuses even when floor-sufficient"
        );

        let (p2, f2, _) = admit_ready_fixture();
        let synthetic = BTreeSet::from([f2.id.clone()]);
        let (admit2, _r2) =
            exact_lane_auto_admit(&p2, &f2, &[], &BTreeSet::new(), &synthetic, true);
        assert!(
            !admit2,
            "synthetic source refuses even when floor-sufficient"
        );
    }

    // ---- derive_trust_tier projection ----

    fn policy_admit_event(proposal_id: &str) -> StateEvent {
        StateEvent {
            schema: events::EVENT_SCHEMA.to_string(),
            id: "vev_test_admit".to_string(),
            kind: events::EVENT_KIND_POLICY_AUTO_ADMITTED.into(),
            target: StateTarget {
                r#type: "proposal".to_string(),
                id: proposal_id.to_string(),
            },
            actor: StateActor {
                id: "policy:exact-lane".to_string(),
                r#type: "agent".to_string(),
            },
            timestamp: "2026-06-19T00:00:00Z".to_string(),
            reason: "exact-lane auto-admit".to_string(),
            before_hash: NULL_HASH.to_string(),
            after_hash: NULL_HASH.to_string(),
            payload: json!({ "proposal_id": proposal_id }),
            caveats: vec![],
            signature: None,
            schema_artifact_id: None,
        }
    }

    #[test]
    fn trust_tier_accepted_when_landed() {
        let (_p, f, _a) = admit_ready_fixture();
        let frontier = project::assemble("t", vec![f.clone()], 0, 0, "t");
        assert_eq!(derive_trust_tier(&frontier, &f.id), TrustTier::Accepted);
    }

    #[test]
    fn trust_tier_candidate_when_retracted() {
        let (_p, mut f, _a) = admit_ready_fixture();
        f.flags.retracted = true;
        let frontier = project::assemble("t", vec![f.clone()], 0, 0, "t");
        assert_eq!(derive_trust_tier(&frontier, &f.id), TrustTier::Candidate);
    }

    #[test]
    fn trust_tier_machine_verified_for_pending_auto_admitted() {
        let (p, f, atts) = admit_ready_fixture();
        let mut frontier = project::assemble("t", vec![], 0, 0, "t");
        frontier.verifier_attachments = atts;
        frontier.events.push(policy_admit_event(&p.id));
        frontier.proposals.push(p);
        assert_eq!(
            derive_trust_tier(&frontier, &f.id),
            TrustTier::MachineVerified
        );
    }

    // A pending finding with passing attachments but no auto-admit marker is
    // only schema_checked — never machine_verified.
    #[test]
    fn trust_tier_schema_checked_without_admit_marker() {
        let (p, f, atts) = admit_ready_fixture();
        let mut frontier = project::assemble("t", vec![], 0, 0, "t");
        frontier.verifier_attachments = atts;
        frontier.proposals.push(p); // pending, NO policy.auto_admitted event
        assert_eq!(
            derive_trust_tier(&frontier, &f.id),
            TrustTier::SchemaChecked
        );
    }

    #[test]
    fn trust_tier_candidate_when_unknown() {
        let frontier = project::assemble("t", vec![], 0, 0, "t");
        assert_eq!(
            derive_trust_tier(&frontier, "vf_nothing"),
            TrustTier::Candidate
        );
    }

    #[test]
    fn emit_policy_auto_admitted_is_idempotent_and_promotes_tier() {
        let (p, f, atts) = admit_ready_fixture();
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("frontier.json");
        let mut frontier = project::assemble("t", vec![], 0, 0, "t");
        frontier.verifier_attachments = atts;
        frontier.proposals.push(p.clone());
        repo::save_to_path(&path, &frontier).unwrap();

        let att_ids: Vec<String> = frontier
            .verifier_attachments
            .iter()
            .map(|a| a.id.clone())
            .collect();
        let digest = crate::verifier_attachment::claim_digest(&f.assertion.text);

        let (id1, new1) = emit_policy_auto_admitted(
            &path,
            &p.id,
            &digest,
            &att_ids,
            "exact-lane.v1",
            "vela-verify@test",
        )
        .unwrap();
        assert!(new1, "first emit creates the event");

        // Idempotent: a second emit writes nothing and returns the same id.
        let (id2, new2) = emit_policy_auto_admitted(
            &path,
            &p.id,
            &digest,
            &att_ids,
            "exact-lane.v1",
            "vela-verify@test",
        )
        .unwrap();
        assert_eq!(id1, id2);
        assert!(!new2, "second emit is a no-op (idempotent)");

        let reloaded = repo::load_from_path(&path).unwrap();
        let count = reloaded
            .events
            .iter()
            .filter(|e| e.kind.as_str() == events::EVENT_KIND_POLICY_AUTO_ADMITTED)
            .count();
        assert_eq!(count, 1, "exactly one admit event after two applies");

        // The pending finding now projects to MachineVerified (live gate Verified).
        assert_eq!(
            derive_trust_tier(&reloaded, &f.id),
            TrustTier::MachineVerified
        );
    }

    #[test]
    fn engine_gate_warns_then_strict_blocks_then_force_applies() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("frontier.json");
        let frontier = project::assemble("test", vec![], 0, 0, "test");
        repo::save_to_path(&path, &frontier).unwrap();

        // A sparse finding (no evidence span) introduces a review warning
        // on accept — the deterministic signal the Engine reads.
        let f = finding("vf_engine_gate");
        let proposal = new_proposal(
            "finding.add",
            StateTarget {
                r#type: "finding".to_string(),
                id: f.id.clone(),
            },
            "reviewer:test",
            "human",
            "add a sparse finding",
            json!({ "finding": f }),
            Vec::new(),
            Vec::new(),
        );
        let created = create_or_apply(&path, proposal, false).unwrap();
        let vpr = created.proposal_id.clone();

        // Prospective verdict: warns (new review warning), would not block.
        let preview = preview_engine_verdict(&path, &vpr).unwrap();
        assert_eq!(preview.status, "warn");
        assert!(!preview.new_warnings.is_empty());

        // Strict + no force: the new warning now gates. Nothing persists.
        let blocked = accept_at_path_engine(
            &path,
            &vpr,
            "reviewer:test",
            "strict",
            AcceptOptions {
                strict: true,
                force: false,
                signing_key: None,
                custody_verified: false,
            },
        );
        assert!(blocked.is_err(), "strict accept should be gated");
        let reloaded = repo::load_from_path(&path).unwrap();
        assert_eq!(
            reloaded
                .proposals
                .iter()
                .find(|p| p.id == vpr)
                .unwrap()
                .status,
            "pending_review",
            "a blocked accept must not change canonical state"
        );

        // Strict + force: applies, records the override, verdict is `forced`.
        let outcome = accept_at_path_engine(
            &path,
            &vpr,
            "reviewer:test",
            "strict",
            AcceptOptions {
                strict: true,
                force: true,
                signing_key: None,
                custody_verified: false,
            },
        )
        .unwrap();
        assert_eq!(outcome.verdict.status, "forced");
        assert!(outcome.verdict.forced);
        let after = repo::load_from_path(&path).unwrap();
        let applied = after.proposals.iter().find(|p| p.id == vpr).unwrap();
        assert_eq!(applied.status, "applied");
        assert!(
            applied
                .decision_reason
                .as_deref()
                .unwrap_or("")
                .contains("--force"),
            "the override must be recorded in the decision reason"
        );
    }

    // Build a frontier on disk seeded with `n` pending `finding.add`
    // proposals (sparse findings → review warnings on accept, not blocking),
    // returning the path and the proposal ids in creation order.
    fn frontier_with_pending_adds(n: usize) -> (TempDir, std::path::PathBuf, Vec<String>) {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("frontier.json");
        let frontier = project::assemble("batch-test", vec![], 0, 0, "test");
        repo::save_to_path(&path, &frontier).unwrap();
        let mut ids = Vec::new();
        for i in 0..n {
            let f = finding(&format!("vf_batch_{i}"));
            let proposal = new_proposal(
                "finding.add",
                StateTarget {
                    r#type: "finding".to_string(),
                    id: f.id.clone(),
                },
                "reviewer:test",
                "human",
                "batch add",
                json!({ "finding": f }),
                Vec::new(),
                Vec::new(),
            );
            ids.push(create_or_apply(&path, proposal, false).unwrap().proposal_id);
        }
        (tmp, path, ids)
    }

    #[test]
    fn accept_batch_applies_all_in_one_pass() {
        let (_tmp, path, ids) = frontier_with_pending_adds(3);
        let report = accept_batch_at_path(
            &path,
            &ids,
            "reviewer:test",
            "batch accept",
            AcceptOptions::default(),
            false,
        )
        .unwrap();

        // Non-strict: sparse-finding warnings do not block; the batch lands.
        assert!(!report.gated);
        assert_eq!(report.accepted_proposal_ids.len(), 3);
        assert_eq!(report.event_ids.len(), 3);
        assert_eq!(report.failed.len(), 0);

        let loaded = repo::load_from_path(&path).unwrap();
        assert_eq!(loaded.findings.len(), 3, "all three findings materialized");
        assert!(
            loaded.proposals.iter().all(|p| p.status == "applied"),
            "every selected proposal is applied"
        );
    }

    #[test]
    fn accept_batch_dry_run_persists_nothing() {
        let (_tmp, path, ids) = frontier_with_pending_adds(3);
        let report = accept_batch_at_path(
            &path,
            &ids,
            "reviewer:test",
            "preview",
            AcceptOptions::default(),
            true, // dry_run
        )
        .unwrap();
        assert!(report.dry_run);
        assert!(!report.gated);
        assert_eq!(
            report.accepted_proposal_ids.len(),
            3,
            "reports what would apply"
        );

        // Nothing was written: the proposals are still pending, no findings.
        let loaded = repo::load_from_path(&path).unwrap();
        assert_eq!(loaded.findings.len(), 0);
        assert!(
            loaded
                .proposals
                .iter()
                .all(|p| p.status == "pending_review")
        );
    }

    #[test]
    fn accept_batch_strict_gate_blocks_whole_batch() {
        let (_tmp, path, ids) = frontier_with_pending_adds(3);
        // Strict: the new review warnings now gate the aggregate. The batch
        // is refused as a whole and nothing is persisted.
        let report = accept_batch_at_path(
            &path,
            &ids,
            "reviewer:test",
            "strict batch",
            AcceptOptions {
                strict: true,
                force: false,
                signing_key: None,
                custody_verified: false,
            },
            false,
        )
        .unwrap();
        assert!(report.gated, "strict batch with new warnings must be gated");
        assert_eq!(report.verdict.status, "blocked");

        let loaded = repo::load_from_path(&path).unwrap();
        assert_eq!(loaded.findings.len(), 0, "a blocked batch persists nothing");
        assert!(
            loaded
                .proposals
                .iter()
                .all(|p| p.status == "pending_review")
        );

        // Strict + force: the same batch now applies in one pass, audited.
        let forced = accept_batch_at_path(
            &path,
            &ids,
            "reviewer:test",
            "strict batch",
            AcceptOptions {
                strict: true,
                force: true,
                signing_key: None,
                custody_verified: false,
            },
            false,
        )
        .unwrap();
        assert!(!forced.gated);
        assert_eq!(forced.verdict.status, "forced");
        let after = repo::load_from_path(&path).unwrap();
        assert_eq!(after.findings.len(), 3);
        assert!(after.proposals.iter().all(|p| {
            p.decision_reason
                .as_deref()
                .unwrap_or("")
                .contains("--force")
        }));
    }

    #[test]
    fn math_profile_skips_study_design_checks_for_theoretical_findings() {
        use crate::evidence_ci::{self, EvidenceCiClassification};

        fn warn_ids(report: &evidence_ci::EvidenceCiReport) -> std::collections::BTreeSet<String> {
            report
                .checks
                .iter()
                .filter(|c| c.classification == EvidenceCiClassification::ReviewWarning)
                .map(|c| c.id.clone())
                .collect()
        }
        const STUDY_DESIGN: &[&str] = &[
            "condition.population",
            "condition.comparator_or_baseline",
            "condition.endpoint",
            "trial.registry_reference",
        ];

        // A theoretical claim (Erdős-style open question, no empirical signal)
        // must NOT raise the clinical study-design warnings — they are a
        // category error on a formal claim.
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("frontier.json");
        let mut theo = finding("vf_theo");
        theo.assertion.assertion_type = "open_question".to_string();
        theo.evidence.evidence_type = "theoretical".to_string();
        theo.conditions.text = "Erdős problem statement".to_string();
        let frontier = project::assemble("math", vec![theo], 0, 0, "test");
        repo::save_to_path(&path, &frontier).unwrap();
        let report = evidence_ci::run_project(&repo::load_from_path(&path).unwrap(), &path);
        let theo_warns = warn_ids(&report);
        for id in STUDY_DESIGN {
            assert!(
                !theo_warns.contains(*id),
                "theoretical finding should not warn on {id}, got {theo_warns:?}"
            );
        }

        // The default empirical finding (mechanism / experimental, in_vivo)
        // still gets the study-design checks — the gate stays meaningful where
        // a study-design dimension actually exists.
        let tmp2 = TempDir::new().unwrap();
        let path2 = tmp2.path().join("frontier.json");
        let emp = finding("vf_emp"); // assertion mechanism, evidence experimental
        let frontier2 = project::assemble("bio", vec![emp], 0, 0, "test");
        repo::save_to_path(&path2, &frontier2).unwrap();
        let report2 = evidence_ci::run_project(&repo::load_from_path(&path2).unwrap(), &path2);
        let emp_warns = warn_ids(&report2);
        assert!(
            emp_warns.contains("condition.comparator_or_baseline")
                || emp_warns.contains("condition.endpoint"),
            "empirical finding should still raise a study-design warning, got {emp_warns:?}"
        );
    }

    #[test]
    fn v0_13_apply_materializes_source_records_inline() {
        // Pre-v0.13: vela check --strict on a CLI-built frontier flagged
        // `missing_source_record` because source_records weren't populated
        // until vela normalize --write — and normalize refuses on event-ful
        // frontiers. v0.13 materializes inline at apply time so source_records
        // grow in lockstep with findings.
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("frontier.json");
        let mut frontier = project::assemble("test", vec![], 0, 0, "test");
        repo::save_to_path(&path, &frontier).unwrap();
        // Add a finding via the standard finding.add proposal flow.
        let f = finding("vf_v013_inline_src");
        let proposal = new_proposal(
            "finding.add",
            StateTarget {
                r#type: "finding".to_string(),
                id: f.id.clone(),
            },
            "reviewer:test",
            "human",
            "Manual finding for v0.13 source-record materialization test",
            json!({"finding": f}),
            Vec::new(),
            Vec::new(),
        );
        create_or_apply(&path, proposal, true).unwrap();
        let loaded = repo::load_from_path(&path).unwrap();
        // Source records, evidence atoms, and condition records should all
        // be materialized — without any explicit normalize call.
        assert!(
            !loaded.sources.is_empty(),
            "v0.13: source_records should materialize inline at apply time"
        );
        assert!(
            !loaded.evidence_atoms.is_empty(),
            "v0.13: evidence_atoms should materialize inline at apply time"
        );
        assert!(
            !loaded.condition_records.is_empty(),
            "v0.13: condition_records should materialize inline at apply time"
        );
        // Sanity: stats reflect the new source registry.
        assert_eq!(loaded.stats.source_count, loaded.sources.len());
        // Suppress unused-mut warning when frontier isn't reused below.
        let _ = &mut frontier;
    }

    fn make_supersede_payload(old_id: &str, new_text: &str) -> (FindingBundle, Value) {
        let mut new_finding = finding("vf_supersede_new");
        new_finding.assertion.text = new_text.to_string();
        // Re-derive id from the new assertion text + provenance. For the
        // test we just hand-pick a distinct id; the real CLI uses
        // `build_finding_bundle` which content-addresses correctly.
        new_finding.id = format!(
            "vf_{:0>16}",
            old_id
                .bytes()
                .fold(0u64, |acc, b| acc.wrapping_add(b as u64))
        );
        let payload = json!({"new_finding": new_finding.clone()});
        (new_finding, payload)
    }

    #[test]
    fn v0_14_supersede_creates_new_finding_and_marks_old() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("frontier.json");
        let mut frontier = project::assemble("test", vec![finding("vf_old")], 0, 0, "test");
        repo::save_to_path(&path, &frontier).unwrap();
        let (new_finding, payload) = make_supersede_payload("vf_old", "Newer claim");
        let proposal = new_proposal(
            "finding.supersede",
            StateTarget {
                r#type: "finding".to_string(),
                id: "vf_old".to_string(),
            },
            "reviewer:test",
            "human",
            "Newer evidence updates the wording",
            payload,
            Vec::new(),
            Vec::new(),
        );
        let result = create_or_apply(&path, proposal, true).unwrap();
        assert!(result.applied_event_id.is_some());
        let loaded = repo::load_from_path(&path).unwrap();
        // Old finding now flagged superseded.
        let old = loaded.findings.iter().find(|f| f.id == "vf_old").unwrap();
        assert!(
            old.flags.superseded,
            "old finding should be flagged superseded"
        );
        // New finding present, with auto-injected supersedes link back to old.
        let new_f = loaded
            .findings
            .iter()
            .find(|f| f.id == new_finding.id)
            .expect("new finding should be in frontier");
        assert!(
            new_f
                .links
                .iter()
                .any(|l| l.target == "vf_old" && l.link_type == "supersedes"),
            "new finding should have an auto-injected supersedes link to old finding"
        );
        // Event with kind finding.superseded targeting old, payload carries new_finding_id.
        let supersede_event = loaded
            .events
            .iter()
            .find(|e| e.kind == "finding.superseded")
            .expect("a finding.superseded event should be emitted");
        assert_eq!(supersede_event.target.id, "vf_old");
        assert_eq!(
            supersede_event.payload["new_finding_id"].as_str(),
            Some(new_finding.id.as_str())
        );
        // suppress unused warning
        let _ = &mut frontier;
    }

    #[test]
    fn v0_14_supersede_refuses_already_superseded() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("frontier.json");
        let mut old = finding("vf_already_done");
        old.flags.superseded = true;
        let frontier = project::assemble("test", vec![old], 0, 0, "test");
        repo::save_to_path(&path, &frontier).unwrap();
        let (_, payload) = make_supersede_payload("vf_already_done", "Newer wording");
        let proposal = new_proposal(
            "finding.supersede",
            StateTarget {
                r#type: "finding".to_string(),
                id: "vf_already_done".to_string(),
            },
            "reviewer:test",
            "human",
            "Attempt to double-supersede",
            payload,
            Vec::new(),
            Vec::new(),
        );
        let result = create_or_apply(&path, proposal, true);
        assert!(
            result.is_err(),
            "double-supersede should be refused; got {result:?}"
        );
    }

    #[test]
    fn v0_14_supersede_refuses_same_content_address() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("frontier.json");
        let frontier = project::assemble("test", vec![finding("vf_same")], 0, 0, "test");
        repo::save_to_path(&path, &frontier).unwrap();
        // new_finding.id == target.id should be refused at validate-time.
        let mut new_finding = finding("vf_same");
        new_finding.assertion.text = "Different text but reused id".to_string();
        let proposal = new_proposal(
            "finding.supersede",
            StateTarget {
                r#type: "finding".to_string(),
                id: "vf_same".to_string(),
            },
            "reviewer:test",
            "human",
            "Same id, should fail",
            json!({"new_finding": new_finding}),
            Vec::new(),
            Vec::new(),
        );
        let result = create_or_apply(&path, proposal, true);
        assert!(
            result.is_err(),
            "supersede with same content address should be refused; got {result:?}"
        );
    }

    /// v0.22 byte-stability: a proposal with `agent_run = None`
    /// must serialize without an `agent_run` field, so existing
    /// frontiers (none of which have agent_run today) round-trip
    /// byte-identically. The whole substrate guarantee depends on
    /// canonical-JSON not silently gaining new keys.
    #[test]
    fn agent_run_none_skips_serialization() {
        let p = new_proposal(
            "finding.add",
            StateTarget {
                r#type: "finding".to_string(),
                id: "vf_test0000000000".to_string(),
            },
            "reviewer:will-blair",
            "human",
            "test",
            json!({}),
            Vec::new(),
            Vec::new(),
        );
        let bytes = canonical::to_canonical_bytes(&p).unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(
            !s.contains("agent_run"),
            "proposal without agent_run leaked the field into canonical JSON: {s}"
        );
    }

    /// And when `agent_run` *is* set, the same proposal id is
    /// produced regardless — `proposal_id`'s preimage explicitly
    /// excludes agent_run, so attaching provenance never changes
    /// the content address.
    #[test]
    fn agent_run_does_not_change_proposal_id() {
        let bare = new_proposal(
            "finding.add",
            StateTarget {
                r#type: "finding".to_string(),
                id: "vf_test0000000000".to_string(),
            },
            "agent:literature-scout",
            "agent",
            "scout extracted this from paper_014",
            json!({}),
            vec!["src_paper_014".to_string()],
            Vec::new(),
        );
        let id_bare = bare.id.clone();

        let mut with_run = bare.clone();
        with_run.agent_run = Some(AgentRun {
            agent: "literature-scout".to_string(),
            model: "claude-opus-4-7".to_string(),
            run_id: "vrun_abc1234567890def".to_string(),
            started_at: "2026-04-26T01:23:45Z".to_string(),
            finished_at: Some("2026-04-26T01:24:10Z".to_string()),
            context: BTreeMap::from([
                ("input_folder".to_string(), "./papers".to_string()),
                ("pdf_count".to_string(), "12".to_string()),
            ]),
            tool_calls: Vec::new(),
            permissions: None,
        });
        let id_with_run = proposal_id(&with_run);
        assert_eq!(
            id_bare, id_with_run,
            "agent_run leaked into proposal_id preimage"
        );
    }

    /// v0.49 byte-stability: tool_calls and permissions on AgentRun
    /// must skip serialization when empty/None, so existing frontiers
    /// (none of which carry these fields today) round-trip byte-
    /// identically through canonical JSON. Same invariant as
    /// agent_run itself in v0.22.
    #[test]
    fn agent_run_empty_tool_calls_and_permissions_skip_serialization() {
        let p = new_proposal(
            "finding.add",
            StateTarget {
                r#type: "finding".to_string(),
                id: "vf_test0000000000".to_string(),
            },
            "agent:scout",
            "agent",
            "test",
            json!({}),
            Vec::new(),
            Vec::new(),
        );
        let mut with_run = p.clone();
        with_run.agent_run = Some(AgentRun {
            agent: "scout".to_string(),
            model: "claude-opus-4-7".to_string(),
            run_id: "vrun_x".to_string(),
            started_at: "2026-04-26T01:00:00Z".to_string(),
            finished_at: None,
            context: BTreeMap::new(),
            tool_calls: Vec::new(),
            permissions: None,
        });
        let bytes = canonical::to_canonical_bytes(&with_run).unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(
            !s.contains("tool_calls"),
            "empty tool_calls leaked into canonical JSON: {s}"
        );
        assert!(
            !s.contains("permissions"),
            "empty permissions leaked into canonical JSON: {s}"
        );
    }

    /// v0.49: when populated, tool_calls and permissions DO serialize
    /// — this is the round-trip we want for new agent runs that
    /// actually carry tool traces.
    #[test]
    fn agent_run_populated_tool_calls_and_permissions_roundtrip() {
        let mut p = new_proposal(
            "finding.add",
            StateTarget {
                r#type: "finding".to_string(),
                id: "vf_test0000000000".to_string(),
            },
            "agent:scout",
            "agent",
            "test",
            json!({}),
            Vec::new(),
            Vec::new(),
        );
        p.agent_run = Some(AgentRun {
            agent: "scout".to_string(),
            model: "claude-opus-4-7".to_string(),
            run_id: "vrun_x".to_string(),
            started_at: "2026-04-26T01:00:00Z".to_string(),
            finished_at: None,
            context: BTreeMap::new(),
            tool_calls: vec![
                ToolCallTrace {
                    tool: "pubmed_search".to_string(),
                    input_sha256: "a".repeat(64),
                    output_sha256: Some("b".repeat(64)),
                    at: "2026-04-26T01:00:05Z".to_string(),
                    duration_ms: Some(842),
                    status: "ok".to_string(),
                    error_message: String::new(),
                },
                // v0.49: a failed tool call with an explanatory
                // error_message — the field a reviewer needs to audit
                // what went wrong without re-running the agent.
                ToolCallTrace {
                    tool: "arxiv_fetch".to_string(),
                    input_sha256: "c".repeat(64),
                    output_sha256: None,
                    at: "2026-04-26T01:00:18Z".to_string(),
                    duration_ms: Some(1200),
                    status: "error".to_string(),
                    error_message: "HTTP 503 from arxiv.org; retry budget exhausted".to_string(),
                },
            ],
            permissions: Some(PermissionState {
                data_access: vec!["pubmed:".to_string(), "frontier:vfr_bd91".to_string()],
                tool_access: vec!["pubmed_search".to_string(), "arxiv_fetch".to_string()],
                note: "read-only access to BBB Flagship".to_string(),
            }),
        });
        let bytes = canonical::to_canonical_bytes(&p).unwrap();
        let json: serde_json::Value =
            serde_json::from_slice(&bytes).expect("canonical bytes round-trip");
        assert_eq!(
            json["agent_run"]["tool_calls"][0]["tool"], "pubmed_search",
            "tool_calls did not survive the round trip: {json}"
        );
        assert_eq!(
            json["agent_run"]["permissions"]["data_access"][0], "pubmed:",
            "permissions did not survive the round trip: {json}"
        );
        // v0.49: a failed tool call with error_message carries the
        // explanation through canonical JSON. A reviewer can audit
        // exactly what failed without rerunning the agent.
        assert_eq!(
            json["agent_run"]["tool_calls"][1]["status"], "error",
            "failed tool call status did not survive: {json}"
        );
        assert_eq!(
            json["agent_run"]["tool_calls"][1]["error_message"],
            "HTTP 503 from arxiv.org; retry budget exhausted",
            "error_message did not survive the round trip: {json}"
        );
        // ...and successful calls still don't leak an empty
        // error_message into canonical bytes.
        let raw = std::str::from_utf8(&bytes).unwrap();
        let okay_call_block_end = raw.find("pubmed_search").unwrap();
        let until_first_call = &raw[..okay_call_block_end + 200];
        assert!(
            !until_first_call.contains("\"error_message\":\"\""),
            "successful tool call leaked an empty error_message: {until_first_call}"
        );
    }

    // ── v0.128: protocol-side accept authority gate ──────────────────
    //
    // These exercise `authorize_proposal_accept` — the per-reviewer-key
    // predicate the public accept boundary runs *before* the strict
    // canonical accept. They prove the gate the open `publish_entry`
    // path lacks: a reviewer accept must resolve to a registered,
    // non-revoked, reviewer-authority actor whose key signed the exact
    // (action, vfr_id, proposal_id, reviewer_id, reason) preimage.

    use crate::sign::ActorRecord;
    use ed25519_dalek::SigningKey;

    fn accept_keypair() -> SigningKey {
        use rand::rngs::OsRng;
        SigningKey::generate(&mut OsRng)
    }

    fn accept_actor(id: &str, pubkey_hex: &str) -> ActorRecord {
        ActorRecord {
            id: id.to_string(),
            public_key: pubkey_hex.to_string(),
            algorithm: "ed25519".to_string(),
            created_at: "2026-05-01T00:00:00Z".to_string(),
            tier: None,
            orcid: None,
            access_clearance: None,
            revoked_at: None,
            revoked_reason: None,
        }
    }

    /// A frontier carrying one pending proposal targeting a finding,
    /// plus the actors passed in. Returns (project, proposal).
    fn frontier_with_proposal(actors: Vec<ActorRecord>) -> (Project, StateProposal) {
        let mut project =
            project::assemble("accept-gate", vec![finding("vf_target0000000")], 0, 0, "t");
        let proposal = new_proposal(
            "finding.review",
            StateTarget {
                r#type: "finding".to_string(),
                id: "vf_target0000000".to_string(),
            },
            "agent:literature-scout",
            "agent",
            "Mouse-only evidence; recommend contested",
            json!({"status": "contested"}),
            Vec::new(),
            Vec::new(),
        );
        project.proposals.push(proposal.clone());
        project.actors = actors;
        (project, proposal)
    }

    const VFR: &str = "vfr_accept_gate_fixture";
    const NOW: &str = "2026-05-29T00:00:00Z";

    /// Sign the canonical accept preimage for `reviewer_id` with `key`.
    fn sign_accept(
        key: &SigningKey,
        vfr_id: &str,
        proposal_id: &str,
        reviewer_id: &str,
        reason: &str,
    ) -> String {
        let bytes = accept_preimage_bytes(vfr_id, proposal_id, reviewer_id, reason).unwrap();
        hex::encode(crate::sign::sign_bytes(key, &bytes))
    }

    #[test]
    fn authorize_accept_valid_reviewer_passes() {
        let key = accept_keypair();
        let pubkey = crate::sign::pubkey_hex(&key);
        let (project, proposal) =
            frontier_with_proposal(vec![accept_actor("reviewer:will-blair", &pubkey)]);
        let reason = "Verified; mouse-only scope is accurate";
        let sig = sign_accept(&key, VFR, &proposal.id, "reviewer:will-blair", reason);

        let auth = authorize_proposal_accept(&project, VFR, &pubkey, &sig, &proposal, reason, NOW)
            .unwrap();
        assert_eq!(auth.actor.id, "reviewer:will-blair");
    }

    #[test]
    fn authorize_accept_forged_signature_rejected() {
        let key = accept_keypair();
        let pubkey = crate::sign::pubkey_hex(&key);
        let (project, proposal) =
            frontier_with_proposal(vec![accept_actor("reviewer:will-blair", &pubkey)]);
        let reason = "Verified";
        // Garbage signature of the right length but not over the preimage.
        let forged = "00".repeat(64);

        let err =
            authorize_proposal_accept(&project, VFR, &pubkey, &forged, &proposal, reason, NOW)
                .unwrap_err();
        assert!(err.contains("does not verify"), "unexpected error: {err}");
    }

    #[test]
    fn authorize_accept_signature_over_other_reason_rejected() {
        // A captured signature for reason A cannot be replayed under B —
        // reason is bound into the preimage.
        let key = accept_keypair();
        let pubkey = crate::sign::pubkey_hex(&key);
        let (project, proposal) =
            frontier_with_proposal(vec![accept_actor("reviewer:will-blair", &pubkey)]);
        let sig_for_a = sign_accept(&key, VFR, &proposal.id, "reviewer:will-blair", "reason A");

        let err = authorize_proposal_accept(
            &project, VFR, &pubkey, &sig_for_a, &proposal, "reason B", NOW,
        )
        .unwrap_err();
        assert!(err.contains("does not verify"), "unexpected error: {err}");
    }

    #[test]
    fn authorize_accept_signature_for_other_proposal_rejected() {
        // A signature bound to a different proposal id must not verify
        // against this proposal — proposal_id is in the preimage.
        let key = accept_keypair();
        let pubkey = crate::sign::pubkey_hex(&key);
        let (project, proposal) =
            frontier_with_proposal(vec![accept_actor("reviewer:will-blair", &pubkey)]);
        let reason = "Verified";
        let sig_other = sign_accept(
            &key,
            VFR,
            "vpr_some_other_proposal",
            "reviewer:will-blair",
            reason,
        );

        let err =
            authorize_proposal_accept(&project, VFR, &pubkey, &sig_other, &proposal, reason, NOW)
                .unwrap_err();
        assert!(err.contains("does not verify"), "unexpected error: {err}");
    }

    #[test]
    fn authorize_accept_unregistered_signer_rejected() {
        // The frontier registers reviewer:will-blair, but the signer
        // presents a different (valid) key that is not on the frontier.
        let registered_key = accept_keypair();
        let registered_pubkey = crate::sign::pubkey_hex(&registered_key);
        let (project, proposal) = frontier_with_proposal(vec![accept_actor(
            "reviewer:will-blair",
            &registered_pubkey,
        )]);

        let stranger = accept_keypair();
        let stranger_pubkey = crate::sign::pubkey_hex(&stranger);
        let reason = "Verified";
        // Even a cryptographically valid self-signature does not help:
        // the key resolves to no registered actor.
        let sig = sign_accept(&stranger, VFR, &proposal.id, "reviewer:will-blair", reason);

        let err = authorize_proposal_accept(
            &project,
            VFR,
            &stranger_pubkey,
            &sig,
            &proposal,
            reason,
            NOW,
        )
        .unwrap_err();
        assert!(
            err.contains("not a registered actor"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn authorize_accept_revoked_key_rejected() {
        let key = accept_keypair();
        let pubkey = crate::sign::pubkey_hex(&key);
        let mut actor = accept_actor("reviewer:will-blair", &pubkey);
        actor.revoked_at = Some("2026-05-10T00:00:00Z".to_string());
        actor.revoked_reason = Some("key rotated".to_string());
        let (project, proposal) = frontier_with_proposal(vec![actor]);
        let reason = "Verified";
        let sig = sign_accept(&key, VFR, &proposal.id, "reviewer:will-blair", reason);

        // NOW (2026-05-29) is after revoked_at → rejected even though
        // the signature itself is valid.
        let err = authorize_proposal_accept(&project, VFR, &pubkey, &sig, &proposal, reason, NOW)
            .unwrap_err();
        assert!(err.contains("revoked"), "unexpected error: {err}");
    }

    #[test]
    fn authorize_accept_non_reviewer_namespace_rejected() {
        // A registered, non-revoked actor in the agent: namespace with a
        // valid signature is still refused: it lacks reviewer authority.
        let key = accept_keypair();
        let pubkey = crate::sign::pubkey_hex(&key);
        let (project, proposal) =
            frontier_with_proposal(vec![accept_actor("agent:replicator", &pubkey)]);
        let reason = "Verified";
        let sig = sign_accept(&key, VFR, &proposal.id, "agent:replicator", reason);

        let err = authorize_proposal_accept(&project, VFR, &pubkey, &sig, &proposal, reason, NOW)
            .unwrap_err();
        assert!(
            err.contains("does not carry reviewer authority"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn authorize_accept_auto_notes_tier_does_not_grant_authority() {
        // The v0.6 write tier (auto-notes) never confers accept
        // authority: the id is still outside the reviewer: namespace.
        let key = accept_keypair();
        let pubkey = crate::sign::pubkey_hex(&key);
        let mut actor = accept_actor("agent:notes-compiler", &pubkey);
        actor.tier = Some("auto-notes".to_string());
        let (project, proposal) = frontier_with_proposal(vec![actor]);
        let reason = "Verified";
        let sig = sign_accept(&key, VFR, &proposal.id, "agent:notes-compiler", reason);

        let err = authorize_proposal_accept(&project, VFR, &pubkey, &sig, &proposal, reason, NOW)
            .unwrap_err();
        assert!(
            err.contains("does not carry reviewer authority"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn authorize_accept_placeholder_reviewer_rejected() {
        // A "reviewer:" prefix is necessary but not sufficient — a
        // placeholder reviewer id is refused.
        let key = accept_keypair();
        let pubkey = crate::sign::pubkey_hex(&key);
        // "reviewer" (bare) and "local-*" are placeholders.
        let (project, proposal) =
            frontier_with_proposal(vec![accept_actor("local-reviewer", &pubkey)]);
        let reason = "Verified";
        let sig = sign_accept(&key, VFR, &proposal.id, "local-reviewer", reason);
        let err = authorize_proposal_accept(&project, VFR, &pubkey, &sig, &proposal, reason, NOW)
            .unwrap_err();
        assert!(
            err.contains("does not carry reviewer authority"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn authorize_accept_empty_reason_rejected() {
        let key = accept_keypair();
        let pubkey = crate::sign::pubkey_hex(&key);
        let (project, proposal) =
            frontier_with_proposal(vec![accept_actor("reviewer:will-blair", &pubkey)]);
        let sig = sign_accept(&key, VFR, &proposal.id, "reviewer:will-blair", "   ");
        let err = authorize_proposal_accept(&project, VFR, &pubkey, &sig, &proposal, "   ", NOW)
            .unwrap_err();
        assert!(err.contains("Decision reason"), "unexpected error: {err}");
    }

    #[test]
    fn authorize_accept_resolves_pubkey_case_insensitively() {
        // The registry hex and the wire hex differ only in case; the
        // resolve must match (Ed25519 hex is case-insensitive).
        let key = accept_keypair();
        let pubkey = crate::sign::pubkey_hex(&key);
        let (project, proposal) = frontier_with_proposal(vec![accept_actor(
            "reviewer:will-blair",
            &pubkey.to_uppercase(),
        )]);
        let reason = "Verified";
        let sig = sign_accept(&key, VFR, &proposal.id, "reviewer:will-blair", reason);
        let auth = authorize_proposal_accept(
            &project, VFR, &pubkey, // lowercase on the wire
            &sig, &proposal, reason, NOW,
        )
        .unwrap();
        assert_eq!(auth.actor.id, "reviewer:will-blair");
    }

    // ── Signed review events + decision parity ────────────────────────

    fn review_events_for<'a>(project: &'a Project, proposal_id: &str) -> Vec<&'a StateEvent> {
        project
            .events
            .iter()
            .filter(|e| {
                e.target.r#type == "proposal"
                    && e.target.id == proposal_id
                    && e.kind.as_str().starts_with("review.")
            })
            .collect()
    }

    #[test]
    fn reject_emits_signed_review_event_and_parity_holds() {
        let key = accept_keypair();
        let pubkey = hex::encode(key.verifying_key().to_bytes());
        let (mut project, proposal) =
            frontier_with_proposal(vec![accept_actor("reviewer:will", &pubkey)]);
        reject_proposal_in_frontier_signed(
            &mut project,
            &proposal.id,
            "reviewer:will",
            "automated draft, not adjudicated",
            Some(&key),
            false,
        )
        .unwrap();

        // The decision is now a signed, log-resident event — the thing a
        // reject used to lack entirely.
        let reviews = review_events_for(&project, &proposal.id);
        assert_eq!(reviews.len(), 1, "exactly one review event");
        let ev = reviews[0];
        assert_eq!(ev.kind, events::EVENT_KIND_REVIEW_REJECTED);
        assert_eq!(ev.target.r#type, "proposal");
        assert!(ev.signature.is_some(), "review.rejected must be signed");
        assert!(
            crate::sign::verify_event_signature(ev, &pubkey).unwrap(),
            "signature must verify under the reviewer's registered key"
        );
        // Side-table: chain-transparent.
        assert_eq!(ev.before_hash, NULL_HASH);
        assert_eq!(ev.after_hash, NULL_HASH);
        // Stored status agrees with the log.
        let stored = &project
            .proposals
            .iter()
            .find(|p| p.id == proposal.id)
            .unwrap()
            .status;
        assert_eq!(stored, "rejected");
        assert!(
            verify_proposal_decision_parity(&project).is_empty(),
            "parity must hold after a signed reject"
        );
    }

    #[test]
    fn reject_requires_key_for_keyed_reviewer() {
        let key = accept_keypair();
        let pubkey = hex::encode(key.verifying_key().to_bytes());
        let (mut project, proposal) =
            frontier_with_proposal(vec![accept_actor("reviewer:will", &pubkey)]);
        // No key supplied → an agent cannot reject under a keyed identity.
        let err = reject_proposal_in_frontier_signed(
            &mut project,
            &proposal.id,
            "reviewer:will",
            "no key here",
            None,
            false,
        )
        .unwrap_err();
        assert!(
            err.contains("require") && err.contains("key"),
            "expected key-custody error, got: {err}"
        );
        // And nothing was recorded.
        assert!(review_events_for(&project, &proposal.id).is_empty());
    }

    #[test]
    fn reject_keyless_ok_for_unregistered_reviewer() {
        // Bootstrap: a reviewer with no registered key can still reject
        // (a brand-new frontier must be usable before any keys exist).
        let (mut project, proposal) = frontier_with_proposal(vec![]);
        reject_proposal_in_frontier_signed(
            &mut project,
            &proposal.id,
            "reviewer:bootstrap",
            "legacy reject",
            None,
            false,
        )
        .unwrap();
        let reviews = review_events_for(&project, &proposal.id);
        assert_eq!(reviews.len(), 1);
        assert!(reviews[0].signature.is_none(), "keyless reject is unsigned");
        assert!(verify_proposal_decision_parity(&project).is_empty());
    }

    #[test]
    fn parity_flags_status_with_no_backing_event() {
        // Hand-edit a status to "rejected" with no event behind it — the
        // exact tamper the mutable field used to allow silently.
        let (mut project, proposal) = frontier_with_proposal(vec![]);
        let idx = project
            .proposals
            .iter()
            .position(|p| p.id == proposal.id)
            .unwrap();
        project.proposals[idx].status = "rejected".to_string();
        project.proposals[idx].reviewed_by = Some("reviewer:ghost".to_string());
        let conflicts = verify_proposal_decision_parity(&project);
        assert_eq!(conflicts.len(), 1);
        assert!(conflicts[0].contains("NO decision event"));
    }

    #[test]
    fn backfill_makes_parity_hold_and_is_idempotent() {
        let (mut project, proposal) = frontier_with_proposal(vec![]);
        let idx = project
            .proposals
            .iter()
            .position(|p| p.id == proposal.id)
            .unwrap();
        project.proposals[idx].status = "rejected".to_string();
        project.proposals[idx].reviewed_by = Some("reviewer:legacy".to_string());
        project.proposals[idx].reviewed_at = Some("2026-06-01T00:00:00Z".to_string());
        project.proposals[idx].decision_reason = Some("old reject".to_string());

        assert!(!verify_proposal_decision_parity(&project).is_empty());
        let n = backfill_legacy_review_events(&mut project).unwrap();
        assert_eq!(n, 1);
        assert!(verify_proposal_decision_parity(&project).is_empty());

        // The backfilled event is honest about provenance: legacy + unsigned.
        let ev = review_events_for(&project, &proposal.id)[0];
        assert_eq!(ev.kind, events::EVENT_KIND_REVIEW_REJECTED);
        assert!(ev.signature.is_none());
        assert_eq!(
            ev.payload.get("legacy_backfill").and_then(Value::as_bool),
            Some(true)
        );
        // Idempotent: a second run adds nothing.
        assert_eq!(backfill_legacy_review_events(&mut project).unwrap(), 0);
    }

    #[test]
    fn accept_decision_is_recognized_by_its_domain_event() {
        // An accept's trace is the domain event it produces; parity must
        // recognize that without requiring a separate review.accepted.
        let (mut project, proposal) = frontier_with_proposal(vec![]);
        let event_id = accept_proposal_in_frontier_signed(
            &mut project,
            &proposal.id,
            "reviewer:test",
            "looks right",
            None,
        )
        .unwrap();
        let stored = project
            .proposals
            .iter()
            .find(|p| p.id == proposal.id)
            .unwrap();
        assert_eq!(stored.status, "applied");
        assert_eq!(stored.applied_event_id.as_deref(), Some(event_id.as_str()));
        assert!(
            verify_proposal_decision_parity(&project).is_empty(),
            "an applied proposal backed by its domain event satisfies parity"
        );
    }

    #[test]
    fn review_event_targeting_missing_proposal_is_flagged() {
        let (mut project, _proposal) = frontier_with_proposal(vec![]);
        let orphan = events::new_review_decision_event(
            "vpr_does_not_exist",
            "finding.add",
            "rejected",
            None,
            "reviewer:x",
            "orphan",
            Some("2026-06-01T00:00:00Z"),
            false,
        )
        .unwrap();
        project.events.push(orphan);
        let conflicts = verify_proposal_decision_parity(&project);
        assert!(
            conflicts.iter().any(|c| c.contains("does not exist")),
            "an orphan review event must be flagged: {conflicts:?}"
        );
    }
}
