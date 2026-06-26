//! Proposal data types: the StateProposal record, agent-run provenance, proof
//! state, accept/preview/validation reports. Re-exported flat from the parent.

use super::*;

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
