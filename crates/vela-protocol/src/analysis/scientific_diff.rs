//! v0.193: Scientific Diff Pack (`vsd_*`).
//!
//! The per-proposal `carina.diff.v0.3` schema captures the change
//! a single proposal would induce on frontier state. A Scientific
//! Diff Pack sits one level up: it bundles N proposals into one
//! reviewable change-set so a reviewer sees a coherent unit
//! ("BBB-shared sister findings reconciled") rather than 12
//! individual events.
//!
//! Substrate-honest framing: the Pack is purely an aggregator. It
//! does NOT introduce new event semantics; applying the pack is
//! exactly equivalent to applying its member proposals in canonical
//! order through the existing reducer. The pack id is content-
//! addressed over the (frontier_id, ordered proposals,
//! aggregate_kind, summary, created_at) tuple and pinned by Lean
//! Theorem 23 (Scientific Diff Pack id injectivity).
//!
//! Composition with later cycles:
//!   - v0.195 vaa_*: Pack carries optional `agent_run: vaa_*` so
//!     a pack produced by an LLM agent links to its signed
//!     attestation envelope.
//!   - v0.200 ver_*: an Evaluation Record can target a `vsd_*`,
//!     letting "this pack was replicated by Lab X" be a first-
//!     class statement.
//!   - v0.201 diff_pack.released: a canonical event arm that turns
//!     a signed pack into a released record across hubs.

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::{frontier_policy, proposals, repo};

pub const SCIENTIFIC_DIFF_SCHEMA: &str = "vela.scientific_diff.v0.1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScientificDiffPack {
    pub schema: String,
    pub pack_id: String,
    pub frontier_id: String,
    pub created_at: String,
    pub summary: String,
    pub proposals: Vec<String>,
    pub aggregate_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_run: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_pack: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applied_event_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_pubkey_hex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiffPackOperationPreview {
    pub proposal_id: String,
    pub kind: String,
    pub operation_class: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_id: Option<String>,
    pub summary: String,
    #[serde(default)]
    pub source_or_evidence_refs: Vec<String>,
    #[serde(default)]
    pub downstream_affected_findings: Vec<String>,
    #[serde(default)]
    pub review_requirements: Vec<String>,
    #[serde(default)]
    pub review_class: String,
    #[serde(default)]
    pub required_reviewer_count: usize,
    #[serde(default)]
    pub required_reviewer_roles: Vec<String>,
    #[serde(default)]
    pub required_reason_fields: Vec<String>,
    #[serde(default)]
    pub allowed_agent_actions: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview_counts: Option<DiffPackPreviewCounts>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiffPackPreviewCounts {
    pub findings_before: usize,
    pub findings_after: usize,
    pub findings_delta: isize,
    pub artifacts_before: usize,
    pub artifacts_after: usize,
    pub artifacts_delta: isize,
    pub events_before: usize,
    pub events_after: usize,
    pub events_delta: isize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiffPackReviewSummary {
    pub pack_id: String,
    pub frontier_id: String,
    pub summary: String,
    pub aggregate_kind: String,
    pub members: usize,
    pub source_artifacts: Vec<String>,
    pub proposed_operations: Vec<DiffPackOperationPreview>,
    pub operation_counts: BTreeMap<String, usize>,
    pub preview_counts: DiffPackPreviewCounts,
    pub proof_freshness_impact: bool,
    pub affected_findings: Vec<String>,
    pub evidence_deltas: Vec<String>,
    pub confidence_deltas: Vec<String>,
    pub contradiction_effects: Vec<String>,
    pub downstream_impacts: Vec<String>,
    pub validation_results: Vec<String>,
    pub evidence_ci_summary: DiffPackEvidenceCiSummary,
    pub required_reviewers: Vec<String>,
    pub cli_equivalents: BTreeMap<String, String>,
    pub review_session_scope: String,
    pub review_session_commands: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiffPackEvidenceCiSummary {
    pub scope: String,
    pub status: String,
    pub total: usize,
    pub passed: usize,
    pub warnings: usize,
    pub failed: usize,
    pub release_blocking_failed: usize,
    pub command: String,
    pub caveat: String,
}

#[derive(Debug, Clone)]
pub struct PackDraft {
    pub frontier_id: String,
    pub created_at: String,
    pub summary: String,
    pub proposals: Vec<String>,
    pub aggregate_kind: String,
    pub agent_run: Option<String>,
    pub parent_pack: Option<String>,
}

impl ScientificDiffPack {
    /// Build an unsigned pack from a draft. The pack_id is
    /// content-addressed over canonical bytes; signing is a
    /// separate step via `sign`.
    pub fn build(draft: PackDraft) -> Result<Self, String> {
        validate_draft(&draft)?;
        let mut pack = Self {
            schema: SCIENTIFIC_DIFF_SCHEMA.to_string(),
            pack_id: String::new(),
            frontier_id: draft.frontier_id,
            created_at: draft.created_at,
            summary: draft.summary,
            proposals: draft.proposals,
            aggregate_kind: draft.aggregate_kind,
            agent_run: draft.agent_run,
            parent_pack: draft.parent_pack,
            applied_event_id: None,
            signature: None,
            signer_pubkey_hex: None,
        };
        pack.pack_id = pack.derive_id();
        Ok(pack)
    }

    /// Sign the pack with an Ed25519 key. Sets `signature` and
    /// `signer_pubkey_hex`; does NOT change `pack_id` (the pack
    /// is content-addressed over its body, not its signature).
    pub fn sign(&mut self, key: &SigningKey) {
        let preimage = self.preimage_bytes();
        self.signature = Some(hex::encode(crate::sign::sign_bytes(key, &preimage)));
        self.signer_pubkey_hex = Some(hex::encode(key.verifying_key().to_bytes()));
    }

    /// Canonical bytes over which pack_id is derived AND signatures
    /// are computed. The order of fields is fixed; any change to
    /// this method is a breaking schema bump.
    fn preimage_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.frontier_id.as_bytes());
        out.push(b'|');
        out.extend_from_slice(self.aggregate_kind.as_bytes());
        out.push(b'|');
        out.extend_from_slice(self.summary.as_bytes());
        out.push(b'|');
        out.extend_from_slice(self.created_at.as_bytes());
        out.push(b'|');
        for (i, vpr) in self.proposals.iter().enumerate() {
            if i > 0 {
                out.push(b',');
            }
            out.extend_from_slice(vpr.as_bytes());
        }
        out.push(b'|');
        if let Some(parent) = &self.parent_pack {
            out.extend_from_slice(parent.as_bytes());
        }
        out.push(b'|');
        if let Some(agent) = &self.agent_run {
            out.extend_from_slice(agent.as_bytes());
        }
        out
    }

    fn derive_id(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.preimage_bytes());
        format!("vsd_{}", &hex::encode(hasher.finalize())[..16])
    }

    /// Verify: pack_id matches re-derivation; if a signature is
    /// present, it verifies under the declared pubkey.
    pub fn verify(&self) -> Result<(), String> {
        let rederived = self.derive_id();
        if rederived != self.pack_id {
            return Err(format!(
                "pack_id mismatch: declared {}, rebuilt {}",
                self.pack_id, rederived
            ));
        }
        if let (Some(sig_hex), Some(pub_hex)) = (&self.signature, &self.signer_pubkey_hex) {
            if !crate::sign::verify_action_signature(&self.preimage_bytes(), sig_hex, pub_hex)? {
                return Err(
                    "scientific_diff signature does not verify under signer_pubkey_hex".to_string(),
                );
            }
        } else if self.signature.is_some() || self.signer_pubkey_hex.is_some() {
            return Err("signature and signer_pubkey_hex must be set together".to_string());
        }
        Ok(())
    }

    pub fn review_summary(&self, repo_path: &Path) -> DiffPackReviewSummary {
        let mut source_artifacts = BTreeSet::new();
        let mut affected_findings = BTreeSet::new();
        let mut evidence_deltas = BTreeSet::new();
        let mut confidence_deltas = BTreeSet::new();
        let mut contradiction_effects = BTreeSet::new();
        let mut downstream_impacts = BTreeSet::new();
        let mut proposed_operations = Vec::new();
        let mut operation_counts = BTreeMap::new();
        let project = repo::load_from_path(repo_path).ok();
        let policy = frontier_policy::load_policy_summary(repo_path).ok();
        let mut preview_counts = project
            .as_ref()
            .map(|frontier| DiffPackPreviewCounts {
                findings_before: frontier.findings.len(),
                findings_after: frontier.findings.len(),
                findings_delta: 0,
                artifacts_before: frontier.artifacts.len(),
                artifacts_after: frontier.artifacts.len(),
                artifacts_delta: 0,
                events_before: frontier.events.len(),
                events_after: frontier.events.len(),
                events_delta: 0,
            })
            .unwrap_or_default();
        let mut proof_freshness_impact = false;

        for proposal_id in &self.proposals {
            let proposal = read_member_proposal(repo_path, proposal_id);
            let kind = proposal
                .as_ref()
                .and_then(|v| string_at(v, &["kind"]))
                .unwrap_or_else(|| "proposal.reference".to_string());
            let operation_class = operation_class_for_kind(&kind, proposal.as_ref()).to_string();
            *operation_counts.entry(operation_class.clone()).or_default() += 1;
            let target_type = proposal
                .as_ref()
                .and_then(|v| string_at(v, &["target", "type"]));
            let target_id = proposal
                .as_ref()
                .and_then(|v| string_at(v, &["target", "id"]))
                .or_else(|| {
                    proposal
                        .as_ref()
                        .and_then(|v| string_at(v, &["payload", "finding_id"]))
                })
                .or_else(|| {
                    proposal
                        .as_ref()
                        .and_then(|v| string_at(v, &["payload", "finding", "id"]))
                });

            let explicit_reason = proposal
                .as_ref()
                .and_then(|v| string_at(v, &["reason"]))
                .filter(|s| !s.trim().is_empty());
            let narrative = proposal
                .as_ref()
                .and_then(|v| string_at(v, &["payload", "narrative"]));
            let summary = explicit_reason
                .clone()
                .or_else(|| narrative.clone())
                .unwrap_or_else(|| "Proposal referenced by id only".to_string());
            let confidence_reason = if operation_class == "revise_confidence" {
                explicit_reason.clone().or_else(|| {
                    proposal
                        .as_ref()
                        .and_then(|v| string_at(v, &["payload", "reason"]))
                })
            } else {
                None
            };

            let mut source_or_evidence_refs = collect_source_or_evidence_refs(proposal.as_ref());
            source_or_evidence_refs.sort();
            source_or_evidence_refs.dedup();

            if let Some(id) = &target_id
                && id.starts_with("vf_")
            {
                affected_findings.insert(id.clone());
            }
            if let Some(tension_with) = proposal
                .as_ref()
                .and_then(|v| string_at(v, &["payload", "tension_with"]))
            {
                affected_findings.insert(tension_with.clone());
                downstream_impacts.insert(format!("Review linked finding {tension_with}"));
            }
            let mut downstream_affected_findings = collect_downstream_findings(
                project.as_ref(),
                proposal.as_ref(),
                target_id.as_deref(),
            );
            for id in &downstream_affected_findings {
                affected_findings.insert(id.clone());
                downstream_impacts.insert(format!("{proposal_id}: affects linked finding {id}"));
            }

            if let Some(source_refs) = proposal.as_ref().and_then(|v| v.get("source_refs"))
                && let Some(arr) = source_refs.as_array()
            {
                for item in arr {
                    if let Some(s) = item.as_str() {
                        source_artifacts.insert(s.to_string());
                    }
                }
            }
            if let Some(pmid) = proposal
                .as_ref()
                .and_then(|v| string_at(v, &["payload", "finding", "provenance", "pmid"]))
            {
                source_artifacts.insert(format!("pmid:{pmid}"));
            }
            if let Some(doi) = proposal
                .as_ref()
                .and_then(|v| string_at(v, &["payload", "finding", "provenance", "doi"]))
            {
                source_artifacts.insert(format!("doi:{doi}"));
            }
            if let Some(title) = proposal
                .as_ref()
                .and_then(|v| string_at(v, &["payload", "finding", "provenance", "title"]))
            {
                source_artifacts.insert(title);
            }

            collect_evidence_spans(proposal.as_ref(), &mut evidence_deltas);
            if kind.contains("evidence") {
                evidence_deltas.insert(format!("{proposal_id}: evidence-affecting proposal"));
            }
            if kind.contains("confidence") {
                confidence_deltas.insert(format!("{proposal_id}: confidence-affecting proposal"));
            }
            if let Some(score) = proposal
                .as_ref()
                .and_then(|v| v.pointer("/payload/finding/confidence/score"))
                .and_then(|v| v.as_f64())
            {
                confidence_deltas.insert(format!("{proposal_id}: confidence score {score:.3}"));
            }
            if let Some(basis) = proposal
                .as_ref()
                .and_then(|v| string_at(v, &["payload", "finding", "confidence", "basis"]))
            {
                confidence_deltas.insert(format!("{proposal_id}: {basis}"));
            }

            if kind.contains("tension") || kind.contains("contradiction") {
                contradiction_effects.insert(format!(
                    "{proposal_id}: reviewer-visible tension or contradiction"
                ));
            }
            if let Some(tension_kind) = proposal
                .as_ref()
                .and_then(|v| string_at(v, &["payload", "tension_kind"]))
            {
                contradiction_effects.insert(format!("{proposal_id}: {tension_kind}"));
            }
            if let Some(action) = proposal
                .as_ref()
                .and_then(|v| string_at(v, &["payload", "proposed_action"]))
            {
                downstream_impacts.insert(format!("{proposal_id}: {action}"));
            }

            let policy_requirement = frontier_policy::review_requirement_for_operation(
                policy.as_ref(),
                &operation_class,
                &kind,
                !downstream_affected_findings.is_empty(),
            );
            let mut review_requirements = operation_review_requirements(
                &operation_class,
                !downstream_affected_findings.is_empty(),
            );
            review_requirements.extend(policy_requirement.reviewer_roles.iter().cloned());
            review_requirements.extend(
                policy_requirement
                    .required_reason_fields
                    .iter()
                    .map(|field| format!("reason:{field}")),
            );
            review_requirements.sort();
            review_requirements.dedup();

            let op_preview_counts = project.as_ref().and_then(|frontier| {
                proposals::preview_in_frontier(frontier, proposal_id, "reviewer:diff-pack-preview")
                    .ok()
                    .map(|preview| DiffPackPreviewCounts {
                        findings_before: preview.findings_before,
                        findings_after: preview.findings_after,
                        findings_delta: preview.findings_delta,
                        artifacts_before: preview.artifacts_before,
                        artifacts_after: preview.artifacts_after,
                        artifacts_delta: preview.artifacts_delta,
                        events_before: preview.events_before,
                        events_after: preview.events_after,
                        events_delta: preview.events_delta,
                    })
            });
            if let Some(counts) = &op_preview_counts {
                preview_counts.findings_after = (preview_counts.findings_after as isize
                    + counts.findings_delta)
                    .max(0) as usize;
                preview_counts.findings_delta += counts.findings_delta;
                preview_counts.artifacts_after = (preview_counts.artifacts_after as isize
                    + counts.artifacts_delta)
                    .max(0) as usize;
                preview_counts.artifacts_delta += counts.artifacts_delta;
                preview_counts.events_after =
                    (preview_counts.events_after as isize + counts.events_delta).max(0) as usize;
                preview_counts.events_delta += counts.events_delta;
                proof_freshness_impact |= counts.events_delta != 0
                    || counts.findings_delta != 0
                    || counts.artifacts_delta != 0;
            } else if proposal.is_some() {
                proof_freshness_impact = true;
            }

            proposed_operations.push(DiffPackOperationPreview {
                proposal_id: proposal_id.clone(),
                kind,
                operation_class,
                target_type,
                target_id,
                summary,
                source_or_evidence_refs,
                downstream_affected_findings: {
                    downstream_affected_findings.sort();
                    downstream_affected_findings.dedup();
                    downstream_affected_findings
                },
                review_requirements,
                review_class: policy_requirement.review_class,
                required_reviewer_count: policy_requirement.required_reviewer_count,
                required_reviewer_roles: policy_requirement.reviewer_roles,
                required_reason_fields: policy_requirement.required_reason_fields,
                allowed_agent_actions: policy_requirement.allowed_agent_actions,
                confidence_reason,
                preview_counts: op_preview_counts,
            });
        }

        let mut validation_results = Vec::new();
        validation_results.push("pack id verified from canonical bytes".to_string());
        if self.signature.is_some() {
            validation_results.push("signature present and verified".to_string());
        } else {
            validation_results.push("unsigned pack".to_string());
        }
        validation_results.push(format!(
            "{} member proposal{} resolved for review",
            proposed_operations.len(),
            if proposed_operations.len() == 1 {
                ""
            } else {
                "s"
            }
        ));
        if source_artifacts.is_empty() {
            validation_results
                .push("no explicit source artifacts declared by member proposals".to_string());
        }
        for op in &proposed_operations {
            if op.operation_class == "revise_confidence" {
                if op.source_or_evidence_refs.is_empty() {
                    validation_results.push(format!(
                        "{}: confidence operation missing source or evidence reference",
                        op.proposal_id
                    ));
                }
                if op
                    .confidence_reason
                    .as_deref()
                    .unwrap_or_default()
                    .trim()
                    .is_empty()
                {
                    validation_results.push(format!(
                        "{}: confidence operation missing review reason",
                        op.proposal_id
                    ));
                }
            }
        }

        let mut required_reviewers = BTreeSet::new();
        required_reviewers.insert("local_reviewer".to_string());
        if !confidence_deltas.is_empty() {
            required_reviewers.insert("domain_reviewer".to_string());
        }
        if !contradiction_effects.is_empty() {
            required_reviewers.insert("method_reviewer".to_string());
        }
        for op in &proposed_operations {
            for role in &op.required_reviewer_roles {
                required_reviewers.insert(role.clone());
            }
        }
        let evidence_ci_summary = diff_pack_evidence_ci_summary(
            &self.pack_id,
            source_artifacts.is_empty(),
            &proposed_operations,
        );

        let mut cli_equivalents = BTreeMap::new();
        cli_equivalents.insert(
            "inspect".to_string(),
            format!("vela diff-pack inspect <frontier> {} --json", self.pack_id),
        );
        cli_equivalents.insert(
            "verify".to_string(),
            format!(
                "vela diff-pack verify <frontier>/.vela/diff_packs/{}.json",
                self.pack_id
            ),
        );
        cli_equivalents.insert(
            "evidence_ci".to_string(),
            format!(
                "vela diff-pack validate <frontier> {} --evidence-ci --json",
                self.pack_id
            ),
        );
        cli_equivalents.insert(
            "accept".to_string(),
            format!(
                "vela diff-pack promote-verdicts <frontier> --json # after local verdict on {}",
                self.pack_id
            ),
        );
        let review_session_scope = format!("diff_pack:{}", self.pack_id);
        let mut review_session_commands = BTreeMap::new();
        review_session_commands.insert(
            "start".to_string(),
            format!(
                "vela review-session start <frontier> --reviewer reviewer:external --scope {} --json",
                review_session_scope
            ),
        );
        review_session_commands.insert(
            "note".to_string(),
            format!(
                "vela review-session note <frontier> vrs_SESSION --object {} --note 'bounded reviewer note' --json",
                self.pack_id
            ),
        );
        review_session_commands.insert(
            "close".to_string(),
            "vela review-session close <frontier> vrs_SESSION --decision needs_revision --reason 'bounded reviewer reason' --json".to_string(),
        );

        DiffPackReviewSummary {
            pack_id: self.pack_id.clone(),
            frontier_id: self.frontier_id.clone(),
            summary: self.summary.clone(),
            aggregate_kind: self.aggregate_kind.clone(),
            members: self.proposals.len(),
            source_artifacts: sorted(source_artifacts),
            proposed_operations,
            operation_counts,
            preview_counts,
            proof_freshness_impact,
            affected_findings: sorted(affected_findings),
            evidence_deltas: sorted(evidence_deltas),
            confidence_deltas: sorted(confidence_deltas),
            contradiction_effects: sorted(contradiction_effects),
            downstream_impacts: sorted(downstream_impacts),
            validation_results,
            evidence_ci_summary,
            required_reviewers: sorted(required_reviewers),
            cli_equivalents,
            review_session_scope,
            review_session_commands,
        }
    }
}

fn diff_pack_evidence_ci_summary(
    pack_id: &str,
    missing_source_artifacts: bool,
    operations: &[DiffPackOperationPreview],
) -> DiffPackEvidenceCiSummary {
    let mut total = 2;
    let mut failed = usize::from(missing_source_artifacts);

    for op in operations {
        total += 1;
        if op.required_reviewer_count == 0 || op.required_reviewer_roles.is_empty() {
            failed += 1;
        }
        if op.operation_class == "revise_confidence" {
            total += 2;
            if op.source_or_evidence_refs.is_empty() {
                failed += 1;
            }
            if op
                .confidence_reason
                .as_deref()
                .unwrap_or_default()
                .trim()
                .is_empty()
            {
                failed += 1;
            }
        }
    }

    DiffPackEvidenceCiSummary {
        scope: format!("diff_pack:{pack_id}"),
        status: if failed == 0 {
            "ready".to_string()
        } else {
            "blocked".to_string()
        },
        total,
        passed: total.saturating_sub(failed),
        warnings: 0,
        failed,
        release_blocking_failed: failed,
        command: format!("vela diff-pack validate <frontier> {pack_id} --evidence-ci --json"),
        caveat: "Evidence CI checks review readiness. It does not accept scientific state."
            .to_string(),
    }
}

fn operation_class_for_kind(kind: &str, proposal: Option<&serde_json::Value>) -> &'static str {
    let normalized = kind.to_ascii_lowercase();
    if normalized.contains("contradiction")
        || normalized.contains("tension")
        || string_at_optional(proposal, &["payload", "tension_kind"]).is_some()
        || string_at_optional(proposal, &["payload", "tension_with"]).is_some()
    {
        return "mark_contradiction";
    }
    if normalized.contains("downstream") || normalized.contains("review_request") {
        return "request_downstream_review";
    }
    if normalized.contains("open_gap")
        || normalized.contains("gap.open")
        || proposal
            .and_then(|p| p.pointer("/payload/finding/flags/gap"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    {
        return "open_gap";
    }
    if normalized.contains("confidence") {
        return "revise_confidence";
    }
    if normalized.contains("caveat") {
        return "add_caveat";
    }
    if normalized.contains("span_repair") || normalized.contains("span.repair") {
        return "repair_span";
    }
    if normalized.contains("locator_repair") || normalized.contains("locator.repair") {
        return "repair_locator";
    }
    if normalized.contains("evidence") {
        return "add_evidence_atom";
    }
    if normalized.contains("link") {
        return "add_link";
    }
    if normalized == "finding.add" || normalized.ends_with(".finding.add") {
        return "add_finding";
    }
    "request_downstream_review"
}

fn operation_review_requirements(
    operation_class: &str,
    has_downstream_impact: bool,
) -> Vec<String> {
    let mut out = BTreeSet::new();
    out.insert("local_reviewer".to_string());
    match operation_class {
        "revise_confidence" | "mark_contradiction" => {
            out.insert("domain_reviewer".to_string());
            out.insert("method_reviewer".to_string());
        }
        "add_evidence_atom" | "repair_locator" | "repair_span" => {
            out.insert("source_reviewer".to_string());
        }
        "open_gap" | "request_downstream_review" => {
            out.insert("frontier_reviewer".to_string());
        }
        _ => {}
    }
    if has_downstream_impact {
        out.insert("frontier_reviewer".to_string());
    }
    out.into_iter().collect()
}

fn sorted(set: BTreeSet<String>) -> Vec<String> {
    set.into_iter().collect()
}

fn read_member_proposal(repo_path: &Path, proposal_id: &str) -> Option<serde_json::Value> {
    for dir in ["agent_proposals", "proposals"] {
        let path = repo_path
            .join(".vela")
            .join(dir)
            .join(format!("{proposal_id}.json"));
        if let Ok(body) = std::fs::read_to_string(path)
            && let Ok(value) = serde_json::from_str::<serde_json::Value>(&body)
        {
            return Some(value);
        }
    }
    None
}

fn string_at(value: &serde_json::Value, path: &[&str]) -> Option<String> {
    let mut cur = value;
    for key in path {
        cur = cur.get(*key)?;
    }
    cur.as_str().map(ToString::to_string)
}

fn string_at_optional(value: Option<&serde_json::Value>, path: &[&str]) -> Option<String> {
    value.and_then(|v| string_at(v, path))
}

fn collect_source_or_evidence_refs(proposal: Option<&serde_json::Value>) -> Vec<String> {
    let mut out = BTreeSet::new();
    let Some(proposal) = proposal else {
        return Vec::new();
    };
    if let Some(source_refs) = proposal.get("source_refs").and_then(|v| v.as_array()) {
        for item in source_refs {
            if let Some(s) = item.as_str()
                && !s.trim().is_empty()
            {
                out.insert(s.to_string());
            }
        }
    }
    collect_ref_strings_recursive(proposal, &mut out);
    out.into_iter().collect()
}

fn collect_ref_strings_recursive(value: &serde_json::Value, out: &mut BTreeSet<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                let key_lower = key.to_ascii_lowercase();
                if (key_lower.contains("source") || key_lower.contains("evidence"))
                    && key_lower.contains("ref")
                {
                    match child {
                        serde_json::Value::String(s) if !s.trim().is_empty() => {
                            out.insert(s.to_string());
                        }
                        serde_json::Value::Array(arr) => {
                            for item in arr {
                                if let Some(s) = item.as_str()
                                    && !s.trim().is_empty()
                                {
                                    out.insert(s.to_string());
                                }
                            }
                        }
                        _ => {}
                    }
                }
                collect_ref_strings_recursive(child, out);
            }
        }
        serde_json::Value::Array(arr) => {
            for child in arr {
                collect_ref_strings_recursive(child, out);
            }
        }
        _ => {}
    }
}

fn collect_downstream_findings(
    project: Option<&crate::project::Project>,
    proposal: Option<&serde_json::Value>,
    target_id: Option<&str>,
) -> Vec<String> {
    let mut out = BTreeSet::new();
    for key in [
        "tension_with",
        "downstream_finding",
        "downstream_review",
        "linked_finding",
        "linked_findings",
        "to_finding",
        "from_finding",
    ] {
        collect_payload_finding_refs(proposal, key, &mut out);
    }
    if let (Some(project), Some(target_id)) = (project, target_id) {
        for finding in &project.findings {
            if finding.id == target_id {
                for link in &finding.links {
                    if link.target.starts_with("vf_") {
                        out.insert(link.target.clone());
                    }
                }
            }
            for link in &finding.links {
                if link.target == target_id && finding.id.starts_with("vf_") {
                    out.insert(finding.id.clone());
                }
            }
        }
    }
    out.remove(target_id.unwrap_or_default());
    out.into_iter().collect()
}

fn collect_payload_finding_refs(
    proposal: Option<&serde_json::Value>,
    key: &str,
    out: &mut BTreeSet<String>,
) {
    let Some(value) = proposal.and_then(|v| v.pointer(&format!("/payload/{key}"))) else {
        return;
    };
    match value {
        serde_json::Value::String(s) if s.starts_with("vf_") => {
            out.insert(s.to_string());
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                if let Some(s) = item.as_str()
                    && s.starts_with("vf_")
                {
                    out.insert(s.to_string());
                }
            }
        }
        _ => {}
    }
}

fn collect_evidence_spans(proposal: Option<&serde_json::Value>, out: &mut BTreeSet<String>) {
    let Some(proposal) = proposal else {
        return;
    };
    let Some(spans) = proposal.pointer("/payload/finding/evidence/evidence_spans") else {
        return;
    };
    let Some(arr) = spans.as_array() else {
        return;
    };
    for span in arr {
        if let Some(text) = span.get("text").and_then(|v| v.as_str()) {
            let clipped: String = text.chars().take(180).collect();
            out.insert(clipped);
        }
    }
}

fn validate_draft(d: &PackDraft) -> Result<(), String> {
    if !d.frontier_id.starts_with("vfr_") {
        return Err(format!(
            "frontier_id must start with `vfr_`, got `{}`",
            d.frontier_id
        ));
    }
    if d.summary.is_empty() {
        return Err("summary cannot be empty".to_string());
    }
    if d.summary.chars().count() > 280 {
        return Err("summary exceeds 280 chars".to_string());
    }
    if d.proposals.is_empty() {
        return Err("a pack must bundle at least one proposal".to_string());
    }
    for vpr in &d.proposals {
        if !vpr.starts_with("vpr_") {
            return Err(format!("every member must start with `vpr_`, got `{vpr}`"));
        }
    }
    if d.aggregate_kind.is_empty() {
        return Err("aggregate_kind cannot be empty".to_string());
    }
    if let Some(parent) = &d.parent_pack
        && !parent.starts_with("vsd_")
    {
        return Err(format!(
            "parent_pack must start with `vsd_`, got `{parent}`"
        ));
    }
    if let Some(agent) = &d.agent_run
        && !agent.starts_with("vaa_")
    {
        return Err(format!("agent_run must start with `vaa_`, got `{agent}`"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn ok_draft() -> PackDraft {
        PackDraft {
            frontier_id: "vfr_5076e7b3ff8e6b0f".to_string(),
            created_at: "2026-05-11T00:00:00Z".to_string(),
            summary: "Test pack — bundles two proposals.".to_string(),
            proposals: vec!["vpr_a1".to_string(), "vpr_b2".to_string()],
            aggregate_kind: "finding.cluster_revision".to_string(),
            agent_run: None,
            parent_pack: None,
        }
    }

    #[test]
    fn operation_classifies_scientific_diff_operations() {
        let cases = [
            ("finding.add", "add_finding"),
            ("evidence_atom.add", "add_evidence_atom"),
            ("finding.locator_repair", "repair_locator"),
            ("finding.span_repair", "repair_span"),
            ("link.add", "add_link"),
            ("finding.caveat", "add_caveat"),
            ("finding.confidence_revise", "revise_confidence"),
            ("finding.contradiction", "mark_contradiction"),
            ("finding.open_gap", "open_gap"),
            ("finding.downstream_review", "request_downstream_review"),
        ];
        for (kind, expected) in cases {
            assert_eq!(operation_class_for_kind(kind, None), expected);
        }
    }

    #[test]
    fn review_summary_exposes_operation_semantics() {
        let tmp = tempfile::tempdir().unwrap();
        let proposals = tmp.path().join(".vela").join("agent_proposals");
        std::fs::create_dir_all(&proposals).unwrap();
        std::fs::write(
            proposals.join("vpr_confidence.json"),
            r#"{
              "id":"vpr_confidence",
              "kind":"finding.confidence_revise",
              "target":{"type":"finding","id":"vf_claim"},
              "reason":"confidence moved because source evidence narrowed the claim",
              "source_refs":["pmid:123"],
              "payload":{
                "finding_id":"vf_claim",
                "score":0.42,
                "evidence_ref":"evidence:abc",
                "downstream_review":["vf_child"],
                "linked_findings":["vf_child"]
              }
            }"#,
        )
        .unwrap();
        let pack = ScientificDiffPack::build(PackDraft {
            frontier_id: "vfr_5076e7b3ff8e6b0f".to_string(),
            created_at: "2026-05-13T00:00:00Z".to_string(),
            summary: "Review one confidence-moving operation.".to_string(),
            proposals: vec!["vpr_confidence".to_string()],
            aggregate_kind: "confidence.review".to_string(),
            agent_run: None,
            parent_pack: None,
        })
        .unwrap();

        let summary = pack.review_summary(tmp.path());
        assert_eq!(summary.operation_counts["revise_confidence"], 1);
        assert!(summary.proof_freshness_impact);
        let op = summary.proposed_operations.first().unwrap();
        assert_eq!(op.operation_class, "revise_confidence");
        assert_eq!(
            op.confidence_reason.as_deref(),
            Some("confidence moved because source evidence narrowed the claim")
        );
        assert!(op.source_or_evidence_refs.contains(&"pmid:123".to_string()));
        assert!(
            op.source_or_evidence_refs
                .contains(&"evidence:abc".to_string())
        );
        assert!(
            op.review_requirements
                .contains(&"domain_reviewer".to_string())
        );
        assert!(
            op.downstream_affected_findings
                .contains(&"vf_child".to_string())
        );
        assert_eq!(
            summary.review_session_scope,
            format!("diff_pack:{}", pack.pack_id)
        );
        assert_eq!(
            summary.evidence_ci_summary.scope,
            summary.review_session_scope
        );
        assert!(summary.evidence_ci_summary.total >= summary.proposed_operations.len());
        assert!(
            summary
                .evidence_ci_summary
                .command
                .contains("diff-pack validate")
        );
        assert!(
            summary
                .review_session_commands
                .get("start")
                .unwrap()
                .contains("vela review-session start")
        );
    }

    #[test]
    fn review_summary_marks_missing_confidence_support() {
        let tmp = tempfile::tempdir().unwrap();
        let proposals = tmp.path().join(".vela").join("agent_proposals");
        std::fs::create_dir_all(&proposals).unwrap();
        std::fs::write(
            proposals.join("vpr_confidence.json"),
            r#"{
              "id":"vpr_confidence",
              "kind":"finding.confidence_revise",
              "target":{"type":"finding","id":"vf_claim"},
              "reason":"",
              "source_refs":[],
              "payload":{"finding_id":"vf_claim"}
            }"#,
        )
        .unwrap();
        let pack = ScientificDiffPack::build(PackDraft {
            frontier_id: "vfr_5076e7b3ff8e6b0f".to_string(),
            created_at: "2026-05-13T00:00:00Z".to_string(),
            summary: "Review one incomplete confidence operation.".to_string(),
            proposals: vec!["vpr_confidence".to_string()],
            aggregate_kind: "confidence.review".to_string(),
            agent_run: None,
            parent_pack: None,
        })
        .unwrap();

        let summary = pack.review_summary(tmp.path());
        assert!(summary.validation_results.iter().any(|line| {
            line.contains("vpr_confidence")
                && line.contains("confidence operation missing source or evidence reference")
        }));
        assert!(summary.validation_results.iter().any(|line| {
            line.contains("vpr_confidence")
                && line.contains("confidence operation missing review reason")
        }));
    }

    #[test]
    fn builds_and_id_is_deterministic() {
        let p1 = ScientificDiffPack::build(ok_draft()).unwrap();
        let p2 = ScientificDiffPack::build(ok_draft()).unwrap();
        assert_eq!(p1.pack_id, p2.pack_id);
        assert!(p1.pack_id.starts_with("vsd_"));
        assert_eq!(p1.pack_id.len(), 4 + 16);
    }

    #[test]
    fn different_proposals_produce_different_ids() {
        let p1 = ScientificDiffPack::build(ok_draft()).unwrap();
        let mut d2 = ok_draft();
        d2.proposals = vec!["vpr_b2".to_string(), "vpr_a1".to_string()];
        let p2 = ScientificDiffPack::build(d2).unwrap();
        assert_ne!(p1.pack_id, p2.pack_id, "order matters in pack_id");
    }

    #[test]
    fn empty_pack_rejected() {
        let mut d = ok_draft();
        d.proposals.clear();
        assert!(ScientificDiffPack::build(d).is_err());
    }

    #[test]
    fn non_vpr_member_rejected() {
        let mut d = ok_draft();
        d.proposals[0] = "vsd_not_a_vpr".to_string();
        assert!(ScientificDiffPack::build(d).is_err());
    }

    #[test]
    fn summary_length_capped() {
        let mut d = ok_draft();
        d.summary = "x".repeat(281);
        assert!(ScientificDiffPack::build(d).is_err());
    }

    #[test]
    fn sign_then_verify() {
        let mut pack = ScientificDiffPack::build(ok_draft()).unwrap();
        pack.sign(&key());
        pack.verify().expect("verifies after signing");
    }

    #[test]
    fn tampered_body_after_sign_fails_verify() {
        let mut pack = ScientificDiffPack::build(ok_draft()).unwrap();
        pack.sign(&key());
        pack.summary = "different summary".to_string();
        // pack_id no longer matches re-derivation.
        assert!(pack.verify().is_err());
    }

    #[test]
    fn unsigned_pack_verifies_without_keys() {
        let pack = ScientificDiffPack::build(ok_draft()).unwrap();
        pack.verify().expect("unsigned pack still verifies its id");
    }

    #[test]
    fn cross_impl_python_sdk_pinned_id() {
        // v0.196: the Python `vela_agent` SDK mirrors this canonical-
        // bytes layout. The constants below are produced by the
        // Python SDK on the exact same inputs (see
        // clients/python/vela_agent/tests/test_primitives.py). Any
        // drift in either implementation flags here.
        let p = ScientificDiffPack::build(PackDraft {
            frontier_id: "vfr_5076e7b3ff8e6b0f".to_string(),
            created_at: "2026-05-11T00:00:00Z".to_string(),
            summary: "Test pack — bundles two proposals.".to_string(),
            proposals: vec!["vpr_a1".to_string(), "vpr_b2".to_string()],
            aggregate_kind: "finding.cluster_revision".to_string(),
            agent_run: None,
            parent_pack: None,
        })
        .unwrap();
        assert_eq!(p.pack_id, "vsd_cd2a0071e7ffbffd");
    }

    #[test]
    fn round_trips_through_json() {
        let mut pack = ScientificDiffPack::build(ok_draft()).unwrap();
        pack.sign(&key());
        let s = serde_json::to_string(&pack).unwrap();
        let back: ScientificDiffPack = serde_json::from_str(&s).unwrap();
        assert_eq!(pack, back);
        back.verify().unwrap();
    }
}
