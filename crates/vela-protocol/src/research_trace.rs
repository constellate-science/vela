//! Research traces as reviewed source material.
//!
//! A research trace records a bounded agent, benchmark, proof-search, or
//! analysis run. The trace may draft review proposals, but it does not mutate
//! frontier state by itself.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::events::StateTarget;
use crate::project::Project;
use crate::proposals::{self, StateProposal};

pub const RESEARCH_TRACE_SCHEMA: &str = "vela.research_trace.v0.1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResearchTrace {
    pub schema: String,
    pub trace_id: String,
    pub created_at: String,
    pub producer: TraceProducer,
    pub objective: String,
    #[serde(default)]
    pub scope: Value,
    #[serde(default)]
    pub source_inputs: Vec<TraceSourceInput>,
    #[serde(default)]
    pub state_outputs: TraceStateOutputs,
    #[serde(default)]
    pub verifier_attachments: Vec<TraceVerifierAttachment>,
    pub formalization_fidelity: FormalizationFidelity,
    pub authority_boundary: AuthorityBoundary,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceProducer {
    pub kind: String,
    pub id: String,
    #[serde(default)]
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceSourceInput {
    pub id: String,
    pub kind: String,
    pub locator: String,
    pub content_hash: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceStateOutputs {
    #[serde(default)]
    pub candidate_findings: Vec<TraceCandidateFinding>,
    #[serde(default)]
    pub open_needs: Vec<TraceOpenNeed>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceCandidateFinding {
    pub id: String,
    pub assertion: String,
    #[serde(default)]
    pub evidence_source_ids: Vec<String>,
    #[serde(default)]
    pub conditions: Vec<String>,
    #[serde(default)]
    pub caveats: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceOpenNeed {
    pub id: String,
    pub question: String,
    #[serde(default)]
    pub reviewer_role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceVerifierAttachment {
    pub id: String,
    pub kind: String,
    pub locator: String,
    pub content_hash: String,
    pub verifies: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FormalizationFidelity {
    pub required: bool,
    pub source_claim: String,
    pub stored_claim: String,
    pub review_question: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorityBoundary {
    pub trace_is_truth: bool,
    pub trace_mutates_frontier_state: bool,
    pub trace_accepts_findings: bool,
    pub trace_resolves_consensus: bool,
    pub reviewer_acceptance_required: bool,
    pub accepted_event_required_for_state_change: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceValidationSummary {
    pub source_inputs: usize,
    pub candidate_findings: usize,
    pub open_needs: usize,
    pub verifier_attachments: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceValidationReport {
    pub ok: bool,
    pub trace: TraceReport,
    pub summary: TraceValidationSummary,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceReport {
    pub trace_id: String,
    pub schema: String,
    pub created_at: String,
    pub producer: String,
    pub content_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PacketVerifierAttachment {
    pub trace_id: String,
    pub id: String,
    pub kind: String,
    pub locator: String,
    pub content_hash: String,
    pub verifies: String,
}

impl ResearchTrace {
    pub fn from_path(path: &Path) -> Result<Self, String> {
        let data = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read research trace {}: {e}", path.display()))?;
        serde_json::from_str(&data)
            .map_err(|e| format!("Failed to parse research trace {}: {e}", path.display()))
    }

    pub fn validate(&self) -> Result<TraceValidationSummary, Vec<String>> {
        let mut issues = Vec::new();

        if self.schema != RESEARCH_TRACE_SCHEMA {
            issues.push(format!(
                "schema must be `{RESEARCH_TRACE_SCHEMA}`, got `{}`",
                self.schema
            ));
        }
        require_non_empty("trace_id", &self.trace_id, &mut issues);
        if !self.trace_id.starts_with("vrt_") {
            issues.push("trace_id must start with `vrt_`".to_string());
        }
        require_non_empty("created_at", &self.created_at, &mut issues);
        require_non_empty("producer.id", &self.producer.id, &mut issues);
        require_non_empty("producer.kind", &self.producer.kind, &mut issues);
        require_non_empty("objective", &self.objective, &mut issues);

        validate_authority_boundary(&self.authority_boundary, &mut issues);
        validate_formalization_fidelity(&self.formalization_fidelity, &mut issues);

        if self.source_inputs.is_empty() {
            issues.push("source_inputs must contain at least one source".to_string());
        }
        let mut source_ids = BTreeSet::new();
        for source in &self.source_inputs {
            require_non_empty("source_inputs[].id", &source.id, &mut issues);
            require_non_empty("source_inputs[].kind", &source.kind, &mut issues);
            require_non_empty("source_inputs[].locator", &source.locator, &mut issues);
            if !source_ids.insert(source.id.clone()) {
                issues.push(format!("duplicate source input id `{}`", source.id));
            }
            if !is_sha256_uri(&source.content_hash) {
                issues.push(format!(
                    "source input `{}` content_hash must be sha256:<64 hex>",
                    source.id
                ));
            }
        }

        for candidate in &self.state_outputs.candidate_findings {
            require_non_empty("candidate_findings[].id", &candidate.id, &mut issues);
            require_non_empty(
                "candidate_findings[].assertion",
                &candidate.assertion,
                &mut issues,
            );
            if candidate.evidence_source_ids.is_empty() {
                issues.push(format!(
                    "candidate finding `{}` must name evidence_source_ids",
                    candidate.id
                ));
            }
            for source_id in &candidate.evidence_source_ids {
                if !source_ids.contains(source_id) {
                    issues.push(format!(
                        "candidate finding `{}` references unknown source `{}`",
                        candidate.id, source_id
                    ));
                }
            }
        }
        for need in &self.state_outputs.open_needs {
            require_non_empty("open_needs[].id", &need.id, &mut issues);
            require_non_empty("open_needs[].question", &need.question, &mut issues);
        }
        for attachment in &self.verifier_attachments {
            require_non_empty("verifier_attachments[].id", &attachment.id, &mut issues);
            require_non_empty("verifier_attachments[].kind", &attachment.kind, &mut issues);
            require_non_empty(
                "verifier_attachments[].locator",
                &attachment.locator,
                &mut issues,
            );
            require_non_empty(
                "verifier_attachments[].verifies",
                &attachment.verifies,
                &mut issues,
            );
            if !is_sha256_uri(&attachment.content_hash) {
                issues.push(format!(
                    "verifier attachment `{}` content_hash must be sha256:<64 hex>",
                    attachment.id
                ));
            }
        }

        if issues.is_empty() {
            Ok(self.summary())
        } else {
            Err(issues)
        }
    }

    pub fn summary(&self) -> TraceValidationSummary {
        TraceValidationSummary {
            source_inputs: self.source_inputs.len(),
            candidate_findings: self.state_outputs.candidate_findings.len(),
            open_needs: self.state_outputs.open_needs.len(),
            verifier_attachments: self.verifier_attachments.len(),
        }
    }

    pub fn packet_verifier_attachments(&self) -> Vec<PacketVerifierAttachment> {
        self.verifier_attachments
            .iter()
            .map(|attachment| PacketVerifierAttachment {
                trace_id: self.trace_id.clone(),
                id: attachment.id.clone(),
                kind: attachment.kind.clone(),
                locator: attachment.locator.clone(),
                content_hash: attachment.content_hash.clone(),
                verifies: attachment.verifies.clone(),
            })
            .collect()
    }
}

pub fn validate_trace_file(path: &Path) -> Result<TraceValidationReport, String> {
    let trace = ResearchTrace::from_path(path)?;
    let data = fs::read(path)
        .map_err(|e| format!("Failed to read research trace {}: {e}", path.display()))?;
    let report = TraceReport {
        trace_id: trace.trace_id.clone(),
        schema: trace.schema.clone(),
        created_at: trace.created_at.clone(),
        producer: trace.producer.id.clone(),
        content_hash: format!("sha256:{}", hex::encode(Sha256::digest(data))),
    };
    match trace.validate() {
        Ok(summary) => Ok(TraceValidationReport {
            ok: true,
            trace: report,
            summary,
            issues: Vec::new(),
        }),
        Err(issues) => Err(format!(
            "Research trace validation failed for {}: {}",
            path.display(),
            issues.join("; ")
        )),
    }
}

pub fn proposals_from_trace_file(
    path: &Path,
    frontier: &Project,
) -> Result<Vec<StateProposal>, String> {
    let trace = ResearchTrace::from_path(path)?;
    trace.validate().map_err(|issues| issues.join("; "))?;
    Ok(proposals_from_trace(&trace, frontier))
}

pub fn proposals_from_trace(trace: &ResearchTrace, frontier: &Project) -> Vec<StateProposal> {
    let mut proposals = Vec::new();
    let source_refs = vec![trace.trace_id.clone()];
    let actor_id = trace.producer.id.clone();
    let actor_type = trace.producer.kind.clone();
    let frontier_id = frontier
        .frontier_id
        .clone()
        .unwrap_or_else(|| frontier.project.name.clone());

    for candidate in &trace.state_outputs.candidate_findings {
        let payload = json!({
            "trace_id": trace.trace_id,
            "frontier": frontier_id,
            "output_kind": "candidate_finding",
            "candidate": candidate,
            "source_inputs": sources_by_id(trace, &candidate.evidence_source_ids),
            "verifier_attachments": trace.verifier_attachments,
            "formalization_fidelity": trace.formalization_fidelity,
            "authority_boundary": trace.authority_boundary,
        });
        proposals.push(proposals::new_proposal(
            "research_trace.review",
            StateTarget {
                r#type: "frontier_observation".to_string(),
                id: observation_id(&trace.trace_id, &candidate.id),
            },
            actor_id.clone(),
            actor_type.clone(),
            format!(
                "Review candidate finding `{}` from research trace",
                candidate.id
            ),
            payload,
            source_refs.clone(),
            candidate.caveats.clone(),
        ));
    }

    for need in &trace.state_outputs.open_needs {
        let payload = json!({
            "trace_id": trace.trace_id,
            "frontier": frontier_id,
            "output_kind": "open_need",
            "open_need": need,
            "source_inputs": trace.source_inputs,
            "verifier_attachments": trace.verifier_attachments,
            "formalization_fidelity": trace.formalization_fidelity,
            "authority_boundary": trace.authority_boundary,
        });
        proposals.push(proposals::new_proposal(
            "research_trace.review",
            StateTarget {
                r#type: "frontier_observation".to_string(),
                id: observation_id(&trace.trace_id, &need.id),
            },
            actor_id.clone(),
            actor_type.clone(),
            format!("Review open need `{}` from research trace", need.id),
            payload,
            source_refs.clone(),
            Vec::new(),
        ));
    }
    proposals
}

pub fn load_traces_for_frontier(source_path: Option<&Path>) -> Result<Vec<ResearchTrace>, String> {
    let Some(root) = trace_root(source_path) else {
        return Ok(Vec::new());
    };
    let trace_dir = root.join("sources/research-traces");
    if !trace_dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut paths = fs::read_dir(&trace_dir)
        .map_err(|e| {
            format!(
                "Failed to read research trace dir {}: {e}",
                trace_dir.display()
            )
        })?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect::<Vec<PathBuf>>();
    paths.sort();
    let mut traces = Vec::new();
    for path in paths {
        let trace = ResearchTrace::from_path(&path)?;
        trace.validate().map_err(|issues| {
            format!(
                "Research trace validation failed for {}: {}",
                path.display(),
                issues.join("; ")
            )
        })?;
        traces.push(trace);
    }
    Ok(traces)
}

pub fn validate_packet_traces(packet_dir: &Path) -> Result<(), String> {
    let traces_path = packet_dir.join("research-traces/research-traces.json");
    let attachments_path = packet_dir.join("research-traces/verifier-attachments.json");
    let traces_data = fs::read_to_string(&traces_path).map_err(|e| {
        format!(
            "Failed to read packet research traces {}: {e}",
            traces_path.display()
        )
    })?;
    let attachments_data = fs::read_to_string(&attachments_path).map_err(|e| {
        format!(
            "Failed to read packet verifier attachments {}: {e}",
            attachments_path.display()
        )
    })?;
    let traces: Vec<ResearchTrace> = serde_json::from_str(&traces_data).map_err(|e| {
        format!(
            "Failed to parse packet research traces {}: {e}",
            traces_path.display()
        )
    })?;
    let attachments: Vec<PacketVerifierAttachment> = serde_json::from_str(&attachments_data)
        .map_err(|e| {
            format!(
                "Failed to parse packet verifier attachments {}: {e}",
                attachments_path.display()
            )
        })?;
    let trace_ids = traces
        .iter()
        .map(|trace| trace.trace_id.as_str())
        .collect::<BTreeSet<_>>();
    for trace in &traces {
        trace.validate().map_err(|issues| {
            format!(
                "Packet research trace {} is invalid: {}",
                trace.trace_id,
                issues.join("; ")
            )
        })?;
    }
    for attachment in &attachments {
        if !trace_ids.contains(attachment.trace_id.as_str()) {
            return Err(format!(
                "Verifier attachment {} references missing trace_id {}",
                attachment.id, attachment.trace_id
            ));
        }
        if !is_sha256_uri(&attachment.content_hash) {
            return Err(format!(
                "Verifier attachment {} content_hash must be sha256:<64 hex>",
                attachment.id
            ));
        }
    }
    Ok(())
}

fn trace_root(source_path: Option<&Path>) -> Option<PathBuf> {
    let source = source_path?;
    if source.is_dir() {
        Some(source.to_path_buf())
    } else {
        source.parent().map(Path::to_path_buf)
    }
}

fn sources_by_id(trace: &ResearchTrace, source_ids: &[String]) -> Vec<TraceSourceInput> {
    let by_id = trace
        .source_inputs
        .iter()
        .map(|source| (source.id.as_str(), source.clone()))
        .collect::<BTreeMap<_, _>>();
    source_ids
        .iter()
        .filter_map(|id| by_id.get(id.as_str()).cloned())
        .collect()
}

fn observation_id(trace_id: &str, output_id: &str) -> String {
    let bytes = crate::canonical::to_canonical_bytes(&json!({
        "trace_id": trace_id,
        "output_id": output_id,
    }))
    .unwrap_or_default();
    format!("vobs_{}", &hex::encode(Sha256::digest(bytes))[..16])
}

fn validate_authority_boundary(boundary: &AuthorityBoundary, issues: &mut Vec<String>) {
    if boundary.trace_is_truth {
        issues.push("authority_boundary.trace_is_truth must be false".to_string());
    }
    if boundary.trace_mutates_frontier_state {
        issues.push("authority_boundary.trace_mutates_frontier_state must be false".to_string());
    }
    if boundary.trace_accepts_findings {
        issues.push("authority_boundary.trace_accepts_findings must be false".to_string());
    }
    if boundary.trace_resolves_consensus {
        issues.push("authority_boundary.trace_resolves_consensus must be false".to_string());
    }
    if !boundary.reviewer_acceptance_required {
        issues.push("authority_boundary.reviewer_acceptance_required must be true".to_string());
    }
    if !boundary.accepted_event_required_for_state_change {
        issues.push(
            "authority_boundary.accepted_event_required_for_state_change must be true".to_string(),
        );
    }
}

fn validate_formalization_fidelity(fidelity: &FormalizationFidelity, issues: &mut Vec<String>) {
    if !fidelity.required {
        issues.push("formalization_fidelity.required must be true".to_string());
    }
    require_non_empty(
        "formalization_fidelity.source_claim",
        &fidelity.source_claim,
        issues,
    );
    require_non_empty(
        "formalization_fidelity.stored_claim",
        &fidelity.stored_claim,
        issues,
    );
    require_non_empty(
        "formalization_fidelity.review_question",
        &fidelity.review_question,
        issues,
    );
}

fn require_non_empty(field: &str, value: &str, issues: &mut Vec<String>) {
    if value.trim().is_empty() {
        issues.push(format!("{field} must be non-empty"));
    }
}

fn is_sha256_uri(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_trace_that_claims_write_authority() {
        let mut trace = minimal_trace();
        trace.authority_boundary.trace_mutates_frontier_state = true;
        let issues = trace.validate().unwrap_err();
        assert!(
            issues
                .iter()
                .any(|issue| issue.contains("trace_mutates_frontier_state must be false")),
            "got: {issues:?}"
        );
    }

    #[test]
    fn rejects_candidate_with_unknown_source() {
        let mut trace = minimal_trace();
        trace.state_outputs.candidate_findings[0].evidence_source_ids =
            vec!["missing_source".to_string()];
        let issues = trace.validate().unwrap_err();
        assert!(
            issues
                .iter()
                .any(|issue| issue.contains("references unknown source")),
            "got: {issues:?}"
        );
    }

    fn minimal_trace() -> ResearchTrace {
        ResearchTrace {
            schema: RESEARCH_TRACE_SCHEMA.to_string(),
            trace_id: "vrt_test".to_string(),
            created_at: "2026-05-25T00:00:00Z".to_string(),
            producer: TraceProducer {
                kind: "agent".to_string(),
                id: "agent:test".to_string(),
                name: "Test agent".to_string(),
            },
            objective: "Test bounded trace validation.".to_string(),
            scope: json!({"frontier": "test"}),
            source_inputs: vec![TraceSourceInput {
                id: "source_a".to_string(),
                kind: "paper".to_string(),
                locator: "https://example.org/a".to_string(),
                content_hash: format!("sha256:{}", "1".repeat(64)),
            }],
            state_outputs: TraceStateOutputs {
                candidate_findings: vec![TraceCandidateFinding {
                    id: "claim_a".to_string(),
                    assertion: "A bounded claim requires review.".to_string(),
                    evidence_source_ids: vec!["source_a".to_string()],
                    conditions: vec!["test".to_string()],
                    caveats: vec!["pending review".to_string()],
                }],
                open_needs: Vec::new(),
            },
            verifier_attachments: vec![TraceVerifierAttachment {
                id: "audit_a".to_string(),
                kind: "source_locator_audit".to_string(),
                locator: "local:audit.json".to_string(),
                content_hash: format!("sha256:{}", "2".repeat(64)),
                verifies: "source locator exists".to_string(),
            }],
            formalization_fidelity: FormalizationFidelity {
                required: true,
                source_claim: "Source claim".to_string(),
                stored_claim: "Stored claim".to_string(),
                review_question: "Review question".to_string(),
            },
            authority_boundary: AuthorityBoundary {
                trace_is_truth: false,
                trace_mutates_frontier_state: false,
                trace_accepts_findings: false,
                trace_resolves_consensus: false,
                reviewer_acceptance_required: true,
                accepted_event_required_for_state_change: true,
            },
        }
    }
}
