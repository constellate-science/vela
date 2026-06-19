//! Structural integrity checks for accepted frontier state.
//!
//! These checks are intentionally about substrate correctness, not scientific
//! completeness. Missing evidence spans can keep a frontier out of strict proof
//! use; duplicate events, broken replay, and applied proposals without events
//! are harder failures because they mean the state history itself is suspect.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use vela_protocol::events::{self, ReplayReport};
use vela_protocol::project::Project;
use vela_protocol::repo;

pub const STATE_INTEGRITY_SCHEMA: &str = "vela.state_integrity_report.v0.1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntegrityIssue {
    pub rule_id: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateIntegrityReport {
    pub schema: String,
    pub status: String,
    #[serde(default)]
    pub structural_errors: Vec<IntegrityIssue>,
    #[serde(default)]
    pub warnings: Vec<IntegrityIssue>,
    pub proof_freshness: String,
    pub replay: ReplayReport,
    #[serde(default)]
    pub summary: BTreeMap<String, usize>,
}

pub fn analyze_path(path: &Path) -> Result<StateIntegrityReport, String> {
    let frontier = repo::load_from_path(path)?;
    let mut report = analyze(&frontier);
    for layout_issue in vela_protocol::frontier_repo::layout_issues(path, &frontier) {
        report.structural_errors.push(IntegrityIssue {
            rule_id: layout_issue.rule_id,
            message: layout_issue.message,
            object_id: None,
        });
    }
    for issue in accounting_divergence_issues(path, &frontier) {
        report.structural_errors.push(issue);
    }
    if !report.structural_errors.is_empty() {
        report.status = "fail".to_string();
    } else if !report.warnings.is_empty() {
        report.status = "warn".to_string();
    } else {
        report.status = "ok".to_string();
    }
    report.summary.insert(
        "structural_errors".to_string(),
        report.structural_errors.len(),
    );
    report
        .summary
        .insert("warnings".to_string(), report.warnings.len());
    Ok(report)
}

pub fn analyze(frontier: &Project) -> StateIntegrityReport {
    let replay = events::replay_report(frontier);
    let mut structural_errors = Vec::new();
    let mut warnings = Vec::new();
    let event_ids = frontier
        .events
        .iter()
        .map(|event| event.id.as_str())
        .collect::<BTreeSet<_>>();

    for id in &replay.event_log.duplicate_ids {
        structural_errors.push(issue(
            "duplicate_event_id",
            format!("Duplicate canonical event id {id}."),
            Some(id.clone()),
        ));
    }
    for id in &replay.event_log.orphan_targets {
        structural_errors.push(issue(
            "orphan_event_target",
            format!("Canonical event targets missing finding {id}."),
            Some(id.clone()),
        ));
    }
    if !replay.ok {
        for conflict in &replay.conflicts {
            if conflict.starts_with("duplicate event id:")
                || conflict.starts_with("orphan event target:")
            {
                continue;
            }
            structural_errors.push(issue("replay_conflict", conflict.clone(), None));
        }
    }

    for event in &frontier.events {
        if is_accepted_state_event(event.kind.as_str())
            && event
                .payload
                .get("proposal_id")
                .and_then(|value| value.as_str())
                .is_none_or(|value| value.trim().is_empty())
        {
            structural_errors.push(issue(
                "accepted_event_missing_proposal_id",
                format!("Accepted event {} has no payload.proposal_id.", event.id),
                Some(event.id.clone()),
            ));
        }
    }

    for proposal in &frontier.proposals {
        if matches!(proposal.status.as_str(), "accepted" | "applied") {
            let Some(event_id) = proposal.applied_event_id.as_deref() else {
                structural_errors.push(issue(
                    "applied_proposal_missing_event",
                    format!(
                        "Proposal {} is {} without an applied event id.",
                        proposal.id, proposal.status
                    ),
                    Some(proposal.id.clone()),
                ));
                continue;
            };
            if !event_ids.contains(event_id) {
                structural_errors.push(issue(
                    "applied_proposal_event_missing",
                    format!(
                        "Proposal {} points to missing event {event_id}.",
                        proposal.id
                    ),
                    Some(proposal.id.clone()),
                ));
            }
        }

        if proposal.kind == "artifact.assert"
            && matches!(proposal.status.as_str(), "accepted" | "applied")
        {
            let artifact = proposal.payload.get("artifact");
            let locator_missing = artifact
                .and_then(|value| value.get("locator"))
                .and_then(|value| value.as_str())
                .is_none_or(|value| value.trim().is_empty());
            let hash_missing = artifact
                .and_then(|value| value.get("content_hash"))
                .and_then(|value| value.as_str())
                .is_none_or(|value| !value.starts_with("sha256:"));
            if locator_missing || hash_missing {
                structural_errors.push(issue(
                    "accepted_artifact_missing_locator_or_hash",
                    format!(
                        "Artifact proposal {} is accepted without locator or content hash.",
                        proposal.id
                    ),
                    Some(proposal.id.clone()),
                ));
            }
        }
    }

    // Trust boundary: an LLM may PROPOSE a finding, but an LLM-authored claim
    // must not stand as canonical state without review. "Activity is not state";
    // canonical state = replay(accepted_events) and the ledger is not authored by
    // a model. Flag canonical findings whose extraction method is LLM-based and
    // that carry no review — neither an inline `provenance.review` nor any
    // `finding.reviewed` event. A warning, not a hard error: surfacing the gap is
    // the protocol's job; demoting such findings to candidate-only is a governance
    // decision, not an automatic one.
    let reviewed_ids = frontier
        .events
        .iter()
        .filter(|event| event.kind == "finding.reviewed")
        .map(|event| event.target.id.as_str())
        .collect::<BTreeSet<_>>();
    let mut ai_unreviewed = 0usize;
    let mut unattributed = 0usize;
    for finding in &frontier.findings {
        let prov = &finding.provenance;
        let has_review = prov.review.is_some() || reviewed_ids.contains(finding.id.as_str());
        if is_unreviewed_llm_finding(&prov.extraction.method, has_review) {
            ai_unreviewed += 1;
            warnings.push(issue(
                "ai_authored_finding_unreviewed",
                format!(
                    "Finding {} is LLM-authored (extraction.method={}) and canonical without any \
                     review. An LLM may propose; a canonical finding needs a review attestation.",
                    finding.id, prov.extraction.method
                ),
                Some(finding.id.clone()),
            ));
        }

        // Every finding must point at a source. A source can be a paper (doi /
        // pmid / pmc / openalex / url), an adapter or model that produced it
        // (extraction.model — e.g. an OpenAI/API/agent run), an author, or a
        // reviewer who attests it. A finding attributable to none of these came
        // from nowhere and cannot carry provenance.
        let has_source_id = [&prov.doi, &prov.url].iter().any(|field| {
            field
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty())
        });
        let has_adapter = prov
            .extraction
            .model
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty());
        let has_author = !prov.authors.is_empty();
        if !is_attributed(has_source_id, has_adapter, has_author, has_review) {
            unattributed += 1;
            warnings.push(issue(
                "finding_source_unattributed",
                format!(
                    "Finding {} (source_type={}) names no source: no paper id, no adapter/model, \
                     no author, no reviewer. Every finding must point at a source.",
                    finding.id, prov.source_type
                ),
                Some(finding.id.clone()),
            ));
        }
    }

    let proof_freshness = proof_freshness(frontier);
    if proof_freshness == "stale" {
        structural_errors.push(issue(
            "stale_proof_packet",
            "Recorded proof packet is stale relative to accepted events.".to_string(),
            None,
        ));
    } else if proof_freshness == "unknown" {
        warnings.push(issue(
            "proof_freshness_unknown",
            "No current proof packet is recorded for this frontier.".to_string(),
            None,
        ));
    }

    let status = if structural_errors.is_empty() {
        if warnings.is_empty() { "ok" } else { "warn" }
    } else {
        "fail"
    }
    .to_string();

    let mut summary = BTreeMap::new();
    summary.insert("events".to_string(), frontier.events.len());
    summary.insert("proposals".to_string(), frontier.proposals.len());
    summary.insert("ai_authored_unreviewed".to_string(), ai_unreviewed);
    summary.insert("source_unattributed".to_string(), unattributed);
    summary.insert("structural_errors".to_string(), structural_errors.len());
    summary.insert("warnings".to_string(), warnings.len());

    StateIntegrityReport {
        schema: STATE_INTEGRITY_SCHEMA.to_string(),
        status,
        structural_errors,
        warnings,
        proof_freshness,
        replay,
        summary,
    }
}

/// Accounting artifacts must not claim more canonical (accepted) findings than
/// the event log can back. The canonical accepted-findings count is the number
/// of findings present in replayed state — each backed by a `finding.asserted`
/// event. Candidate / source-lake records (IDs minted by bulk review passes
/// with no asserted content) are explicitly out of scope: they are not
/// event-backed and must be reported as a *separate* candidate layer, never
/// merged into the canonical findings number. This guard catches the inflation
/// at the reporting layer, complementing `orphan_event_target` (which catches
/// it at the state layer).
fn accounting_divergence_issues(path: &Path, frontier: &Project) -> Vec<IntegrityIssue> {
    // (relative artifact path, json pointer to the claimed canonical findings)
    const SOURCES: &[(&str, &[&str])] = &[
        (
            ".vela/graph/frontier-graph-summary.v1.json",
            &["canonical", "findings"],
        ),
        (
            "review/canonical-accounting.v2.json",
            &["summary", "canonical_findings"],
        ),
    ];
    let accepted = frontier.findings.len();
    let mut issues = Vec::new();
    for (rel, pointer) in SOURCES {
        let Ok(text) = fs::read_to_string(path.join(rel)) else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
            continue;
        };
        let mut cur = &value;
        let mut found = true;
        for key in *pointer {
            match cur.get(*key) {
                Some(next) => cur = next,
                None => {
                    found = false;
                    break;
                }
            }
        }
        if !found {
            continue;
        }
        if let Some(claimed) = cur.as_u64()
            && let Some(issue) = finding_inflation_issue(rel, claimed as usize, accepted)
        {
            issues.push(issue);
        }
    }
    issues
}

/// An LLM-authored finding (extraction method names an LLM) that carries no
/// review of any kind is the literal "AI authored the ledger" case the trust
/// boundary forbids. Import methods like `artifact_to_state_import` are not
/// LLM-authoring a claim and are out of scope here.
fn is_unreviewed_llm_finding(extraction_method: &str, has_review: bool) -> bool {
    let method = extraction_method.to_ascii_lowercase();
    method.contains("llm") && !has_review
}

/// A finding is attributed if it points at any source: a paper identifier, an
/// adapter/model that produced it, a named author, or a reviewer who attests it.
fn is_attributed(
    has_source_id: bool,
    has_adapter: bool,
    has_author: bool,
    has_review: bool,
) -> bool {
    has_source_id || has_adapter || has_author || has_review
}

fn finding_inflation_issue(rel: &str, claimed: usize, accepted: usize) -> Option<IntegrityIssue> {
    (claimed > accepted).then(|| {
        issue(
            "accounting_finding_inflation",
            format!(
                "{rel} claims {claimed} canonical findings but only {accepted} are event-backed \
                 (finding.asserted); the surplus {} are not findings — report them as a separate \
                 candidate layer, not as canonical findings.",
                claimed - accepted
            ),
            Some(rel.to_string()),
        )
    })
}

fn issue(rule_id: &str, message: String, object_id: Option<String>) -> IntegrityIssue {
    IntegrityIssue {
        rule_id: rule_id.to_string(),
        message,
        object_id,
    }
}

fn is_accepted_state_event(kind: &str) -> bool {
    matches!(
        kind,
        "finding.asserted"
            | "finding.reviewed"
            | "finding.noted"
            | "finding.caveated"
            | "finding.confidence_revised"
            | "finding.rejected"
            | "finding.retracted"
            | "finding.dependency_invalidated"
            | "source_text.reviewed"
            | "artifact.asserted"
            | "artifact.reviewed"
            | "artifact.retracted"
    )
}

fn proof_freshness(frontier: &Project) -> String {
    let state = &frontier.proof_state.latest_packet;
    if state.status == "never_exported" {
        return "unknown".to_string();
    }
    if state.status == "stale" {
        return "stale".to_string();
    }
    let current_event_hash = events::event_log_hash(&frontier.events);
    match state.event_log_hash.as_deref() {
        Some(hash) if hash == current_event_hash => "fresh".to_string(),
        Some(_) => "stale".to_string(),
        None => "unknown".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inflation_fires_only_when_claim_exceeds_accepted() {
        // inflation case: accounting claims 5531 findings, event log backs 647.
        let inflated = finding_inflation_issue("review/canonical-accounting.v2.json", 5531, 647)
            .expect("claim above accepted must flag");
        assert_eq!(inflated.rule_id, "accounting_finding_inflation");
        assert!(
            inflated.message.contains("4884"),
            "surplus stated: {}",
            inflated.message
        );

        // honest, separated accounting: claim == accepted → no issue.
        assert!(finding_inflation_issue("a", 647, 647).is_none());
        // an under-count is not inflation (e.g. an in-progress export).
        assert!(finding_inflation_issue("a", 100, 647).is_none());
    }

    #[test]
    fn llm_finding_needs_review_to_be_canonical() {
        // LLM-authored + unreviewed = the failure mode (an unreviewed model-extracted set).
        assert!(is_unreviewed_llm_finding("llm_extraction", false));
        assert!(is_unreviewed_llm_finding("LLM_inference", false));
        // reviewed LLM finding is fine (the Erdős spine: agent-ingested but reviewed).
        assert!(!is_unreviewed_llm_finding("llm_extraction", true));
        // non-LLM origins are out of scope regardless of review.
        assert!(!is_unreviewed_llm_finding("manual_curation", false));
        assert!(!is_unreviewed_llm_finding(
            "artifact_to_state_import",
            false
        ));
    }

    #[test]
    fn attribution_accepts_any_source_including_adapters() {
        // a paper id, an adapter/model, an author, or a reviewer each attribute it.
        assert!(is_attributed(true, false, false, false)); // doi/pmid
        assert!(is_attributed(false, true, false, false)); // adapter/model (OpenAI/API/agent)
        assert!(is_attributed(false, false, true, false)); // author
        assert!(is_attributed(false, false, false, true)); // reviewer
        // none of them: came from nowhere.
        assert!(!is_attributed(false, false, false, false));
    }
}
