//! `vela diff` — structural comparison of two frontiers.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use colored::Colorize;

use crate::cli_style as style;
use serde::Serialize;

use crate::bundle::{ReviewAction, ReviewEvent};
use crate::events;
use crate::project::{Project, ProjectDependency};
use crate::proposals;
use crate::repo;

/// Result of comparing two frontiers.
#[derive(Debug, Serialize)]
pub struct DiffResult {
    pub name_a: String,
    pub name_b: String,
    pub findings_a: usize,
    pub findings_b: usize,
    pub only_in_a: Vec<FindingSummary>,
    pub only_in_b: Vec<FindingSummary>,
    pub only_in_a_reviews: Vec<ReviewSummary>,
    pub only_in_b_reviews: Vec<ReviewSummary>,
    pub only_in_a_dependencies: Vec<DependencySummary>,
    pub only_in_b_dependencies: Vec<DependencySummary>,
    pub semantic_pairs: Vec<SemanticPair>,
    pub field_changes: Vec<FieldChange>,
    pub confidence_changes: Vec<ConfidenceChange>,
    pub new_contradictions: Vec<ContradictionSummary>,
    pub entities_only_in_a: Vec<String>,
    pub entities_only_in_b: Vec<String>,
    pub projections: ProjectionDiff,
    pub proposal_state: ProposalStateDiff,
    pub event_log: EventLogDiff,
    pub proof_state: ProofStateDiff,
    pub review_impacts: Vec<ReviewImpact>,
    pub stats_comparison: StatsComparison,
}

#[derive(Debug, Serialize)]
pub struct ProjectionDiff {
    pub sources: (usize, usize),
    pub evidence_atoms: (usize, usize),
    pub condition_records: (usize, usize),
}

#[derive(Debug, Serialize)]
pub struct ProposalStateDiff {
    pub total: (usize, usize),
    pub pending_review: (usize, usize),
    pub applied: (usize, usize),
}

#[derive(Debug, Serialize)]
pub struct EventLogDiff {
    pub events: (usize, usize),
    pub kinds_only_in_a: Vec<String>,
    pub kinds_only_in_b: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ProofStateDiff {
    pub status_a: String,
    pub status_b: String,
    pub stale_reason_a: Option<String>,
    pub stale_reason_b: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ReviewImpact {
    pub kind: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct DependencySummary {
    pub name: String,
    pub source: String,
    pub version: String,
}

#[derive(Debug, Serialize)]
pub struct ReviewSummary {
    pub id: String,
    pub finding_id: String,
    pub reviewer: String,
    pub action: String,
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct FindingSummary {
    pub id: String,
    pub assertion: String,
}

#[derive(Debug, Serialize)]
pub struct ConfidenceChange {
    pub id: String,
    pub assertion: String,
    pub score_a: f64,
    pub score_b: f64,
    pub delta: f64,
}

#[derive(Debug, Serialize)]
pub struct ContradictionSummary {
    pub from_id: String,
    pub target_id: String,
    pub note: String,
}

#[derive(Debug, Serialize)]
pub struct SemanticPair {
    pub id_a: String,
    pub id_b: String,
    pub score: f64,
    pub reason: String,
    pub assertion_a: String,
    pub assertion_b: String,
}

#[derive(Debug, Serialize)]
pub struct FieldChange {
    pub id_a: String,
    pub id_b: String,
    pub field: String,
    pub value_a: serde_json::Value,
    pub value_b: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct StatsComparison {
    pub findings: (usize, usize),
    pub links: (usize, usize),
    pub replicated: (usize, usize),
    pub gaps: (usize, usize),
    pub contested: (usize, usize),
    pub review_events: (usize, usize),
    pub avg_confidence: (f64, f64),
}

#[derive(Debug, Serialize)]
pub struct DiffJsonEnvelope<'a> {
    pub schema: &'static str,
    pub ok: bool,
    pub generated_at: String,
    pub command: &'static str,
    pub sources: DiffSources<'a>,
    pub summary: DiffSummary,
    pub diff: &'a DiffResult,
}

#[derive(Debug, Serialize)]
pub struct DiffSources<'a> {
    pub a: &'a str,
    pub b: &'a str,
}

#[derive(Debug, Serialize)]
pub struct DiffSummary {
    pub findings_a: usize,
    pub findings_b: usize,
    pub only_in_a: usize,
    pub only_in_b: usize,
    pub semantic_pairs: usize,
    pub field_changes: usize,
    pub confidence_changes: usize,
    pub new_contradictions: usize,
    pub review_events_only_in_a: usize,
    pub review_events_only_in_b: usize,
    pub review_impacts: usize,
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        let mut end = max;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}...", &s[..end])
    }
}

fn summarize_review(event: &ReviewEvent) -> ReviewSummary {
    ReviewSummary {
        id: event.id.clone(),
        finding_id: event.finding_id.clone(),
        reviewer: event.reviewer.clone(),
        action: review_action_label(&event.action),
        reason: event.reason.clone(),
    }
}

fn summarize_dependency(dep: &ProjectDependency) -> DependencySummary {
    DependencySummary {
        name: dep.name.clone(),
        source: dep.source.clone(),
        version: dep.version.clone().unwrap_or_else(|| "-".into()),
    }
}

fn review_action_label(action: &ReviewAction) -> String {
    match action {
        ReviewAction::Approved => "approved".to_string(),
        ReviewAction::Qualified { .. } => "qualified".to_string(),
        ReviewAction::Corrected { field, .. } => format!("corrected:{field}"),
        ReviewAction::Flagged { flag_type } => format!("flagged:{flag_type}"),
        ReviewAction::Disputed { .. } => "disputed".to_string(),
    }
}

fn semantic_key(f: &crate::bundle::FindingBundle) -> String {
    normalize_text(&format!(
        "{} {} {}",
        f.assertion.assertion_type, f.assertion.text, f.conditions.text
    ))
}

fn normalize_text(value: &str) -> String {
    value
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { ' ' })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn token_set(value: &str) -> HashSet<String> {
    normalize_text(value)
        .split_whitespace()
        .filter(|token| token.len() > 2)
        .map(str::to_string)
        .collect()
}

fn jaccard(a: &HashSet<String>, b: &HashSet<String>) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    let intersection = a.intersection(b).count() as f64;
    let union = a.union(b).count() as f64;
    if union == 0.0 {
        0.0
    } else {
        intersection / union
    }
}

fn semantic_similarity(
    a: &crate::bundle::FindingBundle,
    b: &crate::bundle::FindingBundle,
) -> (f64, String) {
    let key_a = semantic_key(a);
    let key_b = semantic_key(b);
    if key_a == key_b {
        return (
            1.0,
            "normalized assertion/type/conditions match".to_string(),
        );
    }

    let tokens_a = token_set(&key_a);
    let tokens_b = token_set(&key_b);
    let token_score = jaccard(&tokens_a, &tokens_b);
    let doi_match = a.provenance.doi.is_some() && a.provenance.doi == b.provenance.doi;
    let pmid_match = a.provenance.pmid.is_some() && a.provenance.pmid == b.provenance.pmid;
    let type_match = a.assertion.assertion_type == b.assertion.assertion_type;
    let provenance_boost = if doi_match || pmid_match { 0.25 } else { 0.0 };
    let type_boost = if type_match { 0.1 } else { 0.0 };
    let score = (token_score + provenance_boost + type_boost).min(1.0);
    let reason = if doi_match {
        "shared DOI with similar assertion".to_string()
    } else if pmid_match {
        "shared PMID with similar assertion".to_string()
    } else if type_match {
        "same assertion type with similar text".to_string()
    } else {
        "similar assertion text".to_string()
    };
    (score, reason)
}

fn value_str(value: impl Into<String>) -> serde_json::Value {
    serde_json::Value::String(value.into())
}

fn push_field_change(
    changes: &mut Vec<FieldChange>,
    id_a: &str,
    id_b: &str,
    field: &str,
    value_a: serde_json::Value,
    value_b: serde_json::Value,
) {
    if value_a != value_b {
        changes.push(FieldChange {
            id_a: id_a.to_string(),
            id_b: id_b.to_string(),
            field: field.to_string(),
            value_a,
            value_b,
        });
    }
}

fn finding_field_changes(
    id_a: &str,
    a: &crate::bundle::FindingBundle,
    id_b: &str,
    b: &crate::bundle::FindingBundle,
) -> Vec<FieldChange> {
    let mut changes = Vec::new();
    push_field_change(
        &mut changes,
        id_a,
        id_b,
        "assertion.text",
        value_str(a.assertion.text.clone()),
        value_str(b.assertion.text.clone()),
    );
    push_field_change(
        &mut changes,
        id_a,
        id_b,
        "assertion.assertion_type",
        value_str(a.assertion.assertion_type.clone()),
        value_str(b.assertion.assertion_type.clone()),
    );
    push_field_change(
        &mut changes,
        id_a,
        id_b,
        "conditions.text",
        value_str(a.conditions.text.clone()),
        value_str(b.conditions.text.clone()),
    );
    push_field_change(
        &mut changes,
        id_a,
        id_b,
        "confidence.score",
        serde_json::json!(a.confidence.score),
        serde_json::json!(b.confidence.score),
    );
    push_field_change(
        &mut changes,
        id_a,
        id_b,
        "evidence.evidence_type",
        value_str(a.evidence.evidence_type.clone()),
        value_str(b.evidence.evidence_type.clone()),
    );
    push_field_change(
        &mut changes,
        id_a,
        id_b,
        "evidence.method",
        value_str(a.evidence.method.clone()),
        value_str(b.evidence.method.clone()),
    );
    push_field_change(
        &mut changes,
        id_a,
        id_b,
        "evidence.replicated",
        serde_json::json!(a.evidence.replicated),
        serde_json::json!(b.evidence.replicated),
    );
    push_field_change(
        &mut changes,
        id_a,
        id_b,
        "flags.gap",
        serde_json::json!(a.flags.gap),
        serde_json::json!(b.flags.gap),
    );
    push_field_change(
        &mut changes,
        id_a,
        id_b,
        "flags.contested",
        serde_json::json!(a.flags.contested),
        serde_json::json!(b.flags.contested),
    );
    push_field_change(
        &mut changes,
        id_a,
        id_b,
        "provenance.title",
        value_str(a.provenance.title.clone()),
        value_str(b.provenance.title.clone()),
    );
    push_field_change(
        &mut changes,
        id_a,
        id_b,
        "provenance.doi",
        serde_json::json!(a.provenance.doi.clone()),
        serde_json::json!(b.provenance.doi.clone()),
    );
    changes
}

pub fn compare(a: &Project, b: &Project) -> DiffResult {
    let ids_a: HashSet<&str> = a.findings.iter().map(|f| f.id.as_str()).collect();
    let ids_b: HashSet<&str> = b.findings.iter().map(|f| f.id.as_str()).collect();

    let map_a: HashMap<&str, &crate::bundle::FindingBundle> =
        a.findings.iter().map(|f| (f.id.as_str(), f)).collect();
    let map_b: HashMap<&str, &crate::bundle::FindingBundle> =
        b.findings.iter().map(|f| (f.id.as_str(), f)).collect();
    let review_ids_a: HashSet<&str> = a.review_events.iter().map(|r| r.id.as_str()).collect();
    let review_ids_b: HashSet<&str> = b.review_events.iter().map(|r| r.id.as_str()).collect();
    let review_map_a: HashMap<&str, &ReviewEvent> = a
        .review_events
        .iter()
        .map(|event| (event.id.as_str(), event))
        .collect();
    let review_map_b: HashMap<&str, &ReviewEvent> = b
        .review_events
        .iter()
        .map(|event| (event.id.as_str(), event))
        .collect();
    let dep_ids_a: HashSet<String> = a
        .project
        .dependencies
        .iter()
        .map(|dep| format!("{}::{}", dep.name, dep.source))
        .collect();
    let dep_ids_b: HashSet<String> = b
        .project
        .dependencies
        .iter()
        .map(|dep| format!("{}::{}", dep.name, dep.source))
        .collect();
    let dep_map_a: HashMap<String, &ProjectDependency> = a
        .project
        .dependencies
        .iter()
        .map(|dep| (format!("{}::{}", dep.name, dep.source), dep))
        .collect();
    let dep_map_b: HashMap<String, &ProjectDependency> = b
        .project
        .dependencies
        .iter()
        .map(|dep| (format!("{}::{}", dep.name, dep.source), dep))
        .collect();

    // Findings only in A / only in B
    let only_in_a: Vec<FindingSummary> = ids_a
        .difference(&ids_b)
        .map(|id| {
            let f = map_a[id];
            FindingSummary {
                id: f.id.clone(),
                assertion: f.assertion.text.clone(),
            }
        })
        .collect();

    let only_in_b: Vec<FindingSummary> = ids_b
        .difference(&ids_a)
        .map(|id| {
            let f = map_b[id];
            FindingSummary {
                id: f.id.clone(),
                assertion: f.assertion.text.clone(),
            }
        })
        .collect();

    let only_in_a_reviews: Vec<ReviewSummary> = review_ids_a
        .difference(&review_ids_b)
        .map(|id| summarize_review(review_map_a[id]))
        .collect();
    let only_in_b_reviews: Vec<ReviewSummary> = review_ids_b
        .difference(&review_ids_a)
        .map(|id| summarize_review(review_map_b[id]))
        .collect();
    let only_in_a_dependencies: Vec<DependencySummary> = dep_ids_a
        .difference(&dep_ids_b)
        .map(|id| summarize_dependency(dep_map_a[id]))
        .collect();
    let only_in_b_dependencies: Vec<DependencySummary> = dep_ids_b
        .difference(&dep_ids_a)
        .map(|id| summarize_dependency(dep_map_b[id]))
        .collect();

    let mut semantic_pairs = Vec::new();
    let mut paired_a: HashSet<String> = HashSet::new();
    let mut paired_b: HashSet<String> = HashSet::new();
    let only_a_ids: Vec<&str> = ids_a.difference(&ids_b).copied().collect();
    let only_b_ids: Vec<&str> = ids_b.difference(&ids_a).copied().collect();
    let mut candidates: Vec<(f64, String, &str, &str)> = Vec::new();
    for id_a in &only_a_ids {
        for id_b in &only_b_ids {
            let (score, reason) = semantic_similarity(map_a[id_a], map_b[id_b]);
            if score >= 0.72 {
                candidates.push((score, reason, *id_a, *id_b));
            }
        }
    }
    candidates.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());
    for (score, reason, id_a, id_b) in candidates {
        if paired_a.contains(id_a) || paired_b.contains(id_b) {
            continue;
        }
        paired_a.insert(id_a.to_string());
        paired_b.insert(id_b.to_string());
        semantic_pairs.push(SemanticPair {
            id_a: id_a.to_string(),
            id_b: id_b.to_string(),
            score: (score * 1000.0).round() / 1000.0,
            reason,
            assertion_a: map_a[id_a].assertion.text.clone(),
            assertion_b: map_b[id_b].assertion.text.clone(),
        });
    }

    // Shared findings with confidence changes
    let shared: Vec<&str> = ids_a.intersection(&ids_b).copied().collect();
    let mut confidence_changes: Vec<ConfidenceChange> = Vec::new();
    let mut field_changes: Vec<FieldChange> = Vec::new();
    for id in &shared {
        let fa = map_a[id];
        let fb = map_b[id];
        field_changes.extend(finding_field_changes(id, fa, id, fb));
        let delta = fb.confidence.score - fa.confidence.score;
        if delta.abs() > 1e-6 {
            confidence_changes.push(ConfidenceChange {
                id: id.to_string(),
                assertion: fa.assertion.text.clone(),
                score_a: fa.confidence.score,
                score_b: fb.confidence.score,
                delta,
            });
        }
    }
    for pair in &semantic_pairs {
        field_changes.extend(finding_field_changes(
            &pair.id_a,
            map_a[pair.id_a.as_str()],
            &pair.id_b,
            map_b[pair.id_b.as_str()],
        ));
    }
    confidence_changes.sort_by(|a, b| b.delta.abs().partial_cmp(&a.delta.abs()).unwrap());
    field_changes.sort_by(|a, b| {
        a.id_a
            .cmp(&b.id_a)
            .then_with(|| a.id_b.cmp(&b.id_b))
            .then_with(|| a.field.cmp(&b.field))
    });

    // Contradiction links in B that don't exist in A
    let contradictions_a: HashSet<(String, String)> = a
        .findings
        .iter()
        .flat_map(|f| {
            f.links
                .iter()
                .filter(|l| l.link_type == "contradicts")
                .map(move |l| (f.id.clone(), l.target.clone()))
        })
        .collect();

    let new_contradictions: Vec<ContradictionSummary> = b
        .findings
        .iter()
        .flat_map(|f| {
            f.links
                .iter()
                .filter(|l| l.link_type == "contradicts")
                .filter(|l| !contradictions_a.contains(&(f.id.clone(), l.target.clone())))
                .map(move |l| ContradictionSummary {
                    from_id: f.id.clone(),
                    target_id: l.target.clone(),
                    note: l.note.clone(),
                })
        })
        .collect();

    // Entity coverage: collect resolved entity names
    fn resolved_entities(c: &Project) -> HashSet<String> {
        c.findings
            .iter()
            .flat_map(|f| {
                f.assertion.entities.iter().filter_map(|e| {
                    if e.canonical_id.is_some() {
                        Some(e.name.clone())
                    } else {
                        None
                    }
                })
            })
            .collect()
    }

    let entities_a = resolved_entities(a);
    let entities_b = resolved_entities(b);

    let mut entities_only_in_a: Vec<String> = entities_a.difference(&entities_b).cloned().collect();
    let mut entities_only_in_b: Vec<String> = entities_b.difference(&entities_a).cloned().collect();
    entities_only_in_a.sort();
    entities_only_in_b.sort();

    let proposal_summary_a = proposals::summary(a);
    let proposal_summary_b = proposals::summary(b);
    let event_summary_a = events::summarize(a);
    let event_summary_b = events::summarize(b);
    let kinds_a = event_summary_a
        .kinds
        .keys()
        .cloned()
        .collect::<HashSet<_>>();
    let kinds_b = event_summary_b
        .kinds
        .keys()
        .cloned()
        .collect::<HashSet<_>>();
    let mut kinds_only_in_a = kinds_a.difference(&kinds_b).cloned().collect::<Vec<_>>();
    let mut kinds_only_in_b = kinds_b.difference(&kinds_a).cloned().collect::<Vec<_>>();
    kinds_only_in_a.sort();
    kinds_only_in_b.sort();

    let mut review_impacts = Vec::new();
    if a.proof_state.latest_packet.status != b.proof_state.latest_packet.status {
        review_impacts.push(ReviewImpact {
            kind: "proof_state".to_string(),
            message: format!(
                "Proof freshness changed: {} -> {}",
                a.proof_state.latest_packet.status, b.proof_state.latest_packet.status
            ),
        });
    }
    if proposal_summary_a.pending_review != proposal_summary_b.pending_review {
        review_impacts.push(ReviewImpact {
            kind: "pending_review".to_string(),
            message: format!(
                "Pending proposals changed: {} -> {}",
                proposal_summary_a.pending_review, proposal_summary_b.pending_review
            ),
        });
    }
    if proposal_summary_a.applied != proposal_summary_b.applied {
        review_impacts.push(ReviewImpact {
            kind: "applied_proposals".to_string(),
            message: format!(
                "Applied proposals changed: {} -> {}",
                proposal_summary_a.applied, proposal_summary_b.applied
            ),
        });
    }
    if a.sources.len() != b.sources.len() || a.evidence_atoms.len() != b.evidence_atoms.len() {
        review_impacts.push(ReviewImpact {
            kind: "provenance_coverage".to_string(),
            message: format!(
                "Sources {} -> {}, evidence atoms {} -> {}",
                a.sources.len(),
                b.sources.len(),
                a.evidence_atoms.len(),
                b.evidence_atoms.len()
            ),
        });
    }
    if a.condition_records.len() != b.condition_records.len() {
        review_impacts.push(ReviewImpact {
            kind: "condition_boundary".to_string(),
            message: format!(
                "Condition records changed: {} -> {}",
                a.condition_records.len(),
                b.condition_records.len()
            ),
        });
    }
    if field_changes
        .iter()
        .any(|change| change.field == "conditions.text")
    {
        review_impacts.push(ReviewImpact {
            kind: "condition_scope".to_string(),
            message: "Condition boundaries changed for one or more paired findings.".to_string(),
        });
    }
    if field_changes
        .iter()
        .any(|change| change.field == "provenance.doi")
    {
        review_impacts.push(ReviewImpact {
            kind: "provenance".to_string(),
            message: "Provenance identifiers changed for one or more paired findings.".to_string(),
        });
    }
    if !new_contradictions.is_empty() {
        review_impacts.push(ReviewImpact {
            kind: "contradiction".to_string(),
            message: format!(
                "{} new contradiction links appeared in {}",
                new_contradictions.len(),
                b.project.name
            ),
        });
    }

    DiffResult {
        name_a: a.project.name.clone(),
        name_b: b.project.name.clone(),
        findings_a: a.findings.len(),
        findings_b: b.findings.len(),
        only_in_a,
        only_in_b,
        only_in_a_reviews,
        only_in_b_reviews,
        only_in_a_dependencies,
        only_in_b_dependencies,
        semantic_pairs,
        field_changes,
        confidence_changes,
        new_contradictions,
        entities_only_in_a,
        entities_only_in_b,
        projections: ProjectionDiff {
            sources: (a.sources.len(), b.sources.len()),
            evidence_atoms: (a.evidence_atoms.len(), b.evidence_atoms.len()),
            condition_records: (a.condition_records.len(), b.condition_records.len()),
        },
        proposal_state: ProposalStateDiff {
            total: (proposal_summary_a.total, proposal_summary_b.total),
            pending_review: (
                proposal_summary_a.pending_review,
                proposal_summary_b.pending_review,
            ),
            applied: (proposal_summary_a.applied, proposal_summary_b.applied),
        },
        event_log: EventLogDiff {
            events: (event_summary_a.count, event_summary_b.count),
            kinds_only_in_a,
            kinds_only_in_b,
        },
        proof_state: ProofStateDiff {
            status_a: a.proof_state.latest_packet.status.clone(),
            status_b: b.proof_state.latest_packet.status.clone(),
            stale_reason_a: a.proof_state.stale_reason.clone(),
            stale_reason_b: b.proof_state.stale_reason.clone(),
        },
        review_impacts,
        stats_comparison: StatsComparison {
            findings: (a.stats.findings, b.stats.findings),
            links: (a.stats.links, b.stats.links),
            replicated: (a.stats.replicated, b.stats.replicated),
            gaps: (a.stats.gaps, b.stats.gaps),
            contested: (a.stats.contested, b.stats.contested),
            review_events: (a.stats.review_event_count, b.stats.review_event_count),
            avg_confidence: (a.stats.avg_confidence, b.stats.avg_confidence),
        },
    }
}

pub fn json_envelope<'a>(
    path_a: &'a Path,
    path_b: &'a Path,
    diff: &'a DiffResult,
) -> DiffJsonEnvelope<'a> {
    DiffJsonEnvelope {
        schema: "vela.diff.v2",
        ok: true,
        generated_at: chrono::Utc::now().to_rfc3339(),
        command: "vela diff",
        sources: DiffSources {
            a: path_a.to_str().unwrap_or_default(),
            b: path_b.to_str().unwrap_or_default(),
        },
        summary: DiffSummary {
            findings_a: diff.findings_a,
            findings_b: diff.findings_b,
            only_in_a: diff.only_in_a.len(),
            only_in_b: diff.only_in_b.len(),
            semantic_pairs: diff.semantic_pairs.len(),
            field_changes: diff.field_changes.len(),
            confidence_changes: diff.confidence_changes.len(),
            new_contradictions: diff.new_contradictions.len(),
            review_events_only_in_a: diff.only_in_a_reviews.len(),
            review_events_only_in_b: diff.only_in_b_reviews.len(),
            review_impacts: diff.review_impacts.len(),
        },
        diff,
    }
}

pub fn run(path_a: &Path, path_b: &Path, json: bool, quiet: bool) {
    let a = repo::load_from_path(path_a).unwrap_or_else(|e| {
        eprintln!(
            "{} failed to load {}: {e}",
            style::err_prefix(),
            path_a.display()
        );
        std::process::exit(1);
    });
    let b = repo::load_from_path(path_b).unwrap_or_else(|e| {
        eprintln!(
            "{} failed to load {}: {e}",
            style::err_prefix(),
            path_b.display()
        );
        std::process::exit(1);
    });

    let diff = compare(&a, &b);

    if json {
        let envelope = json_envelope(path_a, path_b, &diff);
        println!(
            "{}",
            serde_json::to_string_pretty(&envelope).expect("failed to serialize diff")
        );
        return;
    }

    // Summary line
    println!();
    println!("  {}", "VELA · DIFF".dimmed());
    println!(
        "  {}",
        format!(
            "{} ({} findings) vs {} ({} findings)",
            diff.name_a, diff.findings_a, diff.name_b, diff.findings_b
        )
        .bold()
    );
    println!("  {}", style::tick_row(60));

    if quiet {
        println!();
        return;
    }

    // Only in A
    println!(
        "\n{} {} findings only in {}",
        style::madder("---"),
        diff.only_in_a.len(),
        style::madder(&diff.name_a)
    );
    for f in diff.only_in_a.iter().take(5) {
        println!(
            "  {} {} {}",
            style::madder("-"),
            f.id.dimmed(),
            truncate(&f.assertion, 60)
        );
    }
    if diff.only_in_a.len() > 5 {
        println!(
            "  {} ... and {} more",
            " ".dimmed(),
            diff.only_in_a.len() - 5
        );
    }

    // Only in B
    println!(
        "\n{} {} findings only in {}",
        style::moss("+++"),
        diff.only_in_b.len(),
        style::moss(&diff.name_b)
    );
    for f in diff.only_in_b.iter().take(5) {
        println!(
            "  {} {} {}",
            style::moss("+"),
            f.id.dimmed(),
            truncate(&f.assertion, 60)
        );
    }
    if diff.only_in_b.len() > 5 {
        println!(
            "  {} ... and {} more",
            " ".dimmed(),
            diff.only_in_b.len() - 5
        );
    }

    if !diff.semantic_pairs.is_empty() {
        println!(
            "\n{} {} likely semantic pairs with changed IDs",
            style::signal("·"),
            diff.semantic_pairs.len()
        );
        for pair in diff.semantic_pairs.iter().take(10) {
            println!(
                "  {} · {}  score {:.2}  {}",
                pair.id_a.dimmed(),
                pair.id_b.dimmed(),
                pair.score,
                pair.reason
            );
        }
        if diff.semantic_pairs.len() > 10 {
            println!("  ... and {} more", diff.semantic_pairs.len() - 10);
        }
    }

    if !diff.field_changes.is_empty() {
        println!(
            "\n{} {} field-level changes across paired findings",
            style::brass("~"),
            diff.field_changes.len()
        );
        for change in diff.field_changes.iter().take(10) {
            println!(
                "  {} · {} {}",
                change.id_a.dimmed(),
                change.id_b.dimmed(),
                change.field
            );
        }
        if diff.field_changes.len() > 10 {
            println!("  ... and {} more", diff.field_changes.len() - 10);
        }
    }

    println!();
    println!("  {}", "FRONTIER KERNEL DIFF".dimmed());
    println!(
        "  sources:           {} -> {}",
        diff.projections.sources.0, diff.projections.sources.1
    );
    println!(
        "  evidence atoms:    {} -> {}",
        diff.projections.evidence_atoms.0, diff.projections.evidence_atoms.1
    );
    println!(
        "  condition records: {} -> {}",
        diff.projections.condition_records.0, diff.projections.condition_records.1
    );
    println!(
        "  proposals:         {} -> {} (pending {} -> {}, applied {} -> {})",
        diff.proposal_state.total.0,
        diff.proposal_state.total.1,
        diff.proposal_state.pending_review.0,
        diff.proposal_state.pending_review.1,
        diff.proposal_state.applied.0,
        diff.proposal_state.applied.1
    );
    println!(
        "  canonical events:  {} -> {}",
        diff.event_log.events.0, diff.event_log.events.1
    );
    println!(
        "  proof state:       {} -> {}",
        diff.proof_state.status_a, diff.proof_state.status_b
    );
    if !diff.event_log.kinds_only_in_b.is_empty() {
        println!(
            "  new event kinds:   {}",
            diff.event_log.kinds_only_in_b.join(", ")
        );
    }

    if !diff.review_impacts.is_empty() {
        println!();
        println!("  {}", "REVIEW IMPACT".dimmed());
        for impact in diff.review_impacts.iter().take(10) {
            println!("  · [{}] {}", impact.kind, impact.message);
        }
    }

    // Confidence changes
    if !diff.confidence_changes.is_empty() {
        println!(
            "\n{} {} shared findings with confidence changes",
            style::brass("~"),
            diff.confidence_changes.len()
        );
        for c in diff.confidence_changes.iter().take(10) {
            let arrow = if c.delta > 0.0 {
                style::moss(format!(
                    "{:.2} -> {:.2} ({:+.2})",
                    c.score_a, c.score_b, c.delta
                ))
            } else {
                style::madder(format!(
                    "{:.2} -> {:.2} ({:+.2})",
                    c.score_a, c.score_b, c.delta
                ))
            };
            println!(
                "  {} {} {}",
                c.id.dimmed(),
                arrow,
                truncate(&c.assertion, 40)
            );
        }
        if diff.confidence_changes.len() > 10 {
            println!("  ... and {} more", diff.confidence_changes.len() - 10);
        }
    }

    // Review events
    if !diff.only_in_a_reviews.is_empty() || !diff.only_in_b_reviews.is_empty() {
        println!();
        println!("  {}", "REVIEW EVENT DIFF".dimmed());
        if !diff.only_in_b_reviews.is_empty() {
            println!(
                "  {} new review events in {}",
                diff.only_in_b_reviews.len(),
                style::moss(&diff.name_b)
            );
            for review in diff.only_in_b_reviews.iter().take(5) {
                println!(
                    "    {} {} {} {}",
                    style::moss("+"),
                    review.id.dimmed(),
                    review.action,
                    truncate(&review.reason, 45)
                );
            }
            if diff.only_in_b_reviews.len() > 5 {
                println!("    ... and {} more", diff.only_in_b_reviews.len() - 5);
            }
        }
        if !diff.only_in_a_reviews.is_empty() {
            println!(
                "  {} review events only in {}",
                diff.only_in_a_reviews.len(),
                style::madder(&diff.name_a)
            );
            for review in diff.only_in_a_reviews.iter().take(5) {
                println!(
                    "    {} {} {} {}",
                    style::madder("-"),
                    review.id.dimmed(),
                    review.action,
                    truncate(&review.reason, 45)
                );
            }
            if diff.only_in_a_reviews.len() > 5 {
                println!("    ... and {} more", diff.only_in_a_reviews.len() - 5);
            }
        }
    }

    // Dependency / lineage changes
    if !diff.only_in_a_dependencies.is_empty() || !diff.only_in_b_dependencies.is_empty() {
        println!();
        println!("  {}", "LINEAGE DIFF".dimmed());
        if !diff.only_in_b_dependencies.is_empty() {
            println!(
                "  {} ancestry entries only in {}",
                diff.only_in_b_dependencies.len(),
                style::moss(&diff.name_b)
            );
            for dep in diff.only_in_b_dependencies.iter().take(5) {
                println!(
                    "    {} {} [{}]",
                    style::moss("+"),
                    dep.name,
                    dep.source.dimmed()
                );
            }
        }
        if !diff.only_in_a_dependencies.is_empty() {
            println!(
                "  {} ancestry entries only in {}",
                diff.only_in_a_dependencies.len(),
                style::madder(&diff.name_a)
            );
            for dep in diff.only_in_a_dependencies.iter().take(5) {
                println!(
                    "    {} {} [{}]",
                    style::madder("-"),
                    dep.name,
                    dep.source.dimmed()
                );
            }
        }
    }

    // New contradictions
    if !diff.new_contradictions.is_empty() {
        println!(
            "\n{} {} new contradictions in {}",
            style::madder("·"),
            diff.new_contradictions.len(),
            diff.name_b
        );
        for c in &diff.new_contradictions {
            println!(
                "  {} · {} · {}",
                c.from_id.dimmed(),
                c.target_id.dimmed(),
                truncate(&c.note, 50)
            );
        }
    }

    // Entity coverage
    if !diff.entities_only_in_a.is_empty() || !diff.entities_only_in_b.is_empty() {
        println!();
        println!("  {}", "ENTITY COVERAGE DIFF".dimmed());
        if !diff.entities_only_in_b.is_empty() {
            println!(
                "  {} resolved in {} but not {}:",
                diff.entities_only_in_b.len(),
                diff.name_b,
                diff.name_a
            );
            for e in diff.entities_only_in_b.iter().take(10) {
                println!("    {} {}", style::moss("+"), e);
            }
            if diff.entities_only_in_b.len() > 10 {
                println!("    ... and {} more", diff.entities_only_in_b.len() - 10);
            }
        }
        if !diff.entities_only_in_a.is_empty() {
            println!(
                "  {} resolved in {} but not {}:",
                diff.entities_only_in_a.len(),
                diff.name_a,
                diff.name_b
            );
            for e in diff.entities_only_in_a.iter().take(10) {
                println!("    {} {}", style::madder("-"), e);
            }
            if diff.entities_only_in_a.len() > 10 {
                println!("    ... and {} more", diff.entities_only_in_a.len() - 10);
            }
        }
    }

    // Stats comparison
    println!();
    println!("  {}", "STATS COMPARISON".dimmed());
    let s = &diff.stats_comparison;
    println!(
        "  {:<18} {:>8}  {:>8}",
        "",
        diff.name_a.dimmed(),
        diff.name_b.dimmed()
    );
    print_stat_row("findings", s.findings.0, s.findings.1);
    print_stat_row("links", s.links.0, s.links.1);
    print_stat_row("replicated", s.replicated.0, s.replicated.1);
    print_stat_row("gaps", s.gaps.0, s.gaps.1);
    print_stat_row("contested", s.contested.0, s.contested.1);
    print_stat_row("review events", s.review_events.0, s.review_events.1);
    println!(
        "  {:<18} {:>8.3}  {:>8.3}",
        "avg confidence", s.avg_confidence.0, s.avg_confidence.1
    );

    println!();
    println!("  {}", style::tick_row(60));
    println!();
}

fn print_stat_row(label: &str, a: usize, b: usize) {
    let diff = b as i64 - a as i64;
    let delta = if diff > 0 {
        style::moss(format!("(+{})", diff)).to_string()
    } else if diff < 0 {
        style::madder(format!("({})", diff)).to_string()
    } else {
        String::new()
    };
    println!("  {:<18} {:>8}  {:>8}  {}", label, a, b, delta);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::*;
    use crate::project;
    use crate::sources;

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
                species: None,
                method: String::new(),
                sample_size: None,
                effect_size: None,
                p_value: None,
                replicated,
                replication_count: None,
                evidence_spans: vec![],
            },
            conditions: Conditions {
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
            confidence: Confidence::raw(score, "seeded prior", 0.85),
            provenance: Provenance {
                source_type: "published_paper".into(),
                doi: None,
                pmid: None,
                pmc: None,
                openalex_id: None,
                url: None,
                title: "Test".into(),
                authors: vec![],
                year: Some(2024),
                journal: None,
                license: None,
                publisher: None,
                funders: vec![],
                extraction: Extraction::default(),
                review: None,
                citation_count: None,
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

    fn make_frontier(name: &str, findings: Vec<FindingBundle>) -> Project {
        project::assemble(name, findings, 0, 0, "test")
    }

    fn make_review_event(id: &str, finding_id: &str, reason: &str) -> ReviewEvent {
        ReviewEvent {
            id: id.into(),
            workspace: None,
            finding_id: finding_id.into(),
            reviewer: "reviewer:test".into(),
            reviewed_at: "2026-01-01T00:00:00Z".into(),
            scope: None,
            status: Some("accepted".into()),
            action: ReviewAction::Approved,
            reason: reason.into(),
            evidence_considered: Vec::new(),
            state_change: None,
        }
    }

    #[test]
    fn identical_frontiers_have_no_diff() {
        let findings = vec![
            make_finding("f1", 0.8, "mechanism", false, false),
            make_finding("f2", 0.7, "therapeutic", true, false),
        ];
        let a = make_frontier("A", findings.clone());
        let b = make_frontier("B", findings);
        let d = compare(&a, &b);
        assert!(d.only_in_a.is_empty());
        assert!(d.only_in_b.is_empty());
        assert!(d.confidence_changes.is_empty());
    }

    #[test]
    fn detects_findings_only_in_a() {
        let a = make_frontier(
            "A",
            vec![
                make_finding("f1", 0.8, "mechanism", false, false),
                make_finding("f2", 0.7, "therapeutic", true, false),
            ],
        );
        let b = make_frontier(
            "B",
            vec![make_finding("f1", 0.8, "mechanism", false, false)],
        );
        let d = compare(&a, &b);
        assert_eq!(d.only_in_a.len(), 1);
        assert_eq!(d.only_in_a[0].id, "f2");
        assert!(d.only_in_b.is_empty());
    }

    #[test]
    fn detects_confidence_changes() {
        let a = make_frontier(
            "A",
            vec![make_finding("f1", 0.8, "mechanism", false, false)],
        );
        let b = make_frontier(
            "B",
            vec![make_finding("f1", 0.6, "mechanism", false, false)],
        );
        let d = compare(&a, &b);
        assert_eq!(d.confidence_changes.len(), 1);
        assert!((d.confidence_changes[0].delta - (-0.2)).abs() < 1e-6);
    }

    #[test]
    fn pairs_semantically_similar_changed_ids_and_fields() {
        let mut a_finding = make_finding("vf_old", 0.8, "mechanism", false, false);
        a_finding.assertion.text =
            "LRP1 mediates amyloid beta clearance at the blood brain barrier".into();
        a_finding.conditions.text = "human BBB context".into();
        a_finding.provenance.doi = Some("10.1234/test".into());
        let mut b_finding = make_finding("vf_new", 0.9, "mechanism", false, false);
        b_finding.assertion.text =
            "LRP1 mediates amyloid beta clearance at the blood brain barrier".into();
        b_finding.conditions.text = "human BBB context".into();
        b_finding.provenance.doi = Some("10.1234/test".into());

        let a = make_frontier("A", vec![a_finding]);
        let b = make_frontier("B", vec![b_finding]);
        let d = compare(&a, &b);
        assert_eq!(d.semantic_pairs.len(), 1);
        assert_eq!(d.semantic_pairs[0].id_a, "vf_old");
        assert_eq!(d.semantic_pairs[0].id_b, "vf_new");
        assert!(
            d.field_changes
                .iter()
                .any(|c| c.field == "confidence.score")
        );
    }

    #[test]
    fn detects_new_contradictions() {
        let mut fb = make_finding("f1", 0.8, "mechanism", false, false);
        fb.add_link("f2", "contradicts", "opposite direction");
        let a = make_frontier(
            "A",
            vec![make_finding("f1", 0.8, "mechanism", false, false)],
        );
        let b = make_frontier("B", vec![fb]);
        let d = compare(&a, &b);
        assert_eq!(d.new_contradictions.len(), 1);
    }

    #[test]
    fn detects_review_events_only_in_b() {
        let mut a = make_frontier(
            "A",
            vec![make_finding("f1", 0.8, "mechanism", false, false)],
        );
        let mut b = make_frontier(
            "B",
            vec![make_finding("f1", 0.8, "mechanism", false, false)],
        );
        a.review_events
            .push(make_review_event("rev_a", "f1", "existing local review"));
        a.stats.review_event_count = a.review_events.len();
        b.review_events
            .push(make_review_event("rev_a", "f1", "existing local review"));
        b.review_events
            .push(make_review_event("rev_b", "f1", "imported external review"));
        b.stats.review_event_count = b.review_events.len();

        let d = compare(&a, &b);
        assert_eq!(d.only_in_b_reviews.len(), 1);
        assert_eq!(d.only_in_b_reviews[0].id, "rev_b");
        assert_eq!(d.stats_comparison.review_events, (1, 2));
    }

    #[test]
    fn stats_comparison_correct() {
        let a = make_frontier(
            "A",
            vec![
                make_finding("f1", 0.8, "mechanism", true, false),
                make_finding("f2", 0.7, "mechanism", false, true),
            ],
        );
        let b = make_frontier(
            "B",
            vec![
                make_finding("f1", 0.8, "mechanism", true, false),
                make_finding("f2", 0.7, "mechanism", false, true),
                make_finding("f3", 0.9, "therapeutic", true, false),
            ],
        );
        let d = compare(&a, &b);
        assert_eq!(d.stats_comparison.findings, (2, 3));
        assert_eq!(d.stats_comparison.replicated, (1, 2));
        assert_eq!(d.stats_comparison.gaps, (1, 1));
    }

    #[test]
    fn diff_reports_frontier_kernel_state() {
        let mut a = make_frontier(
            "A",
            vec![make_finding("f1", 0.8, "mechanism", false, false)],
        );
        let mut b = make_frontier(
            "B",
            vec![make_finding("f1", 0.8, "mechanism", false, false)],
        );
        sources::materialize_project(&mut a);
        sources::materialize_project(&mut b);
        b.proof_state.latest_packet.status = "stale".into();
        b.proof_state.stale_reason = Some("new accepted proposal".into());

        let d = compare(&a, &b);
        assert_eq!(d.proof_state.status_b, "stale");
        assert!(
            d.review_impacts
                .iter()
                .any(|impact| impact.kind == "proof_state")
        );
    }
}
