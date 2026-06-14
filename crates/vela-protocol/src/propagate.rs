//! Correction propagation through the frontier link graph.
//!
//! When a finding is corrected or retracted, everything that depends on it
//! should know. This module walks the link graph and flags downstream findings,
//! creating ReviewEvent records for each propagation step.

use std::collections::{HashMap, HashSet, VecDeque};

use chrono::Utc;
use sha2::{Digest, Sha256};

use colored::Colorize;

use crate::bundle::{FindingBundle, ReviewAction, ReviewEvent};
use crate::cli_style as style;
use crate::events::{
    EVENT_SCHEMA, StateActor, StateEvent, StateTarget, compute_event_id, finding_hash,
};
use crate::project::Project;
use serde_json::json;

/// The type of correction being propagated.
#[derive(Debug, Clone)]
pub enum PropagationAction {
    /// Source paper was retracted. Mark finding as retracted, flag all dependents.
    Retracted,
    /// A specific field was corrected. Flag dependents if assertion text or direction changed.
    Corrected {
        field: String,
        original: String,
        corrected: String,
    },
    /// Confidence was reduced to a specific value. Flag dependents if below 0.5.
    ConfidenceReduced { new_score: f64 },
    /// v0.36.1: A `vrep_<id>` replication record landed against the
    /// target finding. The target's confidence is recomputed from the
    /// updated `Project.replications` collection (via
    /// `Project::compute_confidence_for`). Dependents are flagged for
    /// review when:
    /// - `failed` / `partial`: downstream may need to weaken;
    /// - `replicated`: downstream may now safely strengthen.
    /// `inconclusive` outcomes do not cascade — they represent
    /// methodological ambiguity, not evidence.
    ReplicationOutcome { outcome: String, vrep_id: String },
}

/// Result of a propagation pass.
pub struct PropagationResult {
    /// Total findings directly or transitively affected.
    pub affected: usize,
    /// Finding IDs affected at each depth level.
    pub cascade: Vec<Vec<String>>,
    /// Review events created during propagation.
    pub events: Vec<ReviewEvent>,
}

/// Maximum recursion depth to prevent runaway cascades.
const MAX_DEPTH: usize = 3;

/// Propagate a correction through the frontier. Returns a PropagationResult
/// describing the cascade.
pub fn propagate_correction(
    frontier: &mut Project,
    finding_id: &str,
    action: PropagationAction,
) -> PropagationResult {
    let now = Utc::now().to_rfc3339();

    // Build a reverse adjacency map: target_id -> list of (source_idx, link_type).
    // We want findings that link TO the corrected finding via supports or depends.
    let mut reverse_links: HashMap<String, Vec<(usize, String)>> = HashMap::new();
    for (idx, finding) in frontier.findings.iter().enumerate() {
        for link in &finding.links {
            if link.link_type == "supports" || link.link_type == "depends" {
                reverse_links
                    .entry(link.target.clone())
                    .or_default()
                    .push((idx, link.link_type.clone()));
            }
        }
    }

    // Also build forward links: source finding has links with target.
    // Findings that the corrected finding supports or that depend on it.
    let mut forward_deps: HashMap<String, Vec<(usize, String)>> = HashMap::new();
    for (idx, finding) in frontier.findings.iter().enumerate() {
        for link in &finding.links {
            forward_deps
                .entry(finding.id.clone())
                .or_default()
                .push((idx, link.link_type.clone()));
        }
    }

    // Find the source finding index.
    let source_idx = frontier.findings.iter().position(|f| f.id == finding_id);

    let mut events: Vec<ReviewEvent> = Vec::new();
    let mut cascade: Vec<Vec<String>> = Vec::new();

    // Step 1: Apply the action to the source finding itself.
    if let Some(idx) = source_idx {
        match &action {
            PropagationAction::Retracted => {
                frontier.findings[idx].flags.retracted = true;
                let event = make_event(
                    finding_id,
                    "propagation_engine",
                    &now,
                    ReviewAction::Flagged {
                        flag_type: "retracted".into(),
                    },
                    "Source paper retracted",
                );
                events.push(event);
            }
            PropagationAction::Corrected {
                field,
                original,
                corrected,
            } => {
                let event = make_event(
                    finding_id,
                    "propagation_engine",
                    &now,
                    ReviewAction::Corrected {
                        field: field.clone(),
                        original: original.clone(),
                        corrected: corrected.clone(),
                    },
                    "Upstream correction applied",
                );
                events.push(event);
            }
            PropagationAction::ConfidenceReduced { new_score } => {
                let old = frontier.findings[idx].confidence.score;
                frontier.findings[idx].confidence.score = *new_score;
                frontier.findings[idx].confidence.basis = format!(
                    "Reduced from {:.3} to {:.3} (manual correction)",
                    old, new_score
                );
                let event = make_event(
                    finding_id,
                    "propagation_engine",
                    &now,
                    ReviewAction::Flagged {
                        flag_type: format!("confidence_reduced_to_{:.2}", new_score),
                    },
                    &format!("Confidence reduced from {:.3} to {:.3}", old, new_score),
                );
                events.push(event);
            }
            PropagationAction::ReplicationOutcome { outcome, vrep_id } => {
                // Recompute the target finding's confidence from the
                // current `Project.replications` collection. This is the
                // v0.36.1 source-of-truth path: confidence is a function
                // of recorded replications, not the legacy scalar flag.
                let target_bundle = frontier.findings[idx].clone();
                let new_conf = frontier.compute_confidence_for(&target_bundle);
                let old = frontier.findings[idx].confidence.score;
                let new_score = new_conf.score;
                // v0.43.0 fix: capture the finding's hash *before* mutating
                // it, then emit a canonical `finding.confidence_revised`
                // state event after mutation so the per-finding event
                // chain stays continuous. Pre-v0.43.0 the cascade
                // mutated confidence silently and broke replay.
                let before_hash = finding_hash(&frontier.findings[idx]);
                frontier.findings[idx].confidence = new_conf;
                let after_hash = finding_hash(&frontier.findings[idx]);
                let revise_reason = format!(
                    "{outcome} replication {vrep_id} recorded; confidence {:.3} -> {:.3}",
                    old, new_score
                );
                let mut state_event = StateEvent {
                    schema: EVENT_SCHEMA.to_string(),
                    id: String::new(),
                    kind: "finding.confidence_revised".to_string(),
                    target: StateTarget {
                        r#type: "finding".to_string(),
                        id: finding_id.to_string(),
                    },
                    actor: StateActor {
                        id: "propagation_engine".to_string(),
                        r#type: "system".to_string(),
                    },
                    timestamp: now.clone(),
                    reason: revise_reason.clone(),
                    before_hash,
                    after_hash,
                    payload: json!({
                        "proposal_id": format!("vpr_synthetic_{}", &vrep_id[..vrep_id.len().min(16)]),
                        "previous_score": old,
                        "new_score": new_score,
                        "trigger": "replication_outcome",
                        "vrep_id": vrep_id,
                        "outcome": outcome,
                    }),
                    caveats: Vec::new(),
                    signature: None,
                    schema_artifact_id: None,
                };
                state_event.id = compute_event_id(&state_event);
                frontier.events.push(state_event);

                // Also emit the human-readable review event for the
                // review queue (existing v0.36.1 behavior).
                let event = make_event(
                    finding_id,
                    "propagation_engine",
                    &now,
                    ReviewAction::Flagged {
                        flag_type: format!("replication_{}", outcome),
                    },
                    &revise_reason,
                );
                events.push(event);
            }
        }
    }

    // Step 2: BFS through dependents, up to MAX_DEPTH.
    let mut visited: HashSet<String> = HashSet::new();
    visited.insert(finding_id.to_string());

    let mut queue: VecDeque<(String, usize)> = VecDeque::new();
    queue.push_back((finding_id.to_string(), 0));

    while let Some((current_id, depth)) = queue.pop_front() {
        if depth >= MAX_DEPTH {
            continue;
        }

        // Find all findings that have a supports/depends link targeting current_id.
        let dependents = find_dependents(&frontier.findings, &current_id);

        if dependents.is_empty() {
            continue;
        }

        let mut level_ids: Vec<String> = Vec::new();

        for dep_idx in dependents {
            let dep_id = frontier.findings[dep_idx].id.clone();
            if visited.contains(&dep_id) {
                continue;
            }
            visited.insert(dep_id.clone());

            // Flag the dependent finding.
            let (flag_type, reason) = match &action {
                PropagationAction::Retracted => (
                    "upstream_retracted".to_string(),
                    format!(
                        "Upstream finding {} was retracted (depth {})",
                        finding_id,
                        depth + 1
                    ),
                ),
                PropagationAction::Corrected { field, .. } => (
                    "upstream_corrected".to_string(),
                    format!(
                        "Upstream finding {} had field '{}' corrected (depth {})",
                        finding_id,
                        field,
                        depth + 1
                    ),
                ),
                PropagationAction::ConfidenceReduced { new_score } => {
                    if *new_score < 0.5 {
                        (
                            "upstream_at_risk".to_string(),
                            format!(
                                "Upstream finding {} confidence reduced to {:.2} (depth {})",
                                finding_id,
                                new_score,
                                depth + 1
                            ),
                        )
                    } else {
                        continue; // Only propagate if below 0.5
                    }
                }
                PropagationAction::ReplicationOutcome { outcome, .. } => match outcome.as_str() {
                    "failed" => (
                        "upstream_replication_failed".to_string(),
                        format!(
                            "Upstream finding {} failed replication (depth {})",
                            finding_id,
                            depth + 1
                        ),
                    ),
                    "partial" => (
                        "upstream_replication_partial".to_string(),
                        format!(
                            "Upstream finding {} partially replicated (depth {})",
                            finding_id,
                            depth + 1
                        ),
                    ),
                    "replicated" => (
                        "upstream_replication_succeeded".to_string(),
                        format!(
                            "Upstream finding {} replicated successfully (depth {})",
                            finding_id,
                            depth + 1
                        ),
                    ),
                    // `inconclusive` and unknown outcomes do not cascade.
                    _ => continue,
                },
            };

            let event = make_event(
                &dep_id,
                "propagation_engine",
                &now,
                ReviewAction::Flagged {
                    flag_type: flag_type.clone(),
                },
                &reason,
            );
            events.push(event);
            level_ids.push(dep_id.clone());

            // If retracted, also mark the dependent as contested.
            if matches!(action, PropagationAction::Retracted) {
                frontier.findings[dep_idx].flags.contested = true;
            }

            queue.push_back((dep_id, depth + 1));
        }

        if !level_ids.is_empty() {
            // Ensure cascade has enough depth levels.
            while cascade.len() <= depth {
                cascade.push(Vec::new());
            }
            cascade[depth].extend(level_ids);
        }
    }

    let affected = cascade.iter().map(|level| level.len()).sum();

    PropagationResult {
        affected,
        cascade,
        events,
    }
}

/// Find indices of findings that have a supports or depends link targeting the
/// given finding ID.
fn find_dependents(findings: &[FindingBundle], target_id: &str) -> Vec<usize> {
    findings
        .iter()
        .enumerate()
        .filter(|(_, f)| {
            f.links.iter().any(|l| {
                l.target == target_id && (l.link_type == "supports" || l.link_type == "depends")
            })
        })
        .map(|(idx, _)| idx)
        .collect()
}

/// Create a content-addressed review event.
fn make_event(
    finding_id: &str,
    reviewer: &str,
    timestamp: &str,
    action: ReviewAction,
    reason: &str,
) -> ReviewEvent {
    let content = serde_json::json!({
        "finding_id": finding_id,
        "reviewer": reviewer,
        "reviewed_at": timestamp,
        "action": action,
        "reason": reason,
    });
    let canonical = serde_json::to_string(&content).unwrap_or_default();
    let hash = Sha256::digest(canonical.as_bytes());
    let id = format!("rev_{}", &hex::encode(hash)[..16]);

    ReviewEvent {
        id,
        workspace: None,
        finding_id: finding_id.to_string(),
        reviewer: reviewer.to_string(),
        reviewed_at: timestamp.to_string(),
        scope: None,
        status: None,
        action,
        reason: reason.to_string(),
        evidence_considered: Vec::new(),
        state_change: None,
    }
}

/// Create a review event recording a retraction with a human-readable reason.
pub fn make_retraction_event(finding_id: &str, reason: &str) -> ReviewEvent {
    let now = Utc::now().to_rfc3339();
    make_event(
        finding_id,
        "retraction",
        &now,
        ReviewAction::Flagged {
            flag_type: "retracted".into(),
        },
        reason,
    )
}

/// Print a propagation result to stdout.
pub fn print_result(result: &PropagationResult, action_label: &str, finding_id: &str) {
    println!();
    println!(
        "  {}",
        format!(
            "VELA · PROPAGATE · {} · {}",
            action_label.to_uppercase(),
            finding_id
        )
        .dimmed()
    );
    println!("  {}", style::tick_row(60));
    println!("  {} findings affected", result.affected);

    for (depth, ids) in result.cascade.iter().enumerate() {
        if !ids.is_empty() {
            println!("  depth {}: {} findings", depth + 1, ids.len());
            for id in ids {
                println!("    · {}", id);
            }
        }
    }

    if !result.events.is_empty() {
        println!();
        println!("  review events created: {}", result.events.len());
        for event in &result.events {
            println!(
                "    {} · {} · {}",
                event.id.dimmed(),
                event.finding_id,
                event.reason
            );
        }
    }
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::*;
    use crate::project;

    fn make_finding(id: &str, score: f64) -> FindingBundle {
        FindingBundle {
            id: id.into(),
            version: 1,
            previous_version: None,
            assertion: Assertion {
                text: format!("Finding {id}"),
                assertion_type: "mechanism".into(),
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
                replicated: false,
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
            confidence: Confidence::raw(score, "test", 0.85),
            provenance: Provenance {
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
            links: vec![],
            attachments: vec![],
            annotations: vec![],
            created: String::new(),
            updated: None,

            access_tier: crate::access_tier::AccessTier::Public,
        }
    }

    fn make_frontier(findings: Vec<FindingBundle>) -> Project {
        project::assemble("test", findings, 1, 0, "test frontier")
    }

    #[test]
    fn retraction_propagates() {
        let a = make_finding("a", 0.8);
        let mut b = make_finding("b", 0.7);
        // b depends on a
        b.add_link("a", "depends", "b depends on a");

        let mut c = make_frontier(vec![a, b]);
        let result = propagate_correction(&mut c, "a", PropagationAction::Retracted);

        // a should be retracted
        assert!(c.findings[0].flags.retracted);
        // b should be contested (flagged)
        assert!(c.findings[1].flags.contested);
        assert_eq!(result.affected, 1);
    }

    #[test]
    fn confidence_reduction_propagates_below_half() {
        let a = make_finding("a", 0.8);
        let mut b = make_finding("b", 0.7);
        b.add_link("a", "supports", "b supports a");

        let mut c = make_frontier(vec![a, b]);
        let result = propagate_correction(
            &mut c,
            "a",
            PropagationAction::ConfidenceReduced { new_score: 0.3 },
        );

        assert!((c.findings[0].confidence.score - 0.3).abs() < 0.001);
        assert_eq!(result.affected, 1);
    }

    #[test]
    fn confidence_above_half_does_not_propagate() {
        let a = make_finding("a", 0.8);
        let mut b = make_finding("b", 0.7);
        b.add_link("a", "supports", "b supports a");

        let mut c = make_frontier(vec![a, b]);
        let result = propagate_correction(
            &mut c,
            "a",
            PropagationAction::ConfidenceReduced { new_score: 0.6 },
        );

        // Confidence updated on source, but no cascade.
        assert!((c.findings[0].confidence.score - 0.6).abs() < 0.001);
        assert_eq!(result.affected, 0);
    }

    #[test]
    fn failed_replication_flags_dependents() {
        // a is supported by b. A failed replication of a lands.
        // b should be flagged with `upstream_replication_failed`.
        let a = make_finding("vf_aaaa", 0.8);
        let mut b = make_finding("vf_bbbb", 0.7);
        b.add_link("vf_aaaa", "supports", "b supports a");
        let mut frontier = make_frontier(vec![a, b]);
        let result = propagate_correction(
            &mut frontier,
            "vf_aaaa",
            PropagationAction::ReplicationOutcome {
                outcome: "failed".into(),
                vrep_id: "vrep_test01".into(),
            },
        );
        // b should be flagged.
        assert_eq!(result.affected, 1);
        assert!(
            result
                .events
                .iter()
                .any(|e| matches!(&e.action,
                    ReviewAction::Flagged { flag_type } if flag_type == "upstream_replication_failed"))
        );
    }

    #[test]
    fn successful_replication_recomputes_target_and_flags_dependents() {
        // a has a successful replication. After propagation, a's
        // confidence is recomputed from Project.replications, and
        // b is flagged for review.
        let a = make_finding("vf_aaaa", 0.5);
        let mut b = make_finding("vf_bbbb", 0.5);
        b.add_link("vf_aaaa", "depends", "b depends on a");
        let mut frontier = make_frontier(vec![a, b]);

        // Inject a replicated record so compute_confidence_for has
        // something to count.
        frontier.replications.push(Replication {
            id: "vrep_test02".into(),
            target_finding: "vf_aaaa".into(),
            attempted_by: "lab:test".into(),
            outcome: "replicated".into(),
            evidence: frontier.findings[0].evidence.clone(),
            conditions: frontier.findings[0].conditions.clone(),
            provenance: frontier.findings[0].provenance.clone(),
            notes: String::new(),
            created: String::new(),
            previous_attempt: None,
        });

        let result = propagate_correction(
            &mut frontier,
            "vf_aaaa",
            PropagationAction::ReplicationOutcome {
                outcome: "replicated".into(),
                vrep_id: "vrep_test02".into(),
            },
        );

        // Target's confidence was recomputed.
        assert_eq!(
            frontier.findings[0].confidence.method,
            ConfidenceMethod::Computed
        );
        // Dependent flagged for review.
        assert_eq!(result.affected, 1);
        assert!(
            result
                .events
                .iter()
                .any(|e| matches!(&e.action,
                    ReviewAction::Flagged { flag_type } if flag_type == "upstream_replication_succeeded"))
        );
    }

    #[test]
    fn inconclusive_replication_does_not_cascade() {
        let a = make_finding("vf_aaaa", 0.7);
        let mut b = make_finding("vf_bbbb", 0.7);
        b.add_link("vf_aaaa", "supports", "");
        let mut frontier = make_frontier(vec![a, b]);
        let result = propagate_correction(
            &mut frontier,
            "vf_aaaa",
            PropagationAction::ReplicationOutcome {
                outcome: "inconclusive".into(),
                vrep_id: "vrep_test03".into(),
            },
        );
        // Source still gets a recompute event, but no dependents flagged.
        assert_eq!(result.affected, 0);
    }

    #[test]
    fn depth_limit_respected() {
        // Chain: a <- b <- c <- d <- e (each depends on previous)
        let a = make_finding("a", 0.8);
        let mut b = make_finding("b", 0.7);
        b.add_link("a", "depends", "");
        let mut c_f = make_finding("c", 0.7);
        c_f.add_link("b", "depends", "");
        let mut d = make_finding("d", 0.7);
        d.add_link("c", "depends", "");
        let mut e = make_finding("e", 0.7);
        e.add_link("d", "depends", "");

        let mut frontier = make_frontier(vec![a, b, c_f, d, e]);
        let result = propagate_correction(&mut frontier, "a", PropagationAction::Retracted);

        // Should stop at depth 3: b, c, d get flagged; e does not.
        assert!(result.affected <= 3);
    }
}
