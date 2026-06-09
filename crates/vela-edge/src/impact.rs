//! Read-only dependency impact reports.

use std::collections::{BTreeSet, VecDeque};
use std::path::Path;

use serde::{Deserialize, Serialize};

use vela_protocol::events;
use vela_protocol::project::Project;
use vela_protocol::repo;

pub const IMPACT_SCHEMA: &str = "vela.impact_report.v0.1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImpactTarget {
    pub r#type: String,
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImpactFrontier {
    pub vfr_id: String,
    pub snapshot_hash: String,
    pub event_log_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImpactSummary {
    pub direct_dependents: usize,
    pub total_downstream: usize,
    pub open_proposals: usize,
    pub accepted_events: usize,
    pub proof_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImpactDownstream {
    pub finding_id: String,
    pub depth: usize,
    pub via_link_type: String,
    pub via_finding_id: String,
    pub cross_frontier: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImpactProposal {
    pub id: String,
    pub kind: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImpactEvent {
    pub id: String,
    pub kind: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImpactReport {
    pub schema: String,
    pub target: ImpactTarget,
    pub frontier: ImpactFrontier,
    pub summary: ImpactSummary,
    #[serde(default)]
    pub downstream: Vec<ImpactDownstream>,
    #[serde(default)]
    pub proposals: Vec<ImpactProposal>,
    #[serde(default)]
    pub events: Vec<ImpactEvent>,
    #[serde(default)]
    pub caveats: Vec<String>,
}

pub fn analyze_path(
    path: &Path,
    finding_id: &str,
    depth: Option<usize>,
) -> Result<ImpactReport, String> {
    let frontier = repo::load_from_path(path)?;
    analyze(&frontier, finding_id, depth)
}

pub fn analyze(
    frontier: &Project,
    finding_id: &str,
    depth: Option<usize>,
) -> Result<ImpactReport, String> {
    if !frontier
        .findings
        .iter()
        .any(|finding| finding.id == finding_id)
    {
        return Err(format!("finding not found: {finding_id}"));
    }
    let max_depth = depth.unwrap_or(3).max(1);
    let downstream = downstream(frontier, finding_id, max_depth);
    let proposals = frontier
        .proposals
        .iter()
        .filter(|proposal| proposal.target.r#type == "finding" && proposal.target.id == finding_id)
        .map(|proposal| ImpactProposal {
            id: proposal.id.clone(),
            kind: proposal.kind.clone(),
            status: proposal.status.clone(),
        })
        .collect::<Vec<_>>();
    let events = frontier
        .events
        .iter()
        .filter(|event| event.target.r#type == "finding" && event.target.id == finding_id)
        .map(|event| ImpactEvent {
            id: event.id.clone(),
            kind: event.kind.clone(),
            reason: event.reason.clone(),
        })
        .collect::<Vec<_>>();
    let direct_dependents = downstream.iter().filter(|item| item.depth == 1).count();
    let open_proposals = proposals
        .iter()
        .filter(|proposal| {
            proposal.status == "pending_review" || proposal.status == "needs_revision"
        })
        .count();
    let accepted_events = events.len();
    Ok(ImpactReport {
        schema: IMPACT_SCHEMA.to_string(),
        target: ImpactTarget {
            r#type: "finding".to_string(),
            id: finding_id.to_string(),
        },
        frontier: ImpactFrontier {
            vfr_id: frontier
                .frontier_id
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
            snapshot_hash: events::snapshot_hash(frontier),
            event_log_hash: events::event_log_hash(&frontier.events),
        },
        summary: ImpactSummary {
            direct_dependents,
            total_downstream: downstream.len(),
            open_proposals,
            accepted_events,
            proof_status: proof_status(frontier),
        },
        downstream,
        proposals,
        events,
        caveats: vec![
            "Impact is a read-only dependency report over declared links, not automatic confidence propagation.".to_string(),
        ],
    })
}

fn downstream(frontier: &Project, finding_id: &str, max_depth: usize) -> Vec<ImpactDownstream> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::<String>::new();
    let mut queue = VecDeque::from([(finding_id.to_string(), 0usize)]);
    while let Some((target, depth)) = queue.pop_front() {
        if depth >= max_depth {
            continue;
        }
        for finding in &frontier.findings {
            for link in &finding.links {
                if !matches!(
                    link.link_type.as_str(),
                    "supports" | "depends" | "contradicts"
                ) {
                    continue;
                }
                if link_target_matches(&link.target, &target) && seen.insert(finding.id.clone()) {
                    let next_depth = depth + 1;
                    out.push(ImpactDownstream {
                        finding_id: finding.id.clone(),
                        depth: next_depth,
                        via_link_type: link.link_type.clone(),
                        via_finding_id: target.clone(),
                        cross_frontier: link.target.contains("@vfr_"),
                    });
                    queue.push_back((finding.id.clone(), next_depth));
                }
            }
        }
    }
    out.sort_by(|a, b| a.depth.cmp(&b.depth).then(a.finding_id.cmp(&b.finding_id)));
    out
}

fn link_target_matches(link_target: &str, target: &str) -> bool {
    link_target == target
        || link_target
            .split_once('@')
            .is_some_and(|(id, _)| id == target)
}

fn proof_status(frontier: &Project) -> String {
    let status = frontier.proof_state.latest_packet.status.as_str();
    match status {
        "current" => "fresh".to_string(),
        "stale" => "stale".to_string(),
        _ => "unknown".to_string(),
    }
}
