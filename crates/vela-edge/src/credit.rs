//! v0.157: CRediT-style contributor ledger.
//!
//! Walks a frontier's canonical event log, maps each event kind
//! to one or more CRediT (Contributor Roles Taxonomy) roles, and
//! aggregates per actor. The output is a downstream-tooling-
//! ready record of "who contributed what" that can ride alongside
//! the v0.156 citation export when a frontier is submitted for
//! publication.
//!
//! The CRediT taxonomy (CASRAI, 2014; adopted by major
//! publishers) defines 14 roles. The substrate maps Vela's
//! canonical event kinds to the roles the substrate can attest
//! to: investigation (proposing findings), validation
//! (reviewing, attesting, retracting, revising confidence),
//! conceptualization (creating frontiers, adding entity tags,
//! bridging), data curation (repairing locators), resources
//! (governance actions), writing - review & editing (notes +
//! caveats).
//!
//! Roles not represented in canonical events:
//!
//! - Methodology, Formal analysis, Software, Visualization,
//!   Supervision, Project administration, Funding acquisition.
//!   These map to the operator's contributor metadata
//!   (provenance.authors fields, agent.yaml manifests). v0.157
//!   ships the event-derived view; a future cycle extends to
//!   actor-declared roles.
//!
//! Substrate-honest framing: the ledger is *derived*, not
//! *authored*. Two consumers walking the same event log produce
//! byte-identical ledgers (deterministic ordering by actor id,
//! then alphabetical role names within each actor).

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use vela_protocol::project::Project;

/// One CRediT role identifier. The 14-role taxonomy is encoded
/// as PascalCase variants; the on-disk serialization uses the
/// canonical CASRAI labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CreditRole {
    Conceptualization,
    Methodology,
    Software,
    Validation,
    FormalAnalysis,
    Investigation,
    Resources,
    DataCuration,
    WritingOriginalDraft,
    WritingReviewEditing,
    Visualization,
    Supervision,
    ProjectAdministration,
    FundingAcquisition,
}

impl CreditRole {
    /// CASRAI canonical label.
    pub fn label(&self) -> &'static str {
        match self {
            CreditRole::Conceptualization => "Conceptualization",
            CreditRole::Methodology => "Methodology",
            CreditRole::Software => "Software",
            CreditRole::Validation => "Validation",
            CreditRole::FormalAnalysis => "Formal analysis",
            CreditRole::Investigation => "Investigation",
            CreditRole::Resources => "Resources",
            CreditRole::DataCuration => "Data curation",
            CreditRole::WritingOriginalDraft => "Writing - original draft",
            CreditRole::WritingReviewEditing => "Writing - review & editing",
            CreditRole::Visualization => "Visualization",
            CreditRole::Supervision => "Supervision",
            CreditRole::ProjectAdministration => "Project administration",
            CreditRole::FundingAcquisition => "Funding acquisition",
        }
    }
}

/// Map a single canonical event kind to the CRediT roles it
/// attests to. Multiple roles can fire per event.
pub fn roles_for_event_kind(kind: &str) -> Vec<CreditRole> {
    match kind {
        // Frontier authorship.
        "frontier.created" => vec![CreditRole::Conceptualization],

        // Finding proposal + investigation.
        "finding.add" => vec![CreditRole::Investigation],
        "finding.reviewed" => vec![CreditRole::Validation],
        "finding.confidence_revise" => vec![CreditRole::Validation],
        "finding.retract" => vec![CreditRole::Validation],
        "finding.reject" => vec![CreditRole::Validation],
        "finding.supersede" => vec![CreditRole::Validation, CreditRole::WritingReviewEditing],

        // Annotation + editorial.
        "finding.note" => vec![CreditRole::WritingReviewEditing],
        "finding.caveat" => vec![CreditRole::WritingReviewEditing],

        // Entity resolution / conceptual structure.
        "finding.entity_add" => vec![CreditRole::Conceptualization],
        "finding.entity_resolve" => vec![CreditRole::Conceptualization],

        // Evidence curation.
        "evidence_atom.locator_repair" => vec![CreditRole::DataCuration],
        "evidence_atom.locator_repaired" => vec![CreditRole::DataCuration],
        "finding.span_repair" => vec![CreditRole::DataCuration],

        // Attestation = explicit validation.
        "attestation.recorded" => vec![CreditRole::Validation],

        // Bridges = conceptual cross-frontier connections.
        kind if kind.starts_with("bridge.") => vec![CreditRole::Conceptualization],

        // Governance actions = resources / supervision.
        kind if kind.starts_with("governance.") => vec![CreditRole::Resources],
        "registry.owner_rotated" => vec![CreditRole::Resources],

        // Unknown kinds attest no specific role; the substrate
        // records the participation under the implicit
        // Project-administration role to avoid losing the
        // contribution.
        _ => vec![CreditRole::ProjectAdministration],
    }
}

/// One contributor's aggregated record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContributorEntry {
    pub actor_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub orcid: Option<String>,
    /// CRediT roles the actor contributed to, sorted by role
    /// label for deterministic output.
    pub roles: Vec<String>,
    /// Per-role event counts (CASRAI label -> integer). Useful
    /// when a publisher wants to surface "validation: 42
    /// events" alongside the role list.
    #[serde(default)]
    pub role_counts: BTreeMap<String, u64>,
    /// Total event count attributable to this actor across the
    /// frontier's canonical event log.
    pub event_count: u64,
}

/// Top-level credit ledger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreditLedger {
    pub schema: String,
    pub frontier_id: String,
    pub generated_at: String,
    pub contributor_count: usize,
    pub contributors: Vec<ContributorEntry>,
}

pub const LEDGER_SCHEMA: &str = "vela.credit_ledger.v0.1";

/// Per-actor accumulator for the credit ledger builder. Pulled
/// into a named type so clippy stops complaining about the
/// nested tuple in the BTreeMap value.
struct ActorAccum {
    roles: BTreeSet<CreditRole>,
    counts: BTreeMap<CreditRole, u64>,
    total: u64,
}

/// Build a CRediT ledger from a frontier's canonical event log.
pub fn build_ledger(project: &Project, now: &str) -> CreditLedger {
    let mut by_actor: BTreeMap<String, ActorAccum> = BTreeMap::new();

    for event in &project.events {
        let actor_id = event.actor.id.clone();
        if actor_id.is_empty() {
            continue;
        }
        let roles = roles_for_event_kind(event.kind.as_str());
        let entry = by_actor.entry(actor_id).or_insert_with(|| ActorAccum {
            roles: BTreeSet::new(),
            counts: BTreeMap::new(),
            total: 0,
        });
        for r in &roles {
            entry.roles.insert(*r);
            *entry.counts.entry(*r).or_insert(0) += 1;
        }
        entry.total += 1;
    }

    // Look up ORCID per actor from the frontier's actor records.
    let orcid_by_actor: BTreeMap<String, Option<String>> = project
        .actors
        .iter()
        .map(|a| (a.id.clone(), a.orcid.clone()))
        .collect();

    let mut contributors: Vec<ContributorEntry> = by_actor
        .into_iter()
        .map(|(actor_id, accum)| {
            let role_labels: Vec<String> =
                accum.roles.iter().map(|r| r.label().to_string()).collect();
            let role_counts: BTreeMap<String, u64> = accum
                .counts
                .into_iter()
                .map(|(r, c)| (r.label().to_string(), c))
                .collect();
            let orcid = orcid_by_actor.get(&actor_id).cloned().flatten();
            ContributorEntry {
                actor_id,
                orcid,
                roles: role_labels,
                role_counts,
                event_count: accum.total,
            }
        })
        .collect();

    contributors.sort_by(|a, b| a.actor_id.cmp(&b.actor_id));

    CreditLedger {
        schema: LEDGER_SCHEMA.to_string(),
        frontier_id: project.frontier_id(),
        generated_at: now.to_string(),
        contributor_count: contributors.len(),
        contributors,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_mapping_basic_kinds() {
        assert_eq!(
            roles_for_event_kind("finding.add"),
            vec![CreditRole::Investigation]
        );
        assert_eq!(
            roles_for_event_kind("finding.reviewed"),
            vec![CreditRole::Validation]
        );
        assert_eq!(
            roles_for_event_kind("frontier.created"),
            vec![CreditRole::Conceptualization]
        );
    }

    #[test]
    fn role_mapping_supersede_emits_two_roles() {
        let roles = roles_for_event_kind("finding.supersede");
        assert!(roles.contains(&CreditRole::Validation));
        assert!(roles.contains(&CreditRole::WritingReviewEditing));
    }

    #[test]
    fn unknown_event_kind_falls_back_to_project_administration() {
        assert_eq!(
            roles_for_event_kind("custom.weird.kind"),
            vec![CreditRole::ProjectAdministration]
        );
    }

    #[test]
    fn bridge_kinds_map_to_conceptualization() {
        assert_eq!(
            roles_for_event_kind("bridge.confirmed"),
            vec![CreditRole::Conceptualization]
        );
    }
}
