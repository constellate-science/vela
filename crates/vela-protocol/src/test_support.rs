//! Shared test fixtures for the protocol record types.
//!
//! Available to this crate's own `#[cfg(test)]` code and, via the
//! `test-support` feature, to downstream crates' tests (e.g. vela-edge tests
//! that need a `Project`/`FindingBundle` to exercise edge behavior over real
//! records). It is never compiled into a normal build, so it adds nothing to
//! the protocol's public surface or the narrow waist.

use crate::bundle::*;
use crate::project::{self, Project};

/// A synthetic, fully-populated finding with one entity and a raw-confidence
/// prior. `score` sets the confidence value.
pub fn make_finding(id: &str, score: f64, assertion_type: &str) -> FindingBundle {
    FindingBundle {
        id: id.into(),
        version: 1,
        previous_version: None,
        assertion: Assertion {
            text: format!("Finding {id}"),
            assertion_type: assertion_type.into(),
            entities: vec![Entity {
                name: "TestEntity".into(),
                entity_type: "protein".into(),
                identifiers: serde_json::Map::new(),
                canonical_id: None,
                candidates: vec![],
                aliases: vec![],
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
        annotations: vec![],
        attachments: vec![],
        created: String::new(),
        updated: None,
        access_tier: crate::access_tier::AccessTier::Public,
    }
}

/// Assemble a `Project` from findings, with placeholder counts and description.
pub fn make_project(name: &str, findings: Vec<FindingBundle>) -> Project {
    project::assemble(name, findings, 10, 0, "Test project")
}
