//! F2: Multi-actor joint-signature end-to-end test.
//!
//! The substrate ships threshold_met / refresh_jointly_accepted /
//! sign_frontier (v0.37). Existing unit tests cover the in-memory
//! cases. This integration test exercises the full flow on a
//! disk-backed frontier:
//!
//!   1. Build a frontier with one finding carrying
//!      `flags.signature_threshold = Some(2)`.
//!   2. Two distinct Ed25519 keypairs sign the finding.
//!   3. Save the frontier, reload, refresh the
//!      `jointly_accepted` flag.
//!   4. Assert: 2 unique signatures, threshold met,
//!      jointly_accepted is true.
//!
//! Also asserts the negative case: same key signing twice does NOT
//! reach the threshold (signers must be distinct).

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use vela_protocol::bundle::{
    Assertion, Conditions, Confidence, Evidence, Extraction, FindingBundle, Flags, Provenance,
};
use vela_protocol::project::{self, Project};
use vela_protocol::sign::{
    refresh_jointly_accepted, sign_finding, threshold_met, valid_signature_count,
};
use vela_protocol::{events, repo};

fn fresh_keypair() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

fn fixture_finding() -> FindingBundle {
    FindingBundle::new(
        Assertion {
            text: "Multi-sig fixture finding".to_string(),
            assertion_type: "mechanism".to_string(),
            entities: Vec::new(),
            relation: None,
            direction: None,
            causal_claim: None,
            causal_evidence_grade: None,
        },
        Evidence {
            evidence_type: "experimental".to_string(),
            model_system: "human".to_string(),
            species: Some("Homo sapiens".to_string()),
            method: "manual".to_string(),
            sample_size: None,
            effect_size: None,
            p_value: None,
            replicated: false,
            replication_count: None,
            evidence_spans: Vec::new(),
        },
        Conditions {
            text: "fixture context".to_string(),
            species_verified: vec!["Homo sapiens".to_string()],
            species_unverified: Vec::new(),
            in_vitro: false,
            in_vivo: false,
            human_data: true,
            clinical_trial: false,
            concentration_range: None,
            duration: None,
            age_group: None,
            cell_type: None,
        },
        Confidence::raw(0.5, "fixture", 0.8),
        Provenance {
            source_type: "published_paper".to_string(),
            doi: Some("10.1/test-multi-sig".to_string()),
            pmid: None,
            pmc: None,
            openalex_id: None,
            url: None,
            title: "Multi-sig fixture source".to_string(),
            authors: Vec::new(),
            year: Some(2026),
            journal: None,
            license: None,
            publisher: None,
            funders: Vec::new(),
            extraction: Extraction::default(),
            review: None,
            citation_count: None,
        },
        Flags {
            gap: false,
            negative_space: false,
            contested: false,
            retracted: false,
            declining: false,
            gravity_well: false,
            review_state: None,
            superseded: false,
            signature_threshold: Some(2),
            jointly_accepted: false,
        },
    )
}

fn frontier_with_threshold_finding() -> Project {
    project::assemble("multi-sig-fixture", vec![fixture_finding()], 0, 0, "test")
}

#[test]
fn two_distinct_signers_meet_threshold_and_set_jointly_accepted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("frontier.json");
    let mut project = frontier_with_threshold_finding();
    let finding_id = project.findings[0].id.clone();

    let key_a = fresh_keypair();
    let key_b = fresh_keypair();
    let env_a = sign_finding(&project.findings[0], &key_a).expect("sign a");
    let env_b = sign_finding(&project.findings[0], &key_b).expect("sign b");
    project.signatures.push(env_a);
    project.signatures.push(env_b);

    repo::save_to_path(&path, &project).expect("save");
    let mut reloaded = repo::load_from_path(&path).expect("reload");

    assert_eq!(valid_signature_count(&reloaded, &finding_id), 2);
    assert!(
        threshold_met(&reloaded, &finding_id),
        "two distinct signers must meet threshold of 2"
    );

    refresh_jointly_accepted(&mut reloaded);
    let f = reloaded
        .findings
        .iter()
        .find(|f| f.id == finding_id)
        .unwrap();
    assert!(
        f.flags.jointly_accepted,
        "jointly_accepted must be true after threshold is met"
    );
}

#[test]
fn one_signer_does_not_meet_two_threshold() {
    let mut project = frontier_with_threshold_finding();
    let finding_id = project.findings[0].id.clone();
    let key = fresh_keypair();
    let env = sign_finding(&project.findings[0], &key).expect("sign");
    project.signatures.push(env);

    assert_eq!(valid_signature_count(&project, &finding_id), 1);
    assert!(
        !threshold_met(&project, &finding_id),
        "one of two does not meet threshold"
    );

    refresh_jointly_accepted(&mut project);
    assert!(!project.findings[0].flags.jointly_accepted);
}

#[test]
fn same_key_twice_counts_once_against_threshold() {
    let mut project = frontier_with_threshold_finding();
    let finding_id = project.findings[0].id.clone();
    let key = fresh_keypair();
    // Same key signs twice — second signature is a duplicate signer.
    let env1 = sign_finding(&project.findings[0], &key).expect("sign 1");
    let env2 = sign_finding(&project.findings[0], &key).expect("sign 2");
    project.signatures.push(env1);
    project.signatures.push(env2);

    // valid_signature_count counts unique public keys, not raw envelopes.
    assert_eq!(
        valid_signature_count(&project, &finding_id),
        1,
        "same key twice must count as one unique signer"
    );
    assert!(!threshold_met(&project, &finding_id));
}

#[test]
fn threshold_can_be_one_and_self_qualifies() {
    let mut project = frontier_with_threshold_finding();
    project.findings[0].flags.signature_threshold = Some(1);
    let finding_id = project.findings[0].id.clone();
    let key = fresh_keypair();
    let env = sign_finding(&project.findings[0], &key).expect("sign");
    project.signatures.push(env);

    assert!(threshold_met(&project, &finding_id));
    refresh_jointly_accepted(&mut project);
    assert!(project.findings[0].flags.jointly_accepted);
}

#[test]
fn no_threshold_set_never_jointly_accepted() {
    let mut project = frontier_with_threshold_finding();
    project.findings[0].flags.signature_threshold = None;
    let finding_id = project.findings[0].id.clone();
    let key_a = fresh_keypair();
    let key_b = fresh_keypair();
    project
        .signatures
        .push(sign_finding(&project.findings[0], &key_a).unwrap());
    project
        .signatures
        .push(sign_finding(&project.findings[0], &key_b).unwrap());

    assert!(
        !threshold_met(&project, &finding_id),
        "no threshold means single-sig regime; threshold_met returns false"
    );
    refresh_jointly_accepted(&mut project);
    assert!(!project.findings[0].flags.jointly_accepted);

    // Sanity: pretend we wrote it to disk.
    let _ = events::event_log_hash(&project.events);
}
