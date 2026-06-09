use std::fs;
use std::path::{Path, PathBuf};

use tempfile::tempdir;
use vela_edge::reviewer_identity::{self, AttestationInput, AttestationScope};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .to_path_buf()
}

fn copy_dir(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).expect("create copied frontier");
    for entry in fs::read_dir(src).expect("read source dir") {
        let entry = entry.expect("read entry");
        let path = entry.path();
        let target = dst.join(entry.file_name());
        if path.is_dir() {
            copy_dir(&path, &target);
        } else {
            fs::copy(&path, &target).expect("copy file");
        }
    }
}

#[test]
fn records_diff_pack_attestation_without_event_mutation() {
    let tmp = tempdir().unwrap();
    let frontier = tmp.path().join("frontier");
    let source = repo_root().join("examples/early-ad");
    if !source.exists() {
        eprintln!("skipping: campaign fixture {source:?} absent in this checkout");
        return;
    }
    copy_dir(&source, &frontier);

    let before = vela_protocol::repo::load_from_path(&frontier)
        .expect("load frontier")
        .events
        .len();
    let report = reviewer_identity::record(
        &frontier,
        AttestationInput {
            target_id: "vsd_be61da0cdcba08ed".to_string(),
            scopes: vec![AttestationScope::DomainRelevance],
            reviewer_id: "reviewer:domain-one".to_string(),
            role: "domain_reviewer".to_string(),
            reason: "Domain relevance reviewed for this diff pack.".to_string(),
            orcid: Some("https://orcid.org/0000-0000-0000-000X".to_string()),
            ror: Some("https://ror.org/03yrm5c26".to_string()),
            proof_id: None,
            signature: None,
        },
    )
    .expect("record attestation");

    assert!(report.attestation.attestation_id.starts_with("vatt_"));
    assert_eq!(report.attestation.target_kind, "diff_pack");
    assert!(Path::new(&report.path).exists());
    let after = vela_protocol::repo::load_from_path(&frontier)
        .expect("load frontier")
        .events
        .len();
    assert_eq!(before, after, "diff pack attestation stays local");
}

#[test]
fn event_attestation_records_local_file_and_canonical_event() {
    let tmp = tempdir().unwrap();
    let frontier = tmp.path().join("frontier");
    let source = repo_root().join("examples/early-ad");
    if !source.exists() {
        eprintln!("skipping: campaign fixture {source:?} absent in this checkout");
        return;
    }
    copy_dir(&source, &frontier);

    let target = "vev_85621cac7ca02583";
    let report = reviewer_identity::record(
        &frontier,
        AttestationInput {
            target_id: target.to_string(),
            scopes: vec![
                AttestationScope::SourceExtraction,
                AttestationScope::MethodReview,
            ],
            reviewer_id: "reviewer:method-one".to_string(),
            role: "method_reviewer".to_string(),
            reason: "Method and source extraction reviewed for this event.".to_string(),
            orcid: None,
            ror: None,
            proof_id: None,
            signature: None,
        },
    )
    .expect("record event attestation");

    let event_id = report
        .attestation
        .canonical_event_id
        .expect("canonical event id");
    let frontier = vela_protocol::repo::load_from_path(&frontier).expect("load frontier");
    let event = frontier
        .events
        .iter()
        .find(|event| event.id == event_id)
        .expect("attestation event");
    assert_eq!(event.kind, "attestation.recorded");
    assert_eq!(event.payload["target_event_id"], target);
    assert_eq!(event.payload["reviewer_role"], "method_reviewer");
    assert_eq!(event.payload["scopes"][0], "source_extraction");
    assert_eq!(event.payload["scopes"][1], "method_review");
}
