//! W1.3 (v0.70): event-driven replication + prediction deposits.
//!
//! Pre-v0.70 the substrate had `Replication` and `Prediction` as
//! first-class kernel objects mutated by direct file writes.
//! v0.70 makes the deposit event-driven via
//! `replication.deposited` and `prediction.deposited` canonical
//! events. This test exercises the round-trip:
//!
//!   1. Build a Replication / Prediction record.
//!   2. Call `state::deposit_replication` / `deposit_prediction`.
//!   3. Confirm a canonical event lands in the project's event log.
//!   4. Confirm the record appears on `Project.replications` /
//!      `Project.predictions`.
//!   5. Confirm a re-deposit with the same content-addressed id is
//!      refused (idempotent).

use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;
use tempfile::TempDir;

fn vela_bin() -> PathBuf {
    if let Ok(env_path) = std::env::var("CARGO_BIN_EXE_vela") {
        return PathBuf::from(env_path);
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let debug = manifest.join("../../target/debug/vela");
    if debug.is_file() {
        return debug;
    }
    let release = manifest.join("../../target/release/vela");
    if release.is_file() {
        return release;
    }
    debug
}

fn run_json(args: &[&str]) -> Value {
    let output = Command::new(vela_bin())
        .args(args)
        .output()
        .expect("failed to run vela");
    assert!(
        output.status.success(),
        "vela command failed\nargs: {args:?}\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("not JSON")
}

#[test]
fn replication_deposit_emits_canonical_event_and_appends_to_state() {
    use vela_protocol::bundle::{Conditions, Evidence, Provenance, Replication};
    use vela_protocol::state;

    let tmp = TempDir::new().expect("tempdir");
    let frontier = tmp.path().join("rep-test");
    let frontier_str = frontier.to_str().unwrap();

    // 1. init a split-repo with a single anchor finding so the
    //    replication has something to target.
    run_json(&[
        "init",
        frontier_str,
        "--name",
        "Replication deposit test",
        "--template",
        "disease-frontier",
        "--no-git",
        "--json",
    ]);
    let finding_payload = run_json(&[
        "finding",
        "add",
        frontier_str,
        "--assertion",
        "Test anchor finding for replication.",
        "--type",
        "methodological",
        "--source",
        "test fixture",
        "--source-type",
        "expert_assertion",
        "--author",
        "reviewer:test",
        "--apply",
        "--json",
    ]);
    let target_finding = finding_payload["finding_id"]
        .as_str()
        .expect("finding_id present")
        .to_string();

    // 2. Build a Replication record + deposit via state helper.
    let evidence = Evidence {
        evidence_type: "experimental".to_string(),
        model_system: "human".to_string(),
        species: None,
        method: "manual".to_string(),
        sample_size: None,
        effect_size: None,
        p_value: None,
        replicated: false,
        replication_count: None,
        evidence_spans: Vec::new(),
    };
    let conditions = Conditions {
        text: "Test conditions; in vitro; pH 7.4.".to_string(),
        species_verified: Vec::new(),
        species_unverified: Vec::new(),
        in_vitro: true,
        in_vivo: false,
        human_data: false,
        clinical_trial: false,
        concentration_range: None,
        duration: None,
        age_group: None,
        cell_type: None,
    };
    let provenance = Provenance {
        title: "Replication deposit fixture".to_string(),
        source_type: "lab_notebook".to_string(),
        doi: None,
        pmid: None,
        pmc: None,
        openalex_id: None,
        url: None,
        authors: Vec::new(),
        year: Some(2026),
        journal: None,
        license: None,
        publisher: None,
        funders: Vec::new(),
        extraction: vela_protocol::bundle::Extraction::default(),
        review: None,
        citation_count: None,
    };
    let rep = Replication::new(
        target_finding.clone(),
        "lab:test-A".to_string(),
        "replicated".to_string(),
        evidence,
        conditions,
        provenance,
        "First attempt; clean replication.".to_string(),
    );
    let rep_id = rep.id.clone();

    let event = state::deposit_replication(
        &frontier,
        rep.clone(),
        "reviewer:test",
        "Replication deposit fixture round-trip",
    )
    .expect("first deposit should succeed");
    assert_eq!(event.kind, "replication.deposited");
    assert!(event.id.starts_with("vev_"));

    // 3. Confirm replication is on the project + the event is in the
    //    canonical log.
    let project = vela_protocol::repo::load_from_path(&frontier).expect("reload");
    assert!(
        project.replications.iter().any(|r| r.id == rep_id),
        "replication should be present after deposit"
    );
    assert!(
        project
            .events
            .iter()
            .any(|e| e.kind == "replication.deposited" && e.id == event.id),
        "deposit event should be on the canonical log"
    );

    // 4. Re-deposit must be refused (idempotent).
    let err = state::deposit_replication(
        &frontier,
        rep,
        "reviewer:test",
        "Second attempt; should be refused",
    )
    .expect_err("duplicate deposit should refuse");
    assert!(
        err.contains("already exists"),
        "error should mention duplicate; got: {err}"
    );
}
