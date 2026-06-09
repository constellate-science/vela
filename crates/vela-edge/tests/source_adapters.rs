use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use chrono::Utc;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::tempdir;
use vela_protocol::access_tier::AccessTier;
use vela_protocol::bundle::{
    Artifact, Assertion, Author, Conditions, Confidence, ConfidenceKind, ConfidenceMethod, Entity,
    Evidence, Extraction, FindingBundle, Flags, Provenance, Review,
};
use vela_protocol::canonical;
use vela_protocol::project;
use vela_protocol::repo;
use vela_edge::source_adapters;
fn sha256_for_value(value: &Value) -> String {
    let bytes = canonical::to_canonical_bytes(value).expect("canonical bytes");
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn sha256_for_bytes(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn trial_record(nct_id: &str, title: &str, status: &str) -> Value {
    json!({
        "protocolSection": {
            "identificationModule": {
                "nctId": nct_id,
                "briefTitle": title
            },
            "statusModule": {
                "overallStatus": status
            },
            "designModule": {
                "phases": ["PHASE3"]
            }
        }
    })
}

fn regulatory_record(entry_id: &str, content: &str, content_type: &str) -> Value {
    json!({
        "schema": "vela.regulatory-source-record.v1",
        "entry_id": entry_id,
        "name": "Primary regulatory source",
        "source_type": "regulatory",
        "representation": "registry_record",
        "locator": format!("https://example.org/{entry_id}"),
        "content_type": content_type,
        "content_length": content.len(),
        "content_hash": sha256_for_bytes(content.as_bytes())
    })
}

fn provenance(title: &str, url: &str) -> Provenance {
    Provenance {
        source_type: "clinical_trial".to_string(),
        doi: None,
        pmid: None,
        pmc: None,
        openalex_id: None,
        url: Some(url.to_string()),
        title: title.to_string(),
        authors: vec![Author {
            name: "ClinicalTrials.gov".to_string(),
            orcid: None,
        }],
        year: None,
        journal: None,
        license: None,
        publisher: Some("ClinicalTrials.gov".to_string()),
        funders: Vec::new(),
        extraction: Extraction {
            method: "source_adapter_fixture".to_string(),
            model: None,
            model_version: None,
            extracted_at: Utc::now().to_rfc3339(),
            extractor_version: "test".to_string(),
        },
        review: Some(Review {
            reviewed: true,
            reviewer: Some("reviewer:test".to_string()),
            reviewed_at: Some(Utc::now().to_rfc3339()),
            corrections: Vec::new(),
        }),
        citation_count: None,
    }
}

fn write_fixture(input_dir: &Path, nct_id: &str, record: &Value) {
    fs::create_dir_all(input_dir).expect("fixture dir");
    fs::write(
        input_dir.join(format!("{nct_id}.json")),
        serde_json::to_string_pretty(record).expect("fixture json"),
    )
    .expect("write fixture");
}

fn write_regulatory_fixture(input_dir: &Path, entry_id: &str, content: &str) {
    fs::create_dir_all(input_dir).expect("fixture dir");
    fs::write(input_dir.join(format!("{entry_id}.txt")), content).expect("write fixture");
}

fn write_previous_run_record(repo_dir: &Path, nct_id: &str, record: &Value) {
    let run_dir = repo_dir.join("ingest/runs/sir_previous/records");
    fs::create_dir_all(&run_dir).expect("previous run dir");
    fs::write(
        run_dir.join(format!("{nct_id}.json")),
        serde_json::to_string_pretty(record).expect("previous record json"),
    )
    .expect("write previous record");
}

fn write_previous_regulatory_record(repo_dir: &Path, entry_id: &str, record: &Value) {
    let run_dir = repo_dir.join("ingest/runs/sir_previous/records");
    fs::create_dir_all(&run_dir).expect("previous run dir");
    fs::write(
        run_dir.join(format!("{entry_id}.json")),
        serde_json::to_string_pretty(record).expect("previous record json"),
    )
    .expect("write previous record");
}

fn write_plan(repo_dir: &Path, artifact_id: Option<&str>, excluded: bool) {
    fs::create_dir_all(repo_dir.join("ingest")).expect("ingest dir");
    let excluded_status = if excluded { "excluded" } else { "ingested" };
    let plan = json!({
        "schema": "vela.source-ingest-plan.v1",
        "frontier_id": "vfr_test",
        "name": "test source ingest plan",
        "verified_at": "2026-05-06T00:00:00Z",
        "policy": {},
        "entries": [
            {
                "id": "ct-primary",
                "name": "Primary trial",
                "category": "clinical_trial_registry",
                "priority": "P0",
                "representation": "clinical_trial_record",
                "source_type": "registry_record",
                "locator": "https://clinicaltrials.gov/study/NCT00000001",
                "ingest_status": "ingested",
                "current_frontier_artifact_id": artifact_id,
                "access_terms": "ClinicalTrials.gov public record",
                "license_note": "Public registry metadata.",
                "target_findings": ["vf_test"],
                "target_use": "Anchor the test trial."
            },
            {
                "id": "ct-secondary",
                "name": "Secondary trial",
                "category": "clinical_trial_registry",
                "priority": "P1",
                "representation": "clinical_trial_record",
                "source_type": "registry_record",
                "locator": "https://clinicaltrials.gov/study/NCT00000002",
                "ingest_status": "ingested",
                "current_frontier_artifact_id": null,
                "access_terms": "ClinicalTrials.gov public record",
                "license_note": "Public registry metadata.",
                "target_findings": ["vf_test"],
                "target_use": "Secondary test trial."
            },
            {
                "id": "ct-excluded",
                "name": "Excluded trial",
                "category": "clinical_trial_registry",
                "priority": "P0",
                "representation": "clinical_trial_record",
                "source_type": "registry_record",
                "locator": "https://clinicaltrials.gov/study/NCT00000999",
                "ingest_status": excluded_status,
                "current_frontier_artifact_id": null,
                "access_terms": "ClinicalTrials.gov public record",
                "license_note": "Excluded fixture row.",
                "target_findings": ["vf_test"],
                "target_use": "Excluded test trial."
            }
        ]
    });
    fs::write(
        repo_dir.join("ingest/source-ingest-plan.v1.json"),
        serde_json::to_string_pretty(&plan).expect("plan json"),
    )
    .expect("write plan");
}

fn write_regulatory_plan(repo_dir: &Path, artifact_id: Option<&str>, excluded: bool) {
    fs::create_dir_all(repo_dir.join("ingest")).expect("ingest dir");
    let excluded_status = if excluded { "excluded" } else { "ingested" };
    let plan = json!({
        "schema": "vela.source-ingest-plan.v1",
        "frontier_id": "vfr_test",
        "name": "test source ingest plan",
        "verified_at": "2026-05-06T00:00:00Z",
        "policy": {},
        "entries": [
            {
                "id": "reg-primary",
                "name": "Primary regulatory source",
                "category": "regulatory",
                "priority": "P0",
                "representation": "registry_record",
                "source_type": "regulatory",
                "locator": "https://example.org/reg-primary",
                "ingest_status": "ingested",
                "current_frontier_artifact_id": artifact_id,
                "access_terms": "Public agency page.",
                "license_note": "Public source metadata only.",
                "target_findings": ["vf_test"],
                "target_use": "Anchor the regulatory status."
            },
            {
                "id": "reg-secondary",
                "name": "Secondary regulatory source",
                "category": "regulatory",
                "priority": "P1",
                "representation": "registry_record",
                "source_type": "regulatory",
                "locator": "https://example.org/reg-secondary",
                "ingest_status": "ingested",
                "current_frontier_artifact_id": null,
                "access_terms": "Public agency page.",
                "license_note": "Public source metadata only.",
                "target_findings": ["vf_test"],
                "target_use": "Secondary regulatory status."
            },
            {
                "id": "reg-excluded",
                "name": "Excluded regulatory source",
                "category": "regulatory",
                "priority": "P0",
                "representation": "registry_record",
                "source_type": "regulatory",
                "locator": "https://example.org/reg-excluded",
                "ingest_status": excluded_status,
                "current_frontier_artifact_id": null,
                "access_terms": "Public agency page.",
                "license_note": "Excluded fixture row.",
                "target_findings": ["vf_test"],
                "target_use": "Excluded regulatory status."
            }
        ]
    });
    fs::write(
        repo_dir.join("ingest/source-ingest-plan.v1.json"),
        serde_json::to_string_pretty(&plan).expect("plan json"),
    )
    .expect("write plan");
}

fn init_frontier(existing_artifact: Option<Artifact>) -> (tempfile::TempDir, PathBuf) {
    let dir = tempdir().expect("tempdir");
    let repo_dir = dir.path().join("frontier");
    let mut frontier = project::assemble(
        "source adapter test",
        vec![test_finding()],
        0,
        0,
        "test frontier",
    );
    frontier.frontier_id = Some("vfr_test".to_string());
    if let Some(artifact) = existing_artifact {
        frontier.artifacts.push(artifact);
    }
    repo::init_repo(&repo_dir, &frontier).expect("init repo");
    (dir, repo_dir)
}

fn test_finding() -> FindingBundle {
    FindingBundle {
        id: "vf_test".to_string(),
        version: 1,
        previous_version: None,
        assertion: Assertion {
            text: "Test finding".to_string(),
            assertion_type: "therapeutic".to_string(),
            entities: vec![Entity {
                name: "amyloid beta".to_string(),
                entity_type: "protein".to_string(),
                identifiers: serde_json::Map::new(),
                canonical_id: None,
                candidates: Vec::new(),
                aliases: Vec::new(),
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
            evidence_type: "experimental".to_string(),
            model_system: String::new(),
            species: None,
            method: "manual".to_string(),
            sample_size: None,
            effect_size: None,
            p_value: None,
            replicated: false,
            replication_count: None,
            evidence_spans: Vec::new(),
        },
        conditions: Conditions {
            text: "test clinical setting".to_string(),
            species_verified: Vec::new(),
            species_unverified: Vec::new(),
            in_vitro: false,
            in_vivo: false,
            human_data: true,
            clinical_trial: true,
            concentration_range: None,
            duration: None,
            age_group: None,
            cell_type: None,
        },
        confidence: Confidence {
            kind: ConfidenceKind::FrontierEpistemic,
            score: 0.7,
            basis: "test".to_string(),
            method: ConfidenceMethod::ExpertJudgment,
            components: None,
            extraction_confidence: 1.0,
        },
        provenance: provenance("Test", "https://clinicaltrials.gov/study/NCT00000001"),
        flags: Flags::default(),
        links: Vec::new(),
        annotations: Vec::new(),
        attachments: Vec::new(),
        created: "2026-05-06T00:00:00Z".to_string(),
        updated: None,
        access_tier: AccessTier::Public,
    }
}

fn clinical_trial_artifact(record: &Value) -> Artifact {
    let hash = sha256_for_value(record);
    Artifact::new(
        "clinical_trial_record",
        "ClinicalTrials.gov NCT00000001",
        hash,
        None,
        Some("application/json".to_string()),
        "remote",
        Some("https://clinicaltrials.gov/api/v2/studies/NCT00000001".to_string()),
        Some("https://clinicaltrials.gov/study/NCT00000001".to_string()),
        Some("ClinicalTrials.gov public record".to_string()),
        Vec::new(),
        provenance(
            "ClinicalTrials.gov NCT00000001",
            "https://clinicaltrials.gov/study/NCT00000001",
        ),
        BTreeMap::new(),
        AccessTier::Public,
    )
    .expect("artifact")
}

fn regulatory_artifact(entry_id: &str, content: &str) -> Artifact {
    let hash = sha256_for_bytes(content.as_bytes());
    Artifact::new(
        "registry_record",
        "Primary regulatory source",
        hash,
        None,
        Some("text/plain".to_string()),
        "remote",
        Some(format!("https://example.org/{entry_id}")),
        Some(format!("https://example.org/{entry_id}")),
        Some("Public agency page.".to_string()),
        vec!["vf_test".to_string()],
        provenance(
            "Primary regulatory source",
            &format!("https://example.org/{entry_id}"),
        ),
        BTreeMap::from([
            ("entry_id".to_string(), json!(entry_id)),
            (
                "source_adapter".to_string(),
                json!("regulatory-documents-v1"),
            ),
        ]),
        AccessTier::Public,
    )
    .expect("artifact")
}

fn regulatory_locator_manifest_artifact(entry_id: &str, url: &str) -> (Artifact, Vec<u8>) {
    let manifest = json!({
        "access_terms": "public locator; stored as a Vela manifest, not copied source bytes",
        "created_at": "2026-05-06T00:00:00Z",
        "metadata": {
            "agency": "FDA"
        },
        "name": "Primary regulatory source",
        "retrieved_for": "test frontier",
        "source_title": "Primary regulatory source",
        "url": url
    });
    let bytes = serde_json::to_vec_pretty(&manifest).expect("manifest bytes");
    let hash = sha256_for_bytes(&bytes);
    let locator = format!(
        ".vela/artifact-blobs/sha256/{}",
        hash.strip_prefix("sha256:").expect("hash prefix")
    );
    let artifact = Artifact::new(
        "registry_record",
        "Primary regulatory source",
        hash,
        Some(bytes.len() as u64),
        Some("application/json".to_string()),
        "local_blob",
        Some(locator),
        Some(url.to_string()),
        Some("Public agency page.".to_string()),
        vec!["vf_test".to_string()],
        provenance("Primary regulatory source", url),
        BTreeMap::from([("entry_id".to_string(), json!(entry_id))]),
        AccessTier::Public,
    )
    .expect("artifact");
    (artifact, bytes)
}

fn write_artifact_blob(repo_dir: &Path, artifact: &Artifact, bytes: &[u8]) {
    let locator = artifact.locator.as_deref().expect("artifact locator");
    let path = repo_dir.join(locator);
    fs::create_dir_all(path.parent().expect("blob parent")).expect("blob dir");
    fs::write(path, bytes).expect("write blob");
}

fn options(input_dir: &Path) -> source_adapters::SourceAdapterRunOptions {
    source_adapters::SourceAdapterRunOptions {
        adapter: "clinicaltrials-gov-v2".to_string(),
        actor: "reviewer:test-source-adapter".to_string(),
        entries: Vec::new(),
        priority: Some("P0".to_string()),
        include_excluded: false,
        allow_partial: false,
        dry_run: false,
        input_dir: Some(input_dir.to_path_buf()),
        apply_artifacts: false,
        write_inbox: false,
    }
}

fn regulatory_options(input_dir: &Path) -> source_adapters::SourceAdapterRunOptions {
    source_adapters::SourceAdapterRunOptions {
        adapter: "regulatory-documents-v1".to_string(),
        actor: "reviewer:test-source-adapter".to_string(),
        entries: Vec::new(),
        priority: Some("P0".to_string()),
        include_excluded: false,
        allow_partial: false,
        dry_run: false,
        input_dir: Some(input_dir.to_path_buf()),
        apply_artifacts: false,
        write_inbox: false,
    }
}

#[tokio::test]
async fn clinicaltrials_adapter_dry_run_selects_p0_and_skips_excluded_without_mutation() {
    let record = trial_record("NCT00000001", "Primary fixture trial", "RECRUITING");
    let (_tmp, repo_dir) = init_frontier(None);
    write_plan(&repo_dir, None, true);
    let input_dir = repo_dir.join("fixtures");
    write_fixture(&input_dir, "NCT00000001", &record);
    let mut opts = options(&input_dir);
    opts.dry_run = true;

    let report = source_adapters::run(&repo_dir, opts).await.expect("run");

    assert!(report.ok);
    assert!(report.dry_run);
    assert_eq!(report.selected_entries, 1);
    assert_eq!(report.fetched_records, 1);
    assert_eq!(report.changed_records, 1);
    assert_eq!(report.unchanged_records, 0);
    assert_eq!(report.skipped_excluded, 1);
    assert!(report.packet_path.is_none());
    assert!(!repo_dir.join("ingest/runs").exists());
    let frontier = repo::load_from_path(&repo_dir).expect("frontier");
    assert!(frontier.proposals.is_empty());
    assert!(frontier.artifacts.is_empty());
}

#[tokio::test]
async fn clinicaltrials_adapter_applies_changed_artifacts_without_truth_proposals() {
    let old_record = trial_record("NCT00000001", "Primary fixture trial", "RECRUITING");
    let old_artifact = clinical_trial_artifact(&old_record);
    let artifact_id = old_artifact.id.clone();
    let new_record = trial_record(
        "NCT00000001",
        "Primary fixture trial",
        "ACTIVE_NOT_RECRUITING",
    );
    let (_tmp, repo_dir) = init_frontier(Some(old_artifact));
    write_plan(&repo_dir, Some(&artifact_id), true);
    let input_dir = repo_dir.join("fixtures");
    write_fixture(&input_dir, "NCT00000001", &new_record);
    let mut opts = options(&input_dir);
    opts.apply_artifacts = true;

    let report = source_adapters::run(&repo_dir, opts).await.expect("run");

    assert_eq!(report.selected_entries, 1);
    assert_eq!(report.changed_records, 1);
    assert_eq!(report.unchanged_records, 0);
    assert_eq!(report.artifact_proposals, 2);
    assert_eq!(report.applied_event_ids.len(), 2);
    assert_eq!(report.trusted_state_effect, "artifact_only");
    assert!(report.idempotency.packet_hash.starts_with("sha256:"));
    assert!(report.packet_path.is_some());
    let packet_path = report.packet_path.as_ref().expect("packet path");
    let packet: Value =
        serde_json::from_str(&fs::read_to_string(packet_path).expect("packet")).expect("json");
    assert_eq!(packet["schema"], "carina.artifact_packet.v0.1");
    assert_eq!(packet["artifacts"].as_array().expect("artifacts").len(), 2);
    assert_eq!(
        packet["artifacts"][1]["metadata"]["old_content_hash"],
        sha256_for_value(&old_record)
    );
    assert_eq!(
        packet["artifacts"][1]["metadata"]["new_content_hash"],
        sha256_for_value(&new_record)
    );

    let frontier = repo::load_from_path(&repo_dir).expect("frontier");
    assert_eq!(
        frontier
            .artifacts
            .iter()
            .filter(|artifact| artifact.kind == "clinical_trial_record")
            .count(),
        2
    );
    assert!(frontier.artifacts.iter().any(|artifact| {
        artifact.kind == "clinical_trial_record"
            && artifact.content_hash == sha256_for_value(&new_record)
            && artifact.target_findings == vec!["vf_test".to_string()]
    }));
    let plan: Value = serde_json::from_str(
        &fs::read_to_string(repo_dir.join("ingest/source-ingest-plan.v1.json")).expect("plan"),
    )
    .expect("plan json");
    let updated_artifact_id = plan["entries"][0]["current_frontier_artifact_id"]
        .as_str()
        .expect("current artifact id");
    assert_ne!(updated_artifact_id, artifact_id);
    assert!(frontier.artifacts.iter().any(|artifact| {
        artifact.id == updated_artifact_id && artifact.content_hash == sha256_for_value(&new_record)
    }));
    assert_eq!(
        frontier
            .proposals
            .iter()
            .filter(|proposal| proposal.kind == "finding.add")
            .count(),
        0
    );
}

#[tokio::test]
async fn changed_clinicaltrials_fields_create_review_note_tasks_for_target_findings() {
    let old_record = trial_record("NCT00000001", "Primary fixture trial", "RECRUITING");
    let old_artifact = clinical_trial_artifact(&old_record);
    let artifact_id = old_artifact.id.clone();
    let new_record = trial_record(
        "NCT00000001",
        "Primary fixture trial",
        "ACTIVE_NOT_RECRUITING",
    );
    let (_tmp, repo_dir) = init_frontier(Some(old_artifact));
    write_plan(&repo_dir, Some(&artifact_id), true);
    write_previous_run_record(&repo_dir, "NCT00000001", &old_record);
    let input_dir = repo_dir.join("fixtures");
    write_fixture(&input_dir, "NCT00000001", &new_record);

    let report = source_adapters::run(&repo_dir, options(&input_dir))
        .await
        .expect("run");

    assert_eq!(report.changed_records, 1);
    assert_eq!(report.review_note_proposals, 1);
    assert_eq!(report.review_proposal_ids.len(), 1);
    assert_eq!(report.records[0].changed_fields.len(), 1);
    assert_eq!(report.records[0].changed_fields[0].field, "overall_status");
    assert_eq!(
        report.records[0].changed_fields[0].old_value,
        Some("RECRUITING".to_string())
    );
    assert_eq!(
        report.records[0].changed_fields[0].new_value,
        Some("ACTIVE_NOT_RECRUITING".to_string())
    );

    let frontier = repo::load_from_path(&repo_dir).expect("frontier");
    let review_proposal = frontier
        .proposals
        .iter()
        .find(|proposal| proposal.id == report.review_proposal_ids[0])
        .expect("review proposal");
    assert_eq!(review_proposal.kind, "finding.note");
    assert_eq!(review_proposal.target.id, "vf_test");
    assert_eq!(review_proposal.status, "pending_review");
    let text = review_proposal
        .payload
        .get("text")
        .and_then(Value::as_str)
        .expect("note text");
    assert!(text.contains("NCT00000001"));
    assert!(text.contains("overall status"));
    assert!(text.contains("RECRUITING"));
    assert!(text.contains("ACTIVE_NOT_RECRUITING"));
}

#[tokio::test]
async fn unchanged_clinicaltrials_records_do_not_emit_duplicate_trial_artifacts() {
    let record = trial_record("NCT00000001", "Primary fixture trial", "RECRUITING");
    let artifact = clinical_trial_artifact(&record);
    let artifact_id = artifact.id.clone();
    let (_tmp, repo_dir) = init_frontier(Some(artifact));
    write_plan(&repo_dir, Some(&artifact_id), true);
    let input_dir = repo_dir.join("fixtures");
    write_fixture(&input_dir, "NCT00000001", &record);
    let mut opts = options(&input_dir);
    opts.apply_artifacts = true;

    let report = source_adapters::run(&repo_dir, opts).await.expect("run");

    assert_eq!(report.selected_entries, 1);
    assert_eq!(report.fetched_records, 1);
    assert_eq!(report.unchanged_records, 1);
    assert_eq!(report.changed_records, 0);
    assert_eq!(report.artifact_proposals, 1);
    let packet: Value = serde_json::from_str(
        &fs::read_to_string(report.packet_path.as_ref().expect("packet path")).expect("packet"),
    )
    .expect("json");
    let clinical_artifacts = packet["artifacts"]
        .as_array()
        .expect("artifacts")
        .iter()
        .filter(|artifact| artifact["kind"] == "clinical_trial_record")
        .count();
    assert_eq!(clinical_artifacts, 0);
}

#[tokio::test]
async fn clinicaltrials_adapter_rerun_is_deterministic_and_duplicate_safe() {
    let record = trial_record("NCT00000001", "Primary fixture trial", "RECRUITING");
    let (_tmp, repo_dir) = init_frontier(None);
    write_plan(&repo_dir, None, true);
    let input_dir = repo_dir.join("fixtures");
    write_fixture(&input_dir, "NCT00000001", &record);

    let first = source_adapters::run(&repo_dir, options(&input_dir))
        .await
        .expect("first run");
    let second = source_adapters::run(&repo_dir, options(&input_dir))
        .await
        .expect("second run");

    assert_eq!(first.run_id, second.run_id);
    assert_eq!(first.packet_id, second.packet_id);
    assert_eq!(
        first.idempotency.packet_hash,
        second.idempotency.packet_hash
    );
    assert!(!first.idempotency.duplicate_packet);
    assert!(second.idempotency.duplicate_packet);
    assert_eq!(
        second.idempotency.skipped_existing_proposals.len()
            + second.idempotency.skipped_existing_artifacts.len(),
        first.proposal_ids.len()
    );

    let frontier = repo::load_from_path(&repo_dir).expect("frontier");
    assert_eq!(frontier.proposals.len(), first.proposal_ids.len());
    assert!(
        frontier
            .proposals
            .iter()
            .all(|proposal| proposal.status == "pending_review")
    );
}

#[tokio::test]
async fn missing_clinicaltrials_record_fails_unless_partial_allowed() {
    let (_tmp, repo_dir) = init_frontier(None);
    write_plan(&repo_dir, None, true);
    let input_dir = repo_dir.join("fixtures");
    fs::create_dir_all(&input_dir).expect("fixtures");

    let err = source_adapters::run(&repo_dir, options(&input_dir))
        .await
        .expect_err("missing fixture should fail");
    assert!(err.contains("NCT00000001"));

    let mut opts = options(&input_dir);
    opts.allow_partial = true;
    let report = source_adapters::run(&repo_dir, opts)
        .await
        .expect("partial run");
    assert_eq!(report.failed_records.len(), 1);
    assert_eq!(report.fetched_records, 0);
}

#[tokio::test]
async fn regulatory_adapter_selects_p0_regulatory_entries_and_skips_excluded() {
    let (_tmp, repo_dir) = init_frontier(None);
    write_regulatory_plan(&repo_dir, None, true);
    let input_dir = repo_dir.join("fixtures");
    write_regulatory_fixture(&input_dir, "reg-primary", "label version 1");
    let mut opts = regulatory_options(&input_dir);
    opts.dry_run = true;

    let report = source_adapters::run(&repo_dir, opts).await.expect("run");

    assert!(report.ok);
    assert_eq!(report.adapter, "regulatory-documents-v1");
    assert_eq!(report.selected_entries, 1);
    assert_eq!(report.skipped_excluded, 1);
    assert_eq!(report.fetched_records, 1);
    assert_eq!(report.records[0].entry_id, "reg-primary");
    assert_eq!(report.records[0].source_id, "reg-primary");
    assert_eq!(report.records[0].artifact_kind, "registry_record");
    assert_eq!(
        report.records[0].content_hash,
        sha256_for_bytes(b"label version 1")
    );
    assert!(!repo_dir.join("ingest/runs").exists());
}

#[tokio::test]
async fn regulatory_adapter_rerun_is_deterministic_and_duplicate_safe() {
    let (_tmp, repo_dir) = init_frontier(None);
    write_regulatory_plan(&repo_dir, None, true);
    let input_dir = repo_dir.join("fixtures");
    write_regulatory_fixture(&input_dir, "reg-primary", "label version 1");

    let first = source_adapters::run(&repo_dir, regulatory_options(&input_dir))
        .await
        .expect("first run");
    let second = source_adapters::run(&repo_dir, regulatory_options(&input_dir))
        .await
        .expect("second run");

    assert_eq!(first.run_id, second.run_id);
    assert_eq!(first.packet_id, second.packet_id);
    assert_eq!(
        first.idempotency.packet_hash,
        second.idempotency.packet_hash
    );
    assert!(!first.idempotency.duplicate_packet);
    assert!(second.idempotency.duplicate_packet);
    assert_eq!(
        second.idempotency.skipped_existing_proposals.len()
            + second.idempotency.skipped_existing_artifacts.len(),
        first.proposal_ids.len()
    );

    let frontier = repo::load_from_path(&repo_dir).expect("frontier");
    assert_eq!(frontier.proposals.len(), first.proposal_ids.len());
    assert!(
        frontier
            .proposals
            .iter()
            .all(|proposal| proposal.kind == "artifact.assert")
    );
}

#[tokio::test]
async fn regulatory_adapter_applies_changed_documents_as_source_artifacts_only() {
    let old_content = "label version 1";
    let new_content = "label version 2";
    let old_artifact = regulatory_artifact("reg-primary", old_content);
    let artifact_id = old_artifact.id.clone();
    let (_tmp, repo_dir) = init_frontier(Some(old_artifact));
    write_regulatory_plan(&repo_dir, Some(&artifact_id), true);
    let input_dir = repo_dir.join("fixtures");
    write_regulatory_fixture(&input_dir, "reg-primary", new_content);
    let mut opts = regulatory_options(&input_dir);
    opts.apply_artifacts = true;

    let report = source_adapters::run(&repo_dir, opts).await.expect("run");

    assert_eq!(report.changed_records, 1);
    assert_eq!(report.artifact_proposals, 2);
    assert_eq!(report.applied_event_ids.len(), 2);
    let packet: Value = serde_json::from_str(
        &fs::read_to_string(report.packet_path.as_ref().expect("packet path")).expect("packet"),
    )
    .expect("json");
    assert_eq!(packet["artifacts"][1]["kind"], "registry_record");
    assert_eq!(
        packet["artifacts"][1]["metadata"]["entry_id"],
        "reg-primary"
    );
    assert_eq!(
        packet["artifacts"][1]["metadata"]["new_content_hash"],
        sha256_for_bytes(new_content.as_bytes())
    );

    let frontier = repo::load_from_path(&repo_dir).expect("frontier");
    assert!(frontier.artifacts.iter().any(|artifact| {
        artifact.kind == "registry_record"
            && artifact.content_hash == sha256_for_bytes(new_content.as_bytes())
            && artifact.target_findings == vec!["vf_test".to_string()]
    }));
    assert_eq!(
        frontier
            .proposals
            .iter()
            .filter(|proposal| proposal.kind == "finding.add")
            .count(),
        0
    );
}

#[tokio::test]
async fn regulatory_adapter_changed_hash_creates_review_note_tasks() {
    let old_content = "label version 1";
    let new_content = "label version 2";
    let old_artifact = regulatory_artifact("reg-primary", old_content);
    let artifact_id = old_artifact.id.clone();
    let (_tmp, repo_dir) = init_frontier(Some(old_artifact));
    write_regulatory_plan(&repo_dir, Some(&artifact_id), true);
    write_previous_regulatory_record(
        &repo_dir,
        "reg-primary",
        &regulatory_record("reg-primary", old_content, "text/plain"),
    );
    let input_dir = repo_dir.join("fixtures");
    write_regulatory_fixture(&input_dir, "reg-primary", new_content);

    let report = source_adapters::run(&repo_dir, regulatory_options(&input_dir))
        .await
        .expect("run");

    assert_eq!(report.changed_records, 1);
    assert_eq!(report.review_note_proposals, 1);
    assert_eq!(report.records[0].changed_fields.len(), 1);
    assert_eq!(report.records[0].changed_fields[0].field, "content_hash");
    let frontier = repo::load_from_path(&repo_dir).expect("frontier");
    let review_proposal = frontier
        .proposals
        .iter()
        .find(|proposal| proposal.id == report.review_proposal_ids[0])
        .expect("review proposal");
    assert_eq!(review_proposal.kind, "finding.note");
    assert_eq!(review_proposal.target.id, "vf_test");
    let text = review_proposal
        .payload
        .get("text")
        .and_then(Value::as_str)
        .expect("note text");
    assert!(text.contains("reg-primary"));
    assert!(text.contains("content hash"));
    assert!(text.contains("source metadata alone does not change the claim"));
}

#[tokio::test]
async fn regulatory_adapter_does_not_flag_locator_manifests_as_source_byte_changes() {
    let source_url = "https://example.org/reg-primary";
    let (old_artifact, old_manifest_bytes) =
        regulatory_locator_manifest_artifact("reg-primary", source_url);
    let artifact_id = old_artifact.id.clone();
    let (_tmp, repo_dir) = init_frontier(Some(old_artifact.clone()));
    write_artifact_blob(&repo_dir, &old_artifact, &old_manifest_bytes);
    write_regulatory_plan(&repo_dir, Some(&artifact_id), true);
    let input_dir = repo_dir.join("fixtures");
    write_regulatory_fixture(
        &input_dir,
        "reg-primary",
        "<html><body>Current agency page bytes</body></html>",
    );

    let report = source_adapters::run(&repo_dir, regulatory_options(&input_dir))
        .await
        .expect("run");

    assert_eq!(report.selected_entries, 1);
    assert_eq!(report.fetched_records, 1);
    assert_eq!(report.changed_records, 0);
    assert_eq!(report.unchanged_records, 1);
    assert_eq!(report.review_note_proposals, 0);
    assert_eq!(report.records[0].status, "unchanged");
    assert!(report.records[0].changed_fields.is_empty());
    assert_ne!(
        report.records[0].old_content_hash.as_deref(),
        Some(report.records[0].content_hash.as_str())
    );
}

#[tokio::test]
async fn regulatory_adapter_reports_locator_drift_for_manifest_backed_sources() {
    let old_source_url = "https://example.org/old-reg-primary";
    let new_source_url = "https://example.org/reg-primary";
    let (old_artifact, old_manifest_bytes) =
        regulatory_locator_manifest_artifact("reg-primary", old_source_url);
    let artifact_id = old_artifact.id.clone();
    let (_tmp, repo_dir) = init_frontier(Some(old_artifact.clone()));
    write_artifact_blob(&repo_dir, &old_artifact, &old_manifest_bytes);
    write_regulatory_plan(&repo_dir, Some(&artifact_id), true);
    let input_dir = repo_dir.join("fixtures");
    write_regulatory_fixture(
        &input_dir,
        "reg-primary",
        "<html><body>Current agency page bytes</body></html>",
    );

    let report = source_adapters::run(&repo_dir, regulatory_options(&input_dir))
        .await
        .expect("run");

    assert_eq!(report.changed_records, 1);
    assert_eq!(report.review_note_proposals, 1);
    assert_eq!(report.records[0].changed_fields.len(), 1);
    assert_eq!(report.records[0].changed_fields[0].field, "locator");
    assert_eq!(
        report.records[0].changed_fields[0].old_value.as_deref(),
        Some(old_source_url)
    );
    assert_eq!(
        report.records[0].changed_fields[0].new_value.as_deref(),
        Some(new_source_url)
    );
}
