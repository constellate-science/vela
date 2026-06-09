//! Source adapter runs that turn live source records into artifact packets.
//!
//! The shipped adapters read the reviewed frontier-owned source ingest plan,
//! fetch selected public records, compare content hashes against the current
//! artifact projection, and route changed source records through the existing
//! artifact-to-state path.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::artifact_to_state::{
    ARTIFACT_PACKET_SCHEMA, ArtifactPacket, ImportIdempotency, PacketArtifact, PacketProducer,
};
use vela_protocol::bundle::{Artifact, valid_artifact_kind};
use vela_protocol::canonical;
use crate::decision::{SOURCE_INGEST_PLAN_SCHEMA, SourceIngestEntry, SourceIngestPlan};
use vela_protocol::events::StateTarget;
use vela_protocol::proposals;
use crate::source_inbox;
use crate::artifact_to_state;
use vela_protocol::project;
use vela_protocol::repo;
pub const CLINICALTRIALS_GOV_V2: &str = "clinicaltrials-gov-v2";
pub const REGULATORY_DOCUMENTS_V1: &str = "regulatory-documents-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdapterKind {
    ClinicalTrialsGovV2,
    RegulatoryDocumentsV1,
}

#[derive(Debug, Clone, Copy)]
struct AdapterSpec {
    id: &'static str,
    kind: AdapterKind,
    category: &'static str,
    manifest_title: &'static str,
    producer_name: &'static str,
    source_label: &'static str,
    caveat: &'static str,
}

fn adapter_spec(adapter: &str) -> Result<AdapterSpec, String> {
    match adapter {
        CLINICALTRIALS_GOV_V2 => Ok(AdapterSpec {
            id: CLINICALTRIALS_GOV_V2,
            kind: AdapterKind::ClinicalTrialsGovV2,
            category: "clinical_trial_registry",
            manifest_title: "ClinicalTrials.gov adapter run",
            producer_name: "ClinicalTrials.gov API v2 source adapter",
            source_label: "ClinicalTrials.gov record",
            caveat: "Source adapter output is registry metadata, not a clinical conclusion.",
        }),
        REGULATORY_DOCUMENTS_V1 => Ok(AdapterSpec {
            id: REGULATORY_DOCUMENTS_V1,
            kind: AdapterKind::RegulatoryDocumentsV1,
            category: "regulatory",
            manifest_title: "Regulatory document adapter run",
            producer_name: "Regulatory document source adapter",
            source_label: "regulatory source record",
            caveat: "Source adapter output is regulatory source metadata, not a clinical conclusion.",
        }),
        _ => Err(format!("unsupported source adapter '{adapter}'")),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceAdapterRunOptions {
    pub adapter: String,
    pub actor: String,
    #[serde(default)]
    pub entries: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<String>,
    #[serde(default)]
    pub include_excluded: bool,
    #[serde(default)]
    pub allow_partial: bool,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_dir: Option<PathBuf>,
    #[serde(default)]
    pub apply_artifacts: bool,
    #[serde(default)]
    pub write_inbox: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceAdapterRunReport {
    pub ok: bool,
    pub command: String,
    pub adapter: String,
    pub run_id: String,
    #[serde(default)]
    pub input_locators: Vec<String>,
    #[serde(default)]
    pub snapshot_hash: String,
    pub frontier: String,
    pub dry_run: bool,
    pub selected_entries: usize,
    pub skipped_excluded: usize,
    pub fetched_records: usize,
    pub unchanged_records: usize,
    pub changed_records: usize,
    #[serde(default)]
    pub duplicate_count: usize,
    #[serde(default)]
    pub rejected_rows: usize,
    pub artifact_proposals: usize,
    #[serde(default)]
    pub review_note_proposals: usize,
    pub proposal_ids: Vec<String>,
    #[serde(default)]
    pub review_proposal_ids: Vec<String>,
    #[serde(default)]
    pub review_tasks: Vec<String>,
    pub applied_event_ids: Vec<String>,
    #[serde(default)]
    pub source_inbox_ids: Vec<String>,
    pub idempotency: ImportIdempotency,
    pub trusted_state_effect: String,
    pub failed_records: Vec<SourceAdapterFailure>,
    pub records: Vec<ClinicalTrialsRecordReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packet_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packet_path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceAdapterFailure {
    pub entry_id: String,
    #[serde(default)]
    pub source_id: String,
    pub nct_id: String,
    pub locator: String,
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClinicalTrialsRecordReport {
    pub entry_id: String,
    #[serde(default)]
    pub source_id: String,
    pub nct_id: String,
    #[serde(default)]
    pub source_label: String,
    #[serde(default)]
    pub artifact_kind: String,
    pub status: String,
    pub source_url: String,
    pub api_url: String,
    pub content_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_artifact_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_content_hash: Option<String>,
    #[serde(default)]
    pub target_findings: Vec<String>,
    #[serde(default)]
    pub changed_fields: Vec<ClinicalTrialsFieldChange>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClinicalTrialsFieldChange {
    pub field: String,
    pub label: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_value: Option<String>,
}

#[derive(Debug, Clone)]
struct FetchedRecord {
    entry: SourceIngestEntry,
    source_id: String,
    nct_id: String,
    source_label: String,
    artifact_kind: String,
    source_url: String,
    api_url: String,
    value: Value,
    content_hash: String,
    old_content_hash: Option<String>,
    changed_fields: Vec<ClinicalTrialsFieldChange>,
    changed: bool,
}

#[derive(Debug, Clone)]
struct SourceFetch {
    value: Value,
    content_hash: String,
    source_url: String,
    api_url: String,
}

pub async fn run(
    frontier_path: &Path,
    options: SourceAdapterRunOptions,
) -> Result<SourceAdapterRunReport, String> {
    let spec = adapter_spec(&options.adapter)?;
    if options.actor.trim().is_empty() {
        return Err("actor must be non-empty".to_string());
    }
    if let Some(priority) = options.priority.as_deref()
        && !matches!(priority, "P0" | "P1" | "P2")
    {
        return Err("priority must be P0, P1, or P2".to_string());
    }

    let frontier = repo::load_from_path(frontier_path)?;
    let ingest_dir = source_ingest_dir(frontier_path)?;
    let frontier_root = frontier_root_for_ingest_dir(&ingest_dir, frontier_path);
    let plan = load_ingest_plan(&ingest_dir)?;
    let selected = selected_entries(&plan, &options, &spec);
    let skipped_excluded = plan
        .entries
        .iter()
        .filter(|entry| {
            entry.category == spec.category
                && entry.ingest_status == "excluded"
                && !options.include_excluded
        })
        .count();

    let mut fetched = Vec::new();
    let mut failures = Vec::new();
    for entry in selected.iter().cloned() {
        let source_id = match source_id_for_entry(&entry, &spec) {
            Ok(source_id) => source_id,
            Err(error) => {
                failures.push(SourceAdapterFailure {
                    entry_id: entry.id,
                    source_id: String::new(),
                    nct_id: String::new(),
                    locator: entry.locator,
                    error,
                });
                continue;
            }
        };
        match fetch_source_record(&entry, &spec, &source_id, options.input_dir.as_deref()).await {
            Ok(fetched_record) => {
                let nct_id = if spec.kind == AdapterKind::ClinicalTrialsGovV2 {
                    source_id.clone()
                } else {
                    entry.id.clone()
                };
                let artifact_kind = artifact_kind_for_entry(&entry);
                let current_artifact = entry
                    .current_frontier_artifact_id
                    .as_deref()
                    .and_then(|id| frontier.artifacts.iter().find(|artifact| artifact.id == id));
                let old_content_hash =
                    current_artifact.map(|artifact| artifact.content_hash.clone());
                let previous_record = previous_source_record(
                    &frontier,
                    &ingest_dir,
                    &entry,
                    &source_id,
                    old_content_hash.as_deref(),
                );
                let mut changed_fields = tracked_source_changes(
                    &spec,
                    previous_record.as_ref(),
                    &fetched_record.value,
                    old_content_hash.as_deref(),
                    &fetched_record.content_hash,
                );
                let changed = source_record_changed(
                    &spec,
                    current_artifact,
                    &entry,
                    &frontier_root,
                    previous_record.as_ref(),
                    old_content_hash.as_deref(),
                    &fetched_record.content_hash,
                );
                if spec.kind == AdapterKind::RegulatoryDocumentsV1
                    && previous_record.is_none()
                    && let Some(old_locator) = current_artifact.and_then(|artifact| {
                        regulatory_locator_manifest_url(&frontier_root, artifact, &entry)
                    })
                {
                    changed_fields = if old_locator == entry.locator {
                        Vec::new()
                    } else {
                        vec![ClinicalTrialsFieldChange {
                            field: "locator".to_string(),
                            label: "source locator".to_string(),
                            path: "/locator".to_string(),
                            old_value: Some(old_locator),
                            new_value: Some(entry.locator.clone()),
                        }]
                    };
                }
                if !changed {
                    changed_fields.clear();
                }
                fetched.push(FetchedRecord {
                    entry,
                    source_id: source_id.clone(),
                    source_label: spec.source_label.to_string(),
                    artifact_kind,
                    source_url: fetched_record.source_url,
                    api_url: fetched_record.api_url,
                    nct_id,
                    value: fetched_record.value,
                    content_hash: fetched_record.content_hash,
                    old_content_hash,
                    changed_fields,
                    changed,
                });
            }
            Err(error) => failures.push(SourceAdapterFailure {
                entry_id: entry.id.clone(),
                source_id: source_id.clone(),
                nct_id: if spec.kind == AdapterKind::ClinicalTrialsGovV2 {
                    source_id
                } else {
                    entry.id
                },
                locator: entry.locator,
                error,
            }),
        }
    }

    if !failures.is_empty() && !options.allow_partial {
        let failed = failures
            .iter()
            .map(|failure| format!("{} ({})", failure.nct_id, failure.error))
            .collect::<Vec<_>>()
            .join(", ");
        return Err(format!("source adapter run failed for {failed}"));
    }

    let changed_records = fetched.iter().filter(|record| record.changed).count();
    let unchanged_records = fetched.len() - changed_records;
    let run_id = run_id(&options.adapter, &fetched, &failures);
    let input_locators = selected
        .iter()
        .map(|entry| entry.locator.clone())
        .collect::<Vec<_>>();
    let rejected_rows = failures.len();
    let records = fetched
        .iter()
        .map(|record| ClinicalTrialsRecordReport {
            entry_id: record.entry.id.clone(),
            source_id: record.source_id.clone(),
            nct_id: record.nct_id.clone(),
            source_label: record.source_label.clone(),
            artifact_kind: record.artifact_kind.clone(),
            status: if record.changed {
                if record.old_content_hash.is_some() {
                    "changed".to_string()
                } else {
                    "new".to_string()
                }
            } else {
                "unchanged".to_string()
            },
            source_url: record.source_url.clone(),
            api_url: record.api_url.clone(),
            content_hash: record.content_hash.clone(),
            old_artifact_id: record.entry.current_frontier_artifact_id.clone(),
            old_content_hash: record.old_content_hash.clone(),
            target_findings: record.entry.target_findings.clone(),
            changed_fields: record.changed_fields.clone(),
        })
        .collect::<Vec<_>>();

    if options.dry_run {
        let snapshot_hash = format!("sha256:{}", hex::encode(Sha256::digest(run_id.as_bytes())));
        return Ok(SourceAdapterRunReport {
            ok: true,
            command: "source-adapter.run".to_string(),
            adapter: options.adapter,
            run_id: run_id.clone(),
            input_locators,
            snapshot_hash: snapshot_hash.clone(),
            frontier: frontier.project.name,
            dry_run: true,
            selected_entries: selected.len(),
            skipped_excluded,
            fetched_records: fetched.len(),
            unchanged_records,
            changed_records,
            duplicate_count: 0,
            rejected_rows,
            artifact_proposals: 0,
            review_note_proposals: 0,
            proposal_ids: Vec::new(),
            review_proposal_ids: Vec::new(),
            review_tasks: Vec::new(),
            applied_event_ids: Vec::new(),
            source_inbox_ids: Vec::new(),
            idempotency: ImportIdempotency {
                packet_hash: format!("sha256:{}", hex::encode(Sha256::digest(run_id.as_bytes()))),
                duplicate_packet: false,
                skipped_existing_proposals: Vec::new(),
                skipped_existing_artifacts: Vec::new(),
            },
            trusted_state_effect: "none".to_string(),
            failed_records: failures,
            records,
            packet_id: None,
            packet_path: None,
            run_path: None,
        });
    }

    let run_dir = ingest_dir.join("runs").join(&run_id);
    fs::create_dir_all(run_dir.join("records"))
        .map_err(|e| format!("create source adapter run dir '{}': {e}", run_dir.display()))?;
    for record in &fetched {
        fs::write(
            run_dir
                .join("records")
                .join(format!("{}.json", record.source_id)),
            serde_json::to_vec_pretty(&record.value)
                .map_err(|e| format!("serialize record: {e}"))?,
        )
        .map_err(|e| format!("write fetched record {}: {e}", record.source_id))?;
    }

    let manifest = run_manifest(
        &options,
        &run_id,
        selected.len(),
        skipped_excluded,
        &records,
        &failures,
    );
    let manifest_bytes = canonical::to_canonical_bytes(&manifest)?;
    let manifest_hash = sha256_for_bytes(&manifest_bytes);
    let packet_id = packet_id(&options.adapter, &run_id, &manifest_hash);
    let packet = artifact_packet(
        &options,
        &packet_id,
        &run_id,
        &manifest_hash,
        &records,
        &fetched,
        &spec,
    )?;
    let packet_path = run_dir.join("artifact-packet.json");
    fs::write(
        &packet_path,
        serde_json::to_vec_pretty(&packet).map_err(|e| format!("serialize packet: {e}"))?,
    )
    .map_err(|e| format!("write artifact packet '{}': {e}", packet_path.display()))?;

    let import_report = artifact_to_state::import_packet_at_path(
        frontier_path,
        &packet_path,
        &options.actor,
        options.apply_artifacts,
    )?;
    let review_proposal_ids = create_review_note_proposals(
        frontier_path,
        &options,
        &spec,
        &run_id,
        &packet_id,
        &fetched,
    )?;
    let mut proposal_ids = import_report.proposal_ids;
    proposal_ids.extend(review_proposal_ids.clone());
    let source_inbox_ids = if options.write_inbox {
        write_source_inbox_records(frontier_path, &options.adapter, &run_id, &records)?
    } else {
        Vec::new()
    };
    if options.apply_artifacts {
        update_ingest_plan_after_apply(frontier_path, &ingest_dir, &fetched)?;
    }
    let duplicate_count = import_report.idempotency.skipped_existing_proposals.len()
        + import_report.idempotency.skipped_existing_artifacts.len();
    let created_records =
        proposal_ids.len() + source_inbox_ids.len() + import_report.applied_event_ids.len();
    let feed_run = json!({
        "schema": "vela.source-feed-run.v0.1",
        "adapter": options.adapter,
        "input_locators": input_locators.clone(),
        "snapshot_hash": manifest_hash.clone(),
        "run_timestamp": packet.created_at,
        "created_records": created_records,
        "duplicate_count": duplicate_count,
        "rejected_rows": rejected_rows,
        "review_tasks": proposal_ids.clone(),
        "source_inbox_ids": source_inbox_ids.clone(),
        "trusted_state_effect": import_report.trusted_state_effect,
    });

    let final_run = json!({
        "schema": "vela.source-adapter-run.v1",
        "run_id": run_id,
        "adapter": options.adapter,
        "input_locators": input_locators,
        "snapshot_hash": manifest_hash,
        "frontier": frontier.project.name,
        "started_at": packet.created_at,
        "selected_entries": selected.len(),
        "skipped_excluded": skipped_excluded,
        "fetched_records": fetched.len(),
        "unchanged_records": unchanged_records,
        "changed_records": changed_records,
        "duplicate_count": duplicate_count,
        "rejected_rows": rejected_rows,
        "failed_records": failures,
        "records": records,
        "packet_id": packet_id,
        "packet_path": "artifact-packet.json",
        "proposal_ids": proposal_ids.clone(),
        "review_proposal_ids": review_proposal_ids,
        "review_tasks": proposal_ids.clone(),
        "source_inbox_ids": source_inbox_ids,
        "applied_event_ids": import_report.applied_event_ids,
        "idempotency": import_report.idempotency,
        "trusted_state_effect": import_report.trusted_state_effect,
        "feed_run": feed_run,
    });
    fs::write(
        run_dir.join("run.json"),
        serde_json::to_vec_pretty(&final_run).map_err(|e| format!("serialize run: {e}"))?,
    )
    .map_err(|e| format!("write run manifest '{}': {e}", run_dir.display()))?;

    Ok(SourceAdapterRunReport {
        ok: true,
        command: "source-adapter.run".to_string(),
        adapter: options.adapter,
        run_id,
        input_locators: final_run["input_locators"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|value| value.as_str().map(str::to_string))
            .collect(),
        snapshot_hash: final_run["snapshot_hash"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        frontier: frontier.project.name,
        dry_run: false,
        selected_entries: selected.len(),
        skipped_excluded,
        fetched_records: fetched.len(),
        unchanged_records,
        changed_records,
        duplicate_count,
        rejected_rows,
        artifact_proposals: import_report.artifact_proposals,
        review_note_proposals: review_proposal_ids.len(),
        proposal_ids,
        review_proposal_ids,
        review_tasks: final_run["review_tasks"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|value| value.as_str().map(str::to_string))
            .collect(),
        applied_event_ids: import_report.applied_event_ids,
        source_inbox_ids,
        idempotency: import_report.idempotency,
        trusted_state_effect: import_report.trusted_state_effect,
        failed_records: failures,
        records,
        packet_id: Some(packet_id),
        packet_path: Some(packet_path),
        run_path: Some(run_dir),
    })
}

fn source_ingest_dir(frontier_path: &Path) -> Result<PathBuf, String> {
    match repo::detect(frontier_path)? {
        repo::VelaSource::VelaRepo(root) => Ok(root.join("ingest")),
        repo::VelaSource::ProjectFile(path) => path
            .parent()
            .map(|parent| parent.join("ingest"))
            .ok_or_else(|| format!("frontier file '{}' has no parent", path.display())),
        repo::VelaSource::PacketDir(dir) => Ok(dir.join("ingest")),
    }
}

fn write_source_inbox_records(
    frontier_path: &Path,
    adapter: &str,
    run_id: &str,
    records: &[ClinicalTrialsRecordReport],
) -> Result<Vec<String>, String> {
    let mut ids = Vec::new();
    for record in records {
        let source_type = if record.artifact_kind.trim().is_empty() {
            "source_material"
        } else {
            record.artifact_kind.as_str()
        };
        let title = if record.source_label.trim().is_empty() {
            record.nct_id.clone()
        } else {
            format!("{} {}", record.source_label, record.nct_id)
        };
        let inbox = source_inbox::upsert_adapter_record(
            frontier_path,
            adapter,
            run_id,
            &record.entry_id,
            &record.source_id,
            &title,
            &record.source_url,
            source_type,
            &record.content_hash,
            &record.status,
        )?;
        ids.push(inbox.id);
    }
    ids.sort();
    ids.dedup();
    Ok(ids)
}

fn frontier_root_for_ingest_dir(ingest_dir: &Path, frontier_path: &Path) -> PathBuf {
    ingest_dir
        .parent()
        .map(Path::to_path_buf)
        .or_else(|| {
            if frontier_path.is_dir() {
                Some(frontier_path.to_path_buf())
            } else {
                frontier_path.parent().map(Path::to_path_buf)
            }
        })
        .unwrap_or_else(|| PathBuf::from("."))
}

fn load_ingest_plan(ingest_dir: &Path) -> Result<SourceIngestPlan, String> {
    let path = ingest_dir.join("source-ingest-plan.v1.json");
    let data = fs::read_to_string(&path)
        .map_err(|e| format!("read source ingest plan '{}': {e}", path.display()))?;
    let plan: SourceIngestPlan =
        serde_json::from_str(&data).map_err(|e| format!("parse source ingest plan: {e}"))?;
    if plan.schema != SOURCE_INGEST_PLAN_SCHEMA {
        return Err(format!(
            "source ingest plan schema must be {SOURCE_INGEST_PLAN_SCHEMA}"
        ));
    }
    Ok(plan)
}

fn source_record_changed(
    spec: &AdapterSpec,
    current_artifact: Option<&Artifact>,
    entry: &SourceIngestEntry,
    frontier_root: &Path,
    previous_record: Option<&Value>,
    old_content_hash: Option<&str>,
    new_content_hash: &str,
) -> bool {
    let Some(old_content_hash) = old_content_hash else {
        return true;
    };
    match spec.kind {
        AdapterKind::ClinicalTrialsGovV2 => old_content_hash != new_content_hash,
        AdapterKind::RegulatoryDocumentsV1 => {
            if previous_record.is_some() {
                return old_content_hash != new_content_hash;
            }
            if let Some(old_locator) = current_artifact.and_then(|artifact| {
                regulatory_locator_manifest_url(frontier_root, artifact, entry)
            }) {
                return old_locator != entry.locator;
            }
            old_content_hash != new_content_hash
        }
    }
}

fn regulatory_locator_manifest_url(
    frontier_root: &Path,
    artifact: &Artifact,
    entry: &SourceIngestEntry,
) -> Option<String> {
    if entry.source_type == "frontier_projection" {
        return Some(entry.locator.clone());
    }
    if artifact.metadata.contains_key("source_adapter")
        || artifact.metadata.contains_key("source_adapter_run_id")
        || artifact.metadata.contains_key("run_id")
    {
        return None;
    }
    if artifact.storage_mode != "local_blob" {
        return None;
    }
    let is_json = artifact
        .media_type
        .as_deref()
        .is_some_and(|media_type| media_type.contains("json"));
    if !is_json {
        return None;
    }
    let locator = artifact.locator.as_deref()?;
    let path = resolve_artifact_locator(frontier_root, locator);
    let Ok(bytes) = fs::read(path) else {
        return None;
    };
    let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
        return None;
    };
    let manifest_url = value
        .get("url")
        .or_else(|| value.get("source_url"))
        .and_then(Value::as_str)
        .map(str::to_string)?;
    let manifest_only = value
        .get("access_terms")
        .and_then(Value::as_str)
        .is_some_and(|terms| terms.contains("stored as a Vela manifest"));
    if manifest_only || value.get("content_hash").is_none() {
        Some(manifest_url)
    } else {
        None
    }
}

fn resolve_artifact_locator(frontier_root: &Path, locator: &str) -> PathBuf {
    let path = Path::new(locator);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        frontier_root.join(path)
    }
}

fn update_ingest_plan_after_apply(
    frontier_path: &Path,
    ingest_dir: &Path,
    fetched: &[FetchedRecord],
) -> Result<(), String> {
    let path = ingest_dir.join("source-ingest-plan.v1.json");
    let mut plan = load_ingest_plan(ingest_dir)?;
    let frontier = repo::load_from_path(frontier_path)?;
    let mut changed = false;
    for record in fetched.iter().filter(|record| record.changed) {
        let Some(artifact_id) = frontier
            .artifacts
            .iter()
            .find(|artifact| {
                artifact.kind == record.artifact_kind
                    && artifact.content_hash == record.content_hash
                    && artifact
                        .metadata
                        .get("source_id")
                        .or_else(|| artifact.metadata.get("entry_id"))
                        .or_else(|| artifact.metadata.get("nct_id"))
                        .and_then(Value::as_str)
                        .is_some_and(|source| source == record.source_id)
            })
            .map(|artifact| artifact.id.clone())
        else {
            continue;
        };
        if let Some(entry) = plan
            .entries
            .iter_mut()
            .find(|entry| entry.id == record.entry.id)
            && entry.current_frontier_artifact_id.as_deref() != Some(artifact_id.as_str())
        {
            entry.current_frontier_artifact_id = Some(artifact_id);
            entry.ingest_status = "ingested".to_string();
            changed = true;
        }
    }
    if changed {
        fs::write(
            &path,
            serde_json::to_vec_pretty(&plan)
                .map_err(|e| format!("serialize source ingest plan: {e}"))?,
        )
        .map_err(|e| format!("write source ingest plan '{}': {e}", path.display()))?;
    }
    Ok(())
}

fn selected_entries(
    plan: &SourceIngestPlan,
    options: &SourceAdapterRunOptions,
    spec: &AdapterSpec,
) -> Vec<SourceIngestEntry> {
    plan.entries
        .iter()
        .filter(|entry| entry.category == spec.category)
        .filter(|entry| options.include_excluded || entry.ingest_status != "excluded")
        .filter(|entry| {
            options.entries.is_empty() || options.entries.iter().any(|wanted| wanted == &entry.id)
        })
        .filter(|entry| {
            options
                .priority
                .as_deref()
                .is_none_or(|priority| entry.priority == priority)
        })
        .cloned()
        .collect()
}

fn previous_source_record(
    frontier: &project::Project,
    ingest_dir: &Path,
    source_entry: &SourceIngestEntry,
    source_id: &str,
    expected_hash: Option<&str>,
) -> Option<Value> {
    let artifact = source_entry
        .current_frontier_artifact_id
        .as_deref()
        .and_then(|id| frontier.artifacts.iter().find(|artifact| artifact.id == id))?;
    let expected_hash = expected_hash.unwrap_or(&artifact.content_hash);

    if let Some(run_id) = artifact
        .metadata
        .get("run_id")
        .or_else(|| artifact.metadata.get("source_adapter_run_id"))
        .and_then(Value::as_str)
    {
        let path = ingest_dir
            .join("runs")
            .join(run_id)
            .join("records")
            .join(format!("{source_id}.json"));
        if let Some(value) = read_record_if_hash_matches(&path, expected_hash) {
            return Some(value);
        }
    }

    let runs_dir = ingest_dir.join("runs");
    let entries = fs::read_dir(runs_dir).ok()?;
    for entry in entries.flatten() {
        let path = entry
            .path()
            .join("records")
            .join(format!("{source_id}.json"));
        if let Some(value) = read_record_if_hash_matches(&path, expected_hash) {
            return Some(value);
        }
    }
    None
}

fn read_record_if_hash_matches(path: &Path, expected_hash: &str) -> Option<Value> {
    let text = fs::read_to_string(path).ok()?;
    let value: Value = serde_json::from_str(&text).ok()?;
    if value
        .get("content_hash")
        .and_then(Value::as_str)
        .is_some_and(|hash| hash == expected_hash)
    {
        return Some(value);
    }
    let bytes = canonical::to_canonical_bytes(&value).ok()?;
    if sha256_for_bytes(&bytes) == expected_hash {
        Some(value)
    } else {
        None
    }
}

fn tracked_source_changes(
    spec: &AdapterSpec,
    previous_record: Option<&Value>,
    new_record: &Value,
    old_content_hash: Option<&str>,
    new_content_hash: &str,
) -> Vec<ClinicalTrialsFieldChange> {
    match spec.kind {
        AdapterKind::ClinicalTrialsGovV2 => previous_record
            .map(|previous| tracked_clinicaltrials_changes(previous, new_record))
            .unwrap_or_default(),
        AdapterKind::RegulatoryDocumentsV1 => {
            if let Some(previous) = previous_record {
                tracked_regulatory_changes(previous, new_record)
            } else if old_content_hash.is_some_and(|old| old != new_content_hash) {
                vec![ClinicalTrialsFieldChange {
                    field: "content_hash".to_string(),
                    label: "content hash".to_string(),
                    path: "/content_hash".to_string(),
                    old_value: old_content_hash.map(str::to_string),
                    new_value: Some(new_content_hash.to_string()),
                }]
            } else {
                Vec::new()
            }
        }
    }
}

fn tracked_regulatory_changes(
    old_record: &Value,
    new_record: &Value,
) -> Vec<ClinicalTrialsFieldChange> {
    const FIELDS: &[(&str, &str, &str)] = &[
        ("content_hash", "content hash", "/content_hash"),
        ("content_length", "content length", "/content_length"),
        ("content_type", "content type", "/content_type"),
        ("locator", "source locator", "/locator"),
    ];

    FIELDS
        .iter()
        .filter_map(|(field, label, path)| {
            let old_value = old_record.pointer(path);
            let new_value = new_record.pointer(path);
            if old_value == new_value {
                return None;
            }
            Some(ClinicalTrialsFieldChange {
                field: (*field).to_string(),
                label: (*label).to_string(),
                path: (*path).to_string(),
                old_value: field_value_summary(old_value),
                new_value: field_value_summary(new_value),
            })
        })
        .collect()
}

fn tracked_clinicaltrials_changes(
    old_record: &Value,
    new_record: &Value,
) -> Vec<ClinicalTrialsFieldChange> {
    const FIELDS: &[(&str, &str, &str)] = &[
        (
            "overall_status",
            "overall status",
            "/protocolSection/statusModule/overallStatus",
        ),
        (
            "start_date",
            "start date",
            "/protocolSection/statusModule/startDateStruct/date",
        ),
        (
            "primary_completion_date",
            "primary completion date",
            "/protocolSection/statusModule/primaryCompletionDateStruct/date",
        ),
        (
            "completion_date",
            "completion date",
            "/protocolSection/statusModule/completionDateStruct/date",
        ),
        (
            "phases",
            "trial phase",
            "/protocolSection/designModule/phases",
        ),
        (
            "enrollment_count",
            "enrollment count",
            "/protocolSection/designModule/enrollmentInfo/count",
        ),
        (
            "enrollment_type",
            "enrollment type",
            "/protocolSection/designModule/enrollmentInfo/type",
        ),
        (
            "primary_outcomes",
            "primary outcomes",
            "/protocolSection/outcomesModule/primaryOutcomes",
        ),
        ("has_results", "posted results section", "/resultsSection"),
    ];

    FIELDS
        .iter()
        .filter_map(|(field, label, path)| {
            let old_value = old_record.pointer(path);
            let new_value = new_record.pointer(path);
            if old_value == new_value {
                return None;
            }
            Some(ClinicalTrialsFieldChange {
                field: (*field).to_string(),
                label: (*label).to_string(),
                path: (*path).to_string(),
                old_value: field_value_summary(old_value),
                new_value: field_value_summary(new_value),
            })
        })
        .collect()
}

fn field_value_summary(value: Option<&Value>) -> Option<String> {
    let value = value?;
    match value {
        Value::Null => None,
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Array(_) | Value::Object(_) => serde_json::to_string(value).ok(),
    }
}

fn create_review_note_proposals(
    frontier_path: &Path,
    options: &SourceAdapterRunOptions,
    spec: &AdapterSpec,
    run_id: &str,
    packet_id: &str,
    fetched: &[FetchedRecord],
) -> Result<Vec<String>, String> {
    let mut ids = Vec::new();
    for record in fetched
        .iter()
        .filter(|record| !record.changed_fields.is_empty())
    {
        let targets = record
            .entry
            .target_findings
            .iter()
            .filter(|id| id.starts_with("vf_"))
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        if targets.is_empty() {
            continue;
        }
        let note_text = review_note_text(record);
        for finding_id in targets {
            let proposal = proposals::new_proposal(
                "finding.note",
                StateTarget {
                    r#type: "finding".to_string(),
                    id: finding_id,
                },
                options.actor.clone(),
                if options.actor.starts_with("agent:") {
                    "agent"
                } else {
                    "human"
                },
                format!(
                    "Review {} delta for {} from run {}",
                    spec.source_label, record.source_id, run_id
                ),
                json!({
                    "text": note_text,
                    "source_adapter": options.adapter,
                    "source_adapter_run_id": run_id,
                    "artifact_packet_id": packet_id,
                    "entry_id": record.entry.id,
                    "source_id": record.source_id,
                    "source_label": record.source_label,
                    "nct_id": record.nct_id,
                    "api_url": record.api_url,
                    "source_url": record.source_url,
                    "old_content_hash": record.old_content_hash,
                    "new_content_hash": record.content_hash,
                    "changed_fields": record.changed_fields,
                }),
                vec![
                    record.api_url.clone(),
                    record.source_url.clone(),
                    format!("source_adapter_run:{run_id}"),
                    format!("artifact_packet:{packet_id}"),
                ],
                review_note_caveats(spec),
            );
            let result = proposals::create_or_apply(frontier_path, proposal, false)?;
            ids.push(result.proposal_id);
        }
    }
    Ok(ids)
}

fn review_note_text(record: &FetchedRecord) -> String {
    let fields = record
        .changed_fields
        .iter()
        .map(|change| {
            format!(
                "{} changed from {} to {}",
                change.label,
                change.old_value.as_deref().unwrap_or("missing"),
                change.new_value.as_deref().unwrap_or("missing")
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    if record.source_label == "ClinicalTrials.gov record" {
        format!(
            "ClinicalTrials.gov record {} changed tracked registry fields: {}. Review whether this affects the linked finding scope, trial table, or decision brief. Registry metadata alone does not change the claim.",
            record.source_id, fields
        )
    } else {
        format!(
            "Regulatory source {} changed tracked source fields: {}. Review whether this affects the linked finding scope, trial table, or decision brief; source metadata alone does not change the claim.",
            record.source_id, fields
        )
    }
}

fn review_note_caveats(spec: &AdapterSpec) -> Vec<String> {
    match spec.kind {
        AdapterKind::ClinicalTrialsGovV2 => vec![
            "ClinicalTrials.gov metadata changed; this is a review task, not a claim update."
                .to_string(),
            "Accepting this note records reviewer awareness only.".to_string(),
        ],
        AdapterKind::RegulatoryDocumentsV1 => vec![
            "Regulatory source metadata changed; this is a review task, not a claim update."
                .to_string(),
            "Accepting this note records reviewer awareness only.".to_string(),
        ],
    }
}

async fn fetch_source_record(
    entry: &SourceIngestEntry,
    spec: &AdapterSpec,
    source_id: &str,
    input_dir: Option<&Path>,
) -> Result<SourceFetch, String> {
    match spec.kind {
        AdapterKind::ClinicalTrialsGovV2 => fetch_clinicaltrials_record(source_id, input_dir).await,
        AdapterKind::RegulatoryDocumentsV1 => {
            fetch_regulatory_record(entry, source_id, input_dir).await
        }
    }
}

async fn fetch_clinicaltrials_record(
    nct_id: &str,
    input_dir: Option<&Path>,
) -> Result<SourceFetch, String> {
    let raw = if let Some(dir) = input_dir {
        let path = dir.join(format!("{nct_id}.json"));
        fs::read_to_string(&path)
            .map_err(|e| format!("read ClinicalTrials.gov fixture '{}': {e}", path.display()))?
    } else {
        let url = format!("https://clinicaltrials.gov/api/v2/studies/{nct_id}");
        let response = reqwest::get(&url)
            .await
            .map_err(|e| format!("fetch {url}: {e}"))?;
        let response = response
            .error_for_status()
            .map_err(|e| format!("fetch {url}: {e}"))?;
        response
            .text()
            .await
            .map_err(|e| format!("read {url}: {e}"))?
    };
    let value: Value =
        serde_json::from_str(&raw).map_err(|e| format!("parse ClinicalTrials.gov record: {e}"))?;
    let canonical_bytes = canonical::to_canonical_bytes(&value)?;
    Ok(SourceFetch {
        value,
        content_hash: sha256_for_bytes(&canonical_bytes),
        source_url: format!("https://clinicaltrials.gov/study/{nct_id}"),
        api_url: format!("https://clinicaltrials.gov/api/v2/studies/{nct_id}"),
    })
}

async fn fetch_regulatory_record(
    entry: &SourceIngestEntry,
    source_id: &str,
    input_dir: Option<&Path>,
) -> Result<SourceFetch, String> {
    let (bytes, content_type) = if let Some(dir) = input_dir {
        let path = fixture_path_for_source(dir, source_id)
            .ok_or_else(|| format!("read regulatory fixture for {source_id}: file not found"))?;
        let bytes = fs::read(&path)
            .map_err(|e| format!("read regulatory fixture '{}': {e}", path.display()))?;
        (bytes, content_type_for_path(&path))
    } else {
        let client = reqwest::Client::builder()
            .user_agent("vela-source-adapter/0.55 (+https://vela.science)")
            .build()
            .map_err(|e| format!("create http client: {e}"))?;
        let response = client
            .get(&entry.locator)
            .send()
            .await
            .map_err(|e| format!("fetch {}: {e}", entry.locator))?;
        let response = response
            .error_for_status()
            .map_err(|e| format!("fetch {}: {e}", entry.locator))?;
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("application/octet-stream")
            .to_string();
        let bytes = response
            .bytes()
            .await
            .map_err(|e| format!("read {}: {e}", entry.locator))?
            .to_vec();
        (bytes, content_type)
    };
    let content_hash = sha256_for_bytes(&bytes);
    let value = json!({
        "schema": "vela.regulatory-source-record.v1",
        "entry_id": entry.id,
        "source_id": source_id,
        "name": entry.name,
        "source_type": entry.source_type,
        "representation": entry.representation,
        "locator": entry.locator,
        "content_type": content_type,
        "content_length": bytes.len(),
        "content_hash": content_hash,
    });
    Ok(SourceFetch {
        value,
        content_hash,
        source_url: entry.locator.clone(),
        api_url: entry.locator.clone(),
    })
}

fn fixture_path_for_source(dir: &Path, source_id: &str) -> Option<PathBuf> {
    ["json", "txt", "html", "pdf"]
        .iter()
        .map(|extension| dir.join(format!("{source_id}.{extension}")))
        .find(|path| path.exists())
}

fn content_type_for_path(path: &Path) -> String {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("json") => "application/json".to_string(),
        Some("html") => "text/html".to_string(),
        Some("pdf") => "application/pdf".to_string(),
        Some("txt") => "text/plain".to_string(),
        _ => "application/octet-stream".to_string(),
    }
}

fn nct_id_from_locator(locator: &str) -> Result<String, String> {
    locator
        .split('/')
        .next_back()
        .filter(|value| value.starts_with("NCT"))
        .map(str::to_string)
        .ok_or_else(|| format!("ClinicalTrials.gov locator does not end in an NCT id: {locator}"))
}

fn source_id_for_entry(entry: &SourceIngestEntry, spec: &AdapterSpec) -> Result<String, String> {
    match spec.kind {
        AdapterKind::ClinicalTrialsGovV2 => nct_id_from_locator(&entry.locator),
        AdapterKind::RegulatoryDocumentsV1 => Ok(entry.id.clone()),
    }
}

fn artifact_kind_for_entry(entry: &SourceIngestEntry) -> String {
    if valid_artifact_kind(&entry.representation) {
        entry.representation.clone()
    } else if valid_artifact_kind(&entry.source_type) {
        entry.source_type.clone()
    } else {
        "registry_record".to_string()
    }
}

fn run_manifest(
    options: &SourceAdapterRunOptions,
    run_id: &str,
    selected_entries: usize,
    skipped_excluded: usize,
    records: &[ClinicalTrialsRecordReport],
    failures: &[SourceAdapterFailure],
) -> Value {
    json!({
        "schema": "vela.source-adapter-run.v1",
        "run_id": run_id,
        "adapter": options.adapter,
        "actor": options.actor,
        "created_at": source_run_created_at(run_id),
        "selected_entries": selected_entries,
        "skipped_excluded": skipped_excluded,
        "records": records,
        "failed_records": failures,
        "policy": {
            "apply_artifacts": options.apply_artifacts,
            "allow_partial": options.allow_partial,
            "include_excluded": options.include_excluded,
            "priority": options.priority,
            "entries": options.entries,
        }
    })
}

fn artifact_packet(
    options: &SourceAdapterRunOptions,
    packet_id: &str,
    run_id: &str,
    manifest_hash: &str,
    records: &[ClinicalTrialsRecordReport],
    fetched: &[FetchedRecord],
    spec: &AdapterSpec,
) -> Result<ArtifactPacket, String> {
    let created_at = source_run_created_at(run_id);
    let target_findings = records
        .iter()
        .flat_map(|record| record.target_findings.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let mut artifacts = vec![PacketArtifact {
        id: format!("{run_id}_manifest"),
        kind: "source_file".to_string(),
        title: format!("{} {run_id}", spec.manifest_title),
        locator: format!(
            "https://github.com/vela-science/vela/tree/main/projects/anti-amyloid-translation/ingest/runs/{run_id}/run.json"
        ),
        content_hash: manifest_hash.to_string(),
        parents: Vec::new(),
        metadata: BTreeMap::from([
            ("adapter".to_string(), json!(options.adapter)),
            ("run_id".to_string(), json!(run_id)),
            ("records".to_string(), json!(records)),
            ("target_findings".to_string(), json!(target_findings)),
        ]),
    }];

    for record in fetched.iter().filter(|record| record.changed) {
        artifacts.push(PacketArtifact {
            id: format!(
                "{}_{}",
                safe_id_fragment(spec.id),
                safe_id_fragment(&record.source_id)
            ),
            kind: record.artifact_kind.clone(),
            title: source_record_title(spec, record),
            locator: record.source_url.clone(),
            content_hash: record.content_hash.clone(),
            parents: vec![format!("{run_id}_manifest")],
            metadata: BTreeMap::from([
                ("adapter".to_string(), json!(options.adapter)),
                ("run_id".to_string(), json!(run_id)),
                ("entry_id".to_string(), json!(record.entry.id)),
                ("source_id".to_string(), json!(record.source_id)),
                ("source_label".to_string(), json!(record.source_label)),
                ("artifact_kind".to_string(), json!(record.artifact_kind)),
                ("nct_id".to_string(), json!(record.nct_id)),
                ("api_url".to_string(), json!(record.api_url)),
                ("source_url".to_string(), json!(record.source_url)),
                (
                    "old_artifact_id".to_string(),
                    json!(record.entry.current_frontier_artifact_id),
                ),
                (
                    "old_content_hash".to_string(),
                    json!(record.old_content_hash),
                ),
                ("new_content_hash".to_string(), json!(record.content_hash)),
                (
                    "target_findings".to_string(),
                    json!(record.entry.target_findings),
                ),
                ("retrieved_at".to_string(), json!(created_at)),
            ]),
        });
    }

    Ok(ArtifactPacket {
        schema: ARTIFACT_PACKET_SCHEMA.to_string(),
        packet_id: packet_id.to_string(),
        producer: PacketProducer {
            kind: "source_adapter".to_string(),
            id: format!("adapter:{}", options.adapter),
            name: spec.producer_name.to_string(),
        },
        topic: "Anti-amyloid translation in Alzheimer's disease".to_string(),
        created_at,
        artifacts,
        candidate_claims: Vec::new(),
        open_needs: Vec::new(),
        caveats: vec![
            spec.caveat.to_string(),
            "Truth-changing frontier updates require reviewer acceptance.".to_string(),
        ],
    })
}

fn source_record_title(spec: &AdapterSpec, record: &FetchedRecord) -> String {
    match spec.kind {
        AdapterKind::ClinicalTrialsGovV2 => record
            .value
            .pointer("/protocolSection/identificationModule/briefTitle")
            .and_then(Value::as_str)
            .or_else(|| {
                record
                    .value
                    .pointer("/protocolSection/identificationModule/officialTitle")
                    .and_then(Value::as_str)
            })
            .map_or_else(
                || format!("ClinicalTrials.gov {}", record.source_id),
                |title| format!("ClinicalTrials.gov {} · {title}", record.source_id),
            ),
        AdapterKind::RegulatoryDocumentsV1 => {
            format!("{} · {}", record.entry.name, record.source_id)
        }
    }
}

fn safe_id_fragment(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn sha256_for_bytes(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn run_id(adapter: &str, fetched: &[FetchedRecord], failures: &[SourceAdapterFailure]) -> String {
    let preimage = json!({
        "adapter": adapter,
        "records": fetched.iter().map(|record| json!({
            "entry_id": record.entry.id,
            "source_id": record.source_id,
            "nct_id": record.nct_id,
            "content_hash": record.content_hash,
            "old_content_hash": record.old_content_hash,
            "changed": record.changed,
        })).collect::<Vec<_>>(),
        "failures": failures,
    });
    let bytes = canonical::to_canonical_bytes(&preimage).unwrap_or_else(|_| Vec::new());
    format!("sir_{}", &hex::encode(Sha256::digest(&bytes))[..16])
}

// Source adapter packets are replay artifacts. Identical fetched records must
// produce identical packet hashes so reruns do not create duplicate review debt.
fn source_run_created_at(_run_id: &str) -> String {
    "2026-05-06T00:00:00Z".to_string()
}

fn packet_id(adapter: &str, run_id: &str, manifest_hash: &str) -> String {
    let preimage = format!("{adapter}|{run_id}|{manifest_hash}");
    format!(
        "cap_{}",
        &hex::encode(Sha256::digest(preimage.as_bytes()))[..16]
    )
}
