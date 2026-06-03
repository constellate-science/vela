//! Read-only share package for external review.

use crate::{
    adoption_log, adoption_transcript, evidence_ci, frontier_health, frontier_task, repo,
    review_session, source_inbox,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub const SHARE_MANIFEST_SCHEMA: &str = "vela.share_manifest.v0.1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShareBuildReport {
    pub ok: bool,
    pub out: String,
    pub frontier_id: String,
    pub files: usize,
    pub manifest_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShareInspectReport {
    pub ok: bool,
    pub path: String,
    pub files: usize,
    pub proof_packet_present: bool,
    pub stale_proof: bool,
    #[serde(default)]
    pub mismatches: Vec<String>,
    #[serde(default)]
    pub missing_required: Vec<String>,
    #[serde(default)]
    pub write_surface_findings: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShareBuildOptions {
    pub include_friction_log: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ManifestFile {
    path: String,
    sha256: String,
    bytes: u64,
}

pub fn build(frontier_path: &Path, out: &Path) -> Result<ShareBuildReport, String> {
    build_with_options(frontier_path, out, ShareBuildOptions::default())
}

pub fn build_with_options(
    frontier_path: &Path,
    out: &Path,
    options: ShareBuildOptions,
) -> Result<ShareBuildReport, String> {
    let project = repo::load_from_path(frontier_path)?;
    if out.exists() {
        fs::remove_dir_all(out).map_err(|e| format!("remove existing share package: {e}"))?;
    }
    fs::create_dir_all(out).map_err(|e| format!("create share package {}: {e}", out.display()))?;

    write_json(out.join("frontier.json"), &project)?;
    let health = frontier_health::analyze(frontier_path)?;
    let source_inbox_list = source_inbox::list_records(frontier_path)?;
    write_json(out.join("frontier-health.json"), &health)?;
    write_json(
        out.join("evidence-ci.json"),
        &evidence_ci::run_frontier(frontier_path)?,
    )?;
    write_json(out.join("source-inbox.json"), &source_inbox_list)?;
    write_json(
        out.join("tasks.json"),
        &frontier_task::list_tasks(frontier_path)?,
    )?;
    write_json(
        out.join("review-sessions.json"),
        &review_session::list(frontier_path)?,
    )?;
    write_json(
        out.join("proof-state.json"),
        &json!({
            "schema": "vela.share_proof_state.v0.2",
            "status": health.metrics.proof_status,
            "package_status": "packet_exported",
            "stale": health.metrics.stale_proof,
            "review_debt": {
                "awaiting_review_tasks": health.metrics.awaiting_review_tasks,
                "pending_diff_packs": health.metrics.pending_diff_packs,
                "missing_attestations": health.metrics.missing_attestations,
                "source_inbox_issues": health.metrics.source_inbox_issues,
                "evidence_ci_warnings": health.metrics.evidence_ci_warnings,
                "evidence_ci_failures": health.metrics.evidence_ci_failures
            },
            "proof_packet_present": true,
            "caveat": "This package proof state is derived from the exported proof packet. Validate proof-packet before relying on it.",
        }),
    )?;
    write_source_snapshots(frontier_path, out, &project, &source_inbox_list)?;
    write_source_locator_audit(out, &project, &source_inbox_list)?;
    write_canonical_verdict_events(out, &project)?;
    copy_optional_dir(
        &frontier_path.join(".vela").join("diff_packs"),
        &out.join("diff-packs"),
    )?;
    copy_optional_dir(
        &frontier_path.join(".vela").join("review_packets"),
        &out.join("review-packets"),
    )?;
    copy_optional_dir(&frontier_path.join("review"), &out.join("review-packets"))?;
    copy_optional_dir(
        &frontier_path.join(".vela").join("review_sessions"),
        &out.join("review-sessions"),
    )?;
    copy_optional_dir(
        &frontier_path.join(".vela").join("attestations"),
        &out.join("attestations"),
    )?;
    adoption_transcript::write_markdown(frontier_path, &out.join("adoption-transcript.md"))?;
    if options.include_friction_log {
        let friction_path = adoption_log::friction_path(frontier_path);
        if friction_path.is_file() {
            fs::copy(&friction_path, out.join("adoption-friction.jsonl")).map_err(|e| {
                format!(
                    "copy adoption friction log {}: {e}",
                    friction_path.display()
                )
            })?;
        }
        write_json(
            out.join("adoption-friction-summary.json"),
            &adoption_log::list(frontier_path)?.summary,
        )?;
    }
    write_readme(out, &project.frontier_id())?;
    write_proof_packet(frontier_path, &out.join("proof-packet"))?;
    write_reviewer_notes_template(out)?;
    write_reviewer_packet_manifest(
        frontier_path,
        out,
        &project.frontier_id(),
        options.include_friction_log,
    )?;

    let files = collect_files(out)?;
    let manifest_files = files
        .iter()
        .filter(|path| path.as_path() != out.join("manifest.json").as_path())
        .map(|path| manifest_file(out, path))
        .collect::<Result<Vec<_>, _>>()?;
    let required_members = required_manifest_members();
    let files_sha256 = sha256_bytes(
        &serde_json::to_vec(&manifest_files).map_err(|e| format!("serialize files: {e}"))?,
    );
    let manifest = json!({
        "schema": SHARE_MANIFEST_SCHEMA,
        "frontier_id": project.frontier_id(),
        "created_at": chrono::Utc::now().to_rfc3339(),
        "read_only": true,
        "required_members": required_members,
        "members": {
            "frontier": "frontier.json",
            "frontier_health": "frontier-health.json",
            "evidence_ci": "evidence-ci.json",
            "source_inbox": "source-inbox.json",
            "tasks": "tasks.json",
            "review_sessions": "review-sessions.json",
            "reviewer_packet": "reviewer-packet.json",
            "reviewer_notes_template": "reviewer-notes-template.md",
            "source_snapshots": "source-snapshots/index.json",
            "source_locator_audit": "source-locator-audit.json",
            "canonical_verdict_events": "canonical-verdict-events.json",
            "proof_state": "proof-state.json",
            "proof_packet_manifest": "proof-packet/manifest.json",
            "adoption_transcript": "adoption-transcript.md"
        },
        "manifest_hashes": {
            "files_sha256": files_sha256
        },
        "trust_pack_v2": {
            "schema": "vela.proof_source_trust_pack.v0.2",
            "members": required_members,
            "member_hashes": member_hashes(&manifest_files, &required_members),
            "checks": [
                "source snapshots or unavailable-source records are present",
                "source locator audit is present",
                "Evidence CI is present",
                "review sessions are present",
                "canonical Diff Pack verdict events are present",
                "proof state and proof-packet manifest are present",
                "all listed files have SHA-256 hashes"
            ]
        },
        "excluded": ["private keys", "local caches", "raw secret env", "unchecked temp files"],
        "friction_log_included": options.include_friction_log,
        "files": manifest_files,
    });
    write_json(out.join("manifest.json"), &manifest)?;

    Ok(ShareBuildReport {
        ok: true,
        out: out.display().to_string(),
        frontier_id: project.frontier_id(),
        files: collect_files(out)?.len(),
        manifest_path: out.join("manifest.json").display().to_string(),
    })
}

pub fn inspect(path: &Path) -> Result<ShareInspectReport, String> {
    let manifest_path = path.join("manifest.json");
    let manifest: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(&manifest_path)
            .map_err(|e| format!("read share manifest {}: {e}", manifest_path.display()))?,
    )
    .map_err(|e| format!("parse share manifest: {e}"))?;
    let files = manifest
        .get("files")
        .and_then(|v| v.as_array())
        .ok_or("share manifest missing files array")?;
    let mut mismatches = Vec::new();
    let mut missing_required = Vec::new();
    for file in files {
        let rel = file.get("path").and_then(|v| v.as_str()).unwrap_or("");
        let expected = file.get("sha256").and_then(|v| v.as_str()).unwrap_or("");
        let full = path.join(rel);
        match sha256_file(&full) {
            Ok(actual) if actual == expected => {}
            Ok(actual) => mismatches.push(format!("{rel}: expected {expected}, got {actual}")),
            Err(err) => mismatches.push(format!("{rel}: {err}")),
        }
    }
    for rel in required_manifest_members() {
        if !path.join(rel).is_file() {
            missing_required.push(rel.to_string());
        }
    }
    let proof_packet_present = path.join("proof-packet").join("manifest.json").is_file();
    let stale_proof = share_proof_is_stale(path);
    let write_surface_findings = find_write_surfaces(path)?;
    Ok(ShareInspectReport {
        ok: mismatches.is_empty()
            && missing_required.is_empty()
            && proof_packet_present
            && !stale_proof
            && write_surface_findings.is_empty(),
        path: path.display().to_string(),
        files: files.len(),
        proof_packet_present,
        stale_proof,
        mismatches,
        missing_required,
        write_surface_findings,
    })
}

fn required_manifest_members() -> Vec<&'static str> {
    vec![
        "frontier.json",
        "frontier-health.json",
        "evidence-ci.json",
        "source-inbox.json",
        "tasks.json",
        "review-sessions.json",
        "reviewer-packet.json",
        "reviewer-notes-template.md",
        "source-snapshots/index.json",
        "source-locator-audit.json",
        "canonical-verdict-events.json",
        "proof-state.json",
        "proof-packet/manifest.json",
        "adoption-transcript.md",
        "README.md",
    ]
}

fn share_proof_is_stale(path: &Path) -> bool {
    let proof_state = path.join("proof-state.json");
    let Ok(body) = fs::read_to_string(proof_state) else {
        return true;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&body) else {
        return true;
    };
    let package_exported = value.get("status").and_then(|v| v.as_str()) == Some("packet_exported")
        || value.get("package_status").and_then(|v| v.as_str()) == Some("packet_exported");
    !package_exported || value.get("proof_packet_present").and_then(|v| v.as_bool()) != Some(true)
}

fn find_write_surfaces(path: &Path) -> Result<Vec<String>, String> {
    let mut findings = Vec::new();
    for file in collect_files(path)? {
        let rel = file
            .strip_prefix(path)
            .unwrap_or(&file)
            .to_string_lossy()
            .to_string();
        let Some(ext) = file.extension().and_then(|ext| ext.to_str()) else {
            continue;
        };
        if !matches!(ext, "html" | "htm") {
            continue;
        }
        let body = fs::read_to_string(&file)
            .map_err(|e| format!("read share file {}: {e}", file.display()))?;
        let lower = body.to_ascii_lowercase();
        if lower.contains("<form")
            || lower.contains("method=\"post\"")
            || lower.contains("javascript:")
            || lower.contains("/accept")
            || lower.contains("/reject")
            || lower.contains("/revision")
        {
            findings.push(rel);
        }
    }
    findings.sort();
    findings.dedup();
    Ok(findings)
}

fn write_json(path: PathBuf, value: &impl Serialize) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    let body = serde_json::to_string_pretty(value).map_err(|e| format!("serialize JSON: {e}"))?;
    fs::write(&path, format!("{body}\n")).map_err(|e| format!("write {}: {e}", path.display()))
}

fn write_readme(out: &Path, frontier_id: &str) -> Result<(), String> {
    fs::write(
        out.join("README.md"),
        format!(
            "# Vela share package\n\nRead-only external review package for `{frontier_id}`.\n\nVerify:\n\n```bash\nvela share inspect {} --json\nvela packet validate {}/proof-packet\njq '.frontier_id' {}/manifest.json\n```\n\nThis package excludes private keys, local caches, raw secret env, and unchecked temp files.\n",
            out.display(),
            out.display(),
            out.display()
        ),
    )
    .map_err(|e| format!("write share README: {e}"))
}

fn write_reviewer_notes_template(out: &Path) -> Result<(), String> {
    fs::write(
        out.join("reviewer-notes-template.md"),
        "# External reviewer notes\n\nFrontier:\nReviewer role:\nDomain familiarity:\nSetup time:\n\n## First pass\n\nFirst confusing step:\nFirst useful object:\nFinding inspected:\nDiff Pack inspected:\n\n## Trust\n\nTrust blockers:\nMissing docs:\nWould use again:\n\n## Notes\n\n- \n",
    )
    .map_err(|e| format!("write reviewer notes template: {e}"))
}

/// A locator scheme a reviewer can click through to an external source.
///
/// Anything else with a non-empty locator (e.g. `title:...`) is cited but
/// not independently resolvable: it is honest review debt, recorded as a
/// preserved-locator caveat, never a hidden gap.
fn locator_is_resolvable(locator: &str) -> bool {
    let l = locator.trim();
    if l.is_empty() {
        return false;
    }
    let scheme = l
        .split(':')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    matches!(
        scheme.as_str(),
        "doi" | "pmid" | "pmcid" | "pmc" | "nct" | "url" | "http" | "https" | "arxiv" | "isbn"
    )
}

fn write_source_snapshots(
    frontier_path: &Path,
    out: &Path,
    project: &crate::project::Project,
    source_inbox: &source_inbox::SourceInboxList,
) -> Result<(), String> {
    let snapshot_root = out.join("source-snapshots");
    let files_root = snapshot_root.join("files");
    fs::create_dir_all(&files_root).map_err(|e| format!("create source snapshots: {e}"))?;
    let mut copied = Vec::new();
    let mut unavailable = Vec::new();
    for record in &source_inbox.records {
        if let Some(source_path) = candidate_source_path(frontier_path, record) {
            let file_name = source_path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("source");
            let target = files_root.join(format!("{}__{}", record.id, file_name));
            fs::copy(&source_path, &target).map_err(|e| {
                format!(
                    "copy source snapshot {} to {}: {e}",
                    source_path.display(),
                    target.display()
                )
            })?;
            copied.push(json!({
                "record_id": record.id,
                "source_id": record.source_id,
                "title": record.title,
                "locator": record.locator,
                "state": record.state.to_string(),
                "path": target.strip_prefix(out).unwrap_or(&target).to_string_lossy().to_string(),
                "sha256": sha256_file(&target)?,
            }));
        } else {
            unavailable.push(json!({
                "record_id": record.id,
                "source_id": record.source_id,
                "title": record.title,
                "locator": record.locator,
                "state": record.state.to_string(),
                "reason": "source artifact unavailable in local frontier package; locator is preserved for review"
            }));
        }
    }
    // Registered sources whose locator is non-empty but not a resolvable
    // scheme (e.g. `title:...`) are cited-unavailable: emit an honest
    // unavailable entry even when there is no source-inbox record, so the
    // trust pack never silently reports zero review debt. Dedupe against
    // source-inbox records that already cover the same source id.
    let covered_source_ids: std::collections::BTreeSet<&str> = source_inbox
        .records
        .iter()
        .filter_map(|record| record.source_id.as_deref())
        .collect();
    for source in &project.sources {
        let locator = source.locator.trim();
        if locator.is_empty() || locator_is_resolvable(locator) {
            continue;
        }
        if covered_source_ids.contains(source.id.as_str()) {
            continue;
        }
        unavailable.push(json!({
            "source_id": source.id,
            "title": source.title,
            "locator": source.locator,
            "state": "cited_unavailable",
            "reason": "registered source locator is not a resolvable scheme (doi/pmid/pmcid/nct/url); cited but not independently clickable; locator preserved for review"
        }));
    }
    write_json(
        snapshot_root.join("index.json"),
        &json!({
            "schema": "vela.source_snapshots.v0.2",
            "copied": copied.len(),
            "unavailable": unavailable.len(),
            "snapshots": copied,
            "unavailable_sources": unavailable
        }),
    )
}

fn candidate_source_path(
    frontier_path: &Path,
    record: &source_inbox::SourceInboxRecord,
) -> Option<PathBuf> {
    for key in ["path", "local_path", "source_path", "content_path", "file"] {
        let Some(value) = record.metadata.get(key).and_then(|value| value.as_str()) else {
            continue;
        };
        let path = PathBuf::from(value);
        let path = if path.is_absolute() {
            path
        } else {
            frontier_path.join(path)
        };
        if path.is_file() {
            return Some(path);
        }
    }
    let mut stems = Vec::new();
    stems.push(record.id.clone());
    if let Some(source_id) = &record.source_id {
        stems.push(source_id.clone());
    }
    for stem in stems {
        for ext in ["pdf", "txt", "md", "json", "jsonl", "csv"] {
            let path = frontier_path.join("sources").join(format!("{stem}.{ext}"));
            if path.is_file() {
                return Some(path);
            }
        }
    }
    None
}

fn write_source_locator_audit(
    out: &Path,
    project: &crate::project::Project,
    source_inbox: &source_inbox::SourceInboxList,
) -> Result<(), String> {
    let missing_registered_locators = project
        .sources
        .iter()
        .filter(|source| source.locator.trim().is_empty())
        .count();
    let missing_inbox_locators = source_inbox
        .records
        .iter()
        .filter(|record| record.locator.trim().is_empty())
        .count();
    let unavailable = read_json_value(&out.join("source-snapshots").join("index.json"))?
        .get("unavailable")
        .and_then(|value| value.as_u64())
        .unwrap_or(0);

    // Click-through classification over every registered source.
    let mut resolvable_sources = 0usize;
    let mut cited_unavailable_sources: Vec<Value> = Vec::new();
    let source_ids: std::collections::BTreeSet<&str> =
        project.sources.iter().map(|s| s.id.as_str()).collect();
    for source in &project.sources {
        let locator = source.locator.trim();
        if locator.is_empty() {
            continue; // counted in missing_registered_locators
        }
        if locator_is_resolvable(locator) {
            resolvable_sources += 1;
        } else {
            cited_unavailable_sources.push(json!({
                "id": source.id,
                "title": source.title,
                "locator": source.locator,
                "reason": "locator is not a resolvable scheme (doi/pmid/pmcid/nct/url); cited but not independently clickable; locator preserved for review"
            }));
        }
    }
    let cited_unavailable_sources_count = cited_unavailable_sources.len();

    // Click-through classification over every evidence atom via source_id.
    let resolvable_by_id: std::collections::BTreeMap<&str, bool> = project
        .sources
        .iter()
        .map(|s| (s.id.as_str(), locator_is_resolvable(s.locator.trim())))
        .collect();
    let mut resolvable_evidence_atoms = 0usize;
    let mut cited_unavailable_evidence_atoms = 0usize;
    let mut dangling_evidence_atoms = 0usize;
    for atom in &project.evidence_atoms {
        if !source_ids.contains(atom.source_id.as_str()) {
            dangling_evidence_atoms += 1;
        } else if *resolvable_by_id
            .get(atom.source_id.as_str())
            .unwrap_or(&false)
        {
            resolvable_evidence_atoms += 1;
        } else {
            cited_unavailable_evidence_atoms += 1;
        }
    }

    // A broken click-through is a dead reviewer click: an empty registered
    // locator, or an evidence atom whose source_id resolves to nothing. A
    // cited-unavailable source is NOT broken: its locator is preserved and
    // (from v0.308) it carries a caveat on every dependent finding.
    let broken_click_throughs = missing_registered_locators + dangling_evidence_atoms;

    write_json(
        out.join("source-locator-audit.json"),
        &json!({
            "schema": "vela.source_locator_audit.v0.3",
            "registered_sources": project.sources.len(),
            "source_inbox_records": source_inbox.records.len(),
            "missing_registered_locators": missing_registered_locators,
            "missing_source_inbox_locators": missing_inbox_locators,
            "unavailable_source_artifacts": unavailable,
            "review_debt": missing_registered_locators + missing_inbox_locators + unavailable as usize,
            "resolvable_sources": resolvable_sources,
            "cited_unavailable_sources_count": cited_unavailable_sources_count,
            "cited_unavailable_sources": cited_unavailable_sources,
            "resolvable_evidence_atoms": resolvable_evidence_atoms,
            "cited_unavailable_evidence_atoms": cited_unavailable_evidence_atoms,
            "dangling_evidence_atoms": dangling_evidence_atoms,
            "broken_click_throughs": broken_click_throughs,
            "caveat": "Unavailable source artifacts are review debt. Locators are preserved so reviewers can retrieve or verify them outside the package. Cited-unavailable sources are honest debt, not hidden gaps; broken click-throughs are dead reviewer clicks (empty locator or dangling evidence atom) and must be zero for the flagship tier."
        }),
    )
}

fn write_canonical_verdict_events(
    out: &Path,
    project: &crate::project::Project,
) -> Result<(), String> {
    let events = project
        .events
        .iter()
        .filter(|event| event.kind == "diff_pack.reviewed")
        .cloned()
        .collect::<Vec<_>>();
    write_json(
        out.join("canonical-verdict-events.json"),
        &json!({
            "schema": "vela.canonical_verdict_events.v0.2",
            "count": events.len(),
            "events": events,
            "caveat": "Canonical verdict events are accepted review events. Pending verdicts and review sessions remain review work until promoted."
        }),
    )
}

fn write_reviewer_packet_manifest(
    frontier_path: &Path,
    out: &Path,
    frontier_id: &str,
    friction_log_included: bool,
) -> Result<(), String> {
    let frontier = read_json_value(&out.join("frontier.json"))?;
    let evidence_ci = read_json_value(&out.join("evidence-ci.json"))?;
    let source_inbox = read_json_value(&out.join("source-inbox.json"))?;
    let tasks = read_json_value(&out.join("tasks.json"))?;
    let review_sessions = read_json_value(&out.join("review-sessions.json"))?;
    let proof_state = read_json_value(&out.join("proof-state.json"))?;
    let source_snapshots = read_json_value(&out.join("source-snapshots").join("index.json"))?;
    let source_locator_audit = read_json_value(&out.join("source-locator-audit.json"))?;
    let canonical_verdict_events = read_json_value(&out.join("canonical-verdict-events.json"))?;
    let diff_pack_files = package_files(out, "diff-packs")?;
    let review_packet_files = package_files(out, "review-packets")?;
    let source_records = source_inbox
        .get("records")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let task_records = tasks
        .get("tasks")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let review_session_records = review_sessions
        .get("sessions")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let diff_pack_ids = diff_pack_files
        .iter()
        .filter_map(|path| {
            Path::new(path)
                .file_stem()
                .and_then(|stem| stem.to_str())
                .map(|stem| stem.to_string())
        })
        .collect::<Vec<_>>();

    let packet = json!({
        "schema": "vela.reviewer_packet_manifest.v0.1",
        "frontier_id": frontier_id,
        "frontier_path": frontier_path.display().to_string(),
        "read_only": true,
        "review_task": "Inspect source grounding, Evidence CI state, Diff Pack scope, proof state, and review friction before any local reviewer accepts frontier state.",
        "boundaries": [
            "This package is for inspection only.",
            "It does not accept, reject, revise, or retract frontier state.",
            "Hosted share pages and hub state are not scientific authority.",
            "Clinical or translational statements are review targets, not medical advice or field consensus."
        ],
        "source_scope": {
            "registered_sources": frontier.get("sources").and_then(|v| v.as_array()).map(|v| v.len()).unwrap_or(0),
            "source_inbox_records": source_records.len(),
            "source_inbox_path": "source-inbox.json",
            "sample_records": source_records.into_iter().take(12).collect::<Vec<_>>()
        },
        "source_snapshots": {
            "path": "source-snapshots/index.json",
            "copied": source_snapshots.get("copied").cloned().unwrap_or(Value::Null),
            "unavailable": source_snapshots.get("unavailable").cloned().unwrap_or(Value::Null)
        },
        "source_locator_audit": {
            "path": "source-locator-audit.json",
            "summary": source_locator_audit
        },
        "diff_pack_scope": {
            "count": diff_pack_files.len(),
            "ids": diff_pack_ids,
            "files": diff_pack_files
        },
        "review_packets": {
            "count": review_packet_files.len(),
            "files": review_packet_files
        },
        "evidence_ci": {
            "path": "evidence-ci.json",
            "summary": evidence_ci.get("summary").cloned().unwrap_or(Value::Null)
        },
        "proof": {
            "state_path": "proof-state.json",
            "packet_path": "proof-packet",
            "state": proof_state
        },
        "canonical_verdict_events": {
            "path": "canonical-verdict-events.json",
            "count": canonical_verdict_events.get("count").cloned().unwrap_or(Value::Null)
        },
        "review_sessions": {
            "count": review_session_records.len(),
            "path": "review-sessions.json"
        },
        "tasks": {
            "count": task_records.len(),
            "path": "tasks.json"
        },
        "friction_log": {
            "included": friction_log_included,
            "summary_path": if friction_log_included { Value::String("adoption-friction-summary.json".to_string()) } else { Value::Null }
        },
        "reviewer_notes_template": "reviewer-notes-template.md",
        "first_pass_commands": [
            "vela share inspect . --json",
            "vela packet validate proof-packet",
            "vela share render . --out /tmp/vela-share-site",
            "jq '.review_task' reviewer-packet.json"
        ],
        "local_frontier_commands": [
            format!("vela workbench {} --no-open", frontier_path.display()),
            format!("vela evidence-ci {} --json", frontier_path.display()),
            format!("vela proof {} --out /tmp/vela-proof --json", frontier_path.display())
        ]
    });
    write_json(out.join("reviewer-packet.json"), &packet)
}

fn member_hashes(
    manifest_files: &[ManifestFile],
    required_members: &[&'static str],
) -> BTreeMap<String, String> {
    let by_path = manifest_files
        .iter()
        .map(|file| (file.path.as_str(), file.sha256.as_str()))
        .collect::<BTreeMap<_, _>>();
    required_members
        .iter()
        .filter_map(|member| {
            by_path
                .get(member)
                .map(|hash| ((*member).to_string(), (*hash).to_string()))
        })
        .collect()
}

fn read_json_value(path: &Path) -> Result<Value, String> {
    let body = fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    serde_json::from_str(&body).map_err(|e| format!("parse {}: {e}", path.display()))
}

fn package_files(out: &Path, dir: &str) -> Result<Vec<String>, String> {
    let root = out.join(dir);
    if !root.is_dir() {
        return Ok(Vec::new());
    }
    let mut files = collect_files(&root)?
        .into_iter()
        .filter_map(|path| path.strip_prefix(out).ok().map(|rel| rel.to_path_buf()))
        .map(|path| path.to_string_lossy().to_string())
        .collect::<Vec<_>>();
    files.sort();
    Ok(files)
}

fn write_proof_packet(frontier_path: &Path, out: &Path) -> Result<(), String> {
    let exe = std::env::var_os("VELA_BIN")
        .map(PathBuf::from)
        .map(Ok)
        .unwrap_or_else(|| {
            std::env::current_exe().map_err(|e| format!("current executable: {e}"))
        })?;
    let status = Command::new(exe)
        .arg("proof")
        .arg(frontier_path)
        .arg("--out")
        .arg(out)
        .stdout(Stdio::null())
        .status()
        .map_err(|e| format!("run proof export: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err("proof export failed for share package".to_string())
    }
}

fn copy_optional_dir(src: &Path, dst: &Path) -> Result<(), String> {
    fs::create_dir_all(dst).map_err(|e| format!("create {}: {e}", dst.display()))?;
    if !src.is_dir() {
        return Ok(());
    }
    for entry in fs::read_dir(src).map_err(|e| format!("read {}: {e}", src.display()))? {
        let entry = entry.map_err(|e| format!("read {} entry: {e}", src.display()))?;
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.contains("key") || name.starts_with('.') || name == "source-cache" {
            continue;
        }
        let target = dst.join(name.as_ref());
        if path.is_dir() {
            copy_optional_dir(&path, &target)?;
        } else if path.is_file() {
            fs::copy(&path, &target)
                .map_err(|e| format!("copy {} to {}: {e}", path.display(), target.display()))?;
        }
    }
    Ok(())
}

fn collect_files(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    collect_files_inner(root, &mut out)?;
    out.sort();
    Ok(out)
}

fn collect_files_inner(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    for entry in fs::read_dir(dir).map_err(|e| format!("read {}: {e}", dir.display()))? {
        let entry = entry.map_err(|e| format!("read dir entry: {e}"))?;
        let path = entry.path();
        if path.is_dir() {
            collect_files_inner(&path, out)?;
        } else if path.is_file() {
            out.push(path);
        }
    }
    Ok(())
}

fn manifest_file(root: &Path, path: &Path) -> Result<ManifestFile, String> {
    let rel = path
        .strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .to_string();
    let meta = fs::metadata(path).map_err(|e| format!("stat {}: {e}", path.display()))?;
    Ok(ManifestFile {
        path: rel,
        sha256: sha256_file(path)?,
        bytes: meta.len(),
    })
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file = fs::File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| format!("read {}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn share_manifest_detects_tampering() {
        let tmp = TempDir::new().unwrap();
        let out = tmp.path().join("share");
        fs::create_dir_all(out.join("proof-packet")).unwrap();
        fs::write(out.join("README.md"), "read-only share\n").unwrap();
        fs::write(out.join("frontier.json"), "{}\n").unwrap();
        fs::write(out.join("frontier-health.json"), "{}\n").unwrap();
        fs::write(out.join("evidence-ci.json"), "{}\n").unwrap();
        fs::write(out.join("source-inbox.json"), "{}\n").unwrap();
        fs::create_dir_all(out.join("source-snapshots")).unwrap();
        fs::write(out.join("source-snapshots").join("index.json"), "{}\n").unwrap();
        fs::write(out.join("source-locator-audit.json"), "{}\n").unwrap();
        fs::write(out.join("tasks.json"), "{}\n").unwrap();
        fs::write(out.join("review-sessions.json"), "{}\n").unwrap();
        fs::write(out.join("reviewer-packet.json"), "{}\n").unwrap();
        fs::write(out.join("reviewer-notes-template.md"), "notes\n").unwrap();
        fs::write(out.join("canonical-verdict-events.json"), "{}\n").unwrap();
        fs::write(
            out.join("proof-state.json"),
            "{\"status\":\"packet_exported\",\"proof_packet_present\":true}\n",
        )
        .unwrap();
        fs::write(out.join("adoption-transcript.md"), "transcript\n").unwrap();
        fs::write(out.join("proof-packet").join("manifest.json"), "{}\n").unwrap();
        let files = collect_files(&out).unwrap();
        let manifest_files = files
            .iter()
            .map(|path| manifest_file(&out, path))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        write_json(
            out.join("manifest.json"),
            &json!({
                "schema": SHARE_MANIFEST_SCHEMA,
                "frontier_id": "vfr_test",
                "created_at": "2026-05-14T00:00:00Z",
                "read_only": true,
                "files": manifest_files,
            }),
        )
        .unwrap();
        assert!(inspect(&out).unwrap().ok);
        fs::write(out.join("README.md"), "changed\n").unwrap();
        assert!(!inspect(&out).unwrap().ok);
    }
}
