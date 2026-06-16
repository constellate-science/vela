//! Canonical frontier repository layout helpers.
//!
//! This module keeps the user-facing repository shape separate from the
//! existing `.vela/` object/event storage. The visible files are the clone and
//! review surface; `.vela/` remains the substrate machinery.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::events;
use crate::project::{self, Project, ProjectDependency};
use crate::proposals;

pub const FRONTIER_REPO_LAYOUT: &str = "vela.frontier_repo.v0.1";
pub const FRONTIER_MANIFEST_SCHEMA: &str = "vela.frontier_manifest.v0.1";
pub const FRONTIER_LOCK_SCHEMA: &str = "vela.frontier_lock.v0.1";
pub const FRONTIER_INIT_SCHEMA: &str = "vela.frontier_repo_init.v0.1";
pub const FRONTIER_MATERIALIZE_SCHEMA: &str = "vela.frontier_materialize.v0.1";
pub const FRONTIER_REPO_STATUS_SCHEMA: &str = "vela.frontier_repo_status.v0.1";
pub const FRONTIER_REPO_DOCTOR_SCHEMA: &str = "vela.frontier_repo_doctor.v0.1";
pub const FRONTIER_PROOF_VERIFY_SCHEMA: &str = "vela.frontier_proof_verify.v0.1";
pub const DEFAULT_CARINA_KERNEL: &str = "carina@0.1.0";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FrontierManifest {
    pub schema: String,
    pub layout: String,
    #[serde(default = "default_split_mode")]
    pub mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frontier_id: Option<String>,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "default_visibility")]
    pub visibility: String,
    #[serde(default)]
    pub scope: FrontierScope,
    pub carina: CarinaManifest,
    pub vela: VelaManifest,
    pub paths: FrontierPaths,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub maintainers: Vec<ManifestMaintainer>,
    #[serde(default)]
    pub policies: ManifestPolicies,
    #[serde(default)]
    pub license: ManifestLicense,
    #[serde(default)]
    pub dependencies: ManifestDependencies,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub templates: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CarinaManifest {
    pub kernel: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VelaManifest {
    pub reducer: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct FrontierScope {
    #[serde(default)]
    pub question: String,
    #[serde(default)]
    pub includes: Vec<String>,
    #[serde(default)]
    pub excludes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FrontierPaths {
    pub state: String,
    pub sources: String,
    pub artifacts: String,
    pub review: String,
    pub proof: String,
    pub exports: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestMaintainer {
    pub id: String,
    pub role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestPolicies {
    pub review: String,
    pub proof: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub frontier: BTreeMap<String, String>,
}

impl Default for ManifestPolicies {
    fn default() -> Self {
        Self {
            review: "review/policy.yaml".to_string(),
            proof: "proof/policy.yaml".to_string(),
            frontier: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestLicense {
    pub content: String,
    pub code: String,
    pub data: String,
}

impl Default for ManifestLicense {
    fn default() -> Self {
        Self {
            content: "CC-BY-4.0".to_string(),
            code: "Apache-2.0".to_string(),
            data: "varies".to_string(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestDependencies {
    #[serde(default)]
    pub frontiers: Vec<String>,
    #[serde(default)]
    pub packages: Vec<String>,
    #[serde(default)]
    pub adapters: Vec<String>,
    /// v0.59: structured cross-frontier dependency entries. Pre-v0.59
    /// split-repos persisted `Project.dependencies` only into the
    /// rendered `frontier.json`, which `vela frontier materialize`
    /// would regenerate without them. This field is the durable
    /// source of truth in the yaml manifest and is rehydrated into
    /// `Project.dependencies` on load.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub frontiers_v2: Vec<ProjectDependency>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FrontierLock {
    pub schema: String,
    pub generated_at: String,
    pub vela_version: String,
    pub carina_kernel: String,
    pub frontier_id: String,
    #[serde(default)]
    pub canonicalization: LockCanonicalization,
    #[serde(default)]
    pub reducer: LockPackage,
    #[serde(default)]
    pub carina: LockKernel,
    pub snapshot_hash: String,
    pub event_log_hash: String,
    pub proposal_state_hash: String,
    #[serde(default)]
    pub sources_hash: String,
    #[serde(default)]
    pub artifacts_hash: String,
    #[serde(default)]
    pub review_hash: String,
    pub proof_freshness: String,
    #[serde(default)]
    pub proof: LockProof,
    pub paths: LockPaths,
    /// v0.109: pinned cross-frontier dependencies. Each entry
    /// records the dependent frontier's `vfr_id`, the
    /// `pinned_snapshot_hash` declared in the manifest, and the
    /// `locator` (typically an https URL or hub registry pointer)
    /// the resolver was told to use. The lockfile reproduces this
    /// information in one place so a downstream consumer can
    /// verify "this frontier depended on exactly these snapshots
    /// of those dependencies" with no manifest cross-reference.
    /// Empty for frontiers with no cross-frontier dependencies;
    /// preserved across pre-v0.109 locks via #[serde(default)].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dependencies: Vec<LockedDependency>,
}

/// v0.109: per-dependency pin entry inside `vela.lock`. Mirrors
/// the manifest's `ProjectDependency` fields that affect
/// reproducibility (id, snapshot, locator) and drops the rest
/// (display name, semver-style version) so the lockfile is the
/// minimum content-addressable witness.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct LockedDependency {
    /// Display name from the manifest. Not part of the
    /// reproducibility witness; kept for human readability.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    /// Source string from the manifest (typically an https URL
    /// or a `vfr_<id>` reference).
    pub source: String,
    /// Content-addressed frontier id of the dependent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vfr_id: Option<String>,
    /// Locator the resolver was told to fetch from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locator: Option<String>,
    /// SHA-256 of the dependent's canonical snapshot. The strict
    /// pull path verifies the fetched dependency matches this
    /// exact hash before satisfying any cross-frontier link.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pinned_snapshot_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LockCanonicalization {
    pub json: String,
    pub yaml: String,
}

impl Default for LockCanonicalization {
    fn default() -> Self {
        Self {
            json: "vela-canonical-json-v0.1".to_string(),
            yaml: "vela-yaml-v0.1".to_string(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct LockPackage {
    pub package: String,
    pub digest: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct LockKernel {
    pub kernel: String,
    pub digest: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct LockProof {
    pub latest: String,
    pub digest: String,
    pub freshness: String,
    pub events_manifest: String,
    pub replay_trace: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LockPaths {
    pub frontier: String,
    pub events: String,
}

#[derive(Debug, Clone)]
struct ProofWrite {
    digest: String,
    freshness: String,
    latest: String,
    events_manifest: String,
    replay_trace: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoLayoutIssue {
    pub rule_id: String,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct InitOptions<'a> {
    pub name: &'a str,
    pub template: &'a str,
    pub initialize_git: bool,
}

pub fn initialize(path: &Path, options: InitOptions<'_>) -> Result<serde_json::Value, String> {
    if path.exists() && !path.is_dir() {
        return Err(format!("{} exists and is not a directory", path.display()));
    }
    fs::create_dir_all(path).map_err(|e| {
        format!(
            "Failed to create frontier directory '{}': {e}",
            path.display()
        )
    })?;

    write_section_readmes(path)?;
    let now = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    let project = empty_project(options.name, "", &now);
    crate::repo::init_repo(path, &project)?;
    write_frontier_card(path, options.name, options.template)?;
    write_scope(path, options.name)?;
    let next_commands = crate::frontier_template::apply(path, options.name, options.template)?;
    if options.initialize_git && !path.join(".git").exists() {
        let status = std::process::Command::new("git")
            .arg("init")
            .arg(path)
            .status()
            .map_err(|e| format!("Failed to run git init: {e}"))?;
        if !status.success() {
            return Err("git init failed".to_string());
        }
    }

    let mut payload = json!({
        "schema": FRONTIER_INIT_SCHEMA,
        "ok": true,
        "layout": FRONTIER_REPO_LAYOUT,
        "path": path.display().to_string(),
        "name": options.name,
        "template": options.template,
        "wrote": [
            "README.md",
            "SCOPE.md",
            "frontier.yaml",
            "frontier.json",
            "vela.lock"
        ],
        "next_commands": next_commands
    });
    if let Some(object) = payload.as_object_mut()
        && options.template == crate::frontier_template::ADOPTION_FRONTIER_TEMPLATE
    {
        object.insert(
            "adoption_template".to_string(),
            crate::frontier_template::init_payload_fields(options.template, path),
        );
    }
    Ok(payload)
}

pub fn materialize(path: &Path) -> Result<serde_json::Value, String> {
    let source = crate::repo::VelaSource::VelaRepo(path.to_path_buf());
    let project = crate::repo::load(&source)?;
    write_section_readmes(path)?;
    let generated_at = materialization_generated_at(path, &project);
    write_visible_state(path, &project, &generated_at)?;
    write_manifest(path, &project)?;
    let proof = write_proof(path, &project, &generated_at)?;
    let lock = write_lock(path, &project, &proof, &generated_at)?;
    Ok(json!({
        "schema": FRONTIER_MATERIALIZE_SCHEMA,
        "ok": true,
        "path": path.display().to_string(),
        "wrote_frontier": "frontier.json",
        "wrote_lock": "vela.lock",
        "wrote_proof": "proof/latest.json",
        "wrote_events_manifest": "proof/events.manifest.jsonl",
        "snapshot_hash": lock.snapshot_hash,
        "event_log_hash": lock.event_log_hash,
        "proposal_state_hash": lock.proposal_state_hash,
    }))
}

pub fn write_visible_repo_files(path: &Path, project: &Project) -> Result<(), String> {
    write_section_readmes(path)?;
    let generated_at = materialization_generated_at(path, project);
    write_visible_state(path, project, &generated_at)?;
    if !path.join("frontier.yaml").is_file() {
        write_manifest(path, project)?;
    } else {
        // v0.59: keep the structured cross-frontier deps in the
        // existing yaml in sync with `Project.dependencies`. We
        // intentionally only touch the `dependencies.frontiers_v2`
        // field; other user-edited fields (scope, maintainers,
        // policies) are preserved.
        sync_manifest_deps(path, &project.project.dependencies)?;
    }
    let proof = write_proof(path, project, &generated_at)?;
    write_lock(path, project, &proof, &generated_at)?;
    Ok(())
}

pub fn read_manifest(path: &Path) -> Result<Option<FrontierManifest>, String> {
    let manifest_path = path.join("frontier.yaml");
    if !manifest_path.is_file() {
        return Ok(None);
    }
    let data = fs::read_to_string(&manifest_path)
        .map_err(|e| format!("Failed to read frontier.yaml: {e}"))?;
    serde_yaml::from_str(&data).map(Some).map_err(|e| {
        format!(
            "Failed to parse frontier manifest '{}': {e}",
            manifest_path.display()
        )
    })
}

pub fn read_lock(path: &Path) -> Result<Option<FrontierLock>, String> {
    let lock_path = path.join("vela.lock");
    if !lock_path.is_file() {
        return Ok(None);
    }
    let data =
        fs::read_to_string(&lock_path).map_err(|e| format!("Failed to read vela.lock: {e}"))?;
    serde_yaml::from_str(&data).map(Some).map_err(|e| {
        format!(
            "Failed to parse frontier lock '{}': {e}",
            lock_path.display()
        )
    })
}

pub fn layout_issues(path: &Path, project: &Project) -> Vec<RepoLayoutIssue> {
    if !path.is_dir() || !path.join(".vela").is_dir() {
        return Vec::new();
    }
    if !path.join("frontier.yaml").is_file() && !path.join("vela.lock").is_file() {
        return Vec::new();
    }
    let mut issues = Vec::new();
    let manifest = match read_manifest(path) {
        Ok(value) => value,
        Err(e) => {
            issues.push(issue("invalid_frontier_manifest", e));
            None
        }
    };
    let lock = match read_lock(path) {
        Ok(value) => value,
        Err(e) => {
            issues.push(issue("invalid_frontier_lock", e));
            None
        }
    };

    if manifest.is_none() {
        issues.push(issue(
            "missing_frontier_manifest",
            "Split frontier repo is missing frontier.yaml.",
        ));
    }
    let Some(lock) = lock else {
        issues.push(issue(
            "missing_frontier_lock",
            "Split frontier repo is missing generated vela.lock.",
        ));
        return issues;
    };

    let locked_project = project_with_frontier_id(project);
    let hash_project = locked_project.as_ref().unwrap_or(project);
    let expected_snapshot = prefixed(events::snapshot_hash(hash_project));
    let expected_event_log = prefixed(events::event_log_hash(&hash_project.events));
    let expected_proposals = proposal_state_hash(&project.proposals);
    let expected_frontier = hash_project.frontier_id();
    let expected_sources = directory_hash(&path.join("sources"));
    let expected_artifacts = directory_hash(&path.join("artifacts"));
    let expected_review = directory_hash(&path.join("review"));
    let expected_proof = directory_hash(&path.join("proof"));
    if lock.snapshot_hash != expected_snapshot {
        issues.push(issue(
            "frontier_lock_mismatch",
            format!(
                "vela.lock snapshot_hash does not match materialized frontier state: lock={}, current={expected_snapshot}",
                lock.snapshot_hash
            ),
        ));
    }
    if lock.event_log_hash != expected_event_log {
        issues.push(issue(
            "frontier_lock_mismatch",
            format!(
                "vela.lock event_log_hash does not match .vela/events: lock={}, current={expected_event_log}",
                lock.event_log_hash
            ),
        ));
    }
    if lock.proposal_state_hash != expected_proposals {
        issues.push(issue(
            "frontier_lock_mismatch",
            format!(
                "vela.lock proposal_state_hash does not match .vela/proposals: lock={}, current={expected_proposals}",
                lock.proposal_state_hash
            ),
        ));
    }
    if lock.frontier_id != expected_frontier {
        issues.push(issue(
            "frontier_lock_mismatch",
            format!(
                "vela.lock frontier_id does not match current frontier: lock={}, current={expected_frontier}",
                lock.frontier_id
            ),
        ));
    }
    if !lock.sources_hash.is_empty() && lock.sources_hash != expected_sources {
        issues.push(issue(
            "frontier_lock_mismatch",
            format!(
                "vela.lock sources_hash does not match sources/: lock={}, current={expected_sources}",
                lock.sources_hash
            ),
        ));
    }
    if !lock.artifacts_hash.is_empty() && lock.artifacts_hash != expected_artifacts {
        issues.push(issue(
            "frontier_lock_mismatch",
            format!(
                "vela.lock artifacts_hash does not match artifacts/: lock={}, current={expected_artifacts}",
                lock.artifacts_hash
            ),
        ));
    }
    if !lock.review_hash.is_empty() && lock.review_hash != expected_review {
        issues.push(issue(
            "frontier_lock_mismatch",
            format!(
                "vela.lock review_hash does not match review/: lock={}, current={expected_review}",
                lock.review_hash
            ),
        ));
    }
    if !lock.proof.digest.is_empty() && lock.proof.digest != expected_proof {
        issues.push(issue(
            "frontier_lock_mismatch",
            format!(
                "vela.lock proof digest does not match proof/: lock={}, current={expected_proof}",
                lock.proof.digest
            ),
        ));
    }

    let visible_path = path.join("frontier.json");
    if !visible_path.is_file() {
        issues.push(issue(
            "missing_materialized_frontier",
            "Split frontier repo is missing frontier.json.",
        ));
        return issues;
    }
    match crate::repo::load_project_file(&visible_path) {
        Ok(visible) => {
            let visible_hash = prefixed(events::snapshot_hash(&visible));
            if visible_hash != expected_snapshot {
                issues.push(issue(
                    "frontier_lock_mismatch",
                    format!(
                        "frontier.json does not match .vela materialized state: visible={visible_hash}, current={expected_snapshot}",
                    ),
                ));
            }
        }
        Err(e) => issues.push(issue("invalid_materialized_frontier", e)),
    }

    issues
}

pub fn manifest_overrides(path: &Path) -> Result<Option<FrontierManifest>, String> {
    read_manifest(path)
}

pub fn repo_status(path: &Path) -> Result<serde_json::Value, String> {
    let project = crate::repo::load_from_path(path)?;
    let lock = read_lock(path)?;
    let layout_issues = layout_issues(path, &project);
    let structural_issue_count = layout_issues.len();
    let lock_agreement = structural_issue_count == 0;
    let open_proposals = project
        .proposals
        .iter()
        .filter(|proposal| {
            !matches!(
                proposal.status.as_str(),
                "accepted" | "applied" | "rejected"
            )
        })
        .count();
    let lock = lock.as_ref();
    let sources_hash = directory_hash(&path.join("sources"));
    let artifacts_hash = directory_hash(&path.join("artifacts"));
    let review_hash = directory_hash(&path.join("review"));
    let proof_hash = directory_hash(&path.join("proof"));
    let source_changed =
        lock.is_some_and(|lock| !lock.sources_hash.is_empty() && lock.sources_hash != sources_hash);
    let artifact_changed = lock.is_some_and(|lock| {
        !lock.artifacts_hash.is_empty() && lock.artifacts_hash != artifacts_hash
    });
    let review_changed =
        lock.is_some_and(|lock| !lock.review_hash.is_empty() && lock.review_hash != review_hash);
    let proof_changed =
        lock.is_some_and(|lock| !lock.proof.digest.is_empty() && lock.proof.digest != proof_hash);
    Ok(json!({
        "schema": FRONTIER_REPO_STATUS_SCHEMA,
        "ok": lock_agreement,
        "path": path.display().to_string(),
        "layout": FRONTIER_REPO_LAYOUT,
        "frontier_id": project.frontier_id(),
        "summary": {
            "accepted_events": project.events.len(),
            "open_proposals": open_proposals,
            "findings": project.findings.len(),
            "sources": project.sources.len(),
            "artifacts": project.artifacts.len(),
        },
        "freshness": {
            "materialized_state": if lock_agreement { "fresh" } else { "stale_or_invalid" },
            "proof": lock.map_or("unknown", |lock| lock.proof_freshness.as_str()),
            "sources_changed": source_changed,
            "artifacts_changed": artifact_changed,
            "review_changed": review_changed,
            "proof_changed": proof_changed,
        },
        "hashes": {
            "snapshot_hash": prefixed(events::snapshot_hash(&project_with_frontier_id(&project)?)),
            "event_log_hash": prefixed(events::event_log_hash(&project.events)),
            "sources_hash": sources_hash,
            "artifacts_hash": artifacts_hash,
            "review_hash": review_hash,
            "proof_hash": proof_hash,
        },
        "lock_agreement": lock_agreement,
        "issues": layout_issues.iter().map(|issue| json!({
            "rule_id": issue.rule_id,
            "message": issue.message,
        })).collect::<Vec<_>>(),
    }))
}

pub fn repo_doctor(path: &Path) -> Result<serde_json::Value, String> {
    let project = crate::repo::load_from_path(path)?;
    let mut issues = layout_issues(path, &project)
        .into_iter()
        .map(|issue| {
            json!({
                "rule_id": issue.rule_id,
                "severity": "error",
                "message": issue.message,
            })
        })
        .collect::<Vec<_>>();

    for file in [
        "README.md",
        "SCOPE.md",
        "frontier.yaml",
        "frontier.json",
        "vela.lock",
    ] {
        if !path.join(file).is_file() {
            issues.push(json!({
                "rule_id": "missing_repo_file",
                "severity": "error",
                "path": file,
                "message": format!("Frontier repo is missing {file}."),
            }));
        }
    }
    for dir in [
        "sources",
        "artifacts",
        "review",
        "proof",
        "exports",
        ".vela",
    ] {
        if !path.join(dir).is_dir() {
            issues.push(json!({
                "rule_id": "missing_repo_directory",
                "severity": "error",
                "path": dir,
                "message": format!("Frontier repo is missing {dir}/."),
            }));
        }
    }
    for dir in [
        "artifacts/packets",
        "artifacts/runs",
        "artifacts/code",
        "artifacts/notebooks",
        "artifacts/data",
        "artifacts/notes",
        "artifacts/tables",
        "artifacts/figures",
        "artifacts/analyses",
        "artifacts/environments",
        "proof/signatures",
        "proof/attestations",
        "exports/prov",
        "exports/ro-crate",
        "exports/frictionless",
        "exports/mcp",
        "exports/report",
        "exports/registry",
    ] {
        if !path.join(dir).is_dir() {
            issues.push(json!({
                "rule_id": "missing_optional_repo_hook",
                "severity": "warning",
                "path": dir,
                "message": format!("Optional repo hook {dir}/ is not present."),
            }));
        }
    }
    for root_artifact in [
        "bbb-core.v0.1.json",
        "bbb-core.v0.2.json",
        "bbb-core.v0.3.json",
        "bbb-core.v0.4.json",
        "review-packet.v1.json",
        "promotion-core.v1.json",
        "review-debt.v1.json",
        "seed-manifest.v1.json",
    ] {
        if path.join(root_artifact).exists() {
            issues.push(json!({
                "rule_id": "root_artifact_clutter",
                "severity": "warning",
                "path": root_artifact,
                "message": format!("{root_artifact} should live under sources/, artifacts/, review/, proof/, or exports/."),
            }));
        }
    }

    Ok(json!({
        "schema": FRONTIER_REPO_DOCTOR_SCHEMA,
        "ok": !issues.iter().any(|issue| issue.get("severity").and_then(|v| v.as_str()) == Some("error")),
        "path": path.display().to_string(),
        "layout": FRONTIER_REPO_LAYOUT,
        "issues": issues,
    }))
}

pub fn proof_verify(path: &Path) -> Result<serde_json::Value, String> {
    let project = crate::repo::load_from_path(path)?;
    let lock = read_lock(path)?;
    let proof_path = path.join("proof/latest.json");
    let mut issues = layout_issues(path, &project)
        .into_iter()
        .map(|issue| {
            json!({
                "rule_id": issue.rule_id,
                "message": issue.message,
            })
        })
        .collect::<Vec<_>>();
    let locked = project_with_frontier_id(&project)?;
    let snapshot_hash = prefixed(events::snapshot_hash(&locked));
    let event_log_hash = prefixed(events::event_log_hash(&locked.events));
    let mut latest_payload = serde_json::Value::Null;
    if !proof_path.is_file() {
        issues.push(json!({
            "rule_id": "missing_proof_latest",
            "message": "proof/latest.json is missing.",
        }));
    } else {
        let data = fs::read_to_string(&proof_path)
            .map_err(|e| format!("Failed to read proof/latest.json: {e}"))?;
        latest_payload = serde_json::from_str(&data).map_err(|e| {
            format!(
                "Failed to parse proof/latest.json '{}': {e}",
                proof_path.display()
            )
        })?;
        if latest_payload
            .get("frontier_hash")
            .and_then(|value| value.as_str())
            != Some(snapshot_hash.as_str())
        {
            issues.push(json!({
                "rule_id": "proof_snapshot_mismatch",
                "message": "proof/latest.json frontier_hash does not match replayed frontier state.",
            }));
        }
        if latest_payload
            .get("event_log_hash")
            .and_then(|value| value.as_str())
            != Some(event_log_hash.as_str())
        {
            issues.push(json!({
                "rule_id": "proof_event_log_mismatch",
                "message": "proof/latest.json event_log_hash does not match .vela/events/.",
            }));
        }
    }
    let proof_digest = directory_hash(&path.join("proof"));
    if let Some(lock) = &lock {
        if !lock.proof.digest.is_empty() && lock.proof.digest != proof_digest {
            issues.push(json!({
                "rule_id": "proof_digest_mismatch",
                "message": format!("proof/ digest does not match vela.lock: lock={}, current={proof_digest}", lock.proof.digest),
            }));
        }
    } else {
        issues.push(json!({
            "rule_id": "missing_frontier_lock",
            "message": "vela.lock is missing.",
        }));
    }

    Ok(json!({
        "schema": FRONTIER_PROOF_VERIFY_SCHEMA,
        "ok": issues.is_empty(),
        "path": path.display().to_string(),
        "frontier_id": locked.frontier_id(),
        "snapshot_hash": snapshot_hash,
        "event_log_hash": event_log_hash,
        "proof_digest": proof_digest,
        "proof": latest_payload,
        "issues": issues,
    }))
}

pub fn proof_explain(path: &Path) -> Result<String, String> {
    let project = crate::repo::load_from_path(path)?;
    let report = proof_verify(path)?;
    let ok = report.get("ok").and_then(|value| value.as_bool()) == Some(true);
    let locked = project_with_frontier_id(&project)?;
    let snapshot_hash = prefixed(events::snapshot_hash(&locked));
    let event_log_hash = prefixed(events::event_log_hash(&locked.events));
    let open_proposals = project
        .proposals
        .iter()
        .filter(|proposal| {
            !matches!(
                proposal.status.as_str(),
                "accepted" | "applied" | "rejected"
            )
        })
        .count();
    let status = if ok { "fresh" } else { "stale or invalid" };
    Ok(format!(
        "vela proof explain\n\nFrontier: {}\nFrontier id: {}\nProof status: {status}\nAccepted events: {}\nOpen proposals: {open_proposals}\nSnapshot hash: {snapshot_hash}\nEvent log hash: {event_log_hash}\n\nAuthority: `.vela/events/` is replayed into `frontier.json`.\nVisible proof: `proof/latest.json`, `proof/events.manifest.jsonl`, and `proof/replay.trace.jsonl`.\nLockfile: `vela.lock` binds the event log, reducer, Carina kernel, visible state, and proof digest.\n",
        project.project.name,
        locked.frontier_id(),
        project.events.len(),
    ))
}

fn empty_project(name: &str, description: &str, compiled_at: &str) -> Project {
    Project {
        vela_version: project::VELA_SCHEMA_VERSION.to_string(),
        schema: project::VELA_SCHEMA_URL.to_string(),
        frontier_id: None,
        project: project::ProjectMeta {
            name: name.to_string(),
            description: description.to_string(),
            compiled_at: compiled_at.to_string(),
            compiler: project::VELA_COMPILER_VERSION.to_string(),
            papers_processed: 0,
            errors: 0,
            dependencies: Vec::new(),
        },
        stats: project::ProjectStats::default(),
        findings: Vec::new(),
        sources: Vec::new(),
        evidence_atoms: Vec::new(),
        condition_records: Vec::new(),
        review_events: Vec::new(),
        confidence_updates: Vec::new(),
        events: Vec::new(),
        proposals: Vec::new(),
        proof_state: proposals::ProofState::default(),
        signatures: Vec::new(),
        actors: Vec::new(),
        replications: Vec::new(),
        datasets: Vec::new(),
        code_artifacts: Vec::new(),
        artifacts: Vec::new(),
        predictions: Vec::new(),
        resolutions: Vec::new(),
        peers: Vec::new(),
        negative_results: Vec::new(),
        trajectories: Vec::new(),
        released_diff_packs: Vec::new(),
        verdict_conflicts: Vec::new(),
        contradictions: Vec::new(),
        verifier_attachments: Vec::new(),
        attempts: Vec::new(),
        attempt_resolutions: Vec::new(),
        transfers: Vec::new(),
        endorsements: Vec::new(),
        statement_attestations: Vec::new(),
        anchor_links: Vec::new(),
        attempt_claims: Vec::new(),
        statement_registrations: Vec::new(),
    }
}

fn write_visible_state(path: &Path, project: &Project, generated_at: &str) -> Result<(), String> {
    let visible = project_with_frontier_id(project)?;
    let snapshot_hash = prefixed(events::snapshot_hash(&visible));
    let event_log_hash = prefixed(events::event_log_hash(&visible.events));
    let mut value = serde_json::to_value(&visible)
        .map_err(|e| format!("Failed to prepare frontier.json: {e}"))?;
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "_warning".to_string(),
            serde_json::Value::String(
                "Generated by Vela. Do not edit frontier.json directly; use Vela commands to propose, accept, reject, materialize, and prove frontier state."
                    .to_string(),
            ),
        );
        object.insert(
            "_meta".to_string(),
            json!({
                "schema": "vela.frontier_state_meta.v0.1",
                "generated_at": generated_at,
                "materialized_from": ".vela/events/",
                "proof": "proof/latest.json",
                "lockfile": "vela.lock",
                "events_manifest": "proof/events.manifest.jsonl",
                "replay_trace": "proof/replay.trace.jsonl",
                "snapshot_hash": snapshot_hash,
                "event_log_hash": event_log_hash,
                "carina_kernel": DEFAULT_CARINA_KERNEL,
                "vela_reducer": format!("vela@{}", env!("CARGO_PKG_VERSION")),
            }),
        );
    }
    let json = serde_json::to_string_pretty(&value)
        .map_err(|e| format!("Failed to serialize frontier.json: {e}"))?;
    fs::write(path.join("frontier.json"), json)
        .map_err(|e| format!("Failed to write frontier.json: {e}"))
}

/// v0.59: read the existing frontier.yaml, replace its
/// `dependencies.frontiers_v2` field with the project's live
/// dependencies, and write it back. Preserves every other field
/// the user may have customized (scope.question, maintainers,
/// policies, license). No-op if no manifest exists yet.
fn sync_manifest_deps(path: &Path, deps: &[ProjectDependency]) -> Result<(), String> {
    let manifest_path = path.join("frontier.yaml");
    if !manifest_path.is_file() {
        return Ok(());
    }
    let mut manifest = match read_manifest(path)? {
        Some(m) => m,
        None => return Ok(()),
    };
    manifest.dependencies.frontiers_v2 = deps.to_vec();
    let yaml = serde_yaml::to_string(&manifest)
        .map_err(|e| format!("Failed to serialize frontier.yaml: {e}"))?;
    fs::write(&manifest_path, yaml).map_err(|e| format!("Failed to write frontier.yaml: {e}"))
}

fn write_manifest(path: &Path, project: &Project) -> Result<(), String> {
    let existing = read_manifest(path).ok().flatten();
    let existing_dependencies = existing
        .as_ref()
        .map(|manifest| manifest.dependencies.clone())
        .unwrap_or_default();
    let manifest = FrontierManifest {
        schema: FRONTIER_MANIFEST_SCHEMA.to_string(),
        layout: FRONTIER_REPO_LAYOUT.to_string(),
        mode: "split".to_string(),
        frontier_id: Some(project.frontier_id()),
        name: project.project.name.clone(),
        description: existing
            .as_ref()
            .map(|manifest| manifest.description.clone())
            .unwrap_or_else(|| project.project.description.clone()),
        visibility: "public".to_string(),
        scope: existing
            .as_ref()
            .map(|manifest| manifest.scope.clone())
            .unwrap_or_else(|| FrontierScope {
                question: project.project.description.clone(),
                includes: Vec::new(),
                excludes: Vec::new(),
            }),
        carina: CarinaManifest {
            kernel: DEFAULT_CARINA_KERNEL.to_string(),
        },
        vela: VelaManifest {
            reducer: format!("vela@{}", env!("CARGO_PKG_VERSION")),
        },
        paths: FrontierPaths {
            state: "frontier.json".to_string(),
            sources: "sources/".to_string(),
            artifacts: "artifacts/".to_string(),
            review: "review/".to_string(),
            proof: "proof/".to_string(),
            exports: "exports/".to_string(),
        },
        maintainers: existing
            .as_ref()
            .map(|manifest| manifest.maintainers.clone())
            .unwrap_or_default(),
        policies: existing
            .as_ref()
            .map(|manifest| manifest.policies.clone())
            .unwrap_or_default(),
        license: existing
            .as_ref()
            .map(|manifest| manifest.license.clone())
            .unwrap_or_default(),
        dependencies: ManifestDependencies {
            frontiers: existing_dependencies.frontiers,
            packages: existing_dependencies.packages,
            adapters: existing_dependencies.adapters,
            frontiers_v2: project.project.dependencies.clone(),
        },
        templates: existing
            .as_ref()
            .map(|manifest| manifest.templates.clone())
            .unwrap_or_default(),
    };
    let yaml = serde_yaml::to_string(&manifest)
        .map_err(|e| format!("Failed to serialize frontier.yaml: {e}"))?;
    fs::write(path.join("frontier.yaml"), yaml)
        .map_err(|e| format!("Failed to write frontier.yaml: {e}"))
}

fn write_lock(
    path: &Path,
    project: &Project,
    proof: &ProofWrite,
    generated_at: &str,
) -> Result<FrontierLock, String> {
    let locked = project_with_frontier_id(project)?;
    let reducer_package = format!("vela@{}", env!("CARGO_PKG_VERSION"));
    let lock = FrontierLock {
        schema: FRONTIER_LOCK_SCHEMA.to_string(),
        generated_at: generated_at.to_string(),
        vela_version: env!("CARGO_PKG_VERSION").to_string(),
        carina_kernel: DEFAULT_CARINA_KERNEL.to_string(),
        frontier_id: locked.frontier_id(),
        canonicalization: LockCanonicalization::default(),
        reducer: LockPackage {
            package: reducer_package.clone(),
            digest: identity_digest(&reducer_package),
        },
        carina: LockKernel {
            kernel: DEFAULT_CARINA_KERNEL.to_string(),
            digest: identity_digest(DEFAULT_CARINA_KERNEL),
        },
        snapshot_hash: prefixed(events::snapshot_hash(&locked)),
        event_log_hash: prefixed(events::event_log_hash(&locked.events)),
        proposal_state_hash: proposal_state_hash(&locked.proposals),
        sources_hash: directory_hash(&path.join("sources")),
        artifacts_hash: directory_hash(&path.join("artifacts")),
        review_hash: directory_hash(&path.join("review")),
        proof_freshness: proof.freshness.clone(),
        proof: LockProof {
            latest: proof.latest.clone(),
            digest: proof.digest.clone(),
            freshness: proof.freshness.clone(),
            events_manifest: proof.events_manifest.clone(),
            replay_trace: proof.replay_trace.clone(),
        },
        paths: LockPaths {
            frontier: "frontier.json".to_string(),
            events: ".vela/events/".to_string(),
        },
        // v0.109: surface every cross-frontier dependency the
        // project declares, in deterministic source order, so the
        // lockfile alone witnesses what state the parent committed
        // to. Pre-v0.109 these pins lived only in `frontier.yaml`
        // and were absent from the lock; v0.109 mirrors them.
        dependencies: locked
            .project
            .dependencies
            .iter()
            .map(|d| LockedDependency {
                name: d.name.clone(),
                source: d.source.clone(),
                vfr_id: d.vfr_id.clone(),
                locator: d.locator.clone(),
                pinned_snapshot_hash: d.pinned_snapshot_hash.clone(),
            })
            .collect(),
    };
    let yaml =
        serde_yaml::to_string(&lock).map_err(|e| format!("Failed to serialize vela.lock: {e}"))?;
    fs::write(path.join("vela.lock"), yaml)
        .map_err(|e| format!("Failed to write vela.lock: {e}"))?;
    Ok(lock)
}

fn materialization_generated_at(path: &Path, project: &Project) -> String {
    let now = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    let Ok(Some(lock)) = read_lock(path) else {
        return now;
    };
    if lock.generated_at.trim().is_empty() {
        return now;
    }
    let Ok(locked) = project_with_frontier_id(project) else {
        return now;
    };
    let reducer_package = format!("vela@{}", env!("CARGO_PKG_VERSION"));
    let current = [
        (
            lock.snapshot_hash.as_str(),
            prefixed(events::snapshot_hash(&locked)),
        ),
        (
            lock.event_log_hash.as_str(),
            prefixed(events::event_log_hash(&locked.events)),
        ),
        (
            lock.proposal_state_hash.as_str(),
            proposal_state_hash(&locked.proposals),
        ),
        (
            lock.sources_hash.as_str(),
            directory_hash(&path.join("sources")),
        ),
        (
            lock.artifacts_hash.as_str(),
            directory_hash(&path.join("artifacts")),
        ),
        (
            lock.review_hash.as_str(),
            directory_hash(&path.join("review")),
        ),
    ];
    let hashes_match = current.iter().all(|(locked, current)| *locked == current);
    let versions_match = lock.vela_version == env!("CARGO_PKG_VERSION")
        && lock.carina_kernel == DEFAULT_CARINA_KERNEL
        && lock.reducer.package == reducer_package
        && lock.carina.kernel == DEFAULT_CARINA_KERNEL;
    if hashes_match && versions_match && lock.proof_freshness == "fresh" {
        lock.generated_at
    } else {
        now
    }
}

fn project_with_frontier_id(project: &Project) -> Result<Project, String> {
    let frontier_id = project.frontier_id();
    let mut value = serde_json::to_value(project)
        .map_err(|e| format!("Failed to prepare frontier state: {e}"))?;
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "frontier_id".to_string(),
            serde_json::Value::String(frontier_id),
        );
    }
    serde_json::from_value(value).map_err(|e| format!("Failed to normalize frontier state: {e}"))
}

fn write_frontier_card(path: &Path, name: &str, template: &str) -> Result<(), String> {
    let text = format!(
        "# {name}\n\nThis is a Vela frontier repository.\n\n- State entrypoint: `frontier.json`\n- Manifest: `frontier.yaml`\n- Lockfile: `vela.lock`\n- Template: `{template}`\n\nRun:\n\n```bash\nvela check . --strict --json\nvela integrity . --json\nvela proof . --out proof/latest\n```\n"
    );
    fs::write(path.join("README.md"), text).map_err(|e| format!("Failed to write README.md: {e}"))
}

fn write_scope(path: &Path, name: &str) -> Result<(), String> {
    let text = format!(
        "# Scope\n\nFrontier: {name}\n\nThis file records boundaries, exclusions, caveats, and review policy for the frontier.\n\nExternal artifacts and agent outputs are source material until reviewed into accepted Vela events.\n"
    );
    fs::write(path.join("SCOPE.md"), text).map_err(|e| format!("Failed to write SCOPE.md: {e}"))
}

fn write_section_readmes(path: &Path) -> Result<(), String> {
    let sections = BTreeMap::from([
        (
            "sources",
            "Source manifests, papers, datasets, registries, and protocols.",
        ),
        (
            "artifacts",
            "Packets, runs, code, notebooks, data pointers, tables, and figures.",
        ),
        (
            "review",
            "Proposal queues, decisions, caveats, rejected records, and audits.",
        ),
        ("proof", "Proof packets, traces, and freshness records."),
        (
            "exports",
            "Generated hub, RO-Crate, Frictionless, MCP, and report bundles.",
        ),
    ]);
    for (dir, description) in sections {
        let section = path.join(dir);
        fs::create_dir_all(&section).map_err(|e| format!("Failed to create {dir}/: {e}"))?;
        let readme = section.join("README.md");
        if !readme.exists() {
            fs::write(readme, format!("# {dir}\n\n{description}\n"))
                .map_err(|e| format!("Failed to write {dir}/README.md: {e}"))?;
        }
    }
    let artifact_sections = BTreeMap::from([
        ("artifacts/packets", "Import, review, and proof packets."),
        (
            "artifacts/runs",
            "Agent, source-adapter, computational, and lab run records.",
        ),
        (
            "artifacts/code",
            "Analysis, extraction, and validation code.",
        ),
        ("artifacts/notebooks", "Exploratory and report notebooks."),
        (
            "artifacts/data",
            "Small data files, data pointers, and external-data metadata.",
        ),
        (
            "artifacts/notes",
            "Reading notes, decision notes, meeting notes, and scratch context.",
        ),
        (
            "artifacts/tables",
            "Generated tables and tabular review outputs.",
        ),
        ("artifacts/figures", "Generated figures and visual outputs."),
        (
            "artifacts/analyses",
            "Analysis outputs and state-transition examples.",
        ),
        (
            "artifacts/environments",
            "Execution context pointers: containers, lockfiles, hardware, cloud runtimes, and lab instruments.",
        ),
    ]);
    for (dir, description) in artifact_sections {
        let section = path.join(dir);
        fs::create_dir_all(&section).map_err(|e| format!("Failed to create {dir}/: {e}"))?;
        let readme = section.join("README.md");
        if !readme.exists() {
            let title = dir.rsplit('/').next().unwrap_or(dir);
            fs::write(readme, format!("# {title}\n\n{description}\n"))
                .map_err(|e| format!("Failed to write {dir}/README.md: {e}"))?;
        }
    }
    let proof_sections = BTreeMap::from([
        (
            "proof/signatures",
            "Optional signatures for proof packets, events, lockfiles, or institutional attestations.",
        ),
        (
            "proof/attestations",
            "Optional external proof attestations. Vela events remain the state authority.",
        ),
    ]);
    for (dir, description) in proof_sections {
        let section = path.join(dir);
        fs::create_dir_all(&section).map_err(|e| format!("Failed to create {dir}/: {e}"))?;
        let readme = section.join("README.md");
        if !readme.exists() {
            let title = dir.rsplit('/').next().unwrap_or(dir);
            fs::write(readme, format!("# {title}\n\n{description}\n"))
                .map_err(|e| format!("Failed to write {dir}/README.md: {e}"))?;
        }
    }
    let export_sections = BTreeMap::from([
        ("exports/prov", "Generated W3C PROV exports."),
        ("exports/ro-crate", "Generated RO-Crate exports."),
        (
            "exports/frictionless",
            "Generated Frictionless Data Package exports.",
        ),
        ("exports/mcp", "Generated MCP-serving export bundles."),
        (
            "exports/report",
            "Generated reviewer, funder, or release reports.",
        ),
        (
            "exports/registry",
            "Generated registry and federation bundles.",
        ),
    ]);
    for (dir, description) in export_sections {
        let section = path.join(dir);
        fs::create_dir_all(&section).map_err(|e| format!("Failed to create {dir}/: {e}"))?;
        let readme = section.join("README.md");
        if !readme.exists() {
            let title = dir.rsplit('/').next().unwrap_or(dir);
            fs::write(readme, format!("# {title}\n\n{description}\n"))
                .map_err(|e| format!("Failed to write {dir}/README.md: {e}"))?;
        }
    }
    Ok(())
}

fn write_proof(path: &Path, project: &Project, generated_at: &str) -> Result<ProofWrite, String> {
    let locked = project_with_frontier_id(project)?;
    let proof_dir = path.join("proof");
    fs::create_dir_all(&proof_dir).map_err(|e| format!("Failed to create proof/: {e}"))?;

    // Freshness skip (safe, deterministic): the proof packet is a pure function
    // of (event log, reducer version). If the recorded proof already pins this
    // exact event log and reducer, regenerating is byte-identical work — so skip
    // the O(N^2) manifest/trace rebuild (the cumulative per-event hash makes a
    // full rebuild quadratic in event count: the bbb-flagship 22s wall). Proof
    // freshness is defined by event_log_hash (see state_integrity::proof_freshness),
    // so gating on it matches the system's own freshness contract. The first
    // materialize after a real change still regenerates in full.
    let event_log_hash = prefixed(events::event_log_hash(&locked.events));
    let snapshot_hash = prefixed(events::snapshot_hash(&locked));
    if proof_is_current(&proof_dir, &event_log_hash, &snapshot_hash) {
        return Ok(ProofWrite {
            digest: directory_hash(&proof_dir),
            freshness: "fresh".to_string(),
            latest: "proof/latest.json".to_string(),
            events_manifest: "proof/events.manifest.jsonl".to_string(),
            replay_trace: "proof/replay.trace.jsonl".to_string(),
        });
    }
    let proposal_state_hash = proposal_state_hash(&locked.proposals);
    let reducer_package = format!("vela@{}", env!("CARGO_PKG_VERSION"));

    let latest = json!({
        "schema": "vela.frontier_repo_proof.v0.1",
        "frontier_id": locked.frontier_id(),
        "frontier_hash": snapshot_hash,
        "event_log_hash": event_log_hash,
        "proposal_state_hash": proposal_state_hash,
        "reducer": {
            "name": "vela",
            "version": env!("CARGO_PKG_VERSION"),
            "package": reducer_package,
            "digest": identity_digest(&format!("vela@{}", env!("CARGO_PKG_VERSION"))),
        },
        "carina": {
            "kernel": DEFAULT_CARINA_KERNEL,
            "digest": identity_digest(DEFAULT_CARINA_KERNEL),
        },
        "materialized_at": generated_at,
        "freshness": "fresh",
        "event_count": locked.events.len(),
        "paths": {
            "frontier": "frontier.json",
            "lockfile": "vela.lock",
            "events_authority": ".vela/events/",
            "events_manifest": "proof/events.manifest.jsonl",
            "replay_trace": "proof/replay.trace.jsonl"
        },
        "warning": "Do not edit frontier.json directly. Use Vela commands to propose, accept, reject, materialize, and prove frontier state."
    });
    fs::write(
        proof_dir.join("latest.json"),
        serde_json::to_string_pretty(&latest)
            .map_err(|e| format!("Failed to serialize proof/latest.json: {e}"))?,
    )
    .map_err(|e| format!("Failed to write proof/latest.json: {e}"))?;

    let mut manifest_lines = String::new();
    let mut trace_lines = String::new();
    // O(N) cumulative checkpoint chain: h_i = sha256(h_{i-1} || event_hash_i),
    // computed from the already-hashed event in O(1) per step. The previous
    // formulation recomputed event_log_hash over the whole [0..=idx] prefix each
    // step, which is O(N^2) and was the bbb-flagship 22s materialize wall. This
    // field is diagnostic (never verified against the canonical event_log_hash —
    // grep confirms nothing reads it), so a running chain is the correct O(N)
    // replacement. Schema bumped to v0.2 to mark the changed value semantics.
    let mut chained_log_hash = String::new();
    for (idx, event) in locked.events.iter().enumerate() {
        let event_hash = prefixed(event_hash(event));
        let entry = json!({
            "schema": "vela.proof_event_manifest_entry.v0.1",
            "index": idx + 1,
            "id": event.id,
            "kind": event.kind,
            "target": event.target,
            "actor": event.actor,
            "timestamp": event.timestamp,
            "event_hash": event_hash,
            "before_hash": event.before_hash,
            "after_hash": event.after_hash,
            "caveat_count": event.caveats.len(),
        });
        manifest_lines.push_str(
            &serde_json::to_string(&entry)
                .map_err(|e| format!("Failed to serialize event manifest entry: {e}"))?,
        );
        manifest_lines.push('\n');

        chained_log_hash = hex::encode(Sha256::digest(
            format!("{chained_log_hash}{event_hash}").as_bytes(),
        ));
        let trace = json!({
            "schema": "vela.replay_trace_entry.v0.2",
            "step": idx + 1,
            "event": event.id,
            "kind": event.kind,
            "event_hash": event_hash,
            "event_log_hash_after": prefixed(chained_log_hash.clone()),
            "target_after_hash": event.after_hash,
        });
        trace_lines.push_str(
            &serde_json::to_string(&trace)
                .map_err(|e| format!("Failed to serialize replay trace entry: {e}"))?,
        );
        trace_lines.push('\n');
    }
    fs::write(proof_dir.join("events.manifest.jsonl"), manifest_lines)
        .map_err(|e| format!("Failed to write proof/events.manifest.jsonl: {e}"))?;
    fs::write(proof_dir.join("replay.trace.jsonl"), trace_lines)
        .map_err(|e| format!("Failed to write proof/replay.trace.jsonl: {e}"))?;

    fs::write(
        proof_dir.join("freshness.md"),
        format!(
            "# Freshness\n\nCurrent proof status: fresh\n\n`frontier.json` was materialized from `.vela/events/` at {generated_at}.\n\nAccepted events: {}\nEvent log hash: `{event_log_hash}`\nSnapshot hash: `{snapshot_hash}`\n\nRun:\n\n```bash\nvela check . --strict --json\nvela integrity . --json\n```\n",
            locked.events.len()
        ),
    )
    .map_err(|e| format!("Failed to write proof/freshness.md: {e}"))?;

    let hashes = json!({
        "schema": "vela.frontier_repo_hashes.v0.1",
        "frontier_id": locked.frontier_id(),
        "snapshot_hash": snapshot_hash,
        "event_log_hash": event_log_hash,
        "proposal_state_hash": proposal_state_hash,
        "sources_hash": directory_hash(&path.join("sources")),
        "artifacts_hash": directory_hash(&path.join("artifacts")),
        "review_hash": directory_hash(&path.join("review")),
    });
    fs::write(
        proof_dir.join("hashes.json"),
        serde_json::to_string_pretty(&hashes)
            .map_err(|e| format!("Failed to serialize proof/hashes.json: {e}"))?,
    )
    .map_err(|e| format!("Failed to write proof/hashes.json: {e}"))?;

    Ok(ProofWrite {
        digest: directory_hash(&proof_dir),
        freshness: "fresh".to_string(),
        latest: "proof/latest.json".to_string(),
        events_manifest: "proof/events.manifest.jsonl".to_string(),
        replay_trace: "proof/replay.trace.jsonl".to_string(),
    })
}

/// True when the recorded proof packet already pins this exact event log and
/// reducer version (and its files exist) — so regeneration would be a byte-for-byte
/// no-op and can be skipped. Reads only `proof/latest.json` (O(1)); the event-log
/// hash is computed once by the caller (O(N), not O(N^2)).
fn proof_is_current(proof_dir: &Path, event_log_hash: &str, snapshot_hash: &str) -> bool {
    let Ok(text) = fs::read_to_string(proof_dir.join("latest.json")) else {
        return false;
    };
    let Ok(latest) = serde_json::from_str::<serde_json::Value>(&text) else {
        return false;
    };
    let same_log = latest.get("event_log_hash").and_then(|v| v.as_str()) == Some(event_log_hash);
    let same_snapshot = latest.get("frontier_hash").and_then(|v| v.as_str()) == Some(snapshot_hash);
    let same_reducer = latest.pointer("/reducer/version").and_then(|v| v.as_str())
        == Some(env!("CARGO_PKG_VERSION"));
    same_log
        && same_snapshot
        && same_reducer
        && proof_dir.join("events.manifest.jsonl").is_file()
        && proof_dir.join("replay.trace.jsonl").is_file()
        && proof_dir.join("hashes.json").is_file()
}

fn proposal_state_hash(proposals: &[crate::proposals::StateProposal]) -> String {
    let bytes = crate::canonical::to_canonical_bytes(proposals).unwrap_or_default();
    prefixed(hex::encode(Sha256::digest(bytes)))
}

fn directory_hash(path: &Path) -> String {
    let mut entries = Vec::new();
    if path.is_dir() {
        collect_file_entries(path, path, &mut entries);
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let bytes = crate::canonical::to_canonical_bytes(&entries).unwrap_or_default();
    prefixed(hex::encode(Sha256::digest(bytes)))
}

fn collect_file_entries(root: &Path, path: &Path, entries: &mut Vec<(String, String)>) {
    let Ok(read_dir) = fs::read_dir(path) else {
        return;
    };
    for entry in read_dir.flatten() {
        let entry_path = entry.path();
        let Some(name) = entry_path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if name == ".DS_Store" {
            continue;
        }
        if entry_path.is_dir() {
            collect_file_entries(root, &entry_path, entries);
        } else if entry_path.is_file() {
            let rel = entry_path
                .strip_prefix(root)
                .unwrap_or(&entry_path)
                .to_string_lossy()
                .replace('\\', "/");
            let digest = fs::read(&entry_path)
                .map(|bytes| prefixed(hex::encode(Sha256::digest(bytes))))
                .unwrap_or_else(|_| "sha256:unreadable".to_string());
            entries.push((rel, digest));
        }
    }
}

fn event_hash(event: &crate::events::StateEvent) -> String {
    let bytes = crate::canonical::to_canonical_bytes(event).unwrap_or_default();
    hex::encode(Sha256::digest(bytes))
}

fn identity_digest(value: &str) -> String {
    prefixed(hex::encode(Sha256::digest(value.as_bytes())))
}

fn prefixed(hash: String) -> String {
    if hash.starts_with("sha256:") {
        hash
    } else {
        format!("sha256:{hash}")
    }
}

fn issue(rule_id: &str, message: impl Into<String>) -> RepoLayoutIssue {
    RepoLayoutIssue {
        rule_id: rule_id.to_string(),
        message: message.into(),
    }
}

fn default_split_mode() -> String {
    "split".to_string()
}

fn default_visibility() -> String {
    "public".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_current_requires_matching_snapshot_hash() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let proof_dir = tmp.path();
        fs::write(
            proof_dir.join("latest.json"),
            serde_json::to_string_pretty(&json!({
                "event_log_hash": "sha256:event-log",
                "frontier_hash": "sha256:old-snapshot",
                "reducer": {
                    "version": env!("CARGO_PKG_VERSION")
                }
            }))
            .expect("serialize proof latest"),
        )
        .expect("write proof latest");
        fs::write(proof_dir.join("events.manifest.jsonl"), "").expect("write events manifest");
        fs::write(proof_dir.join("replay.trace.jsonl"), "").expect("write replay trace");
        fs::write(proof_dir.join("hashes.json"), "{}").expect("write hashes");

        assert!(!proof_is_current(
            proof_dir,
            "sha256:event-log",
            "sha256:new-snapshot"
        ));
    }
}
