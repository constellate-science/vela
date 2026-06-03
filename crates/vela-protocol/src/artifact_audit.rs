//! Artifact proof-readiness checks for frontier-owned files and pointers.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::bundle::Artifact;
use crate::project::Project;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactAudit {
    pub ok: bool,
    pub command: String,
    pub frontier: String,
    pub artifact_count: usize,
    pub checked_local_blobs: usize,
    pub local_blob_bytes: u64,
    pub by_kind: BTreeMap<String, usize>,
    pub by_storage_mode: BTreeMap<String, usize>,
    pub issue_count: usize,
    pub issues: Vec<ArtifactAuditIssue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactAuditIssue {
    pub id: String,
    pub field: String,
    pub message: String,
}

pub fn audit_artifacts(source: &Path, project: &Project) -> ArtifactAudit {
    let root = artifact_root(source);
    let finding_ids = project
        .findings
        .iter()
        .map(|finding| finding.id.as_str())
        .collect::<HashSet<_>>();
    let mut issues = Vec::new();
    let mut by_kind = BTreeMap::new();
    let mut by_storage_mode = BTreeMap::new();
    let mut checked_local_blobs = 0usize;
    let mut local_blob_bytes = 0u64;

    for artifact in &project.artifacts {
        *by_kind.entry(artifact.kind.clone()).or_insert(0) += 1;
        *by_storage_mode
            .entry(artifact.storage_mode.clone())
            .or_insert(0) += 1;
        audit_artifact_shape(artifact, &finding_ids, &mut issues);
        if matches!(artifact.storage_mode.as_str(), "local_blob" | "local_file") {
            if let Some(root) = root.as_deref() {
                if let Some((checked, bytes)) = audit_local_blob(root, artifact, &mut issues) {
                    checked_local_blobs += usize::from(checked);
                    local_blob_bytes += bytes;
                }
            } else {
                push_issue(
                    &mut issues,
                    &artifact.id,
                    "locator",
                    "local artifact cannot be checked without a frontier directory",
                );
            }
        }
    }

    ArtifactAudit {
        ok: issues.is_empty(),
        command: "artifact-audit".to_string(),
        frontier: source.display().to_string(),
        artifact_count: project.artifacts.len(),
        checked_local_blobs,
        local_blob_bytes,
        by_kind,
        by_storage_mode,
        issue_count: issues.len(),
        issues,
    }
}

fn audit_artifact_shape(
    artifact: &Artifact,
    finding_ids: &HashSet<&str>,
    issues: &mut Vec<ArtifactAuditIssue>,
) {
    if !artifact.id.starts_with("va_") {
        push_issue(
            issues,
            &artifact.id,
            "id",
            "artifact id must start with va_",
        );
    }
    if !is_sha256(&artifact.content_hash) {
        push_issue(
            issues,
            &artifact.id,
            "content_hash",
            "content_hash must be sha256:<64 lowercase hex>",
        );
    }
    if artifact.license.as_deref().unwrap_or("").trim().is_empty()
        && artifact
            .provenance
            .license
            .as_deref()
            .unwrap_or("")
            .trim()
            .is_empty()
    {
        push_issue(
            issues,
            &artifact.id,
            "license",
            "artifact must declare license or access terms",
        );
    }
    if artifact.target_findings.is_empty() {
        push_issue(
            issues,
            &artifact.id,
            "target_findings",
            "artifact must target at least one finding",
        );
    }
    for finding_id in &artifact.target_findings {
        if !finding_ids.contains(finding_id.as_str()) {
            push_issue(
                issues,
                &artifact.id,
                "target_findings",
                format!("unknown finding id: {finding_id}"),
            );
        }
    }
    if matches!(artifact.storage_mode.as_str(), "remote" | "pointer")
        && artifact.locator.is_none()
        && artifact.source_url.is_none()
    {
        push_issue(
            issues,
            &artifact.id,
            "locator",
            "remote or pointer artifact must have locator or source_url",
        );
    }
    for (field, value) in [
        ("source_url", artifact.source_url.as_deref()),
        ("provenance.url", artifact.provenance.url.as_deref()),
    ] {
        if let Some(url) = value
            && !is_http_url(url)
        {
            push_issue(
                issues,
                &artifact.id,
                field,
                format!("{field} must be http(s): {url}"),
            );
        }
    }
    audit_profile_fields(artifact, issues);
}

fn audit_profile_fields(artifact: &Artifact, issues: &mut Vec<ArtifactAuditIssue>) {
    match artifact.kind.as_str() {
        "clinical_trial_record" => {
            let has_nct = metadata_string(artifact, "nct_id")
                .or_else(|| metadata_string(artifact, "nct"))
                .is_some()
                || metadata_array_contains_nct(artifact, "nct_ids")
                || artifact
                    .source_url
                    .as_deref()
                    .or(artifact.locator.as_deref())
                    .is_some_and(contains_nct_id);
            if !has_nct {
                push_issue(
                    issues,
                    &artifact.id,
                    "metadata.nct_id",
                    "clinical trial artifacts must carry or point to an NCT id",
                );
            }
        }
        "dataset" => {
            let has_dataset_id = ["accession", "dataset_id", "repository", "registry"]
                .iter()
                .any(|key| metadata_string(artifact, key).is_some());
            if !has_dataset_id && artifact.source_url.is_none() && artifact.locator.is_none() {
                push_issue(
                    issues,
                    &artifact.id,
                    "metadata",
                    "dataset artifacts must carry an accession, repository, locator, or source_url",
                );
            }
        }
        "code" => {
            let has_commit = metadata_string(artifact, "commit").is_some();
            let has_pinned_blob =
                matches!(artifact.storage_mode.as_str(), "local_blob" | "local_file")
                    && is_sha256(&artifact.content_hash);
            if !has_commit && !has_pinned_blob {
                push_issue(
                    issues,
                    &artifact.id,
                    "metadata.commit",
                    "remote code artifacts should pin a commit, release tag, or equivalent version",
                );
            }
        }
        "registry_record" => {
            if artifact.source_url.is_none()
                && artifact.locator.is_none()
                && artifact.provenance.url.is_none()
            {
                push_issue(
                    issues,
                    &artifact.id,
                    "source_url",
                    "registry records must point to an upstream registry page",
                );
            }
        }
        _ => {}
    }
}

fn audit_local_blob(
    root: &Path,
    artifact: &Artifact,
    issues: &mut Vec<ArtifactAuditIssue>,
) -> Option<(bool, u64)> {
    let Some(locator) = artifact.locator.as_deref() else {
        push_issue(
            issues,
            &artifact.id,
            "locator",
            "local artifact must have a locator",
        );
        return None;
    };
    let blob_path = resolve_locator(root, locator);
    let Ok(bytes) = fs::read(&blob_path) else {
        push_issue(
            issues,
            &artifact.id,
            "locator",
            format!("local blob not found: {locator}"),
        );
        return None;
    };
    if is_sha256(&artifact.content_hash) {
        let actual = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
        if actual != artifact.content_hash {
            push_issue(
                issues,
                &artifact.id,
                "content_hash",
                format!("local blob hash mismatch: {actual}"),
            );
        }
    }
    if let Some(expected_size) = artifact.size_bytes
        && expected_size != bytes.len() as u64
    {
        push_issue(
            issues,
            &artifact.id,
            "size_bytes",
            format!("expected {expected_size}, found {}", bytes.len()),
        );
    }
    Some((true, bytes.len() as u64))
}

fn artifact_root(source: &Path) -> Option<PathBuf> {
    if source.is_dir() {
        return Some(source.to_path_buf());
    }
    source.parent().map(Path::to_path_buf)
}

fn resolve_locator(root: &Path, locator: &str) -> PathBuf {
    let path = Path::new(locator);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    }
}

fn is_sha256(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn is_http_url(value: &str) -> bool {
    value.starts_with("https://") || value.starts_with("http://")
}

fn contains_nct_id(value: &str) -> bool {
    value
        .as_bytes()
        .windows(11)
        .any(|window| window.starts_with(b"NCT") && window[3..].iter().all(u8::is_ascii_digit))
}

fn metadata_string<'a>(artifact: &'a Artifact, key: &str) -> Option<&'a str> {
    artifact
        .metadata
        .get(key)
        .and_then(serde_json::Value::as_str)
}

fn metadata_array_contains_nct(artifact: &Artifact, key: &str) -> bool {
    artifact
        .metadata
        .get(key)
        .and_then(serde_json::Value::as_array)
        .is_some_and(|items| {
            items
                .iter()
                .filter_map(serde_json::Value::as_str)
                .any(contains_nct_id)
        })
}

fn push_issue(
    issues: &mut Vec<ArtifactAuditIssue>,
    id: &str,
    field: impl Into<String>,
    message: impl Into<String>,
) {
    issues.push(ArtifactAuditIssue {
        id: id.to_string(),
        field: field.into(),
        message: message.into(),
    });
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;

    use serde_json::json;

    use super::*;
    use crate::access_tier::AccessTier;
    use crate::bundle::{
        Assertion, Conditions, Confidence, Evidence, Extraction, Flags, Provenance,
    };
    use crate::project;

    #[test]
    fn local_blob_hash_and_size_are_checked() {
        let dir = tempfile::tempdir().expect("tempdir");
        let blob_dir = dir.path().join(".vela/artifact-blobs/sha256");
        fs::create_dir_all(&blob_dir).expect("blob dir");
        let bytes = b"{\"ok\":true}\n";
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(bytes)));
        let hex = digest.trim_start_matches("sha256:").to_string();
        fs::write(blob_dir.join(&hex), bytes).expect("write blob");

        let mut project = project_with_one_finding();
        let target = project.findings[0].id.clone();
        project.artifacts.push(
            Artifact::new(
                "clinical_trial_record",
                "CLARITY AD registry record",
                digest,
                Some(bytes.len() as u64),
                Some("application/json".to_string()),
                "local_blob",
                Some(format!(".vela/artifact-blobs/sha256/{hex}")),
                Some("https://clinicaltrials.gov/study/NCT03887455".to_string()),
                Some("ClinicalTrials.gov public record".to_string()),
                vec![target],
                Provenance {
                    source_type: "database_record".to_string(),
                    doi: None,
                    pmid: None,
                    pmc: None,
                    openalex_id: None,
                    title: "ClinicalTrials.gov NCT03887455".to_string(),
                    authors: vec![],
                    year: None,
                    journal: None,
                    url: Some("https://clinicaltrials.gov/study/NCT03887455".to_string()),
                    license: Some("ClinicalTrials.gov public record".to_string()),
                    publisher: None,
                    funders: vec![],
                    extraction: test_extraction(),
                    review: None,
                    citation_count: None,
                },
                BTreeMap::from([("nct_id".to_string(), json!("NCT03887455"))]),
                AccessTier::Public,
            )
            .expect("artifact"),
        );

        let audit = audit_artifacts(dir.path(), &project);
        assert!(audit.ok, "{:?}", audit.issues);
        assert_eq!(audit.checked_local_blobs, 1);
        assert_eq!(audit.local_blob_bytes, bytes.len() as u64);
    }

    #[test]
    fn missing_profile_fields_are_reported() {
        let mut project = project_with_one_finding();
        let target = project.findings[0].id.clone();
        project.artifacts.push(
            Artifact::new(
                "code",
                "unpinned analysis repository",
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                None,
                None,
                "pointer",
                Some("https://github.com/example/analysis".to_string()),
                Some("https://github.com/example/analysis".to_string()),
                Some("MIT".to_string()),
                vec![target],
                Provenance {
                    source_type: "database_record".to_string(),
                    doi: None,
                    pmid: None,
                    pmc: None,
                    openalex_id: None,
                    title: "analysis repository".to_string(),
                    authors: vec![],
                    year: None,
                    journal: None,
                    url: Some("https://github.com/example/analysis".to_string()),
                    license: Some("MIT".to_string()),
                    publisher: None,
                    funders: vec![],
                    extraction: test_extraction(),
                    review: None,
                    citation_count: None,
                },
                BTreeMap::new(),
                AccessTier::Public,
            )
            .expect("artifact"),
        );

        let audit = audit_artifacts(Path::new("."), &project);
        assert!(!audit.ok);
        assert!(
            audit
                .issues
                .iter()
                .any(|issue| issue.field == "metadata.commit")
        );
    }

    fn project_with_one_finding() -> Project {
        let finding = crate::bundle::FindingBundle::new(
            Assertion {
                text: "Lecanemab trial records belong in the frontier.".to_string(),
                assertion_type: "treatment_effect".to_string(),
                entities: vec![],
                relation: Some("has_registry_record".to_string()),
                direction: None,
                causal_claim: None,
                causal_evidence_grade: None,
            },
            Evidence {
                evidence_type: "observational".to_string(),
                model_system: "registry".to_string(),
                species: Some("Homo sapiens".to_string()),
                method: "manual test".to_string(),
                sample_size: None,
                effect_size: None,
                p_value: None,
                replicated: false,
                replication_count: None,
                evidence_spans: vec![],
            },
            test_conditions(),
            Confidence::raw(0.6, "test", 0.6),
            Provenance {
                source_type: "database_record".to_string(),
                doi: None,
                pmid: None,
                pmc: None,
                openalex_id: None,
                url: None,
                title: "test".to_string(),
                authors: vec![],
                year: None,
                journal: None,
                license: Some("test".to_string()),
                publisher: None,
                funders: vec![],
                extraction: test_extraction(),
                review: None,
                citation_count: None,
            },
            Flags::default(),
        );
        project::assemble("artifact audit test", vec![finding], 1, 0, "test")
    }

    fn test_conditions() -> Conditions {
        Conditions {
            text: "test condition".to_string(),
            species_verified: vec!["Homo sapiens".to_string()],
            species_unverified: vec![],
            in_vitro: false,
            in_vivo: false,
            human_data: true,
            clinical_trial: true,
            concentration_range: None,
            duration: None,
            age_group: None,
            cell_type: None,
        }
    }

    fn test_extraction() -> Extraction {
        Extraction {
            method: "manual".to_string(),
            model: None,
            model_version: None,
            extracted_at: "2026-05-06T00:00:00Z".to_string(),
            extractor_version: "test".to_string(),
        }
    }
}
