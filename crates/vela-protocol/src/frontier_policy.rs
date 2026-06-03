//! Frontier-owned policy files.
//!
//! Policy guides local review and validation. It is not evidence and it does
//! not mutate frontier state by itself.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::{canonical, repo};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDocumentKind {
    Evidence,
    Review,
    Confidence,
    Agent,
}

impl PolicyDocumentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Evidence => "evidence",
            Self::Review => "review",
            Self::Confidence => "confidence",
            Self::Agent => "agent",
        }
    }

    pub fn filename(self) -> &'static str {
        match self {
            Self::Evidence => "evidence_policy.md",
            Self::Review => "review_policy.md",
            Self::Confidence => "confidence_policy.md",
            Self::Agent => "agent_policy.md",
        }
    }

    fn all() -> [Self; 4] {
        [Self::Evidence, Self::Review, Self::Confidence, Self::Agent]
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyDocumentSummary {
    pub kind: PolicyDocumentKind,
    pub path: String,
    pub title: String,
    pub body_sha256: String,
    pub bytes: usize,
    pub declared_in_manifest: bool,
    #[serde(default)]
    pub front_matter: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FrontierPolicySummary {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frontier_id: Option<String>,
    pub frontier_path: String,
    #[serde(default)]
    pub documents: Vec<PolicyDocumentSummary>,
    #[serde(default)]
    pub missing_required: Vec<String>,
    pub defaults_used: bool,
    pub canonical_json_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperationReviewRequirement {
    pub review_class: String,
    pub required_reviewer_count: usize,
    #[serde(default)]
    pub reviewer_roles: Vec<String>,
    #[serde(default)]
    pub required_reason_fields: Vec<String>,
    #[serde(default)]
    pub allowed_agent_actions: Vec<String>,
    #[serde(default)]
    pub policy_sources: Vec<String>,
}

pub fn load_policy_summary(frontier_path: &Path) -> Result<FrontierPolicySummary, String> {
    let root = frontier_root(frontier_path);
    let manifest_path = root.join("frontier.yaml");
    let manifest = std::fs::read_to_string(&manifest_path)
        .ok()
        .and_then(|body| serde_yaml::from_str::<serde_yaml::Value>(&body).ok());
    let frontier_id = manifest
        .as_ref()
        .and_then(|m| yaml_string_at(m, &["frontier_id"]))
        .or_else(|| {
            repo::load_from_path(frontier_path)
                .ok()
                .and_then(|project| project.frontier_id)
        });

    let manifest_refs = manifest
        .as_ref()
        .map(policy_refs_from_manifest)
        .unwrap_or_default();
    let mut documents = Vec::new();
    let mut missing_required = Vec::new();
    let mut used_default_path = false;

    for kind in PolicyDocumentKind::all() {
        let manifest_ref = manifest_refs.get(&kind);
        let declared_path = manifest_ref.map(|p| root.join(p));
        let default_path = root.join(".vela").join("policy").join(kind.filename());
        let chosen = declared_path
            .as_ref()
            .filter(|p| p.is_file())
            .cloned()
            .or_else(|| {
                if default_path.is_file() {
                    used_default_path = true;
                    Some(default_path.clone())
                } else {
                    None
                }
            });

        if let Some(path) = chosen {
            let body = std::fs::read_to_string(&path)
                .map_err(|e| format!("read policy {}: {e}", path.display()))?;
            let (front_matter, title) = parse_front_matter(&body, kind);
            documents.push(PolicyDocumentSummary {
                kind,
                path: display_path(&root, &path),
                title,
                body_sha256: format!("sha256:{}", hex::encode(Sha256::digest(body.as_bytes()))),
                bytes: body.len(),
                declared_in_manifest: manifest_ref.is_some()
                    && declared_path.as_ref().is_some_and(|p| p == &path),
                front_matter,
            });
        } else {
            missing_required.push(kind.as_str().to_string());
            if manifest_ref.is_none() {
                used_default_path = true;
            }
        }
    }

    documents.sort_by(|a, b| a.kind.cmp(&b.kind));
    missing_required.sort();
    let mut summary = FrontierPolicySummary {
        ok: missing_required.is_empty(),
        frontier_id,
        frontier_path: root.display().to_string(),
        documents,
        missing_required,
        defaults_used: used_default_path,
        canonical_json_sha256: String::new(),
    };
    summary.canonical_json_sha256 = summary_hash(&summary)?;
    Ok(summary)
}

pub fn review_requirement_for_operation(
    summary: Option<&FrontierPolicySummary>,
    operation_class: &str,
    proposal_kind: &str,
    has_downstream_impact: bool,
) -> OperationReviewRequirement {
    let review_class =
        review_class_for_operation(operation_class, proposal_kind, has_downstream_impact);
    let mut reviewer_roles =
        policy_roles_for_review_class(summary, &review_class).unwrap_or_else(|| {
            default_roles_for_review_class(&review_class)
                .into_iter()
                .map(ToString::to_string)
                .collect()
        });
    reviewer_roles.sort();
    reviewer_roles.dedup();
    if reviewer_roles.is_empty() {
        reviewer_roles.push("local_reviewer".to_string());
    }

    let mut required_reason_fields = BTreeSet::new();
    required_reason_fields.insert("reason".to_string());
    if matches!(
        review_class.as_str(),
        "source_repair" | "clinical_translation" | "retraction_impact"
    ) || (review_class == "confidence_change"
        && confidence_policy_requires_source_or_evidence_ref(summary))
    {
        required_reason_fields.insert("source_or_evidence_ref".to_string());
    }
    if matches!(
        review_class.as_str(),
        "clinical_translation" | "retraction_impact" | "decision_impact"
    ) {
        required_reason_fields.insert("impact_scope".to_string());
    }

    let mut policy_sources = BTreeSet::new();
    let mut allowed_agent_actions = agent_allowed_actions(summary);
    allowed_agent_actions.sort();
    allowed_agent_actions.dedup();
    if summary.is_some() {
        policy_sources.insert("frontier_policy".to_string());
    } else {
        policy_sources.insert("built_in_defaults".to_string());
    }

    OperationReviewRequirement {
        review_class,
        required_reviewer_count: reviewer_roles.len().max(1),
        reviewer_roles,
        required_reason_fields: required_reason_fields.into_iter().collect(),
        allowed_agent_actions,
        policy_sources: policy_sources.into_iter().collect(),
    }
}

pub fn attestation_enforcement_enabled(summary: Option<&FrontierPolicySummary>) -> bool {
    summary
        .and_then(|s| {
            s.documents
                .iter()
                .find(|doc| doc.kind == PolicyDocumentKind::Review)
        })
        .and_then(|doc| {
            doc.front_matter
                .get("enforce_attestations")
                .or_else(|| doc.front_matter.get("attestation_enforcement"))
        })
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

pub fn override_reason_is_explicit(reason: &str) -> bool {
    let lower = reason.to_ascii_lowercase();
    lower.contains("policy_override:") || lower.contains("attestation_override:")
}

fn frontier_root(path: &Path) -> PathBuf {
    if path.is_dir() {
        path.to_path_buf()
    } else {
        path.parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."))
    }
}

fn policy_refs_from_manifest(
    manifest: &serde_yaml::Value,
) -> BTreeMap<PolicyDocumentKind, PathBuf> {
    let mut out = BTreeMap::new();
    for kind in PolicyDocumentKind::all() {
        if let Some(value) = yaml_string_at(manifest, &["policies", "frontier", kind.as_str()]) {
            out.insert(kind, PathBuf::from(value));
            continue;
        }
        if let Some(value) = yaml_string_at(manifest, &["policies", kind.as_str()]) {
            out.insert(kind, PathBuf::from(value));
        }
    }
    out
}

fn review_class_for_operation(
    operation_class: &str,
    proposal_kind: &str,
    has_downstream_impact: bool,
) -> String {
    let haystack = format!(
        "{} {}",
        operation_class.to_ascii_lowercase(),
        proposal_kind.to_ascii_lowercase()
    );
    if haystack.contains("clinical") || haystack.contains("translation") {
        return "clinical_translation".to_string();
    }
    if haystack.contains("retraction") || haystack.contains("retract") {
        return "retraction_impact".to_string();
    }
    match operation_class {
        "revise_confidence" => "confidence_change",
        "mark_contradiction" => "contradiction_change",
        "repair_locator" | "repair_span" | "add_evidence_atom" => "source_repair",
        "resolve_entity" => "entity_issue",
        "request_downstream_review" | "open_gap" => "decision_impact",
        _ if has_downstream_impact => "decision_impact",
        _ => "low_risk",
    }
    .to_string()
}

fn default_roles_for_review_class(review_class: &str) -> Vec<&'static str> {
    match review_class {
        "confidence_change" | "contradiction_change" | "retraction_impact" => {
            vec!["domain_reviewer", "method_reviewer"]
        }
        "clinical_translation" => vec!["domain_reviewer", "safety_reviewer"],
        "source_repair" => vec!["source_reviewer"],
        "entity_issue" => vec!["entity_reviewer"],
        "decision_impact" => vec!["frontier_reviewer"],
        _ => vec!["local_reviewer"],
    }
}

fn policy_roles_for_review_class(
    summary: Option<&FrontierPolicySummary>,
    review_class: &str,
) -> Option<Vec<String>> {
    let review_doc = summary?
        .documents
        .iter()
        .find(|doc| doc.kind == PolicyDocumentKind::Review && !doc.front_matter.is_empty())?;
    let roles = review_doc
        .front_matter
        .get("required_roles")?
        .get(review_class)?
        .as_array()?
        .iter()
        .filter_map(|v| v.as_str().map(ToString::to_string))
        .collect::<Vec<_>>();
    if roles.is_empty() { None } else { Some(roles) }
}

fn confidence_policy_requires_source_or_evidence_ref(
    summary: Option<&FrontierPolicySummary>,
) -> bool {
    summary
        .and_then(|s| {
            s.documents
                .iter()
                .find(|doc| doc.kind == PolicyDocumentKind::Confidence)
        })
        .and_then(|doc| doc.front_matter.get("requires_source_or_evidence_ref"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

fn agent_allowed_actions(summary: Option<&FrontierPolicySummary>) -> Vec<String> {
    summary
        .and_then(|s| {
            s.documents
                .iter()
                .find(|doc| doc.kind == PolicyDocumentKind::Agent)
        })
        .and_then(|doc| doc.front_matter.get("agents_may"))
        .and_then(serde_json::Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(ToString::to_string))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn parse_front_matter(
    body: &str,
    kind: PolicyDocumentKind,
) -> (BTreeMap<String, serde_json::Value>, String) {
    let mut metadata = BTreeMap::new();
    if let Some(rest) = body.strip_prefix("---\n")
        && let Some((front, _body)) = rest.split_once("\n---")
        && let Ok(yaml) = serde_yaml::from_str::<serde_yaml::Value>(front)
        && let Some(map) = yaml.as_mapping()
    {
        for (key, value) in map {
            if let Some(key) = key.as_str()
                && let Ok(json_value) = serde_json::to_value(value)
            {
                metadata.insert(key.to_string(), json_value);
            }
        }
    }
    let title = metadata
        .get("title")
        .and_then(|v| v.as_str())
        .map(ToString::to_string)
        .unwrap_or_else(|| format!("{} policy", kind.as_str()));
    (metadata, title)
}

fn yaml_string_at(value: &serde_yaml::Value, path: &[&str]) -> Option<String> {
    let mut cur = value;
    for key in path {
        cur = cur.get(*key)?;
    }
    cur.as_str().map(ToString::to_string)
}

fn display_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .to_string()
}

fn summary_hash(summary: &FrontierPolicySummary) -> Result<String, String> {
    let mut value = serde_json::to_value(summary).map_err(|e| format!("serialize policy: {e}"))?;
    if let Some(obj) = value.as_object_mut() {
        obj.remove("canonical_json_sha256");
    }
    let bytes = canonical::to_canonical_bytes(&value)?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}
