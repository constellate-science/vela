//! Role-scoped scientific attestations.
//!
//! These records are local review artifacts. They state that a named
//! reviewer attested a bounded target under a declared scope. They do
//! not imply global consensus or institutional multi-signature approval.

use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use chrono::Utc;
use serde::{Deserialize, Serialize};

use vela_protocol::canonical;

use crate::frontier_task;

use vela_protocol::state;
pub const SCIENTIFIC_ATTESTATION_SCHEMA: &str = "vela.scientific_attestation.v0.1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AttestationScope {
    SourceExtraction,
    MethodReview,
    StatisticalReview,
    DomainRelevance,
    TranslationClarity,
    PolicyApproval,
}

impl AttestationScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SourceExtraction => "source_extraction",
            Self::MethodReview => "method_review",
            Self::StatisticalReview => "statistical_review",
            Self::DomainRelevance => "domain_relevance",
            Self::TranslationClarity => "translation_clarity",
            Self::PolicyApproval => "policy_approval",
        }
    }
}

impl fmt::Display for AttestationScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for AttestationScope {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim() {
            "source_extraction" => Ok(Self::SourceExtraction),
            "method_review" => Ok(Self::MethodReview),
            "statistical_review" => Ok(Self::StatisticalReview),
            "domain_relevance" => Ok(Self::DomainRelevance),
            "translation_clarity" => Ok(Self::TranslationClarity),
            "policy_approval" => Ok(Self::PolicyApproval),
            other => Err(format!("unknown attestation scope `{other}`")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReviewerIdentity {
    pub reviewer_id: String,
    pub role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub orcid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ror: Option<String>,
    #[serde(default)]
    pub declared_scopes: Vec<AttestationScope>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScientificAttestation {
    pub schema: String,
    pub attestation_id: String,
    pub target_id: String,
    pub target_kind: String,
    pub reviewer: ReviewerIdentity,
    pub reason: String,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical_event_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScientificAttestationReport {
    pub ok: bool,
    pub command: String,
    pub frontier_path: String,
    pub attestation: ScientificAttestation,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationInput {
    pub target_id: String,
    pub scopes: Vec<AttestationScope>,
    pub reviewer_id: String,
    pub role: String,
    pub reason: String,
    pub orcid: Option<String>,
    pub ror: Option<String>,
    pub proof_id: Option<String>,
    pub signature: Option<String>,
}

pub fn record(
    frontier_path: &Path,
    input: AttestationInput,
) -> Result<ScientificAttestationReport, String> {
    validate_input(&input)?;
    let root = frontier_task::repo_root(frontier_path)?;
    let target_kind = target_kind(&input.target_id)?;
    let mut attestation = ScientificAttestation {
        schema: SCIENTIFIC_ATTESTATION_SCHEMA.to_string(),
        attestation_id: String::new(),
        target_id: input.target_id.clone(),
        target_kind,
        reviewer: ReviewerIdentity {
            reviewer_id: input.reviewer_id.clone(),
            role: input.role.clone(),
            orcid: input.orcid.clone(),
            ror: input.ror.clone(),
            declared_scopes: input.scopes.clone(),
        },
        reason: input.reason.clone(),
        created_at: Utc::now().to_rfc3339(),
        canonical_event_id: None,
        proof_id: input.proof_id.clone(),
        signature: input.signature.clone(),
    };
    attestation.attestation_id = derive_attestation_id(&attestation)?;

    if attestation.target_kind == "event" {
        let scope_names = attestation
            .reviewer
            .declared_scopes
            .iter()
            .map(|scope| scope.as_str().to_string())
            .collect::<Vec<_>>();
        let canonical_event_id = state::record_scoped_attestation(
            &root,
            &attestation.target_id,
            state::ScopedAttestationInput {
                attester_id: &attestation.reviewer.reviewer_id,
                scope_note: &attestation.reason,
                scopes: &scope_names,
                reviewer_role: Some(&attestation.reviewer.role),
                orcid: attestation.reviewer.orcid.as_deref(),
                ror: attestation.reviewer.ror.as_deref(),
                proof_id: attestation.proof_id.as_deref(),
                signature: attestation.signature.as_deref(),
                attestation_id: Some(&attestation.attestation_id),
            },
        )?;
        attestation.canonical_event_id = Some(canonical_event_id);
    }

    let path = attestation_path(&root, &attestation.attestation_id);
    write_attestation(&path, &attestation)?;
    Ok(ScientificAttestationReport {
        ok: true,
        command: "attest".to_string(),
        frontier_path: root.display().to_string(),
        path: path.display().to_string(),
        attestation,
    })
}

pub fn list(frontier_path: &Path) -> Result<Vec<ScientificAttestation>, String> {
    let root = frontier_task::repo_root(frontier_path)?;
    let dir = attestations_dir(&root);
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir).map_err(|e| format!("read attestations dir: {e}"))? {
        let path = entry
            .map_err(|e| format!("read attestation entry: {e}"))?
            .path();
        if path.extension().is_some_and(|ext| ext == "json") {
            let data = std::fs::read_to_string(&path)
                .map_err(|e| format!("read attestation {}: {e}", path.display()))?;
            let attestation: ScientificAttestation =
                serde_json::from_str(&data).map_err(|e| format!("parse attestation: {e}"))?;
            out.push(attestation);
        }
    }
    out.sort_by(|a, b| a.attestation_id.cmp(&b.attestation_id));
    Ok(out)
}

pub fn attestations_for_target(
    frontier_path: &Path,
    target_id: &str,
) -> Result<Vec<ScientificAttestation>, String> {
    Ok(list(frontier_path)?
        .into_iter()
        .filter(|attestation| attestation.target_id == target_id)
        .collect())
}

pub fn missing_roles_for_target(
    frontier_path: &Path,
    target_id: &str,
    required_roles: &[String],
) -> Result<Vec<String>, String> {
    let attestations = attestations_for_target(frontier_path, target_id)?;
    let mut missing = Vec::new();
    for role in required_roles {
        if !attestations
            .iter()
            .any(|attestation| attestation.reviewer.role == *role)
        {
            missing.push(role.clone());
        }
    }
    missing.sort();
    missing.dedup();
    Ok(missing)
}

pub fn parse_scopes(values: &[String]) -> Result<Vec<AttestationScope>, String> {
    let mut scopes = Vec::new();
    for value in values {
        scopes.push(AttestationScope::from_str(value)?);
    }
    scopes.sort();
    scopes.dedup();
    if scopes.is_empty() {
        return Err("at least one attestation scope is required".to_string());
    }
    Ok(scopes)
}

fn validate_input(input: &AttestationInput) -> Result<(), String> {
    if !input.reviewer_id.starts_with("reviewer:") {
        return Err(format!(
            "reviewer id must start with `reviewer:`, got `{}`",
            input.reviewer_id
        ));
    }
    if input.role.trim().is_empty() {
        return Err("reviewer role is required".to_string());
    }
    if input.reason.trim().is_empty() {
        return Err("attestation reason is required".to_string());
    }
    if input.scopes.is_empty() {
        return Err("at least one attestation scope is required".to_string());
    }
    if let Some(orcid) = &input.orcid {
        validate_orcid(orcid)?;
    }
    if let Some(ror) = &input.ror {
        validate_ror(ror)?;
    }
    if let Some(proof_id) = &input.proof_id
        && !proof_id.starts_with("vpf_")
    {
        return Err(format!("proof id must start with `vpf_`, got `{proof_id}`"));
    }
    target_kind(&input.target_id)?;
    Ok(())
}

fn validate_orcid(orcid: &str) -> Result<(), String> {
    let raw = orcid
        .strip_prefix("https://orcid.org/")
        .unwrap_or(orcid)
        .trim();
    let parts = raw.split('-').collect::<Vec<_>>();
    if parts.len() != 4
        || parts.iter().any(|part| part.len() != 4)
        || !raw
            .chars()
            .all(|c| c.is_ascii_digit() || c == '-' || c == 'X')
    {
        return Err(format!("invalid ORCID `{orcid}`"));
    }
    Ok(())
}

fn validate_ror(ror: &str) -> Result<(), String> {
    if ror.starts_with("https://ror.org/") || ror.starts_with("ror:") {
        Ok(())
    } else {
        Err(format!(
            "ROR affiliation must start with `https://ror.org/` or `ror:`, got `{ror}`"
        ))
    }
}

fn target_kind(target_id: &str) -> Result<String, String> {
    if target_id.starts_with("vev_") {
        Ok("event".to_string())
    } else if target_id.starts_with("vsd_") {
        Ok("diff_pack".to_string())
    } else if target_id.starts_with("vrp_") {
        Ok("review_packet".to_string())
    } else if target_id.starts_with("vpf_") {
        Ok("proof_packet".to_string())
    } else {
        Err(format!(
            "attestation target must start with vev_, vsd_, vrp_, or vpf_; got `{target_id}`"
        ))
    }
}

fn derive_attestation_id(attestation: &ScientificAttestation) -> Result<String, String> {
    let value = serde_json::json!({
        "schema": &attestation.schema,
        "target_id": &attestation.target_id,
        "target_kind": &attestation.target_kind,
        "reviewer": &attestation.reviewer,
        "reason": &attestation.reason,
        "created_at": &attestation.created_at,
        "proof_id": &attestation.proof_id,
        "signature": &attestation.signature,
    });
    let hash = canonical::sha256_canonical(&value)?;
    Ok(format!("vatt_{}", &hash[..16]))
}

fn attestations_dir(root: &Path) -> PathBuf {
    root.join(".vela").join("attestations")
}

fn attestation_path(root: &Path, attestation_id: &str) -> PathBuf {
    attestations_dir(root).join(format!("{attestation_id}.json"))
}

fn write_attestation(path: &Path, attestation: &ScientificAttestation) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("create attestations dir {}: {e}", parent.display()))?;
    }
    let body = serde_json::to_string_pretty(attestation)
        .map_err(|e| format!("serialize attestation: {e}"))?;
    std::fs::write(path, format!("{body}\n")).map_err(|e| format!("write {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_parser_accepts_declared_scopes() {
        let scopes = parse_scopes(&[
            "domain_relevance".to_string(),
            "source_extraction".to_string(),
        ])
        .unwrap();
        assert_eq!(
            scopes,
            vec![
                AttestationScope::SourceExtraction,
                AttestationScope::DomainRelevance
            ]
        );
    }

    #[test]
    fn reviewer_identity_rejects_placeholder_prefix() {
        let err = validate_input(&AttestationInput {
            target_id: "vsd_demo".to_string(),
            scopes: vec![AttestationScope::DomainRelevance],
            reviewer_id: "agent:not-a-human-reviewer".to_string(),
            role: "domain_reviewer".to_string(),
            reason: "bounded role review".to_string(),
            orcid: None,
            ror: None,
            proof_id: None,
            signature: None,
        })
        .unwrap_err();
        assert!(err.contains("reviewer id"));
    }
}
