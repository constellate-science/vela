//! Correction returns as review material.
//!
//! A correction return is an outsider or reviewer-submitted object that
//! points at a finding, source, trace, benchmark artifact, or review note. It
//! can draft review proposals, but it does not mutate frontier state by itself.

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::events::StateTarget;
use crate::project::Project;
use crate::proposals::{self, StateProposal};

pub const CORRECTION_RETURN_SCHEMA: &str = "vela.correction_return.v0.1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CorrectionReturn {
    pub schema: String,
    pub frontier: String,
    pub frontier_id: String,
    pub returned_by: String,
    pub returned_at: String,
    pub claim_boundary: CorrectionClaimBoundary,
    #[serde(default)]
    pub corrections: Vec<ReturnedCorrection>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CorrectionClaimBoundary {
    pub claims_clinical_validity: bool,
    pub claims_external_adoption: bool,
    pub claims_external_validation: bool,
    pub claims_lab_validation: bool,
    pub claims_scientific_discovery: bool,
    pub claims_target_validation: bool,
    pub claims_treatment_advice: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReturnedCorrection {
    pub target_type: String,
    pub target_id: String,
    pub issue: String,
    pub proposed_change: String,
    pub source_locator: String,
    pub evidence_span: String,
    #[serde(default)]
    pub supporting_artifacts: Vec<String>,
    #[serde(default)]
    pub verification_run: Vec<String>,
    pub review_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CorrectionValidationSummary {
    pub corrections: usize,
    pub supporting_artifacts: usize,
    pub verification_runs: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CorrectionValidationReport {
    pub ok: bool,
    pub correction_return: CorrectionReturnReport,
    pub summary: CorrectionValidationSummary,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CorrectionReturnReport {
    pub schema: String,
    pub frontier: String,
    pub frontier_id: String,
    pub returned_by: String,
    pub returned_at: String,
    pub content_hash: String,
}

impl CorrectionReturn {
    pub fn from_path(path: &Path) -> Result<Self, String> {
        let data = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read correction return {}: {e}", path.display()))?;
        serde_json::from_str(&data)
            .map_err(|e| format!("Failed to parse correction return {}: {e}", path.display()))
    }

    pub fn validate(&self) -> Result<CorrectionValidationSummary, Vec<String>> {
        let mut issues = Vec::new();
        if self.schema != CORRECTION_RETURN_SCHEMA {
            issues.push(format!(
                "schema must be `{CORRECTION_RETURN_SCHEMA}`, got `{}`",
                self.schema
            ));
        }
        require_non_empty("frontier", &self.frontier, &mut issues);
        require_non_empty("frontier_id", &self.frontier_id, &mut issues);
        require_non_empty("returned_by", &self.returned_by, &mut issues);
        require_non_empty("returned_at", &self.returned_at, &mut issues);
        validate_claim_boundary(&self.claim_boundary, &mut issues);

        if self.corrections.is_empty() {
            issues.push("corrections must contain at least one item".to_string());
        }
        for correction in &self.corrections {
            require_non_empty(
                "corrections[].target_type",
                &correction.target_type,
                &mut issues,
            );
            require_non_empty(
                "corrections[].target_id",
                &correction.target_id,
                &mut issues,
            );
            require_non_empty("corrections[].issue", &correction.issue, &mut issues);
            require_non_empty(
                "corrections[].proposed_change",
                &correction.proposed_change,
                &mut issues,
            );
            require_non_empty(
                "corrections[].source_locator",
                &correction.source_locator,
                &mut issues,
            );
            require_non_empty(
                "corrections[].evidence_span",
                &correction.evidence_span,
                &mut issues,
            );
            if correction.verification_run.is_empty() {
                issues.push(format!(
                    "correction for `{}` must name verification_run",
                    correction.target_id
                ));
            }
            if correction.review_status != "pending_review" {
                issues.push(format!(
                    "correction for `{}` review_status must be pending_review",
                    correction.target_id
                ));
            }
        }

        if issues.is_empty() {
            Ok(self.summary())
        } else {
            Err(issues)
        }
    }

    pub fn summary(&self) -> CorrectionValidationSummary {
        CorrectionValidationSummary {
            corrections: self.corrections.len(),
            supporting_artifacts: self
                .corrections
                .iter()
                .map(|correction| correction.supporting_artifacts.len())
                .sum(),
            verification_runs: self
                .corrections
                .iter()
                .map(|correction| correction.verification_run.len())
                .sum(),
        }
    }
}

pub fn validate_correction_return_file(path: &Path) -> Result<CorrectionValidationReport, String> {
    let correction_return = CorrectionReturn::from_path(path)?;
    let data = fs::read(path)
        .map_err(|e| format!("Failed to read correction return {}: {e}", path.display()))?;
    let report = CorrectionReturnReport {
        schema: correction_return.schema.clone(),
        frontier: correction_return.frontier.clone(),
        frontier_id: correction_return.frontier_id.clone(),
        returned_by: correction_return.returned_by.clone(),
        returned_at: correction_return.returned_at.clone(),
        content_hash: format!("sha256:{}", hex::encode(Sha256::digest(data))),
    };
    match correction_return.validate() {
        Ok(summary) => Ok(CorrectionValidationReport {
            ok: true,
            correction_return: report,
            summary,
            issues: Vec::new(),
        }),
        Err(issues) => Err(format!(
            "Correction return validation failed for {}: {}",
            path.display(),
            issues
                .into_iter()
                .map(|issue| format!("{issue}. edit {}", path.display()))
                .collect::<Vec<_>>()
                .join("; ")
        )),
    }
}

pub fn proposals_from_correction_return_file(
    path: &Path,
    frontier: &Project,
) -> Result<Vec<StateProposal>, String> {
    let correction_return = CorrectionReturn::from_path(path)?;
    correction_return
        .validate()
        .map_err(|issues| issues.join("; "))?;
    let source_ref = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("correction-return.source-debt-real.v1.json")
        .to_string();
    Ok(proposals_from_correction_return(
        &correction_return,
        frontier,
        &source_ref,
    ))
}

pub fn proposals_from_correction_return(
    correction_return: &CorrectionReturn,
    frontier: &Project,
    source_ref: &str,
) -> Vec<StateProposal> {
    let frontier_id = frontier
        .frontier_id
        .clone()
        .unwrap_or_else(|| frontier.project.name.clone());
    correction_return
        .corrections
        .iter()
        .map(|correction| {
            let payload = json!({
                "frontier": frontier_id,
                "returned_by": correction_return.returned_by,
                "returned_at": correction_return.returned_at,
                "claim_boundary": correction_return.claim_boundary,
                "correction": correction,
            });
            proposals::new_proposal(
                "correction_return.review",
                StateTarget {
                    r#type: "frontier_observation".to_string(),
                    id: observation_id(
                        &correction_return.frontier_id,
                        &correction.target_id,
                        &correction.issue,
                    ),
                },
                correction_return.returned_by.clone(),
                "reviewer".to_string(),
                format!("Review returned correction for `{}`", correction.target_id),
                payload,
                vec![source_ref.to_string()],
                Vec::new(),
            )
        })
        .collect()
}

fn observation_id(frontier_id: &str, target_id: &str, issue: &str) -> String {
    let bytes = crate::canonical::to_canonical_bytes(&json!({
        "frontier_id": frontier_id,
        "target_id": target_id,
        "issue": issue,
    }))
    .unwrap_or_default();
    format!("vobs_{}", &hex::encode(Sha256::digest(bytes))[..16])
}

fn validate_claim_boundary(boundary: &CorrectionClaimBoundary, issues: &mut Vec<String>) {
    if boundary.claims_clinical_validity {
        issues.push("claim_boundary.claims_clinical_validity must be false".to_string());
    }
    if boundary.claims_external_adoption {
        issues.push("claim_boundary.claims_external_adoption must be false".to_string());
    }
    if boundary.claims_external_validation {
        issues.push("claim_boundary.claims_external_validation must be false".to_string());
    }
    if boundary.claims_lab_validation {
        issues.push("claim_boundary.claims_lab_validation must be false".to_string());
    }
    if boundary.claims_scientific_discovery {
        issues.push("claim_boundary.claims_scientific_discovery must be false".to_string());
    }
    if boundary.claims_target_validation {
        issues.push("claim_boundary.claims_target_validation must be false".to_string());
    }
    if boundary.claims_treatment_advice {
        issues.push("claim_boundary.claims_treatment_advice must be false".to_string());
    }
}

fn require_non_empty(label: &str, value: &str, issues: &mut Vec<String>) {
    if value.trim().is_empty() {
        issues.push(format!("{label} must be non-empty"));
    }
}
