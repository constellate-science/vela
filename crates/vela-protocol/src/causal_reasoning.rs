//! v0.40: Causal reasoning over the schema landed in v0.38.
//!
//! v0.38.0 made `causal_claim` and `causal_evidence_grade` first-class
//! fields on `Assertion`. v0.38.1 folded a soft compatibility multiplier
//! into the confidence formula. v0.38.2 let aggregate queries filter
//! by claim type. v0.38.3 caught the most common structural error
//! (`supports` across claim-strength mismatch).
//!
//! v0.40.0 lands the *reasoning* move: a hard identifiability verdict.
//! Given a finding's (claim, grade), can the design — *as declared* —
//! support the claim being made? This is Pearl's identifiability
//! question at level 1: does the rung-of-the-ladder match the
//! evidence type?
//!
//! Doctrine:
//! - Identifiability is a function of (claim, grade), not of the
//!   confidence score, the citation count, or any soft signal.
//!   Either the design admits the claim or it doesn't.
//! - The kernel records the verdict; the kernel does not auto-correct.
//!   v0.40.1+ will surface remediation proposals so a reviewer can
//!   downgrade the claim or strengthen the evidence.
//! - Findings without typed claims (`causal_claim = None`) are
//!   `Underdetermined` — the kernel knows it doesn't know.

use serde::{Deserialize, Serialize};

use crate::bundle::{CausalClaim, CausalEvidenceGrade, FindingBundle};
use crate::project::Project;

/// v0.40: hard identifiability verdict for a finding's causal claim
/// against the declared study-design grade.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Identifiability {
    /// The design admits the claim. (Correlation under any grade,
    /// mediation under RCT/QE, intervention under RCT.)
    Identified,
    /// The design admits the claim only under additional assumptions
    /// the kernel cannot verify (instrument validity for QE-grade
    /// intervention, lack of unmeasured confounders for QE-grade
    /// mediation). The reviewer must document the assumption.
    Conditional,
    /// The design cannot identify the claim. Observational data
    /// alone does not identify intervention. Theoretical evidence
    /// alone does not identify causation.
    Underidentified,
    /// `causal_claim` or `causal_evidence_grade` is unset; the kernel
    /// has nothing to grade. Pre-v0.38 findings are all in this
    /// bucket until reviewed.
    Underdetermined,
}

impl Identifiability {
    pub fn as_str(self) -> &'static str {
        match self {
            Identifiability::Identified => "identified",
            Identifiability::Conditional => "conditional",
            Identifiability::Underidentified => "underidentified",
            Identifiability::Underdetermined => "underdetermined",
        }
    }

    /// True if this verdict signals the substrate cannot vouch for
    /// the claim as stated. `Underidentified` is the obvious case;
    /// `Conditional` is included here because it requires reviewer
    /// attestation the kernel hasn't seen.
    pub fn needs_reviewer_attention(self) -> bool {
        matches!(
            self,
            Identifiability::Underidentified | Identifiability::Conditional
        )
    }
}

/// v0.40: hard identifiability check on (claim, grade). Pure function;
/// the matrix encodes the Pearlian doctrine documented above.
#[must_use]
pub fn is_identifiable(
    claim: Option<CausalClaim>,
    grade: Option<CausalEvidenceGrade>,
) -> Identifiability {
    use CausalClaim::*;
    use CausalEvidenceGrade::*;
    let (Some(c), Some(g)) = (claim, grade) else {
        return Identifiability::Underdetermined;
    };
    match (c, g) {
        // Correlation: any reasonable design admits association.
        (Correlation, _) => Identifiability::Identified,
        // Mediation:
        (Mediation, Rct) => Identifiability::Identified,
        (Mediation, QuasiExperimental) => Identifiability::Conditional,
        (Mediation, Observational) => Identifiability::Underidentified,
        (Mediation, Theoretical) => Identifiability::Underidentified,
        // Intervention: the strongest claim. RCT identifies; QE under
        // instrument validity (conditional); observational and
        // theoretical alone don't.
        (Intervention, Rct) => Identifiability::Identified,
        (Intervention, QuasiExperimental) => Identifiability::Conditional,
        (Intervention, Observational) => Identifiability::Underidentified,
        (Intervention, Theoretical) => Identifiability::Underidentified,
    }
}

/// One row of the causal-audit report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub finding_id: String,
    pub assertion_text: String,
    pub causal_claim: Option<CausalClaim>,
    pub causal_evidence_grade: Option<CausalEvidenceGrade>,
    pub verdict: Identifiability,
    /// One short sentence explaining why this finding earned this
    /// verdict, suitable for a review-queue display.
    pub rationale: String,
    /// Suggested remediation — downgrade the claim, strengthen the
    /// evidence, or document the assumption.
    pub remediation: String,
}

fn rationale_for(claim: CausalClaim, grade: CausalEvidenceGrade) -> &'static str {
    use CausalClaim::*;
    use CausalEvidenceGrade::*;
    match (claim, grade) {
        (Correlation, _) => "Correlation claims are admitted by any reasonable design.",
        (Mediation, Rct) => "RCT design identifies mediation pathways.",
        (Mediation, QuasiExperimental) => {
            "Quasi-experimental design identifies mediation only when the instrument is valid and confounders are addressed."
        }
        (Mediation, Observational) => {
            "Observational data leaves the back-door problem open: confounders may explain the apparent mediation."
        }
        (Mediation, Theoretical) => {
            "Theoretical models propose mediation; they do not identify it from data."
        }
        (Intervention, Rct) => "RCT design identifies intervention effects directly.",
        (Intervention, QuasiExperimental) => {
            "Quasi-experimental design identifies intervention effects only under instrument validity."
        }
        (Intervention, Observational) => {
            "Observational data does not identify intervention effects (Rubin/Pearl: do(X=x) is unobserved)."
        }
        (Intervention, Theoretical) => {
            "Theoretical analysis cannot identify intervention effects from real-world data alone."
        }
    }
}

fn remediation_for(verdict: Identifiability, claim: Option<CausalClaim>) -> String {
    match (verdict, claim) {
        (Identifiability::Identified, _) => "No action; design supports the claim.".into(),
        (Identifiability::Conditional, _) => {
            "Document the additional assumptions (instrument validity, ignorability of confounders) on the finding as a caveat or evidence_span."
                .into()
        }
        (Identifiability::Underidentified, Some(CausalClaim::Intervention)) => {
            "Either downgrade the claim from `intervention` to `correlation`, or attach RCT/QE-grade evidence that identifies the effect."
                .into()
        }
        (Identifiability::Underidentified, Some(CausalClaim::Mediation)) => {
            "Either downgrade to `correlation`, or attach RCT/QE-grade evidence that closes the back-door pathways."
                .into()
        }
        (Identifiability::Underidentified, _) => {
            "Downgrade the claim or supply stronger evidence.".into()
        }
        (Identifiability::Underdetermined, _) => {
            "Set `causal_claim` and `causal_evidence_grade` via `vela finding causal-set`."
                .into()
        }
    }
}

/// v0.40: audit one finding against the identifiability matrix.
#[must_use]
pub fn audit_finding(finding: &FindingBundle) -> AuditEntry {
    let claim = finding.assertion.causal_claim;
    let grade = finding.assertion.causal_evidence_grade;
    let verdict = is_identifiable(claim, grade);
    let rationale = match (claim, grade) {
        (Some(c), Some(g)) => rationale_for(c, g).to_string(),
        _ => "Causal type or evidence grade unset.".to_string(),
    };
    let remediation = remediation_for(verdict, claim);
    AuditEntry {
        finding_id: finding.id.clone(),
        assertion_text: finding.assertion.text.clone(),
        causal_claim: claim,
        causal_evidence_grade: grade,
        verdict,
        rationale,
        remediation,
    }
}

/// v0.40: audit every finding in a frontier. Return entries sorted
/// so reviewer-attention items (Underidentified, then Conditional)
/// surface first; identified findings sink to the bottom.
#[must_use]
pub fn audit_frontier(project: &Project) -> Vec<AuditEntry> {
    let mut entries: Vec<AuditEntry> = project.findings.iter().map(audit_finding).collect();
    entries.sort_by_key(|e| match e.verdict {
        Identifiability::Underidentified => 0,
        Identifiability::Conditional => 1,
        Identifiability::Underdetermined => 2,
        Identifiability::Identified => 3,
    });
    entries
}

/// Summary counters for an audit pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSummary {
    pub total: usize,
    pub identified: usize,
    pub conditional: usize,
    pub underidentified: usize,
    pub underdetermined: usize,
}

#[must_use]
pub fn summarize_audit(entries: &[AuditEntry]) -> AuditSummary {
    let mut s = AuditSummary {
        total: entries.len(),
        identified: 0,
        conditional: 0,
        underidentified: 0,
        underdetermined: 0,
    };
    for e in entries {
        match e.verdict {
            Identifiability::Identified => s.identified += 1,
            Identifiability::Conditional => s.conditional += 1,
            Identifiability::Underidentified => s.underidentified += 1,
            Identifiability::Underdetermined => s.underdetermined += 1,
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn underdetermined_when_missing_either_field() {
        assert_eq!(
            is_identifiable(None, None),
            Identifiability::Underdetermined
        );
        assert_eq!(
            is_identifiable(Some(CausalClaim::Intervention), None),
            Identifiability::Underdetermined
        );
        assert_eq!(
            is_identifiable(None, Some(CausalEvidenceGrade::Rct)),
            Identifiability::Underdetermined
        );
    }

    #[test]
    fn correlation_identified_under_any_grade() {
        for g in [
            CausalEvidenceGrade::Theoretical,
            CausalEvidenceGrade::Observational,
            CausalEvidenceGrade::QuasiExperimental,
            CausalEvidenceGrade::Rct,
        ] {
            assert_eq!(
                is_identifiable(Some(CausalClaim::Correlation), Some(g)),
                Identifiability::Identified,
                "correlation under {g:?} should be identified"
            );
        }
    }

    #[test]
    fn rct_identifies_any_claim() {
        for c in [
            CausalClaim::Correlation,
            CausalClaim::Mediation,
            CausalClaim::Intervention,
        ] {
            assert_eq!(
                is_identifiable(Some(c), Some(CausalEvidenceGrade::Rct)),
                Identifiability::Identified,
                "RCT should identify {c:?}"
            );
        }
    }

    #[test]
    fn intervention_observational_underidentified() {
        assert_eq!(
            is_identifiable(
                Some(CausalClaim::Intervention),
                Some(CausalEvidenceGrade::Observational)
            ),
            Identifiability::Underidentified
        );
    }

    #[test]
    fn intervention_quasi_experimental_conditional() {
        assert_eq!(
            is_identifiable(
                Some(CausalClaim::Intervention),
                Some(CausalEvidenceGrade::QuasiExperimental)
            ),
            Identifiability::Conditional
        );
    }

    #[test]
    fn mediation_observational_underidentified() {
        assert_eq!(
            is_identifiable(
                Some(CausalClaim::Mediation),
                Some(CausalEvidenceGrade::Observational)
            ),
            Identifiability::Underidentified
        );
    }

    #[test]
    fn needs_reviewer_attention_only_for_problem_verdicts() {
        assert!(!Identifiability::Identified.needs_reviewer_attention());
        assert!(!Identifiability::Underdetermined.needs_reviewer_attention());
        assert!(Identifiability::Conditional.needs_reviewer_attention());
        assert!(Identifiability::Underidentified.needs_reviewer_attention());
    }

    #[test]
    fn audit_remediation_intervention_observational_suggests_downgrade() {
        let r = remediation_for(
            Identifiability::Underidentified,
            Some(CausalClaim::Intervention),
        );
        assert!(r.contains("downgrade"));
        assert!(r.contains("intervention"));
    }
}
