//! Statistical validation linter — catches common methodological red flags in findings.

use vela_protocol::bundle::FindingBundle;
use vela_protocol::project::Project;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Error,
    Warning,
    Info,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Error => write!(f, "error"),
            Severity::Warning => write!(f, "warning"),
            Severity::Info => write!(f, "info"),
        }
    }
}

impl std::str::FromStr for Severity {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "error" => Ok(Severity::Error),
            "warning" => Ok(Severity::Warning),
            "info" => Ok(Severity::Info),
            _ => Err(format!(
                "Unknown severity: {s}. Use error, warning, or info."
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LintRule {
    pub id: String,
    pub name: String,
    pub severity: Severity,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Diagnostic {
    pub rule_id: String,
    pub finding_id: String,
    pub message: String,
    pub suggestion: String,
    pub severity: Severity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LintReport {
    pub diagnostics: Vec<Diagnostic>,
    pub findings_checked: usize,
    pub errors: usize,
    pub warnings: usize,
    pub infos: usize,
}

/// Return all lint rules.
pub fn all_rules() -> Vec<LintRule> {
    vec![
        LintRule {
            id: "L001".into(),
            name: "small_sample".into(),
            severity: Severity::Warning,
            description: "Experimental finding with sample size < 10".into(),
        },
        LintRule {
            id: "L002".into(),
            name: "no_replication".into(),
            severity: Severity::Warning,
            description: "High-confidence finding without replication".into(),
        },
        LintRule {
            id: "L003".into(),
            name: "missing_species".into(),
            severity: Severity::Warning,
            description: "Experimental finding without species information".into(),
        },
        LintRule {
            id: "L004".into(),
            name: "confidence_mismatch".into(),
            severity: Severity::Warning,
            description: "Theoretical finding with unusually high confidence".into(),
        },
        LintRule {
            id: "L005".into(),
            name: "unreported_effect".into(),
            severity: Severity::Warning,
            description: "P-value reported but no effect size".into(),
        },
        LintRule {
            id: "L006".into(),
            name: "p_boundary".into(),
            severity: Severity::Info,
            description: "P-value near significance boundary (0.04-0.06)".into(),
        },
        LintRule {
            id: "L007".into(),
            name: "missing_controls".into(),
            severity: Severity::Warning,
            description: "Experimental finding with no mention of controls".into(),
        },
        LintRule {
            id: "L008".into(),
            name: "multiple_comparisons".into(),
            severity: Severity::Warning,
            description: "Multiple evidence spans without correction for multiple comparisons"
                .into(),
        },
        LintRule {
            id: "L009".into(),
            name: "cherry_picking".into(),
            severity: Severity::Warning,
            description:
                "Same DOI has findings with mixed significance, potential selective reporting"
                    .into(),
        },
        LintRule {
            id: "L010".into(),
            name: "wrong_test".into(),
            severity: Severity::Warning,
            description: "T-test used when multiple groups are mentioned".into(),
        },
        LintRule {
            id: "L011".into(),
            name: "causal_mismatch_supports".into(),
            severity: Severity::Warning,
            description:
                "A `supports` link from a weaker causal claim (correlation) to a stronger one (intervention) is a category error: correlation alone cannot support a causal claim."
                    .into(),
        },
    ]
}

fn parse_sample_size(s: &str) -> Option<u32> {
    // Extract numeric portion: "n=24" -> 24, "24 patients" -> 24, "24" -> 24
    let cleaned = s.trim().to_lowercase();
    let cleaned = cleaned.strip_prefix("n=").unwrap_or(&cleaned);
    cleaned
        .split(|c: char| !c.is_ascii_digit())
        .next()?
        .parse()
        .ok()
}

fn parse_p_value(s: &str) -> Option<f64> {
    let cleaned = s.trim().to_lowercase();
    let cleaned = cleaned
        .strip_prefix("p=")
        .or_else(|| cleaned.strip_prefix("p ="))
        .or_else(|| cleaned.strip_prefix("p<"))
        .or_else(|| cleaned.strip_prefix("p < "))
        .unwrap_or(&cleaned);
    cleaned
        .split(|c: char| !c.is_ascii_digit() && c != '.')
        .next()?
        .parse()
        .ok()
}

fn has_abstract_only_caveat(finding: &FindingBundle) -> bool {
    finding.annotations.iter().any(|annotation| {
        let text = annotation.text.to_lowercase();
        text.contains("abstract-only") || text.contains("title and abstract only")
    })
}

pub fn check_sample_size(finding: &FindingBundle) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    if (finding.evidence.evidence_type == "experimental"
        || finding.evidence.evidence_type == "observational")
        && let Some(ref ss) = finding.evidence.sample_size
        && let Some(n) = parse_sample_size(ss)
        && n < 10
    {
        diags.push(Diagnostic {
            rule_id: "L001".into(),
            finding_id: finding.id.clone(),
            message: format!("Sample size {} is below minimum threshold of 10", n),
            suggestion: "Consider whether this finding has adequate statistical power".into(),
            severity: Severity::Warning,
        });
    }
    diags
}

pub fn check_no_replication(finding: &FindingBundle) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    if finding.confidence.score > 0.8 && !finding.evidence.replicated {
        diags.push(Diagnostic {
            rule_id: "L002".into(),
            finding_id: finding.id.clone(),
            message: format!(
                "Confidence {:.2} but no replication reported",
                finding.confidence.score
            ),
            suggestion: "High-confidence claims should have independent replication".into(),
            severity: Severity::Warning,
        });
    }
    diags
}

pub fn check_missing_species(finding: &FindingBundle) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    if finding.evidence.evidence_type == "experimental"
        && finding.evidence.species.is_none()
        && !has_abstract_only_caveat(finding)
    {
        diags.push(Diagnostic {
            rule_id: "L003".into(),
            finding_id: finding.id.clone(),
            message: "Experimental finding without species information".into(),
            suggestion: "Specify the species or model organism used".into(),
            severity: Severity::Warning,
        });
    }
    diags
}

pub fn check_confidence_mismatch(finding: &FindingBundle) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    if finding.assertion.assertion_type == "theoretical" && finding.confidence.score > 0.9 {
        diags.push(Diagnostic {
            rule_id: "L004".into(),
            finding_id: finding.id.clone(),
            message: format!(
                "Theoretical assertion with confidence {:.2} — unusually high for unvalidated theory",
                finding.confidence.score
            ),
            suggestion: "Theoretical findings typically warrant lower confidence until experimentally validated".into(),
            severity: Severity::Warning,
        });
    }
    diags
}

pub fn check_unreported_effect(finding: &FindingBundle) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    if finding.evidence.p_value.is_some() && finding.evidence.effect_size.is_none() {
        diags.push(Diagnostic {
            rule_id: "L005".into(),
            finding_id: finding.id.clone(),
            message: "P-value reported but effect size is missing".into(),
            suggestion: "Report effect size (Cohen's d, odds ratio, etc.) alongside p-value".into(),
            severity: Severity::Warning,
        });
    }
    diags
}

pub fn check_p_boundary(finding: &FindingBundle) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    if let Some(ref pv) = finding.evidence.p_value
        && let Some(p) = parse_p_value(pv)
        && (0.04..=0.06).contains(&p)
    {
        diags.push(Diagnostic {
            rule_id: "L006".into(),
            finding_id: finding.id.clone(),
            message: format!("P-value {:.4} is near the significance boundary", p),
            suggestion: "Consider this finding borderline; report exact p-value and effect size"
                .into(),
            severity: Severity::Info,
        });
    }
    diags
}

pub fn check_missing_controls(finding: &FindingBundle) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    if finding.evidence.evidence_type == "experimental" && !has_abstract_only_caveat(finding) {
        let method_lower = finding.evidence.method.to_lowercase();
        if !method_lower.contains("control")
            && !method_lower.contains("sham")
            && !method_lower.contains("vehicle")
            && !method_lower.contains("placebo")
        {
            diags.push(Diagnostic {
                rule_id: "L007".into(),
                finding_id: finding.id.clone(),
                message: "Experimental finding with no mention of controls in method".into(),
                suggestion: "Document the control condition used (vehicle, sham, placebo, etc.)"
                    .into(),
                severity: Severity::Warning,
            });
        }
    }
    diags
}

pub fn check_multiple_comparisons(finding: &FindingBundle) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    if finding.evidence.evidence_spans.len() > 3 {
        let method_lower = finding.evidence.method.to_lowercase();
        if !method_lower.contains("correction")
            && !method_lower.contains("bonferroni")
            && !method_lower.contains("holm")
            && !method_lower.contains("fdr")
            && !method_lower.contains("benjamini")
            && !method_lower.contains("tukey")
        {
            diags.push(Diagnostic {
                rule_id: "L008".into(),
                finding_id: finding.id.clone(),
                message: format!(
                    "{} evidence spans without mention of multiple comparison correction",
                    finding.evidence.evidence_spans.len()
                ),
                suggestion: "Apply Bonferroni, FDR, or other appropriate correction for multiple comparisons".into(),
                severity: Severity::Warning,
            });
        }
    }
    diags
}

pub fn check_cherry_picking(frontier: &Project) -> Vec<Diagnostic> {
    use std::collections::HashMap;

    let mut doi_findings: HashMap<String, Vec<&FindingBundle>> = HashMap::new();
    for f in &frontier.findings {
        if let Some(ref doi) = f.provenance.doi {
            doi_findings.entry(doi.clone()).or_default().push(f);
        }
    }

    let mut diags = Vec::new();
    for (doi, findings) in &doi_findings {
        if findings.len() < 2 {
            continue;
        }
        let has_significant = findings.iter().any(|f| {
            f.evidence
                .p_value
                .as_ref()
                .and_then(|pv| parse_p_value(pv))
                .is_some_and(|p| p < 0.05)
        });
        let has_nonsignificant = findings.iter().any(|f| {
            f.evidence
                .p_value
                .as_ref()
                .and_then(|pv| parse_p_value(pv))
                .is_some_and(|p| p >= 0.05)
        });
        if has_significant && has_nonsignificant {
            for f in findings {
                diags.push(Diagnostic {
                    rule_id: "L009".into(),
                    finding_id: f.id.clone(),
                    message: format!("DOI {} has findings with mixed significance", doi),
                    suggestion: "Verify all findings from this paper are reported, not just significant ones".into(),
                    severity: Severity::Warning,
                });
            }
        }
    }
    diags
}

pub fn check_wrong_test(finding: &FindingBundle) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    let method_lower = finding.evidence.method.to_lowercase();
    if method_lower.contains("t-test") || method_lower.contains("t test") {
        let assertion_lower = finding.assertion.text.to_lowercase();
        let multi_group = assertion_lower.contains("groups")
            || assertion_lower.contains("three")
            || assertion_lower.contains("four")
            || assertion_lower.contains("multiple")
            || assertion_lower.contains("several")
            || finding.assertion.entities.len() > 3;
        if multi_group {
            diags.push(Diagnostic {
                rule_id: "L010".into(),
                finding_id: finding.id.clone(),
                message: "T-test used but multiple groups appear to be compared".into(),
                suggestion: "Use ANOVA or Kruskal-Wallis for comparisons across >2 groups".into(),
                severity: Severity::Warning,
            });
        }
    }
    diags
}

/// v0.38.3: A `supports` link from finding A to finding B asserts
/// that A's evidence reinforces B's claim. When both findings carry
/// causal typing, the link is only epistemically valid if A's claim
/// is at least as strong as B's. A correlation claim cannot support
/// an intervention claim — that's a textbook category error.
///
/// Strength order: Correlation < Mediation < Intervention.
/// Findings with `causal_claim = None` are skipped (the link may be
/// fine; the kernel doesn't yet know).
pub fn check_causal_mismatch_on_supports(frontier: &Project) -> Vec<Diagnostic> {
    use std::collections::HashMap;
    use vela_protocol::bundle::CausalClaim;

    let claim_rank = |c: CausalClaim| -> u32 {
        match c {
            CausalClaim::Correlation => 1,
            CausalClaim::Mediation => 2,
            CausalClaim::Intervention => 3,
        }
    };
    let claim_name = |c: CausalClaim| -> &'static str {
        match c {
            CausalClaim::Correlation => "correlation",
            CausalClaim::Mediation => "mediation",
            CausalClaim::Intervention => "intervention",
        }
    };

    let by_id: HashMap<&str, &FindingBundle> = frontier
        .findings
        .iter()
        .map(|f| (f.id.as_str(), f))
        .collect();

    let mut diags = Vec::new();
    for source in &frontier.findings {
        let Some(source_claim) = source.assertion.causal_claim else {
            continue;
        };
        for link in &source.links {
            if link.link_type != "supports" {
                continue;
            }
            let Some(target) = by_id.get(link.target.as_str()) else {
                continue; // cross-frontier link or unresolved; not our concern here
            };
            let Some(target_claim) = target.assertion.causal_claim else {
                continue;
            };
            if claim_rank(source_claim) < claim_rank(target_claim) {
                diags.push(Diagnostic {
                    rule_id: "L011".into(),
                    finding_id: source.id.clone(),
                    message: format!(
                        "{src} (claim: {sc}) supports→ {tgt} (claim: {tc}); the source's design cannot bear the target's causal weight",
                        src = source.id,
                        sc = claim_name(source_claim),
                        tgt = target.id,
                        tc = claim_name(target_claim),
                    ),
                    suggestion: format!(
                        "Either re-grade {src} to {tc} (with appropriate evidence) or re-type the link from `supports` to `correlates_with` / `extends` / a weaker relationship.",
                        src = source.id,
                        tc = claim_name(target_claim),
                    ),
                    severity: Severity::Warning,
                });
            }
        }
    }
    diags
}

/// Structural graph linter — finds orphans, unresolved contradictions, fragile anchors,
/// critical gaps, missing cross-references, and stale superseded findings.
pub fn lint_frontier(frontier: &Project) -> LintReport {
    use std::collections::{HashMap, HashSet};

    let mut diagnostics = Vec::new();
    let finding_count = frontier.findings.len();

    // Build lookup structures
    let finding_ids: HashSet<&str> = frontier.findings.iter().map(|f| f.id.as_str()).collect();
    // Map from finding ID to the finding itself
    let finding_map: HashMap<&str, &FindingBundle> = frontier
        .findings
        .iter()
        .map(|f| (f.id.as_str(), f))
        .collect();

    // Inbound link count: how many other findings link TO each finding
    let mut inbound_count: HashMap<&str, usize> = HashMap::new();
    // Outbound links by type
    let mut contradiction_pairs: Vec<(&str, &str)> = Vec::new();
    let mut superseded_targets: HashSet<&str> = HashSet::new();
    // Dependent count: how many findings link TO this finding (any type)
    let mut dependent_count: HashMap<&str, usize> = HashMap::new();

    for f in &frontier.findings {
        for link in &f.links {
            if finding_ids.contains(link.target.as_str()) {
                *inbound_count.entry(link.target.as_str()).or_insert(0) += 1;
                *dependent_count.entry(link.target.as_str()).or_insert(0) += 1;

                if link.link_type == "contradicts" {
                    contradiction_pairs.push((f.id.as_str(), link.target.as_str()));
                }
                if link.link_type == "supersedes" {
                    superseded_targets.insert(link.target.as_str());
                }
            }
        }
    }

    // 1. Orphan findings — zero inbound links
    for f in &frontier.findings {
        if inbound_count.get(f.id.as_str()).copied().unwrap_or(0) == 0 {
            diagnostics.push(Diagnostic {
                rule_id: "orphan".into(),
                finding_id: f.id.clone(),
                message: "Finding has no inbound links — may be disconnected from the graph".into(),
                suggestion:
                    "Consider linking this finding to related findings, or mark as a seed finding"
                        .into(),
                severity: Severity::Info,
            });
        }
    }

    // 2. Unresolved contradictions — contradicts link where neither finding is retracted
    for (id_a, id_b) in &contradiction_pairs {
        let a = finding_map.get(id_a);
        let b = finding_map.get(id_b);
        if let (Some(a), Some(b)) = (a, b)
            && !a.flags.retracted
            && !b.flags.retracted
        {
            let reviewed_tension = a.flags.contested
                || b.flags.contested
                || a.flags.review_state.is_some()
                || b.flags.review_state.is_some();
            diagnostics.push(Diagnostic {
                    rule_id: "unresolved_contradiction".into(),
                    finding_id: id_a.to_string(),
                    message: format!("Contradiction between {} and {} has no resolution", id_a, id_b),
                    suggestion: "Review both findings and either retract one, adjust confidence, or add a resolution note".into(),
                    severity: if reviewed_tension { Severity::Info } else { Severity::Warning },
                });
        }
    }

    // 3. High-dependency gaps — gap findings with many dependents
    for f in &frontier.findings {
        if f.flags.gap {
            let deps = dependent_count.get(f.id.as_str()).copied().unwrap_or(0);
            if deps > 0 {
                diagnostics.push(Diagnostic {
                    rule_id: "critical_gap".into(),
                    finding_id: f.id.clone(),
                    message: format!(
                        "Gap finding has {} dependents — high-value experiment target",
                        deps
                    ),
                    suggestion: format!("Prioritize investigating this gap: {}", f.assertion.text),
                    severity: Severity::Info,
                });
            }
        }
    }

    // 4. Low-confidence anchors — confidence < 0.6 with > 5 dependents
    for f in &frontier.findings {
        if f.confidence.score < 0.6 {
            let deps = dependent_count.get(f.id.as_str()).copied().unwrap_or(0);
            if deps > 5 {
                let severity = if has_abstract_only_caveat(f) {
                    Severity::Info
                } else {
                    Severity::Warning
                };
                diagnostics.push(Diagnostic {
                    rule_id: "fragile_anchor".into(),
                    finding_id: f.id.clone(),
                    message: format!("Low-confidence finding ({:.2}) supports {} other findings", f.confidence.score, deps),
                    suggestion: "This finding is a fragile anchor — seek replication or higher-quality evidence".into(),
                    severity,
                });
            }
        }
    }

    // 5. Missing entity links — entities in 3+ findings with no links between those findings
    let mut entity_findings: HashMap<String, Vec<&str>> = HashMap::new();
    for f in &frontier.findings {
        for entity in &f.assertion.entities {
            let key = entity.name.to_lowercase();
            entity_findings.entry(key).or_default().push(f.id.as_str());
        }
    }

    for (entity_name, fids) in &entity_findings {
        if fids.len() >= 3 {
            // Check if any pair of these findings is linked
            let fid_set: HashSet<&str> = fids.iter().copied().collect();
            let mut has_any_link = false;
            'outer: for &fid in fids {
                if let Some(f) = finding_map.get(fid) {
                    for link in &f.links {
                        if fid_set.contains(link.target.as_str()) {
                            has_any_link = true;
                            break 'outer;
                        }
                    }
                }
            }
            if !has_any_link {
                // Find the original-case name from the first finding that has it
                let display_name = frontier
                    .findings
                    .iter()
                    .flat_map(|f| f.assertion.entities.iter())
                    .find(|e| e.name.to_lowercase() == *entity_name)
                    .map(|e| e.name.clone())
                    .unwrap_or_else(|| entity_name.clone());

                diagnostics.push(Diagnostic {
                    rule_id: "missing_crossref".into(),
                    finding_id: fids[0].to_string(),
                    message: format!(
                        "Entity '{}' appears in {} findings with no links between them",
                        display_name,
                        fids.len()
                    ),
                    suggestion: format!(
                        "Consider adding typed links between findings that share entity '{}'",
                        display_name
                    ),
                    severity: Severity::Info,
                });
            }
        }
    }

    // 6. Stale superseded findings — superseded but not retracted or low-confidence
    for &target_id in &superseded_targets {
        if let Some(f) = finding_map.get(target_id)
            && !f.flags.retracted
            && f.confidence.score >= 0.6
        {
            diagnostics.push(Diagnostic {
                rule_id: "stale_superseded".into(),
                finding_id: target_id.to_string(),
                message: "Finding has been superseded but confidence hasn't been adjusted".into(),
                suggestion: "Lower confidence or mark as superseded".into(),
                severity: Severity::Warning,
            });
        }
    }

    let errors = diagnostics
        .iter()
        .filter(|d| d.severity == Severity::Error)
        .count();
    let warnings = diagnostics
        .iter()
        .filter(|d| d.severity == Severity::Warning)
        .count();
    let infos = diagnostics
        .iter()
        .filter(|d| d.severity == Severity::Info)
        .count();

    LintReport {
        diagnostics,
        findings_checked: finding_count,
        errors,
        warnings,
        infos,
    }
}

/// Run all lint checks on a frontier, with optional rule and severity filters.
pub fn lint(
    frontier: &Project,
    rule_filter: Option<&str>,
    severity_filter: Option<&str>,
) -> LintReport {
    let rules = all_rules();
    let severity_threshold: Option<Severity> = severity_filter.and_then(|s| s.parse().ok());

    let mut diagnostics = Vec::new();

    // Per-finding checks
    for finding in &frontier.findings {
        let mut finding_diags = Vec::new();
        finding_diags.extend(check_sample_size(finding));
        finding_diags.extend(check_no_replication(finding));
        finding_diags.extend(check_missing_species(finding));
        finding_diags.extend(check_confidence_mismatch(finding));
        finding_diags.extend(check_unreported_effect(finding));
        finding_diags.extend(check_p_boundary(finding));
        finding_diags.extend(check_missing_controls(finding));
        finding_diags.extend(check_multiple_comparisons(finding));
        finding_diags.extend(check_wrong_test(finding));
        diagnostics.extend(finding_diags);
    }

    // Project-level checks
    diagnostics.extend(check_cherry_picking(frontier));
    diagnostics.extend(check_causal_mismatch_on_supports(frontier));

    // Apply filters
    if let Some(rule_id) = rule_filter {
        // Match by rule ID or name
        let matching_ids: Vec<&str> = rules
            .iter()
            .filter(|r| r.id == rule_id || r.name == rule_id)
            .map(|r| r.id.as_str())
            .collect();
        diagnostics.retain(|d| matching_ids.contains(&d.rule_id.as_str()));
    }

    if let Some(ref sev) = severity_threshold {
        diagnostics.retain(|d| d.severity == *sev);
    }

    let errors = diagnostics
        .iter()
        .filter(|d| d.severity == Severity::Error)
        .count();
    let warnings = diagnostics
        .iter()
        .filter(|d| d.severity == Severity::Warning)
        .count();
    let infos = diagnostics
        .iter()
        .filter(|d| d.severity == Severity::Info)
        .count();

    LintReport {
        diagnostics,
        findings_checked: frontier.findings.len(),
        errors,
        warnings,
        infos,
    }
}

/// Print a lint report to stdout.
pub fn print_report(report: &LintReport) {
    if report.diagnostics.is_empty() {
        println!(
            "No issues found across {} findings.",
            report.findings_checked
        );
        return;
    }

    for d in &report.diagnostics {
        let severity_str = match d.severity {
            Severity::Error => "ERROR",
            Severity::Warning => "WARN ",
            Severity::Info => "INFO ",
        };
        println!(
            "[{}] {} ({}): {}",
            severity_str, d.finding_id, d.rule_id, d.message
        );
        println!("       suggestion: {}", d.suggestion);
    }

    println!(
        "\n{} findings checked: {} errors, {} warnings, {} info",
        report.findings_checked, report.errors, report.warnings, report.infos,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use vela_protocol::bundle::*;

    fn make_finding(id: &str) -> FindingBundle {
        FindingBundle {
            id: id.to_string(),
            version: 1,
            previous_version: None,
            assertion: Assertion {
                text: "Test assertion".into(),
                assertion_type: "mechanism".into(),
                entities: vec![],
                relation: None,
                direction: Some("positive".into()),
                causal_claim: None,
                causal_evidence_grade: None,
            },
            evidence: Evidence {
                evidence_type: "experimental".into(),
                model_system: "cell_culture".into(),
                species: Some("Homo sapiens".into()),
                method: "Western blot with control group".into(),
                sample_size: Some("n=30".into()),
                effect_size: Some("d=0.8".into()),
                p_value: Some("p=0.01".into()),
                replicated: true,
                replication_count: Some(2),
                evidence_spans: vec![],
            },
            conditions: Conditions {
                text: "Standard conditions".into(),
                species_verified: vec!["Homo sapiens".into()],
                species_unverified: vec![],
                in_vitro: true,
                in_vivo: false,
                human_data: false,
                clinical_trial: false,
                concentration_range: None,
                duration: None,
                age_group: None,
                cell_type: None,
            },
            confidence: Confidence::raw(0.75, "experimental evidence", 0.9),
            provenance: Provenance {
                source_type: "published_paper".into(),
                doi: Some("10.1234/test".into()),
                pmid: None,
                pmc: None,
                openalex_id: None,
                url: None,
                title: "Test paper".into(),
                authors: vec![],
                year: Some(2024),
                journal: Some("Test Journal".into()),
                license: None,
                publisher: None,
                funders: vec![],
                extraction: Extraction::default(),
                review: None,
                citation_count: None,
            },
            flags: Flags {
                gap: false,
                negative_space: false,
                contested: false,
                retracted: false,
                declining: false,
                gravity_well: false,
                review_state: None,
                superseded: false,
                signature_threshold: None,
                jointly_accepted: false,
            },
            links: vec![],
            annotations: vec![],
            attachments: vec![],
            created: "2024-01-01T00:00:00Z".into(),
            updated: None,

            access_tier: vela_protocol::access_tier::AccessTier::Public,
        }
    }

    fn make_frontier(findings: Vec<FindingBundle>) -> Project {
        use std::collections::HashMap;
        use vela_protocol::project::*;
        Project {
            vela_version: "0.1.0".into(),
            schema: "vela/finding-bundle/0.1.0".into(),
            frontier_id: None,
            project: ProjectMeta {
                name: "test".into(),
                description: "test frontier".into(),
                compiled_at: "2024-01-01T00:00:00Z".into(),
                compiler: "vela/0.2.0".into(),
                papers_processed: 1,
                errors: 0,
                dependencies: vec![],
            },
            stats: ProjectStats {
                findings: findings.len(),
                links: 0,
                replicated: 0,
                unreplicated: 0,
                avg_confidence: 0.7,
                gaps: 0,
                negative_space: 0,
                contested: 0,
                categories: HashMap::new(),
                link_types: HashMap::new(),
                human_reviewed: 0,
                agent_reviewed: 0,
                review_event_count: 0,
                confidence_update_count: 0,
                event_count: 0,
                source_count: 0,
                evidence_atom_count: 0,
                condition_record_count: 0,
                proposal_count: 0,
                confidence_distribution: ConfidenceDistribution {
                    high_gt_80: 0,
                    medium_60_80: 0,
                    low_lt_60: 0,
                },
            },
            findings,
            sources: vec![],
            evidence_atoms: vec![],
            condition_records: vec![],
            review_events: vec![],
            confidence_updates: vec![],
            events: vec![],
            proposals: vec![],
            proof_state: Default::default(),
            signatures: vec![],
            actors: Vec::new(),
            replications: Vec::new(),
            datasets: Vec::new(),
            code_artifacts: Vec::new(),
            artifacts: Vec::new(),
            predictions: Vec::new(),
            resolutions: Vec::new(),
            peers: vec![],
            negative_results: vec![],
            trajectories: vec![],
            released_diff_packs: vec![],
            verdict_conflicts: vec![],
            contradictions: vec![],
            verifier_attachments: vec![],
            attempts: vec![],
            attempt_resolutions: vec![],
            transfers: vec![],
            endorsements: vec![],
            statement_attestations: vec![],
            attempt_claims: vec![],
            statement_registrations: vec![],
        }
    }

    #[test]
    fn all_rules_count() {
        assert_eq!(all_rules().len(), 11);
    }

    #[test]
    fn check_sample_size_small() {
        let mut f = make_finding("vf_001");
        f.evidence.sample_size = Some("n=5".into());
        let diags = check_sample_size(&f);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].rule_id, "L001");
    }

    #[test]
    fn check_sample_size_adequate() {
        let f = make_finding("vf_002"); // n=30
        let diags = check_sample_size(&f);
        assert!(diags.is_empty());
    }

    #[test]
    fn check_no_replication_high_confidence() {
        let mut f = make_finding("vf_003");
        f.confidence.score = 0.9;
        f.evidence.replicated = false;
        let diags = check_no_replication(&f);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].rule_id, "L002");
    }

    #[test]
    fn check_no_replication_ok() {
        let mut f = make_finding("vf_004");
        f.confidence.score = 0.9;
        f.evidence.replicated = true;
        let diags = check_no_replication(&f);
        assert!(diags.is_empty());
    }

    #[test]
    fn check_missing_species_experimental() {
        let mut f = make_finding("vf_005");
        f.evidence.species = None;
        let diags = check_missing_species(&f);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].rule_id, "L003");
    }

    #[test]
    fn check_confidence_mismatch_theoretical() {
        let mut f = make_finding("vf_006");
        f.assertion.assertion_type = "theoretical".into();
        f.confidence.score = 0.95;
        let diags = check_confidence_mismatch(&f);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].rule_id, "L004");
    }

    #[test]
    fn check_unreported_effect_size() {
        let mut f = make_finding("vf_007");
        f.evidence.p_value = Some("p=0.01".into());
        f.evidence.effect_size = None;
        let diags = check_unreported_effect(&f);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].rule_id, "L005");
    }

    #[test]
    fn check_p_boundary_near() {
        let mut f = make_finding("vf_008");
        f.evidence.p_value = Some("p=0.049".into());
        let diags = check_p_boundary(&f);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].rule_id, "L006");
    }

    #[test]
    fn check_p_boundary_clear() {
        let mut f = make_finding("vf_009");
        f.evidence.p_value = Some("p=0.001".into());
        let diags = check_p_boundary(&f);
        assert!(diags.is_empty());
    }

    #[test]
    fn check_missing_controls_no_mention() {
        let mut f = make_finding("vf_010");
        f.evidence.method = "Western blot".into();
        let diags = check_missing_controls(&f);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].rule_id, "L007");
    }

    #[test]
    fn check_multiple_comparisons_many_spans() {
        let mut f = make_finding("vf_011");
        f.evidence.evidence_spans = vec![
            serde_json::json!("span1"),
            serde_json::json!("span2"),
            serde_json::json!("span3"),
            serde_json::json!("span4"),
        ];
        f.evidence.method = "ANOVA".into();
        let diags = check_multiple_comparisons(&f);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].rule_id, "L008");
    }

    #[test]
    fn check_multiple_comparisons_with_correction() {
        let mut f = make_finding("vf_012");
        f.evidence.evidence_spans = vec![
            serde_json::json!("span1"),
            serde_json::json!("span2"),
            serde_json::json!("span3"),
            serde_json::json!("span4"),
        ];
        f.evidence.method = "ANOVA with Bonferroni correction".into();
        let diags = check_multiple_comparisons(&f);
        assert!(diags.is_empty());
    }

    #[test]
    fn check_wrong_test_multiple_groups() {
        let mut f = make_finding("vf_013");
        f.evidence.method = "Student's t-test".into();
        f.assertion.text = "Comparison across three groups shows difference".into();
        let diags = check_wrong_test(&f);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].rule_id, "L010");
    }

    #[test]
    fn check_cherry_picking_mixed_significance() {
        let mut f1 = make_finding("vf_014a");
        f1.provenance.doi = Some("10.1234/mixed".into());
        f1.evidence.p_value = Some("p=0.01".into());

        let mut f2 = make_finding("vf_014b");
        f2.provenance.doi = Some("10.1234/mixed".into());
        f2.evidence.p_value = Some("p=0.15".into());

        let frontier = make_frontier(vec![f1, f2]);
        let diags = check_cherry_picking(&frontier);
        assert_eq!(diags.len(), 2);
        assert!(diags.iter().all(|d| d.rule_id == "L009"));
    }

    #[test]
    fn lint_with_rule_filter() {
        let mut f = make_finding("vf_015");
        f.evidence.sample_size = Some("n=3".into());
        f.evidence.species = None;
        let frontier = make_frontier(vec![f]);
        let report = lint(&frontier, Some("L001"), None);
        assert!(report.diagnostics.iter().all(|d| d.rule_id == "L001"));
    }

    #[test]
    fn lint_with_severity_filter() {
        let mut f = make_finding("vf_016");
        f.evidence.p_value = Some("p=0.05".into());
        f.evidence.effect_size = None;
        let frontier = make_frontier(vec![f]);
        let report = lint(&frontier, None, Some("info"));
        assert!(
            report
                .diagnostics
                .iter()
                .all(|d| d.severity == Severity::Info)
        );
    }

    #[test]
    fn lint_clean_finding() {
        let f = make_finding("vf_clean");
        let frontier = make_frontier(vec![f]);
        let report = lint(&frontier, None, None);
        assert_eq!(report.errors, 0);
        assert_eq!(report.warnings, 0);
    }

    #[test]
    fn parse_sample_size_variants() {
        assert_eq!(parse_sample_size("n=24"), Some(24));
        assert_eq!(parse_sample_size("24 patients"), Some(24));
        assert_eq!(parse_sample_size("5"), Some(5));
        assert_eq!(parse_sample_size("n=100"), Some(100));
    }

    #[test]
    fn parse_p_value_variants() {
        assert!((parse_p_value("p=0.05").unwrap() - 0.05).abs() < 0.001);
        assert!((parse_p_value("p<0.001").unwrap() - 0.001).abs() < 0.0001);
        assert!((parse_p_value("0.03").unwrap() - 0.03).abs() < 0.001);
    }

    // ── lint_frontier (structural graph linter) tests ─────────────────

    #[test]
    fn lint_frontier_orphan_findings() {
        let f1 = make_finding("vf_a");
        let mut f2 = make_finding("vf_b");
        // f2 links to f1, so f1 has an inbound link but f2 does not
        f2.links.push(vela_protocol::bundle::Link {
            target: "vf_a".into(),
            link_type: "supports".into(),
            note: "".into(),
            inferred_by: "compiler".into(),
            created_at: "".into(),
            mechanism: None,
        });
        let frontier = make_frontier(vec![f1, f2]);
        let report = lint_frontier(&frontier);
        let orphans: Vec<_> = report
            .diagnostics
            .iter()
            .filter(|d| d.rule_id == "orphan")
            .collect();
        // f2 has no inbound links -> orphan
        assert!(orphans.iter().any(|d| d.finding_id == "vf_b"));
        // f1 has an inbound link from f2 -> not orphan
        assert!(!orphans.iter().any(|d| d.finding_id == "vf_a"));
    }

    #[test]
    fn lint_frontier_unresolved_contradiction() {
        let mut f1 = make_finding("vf_c");
        let f2 = make_finding("vf_d");
        f1.links.push(vela_protocol::bundle::Link {
            target: "vf_d".into(),
            link_type: "contradicts".into(),
            note: "".into(),
            inferred_by: "compiler".into(),
            created_at: "".into(),
            mechanism: None,
        });
        let frontier = make_frontier(vec![f1, f2]);
        let report = lint_frontier(&frontier);
        let contras: Vec<_> = report
            .diagnostics
            .iter()
            .filter(|d| d.rule_id == "unresolved_contradiction")
            .collect();
        assert_eq!(contras.len(), 1);
        assert!(contras[0].message.contains("vf_c"));
        assert!(contras[0].message.contains("vf_d"));
    }

    #[test]
    fn lint_frontier_resolved_contradiction_no_warning() {
        let mut f1 = make_finding("vf_e");
        let mut f2 = make_finding("vf_f");
        f1.links.push(vela_protocol::bundle::Link {
            target: "vf_f".into(),
            link_type: "contradicts".into(),
            note: "".into(),
            inferred_by: "compiler".into(),
            created_at: "".into(),
            mechanism: None,
        });
        f2.flags.retracted = true;
        let frontier = make_frontier(vec![f1, f2]);
        let report = lint_frontier(&frontier);
        let contras: Vec<_> = report
            .diagnostics
            .iter()
            .filter(|d| d.rule_id == "unresolved_contradiction")
            .collect();
        assert_eq!(contras.len(), 0);
    }

    #[test]
    fn lint_frontier_critical_gap() {
        let mut gap = make_finding("vf_gap");
        gap.flags.gap = true;
        let mut f1 = make_finding("vf_dep1");
        f1.links.push(vela_protocol::bundle::Link {
            target: "vf_gap".into(),
            link_type: "supports".into(),
            note: "".into(),
            inferred_by: "compiler".into(),
            created_at: "".into(),
            mechanism: None,
        });
        let frontier = make_frontier(vec![gap, f1]);
        let report = lint_frontier(&frontier);
        let gaps: Vec<_> = report
            .diagnostics
            .iter()
            .filter(|d| d.rule_id == "critical_gap")
            .collect();
        assert_eq!(gaps.len(), 1);
        assert!(gaps[0].message.contains("1 dependents"));
        assert_eq!(gaps[0].severity, Severity::Info);
    }

    #[test]
    fn lint_frontier_fragile_anchor() {
        let mut anchor = make_finding("vf_anchor");
        anchor.confidence.score = 0.4;
        // Need > 5 dependents
        let mut findings = vec![anchor];
        for i in 0..6 {
            let mut f = make_finding(&format!("vf_dep_{}", i));
            f.links.push(vela_protocol::bundle::Link {
                target: "vf_anchor".into(),
                link_type: "supports".into(),
                note: "".into(),
                inferred_by: "compiler".into(),
                created_at: "".into(),
                mechanism: None,
            });
            findings.push(f);
        }
        let frontier = make_frontier(findings);
        let report = lint_frontier(&frontier);
        let fragile: Vec<_> = report
            .diagnostics
            .iter()
            .filter(|d| d.rule_id == "fragile_anchor")
            .collect();
        assert_eq!(fragile.len(), 1);
        assert!(fragile[0].message.contains("0.40"));
        assert!(fragile[0].message.contains("6 other findings"));
    }

    #[test]
    fn lint_frontier_missing_crossref() {
        // Three findings sharing entity "NLRP3" with no links between them
        let entity = Entity {
            name: "NLRP3".into(),
            entity_type: "protein".into(),
            identifiers: serde_json::Map::new(),
            canonical_id: None,
            candidates: vec![],
            aliases: vec![],
            resolution_provenance: None,
            resolution_confidence: 1.0,
            resolution_method: None,
            species_context: None,
            needs_review: false,
        };
        let mut f1 = make_finding("vf_x1");
        f1.assertion.entities = vec![entity.clone()];
        let mut f2 = make_finding("vf_x2");
        f2.assertion.entities = vec![entity.clone()];
        let mut f3 = make_finding("vf_x3");
        f3.assertion.entities = vec![entity.clone()];
        let frontier = make_frontier(vec![f1, f2, f3]);
        let report = lint_frontier(&frontier);
        let missing: Vec<_> = report
            .diagnostics
            .iter()
            .filter(|d| d.rule_id == "missing_crossref")
            .collect();
        assert_eq!(missing.len(), 1);
        assert!(missing[0].message.contains("NLRP3"));
        assert!(missing[0].message.contains("3 findings"));
    }

    #[test]
    fn lint_frontier_stale_superseded() {
        let mut f1 = make_finding("vf_new");
        let f2 = make_finding("vf_old");
        // f1 supersedes f2
        f1.links.push(vela_protocol::bundle::Link {
            target: "vf_old".into(),
            link_type: "supersedes".into(),
            note: "".into(),
            inferred_by: "compiler".into(),
            created_at: "".into(),
            mechanism: None,
        });
        // f2 is not retracted and confidence >= 0.6 -> stale
        let frontier = make_frontier(vec![f1, f2]);
        let report = lint_frontier(&frontier);
        let stale: Vec<_> = report
            .diagnostics
            .iter()
            .filter(|d| d.rule_id == "stale_superseded")
            .collect();
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].finding_id, "vf_old");
    }

    #[test]
    fn lint_frontier_clean_frontier() {
        // Single finding with no structural issues beyond being an orphan
        let f = make_finding("vf_clean2");
        let frontier = make_frontier(vec![f]);
        let report = lint_frontier(&frontier);
        // Only diagnostic should be orphan (single finding, no inbound links)
        assert!(report.diagnostics.iter().all(|d| d.rule_id == "orphan"));
        assert_eq!(report.errors, 0);
        assert_eq!(report.warnings, 0);
    }

    // ── v0.38.3 causal-mismatch lint tests ────────────────────────────

    fn link_supports(target: &str) -> Link {
        Link {
            target: target.into(),
            link_type: "supports".into(),
            note: String::new(),
            inferred_by: "test".into(),
            created_at: String::new(),
            mechanism: None,
        }
    }

    #[test]
    fn correlation_supports_intervention_flagged() {
        let mut weak = make_finding("vf_weak");
        weak.assertion.causal_claim = Some(CausalClaim::Correlation);
        let mut strong = make_finding("vf_strong");
        strong.assertion.causal_claim = Some(CausalClaim::Intervention);
        weak.links.push(link_supports("vf_strong"));
        let frontier = make_frontier(vec![weak, strong]);
        let diags = check_causal_mismatch_on_supports(&frontier);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].rule_id, "L011");
        assert_eq!(diags[0].finding_id, "vf_weak");
    }

    #[test]
    fn correlation_supports_correlation_clean() {
        let mut a = make_finding("vf_a");
        a.assertion.causal_claim = Some(CausalClaim::Correlation);
        let mut b = make_finding("vf_b");
        b.assertion.causal_claim = Some(CausalClaim::Correlation);
        a.links.push(link_supports("vf_b"));
        let frontier = make_frontier(vec![a, b]);
        let diags = check_causal_mismatch_on_supports(&frontier);
        assert_eq!(diags.len(), 0);
    }

    #[test]
    fn intervention_supports_correlation_clean() {
        // Stronger evidence supports a weaker claim — fine.
        let mut a = make_finding("vf_a");
        a.assertion.causal_claim = Some(CausalClaim::Intervention);
        let mut b = make_finding("vf_b");
        b.assertion.causal_claim = Some(CausalClaim::Correlation);
        a.links.push(link_supports("vf_b"));
        let frontier = make_frontier(vec![a, b]);
        let diags = check_causal_mismatch_on_supports(&frontier);
        assert_eq!(diags.len(), 0);
    }

    #[test]
    fn ungraded_findings_skipped() {
        // No causal_claim on either side → can't decide; skip silently.
        let mut a = make_finding("vf_a");
        a.assertion.causal_claim = None;
        let mut b = make_finding("vf_b");
        b.assertion.causal_claim = Some(CausalClaim::Intervention);
        a.links.push(link_supports("vf_b"));
        let frontier = make_frontier(vec![a, b]);
        let diags = check_causal_mismatch_on_supports(&frontier);
        assert_eq!(diags.len(), 0);
    }

    #[test]
    fn non_supports_link_types_ignored() {
        // contradicts / extends / depends links are not the lint target.
        let mut a = make_finding("vf_a");
        a.assertion.causal_claim = Some(CausalClaim::Correlation);
        let mut b = make_finding("vf_b");
        b.assertion.causal_claim = Some(CausalClaim::Intervention);
        a.links.push(Link {
            target: "vf_b".into(),
            link_type: "contradicts".into(),
            note: String::new(),
            inferred_by: "test".into(),
            created_at: String::new(),
            mechanism: None,
        });
        let frontier = make_frontier(vec![a, b]);
        let diags = check_causal_mismatch_on_supports(&frontier);
        assert_eq!(diags.len(), 0);
    }

    #[test]
    fn mediation_supports_intervention_flagged() {
        let mut med = make_finding("vf_med");
        med.assertion.causal_claim = Some(CausalClaim::Mediation);
        let mut iv = make_finding("vf_iv");
        iv.assertion.causal_claim = Some(CausalClaim::Intervention);
        med.links.push(link_supports("vf_iv"));
        let frontier = make_frontier(vec![med, iv]);
        let diags = check_causal_mismatch_on_supports(&frontier);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].rule_id, "L011");
    }
}
