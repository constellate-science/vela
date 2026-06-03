//! v0.35: Consensus aggregation — the inference layer.
//!
//! Given a target finding, the kernel can find other findings making
//! similar claims, weight them by evidence quality (replication
//! count, review state, time decay), and return a consensus
//! confidence with a credible interval.
//!
//! This is what turns Vela from "a database of claims" into "a
//! reasoning surface over claims." Other parts of the substrate
//! describe what's *believed* (findings) and what's *expected*
//! (predictions). This module describes what the *field* collectively
//! holds — derived deterministically from canonical state, never
//! stored.
//!
//! Doctrine: aggregation is a derived view, not a kernel object.
//! Same input frontier → same consensus result, byte-for-byte.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::bundle::{CausalClaim, CausalEvidenceGrade, FindingBundle};
use crate::project::Project;

/// v0.38.2: filter constraints for consensus aggregation. Consensus
/// computed without a filter blends all claim-similar findings —
/// fine when "what does the field hold?" is the question, but wrong
/// when the question is specifically "what does the field hold *as
/// causation*?" or "what's the consensus among RCT-grade evidence?"
///
/// `None` for any field means no constraint; the default value of
/// `Filter::default()` is the pre-v0.38.2 behavior.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AggregateFilter {
    /// Only include findings whose `causal_claim` matches. `None`
    /// includes all (including unset claims).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub causal_claim: Option<CausalClaim>,
    /// Minimum study-design grade. Findings with `causal_evidence_grade`
    /// strictly weaker than this are excluded. `None` includes all
    /// (including unset grades). Ordering: Theoretical < Observational
    /// < QuasiExperimental < Rct.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub causal_grade_min: Option<CausalEvidenceGrade>,
}

/// Total order on `CausalEvidenceGrade` for the `causal_grade_min`
/// filter. Higher value means stronger study design.
fn grade_rank(g: CausalEvidenceGrade) -> u32 {
    match g {
        CausalEvidenceGrade::Theoretical => 1,
        CausalEvidenceGrade::Observational => 2,
        CausalEvidenceGrade::QuasiExperimental => 3,
        CausalEvidenceGrade::Rct => 4,
    }
}

fn passes_filter(f: &FindingBundle, filter: &AggregateFilter) -> bool {
    if let Some(want) = filter.causal_claim
        && f.assertion.causal_claim != Some(want)
    {
        return false;
    }
    if let Some(min) = filter.causal_grade_min {
        match f.assertion.causal_evidence_grade {
            None => return false, // ungraded findings can't satisfy a min
            Some(g) if grade_rank(g) < grade_rank(min) => return false,
            _ => {}
        }
    }
    true
}

/// How candidate findings are weighted when computing consensus.
///
/// `Unweighted`: every matching finding contributes equally. Good for
/// counting how many independent assertions exist.
/// `ReplicationWeighted`: each finding's weight scales with the
/// number of successful (or failed) replications referencing it as
/// `target_finding`. Failed replications subtract weight; successful
/// ones add weight. The substrate move that makes well-replicated
/// claims dominate consensus over freshly-asserted ones.
/// `CitationWeighted`: weight scales with `provenance.citation_count`.
/// Useful when most findings carry real citation counts; falls back
/// to unweighted otherwise.
/// `Composite`: weighted blend of the three above, currently in
/// fixed proportions (`replication 0.5 + citation 0.3 + base 0.2`).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WeightingScheme {
    Unweighted,
    ReplicationWeighted,
    CitationWeighted,
    Composite,
}

impl WeightingScheme {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "unweighted" | "uniform" => Ok(WeightingScheme::Unweighted),
            "replication" | "replication_weighted" => Ok(WeightingScheme::ReplicationWeighted),
            "citation" | "citation_weighted" => Ok(WeightingScheme::CitationWeighted),
            "composite" | "default" => Ok(WeightingScheme::Composite),
            _ => Err(format!(
                "unknown weighting scheme `{s}`; valid: unweighted | replication | citation | composite"
            )),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            WeightingScheme::Unweighted => "unweighted",
            WeightingScheme::ReplicationWeighted => "replication_weighted",
            WeightingScheme::CitationWeighted => "citation_weighted",
            WeightingScheme::Composite => "composite",
        }
    }
}

/// One finding's contribution to a consensus result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusConstituent {
    pub finding_id: String,
    pub assertion_text: String,
    /// Original `Confidence.score` from the finding, before any
    /// adjustments.
    pub raw_score: f64,
    /// `raw_score` after replication / review-state adjustments.
    /// `>= raw_score` if the finding has successful replications,
    /// `< raw_score` if the finding is contested or has failed
    /// replications.
    pub adjusted_score: f64,
    /// Final weight in the consensus computation.
    pub weight: f64,
    /// Number of `Replication` records targeting this finding,
    /// broken down by outcome. Useful for the rendering layer.
    pub n_replications: usize,
    pub n_replicated: usize,
    pub n_failed_replications: usize,
}

/// Derived consensus over claim-similar findings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusResult {
    /// `vf_<id>` of the target finding the consensus is anchored to.
    pub target: String,
    /// The target finding's assertion text, for display.
    pub target_assertion: String,
    /// Number of findings (including the target) that contributed.
    pub n_findings: usize,
    /// Weighted-mean confidence on `[0, 1]`.
    pub consensus_confidence: f64,
    /// 95% credible interval over the weighted distribution.
    pub credible_interval_lo: f64,
    pub credible_interval_hi: f64,
    /// Each constituent finding with its weight + adjusted score.
    pub constituents: Vec<ConsensusConstituent>,
    /// Name of the weighting scheme used.
    pub weighting: String,
    /// v0.38.2: filter applied to neighbor findings before similarity
    /// computation. `None` (the v0.35–v0.38.1 default) means no
    /// filter; everything similar contributes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<AggregateFilter>,
}

/// Compute consensus over findings similar to `target_id`.
///
/// "Similar" means: shares ≥ 1 named entity with the target's
/// assertion AND has either matching `assertion_type` or substantial
/// text overlap. This is intentionally fuzzier than `vf_id` equality
/// — two papers asserting the same mechanism in different prose
/// should both contribute.
///
/// Returns `None` if `target_id` isn't in the project.
///
/// Equivalent to `consensus_for_with_filter` with the default
/// (no-op) filter; preserved for backward compatibility.
pub fn consensus_for(
    project: &Project,
    target_id: &str,
    weighting: WeightingScheme,
) -> Option<ConsensusResult> {
    consensus_for_with_filter(project, target_id, weighting, &AggregateFilter::default())
}

/// v0.38.2: same as `consensus_for`, with a structured `AggregateFilter`
/// applied to candidate findings before similarity is checked. Lets
/// callers ask sharper questions: "what's the consensus *as
/// intervention*?" or "consensus among RCT-grade evidence only?"
///
/// The target finding is always included as the anchor, even if it
/// would not pass the filter — the consensus is *about* this claim.
/// Only the *neighbors* are filtered.
pub fn consensus_for_with_filter(
    project: &Project,
    target_id: &str,
    weighting: WeightingScheme,
    filter: &AggregateFilter,
) -> Option<ConsensusResult> {
    let target = project.findings.iter().find(|f| f.id == target_id)?;
    let target_entities: HashSet<String> = target
        .assertion
        .entities
        .iter()
        .map(|e| e.name.to_lowercase())
        .collect();
    let target_text_words: HashSet<String> = target
        .assertion
        .text
        .to_lowercase()
        .split_whitespace()
        .filter(|w| w.len() > 4)
        .map(|w| w.trim_matches(|c: char| !c.is_alphanumeric()).to_string())
        .filter(|w| !w.is_empty())
        .collect();

    // Find candidate findings — including the target itself, which
    // anchors the consensus on its own evidence.
    //
    // v0.38.2: neighbor findings must pass the optional `filter`
    // (causal_claim match + causal_grade_min). The target is always
    // included regardless of filter — the consensus is *about* this
    // claim, not selecting *for* it.
    let mut candidates: Vec<&FindingBundle> = Vec::new();
    for f in &project.findings {
        if f.id == target_id {
            candidates.push(f);
            continue;
        }
        if !is_similar(
            f,
            &target_entities,
            &target_text_words,
            &target.assertion.assertion_type,
        ) {
            continue;
        }
        if !passes_filter(f, filter) {
            continue;
        }
        candidates.push(f);
    }

    // Build constituent records: replication tallies + adjusted score
    // + weight.
    let constituents: Vec<ConsensusConstituent> = candidates
        .iter()
        .map(|f| {
            let (n_repls, n_replicated, n_failed) = replication_tallies(project, &f.id);
            let raw_score = f.confidence.score;
            let adjusted_score = adjust_score_for_replications_and_review(
                raw_score,
                n_replicated,
                n_failed,
                f.flags.contested,
            );
            let weight = compute_weight(weighting, f, n_replicated, n_failed);
            ConsensusConstituent {
                finding_id: f.id.clone(),
                assertion_text: f.assertion.text.clone(),
                raw_score,
                adjusted_score,
                weight,
                n_replications: n_repls,
                n_replicated,
                n_failed_replications: n_failed,
            }
        })
        .collect();

    // Weighted mean + credible interval. If total weight is zero
    // (degenerate), fall back to the unweighted mean of adjusted
    // scores.
    let total_weight: f64 = constituents.iter().map(|c| c.weight).sum();
    let consensus_confidence = if total_weight > 0.0 {
        constituents
            .iter()
            .map(|c| c.adjusted_score * c.weight)
            .sum::<f64>()
            / total_weight
    } else if !constituents.is_empty() {
        constituents.iter().map(|c| c.adjusted_score).sum::<f64>() / constituents.len() as f64
    } else {
        0.0
    };

    let (credible_interval_lo, credible_interval_hi) =
        weighted_credible_interval(&constituents, consensus_confidence, total_weight);

    let filter_serialized = if filter.causal_claim.is_some() || filter.causal_grade_min.is_some() {
        Some(filter.clone())
    } else {
        None
    };

    Some(ConsensusResult {
        target: target.id.clone(),
        target_assertion: target.assertion.text.clone(),
        n_findings: constituents.len(),
        consensus_confidence: round3(consensus_confidence),
        credible_interval_lo: round3(credible_interval_lo),
        credible_interval_hi: round3(credible_interval_hi),
        constituents,
        weighting: weighting.name().to_string(),
        filter: filter_serialized,
    })
}

fn is_similar(
    candidate: &FindingBundle,
    target_entities: &HashSet<String>,
    target_text_words: &HashSet<String>,
    target_type: &str,
) -> bool {
    // Entity overlap: share at least one named entity (case-insensitive).
    let cand_entities: HashSet<String> = candidate
        .assertion
        .entities
        .iter()
        .map(|e| e.name.to_lowercase())
        .collect();
    let entity_overlap = !cand_entities.is_disjoint(target_entities);

    // Text overlap: at least 3 substantive words shared (Jaccard-ish).
    let cand_text_words: HashSet<String> = candidate
        .assertion
        .text
        .to_lowercase()
        .split_whitespace()
        .filter(|w| w.len() > 4)
        .map(|w| w.trim_matches(|c: char| !c.is_alphanumeric()).to_string())
        .filter(|w| !w.is_empty())
        .collect();
    let text_overlap = cand_text_words.intersection(target_text_words).count() >= 3;

    // Type match contributes to similarity but isn't required.
    let type_match = candidate.assertion.assertion_type == target_type;

    // Loose-OR: any two of the three signals (or strong overlap on
    // one) qualifies as similar.
    let signals = [entity_overlap, text_overlap, type_match]
        .iter()
        .filter(|x| **x)
        .count();
    signals >= 2 || (entity_overlap && cand_entities.intersection(target_entities).count() >= 2)
}

fn replication_tallies(project: &Project, finding_id: &str) -> (usize, usize, usize) {
    let mut total = 0usize;
    let mut replicated = 0usize;
    let mut failed = 0usize;
    for r in &project.replications {
        if r.target_finding == finding_id {
            total += 1;
            match r.outcome.as_str() {
                "replicated" => replicated += 1,
                "failed" => failed += 1,
                _ => {}
            }
        }
    }
    (total, replicated, failed)
}

fn adjust_score_for_replications_and_review(
    raw: f64,
    n_replicated: usize,
    n_failed: usize,
    contested: bool,
) -> f64 {
    // Replications: each successful adds 5%, each failed subtracts
    // 10%. Capped at [0, 1].
    let mut adj = raw + 0.05 * n_replicated as f64 - 0.10 * n_failed as f64;
    if contested {
        adj *= 0.85;
    }
    adj.clamp(0.0, 1.0)
}

fn compute_weight(
    scheme: WeightingScheme,
    f: &FindingBundle,
    n_replicated: usize,
    n_failed: usize,
) -> f64 {
    let base = 1.0;
    let replication_factor = 1.0 + 0.5 * n_replicated as f64 - 0.5 * n_failed as f64;
    let citation_factor = 1.0 + (f.provenance.citation_count.unwrap_or(0) as f64).ln_1p() * 0.10;
    match scheme {
        WeightingScheme::Unweighted => base,
        WeightingScheme::ReplicationWeighted => replication_factor.max(0.0),
        WeightingScheme::CitationWeighted => citation_factor.max(0.0),
        WeightingScheme::Composite => {
            (0.2 * base + 0.5 * replication_factor.max(0.0) + 0.3 * citation_factor.max(0.0))
                .max(0.0)
        }
    }
}

fn weighted_credible_interval(
    constituents: &[ConsensusConstituent],
    mean: f64,
    total_weight: f64,
) -> (f64, f64) {
    if constituents.is_empty() || total_weight <= 0.0 {
        return (mean, mean);
    }
    // Weighted variance.
    let var = constituents
        .iter()
        .map(|c| c.weight * (c.adjusted_score - mean).powi(2))
        .sum::<f64>()
        / total_weight;
    let sd = var.sqrt();
    // 95% interval ≈ ±1.96 SD; clamp to [0, 1].
    let lo = (mean - 1.96 * sd).clamp(0.0, 1.0);
    let hi = (mean + 1.96 * sd).clamp(0.0, 1.0);
    (lo, hi)
}

fn round3(x: f64) -> f64 {
    (x * 1000.0).round() / 1000.0
}

#[cfg(test)]
mod v0_38_2_filter_tests {
    use super::*;
    use crate::bundle::*;
    use crate::project;

    fn finding(
        id: &str,
        claim: Option<CausalClaim>,
        grade: Option<CausalEvidenceGrade>,
    ) -> FindingBundle {
        FindingBundle::new(
            Assertion {
                text: format!("X covaries with Y in {id}"),
                assertion_type: "mechanism".into(),
                entities: vec![
                    Entity {
                        name: "X".into(),
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
                    },
                    Entity {
                        name: "Y".into(),
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
                    },
                ],
                relation: Some("covaries_with".into()),
                direction: Some("positive".into()),
                causal_claim: claim,
                causal_evidence_grade: grade,
            },
            Evidence {
                evidence_type: "experimental".into(),
                model_system: String::new(),
                species: None,
                method: String::new(),
                sample_size: Some("n=100".into()),
                effect_size: None,
                p_value: None,
                replicated: false,
                replication_count: None,
                evidence_spans: vec![],
            },
            Conditions {
                text: String::new(),
                species_verified: vec![],
                species_unverified: vec![],
                in_vitro: false,
                in_vivo: false,
                human_data: false,
                clinical_trial: false,
                concentration_range: None,
                duration: None,
                age_group: None,
                cell_type: None,
            },
            Confidence::raw(0.7, "test", 0.85),
            Provenance {
                source_type: "published_paper".into(),
                doi: None,
                pmid: None,
                pmc: None,
                openalex_id: None,
                url: None,
                title: "Test".into(),
                authors: vec![],
                year: Some(2025),
                journal: None,
                license: None,
                publisher: None,
                funders: vec![],
                extraction: Extraction::default(),
                review: None,
                citation_count: None,
            },
            Flags::default(),
        )
    }

    fn make_project(findings: Vec<FindingBundle>) -> Project {
        project::assemble("test", findings, 1, 0, "test")
    }

    #[test]
    fn unfiltered_blends_all_similar_findings() {
        let target = finding(
            "a",
            Some(CausalClaim::Correlation),
            Some(CausalEvidenceGrade::Observational),
        );
        let interv = finding(
            "b",
            Some(CausalClaim::Intervention),
            Some(CausalEvidenceGrade::Rct),
        );
        let target_id = target.id.clone();
        let project = make_project(vec![target, interv]);
        let result = consensus_for(&project, &target_id, WeightingScheme::Unweighted).unwrap();
        // No filter: both findings contribute.
        assert_eq!(result.n_findings, 2);
        assert!(result.filter.is_none());
    }

    #[test]
    fn causal_claim_filter_keeps_only_matching_neighbors() {
        let target = finding(
            "a",
            Some(CausalClaim::Correlation),
            Some(CausalEvidenceGrade::Observational),
        );
        let interv = finding(
            "b",
            Some(CausalClaim::Intervention),
            Some(CausalEvidenceGrade::Rct),
        );
        let target_id = target.id.clone();
        let project = make_project(vec![target, interv]);
        let filter = AggregateFilter {
            causal_claim: Some(CausalClaim::Intervention),
            causal_grade_min: None,
        };
        let result =
            consensus_for_with_filter(&project, &target_id, WeightingScheme::Unweighted, &filter)
                .unwrap();
        // Target (correlation) is the anchor — always included.
        // Neighbor (intervention) passes the filter.
        // Result includes both — anchor + 1 matching neighbor.
        assert_eq!(result.n_findings, 2);
        // But if the target had a correlation neighbor not matching
        // intervention, it would be excluded.
    }

    #[test]
    fn causal_claim_filter_excludes_non_matching_neighbors() {
        let target = finding(
            "a",
            Some(CausalClaim::Intervention),
            Some(CausalEvidenceGrade::Rct),
        );
        let neighbor_corr = finding(
            "b",
            Some(CausalClaim::Correlation),
            Some(CausalEvidenceGrade::Observational),
        );
        let target_id = target.id.clone();
        let project = make_project(vec![target, neighbor_corr]);
        let filter = AggregateFilter {
            causal_claim: Some(CausalClaim::Intervention),
            causal_grade_min: None,
        };
        let result =
            consensus_for_with_filter(&project, &target_id, WeightingScheme::Unweighted, &filter)
                .unwrap();
        // Only the target (always included) — neighbor filtered out.
        assert_eq!(result.n_findings, 1);
        assert_eq!(
            result.filter.as_ref().unwrap().causal_claim,
            Some(CausalClaim::Intervention)
        );
    }

    #[test]
    fn grade_min_excludes_lower_grades() {
        let target = finding(
            "a",
            Some(CausalClaim::Mediation),
            Some(CausalEvidenceGrade::Rct),
        );
        let neighbor_obs = finding(
            "b",
            Some(CausalClaim::Mediation),
            Some(CausalEvidenceGrade::Observational),
        );
        let neighbor_rct = finding(
            "c",
            Some(CausalClaim::Mediation),
            Some(CausalEvidenceGrade::Rct),
        );
        let target_id = target.id.clone();
        let project = make_project(vec![target, neighbor_obs, neighbor_rct]);
        let filter = AggregateFilter {
            causal_claim: None,
            causal_grade_min: Some(CausalEvidenceGrade::QuasiExperimental),
        };
        let result =
            consensus_for_with_filter(&project, &target_id, WeightingScheme::Unweighted, &filter)
                .unwrap();
        // Target (RCT, anchor) + neighbor_rct. Observational excluded.
        assert_eq!(result.n_findings, 2);
    }

    #[test]
    fn ungraded_findings_excluded_when_grade_min_set() {
        let target = finding(
            "a",
            Some(CausalClaim::Mediation),
            Some(CausalEvidenceGrade::Rct),
        );
        let neighbor_ungraded = finding("b", Some(CausalClaim::Mediation), None);
        let target_id = target.id.clone();
        let project = make_project(vec![target, neighbor_ungraded]);
        let filter = AggregateFilter {
            causal_claim: None,
            causal_grade_min: Some(CausalEvidenceGrade::Observational),
        };
        let result =
            consensus_for_with_filter(&project, &target_id, WeightingScheme::Unweighted, &filter)
                .unwrap();
        // Ungraded neighbor is excluded; only target remains.
        assert_eq!(result.n_findings, 1);
    }

    #[test]
    fn grade_rank_orders_correctly() {
        assert!(
            grade_rank(CausalEvidenceGrade::Theoretical)
                < grade_rank(CausalEvidenceGrade::Observational)
        );
        assert!(
            grade_rank(CausalEvidenceGrade::Observational)
                < grade_rank(CausalEvidenceGrade::QuasiExperimental)
        );
        assert!(
            grade_rank(CausalEvidenceGrade::QuasiExperimental)
                < grade_rank(CausalEvidenceGrade::Rct)
        );
    }
}
