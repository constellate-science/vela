//! Citation-grounded frontier confidence calibration.
//!
//! Adjusts existing frontier epistemic confidence scores using calibration signals:
//! citation count, recency, evidence type, and evidence span availability.
//!
//! ## Integration
//!
//! Add to main.rs:
//! ```ignore
//! mod confidence;
//! ```
//!
//! Insert in the compile pipeline after normalization, before resolve/link:
//! ```ignore
//! println!("[X/N] Calibrating confidence...");
//! let adjustments = confidence::ground_confidence(&mut all_bundles);
//! println!("  -> {adjustments} findings adjusted");
//! ```

use chrono::{Datelike, Utc};

use crate::bundle::{ConfidenceUpdate, FindingBundle};

/// Calibrate confidence scores on all bundles using citation, recency, evidence,
/// and span signals. Returns a vector of ConfidenceUpdate records (one per
/// bundle whose score changed). Also mutates each bundle's confidence in place
/// for backward compatibility.
pub fn ground_confidence(bundles: &mut [FindingBundle]) -> Vec<ConfidenceUpdate> {
    if bundles.is_empty() {
        return Vec::new();
    }

    // Compute citation percentiles across the corpus.
    let mut citation_counts: Vec<u64> = bundles
        .iter()
        .filter_map(|b| b.provenance.citation_count)
        .collect();
    citation_counts.sort_unstable();

    let p90 = percentile_value(&citation_counts, 90);
    let p10 = percentile_value(&citation_counts, 10);

    let current_year = Utc::now().naive_utc().year();
    let mut updates: Vec<ConfidenceUpdate> = Vec::new();
    let now = Utc::now().to_rfc3339();

    for bundle in bundles.iter_mut() {
        let prior_score = bundle.confidence.score;
        let mut adjustment = 0.0f64;
        let mut basis_parts: Vec<String> = vec![format!("pre_calibration: {:.2}", prior_score)];

        // Factor 1: Citation count (log-scaled, clamped to -0.15 .. +0.15).
        if let Some(cites) = bundle.provenance.citation_count {
            let log_signal = (cites as f64 + 1.0).log10() / 4.0; // 0..~1 for 0..9999
            let citation_adj = if cites >= p90 {
                log_signal.min(0.15)
            } else if cites <= p10 {
                -(0.10f64.min(0.15 - log_signal))
            } else {
                (log_signal - 0.3).clamp(-0.05, 0.10)
            };
            adjustment += citation_adj;
            basis_parts.push(format!("citations: {} ({:+.2})", cites, citation_adj));
        }

        // Factor 2: Recency.
        if let Some(year) = bundle.provenance.year {
            let age = current_year - year;
            let recency_adj = if age <= 3 {
                0.05
            } else if age <= 10 {
                0.0
            } else {
                -0.05
            };
            adjustment += recency_adj;
            basis_parts.push(format!("recency: {} ({:+.2})", year, recency_adj));
        }

        // Factor 3: Evidence type weighting.
        let etype = bundle.evidence.evidence_type.as_str();
        let etype_adj = match etype {
            "meta_analysis" | "systematic_review" => 0.10,
            "experimental" if bundle.conditions.human_data => 0.05,
            "experimental" => 0.0,
            "observational" => 0.0,
            "theoretical" | "computational" => -0.05,
            _ => 0.0,
        };
        adjustment += etype_adj;
        basis_parts.push(format!("evidence: {} ({:+.2})", etype, etype_adj));

        // Factor 4: Evidence spans (auditable extraction).
        let span_adj = if !bundle.evidence.evidence_spans.is_empty() {
            0.05
        } else {
            -0.05
        };
        adjustment += span_adj;

        // Weighted combination: 60% LLM, 40% grounded adjustment.
        let calibrated = (prior_score + adjustment).clamp(0.0, 1.0);
        let final_score = (0.6 * prior_score + 0.4 * calibrated).clamp(0.05, 0.99);

        // Round to 3 decimal places.
        let final_score = (final_score * 1000.0).round() / 1000.0;

        basis_parts.push(format!("calibration: {:+.2}", adjustment));
        basis_parts.push(format!("-> {:.3}", final_score));
        bundle.confidence.basis = basis_parts.join(", ");
        if let Some(components) = bundle.confidence.components.as_mut() {
            components.calibration_adjustment = adjustment;
        }

        if (final_score - prior_score).abs() > 0.001 {
            updates.push(ConfidenceUpdate {
                finding_id: bundle.id.clone(),
                previous_score: prior_score,
                new_score: final_score,
                basis: bundle.confidence.basis.clone(),
                updated_by: "grounding_pass".into(),
                updated_at: now.clone(),
            });
        }

        bundle.confidence.score = final_score;
    }

    updates
}

/// Return the value at the given percentile (0-100) from a sorted slice.
fn percentile_value(sorted: &[u64], pct: usize) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = (pct * sorted.len() / 100).min(sorted.len() - 1);
    sorted[idx]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::*;

    fn make_bundle(score: f64, citations: u64, year: i32, etype: &str) -> FindingBundle {
        FindingBundle {
            id: "test".into(),
            version: 1,
            previous_version: None,
            assertion: Assertion {
                text: "Test assertion".into(),
                assertion_type: "mechanism".into(),
                entities: vec![],
                relation: None,
                direction: None,
                causal_claim: None,
                causal_evidence_grade: None,
            },
            evidence: Evidence {
                evidence_type: etype.into(),
                model_system: String::new(),
                species: None,
                method: String::new(),
                sample_size: None,
                effect_size: None,
                p_value: None,
                replicated: false,
                replication_count: None,
                evidence_spans: vec![],
            },
            conditions: Conditions {
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
            confidence: Confidence {
                kind: crate::bundle::ConfidenceKind::FrontierEpistemic,
                score,
                basis: "seeded prior".into(),
                method: crate::bundle::ConfidenceMethod::LlmInitial,
                components: None,
                extraction_confidence: 0.85,
            },
            provenance: Provenance {
                source_type: "published_paper".into(),
                doi: None,
                pmid: None,
                pmc: None,
                openalex_id: None,
                url: None,
                title: "Test".into(),
                authors: vec![],
                year: Some(year),
                journal: None,
                license: None,
                publisher: None,
                funders: vec![],
                extraction: Extraction::default(),
                review: None,
                citation_count: Some(citations),
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
            created: String::new(),
            updated: None,

            access_tier: crate::access_tier::AccessTier::Public,
        }
    }

    #[test]
    fn high_citations_boost() {
        let mut bundles = vec![
            make_bundle(0.70, 5000, 2024, "meta_analysis"),
            make_bundle(0.70, 2, 2010, "theoretical"),
        ];
        let updates = ground_confidence(&mut bundles);
        // Highly cited meta-analysis should score higher than low-cited theoretical.
        assert!(bundles[0].confidence.score > bundles[1].confidence.score);
        // Should return update records for changed scores.
        assert!(!updates.is_empty());
    }

    #[test]
    fn scores_clamped() {
        let mut bundles = vec![make_bundle(0.99, 10000, 2025, "meta_analysis")];
        let _updates = ground_confidence(&mut bundles);
        assert!(bundles[0].confidence.score <= 0.99);
        assert!(bundles[0].confidence.score >= 0.05);
    }

    #[test]
    fn recency_bonus_for_recent_papers() {
        let current_year = Utc::now().naive_utc().year();
        let recent_year = current_year - 1; // within 3 years
        let mut bundles = vec![
            make_bundle(0.70, 100, recent_year, "experimental"),
            make_bundle(0.70, 100, current_year - 15, "experimental"), // old paper
        ];
        ground_confidence(&mut bundles);
        // Recent paper should score higher due to recency bonus (+0.05 vs -0.05)
        assert!(bundles[0].confidence.score > bundles[1].confidence.score);
    }

    #[test]
    fn recency_penalty_for_old_papers() {
        let current_year = Utc::now().naive_utc().year();
        let old_year = current_year - 20; // > 10 years old
        let mid_year = current_year - 5; // 3-10 years: neutral
        let mut bundles = vec![
            make_bundle(0.70, 100, mid_year, "experimental"),
            make_bundle(0.70, 100, old_year, "experimental"),
        ];
        ground_confidence(&mut bundles);
        // Mid-age paper (neutral recency) should score higher than old paper (penalized)
        assert!(bundles[0].confidence.score > bundles[1].confidence.score);
    }

    #[test]
    fn meta_analysis_boosted_over_theoretical() {
        let current_year = Utc::now().naive_utc().year();
        let mut bundles = vec![
            make_bundle(0.70, 100, current_year - 5, "meta_analysis"),
            make_bundle(0.70, 100, current_year - 5, "theoretical"),
        ];
        ground_confidence(&mut bundles);
        // meta_analysis gets +0.10, theoretical gets -0.05
        assert!(bundles[0].confidence.score > bundles[1].confidence.score);
    }

    #[test]
    fn experimental_human_data_boost() {
        let current_year = Utc::now().naive_utc().year();
        let mut b_human = make_bundle(0.70, 100, current_year - 5, "experimental");
        b_human.conditions.human_data = true;
        let b_animal = make_bundle(0.70, 100, current_year - 5, "experimental");
        let mut bundles = vec![b_human, b_animal];
        ground_confidence(&mut bundles);
        // experimental + human_data gets +0.05, experimental alone gets 0.0
        assert!(bundles[0].confidence.score > bundles[1].confidence.score);
    }

    #[test]
    fn evidence_span_bonus() {
        let current_year = Utc::now().naive_utc().year();
        let mut b_with_span = make_bundle(0.70, 100, current_year - 5, "experimental");
        b_with_span.evidence.evidence_spans = vec![serde_json::json!({"text": "some evidence"})];
        let b_without = make_bundle(0.70, 100, current_year - 5, "experimental");
        let mut bundles = vec![b_with_span, b_without];
        ground_confidence(&mut bundles);
        // With spans gets +0.05, without gets -0.05
        assert!(bundles[0].confidence.score > bundles[1].confidence.score);
    }

    #[test]
    fn empty_bundles_returns_empty() {
        let mut bundles: Vec<FindingBundle> = vec![];
        let updates = ground_confidence(&mut bundles);
        assert!(updates.is_empty());
    }

    #[test]
    fn score_never_exceeds_bounds() {
        // Very low initial score with all negative adjustments
        let mut bundles = vec![make_bundle(0.05, 0, 1990, "theoretical")];
        ground_confidence(&mut bundles);
        assert!(bundles[0].confidence.score >= 0.05);
        assert!(bundles[0].confidence.score <= 0.99);

        // Very high initial score with all positive adjustments
        let current_year = Utc::now().naive_utc().year();
        let mut b = make_bundle(0.99, 10000, current_year, "meta_analysis");
        b.evidence.evidence_spans = vec![serde_json::json!({"text": "span"})];
        let mut bundles2 = vec![b];
        ground_confidence(&mut bundles2);
        assert!(bundles2[0].confidence.score >= 0.05);
        assert!(bundles2[0].confidence.score <= 0.99);
    }

    #[test]
    fn update_records_have_correct_fields() {
        let current_year = Utc::now().naive_utc().year();
        let mut bundles = vec![make_bundle(0.70, 5000, current_year, "meta_analysis")];
        let updates = ground_confidence(&mut bundles);
        assert!(!updates.is_empty());
        let u = &updates[0];
        assert_eq!(u.finding_id, "test");
        assert_eq!(u.previous_score, 0.70);
        assert_eq!(u.updated_by, "grounding_pass");
        assert!(!u.updated_at.is_empty());
        assert!(!u.basis.is_empty());
    }

    #[test]
    fn basis_string_populated() {
        let current_year = Utc::now().naive_utc().year();
        let mut bundles = vec![make_bundle(0.70, 100, current_year, "experimental")];
        ground_confidence(&mut bundles);
        let basis = &bundles[0].confidence.basis;
        assert!(basis.contains("pre_calibration:"));
        assert!(basis.contains("citations:"));
        assert!(basis.contains("recency:"));
        assert!(basis.contains("evidence:"));
        assert!(basis.contains("calibration:"));
    }

    #[test]
    fn computed_components_capture_calibration_adjustment() {
        let current_year = Utc::now().naive_utc().year();
        let mut bundle = make_bundle(0.70, 5000, current_year, "meta_analysis");
        bundle.confidence =
            crate::bundle::compute_confidence(&bundle.evidence, &bundle.conditions, false);
        let mut bundles = vec![bundle];
        ground_confidence(&mut bundles);
        let components = bundles[0].confidence.components.as_ref().unwrap();
        assert!(components.calibration_adjustment > 0.0);
    }

    #[test]
    fn percentile_value_works() {
        assert_eq!(percentile_value(&[], 90), 0);
        assert_eq!(percentile_value(&[10], 50), 10);
        assert_eq!(percentile_value(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 90), 10);
        assert_eq!(percentile_value(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 10), 2);
    }

    #[test]
    fn no_citation_count_still_works() {
        let current_year = Utc::now().naive_utc().year();
        let mut b = make_bundle(0.70, 0, current_year, "experimental");
        b.provenance.citation_count = None;
        let mut bundles = vec![b];
        let _updates = ground_confidence(&mut bundles);
        // Should not panic; score should still be valid
        assert!(bundles[0].confidence.score >= 0.05);
        assert!(bundles[0].confidence.score <= 0.99);
    }

    #[test]
    fn observational_is_neutral() {
        let current_year = Utc::now().naive_utc().year();
        let b_obs = make_bundle(0.70, 100, current_year - 5, "observational");
        let b_exp = make_bundle(0.70, 100, current_year - 5, "experimental");
        // Both same conditions otherwise
        let mut bundles = vec![b_obs, b_exp];
        ground_confidence(&mut bundles);
        // Both should be equal since observational and experimental (non-human) both get 0.0
        assert!((bundles[0].confidence.score - bundles[1].confidence.score).abs() < 0.001);
    }

    #[test]
    fn systematic_review_boosted() {
        let current_year = Utc::now().naive_utc().year();
        let mut bundles = vec![
            make_bundle(0.70, 100, current_year - 5, "systematic_review"),
            make_bundle(0.70, 100, current_year - 5, "experimental"),
        ];
        ground_confidence(&mut bundles);
        assert!(bundles[0].confidence.score > bundles[1].confidence.score);
    }
}
