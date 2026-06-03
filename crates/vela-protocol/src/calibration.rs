//! v0.34: Calibration scoring over resolved predictions.
//!
//! A `Prediction` carries the predictor's confidence in the expected
//! outcome (a number on `[0, 1]`). When a `Resolution` records what
//! actually happened, the resolver also records `matched_expected`
//! (a bool). Together those two facts let us compute, per actor:
//!
//! - **Hit rate**: fraction of resolved predictions that matched.
//! - **Brier score**: mean of `(confidence - matched)^2` across the
//!   resolved subset, where `matched ∈ {0, 1}`. Lower is better.
//!   Brier = 0 means perfect calibration; 0.25 is a chance-level
//!   binary predictor; 1.0 is maximally wrong.
//! - **Log score**: mean of `log(p_assigned_to_actual_outcome)`. We
//!   clip to `[1e-9, 1 - 1e-9]` to avoid `-∞`. Higher (closer to 0)
//!   is better.
//!
//! These are derived signals — never written to disk, always
//! recomputed from the canonical `predictions` and `resolutions`
//! collections. That keeps the kernel ledger source-of-truth and
//! avoids stale calibration cache concerns.
//!
//! Calibration is the move that makes Vela an epistemic ledger
//! rather than a knowledge graph: every actor accumulates a public,
//! reproducible track record of how well their stated beliefs match
//! reality.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::bundle::{Prediction, Resolution};
use crate::events::{self, FindingEventInput, NULL_HASH};
use crate::project::Project;

/// Per-actor calibration summary computed over the resolved subset of
/// the actor's predictions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalibrationRecord {
    /// Stable actor id (e.g. `reviewer:will-blair`).
    pub actor: String,
    /// Total predictions made by this actor in the frontier.
    pub n_predictions: usize,
    /// Predictions that have been resolved (have an associated
    /// `Resolution`). Open predictions don't contribute to scoring.
    pub n_resolved: usize,
    /// Resolved predictions whose `matched_expected = true`.
    pub n_hit: usize,
    /// v0.40.1: predictions closed by the calibration runtime
    /// without an explicit `Resolution` (deadline passed). Counted
    /// separately from `n_resolved` so the predictor still answers
    /// for the missing commitment without their Brier or log score
    /// being moved by it.
    #[serde(default)]
    pub n_expired: usize,
    /// Hit rate over resolved (or `None` if `n_resolved == 0`).
    pub hit_rate: Option<f64>,
    /// Brier score, lower is better. `None` if no resolutions.
    pub brier_score: Option<f64>,
    /// Log score, higher (closer to 0) is better. `None` if no resolutions.
    pub log_score: Option<f64>,
    /// Bucketed reliability diagram: for each predicted-confidence
    /// band, the observed match rate. Empty bands are omitted.
    /// Format: `(confidence_lower_bound, observed_hit_rate, n_in_band)`.
    pub reliability_buckets: Vec<(f64, f64, usize)>,
}

/// Compute calibration records for every actor that has at least one
/// prediction in the frontier.
pub fn calibration_records(
    predictions: &[Prediction],
    resolutions: &[Resolution],
) -> Vec<CalibrationRecord> {
    // Index resolutions by prediction_id for cheap lookup.
    let mut resolution_by_pred: HashMap<&str, &Resolution> = HashMap::new();
    for r in resolutions {
        resolution_by_pred.insert(r.prediction_id.as_str(), r);
    }

    // Group predictions by actor.
    let mut by_actor: HashMap<String, Vec<&Prediction>> = HashMap::new();
    for p in predictions {
        by_actor.entry(p.made_by.clone()).or_default().push(p);
    }

    let mut out = Vec::with_capacity(by_actor.len());
    for (actor, preds) in by_actor {
        let n_predictions = preds.len();
        let mut resolved: Vec<(&Prediction, &Resolution)> = Vec::new();
        for p in &preds {
            if let Some(r) = resolution_by_pred.get(p.id.as_str()) {
                resolved.push((p, r));
            }
        }
        let n_resolved = resolved.len();
        let n_hit = resolved.iter().filter(|(_, r)| r.matched_expected).count();
        let n_expired = preds.iter().filter(|p| p.expired_unresolved).count();
        let hit_rate = if n_resolved > 0 {
            Some(n_hit as f64 / n_resolved as f64)
        } else {
            None
        };

        // Brier: mean of (confidence - matched_int)^2.
        let brier_score = if n_resolved > 0 {
            let sum: f64 = resolved
                .iter()
                .map(|(p, r)| {
                    let m = if r.matched_expected { 1.0 } else { 0.0 };
                    (p.confidence - m).powi(2)
                })
                .sum();
            Some(sum / n_resolved as f64)
        } else {
            None
        };

        // Log score: mean log(p_actual). For matched, p_actual = confidence;
        // for not matched, p_actual = (1 - confidence). Clipped.
        let log_score = if n_resolved > 0 {
            let sum: f64 = resolved
                .iter()
                .map(|(p, r)| {
                    let p_actual = if r.matched_expected {
                        p.confidence
                    } else {
                        1.0 - p.confidence
                    };
                    p_actual.clamp(1e-9, 1.0 - 1e-9).ln()
                })
                .sum();
            Some(sum / n_resolved as f64)
        } else {
            None
        };

        // Reliability buckets: 5 bands of width 0.2, omit empty bands.
        let bands: [(f64, f64); 5] = [(0.0, 0.2), (0.2, 0.4), (0.4, 0.6), (0.6, 0.8), (0.8, 1.001)];
        let mut reliability_buckets: Vec<(f64, f64, usize)> = Vec::new();
        for (lo, hi) in bands {
            let in_band: Vec<&(&Prediction, &Resolution)> = resolved
                .iter()
                .filter(|(p, _)| p.confidence >= lo && p.confidence < hi)
                .collect();
            if in_band.is_empty() {
                continue;
            }
            let hits = in_band.iter().filter(|(_, r)| r.matched_expected).count();
            let observed = hits as f64 / in_band.len() as f64;
            reliability_buckets.push((lo, observed, in_band.len()));
        }

        out.push(CalibrationRecord {
            actor,
            n_predictions,
            n_resolved,
            n_hit,
            n_expired,
            hit_rate,
            brier_score,
            log_score,
            reliability_buckets,
        });
    }

    // Stable order: by actor id alphabetically.
    out.sort_by(|a, b| a.actor.cmp(&b.actor));
    out
}

/// v0.40.1: report from one expiration pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpirationReport {
    pub now: String,
    /// IDs of predictions that were already resolved (no action).
    pub already_resolved: Vec<String>,
    /// IDs of predictions that were already marked expired before
    /// this pass (idempotent re-runs).
    pub already_expired: Vec<String>,
    /// IDs newly marked expired by this pass.
    pub newly_expired: Vec<String>,
    /// Open predictions whose deadline is still in the future
    /// (or whose deadline is unset).
    pub still_open: Vec<String>,
}

/// v0.40.1: walk every prediction in the project and mark as
/// `expired_unresolved` any whose `resolves_by` is in the past *and*
/// has no associated `Resolution`. Emits one
/// `prediction.expired_unresolved` event per newly-expired prediction.
///
/// Idempotent: predictions already flagged are surfaced in
/// `already_expired` rather than re-flagged or duplicated.
///
/// `now` is taken as a parameter (not `Utc::now()`) so unit tests can
/// pin time deterministically. The `predictions expire` CLI passes
/// the system clock by default but accepts `--now <rfc3339>` for
/// reproducibility.
pub fn expire_overdue_predictions(project: &mut Project, now: DateTime<Utc>) -> ExpirationReport {
    let now_str = now.to_rfc3339();
    let resolved_ids: std::collections::HashSet<String> = project
        .resolutions
        .iter()
        .map(|r| r.prediction_id.clone())
        .collect();

    let mut report = ExpirationReport {
        now: now_str.clone(),
        already_resolved: Vec::new(),
        already_expired: Vec::new(),
        newly_expired: Vec::new(),
        still_open: Vec::new(),
    };

    // Take an indexed snapshot to avoid borrow-checker churn against
    // the mutable findings/events loop below.
    let mut to_expire: Vec<usize> = Vec::new();
    for (idx, p) in project.predictions.iter().enumerate() {
        if resolved_ids.contains(&p.id) {
            report.already_resolved.push(p.id.clone());
            continue;
        }
        if p.expired_unresolved {
            report.already_expired.push(p.id.clone());
            continue;
        }
        let Some(deadline_str) = p.resolves_by.as_deref() else {
            report.still_open.push(p.id.clone());
            continue;
        };
        let Ok(deadline) = DateTime::parse_from_rfc3339(deadline_str) else {
            // Malformed deadline: treat as still-open rather than
            // silently expiring. The reviewer can fix the date.
            report.still_open.push(p.id.clone());
            continue;
        };
        if deadline.with_timezone(&Utc) <= now {
            to_expire.push(idx);
        } else {
            report.still_open.push(p.id.clone());
        }
    }

    // Mutate + emit events in a second pass to keep the borrow
    // checker happy.
    for idx in to_expire {
        let pred_id = project.predictions[idx].id.clone();
        let resolves_by = project.predictions[idx]
            .resolves_by
            .clone()
            .unwrap_or_default();
        project.predictions[idx].expired_unresolved = true;
        let reason = format!("deadline {resolves_by} passed without resolution");
        let event = events::new_finding_event(FindingEventInput {
            kind: "prediction.expired_unresolved",
            finding_id: &pred_id,
            actor_id: "calibration",
            actor_type: "system",
            reason: &reason,
            before_hash: NULL_HASH,
            after_hash: NULL_HASH,
            payload: json!({
                "prediction_id": pred_id,
                "resolves_by": resolves_by,
                "expired_at": now_str,
            }),
            caveats: Vec::new(),
        });
        project.events.push(event);
        report.newly_expired.push(pred_id);
    }

    report
}

/// Convenience: calibration for a single actor.
pub fn calibration_for_actor(
    actor: &str,
    predictions: &[Prediction],
    resolutions: &[Resolution],
) -> Option<CalibrationRecord> {
    calibration_records(predictions, resolutions)
        .into_iter()
        .find(|r| r.actor == actor)
}

#[cfg(test)]
mod v0_40_1_expiration_tests {
    use super::*;
    use crate::bundle::{Conditions, ExpectedOutcome, Prediction};
    use crate::project;

    fn cond() -> Conditions {
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
        }
    }

    fn pred(id_seed: &str, resolves_by: Option<&str>) -> Prediction {
        let mut p = Prediction::new(
            format!("claim {id_seed}"),
            vec![],
            Some("2024-01-01T00:00:00Z".into()),
            resolves_by.map(|s| s.to_string()),
            "criterion".to_string(),
            ExpectedOutcome::Affirmed,
            "reviewer:test".to_string(),
            0.7,
            cond(),
        );
        // Ensure unique ids in tests by suffixing the seed.
        p.id = format!("vpred_test_{id_seed}");
        p
    }

    fn empty_project() -> Project {
        project::assemble("test", vec![], 0, 0, "test")
    }

    #[test]
    fn overdue_unresolved_prediction_gets_expired() {
        let mut project = empty_project();
        project
            .predictions
            .push(pred("a", Some("2025-01-01T00:00:00Z")));
        let now = DateTime::parse_from_rfc3339("2026-04-27T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let report = expire_overdue_predictions(&mut project, now);
        assert_eq!(report.newly_expired.len(), 1);
        assert!(project.predictions[0].expired_unresolved);
        // Event was appended.
        let last = project.events.last().unwrap();
        assert_eq!(last.kind, "prediction.expired_unresolved");
    }

    #[test]
    fn future_deadline_stays_open() {
        let mut project = empty_project();
        project
            .predictions
            .push(pred("a", Some("2099-01-01T00:00:00Z")));
        let now = DateTime::parse_from_rfc3339("2026-04-27T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let report = expire_overdue_predictions(&mut project, now);
        assert_eq!(report.newly_expired.len(), 0);
        assert_eq!(report.still_open.len(), 1);
        assert!(!project.predictions[0].expired_unresolved);
    }

    #[test]
    fn unset_deadline_stays_open() {
        let mut project = empty_project();
        project.predictions.push(pred("a", None));
        let now = Utc::now();
        let report = expire_overdue_predictions(&mut project, now);
        assert_eq!(report.newly_expired.len(), 0);
        assert_eq!(report.still_open.len(), 1);
    }

    #[test]
    fn already_resolved_prediction_does_not_expire() {
        let mut project = empty_project();
        project
            .predictions
            .push(pred("a", Some("2025-01-01T00:00:00Z")));
        let pid = project.predictions[0].id.clone();
        // Synthesize a resolution.
        project.resolutions.push(crate::bundle::Resolution {
            id: "vres_a".into(),
            prediction_id: pid.clone(),
            actual_outcome: "yes".into(),
            matched_expected: true,
            resolved_at: "2024-12-01T00:00:00Z".into(),
            resolved_by: "reviewer:test".into(),
            evidence: crate::bundle::Evidence {
                evidence_type: "experimental".into(),
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
            confidence: 1.0,
        });
        let now = DateTime::parse_from_rfc3339("2026-04-27T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let report = expire_overdue_predictions(&mut project, now);
        assert_eq!(report.newly_expired.len(), 0);
        assert_eq!(report.already_resolved.len(), 1);
        assert!(!project.predictions[0].expired_unresolved);
    }

    #[test]
    fn idempotent_re_run_lists_already_expired() {
        let mut project = empty_project();
        project
            .predictions
            .push(pred("a", Some("2025-01-01T00:00:00Z")));
        let now = DateTime::parse_from_rfc3339("2026-04-27T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let _ = expire_overdue_predictions(&mut project, now);
        let report2 = expire_overdue_predictions(&mut project, now);
        assert_eq!(report2.newly_expired.len(), 0);
        assert_eq!(report2.already_expired.len(), 1);
        // No second event should have been appended.
        let count = project
            .events
            .iter()
            .filter(|e| e.kind == "prediction.expired_unresolved")
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn calibration_record_carries_n_expired() {
        let mut project = empty_project();
        let mut p = pred("a", Some("2025-01-01T00:00:00Z"));
        p.expired_unresolved = true;
        project.predictions.push(p);
        let records = calibration_records(&project.predictions, &project.resolutions);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].n_expired, 1);
        assert_eq!(records[0].n_resolved, 0);
    }
}
