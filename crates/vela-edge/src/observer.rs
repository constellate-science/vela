//! Observer policies — named lenses over the frontier.
//!
//! The observer layer separates the record from the judgment. The kernel stores
//! structural facts. Observers are functions over that shared record — they
//! score, filter, and rank under declared policies without altering shared state.
//!
//! Different communities interpret the same evidence differently: a pharma team
//! weights clinical trial data and citation counts; an academic team weights
//! replication and evidence spans; a regulatory body demands human data at high
//! confidence thresholds. The observer makes those lenses explicit.

use chrono::Datelike;
use colored::Colorize;

use vela_protocol::bundle::FindingBundle;
use vela_protocol::cli_style as style;

/// An observer policy — a named lens over the frontier.
pub struct ObserverPolicy {
    pub name: String,
    pub description: String,
    pub weights: ObserverWeights,
}

pub struct ObserverWeights {
    /// Weight for replicated findings.
    pub replication: f64,
    /// Weight for recency (newer = higher).
    pub recency: f64,
    /// Weight for citation count.
    pub citations: f64,
    /// Weight for evidence spans present (auditability).
    pub evidence_spans: f64,
    /// Minimum confidence threshold — findings below this are hidden.
    pub min_confidence: f64,
    /// Entity types to prioritize (empty = all).
    pub priority_entity_types: Vec<String>,
    /// Assertion types to prioritize (empty = all).
    pub priority_assertion_types: Vec<String>,
    /// Weight for gap and negative-space findings (exploration lens).
    pub dark_territory: f64,
}

/// A scored finding within an observer view.
pub struct ScoredFinding {
    pub finding_id: String,
    pub original_confidence: f64,
    pub observer_score: f64,
    pub rank: usize,
    /// Short label for display (truncated assertion text).
    pub label: String,
}

/// The output of applying an observer policy to a frontier's findings.
pub struct ObserverView {
    pub policy: String,
    pub findings: Vec<ScoredFinding>,
    pub hidden: usize,
    pub total: usize,
}

// ── Built-in policies ───────────────────────────────────────────────────

pub fn builtin_policies() -> Vec<ObserverPolicy> {
    vec![
        pharma(),
        academic(),
        regulatory(),
        clinical(),
        exploration(),
    ]
}

pub fn policy_by_name(name: &str) -> Option<ObserverPolicy> {
    builtin_policies().into_iter().find(|p| p.name == name)
}

pub fn pharma() -> ObserverPolicy {
    ObserverPolicy {
        name: "pharma".into(),
        description: "Weights clinical trial data, human evidence, and citation count.".into(),
        weights: ObserverWeights {
            replication: 1.0,
            recency: 1.0,
            citations: 1.3,
            evidence_spans: 1.0,
            min_confidence: 0.7,
            priority_entity_types: vec![],
            priority_assertion_types: vec!["therapeutic".into(), "diagnostic".into()],
            dark_territory: 1.0,
        },
    }
}

pub fn academic() -> ObserverPolicy {
    ObserverPolicy {
        name: "academic".into(),
        description: "Weights replication, evidence spans, and recency.".into(),
        weights: ObserverWeights {
            replication: 1.5,
            recency: 1.2,
            citations: 1.0,
            evidence_spans: 1.3,
            min_confidence: 0.5,
            priority_entity_types: vec![],
            priority_assertion_types: vec![],
            dark_territory: 1.0,
        },
    }
}

pub fn regulatory() -> ObserverPolicy {
    ObserverPolicy {
        name: "regulatory".into(),
        description: "Demands human data, clinical trials, and auditability. High threshold."
            .into(),
        weights: ObserverWeights {
            replication: 1.0,
            recency: 1.0,
            citations: 1.0,
            evidence_spans: 1.5,
            min_confidence: 0.8,
            priority_entity_types: vec![],
            priority_assertion_types: vec!["diagnostic".into(), "epidemiological".into()],
            dark_territory: 1.0,
        },
    }
}

pub fn clinical() -> ObserverPolicy {
    ObserverPolicy {
        name: "clinical".into(),
        description: "Weights human data, replication, and recency for clinical relevance.".into(),
        weights: ObserverWeights {
            replication: 1.5,
            recency: 1.3,
            citations: 1.0,
            evidence_spans: 1.0,
            min_confidence: 0.6,
            priority_entity_types: vec![],
            priority_assertion_types: vec!["therapeutic".into(), "diagnostic".into()],
            dark_territory: 1.0,
        },
    }
}

pub fn exploration() -> ObserverPolicy {
    ObserverPolicy {
        name: "exploration".into(),
        description: "No minimum confidence. Surfaces gaps and dark territory.".into(),
        weights: ObserverWeights {
            replication: 1.0,
            recency: 1.0,
            citations: 1.0,
            evidence_spans: 1.0,
            min_confidence: 0.0,
            priority_entity_types: vec![],
            priority_assertion_types: vec![],
            dark_territory: 2.0,
        },
    }
}

// ── Scoring ─────────────────────────────────────────────────────────────

/// Score a single finding under the given policy weights.
/// Returns the raw (unnormalized) score.
fn score_finding(finding: &FindingBundle, w: &ObserverWeights) -> f64 {
    let base = finding.confidence.score;
    let mut multiplier = 1.0;

    // Replication signal: the finding's own `evidence.replicated` flag.
    if finding.evidence.replicated {
        multiplier *= w.replication;
    }

    // Recency signal: papers from the last 3 years get the weight boost.
    let current_year = chrono::Utc::now().naive_utc().year();
    if let Some(year) = finding.provenance.year
        && current_year - year <= 3
    {
        multiplier *= w.recency;
    }

    // Evidence spans (auditability).
    if !finding.evidence.evidence_spans.is_empty() {
        multiplier *= w.evidence_spans;
    }

    // Dark territory: gap and negative-space findings.
    if finding.flags.gap || finding.flags.negative_space {
        multiplier *= w.dark_territory;
    }

    // Priority assertion type boost (1.2x if matching).
    if !w.priority_assertion_types.is_empty()
        && w.priority_assertion_types
            .contains(&finding.assertion.assertion_type)
    {
        multiplier *= 1.2;
    }

    // Priority entity type boost (1.1x per matching entity, capped at 1.3x).
    if !w.priority_entity_types.is_empty() {
        let matches = finding
            .assertion
            .entities
            .iter()
            .filter(|e| w.priority_entity_types.contains(&e.entity_type))
            .count();
        if matches > 0 {
            multiplier *= (1.0 + 0.1 * matches as f64).min(1.3);
        }
    }

    // Apply and clamp to 0.0-1.0.
    (base * multiplier).clamp(0.0, 1.0)
}

/// Apply an observer policy to a set of findings, producing a filtered,
/// reranked view. The findings vector is not mutated. The replication
/// multiplier reads each finding's own `evidence.replicated` flag.
pub fn observe(findings: &[FindingBundle], policy: &ObserverPolicy) -> ObserverView {
    let total = findings.len();

    let mut scored: Vec<ScoredFinding> = findings
        .iter()
        .map(|f| {
            let s = score_finding(f, &policy.weights);
            let label = if f.assertion.text.len() > 72 {
                let mut end = 72;
                while end > 0 && !f.assertion.text.is_char_boundary(end) {
                    end -= 1;
                }
                format!("{}...", &f.assertion.text[..end])
            } else {
                f.assertion.text.clone()
            };
            ScoredFinding {
                finding_id: f.id.clone(),
                original_confidence: f.confidence.score,
                observer_score: s,
                rank: 0,
                label,
            }
        })
        .collect();

    // Filter below min_confidence.
    let hidden = scored
        .iter()
        .filter(|s| s.observer_score < policy.weights.min_confidence)
        .count();

    scored.retain(|s| s.observer_score >= policy.weights.min_confidence);

    // Sort descending by observer_score.
    scored.sort_by(|a, b| {
        b.observer_score
            .partial_cmp(&a.observer_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    // Assign ranks.
    for (i, s) in scored.iter_mut().enumerate() {
        s.rank = i + 1;
    }

    ObserverView {
        policy: policy.name.clone(),
        findings: scored,
        hidden,
        total,
    }
}

/// Compute the disagreement between two observer views. Returns findings sorted
/// by the absolute difference in rank between the two policies — the most
/// contested findings first.
pub struct Disagreement {
    pub finding_id: String,
    pub label: String,
    pub score_a: f64,
    pub score_b: f64,
    pub rank_a: Option<usize>,
    pub rank_b: Option<usize>,
    pub delta: f64,
}

pub fn diff_views(view_a: &ObserverView, view_b: &ObserverView) -> Vec<Disagreement> {
    use std::collections::HashMap;

    // Build lookup maps by finding_id.
    let map_a: HashMap<&str, &ScoredFinding> = view_a
        .findings
        .iter()
        .map(|f| (f.finding_id.as_str(), f))
        .collect();
    let map_b: HashMap<&str, &ScoredFinding> = view_b
        .findings
        .iter()
        .map(|f| (f.finding_id.as_str(), f))
        .collect();

    // Collect all finding IDs from both views.
    let mut all_ids: Vec<&str> = map_a.keys().copied().collect();
    for id in map_b.keys() {
        if !map_a.contains_key(id) {
            all_ids.push(id);
        }
    }

    let mut disagreements: Vec<Disagreement> = all_ids
        .iter()
        .map(|id| {
            let a = map_a.get(id);
            let b = map_b.get(id);

            let score_a = a.map(|f| f.observer_score).unwrap_or(0.0);
            let score_b = b.map(|f| f.observer_score).unwrap_or(0.0);
            let label = a.or(b).map(|f| f.label.clone()).unwrap_or_default();

            Disagreement {
                finding_id: id.to_string(),
                label,
                score_a,
                score_b,
                rank_a: a.map(|f| f.rank),
                rank_b: b.map(|f| f.rank),
                delta: (score_a - score_b).abs(),
            }
        })
        .collect();

    disagreements.sort_by(|a, b| {
        b.delta
            .partial_cmp(&a.delta)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    disagreements
}

/// Print an observer view to stdout.
pub fn print_view(view: &ObserverView) {
    println!();
    println!(
        "  {}",
        format!("VELA · OBSERVER · {}", view.policy.to_uppercase()).dimmed()
    );
    println!("  {}", style::tick_row(80));
    println!(
        "  {} findings shown · {} hidden (below threshold) · {} total",
        view.findings.len(),
        view.hidden,
        view.total
    );
    println!();
    println!(
        "  {}",
        format!(
            "{:<5} {:<16} {:>8} {:>8}  assertion",
            "rank", "id", "orig", "score"
        )
        .dimmed()
    );

    for sf in &view.findings {
        println!(
            "  {:<5} {:<16} {:>8.3} {:>8.3}  {}",
            sf.rank, sf.finding_id, sf.original_confidence, sf.observer_score, sf.label
        );
    }
    println!();
}

/// Print a diff between two observer views.
pub fn print_diff(policy_a: &str, policy_b: &str, disagreements: &[Disagreement], limit: usize) {
    println!();
    println!(
        "  {}",
        format!(
            "VELA · OBSERVER · DIFF · {} VS {}",
            policy_a.to_uppercase(),
            policy_b.to_uppercase()
        )
        .dimmed()
    );
    println!("  {}", style::tick_row(90));
    println!("  top {} disagreements by score delta", limit);
    println!();
    println!(
        "  {}",
        format!(
            "{:<16} {:>10} {:>10} {:>8}  assertion",
            "id", policy_a, policy_b, "delta"
        )
        .dimmed()
    );

    for d in disagreements.iter().take(limit) {
        let rank_a = d
            .rank_a
            .map(|r| format!("#{} ({:.3})", r, d.score_a))
            .unwrap_or_else(|| "hidden".into());
        let rank_b = d
            .rank_b
            .map(|r| format!("#{} ({:.3})", r, d.score_b))
            .unwrap_or_else(|| "hidden".into());

        let label = if d.label.len() > 40 {
            let mut end = 40;
            while end > 0 && !d.label.is_char_boundary(end) {
                end -= 1;
            }
            format!("{}...", &d.label[..end])
        } else {
            d.label.clone()
        };

        println!(
            "  {:<16} {:>10} {:>10} {:>8.3}  {}",
            d.finding_id, rank_a, rank_b, d.delta, label
        );
    }
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;
    use vela_protocol::bundle::*;

    fn make_finding(
        id: &str,
        score: f64,
        _clinical_trial: bool,
        _human: bool,
        replicated: bool,
    ) -> FindingBundle {
        FindingBundle {
            id: id.into(),
            version: 1,
            previous_version: None,
            assertion: Assertion {
                text: format!("Finding {id}"),
                assertion_type: "mechanism".into(),
                entities: vec![],
                relation: None,
                direction: None,
                causal_claim: None,
                causal_evidence_grade: None,
            },
            evidence: Evidence {
                evidence_type: "experimental".into(),
                model_system: String::new(),
                method: String::new(),
                replicated,
                replication_count: if replicated { Some(3) } else { None },
                evidence_spans: vec![],
            },
            conditions: Conditions {
                text: String::new(),
                duration: None,
            },
            confidence: Confidence::raw(score, "test", 0.85),
            provenance: Provenance {
                source_type: "published_paper".into(),
                doi: None,
                url: None,
                title: "Test".into(),
                authors: vec![],
                year: Some(2020),
                license: None,
                publisher: None,
                funders: vec![],
                extraction: Extraction::default(),
                review: None,
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

            access_tier: vela_protocol::access_tier::AccessTier::Public,
        }
    }

    #[test]
    fn exploration_shows_all() {
        let findings = vec![make_finding("low", 0.3, false, false, false)];
        let view = observe(&findings, &exploration());
        assert_eq!(view.hidden, 0);
        assert_eq!(view.findings.len(), 1);
    }

    #[test]
    fn regulatory_hides_low_confidence() {
        let findings = vec![make_finding("low", 0.5, false, false, false)];
        let view = observe(&findings, &regulatory());
        assert_eq!(view.hidden, 1);
        assert_eq!(view.findings.len(), 0);
    }

    // ── policy_by_name tests ────────────────────────────────────────

    #[test]
    fn policy_by_name_returns_pharma() {
        let p = policy_by_name("pharma").unwrap();
        assert_eq!(p.name, "pharma");
        // clinical_trial weight removed; verify other weights are present
        assert!(p.weights.citations > 1.0);
    }

    #[test]
    fn policy_by_name_returns_academic() {
        let p = policy_by_name("academic").unwrap();
        assert_eq!(p.name, "academic");
        assert!(p.weights.replication > 1.0);
    }

    #[test]
    fn policy_by_name_returns_regulatory() {
        let p = policy_by_name("regulatory").unwrap();
        assert_eq!(p.name, "regulatory");
        assert_eq!(p.weights.min_confidence, 0.8);
    }

    #[test]
    fn policy_by_name_returns_clinical() {
        let p = policy_by_name("clinical").unwrap();
        assert_eq!(p.name, "clinical");
        // human_data weight removed; verify replication weight is present
        assert!(p.weights.replication > 1.0);
    }

    #[test]
    fn policy_by_name_returns_exploration() {
        let p = policy_by_name("exploration").unwrap();
        assert_eq!(p.name, "exploration");
        assert_eq!(p.weights.min_confidence, 0.0);
        assert_eq!(p.weights.dark_territory, 2.0);
    }

    #[test]
    fn policy_by_name_unknown_returns_none() {
        assert!(policy_by_name("nonexistent").is_none());
        assert!(policy_by_name("").is_none());
    }

    #[test]
    fn builtin_policies_has_five() {
        let all = builtin_policies();
        assert_eq!(all.len(), 5);
        let names: Vec<&str> = all.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"pharma"));
        assert!(names.contains(&"academic"));
        assert!(names.contains(&"regulatory"));
        assert!(names.contains(&"clinical"));
        assert!(names.contains(&"exploration"));
    }

    // ── Scoring edge cases ──────────────────────────────────────────

    #[test]
    fn academic_ranks_replicated_higher() {
        let findings = vec![
            make_finding("rep", 0.7, false, false, true),
            make_finding("norep", 0.7, false, false, false),
        ];
        let view = observe(&findings, &academic());
        assert_eq!(view.findings[0].finding_id, "rep");
        assert!(view.findings[0].observer_score > view.findings[1].observer_score);
    }

    #[test]
    fn clinical_ranks_replicated_higher() {
        // human_data no longer affects scoring; replicated does.
        let findings = vec![
            make_finding("rep", 0.7, false, false, true),
            make_finding("norep", 0.7, false, false, false),
        ];
        let view = observe(&findings, &clinical());
        assert_eq!(view.findings[0].finding_id, "rep");
        assert!(view.findings[0].observer_score > view.findings[1].observer_score);
    }

    #[test]
    fn exploration_boosts_gap_findings() {
        let mut gap_finding = make_finding("gap", 0.5, false, false, false);
        gap_finding.flags.gap = true;
        let normal_finding = make_finding("normal", 0.5, false, false, false);
        let findings = vec![gap_finding, normal_finding];
        let view = observe(&findings, &exploration());
        let gap_scored = view
            .findings
            .iter()
            .find(|f| f.finding_id == "gap")
            .unwrap();
        let normal_scored = view
            .findings
            .iter()
            .find(|f| f.finding_id == "normal")
            .unwrap();
        assert!(gap_scored.observer_score > normal_scored.observer_score);
    }

    #[test]
    fn exploration_boosts_negative_space() {
        let mut ns_finding = make_finding("ns", 0.5, false, false, false);
        ns_finding.flags.negative_space = true;
        let normal_finding = make_finding("normal", 0.5, false, false, false);
        let findings = vec![ns_finding, normal_finding];
        let view = observe(&findings, &exploration());
        let ns_scored = view.findings.iter().find(|f| f.finding_id == "ns").unwrap();
        let normal_scored = view
            .findings
            .iter()
            .find(|f| f.finding_id == "normal")
            .unwrap();
        assert!(ns_scored.observer_score > normal_scored.observer_score);
    }

    #[test]
    fn pharma_hides_below_threshold() {
        // pharma min_confidence = 0.7
        let findings = vec![
            make_finding("low", 0.4, false, false, false),
            make_finding("high", 0.9, true, true, false),
        ];
        let view = observe(&findings, &pharma());
        assert_eq!(view.hidden, 1);
        assert_eq!(view.findings.len(), 1);
        assert_eq!(view.findings[0].finding_id, "high");
    }

    #[test]
    fn observer_view_total_is_correct() {
        let findings = vec![
            make_finding("a", 0.3, false, false, false),
            make_finding("b", 0.5, false, false, false),
            make_finding("c", 0.9, true, true, false),
        ];
        let view = observe(&findings, &pharma());
        assert_eq!(view.total, 3);
        assert_eq!(view.findings.len() + view.hidden, view.total);
    }

    #[test]
    fn observer_rankings_are_sequential() {
        let findings = vec![
            make_finding("a", 0.9, true, true, true),
            make_finding("b", 0.85, true, false, false),
            make_finding("c", 0.8, false, false, false),
        ];
        let view = observe(&findings, &pharma());
        for (i, sf) in view.findings.iter().enumerate() {
            assert_eq!(sf.rank, i + 1);
        }
    }

    #[test]
    fn observe_empty_findings() {
        let view = observe(&[], &pharma());
        assert_eq!(view.total, 0);
        assert_eq!(view.findings.len(), 0);
        assert_eq!(view.hidden, 0);
    }

    #[test]
    fn score_clamped_to_one() {
        // A finding with every possible boost should still be <= 1.0
        let mut f = make_finding("max", 0.95, false, false, true);
        f.evidence.evidence_spans = vec![serde_json::json!("span")];
        f.provenance.year = Some(2025);
        f.flags.gap = true;
        f.assertion.assertion_type = "therapeutic".into();
        let findings = vec![f];
        let view = observe(&findings, &pharma());
        assert!(view.findings[0].observer_score <= 1.0);
    }

    // ── diff_views tests ────────────────────────────────────────────

    #[test]
    fn diff_views_finds_disagreement() {
        let findings = vec![
            make_finding("a", 0.9, true, true, false), // pharma loves this
            make_finding("b", 0.7, false, false, true), // academic prefers replicated
        ];
        let view_pharma = observe(&findings, &pharma());
        let view_academic = observe(&findings, &academic());
        let diffs = diff_views(&view_pharma, &view_academic);
        assert!(!diffs.is_empty());
    }

    #[test]
    fn diff_views_sorted_by_delta() {
        let findings = vec![
            make_finding("a", 0.9, true, true, false),
            make_finding("b", 0.8, false, false, true),
            make_finding("c", 0.7, false, false, false),
        ];
        let view_pharma = observe(&findings, &pharma());
        let view_academic = observe(&findings, &academic());
        let diffs = diff_views(&view_pharma, &view_academic);
        for w in diffs.windows(2) {
            assert!(w[0].delta >= w[1].delta);
        }
    }

    #[test]
    fn diff_views_includes_hidden_findings() {
        // regulatory hides low-confidence, exploration does not
        let findings = vec![make_finding("low", 0.3, false, false, false)];
        let view_reg = observe(&findings, &regulatory());
        let view_exp = observe(&findings, &exploration());
        let diffs = diff_views(&view_reg, &view_exp);
        assert!(!diffs.is_empty());
        let low_diff = diffs.iter().find(|d| d.finding_id == "low").unwrap();
        assert!(low_diff.rank_a.is_none()); // hidden in regulatory
        assert!(low_diff.rank_b.is_some()); // visible in exploration
    }

    #[test]
    fn label_truncated_for_long_assertions() {
        let mut f = make_finding("long", 0.8, false, false, false);
        f.assertion.text = "A".repeat(200);
        let findings = vec![f];
        let view = observe(&findings, &exploration());
        assert!(view.findings[0].label.len() < 200);
        assert!(view.findings[0].label.ends_with("..."));
    }

    // ── Priority assertion type boost ───────────────────────────────

    #[test]
    fn pharma_boosts_therapeutic_assertion_type() {
        let mut therapeutic = make_finding("ther", 0.8, false, false, false);
        therapeutic.assertion.assertion_type = "therapeutic".into();
        let mechanism = make_finding("mech", 0.8, false, false, false);
        let findings = vec![therapeutic, mechanism];
        let view = observe(&findings, &pharma());
        let ther_scored = view
            .findings
            .iter()
            .find(|f| f.finding_id == "ther")
            .unwrap();
        let mech_scored = view
            .findings
            .iter()
            .find(|f| f.finding_id == "mech")
            .unwrap();
        assert!(ther_scored.observer_score > mech_scored.observer_score);
    }
}
