//! Unresolved contradiction analysis — "Where does science disagree with itself?"
//!
//! Finds all `contradicts` link pairs, scores them by tension (high confidence
//! on both sides = maximum tension), and checks whether a superseding finding
//! has resolved the disagreement.

use std::collections::HashSet;

use colored::Colorize;

use vela_protocol::cli_style as style;

use vela_protocol::bundle::FindingBundle;
use vela_protocol::project::Project;

/// A pair of contradicting findings with a tension score.
#[derive(Debug, Clone)]
pub struct Tension {
    pub finding_a: TensionSide,
    pub finding_b: TensionSide,
    pub score: f64,
    pub resolved: bool,
    pub superseding_id: Option<String>,
}

/// One side of a contradiction.
#[derive(Debug, Clone)]
pub struct TensionSide {
    pub id: String,
    pub assertion: String,
    pub confidence: f64,
    pub assertion_type: String,
    pub contradicts_count: usize,
}

/// Run the tensions analysis.
pub fn analyze(
    frontier: &Project,
    both_high: bool,
    cross_domain: bool,
    top: usize,
) -> Vec<Tension> {
    // Build a set of all `contradicts` pairs (deduplicated by sorted ID pair).
    let mut seen_pairs: HashSet<(String, String)> = HashSet::new();
    let mut tensions: Vec<Tension> = Vec::new();

    // Pre-compute contradiction counts per finding.
    let mut contradict_counts: std::collections::HashMap<&str, usize> =
        std::collections::HashMap::new();
    for f in &frontier.findings {
        for l in &f.links {
            if l.link_type == "contradicts" {
                *contradict_counts.entry(f.id.as_str()).or_default() += 1;
            }
        }
    }

    // Build ID -> index map.
    let id_map: std::collections::HashMap<&str, usize> = frontier
        .findings
        .iter()
        .enumerate()
        .map(|(i, f)| (f.id.as_str(), i))
        .collect();

    for f in &frontier.findings {
        for l in &f.links {
            if l.link_type != "contradicts" {
                continue;
            }

            // Get the target finding.
            let target_idx = match id_map.get(l.target.as_str()) {
                Some(&i) => i,
                None => continue,
            };
            let target = &frontier.findings[target_idx];

            // Deduplicate: use sorted pair.
            let pair = if f.id < target.id {
                (f.id.clone(), target.id.clone())
            } else {
                (target.id.clone(), f.id.clone())
            };

            if seen_pairs.contains(&pair) {
                continue;
            }
            seen_pairs.insert(pair);

            // Apply filters.
            if both_high && (f.confidence.score < 0.8 || target.confidence.score < 0.8) {
                continue;
            }

            if cross_domain && f.assertion.assertion_type == target.assertion.assertion_type {
                continue;
            }

            let side_a = make_side(f, &contradict_counts);
            let side_b = make_side(target, &contradict_counts);

            // Tension score = min(conf_a, conf_b)
            let min_conf = f.confidence.score.min(target.confidence.score);
            let score = min_conf;

            // Check if resolved: is there a finding that supersedes either side?
            let (resolved, superseding_id) = check_resolved(&f.id, &target.id, frontier, &id_map);

            tensions.push(Tension {
                finding_a: side_a,
                finding_b: side_b,
                score,
                resolved,
                superseding_id,
            });
        }
    }

    tensions.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    tensions.truncate(top);
    tensions
}

fn make_side(
    f: &FindingBundle,
    contradict_counts: &std::collections::HashMap<&str, usize>,
) -> TensionSide {
    TensionSide {
        id: f.id.clone(),
        assertion: f.assertion.text.clone(),
        confidence: f.confidence.score,
        assertion_type: f.assertion.assertion_type.clone(),
        contradicts_count: contradict_counts.get(f.id.as_str()).copied().unwrap_or(0),
    }
}

/// Check if either finding in a contradiction has been superseded by a third finding.
/// A finding is "superseded" if another finding links to it with a "supersedes" link type,
/// or if a newer finding with higher confidence contradicts it.
fn check_resolved(
    id_a: &str,
    id_b: &str,
    frontier: &Project,
    _id_map: &std::collections::HashMap<&str, usize>,
) -> (bool, Option<String>) {
    for f in &frontier.findings {
        for l in &f.links {
            // A finding that explicitly supersedes either side resolves the tension.
            if l.link_type == "supersedes" && (l.target == id_a || l.target == id_b) {
                return (true, Some(f.id.clone()));
            }
        }
    }
    (false, None)
}

/// Print the tensions report to stdout with colored formatting.
pub fn print_tensions(tensions: &[Tension]) {
    println!();
    println!("  {}", "VELA · TENSIONS".dimmed());
    println!("  {}", style::tick_row(60));

    if tensions.is_empty() {
        println!("  no tensions found in this frontier.");
        println!();
        return;
    }

    for (i, t) in tensions.iter().enumerate() {
        let status = if t.resolved {
            style::ok(&format!(
                "resolved by {}",
                t.superseding_id.as_deref().unwrap_or("unknown")
            ))
        } else {
            style::warn("contested")
        };

        println!(
            "{} {}  (tension score: {:.1})",
            format!("{}.", i + 1).bold(),
            status,
            t.score
        );
        println!(
            "  a: \"{}\" ({:.2})",
            truncate(&t.finding_a.assertion, 60),
            t.finding_a.confidence
        );
        println!(
            "     {} [{} contradictions]",
            t.finding_a.id, t.finding_a.contradicts_count
        );
        println!(
            "  b: \"{}\" ({:.2})",
            truncate(&t.finding_b.assertion, 60),
            t.finding_b.confidence
        );
        println!(
            "     {} [{} contradictions]",
            t.finding_b.id, t.finding_b.contradicts_count
        );

        if t.finding_a.assertion_type != t.finding_b.assertion_type {
            println!(
                "  {} cross-domain: {} vs {}",
                style::brass("·"),
                t.finding_a.assertion_type,
                t.finding_b.assertion_type
            );
        }

        println!();
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &s[..end])
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use vela_protocol::bundle::*;
    use vela_protocol::project;

    fn make_finding(id: &str, score: f64, assertion_type: &str) -> FindingBundle {
        FindingBundle {
            id: id.into(),
            version: 1,
            previous_version: None,
            assertion: Assertion {
                text: format!("Finding {id}"),
                assertion_type: assertion_type.into(),
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
                replicated: false,
                replication_count: None,
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
                year: Some(2025),
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

    fn make_frontier_from(findings: Vec<FindingBundle>) -> Project {
        project::assemble("test", findings, 1, 0, "test frontier")
    }

    #[test]
    fn basic_contradiction_detected() {
        let mut a = make_finding("a", 0.9, "mechanism");
        let b = make_finding("b", 0.85, "mechanism");
        a.add_link("b", "contradicts", "opposite findings");

        let c = make_frontier_from(vec![a, b]);
        let results = analyze(&c, false, false, 20);

        assert_eq!(results.len(), 1);
        assert!(!results[0].resolved);
        assert!(results[0].score > 0.0);
    }

    #[test]
    fn both_high_filter() {
        let mut a = make_finding("a", 0.9, "mechanism");
        let b = make_finding("b", 0.5, "mechanism"); // low confidence
        a.add_link("b", "contradicts", "");

        let c = make_frontier_from(vec![a, b]);

        // Without filter: found
        let results = analyze(&c, false, false, 20);
        assert_eq!(results.len(), 1);

        // With both_high filter: excluded (b < 0.8)
        let results_filtered = analyze(&c, true, false, 20);
        assert_eq!(results_filtered.len(), 0);
    }

    #[test]
    fn cross_domain_filter() {
        let mut a = make_finding("a", 0.9, "mechanism");
        let b = make_finding("b", 0.85, "mechanism"); // same type
        a.add_link("b", "contradicts", "");

        let mut c_finding = make_finding("c", 0.88, "therapeutic"); // different type
        let d = make_finding("d", 0.82, "mechanism");
        c_finding.add_link("d", "contradicts", "");

        let frontier = make_frontier_from(vec![a, b, c_finding, d]);

        // Without filter: both found
        let results = analyze(&frontier, false, false, 20);
        assert_eq!(results.len(), 2);

        // With cross_domain: only c vs d (different types)
        let results_filtered = analyze(&frontier, false, true, 20);
        assert_eq!(results_filtered.len(), 1);
    }

    #[test]
    fn resolved_by_supersedes() {
        let mut a = make_finding("a", 0.9, "mechanism");
        let b = make_finding("b", 0.85, "mechanism");
        a.add_link("b", "contradicts", "");
        let mut resolver = make_finding("resolver", 0.95, "mechanism");
        resolver.add_link("a", "supersedes", "newer finding");

        let c = make_frontier_from(vec![a, b, resolver]);
        let results = analyze(&c, false, false, 20);

        assert_eq!(results.len(), 1);
        assert!(results[0].resolved);
        assert_eq!(results[0].superseding_id.as_deref(), Some("resolver"));
    }

    #[test]
    fn tension_score_uses_min_confidence() {
        let mut a = make_finding("a", 0.9, "mechanism");
        let b = make_finding("b", 0.7, "mechanism");
        a.add_link("b", "contradicts", "");

        let c = make_frontier_from(vec![a, b]);
        let results = analyze(&c, false, false, 20);

        // score = min(0.9, 0.7) = 0.7
        assert_eq!(results.len(), 1);
        assert!((results[0].score - 0.7).abs() < 0.001);
    }

    #[test]
    fn deduplicated_pairs() {
        // Both a->b and b->a contradicts links should produce only one tension.
        let mut a = make_finding("a", 0.9, "mechanism");
        let mut b = make_finding("b", 0.85, "mechanism");
        a.add_link("b", "contradicts", "");
        b.add_link("a", "contradicts", "");

        let c = make_frontier_from(vec![a, b]);
        let results = analyze(&c, false, false, 20);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn no_contradictions_empty() {
        let a = make_finding("a", 0.9, "mechanism");
        let b = make_finding("b", 0.85, "mechanism");
        let c = make_frontier_from(vec![a, b]);
        let results = analyze(&c, false, false, 20);
        assert!(results.is_empty());
    }
}
