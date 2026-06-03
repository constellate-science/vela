//! Stage 4: LINK — infer typed relationships between findings.
//!
//! Two passes:
//! 1. **Deterministic** (`deterministic_links`): O(n^2) entity-overlap scan, no API calls.
//! 2. **LLM** (`infer_links`): existing LLM-based inference on top, with dedup/merge.
//!
//! ## Integration
//!
//! Add to the compile pipeline in main.rs, BEFORE `infer_links`:
//! ```ignore
//! let det_count = link::deterministic_links(&mut all_bundles);
//! println!("  -> {det_count} deterministic links (entity overlap)");
//! let llm_count = link::infer_links(&client, &config, &mut all_bundles).await.unwrap_or(0);
//! println!("  -> {llm_count} LLM links inferred");
//! ```
use crate::bundle::FindingBundle;
use std::collections::HashSet;
// ── Deterministic entity-overlap linking ─────────────────────────────

/// Run a fast, deterministic linking pass based on shared entities between
/// findings. Returns the number of links created.
///
/// Rules:
/// - Shared entity, different papers -> "extends"
/// - Shared entity, opposite direction (positive/negative) -> "contradicts"
/// - Shared entity, same direction, newer + higher confidence -> "supersedes"
/// - 2+ shared entities -> noted as strong overlap in the link note
pub fn deterministic_links(bundles: &mut [FindingBundle]) -> usize {
    let n = bundles.len();
    if n < 2 {
        return 0;
    }

    // Pre-compute normalized entity sets for each bundle.
    // Include aliases so that "NLRP3" in one paper matches "cryopyrin" in another.
    let entity_sets: Vec<HashSet<String>> = bundles
        .iter()
        .map(|b| {
            let mut names = HashSet::new();
            for e in &b.assertion.entities {
                names.insert(e.name.to_lowercase());
                for alias in &e.aliases {
                    names.insert(alias.to_lowercase());
                }
            }
            names
        })
        .collect();

    // Pre-compute DOIs for same-paper detection.
    let dois: Vec<Option<String>> = bundles
        .iter()
        .map(|b| b.provenance.doi.as_ref().map(|d| d.to_lowercase()))
        .collect();

    // Collect all links first to avoid borrow issues.
    struct PendingLink {
        from_idx: usize,
        to_id: String,
        link_type: String,
        note: String,
    }

    let mut pending: Vec<PendingLink> = Vec::new();

    for i in 0..n {
        for j in (i + 1)..n {
            let shared: HashSet<&String> = entity_sets[i].intersection(&entity_sets[j]).collect();
            if shared.is_empty() {
                continue;
            }

            let same_paper = match (&dois[i], &dois[j]) {
                (Some(a), Some(b)) => a == b,
                _ => false,
            };

            // Skip intra-paper links (findings from the same paper already cohere).
            if same_paper {
                continue;
            }

            let shared_names: Vec<String> = shared.iter().map(|s| s.to_string()).collect();
            let overlap_count = shared_names.len();
            let overlap_label = shared_names.join(", ");
            let strong = overlap_count >= 2;

            // Determine link type.
            let dir_i = bundles[i].assertion.direction.as_deref();
            let dir_j = bundles[j].assertion.direction.as_deref();

            let (link_type, note) = if is_opposite(dir_i, dir_j) {
                (
                    "contradicts",
                    format!(
                        "Opposite directions on shared entit{}: {}{}",
                        if overlap_count == 1 { "y" } else { "ies" },
                        overlap_label,
                        if strong { " (strong overlap)" } else { "" }
                    ),
                )
            } else if is_same_direction(dir_i, dir_j) && could_supersede(bundles, i, j) {
                let (newer, _older) = if supersede_order(bundles, i, j) {
                    (i, j)
                } else {
                    (j, i)
                };
                let _is_i_newer = newer == i;
                (
                    "supersedes",
                    format!(
                        "Newer/higher-confidence finding on shared entit{}: {}{}",
                        if overlap_count == 1 { "y" } else { "ies" },
                        overlap_label,
                        if strong { " (strong overlap)" } else { "" }
                    ),
                )
            } else {
                (
                    "extends",
                    format!(
                        "Cross-paper shared entit{}: {}{}",
                        if overlap_count == 1 { "y" } else { "ies" },
                        overlap_label,
                        if strong { " (strong overlap)" } else { "" }
                    ),
                )
            };

            // For supersedes, only the newer finding gets the outgoing link.
            if link_type == "supersedes" {
                let (from_idx, to_idx) = if supersede_order(bundles, i, j) {
                    (i, j)
                } else {
                    (j, i)
                };
                pending.push(PendingLink {
                    from_idx,
                    to_id: bundles[to_idx].id.clone(),
                    link_type: link_type.to_string(),
                    note,
                });
            } else {
                // Bidirectional awareness: add from i -> j.
                pending.push(PendingLink {
                    from_idx: i,
                    to_id: bundles[j].id.clone(),
                    link_type: link_type.to_string(),
                    note,
                });
            }
        }
    }

    let count = pending.len();
    for pl in pending {
        bundles[pl.from_idx].add_link_with_source(&pl.to_id, &pl.link_type, &pl.note, "compiler");
    }

    count
}

/// True if two directions are opposite (positive vs negative).
fn is_opposite(a: Option<&str>, b: Option<&str>) -> bool {
    matches!(
        (a, b),
        (Some("positive"), Some("negative")) | (Some("negative"), Some("positive"))
    )
}

/// True if two directions are the same non-null value.
fn is_same_direction(a: Option<&str>, b: Option<&str>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => a == b && a != "null",
        _ => false,
    }
}

/// True if one finding plausibly supersedes the other (same direction, one is
/// newer with higher confidence).
fn could_supersede(bundles: &[FindingBundle], i: usize, j: usize) -> bool {
    let yi = bundles[i].provenance.year.unwrap_or(0);
    let yj = bundles[j].provenance.year.unwrap_or(0);
    let ci = bundles[i].confidence.score;
    let cj = bundles[j].confidence.score;

    // One must be strictly newer AND have higher confidence.
    (yi > yj && ci > cj) || (yj > yi && cj > ci)
}

/// Returns true if bundle[i] supersedes bundle[j] (i is newer+stronger).
fn supersede_order(bundles: &[FindingBundle], i: usize, j: usize) -> bool {
    let yi = bundles[i].provenance.year.unwrap_or(0);
    let yj = bundles[j].provenance.year.unwrap_or(0);
    let ci = bundles[i].confidence.score;
    let cj = bundles[j].confidence.score;
    yi > yj && ci > cj
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::*;

    fn make_finding(
        id: &str,
        entities: Vec<(&str, &str)>,
        direction: Option<&str>,
        doi: Option<&str>,
        year: i32,
        score: f64,
    ) -> FindingBundle {
        FindingBundle {
            id: id.into(),
            version: 1,
            previous_version: None,
            assertion: Assertion {
                text: format!("Finding {id}"),
                assertion_type: "mechanism".into(),
                entities: entities
                    .into_iter()
                    .map(|(name, etype)| Entity {
                        name: name.into(),
                        entity_type: etype.into(),
                        identifiers: serde_json::Map::new(),
                        canonical_id: None,
                        candidates: vec![],
                        aliases: vec![],
                        resolution_provenance: None,
                        resolution_confidence: 1.0,
                        resolution_method: None,
                        species_context: None,
                        needs_review: false,
                    })
                    .collect(),
                relation: None,
                direction: direction.map(|s| s.to_string()),
                causal_claim: None,
                causal_evidence_grade: None,
            },
            evidence: Evidence {
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
            confidence: Confidence::raw(score, "seeded prior", 0.85),
            provenance: Provenance {
                source_type: "published_paper".into(),
                doi: doi.map(|s| s.to_string()),
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
            created: String::new(),
            updated: None,

            access_tier: crate::access_tier::AccessTier::Public,
        }
    }

    #[test]
    fn shared_entity_creates_extends_link() {
        let mut bundles = vec![
            make_finding(
                "f1",
                vec![("NLRP3", "protein")],
                None,
                Some("10.1/a"),
                2020,
                0.7,
            ),
            make_finding(
                "f2",
                vec![("NLRP3", "protein")],
                None,
                Some("10.1/b"),
                2021,
                0.7,
            ),
        ];
        let count = deterministic_links(&mut bundles);
        assert_eq!(count, 1);
        assert_eq!(bundles[0].links.len(), 1);
        assert_eq!(bundles[0].links[0].link_type, "extends");
        assert_eq!(bundles[0].links[0].target, "f2");
    }

    #[test]
    fn opposite_directions_creates_contradicts_link() {
        let mut bundles = vec![
            make_finding(
                "f1",
                vec![("NLRP3", "protein")],
                Some("positive"),
                Some("10.1/a"),
                2020,
                0.7,
            ),
            make_finding(
                "f2",
                vec![("NLRP3", "protein")],
                Some("negative"),
                Some("10.1/b"),
                2021,
                0.7,
            ),
        ];
        let count = deterministic_links(&mut bundles);
        assert_eq!(count, 1);
        assert_eq!(bundles[0].links[0].link_type, "contradicts");
    }

    #[test]
    fn newer_higher_confidence_creates_supersedes() {
        let mut bundles = vec![
            make_finding(
                "f1",
                vec![("NLRP3", "protein")],
                Some("positive"),
                Some("10.1/a"),
                2018,
                0.6,
            ),
            make_finding(
                "f2",
                vec![("NLRP3", "protein")],
                Some("positive"),
                Some("10.1/b"),
                2024,
                0.9,
            ),
        ];
        let count = deterministic_links(&mut bundles);
        assert_eq!(count, 1);
        // f2 is newer+stronger, so it gets the supersedes link pointing to f1
        assert_eq!(bundles[1].links.len(), 1);
        assert_eq!(bundles[1].links[0].link_type, "supersedes");
        assert_eq!(bundles[1].links[0].target, "f1");
    }

    #[test]
    fn no_shared_entities_no_link() {
        let mut bundles = vec![
            make_finding(
                "f1",
                vec![("NLRP3", "protein")],
                None,
                Some("10.1/a"),
                2020,
                0.7,
            ),
            make_finding(
                "f2",
                vec![("APOE4", "gene")],
                None,
                Some("10.1/b"),
                2021,
                0.7,
            ),
        ];
        let count = deterministic_links(&mut bundles);
        assert_eq!(count, 0);
        assert!(bundles[0].links.is_empty());
        assert!(bundles[1].links.is_empty());
    }

    #[test]
    fn same_paper_skipped() {
        let mut bundles = vec![
            make_finding(
                "f1",
                vec![("NLRP3", "protein")],
                None,
                Some("10.1/same"),
                2020,
                0.7,
            ),
            make_finding(
                "f2",
                vec![("NLRP3", "protein")],
                None,
                Some("10.1/same"),
                2020,
                0.7,
            ),
        ];
        let count = deterministic_links(&mut bundles);
        assert_eq!(count, 0);
    }

    #[test]
    fn single_bundle_no_links() {
        let mut bundles = vec![make_finding(
            "f1",
            vec![("NLRP3", "protein")],
            None,
            Some("10.1/a"),
            2020,
            0.7,
        )];
        let count = deterministic_links(&mut bundles);
        assert_eq!(count, 0);
    }

    #[test]
    fn empty_bundles_no_links() {
        let mut bundles: Vec<FindingBundle> = vec![];
        let count = deterministic_links(&mut bundles);
        assert_eq!(count, 0);
    }

    #[test]
    fn strong_overlap_noted() {
        let mut bundles = vec![
            make_finding(
                "f1",
                vec![("NLRP3", "protein"), ("IL-1β", "protein")],
                None,
                Some("10.1/a"),
                2020,
                0.7,
            ),
            make_finding(
                "f2",
                vec![("NLRP3", "protein"), ("IL-1β", "protein")],
                None,
                Some("10.1/b"),
                2021,
                0.7,
            ),
        ];
        let count = deterministic_links(&mut bundles);
        assert_eq!(count, 1);
        assert!(bundles[0].links[0].note.contains("strong overlap"));
    }

    #[test]
    fn alias_matching_works() {
        let mut bundles = vec![
            make_finding("f1", vec![], None, Some("10.1/a"), 2020, 0.7),
            make_finding("f2", vec![], None, Some("10.1/b"), 2021, 0.7),
        ];
        // Add entity with alias to f1
        bundles[0].assertion.entities.push(Entity {
            name: "NLRP3".into(),
            entity_type: "protein".into(),
            identifiers: serde_json::Map::new(),
            canonical_id: None,
            candidates: vec![],
            aliases: vec!["cryopyrin".into()],
            resolution_provenance: None,
            resolution_confidence: 1.0,
            resolution_method: None,
            species_context: None,
            needs_review: false,
        });
        // Add entity matching the alias in f2
        bundles[1].assertion.entities.push(Entity {
            name: "cryopyrin".into(),
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
        });
        let count = deterministic_links(&mut bundles);
        assert_eq!(count, 1);
    }

    #[test]
    fn link_inferred_by_is_compiler() {
        let mut bundles = vec![
            make_finding(
                "f1",
                vec![("NLRP3", "protein")],
                None,
                Some("10.1/a"),
                2020,
                0.7,
            ),
            make_finding(
                "f2",
                vec![("NLRP3", "protein")],
                None,
                Some("10.1/b"),
                2021,
                0.7,
            ),
        ];
        deterministic_links(&mut bundles);
        assert_eq!(bundles[0].links[0].inferred_by, "compiler");
    }

    #[test]
    fn is_opposite_helper() {
        assert!(is_opposite(Some("positive"), Some("negative")));
        assert!(is_opposite(Some("negative"), Some("positive")));
        assert!(!is_opposite(Some("positive"), Some("positive")));
        assert!(!is_opposite(None, Some("negative")));
        assert!(!is_opposite(None, None));
    }

    #[test]
    fn is_same_direction_helper() {
        assert!(is_same_direction(Some("positive"), Some("positive")));
        assert!(!is_same_direction(Some("positive"), Some("negative")));
        assert!(!is_same_direction(None, None));
        assert!(!is_same_direction(Some("null"), Some("null")));
    }

    #[test]
    fn valid_link_types_list() {
        assert!(VALID_LINK_TYPES.contains(&"supports"));
        assert!(VALID_LINK_TYPES.contains(&"contradicts"));
        assert!(VALID_LINK_TYPES.contains(&"extends"));
        assert!(VALID_LINK_TYPES.contains(&"supersedes"));
        assert!(!VALID_LINK_TYPES.contains(&"invalidtype"));
    }
}
