//! Full-text search across findings in a frontier or VelaRepo.

use std::path::Path;

use colored::Colorize;

use vela_protocol::cli_style as style;

use vela_protocol::bundle::FindingBundle;
use vela_protocol::project::Project;
use vela_protocol::repo;

/// A single search result with relevance score.
pub struct SearchResult {
    pub id: String,
    pub score: f32,
    pub assertion: String,
    pub assertion_type: String,
    pub confidence: f64,
    pub entities: Vec<String>,
    pub doi: Option<String>,
}

/// Search findings by query text, with optional entity and assertion type filters.
///
/// Scoring: query word matches in assertion text (x2), entity names (x3),
/// conditions text (x1). Normalized by total query words.
pub fn search(
    source_path: &Path,
    query: &str,
    entity_filter: Option<&str>,
    type_filter: Option<&str>,
    limit: usize,
) -> Vec<SearchResult> {
    let frontier = match repo::load_from_path(source_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{} failed to load frontier: {e}", style::err_prefix());
            return Vec::new();
        }
    };

    let query_words: Vec<String> = query
        .to_lowercase()
        .split_whitespace()
        .map(|w| w.to_string())
        .collect();

    if query_words.is_empty() {
        return Vec::new();
    }

    let mut results: Vec<SearchResult> = frontier
        .findings
        .iter()
        .filter(|f| {
            if let Some(ef) = entity_filter {
                let ef_lower = ef.to_lowercase();
                if !f
                    .assertion
                    .entities
                    .iter()
                    .any(|e| e.name.to_lowercase().contains(&ef_lower))
                {
                    return false;
                }
            }
            if let Some(tf) = type_filter
                && f.assertion.assertion_type.to_lowercase() != tf.to_lowercase()
            {
                return false;
            }
            true
        })
        .filter_map(|f| {
            let score = score_finding(f, &query_words);
            if score > 0.0 {
                Some(SearchResult {
                    id: f.id.clone(),
                    score,
                    assertion: f.assertion.text.clone(),
                    assertion_type: f.assertion.assertion_type.clone(),
                    confidence: f.confidence.score,
                    entities: f
                        .assertion
                        .entities
                        .iter()
                        .map(|e| e.name.clone())
                        .collect(),
                    doi: f.provenance.doi.clone(),
                })
            } else {
                None
            }
        })
        .collect();

    results.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    results.truncate(limit);
    results
}

/// Score a finding against query words.
fn score_finding(finding: &FindingBundle, query_words: &[String]) -> f32 {
    let assertion_lower = finding.assertion.text.to_lowercase();
    let conditions_lower = finding.conditions.text.to_lowercase();

    let mut total_score: f32 = 0.0;

    for word in query_words {
        // Assertion text matches (weight x2)
        if assertion_lower.contains(word.as_str()) {
            total_score += 2.0;
        }

        // Entity name matches (weight x3)
        for entity in &finding.assertion.entities {
            if entity.name.to_lowercase().contains(word.as_str()) {
                total_score += 3.0;
            }
        }

        // Conditions text matches (weight x1)
        if conditions_lower.contains(word.as_str()) {
            total_score += 1.0;
        }
    }

    // Normalize by number of query words
    total_score / query_words.len() as f32
}

fn truncate_for_cli(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    let keep = max_chars.saturating_sub(3);
    let prefix: String = text.chars().take(keep).collect();
    format!("{prefix}...")
}

/// CLI entry point for `vela search`.
pub fn run(
    source: &Path,
    query: &str,
    entity: Option<&str>,
    type_filter: Option<&str>,
    limit: usize,
) {
    let results = search(source, query, entity, type_filter, limit);

    if results.is_empty() {
        println!("no findings matched the query.");
        return;
    }

    println!();
    println!(
        "  {} results for {}",
        results.len(),
        format!("\"{}\"", query).bold()
    );
    println!("  {}", style::tick_row(60));

    for (i, r) in results.iter().enumerate() {
        let truncated = truncate_for_cli(&r.assertion, 120);

        println!(
            "  {}. {} [score: {:.2}] [conf: {:.2}] [{}]",
            (i + 1).to_string().dimmed(),
            style::signal(&r.id),
            r.score,
            r.confidence,
            style::dust_color(&r.assertion_type),
        );
        println!("     {}", truncated);
        if !r.entities.is_empty() {
            println!("     entities: {}", r.entities.join(", ").dimmed());
        }
        if let Some(doi) = &r.doi {
            println!("     doi: {}", doi.dimmed());
        }
        println!();
    }
}

// ── Cross-frontier search ───────────────────────────────────────────

/// A search result grouped by source frontier.
pub struct CrossFrontierResult {
    pub frontier_name: String,
    pub frontier_file: String,
    pub results: Vec<SearchResult>,
}

/// Search a pre-loaded frontier (avoids re-loading from disk).
pub fn search_frontier(
    frontier: &Project,
    query: &str,
    entity_filter: Option<&str>,
    type_filter: Option<&str>,
    limit: usize,
) -> Vec<SearchResult> {
    let query_words: Vec<String> = query
        .to_lowercase()
        .split_whitespace()
        .map(|w| w.to_string())
        .collect();

    if query_words.is_empty() {
        return Vec::new();
    }

    let mut results: Vec<SearchResult> = frontier
        .findings
        .iter()
        .filter(|f| {
            if let Some(ef) = entity_filter {
                let ef_lower = ef.to_lowercase();
                if !f
                    .assertion
                    .entities
                    .iter()
                    .any(|e| e.name.to_lowercase().contains(&ef_lower))
                {
                    return false;
                }
            }
            if let Some(tf) = type_filter
                && f.assertion.assertion_type.to_lowercase() != tf.to_lowercase()
            {
                return false;
            }
            true
        })
        .filter_map(|f| {
            let score = score_finding(f, &query_words);
            if score > 0.0 {
                Some(SearchResult {
                    id: f.id.clone(),
                    score,
                    assertion: f.assertion.text.clone(),
                    assertion_type: f.assertion.assertion_type.clone(),
                    confidence: f.confidence.score,
                    entities: f
                        .assertion
                        .entities
                        .iter()
                        .map(|e| e.name.clone())
                        .collect(),
                    doi: f.provenance.doi.clone(),
                })
            } else {
                None
            }
        })
        .collect();

    results.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    results.truncate(limit);
    results
}

/// Search across all `.json` frontier files in a directory.
///
/// Loads each frontier, runs scored search, collects top `limit` results
/// sorted by score across all frontiers, then groups by frontier.
pub fn search_all(
    dir: &Path,
    query: &str,
    entity_filter: Option<&str>,
    type_filter: Option<&str>,
    limit: usize,
) -> Vec<CrossFrontierResult> {
    // Collect all .json files in the directory
    let entries: Vec<std::path::PathBuf> = match std::fs::read_dir(dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|ext| ext == "json"))
            .collect(),
        Err(e) => {
            eprintln!(
                "{} failed to read directory '{}': {e}",
                style::err_prefix(),
                dir.display()
            );
            return Vec::new();
        }
    };

    if entries.is_empty() {
        eprintln!("no .json frontier files found in {}", dir.display());
        return Vec::new();
    }

    // Score every finding across all frontiers, keeping frontier provenance
    let mut scored: Vec<(String, String, SearchResult)> = Vec::new(); // (name, file, result)

    for path in &entries {
        let frontier = match repo::load_from_path(path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("skipping {}: {e}", path.display());
                continue;
            }
        };

        let name = frontier.project.name.clone();
        let file = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        // Get all results from this frontier (no per-frontier limit yet)
        let results = search_frontier(&frontier, query, entity_filter, type_filter, usize::MAX);
        for r in results {
            scored.push((name.clone(), file.clone(), r));
        }
    }

    // Sort all results by score descending, take top `limit`
    scored.sort_by(|a, b| {
        b.2.score
            .partial_cmp(&a.2.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    scored.truncate(limit);

    // Group by frontier, preserving sort order within each group
    let mut groups: Vec<CrossFrontierResult> = Vec::new();
    let mut seen_frontiers: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();

    for (name, file, result) in scored {
        if let Some(&idx) = seen_frontiers.get(&file) {
            groups[idx].results.push(result);
        } else {
            let idx = groups.len();
            seen_frontiers.insert(file.clone(), idx);
            groups.push(CrossFrontierResult {
                frontier_name: name,
                frontier_file: file,
                results: vec![result],
            });
        }
    }

    groups
}

/// CLI entry point for `vela search --all <dir>`.
pub fn run_all(
    dir: &Path,
    query: &str,
    entity: Option<&str>,
    type_filter: Option<&str>,
    limit: usize,
) {
    let groups = search_all(dir, query, entity, type_filter, limit);

    if groups.is_empty() {
        println!("no findings matched the query across any frontier.");
        return;
    }

    let total_results: usize = groups.iter().map(|g| g.results.len()).sum();
    let frontier_count = groups.len();

    println!();
    println!(
        "  {} results across {} frontiers for {}",
        total_results,
        frontier_count,
        format!("\"{}\"", query).bold(),
    );
    println!("  {}", style::tick_row(60));

    for group in &groups {
        let stem = group
            .frontier_file
            .strip_suffix(".json")
            .unwrap_or(&group.frontier_file);
        println!(
            "  [{}] {} results",
            style::signal(stem),
            group.results.len()
        );
        for (i, r) in group.results.iter().enumerate() {
            let truncated = truncate_for_cli(&r.assertion, 100);
            println!(
                "    {}. {} [score: {:.1}] [conf: {:.2}] {}",
                (i + 1).to_string().dimmed(),
                style::signal(&r.id),
                r.score,
                r.confidence,
                truncated,
            );
        }
        println!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use vela_protocol::bundle::*;
    use vela_protocol::project;

    fn make_finding(
        id: &str,
        assertion: &str,
        assertion_type: &str,
        entities: Vec<(&str, &str)>,
        conditions: &str,
        confidence: f64,
        doi: Option<&str>,
    ) -> FindingBundle {
        FindingBundle {
            id: id.into(),
            version: 1,
            previous_version: None,
            assertion: Assertion {
                text: assertion.into(),
                assertion_type: assertion_type.into(),
                entities: entities
                    .iter()
                    .map(|(name, etype)| Entity {
                        name: name.to_string(),
                        entity_type: etype.to_string(),
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
                text: conditions.into(),
                duration: None,
            },
            confidence: Confidence::raw(confidence, "test", 0.85),
            provenance: Provenance {
                source_type: "published_paper".into(),
                doi: doi.map(|s| s.to_string()),
                url: None,
                title: "Test Paper".into(),
                authors: vec![],
                year: Some(2024),
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

    fn write_test_frontier(dir: &Path) -> std::path::PathBuf {
        let findings = vec![
            make_finding(
                "vf_0000000000000001",
                "NLRP3 activates caspase-1 in microglia",
                "mechanism",
                vec![("NLRP3", "protein"), ("caspase-1", "protein")],
                "in vitro mouse",
                0.9,
                Some("10.1234/a"),
            ),
            make_finding(
                "vf_0000000000000002",
                "Tau phosphorylation increases in Alzheimer disease",
                "biomarker",
                vec![("Tau", "protein"), ("Alzheimer disease", "disease")],
                "human brain tissue",
                0.85,
                Some("10.1234/b"),
            ),
            make_finding(
                "vf_0000000000000003",
                "Donepezil improves cognition in mild AD patients",
                "therapeutic",
                vec![("Donepezil", "compound"), ("Alzheimer disease", "disease")],
                "clinical trial phase 3",
                0.95,
                None,
            ),
        ];
        let c = project::assemble("test-frontier", findings, 3, 0, "Test");
        let path = dir.join("test.json");
        let json = serde_json::to_string_pretty(&c).unwrap();
        std::fs::write(&path, json).unwrap();
        path
    }

    #[test]
    fn search_by_query_returns_scored_results() {
        let tmp = TempDir::new().unwrap();
        let path = write_test_frontier(tmp.path());
        let results = search(&path, "NLRP3 caspase", None, None, 10);
        assert!(!results.is_empty());
        assert_eq!(results[0].id, "vf_0000000000000001");
        assert!(results[0].score > 0.0);
    }

    #[test]
    fn search_with_entity_filter() {
        let tmp = TempDir::new().unwrap();
        let path = write_test_frontier(tmp.path());
        let results = search(&path, "disease", Some("Tau"), None, 10);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "vf_0000000000000002");
    }

    #[test]
    fn search_with_type_filter() {
        let tmp = TempDir::new().unwrap();
        let path = write_test_frontier(tmp.path());
        let results = search(&path, "Alzheimer", None, Some("therapeutic"), 10);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "vf_0000000000000003");
    }

    #[test]
    fn search_no_match_returns_empty() {
        let tmp = TempDir::new().unwrap();
        let path = write_test_frontier(tmp.path());
        let results = search(&path, "xyzzyfoobar", None, None, 10);
        assert!(results.is_empty());
    }

    #[test]
    fn search_respects_limit() {
        let tmp = TempDir::new().unwrap();
        let path = write_test_frontier(tmp.path());
        let results = search(&path, "disease", None, None, 1);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn entity_match_scores_higher_than_assertion() {
        let tmp = TempDir::new().unwrap();
        let path = write_test_frontier(tmp.path());
        // "NLRP3" appears in both entity name and assertion text for finding 1
        // but only in assertion text for others (if any)
        let results = search(&path, "NLRP3", None, None, 10);
        assert!(!results.is_empty());
        // First result should have entity match (score = (2+3)/1 = 5.0)
        assert!(results[0].score >= 5.0);
    }

    #[test]
    fn truncate_for_cli_preserves_utf8_boundaries() {
        let text = "Erdős proved that a B₂[1] Sidon set satisfies |A| ≤ √n + O(n^{1/4}) on [1, n].";
        let truncated = truncate_for_cli(text, 48);
        assert!(truncated.ends_with("..."));
        assert!(truncated.len() <= text.len());
        assert!(std::str::from_utf8(truncated.as_bytes()).is_ok());
    }

    // ── Cross-frontier search tests ─────────────────────────────────

    fn write_second_frontier(dir: &Path) -> std::path::PathBuf {
        let findings = vec![
            make_finding(
                "vf_1000000000000001",
                "Iron accumulation in senescent cells",
                "mechanism",
                vec![("iron", "compound"), ("senescent cells", "cell_type")],
                "in vitro human fibroblasts",
                0.88,
                Some("10.5678/a"),
            ),
            make_finding(
                "vf_1000000000000002",
                "Ferrostatin-1 prevents iron-mediated neuronal death after TBI",
                "therapeutic",
                vec![("Ferrostatin-1", "compound"), ("iron", "compound")],
                "mouse model TBI",
                0.94,
                Some("10.5678/b"),
            ),
        ];
        let c = project::assemble("iron-biology", findings, 2, 0, "Iron biology frontier");
        let path = dir.join("iron-biology.json");
        let json = serde_json::to_string_pretty(&c).unwrap();
        std::fs::write(&path, json).unwrap();
        path
    }

    #[test]
    fn search_all_finds_across_frontiers() {
        let tmp = TempDir::new().unwrap();
        write_test_frontier(tmp.path());
        write_second_frontier(tmp.path());

        let groups = search_all(tmp.path(), "iron", None, None, 20);
        assert!(!groups.is_empty());
        // Iron findings should come from the iron-biology frontier
        let total: usize = groups.iter().map(|g| g.results.len()).sum();
        assert!(
            total >= 2,
            "Expected at least 2 results for 'iron', got {total}"
        );
    }

    #[test]
    fn search_all_respects_limit() {
        let tmp = TempDir::new().unwrap();
        write_test_frontier(tmp.path());
        write_second_frontier(tmp.path());

        // Both frontiers have findings that match "disease" or broad terms
        // but we limit to 1 result total
        let groups = search_all(tmp.path(), "iron", None, None, 1);
        let total: usize = groups.iter().map(|g| g.results.len()).sum();
        assert_eq!(total, 1);
    }

    #[test]
    fn search_all_empty_dir_returns_empty() {
        let tmp = TempDir::new().unwrap();
        let empty_dir = tmp.path().join("empty");
        std::fs::create_dir_all(&empty_dir).unwrap();
        let groups = search_all(&empty_dir, "anything", None, None, 20);
        assert!(groups.is_empty());
    }
}
