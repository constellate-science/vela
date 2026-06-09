//! Benchmark extraction quality against a gold standard.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use colored::Colorize;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use vela_protocol::bundle::{Entity, FindingBundle};
use vela_protocol::cli_style as style;
use vela_protocol::project;
use vela_protocol::repo;

/// A single gold-standard finding.
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct GoldFinding {
    #[serde(default)]
    pub id: Option<String>,
    pub assertion_text: String,
    pub assertion_type: String,
    pub entities: Vec<String>,
    pub confidence_range: ConfidenceRange,
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ConfidenceRange {
    pub low: f64,
    pub high: f64,
}

/// Full benchmark report.
#[derive(Debug, Serialize)]
pub struct BenchmarkReport {
    pub total_frontier_findings: usize,
    pub total_gold_findings: usize,
    pub matched: usize,
    pub total_frontier_matched: usize,
    pub unmatched_gold: usize,
    pub unmatched_frontier: usize,
    pub exact_id_matches: usize,
    pub precision: f64,
    pub recall: f64,
    pub f1: f64,
    pub entity_accuracy: f64,
    pub assertion_type_accuracy: f64,
    pub confidence_calibration: f64,
    pub match_details: Vec<MatchDetail>,
}

#[derive(Debug, Serialize)]
pub struct MatchDetail {
    pub gold_id: Option<String>,
    pub frontier_id: String,
    pub gold_text: String,
    pub frontier_text: String,
    pub similarity: f64,
    pub entity_overlap: f64,
    pub assertion_type_match: bool,
    pub confidence_in_range: bool,
    pub exact_id_match: bool,
}

pub fn run(frontier_path: &Path, gold_path: &Path, json_output: bool) {
    let frontier = repo::load_from_path(frontier_path).expect("Failed to load frontier");

    let gold_data = std::fs::read_to_string(gold_path).expect("Failed to read gold standard file");
    let gold: Vec<GoldFinding> =
        serde_json::from_str(&gold_data).expect("Failed to parse gold standard JSON");

    let report = benchmark(&frontier.findings, &gold);

    if json_output {
        let json = serde_json::to_string_pretty(&report).unwrap();
        println!("{json}");
    } else {
        print_report(&report);
    }
}

pub fn benchmark(findings: &[FindingBundle], gold: &[GoldFinding]) -> BenchmarkReport {
    let mut match_details = Vec::new();
    let mut gold_matched = vec![false; gold.len()];
    let mut frontier_matched = vec![false; findings.len()];
    let mut candidates = Vec::new();

    for (gi, g) in gold.iter().enumerate() {
        for (fi, f) in findings.iter().enumerate() {
            let sim = jaccard_similarity(&g.assertion_text, &f.assertion.text);
            let exact_id = g.id.as_deref().is_some_and(|id| id == f.id);
            if exact_id || sim >= 0.2 {
                candidates.push(FindingCandidate {
                    gold_idx: gi,
                    frontier_idx: fi,
                    similarity: sim,
                    exact_id,
                    assertion_type_match: g.assertion_type == f.assertion.assertion_type,
                });
            }
        }
    }

    candidates.sort_by(|a, b| {
        b.exact_id
            .cmp(&a.exact_id)
            .then_with(|| {
                b.similarity
                    .partial_cmp(&a.similarity)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| b.assertion_type_match.cmp(&a.assertion_type_match))
            .then_with(|| a.gold_idx.cmp(&b.gold_idx))
            .then_with(|| a.frontier_idx.cmp(&b.frontier_idx))
    });

    for candidate in candidates {
        let gi = candidate.gold_idx;
        let fi = candidate.frontier_idx;
        if gold_matched[gi] || frontier_matched[fi] {
            continue;
        }

        gold_matched[gi] = true;
        frontier_matched[fi] = true;

        let g = &gold[gi];
        let f = &findings[fi];

        let gold_entities: HashSet<String> =
            g.entities.iter().map(|e| normalize_token(e)).collect();
        let frontier_entities: HashSet<String> = f
            .assertion
            .entities
            .iter()
            .map(|e| normalize_token(&e.name))
            .collect();
        let entity_overlap = if gold_entities.is_empty() {
            1.0
        } else {
            let matches = gold_entities
                .iter()
                .filter(|e| frontier_entities.contains(*e))
                .count();
            matches as f64 / gold_entities.len() as f64
        };

        let in_range = f.confidence.score >= g.confidence_range.low
            && f.confidence.score <= g.confidence_range.high;

        match_details.push(MatchDetail {
            gold_id: g.id.clone(),
            frontier_id: f.id.clone(),
            gold_text: truncate(&g.assertion_text, 80),
            frontier_text: truncate(&f.assertion.text, 80),
            similarity: round3(candidate.similarity),
            entity_overlap: round3(entity_overlap),
            assertion_type_match: candidate.assertion_type_match,
            confidence_in_range: in_range,
            exact_id_match: candidate.exact_id,
        });
    }

    let matched = gold_matched.iter().filter(|&&m| m).count();
    let frontier_matched_count = frontier_matched.iter().filter(|&&m| m).count();
    let exact_id_matches = match_details.iter().filter(|d| d.exact_id_match).count();

    let precision = if findings.is_empty() {
        0.0
    } else {
        frontier_matched_count as f64 / findings.len() as f64
    };
    let recall = if gold.is_empty() {
        0.0
    } else {
        matched as f64 / gold.len() as f64
    };
    let f1 = if precision + recall == 0.0 {
        0.0
    } else {
        2.0 * precision * recall / (precision + recall)
    };

    let entity_accuracy = if match_details.is_empty() {
        0.0
    } else {
        match_details.iter().map(|d| d.entity_overlap).sum::<f64>() / match_details.len() as f64
    };

    let confidence_calibration = if match_details.is_empty() {
        0.0
    } else {
        match_details
            .iter()
            .filter(|d| d.confidence_in_range)
            .count() as f64
            / match_details.len() as f64
    };
    let assertion_type_accuracy = if match_details.is_empty() {
        0.0
    } else {
        match_details
            .iter()
            .filter(|d| d.assertion_type_match)
            .count() as f64
            / match_details.len() as f64
    };

    BenchmarkReport {
        total_frontier_findings: findings.len(),
        total_gold_findings: gold.len(),
        matched,
        total_frontier_matched: frontier_matched_count,
        unmatched_gold: gold.len().saturating_sub(matched),
        unmatched_frontier: findings.len().saturating_sub(frontier_matched_count),
        exact_id_matches,
        precision: round3(precision),
        recall: round3(recall),
        f1: round3(f1),
        entity_accuracy: round3(entity_accuracy),
        assertion_type_accuracy: round3(assertion_type_accuracy),
        confidence_calibration: round3(confidence_calibration),
        match_details,
    }
}

struct FindingCandidate {
    gold_idx: usize,
    frontier_idx: usize,
    similarity: f64,
    exact_id: bool,
    assertion_type_match: bool,
}

fn round3(v: f64) -> f64 {
    (v * 1000.0).round() / 1000.0
}

fn normalize_token(value: &str) -> String {
    value
        .trim()
        .to_lowercase()
        .replace('β', "beta")
        .replace('α', "alpha")
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        let mut end = max;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}...", &s[..end])
    }
}

/// Jaccard similarity between two strings based on word overlap.
fn jaccard_similarity(a: &str, b: &str) -> f64 {
    let words_a: HashSet<&str> = a
        .split_whitespace()
        .map(|w| w.trim_matches(|c: char| !c.is_alphanumeric()))
        .filter(|w| !w.is_empty())
        .collect();
    let words_b: HashSet<&str> = b
        .split_whitespace()
        .map(|w| w.trim_matches(|c: char| !c.is_alphanumeric()))
        .filter(|w| !w.is_empty())
        .collect();

    if words_a.is_empty() && words_b.is_empty() {
        return 1.0;
    }

    let intersection = words_a.intersection(&words_b).count();
    let union = words_a.union(&words_b).count();

    if union == 0 {
        0.0
    } else {
        intersection as f64 / union as f64
    }
}

pub fn print_report(report: &BenchmarkReport) {
    println!();
    println!("  {}", "VELA · BENCHMARK REPORT".dimmed());
    println!("  {}", style::tick_row(60));
    println!("  project findings: {}", report.total_frontier_findings);
    println!("  gold findings:    {}", report.total_gold_findings);
    println!("  matched:          {}", report.matched);
    println!();
    println!("  precision:        {:.1}%", report.precision * 100.0);
    println!("  recall:           {:.1}%", report.recall * 100.0);
    println!("  f1:               {:.1}%", report.f1 * 100.0);
    println!();
    println!(
        "  entity accuracy:       {:.1}%",
        report.entity_accuracy * 100.0
    );
    println!(
        "  confidence calibration: {:.1}%",
        report.confidence_calibration * 100.0
    );

    if !report.match_details.is_empty() {
        println!();
        println!("  {}", "MATCH DETAILS".dimmed());
        println!("  {}", style::tick_row(110));
        for d in &report.match_details {
            let cal = if d.confidence_in_range {
                style::ok("ok")
            } else {
                style::lost("miss")
            };
            println!(
                "  sim:{:.2} ent:{:.2} conf:{} · {} · {}",
                d.similarity, d.entity_overlap, cal, d.gold_text, d.frontier_text
            );
        }
    }

    println!();
    println!("  {}", style::tick_row(60));
    println!();
}

// ---------------------------------------------------------------------------
// Entity resolution benchmark
// ---------------------------------------------------------------------------

/// A single gold-standard entity for resolution benchmarking.
#[derive(Debug, Clone, Deserialize)]
pub struct GoldEntity {
    /// Entity name as it appears in findings.
    pub name: String,
    /// Entity type (gene, protein, compound, disease, pathway, other).
    #[serde(rename = "type")]
    pub entity_type: String,
    /// Expected database source (uniprot, mesh, pubchem, chebi, etc.).
    pub expected_source: String,
    /// Expected canonical ID in that database.
    pub expected_id: String,
    /// Minimum acceptable resolution confidence.
    pub expected_confidence: f64,
    /// Alternative acceptable IDs.
    #[serde(default)]
    pub alternatives: Vec<AlternativeId>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AlternativeId {
    pub source: String,
    pub id: String,
}

/// Per-entity match result.
#[derive(Debug, Serialize)]
pub struct EntityMatchDetail {
    pub name: String,
    pub entity_type: String,
    pub expected_source: String,
    pub expected_id: String,
    pub found_type: Option<String>,
    pub resolved_source: Option<String>,
    pub resolved_id: Option<String>,
    pub resolved_confidence: f64,
    pub type_match: bool,
    pub id_match: bool,
    pub confidence_ok: bool,
}

/// Per-type breakdown.
#[derive(Debug, Serialize)]
pub struct TypeBreakdown {
    pub entity_type: String,
    pub total: usize,
    pub found: usize,
    pub id_correct: usize,
    pub confidence_ok: usize,
    pub precision: f64,
    pub recall: f64,
    pub f1: f64,
}

/// Full entity resolution benchmark report.
#[derive(Debug, Serialize)]
pub struct EntityBenchmarkReport {
    pub total_gold_entities: usize,
    pub found_in_frontier: usize,
    pub type_correct: usize,
    pub id_correct: usize,
    pub confidence_ok: usize,
    pub precision: f64,
    pub recall: f64,
    pub f1: f64,
    pub type_accuracy: f64,
    pub by_type: Vec<TypeBreakdown>,
    pub details: Vec<EntityMatchDetail>,
}

pub fn run_entity_benchmark(frontier_path: &Path, gold_path: &Path, json_output: bool) {
    let frontier = repo::load_from_path(frontier_path).expect("Failed to load frontier");

    let gold_data =
        std::fs::read_to_string(gold_path).expect("Failed to read entity gold standard file");
    let gold: Vec<GoldEntity> =
        serde_json::from_str(&gold_data).expect("Failed to parse entity gold standard JSON");

    let report = entity_benchmark(&frontier.findings, &gold);

    if json_output {
        let json = serde_json::to_string_pretty(&report).unwrap();
        println!("{json}");
    } else {
        print_entity_report(&report);
    }
}

/// Collect all entities from findings into a lookup keyed by lowercase name.
fn collect_entities(findings: &[FindingBundle]) -> HashMap<String, Vec<&Entity>> {
    let mut map: HashMap<String, Vec<&Entity>> = HashMap::new();
    for f in findings {
        for ent in &f.assertion.entities {
            map.entry(ent.name.to_lowercase()).or_default().push(ent);
        }
    }
    map
}

/// Check whether a resolved entity matches the gold entry (ID match).
fn id_matches(entity: &Entity, gold: &GoldEntity) -> bool {
    if gold.expected_source.is_empty() && gold.expected_id.is_empty() {
        return entity.entity_type == gold.entity_type;
    }
    if let Some(ref cid) = entity.canonical_id {
        // Primary match.
        if cid.source == gold.expected_source && cid.id == gold.expected_id {
            return true;
        }
        // Check alternatives.
        for alt in &gold.alternatives {
            if cid.source == alt.source && cid.id == alt.id {
                return true;
            }
        }
    }
    false
}

/// Check whether confidence meets the minimum threshold.
fn confidence_ok(entity: &Entity, gold: &GoldEntity) -> bool {
    if let Some(ref cid) = entity.canonical_id {
        cid.confidence >= gold.expected_confidence
    } else {
        entity.resolution_confidence >= gold.expected_confidence
    }
}

pub fn entity_benchmark(findings: &[FindingBundle], gold: &[GoldEntity]) -> EntityBenchmarkReport {
    let entity_map = collect_entities(findings);
    let mut details = Vec::new();

    for g in gold {
        let key = g.name.to_lowercase();
        let entities = entity_map.get(&key);

        let (found_type, resolved_source, resolved_id, resolved_conf, type_match, matched, conf_ok) =
            if let Some(ents) = entities {
                let best = ents.iter().max_by(|a, b| {
                    entity_rank(a, g)
                        .cmp(&entity_rank(b, g))
                        .then_with(|| a.name.cmp(&b.name))
                });

                if let Some(ent) = best {
                    (
                        Some(ent.entity_type.clone()),
                        ent.canonical_id.as_ref().map(|cid| cid.source.clone()),
                        ent.canonical_id.as_ref().map(|cid| cid.id.clone()),
                        entity_resolution_confidence(ent),
                        ent.entity_type == g.entity_type,
                        id_matches(ent, g),
                        confidence_ok(ent, g),
                    )
                } else {
                    (None, None, None, 0.0, false, false, false)
                }
            } else {
                (None, None, None, 0.0, false, false, false)
            };

        details.push(EntityMatchDetail {
            name: g.name.clone(),
            entity_type: g.entity_type.clone(),
            expected_source: g.expected_source.clone(),
            expected_id: g.expected_id.clone(),
            found_type,
            resolved_source,
            resolved_id,
            resolved_confidence: round3(resolved_conf),
            type_match,
            id_match: matched,
            confidence_ok: conf_ok,
        });
    }

    let total = gold.len();
    let found = details.iter().filter(|d| d.found_type.is_some()).count();
    let type_correct = details.iter().filter(|d| d.type_match).count();
    let id_correct = details.iter().filter(|d| d.id_match).count();
    let conf_ok_count = details.iter().filter(|d| d.confidence_ok).count();

    // Precision = correct / found, Recall = correct / total.
    let precision = if found == 0 {
        0.0
    } else {
        id_correct as f64 / found as f64
    };
    let recall = if total == 0 {
        0.0
    } else {
        id_correct as f64 / total as f64
    };
    let f1 = if precision + recall == 0.0 {
        0.0
    } else {
        2.0 * precision * recall / (precision + recall)
    };
    let type_accuracy = if total == 0 {
        0.0
    } else {
        type_correct as f64 / total as f64
    };

    // Per-type breakdown.
    let mut type_groups: HashMap<String, Vec<&EntityMatchDetail>> = HashMap::new();
    for d in &details {
        type_groups
            .entry(d.entity_type.clone())
            .or_default()
            .push(d);
    }

    let mut by_type: Vec<TypeBreakdown> = type_groups
        .into_iter()
        .map(|(etype, ds)| {
            let t = ds.len();
            let f = ds.iter().filter(|d| d.found_type.is_some()).count();
            let c = ds.iter().filter(|d| d.id_match).count();
            let co = ds.iter().filter(|d| d.confidence_ok).count();
            let p = if f == 0 { 0.0 } else { c as f64 / f as f64 };
            let r = if t == 0 { 0.0 } else { c as f64 / t as f64 };
            let f1t = if p + r == 0.0 {
                0.0
            } else {
                2.0 * p * r / (p + r)
            };
            TypeBreakdown {
                entity_type: etype,
                total: t,
                found: f,
                id_correct: c,
                confidence_ok: co,
                precision: round3(p),
                recall: round3(r),
                f1: round3(f1t),
            }
        })
        .collect();
    by_type.sort_by(|a, b| a.entity_type.cmp(&b.entity_type));

    EntityBenchmarkReport {
        total_gold_entities: total,
        found_in_frontier: found,
        type_correct,
        id_correct,
        confidence_ok: conf_ok_count,
        precision: round3(precision),
        recall: round3(recall),
        f1: round3(f1),
        type_accuracy: round3(type_accuracy),
        by_type,
        details,
    }
}

fn entity_rank(entity: &Entity, gold: &GoldEntity) -> (u8, u8, u32) {
    (
        u8::from(entity.entity_type == gold.entity_type),
        u8::from(entity.canonical_id.is_some()),
        (entity_resolution_confidence(entity) * 1000.0).round() as u32,
    )
}

fn entity_resolution_confidence(entity: &Entity) -> f64 {
    entity
        .canonical_id
        .as_ref()
        .map(|cid| cid.confidence)
        .unwrap_or(entity.resolution_confidence)
}

fn print_entity_report(report: &EntityBenchmarkReport) {
    println!();
    println!("  {}", "VELA · ENTITY RESOLUTION BENCHMARK".dimmed());
    println!("  {}", style::tick_row(60));
    println!("  gold entities:      {}", report.total_gold_entities);
    println!("  found in frontier:  {}", report.found_in_frontier);
    println!("  type correct:       {}", report.type_correct);
    println!("  id correct:         {}", report.id_correct);
    println!("  confidence ok:      {}", report.confidence_ok);
    println!();
    println!("  precision:  {:.1}%", report.precision * 100.0);
    println!("  recall:     {:.1}%", report.recall * 100.0);
    println!("  f1:         {:.1}%", report.f1 * 100.0);
    println!("  type accuracy: {:.1}%", report.type_accuracy * 100.0);
    println!();
    println!("  {}", "BY TYPE".dimmed());
    println!(
        "  {}",
        format!(
            "{:<12} {:>5} {:>5} {:>7} {:>8} {:>6} {:>6}",
            "type", "total", "found", "correct", "conf_ok", "prec", "f1"
        )
        .dimmed()
    );
    for t in &report.by_type {
        println!(
            "  {:<12} {:>5} {:>5} {:>7} {:>8} {:>5.1}% {:>5.1}%",
            t.entity_type,
            t.total,
            t.found,
            t.id_correct,
            t.confidence_ok,
            t.precision * 100.0,
            t.f1 * 100.0,
        );
    }

    // Show mismatches.
    let mismatches: Vec<_> = report.details.iter().filter(|d| !d.id_match).collect();
    if !mismatches.is_empty() {
        println!();
        println!(
            "  {}",
            format!("MISMATCHES ({})", mismatches.len()).dimmed()
        );
        println!("  {}", style::tick_row(60));
        for d in &mismatches {
            let resolved = match (&d.resolved_source, &d.resolved_id) {
                (Some(s), Some(id)) => format!("{s}:{id}"),
                _ => d
                    .found_type
                    .clone()
                    .unwrap_or_else(|| "missing".to_string()),
            };
            println!(
                "  {} ({}) expected {}:{} got {}",
                d.name, d.entity_type, d.expected_source, d.expected_id, resolved
            );
        }
    }

    println!();
    println!("  {}", style::tick_row(60));
    println!();
}

// ---------------------------------------------------------------------------
// Link benchmark
// ---------------------------------------------------------------------------

/// A single gold-standard link for link benchmarking.
#[derive(Debug, Clone, Deserialize)]
pub struct GoldLink {
    pub source_id: String,
    pub target_id: String,
    pub link_type: String,
    #[serde(default)]
    pub note: String,
}

/// Per-link match result.
#[derive(Debug, Serialize)]
pub struct LinkMatchDetail {
    pub source_id: String,
    pub target_id: String,
    pub expected_type: String,
    pub found: bool,
    pub found_type: Option<String>,
    pub type_correct: bool,
}

/// Per-type breakdown for links.
#[derive(Debug, Serialize)]
pub struct LinkTypeBreakdown {
    pub link_type: String,
    pub total: usize,
    pub found: usize,
    pub type_correct: usize,
    pub precision: f64,
    pub recall: f64,
    pub f1: f64,
}

/// Full link benchmark report.
#[derive(Debug, Serialize)]
pub struct LinkBenchmarkReport {
    pub total_gold_links: usize,
    pub total_frontier_links: usize,
    pub found: usize,
    pub type_correct: usize,
    pub precision: f64,
    pub recall: f64,
    pub f1: f64,
    pub by_type: Vec<LinkTypeBreakdown>,
    pub details: Vec<LinkMatchDetail>,
}

pub fn run_link_benchmark(frontier_path: &Path, gold_path: &Path, json_output: bool) {
    let frontier = repo::load_from_path(frontier_path).expect("Failed to load frontier");

    let gold_data =
        std::fs::read_to_string(gold_path).expect("Failed to read link gold standard file");
    let gold: Vec<GoldLink> =
        serde_json::from_str(&gold_data).expect("Failed to parse link gold standard JSON");

    let report = link_benchmark(&frontier.findings, &gold);

    if json_output {
        let json = serde_json::to_string_pretty(&report).unwrap();
        println!("{json}");
    } else {
        print_link_report(&report);
    }
}

/// Build a lookup: (source_id, target_id) -> list of link types.
fn collect_links(findings: &[FindingBundle]) -> HashMap<(String, String), Vec<String>> {
    let mut map: HashMap<(String, String), Vec<String>> = HashMap::new();
    for f in findings {
        for link in &f.links {
            map.entry((f.id.clone(), link.target.clone()))
                .or_default()
                .push(link.link_type.clone());
        }
    }
    map
}

pub fn link_benchmark(findings: &[FindingBundle], gold: &[GoldLink]) -> LinkBenchmarkReport {
    let link_map = collect_links(findings);
    let total_frontier_links: usize = findings.iter().map(|f| f.links.len()).sum();
    let mut details = Vec::new();

    for g in gold {
        let key = (g.source_id.clone(), g.target_id.clone());
        let types = link_map.get(&key);

        let (found, found_type, type_correct) = if let Some(ts) = types {
            let correct = ts.contains(&g.link_type);
            (true, Some(ts[0].clone()), correct)
        } else {
            (false, None, false)
        };

        details.push(LinkMatchDetail {
            source_id: g.source_id.clone(),
            target_id: g.target_id.clone(),
            expected_type: g.link_type.clone(),
            found,
            found_type,
            type_correct,
        });
    }

    let total = gold.len();
    let found_count = details.iter().filter(|d| d.found).count();
    let type_correct_count = details.iter().filter(|d| d.type_correct).count();

    // Precision = type_correct / found, Recall = type_correct / total gold.
    let precision = if found_count == 0 {
        0.0
    } else {
        type_correct_count as f64 / found_count as f64
    };
    let recall = if total == 0 {
        0.0
    } else {
        type_correct_count as f64 / total as f64
    };
    let f1 = if precision + recall == 0.0 {
        0.0
    } else {
        2.0 * precision * recall / (precision + recall)
    };

    // Per-type breakdown.
    let mut type_groups: HashMap<String, Vec<&LinkMatchDetail>> = HashMap::new();
    for d in &details {
        type_groups
            .entry(d.expected_type.clone())
            .or_default()
            .push(d);
    }

    let mut by_type: Vec<LinkTypeBreakdown> = type_groups
        .into_iter()
        .map(|(lt, ds)| {
            let t = ds.len();
            let f = ds.iter().filter(|d| d.found).count();
            let c = ds.iter().filter(|d| d.type_correct).count();
            let p = if f == 0 { 0.0 } else { c as f64 / f as f64 };
            let r = if t == 0 { 0.0 } else { c as f64 / t as f64 };
            let f1t = if p + r == 0.0 {
                0.0
            } else {
                2.0 * p * r / (p + r)
            };
            LinkTypeBreakdown {
                link_type: lt,
                total: t,
                found: f,
                type_correct: c,
                precision: round3(p),
                recall: round3(r),
                f1: round3(f1t),
            }
        })
        .collect();
    by_type.sort_by(|a, b| a.link_type.cmp(&b.link_type));

    LinkBenchmarkReport {
        total_gold_links: total,
        total_frontier_links,
        found: found_count,
        type_correct: type_correct_count,
        precision: round3(precision),
        recall: round3(recall),
        f1: round3(f1),
        by_type,
        details,
    }
}

fn print_link_report(report: &LinkBenchmarkReport) {
    println!();
    println!("  {}", "VELA · LINK BENCHMARK".dimmed());
    println!("  {}", style::tick_row(60));
    println!("  gold links:        {}", report.total_gold_links);
    println!("  project links:     {}", report.total_frontier_links);
    println!("  found:             {}", report.found);
    println!("  type correct:      {}", report.type_correct);
    println!();
    println!("  precision:  {:.1}%", report.precision * 100.0);
    println!("  recall:     {:.1}%", report.recall * 100.0);
    println!("  f1:         {:.1}%", report.f1 * 100.0);
    println!();
    println!("  {}", "BY TYPE".dimmed());
    println!(
        "  {}",
        format!(
            "{:<12} {:>5} {:>5} {:>7} {:>6} {:>6}",
            "type", "total", "found", "correct", "prec", "f1"
        )
        .dimmed()
    );
    for t in &report.by_type {
        println!(
            "  {:<12} {:>5} {:>5} {:>7} {:>5.1}% {:>5.1}%",
            t.link_type,
            t.total,
            t.found,
            t.type_correct,
            t.precision * 100.0,
            t.f1 * 100.0,
        );
    }

    // Show mismatches.
    let mismatches: Vec<_> = report.details.iter().filter(|d| !d.type_correct).collect();
    if !mismatches.is_empty() {
        println!();
        println!(
            "  {}",
            format!("MISMATCHES ({})", mismatches.len()).dimmed()
        );
        println!("  {}", style::tick_row(60));
        for d in &mismatches {
            let found_str = match &d.found_type {
                Some(t) => t.as_str(),
                None => "missing",
            };
            println!(
                "  {} · {} expected:{} got:{}",
                d.source_id, d.target_id, d.expected_type, found_str
            );
        }
    }

    println!();
    println!("  {}", style::tick_row(60));
    println!();
}

// ---------------------------------------------------------------------------
// Suite-based benchmark gate
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BenchmarkMode {
    Finding,
    Entity,
    Link,
    Workflow,
}

impl BenchmarkMode {
    fn as_str(&self) -> &'static str {
        match self {
            BenchmarkMode::Finding => "finding",
            BenchmarkMode::Entity => "entity",
            BenchmarkMode::Link => "link",
            BenchmarkMode::Workflow => "workflow",
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct BenchmarkThresholds {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_f1: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_precision: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_recall: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_entity_accuracy: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_confidence_calibration: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_type_accuracy: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_workflow_score: Option<f64>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct WorkflowExpectations {
    #[serde(default)]
    pub min_findings: usize,
    #[serde(default)]
    pub min_links: usize,
    #[serde(default)]
    pub min_entity_mentions: usize,
    #[serde(default)]
    pub min_evidence_spans: usize,
    #[serde(default)]
    pub min_provenance_complete: usize,
    #[serde(default)]
    pub min_assertion_types: usize,
    #[serde(default)]
    pub min_gap_flags: usize,
    #[serde(default)]
    pub min_contested_flags: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BenchmarkTask {
    pub id: String,
    pub mode: BenchmarkMode,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub frontier: Option<String>,
    #[serde(default)]
    pub gold: Option<String>,
    #[serde(default)]
    pub thresholds: BenchmarkThresholds,
    #[serde(default)]
    pub workflow: Option<WorkflowExpectations>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BenchmarkSuite {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub frontier: String,
    pub tasks: Vec<BenchmarkTask>,
}

#[derive(Debug, Serialize)]
pub struct WorkflowBenchmarkReport {
    pub total_findings: usize,
    pub total_links: usize,
    pub total_entity_mentions: usize,
    pub total_evidence_spans: usize,
    pub total_provenance_complete: usize,
    pub evidence_span_coverage: f64,
    pub provenance_coverage: f64,
    pub assertion_types: usize,
    pub gap_flags: usize,
    pub contested_flags: usize,
    pub checks_total: usize,
    pub checks_passed: usize,
    pub workflow_score: f64,
    pub details: Vec<WorkflowCheckDetail>,
}

#[derive(Debug, Serialize)]
pub struct WorkflowCheckDetail {
    pub metric: String,
    pub actual: usize,
    pub expected_min: usize,
    pub passed: bool,
}

pub fn load_suite(path: &Path) -> Result<BenchmarkSuite, String> {
    let data = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read benchmark suite '{}': {e}", path.display()))?;
    serde_json::from_str(&data)
        .map_err(|e| format!("Failed to parse benchmark suite '{}': {e}", path.display()))
}

pub fn suite_ready_report(suite_path: &Path) -> Result<serde_json::Value, String> {
    let envelope = run_suite(suite_path)?;
    let suite_ready = envelope
        .get("ok")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    Ok(json!({
        "ok": suite_ready,
        "command": "bench",
        "suite_ready": suite_ready,
        "suite": envelope.get("suite").cloned().unwrap_or(serde_json::Value::Null),
        "tasks": envelope.get("tasks").cloned().unwrap_or_else(|| json!([])),
        "failures": envelope.get("failures").cloned().unwrap_or_else(|| json!([])),
    }))
}

pub fn run_suite(suite_path: &Path) -> Result<serde_json::Value, String> {
    let suite = load_suite(suite_path)?;
    let base_dir = suite_path.parent().unwrap_or_else(|| Path::new("."));
    let frontier_path = resolve_suite_path(base_dir, &suite.frontier);
    let loaded = repo::load_from_path(&frontier_path)?;
    let frontier_hash = hash_path(&frontier_path)?;

    let mut task_outputs = Vec::new();
    let mut failures = Vec::new();
    let mut standard_candles = Vec::new();

    for task in &suite.tasks {
        if let Some(gold) = &task.gold {
            let gold_path = resolve_suite_path(base_dir, gold);
            standard_candles.push(json!({
                "task_id": task.id,
                "mode": task.mode.as_str(),
                "path": gold_path.display().to_string(),
                "items": count_json_array_items(&gold_path)?,
                "role": "reviewed calibration anchor"
            }));
        }
        let task_frontier = task
            .frontier
            .as_deref()
            .map(|p| resolve_suite_path(base_dir, p))
            .unwrap_or_else(|| frontier_path.clone());
        let output = task_envelope(
            &task_frontier,
            Some((&suite.id, &task.id)),
            task.mode.clone(),
            task.gold
                .as_deref()
                .map(|p| resolve_suite_path(base_dir, p))
                .as_deref(),
            &task.thresholds,
            task.workflow.as_ref(),
        )?;
        if !output
            .get("ok")
            .and_then(|value| value.as_bool())
            .unwrap_or(false)
        {
            failures.push(format!("task {} failed", task.id));
        }
        task_outputs.push(output);
    }

    let passed = task_outputs
        .iter()
        .filter(|task| task.get("ok").and_then(|value| value.as_bool()) == Some(true))
        .count();
    let ok = failures.is_empty();

    Ok(json!({
        "ok": ok,
        "command": "bench",
        "benchmark_type": "suite",
        "schema_version": project::VELA_SCHEMA_VERSION,
        "suite": {
            "id": suite.id,
            "name": suite.name,
            "path": suite_path.display().to_string(),
            "tasks": suite.tasks.len(),
        },
        "frontier": {
            "name": loaded.project.name,
            "source": frontier_path.display().to_string(),
            "hash": format!("sha256:{frontier_hash}"),
        },
        "metrics": {
            "tasks_total": task_outputs.len(),
            "tasks_passed": passed,
            "tasks_failed": task_outputs.len().saturating_sub(passed),
            "standard_candles": standard_candles
                .iter()
                .filter_map(|item| item.get("items").and_then(|value| value.as_u64()))
                .sum::<u64>(),
        },
        "standard_candles": {
            "definition": "Reviewed gold fixtures used as calibration anchors for release drift, not proof of scientific superiority.",
            "items": standard_candles,
        },
        "failures": failures,
        "tasks": task_outputs,
    }))
}

fn count_json_array_items(path: &Path) -> Result<usize, String> {
    let data = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read gold fixture '{}': {e}", path.display()))?;
    let value: serde_json::Value = serde_json::from_str(&data)
        .map_err(|e| format!("Failed to parse gold fixture '{}': {e}", path.display()))?;
    value
        .as_array()
        .map(Vec::len)
        .ok_or_else(|| format!("Gold fixture '{}' must be a JSON array", path.display()))
}

pub fn task_envelope(
    frontier_path: &Path,
    suite_task: Option<(&str, &str)>,
    mode: BenchmarkMode,
    gold_path: Option<&Path>,
    thresholds: &BenchmarkThresholds,
    workflow: Option<&WorkflowExpectations>,
) -> Result<serde_json::Value, String> {
    let loaded = repo::load_from_path(frontier_path)?;
    let frontier_hash = hash_path(frontier_path)?;
    let (suite_id, task_id) = suite_task
        .map(|(suite, task)| (Some(suite.to_string()), Some(task.to_string())))
        .unwrap_or((None, None));

    match mode {
        BenchmarkMode::Finding => {
            let gold_path =
                gold_path.ok_or_else(|| "finding benchmark requires gold".to_string())?;
            let gold_data = std::fs::read_to_string(gold_path).map_err(|e| {
                format!("Failed to read finding gold '{}': {e}", gold_path.display())
            })?;
            let gold: Vec<GoldFinding> = serde_json::from_str(&gold_data).map_err(|e| {
                format!(
                    "Failed to parse finding gold '{}': {e}",
                    gold_path.display()
                )
            })?;
            let report = benchmark(&loaded.findings, &gold);
            let failures = finding_threshold_failures(&report, thresholds);
            let gold_hash = hash_path(gold_path)?;
            Ok(json!({
                "ok": failures.is_empty(),
                "command": "bench",
                "benchmark_type": BenchmarkMode::Finding.as_str(),
                "mode": BenchmarkMode::Finding.as_str(),
                "suite_id": suite_id,
                "task_id": task_id,
                "schema_version": project::VELA_SCHEMA_VERSION,
                "frontier": frontier_metadata(&loaded, frontier_path, &frontier_hash),
                "gold": gold_metadata(gold_path, &gold_hash, gold.len()),
                "metrics": {
                    "total_frontier_findings": report.total_frontier_findings,
                    "total_gold_findings": report.total_gold_findings,
                    "matched": report.matched,
                    "total_frontier_matched": report.total_frontier_matched,
                    "unmatched_gold": report.unmatched_gold,
                    "unmatched_frontier": report.unmatched_frontier,
                    "exact_id_matches": report.exact_id_matches,
                    "precision": report.precision,
                    "recall": report.recall,
                    "f1": report.f1,
                    "entity_accuracy": report.entity_accuracy,
                    "assertion_type_accuracy": report.assertion_type_accuracy,
                    "confidence_calibration": report.confidence_calibration,
                },
                "thresholds": thresholds,
                "failures": failures,
                "match_details": report.match_details,
            }))
        }
        BenchmarkMode::Entity => {
            let gold_path =
                gold_path.ok_or_else(|| "entity benchmark requires gold".to_string())?;
            let gold_data = std::fs::read_to_string(gold_path).map_err(|e| {
                format!("Failed to read entity gold '{}': {e}", gold_path.display())
            })?;
            let gold: Vec<GoldEntity> = serde_json::from_str(&gold_data).map_err(|e| {
                format!("Failed to parse entity gold '{}': {e}", gold_path.display())
            })?;
            let report = entity_benchmark(&loaded.findings, &gold);
            let failures = entity_threshold_failures(&report, thresholds);
            let gold_hash = hash_path(gold_path)?;
            Ok(json!({
                "ok": failures.is_empty(),
                "command": "bench",
                "benchmark_type": BenchmarkMode::Entity.as_str(),
                "mode": BenchmarkMode::Entity.as_str(),
                "suite_id": suite_id,
                "task_id": task_id,
                "schema_version": project::VELA_SCHEMA_VERSION,
                "frontier": frontier_metadata(&loaded, frontier_path, &frontier_hash),
                "gold": gold_metadata(gold_path, &gold_hash, gold.len()),
                "metrics": {
                    "total_gold_entities": report.total_gold_entities,
                    "found_in_frontier": report.found_in_frontier,
                    "type_correct": report.type_correct,
                    "id_correct": report.id_correct,
                    "confidence_ok": report.confidence_ok,
                    "precision": report.precision,
                    "recall": report.recall,
                    "f1": report.f1,
                    "type_accuracy": report.type_accuracy,
                },
                "thresholds": thresholds,
                "failures": failures,
                "by_type": report.by_type,
                "details": report.details,
            }))
        }
        BenchmarkMode::Link => {
            let gold_path = gold_path.ok_or_else(|| "link benchmark requires gold".to_string())?;
            let gold_data = std::fs::read_to_string(gold_path)
                .map_err(|e| format!("Failed to read link gold '{}': {e}", gold_path.display()))?;
            let gold: Vec<GoldLink> = serde_json::from_str(&gold_data)
                .map_err(|e| format!("Failed to parse link gold '{}': {e}", gold_path.display()))?;
            let report = link_benchmark(&loaded.findings, &gold);
            let failures = link_threshold_failures(&report, thresholds);
            let gold_hash = hash_path(gold_path)?;
            Ok(json!({
                "ok": failures.is_empty(),
                "command": "bench",
                "benchmark_type": BenchmarkMode::Link.as_str(),
                "mode": BenchmarkMode::Link.as_str(),
                "suite_id": suite_id,
                "task_id": task_id,
                "schema_version": project::VELA_SCHEMA_VERSION,
                "frontier": frontier_metadata(&loaded, frontier_path, &frontier_hash),
                "gold": gold_metadata(gold_path, &gold_hash, gold.len()),
                "metrics": {
                    "total_gold_links": report.total_gold_links,
                    "total_frontier_links": report.total_frontier_links,
                    "found": report.found,
                    "type_correct": report.type_correct,
                    "precision": report.precision,
                    "recall": report.recall,
                    "f1": report.f1,
                },
                "thresholds": thresholds,
                "failures": failures,
                "by_type": report.by_type,
                "details": report.details,
            }))
        }
        BenchmarkMode::Workflow => {
            let expectations = workflow.cloned().unwrap_or_default();
            let report = workflow_benchmark(&loaded.findings, &expectations);
            let failures = workflow_threshold_failures(&report, thresholds);
            Ok(json!({
                "ok": failures.is_empty(),
                "command": "bench",
                "benchmark_type": BenchmarkMode::Workflow.as_str(),
                "mode": BenchmarkMode::Workflow.as_str(),
                "suite_id": suite_id,
                "task_id": task_id,
                "schema_version": project::VELA_SCHEMA_VERSION,
                "frontier": frontier_metadata(&loaded, frontier_path, &frontier_hash),
                "gold": null,
                "metrics": {
                    "total_findings": report.total_findings,
                    "total_links": report.total_links,
                    "total_entity_mentions": report.total_entity_mentions,
                    "total_evidence_spans": report.total_evidence_spans,
                    "total_provenance_complete": report.total_provenance_complete,
                    "evidence_span_coverage": report.evidence_span_coverage,
                    "provenance_coverage": report.provenance_coverage,
                    "assertion_types": report.assertion_types,
                    "gap_flags": report.gap_flags,
                    "contested_flags": report.contested_flags,
                    "checks_total": report.checks_total,
                    "checks_passed": report.checks_passed,
                    "workflow_score": report.workflow_score,
                },
                "thresholds": thresholds,
                "failures": failures,
                "details": report.details,
            }))
        }
    }
}

pub fn workflow_benchmark(
    findings: &[FindingBundle],
    expectations: &WorkflowExpectations,
) -> WorkflowBenchmarkReport {
    let total_links = findings.iter().map(|f| f.links.len()).sum();
    let total_entity_mentions = findings.iter().map(|f| f.assertion.entities.len()).sum();
    let total_evidence_spans = findings
        .iter()
        .map(|f| f.evidence.evidence_spans.len())
        .sum();
    let findings_with_spans = findings
        .iter()
        .filter(|f| !f.evidence.evidence_spans.is_empty())
        .count();
    let total_provenance_complete = findings
        .iter()
        .filter(|f| {
            f.provenance.doi.is_some()
                || f.provenance.pmid.is_some()
                || !f.provenance.title.trim().is_empty()
        })
        .count();
    let evidence_span_coverage = if findings.is_empty() {
        1.0
    } else {
        findings_with_spans as f64 / findings.len() as f64
    };
    let provenance_coverage = if findings.is_empty() {
        1.0
    } else {
        total_provenance_complete as f64 / findings.len() as f64
    };
    let assertion_types = findings
        .iter()
        .map(|f| f.assertion.assertion_type.as_str())
        .collect::<HashSet<_>>()
        .len();
    let gap_flags = findings.iter().filter(|f| f.flags.gap).count();
    let contested_flags = findings.iter().filter(|f| f.flags.contested).count();

    let checks = vec![
        ("findings", findings.len(), expectations.min_findings),
        ("links", total_links, expectations.min_links),
        (
            "entity_mentions",
            total_entity_mentions,
            expectations.min_entity_mentions,
        ),
        (
            "evidence_spans",
            total_evidence_spans,
            expectations.min_evidence_spans,
        ),
        (
            "provenance_complete",
            total_provenance_complete,
            expectations.min_provenance_complete,
        ),
        (
            "assertion_types",
            assertion_types,
            expectations.min_assertion_types,
        ),
        ("gap_flags", gap_flags, expectations.min_gap_flags),
        (
            "contested_flags",
            contested_flags,
            expectations.min_contested_flags,
        ),
    ];
    let details: Vec<WorkflowCheckDetail> = checks
        .into_iter()
        .filter(|(_, _, expected)| *expected > 0)
        .map(|(metric, actual, expected_min)| WorkflowCheckDetail {
            metric: metric.to_string(),
            actual,
            expected_min,
            passed: actual >= expected_min,
        })
        .collect();
    let checks_total = details.len();
    let checks_passed = details.iter().filter(|detail| detail.passed).count();
    let workflow_score = if checks_total == 0 {
        1.0
    } else {
        checks_passed as f64 / checks_total as f64
    };

    WorkflowBenchmarkReport {
        total_findings: findings.len(),
        total_links,
        total_entity_mentions,
        total_evidence_spans,
        total_provenance_complete,
        evidence_span_coverage: round3(evidence_span_coverage),
        provenance_coverage: round3(provenance_coverage),
        assertion_types,
        gap_flags,
        contested_flags,
        checks_total,
        checks_passed,
        workflow_score: round3(workflow_score),
        details,
    }
}

fn resolve_suite_path(base_dir: &Path, value: &str) -> PathBuf {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        path
    } else {
        let from_suite = base_dir.join(&path);
        if from_suite.exists() {
            from_suite
        } else {
            PathBuf::from(value)
        }
    }
}

fn frontier_metadata(
    loaded: &project::Project,
    frontier_path: &Path,
    frontier_hash: &str,
) -> serde_json::Value {
    json!({
        "name": loaded.project.name,
        "source": frontier_path.display().to_string(),
        "hash": format!("sha256:{frontier_hash}"),
    })
}

fn gold_metadata(gold_path: &Path, gold_hash: &str, items: usize) -> serde_json::Value {
    json!({
        "path": gold_path.display().to_string(),
        "hash": format!("sha256:{gold_hash}"),
        "items": items,
    })
}

fn finding_threshold_failures(
    report: &BenchmarkReport,
    thresholds: &BenchmarkThresholds,
) -> Vec<String> {
    let mut failures =
        generic_threshold_failures(report.precision, report.recall, report.f1, thresholds);
    if let Some(threshold) = thresholds.min_entity_accuracy
        && report.entity_accuracy < threshold
    {
        failures.push(format!(
            "entity_accuracy {} is below threshold {}",
            report.entity_accuracy, threshold
        ));
    }
    if let Some(threshold) = thresholds.min_confidence_calibration
        && report.confidence_calibration < threshold
    {
        failures.push(format!(
            "confidence_calibration {} is below threshold {}",
            report.confidence_calibration, threshold
        ));
    }
    if let Some(threshold) = thresholds.min_type_accuracy
        && report.assertion_type_accuracy < threshold
    {
        failures.push(format!(
            "assertion_type_accuracy {} is below threshold {}",
            report.assertion_type_accuracy, threshold
        ));
    }
    failures
}

fn entity_threshold_failures(
    report: &EntityBenchmarkReport,
    thresholds: &BenchmarkThresholds,
) -> Vec<String> {
    let mut failures =
        generic_threshold_failures(report.precision, report.recall, report.f1, thresholds);
    if let Some(threshold) = thresholds.min_type_accuracy
        && report.type_accuracy < threshold
    {
        failures.push(format!(
            "type_accuracy {} is below threshold {}",
            report.type_accuracy, threshold
        ));
    }
    failures
}

fn link_threshold_failures(
    report: &LinkBenchmarkReport,
    thresholds: &BenchmarkThresholds,
) -> Vec<String> {
    generic_threshold_failures(report.precision, report.recall, report.f1, thresholds)
}

fn workflow_threshold_failures(
    report: &WorkflowBenchmarkReport,
    thresholds: &BenchmarkThresholds,
) -> Vec<String> {
    let mut failures = Vec::new();
    for detail in &report.details {
        if !detail.passed {
            failures.push(format!(
                "{} {} is below minimum {}",
                detail.metric, detail.actual, detail.expected_min
            ));
        }
    }
    if let Some(threshold) = thresholds.min_workflow_score
        && report.workflow_score < threshold
    {
        failures.push(format!(
            "workflow_score {} is below threshold {}",
            report.workflow_score, threshold
        ));
    }
    failures
}

fn generic_threshold_failures(
    precision: f64,
    recall: f64,
    f1: f64,
    thresholds: &BenchmarkThresholds,
) -> Vec<String> {
    let mut failures = Vec::new();
    if let Some(threshold) = thresholds.min_f1
        && f1 < threshold
    {
        failures.push(format!("f1 {} is below threshold {}", f1, threshold));
    }
    if let Some(threshold) = thresholds.min_precision
        && precision < threshold
    {
        failures.push(format!(
            "precision {} is below threshold {}",
            precision, threshold
        ));
    }
    if let Some(threshold) = thresholds.min_recall
        && recall < threshold
    {
        failures.push(format!(
            "recall {} is below threshold {}",
            recall, threshold
        ));
    }
    failures
}

fn hash_path(path: &Path) -> Result<String, String> {
    let mut hasher = Sha256::new();
    if path.is_file() {
        let bytes = std::fs::read(path)
            .map_err(|e| format!("Failed to read {} for hashing: {e}", path.display()))?;
        hasher.update(&bytes);
    } else if path.is_dir() {
        let mut files = Vec::new();
        collect_hash_files(path, path, &mut files)?;
        files.sort();
        for rel in files {
            hasher.update(rel.to_string_lossy().as_bytes());
            let bytes = std::fs::read(path.join(&rel))
                .map_err(|e| format!("Failed to read {} for hashing: {e}", rel.display()))?;
            hasher.update(&bytes);
        }
    } else {
        return Err(format!("Cannot hash missing path {}", path.display()));
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn collect_hash_files(root: &Path, dir: &Path, files: &mut Vec<PathBuf>) -> Result<(), String> {
    for entry in
        std::fs::read_dir(dir).map_err(|e| format!("Failed to read {}: {e}", dir.display()))?
    {
        let entry = entry.map_err(|e| format!("Failed to read directory entry: {e}"))?;
        let path = entry.path();
        if path.is_dir() {
            collect_hash_files(root, &path, files)?;
        } else if path.is_file() {
            let rel = path.strip_prefix(root).map_err(|e| e.to_string())?;
            files.push(rel.to_path_buf());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jaccard_identical() {
        let sim = jaccard_similarity("NLRP3 activates caspase-1", "NLRP3 activates caspase-1");
        assert!((sim - 1.0).abs() < 0.001);
    }

    #[test]
    fn jaccard_disjoint() {
        let sim = jaccard_similarity("NLRP3 activates caspase-1", "tau propagation in cortex");
        assert!(sim < 0.1);
    }

    #[test]
    fn jaccard_partial() {
        let sim = jaccard_similarity(
            "NLRP3 inflammasome activates caspase-1 in microglia",
            "NLRP3 activates caspase-1",
        );
        assert!(sim > 0.3);
        assert!(sim < 1.0);
    }

    #[test]
    fn jaccard_empty() {
        assert!((jaccard_similarity("", "") - 1.0).abs() < 0.001);
        assert!((jaccard_similarity("word", "")).abs() < 0.001);
    }

    #[test]
    fn benchmark_empty() {
        let report = benchmark(&[], &[]);
        assert_eq!(report.matched, 0);
        assert_eq!(report.f1, 0.0);
    }

    #[test]
    fn benchmark_perfect_match() {
        use vela_protocol::bundle::*;

        let finding = FindingBundle {
            id: "vf_test".into(),
            version: 1,
            previous_version: None,
            assertion: Assertion {
                text: "NLRP3 activates caspase-1 in microglia".into(),
                assertion_type: "mechanism".into(),
                entities: vec![
                    Entity {
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
                    },
                    Entity {
                        name: "caspase-1".into(),
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
                relation: None,
                direction: None,
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
            confidence: Confidence::raw(0.85, "test", 0.9),
            provenance: Provenance {
                source_type: "published_paper".into(),
                doi: None,
                pmid: None,
                pmc: None,
                openalex_id: None,
                url: None,
                title: "Test".into(),
                authors: vec![],
                year: Some(2024),
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

            access_tier: vela_protocol::access_tier::AccessTier::Public,
        };

        let gold = vec![GoldFinding {
            id: None,
            assertion_text: "NLRP3 activates caspase-1 in microglia".into(),
            assertion_type: "mechanism".into(),
            entities: vec!["NLRP3".into(), "caspase-1".into()],
            confidence_range: ConfidenceRange {
                low: 0.7,
                high: 0.95,
            },
            notes: None,
        }];

        let report = benchmark(&[finding], &gold);
        assert_eq!(report.matched, 1);
        assert!((report.recall - 1.0).abs() < 0.001);
        assert!((report.precision - 1.0).abs() < 0.001);
        assert!((report.entity_accuracy - 1.0).abs() < 0.001);
        assert!((report.confidence_calibration - 1.0).abs() < 0.001);
    }

    // Helper to create a minimal FindingBundle with given entities.
    fn make_finding_with_entities(entities: Vec<Entity>) -> FindingBundle {
        use vela_protocol::bundle::*;
        FindingBundle {
            id: "vf_ent_test".into(),
            version: 1,
            previous_version: None,
            assertion: Assertion {
                text: "test assertion".into(),
                assertion_type: "mechanism".into(),
                entities,
                relation: None,
                direction: None,
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
            confidence: Confidence::raw(0.9, "test", 0.9),
            provenance: Provenance {
                source_type: "published_paper".into(),
                doi: None,
                pmid: None,
                pmc: None,
                openalex_id: None,
                url: None,
                title: "Test".into(),
                authors: vec![],
                year: Some(2024),
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

            access_tier: vela_protocol::access_tier::AccessTier::Public,
        }
    }

    #[test]
    fn entity_benchmark_empty() {
        let report = entity_benchmark(&[], &[]);
        assert_eq!(report.total_gold_entities, 0);
        assert_eq!(report.found_in_frontier, 0);
        assert_eq!(report.f1, 0.0);
    }

    #[test]
    fn entity_benchmark_perfect_match() {
        use vela_protocol::bundle::*;

        let entity = Entity {
            name: "NLRP3".into(),
            entity_type: "protein".into(),
            identifiers: serde_json::Map::new(),
            canonical_id: Some(ResolvedId {
                source: "uniprot".into(),
                id: "Q96P20".into(),
                confidence: 0.95,
                matched_name: Some("NLRP3".into()),
            }),
            candidates: vec![],
            aliases: vec![],
            resolution_provenance: Some("vela_resolve/uniprot".into()),
            resolution_confidence: 0.95,
            resolution_method: None,
            species_context: None,
            needs_review: false,
        };

        let finding = make_finding_with_entities(vec![entity]);

        let gold = vec![GoldEntity {
            name: "NLRP3".into(),
            entity_type: "protein".into(),
            expected_source: "uniprot".into(),
            expected_id: "Q96P20".into(),
            expected_confidence: 0.8,
            alternatives: vec![],
        }];

        let report = entity_benchmark(&[finding], &gold);
        assert_eq!(report.total_gold_entities, 1);
        assert_eq!(report.found_in_frontier, 1);
        assert_eq!(report.id_correct, 1);
        assert_eq!(report.confidence_ok, 1);
        assert!((report.precision - 1.0).abs() < 0.001);
        assert!((report.recall - 1.0).abs() < 0.001);
        assert!((report.f1 - 1.0).abs() < 0.001);
    }

    #[test]
    fn entity_benchmark_alternative_id() {
        use vela_protocol::bundle::*;

        let entity = Entity {
            name: "aspirin".into(),
            entity_type: "compound".into(),
            identifiers: serde_json::Map::new(),
            canonical_id: Some(ResolvedId {
                source: "pubchem".into(),
                id: "2244".into(),
                confidence: 0.9,
                matched_name: Some("Aspirin".into()),
            }),
            candidates: vec![],
            aliases: vec![],
            resolution_provenance: None,
            resolution_confidence: 0.9,
            resolution_method: None,
            species_context: None,
            needs_review: false,
        };

        let finding = make_finding_with_entities(vec![entity]);

        // Gold expects a different primary ID but lists 2244 as an alternative.
        let gold = vec![GoldEntity {
            name: "aspirin".into(),
            entity_type: "compound".into(),
            expected_source: "chebi".into(),
            expected_id: "CHEBI:15365".into(),
            expected_confidence: 0.7,
            alternatives: vec![AlternativeId {
                source: "pubchem".into(),
                id: "2244".into(),
            }],
        }];

        let report = entity_benchmark(&[finding], &gold);
        assert_eq!(
            report.id_correct, 1,
            "Alternative ID should count as correct"
        );
        assert!((report.precision - 1.0).abs() < 0.001);
    }

    #[test]
    fn entity_benchmark_mismatch_and_missing() {
        use vela_protocol::bundle::*;

        // Entity with wrong ID.
        let entity = Entity {
            name: "BRCA1".into(),
            entity_type: "gene".into(),
            identifiers: serde_json::Map::new(),
            canonical_id: Some(ResolvedId {
                source: "uniprot".into(),
                id: "WRONG_ID".into(),
                confidence: 0.8,
                matched_name: Some("BRCA1".into()),
            }),
            candidates: vec![],
            aliases: vec![],
            resolution_provenance: None,
            resolution_confidence: 0.8,
            resolution_method: None,
            species_context: None,
            needs_review: false,
        };

        let finding = make_finding_with_entities(vec![entity]);

        let gold = vec![
            GoldEntity {
                name: "BRCA1".into(),
                entity_type: "gene".into(),
                expected_source: "uniprot".into(),
                expected_id: "P38398".into(),
                expected_confidence: 0.7,
                alternatives: vec![],
            },
            // Entity not present in frontier at all.
            GoldEntity {
                name: "TP53".into(),
                entity_type: "gene".into(),
                expected_source: "uniprot".into(),
                expected_id: "P04637".into(),
                expected_confidence: 0.7,
                alternatives: vec![],
            },
        ];

        let report = entity_benchmark(&[finding], &gold);
        assert_eq!(report.total_gold_entities, 2);
        assert_eq!(report.found_in_frontier, 1); // BRCA1 found but wrong ID
        assert_eq!(report.id_correct, 0);
        assert!((report.precision).abs() < 0.001); // 0/1
        assert!((report.recall).abs() < 0.001); // 0/2
        assert_eq!(report.by_type.len(), 1);
        assert_eq!(report.by_type[0].entity_type, "gene");
        assert_eq!(report.by_type[0].total, 2);
    }
}
