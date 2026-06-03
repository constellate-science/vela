//! # VelaBench v0.26 — agent state-update scoring
//!
//! Compares a *candidate* frontier (typically agent-generated)
//! against a *gold* frontier (curator-validated) and produces a
//! reproducible score.
//!
//! Unlike the legacy `benchmark` module — which scores literature
//! extraction quality — this scorer reads two frontiers as data
//! artifacts and judges how well one approximates the other.
//! Determinism is the doctrine: sort by `vf_id`, no wall-clock,
//! no RNG. Same inputs → same numbers.
//!
//! Substrate stays dumb: this is pure data comparison. No LLM
//! call, no network, no agent invocation. The scorer never spawns
//! `claude` or anything else; it operates on already-emitted
//! `FindingBundle`s and `StateProposal`s.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::bundle::FindingBundle;
use crate::project::Project;
use crate::repo;

/// Composite score weights, summing to 1.0 — locked here so the
/// formula is auditable in one line. Adjust deliberately.
pub const W_CLAIM_MATCH: f64 = 0.25;
pub const W_SCOPE: f64 = 0.20;
pub const W_EVIDENCE_FIDELITY: f64 = 0.20;
pub const W_CONTRADICTION_RECALL: f64 = 0.15;
pub const W_DOWNSTREAM_LINK: f64 = 0.10;
pub const W_DUPLICATE_INV: f64 = 0.10;

/// Inputs to a single VelaBench run.
#[derive(Debug, Clone)]
pub struct BenchInput {
    pub gold_path: PathBuf,
    pub candidate_path: PathBuf,
    /// When provided, `evidence_fidelity` checks each candidate
    /// finding's evidence span against the actual file content.
    /// Without it, that metric is reported as `None` and dropped
    /// from the composite (weight rebalanced).
    pub sources: Option<PathBuf>,
    /// Threshold for the composite score; the binary exit code is
    /// non-zero if the score falls below.
    pub threshold: f64,
}

/// One metric's worth of result. `pass` is purely informational
/// (target met) — the binary's exit code is driven by the
/// composite, not by individual metrics.
///
/// `vacuous` (v0.29.2): true when the metric had no data to
/// measure (e.g. no gold contradictions to recall, no novel
/// candidate findings to ground). Such metrics still report a
/// formal score of 1.0 ("vacuously satisfied"), but they are
/// excluded from the composite weighting. Friction #13 from sim-
/// user pass #2: vacuous 1.0s were inflating the composite to
/// ~0.31 even when claim_match_rate was 0, which made the score
/// look like a passing grade when it really meant "no overlap
/// detected".
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MetricResult {
    pub score: f64,
    pub target: f64,
    pub pass: bool,
    pub note: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub vacuous: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// Full bench report. Serializable to JSON for `--json` mode and
/// for checking in as `expected.json` regression bands.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BenchReport {
    pub gold_path: String,
    pub candidate_path: String,
    pub gold_findings: usize,
    pub candidate_findings: usize,
    pub matched_pairs: usize,
    pub claim_match_rate: MetricResult,
    pub scope_accuracy: MetricResult,
    pub evidence_fidelity: Option<MetricResult>,
    pub duplicate_rate: f64,
    pub novelty_rate: f64,
    pub contradiction_recall: MetricResult,
    pub downstream_link_rate: MetricResult,
    pub composite: f64,
    pub threshold: f64,
    pub pass: bool,
}

/// Run a complete bench. Loads both frontiers, computes every
/// metric, and returns the report. Caller decides what to do with
/// the exit code.
pub fn run(input: BenchInput) -> Result<BenchReport, String> {
    let gold: Project = repo::load_from_path(&input.gold_path)
        .map_err(|e| format!("load gold {}: {e}", input.gold_path.display()))?;
    let candidate: Project = repo::load_from_path(&input.candidate_path)
        .map_err(|e| format!("load candidate {}: {e}", input.candidate_path.display()))?;

    let gold_findings = sorted_findings(&gold);
    // Candidates are most often unsigned: an agent's `vela scout`
    // run leaves its output as `finding.add` proposals, not as
    // committed findings. Pull both surfaces into the candidate
    // set so the bench can score pre-review agent quality (where
    // the dogfood lives) as well as post-review accepted state.
    let candidate_findings = sorted_findings_with_proposals(&candidate);

    let matches = match_findings(&gold_findings, &candidate_findings);

    let claim_match_rate = score_claim_match(&gold_findings, &candidate_findings, &matches);
    let scope_accuracy = score_scope(&gold_findings, &candidate_findings, &matches);
    let evidence_fidelity = input
        .sources
        .as_ref()
        .map(|src| score_evidence_fidelity(&candidate_findings, src));
    let (duplicate_inv, duplicate_rate) = score_duplicates(&candidate_findings);
    let novelty_rate = score_novelty(&candidate_findings, &matches);
    let contradiction_recall = score_contradiction_recall(&gold_findings, &candidate_findings);
    let downstream_link_rate = score_downstream_link(&gold_findings, &candidate_findings, &matches);

    let composite = compute_composite(
        &claim_match_rate,
        &scope_accuracy,
        evidence_fidelity.as_ref(),
        duplicate_inv,
        &contradiction_recall,
        &downstream_link_rate,
    );

    Ok(BenchReport {
        gold_path: input.gold_path.display().to_string(),
        candidate_path: input.candidate_path.display().to_string(),
        gold_findings: gold_findings.len(),
        candidate_findings: candidate_findings.len(),
        matched_pairs: matches.len(),
        claim_match_rate,
        scope_accuracy,
        evidence_fidelity,
        duplicate_rate,
        novelty_rate,
        contradiction_recall,
        downstream_link_rate,
        composite,
        threshold: input.threshold,
        pass: composite >= input.threshold,
    })
}

fn sorted_findings(p: &Project) -> Vec<FindingBundle> {
    let mut out = p.findings.clone();
    out.sort_by(|a, b| a.id.cmp(&b.id));
    out
}

/// Like `sorted_findings`, but also pulls `finding.add` proposal
/// payloads into the set so unsigned agent output can be scored.
/// Skips proposals whose target id collides with an already-
/// committed finding (the committed copy wins).
fn sorted_findings_with_proposals(p: &Project) -> Vec<FindingBundle> {
    let mut out = p.findings.clone();
    let already: HashSet<String> = out.iter().map(|f| f.id.clone()).collect();
    let mut seen = already.clone();
    for proposal in &p.proposals {
        if proposal.kind != "finding.add" {
            continue;
        }
        let Some(payload_finding) = proposal.payload.get("finding") else {
            continue;
        };
        let Ok(bundle) = serde_json::from_value::<FindingBundle>(payload_finding.clone()) else {
            continue;
        };
        if seen.contains(&bundle.id) {
            continue;
        }
        seen.insert(bundle.id.clone());
        out.push(bundle);
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    out
}

// ---------- Matching ----------

/// Returns matched pairs (gold_index, candidate_index). Greedy
/// (not full Hungarian — F1 is symmetric in our use, and this
/// stays deterministic with sorted-by-id input). Match rule:
/// either content-address equal OR claim-text Jaccard ≥ 0.4.
fn match_findings(gold: &[FindingBundle], candidate: &[FindingBundle]) -> Vec<(usize, usize)> {
    let mut used_g: HashSet<usize> = HashSet::new();
    let mut used_c: HashSet<usize> = HashSet::new();
    let mut pairs: Vec<(usize, usize, f64)> = Vec::new();

    // First pass: exact id matches (cheap, certain).
    let g_by_id: HashMap<&str, usize> = gold
        .iter()
        .enumerate()
        .map(|(i, f)| (f.id.as_str(), i))
        .collect();
    for (ci, cand) in candidate.iter().enumerate() {
        if let Some(&gi) = g_by_id.get(cand.id.as_str()) {
            pairs.push((gi, ci, 1.0));
            used_g.insert(gi);
            used_c.insert(ci);
        }
    }

    // Second pass: jaccard ≥ 0.4 on remaining.
    let g_tokens: Vec<BTreeSet<String>> = gold
        .iter()
        .map(|f| tokenize_claim(&f.assertion.text))
        .collect();
    let c_tokens: Vec<BTreeSet<String>> = candidate
        .iter()
        .map(|f| tokenize_claim(&f.assertion.text))
        .collect();
    for (ci, c_set) in c_tokens.iter().enumerate() {
        if used_c.contains(&ci) {
            continue;
        }
        let mut best: Option<(usize, f64)> = None;
        for (gi, g_set) in g_tokens.iter().enumerate() {
            if used_g.contains(&gi) {
                continue;
            }
            let j = jaccard(g_set, c_set);
            if j >= 0.4 && best.map(|(_, b)| j > b).unwrap_or(true) {
                best = Some((gi, j));
            }
        }
        if let Some((gi, score)) = best {
            pairs.push((gi, ci, score));
            used_g.insert(gi);
            used_c.insert(ci);
        }
    }

    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    pairs.into_iter().map(|(g, c, _)| (g, c)).collect()
}

fn tokenize_claim(s: &str) -> BTreeSet<String> {
    s.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| t.len() > 2)
        .map(String::from)
        .collect()
}

fn jaccard(a: &BTreeSet<String>, b: &BTreeSet<String>) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    let inter = a.intersection(b).count() as f64;
    let union = a.union(b).count() as f64;
    if union == 0.0 { 0.0 } else { inter / union }
}

// ---------- Metrics ----------

fn score_claim_match(
    gold: &[FindingBundle],
    candidate: &[FindingBundle],
    matches: &[(usize, usize)],
) -> MetricResult {
    let g = gold.len();
    let c = candidate.len();
    let m = matches.len();
    let denom = g + c;
    let score = if denom == 0 {
        0.0
    } else {
        (2.0 * m as f64) / denom as f64
    };
    let target = 0.70;
    MetricResult {
        score,
        target,
        pass: score >= target,
        note: format!("F1 over claim-text match: 2·|M|/(|G|+|C|) = 2·{m}/({g}+{c})"),
        vacuous: false,
    }
}

fn score_scope(
    gold: &[FindingBundle],
    candidate: &[FindingBundle],
    matches: &[(usize, usize)],
) -> MetricResult {
    if matches.is_empty() {
        return MetricResult {
            score: 0.0,
            target: 0.80,
            pass: false,
            note: "no matched pairs to evaluate scope on".to_string(),
            vacuous: false,
        };
    }
    let mut sum = 0.0_f64;
    for &(gi, ci) in matches {
        let g = &gold[gi];
        let c = &candidate[ci];
        let organism_eq = entity_eq_for_type(g, c, "organism");
        let intervention_overlap = entity_overlap_for_type(g, c, "intervention");
        sum += 0.5 * organism_eq + 0.5 * intervention_overlap;
    }
    let score = sum / matches.len() as f64;
    MetricResult {
        score,
        target: 0.80,
        pass: score >= 0.80,
        note: "mean of (0.5·organism_eq + 0.5·intervention_overlap) over matched pairs".to_string(),
        vacuous: false,
    }
}

fn entity_eq_for_type(g: &FindingBundle, c: &FindingBundle, ent_type: &str) -> f64 {
    let g_set: BTreeSet<String> = g
        .assertion
        .entities
        .iter()
        .filter(|e| e.entity_type.eq_ignore_ascii_case(ent_type))
        .map(|e| e.name.to_lowercase())
        .collect();
    let c_set: BTreeSet<String> = c
        .assertion
        .entities
        .iter()
        .filter(|e| e.entity_type.eq_ignore_ascii_case(ent_type))
        .map(|e| e.name.to_lowercase())
        .collect();
    if g_set.is_empty() && c_set.is_empty() {
        // Neither side specified — neutral, count as match.
        return 1.0;
    }
    if g_set == c_set { 1.0 } else { 0.0 }
}

fn entity_overlap_for_type(g: &FindingBundle, c: &FindingBundle, ent_type: &str) -> f64 {
    let g_set: BTreeSet<String> = g
        .assertion
        .entities
        .iter()
        .filter(|e| e.entity_type.eq_ignore_ascii_case(ent_type))
        .map(|e| e.name.to_lowercase())
        .collect();
    let c_set: BTreeSet<String> = c
        .assertion
        .entities
        .iter()
        .filter(|e| e.entity_type.eq_ignore_ascii_case(ent_type))
        .map(|e| e.name.to_lowercase())
        .collect();
    jaccard(&g_set, &c_set)
}

fn score_evidence_fidelity(candidate: &[FindingBundle], sources: &Path) -> MetricResult {
    // Walk all files under `sources` once, build a lowercase
    // whitespace-normalized buffer per file; for each candidate
    // finding's evidence_spans, check substring presence.
    let source_blobs = collect_source_blobs(sources);
    if source_blobs.is_empty() {
        return MetricResult {
            score: 0.0,
            target: 0.95,
            pass: false,
            note: format!(
                "no readable source files under {} — cannot score fidelity",
                sources.display()
            ),
            vacuous: false,
        };
    }

    let mut checked = 0;
    let mut hit = 0;
    for f in candidate {
        for span in &f.evidence.evidence_spans {
            let text = extract_span_text(span);
            if text.is_empty() {
                continue;
            }
            let needle = normalize_for_match(&text);
            if needle.len() < 12 {
                // Too short to be meaningful (single tokens trivially
                // match the whole corpus). Skip.
                continue;
            }
            checked += 1;
            if source_blobs.iter().any(|b| b.contains(&needle)) {
                hit += 1;
            }
        }
    }

    let score = if checked == 0 {
        0.0
    } else {
        hit as f64 / checked as f64
    };
    MetricResult {
        score,
        target: 0.95,
        pass: score >= 0.95,
        note: format!("{hit}/{checked} candidate evidence spans substring-match a source file"),
        vacuous: false,
    }
}

fn collect_source_blobs(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let basename = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            if basename.starts_with('.') {
                continue;
            }
            let Ok(meta) = entry.metadata() else { continue };
            if meta.is_dir() {
                stack.push(path);
                continue;
            }
            // Read as text — binary files (PDFs) get skipped via
            // the utf8 check (the corresponding raw .txt sibling
            // is what bench actually scores against).
            if let Ok(s) = std::fs::read_to_string(&path) {
                out.push(normalize_for_match(&s));
            }
        }
    }
    out
}

fn extract_span_text(span: &serde_json::Value) -> String {
    if let Some(s) = span.as_str() {
        return s.to_string();
    }
    if let Some(s) = span.get("text").and_then(|v| v.as_str()) {
        return s.to_string();
    }
    if let Some(s) = span.get("snippet").and_then(|v| v.as_str()) {
        return s.to_string();
    }
    String::new()
}

fn normalize_for_match(s: &str) -> String {
    s.to_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn score_duplicates(candidate: &[FindingBundle]) -> (f64, f64) {
    if candidate.is_empty() {
        return (1.0, 0.0);
    }
    let unique: HashSet<&str> = candidate.iter().map(|f| f.id.as_str()).collect();
    let dup_rate = 1.0 - (unique.len() as f64 / candidate.len() as f64);
    (1.0 - dup_rate, dup_rate)
}

fn score_novelty(candidate: &[FindingBundle], matches: &[(usize, usize)]) -> f64 {
    if candidate.is_empty() {
        return 0.0;
    }
    let matched_c: HashSet<usize> = matches.iter().map(|&(_, ci)| ci).collect();
    let novel = candidate.len() - matched_c.len();
    novel as f64 / candidate.len() as f64
}

fn score_contradiction_recall(gold: &[FindingBundle], candidate: &[FindingBundle]) -> MetricResult {
    let gold_contradictions = collect_contradiction_set(gold);
    if gold_contradictions.is_empty() {
        return MetricResult {
            score: 1.0,
            target: 0.60,
            pass: true,
            note: "no contradictions in gold — excluded from composite".to_string(),
            vacuous: true,
        };
    }
    let candidate_contradictions = collect_contradiction_set(candidate);
    let detected = gold_contradictions
        .iter()
        .filter(|pair| candidate_contradictions.contains(*pair))
        .count();
    let score = detected as f64 / gold_contradictions.len() as f64;
    MetricResult {
        score,
        target: 0.60,
        pass: score >= 0.60,
        note: format!(
            "{detected}/{} gold contradictions detected by candidate",
            gold_contradictions.len()
        ),
        vacuous: false,
    }
}

fn collect_contradiction_set(p: &[FindingBundle]) -> BTreeSet<(String, String)> {
    let mut out = BTreeSet::new();
    for f in p {
        for link in &f.links {
            let lt = link.link_type.to_lowercase();
            if lt == "contradicts" || lt == "tension" || lt == "contests" {
                let mut pair = [f.id.clone(), link.target.clone()];
                pair.sort();
                out.insert((pair[0].clone(), pair[1].clone()));
            }
        }
    }
    out
}

fn score_downstream_link(
    gold: &[FindingBundle],
    candidate: &[FindingBundle],
    matches: &[(usize, usize)],
) -> MetricResult {
    // Among candidate findings that aren't matches (i.e. novel),
    // what fraction link to ≥1 existing gold vf_id? A sign that
    // the agent is grounding new claims in the existing frontier.
    let matched_c: HashSet<usize> = matches.iter().map(|&(_, ci)| ci).collect();
    let novel: Vec<&FindingBundle> = candidate
        .iter()
        .enumerate()
        .filter(|(i, _)| !matched_c.contains(i))
        .map(|(_, f)| f)
        .collect();
    if novel.is_empty() {
        return MetricResult {
            score: 1.0,
            target: 0.75,
            pass: true,
            note: "no novel candidate findings — excluded from composite".to_string(),
            vacuous: true,
        };
    }
    let gold_ids: HashSet<&str> = gold.iter().map(|f| f.id.as_str()).collect();
    let linked = novel
        .iter()
        .filter(|f| f.links.iter().any(|l| gold_ids.contains(l.target.as_str())))
        .count();
    let score = linked as f64 / novel.len() as f64;
    MetricResult {
        score,
        target: 0.75,
        pass: score >= 0.75,
        note: format!(
            "{linked}/{} novel candidate findings link to a gold finding",
            novel.len()
        ),
        vacuous: false,
    }
}

fn compute_composite(
    claim_match: &MetricResult,
    scope: &MetricResult,
    evidence_fidelity: Option<&MetricResult>,
    duplicate_inv: f64,
    contradiction_recall: &MetricResult,
    downstream_link: &MetricResult,
) -> f64 {
    // v0.29.2: weighted average over only the metrics that have
    // real data. A vacuous metric (e.g. contradiction_recall=1.0
    // because gold has 0 contradictions to recall) is dropped from
    // both the numerator AND the denominator so it can't inflate
    // the composite. Friction #13: pre-fix, an unrelated candidate
    // frontier could score 0.31 just from vacuous 1.0s, masking
    // the fact that claim_match_rate was 0. Post-fix, it scores 0.
    let mut num = W_CLAIM_MATCH * claim_match.score + W_SCOPE * scope.score;
    let mut denom = W_CLAIM_MATCH + W_SCOPE;

    if let Some(ef) = evidence_fidelity
        && !ef.vacuous
    {
        num += W_EVIDENCE_FIDELITY * ef.score;
        denom += W_EVIDENCE_FIDELITY;
    }
    if !contradiction_recall.vacuous {
        num += W_CONTRADICTION_RECALL * contradiction_recall.score;
        denom += W_CONTRADICTION_RECALL;
    }
    if !downstream_link.vacuous {
        num += W_DOWNSTREAM_LINK * downstream_link.score;
        denom += W_DOWNSTREAM_LINK;
    }
    // duplicate_inv is never vacuous: even with 0 candidate
    // findings it has the trivial meaning "no duplicates among 0".
    num += W_DUPLICATE_INV * duplicate_inv;
    denom += W_DUPLICATE_INV;

    if denom == 0.0 { 0.0 } else { num / denom }
}

/// Render a human-readable report. JSON callers serialize
/// `BenchReport` directly.
pub fn render_pretty(report: &BenchReport) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "  gold:                {} ({} findings)\n",
        report.gold_path, report.gold_findings
    ));
    out.push_str(&format!(
        "  candidate:           {} ({} findings)\n",
        report.candidate_path, report.candidate_findings
    ));
    out.push_str(&format!(
        "  matched pairs:       {}\n",
        report.matched_pairs
    ));
    out.push_str("  ----\n");
    pretty_metric(&mut out, "claim_match_rate    ", &report.claim_match_rate);
    pretty_metric(&mut out, "scope_accuracy      ", &report.scope_accuracy);
    if let Some(ef) = &report.evidence_fidelity {
        pretty_metric(&mut out, "evidence_fidelity   ", ef);
    } else {
        out.push_str("  evidence_fidelity     (skipped — no --sources provided)\n");
    }
    out.push_str(&format!(
        "  duplicate_rate        {:.3} (lower is better)\n",
        report.duplicate_rate
    ));
    out.push_str(&format!(
        "  novelty_rate          {:.3} (informational)\n",
        report.novelty_rate
    ));
    pretty_metric(
        &mut out,
        "contradiction_recall",
        &report.contradiction_recall,
    );
    pretty_metric(
        &mut out,
        "downstream_link_rate",
        &report.downstream_link_rate,
    );
    out.push_str("  ----\n");
    // v0.29.2: surface a clear "no-overlap detected" banner when
    // claim_match_rate is 0 against a non-empty gold + candidate.
    // Without this, a candidate covering tangential subject matter
    // can collapse the composite to whatever the duplicate_inv +
    // duplicate_rate floor allows, and the user reads the score as
    // "passing". Friction #13.
    let no_overlap =
        report.matched_pairs == 0 && report.gold_findings > 0 && report.candidate_findings > 0;
    if no_overlap {
        out.push_str(
            "  ⚠ no overlap detected: 0 matched pairs against a non-empty gold;\n    composite reflects only the metrics with real data\n",
        );
    }
    out.push_str(&format!(
        "  COMPOSITE             {:.3}  (threshold {:.2}, {})\n",
        report.composite,
        report.threshold,
        if report.pass { "PASS" } else { "FAIL" }
    ));
    out
}

fn pretty_metric(out: &mut String, label: &str, m: &MetricResult) {
    let tag = if m.vacuous {
        "n/a"
    } else if m.pass {
        "ok"
    } else {
        "low"
    };
    out.push_str(&format!(
        "  {label}  {:.3}  (target {:.2}, {tag})\n",
        m.score, m.target,
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::{
        Assertion, Conditions, Confidence, Evidence, Extraction, FindingBundle, Flags, Provenance,
    };

    fn finding(id: &str, claim: &str) -> FindingBundle {
        FindingBundle {
            id: id.to_string(),
            version: 1,
            previous_version: None,
            assertion: Assertion {
                text: claim.to_string(),
                assertion_type: "mechanism".to_string(),
                entities: Vec::new(),
                relation: None,
                direction: None,
                causal_claim: None,
                causal_evidence_grade: None,
            },
            evidence: Evidence {
                evidence_type: "test".to_string(),
                model_system: String::new(),
                species: None,
                method: "test".to_string(),
                sample_size: None,
                effect_size: None,
                p_value: None,
                replicated: false,
                replication_count: None,
                evidence_spans: Vec::new(),
            },
            conditions: Conditions {
                text: String::new(),
                species_verified: Vec::new(),
                species_unverified: Vec::new(),
                in_vitro: false,
                in_vivo: false,
                human_data: false,
                clinical_trial: false,
                concentration_range: None,
                duration: None,
                age_group: None,
                cell_type: None,
            },
            confidence: Confidence::raw(0.5, "test", 0.7),
            provenance: Provenance {
                source_type: "test".to_string(),
                doi: None,
                pmid: None,
                pmc: None,
                openalex_id: None,
                url: None,
                title: "t".to_string(),
                authors: Vec::new(),
                year: None,
                journal: None,
                license: None,
                publisher: None,
                funders: Vec::new(),
                extraction: Extraction {
                    method: "test".to_string(),
                    model: None,
                    model_version: None,
                    extracted_at: String::new(),
                    extractor_version: "test".to_string(),
                },
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
            links: Vec::new(),
            annotations: Vec::new(),
            attachments: Vec::new(),
            created: String::new(),
            updated: None,

            access_tier: crate::access_tier::AccessTier::Public,
        }
    }

    #[test]
    fn jaccard_basics() {
        let a: BTreeSet<String> = ["a", "b", "c"].iter().map(|s| s.to_string()).collect();
        let b: BTreeSet<String> = ["b", "c", "d"].iter().map(|s| s.to_string()).collect();
        assert!((jaccard(&a, &b) - (2.0 / 4.0)).abs() < f64::EPSILON);
    }

    #[test]
    fn match_findings_id_first() {
        let g = vec![finding("vf_1", "alpha increases beta in mouse")];
        let c = vec![finding("vf_1", "totally different text")];
        let m = match_findings(&g, &c);
        assert_eq!(m, vec![(0, 0)]);
    }

    #[test]
    fn match_findings_jaccard_fallback() {
        let g = vec![finding(
            "vf_g1",
            "Focused ultrasound increases BBB permeability in mouse models",
        )];
        let c = vec![finding(
            "vf_c1",
            "Focused ultrasound transiently opens BBB permeability across mouse models",
        )];
        let m = match_findings(&g, &c);
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn claim_match_rate_at_full_overlap() {
        let g = vec![
            finding("vf_g1", "alpha increases beta in mouse"),
            finding("vf_g2", "gamma decreases delta in human"),
        ];
        let c = g.clone();
        let m = match_findings(&g, &c);
        let r = score_claim_match(&g, &c, &m);
        assert!((r.score - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn duplicate_rate_zero_for_unique() {
        let c = vec![finding("vf_a", "x"), finding("vf_b", "y")];
        let (inv, dup) = score_duplicates(&c);
        assert!((dup - 0.0).abs() < f64::EPSILON);
        assert!((inv - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn empty_candidate_zero_composite() {
        let g = vec![finding("vf_g1", "a b c d e")];
        let c: Vec<FindingBundle> = Vec::new();
        let m = match_findings(&g, &c);
        let cm = score_claim_match(&g, &c, &m);
        assert_eq!(cm.score, 0.0);
    }
}
