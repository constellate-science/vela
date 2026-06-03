//! Bridge detection — find cross-domain hypotheses from multiple frontiers.
//!
//! The core value proposition of Vela: compile findings from separate fields,
//! link them by shared entities, and surface testable hypotheses at the intersection.
//!
//! ## v0.46 — bridges as first-class kernel objects
//!
//! v0.45 and earlier treated bridges as a derived report — a function from
//! two `Project`s to a `Vec<BridgeEntity>` that ran on demand and was
//! never persisted. v0.46 promotes bridges to first-class kernel objects:
//! content-addressed `vbr_<hash>` records that live in
//! `.vela/bridges/<vbr_id>.json` alongside findings, replications,
//! datasets, and code artifacts.
//!
//! The shape: a `Bridge` is a *compositional hypothesis* that two
//! frontiers' shared entity admits a cross-frontier claim. The kernel
//! never asserts the hypothesis is true — that's a reviewer call,
//! recorded by transitioning the bridge's `status` from `Derived` to
//! `Confirmed` or `Refuted`. Bridges are written by `vela bridges
//! derive`, read by `vela bridges list / show`, and updated by `vela
//! bridges confirm / refute`.
//!
//! Doctrine: bridges are derived, not invented. The derivation runs the
//! same `detect_bridges` algorithm and records its output verbatim.
//! Confirmation / refutation is a reviewer act, not an automated one.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::project::Project;

/// A bridge entity — appears in findings from 2+ different source frontiers.
pub struct BridgeEntity {
    pub entity_name: String,
    pub frontiers: Vec<String>,
    pub findings_per_frontier: HashMap<String, Vec<BridgeFinding>>,
    pub total_findings: usize,
    pub breadth: usize,
    pub pubmed_count: Option<u64>,
    pub tension: Option<String>,
}

#[allow(dead_code)]
pub struct BridgeFinding {
    pub id: String,
    pub assertion: String,
    pub confidence: f64,
    pub direction: Option<String>,
    pub year: Option<i32>,
    pub doi: Option<String>,
    pub title: String,
}

/// Detect bridges across multiple named frontiers.
pub fn detect_bridges(named_frontiers: &[(&str, &Project)]) -> Vec<BridgeEntity> {
    let mut entity_map: HashMap<String, HashMap<String, Vec<BridgeFinding>>> = HashMap::new();

    for (frontier_name, frontier) in named_frontiers {
        for f in &frontier.findings {
            let mut entity_names: Vec<String> = f
                .assertion
                .entities
                .iter()
                .map(|e| e.name.to_lowercase())
                .collect();

            // Include aliases
            for e in &f.assertion.entities {
                for alias in &e.aliases {
                    let a = alias.to_lowercase();
                    if !entity_names.contains(&a) {
                        entity_names.push(a);
                    }
                }
            }

            for name in entity_names {
                let corr_map = entity_map.entry(name).or_default();
                let findings = corr_map.entry(frontier_name.to_string()).or_default();
                // Avoid duplicates within same frontier
                if !findings.iter().any(|bf| bf.id == f.id) {
                    findings.push(BridgeFinding {
                        id: f.id.clone(),
                        assertion: f.assertion.text.clone(),
                        confidence: f.confidence.score,
                        direction: f.assertion.direction.clone(),
                        year: f.provenance.year,
                        doi: f.provenance.doi.clone(),
                        title: f.provenance.title.clone(),
                    });
                }
            }
        }
    }

    let mut bridges: Vec<BridgeEntity> = entity_map
        .into_iter()
        .filter(|(name, corr_map)| corr_map.len() >= 2 && !is_obvious(name))
        .map(|(name, corr_map)| {
            let total = corr_map.values().map(|v| v.len()).sum();
            let frontiers: Vec<String> = corr_map.keys().cloned().collect();
            let breadth = frontiers.len();

            // Detect tension (opposite directions across frontiers)
            let tension = detect_tension(&corr_map);

            BridgeEntity {
                entity_name: name,
                frontiers,
                findings_per_frontier: corr_map,
                total_findings: total,
                breadth,
                pubmed_count: None,
                tension,
            }
        })
        .collect();

    bridges.sort_by(|a, b| {
        b.breadth
            .cmp(&a.breadth)
            .then(b.tension.is_some().cmp(&a.tension.is_some()))
            .then(b.total_findings.cmp(&a.total_findings))
    });
    bridges
}

fn detect_tension(corr_map: &HashMap<String, Vec<BridgeFinding>>) -> Option<String> {
    let mut pos = Vec::new();
    let mut neg = Vec::new();
    for (frontier, findings) in corr_map {
        for f in findings {
            match f.direction.as_deref() {
                Some("positive") if !pos.contains(frontier) => pos.push(frontier.clone()),
                Some("negative") if !neg.contains(frontier) => neg.push(frontier.clone()),
                _ => {}
            }
        }
    }
    if !pos.is_empty() && !neg.is_empty() {
        Some(format!(
            "positive in [{}], negative in [{}]",
            pos.join(", "),
            neg.join(", ")
        ))
    } else {
        None
    }
}

pub fn is_obvious(name: &str) -> bool {
    const OBVIOUS: &[&str] = &[
        "alzheimer's disease",
        "blood-brain barrier",
        "brain",
        "neuron",
        "neurons",
        "neurodegeneration",
        "neuroinflammation",
        "cns",
        "inflammation",
        "dementia",
        "parkinson's disease",
        "microglia",
        "astrocyte",
        "astrocytes",
        "hippocampus",
        "cortex",
        "cognitive decline",
        "cognitive function",
        "neurodegenerative diseases",
        "oxidative stress",
        "cytokines",
        "cerebrospinal fluid",
        "amyloid",
        "amyloid-beta",
        "β-amyloid",
        "amyloid β",
        "tau",
        "mouse",
        "mice",
        "rat",
        "human",
        "patient",
        "patients",
        "disease",
        "treatment",
        "therapy",
        "drug",
        "receptor",
        "cell",
        "cells",
        "protein",
        "gene",
        "pathway",
        "mechanism",
        "model",
        "study",
        "expression",
        "level",
        "levels",
        "activity",
        "function",
        "role",
        "effect",
        "effects",
    ];
    OBVIOUS.contains(&name.to_lowercase().as_str())
}

/// Run a rough PubMed prior-art check for a cross-domain query.
/// Retries up to 2 times with exponential backoff on transient failures.
pub async fn check_novelty(client: &reqwest::Client, query: &str) -> Result<u64, String> {
    let url = format!(
        "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esearch.fcgi?db=pubmed&term={}&rettype=json&retmode=json&tool=vela&email=vela@borrowedlight.org",
        urlencoding::encode(query)
    );
    let json: serde_json::Value =
        crate::retry::retry_with_backoff("PubMed prior-art check", 2, || {
            let client = client.clone();
            let url = url.clone();
            async move {
                let resp = client
                    .get(&url)
                    .timeout(std::time::Duration::from_secs(10))
                    .send()
                    .await
                    .map_err(|e| format!("PubMed: {e}"))?;
                if !resp.status().is_success() {
                    return Err(format!("PubMed {}", resp.status()));
                }
                resp.json::<serde_json::Value>()
                    .await
                    .map_err(|e| format!("PubMed parse: {e}"))
            }
        })
        .await?;
    Ok(json["esearchresult"]["count"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0))
}

/// Build a specific PubMed query for a bridge entity.
/// Uses the most distinctive co-occurring entity from each frontier, not just field names.
pub fn novelty_query(entity: &str, bridge: &BridgeEntity) -> String {
    // Get the most specific co-occurring entity from each frontier
    let mut frontier_specifics: Vec<String> = Vec::new();
    for findings in bridge.findings_per_frontier.values() {
        // Find the most specific entity that co-occurs with the bridge entity
        // (not the bridge entity itself, and not an obvious term)
        let mut cooccur: HashMap<String, usize> = HashMap::new();
        for f in findings {
            // We don't have access to other entities here directly,
            // so extract keywords from the assertion text
            let words: Vec<&str> = f.assertion.split_whitespace().collect();
            for w in words {
                let clean = w
                    .trim_matches(|c: char| !c.is_alphanumeric())
                    .to_lowercase();
                if clean.len() > 3 && !is_obvious(&clean) && clean != entity.to_lowercase() {
                    *cooccur.entry(clean).or_default() += 1;
                }
            }
        }
        // Pick the most frequent non-obvious co-occurring word
        if let Some((word, _)) = cooccur.into_iter().max_by_key(|(_, count)| *count) {
            frontier_specifics.push(word);
        }
    }

    // Build query: entity + top 2 specific terms from different frontiers
    let mut parts = vec![entity.to_string()];
    for term in frontier_specifics.iter().take(2) {
        parts.push(term.clone());
    }
    parts.join(" AND ")
}

/// Format the bridge report.
pub fn format_report(bridges: &[BridgeEntity], total_findings: usize) -> String {
    let mut r = String::new();

    let prior_art_clear: Vec<_> = bridges
        .iter()
        .filter(|b| b.pubmed_count == Some(0))
        .collect();
    let emerging: Vec<_> = bridges
        .iter()
        .filter(|b| matches!(b.pubmed_count, Some(1..=5)))
        .collect();
    let with_tension: Vec<_> = bridges.iter().filter(|b| b.tension.is_some()).collect();

    r.push_str(&format!("\n{}\n", "═".repeat(70)));
    r.push_str("VELA BRIDGE REPORT\n");
    r.push_str(&format!("{}\n\n", "═".repeat(70)));
    r.push_str(&format!("  Total findings:    {total_findings}\n"));
    r.push_str(&format!(
        "  Bridge entities:   {} (non-obvious)\n",
        bridges.len()
    ));
    r.push_str(&format!(
        "  Zero-result prior-art checks: {}\n",
        prior_art_clear.len()
    ));
    r.push_str(&format!("  Emerging (1-5):    {}\n", emerging.len()));
    r.push_str(&format!("  With tension:      {}\n", with_tension.len()));

    if !prior_art_clear.is_empty() {
        r.push_str(&format!("\n{}\n", "─".repeat(70)));
        r.push_str("CANDIDATE BRIDGES — zero PubMed results for query\n");
        r.push_str(&format!("{}\n\n", "─".repeat(70)));

        for (i, b) in prior_art_clear.iter().enumerate().take(20) {
            r.push_str(&format!("  {}. {}", i + 1, b.entity_name.to_uppercase()));
            if let Some(t) = &b.tension {
                r.push_str(&format!("  ⚡ {t}"));
            }
            r.push('\n');
            r.push_str(&format!("     Bridges: {}\n", b.frontiers.join(" ↔ ")));
            for (corr, findings) in &b.findings_per_frontier {
                let top = &findings[0];
                let trunc: String = top.assertion.chars().take(90).collect();
                r.push_str(&format!(
                    "     [{corr}] conf:{:.2} | {trunc}...\n",
                    top.confidence
                ));
            }
            r.push('\n');
        }
    }

    if !with_tension.is_empty() {
        r.push_str(&format!("{}\n", "─".repeat(70)));
        r.push_str("CROSS-DOMAIN TENSION — opposite directions across fields\n");
        r.push_str(&format!("{}\n\n", "─".repeat(70)));

        for (i, b) in with_tension.iter().enumerate().take(15) {
            if b.pubmed_count == Some(0) {
                continue;
            } // already shown above
            r.push_str(&format!(
                "  {}. {} — {}\n",
                i + 1,
                b.entity_name,
                b.tension.as_deref().unwrap_or("")
            ));
            r.push_str(&format!(
                "     PubMed: {} results\n\n",
                b.pubmed_count.unwrap_or(0)
            ));
        }
    }

    r.push_str(&format!("{}\n", "═".repeat(70)));
    r.push_str("Generated by Vela — the stars have always been there\n\n");
    r
}

// ── v0.46: first-class Bridge objects ────────────────────────────────

/// A first-class, content-addressed bridge object. Persisted in
/// `.vela/bridges/<vbr_id>.json` next to findings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Bridge {
    /// `vbr_<16hex>`, content-addressed.
    pub id: String,
    /// Schema URL pin so old readers refuse mismatched data.
    #[serde(default = "default_bridge_schema")]
    pub schema: String,
    /// Canonical (lowercased) entity name that bridges the frontiers.
    pub entity_name: String,
    /// Human labels of the bridged frontiers ("bbb", "landscape", …),
    /// in canonical sort order (used in the content address).
    pub frontiers: Vec<String>,
    /// `vfr_<id>`s of the bridged frontiers, when known. Empty vec
    /// when the source was a flat JSON file lacking frontier metadata.
    #[serde(default)]
    pub frontier_ids: Vec<String>,
    /// Per-finding evidence backing the bridge. Each entry pins one
    /// finding from one frontier; the bridge is "the entity links
    /// these findings."
    pub finding_refs: Vec<BridgeRef>,
    /// `Some` when at least one frontier asserts a positive direction
    /// for the entity and another asserts negative — the most
    /// interesting case (cross-domain tension).
    pub tension: Option<String>,
    /// RFC 3339 timestamp when `vela bridges derive` produced this.
    pub derived_at: String,
    /// Reviewer state. Newly derived bridges start `Derived`.
    pub status: BridgeStatus,
}

fn default_bridge_schema() -> String {
    "https://vela.science/schema/bridge/v0.46.0".into()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BridgeRef {
    /// Human label of the frontier this finding belongs to.
    pub frontier: String,
    /// `vf_<id>`.
    pub finding_id: String,
    /// Snapshot of the assertion text at derivation time. Lets the
    /// bridge survive a frontier rewrite (the bridge captures *what
    /// was true when it was derived*).
    pub assertion_text: String,
    pub confidence: f64,
    pub direction: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum BridgeStatus {
    /// Just derived; awaiting reviewer attention.
    Derived,
    /// A reviewer has examined the bridge and confirmed it is a
    /// meaningful cross-frontier composition (not a coincidence of
    /// shared vocabulary).
    Confirmed,
    /// A reviewer has examined the bridge and dismissed it.
    Refuted,
}

impl Bridge {
    /// `vbr_<16hex>` content address. Preimage is
    /// `bridge|<sorted_frontiers>|<entity_name_lowercased>`. Two
    /// derivations against the same frontiers and entity always yield
    /// the same id; re-derivation is idempotent.
    #[must_use]
    pub fn content_address(frontiers: &[String], entity_name: &str) -> String {
        let mut sorted = frontiers.to_vec();
        sorted.sort();
        let preimage = format!("bridge|{}|{}", sorted.join(","), entity_name.to_lowercase());
        let hash = Sha256::digest(preimage.as_bytes());
        format!("vbr_{}", &hex::encode(hash)[..16])
    }

    /// Lift a `BridgeEntity` (the v0.45 detection output) into a
    /// content-addressed `Bridge`. The reviewer status defaults to
    /// `Derived`; transitions are explicit acts.
    pub fn from_detection(
        b: &BridgeEntity,
        frontier_ids: &HashMap<String, String>,
        derived_at: &str,
    ) -> Self {
        let mut refs: Vec<BridgeRef> = b
            .findings_per_frontier
            .iter()
            .flat_map(|(frontier, findings)| {
                findings.iter().map(move |f| BridgeRef {
                    frontier: frontier.clone(),
                    finding_id: f.id.clone(),
                    assertion_text: f.assertion.clone(),
                    confidence: f.confidence,
                    direction: f.direction.clone(),
                })
            })
            .collect();
        refs.sort_by(|a, b| {
            a.frontier
                .cmp(&b.frontier)
                .then(a.finding_id.cmp(&b.finding_id))
        });

        let mut frontiers = b.frontiers.clone();
        frontiers.sort();
        let id = Self::content_address(&frontiers, &b.entity_name);
        let frontier_ids_vec: Vec<String> = frontiers
            .iter()
            .filter_map(|f| frontier_ids.get(f).cloned())
            .collect();

        Self {
            id,
            schema: default_bridge_schema(),
            entity_name: b.entity_name.clone(),
            frontiers,
            frontier_ids: frontier_ids_vec,
            finding_refs: refs,
            tension: b.tension.clone(),
            derived_at: derived_at.to_string(),
            status: BridgeStatus::Derived,
        }
    }
}

/// Top-level v0.46 entry point: derive bridges between two named
/// frontiers and return content-addressed `Bridge` records ready to be
/// written to `.vela/bridges/`.
///
/// Identity-stable: re-running against the same frontiers produces the
/// same `vbr_<id>` per (entity_name, frontier-pair). Callers are
/// expected to merge by id rather than blindly re-write.
#[must_use]
pub fn derive_bridges(named_frontiers: &[(&str, &Project)], derived_at: &str) -> Vec<Bridge> {
    let entities = detect_bridges(named_frontiers);
    let frontier_ids: HashMap<String, String> = named_frontiers
        .iter()
        .filter_map(|(label, p)| p.frontier_id.clone().map(|fid| (label.to_string(), fid)))
        .collect();
    entities
        .iter()
        .map(|b| Bridge::from_detection(b, &frontier_ids, derived_at))
        .collect()
}

#[cfg(test)]
mod v046_tests {
    use super::*;
    use std::fs;

    /// Real-frontier integration: load both BBB-Alzheimer and the
    /// will-alzheimer-landscape JSON fixtures, derive bridges, and
    /// confirm the output is non-empty, content-addressed, and stable
    /// across runs.
    #[test]
    fn derive_real_frontier_pair_is_stable() {
        // Look for fixtures relative to the workspace root. The crate
        // is run from `crates/vela-protocol`; the fixtures live two
        // levels up at `frontiers/*.json`.
        let workspace_root = std::env::var("CARGO_MANIFEST_DIR")
            .map(|s| format!("{s}/../.."))
            .unwrap_or_else(|_| ".".into());
        let bbb_path = format!("{workspace_root}/frontiers/bbb-alzheimer.json");
        let landscape_path = format!("{workspace_root}/frontiers/will-alzheimer-landscape.json");
        if !std::path::Path::new(&bbb_path).exists() {
            eprintln!("skipping derive_real_frontier_pair_is_stable: fixture missing");
            return;
        }
        let bbb_text = fs::read_to_string(&bbb_path).expect("read bbb");
        let landscape_text = fs::read_to_string(&landscape_path).expect("read landscape");
        let bbb: crate::project::Project = serde_json::from_str(&bbb_text).expect("parse bbb");
        let landscape: crate::project::Project =
            serde_json::from_str(&landscape_text).expect("parse landscape");

        let now = "2026-04-28T00:00:00Z";
        let first = derive_bridges(&[("bbb", &bbb), ("landscape", &landscape)], now);
        let second = derive_bridges(&[("bbb", &bbb), ("landscape", &landscape)], now);
        assert!(
            !first.is_empty(),
            "expected real cross-frontier bridges; found 0"
        );
        let ids_first: Vec<&String> = first.iter().map(|b| &b.id).collect();
        let ids_second: Vec<&String> = second.iter().map(|b| &b.id).collect();
        assert_eq!(
            ids_first, ids_second,
            "vbr_<id> set must be stable across runs"
        );
        for b in &first {
            assert!(b.id.starts_with("vbr_"));
            assert_eq!(b.id.len(), "vbr_".len() + 16);
            assert!(!b.finding_refs.is_empty());
            assert_eq!(b.status, BridgeStatus::Derived);
            // Content address recomputes correctly from declared parts.
            let recomputed = Bridge::content_address(&b.frontiers, &b.entity_name);
            assert_eq!(b.id, recomputed);
        }
    }

    #[test]
    fn content_address_independent_of_frontier_order() {
        let a = Bridge::content_address(&["bbb".to_string(), "landscape".to_string()], "trem2");
        let b = Bridge::content_address(&["landscape".to_string(), "bbb".to_string()], "trem2");
        assert_eq!(a, b);
    }

    #[test]
    fn content_address_lowercases_entity() {
        let a = Bridge::content_address(&["a".into(), "b".into()], "TREM2");
        let b = Bridge::content_address(&["a".into(), "b".into()], "trem2");
        assert_eq!(a, b);
    }
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
            confidence: Confidence::raw(0.8, "seeded prior", 0.85),
            provenance: Provenance {
                source_type: "published_paper".into(),
                doi: doi.map(|s| s.to_string()),
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

            access_tier: crate::access_tier::AccessTier::Public,
        }
    }

    fn make_frontier(findings: Vec<FindingBundle>) -> Project {
        crate::project::assemble("test", findings, 1, 0, "test frontier")
    }

    #[test]
    fn entity_in_two_frontiers_is_bridge() {
        let c1 = make_frontier(vec![make_finding(
            "f1",
            vec![("NLRP3", "protein"), ("IL-1B", "protein")],
            None,
            None,
        )]);
        let c2 = make_frontier(vec![make_finding(
            "f2",
            vec![("NLRP3", "protein"), ("caspase-1", "protein")],
            None,
            None,
        )]);
        let named = vec![("neuro", &c1), ("immune", &c2)];
        let bridges = detect_bridges(&named);
        let nlrp3 = bridges.iter().find(|b| b.entity_name == "nlrp3");
        assert!(nlrp3.is_some());
        let nlrp3 = nlrp3.unwrap();
        assert_eq!(nlrp3.breadth, 2);
        assert_eq!(nlrp3.frontiers.len(), 2);
    }

    #[test]
    fn entity_in_one_frontier_not_bridge() {
        let c1 = make_frontier(vec![make_finding(
            "f1",
            vec![("NLRP3", "protein")],
            None,
            None,
        )]);
        let c2 = make_frontier(vec![make_finding(
            "f2",
            vec![("APOE4", "gene")],
            None,
            None,
        )]);
        let named = vec![("neuro", &c1), ("genetics", &c2)];
        let bridges = detect_bridges(&named);
        assert!(bridges.iter().all(|b| b.entity_name != "nlrp3"));
        assert!(bridges.iter().all(|b| b.entity_name != "apoe4"));
    }

    #[test]
    fn obvious_entities_filtered() {
        assert!(is_obvious("brain"));
        assert!(is_obvious("neuron"));
        assert!(is_obvious("Alzheimer's disease"));
        assert!(is_obvious("mouse"));
        assert!(is_obvious("protein"));
        assert!(!is_obvious("NLRP3"));
        assert!(!is_obvious("cryopyrin"));
        assert!(!is_obvious("rapamycin"));
    }

    #[test]
    fn obvious_entities_not_bridges() {
        let c1 = make_frontier(vec![make_finding(
            "f1",
            vec![("brain", "anatomical_structure")],
            None,
            None,
        )]);
        let c2 = make_frontier(vec![make_finding(
            "f2",
            vec![("brain", "anatomical_structure")],
            None,
            None,
        )]);
        let named = vec![("neuro", &c1), ("imaging", &c2)];
        let bridges = detect_bridges(&named);
        assert!(bridges.iter().all(|b| b.entity_name != "brain"));
    }

    #[test]
    fn tension_detected_opposite_directions() {
        let c1 = make_frontier(vec![make_finding(
            "f1",
            vec![("NLRP3", "protein")],
            Some("positive"),
            None,
        )]);
        let c2 = make_frontier(vec![make_finding(
            "f2",
            vec![("NLRP3", "protein")],
            Some("negative"),
            None,
        )]);
        let named = vec![("neuro", &c1), ("immune", &c2)];
        let bridges = detect_bridges(&named);
        let nlrp3 = bridges.iter().find(|b| b.entity_name == "nlrp3").unwrap();
        assert!(nlrp3.tension.is_some());
        let tension = nlrp3.tension.as_ref().unwrap();
        assert!(tension.contains("positive"));
        assert!(tension.contains("negative"));
    }

    #[test]
    fn no_tension_same_direction() {
        let c1 = make_frontier(vec![make_finding(
            "f1",
            vec![("NLRP3", "protein")],
            Some("positive"),
            None,
        )]);
        let c2 = make_frontier(vec![make_finding(
            "f2",
            vec![("NLRP3", "protein")],
            Some("positive"),
            None,
        )]);
        let named = vec![("neuro", &c1), ("immune", &c2)];
        let bridges = detect_bridges(&named);
        let nlrp3 = bridges.iter().find(|b| b.entity_name == "nlrp3").unwrap();
        assert!(nlrp3.tension.is_none());
    }

    #[test]
    fn sorted_by_breadth_then_tension() {
        let c1 = make_frontier(vec![make_finding(
            "f1",
            vec![("entityA", "protein"), ("entityB", "gene")],
            Some("positive"),
            None,
        )]);
        let c2 = make_frontier(vec![make_finding(
            "f2",
            vec![("entityA", "protein"), ("entityB", "gene")],
            Some("negative"),
            None,
        )]);
        let c3 = make_frontier(vec![make_finding(
            "f3",
            vec![("entityA", "protein")],
            None,
            None,
        )]);
        let named = vec![("c1", &c1), ("c2", &c2), ("c3", &c3)];
        let bridges = detect_bridges(&named);
        assert!(bridges.len() >= 2);
        assert!(bridges[0].breadth >= bridges[1].breadth);
    }

    #[test]
    fn empty_input() {
        let bridges = detect_bridges(&[]);
        assert!(bridges.is_empty());
    }

    #[test]
    fn alias_creates_bridge() {
        let mut f1 = make_finding("f1", vec![], None, None);
        f1.assertion.entities.push(Entity {
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
        let c1 = make_frontier(vec![f1]);
        let c2 = make_frontier(vec![make_finding(
            "f2",
            vec![("cryopyrin", "protein")],
            None,
            None,
        )]);
        let named = vec![("neuro", &c1), ("immune", &c2)];
        let bridges = detect_bridges(&named);
        let cryo = bridges.iter().find(|b| b.entity_name == "cryopyrin");
        assert!(cryo.is_some());
    }

    #[test]
    fn detect_tension_helper() {
        let mut map: HashMap<String, Vec<BridgeFinding>> = HashMap::new();
        map.insert(
            "c1".into(),
            vec![BridgeFinding {
                id: "f1".into(),
                assertion: "test".into(),
                confidence: 0.8,
                direction: Some("positive".into()),
                year: Some(2024),
                doi: None,
                title: "T".into(),
            }],
        );
        map.insert(
            "c2".into(),
            vec![BridgeFinding {
                id: "f2".into(),
                assertion: "test".into(),
                confidence: 0.8,
                direction: Some("negative".into()),
                year: Some(2024),
                doi: None,
                title: "T".into(),
            }],
        );
        assert!(detect_tension(&map).is_some());

        let mut map2: HashMap<String, Vec<BridgeFinding>> = HashMap::new();
        map2.insert(
            "c1".into(),
            vec![BridgeFinding {
                id: "f1".into(),
                assertion: "test".into(),
                confidence: 0.8,
                direction: Some("positive".into()),
                year: Some(2024),
                doi: None,
                title: "T".into(),
            }],
        );
        map2.insert(
            "c2".into(),
            vec![BridgeFinding {
                id: "f2".into(),
                assertion: "test".into(),
                confidence: 0.8,
                direction: Some("positive".into()),
                year: Some(2024),
                doi: None,
                title: "T".into(),
            }],
        );
        assert!(detect_tension(&map2).is_none());
    }

    #[test]
    fn is_obvious_case_insensitive() {
        assert!(is_obvious("Brain"));
        assert!(is_obvious("BRAIN"));
        assert!(is_obvious("Cell"));
        assert!(is_obvious("PROTEIN"));
        assert!(is_obvious("Gene"));
        assert!(is_obvious("Pathway"));
        assert!(is_obvious("Mouse"));
    }

    #[test]
    fn is_obvious_rejects_specific_entities() {
        assert!(!is_obvious("rapamycin"));
        assert!(!is_obvious("metformin"));
        assert!(!is_obvious("TREM2"));
        assert!(!is_obvious("GLP-1"));
        assert!(!is_obvious("synuclein"));
        assert!(!is_obvious("berberine"));
    }

    #[test]
    fn is_obvious_all_listed_terms() {
        // Verify every term in the OBVIOUS list is actually caught
        let terms = vec![
            "alzheimer's disease",
            "blood-brain barrier",
            "brain",
            "neuron",
            "neurons",
            "neurodegeneration",
            "neuroinflammation",
            "cns",
            "inflammation",
            "dementia",
            "cell",
            "cells",
            "protein",
            "gene",
            "pathway",
            "mechanism",
            "model",
            "study",
            "expression",
            "level",
            "levels",
            "activity",
            "function",
            "role",
            "effect",
            "effects",
        ];
        for t in terms {
            assert!(is_obvious(t), "Expected '{t}' to be obvious");
        }
    }

    #[test]
    fn bridge_entity_three_frontiers() {
        let c1 = make_frontier(vec![make_finding(
            "f1",
            vec![("TREM2", "protein")],
            None,
            None,
        )]);
        let c2 = make_frontier(vec![make_finding(
            "f2",
            vec![("TREM2", "protein")],
            None,
            None,
        )]);
        let c3 = make_frontier(vec![make_finding(
            "f3",
            vec![("TREM2", "protein")],
            None,
            None,
        )]);
        let named = vec![("neuro", &c1), ("immune", &c2), ("genetics", &c3)];
        let bridges = detect_bridges(&named);
        let trem2 = bridges.iter().find(|b| b.entity_name == "trem2").unwrap();
        assert_eq!(trem2.breadth, 3);
        assert_eq!(trem2.total_findings, 3);
    }

    #[test]
    fn duplicate_finding_in_same_frontier_not_counted_twice() {
        let c1 = make_frontier(vec![
            make_finding("f1", vec![("NLRP3", "protein")], None, None),
            make_finding("f1", vec![("NLRP3", "protein")], None, None), // same ID
        ]);
        let c2 = make_frontier(vec![make_finding(
            "f2",
            vec![("NLRP3", "protein")],
            None,
            None,
        )]);
        let named = vec![("neuro", &c1), ("immune", &c2)];
        let bridges = detect_bridges(&named);
        let nlrp3 = bridges.iter().find(|b| b.entity_name == "nlrp3").unwrap();
        // f1 should only appear once in neuro frontier
        let neuro_findings = nlrp3.findings_per_frontier.get("neuro").unwrap();
        assert_eq!(neuro_findings.len(), 1);
    }

    #[test]
    fn novelty_query_includes_entity() {
        let bridge = BridgeEntity {
            entity_name: "trem2".into(),
            frontiers: vec!["neuro".into(), "immune".into()],
            findings_per_frontier: {
                let mut m = HashMap::new();
                m.insert(
                    "neuro".into(),
                    vec![BridgeFinding {
                        id: "f1".into(),
                        assertion: "TREM2 modulates microglial phagocytosis".into(),
                        confidence: 0.8,
                        direction: None,
                        year: Some(2024),
                        doi: None,
                        title: "T".into(),
                    }],
                );
                m.insert(
                    "immune".into(),
                    vec![BridgeFinding {
                        id: "f2".into(),
                        assertion: "TREM2 regulates complement activation".into(),
                        confidence: 0.7,
                        direction: None,
                        year: Some(2024),
                        doi: None,
                        title: "T".into(),
                    }],
                );
                m
            },
            total_findings: 2,
            breadth: 2,
            pubmed_count: None,
            tension: None,
        };
        let query = novelty_query("trem2", &bridge);
        assert!(query.contains("trem2"));
        // Should have AND separators
        assert!(query.contains(" AND "));
    }

    #[test]
    fn detect_tension_no_direction() {
        let mut map: HashMap<String, Vec<BridgeFinding>> = HashMap::new();
        map.insert(
            "c1".into(),
            vec![BridgeFinding {
                id: "f1".into(),
                assertion: "test".into(),
                confidence: 0.8,
                direction: None,
                year: Some(2024),
                doi: None,
                title: "T".into(),
            }],
        );
        map.insert(
            "c2".into(),
            vec![BridgeFinding {
                id: "f2".into(),
                assertion: "test".into(),
                confidence: 0.8,
                direction: None,
                year: Some(2024),
                doi: None,
                title: "T".into(),
            }],
        );
        assert!(detect_tension(&map).is_none());
    }

    #[test]
    fn format_report_empty_bridges() {
        let report = format_report(&[], 0);
        assert!(report.contains("VELA BRIDGE REPORT"));
        assert!(report.contains("Bridge entities:   0"));
        assert!(report.contains("Total findings:    0"));
    }

    #[test]
    fn format_report_with_novel_bridge() {
        let bridge = BridgeEntity {
            entity_name: "trem2".into(),
            frontiers: vec!["neuro".into(), "immune".into()],
            findings_per_frontier: {
                let mut m = HashMap::new();
                m.insert(
                    "neuro".into(),
                    vec![BridgeFinding {
                        id: "f1".into(),
                        assertion: "TREM2 finding".into(),
                        confidence: 0.85,
                        direction: None,
                        year: Some(2024),
                        doi: None,
                        title: "T".into(),
                    }],
                );
                m.insert(
                    "immune".into(),
                    vec![BridgeFinding {
                        id: "f2".into(),
                        assertion: "TREM2 immune".into(),
                        confidence: 0.7,
                        direction: None,
                        year: Some(2024),
                        doi: None,
                        title: "T".into(),
                    }],
                );
                m
            },
            total_findings: 2,
            breadth: 2,
            pubmed_count: Some(0),
            tension: None,
        };
        let report = format_report(&[bridge], 5);
        assert!(report.contains("CANDIDATE BRIDGES"));
        assert!(report.contains("TREM2"));
    }
}
