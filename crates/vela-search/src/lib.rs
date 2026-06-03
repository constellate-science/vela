//! Vela Search (v0.149).
//!
//! Build-time content-addressed index over registered frontiers.
//! Indexes findings, entities, evidence, attestations, proof
//! artifacts, actors, atlases, and Belnap status.
//!
//! ## Doctrine
//!
//! The index is a **derived view**, never authority. The
//! canonical state is always the registry + frontier event logs.
//! Two consumers who run `build_index` against the same set of
//! frontiers produce byte-identical indices (deterministic key
//! ordering, alphabetical iteration). The index carries a
//! content-addressed hash (`vsi_*`) that the v0.150 site loader
//! cross-checks against the most recent checkpoint declaration.
//!
//! ## Inclusion rules
//!
//! By default, the indexer skips frontiers whose owner-epoch
//! chain status is `broken` (v0.146 verify-chain) and skips
//! frontiers whose chain is in `bootstrap` (no governed
//! rotations yet) unless `include_bootstrap = true` is set on
//! the indexer config. Legacy entries (pre-v0.144, no chain
//! file present) are included with `chain_status = "legacy"`
//! so the site can surface a badge.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

use vela_protocol::project::Project;
use vela_protocol::repo;

pub const INDEX_SCHEMA: &str = "vela.search_index.v0.1";

/// Top-level index. Content-addressed by `vsi_*` over canonical
/// bytes of the sorted entry list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Index {
    pub schema: String,
    pub index_id: String,
    pub generated_at: String,
    pub frontier_count: usize,
    pub entry_count: usize,
    pub entries: Vec<IndexEntry>,
}

/// One indexed item. The `kind` field distinguishes finding /
/// actor / entity / atlas / proof entries; the `body` is a
/// kind-specific blob.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexEntry {
    pub kind: String,
    pub frontier_id: String,
    pub frontier_name: String,
    /// Free-text tokens lowercased, used for substring match.
    pub text: String,
    /// Belnap status: `accepted_core` | `accepted` | `pending` |
    /// `retracted` | `contested` | `unknown`. May be empty for
    /// non-finding entries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// Entity tags collected from finding annotations.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entities: Vec<String>,
    /// Optional source-document identifier (DOI, PMID, ArXiv).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
    /// Stable cross-link to the underlying object (event id,
    /// finding id, actor id, etc.).
    pub target_id: String,
    /// Owner-epoch chain status for this frontier, per v0.146.
    /// Values: `bootstrap | verified | legacy | broken`.
    pub chain_status: String,
}

#[derive(Debug, Clone, Default)]
pub struct IndexerConfig {
    pub include_bootstrap: bool,
    /// When set, the indexer treats `broken` chains the same as
    /// `verified` (used by ops dashboards that want to see the
    /// failure mode rather than skip it). Default false.
    pub include_broken: bool,
}

/// Build an index over the supplied frontier paths. Each path
/// must resolve to a frontier loadable via
/// `vela_protocol::repo::load_from_path`.
pub fn build_index(
    frontier_paths: &[PathBuf],
    cfg: &IndexerConfig,
    now: &str,
) -> Result<Index, String> {
    let mut entries: Vec<IndexEntry> = Vec::new();
    let mut frontier_count = 0usize;

    for path in frontier_paths {
        let project = match repo::load_from_path(path) {
            Ok(p) => p,
            Err(e) => return Err(format!("load {}: {e}", path.display())),
        };
        let chain_status = derive_chain_status(path);

        // Honor inclusion rules.
        if chain_status == "broken" && !cfg.include_broken {
            continue;
        }
        if chain_status == "bootstrap" && !cfg.include_bootstrap {
            // bootstrap = chain file present with zero transitions
            // OR no chain file but the frontier explicitly opted
            // in via a marker (future cycle). For v0.149,
            // bootstrap and legacy are skipped by default.
            continue;
        }
        if chain_status == "legacy" && !cfg.include_bootstrap {
            // Legacy entries pre-date the governance arc; admit
            // them under the same flag as bootstrap.
            continue;
        }

        frontier_count += 1;
        index_one_frontier(&project, &chain_status, &mut entries);
        // v0.210: extend the index over the five new primitives that
        // live as sibling directories under `.vela/`.
        index_v0210_primitives(path, &project, &chain_status, &mut entries);
    }

    // Stable ordering: by (kind, frontier_id, target_id).
    entries.sort_by(|a, b| {
        a.kind
            .cmp(&b.kind)
            .then_with(|| a.frontier_id.cmp(&b.frontier_id))
            .then_with(|| a.target_id.cmp(&b.target_id))
    });

    let entry_count = entries.len();
    let mut index = Index {
        schema: INDEX_SCHEMA.to_string(),
        index_id: String::new(),
        generated_at: now.to_string(),
        frontier_count,
        entry_count,
        entries,
    };
    index.index_id = index.derive_id()?;
    Ok(index)
}

impl Index {
    /// Content-address: `vsi_` + first 16 hex of sha256 over
    /// canonical bytes of the body with `index_id` and
    /// `generated_at` zeroed. The id is stable across runs over
    /// the same input.
    pub fn derive_id(&self) -> Result<String, String> {
        let mut preimage = self.clone();
        preimage.index_id = String::new();
        preimage.generated_at = String::new();
        let bytes = vela_protocol::canonical::to_canonical_bytes(&preimage)
            .map_err(|e| format!("canonicalize index: {e}"))?;
        let digest = Sha256::digest(&bytes);
        Ok(format!("vsi_{}", &hex::encode(digest)[..16]))
    }
}

/// Result row from a query.
#[derive(Debug, Clone, Serialize)]
pub struct SearchResult<'a> {
    pub entry: &'a IndexEntry,
    pub score: f32,
}

/// Filters parameter for `search`. All Some-fields are required
/// to match; None-fields are wildcards.
#[derive(Debug, Clone, Default)]
pub struct SearchFilters {
    pub kind: Option<String>,
    pub entity: Option<String>,
    pub status: Option<String>,
    pub frontier_id: Option<String>,
    pub source_id: Option<String>,
    /// When Some, restrict to entries whose chain_status equals
    /// the given value (e.g. "verified" for strict mode).
    pub chain_status: Option<String>,
    pub limit: Option<usize>,
}

/// Run a query against an index. The query is matched as a
/// lowercased substring against each entry's `text` field; an
/// empty query returns every entry that passes the filters.
/// Score is `text.matches(q).count() as f32` (capped at 100);
/// for empty queries it is 0.
pub fn search<'a>(index: &'a Index, query: &str, filters: &SearchFilters) -> Vec<SearchResult<'a>> {
    let q = query.trim().to_lowercase();
    let mut results: Vec<SearchResult<'a>> = Vec::new();
    for entry in &index.entries {
        if let Some(k) = &filters.kind
            && &entry.kind != k
        {
            continue;
        }
        if let Some(e) = &filters.entity {
            let want = e.to_lowercase();
            if !entry.entities.iter().any(|en| en.to_lowercase() == want) {
                continue;
            }
        }
        if let Some(s) = &filters.status
            && entry.status.as_deref() != Some(s.as_str())
        {
            continue;
        }
        if let Some(fid) = &filters.frontier_id
            && &entry.frontier_id != fid
        {
            continue;
        }
        if let Some(src) = &filters.source_id
            && entry.source_id.as_deref() != Some(src.as_str())
        {
            continue;
        }
        if let Some(cs) = &filters.chain_status
            && &entry.chain_status != cs
        {
            continue;
        }
        let score = if q.is_empty() {
            0.0
        } else {
            let matches = entry.text.matches(&q).count() as f32;
            if matches == 0.0 {
                continue;
            }
            matches.min(100.0)
        };
        results.push(SearchResult { entry, score });
    }
    // Sort by score descending then (kind, frontier_id, target_id) for stability.
    results.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.entry.kind.cmp(&b.entry.kind))
            .then_with(|| a.entry.frontier_id.cmp(&b.entry.frontier_id))
            .then_with(|| a.entry.target_id.cmp(&b.entry.target_id))
    });
    if let Some(limit) = filters.limit {
        results.truncate(limit);
    }
    results
}

fn index_one_frontier(project: &Project, chain_status: &str, out: &mut Vec<IndexEntry>) {
    let vfr_id = project.frontier_id();
    let frontier_name = project.project.name.clone();

    // Compute per-finding status from finding.reviewed events.
    let mut status_by_finding: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    for ev in &project.events {
        if ev.kind == "finding.reviewed"
            && let Some(s) = ev.payload.get("status").and_then(|v| v.as_str())
        {
            status_by_finding.insert(ev.target.id.clone(), s.to_string());
        }
    }

    for finding in &project.findings {
        let status = status_by_finding.get(&finding.id).cloned();
        let text_parts: Vec<String> = vec![
            finding.assertion.text.to_lowercase(),
            finding.assertion.assertion_type.clone(),
            finding.provenance.title.to_lowercase(),
            finding
                .provenance
                .doi
                .clone()
                .unwrap_or_default()
                .to_lowercase(),
        ];
        let entities: Vec<String> = finding
            .assertion
            .entities
            .iter()
            .map(|e| e.name.to_lowercase())
            .collect();
        let source_id = finding
            .provenance
            .doi
            .clone()
            .or_else(|| finding.provenance.pmid.clone());
        out.push(IndexEntry {
            kind: "finding".to_string(),
            frontier_id: vfr_id.clone(),
            frontier_name: frontier_name.clone(),
            text: text_parts.join(" "),
            status,
            entities,
            source_id,
            target_id: finding.id.clone(),
            chain_status: chain_status.to_string(),
        });
    }

    for actor in &project.actors {
        out.push(IndexEntry {
            kind: "actor".to_string(),
            frontier_id: vfr_id.clone(),
            frontier_name: frontier_name.clone(),
            text: actor.id.to_lowercase(),
            status: actor.revoked_at.as_ref().map(|_| "revoked".to_string()),
            entities: Vec::new(),
            source_id: actor.orcid.clone(),
            target_id: actor.id.clone(),
            chain_status: chain_status.to_string(),
        });
    }
}

/// v0.210: walk the five new-primitive directories under
/// `<frontier>/.vela/` and emit IndexEntry rows. Each kind
/// indexes different fields:
///
///   vsd_* (diff_packs/): summary + aggregate_kind
///   vaa_* (agent_attestations/): agent_actor + model_name
///   vtr_* (trajectories/): notes + step descriptions
///   vtd_* (tool_descriptors/): tool_name + provider
///   ver_* (evaluations/): evaluator_actor + outcome + notes
fn index_v0210_primitives(
    frontier: &Path,
    project: &Project,
    chain_status: &str,
    out: &mut Vec<IndexEntry>,
) {
    let vfr_id = project.frontier_id();
    let frontier_name = project.project.name.clone();
    let vela_dir = if frontier.is_dir() {
        frontier.join(".vela")
    } else {
        match frontier.parent() {
            Some(p) => p.join(".vela"),
            None => return,
        }
    };

    let push_entry = |out: &mut Vec<IndexEntry>,
                      kind: &str,
                      target_id: String,
                      text: String,
                      status: Option<String>,
                      source_id: Option<String>| {
        out.push(IndexEntry {
            kind: kind.to_string(),
            frontier_id: vfr_id.clone(),
            frontier_name: frontier_name.clone(),
            text: text.to_lowercase(),
            status,
            entities: Vec::new(),
            source_id,
            target_id,
            chain_status: chain_status.to_string(),
        });
    };

    // diff_packs — v0.222: read from the canonical
    // `Project.released_diff_packs` substrate field (populated by
    // the v0.213 reducer arm and the v0.221 load-time
    // materializer) instead of disk-walking `.vela/diff_packs/`.
    // The substrate field is the source of truth for "which packs
    // are released"; pre-v0.222 the index surfaced unreleased
    // drafts as if they were canonical.
    for rec in &project.released_diff_packs {
        let status = rec
            .verdict
            .as_ref()
            .map(|_| "applied".to_string())
            .or(Some("pending".to_string()));
        push_entry(
            out,
            "vsd",
            rec.pack_id.clone(),
            format!("{} {}", rec.summary, rec.aggregate_kind),
            status,
            None,
        );
    }

    // agent_attestations/
    walk_jsons(&vela_dir.join("agent_attestations"), |id, body| {
        if !id.starts_with("vaa_") {
            return;
        }
        let actor = body
            .get("agent_actor")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let model = body
            .get("model_name")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        push_entry(
            out,
            "vaa",
            id.to_string(),
            format!("{actor} {model}"),
            None,
            None,
        );
    });

    // trajectories/
    walk_jsons(&vela_dir.join("trajectories"), |id, body| {
        if !id.starts_with("vtr_") {
            return;
        }
        let notes = body
            .get("notes")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let steps_text: String = body
            .get("steps")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|s| s.get("description").and_then(|v| v.as_str()))
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .unwrap_or_default();
        let status = body
            .get("retracted")
            .and_then(|v| v.as_bool())
            .and_then(|b| {
                if b {
                    Some("retracted".to_string())
                } else {
                    None
                }
            });
        push_entry(
            out,
            "vtr",
            id.to_string(),
            format!("{notes} {steps_text}"),
            status,
            None,
        );
    });

    // tool_descriptors/
    walk_jsons(&vela_dir.join("tool_descriptors"), |id, body| {
        if !id.starts_with("vtd_") {
            return;
        }
        let tool = body
            .get("tool_name")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let provider = body
            .get("provider")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let version = body
            .get("tool_version")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        push_entry(
            out,
            "vtd",
            id.to_string(),
            format!("{tool} {version} {provider}"),
            None,
            None,
        );
    });

    // evaluations/
    walk_jsons(&vela_dir.join("evaluations"), |id, body| {
        if !id.starts_with("ver_") {
            return;
        }
        let evaluator = body
            .get("evaluator_actor")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let outcome = body
            .get("outcome")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let notes = body
            .get("notes")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        push_entry(
            out,
            "ver",
            id.to_string(),
            format!("{evaluator} {outcome} {notes}"),
            Some(outcome.to_string()),
            body.get("benchmark_id")
                .and_then(|v| v.as_str())
                .map(String::from),
        );
    });

    // verdict_conflicts/ — v0.220 extension
    walk_jsons(&vela_dir.join("verdict_conflicts"), |id, body| {
        if !id.starts_with("vdc_") {
            return;
        }
        let mode = body
            .get("resolution_mode")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let actor = body
            .get("resolution_actor")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let rationale = body
            .get("rationale")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        push_entry(
            out,
            "vdc",
            id.to_string(),
            format!("{mode} {actor} {rationale}"),
            Some(mode.to_string()),
            body.get("winning_verdict_id")
                .and_then(|v| v.as_str())
                .map(String::from),
        );
    });
}

/// Helper: walk every `*.json` file in `dir`, parse it as serde
/// JSON, and call `visit(stem, body)` for each one. Silently skips
/// non-json files and parse failures.
fn walk_jsons(dir: &Path, mut visit: impl FnMut(&str, &serde_json::Value)) {
    if !dir.is_dir() {
        return;
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let stem = match p.file_stem().and_then(|s| s.to_str()) {
            Some(s) => s.to_string(),
            None => continue,
        };
        let body = match std::fs::read_to_string(&p) {
            Ok(s) => s,
            Err(_) => continue,
        };
        match serde_json::from_str::<serde_json::Value>(&body) {
            Ok(v) => visit(&stem, &v),
            Err(_) => continue,
        }
    }
}

/// Derive owner-epoch chain status for a frontier path by
/// inspecting `<frontier-dir>/.vela/governance/chain.json`. The
/// indexer does not re-run v0.146 verify_chain (which would
/// require loading the artifact set); it surfaces the cheaper
/// presence/length check. Consumers who need authority on chain
/// status run `vela registry verify-chain` separately.
fn derive_chain_status(frontier: &Path) -> String {
    let chain_path = chain_path_for(frontier);
    if !chain_path.exists() {
        return "legacy".to_string();
    }
    match std::fs::read_to_string(&chain_path) {
        Ok(raw) => match serde_json::from_str::<serde_json::Value>(&raw) {
            Ok(v) => {
                let count = v
                    .get("transitions")
                    .and_then(|t| t.as_array())
                    .map_or(0, Vec::len);
                if count == 0 {
                    "bootstrap".to_string()
                } else {
                    "verified".to_string()
                }
            }
            Err(_) => "broken".to_string(),
        },
        Err(_) => "broken".to_string(),
    }
}

fn chain_path_for(frontier: &Path) -> PathBuf {
    let dir = if frontier.is_dir() {
        frontier.to_path_buf()
    } else if let Some(parent) = frontier.parent() {
        parent.to_path_buf()
    } else {
        PathBuf::from(".")
    };
    dir.join(".vela").join("governance").join("chain.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_index() -> Index {
        Index {
            schema: INDEX_SCHEMA.to_string(),
            index_id: String::new(),
            generated_at: String::new(),
            frontier_count: 0,
            entry_count: 0,
            entries: Vec::new(),
        }
    }

    #[test]
    fn empty_index_round_trips() {
        let mut idx = empty_index();
        idx.index_id = idx.derive_id().unwrap();
        assert!(idx.index_id.starts_with("vsi_"));
    }

    #[test]
    fn search_matches_finding_text() {
        let mut idx = empty_index();
        idx.entries.push(IndexEntry {
            kind: "finding".to_string(),
            frontier_id: "vfr_a".to_string(),
            frontier_name: "A".to_string(),
            text: "apoe4 increases alzheimer risk".to_string(),
            status: Some("accepted".to_string()),
            entities: vec!["apoe4".to_string()],
            source_id: None,
            target_id: "vf_1".to_string(),
            chain_status: "verified".to_string(),
        });
        idx.entry_count = idx.entries.len();
        let hits = search(&idx, "apoe4", &SearchFilters::default());
        assert_eq!(hits.len(), 1);
        assert!(hits[0].score > 0.0);
    }

    #[test]
    fn search_filters_by_status_and_entity() {
        let mut idx = empty_index();
        idx.entries.push(IndexEntry {
            kind: "finding".to_string(),
            frontier_id: "vfr_a".to_string(),
            frontier_name: "A".to_string(),
            text: "x".to_string(),
            status: Some("accepted".to_string()),
            entities: vec!["app".to_string()],
            source_id: None,
            target_id: "vf_1".to_string(),
            chain_status: "verified".to_string(),
        });
        idx.entries.push(IndexEntry {
            kind: "finding".to_string(),
            frontier_id: "vfr_a".to_string(),
            frontier_name: "A".to_string(),
            text: "x".to_string(),
            status: Some("retracted".to_string()),
            entities: vec!["app".to_string()],
            source_id: None,
            target_id: "vf_2".to_string(),
            chain_status: "verified".to_string(),
        });
        let hits = search(
            &idx,
            "",
            &SearchFilters {
                entity: Some("app".to_string()),
                status: Some("accepted".to_string()),
                ..Default::default()
            },
        );
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].entry.target_id, "vf_1");
    }

    #[test]
    fn search_limit_caps_results() {
        let mut idx = empty_index();
        for i in 0..5 {
            idx.entries.push(IndexEntry {
                kind: "finding".to_string(),
                frontier_id: "vfr_a".to_string(),
                frontier_name: "A".to_string(),
                text: format!("foo {i}"),
                status: None,
                entities: Vec::new(),
                source_id: None,
                target_id: format!("vf_{i}"),
                chain_status: "verified".to_string(),
            });
        }
        let hits = search(
            &idx,
            "foo",
            &SearchFilters {
                limit: Some(2),
                ..Default::default()
            },
        );
        assert_eq!(hits.len(), 2);
    }
}
