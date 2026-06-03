//! # vela-constellation
//!
//! The Vela Constellation layer: a network of connected Atlases
//! across scientific domains.
//!
//! ## What a Constellation is
//!
//! A Constellation (`vco_*`) is a **read-only composition** over
//! one or more Atlases (`vat_*`), each itself a composition over
//! Vela frontiers (`vfr_*`). The substrate stack:
//!
//! ```text
//! Frontier (vfr_*)        bounded reviewable state, unit of replay
//!     │
//!     │ composed into
//!     ▼
//! Atlas (vat_*)           living domain map, unit of reviewer-
//!                         confirmed bridges
//!     │
//!     │ networked into
//!     ▼
//! Constellation (vco_*)   cross-domain map, read-only over Atlas
//!                         snapshots
//! ```
//!
//! See `docs/MISSION_ATLAS.md`. The Carina v0.5 schema for the
//! Constellation primitive ships at
//! `examples/carina-kernel/schemas/constellation.schema.json`.
//!
//! ## What this crate ships at v0.81
//!
//! - `ConstellationManifest`: typed
//!   `constellations/<name>/manifest.yaml`.
//! - `ConstellationSnapshot`: the materialized cross-Atlas view.
//! - `init_constellation()`: scaffolds a new Constellation pointing
//!   at one or more Atlases by `vat_*` id.
//! - `materialize_constellation()`: reads each composing Atlas's
//!   snapshot.json, sums findings + events + bridges across, and
//!   computes a content-addressed composition hash.
//!
//! Constellation is read-only. Confirmed bridges live in Atlas;
//! a `cross_atlas_bridges[]` field on the manifest is
//! auto-populated by `materialize_constellation` for any
//! confirmed bridge whose two endpoint frontiers land in
//! different composing Atlases (v0.82.5).

use std::fs;
use std::path::{Path, PathBuf};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// `constellations/<name>/manifest.yaml` schema. Mirrors the
/// Carina v0.5 `Constellation` primitive.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConstellationManifest {
    /// Should equal `vela.constellation_manifest.v0.1`.
    pub schema: String,
    /// Constellation content-addressed id (`vco_*`).
    pub id: String,
    /// Human-readable Constellation name.
    pub name: String,
    /// Optional bounded-question text describing what cross-domain
    /// question this Constellation maps.
    #[serde(default)]
    pub scope_note: Option<String>,
    /// Composing Atlases (one or more).
    pub composing_atlases: Vec<ConstellationAtlasRef>,
    /// Cross-Atlas bridges (vbr_* ids) where the bridge's
    /// endpoints span findings in two different composing Atlases.
    #[serde(default)]
    pub cross_atlas_bridges: Vec<String>,
    /// Constellation maintainers.
    #[serde(default)]
    pub maintainers: Vec<ConstellationMaintainer>,
    /// RFC3339 timestamp.
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConstellationAtlasRef {
    /// Atlas content-addressed id (`vat_*`).
    pub vat_id: String,
    /// Human-readable Atlas name.
    pub name: String,
    /// File path to the Atlas's `manifest.yaml`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locator: Option<String>,
    /// Optional role (e.g. `core`, `partner-atlas`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConstellationMaintainer {
    pub actor_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
}

/// The materialized Constellation snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstellationSnapshot {
    pub schema: String,
    pub constellation_id: String,
    pub constellation_name: String,
    pub generated_at: String,
    pub atlas_count: usize,
    pub total_frontiers: usize,
    pub total_findings: usize,
    pub total_accepted_core: usize,
    pub total_events: usize,
    pub total_bridges: usize,
    pub cross_atlas_bridges: usize,
    pub atlases: Vec<ConstellationAtlasSummary>,
    pub composition_hash: String,
    /// v0.225: rolled-up substrate counts across composing
    /// Atlases (each Atlas already sums across its frontiers).
    #[serde(default)]
    pub released_diff_pack_count: usize,
    #[serde(default)]
    pub verdict_conflict_count: usize,
    #[serde(default)]
    pub pending_verdict_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstellationAtlasSummary {
    pub vat_id: String,
    pub name: String,
    pub frontiers: usize,
    pub findings: usize,
    pub accepted_core: usize,
    pub events: usize,
    pub bridges: usize,
    pub role: Option<String>,
}

/// Initialize a Constellation: scaffold
/// `constellations/<name>/manifest.yaml` pointing at one or more
/// existing Atlas dirs.
pub fn init_constellation(
    constellations_root: &Path,
    name: &str,
    scope_note: Option<&str>,
    atlas_dirs: &[PathBuf],
) -> Result<(PathBuf, ConstellationManifest), String> {
    if atlas_dirs.is_empty() {
        return Err("init_constellation: at least one Atlas dir is required".to_string());
    }
    let dir_name = sanitize_name(name);
    let dir = constellations_root.join(&dir_name);
    fs::create_dir_all(&dir)
        .map_err(|e| format!("create constellation dir {}: {e}", dir.display()))?;

    let mut composing = Vec::with_capacity(atlas_dirs.len());
    for ad in atlas_dirs {
        let manifest_path = ad.join("manifest.yaml");
        let yaml = fs::read_to_string(&manifest_path)
            .map_err(|e| format!("read atlas manifest {}: {e}", manifest_path.display()))?;
        let atlas_manifest: vela_atlas::AtlasManifest =
            serde_yaml::from_str(&yaml).map_err(|e| format!("parse atlas manifest: {e}"))?;
        composing.push(ConstellationAtlasRef {
            vat_id: atlas_manifest.id.clone(),
            name: atlas_manifest.name.clone(),
            locator: Some(format!("file://{}", manifest_path.display())),
            role: None,
        });
    }

    let id = constellation_id_from_manifest(name, &composing);
    let manifest = ConstellationManifest {
        schema: "vela.constellation_manifest.v0.1".to_string(),
        id,
        name: name.to_string(),
        scope_note: scope_note.map(String::from),
        composing_atlases: composing,
        cross_atlas_bridges: Vec::new(),
        maintainers: Vec::new(),
        created_at: Utc::now().to_rfc3339(),
    };
    let manifest_path = dir.join("manifest.yaml");
    let yaml = serde_yaml::to_string(&manifest).map_err(|e| format!("serialize manifest: {e}"))?;
    fs::write(&manifest_path, yaml).map_err(|e| format!("write manifest: {e}"))?;
    Ok((manifest_path, manifest))
}

/// Materialize a Constellation: read each composing Atlas's
/// `snapshot.json`, sum findings/events/bridges across, compute
/// content-addressed composition hash, write
/// `constellations/<name>/snapshot.json` and a static
/// `index.html`.
pub fn materialize_constellation(
    constellation_dir: &Path,
) -> Result<(PathBuf, ConstellationSnapshot), String> {
    let manifest_path = constellation_dir.join("manifest.yaml");
    let yaml = fs::read_to_string(&manifest_path)
        .map_err(|e| format!("read manifest {}: {e}", manifest_path.display()))?;
    let mut manifest: ConstellationManifest =
        serde_yaml::from_str(&yaml).map_err(|e| format!("parse manifest: {e}"))?;

    // v0.82.5: auto-discover cross-Atlas bridges. Walks each
    // composing Atlas's confirmed bridges and appends any whose
    // endpoint frontiers span Atlas boundaries to
    // `cross_atlas_bridges`. Manifest is re-written if any new
    // entries are added.
    let cross_added = sync_cross_atlas_bridges(&mut manifest)?;
    if cross_added > 0 {
        let yaml_out = serde_yaml::to_string(&manifest)
            .map_err(|e| format!("re-serialize manifest after cross-bridge sync: {e}"))?;
        fs::write(&manifest_path, yaml_out)
            .map_err(|e| format!("write manifest after cross-bridge sync: {e}"))?;
    }

    let mut atlas_summaries = Vec::with_capacity(manifest.composing_atlases.len());
    let mut total_frontiers = 0usize;
    let mut total_findings = 0usize;
    let mut total_accepted_core = 0usize;
    let mut total_events = 0usize;
    let mut total_bridges = 0usize;
    // v0.225: roll up the v0.213+ substrate counts.
    let mut released_diff_pack_count = 0usize;
    let mut verdict_conflict_count = 0usize;
    let mut pending_verdict_count = 0usize;
    for ar in &manifest.composing_atlases {
        let locator = ar
            .locator
            .as_deref()
            .ok_or_else(|| format!("atlas {} has no locator", ar.name))?;
        let manifest_path = locator
            .strip_prefix("file://")
            .map(PathBuf::from)
            .ok_or_else(|| format!("atlas locator must be a file:// URL, got '{locator}'"))?;
        let atlas_dir = manifest_path.parent().ok_or_else(|| {
            format!(
                "atlas manifest path has no parent: {}",
                manifest_path.display()
            )
        })?;

        // Materialize the Atlas (or read its existing snapshot).
        // For substrate honesty, re-materialize on demand so the
        // Constellation snapshot is always over fresh per-Atlas
        // data.
        let (_, atlas_snapshot) = vela_atlas::materialize_atlas(atlas_dir)
            .map_err(|e| format!("materialize atlas {}: {e}", atlas_dir.display()))?;

        total_frontiers += atlas_snapshot.frontier_count;
        total_findings += atlas_snapshot.total_findings;
        total_accepted_core += atlas_snapshot.accepted_core_findings;
        total_events += atlas_snapshot.total_events;
        total_bridges += atlas_snapshot.bridge_count;
        released_diff_pack_count += atlas_snapshot.released_diff_pack_count;
        verdict_conflict_count += atlas_snapshot.verdict_conflict_count;
        pending_verdict_count += atlas_snapshot.pending_verdict_count;

        atlas_summaries.push(ConstellationAtlasSummary {
            vat_id: atlas_snapshot.atlas_id,
            name: atlas_snapshot.atlas_name,
            frontiers: atlas_snapshot.frontier_count,
            findings: atlas_snapshot.total_findings,
            accepted_core: atlas_snapshot.accepted_core_findings,
            events: atlas_snapshot.total_events,
            bridges: atlas_snapshot.bridge_count,
            role: ar.role.clone(),
        });
    }

    let snapshot = ConstellationSnapshot {
        schema: "vela.constellation_snapshot.v0.1".to_string(),
        constellation_id: manifest.id.clone(),
        constellation_name: manifest.name.clone(),
        generated_at: Utc::now().to_rfc3339(),
        atlas_count: manifest.composing_atlases.len(),
        total_frontiers,
        total_findings,
        total_accepted_core,
        total_events,
        total_bridges,
        cross_atlas_bridges: manifest.cross_atlas_bridges.len(),
        atlases: atlas_summaries,
        composition_hash: composition_hash(&manifest),
        released_diff_pack_count,
        verdict_conflict_count,
        pending_verdict_count,
    };

    let snapshot_path = constellation_dir.join("snapshot.json");
    let json =
        serde_json::to_string_pretty(&snapshot).map_err(|e| format!("serialize snapshot: {e}"))?;
    fs::write(&snapshot_path, format!("{json}\n")).map_err(|e| format!("write snapshot: {e}"))?;

    let html = render_constellation_html(&manifest, &snapshot);
    fs::write(constellation_dir.join("index.html"), html)
        .map_err(|e| format!("write constellation index.html: {e}"))?;

    Ok((snapshot_path, snapshot))
}

/// Walks the bridges of every composing Atlas and identifies any
/// confirmed bridge whose two frontier endpoints land in *different*
/// composing Atlases. Such bridges are recorded in
/// `manifest.cross_atlas_bridges` (deduped). Returns the number of
/// newly added entries.
///
/// Substrate honesty: bridges remain Atlas-owned; this function only
/// reads them and records cross-Atlas pointers at the Constellation
/// layer. No bridge state is rewritten.
fn sync_cross_atlas_bridges(manifest: &mut ConstellationManifest) -> Result<usize, String> {
    use serde_json::Value;
    use std::collections::{HashMap, HashSet};

    // Build vfr_id -> vat_id map and collect each frontier's
    // candidate `.vela/bridges/` directory.
    let mut vfr_to_vat: HashMap<String, String> = HashMap::new();
    let mut bridge_dirs: Vec<PathBuf> = Vec::new();

    for ar in &manifest.composing_atlases {
        let Some(locator) = ar.locator.as_deref() else {
            continue;
        };
        let Some(atlas_manifest_path) = locator.strip_prefix("file://") else {
            continue;
        };
        let atlas_manifest_path = PathBuf::from(atlas_manifest_path);
        let yaml = match fs::read_to_string(&atlas_manifest_path) {
            Ok(y) => y,
            Err(_) => continue,
        };
        let atlas_manifest: vela_atlas::AtlasManifest = match serde_yaml::from_str(&yaml) {
            Ok(m) => m,
            Err(_) => continue,
        };
        let vat_id = atlas_manifest.id.clone();
        for fr in &atlas_manifest.composing_frontiers {
            vfr_to_vat
                .entry(fr.vfr_id.clone())
                .or_insert_with(|| vat_id.clone());
            // Resolve frontier locator to a candidate bridges dir.
            let Some(loc) = fr.locator.as_deref() else {
                continue;
            };
            let Some(frontier_path) = loc.strip_prefix("file://") else {
                continue;
            };
            let p = PathBuf::from(frontier_path);
            if p.is_dir() {
                bridge_dirs.push(p.join(".vela").join("bridges"));
            } else if let Some(parent) = p.parent() {
                bridge_dirs.push(parent.join(".vela").join("bridges"));
            }
        }
    }

    if vfr_to_vat.is_empty() {
        return Ok(0);
    }

    let already: HashSet<String> = manifest.cross_atlas_bridges.iter().cloned().collect();
    let mut seen_this_run: HashSet<String> = HashSet::new();
    let mut added = 0usize;

    // Dedup bridge dirs (multiple frontiers may share a parent).
    bridge_dirs.sort();
    bridge_dirs.dedup();

    for dir in &bridge_dirs {
        if !dir.is_dir() {
            continue;
        }
        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            let Ok(text) = fs::read_to_string(&path) else {
                continue;
            };
            let Ok(bridge): Result<Value, _> = serde_json::from_str(&text) else {
                continue;
            };
            let id = bridge
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            if id.is_empty() || already.contains(&id) || seen_this_run.contains(&id) {
                continue;
            }
            let status = bridge.get("status").and_then(Value::as_str).unwrap_or("");
            if !matches!(status, "confirmed" | "Confirmed") {
                continue;
            }
            let endpoints: Vec<String> = bridge
                .get("frontier_ids")
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            if endpoints.len() < 2 {
                continue;
            }
            // Map each endpoint to its vat_id; the bridge is
            // cross-Atlas iff at least two distinct vat_ids appear
            // and every endpoint resolves into the Constellation.
            let mats: Vec<&String> = endpoints.iter().filter_map(|e| vfr_to_vat.get(e)).collect();
            if mats.len() != endpoints.len() {
                // Some endpoint isn't in any composing Atlas; skip
                // (the bridge isn't fully inside this Constellation).
                continue;
            }
            let distinct: HashSet<&&String> = mats.iter().collect();
            if distinct.len() < 2 {
                continue;
            }
            seen_this_run.insert(id.clone());
            manifest.cross_atlas_bridges.push(id);
            added += 1;
        }
    }

    Ok(added)
}

fn composition_hash(manifest: &ConstellationManifest) -> String {
    let mut h = Sha256::new();
    h.update(manifest.id.as_bytes());
    h.update(b"|");
    for ar in &manifest.composing_atlases {
        h.update(ar.vat_id.as_bytes());
        h.update(b",");
    }
    h.update(b"|cross_bridges|");
    for vbr in &manifest.cross_atlas_bridges {
        h.update(vbr.as_bytes());
        h.update(b",");
    }
    format!("sha256:{}", hex::encode(h.finalize()))
}

fn constellation_id_from_manifest(name: &str, composing: &[ConstellationAtlasRef]) -> String {
    let mut h = Sha256::new();
    h.update(name.as_bytes());
    h.update(b"|");
    for ar in composing {
        h.update(ar.vat_id.as_bytes());
        h.update(b",");
    }
    let digest = h.finalize();
    let short = hex::encode(&digest[..8]);
    format!("vco_{short}")
}

fn sanitize_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect()
}

fn render_constellation_html(
    manifest: &ConstellationManifest,
    snapshot: &ConstellationSnapshot,
) -> String {
    let mut atlases_html = String::new();
    for a in &snapshot.atlases {
        let role = a.role.as_deref().unwrap_or("");
        let role_html = if role.is_empty() {
            String::new()
        } else {
            format!(" <span class=\"role\">{role}</span>")
        };
        atlases_html.push_str(&format!(
            "<li><strong>{name}</strong>{role_html}<br/><code>{vat}</code> · {frontiers} frontiers, {findings} findings ({accepted} accepted-core), {events} events, {bridges} bridges</li>",
            name = html_escape(&a.name),
            vat = html_escape(&a.vat_id),
            frontiers = a.frontiers,
            findings = a.findings,
            accepted = a.accepted_core,
            events = a.events,
            bridges = a.bridges,
        ));
    }
    let scope = match manifest.scope_note.as_deref() {
        Some(text) if !text.is_empty() => {
            format!("<p class=\"scope\">{}</p>", html_escape(text))
        }
        _ => String::new(),
    };
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{name} · Vela Constellation</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif; max-width: 760px; margin: 2rem auto; padding: 0 1.4rem; color: #222; line-height: 1.55; }}
  h1 {{ font-size: 1.4rem; margin: 0 0 0.4rem 0; }}
  h2 {{ font-size: 1.05rem; margin: 1.6rem 0 0.5rem 0; border-bottom: 1px solid #eee; padding-bottom: 0.2rem; }}
  .meta {{ color: #666; font-size: 0.92em; }}
  .scope {{ background: #f7f5f0; border-left: 3px solid #4a7c59; padding: 0.6rem 0.9rem; margin: 0.8rem 0; }}
  code {{ background: #f5f2ec; padding: 0.05em 0.35em; border-radius: 2px; font-size: 0.9em; }}
  ul {{ padding-left: 1.4rem; }}
  li {{ margin: 0.4rem 0; }}
  .role {{ color: #888; font-size: 0.85em; font-style: italic; }}
  table {{ border-collapse: collapse; margin: 0.6rem 0; }}
  td {{ padding: 0.2rem 0.8rem 0.2rem 0; vertical-align: top; }}
  td.k {{ color: #666; }}
  footer {{ margin-top: 2rem; color: #999; font-size: 0.85em; }}
</style>
</head>
<body>
<h1>{name}</h1>
<div class="meta">{vco}</div>
{scope}

<h2>Composition</h2>
<table>
<tr><td class="k">atlases</td><td>{atlases}</td></tr>
<tr><td class="k">total frontiers</td><td>{frontiers}</td></tr>
<tr><td class="k">total findings</td><td>{findings}</td></tr>
<tr><td class="k">accepted-core findings</td><td>{accepted}</td></tr>
<tr><td class="k">total events</td><td>{events}</td></tr>
<tr><td class="k">total bridges (manifest)</td><td>{bridges}</td></tr>
<tr><td class="k">cross-Atlas bridges</td><td>{cross}</td></tr>
<tr><td class="k">composition hash</td><td><code>{hash}</code></td></tr>
<tr><td class="k">generated at</td><td>{ts}</td></tr>
</table>

<h2>Composing Atlases</h2>
<ul>
{atlases_html}
</ul>

<footer>
Vela Constellation v0.81 · <a href="https://github.com/vela-science/vela">github.com/vela-science/vela</a>
</footer>
</body>
</html>
"#,
        name = html_escape(&manifest.name),
        vco = html_escape(&manifest.id),
        scope = scope,
        atlases = snapshot.atlas_count,
        frontiers = snapshot.total_frontiers,
        findings = snapshot.total_findings,
        accepted = snapshot.total_accepted_core,
        events = snapshot.total_events,
        bridges = snapshot.total_bridges,
        cross = snapshot.cross_atlas_bridges,
        hash = html_escape(&snapshot.composition_hash),
        ts = html_escape(&snapshot.generated_at),
        atlases_html = atlases_html,
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn constellation_id_is_content_addressed() {
        let composing = vec![
            ConstellationAtlasRef {
                vat_id: "vat_aaaa".to_string(),
                name: "a".to_string(),
                locator: None,
                role: None,
            },
            ConstellationAtlasRef {
                vat_id: "vat_bbbb".to_string(),
                name: "b".to_string(),
                locator: None,
                role: None,
            },
        ];
        let id1 = constellation_id_from_manifest("Demo", &composing);
        let id2 = constellation_id_from_manifest("Demo", &composing);
        assert_eq!(id1, id2);
        let id3 = constellation_id_from_manifest("Other", &composing);
        assert_ne!(id1, id3);
    }

    #[test]
    fn init_constellation_writes_manifest() {
        let dir = tempdir().expect("tempdir");
        let constellations = dir.path().join("constellations");

        // Build a fake Atlas dir with manifest.yaml so init can
        // load it.
        let atlas_dir = dir.path().join("atlas-a");
        fs::create_dir_all(&atlas_dir).unwrap();
        let atlas_manifest = vela_atlas::AtlasManifest {
            schema: "vela.atlas_manifest.v0.1".to_string(),
            id: "vat_test".to_string(),
            name: "Test Atlas".to_string(),
            domain: "demo".to_string(),
            scope_note: None,
            composing_frontiers: vec![],
            bridges: vec![],
            maintainers: vec![],
            review_policy_locator: None,
            created_at: Utc::now().to_rfc3339(),
        };
        let yaml = serde_yaml::to_string(&atlas_manifest).unwrap();
        fs::write(atlas_dir.join("manifest.yaml"), yaml).unwrap();

        let (manifest_path, manifest) = init_constellation(
            &constellations,
            "demo-constellation",
            Some("test scope"),
            &[atlas_dir],
        )
        .expect("init");

        assert!(manifest_path.is_file());
        assert!(manifest.id.starts_with("vco_"));
        assert_eq!(manifest.composing_atlases.len(), 1);
        assert_eq!(manifest.composing_atlases[0].vat_id, "vat_test");
    }
}
