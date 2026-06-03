//! # vela-atlas
//!
//! The Vela Atlas layer: a living, versioned map of a scientific
//! domain composed of one or more Vela frontiers.
//!
//! ## What an Atlas is
//!
//! An Atlas is a **read-only composition** over per-frontier event
//! logs. It carries:
//!
//! - Composition rules: which frontiers compose, what role each plays.
//! - Bridges: cross-frontier connections through shared entities.
//! - Persistent accepted-core: union of accepted findings across
//!   composing frontiers.
//! - Domain-level metadata: name, scope, maintainers, review policy.
//!
//! Frontier (`vfr_*`) stays the substrate-level unit of replay.
//! Atlas (`vat_*`) is the higher-level construct above it. See
//! `docs/MISSION_ATLAS.md` for the full doctrine.
//!
//! ## What this crate ships at v0.78
//!
//! - `AtlasManifest`: the typed representation of
//!   `atlases/<name>/manifest.yaml`.
//! - `Atlas`: the materialized snapshot.
//! - `materialize_atlas()`: reads composing frontiers, unions
//!   accepted-core findings, computes a snapshot hash, writes
//!   `atlases/<name>/snapshot.json`.
//! - `init_atlas()`: scaffolds a new Atlas with a manifest pointing
//!   at one or more existing frontiers.
//!
//! Federation, Atlas-level publish to crates.io / public hub, and
//! the Atlas-level Workbench surface are v0.79+.

use std::fs;
use std::path::{Path, PathBuf};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use vela_protocol::repo;

/// `atlases/<name>/manifest.yaml` schema. Mirrors the Carina v0.4
/// `Atlas` primitive (`docs/MISSION_ATLAS.md`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AtlasManifest {
    /// Should equal `vela.atlas_manifest.v0.1`.
    pub schema: String,
    /// Atlas content-addressed id (`vat_*`).
    pub id: String,
    /// Human-readable Atlas name.
    pub name: String,
    /// Scientific domain.
    pub domain: String,
    /// Optional bounded-question text.
    #[serde(default)]
    pub scope_note: Option<String>,
    /// Composing frontiers (one or more).
    pub composing_frontiers: Vec<AtlasFrontierRef>,
    /// Confirmed bridges by `vbr_*` id.
    #[serde(default)]
    pub bridges: Vec<String>,
    /// Atlas maintainers.
    #[serde(default)]
    pub maintainers: Vec<AtlasMaintainer>,
    /// Optional locator for the Atlas-level review policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_policy_locator: Option<String>,
    /// RFC3339 timestamp when the Atlas was first composed.
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AtlasFrontierRef {
    /// Frontier content-addressed id (`vfr_*`).
    pub vfr_id: String,
    /// Human-readable frontier name.
    pub name: String,
    /// File path or URL for the frontier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locator: Option<String>,
    /// Optional role within the Atlas.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AtlasMaintainer {
    pub actor_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
}

/// The materialized Atlas snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtlasSnapshot {
    pub schema: String,
    pub atlas_id: String,
    pub atlas_name: String,
    pub domain: String,
    pub generated_at: String,
    pub frontier_count: usize,
    pub total_findings: usize,
    pub accepted_core_findings: usize,
    pub total_events: usize,
    pub bridge_count: usize,
    /// v0.81.3: total pending proposals across composing
    /// frontiers (sum of `frontiers[i].pending_proposals`).
    /// The Atlas Workbench inbox is the cross-frontier view.
    #[serde(default)]
    pub pending_proposals_total: usize,
    /// Count of composing frontiers whose latest proof packet is
    /// marked current.
    #[serde(default)]
    pub proof_current_frontiers: usize,
    /// Count of composing frontiers whose latest proof packet is
    /// marked stale.
    #[serde(default)]
    pub stale_proof_frontiers: usize,
    /// Sum of human-reviewed finding coverage across composing
    /// frontiers.
    #[serde(default)]
    pub total_human_reviewed: usize,
    /// Sum of typed links across composing frontiers.
    #[serde(default)]
    pub total_links: usize,
    pub frontiers: Vec<AtlasFrontierSummary>,
    pub composition_hash: String,
    /// v0.81.3: most recent pending proposals across all
    /// composing frontiers, capped at 25 entries. Lets the
    /// Atlas Workbench page surface a real reviewer inbox.
    #[serde(default)]
    pub pending_proposals: Vec<AtlasPendingProposal>,
    /// v0.141: per-bridge details for the confirmed-bridge set.
    /// Mirrors `bridge_count` but carries the shape consumers
    /// need to render a useful overlap view: which bridge
    /// connects which composing frontiers via which shared
    /// entity name. Skipped when empty so pre-v0.141 snapshots
    /// remain byte-identical except for the always-changing
    /// `generated_at` timestamp.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bridges_detail: Vec<AtlasBridgeDetail>,
    /// v0.338: derived bridge candidates across composing
    /// frontiers. These are review leads only; unlike confirmed
    /// bridges, materialization must not promote them into the
    /// manifest's `bridges[]` set.
    #[serde(default)]
    pub bridge_candidate_count: usize,
    /// v0.338: compact derived-bridge details for the Atlas
    /// Workbench overview.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bridge_candidates_detail: Vec<AtlasBridgeCandidateDetail>,
    /// v0.225: count of released Diff Packs across composing
    /// frontiers (sum of each frontier's
    /// `Project.released_diff_packs.len()`). Reflects the v0.213
    /// canonical replay state; populated by the v0.221 load-time
    /// materializer. Zero on Atlases composed entirely of
    /// pre-v0.221 frontiers.
    #[serde(default)]
    pub released_diff_pack_count: usize,
    /// v0.225: count of resolved Verdict Conflicts (vdc_*) across
    /// composing frontiers. Zero on Atlases that have never
    /// surfaced reviewer disagreement on overlapping pack members.
    #[serde(default)]
    pub verdict_conflict_count: usize,
    /// v0.225: count of pending verdicts on disk under
    /// `.vela/pending_verdicts/` across composing frontiers.
    /// These are reviewer drafts awaiting promotion to a
    /// `diff_pack.reviewed` event. The Atlas Workbench can
    /// surface this as "verdicts in flight."
    #[serde(default)]
    pub pending_verdict_count: usize,
}

/// v0.141: per-bridge details for the Atlas snapshot's
/// confirmed-bridge set. The Atlas explorer renders this on
/// `/atlases/<slug>/bridges` so a visitor can see the
/// per-entity overlap, not just the count.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtlasBridgeDetail {
    /// `vbr_*` content-addressed bridge id.
    pub vbr_id: String,
    /// The shared entity name the bridge is anchored on.
    pub entity_name: String,
    /// Endpoint frontier ids (typically two; the bridge JSON
    /// schema admits more).
    pub frontier_ids: Vec<String>,
    /// Human-readable frontier names parallel to `frontier_ids`,
    /// resolved against the Atlas's composing frontiers.
    pub frontier_names: Vec<String>,
    /// Bridge status from the on-disk JSON (typically
    /// `confirmed` for entries that landed in this list).
    pub status: String,
}

/// v0.338: per-candidate bridge details for derived, not yet
/// reviewer-confirmed, cross-frontier bridges.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtlasBridgeCandidateDetail {
    /// `vbr_*` content-addressed bridge id.
    pub vbr_id: String,
    /// The shared entity name the bridge is anchored on.
    pub entity_name: String,
    /// Endpoint frontier ids.
    pub frontier_ids: Vec<String>,
    /// Human-readable frontier names parallel to `frontier_ids`.
    pub frontier_names: Vec<String>,
    /// Bridge status, expected to be `derived`.
    pub status: String,
    /// Number of finding refs captured on the bridge record.
    #[serde(default)]
    pub finding_refs: usize,
    /// Optional tension note from the bridge detector.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tension: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtlasFrontierSummary {
    pub vfr_id: String,
    pub name: String,
    pub findings: usize,
    pub accepted_core: usize,
    pub events: usize,
    /// Number of findings with human review coverage.
    #[serde(default)]
    pub human_reviewed: usize,
    /// Number of typed finding links.
    #[serde(default)]
    pub links: usize,
    /// Number of source records in the frontier source registry.
    #[serde(default)]
    pub sources: usize,
    /// Number of materialized source-grounded evidence atoms.
    #[serde(default)]
    pub evidence_atoms: usize,
    /// Number of materialized condition-boundary records.
    #[serde(default)]
    pub condition_records: usize,
    /// Latest proof packet status (`current`, `stale`, or
    /// `never_exported`).
    #[serde(default)]
    pub proof_status: String,
    /// Latest proof packet snapshot hash, when exported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_hash: Option<String>,
    /// Latest proof packet event-log hash, when exported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_log_hash: Option<String>,
    /// Declared cross-frontier dependencies pinned by this frontier.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub declared_dependencies: Vec<AtlasDependencySummary>,
    /// Decision-question summaries read from
    /// `decision/decision-brief.v1.json`, when present. This is a
    /// read-only projection so the Atlas page can show the questions
    /// a reviewer is actually trying to answer without reifying them
    /// as Atlas-level state.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub decision_questions: Vec<AtlasDecisionQuestionSummary>,
    /// v0.81.3: pending proposals on this frontier
    /// (`status: pending_review`).
    #[serde(default)]
    pub pending_proposals: usize,
    pub role: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtlasDecisionQuestionSummary {
    pub id: String,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<String>,
    #[serde(default)]
    pub supporting_findings: usize,
    #[serde(default)]
    pub tension_findings: usize,
    #[serde(default)]
    pub gap_findings: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtlasDependencySummary {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vfr_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pinned_snapshot_hash: Option<String>,
}

/// v0.81.3: one entry in the Atlas-level pending-review queue.
/// Carries enough info for a reviewer to decide whether to
/// open the proposal in the per-frontier Workbench.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtlasPendingProposal {
    pub vpr_id: String,
    pub frontier_name: String,
    pub vfr_id: String,
    pub kind: String,
    pub target_id: String,
    pub actor_id: String,
    /// First ~120 chars of the proposal's reason field.
    pub reason_preview: String,
}

/// Initialize an Atlas: scaffold `atlases/<name>/manifest.yaml`
/// pointing at one or more existing frontier paths.
///
/// `name` is the human-readable Atlas name (also used for the
/// directory). `domain` is the scientific domain string. Each
/// frontier in `frontier_paths` is loaded so the resulting manifest
/// carries its real `vfr_id`.
pub fn init_atlas(
    atlases_root: &Path,
    name: &str,
    domain: &str,
    scope_note: Option<&str>,
    frontier_paths: &[PathBuf],
) -> Result<(PathBuf, AtlasManifest), String> {
    if frontier_paths.is_empty() {
        return Err("init_atlas: at least one frontier path is required".to_string());
    }
    let dir_name = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>();
    let atlas_dir = atlases_root.join(&dir_name);
    fs::create_dir_all(&atlas_dir)
        .map_err(|e| format!("create atlas dir {}: {e}", atlas_dir.display()))?;

    let mut composing = Vec::with_capacity(frontier_paths.len());
    for fp in frontier_paths {
        let project =
            repo::load_from_path(fp).map_err(|e| format!("load frontier {}: {e}", fp.display()))?;
        composing.push(AtlasFrontierRef {
            vfr_id: project.frontier_id().to_string(),
            name: project.project.name.clone(),
            locator: Some(format!("file://{}", fp.display())),
            role: None,
        });
    }

    let id = atlas_id_from_manifest(name, domain, &composing);
    let manifest = AtlasManifest {
        schema: "vela.atlas_manifest.v0.1".to_string(),
        id,
        name: name.to_string(),
        domain: domain.to_string(),
        scope_note: scope_note.map(String::from),
        composing_frontiers: composing,
        bridges: Vec::new(),
        maintainers: Vec::new(),
        review_policy_locator: None,
        created_at: Utc::now().to_rfc3339(),
    };

    let manifest_path = atlas_dir.join("manifest.yaml");
    let yaml = serde_yaml::to_string(&manifest).map_err(|e| format!("serialize manifest: {e}"))?;
    fs::write(&manifest_path, yaml).map_err(|e| format!("write manifest: {e}"))?;

    Ok((manifest_path, manifest))
}

/// v0.81.2: Add or remove a frontier from an existing Atlas
/// without re-initializing. Re-computes the Atlas's
/// content-addressed id from the new composing-frontier list,
/// preserving everything else (name, domain, scope_note,
/// bridges, maintainers). Note: the atlas dir is NOT renamed,
/// even if the dir name was derived from `vat_*` originally.
///
/// Returns the updated manifest (with new id) and the path to
/// the manifest file. The Atlas's vat_id changes whenever the
/// composing-frontier set changes — this is correct
/// content-addressing behavior.
pub fn update_atlas(
    atlas_dir: &Path,
    add_frontiers: &[PathBuf],
    remove_vfr_ids: &[String],
) -> Result<(PathBuf, AtlasManifest), String> {
    let manifest_path = atlas_dir.join("manifest.yaml");
    let yaml = fs::read_to_string(&manifest_path)
        .map_err(|e| format!("read manifest {}: {e}", manifest_path.display()))?;
    let mut manifest: AtlasManifest =
        serde_yaml::from_str(&yaml).map_err(|e| format!("parse manifest: {e}"))?;

    // Apply removes first.
    if !remove_vfr_ids.is_empty() {
        let before = manifest.composing_frontiers.len();
        manifest
            .composing_frontiers
            .retain(|fr| !remove_vfr_ids.iter().any(|v| v == &fr.vfr_id));
        let removed = before - manifest.composing_frontiers.len();
        if removed != remove_vfr_ids.len() {
            return Err(format!(
                "update_atlas: requested removal of {} vfr_ids but only {} matched the Atlas's composing frontiers",
                remove_vfr_ids.len(),
                removed
            ));
        }
    }

    // Apply adds: load each new frontier and append.
    for fp in add_frontiers {
        let project =
            repo::load_from_path(fp).map_err(|e| format!("load frontier {}: {e}", fp.display()))?;
        let new_vfr = project.frontier_id().to_string();
        // Idempotency: skip if already present.
        if manifest
            .composing_frontiers
            .iter()
            .any(|fr| fr.vfr_id == new_vfr)
        {
            continue;
        }
        manifest.composing_frontiers.push(AtlasFrontierRef {
            vfr_id: new_vfr,
            name: project.project.name.clone(),
            locator: Some(format!("file://{}", fp.display())),
            role: None,
        });
    }

    if manifest.composing_frontiers.is_empty() {
        return Err(
            "update_atlas: result would have zero composing frontiers; refusing to leave Atlas empty"
                .to_string(),
        );
    }

    // Re-compute the Atlas id from the new composing-frontier list.
    manifest.id = atlas_id_from_manifest(
        &manifest.name,
        &manifest.domain,
        &manifest.composing_frontiers,
    );

    let new_yaml =
        serde_yaml::to_string(&manifest).map_err(|e| format!("serialize updated manifest: {e}"))?;
    fs::write(&manifest_path, new_yaml).map_err(|e| format!("write updated manifest: {e}"))?;
    Ok((manifest_path, manifest))
}

/// Materialize an Atlas: read each composing frontier, union
/// accepted-core findings, compute a composition hash, write
/// `atlases/<name>/snapshot.json`.
///
/// Read-only over per-frontier event logs. Does not mutate any
/// frontier state.
///
/// v0.79.3: Auto-syncs confirmed bridges from each composing
/// frontier's `.vela/bridges/<vbr_*>.json` into the manifest's
/// `bridges[]` field if both bridge endpoints are in the Atlas's
/// composing frontiers. Re-writes the manifest if new bridges are
/// added; otherwise leaves it untouched. The frontier-side bridge
/// records stay authoritative; the Atlas manifest is a derived
/// projection of the confirmed bridges that connect its frontiers.
pub fn materialize_atlas(atlas_dir: &Path) -> Result<(PathBuf, AtlasSnapshot), String> {
    let manifest_path = atlas_dir.join("manifest.yaml");
    let yaml = fs::read_to_string(&manifest_path)
        .map_err(|e| format!("read manifest {}: {e}", manifest_path.display()))?;
    let mut manifest: AtlasManifest =
        serde_yaml::from_str(&yaml).map_err(|e| format!("parse manifest: {e}"))?;

    // v0.79.3: auto-sync confirmed bridges from composing frontiers.
    // v0.141: also collect per-bridge detail for the snapshot.
    let (auto_synced, bridges_detail, bridge_candidates_detail) =
        sync_confirmed_bridges_with_detail(&mut manifest)?;
    if auto_synced > 0 {
        let new_yaml = serde_yaml::to_string(&manifest)
            .map_err(|e| format!("serialize updated manifest: {e}"))?;
        fs::write(&manifest_path, new_yaml)
            .map_err(|e| format!("write updated manifest {}: {e}", manifest_path.display()))?;
    }

    let mut summaries = Vec::with_capacity(manifest.composing_frontiers.len());
    let mut total_findings = 0usize;
    let mut accepted_core = 0usize;
    let mut total_events = 0usize;
    let mut pending_total = 0usize;
    let mut proof_current_frontiers = 0usize;
    let mut stale_proof_frontiers = 0usize;
    let mut total_human_reviewed = 0usize;
    let mut total_links = 0usize;
    let mut pending_proposals_global: Vec<AtlasPendingProposal> = Vec::new();
    // v0.225: roll up the v0.213-v0.220 substrate primitives.
    let mut released_diff_pack_count = 0usize;
    let mut verdict_conflict_count = 0usize;
    let mut pending_verdict_count = 0usize;
    for fr in &manifest.composing_frontiers {
        let locator = fr
            .locator
            .as_deref()
            .ok_or_else(|| format!("frontier {} has no locator", fr.name))?;
        let path = locator
            .strip_prefix("file://")
            .map(PathBuf::from)
            .ok_or_else(|| {
                format!("frontier locator must be a file:// URL today; got '{locator}'")
            })?;
        let project = repo::load_from_path(&path)
            .map_err(|e| format!("load frontier {}: {e}", path.display()))?;
        let findings = project.findings.len();
        // FindingBundle has no direct `status` field; accepted-core
        // is determined by walking finding.reviewed events and
        // taking the latest status per target. Build a per-finding
        // status map first, then count.
        let mut latest_status: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        for ev in &project.events {
            if ev.kind == "finding.reviewed"
                && let Some(status) = ev.payload.get("status").and_then(|v| v.as_str())
            {
                latest_status.insert(ev.target.id.clone(), status.to_string());
            }
        }
        let accepted = project
            .findings
            .iter()
            .filter(|f| {
                latest_status
                    .get(&f.id)
                    .map(|s| matches!(s.as_str(), "accepted" | "accepted_core"))
                    .unwrap_or(false)
            })
            .count();
        let events = project.events.len();
        total_findings += findings;
        accepted_core += accepted;
        total_events += events;
        total_human_reviewed += project.stats.human_reviewed;
        total_links += project.stats.links;

        let proof_state = &project.proof_state.latest_packet;
        let proof_status = proof_state.status.clone();
        match proof_status.as_str() {
            "current" => proof_current_frontiers += 1,
            "stale" => stale_proof_frontiers += 1,
            _ => {}
        }
        let snapshot_hash = non_empty_string(proof_state.snapshot_hash.clone());
        let event_log_hash = non_empty_string(proof_state.event_log_hash.clone());
        let declared_dependencies = project
            .project
            .dependencies
            .iter()
            .filter(|dep| dep.is_cross_frontier())
            .map(|dep| AtlasDependencySummary {
                name: dep.name.clone(),
                vfr_id: dep.vfr_id.clone(),
                pinned_snapshot_hash: dep.pinned_snapshot_hash.clone(),
            })
            .collect();
        let decision_questions = read_decision_questions(&path);

        // v0.81.3: count pending proposals + collect a sample.
        let mut pending_count = 0usize;
        for proposal in &project.proposals {
            if proposal.status == "pending_review" {
                pending_count += 1;
                let preview: String = proposal.reason.chars().take(120).collect();
                pending_proposals_global.push(AtlasPendingProposal {
                    vpr_id: proposal.id.clone(),
                    frontier_name: project.project.name.clone(),
                    vfr_id: project.frontier_id().to_string(),
                    kind: proposal.kind.clone(),
                    target_id: proposal.target.id.clone(),
                    actor_id: proposal.actor.id.clone(),
                    reason_preview: if preview.len() == proposal.reason.len() {
                        preview
                    } else {
                        format!("{preview}...")
                    },
                });
            }
        }
        pending_total += pending_count;

        // v0.225: roll up the v0.213+ substrate counts.
        released_diff_pack_count += project.released_diff_packs.len();
        verdict_conflict_count += project.verdict_conflicts.len();
        let pending_verdicts_dir = path.join(".vela").join("pending_verdicts");
        if let Ok(entries) = std::fs::read_dir(&pending_verdicts_dir) {
            for e in entries.flatten() {
                let p = e.path();
                if p.extension().and_then(|s| s.to_str()) == Some("json") {
                    pending_verdict_count += 1;
                }
            }
        }

        summaries.push(AtlasFrontierSummary {
            vfr_id: project.frontier_id().to_string(),
            name: project.project.name.clone(),
            findings,
            accepted_core: accepted,
            events,
            human_reviewed: project.stats.human_reviewed,
            links: project.stats.links,
            sources: project.stats.source_count,
            evidence_atoms: project.stats.evidence_atom_count,
            condition_records: project.stats.condition_record_count,
            proof_status,
            snapshot_hash,
            event_log_hash,
            declared_dependencies,
            decision_questions,
            pending_proposals: pending_count,
            role: fr.role.clone(),
        });
    }
    // Cap at 25 proposals total for the Atlas-level inbox.
    pending_proposals_global.truncate(25);

    let snapshot = AtlasSnapshot {
        schema: "vela.atlas_snapshot.v0.1".to_string(),
        atlas_id: manifest.id.clone(),
        atlas_name: manifest.name.clone(),
        domain: manifest.domain.clone(),
        generated_at: Utc::now().to_rfc3339(),
        frontier_count: manifest.composing_frontiers.len(),
        total_findings,
        accepted_core_findings: accepted_core,
        total_events,
        bridge_count: manifest.bridges.len(),
        pending_proposals_total: pending_total,
        proof_current_frontiers,
        stale_proof_frontiers,
        total_human_reviewed,
        total_links,
        frontiers: summaries,
        composition_hash: composition_hash(&manifest),
        pending_proposals: pending_proposals_global,
        bridges_detail,
        bridge_candidate_count: bridge_candidates_detail.len(),
        bridge_candidates_detail,
        released_diff_pack_count,
        verdict_conflict_count,
        pending_verdict_count,
    };

    let snapshot_path = atlas_dir.join("snapshot.json");
    let json =
        serde_json::to_string_pretty(&snapshot).map_err(|e| format!("serialize snapshot: {e}"))?;
    fs::write(&snapshot_path, format!("{json}\n")).map_err(|e| format!("write snapshot: {e}"))?;

    // v0.79.2: Atlas-level Workbench surface. Emit a static
    // `index.html` alongside `snapshot.json` showing Atlas metadata,
    // composing frontiers (clickable), confirmed bridges, and
    // composition hash. Users open the file directly or `vela atlas
    // serve` reads it.
    let html_path = atlas_dir.join("index.html");
    let html = render_atlas_html(&manifest, &snapshot);
    fs::write(&html_path, html).map_err(|e| format!("write atlas index.html: {e}"))?;

    Ok((snapshot_path, snapshot))
}

/// v0.79.2: render a static HTML overview of an Atlas. No
/// JavaScript, no external dependencies; this is a snapshot
/// document the reviewer opens locally. The dynamic Atlas
/// Workbench (server-rendered, with per-frontier inboxes
/// surfaced inline) is a v0.80+ surface.
fn render_atlas_html(manifest: &AtlasManifest, snapshot: &AtlasSnapshot) -> String {
    let mut frontiers_html = String::new();
    for fr in &snapshot.frontiers {
        let role = fr.role.as_deref().unwrap_or("");
        let role_html = if role.is_empty() {
            String::new()
        } else {
            format!(" <span class=\"role\">{role}</span>")
        };
        let pending_html = if fr.pending_proposals > 0 {
            format!(", <strong>{} pending</strong>", fr.pending_proposals)
        } else {
            String::new()
        };
        let proof_status = if fr.proof_status.is_empty() {
            "never_exported"
        } else {
            fr.proof_status.as_str()
        };
        let snapshot_html = fr
            .snapshot_hash
            .as_deref()
            .map(|hash| {
                format!(
                    "<br/><span class=\"meta\">snapshot <code>{}</code></span>",
                    html_escape(hash)
                )
            })
            .unwrap_or_default();
        let dependencies_html = if fr.declared_dependencies.is_empty() {
            String::new()
        } else {
            let deps = fr
                .declared_dependencies
                .iter()
                .map(|dep| {
                    let vfr = dep.vfr_id.as_deref().unwrap_or("unresolved");
                    let pin = dep
                        .pinned_snapshot_hash
                        .as_deref()
                        .map(|hash| format!(" pinned <code>{}</code>", html_escape(hash)))
                        .unwrap_or_default();
                    format!(
                        "<span class=\"dep\">{} <code>{}</code>{}</span>",
                        html_escape(&dep.name),
                        html_escape(vfr),
                        pin
                    )
                })
                .collect::<Vec<_>>()
                .join("<br/>");
            format!("<br/><span class=\"meta\">dependencies</span><br/>{deps}")
        };
        frontiers_html.push_str(&format!(
            "<li><strong>{name}</strong>{role_html}<br/><code>{vfr_id}</code> · proof <code>{proof_status}</code> · {findings} findings, {accepted_core} accepted-core, {human_reviewed} human-reviewed, {events} events, {links} links, {sources} sources, {evidence_atoms} evidence atoms, {condition_records} conditions{pending_html}{snapshot_html}{dependencies_html}</li>",
            name = html_escape(&fr.name),
            vfr_id = html_escape(&fr.vfr_id),
            proof_status = html_escape(proof_status),
            findings = fr.findings,
            accepted_core = fr.accepted_core,
            human_reviewed = fr.human_reviewed,
            events = fr.events,
            links = fr.links,
            sources = fr.sources,
            evidence_atoms = fr.evidence_atoms,
            condition_records = fr.condition_records,
        ));
    }
    // v0.81.3: pending-review queue across all composing
    // frontiers. Caps at 25 entries (set by materialize_atlas).
    let pending_html = if snapshot.pending_proposals.is_empty() {
        "<em>No pending proposals across composing frontiers.</em>".to_string()
    } else {
        let mut s = format!(
            "<p>{count} pending proposals across composing frontiers (showing up to 25):</p><ul>",
            count = snapshot.pending_proposals_total
        );
        for p in &snapshot.pending_proposals {
            s.push_str(&format!(
                "<li><code>{vpr}</code> on <strong>{frontier}</strong> ({kind} → {target}, by <code>{actor}</code>)<br/><span class=\"reason\">{reason}</span></li>",
                vpr = html_escape(&p.vpr_id),
                frontier = html_escape(&p.frontier_name),
                kind = html_escape(&p.kind),
                target = html_escape(&p.target_id),
                actor = html_escape(&p.actor_id),
                reason = html_escape(&p.reason_preview),
            ));
        }
        s.push_str("</ul>");
        s
    };
    let bridges_html = if manifest.bridges.is_empty() {
        "<em>No bridges declared in manifest. Run <code>vela bridges derive &lt;a&gt; &lt;b&gt;</code> + <code>vela bridges confirm</code> to populate.</em>".to_string()
    } else {
        let mut s = String::new();
        for vbr in &manifest.bridges {
            s.push_str(&format!("<li><code>{}</code></li>", html_escape(vbr)));
        }
        format!("<ul>{s}</ul>")
    };
    let candidate_bridges_html = render_candidate_bridges_html(snapshot);
    let decision_questions_html = render_decision_questions_html(snapshot);
    let scope_note_html = match manifest.scope_note.as_deref() {
        Some(text) if !text.is_empty() => {
            format!("<p class=\"scope\">{}</p>", html_escape(text))
        }
        _ => String::new(),
    };
    let maintainers_html = if manifest.maintainers.is_empty() {
        String::new()
    } else {
        let mut s = String::new();
        for m in &manifest.maintainers {
            let role = match m.role.as_deref() {
                Some(r) if !r.is_empty() => format!(" ({r})"),
                _ => String::new(),
            };
            s.push_str(&format!(
                "<li><code>{}</code>{role}</li>",
                html_escape(&m.actor_id)
            ));
        }
        format!("<h2>Maintainers</h2><ul>{s}</ul>")
    };

    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{name} · Vela Atlas</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif; max-width: 760px; margin: 2rem auto; padding: 0 1.4rem; color: #222; line-height: 1.55; }}
  h1 {{ font-size: 1.4rem; margin: 0 0 0.4rem 0; }}
  h2 {{ font-size: 1.05rem; margin: 1.6rem 0 0.5rem 0; border-bottom: 1px solid #eee; padding-bottom: 0.2rem; }}
  .meta {{ color: #666; font-size: 0.92em; }}
  .scope {{ background: #f7f5f0; border-left: 3px solid #c9a227; padding: 0.6rem 0.9rem; margin: 0.8rem 0; }}
  code {{ background: #f5f2ec; padding: 0.05em 0.35em; border-radius: 2px; font-size: 0.9em; }}
  ul {{ padding-left: 1.4rem; }}
  li {{ margin: 0.4rem 0; }}
  .role {{ color: #888; font-size: 0.85em; font-style: italic; }}
  .reason {{ color: #555; font-size: 0.9em; }}
  .dep {{ display: inline-block; margin: 0.1rem 0 0 0.7rem; }}
  table {{ border-collapse: collapse; margin: 0.6rem 0; }}
  td {{ padding: 0.2rem 0.8rem 0.2rem 0; vertical-align: top; }}
  td.k {{ color: #666; }}
  footer {{ margin-top: 2rem; color: #999; font-size: 0.85em; }}
</style>
</head>
<body>
<h1>{name}</h1>
<div class="meta">{atlas_id} · domain <code>{domain}</code></div>
{scope_note_html}

<h2>Composition</h2>
<table>
<tr><td class="k">frontiers</td><td>{frontier_count}</td></tr>
<tr><td class="k">total findings</td><td>{total_findings}</td></tr>
<tr><td class="k">accepted-core findings</td><td>{accepted_core}</td></tr>
<tr><td class="k">total events</td><td>{total_events}</td></tr>
<tr><td class="k">proof current</td><td>{proof_current_frontiers}</td></tr>
<tr><td class="k">stale proof</td><td>{stale_proof_frontiers}</td></tr>
<tr><td class="k">human-reviewed findings</td><td>{total_human_reviewed}</td></tr>
<tr><td class="k">typed links</td><td>{total_links}</td></tr>
<tr><td class="k">bridges (manifest)</td><td>{bridge_count}</td></tr>
<tr><td class="k">composition hash</td><td><code>{composition_hash}</code></td></tr>
<tr><td class="k">generated at</td><td>{generated_at}</td></tr>
</table>

<h2>Composing frontiers</h2>
<ul>
{frontiers_html}
</ul>

<h2>Decision questions</h2>
{decision_questions_html}

<h2>Pending review queue</h2>
{pending_html}

<h2>Bridges</h2>
{bridges_html}

<h2>Candidate bridge review</h2>
{candidate_bridges_html}

{maintainers_html}

<h2>Reproduce</h2>
<p>This page was generated by <code>vela atlas materialize {atlas_short}</code>.
The Atlas is a read-only composition over per-frontier event logs.
Replay determinism stays per-frontier; this page is a snapshot
document, not a writable surface.</p>

<footer>
Vela Atlas v0.79 · <a href="https://github.com/vela-science/vela">github.com/vela-science/vela</a>
</footer>
</body>
</html>
"#,
        name = html_escape(&manifest.name),
        atlas_id = html_escape(&manifest.id),
        domain = html_escape(&manifest.domain),
        scope_note_html = scope_note_html,
        frontier_count = snapshot.frontier_count,
        total_findings = snapshot.total_findings,
        accepted_core = snapshot.accepted_core_findings,
        total_events = snapshot.total_events,
        proof_current_frontiers = snapshot.proof_current_frontiers,
        stale_proof_frontiers = snapshot.stale_proof_frontiers,
        total_human_reviewed = snapshot.total_human_reviewed,
        total_links = snapshot.total_links,
        bridge_count = snapshot.bridge_count,
        composition_hash = html_escape(&snapshot.composition_hash),
        generated_at = html_escape(&snapshot.generated_at),
        frontiers_html = frontiers_html,
        decision_questions_html = decision_questions_html,
        bridges_html = bridges_html,
        candidate_bridges_html = candidate_bridges_html,
        maintainers_html = maintainers_html,
        atlas_short = html_escape(&snapshot.atlas_name),
        pending_html = pending_html,
    )
}

fn render_decision_questions_html(snapshot: &AtlasSnapshot) -> String {
    let total = snapshot
        .frontiers
        .iter()
        .map(|fr| fr.decision_questions.len())
        .sum::<usize>();
    if total == 0 {
        return "<em>No decision briefs found in composing frontiers.</em>".to_string();
    }

    let mut body = format!("<p>{total} decision questions across composing frontiers.</p>");
    for fr in &snapshot.frontiers {
        if fr.decision_questions.is_empty() {
            continue;
        }
        body.push_str(&format!("<h3>{}</h3><ul>", html_escape(&fr.name)));
        for question in &fr.decision_questions {
            let confidence = question
                .confidence
                .as_deref()
                .filter(|value| !value.is_empty())
                .map(|value| format!(" · <span class=\"meta\">{}</span>", html_escape(value)))
                .unwrap_or_default();
            body.push_str(&format!(
                "<li><code>{id}</code> {title}{confidence}<br/><span class=\"meta\">support {supporting}; tensions {tensions}; gaps {gaps}</span></li>",
                id = html_escape(&question.id),
                title = html_escape(&question.title),
                confidence = confidence,
                supporting = question.supporting_findings,
                tensions = question.tension_findings,
                gaps = question.gap_findings,
            ));
        }
        body.push_str("</ul>");
    }
    body
}

fn render_candidate_bridges_html(snapshot: &AtlasSnapshot) -> String {
    if snapshot.bridge_candidates_detail.is_empty() {
        return "<em>No derived bridge candidates across composing frontiers.</em>".to_string();
    }

    let mut body = format!(
        "<p>{} derived bridge candidates awaiting review. These are not confirmed bridges.</p><ul>",
        snapshot.bridge_candidate_count
    );
    for bridge in &snapshot.bridge_candidates_detail {
        let frontier_names = if bridge.frontier_names.is_empty() {
            "unresolved frontiers".to_string()
        } else {
            bridge
                .frontier_names
                .iter()
                .map(|name| html_escape(name))
                .collect::<Vec<_>>()
                .join(" <-> ")
        };
        let tension = bridge
            .tension
            .as_deref()
            .filter(|value| !value.is_empty())
            .map(|value| {
                format!(
                    "<br/><span class=\"meta\">tension {}</span>",
                    html_escape(value)
                )
            })
            .unwrap_or_default();
        body.push_str(&format!(
            "<li><code>{id}</code> <strong>{entity}</strong><br/><span class=\"meta\">{frontiers} · {refs} finding refs · status <code>{status}</code></span>{tension}</li>",
            id = html_escape(&bridge.vbr_id),
            entity = html_escape(&bridge.entity_name),
            frontiers = frontier_names,
            refs = bridge.finding_refs,
            status = html_escape(&bridge.status),
            tension = tension,
        ));
    }
    body.push_str("</ul>");
    body
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn non_empty_string(value: Option<String>) -> Option<String> {
    value.filter(|s| !s.is_empty())
}

fn read_decision_questions(frontier_path: &Path) -> Vec<AtlasDecisionQuestionSummary> {
    let path = frontier_path
        .join("decision")
        .join("decision-brief.v1.json");
    let Ok(body) = fs::read_to_string(&path) else {
        return Vec::new();
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&body) else {
        return Vec::new();
    };
    let Some(questions) = value.get("questions").and_then(|v| v.as_array()) else {
        return Vec::new();
    };

    questions
        .iter()
        .filter_map(|question| {
            let id = question.get("id").and_then(|v| v.as_str())?;
            let title = question
                .get("title")
                .and_then(|v| v.as_str())
                .or_else(|| question.get("question").and_then(|v| v.as_str()))
                .unwrap_or(id);
            Some(AtlasDecisionQuestionSummary {
                id: id.to_string(),
                title: title.to_string(),
                confidence: question
                    .get("confidence")
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
                supporting_findings: array_len(question, "supporting_findings"),
                tension_findings: array_len(question, "tension_findings"),
                gap_findings: array_len(question, "gap_findings"),
            })
        })
        .collect()
}

fn array_len(value: &serde_json::Value, key: &str) -> usize {
    value
        .get(key)
        .and_then(|v| v.as_array())
        .map(|items| items.len())
        .unwrap_or(0)
}

/// v0.79.3: scan each composing frontier's `.vela/bridges/` and
/// add confirmed bridges whose endpoints are both in the Atlas's
/// composing-frontier set. Returns the count of newly added
/// bridges. Idempotent: re-running with no new confirmations is a
/// no-op. Bridge ids that are already in `manifest.bridges` are
/// skipped.
/// v0.141: same surface as `sync_confirmed_bridges` (auto-adds
/// confirmed bridge ids to `manifest.bridges`) but additionally
/// returns a `Vec<AtlasBridgeDetail>` covering every confirmed
/// bridge in the manifest after the sync — including ones that
/// were already present pre-sync. The detail vector is what the
/// snapshot's `bridges_detail` field uses to render the per-
/// bridge overlap view in the Atlas explorer.
fn sync_confirmed_bridges_with_detail(
    manifest: &mut AtlasManifest,
) -> Result<
    (
        usize,
        Vec<AtlasBridgeDetail>,
        Vec<AtlasBridgeCandidateDetail>,
    ),
    String,
> {
    use serde_json::Value;

    // Build the set of vfr_ids the Atlas composes + the name map
    // so per-bridge details can resolve human-readable frontier
    // names.
    let atlas_vfrs: std::collections::HashSet<String> = manifest
        .composing_frontiers
        .iter()
        .map(|f| f.vfr_id.clone())
        .collect();
    let name_by_vfr: std::collections::HashMap<String, String> = manifest
        .composing_frontiers
        .iter()
        .map(|f| (f.vfr_id.clone(), f.name.clone()))
        .collect();

    let mut added = 0usize;
    let already: std::collections::HashSet<String> = manifest.bridges.iter().cloned().collect();
    let mut detail_by_id: std::collections::HashMap<String, AtlasBridgeDetail> =
        std::collections::HashMap::new();
    let mut candidate_by_id: std::collections::HashMap<String, AtlasBridgeCandidateDetail> =
        std::collections::HashMap::new();

    for fr in &manifest.composing_frontiers {
        let Some(locator) = fr.locator.as_deref() else {
            continue;
        };
        let Some(frontier_path) = locator.strip_prefix("file://") else {
            continue;
        };
        let bridges_dir = std::path::Path::new(frontier_path)
            .parent()
            .map(|p| p.join(".vela").join("bridges"))
            .unwrap_or_else(|| std::path::PathBuf::from(format!("{frontier_path}/.vela/bridges")));
        if !bridges_dir.is_dir() {
            // v0.78 layout: split-repo frontier with .vela/ at the
            // frontier directory. Try the alternate.
            let alt = std::path::Path::new(frontier_path)
                .join(".vela")
                .join("bridges");
            if !alt.is_dir() {
                continue;
            }
        }
        // Re-derive the bridges directory more robustly: support
        // both "file:///path/to/repo" (split-repo) and
        // "file:///path/to/frontier.json" (monolithic) shapes.
        let p = std::path::PathBuf::from(frontier_path);
        let candidate_dirs: Vec<std::path::PathBuf> = if p.is_dir() {
            vec![p.join(".vela").join("bridges")]
        } else if let Some(parent) = p.parent() {
            vec![parent.join(".vela").join("bridges")]
        } else {
            Vec::new()
        };

        for dir in candidate_dirs {
            if !dir.is_dir() {
                continue;
            }
            let entries = match std::fs::read_dir(&dir) {
                Ok(e) => e,
                Err(_) => continue,
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) != Some("json") {
                    continue;
                }
                let Ok(text) = std::fs::read_to_string(&path) else {
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
                if id.is_empty() {
                    continue;
                }
                let status = bridge.get("status").and_then(Value::as_str).unwrap_or("");
                let confirmed = matches!(status, "confirmed" | "Confirmed");
                let derived = matches!(status, "derived" | "Derived");
                if !confirmed && !derived {
                    continue;
                }
                // Both endpoints must be in the Atlas's composing
                // frontier vfr_ids. The bridge stores frontier_ids
                // as Vec<String>.
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
                if endpoints.is_empty() {
                    continue;
                }
                let all_in_atlas = endpoints.iter().all(|e| atlas_vfrs.contains(e));
                if !all_in_atlas {
                    continue;
                }
                let entity_name = bridge
                    .get("entity_name")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let frontier_names = endpoints
                    .iter()
                    .map(|vfr| name_by_vfr.get(vfr).cloned().unwrap_or_else(|| vfr.clone()))
                    .collect::<Vec<_>>();
                if confirmed {
                    let detail = AtlasBridgeDetail {
                        vbr_id: id.clone(),
                        entity_name,
                        frontier_ids: endpoints,
                        frontier_names,
                        status: status.to_string(),
                    };
                    detail_by_id.entry(id.clone()).or_insert(detail);
                    if !already.contains(&id) && !manifest.bridges.contains(&id) {
                        manifest.bridges.push(id);
                        added += 1;
                    }
                } else {
                    let finding_refs = bridge
                        .get("finding_refs")
                        .and_then(Value::as_array)
                        .map(|refs| refs.len())
                        .unwrap_or(0);
                    let tension = bridge
                        .get("tension")
                        .and_then(Value::as_str)
                        .map(str::to_string);
                    let candidate = AtlasBridgeCandidateDetail {
                        vbr_id: id.clone(),
                        entity_name,
                        frontier_ids: endpoints,
                        frontier_names,
                        status: status.to_string(),
                        finding_refs,
                        tension,
                    };
                    candidate_by_id.entry(id).or_insert(candidate);
                }
            }
        }
    }
    // Stable order: alphabetical by vbr_id so snapshot bytes are
    // deterministic across runs.
    let mut details: Vec<AtlasBridgeDetail> = detail_by_id.into_values().collect();
    details.sort_by(|a, b| a.vbr_id.cmp(&b.vbr_id));
    let mut candidates: Vec<AtlasBridgeCandidateDetail> = candidate_by_id.into_values().collect();
    candidates.sort_by(|a, b| {
        a.entity_name
            .cmp(&b.entity_name)
            .then(a.vbr_id.cmp(&b.vbr_id))
    });
    Ok((added, details, candidates))
}

/// Compute a content-addressed hash over the manifest's composing
/// frontier ids + bridges; this is what makes the Atlas composition
/// itself replay-verifiable.
fn composition_hash(manifest: &AtlasManifest) -> String {
    let mut h = Sha256::new();
    h.update(manifest.id.as_bytes());
    h.update(b"|");
    for fr in &manifest.composing_frontiers {
        h.update(fr.vfr_id.as_bytes());
        h.update(b",");
    }
    h.update(b"|bridges|");
    for vbr in &manifest.bridges {
        h.update(vbr.as_bytes());
        h.update(b",");
    }
    format!("sha256:{}", hex::encode(h.finalize()))
}

/// Derive a stable Atlas id from name + domain + composing frontier
/// ids. Ensures `vela atlas init` is content-addressed; running it
/// twice on the same composition produces the same id.
fn atlas_id_from_manifest(name: &str, domain: &str, composing: &[AtlasFrontierRef]) -> String {
    let mut h = Sha256::new();
    h.update(name.as_bytes());
    h.update(b"|");
    h.update(domain.as_bytes());
    h.update(b"|");
    for fr in composing {
        h.update(fr.vfr_id.as_bytes());
        h.update(b",");
    }
    let digest = h.finalize();
    let short = hex::encode(&digest[..8]);
    format!("vat_{short}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use vela_protocol::project;

    fn make_frontier(path: &Path, name: &str) {
        let frontier = project::assemble(name, vec![], 0, 0, "atlas-test fixture");
        repo::save_to_path(path, &frontier).expect("save frontier");
    }

    #[test]
    fn init_atlas_writes_manifest_with_real_frontier_ids() {
        let dir = tempdir().expect("tempdir");
        let frontier_a = dir.path().join("frontier-a.json");
        let frontier_b = dir.path().join("frontier-b.json");
        make_frontier(&frontier_a, "alpha frontier");
        make_frontier(&frontier_b, "beta frontier");
        let atlases = dir.path().join("atlases");

        let (manifest_path, manifest) = init_atlas(
            &atlases,
            "demo-atlas",
            "oncology",
            Some("test scope"),
            &[frontier_a.clone(), frontier_b.clone()],
        )
        .expect("init atlas");

        assert!(manifest_path.is_file());
        assert_eq!(manifest.composing_frontiers.len(), 2);
        assert!(manifest.id.starts_with("vat_"));
        assert_eq!(manifest.domain, "oncology");
        assert_eq!(manifest.scope_note.as_deref(), Some("test scope"));
        // Each frontier ref carries the real vfr_id from the loaded frontier.
        for fr in &manifest.composing_frontiers {
            assert!(fr.vfr_id.starts_with("vfr_"), "got {}", fr.vfr_id);
            assert!(fr.locator.is_some());
        }
    }

    #[test]
    fn materialize_atlas_writes_snapshot_with_finding_counts() {
        let dir = tempdir().expect("tempdir");
        let frontier_a = dir.path().join("frontier-a.json");
        let frontier_b = dir.path().join("frontier-b.json");
        make_frontier(&frontier_a, "alpha frontier");
        make_frontier(&frontier_b, "beta frontier");
        let atlases = dir.path().join("atlases");

        let (_manifest_path, _manifest) = init_atlas(
            &atlases,
            "demo-atlas",
            "oncology",
            None,
            &[frontier_a.clone(), frontier_b.clone()],
        )
        .expect("init atlas");

        let atlas_dir = atlases.join("demo-atlas");
        let (snapshot_path, snapshot) = materialize_atlas(&atlas_dir).expect("materialize atlas");
        assert!(snapshot_path.is_file());
        assert_eq!(snapshot.frontier_count, 2);
        assert_eq!(snapshot.frontiers.len(), 2);
        assert_eq!(snapshot.proof_current_frontiers, 0);
        assert_eq!(snapshot.stale_proof_frontiers, 0);
        assert_eq!(snapshot.total_human_reviewed, 0);
        assert_eq!(snapshot.total_links, 0);
        assert!(
            snapshot
                .frontiers
                .iter()
                .all(|fr| fr.proof_status == "never_exported")
        );
        assert!(snapshot.composition_hash.starts_with("sha256:"));
    }

    #[test]
    fn atlas_id_is_content_addressed_stable() {
        // Same name + domain + frontier vfr_id list yields same id.
        let composing = vec![
            AtlasFrontierRef {
                vfr_id: "vfr_aaaa".to_string(),
                name: "a".to_string(),
                locator: None,
                role: None,
            },
            AtlasFrontierRef {
                vfr_id: "vfr_bbbb".to_string(),
                name: "b".to_string(),
                locator: None,
                role: None,
            },
        ];
        let id1 = atlas_id_from_manifest("Demo", "x", &composing);
        let id2 = atlas_id_from_manifest("Demo", "x", &composing);
        assert_eq!(id1, id2);
        let id3 = atlas_id_from_manifest("Other", "x", &composing);
        assert_ne!(id1, id3);
    }
}
