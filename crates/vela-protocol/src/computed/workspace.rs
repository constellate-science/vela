//! Workspace registry: a content-light index of the frontiers a producer
//! (or the conformance gate) has checked out, plus the hub remote each one
//! tracks. This is the git-style "list of working copies" that turns the hub
//! into a discoverable remote — `vela workspace add` records a checkout, and
//! the gate reads this index instead of a hardcoded frontier list.
//!
//! It is DISTINCT from the per-frontier `.vela/workspaces/` task-state
//! directory: that is execution scratch inside ONE frontier; this is a
//! cross-frontier index. The default location is user-level
//! (`~/.vela/workspace.json`), parallel to the registry at
//! `~/.vela/registry/entries.json`; the gate keeps a repo-committed copy at
//! `scripts/workspace.json`.

use std::path::Path;

use serde::{Deserialize, Serialize};

pub const WORKSPACE_SCHEMA: &str = "vela.workspace.v0.1";

/// One checked-out frontier and the hub remote it tracks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceFrontier {
    /// Path to the frontier (relative to the workspace file's repo, or
    /// absolute). The natural key together with `vfr_id`.
    pub path: String,
    /// The frontier's content-addressed id (`vfr_…`), if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vfr_id: Option<String>,
    /// The hub this frontier pushes to / pulls from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote: Option<String>,
    /// Human-friendly name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// When this entry was added (RFC3339); provenance only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub added_at: Option<String>,
}

/// The workspace index: a list of checked-out frontiers + remotes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceRegistry {
    pub schema: String,
    #[serde(default)]
    pub frontiers: Vec<WorkspaceFrontier>,
}

impl Default for WorkspaceRegistry {
    fn default() -> Self {
        Self {
            schema: WORKSPACE_SCHEMA.to_string(),
            frontiers: Vec::new(),
        }
    }
}

/// Load a workspace index, returning an empty default if the file is absent
/// (so `vela workspace list` on a fresh machine prints nothing, not an error).
pub fn load_workspace(path: &Path) -> Result<WorkspaceRegistry, String> {
    if !path.exists() {
        return Ok(WorkspaceRegistry::default());
    }
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("read workspace {}: {e}", path.display()))?;
    serde_json::from_str(&raw).map_err(|e| format!("parse workspace {}: {e}", path.display()))
}

/// Persist a workspace index (pretty JSON, creating the parent dir).
pub fn save_workspace(path: &Path, ws: &WorkspaceRegistry) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }
    let raw = serde_json::to_string_pretty(ws).map_err(|e| format!("serialize workspace: {e}"))?;
    std::fs::write(path, raw).map_err(|e| format!("write workspace {}: {e}", path.display()))
}

/// Upsert a frontier by `path` (the natural key): replaces an existing entry
/// for the same path rather than appending a duplicate.
pub fn upsert(ws: &mut WorkspaceRegistry, entry: WorkspaceFrontier) {
    if let Some(slot) = ws.frontiers.iter_mut().find(|f| f.path == entry.path) {
        *slot = entry;
    } else {
        ws.frontiers.push(entry);
    }
}

/// Remove a frontier by path. Returns true if one was removed.
pub fn remove(ws: &mut WorkspaceRegistry, path: &str) -> bool {
    let before = ws.frontiers.len();
    ws.frontiers.retain(|f| f.path != path);
    ws.frontiers.len() != before
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn load_absent_is_empty_default() {
        let dir = TempDir::new().unwrap();
        let ws = load_workspace(&dir.path().join("nope.json")).unwrap();
        assert_eq!(ws.schema, WORKSPACE_SCHEMA);
        assert!(ws.frontiers.is_empty());
    }

    #[test]
    fn upsert_is_keyed_by_path_and_round_trips() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("workspace.json");
        let mut ws = WorkspaceRegistry::default();
        upsert(
            &mut ws,
            WorkspaceFrontier {
                path: "examples/sidon-sets".into(),
                vfr_id: Some("vfr_aaa".into()),
                remote: Some("https://hub.example".into()),
                name: Some("Sidon".into()),
                added_at: None,
            },
        );
        // Re-adding the same path updates in place (no duplicate).
        upsert(
            &mut ws,
            WorkspaceFrontier {
                path: "examples/sidon-sets".into(),
                vfr_id: Some("vfr_bbb".into()),
                remote: None,
                name: None,
                added_at: None,
            },
        );
        assert_eq!(ws.frontiers.len(), 1);
        assert_eq!(ws.frontiers[0].vfr_id.as_deref(), Some("vfr_bbb"));

        save_workspace(&file, &ws).unwrap();
        let reloaded = load_workspace(&file).unwrap();
        assert_eq!(reloaded.frontiers.len(), 1);
        assert_eq!(reloaded.frontiers[0].path, "examples/sidon-sets");

        assert!(remove(&mut ws, "examples/sidon-sets"));
        assert!(!remove(&mut ws, "examples/sidon-sets"));
    }
}
