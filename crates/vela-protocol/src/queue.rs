//! Phase R (v0.5): a local queue of unsigned draft actions.
//!
//! The Workbench writes here; `vela queue sign` walks the queue, signs
//! each action with the caller's Ed25519 key, and posts the signed
//! action to a live `vela serve` (or applies it directly via the same
//! `proposals::*_at_path` helpers the CLI uses).
//!
//! This is the v0.5 doctrine for human review actions: signing is a
//! deliberate human act on a terminal that holds the key. The browser
//! never sees the key. Drafts queue here; the CLI is the only signer.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const QUEUE_SCHEMA: &str = "vela.queue.v0.1";

/// A queued draft action. `kind` matches a write tool name
/// (`propose_review`, `propose_note`, `propose_revise_confidence`,
/// `propose_retract`, `accept_proposal`, `reject_proposal`); `args` is
/// the tool-specific argument bundle *without* the signature field —
/// `vela queue sign` constructs the signature at sign-time.
///
/// `frontier` is the path to the frontier file the action targets.
/// Multiple frontiers can be queued in a single queue file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueuedAction {
    pub kind: String,
    pub frontier: PathBuf,
    #[serde(default)]
    pub args: Value,
    pub queued_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Queue {
    #[serde(default = "default_schema")]
    pub schema: String,
    #[serde(default)]
    pub actions: Vec<QueuedAction>,
}

fn default_schema() -> String {
    QUEUE_SCHEMA.to_string()
}

impl Default for Queue {
    fn default() -> Self {
        Self {
            schema: QUEUE_SCHEMA.to_string(),
            actions: Vec::new(),
        }
    }
}

/// Resolve the queue file path. Defaults to `~/.vela/queue.json`.
/// Override with `VELA_QUEUE_FILE` for testing or alternate locations.
#[must_use]
pub fn default_queue_path() -> PathBuf {
    if let Ok(path) = std::env::var("VELA_QUEUE_FILE") {
        return PathBuf::from(path);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".vela").join("queue.json")
}

/// Load the queue from `path`. If the file does not exist, returns an
/// empty queue (the queue is ephemeral; nonexistence is a normal state).
pub fn load(path: &Path) -> Result<Queue, String> {
    if !path.exists() {
        return Ok(Queue::default());
    }
    let raw =
        std::fs::read_to_string(path).map_err(|e| format!("read queue {}: {e}", path.display()))?;
    let queue: Queue =
        serde_json::from_str(&raw).map_err(|e| format!("parse queue {}: {e}", path.display()))?;
    Ok(queue)
}

/// Write the queue to `path`, creating parent directories as needed.
pub fn save(path: &Path, queue: &Queue) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }
    let raw = serde_json::to_string_pretty(queue).map_err(|e| format!("serialize queue: {e}"))?;
    std::fs::write(path, raw).map_err(|e| format!("write queue {}: {e}", path.display()))?;
    Ok(())
}

/// Append a draft action to the queue file (creating it if absent).
pub fn append(path: &Path, action: QueuedAction) -> Result<(), String> {
    let mut queue = load(path)?;
    queue.actions.push(action);
    save(path, &queue)
}

/// Remove all actions from the queue file. Idempotent.
pub fn clear(path: &Path) -> Result<usize, String> {
    let queue = load(path)?;
    let dropped = queue.actions.len();
    save(path, &Queue::default())?;
    Ok(dropped)
}

/// Replace the queue's action list (used by `sign` after each successful
/// signed-and-applied action to remove the signed entry).
pub fn replace_actions(path: &Path, actions: Vec<QueuedAction>) -> Result<(), String> {
    save(
        path,
        &Queue {
            schema: QUEUE_SCHEMA.to_string(),
            actions,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::TempDir;

    #[test]
    fn empty_queue_when_file_absent() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("queue.json");
        let q = load(&path).unwrap();
        assert_eq!(q.actions.len(), 0);
        assert_eq!(q.schema, QUEUE_SCHEMA);
    }

    #[test]
    fn append_persists_and_round_trips() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("queue.json");
        append(
            &path,
            QueuedAction {
                kind: "accept_proposal".to_string(),
                frontier: PathBuf::from("/tmp/x.json"),
                args: json!({"proposal_id": "vpr_x", "reviewer_id": "r:test", "reason": "ok"}),
                queued_at: "2026-04-25T00:00:00Z".to_string(),
            },
        )
        .unwrap();
        let q = load(&path).unwrap();
        assert_eq!(q.actions.len(), 1);
        assert_eq!(q.actions[0].kind, "accept_proposal");
    }

    #[test]
    fn clear_drops_all_actions() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("queue.json");
        for i in 0..3 {
            append(
                &path,
                QueuedAction {
                    kind: "propose_review".to_string(),
                    frontier: PathBuf::from("/tmp/x.json"),
                    args: json!({"i": i}),
                    queued_at: "2026-04-25T00:00:00Z".to_string(),
                },
            )
            .unwrap();
        }
        let dropped = clear(&path).unwrap();
        assert_eq!(dropped, 3);
        let q = load(&path).unwrap();
        assert_eq!(q.actions.len(), 0);
    }
}
