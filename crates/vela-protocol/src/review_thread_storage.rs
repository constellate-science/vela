//! v0.174: storage helpers for review threads (`vrt_*`).
//!
//! Threads are persisted under `<frontier>/.vela/review-threads/`,
//! one JSON file per thread named by its content-addressed id
//! (e.g. `vrt_3a8f1bc24fefa091.json`). This module ships pure
//! filesystem helpers; the workbench read surface and the v0.168
//! CLI commands both compose against these.
//!
//! Substrate-honest framing: threads are append-only, signed, and
//! content-addressed at the message level. The storage layer
//! doesn't impose schema on top of the v0.168 primitive — it just
//! provides a canonical on-disk location and discovery.

use crate::review_thread::ReviewThread;
use std::fs;
use std::path::{Path, PathBuf};

/// Resolve the threads directory for a frontier path. Accepts
/// either a frontier-dir path or a `frontier.json` file path.
pub fn threads_dir(frontier: &Path) -> PathBuf {
    let base = if frontier.is_dir() {
        frontier.to_path_buf()
    } else if let Some(parent) = frontier.parent() {
        parent.to_path_buf()
    } else {
        PathBuf::from(".")
    };
    base.join(".vela").join("review-threads")
}

/// Load every thread under `<frontier>/.vela/review-threads/`. Skips
/// malformed files quietly so a single bad file doesn't block the
/// rest of the surface. Returns threads sorted by `created_at`
/// ascending.
pub fn load_all_threads(frontier: &Path) -> Vec<ReviewThread> {
    let dir = threads_dir(frontier);
    if !dir.exists() {
        return Vec::new();
    }
    let entries = match fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };
    let mut out: Vec<ReviewThread> = entries
        .filter_map(|r| r.ok())
        .filter_map(|entry| {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                return None;
            }
            let body = fs::read_to_string(&path).ok()?;
            serde_json::from_str::<ReviewThread>(&body).ok()
        })
        .collect();
    out.sort_by(|a, b| a.created_at.cmp(&b.created_at));
    out
}

/// Load one thread by `vrt_*` id. Returns None if the file is
/// missing or unparsable.
pub fn load_thread(frontier: &Path, thread_id: &str) -> Option<ReviewThread> {
    let path = threads_dir(frontier).join(format!("{thread_id}.json"));
    let body = fs::read_to_string(&path).ok()?;
    serde_json::from_str::<ReviewThread>(&body).ok()
}

/// Persist a thread under `<frontier>/.vela/review-threads/`.
/// Creates the directory if needed.
pub fn save_thread(frontier: &Path, thread: &ReviewThread) -> Result<PathBuf, String> {
    let dir = threads_dir(frontier);
    fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let path = dir.join(format!("{}.json", thread.thread_id));
    let body = serde_json::to_string_pretty(thread).map_err(|e| format!("serialize: {e}"))?;
    fs::write(&path, format!("{body}\n")).map_err(|e| format!("write {}: {e}", path.display()))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::review_thread::{ReviewThread, ThreadTargetKind};
    use tempfile::TempDir;

    fn thread() -> ReviewThread {
        ReviewThread::new(
            ThreadTargetKind::Proposal,
            "vpr_abc123".to_string(),
            "vfr_def456".to_string(),
            "2026-05-11T00:00:00Z".to_string(),
        )
        .unwrap()
    }

    #[test]
    fn save_then_load_round_trips() {
        let tmp = TempDir::new().unwrap();
        let t = thread();
        let path = save_thread(tmp.path(), &t).unwrap();
        assert!(path.exists());
        let back = load_thread(tmp.path(), &t.thread_id).unwrap();
        assert_eq!(back.thread_id, t.thread_id);
        let all = load_all_threads(tmp.path());
        assert_eq!(all.len(), 1);
    }

    #[test]
    fn load_all_skips_garbage_files() {
        let tmp = TempDir::new().unwrap();
        let dir = threads_dir(tmp.path());
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("vrt_good.json"),
            serde_json::to_string(&thread()).unwrap(),
        )
        .unwrap();
        fs::write(dir.join("garbage.json"), "{not valid").unwrap();
        fs::write(dir.join("not-json.txt"), "ignored").unwrap();
        let all = load_all_threads(tmp.path());
        assert_eq!(all.len(), 1);
    }

    #[test]
    fn missing_frontier_returns_empty() {
        let tmp = TempDir::new().unwrap();
        assert!(load_all_threads(tmp.path()).is_empty());
        assert!(load_thread(tmp.path(), "vrt_anything").is_none());
    }
}
