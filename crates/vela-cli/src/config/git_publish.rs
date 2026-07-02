//! Decisions self-publish.
//!
//! Once a human key has signed, nothing that follows is a decision —
//! materializing derived views, staging the store, writing the commit
//! message, pushing — it is mechanical consequence, and mechanical
//! consequence is the substrate's job. Before this module, a reviewer
//! expressed one intention ("accept this") in four acts and the signed
//! decision routinely rotted uncommitted on one laptop, invisible to CI,
//! the hub, and everyone else.
//!
//! Custody note: nothing here signs anything. Publication only carries
//! events a key already signed; withholding publication was never a
//! second decision, just friction.
//!
//! Failure posture: publication never fails the decision. The signed
//! event is already in the store; a git hiccup degrades to a warning
//! with the exact manual command.

use std::path::Path;
use std::process::Command;

use vela_protocol::cli_style as style;

pub(crate) struct PublishOptions {
    pub no_commit: bool,
    pub no_push: bool,
}

impl PublishOptions {
    pub(crate) fn new(no_commit: bool, no_push: bool) -> Self {
        Self { no_commit, no_push }
    }
}

fn git(root: &Path, args: &[&str]) -> Result<String, String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .map_err(|e| format!("git: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

/// Publish a signed decision: materialize derived views, stage the
/// frontier's store paths, commit with a canonical message binding the
/// event ids, and push. Config: identity `git_commit` / `git_push`
/// ("auto" default, "off" opts out); `VELA_NO_PUBLISH=1` disables
/// globally (gates, tests); per-call flags override.
pub(crate) fn publish_decision(
    frontier: &Path,
    summary: &str,
    event_ids: &[String],
    opts: &PublishOptions,
) {
    // cfg!(test): the unit test below exercises the publish path itself
    // and must not be muted by the conformance gate's own guard.
    if !cfg!(test) && std::env::var("VELA_NO_PUBLISH").is_ok_and(|v| v == "1") {
        return;
    }
    let identity = crate::cli_identity::load_identity();
    let commit_mode = identity
        .as_ref()
        .map(|i| i.git_commit.clone())
        .unwrap_or_else(|| "auto".to_string());
    if opts.no_commit || commit_mode == "off" {
        println!("  unpublished: decision is signed but not committed (publish it with git)");
        return;
    }
    let Ok(root) = git(frontier, &["rev-parse", "--show-toplevel"]) else {
        // Not a git repo: nothing to publish to; the store is still the store.
        return;
    };
    let root = std::path::PathBuf::from(root);

    // The store must never be committed ahead of its derived views: the
    // vela-check Action holds committed views to replayed-state hash
    // parity, so store-without-views is a red CI by construction.
    if let Err(e) = vela_protocol::frontier_repo::materialize(frontier) {
        println!(
            "  {} materialize before publish failed ({e}); publishing store as-is",
            style::warn("warn")
        );
    }

    let frontier_abs = frontier
        .canonicalize()
        .unwrap_or_else(|_| frontier.to_path_buf());
    let rel = frontier_abs.strip_prefix(&root).unwrap_or(Path::new(""));
    let mut staged_any = false;
    for name in [".vela", "frontier.json", "vela.lock", "proof"] {
        let candidate = frontier_abs.join(name);
        if candidate.exists() {
            let spec = rel.join(name);
            let spec = if spec.as_os_str().is_empty() {
                name.to_string()
            } else {
                spec.display().to_string()
            };
            if git(&root, &["add", "-A", "--", &spec]).is_ok() {
                staged_any = true;
            }
        }
    }
    if !staged_any || git(&root, &["diff", "--cached", "--quiet"]).is_ok() {
        // diff --cached --quiet exits 0 when nothing is staged.
        return;
    }

    let mut message = summary.to_string();
    if !event_ids.is_empty() {
        message.push_str("\n\nsigned events:\n");
        for id in event_ids.iter().take(20) {
            message.push_str("  ");
            message.push_str(id);
            message.push('\n');
        }
        if event_ids.len() > 20 {
            message.push_str(&format!("  … +{} more\n", event_ids.len() - 20));
        }
    }
    if let Err(e) = git(&root, &["commit", "-q", "-m", &message]) {
        println!(
            "  {} publish commit failed: {e}\n  publish manually: git add -A && git commit",
            style::warn("warn")
        );
        return;
    }
    let sha = git(&root, &["rev-parse", "--short", "HEAD"]).unwrap_or_default();
    println!("  published · {sha} {summary}");

    let push_mode = identity
        .as_ref()
        .map(|i| i.git_push.clone())
        .unwrap_or_else(|| "auto".to_string());
    if opts.no_push || push_mode == "off" {
        println!("  not pushed (push when ready: git push)");
        return;
    }
    match git(&root, &["push", "-q"]) {
        Ok(_) => println!("  pushed · publication is the push; the index re-derives in seconds"),
        Err(e) => {
            let tail: String = e.lines().last().unwrap_or("").chars().take(90).collect();
            println!(
                "  {} push failed ({tail})\n  the commit is local; push manually: git push",
                style::warn("warn")
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sh(dir: &Path, cmd: &[&str]) {
        assert!(
            Command::new(cmd[0])
                .args(&cmd[1..])
                .current_dir(dir)
                .output()
                .unwrap()
                .status
                .success(),
            "{cmd:?}"
        );
    }

    #[test]
    fn publishes_a_commit_with_event_ids_and_survives_pushless_remotes() {
        let tmp = std::env::temp_dir().join(format!("vela-publish-test-{}", std::process::id()));
        std::fs::create_dir_all(tmp.join(".vela/events")).unwrap();
        sh(&tmp, &["git", "init", "-q"]);
        sh(&tmp, &["git", "config", "user.email", "t@t"]);
        sh(&tmp, &["git", "config", "user.name", "t"]);
        std::fs::write(tmp.join(".vela/events/vev_x.json"), "{}").unwrap();

        // Not a loadable frontier, so materialize fails soft; the commit
        // must still land, and the push failure (no remote) must warn,
        // not panic or fail.
        publish_decision(
            &tmp,
            "accept: 1 proposal",
            &["vev_x".to_string()],
            &PublishOptions::new(false, false),
        );

        let log = Command::new("git")
            .args(["-C", tmp.to_str().unwrap(), "log", "-1", "--format=%B"])
            .output()
            .unwrap();
        let body = String::from_utf8_lossy(&log.stdout).to_string();
        assert!(body.contains("accept: 1 proposal"), "{body}");
        assert!(body.contains("vev_x"), "{body}");

        // --no-commit leaves new work uncommitted.
        std::fs::write(tmp.join(".vela/events/vev_y.json"), "{}").unwrap();
        publish_decision(&tmp, "x", &[], &PublishOptions::new(true, false));
        let status = Command::new("git")
            .args(["-C", tmp.to_str().unwrap(), "status", "--porcelain"])
            .output()
            .unwrap();
        assert!(!status.stdout.is_empty(), "no-commit must not commit");

        std::fs::remove_dir_all(&tmp).ok();
    }
}
