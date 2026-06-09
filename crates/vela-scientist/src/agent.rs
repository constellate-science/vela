//! # Shared agent infrastructure
//!
//! v0.22 invented one agent (Literature Scout). v0.23+ adds three
//! more (Notes Compiler, Code Analyst, Datasets). This module hoists
//! the shape that every agent shares so each new module only has to
//! write its prompt + schema + lift-to-FindingBundle.
//!
//! Doctrine: this is still the agent layer. `vela-protocol` does not
//! depend on it. Removing this module + every per-agent module would
//! leave the substrate identical.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use chrono::Utc;
use serde_json::json;
use vela_protocol::bundle::FindingBundle;
use vela_protocol::events::StateTarget;
use vela_protocol::proposals::{AgentRun, StateProposal, new_proposal};

use crate::new_run_id;

/// One-shot context built at the top of an agent run. Everything
/// downstream (proposal builder, report) reads from here so the
/// agent's own `run` function stays small.
#[derive(Debug, Clone)]
pub struct AgentContext {
    pub agent_name: String, // e.g. "literature-scout"
    pub actor_id: String,   // e.g. "agent:literature-scout"
    pub run_id: String,     // vrun_…
    pub started_at: String, // RFC3339
    pub model: Option<String>,
    pub cli_command: String,
    pub frontier_path: PathBuf,
    pub input_root: PathBuf,
}

impl AgentContext {
    /// Build the context for a single run. Generates a fresh run id
    /// and stamps the start time. The agent's own `run` function
    /// passes the resulting `AgentContext` into `build_finding_add_proposal`
    /// and `agent_run_meta`.
    #[must_use]
    pub fn new(
        agent_name: impl Into<String>,
        frontier_path: PathBuf,
        input_root: PathBuf,
        model: Option<String>,
        cli_command: String,
    ) -> Self {
        let agent_name = agent_name.into();
        let run_id = new_run_id(&agent_name);
        let actor_id = format!("agent:{agent_name}");
        Self {
            agent_name,
            actor_id,
            run_id,
            started_at: Utc::now().to_rfc3339(),
            model,
            cli_command,
            frontier_path,
            input_root,
        }
    }
}

/// Build the `AgentRun` block stamped on every proposal in this run.
/// `extra` carries agent-specific context like file counts, vault
/// paths, sample-row counts. Standard keys are filled here so each
/// agent only adds its own.
#[must_use]
pub fn agent_run_meta(ctx: &AgentContext, mut extra: BTreeMap<String, String>) -> AgentRun {
    extra
        .entry("backend".to_string())
        .or_insert_with(|| "claude-cli".to_string());
    extra
        .entry("cli_command".to_string())
        .or_insert_with(|| ctx.cli_command.clone());
    extra
        .entry("input_root".to_string())
        .or_insert_with(|| ctx.input_root.display().to_string());
    AgentRun {
        agent: ctx.agent_name.clone(),
        model: ctx.model.clone().unwrap_or_default(),
        run_id: ctx.run_id.clone(),
        started_at: ctx.started_at.clone(),
        finished_at: None,
        context: extra,
        tool_calls: Vec::new(),
        permissions: None,
    }
}

/// Wrap a `FindingBundle` as a `finding.add` `StateProposal` tagged
/// with the agent's `AgentRun`. Every agent uses this to keep the
/// proposal shape uniform — the Workbench Inbox grouping depends on
/// it.
///
/// `model_rationale` is the model's own one-sentence reason for the
/// proposal. When non-empty it becomes the proposal's `reason` (so
/// the Inbox card surfaces the model's "why" first); when empty we
/// fall back to a generic `<agent_name> extracted from <source>`.
/// Flags get appended in brackets so the reviewer sees them inline.
#[must_use]
pub fn build_finding_add_proposal(
    finding: &FindingBundle,
    ctx: &AgentContext,
    source_label: &str,
    model_rationale: &str,
    flags: &[String],
    run: &AgentRun,
) -> StateProposal {
    let payload = json!({ "finding": finding });
    let reason = if !model_rationale.trim().is_empty() {
        if flags.is_empty() {
            model_rationale.to_string()
        } else {
            format!("{model_rationale} [flags: {}]", flags.join(", "))
        }
    } else if flags.is_empty() {
        format!("{} extracted from {source_label}", ctx.agent_name)
    } else {
        format!(
            "{} extracted from {source_label} [flags: {}]",
            ctx.agent_name,
            flags.join(", ")
        )
    };
    let mut proposal = new_proposal(
        "finding.add",
        StateTarget {
            r#type: "finding".to_string(),
            id: finding.id.clone(),
        },
        &ctx.actor_id,
        "agent",
        reason,
        payload,
        vec![source_label.to_string()],
        flags.to_vec(),
    );
    proposal.agent_run = Some(run.clone());
    proposal
}

/// v0.52: Wrap a `NegativeResult` in a `negative_result.assert`
/// `StateProposal` for the agent inbox. Mirrors
/// `build_finding_add_proposal`: target.type is `negative_result`,
/// payload carries the inline NegativeResult, the proposal is tagged
/// with the agent's run. Reviewers accept in the Workbench; the CLI
/// signs.
#[must_use]
pub fn build_negative_result_assert_proposal(
    nr: &vela_protocol::bundle::NegativeResult,
    ctx: &AgentContext,
    source_label: &str,
    model_rationale: &str,
    flags: &[String],
    run: &AgentRun,
) -> StateProposal {
    let payload = json!({ "negative_result": nr });
    let reason = if !model_rationale.trim().is_empty() {
        if flags.is_empty() {
            model_rationale.to_string()
        } else {
            format!("{model_rationale} [flags: {}]", flags.join(", "))
        }
    } else if flags.is_empty() {
        format!("{} extracted null from {source_label}", ctx.agent_name)
    } else {
        format!(
            "{} extracted null from {source_label} [flags: {}]",
            ctx.agent_name,
            flags.join(", ")
        )
    };
    let mut proposal = new_proposal(
        "negative_result.assert",
        StateTarget {
            r#type: "negative_result".to_string(),
            id: nr.id.clone(),
        },
        &ctx.actor_id,
        "agent",
        reason,
        payload,
        vec![source_label.to_string()],
        flags.to_vec(),
    );
    proposal.agent_run = Some(run.clone());
    proposal
}

/// v0.52: Wrap a `Trajectory` in a `trajectory.create`
/// `StateProposal` for the agent inbox. Steps land later via
/// separate `build_trajectory_step_append_proposal` calls.
#[must_use]
pub fn build_trajectory_create_proposal(
    trajectory: &vela_protocol::bundle::Trajectory,
    ctx: &AgentContext,
    source_label: &str,
    model_rationale: &str,
    flags: &[String],
    run: &AgentRun,
) -> StateProposal {
    let payload = json!({ "trajectory": trajectory });
    let reason = if !model_rationale.trim().is_empty() {
        if flags.is_empty() {
            model_rationale.to_string()
        } else {
            format!("{model_rationale} [flags: {}]", flags.join(", "))
        }
    } else if flags.is_empty() {
        format!(
            "{} extracted search path from {source_label}",
            ctx.agent_name
        )
    } else {
        format!(
            "{} extracted search path from {source_label} [flags: {}]",
            ctx.agent_name,
            flags.join(", ")
        )
    };
    let mut proposal = new_proposal(
        "trajectory.create",
        StateTarget {
            r#type: "trajectory".to_string(),
            id: trajectory.id.clone(),
        },
        &ctx.actor_id,
        "agent",
        reason,
        payload,
        vec![source_label.to_string()],
        flags.to_vec(),
    );
    proposal.agent_run = Some(run.clone());
    proposal
}

/// v0.52: Wrap a `TrajectoryStep` in a `trajectory.step_append`
/// `StateProposal`. `parent_trajectory_id` is the existing `vtr_*`
/// the step extends. Steps are content-addressed; idempotent on
/// duplicate ids.
#[must_use]
pub fn build_trajectory_step_append_proposal(
    parent_trajectory_id: &str,
    step: &vela_protocol::bundle::TrajectoryStep,
    ctx: &AgentContext,
    source_label: &str,
    model_rationale: &str,
    flags: &[String],
    run: &AgentRun,
) -> StateProposal {
    let payload = json!({ "step": step });
    let reason = if !model_rationale.trim().is_empty() {
        if flags.is_empty() {
            model_rationale.to_string()
        } else {
            format!("{model_rationale} [flags: {}]", flags.join(", "))
        }
    } else if flags.is_empty() {
        format!("{} extracted step from {source_label}", ctx.agent_name)
    } else {
        format!(
            "{} extracted step from {source_label} [flags: {}]",
            ctx.agent_name,
            flags.join(", ")
        )
    };
    let mut proposal = new_proposal(
        "trajectory.step_append",
        StateTarget {
            r#type: "trajectory".to_string(),
            id: parent_trajectory_id.to_string(),
        },
        &ctx.actor_id,
        "agent",
        reason,
        payload,
        vec![source_label.to_string()],
        flags.to_vec(),
    );
    proposal.agent_run = Some(run.clone());
    proposal
}

/// Generic file discovery — walks `root` (top level only), filters
/// hidden entries and anything not in `extensions` (lowercase, no
/// dot). Sorted output for determinism.
///
/// Used by every agent to produce a stable list of input files
/// without recursing into `.git`/`node_modules`/`.obsidian`-style
/// directories. Recursive walking lands in v0.24+ if the dogfood
/// runs show it's needed.
pub fn discover_files(root: &Path, extensions: &[&str]) -> Result<Vec<PathBuf>, String> {
    // v0.74.2: accept a single file as well as a folder. When `root`
    // is a regular file with a matching extension, return it as a
    // one-element vec. This is what makes `vela ingest paper.pdf`
    // work without requiring a wrapping folder.
    if root.is_file() {
        let is_hidden = root
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with('.'));
        if is_hidden {
            return Ok(Vec::new());
        }
        let ext = root
            .extension()
            .and_then(|e| e.to_str())
            .map(str::to_ascii_lowercase);
        if let Some(ext) = ext
            && extensions.contains(&ext.as_str())
        {
            return Ok(vec![root.to_path_buf()]);
        }
        return Ok(Vec::new());
    }

    let entries = std::fs::read_dir(root).map_err(|e| format!("read {}: {e}", root.display()))?;
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let is_hidden = path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with('.'));
        if is_hidden {
            continue;
        }
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .map(str::to_ascii_lowercase);
        if let Some(ext) = ext
            && extensions.contains(&ext.as_str())
        {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

/// Recursive variant of `discover_files`. Walks the entire tree,
/// skipping hidden directories and anything in `skip_dirs` (matched
/// by basename). Used by agents that scan source-code repos or
/// Obsidian vaults where useful files live in subdirectories.
pub fn discover_files_recursive(
    root: &Path,
    extensions: &[&str],
    skip_dirs: &[&str],
) -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries =
            std::fs::read_dir(&dir).map_err(|e| format!("read {}: {e}", dir.display()))?;
        for entry in entries.flatten() {
            let path = entry.path();
            let basename = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            if basename.starts_with('.') {
                continue;
            }
            let metadata = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            if metadata.is_dir() {
                if skip_dirs.contains(&basename) {
                    continue;
                }
                stack.push(path);
            } else if metadata.is_file() {
                let ext = path
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(str::to_ascii_lowercase);
                if let Some(ext) = ext
                    && extensions.contains(&ext.as_str())
                {
                    out.push(path);
                }
            }
        }
    }
    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discover_files_filters_extension_and_hidden() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.md"), b"x").unwrap();
        std::fs::write(dir.path().join("b.txt"), b"x").unwrap();
        std::fs::write(dir.path().join(".hidden.md"), b"x").unwrap();
        std::fs::write(dir.path().join("c.MD"), b"x").unwrap();

        let mds = discover_files(dir.path(), &["md"]).unwrap();
        let names: Vec<String> = mds
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert!(names.contains(&"a.md".to_string()));
        // case-insensitive: c.MD also matches
        assert!(names.contains(&"c.MD".to_string()));
        assert!(!names.iter().any(|n| n == "b.txt"));
        assert!(!names.iter().any(|n| n.starts_with('.')));
    }

    #[test]
    fn discover_files_accepts_single_file() {
        // v0.74.2: a single file path with a matching extension
        // returns a one-element vec, so `vela ingest paper.pdf`
        // doesn't need a wrapping folder.
        let dir = tempfile::tempdir().unwrap();
        let pdf = dir.path().join("paper.pdf");
        std::fs::write(&pdf, b"%PDF-1.4").unwrap();
        let pdfs = discover_files(&pdf, &["pdf"]).unwrap();
        assert_eq!(pdfs.len(), 1);
        assert_eq!(pdfs[0], pdf);

        // Single file with non-matching extension returns empty.
        let txt = dir.path().join("notes.txt");
        std::fs::write(&txt, b"hi").unwrap();
        let pdfs = discover_files(&txt, &["pdf"]).unwrap();
        assert!(pdfs.is_empty());

        // Hidden single file is skipped.
        let hidden = dir.path().join(".secret.pdf");
        std::fs::write(&hidden, b"%PDF-1.4").unwrap();
        let pdfs = discover_files(&hidden, &["pdf"]).unwrap();
        assert!(pdfs.is_empty());
    }

    #[test]
    fn discover_files_recursive_skips_directories() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.md"), b"x").unwrap();
        std::fs::create_dir(dir.path().join("nested")).unwrap();
        std::fs::write(dir.path().join("nested/b.md"), b"x").unwrap();
        std::fs::create_dir(dir.path().join("node_modules")).unwrap();
        std::fs::write(dir.path().join("node_modules/skip.md"), b"x").unwrap();
        std::fs::create_dir(dir.path().join(".git")).unwrap();
        std::fs::write(dir.path().join(".git/skip.md"), b"x").unwrap();

        let mds =
            discover_files_recursive(dir.path(), &["md"], &["node_modules", "target", "dist"])
                .unwrap();
        let names: Vec<String> = mds
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"a.md".to_string()));
        assert!(names.contains(&"b.md".to_string()));
    }

    #[test]
    fn agent_run_meta_carries_standard_keys() {
        let ctx = AgentContext::new(
            "test-agent",
            PathBuf::from("/tmp/f.json"),
            PathBuf::from("/tmp/in"),
            Some("sonnet".to_string()),
            "claude".to_string(),
        );
        let run = agent_run_meta(&ctx, BTreeMap::new());
        assert_eq!(run.agent, "test-agent");
        assert_eq!(run.model, "sonnet");
        assert!(run.context.contains_key("backend"));
        assert!(run.context.contains_key("cli_command"));
        assert!(run.context.contains_key("input_root"));
    }
}
