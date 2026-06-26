//! First-user diagnostic report.
//!
//! The doctor command is operational. It explains whether a checkout,
//! binary, local frontier, proof state, and Workbench port are ready for the
//! adoption path. It does not validate scientific truth.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};

use vela_protocol::evidence_ci;

use crate::frontier_health;

use vela_protocol::frontier_policy;

use vela_protocol::repo;
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DoctorReport {
    pub ok: bool,
    pub command: String,
    pub binary_version: String,
    pub workspace_root: String,
    pub has_cargo: bool,
    pub has_jq: bool,
    pub has_rg: bool,
    pub has_curl: bool,
    pub release_binary_exists: bool,
    pub frontier_path: String,
    pub frontier_kind: String,
    pub frontier_load_ok: bool,
    pub policy_ok: bool,
    pub proof_status: String,
    pub evidence_ci_ok: bool,
    pub workbench_port: u16,
    pub workbench_port_available: bool,
    #[serde(default)]
    pub blocking: Vec<String>,
    #[serde(default)]
    pub warnings: Vec<String>,
    #[serde(default)]
    pub next_commands: Vec<String>,
    #[serde(default)]
    pub mcp_config: Option<serde_json::Value>,
}

pub fn run(frontier_arg: Option<&Path>, port: u16) -> DoctorReport {
    let workspace_root = workspace_root();
    let frontier_path = resolve_frontier_path(frontier_arg, Path::new(&workspace_root));
    let frontier_kind = frontier_kind(&frontier_path);
    let release_binary_exists = Path::new("target/release/vela").is_file();
    let has_cargo = command_exists("cargo");
    let has_jq = command_exists("jq");
    let has_rg = command_exists("rg");
    let has_curl = command_exists("curl");
    let workbench_port_available = port_available(port);

    let project_result = repo::load_from_path(&frontier_path);
    let frontier_load_ok = project_result.is_ok();
    let proof_status = project_result
        .as_ref()
        .map(|project| project.proof_state.latest_packet.status.clone())
        .unwrap_or_else(|_| "unavailable".to_string());

    let policy_ok = frontier_load_ok
        && frontier_policy::load_policy_summary(&frontier_path)
            .map(|summary| summary.ok)
            .unwrap_or(false);
    let evidence_ci_ok = frontier_load_ok
        && evidence_ci::run_frontier(&frontier_path)
            .map(|report| report.ok && report.summary.release_blocking_failed == 0)
            .unwrap_or(false);
    let health_ok = frontier_load_ok
        && frontier_health::analyze(&frontier_path)
            .map(|report| report.metrics.evidence_ci_failures == 0)
            .unwrap_or(false);

    let mut blocking = Vec::new();
    let mut warnings = Vec::new();

    if !has_cargo {
        blocking.push("cargo_missing".to_string());
    }
    if !frontier_load_ok {
        blocking.push("frontier_load_failed".to_string());
    }
    if frontier_load_ok && !policy_ok {
        blocking.push("policy_missing_or_invalid".to_string());
    }
    if frontier_load_ok && !evidence_ci_ok {
        blocking.push("evidence_ci_release_blocking".to_string());
    }
    if !workbench_port_available {
        blocking.push("workbench_port_unavailable".to_string());
    }
    if !release_binary_exists {
        warnings.push("release binary missing; run cargo build --release --bin vela".to_string());
    }
    if !has_jq {
        warnings.push("jq missing; JSON examples will be harder to inspect".to_string());
    }
    if !has_rg {
        warnings.push("rg missing; release gates use ripgrep for text checks".to_string());
    }
    if !has_curl {
        warnings.push("curl missing; HTTP and serve smoke checks will fail".to_string());
    }
    if frontier_load_ok && !matches!(proof_status.as_str(), "fresh" | "current" | "ready") {
        warnings.push(format!("proof state is {proof_status}"));
    }
    if frontier_load_ok && !health_ok {
        warnings.push("frontier health has review debt".to_string());
    }

    let frontier_display = frontier_path.display().to_string();
    let next_commands = if frontier_load_ok {
        vec![
            format!("vela doctor {frontier_display} --port {port}"),
            format!("vela serve {frontier_display} --http {port}"),
            format!("vela frontier audit {frontier_display}"),
            format!("vela check {frontier_display} --evidence"),
            format!("vela proof {frontier_display} --out /tmp/vela-proof"),
            "vela verify /tmp/vela-proof".to_string(),
        ]
    } else {
        vec![
            "vela init ./my-frontier --template adoption-frontier".to_string(),
            "vela doctor ./my-frontier".to_string(),
        ]
    };

    let mcp_config = if frontier_load_ok {
        Some(serde_json::json!({
            "command": "vela",
            "args": ["serve", frontier_display],
            "transport": "stdio"
        }))
    } else {
        None
    };

    DoctorReport {
        ok: blocking.is_empty(),
        command: "doctor".to_string(),
        binary_version: env!("CARGO_PKG_VERSION").to_string(),
        workspace_root,
        has_cargo,
        has_jq,
        has_rg,
        has_curl,
        release_binary_exists,
        frontier_path: frontier_display,
        frontier_kind,
        frontier_load_ok,
        policy_ok,
        proof_status,
        evidence_ci_ok,
        workbench_port: port,
        workbench_port_available,
        blocking,
        warnings,
        next_commands,
        mcp_config,
    }
}

fn resolve_frontier_path(frontier_arg: Option<&Path>, workspace_root: &Path) -> PathBuf {
    if let Some(path) = frontier_arg {
        return path.to_path_buf();
    }
    if let Some(frontier) = first_local_frontier(&workspace_root.join("projects")) {
        return frontier;
    }
    workspace_root.to_path_buf()
}

/// Returns the first frontier repo (a directory carrying a `.vela/` store)
/// under `projects_root`, in sorted order. Frontier-agnostic: the doctor does
/// not privilege any single campaign.
fn first_local_frontier(projects_root: &Path) -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = std::fs::read_dir(projects_root)
        .ok()?
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.join(".vela").is_dir())
        .collect();
    candidates.sort();
    candidates.into_iter().next()
}

fn workspace_root() -> String {
    if let Ok(output) = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        && output.status.success()
    {
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !stdout.is_empty() {
            return stdout;
        }
    }
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .display()
        .to_string()
}

fn frontier_kind(path: &Path) -> String {
    if path.is_dir() {
        if path.join(".vela").is_dir() {
            "frontier_repo".to_string()
        } else {
            "directory".to_string()
        }
    } else if path.is_file() {
        "frontier_json".to_string()
    } else {
        "missing".to_string()
    }
}

fn command_exists(command: &str) -> bool {
    Command::new(command)
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn port_available(port: u16) -> bool {
    TcpListener::bind(("127.0.0.1", port)).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_frontier_blocks() {
        let report = run(Some(Path::new("/tmp/vela-doctor-missing-frontier")), 47991);
        assert!(!report.ok);
        assert!(
            report
                .blocking
                .contains(&"frontier_load_failed".to_string())
        );
    }

    #[test]
    fn kind_reports_frontier_repo() {
        let dir = tempfile::tempdir().expect("tempdir");
        let frontier = dir.path().join("some-frontier");
        std::fs::create_dir_all(frontier.join(".vela")).expect("create frontier store");
        assert_eq!(frontier_kind(&frontier), "frontier_repo");
    }

    #[test]
    fn first_local_frontier_picks_first_vela_repo() {
        let dir = tempfile::tempdir().expect("tempdir");
        let projects = dir.path().join("projects");
        // A plain directory is not a frontier; a directory with .vela/ is.
        std::fs::create_dir_all(projects.join("not-a-frontier")).expect("plain dir");
        std::fs::create_dir_all(projects.join("zebra-frontier").join(".vela")).expect("frontier b");
        std::fs::create_dir_all(projects.join("alpha-frontier").join(".vela")).expect("frontier a");
        let found = first_local_frontier(&projects).expect("a frontier repo exists");
        assert_eq!(found, projects.join("alpha-frontier"));
        // No projects directory at all resolves to None, not a panic.
        assert!(first_local_frontier(&dir.path().join("absent")).is_none());
    }
}
