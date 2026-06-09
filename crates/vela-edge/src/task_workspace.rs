//! Isolated local workspaces for frontier tasks.
//!
//! A task workspace preserves source material, extracted artifacts, validation
//! output, and review packets before any accepted event mutates frontier state.

use crate::frontier_task;

use vela_protocol::repo;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaskWorkspaceStatus {
    pub task_id: String,
    pub frontier_id: String,
    pub exists: bool,
    pub workspace_path: String,
    #[serde(default)]
    pub directories: Vec<String>,
    #[serde(default)]
    pub files: Vec<String>,
    #[serde(default)]
    pub source_artifacts: Vec<WorkspaceSourceArtifact>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frontier_snapshot_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceSourceArtifact {
    pub input: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
}

pub fn init_workspace(frontier_path: &Path, task_id: &str) -> Result<TaskWorkspaceStatus, String> {
    let root = frontier_task::repo_root(frontier_path)?;
    let task = frontier_task::load_task(&root, task_id)?;
    let workspace = workspace_root(&root, &task.id)?;
    std::fs::create_dir_all(&workspace)
        .map_err(|e| format!("create workspace {}: {e}", workspace.display()))?;

    let dirs = workspace_dirs();
    for dir in &dirs {
        let path = safe_join(&workspace, dir)?;
        std::fs::create_dir_all(&path)
            .map_err(|e| format!("create workspace directory {}: {e}", path.display()))?;
    }

    let task_yaml =
        serde_yaml::to_string(&task).map_err(|e| format!("serialize task yaml: {e}"))?;
    write_inside(&workspace, "task.yaml", task_yaml.as_bytes())?;

    let project = repo::load_from_path(&root)?;
    let snapshot = serde_json::to_vec_pretty(&project)
        .map_err(|e| format!("serialize frontier snapshot: {e}"))?;
    write_inside(&workspace, "frontier_snapshot_before.json", &snapshot)?;

    let review_packet = format!(
        "# Review packet\n\nTask: `{}`\n\nObjective: {}\n\nThis file is a placeholder until `vela review-packet build` writes a packet.\n",
        task.id, task.objective
    );
    write_inside(&workspace, "review_packet.md", review_packet.as_bytes())?;

    let source_artifacts = copy_declared_sources(&root, &workspace, &task.inputs)?;
    let manifest = serde_json::to_vec_pretty(&source_artifacts)
        .map_err(|e| format!("serialize source artifact manifest: {e}"))?;
    write_inside(&workspace, "sources/manifest.json", &manifest)?;

    workspace_status(&root, &task.id)
}

pub fn workspace_status(
    frontier_path: &Path,
    task_id: &str,
) -> Result<TaskWorkspaceStatus, String> {
    let root = frontier_task::repo_root(frontier_path)?;
    let task = frontier_task::load_task(&root, task_id)?;
    let workspace = workspace_root(&root, &task.id)?;
    let exists = workspace.is_dir();
    let mut files = Vec::new();
    let mut directories = Vec::new();
    if exists {
        for rel in workspace_dirs() {
            if safe_join(&workspace, rel)?.is_dir() {
                directories.push(rel.to_string());
            }
        }
        for rel in [
            "task.yaml",
            "frontier_snapshot_before.json",
            "review_packet.md",
            "sources/manifest.json",
        ] {
            if safe_join(&workspace, rel)?.is_file() {
                files.push(rel.to_string());
            }
        }
    }

    let source_artifacts = if exists {
        let manifest_path = safe_join(&workspace, "sources/manifest.json")?;
        if manifest_path.is_file() {
            let body = std::fs::read_to_string(&manifest_path)
                .map_err(|e| format!("read {}: {e}", manifest_path.display()))?;
            serde_json::from_str(&body)
                .map_err(|e| format!("parse {}: {e}", manifest_path.display()))?
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    let frontier_snapshot_sha256 = if exists {
        let snapshot_path = safe_join(&workspace, "frontier_snapshot_before.json")?;
        if snapshot_path.is_file() {
            let bytes = std::fs::read(&snapshot_path)
                .map_err(|e| format!("read {}: {e}", snapshot_path.display()))?;
            Some(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
        } else {
            None
        }
    } else {
        None
    };

    Ok(TaskWorkspaceStatus {
        task_id: task.id,
        frontier_id: task.frontier_id,
        exists,
        workspace_path: workspace.display().to_string(),
        directories,
        files,
        source_artifacts,
        frontier_snapshot_sha256,
    })
}

pub fn workspace_root(frontier_root: &Path, task_id: &str) -> Result<PathBuf, String> {
    if !task_id.starts_with("vtask_")
        || task_id.contains('/')
        || task_id.contains('\\')
        || task_id.contains("..")
    {
        return Err(format!("invalid task id for workspace `{task_id}`"));
    }
    let root = frontier_root.join(".vela").join("workspaces");
    safe_join(&root, task_id)
}

fn workspace_dirs() -> Vec<&'static str> {
    vec![
        "sources",
        "parsed",
        "extracted",
        "validation",
        "diff_pack",
        "logs",
        "attestations",
    ]
}

fn copy_declared_sources(
    frontier_root: &Path,
    workspace: &Path,
    inputs: &[String],
) -> Result<Vec<WorkspaceSourceArtifact>, String> {
    let source_dir = safe_join(workspace, "sources")?;
    let frontier_root = frontier_root.canonicalize().map_err(|e| {
        format!(
            "canonicalize frontier root {}: {e}",
            frontier_root.display()
        )
    })?;
    let mut artifacts = Vec::new();
    for input in inputs {
        let candidate = input.strip_prefix("file:").unwrap_or(input);
        let path = PathBuf::from(candidate);
        let source_path = if path.is_absolute() {
            path
        } else {
            frontier_root.join(path)
        };
        let Some(source_path) = source_path.canonicalize().ok().filter(|p| p.is_file()) else {
            artifacts.push(WorkspaceSourceArtifact {
                input: input.clone(),
                status: "declared_only".to_string(),
                source_path: None,
                workspace_path: None,
                sha256: None,
                bytes: None,
            });
            continue;
        };
        if !source_path.starts_with(&frontier_root) {
            artifacts.push(WorkspaceSourceArtifact {
                input: input.clone(),
                status: "outside_frontier_not_copied".to_string(),
                source_path: Some(source_path.display().to_string()),
                workspace_path: None,
                sha256: None,
                bytes: None,
            });
            continue;
        }
        let bytes = std::fs::read(&source_path)
            .map_err(|e| format!("read source artifact {}: {e}", source_path.display()))?;
        let sha = hex::encode(Sha256::digest(&bytes));
        let name = source_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("source-artifact");
        let dest_name = format!("sha256-{sha}-{name}");
        let dest = safe_join(&source_dir, &dest_name)?;
        std::fs::write(&dest, &bytes)
            .map_err(|e| format!("copy source artifact {}: {e}", dest.display()))?;
        artifacts.push(WorkspaceSourceArtifact {
            input: input.clone(),
            status: "copied".to_string(),
            source_path: Some(source_path.display().to_string()),
            workspace_path: Some(format!("sources/{dest_name}")),
            sha256: Some(format!("sha256:{sha}")),
            bytes: Some(bytes.len() as u64),
        });
    }
    Ok(artifacts)
}

fn write_inside(workspace: &Path, rel: &str, bytes: &[u8]) -> Result<(), String> {
    let path = safe_join(workspace, rel)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("create workspace parent {}: {e}", parent.display()))?;
    }
    std::fs::write(&path, bytes).map_err(|e| format!("write {}: {e}", path.display()))
}

fn safe_join(root: &Path, rel: &str) -> Result<PathBuf, String> {
    let rel_path = Path::new(rel);
    if rel_path.is_absolute()
        || rel_path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(format!("workspace path escapes root: {rel}"));
    }
    Ok(root.join(rel_path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use vela_protocol::frontier_repo::{self, InitOptions};
    use tempfile::tempdir;

    #[test]
    fn workspace_root_rejects_path_escape() {
        let root = Path::new("/tmp/frontier");
        assert!(workspace_root(root, "../bad").is_err());
        assert!(workspace_root(root, "vtask_bad/path").is_err());
    }

    #[test]
    fn init_workspace_creates_expected_layout() {
        let tmp = tempdir().unwrap();
        frontier_repo::initialize(
            tmp.path(),
            InitOptions {
                name: "Workspace test frontier",
                template: "disease-frontier",
                initialize_git: false,
            },
        )
        .unwrap();
        std::fs::create_dir_all(tmp.path().join("sources")).unwrap();
        std::fs::write(tmp.path().join("sources/demo.txt"), "source bytes").unwrap();
        let task = frontier_task::create_task(
            tmp.path(),
            "source_ingestion".to_string(),
            "Review a local source file.".to_string(),
            vec![
                "sources/demo.txt".to_string(),
                "doi:10.5555/demo".to_string(),
            ],
            "source_repair".to_string(),
            vec![],
            vec!["source is copied".to_string()],
            frontier_task::FrontierTaskStatus::Eligible,
        )
        .unwrap();

        let status = init_workspace(tmp.path(), &task.id).unwrap();
        assert!(status.exists);
        assert!(status.files.contains(&"task.yaml".to_string()));
        assert!(
            status
                .files
                .contains(&"frontier_snapshot_before.json".to_string())
        );
        assert_eq!(status.source_artifacts.len(), 2);
        assert_eq!(status.source_artifacts[0].status, "copied");
        assert_eq!(status.source_artifacts[1].status, "declared_only");
    }
}
