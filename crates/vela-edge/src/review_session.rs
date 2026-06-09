//! Local reviewer sessions.
//!
//! A review session records outside reviewer work over local frontier
//! objects. It is operational state under `.vela/review_sessions/`;
//! it does not mutate accepted frontier truth state.

use vela_protocol::canonical;

use vela_protocol::repo;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::str::FromStr;

pub const REVIEW_SESSION_SCHEMA: &str = "vela.review_session.v0.1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ReviewSessionStatus {
    Open,
    Accepted,
    Rejected,
    NeedsRevision,
    Closed,
}

impl ReviewSessionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::NeedsRevision => "needs_revision",
            Self::Closed => "closed",
        }
    }

    pub fn is_terminal(self) -> bool {
        !matches!(self, Self::Open)
    }
}

impl std::fmt::Display for ReviewSessionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ReviewSessionStatus {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim() {
            "open" => Ok(Self::Open),
            "accepted" | "accept" => Ok(Self::Accepted),
            "rejected" | "reject" => Ok(Self::Rejected),
            "needs_revision" | "revision_requested" | "revise" => Ok(Self::NeedsRevision),
            "closed" => Ok(Self::Closed),
            other => Err(format!(
                "review session decision must be accepted, rejected, needs_revision, or closed; got `{other}`"
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReviewSessionSeed {
    pub frontier_id: String,
    pub reviewer_id: String,
    pub scope: String,
    pub started_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReviewSessionNote {
    pub object_id: String,
    pub note: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReviewSessionDecision {
    pub decision: ReviewSessionStatus,
    pub reason: String,
    pub decided_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReviewSession {
    pub schema: String,
    pub id: String,
    pub frontier_id: String,
    pub reviewer_id: String,
    pub scope: String,
    pub status: ReviewSessionStatus,
    pub started_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<String>,
    #[serde(default)]
    pub objects_reviewed: Vec<String>,
    #[serde(default)]
    pub notes: Vec<ReviewSessionNote>,
    #[serde(default)]
    pub decisions: Vec<ReviewSessionDecision>,
    #[serde(default)]
    pub unresolved_objections: Vec<String>,
    #[serde(default)]
    pub follow_up_tasks: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transcript_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReviewSessionList {
    pub ok: bool,
    pub frontier_id: String,
    pub frontier_path: String,
    pub total: usize,
    pub open: usize,
    pub terminal: usize,
    #[serde(default)]
    pub sessions: Vec<ReviewSession>,
}

pub fn start(
    frontier_path: &Path,
    reviewer_id: String,
    scope: String,
    transcript_path: Option<PathBuf>,
) -> Result<ReviewSession, String> {
    let root = repo_root(frontier_path)?;
    let project = repo::load_from_path(&root)?;
    let started_at = chrono::Utc::now().to_rfc3339();
    let seed = ReviewSessionSeed {
        frontier_id: project.frontier_id(),
        reviewer_id: validate_reviewer(reviewer_id)?,
        scope: non_empty("scope", scope)?,
        started_at: started_at.clone(),
    };
    let id = derive_session_id(&seed)?;
    let session = ReviewSession {
        schema: REVIEW_SESSION_SCHEMA.to_string(),
        id,
        frontier_id: seed.frontier_id,
        reviewer_id: seed.reviewer_id,
        scope: seed.scope,
        status: ReviewSessionStatus::Open,
        started_at,
        ended_at: None,
        objects_reviewed: Vec::new(),
        notes: Vec::new(),
        decisions: Vec::new(),
        unresolved_objections: Vec::new(),
        follow_up_tasks: Vec::new(),
        transcript_path: transcript_path.map(|p| p.display().to_string()),
    };
    write_session(&root, &session, false)?;
    Ok(session)
}

pub fn add_note(
    frontier_path: &Path,
    session_id: &str,
    object_id: String,
    note: String,
) -> Result<ReviewSession, String> {
    let root = repo_root(frontier_path)?;
    let mut session = load(&root, session_id)?;
    if session.status.is_terminal() {
        return Err(format!(
            "review session {} is {}; reopen is not supported",
            session.id, session.status
        ));
    }
    let object_id = non_empty("object", object_id)?;
    if !session.objects_reviewed.contains(&object_id) {
        session.objects_reviewed.push(object_id.clone());
        session.objects_reviewed.sort();
    }
    session.notes.push(ReviewSessionNote {
        object_id,
        note: non_empty("note", note)?,
        created_at: chrono::Utc::now().to_rfc3339(),
    });
    write_session(&root, &session, true)?;
    Ok(session)
}

pub fn close(
    frontier_path: &Path,
    session_id: &str,
    decision: ReviewSessionStatus,
    reason: String,
    follow_up_tasks: Vec<String>,
) -> Result<ReviewSession, String> {
    if !decision.is_terminal() {
        return Err("review session close requires a terminal decision".to_string());
    }
    let root = repo_root(frontier_path)?;
    let mut session = load(&root, session_id)?;
    if session.status.is_terminal() {
        return Err(format!("review session {} is already closed", session.id));
    }
    let decided_at = chrono::Utc::now().to_rfc3339();
    session.status = decision;
    session.ended_at = Some(decided_at.clone());
    session.decisions.push(ReviewSessionDecision {
        decision,
        reason: non_empty("reason", reason)?,
        decided_at,
    });
    for task in clean_list(follow_up_tasks) {
        if !session.follow_up_tasks.contains(&task) {
            session.follow_up_tasks.push(task);
        }
    }
    session.follow_up_tasks.sort();
    write_session(&root, &session, true)?;
    Ok(session)
}

pub fn list(frontier_path: &Path) -> Result<ReviewSessionList, String> {
    let root = repo_root(frontier_path)?;
    let project = repo::load_from_path(&root)?;
    let mut sessions = Vec::new();
    let dir = sessions_dir(&root);
    if dir.is_dir() {
        for entry in std::fs::read_dir(&dir)
            .map_err(|e| format!("read review sessions directory {}: {e}", dir.display()))?
        {
            let entry = entry.map_err(|e| format!("read review session entry: {e}"))?;
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "json") {
                sessions.push(read_session_file(&path)?);
            }
        }
    }
    sessions.sort_by(|a, b| {
        a.status
            .cmp(&b.status)
            .then_with(|| b.started_at.cmp(&a.started_at))
            .then_with(|| a.id.cmp(&b.id))
    });
    let open = sessions
        .iter()
        .filter(|session| !session.status.is_terminal())
        .count();
    let terminal = sessions.len().saturating_sub(open);
    Ok(ReviewSessionList {
        ok: true,
        frontier_id: project.frontier_id(),
        frontier_path: root.display().to_string(),
        total: sessions.len(),
        open,
        terminal,
        sessions,
    })
}

pub fn load(frontier_path: &Path, session_id: &str) -> Result<ReviewSession, String> {
    let root = repo_root(frontier_path)?;
    let id = validate_session_id(session_id)?;
    read_session_file(&sessions_dir(&root).join(format!("{id}.json")))
}

pub fn derive_session_id(seed: &ReviewSessionSeed) -> Result<String, String> {
    let hash = canonical::sha256_canonical(seed)?;
    Ok(format!("vrs_{}", &hash[..16]))
}

pub fn sessions_dir(frontier_root: &Path) -> PathBuf {
    frontier_root.join(".vela").join("review_sessions")
}

fn repo_root(frontier_path: &Path) -> Result<PathBuf, String> {
    match repo::detect(frontier_path)? {
        repo::VelaSource::VelaRepo(root) => Ok(root),
        repo::VelaSource::ProjectFile(_) | repo::VelaSource::PacketDir(_) => Err(format!(
            "review sessions require a local .vela/ repository; got {}",
            frontier_path.display()
        )),
    }
}

fn write_session(root: &Path, session: &ReviewSession, overwrite: bool) -> Result<(), String> {
    validate_session_id(&session.id)?;
    let dir = sessions_dir(root);
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("create review sessions directory {}: {e}", dir.display()))?;
    let path = dir.join(format!("{}.json", session.id));
    if path.exists() && !overwrite {
        return Err(format!(
            "review session {} already exists at {}",
            session.id,
            path.display()
        ));
    }
    let body = serde_json::to_string_pretty(session)
        .map_err(|e| format!("serialize review session {}: {e}", session.id))?;
    std::fs::write(&path, format!("{body}\n"))
        .map_err(|e| format!("write review session {}: {e}", path.display()))
}

fn read_session_file(path: &Path) -> Result<ReviewSession, String> {
    let body = std::fs::read_to_string(path)
        .map_err(|e| format!("read review session {}: {e}", path.display()))?;
    let session: ReviewSession = serde_json::from_str(&body)
        .map_err(|e| format!("parse review session {}: {e}", path.display()))?;
    validate_session_id(&session.id)?;
    Ok(session)
}

fn validate_session_id(session_id: &str) -> Result<String, String> {
    let ok = session_id.starts_with("vrs_")
        && session_id.len() == "vrs_".len() + 16
        && session_id["vrs_".len()..]
            .chars()
            .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase());
    if ok {
        Ok(session_id.to_string())
    } else {
        Err(format!("invalid review session id `{session_id}`"))
    }
}

fn validate_reviewer(reviewer: String) -> Result<String, String> {
    let reviewer = non_empty("reviewer", reviewer)?;
    if reviewer.contains(':') {
        Ok(reviewer)
    } else {
        Err("reviewer must be a typed id such as reviewer:external".to_string())
    }
}

fn non_empty(label: &str, value: String) -> Result<String, String> {
    let trimmed = value.trim().to_string();
    if trimmed.is_empty() {
        Err(format!("review session {label} is required"))
    } else {
        Ok(trimmed)
    }
}

fn clean_list(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use vela_protocol::frontier_repo::{self, InitOptions};
    use tempfile::TempDir;

    #[test]
    fn session_lifecycle_is_local() {
        let tmp = TempDir::new().unwrap();
        frontier_repo::initialize(
            tmp.path(),
            InitOptions {
                name: "Review session frontier",
                template: "adoption-frontier",
                initialize_git: false,
            },
        )
        .unwrap();
        let session = start(
            tmp.path(),
            "reviewer:external".to_string(),
            "diff_pack:vsd_demo".to_string(),
            None,
        )
        .unwrap();
        assert!(session.id.starts_with("vrs_"));
        let session = add_note(
            tmp.path(),
            &session.id,
            "vsd_demo".to_string(),
            "Source locator needs review.".to_string(),
        )
        .unwrap();
        assert_eq!(session.notes.len(), 1);
        assert_eq!(session.objects_reviewed, vec!["vsd_demo"]);
        let session = close(
            tmp.path(),
            &session.id,
            ReviewSessionStatus::NeedsRevision,
            "Source locator needs review before acceptance.".to_string(),
            vec!["vtask_1234567890abcdef".to_string()],
        )
        .unwrap();
        assert_eq!(session.status, ReviewSessionStatus::NeedsRevision);
        assert!(session.ended_at.is_some());
        let list = list(tmp.path()).unwrap();
        assert_eq!(list.total, 1);
        assert_eq!(list.terminal, 1);
    }

    #[test]
    fn typed_reviewer_required() {
        let tmp = TempDir::new().unwrap();
        frontier_repo::initialize(
            tmp.path(),
            InitOptions {
                name: "Review session frontier",
                template: "adoption-frontier",
                initialize_git: false,
            },
        )
        .unwrap();
        assert!(
            start(
                tmp.path(),
                "external".to_string(),
                "diff_pack:vsd_demo".to_string(),
                None,
            )
            .is_err()
        );
    }
}
