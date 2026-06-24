//! Incremental, append-only batch ingest into a `.vela/` repo.
//!
//! Motivation (Workstream A, scale architecture). The publish path and
//! `repo::save_vela_repo` re-serialize the *entire* `Project` on every
//! write: every finding, every event, every source projection is rewritten
//! even when a single new finding is appended. For a small frontier that is
//! fine. For the Erdős spine — ~1,180 proposal files and growing — a full
//! rewrite per appended batch is O(N) disk churn on an O(1) logical change,
//! and the publish path uploads the whole substrate inline.
//!
//! This module adds the *additive* primitive the rest of the scale plan is
//! built on: append a signed batch of new finding/null/event records to an
//! existing `.vela/` repo by writing ONLY the new per-record files plus the
//! new event files, never touching the records that did not change.
//!
//! Doctrine kept intact:
//!   - The `.vela/` on-disk layout is already one-file-per-record
//!     (`findings/<vf_id>.json`, `events/<vev_id>.json`, …) — see
//!     `repo::save_vela_repo`. An append therefore maps cleanly to "write
//!     the new files"; it does not invent a new storage shape.
//!   - Append is content-addressed and idempotent. A record whose id is
//!     already present on disk is skipped, so re-applying the same batch
//!     (federation re-sync, a retried agent run) is a no-op.
//!   - This is purely additive. It does NOT modify `repo::save`,
//!     `proposals::accept_proposal_in_frontier`, or the hub publish/accept
//!     boundary. A frontier written by `save_vela_repo` loads identically
//!     whether or not it was later appended to via this primitive, because
//!     `repo::load_vela_repo` reads every per-record directory the same way.
//!
//! What this primitive intentionally does NOT do (left to the phased plan
//! in `docs/superpowers/plans/2026-05-29-scale-architecture-incremental-ingest.md`):
//!   - It does not push to the hub. It mutates a local `.vela/` repo only.
//!   - It does not re-run the proposal reducer or Evidence CI gate. The
//!     records in a batch are already-materialized objects + their canonical
//!     events; the deposit-style event kinds (e.g. `finding.asserted`)
//!     carry their object inline exactly as the reducer would have emitted
//!     them. Callers that need the full proposal -> accept -> reducer
//!     pipeline still use `proposals::accept_proposal_in_frontier`.

use std::collections::BTreeSet;
use std::path::Path;

use serde::{Deserialize, Serialize};

use vela_protocol::bundle::FindingBundle;
use vela_protocol::events::StateEvent;

/// One appendable object plus the canonical event that asserts it. The
/// batch carries already-materialized records (the same shape
/// `repo::save_vela_repo` writes), not proposals — the deposit has already
/// been decided. Each variant pairs the object with its asserting event so
/// the append writes both the projection file and the event log entry in
/// one step, keeping them in lockstep exactly as a reducer replay would.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "object_kind", rename_all = "snake_case")]
pub enum AppendRecord {
    /// A new finding plus its `finding.asserted` event. The finding is
    /// written to `findings/<vf_id>.json` (its own projection file, the
    /// same one `repo::save_vela_repo` writes) and the event to
    /// `events/<vev_id>.json`.
    Finding {
        finding: Box<FindingBundle>,
        event: Box<StateEvent>,
    },
    /// An event whose object (if any) is carried inline on the event
    /// payload and materialized from the event log on load — attestations
    /// and every frontier-level observation. `repo::load_vela_repo` rebuilds
    /// these from the event stream (see `materialize_*_from_events`), so the
    /// append only needs to write the event file. No separate projection
    /// file exists for them on disk.
    EventOnly { event: Box<StateEvent> },
}

impl AppendRecord {
    /// The canonical event this record appends. Always present.
    pub fn event(&self) -> &StateEvent {
        match self {
            Self::Finding { event, .. } => event,
            Self::EventOnly { event } => event,
        }
    }
}

/// What an [`append_batch`] call actually did. Counts are the records that
/// were *newly written*; `skipped_*` are the ones already present on disk
/// (idempotent no-ops). The `event_log_tail` is the id of the last event
/// the append left on disk, so a caller can chain the next batch's
/// `before_hash`/cursor without re-reading the whole log.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AppendReport {
    pub findings_written: usize,
    pub events_written: usize,
    pub skipped_duplicate_objects: usize,
    pub skipped_duplicate_events: usize,
    pub event_log_tail: Option<String>,
}

/// Error surface for the append primitive. Deliberately small; the append
/// boundary either writes a record or rejects the whole batch on a
/// validation failure, so a batch never lands half-applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppendError {
    /// The target directory is not a `.vela/` repo (no `.vela/` subdir).
    NotARepo(String),
    /// An event in the batch failed canonical payload validation. Carries
    /// the offending event id and the validator message.
    InvalidEvent { event_id: String, reason: String },
    /// A filesystem write/read failed.
    Io(String),
}

impl std::fmt::Display for AppendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotARepo(p) => write!(f, "'{p}' is not a .vela/ repo (run `vela init` first)"),
            Self::InvalidEvent { event_id, reason } => {
                write!(f, "event {event_id} failed validation: {reason}")
            }
            Self::Io(e) => write!(f, "io: {e}"),
        }
    }
}

impl std::error::Error for AppendError {}

/// Append a batch of new records to the `.vela/` repo rooted at `dir`,
/// writing ONLY the new files. The whole `Project` is never re-serialized.
///
/// Contract:
///   1. `dir` MUST already be a `.vela/` repo. The append never creates a
///      frontier from nothing — that is `repo::init_repo`'s job.
///   2. Every event in the batch is validated against
///      `events::validate_event_payload` first. If ANY event is invalid the
///      whole batch is rejected and nothing is written (validate-then-write,
///      so a batch is all-or-nothing at the validation boundary).
///   3. Records whose object id / event id already exist on disk are
///      skipped (idempotent). This makes federation re-sync and agent
///      retries safe.
///   4. Objects are written before their events, so a crash mid-batch
///      leaves the on-disk log referencing only objects that exist (a
///      reader never sees an event whose object file is missing).
///
/// The frontier's `config.toml` and visible `frontier.json` are NOT
/// rewritten here — they carry aggregate stats that a separate
/// (cheap, O(1)-amortizable) refresh step recomputes. Keeping them out of
/// the per-batch path is the entire point: an append touches `b` new files
/// for a batch of `b` records, not `N` for a frontier of `N`.
pub fn append_batch(dir: &Path, batch: &[AppendRecord]) -> Result<AppendReport, AppendError> {
    let vela_dir = dir.join(".vela");
    if !vela_dir.is_dir() {
        return Err(AppendError::NotARepo(dir.display().to_string()));
    }

    // 1. Validate every event up front. Reject the whole batch on the first
    //    invalid event so a malformed deposit never lands a partial batch.
    for record in batch {
        let event = record.event();
        if let Err(reason) =
            vela_protocol::events::validate_event_payload(event.kind.as_str(), &event.payload)
        {
            return Err(AppendError::InvalidEvent {
                event_id: event.id.clone(),
                reason,
            });
        }
    }

    let findings_dir = vela_dir.join("findings");
    let events_dir = vela_dir.join("events");
    for d in [&findings_dir, &events_dir] {
        std::fs::create_dir_all(d).map_err(|e| AppendError::Io(e.to_string()))?;
    }

    // Pre-read the existing ids in each touched directory ONCE so the
    // idempotency check is O(batch) filesystem reads, not O(batch * dir).
    let existing_findings = existing_ids(&findings_dir)?;
    let existing_events = existing_ids(&events_dir)?;

    let mut report = AppendReport::default();
    // Track ids written in this batch too, so a batch that carries the same
    // id twice writes it once (intra-batch idempotency).
    let mut wrote_findings: BTreeSet<String> = BTreeSet::new();
    let mut wrote_events: BTreeSet<String> = BTreeSet::new();

    for record in batch {
        match record {
            AppendRecord::Finding { finding, event } => {
                let id = finding.id.clone();
                if existing_findings.contains(&id) || wrote_findings.contains(&id) {
                    report.skipped_duplicate_objects += 1;
                } else {
                    write_json(&findings_dir, &id, finding.as_ref())?;
                    wrote_findings.insert(id);
                    report.findings_written += 1;
                }
                write_event(
                    &events_dir,
                    event,
                    &existing_events,
                    &mut wrote_events,
                    &mut report,
                )?;
            }
            AppendRecord::EventOnly { event } => {
                write_event(
                    &events_dir,
                    event,
                    &existing_events,
                    &mut wrote_events,
                    &mut report,
                )?;
            }
        }
    }

    report.event_log_tail = batch.last().map(|r| r.event().id.clone());
    Ok(report)
}

/// Read the set of `<id>` stems present as `<id>.json` in a directory.
/// Missing directory ⇒ empty set (the caller already created it, but a
/// concurrent removal should degrade to "nothing present" rather than err).
fn existing_ids(dir: &Path) -> Result<BTreeSet<String>, AppendError> {
    let mut out = BTreeSet::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Ok(out);
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "json")
            && let Some(stem) = path.file_stem().and_then(|s| s.to_str())
        {
            out.insert(stem.to_string());
        }
    }
    Ok(out)
}

fn write_json<T: Serialize>(dir: &Path, id: &str, value: &T) -> Result<(), AppendError> {
    let json = serde_json::to_string_pretty(value).map_err(|e| AppendError::Io(e.to_string()))?;
    std::fs::write(dir.join(format!("{id}.json")), json).map_err(|e| AppendError::Io(e.to_string()))
}

fn write_event(
    events_dir: &Path,
    event: &StateEvent,
    existing_events: &BTreeSet<String>,
    wrote_events: &mut BTreeSet<String>,
    report: &mut AppendReport,
) -> Result<(), AppendError> {
    if existing_events.contains(&event.id) || wrote_events.contains(&event.id) {
        report.skipped_duplicate_events += 1;
        return Ok(());
    }
    write_json(events_dir, &event.id, event)?;
    wrote_events.insert(event.id.clone());
    report.events_written += 1;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use vela_protocol::bundle::*;
    use vela_protocol::events::{self, FindingEventInput, NULL_HASH};
    use vela_protocol::project;
    use vela_protocol::repo;

    fn make_finding(id: &str, score: f64) -> FindingBundle {
        FindingBundle {
            id: id.into(),
            version: 1,
            previous_version: None,
            assertion: Assertion {
                text: format!("Finding {id}"),
                assertion_type: "mechanism".into(),
                entities: vec![],
                relation: None,
                direction: None,
                causal_claim: None,
                causal_evidence_grade: None,
            },
            evidence: Evidence {
                evidence_type: "experimental".into(),
                model_system: String::new(),
                method: String::new(),
                replicated: false,
                replication_count: None,
                evidence_spans: vec![],
            },
            conditions: Conditions {
                text: String::new(),
                duration: None,
            },
            confidence: Confidence::raw(score, "seeded prior", 0.85),
            provenance: Provenance {
                source_type: "published_paper".into(),
                doi: None,
                url: None,
                title: "Test".into(),
                authors: vec![],
                year: Some(2024),
                license: None,
                publisher: None,
                funders: vec![],
                extraction: Extraction::default(),
                review: None,
            },
            flags: Flags {
                gap: false,
                negative_space: false,
                contested: false,
                retracted: false,
                declining: false,
                gravity_well: false,
                review_state: None,
                superseded: false,
                signature_threshold: None,
                jointly_accepted: false,
            },
            links: vec![],
            annotations: vec![],
            attachments: vec![],
            created: String::new(),
            updated: None,
            access_tier: vela_protocol::access_tier::AccessTier::Public,
        }
    }

    /// Build a `finding.asserted` event for `finding` against a frontier
    /// in which it is the newest record (its after_hash is the finding's
    /// own hash). Mirrors `proposals::apply_add`'s event shape.
    fn assert_event(finding: &FindingBundle, proposal_id: &str) -> StateEvent {
        let after_hash = events::finding_hash(finding);
        events::new_finding_event(FindingEventInput {
            kind: "finding.asserted",
            finding_id: &finding.id,
            actor_id: "reviewer:test",
            actor_type: "human",
            reason: "append batch test",
            before_hash: NULL_HASH,
            after_hash: &after_hash,
            payload: serde_json::json!({ "proposal_id": proposal_id }),
            caveats: vec![],
            timestamp: None,
        })
    }

    fn init_repo_with(findings: Vec<FindingBundle>) -> (TempDir, std::path::PathBuf) {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("frontier");
        let proj = project::assemble("append-test", findings, 1, 0, "test");
        repo::init_repo(&dir, &proj).unwrap();
        (tmp, dir)
    }

    #[test]
    fn append_writes_only_new_files_and_loads_back() {
        // Seed a repo with one finding.
        let f0 = make_finding("vf_000", 0.7);
        let (_tmp, dir) = init_repo_with(vec![f0.clone()]);

        // Capture the seed finding's on-disk bytes; the append must not
        // touch it.
        let f0_path = dir.join(".vela/findings/vf_000.json");
        let f0_bytes_before = std::fs::read(&f0_path).unwrap();

        // Append two new findings, each with its asserting event.
        let f1 = make_finding("vf_001", 0.8);
        let f2 = make_finding("vf_002", 0.6);
        let batch = vec![
            AppendRecord::Finding {
                finding: Box::new(f1.clone()),
                event: Box::new(assert_event(&f1, "vpr_a")),
            },
            AppendRecord::Finding {
                finding: Box::new(f2.clone()),
                event: Box::new(assert_event(&f2, "vpr_b")),
            },
        ];
        let report = append_batch(&dir, &batch).unwrap();
        assert_eq!(report.findings_written, 2);
        assert_eq!(report.events_written, 2);
        assert_eq!(report.skipped_duplicate_objects, 0);

        // The seed finding's file is byte-for-byte unchanged — proof the
        // append did not re-serialize unrelated state.
        assert_eq!(std::fs::read(&f0_path).unwrap(), f0_bytes_before);

        // The appended records load through the normal repo loader, which
        // reads every per-record directory. No special append-aware reader
        // is required.
        let loaded = repo::load_from_path(&dir).unwrap();
        let ids: BTreeSet<String> = loaded.findings.iter().map(|f| f.id.clone()).collect();
        assert_eq!(
            ids,
            ["vf_000", "vf_001", "vf_002"]
                .iter()
                .map(|s| s.to_string())
                .collect()
        );
        // Both new events are on the log.
        let event_ids: BTreeSet<String> = loaded.events.iter().map(|e| e.id.clone()).collect();
        for r in &batch {
            assert!(event_ids.contains(&r.event().id));
        }
    }

    #[test]
    fn append_is_idempotent_on_reapply() {
        let f0 = make_finding("vf_000", 0.7);
        let (_tmp, dir) = init_repo_with(vec![f0]);
        let f1 = make_finding("vf_001", 0.8);
        let batch = vec![AppendRecord::Finding {
            finding: Box::new(f1.clone()),
            event: Box::new(assert_event(&f1, "vpr_a")),
        }];

        let first = append_batch(&dir, &batch).unwrap();
        assert_eq!(first.findings_written, 1);
        assert_eq!(first.events_written, 1);

        // Re-apply the exact same batch: nothing new is written.
        let second = append_batch(&dir, &batch).unwrap();
        assert_eq!(second.findings_written, 0);
        assert_eq!(second.events_written, 0);
        assert_eq!(second.skipped_duplicate_objects, 1);
        assert_eq!(second.skipped_duplicate_events, 1);

        // The frontier still has exactly one appended finding (no dup).
        let loaded = repo::load_from_path(&dir).unwrap();
        assert_eq!(
            loaded.findings.iter().filter(|f| f.id == "vf_001").count(),
            1
        );
    }

    #[test]
    fn invalid_event_rejects_whole_batch() {
        let f0 = make_finding("vf_000", 0.7);
        let (_tmp, dir) = init_repo_with(vec![f0]);

        let f1 = make_finding("vf_001", 0.8);
        let mut bad_event = assert_event(&f1, "vpr_a");
        // finding.asserted requires payload.proposal_id; strip it.
        bad_event.payload = serde_json::json!({});

        let f2 = make_finding("vf_002", 0.6);
        let batch = vec![
            AppendRecord::Finding {
                finding: Box::new(f2.clone()),
                event: Box::new(assert_event(&f2, "vpr_b")),
            },
            AppendRecord::Finding {
                finding: Box::new(f1.clone()),
                event: Box::new(bad_event),
            },
        ];

        let err = append_batch(&dir, &batch).unwrap_err();
        assert!(matches!(err, AppendError::InvalidEvent { .. }));

        // Validate-then-write: the valid record (vf_002) in the same batch
        // must NOT have landed, because the batch is rejected as a whole.
        assert!(!dir.join(".vela/findings/vf_002.json").exists());
    }

    #[test]
    fn append_rejects_non_repo_dir() {
        let tmp = TempDir::new().unwrap();
        let plain = tmp.path().join("not-a-repo");
        std::fs::create_dir_all(&plain).unwrap();
        let err = append_batch(&plain, &[]).unwrap_err();
        assert!(matches!(err, AppendError::NotARepo(_)));
    }
}
