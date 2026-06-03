//! Review import compatibility for frontier proof packets and legacy review bundles.

use std::path::Path;

use serde::Deserialize;

use crate::bundle::ReviewEvent;
use crate::events::StateEvent;
use crate::project::Project;
use crate::repo;

#[derive(Debug)]
pub struct ReviewImportReport {
    pub source: String,
    pub imported: usize,
    pub new: usize,
    pub duplicate: usize,
    pub events_imported: usize,
    pub events_new: usize,
    pub events_duplicate: usize,
}

impl std::fmt::Display for ReviewImportReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Imported reviews from {}\n  {} review events imported ({} new, {} duplicate)\n  {} canonical events imported ({} new, {} duplicate)",
            self.source,
            self.imported,
            self.new,
            self.duplicate,
            self.events_imported,
            self.events_new,
            self.events_duplicate,
        )
    }
}

#[derive(Debug, Deserialize)]
struct PacketManifestHeader {
    packet_format: String,
}

pub fn import_review_events(source: &Path, target: &Path) -> Result<ReviewImportReport, String> {
    let review_result = load_review_events_from_path(source);
    let state_result = load_state_events_from_path(source);
    if review_result.is_err() && state_result.is_err() {
        return Err(format!(
            "Failed to import review or state events from {}: {}; {}",
            source.display(),
            review_result
                .err()
                .unwrap_or_else(|| "review parse failed".to_string()),
            state_result
                .err()
                .unwrap_or_else(|| "state event parse failed".to_string())
        ));
    }
    let review_events = review_result.unwrap_or_default();
    let state_events = state_result.unwrap_or_default();
    let mut frontier: Project =
        repo::load_from_path(target).map_err(|e| format!("Failed to load target frontier: {e}"))?;

    let existing_ids: std::collections::HashSet<String> = frontier
        .review_events
        .iter()
        .map(|event| event.id.clone())
        .collect();
    let imported = review_events.len();
    let mut new_count = 0usize;
    let mut duplicate_count = 0usize;

    for event in review_events {
        if existing_ids.contains(&event.id) {
            duplicate_count += 1;
        } else {
            frontier.review_events.push(event);
            new_count += 1;
        }
    }

    let existing_event_ids: std::collections::HashSet<String> = frontier
        .events
        .iter()
        .map(|event| event.id.clone())
        .collect();
    let events_imported = state_events.len();
    let mut events_new = 0usize;
    let mut events_duplicate = 0usize;
    for event in state_events {
        if existing_event_ids.contains(&event.id)
            || frontier.events.iter().any(|e| e.id == event.id)
        {
            events_duplicate += 1;
        } else {
            frontier.events.push(event);
            events_new += 1;
        }
    }

    crate::project::recompute_stats(&mut frontier);
    repo::save_to_path(target, &frontier)
        .map_err(|e| format!("Failed to save target frontier: {e}"))?;

    Ok(ReviewImportReport {
        source: source.display().to_string(),
        imported,
        new: new_count,
        duplicate: duplicate_count,
        events_imported,
        events_new,
        events_duplicate,
    })
}

fn load_review_events_from_path(source: &Path) -> Result<Vec<ReviewEvent>, String> {
    if is_packet_dir(source) {
        return load_review_events_from_json_file(&source.join("reviews/review-events.json"));
    }

    if source.is_dir() {
        let packet_style = source.join("review-events.json");
        if packet_style.is_file() {
            return load_review_events_from_json_file(&packet_style);
        }
        return Err(format!(
            "Directory {} does not look like a packet or review-events bundle",
            source.display()
        ));
    }

    load_review_events_from_json_file(source)
}

fn load_state_events_from_path(source: &Path) -> Result<Vec<StateEvent>, String> {
    if is_packet_dir(source) {
        return load_state_events_from_json_file(&source.join("events/events.json"));
    }
    if source.is_dir() {
        let event_bundle = source.join("events.json");
        if event_bundle.is_file() {
            return load_state_events_from_json_file(&event_bundle);
        }
        return Ok(Vec::new());
    }
    load_state_events_from_json_file(source)
}

fn load_state_events_from_json_file(path: &Path) -> Result<Vec<StateEvent>, String> {
    let data = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read state events {}: {e}", path.display()))?;
    if let Ok(events) = serde_json::from_str::<Vec<StateEvent>>(&data) {
        return Ok(events);
    }
    let event = serde_json::from_str::<StateEvent>(&data)
        .map_err(|e| format!("Failed to parse state event(s) {}: {e}", path.display()))?;
    Ok(vec![event])
}

fn is_packet_dir(source: &Path) -> bool {
    let manifest = source.join("manifest.json");
    if !manifest.is_file() {
        return false;
    }
    let Ok(content) = std::fs::read_to_string(&manifest) else {
        return false;
    };
    let Ok(header) = serde_json::from_str::<PacketManifestHeader>(&content) else {
        return false;
    };
    header.packet_format == "vela.frontier-packet"
}

fn load_review_events_from_json_file(path: &Path) -> Result<Vec<ReviewEvent>, String> {
    let data = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read review events {}: {e}", path.display()))?;

    if let Ok(events) = serde_json::from_str::<Vec<ReviewEvent>>(&data) {
        return Ok(events);
    }

    let event = serde_json::from_str::<ReviewEvent>(&data)
        .map_err(|e| format!("Failed to parse review event(s) {}: {e}", path.display()))?;
    Ok(vec![event])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::ReviewAction;

    #[test]
    fn import_review_events_from_json_file_merges_new_event() {
        use tempfile::TempDir;

        let tmp = TempDir::new().unwrap();
        let target = tmp.path().join("target.json");
        let frontier = crate::project::assemble("target", vec![], 0, 0, "target");
        std::fs::write(&target, serde_json::to_string_pretty(&frontier).unwrap()).unwrap();

        let review = ReviewEvent {
            id: "rev_import_001".into(),
            workspace: None,
            finding_id: "vf_test".into(),
            reviewer: "reviewer".into(),
            reviewed_at: "2026-01-01T00:00:00Z".into(),
            scope: None,
            status: Some("accepted".into()),
            action: ReviewAction::Approved,
            reason: "looks right".into(),
            evidence_considered: Vec::new(),
            state_change: None,
        };
        let source = tmp.path().join("review.json");
        std::fs::write(&source, serde_json::to_string_pretty(&review).unwrap()).unwrap();

        let report = import_review_events(&source, &target).unwrap();
        assert_eq!(report.imported, 1);
        assert_eq!(report.new, 1);
        assert_eq!(report.duplicate, 0);

        let loaded = crate::repo::load_from_path(&target).unwrap();
        assert_eq!(loaded.review_events.len(), 1);
        assert_eq!(loaded.review_events[0].id, "rev_import_001");
    }

    #[test]
    fn import_review_events_from_packet_dir_reads_review_events_bundle() {
        use tempfile::TempDir;

        let tmp = TempDir::new().unwrap();
        let packet_dir = tmp.path().join("packet");
        std::fs::create_dir_all(packet_dir.join("reviews")).unwrap();
        std::fs::write(
            packet_dir.join("manifest.json"),
            r#"{"packet_format":"vela.frontier-packet"}"#,
        )
        .unwrap();

        let review = ReviewEvent {
            id: "rev_packet_ingest_001".into(),
            workspace: Some("packet".into()),
            finding_id: "vf_packet".into(),
            reviewer: "external-reviewer".into(),
            reviewed_at: "2026-01-01T00:00:00Z".into(),
            scope: Some("bbb".into()),
            status: Some("accepted".into()),
            action: ReviewAction::Qualified {
                target: "trusted_interpretation".into(),
            },
            reason: "narrow this claim".into(),
            evidence_considered: Vec::new(),
            state_change: None,
        };
        std::fs::write(
            packet_dir.join("reviews/review-events.json"),
            serde_json::to_string_pretty(&vec![review]).unwrap(),
        )
        .unwrap();

        let target = tmp.path().join("target.json");
        let frontier = crate::project::assemble("target", vec![], 0, 0, "target");
        std::fs::write(&target, serde_json::to_string_pretty(&frontier).unwrap()).unwrap();

        let report = import_review_events(&packet_dir, &target).unwrap();
        assert_eq!(report.imported, 1);
        assert_eq!(report.new, 1);

        let loaded = crate::repo::load_from_path(&target).unwrap();
        assert_eq!(loaded.review_events.len(), 1);
        assert_eq!(loaded.review_events[0].id, "rev_packet_ingest_001");
    }
}
