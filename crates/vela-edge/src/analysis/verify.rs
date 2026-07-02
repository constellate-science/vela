//! The one strict-verification bundle: what it means for a frontier
//! directory to BE its signed state, defined once and consumed everywhere
//! (the hub's git ingestor today; any future indexer or tool tomorrow).
//!
//! Three passes, in order, all mandatory, no degradation:
//!
//! 1. **Validation** — content-address re-derivation and schema shape for
//!    every object; a tampered signed event fails "id does not re-derive"
//!    here or in pass 2.
//! 2. **Strict reducer replay** — the loader deliberately DEGRADES a replay
//!    failure to a warning (a broken log must stay loadable for repair);
//!    an index must not, so the reducer replay is re-run strictly and its
//!    rejection propagates. The replay report must also reproduce the
//!    materialized state.
//! 3. **Signature signals** — every error-severity signal (including every
//!    event-signature failure from a registered actor) refuses.
//!
//! The frontier must also DECLARE its identity: a project that replays to
//! no `frontier_id` is not a verifiable frontier, it is a pile of files.

use std::path::Path;
use vela_protocol::project::Project;

/// Load a frontier directory and hold it to the full strict bar.
/// Returns the loaded project and its (required) frontier id.
pub fn verify_frontier_strict(dir: &Path) -> Result<(Project, String), String> {
    let validation = crate::validate::validate(dir);
    if !validation.errors.is_empty() {
        let first = validation
            .errors
            .iter()
            .take(3)
            .map(|e| format!("{}: {}", e.file, e.error))
            .collect::<Vec<_>>()
            .join(" | ");
        return Err(format!(
            "validation failed ({} error(s)): {first}",
            validation.errors.len()
        ));
    }

    let project =
        vela_protocol::repo::load_from_path(dir).map_err(|e| format!("load/replay failed: {e}"))?;

    let Some(frontier_id) = project.frontier_id.clone() else {
        return Err(
            "the directory replays to no frontier_id — not a verifiable frontier".to_string(),
        );
    };

    vela_protocol::reducer::replayed_projection(&project)
        .map_err(|e| format!("event-log replay rejected: {e}"))?;

    let replay = vela_protocol::events::replay_report(&project);
    if replay.status != "ok" {
        return Err(format!(
            "replay verification failed: {} ({} conflict(s))",
            replay.status,
            replay.conflicts.len()
        ));
    }

    let signals = crate::signals::analyze(&project, &[]);
    let errors: Vec<String> = signals
        .signals
        .iter()
        .filter(|s| s.severity == "error")
        .map(|s| format!("{}: {}", s.kind, s.reason))
        .collect();
    if !errors.is_empty() {
        return Err(format!(
            "strict verification failed ({} error signal(s)): {}",
            errors.len(),
            errors.join(" | ")
        ));
    }

    Ok((project, frontier_id))
}
