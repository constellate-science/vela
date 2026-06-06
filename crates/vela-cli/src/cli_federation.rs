//! `cmd_federation` and its handler logic, split out of cli.rs.

use crate::cli::{cmd_federation_push_resolution, fail, fail_return};
use crate::cli_commands::*;
use vela_protocol::cli_style as style;
use vela_protocol::repo;

use colored::Colorize;
use serde_json::json;

/// v0.39: Manage the federation peer registry.
pub(crate) fn cmd_federation(action: FederationAction) {
    use vela_protocol::federation::PeerHub;

    match action {
        FederationAction::PeerAdd {
            frontier,
            id,
            url,
            pubkey,
            note,
            json,
        } => {
            let peer = PeerHub {
                id: id.clone(),
                url: url.clone(),
                public_key: pubkey.trim().to_string(),
                added_at: chrono::Utc::now().to_rfc3339(),
                note: note.clone(),
            };
            peer.validate().unwrap_or_else(|e| fail_return(&e));

            let mut project = repo::load_from_path(&frontier).unwrap_or_else(|e| fail_return(&e));
            if project.peers.iter().any(|p| p.id == id) {
                fail(&format!("peer '{id}' already in registry"));
            }
            project.peers.push(peer.clone());
            repo::save_to_path(&frontier, &project).unwrap_or_else(|e| fail_return(&e));

            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": true,
                        "command": "federation.peer-add",
                        "frontier": frontier.display().to_string(),
                        "peer": peer,
                        "registered_count": project.peers.len(),
                    }))
                    .expect("serialize federation.peer-add")
                );
            } else {
                println!(
                    "{} peer {} (pubkey {}…) at {}",
                    style::ok("registered"),
                    id,
                    &peer.public_key[..16],
                    peer.url
                );
            }
        }
        FederationAction::PeerList { frontier, json } => {
            let project = repo::load_from_path(&frontier).unwrap_or_else(|e| fail_return(&e));
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": true,
                        "command": "federation.peer-list",
                        "frontier": frontier.display().to_string(),
                        "peers": project.peers,
                    }))
                    .expect("serialize federation.peer-list")
                );
            } else {
                println!();
                println!(
                    "  {}",
                    format!("VELA · FEDERATION · PEERS · {}", frontier.display())
                        .to_uppercase()
                        .dimmed()
                );
                println!("  {}", style::tick_row(60));
                if project.peers.is_empty() {
                    println!("  (no peers registered)");
                } else {
                    for p in &project.peers {
                        let note_suffix = if p.note.is_empty() {
                            String::new()
                        } else {
                            format!("  · {}", p.note)
                        };
                        println!(
                            "  {:<24}  {}  {}…{note_suffix}",
                            p.id,
                            p.url,
                            &p.public_key[..16]
                        );
                    }
                }
            }
        }
        FederationAction::Sync {
            frontier,
            peer_id,
            url,
            via_hub,
            vfr_id,
            allow_cross_vfr,
            dry_run,
            json,
        } => {
            use vela_protocol::federation::{self, DiscoveryResult};

            let mut project = repo::load_from_path(&frontier).unwrap_or_else(|e| fail_return(&e));
            let Some(peer) = project.peers.iter().find(|p| p.id == peer_id).cloned() else {
                fail(&format!(
                    "peer '{peer_id}' not in registry; run `vela federation peer add` first"
                ));
            };
            let local_frontier_id = project.frontier_id();

            // v0.64: refuse cross-vfr sync without explicit opt-in.
            // The substrate path is honest about cross-vfr divergence
            // (every peer-side finding becomes a "missing_locally"
            // conflict), but in practice that floods the inbox with
            // noise. The intended use of `--via-hub --vfr-id` is to
            // sync against your OWN frontier_id on the peer hub.
            if via_hub
                && let Some(target) = vfr_id.as_deref()
                && target != local_frontier_id
                && !allow_cross_vfr
            {
                fail(&format!(
                    "cross-vfr sync refused: --vfr-id {target} differs from local frontier_id {local_frontier_id}. \
                     Pass --allow-cross-vfr to opt in (every peer-side finding will be recorded as a \
                     missing_locally conflict). Or omit --vfr-id to default to the local frontier id."
                ));
            }

            // v0.41.0: three sync modes (via-hub / direct-url / default-manifest-path).
            #[derive(Debug)]
            enum SyncOutcome {
                Resolved(vela_protocol::project::Project, String), // (peer state, source description)
                BrokenLocator(String, String, u16),        // (vfr_id, locator, status)
                UnverifiedEntry(String, String),           // (vfr_id, reason)
                EntryNotFound(String, u16),
            }

            let outcome = if via_hub {
                let target_vfr = vfr_id.clone().unwrap_or_else(|| local_frontier_id.clone());
                match federation::discover_peer_frontier(
                    &peer.url,
                    &target_vfr,
                    Some(&peer.public_key),
                ) {
                    DiscoveryResult::Resolved(p) => {
                        let src =
                            format!("{}/entries/{}", peer.url.trim_end_matches('/'), target_vfr);
                        SyncOutcome::Resolved(p, src)
                    }
                    DiscoveryResult::BrokenLocator {
                        vfr_id,
                        locator,
                        status,
                    } => SyncOutcome::BrokenLocator(vfr_id, locator, status),
                    DiscoveryResult::UnverifiedEntry { vfr_id, reason } => {
                        SyncOutcome::UnverifiedEntry(vfr_id, reason)
                    }
                    DiscoveryResult::EntryNotFound { vfr_id, status } => {
                        SyncOutcome::EntryNotFound(vfr_id, status)
                    }
                    DiscoveryResult::Unreachable { url, error } => {
                        fail(&format!("peer hub unreachable ({url}): {error}"));
                    }
                }
            } else {
                let resolved_url = url.unwrap_or_else(|| {
                    let base = peer.url.trim_end_matches('/');
                    format!("{base}/manifest/{local_frontier_id}.json")
                });
                match federation::fetch_peer_frontier(&resolved_url) {
                    Ok(p) => SyncOutcome::Resolved(p, resolved_url),
                    Err(e) => fail(&format!("direct fetch failed: {e}")),
                }
            };

            // Handle the non-resolved cases by emitting a single
            // synthetic conflict event and a sync record.
            let peer_source: String;
            let peer_state = match outcome {
                SyncOutcome::Resolved(p, src) => {
                    if !json {
                        println!("  · resolved via {src}");
                    }
                    peer_source = src;
                    p
                }
                SyncOutcome::BrokenLocator(vfr, locator, status) => {
                    if dry_run {
                        if json {
                            println!(
                                "{}",
                                serde_json::to_string_pretty(&json!({
                                    "ok": true,
                                    "command": "federation.sync",
                                    "dry_run": true,
                                    "outcome": "broken_locator",
                                    "vfr_id": vfr,
                                    "locator": locator,
                                    "http_status": status,
                                }))
                                .expect("serialize")
                            );
                        } else {
                            println!(
                                "{} dry-run: peer entry resolved but locator dead",
                                style::warn("broken_locator")
                            );
                            println!("  vfr_id:  {vfr}");
                            println!("  locator: {locator} (HTTP {status})");
                        }
                        return;
                    }
                    let report = federation::record_locator_failure(
                        &mut project,
                        &peer_id,
                        &vfr,
                        &locator,
                        status,
                    );
                    repo::save_to_path(&frontier, &project).unwrap_or_else(|e| fail_return(&e));
                    if json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json!({
                                "ok": true,
                                "command": "federation.sync",
                                "outcome": "broken_locator",
                                "report": report,
                            }))
                            .expect("serialize")
                        );
                    } else {
                        println!(
                            "{} sync recorded broken-locator conflict against {peer_id}",
                            style::warn("broken_locator")
                        );
                        println!("  vfr_id:  {vfr}");
                        println!("  locator: {locator} (HTTP {status})");
                        println!("  events appended: {}", report.events_appended);
                    }
                    return;
                }
                SyncOutcome::UnverifiedEntry(vfr, reason) => {
                    if dry_run {
                        if json {
                            println!(
                                "{}",
                                serde_json::to_string_pretty(&json!({
                                    "ok": true,
                                    "command": "federation.sync",
                                    "dry_run": true,
                                    "outcome": "unverified_peer_entry",
                                    "vfr_id": vfr,
                                    "reason": reason,
                                }))
                                .expect("serialize")
                            );
                        } else {
                            println!(
                                "{} dry-run: peer entry signature did not verify",
                                style::lost("unverified_peer_entry")
                            );
                            println!("  vfr_id: {vfr}");
                            println!("  reason: {reason}");
                        }
                        return;
                    }
                    let report =
                        federation::record_unverified_entry(&mut project, &peer_id, &vfr, &reason);
                    repo::save_to_path(&frontier, &project).unwrap_or_else(|e| fail_return(&e));
                    if json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json!({
                                "ok": true,
                                "command": "federation.sync",
                                "outcome": "unverified_peer_entry",
                                "report": report,
                            }))
                            .expect("serialize")
                        );
                    } else {
                        println!(
                            "{} sync halted; peer's registry entry signature did not verify",
                            style::lost("unverified_peer_entry")
                        );
                        println!("  vfr_id: {vfr}");
                        println!("  reason: {reason}");
                    }
                    return;
                }
                SyncOutcome::EntryNotFound(vfr, status) => {
                    if json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json!({
                                "ok": false,
                                "command": "federation.sync",
                                "outcome": "entry_not_found",
                                "vfr_id": vfr,
                                "http_status": status,
                            }))
                            .expect("serialize")
                        );
                    } else {
                        println!(
                            "{} peer's hub does not publish vfr_id {vfr} (HTTP {status})",
                            style::warn("entry_not_found")
                        );
                    }
                    return;
                }
            };

            if dry_run {
                let conflicts = federation::diff_frontiers(&project, &peer_state);
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&json!({
                            "ok": true,
                            "command": "federation.sync",
                            "dry_run": true,
                            "peer_id": peer_id,
                            "peer_source": peer_source,
                            "conflicts": conflicts,
                        }))
                        .expect("serialize federation.sync (dry-run)")
                    );
                } else {
                    println!(
                        "{} dry-run vs {peer_id} ({}): {} conflict(s)",
                        style::ok("ok"),
                        peer_source,
                        conflicts.len()
                    );
                    for c in &conflicts {
                        println!("  · {} {} {}", c.kind.as_str(), c.finding_id, c.detail);
                    }
                }
                return;
            }

            let report = federation::sync_with_peer(&mut project, &peer_id, &peer_state);
            repo::save_to_path(&frontier, &project).unwrap_or_else(|e| fail_return(&e));

            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": true,
                        "command": "federation.sync",
                        "peer_id": peer_id,
                        "peer_source": peer_source,
                        "report": report,
                    }))
                    .expect("serialize federation.sync")
                );
            } else {
                println!(
                    "{} synced with {} ({})",
                    style::ok("ok"),
                    peer_id,
                    peer_source
                );
                println!(
                    "  our:    {}",
                    &report.our_snapshot_hash[..16.min(report.our_snapshot_hash.len())]
                );
                println!(
                    "  peer:   {}",
                    &report.peer_snapshot_hash[..16.min(report.peer_snapshot_hash.len())]
                );
                println!(
                    "  conflicts: {}  events appended: {}",
                    report.conflicts.len(),
                    report.events_appended
                );
                for c in &report.conflicts {
                    println!("  · {} {} {}", c.kind.as_str(), c.finding_id, c.detail);
                }
            }
        }
        FederationAction::PushResolution {
            frontier,
            conflict_event_id,
            to,
            key,
            vfr_id,
            json,
        } => {
            cmd_federation_push_resolution(frontier, conflict_event_id, to, key, vfr_id, json);
        }
        FederationAction::PeerRemove { frontier, id, json } => {
            let mut project = repo::load_from_path(&frontier).unwrap_or_else(|e| fail_return(&e));
            let before = project.peers.len();
            project.peers.retain(|p| p.id != id);
            if project.peers.len() == before {
                fail(&format!("peer '{id}' not found in registry"));
            }
            repo::save_to_path(&frontier, &project).unwrap_or_else(|e| fail_return(&e));

            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": true,
                        "command": "federation.peer-remove",
                        "frontier": frontier.display().to_string(),
                        "removed": id,
                        "remaining": project.peers.len(),
                    }))
                    .expect("serialize federation.peer-remove")
                );
            } else {
                println!(
                    "{} peer {} ({} remaining)",
                    style::ok("removed"),
                    id,
                    project.peers.len()
                );
            }
        }
    }
}
