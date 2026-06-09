//! `cmd_frontier` and its handler logic, split out of cli.rs.

use crate::cli::{
    cmd_frontier_audit, cmd_frontier_diff, cmd_frontier_health, cmd_frontier_release,
    cmd_frontier_releases, cmd_frontier_shards, fail, fail_return, print_json,
};
use crate::cli_commands::FrontierAction;
use vela_protocol::cli_style as style;
use vela_protocol::frontier_repo;
use vela_protocol::project;
use vela_protocol::proposals;
use colored::Colorize;
use serde_json::json;

pub(crate) fn cmd_frontier(action: FrontierAction) {
    use vela_protocol::project::ProjectDependency;
    use vela_protocol::repo;
    match action {
        FrontierAction::New {
            path,
            name,
            description,
            force,
            json,
        } => {
            if path.exists() && !force {
                fail(&format!(
                    "{} already exists; pass --force to overwrite",
                    path.display()
                ));
            }
            let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
            let project = project::Project {
                vela_version: project::VELA_SCHEMA_VERSION.to_string(),
                schema: project::VELA_SCHEMA_URL.to_string(),
                frontier_id: None,
                project: project::ProjectMeta {
                    name: name.clone(),
                    description: description.clone(),
                    compiled_at: now,
                    compiler: project::VELA_COMPILER_VERSION.to_string(),
                    papers_processed: 0,
                    errors: 0,
                    dependencies: Vec::new(),
                },
                stats: project::ProjectStats::default(),
                findings: Vec::new(),
                sources: Vec::new(),
                evidence_atoms: Vec::new(),
                condition_records: Vec::new(),
                review_events: Vec::new(),
                confidence_updates: Vec::new(),
                events: Vec::new(),
                proposals: Vec::new(),
                proof_state: proposals::ProofState::default(),
                signatures: Vec::new(),
                actors: Vec::new(),
                replications: Vec::new(),
                datasets: Vec::new(),
                code_artifacts: Vec::new(),
                artifacts: Vec::new(),
                predictions: Vec::new(),
                resolutions: Vec::new(),
                peers: Vec::new(),
                negative_results: Vec::new(),
                trajectories: Vec::new(),
                released_diff_packs: Vec::new(),
                verdict_conflicts: Vec::new(),
                contradictions: Vec::new(),
        verifier_attachments: Vec::new(),
        attempts: Vec::new(),
        attempt_resolutions: Vec::new(),
            };
            repo::save_to_path(&path, &project).unwrap_or_else(|e| fail_return(&e));
            let payload = json!({
                "ok": true,
                "command": "frontier.new",
                "path": path.display().to_string(),
                "name": name,
                "schema": project::VELA_SCHEMA_URL,
                "vela_version": env!("CARGO_PKG_VERSION"),
                "next_steps": [
                    "vela finding add <path> --assertion '...' --author 'reviewer:you' --apply",
                    "vela sign generate-keypair --out keys",
                    "vela actor add <path> reviewer:you --pubkey \"$(cat keys/public.key)\"",
                    "vela registry publish <path> --owner reviewer:you --key keys/private.key --locator <url> --to https://vela-hub.fly.dev",
                ],
            });
            if json {
                print_json(&payload);
            } else {
                println!(
                    "{} scaffolded frontier '{name}' at {}",
                    style::ok("frontier"),
                    path.display()
                );
                println!("  next steps:");
                println!(
                    "    1. vela finding add {} --assertion '...' --author 'reviewer:you' --apply",
                    path.display()
                );
                println!("    2. vela sign generate-keypair --out keys");
                println!(
                    "    3. vela actor add {} reviewer:you --pubkey \"$(cat keys/public.key)\"",
                    path.display()
                );
                println!(
                    "    4. vela registry publish {} --owner reviewer:you --key keys/private.key --locator <url> --to https://vela-hub.fly.dev",
                    path.display()
                );
            }
        }
        FrontierAction::Materialize { frontier, json } => {
            let payload = frontier_repo::materialize(&frontier).unwrap_or_else(|e| fail_return(&e));
            if json {
                print_json(&payload);
            } else {
                println!(
                    "{} materialized frontier repo at {}",
                    style::ok("frontier"),
                    frontier.display()
                );
            }
        }
        FrontierAction::AddDep {
            frontier,
            vfr_id,
            locator,
            snapshot,
            name,
            json,
        } => {
            let mut p = repo::load_from_path(&frontier).unwrap_or_else(|e| fail_return(&e));
            if p.project
                .dependencies
                .iter()
                .any(|d| d.vfr_id.as_deref() == Some(&vfr_id))
            {
                fail(&format!(
                    "cross-frontier dependency '{vfr_id}' already declared; remove it first via `vela frontier remove-dep`"
                ));
            }
            let dep = ProjectDependency {
                name: name.unwrap_or_else(|| vfr_id.clone()),
                source: "vela.hub".into(),
                version: None,
                pinned_hash: None,
                vfr_id: Some(vfr_id.clone()),
                locator: Some(locator.clone()),
                pinned_snapshot_hash: Some(snapshot.clone()),
            };
            p.project.dependencies.push(dep);
            repo::save_to_path(&frontier, &p).unwrap_or_else(|e| fail_return(&e));
            let payload = json!({
                "ok": true,
                "command": "frontier.add-dep",
                "frontier": frontier.display().to_string(),
                "vfr_id": vfr_id,
                "locator": locator,
                "pinned_snapshot_hash": snapshot,
                "declared_count": p.project.dependencies.len(),
            });
            if json {
                print_json(&payload);
            } else {
                println!(
                    "{} declared cross-frontier dep {vfr_id}",
                    style::ok("frontier")
                );
                println!("  locator:  {locator}");
                println!("  snapshot: {snapshot}");
            }
        }
        FrontierAction::ListDeps { frontier, json } => {
            let p = repo::load_from_path(&frontier).unwrap_or_else(|e| fail_return(&e));
            let deps: Vec<&ProjectDependency> = p.project.dependencies.iter().collect();
            if json {
                let payload = json!({
                    "ok": true,
                    "command": "frontier.list-deps",
                    "frontier": frontier.display().to_string(),
                    "count": deps.len(),
                    "dependencies": deps,
                });
                print_json(&payload);
            } else {
                println!();
                println!(
                    "  {}",
                    format!("VELA · FRONTIER · LIST-DEPS · {}", frontier.display())
                        .to_uppercase()
                        .dimmed()
                );
                println!("  {}", style::tick_row(60));
                if deps.is_empty() {
                    println!("  (no dependencies declared)");
                } else {
                    for d in &deps {
                        let kind = if d.is_cross_frontier() {
                            "cross-frontier"
                        } else {
                            "compile-time"
                        };
                        println!("  · {} [{kind}]", d.name);
                        if let Some(v) = &d.vfr_id {
                            println!("    vfr_id:   {v}");
                        }
                        if let Some(l) = &d.locator {
                            println!("    locator:  {l}");
                        }
                        if let Some(s) = &d.pinned_snapshot_hash {
                            println!("    snapshot: {s}");
                        }
                    }
                }
            }
        }
        FrontierAction::RemoveDep {
            frontier,
            vfr_id,
            json,
        } => {
            let mut p = repo::load_from_path(&frontier).unwrap_or_else(|e| fail_return(&e));
            // Refuse if any link still references this vfr_id.
            for f in &p.findings {
                for l in &f.links {
                    if let Ok(vela_protocol::bundle::LinkRef::Cross { vfr_id: ref v, .. }) =
                        vela_protocol::bundle::LinkRef::parse(&l.target)
                        && v == &vfr_id
                    {
                        fail(&format!(
                            "cannot remove dep '{vfr_id}': finding {} still links to it via {}",
                            f.id, l.target
                        ));
                    }
                }
            }
            let before = p.project.dependencies.len();
            p.project
                .dependencies
                .retain(|d| d.vfr_id.as_deref() != Some(&vfr_id));
            let removed = before - p.project.dependencies.len();
            if removed == 0 {
                fail(&format!("no cross-frontier dependency '{vfr_id}' found"));
            }
            repo::save_to_path(&frontier, &p).unwrap_or_else(|e| fail_return(&e));
            let payload = json!({
                "ok": true,
                "command": "frontier.remove-dep",
                "frontier": frontier.display().to_string(),
                "vfr_id": vfr_id,
                "removed": removed,
            });
            if json {
                print_json(&payload);
            } else {
                println!(
                    "{} removed cross-frontier dep {vfr_id}",
                    style::ok("frontier")
                );
            }
        }
        FrontierAction::RefreshDeps {
            frontier,
            from,
            dry_run,
            json,
        } => {
            let mut p = repo::load_from_path(&frontier).unwrap_or_else(|e| fail_return(&e));
            let cross_deps: Vec<String> = p
                .project
                .dependencies
                .iter()
                .filter_map(|d| d.vfr_id.clone())
                .collect();
            if cross_deps.is_empty() {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&json!({
                            "ok": true,
                            "command": "frontier.refresh-deps",
                            "frontier": frontier.display().to_string(),
                            "from": from,
                            "dry_run": dry_run,
                            "deps": [],
                            "summary": { "total": 0, "refreshed": 0, "unchanged": 0, "missing": 0, "unreachable": 0 },
                        })).expect("serialize")
                    );
                } else {
                    println!(
                        "{} no cross-frontier deps declared in {}",
                        style::ok("frontier"),
                        frontier.display()
                    );
                }
                return;
            }
            let client = reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(20))
                .build()
                .unwrap_or_else(|e| fail_return(&format!("http client init failed: {e}")));
            let base = from.trim_end_matches('/');
            #[derive(serde::Deserialize)]
            struct HubEntry {
                latest_snapshot_hash: String,
            }
            let mut per_dep: Vec<serde_json::Value> = Vec::new();
            let (mut refreshed, mut unchanged, mut missing, mut unreachable) =
                (0u32, 0u32, 0u32, 0u32);
            for vfr in &cross_deps {
                let url = format!("{base}/entries/{vfr}");
                let resp = client.get(&url).send();
                let outcome = match resp {
                    Ok(r) if r.status().as_u16() == 404 => {
                        missing += 1;
                        json!({ "vfr_id": vfr, "status": "missing", "url": url })
                    }
                    Ok(r) if !r.status().is_success() => {
                        unreachable += 1;
                        json!({ "vfr_id": vfr, "status": "unreachable", "http_status": r.status().as_u16() })
                    }
                    Err(e) => {
                        unreachable += 1;
                        json!({ "vfr_id": vfr, "status": "unreachable", "error": e.to_string() })
                    }
                    Ok(r) => match r.json::<HubEntry>() {
                        Err(e) => {
                            unreachable += 1;
                            json!({ "vfr_id": vfr, "status": "unreachable", "error": format!("invalid hub response: {e}") })
                        }
                        Ok(entry) => {
                            // Locate the dep in our project to compare + (maybe) mutate.
                            match p
                                .project
                                .dependencies
                                .iter()
                                .position(|d| d.vfr_id.as_deref() == Some(vfr.as_str()))
                            {
                                None => {
                                    unreachable += 1;
                                    json!({ "vfr_id": vfr, "status": "unreachable", "error": "dep disappeared mid-scan" })
                                }
                                Some(idx) => {
                                    let local_pin =
                                        p.project.dependencies[idx].pinned_snapshot_hash.clone();
                                    let new_pin = entry.latest_snapshot_hash;
                                    if local_pin.as_deref() == Some(new_pin.as_str()) {
                                        unchanged += 1;
                                        json!({ "vfr_id": vfr, "status": "unchanged", "snapshot": new_pin })
                                    } else {
                                        if !dry_run {
                                            p.project.dependencies[idx].pinned_snapshot_hash =
                                                Some(new_pin.clone());
                                        }
                                        refreshed += 1;
                                        json!({
                                            "vfr_id": vfr,
                                            "status": "refreshed",
                                            "old_snapshot": local_pin,
                                            "new_snapshot": new_pin,
                                        })
                                    }
                                }
                            }
                        }
                    },
                };
                per_dep.push(outcome);
            }
            if !dry_run && refreshed > 0 {
                repo::save_to_path(&frontier, &p).unwrap_or_else(|e| fail_return(&e));
            }
            let payload = json!({
                "ok": true,
                "command": "frontier.refresh-deps",
                "frontier": frontier.display().to_string(),
                "from": from,
                "dry_run": dry_run,
                "deps": per_dep,
                "summary": {
                    "total": cross_deps.len(),
                    "refreshed": refreshed,
                    "unchanged": unchanged,
                    "missing": missing,
                    "unreachable": unreachable,
                },
            });
            if json {
                print_json(&payload);
            } else {
                let mode = if dry_run { " (dry-run)" } else { "" };
                println!(
                    "{} refresh-deps{mode} · {} total · {refreshed} refreshed · {unchanged} unchanged · {missing} missing · {unreachable} unreachable",
                    style::ok("frontier"),
                    cross_deps.len()
                );
                for d in &per_dep {
                    let vfr = d["vfr_id"].as_str().unwrap_or("?");
                    let status = d["status"].as_str().unwrap_or("?");
                    match status {
                        "refreshed" => println!(
                            "  {vfr}  refreshed  {} → {}",
                            d["old_snapshot"]
                                .as_str()
                                .unwrap_or("(none)")
                                .chars()
                                .take(16)
                                .collect::<String>(),
                            d["new_snapshot"]
                                .as_str()
                                .unwrap_or("?")
                                .chars()
                                .take(16)
                                .collect::<String>(),
                        ),
                        "unchanged" => println!("  {vfr}  unchanged"),
                        "missing" => println!("  {vfr}  missing on hub"),
                        _ => println!("  {vfr}  unreachable"),
                    }
                }
            }
        }
        FrontierAction::Diff {
            frontier,
            since,
            week,
            json,
        } => cmd_frontier_diff(&frontier, since.as_deref(), week.as_deref(), json),
        FrontierAction::Release {
            frontier,
            name,
            notes,
            previous,
            json,
        } => cmd_frontier_release(frontier, name, notes, previous, json),
        FrontierAction::Releases { frontier, json } => cmd_frontier_releases(frontier, json),
        FrontierAction::Audit { frontier, json } => cmd_frontier_audit(frontier, json),
        FrontierAction::Health { frontier, json } => cmd_frontier_health(frontier, json),
        FrontierAction::Shards { frontier, json } => cmd_frontier_shards(frontier, json),
    }
}
