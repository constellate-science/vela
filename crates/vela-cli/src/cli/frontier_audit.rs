//! Frontier release tagging (`vela frontier release/releases`) and the
//! read-only release-readiness audit (`vela frontier audit`). All read-only
//! over canonical state; no signing key.

use super::*;

/// v0.158: tag the current frontier state as a versioned release.
pub(crate) fn cmd_frontier_release(
    frontier: PathBuf,
    name: String,
    notes: Option<String>,
    previous: Option<String>,
    json: bool,
) {
    use vela_edge::frontier_release::{FrontierRelease, ReleaseDraft};

    let project = repo::load_from_path(&frontier).unwrap_or_else(|e| fail_return(&e));
    let frontier_id = project.frontier_id();
    let snapshot_hash = events::snapshot_hash(&project);
    let event_log_hash = events::event_log_hash(&project.events);

    // Derive releases dir + chain on the latest existing release
    // (if no --previous was supplied).
    let releases_dir = releases_dir_for(&frontier);
    let chained_previous = if previous.is_some() {
        previous
    } else {
        latest_release_id(&releases_dir)
    };

    // Owner epoch: the chain transcript at v0.146 has it. If
    // present, take the latest transition's owner_epoch;
    // otherwise default to 0 (bootstrap).
    let owner_epoch = derive_owner_epoch(&frontier);

    let draft = ReleaseDraft {
        frontier_id: frontier_id.clone(),
        name,
        notes,
        owner_epoch,
        snapshot_hash,
        event_log_hash,
        governance_policy_id: None,
        previous_release: chained_previous,
        released_at: chrono::Utc::now().to_rfc3339(),
    };
    let release = FrontierRelease::from_draft(draft).unwrap_or_else(|e| fail_return(&e));

    if let Err(e) = std::fs::create_dir_all(&releases_dir) {
        fail(&format!("create releases dir: {e}"));
    }
    let path = releases_dir.join(format!("{}.json", release.release_id));
    let body = serde_json::to_string_pretty(&release).expect("serialize frontier release");
    std::fs::write(&path, format!("{body}\n"))
        .unwrap_or_else(|e| fail_return(&format!("write {}: {e}", path.display())));

    if json {
        let payload = json!({
            "ok": true,
            "command": "frontier.release",
            "release_id": release.release_id,
            "frontier_id": release.frontier_id,
            "name": release.name,
            "owner_epoch": release.owner_epoch,
            "snapshot_hash": release.snapshot_hash,
            "event_log_hash": release.event_log_hash,
            "previous_release": release.previous_release,
            "released_at": release.released_at,
            "out": path.display().to_string(),
        });
        print_json(&payload);
    } else {
        println!(
            "{} released {} ({}) of {}",
            style::ok("release"),
            release.release_id,
            release.name,
            release.frontier_id
        );
        println!("  owner_epoch:   {}", release.owner_epoch);
        println!("  snapshot:      {}", release.snapshot_hash);
        println!("  event_log:     {}", release.event_log_hash);
        if let Some(prev) = &release.previous_release {
            println!("  previous:      {}", prev);
        }
        println!("  out:           {}", path.display());
    }
}

/// v0.158: list every release recorded for a frontier.
pub(crate) fn cmd_frontier_releases(frontier: PathBuf, json: bool) {
    use vela_edge::frontier_release::FrontierRelease;

    let releases_dir = releases_dir_for(&frontier);
    let mut releases: Vec<FrontierRelease> = Vec::new();
    if releases_dir.exists() {
        for entry in std::fs::read_dir(&releases_dir)
            .unwrap_or_else(|e| fail_return(&format!("read releases dir: {e}")))
        {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            let raw = match std::fs::read_to_string(&path) {
                Ok(r) => r,
                Err(_) => continue,
            };
            if let Ok(r) = serde_json::from_str::<FrontierRelease>(&raw) {
                releases.push(r);
            }
        }
    }
    releases.sort_by(|a, b| b.released_at.cmp(&a.released_at));

    if json {
        let payload = json!({
            "ok": true,
            "command": "frontier.releases",
            "frontier": frontier.display().to_string(),
            "release_count": releases.len(),
            "releases": releases,
        });
        print_json(&payload);
    } else {
        println!(
            "{} {} release(s) for {}",
            style::ok("releases"),
            releases.len(),
            frontier.display()
        );
        for r in &releases {
            println!("  {}  {}  (epoch {})", r.release_id, r.name, r.owner_epoch);
            println!("    released_at: {}", r.released_at);
            if let Some(prev) = &r.previous_release {
                println!("    previous:    {}", prev);
            }
        }
    }
}

pub(crate) fn cmd_frontier_audit(frontier: PathBuf, json_out: bool) {
    let project = repo::load_from_path(&frontier).unwrap_or_else(|e| fail_return(&e));
    let strict_check = check_json_payload(&frontier, false, true);
    let proof = frontier_repo::proof_verify(&frontier).unwrap_or_else(|e| {
        json!({
            "ok": false,
            "command": "proof.verify",
            "frontier": frontier.display().to_string(),
            "error": e,
        })
    });
    let evidence = evidence_ci::run_frontier(&frontier).unwrap_or_else(|e| fail_return(&e));
    let health = frontier_health::analyze(&frontier).unwrap_or_else(|e| fail_return(&e));
    let mut review_work = crate::review_work::build_review_work_json(&frontier)
        .map(Some)
        .unwrap_or_else(|e| {
            Some(json!({
                "ok": false,
                "command": "review-work",
                "frontier_path": frontier.display().to_string(),
                "error": e,
            }))
        });

    let provenance = vela_protocol::reducer::classify_provenance(&project);
    let fully_event_sourced = provenance.fully_event_sourced();
    let event_source = json!({
        "fully_event_sourced": fully_event_sourced,
        "inline": provenance.inline.len(),
        "proposal_backed": provenance.proposal_backed.len(),
        "remnant": provenance.remnant.len(),
        "actors": provenance.actors,
        "proposals": provenance.proposals,
        "pins": {
            // What still keeps a derived view committed to git.
            "findings_dir": provenance.remnant.len(),
            "proposals_dir": provenance.proposal_backed.len(),
        },
        "note": if fully_event_sourced {
            "events/ reduces to the whole finding set; findings/ + proposals/ are pure caches, safe to decommit once verify_replay is green"
        } else {
            "some finding bodies live only in findings/ (remnants) or proposals/ (proposal-backed asserts); migrate them to inline asserts before decommitting"
        },
    });

    let strict_ok = json_bool(&strict_check, "ok");
    let proof_ok = json_bool(&proof, "ok");
    let evidence_ok = evidence.ok;
    let health_ok = health.ok;
    let review_work_by_lane = review_work_by_lane(review_work.as_ref());
    if let Some(Value::Object(payload)) = review_work.as_mut() {
        payload.insert("by_lane".to_string(), review_work_by_lane);
    }
    let review_work_open = review_work_total_open(review_work.as_ref());
    let strict_check_summary = compact_strict_check(&strict_check);
    let evidence_ci_summary = compact_evidence_ci(&evidence);
    let quality_tier = frontier_audit_tier(
        strict_ok,
        proof_ok,
        evidence_ok,
        health_ok,
        review_work_open,
    );
    let release_blockers = frontier_audit_release_blockers(
        &strict_check,
        &proof,
        &evidence,
        &health,
        review_work.as_ref(),
    );
    let ok = strict_ok && proof_ok && evidence_ok && health_ok;

    let payload = json!({
        "ok": ok,
        "command": "frontier.audit",
        "checked_at": chrono::Utc::now().to_rfc3339(),
        "quality_tier": quality_tier,
        "release_blockers": release_blockers,
        "frontier": {
            "id": project.frontier_id(),
            "name": &project.project.name,
            "path": frontier.display().to_string(),
            "compiled_at": &project.project.compiled_at,
        },
        "summary": {
            "findings": project.stats.findings,
            "sources": project.stats.source_count,
            "evidence_atoms": project.stats.evidence_atom_count,
            "events": project.stats.event_count,
            "links": project.stats.links,
            "strict_check_ok": strict_ok,
            "proof_ok": proof_ok,
            "evidence_ci_ok": evidence_ok,
            "health_ok": health_ok,
            "review_work_open": review_work_open,
            "proof_status": &project.proof_state.latest_packet.status,
            "evidence_ci_failures": evidence.summary.release_blocking_failed,
            "evidence_ci_warnings": evidence.summary.warnings,
            "health_issues": health.issues.len(),
        },
        "stats": &project.stats,
        "event_source": event_source,
        "strict_check": strict_check_summary,
        "proof": proof,
        "evidence_ci": evidence_ci_summary,
        "frontier_health": health,
        "review_work": review_work,
        "caveats": [
            "Frontier audit is a readiness report. It is not a truth verdict.",
            "Review-work queues are read-only and do not count as review.",
            "Outside-review lanes are reported only when returned artifacts exist."
        ],
    });

    if json_out {
        print_json(&payload);
        return;
    }

    let status = if ok {
        style::ok("frontier.audit")
    } else {
        style::warn("frontier.audit")
    };
    println!();
    println!("  {}", "Vela · frontier audit".dimmed());
    println!("  {}", style::tick_row(60));
    println!("  {status} {quality_tier}");
    println!("  frontier:        {}", project.frontier_id());
    println!("  path:            {}", frontier.display());
    println!(
        "  stats:           {} findings · {} sources · {} evidence atoms · {} events · {} links",
        project.stats.findings,
        project.stats.source_count,
        project.stats.evidence_atom_count,
        project.stats.event_count,
        project.stats.links
    );
    println!(
        "  event-sourced:   {} ({} inline · {} proposal-backed · {} remnant)",
        if fully_event_sourced {
            style::ok("fully")
        } else {
            style::warn("partial")
        },
        provenance.inline.len(),
        provenance.proposal_backed.len(),
        provenance.remnant.len()
    );
    println!(
        "  strict check:    {}",
        if strict_ok {
            style::ok("pass")
        } else {
            style::lost("fail")
        }
    );
    println!(
        "  proof verify:    {} ({})",
        if proof_ok {
            style::ok("pass")
        } else {
            style::lost("fail")
        },
        project.proof_state.latest_packet.status
    );
    println!(
        "  Evidence CI:     {} · {} failures · {} warnings",
        if evidence_ok {
            style::ok("pass")
        } else {
            style::lost("fail")
        },
        evidence.summary.release_blocking_failed,
        evidence.summary.warnings
    );
    println!(
        "  health:          {} · {} issue(s)",
        if health_ok {
            style::ok("pass")
        } else {
            style::warn("attention")
        },
        health.issues.len()
    );
    println!("  review work:     {review_work_open} open row(s)");
    println!("  boundary:        read-only. This does not count as review.");
}

fn json_bool(value: &Value, key: &str) -> bool {
    value.get(key).and_then(Value::as_bool) == Some(true)
}

fn review_work_total_open(value: Option<&Value>) -> usize {
    value
        .and_then(|payload| payload.get("total_open"))
        .and_then(Value::as_u64)
        .unwrap_or(0) as usize
}

fn review_work_by_lane(value: Option<&Value>) -> Value {
    let mut lanes = serde_json::Map::new();
    if let Some(queues) = value
        .and_then(|payload| payload.get("queues"))
        .and_then(Value::as_array)
    {
        for queue in queues {
            if let Some(lane_id) = queue.get("lane_id").and_then(Value::as_str) {
                lanes.insert(lane_id.to_string(), queue.clone());
            }
        }
    }
    Value::Object(lanes)
}

fn frontier_audit_release_blockers(
    strict_check: &Value,
    proof: &Value,
    evidence: &evidence_ci::EvidenceCiReport,
    health: &frontier_health::FrontierHealthReport,
    review_work: Option<&Value>,
) -> Value {
    let mut blockers = Vec::new();

    if !json_bool(strict_check, "ok") {
        blockers.push(json!({
            "id": "strict_check",
            "title": "strict check",
            "severity": "release_blocker",
            "detail": "Strict check failed.",
            "count": strict_check
                .get("diagnostics")
                .and_then(Value::as_array)
                .map_or(0, Vec::len),
        }));
    }

    if !json_bool(proof, "ok") {
        blockers.push(json!({
            "id": "proof_verify",
            "title": "proof verify",
            "severity": "release_blocker",
            "detail": proof
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("Proof verification failed."),
        }));
    }

    if !evidence.ok {
        blockers.push(json!({
            "id": "evidence_ci",
            "title": "Evidence CI",
            "severity": "release_blocker",
            "detail": "Evidence CI has release-blocking failures.",
            "count": evidence.summary.release_blocking_failed,
        }));
    }

    if !health.ok {
        blockers.push(json!({
            "id": "frontier_health",
            "title": "frontier health",
            "severity": "release_blocker",
            "detail": "Frontier health requires attention.",
            "count": health.issues.len(),
        }));
    }

    if review_work
        .and_then(|payload| payload.get("ok"))
        .and_then(Value::as_bool)
        == Some(false)
    {
        blockers.push(json!({
            "id": "review_work",
            "title": "review work",
            "severity": "release_blocker",
            "detail": review_work
                .and_then(|payload| payload.get("error"))
                .and_then(Value::as_str)
                .unwrap_or("Review-work queues could not be read."),
        }));
    }

    Value::Array(blockers)
}

fn compact_strict_check(report: &Value) -> Value {
    json!({
        "ok": report.get("ok").cloned().unwrap_or(Value::Bool(false)),
        "command": report.get("command").cloned().unwrap_or(Value::String("check".to_string())),
        "summary": report.get("summary").cloned().unwrap_or(Value::Null),
        "checks": report.get("checks").cloned().unwrap_or(Value::Array(Vec::new())),
        "proof_readiness": report.get("proof_readiness").cloned().unwrap_or(Value::Null),
        "state_integrity": report.get("state_integrity").cloned().unwrap_or(Value::Null),
        "diagnostic_count": report
            .get("diagnostics")
            .and_then(Value::as_array)
            .map_or(0, Vec::len),
        "review_queue_count": report
            .get("review_queue")
            .and_then(Value::as_array)
            .map_or(0, Vec::len),
    })
}

fn compact_evidence_ci(report: &evidence_ci::EvidenceCiReport) -> Value {
    json!({
        "ok": report.ok,
        "command": &report.command,
        "frontier_id": &report.frontier_id,
        "frontier_path": &report.frontier_path,
        "checked_at": &report.checked_at,
        "scope": &report.scope,
        "summary": &report.summary,
        "caveats": &report.caveats,
    })
}

fn frontier_audit_tier(
    strict_ok: bool,
    proof_ok: bool,
    evidence_ok: bool,
    health_ok: bool,
    review_work_open: usize,
) -> &'static str {
    if strict_ok && proof_ok && evidence_ok && health_ok && review_work_open == 0 {
        "release_ready"
    } else if strict_ok && proof_ok && evidence_ok {
        "release_clean_with_open_review_work"
    } else if proof_ok && evidence_ok {
        "review_ready"
    } else {
        "blocked"
    }
}

fn releases_dir_for(frontier: &Path) -> PathBuf {
    let dir = if frontier.is_dir() {
        frontier.to_path_buf()
    } else if let Some(parent) = frontier.parent() {
        parent.to_path_buf()
    } else {
        PathBuf::from(".")
    };
    dir.join(".vela").join("releases")
}

fn latest_release_id(releases_dir: &Path) -> Option<String> {
    use vela_edge::frontier_release::FrontierRelease;
    if !releases_dir.exists() {
        return None;
    }
    let mut latest: Option<(String, String)> = None;
    if let Ok(entries) = std::fs::read_dir(releases_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            let raw = match std::fs::read_to_string(&path) {
                Ok(r) => r,
                Err(_) => continue,
            };
            if let Ok(r) = serde_json::from_str::<FrontierRelease>(&raw) {
                let pick = latest
                    .as_ref()
                    .map(|(_, ts)| ts.as_str() < r.released_at.as_str())
                    .unwrap_or(true);
                if pick {
                    latest = Some((r.release_id, r.released_at));
                }
            }
        }
    }
    latest.map(|(id, _)| id)
}

fn derive_owner_epoch(frontier: &Path) -> u64 {
    let chain_path = if frontier.is_dir() {
        frontier.join(".vela").join("governance").join("chain.json")
    } else if let Some(parent) = frontier.parent() {
        parent.join(".vela").join("governance").join("chain.json")
    } else {
        return 0;
    };
    if !chain_path.exists() {
        return 0;
    }
    let raw = match std::fs::read_to_string(&chain_path) {
        Ok(r) => r,
        Err(_) => return 0,
    };
    let v: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(_) => return 0,
    };
    v.get("transitions")
        .and_then(|t| t.as_array())
        .and_then(|arr| arr.last())
        .and_then(|t| t.get("owner_epoch"))
        .and_then(|e| e.as_u64())
        .unwrap_or(0)
}
