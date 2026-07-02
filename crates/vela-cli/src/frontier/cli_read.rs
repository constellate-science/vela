use crate::cli::{fail, fail_return, fmt_timestamp, frontier_label, print_json};
use colored::Colorize;
use serde_json::json;
use std::path::Path;
use vela_edge::doctor;
use vela_edge::packet;
use vela_protocol::cli_style as style;
use vela_protocol::repo;

/// v0.42: One-screen status. The `git status` analogue.
pub(crate) fn cmd_status(path: &Path, json: bool) {
    let project = repo::load_from_path(path).unwrap_or_else(|e| fail_return(&e));

    // Replay integrity: the one-line truth a stranger checks first.
    let replay = vela_protocol::reducer::verify_replay(&project);
    let replay_line = if replay.ok {
        "reproduced".to_string()
    } else {
        format!("DIVERGED ({} diff(s))", replay.diffs.len())
    };

    // Production state: live leases, attestations, registrations.
    let now_iso = chrono::Utc::now().to_rfc3339();
    let live_leases: Vec<&vela_protocol::project::AttemptClaim> = project
        .attempt_claims
        .iter()
        .filter(|c| {
            chrono::DateTime::parse_from_rfc3339(&c.claimed_at)
                .map(|t| {
                    (t + chrono::Duration::seconds(c.lease_ttl_seconds as i64)).to_rfc3339()
                        > now_iso
                })
                .unwrap_or(false)
        })
        .collect();
    let attestation_count = project.statement_attestations.len();
    let registration_count = project.statement_registrations.len();
    let last_event_ts = project.events.iter().map(|e| e.timestamp.as_str()).max();

    // Inbox counts.
    let mut pending_total = 0usize;
    let mut pending_by_kind: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    for p in &project.proposals {
        if p.status == "pending_review" {
            pending_total += 1;
            *pending_by_kind.entry(p.kind.clone()).or_insert(0) += 1;
        }
    }

    // The memo's epistemic vector: never collapse into one green check.
    // claimed / evidence-attached / contested / refuted / retracted / stale
    // are DIFFERENT states, and an agent reading --json gets each count.
    let mut by_status: std::collections::BTreeMap<String, usize> = Default::default();
    let mut with_evidence = 0usize;
    for f in &project.findings {
        let s = if f.flags.retracted {
            "retracted"
        } else if f.flags.contested {
            "contested"
        } else if f.flags.superseded {
            "superseded"
        } else {
            "accepted"
        };
        *by_status.entry(s.to_string()).or_default() += 1;
        if !f.evidence.evidence_spans.is_empty()
            || f.provenance.url.as_deref().is_some_and(|u| !u.is_empty())
            || f.provenance.doi.as_deref().is_some_and(|d| !d.is_empty())
        {
            with_evidence += 1;
        }
    }
    let verdicts: std::collections::BTreeMap<String, usize> = {
        let mut m: std::collections::BTreeMap<String, usize> = Default::default();
        for a in &project.statement_attestations {
            *m.entry(format!("{:?}", a.verdict).to_lowercase())
                .or_default() += 1;
        }
        m
    };

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": true,
                "command": "status",
                "frontier": frontier_label(&project),
                "vfr_id": project.frontier_id(),
                "replay": {"ok": replay.ok, "diffs": replay.diffs.len()},
                "findings": {
                    "total": project.findings.len(),
                    "by_status": by_status,
                    "with_evidence": with_evidence,
                },
                "judgment": {
                    "statement_attestations": project.statement_attestations.len(),
                    "by_verdict": verdicts,
                },
                "proof": {
                    "status": project.proof_state.latest_packet.status,
                },
                "events": project.events.len(),
                "actors": project.actors.len(),
                "inbox": {
                    "pending_total": pending_total,
                    "pending_by_kind": pending_by_kind,
                },
                "next": if pending_total > 0 {
                    json!(format!(
                        "{pending_total} pending proposal(s) await a human key: `vela inbox .` then `vela accept . --all-pending`"
                    ))
                } else if !replay.ok {
                    json!("replay DIVERGED: run `vela check .` and inspect")
                } else if project.proof_state.latest_packet.status == "stale" {
                    json!("proof packet stale: `vela frontier materialize .`")
                } else {
                    json!(null)
                },
            }))
            .expect("serialize status")
        );
        return;
    }

    println!();
    println!(
        "  {}",
        format!("VELA · STATUS · {}", path.display())
            .to_uppercase()
            .dimmed()
    );
    println!("  {}", style::tick_row(60));
    println!();
    println!("  frontier:    {}", frontier_label(&project));
    println!("  vfr_id:      {}", project.frontier_id());
    println!(
        "  replay:      {}",
        if replay.ok {
            style::ok(&replay_line)
        } else {
            style::warn(&replay_line)
        }
    );
    println!("  last event:  {}", last_event_ts.unwrap_or("none"));
    if !live_leases.is_empty() {
        println!("  leases:      {} live", live_leases.len());
        for l in live_leases.iter().take(5) {
            println!(
                "    · {} by {} (ttl {}s from {})",
                l.obligation_id, l.claimant_actor, l.lease_ttl_seconds, l.claimed_at
            );
        }
    }
    if attestation_count + registration_count > 0 {
        println!(
            "  judgment:    {attestation_count} statement attestation(s), {registration_count} registration(s)"
        );
    }
    {
        let vec_line: Vec<String> = by_status.iter().map(|(k, v)| format!("{v} {k}")).collect();
        if !vec_line.is_empty() {
            println!("  state:       {}", vec_line.join(" · "));
        }
    }
    println!(
        "  findings:    {}    events: {}    actors: {}",
        project.findings.len(),
        project.events.len(),
        project.actors.len(),
    );
    println!();
    if pending_total > 0 {
        println!(
            "  {}  {pending_total} pending proposals",
            style::warn("inbox")
        );
        for (k, n) in &pending_by_kind {
            println!("    · {n:>3}  {k}");
        }
    } else {
        println!("  {}  inbox clean", style::ok("ok"));
    }
    println!();
}

/// v0.42: Recent canonical events. The `git log` analogue.
pub(crate) fn cmd_log(path: &Path, limit: usize, kind_filter: Option<&str>, json: bool) {
    let project = repo::load_from_path(path).unwrap_or_else(|e| fail_return(&e));
    let mut events: Vec<&vela_protocol::events::StateEvent> = project
        .events
        .iter()
        .filter(|e| match kind_filter {
            Some(k) => e.kind.as_str().contains(k),
            None => true,
        })
        .collect();
    events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    events.truncate(limit);

    if json {
        let payload: Vec<_> = events
            .iter()
            .map(|e| {
                json!({
                    "id": e.id,
                    "kind": e.kind,
                    "actor": e.actor.id,
                    "target": &e.target.id,
                    "target_type": &e.target.r#type,
                    "timestamp": e.timestamp,
                    "reason": e.reason,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": true,
                "command": "log",
                "events": payload,
            }))
            .expect("serialize log")
        );
        return;
    }

    println!();
    println!(
        "  {}",
        format!("VELA · LOG · {}  (latest {})", path.display(), events.len())
            .to_uppercase()
            .dimmed()
    );
    println!("  {}", style::tick_row(60));
    if events.is_empty() {
        println!("  (no events)");
        return;
    }
    for e in &events {
        let when = fmt_timestamp(&e.timestamp);
        let target_short = if e.target.id.len() > 22 {
            format!("{}…", &e.target.id[..21])
        } else {
            e.target.id.clone()
        };
        let reason: String = e.reason.chars().take(70).collect();
        println!(
            "  {:<19}  {:<32}  {:<24}  {}",
            when, e.kind, target_short, reason
        );
    }
    println!();
}

/// v0.42: Pending-proposals triage. The thing you sit down to review.
pub(crate) fn cmd_inbox(path: &Path, kind_filter: Option<&str>, limit: usize, json: bool) {
    let project = repo::load_from_path(path).unwrap_or_else(|e| fail_return(&e));

    // Collect reviewer-agent score map (composite shown alongside each
    // proposal where present).
    let mut score_map: std::collections::HashMap<String, (f64, f64, f64, f64)> =
        std::collections::HashMap::new();
    for p in &project.proposals {
        if p.kind != "finding.note" {
            continue;
        }
        if p.actor.id != "agent:reviewer-agent" {
            continue;
        }
        let reason = &p.reason;
        let Some(target) = reason.split_whitespace().find(|s| s.starts_with("vpr_")) else {
            continue;
        };
        let text = p.payload.get("text").and_then(|v| v.as_str()).unwrap_or("");
        let extract = |k: &str| -> f64 {
            let pat = format!("{k} ");
            text.find(&pat)
                .and_then(|idx| text[idx + pat.len()..].split_whitespace().next())
                .and_then(|t| t.parse::<f64>().ok())
                .unwrap_or(0.0)
        };
        score_map.insert(
            target.to_string(),
            (
                extract("plausibility"),
                extract("evidence"),
                extract("scope"),
                extract("duplicate-risk"),
            ),
        );
    }

    let mut pending: Vec<&vela_protocol::proposals::StateProposal> = project
        .proposals
        .iter()
        .filter(|p| {
            p.status == "pending_review"
                && match kind_filter {
                    Some(k) => p.kind.contains(k),
                    None => true,
                }
        })
        .collect();
    // Sort: high reviewer-agent composite first, then untyped.
    pending.sort_by(|a, b| {
        let sa = score_map
            .get(&a.id)
            .map(|(p, e, s, d)| 0.4 * p + 0.3 * e + 0.2 * s - 0.3 * d);
        let sb = score_map
            .get(&b.id)
            .map(|(p, e, s, d)| 0.4 * p + 0.3 * e + 0.2 * s - 0.3 * d);
        sb.partial_cmp(&sa).unwrap_or(std::cmp::Ordering::Equal)
    });
    pending.truncate(limit);

    if json {
        let payload: Vec<_> = pending
            .iter()
            .map(|p| {
                let assertion_text = p
                    .payload
                    .get("finding")
                    .and_then(|f| f.get("assertion"))
                    .and_then(|a| a.get("text"))
                    .and_then(|t| t.as_str());
                let assertion_type = p
                    .payload
                    .get("finding")
                    .and_then(|f| f.get("assertion"))
                    .and_then(|a| a.get("type"))
                    .and_then(|t| t.as_str());
                let composite = score_map
                    .get(&p.id)
                    .map(|(pl, e, s, d)| 0.4 * pl + 0.3 * e + 0.2 * s - 0.3 * d);
                json!({
                    "proposal_id": p.id,
                    "kind": p.kind,
                    "actor": p.actor,
                    "reason": p.reason,
                    "assertion_text": assertion_text,
                    "assertion_type": assertion_type,
                    "reviewer_composite": composite,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": true,
                "command": "inbox",
                "shown": pending.len(),
                "proposals": payload,
            }))
            .expect("serialize inbox")
        );
        return;
    }

    println!();
    println!(
        "  {}",
        format!(
            "VELA · INBOX · {}  ({} pending shown)",
            path.display(),
            pending.len()
        )
        .to_uppercase()
        .dimmed()
    );
    println!("  {}", style::tick_row(60));
    if pending.is_empty() {
        println!("  (inbox clean)");
        return;
    }
    for p in &pending {
        let assertion_text = p
            .payload
            .get("finding")
            .and_then(|f| f.get("assertion"))
            .and_then(|a| a.get("text"))
            .and_then(|t| t.as_str())
            .unwrap_or("");
        let assertion_type = p
            .payload
            .get("finding")
            .and_then(|f| f.get("assertion"))
            .and_then(|a| a.get("type"))
            .and_then(|t| t.as_str())
            .unwrap_or("");
        let composite = score_map
            .get(&p.id)
            .map(|(pl, e, s, d)| 0.4 * pl + 0.3 * e + 0.2 * s - 0.3 * d);
        let score_str = composite
            .map(|c| format!("[{:.2}]", c))
            .unwrap_or_else(|| "[—]   ".to_string());
        let kind_short = if p.kind.len() > 12 {
            format!("{}…", &p.kind[..11])
        } else {
            p.kind.clone()
        };
        let summary: String = if !assertion_text.is_empty() {
            assertion_text.chars().take(80).collect()
        } else {
            p.reason.chars().take(80).collect()
        };
        println!(
            "  {}  {}  {:<13}  {:<18}  {}",
            score_str, p.id, kind_short, assertion_type, summary
        );
    }
    println!();
}

/// `vela verify <packet_dir>` — same code path as
/// `vela packet validate`, surfaced under a friendlier top-level name.
/// Reads every file in the manifest, recomputes SHA-256, validates the
/// proof-trace chain. Exit 0 on all-match, 1 on any mismatch.
pub(crate) fn cmd_verify(path: &Path, json_output: bool) {
    let result = packet::validate(path);
    match result {
        Ok(output) if json_output => {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "ok": true,
                    "command": "verify",
                    "result": output,
                }))
                .expect("failed to serialize verify response")
            );
        }
        Ok(output) => {
            println!("{output}");
            println!(
                "\nverify: ok\n  every file in the manifest matched its claimed sha256.\n  pull this packet on another machine, run the same command, see the same line."
            );
        }
        Err(e) => fail(&e),
    }
}

pub(crate) fn cmd_doctor(frontier: Option<&Path>, port: u16, json_output: bool) {
    let report = doctor::run(frontier, port);
    if json_output {
        print_json(&report);
    } else {
        println!("vela doctor");
        println!("  binary:      {}", report.binary_version);
        println!("  frontier:    {}", report.frontier_path);
        println!("  kind:        {}", report.frontier_kind);
        println!(
            "  policy:      {}",
            if report.policy_ok {
                "ok"
            } else {
                "needs attention"
            }
        );
        println!("  proof:       {}", report.proof_status);
        println!(
            "  evidence ci: {}",
            if report.evidence_ci_ok {
                "ok"
            } else {
                "needs attention"
            }
        );
        println!(
            "  serve:       port {} {}",
            report.workbench_port,
            if report.workbench_port_available {
                "available"
            } else {
                "unavailable"
            }
        );
        if !report.blocking.is_empty() {
            println!("  blocking:    {}", report.blocking.join(", "));
        }
        if !report.warnings.is_empty() {
            println!("  warnings:    {}", report.warnings.join(", "));
        }
        println!();
        println!("next:");
        for command in &report.next_commands {
            println!("  {command}");
        }
        if let Some(config) = &report.mcp_config {
            println!();
            println!("mcp:");
            println!(
                "  {}",
                serde_json::to_string(config).expect("serialize mcp config")
            );
        }
    }
    if !report.blocking.is_empty() {
        std::process::exit(1);
    }
}
