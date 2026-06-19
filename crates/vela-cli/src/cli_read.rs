use crate::cli::{
    answer, fail, fail_return, fmt_timestamp, frontier_label, hash_path_or_fail,
    load_frontier_or_fail, print_json, print_stats_from_shards_human,
};
use colored::Colorize;
use serde_json::json;
use std::path::Path;
use vela_edge::doctor;
use vela_edge::packet;
use vela_edge::search;
use vela_edge::state_integrity;
use vela_edge::tensions;
use vela_protocol::cli_style as style;
use vela_protocol::project;
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

    // Causal audit summary.
    let audit = vela_edge::causal_reasoning::audit_frontier(&project);
    let audit_summary = vela_edge::causal_reasoning::summarize_audit(&audit);

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": true,
                "command": "status",
                "frontier": frontier_label(&project),
                "vfr_id": project.frontier_id(),
                "findings": project.findings.len(),
                "events": project.events.len(),
                "actors": project.actors.len(),
                "inbox": {
                    "pending_total": pending_total,
                    "pending_by_kind": pending_by_kind,
                },
                "causal_audit": {
                    "identified": audit_summary.identified,
                    "conditional": audit_summary.conditional,
                    "underidentified": audit_summary.underidentified,
                    "underdetermined": audit_summary.underdetermined,
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
    if audit_summary.underidentified > 0 || audit_summary.conditional > 0 {
        let chip = if audit_summary.underidentified > 0 {
            style::lost("audit")
        } else {
            style::warn("audit")
        };
        println!(
            "  {}  identified {} · conditional {} · underidentified {} · underdetermined {}",
            chip,
            audit_summary.identified,
            audit_summary.conditional,
            audit_summary.underidentified,
            audit_summary.underdetermined,
        );
        if audit_summary.underidentified > 0 {
            println!(
                "    next: vela causal audit {} --problems-only",
                path.display()
            );
        }
    } else if audit_summary.underdetermined == 0 {
        println!(
            "  {}  causal audit: all {} identified",
            style::ok("ok"),
            audit_summary.identified
        );
    } else {
        println!(
            "  {}  causal audit: {} identified, {} ungraded",
            style::warn("audit"),
            audit_summary.identified,
            audit_summary.underdetermined,
        );
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

/// v0.42: Conversational substrate access. Thin REPL over kernel
/// queries. Doesn't pretend to be an agent — every answer comes from
/// a structured query the kernel can produce deterministically. The
/// goal is fluency, not magic.
pub(crate) fn cmd_ask(path: &Path, question: &str, json: bool) {
    let project = repo::load_from_path(path).unwrap_or_else(|e| fail_return(&e));

    if question.trim().is_empty() {
        // REPL mode.
        use std::io::{BufRead, Write};
        println!();
        println!(
            "  {}",
            format!("VELA · ASK · {}", path.display())
                .to_uppercase()
                .dimmed()
        );
        println!("  {}", style::tick_row(60));
        println!("  Ask a question. Type `exit` to quit.");
        println!("  Examples:");
        println!("    · what's pending?");
        println!("    · what's underidentified?");
        println!("    · how many findings?");
        println!("    · what changed recently?");
        println!("    · who has what calibration?");
        println!();
        let stdin = std::io::stdin();
        let mut stdout = std::io::stdout();
        loop {
            print!("  ask> ");
            stdout.flush().ok();
            let mut line = String::new();
            if stdin.lock().read_line(&mut line).is_err() {
                break;
            }
            let q = line.trim();
            if q.is_empty() {
                continue;
            }
            if matches!(q, "exit" | "quit" | "q") {
                break;
            }
            answer(&project, q, false);
        }
        return;
    }

    answer(&project, question, json);
}

pub(crate) fn cmd_stats(path: &Path) {
    if print_stats_from_shards_human(path) {
        return;
    }

    let frontier = load_frontier_or_fail(path);
    let s = &frontier.stats;
    println!();
    println!("  {}", "FRONTIER · V0.36.0".dimmed());
    println!("  {}", frontier.project.name.bold());
    println!("  {}", style::tick_row(60));
    println!("  id:             {}", frontier.frontier_id());
    println!("  compiled:       {}", frontier.project.compiled_at);
    println!("  papers:         {}", frontier.project.papers_processed);
    println!("  findings:       {}", s.findings);
    println!("  links:          {}", s.links);
    println!("  replicated:     {}", s.replicated);
    println!("  avg confidence: {}", s.avg_confidence);
    println!("  gaps:           {}", s.gaps);
    println!("  contested:      {}", s.contested);
    println!("  reviewed:       {}", s.human_reviewed);
    println!("  proposals:      {}", s.proposal_count);
    println!(
        "  recorded proof: {}",
        frontier.proof_state.latest_packet.status
    );
    if frontier.proof_state.latest_packet.status != "never_exported" {
        println!(
            "  proof note:     recorded frontier metadata; packet files are checked by `vela verify`"
        );
    }
    if !s.categories.is_empty() {
        println!();
        println!("  {}", "categories".dimmed());
        let mut categories = s.categories.iter().collect::<Vec<_>>();
        categories.sort_by(|a, b| b.1.cmp(a.1));
        for (category, count) in categories {
            println!("    {category}: {}", count);
        }
    }
    println!();
    println!("  {}", style::tick_row(60));
    println!();
}

pub(crate) fn cmd_search(
    source: Option<&Path>,
    query: &str,
    entity: Option<&str>,
    assertion_type: Option<&str>,
    all: Option<&Path>,
    limit: usize,
    json_output: bool,
) {
    if let Some(dir) = all {
        search::run_all(dir, query, entity, assertion_type, limit);
        return;
    }
    let Some(src) = source else {
        fail("Provide --source <frontier> or --all <directory>.");
    };
    if json_output {
        let results = search::search(src, query, entity, assertion_type, limit);
        let loaded = load_frontier_or_fail(src);
        let source_hash = hash_path_or_fail(src);
        let payload = json!({
            "ok": true,
            "command": "search",
            "schema_version": project::VELA_SCHEMA_VERSION,
            "query": query,
            "frontier": {
                "name": &loaded.project.name,
                "source": src.display().to_string(),
                "hash": format!("sha256:{source_hash}"),
            },
            "filters": {
                "entity": entity,
                "assertion_type": assertion_type,
                "limit": limit,
            },
            "count": results.len(),
            "results": results.iter().map(|result| json!({
                "id": &result.id,
                "score": result.score,
                "assertion": &result.assertion,
                "assertion_type": &result.assertion_type,
                "confidence": result.confidence,
                "entities": &result.entities,
                "doi": &result.doi,
            })).collect::<Vec<_>>()
        });
        print_json(&payload);
    } else {
        search::run(src, query, entity, assertion_type, limit);
    }
}

pub(crate) fn cmd_tensions(
    source: &Path,
    both_high: bool,
    cross_domain: bool,
    top: usize,
    json_output: bool,
) {
    let frontier = load_frontier_or_fail(source);
    let result = tensions::analyze(&frontier, both_high, cross_domain, top);
    if json_output {
        let source_hash = hash_path_or_fail(source);
        let payload = json!({
            "ok": true,
            "command": "tensions",
            "schema_version": project::VELA_SCHEMA_VERSION,
            "frontier": {
                "name": &frontier.project.name,
                "source": source.display().to_string(),
                "hash": format!("sha256:{source_hash}"),
            },
            "filters": {
                "both_high": both_high,
                "cross_domain": cross_domain,
                "top": top,
            },
            "count": result.len(),
            "tensions": result.iter().map(|t| json!({
                "score": t.score,
                "resolved": t.resolved,
                "superseding_id": &t.superseding_id,
                "finding_a": {
                    "id": &t.finding_a.id,
                    "assertion": &t.finding_a.assertion,
                    "confidence": t.finding_a.confidence,
                    "assertion_type": &t.finding_a.assertion_type,
                    "contradicts_count": t.finding_a.contradicts_count,
                },
                "finding_b": {
                    "id": &t.finding_b.id,
                    "assertion": &t.finding_b.assertion,
                    "confidence": t.finding_b.confidence,
                    "assertion_type": &t.finding_b.assertion_type,
                    "contradicts_count": t.finding_b.contradicts_count,
                }
            })).collect::<Vec<_>>()
        });
        print_json(&payload);
    } else {
        tensions::print_tensions(&result);
    }
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

pub(crate) fn cmd_integrity(frontier: &Path, json: bool, strict: bool) {
    let mut report = state_integrity::analyze_path(frontier).unwrap_or_else(|e| fail_return(&e));
    // CI gate: --strict treats warnings as failures. Promote the reported status
    // so the JSON and the exit code both reflect the gate; default behaviour is
    // unchanged (informational, exit 0).
    let strict_fail =
        strict && (!report.structural_errors.is_empty() || !report.warnings.is_empty());
    if strict_fail {
        report.status = "fail".to_string();
    }
    if json {
        print_json(&report);
    } else {
        println!("vela integrity");
        println!("  frontier: {}", frontier.display());
        println!("  status: {}", report.status);
        println!("  proof freshness: {}", report.proof_freshness);
        println!("  structural errors: {}", report.structural_errors.len());
        for error in report.structural_errors.iter().take(8) {
            println!("  - {}: {}", error.rule_id, error.message);
        }
        println!("  warnings: {}", report.warnings.len());
        for warning in report.warnings.iter().take(8) {
            println!("  ~ {}: {}", warning.rule_id, warning.message);
        }
        if strict {
            println!("  strict: warnings treated as failures");
        }
    }
    if strict_fail {
        std::process::exit(1);
    }
}
