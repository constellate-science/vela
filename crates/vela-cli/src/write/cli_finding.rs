//! `cmd_finding_show` and its handler logic, split out of cli.rs.

use crate::cli::{fail_return, print_json, wrap_line};

use std::path::Path;
use vela_protocol::cli_style as style;
use vela_protocol::repo;
use vela_protocol::state;

use colored::Colorize;
use serde_json::Value;

pub(crate) fn cmd_finding_show(frontier: &Path, finding_id: &str, json_out: bool) {
    crate::ui::set_mode("finding.show", json_out);
    let project = repo::load_from_path(frontier).unwrap_or_else(|e| fail_return(&e));
    let ctx = state::finding_context(&project, finding_id).unwrap_or_else(|_| {
        crate::cli::fail_not_found(
            &format!("no finding '{finding_id}' in this frontier"),
            "list recent findings: `vela log .` — or search: `vela status .`",
        )
    });
    if json_out {
        print_json(&ctx);
        return;
    }
    let finding = ctx.get("finding").cloned().unwrap_or(Value::Null);
    println!();
    println!(
        "  {}",
        format!("VELA · FINDING · {finding_id}")
            .to_uppercase()
            .dimmed()
    );
    println!("  {}", style::tick_row(60));
    println!(
        "  assertion: {}",
        wrap_line(
            finding
                .pointer("/assertion/text")
                .and_then(Value::as_str)
                .unwrap_or(""),
            82
        )
    );
    let cs = ctx
        .get("confidence_score")
        .and_then(Value::as_f64)
        .unwrap_or_default();
    let cb = ctx
        .get("confidence_basis")
        .and_then(Value::as_str)
        .unwrap_or("unspecified");
    let rv = ctx
        .get("reviewed")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let rk = ctx
        .get("reviewed_by_kind")
        .and_then(Value::as_str)
        .unwrap_or("none");
    println!("  confidence: {cs:.3}  (basis: {cb}) [reviewed: {rv} by {rk}]");
    if cs >= 0.7 && !rv {
        println!("  note: confidence >=0.70 on an unreviewed basis — not adjudicated evidence");
    }
    // Phase 1A: the verification trust tier, rendered DISTINCT from human accept.
    let tier = ctx
        .get("trust_tier")
        .and_then(Value::as_str)
        .unwrap_or("candidate");
    let tier_line = match tier {
        "accepted" => "trust tier: accepted (human, key-custody)".green(),
        "machine_verified" => {
            "trust tier: machine_verified (deterministic exact-lane; not human-accepted)".cyan()
        }
        "schema_checked" => "trust tier: schema_checked".yellow(),
        _ => "trust tier: candidate".dimmed(),
    };
    println!("  {tier_line}");
    // The verification gate (G1–G4), derived — never stored. Reviewer
    // accept and machine seal are DIFFERENT facts; a finding can be
    // human-accepted and still needs_verification, and hiding that gap
    // is the exact failure the gate exists to prevent.
    {
        use vela_protocol::verifier_attachment::{GateStatus, claim_digest, derive_gate_status};
        if let Some(bundle) = project.findings.iter().find(|b| b.id == finding_id) {
            let attachments: Vec<_> = project
                .verifier_attachments
                .iter()
                .filter(|a| a.target == finding_id)
                .cloned()
                .collect();
            let outcome = derive_gate_status(&claim_digest(&bundle.assertion.text), &attachments);
            let status_json = serde_json::json!(outcome.status);
            let status_str = status_json.as_str().unwrap_or("unknown");
            let line = format!(
                "verification: {status_str} ({} attachment{})",
                attachments.len(),
                if attachments.len() == 1 { "" } else { "s" }
            );
            let line = match outcome.status {
                GateStatus::Verified => line.green(),
                GateStatus::Refuted => line.red(),
                _ => line.yellow(),
            };
            println!("  {line}");
            for reason in outcome.reasons.iter().take(3) {
                println!("    · {reason}");
            }
        }
    }
    if let Some(atoms) = ctx.get("evidence_atoms").and_then(Value::as_array) {
        println!("  evidence atoms: {}", atoms.len());
        for a in atoms.iter().take(12) {
            let claim: String = a
                .get("measurement_or_claim")
                .and_then(Value::as_str)
                .unwrap_or("")
                .chars()
                .take(100)
                .collect();
            println!(
                "    - [{}] {} :: {}",
                a.get("source_id").and_then(Value::as_str).unwrap_or(""),
                a.get("locator")
                    .and_then(Value::as_str)
                    .unwrap_or("(no locator)"),
                claim
            );
        }
    }
    if let Some(cr) = ctx.get("condition_records").and_then(Value::as_array)
        && !cr.is_empty()
    {
        println!("  condition records: {}", cr.len());
    }
    if let Some(links) = finding.get("links").and_then(Value::as_array)
        && !links.is_empty()
    {
        println!("  links:");
        for l in links.iter().take(12) {
            println!(
                "    - {} -> {} ({})",
                l.get("type").and_then(Value::as_str).unwrap_or(""),
                l.get("target").and_then(Value::as_str).unwrap_or(""),
                l.get("inferred_by").and_then(Value::as_str).unwrap_or("")
            );
        }
    }
    println!(
        "  canonical events: {}",
        ctx.get("events")
            .and_then(Value::as_array)
            .map_or(0, Vec::len)
    );
}
