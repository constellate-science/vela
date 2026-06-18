//! `cmd_check` and its handler logic, split out of cli.rs.

use crate::cli::{
    check_json_payload, fail, load_frontier_or_fail, print_json, print_signal_summary,
    scan_for_sensitive_paths,
};
use serde_json::Value;
use std::path::Path;
use vela_edge::conformance;
use vela_edge::lint;
use vela_edge::signals;
use vela_edge::validate;
use vela_protocol::cli_style as style;
use vela_protocol::events;
use vela_protocol::sign;

pub(crate) fn cmd_check(
    source: Option<&Path>,
    schema: bool,
    stats: bool,
    conformance_flag: bool,
    conformance_dir: &Path,
    all: bool,
    schema_only: bool,
    strict: bool,
    fix: bool,
    json_output: bool,
) {
    if json_output {
        let Some(src) = source else {
            fail("--json requires a frontier source");
        };
        let payload = check_json_payload(src, schema_only, strict);
        print_json(&payload);
        if payload.get("ok").and_then(Value::as_bool) != Some(true) {
            std::process::exit(1);
        }
        return;
    }

    // v0.113: secret-audit pass under --strict runs first, before any
    // signal/replay check that could short-circuit via process::exit.
    // Scans the frontier tree for files matching sensitive-path shapes
    // (private keys, PEM files, files whose names contain "credential",
    // "private", "secret"). Closes part of THREAT_MODEL.md A17 by giving
    // every user's frontier active detection on top of the passive
    // .gitignore exclusion shipped at v0.111.1. Only runs in strict
    // mode so the default vela check stays quiet when a user has
    // intentionally placed a key under their frontier (e.g. for local
    // signing) that they have NOT committed.
    if strict && let Some(src) = source {
        let hits = scan_for_sensitive_paths(src);
        if !hits.is_empty() {
            eprintln!(
                "{} secret-audit: {} sensitive path(s) found under {}",
                style::err_prefix(),
                hits.len(),
                src.display()
            );
            for hit in &hits {
                eprintln!("  - {}", hit.display());
            }
            eprintln!(
                "  hint: add `keys/` and `*.key` to .gitignore so these never reach a public repo (see THREAT_MODEL.md A17)"
            );
            std::process::exit(1);
        }
    }

    let run_all = all || (!schema && !stats && !conformance_flag && !schema_only);
    if run_all || schema || schema_only {
        let Some(src) = source else {
            fail("check requires a frontier source");
        };
        validate::run(src);
    }
    if !schema_only && (run_all || stats) {
        let Some(src) = source else {
            fail("--stats requires a frontier source");
        };
        let frontier = load_frontier_or_fail(src);
        let report = lint::lint(&frontier, None, None);
        lint::print_report(&report);
        let replay_report = events::replay_report(&frontier);
        println!("event replay: {}", replay_report.status);
        if !replay_report.conflicts.is_empty() {
            for conflict in &replay_report.conflicts {
                println!("  - {conflict}");
            }
        }
        // Loader = reducer: the materialized state must be reproducible
        // from its own event log (genesis seeded from the proposal
        // payload store, then one full reducer replay). A divergence
        // here means the loader and the reducer disagree — the bug
        // class that silently dropped side tables four times.
        let replay_verification = vela_protocol::reducer::verify_replay(&frontier);
        println!("replay verification: {}", replay_verification.note);
        if !replay_verification.ok {
            for diff in replay_verification.diffs.iter().take(20) {
                println!("  - {diff}");
            }
        }
        // Review-decision parity: every proposal's stored status must be
        // backed by a signed, replayable decision event in the log (a
        // `review.*` event, or for an accept its domain event). A rejected
        // proposal with no `review.rejected` event behind it is a
        // decision with no tamper-evident record — the silent-drop vector.
        // This makes the mutable `status` field a verified projection.
        let parity_conflicts = vela_protocol::proposals::verify_proposal_decision_parity(&frontier);
        println!(
            "review-decision parity: {}",
            if parity_conflicts.is_empty() {
                "ok".to_string()
            } else {
                format!("{} conflict(s)", parity_conflicts.len())
            }
        );
        for conflict in parity_conflicts.iter().take(20) {
            println!("  - {conflict}");
        }
        // Activity/state boundary: no activity-plane id (vac_/vrr_) may appear
        // in a lineage-bearing position of accepted state (a finding's
        // dependency link, a verifier gate's target/independence). Activity is
        // non-authoritative by construction; a leak here is a soundness break
        // (the `activity::assert_not_in_lineage` law, over the live frontier).
        let activity_leaks = vela_protocol::activity::activity_ids_in_lineage(
            &frontier.findings,
            &frontier.verifier_attachments,
        );
        println!(
            "activity/state boundary: {}",
            if activity_leaks.is_empty() {
                "ok".to_string()
            } else {
                format!("{} leak(s)", activity_leaks.len())
            }
        );
        for (holder, atom) in activity_leaks.iter().take(20) {
            println!("  - {holder} references activity id {atom} in lineage");
        }
        // Key-custody audit: once a reviewer is registered WITH a key,
        // their accept events should carry a signature (key possession is
        // the accept authority). Unsigned accepts predating key
        // registration are warned, not failed — history is immutable.
        let keyed_reviewers: std::collections::HashSet<&str> = frontier
            .actors
            .iter()
            .filter(|a| a.id.starts_with("reviewer:") && !a.public_key.trim().is_empty())
            .map(|a| a.id.as_str())
            .collect();
        let unsigned_keyed_accepts = frontier
            .events
            .iter()
            .filter(|e| {
                e.signature.is_none()
                    && keyed_reviewers.contains(e.actor.id.as_str())
                    && (e.kind.as_str().ends_with(".reviewed") || e.kind == "finding.asserted")
            })
            .count();
        // Prior-art collision lint: exact normalized-statement duplicates
        // among non-superseded findings are a state error.
        let mut seen_hashes: std::collections::HashMap<String, &str> =
            std::collections::HashMap::new();
        let mut collisions = Vec::new();
        for f in frontier.findings.iter().filter(|f| !f.flags.superseded) {
            let h = vela_protocol::canonical::normalized_statement_hash(&f.assertion.text);
            if let Some(prev) = seen_hashes.get(&h) {
                collisions.push(format!("{} duplicates {}", f.id, prev));
            } else {
                seen_hashes.insert(h, f.id.as_str());
            }
        }
        if !collisions.is_empty() {
            println!("prior-art collisions: {}", collisions.len());
            for c in collisions.iter().take(10) {
                println!("  - {c}");
            }
        }
        if unsigned_keyed_accepts > 0 {
            println!(
                "key custody: {unsigned_keyed_accepts} accept-class event(s) by keyed reviewers carry no signature (history predating key registration; new accepts require --key)"
            );
        }
        if let Ok(signature_report) = sign::verify_frontier_data(&frontier, None)
            && signature_report.signed > 0
        {
            println!(
                "Signatures: {} valid / {} invalid / {} unsigned",
                signature_report.valid, signature_report.invalid, signature_report.unsigned
            );
        }
        let signal_report = signals::analyze(&frontier, &[]);
        print_signal_summary(&signal_report, strict);
        if !replay_report.ok
            || !replay_verification.ok
            || !parity_conflicts.is_empty()
            || !activity_leaks.is_empty()
            || (strict
                && (!signal_report.review_queue.is_empty()
                    || signal_report.proof_readiness.status != "ready"))
        {
            std::process::exit(1);
        }
    }
    if run_all || conformance_flag {
        // v0.106: a fresh `cargo install vela-cli` user runs `vela check`
        // from a directory without `conformance/` (those vectors
        // live in the source repo). Pre-v0.106 the default
        // `run_all` path called `conformance::run` unconditionally,
        // which `process::exit(1)`'d with a confusing error. Skip
        // gracefully when the conformance dir is missing AND the
        // user did not pass `--conformance` explicitly. The
        // explicit `--conformance` flag still errors, which is the
        // right behavior for someone who asked for it.
        if conformance_flag || conformance_dir.is_dir() {
            conformance::run(conformance_dir);
        } else {
            eprintln!(
                "  conformance: skipped ({} not present; pass --conformance-dir <path> to point at the source repo's conformance directory)",
                conformance_dir.display()
            );
        }
    }
    let _ = fix;
}
