//! `vela atlas` — the Math Atlas surface (spec `docs/research/MATH_ATLAS.md`).
//!
//!   - `vela atlas <frontier>...`     read-only cross-frontier projection (step 3)
//!   - `vela atlas ingest <frontier> --namespace erdos`   bulk-anchor a corpus
//!
//! Ingest is the corpus move: it derives an external-catalogue anchor for every
//! finding that carries one (e.g. "Erdős Problem #N" → `(erdos, N, "problem")`),
//! signs each as a `val_` anchor link, and writes them all in one load/save pass.
//! Anchors are mechanical, retractable annotations (a fact about which external
//! id a claim names), so the ingest is agent-signed, not a human accept. Idempotent:
//! re-running skips findings that already carry the same `(namespace, id, role)`.

use std::path::Path;

use serde_json::json;
use vela_protocol::{atlas, repo};

use crate::cli::{fail, print_json};

/// Entry from the `cli.rs::run_from_args` intercept.
pub(crate) fn run(args: &[String]) {
    if args.get(2).map(String::as_str) == Some("ingest") {
        run_ingest(args);
        return;
    }
    if args.get(2).map(String::as_str) == Some("ingest-source") {
        run_ingest_source(args);
        return;
    }
    if args.get(2).map(String::as_str) == Some("frontier") {
        run_frontier(args);
        return;
    }
    let frontiers: Vec<&str> = args
        .iter()
        .skip(2)
        .filter(|a| !a.starts_with('-'))
        .map(String::as_str)
        .collect();
    if frontiers.is_empty() {
        fail(
            "usage: vela atlas <frontier> [<frontier> ...]   |   vela atlas ingest <frontier> --namespace <ns>",
        );
    }
    let projects: Vec<_> = frontiers
        .iter()
        .map(|f| {
            repo::load_from_path(Path::new(f)).unwrap_or_else(|e| fail(&format!("load {f}: {e}")))
        })
        .collect();
    let refs: Vec<&_> = projects.iter().collect();
    let out = atlas::project(&refs);
    print_json(&serde_json::to_value(&out).unwrap_or_else(|e| fail(&format!("serialize: {e}"))));
}

/// The digits that follow `keyword` (ASCII, case-insensitive) in `text`, after
/// skipping up to `max_skip` non-digit separators. e.g. `("erdos", 2)` finds the
/// number in "Erdos257", "erdos_257", "Erdős-642" (ASCII match on "erdos").
fn digits_after(text: &str, keyword: &str, max_skip: usize) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    let pos = lower.find(keyword)?;
    let mut chars = text[pos + keyword.len()..].chars().peekable();
    let mut skipped = 0;
    while let Some(&c) = chars.peek() {
        if c.is_ascii_digit() {
            break;
        }
        if skipped >= max_skip {
            return None;
        }
        chars.next();
        skipped += 1;
    }
    let digits: String = chars.take_while(char::is_ascii_digit).collect();
    (!digits.is_empty()).then_some(digits)
}

/// `vela atlas frontier <frontier>...` — the router view: the status landscape,
/// the edge count, and the **stale-open frontier** (problems marked open in one
/// source but resolved in another — the registry-stale wedge, an adoption queue).
fn run_frontier(args: &[String]) {
    let frontiers: Vec<&str> = args
        .iter()
        .skip(3)
        .filter(|a| !a.starts_with('-'))
        .map(String::as_str)
        .collect();
    if frontiers.is_empty() {
        fail("usage: vela atlas frontier <frontier> [<frontier> ...]");
    }
    let projects: Vec<_> = frontiers
        .iter()
        .map(|f| {
            repo::load_from_path(Path::new(f)).unwrap_or_else(|e| fail(&format!("load {f}: {e}")))
        })
        .collect();
    let refs: Vec<&_> = projects.iter().collect();
    let out = atlas::project(&refs);

    let mut by_status: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    let mut stale_open: Vec<serde_json::Value> = Vec::new();
    for c in &out.cells {
        let s = c.status.clone().unwrap_or_else(|| "undeclared".to_string());
        *by_status.entry(s.clone()).or_default() += 1;
        if s == "contested" {
            stale_open.push(json!({
                "handle": c.stable_handle, "members": c.members.len(), "label": c.label,
            }));
        }
    }
    print_json(&json!({
        "frontiers": out.frontiers,
        "cells": out.cells.len(),
        "edges": out.edges.len(),
        "status_landscape": by_status,
        "stale_open_frontier": {
            "note": "open in one source, resolved in another — the registry-stale wedge (an adoption queue)",
            "count": stale_open.len(),
            "cells": stale_open,
        },
    }));
}

/// Extract a problem/sequence number from a finding's assertion text. Handles
/// "Erdős Problem #105", "#105", "Problem 105", "Erdos257", "erdos_1150",
/// "A309370" — so the same problem written different ways in different databases
/// lands on the same anchor.
fn extract_id(namespace: &str, text: &str) -> Option<String> {
    match namespace {
        "oeis" => {
            let bytes = text.as_bytes();
            for (i, &b) in bytes.iter().enumerate() {
                if b == b'A' {
                    let digits: String = text[i + 1..]
                        .chars()
                        .take_while(char::is_ascii_digit)
                        .collect();
                    if digits.len() >= 6 {
                        return Some(format!("A{digits}"));
                    }
                }
            }
            None
        }
        _ => digits_after(text, "#", 0)
            .or_else(|| digits_after(text, "erdos", 2))
            .or_else(|| digits_after(text, "problem ", 0)),
    }
}

fn run_ingest(args: &[String]) {
    use vela_protocol::anchor::{Anchor, AnchorKind, JoinPolicy};

    let positionals: Vec<&str> = args
        .iter()
        .skip(3)
        .filter(|a| !a.starts_with('-'))
        .map(String::as_str)
        .collect();
    let frontier = positionals.first().copied().unwrap_or_else(|| {
        fail("usage: vela atlas ingest <frontier> --namespace <erdos|oeis> [--dry-run] [--key <agentkey>] [--actor <agent>]")
    });
    let flag = |name: &str| -> Option<String> {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .map(|s| s.to_string())
    };
    let ns = flag("--namespace").unwrap_or_else(|| fail("--namespace is required (erdos|oeis)"));
    let dry = args.iter().any(|a| a == "--dry-run");
    let actor = flag("--actor").unwrap_or_else(|| "agent:atlas-ingest".to_string());
    let kind = match ns.as_str() {
        "erdos" => AnchorKind::ProblemEntry,
        "oeis" => AnchorKind::Sequence,
        _ => AnchorKind::Statement,
    };
    // The anchor role is part of the join key, so it must be namespace-correct: an
    // OEIS node is a sequence, an Erdős node is a problem. A different source
    // anchoring the same sequence with role "sequence" must land on the same cell.
    let role = match ns.as_str() {
        "oeis" => "sequence",
        _ => "problem",
    }
    .to_string();

    let mut project = repo::load_from_path(Path::new(frontier)).unwrap_or_else(|e| fail(&e));

    // Plan the anchors (idempotent: skip findings already carrying this anchor).
    let mut plan: Vec<(String, Anchor)> = Vec::new();
    let (mut already, mut no_number) = (0usize, 0usize);
    for f in &project.findings {
        let Some(id) = extract_id(&ns, &f.assertion.text) else {
            no_number += 1;
            continue;
        };
        let exists = project.anchor_links.iter().any(|l| {
            l.target == f.id
                && l.anchor.namespace == ns
                && l.anchor.id == id
                && l.anchor.role == role
        });
        if exists {
            already += 1;
            continue;
        }
        plan.push((
            f.id.clone(),
            Anchor {
                namespace: ns.clone(),
                id,
                role: role.clone(),
                kind,
                join_policy: JoinPolicy::HardIdentity,
                namespace_version: None,
                source_revision: None,
                statement_fingerprint: None,
            },
        ));
    }

    if dry {
        let sample: Vec<_> = plan
            .iter()
            .take(8)
            .map(|(t, a)| json!({"target": t, "anchor": format!("{}:{}#{}", a.namespace, a.id, a.role)}))
            .collect();
        print_json(&json!({
            "dry_run": true, "namespace": ns,
            "would_anchor": plan.len(), "already_anchored": already,
            "no_number_skipped": no_number, "sample": sample,
        }));
        return;
    }

    let key = crate::cli_identity::resolve_signing_key(flag("--key").as_deref().map(Path::new));
    let anchored = anchor_findings(&mut project, plan, &actor, &key);
    repo::save_to_path(Path::new(frontier), &project).unwrap_or_else(|e| fail(&e));
    print_json(&json!({
        "ok": true, "namespace": ns, "anchored": anchored,
        "already_anchored": already, "no_number_skipped": no_number, "signer": actor,
    }));
}

/// Attach a planned set of `(finding_id, anchor)` as signed `anchor.attached`
/// events. Shared by `ingest` (text-derived anchors) and `ingest-source`
/// (adapter-derived anchors). Anchors are mechanical, retractable annotations,
/// so agent-signing is in-doctrine (not a human accept). Returns the count.
fn anchor_findings(
    project: &mut vela_protocol::project::Project,
    plan: Vec<(String, vela_protocol::anchor::Anchor)>,
    actor: &str,
    key: &ed25519_dalek::SigningKey,
) -> usize {
    use vela_protocol::anchor::{AnchorLink, AnchorLinkDraft};
    let mut anchored = 0usize;
    for (target, anchor) in plan {
        let link = AnchorLink::build(
            AnchorLinkDraft {
                target: target.clone(),
                anchor,
                attached_by: actor.to_string(),
                attached_at: chrono::Utc::now().to_rfc3339(),
            },
            key,
        )
        .unwrap_or_else(|e| fail(&e));
        let event =
            vela_protocol::events::new_finding_event(vela_protocol::events::FindingEventInput {
                kind: "anchor.attached",
                finding_id: &target,
                actor_id: actor,
                actor_type: vela_protocol::events::actor_kind(actor),
                reason: "atlas ingest: external-catalogue anchor",
                before_hash: "sha256:null",
                after_hash: "sha256:null",
                payload: json!({ "anchor_link": link }),
                caveats: Vec::new(),
                timestamp: None,
            });
        vela_protocol::reducer::apply_event(project, &event).unwrap_or_else(|e| fail(&e));
        project.events.push(event);
        anchored += 1;
    }
    anchored
}

/// `vela atlas ingest-source --adapter <formal|alphaproof> --input <dir> --out
/// <frontier.json|repo> [--namespace erdos|oeis] [--rev <prov>] [--actor <a>]
/// [--key <agentkey>] [--dry-run]` — the native production path that replaces
/// the synthetic-id Python prototypes. Reads a catalogue via a `SourceAdapter`,
/// mints real content-addressed finding bundles (genesis remnants), attaches
/// signed `anchor.attached` events, and writes the repo — then gates on
/// `verify_replay` (the loader-is-reducer round-trip). Deterministic: same
/// source in → same repo out.
fn run_ingest_source(args: &[String]) {
    use vela_protocol::anchor::{Anchor, AnchorKind, JoinPolicy};

    let flag = |name: &str| -> Option<String> {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .map(|s| s.to_string())
    };
    let adapter = flag("--adapter")
        .unwrap_or_else(|| fail("--adapter is required (formal|alphaproof)"));
    let input = flag("--input").unwrap_or_else(|| fail("--input <dir> is required"));
    let out = flag("--out")
        .unwrap_or_else(|| fail("--out <frontier.json|repo-dir> is required"));
    let ns = flag("--namespace").unwrap_or_else(|| "erdos".to_string());
    let rev = flag("--rev").unwrap_or_else(|| "unknown".to_string());
    let actor = flag("--actor").unwrap_or_else(|| "agent:atlas-ingest".to_string());
    let dry = args.iter().any(|a| a == "--dry-run");

    let (kind, role) = match ns.as_str() {
        "oeis" => (AnchorKind::Sequence, "sequence"),
        _ => (AnchorKind::ProblemEntry, "problem"),
    };

    let records = crate::atlas_adapters::read_adapter(&adapter, Path::new(&input), &rev)
        .unwrap_or_else(|e| fail(&e));
    if records.is_empty() {
        fail(&format!("adapter '{adapter}' yielded no records from {input}"));
    }

    // Build content-addressed findings (deduped by id) + an anchor plan entry
    // per record. Fresh build each run — these source frontiers are regenerable.
    let mut findings = Vec::new();
    let mut plan: Vec<(String, Anchor)> = Vec::new();
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut id_by_extid: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    for rec in &records {
        let finding = crate::atlas_adapters::build_finding(rec, &adapter);
        let fid = finding.id.clone();
        if !seen.insert(fid.clone()) {
            continue; // duplicate content-address (same text+type+id)
        }
        id_by_extid.entry(rec.external_id.clone()).or_insert(fid.clone());
        findings.push(finding);
        plan.push((
            fid,
            Anchor {
                namespace: ns.clone(),
                id: rec.external_id.clone(),
                role: role.to_string(),
                kind,
                join_policy: JoinPolicy::HardIdentity,
                namespace_version: None,
                source_revision: Some(rev.clone()),
                statement_fingerprint: None,
            },
        ));
    }

    // Second pass: resolve cross-problem `implies` edges now that every finding
    // id is known. A typed `implies` link from the source finding to the target
    // problem's finding lifts to a real erdos→erdos edge in `vela atlas`. Sparse.
    let mut edges = 0usize;
    for rec in &records {
        if rec.implies.is_empty() {
            continue;
        }
        let Some(src_id) = id_by_extid.get(&rec.external_id).cloned() else {
            continue;
        };
        for tgt_ext in &rec.implies {
            if let Some(tgt_id) = id_by_extid.get(tgt_ext)
                && let Some(f) = findings.iter_mut().find(|f| f.id == src_id)
            {
                f.add_link(
                    tgt_id,
                    "implies",
                    &format!("Lean: erdos_{} implies_erdos_{}", rec.external_id, tgt_ext),
                );
                edges += 1;
            }
        }
    }

    if dry {
        print_json(&json!({
            "dry_run": true, "adapter": adapter, "namespace": ns,
            "records": records.len(), "findings": findings.len(), "anchors": plan.len(),
            "cross_problem_edges": edges,
        }));
        return;
    }

    let mut project = vela_protocol::project::assemble(
        &format!("Atlas source: {adapter}"),
        findings,
        0,
        0,
        &format!("Native atlas source adapter ({adapter}) @ {rev}"),
    );

    let key = crate::cli_identity::resolve_signing_key(flag("--key").as_deref().map(Path::new));
    let anchored = anchor_findings(&mut project, plan, &actor, &key);

    let out_path = Path::new(&out);
    if let Some(parent) = out_path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .unwrap_or_else(|e| fail(&format!("create {}: {e}", parent.display())));
    }
    repo::save_to_path(out_path, &project).unwrap_or_else(|e| fail(&e));

    // Gate: the loader-is-reducer round-trip must hold. Findings ride as genesis
    // remnants (no introducing event); the anchor events replay cleanly.
    let reloaded = repo::load_from_path(out_path).unwrap_or_else(|e| fail(&e));
    let replay = vela_protocol::reducer::verify_replay(&reloaded);

    print_json(&json!({
        "ok": true, "adapter": adapter, "namespace": ns,
        "findings": project.findings.len(), "anchored": anchored,
        "cross_problem_edges": edges,
        "out": out, "verify_replay_ok": replay.ok, "signer": actor,
    }));
}
