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
    use vela_protocol::anchor::{Anchor, AnchorKind, AnchorLink, AnchorLinkDraft, JoinPolicy};

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

    let mut project = repo::load_from_path(Path::new(frontier)).unwrap_or_else(|e| fail(&e));

    // Plan the anchors (idempotent: skip findings already carrying this anchor).
    let role = "problem".to_string();
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
    let mut anchored = 0usize;
    for (target, anchor) in plan {
        let link = AnchorLink::build(
            AnchorLinkDraft {
                target: target.clone(),
                anchor,
                attached_by: actor.clone(),
                attached_at: chrono::Utc::now().to_rfc3339(),
            },
            &key,
        )
        .unwrap_or_else(|e| fail(&e));
        let event =
            vela_protocol::events::new_finding_event(vela_protocol::events::FindingEventInput {
                kind: "anchor.attached",
                finding_id: &target,
                actor_id: &actor,
                actor_type: vela_protocol::events::actor_kind(&actor),
                reason: "atlas ingest: external-catalogue anchor",
                before_hash: "sha256:null",
                after_hash: "sha256:null",
                payload: json!({ "anchor_link": link }),
                caveats: Vec::new(),
                timestamp: None,
            });
        vela_protocol::reducer::apply_event(&mut project, &event).unwrap_or_else(|e| fail(&e));
        project.events.push(event);
        anchored += 1;
    }
    repo::save_to_path(Path::new(frontier), &project).unwrap_or_else(|e| fail(&e));
    print_json(&json!({
        "ok": true, "namespace": ns, "anchored": anchored,
        "already_anchored": already, "no_number_skipped": no_number, "signer": actor,
    }));
}
