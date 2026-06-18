//! `vela campaign` — drive the discovery engine from the CLI. `search` runs the
//! engine and reports the best verified construction it found (writing
//! nothing); `run` additionally writes the witness so `vela reproduce` covers
//! it, and can land a *pending* `finding.add` proposal (key-free — AI proposes,
//! a key-holder accepts). The engine itself lives in `crate::campaign`; this
//! module is only orchestration + reporting.

use crate::campaign;
use crate::cli::{fail_return, print_json};
use crate::cli_commands::CampaignAction;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::path::Path;
use vela_protocol::activity::{ActivityDraft, ActivityEnvelope};

pub(crate) fn cmd_campaign(action: CampaignAction) {
    match action {
        CampaignAction::Search {
            kind,
            n,
            h,
            d,
            w,
            k,
            t,
            restarts,
            seed,
            json,
        } => cmd_search(
            &campaign::Target {
                kind,
                n,
                h,
                d,
                w,
                k,
                t,
            },
            restarts,
            seed,
            json,
        ),
        CampaignAction::Run {
            kind,
            n,
            h,
            d,
            w,
            k,
            t,
            restarts,
            seed,
            out,
            frontier,
            propose,
            reviewer,
            json,
        } => cmd_run(
            &campaign::Target {
                kind,
                n,
                h,
                d,
                w,
                k,
                t,
            },
            restarts,
            seed,
            out,
            frontier,
            propose,
            &reviewer,
            json,
        ),
    }
}

fn cmd_search(tg: &campaign::Target, restarts: u64, seed: u64, json_out: bool) {
    let (kind, n, h) = (tg.kind.as_str(), tg.n, tg.h);
    let found = campaign::search_target(tg, restarts, seed).unwrap_or_else(|e| fail_return(&e));
    let Some(f) = found else {
        if json_out {
            print_json(&json!({
                "command": "campaign search", "kind": kind, "n": n,
                "found": false,
            }));
        } else {
            println!("· campaign {kind} n={n}: no witness found within {restarts} restarts");
        }
        return;
    };
    if json_out {
        print_json(&json!({
            "command": "campaign search",
            "kind": kind, "n": n, "h": h,
            "found": true,
            "score": f.score,
            "restarts": f.iterations,
            "seed": seed,
            "witness": f.witness,
            "verified": true,
        }));
    } else {
        println!(
            "· campaign {kind} n={n}: best verified score {} (over {} restarts, seed {seed})",
            f.score, f.iterations
        );
        println!("  the witness re-checks under the frozen verifier (vela-verify).");
    }
}

#[allow(clippy::too_many_arguments)]
fn cmd_run(
    tg: &campaign::Target,
    restarts: u64,
    seed: u64,
    out: Option<std::path::PathBuf>,
    frontier: Option<std::path::PathBuf>,
    propose: bool,
    reviewer: &str,
    json_out: bool,
) {
    let (kind, n, h) = (tg.kind.as_str(), tg.n, tg.h);
    let found = campaign::search_target(tg, restarts, seed).unwrap_or_else(|e| fail_return(&e));
    let f = match found {
        Some(f) => f,
        None => fail_return(&format!(
            "campaign {kind} n={n}: no witness found within {restarts} restarts (raise --restarts or --seed)"
        )),
    };

    // Resolve the witness output path: explicit --out, else
    // <frontier>/witnesses/<kind>-n<N>[-h<H>].witness.json.
    let out_path = out.unwrap_or_else(|| {
        let dir = frontier
            .as_ref()
            .unwrap_or_else(|| fail_return("campaign run needs --out <file> or --frontier <dir>"))
            .join("witnesses");
        let name = if kind == "bh" {
            format!("{kind}-n{n}-h{h}.witness.json")
        } else {
            format!("{kind}-n{n}.witness.json")
        };
        dir.join(name)
    });
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .unwrap_or_else(|e| fail_return(&format!("create {}: {e}", parent.display())));
    }
    let body = serde_json::to_string_pretty(&f.witness)
        .unwrap_or_else(|e| fail_return(&format!("serialize witness: {e}")));
    let witness_bytes = format!("{body}\n");
    std::fs::write(&out_path, &witness_bytes)
        .unwrap_or_else(|e| fail_return(&format!("write {}: {e}", out_path.display())));

    // Record the search as ACTIVITY, never as state. The engine is a heuristic
    // producer; `search_target` already ran the FROZEN verifier (vela-verify) on
    // this witness before returning it, so the candidate is target-checked, but a
    // target-checked candidate is still a PROPOSAL until a key-holder accepts it.
    // The envelope is content-addressed (`vac_`), non-authoritative by
    // construction, and the `assert_not_in_lineage` law forbids it from ever
    // entering accepted lineage. This is the target-checked lane made legible:
    // agent activity → deterministic target check → candidate + trace, with no
    // model anywhere in the trust path.
    let assertion = assertion_for(kind, n, h, f.score);
    // Address the exact on-disk bytes, so `sha256sum <witness>` reproduces this
    // root independently, so the trace is verifiable against the artifact, not a
    // private re-serialization.
    let witness_digest = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(witness_bytes.as_bytes()))
    );
    let envelope = ActivityEnvelope::new(ActivityDraft {
        actor_id: "agent:vela-campaign".to_string(),
        actor_type: "agent".to_string(),
        kind: "search.candidate".into(),
        base_root: target_descriptor(kind, n, h),
        input_roots: Vec::new(),
        output_roots: vec![witness_digest.clone()],
        tool_digests: vec![format!("vela-verify:{kind}")],
        trace_root: Some(witness_digest),
        risk_tags: vec![
            "heuristic-search".to_string(),
            "lower-bound-only".to_string(),
        ],
        claimed_relation: assertion.clone(),
        created_at: chrono::Utc::now().to_rfc3339(),
    })
    .unwrap_or_else(|e| fail_return(&format!("build activity envelope: {e}")));
    let activity_dir = frontier
        .as_ref()
        .map(|f| f.join("activity"))
        .unwrap_or_else(|| {
            out_path
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| std::path::PathBuf::from("."))
        });
    std::fs::create_dir_all(&activity_dir)
        .unwrap_or_else(|e| fail_return(&format!("create {}: {e}", activity_dir.display())));
    let activity_path = activity_dir.join(format!("{}.json", envelope.activity_id));
    let env_body = serde_json::to_string_pretty(&envelope)
        .unwrap_or_else(|e| fail_return(&format!("serialize activity envelope: {e}")));
    std::fs::write(&activity_path, env_body + "\n")
        .unwrap_or_else(|e| fail_return(&format!("write {}: {e}", activity_path.display())));

    // Optionally land a pending finding.add proposal (no key -> pending; a
    // key-holder accepts). Shell to the same `vela finding add` the rest of the
    // tool uses, so the proposal is byte-identical to a hand-made one.
    let mut proposal_note = None;
    if propose {
        let fr = frontier
            .as_ref()
            .unwrap_or_else(|| fail_return("campaign run --propose needs --frontier <dir>"));
        propose_pending(fr, &assertion, reviewer);
        proposal_note = Some(assertion.clone());
    }

    if json_out {
        print_json(&json!({
            "command": "campaign run",
            "kind": kind, "n": n, "h": h,
            "score": f.score,
            "restarts": f.iterations,
            "seed": seed,
            "witness_path": out_path.display().to_string(),
            "verified": true,
            "activity_id": envelope.activity_id,
            "activity_path": activity_path.display().to_string(),
            "proposed": propose,
            "assertion": proposal_note,
        }));
    } else {
        println!(
            "· campaign {kind} n={n}: verified score {} → {}",
            f.score,
            out_path.display()
        );
        println!(
            "  activity (non-authoritative): {} → {}",
            envelope.activity_id,
            activity_path.display()
        );
        if let Some(a) = proposal_note {
            println!("  proposed (pending review): {a}");
            println!(
                "  accept with your key: vela accept <frontier> <proposal-id> --reviewer {reviewer} --key <key>"
            );
        } else {
            println!("  re-verify: vela reproduce {}", out_path.display());
        }
    }
}

/// A stable descriptor of the target a campaign ran against: the activity
/// envelope's `base_root`. The engine searches fresh against a named cell, so the
/// honest base is that target spec, not a frontier presentation root (it reads
/// none). Mirrors the witness filename convention so the two line up.
fn target_descriptor(kind: &str, n: usize, h: usize) -> String {
    if kind == "bh" {
        format!("campaign-target:{kind}:n{n}:h{h}")
    } else {
        format!("campaign-target:{kind}:n{n}")
    }
}

/// A human-legible lower-bound assertion for a verified construction.
fn assertion_for(kind: &str, n: usize, h: usize, score: usize) -> String {
    match kind {
        "gf2_sidon" => format!(
            "OEIS A394031 a({n}) >= {score}: a Sidon set of {score} elements in GF(2)^{n} (all pairwise XORs distinct). Frozen-verified by vela-verify (gf2_sidon kind)."
        ),
        "union_free" => format!(
            "OEIS A347025 a({n}) >= {score}: a union-free family of {score} subsets of {{1..{n}}} (no member is the union of others). Frozen-verified by vela-verify (union_free kind)."
        ),
        "rook_directions" => format!(
            "OEIS A321531 a({n}) >= {score}: a placement of {n} non-attacking rooks with {score} distinct direction classes. Frozen-verified by vela-verify (rook_directions kind)."
        ),
        "sidon" => format!(
            "OEIS A309370 a({n}) >= {score}: a Sidon set of {score} distinct binary vectors in {{0,1}}^{n} under componentwise integer addition. Frozen-verified by vela-verify (sidon kind)."
        ),
        "bh" => format!(
            "a B_{h} set of {score} distinct binary vectors in {{0,1}}^{n} (all {h}-fold sums distinct). Frozen-verified by vela-verify (bh kind)."
        ),
        "golomb" => format!(
            "a Golomb ruler of order {n} (length {score}). Frozen-verified by vela-verify (golomb kind)."
        ),
        "costas" => {
            format!("a Costas array of order {n}. Frozen-verified by vela-verify (costas kind).")
        }
        _ => format!("{kind} witness, score {score}. Frozen-verified by vela-verify."),
    }
}

/// Land a pending `finding.add` by shelling to this same binary (no `--apply`,
/// so it stays a key-free proposal awaiting a signed accept).
fn propose_pending(frontier: &Path, assertion: &str, reviewer: &str) {
    let exe = std::env::current_exe()
        .unwrap_or_else(|e| fail_return(&format!("locate vela binary: {e}")));
    let status = std::process::Command::new(exe)
        .arg("finding")
        .arg("add")
        .arg(frontier)
        .arg("--assertion")
        .arg(assertion)
        .arg("--type")
        .arg("computational")
        .arg("--source")
        .arg("vela campaign (discovery engine)")
        .arg("--source-type")
        .arg("model_output")
        .arg("--evidence-type")
        .arg("computational")
        .arg("--confidence")
        .arg("1.0")
        .arg("--author")
        .arg(reviewer)
        .status()
        .unwrap_or_else(|e| fail_return(&format!("shell finding add: {e}")));
    if !status.success() {
        fail_return::<()>("campaign: finding add proposal failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn target_descriptor_matches_witness_naming() {
        // Set/order kinds key on n only; `bh` additionally carries the order h,
        // the same split the witness filename uses.
        assert_eq!(target_descriptor("sidon", 5, 2), "campaign-target:sidon:n5");
        assert_eq!(target_descriptor("bh", 9, 3), "campaign-target:bh:n9:h3");
    }

    #[test]
    fn campaign_output_is_activity_never_lineage() {
        // The exact envelope shape `cmd_run` builds. The point of the demonstrator:
        // a heuristic search that the frozen verifier target-checked is still only
        // ACTIVITY: content-addressed, non-authoritative, and forbidden from
        // accepted lineage. The candidate becomes state only via a human accept.
        let env = ActivityEnvelope::new(ActivityDraft {
            actor_id: "agent:vela-campaign".into(),
            actor_type: "agent".into(),
            kind: "search.candidate".into(),
            base_root: target_descriptor("sidon", 5, 2),
            output_roots: vec!["sha256:abc".into()],
            tool_digests: vec!["vela-verify:sidon".into()],
            trace_root: Some("sha256:abc".into()),
            risk_tags: vec!["heuristic-search".into(), "lower-bound-only".into()],
            claimed_relation: assertion_for("sidon", 5, 2, 12),
            created_at: "2026-06-18T00:00:00Z".into(),
            ..Default::default()
        })
        .unwrap();
        assert!(env.activity_id.starts_with("vac_"));
        assert!(!env.is_authoritative());
        env.verify().unwrap();

        // The activity/state boundary law rejects it if it ever leaks into lineage.
        let mut leaked = BTreeSet::new();
        leaked.insert(env.activity_id.clone());
        assert!(vela_protocol::activity::assert_not_in_lineage(&leaked).is_err());
    }
}
