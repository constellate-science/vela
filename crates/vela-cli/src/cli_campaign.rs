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
use std::path::Path;

pub(crate) fn cmd_campaign(action: CampaignAction) {
    match action {
        CampaignAction::Search {
            kind,
            n,
            h,
            restarts,
            seed,
            json,
        } => cmd_search(&kind, n, h, restarts, seed, json),
        CampaignAction::Run {
            kind,
            n,
            h,
            restarts,
            seed,
            out,
            frontier,
            propose,
            reviewer,
            json,
        } => cmd_run(
            &kind, n, h, restarts, seed, out, frontier, propose, &reviewer, json,
        ),
    }
}

fn cmd_search(kind: &str, n: usize, h: usize, restarts: u64, seed: u64, json_out: bool) {
    let found = campaign::search(kind, n, h, restarts, seed).unwrap_or_else(|e| fail_return(&e));
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
    kind: &str,
    n: usize,
    h: usize,
    restarts: u64,
    seed: u64,
    out: Option<std::path::PathBuf>,
    frontier: Option<std::path::PathBuf>,
    propose: bool,
    reviewer: &str,
    json_out: bool,
) {
    let found = campaign::search(kind, n, h, restarts, seed).unwrap_or_else(|e| fail_return(&e));
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
            .unwrap_or_else(|| {
                fail_return("campaign run needs --out <file> or --frontier <dir>")
            })
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
    std::fs::write(&out_path, body + "\n")
        .unwrap_or_else(|e| fail_return(&format!("write {}: {e}", out_path.display())));

    // Optionally land a pending finding.add proposal (no key -> pending; a
    // key-holder accepts). Shell to the same `vela finding add` the rest of the
    // tool uses, so the proposal is byte-identical to a hand-made one.
    let mut proposal_note = None;
    if propose {
        let fr = frontier.as_ref().unwrap_or_else(|| {
            fail_return("campaign run --propose needs --frontier <dir>")
        });
        let assertion = assertion_for(kind, n, h, f.score);
        propose_pending(fr, &assertion, reviewer);
        proposal_note = Some(assertion);
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
            "proposed": propose,
            "assertion": proposal_note,
        }));
    } else {
        println!(
            "· campaign {kind} n={n}: verified score {} → {}",
            f.score,
            out_path.display()
        );
        if let Some(a) = proposal_note {
            println!("  proposed (pending review): {a}");
            println!("  accept with your key: vela accept <frontier> <proposal-id> --reviewer {reviewer} --key <key>");
        } else {
            println!("  re-verify: vela reproduce {}", out_path.display());
        }
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
        "costas" => format!(
            "a Costas array of order {n}. Frozen-verified by vela-verify (costas kind)."
        ),
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
