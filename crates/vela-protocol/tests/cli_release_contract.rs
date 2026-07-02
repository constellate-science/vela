use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;
use tempfile::TempDir;

fn vela_bin() -> PathBuf {
    if let Ok(env_path) = std::env::var("CARGO_BIN_EXE_vela") {
        return PathBuf::from(env_path);
    }
    // CI may have built only the release binary; check both locations.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let debug = manifest.join("../../target/debug/vela");
    if debug.is_file() {
        return debug;
    }
    let release = manifest.join("../../target/release/vela");
    if release.is_file() {
        return release;
    }
    debug
}

// The bbb-alzheimer fixture is campaign data living in the internal monorepo,
// not the standalone OSS checkout. Returns None when absent so the tests below
// skip cleanly there and still run in-monorepo.
fn copy_bbb_frontier(tmp: &TempDir) -> Option<PathBuf> {
    let source =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../frontiers/bbb-alzheimer.json");
    if !source.exists() {
        return None;
    }
    let target = tmp.path().join("frontier.json");
    fs::copy(source, &target).expect("failed to copy BBB fixture");
    Some(target)
}

fn run_json(args: &[&str]) -> Value {
    let output = Command::new(vela_bin())
        .args(args)
        .output()
        .expect("failed to run vela");
    assert!(
        output.status.success(),
        "vela command failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("command did not return JSON")
}

fn run_text(args: &[&str]) -> String {
    let output = Command::new(vela_bin())
        .args(args)
        .output()
        .expect("failed to run vela");
    assert!(
        output.status.success(),
        "vela command failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("command output was not UTF-8")
}

fn run_expect_failure(args: &[&str]) -> String {
    let output = Command::new(vela_bin())
        .args(args)
        .output()
        .expect("failed to run vela");
    assert!(
        !output.status.success(),
        "vela command unexpectedly succeeded\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn first_finding_id(path: &Path) -> String {
    let data: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    data["findings"][0]["id"].as_str().unwrap().to_string()
}

#[test]
fn check_missing_frontier_reports_error_without_panic() {
    let tmp = TempDir::new().unwrap();
    let missing = tmp.path().join("missing-frontier.json");

    // `stats` was retired; `check` is the kept loader-error contract.
    let error = run_expect_failure(&["check", missing.to_str().unwrap()]);

    assert!(error.contains(missing.to_str().unwrap()));
    assert!(!error.contains("panicked at"));
}

#[test]
fn proof_without_record_proof_state_leaves_input_byte_identical() {
    let tmp = TempDir::new().unwrap();
    let Some(frontier) = copy_bbb_frontier(&tmp) else {
        eprintln!("skip: bbb-alzheimer.json fixture absent (internal-only)");
        return;
    };
    let before = fs::read(&frontier).unwrap();
    let out = tmp.path().join("proof-packet");

    let payload = run_json(&[
        "proof",
        frontier.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
        "--json",
    ]);

    let after = fs::read(&frontier).unwrap();
    assert_eq!(before, after);
    assert_eq!(payload["recorded_proof_state"], false);
    assert_eq!(payload["proof_state"]["latest_packet"]["status"], "current");
}

#[test]
fn proof_record_proof_state_updates_frontier() {
    let tmp = TempDir::new().unwrap();
    let Some(frontier) = copy_bbb_frontier(&tmp) else {
        eprintln!("skip: bbb-alzheimer.json fixture absent (internal-only)");
        return;
    };
    let before = fs::read(&frontier).unwrap();
    let out = tmp.path().join("proof-packet");

    let payload = run_json(&[
        "proof",
        frontier.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
        "--record-proof-state",
        "--json",
    ]);

    let after = fs::read(&frontier).unwrap();
    assert_ne!(before, after);
    assert_eq!(payload["recorded_proof_state"], true);
    let saved: Value = serde_json::from_slice(&after).unwrap();
    assert_eq!(saved["proof_state"]["latest_packet"]["status"], "current");
}

#[test]
fn note_is_proposal_backed_by_default_and_applies_with_flag() {
    let tmp = TempDir::new().unwrap();
    let Some(frontier) = copy_bbb_frontier(&tmp) else {
        eprintln!("skip: bbb-alzheimer.json fixture absent (internal-only)");
        return;
    };
    let finding_id = first_finding_id(&frontier);
    let before: Value = serde_json::from_slice(&fs::read(&frontier).unwrap()).unwrap();
    let initial_annotations = before["findings"][0]["annotations"]
        .as_array()
        .map(Vec::len)
        .unwrap_or(0);

    let pending = run_json(&[
        "note",
        frontier.to_str().unwrap(),
        &finding_id,
        "--text",
        "Track evidence scope before reuse.",
        "--author",
        "reviewer:test",
        "--json",
    ]);
    assert_eq!(pending["proposal_status"], "pending_review");
    assert_ne!(pending["proposal_id"], "none");
    assert!(pending.get("applied_event_id").is_none());

    let after_pending: Value = serde_json::from_slice(&fs::read(&frontier).unwrap()).unwrap();
    assert_eq!(
        after_pending["findings"][0]["annotations"]
            .as_array()
            .map(Vec::len)
            .unwrap_or(0),
        initial_annotations
    );
    // v0.49: the BBB sample now ships with applied proposals (10
    // canonical state transitions populated for the falsifier
    // numerator). The note proposal we just submitted is whichever
    // entry is `pending_review`, not necessarily index 0.
    let pending_proposals: Vec<&Value> = after_pending["proposals"]
        .as_array()
        .expect("proposals array")
        .iter()
        .filter(|p| p["status"] == "pending_review")
        .collect();
    assert_eq!(pending_proposals.len(), 1, "exactly one pending proposal");
    assert_eq!(pending_proposals[0]["kind"], "finding.note");

    let applied = run_json(&[
        "note",
        frontier.to_str().unwrap(),
        &finding_id,
        "--text",
        "Apply evidence scope note.",
        "--author",
        "reviewer:test",
        "--apply",
        "--json",
    ]);
    assert_eq!(applied["proposal_status"], "applied");
    assert!(applied["applied_event_id"].as_str().is_some());

    let after_applied: Value = serde_json::from_slice(&fs::read(&frontier).unwrap()).unwrap();
    assert_eq!(
        after_applied["findings"][0]["annotations"]
            .as_array()
            .map(Vec::len)
            .unwrap_or(0),
        initial_annotations + 1
    );
    assert_eq!(
        after_applied["events"].as_array().unwrap().last().unwrap()["kind"],
        "finding.noted"
    );
}

#[test]
fn tool_check_json_has_concise_tool_lists() {
    let tmp = TempDir::new().unwrap();
    let Some(frontier) = copy_bbb_frontier(&tmp) else {
        eprintln!("skip: bbb-alzheimer.json fixture absent (internal-only)");
        return;
    };

    let payload = run_json(&[
        "serve",
        frontier.to_str().unwrap(),
        "--check-tools",
        "--json",
    ]);

    assert_eq!(payload["ok"], true);
    assert!(payload["tool_count"].as_u64().unwrap() >= 5);
    assert!(
        payload["tools"]
            .as_array()
            .unwrap()
            .contains(&Value::String("orient".to_string()))
    );
    // The registered surface is the ten-tool contract.
    assert_eq!(payload["registered_tool_count"].as_u64().unwrap(), 10);
    assert!(
        payload["registered_tools"]
            .as_array()
            .unwrap()
            .contains(&Value::String("external".to_string()))
    );
}

#[test]
fn advanced_help_quickstart_uses_release_commands() {
    let help = run_text(&["help", "advanced"]);

    assert!(help.contains("check         The full trust gate"));
    assert!(
        help.contains("reproduce     Re-verify stored witnesses from scratch (frozen verifiers)")
    );

    assert!(!help.contains("bridges derive"));
    assert!(!help.contains("vela workbench"));
    // The v0.700 cut: the help must advertise nothing the binary
    // cannot run. These were the most prominent removed families.
    // (`atlas` is NOT here: it is a live first-class noun group —
    // cross-frontier projection, `vela atlas <frontier>` — and is now
    // correctly listed in the advanced-help Nouns block alongside
    // workspace/task/serve. `policy` likewise.)
    for dead in [
        "scout",
        "compile-notes",
        "clinical-trial-import",
        "source-inbox",
        "constellation",
        "federation",
        "  bridge ",
        "  packet ",
        "  bench ",
        "Workbench",
    ] {
        assert!(
            !help.contains(dead),
            "help advanced still advertises removed surface: {dead}"
        );
    }
}
