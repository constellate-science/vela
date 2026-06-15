//! V1.1 regression: cross-frontier `Project.dependencies` survive
//! a split-repo materialize cycle.
//!
//! Pre-v0.59 the split-repo loader ignored cross-frontier
//! dependencies entirely. `vela frontier add-dep` wrote into
//! `frontier.json`, but `vela frontier materialize` regenerated
//! that file from events + yaml without the dep section. Any
//! follow-up `vela link add` against the directory then failed
//! with "no matching dep is declared" because the loader saw an
//! empty `Project.dependencies`.
//!
//! v0.59 introduces `ManifestDependencies.frontiers_v2` carrying
//! the full `ProjectDependency` struct in the yaml. The loader
//! rehydrates it on every load. This test proves that the
//! cross-frontier link from a split-repo to a remote vfr_id
//! survives:
//!
//!   1. init a fresh split-repo
//!   2. add a dummy local finding (the link --from anchor)
//!   3. add a cross-frontier dep
//!   4. add a cross-frontier link
//!   5. materialize (which previously wiped the dep)
//!   6. reload, confirm dep + link are both still there

use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;
use tempfile::TempDir;

fn vela_bin() -> PathBuf {
    if let Ok(env_path) = std::env::var("CARGO_BIN_EXE_vela") {
        return PathBuf::from(env_path);
    }
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

fn run_json(args: &[&str]) -> Value {
    let output = Command::new(vela_bin())
        .args(args)
        .output()
        .expect("failed to run vela");
    assert!(
        output.status.success(),
        "vela command failed\nargs: {args:?}\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("command did not return JSON")
}

fn run_ok(args: &[&str]) {
    let output = Command::new(vela_bin())
        .args(args)
        .output()
        .expect("failed to run vela");
    assert!(
        output.status.success(),
        "vela command failed\nargs: {args:?}\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn cross_frontier_dep_and_link_survive_materialize_cycle() {
    let tmp = TempDir::new().expect("tempdir");
    let frontier = tmp.path().join("dep-test");
    let frontier_str = frontier.to_str().unwrap();

    // 1. init a split-repo
    run_json(&[
        "init",
        frontier_str,
        "--name",
        "Dep persistence test",
        "--template",
        "disease-frontier",
        "--no-git",
        "--json",
    ]);

    // 2. add a local finding (the cross-frontier link's --from anchor)
    let finding_payload = run_json(&[
        "finding",
        "add",
        frontier_str,
        "--assertion",
        "Dummy local anchor for the cross-frontier link.",
        "--type",
        "methodological",
        "--source",
        "test fixture",
        "--source-type",
        "expert_assertion",
        "--author",
        "reviewer:test",
        "--apply",
        "--json",
    ]);
    let local_finding_id = finding_payload["finding_id"]
        .as_str()
        .expect("finding_id present in payload")
        .to_string();

    // 3. add a cross-frontier dep
    let target_vfr = "vfr_aaaaaaaaaaaaaaaa";
    let target_vf = "vf_bbbbbbbbbbbbbbbb";
    let target_snapshot = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    run_ok(&[
        "frontier",
        "add-dep",
        frontier_str,
        target_vfr,
        "--locator",
        "https://example.test/frontier.json",
        "--snapshot",
        target_snapshot,
        "--name",
        "test-target-frontier",
    ]);

    // 4. add a cross-frontier link
    run_ok(&[
        "finding",
        "link",
        "add",
        frontier_str,
        "--from",
        &local_finding_id,
        "--to",
        &format!("{target_vf}@{target_vfr}"),
        "--type",
        "depends",
        "--note",
        "Test cross-frontier link.",
        "--inferred-by",
        "reviewer",
        "--no-check-target",
    ]);

    // 5. materialize: this is the step that previously wiped the
    // dep section in frontier.json before v0.59.
    run_json(&["frontier", "materialize", frontier_str, "--json"]);

    // 6a. The dep must still be visible via list-deps after
    // materialize.
    let deps_payload = run_json(&["frontier", "list-deps", frontier_str, "--json"]);
    let deps = deps_payload["dependencies"]
        .as_array()
        .expect("dependencies array");
    assert_eq!(
        deps.len(),
        1,
        "expected exactly one cross-frontier dep after materialize, got {}: {deps_payload}",
        deps.len()
    );
    assert_eq!(deps[0]["vfr_id"], target_vfr);
    assert_eq!(deps[0]["pinned_snapshot_hash"], target_snapshot);

    // 6b. The link must also still be present in the rendered
    // frontier.json.
    let frontier_json: Value = serde_json::from_slice(
        &std::fs::read(frontier.join("frontier.json")).expect("read frontier.json"),
    )
    .expect("parse frontier.json");
    let findings = frontier_json["findings"]
        .as_array()
        .expect("findings array");
    let local_finding = findings
        .iter()
        .find(|f| f["id"].as_str() == Some(&local_finding_id))
        .expect("local finding present");
    let links = local_finding["links"].as_array().expect("links array");
    assert!(
        links.iter().any(|l| {
            l["target"].as_str() == Some(&format!("{target_vf}@{target_vfr}"))
                && l["type"].as_str() == Some("depends")
        }),
        "cross-frontier link not present after materialize: {links:?}"
    );

    // 6c. A second add-link round-trip should not error out as
    // "no matching dep is declared". Use a fresh source finding
    // to avoid duplicate-link rejection.
    let second_finding_payload = run_json(&[
        "finding",
        "add",
        frontier_str,
        "--assertion",
        "Second dummy anchor.",
        "--type",
        "methodological",
        "--source",
        "test fixture",
        "--source-type",
        "expert_assertion",
        "--author",
        "reviewer:test",
        "--apply",
        "--json",
    ]);
    let second_finding_id = second_finding_payload["finding_id"]
        .as_str()
        .expect("second finding_id present")
        .to_string();
    run_ok(&[
        "finding",
        "link",
        "add",
        frontier_str,
        "--from",
        &second_finding_id,
        "--to",
        &format!("{target_vf}@{target_vfr}"),
        "--type",
        "supports",
        "--note",
        "Second link to the same dep target.",
        "--inferred-by",
        "reviewer",
        "--no-check-target",
    ]);
}
