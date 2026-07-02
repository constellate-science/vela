//! Integration tests pinning the consolidated CLI surface. After the
//! dev-only cleanup, each concept has exactly ONE spelling: the
//! acting-identity flag is `--reviewer` (no `--actor`/`--by`), the key flag
//! is `--key` (no `--private-key`), and the finding-mutation verbs live only
//! under `vela finding <verb>` (no top-level `vela note`). These run the
//! built `vela` binary so they catch surface drift the clap-tree unit tests
//! can't.

use std::process::{Command, Output};

fn vela(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_vela"))
        .args(args)
        .output()
        .expect("run vela")
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn combined(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// The acting-identity flag is `--as` and ONLY `--as` — the retired
/// `--reviewer`/`--actor`/`--by` spellings must be rejected (one name).
#[test]
fn identity_flag_is_canonical_as_only() {
    let ok = vela(&[
        "accept",
        "/tmp/vela_nonexistent.json",
        "vpr_x",
        "--as",
        "reviewer:w",
        "--reason",
        "r",
    ]);
    assert!(
        !stderr(&ok).contains("unexpected argument"),
        "`accept --as` should parse, got: {}",
        stderr(&ok)
    );
    for retired in ["--reviewer", "--actor", "--by"] {
        let out = vela(&[
            "accept",
            "/tmp/x.json",
            "vpr_x",
            retired,
            "reviewer:w",
            "--reason",
            "r",
        ]);
        assert!(
            stderr(&out).contains("unexpected argument") || stderr(&out).contains(retired),
            "retired alias `{retired}` should be rejected, got: {}",
            stderr(&out)
        );
    }
}

/// `id sign` takes `--key` and only `--key`; the retired `sign` top-level
/// 404s outright.
#[test]
fn key_flag_is_canonical_key_only() {
    let ok = vela(&[
        "id",
        "sign",
        "/tmp/vela_nonexistent.json",
        "--key",
        "/tmp/nope",
    ]);
    assert!(
        !stderr(&ok).contains("unexpected argument"),
        "`id sign --key` should parse, got: {}",
        stderr(&ok)
    );
    let retired = vela(&["sign", "apply", "/tmp/x.json", "--key", "/tmp/nope"]);
    assert!(
        combined(&retired).contains("unknown or non-release command"),
        "retired `sign` top-level should 404, got: {}",
        combined(&retired)
    );
}

/// Every retired top-level spelling 404s with the release-surface error —
/// no aliases, no shims, the porcelain is the porcelain.
#[test]
fn retired_top_level_verbs_404() {
    for verb in [
        "land",
        "verify",
        "history",
        "accept-batch",
        "normalize",
        "ingest",
        "claim",
        "sign",
        "campaign",
        "lean",
        "attempt",
        "transfer",
        "experiment",
        "registry",
        "attest",
        "receipt",
        "publish",
        "clone",
        "workspace",
    ] {
        let out = vela(&[verb, "--help"]);
        assert!(
            combined(&out).contains("unknown or non-release command"),
            "retired verb `{verb}` should 404, got: {}",
            combined(&out)
        );
    }
}

/// The folded spellings dispatch: hub, foundry planes, id keygen, state.
#[test]
fn folded_spellings_dispatch() {
    for args in [
        vec!["hub", "--help"],
        vec!["foundry", "campaign", "--help"],
        vec!["foundry", "lean", "--help"],
        vec!["foundry", "attempt", "--help"],
        vec!["foundry", "transfer", "--help"],
        vec!["foundry", "experiment", "--help"],
        vec!["id", "keygen", "--help"],
        vec!["accept", "--help"],
    ] {
        let out = vela(&args);
        assert!(
            !combined(&out).contains("unknown or non-release command"),
            "`{}` should dispatch, got: {}",
            args.join(" "),
            combined(&out)
        );
    }
    // the state intercept: reaches the projection parser (usage error is
    // fine; a 404 is not)
    let out = vela(&["state"]);
    assert!(
        !combined(&out).contains("unknown or non-release command"),
        "`state` should reach the intercept, got: {}",
        combined(&out)
    );
}

/// Sanity: a genuinely-unknown flag is rejected (so the checks above mean
/// something — the parser doesn't swallow everything).
#[test]
fn unknown_flag_is_rejected() {
    let out = vela(&[
        "accept",
        "/tmp/x.json",
        "vpr_x",
        "--definitely-not-a-flag",
        "y",
        "--reason",
        "r",
    ]);
    let e = stderr(&out);
    assert!(
        e.contains("unexpected argument") || e.contains("--definitely-not-a-flag"),
        "unknown flag should be rejected, got: {e}"
    );
}

/// The two intentionally-distinct accept/reject paths still dispatch:
/// top-level `accept` (engine-gated) + `proposals accept`/`proposals reject`
/// (lower-level). Neither regresses to "unknown or non-release command".
/// (Top-level `vela reject` was retired — see `finding_verbs_are_nested_only`.)
#[test]
fn accept_paths_dispatch() {
    for args in [
        vec!["accept", "--help"],
        vec!["proposals", "accept", "--help"],
        vec!["proposals", "reject", "--help"],
    ] {
        let out = vela(&args);
        assert!(
            !combined(&out).contains("unknown or non-release command"),
            "`{}` should dispatch, not 404",
            args.join(" ")
        );
    }
}

/// The managed-identity verbs must be reachable through the clap-derived
/// allowlist (the drift that bit `id`). `publish` is retired (ADR 0001
/// Phase 2: git push is publication), so it is no longer asserted here.
#[test]
fn ergonomics_verbs_are_reachable() {
    let out = vela(&["id", "--help"]);
    assert!(
        !combined(&out).contains("unknown or non-release command"),
        "`id` should be reachable"
    );
}

/// The finding-mutation/graph verbs live ONLY under `vela finding <verb>`;
/// the retired top-level spellings (`vela note` …) must now 404.
#[test]
fn finding_verbs_are_nested_only() {
    for verb in ["note", "caveat", "revise", "reject", "retract", "link"] {
        let nested = vela(&["finding", verb, "--help"]);
        assert!(
            !combined(&nested).contains("unknown or non-release command")
                && !combined(&nested).contains("unrecognized subcommand"),
            "`vela finding {verb}` should dispatch"
        );
        let top = vela(&[verb, "--help"]);
        assert!(
            combined(&top).contains("unknown or non-release command"),
            "retired top-level `vela {verb}` should 404, got: {}",
            combined(&top)
        );
    }
    let finding_help = combined(&vela(&["finding", "--help"]));
    assert!(finding_help.contains("note") && finding_help.contains("retract"));
}
