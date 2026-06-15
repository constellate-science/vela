//! Integration tests pinning the consolidated CLI surface: flag aliases
//! (B3) and the dual top-level/subcommand paths (B1/B4). These run the
//! actual built `vela` binary, so they catch alias-path divergence and
//! surface drift that unit tests over the clap tree cannot.

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

/// The acting-identity flag accepts all three spellings (canonical
/// `--reviewer`, hidden aliases `--actor` / `--by`), so no existing script
/// breaks. We assert the flag PARSES (reaches the handler, which then fails
/// on the bogus frontier) rather than being rejected as an unknown arg.
#[test]
fn identity_flag_aliases_parse() {
    for flag in ["--reviewer", "--actor", "--by"] {
        let out = vela(&[
            "accept",
            "/tmp/vela_nonexistent.json",
            "vpr_x",
            flag,
            "reviewer:w",
            "--reason",
            "r",
        ]);
        assert!(
            !stderr(&out).contains("unexpected argument"),
            "`accept {flag}` should parse, got: {}",
            stderr(&out)
        );
    }
}

/// `sign apply` takes the canonical `--key` and the back-compat alias
/// `--private-key`.
#[test]
fn key_flag_alias_parses() {
    for flag in ["--key", "--private-key"] {
        let out = vela(&[
            "sign",
            "apply",
            "/tmp/vela_nonexistent.json",
            flag,
            "/tmp/nope",
        ]);
        assert!(
            !stderr(&out).contains("unexpected argument"),
            "`sign apply {flag}` should parse, got: {}",
            stderr(&out)
        );
    }
}

/// Sanity: a genuinely-unknown flag IS still rejected, so the alias
/// acceptance above is meaningful (not a parser that swallows everything).
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

/// Both the top-level alias and the namespaced subcommand dispatch (they
/// are intentionally-distinct paths: top-level `accept` runs the engine
/// gate; `proposals accept` is the lower-level apply). Neither must regress
/// to "unknown or non-release command".
#[test]
fn dual_accept_paths_both_dispatch() {
    for args in [
        vec!["accept", "--help"],
        vec!["proposals", "accept", "--help"],
        vec!["reject", "--help"],
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

/// The managed-identity verbs added this cycle must be reachable through
/// the clap-derived allowlist (the drift that bit `id`/`publish`).
#[test]
fn ergonomics_verbs_are_reachable() {
    for verb in ["id", "publish"] {
        let out = vela(&[verb, "--help"]);
        assert!(
            !combined(&out).contains("unknown or non-release command"),
            "`{verb}` should be reachable"
        );
    }
}
