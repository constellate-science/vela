#[cfg(test)]
mod surface_tests {
    //! Pins the released command surface to the clap enum, so the
    //! drift that silently broke `id` and `publish` this cycle (a real
    //! command rejected as "unknown or non-release") can never recur, and
    //! so the curated `help advanced` reference can never omit a command.
    use crate::cli::*;
    use clap::CommandFactory;

    /// Building the ~226-node clap tree needs more than a default test
    /// thread's 2 MiB stack (it is fine on the 8 MiB main thread, where the
    /// CLI actually runs), so each test runs its body on a roomy stack.
    fn on_big_stack(f: impl FnOnce() + Send + 'static) {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(f)
            .unwrap()
            .join()
            .unwrap();
    }

    fn released_names() -> Vec<String> {
        Cli::command()
            .get_subcommands()
            .map(|c| c.get_name().to_string())
            .collect()
    }

    #[test]
    fn every_clap_subcommand_is_released() {
        on_big_stack(|| {
            for name in released_names() {
                assert!(
                    is_science_subcommand(&name),
                    "clap exposes subcommand `{name}` but is_science_subcommand rejects it \
                     (a RELEASE_DENY entry, or a derivation bug) — it would 404 at dispatch"
                );
            }
        });
    }

    #[test]
    fn every_subcommand_is_documented_in_advanced_help() {
        on_big_stack(|| {
            let help = strict_help_text();
            for name in released_names() {
                // Commands curated out of the menu (DEPRECATED_FROM_HELP) stay
                // callable but are intentionally not listed; the guard applies
                // only to the canonical surface.
                if DEPRECATED_FROM_HELP.contains(&name.as_str()) {
                    continue;
                }
                let listed = help.lines().any(|l| {
                    let t = l.trim_start();
                    t == name || t.starts_with(&format!("{name} "))
                });
                assert!(
                    listed,
                    "subcommand `{name}` is not listed in `vela help advanced` \
                     (strict_help_text) — add a row so the reference stays complete, \
                     or add it to DEPRECATED_FROM_HELP if it is intentionally off-menu"
                );
            }
        });
    }

    /// The v0.723 porcelain: the EXACT visible surface, guarded in both
    /// directions. A dropped command fails ("a collapse removed it"); a new
    /// command fails too ("extend this list deliberately"). Growth is a
    /// decision, not a drift.
    const V0723_VISIBLE: &[&str] = &[
        "accept",
        "actor",
        "agents",
        "attach",
        "check",
        "diff",
        "doctor",
        "finding",
        "foundry",
        "frontier",
        "gate",
        "hub",
        "id",
        "inbox",
        "init",
        "log",
        "proof",
        "proposals",
        "propose",
        "record",
        "reproduce",
        "review",
        "serve",
        "status",
    ];
    const V0723_HIDDEN: &[&str] = &["completions", "queue"];

    #[test]
    fn v0723_surface_is_exact_both_directions() {
        on_big_stack(|| {
            let cmd = Cli::command();
            let mut visible: Vec<String> = Vec::new();
            let mut hidden: Vec<String> = Vec::new();
            for c in cmd.get_subcommands() {
                if c.is_hide_set() {
                    hidden.push(c.get_name().to_string());
                } else {
                    visible.push(c.get_name().to_string());
                }
            }
            visible.sort();
            hidden.sort();
            let want_visible: Vec<String> = V0723_VISIBLE.iter().map(|s| s.to_string()).collect();
            let want_hidden: Vec<String> = V0723_HIDDEN.iter().map(|s| s.to_string()).collect();
            assert_eq!(
                visible, want_visible,
                "the VISIBLE surface drifted — a removal broke the porcelain, or an \
                 addition must be a deliberate baseline change"
            );
            assert_eq!(
                hidden, want_hidden,
                "the HIDDEN surface drifted — hiding/unhiding is a deliberate act"
            );
        });
    }

    #[test]
    fn retired_verbs_are_not_reachable() {
        on_big_stack(|| {
            for name in [
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
                "publish",
                "clone",
                "workspace",
                "attest",
                "receipt",
            ] {
                assert!(
                    !is_science_subcommand(name),
                    "retired verb `{name}` is still reachable — the cut regressed"
                );
            }
        });
    }
}
