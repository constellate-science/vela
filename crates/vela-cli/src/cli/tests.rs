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

    /// The v0.700 released command set, minus the bespoke hub transport
    /// retired at v0.721 (ADR 0001 Phase 2: `publish`, `clone`, `workspace`
    /// — git push is publication; the hub re-derives its index from
    /// registered git remotes). A regression guard: later consolidation
    /// batches may NEST these (keeping a hidden top-level alias) but must
    /// never make one unreachable. `is_science_subcommand` counts aliases,
    /// so a nested-with-alias command still passes here.
    const V0700_BASELINE: &[&str] = &[
        "accept",
        "accept-batch",
        "actor",
        "attach",
        "attempt",
        "attest",
        "check",
        "claim",
        "completions",
        "diff",
        "doctor",
        "finding",
        "frontier",
        "gate",
        "history",
        "id",
        "inbox",
        "ingest",
        "init",
        "lean",
        "log",
        "normalize",
        "proof",
        "proposals",
        "propose",
        "queue",
        "registry",
        "reproduce",
        "serve",
        "sign",
        "status",
        "transfer",
        "verify",
    ];

    #[test]
    fn v0700_baseline_commands_stay_reachable() {
        on_big_stack(|| {
            for name in V0700_BASELINE {
                assert!(
                    is_science_subcommand(name),
                    "v0.700 command `{name}` is no longer reachable — a consolidation \
                     dropped it instead of nesting-with-alias"
                );
            }
        });
    }
}
