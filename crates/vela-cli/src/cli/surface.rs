//! The released command surface: the deny/curation lists, the derived
//! `is_science_subcommand` gate, and the curated `vela help advanced`
//! text. Moved verbatim from `cli/mod.rs`.

use super::*;

// The strict v0.700 command surface. Every name here is a live clap
// subcommand in `cli_commands.rs::Commands` (plus the pre-clap
// intercepts: `help`, `version`, `proof verify|explain`,
// `claim state|trust|pack`). This list is the allowlist `run_from_args`
// consults before handing off to clap; it must advertise nothing the
// binary cannot run.
/// Commands intentionally withheld from the released surface. A DENY list,
/// not an ALLOW list: hiding a command here is safe (the worst case is a
/// real command stays unreachable until removed from the list), whereas the
/// old hand-maintained allowlist had the opposite, dangerous failure mode —
/// a NEW command silently 404'd ("unknown or non-release command") until
/// someone remembered to add its string. Empty today.
const RELEASE_DENY: &[&str] = &[];

/// Commands that stay fully callable + dispatchable but are curated OUT of the
/// `vela help advanced` menu (`strict_help_text`) to keep the presented surface
/// minimal and coherent. This is presentation only: every name here still
/// resolves through `is_science_subcommand`, so the gate scripts, the web app,
/// MCP/serve, and any existing invocation keep working unchanged. The
/// completeness guard (`every_subcommand_is_documented_in_advanced_help`) skips
/// these so the curated menu can shrink without losing the "no command is
/// silently undocumented" protection for the canonical set.
pub(crate) const DEPRECATED_FROM_HELP: &[&str] = &["queue", "completions"];

/// Whether `name` is a released top-level command the dispatcher will hand
/// to clap. Derived from the clap command tree (`Cli::command()`), not a
/// hand-maintained list, so a newly-added subcommand — or any of its
/// aliases — is accepted the instant it exists. `surface.rs`'s unit tests
/// pin this to the enum so the derivation can never silently drop a
/// command. (Pre-clap intercepts like `claim state` / `proof verify` are
/// matched in `run_from_args` before this gate, so they need no entry.)
/// The released top-level command names + aliases, derived once from the
/// clap tree and memoized. Building the full command tree is not free, so
/// caching keeps `is_science_subcommand` O(1) per dispatch instead of
/// rebuilding ~226 nodes every call.
fn released_command_names() -> &'static std::collections::HashSet<String> {
    use std::sync::OnceLock;
    static NAMES: OnceLock<std::collections::HashSet<String>> = OnceLock::new();
    NAMES.get_or_init(|| {
        use clap::CommandFactory;
        let mut set = std::collections::HashSet::new();
        for c in Cli::command().get_subcommands() {
            set.insert(c.get_name().to_string());
            for a in c.get_all_aliases() {
                set.insert(a.to_string());
            }
        }
        set
    })
}

pub fn is_science_subcommand(name: &str) -> bool {
    if RELEASE_DENY.contains(&name) {
        return false;
    }
    released_command_names().contains(name)
}

pub(crate) fn print_strict_help() {
    print!("{}", strict_help_text());
}

/// The curated, grouped command reference (`vela help advanced`). Kept
/// hand-curated for legibility — clap's flat alphabetical dump is worse UX —
/// but `mod surface_tests` asserts every released subcommand appears here,
/// so it can never silently omit a newly-added command (the drift the old
/// hand-maintained allowlist suffered, now caught at the help layer too).
pub(crate) fn strict_help_text() -> String {
    let deprecated_line = DEPRECATED_FROM_HELP.join(", ");
    format!(
        r#"Vela {}
Version control for scientific state.
Agents propose. Verifiers reproduce. Humans accept. Git publishes.

Usage:
  vela <COMMAND>

Setup (once):
  id            Your key + identity (create/show/import/keygen/sign); then no
                --key/--as flags. `id sign` re-signs your unsigned events.
  init          Initialize a new frontier repo (git-native: .vela is committed,
                CI gate + agent charter + MCP scaffolded)

The loop:
  status        One-screen frontier state
  inbox         Pending proposals awaiting a human key
  log           Recent signed events; `vela log <dir> <vf_>` = one finding's history
  diff          Two frontiers, or one pending proposal previewed
  record        Record activity into a portable claim packet (vrc_): claim +
                hashed artifacts + caveats; --propose lands it pending review
  propose       Draft the common finding.review proposal
  review        Signed human judgments: statement-fidelity verdicts (--fidelity,
                --batch) and role-scoped reviewer attestations
  accept        Apply proposals under your key; --all-pending/--id for the batch,
                --pack vsd_… for one atomic changeset decision
  pack          Bundle pending proposals into a changeset (vsd_) — the
                pull-request analogue; `vela pack . vsd_…` shows one
  proposals     The full proposal store: list/show/preview/import/validate/export/
                accept/reject
  attach        Bind mechanical verifier evidence (or --proof lean_kernel) to a finding

Verify:
  check         The full trust gate: replay, signatures, parity (--strict)
  reproduce     Re-verify stored witnesses from scratch (frozen verifiers)
  proof         Export a proof packet; `proof verify` re-checks one, `proof explain`
  gate          Claim-level verification gate (grade/check/vocab/backfill/auto-admit)

Publish (git push IS publication):
  hub           The index: register-git (bind repo->vfr once), witness-check,
                verify-chain, verify-log

Nouns (run `vela <noun> --help`):
  finding       The core primitive: add/show/supersede/note/caveat/revise/reject/retract/link
  frontier      Repo-level: new/materialize/add-dep/list-deps/diff/release/audit
  actor         Frontier-registered identities: add/list/rotate
  agents        VELA.md charter adapters: sync/doctor/diff
  serve         MCP + HTTP read surface (profiles: read-only/draft/maintainer)

Projections (read-only):
  state         Claim-state cell, trust vector, packs, evidence diff, anchors
  atlas         Cross-frontier math atlas projections
  policy        Governance policy: show/seal/test/evaluate
  doctor        First-user diagnosis of checkout/frontier/proof/serve
  foundry       The discovery/prover plane: run/targets/ablate, campaign,
                lean, attempt, transfer, experiment

Off-menu (reachable, intentionally undocumented here): {}
"#,
        env!("CARGO_PKG_VERSION"),
        deprecated_line,
    )
}
