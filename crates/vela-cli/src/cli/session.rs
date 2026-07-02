//! The no-argument `vela` session dashboard: locate the enclosing `.vela/`
//! repo, print a one-screen frontier summary, and route bare session verbs.

use super::*;

/// Walk up from `cwd` looking for a `.vela/` directory. Returns the
/// first parent that contains one, or `None` if none found.
/// A frontier's `.vela` (it has the event log), NOT the user config
/// dir — `~/.vela` holds keys/identity/hub.env, and a parent walk from
/// anywhere under $HOME would otherwise "find" it and load the config
/// dir as an empty frontier.
fn is_frontier_store(store: &Path) -> bool {
    store.is_dir()
        && (store.join("events").is_dir()
            || store.join("proposals").is_dir()
            || store.join("genesis.json").is_file())
}

fn find_vela_repo() -> Option<PathBuf> {
    let mut cur = std::env::current_dir().ok()?;
    loop {
        if is_frontier_store(&cur.join(".vela")) {
            return Some(cur);
        }
        if !cur.pop() {
            return None;
        }
    }
}

pub(crate) fn print_session_help() {
    println!(
        "  Vela {} · Version control for scientific state.",
        env!("CARGO_PKG_VERSION")
    );
    println!();
    println!("  Agents propose. Verifiers reproduce. Humans accept. Git publishes.");
    println!();
    println!("  HOW IT FITS");
    println!("    A frontier is a git repo whose .vela/ event log is the state.");
    println!("    record   = your ACTIVITY, as a portable claim packet (optional)");
    println!("    propose  = one reviewable CHANGE; pack = several as one changeset");
    println!("    accept   = a human key decides — and the decision publishes itself");
    println!("    check    = is the LOG intact (replay, signatures, parity)");
    println!("    reproduce= is the SCIENCE intact (re-run every frozen verifier)");
    println!();
    println!("  USAGE");
    println!("    vela              Dashboard for the nearest frontier (found upward)");
    println!("    vela <command>    Most commands find the frontier the same way");
    println!("    vela help advanced   Everything reachable, grouped");
    println!();
    println!("  SETUP (once)");
    println!("    id create         Your key + identity; then no --key/--as flags");
    println!("    init <dir>        Start a new frontier repo (git clone joins one)");
    println!();
    println!("  THE LOOP");
    println!("    status            One-screen frontier state");
    println!("    inbox             Pending proposals awaiting a human key");
    println!("    log [vf_]         Recent signed events, or one finding's history");
    println!("    diff <vpr_>       Preview a pending proposal");
    println!("    record <dir>      Record activity: claim + hashed artifacts + caveats");
    println!("    propose           Draft a finding.review proposal");
    println!("    review            Sign fidelity verdicts (--fidelity, --batch)");
    println!("    accept            Decide under your key: <vpr_>, --all-pending,");
    println!("                      or --pack <vsd_> for one atomic changeset verdict");
    println!("    attach            Bind mechanical verifier evidence to a finding");
    println!();
    println!("  VERIFY");
    println!("    check <dir>       The full trust gate, locally (--strict)");
    println!("    reproduce <dir>   Re-verify witnesses with the frozen verifiers");
    println!("    proof <dir>       Export a proof packet (proof verify re-checks one)");
    println!();
    println!("  PUBLISH");
    println!("    git push          IS publication; the hub re-derives its index");
    println!("    hub register-git  Bind this repo to its vfr_ on the hub, once");
    println!();
    println!("  AGENTS");
    println!("    serve             This frontier as an MCP server for AI agents");
    println!("                      (Claude Code, Cursor, any MCP client; also hosted");
    println!("                      at hub.constellate.science/mcp — no clone needed)");
    println!("    policy            The governance policy: what auto-admits, what");
    println!("                      always needs a human key (show/seal/test)");
    println!();
}

pub(crate) fn print_session_dashboard(project: &vela_protocol::project::Project, repo_path: &Path) {
    let label = frontier_label(project);
    let vfr = project.frontier_id();
    let vfr_short = vfr.chars().take(16).collect::<String>();

    let mut pending = 0usize;
    let mut by_kind: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for p in &project.proposals {
        if p.status == "pending_review" {
            pending += 1;
            *by_kind.entry(p.kind.clone()).or_insert(0) += 1;
        }
    }

    println!();
    let version = vela_protocol::project::VELA_COMPILER_VERSION
        .strip_prefix("vela/")
        .unwrap_or(vela_protocol::project::VELA_COMPILER_VERSION);
    println!(
        "  {}",
        format!("VELA · {version} · {label}")
            .to_uppercase()
            .dimmed()
    );
    println!("  {}", style::tick_row(60));
    println!(
        "  vfr_id     {}…   repo  {}",
        vfr_short,
        repo_path.display()
    );
    println!(
        "  findings   {:>4}     events   {}     proposals pending  {}",
        project.findings.len(),
        project.events.len(),
        pending
    );

    if pending > 0 {
        let parts: Vec<String> = by_kind.iter().map(|(k, n)| format!("{n} {k}")).collect();
        println!("  {}     · {}", style::warn("inbox"), parts.join("  "));
    }
    println!();
    println!("  type a verb or ask anything:");
    println!("    i  inbox (pending)    l  log (recent)        s  refresh status");
    println!("    h  help (more verbs)  q  quit");
    println!();
}

pub(crate) fn run_session() {
    let repo_path = match find_vela_repo() {
        Some(p) => p,
        None => {
            println!();
            println!(
                "  {}",
                "VELA · NO FRONTIER FOUND IN CWD OR ANY PARENT".dimmed()
            );
            println!("  {}", style::tick_row(60));
            println!("  Run `vela init` here to create a frontier, or cd into one.");
            println!("  Or run `vela help` for the command list.");
            println!();
            return;
        }
    };

    let project = match repo::load_from_path(&repo_path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{} failed to load .vela/ repo: {e}", style::err_prefix());
            std::process::exit(1);
        }
    };

    print_session_dashboard(&project, &repo_path);

    // The dashboard IS the session: one screen of state plus the ranked
    // next actions, then your shell prompt back. (The old REPL loop is
    // retired — a prompt that shadows the shell helps neither humans
    // nor agents; every quick verb is one `vela <verb>` away.)
    let unpublished = crate::cli_read::unpublished_store_files(&repo_path);
    if unpublished > 0 {
        println!(
            "  {}  {unpublished} store file(s) not committed — signed state only on this machine",
            style::warn("unpublished")
        );
    }
    let targets = vela_edge::frontier_next::frontier_next(&project, Some(&repo_path), 3);
    if !targets.is_empty() {
        println!();
        println!(
            "  {}",
            "next, ranked (vela frontier next for more):".dimmed()
        );
        for t in &targets {
            println!(
                "    {}  {}",
                t.id,
                t.title.chars().take(56).collect::<String>()
            );
            println!("      {}", t.next_command.dimmed());
        }
    }
    println!();
}

#[cfg(test)]
mod frontier_store_tests {
    use super::is_frontier_store;

    #[test]
    fn config_shaped_vela_dir_is_not_a_frontier() {
        let tmp = std::env::temp_dir().join(format!("vela-store-test-{}", std::process::id()));
        // The user config shape: keys + identity, no event log.
        let config = tmp.join("config/.vela");
        std::fs::create_dir_all(config.join("keys")).unwrap();
        std::fs::write(config.join("identity.json"), "{}").unwrap();
        assert!(!is_frontier_store(&config));

        // The frontier shape: an events directory.
        let frontier = tmp.join("frontier/.vela");
        std::fs::create_dir_all(frontier.join("events")).unwrap();
        assert!(is_frontier_store(&frontier));

        std::fs::remove_dir_all(&tmp).ok();
    }
}
