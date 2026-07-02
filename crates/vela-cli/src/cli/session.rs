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
    println!("  USAGE");
    println!("    vela              Open a session against the nearest .vela/ repo");
    println!("    vela <command>    Run a specific subcommand");
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
    println!("    accept            Apply proposals under your key (--all-pending)");
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
    println!("  In session, type a single letter for a quick verb, or any");
    println!("  question in plain text. `q` or `exit` quits.");
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

/// Run a single verb shortcut. Returns true if the verb was recognized.
fn run_session_verb(verb: &str, repo_path: &Path) -> bool {
    match verb {
        "i" | "inbox" => {
            let action = ProposalAction::List {
                frontier: repo_path.to_path_buf(),
                status: Some("pending_review".into()),
                json: false,
            };
            cmd_proposals(action);
            true
        }
        "l" | "log" => {
            cmd_log(repo_path, 10, None, false);
            true
        }
        "s" | "status" | "refresh" => {
            // Reload + re-render dashboard.
            match repo::load_from_path(repo_path) {
                Ok(p) => print_session_dashboard(&p, repo_path),
                Err(e) => eprintln!("{} {e}", style::err_prefix()),
            }
            true
        }
        "h" | "help" | "?" => {
            print_session_help();
            true
        }
        _ => false,
    }
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

    // Piped or scripted invocation: the dashboard IS the answer. A
    // prompt loop over a closed stdin never sees EOF as "stop" from
    // read_line's Ok(0), so it would spin forever printing prompts.
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        return;
    }

    use std::io::{BufRead, Write};
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    loop {
        print!("  > ");
        stdout.flush().ok();
        let mut line = String::new();
        match stdin.lock().read_line(&mut line) {
            Ok(0) | Err(_) => break, // EOF ends the session
            Ok(_) => {}
        }
        let input = line.trim();
        if input.is_empty() {
            continue;
        }
        if matches!(input, "q" | "quit" | "exit") {
            break;
        }
        if run_session_verb(input, &repo_path) {
            continue;
        }
        // Fall through: treat as natural-language question.
        let project = match repo::load_from_path(&repo_path) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{} {e}", style::err_prefix());
                continue;
            }
        };
        answer(&project, input, false);
    }
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
