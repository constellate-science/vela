//! The no-argument `vela` session dashboard: locate the enclosing `.vela/`
//! repo, print a one-screen frontier summary, and route bare session verbs.

use super::*;

/// Walk up from `cwd` looking for a `.vela/` directory. Returns the
/// first parent that contains one, or `None` if none found.
fn find_vela_repo() -> Option<PathBuf> {
    let mut cur = std::env::current_dir().ok()?;
    loop {
        if cur.join(".vela").is_dir() {
            return Some(cur);
        }
        if !cur.pop() {
            return None;
        }
    }
}

pub(crate) fn print_session_help() {
    println!();
    println!(
        "  Vela {} · Version control for scientific state.",
        env!("CARGO_PKG_VERSION")
    );
    println!();
    println!("  USAGE");
    println!("    vela              Open a session against the nearest .vela/ repo");
    println!("    vela <command>    Run a specific subcommand");
    println!("    vela help advanced   Full subcommand list (30+ commands)");
    println!();
    println!("  SETUP (once)");
    println!(
        "    id create         Generate your key + identity; then no --key/--actor/--hub flags"
    );
    println!("    init <dir>        Start a new frontier repo (vs clone, which joins one)");
    println!();
    println!("  PRODUCER LOOP (the git-style path: clone, reproduce, propose, push)");
    println!("    clone <vfr|url>   Clone a published frontier from the hub into a working tree");
    println!(
        "    reproduce <dir>   Re-verify the cloned witnesses from scratch (frozen verifiers)"
    );
    println!("    ingest <path>     Ingest a paper, dataset, or Carina packet");
    println!("    propose           Create a finding.review proposal");
    println!(
        "    publish <dir>     Push your frontier to the hub (alias: push); owner/key/hub from id"
    );
    println!();
    println!("  SYNC");
    println!("    status            One-screen frontier state");
    println!("    log               Recent canonical state events");
    println!();
    println!("  REVIEW (maintainers)");
    println!("    inbox             Pending review proposals");
    println!("    propose <vf>      Create/apply a finding.review proposal (the review verb)");
    println!("    diff <vpr_id>     Preview a pending proposal vs current frontier");
    println!("    accept <vpr_id>   Apply a proposal under your reviewer key");
    println!(
        "    accept-batch      Accept all pending in one signed, reconciled pass (--all-pending)"
    );
    println!("    attest            Sign findings under your private key");
    println!();
    println!("  VERIFY");
    println!("    gate check <vf>                    Trust-gate status for one finding");
    println!("    reproduce <dir>                    Re-verify stored witnesses from scratch");
    println!(
        "    registry verify-log <vfr>          Independently verify a hub's transparency log"
    );
    println!("    claim state <vf>                   Claim-State Cell (Belnap status, deps)");
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

    use std::io::{BufRead, Write};
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    loop {
        print!("  > ");
        stdout.flush().ok();
        let mut line = String::new();
        if stdin.lock().read_line(&mut line).is_err() {
            break;
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
