//! The one output contract.
//!
//! Every porcelain verb speaks through this module, so the surface can
//! only be coherent: one header shape, one aligned key-value block, one
//! error grammar with an exit-code contract, and one guarantee — under
//! `--json`, EVERY outcome (including every failure) is a single JSON
//! object with `{ok, command, ...}` and the process exit code tells the
//! truth. Dispatch arms call [`set_mode`] once; everything downstream
//! (including deep `fail_*` sites) inherits the right behavior without
//! threading flags.
//!
//! Exit-code contract (research: gh/clig.dev structured-error pattern —
//! an agent that knows WHY a call failed can self-correct):
//!   0 ok · 1 domain failure (gate red, verify fail) · 2 usage ·
//!   3 not found · 4 custody/permission refused · 5 already exists
//!   (idempotent no-op).
//!
//! Advice (the `hint:` line naming the next command) is a first-class
//! part of every error, and togglable: `VELA_ADVICE=0` or `set_quiet`
//! silences hints without touching the message (git's advice.* pattern).

use std::sync::Mutex;

use colored::Colorize;
use serde_json::json;
use vela_protocol::cli_style as style;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// Wrong invocation: missing/invalid arguments.
    Usage,
    /// The named object does not exist here.
    NotFound,
    /// Refused by the custody engine or a permission profile.
    Custody,
    /// Idempotent no-op: the thing already exists.
    Exists,
    /// The domain said no: gate red, verification failed, replay broken.
    Domain,
    /// Our fault: unexpected internal failure.
    #[allow(dead_code)] // part of the published contract; no CLI path is honestly internal yet
    Internal,
}

impl ErrorKind {
    pub fn exit_code(self) -> i32 {
        match self {
            Self::Domain | Self::Internal => 1,
            Self::Usage => 2,
            Self::NotFound => 3,
            Self::Custody => 4,
            Self::Exists => 5,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Usage => "usage",
            Self::NotFound => "not_found",
            Self::Custody => "custody_refused",
            Self::Exists => "already_exists",
            Self::Domain => "domain",
            Self::Internal => "internal",
        }
    }
}

/// The per-invocation output mode, set once by the dispatch arm. A CLI
/// process runs exactly one command, so a process-global is the honest
/// scope (and lets `fail_*` sites deep in call stacks emit correctly
/// without threading `json` through every signature).
struct Mode {
    command: String,
    json: bool,
}

static MODE: Mutex<Option<Mode>> = Mutex::new(None);
/// Quiet is set at parse time, before any command mode exists.
static QUIET: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn set_mode(command: &str, json: bool) {
    *MODE.lock().unwrap() = Some(Mode {
        command: command.to_string(),
        json,
    });
}

pub fn set_quiet(quiet: bool) {
    QUIET.store(quiet, std::sync::atomic::Ordering::Relaxed);
}

fn mode() -> (String, bool) {
    MODE.lock()
        .unwrap()
        .as_ref()
        .map(|m| (m.command.clone(), m.json))
        .unwrap_or_else(|| (String::new(), false))
}

fn advice_enabled() -> bool {
    if QUIET.load(std::sync::atomic::Ordering::Relaxed) {
        return false;
    }
    !std::env::var("VELA_ADVICE").is_ok_and(|v| v == "0")
}

/// Terminate with the one error grammar. Human mode:
/// `err · <message>` + optional `hint: <next command>`; JSON mode: a
/// single `{ok:false, command, error:{kind,message,hint}}` object on
/// stdout. Exit code from the kind, always.
pub fn fail_with(kind: ErrorKind, message: &str, hint: Option<&str>) -> ! {
    let (command, json) = mode();
    if json {
        let payload = json!({
            "ok": false,
            "command": if command.is_empty() { serde_json::Value::Null } else { json!(command) },
            "error": {
                "kind": kind.as_str(),
                "message": message,
                "hint": hint,
            },
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".into())
        );
    } else {
        eprintln!("{} {message}", style::err_prefix());
        if let Some(hint) = hint
            && advice_enabled()
        {
            eprintln!("  hint: {hint}");
        }
    }
    std::process::exit(kind.exit_code());
}

/// The house header: `VELA · CMD · subject  (note)` over a tick row.
/// Status set the style; every verb renders through here so no command
/// can drift into its own dialect again.
pub fn header(command: &str, subject: &str, note: Option<&str>) {
    println!();
    let mut line = format!("VELA · {command}");
    if !subject.is_empty() {
        line.push_str(&format!(" · {subject}"));
    }
    if let Some(note) = note {
        line.push_str(&format!("  ({note})"));
    }
    println!("  {}", line.to_uppercase().dimmed());
    println!("  {}", style::tick_row(60));
}

/// Resolve the frontier argument: an explicit path wins; otherwise walk
/// upward from cwd for a frontier-shaped `.vela` (the git discovery
/// pattern — `vela status` from anywhere inside a frontier just works).
/// The config dir `~/.vela` never matches (it has no event log).
pub fn resolve_frontier(explicit: Option<std::path::PathBuf>) -> std::path::PathBuf {
    if let Some(path) = explicit {
        return path;
    }
    let Ok(mut cur) = std::env::current_dir() else {
        fail_with(
            ErrorKind::Usage,
            "cannot resolve the current directory",
            None,
        );
    };
    let started = cur.clone();
    loop {
        let store = cur.join(".vela");
        if store.is_dir()
            && (store.join("events").is_dir()
                || store.join("proposals").is_dir()
                || store.join("genesis.json").is_file())
        {
            return cur;
        }
        if !cur.pop() {
            fail_with(
                ErrorKind::NotFound,
                &format!(
                    "no frontier found from {} up to the filesystem root",
                    started.display()
                ),
                Some("run `vela init` to create one here, or pass a path: `vela status <dir>`"),
            );
        }
    }
}

/// For verbs shaped `[frontier] [id]`: when the user omits the frontier,
/// clap binds the id into the frontier slot. If the first positional
/// looks like an object id (known prefix) and is not an existing path,
/// shift it into the id slot and discover the frontier upward.
pub fn resolve_frontier_with_id(
    frontier: Option<std::path::PathBuf>,
    id: Option<String>,
    id_prefixes: &[&str],
) -> (std::path::PathBuf, Option<String>) {
    if let Some(first) = &frontier {
        let s = first.display().to_string();
        if id.is_none() && id_prefixes.iter().any(|p| s.starts_with(p)) && !first.exists() {
            return (resolve_frontier(None), Some(s));
        }
    }
    (resolve_frontier(frontier), id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_follow_the_contract() {
        assert_eq!(ErrorKind::Domain.exit_code(), 1);
        assert_eq!(ErrorKind::Usage.exit_code(), 2);
        assert_eq!(ErrorKind::NotFound.exit_code(), 3);
        assert_eq!(ErrorKind::Custody.exit_code(), 4);
        assert_eq!(ErrorKind::Exists.exit_code(), 5);
    }

    #[test]
    fn mode_roundtrip() {
        set_mode("status", true);
        assert!(mode().1);
        set_mode("status", false);
        assert!(!mode().1);
    }
}
