//! Frontier lifecycle: `vela init` (with versioned git hooks) and the
//! `vela serve --setup` MCP scaffold. Moved verbatim from `cli/mod.rs`.

use super::*;

pub(crate) fn cmd_init(
    path: &Path,
    name: &str,
    template: &str,
    initialize_git: bool,
    json_output: bool,
) {
    if path.join(".vela").exists() {
        crate::ui::fail_with(
            crate::ui::ErrorKind::Exists,
            &format!(
                "already initialized: {} exists",
                path.join(".vela").display()
            ),
            Some("run `vela status` to see the frontier that already lives here"),
        );
    }
    let payload = frontier_repo::initialize(
        path,
        frontier_repo::InitOptions {
            name,
            template,
            initialize_git,
        },
    )
    .unwrap_or_else(|e| fail_return(&e));
    let hooks = scaffold_git_hooks(path);
    if json_output {
        print_json(&payload);
    } else {
        println!(
            "{} initialized frontier repository in {}",
            style::ok("ok"),
            path.display()
        );
        if hooks {
            println!("  git hooks installed (.vela/hooks): pre-push runs the strict check");
        }
    }
}

/// Versioned git hooks: local CI before the Action sees the push, and
/// derived views that can never lag the committed store. Written under
/// `.vela/hooks` (committed with the repo) and activated via
/// `core.hooksPath`; a clone re-activates with one config line, which
/// `vela doctor` suggests.
fn scaffold_git_hooks(path: &Path) -> bool {
    if !path.join(".git").exists() {
        return false;
    }
    let hooks_dir = path.join(".vela/hooks");
    if std::fs::create_dir_all(&hooks_dir).is_err() {
        return false;
    }
    let pre_commit = r#"#!/bin/sh
# vela pre-commit: the committed store must never lead its derived views
# (CI holds them to hash parity). If events are staged, re-materialize
# and stage the views alongside them.
if git diff --cached --name-only | grep -q "\.vela/events/"; then
  if command -v vela >/dev/null 2>&1; then
    root="$(git rev-parse --show-toplevel)"
    vela frontier materialize "$root" >/dev/null 2>&1 &&       git add "$root/frontier.json" "$root/vela.lock" "$root/proof" 2>/dev/null
  fi
fi
exit 0
"#;
    let pre_push = r#"#!/bin/sh
# vela pre-push: hold the push to the same strict bar CI will.
command -v vela >/dev/null 2>&1 || exit 0
root="$(git rev-parse --show-toplevel)"
if ! vela check "$root" --strict >/dev/null 2>&1; then
  echo "vela pre-push: strict check failed — push aborted."
  echo "  inspect: vela check $root --strict"
  echo "  bypass (CI will still refuse): git push --no-verify"
  exit 1
fi
exit 0
"#;
    let ok = std::fs::write(hooks_dir.join("pre-commit"), pre_commit).is_ok()
        && std::fs::write(hooks_dir.join("pre-push"), pre_push).is_ok();
    if !ok {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for name in ["pre-commit", "pre-push"] {
            let _ = std::fs::set_permissions(
                hooks_dir.join(name),
                std::fs::Permissions::from_mode(0o755),
            );
        }
    }
    std::process::Command::new("git")
        .arg("-C")
        .arg(path)
        .args(["config", "core.hooksPath", ".vela/hooks"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

pub(crate) fn cmd_mcp_setup(source: Option<&Path>, frontiers: Option<&Path>) {
    let source_desc = source
        .map(|p| p.display().to_string())
        .or_else(|| frontiers.map(|p| p.display().to_string()))
        .unwrap_or_else(|| "frontier.json".to_string());
    // Emit the read-only profile by default (memo §9.1): the safe MCP surface
    // an agent should get unless a human starts a scoped draft/maintainer
    // session. Matches the `.mcp.json` that `vela agents sync` generates.
    let args = if let Some(path) = source {
        format!(r#""serve", "{}", "--profile", "read-only""#, path.display())
    } else if let Some(path) = frontiers {
        format!(
            r#""serve", "--frontiers", "{}", "--profile", "read-only""#,
            path.display()
        )
    } else {
        r#""serve", "frontier.json", "--profile", "read-only""#.to_string()
    };
    println!(
        r#"Add this MCP server configuration to your client:

{{
  "mcpServers": {{
    "vela": {{
      "command": "vela",
      "args": [{args}]
    }}
  }}
}}

Source: {source_desc}"#
    );
}
