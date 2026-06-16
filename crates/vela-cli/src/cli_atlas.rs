//! `vela atlas <frontier>...` — the cross-frontier Math Atlas projection
//! (spec `docs/research/MATH_ATLAS.md`, build step 3). A pure, read-only
//! projection: it loads the given frontiers and unions their claims into
//! AtlasCells by `HardIdentity` anchors (context-indexed). JSON only; the
//! atlas is a machine object.

use std::path::Path;

use vela_protocol::{atlas, repo};

use crate::cli::{fail, print_json};

/// Entry from the `cli.rs::run_from_args` intercept. `args[2..]` are the
/// frontier paths (non-flag tokens).
pub(crate) fn run(args: &[String]) {
    let frontiers: Vec<&str> = args
        .iter()
        .skip(2)
        .filter(|a| !a.starts_with('-'))
        .map(String::as_str)
        .collect();
    if frontiers.is_empty() {
        fail("usage: vela atlas <frontier> [<frontier> ...]");
    }
    let projects: Vec<_> = frontiers
        .iter()
        .map(|f| {
            repo::load_from_path(Path::new(f)).unwrap_or_else(|e| fail(&format!("load {f}: {e}")))
        })
        .collect();
    let refs: Vec<&_> = projects.iter().collect();
    let out = atlas::project(&refs);
    print_json(&serde_json::to_value(&out).unwrap_or_else(|e| fail(&format!("serialize: {e}"))));
}
