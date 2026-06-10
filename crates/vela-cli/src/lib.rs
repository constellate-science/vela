//! `vela` — the command-line binary.
//!
//! Wires the agent handlers from `vela-scientist` into the
//! substrate's CLI dispatch table, then hands off to
//! `crate::cli::run_from_args`.
//!
//! Doctrine: the substrate library doesn't know about agents. This
//! binary does the marriage.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;

use colored::Colorize;

// The CLI / serve / workbench surface, relocated out of the
// `vela-protocol` library so the substrate crate stays a pure protocol
// library. These were `vela_protocol::{cli, serve, workbench, cli_*}`
// before; they now live here and reach into the substrate via
// `vela_protocol::*`.
pub mod cli;
mod cli_bridge_kit;
mod cli_causal;
mod cli_check;
mod cli_commands;
mod cli_diff_pack;
mod cli_federation;
mod cli_finding;
mod cli_frontier;
mod cli_lean;
mod cli_owner_rotate;
mod cli_registry;
mod cli_source_fetch;
mod serve;
mod review_work;

pub fn run() {
    // Atlas R.2 intercept: read-only verifier subcommands for the
    // primitives added in R.1 (v0.338). Live ahead of run_from_args()
    // because the dispatcher in vela-protocol/cli.rs predates these
    // primitives. When the next vela-protocol release lands them in the
    // dispatcher proper, this intercept can be removed.
    if try_handle_atlas_r2_verify_intercept() {
        return;
    }

    // Agent handlers (Scout, Notes Compiler, Code Analyst, Datasets,
    // Reviewer, Contradiction Finder, Experiment Planner). These wire
    // the v0.22+ agent inbox into the substrate CLI dispatch.
    crate::cli::register_scout_handler(scout_handler);
    crate::cli::register_notes_handler(notes_handler);
    crate::cli::register_code_handler(code_handler);
    crate::cli::register_datasets_handler(datasets_handler);
    crate::cli::register_reviewer_handler(reviewer_handler);
    crate::cli::register_tensions_handler(tensions_handler);
    crate::cli::register_experiments_handler(experiments_handler);
    // v0.78: Atlas-level handlers (init / materialize / serve).
    // Route through the `vela-atlas` crate.
    crate::cli::register_atlas_init_handler(atlas_init_handler);
    crate::cli::register_atlas_materialize_handler(atlas_materialize_handler);
    crate::cli::register_atlas_serve_handler(atlas_serve_handler);
    // v0.81.2: Atlas update (add/remove composing frontiers).
    crate::cli::register_atlas_update_handler(atlas_update_handler);
    // v0.82.4: Constellation-level handlers (init / materialize / serve).
    crate::cli::register_constellation_init_handler(constellation_init_handler);
    crate::cli::register_constellation_materialize_handler(
        constellation_materialize_handler,
    );
    crate::cli::register_constellation_serve_handler(constellation_serve_handler);
    // v0.149: search handlers wire the vela-search crate into the
    // CLI dispatch table.
    crate::cli::register_search_build_handler(search_build_handler);
    crate::cli::register_search_query_handler(search_query_handler);
    crate::cli::run_from_args();
}

/// v0.149: `vela search build <frontiers...> --out <path>`.
fn search_build_handler(
    frontiers: Vec<PathBuf>,
    out: PathBuf,
    include_bootstrap: bool,
    include_broken: bool,
    json: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(async move {
        let cfg = vela_search::IndexerConfig {
            include_bootstrap,
            include_broken,
        };
        let now = chrono::Utc::now().to_rfc3339();
        let index = match vela_search::build_index(&frontiers, &cfg, &now) {
            Ok(i) => i,
            Err(e) => {
                eprintln!("err · build index: {e}");
                std::process::exit(1);
            }
        };
        let body = match serde_json::to_string_pretty(&index) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("err · serialize index: {e}");
                std::process::exit(1);
            }
        };
        if let Err(e) = std::fs::write(&out, format!("{body}\n")) {
            eprintln!("err · write {}: {e}", out.display());
            std::process::exit(1);
        }
        if json {
            let payload = serde_json::json!({
                "ok": true,
                "command": "search.build",
                "index_id": index.index_id,
                "frontier_count": index.frontier_count,
                "entry_count": index.entry_count,
                "out": out.display().to_string(),
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&payload).expect("serialize summary")
            );
        } else {
            println!(
                "  {} indexed {} frontier(s), {} entries -> {}",
                "search".green().bold(),
                index.frontier_count,
                index.entry_count,
                out.display()
            );
            println!("  index_id: {}", index.index_id);
        }
    })
}

/// v0.149: `vela search query "..." [filters]`.
#[allow(clippy::too_many_arguments)]
fn search_query_handler(
    query: String,
    index: Option<PathBuf>,
    kind: Option<String>,
    entity: Option<String>,
    status: Option<String>,
    frontier_id: Option<String>,
    source_id: Option<String>,
    chain_status: Option<String>,
    limit: Option<usize>,
    json: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(async move {
        let index_path = match index {
            Some(p) => p,
            None => {
                let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
                PathBuf::from(home).join(".vela").join("search-index.json")
            }
        };
        let raw = match std::fs::read_to_string(&index_path) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("err · read index {}: {e}", index_path.display());
                std::process::exit(1);
            }
        };
        let idx: vela_search::Index = match serde_json::from_str(&raw) {
            Ok(i) => i,
            Err(e) => {
                eprintln!("err · parse index: {e}");
                std::process::exit(1);
            }
        };
        let filters = vela_search::SearchFilters {
            kind,
            entity,
            status,
            frontier_id,
            source_id,
            chain_status,
            limit,
        };
        let hits = vela_search::search(&idx, &query, &filters);
        if json {
            let body: Vec<_> = hits
                .iter()
                .map(|h| {
                    serde_json::json!({
                        "score": h.score,
                        "kind": h.entry.kind,
                        "frontier_id": h.entry.frontier_id,
                        "frontier_name": h.entry.frontier_name,
                        "target_id": h.entry.target_id,
                        "status": h.entry.status,
                        "entities": h.entry.entities,
                        "source_id": h.entry.source_id,
                        "chain_status": h.entry.chain_status,
                    })
                })
                .collect();
            let payload = serde_json::json!({
                "ok": true,
                "command": "search.query",
                "query": query,
                "result_count": hits.len(),
                "results": body,
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&payload).expect("serialize")
            );
        } else {
            println!(
                "  {} {} result(s) for {:?}",
                "search".green().bold(),
                hits.len(),
                query
            );
            for h in &hits {
                println!(
                    "  [{:>5.1}] {}  {}  {}  ({})",
                    h.score,
                    h.entry.kind,
                    h.entry.frontier_name,
                    h.entry.target_id,
                    h.entry.chain_status
                );
            }
        }
    })
}

/// v0.78: `vela atlas init <name> --frontiers <a>,<b> [--domain] [--scope-note]`.
fn atlas_init_handler(
    atlases_root: PathBuf,
    name: String,
    domain: String,
    scope_note: Option<String>,
    frontiers: Vec<PathBuf>,
    json: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(async move {
        match vela_atlas::init_atlas(
            &atlases_root,
            &name,
            &domain,
            scope_note.as_deref(),
            &frontiers,
        ) {
            Ok((manifest_path, manifest)) => {
                if json {
                    let payload = serde_json::json!({
                        "ok": true,
                        "command": "atlas.init",
                        "atlas_id": manifest.id,
                        "manifest_path": manifest_path.display().to_string(),
                        "frontier_count": manifest.composing_frontiers.len(),
                    });
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&payload).expect("serialize atlas init")
                    );
                } else {
                    println!();
                    println!("  {}  {}", "ok".green(), manifest.id);
                    println!("  manifest:           {}", manifest_path.display());
                    println!(
                        "  composing frontiers: {}",
                        manifest.composing_frontiers.len()
                    );
                    for fr in &manifest.composing_frontiers {
                        println!("    · {} ({})", fr.name, fr.vfr_id);
                    }
                }
            }
            Err(e) => {
                eprintln!("{} atlas init: {e}", "err ·".red());
                std::process::exit(1);
            }
        }
    })
}

/// v0.78: `vela atlas materialize <name>`. Reads composing
/// frontiers, unions accepted-core findings, computes
/// composition hash, writes `snapshot.json`.
fn atlas_materialize_handler(
    atlases_root: PathBuf,
    name: String,
    json: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(async move {
        let atlas_dir = atlases_root.join(&name);
        match vela_atlas::materialize_atlas(&atlas_dir) {
            Ok((snapshot_path, snapshot)) => {
                if json {
                    let payload = serde_json::json!({
                        "ok": true,
                        "command": "atlas.materialize",
                        "atlas_id": snapshot.atlas_id,
                        "snapshot_path": snapshot_path.display().to_string(),
                        "frontier_count": snapshot.frontier_count,
                        "total_findings": snapshot.total_findings,
                        "accepted_core_findings": snapshot.accepted_core_findings,
                        "total_events": snapshot.total_events,
                        "composition_hash": snapshot.composition_hash,
                    });
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&payload)
                            .expect("serialize atlas materialize")
                    );
                } else {
                    println!();
                    println!("  {}  {}", "atlas".green(), snapshot.atlas_name);
                    println!("  vat_id:             {}", snapshot.atlas_id);
                    println!("  domain:             {}", snapshot.domain);
                    println!("  frontiers:          {}", snapshot.frontier_count);
                    println!("  total findings:     {}", snapshot.total_findings);
                    println!("  accepted-core:      {}", snapshot.accepted_core_findings);
                    println!("  total events:       {}", snapshot.total_events);
                    println!("  composition hash:   {}", snapshot.composition_hash);
                    println!("  snapshot:           {}", snapshot_path.display());
                    for fr in &snapshot.frontiers {
                        println!(
                            "    · {} ({}): {} findings, {} events",
                            fr.name, fr.vfr_id, fr.findings, fr.events
                        );
                    }
                }
            }
            Err(e) => {
                eprintln!("{} atlas materialize: {e}", "err ·".red());
                std::process::exit(1);
            }
        }
    })
}

/// v0.78 stub: route to the per-frontier Workbench for the first
/// composing frontier in the manifest. Atlas-level Workbench page
/// lands in v0.79+.
/// v0.81.2: `vela atlas update <name> --add-frontier <p>
/// --remove-vfr-id <vfr_*>`. Re-computes the Atlas's
/// content-addressed id and writes the updated manifest.
fn atlas_update_handler(
    atlases_root: PathBuf,
    name: String,
    add_frontier: Vec<PathBuf>,
    remove_vfr_id: Vec<String>,
    json: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(async move {
        let atlas_dir = atlases_root.join(&name);
        match vela_atlas::update_atlas(&atlas_dir, &add_frontier, &remove_vfr_id) {
            Ok((manifest_path, manifest)) => {
                if json {
                    let payload = serde_json::json!({
                        "ok": true,
                        "command": "atlas.update",
                        "atlas_id": manifest.id,
                        "manifest_path": manifest_path.display().to_string(),
                        "frontier_count": manifest.composing_frontiers.len(),
                        "added": add_frontier.len(),
                        "removed": remove_vfr_id.len(),
                    });
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&payload).expect("serialize atlas update")
                    );
                } else {
                    println!();
                    println!("  {}  {}", "ok".green(), manifest.id);
                    println!("  manifest:           {}", manifest_path.display());
                    println!(
                        "  composing frontiers: {}",
                        manifest.composing_frontiers.len()
                    );
                    println!("  added:              {}", add_frontier.len());
                    println!("  removed:            {}", remove_vfr_id.len());
                    for fr in &manifest.composing_frontiers {
                        println!("    · {} ({})", fr.name, fr.vfr_id);
                    }
                }
            }
            Err(e) => {
                eprintln!("{} atlas update: {e}", "err ·".red());
                std::process::exit(1);
            }
        }
    })
}

/// v0.80.2: Atlas-level Workbench server. Materializes the
/// Atlas (refreshing index.html, snapshot.json, and any
/// auto-synced manifest bridges), then serves the atlas dir
/// over HTTP on the requested port. Static-file only at
/// v0.80; the dynamic cross-frontier review surface is a
/// future cycle.
fn atlas_serve_handler(
    atlases_root: PathBuf,
    name: String,
    port: u16,
    open_browser: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(async move {
        let atlas_dir = atlases_root.join(&name);

        // 1. Materialize first to refresh snapshot.json + index.html
        // and auto-sync confirmed bridges.
        match vela_atlas::materialize_atlas(&atlas_dir) {
            Ok((_path, snapshot)) => {
                println!();
                println!("  {}  {}", "atlas".green(), snapshot.atlas_name);
                println!("  vat_id:             {}", snapshot.atlas_id);
                println!("  composing frontiers: {}", snapshot.frontier_count);
                println!("  total findings:     {}", snapshot.total_findings);
                println!("  bridges (manifest): {}", snapshot.bridge_count);
                println!();
            }
            Err(e) => {
                eprintln!("{} atlas materialize: {e}", "err ·".red());
                std::process::exit(1);
            }
        }

        // 2. Serve the atlas dir over HTTP. Index served from
        // index.html. snapshot.json + manifest.yaml accessible
        // by path. No interactive review surface; this is the
        // static-file serve from v0.80.
        use axum::{
            Router,
            http::StatusCode,
            response::{Html, IntoResponse},
            routing::get,
        };
        use tower_http::services::ServeDir;
        let serve_dir = ServeDir::new(&atlas_dir);
        let atlas_page_dir = atlas_dir.clone();
        let app: Router = Router::new()
            .route(
                "/atlas",
                get({
                    let atlas_page_dir = atlas_page_dir.clone();
                    move || {
                        let index_path = atlas_page_dir.join("index.html");
                        async move {
                            match tokio::fs::read_to_string(&index_path).await {
                                Ok(body) => Html(body).into_response(),
                                Err(e) => (
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    format!("could not read atlas index: {e}"),
                                )
                                    .into_response(),
                            }
                        }
                    }
                }),
            )
            .route(
                "/atlas/",
                get({
                    let atlas_page_dir = atlas_dir.clone();
                    move || {
                        let index_path = atlas_page_dir.join("index.html");
                        async move {
                            match tokio::fs::read_to_string(&index_path).await {
                                Ok(body) => Html(body).into_response(),
                                Err(e) => (
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    format!("could not read atlas index: {e}"),
                                )
                                    .into_response(),
                            }
                        }
                    }
                }),
            )
            .fallback_service(serve_dir);

        let addr = format!("127.0.0.1:{port}");
        let listener = match tokio::net::TcpListener::bind(&addr).await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("{} bind {addr}: {e}", "err ·".red());
                std::process::exit(1);
            }
        };
        let url = format!("http://{addr}/");
        println!("  {} {}", "serving atlas at".green(), url);
        println!();
        if open_browser && let Err(e) = std::process::Command::new("open").arg(&url).spawn() {
            eprintln!("  (note: could not auto-open browser: {e})");
        }
        if let Err(e) = axum::serve(listener, app).await {
            eprintln!("{} axum::serve: {e}", "err ·".red());
            std::process::exit(1);
        }
    })
}

/// Adapter from the substrate's `ScoutHandler` signature to
/// `vela_scientist::scout::run`. Owns the user-facing rendering of
/// the report so the agent crate can stay UI-free.
fn scout_handler(
    folder: PathBuf,
    frontier: PathBuf,
    backend: Option<String>,
    dry_run: bool,
    json_out: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(async move {
        use vela_scientist::scout::{ScoutInput, run};
        // The substrate's CLI plumbs through a generic `backend`
        // string from the `vela scout --backend` flag. v0.22's only
        // backend is `claude-cli`, so we treat the legacy flag as a
        // model-alias override (e.g. `--backend sonnet`) and ignore
        // empty / "claude-cli" / "default" values.
        let model = backend.and_then(|b| {
            let trimmed = b.trim().to_string();
            if trimmed.is_empty() || trimmed == "claude-cli" || trimmed == "default" {
                None
            } else {
                Some(trimmed)
            }
        });
        let input = ScoutInput {
            folder: folder.clone(),
            frontier_path: frontier.clone(),
            model,
            cli_command: std::env::var("VELA_SCIENTIST_CLI")
                .unwrap_or_else(|_| "claude".to_string()),
            apply: !dry_run,
        };
        match run(input).await {
            Ok(report) => {
                if json_out {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&report).unwrap_or_default()
                    );
                    return;
                }
                println!();
                println!("  {}", "VELA · SCOUT · LITERATURE".dimmed());
                println!("  {}", tick_row(60));
                println!("  agent:           {}", report.run.agent);
                println!("  run id:          {}", report.run.run_id);
                println!(
                    "  model:           {}",
                    if report.run.model.is_empty() {
                        "(env default)"
                    } else {
                        &report.run.model
                    }
                );
                println!("  folder:          {}", folder.display());
                println!("  frontier:        {}", frontier.display());
                println!("  pdfs seen:       {}", report.pdfs_seen);
                println!("  pdfs processed:  {}", report.pdfs_processed);
                println!("  candidates:      {}", report.candidates_emitted);
                println!(
                    "  proposals:       {} {}",
                    report.proposals_written,
                    if dry_run {
                        "(dry-run, not written)"
                    } else {
                        "(appended to frontier)"
                    }
                );
                if !report.skipped.is_empty() {
                    println!("  skipped:         {} files", report.skipped.len());
                    for s in report.skipped.iter().take(5) {
                        println!("    - {}: {}", s.path, s.reason);
                    }
                    if report.skipped.len() > 5 {
                        println!("    … {} more", report.skipped.len() - 5);
                    }
                }
                println!();
                if !dry_run && report.proposals_written > 0 {
                    println!(
                        "  next: review in the Workbench Inbox, then `vela queue sign --all`."
                    );
                }
            }
            Err(e) => {
                eprintln!("  scout failed: {e}");
                std::process::exit(1);
            }
        }
    })
}

/// Adapter for `vela compile-notes` (v0.23). Same shape as
/// scout_handler — render the report to terminal in a friendly form,
/// or as JSON when requested.
fn notes_handler(
    vault: PathBuf,
    frontier: PathBuf,
    backend: Option<String>,
    max_files: Option<usize>,
    max_items_per_category: Option<usize>,
    dry_run: bool,
    json_out: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(async move {
        use vela_scientist::notes::{NotesInput, run};
        let model = backend.and_then(|b| {
            let trimmed = b.trim().to_string();
            if trimmed.is_empty() || trimmed == "claude-cli" || trimmed == "default" {
                None
            } else {
                Some(trimmed)
            }
        });
        let input = NotesInput {
            vault: vault.clone(),
            frontier_path: frontier.clone(),
            model,
            cli_command: std::env::var("VELA_SCIENTIST_CLI")
                .unwrap_or_else(|_| "claude".to_string()),
            apply: !dry_run,
            max_files: max_files.or(Some(50)),
            max_items_per_category: max_items_per_category.or(Some(4)),
        };
        match run(input).await {
            Ok(report) => {
                if json_out {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&report).unwrap_or_default()
                    );
                    return;
                }
                println!();
                println!("  {}", "VELA · COMPILE-NOTES · NOTES-COMPILER".dimmed());
                println!("  {}", tick_row(60));
                println!("  agent:                 {}", report.run.agent);
                println!("  run id:                {}", report.run.run_id);
                println!(
                    "  model:                 {}",
                    if report.run.model.is_empty() {
                        "(env default)"
                    } else {
                        &report.run.model
                    }
                );
                println!("  vault:                 {}", vault.display());
                println!("  frontier:              {}", frontier.display());
                println!("  notes seen:            {}", report.notes_seen);
                println!("  notes processed:       {}", report.notes_processed);
                println!("  open questions:        {}", report.open_questions_emitted);
                println!("  hypotheses:            {}", report.hypotheses_emitted);
                println!(
                    "  candidate findings:    {}",
                    report.candidate_findings_emitted
                );
                println!("  tensions:              {}", report.tensions_emitted);
                println!(
                    "  proposals:             {} {}",
                    report.proposals_written,
                    if dry_run {
                        "(dry-run, not written)"
                    } else {
                        "(appended to frontier)"
                    }
                );
                if !report.skipped.is_empty() {
                    println!("  skipped:               {} files", report.skipped.len());
                    for s in report.skipped.iter().take(5) {
                        println!("    - {}: {}", s.path, s.reason);
                    }
                    if report.skipped.len() > 5 {
                        println!("    … {} more", report.skipped.len() - 5);
                    }
                }
                println!();
                if !dry_run && report.proposals_written > 0 {
                    println!(
                        "  next: review in the Workbench Inbox, then `vela queue sign --all`."
                    );
                }
            }
            Err(e) => {
                eprintln!("  notes compiler failed: {e}");
                std::process::exit(1);
            }
        }
    })
}

/// Adapter for `vela compile-code` (v0.24).
fn code_handler(
    root: PathBuf,
    frontier: PathBuf,
    backend: Option<String>,
    max_files: Option<usize>,
    dry_run: bool,
    json_out: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(async move {
        use vela_scientist::code_analyst::{CodeAnalystInput, run};
        let model = backend.and_then(|b| {
            let trimmed = b.trim().to_string();
            if trimmed.is_empty() || trimmed == "claude-cli" || trimmed == "default" {
                None
            } else {
                Some(trimmed)
            }
        });
        let input = CodeAnalystInput {
            root: root.clone(),
            frontier_path: frontier.clone(),
            model,
            cli_command: std::env::var("VELA_SCIENTIST_CLI")
                .unwrap_or_else(|_| "claude".to_string()),
            apply: !dry_run,
            max_files: max_files.or(Some(30)),
        };
        match run(input).await {
            Ok(report) => {
                if json_out {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&report).unwrap_or_default()
                    );
                    return;
                }
                println!();
                println!("  {}", "VELA · COMPILE-CODE · CODE-ANALYST".dimmed());
                println!("  {}", tick_row(60));
                println!("  agent:                {}", report.run.agent);
                println!("  run id:               {}", report.run.run_id);
                println!(
                    "  model:                {}",
                    if report.run.model.is_empty() {
                        "(env default)"
                    } else {
                        &report.run.model
                    }
                );
                println!("  root:                 {}", root.display());
                println!("  frontier:             {}", frontier.display());
                println!("  files seen:           {}", report.files_seen);
                println!("  notebooks processed:  {}", report.notebooks_processed);
                println!("  scripts processed:    {}", report.scripts_processed);
                println!("  analyses:             {}", report.analyses_emitted);
                println!("  code findings:        {}", report.code_findings_emitted);
                println!(
                    "  experiment intents:   {}",
                    report.experiment_intents_emitted
                );
                println!(
                    "  proposals:            {} {}",
                    report.proposals_written,
                    if dry_run {
                        "(dry-run, not written)"
                    } else {
                        "(appended to frontier)"
                    }
                );
                if !report.skipped.is_empty() {
                    println!("  skipped:              {} files", report.skipped.len());
                    for s in report.skipped.iter().take(5) {
                        println!("    - {}: {}", s.path, s.reason);
                    }
                    if report.skipped.len() > 5 {
                        println!("    … {} more", report.skipped.len() - 5);
                    }
                }
                println!();
                if !dry_run && report.proposals_written > 0 {
                    println!(
                        "  next: review in the Workbench Inbox, then `vela queue sign --all`."
                    );
                }
            }
            Err(e) => {
                eprintln!("  code analyst failed: {e}");
                std::process::exit(1);
            }
        }
    })
}

/// Adapter for `vela compile-data` (v0.25).
fn datasets_handler(
    root: PathBuf,
    frontier: PathBuf,
    backend: Option<String>,
    sample_rows: Option<usize>,
    dry_run: bool,
    json_out: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(async move {
        use vela_scientist::datasets::{DatasetInput, run};
        let model = backend.and_then(|b| {
            let trimmed = b.trim().to_string();
            if trimmed.is_empty() || trimmed == "claude-cli" || trimmed == "default" {
                None
            } else {
                Some(trimmed)
            }
        });
        let input = DatasetInput {
            root: root.clone(),
            frontier_path: frontier.clone(),
            model,
            cli_command: std::env::var("VELA_SCIENTIST_CLI")
                .unwrap_or_else(|_| "claude".to_string()),
            apply: !dry_run,
            sample_rows: sample_rows.unwrap_or(50),
        };
        match run(input).await {
            Ok(report) => {
                if json_out {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&report).unwrap_or_default()
                    );
                    return;
                }
                println!();
                println!("  {}", "VELA · COMPILE-DATA · DATASETS".dimmed());
                println!("  {}", tick_row(60));
                println!("  agent:                {}", report.run.agent);
                println!("  run id:               {}", report.run.run_id);
                println!(
                    "  model:                {}",
                    if report.run.model.is_empty() {
                        "(env default)"
                    } else {
                        &report.run.model
                    }
                );
                println!("  root:                 {}", root.display());
                println!("  frontier:             {}", frontier.display());
                println!("  datasets seen:        {}", report.datasets_seen);
                println!("  csv processed:        {}", report.csv_processed);
                println!("  parquet processed:    {}", report.parquet_processed);
                println!(
                    "  dataset summaries:    {}",
                    report.dataset_summaries_emitted
                );
                println!(
                    "  supported claims:     {}",
                    report.supported_claims_emitted
                );
                println!(
                    "  proposals:            {} {}",
                    report.proposals_written,
                    if dry_run {
                        "(dry-run, not written)"
                    } else {
                        "(appended to frontier)"
                    }
                );
                if !report.skipped.is_empty() {
                    println!("  skipped:              {} files", report.skipped.len());
                    for s in report.skipped.iter().take(5) {
                        println!("    - {}: {}", s.path, s.reason);
                    }
                    if report.skipped.len() > 5 {
                        println!("    … {} more", report.skipped.len() - 5);
                    }
                }
                println!();
                if !dry_run && report.proposals_written > 0 {
                    println!(
                        "  next: review in the Workbench Inbox, then `vela queue sign --all`."
                    );
                }
            }
            Err(e) => {
                eprintln!("  datasets agent failed: {e}");
                std::process::exit(1);
            }
        }
    })
}

/// Adapter for `vela review-pending` (v0.28).
fn reviewer_handler(
    frontier: PathBuf,
    backend: Option<String>,
    max_proposals: Option<usize>,
    batch_size: usize,
    dry_run: bool,
    json_out: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(async move {
        use vela_scientist::reviewer::{ReviewerInput, run};
        let model = backend.and_then(|b| {
            let t = b.trim().to_string();
            if t.is_empty() || t == "claude-cli" || t == "default" {
                None
            } else {
                Some(t)
            }
        });
        let input = ReviewerInput {
            frontier_path: frontier.clone(),
            model,
            cli_command: std::env::var("VELA_SCIENTIST_CLI")
                .unwrap_or_else(|_| "claude".to_string()),
            apply: !dry_run,
            max_proposals: max_proposals.or(Some(30)),
            batch_size,
        };
        match run(input).await {
            Ok(report) => {
                if json_out {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&report).unwrap_or_default()
                    );
                    return;
                }
                println!();
                println!("  {}", "VELA · REVIEW-PENDING · REVIEWER-AGENT".dimmed());
                println!("  {}", tick_row(60));
                println!("  agent:           {}", report.run.agent);
                println!("  run id:          {}", report.run.run_id);
                println!("  frontier:        {}", frontier.display());
                println!("  pending seen:    {}", report.pending_seen);
                println!("  scored:          {}", report.scored);
                println!(
                    "  notes:           {} {}",
                    report.notes_written,
                    if dry_run {
                        "(dry-run, not written)"
                    } else {
                        "(appended to frontier)"
                    }
                );
                if !report.skipped.is_empty() {
                    println!("  skipped:         {}", report.skipped.len());
                    for s in report.skipped.iter().take(5) {
                        println!("    - {}: {}", s.proposal_id, s.reason);
                    }
                }
                println!();
            }
            Err(e) => {
                eprintln!("  reviewer agent failed: {e}");
                std::process::exit(1);
            }
        }
    })
}

/// Adapter for `vela find-tensions` (v0.28).
fn tensions_handler(
    frontier: PathBuf,
    backend: Option<String>,
    max_findings: Option<usize>,
    dry_run: bool,
    json_out: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(async move {
        use vela_scientist::tensions::{TensionsInput, run};
        let model = backend.and_then(|b| {
            let t = b.trim().to_string();
            if t.is_empty() || t == "claude-cli" || t == "default" {
                None
            } else {
                Some(t)
            }
        });
        let input = TensionsInput {
            frontier_path: frontier.clone(),
            model,
            cli_command: std::env::var("VELA_SCIENTIST_CLI")
                .unwrap_or_else(|_| "claude".to_string()),
            apply: !dry_run,
            max_findings: max_findings.or(Some(60)),
        };
        match run(input).await {
            Ok(report) => {
                if json_out {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&report).unwrap_or_default()
                    );
                    return;
                }
                println!();
                println!(
                    "  {}",
                    "VELA · FIND-TENSIONS · CONTRADICTION-FINDER".dimmed()
                );
                println!("  {}", tick_row(60));
                println!("  agent:               {}", report.run.agent);
                println!("  run id:              {}", report.run.run_id);
                println!("  frontier:            {}", frontier.display());
                println!("  findings seen:       {}", report.findings_seen);
                println!("  batches processed:   {}", report.batches_processed);
                println!("  tensions emitted:    {}", report.tensions_emitted);
                println!(
                    "  proposals:           {} {}",
                    report.proposals_written,
                    if dry_run {
                        "(dry-run, not written)"
                    } else {
                        "(appended to frontier)"
                    }
                );
                if !report.skipped.is_empty() {
                    println!("  skipped batches:     {}", report.skipped.len());
                    for s in report.skipped.iter().take(5) {
                        println!("    - batch {}: {}", s.batch, s.reason);
                    }
                }
                println!();
            }
            Err(e) => {
                eprintln!("  contradiction finder failed: {e}");
                std::process::exit(1);
            }
        }
    })
}

/// Adapter for `vela plan-experiments` (v0.28).
fn experiments_handler(
    frontier: PathBuf,
    backend: Option<String>,
    max_findings: Option<usize>,
    dry_run: bool,
    json_out: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(async move {
        use vela_scientist::experiments::{ExperimentsInput, run};
        let model = backend.and_then(|b| {
            let t = b.trim().to_string();
            if t.is_empty() || t == "claude-cli" || t == "default" {
                None
            } else {
                Some(t)
            }
        });
        let input = ExperimentsInput {
            frontier_path: frontier.clone(),
            model,
            cli_command: std::env::var("VELA_SCIENTIST_CLI")
                .unwrap_or_else(|_| "claude".to_string()),
            apply: !dry_run,
            max_findings: max_findings.or(Some(20)),
        };
        match run(input).await {
            Ok(report) => {
                if json_out {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&report).unwrap_or_default()
                    );
                    return;
                }
                println!();
                println!(
                    "  {}",
                    "VELA · PLAN-EXPERIMENTS · EXPERIMENT-PLANNER".dimmed()
                );
                println!("  {}", tick_row(60));
                println!("  agent:               {}", report.run.agent);
                println!("  run id:              {}", report.run.run_id);
                println!("  frontier:            {}", frontier.display());
                println!("  questions seen:      {}", report.questions_seen);
                println!("  hypotheses seen:     {}", report.hypotheses_seen);
                println!("  experiments emitted: {}", report.experiments_emitted);
                println!(
                    "  proposals:           {} {}",
                    report.proposals_written,
                    if dry_run {
                        "(dry-run, not written)"
                    } else {
                        "(appended to frontier)"
                    }
                );
                if !report.skipped.is_empty() {
                    println!("  skipped:             {}", report.skipped.len());
                    for s in report.skipped.iter().take(5) {
                        println!("    - {}: {}", s.finding_id, s.reason);
                    }
                }
                println!();
            }
            Err(e) => {
                eprintln!("  experiment planner failed: {e}");
                std::process::exit(1);
            }
        }
    })
}

/// Tiny copy of `vela_protocol::cli_style::tick_row` to keep the
/// binary independent of crate-private chrome helpers. If the
/// instrument styling diverges, that's fine — this binary's output
/// is local-only.
fn tick_row(width: usize) -> String {
    let mut out = String::with_capacity(width);
    for i in 0..width {
        out.push(if i % 4 == 0 { '·' } else { ' ' });
    }
    out
}

/// v0.82.4: `vela constellation init <name> --atlases <a>,<b>`.
fn constellation_init_handler(
    constellations_root: PathBuf,
    name: String,
    scope_note: Option<String>,
    atlases: Vec<PathBuf>,
    json: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(async move {
        match vela_constellation::init_constellation(
            &constellations_root,
            &name,
            scope_note.as_deref(),
            &atlases,
        ) {
            Ok((manifest_path, manifest)) => {
                if json {
                    let payload = serde_json::json!({
                        "ok": true,
                        "command": "constellation.init",
                        "constellation_id": manifest.id,
                        "manifest_path": manifest_path.display().to_string(),
                        "atlas_count": manifest.composing_atlases.len(),
                    });
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&payload)
                            .expect("serialize constellation init")
                    );
                } else {
                    println!();
                    println!("  {}  {}", "ok".green(), manifest.id);
                    println!("  manifest:           {}", manifest_path.display());
                    println!("  composing atlases:  {}", manifest.composing_atlases.len());
                    for a in &manifest.composing_atlases {
                        println!("    · {} ({})", a.name, a.vat_id);
                    }
                }
            }
            Err(e) => {
                eprintln!("{} constellation init: {e}", "err ·".red());
                std::process::exit(1);
            }
        }
    })
}

/// v0.82.4: `vela constellation materialize <name>`. Reads each
/// composing Atlas's snapshot.json (re-materializing on demand),
/// sums findings + events + bridges, computes composition hash,
/// writes snapshot.json + index.html.
fn constellation_materialize_handler(
    constellations_root: PathBuf,
    name: String,
    json: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(async move {
        let dir = constellations_root.join(&name);
        match vela_constellation::materialize_constellation(&dir) {
            Ok((snapshot_path, snapshot)) => {
                if json {
                    let payload = serde_json::json!({
                        "ok": true,
                        "command": "constellation.materialize",
                        "constellation_id": snapshot.constellation_id,
                        "snapshot_path": snapshot_path.display().to_string(),
                        "atlas_count": snapshot.atlas_count,
                        "total_frontiers": snapshot.total_frontiers,
                        "total_findings": snapshot.total_findings,
                        "total_accepted_core": snapshot.total_accepted_core,
                        "total_events": snapshot.total_events,
                        "total_bridges": snapshot.total_bridges,
                        "cross_atlas_bridges": snapshot.cross_atlas_bridges,
                        "composition_hash": snapshot.composition_hash,
                    });
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&payload)
                            .expect("serialize constellation materialize")
                    );
                } else {
                    println!();
                    println!(
                        "  {}  {}",
                        "constellation".green(),
                        snapshot.constellation_name
                    );
                    println!("  vco_id:             {}", snapshot.constellation_id);
                    println!("  atlases:            {}", snapshot.atlas_count);
                    println!("  total frontiers:    {}", snapshot.total_frontiers);
                    println!("  total findings:     {}", snapshot.total_findings);
                    println!("  accepted-core:      {}", snapshot.total_accepted_core);
                    println!("  total events:       {}", snapshot.total_events);
                    println!("  total bridges:      {}", snapshot.total_bridges);
                    println!("  cross-Atlas bridges: {}", snapshot.cross_atlas_bridges);
                    println!("  composition hash:   {}", snapshot.composition_hash);
                    println!("  snapshot:           {}", snapshot_path.display());
                    for a in &snapshot.atlases {
                        println!(
                            "    · {} ({}): {} frontiers, {} findings, {} events, {} bridges",
                            a.name, a.vat_id, a.frontiers, a.findings, a.events, a.bridges
                        );
                    }
                }
            }
            Err(e) => {
                eprintln!("{} constellation materialize: {e}", "err ·".red());
                std::process::exit(1);
            }
        }
    })
}

/// v0.82.4: `vela constellation serve <name>`. Static-file HTTP
/// server pointing at the constellation dir; refreshes
/// snapshot.json + index.html on start by re-materializing.
fn constellation_serve_handler(
    constellations_root: PathBuf,
    name: String,
    port: u16,
    open_browser: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(async move {
        let dir = constellations_root.join(&name);
        match vela_constellation::materialize_constellation(&dir) {
            Ok((_, snapshot)) => {
                println!();
                println!(
                    "  {}  {}",
                    "constellation".green(),
                    snapshot.constellation_name
                );
                println!("  vco_id:             {}", snapshot.constellation_id);
                println!("  atlases:            {}", snapshot.atlas_count);
                println!("  total findings:     {}", snapshot.total_findings);
                println!();
            }
            Err(e) => {
                eprintln!("{} constellation materialize: {e}", "err ·".red());
                std::process::exit(1);
            }
        }
        use axum::Router;
        use tower_http::services::ServeDir;
        let serve_dir = ServeDir::new(&dir);
        let app: Router = Router::new().fallback_service(serve_dir);
        let addr = format!("127.0.0.1:{port}");
        let listener = match tokio::net::TcpListener::bind(&addr).await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("{} bind {addr}: {e}", "err ·".red());
                std::process::exit(1);
            }
        };
        let url = format!("http://{addr}/");
        println!("  {} {}", "serving constellation at".green(), url);
        println!();
        if open_browser && let Err(e) = std::process::Command::new("open").arg(&url).spawn() {
            eprintln!("  (note: could not auto-open browser: {e})");
        }
        if let Err(e) = axum::serve(listener, app).await {
            eprintln!("{} axum::serve: {e}", "err ·".red());
            std::process::exit(1);
        }
    })
}

// --- Atlas R.2 verifier intercept ---
//
// Read-only subcommands added in v0.338 for the Conjecture
// (`vela.conjecture.v0.1`, `vcj_*`) and ProofPacket
// (`vela.proof_packet.v0.1`) primitives.
//
// Usage:
//   vela conjecture verify <path-to-vcj_*.json>
//   vela proof-packet verify <path-to-pp_*.json>
//   vela proof-packet verify-external <path-to-pp_*.json>
//
// The intercept handles these subcommands and returns true; otherwise
// returns false and lets the regular dispatcher run.

fn try_handle_atlas_r2_verify_intercept() -> bool {
    let argv: Vec<String> = std::env::args().collect();
    if argv.len() < 3 {
        return false;
    }
    match (argv[1].as_str(), argv[2].as_str()) {
        ("conjecture", "verify") => {
            handle_conjecture_verify(&argv[3..]);
            true
        }
        ("proof-packet", "verify") => {
            handle_proof_packet_verify(&argv[3..]);
            true
        }
        ("proof-packet", "verify-external") => {
            handle_proof_packet_verify_external(&argv[3..]);
            true
        }
        _ => false,
    }
}

fn handle_conjecture_verify(args: &[String]) {
    let path = match args.first() {
        Some(p) => p,
        None => {
            eprintln!("{} usage: vela conjecture verify <path>", "err ·".red());
            std::process::exit(2);
        }
    };
    let body = match std::fs::read_to_string(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{} read {path}: {e}", "err ·".red());
            std::process::exit(1);
        }
    };
    let conj: vela_edge::conjecture::Conjecture = match serde_json::from_str(&body) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{} parse {path}: {e}", "err ·".red());
            std::process::exit(1);
        }
    };
    if let Err(e) = conj.verify() {
        eprintln!("{} witness signature/id invalid: {e}", "err ·".red());
        std::process::exit(1);
    }
    let cosigs = match conj.verify_cosignatures() {
        Ok(n) => n,
        Err(e) => {
            eprintln!("{} co-signature invalid: {e}", "err ·".red());
            std::process::exit(1);
        }
    };
    println!(
        "  {} {} witness:{} cosigners:{} status:{:?}",
        "conjecture verified".green().bold(),
        conj.id,
        conj.witness.actor_id,
        cosigs,
        conj.status,
    );
}

fn handle_proof_packet_verify(args: &[String]) {
    let path = match args.first() {
        Some(p) => p,
        None => {
            eprintln!(
                "{} usage: vela proof-packet verify <path>",
                "err ·".red()
            );
            std::process::exit(2);
        }
    };
    let body = match std::fs::read_to_string(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{} read {path}: {e}", "err ·".red());
            std::process::exit(1);
        }
    };
    let packet: vela_edge::proof_packet::ProofPacket =
        match serde_json::from_str(&body) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{} parse {path}: {e}", "err ·".red());
                std::process::exit(1);
            }
        };
    if let Err(e) = packet.verify() {
        eprintln!("{} packet invalid: {e}", "err ·".red());
        std::process::exit(1);
    }
    println!(
        "  {} {} hash:{} signer:{}",
        "proof packet verified".green().bold(),
        packet.packet_id,
        &packet.packet_hash[..24],
        packet.signer_actor_id,
    );
}

fn handle_proof_packet_verify_external(args: &[String]) {
    let path = match args.first() {
        Some(p) => p,
        None => {
            eprintln!(
                "{} usage: vela proof-packet verify-external <path>",
                "err ·".red()
            );
            std::process::exit(2);
        }
    };
    let body = match std::fs::read_to_string(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{} read {path}: {e}", "err ·".red());
            std::process::exit(1);
        }
    };
    let packet: vela_edge::proof_packet::ProofPacket =
        match serde_json::from_str(&body) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{} parse {path}: {e}", "err ·".red());
                std::process::exit(1);
            }
        };
    if let Err(e) = packet.verify() {
        eprintln!("{} packet invalid: {e}", "err ·".red());
        std::process::exit(1);
    }
    let n = match packet.verify_external_verifications() {
        Ok(n) => n,
        Err(e) => {
            eprintln!("{} external verification invalid: {e}", "err ·".red());
            std::process::exit(1);
        }
    };
    println!(
        "  {} {} external:{} (signer:{})",
        "proof packet + externals verified".green().bold(),
        packet.packet_id,
        n,
        packet.signer_actor_id,
    );
}
