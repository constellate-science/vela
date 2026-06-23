//! Read-only MCP/HTTP frontier server.

#![allow(clippy::too_many_lines)]

use std::collections::HashMap;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use reqwest::Client;
use serde::Serialize;
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower_http::cors::CorsLayer;

use vela_edge::observer;
use vela_edge::signals;
use vela_edge::tool_registry;
use vela_protocol::bundle::FindingBundle;
use vela_protocol::events;
use vela_protocol::project::{self, ConfidenceDistribution, Project, ProjectStats};
use vela_protocol::repo;
use vela_protocol::sources;
use vela_protocol::state;
pub enum ProjectSource {
    Single(PathBuf),
    Directory(PathBuf),
}

impl ProjectSource {
    pub fn from_args(single: Option<&Path>, dir: Option<&Path>) -> Self {
        if let Some(d) = dir {
            Self::Directory(d.to_path_buf())
        } else if let Some(s) = single {
            Self::Single(s.to_path_buf())
        } else {
            eprintln!(
                "{} provide either a frontier file or --frontiers <dir>",
                vela_protocol::cli_style::err_prefix()
            );
            std::process::exit(1);
        }
    }
}

#[derive(Clone)]
pub struct ProjectInfo {
    pub name: String,
    pub file: String,
    pub findings_count: usize,
    pub links_count: usize,
    pub papers: usize,
}

pub fn load_projects(source: &ProjectSource) -> (Project, Vec<ProjectInfo>) {
    match source {
        ProjectSource::Single(path) => {
            let mut frontier = repo::load_from_path(path).unwrap_or_else(|e| {
                eprintln!(
                    "{} failed to load frontier: {e}",
                    vela_protocol::cli_style::err_prefix()
                );
                std::process::exit(1);
            });
            sources::materialize_project(&mut frontier);
            let info = ProjectInfo {
                name: frontier.project.name.clone(),
                file: path.display().to_string(),
                findings_count: frontier.findings.len(),
                links_count: frontier.stats.links,
                papers: frontier.project.papers_processed,
            };
            (frontier, vec![info])
        }
        ProjectSource::Directory(dir) => {
            let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
                .unwrap_or_else(|e| {
                    eprintln!(
                        "{} failed to read directory: {e}",
                        vela_protocol::cli_style::err_prefix()
                    );
                    std::process::exit(1);
                })
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|path| {
                    (path.is_dir() && path.join(".vela").exists())
                        || path.extension().is_some_and(|ext| ext == "json")
                })
                .collect();
            entries.sort();
            if entries.is_empty() {
                eprintln!("no frontier files found in {}", dir.display());
                std::process::exit(1);
            }

            let mut named = Vec::new();
            for path in &entries {
                let mut frontier = repo::load_from_path(path).unwrap_or_else(|e| {
                    eprintln!(
                        "{} failed to load {}: {e}",
                        vela_protocol::cli_style::err_prefix(),
                        path.display()
                    );
                    std::process::exit(1);
                });
                sources::materialize_project(&mut frontier);
                let name = path
                    .file_stem()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                named.push((name, frontier));
            }
            let infos = named
                .iter()
                .map(|(name, frontier)| ProjectInfo {
                    name: frontier.project.name.clone(),
                    file: name.clone(),
                    findings_count: frontier.findings.len(),
                    links_count: frontier.stats.links,
                    papers: frontier.project.papers_processed,
                })
                .collect::<Vec<_>>();
            (merge_projects(named), infos)
        }
    }
}

fn merge_projects(frontiers: Vec<(String, Project)>) -> Project {
    let mut findings = Vec::<FindingBundle>::new();
    let mut categories = HashMap::<String, usize>::new();
    let mut link_types = HashMap::<String, usize>::new();
    let mut names = Vec::new();
    let mut papers_processed = 0usize;
    let mut errors = 0usize;
    // v0.36.2: preserve v0.32+ kernel objects across the merge.
    // Pre-v0.36.2, `datasets`, `code_artifacts`, and `artifacts` were dropped
    // during merge, leaving the merged stats incomplete.
    let mut datasets = Vec::new();
    let mut code_artifacts = Vec::new();
    let mut artifacts = Vec::new();

    for (name, frontier) in frontiers {
        names.push(name);
        papers_processed += frontier.project.papers_processed;
        errors += frontier.project.errors;
        for (category, count) in frontier.stats.categories {
            *categories.entry(category).or_default() += count;
        }
        for (link_type, count) in frontier.stats.link_types {
            *link_types.entry(link_type).or_default() += count;
        }
        findings.extend(frontier.findings);
        datasets.extend(frontier.datasets);
        code_artifacts.extend(frontier.code_artifacts);
        artifacts.extend(frontier.artifacts);
    }

    let mut deduped = Vec::<FindingBundle>::new();
    let mut seen = HashMap::<String, usize>::new();
    for finding in findings {
        if let Some(existing) = seen.get(&finding.id).copied() {
            if finding.confidence.score > deduped[existing].confidence.score {
                deduped[existing] = finding;
            }
        } else {
            seen.insert(finding.id.clone(), deduped.len());
            deduped.push(finding);
        }
    }

    let links = deduped.iter().map(|finding| finding.links.len()).sum();
    let replicated = deduped
        .iter()
        .filter(|finding| finding.evidence.replicated)
        .count();
    let avg_confidence = if deduped.is_empty() {
        0.0
    } else {
        (deduped
            .iter()
            .map(|finding| finding.confidence.score)
            .sum::<f64>()
            / deduped.len() as f64
            * 1000.0)
            .round()
            / 1000.0
    };
    let stats = ProjectStats {
        findings: deduped.len(),
        links,
        replicated,
        unreplicated: deduped.len().saturating_sub(replicated),
        avg_confidence,
        gaps: deduped.iter().filter(|finding| finding.flags.gap).count(),
        negative_space: deduped
            .iter()
            .filter(|finding| finding.flags.negative_space)
            .count(),
        contested: deduped
            .iter()
            .filter(|finding| finding.flags.contested)
            .count(),
        categories,
        link_types,
        human_reviewed: deduped
            .iter()
            .filter(|finding| {
                finding.provenance.review.as_ref().is_some_and(|review| {
                    review.reviewed
                        && review
                            .reviewer
                            .as_deref()
                            .map(vela_protocol::events::actor_kind)
                            .unwrap_or("human")
                            == "human"
                })
            })
            .count(),
        agent_reviewed: deduped
            .iter()
            .filter(|finding| {
                finding.provenance.review.as_ref().is_some_and(|review| {
                    review.reviewed
                        && review
                            .reviewer
                            .as_deref()
                            .map(vela_protocol::events::actor_kind)
                            .unwrap_or("human")
                            != "human"
                })
            })
            .count(),
        review_event_count: 0,
        confidence_update_count: 0,
        event_count: 0,
        source_count: 0,
        evidence_atom_count: 0,
        condition_record_count: 0,
        proposal_count: 0,
        confidence_distribution: ConfidenceDistribution {
            high_gt_80: deduped
                .iter()
                .filter(|finding| finding.confidence.score > 0.8)
                .count(),
            medium_60_80: deduped
                .iter()
                .filter(|finding| (0.6..=0.8).contains(&finding.confidence.score))
                .count(),
            low_lt_60: deduped
                .iter()
                .filter(|finding| finding.confidence.score < 0.6)
                .count(),
        },
    };

    let mut project = Project {
        vela_version: project::VELA_SCHEMA_VERSION.to_string(),
        schema: project::VELA_SCHEMA_URL.to_string(),
        frontier_id: None,
        project: project::ProjectMeta {
            name: format!("merged: {}", names.join(", ")),
            description: format!("Merged from {} frontiers", names.len()),
            compiled_at: chrono::Utc::now().to_rfc3339(),
            compiler: project::VELA_COMPILER_VERSION.to_string(),
            papers_processed,
            errors,
            dependencies: Vec::new(),
        },
        stats,
        findings: deduped,
        sources: Vec::new(),
        evidence_atoms: Vec::new(),
        condition_records: Vec::new(),
        review_events: Vec::new(),
        confidence_updates: Vec::new(),
        events: Vec::new(),
        proposals: Vec::new(),
        proof_state: Default::default(),
        signatures: Vec::new(),
        actors: Vec::new(),
        datasets,
        code_artifacts,
        artifacts,
        released_diff_packs: Vec::new(),
        verdict_conflicts: Vec::new(),
        contradictions: Vec::new(),
        verifier_attachments: Vec::new(),
        attempts: Vec::new(),
        attempt_resolutions: Vec::new(),
        transfers: Vec::new(),
        endorsements: Vec::new(),
        statement_attestations: Vec::new(),
        anchor_links: Vec::new(),
        attempt_claims: Vec::new(),
        statement_registrations: Vec::new(),
    };
    sources::materialize_project(&mut project);
    project
}

pub async fn run(
    source: ProjectSource,
    _backend: Option<&str>,
    profile: tool_registry::McpProfile,
) {
    dotenvy::dotenv().ok();
    let (frontier, project_infos) = load_projects(&source);
    let source_path: Option<PathBuf> = match &source {
        ProjectSource::Single(path) => Some(path.clone()),
        ProjectSource::Directory(_) => None,
    };
    let frontier = Arc::new(Mutex::new(frontier));
    let client = Client::new();
    let stdin = io::stdin();
    let stdout = io::stdout();

    for line in stdin.lock().lines() {
        let Ok(line) = line else {
            break;
        };
        if line.trim().is_empty() {
            continue;
        }
        let Ok(request) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        let id = request.get("id").cloned();
        let method = request["method"].as_str().unwrap_or_default();
        let response = match method {
            "initialize" => json_rpc_result(
                &id,
                json!({
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "vela", "version": project::VELA_SCHEMA_VERSION}
                }),
            ),
            "notifications/initialized" => continue,
            "tools/list" => json_rpc_result(
                &id,
                json!({"tools": tool_registry::mcp_tools_json_for_profile(profile)}),
            ),
            "tools/call" => {
                let name = request["params"]["name"].as_str().unwrap_or_default();
                let args = request["params"]["arguments"].clone();
                if let Some(err) = profile_gate(&id, name, profile) {
                    err
                } else {
                    handle_tool_call(
                        &id,
                        name,
                        &args,
                        &frontier,
                        &client,
                        &project_infos,
                        source_path.as_deref(),
                    )
                    .await
                }
            }
            "ping" => json_rpc_result(&id, json!({})),
            _ => json_rpc_error(&id, -32601, "Method not found"),
        };
        let mut out = stdout.lock();
        let _ = serde_json::to_writer(&mut out, &response);
        let _ = out.write_all(b"\n");
        let _ = out.flush();
    }
}

pub async fn run_http(
    source: ProjectSource,
    backend: Option<&str>,
    port: u16,
    profile: tool_registry::McpProfile,
) {
    let _ = backend;
    dotenvy::dotenv().ok();
    let (frontier, project_infos) = load_projects(&source);
    let source_path = match &source {
        ProjectSource::Single(path) => Some(path.clone()),
        ProjectSource::Directory(_) => None,
    };
    let state = AppState {
        project: Arc::new(Mutex::new(frontier)),
        project_infos,
        client: Client::new(),
        profile,
        source_path,
    };

    let app = Router::new()
        .route("/health", get(http_health))
        .route("/healthz", get(http_health))
        .route("/api/frontier", get(http_frontier))
        .route("/api/findings", get(http_findings))
        .route("/api/findings/{id}", get(http_finding_by_id))
        .route("/api/contradictions", get(http_contradictions))
        // v0.97: HTTP mirror of `vela discord` CLI. Frontier-wide
        // discord report computed read-only from the live event log.
        // Optional ?kind=<DiscordKind> filter.
        .route("/api/discord", get(http_discord))
        .route("/api/tensions", get(http_tensions))
        .route("/api/gaps", get(http_gaps))
        .route("/api/artifacts", get(http_artifacts))
        .route("/api/artifact-audit", get(http_artifact_audit))
        .route("/api/proof", get(http_proof))
        .route("/api/observer/{policy}", get(http_observer))
        .route("/api/propagate/{id}", get(http_propagate))
        .route("/api/stats", get(http_stats))
        .route("/api/frontiers", get(http_frontiers))
        .route("/api/pubmed", get(http_pubmed))
        // Phase Q-r (v0.5): cursor-paginated event-log read for agent
        // loops and public consumers. The canonical event log is
        // already ordered and content-addressed, so the cursor is just
        // the last seen `vev_…`.
        .route("/api/events", get(http_events))
        // Phase R (v0.5): Workbench draft queue. Browser POSTs unsigned
        // intents here; `vela queue sign` is the only path that turns
        // them into signed canonical state. The Ed25519 key never
        // enters the browser.
        .route("/api/queue", post(http_queue_append))
        // v0.92: agent write target. POST a Carina ArtifactPacket
        // JSON; substrate validates, writes proposals to disk,
        // returns the new vpr_* ids. The single integration
        // surface for AI agents that produce structured
        // scientific output.
        .route("/api/proposals/from-carina", post(http_from_carina))
        .route("/api/tools", get(http_tools_list))
        .route("/mcp/tools", get(http_tools_list))
        .route("/api/tool", post(http_tool_call));

    // v0.107.5: explicit request-body cap. Closes the integrity
    // half of THREAT_MODEL.md A13 (resource exhaustion via large
    // packets). axum's default body limit is 2MB; we raise to 8MB
    // so a real Carina packet with several artifacts fits, then
    // pin the limit explicitly so a future axum default change
    // does not silently expose the surface. Localhost-only deploys
    // are bounded by this limit; remote deploys behind a reverse
    // proxy should layer rate limiting on top (the substrate does
    // not enforce per-actor or per-IP request budgets).
    let app = app
        .layer(axum::extract::DefaultBodyLimit::max(8 * 1024 * 1024))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let addr = format!("0.0.0.0:{port}");
    eprintln!(
        "  {}",
        format!("VELA · SERVE · HTTP :{port}").to_uppercase()
    );
    eprintln!("  {}", vela_protocol::cli_style::tick_row(60));
    eprintln!("  listening on http://{addr}");
    // v0.91: full endpoint enumeration so a fresh user opening
    // `vela serve --http` knows what they can hit. Grouped by
    // function rather than alphabetically.
    eprintln!("  endpoints:");
    eprintln!("    health:     GET  /health");
    eprintln!("    state:      GET  /api/frontier      /api/frontiers     /api/stats");
    eprintln!("    findings:   GET  /api/findings      /api/findings/{{id}}");
    eprintln!("                     (no params -> structured list; query=... -> search)");
    eprintln!("    events:     GET  /api/events");
    eprintln!("    artifacts:  GET  /api/artifacts     /api/artifact-audit");
    eprintln!("    proof:      GET  /api/proof");
    eprintln!("    discord:    GET  /api/contradictions /api/tensions     /api/gaps");
    eprintln!("                     /api/discord (frontier-wide discord report)");
    eprintln!(
        "    projections:GET  /api/decision-brief /api/trials       /api/source-verification"
    );
    eprintln!("                     /api/source-ingest-plan /api/observer/{{policy}}");
    eprintln!("                     /api/propagate/{{id}}     /api/pubmed");
    eprintln!("    queue:      POST /api/queue");
    eprintln!("    agent:      POST /api/proposals/from-carina (Carina artifact -> proposals)");
    eprintln!("    tools:      POST /api/tool/{{name}} (MCP-style tool dispatch)");
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| {
            eprintln!(
                "{} failed to bind to {addr}: {e}",
                vela_protocol::cli_style::err_prefix()
            );
            std::process::exit(1);
        });
    axum::serve(listener, app).await.unwrap();
}

pub fn check_tools(source: ProjectSource, adoption: bool) -> Result<Value, String> {
    let started = std::time::Instant::now();
    let source_label = match &source {
        ProjectSource::Single(path) => path.display().to_string(),
        ProjectSource::Directory(path) => path.display().to_string(),
    };
    let (frontier, _project_infos) = load_projects(&source);
    let first_id = frontier.findings.first().map(|finding| finding.id.clone());
    let mut checks = vec![
        check_tool_result("frontier_stats", tool_frontier_stats(&frontier), started),
        check_tool_result(
            "search_findings",
            tool_search_findings(&json!({"query": "Sidon", "limit": 3}), &frontier),
            started,
        ),
        check_tool_result("list_gaps", tool_list_gaps(&frontier), started),
        check_tool_result(
            "list_contradictions",
            tool_list_contradictions(&frontier),
            started,
        ),
        check_tool_result(
            "frontier_graph",
            tool_frontier_graph(&json!({"kind": "contradicts"}), &frontier),
            started,
        ),
        check_tool_result(
            "contradictions",
            tool_contradictions(&json!({}), &frontier),
            started,
        ),
        check_tool_result(
            "frontier_compare",
            tool_frontier_compare(&json!({"limit": 10}), &frontier),
            started,
        ),
        check_tool_result(
            "apply_observer",
            tool_apply_observer(&json!({"policy": "academic", "limit": 5}), &frontier),
            started,
        ),
        check_tool_result(
            "propagate_retraction",
            tool_propagate_retraction(&json!({"finding_id": "vf_missing"}), &frontier),
            started,
        ),
    ];
    if let Some(id) = first_id {
        checks.push(check_tool_result(
            "get_finding",
            tool_get_finding(&json!({"id": id}), &frontier),
            started,
        ));
        checks.push(check_tool_result(
            "get_finding_history",
            tool_get_finding_history(&json!({"id": id}), &frontier),
            started,
        ));
        checks.push(check_tool_result(
            "trace_evidence_chain",
            tool_trace_evidence_chain(&json!({"finding_id": id}), &frontier),
            started,
        ));
        checks.push(check_tool_result(
            "list_dependents",
            tool_list_dependents(&json!({"finding_id": id, "transitive": true}), &frontier),
            started,
        ));
        checks.push(check_tool_result(
            "context",
            tool_frontier_context(&json!({"finding_id": id}), &frontier),
            started,
        ));
        checks.push(check_tool_result(
            "frontier_explore",
            tool_frontier_explore(&json!({"problem": id}), &frontier),
            started,
        ));
        checks.push(check_tool_result(
            "task_packet",
            tool_task_packet(
                &json!({"problem": id}),
                &frontier,
                match &source {
                    ProjectSource::Single(p) => Some(p.as_path()),
                    ProjectSource::Directory(p) => Some(p.as_path()),
                },
            ),
            started,
        ));
        checks.push(check_tool_result(
            "deep_trace",
            tool_deep_trace(&json!({"finding_id": id, "max_hops": 3}), &frontier),
            started,
        ));
        checks.push(check_tool_result(
            "nanopublication",
            tool_nanopublication(&json!({"finding_id": id}), &frontier),
            started,
        ));
    }
    let failures = checks
        .iter()
        .filter(|check| check.get("ok").and_then(Value::as_bool) != Some(true))
        .filter_map(|check| {
            check
                .get("tool")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .collect::<Vec<_>>();
    let checked_tools = checks
        .iter()
        .filter_map(|check| check.get("tool").and_then(Value::as_str))
        .map(str::to_string)
        .collect::<Vec<_>>();
    let registered_tools = tool_registry::all_tools()
        .into_iter()
        .map(|tool| tool.name)
        .collect::<Vec<_>>();
    let adoption_report = adoption.then(|| adoption_tool_report(&checks, &source_label));

    Ok(json!({
        "ok": failures.is_empty(),
        "command": if adoption { "serve --check-tools --adoption" } else { "serve --check-tools" },
        "schema": "vela.tool-check.v0",
        "frontier": {
            "name": frontier.project.name,
            "findings": frontier.stats.findings,
            "links": frontier.stats.links,
        },
        "summary": {
            "checks": checks.len(),
            "passed": checks.len().saturating_sub(failures.len()),
            "failed": failures.len(),
        },
        "tool_count": checked_tools.len(),
        "tools": checked_tools,
        "registered_tool_count": registered_tools.len(),
        "registered_tools": registered_tools,
        "checks": checks,
        "failures": failures,
        "adoption": adoption_report,
    }))
}

fn adoption_tool_report(checks: &[Value], source_label: &str) -> Value {
    let required_tools = vec![
        "frontier_stats",
        "search_findings",
        "get_finding",
        "list_gaps",
        "list_contradictions",
        "trace_evidence_chain",
    ];
    let missing_or_failed = required_tools
        .iter()
        .filter(|tool| {
            !checks.iter().any(|check| {
                check.get("tool").and_then(Value::as_str) == Some(**tool)
                    && check.get("ok").and_then(Value::as_bool) == Some(true)
            })
        })
        .copied()
        .collect::<Vec<_>>();
    json!({
        "ok": missing_or_failed.is_empty(),
        "required_tools": required_tools,
        "missing_or_failed": missing_or_failed,
        "mcp_config": {
            "mcpServers": {
                "vela": {
                    "command": "vela",
                    "args": ["serve", source_label]
                }
            }
        },
        "prompt": "Call frontier_stats first. Then use search_findings for the review question. Inspect important results with get_finding. Cite vf_* ids. Review list_contradictions and list_gaps as candidate signals. Use trace_evidence_chain before summarizing provenance. Preserve caveats and do not present Vela output as field consensus.",
        "commands": [
            format!("vela serve {source_label} --check-tools --adoption --json"),
            format!("vela serve {source_label}")
        ],
    })
}

#[derive(Clone)]
struct AppState {
    project: Arc<Mutex<Project>>,
    project_infos: Vec<ProjectInfo>,
    client: Client,
    /// MCP exposure profile (memo §9.1). Scopes which tools `/api/tools`
    /// lists and `/api/tool` will execute. Defaults to read-only.
    profile: tool_registry::McpProfile,
    /// Phase Q-w (v0.5): when serving a single frontier file, this is
    /// the path to write back to after a successful signed write. None
    /// when `--frontiers <dir>` is used; in that mode all writes are
    /// rejected.
    source_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize)]
struct ToolResult {
    tool: String,
    ok: bool,
    data: Value,
    markdown: String,
    signals: Vec<signals::SignalItem>,
    caveats: Vec<String>,
    duration_ms: u128,
}

impl ToolResult {
    fn from_text(
        tool: &str,
        text: String,
        duration_ms: u128,
        is_error: bool,
        frontier: Option<&Project>,
    ) -> Self {
        let data = serde_json::from_str(&text).unwrap_or_else(|_| json!({"text": text}));
        let signal_items = frontier
            .map(|project| signals::analyze(project, &[]).signals)
            .unwrap_or_default();
        Self {
            tool: tool.to_string(),
            ok: !is_error,
            data,
            markdown: text,
            signals: signal_items,
            caveats: tool_registry::tool_caveats(tool),
            duration_ms,
        }
    }

    fn metadata(&self) -> Value {
        json!({
            "tool": self.tool,
            "ok": self.ok,
            "duration_ms": self.duration_ms,
            "signals": self.signals,
            "caveats": self.caveats,
            "definition": tool_registry::get_tool(&self.tool),
        })
    }

    fn to_json_text(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }
}

/// MCP profile gate (memo §9.4): refuse to execute a tool the active profile
/// does not admit, returning a structured next-action error. `None` means the
/// call may proceed (allowed, or unknown — `handle_tool_call` then returns its
/// own not-found). This is the execution boundary; `tools/list` already hides
/// the tool, but a client could still call it by name.
fn profile_gate(
    id: &Option<Value>,
    name: &str,
    profile: tool_registry::McpProfile,
) -> Option<Value> {
    let tool = tool_registry::get_tool(name)?;
    if profile.allows(&tool) {
        return None;
    }
    let needed = if tool_registry::McpProfile::Draft.allows(&tool) {
        "draft"
    } else {
        "maintainer"
    };
    Some(json_rpc_error(
        id,
        -32001,
        &format!(
            "tool `{name}` ({}) is not available in the `{}` MCP profile; restart `vela serve` with `--profile {needed}` for a scoped session. MCP exposes tools; accepted public state still requires a key-custody human accept.",
            tool.permission_level,
            profile.as_str()
        ),
    ))
}

async fn handle_tool_call(
    id: &Option<Value>,
    name: &str,
    args: &Value,
    frontier: &Arc<Mutex<Project>>,
    client: &Client,
    project_infos: &[ProjectInfo],
    source_path: Option<&Path>,
) -> Value {
    let started = std::time::Instant::now();
    let (result, snapshot) =
        execute_tool(name, args, frontier, client, project_infos, source_path).await;
    match result {
        Ok(text) => {
            let output = ToolResult::from_text(
                name,
                text,
                started.elapsed().as_millis(),
                false,
                snapshot.as_ref(),
            );
            json_rpc_result(
                id,
                json!({
                    "content": [{"type": "text", "text": output.to_json_text()}],
                    "isError": false,
                    "_meta": output.metadata()
                }),
            )
        }
        Err(error) => {
            let output = ToolResult::from_text(
                name,
                error,
                started.elapsed().as_millis(),
                true,
                snapshot.as_ref(),
            );
            json_rpc_result(
                id,
                json!({
                    "content": [{"type": "text", "text": output.to_json_text()}],
                    "isError": true,
                    "_meta": output.metadata()
                }),
            )
        }
    }
}

async fn execute_tool(
    name: &str,
    args: &Value,
    frontier: &Arc<Mutex<Project>>,
    client: &Client,
    _project_infos: &[ProjectInfo],
    source_path: Option<&Path>,
) -> (Result<String, String>, Option<Project>) {
    match name {
        "search_findings" => {
            let project = frontier.lock().await;
            (
                tool_search_findings(args, &project),
                Some(clone_project(&project)),
            )
        }
        "get_finding" => {
            let project = frontier.lock().await;
            (
                tool_get_finding(args, &project),
                Some(clone_project(&project)),
            )
        }
        "get_finding_history" => {
            let project = frontier.lock().await;
            (
                tool_get_finding_history(args, &project),
                Some(clone_project(&project)),
            )
        }
        "list_gaps" => {
            let project = frontier.lock().await;
            (tool_list_gaps(&project), Some(clone_project(&project)))
        }
        "list_contradictions" => {
            let project = frontier.lock().await;
            (
                tool_list_contradictions(&project),
                Some(clone_project(&project)),
            )
        }
        "frontier_stats" => {
            let project = frontier.lock().await;
            (tool_frontier_stats(&project), Some(clone_project(&project)))
        }
        "propagate_retraction" => {
            let project = frontier.lock().await;
            (
                tool_propagate_retraction(args, &project),
                Some(clone_project(&project)),
            )
        }
        "apply_observer" => {
            let project = frontier.lock().await;
            (
                tool_apply_observer(args, &project),
                Some(clone_project(&project)),
            )
        }
        "trace_evidence_chain" => {
            let project = frontier.lock().await;
            (
                tool_trace_evidence_chain(args, &project),
                Some(clone_project(&project)),
            )
        }
        "list_dependents" => {
            let project = frontier.lock().await;
            (
                tool_list_dependents(args, &project),
                Some(clone_project(&project)),
            )
        }
        "context" => {
            let project = frontier.lock().await;
            (
                tool_frontier_context(args, &project),
                Some(clone_project(&project)),
            )
        }
        "frontier_explore" => {
            let project = frontier.lock().await;
            (
                tool_frontier_explore(args, &project),
                Some(clone_project(&project)),
            )
        }
        "task_packet" => {
            let project = frontier.lock().await;
            (
                tool_task_packet(args, &project, source_path),
                Some(clone_project(&project)),
            )
        }
        "frontier_graph" => {
            let project = frontier.lock().await;
            (
                tool_frontier_graph(args, &project),
                Some(clone_project(&project)),
            )
        }
        "contradictions" => {
            let project = frontier.lock().await;
            (
                tool_contradictions(args, &project),
                Some(clone_project(&project)),
            )
        }
        "deep_trace" => {
            let project = frontier.lock().await;
            (
                tool_deep_trace(args, &project),
                Some(clone_project(&project)),
            )
        }
        "blast_radius" => {
            let project = frontier.lock().await;
            (
                tool_blast_radius(args, &project),
                Some(clone_project(&project)),
            )
        }
        "frontier_compare" => {
            let project = frontier.lock().await;
            (
                tool_frontier_compare(args, &project),
                Some(clone_project(&project)),
            )
        }
        "nanopublication" => {
            let project = frontier.lock().await;
            (
                tool_nanopublication(args, &project),
                Some(clone_project(&project)),
            )
        }
        "check_pubmed" => (tool_check_pubmed(args, client).await, None),
        "list_events_since" => {
            let project = frontier.lock().await;
            (
                tool_list_events_since(args, &project),
                Some(clone_project(&project)),
            )
        }
        // Phase Q-w (v0.5): write surface — propose-* and decision tools.
        // Each requires a registered actor and a verifying signature
        // over a canonical preimage. Idempotent under Phase P.
        "propose_review" => {
            let result = write_tool_propose(
                args,
                frontier,
                source_path,
                "finding.review",
                |args| {
                    let status = args
                        .get("status")
                        .and_then(Value::as_str)
                        .ok_or("propose_review requires `status`")?;
                    if !matches!(
                        status,
                        "accepted" | "approved" | "contested" | "needs_revision" | "rejected"
                    ) {
                        return Err(format!("invalid review status '{status}'"));
                    }
                    Ok(json!({"status": status}))
                },
                false,
            )
            .await;
            let snapshot = Some(clone_project(&*frontier.lock().await));
            (result, snapshot)
        }
        "propose_note" => {
            let result = write_tool_propose(
                args,
                frontier,
                source_path,
                "finding.note",
                |args| build_note_payload(args, "propose_note"),
                false,
            )
            .await;
            let snapshot = Some(clone_project(&*frontier.lock().await));
            (result, snapshot)
        }
        // Phase α (v0.6): one-call propose-and-apply for `finding.note`.
        // Requires the actor to have `tier="auto-notes"` registered; the
        // `write_tool_propose` helper rejects with a clear error otherwise.
        // Doctrine: tiers permit review-context kinds only; never state-
        // changing kinds (no `propose_and_apply_review`/`_retract`/`_revise`).
        "propose_and_apply_note" => {
            let result = write_tool_propose(
                args,
                frontier,
                source_path,
                "finding.note",
                |args| build_note_payload(args, "propose_and_apply_note"),
                true,
            )
            .await;
            let snapshot = Some(clone_project(&*frontier.lock().await));
            (result, snapshot)
        }
        "propose_revise_confidence" => {
            let result = write_tool_propose(
                args,
                frontier,
                source_path,
                "finding.confidence_revise",
                |args| {
                    let new_score = args
                        .get("new_score")
                        .and_then(Value::as_f64)
                        .ok_or("propose_revise_confidence requires `new_score`")?;
                    if !(0.0..=1.0).contains(&new_score) {
                        return Err(format!("new_score {new_score} out of [0.0, 1.0]"));
                    }
                    Ok(json!({"new_score": new_score}))
                },
                false,
            )
            .await;
            let snapshot = Some(clone_project(&*frontier.lock().await));
            (result, snapshot)
        }
        "propose_retract" => {
            let result = write_tool_propose(
                args,
                frontier,
                source_path,
                "finding.retract",
                |_args| Ok(json!({})),
                false,
            )
            .await;
            let snapshot = Some(clone_project(&*frontier.lock().await));
            (result, snapshot)
        }
        "accept_proposal" => {
            let result = write_tool_decision(args, frontier, source_path, "accept").await;
            let snapshot = Some(clone_project(&*frontier.lock().await));
            (result, snapshot)
        }
        "reject_proposal" => {
            let result = write_tool_decision(args, frontier, source_path, "reject").await;
            let snapshot = Some(clone_project(&*frontier.lock().await));
            (result, snapshot)
        }
        // v0.206: write-side tools for the vela_agent SDK. Both
        // require VELA_AGENT_KEY_HEX (or skip-as-error). Stateless
        // one-shot calls — the agent does its own session bookkeeping
        // and only invokes Vela when ready to submit.
        "vela_agent_submit_diff_pack" => (vela_edge::vela_agent_mcp::submit_diff_pack(args), None),
        "vela_agent_propose_to_hub" => (vela_edge::vela_agent_mcp::propose_to_hub(args), None),
        // v0.214: read-side tools. None require VELA_AGENT_KEY_HEX.
        "vela_agent_get_pack" => (vela_edge::vela_agent_mcp::get_pack(args), None),
        "vela_agent_list_packs" => (vela_edge::vela_agent_mcp::list_packs(args), None),
        "vela_agent_get_attestation" => (vela_edge::vela_agent_mcp::get_attestation(args), None),
        "vela_agent_frontier_summary" => (vela_edge::vela_agent_mcp::frontier_summary(args), None),
        // v0.220: parity read tools.
        "vela_agent_get_tool_descriptor" => {
            (vela_edge::vela_agent_mcp::get_tool_descriptor(args), None)
        }
        "vela_agent_get_evaluation" => (vela_edge::vela_agent_mcp::get_evaluation(args), None),
        "vela_agent_list_evaluations" => (vela_edge::vela_agent_mcp::list_evaluations(args), None),
        "vela_agent_get_conflict" => (vela_edge::vela_agent_mcp::get_conflict(args), None),
        "vela_agent_list_conflicts" => (vela_edge::vela_agent_mcp::list_conflicts(args), None),
        _ => (Err(format!("Unknown tool: {name}")), None),
    }
}

/// Phase β (v0.6): build the `finding.note` proposal payload from
/// caller args. Accepts the required `text` plus an optional structured
/// `provenance` object whose at-least-one-identifier rule is enforced
/// here at the API boundary, so the same validation runs whether the
/// caller is `propose_note` or `propose_and_apply_note`.
fn build_note_payload(args: &Value, tool_name: &str) -> Result<Value, String> {
    let text = args
        .get("text")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{tool_name} requires `text`"))?;
    if text.trim().is_empty() {
        return Err("text must be non-empty".to_string());
    }
    let mut payload = json!({"text": text});
    if let Some(prov) = args.get("provenance") {
        let prov_obj = prov
            .as_object()
            .ok_or("provenance must be a JSON object when present")?;
        let has_id = ["doi", "pmid", "title"].iter().any(|k| {
            prov_obj
                .get(*k)
                .and_then(Value::as_str)
                .is_some_and(|s| !s.trim().is_empty())
        });
        if !has_id {
            return Err("provenance must include at least one of doi/pmid/title".to_string());
        }
        payload["provenance"] = prov.clone();
    }
    Ok(payload)
}

/// Phase Q-w (v0.5) + Phase α (v0.6): shared body for the propose-* write
/// tools. `payload_builder` extracts the kind-specific payload from `args`.
/// `apply_if_tier_permits` (Phase α): when `true`, the function looks up the
/// actor's `tier`, requires `sign::actor_can_auto_apply(actor, kind)` to
/// return `true`, and applies the proposal in one canonical event;
/// otherwise rejects with a clear error. When `false` (the v0.5 default),
/// the proposal stays in `pending_review` regardless of tier.
async fn write_tool_propose<F>(
    args: &Value,
    frontier: &Arc<Mutex<Project>>,
    source_path: Option<&Path>,
    kind: &str,
    payload_builder: F,
    apply_if_tier_permits: bool,
) -> Result<String, String>
where
    F: Fn(&Value) -> Result<Value, String>,
{
    let path = source_path.ok_or_else(|| {
        "Write tools require a single-file frontier (--frontier <PATH>); rejected in --frontiers <DIR> mode".to_string()
    })?;
    let actor_id = args
        .get("actor_id")
        .and_then(Value::as_str)
        .ok_or("write tool requires `actor_id`")?;
    let target_finding_id = args
        .get("target_finding_id")
        .and_then(Value::as_str)
        .ok_or("write tool requires `target_finding_id`")?;
    let reason = args
        .get("reason")
        .and_then(Value::as_str)
        .ok_or("write tool requires `reason`")?;
    let signature_hex = args
        .get("signature")
        .and_then(Value::as_str)
        .ok_or("write tool requires `signature` (Ed25519 over canonical proposal preimage)")?;
    let created_at = args
        .get("created_at")
        .and_then(Value::as_str)
        .map(String::from)
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
    let payload = payload_builder(args)?;

    // Look up the actor's registered pubkey AND tier (Phase α).
    let (pubkey, tier_permits_apply) = {
        let project = frontier.lock().await;
        let actor = project
            .actors
            .iter()
            .find(|actor| actor.id == actor_id)
            .ok_or_else(|| {
                format!(
                    "actor '{actor_id}' is not registered in this frontier; register via `vela actor add` before writing"
                )
            })?;
        let tier_permits = vela_protocol::sign::actor_can_auto_apply(actor, kind);
        // If the caller asked to auto-apply but the actor's tier doesn't
        // permit this kind, reject before signature verification — the
        // capability gate is independent of signing correctness.
        if apply_if_tier_permits && !tier_permits {
            let tier_label = actor.tier.as_deref().unwrap_or("none");
            return Err(format!(
                "actor '{actor_id}' tier '{tier_label}' does not permit auto-apply for {kind}"
            ));
        }
        (actor.public_key.clone(), tier_permits)
    };

    // Build the proposal exactly as the CLI would, then verify the signature
    // against the registered pubkey before persisting.
    let mut proposal = vela_protocol::proposals::new_proposal(
        kind,
        vela_protocol::events::StateTarget {
            r#type: "finding".to_string(),
            id: target_finding_id.to_string(),
        },
        actor_id,
        "human",
        reason,
        payload,
        Vec::new(),
        Vec::new(),
    );
    proposal.created_at = created_at;
    proposal.id = vela_protocol::proposals::proposal_id(&proposal);

    let valid = vela_protocol::sign::verify_proposal_signature(&proposal, signature_hex, &pubkey)?;
    if !valid {
        return Err(format!(
            "Signature does not verify for actor '{actor_id}' on this proposal"
        ));
    }

    // Persist. Phase α: apply iff caller asked AND tier permits (already
    // enforced above). Phase P guarantees `create_or_apply` is idempotent
    // either way.
    let apply = apply_if_tier_permits && tier_permits_apply;
    let result = vela_protocol::proposals::create_or_apply(path, proposal, apply)
        .map_err(|e| format!("create_or_apply failed: {e}"))?;

    // Refresh the in-memory state from disk so subsequent reads see the write.
    let fresh = vela_protocol::repo::load_from_path(path)
        .map_err(|e| format!("reload after write failed: {e}"))?;
    let mut project = frontier.lock().await;
    *project = fresh;

    serde_json::to_string(&json!({
        "proposal_id": result.proposal_id,
        "finding_id": result.finding_id,
        "status": result.status,
        "applied_event_id": result.applied_event_id,
    }))
    .map_err(|e| format!("serialize write result: {e}"))
}

/// Phase Q-w (v0.5): shared body for `accept_proposal` and `reject_proposal`.
/// The signing preimage is `{action, proposal_id, reviewer_id, reason, timestamp}`
/// canonicalized; the reviewer must be a registered actor.
async fn write_tool_decision(
    args: &Value,
    frontier: &Arc<Mutex<Project>>,
    source_path: Option<&Path>,
    action: &str,
) -> Result<String, String> {
    let path = source_path.ok_or_else(|| {
        "Write tools require a single-file frontier (--frontier <PATH>); rejected in --frontiers <DIR> mode".to_string()
    })?;
    let proposal_id = args
        .get("proposal_id")
        .and_then(Value::as_str)
        .ok_or("decision tool requires `proposal_id`")?;
    let reviewer_id = args
        .get("reviewer_id")
        .and_then(Value::as_str)
        .ok_or("decision tool requires `reviewer_id`")?;
    let reason = args
        .get("reason")
        .and_then(Value::as_str)
        .ok_or("decision tool requires `reason`")?;
    let signature_hex = args
        .get("signature")
        .and_then(Value::as_str)
        .ok_or("decision tool requires `signature`")?;
    let timestamp = args
        .get("timestamp")
        .and_then(Value::as_str)
        .map(String::from)
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());

    // Canonical preimage for the decision action.
    let preimage = json!({
        "action": action,
        "proposal_id": proposal_id,
        "reviewer_id": reviewer_id,
        "reason": reason,
        "timestamp": timestamp,
    });
    let signing_bytes = vela_protocol::canonical::to_canonical_bytes(&preimage)?;

    // Look up the reviewer's registered pubkey.
    let pubkey = {
        let project = frontier.lock().await;
        project
            .actors
            .iter()
            .find(|actor| actor.id == reviewer_id)
            .map(|actor| actor.public_key.clone())
            .ok_or_else(|| format!("reviewer '{reviewer_id}' is not registered"))?
    };

    let valid =
        vela_protocol::sign::verify_action_signature(&signing_bytes, signature_hex, &pubkey)?;
    if !valid {
        return Err(format!(
            "Signature does not verify for reviewer '{reviewer_id}' on {action} of {proposal_id}"
        ));
    }

    let outcome = match action {
        "accept" => {
            let event_id =
                vela_protocol::proposals::accept_at_path(path, proposal_id, reviewer_id, reason)
                    .map_err(|e| format!("accept failed: {e}"))?;
            json!({
                "proposal_id": proposal_id,
                "applied_event_id": event_id,
                "status": "applied",
            })
        }
        "reject" => {
            vela_protocol::proposals::reject_at_path(path, proposal_id, reviewer_id, reason)
                .map_err(|e| format!("reject failed: {e}"))?;
            json!({
                "proposal_id": proposal_id,
                "applied_event_id": Value::Null,
                "status": "rejected",
            })
        }
        other => return Err(format!("unsupported decision action '{other}'")),
    };

    // Refresh in-memory state.
    let fresh = vela_protocol::repo::load_from_path(path)
        .map_err(|e| format!("reload after write failed: {e}"))?;
    let mut project = frontier.lock().await;
    *project = fresh;

    serde_json::to_string(&outcome).map_err(|e| format!("serialize decision: {e}"))
}

/// Phase Q-r (v0.5): MCP-tool form of the cursor-paginated event read.
/// Mirrors `GET /api/events`. Same cursor semantics: events strictly
/// after `cursor` (a `vev_…` id), or from genesis if cursor is omitted.
fn tool_list_events_since(args: &Value, project: &Project) -> Result<String, String> {
    let cursor = args.get("cursor").and_then(Value::as_str);
    let limit = args
        .get("limit")
        .and_then(Value::as_u64)
        .map_or(100usize, |n| (n as usize).min(500));
    let start_idx: usize = match cursor {
        None => 0,
        Some(c) => match project.events.iter().position(|event| event.id == c) {
            Some(idx) => idx + 1,
            None => {
                return Err(format!(
                    "cursor '{c}' not found in event log; client is out of sync"
                ));
            }
        },
    };
    let end_idx = (start_idx + limit).min(project.events.len());
    let slice = &project.events[start_idx..end_idx];
    let next_cursor = if end_idx < project.events.len() {
        slice.last().map(|event| event.id.clone())
    } else {
        None
    };
    let payload = json!({
        "events": slice,
        "count": slice.len(),
        "next_cursor": next_cursor,
        "log_total": project.events.len(),
    });
    serde_json::to_string(&payload).map_err(|e| format!("serialize list_events_since: {e}"))
}

fn check_tool_result(
    name: &str,
    result: Result<String, String>,
    started: std::time::Instant,
) -> Value {
    let output = ToolResult::from_text(
        name,
        result.unwrap_or_else(|e| e),
        started.elapsed().as_millis(),
        false,
        None,
    );
    let has_data = !output.data.is_null();
    let has_markdown = !output.markdown.trim().is_empty();
    let has_signals = true;
    let has_caveats = true;
    json!({
        "tool": name,
        "ok": has_data && has_markdown && has_signals && has_caveats,
        "data": output.data,
        "markdown": output.markdown,
        "has_data": has_data,
        "has_markdown": has_markdown,
        "has_signals": has_signals,
        "has_caveats": has_caveats,
        "signals": output.signals,
        "caveats": output.caveats,
        "duration_ms": output.duration_ms,
    })
}

/// Phase Q-r (v0.5): cursor-paginated read over the canonical event log.
///
/// Query params:
///   - `since` (optional): a `vev_…` event id; events strictly after this id
///     are returned. Omit to start from the genesis event.
///   - `limit` (optional, default 100, max 500): cap the response size.
///
/// Returns `{events: [...], next_cursor: "vev_..." | null, count: usize}`.
/// `next_cursor` is null when the response includes the tail of the log.
///
/// 400 if `since` is provided but does not exist in the log (the client is
/// out of sync with the log it's reading; better to fail loudly than to
/// silently skip).
async fn http_events(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    let project = state.project.lock().await;
    let limit = params
        .get("limit")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(100)
        .min(500);
    let start_idx: usize = match params.get("since") {
        None => 0,
        Some(cursor) => match project.events.iter().position(|event| &event.id == cursor) {
            Some(idx) => idx + 1,
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": format!(
                            "cursor '{cursor}' not found in event log; client is out of sync"
                        ),
                    })),
                );
            }
        },
    };
    // v0.17: server-side `?kind=` and `?target=` filters. Agents watching
    // for specific event kinds (e.g. polling for new finding.superseded
    // events) shouldn't need to fetch the whole log to locate one match.
    // Filters apply BEFORE the limit/cursor so pagination works on the
    // filtered view.
    let kind_filter = params.get("kind").map(String::as_str);
    let target_filter = params.get("target").map(String::as_str);
    let filtered: Vec<&vela_protocol::events::StateEvent> = project
        .events
        .iter()
        .skip(start_idx)
        .filter(|e| kind_filter.is_none_or(|k| e.kind == k))
        .filter(|e| target_filter.is_none_or(|t| e.target.id == t))
        .collect();
    let total_filtered = filtered.len();
    let take_n = limit.min(total_filtered);
    let slice: Vec<&vela_protocol::events::StateEvent> =
        filtered.into_iter().take(take_n).collect();
    let next_cursor = if take_n < total_filtered {
        slice.last().map(|event| event.id.clone())
    } else {
        None
    };
    (
        StatusCode::OK,
        Json(json!({
            "events": slice,
            "count": slice.len(),
            "next_cursor": next_cursor,
            "log_total": project.events.len(),
            "filtered_total": total_filtered,
        })),
    )
}

/// Phase R (v0.5): append a draft Workbench action to the local queue.
/// The browser POSTs `{kind, args}` (no signature, no actor key — the
/// browser is identity-blind under the v0.5 doctrine). The Workbench
/// host process appends to the configured queue file; `vela queue sign`
/// is the only path that produces a signed write.
///
/// Body:
///   `{"kind": "<tool_name>", "args": { ... }}`
///
/// Returns `{ok: true, queued_at: "<rfc3339>"}` on success.
async fn http_queue_append(
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let path = match &state.source_path {
        Some(p) => p.clone(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(
                    json!({"error": "The draft queue requires a single-file frontier (--frontier <PATH>)"}),
                ),
            );
        }
    };
    let kind = match body.get("kind").and_then(Value::as_str) {
        Some(k) => k.to_string(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "POST /api/queue requires `kind`"})),
            );
        }
    };
    let valid_kinds = [
        "propose_review",
        "propose_note",
        "propose_revise_confidence",
        "propose_retract",
        "accept_proposal",
        "reject_proposal",
    ];
    if !valid_kinds.contains(&kind.as_str()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("unsupported queue kind '{kind}'")})),
        );
    }
    let args = body.get("args").cloned().unwrap_or(Value::Null);
    let queued_at = chrono::Utc::now().to_rfc3339();
    let action = vela_edge::queue::QueuedAction {
        kind,
        frontier: path,
        args,
        queued_at: queued_at.clone(),
    };
    let queue_path = vela_edge::queue::default_queue_path();
    if let Err(error) = vela_edge::queue::append(&queue_path, action) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("append to queue: {error}")})),
        );
    }
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "queue_file": queue_path.display().to_string(),
            "queued_at": queued_at,
            "next_step": "run `vela queue sign` to apply queued drafts",
        })),
    )
}

/// v0.92: agent write target.
///
/// POST a Carina `ArtifactPacket` JSON. The substrate validates it,
/// imports it as proposals via `artifact_to_state::import_packet_at_path`,
/// reloads the in-memory project so subsequent reads see the new
/// proposals, and returns the new `vpr_*` ids plus the full report.
///
/// Optional query params:
/// - `actor`: actor id to attribute the import to (defaults to
///   `agent:carina-write-target`).
/// - `apply_artifacts`: if `true`, applies the Carina artifacts as
///   accepted-state events instead of pending proposals. Default `false`.
async fn http_from_carina(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let path = match &state.source_path {
        Some(p) => p.clone(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "agent write target requires a single-file or single-repo frontier (`vela serve <path> --http <port>`)"
                })),
            );
        }
    };
    let actor = params
        .get("actor")
        .cloned()
        .unwrap_or_else(|| "agent:carina-write-target".to_string());
    let apply_artifacts = params
        .get("apply_artifacts")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    // Validate the body against the ArtifactPacket schema before
    // touching disk. Decoupling validation from filesystem write
    // means a malformed packet returns 400 cheaply.
    let packet: vela_edge::artifact_to_state::ArtifactPacket =
        match serde_json::from_value(body.clone()) {
            Ok(p) => p,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": format!("packet parse: {e}")})),
                );
            }
        };
    let packet = match packet.validate() {
        Ok(p) => p,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("packet validate: {e}")})),
            );
        }
    };

    // Write the validated packet to a temp file, since the existing
    // `import_packet_at_path` takes a path. Future cleanup: a
    // direct in-memory variant that skips this hop.
    let tmp = match tempfile::NamedTempFile::new() {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("tempfile: {e}")})),
            );
        }
    };
    let canonical = match serde_json::to_vec_pretty(&packet) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("re-serialize: {e}")})),
            );
        }
    };
    if let Err(e) = std::fs::write(tmp.path(), &canonical) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("write tempfile: {e}")})),
        );
    }

    // Drop the project lock around the import call so the import's
    // own loads/writes don't deadlock against ongoing reads.
    drop(state.project.lock().await);
    let report = match vela_edge::artifact_to_state::import_packet_at_path(
        &path,
        tmp.path(),
        &actor,
        apply_artifacts,
    ) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("import: {e}")})),
            );
        }
    };

    // Reload the project so later GET /api/findings, GET /api/findings/{id},
    // etc. see the new proposals.
    let mut reloaded = match vela_protocol::repo::load_from_path(&path) {
        Ok(p) => p,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("reload after import: {e}")})),
            );
        }
    };
    vela_protocol::sources::materialize_project(&mut reloaded);
    {
        let mut guard = state.project.lock().await;
        *guard = reloaded;
    }

    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "actor": actor,
            "apply_artifacts": apply_artifacts,
            "report": report,
        })),
    )
}

/// v0.51: Resolve the requesting actor's read-side access clearance
/// from the `X-Vela-Actor` request header. The header value, if
/// present, is matched against `Project.actors` by id; the actor's
/// `access_clearance` field is returned. Anonymous reads (header
/// absent) get `None`, which equals "public-only" per
/// `access_tier::actor_may_read`.
///
/// This is a deliberately thin authentication surface for v0.51 —
/// the assumption is that a real deployment terminates TLS and
/// validates actor signatures at a reverse proxy in front of `vela
/// serve`, then forwards `X-Vela-Actor` only when verified. v0.52+
/// can tighten this to require a signed bearer token end-to-end.
fn requesting_clearance(
    headers: &HeaderMap,
    project: &Project,
) -> Option<vela_protocol::access_tier::AccessTier> {
    let actor_id = headers
        .get("x-vela-actor")
        .and_then(|v| v.to_str().ok())?
        .trim();
    if actor_id.is_empty() {
        return None;
    }
    let actor = project.actors.iter().find(|a| a.id == actor_id)?;
    actor.access_clearance
}

async fn http_frontier(State(state): State<AppState>, headers: HeaderMap) -> Json<Value> {
    let project = state.project.lock().await;
    let clearance = requesting_clearance(&headers, &project);
    let view = vela_protocol::access_tier::redact_for_actor(&project, clearance);
    Json(serde_json::to_value(&view).unwrap_or_else(|_| json!({"error": "serialization failed"})))
}

async fn http_findings(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
) -> Json<Value> {
    let project = state.project.lock().await;
    let clearance = requesting_clearance(&headers, &project);
    let view = vela_protocol::access_tier::redact_for_actor(&project, clearance);

    // v0.91: When no search-style filter is supplied, return a
    // structured `{findings, count}` list rather than the search
    // tool's text-shaped result. The previous behavior was
    // surprising for API consumers expecting a REST-style list
    // and forced them to scrape free-text. Search filters
    // (`query`, `entity`, `entity_type`, `type`) preserve the
    // existing search-tool behavior for callers that depend on it.
    let has_search = params.contains_key("query")
        || params.contains_key("entity")
        || params.contains_key("entity_type")
        || params.contains_key("type");
    if !has_search {
        let limit = params
            .get("limit")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(view.findings.len());
        let findings: Vec<Value> = view
            .findings
            .iter()
            .take(limit)
            .map(|f| serde_json::to_value(f).unwrap_or_default())
            .collect();
        return Json(json!({
            "count": view.findings.len(),
            "returned": findings.len(),
            "findings": findings,
        }));
    }

    let args = json!({
        "query": params.get("query"),
        "entity": params.get("entity"),
        "entity_type": params.get("entity_type"),
        "assertion_type": params.get("type"),
        "limit": params.get("limit").and_then(|v| v.parse::<u64>().ok()).unwrap_or(50),
    });
    match tool_search_findings(&args, &view) {
        Ok(text) => Json(json!({"result": text})),
        Err(error) => Json(json!({"error": error})),
    }
}

async fn http_finding_by_id(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> (StatusCode, Json<Value>) {
    let project = state.project.lock().await;
    let clearance = requesting_clearance(&headers, &project);
    match project
        .findings
        .iter()
        .find(|finding| finding.id == id || finding.id.starts_with(&id))
    {
        Some(finding) => {
            if !vela_protocol::access_tier::actor_may_read(finding.access_tier, clearance) {
                // v0.51: above-clearance findings 404 — the existence
                // of the object is itself part of the tiered content.
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"error": format!("Finding not found: {id}")})),
                );
            }
            // v0.85: surface the substrate-derived Belnap status
            // alongside the on-disk finding. Computed read-only
            // from the event log via `provenance_compute`. The
            // existing finding fields remain authoritative; this
            // is a derived view per docs/THEORY.md Section 7.
            let sp =
                vela_edge::provenance_compute::status_provenance_for_finding(&project, &finding.id);
            let belnap = sp.derive_status();
            // v0.87: surface the substrate-derived discord set per
            // docs/THEORY.md Section 4. Detectors run read-only
            // against the live Project state; results are advisory.
            let discord =
                vela_edge::discord_compute::compute_discord_for_finding(&project, &finding.id);
            let discord_kinds: Vec<String> =
                discord.iter().map(|k| k.as_str().to_string()).collect();
            let mut value = serde_json::to_value(finding).unwrap_or_default();
            if let Some(map) = value.as_object_mut() {
                map.insert(
                    "belnap_status".to_string(),
                    serde_json::to_value(belnap).unwrap_or_default(),
                );
                map.insert(
                    "belnap_letter".to_string(),
                    json!(belnap.letter().to_string()),
                );
                map.insert(
                    "support_term_count".to_string(),
                    json!(sp.support.term_count()),
                );
                map.insert(
                    "refute_term_count".to_string(),
                    json!(sp.refute.term_count()),
                );
                map.insert("discord_kinds".to_string(), json!(discord_kinds));
                map.insert("discord_count".to_string(), json!(discord.len()));
                // v0.88: surface the actual provenance-polynomial
                // structure per docs/THEORY.md §2.2. The serde-
                // friendly form is `[{monomial, coefficient}]`,
                // suitable for audit trails and downstream tooling
                // that needs to know which events derive support.
                map.insert(
                    "support_polynomial".to_string(),
                    serde_json::to_value(&sp.support).unwrap_or_default(),
                );
                map.insert(
                    "refute_polynomial".to_string(),
                    serde_json::to_value(&sp.refute).unwrap_or_default(),
                );
                // Display strings render polynomials in standard
                // additive form: `2*p1*d3 + r7*e2`. Suitable for
                // debug surfaces and Workbench tooltips.
                map.insert(
                    "support_polynomial_display".to_string(),
                    json!(format!("{}", sp.support)),
                );
                map.insert(
                    "refute_polynomial_display".to_string(),
                    json!(format!("{}", sp.refute)),
                );
            }
            (StatusCode::OK, Json(value))
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": format!("Finding not found: {id}")})),
        ),
    }
}

async fn http_contradictions(State(state): State<AppState>) -> Json<Value> {
    let project = state.project.lock().await;
    Json(
        serde_json::from_str(&tool_list_contradictions(&project).unwrap_or_default())
            .unwrap_or_else(
                |_| json!({"result": tool_list_contradictions(&project).unwrap_or_default()}),
            ),
    )
}

/// v0.97: HTTP mirror of `vela discord`. Returns the frontier-wide
/// discord assignment computed read-only against live Project state
/// per docs/THEORY.md §4. Body shape matches the CLI's --json output.
///
/// Query params:
/// - `kind`: optional filter to a single discord kind (e.g.
///   `provenance_fragile`, `evidence_gap`, `status_divergent`).
async fn http_discord(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
) -> Json<Value> {
    use vela_edge::discord::DiscordKind;
    use vela_edge::discord_compute::compute_discord_assignment;

    let project = state.project.lock().await;
    let assignment = compute_discord_assignment(&project);
    let support = assignment.frontier_support();
    let filter = params.get("kind").cloned();

    let mut rows: Vec<Value> = Vec::new();
    for context in support.iter() {
        let set = assignment.get(context);
        let kinds: Vec<String> = set.iter().map(|k| k.as_str().to_string()).collect();
        if let Some(f) = &filter
            && !kinds.iter().any(|k| k == f)
        {
            continue;
        }
        rows.push(json!({
            "finding_id": context,
            "discord_kinds": kinds,
        }));
    }

    let mut histogram = serde_json::Map::new();
    for kind in DiscordKind::ALL {
        let count = assignment
            .iter()
            .filter(|(_, set)| set.contains(*kind))
            .count();
        if count > 0 {
            histogram.insert(kind.as_str().to_string(), json!(count));
        }
    }

    let frontier_id = project
        .frontier_id
        .clone()
        .unwrap_or_else(|| String::from("<unknown>"));

    Json(json!({
        "frontier_id": frontier_id,
        "total_findings": project.findings.len(),
        "frontier_support_size": support.len(),
        "filtered_row_count": rows.len(),
        "filter_kind": filter,
        "histogram": Value::Object(histogram),
        "rows": rows,
    }))
}

async fn http_health(State(state): State<AppState>) -> Json<Value> {
    let project = state.project.lock().await;
    Json(json!({
        "ok": true,
        "frontier": {
            "name": project.project.name,
            "findings": project.stats.findings,
            "events": project.events.len(),
        }
    }))
}

async fn http_artifacts(State(state): State<AppState>) -> Json<Value> {
    let project = state.project.lock().await;
    Json(json!({
        "ok": true,
        "count": project.artifacts.len(),
        "artifacts": project.artifacts,
    }))
}

async fn http_artifact_audit(State(state): State<AppState>) -> Json<Value> {
    let source_path = state.source_path.clone();
    let project = state.project.lock().await;
    let Some(path) = source_path else {
        return Json(json!({
            "ok": false,
            "available": false,
            "issues": [],
            "error": "artifact audit requires a single frontier source",
        }));
    };
    Json(
        serde_json::to_value(vela_edge::artifact_audit::audit_artifacts(&path, &project))
            .unwrap_or_else(|_| json!({"ok": false, "error": "serialization failed"})),
    )
}

async fn http_proof(State(state): State<AppState>) -> Json<Value> {
    let project = state.project.lock().await;
    let integrity = vela_edge::state_integrity::analyze(&project);
    let signal_report = signals::analyze(&project, &[]);
    let latest = &project.proof_state.latest_packet;
    Json(json!({
        "ok": true,
        "schema": "vela.http_proof_status.v0.1",
        "frontier_id": project.frontier_id(),
        "proof_state": project.proof_state,
        "latest_packet": latest,
        "freshness": integrity.proof_freshness,
        "current_snapshot_hash": events::snapshot_hash(&project),
        "current_event_log_hash": events::event_log_hash(&project.events),
        "readiness": {
            "status": signal_report.proof_readiness.status,
            "blockers": signal_report.proof_readiness.blockers,
            "warnings": signal_report.proof_readiness.warnings,
        },
        "boundary": "Proof verifies replay and hashes. It does not prove clinical actionability.",
    }))
}

async fn http_gaps(State(state): State<AppState>) -> Json<Value> {
    let project = state.project.lock().await;
    let gaps = project
        .findings
        .iter()
        .filter(|finding| finding.flags.gap || finding.flags.negative_space)
        .map(|finding| {
            json!({
                "id": finding.id,
                "assertion": finding.assertion.text,
                "confidence": finding.confidence.score,
                "conditions": finding.conditions.text,
                "source": finding.provenance.title,
            })
        })
        .collect::<Vec<_>>();
    Json(json!({
        "ok": true,
        "count": gaps.len(),
        "gaps": gaps,
        "caveats": ["Candidate gap rankings are review leads, not confirmed experiment targets."],
    }))
}

async fn http_tensions(State(state): State<AppState>) -> Json<Value> {
    let project = state.project.lock().await;
    let lookup = project
        .findings
        .iter()
        .map(|finding| (finding.id.as_str(), finding))
        .collect::<HashMap<_, _>>();
    let mut tensions = Vec::new();
    for finding in &project.findings {
        for link in &finding.links {
            if link.link_type != "contradicts" {
                continue;
            }
            // Cross-frontier resolution, consistent with the graph
            // tools: resolve `vf_X@vfr_Y` to the bare `vf_X` node when
            // present (as under `serve --frontiers`).
            let bare = vela_protocol::bundle::bare_finding_id(&link.target);
            let target = lookup
                .get(link.target.as_str())
                .or_else(|| lookup.get(bare));
            tensions.push(json!({
                "source": {
                    "id": finding.id,
                    "assertion": finding.assertion.text,
                    "confidence": finding.confidence.score,
                },
                "target": target.map(|target| json!({
                    "id": target.id,
                    "assertion": target.assertion.text,
                    "confidence": target.confidence.score,
                })),
                "type": link.link_type,
                "note": link.note,
                "resolved": finding.flags.retracted || target.is_some_and(|target| target.flags.retracted),
            }));
        }
    }
    Json(json!({
        "ok": true,
        "count": tensions.len(),
        "tensions": tensions,
        "caveats": ["Candidate tensions are review surfaces, not definitive contradictions."],
    }))
}

async fn http_observer(
    State(state): State<AppState>,
    axum::extract::Path(policy): axum::extract::Path<String>,
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
) -> Json<Value> {
    let project = state.project.lock().await;
    let args = json!({
        "policy": policy,
        "limit": params.get("limit").and_then(|v| v.parse::<u64>().ok()).unwrap_or(20),
    });
    match tool_apply_observer(&args, &project) {
        Ok(text) => Json(serde_json::from_str(&text).unwrap_or_else(|_| json!({"result": text}))),
        Err(error) => Json(json!({"error": error})),
    }
}

async fn http_propagate(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Json<Value> {
    let project = state.project.lock().await;
    let args = json!({"finding_id": id});
    match tool_propagate_retraction(&args, &project) {
        Ok(text) => Json(serde_json::from_str(&text).unwrap_or_else(|_| json!({"result": text}))),
        Err(error) => Json(json!({"error": error})),
    }
}

async fn http_stats(State(state): State<AppState>) -> Json<Value> {
    let project = state.project.lock().await;
    Json(json!({
        "frontier": {
            "name": project.project.name,
            "compiled_at": project.project.compiled_at,
            "compiler": project.project.compiler,
        },
        "stats": project.stats,
        "signals": signals::analyze(&project, &[]).signals,
    }))
}

async fn http_frontiers(State(state): State<AppState>) -> Json<Value> {
    Json(
        serde_json::from_str(&frontier_index_json(&state.project_infos).unwrap_or_default())
            .unwrap_or_else(|_| json!({"frontier_count": 0, "frontiers": []})),
    )
}

async fn http_pubmed(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
) -> Json<Value> {
    let args = json!({"query": params.get("query").cloned().unwrap_or_default()});
    match tool_check_pubmed(&args, &state.client).await {
        Ok(text) => Json(serde_json::from_str(&text).unwrap_or_else(|_| json!({"result": text}))),
        Err(error) => Json(json!({"error": error})),
    }
}

async fn http_tools_list(State(state): State<AppState>) -> Json<Value> {
    Json(tool_registry::mcp_tools_json_for_profile(state.profile))
}

async fn http_tool_call(
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let name = body["name"].as_str().unwrap_or_default();
    let args = &body["arguments"];
    // MCP profile gate (memo §9.4): refuse tools outside the active profile.
    if let Some(tool) = tool_registry::get_tool(name)
        && !state.profile.allows(&tool)
    {
        let needed = if tool_registry::McpProfile::Draft.allows(&tool) {
            "draft"
        } else {
            "maintainer"
        };
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": format!(
                    "tool `{name}` ({}) is not available in the `{}` MCP profile; serve with `--profile {needed}`. MCP exposes tools; accepted public state still requires a key-custody human accept.",
                    tool.permission_level, state.profile.as_str()
                ),
            })),
        );
    }
    let started = std::time::Instant::now();
    let (result, snapshot) = execute_tool(
        name,
        args,
        &state.project,
        &state.client,
        &state.project_infos,
        state.source_path.as_deref(),
    )
    .await;
    match result {
        Ok(text) => {
            let output = ToolResult::from_text(
                name,
                text,
                started.elapsed().as_millis(),
                false,
                snapshot.as_ref(),
            );
            (
                StatusCode::OK,
                Json(json!({
                    "result": output.markdown,
                    "tool": output.tool,
                    "ok": output.ok,
                    "data": output.data,
                    "markdown": output.markdown,
                    "signals": output.signals,
                    "caveats": output.caveats,
                    "duration_ms": output.duration_ms,
                    "metadata": output.metadata(),
                })),
            )
        }
        Err(error) => {
            let output = ToolResult::from_text(
                name,
                error,
                started.elapsed().as_millis(),
                true,
                snapshot.as_ref(),
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": output.markdown,
                    "tool": output.tool,
                    "ok": output.ok,
                    "data": output.data,
                    "markdown": output.markdown,
                    "signals": output.signals,
                    "caveats": output.caveats,
                    "duration_ms": output.duration_ms,
                    "metadata": output.metadata(),
                })),
            )
        }
    }
}

fn tool_search_findings(args: &Value, frontier: &Project) -> Result<String, String> {
    let query = args["query"].as_str().map(str::to_lowercase);
    let entity = args["entity"].as_str().map(str::to_lowercase);
    let entity_type = args["entity_type"].as_str().map(str::to_lowercase);
    let assertion_type = args["assertion_type"].as_str().map(str::to_lowercase);
    let limit = args["limit"].as_u64().unwrap_or(20) as usize;
    let results = frontier
        .findings
        .iter()
        .filter(|finding| {
            query.as_ref().is_none_or(|q| {
                finding.assertion.text.to_lowercase().contains(q)
                    || finding.conditions.text.to_lowercase().contains(q)
                    || finding
                        .assertion
                        .entities
                        .iter()
                        .any(|e| e.name.to_lowercase().contains(q))
            }) && entity.as_ref().is_none_or(|needle| {
                finding
                    .assertion
                    .entities
                    .iter()
                    .any(|e| e.name.to_lowercase().contains(needle))
            }) && entity_type.as_ref().is_none_or(|needle| {
                finding
                    .assertion
                    .entities
                    .iter()
                    .any(|e| e.entity_type.to_lowercase() == *needle)
            }) && assertion_type
                .as_ref()
                .is_none_or(|needle| finding.assertion.assertion_type.to_lowercase() == *needle)
        })
        .take(limit)
        .collect::<Vec<_>>();

    if results.is_empty() {
        return Ok("No findings matched the search criteria.".to_string());
    }
    let mut out = format!("{} findings matched:\n\n", results.len());
    for finding in results {
        let entities = finding
            .assertion
            .entities
            .iter()
            .map(|e| format!("{} ({})", e.name, e.entity_type))
            .collect::<Vec<_>>();
        out.push_str(&format!(
            "**{}** [conf: {}, type: {}]\n{}\nEntities: {}\nReplicated: {} | Gap: {} | Contested: {}\nSource: {} ({})\n\n",
            finding.id,
            finding.confidence.score,
            finding.assertion.assertion_type,
            finding.assertion.text,
            entities.join(", "),
            finding.evidence.replicated,
            finding.flags.gap,
            finding.flags.contested,
            finding.provenance.title,
            finding.provenance.year.map(|y| y.to_string()).unwrap_or_else(|| "?".to_string()),
        ));
    }
    Ok(out)
}

fn tool_get_finding(args: &Value, frontier: &Project) -> Result<String, String> {
    let id = args["id"].as_str().ok_or("Missing 'id' argument")?;
    let finding = frontier
        .findings
        .iter()
        .find(|finding| finding.id == id || finding.id.starts_with(id))
        .ok_or_else(|| format!("Finding '{id}' not found"))?;
    let mut context = state::finding_context(frontier, &finding.id)?;
    if let Value::Object(map) = &mut context {
        map.insert(
            "caveats".to_string(),
            json!([
            "Finding-local events are canonical state transitions; review_events are projection artifacts.",
            "Sources identify artifacts; evidence atoms identify source-grounded units that bear on the finding."
            ]),
        );
    }
    serde_json::to_string_pretty(&context).map_err(|e| format!("Serialization error: {e}"))
}

/// v0.17: chronological event log for one finding. The full canonical event
/// log filtered to events whose `target.id` matches the requested finding,
/// sorted ascending by timestamp. Useful for agents walking the supersedes
/// chain or auditing corrections.
fn tool_get_finding_history(args: &Value, frontier: &Project) -> Result<String, String> {
    let id = args["id"].as_str().ok_or("Missing 'id' argument")?;
    let mut events: Vec<&vela_protocol::events::StateEvent> = frontier
        .events
        .iter()
        .filter(|e| {
            e.target.r#type == "finding" && (e.target.id == id || e.target.id.starts_with(id))
        })
        .collect();
    events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
    let payload = json!({
        "finding_id": id,
        "event_count": events.len(),
        "events": events,
        "caveats": [
            "Events are the canonical state-transition log; events without a 'finding' target are excluded.",
            "Use payload.new_finding_id on finding.superseded events to walk forward in the supersedes chain."
        ],
    });
    serde_json::to_string_pretty(&payload).map_err(|e| format!("Serialization error: {e}"))
}

fn tool_list_gaps(frontier: &Project) -> Result<String, String> {
    let gaps = frontier
        .findings
        .iter()
        .filter(|finding| finding.flags.gap)
        .collect::<Vec<_>>();
    if gaps.is_empty() {
        return Ok("No gap-flagged findings in this frontier.".to_string());
    }
    let mut out = format!(
        "{} candidate gap review leads:\nTreat these as navigation signals, not confirmed experiment targets.\n\n",
        gaps.len()
    );
    for finding in gaps {
        out.push_str(&format!(
            "**{}** [conf: {}]\n{}\nConditions: {}\n\n",
            finding.id, finding.confidence.score, finding.assertion.text, finding.conditions.text
        ));
    }
    Ok(out)
}

fn tool_list_contradictions(frontier: &Project) -> Result<String, String> {
    let lookup = frontier
        .findings
        .iter()
        .map(|finding| (finding.id.as_str(), finding))
        .collect::<HashMap<_, _>>();
    let mut contradictions = Vec::new();
    for finding in &frontier.findings {
        for link in &finding.links {
            if matches!(link.link_type.as_str(), "contradicts" | "disputes") {
                let target = lookup
                    .get(link.target.as_str())
                    .map(|f| f.assertion.text.as_str())
                    .unwrap_or("(unknown target)");
                contradictions.push(format!(
                    "**{}** {} **{}**\n  {} --[{}]--> {}\n  Note: {}\n",
                    finding.id,
                    link.link_type,
                    link.target,
                    trunc(&finding.assertion.text, 80),
                    link.link_type,
                    trunc(target, 80),
                    link.note,
                ));
            }
        }
    }
    if contradictions.is_empty() {
        return Ok("No candidate contradiction links in this frontier.".to_string());
    }
    Ok(format!(
        "{} candidate contradiction links:\n\n{}",
        contradictions.len(),
        contradictions.join("\n")
    ))
}

fn tool_frontier_stats(frontier: &Project) -> Result<String, String> {
    serde_json::to_string_pretty(&json!({
        "frontier": {
            "name": frontier.project.name,
            "description": frontier.project.description,
            "compiled_at": frontier.project.compiled_at,
            "compiler": frontier.project.compiler,
            "papers_processed": frontier.project.papers_processed,
            "errors": frontier.project.errors,
        },
        "stats": frontier.stats,
        "source_registry": sources::source_summary(frontier),
        "evidence_atoms": sources::evidence_summary(frontier),
        "conditions": sources::condition_summary(frontier),
        "proposals": vela_protocol::proposals::summary(frontier),
        "proof_state": frontier.proof_state,
        "events": {
            "count": frontier.events.len(),
            "summary": events::summarize(frontier),
            "replay": events::replay_report(frontier),
        },
        "signals": signals::analyze(frontier, &[]).signals,
    }))
    .map_err(|e| format!("Serialization error: {e}"))
}

fn tool_propagate_retraction(args: &Value, frontier: &Project) -> Result<String, String> {
    let id = args["finding_id"]
        .as_str()
        .ok_or("Missing 'finding_id' argument")?;
    let target = frontier
        .findings
        .iter()
        .find(|finding| finding.id == id || finding.id.starts_with(id))
        .ok_or_else(|| format!("Finding '{id}' not found"))?;

    // v0.49.3: O(1) reverse-dep lookup via the denormalized index
    // instead of the prior O(N×L) scan over every finding × every
    // link. The index is built once per request — at this frontier's
    // size it costs microseconds; at 100K findings it stays under a
    // second. Filter on link_type after the lookup so "supports" /
    // "depends" semantics are preserved.
    let reverse_idx = frontier.build_reverse_dep_index();
    let dependent_ids = reverse_idx.dependents_of(&target.id);
    let id_to_finding: std::collections::HashMap<&str, &vela_protocol::bundle::FindingBundle> =
        frontier
            .findings
            .iter()
            .map(|f| (f.id.as_str(), f))
            .collect();

    let mut affected = Vec::new();
    for dep_id in dependent_ids {
        let Some(dependent) = id_to_finding.get(dep_id.as_str()) else {
            continue;
        };
        for link in &dependent.links {
            if matches!(link.link_type.as_str(), "supports" | "depends") && link.target == target.id
            {
                affected.push(json!({
                    "id": dependent.id,
                    "assertion": trunc(&dependent.assertion.text, 100),
                    "link_type": link.link_type,
                }));
            }
        }
    }
    serde_json::to_string_pretty(&json!({
        "retracted": {"id": target.id, "assertion": trunc(&target.assertion.text, 120)},
        "directly_affected": affected.len(),
        "affected_findings": affected,
        "caveat": "Retraction impact is simulated over declared dependency links.",
    }))
    .map_err(|e| format!("Serialization error: {e}"))
}

/// Inbound counterpart to `tool_trace_evidence_chain`: list the
/// findings that cite or rest on `finding_id`. Direct dependents are
/// every finding whose declared links point at the target (any link
/// type); when `transitive` is set we additionally return the causal
/// closure over `depends`/`supports` edges. Read-only navigation —
/// `propagate_retraction` is the retraction-cascade framing of the
/// same reverse graph.
fn tool_list_dependents(args: &Value, frontier: &Project) -> Result<String, String> {
    let id = args["finding_id"]
        .as_str()
        .ok_or("Missing 'finding_id' argument")?;
    let transitive = args["transitive"].as_bool().unwrap_or(false);
    let limit = args["limit"].as_u64().unwrap_or(100) as usize;

    let target = frontier
        .findings
        .iter()
        .find(|finding| finding.id == id || finding.id.starts_with(id))
        .ok_or_else(|| format!("Finding '{id}' not found"))?;

    // O(1) reverse-dep lookup via the denormalized index, mirroring
    // tool_propagate_retraction. The reverse index keys on link target
    // regardless of link type, so we re-read each dependent's links to
    // report which relation points at the target.
    let reverse_idx = frontier.build_reverse_dep_index();
    let id_to_finding: std::collections::HashMap<&str, &vela_protocol::bundle::FindingBundle> =
        frontier
            .findings
            .iter()
            .map(|f| (f.id.as_str(), f))
            .collect();

    let mut direct = Vec::new();
    for dep_id in reverse_idx.dependents_of(&target.id) {
        let Some(dependent) = id_to_finding.get(dep_id.as_str()) else {
            continue;
        };
        let link_types: Vec<&str> = dependent
            .links
            .iter()
            .filter(|link| link.target == target.id)
            .map(|link| link.link_type.as_str())
            .collect();
        if link_types.is_empty() {
            continue;
        }
        direct.push(json!({
            "id": dependent.id,
            "assertion": trunc(&dependent.assertion.text, 100),
            "link_types": link_types,
        }));
    }
    let direct_total = direct.len();
    direct.truncate(limit);

    let mut payload = json!({
        "finding": {"id": target.id, "assertion": trunc(&target.assertion.text, 120)},
        "direct_dependents": direct_total,
        "returned": direct.len(),
        "dependents": direct,
        "caveat": "Dependents reflect declared links only; this is navigation, not impact analysis.",
    });

    if transitive {
        // Causal closure walks depends/supports edges only (the
        // CausalGraph excludes contradicts/extends), so transitive
        // dependents are the findings that ultimately rest on the
        // target through its evidence chain.
        let graph = vela_protocol::causal_graph::CausalGraph::from_project(frontier);
        let mut closure: Vec<String> = graph.descendants(&target.id).into_iter().collect();
        closure.sort();
        let transitive_total = closure.len();
        closure.truncate(limit);
        payload["transitive_dependents"] = json!(transitive_total);
        payload["transitive_returned"] = json!(closure.len());
        payload["transitive_ids"] = json!(closure);
    }

    serde_json::to_string_pretty(&payload).map_err(|e| format!("Serialization error: {e}"))
}

/// One-shot orientation around a finding: the node, what it rests on
/// (outbound depends/supports/derived edges), what rests on it
/// (inbound dependents), its sideways relations (extends/improves/
/// generalizes/specializes/supersedes), and its contradictions in both
/// directions. Collapses the get_finding + trace_evidence_chain +
/// list_dependents chain an agent would otherwise walk into a single
/// call — the move that pays off most when several frontiers are open
/// at once. Mirrors codegraph's `context` tool.
fn tool_frontier_context(args: &Value, frontier: &Project) -> Result<String, String> {
    let id = args["finding_id"]
        .as_str()
        .or_else(|| args["id"].as_str())
        .ok_or("Missing 'finding_id' argument")?;
    let limit = args["limit"].as_u64().unwrap_or(50) as usize;

    let target = frontier
        .findings
        .iter()
        .find(|finding| finding.id == id || finding.id.starts_with(id))
        .ok_or_else(|| format!("Finding '{id}' not found"))?;

    let id_to_finding: std::collections::HashMap<&str, &vela_protocol::bundle::FindingBundle> =
        frontier
            .findings
            .iter()
            .map(|f| (f.id.as_str(), f))
            .collect();
    let assertion_of = |fid: &str| {
        id_to_finding
            .get(fid)
            .map(|f| trunc(&f.assertion.text, 100))
            .unwrap_or_default()
    };

    // Outbound edges declared on the target itself.
    let mut rests_on = Vec::new();
    let mut related = Vec::new();
    let mut contradictions = Vec::new();
    for link in &target.links {
        use vela_protocol::frontier_graph::EdgeKind;
        match EdgeKind::from_link_type(&link.link_type) {
            Some(EdgeKind::Supports | EdgeKind::DependsOn | EdgeKind::DerivedFrom) => rests_on
                .push(json!({
                    "id": link.target,
                    "assertion": assertion_of(&link.target),
                    "link_type": link.link_type,
                })),
            Some(EdgeKind::Contradicts) => contradictions.push(json!({
                "id": link.target,
                "assertion": assertion_of(&link.target),
                "direction": "this_contradicts",
            })),
            _ => related.push(json!({
                "id": link.target,
                "assertion": assertion_of(&link.target),
                "link_type": link.link_type,
            })),
        }
    }

    // Inbound edges via the reverse-dependency index.
    let reverse_idx = frontier.build_reverse_dep_index();
    let mut dependents = Vec::new();
    for dep_id in reverse_idx.dependents_of(&target.id) {
        let Some(dep) = id_to_finding.get(dep_id.as_str()) else {
            continue;
        };
        let inbound: Vec<&str> = dep
            .links
            .iter()
            .filter(|link| link.target == target.id)
            .map(|link| link.link_type.as_str())
            .collect();
        if inbound.contains(&"contradicts") {
            contradictions.push(json!({
                "id": dep.id,
                "assertion": trunc(&dep.assertion.text, 100),
                "direction": "contradicted_by",
            }));
        }
        let non_contra: Vec<&str> = inbound
            .into_iter()
            .filter(|t| *t != "contradicts")
            .collect();
        if !non_contra.is_empty() {
            dependents.push(json!({
                "id": dep.id,
                "assertion": trunc(&dep.assertion.text, 100),
                "link_types": non_contra,
            }));
        }
    }

    let (rests_on_total, dependents_total, related_total, contradictions_total) = (
        rests_on.len(),
        dependents.len(),
        related.len(),
        contradictions.len(),
    );
    rests_on.truncate(limit);
    dependents.truncate(limit);
    related.truncate(limit);
    contradictions.truncate(limit);

    serde_json::to_string_pretty(&json!({
        "finding": {
            "id": target.id,
            "assertion": trunc(&target.assertion.text, 160),
            "contested": target.flags.contested,
            "gap": target.flags.gap,
            "confidence": target.confidence.score,
        },
        "rests_on": {"count": rests_on_total, "edges": rests_on},
        "dependents": {"count": dependents_total, "edges": dependents},
        "related": {"count": related_total, "edges": related},
        "contradictions": {"count": contradictions_total, "edges": contradictions},
        "caveat": "Local graph view over declared links; relations are candidates, not adjudicated truth.",
    }))
    .map_err(|e| format!("Serialization error: {e}"))
}

/// Resolve a `problem` argument to one finding: a `#<num>` problem number
/// (the digit run must not extend, so `#617` ≠ `#6170`), a `vf_…` id or
/// prefix, or a case-insensitive substring of the statement.
fn resolve_problem<'a>(
    arg: &str,
    frontier: &'a Project,
) -> Option<&'a vela_protocol::bundle::FindingBundle> {
    let arg = arg.trim();
    if arg.starts_with("vf_") {
        return frontier
            .findings
            .iter()
            .find(|f| f.id == arg || f.id.starts_with(arg));
    }
    if arg.chars().all(|c| c.is_ascii_digit()) && !arg.is_empty() {
        let needle = format!("#{arg}");
        if let Some(f) = frontier.findings.iter().find(|f| {
            let t = &f.assertion.text;
            t.match_indices(&needle).any(|(i, _)| {
                t[i + needle.len()..]
                    .chars()
                    .next()
                    .is_none_or(|c| !c.is_ascii_digit())
            })
        }) {
            return Some(f);
        }
    }
    let lc = arg.to_lowercase();
    frontier
        .findings
        .iter()
        .find(|f| f.assertion.text.to_lowercase().contains(&lc))
}

/// One-call problem briefing: statement, gate status, open obligations
/// (gap-flagged findings linked to it), rests-on, dependents, and
/// staleness — the CodeGraph one-shot context call for frontier state.
/// The agent entry contract: everything needed to start work on a
/// problem cold, in one call. Statement + state hashes + gate status +
/// ALLOWED OUTPUTS (each mapped to the frozen verifier kind that would
/// check it) + failed-route memory (the BANKED clauses of the linked
/// obligations — what is provably exhausted, do not re-grind) + open
/// targets + the attempt ledger for this problem. An agent's output is
/// acceptable only if it is one of the allowed output types with its
/// verifier passing; prose strategy is not a state transition.
fn tool_task_packet(
    args: &Value,
    frontier: &Project,
    source_path: Option<&std::path::Path>,
) -> Result<String, String> {
    let arg = args["problem"]
        .as_str()
        .or_else(|| args["id"].as_str())
        .ok_or("Missing 'problem' argument")?;
    let v = build_task_packet(
        arg,
        frontier,
        source_path,
        default_decl_graph_path().as_deref(),
    )?;
    serde_json::to_string_pretty(&v).map_err(|e| e.to_string())
}

/// Default location of the Mathlib decl-dependency graph (regenerable working
/// data; `data/` is gitignored, so this is present only on a worktree that has
/// run the decl-build / Lean pass — absent is fine, the premise slice is then
/// honestly empty). Prefers the WIDE slice (`decl-edges-wide.jsonl`, ~37k
/// kernel premise edges) so the live atlas defaults to the wide graph; the
/// `load_decl_edges` reader accepts either the raw `.jsonl` or the built
/// `decl-graph.v1.json`. Falls back to a built `decl-graph.v1.json` artifact
/// (which `vela atlas decl-build` now regenerates from the wide edges by
/// default), then the legacy narrow slice, so an older worktree still resolves.
pub(crate) fn default_decl_graph_path() -> Option<std::path::PathBuf> {
    for cand in [
        "data/mathlib/decl-edges-wide.jsonl",
        "data/mathlib/decl-graph.v1.json",
        "data/mathlib/decl-edges.jsonl",
    ] {
        let p = std::path::PathBuf::from(cand);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

/// The CodeGraph bridge: the minimal KERNEL-CHECKED premise slice for a target,
/// found by looking up the target's Mathlib declaration anchor(s) in the
/// `getUsedConstants` decl-dependency graph. This is the first consumer that
/// joins the decl graph into the finding (`vf_`) id-space. Premises are the
/// decls this target's proof USES; dependents rest on it. Edges are
/// kernel-extracted, never asserted, so no fabrication enters the packet. Empty
/// (honestly) for any target with no Mathlib anchor (e.g. exact combinatorial
/// witnesses), or when the local decl-graph artifact is absent.
pub(crate) fn decl_premise_slice(
    frontier: &Project,
    target_id: &str,
    decl_graph: Option<&std::path::Path>,
    max: usize,
) -> Value {
    let decls: Vec<String> = frontier
        .anchor_links
        .iter()
        .filter(|l| l.target == target_id && l.anchor.namespace == "mathlib")
        .map(|l| l.anchor.id.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    if decls.is_empty() {
        return json!({
            "decl_anchored": false,
            "decls": [],
            "note": "target carries no Mathlib declaration anchor; no kernel-premise slice (most non-Lean targets are honestly empty here).",
        });
    }
    let Some(path) = decl_graph else {
        return json!({
            "decl_anchored": true,
            "graph_present": false,
            "decls": decls,
            "note": "target is Mathlib-anchored but the decl-graph artifact (data/mathlib/decl-graph.v1.json) is absent on this worktree; run `vela atlas decl-build`.",
        });
    };
    let edges = match crate::cli_atlas::load_decl_edges(&path.to_string_lossy()) {
        Ok(e) => e,
        Err(e) => {
            return json!({"decl_anchored": true, "graph_present": false, "decls": decls, "error": e});
        }
    };
    let items: Vec<Value> = decls
        .iter()
        .map(|d| {
            let mut premises: Vec<&str> = edges
                .iter()
                .filter(|(f, _)| f == d)
                .map(|(_, t)| t.as_str())
                .collect();
            premises.sort_unstable();
            premises.dedup();
            let mut dependents: Vec<&str> = edges
                .iter()
                .filter(|(_, t)| t == d)
                .map(|(f, _)| f.as_str())
                .collect();
            dependents.sort_unstable();
            dependents.dedup();
            json!({
                "decl": d,
                "premise_count": premises.len(),
                "premises": premises.iter().take(max).collect::<Vec<_>>(),
                "dependent_count": dependents.len(),
                "dependents": dependents.iter().take(max).collect::<Vec<_>>(),
            })
        })
        .collect();
    json!({
        "decl_anchored": true,
        "graph_present": true,
        "source": "data/mathlib/decl-graph.v1.json (kernel getUsedConstants, noise-filtered)",
        "decls": items,
        "note": "minimal kernel-checked premise slice: premises are decls this target's proof uses; dependents rest on it. Edges are kernel-extracted, never asserted.",
    })
}

/// Compose one root-pinned, replayable Frontier Packet for a single target. The
/// MCP `task_packet` tool and the `vela task packet` CLI verb share this. It
/// binds: the resolved obligation, the accepted state at (snapshot_hash,
/// event_log_hash), the gate status, the minimal kernel-premise slice
/// ([`decl_premise_slice`], the CodeGraph bridge), the failed-route memory and
/// open obligations from the linked gap findings, the attempt ledger, and the
/// submission contract. Compact and complete: small enough to read, but every
/// authoritative line replays from the named root.
pub(crate) fn build_task_packet(
    arg: &str,
    frontier: &Project,
    source_path: Option<&std::path::Path>,
    decl_graph: Option<&std::path::Path>,
) -> Result<Value, String> {
    use vela_protocol::verifier_attachment::{claim_digest, derive_gate_status};
    let target = resolve_problem(arg, frontier)
        .ok_or_else(|| format!("No finding resolves problem '{arg}'"))?;

    // Problem number: from the arg (e.g. "#617" / "617") or the text.
    let num_from = |t: &str| -> Option<u64> {
        let i = t.find('#')?;
        t[i + 1..]
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect::<String>()
            .parse()
            .ok()
    };
    let problem_number = num_from(arg)
        .or_else(|| arg.parse().ok())
        .or_else(|| num_from(&target.assertion.text));

    let digest = claim_digest(&target.assertion.text);
    let atts: Vec<_> = frontier
        .verifier_attachments
        .iter()
        .filter(|a| a.target == target.id)
        .cloned()
        .collect();
    let gate = derive_gate_status(&digest, &atts);

    // Curated closure routes: `closure-routes.json` in the frontier dir
    // maps each problem to the artifact types that would close it and
    // the frozen verifier kind that checks each. Absent file -> only the
    // universal outputs are advertised.
    let mut allowed_outputs: Vec<Value> = Vec::new();
    if let (Some(p), Some(n)) = (source_path, problem_number) {
        // Single-file serves point at frontier.json; the curated routes
        // live next to it (or in the served directory).
        let dir = if p.is_dir() {
            p
        } else {
            p.parent().unwrap_or(p)
        };
        let routes_path = dir.join("closure-routes.json");
        if let Ok(txt) = std::fs::read_to_string(&routes_path)
            && let Ok(routes) = serde_json::from_str::<Value>(&txt)
            && let Some(entry) = routes["problems"][n.to_string()].as_object()
            && let Some(types) = entry.get("closure_types").and_then(Value::as_array)
        {
            allowed_outputs.extend(types.iter().cloned());
        }
    }
    // Universal outputs: every frontier accepts these regardless of the
    // problem-specific routes (skipped when the curated routes already
    // name the same type).
    let has = |t: &str| allowed_outputs.iter().any(|o| o["type"] == t);
    if !has("obstruction_report") {
        allowed_outputs.push(json!({
        "type": "obstruction_report",
        "verifier_kind": "review",
        "note": "A gap-flagged finding through the Frontier PR flow: a precise, checkable reason a route cannot work. Prevents duplicate wasted passes.",
        }));
    }
    allowed_outputs.push(json!({
        "type": "attempt_deposit",
        "verifier_kind": "signature",
        "note": "A signed vat_ attempt record (banked or failed) so the pass itself becomes part of the ledger.",
    }));

    // Obligations carry the route memory: BANKED = exhausted channels
    // (failed-route memory; do not re-grind), OPEN = the live targets.
    let mut failed_routes: Vec<Value> = Vec::new();
    let mut open_targets: Vec<Value> = Vec::new();
    for f in &frontier.findings {
        if !f.flags.gap || f.id == target.id {
            continue;
        }
        let linked = f.links.iter().any(|l| l.target == target.id)
            || target.links.iter().any(|l| l.target == f.id);
        if !linked {
            continue;
        }
        let text = &f.assertion.text;
        if let Some(b) = text.find("BANKED:") {
            let end = text.find("OPEN:").unwrap_or(text.len());
            failed_routes.push(json!({
                "obligation": f.id,
                "banked": text[b + 7..end].trim().trim_end_matches('.'),
            }));
        }
        if let Some(o) = text.find("OPEN:") {
            // Opportunity view v1: how much of the frontier rests on this
            // obligation (direct dependents via links, either direction).
            let dependents = frontier
                .findings
                .iter()
                .filter(|d| d.id != f.id && d.links.iter().any(|l| l.target == f.id))
                .count();
            let lease = frontier
                .attempt_claims
                .iter()
                .find(|c| c.obligation_id == f.id)
                .map(|c| {
                    json!({
                        "leased_by": c.claimant_actor,
                        "claimed_at": c.claimed_at,
                        "ttl_seconds": c.lease_ttl_seconds,
                    })
                });
            open_targets.push(json!({
                "obligation": f.id,
                "open": text[o + 5..].trim(),
                "dependents": dependents,
                "lease": lease,
            }));
        }
    }
    // Highest-leverage first: the opportunity ranking is a derived view,
    // it never gates trust.
    open_targets.sort_by_key(|t| std::cmp::Reverse(t["dependents"].as_u64().unwrap_or(0)));

    // Attempt ledger: every signed pass on this problem, banked or
    // failed — the run history the next agent starts from.
    let attempts: Vec<Value> = frontier
        .attempts
        .iter()
        .filter(|a| Some(a.problem as u64) == problem_number)
        .map(|a| {
            let resolution = frontier
                .attempt_resolutions
                .iter()
                .filter(|r| r.attempt_id == a.attempt_id)
                .max_by(|x, y| x.at.cmp(&y.at))
                .map(|r| format!("{:?}", r.resolution));
            json!({
                "attempt_id": a.attempt_id,
                "kind": a.kind,
                "claim": trunc(&a.claim, 120),
                "claimed_status": a.claimed_status,
                "verifier_attachments": a.verifier_attachments.len(),
                "resolution": resolution,
            })
        })
        .collect();

    // Context-of-use: derived, never stored — what "verified" MEANS for
    // this claim. Formal-proof attachments need a faithful statement
    // attestation to count as verified_formal_statement.
    let has_formal = atts.iter().any(|a| {
        format!("{:?}", a.verifier_method)
            .to_lowercase()
            .contains("lean")
    });
    let attested_faithful = frontier.statement_attestations.iter().any(|a| {
        a.target == target.id
            && matches!(
                a.verdict,
                vela_protocol::statement_attestation::FaithfulnessVerdict::Faithful
            )
    });
    let context_label = match (
        format!("{:?}", gate.status).as_str(),
        has_formal,
        attested_faithful,
    ) {
        ("Verified", true, true) => "verified_formal_statement",
        ("Verified", true, false) => "verified_proof_statement_unattested",
        ("Verified", false, _) => "verified_computational_replay",
        _ if attested_faithful => "human_attested_statement",
        _ => "unverified",
    };

    Ok(json!({
        "tool": "task_packet",
        "resolved": {"id": target.id, "problem": problem_number, "from": arg},
        "statement": target.assertion.text,
        "state": {
            "snapshot_hash": vela_protocol::events::snapshot_hash(frontier),
            "event_log_hash": vela_protocol::events::event_log_hash(&frontier.events),
        },
        "premise_slice": decl_premise_slice(frontier, &target.id, decl_graph, 12),
        "gate_status": {
            "status": format!("{:?}", gate.status),
            "reasons": gate.reasons,
            "attachments": atts.len(),
        },
        "context_of_use": {
            "label": context_label,
            "regulatory_grade": false,
        },
        "statement_attestations": frontier
            .statement_attestations
            .iter()
            .filter(|a| a.target == target.id)
            .map(|a| json!({
                "id": a.id,
                "verdict": format!("{:?}", a.verdict),
                "attested_by": a.attested_by,
                "formal_ref": sanitize_local_path(&a.formal_ref),
            }))
            .collect::<Vec<_>>(),
        "allowed_outputs": allowed_outputs,
        "failed_routes": {
            "count": failed_routes.len(),
            "items": failed_routes,
            "rule": "Do not re-attempt a banked route unless you produce a NEW counterexample or proof against the banked obstruction itself.",
        },
        "open_targets": {"count": open_targets.len(), "items": open_targets},
        "attempts": {"count": attempts.len(), "items": attempts},
        "submission": {
            "witness": "write the artifact as <frontier>/witnesses/<name>.witness.json and run `vela reproduce <frontier>` — the frozen verifier must pass",
            "finding": "propose via `vela note`/`vela finding add` WITHOUT --apply; a keyed reviewer accepts with --key (key custody is the accept authority)",
            "attempt": "deposit a signed vat_ attempt; failed passes are ledger entries, not noise",
        },
        "caveat": "Allowed outputs are the only state-changing submissions; strategy prose without an artifact does not move the frontier.",
    }))
}

fn tool_frontier_explore(args: &Value, frontier: &Project) -> Result<String, String> {
    use vela_protocol::verifier_attachment::{claim_digest, derive_gate_status};
    let arg = args["problem"]
        .as_str()
        .or_else(|| args["id"].as_str())
        .ok_or("Missing 'problem' argument")?;
    let target = resolve_problem(arg, frontier)
        .ok_or_else(|| format!("No finding resolves problem '{arg}'"))?;

    let id_to = |fid: &str| -> String {
        frontier
            .findings
            .iter()
            .find(|f| f.id == fid)
            .map(|f| trunc(&f.assertion.text, 120))
            .unwrap_or_default()
    };

    // Gate status: derive over this finding's verifier attachments.
    let digest = claim_digest(&target.assertion.text);
    let atts: Vec<_> = frontier
        .verifier_attachments
        .iter()
        .filter(|a| a.target == target.id)
        .cloned()
        .collect();
    let gate = derive_gate_status(&digest, &atts);

    // Obligations: gap-flagged findings linked to this finding in either
    // direction — what is unproven / the bottleneck / the next step.
    let mut obligations = Vec::new();
    for f in &frontier.findings {
        if !f.flags.gap || f.id == target.id {
            continue;
        }
        let links_to_target = f.links.iter().any(|l| l.target == target.id);
        let target_links_here = target.links.iter().any(|l| l.target == f.id);
        if links_to_target || target_links_here {
            obligations.push(json!({
                "id": f.id,
                "statement": trunc(&f.assertion.text, 200),
                "review_state": f.flags.review_state.as_ref().map(|s| format!("{s:?}")),
            }));
        }
    }

    // rests_on / dependents from declared links.
    let mut rests_on = Vec::new();
    for l in &target.links {
        use vela_protocol::frontier_graph::EdgeKind;
        if matches!(
            EdgeKind::from_link_type(&l.link_type),
            Some(EdgeKind::Supports | EdgeKind::DependsOn | EdgeKind::DerivedFrom)
        ) {
            rests_on.push(
                json!({"id": l.target, "assertion": id_to(&l.target), "link_type": l.link_type}),
            );
        }
    }
    let mut dependents = Vec::new();
    for f in &frontier.findings {
        if f.links.iter().any(|l| l.target == target.id) {
            dependents.push(json!({"id": f.id, "assertion": trunc(&f.assertion.text, 120)}));
        }
    }

    // Staleness: the latest event touching this finding.
    let events = vela_protocol::events::events_for_finding(frontier, &target.id);
    let latest = events
        .iter()
        .max_by(|a, b| a.timestamp.cmp(&b.timestamp))
        .map(|e| json!({"at": e.timestamp, "kind": e.kind}));

    serde_json::to_string_pretty(&json!({
        "tool": "frontier_explore",
        "resolved": {"id": target.id, "from": arg},
        "statement": target.assertion.text,
        "gate_status": {
            "status": format!("{:?}", gate.status),
            "reasons": gate.reasons,
            "attachments": atts.len(),
        },
        "obligations": {"count": obligations.len(), "items": obligations},
        "rests_on": {"count": rests_on.len(), "edges": rests_on},
        "dependents": {"count": dependents.len(), "edges": dependents},
        "staleness": {"latest_event": latest, "event_count": events.len()},
        "caveat": "Obligations are stated work items, not adjudicated truth; gate status reflects only verified attachments.",
    }))
    .map_err(|e| format!("Serialization error: {e}"))
}

/// T7: typed claim-level graph summary. Returns node/edge counts and
/// the per-kind edge breakdown by default; with a `kind` argument it
/// also returns up to `limit` edges of that relation. Derived view
/// over the declared link graph (see [`vela_protocol::frontier_graph`]).
fn tool_frontier_graph(args: &Value, frontier: &Project) -> Result<String, String> {
    let graph = vela_protocol::frontier_graph::FrontierGraph::from_project(frontier);
    let mut summary = json!({
        "schema": "vela.frontier_graph.claims.v0.1",
        "nodes": graph.node_count(),
        "edges": graph.edge_count(),
        "edge_kinds": graph.edge_kind_counts(),
        "contradiction_pairs": graph.contradiction_pairs().len(),
        "claim_boundary": {
            "graph_is_derived": true,
            "relations_are_candidates_not_adjudicated": true,
        },
    });

    if let Some(kind_str) = args["kind"].as_str() {
        let kind = vela_protocol::frontier_graph::EdgeKind::parse(kind_str)
            .ok_or_else(|| format!("Unknown edge kind '{kind_str}'"))?;
        let limit = args["limit"].as_u64().unwrap_or(100) as usize;
        let edges: Vec<Value> = graph
            .edges_of_kind(kind)
            .take(limit)
            .map(|e| {
                json!({
                    "source": e.source,
                    "target": e.target,
                    "kind": e.kind.as_str(),
                    "in_frontier": e.target_in_frontier,
                    "note": trunc(&e.note, 80),
                })
            })
            .collect();
        if let Value::Object(map) = &mut summary {
            map.insert("kind".to_string(), json!(kind.as_str()));
            map.insert("matched_edges".to_string(), json!(edges));
        }
    }

    serde_json::to_string_pretty(&summary).map_err(|e| format!("Serialization error: {e}"))
}

/// T7: first-class candidate Contradiction objects (`vcx_`) derived
/// from the typed graph. Each carries an honest claim boundary and a
/// resolution status that defaults to `candidate` — auto-detected
/// signals pending expert review, never adjudicated truth.
fn tool_contradictions(args: &Value, frontier: &Project) -> Result<String, String> {
    let graph = vela_protocol::frontier_graph::FrontierGraph::from_project(frontier);
    let frontier_id = frontier.frontier_id();
    let limit = args["limit"].as_u64().unwrap_or(100) as usize;

    // Derived candidates from the graph, overlaid with any persisted
    // review state from the event log (persisted wins). Persisted
    // contradictions whose pair no longer derives are still surfaced —
    // a reviewer's judgment outlives the edge that prompted it.
    let mut by_id: std::collections::BTreeMap<String, vela_protocol::contradiction::Contradiction> =
        vela_protocol::contradiction::derive_candidates(&graph, &frontier_id)
            .into_iter()
            .map(|c| (c.contradiction_id.clone(), c))
            .collect();
    let candidate_total = by_id.len();
    for c in &frontier.contradictions {
        by_id.insert(c.contradiction_id.clone(), c.clone());
    }
    let reviewed_total = frontier.contradictions.len();

    // Bi-temporal `as_of` query: restrict to contradictions open at a
    // given world-time (valid time), not the order events landed.
    let as_of = args["as_of"].as_str();
    let mut all: Vec<vela_protocol::contradiction::Contradiction> = by_id.into_values().collect();
    if let Some(at) = as_of {
        all.retain(|c| c.is_open_at(at));
    }
    let total = all.len();
    let items: Vec<Value> = all.iter().take(limit).map(|c| c.to_json()).collect();

    serde_json::to_string_pretty(&json!({
        "frontier_id": frontier_id,
        "total": total,
        "candidate_contradictions": candidate_total,
        "reviewed_contradictions": reviewed_total,
        "as_of": as_of,
        "returned": items.len(),
        "contradictions": items,
        "caveat": "Candidate contradictions are auto-detected signals pending expert review. Reviewed ones record a named reviewer's judgment, not platform-adjudicated truth.",
    }))
    .map_err(|e| format!("Serialization error: {e}"))
}

/// Export a finding as a nanopublication (TriG/RDF) for interchange
/// with the FAIR / semantic-web science ecosystem. See
/// [`vela_protocol::nanopub`].
fn tool_nanopublication(args: &Value, frontier: &Project) -> Result<String, String> {
    let id = args["finding_id"]
        .as_str()
        .or_else(|| args["id"].as_str())
        .ok_or("Missing 'finding_id' argument")?;
    let finding = frontier
        .findings
        .iter()
        .find(|f| f.id == id || f.id.starts_with(id))
        .ok_or_else(|| format!("Finding '{id}' not found"))?;
    let trig = vela_protocol::nanopub::finding_to_nanopub_trig(finding, &frontier.frontier_id());
    serde_json::to_string_pretty(&json!({
        "finding_id": finding.id,
        "format": "trig",
        "schema": "vela.finding.nanopub.v0.1",
        "nanopublication": trig,
        "caveat": "Derived interchange artifact; the canonical finding remains the vf_ object in the frontier.",
    }))
    .map_err(|e| format!("Serialization error: {e}"))
}

/// ORKG-style comparison: line up findings addressing the same scoped
/// problem against a fixed set of generic comparison properties, so a
/// reviewer can read the state of a question as a table rather than
/// prose. Scope is set by `query` (substring on the assertion),
/// `assertion_type`, and/or an explicit `ids` list; with none, compares
/// the whole frontier (capped by `limit`).
fn tool_frontier_compare(args: &Value, frontier: &Project) -> Result<String, String> {
    let query = args["query"].as_str().map(str::to_lowercase);
    let assertion_type = args["assertion_type"].as_str();
    let ids: Vec<&str> = args["ids"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let limit = args["limit"].as_u64().unwrap_or(50) as usize;

    let selected: Vec<&vela_protocol::bundle::FindingBundle> = frontier
        .findings
        .iter()
        .filter(|f| {
            query
                .as_deref()
                .is_none_or(|q| f.assertion.text.to_lowercase().contains(q))
                && assertion_type.is_none_or(|t| f.assertion.assertion_type == t)
                && (ids.is_empty() || ids.iter().any(|id| f.id == *id || f.id.starts_with(id)))
        })
        .take(limit)
        .collect();

    // The generic comparison properties (ORKG's "comparison
    // properties"): applicable across any contribution on the problem.
    let properties = json!([
        "assertion_type",
        "confidence",
        "evidence_type",
        "method",
        "model_system",
        "replicated",
        "replication_count",
        "human_data",
        "clinical_trial",
        "contested",
        "gap",
        "year"
    ]);

    let rows: Vec<Value> = selected
        .iter()
        .map(|f| {
            json!({
                "id": f.id,
                "assertion": trunc(&f.assertion.text, 100),
                "assertion_type": f.assertion.assertion_type,
                "confidence": f.confidence.score,
                "evidence_type": f.evidence.evidence_type,
                "method": trunc(&f.evidence.method, 60),
                "model_system": f.evidence.model_system,
                "replicated": f.evidence.replicated,
                "replication_count": f.evidence.replication_count,
                "contested": f.flags.contested,
                "gap": f.flags.gap,
                "year": f.provenance.year,
            })
        })
        .collect();

    serde_json::to_string_pretty(&json!({
        "scope": {"query": args["query"], "assertion_type": assertion_type, "ids": ids},
        "compared": rows.len(),
        "properties": properties,
        "rows": rows,
        "caveat": "A structured side-by-side of declared finding properties; not a ranking or adjudication.",
    }))
    .map_err(|e| format!("Serialization error: {e}"))
}

/// The "deep" tier (DeepWiki pattern): multi-hop traversal from a
/// finding across the typed graph, layered by hop distance, versus the
/// single-hop `context`/`frontier_graph` "fast" tier. Returns the
/// explored subgraph organized for an agent to synthesize a multi-hop
/// answer — nodes by hop, edge-kind distribution, and contradictions
/// encountered in the region.
fn tool_deep_trace(args: &Value, frontier: &Project) -> Result<String, String> {
    let id = args["finding_id"]
        .as_str()
        .ok_or("Missing 'finding_id' argument")?;
    let max_hops = args["max_hops"].as_u64().unwrap_or(3).min(8) as usize;
    let limit_per_hop = args["limit_per_hop"].as_u64().unwrap_or(25) as usize;

    let graph = vela_protocol::frontier_graph::FrontierGraph::from_project(frontier);
    let start = frontier
        .findings
        .iter()
        .find(|f| f.id == id || f.id.starts_with(id))
        .ok_or_else(|| format!("Finding '{id}' not found"))?;

    let exploration = graph.explore(&start.id, max_hops);

    // Nodes grouped by hop distance, each with its label.
    let layers: Vec<Value> = (0..=exploration.max_hop())
        .map(|hop| {
            let at = exploration.nodes_at(hop);
            let nodes: Vec<Value> = at
                .iter()
                .take(limit_per_hop)
                .map(|&nid| {
                    json!({"id": nid, "label": graph.label_of(nid).map(|l| trunc(l, 90)).unwrap_or_default()})
                })
                .collect();
            json!({"hop": hop, "count": at.len(), "nodes": nodes})
        })
        .collect();

    // Contradictions encountered anywhere in the explored region.
    let contradictions: Vec<Value> = exploration
        .edges
        .iter()
        .filter(|e| e.kind == vela_protocol::frontier_graph::EdgeKind::Contradicts)
        .map(|e| json!({"source": e.source, "target": e.target}))
        .collect();

    serde_json::to_string_pretty(&json!({
        "start": {"id": start.id, "assertion": trunc(&start.assertion.text, 140)},
        "max_hops": max_hops,
        "reached": exploration.node_count(),
        "edges_in_region": exploration.edges.len(),
        "edge_kinds": exploration.edge_kind_counts(),
        "contradictions_in_region": contradictions.len(),
        "contradictions": contradictions,
        "layers": layers,
        "caveat": "Multi-hop view over declared links for synthesis; relations are candidates, not adjudicated truth.",
    }))
    .map_err(|e| format!("Serialization error: {e}"))
}

fn tool_blast_radius(args: &Value, frontier: &Project) -> Result<String, String> {
    use vela_protocol::frontier_graph::{BlastDirection, EdgeKind, FrontierGraph};
    let q = args["finding"]
        .as_str()
        .ok_or("Missing 'finding' argument")?;
    let direction = match args["impact"].as_str() {
        Some("up") | Some("upstream") => BlastDirection::Upstream,
        Some("down") | Some("downstream") => BlastDirection::Downstream,
        _ => BlastDirection::Both,
    };
    let kinds: Vec<EdgeKind> = args["kinds"]
        .as_str()
        .map(|csv| csv.split(',').filter_map(EdgeKind::parse).collect())
        .unwrap_or_default();
    let graph = FrontierGraph::from_project(frontier);
    let center = graph
        .find_node(q)
        .ok_or_else(|| format!("Finding '{q}' not found"))?;
    let br = graph.blast_radius_graded(frontier, &center, &kinds, direction);
    serde_json::to_string_pretty(&br.to_json()).map_err(|e| format!("Serialization error: {e}"))
}

fn tool_apply_observer(args: &Value, frontier: &Project) -> Result<String, String> {
    let policy_name = args["policy"].as_str().ok_or("Missing 'policy' argument")?;
    let limit = args["limit"].as_u64().unwrap_or(15) as usize;
    let policy = observer::policy_by_name(policy_name).unwrap_or_else(observer::academic);
    let view = observer::observe(&frontier.findings, &policy);
    let top = view
        .findings
        .iter()
        .take(limit)
        .map(|scored| {
            let finding = frontier
                .findings
                .iter()
                .find(|finding| finding.id == scored.finding_id);
            json!({
                "id": scored.finding_id,
                "original_confidence": scored.original_confidence,
                "observer_score": scored.observer_score,
                "rank": scored.rank,
                "assertion": finding.map(|f| trunc(&f.assertion.text, 100)).unwrap_or_default(),
            })
        })
        .collect::<Vec<_>>();
    serde_json::to_string_pretty(&json!({
        "policy": policy_name,
        "shown": top.len(),
        "hidden": view.hidden,
        "top_findings": top,
        "caveat": "Observer output is policy-weighted reranking, not definitive disagreement.",
    }))
    .map_err(|e| format!("Serialization error: {e}"))
}

async fn tool_check_pubmed(args: &Value, client: &Client) -> Result<String, String> {
    let query = args["query"].as_str().ok_or("Missing 'query' argument")?;
    let count = pubmed_result_count(client, query).await?;
    serde_json::to_string_pretty(&json!({
        "query": query,
        "pubmed_results": count,
        "rough_prior_art_clear": count == 0,
        "caveat": "PubMed counts are rough prior-art signals, not proof of novelty.",
    }))
    .map_err(|e| format!("Serialization error: {e}"))
}

/// Rough PubMed prior-art count via the NCBI esearch endpoint. A single
/// best-effort request: the result is a coarse novelty signal, not proof.
async fn pubmed_result_count(client: &Client, query: &str) -> Result<u64, String> {
    let url = format!(
        "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esearch.fcgi?db=pubmed&term={}&rettype=json&retmode=json&tool=vela&email=vela@borrowedlight.org",
        urlencoding::encode(query)
    );
    let resp = client
        .get(&url)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| format!("PubMed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("PubMed {}", resp.status()));
    }
    let json: Value = resp
        .json()
        .await
        .map_err(|e| format!("PubMed parse: {e}"))?;
    Ok(json["esearchresult"]["count"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0))
}

fn frontier_index_json(project_infos: &[ProjectInfo]) -> Result<String, String> {
    let frontiers = project_infos
        .iter()
        .map(|info| {
            json!({
                "name": info.name,
                "file": info.file,
                "findings": info.findings_count,
                "links": info.links_count,
                "papers": info.papers,
            })
        })
        .collect::<Vec<_>>();
    serde_json::to_string_pretty(&json!({
        "frontier_count": frontiers.len(),
        "frontiers": frontiers,
    }))
    .map_err(|e| format!("Serialization error: {e}"))
}

fn tool_trace_evidence_chain(args: &Value, frontier: &Project) -> Result<String, String> {
    let id = args["finding_id"]
        .as_str()
        .ok_or("Missing 'finding_id' argument")?;
    let depth = args["depth"].as_u64().unwrap_or(2) as usize;
    let lookup = frontier
        .findings
        .iter()
        .map(|finding| (finding.id.as_str(), finding))
        .collect::<HashMap<_, _>>();
    let finding = lookup
        .get(id)
        .copied()
        .or_else(|| {
            frontier
                .findings
                .iter()
                .find(|finding| finding.id.starts_with(id))
        })
        .ok_or_else(|| format!("Finding '{id}' not found"))?;
    let links = finding
        .links
        .iter()
        .take(depth.saturating_mul(10).max(10))
        .map(|link| {
            // Cross-frontier resolution, consistent with FrontierGraph /
            // CausalGraph: a `vf_X@vfr_Y` target resolves to the bare
            // `vf_X` node when present (as under `serve --frontiers`).
            let bare = vela_protocol::bundle::bare_finding_id(&link.target);
            let target = lookup
                .get(link.target.as_str())
                .or_else(|| lookup.get(bare));
            json!({
                "target": link.target,
                "type": link.link_type,
                "note": link.note,
                "target_assertion": target.map(|f| trunc(&f.assertion.text, 120)),
                "target_in_frontier": target.is_some(),
            })
        })
        .collect::<Vec<_>>();
    let evidence_span_count = finding.evidence.evidence_spans.len();
    let source_ref = finding
        .provenance
        .doi
        .as_deref()
        .unwrap_or(&finding.provenance.title);
    let review_state = finding
        .provenance
        .review
        .as_ref()
        .map(|review| {
            if review.reviewed {
                "reviewed"
            } else {
                "pending_review"
            }
        })
        .unwrap_or("pending_review");
    let finding_events = events::events_for_finding(frontier, &finding.id);
    let linked_sources = sources::sources_for_finding(frontier, &finding.id);
    let linked_atoms = sources::evidence_atoms_for_finding(frontier, &finding.id);
    let linked_conditions = sources::condition_records_for_finding(frontier, &finding.id);
    let linked_proposals = vela_protocol::proposals::proposals_for_finding(frontier, &finding.id);
    serde_json::to_string_pretty(&json!({
        "finding": {"id": finding.id, "assertion": finding.assertion.text},
        "sources": linked_sources,
        "evidence_atoms": linked_atoms,
        "condition_records": linked_conditions,
        "proposals": linked_proposals,
        "source_to_state": [
            {"step": "source", "value": linked_sources, "fallback": source_ref},
            {"step": "evidence_atom", "value": linked_atoms},
            {"step": "condition_boundary", "value": linked_conditions},
            {"step": "proposal_lineage", "value": linked_proposals},
            {"step": "legacy_evidence", "value": {"type": finding.evidence.evidence_type, "spans": evidence_span_count, "method": finding.evidence.method}},
            {"step": "finding", "value": {"id": finding.id, "assertion_type": finding.assertion.assertion_type, "confidence": finding.confidence.score}},
            {"step": "event_history", "value": finding_events},
            {"step": "links", "value": {"declared": finding.links.len()}},
            {"step": "review_state", "value": review_state}
        ],
        "state_events": finding_events,
        "path_explanation": format!(
            "source -> evidence spans ({}) -> finding {} -> {} declared links -> {}",
            evidence_span_count,
            finding.id,
            finding.links.len(),
            review_state
        ),
        "depth": depth,
        "links": links,
        "caveat": "Evidence-chain strength is heuristic and depends on declared links.",
    }))
    .map_err(|e| format!("Serialization error: {e}"))
}

fn clone_project(project: &Project) -> Project {
    serde_json::from_value(serde_json::to_value(project).unwrap_or_default()).unwrap_or_else(|_| {
        project::assemble("unavailable", Vec::new(), 0, 1, "failed to clone frontier")
    })
}

fn json_rpc_result(id: &Option<Value>, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn json_rpc_error(id: &Option<Value>, code: i32, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

/// Projection-side path sanitation: some early signed attestations recorded
/// a LOCAL absolute checkout path in `formal_ref`. The signed event is
/// immutable, so the fix lives at the serializer boundary — a local absolute
/// path renders as its bare artifact name (the statement hash carried
/// alongside pins the content, not the path).
fn sanitize_local_path(s: &str) -> String {
    const LOCAL_PREFIXES: [&str; 5] = ["/Users/", "/home/", "/private/", "/var/", "/tmp/"];
    if LOCAL_PREFIXES.iter().any(|p| s.starts_with(p)) {
        return s
            .rsplit('/')
            .find(|seg| !seg.is_empty())
            .unwrap_or("")
            .to_string();
    }
    s.to_string()
}

fn trunc(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &s[..end])
}

#[cfg(test)]
mod sanitize_local_path_tests {
    use super::sanitize_local_path;

    #[test]
    fn local_absolute_path_renders_as_bare_artifact_name() {
        // The real leak shape: an early attestation recorded a local
        // checkout path (with a corrupted segment) as formal_ref.
        let leaked = "/Users/someone/personal/vela/google-deepmind/x@0647711a7118PNOutputs/ErdosProblems/erdos_152.lean";
        assert_eq!(sanitize_local_path(leaked), "erdos_152.lean");
        assert_eq!(sanitize_local_path("/home/ci/build/a.lean"), "a.lean");
    }

    #[test]
    fn non_local_refs_pass_through() {
        assert_eq!(
            sanitize_local_path("Outputs/ErdosProblems/erdos_152.lean"),
            "Outputs/ErdosProblems/erdos_152.lean"
        );
        assert_eq!(
            sanitize_local_path("erdosproblems.com #125"),
            "erdosproblems.com #125"
        );
        assert_eq!(sanitize_local_path(""), "");
    }
}

#[cfg(test)]
mod list_dependents_tests {
    use super::*;
    use vela_protocol::project::assemble;

    // Local copies of the reverse-dep-index test helpers (formerly
    // `vela_protocol::project::reverse_dep_index_tests::{synth_finding,
    // link_to}`). Inlined here when this test moved out of the
    // `vela-protocol` crate, since protocol's test helpers are not part
    // of its public, cross-crate API.
    use vela_protocol::bundle::{
        Assertion, Author, Conditions, Confidence, ConfidenceKind, ConfidenceMethod, Evidence,
        Extraction, FindingBundle, Flags, Link, Provenance,
    };

    fn synth_finding(idx: usize, links: Vec<Link>) -> FindingBundle {
        let assertion = Assertion {
            text: format!("Synthetic finding {idx}"),
            assertion_type: "mechanism".into(),
            entities: vec![],
            relation: None,
            direction: None,
            causal_claim: None,
            causal_evidence_grade: None,
        };
        let evidence = Evidence {
            evidence_type: "experimental".into(),
            model_system: "test".into(),
            method: "test".into(),
            replicated: false,
            replication_count: None,
            evidence_spans: vec![],
        };
        let conditions = Conditions {
            text: "test".into(),
            duration: None,
        };
        let confidence = Confidence {
            kind: ConfidenceKind::FrontierEpistemic,
            score: 0.5,
            basis: "test".into(),
            method: ConfidenceMethod::LlmInitial,
            components: None,
            extraction_confidence: 0.9,
        };
        let provenance = Provenance {
            source_type: "published_paper".into(),
            doi: Some(format!("10.0000/reverse-dep-index-test.{idx:04}")),
            url: None,
            title: format!("Synthetic test paper {idx}"),
            authors: vec![Author {
                name: "T".into(),
                orcid: None,
            }],
            year: None,
            license: None,
            publisher: None,
            funders: vec![],
            extraction: Extraction::default(),
            review: None,
        };
        let flags = Flags::default();
        let mut bundle = FindingBundle::new(
            assertion, evidence, conditions, confidence, provenance, flags,
        );
        bundle.links = links;
        bundle
    }

    fn link_to(target: &str) -> Link {
        Link {
            target: target.into(),
            link_type: "supports".into(),
            note: "test".into(),
            inferred_by: "test".into(),
            created_at: "2026-05-02T00:00:00Z".into(),
            mechanism: None,
        }
    }

    /// Chain f0 → f1 → f2 → f3, where each finding `supports` the next
    /// (so f0 rests on f1, f1 on f2, f2 on f3). The reverse graph then
    /// says f3's direct dependent is f2, and f3's transitive dependents
    /// are {f2, f1, f0}.
    fn chain_project() -> (Project, [String; 4]) {
        let f3 = synth_finding(3, vec![]);
        let f2 = synth_finding(2, vec![link_to(&f3.id)]);
        let f1 = synth_finding(1, vec![link_to(&f2.id)]);
        let f0 = synth_finding(0, vec![link_to(&f1.id)]);
        let ids = [f0.id.clone(), f1.id.clone(), f2.id.clone(), f3.id.clone()];
        let mut project = assemble("chain", vec![], 0, 0, "test");
        project.findings = vec![f0, f1, f2, f3];
        (project, ids)
    }

    #[test]
    fn direct_dependents_lists_immediate_callers_with_link_type() {
        let (project, [_f0, f1, f2, _f3]) = chain_project();
        let out = tool_list_dependents(&json!({"finding_id": f2}), &project).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["direct_dependents"], 1);
        assert_eq!(v["dependents"][0]["id"], f1);
        assert_eq!(v["dependents"][0]["link_types"][0], "supports");
        // A read-only navigation tool must not emit transitive data
        // unless asked.
        assert!(v.get("transitive_dependents").is_none());
    }

    #[test]
    fn transitive_returns_full_causal_closure() {
        let (project, [f0, f1, f2, f3]) = chain_project();
        let out =
            tool_list_dependents(&json!({"finding_id": f3, "transitive": true}), &project).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["direct_dependents"], 1); // only f2 links f3 directly
        assert_eq!(v["transitive_dependents"], 3); // f2, f1, f0
        let ids: Vec<String> = v["transitive_ids"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap().to_string())
            .collect();
        assert!(ids.contains(&f0) && ids.contains(&f1) && ids.contains(&f2));
    }

    #[test]
    fn root_with_no_callers_returns_empty() {
        let (project, [f0, _f1, _f2, _f3]) = chain_project();
        let out = tool_list_dependents(&json!({"finding_id": f0}), &project).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["direct_dependents"], 0);
        assert_eq!(v["dependents"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn unknown_finding_is_an_error() {
        let (project, _ids) = chain_project();
        assert!(
            tool_list_dependents(&json!({"finding_id": "vf_does_not_exist"}), &project).is_err()
        );
    }

    fn contradicts_to(target: &str) -> vela_protocol::bundle::Link {
        let mut link = link_to(target);
        link.link_type = "contradicts".into();
        link
    }

    /// base ← target (supports), target ← a (supports, a dependent),
    /// target ← b (contradicts, inbound contradiction). The context of
    /// `target` should show one rests_on (base), one dependent (a), and
    /// one contradiction (b, contradicted_by).
    /// End-to-end at the tool layer: a derived candidate, once an
    /// expert-confirm resolution event is applied, surfaces through the
    /// `contradictions` tool with its persisted reviewed status.
    #[test]
    fn contradictions_tool_reflects_persisted_resolution() {
        let x = synth_finding(0, vec![]);
        let y = synth_finding(1, vec![contradicts_to(&x.id)]);
        let mut project = assemble("ctool", vec![], 0, 0, "test");
        project.findings = vec![x, y];

        // Before review: one candidate, zero reviewed.
        let before: Value =
            serde_json::from_str(&tool_contradictions(&json!({}), &project).unwrap()).unwrap();
        assert_eq!(before["candidate_contradictions"], 1);
        assert_eq!(before["reviewed_contradictions"], 0);

        // Derive the candidate (correct id for this frontier), confirm
        // it, and apply the resolution event to the log.
        let graph = vela_protocol::frontier_graph::FrontierGraph::from_project(&project);
        let fid = project.frontier_id();
        let cand = vela_protocol::contradiction::derive_candidates(&graph, &fid)
            .pop()
            .unwrap();
        let confirmed = cand.expert_confirm("actor:e", "2026-05-31T00:00:00Z", "real");
        let event = confirmed.resolution_event("actor:e", "human", "confirm");
        vela_protocol::reducer::apply_event(&mut project, &event).unwrap();

        // After review: still one contradiction, now counted as reviewed
        // and carrying the expert_confirmed status + honest boundary.
        let after: Value =
            serde_json::from_str(&tool_contradictions(&json!({}), &project).unwrap()).unwrap();
        assert_eq!(after["total"], 1);
        assert_eq!(after["reviewed_contradictions"], 1);
        assert_eq!(
            after["contradictions"][0]["status"]["state"],
            "expert_confirmed"
        );
        assert_eq!(
            after["contradictions"][0]["claim_boundary"]["authoritative"],
            false
        );
        assert_eq!(
            after["contradictions"][0]["claim_boundary"]["reviewed"],
            true
        );
    }

    #[test]
    fn trace_evidence_chain_resolves_cross_frontier_target() {
        // Merged-project shape: `local` depends on `remote` via a
        // `@vfr` link. trace must enrich the target like the graph
        // tools now do, not leave it null.
        let remote = synth_finding(0, vec![]);
        let cross = format!("{}@vfr_other", remote.id);
        let local = synth_finding(1, vec![link_typed(&cross, "depends")]);
        let local_id = local.id.clone();

        let mut project = assemble("xf-trace", vec![], 0, 0, "test");
        project.findings = vec![remote, local];

        let out = tool_trace_evidence_chain(&json!({"finding_id": local_id}), &project).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        let link = &v["links"][0];
        assert_eq!(link["target_in_frontier"], true);
        assert!(link["target_assertion"].is_string());
    }

    fn link_typed(target: &str, link_type: &str) -> vela_protocol::bundle::Link {
        let mut l = link_to(target);
        l.link_type = link_type.into();
        l
    }

    #[test]
    fn frontier_compare_tabulates_properties_and_scopes_by_type() {
        let mut a = synth_finding(0, vec![]);
        a.assertion.assertion_type = "mechanism".into();
        a.evidence.replicated = true;
        let mut b = synth_finding(1, vec![]);
        b.assertion.assertion_type = "association".into();
        let (a_id, _b_id) = (a.id.clone(), b.id.clone());

        let mut project = assemble("cmp", vec![], 0, 0, "test");
        project.findings = vec![a, b];

        // No scope: both findings compared, with the property columns.
        let all: Value =
            serde_json::from_str(&tool_frontier_compare(&json!({}), &project).unwrap()).unwrap();
        assert_eq!(all["compared"], 2);
        assert!(
            all["properties"]
                .as_array()
                .unwrap()
                .iter()
                .any(|p| p == "confidence")
        );

        // Scoped by assertion_type: only the mechanism finding.
        let scoped: Value = serde_json::from_str(
            &tool_frontier_compare(&json!({"assertion_type": "mechanism"}), &project).unwrap(),
        )
        .unwrap();
        assert_eq!(scoped["compared"], 1);
        assert_eq!(scoped["rows"][0]["id"], a_id);
        assert_eq!(scoped["rows"][0]["replicated"], true);
    }

    #[test]
    fn context_assembles_local_neighborhood_in_one_call() {
        let base = synth_finding(0, vec![]);
        let target = synth_finding(1, vec![link_to(&base.id)]);
        let a = synth_finding(2, vec![link_to(&target.id)]);
        let b = synth_finding(3, vec![contradicts_to(&target.id)]);
        let (base_id, target_id, a_id, b_id) = (
            base.id.clone(),
            target.id.clone(),
            a.id.clone(),
            b.id.clone(),
        );

        let mut project = assemble("ctx", vec![], 0, 0, "test");
        project.findings = vec![base, target, a, b];

        let out = tool_frontier_context(&json!({"finding_id": target_id}), &project).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();

        assert_eq!(v["rests_on"]["count"], 1);
        assert_eq!(v["rests_on"]["edges"][0]["id"], base_id);

        assert_eq!(v["dependents"]["count"], 1);
        assert_eq!(v["dependents"]["edges"][0]["id"], a_id);

        assert_eq!(v["contradictions"]["count"], 1);
        assert_eq!(v["contradictions"]["edges"][0]["id"], b_id);
        assert_eq!(
            v["contradictions"]["edges"][0]["direction"],
            "contradicted_by"
        );
    }

    #[test]
    fn premise_slice_bridges_mathlib_anchor_into_the_kernel_graph() {
        use vela_protocol::anchor::{Anchor, AnchorKind, AnchorLink, JoinPolicy};
        let target = synth_finding(1, vec![]);
        let plain = synth_finding(2, vec![]);
        let (tid, pid) = (target.id.clone(), plain.id.clone());

        let mut project = assemble("premise", vec![], 0, 0, "test");
        project.findings = vec![target, plain];
        // The target carries a Mathlib declaration anchor; the plain finding does not.
        project.anchor_links = vec![AnchorLink {
            schema: "vela.anchor_link.v1".into(),
            id: "val_test".into(),
            target: tid.clone(),
            anchor: Anchor {
                namespace: "mathlib".into(),
                id: "Nat.Perfect".into(),
                role: "formal-decl".into(),
                kind: AnchorKind::FormalDeclaration,
                join_policy: JoinPolicy::HardIdentity,
                namespace_version: None,
                source_revision: None,
                statement_fingerprint: None,
            },
            attached_by: "agent:test".into(),
            attached_at: "2026-06-22T00:00:00Z".into(),
            signature: "x".into(),
            signer_pubkey_hex: "x".into(),
        }];

        // A tiny decl-graph: Nat.Perfect USES Nat.properDivisors; Foo rests on it.
        let dir = std::env::temp_dir().join(format!("vela_premise_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dg = dir.join("decl-graph.v1.json");
        std::fs::write(
            &dg,
            r#"{"edges":[{"from":"Nat.Perfect","to":"Nat.properDivisors"},{"from":"Foo.usesPerfect","to":"Nat.Perfect"}]}"#,
        )
        .unwrap();

        // Anchored target: the slice is the real kernel premise neighborhood.
        let s = decl_premise_slice(&project, &tid, Some(dg.as_path()), 12);
        assert_eq!(s["decl_anchored"], true);
        assert_eq!(s["graph_present"], true);
        assert_eq!(s["decls"][0]["decl"], "Nat.Perfect");
        assert_eq!(s["decls"][0]["premise_count"], 1);
        assert_eq!(s["decls"][0]["premises"][0], "Nat.properDivisors");
        assert_eq!(s["decls"][0]["dependent_count"], 1);
        assert_eq!(s["decls"][0]["dependents"][0], "Foo.usesPerfect");

        // Un-anchored target: honestly empty (no fabricated premises).
        let e = decl_premise_slice(&project, &pid, Some(dg.as_path()), 12);
        assert_eq!(e["decl_anchored"], false);
        assert_eq!(e["decls"].as_array().unwrap().len(), 0);

        std::fs::remove_dir_all(&dir).ok();
    }
}
