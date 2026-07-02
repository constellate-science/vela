//! Read-only MCP/HTTP frontier server.

#![allow(clippy::too_many_lines)]

use std::collections::{HashMap, HashSet};
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::{
    Router,
    routing::{get, post},
};
use reqwest::Client;
use serde::Serialize;
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower_http::cors::CorsLayer;

use vela_edge::signals;
use vela_edge::tool_registry;
use vela_protocol::bundle::FindingBundle;
use vela_protocol::project::{self, ConfidenceDistribution, Project, ProjectStats};
use vela_protocol::repo;
use vela_protocol::sources;

use super::http::{
    http_entries, http_entry, http_entry_events, http_entry_finding, http_entry_findings,
    http_health, http_mcp, http_mcp_get,
};
use super::tools::{
    tool_decide, tool_external, tool_finding, tool_graph, tool_nanopublication, tool_objects,
    tool_orient, tool_propose, tool_search, tool_verify, tool_work,
};
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
    // Pre-v0.36.2, `artifacts` were dropped during merge, leaving the
    // merged stats incomplete.
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
    let state = AppState {
        project: Arc::new(Mutex::new(frontier)),
        project_infos,
        client: Client::new(),
        profile,
        source_path,
    };
    let no_exclusions = HashSet::new();
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
        let Some(response) = rpc_dispatch(&request, &state, &no_exclusions).await else {
            continue;
        };
        let mut out = stdout.lock();
        let _ = serde_json::to_writer(&mut out, &response);
        let _ = out.write_all(b"\n");
        let _ = out.flush();
    }
}

/// The one JSON-RPC dispatcher behind every MCP transport: the stdio line
/// loop, the `/mcp` streamable-HTTP route, and the hub's hosted endpoint
/// (via `McpService`). `None` means the message was a notification and no
/// response is owed. `excluded` names tools withheld from this transport
/// (the hosted endpoint drops the filesystem-path `vela_*` family); the
/// exclusion applies to both `tools/list` and `tools/call`.
async fn rpc_dispatch(request: &Value, st: &AppState, excluded: &HashSet<String>) -> Option<Value> {
    let id = request.get("id").cloned();
    let method = request["method"].as_str().unwrap_or_default();
    if method.starts_with("notifications/") {
        return None;
    }
    Some(match method {
        "initialize" => {
            // Stateless JSON either way, so echo the client's requested
            // protocol version; default to the widely-supported baseline.
            let requested = request["params"]["protocolVersion"]
                .as_str()
                .unwrap_or("2024-11-05");
            json_rpc_result(
                &id,
                json!({
                    "protocolVersion": requested,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "vela", "version": project::VELA_SCHEMA_VERSION}
                }),
            )
        }
        "tools/list" => {
            let mut tools = tool_registry::mcp_tools_json_for_profile(st.profile);
            if !excluded.is_empty()
                && let Some(arr) = tools.as_array_mut()
            {
                arr.retain(|t| t["name"].as_str().is_none_or(|n| !excluded.contains(n)));
            }
            json_rpc_result(&id, json!({"tools": tools}))
        }
        "tools/call" => {
            let name = request["params"]["name"].as_str().unwrap_or_default();
            let args = request["params"]["arguments"].clone();
            if excluded.contains(name) {
                let available: Vec<String> = tool_registry::tools_for_profile(st.profile)
                    .into_iter()
                    .map(|t| t.name)
                    .filter(|n| !excluded.contains(n))
                    .collect();
                json_rpc_error(
                    &id,
                    -32602,
                    &format!(
                        "`{name}` is not served on this hosted endpoint (it operates on \
                         local filesystem paths); clone the frontier repo and run it \
                         there. Tools available here: {}",
                        available.join(", ")
                    ),
                )
            } else if let Some(err) = profile_gate(name, st.profile) {
                ToolResult::failure(name, err, 0).to_rpc(&id)
            } else {
                handle_tool_call(
                    &id,
                    name,
                    &args,
                    &st.project,
                    &st.client,
                    &st.project_infos,
                    st.source_path.as_deref(),
                )
                .await
            }
        }
        "ping" => json_rpc_result(&id, json!({})),
        _ => json_rpc_error(&id, -32601, "Method not found"),
    })
}

/// One streamable-HTTP MCP exchange (stateless JSON responses; no
/// server-initiated SSE). Accepts a single JSON-RPC message or a batch
/// array. Returns `(http_status, body)`; `None` body means an empty 202
/// (the message was all notifications).
pub(crate) async fn mcp_http_exchange(
    body: &str,
    st: &AppState,
    excluded: &HashSet<String>,
) -> (u16, Option<Value>) {
    let Ok(message) = serde_json::from_str::<Value>(body) else {
        return (
            400,
            Some(json!({
                "jsonrpc": "2.0", "id": null,
                "error": {"code": -32700, "message": "Parse error"}
            })),
        );
    };
    if let Some(batch) = message.as_array() {
        let mut responses = Vec::new();
        for request in batch {
            if let Some(response) = rpc_dispatch(request, st, excluded).await {
                responses.push(response);
            }
        }
        if responses.is_empty() {
            (202, None)
        } else {
            (200, Some(Value::Array(responses)))
        }
    } else {
        match rpc_dispatch(&message, st, excluded).await {
            Some(response) => (200, Some(response)),
            None => (202, None),
        }
    }
}

/// A hosted, in-process MCP service over named frontier checkouts. The hub
/// embeds this to serve `hub.constellate.science/mcp` without a sidecar:
/// the same dispatcher, profile gate, and tool registry as `vela serve`,
/// loaded from the git checkouts its ingest lane already maintains.
pub struct McpService {
    state: AppState,
    excluded: HashSet<String>,
}

impl McpService {
    /// Load named frontier directories into one merged read-only service.
    /// A broken entry is skipped and reported in the returned warnings,
    /// never fatal: one frontier failing to replay must not take the
    /// hosted endpoint down for the rest.
    pub fn from_named_paths(
        entries: &[(String, PathBuf)],
        profile_str: &str,
        exclude: &[String],
    ) -> Result<(Self, Vec<String>), String> {
        let profile = tool_registry::McpProfile::parse(profile_str)?;
        let mut named = Vec::new();
        let mut warnings = Vec::new();
        for (name, path) in entries {
            match repo::load_from_path(path) {
                Ok(mut frontier) => {
                    sources::materialize_project(&mut frontier);
                    named.push((name.clone(), frontier));
                }
                Err(e) => warnings.push(format!("{name}: {e}")),
            }
        }
        if named.is_empty() {
            return Err(format!(
                "no loadable frontier among {} entries: {}",
                entries.len(),
                warnings.join(" | ")
            ));
        }
        let project_infos = named
            .iter()
            .map(|(name, frontier)| ProjectInfo {
                name: frontier.project.name.clone(),
                file: name.clone(),
                findings_count: frontier.findings.len(),
                links_count: frontier.stats.links,
                papers: frontier.project.papers_processed,
            })
            .collect();
        let project = merge_projects(named);
        Ok((
            Self {
                state: AppState {
                    project: Arc::new(Mutex::new(project)),
                    project_infos,
                    client: Client::new(),
                    profile,
                    source_path: None,
                },
                excluded: exclude.iter().cloned().collect(),
            },
            warnings,
        ))
    }

    /// The hosted exclusion set: every tool that operates on a
    /// caller-supplied filesystem path. On a public endpoint those are
    /// useless at best (the caller has no paths on the server) and a CPU
    /// sink at worst (`verify` with mode=witness). The hosted endpoint runs
    /// the read-only profile, so its `tools/list` is the read-only surface
    /// minus these three: orient, finding, search, graph, external.
    pub fn hosted_exclusions() -> Vec<String> {
        ["verify", "work", "objects"]
            .into_iter()
            .map(str::to_string)
            .collect()
    }

    /// Handle one streamable-HTTP MCP exchange (single message or batch).
    /// Returns `(http_status, body)`; `None` body = empty 202.
    pub async fn handle_http(&self, body: &str) -> (u16, Option<Value>) {
        mcp_http_exchange(body, &self.state, &self.excluded).await
    }

    /// The loaded frontier labels, for the hub's status surfaces.
    pub fn frontier_labels(&self) -> Vec<String> {
        self.state
            .project_infos
            .iter()
            .map(|i| format!("{} ({})", i.name, i.file))
            .collect()
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

    // One HTTP shape: the read surface mirrors the hub's `/entries/{vfr}/…`
    // paths for the concepts serve supports, and `/mcp` at the root is the
    // tool surface. The literal segment `self` names the served frontier;
    // its real vfr_ id (or a prefix) is accepted too.
    let app = Router::new()
        .route("/health", get(http_health))
        .route("/healthz", get(http_health))
        .route("/entries", get(http_entries))
        .route("/entries/{vfr}", get(http_entry))
        .route("/entries/{vfr}/findings", get(http_entry_findings))
        .route("/entries/{vfr}/findings/{id}", get(http_entry_finding))
        .route("/entries/{vfr}/events", get(http_entry_events))
        // Streamable-HTTP MCP (stateless JSON): the same dispatcher as
        // stdio, so any remote MCP client can connect without a clone.
        .route("/mcp", post(http_mcp).get(http_mcp_get));

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
    // Full endpoint enumeration so a fresh user opening `vela serve --http`
    // knows what they can hit. `self` names the served frontier; its real
    // vfr_ id works too.
    eprintln!("  endpoints:");
    eprintln!("    health:    GET  /health  /healthz");
    eprintln!("    entries:   GET  /entries                          (single-element list)");
    eprintln!("               GET  /entries/self                     (frontier summary)");
    eprintln!("               GET  /entries/self/findings            (?query= to search)");
    eprintln!("               GET  /entries/self/findings/{{id}}");
    eprintln!("               GET  /entries/self/events?cursor=&limit=");
    eprintln!("    tools:     POST /mcp   (streamable-HTTP MCP; the tool surface)");
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
    let source_path = match &source {
        ProjectSource::Single(p) => Some(p.as_path()),
        ProjectSource::Directory(p) => Some(p.as_path()),
    };
    let (frontier, _project_infos) = load_projects(&source);
    let first_id = frontier.findings.first().map(|finding| finding.id.clone());
    let mut checks = vec![
        check_tool_result(
            "orient",
            tool_orient(&json!({}), &frontier, source_path),
            started,
        ),
        check_tool_result(
            "search",
            tool_search(&json!({"query": "Sidon", "limit": 3}), &frontier),
            started,
        ),
        check_tool_result("graph", tool_graph(&json!({}), &frontier), started),
        check_tool_result(
            "graph",
            tool_graph(&json!({"mode": "contradictions"}), &frontier),
            started,
        ),
    ];
    if let Some(id) = first_id {
        checks.push(check_tool_result(
            "finding",
            tool_finding(
                &json!({"id": id, "include": ["history", "dependents", "neighborhood"]}),
                &frontier,
            ),
            started,
        ));
        checks.push(check_tool_result(
            "orient",
            tool_orient(&json!({"problem": id}), &frontier, source_path),
            started,
        ));
        checks.push(check_tool_result(
            "graph",
            tool_graph(
                &json!({"root": id, "mode": "traverse", "max_hops": 3}),
                &frontier,
            ),
            started,
        ));
        checks.push(check_tool_result(
            "graph",
            tool_graph(&json!({"root": id, "mode": "impact"}), &frontier),
            started,
        ));
        checks.push(check_tool_result(
            "external",
            parse_payload(tool_nanopublication(&json!({"finding_id": id}), &frontier))
                .map(|v| (v, Vec::new())),
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
    let required_tools = vec!["orient", "search", "finding", "graph"];
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
        "prompt": "Call orient first. Then use search for the review question. Inspect important results with finding (include history/dependents/neighborhood as needed). Cite vf_* ids. Review graph mode=contradictions and orient's gaps as candidate signals. Use graph mode=traverse on a root before summarizing provenance. Preserve caveats and do not present Vela output as field consensus.",
        "commands": [
            format!("vela serve {source_label} --check-tools --adoption --json"),
            format!("vela serve {source_label}")
        ],
    })
}

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) project: Arc<Mutex<Project>>,
    pub(crate) project_infos: Vec<ProjectInfo>,
    pub(crate) client: Client,
    /// MCP exposure profile (memo §9.1). Scopes which tools `tools/list`
    /// exposes and `tools/call` will execute. Defaults to read-only.
    pub(crate) profile: tool_registry::McpProfile,
    /// Phase Q-w (v0.5): when serving a single frontier file, this is
    /// the path to write back to after a successful signed write. None
    /// when `--frontiers <dir>` is used; in that mode all writes are
    /// rejected.
    pub(crate) source_path: Option<PathBuf>,
}

/// Structured tool-error kinds. One closed set for every transport: the MCP
/// envelope and both HTTP servers speak `{kind, message, hint?}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) enum ToolErrorKind {
    #[serde(rename = "NOT_FOUND")]
    NotFound,
    #[serde(rename = "INVALID_ARG")]
    InvalidArg,
    #[serde(rename = "PERMISSION_DENIED")]
    PermissionDenied,
    #[serde(rename = "CUSTODY_REFUSED")]
    CustodyRefused,
    #[serde(rename = "INTERNAL")]
    Internal,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ToolError {
    pub(crate) kind: ToolErrorKind,
    pub(crate) message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) hint: Option<String>,
}

impl ToolError {
    pub(crate) fn new(kind: ToolErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            hint: None,
        }
    }

    pub(crate) fn not_found(message: impl Into<String>) -> Self {
        Self::new(ToolErrorKind::NotFound, message)
    }

    pub(crate) fn invalid(message: impl Into<String>) -> Self {
        Self::new(ToolErrorKind::InvalidArg, message)
    }

    pub(crate) fn internal(message: impl Into<String>) -> Self {
        Self::new(ToolErrorKind::Internal, message)
    }

    pub(crate) fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    /// Classify a prose error from an underlying impl. The impls predate the
    /// kind vocabulary, so this is a boundary heuristic: id/file lookups read
    /// as NOT_FOUND, argument shapes as INVALID_ARG, everything else INTERNAL.
    pub(crate) fn classify(message: String) -> Self {
        let lc = message.to_lowercase();
        let kind = if lc.contains("not found")
            || lc.contains("no finding resolves")
            || lc.contains("is not registered")
            || lc.contains("no such file")
            || lc.contains("is neither a finding")
        {
            ToolErrorKind::NotFound
        } else if lc.contains("required")
            || lc.contains("missing")
            || lc.contains("must be")
            || lc.contains("must start")
            || lc.contains("must include")
            || lc.contains("must contain")
            || lc.contains("invalid")
            || lc.contains("unknown edge kind")
            || lc.contains("out of [0.0, 1.0]")
            || lc.contains("is for agent:/ci: actors")
        {
            ToolErrorKind::InvalidArg
        } else {
            ToolErrorKind::Internal
        };
        Self::new(kind, message)
    }
}

/// The one result envelope every tool call returns, as a single JSON text
/// block: `{tool, ok, data, notes?, error?, signals, caveats, duration_ms}`.
/// No markdown duplication — `data` is the payload, `notes` carries
/// truncation and degradation notices, `error` carries `{kind, message,
/// hint?}` on failure.
#[derive(Debug, Clone, Serialize)]
struct ToolResult {
    tool: String,
    ok: bool,
    data: Value,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    notes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<ToolError>,
    signals: Vec<signals::SignalItem>,
    caveats: Vec<String>,
    duration_ms: u128,
}

impl ToolResult {
    fn success(
        tool: &str,
        data: Value,
        notes: Vec<String>,
        duration_ms: u128,
        frontier: Option<&Project>,
    ) -> Self {
        let signal_items = frontier
            .map(|project| signals::analyze(project, &[]).signals)
            .unwrap_or_default();
        Self {
            tool: tool.to_string(),
            ok: true,
            data,
            notes,
            error: None,
            signals: signal_items,
            caveats: tool_registry::tool_caveats(tool),
            duration_ms,
        }
    }

    fn failure(tool: &str, error: ToolError, duration_ms: u128) -> Self {
        Self {
            tool: tool.to_string(),
            ok: false,
            data: Value::Null,
            notes: Vec::new(),
            error: Some(error),
            signals: Vec::new(),
            caveats: tool_registry::tool_caveats(tool),
            duration_ms,
        }
    }

    fn metadata(&self) -> Value {
        json!({
            "tool": self.tool,
            "ok": self.ok,
            "duration_ms": self.duration_ms,
            "caveats": self.caveats,
        })
    }

    fn to_json_text(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }

    fn to_rpc(&self, id: &Option<Value>) -> Value {
        json_rpc_result(
            id,
            json!({
                "content": [{"type": "text", "text": self.to_json_text()}],
                "isError": !self.ok,
                "_meta": self.metadata()
            }),
        )
    }
}

/// MCP profile gate (memo §9.4): refuse to execute a tool the active profile
/// does not admit, returning a structured error envelope. `None` means the
/// call may proceed (allowed, or unknown — the dispatch then returns its own
/// NOT_FOUND). This is the execution boundary; `tools/list` already hides the
/// tool, but a client could still call it by name.
fn profile_gate(name: &str, profile: tool_registry::McpProfile) -> Option<ToolError> {
    let tool = tool_registry::get_tool(name)?;
    if profile.allows(&tool) {
        return None;
    }
    // A non-maintainer session reaching for `decide` is the custody boundary
    // itself — an agent lane asking to finalize. Everything else is a plain
    // profile mismatch.
    let kind = if name == "decide" {
        ToolErrorKind::CustodyRefused
    } else {
        ToolErrorKind::PermissionDenied
    };
    let needed = if tool_registry::McpProfile::Draft.allows(&tool) {
        "draft"
    } else {
        "maintainer"
    };
    Some(
        ToolError::new(
            kind,
            format!(
                "tool `{name}` ({}) is not available in the `{}` MCP profile",
                tool.permission_level,
                profile.as_str()
            ),
        )
        .with_hint(format!(
            "restart `vela serve` with `--profile {needed}` for a scoped session; MCP exposes tools, accepted public state still requires a key-custody human accept"
        )),
    )
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
    let elapsed = started.elapsed().as_millis();
    match result {
        Ok((data, notes)) => {
            ToolResult::success(name, data, notes, elapsed, snapshot.as_ref()).to_rpc(id)
        }
        Err(error) => ToolResult::failure(name, error, elapsed).to_rpc(id),
    }
}

/// Every tool call resolves to `(data, notes)` or a typed error. `notes`
/// carries truncation and degradation notices for the envelope.
pub(crate) type ToolOutput = Result<(Value, Vec<String>), ToolError>;

/// Parse an underlying impl's JSON-string result into the envelope's `data`,
/// classifying prose errors into the kind vocabulary at the boundary.
pub(crate) fn parse_payload(result: Result<String, String>) -> Result<Value, ToolError> {
    let text = result.map_err(ToolError::classify)?;
    serde_json::from_str(&text)
        .map_err(|e| ToolError::internal(format!("tool payload did not parse as JSON: {e}")))
}

pub(crate) fn clamp_limit(args: &Value, default: u64, max: u64) -> usize {
    args.get("limit")
        .and_then(Value::as_u64)
        .unwrap_or(default)
        .clamp(1, max) as usize
}

/// Decode an opaque list cursor (an offset into the stable result order,
/// issued by a previous response's `next_cursor`).
pub(crate) fn decode_cursor(args: &Value) -> Result<usize, ToolError> {
    match args.get("cursor").and_then(Value::as_str) {
        None => Ok(0),
        Some(c) => c.parse::<usize>().map_err(|_| {
            ToolError::invalid(format!("cursor '{c}' is not a cursor this server issued"))
                .with_hint("pass a previous response's next_cursor back unchanged")
        }),
    }
}

async fn execute_tool(
    name: &str,
    args: &Value,
    frontier: &Arc<Mutex<Project>>,
    client: &Client,
    _project_infos: &[ProjectInfo],
    source_path: Option<&Path>,
) -> (ToolOutput, Option<Project>) {
    match name {
        "orient" => {
            let project = frontier.lock().await;
            (
                tool_orient(args, &project, source_path),
                Some(clone_project(&project)),
            )
        }
        "finding" => {
            let project = frontier.lock().await;
            (tool_finding(args, &project), Some(clone_project(&project)))
        }
        "search" => {
            let project = frontier.lock().await;
            (tool_search(args, &project), Some(clone_project(&project)))
        }
        "graph" => {
            let project = frontier.lock().await;
            (tool_graph(args, &project), Some(clone_project(&project)))
        }
        "verify" => (tool_verify(args), None),
        "propose" => {
            let result = tool_propose(args, frontier, source_path).await;
            let snapshot = Some(clone_project(&*frontier.lock().await));
            (result, snapshot)
        }
        "decide" => {
            let result = tool_decide(args, frontier, source_path).await;
            let snapshot = Some(clone_project(&*frontier.lock().await));
            (result, snapshot)
        }
        "work" => (tool_work(args), None),
        "objects" => (tool_objects(args), None),
        "external" => {
            let project = frontier.lock().await;
            (
                tool_external(args, &project, client).await,
                Some(clone_project(&project)),
            )
        }
        _ => {
            let known: Vec<String> = tool_registry::all_tools()
                .into_iter()
                .map(|t| t.name)
                .collect();
            (
                Err(ToolError::not_found(format!("unknown tool `{name}`"))
                    .with_hint(format!("this server exposes: {}", known.join(", ")))),
                None,
            )
        }
    }
}

fn check_tool_result(name: &str, result: ToolOutput, started: std::time::Instant) -> Value {
    let duration_ms = started.elapsed().as_millis();
    match result {
        Ok((data, notes)) => {
            let has_data = !data.is_null();
            json!({
                "tool": name,
                "ok": has_data,
                "data": data,
                "notes": notes,
                "has_data": has_data,
                "caveats": tool_registry::tool_caveats(name),
                "duration_ms": duration_ms,
            })
        }
        Err(error) => json!({
            "tool": name,
            "ok": false,
            "data": Value::Null,
            "error": error,
            "caveats": tool_registry::tool_caveats(name),
            "duration_ms": duration_ms,
        }),
    }
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

#[cfg(test)]
mod mcp_service_tests {
    use super::*;

    fn fixture() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/erdos-formalization")
    }

    fn service() -> McpService {
        let entries = vec![("erdos-formalization".to_string(), fixture())];
        let (service, warnings) =
            McpService::from_named_paths(&entries, "read-only", &McpService::hosted_exclusions())
                .expect("fixture frontier loads");
        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
        service
    }

    #[tokio::test]
    async fn initialize_echoes_protocol_version_and_lists_filtered_tools() {
        let svc = service();
        let (status, body) = svc
            .handle_http(
                r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}"#,
            )
            .await;
        assert_eq!(status, 200);
        let body = body.unwrap();
        assert_eq!(body["result"]["protocolVersion"], "2025-06-18");

        let (status, body) = svc
            .handle_http(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#)
            .await;
        assert_eq!(status, 200);
        let tools = body.unwrap()["result"]["tools"].clone();
        let names: Vec<String> = tools
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_string())
            .collect();
        // Hosted = the read-only profile minus the path-bound exclusions:
        // exactly these five.
        assert_eq!(
            names,
            vec!["orient", "finding", "search", "graph", "external"],
            "hosted tools/list is the read-only surface minus verify/work/objects"
        );
    }

    #[tokio::test]
    async fn tool_call_returns_envelope_and_excluded_tool_is_refused_by_name() {
        let svc = service();
        let (status, body) = svc
            .handle_http(
                r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"orient","arguments":{}}}"#,
            )
            .await;
        assert_eq!(status, 200);
        let body = body.unwrap();
        assert_eq!(body["result"]["isError"], false, "orient call succeeds");
        // The one JSON text block: {tool, ok, data, notes?, signals,
        // caveats, duration_ms} — and no markdown duplication.
        let text = body["result"]["content"][0]["text"].as_str().unwrap();
        let envelope: Value = serde_json::from_str(text).unwrap();
        assert_eq!(envelope["tool"], "orient");
        assert_eq!(envelope["ok"], true);
        assert!(envelope["data"].is_object(), "data payload present");
        assert!(envelope.get("markdown").is_none(), "no markdown field");
        assert!(envelope["duration_ms"].is_number());

        let (status, body) = svc
            .handle_http(
                r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"verify","arguments":{}}}"#,
            )
            .await;
        assert_eq!(status, 200);
        let body = body.unwrap();
        assert_eq!(body["error"]["code"], -32602, "excluded tool refused");
        let message = body["error"]["message"].as_str().unwrap();
        assert!(
            message.contains("orient, finding, search, graph, external"),
            "refusal names the available tool set: {message}"
        );
    }

    #[tokio::test]
    async fn errors_carry_kind_and_profile_gate_refuses_writes() {
        let svc = service();
        // Unknown finding id → NOT_FOUND in the envelope, isError true.
        let (_, body) = svc
            .handle_http(
                r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"finding","arguments":{"id":"vf_does_not_exist"}}}"#,
            )
            .await;
        let body = body.unwrap();
        assert_eq!(body["result"]["isError"], true);
        let text = body["result"]["content"][0]["text"].as_str().unwrap();
        let envelope: Value = serde_json::from_str(text).unwrap();
        assert_eq!(envelope["ok"], false);
        assert_eq!(envelope["error"]["kind"], "NOT_FOUND");

        // A write tool on a read-only profile → PERMISSION_DENIED; the
        // finalizing tool → CUSTODY_REFUSED (the human lane).
        let (_, body) = svc
            .handle_http(
                r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"propose","arguments":{}}}"#,
            )
            .await;
        let text = body.unwrap()["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .to_string();
        let envelope: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(envelope["error"]["kind"], "PERMISSION_DENIED");

        let (_, body) = svc
            .handle_http(
                r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"decide","arguments":{}}}"#,
            )
            .await;
        let text = body.unwrap()["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .to_string();
        let envelope: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(envelope["error"]["kind"], "CUSTODY_REFUSED");
    }

    #[tokio::test]
    async fn notifications_get_202_and_batches_collect() {
        let svc = service();
        let (status, body) = svc
            .handle_http(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#)
            .await;
        assert_eq!(status, 202);
        assert!(body.is_none());

        let (status, body) = svc
            .handle_http(
                r#"[{"jsonrpc":"2.0","method":"notifications/initialized"},{"jsonrpc":"2.0","id":5,"method":"ping"}]"#,
            )
            .await;
        assert_eq!(status, 200);
        assert_eq!(body.unwrap().as_array().unwrap().len(), 1);

        let (status, body) = svc.handle_http("not json").await;
        assert_eq!(status, 400);
        assert_eq!(body.unwrap()["error"]["code"], -32700);
    }
}
