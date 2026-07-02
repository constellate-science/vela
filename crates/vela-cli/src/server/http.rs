//! The HTTP read surface for `vela serve --http`: the `/entries/{vfr}/…`
//! route handlers, the `/mcp` streamable-HTTP endpoints, and their shared
//! error/lookup helpers. Moved verbatim from `server/serve.rs`; the router
//! itself (`run_http`) and `McpService` stay there.

use std::collections::{HashMap, HashSet};

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
};
use serde_json::{Value, json};

use vela_edge::signals;
use vela_protocol::project::Project;

use super::serve::{AppState, mcp_http_exchange};
use super::tools::tool_search_findings;

/// JSON error body shared by every serve HTTP error response:
/// `{"error": {"kind": "...", "message": "..."}}`, matching the hub's shape
/// and the MCP envelope's kind vocabulary.
fn http_error(status: StatusCode, kind: &str, message: String) -> (StatusCode, Json<Value>) {
    (
        status,
        Json(json!({"error": {"kind": kind, "message": message}})),
    )
}

/// Resolve the `{vfr}` path segment: the literal `self`, the served
/// frontier's real vfr_ id, or a vfr_ prefix of it.
fn resolve_vfr(project: &Project, segment: &str) -> Option<String> {
    let fid = project.frontier_id();
    if segment == "self" || (segment.starts_with("vfr_") && fid.starts_with(segment)) {
        Some(fid)
    } else {
        None
    }
}

fn vfr_not_found(project: &Project, segment: &str) -> (StatusCode, Json<Value>) {
    http_error(
        StatusCode::NOT_FOUND,
        "NOT_FOUND",
        format!(
            "{segment} is not served here; this server serves {} (use `self`)",
            project.frontier_id()
        ),
    )
}

/// GET /entries/{vfr}/events — cursor-paginated read over the canonical
/// event log, mirroring the hub's shape.
///
/// Query params:
///   - `cursor` (optional): a `vev_…` event id; events strictly after this
///     id are returned. Omit to start from the genesis event.
///   - `limit` (optional, default 100, max 500): cap the response size.
///   - `kind`, `target` (optional): server-side filters, applied before
///     pagination so the cursor walks the filtered view.
///
/// Returns `{events: [...], next_cursor: "vev_..." | null, count: usize}`.
/// `next_cursor` is null when the response includes the tail of the log.
/// 400 if `cursor` does not exist in the log (the client is out of sync;
/// better to fail loudly than to silently skip).
pub(crate) async fn http_entry_events(
    State(state): State<AppState>,
    axum::extract::Path(vfr): axum::extract::Path<String>,
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    let project = state.project.lock().await;
    let Some(vfr_id) = resolve_vfr(&project, &vfr) else {
        return vfr_not_found(&project, &vfr);
    };
    let limit = params
        .get("limit")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(100)
        .min(500);
    let start_idx: usize = match params.get("cursor") {
        None => 0,
        Some(cursor) => match project.events.iter().position(|event| &event.id == cursor) {
            Some(idx) => idx + 1,
            None => {
                return http_error(
                    StatusCode::BAD_REQUEST,
                    "INVALID_ARG",
                    format!("cursor '{cursor}' not found in event log; client is out of sync"),
                );
            }
        },
    };
    // Server-side `?kind=` and `?target=` filters. Agents watching for
    // specific event kinds (e.g. polling for new finding.superseded events)
    // shouldn't need to fetch the whole log to locate one match. Filters
    // apply BEFORE the limit/cursor so pagination works on the filtered view.
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
            "vfr_id": vfr_id,
            "events": slice,
            "count": slice.len(),
            "next_cursor": next_cursor,
            "log_total": project.events.len(),
            "filtered_total": total_filtered,
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

/// GET /entries — the single-element registry list. `vela serve` serves one
/// (possibly merged) frontier; this mirrors the hub's `/entries` shape so a
/// client can speak one protocol to either server.
pub(crate) async fn http_entries(State(state): State<AppState>) -> Json<Value> {
    let project = state.project.lock().await;
    Json(json!({
        "schema": "vela.entries.v0",
        "count": 1,
        "entries": [{
            "vfr_id": project.frontier_id(),
            "name": project.project.name,
            "findings": project.stats.findings,
            "links": project.stats.links,
            "events": project.events.len(),
            "sources": state.project_infos.iter().map(|info| json!({
                "name": info.name,
                "file": info.file,
                "findings": info.findings_count,
                "links": info.links_count,
                "papers": info.papers,
            })).collect::<Vec<_>>(),
        }],
    }))
}

/// GET /entries/{vfr} — the frontier summary: stats, proof state, signals.
pub(crate) async fn http_entry(
    State(state): State<AppState>,
    axum::extract::Path(vfr): axum::extract::Path<String>,
) -> (StatusCode, Json<Value>) {
    let project = state.project.lock().await;
    let Some(vfr_id) = resolve_vfr(&project, &vfr) else {
        return vfr_not_found(&project, &vfr);
    };
    (
        StatusCode::OK,
        Json(json!({
            "vfr_id": vfr_id,
            "frontier": {
                "name": project.project.name,
                "description": project.project.description,
                "compiled_at": project.project.compiled_at,
                "compiler": project.project.compiler,
            },
            "stats": project.stats,
            "events": project.events.len(),
            "proof_state": project.proof_state,
            "signals": signals::analyze(&project, &[]).signals,
        })),
    )
}

/// GET /entries/{vfr}/findings — structured list, or text-shaped search when
/// a `query`/`entity`/`entity_type`/`type` filter is supplied.
pub(crate) async fn http_entry_findings(
    State(state): State<AppState>,
    axum::extract::Path(vfr): axum::extract::Path<String>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    let project = state.project.lock().await;
    if resolve_vfr(&project, &vfr).is_none() {
        return vfr_not_found(&project, &vfr);
    }
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
        return (
            StatusCode::OK,
            Json(json!({
                "count": view.findings.len(),
                "returned": findings.len(),
                "findings": findings,
            })),
        );
    }

    let args = json!({
        "query": params.get("query"),
        "entity": params.get("entity"),
        "entity_type": params.get("entity_type"),
        "assertion_type": params.get("type"),
        "limit": params.get("limit").and_then(|v| v.parse::<u64>().ok()).unwrap_or(50),
    });
    match tool_search_findings(&args, &view) {
        Ok(text) => (StatusCode::OK, Json(json!({"result": text}))),
        Err(error) => http_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", error),
    }
}

/// GET /entries/{vfr}/findings/{id} — one finding with its derived Belnap
/// status and provenance overlays.
pub(crate) async fn http_entry_finding(
    State(state): State<AppState>,
    axum::extract::Path((vfr, id)): axum::extract::Path<(String, String)>,
    headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
    let project = state.project.lock().await;
    if resolve_vfr(&project, &vfr).is_none() {
        return vfr_not_found(&project, &vfr);
    }
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
                return http_error(
                    StatusCode::NOT_FOUND,
                    "NOT_FOUND",
                    format!("Finding not found: {id}"),
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
                map.insert("support_term_count".to_string(), json!(sp.support.len()));
                map.insert("refute_term_count".to_string(), json!(sp.refute.len()));
                // Surface the support/refute id sets per docs/THEORY.md
                // §7, suitable for audit trails and downstream tooling
                // that needs to know which events derive support.
                map.insert(
                    "support_provenance".to_string(),
                    serde_json::to_value(&sp.support).unwrap_or_default(),
                );
                map.insert(
                    "refute_provenance".to_string(),
                    serde_json::to_value(&sp.refute).unwrap_or_default(),
                );
                // Display strings join the ids additively (`vev_a + vev_b`).
                // Suitable for debug surfaces and Workbench tooltips.
                let join = |s: &std::collections::BTreeSet<String>| -> String {
                    if s.is_empty() {
                        "0".to_string()
                    } else {
                        s.iter().cloned().collect::<Vec<_>>().join(" + ")
                    }
                };
                map.insert(
                    "support_provenance_display".to_string(),
                    json!(join(&sp.support)),
                );
                map.insert(
                    "refute_provenance_display".to_string(),
                    json!(join(&sp.refute)),
                );
            }
            (StatusCode::OK, Json(value))
        }
        None => http_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            format!("Finding not found: {id}"),
        ),
    }
}

pub(crate) async fn http_health(State(state): State<AppState>) -> Json<Value> {
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

/// POST /mcp — streamable-HTTP MCP with stateless JSON responses.
pub(crate) async fn http_mcp(
    State(state): State<AppState>,
    body: String,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let (status, response) = mcp_http_exchange(&body, &state, &HashSet::new()).await;
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::OK);
    match response {
        Some(value) => (status, Json(value)).into_response(),
        None => status.into_response(),
    }
}

/// GET /mcp — this endpoint offers no server-initiated SSE stream.
pub(crate) async fn http_mcp_get() -> (StatusCode, Json<Value>) {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        Json(json!({
            "error": "stateless MCP endpoint: POST a JSON-RPC message; no server-initiated stream is offered"
        })),
    )
}
