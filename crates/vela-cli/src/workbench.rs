//! v0.48: local workbench: axum web app rendering the substrate
//! against the cwd's `.vela/` repo.
//!
//! Doctrine: the static site (vela-site.fly.dev) is a marketing surface
//! bundled against one frontier at build time. The workbench is a
//! single-binary, single-user, localhost UI that renders the *user's*
//! frontier, with read+write actions that hit the same on-disk
//! representation `vela <subcommand>` would.
//!
//! Architecture:
//! - Pure Rust + axum. No node, no bun, no static-build step.
//! - Each request reads from disk. Writes call back into the same
//!   modules `vela <cmd>` uses (e.g., bridge confirm rewrites the
//!   `.vela/bridges/<vbr_id>.json` file in place).
//! - Shared CSS with the hub (`web/styles/tokens.css`,
//!   `web/styles/workbench.css`) via `include_str!`.
//! - Auto-opens the default browser on start unless `--no-open`.

#![allow(clippy::too_many_lines)]

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::{
    Json, Router,
    extract::{Form, Path as AxumPath, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tower_http::cors::CorsLayer;

use vela_edge::adoption_log;
use vela_edge::bridge::{Bridge, BridgeStatus};
use vela_protocol::bundle::{FindingBundle, Replication};
use vela_edge::causal_reasoning::{Identifiability, audit_frontier, summarize_audit};
use vela_edge::decision;
use vela_protocol::diff_pack_review::{self, DiffPackVerdict};
use vela_protocol::evidence_ci;
use vela_edge::frontier_health;
use vela_edge::frontier_incident;
use vela_edge::frontier_task;
use vela_edge::index_db_schema;
use vela_protocol::project::Project;
use vela_protocol::proposals::{self, StateProposal};
use vela_protocol::repo;
use vela_edge::review_packet;
use vela_edge::review_session;
use vela_edge::reviewer_identity;
use vela_protocol::scientific_diff::ScientificDiffPack;
use vela_edge::source_inbox;
use vela_protocol::state::{self, ReviseOptions};
use vela_edge::task_workspace;

const TOKENS_CSS: &str = include_str!("../embedded/web/styles/tokens.css");
const WORKBENCH_CSS: &str = include_str!("../embedded/web/styles/workbench.css");

const FAVICON_SVG: &str = include_str!("../embedded/assets/brand/favicon.svg");

const WB_VERSION: &str = "0.55.0"; // v0.55: + /constellation page with live cascade firing

/// Workbench app state: the absolute path to the user's `.vela/` repo
/// (its parent, the path that `repo::load_from_path` accepts).
///
/// W1.5: also carries an in-memory form-state cache so that a
/// validator rejection on a POST can redirect the reviewer back to
/// the GET form with their typed values pre-filled and an inline
/// error banner. The cache is keyed by an opaque token returned in
/// the redirect URL. Localhost-only by construction; the cache
/// never crosses the workbench process boundary.
#[derive(Clone)]
struct AppState {
    repo_path: Arc<PathBuf>,
    form_cache: Arc<Mutex<HashMap<String, FormCacheEntry>>>,
}

/// W1.5: TTL for cached form-state entries. Five minutes is long
/// enough for a reviewer to read the error banner, fix the input,
/// and resubmit; short enough that stale tokens cannot accumulate
/// across a workday.
const FORM_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(300);

#[derive(Clone)]
struct FormCacheEntry {
    inserted_at: Instant,
    state: FormState,
}

/// W1.5: cached form values plus the validator's error message,
/// keyed per failed POST. One variant per write surface. Some
/// id fields are stored for symmetry with the form payload (and
/// for future audit hooks) even though the GET handler reads the
/// path id directly; suppress the dead-field warning rather than
/// drop them from the cache shape.
#[allow(dead_code)]
#[derive(Clone)]
enum FormState {
    LocatorRepair {
        atom_id: String,
        locator: String,
        reviewer: String,
        reason: String,
        error: String,
    },
    SpanRepair {
        finding_id: String,
        section: String,
        text: String,
        reviewer: String,
        reason: String,
        error: String,
    },
    EntityResolve {
        finding_id: String,
        entity_name: String,
        source: String,
        id: String,
        confidence: f64,
        matched_name: Option<String>,
        resolution_method: String,
        reviewer: String,
        reason: String,
        error: String,
    },
    Promote {
        finding_id: String,
        status: String,
        reviewer: String,
        reason: String,
        error: String,
    },
    ConflictResolve {
        conflict_event_id: String,
        resolution_note: String,
        winning_proposal_id: Option<String>,
        reviewer: String,
        error: String,
    },
    ReplicationAdd {
        finding_id: String,
        outcome: String,
        attempted_by: String,
        conditions_text: String,
        source_title: String,
        doi: String,
        pmid: String,
        note: String,
        error: String,
    },
    PredictionAdd {
        finding_id: String,
        claim_text: String,
        resolves_by: String,
        resolution_criterion: String,
        expected_outcome: String,
        made_by: String,
        confidence: f64,
        conditions_text: String,
        error: String,
    },
}

/// W1.5: 16-byte hex token. `rand` is already a workspace dep, so
/// no new crate. Collisions across a single workday are
/// astronomically unlikely.
fn new_form_token() -> String {
    let mut buf = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

fn store_form_state(state: &AppState, fs: FormState) -> String {
    let token = new_form_token();
    let mut cache = match state.form_cache.lock() {
        Ok(c) => c,
        Err(e) => e.into_inner(),
    };
    // Opportunistic prune: drop expired entries before insert.
    let now = Instant::now();
    cache.retain(|_, entry| now.duration_since(entry.inserted_at) < FORM_CACHE_TTL);
    cache.insert(
        token.clone(),
        FormCacheEntry {
            inserted_at: now,
            state: fs,
        },
    );
    token
}

fn take_form_state(state: &AppState, token: &str) -> Option<FormState> {
    let mut cache = match state.form_cache.lock() {
        Ok(c) => c,
        Err(e) => e.into_inner(),
    };
    let now = Instant::now();
    cache.retain(|_, entry| now.duration_since(entry.inserted_at) < FORM_CACHE_TTL);
    cache.remove(token).map(|e| e.state)
}

#[derive(Debug, Deserialize, Default)]
struct ErrorTokenQuery {
    #[serde(default)]
    error: Option<String>,
}

/// W1.5: render the inline error banner above a review form. Uses
/// the existing `--ink-1` token plus a left border in `--gold` and
/// a literal red color value (no new visual tokens introduced; the
/// red is local to this banner only).
fn render_error_banner(message: &str) -> String {
    format!(
        r#"<div class="wb-card" style="border-left:3px solid var(--gold,#b71c1c);background:#fbeaea;"><p style="margin:0;color:#b71c1c;font-weight:500;">Submission rejected by validator</p><p style="margin:0.3rem 0 0 0;color:var(--ink-1);font-size:0.92rem;">{msg}</p></div>"#,
        msg = escape_html(message)
    )
}

/// Start the workbench on `127.0.0.1:<port>`, against `repo_path`. If
/// `open_browser` is true, opens the default browser at the local URL.
pub async fn run(repo_path: PathBuf, port: u16, open_browser: bool) -> Result<(), String> {
    if !repo_path.join(".vela").is_dir() {
        return Err(format!(
            "no .vela/ found at {}. Run `vela init` first",
            repo_path.display()
        ));
    }
    // Sanity-check loadability before binding the port.
    let _ =
        repo::load_from_path(&repo_path).map_err(|e| format!("failed to load .vela/ repo: {e}"))?;

    let state = AppState {
        repo_path: Arc::new(repo_path),
        form_cache: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/", get(page_dashboard))
        .route("/start", get(page_start))
        .route("/ask", get(page_ask))
        .route("/transcript", get(page_transcript))
        .route("/review/sessions", get(page_review_sessions))
        .route(
            "/review/sessions/{session_id}",
            get(page_review_session_detail),
        )
        .route(
            "/adoption/friction",
            get(page_adoption_friction).post(post_adoption_friction),
        )
        .route("/decision", get(page_decision_brief))
        .route("/findings", get(page_findings))
        .route("/findings/{vf_id}", get(page_finding_detail))
        .route("/proposals", get(page_proposals))
        .route("/proposals/{vpr_id}/preview", get(page_proposal_preview))
        .route("/proposals/{vpr_id}/accept", post(post_proposal_accept))
        .route("/proposals/{vpr_id}/reject", post(post_proposal_reject))
        .route("/proposals/{vpr_id}/revision", post(post_proposal_revision))
        .route("/artifact-packets", get(page_artifact_packets))
        .route("/tasks", get(page_tasks))
        .route("/tasks/{task_id}/claim", post(post_task_claim))
        .route("/tasks/{task_id}/status", post(post_task_status))
        .route("/tasks/{task_id}/close", post(post_task_close))
        .route(
            "/tasks/{task_id}/workspace",
            get(page_task_workspace_status),
        )
        .route(
            "/tasks/{task_id}/review-packet",
            get(page_task_review_packet),
        )
        .route("/source-inbox", get(page_source_inbox))
        .route(
            "/source-inbox/{record_id}/verify",
            post(post_source_inbox_verify),
        )
        .route(
            "/source-inbox/{record_id}/create-task",
            post(post_source_inbox_create_task),
        )
        .route("/incidents", get(page_incidents))
        .route("/proof", get(page_proof_center))
        .route("/frontier/answer-book", get(page_frontier_answer_book))
        .route(
            "/frontier/answer-book.json",
            get(page_frontier_answer_book_json),
        )
        .route("/frontier/use-map", get(page_frontier_use_map))
        .route("/frontier/use-map.json", get(page_frontier_use_map_json))
        .route("/frontier/questions", get(page_frontier_questions))
        .route(
            "/frontier/questions.json",
            get(page_frontier_questions_json),
        )
        .route(
            "/frontier/questions/{question_id}",
            get(page_frontier_question_detail),
        )
        .route("/frontier/answer-paths", get(page_frontier_answer_paths))
        .route(
            "/frontier/answer-paths.json",
            get(page_frontier_answer_paths_json),
        )
        .route(
            "/frontier/decision-grade",
            get(page_frontier_decision_grade),
        )
        .route(
            "/frontier/decision-grade.json",
            get(page_frontier_decision_grade_json),
        )
        .route("/frontier/reviewer-demo", get(page_frontier_reviewer_demo))
        .route(
            "/frontier/reviewer-demo.json",
            get(page_frontier_reviewer_demo_json),
        )
        .route(
            "/frontier/reviewer-demo/questions/{question_id}",
            get(page_frontier_reviewer_demo_question_detail),
        )
        .route(
            "/frontier/decision-grade/{trail_slug}",
            get(page_frontier_decision_trail_detail),
        )
        .route(
            "/frontier/answer-paths/{answer_id}",
            get(page_frontier_answer_path_detail),
        )
        .route("/frontier/findings/{vf_id}", get(page_finding_detail))
        .route("/frontier/sources/{source_id}", get(page_source_detail))
        .route("/frontier/proof", get(page_proof_center))
        .route("/frontier/returns", get(page_external_proof_loop))
        .route("/frontier/benchmarks", get(page_frontier_benchmarks))
        .route("/frontier/demo", get(page_frontier_scientist_demo))
        .route(
            "/frontier/demo.json",
            get(page_frontier_scientist_demo_json),
        )
        .route(
            "/frontier/demo/paths/{path_id}",
            get(page_frontier_scientist_demo_path_detail),
        )
        .route("/frontier/graph", get(page_frontier_graph))
        .route("/frontier/graph.json", get(page_frontier_graph_json))
        .route(
            "/frontier/graph/nodes/{node_id}",
            get(page_frontier_graph_node_detail),
        )
        .route(
            "/frontier/graph/traversals/{traversal_id}",
            get(page_frontier_graph_traversal_detail),
        )
        .route("/graph/path", get(page_graph_path))
        .route("/health/frontier", get(page_frontier_health))
        .route("/sources", get(page_sources))
        .route("/sources/{source_id}", get(page_source_detail))
        .route("/audit", get(page_audit))
        .route("/bridges", get(page_bridges))
        .route("/bridges/{vbr_id}/confirm", post(post_bridge_confirm))
        .route("/bridges/{vbr_id}/refute", post(post_bridge_refute))
        // v0.54: surface the v0.49–v0.51 primitives that the kernel
        // already supports but the read+write UI was blind to.
        .route("/negative-results", get(page_negative_results))
        .route("/trajectories", get(page_trajectories))
        .route("/tiers", get(page_tiers))
        // v0.55: live constellation visualization with cascade firing.
        // The marketing site has had a static SVG render for a while
        // (vela-hub's render_findings_constellation); the Workbench
        // now mounts the same render with click-to-navigate to the
        // existing /findings/{vf_id} detail page, plus an interactive
        // cascade-firing slider that POSTs to /api/propagate.
        .route("/constellation", get(page_constellation))
        .route(
            "/api/propagate/{vf_id}",
            post(post_api_propagate_confidence),
        )
        // v0.55 Phase D: time-travel replay: per-finding confidence
        // sparkline + event timeline. The CLI side is `vela history
        // <vf> --as-of <ts>`; this is the visual surface.
        .route("/replay/{vf_id}", get(page_replay))
        // v0.174: review-thread surface. Read-only list of every
        // `vrt_*` thread under <frontier>/.vela/review-threads/.
        // Threads are append-only signed comment chains posted via
        // `vela review-thread create/post`. Workbench is read-only
        // for now; CLI is the write surface.
        .route("/threads", get(page_threads_list))
        .route("/threads/{thread_id}", get(page_thread_detail))
        // v0.203: Diff Pack reviewer surface. Localhost-only.
        // GET lists every signed vsd_* on the frontier with its
        // current pending-verdict state (if any). The detail page
        // renders the pack body + member proposals + verdict form.
        // POST handlers write a pending verdict to
        // .vela/pending_verdicts/<vpv_id>.json. The v0.205 cycle
        // promotes pending verdicts to canonical events through
        // the new `diff_pack.reviewed` reducer arm.
        .route("/diff-packs", get(page_diff_packs_list))
        .route("/diff-packs/{pack_id}", get(page_diff_pack_detail))
        .route("/diff-packs/{pack_id}/accept", post(post_diff_pack_accept))
        .route("/diff-packs/{pack_id}/reject", post(post_diff_pack_reject))
        .route("/diff-packs/{pack_id}/revise", post(post_diff_pack_revise))
        .route("/diff-packs/{pack_id}/attest", post(post_diff_pack_attest))
        // v0.219: conflict reviewer surface. Localhost-only.
        // GET /conflicts lists candidate contradictions + already-
        // resolved vdc_* records side by side. The resolve flow
        // stays on the CLI (`vela conflict resolve`) per the
        // existing pending-verdict doctrine.
        .route("/conflicts", get(page_conflicts_list))
        // v0.229: unified verdict timeline. Renders pending
        // verdicts (vpv_*), resolved verdicts on packs (via
        // released_diff_packs), and vdc_* resolutions in a
        // single chronological view. Closes the operator loop
        // for "what verdicts are in flight, what's settled,
        // what's contested." Read-only.
        .route("/verdicts", get(page_verdicts_timeline))
        // v0.57: localhost-only curation write surface for the new
        // protocol primitives. Public site stays read-only; these
        // routes only respond on 127.0.0.1.
        .route("/review/cockpit", get(page_review_cockpit))
        .route("/review/work", get(page_review_work))
        .route("/review/work.json", get(page_review_work_json))
        .route("/demo/first-user", get(page_first_user_demo))
        .route("/demo/first-user.json", get(page_first_user_demo_json))
        .route("/demo/score-return", get(page_score_return_preview))
        .route(
            "/demo/score-return.json",
            get(page_score_return_preview_json),
        )
        .route("/demo/external-review", get(page_external_review_packet))
        .route(
            "/demo/external-review.json",
            get(page_external_review_packet_json),
        )
        .route("/demo/external-proof-loop", get(page_external_proof_loop))
        .route(
            "/demo/external-proof-loop.json",
            get(page_external_proof_loop_json),
        )
        .route("/demo/adjudication", get(page_adjudication_cockpit))
        .route(
            "/demo/adjudication.json",
            get(page_adjudication_cockpit_json),
        )
        .route("/review/inbox", get(page_review_inbox))
        .route("/review/session", get(page_review_session))
        .route("/review/session.json", get(page_review_session_json))
        .route(
            "/review/locator-repair/{atom_id}",
            get(page_review_locator_repair),
        )
        .route("/review/locator-repair", post(post_review_locator_repair))
        .route(
            "/review/span-repair/{finding_id}",
            get(page_review_span_repair),
        )
        .route("/review/span-repair", post(post_review_span_repair))
        .route(
            "/review/entity-resolve/{finding_id}",
            get(page_review_entity_resolve),
        )
        .route("/review/entity-resolve", post(post_review_entity_resolve))
        // v0.59: promote-to-accepted-core write surface. Sends the
        // canonical finding.review event under the configured
        // reviewer identity. No bulk affordance; one finding per
        // submission.
        .route("/review/promote/{finding_id}", get(page_review_promote))
        .route("/review/promote", post(post_review_promote))
        // v0.59: federation conflict-resolution write surface.
        // Records the reviewer's verdict on a previously detected
        // conflict as a paired `frontier.conflict_resolved` event.
        .route(
            "/review/conflict-resolve/{conflict_event_id}",
            get(page_review_conflict_resolve),
        )
        .route(
            "/review/conflict-resolve",
            post(post_review_conflict_resolve),
        )
        // v0.71: replication + prediction deposit write surfaces.
        // Reviewer attaches a Replication or Prediction record to a
        // finding via the substrate's v0.70 event-driven deposit
        // path (replication.deposited / prediction.deposited).
        .route(
            "/review/replication-add/{finding_id}",
            get(page_review_replication_add),
        )
        .route("/review/replication-add", post(post_review_replication_add))
        .route(
            "/review/prediction-add/{finding_id}",
            get(page_review_prediction_add),
        )
        .route("/review/prediction-add", post(post_review_prediction_add))
        .route("/static/tokens.css", get(static_tokens_css))
        .route("/static/workbench.css", get(static_workbench_css))
        .route("/static/favicon.svg", get(static_favicon_svg))
        .route("/healthz", get(healthz))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let addr: SocketAddr = ([127, 0, 0, 1], port).into();
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(|e| format!("failed to bind {addr}: {e}"))?;
    let actual_addr = listener.local_addr().unwrap_or(addr);
    let url = format!("http://{actual_addr}/");

    println!("vela workbench listening on {url}");
    if open_browser && let Err(e) = open_browser_at(&url) {
        eprintln!("(could not auto-open browser: {e})");
    }
    println!("Ctrl-C to stop.");

    axum::serve(listener, app)
        .await
        .map_err(|e| format!("axum serve: {e}"))
}

fn open_browser_at(url: &str) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    let cmd = "open";
    #[cfg(target_os = "linux")]
    let cmd = "xdg-open";
    #[cfg(target_os = "windows")]
    let cmd = "explorer";

    std::process::Command::new(cmd)
        .arg(url)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("{cmd}: {e}"))
}

// ── HTML helpers ─────────────────────────────────────────────────────

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// W1.5: minimal percent-encoder for path segments. Atom and
/// finding ids are typically alphanumeric plus `:` `_` `-`, but a
/// stray space or `?` would break the redirect URL. Encode any
/// byte outside the unreserved set.
fn urlencode_path(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b':' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn shell(active: &str, title: &str, eyebrow: &str, page_title: &str, body: &str) -> String {
    let nav = |id: &str, href: &str, label: &str| -> String {
        let on = if id == active {
            " wb-rim__link--on"
        } else {
            ""
        };
        format!(r#"<a class="wb-rim__link{on}" href="{href}">{label}</a>"#)
    };
    let constellation_nav = [
        nav("tiers", "/tiers", "09 · Tiers"),
        nav("bridges", "/bridges", "10 · Bridges"),
        nav("constellation", "/constellation", "11 · Constellation"),
        nav("threads", "/threads", "12 · Threads"),
        nav("diff-packs", "/diff-packs", "13 · Diff packs"),
        nav("conflicts", "/conflicts", "15 · Conflicts"),
        nav("verdicts", "/verdicts", "16 · Verdicts"),
    ]
    .join("");
    let review_nav = format!(
        "{}{}{}{}",
        nav("review-cockpit", "/review/cockpit", "14 · Review cockpit"),
        nav(
            "review-sessions",
            "/review/sessions",
            "15 · Review sessions"
        ),
        nav("review-work", "/review/work", "16 · Review work"),
        nav("incidents", "/incidents", "17 · Incidents")
    );
    let rim = format!(
        r#"<aside class="wb-rim">
  <div class="wb-rim__mark">
    <a class="wb-rim__brand" href="/" aria-label="Vela workbench">
      <span class="wb-rim__glyph">v</span>
      <span>
        <span class="wb-rim__brand-title">Vela workbench</span>
        <span class="wb-rim__brand-subtitle">local frontier review</span>
      </span>
    </a>
  </div>
  <nav class="wb-rim__nav" aria-label="Workbench">
    {l1}
    {l2}
    {l3}
    {l4}
    {l5}
    {l6}
    {l7}
    {l8}
    {l9}
    {l10}
    {l11}
    {l12}
    {l13}
    {l14}
    {l15}
  </nav>
  <div class="wb-rim__index">v{ver}</div>
</aside>"#,
        l1 = nav("dashboard", "/", "01 · Dashboard"),
        l2 = nav("decision", "/decision", "02 · Decision"),
        l3 = nav("findings", "/findings", "03 · Findings"),
        l4 = nav("proposals", "/proposals", "04 · Proposals"),
        l5 = nav("packets", "/artifact-packets", "05 · Packets"),
        l6 = nav("nulls", "/negative-results", "06 · Nulls"),
        l7 = nav("trajectories", "/trajectories", "07 · Trajectories"),
        l8 = nav("tasks", "/tasks", "08 · Tasks"),
        l9 = nav("source-inbox", "/source-inbox", "09 · Source inbox"),
        l10 = nav("proof", "/proof", "10 · Proof"),
        l11 = nav("frontier-health", "/health/frontier", "11 · Health"),
        l12 = nav("sources", "/sources", "12 · Sources"),
        l13 = nav("audit", "/audit", "13 · Audit"),
        l14 = constellation_nav,
        l15 = review_nav,
        ver = WB_VERSION,
    );
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title_safe}</title>
<link rel="icon" type="image/svg+xml" href="/static/favicon.svg">
<link rel="stylesheet" href="/static/tokens.css">
<link rel="stylesheet" href="/static/workbench.css">
<style>
  :root {{ color-scheme: light; }}
  * {{ box-sizing: border-box; }}
  body {{ margin: 0; font-family: var(--font-sans, var(--font-text, system-ui, sans-serif)); color: var(--ink-1, #202838); background: var(--paper-0, var(--bg-1, #f6f4ef)); -webkit-font-smoothing: antialiased; }}
  .wb {{ display: grid; grid-template-columns: minmax(220px, 15.5rem) minmax(0, 1fr); min-width: 0; min-height: 100vh; }}
  .wb-rim {{ position: sticky; top: 0; align-self: start; min-height: 100vh; padding: 1rem 0.85rem; border-right: 1px solid var(--rule-2, #d8d4cc); background: linear-gradient(180deg, var(--paper-1, #fbf8f1), var(--paper-0, #f6f4ef)); }}
  .wb-rim::before {{ content: ""; display: block; height: 1px; margin: 0 0 1rem 0; background: linear-gradient(90deg, transparent, var(--gold, #c8a45d), transparent); opacity: 0.72; }}
  .wb-rim__mark {{ margin-bottom: 1rem; }}
  .wb-rim__brand {{ display: grid; grid-template-columns: 2rem minmax(0, 1fr); gap: 0.65rem; align-items: center; color: var(--ink-0, #182131); text-decoration: none; border-radius: 10px; padding: 0.45rem; }}
  .wb-rim__brand:focus-visible, .wb-rim__link:focus-visible, a:focus-visible, button:focus-visible, input:focus-visible, select:focus-visible, textarea:focus-visible {{ outline: 2px solid var(--gold, #c8a45d); outline-offset: 2px; }}
  .wb-rim__glyph {{ display: grid; place-items: center; width: 2rem; height: 2rem; border-radius: 8px; border: 1px solid var(--rule-3, #b7ae9a); background: var(--ink-0, #182131); color: var(--paper-1, #fbf8f1); font-family: var(--font-mono, ui-monospace, Menlo, monospace); font-size: 0.72rem; font-weight: 700; letter-spacing: 0; }}
  .wb-rim__brand-title {{ display: block; font-size: 0.92rem; font-weight: 600; line-height: 1.1; }}
  .wb-rim__brand-subtitle {{ display: block; margin-top: 0.1rem; font-family: var(--font-mono, ui-monospace, Menlo, monospace); font-size: 0.62rem; color: var(--ink-3, #6d7280); letter-spacing: 0.02em; }}
  .wb-rim__nav {{ display: flex; flex-direction: column; gap: 0.22rem; padding-top: 0.7rem; border-top: 1px solid var(--rule-1, #ebe4d8); }}
  .wb-rim__link {{ position: relative; display: block; font-size: 0.86rem; color: var(--ink-2, #3f4a5a); text-decoration: none; padding: 0.44rem 0.55rem; border-radius: 6px; transition: background 180ms cubic-bezier(0.20, 0, 0.13, 1), color 180ms cubic-bezier(0.20, 0, 0.13, 1); }}
  .wb-rim__link:hover {{ color: var(--ink-0, #182131); background: color-mix(in oklch, var(--paper-2, #ece3d2) 60%, transparent); }}
  .wb-rim__link--on {{ color: var(--ink-0, #182131); background: var(--paper-2, var(--bg-3, #ebe6dd)); font-weight: 600; box-shadow: inset 2px 0 0 var(--gold, #c8a45d); }}
  .wb-rim__index {{ margin-top: 1.5rem; padding: 0.65rem 0.55rem 0; border-top: 1px solid var(--rule-1, #ebe4d8); color: var(--ink-4, #8b8f98); font-size: 0.72rem; font-family: var(--font-mono, ui-monospace, Menlo, monospace); }}
  .wb-content {{ width: min(100%, 1180px); max-width: 100%; min-width: 0; padding: clamp(1.25rem, 3.5vw, 3rem); }}
  .wb-eyebrow {{ position: relative; display: inline-block; font-family: var(--font-mono, ui-monospace, Menlo, monospace); font-size: 0.68rem; text-transform: uppercase; letter-spacing: 0.08em; color: var(--ink-3, #6d7280); margin-bottom: 0.55rem; padding-top: 0.55rem; }}
  .wb-eyebrow::before {{ content: ""; position: absolute; left: 0; top: 0; width: 6.5rem; height: 1px; background: linear-gradient(90deg, var(--gold, #c8a45d), transparent); }}
  .wb-title {{ font-family: var(--font-display, Georgia, serif); font-size: var(--text-h1, 28px); font-weight: 400; margin: 0 0 1.15rem 0; line-height: 1.12; color: var(--ink-0, #182131); max-width: 46rem; }}
  .wb-hero {{ position: relative; overflow: hidden; margin: 0 0 1.25rem 0; padding: clamp(1rem, 2.2vw, 1.5rem); border: 1px solid var(--rule-2, #d8d4cc); border-radius: 14px; background: linear-gradient(135deg, var(--paper-1, #fbf8f1), var(--paper-0, #f6f4ef)); }}
  .wb-hero::before {{ content: ""; display: block; height: 1px; margin-bottom: 1rem; background: linear-gradient(90deg, transparent, var(--gold, #c8a45d), transparent); opacity: 0.62; }}
  .wb-hero__grid {{ display: grid; grid-template-columns: minmax(0, 1.35fr) minmax(15rem, 0.65fr); gap: 1rem; align-items: start; }}
  .wb-hero h2 {{ margin: 0; font-family: var(--font-display, Georgia, serif); font-size: 1.55rem; font-weight: 400; color: var(--ink-0, #182131); }}
  .wb-hero p {{ margin: 0.45rem 0 0; color: var(--ink-2, #3f4a5a); line-height: 1.55; max-width: 62ch; }}
  .wb-action-row {{ display: flex; flex-wrap: wrap; gap: 0.55rem; margin-top: 1rem; }}
  .wb-button {{ display: inline-flex; align-items: center; justify-content: center; min-height: 2.15rem; padding: 0.45rem 0.75rem; border: 1px solid var(--rule-3, #b7ae9a); border-radius: 6px; background: var(--ink-0, #182131); color: var(--paper-1, #fbf8f1); text-decoration: none; font-size: 0.86rem; font-weight: 600; }}
  .wb-button--quiet {{ background: transparent; color: var(--ink-1, #202838); }}
  .wb-status-panel {{ display: grid; gap: 0.5rem; padding: 0.75rem; border-radius: 12px; border: 1px solid var(--rule-2, #d8d4cc); background: color-mix(in oklch, var(--paper-2, #ece3d2) 50%, transparent); }}
  .wb-status-panel div {{ display: flex; justify-content: space-between; gap: 1rem; font-size: 0.84rem; color: var(--ink-2, #3f4a5a); }}
  .wb-status-panel strong {{ color: var(--ink-0, #182131); font-family: var(--font-mono, ui-monospace, Menlo, monospace); font-size: 0.78rem; }}
  .wb-stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 0.75rem; margin: 1rem 0 1.25rem 0; }}
  .wb-stats > div {{ min-width: 0; padding: 0.82rem 0.9rem; border: 1px solid var(--rule-2, #d8d4cc); border-radius: 12px; background: var(--paper-1, var(--bg-2, #f5f2ec)); }}
  .wb-stat__num {{ font-family: var(--font-mono, ui-monospace, Menlo, monospace); font-size: 1.2rem; font-weight: 600; color: var(--ink-0, #182131); letter-spacing: 0; overflow-wrap: anywhere; }}
  .wb-stat__label {{ margin-top: 0.25rem; font-family: var(--font-mono, ui-monospace, Menlo, monospace); font-size: 0.66rem; text-transform: uppercase; letter-spacing: 0.06em; color: var(--ink-3, #6d7280); }}
  .wb-card {{ max-width: 100%; min-width: 0; overflow-x: auto; border: 1px solid var(--rule-2, #d8d4cc); border-radius: 12px; padding: 0.95rem 1rem; margin: 0 0 0.85rem 0; background: var(--paper-1, #fbf8f1); }}
  .wb-card h3 {{ margin: 0 0 0.45rem 0; font-size: 1rem; color: var(--ink-0, #182131); }}
  .wb-card p {{ margin: 0.25rem 0; font-size: 0.92rem; line-height: 1.55; color: var(--ink-2, #3f4a5a); }}
  .wb-mutation-preview {{ max-width: 100%; min-width: 0; overflow-x: auto; border: 1px solid var(--rule-2, #d8d4cc); border-left: 3px solid var(--gold, #c8a45d); border-radius: 10px; padding: 0.75rem 0.85rem; margin: 0.3rem 0 0.75rem 0; background: color-mix(in oklch, var(--paper-2, #ece3d2) 42%, transparent); }}
  .wb-mutation-preview h3 {{ margin: 0 0 0.35rem 0; font-size: 0.92rem; color: var(--ink-0, #182131); }}
  .wb-mutation-preview p {{ margin: 0.2rem 0; font-size: 0.84rem; line-height: 1.45; color: var(--ink-2, #3f4a5a); }}
  .wb-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 0.85rem; margin: 0 0 1rem 0; }}
  .wb-chip {{ display: inline-block; padding: 0.14em 0.58em; border-radius: 999px; font-family: var(--font-mono, ui-monospace, Menlo, monospace); font-size: 0.66rem; text-transform: uppercase; letter-spacing: 0.06em; margin-right: 0.45em; border: 1px solid transparent; vertical-align: 0.08em; }}
  .wb-chip--ok {{ background: color-mix(in oklch, var(--state-ok, #4e7a4c) 16%, transparent); color: var(--state-ok, #2f5d3a); border-color: color-mix(in oklch, var(--state-ok, #4e7a4c) 28%, transparent); }}
  .wb-chip--warn {{ background: color-mix(in oklch, var(--state-warn, #9b7426) 18%, transparent); color: var(--state-warn, #8a6d1f); border-color: color-mix(in oklch, var(--state-warn, #9b7426) 30%, transparent); }}
  .wb-chip--lost {{ background: color-mix(in oklch, var(--state-lost, #a33b2b) 16%, transparent); color: var(--state-lost, #872c2c); border-color: color-mix(in oklch, var(--state-lost, #a33b2b) 30%, transparent); }}
  .wb-table {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; margin: 0.4rem 0 0; }}
  .wb-table th, .wb-table td {{ text-align: left; padding: 0.58rem 0.65rem; border-bottom: 1px solid var(--rule-1, #ebe4d8); vertical-align: top; }}
  .wb-table th {{ font-family: var(--font-mono, ui-monospace, Menlo, monospace); font-size: 0.66rem; text-transform: uppercase; letter-spacing: 0.06em; color: var(--ink-3, #6d7280); font-weight: 500; }}
  .wb-table tr:hover td {{ background: color-mix(in oklch, var(--paper-2, #ece3d2) 34%, transparent); }}
  .wb-actions form {{ display: inline-block; margin-right: 0.4em; }}
  .wb-actions--stacked {{ display: grid; gap: 0.7rem; }}
  .wb-actions--stacked form {{ display: grid; grid-template-columns: minmax(12rem, 0.55fr) minmax(16rem, 1fr) auto; gap: 0.55rem; align-items: end; margin: 0; padding: 0.75rem 0; border-top: 1px solid var(--rule-1, #ebe4d8); }}
  .wb-review-rail {{ border-left: 3px solid var(--gold, #c8a45d); }}
  .wb-review-rail__commands {{ display: grid; gap: 0.45rem; margin-top: 0.6rem; }}
  .wb-review-rail__objects {{ display: flex; flex-wrap: wrap; gap: 0.35rem; margin-top: 0.5rem; }}
  .wb-decision-form label {{ display: grid; gap: 0.3rem; color: var(--ink-3, #6d7280); font-size: 0.76rem; font-family: var(--font-mono, ui-monospace, Menlo, monospace); text-transform: uppercase; letter-spacing: 0.04em; }}
  .wb-decision-form input {{ width: 100%; font-family: var(--font-sans, system-ui, sans-serif); font-size: 0.9rem; text-transform: none; letter-spacing: 0; }}
  input, select, textarea {{ font: inherit; color: var(--ink-1, #202838); border: 1px solid var(--rule-2, #d8d4cc); border-radius: 6px; background: var(--paper-1, #fbf8f1); padding: 0.43rem 0.52rem; }}
  button, .wb-actions button {{ font-family: inherit; font-size: 0.82rem; min-height: 2rem; padding: 0.34rem 0.72rem; border: 1px solid var(--rule-3, #b7ae9a); background: var(--paper-1, #fbf8f1); color: var(--ink-0, #182131); cursor: pointer; border-radius: 6px; }}
  button:hover, .wb-actions button:hover {{ background: var(--paper-2, #ece3d2); }}
  pre {{ overflow: auto; padding: 0.85rem; border: 1px solid var(--rule-1, #ebe4d8); border-radius: 10px; background: var(--paper-2, #ece3d2); }}
  code {{ font-family: var(--font-mono, ui-monospace, Menlo, monospace); background: var(--paper-2, var(--bg-3, #ebe6dd)); padding: 0.05em 0.3em; border-radius: 4px; font-size: 0.88em; overflow-wrap: anywhere; }}
  blockquote {{ color: var(--ink-2, #3f4a5a); font-size: 0.92rem; margin: 0.55rem 0; border-left: 2px solid var(--gold, #c8a45d); padding: 0.05rem 0 0.05rem 0.8rem; }}
  a {{ color: var(--ink-0, #182131); text-underline-offset: 0.17em; }}
  @media (max-width: 860px) {{
    .wb {{ display: block; }}
    .wb-rim {{ position: static; min-height: auto; border-right: 0; border-bottom: 1px solid var(--rule-2, #d8d4cc); }}
    .wb-rim__nav {{ max-width: 100%; min-width: 0; flex-direction: row; flex-wrap: nowrap; overflow-x: auto; padding-bottom: 0.3rem; }}
    .wb-rim__link {{ white-space: nowrap; }}
    .wb-content {{ padding: 1.25rem; }}
    .wb-table {{ display: block; max-width: 100%; overflow-x: auto; }}
    .wb-hero__grid {{ grid-template-columns: 1fr; }}
    .wb-actions--stacked form {{ grid-template-columns: 1fr; }}
    .wb-actions form {{ display: grid; gap: 0.5rem; width: 100%; margin: 0 0 0.6rem 0; }}
  }}
</style>
</head>
<body>
<div class="wb">
{rim}
<main class="wb-content">
  <div class="wb-eyebrow">{eyebrow}</div>
  <h1 class="wb-title">{page_title}</h1>
  {body}
</main>
</div>
</body>
</html>
"#,
        title_safe = escape_html(title),
    )
}

fn frontier_label(p: &Project) -> String {
    p.project.name.clone()
}

fn workspace_root_for(repo_path: &Path) -> PathBuf {
    let mut dir = repo_path
        .canonicalize()
        .unwrap_or_else(|_| repo_path.to_path_buf());
    if dir.is_file() {
        dir.pop();
    }
    loop {
        if dir.join("benchmarks").is_dir() && dir.join("Cargo.toml").is_file() {
            return dir;
        }
        if !dir.pop() {
            return std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        }
    }
}

fn load_workspace_json(repo_path: &Path, rel_path: &str) -> Option<serde_json::Value> {
    let path = workspace_root_for(repo_path).join(rel_path);
    let body = fs::read_to_string(path).ok()?;
    serde_json::from_str(&body).ok()
}

fn load_frontier_json(repo_path: &Path, rel_path: &str) -> Option<serde_json::Value> {
    let path = repo_path.join(rel_path);
    let body = fs::read_to_string(path).ok()?;
    serde_json::from_str(&body).ok()
}

fn frontier_index_backing(repo_path: &Path, fallback_source: &str) -> serde_json::Value {
    let db_path = repo_path
        .join(".vela")
        .join("index")
        .join("frontier-index.sqlite");
    let report_path = repo_path
        .join(".vela")
        .join("index")
        .join("frontier-index.report.v1.json");
    let present = db_path.is_file() && report_path.is_file();
    serde_json::json!({
        "present": present,
        "source": if present { "frontier_index" } else { fallback_source },
        "database_path": db_path.display().to_string(),
        "report_path": report_path.display().to_string(),
        "database_is_authority": false,
        "canonical_state": index_db_schema::CANONICAL_STATE,
        "fallback_source": fallback_source,
        "fallback_counts_from_files": !present,
        "boundary": "The index is a rebuildable read model. Canonical state remains frontier files and accepted events.",
    })
}

fn attach_frontier_index_backing(
    mut payload: serde_json::Value,
    repo_path: &Path,
    fallback_source: &str,
) -> serde_json::Value {
    if let Some(obj) = payload.as_object_mut() {
        obj.insert(
            "index_backing".to_string(),
            frontier_index_backing(repo_path, fallback_source),
        );
    }
    payload
}

fn dashboard_draft_event_count(repo_path: &Path) -> usize {
    load_workspace_json(
        repo_path,
        "benchmarks/public/score-returns/review-event-drafts/score-return.review-event-drafts.v1.json",
    )
    .and_then(|value| {
        value
            .get("draft_review_events")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len)
    })
    .unwrap_or(0)
}

fn dashboard_benchmark_status(repo_path: &Path) -> (String, usize, usize) {
    let Some(value) = load_workspace_json(
        repo_path,
        "benchmarks/public/anti-amyloid-score-ledger.v1.json",
    ) else {
        return ("not available".to_string(), 0, 0);
    };
    let summary = value.get("summary").unwrap_or(&serde_json::Value::Null);
    let status = summary
        .get("claim_status")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let local_returns = summary
        .get("local_returns")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0) as usize;
    let external_returns = summary
        .get("external_returns")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0) as usize;
    (status, local_returns, external_returns)
}

// ── Pages ────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct StartQuery {
    show_start: Option<String>,
}

async fn page_dashboard(
    State(state): State<AppState>,
    Query(query): Query<StartQuery>,
) -> Response {
    let repo_path = state.repo_path.clone();
    let project = match repo::load_from_path(&repo_path) {
        Ok(p) => p,
        Err(e) => return error_page("dashboard", "Could not load frontier", &e),
    };
    let label = frontier_label(&project);

    let mut pending = 0usize;
    let mut by_kind: BTreeMap<String, usize> = BTreeMap::new();
    for p in &project.proposals {
        if p.status == "pending_review" {
            pending += 1;
            *by_kind.entry(p.kind.clone()).or_insert(0) += 1;
        }
    }

    let audit = audit_frontier(&project);
    let audit_summary = summarize_audit(&audit);
    let proof_status = match project.proof_state.latest_packet.status.as_str() {
        "current" | "fresh" => "fresh",
        "never_exported" => "not exported",
        "stale" => "stale",
        other if other.trim().is_empty() => "unknown",
        other => other,
    };
    let proof_generated = project
        .proof_state
        .latest_packet
        .generated_at
        .as_deref()
        .map(|s| s.chars().take(10).collect::<String>())
        .unwrap_or_else(|| "n/a".to_string());
    let task_summary = frontier_task::task_summary(&repo_path);
    let source_inbox_summary = source_inbox::source_inbox_summary(&repo_path);
    let review_debt = pending + audit_summary.underidentified + audit_summary.conditional;
    let health = frontier_health::analyze(&repo_path).ok();
    let draft_event_count = dashboard_draft_event_count(&repo_path);
    let (benchmark_status, benchmark_local_returns, benchmark_external_returns) =
        dashboard_benchmark_status(&repo_path);
    let locator_debt = project
        .sources
        .iter()
        .filter(|source| {
            source.locator.trim().is_empty()
                && source.doi.as_deref().unwrap_or("").trim().is_empty()
                && source.pmid.as_deref().unwrap_or("").trim().is_empty()
        })
        .count();
    let evidence_source_debt = project
        .evidence_atoms
        .iter()
        .filter(|atom| atom.source_id.trim().is_empty())
        .count();
    let source_debt = source_inbox_summary.total
        + source_inbox_summary.stale
        + source_inbox_summary.quarantined
        + locator_debt
        + evidence_source_debt;
    let frontier_health_label = health
        .as_ref()
        .map(|report| if report.ok { "ok" } else { "needs review" })
        .unwrap_or("unknown");
    let frontier_health_issues = health
        .as_ref()
        .map(|report| report.issues.len())
        .unwrap_or(0);

    let bridges = list_bridges(&repo_path);
    let bridge_total = bridges.len();
    let bridge_confirmed = bridges
        .iter()
        .filter(|b| b.status == BridgeStatus::Confirmed)
        .count();
    let bridge_derived = bridges
        .iter()
        .filter(|b| b.status == BridgeStatus::Derived)
        .count();

    let mut targets_with_success = std::collections::HashSet::new();
    let mut failed_replications = 0usize;
    for r in &project.replications {
        if r.outcome == "replicated" {
            targets_with_success.insert(r.target_finding.clone());
        } else if r.outcome == "failed" {
            failed_replications += 1;
        }
    }

    // v0.54: surface NR + trajectory counts at the dashboard level
    // so the new primitives are discoverable without first browsing
    // their dedicated pages.
    let stats_html = format!(
        r#"<div class="wb-stats">
  <div><div class="wb-stat__num">{}</div><div class="wb-stat__label">findings</div></div>
  <div><div class="wb-stat__num">{}</div><div class="wb-stat__label">nulls</div></div>
  <div><div class="wb-stat__num">{}</div><div class="wb-stat__label">trajectories</div></div>
  <div><div class="wb-stat__num">{}</div><div class="wb-stat__label">events</div></div>
</div>
<div class="wb-stats" style="margin-top:0.6rem;">
  <div><div class="wb-stat__num">{}</div><div class="wb-stat__label">pending</div></div>
  <div><div class="wb-stat__num">{}</div><div class="wb-stat__label">bridges</div></div>
  <div><div class="wb-stat__num">{}</div><div class="wb-stat__label">restricted</div></div>
  <div><div class="wb-stat__num">{}</div><div class="wb-stat__label">classified</div></div>
</div>"#,
        project.findings.len(),
        project.negative_results.len(),
        project.trajectories.len(),
        project.events.len(),
        pending,
        bridge_total,
        project
            .findings
            .iter()
            .filter(|f| matches!(f.access_tier, vela_protocol::access_tier::AccessTier::Restricted))
            .count()
            + project
                .negative_results
                .iter()
                .filter(|n| matches!(n.access_tier, vela_protocol::access_tier::AccessTier::Restricted))
                .count()
            + project
                .trajectories
                .iter()
                .filter(|t| matches!(t.access_tier, vela_protocol::access_tier::AccessTier::Restricted))
                .count(),
        project
            .findings
            .iter()
            .filter(|f| matches!(f.access_tier, vela_protocol::access_tier::AccessTier::Classified))
            .count()
            + project
                .negative_results
                .iter()
                .filter(|n| matches!(n.access_tier, vela_protocol::access_tier::AccessTier::Classified))
                .count()
            + project
                .trajectories
                .iter()
                .filter(|t| matches!(t.access_tier, vela_protocol::access_tier::AccessTier::Classified))
                .count(),
    );

    let hero_html = format!(
        r#"<section class="wb-hero" aria-label="Workbench summary">
  <div class="wb-hero__grid">
    <div>
      <h2>Daily cockpit</h2>
      <p>Start here for the current frontier. This screen brings review queues, source debt, draft events, proof freshness, benchmark status, and frontier health into one read-only surface.</p>
      <div class="wb-action-row">
        <a class="wb-button" href="/review/cockpit">Open review cockpit</a>
        <a class="wb-button" href="/review/work">Open work queues</a>
        <a class="wb-button wb-button--quiet" href="/review/inbox">Open review inbox</a>
        <a class="wb-button wb-button--quiet" href="/health/frontier">Check frontier health</a>
        <a class="wb-button wb-button--quiet" href="/findings">Browse findings</a>
        <a class="wb-button wb-button--quiet" href="/frontier/decision-grade">Decision-grade frontier</a>
        <a class="wb-button wb-button--quiet" href="/proposals">Inspect proposals</a>
        <a class="wb-button wb-button--quiet" href="/demo/external-review">External review</a>
        <a class="wb-button wb-button--quiet" href="/audit">Run the audit</a>
      </div>
    </div>
    <div class="wb-status-panel" aria-label="Frontier health">
      <div><span>Proof packet</span><strong>{proof_status}</strong></div>
      <div><span>Generated</span><strong>{proof_generated}</strong></div>
      <div><span>Active tasks</span><strong>{task_active}</strong></div>
      <div><span>Source inbox</span><strong>{source_inbox}</strong></div>
      <div><span>Review debt</span><strong>{review_debt}</strong></div>
      <div><span>Draft events</span><strong>{draft_events}</strong></div>
      <div><span>Benchmark</span><strong>{benchmark_status}</strong></div>
      <div><span>Frontier id</span><strong>{frontier_id}</strong></div>
    </div>
  </div>
</section>"#,
        proof_status = escape_html(proof_status),
        proof_generated = escape_html(&proof_generated),
        task_active = task_summary.active,
        source_inbox = source_inbox_summary.total,
        review_debt = review_debt,
        draft_events = draft_event_count,
        benchmark_status = escape_html(&benchmark_status),
        frontier_id = escape_html(&project.frontier_id()),
    );

    let start_screen = format!(
        r#"<section aria-label="Daily cockpit start screen">
  <h3>Daily cockpit start screen</h3>
  <p>This is the first screen for review work. It is read-only and does not count as review.</p>
  <div class="wb-grid" aria-label="Daily cockpit signals">
    <div class="wb-card">
      <h3>Review queues</h3>
      <p><strong>{review_debt}</strong> review-debt signal(s) · <strong>{pending}</strong> pending proposal(s) · <strong>{active_tasks}</strong> active task(s).</p>
      <p><a href="/review/work">Open review work</a></p>
    </div>
    <div class="wb-card">
      <h3>Source debt</h3>
      <p><strong>{source_debt}</strong> source-debt signal(s): <strong>{source_inbox}</strong> inbox record(s), <strong>{stale_sources}</strong> stale, <strong>{quarantined_sources}</strong> quarantined, <strong>{locator_debt}</strong> locator gap(s), <strong>{evidence_source_debt}</strong> evidence source gap(s).</p>
      <p><a href="/source-inbox">Open source inbox</a></p>
    </div>
    <div class="wb-card">
      <h3>Draft events</h3>
      <p><strong>{draft_events}</strong> draft review-event record(s) are review material. They are not accepted frontier state until a reviewer action accepts them.</p>
      <p><a href="/demo/adjudication">Open adjudication</a></p>
    </div>
    <div class="wb-card">
      <h3>Proof freshness</h3>
      <p>Latest packet status is <code>{proof_status}</code>. Generated <code>{proof_generated}</code>.</p>
      <p><a href="/proof">Open proof</a></p>
    </div>
    <div class="wb-card">
      <h3>Benchmark status</h3>
      <p><code>{benchmark_status}</code> · <strong>{benchmark_local_returns}</strong> local return(s) · <strong>{benchmark_external_returns}</strong> external return(s).</p>
      <p><a href="/review/work">Open benchmark review</a> · <a href="/demo/external-review">Open external review packet</a></p>
    </div>
    <div class="wb-card">
      <h3>Frontier health</h3>
      <p><code>{frontier_health_label}</code> · <strong>{frontier_health_issues}</strong> issue row(s) · <strong>{evidence_failures}</strong> Evidence CI failure(s) · <strong>{evidence_warnings}</strong> warning(s).</p>
      <p><a href="/health/frontier">Open health</a></p>
    </div>
  </div>
</section>"#,
        review_debt = review_debt,
        pending = pending,
        active_tasks = task_summary.active,
        source_debt = source_debt,
        source_inbox = source_inbox_summary.total,
        stale_sources = source_inbox_summary.stale,
        quarantined_sources = source_inbox_summary.quarantined,
        locator_debt = locator_debt,
        evidence_source_debt = evidence_source_debt,
        draft_events = draft_event_count,
        proof_status = escape_html(proof_status),
        proof_generated = escape_html(&proof_generated),
        benchmark_status = escape_html(&benchmark_status),
        benchmark_local_returns = benchmark_local_returns,
        benchmark_external_returns = benchmark_external_returns,
        frontier_health_label = escape_html(frontier_health_label),
        frontier_health_issues = frontier_health_issues,
        evidence_failures = health
            .as_ref()
            .map(|report| report.metrics.evidence_ci_failures)
            .unwrap_or(0),
        evidence_warnings = health
            .as_ref()
            .map(|report| report.metrics.evidence_ci_warnings)
            .unwrap_or(0),
    );

    let daily_path = r#"<div class="wb-card">
  <h3>Daily review path</h3>
  <p>Use this path when a reader or reviewer has no prior Vela context.</p>
  <div class="wb-grid" aria-label="Daily review path">
    <div class="wb-card"><h3>01 answer</h3><p>Start from the bounded field answer and its caveats.</p></div>
    <div class="wb-card"><h3>02 support finding</h3><p>Open the finding bundle that carries the answer.</p></div>
    <div class="wb-card"><h3>03 trial artifact</h3><p>Inspect the source or artifact record behind the finding.</p></div>
    <div class="wb-card"><h3>04 event trail</h3><p>Follow the canonical events that changed frontier state.</p></div>
    <div class="wb-card"><h3>05 rejected import</h3><p>Show that runtime output remains source material until review.</p></div>
    <div class="wb-card"><h3>06 open gap</h3><p>Keep unresolved evidence visible as frontier work.</p></div>
    <div class="wb-card"><h3>07 proof</h3><p>End on packet freshness, hashes, and replay checks.</p></div>
  </div>
</div>"#;

    let queue_priority = format!(
        r#"<div class="wb-grid" aria-label="Review queue by priority">
  <div class="wb-card">
    <h3>Review queue by priority</h3>
    <p><strong>{pending}</strong> proposal(s) pending · <strong>{underidentified}</strong> underidentified audit item(s) · <strong>{conditional}</strong> conditional audit item(s).</p>
    <p><a href="/review/work">Open work queues →</a> · <a href="/review/inbox">Open review inbox →</a></p>
  </div>
  <div class="wb-card">
    <h3>Frontier tasks</h3>
    <p><strong>{task_active}</strong> active · <strong>{task_blocked}</strong> blocked · <strong>{task_review}</strong> awaiting review.</p>
    <p><a href="/tasks">Open tasks →</a></p>
  </div>
  <div class="wb-card">
    <h3>Source inbox</h3>
    <p><strong>{source_total}</strong> records · <strong>{source_quarantined}</strong> quarantined · <strong>{source_retracted}</strong> retracted · <strong>{source_task_linked}</strong> task-linked.</p>
    <p><a href="/source-inbox">Open source inbox →</a></p>
  </div>
  <div class="wb-card">
    <h3>Proof freshness</h3>
    <p>Latest packet is <code>{proof_status}</code>. Any accepted proposal should be followed by a fresh proof export before sharing.</p>
    <p><code>vela proof FRONTIER --out /tmp/vela-proof</code></p>
  </div>
</div>"#,
        pending = pending,
        underidentified = audit_summary.underidentified,
        conditional = audit_summary.conditional,
        task_active = task_summary.active,
        task_blocked = task_summary.blocked,
        task_review = task_summary.awaiting_review,
        source_total = source_inbox_summary.total,
        source_quarantined = source_inbox_summary.quarantined,
        source_retracted = source_inbox_summary.retracted,
        source_task_linked = source_inbox_summary.task_linked,
        proof_status = escape_html(proof_status),
    );

    let mut cards = String::new();

    if pending > 0 {
        let parts: Vec<String> = by_kind
            .iter()
            .map(|(k, n)| format!("<code>{n}</code> {}", escape_html(k)))
            .collect();
        cards.push_str(&format!(
            r#"<div class="wb-card">
  <h3><span class="wb-chip wb-chip--warn">inbox</span>{} pending proposals</h3>
  <p>{}</p>
  <p><a href="/audit">Open audit →</a></p>
</div>"#,
            pending,
            parts.join(" · ")
        ));
    }

    if audit_summary.underidentified > 0 || audit_summary.conditional > 0 {
        let chip_kind = if audit_summary.underidentified > 0 {
            "lost"
        } else {
            "warn"
        };
        cards.push_str(&format!(
            r#"<div class="wb-card">
  <h3><span class="wb-chip wb-chip--{chip}">audit</span>identifiability</h3>
  <p><strong>{}</strong> underidentified · <strong>{}</strong> conditional · <strong>{}</strong> identified</p>
  <p><a href="/audit">Open audit →</a></p>
</div>"#,
            audit_summary.underidentified,
            audit_summary.conditional,
            audit_summary.identified,
            chip = chip_kind,
        ));
    }

    if bridge_total > 0 {
        cards.push_str(&format!(
            r#"<div class="wb-card">
  <h3><span class="wb-chip wb-chip--ok">bridges</span>cross-frontier composition</h3>
  <p><strong>{bridge_total}</strong> total · <strong>{bridge_confirmed}</strong> confirmed · <strong>{bridge_derived}</strong> awaiting review</p>
  <p><a href="/bridges">Open bridges →</a></p>
</div>"#
        ));
    }

    if !project.replications.is_empty() {
        cards.push_str(&format!(
            r#"<div class="wb-card">
  <h3><span class="wb-chip wb-chip--ok">replications</span>empirical bedrock</h3>
  <p><strong>{}</strong> records · <strong>{}</strong> findings replicated · <strong>{}</strong> failed</p>
</div>"#,
            project.replications.len(),
            targets_with_success.len(),
            failed_replications
        ));
    }

    cards.push_str(&format!(
        r#"<div class="wb-card">
  <h3><span class="wb-chip wb-chip--warn">causal</span>Causal map health</h3>
  <p><strong>{attention}</strong> audit item(s) need attention · <strong>{links}</strong> link(s) · <strong>{bridges}</strong> bridge candidate(s).</p>
  <p><a href="/audit">Causal audit</a> · <a href="/bridges">Open bridges</a> · <a href="/health/frontier">Frontier health</a></p>
</div>"#,
        attention = audit_summary.underidentified + audit_summary.conditional,
        links = project.stats.links,
        bridges = bridge_total,
    ));

    cards.push_str(
        r#"<div class="wb-card">
  <h3><span class="wb-chip wb-chip--warn">route</span>Causal map routing</h3>
  <p>Route causal-map work through review queues, source intake, tasks, audit, bridges, and proof before sharing.</p>
  <p><a href="/review/work">Review work</a> · <a href="/source-inbox">Source inbox</a> · <a href="/tasks">Tasks</a></p>
  <p><a href="/audit">Causal audit</a> · <a href="/bridges">Open bridges</a> · <a href="/health/frontier">Frontier health</a></p>
</div>"#,
    );

    let next_actions = r#"<div class="wb-grid" aria-label="Workbench paths">
  <div class="wb-card">
    <h3>Review queue</h3>
    <p>Find missing locators, thin evidence spans, entity flags, link gaps, pending verdicts, and federation conflicts in one place.</p>
    <p><a href="/review/work">Open work queues →</a> · <a href="/review/inbox">Open the queue →</a></p>
  </div>
  <div class="wb-card">
    <h3>Proposal history</h3>
    <p>Check runtime output before it becomes frontier state. Preview the state diff, then accept, reject, or request revision.</p>
    <p><a href="/proposals">Open proposals →</a></p>
  </div>
  <div class="wb-card">
    <h3>Frontier audit</h3>
    <p>Inspect identifiability, causal caveats, access tiers, and review coverage before proof export or sharing.</p>
    <p><a href="/audit">Open audit →</a></p>
  </div>
</div>"#;

    let first_path = if project.events.is_empty() || query.show_start.as_deref() == Some("1") {
        first_frontier_path_html(&repo_path, false)
    } else {
        String::new()
    };
    let route_map = first_frontier_route_map_html(&repo_path);
    let command_copy = render_command_copy(
        "First-user commands",
        &[
            format!("vela stats {}/frontier.json", repo_path.display()),
            format!("vela index status {} --json", repo_path.display()),
            format!("vela proof {} --out /tmp/vela-proof", repo_path.display()),
        ],
    );
    let body = format!(
        "{hero_html}{start_screen}{command_copy}{stats_html}{route_map}{first_path}{daily_path}{queue_priority}{next_actions}{cards}"
    );

    Html(shell(
        "dashboard",
        &format!("Vela workbench · {label}"),
        "Workbench",
        &escape_html(&label),
        &body,
    ))
    .into_response()
}

async fn page_decision_brief(State(state): State<AppState>) -> Response {
    let project = match repo::load_from_path(&state.repo_path) {
        Ok(p) => p,
        Err(e) => return error_page("decision", "Could not load frontier", &e),
    };
    let projection = decision::load_decision_brief(&state.repo_path, &project);
    let Some(brief) = projection.projection.as_ref() else {
        let issues = projection
            .issues
            .iter()
            .map(|issue| {
                format!(
                    r#"<li><code>{}</code>: {}</li>"#,
                    escape_html(&issue.path),
                    escape_html(&issue.message)
                )
            })
            .collect::<String>();
        let error = projection
            .error
            .as_deref()
            .unwrap_or("Decision brief unavailable.");
        let body = format!(
            r#"<div class="wb-card">
  <h3><span class="wb-chip wb-chip--warn">decision</span>Decision brief unavailable</h3>
  <p>{}</p>
  <ul>{}</ul>
  <p><code>vela decision-brief {} --json</code></p>
</div>"#,
            escape_html(error),
            issues,
            escape_html(&state.repo_path.display().to_string())
        );
        return Html(shell(
            "decision",
            "decision",
            "Workbench",
            "Decision brief",
            &body,
        ))
        .into_response();
    };

    let issue_rows = if projection.issues.is_empty() {
        r#"<tr><td colspan="2">No projection issues.</td></tr>"#.to_string()
    } else {
        projection
            .issues
            .iter()
            .map(|issue| {
                format!(
                    r#"<tr><td><code>{}</code></td><td>{}</td></tr>"#,
                    escape_html(&issue.path),
                    escape_html(&issue.message)
                )
            })
            .collect::<String>()
    };

    let render_id_links = |ids: &[String]| -> String {
        if ids.is_empty() {
            return "none".to_string();
        }
        ids.iter()
            .map(|id| {
                format!(
                    r#"<a href="/findings/{}"><code>{}</code></a>"#,
                    urlencode_path(id),
                    escape_html(id)
                )
            })
            .collect::<Vec<_>>()
            .join(" ")
    };

    let mut question_cards = String::new();
    for question in &brief.questions {
        let tags = if question.tags.is_empty() {
            String::new()
        } else {
            question
                .tags
                .iter()
                .map(|tag| {
                    format!(
                        r#"<span class="wb-chip wb-chip--ok">{}</span>"#,
                        escape_html(tag)
                    )
                })
                .collect::<Vec<_>>()
                .join(" ")
        };
        let correction_rows = if question.correction_paths.is_empty() {
            r#"<tr><td colspan="3">No correction paths recorded for this question.</td></tr>"#
                .to_string()
        } else {
            question
                .correction_paths
                .iter()
                .map(|path| {
                    format!(
                        r#"<tr><td><a href="/findings/{finding_href}"><code>{finding_id}</code></a></td><td>{summary}</td><td>{status}</td></tr>"#,
                        finding_href = urlencode_path(&path.finding_id),
                        finding_id = escape_html(&path.finding_id),
                        summary = escape_html(&path.summary),
                        status = escape_html(&path.status),
                    )
                })
                .collect::<String>()
        };
        let basis_rows = if question.evidence_basis.is_empty() {
            r#"<tr><td colspan="5">No source-backed basis rows recorded for this question.</td></tr>"#
                .to_string()
        } else {
            question
                .evidence_basis
                .iter()
                .map(|basis| {
                    format!(
                        r#"<tr><td>{role}</td><td><a href="/findings/{finding_href}"><code>{finding_id}</code></a></td><td><code>{locator}</code></td><td>{review}</td><td>{caveat}</td></tr>"#,
                        role = escape_html(&basis.role),
                        finding_href = urlencode_path(&basis.finding_id),
                        finding_id = escape_html(&basis.finding_id),
                        locator = escape_html(&basis.source_locator),
                        review = escape_html(&basis.review_status),
                        caveat = escape_html(&basis.caveat),
                    )
                })
                .collect::<String>()
        };
        question_cards.push_str(&format!(
            r#"<div class="wb-card">
  <h3><span class="wb-chip wb-chip--ok">decision</span>{title}</h3>
  <p>{short_answer}</p>
  <p><strong>Confidence:</strong> {confidence}</p>
  <p><strong>Caveat:</strong> {caveat}</p>
  <p><strong>What would change this answer:</strong> {change}</p>
  <p>{tags}</p>
  <table class="wb-table">
    <thead><tr><th>role</th><th>finding ids</th></tr></thead>
    <tbody>
      <tr><td>supporting</td><td>{supporting}</td></tr>
      <tr><td>tensions</td><td>{tensions}</td></tr>
      <tr><td>gaps</td><td>{gaps}</td></tr>
    </tbody>
  </table>
  <table class="wb-table">
    <thead><tr><th colspan="5">Source-backed basis</th></tr><tr><th>role</th><th>finding</th><th>locator</th><th>review</th><th>caveat</th></tr></thead>
    <tbody>{basis_rows}</tbody>
  </table>
  <table class="wb-table">
    <thead><tr><th>correction path</th><th>summary</th><th>status</th></tr></thead>
    <tbody>{correction_rows}</tbody>
  </table>
</div>"#,
            title = escape_html(&question.title),
            short_answer = escape_html(&question.short_answer),
            confidence = escape_html(&question.confidence),
            caveat = escape_html(&question.caveat),
            change = escape_html(&question.what_would_change_this_answer),
            tags = tags,
            supporting = render_id_links(&question.supporting_findings),
            tensions = render_id_links(&question.tension_findings),
            gaps = render_id_links(&question.gap_findings),
            basis_rows = basis_rows,
            correction_rows = correction_rows,
        ));
    }

    let status_chip = if projection.ok { "ok" } else { "warn" };
    let fallback_frontier_id = project.frontier_id();
    let boundary_html = brief
        .projection_boundary
        .as_ref()
        .map(|boundary| {
            format!(
                r#"<div class="wb-card">
  <h3><span class="wb-chip wb-chip--warn">boundary</span>Projection boundary</h3>
  <p>Status: <code>{status}</code>. Reviewer profile: <code>{reviewer_profile}</code>.</p>
  <p>Medical guidance: <code>{medical}</code>. Outside review claimed: <code>{outside}</code>.</p>
  <p>{policy}</p>
</div>"#,
                status = escape_html(&boundary.status),
                reviewer_profile = escape_html(&boundary.reviewer_profile),
                medical = boundary.counts_as_medical_guidance,
                outside = boundary.outside_review_claimed,
                policy = escape_html(&boundary.agent_confidence_policy),
            )
        })
        .unwrap_or_default();
    let body = format!(
        r#"<div class="wb-card">
  <h3><span class="wb-chip wb-chip--{status_chip}">decision</span>Decision state</h3>
  <p>This page renders the frontier-owned decision brief. It is not medical advice and does not replace reviewer adjudication.</p>
  <p>Frontier: <code>{frontier_id}</code>. Questions: <code>{question_count}</code>. Updated: <code>{updated_at}</code>.</p>
  <p><code>vela decision-brief {frontier_path} --json</code></p>
</div>
{boundary_html}
<div class="wb-card">
  <h3>Projection issues</h3>
  <table class="wb-table"><thead><tr><th>path</th><th>message</th></tr></thead><tbody>{issue_rows}</tbody></table>
</div>
{question_cards}"#,
        status_chip = status_chip,
        frontier_id = escape_html(
            brief
                .frontier_id
                .as_deref()
                .unwrap_or(&fallback_frontier_id)
        ),
        question_count = brief.questions.len(),
        updated_at = escape_html(&brief.updated_at),
        frontier_path = escape_html(&state.repo_path.display().to_string()),
        boundary_html = boundary_html,
        issue_rows = issue_rows,
        question_cards = question_cards,
    );

    Html(shell(
        "decision",
        "decision",
        "Workbench",
        "Decision brief",
        &body,
    ))
    .into_response()
}

async fn page_start(State(state): State<AppState>) -> Response {
    let project = match repo::load_from_path(&state.repo_path) {
        Ok(p) => p,
        Err(e) => return error_page("start", "Could not load frontier", &e),
    };
    let body = format!(
        "{}{}{}",
        first_frontier_route_map_html(&state.repo_path),
        first_frontier_path_html(&state.repo_path, true),
        adoption_friction_form_html(&state.repo_path, "/start")
    );
    Html(shell(
        "start",
        &format!("First frontier path · {}", frontier_label(&project)),
        "Workbench",
        "First frontier path",
        &body,
    ))
    .into_response()
}

async fn page_ask(State(state): State<AppState>) -> Response {
    let project = match repo::load_from_path(&state.repo_path) {
        Ok(p) => p,
        Err(e) => return error_page("ask", "Could not load frontier", &e),
    };
    let frontier_path = state.repo_path.display().to_string();
    let body = format!(
        r#"<div class="wb-card">
  <h3>Ask this frontier</h3>
  <p>Questions are routing prompts over local frontier state. This page does not write review events and does not change accepted frontier state.</p>
  <div class="wb-grid">
    <div class="wb-card">
      <h3>Inspect</h3>
      <p><code>vela ask {frontier_path} "what needs review first?"</code></p>
    </div>
    <div class="wb-card">
      <h3>Correct</h3>
      <p><code>vela ask {frontier_path} "which claims need source repair?"</code></p>
    </div>
    <div class="wb-card">
      <h3>Prove</h3>
      <p><code>vela ask {frontier_path} "is proof fresh enough to share?"</code></p>
    </div>
    <div class="wb-card">
      <h3>Distribute</h3>
      <p><code>vela ask {frontier_path} "what should ship in the release packet?"</code></p>
    </div>
  </div>
  <p>Answers are local orientation. They are not treatment advice, not target validation, and not patient stratification.</p>
</div>"#,
        frontier_path = escape_html(&frontier_path),
    );
    Html(shell(
        "ask",
        &format!("Ask · {}", frontier_label(&project)),
        "Workbench",
        "Ask",
        &body,
    ))
    .into_response()
}

async fn page_transcript(State(state): State<AppState>) -> Response {
    let transcript = match vela_edge::adoption_transcript::build(&state.repo_path) {
        Ok(transcript) => transcript,
        Err(e) => return error_page("transcript", "Could not build adoption transcript", &e),
    };
    let body = format!(
        r#"<div class="wb-card">
  <h3>Adoption transcript</h3>
  <p>Operational first-review commands for this local frontier. These commands inspect state; write actions still require explicit reviewer identity and reason.</p>
  <pre><code>{markdown}</code></pre>
</div>{friction_form}"#,
        markdown = escape_html(&transcript.markdown),
        friction_form = adoption_friction_form_html(&state.repo_path, "/transcript"),
    );
    Html(shell(
        "transcript",
        "Adoption transcript · Vela workbench",
        "Workbench",
        "Adoption transcript",
        &body,
    ))
    .into_response()
}

async fn page_review_sessions(State(state): State<AppState>) -> Response {
    let list = match review_session::list(&state.repo_path) {
        Ok(list) => list,
        Err(e) => return error_page("review-sessions", "Could not load review sessions", &e),
    };
    let rows = if list.sessions.is_empty() {
        r#"<tr><td colspan="6" class="wb-empty">No local review sessions. Start one with <code>vela review-session start FRONTIER --reviewer reviewer:external --scope diff_pack:vsd_ID</code>.</td></tr>"#.to_string()
    } else {
        list.sessions
            .iter()
            .map(|session| {
                format!(
                    r#"<tr>
  <td><a href="/review/sessions/{id}"><code>{id}</code></a></td>
  <td>{status}</td>
  <td><code>{reviewer}</code></td>
  <td>{scope}</td>
  <td>{objects}</td>
  <td>{notes}</td>
</tr>"#,
                    id = escape_html(&session.id),
                    status = escape_html(session.status.as_str()),
                    reviewer = escape_html(&session.reviewer_id),
                    scope = escape_html(&session.scope),
                    objects = session.objects_reviewed.len(),
                    notes = session.notes.len(),
                )
            })
            .collect()
    };
    let body = format!(
        r#"<div class="wb-card">
  <h3>Reviewer sessions</h3>
  <p>Local records of outside review work. Sessions collect scope, notes, decisions, unresolved objections, and follow-up tasks without changing accepted frontier state.</p>
  <dl class="wb-meta">
    <dt>frontier</dt><dd><code>{frontier}</code></dd>
    <dt>sessions</dt><dd>{total}</dd>
    <dt>open</dt><dd>{open}</dd>
    <dt>closed</dt><dd>{terminal}</dd>
    <dt>CLI</dt><dd><code>vela review-session list {frontier_path} --json</code></dd>
  </dl>
  <table class="wb-table">
    <thead><tr><th>session</th><th>status</th><th>reviewer</th><th>scope</th><th>objects</th><th>notes</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div>"#,
        frontier = escape_html(&list.frontier_id),
        frontier_path = escape_html(&state.repo_path.display().to_string()),
        total = list.total,
        open = list.open,
        terminal = list.terminal,
        rows = rows,
    );
    Html(shell(
        "review-sessions",
        "Review sessions · Vela workbench",
        "Workbench",
        "Review sessions",
        &body,
    ))
    .into_response()
}

async fn page_review_session_detail(
    AxumPath(session_id): AxumPath<String>,
    State(state): State<AppState>,
) -> Response {
    let session = match review_session::load(&state.repo_path, &session_id) {
        Ok(session) => session,
        Err(e) => return error_page("review-sessions", "Could not load review session", &e),
    };
    let object_rows = if session.objects_reviewed.is_empty() {
        r#"<li class="wb-empty">No objects recorded yet.</li>"#.to_string()
    } else {
        session
            .objects_reviewed
            .iter()
            .map(|object| format!(r#"<li>{}</li>"#, review_session_object_link(object)))
            .collect()
    };
    let note_rows = if session.notes.is_empty() {
        r#"<tr><td colspan="3" class="wb-empty">No notes recorded yet.</td></tr>"#.to_string()
    } else {
        session
            .notes
            .iter()
            .map(|note| {
                format!(
                    r#"<tr><td>{object}</td><td>{note}</td><td>{at}</td></tr>"#,
                    object = review_session_object_link(&note.object_id),
                    note = escape_html(&note.note),
                    at = escape_html(&note.created_at),
                )
            })
            .collect()
    };
    let decision_rows = if session.decisions.is_empty() {
        r#"<tr><td colspan="3" class="wb-empty">No terminal decision recorded.</td></tr>"#
            .to_string()
    } else {
        session
            .decisions
            .iter()
            .map(|decision| {
                format!(
                    r#"<tr><td>{decision}</td><td>{reason}</td><td>{at}</td></tr>"#,
                    decision = escape_html(decision.decision.as_str()),
                    reason = escape_html(&decision.reason),
                    at = escape_html(&decision.decided_at),
                )
            })
            .collect()
    };
    let follow_ups = if session.follow_up_tasks.is_empty() {
        r#"<li class="wb-empty">No follow-up tasks linked.</li>"#.to_string()
    } else {
        session
            .follow_up_tasks
            .iter()
            .map(|task| format!(r#"<li>{}</li>"#, review_session_object_link(task)))
            .collect()
    };
    let transcript = session
        .transcript_path
        .as_deref()
        .map(escape_html)
        .unwrap_or_else(|| "none recorded".to_string());
    let body = format!(
        r#"<div class="wb-card">
  <h3>Review session <code>{id}</code></h3>
  <p>Local review record. Closing a session records reviewer work; it does not accept or reject frontier truth by itself.</p>
  <dl class="wb-meta">
    <dt>status</dt><dd>{status}</dd>
    <dt>reviewer</dt><dd><code>{reviewer}</code></dd>
    <dt>scope</dt><dd>{scope}</dd>
    <dt>started</dt><dd>{started}</dd>
    <dt>ended</dt><dd>{ended}</dd>
    <dt>transcript</dt><dd>{transcript}</dd>
    <dt>CLI</dt><dd><code>vela review-session show {frontier_path} {id} --json</code></dd>
  </dl>
</div>
<div class="wb-card">
  <h3>Objects reviewed</h3>
  <ul class="wb-list">{object_rows}</ul>
</div>
<div class="wb-card">
  <h3>Notes</h3>
  <table class="wb-table"><thead><tr><th>object</th><th>note</th><th>at</th></tr></thead><tbody>{note_rows}</tbody></table>
</div>
<div class="wb-card">
  <h3>Decision</h3>
  <table class="wb-table"><thead><tr><th>decision</th><th>reason</th><th>at</th></tr></thead><tbody>{decision_rows}</tbody></table>
</div>
<div class="wb-card">
  <h3>Follow-up tasks</h3>
  <ul class="wb-list">{follow_ups}</ul>
</div>"#,
        id = escape_html(&session.id),
        status = escape_html(session.status.as_str()),
        reviewer = escape_html(&session.reviewer_id),
        scope = escape_html(&session.scope),
        started = escape_html(&session.started_at),
        ended = escape_html(session.ended_at.as_deref().unwrap_or("open")),
        transcript = transcript,
        frontier_path = escape_html(&state.repo_path.display().to_string()),
        object_rows = object_rows,
        note_rows = note_rows,
        decision_rows = decision_rows,
        follow_ups = follow_ups,
    );
    Html(shell(
        "review-sessions",
        &format!("Review session {session_id} · Vela workbench"),
        "Workbench",
        "Review session",
        &body,
    ))
    .into_response()
}

fn review_session_object_link(object_id: &str) -> String {
    let safe = escape_html(object_id);
    if object_id.starts_with("vsd_") {
        format!(r#"<a href="/diff-packs/{safe}"><code>{safe}</code></a>"#)
    } else if object_id.starts_with("vtask_") {
        format!(r#"<a href="/tasks/{safe}/workspace"><code>{safe}</code></a>"#)
    } else if object_id.starts_with("vf_") {
        format!(r#"<a href="/findings/{safe}"><code>{safe}</code></a>"#)
    } else {
        format!(r#"<code>{safe}</code>"#)
    }
}

fn render_evidence_ci_groups(report: &evidence_ci::EvidenceCiReport) -> String {
    let rows = report
        .summary
        .groups
        .iter()
        .map(|group| {
            format!(
                r#"<tr><td><code>{group}</code></td><td>{total}</td><td>{release_blocking}</td><td>{review_warning}</td><td>{info}</td><td>{blocking}</td></tr>"#,
                group = escape_html(&group.group),
                total = group.total,
                release_blocking = group.release_blocking,
                review_warning = group.review_warning,
                info = group.info,
                blocking = group.release_blocking_failed,
            )
        })
        .collect::<Vec<_>>()
        .join("");
    format!(
        r#"<table class="wb-table"><thead><tr><th>group</th><th>checks</th><th>release blocking</th><th>review warnings</th><th>info</th><th>blocking failures</th></tr></thead><tbody>{rows}</tbody></table>"#
    )
}

#[derive(Debug, Deserialize)]
struct AdoptionFrictionForm {
    step: String,
    category: Option<String>,
    kind: String,
    note: String,
    redirect: Option<String>,
}

async fn post_adoption_friction(
    State(state): State<AppState>,
    Form(form): Form<AdoptionFrictionForm>,
) -> Response {
    if let Err(e) = adoption_log::log_with_category(
        &state.repo_path,
        &form.step,
        form.category.as_deref(),
        &form.kind,
        &form.note,
    ) {
        return error_page(
            "adoption friction",
            "Could not record adoption friction",
            &e,
        );
    }
    let redirect = form
        .redirect
        .filter(|value| value.starts_with('/'))
        .unwrap_or_else(|| "/start".to_string());
    Redirect::to(&redirect).into_response()
}

async fn page_adoption_friction(State(state): State<AppState>) -> Response {
    let list = match adoption_log::list(&state.repo_path) {
        Ok(list) => list,
        Err(e) => return error_page("adoption friction", "Could not load friction log", &e),
    };
    let mut open_rows = String::new();
    let mut closed_rows = String::new();
    for record in &list.records {
        let row = format!(
            r#"<tr><td><code>{id}</code></td><td>{category}</td><td>{kind}</td><td>{step}</td><td>{task}</td><td>{note}</td></tr>"#,
            id = escape_html(&record.id),
            category = escape_html(&record.category),
            kind = escape_html(&record.kind),
            step = escape_html(&record.step),
            task = record
                .linked_task_id
                .as_deref()
                .map(|id| format!(r#"<a href="/tasks/{id}/workspace"><code>{id}</code></a>"#))
                .unwrap_or_else(|| "none".to_string()),
            note = escape_html(&record.note),
        );
        if record.status == "closed" {
            closed_rows.push_str(&row);
        } else {
            open_rows.push_str(&row);
        }
    }
    if open_rows.is_empty() {
        open_rows.push_str(
            r#"<tr><td colspan="6" class="wb-empty">No open adoption friction records.</td></tr>"#,
        );
    }
    if closed_rows.is_empty() {
        closed_rows.push_str(
            r#"<tr><td colspan="6" class="wb-empty">No closed adoption friction records.</td></tr>"#,
        );
    }
    let form = adoption_friction_form_html(&state.repo_path, "/adoption/friction");
    let body = format!(
        r#"<div class="wb-card">
  <h3>Adoption friction</h3>
  <p>Local review notes that can become follow-up tasks. These records stay in this frontier unless explicitly included in a share package.</p>
</div>
<div class="wb-stats">
  <div><div class="wb-stat__num">{open}</div><div class="wb-stat__label">open</div></div>
  <div><div class="wb-stat__num">{closed}</div><div class="wb-stat__label">closed</div></div>
  <div><div class="wb-stat__num">{linked}</div><div class="wb-stat__label">linked to task</div></div>
</div>
{form}
<div class="wb-card">
  <h3>Open records</h3>
  <table class="wb-table"><thead><tr><th>id</th><th>category</th><th>kind</th><th>step</th><th>task</th><th>note</th></tr></thead><tbody>{open_rows}</tbody></table>
</div>
<div class="wb-card">
  <h3>Closed records</h3>
  <table class="wb-table"><thead><tr><th>id</th><th>category</th><th>kind</th><th>step</th><th>task</th><th>note</th></tr></thead><tbody>{closed_rows}</tbody></table>
</div>"#,
        open = list.summary.open,
        closed = list.summary.closed,
        linked = list.summary.linked_to_task,
        form = form,
        open_rows = open_rows,
        closed_rows = closed_rows,
    );
    Html(shell(
        "adoption-friction",
        "Adoption friction · Vela workbench",
        "Workbench",
        "Adoption friction",
        &body,
    ))
    .into_response()
}

fn adoption_friction_form_html(repo_path: &Path, redirect: &str) -> String {
    let summary = adoption_log::list(repo_path)
        .map(|list| list.summary)
        .unwrap_or_default();
    let options = adoption_log::valid_kinds()
        .iter()
        .map(|kind| format!(r#"<option value="{kind}">{kind}</option>"#))
        .collect::<String>();
    let categories = adoption_log::valid_categories()
        .iter()
        .map(|category| format!(r#"<option value="{category}">{category}</option>"#))
        .collect::<String>();
    format!(
        r#"<div class="wb-card">
  <h3>Record friction</h3>
  <p>Local-only notes about confusing steps, missing docs, slow commands, trust blockers, or useful objects. These records stay in this frontier.</p>
  <form method="post" action="/adoption/friction" class="wb-form">
    <input type="hidden" name="redirect" value="{redirect}">
    <label>Step <input name="step" required placeholder="source-inbox"></label>
    <label>Category <select name="category">{categories}</select></label>
    <label>Kind <select name="kind">{options}</select></label>
    <label>Note <textarea name="note" required rows="3" placeholder="What happened?"></textarea></label>
    <button type="submit">Record friction</button>
  </form>
  <p>{open} open friction record(s), {closed} closed.</p>
</div>"#,
        redirect = escape_html(redirect),
        categories = categories,
        options = options,
        open = summary.open,
        closed = summary.closed,
    )
}

fn first_frontier_path_html(repo_path: &Path, include_empty_states: bool) -> String {
    let project = match repo::load_from_path(repo_path) {
        Ok(project) => project,
        Err(_) => return String::new(),
    };
    let source_total = source_inbox::source_inbox_summary(repo_path).total;
    let task_total = frontier_task::task_summary(repo_path).total;
    let diff_pack_total = list_released_diff_packs(&project, repo_path).len();
    let review_packet_total =
        count_non_readme_files(&repo_path.join(".vela").join("review_packets"));
    let proof_status = project.proof_state.latest_packet.status.as_str();
    let proof_label = match proof_status {
        "current" | "fresh" => "fresh",
        "never_exported" => "not exported",
        "stale" => "stale",
        other if other.trim().is_empty() => "unknown",
        other => other,
    };
    let steps = [
        (
            "01",
            "Check frontier health",
            Some("/health/frontier"),
            format!("vela frontier health {} --json", repo_path.display()),
        ),
        (
            "02",
            "Add or verify sources",
            Some("/source-inbox"),
            format!(
                "vela source-inbox resolve {} --doi 10.1056/NEJMoa2212948 --json",
                repo_path.display()
            ),
        ),
        (
            "03",
            "Create or claim a task",
            Some("/tasks"),
            format!(
                "vela task create {} --type source_ingestion --objective \"Review source impact\" --status eligible --json",
                repo_path.display()
            ),
        ),
        (
            "04",
            "Initialize task workspace",
            Some("/tasks"),
            format!(
                "vela task workspace init {} vtask_ID --json",
                repo_path.display()
            ),
        ),
        (
            "05",
            "Run Evidence CI",
            Some("/health/frontier"),
            format!("vela evidence-ci {} --json", repo_path.display()),
        ),
        (
            "06",
            "Inspect Diff Pack",
            Some("/diff-packs"),
            format!(
                "vela diff-pack validate {} vsd_ID --evidence-ci --json",
                repo_path.display()
            ),
        ),
        (
            "07",
            "Build review packet",
            Some("/tasks"),
            format!(
                "vela review-packet build {} vtask_ID --json",
                repo_path.display()
            ),
        ),
        (
            "08",
            "Record review or attestation",
            Some("/review/inbox"),
            "Use the local review form with reviewer id and reason.".to_string(),
        ),
        (
            "09",
            "Export proof",
            Some("/proof"),
            format!("vela proof {} --out /tmp/vela-proof", repo_path.display()),
        ),
        (
            "10",
            "Build share package",
            None,
            format!(
                "vela share build {} --out /tmp/vela-share",
                repo_path.display()
            ),
        ),
    ];
    let step_rows = steps
        .iter()
        .map(|(index, label, href, cli)| {
            let target = href
                .map(|href| format!(r#"<a href="{href}">{}</a>"#, escape_html(label)))
                .unwrap_or_else(|| escape_html(label));
            format!(
                r#"<tr><td><code>{index}</code></td><td>{target}</td><td><code>{cli}</code></td></tr>"#,
                index = escape_html(index),
                target = target,
                cli = escape_html(cli),
            )
        })
        .collect::<String>();
    let empty_states = if include_empty_states {
        format!(
            r#"<div class="wb-grid">
  <div class="wb-card"><h3>Sources</h3><p>{sources}</p></div>
  <div class="wb-card"><h3>Tasks</h3><p>{tasks}</p></div>
  <div class="wb-card"><h3>Diff Packs</h3><p>{packs}</p></div>
  <div class="wb-card"><h3>Proof packet</h3><p>{proof}</p></div>
  <div class="wb-card"><h3>Review packets</h3><p>{review_packets}</p></div>
</div>"#,
            sources = if source_total == 0 {
                "No source-inbox records yet. Resolve or import source locators first.".to_string()
            } else {
                format!("{source_total} source record(s) waiting for review.")
            },
            tasks = if task_total == 0 {
                "No local tasks yet. Create one from a source record or objective.".to_string()
            } else {
                format!("{task_total} local task(s) on disk.")
            },
            packs = if diff_pack_total == 0 {
                "No Diff Packs yet. Proposed state changes should appear here before review."
                    .to_string()
            } else {
                format!("{diff_pack_total} Diff Pack(s) available for review.")
            },
            proof = if proof_label == "not exported" || proof_label == "unknown" {
                "No current proof packet. Export proof before sharing.".to_string()
            } else {
                format!("Proof status: {proof_label}.")
            },
            review_packets = if review_packet_total == 0 {
                "No generated review packets yet. Build one from a task workspace.".to_string()
            } else {
                format!("{review_packet_total} review packet file(s) on disk.")
            },
        )
    } else {
        String::new()
    };
    format!(
        r#"<div class="wb-card">
  <h3>First frontier path</h3>
  <p>Use this path when a reviewer is opening this local frontier for the first time. Every write action stays local and requires an explicit command or review form.</p>
  <table class="wb-table">
    <thead><tr><th>step</th><th>surface</th><th>CLI equivalent</th></tr></thead>
    <tbody>{step_rows}</tbody>
  </table>
</div>{empty_states}"#
    )
}

fn first_frontier_route_map_html(_repo_path: &Path) -> String {
    let routes = [
        (
            "Daily cockpit",
            "/",
            "Start with the dashboard view of source debt, trace review, benchmark scoring, correction return, and proof packet work.",
        ),
        (
            "Review action queue",
            "/review/work",
            "Open the local queue that mirrors review/frontier-action-queue.v1.json before changing state.",
        ),
        (
            "Correct",
            "/review/inbox",
            "Use local review forms and explicit reasons before any accepted correction event.",
        ),
        (
            "Prove",
            "/proof",
            "Check proof packet freshness, hashes, and replay status before sharing.",
        ),
        (
            "Distribute",
            "/artifact-packets",
            "Inspect packet material that can be copied into release assets or dataset mirrors.",
        ),
        (
            "Ask",
            "/ask",
            "Ask bounded questions that route work back to source, review, proof, or packet surfaces.",
        ),
    ];
    let route_cards = routes
        .iter()
        .map(|(label, href, description)| {
            format!(
                r#"<div class="wb-card">
  <h3><a href="{href}">{label}</a></h3>
  <p>{description}</p>
</div>"#,
                href = escape_html(href),
                label = escape_html(label),
                description = escape_html(description),
            )
        })
        .collect::<String>();
    format!(
        r#"<div class="wb-card">
  <h3>First frontier route map</h3>
  <p>Use these six routes for a first pass through the local frontier: daily cockpit, review action queue, correct, prove, distribute, and ask. Opening routes does not count as review and does not change accepted frontier state.</p>
  <div class="wb-grid">{route_cards}</div>
</div>"#
    )
}

fn count_non_readme_files(dir: &Path) -> usize {
    fs::read_dir(dir)
        .ok()
        .into_iter()
        .flat_map(|entries| entries.flatten())
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name != "README.md")
                && entry.path().is_file()
        })
        .count()
}

fn reviewer_session_rail_html(repo_path: &Path, scope: &str, objects: &[String]) -> String {
    let frontier = repo_path.display().to_string();
    let primary_object = objects
        .first()
        .map(String::as_str)
        .unwrap_or(scope)
        .to_string();
    let object_chips = if objects.is_empty() {
        r#"<span class="wb-chip wb-chip--warn">no object</span>"#.to_string()
    } else {
        objects
            .iter()
            .map(|object| format!(r#"<code>{}</code>"#, escape_html(object)))
            .collect::<Vec<_>>()
            .join("")
    };
    let start_cli = format!(
        "vela review-session start {} --reviewer reviewer:external --scope {} --json",
        frontier, scope
    );
    let note_cli = format!(
        "vela review-session note {} vrs_ID --object {} --note 'bounded reviewer note' --json",
        frontier, primary_object
    );
    let close_cli = format!(
        "vela review-session close {} vrs_ID --decision needs_revision --reason 'bounded reviewer reason' --json",
        frontier
    );
    format!(
        r#"<section class="wb-card wb-review-rail" aria-label="Reviewer session rail">
  <h3>Reviewer session rail</h3>
  <p>Use a local session to collect reviewer notes before accepting, rejecting, or requesting revision. Session records do not change frontier truth by themselves.</p>
  <dl class="wb-meta">
    <dt>scope</dt><dd><code>{scope}</code></dd>
    <dt>objects</dt><dd><span class="wb-review-rail__objects">{object_chips}</span></dd>
  </dl>
  <div class="wb-review-rail__commands">
    <code>{start_cli}</code>
    <code>{note_cli}</code>
    <code>{close_cli}</code>
  </div>
  <p><a href="/review/sessions">Open review sessions</a></p>
</section>"#,
        scope = escape_html(scope),
        object_chips = object_chips,
        start_cli = escape_html(&start_cli),
        note_cli = escape_html(&note_cli),
        close_cli = escape_html(&close_cli),
    )
}

async fn page_frontier_health(State(state): State<AppState>) -> Response {
    let project = match repo::load_from_path(&state.repo_path) {
        Ok(p) => p,
        Err(e) => return error_page("frontier health", "Could not load frontier", &e),
    };
    let report = match frontier_health::analyze(&state.repo_path) {
        Ok(report) => report,
        Err(e) => return error_page("frontier health", "Could not compute health", &e),
    };
    let incident_summary = frontier_incident::incident_summary(&state.repo_path);

    let issue_rows = if report.issues.is_empty() {
        r#"<tr><td colspan="5" class="wb-empty">No operating issues are active in this projection.</td></tr>"#.to_string()
    } else {
        report
            .issues
            .iter()
            .map(|issue| {
                let chip = match issue.severity.as_str() {
                    "error" => "lost",
                    "warn" => "warn",
                    _ => "ok",
                };
                format!(
                    r#"<tr>
  <td><span class="wb-chip wb-chip--{chip}">{severity}</span></td>
  <td>{count}</td>
  <td>{label}</td>
  <td>{message}</td>
  <td><a href="{href}">Open</a></td>
</tr>"#,
                    chip = chip,
                    severity = escape_html(&issue.severity),
                    count = issue.count,
                    label = escape_html(&issue.label),
                    message = escape_html(&issue.message),
                    href = escape_html(&issue.href),
                )
            })
            .collect()
    };

    let threshold_rows = report
        .threshold_classes
        .iter()
        .map(|threshold| {
            let roles = if threshold.reviewer_roles.is_empty() {
                "none".to_string()
            } else {
                threshold
                    .reviewer_roles
                    .iter()
                    .map(|role| format!("<code>{}</code>", escape_html(role)))
                    .collect::<Vec<_>>()
                    .join(" · ")
            };
            format!(
                r#"<tr><td><code>{class}</code></td><td>{count}</td><td>{roles}</td></tr>"#,
                class = escape_html(&threshold.review_class),
                count = threshold.required_reviewer_count,
                roles = roles,
            )
        })
        .collect::<String>();

    let cli = format!("vela frontier health {} --json", state.repo_path.display());
    let body = format!(
        r#"<div class="wb-card">
  <h3><span class="wb-chip wb-chip--{status_chip}">health</span>Frontier operating state</h3>
  <p>This dashboard reports local review debt, source queue state, proof freshness, and scoped attestation gaps. It does not mark scientific claims as true.</p>
  <div class="wb-action-row">
    <a class="wb-button" href="/review/inbox">Review inbox</a>
    <a class="wb-button wb-button--quiet" href="/tasks">Tasks</a>
    <a class="wb-button wb-button--quiet" href="/source-inbox">Source inbox</a>
    <a class="wb-button wb-button--quiet" href="/incidents">Incidents</a>
    <a class="wb-button wb-button--quiet" href="/diff-packs">Diff Packs</a>
    <a class="wb-button wb-button--quiet" href="/proof">Proof</a>
  </div>
</div>
<div class="wb-stats">
  <div><div class="wb-stat__num">{active_tasks}</div><div class="wb-stat__label">active tasks</div></div>
  <div><div class="wb-stat__num">{pending_packs}</div><div class="wb-stat__label">pending Diff Packs</div></div>
  <div><div class="wb-stat__num">{proof}</div><div class="wb-stat__label">proof state</div></div>
  <div><div class="wb-stat__num">{missing}</div><div class="wb-stat__label">missing attestations</div></div>
</div>
<div class="wb-stats" style="margin-top:0.6rem;">
  <div><div class="wb-stat__num">{source_issues}</div><div class="wb-stat__label">source issues</div></div>
  <div><div class="wb-stat__num">{ci_failures}</div><div class="wb-stat__label">Evidence CI failures</div></div>
  <div><div class="wb-stat__num">{open_incidents}</div><div class="wb-stat__label">open incidents</div></div>
  <div><div class="wb-stat__num">{latency}</div><div class="wb-stat__label">max review latency days</div></div>
</div>
<div class="wb-grid">
  <div class="wb-card">
    <h3>Tasks and sources</h3>
    <p><strong>{blocked}</strong> blocked task(s) · <strong>{awaiting}</strong> awaiting review · <strong>{source_issues}</strong> source inbox issue(s).</p>
    <p><a href="/tasks">Open tasks</a> · <a href="/source-inbox">Open source inbox</a></p>
  </div>
  <div class="wb-card">
    <h3>Diff review</h3>
    <p><strong>{pending_packs}</strong> pending · <strong>{accepted}</strong> accepted · <strong>{rejected}</strong> rejected · <strong>{revision}</strong> revision requested.</p>
    <p><a href="/diff-packs">Open Diff Packs</a></p>
  </div>
  <div class="wb-card">
    <h3>Proof and Evidence CI</h3>
    <p>Proof is <code>{proof}</code>. Evidence CI reports <strong>{ci_failures}</strong> failure(s) and <strong>{ci_warnings}</strong> warning(s).</p>
    <p><a href="/proof">Open proof center</a> · <a href="/review/session">Open review session</a></p>
  </div>
  <div class="wb-card">
    <h3>Scientific debt signals</h3>
    <p><strong>{stale_claims}</strong> claim(s) need source review · <strong>{contradiction}</strong> contradictory link(s) · <strong>{retractions}</strong> retraction impact signal(s).</p>
    <p><a href="/conflicts">Open conflicts</a> · <a href="/incidents">Open incidents</a></p>
  </div>
  <div class="wb-card">
    <h3>Incidents</h3>
    <p><strong>{open_incidents}</strong> open · <strong>{closed_incidents}</strong> closed. Incidents trigger review tasks; they do not retract claims by themselves.</p>
    <p><a href="/incidents">Open incident log</a></p>
  </div>
</div>
<div class="wb-card">
  <h3>Active issues</h3>
  <table class="wb-table">
    <thead><tr><th>severity</th><th>count</th><th>issue</th><th>meaning</th><th>route</th></tr></thead>
    <tbody>{issue_rows}</tbody>
  </table>
</div>
<div class="wb-card">
  <h3>Policy threshold classes</h3>
  <p>Review roles are derived from frontier policy when present, then from built-in defaults.</p>
  <table class="wb-table">
    <thead><tr><th>review class</th><th>required reviewers</th><th>roles</th></tr></thead>
    <tbody>{threshold_rows}</tbody>
  </table>
</div>
<div class="wb-card">
  <h3>CLI equivalent</h3>
  <pre><code>{cli}</code></pre>
</div>"#,
        status_chip = if report.ok { "ok" } else { "warn" },
        active_tasks = report.metrics.active_tasks,
        pending_packs = report.metrics.pending_diff_packs,
        proof = escape_html(&report.metrics.proof_status),
        missing = report.metrics.missing_attestations,
        source_issues = report.metrics.source_inbox_issues,
        ci_failures = report.metrics.evidence_ci_failures,
        stale_claims = report.metrics.stale_claims,
        open_incidents = incident_summary.open,
        closed_incidents = incident_summary.closed,
        latency = report.metrics.max_review_latency_days,
        blocked = report.metrics.blocked_tasks,
        awaiting = report.metrics.awaiting_review_tasks,
        accepted = report.metrics.accepted_diff_packs,
        rejected = report.metrics.rejected_diff_packs,
        revision = report.metrics.revision_requested_diff_packs,
        ci_warnings = report.metrics.evidence_ci_warnings,
        contradiction = report.metrics.contradiction_debt,
        retractions = report.metrics.retraction_impacts,
        issue_rows = issue_rows,
        threshold_rows = threshold_rows,
        cli = escape_html(&cli),
    );

    Html(shell(
        "frontier-health",
        &format!("Frontier health · {}", project.project.name),
        "Workbench",
        "Frontier health",
        &body,
    ))
    .into_response()
}

async fn page_tasks(State(state): State<AppState>) -> Response {
    let list = match frontier_task::list_tasks(&state.repo_path) {
        Ok(list) => list,
        Err(e) => return error_page("tasks", "Could not load frontier tasks", &e),
    };
    let summary = frontier_task::FrontierTaskSummary::from_tasks(&list.tasks);
    let mut rows = String::new();
    for task in &list.tasks {
        let task_path = urlencode_path(&task.id);
        let blockers = if task.blockers.is_empty() {
            "none".to_string()
        } else {
            task.blockers
                .iter()
                .map(|value| format!("<code>{}</code>", escape_html(value)))
                .collect::<Vec<_>>()
                .join(" · ")
        };
        let inputs = if task.inputs.is_empty() {
            "none".to_string()
        } else {
            task.inputs
                .iter()
                .map(|value| format!("<code>{}</code>", escape_html(value)))
                .collect::<Vec<_>>()
                .join(" · ")
        };
        let status_options = [
            frontier_task::FrontierTaskStatus::Backlog,
            frontier_task::FrontierTaskStatus::Eligible,
            frontier_task::FrontierTaskStatus::Claimed,
            frontier_task::FrontierTaskStatus::PreparingWorkspace,
            frontier_task::FrontierTaskStatus::Running,
            frontier_task::FrontierTaskStatus::ProposedDiff,
            frontier_task::FrontierTaskStatus::AwaitingReview,
            frontier_task::FrontierTaskStatus::RevisionRequested,
        ]
        .iter()
        .map(|status| {
            let value = status.to_string();
            let selected = if *status == task.status {
                " selected"
            } else {
                ""
            };
            format!(
                r#"<option value="{value}"{selected}>{value}</option>"#,
                value = escape_html(&value),
                selected = selected
            )
        })
        .collect::<Vec<_>>()
        .join("");
        let task_preview = render_mutation_preview(
            "Update frontier task",
            &task.id,
            "task ledger file write",
            "updates only local operational task state under .vela/tasks; it does not accept frontier findings",
        );
        let task_actions = format!(
            r#"{preview}<div class="wb-actions wb-actions--stacked">
  <form method="post" action="/tasks/{task_path}/claim">
    <label>Reviewer <input name="reviewer" placeholder="reviewer:you" required></label>
    <button class="wb-button" type="submit">Claim</button>
  </form>
  <form method="post" action="/tasks/{task_path}/status">
    <label>Status <select name="status">{status_options}</select></label>
    <button class="wb-button wb-button--quiet" type="submit">Set</button>
  </form>
  <form method="post" action="/tasks/{task_path}/close">
    <label>Close as <select name="status">
      <option value="accepted">accepted</option>
      <option value="rejected">rejected</option>
      <option value="superseded">superseded</option>
      <option value="archived">archived</option>
    </select></label>
    <label>Reason <input name="reason" placeholder="bounded closure reason" required></label>
    <button class="wb-button wb-button--quiet" type="submit">Close</button>
  </form>
</div>"#,
            preview = task_preview,
            task_path = task_path,
            status_options = status_options,
        );
        rows.push_str(&format!(
            r#"<tr>
  <td><code>{id}</code></td>
  <td><span class="wb-chip">{status}</span></td>
  <td>{task_type}</td>
  <td>{risk}</td>
  <td>{objective}</td>
  <td>{inputs}</td>
  <td>{blockers}</td>
  <td><a href="/tasks/{id}/workspace">Workspace</a></td>
  <td>{task_actions}</td>
  <td>{updated}</td>
</tr>"#,
            id = escape_html(&task.id),
            status = escape_html(&task.status.to_string()),
            task_type = escape_html(&task.task_type),
            risk = escape_html(&task.risk_class),
            objective = escape_html(&task.objective),
            inputs = inputs,
            blockers = blockers,
            task_actions = task_actions,
            updated = escape_html(&task.updated_at.chars().take(10).collect::<String>()),
        ));
    }
    if rows.is_empty() {
        rows.push_str(
            r#"<tr><td colspan="10">No local frontier tasks. Create one with <code>vela task create FRONTIER --type source_ingestion --objective "..."</code>.</td></tr>"#,
        );
    }
    let body = format!(
        r#"<section class="wb-hero" aria-label="Frontier task summary">
  <div class="wb-hero__grid">
    <div>
      <h2>Frontier tasks</h2>
      <p>Local work units for source review, contradiction repair, proof freshness, and diff-pack preparation. Task state is operational; accepted frontier truth still comes from reviewed events.</p>
    </div>
    <div class="wb-status-panel" aria-label="Task health">
      <div><span>Total</span><strong>{total}</strong></div>
      <div><span>Active</span><strong>{active}</strong></div>
      <div><span>Blocked</span><strong>{blocked}</strong></div>
      <div><span>Awaiting review</span><strong>{awaiting_review}</strong></div>
    </div>
  </div>
</section>
<div class="wb-card">
  <h3>Browser write lane</h3>
  <p>Task buttons update only local operational records under <code>.vela/tasks/</code>. Closing a task does not accept frontier truth; accepted state still requires a reviewed event or Diff Pack verdict.</p>
</div>
<div class="wb-card">
  <h3>Task ledger</h3>
  <table class="wb-table">
    <thead><tr><th>Task</th><th>Status</th><th>Type</th><th>Risk</th><th>Objective</th><th>Inputs</th><th>Blockers</th><th>Workspace</th><th>Actions</th><th>Updated</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div>
<div class="wb-card">
  <h3>CLI equivalent</h3>
  <p><code>vela task list {frontier_path} --json</code></p>
  <p><code>vela task workspace init {frontier_path} VTASK_ID --json</code></p>
  <p><code>vela task claim {frontier_path} VTASK_ID --reviewer reviewer:you</code></p>
</div>"#,
        total = summary.total,
        active = summary.active,
        blocked = summary.blocked,
        awaiting_review = summary.awaiting_review,
        rows = rows,
        frontier_path = escape_html(&state.repo_path.display().to_string()),
    );
    Html(shell(
        "tasks",
        "Tasks · Vela workbench",
        "Workbench",
        "Frontier tasks",
        &body,
    ))
    .into_response()
}

#[derive(Debug, Deserialize)]
struct SourceInboxFilter {
    state: Option<String>,
}

async fn page_source_inbox(
    State(state): State<AppState>,
    Query(filter): Query<SourceInboxFilter>,
) -> Response {
    let mut list = match source_inbox::list_records(&state.repo_path) {
        Ok(list) => list,
        Err(e) => return error_page("source-inbox", "Could not load source inbox", &e),
    };
    let all_summary = source_inbox::SourceInboxSummary::from_list(&list);
    let filter_label = filter.state.as_deref().unwrap_or("all").to_string();
    if let Some(filter_state) = filter.state.as_deref() {
        match filter_state {
            "task-linked" | "linked-to-task" => list
                .records
                .retain(|record| record.linked_task_id.is_some()),
            "rejected" => list.records.clear(),
            "stale" => list.records.retain(|record| {
                chrono::DateTime::parse_from_rfc3339(&record.updated_at)
                    .ok()
                    .map(|updated| {
                        chrono::Utc::now()
                            .signed_duration_since(updated.with_timezone(&chrono::Utc))
                            .num_days()
                            > 30
                    })
                    .unwrap_or(false)
            }),
            other => {
                if let Ok(state) = other.parse::<source_inbox::SourceInboxState>() {
                    list.records.retain(|record| record.state == state);
                }
            }
        }
        list.total = list.records.len();
    }
    let mut rows = String::new();
    for record in &list.records {
        let record_path = urlencode_path(&record.id);
        let task_link = record
            .linked_task_id
            .as_ref()
            .map(|task_id| {
                format!(
                    r#"<a href="/tasks/{}/workspace"><code>{}</code></a>"#,
                    urlencode_path(task_id),
                    escape_html(task_id)
                )
            })
            .unwrap_or_else(|| "not linked".to_string());
        let policy = source_inbox::review_requirement_for_record(&state.repo_path, record);
        let source_preview = render_mutation_preview(
            "Review source inbox record",
            &record.id,
            "source inbox or task ledger file write",
            "verifies the source-inbox record or creates a linked task; it does not accept the source as frontier truth",
        );
        let source_actions = format!(
            r#"{preview}<div class="wb-actions wb-actions--stacked">
  <form method="post" action="/source-inbox/{record_path}/verify">
    <label>Reviewer <input name="reviewer" placeholder="reviewer:you" required></label>
    <label>Reason <input name="reason" placeholder="locator resolves to intended source" required></label>
    <button class="wb-button" type="submit">Verify</button>
  </form>
  <form method="post" action="/source-inbox/{record_path}/create-task">
    <label>Objective <input name="objective" placeholder="Review source impact"></label>
    <label>Status <select name="status">
      <option value="eligible">eligible</option>
      <option value="backlog">backlog</option>
      <option value="awaiting_review">awaiting_review</option>
    </select></label>
    <button class="wb-button wb-button--quiet" type="submit">Create task</button>
  </form>
</div>"#,
            preview = source_preview,
            record_path = record_path,
        );
        rows.push_str(&format!(
            r#"<tr>
  <td><code>{id}</code></td>
  <td>{state}</td>
  <td>{title}<br><code>{locator}</code></td>
  <td><code>{source_type}</code></td>
  <td>{risk}<br><span style="color:var(--ink-3);">{policy}</span></td>
  <td>{task}</td>
  <td><code>vela source-inbox create-task FRONTIER {id}</code></td>
  <td>{source_actions}</td>
</tr>"#,
            id = escape_html(&record.id),
            state = escape_html(record.state.as_str()),
            title = escape_html(&truncate(&record.title, 88)),
            locator = escape_html(&truncate(&record.locator, 88)),
            source_type = escape_html(&record.source_type),
            risk = escape_html(&record.risk_class),
            policy = escape_html(&format!(
                "{} · {} reviewer(s)",
                policy.review_class, policy.required_reviewer_count
            )),
            task = task_link,
            source_actions = source_actions,
        ));
    }
    if rows.is_empty() {
        rows.push_str(
            r#"<tr><td colspan="8">No source inbox records for this filter. Add one with <code>vela source-inbox add FRONTIER --title ... --locator ...</code>.</td></tr>"#,
        );
    }
    let rejected_rows: String = list
        .rejected_imports
        .iter()
        .take(20)
        .map(|row| {
            format!(
                r#"<tr><td>{format}</td><td>{row_number}</td><td><code>{raw}</code></td><td>{reason}</td></tr>"#,
                format = escape_html(&row.format),
                row_number = row.row_number,
                raw = escape_html(&truncate(&row.raw, 110)),
                reason = escape_html(&row.reason),
            )
        })
        .collect();
    let rejected_html = if list.rejected_imports.is_empty() {
        r#"<p class="wb-empty">No rejected source imports recorded.</p>"#.to_string()
    } else {
        format!(
            r#"<table class="wb-table">
    <thead><tr><th>format</th><th>row</th><th>raw input</th><th>reason</th></tr></thead>
    <tbody>{rejected_rows}</tbody>
  </table>"#
        )
    };
    let body = format!(
        r#"<section class="wb-hero">
  <h2>Source inbox</h2>
  <p>Operational source material waiting for verification, task routing, or diff-pack review. Imported records are unverified source identity support, not evidence atoms.</p>
</section>
<div class="wb-stats">
  <div><div class="wb-stat__num">{total}</div><div class="wb-stat__label">records</div></div>
  <div><div class="wb-stat__num">{quarantined}</div><div class="wb-stat__label">quarantined</div></div>
  <div><div class="wb-stat__num">{retracted}</div><div class="wb-stat__label">retracted</div></div>
  <div><div class="wb-stat__num">{task_linked}</div><div class="wb-stat__label">task-linked</div></div>
  <div><div class="wb-stat__num">{rejected}</div><div class="wb-stat__label">rejected imports</div></div>
</div>
<div class="wb-card">
  <h3>Filters</h3>
  <p><a href="/source-inbox">all</a> · <a href="/source-inbox?state=discovered">discovered</a> · <a href="/source-inbox?state=verified">verified</a> · <a href="/source-inbox?state=rejected">rejected</a> · <a href="/source-inbox?state=linked-to-task">linked-to-task</a> · <a href="/source-inbox?state=stale">stale</a></p>
  <p>Current filter: <code>{filter}</code></p>
</div>
<div class="wb-card">
  <h3>Browser write lane</h3>
  <p>Verify and create-task actions mutate only local source-inbox and task files. Source records remain source material until a later reviewed frontier event changes accepted state.</p>
</div>
<div class="wb-card">
  <h3>Records</h3>
  <table class="wb-table">
    <thead><tr><th>record</th><th>state</th><th>source</th><th>type</th><th>risk / policy</th><th>task</th><th>CLI equivalent</th><th>Actions</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div>
<div class="wb-card">
  <h3>Rejected imports</h3>
  <p>Rows here were not converted into source records. They remain visible with their original input and reason.</p>
  {rejected_html}
</div>"#,
        total = all_summary.total,
        quarantined = all_summary.quarantined,
        retracted = all_summary.retracted,
        task_linked = all_summary.task_linked,
        rejected = all_summary.rejected_imports,
        filter = escape_html(&filter_label),
        rows = rows,
        rejected_html = rejected_html,
    );
    Html(shell(
        "source-inbox",
        "Source inbox · Vela workbench",
        "Workbench",
        "Source inbox",
        &body,
    ))
    .into_response()
}

#[derive(Debug, Deserialize)]
struct SourceInboxVerifyForm {
    reviewer: Option<String>,
    reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SourceInboxCreateTaskForm {
    objective: Option<String>,
    status: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TaskClaimForm {
    reviewer: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TaskStatusForm {
    status: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TaskCloseForm {
    status: Option<String>,
    reason: Option<String>,
}

fn required_form_value(value: Option<String>, label: &str) -> Result<String, String> {
    value
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("{label} is required"))
}

fn required_typed_reviewer(value: Option<String>) -> Result<String, String> {
    let reviewer = required_form_value(value, "reviewer")?;
    if reviewer.contains(':') {
        Ok(reviewer)
    } else {
        Err("Reviewer identity must be a typed actor id such as reviewer:you.".to_string())
    }
}

fn required_bounded_reason(value: Option<String>, label: &str) -> Result<String, String> {
    let reason = required_form_value(value, label)?;
    if reason.len() >= 12 {
        Ok(reason)
    } else {
        Err(format!("{label} must be at least 12 characters."))
    }
}

async fn post_source_inbox_verify(
    AxumPath(record_id): AxumPath<String>,
    State(state): State<AppState>,
    Form(form): Form<SourceInboxVerifyForm>,
) -> Response {
    let reviewer = match required_typed_reviewer(form.reviewer) {
        Ok(reviewer) => reviewer,
        Err(e) => return error_page("source-inbox", "Policy requirement missing", &e),
    };
    let reason = match required_bounded_reason(form.reason, "verification reason") {
        Ok(reason) => reason,
        Err(e) => return error_page("source-inbox", "Policy requirement missing", &e),
    };
    match source_inbox::verify_record(&state.repo_path, &record_id, reviewer, reason) {
        Ok(_) => Redirect::to("/source-inbox").into_response(),
        Err(e) => error_page("source-inbox", "Could not verify source record", &e),
    }
}

async fn post_source_inbox_create_task(
    AxumPath(record_id): AxumPath<String>,
    State(state): State<AppState>,
    Form(form): Form<SourceInboxCreateTaskForm>,
) -> Response {
    let status = match form
        .status
        .as_deref()
        .unwrap_or("eligible")
        .parse::<frontier_task::FrontierTaskStatus>()
    {
        Ok(status) if !status.is_terminal() => status,
        Ok(status) => {
            return error_page(
                "source-inbox",
                "Policy requirement missing",
                &format!("Initial browser-created tasks cannot start terminal; got `{status}`."),
            );
        }
        Err(e) => return error_page("source-inbox", "Invalid task status", &e),
    };
    match source_inbox::create_task_from_record(
        &state.repo_path,
        &record_id,
        form.objective,
        status,
    ) {
        Ok(_) => Redirect::to("/source-inbox?state=linked-to-task").into_response(),
        Err(e) => error_page("source-inbox", "Could not create source-review task", &e),
    }
}

async fn post_task_claim(
    AxumPath(task_id): AxumPath<String>,
    State(state): State<AppState>,
    Form(form): Form<TaskClaimForm>,
) -> Response {
    let reviewer = match required_typed_reviewer(form.reviewer) {
        Ok(reviewer) => reviewer,
        Err(e) => return error_page("tasks", "Policy requirement missing", &e),
    };
    match frontier_task::claim_task(&state.repo_path, &task_id, reviewer) {
        Ok(_) => Redirect::to("/tasks").into_response(),
        Err(e) => error_page("tasks", "Could not claim task", &e),
    }
}

async fn post_task_status(
    AxumPath(task_id): AxumPath<String>,
    State(state): State<AppState>,
    Form(form): Form<TaskStatusForm>,
) -> Response {
    let status = match required_form_value(form.status, "task status")
        .and_then(|status| status.parse::<frontier_task::FrontierTaskStatus>())
    {
        Ok(status) if !status.is_terminal() => status,
        Ok(status) => {
            return error_page(
                "tasks",
                "Policy requirement missing",
                &format!("Use close with a reason for terminal task status `{status}`."),
            );
        }
        Err(e) => return error_page("tasks", "Invalid task status", &e),
    };
    match frontier_task::set_task_status(&state.repo_path, &task_id, status) {
        Ok(_) => Redirect::to("/tasks").into_response(),
        Err(e) => error_page("tasks", "Could not update task status", &e),
    }
}

async fn post_task_close(
    AxumPath(task_id): AxumPath<String>,
    State(state): State<AppState>,
    Form(form): Form<TaskCloseForm>,
) -> Response {
    let status = match required_form_value(form.status, "close status")
        .and_then(|status| status.parse::<frontier_task::FrontierTaskStatus>())
    {
        Ok(status) if status.is_terminal() => status,
        Ok(status) => {
            return error_page(
                "tasks",
                "Policy requirement missing",
                &format!("Close requires a terminal task status; got `{status}`."),
            );
        }
        Err(e) => return error_page("tasks", "Invalid close status", &e),
    };
    let reason = match required_bounded_reason(form.reason, "closure reason") {
        Ok(reason) => reason,
        Err(e) => return error_page("tasks", "Policy requirement missing", &e),
    };
    match frontier_task::close_task(&state.repo_path, &task_id, status, reason) {
        Ok(_) => Redirect::to("/tasks").into_response(),
        Err(e) => error_page("tasks", "Could not close task", &e),
    }
}

async fn page_incidents(State(state): State<AppState>) -> Response {
    let list = match frontier_incident::list_incidents(&state.repo_path) {
        Ok(list) => list,
        Err(e) => return error_page("incidents", "Could not load frontier incidents", &e),
    };
    let summary = frontier_incident::FrontierIncidentSummary::from_incidents(&list.incidents);
    let mut rows = String::new();
    for incident in &list.incidents {
        let source = incident
            .source_id
            .as_deref()
            .map(|id| format!("<code>{}</code>", escape_html(id)))
            .unwrap_or_else(|| "n/a".to_string());
        let finding = incident
            .finding_id
            .as_deref()
            .map(|id| {
                format!(
                    r#"<a href="/findings/{path}"><code>{id}</code></a>"#,
                    path = urlencode_path(id),
                    id = escape_html(id)
                )
            })
            .unwrap_or_else(|| "n/a".to_string());
        let tasks = if incident.linked_task_ids.is_empty() {
            "none".to_string()
        } else {
            incident
                .linked_task_ids
                .iter()
                .map(|task_id| {
                    format!(
                        r#"<a href="/tasks/{path}/workspace"><code>{id}</code></a>"#,
                        path = urlencode_path(task_id),
                        id = escape_html(task_id)
                    )
                })
                .collect::<Vec<_>>()
                .join(" · ")
        };
        rows.push_str(&format!(
            r#"<tr>
  <td><code>{id}</code><br><span class="wb-chip wb-chip--{chip}">{status}</span></td>
  <td><code>{kind}</code><br>{severity}</td>
  <td>{title}<br><span style="color:var(--ink-3);">{reason}</span></td>
  <td>{source}<br>{finding}</td>
  <td>{affected} finding(s)<br>{atoms} evidence atom(s)</td>
  <td>{tasks}</td>
</tr>"#,
            id = escape_html(&incident.id),
            chip = if incident.status == frontier_incident::FrontierIncidentStatus::Open {
                "warn"
            } else {
                "ok"
            },
            status = escape_html(incident.status.as_str()),
            kind = escape_html(incident.incident_type.as_str()),
            severity = escape_html(&incident.severity),
            title = escape_html(&incident.title),
            reason = escape_html(&truncate(&incident.reason, 120)),
            source = source,
            finding = finding,
            affected = incident.affected_findings.len(),
            atoms = incident.affected_evidence_atoms.len(),
            tasks = tasks,
        ));
    }
    if rows.is_empty() {
        rows.push_str(
            r#"<tr><td colspan="6">No local frontier incidents. Open one with <code>vela incident open FRONTIER --kind source_retracted --source-id ... --reviewer reviewer:you --reason ... --title ...</code>.</td></tr>"#,
        );
    }
    let body = format!(
        r#"<section class="wb-hero">
  <h2>Incidents</h2>
  <p>Local review triggers for retractions, corrections, extraction errors, registry mismatches, contradictions, and translation risk. Incident records do not change accepted frontier state.</p>
</section>
<div class="wb-stats">
  <div><div class="wb-stat__num">{total}</div><div class="wb-stat__label">incidents</div></div>
  <div><div class="wb-stat__num">{open}</div><div class="wb-stat__label">open</div></div>
  <div><div class="wb-stat__num">{closed}</div><div class="wb-stat__label">closed</div></div>
  <div><div class="wb-stat__num">{frontier}</div><div class="wb-stat__label">frontier</div></div>
</div>
<div class="wb-card">
  <h3>Incident log</h3>
  <table class="wb-table">
    <thead><tr><th>incident</th><th>type</th><th>reason</th><th>target</th><th>impact</th><th>tasks</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div>
<div class="wb-card">
  <h3>CLI equivalent</h3>
  <pre><code>vela incident list {path} --json
vela incident impact {path} SOURCE_ID --json</code></pre>
</div>"#,
        total = summary.total,
        open = summary.open,
        closed = summary.closed,
        frontier = escape_html(&list.frontier_id),
        path = escape_html(&state.repo_path.display().to_string()),
        rows = rows,
    );
    Html(shell(
        "incidents",
        "Incidents · Vela workbench",
        "Workbench",
        "Incidents",
        &body,
    ))
    .into_response()
}

async fn page_task_workspace_status(
    State(state): State<AppState>,
    AxumPath(task_id): AxumPath<String>,
) -> Response {
    let status = match task_workspace::workspace_status(&state.repo_path, &task_id) {
        Ok(status) => status,
        Err(e) => return error_page("tasks", "Could not load task workspace", &e),
    };
    let mut source_rows = String::new();
    for source in &status.source_artifacts {
        source_rows.push_str(&format!(
            r#"<tr>
  <td>{input}</td>
  <td><span class="wb-chip">{status}</span></td>
  <td>{workspace_path}</td>
  <td>{sha}</td>
  <td>{bytes}</td>
</tr>"#,
            input = escape_html(&source.input),
            status = escape_html(&source.status),
            workspace_path = escape_html(source.workspace_path.as_deref().unwrap_or("n/a")),
            sha = escape_html(source.sha256.as_deref().unwrap_or("n/a")),
            bytes = source
                .bytes
                .map(|n| n.to_string())
                .unwrap_or_else(|| "n/a".to_string()),
        ));
    }
    if source_rows.is_empty() {
        source_rows.push_str(
            r#"<tr><td colspan="5">No copied source artifacts. Run <code>vela task workspace init FRONTIER VTASK_ID</code> after declaring file inputs.</td></tr>"#,
        );
    }
    let files = if status.files.is_empty() {
        "none".to_string()
    } else {
        status
            .files
            .iter()
            .map(|file| format!("<code>{}</code>", escape_html(file)))
            .collect::<Vec<_>>()
            .join(" · ")
    };
    let directories = if status.directories.is_empty() {
        "none".to_string()
    } else {
        status
            .directories
            .iter()
            .map(|dir| format!("<code>{}</code>", escape_html(dir)))
            .collect::<Vec<_>>()
            .join(" · ")
    };
    let ready = if status.exists { "ready" } else { "missing" };
    let evidence_ci_html = match evidence_ci::run_frontier(&state.repo_path) {
        Ok(report) => {
            let group_summary = render_evidence_ci_groups(&report);
            format!(
                r#"<div class="wb-card">
  <h3>Evidence CI</h3>
  <p>Review-readiness checks for the selected local frontier. This is not a truth verdict.</p>
  <dl class="wb-meta">
    <dt>status</dt><dd>{status}</dd>
    <dt>checks</dt><dd>{total}</dd>
    <dt>release-blocking checks</dt><dd>{release_blocking}</dd>
    <dt>review warnings</dt><dd>{review_warning}</dd>
    <dt>info checks</dt><dd>{info}</dd>
    <dt>warnings</dt><dd>{warnings}</dd>
    <dt>release-blocking failures</dt><dd>{blocking}</dd>
  </dl>
  {group_summary}
  <p><code>vela evidence-ci {frontier_path} --json</code></p>
</div>"#,
                status = if report.ok { "ready" } else { "blocked" },
                total = report.summary.total,
                release_blocking = report.summary.release_blocking,
                review_warning = report.summary.review_warning,
                info = report.summary.info,
                warnings = report.summary.warnings,
                blocking = report.summary.release_blocking_failed,
                frontier_path = escape_html(&state.repo_path.display().to_string()),
                group_summary = group_summary,
            )
        }
        Err(e) => format!(
            r#"<div class="wb-card">
  <h3>Evidence CI</h3>
  <p>Could not run Evidence CI: {}</p>
</div>"#,
            escape_html(&e)
        ),
    };
    let session_rail = reviewer_session_rail_html(
        &state.repo_path,
        &format!("task:{}", status.task_id),
        std::slice::from_ref(&status.task_id),
    );
    let body = format!(
        r#"<section class="wb-hero" aria-label="Task workspace status">
  <div class="wb-hero__grid">
    <div>
      <h2>Task workspace</h2>
      <p>Durable local artifact trail for one task. It preserves source copies, a before snapshot, validation output, logs, and later review artifacts without accepting scientific state by itself.</p>
    </div>
    <div class="wb-status-panel" aria-label="Workspace health">
      <div><span>Status</span><strong>{ready}</strong></div>
      <div><span>Files</span><strong>{file_count}</strong></div>
      <div><span>Sources</span><strong>{source_count}</strong></div>
      <div><span>Snapshot</span><strong>{snapshot}</strong></div>
    </div>
  </div>
</section>
{session_rail}
<div class="wb-card">
  <h3>Workspace path</h3>
  <p><code>{workspace_path}</code></p>
  <p>Directories: {directories}</p>
  <p>Files: {files}</p>
</div>
<div class="wb-card">
  <h3>Source artifacts</h3>
  <table class="wb-table">
    <thead><tr><th>Input</th><th>Status</th><th>Workspace path</th><th>Hash</th><th>Bytes</th></tr></thead>
    <tbody>{source_rows}</tbody>
  </table>
</div>
{evidence_ci_html}
<div class="wb-card">
  <h3>CLI equivalent</h3>
  <p><code>vela task workspace init {frontier_path} {task_id} --json</code></p>
  <p><code>vela task workspace status {frontier_path} {task_id} --json</code></p>
  <p><code>vela review-packet build {frontier_path} {task_id} --out /tmp/{task_id}-review-packet.md --json</code></p>
  <p><a href="/tasks/{task_id}/review-packet">Open review packet</a></p>
</div>"#,
        ready = ready,
        file_count = status.files.len(),
        source_count = status.source_artifacts.len(),
        snapshot = escape_html(status.frontier_snapshot_sha256.as_deref().unwrap_or("n/a")),
        workspace_path = escape_html(&status.workspace_path),
        directories = directories,
        files = files,
        source_rows = source_rows,
        evidence_ci_html = evidence_ci_html,
        frontier_path = escape_html(&state.repo_path.display().to_string()),
        task_id = escape_html(&status.task_id),
        session_rail = session_rail,
    );
    Html(shell(
        "tasks",
        "Task workspace · Vela workbench",
        "Workbench",
        "Task workspace",
        &body,
    ))
    .into_response()
}

async fn page_task_review_packet(
    State(state): State<AppState>,
    AxumPath(task_id): AxumPath<String>,
) -> Response {
    let out = std::env::temp_dir().join(format!("{task_id}-review-packet.md"));
    let build = match review_packet::build(&state.repo_path, &task_id, Some(&out)) {
        Ok(build) => build,
        Err(e) => return error_page("tasks", "Could not build review packet", &e),
    };
    let packet = &build.packet;
    let session_rail = reviewer_session_rail_html(
        &state.repo_path,
        &format!("task:{}", task_id),
        std::slice::from_ref(&task_id),
    );
    let body = format!(
        r#"<section class="wb-hero" aria-label="Review packet">
  <div class="wb-hero__grid">
    <div>
      <h2>Review packet</h2>
      <p>Local review handoff for one task. It summarizes sources, proposed changes, Evidence CI, proof impact, reviewer questions, and exact commands.</p>
    </div>
    <div class="wb-status-panel" aria-label="Review packet status">
      <div><span>Evidence CI</span><strong>{ci_status}</strong></div>
      <div><span>Warnings</span><strong>{warnings}</strong></div>
      <div><span>Blocking</span><strong>{blocking}</strong></div>
      <div><span>Reviewers</span><strong>{reviewers}</strong></div>
    </div>
  </div>
</section>
{session_rail}
<div class="wb-card">
  <h3>Packet files</h3>
  <dl class="wb-meta">
    <dt>packet</dt><dd><code>{packet_id}</code></dd>
    <dt>workspace markdown</dt><dd><code>{markdown_path}</code></dd>
    <dt>workspace json</dt><dd><code>{json_path}</code></dd>
    <dt>exported markdown</dt><dd><code>{out}</code></dd>
  </dl>
</div>
<div class="wb-card">
  <h3>Markdown</h3>
  <pre class="wb-pre">{markdown}</pre>
</div>"#,
        ci_status = if packet.evidence_ci.ok {
            "ready"
        } else {
            "blocked"
        },
        warnings = packet.evidence_ci.warnings,
        blocking = packet.evidence_ci.release_blocking_failed,
        reviewers = packet.required_reviewers.len().max(1),
        packet_id = escape_html(&packet.packet_id),
        markdown_path = escape_html(&packet.markdown_path),
        json_path = escape_html(&packet.json_path),
        out = escape_html(&out.display().to_string()),
        markdown = escape_html(&build.markdown),
        session_rail = session_rail,
    );
    Html(shell(
        "tasks",
        "Review packet · Vela workbench",
        "Workbench",
        "Review packet",
        &body,
    ))
    .into_response()
}

async fn page_findings(State(state): State<AppState>) -> Response {
    let project = match repo::load_from_path(&state.repo_path) {
        Ok(p) => p,
        Err(e) => return error_page("findings", "Could not load frontier", &e),
    };

    let mut rows = String::new();
    for f in project.findings.iter().take(500) {
        let conf_pct = (f.confidence.score * 100.0).round() as i64;
        let claim = f.assertion.causal_claim.map_or("n/a", |c| match c {
            vela_protocol::bundle::CausalClaim::Correlation => "correlation",
            vela_protocol::bundle::CausalClaim::Mediation => "mediation",
            vela_protocol::bundle::CausalClaim::Intervention => "intervention",
        });
        let assertion_short: String = f.assertion.text.chars().take(110).collect();
        rows.push_str(&format!(
            r#"<tr>
  <td><a href="/findings/{vf}"><code>{vf_short}</code></a></td>
  <td>{conf}%</td>
  <td>{claim}</td>
  <td>{text}</td>
</tr>"#,
            vf = escape_html(&f.id),
            vf_short = escape_html(&f.id),
            conf = conf_pct,
            claim = claim,
            text = escape_html(&assertion_short),
        ));
    }

    let command_copy = render_command_copy(
        "Finding list commands",
        &[
            format!("vela stats {}/frontier.json", state.repo_path.display()),
            format!(
                "vela search \"amyloid\" --source {}/frontier.json",
                state.repo_path.display()
            ),
            format!(
                "vela index query {} --kind finding --q amyloid --json",
                state.repo_path.display()
            ),
        ],
    );
    let body = format!(
        r#"{command_copy}<table class="wb-table">
  <thead>
    <tr><th>vf_id</th><th>conf</th><th>claim</th><th>assertion</th></tr>
  </thead>
  <tbody>
{rows}
  </tbody>
</table>"#,
        command_copy = command_copy,
        rows = rows
    );

    Html(shell(
        "findings",
        "Findings",
        "Workbench",
        &format!("{} findings", project.findings.len()),
        &body,
    ))
    .into_response()
}

async fn page_finding_detail(
    AxumPath(vf_id): AxumPath<String>,
    State(state): State<AppState>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let project = match repo::load_from_path(&state.repo_path) {
        Ok(p) => p,
        Err(e) => return error_page("findings", "Could not load frontier", &e),
    };
    let Some(f) = project.findings.iter().find(|f| f.id == vf_id) else {
        return error_page(
            "findings",
            "Finding not found",
            &format!("no finding with id {vf_id}"),
        );
    };

    let conf_pct = (f.confidence.score * 100.0).round() as i64;
    let finding_atoms: Vec<&vela_protocol::sources::EvidenceAtom> = project
        .evidence_atoms
        .iter()
        .filter(|atom| atom.finding_id == f.id)
        .collect();
    let finding_source_ids = finding_atoms
        .iter()
        .map(|atom| atom.source_id.clone())
        .chain(
            project
                .sources
                .iter()
                .filter(|source| source.finding_ids.iter().any(|id| id == &f.id))
                .map(|source| source.id.clone()),
        )
        .collect::<BTreeSet<_>>();
    let finding_sources = project
        .sources
        .iter()
        .filter(|source| finding_source_ids.contains(&source.id))
        .collect::<Vec<_>>();

    let mut links_html = String::new();
    if !f.links.is_empty() {
        links_html.push_str(r#"<table class="wb-table"><thead><tr><th>type</th><th>target</th><th>mechanism</th></tr></thead><tbody>"#);
        for l in &f.links {
            let mech = l.mechanism.map_or("n/a".to_string(), |m| {
                use vela_protocol::bundle::Mechanism;
                match m {
                    Mechanism::Linear { sign, slope } => {
                        format!("linear {sign:?} slope {slope:.2}")
                    }
                    Mechanism::Monotonic { sign } => format!("monotonic {sign:?}"),
                    Mechanism::Threshold { sign, threshold } => {
                        format!("threshold {sign:?} {threshold:.2}")
                    }
                    Mechanism::Saturating { sign, half_max } => {
                        format!("saturating {sign:?} half_max {half_max:.2}")
                    }
                    Mechanism::Unknown => "unknown".into(),
                }
            });
            links_html.push_str(&format!(
                "<tr><td><code>{}</code></td><td><code>{}</code></td><td>{}</td></tr>",
                escape_html(&l.link_type),
                escape_html(&l.target),
                escape_html(&mech)
            ));
        }
        links_html.push_str("</tbody></table>");
    } else {
        links_html.push_str(
            r#"<p style="color:var(--ink-3);font-size:0.86rem;">No outgoing links recorded for this finding.</p>"#,
        );
    }

    let answer_path_context = query.get("answer_path").map(String::as_str).unwrap_or("");
    let answer_query = answer_path_query(answer_path_context);
    let answer_return = answer_path_return_panel(answer_path_context);

    let source_rows = if finding_sources.is_empty() {
        r#"<tr><td colspan="4">No source records are linked to this finding.</td></tr>"#.to_string()
    } else {
        finding_sources
            .iter()
            .map(|source| {
                format!(
                    r#"<tr><td><a href="/sources/{sid_path}{answer_query}"><code>{sid}</code></a></td><td>{title}</td><td><code>{kind}</code></td><td>{locator}</td></tr>"#,
                    sid_path = urlencode_path(&source.id),
                    answer_query = answer_query,
                    sid = escape_html(&source.id),
                    title = escape_html(&truncate(&source.title, 96)),
                    kind = escape_html(&source.source_type),
                    locator = escape_html(&truncate(&source.locator, 84)),
                )
            })
            .collect::<String>()
    };

    let atom_rows = if finding_atoms.is_empty() {
        r#"<tr><td colspan="5">No evidence atoms are linked to this finding.</td></tr>"#.to_string()
    } else {
        finding_atoms
            .iter()
            .map(|atom| {
                format!(
                    r#"<tr><td><code>{aid}</code></td><td><a href="/sources/{sid_path}{answer_query}"><code>{sid}</code></a></td><td>{locator}</td><td>{review}</td><td>{claim}</td></tr>"#,
                    aid = escape_html(&atom.id),
                    sid_path = urlencode_path(&atom.source_id),
                    answer_query = answer_query,
                    sid = escape_html(&atom.source_id),
                    locator = atom
                        .locator
                        .as_deref()
                        .map(escape_html)
                        .unwrap_or_else(|| "missing".to_string()),
                    review = if atom.human_verified { "verified" } else { "needs review" },
                    claim = escape_html(&truncate(&atom.measurement_or_claim, 90)),
                )
            })
            .collect::<String>()
    };
    let human_verified_atom_count = finding_atoms
        .iter()
        .filter(|atom| atom.human_verified)
        .count();
    let source_ready_status = if finding_atoms.is_empty() || finding_sources.is_empty() {
        "not source-ready"
    } else if human_verified_atom_count == finding_atoms.len() {
        "source-ready"
    } else {
        "source review partial"
    };

    let mut contradiction_rows = String::new();
    for link in f
        .links
        .iter()
        .filter(|link| link.link_type.contains("contradict") || link.link_type.contains("refute"))
    {
        contradiction_rows.push_str(&format!(
            r#"<tr><td><code>outgoing</code></td><td><code>{kind}</code></td><td><a href="/findings/{target}"><code>{target}</code></a></td><td>{note}</td></tr>"#,
            kind = escape_html(&link.link_type),
            target = escape_html(&link.target),
            note = escape_html(&link.note),
        ));
    }
    for other in &project.findings {
        for link in other.links.iter().filter(|link| {
            link.target == f.id
                && (link.link_type.contains("contradict") || link.link_type.contains("refute"))
        }) {
            contradiction_rows.push_str(&format!(
                r#"<tr><td><code>incoming</code></td><td><code>{kind}</code></td><td><a href="/findings/{source}"><code>{source}</code></a></td><td>{note}</td></tr>"#,
                kind = escape_html(&link.link_type),
                source = escape_html(&other.id),
                note = escape_html(&link.note),
            ));
        }
    }
    if f.flags.contested {
        contradiction_rows.push_str(
            r#"<tr><td><code>review</code></td><td><code>contested</code></td><td>this finding</td><td>Finding review state is contested.</td></tr>"#,
        );
    }
    let contradiction_rows = if contradiction_rows.is_empty() {
        r#"<tr><td colspan="4">No contradiction links or contested review state are recorded for this finding.</td></tr>"#.to_string()
    } else {
        contradiction_rows
    };

    let assertion = escape_html(&f.assertion.text);

    // v0.66 richer view: source attribution
    let source_block = {
        let mut parts: Vec<String> = Vec::new();
        if let Some(doi) = f.provenance.doi.as_deref().filter(|s| !s.is_empty()) {
            parts.push(format!(
                "<a href=\"https://doi.org/{doi}\" target=\"_blank\" rel=\"noopener\"><code>doi:{doi}</code></a>",
                doi = escape_html(doi)
            ));
        }
        if let Some(pmid) = f.provenance.pmid.as_deref().filter(|s| !s.is_empty()) {
            parts.push(format!(
                "<a href=\"https://pubmed.ncbi.nlm.nih.gov/{pmid}/\" target=\"_blank\" rel=\"noopener\"><code>pmid:{pmid}</code></a>",
                pmid = escape_html(pmid)
            ));
        }
        if let Some(y) = f.provenance.year {
            parts.push(format!("{y}"));
        }
        if let Some(j) = f.provenance.journal.as_deref().filter(|s| !s.is_empty()) {
            parts.push(escape_html(j));
        }
        if parts.is_empty() {
            "<span style=\"color:var(--ink-3);\">no source metadata</span>".to_string()
        } else {
            parts.join(" · ")
        }
    };

    // v0.66 richer view: evidence_spans block
    let mut spans_block = String::new();
    if f.evidence.evidence_spans.is_empty() {
        spans_block.push_str(
            r#"<p style="color:var(--ink-3);font-size:0.86rem;">No evidence_spans attached. Repair via /review/span-repair if the source has retrievable text.</p>"#,
        );
    } else {
        for s in &f.evidence.evidence_spans {
            let section = s
                .get("section")
                .and_then(|v| v.as_str())
                .unwrap_or("(unsectioned)");
            let text = s.get("text").and_then(|v| v.as_str()).unwrap_or("");
            if text.is_empty() {
                continue;
            }
            spans_block.push_str(&format!(
                r#"<blockquote style="color:var(--ink-2);font-size:0.92rem;margin:0.4rem 0 0.6rem 0;border-left:2px solid var(--ink-4);padding-left:0.8rem;"><strong>[{section}]</strong> {text}</blockquote>"#,
                section = escape_html(section),
                text = escape_html(text),
            ));
        }
    }

    // v0.66 richer view: review state + history of events touching
    // this finding. Walk state.events; filter to events whose target.id
    // equals this finding's id. Render in chronological order with the
    // event's reason + actor + timestamp.
    let review_state_label = match &f.flags.review_state {
        Some(vela_protocol::bundle::ReviewState::Accepted) => "<code>accepted</code>",
        Some(vela_protocol::bundle::ReviewState::Contested) => "<code>contested</code>",
        Some(vela_protocol::bundle::ReviewState::NeedsRevision) => "<code>needs_revision</code>",
        Some(vela_protocol::bundle::ReviewState::Rejected) => "<code>rejected</code>",
        None => "<span style=\"color:var(--ink-3);\">(unset)</span>",
    };
    let mut events_for_finding: Vec<&vela_protocol::events::StateEvent> = project
        .events
        .iter()
        .filter(|e| e.target.id == f.id)
        .collect();
    events_for_finding.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
    let mut history_block = String::new();
    if events_for_finding.is_empty() {
        history_block.push_str(
            r#"<p style="color:var(--ink-3);font-size:0.86rem;">No canonical events recorded against this finding yet.</p>"#,
        );
    } else {
        history_block.push_str(r#"<table class="wb-table"><thead><tr><th>event</th><th>when</th><th>kind</th><th>actor</th><th>reason</th></tr></thead><tbody>"#);
        for ev in &events_for_finding {
            let when = if ev.timestamp.len() >= 10 {
                &ev.timestamp[..10]
            } else {
                ev.timestamp.as_str()
            };
            history_block.push_str(&format!(
                r#"<tr><td><code>{event}</code></td><td><code>{when}</code></td><td><code>{kind}</code></td><td><code>{actor}</code></td><td>{reason}</td></tr>"#,
                event = escape_html(&ev.id),
                when = escape_html(when),
                kind = escape_html(&ev.kind),
                actor = escape_html(&ev.actor.id),
                reason = escape_html(&ev.reason),
            ));
        }
        history_block.push_str("</tbody></table>");
    }

    let mut caveat_items = Vec::new();
    if f.flags.review_state.is_none() && f.evidence.evidence_spans.is_empty() {
        caveat_items.push("Draft finding with no evidence spans yet.".to_string());
    }
    if f.flags.contested {
        caveat_items.push("Review state is contested.".to_string());
    }
    if f.flags.retracted {
        caveat_items.push("Finding is marked retracted.".to_string());
    }
    if f.flags.gap {
        caveat_items.push("Finding is marked as a gap.".to_string());
    }
    if f.flags.negative_space {
        caveat_items.push("Finding is marked as negative space.".to_string());
    }
    if let Some(review) = &f.provenance.review {
        for correction in &review.corrections {
            caveat_items.push(format!(
                "Review correction: {}",
                truncate(&correction.to_string(), 140)
            ));
        }
    }
    let caveats_block = if caveat_items.is_empty() {
        "No finding-level caveats are recorded.".to_string()
    } else {
        caveat_items
            .iter()
            .map(|item| format!("<p>{}</p>", escape_html(item)))
            .collect::<String>()
    };

    let finding_incidents = frontier_incident::incidents_for_finding(&state.repo_path, &f.id);
    let incidents_block = if finding_incidents.is_empty() {
        r#"<p style="color:var(--ink-3);font-size:0.86rem;">No local incidents are linked to this finding.</p>"#.to_string()
    } else {
        let rows = finding_incidents
            .iter()
            .map(|incident| {
                let tasks = if incident.linked_task_ids.is_empty() {
                    "none".to_string()
                } else {
                    incident
                        .linked_task_ids
                        .iter()
                        .map(|task_id| {
                            format!(
                                r#"<a href="/tasks/{path}/workspace"><code>{id}</code></a>"#,
                                path = urlencode_path(task_id),
                                id = escape_html(task_id)
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(" · ")
                };
                format!(
                    r#"<tr><td><code>{id}</code></td><td><code>{kind}</code></td><td>{status}</td><td>{title}</td><td>{tasks}</td></tr>"#,
                    id = escape_html(&incident.id),
                    kind = escape_html(incident.incident_type.as_str()),
                    status = escape_html(incident.status.as_str()),
                    title = escape_html(&incident.title),
                    tasks = tasks,
                )
            })
            .collect::<String>();
        format!(
            r#"<table class="wb-table"><thead><tr><th>incident</th><th>type</th><th>status</th><th>title</th><th>tasks</th></tr></thead><tbody>{rows}</tbody></table>"#
        )
    };

    let command_copy = render_command_copy(
        "Finding commands",
        &[
            format!(
                "vela history {}/frontier.json {}",
                state.repo_path.display(),
                f.id
            ),
            format!(
                "vela search \"{}\" --source {}/frontier.json",
                f.id,
                state.repo_path.display()
            ),
            format!(
                "vela proof {} --out /tmp/vela-proof",
                state.repo_path.display()
            ),
        ],
    );

    let body = format!(
        r#"<div class="wb-stats">
  <div><div class="wb-stat__num">{conf_pct}%</div><div class="wb-stat__label">confidence</div></div>
  <div><div class="wb-stat__num">{n_links}</div><div class="wb-stat__label">links</div></div>
  <div><div class="wb-stat__num">{n_events}</div><div class="wb-stat__label">events</div></div>
  <div><div class="wb-stat__num">{atype}</div><div class="wb-stat__label">type</div></div>
</div>
<div class="wb-card">
  <h3>Assertion</h3>
  <p>{assertion}</p>
  <p style="color:var(--ink-3);font-size:0.86rem;margin-top:0.4rem;">Source: {source_block} · Review state: {review_state_label} · Schema version: {ver}</p>
</div>
{command_copy}
{answer_return}
<div class="wb-card">
  <h3>source-ready verification</h3>
  <p>human verification records: <code>{human_verified_atom_count}/{atom_count}</code> evidence atom(s). Linked source records: <code>{source_count}</code>. Status: <code>{source_ready_status}</code>.</p>
  <p>This is derived context for review. It does not accept the finding or change the claim boundary.</p>
</div>
<div class="wb-card">
  <h3>Source records</h3>
  <table class="wb-table"><thead><tr><th>source</th><th>title</th><th>type</th><th>locator</th></tr></thead><tbody>{source_rows}</tbody></table>
</div>
<div class="wb-card">
  <h3>Evidence spans</h3>
  {spans_block}
</div>
<div class="wb-card">
  <h3>Evidence atoms</h3>
  <table class="wb-table"><thead><tr><th>atom</th><th>source</th><th>locator</th><th>review</th><th>claim</th></tr></thead><tbody>{atom_rows}</tbody></table>
</div>
<div class="wb-card">
  <h3>Links</h3>
  {links_html}
  <p><a href="/graph/path?finding={vf_path}">Open graph path view</a></p>
</div>
<div class="wb-card">
  <h3>Contradictions</h3>
  <table class="wb-table"><thead><tr><th>direction</th><th>kind</th><th>finding</th><th>note</th></tr></thead><tbody>{contradiction_rows}</tbody></table>
</div>
<div class="wb-card">
  <h3>Caveats</h3>
  {caveats_block}
</div>
<div class="wb-card">
  <h3>Events</h3>
  {history_block}
</div>
<div class="wb-card">
  <h3>Incidents</h3>
  {incidents_block}
</div>"#,
        n_links = f.links.len(),
        n_events = events_for_finding.len(),
        atype = escape_html(&f.assertion.assertion_type),
        ver = f.version,
        conf_pct = conf_pct,
        assertion = assertion,
        command_copy = command_copy,
        answer_return = answer_return,
        human_verified_atom_count = human_verified_atom_count,
        atom_count = finding_atoms.len(),
        source_count = finding_sources.len(),
        source_ready_status = escape_html(source_ready_status),
        source_block = source_block,
        review_state_label = review_state_label,
        source_rows = source_rows,
        spans_block = spans_block,
        atom_rows = atom_rows,
        links_html = links_html,
        vf_path = urlencode_path(&f.id),
        contradiction_rows = contradiction_rows,
        caveats_block = caveats_block,
        history_block = history_block,
        incidents_block = incidents_block,
    );

    Html(shell(
        "findings",
        &format!("{} · {}", vf_id, project.project.name),
        "Finding",
        &vf_id,
        &body,
    ))
    .into_response()
}

async fn page_proposals(State(state): State<AppState>) -> Response {
    let project = match repo::load_from_path(&state.repo_path) {
        Ok(p) => p,
        Err(e) => return error_page("proposals", "Could not load frontier", &e),
    };

    let mut proposals = project.proposals.clone();
    proposals.sort_by(|a, b| {
        status_rank(&a.status)
            .cmp(&status_rank(&b.status))
            .then(a.created_at.cmp(&b.created_at))
            .then(a.id.cmp(&b.id))
    });

    let pending = proposals
        .iter()
        .filter(|proposal| proposal.status == "pending_review")
        .count();
    let needs_revision = proposals
        .iter()
        .filter(|proposal| proposal.status == "needs_revision")
        .count();
    let applied = proposals
        .iter()
        .filter(|proposal| proposal.status == "applied")
        .count();
    let pending_agent_imports = proposals
        .iter()
        .filter(|proposal| {
            is_external_agent_import(proposal) && proposal.status == "pending_review"
        })
        .count();
    let rejected_agent_imports = proposals
        .iter()
        .filter(|proposal| is_external_agent_import(proposal) && proposal.status == "rejected")
        .count();

    let rows = proposals
        .iter()
        .take(300)
        .map(render_proposal_row)
        .collect::<String>();
    let body = format!(
        r#"<div class="wb-stats">
  <div><div class="wb-stat__num">{pending}</div><div class="wb-stat__label">pending</div></div>
  <div><div class="wb-stat__num">{needs_revision}</div><div class="wb-stat__label">revision</div></div>
  <div><div class="wb-stat__num">{applied}</div><div class="wb-stat__label">applied</div></div>
  <div><div class="wb-stat__num">{pending_agent_imports}</div><div class="wb-stat__label">pending agent imports</div></div>
  <div><div class="wb-stat__num">{rejected_agent_imports}</div><div class="wb-stat__label">rejected agent imports</div></div>
  <div><div class="wb-stat__num">{total}</div><div class="wb-stat__label">total</div></div>
</div>
<div class="wb-card">
  <h3>Proposal inbox</h3>
  <p>External runtime output is source material. Pending and rejected agent imports stay visible until local review decides what to do with them.</p>
  <pre><code>vela bridge-kit validate packet.json --json
vela proposals preview FRONTIER vpr_... --json</code></pre>
</div>
<table class="wb-table">
  <thead>
    <tr><th>status</th><th>proposal</th><th>target</th><th>packet/source</th><th>actions</th></tr>
  </thead>
  <tbody>
    {rows}
  </tbody>
</table>"#,
        total = proposals.len(),
        pending_agent_imports = pending_agent_imports,
        rejected_agent_imports = rejected_agent_imports,
    );

    Html(shell(
        "proposals",
        &format!("Proposal inbox · {}", project.project.name),
        "Workbench",
        "Proposal inbox",
        &body,
    ))
    .into_response()
}

async fn page_proposal_preview(
    AxumPath(vpr_id): AxumPath<String>,
    State(state): State<AppState>,
) -> Response {
    let project = match repo::load_from_path(&state.repo_path) {
        Ok(p) => p,
        Err(e) => return error_page("proposals", "Could not load frontier", &e),
    };
    let Some(proposal) = project
        .proposals
        .iter()
        .find(|proposal| proposal.id == vpr_id)
    else {
        return error_page("proposals", "Proposal not found", &vpr_id);
    };
    let preview = if matches!(
        proposal.status.as_str(),
        "pending_review" | "accepted" | "applied"
    ) {
        match proposals::preview_at_path(&state.repo_path, &vpr_id, "reviewer:workbench") {
            Ok(preview) => Some(preview),
            Err(e) => return error_page("proposals", "Could not preview proposal", &e),
        }
    } else {
        None
    };
    let findings_delta = preview.as_ref().map_or(0, |preview| preview.findings_delta);
    let artifacts_delta = preview
        .as_ref()
        .map_or(0, |preview| preview.artifacts_delta);
    let events_delta = preview.as_ref().map_or(0, |preview| preview.events_delta);
    let event_id = preview
        .as_ref()
        .map(|preview| preview.applied_event_id.clone())
        .or_else(|| proposal.applied_event_id.clone())
        .unwrap_or_else(|| "event not applied".to_string());
    let actions = if proposal.status == "pending_review" || proposal.status == "needs_revision" {
        format!(
            r#"<div class="wb-actions wb-actions--stacked">
  {}
  {}
  {}
</div>"#,
            render_proposal_decision_form(&proposal.id, "accept", "Accept"),
            render_proposal_decision_form(&proposal.id, "revision", "Request revision"),
            render_proposal_decision_form(&proposal.id, "reject", "Reject"),
        )
    } else {
        format!(
            r#"<div class="wb-card"><p>This proposal is <code>{}</code>. It is shown as review history.</p></div>"#,
            escape_html(&proposal.status)
        )
    };
    let changed_findings = preview
        .as_ref()
        .map(|preview| preview.changed_findings.clone())
        .unwrap_or_default();
    let changed_artifacts = preview
        .as_ref()
        .map(|preview| preview.changed_artifacts.clone())
        .unwrap_or_default();
    let event_kinds = preview
        .as_ref()
        .map(|preview| preview.event_kinds.clone())
        .unwrap_or_default();
    let changed_objects = changed_findings
        .iter()
        .chain(changed_artifacts.iter())
        .map(|id| format!("<code>{}</code>", escape_html(id)))
        .collect::<Vec<_>>()
        .join(" ");
    let changed_objects = if changed_objects.is_empty() {
        "No object ids changed in this preview.".to_string()
    } else {
        changed_objects
    };
    let event_kind_list = if event_kinds.is_empty() {
        "No new event kind is available for this proposal state.".to_string()
    } else {
        event_kinds
            .iter()
            .map(|kind| format!("<code>{}</code>", escape_html(kind)))
            .collect::<Vec<_>>()
            .join(" ")
    };
    let decision_record = match (&proposal.reviewed_by, &proposal.decision_reason) {
        (Some(reviewer), Some(reason)) => format!(
            r#"<p>Decision recorded by <code>{}</code>: {}</p>"#,
            escape_html(reviewer),
            escape_html(reason),
        ),
        _ => "<p>No reviewer decision has been recorded yet.</p>".to_string(),
    };
    let cli_equivalent = format!(
        "vela proposals preview FRONTIER {} --reviewer reviewer:you --json\nvela proposals accept FRONTIER {} --reviewer reviewer:you --reason \"Bounded reviewer reason.\" --json\nvela proposals reject FRONTIER {} --reviewer reviewer:you --reason \"Bounded reviewer reason.\" --json",
        proposal.id, proposal.id, proposal.id
    );
    let diff_text = if proposal.status == "applied" {
        format!(
            "This proposal already emitted <code>{}</code>. The preview reports the recorded event and leaves the frontier unchanged.",
            escape_html(&event_id)
        )
    } else if proposal.status == "rejected" {
        "This proposal was rejected. It remains visible as review history and is not applied to the frontier.".to_string()
    } else {
        format!(
            "Accepting this proposal would emit <code>{}</code> and mutate the in-memory frontier by the deltas above. This preview has not written to disk.",
            escape_html(&event_id)
        )
    };
    let body = format!(
        r#"<div class="wb-card">
  <h3><span class="wb-chip wb-chip--warn">preview</span>{id}</h3>
  <p>{reason}</p>
  <p><code>{kind}</code> targets <code>{target_type}:{target_id}</code></p>
</div>
<div class="wb-stats">
  <div><div class="wb-stat__num">{findings_delta:+}</div><div class="wb-stat__label">findings</div></div>
  <div><div class="wb-stat__num">{artifacts_delta:+}</div><div class="wb-stat__label">artifacts</div></div>
  <div><div class="wb-stat__num">{events_delta:+}</div><div class="wb-stat__label">events</div></div>
  <div><div class="wb-stat__num">stale</div><div class="wb-stat__label">proof after accept</div></div>
</div>
<div class="wb-card">
  <h3>Reviewer diff</h3>
  <p>{diff_text}</p>
  <p>External confidence, comments, and votes remain provenance. Only this review action changes canonical frontier state.</p>
</div>
<div class="wb-card">
  <h3>Changed objects</h3>
  <p>{changed_objects}</p>
  <h3>Event kinds</h3>
  <p>{event_kind_list}</p>
  <h3>CLI equivalent</h3>
  <pre><code>{cli_equivalent}</code></pre>
</div>
<div class="wb-card">
  <h3>Reviewer decision</h3>
  {decision_record}
</div>
<div class="wb-card">
  <h3>Source packet</h3>
  {packet}
</div>
{actions}
<div class="wb-card">
  <h3>Proposal payload</h3>
  <pre><code>{payload}</code></pre>
</div>"#,
        id = escape_html(&proposal.id),
        reason = escape_html(&proposal.reason),
        kind = escape_html(&proposal.kind),
        target_type = escape_html(&proposal.target.r#type),
        target_id = escape_html(&proposal.target.id),
        findings_delta = findings_delta,
        artifacts_delta = artifacts_delta,
        events_delta = events_delta,
        diff_text = diff_text,
        changed_objects = changed_objects,
        event_kind_list = event_kind_list,
        cli_equivalent = escape_html(&cli_equivalent),
        decision_record = decision_record,
        packet = render_packet_reference(proposal),
        actions = actions,
        payload = escape_html(&pretty_json(&proposal.payload)),
    );

    Html(shell(
        "proposals",
        &format!("Proposal preview · {}", project.project.name),
        "Proposal",
        &proposal.id,
        &body,
    ))
    .into_response()
}

async fn page_artifact_packets(State(state): State<AppState>) -> Response {
    let project = match repo::load_from_path(&state.repo_path) {
        Ok(p) => p,
        Err(e) => return error_page("packets", "Could not load frontier", &e),
    };
    let mut packets: BTreeMap<String, Vec<StateProposal>> = BTreeMap::new();
    for proposal in &project.proposals {
        if let Some(packet_id) = proposal_packet_id(proposal) {
            packets
                .entry(packet_id.to_string())
                .or_default()
                .push(proposal.clone());
        }
    }
    let cards = if packets.is_empty() {
        r#"<div class="wb-card"><p>No artifact packet provenance is present in the proposal ledger.</p></div>"#.to_string()
    } else {
        packets
            .iter()
            .map(|(packet_id, proposals)| {
                let applied = proposals
                    .iter()
                    .filter(|proposal| proposal.status == "applied")
                    .count();
                let pending = proposals
                    .iter()
                    .filter(|proposal| proposal.status == "pending_review")
                    .count();
                let proposal_links = proposals
                    .iter()
                    .map(|proposal| {
                        format!(
                            r#"<p><a href="/proposals/{id}/preview"><code>{id}</code></a> · {kind} · {status}</p>"#,
                            id = escape_html(&proposal.id),
                            kind = escape_html(&proposal.kind),
                            status = escape_html(&proposal.status),
                        )
                    })
                    .collect::<String>();
                format!(
                    r#"<div class="wb-card">
  <h3><span class="wb-chip wb-chip--ok">packet</span>{packet_id}</h3>
  <p><strong>{count}</strong> generated proposals · <strong>{applied}</strong> applied · <strong>{pending}</strong> pending review.</p>
  {proposal_links}
</div>"#,
                    packet_id = escape_html(packet_id),
                    count = proposals.len(),
                )
            })
            .collect::<String>()
    };
    let body = format!(
        r#"<div class="wb-card">
  <h3>Artifact packet ledger</h3>
  <p>ScienceClaw-shaped packets are source material. Vela records their artifacts, claims, and open needs as reviewable proposals before state changes.</p>
</div>
{cards}"#
    );
    Html(shell(
        "packets",
        &format!("Artifact packets · {}", project.project.name),
        "Workbench",
        "Artifact packets",
        &body,
    ))
    .into_response()
}

async fn page_proof_center(State(state): State<AppState>) -> Response {
    let project = match repo::load_from_path(&state.repo_path) {
        Ok(p) => p,
        Err(e) => return error_page("proof", "Could not load frontier", &e),
    };

    let integrity = vela_edge::state_integrity::analyze(&project);
    let signals = vela_edge::signals::analyze(&project, &[]);
    let packet = &project.proof_state.latest_packet;
    let recorded_snapshot = packet.snapshot_hash.as_deref().unwrap_or("not recorded");
    let recorded_event_log = packet.event_log_hash.as_deref().unwrap_or("not recorded");
    let current_snapshot = vela_protocol::events::snapshot_hash(&project);
    let current_event_log = vela_protocol::events::event_log_hash(&project.events);
    let generated_at = packet.generated_at.as_deref().unwrap_or("not generated");
    let manifest_hash = packet
        .packet_manifest_hash
        .as_deref()
        .unwrap_or("not recorded");
    let stale_reason = project
        .proof_state
        .stale_reason
        .as_deref()
        .unwrap_or("No stale reason is recorded.");
    let status_chip = match integrity.proof_freshness.as_str() {
        "fresh" => "ok",
        "stale" => "lost",
        _ => "warn",
    };
    let cli = format!(
        "vela integrity {} --json\nvela proof {} --out /tmp/vela-proof\nvela packet validate /tmp/vela-proof",
        state.repo_path.display(),
        state.repo_path.display(),
    );
    let answer_context_cli = format!(
        "open /frontier/answer-paths/efficacy_magnitude\nvela proof {} --out /tmp/vela-proof\njq '.proof_packet_refs // empty' projects/anti-amyloid-translation/review/answer-paths.v1.json",
        state.repo_path.display(),
    );

    let blockers = signals
        .signals
        .iter()
        .filter(|signal| signal.blocks.iter().any(|block| block == "proof_ready"))
        .take(8)
        .map(|signal| {
            format!(
                r#"<tr><td><code>{kind}</code></td><td><code>{target_type}:{target_id}</code></td><td>{reason}</td></tr>"#,
                kind = escape_html(&signal.kind),
                target_type = escape_html(&signal.target.r#type),
                target_id = escape_html(&signal.target.id),
                reason = escape_html(&signal.reason),
            )
        })
        .collect::<String>();
    let blockers = if blockers.is_empty() {
        r#"<tr><td colspan="3">No proof-readiness blockers from current signals.</td></tr>"#
            .to_string()
    } else {
        blockers
    };

    let session_rail = reviewer_session_rail_html(
        &state.repo_path,
        &format!("proof:{}", project.frontier_id()),
        &[project.frontier_id()],
    );
    let body = format!(
        r#"<div class="wb-card">
  <h3><span class="wb-chip wb-chip--{status_chip}">proof</span>Proof center</h3>
  <p>proof freshness is derived from frontier state. It is review state, not a claim that the science is settled.</p>
</div>
{session_rail}
<div class="wb-stats">
  <div><div class="wb-stat__num">{freshness}</div><div class="wb-stat__label">Proof freshness</div></div>
  <div><div class="wb-stat__num">{packet_status}</div><div class="wb-stat__label">packet state</div></div>
  <div><div class="wb-stat__num">{blockers_count}</div><div class="wb-stat__label">readiness blockers</div></div>
  <div><div class="wb-stat__num">{warnings}</div><div class="wb-stat__label">warnings</div></div>
</div>
<div class="wb-grid">
  <div class="wb-card">
    <h3>Recorded packet</h3>
    <p>Generated: <code>{generated_at}</code></p>
    <p>snapshot hash: <code>{recorded_snapshot}</code></p>
    <p>event-log hash: <code>{recorded_event_log}</code></p>
    <p>manifest hash: <code>{manifest_hash}</code></p>
  </div>
  <div class="wb-card">
    <h3>Current frontier</h3>
    <p>snapshot hash: <code>{current_snapshot}</code></p>
    <p>event-log hash: <code>{current_event_log}</code></p>
    <p>stale reason: {stale_reason}</p>
  </div>
</div>
<div class="wb-card">
  <h3>Proof readiness</h3>
  <p>Status: <code>{readiness}</code>. Blockers: <code>{blockers_count}</code>. Warnings: <code>{warnings}</code>.</p>
  <table class="wb-table"><thead><tr><th>kind</th><th>target</th><th>reason</th></tr></thead><tbody>{blockers}</tbody></table>
</div>
<div class="wb-card">
  <h3>CLI equivalent</h3>
  <pre><code>{cli}</code></pre>
</div>
<div class="wb-card">
  <h3>answer-context proof export</h3>
  <p>Use answer path source context before sharing a proof packet. The proof packet is frontier-level; the answer path tells the reviewer which findings, sources, caveats, and source trails triggered the export.</p>
  <pre><code>{answer_context_cli}</code></pre>
</div>"#,
        status_chip = status_chip,
        freshness = escape_html(&integrity.proof_freshness),
        packet_status = escape_html(&packet.status),
        blockers_count = signals.proof_readiness.blockers,
        warnings = signals.proof_readiness.warnings,
        generated_at = escape_html(generated_at),
        recorded_snapshot = escape_html(recorded_snapshot),
        recorded_event_log = escape_html(recorded_event_log),
        manifest_hash = escape_html(manifest_hash),
        current_snapshot = escape_html(&current_snapshot),
        current_event_log = escape_html(&current_event_log),
        stale_reason = escape_html(stale_reason),
        readiness = escape_html(&signals.proof_readiness.status),
        blockers = blockers,
        cli = escape_html(&cli),
        answer_context_cli = escape_html(&answer_context_cli),
        session_rail = session_rail,
    );

    Html(shell(
        "proof",
        &format!("Proof center · {}", project.project.name),
        "Workbench",
        "Proof center",
        &body,
    ))
    .into_response()
}

fn read_graph_json(repo_path: &Path, name: &str) -> Option<serde_json::Value> {
    let path = repo_path.join(".vela").join("graph").join(name);
    let body = fs::read_to_string(path).ok()?;
    serde_json::from_str(&body).ok()
}

fn graph_node_path(graph: &serde_json::Value, node_id: &str) -> String {
    graph
        .get("nodes")
        .and_then(serde_json::Value::as_array)
        .and_then(|nodes| {
            nodes.iter().find_map(|node| {
                if node.get("id").and_then(serde_json::Value::as_str) == Some(node_id) {
                    node.get("path")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_string)
                } else {
                    None
                }
            })
        })
        .unwrap_or_else(|| "not indexed".to_string())
}

async fn page_graph_path(
    State(state): State<AppState>,
    Query(query): Query<GraphPathQuery>,
) -> Response {
    let project = match repo::load_from_path(&state.repo_path) {
        Ok(p) => p,
        Err(e) => return error_page("graph path", "Could not load frontier", &e),
    };
    let selected_finding_id = if query.finding.trim().is_empty() {
        project
            .findings
            .iter()
            .find(|finding| !finding.links.is_empty())
            .or_else(|| project.findings.first())
            .map(|finding| finding.id.clone())
            .unwrap_or_default()
    } else {
        query.finding.clone()
    };
    let Some(finding) = project
        .findings
        .iter()
        .find(|finding| finding.id == selected_finding_id)
    else {
        return error_page("graph path", "Finding not found", &selected_finding_id);
    };

    let graph = read_graph_json(&state.repo_path, "frontier-graph.v1.json")
        .unwrap_or_else(|| serde_json::json!({"nodes": [], "edges": []}));
    let impact = read_graph_json(&state.repo_path, "impact-index.v1.json")
        .unwrap_or_else(|| serde_json::json!({"finding_neighborhoods": []}));

    let finding_to_finding_rows = {
        let mut rows = String::new();
        for link in &finding.links {
            rows.push_str(&format!(
                r#"<tr><td><code>{source}</code></td><td><code>{relation}</code></td><td><a href="/findings/{target_path}"><code>{target}</code></a></td><td>{path}</td></tr>"#,
                source = escape_html(&finding.id),
                relation = escape_html(&link.link_type),
                target_path = urlencode_path(&link.target),
                target = escape_html(&link.target),
                path = escape_html(&graph_node_path(&graph, &link.target)),
            ));
        }
        for other in &project.findings {
            for link in other.links.iter().filter(|link| link.target == finding.id) {
                rows.push_str(&format!(
                    r#"<tr><td><a href="/findings/{source_path}"><code>{source}</code></a></td><td><code>incoming:{relation}</code></td><td><code>{target}</code></td><td>{path}</td></tr>"#,
                    source_path = urlencode_path(&other.id),
                    source = escape_html(&other.id),
                    relation = escape_html(&link.link_type),
                    target = escape_html(&finding.id),
                    path = escape_html(&graph_node_path(&graph, &other.id)),
                ));
            }
        }
        if rows.is_empty() {
            r#"<tr><td colspan="4">No finding-to-finding graph paths are recorded for this finding.</td></tr>"#.to_string()
        } else {
            rows
        }
    };

    let finding_atoms = project
        .evidence_atoms
        .iter()
        .filter(|atom| atom.finding_id == finding.id)
        .collect::<Vec<_>>();
    let finding_to_source_rows = if finding_atoms.is_empty() {
        r#"<tr><td colspan="4">No finding-to-source evidence-atom paths are recorded for this finding.</td></tr>"#.to_string()
    } else {
        finding_atoms
            .iter()
            .map(|atom| {
                format!(
                    r#"<tr><td><code>{finding}</code></td><td><code>{atom}</code></td><td><a href="/sources/{source_path}"><code>{source}</code></a></td><td>{locator}</td></tr>"#,
                    finding = escape_html(&finding.id),
                    atom = escape_html(&atom.id),
                    source_path = urlencode_path(&atom.source_id),
                    source = escape_html(&atom.source_id),
                    locator = atom
                        .locator
                        .as_deref()
                        .map(escape_html)
                        .unwrap_or_else(|| "missing".to_string()),
                )
            })
            .collect::<String>()
    };

    let proof_file_rows = impact
        .get("finding_neighborhoods")
        .and_then(serde_json::Value::as_array)
        .and_then(|rows| {
            rows.iter().find(|row| {
                row.get("finding_id").and_then(serde_json::Value::as_str)
                    == Some(finding.id.as_str())
            })
        })
        .and_then(|row| row.get("neighbors").and_then(serde_json::Value::as_array))
        .map(|neighbors| {
            neighbors
                .iter()
                .filter(|neighbor| {
                    neighbor
                        .get("node_id")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|node| node.starts_with("proof_file:"))
                })
                .map(|neighbor| {
                    let node = neighbor
                        .get("node_id")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("");
                    format!(
                        r#"<tr><td><code>{node}</code></td><td><code>{relation}</code></td><td>{path}</td></tr>"#,
                        node = escape_html(node),
                        relation = escape_html(
                            neighbor
                                .get("relation")
                                .and_then(serde_json::Value::as_str)
                                .unwrap_or("included_in_proof")
                        ),
                        path = escape_html(&graph_node_path(&graph, node)),
                    )
                })
                .collect::<String>()
        })
        .filter(|rows| !rows.is_empty())
        .unwrap_or_else(|| {
            r#"<tr><td colspan="3">No proof file paths are indexed for this finding.</td></tr>"#
                .to_string()
        });

    let intervention_rows = graph
        .get("edges")
        .and_then(serde_json::Value::as_array)
        .map(|edges| {
            edges
                .iter()
                .filter(|edge| {
                    edge.get("source")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|source| source.starts_with("intervention_packet:"))
                })
                .take(8)
                .map(|edge| {
                    let source = edge
                        .get("source")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("");
                    let target = edge
                        .get("target")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("");
                    format!(
                        r#"<tr><td><code>{source}</code></td><td><code>{relation}</code></td><td><code>{target}</code></td><td>{path}</td></tr>"#,
                        source = escape_html(source),
                        relation = escape_html(
                            edge.get("relation")
                                .and_then(serde_json::Value::as_str)
                                .unwrap_or("")
                        ),
                        target = escape_html(target),
                        path = escape_html(&graph_node_path(&graph, source)),
                    )
                })
                .collect::<String>()
        })
        .filter(|rows| !rows.is_empty())
        .unwrap_or_else(|| {
            r#"<tr><td colspan="4">No intervention packet paths are indexed.</td></tr>"#.to_string()
        });

    let correction_rows = graph
        .get("nodes")
        .and_then(serde_json::Value::as_array)
        .map(|nodes| {
            nodes
                .iter()
                .filter(|node| {
                    node.get("kind").and_then(serde_json::Value::as_str)
                        == Some("correction_return")
                })
                .map(|node| {
                    let id = node
                        .get("id")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("");
                    format!(
                        r#"<tr><td><code>{id}</code></td><td>{label}</td><td>{path}</td></tr>"#,
                        id = escape_html(id),
                        label = escape_html(
                            node.get("label")
                                .and_then(serde_json::Value::as_str)
                                .unwrap_or("correction return")
                        ),
                        path = escape_html(
                            node.get("path")
                                .and_then(serde_json::Value::as_str)
                                .unwrap_or("not indexed")
                        ),
                    )
                })
                .collect::<String>()
        })
        .filter(|rows| !rows.is_empty())
        .unwrap_or_else(|| {
            r#"<tr><td colspan="3">No correction return paths are indexed.</td></tr>"#.to_string()
        });

    let command_copy = render_command_copy(
        "Graph commands",
        &[
            format!(
                "vela index query {} --kind finding --q {} --json",
                state.repo_path.display(),
                finding.id
            ),
            format!(
                "jq '.edges[] | select(.source == \"{}\" or .target == \"{}\")' {}/.vela/graph/frontier-graph.v1.json",
                finding.id,
                finding.id,
                state.repo_path.display()
            ),
            format!(
                "vela proof {} --out /tmp/vela-proof",
                state.repo_path.display()
            ),
        ],
    );

    let body = format!(
        r#"<section class="wb-hero" aria-label="Graph path view">
  <div class="wb-hero__grid">
    <div>
      <h2>Graph path view</h2>
      <p>This read-only view traces derived graph paths from checked frontier artifacts. The graph is a navigation aid, not canonical state.</p>
    </div>
    <div class="wb-status-panel" aria-label="Graph path boundary">
      <div><span>Finding</span><strong>{finding_id}</strong></div>
      <div><span>Graph source</span><strong>.vela/graph</strong></div>
      <div><span>Canonical state</span><strong>frontier files</strong></div>
    </div>
  </div>
</section>
{command_copy}
<div class="wb-card">
  <h3>Finding-to-finding paths</h3>
  <table class="wb-table"><thead><tr><th>source</th><th>relation</th><th>target</th><th>path</th></tr></thead><tbody>{finding_to_finding_rows}</tbody></table>
</div>
<div class="wb-card">
  <h3>Finding-to-source paths</h3>
  <table class="wb-table"><thead><tr><th>finding</th><th>evidence atom</th><th>source</th><th>locator</th></tr></thead><tbody>{finding_to_source_rows}</tbody></table>
</div>
<div class="wb-card">
  <h3>Intervention packet paths</h3>
  <table class="wb-table"><thead><tr><th>packet</th><th>relation</th><th>target</th><th>path</th></tr></thead><tbody>{intervention_rows}</tbody></table>
</div>
<div class="wb-card">
  <h3>Correction return paths</h3>
  <table class="wb-table"><thead><tr><th>return</th><th>label</th><th>path</th></tr></thead><tbody>{correction_rows}</tbody></table>
</div>
<div class="wb-card">
  <h3>Proof file paths</h3>
  <table class="wb-table"><thead><tr><th>proof file</th><th>relation</th><th>path</th></tr></thead><tbody>{proof_file_rows}</tbody></table>
</div>
<div class="wb-card">
  <h3>Boundary</h3>
  <p>Graph paths are derived review material. They do not accept findings, update source records, validate interventions, or claim proof freshness by themselves.</p>
</div>"#,
        finding_id = escape_html(&finding.id),
        command_copy = command_copy,
        finding_to_finding_rows = finding_to_finding_rows,
        finding_to_source_rows = finding_to_source_rows,
        intervention_rows = intervention_rows,
        correction_rows = correction_rows,
        proof_file_rows = proof_file_rows,
    );

    Html(shell(
        "graph-path",
        "Graph path view · Vela workbench",
        "Workbench",
        "Graph path view",
        &body,
    ))
    .into_response()
}

async fn page_sources(State(state): State<AppState>) -> Response {
    let project = match repo::load_from_path(&state.repo_path) {
        Ok(p) => p,
        Err(e) => return error_page("sources", "Could not load frontier", &e),
    };
    let source_summary = vela_protocol::sources::source_summary(&project);
    let evidence_summary = vela_protocol::sources::evidence_summary(&project);
    let signals = vela_edge::signals::analyze(&project, &[]);
    let source_issue_count = signals
        .signals
        .iter()
        .filter(|signal| signal.target.r#type == "source" || signal.kind.contains("source"))
        .count();

    let mut rows = String::new();
    for source in project.sources.iter().take(300) {
        rows.push_str(&format!(
            r#"<tr>
  <td><a href="/sources/{sid_path}"><code>{sid}</code></a></td>
  <td>{title}</td>
  <td><code>{source_type}</code></td>
  <td>{locator}</td>
  <td>{findings}</td>
</tr>"#,
            sid_path = urlencode_path(&source.id),
            sid = escape_html(&source.id),
            title = escape_html(&truncate(&source.title, 96)),
            source_type = escape_html(&source.source_type),
            locator = escape_html(&truncate(&source.locator, 80)),
            findings = source.finding_ids.len(),
        ));
    }
    if rows.is_empty() {
        rows.push_str(r#"<tr><td colspan="5">No source records are materialized for this frontier.</td></tr>"#);
    }

    let command_copy = render_command_copy(
        "Source list commands",
        &[
            format!("vela index status {} --json", state.repo_path.display()),
            format!(
                "vela index query {} --kind source --q doi --json",
                state.repo_path.display()
            ),
            format!(
                "vela check {}/frontier.json --strict --json",
                state.repo_path.display()
            ),
        ],
    );
    let body = format!(
        r#"<div class="wb-card">
  <h3>Source and evidence audit</h3>
  <p>Sources identify imported material. Evidence atoms identify the exact source-grounded unit that bears on a finding.</p>
</div>
{command_copy}
<div class="wb-stats">
  <div><div class="wb-stat__num">{source_count}</div><div class="wb-stat__label">source coverage</div></div>
  <div><div class="wb-stat__num">{atom_count}</div><div class="wb-stat__label">evidence atoms</div></div>
  <div><div class="wb-stat__num">{missing_locators}</div><div class="wb-stat__label">missing locators</div></div>
  <div><div class="wb-stat__num">{source_issue_count}</div><div class="wb-stat__label">unresolved source issues</div></div>
</div>
<div class="wb-card">
  <h3>Source records</h3>
  <table class="wb-table">
    <thead><tr><th>source</th><th>title</th><th>type</th><th>locator</th><th>findings</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div>"#,
        source_count = source_summary.count,
        atom_count = evidence_summary.count,
        missing_locators = evidence_summary.missing_locator_count,
        source_issue_count = source_issue_count,
        command_copy = command_copy,
        rows = rows,
    );

    Html(shell(
        "sources",
        &format!("Sources · {}", project.project.name),
        "Workbench",
        "Source and evidence audit",
        &body,
    ))
    .into_response()
}

async fn page_source_detail(
    AxumPath(source_id): AxumPath<String>,
    State(state): State<AppState>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let project = match repo::load_from_path(&state.repo_path) {
        Ok(p) => p,
        Err(e) => return error_page("sources", "Could not load frontier", &e),
    };
    let Some(source) = project.sources.iter().find(|source| source.id == source_id) else {
        return error_page("sources", "Source not found", &source_id);
    };
    let atoms: Vec<&vela_protocol::sources::EvidenceAtom> = project
        .evidence_atoms
        .iter()
        .filter(|atom| atom.source_id == source.id)
        .collect();
    let affected_finding_ids = source
        .finding_ids
        .iter()
        .cloned()
        .chain(atoms.iter().map(|atom| atom.finding_id.clone()))
        .collect::<BTreeSet<_>>();
    let affected_findings = project
        .findings
        .iter()
        .filter(|finding| affected_finding_ids.contains(&finding.id))
        .collect::<Vec<_>>();
    let answer_path_context = query.get("answer_path").map(String::as_str).unwrap_or("");
    let answer_query = answer_path_query(answer_path_context);
    let answer_return = answer_path_return_panel(answer_path_context);

    let linked_findings = affected_findings
        .iter()
        .take(100)
        .map(|finding| {
            format!(
                r#"<tr><td><a href="/findings/{fid_path}{answer_query}"><code>{fid}</code></a></td><td>{text}</td></tr>"#,
                fid_path = urlencode_path(&finding.id),
                answer_query = answer_query,
                fid = escape_html(&finding.id),
                text = escape_html(&truncate(&finding.assertion.text, 110)),
            )
        })
        .collect::<String>();
    let linked_findings = if linked_findings.is_empty() {
        r#"<tr><td colspan="2">No linked findings recorded.</td></tr>"#.to_string()
    } else {
        linked_findings
    };
    let source_locator = source.locator.trim();
    let locator_scheme = source_locator
        .split_once(':')
        .map(|(scheme, _)| scheme)
        .filter(|scheme| !scheme.is_empty())
        .unwrap_or("none");
    let locator_health = if source_locator.is_empty() {
        "missing locator"
    } else if matches!(
        locator_scheme,
        "doi" | "pmid" | "pmcid" | "nct" | "url" | "https" | "http"
    ) {
        "scheme-backed locator"
    } else if source.doi.is_some() || source.pmid.is_some() {
        "identifier-backed locator"
    } else {
        "preserved locator needs retrieval review"
    };
    let atom_locator_count = atoms
        .iter()
        .filter(|atom| {
            atom.locator
                .as_deref()
                .map(|locator| !locator.trim().is_empty())
                .unwrap_or(false)
        })
        .count();
    let atom_locator_gap_count = atoms.len().saturating_sub(atom_locator_count);
    let source_debt_queue = load_workspace_json(
        &state.repo_path,
        "projects/anti-amyloid-translation/review/source-debt-queue.v1.json",
    )
    .unwrap_or_else(|| serde_json::json!({}));
    let source_debt_items = source_debt_queue
        .get("items")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|item| affected_finding_ids.contains(json_str(item, "finding_id")))
        .collect::<Vec<_>>();
    let source_debt_count = source_debt_items.len();
    let source_debt_high = source_debt_items
        .iter()
        .filter(|item| json_str(item, "priority") == "high")
        .count();
    let source_debt_medium = source_debt_items
        .iter()
        .filter(|item| json_str(item, "priority") == "medium")
        .count();
    let atom_rows = atoms
        .iter()
        .take(120)
        .map(|atom| {
            format!(
                r#"<tr><td><code>{aid}</code></td><td><a href="/findings/{fid_path}{answer_query}"><code>{fid}</code></a></td><td>{locator}</td><td>{verified}</td><td>{claim}</td></tr>"#,
                aid = escape_html(&atom.id),
                fid_path = urlencode_path(&atom.finding_id),
                answer_query = answer_query,
                fid = escape_html(&atom.finding_id),
                locator = atom.locator.as_deref().map(escape_html).unwrap_or_else(|| "missing".to_string()),
                verified = if atom.human_verified { "verified" } else { "needs review" },
                claim = escape_html(&truncate(&atom.measurement_or_claim, 90)),
            )
        })
        .collect::<String>();
    let atom_rows = if atom_rows.is_empty() {
        r#"<tr><td colspan="5">No evidence atoms recorded for this source.</td></tr>"#.to_string()
    } else {
        atom_rows
    };
    let caveats = if source.caveats.is_empty() {
        "No source-level caveats recorded.".to_string()
    } else {
        source
            .caveats
            .iter()
            .map(|caveat| format!("<p>{}</p>", escape_html(caveat)))
            .collect::<String>()
    };

    let session_rail = reviewer_session_rail_html(
        &state.repo_path,
        &format!("source:{}", source.id),
        std::slice::from_ref(&source.id),
    );
    let command_copy = render_command_copy(
        "Source commands",
        &[
            format!(
                "vela search \"{}\" --source {}/frontier.json",
                source.id,
                state.repo_path.display()
            ),
            format!(
                "vela index query {} --kind source --q {}",
                state.repo_path.display(),
                source.id
            ),
            format!(
                "vela proof {} --out /tmp/vela-proof",
                state.repo_path.display()
            ),
        ],
    );
    let body = format!(
        r#"<div class="wb-card">
  <h3><span class="wb-chip wb-chip--ok">source</span>Source record</h3>
  <p><code>{sid}</code></p>
  <p>{title}</p>
  <p><code>{source_type}</code> · <code>{quality}</code> · {year}</p>
  <p>locator: <code>{locator}</code></p>
  <p>content hash: <code>{content_hash}</code></p>
</div>
{command_copy}
{answer_return}
{session_rail}
<div class="wb-card">
  <h3>source-debt banner</h3>
  <p>source-quality wave artifact: <code>projects/anti-amyloid-translation/review/source-debt-queue.v1.json</code>. verification artifact: <code>tests/test-workbench-first-frontier-usability-v0674.sh</code>.</p>
  <p>Linked finding debt: <code>{source_debt_count}</code> item(s), including <code>{source_debt_high}</code> high and <code>{source_debt_medium}</code> medium priority row(s).</p>
  <p>This banner is operational source debt. It does not reject the source or mark the linked findings false.</p>
</div>
<div class="wb-card">
  <h3>Locator health</h3>
  <dl class="wb-meta">
    <dt>status</dt><dd>{locator_health}</dd>
    <dt>scheme</dt><dd><code>{locator_scheme}</code></dd>
    <dt>source locator</dt><dd><code>{locator}</code></dd>
    <dt>evidence atoms</dt><dd>{atom_count}</dd>
    <dt>atom locator gaps</dt><dd>{atom_locator_gap_count}</dd>
    <dt>affected findings</dt><dd>{affected_finding_count}</dd>
  </dl>
  <p>Locator health is an operational retrieval signal. It does not judge whether the finding is true.</p>
</div>
<div class="wb-card">
  <h3>Caveats</h3>
  {caveats}
</div>
<div class="wb-card">
  <h3>Affected findings</h3>
  <table class="wb-table"><thead><tr><th>finding</th><th>assertion</th></tr></thead><tbody>{linked_findings}</tbody></table>
</div>
<div class="wb-card">
  <h3>Evidence atoms</h3>
  <table class="wb-table"><thead><tr><th>atom</th><th>finding</th><th>locator</th><th>review</th><th>claim</th></tr></thead><tbody>{atom_rows}</tbody></table>
</div>"#,
        sid = escape_html(&source.id),
        title = escape_html(&source.title),
        source_type = escape_html(&source.source_type),
        quality = escape_html(&source.source_quality),
        year = source
            .year
            .map_or("year n/a".to_string(), |year| year.to_string()),
        locator = escape_html(&source.locator),
        content_hash = source
            .content_hash
            .as_deref()
            .map(escape_html)
            .unwrap_or_else(|| "not recorded".to_string()),
        locator_health = escape_html(locator_health),
        locator_scheme = escape_html(locator_scheme),
        atom_count = atoms.len(),
        atom_locator_gap_count = atom_locator_gap_count,
        affected_finding_count = affected_findings.len(),
        source_debt_count = source_debt_count,
        source_debt_high = source_debt_high,
        source_debt_medium = source_debt_medium,
        caveats = caveats,
        linked_findings = linked_findings,
        atom_rows = atom_rows,
        command_copy = command_copy,
        answer_return = answer_return,
        session_rail = session_rail,
    );

    Html(shell(
        "sources",
        &format!("{} · {}", source.id, project.project.name),
        "Source",
        &source.id,
        &body,
    ))
    .into_response()
}

fn status_rank(status: &str) -> u8 {
    match status {
        "pending_review" => 0,
        "needs_revision" => 1,
        "accepted" => 2,
        "applied" => 3,
        "rejected" => 4,
        _ => 5,
    }
}

fn is_external_agent_import(proposal: &StateProposal) -> bool {
    proposal
        .agent_run
        .as_ref()
        .is_some_and(|run| run.model.starts_with("runtime-adapter:"))
        || proposal.payload.get("artifact_packet").is_some()
}

fn render_proposal_row(proposal: &StateProposal) -> String {
    let chip = match proposal.status.as_str() {
        "applied" | "accepted" => "ok",
        "pending_review" | "needs_revision" => "warn",
        "rejected" => "lost",
        _ => "warn",
    };
    let packet = proposal_packet_id(proposal).unwrap_or("");
    let source = if packet.is_empty() {
        proposal
            .source_refs
            .first()
            .map(|value| escape_html(value))
            .unwrap_or_else(|| "source not declared".to_string())
    } else {
        format!("<code>{}</code>", escape_html(packet))
    };
    let actions = if matches!(
        proposal.status.as_str(),
        "pending_review" | "needs_revision"
    ) {
        format!(
            r#"<div class="wb-actions">
  <a href="/proposals/{id}/preview">Preview and decide</a>
</div>"#,
            id = escape_html(&proposal.id),
        )
    } else {
        format!(
            r#"<a href="/proposals/{}/preview">Preview</a>"#,
            escape_html(&proposal.id)
        )
    };
    format!(
        r#"<tr>
  <td><span class="wb-chip wb-chip--{chip}">{status}</span></td>
  <td><a href="/proposals/{id}/preview"><code>{id}</code></a><br>{reason}</td>
  <td><code>{target_type}:{target_id}</code><br><code>{kind}</code></td>
  <td>{source}</td>
  <td>{actions}</td>
</tr>"#,
        status = escape_html(&proposal.status),
        id = escape_html(&proposal.id),
        reason = escape_html(&proposal.reason),
        target_type = escape_html(&proposal.target.r#type),
        target_id = escape_html(&proposal.target.id),
        kind = escape_html(&proposal.kind),
    )
}

fn render_proposal_decision_form(proposal_id: &str, action: &str, label: &str) -> String {
    let preview = render_mutation_preview(
        label,
        proposal_id,
        &format!("proposal decision route /proposals/{proposal_id}/{action}"),
        "updates the proposal decision state and emits a reviewer decision event when the validator accepts it",
    );
    format!(
        r#"{preview}<form method="post" action="/proposals/{id}/{action}" class="wb-decision-form">
  <label>Reviewer identity
    <input name="reviewer" required pattern="[^:]+:.+" placeholder="reviewer:you" autocomplete="off">
  </label>
  <label>Decision reason
    <input name="reason" required minlength="12" placeholder="Bounded reviewer reason.">
  </label>
  <button type="submit">{label}</button>
</form>"#,
        preview = preview,
        id = escape_html(proposal_id),
        action = escape_html(action),
        label = escape_html(label),
    )
}

fn proposal_packet_id(proposal: &StateProposal) -> Option<&str> {
    proposal
        .payload
        .get("artifact_packet")
        .and_then(|packet| packet.get("packet_id"))
        .and_then(|value| value.as_str())
        .or_else(|| {
            proposal
                .payload
                .get("artifact_packet_id")
                .and_then(|value| value.as_str())
        })
}

fn render_packet_reference(proposal: &StateProposal) -> String {
    let Some(packet) = proposal.payload.get("artifact_packet") else {
        return "<p>No artifact packet metadata is attached.</p>".to_string();
    };
    let packet_id = packet
        .get("packet_id")
        .and_then(|value| value.as_str())
        .unwrap_or("packet id unavailable");
    let producer = packet
        .get("producer")
        .and_then(|producer| producer.get("id"))
        .and_then(|value| value.as_str())
        .unwrap_or("producer unavailable");
    let artifact_ids = packet
        .get("external_artifact_ids")
        .and_then(|value| value.as_array())
        .map(|ids| {
            ids.iter()
                .filter_map(|value| value.as_str())
                .map(|id| format!("<code>{}</code>", escape_html(id)))
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default();
    format!(
        r#"<p><code>{}</code> from <code>{}</code></p><p>{}</p>"#,
        escape_html(packet_id),
        escape_html(producer),
        artifact_ids
    )
}

fn pretty_json(value: &serde_json::Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| "{}".to_string())
}

async fn page_audit(State(state): State<AppState>) -> Response {
    let project = match repo::load_from_path(&state.repo_path) {
        Ok(p) => p,
        Err(e) => return error_page("audit", "Could not load frontier", &e),
    };

    let mut entries = audit_frontier(&project);
    let summary = summarize_audit(&entries);
    entries.retain(|e| {
        matches!(
            e.verdict,
            Identifiability::Underidentified | Identifiability::Conditional
        )
    });

    let mut rows = String::new();
    for e in &entries {
        let chip = match e.verdict {
            Identifiability::Underidentified => "lost",
            Identifiability::Conditional => "warn",
            _ => continue,
        };
        let claim = e
            .causal_claim
            .map_or("n/a".to_string(), |c| format!("{c:?}").to_lowercase());
        let grade = e
            .causal_evidence_grade
            .map_or("n/a".to_string(), |g| format!("{g:?}").to_lowercase());
        let text: String = e.assertion_text.chars().take(120).collect();
        rows.push_str(&format!(
            r#"<tr>
  <td><span class="wb-chip wb-chip--{chip}">{verdict}</span></td>
  <td><a href="/findings/{vf}"><code>{vf_short}</code></a></td>
  <td>{claim} / {grade}</td>
  <td>{text}</td>
</tr>"#,
            chip = chip,
            verdict = match e.verdict {
                Identifiability::Underidentified => "underidentified",
                Identifiability::Conditional => "conditional",
                _ => "n/a",
            },
            vf = escape_html(&e.finding_id),
            vf_short = escape_html(&e.finding_id),
            claim = escape_html(&claim),
            grade = escape_html(&grade),
            text = escape_html(&text),
        ));
    }

    let stats_html = format!(
        r#"<div class="wb-stats">
  <div><div class="wb-stat__num">{}</div><div class="wb-stat__label">identified</div></div>
  <div><div class="wb-stat__num">{}</div><div class="wb-stat__label">conditional</div></div>
  <div><div class="wb-stat__num">{}</div><div class="wb-stat__label">underidentified</div></div>
  <div><div class="wb-stat__num">{}</div><div class="wb-stat__label">underdetermined</div></div>
</div>"#,
        summary.identified, summary.conditional, summary.underidentified, summary.underdetermined,
    );

    let body = if entries.is_empty() {
        format!(
            "{stats_html}<div class=\"wb-card\"><p>No reviewer-attention items. Audit clean.</p></div>"
        )
    } else {
        format!(
            r#"{stats_html}
<table class="wb-table">
  <thead>
    <tr><th>verdict</th><th>finding</th><th>claim/grade</th><th>assertion</th></tr>
  </thead>
  <tbody>
{rows}
  </tbody>
</table>"#
        )
    };

    Html(shell(
        "audit",
        "Causal audit",
        "Workbench",
        "Identifiability audit",
        &body,
    ))
    .into_response()
}

async fn page_bridges(State(state): State<AppState>) -> Response {
    let bridges = list_bridges(&state.repo_path);

    if bridges.is_empty() {
        let body = r#"<div class="wb-card">
  <p>No bridges yet. Derive one with:</p>
  <p><code>vela bridges derive &lt;frontier_a&gt; &lt;frontier_b&gt;</code></p>
</div>"#;
        return Html(shell("bridges", "Bridges", "Workbench", "No bridges", body)).into_response();
    }

    let mut cards = String::new();
    for b in &bridges {
        let chip = match b.status {
            BridgeStatus::Confirmed => "ok",
            BridgeStatus::Refuted => "lost",
            BridgeStatus::Derived => "warn",
        };
        let chip_label = match b.status {
            BridgeStatus::Confirmed => "confirmed",
            BridgeStatus::Refuted => "refuted",
            BridgeStatus::Derived => "derived",
        };

        let mut refs_html = String::new();
        for r in b.finding_refs.iter().take(6) {
            let txt: String = r.assertion_text.chars().take(110).collect();
            refs_html.push_str(&format!(
                "<p>· <code>[{}]</code> <code>{}</code> conf {:.2}: {}</p>",
                escape_html(&r.frontier),
                escape_html(&r.finding_id),
                r.confidence,
                escape_html(&txt),
            ));
        }
        if b.finding_refs.len() > 6 {
            refs_html.push_str(&format!("<p>… and {} more</p>", b.finding_refs.len() - 6));
        }

        let bridge_preview = render_mutation_preview(
            "Review bridge status",
            &b.id,
            "bridge status write on the local bridge record",
            "updates the selected .vela/bridges record status; it does not edit either source frontier finding",
        );
        let actions_html = match b.status {
            BridgeStatus::Derived => format!(
                r#"{preview}<div class="wb-actions">
  <form method="post" action="/bridges/{id}/confirm"><button type="submit">Confirm</button></form>
  <form method="post" action="/bridges/{id}/refute"><button type="submit">Refute</button></form>
</div>"#,
                preview = bridge_preview,
                id = escape_html(&b.id),
            ),
            BridgeStatus::Confirmed => format!(
                r#"{preview}<div class="wb-actions">
  <form method="post" action="/bridges/{id}/refute"><button type="submit">Mark refuted</button></form>
</div>"#,
                preview = bridge_preview,
                id = escape_html(&b.id),
            ),
            BridgeStatus::Refuted => format!(
                r#"{preview}<div class="wb-actions">
  <form method="post" action="/bridges/{id}/confirm"><button type="submit">Re-confirm</button></form>
</div>"#,
                preview = bridge_preview,
                id = escape_html(&b.id),
            ),
        };

        let tension_html = b.tension.as_deref().map_or(String::new(), |t| {
            format!(
                r#"<p style="color:#872c2c;font-style:italic;">tension: {}</p>"#,
                escape_html(t)
            )
        });

        cards.push_str(&format!(
            r#"<div class="wb-card">
  <h3><span class="wb-chip wb-chip--{chip}">{chip_label}</span><code>{id}</code> · {entity}</h3>
  <p><strong>frontiers:</strong> {frontiers} · <strong>findings:</strong> {n_refs}</p>
  {tension_html}
  {refs_html}
  {actions_html}
</div>"#,
            chip = chip,
            chip_label = chip_label,
            id = escape_html(&b.id),
            entity = escape_html(&b.entity_name),
            frontiers = escape_html(&b.frontiers.join(" ↔ ")),
            n_refs = b.finding_refs.len(),
        ));
    }

    let body = cards;

    Html(shell(
        "bridges",
        "Bridges",
        "Workbench",
        &format!("{} cross-frontier bridge(s)", bridges.len()),
        &body,
    ))
    .into_response()
}

// ── v0.54: NegativeResults page ──────────────────────────────────────

async fn page_negative_results(State(state): State<AppState>) -> Response {
    let project = match repo::load_from_path(&state.repo_path) {
        Ok(p) => p,
        Err(e) => return error_page("nulls", "Could not load frontier", &e),
    };

    if project.negative_results.is_empty() {
        let body = r#"<div class="wb-card">
  <p>No NegativeResults deposited yet. Add one with:</p>
  <p><code>vela negative-result-add &lt;frontier&gt; --kind exploratory \
    --reagent &lt;...&gt; --observation &lt;...&gt; --attempts &lt;n&gt; \
    --deposited-by &lt;actor&gt; --reason &lt;...&gt; \
    --conditions-text &lt;...&gt; --source-title &lt;...&gt;</code></p>
  <p>Or for a registered-trial null:</p>
  <p><code>vela negative-result-add &lt;frontier&gt; --kind registered_trial \
    --endpoint &lt;...&gt; --intervention &lt;...&gt; --comparator &lt;...&gt; \
    --population &lt;...&gt; --n-enrolled &lt;n&gt; --power &lt;p&gt; \
    --ci-lower &lt;l&gt; --ci-upper &lt;u&gt; ...</code></p>
</div>"#;
        return Html(shell(
            "nulls",
            "Negative Results",
            "Workbench",
            "No NegativeResults",
            body,
        ))
        .into_response();
    }

    let mut trial_count = 0usize;
    let mut exploratory_count = 0usize;
    let mut informative_count = 0usize;
    for nr in &project.negative_results {
        match &nr.kind {
            vela_protocol::bundle::NegativeResultKind::RegisteredTrial { .. } => trial_count += 1,
            vela_protocol::bundle::NegativeResultKind::Exploratory { .. } => exploratory_count += 1,
        }
        if nr.is_informative_trial_null() == Some(true) {
            informative_count += 1;
        }
    }

    let stats_html = format!(
        r#"<div class="wb-stats">
  <div><div class="wb-stat__num">{total}</div><div class="wb-stat__label">total</div></div>
  <div><div class="wb-stat__num">{trial}</div><div class="wb-stat__label">trial</div></div>
  <div><div class="wb-stat__num">{expl}</div><div class="wb-stat__label">exploratory</div></div>
  <div><div class="wb-stat__num">{inf}</div><div class="wb-stat__label">informative</div></div>
</div>"#,
        total = project.negative_results.len(),
        trial = trial_count,
        expl = exploratory_count,
        inf = informative_count,
    );

    let mut cards = String::new();
    for nr in &project.negative_results {
        let (chip_kind, chip_label, kind_body) = match &nr.kind {
            vela_protocol::bundle::NegativeResultKind::RegisteredTrial {
                endpoint,
                intervention,
                comparator,
                population,
                n_enrolled,
                power,
                effect_size_ci,
                effect_size_threshold,
                registry_id,
            } => {
                let informative = nr.is_informative_trial_null();
                let inf_chip = match informative {
                    Some(true) => r#"<span class="wb-chip wb-chip--ok">informative</span>"#,
                    Some(false) => r#"<span class="wb-chip wb-chip--warn">uninformative</span>"#,
                    None => "",
                };
                let mcid = effect_size_threshold
                    .map(|t| format!("MCID ±{t:.3}"))
                    .unwrap_or_else(|| "no MCID declared".to_string());
                let registry = registry_id
                    .as_deref()
                    .map(|r| format!(" · <code>{}</code>", escape_html(r)))
                    .unwrap_or_default();
                (
                    "warn",
                    "registered_trial",
                    format!(
                        "<p>{inf_chip}<strong>{ep}</strong>{reg}</p>\
                         <p>{int} vs {cmp} · {pop}</p>\
                         <p>n={n} · power {pw:.2} · CI [{lo:.3}, {hi:.3}] · {mcid}</p>",
                        ep = escape_html(endpoint),
                        reg = registry,
                        int = escape_html(intervention),
                        cmp = escape_html(comparator),
                        pop = escape_html(population),
                        n = n_enrolled,
                        pw = power,
                        lo = effect_size_ci.0,
                        hi = effect_size_ci.1,
                    ),
                )
            }
            vela_protocol::bundle::NegativeResultKind::Exploratory {
                reagent,
                observation,
                attempts,
            } => (
                "warn",
                "exploratory",
                format!(
                    "<p><strong>reagent:</strong> {r}</p>\
                     <p><strong>observation:</strong> {o}</p>\
                     <p><strong>attempts:</strong> {a}</p>",
                    r = escape_html(reagent),
                    o = escape_html(observation),
                    a = attempts,
                ),
            ),
        };

        let retracted_chip = if nr.retracted {
            r#"<span class="wb-chip wb-chip--lost">retracted</span>"#
        } else {
            ""
        };
        let review_chip = nr
            .review_state
            .as_ref()
            .map(|s| {
                let (c, label) = match s {
                    vela_protocol::bundle::ReviewState::Accepted => ("ok", "accepted"),
                    vela_protocol::bundle::ReviewState::Contested => ("warn", "contested"),
                    vela_protocol::bundle::ReviewState::NeedsRevision => ("warn", "needs revision"),
                    vela_protocol::bundle::ReviewState::Rejected => ("lost", "rejected"),
                };
                format!(r#"<span class="wb-chip wb-chip--{c}">{label}</span>"#)
            })
            .unwrap_or_default();
        let tier_chip = if !matches!(nr.access_tier, vela_protocol::access_tier::AccessTier::Public) {
            format!(
                r#"<span class="wb-chip wb-chip--lost">{}</span>"#,
                nr.access_tier.canonical()
            )
        } else {
            String::new()
        };

        let targets_html = if nr.target_findings.is_empty() {
            String::new()
        } else {
            let links: Vec<String> = nr
                .target_findings
                .iter()
                .map(|t| {
                    format!(
                        r#"<a href="/findings/{t}"><code>{t}</code></a>"#,
                        t = escape_html(t)
                    )
                })
                .collect();
            format!(
                "<p><strong>bears against:</strong> {}</p>",
                links.join(" · ")
            )
        };

        let notes_html = if nr.notes.trim().is_empty() {
            String::new()
        } else {
            format!(
                "<p style=\"color:var(--ink-2,#6b665d);font-style:italic;\">{}</p>",
                escape_html(&nr.notes)
            )
        };

        cards.push_str(&format!(
            r#"<div class="wb-card">
  <h3><span class="wb-chip wb-chip--{chip_kind}">{chip_label}</span>{retracted_chip}{review_chip}{tier_chip}<code>{id}</code></h3>
  {kind_body}
  {targets_html}
  {notes_html}
  <p style="font-size:0.78rem;color:var(--ink-3,#a09a8d);">deposited by {actor} · {created}</p>
</div>"#,
            id = escape_html(&nr.id),
            actor = escape_html(&nr.deposited_by),
            created = escape_html(&nr.created),
        ));
    }

    let body = format!("{stats_html}{cards}");
    Html(shell(
        "nulls",
        "Negative Results",
        "Workbench",
        &format!("{} negative result(s)", project.negative_results.len()),
        &body,
    ))
    .into_response()
}

// ── v0.54: Trajectories page ─────────────────────────────────────────

async fn page_trajectories(State(state): State<AppState>) -> Response {
    let project = match repo::load_from_path(&state.repo_path) {
        Ok(p) => p,
        Err(e) => return error_page("trajectories", "Could not load frontier", &e),
    };

    if project.trajectories.is_empty() {
        let body = r#"<div class="wb-card">
  <p>No trajectories deposited yet. Open one with:</p>
  <p><code>vela trajectory-create &lt;frontier&gt; --deposited-by &lt;actor&gt; \
    --reason &lt;...&gt; [--target vf_…]* [--notes &lt;...&gt;]</code></p>
  <p>Then append steps:</p>
  <p><code>vela trajectory-step &lt;frontier&gt; &lt;vtr_id&gt; \
    --kind hypothesis|tried|ruled_out|observed|refined \
    --description &lt;...&gt; --actor &lt;id&gt; --reason &lt;...&gt;</code></p>
</div>"#;
        return Html(shell(
            "trajectories",
            "Trajectories",
            "Workbench",
            "No trajectories",
            body,
        ))
        .into_response();
    }

    let total_steps: usize = project.trajectories.iter().map(|t| t.steps.len()).sum();
    let stats_html = format!(
        r#"<div class="wb-stats">
  <div><div class="wb-stat__num">{}</div><div class="wb-stat__label">trajectories</div></div>
  <div><div class="wb-stat__num">{}</div><div class="wb-stat__label">total steps</div></div>
  <div><div class="wb-stat__num">{}</div><div class="wb-stat__label">retracted</div></div>
  <div><div class="wb-stat__num">{}</div><div class="wb-stat__label">reviewed</div></div>
</div>"#,
        project.trajectories.len(),
        total_steps,
        project.trajectories.iter().filter(|t| t.retracted).count(),
        project
            .trajectories
            .iter()
            .filter(|t| t.review_state.is_some())
            .count(),
    );

    let mut cards = String::new();
    for t in &project.trajectories {
        let retracted_chip = if t.retracted {
            r#"<span class="wb-chip wb-chip--lost">retracted</span>"#
        } else {
            ""
        };
        let review_chip = t
            .review_state
            .as_ref()
            .map(|s| {
                let (c, label) = match s {
                    vela_protocol::bundle::ReviewState::Accepted => ("ok", "accepted"),
                    vela_protocol::bundle::ReviewState::Contested => ("warn", "contested"),
                    vela_protocol::bundle::ReviewState::NeedsRevision => ("warn", "needs revision"),
                    vela_protocol::bundle::ReviewState::Rejected => ("lost", "rejected"),
                };
                format!(r#"<span class="wb-chip wb-chip--{c}">{label}</span>"#)
            })
            .unwrap_or_default();
        let tier_chip = if !matches!(t.access_tier, vela_protocol::access_tier::AccessTier::Public) {
            format!(
                r#"<span class="wb-chip wb-chip--lost">{}</span>"#,
                t.access_tier.canonical()
            )
        } else {
            String::new()
        };

        let targets_html = if t.target_findings.is_empty() {
            String::new()
        } else {
            let links: Vec<String> = t
                .target_findings
                .iter()
                .map(|f| {
                    format!(
                        r#"<a href="/findings/{f}"><code>{f}</code></a>"#,
                        f = escape_html(f)
                    )
                })
                .collect();
            format!("<p><strong>targets:</strong> {}</p>", links.join(" · "))
        };

        let mut steps_html = String::new();
        for (i, step) in t.steps.iter().enumerate() {
            // v0.194: chip color follows the kind's semantic
            // bucket. "lost" for excluding decisions, "warn" for
            // open/in-flight steps, "ok" for confirmations.
            let (chip_kind, kind_label) = match step.kind {
                // v0.50 legacy
                vela_protocol::bundle::TrajectoryStepKind::Hypothesis => ("warn", "hypothesis"),
                vela_protocol::bundle::TrajectoryStepKind::Tried => ("warn", "tried"),
                vela_protocol::bundle::TrajectoryStepKind::RuledOut => ("lost", "ruled out"),
                vela_protocol::bundle::TrajectoryStepKind::Observed => ("ok", "observed"),
                vela_protocol::bundle::TrajectoryStepKind::Refined => ("ok", "refined"),
                // v0.194 vision-taxonomy
                vela_protocol::bundle::TrajectoryStepKind::Question => ("warn", "question"),
                vela_protocol::bundle::TrajectoryStepKind::Context => ("ok", "context"),
                vela_protocol::bundle::TrajectoryStepKind::Data => ("ok", "data"),
                vela_protocol::bundle::TrajectoryStepKind::Tool => ("ok", "tool"),
                vela_protocol::bundle::TrajectoryStepKind::Model => ("ok", "model"),
                vela_protocol::bundle::TrajectoryStepKind::Expert => ("ok", "expert"),
                vela_protocol::bundle::TrajectoryStepKind::Decision => ("ok", "decision"),
                vela_protocol::bundle::TrajectoryStepKind::Protocol => ("ok", "protocol"),
                vela_protocol::bundle::TrajectoryStepKind::Output => ("ok", "output"),
                vela_protocol::bundle::TrajectoryStepKind::Review => ("ok", "review"),
                vela_protocol::bundle::TrajectoryStepKind::Risk => ("lost", "risk"),
                vela_protocol::bundle::TrajectoryStepKind::Outcome => ("ok", "outcome"),
            };
            steps_html.push_str(&format!(
                r#"<div style="border-left:2px solid var(--rule-2,#d8d4cc);padding:0.4rem 0.7rem;margin:0.3rem 0;">
  <p style="margin:0 0 0.2rem 0;"><span class="wb-chip wb-chip--{chip_kind}">{i:02} · {kind_label}</span></p>
  <p style="margin:0 0 0.2rem 0;">{desc}</p>
  <p style="font-size:0.74rem;color:var(--ink-3,#a09a8d);margin:0;">{actor} · {at}</p>
</div>"#,
                i = i + 1,
                desc = escape_html(&step.description),
                actor = escape_html(&step.actor),
                at = escape_html(&step.at),
            ));
        }
        if t.steps.is_empty() {
            steps_html.push_str(
                r#"<p style="color:var(--ink-3,#a09a8d);font-style:italic;">No steps yet.</p>"#,
            );
        }

        let notes_html = if t.notes.trim().is_empty() {
            String::new()
        } else {
            format!(
                "<p style=\"color:var(--ink-2,#6b665d);font-style:italic;\">{}</p>",
                escape_html(&t.notes)
            )
        };

        cards.push_str(&format!(
            r#"<div class="wb-card">
  <h3>{retracted_chip}{review_chip}{tier_chip}<code>{id}</code> · {n_steps} step(s)</h3>
  {targets_html}
  {notes_html}
  {steps_html}
  <p style="font-size:0.78rem;color:var(--ink-3,#a09a8d);">opened by {actor} · {created}</p>
</div>"#,
            id = escape_html(&t.id),
            n_steps = t.steps.len(),
            actor = escape_html(&t.deposited_by),
            created = escape_html(&t.created),
        ));
    }

    let body = format!("{stats_html}{cards}");
    Html(shell(
        "trajectories",
        "Trajectories",
        "Workbench",
        &format!("{} trajector(y/ies)", project.trajectories.len()),
        &body,
    ))
    .into_response()
}

// ── v0.54: Tiers page ────────────────────────────────────────────────

async fn page_tiers(State(state): State<AppState>) -> Response {
    let project = match repo::load_from_path(&state.repo_path) {
        Ok(p) => p,
        Err(e) => return error_page("tiers", "Could not load frontier", &e),
    };

    let count_findings = |tier: vela_protocol::access_tier::AccessTier| {
        project
            .findings
            .iter()
            .filter(|f| f.access_tier == tier)
            .count()
    };
    let count_nrs = |tier: vela_protocol::access_tier::AccessTier| {
        project
            .negative_results
            .iter()
            .filter(|n| n.access_tier == tier)
            .count()
    };
    let count_trajs = |tier: vela_protocol::access_tier::AccessTier| {
        project
            .trajectories
            .iter()
            .filter(|t| t.access_tier == tier)
            .count()
    };
    let public_total = count_findings(vela_protocol::access_tier::AccessTier::Public)
        + count_nrs(vela_protocol::access_tier::AccessTier::Public)
        + count_trajs(vela_protocol::access_tier::AccessTier::Public);
    let restricted_total = count_findings(vela_protocol::access_tier::AccessTier::Restricted)
        + count_nrs(vela_protocol::access_tier::AccessTier::Restricted)
        + count_trajs(vela_protocol::access_tier::AccessTier::Restricted);
    let classified_total = count_findings(vela_protocol::access_tier::AccessTier::Classified)
        + count_nrs(vela_protocol::access_tier::AccessTier::Classified)
        + count_trajs(vela_protocol::access_tier::AccessTier::Classified);

    let stats_html = format!(
        r#"<div class="wb-stats">
  <div><div class="wb-stat__num">{public_total}</div><div class="wb-stat__label">public</div></div>
  <div><div class="wb-stat__num">{restricted_total}</div><div class="wb-stat__label">restricted</div></div>
  <div><div class="wb-stat__num">{classified_total}</div><div class="wb-stat__label">classified</div></div>
  <div><div class="wb-stat__num">{cleared}</div><div class="wb-stat__label">cleared actors</div></div>
</div>"#,
        cleared = project
            .actors
            .iter()
            .filter(|a| a.access_clearance.is_some())
            .count(),
    );

    let mut tier_events: Vec<&vela_protocol::events::StateEvent> = project
        .events
        .iter()
        .filter(|e| e.kind == "tier.set")
        .collect();
    tier_events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

    let events_html = if tier_events.is_empty() {
        r#"<div class="wb-card"><p>No <code>tier.set</code> events yet. Reclassify with:</p>
<p><code>vela tier-set &lt;frontier&gt; --object-type finding|negative_result|trajectory \
  --object-id &lt;id&gt; --tier public|restricted|classified \
  --actor &lt;id&gt; --reason &lt;...&gt;</code></p></div>"#
            .to_string()
    } else {
        let mut rows = String::new();
        for e in &tier_events {
            let prev_tier = e
                .payload
                .get("previous_tier")
                .and_then(|v| v.as_str())
                .unwrap_or("public");
            let new_tier = e
                .payload
                .get("new_tier")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let chip_kind = match new_tier {
                "public" => "ok",
                "restricted" => "warn",
                "classified" => "lost",
                _ => "warn",
            };
            rows.push_str(&format!(
                r#"<tr>
  <td><code>{ts}</code></td>
  <td><span class="wb-chip wb-chip--ok">{prev}</span> → <span class="wb-chip wb-chip--{chip_kind}">{new}</span></td>
  <td><code>{ot}</code> <code>{oi}</code></td>
  <td>{actor}</td>
  <td>{reason}</td>
</tr>"#,
                ts = escape_html(&e.timestamp),
                prev = escape_html(prev_tier),
                new = escape_html(new_tier),
                ot = escape_html(&e.target.r#type),
                oi = escape_html(&e.target.id),
                actor = escape_html(&e.actor.id),
                reason = escape_html(&e.reason),
            ));
        }
        format!(
            r#"<table class="wb-table">
  <thead><tr><th>at</th><th>change</th><th>object</th><th>actor</th><th>reason</th></tr></thead>
  <tbody>{rows}</tbody>
</table>"#
        )
    };

    let breakdown_html = format!(
        r#"<div class="wb-card">
  <h3>Per-collection breakdown</h3>
  <table class="wb-table">
    <thead><tr><th>collection</th><th>public</th><th>restricted</th><th>classified</th></tr></thead>
    <tbody>
      <tr><td>findings</td><td>{fp}</td><td>{fr}</td><td>{fc}</td></tr>
      <tr><td>negative_results</td><td>{np}</td><td>{nr}</td><td>{nc}</td></tr>
      <tr><td>trajectories</td><td>{tp}</td><td>{tr}</td><td>{tc}</td></tr>
    </tbody>
  </table>
</div>"#,
        fp = count_findings(vela_protocol::access_tier::AccessTier::Public),
        fr = count_findings(vela_protocol::access_tier::AccessTier::Restricted),
        fc = count_findings(vela_protocol::access_tier::AccessTier::Classified),
        np = count_nrs(vela_protocol::access_tier::AccessTier::Public),
        nr = count_nrs(vela_protocol::access_tier::AccessTier::Restricted),
        nc = count_nrs(vela_protocol::access_tier::AccessTier::Classified),
        tp = count_trajs(vela_protocol::access_tier::AccessTier::Public),
        tr = count_trajs(vela_protocol::access_tier::AccessTier::Restricted),
        tc = count_trajs(vela_protocol::access_tier::AccessTier::Classified),
    );

    let body = format!("{stats_html}{breakdown_html}{events_html}");
    Html(shell(
        "tiers",
        "Access tiers",
        "Workbench",
        "Dual-use access tiers",
        &body,
    ))
    .into_response()
}

// ── v0.55: Constellation page + cascade-firing API ──────────────────

async fn page_constellation(State(state): State<AppState>) -> Response {
    let project = match repo::load_from_path(&state.repo_path) {
        Ok(p) => p,
        Err(e) => return error_page("constellation", "Could not load frontier", &e),
    };

    let n_findings = project.findings.len();
    let n_links: usize = project.findings.iter().map(|f| f.links.len()).sum();
    let n_cascade = project
        .events
        .iter()
        .filter(|e| e.kind == "finding.dependency_invalidated" || e.kind == "finding.cascade_fired")
        .count();
    let n_retracted = project
        .findings
        .iter()
        .filter(|f| f.flags.retracted)
        .count();

    let stats_html = format!(
        r#"<div class="wb-stats">
  <div><div class="wb-stat__num">{n_findings}</div><div class="wb-stat__label">findings</div></div>
  <div><div class="wb-stat__num">{n_links}</div><div class="wb-stat__label">links</div></div>
  <div><div class="wb-stat__num">{n_cascade}</div><div class="wb-stat__label">cascade events</div></div>
  <div><div class="wb-stat__num">{n_retracted}</div><div class="wb-stat__label">retracted</div></div>
</div>"#
    );

    let svg_html = render_constellation_svg(&project);

    let panel_html = r#"<aside class="vc-panel" data-vc-panel hidden>
  <header class="vc-panel__head">
    <span class="vc-panel__eyebrow">Selected finding</span>
    <h3 class="vc-panel__title" data-vc-panel-title>n/a</h3>
    <p class="vc-panel__id"><code data-vc-panel-id>n/a</code></p>
  </header>
  <p class="vc-panel__claim" data-vc-panel-claim>Click a node in the constellation to inspect it.</p>
  <dl class="vc-panel__meta">
    <div><dt>confidence</dt><dd data-vc-panel-conf>n/a</dd></div>
    <div><dt>state</dt><dd data-vc-panel-state>n/a</dd></div>
    <div><dt>dependents</dt><dd data-vc-panel-deps-in>n/a</dd></div>
    <div><dt>dependencies</dt><dd data-vc-panel-deps-out>n/a</dd></div>
  </dl>
  <form class="vc-panel__cascade" data-vc-cascade-form>
    <label for="vc-cascade-conf">Fire correction: drop confidence to</label>
    <input id="vc-cascade-conf" type="range" min="0" max="100" value="40" step="1" data-vc-cascade-slider>
    <output data-vc-cascade-readout>0.40</output>
    <button type="submit">Apply correction & cascade</button>
    <p class="vc-panel__note" data-vc-cascade-status></p>
  </form>
  <p class="vc-panel__open"><a href="" data-vc-panel-open>→ open detail page</a></p>
</aside>"#;

    let body = format!(
        r#"{stats_html}
<p class="wb-eyebrow" style="margin-top:0.4rem;">Click a node to focus + open the inspector. Drag the slider, hit
"Apply correction" to drop the finding's confidence. The cascade fires
through <code>supports</code> and <code>depends</code> edges live, and any
flagged dependents pulse gold.</p>
<div class="vc-stage">
  {svg_html}
  {panel_html}
</div>
<style>{vc_css}</style>
<script>{vc_js}</script>"#,
        vc_css = CONSTELLATION_CSS,
        vc_js = CONSTELLATION_JS,
    );

    Html(shell(
        "constellation",
        "Constellation",
        "Workbench",
        "Live constellation",
        &body,
    ))
    .into_response()
}

#[derive(Deserialize)]
struct PropagateForm {
    new_score: f64,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    reviewer: Option<String>,
}

#[derive(serde::Serialize)]
struct PropagateResponse {
    ok: bool,
    finding_id: String,
    new_confidence: f64,
    affected: Vec<String>,
    cascade_events: usize,
    message: String,
}

async fn post_api_propagate_confidence(
    AxumPath(vf_id): AxumPath<String>,
    State(state): State<AppState>,
    Form(body): Form<PropagateForm>,
) -> Response {
    let new_score = body.new_score.clamp(0.0, 1.0);
    let reviewer = body
        .reviewer
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "reviewer:workbench".to_string());
    let reason = body
        .reason
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "Workbench cascade fire".to_string());

    let project_before = match repo::load_from_path(&state.repo_path) {
        Ok(p) => p,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(PropagateResponse {
                    ok: false,
                    finding_id: vf_id.clone(),
                    new_confidence: new_score,
                    affected: Vec::new(),
                    cascade_events: 0,
                    message: format!("load failed: {e}"),
                }),
            )
                .into_response();
        }
    };
    let cascade_before = project_before
        .events
        .iter()
        .filter(|e| e.kind == "finding.dependency_invalidated")
        .count();

    let opts = ReviseOptions {
        confidence: new_score,
        reason,
        reviewer,
    };
    let result = state::revise_confidence(&state.repo_path, &vf_id, opts, true);
    let report = match result {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(PropagateResponse {
                    ok: false,
                    finding_id: vf_id.clone(),
                    new_confidence: new_score,
                    affected: Vec::new(),
                    cascade_events: 0,
                    message: format!("revise failed: {e}"),
                }),
            )
                .into_response();
        }
    };

    let project_after = match repo::load_from_path(&state.repo_path) {
        Ok(p) => p,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(PropagateResponse {
                    ok: false,
                    finding_id: vf_id.clone(),
                    new_confidence: new_score,
                    affected: Vec::new(),
                    cascade_events: 0,
                    message: format!("post-load failed: {e}"),
                }),
            )
                .into_response();
        }
    };
    let cascade_events: Vec<&vela_protocol::events::StateEvent> = project_after
        .events
        .iter()
        .filter(|e| e.kind == "finding.dependency_invalidated")
        .collect();
    let new_cascade = cascade_events.len().saturating_sub(cascade_before);
    let mut affected: Vec<String> = cascade_events
        .iter()
        .rev()
        .take(new_cascade)
        .filter_map(|e| {
            e.payload
                .get("affected_finding")
                .and_then(|v| v.as_str())
                .map(String::from)
                .or_else(|| Some(e.target.id.clone()))
        })
        .collect();
    affected.sort();
    affected.dedup();

    (
        StatusCode::OK,
        Json(PropagateResponse {
            ok: true,
            finding_id: if report.finding_id.is_empty() {
                vf_id
            } else {
                report.finding_id
            },
            new_confidence: new_score,
            affected,
            cascade_events: new_cascade,
            message: report.message,
        }),
    )
        .into_response()
}

fn finding_state_classes(
    b: &FindingBundle,
    replications: &[Replication],
) -> (&'static str, &'static str) {
    use vela_protocol::bundle::ReviewState;
    if b.flags.retracted {
        return ("retracted", "lost");
    }
    if b.flags.gap || b.flags.negative_space {
        return ("gap", "stale");
    }
    if let Some(state) = &b.flags.review_state {
        match state {
            ReviewState::Contested => return ("contested", "warn"),
            ReviewState::NeedsRevision => return ("contested", "warn"),
            ReviewState::Rejected => return ("retracted", "lost"),
            ReviewState::Accepted => {
                if is_replicated_for_constellation(b, replications) {
                    return ("replicated", "ok");
                }
                return ("supported", "ok");
            }
        }
    }
    if b.flags.contested {
        return ("contested", "warn");
    }
    if is_replicated_for_constellation(b, replications) {
        return ("replicated", "ok");
    }
    ("supported", "ok")
}

fn is_replicated_for_constellation(b: &FindingBundle, replications: &[Replication]) -> bool {
    let mut has_record = false;
    let mut has_success = false;
    for r in replications {
        if r.target_finding == b.id {
            has_record = true;
            if r.outcome == "replicated" {
                has_success = true;
            }
        }
    }
    if has_record {
        has_success
    } else {
        b.evidence.replicated
    }
}

fn render_constellation_svg(p: &Project) -> String {
    if p.findings.is_empty() {
        return String::from(
            r#"<p class="vc-empty">No findings yet. Deposit one with <code>vela finding add</code>.</p>"#,
        );
    }
    let n = p.findings.len();
    let view_w: i32 = 720;
    let view_h: i32 = 380;
    let cx = view_w as f64 / 2.0;
    let cy = view_h as f64 / 2.0;
    let ring_r = (cx.min(cy) - 60.0).max(80.0);

    let pos: std::collections::HashMap<&str, (f64, f64)> = p
        .findings
        .iter()
        .enumerate()
        .map(|(i, b)| {
            let angle = (i as f64 / n as f64) * std::f64::consts::TAU - std::f64::consts::FRAC_PI_2;
            let x = cx + ring_r * angle.cos();
            let y = cy + ring_r * angle.sin();
            (b.id.as_str(), (x, y))
        })
        .collect();

    let mut deps_out: std::collections::HashMap<&str, u32> = std::collections::HashMap::new();
    let mut deps_in: std::collections::HashMap<&str, u32> = std::collections::HashMap::new();
    for b in &p.findings {
        let from = b.id.as_str();
        for link in &b.links {
            *deps_out.entry(from).or_default() += 1;
            if pos.contains_key(link.target.as_str()) {
                *deps_in.entry(link.target.as_str()).or_default() += 1;
            }
        }
    }

    let mut edges = String::new();
    for b in &p.findings {
        let Some(&(x1, y1)) = pos.get(b.id.as_str()) else {
            continue;
        };
        let from = escape_html(&b.id);
        for link in &b.links {
            if let Some(&(x2, y2)) = pos.get(link.target.as_str()) {
                let mx = (x1 + x2) / 2.0;
                let my = (y1 + y2) / 2.0;
                let pull = 0.45;
                let qx = cx + (mx - cx) * pull;
                let qy = cy + (my - cy) * pull;
                let to = escape_html(&link.target);
                let lt = escape_html(&link.link_type);
                edges.push_str(&format!(
                    r##"<path class="vc-edge" data-from="{from}" data-to="{to}" data-link-type="{lt}" d="M {x1:.1} {y1:.1} Q {qx:.1} {qy:.1} {x2:.1} {y2:.1}"/>"##
                ));
            } else {
                let dx = x1 - cx;
                let dy = y1 - cy;
                let mag = (dx * dx + dy * dy).sqrt().max(1e-6);
                let conf = b.confidence.score.clamp(0.0, 1.0);
                let outward = 18.0 + conf * 22.0;
                let xt = x1 + (dx / mag) * outward;
                let yt = y1 + (dy / mag) * outward;
                edges.push_str(&format!(
                    r##"<path class="vc-edge vc-edge--cross" data-from="{from}" data-to="cross" d="M {x1:.1} {y1:.1} L {xt:.1} {yt:.1}"/>"##
                ));
            }
        }
    }

    let mut nodes = String::new();
    for b in &p.findings {
        let (x, y) = pos[b.id.as_str()];
        let (label, state_class) = finding_state_classes(b, &p.replications);
        let r = 4.0 + b.confidence.score.clamp(0.0, 1.0) * 5.0;
        let live_class = if label == "replicated" {
            " vc-node--live"
        } else {
            ""
        };
        let vf = escape_html(&b.id);
        let claim = escape_html(&b.assertion.text);
        let n_out = deps_out.get(b.id.as_str()).copied().unwrap_or(0);
        let n_in = deps_in.get(b.id.as_str()).copied().unwrap_or(0);
        let conf = b.confidence.score;
        let href = format!("/findings/{}", escape_html(&b.id));
        nodes.push_str(&format!(
            r#"<a class="vc-node{live_class}" href="{href}" data-vf="{vf}" data-state="{label}" data-claim="{claim}" data-conf="{conf:.3}" data-deps-out="{n_out}" data-deps-in="{n_in}">
              <circle class="vc-glow" cx="{x:.1}" cy="{y:.1}" r="{rg:.1}"/>
              <circle class="vc-dot" cx="{x:.1}" cy="{y:.1}" r="{r:.1}" style="fill:var(--state-{state_class});"/>
            </a>"#,
            rg = r * 2.6,
        ));
    }

    format!(
        r#"<figure class="vc-figure" data-vc-figure>
          <svg class="vc" viewBox="0 0 {w} {h}" preserveAspectRatio="xMidYMid meet" role="img" aria-label="Finding constellation: {n} findings as a star chart">
            <circle class="vc-ring" cx="{cx}" cy="{cy}" r="{rr}"/>
            <circle class="vc-center" cx="{cx}" cy="{cy}" r="2.5"/>
            <g class="vc-edges">{edges}</g>
            <g class="vc-nodes">{nodes}</g>
          </svg>
          <p class="vc-tooltip" data-vc-tooltip aria-hidden="true"></p>
          <p class="vc-legend">
            <span><span class="vc-legend__dot" style="background:#3b7a48;"></span>replicated · supported</span>
            <span class="vc-sep">·</span>
            <span><span class="vc-legend__dot" style="background:#a07a1f;"></span>contested</span>
            <span class="vc-sep">·</span>
            <span><span class="vc-legend__dot" style="background:#7d7d7d;"></span>gap · inferred</span>
            <span class="vc-sep">·</span>
            <span><span class="vc-legend__dot" style="background:#9b3232;"></span>retracted</span>
            <span class="vc-sep">·</span>
            <span><span class="vc-legend__dot" style="background:#3a6a8a;"></span>cross-frontier</span>
            <span class="vc-sep">·</span>
            <span>radius = confidence · click to focus · esc to clear</span>
          </p>
        </figure>"#,
        w = view_w,
        h = view_h,
        rr = ring_r,
    )
}

const CONSTELLATION_CSS: &str = r#"
:root {
  --vc-gold: #c79a3a;
  --vc-gold-glow: rgba(199, 154, 58, 0.55);
  --vc-winter: #3a6a8a;
  --state-ok: #3b7a48;
  --state-warn: #a07a1f;
  --state-stale: #7d7d7d;
  --state-lost: #9b3232;
}
.vc-stage { display: grid; grid-template-columns: minmax(0, 1fr) 320px; gap: 1.25rem; align-items: start; }
@media (max-width: 980px) { .vc-stage { grid-template-columns: 1fr; } }
.vc-figure {
  margin: 0;
  background: #1c1d22;
  border: 1px solid var(--rule-2, #d8d4cc);
  border-radius: 4px;
  overflow: hidden;
  position: relative;
}
.vc { display: block; width: 100%; height: auto; max-height: 460px;
  background: radial-gradient(circle at 50% 50%, rgba(199,154,58,0.10) 0%, transparent 38%), #1c1d22; }
.vc-ring { fill: none; stroke: rgba(199,154,58,0.28); stroke-width: 0.6; stroke-dasharray: 1 5; }
.vc-center { fill: var(--vc-gold); filter: drop-shadow(0 0 6px var(--vc-gold-glow)); }
.vc-edges { fill: none; stroke: rgba(199,154,58,0.34); stroke-width: 0.7; pointer-events: none; }
.vc-edge { transition: stroke 200ms ease, stroke-width 200ms ease, opacity 200ms ease; }
.vc-edge--cross { stroke: rgba(58,106,138,0.62); stroke-width: 0.85; stroke-linecap: round; }
.vc-edge--cascade { stroke: var(--vc-gold) !important; stroke-width: 2 !important; opacity: 1 !important;
  filter: drop-shadow(0 0 4px var(--vc-gold-glow));
  stroke-dasharray: 6 4; animation: vc-flow 1.2s linear infinite; }
@keyframes vc-flow { from { stroke-dashoffset: 0; } to { stroke-dashoffset: -20; } }
.vc-node { cursor: pointer; outline: none; transition: opacity 200ms ease; }
.vc-glow { fill: var(--vc-gold); opacity: 0; transition: opacity 200ms ease; pointer-events: none; }
.vc-node:hover .vc-glow, .vc-node:focus .vc-glow { opacity: 0.32; }
.vc-dot { transition: r 200ms ease, stroke 200ms ease, stroke-width 200ms ease;
  stroke: rgba(255,255,255,0.20); stroke-width: 0.5; }
.vc-node:hover .vc-dot, .vc-node:focus .vc-dot { stroke: #fff; stroke-width: 1; }
.vc-node--live .vc-dot { filter: drop-shadow(0 0 4px var(--vc-gold-glow)); }
.vc-node--live .vc-glow { opacity: 0.18; }
.vc--focused .vc-node          { opacity: 0.22; }
.vc--focused .vc-node--focus   { opacity: 1; }
.vc--focused .vc-node--related { opacity: 1; }
.vc--focused .vc-edge          { opacity: 0.16; }
.vc--focused .vc-edge--focus   { opacity: 1; stroke: var(--vc-gold); stroke-width: 1.4; }
.vc--focused .vc-ring          { opacity: 0.4; }
.vc--focused .vc-center        { opacity: 0.5; }
.vc-node--focus .vc-glow       { opacity: 0.42; }
.vc-node--focus .vc-dot        { stroke: #fff; stroke-width: 1.4; }
.vc-node--cascade-hit .vc-dot  { stroke: var(--vc-gold); stroke-width: 2.2;
  filter: drop-shadow(0 0 8px var(--vc-gold-glow)); }
.vc-node--cascade-hit .vc-glow { opacity: 0.55; }
.vc-tooltip { margin: 0; padding: 10px 14px 12px; border-top: 1px solid #303237;
  font-size: 13px; line-height: 1.4; color: #e6e2d6; min-height: 1.4em;
  background: #232428; opacity: 1; transition: opacity 200ms ease; }
.vc-tooltip:empty::before { content: 'Hover a node to read the claim · click to focus.';
  color: #8c8a82; font-style: italic; }
.vc-tooltip__meta { font-family: ui-monospace, Menlo, monospace; font-size: 11px;
  font-weight: 400; letter-spacing: 0.04em; color: #a8a39a; }
.vc-legend { margin: 0; padding: 8px 14px 12px; font-family: ui-monospace, Menlo, monospace;
  font-size: 10px; letter-spacing: 0.14em; text-transform: uppercase; color: #a8a39a;
  display: flex; flex-wrap: wrap; gap: 4px 10px; align-items: center;
  border-top: 1px solid #2c2d31; background: transparent; }
.vc-legend > span { display: inline-flex; align-items: center; gap: 4px; }
.vc-legend__dot { display: inline-block; width: 6px; height: 6px; border-radius: 50%; }
.vc-legend .vc-sep { color: #5c5b56; }
.vc-empty { padding: 1.5rem; color: var(--ink-2, #6b665d); }

.vc-panel { background: var(--bg-2, #f5f2ec); border: 1px solid var(--rule-2, #d8d4cc);
  padding: 1rem 1.1rem; font-size: 0.92rem; }
.vc-panel[hidden] { display: none; }
.vc-panel__head { margin-bottom: 0.6rem; }
.vc-panel__eyebrow { font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.08em;
  color: var(--ink-2, #6b665d); }
.vc-panel__title { margin: 0.2rem 0; font-size: 1rem; }
.vc-panel__id { margin: 0; font-size: 0.78rem; color: var(--ink-2, #6b665d); }
.vc-panel__claim { margin: 0.6rem 0 0.8rem; line-height: 1.5; }
.vc-panel__meta { display: grid; grid-template-columns: 1fr 1fr; gap: 0.3rem 0.8rem;
  margin: 0 0 1rem 0; font-size: 0.84rem; }
.vc-panel__meta div { display: flex; flex-direction: column; }
.vc-panel__meta dt { font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.06em;
  color: var(--ink-2, #6b665d); }
.vc-panel__meta dd { margin: 0.05rem 0 0 0; font-family: ui-monospace, Menlo, monospace;
  font-size: 0.86rem; }
.vc-panel__cascade { display: flex; flex-direction: column; gap: 0.4rem;
  border-top: 1px solid var(--rule-2, #d8d4cc); padding-top: 0.8rem; margin-top: 0.4rem; }
.vc-panel__cascade label { font-size: 0.78rem; color: var(--ink-2, #6b665d); }
.vc-panel__cascade input[type=range] { width: 100%; }
.vc-panel__cascade output { font-family: ui-monospace, Menlo, monospace; font-size: 0.92rem;
  font-weight: 600; }
.vc-panel__cascade button { font-family: inherit; font-size: 0.84rem; padding: 0.4rem 0.7rem;
  border: 1px solid #1a1a1a; background: #1a1a1a; color: #fff; cursor: pointer; border-radius: 2px; }
.vc-panel__cascade button:disabled { opacity: 0.5; cursor: wait; }
.vc-panel__note { margin: 0.4rem 0 0 0; font-size: 0.82rem; color: var(--ink-2, #6b665d);
  min-height: 1.1em; line-height: 1.4; }
.vc-panel__note.is-success { color: #2f5d3a; }
.vc-panel__note.is-error { color: #872c2c; }
.vc-panel__open { margin: 0.8rem 0 0 0; font-size: 0.82rem; }
.vc-panel__open a { color: #1a1a1a; }
"#;

const CONSTELLATION_JS: &str = r#"
(function(){
  var fig = document.querySelector('[data-vc-figure]');
  var panel = document.querySelector('[data-vc-panel]');
  if (!fig || !panel) return;
  var nodes = fig.querySelectorAll('.vc-node');
  var edges = fig.querySelectorAll('.vc-edge');
  var tip = fig.querySelector('[data-vc-tooltip]');
  var focused = null;

  var pTitle  = panel.querySelector('[data-vc-panel-title]');
  var pId     = panel.querySelector('[data-vc-panel-id]');
  var pClaim  = panel.querySelector('[data-vc-panel-claim]');
  var pConf   = panel.querySelector('[data-vc-panel-conf]');
  var pState  = panel.querySelector('[data-vc-panel-state]');
  var pIn     = panel.querySelector('[data-vc-panel-deps-in]');
  var pOut    = panel.querySelector('[data-vc-panel-deps-out]');
  var pOpen   = panel.querySelector('[data-vc-panel-open]');
  var form    = panel.querySelector('[data-vc-cascade-form]');
  var slider  = panel.querySelector('[data-vc-cascade-slider]');
  var readout = panel.querySelector('[data-vc-cascade-readout]');
  var status  = panel.querySelector('[data-vc-cascade-status]');
  var button  = form ? form.querySelector('button') : null;

  function clearTip(){ tip.innerHTML = ''; }
  function showTipFromNode(n){
    var claim = n.getAttribute('data-claim') || '';
    var nOut = parseInt(n.getAttribute('data-deps-out') || '0', 10);
    var nIn  = parseInt(n.getAttribute('data-deps-in')  || '0', 10);
    var meta = nOut + ' dep' + (nOut === 1 ? '' : 's') + ' · ' + nIn + ' dependent' + (nIn === 1 ? '' : 's');
    tip.innerHTML = claim + ' <span class="vc-tooltip__meta">· ' + meta + '</span>';
  }

  function relatedSet(vf){
    var related = {};
    edges.forEach(function(e){
      var from = e.getAttribute('data-from');
      var to   = e.getAttribute('data-to');
      if (from === vf) { related[to] = true; e.classList.add('vc-edge--focus'); }
      else if (to === vf) { related[from] = true; e.classList.add('vc-edge--focus'); }
      else { e.classList.remove('vc-edge--focus'); }
    });
    return related;
  }

  function fillPanel(node){
    var vf = node.getAttribute('data-vf');
    var claim = node.getAttribute('data-claim') || '';
    var conf = parseFloat(node.getAttribute('data-conf') || '0');
    var st = node.getAttribute('data-state') || 'n/a';
    var nOut = parseInt(node.getAttribute('data-deps-out') || '0', 10);
    var nIn  = parseInt(node.getAttribute('data-deps-in')  || '0', 10);
    pTitle.textContent = vf;
    pId.textContent = vf;
    pClaim.textContent = claim;
    pConf.textContent  = conf.toFixed(3);
    pState.textContent = st;
    pIn.textContent  = String(nIn);
    pOut.textContent = String(nOut);
    pOpen.setAttribute('href', '/findings/' + vf);
    panel.removeAttribute('hidden');
    if (status) { status.textContent = ''; status.classList.remove('is-success','is-error'); }
    if (button) { button.disabled = false; }
  }

  function applyFocus(node){
    var vf = node.getAttribute('data-vf');
    focused = vf;
    fig.classList.add('vc--focused');
    var related = relatedSet(vf);
    nodes.forEach(function(n){
      var nv = n.getAttribute('data-vf');
      n.classList.remove('vc-node--focus','vc-node--related','vc-node--cascade-hit');
      if (nv === vf) n.classList.add('vc-node--focus');
      else if (related[nv]) n.classList.add('vc-node--related');
    });
    edges.forEach(function(e){ e.classList.remove('vc-edge--cascade'); });
    showTipFromNode(node);
    fillPanel(node);
  }

  function clearFocus(){
    focused = null;
    fig.classList.remove('vc--focused');
    nodes.forEach(function(n){ n.classList.remove('vc-node--focus','vc-node--related'); });
    edges.forEach(function(e){ e.classList.remove('vc-edge--focus'); });
    clearTip();
  }

  nodes.forEach(function(n){
    n.addEventListener('mouseenter', function(){ if (!focused) showTipFromNode(n); });
    n.addEventListener('mouseleave', function(){ if (!focused) clearTip(); });
    n.addEventListener('click', function(e){
      var vf = n.getAttribute('data-vf');
      if (focused === vf) { return; } // second click → navigate
      e.preventDefault();
      applyFocus(n);
    });
  });

  document.addEventListener('keydown', function(e){
    if (e.key === 'Escape' && focused) { clearFocus(); }
  });

  if (slider && readout) {
    var sync = function(){ readout.textContent = (slider.value/100).toFixed(2); };
    slider.addEventListener('input', sync);
    sync();
  }

  if (form) {
    form.addEventListener('submit', function(e){
      e.preventDefault();
      if (!focused) { return; }
      var newScore = (slider ? slider.value : 40) / 100;
      var fd = new URLSearchParams();
      fd.append('new_score', String(newScore));
      fd.append('reason', 'Workbench cascade fire from constellation');
      fd.append('reviewer', 'reviewer:workbench');
      if (button) button.disabled = true;
      if (status) { status.textContent = 'firing cascade…'; status.classList.remove('is-success','is-error'); }
      fetch('/api/propagate/' + encodeURIComponent(focused), {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: fd.toString()
      }).then(function(r){ return r.json(); }).then(function(j){
        if (button) button.disabled = false;
        if (!j.ok) {
          if (status) { status.textContent = j.message || 'cascade failed'; status.classList.add('is-error'); }
          return;
        }
        var hits = (j.affected || []);
        if (status) {
          status.classList.add('is-success');
          status.textContent = 'cascade fired · confidence ' + j.new_confidence.toFixed(2) +
            ' · ' + j.cascade_events + ' downstream flagged';
        }
        // Animate gold edges from focused → each affected.
        var fromVf = focused;
        edges.forEach(function(e){
          var from = e.getAttribute('data-from');
          var to   = e.getAttribute('data-to');
          if ((from === fromVf && hits.indexOf(to) >= 0) ||
              (to === fromVf && hits.indexOf(from) >= 0)) {
            e.classList.add('vc-edge--cascade');
          }
        });
        // Pulse hit nodes.
        nodes.forEach(function(n){
          if (hits.indexOf(n.getAttribute('data-vf')) >= 0) {
            n.classList.add('vc-node--cascade-hit');
          }
        });
        // Update local conf readout for source.
        if (pConf) pConf.textContent = j.new_confidence.toFixed(3);
      }).catch(function(err){
        if (button) button.disabled = false;
        if (status) { status.textContent = String(err); status.classList.add('is-error'); }
      });
    });
  }
})();
"#;

// ── v0.55 Phase D: Time-travel replay page ───────────────────────────

async fn page_replay(AxumPath(vf_id): AxumPath<String>, State(state): State<AppState>) -> Response {
    let payload = match state::history_as_of(&state.repo_path, &vf_id, None) {
        Ok(v) => v,
        Err(e) => return error_page("replay", "history failed", &e),
    };
    let project = match repo::load_from_path(&state.repo_path) {
        Ok(p) => p,
        Err(e) => return error_page("replay", "load failed", &e),
    };

    let assertion = payload
        .pointer("/finding/assertion")
        .and_then(|v| v.as_str())
        .unwrap_or("(no assertion)")
        .to_string();
    let current_conf = payload
        .pointer("/finding/confidence")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);

    // Build a (timestamp, score, kind, reason) tuple list from events,
    // sorted by timestamp ascending. Genesis is the earliest event with
    // payload.previous_score, used as the starting point if available.
    #[derive(Clone)]
    struct ReplayPoint {
        ts: String,
        kind: String,
        previous: Option<f64>,
        new: Option<f64>,
        reason: String,
    }
    let empty = Vec::new();
    let events = payload
        .pointer("/events")
        .and_then(|v| v.as_array())
        .unwrap_or(&empty);
    let mut points: Vec<ReplayPoint> = events
        .iter()
        .map(|e| ReplayPoint {
            ts: e
                .get("timestamp")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            kind: e
                .get("kind")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            previous: e
                .pointer("/payload/previous_score")
                .and_then(|v| v.as_f64()),
            new: e
                .pointer("/payload/new_score")
                .and_then(|v| v.as_f64())
                .or_else(|| e.pointer("/payload/confidence").and_then(|v| v.as_f64())),
            reason: e
                .get("reason")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
        })
        .collect();
    points.sort_by(|a, b| a.ts.cmp(&b.ts));

    // Sparkline: x = position in event sequence, y = score (or carry-forward).
    let mut series: Vec<(String, f64, String)> = Vec::new();
    let mut last = if let Some(p) = points.first() {
        p.previous.unwrap_or(current_conf)
    } else {
        current_conf
    };
    for p in &points {
        let score = p.new.unwrap_or_else(|| p.previous.unwrap_or(last));
        series.push((p.ts.clone(), score, p.kind.clone()));
        last = score;
    }
    if series.is_empty() {
        series.push((String::new(), current_conf, "current".to_string()));
    }

    // Render sparkline SVG.
    let view_w = 720i32;
    let view_h = 140i32;
    let pad_l = 40.0;
    let pad_r = 20.0;
    let pad_t = 16.0;
    let pad_b = 28.0;
    let plot_w = view_w as f64 - pad_l - pad_r;
    let plot_h = view_h as f64 - pad_t - pad_b;
    let n = series.len() as f64;
    let mut path = String::new();
    let mut points_svg = String::new();
    for (i, (_, score, kind)) in series.iter().enumerate() {
        let x = pad_l + (i as f64 / (n - 1.0).max(1.0)) * plot_w;
        let y = pad_t + (1.0 - score.clamp(0.0, 1.0)) * plot_h;
        if i == 0 {
            path.push_str(&format!("M {x:.1} {y:.1}"));
        } else {
            path.push_str(&format!(" L {x:.1} {y:.1}"));
        }
        let dot_class = match kind.as_str() {
            "finding.asserted" => "rp-dot rp-dot--genesis",
            "finding.confidence_revised" => "rp-dot rp-dot--revise",
            "finding.retracted" | "finding.flagged" => "rp-dot rp-dot--retract",
            "finding.dependency_invalidated" => "rp-dot rp-dot--cascade",
            _ => "rp-dot",
        };
        points_svg.push_str(&format!(
            r#"<circle class="{dot_class}" cx="{x:.1}" cy="{y:.1}" r="3.5"><title>{score:.2} · {kind}</title></circle>"#,
        ));
    }
    let threshold_y = pad_t + (1.0 - 0.5) * plot_h;
    let svg = format!(
        r#"<svg class="rp-svg" viewBox="0 0 {view_w} {view_h}" preserveAspectRatio="xMidYMid meet" role="img" aria-label="Confidence trajectory over time">
  <line class="rp-axis" x1="{pad_l}" y1="{ax_y}" x2="{x_end}" y2="{ax_y}"/>
  <line class="rp-axis" x1="{pad_l}" y1="{pad_t}" x2="{pad_l}" y2="{ax_y}"/>
  <line class="rp-threshold" x1="{pad_l}" y1="{threshold_y:.1}" x2="{x_end}" y2="{threshold_y:.1}"><title>0.5 cascade threshold</title></line>
  <text class="rp-label" x="6" y="{pad_t}" dy="0.32em">1.0</text>
  <text class="rp-label" x="6" y="{ax_y}" dy="0.32em">0.0</text>
  <text class="rp-label" x="6" y="{threshold_y:.1}" dy="0.32em">0.5</text>
  <path class="rp-line" d="{path}"/>
  {points_svg}
</svg>"#,
        ax_y = pad_t + plot_h,
        x_end = pad_l + plot_w,
    );

    // Event timeline rows.
    let mut rows = String::new();
    for p in points.iter().rev() {
        let kind_chip = match p.kind.as_str() {
            "finding.asserted" => ("ok", "asserted"),
            "finding.confidence_revised" => ("warn", "revised"),
            "finding.retracted" => ("lost", "retracted"),
            "finding.dependency_invalidated" => ("warn", "cascade"),
            "finding.reviewed" => ("ok", "reviewed"),
            "finding.flagged" => ("warn", "flagged"),
            _ => ("warn", p.kind.as_str()),
        };
        let from = p
            .previous
            .map(|v| format!("{v:.2}"))
            .unwrap_or("n/a".to_string());
        let to = p
            .new
            .map(|v| format!("{v:.2}"))
            .unwrap_or("n/a".to_string());
        rows.push_str(&format!(
            r#"<tr>
  <td><code>{ts}</code></td>
  <td><span class="wb-chip wb-chip--{c}">{label}</span></td>
  <td><code>{from}</code> → <code>{to}</code></td>
  <td>{reason}</td>
</tr>"#,
            ts = escape_html(&p.ts),
            c = kind_chip.0,
            label = escape_html(kind_chip.1),
            reason = escape_html(&p.reason),
        ));
    }
    if rows.is_empty() {
        rows =
            r#"<tr><td colspan="4">No events recorded for this finding yet.</td></tr>"#.to_string();
    }

    let n_revisions = points
        .iter()
        .filter(|p| p.kind == "finding.confidence_revised")
        .count();
    let n_cascades = points
        .iter()
        .filter(|p| p.kind == "finding.dependency_invalidated")
        .count();
    let stats = format!(
        r#"<div class="wb-stats">
  <div><div class="wb-stat__num">{}</div><div class="wb-stat__label">events</div></div>
  <div><div class="wb-stat__num">{n_revisions}</div><div class="wb-stat__label">revisions</div></div>
  <div><div class="wb-stat__num">{n_cascades}</div><div class="wb-stat__label">cascade hits</div></div>
  <div><div class="wb-stat__num">{current_conf:.2}</div><div class="wb-stat__label">current</div></div>
</div>"#,
        points.len(),
    );

    let _ = project; // unused but keeps linker honest if we extend later

    let body = format!(
        r#"{stats}
<p class="wb-eyebrow" style="margin-top:0.4rem;">Confidence trajectory and event timeline for <code>{vf}</code>. The dashed line marks the 0.5 cascade threshold. Drops below it propagate through dependents.</p>
<p style="font-size:0.95rem;line-height:1.5;margin:0.4rem 0 1rem;">{claim}</p>
<div class="rp-figure">{svg}</div>
<p class="rp-legend">
  <span><span class="rp-legend__dot" style="background:#3b7a48;"></span>asserted</span>
  <span><span class="rp-legend__dot" style="background:#a07a1f;"></span>revised</span>
  <span><span class="rp-legend__dot" style="background:#9b3232;"></span>retracted</span>
  <span><span class="rp-legend__dot" style="background:#c79a3a;"></span>cascade hit</span>
</p>
<table class="wb-table">
  <thead><tr><th>at</th><th>kind</th><th>score</th><th>reason</th></tr></thead>
  <tbody>{rows}</tbody>
</table>
<style>{css}</style>
<p style="margin-top:1rem;font-size:0.86rem;"><a href="/findings/{vf}">← back to finding detail</a> · <a href="/constellation">← constellation</a></p>"#,
        vf = escape_html(&vf_id),
        claim = escape_html(&assertion),
        css = REPLAY_CSS,
    );

    Html(shell(
        "constellation",
        "Time-travel replay",
        "Workbench",
        "Time-travel replay",
        &body,
    ))
    .into_response()
}

const REPLAY_CSS: &str = r#"
.rp-figure { background: #1c1d22; border: 1px solid var(--rule-2, #d8d4cc); border-radius: 4px; padding: 0; margin: 1rem 0 0.5rem; overflow: hidden; }
.rp-svg { display: block; width: 100%; height: auto; max-height: 200px;
  background: radial-gradient(circle at 50% 50%, rgba(199,154,58,0.10) 0%, transparent 38%), #1c1d22; }
.rp-axis { stroke: rgba(255,255,255,0.18); stroke-width: 0.7; }
.rp-threshold { stroke: rgba(199,154,58,0.55); stroke-width: 0.6; stroke-dasharray: 3 3; }
.rp-label { font-family: ui-monospace, Menlo, monospace; font-size: 9px; fill: #a8a39a; }
.rp-line { fill: none; stroke: #c79a3a; stroke-width: 1.6; filter: drop-shadow(0 0 4px rgba(199,154,58,0.45)); }
.rp-dot { stroke: #1c1d22; stroke-width: 1; fill: #c79a3a; }
.rp-dot--genesis { fill: #3b7a48; }
.rp-dot--revise { fill: #a07a1f; }
.rp-dot--retract { fill: #9b3232; }
.rp-dot--cascade { fill: #c79a3a; }
.rp-legend { margin: 0.3rem 0 1rem; font-family: ui-monospace, Menlo, monospace; font-size: 10px;
  letter-spacing: 0.14em; text-transform: uppercase; color: var(--ink-2, #6b665d);
  display: flex; flex-wrap: wrap; gap: 4px 12px; }
.rp-legend > span { display: inline-flex; align-items: center; gap: 4px; }
.rp-legend__dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; }
"#;

#[derive(Deserialize)]
struct ProposalDecisionForm {
    #[serde(default)]
    reviewer: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

fn proposal_decision(form: ProposalDecisionForm) -> (String, String) {
    let reviewer = form.reviewer.unwrap_or_default().trim().to_string();
    let reason = form.reason.unwrap_or_default().trim().to_string();
    (reviewer, reason)
}

fn validate_proposal_decision(form: ProposalDecisionForm) -> Result<(String, String), String> {
    let (reviewer, reason) = proposal_decision(form);
    if reviewer.is_empty() || reason.is_empty() {
        return Err("Reviewer identity and decision reason are required.".to_string());
    }
    Ok((reviewer, reason))
}

fn proposal_decision_error_page(message: &str) -> Response {
    let body = format!(
        r#"<div class="wb-card">
  <h3>Reviewer decision rejected</h3>
  <p>{}</p>
  <p>Return to the proposal preview and enter a reviewer identity plus a bounded reason.</p>
</div>"#,
        escape_html(message),
    );
    (
        StatusCode::BAD_REQUEST,
        Html(shell(
            "proposals",
            "Reviewer decision rejected",
            "Proposal",
            "Reviewer decision rejected",
            &body,
        )),
    )
        .into_response()
}

async fn post_proposal_accept(
    AxumPath(vpr_id): AxumPath<String>,
    State(state): State<AppState>,
    Form(form): Form<ProposalDecisionForm>,
) -> Response {
    let (reviewer, reason) = match validate_proposal_decision(form) {
        Ok(decision) => decision,
        Err(e) => return proposal_decision_error_page(&e),
    };
    match proposals::accept_at_path(&state.repo_path, &vpr_id, &reviewer, &reason) {
        Ok(_) => {
            Redirect::to(&format!("/proposals/{}/preview", urlencode_path(&vpr_id))).into_response()
        }
        Err(e) => error_page("proposals", "Could not accept proposal", &e),
    }
}

async fn post_proposal_reject(
    AxumPath(vpr_id): AxumPath<String>,
    State(state): State<AppState>,
    Form(form): Form<ProposalDecisionForm>,
) -> Response {
    let (reviewer, reason) = match validate_proposal_decision(form) {
        Ok(decision) => decision,
        Err(e) => return proposal_decision_error_page(&e),
    };
    match proposals::reject_at_path(&state.repo_path, &vpr_id, &reviewer, &reason) {
        Ok(()) => {
            Redirect::to(&format!("/proposals/{}/preview", urlencode_path(&vpr_id))).into_response()
        }
        Err(e) => error_page("proposals", "Could not reject proposal", &e),
    }
}

async fn post_proposal_revision(
    AxumPath(vpr_id): AxumPath<String>,
    State(state): State<AppState>,
    Form(form): Form<ProposalDecisionForm>,
) -> Response {
    let (reviewer, reason) = match validate_proposal_decision(form) {
        Ok(decision) => decision,
        Err(e) => return proposal_decision_error_page(&e),
    };
    match proposals::request_revision_at_path(&state.repo_path, &vpr_id, &reviewer, &reason) {
        Ok(()) => {
            Redirect::to(&format!("/proposals/{}/preview", urlencode_path(&vpr_id))).into_response()
        }
        Err(e) => error_page("proposals", "Could not request revision", &e),
    }
}

async fn post_bridge_confirm(
    AxumPath(vbr_id): AxumPath<String>,
    State(state): State<AppState>,
) -> Response {
    set_bridge_status(&state.repo_path, &vbr_id, BridgeStatus::Confirmed);
    Redirect::to("/bridges").into_response()
}

async fn post_bridge_refute(
    AxumPath(vbr_id): AxumPath<String>,
    State(state): State<AppState>,
) -> Response {
    set_bridge_status(&state.repo_path, &vbr_id, BridgeStatus::Refuted);
    Redirect::to("/bridges").into_response()
}

// ── Bridge persistence (mirrors cli.rs cmd_bridges) ─────────────────

fn bridges_dir(repo_path: &Path) -> PathBuf {
    repo_path.join(".vela/bridges")
}

fn list_bridges(repo_path: &Path) -> Vec<Bridge> {
    let dir = bridges_dir(repo_path);
    if !dir.is_dir() {
        return Vec::new();
    }
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for e in entries.flatten() {
            let p = e.path();
            if p.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            if let Ok(data) = std::fs::read_to_string(&p)
                && let Ok(b) = serde_json::from_str::<Bridge>(&data)
            {
                out.push(b);
            }
        }
    }
    out.sort_by(|a, b| {
        b.finding_refs
            .len()
            .cmp(&a.finding_refs.len())
            .then(a.entity_name.cmp(&b.entity_name))
    });
    out
}

fn set_bridge_status(repo_path: &Path, vbr_id: &str, status: BridgeStatus) {
    let p = bridges_dir(repo_path).join(format!("{vbr_id}.json"));
    let Ok(data) = std::fs::read_to_string(&p) else {
        return;
    };
    let Ok(mut b) = serde_json::from_str::<Bridge>(&data) else {
        return;
    };
    b.status = status;
    if let Ok(out) = serde_json::to_string_pretty(&b) {
        let _ = std::fs::write(&p, format!("{out}\n"));
    }
}

// ── Static assets ───────────────────────────────────────────────────

async fn static_tokens_css() -> Response {
    css_response(TOKENS_CSS)
}
async fn static_workbench_css() -> Response {
    css_response(WORKBENCH_CSS)
}
async fn static_favicon_svg() -> Response {
    svg_response(FAVICON_SVG)
}
async fn healthz() -> Response {
    (StatusCode::OK, "ok").into_response()
}

fn css_response(body: &'static str) -> Response {
    (
        StatusCode::OK,
        [
            (axum::http::header::CONTENT_TYPE, "text/css; charset=utf-8"),
            (axum::http::header::CACHE_CONTROL, "public, max-age=300"),
        ],
        body,
    )
        .into_response()
}

fn svg_response(body: &'static str) -> Response {
    (
        StatusCode::OK,
        [
            (axum::http::header::CONTENT_TYPE, "image/svg+xml"),
            (axum::http::header::CACHE_CONTROL, "public, max-age=300"),
        ],
        body,
    )
        .into_response()
}

fn error_page(active: &str, title: &str, message: &str) -> Response {
    let body = format!(
        r#"<div class="wb-card"><h3>{title}</h3><p>{msg}</p></div>"#,
        title = escape_html(title),
        msg = escape_html(message)
    );
    let html = shell(active, title, "Workbench", title, &body);
    (StatusCode::INTERNAL_SERVER_ERROR, Html(html)).into_response()
}

// ── v0.57 review routes ───────────────────────────────────────────

fn default_reviewer() -> String {
    std::env::var("VELA_REVIEWER_ID").unwrap_or_else(|_| "reviewer:will-blair".to_string())
}

fn render_mutation_preview(action: &str, target: &str, effect: &str, writes: &str) -> String {
    format!(
        r#"<div class="wb-mutation-preview">
  <h3>Mutation preview</h3>
  <p>This preview is read-only. The POST route below is the only action that writes.</p>
  <table class="wb-table"><tbody>
    <tr><th>action</th><td>{action}</td></tr>
    <tr><th>target</th><td><code>{target}</code></td></tr>
    <tr><th>event or file effect</th><td>{effect}</td></tr>
    <tr><th>write boundary</th><td>{writes}</td></tr>
  </tbody></table>
</div>"#,
        action = escape_html(action),
        target = escape_html(target),
        effect = escape_html(effect),
        writes = escape_html(writes),
    )
}

fn render_command_copy(title: &str, commands: &[String]) -> String {
    let body = commands
        .iter()
        .map(|command| escape_html(command))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        r#"<div class="wb-card">
  <h3>{title}</h3>
  <p>Copyable commands for the same local frontier state.</p>
  <pre><code>{body}</code></pre>
</div>"#,
        title = escape_html(title),
        body = body,
    )
}

fn select_options(selected: &str, options: &[(&str, &str)]) -> String {
    options
        .iter()
        .map(|(value, label)| {
            if *value == selected {
                format!(
                    r#"<option value="{}" selected>{}</option>"#,
                    escape_html(value),
                    escape_html(label)
                )
            } else {
                format!(
                    r#"<option value="{}">{}</option>"#,
                    escape_html(value),
                    escape_html(label)
                )
            }
        })
        .collect::<Vec<_>>()
        .join("")
}

fn review_age_label(timestamp: &str) -> Option<String> {
    let then = chrono::DateTime::parse_from_rfc3339(timestamp)
        .ok()?
        .with_timezone(&chrono::Utc);
    let seconds = (chrono::Utc::now() - then).num_seconds().max(0);
    Some(match seconds {
        0..=59 => format!("{seconds}s"),
        60..=3_599 => format!("{}m", seconds / 60),
        3_600..=86_399 => format!("{}h", seconds / 3_600),
        _ => format!("{}d", seconds / 86_400),
    })
}

/// V3 follow-on: build a `<datalist>` of registered actor ids for
/// the form's reviewer input. The input still accepts free text
/// (so a new actor can be typed before being registered), but the
/// browser will autocomplete from this list.
fn actor_datalist(project: &Project) -> String {
    if project.actors.is_empty() {
        return String::new();
    }
    let mut html = String::from(r#"<datalist id="vela-actors">"#);
    for actor in &project.actors {
        html.push_str(&format!(r#"<option value="{}">"#, escape_html(&actor.id)));
    }
    html.push_str("</datalist>");
    html
}

#[derive(Debug, Deserialize)]
struct LocatorRepairForm {
    atom_id: String,
    locator: String,
    reviewer: String,
    reason: String,
}

#[derive(Debug, Deserialize)]
struct SpanRepairForm {
    finding_id: String,
    section: String,
    text: String,
    reviewer: String,
    reason: String,
}

#[derive(Debug, Deserialize)]
struct EntityResolveForm {
    finding_id: String,
    entity_name: String,
    source: String,
    id: String,
    confidence: f64,
    matched_name: Option<String>,
    resolution_method: String,
    reviewer: String,
    reason: String,
}

#[derive(Debug, Deserialize)]
struct PromoteForm {
    finding_id: String,
    status: String,
    reviewer: String,
    reason: String,
}

#[derive(Debug, Deserialize)]
struct ConflictResolveForm {
    conflict_event_id: String,
    resolution_note: String,
    reviewer: String,
    winning_proposal_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ReplicationAddForm {
    finding_id: String,
    outcome: String,
    attempted_by: String,
    conditions_text: String,
    source_title: String,
    #[serde(default)]
    doi: String,
    #[serde(default)]
    pmid: String,
    #[serde(default)]
    note: String,
}

#[derive(Debug, Deserialize)]
struct PredictionAddForm {
    finding_id: String,
    claim_text: String,
    resolves_by: String,
    resolution_criterion: String,
    expected_outcome: String,
    made_by: String,
    confidence: f64,
    conditions_text: String,
}

// V3 follow-on: inbox filter by source identifier prefix. The form
// at the top of the page submits via GET (no JS), and the
// pending-review table filters server-side. Empty filter means
// show everything.
#[derive(Debug, Deserialize, Default)]
struct InboxFilter {
    #[serde(default)]
    source: String,
    #[serde(default)]
    group: String,
    #[serde(default)]
    sort: String,
}

#[derive(Debug, Deserialize, Default)]
struct GraphPathQuery {
    #[serde(default)]
    finding: String,
}

#[derive(Debug, Clone, Serialize)]
struct ReviewWorkPayload {
    schema: &'static str,
    frontier_id: String,
    frontier_name: String,
    frontier_path: String,
    read_only: bool,
    counts_as_review: bool,
    mutates_frontier: bool,
    total_open: usize,
    proof_status: String,
    validation_commands: Vec<&'static str>,
    frontier_index: ReviewWorkFrontierIndex,
    frontier_graph: ReviewWorkGraphNavigation,
    benchmark_mode: ReviewWorkBenchmarkMode,
    action_queue_submit: ReviewWorkSubmitPath,
    queues: Vec<ReviewWorkQueue>,
}

#[derive(Debug, Clone, Serialize)]
struct ReviewWorkGraphNavigation {
    title: &'static str,
    graph_artifacts: Vec<&'static str>,
    copy_commands: Vec<&'static str>,
    boundary: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct ReviewWorkFrontierIndex {
    title: &'static str,
    present: bool,
    source: &'static str,
    database_path: String,
    report_path: String,
    database_is_authority: bool,
    canonical_state: &'static str,
    fallback_counts_from_files: bool,
    counts: BTreeMap<String, usize>,
    copy_commands: Vec<String>,
    boundary: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct ReviewWorkBenchmarkMode {
    title: &'static str,
    benchmark_artifacts: Vec<&'static str>,
    copy_commands: Vec<&'static str>,
    boundary: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct ReviewWorkSubmitPath {
    source: &'static str,
    proposal_preview_commands: Vec<&'static str>,
    explicit_reviewer_actions: Vec<&'static str>,
    boundary: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct ReviewWorkQueue {
    lane_id: &'static str,
    title: &'static str,
    count: usize,
    examples: Vec<String>,
    operator_artifacts: Vec<&'static str>,
    validation_commands: Vec<&'static str>,
    boundary: &'static str,
    next_href: &'static str,
    next_label: &'static str,
    reviewer_authority_required: bool,
}

fn render_review_work_examples(examples: &[String]) -> String {
    if examples.is_empty() {
        return "none".to_string();
    }
    examples
        .iter()
        .map(|id| format!("<code>{}</code>", escape_html(id)))
        .collect::<Vec<_>>()
        .join(" · ")
}

fn render_review_work_artifacts(artifacts: &[&str]) -> String {
    if artifacts.is_empty() {
        return "none".to_string();
    }
    artifacts
        .iter()
        .map(|artifact| format!("<code>{}</code>", escape_html(artifact)))
        .collect::<Vec<_>>()
        .join(" · ")
}

fn render_review_work_commands(commands: &[&str]) -> String {
    if commands.is_empty() {
        return "none".to_string();
    }
    commands
        .iter()
        .map(|command| format!("<code>{}</code>", escape_html(command)))
        .collect::<Vec<_>>()
        .join(" · ")
}

fn render_review_work_owned_commands(commands: &[String]) -> String {
    if commands.is_empty() {
        return "none".to_string();
    }
    commands
        .iter()
        .map(|command| format!("<code>{}</code>", escape_html(command)))
        .collect::<Vec<_>>()
        .join(" · ")
}

fn render_index_counts(counts: &BTreeMap<String, usize>) -> String {
    if counts.is_empty() {
        return "none".to_string();
    }
    counts
        .iter()
        .map(|(key, count)| format!("<code>{}</code>: {}", escape_html(key), count))
        .collect::<Vec<_>>()
        .join(" · ")
}

fn build_review_work_frontier_index(
    repo_path: &Path,
    project: &Project,
) -> ReviewWorkFrontierIndex {
    let db_path = repo_path
        .join(".vela")
        .join("index")
        .join("frontier-index.sqlite");
    let report_path = repo_path
        .join(".vela")
        .join("index")
        .join("frontier-index.report.v1.json");
    let mut counts = BTreeMap::new();
    let present = db_path.is_file() && report_path.is_file();
    let mut source = "canonical_frontier_files";
    let mut fallback_counts_from_files = true;

    if present
        && let Ok(body) = fs::read_to_string(&report_path)
        && let Ok(report) = serde_json::from_str::<serde_json::Value>(&body)
        && let Some(index_counts) = report.get("counts").and_then(serde_json::Value::as_object)
    {
        for key in [
            "findings",
            "sources",
            "evidence_atoms",
            "links",
            "events",
            "proposals",
            "proof_files",
            "score_returns",
            "benchmark_rows",
        ] {
            if let Some(count) = index_counts
                .get(key)
                .and_then(serde_json::Value::as_u64)
                .map(|count| count as usize)
            {
                counts.insert(key.to_string(), count);
            }
        }
        source = "frontier_index";
        fallback_counts_from_files = false;
    }

    if fallback_counts_from_files {
        counts.insert("findings".to_string(), project.findings.len());
        counts.insert("sources".to_string(), project.sources.len());
        counts.insert("evidence_atoms".to_string(), project.evidence_atoms.len());
        counts.insert("links".to_string(), project.stats.links);
        counts.insert("events".to_string(), project.events.len());
        counts.insert("proposals".to_string(), project.proposals.len());
    }

    ReviewWorkFrontierIndex {
        title: "Frontier index database",
        present,
        source,
        database_path: db_path.display().to_string(),
        report_path: report_path.display().to_string(),
        database_is_authority: false,
        canonical_state: index_db_schema::CANONICAL_STATE,
        fallback_counts_from_files,
        counts,
        copy_commands: vec![
            format!("vela index build {} --json", repo_path.display()),
            format!("vela index status {} --json", repo_path.display()),
            format!(
                "vela index query {} --kind finding --q amyloid --json",
                repo_path.display()
            ),
        ],
        boundary: "The database is a rebuildable read model. Canonical state remains frontier files and accepted events.",
    }
}

fn render_review_work_row(row: &ReviewWorkQueue) -> String {
    let next_step = format!(
        r#"<a href="{}">{}</a>"#,
        escape_html(row.next_href),
        escape_html(row.next_label)
    );
    format!(
        r#"<tr>
  <td>{queue}</td>
  <td>{count}</td>
  <td>{examples}</td>
  <td>{artifacts}</td>
  <td>{commands}</td>
  <td>{boundary}</td>
  <td>{next_step}</td>
</tr>"#,
        queue = row.title,
        count = row.count,
        examples = render_review_work_examples(&row.examples),
        artifacts = render_review_work_artifacts(&row.operator_artifacts),
        commands = render_review_work_commands(&row.validation_commands),
        boundary = escape_html(row.boundary),
    )
}

fn review_work_validation_commands(project: &Project) -> Vec<&'static str> {
    let name = project.project.name.to_ascii_lowercase();
    if name.contains("anti-amyloid") {
        vec![
            "reviewer-extraction-signoff.sh",
            "validate-human-reviewer-completion.sh",
            "validate-outside-review-return.sh",
            "validate-outside-review-action-map.sh",
            "validate-outside-review-completion.sh",
        ]
    } else if name.contains("pediatric") || name.contains("hgg") {
        vec![
            "validate-pediatric-hgg-cleanup-return.sh",
            "validate-pediatric-hgg-cleanup-action-map.sh",
        ]
    } else {
        vec![
            "validate-strict-signal-return.sh",
            "validate-strict-signal-action-map.sh",
        ]
    }
}

fn review_work_queue_validation_commands(
    lane_id: &str,
    anti_amyloid_review: bool,
    pediatric_review: bool,
) -> Vec<&'static str> {
    if anti_amyloid_review {
        match lane_id {
            "source_review" => vec![
                "validate-human-reviewer-completion.sh",
                "validate-outside-review-completion.sh",
            ],
            "extraction_signoff" => vec![
                "reviewer-extraction-signoff.sh",
                "validate-human-reviewer-completion.sh",
            ],
            "decision_adjudication" => vec![
                "validate-anti-amyloid-decision-review-ledger.sh",
                "validate-human-reviewer-completion.sh",
            ],
            "outside_review" => vec![
                "validate-outside-review-return.sh",
                "validate-outside-review-action-map.sh",
                "validate-outside-review-completion.sh",
            ],
            "post_review_refresh" => vec!["vela proof verify"],
            _ => Vec::new(),
        }
    } else if pediatric_review {
        match lane_id {
            "source_review"
            | "entity_review"
            | "proposal_review"
            | "diff_pack_attestation"
            | "strict_signal_review"
            | "task_closure" => vec![
                "validate-pediatric-hgg-cleanup-return.sh",
                "validate-pediatric-hgg-cleanup-action-map.sh",
                "validate-pediatric-hgg-cleanup-completion.sh",
            ],
            "post_review_refresh" => vec!["vela proof verify"],
            _ => Vec::new(),
        }
    } else {
        match lane_id {
            "source_review" => vec![
                "validate-strict-signal-return.sh",
                "validate-strict-signal-action-map.sh",
                "validate-gbm-strict-signal-completion.sh",
            ],
            "entity_review" | "proposal_review" | "strict_signal_review" => vec![
                "validate-strict-signal-return.sh",
                "validate-strict-signal-action-map.sh",
                "validate-gbm-strict-signal-completion.sh",
            ],
            "outside_review" => vec![
                "validate-outside-review-return.sh",
                "validate-outside-review-action-map.sh",
            ],
            "task_closure" => vec!["validate-gbm-strict-signal-completion.sh"],
            "post_review_refresh" => vec!["vela proof verify"],
            _ => Vec::new(),
        }
    }
}

fn outside_review_files(repo_path: &Path) -> Vec<String> {
    let review_dir = repo_path.join("review");
    let mut files = Vec::new();
    let Ok(entries) = fs::read_dir(&review_dir) else {
        return files;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if name.starts_with("outside-review") && name.ends_with(".md") {
            files.push(name.to_string());
        }
    }
    files.sort();
    files
}

fn review_heading_ids(
    repo_path: &Path,
    rel_path: &str,
    heading_marker: &str,
    id_prefix: &str,
) -> Vec<String> {
    let path = repo_path.join(rel_path);
    let Ok(content) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut ids = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim_start();
        let Some(rest) = trimmed.strip_prefix(heading_marker) else {
            continue;
        };
        let rest = rest.trim_start();
        if !rest.starts_with(id_prefix) {
            continue;
        }
        let id = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric())
            .collect::<String>();
        if !id.is_empty() {
            ids.push(id);
        }
    }
    ids
}

fn decision_adjudication_open_ids(repo_path: &Path) -> Vec<String> {
    let ledger_path = repo_path.join("review/decision-review-ledger.v1.json");
    let Ok(content) = fs::read_to_string(ledger_path) else {
        return review_heading_ids(
            repo_path,
            "review/decision-adjudication-queue.v1.md",
            "##",
            "A",
        );
    };
    let Ok(ledger) = serde_json::from_str::<serde_json::Value>(&content) else {
        return review_heading_ids(
            repo_path,
            "review/decision-adjudication-queue.v1.md",
            "##",
            "A",
        );
    };
    ledger
        .get("items")
        .and_then(|items| items.as_array())
        .into_iter()
        .flatten()
        .filter(|item| {
            item.get("lane").and_then(|lane| lane.as_str()) == Some("decision_adjudication")
        })
        .filter(|item| item.get("status").and_then(|status| status.as_str()) == Some("pending"))
        .filter_map(|item| {
            item.get("id")
                .and_then(|id| id.as_str())
                .map(str::to_string)
        })
        .collect()
}

fn extraction_signoff_ids_from_applied_proposals(project: &Project) -> BTreeSet<String> {
    project
        .proposals
        .iter()
        .filter(|proposal| {
            proposal.kind == "finding.add"
                && proposal.status == "applied"
                && proposal.actor.id == "agent:extraction-bot-2026-05-16"
                && proposal.reviewed_by.as_deref() == Some("reviewer:will-blair")
        })
        .filter_map(|proposal| proposal.decision_reason.as_deref())
        .filter(|reason| reason.contains("extraction batch-sign"))
        .filter_map(extraction_signoff_id_from_reason)
        .collect()
}

fn extraction_signoff_id_from_reason(reason: &str) -> Option<String> {
    let start = reason.find("(E")? + 1;
    let id = reason[start..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric())
        .collect::<String>();
    let suffix = id.strip_prefix('E')?;
    if suffix.is_empty() || !suffix.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some(id)
}

fn review_table_lane_ids(repo_path: &Path, rel_path: &str) -> Vec<String> {
    let path = repo_path.join(rel_path);
    let Ok(content) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut ids = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim_start();
        let Some(rest) = trimmed.strip_prefix('|') else {
            continue;
        };
        let Some(first_cell) = rest.split('|').next() else {
            continue;
        };
        let id = first_cell.trim();
        if id.len() == 2 && id.starts_with('R') && id[1..].chars().all(|c| c.is_ascii_digit()) {
            ids.push(id.to_string());
        }
    }
    ids
}

fn local_diff_pack_ids(repo_path: &Path) -> Vec<String> {
    let diff_pack_dir = repo_path.join(".vela").join("diff_packs");
    let mut ids = Vec::new();
    let Ok(entries) = fs::read_dir(&diff_pack_dir) else {
        return ids;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.extension().is_some_and(|ext| ext == "json") {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
            continue;
        };
        ids.push(stem.to_string());
    }
    ids.sort();
    ids
}

fn build_review_work_payload(repo_path: &Path) -> Result<ReviewWorkPayload, String> {
    let project = repo::load_from_path(repo_path)?;
    let source_list = source_inbox::list_records(repo_path)?;
    let task_list = frontier_task::list_tasks(repo_path)?;
    let health = frontier_health::analyze(repo_path)?;
    let frontier_index = build_review_work_frontier_index(repo_path, &project);

    let source_review: Vec<String> = source_list
        .records
        .iter()
        .filter(|record| {
            matches!(
                record.state,
                source_inbox::SourceInboxState::Discovered
                    | source_inbox::SourceInboxState::Retrieved
            )
        })
        .map(|record| record.id.clone())
        .collect();
    let entity_review: Vec<String> = project
        .findings
        .iter()
        .filter(|finding| {
            finding
                .assertion
                .entities
                .iter()
                .any(|entity| entity.needs_review)
        })
        .map(|finding| finding.id.clone())
        .collect();
    let proposal_review: Vec<String> = project
        .proposals
        .iter()
        .filter(|proposal| proposal.status == "pending_review")
        .map(|proposal| proposal.id.clone())
        .collect();
    let mut strict_signal_examples = entity_review.iter().take(4).cloned().collect::<Vec<_>>();
    strict_signal_examples.extend(proposal_review.iter().take(4).cloned());

    let diff_pack_examples = local_diff_pack_ids(repo_path);
    let diff_pack_blockers =
        health.metrics.pending_diff_packs + health.metrics.missing_attestations;
    let diff_pack_examples = if diff_pack_blockers == 0 {
        Vec::new()
    } else {
        diff_pack_examples
    };
    let task_closure: Vec<String> = task_list
        .tasks
        .iter()
        .filter(|task| !task.status.is_terminal())
        .map(|task| task.id.clone())
        .collect();
    let outside_review = outside_review_files(repo_path);
    let proof_refresh_count = if matches!(
        project.proof_state.latest_packet.status.as_str(),
        "fresh" | "current" | "ready"
    ) {
        0
    } else {
        1
    };
    let validation_commands = review_work_validation_commands(&project);
    let frontier_id = project.frontier_id();
    let proof_status = project.proof_state.latest_packet.status.clone();
    let frontier_name = project.project.name.clone();

    let frontier_name_lower = frontier_name.to_ascii_lowercase();
    let anti_amyloid_review = frontier_name_lower.contains("anti-amyloid");
    let pediatric_review =
        frontier_name_lower.contains("pediatric") || frontier_name_lower.contains("hgg");
    let queues = if anti_amyloid_review {
        let applied_extraction_signoffs = extraction_signoff_ids_from_applied_proposals(&project);
        let extraction_signoff = review_heading_ids(
            repo_path,
            "review/decision-extraction-queue.v1.md",
            "###",
            "E",
        )
        .into_iter()
        .filter(|id| !applied_extraction_signoffs.contains(id))
        .collect::<Vec<_>>();
        let decision_adjudication = decision_adjudication_open_ids(repo_path);
        let outside_review_lanes =
            review_heading_ids(repo_path, "review/outside-review-2026-q2.md", "###", "R");
        let outside_review_lanes = if outside_review_lanes.len() >= 4 {
            outside_review_lanes
        } else {
            review_table_lane_ids(repo_path, "review/outside-review-launch-2026-q2.md")
        };
        vec![
            ReviewWorkQueue {
                lane_id: "source_review",
                title: "source review",
                count: source_review.len(),
                examples: source_review.iter().take(8).cloned().collect(),
                operator_artifacts: vec![
                    "docs/REVIEWER_PLAYBOOK.md",
                    "review/decision-corpus-queue.v1.md",
                ],
                validation_commands: review_work_queue_validation_commands(
                    "source_review",
                    anti_amyloid_review,
                    pediatric_review,
                ),
                boundary: "Decision-corpus sources require human attestation before they count as reviewed state.",
                next_href: "/source-inbox",
                next_label: "Open source inbox",
                reviewer_authority_required: true,
            },
            ReviewWorkQueue {
                lane_id: "extraction_signoff",
                title: "extraction signoff",
                count: extraction_signoff.len(),
                examples: extraction_signoff.iter().take(12).cloned().collect(),
                operator_artifacts: vec![
                    "review/extraction-policy.v1.md",
                    "review/decision-extraction-queue.v1.md",
                    "scripts/reviewer-extraction-signoff.sh",
                ],
                validation_commands: review_work_queue_validation_commands(
                    "extraction_signoff",
                    anti_amyloid_review,
                    pediatric_review,
                ),
                boundary: "Extraction signoff attests faithful spans only after reviewer confirmation.",
                next_href: "/review/inbox",
                next_label: "Open review inbox",
                reviewer_authority_required: true,
            },
            ReviewWorkQueue {
                lane_id: "decision_adjudication",
                title: "decision adjudication",
                count: decision_adjudication.len(),
                examples: decision_adjudication.iter().take(8).cloned().collect(),
                operator_artifacts: vec![
                    "review/decision-adjudication-queue.v1.md",
                    "decision/decision-brief.v1.json",
                ],
                validation_commands: review_work_queue_validation_commands(
                    "decision_adjudication",
                    anti_amyloid_review,
                    pediatric_review,
                ),
                boundary: "Decision nodes remain pending until reviewer verdicts accept, caveat, reject, or hold them.",
                next_href: "/decision",
                next_label: "Open decision brief",
                reviewer_authority_required: true,
            },
            ReviewWorkQueue {
                lane_id: "outside_review",
                title: "outside review",
                count: outside_review_lanes.len(),
                examples: outside_review_lanes.iter().take(4).cloned().collect(),
                operator_artifacts: vec![
                    "review/outside-review-2026-q2.md",
                    "review/outside-review-launch-2026-q2.md",
                    "docs/templates/outside-review-return.md",
                    "docs/templates/outside-review-action-map.md",
                ],
                validation_commands: review_work_queue_validation_commands(
                    "outside_review",
                    anti_amyloid_review,
                    pediatric_review,
                ),
                boundary: "Outside-review lanes require returned artifacts and action maps before the gate clears.",
                next_href: "/review/inbox",
                next_label: "Open review inbox",
                reviewer_authority_required: true,
            },
            ReviewWorkQueue {
                lane_id: "post_review_refresh",
                title: "post-review refresh",
                count: proof_refresh_count,
                examples: vec![frontier_id.clone()],
                operator_artifacts: vec!["proof/latest.json", "proof/hashes.json"],
                validation_commands: review_work_queue_validation_commands(
                    "post_review_refresh",
                    anti_amyloid_review,
                    pediatric_review,
                ),
                boundary: "Proof packets should be refreshed after accepted frontier changes.",
                next_href: "/proof",
                next_label: "Open proof",
                reviewer_authority_required: false,
            },
        ]
    } else {
        vec![
            ReviewWorkQueue {
                lane_id: "source_review",
                title: "source review",
                count: source_review.len(),
                examples: source_review.iter().take(8).cloned().collect(),
                operator_artifacts: if pediatric_review {
                    vec!["pediatric-hgg-cleanup-packet.json"]
                } else {
                    vec!["review/decision-corpus-queue.v1.md"]
                },
                validation_commands: review_work_queue_validation_commands(
                    "source_review",
                    anti_amyloid_review,
                    pediatric_review,
                ),
                boundary: "Source records are not evidence until reviewed into frontier state.",
                next_href: "/source-inbox",
                next_label: "Open source inbox",
                reviewer_authority_required: true,
            },
            ReviewWorkQueue {
                lane_id: "entity_review",
                title: "entity review",
                count: entity_review.len(),
                examples: entity_review.iter().take(8).cloned().collect(),
                operator_artifacts: if pediatric_review {
                    vec!["PEDIATRIC_HGG_CLEANUP_LANES.md"]
                } else {
                    vec!["review/strict-signal-remediation.v1.md"]
                },
                validation_commands: review_work_queue_validation_commands(
                    "entity_review",
                    anti_amyloid_review,
                    pediatric_review,
                ),
                boundary: "Entity flags mark candidates that still need human normalization.",
                next_href: "/review/inbox?group=entity_issue",
                next_label: "Open entity queue",
                reviewer_authority_required: true,
            },
            ReviewWorkQueue {
                lane_id: "proposal_review",
                title: "proposal review",
                count: proposal_review.len(),
                examples: proposal_review.iter().take(12).cloned().collect(),
                operator_artifacts: if pediatric_review {
                    vec!["PEDIATRIC_HGG_CLEANUP_LANES.md"]
                } else {
                    vec![
                        "review/decision-adjudication-queue.v1.md",
                        "review/strict-signal-remediation.v1.md",
                    ]
                },
                validation_commands: review_work_queue_validation_commands(
                    "proposal_review",
                    anti_amyloid_review,
                    pediatric_review,
                ),
                boundary: "Pending proposals are runtime output until a reviewer applies or rejects them.",
                next_href: "/proposals",
                next_label: "Open proposals",
                reviewer_authority_required: true,
            },
            ReviewWorkQueue {
                lane_id: "outside_review",
                title: "outside review",
                count: outside_review.len(),
                examples: outside_review.iter().take(4).cloned().collect(),
                operator_artifacts: if pediatric_review {
                    vec!["pediatric-hgg-cleanup-packet.json"]
                } else {
                    vec![
                        "review/outside-review-2026-q3.md",
                        "docs/templates/outside-review-return.md",
                        "docs/templates/outside-review-action-map.md",
                    ]
                },
                validation_commands: review_work_queue_validation_commands(
                    "outside_review",
                    anti_amyloid_review,
                    pediatric_review,
                ),
                boundary: "Outside review packets must be dispatched and returned outside this read-only page.",
                next_href: "/review/inbox",
                next_label: "Open review inbox",
                reviewer_authority_required: true,
            },
            ReviewWorkQueue {
                lane_id: "diff_pack_attestation",
                title: "Diff Pack attestation",
                count: diff_pack_blockers,
                examples: diff_pack_examples.iter().take(8).cloned().collect(),
                operator_artifacts: vec![
                    "PEDIATRIC_HGG_CLEANUP_LANES.md",
                    "pediatric-hgg-cleanup-packet.json",
                ],
                validation_commands: review_work_queue_validation_commands(
                    "diff_pack_attestation",
                    anti_amyloid_review,
                    pediatric_review,
                ),
                boundary: "Missing role attestations block release promotion.",
                next_href: "/diff-packs",
                next_label: "Open Diff Packs",
                reviewer_authority_required: true,
            },
            ReviewWorkQueue {
                lane_id: "strict_signal_review",
                title: "strict-signal review",
                count: entity_review.len() + proposal_review.len(),
                examples: strict_signal_examples,
                operator_artifacts: vec![
                    "review/strict-signal-remediation.v1.md",
                    "PEDIATRIC_HGG_CLEANUP_LANES.md",
                ],
                validation_commands: review_work_queue_validation_commands(
                    "strict_signal_review",
                    anti_amyloid_review,
                    pediatric_review,
                ),
                boundary: "Strict signals are candidates for source-grounded review, not accepted frontier truth.",
                next_href: "/review/inbox",
                next_label: "Open review inbox",
                reviewer_authority_required: true,
            },
            ReviewWorkQueue {
                lane_id: "task_closure",
                title: "task closure",
                count: task_closure.len(),
                examples: task_closure.iter().take(12).cloned().collect(),
                operator_artifacts: vec![
                    "PEDIATRIC_HGG_CLEANUP_PACKET.md",
                    "PEDIATRIC_HGG_CLEANUP_LANES.md",
                ],
                validation_commands: review_work_queue_validation_commands(
                    "task_closure",
                    anti_amyloid_review,
                    pediatric_review,
                ),
                boundary: "Tasks are operational work units; closure does not rewrite reviewed findings.",
                next_href: "/tasks",
                next_label: "Open tasks",
                reviewer_authority_required: true,
            },
            ReviewWorkQueue {
                lane_id: "post_review_refresh",
                title: "post-review refresh",
                count: proof_refresh_count,
                examples: vec![frontier_id.clone()],
                operator_artifacts: vec!["proof/latest.json", "proof/hashes.json"],
                validation_commands: review_work_queue_validation_commands(
                    "post_review_refresh",
                    anti_amyloid_review,
                    pediatric_review,
                ),
                boundary: "Proof packets should be refreshed after accepted frontier changes.",
                next_href: "/proof",
                next_label: "Open proof",
                reviewer_authority_required: false,
            },
        ]
    };
    let total_open = queues.iter().map(|queue| queue.count).sum();

    Ok(ReviewWorkPayload {
        schema: "vela.workbench.review_work.v0.1",
        frontier_id,
        frontier_name,
        frontier_path: repo_path.display().to_string(),
        read_only: true,
        counts_as_review: false,
        mutates_frontier: false,
        total_open,
        proof_status,
        validation_commands,
        frontier_index,
        frontier_graph: ReviewWorkGraphNavigation {
            title: "Frontier graph navigation",
            graph_artifacts: vec![
                ".vela/graph/frontier-graph.v1.json",
                ".vela/graph/impact-index.v1.json",
                ".vela/graph/guided-tours.v1.json",
            ],
            copy_commands: vec![
                "jq '.summary, .claim_boundary' .vela/graph/frontier-graph.v1.json",
                "jq '.finding_neighborhoods[0:5]' .vela/graph/impact-index.v1.json",
                "jq '.tours[] | {id,title,steps: (.steps | length)}' .vela/graph/guided-tours.v1.json",
            ],
            boundary: "copy commands only; graph navigation does not mutate frontier state",
        },
        benchmark_mode: ReviewWorkBenchmarkMode {
            title: "Graph benchmark mode",
            benchmark_artifacts: vec![
                "benchmarks/frontier-graph-navigation-answers.v1.json",
                "benchmarks/frontier-graph-navigation-paper-rag-baseline.v1.json",
                "benchmarks/frontier-graph-blind-scoring-pack.v1.json",
                "benchmarks/frontier-graph-benchmark-error-analysis.v1.json",
                "docs/FRONTIER_GRAPH_BENCHMARK_ERROR_ANALYSIS_v0.482.md",
            ],
            copy_commands: vec![
                "./scripts/run-frontier-graph-navigation-answers.py projects/anti-amyloid-translation",
                "./scripts/build-frontier-paper-rag-baseline-v2.py projects/anti-amyloid-translation",
                "./scripts/build-frontier-graph-blind-scoring-pack.py",
                "./scripts/score-frontier-graph-benchmark-errors.py",
            ],
            boundary: "copy benchmark commands only; this workbench mode does not score external validation and does not mutate frontier state",
        },
        action_queue_submit: ReviewWorkSubmitPath {
            source: "review/frontier-action-queue.v1.json",
            proposal_preview_commands: vec![
                "vela correction-return propose projects/anti-amyloid-translation/review/correction-return.template.json --frontier projects/anti-amyloid-translation --out /tmp/correction-return-proposals.json --json",
                "vela proposals import projects/anti-amyloid-translation /tmp/correction-return-proposals.json --json",
            ],
            explicit_reviewer_actions: vec![
                "vela proposals accept projects/anti-amyloid-translation <proposal-id> --reviewer reviewer:solo-maintainer --reason \"Accept returned correction into observation review history.\" --json",
                "vela proposals reject projects/anti-amyloid-translation <proposal-id> --reviewer reviewer:solo-maintainer --reason \"Reject returned correction for now.\" --json",
            ],
            boundary: "Proposal previews and reviewer actions are commands to copy. The workbench page does not execute them.",
        },
        queues,
    })
}

pub(crate) fn build_review_work_json(repo_path: &Path) -> Result<serde_json::Value, String> {
    let payload = build_review_work_payload(repo_path)?;
    serde_json::to_value(payload).map_err(|e| format!("serialize review work: {e}"))
}

async fn page_review_cockpit(State(state): State<AppState>) -> Response {
    let project = match repo::load_from_path(&state.repo_path) {
        Ok(project) => project,
        Err(e) => return error_page("review cockpit", "Could not load frontier", &e),
    };
    let payload = match build_review_work_payload(&state.repo_path) {
        Ok(payload) => payload,
        Err(e) => return error_page("review cockpit", "Could not load review work", &e),
    };
    let health = match frontier_health::analyze(&state.repo_path) {
        Ok(health) => health,
        Err(e) => return error_page("review cockpit", "Could not compute health", &e),
    };
    let task_summary = frontier_task::task_summary(&state.repo_path);
    let source_summary = source_inbox::source_inbox_summary(&state.repo_path);
    let queue_rows = payload
        .queues
        .iter()
        .map(render_review_work_row)
        .collect::<Vec<_>>()
        .join("");
    let validation_commands = payload
        .validation_commands
        .iter()
        .map(|cmd| format!("<code>{}</code>", escape_html(cmd)))
        .collect::<Vec<_>>()
        .join(" · ");
    let review_queue_count = payload.queues.len();
    let release_asset_count = project.artifacts.len()
        + project.datasets.len()
        + project.code_artifacts.len()
        + project.released_diff_packs.len();
    let proof_label = if health.metrics.stale_proof {
        "stale"
    } else {
        health.metrics.proof_status.as_str()
    };
    let benchmark_replay_rows = [
        (
            "v0.419",
            "Live-evaluator benchmark protocol",
            "./scripts/build-live-evaluator-benchmark-protocol.sh /tmp/vela-v0425/v0419",
            "/review/work",
        ),
        (
            "v0.420",
            "Live-evaluator output capture",
            "./scripts/build-live-evaluator-output-capture.sh /tmp/vela-v0425/v0420",
            "/artifact-packets",
        ),
        (
            "v0.421",
            "Blinded scoring",
            "./scripts/build-live-evaluator-blinded-scoring.sh /tmp/vela-v0425/v0421",
            "/review/work",
        ),
        (
            "v0.422",
            "Causal intervention-node packets",
            "./scripts/build-anti-amyloid-causal-intervention-node-packets.sh /tmp/vela-v0425/v0422",
            "/review/inbox",
        ),
        (
            "v0.423",
            "Organoid perturbation import",
            "./scripts/build-organoid-perturbation-import.sh /tmp/vela-v0425/v0423",
            "/source-inbox",
        ),
        (
            "v0.424",
            "Source freshness trial regulatory adapters",
            "./scripts/build-source-freshness-trial-regulatory-adapters.sh /tmp/vela-v0425/v0424",
            "/source-inbox",
        ),
        (
            "v0.432",
            "Multi-frontier benchmark task freeze",
            "./scripts/build-multi-frontier-benchmark-task-freeze.sh /tmp/vela-v0434/v0432",
            "/review/work",
        ),
        (
            "v0.433",
            "Multi-frontier benchmark scored outputs",
            "./scripts/build-multi-frontier-benchmark-scored-outputs.sh /tmp/vela-v0434/v0433",
            "/review/work",
        ),
    ]
    .iter()
    .map(|(slice, title, command, route)| {
        format!(
            r#"<tr>
  <td><code>{slice}</code></td>
  <td>{title}</td>
  <td><code>{command}</code></td>
  <td><a href="{route}">{route}</a></td>
  <td><code>counts_as_review=false</code> · <code>claims_external_validation=false</code></td>
</tr>"#,
            slice = escape_html(slice),
            title = escape_html(title),
            command = escape_html(command),
            route = escape_html(route),
        )
    })
    .collect::<Vec<_>>()
    .join("");

    let body = format!(
        r#"<section class="wb-hero" aria-label="Daily review cockpit">
  <div class="wb-hero__grid">
    <div>
      <h2>Daily review cockpit</h2>
      <p>This read-only cockpit gathers review work, proof freshness, source inbox, tasks, Evidence CI, and release assets for the current frontier. It does not count as review and does not mutate frontier state.</p>
      <div class="wb-action-row">
        <a class="wb-button" href="/review/work">Open review work</a>
        <a class="wb-button wb-button--quiet" href="/review/inbox">Open review inbox</a>
        <a class="wb-button wb-button--quiet" href="/health/frontier">Open health</a>
        <a class="wb-button wb-button--quiet" href="/proof">Open proof</a>
        <a class="wb-button wb-button--quiet" href="/artifact-packets">Open packets</a>
      </div>
    </div>
    <div class="wb-status-panel" aria-label="Cockpit summary">
      <div><span>Frontier</span><strong>{frontier_id}</strong></div>
      <div><span>Open review work</span><strong>{total_open}</strong></div>
      <div><span>Review lanes</span><strong>{review_queue_count}</strong></div>
      <div><span>Proof freshness</span><strong>{proof_label}</strong></div>
      <div><span>Evidence CI</span><strong>{evidence_ci_summary}</strong></div>
      <div><span>Release assets</span><strong>{release_asset_count}</strong></div>
    </div>
  </div>
</section>

<div class="wb-grid" aria-label="Daily cockpit modules">
  <section class="wb-card">
    <h3>Review work</h3>
    <p><strong>{total_open}</strong> open row(s) across <strong>{review_queue_count}</strong> lane(s). Queue rows route to source review, extraction signoff, decision adjudication, outside review, Diff Packs, tasks, and proof refresh when present.</p>
    <p><a href="/review/work">Open review work</a></p>
  </section>
  <section class="wb-card">
    <h3>Proof freshness</h3>
    <p>Latest packet status is <code>{proof_status}</code>. Stale proof is <code>{stale_proof}</code>.</p>
    <p><a href="/proof">Open proof</a></p>
  </section>
  <section class="wb-card">
    <h3>Source inbox</h3>
    <p><strong>{source_total}</strong> records · <strong>{source_quarantined}</strong> quarantined · <strong>{source_retracted}</strong> retracted · <strong>{source_task_linked}</strong> task-linked · <strong>{source_stale}</strong> stale · <strong>{source_rejected}</strong> rejected imports.</p>
    <p><a href="/source-inbox">Open source inbox</a></p>
  </section>
  <section class="wb-card">
    <h3>Tasks</h3>
    <p><strong>{task_total}</strong> total · <strong>{task_active}</strong> active · <strong>{task_blocked}</strong> blocked · <strong>{task_review}</strong> awaiting review · <strong>{task_terminal}</strong> terminal.</p>
    <p><a href="/tasks">Open tasks</a></p>
  </section>
  <section class="wb-card">
    <h3>Evidence CI</h3>
    <p><strong>{evidence_failures}</strong> failure(s) · <strong>{evidence_warnings}</strong> warning(s). Evidence CI marks operating issues. It does not decide scientific truth.</p>
    <p><a href="/health/frontier">Open health</a></p>
  </section>
  <section class="wb-card">
    <h3>Release assets</h3>
    <p><strong>{release_asset_count}</strong> artifact, dataset, code, or released Diff Pack record(s) are visible in this projection. Artifact packets remain distribution material until reviewed into state.</p>
    <p><a href="/artifact-packets">Open artifact packets</a></p>
  </section>
  <section class="wb-card">
    <h3>Write boundary</h3>
    <p>Only explicit reviewer actions write events. This cockpit is read-only: <code>read_only=true</code>, <code>counts_as_review=false</code>, and <code>mutates_frontier=false</code>.</p>
    <p><a href="/review/sessions">Open review sessions</a></p>
  </section>
</div>

  <section class="wb-card">
    <h3>Benchmark replay</h3>
  <p>Replay the v0.419-v0.424 benchmark/source-review arc and the v0.432-v0.433 multi-frontier benchmark arc before interpreting the current frontier. These commands rebuild local artifacts from checked-in state. Viewing this cockpit has <code>read_only=true</code>, <code>counts_as_review=false</code>, and <code>claims_external_validation=false</code>.</p>
  <div class="wb-action-row">
    <a class="wb-button wb-button--quiet" href="/review/work.json">Open review work JSON</a>
    <a class="wb-button wb-button--quiet" href="/source-inbox">Open source inbox</a>
    <a class="wb-button wb-button--quiet" href="/diff-packs">Open Diff Packs</a>
    <a class="wb-button wb-button--quiet" href="/health/frontier">Open health</a>
    <a class="wb-button wb-button--quiet" href="/proof">Open proof</a>
  </div>
  <table class="wb-table">
    <thead><tr><th>slice</th><th>artifact</th><th>replay command</th><th>route</th><th>boundary</th></tr></thead>
    <tbody>{benchmark_replay_rows}</tbody>
  </table>
</section>

<section class="wb-card">
  <h3>Review work lanes</h3>
  <table class="wb-table">
    <thead><tr><th>queue</th><th>count</th><th>examples</th><th>operator artifacts</th><th>validators</th><th>boundary</th><th>next step</th></tr></thead>
    <tbody>{queue_rows}</tbody>
  </table>
</section>

<section class="wb-card">
  <h3>Validation commands</h3>
  <p>{validation_commands}</p>
  <p>Run these after human review artifacts are returned or solo-maintainer review actions are recorded. Viewing this page does not change accepted frontier state.</p>
</section>"#,
        frontier_id = escape_html(&payload.frontier_id),
        total_open = payload.total_open,
        review_queue_count = review_queue_count,
        proof_label = escape_html(proof_label),
        evidence_ci_summary = escape_html(&format!(
            "{} fail / {} warn",
            health.metrics.evidence_ci_failures, health.metrics.evidence_ci_warnings
        )),
        release_asset_count = release_asset_count,
        proof_status = escape_html(&payload.proof_status),
        stale_proof = health.metrics.stale_proof,
        source_total = source_summary.total,
        source_quarantined = source_summary.quarantined,
        source_retracted = source_summary.retracted,
        source_task_linked = source_summary.task_linked,
        source_stale = source_summary.stale,
        source_rejected = source_summary.rejected_imports,
        task_total = task_summary.total,
        task_active = task_summary.active,
        task_blocked = task_summary.blocked,
        task_review = task_summary.awaiting_review,
        task_terminal = task_summary.terminal,
        evidence_failures = health.metrics.evidence_ci_failures,
        evidence_warnings = health.metrics.evidence_ci_warnings,
        benchmark_replay_rows = benchmark_replay_rows,
        queue_rows = queue_rows,
        validation_commands = validation_commands,
    );
    Html(shell(
        "review-cockpit",
        "Daily review cockpit · Vela Workbench",
        "Workbench",
        "Daily review cockpit",
        &body,
    ))
    .into_response()
}

async fn page_review_work(State(state): State<AppState>) -> Response {
    let payload = match build_review_work_payload(&state.repo_path) {
        Ok(payload) => payload,
        Err(e) => return error_page("review work", "Could not load review work queues", &e),
    };
    let rows = payload
        .queues
        .iter()
        .map(render_review_work_row)
        .collect::<Vec<_>>()
        .join("");
    let validation_commands = payload
        .validation_commands
        .iter()
        .map(|cmd| format!("<code>{}</code>", escape_html(cmd)))
        .collect::<Vec<_>>()
        .join(" · ");
    let proposal_preview_commands = payload
        .action_queue_submit
        .proposal_preview_commands
        .iter()
        .map(|cmd| format!("<code>{}</code>", escape_html(cmd)))
        .collect::<Vec<_>>()
        .join(" · ");
    let explicit_reviewer_actions = payload
        .action_queue_submit
        .explicit_reviewer_actions
        .iter()
        .map(|cmd| format!("<code>{}</code>", escape_html(cmd)))
        .collect::<Vec<_>>()
        .join(" · ");
    let graph_artifacts = payload
        .frontier_graph
        .graph_artifacts
        .iter()
        .map(|artifact| format!("<code>{}</code>", escape_html(artifact)))
        .collect::<Vec<_>>()
        .join(" · ");
    let graph_commands = payload
        .frontier_graph
        .copy_commands
        .iter()
        .map(|cmd| format!("<code>{}</code>", escape_html(cmd)))
        .collect::<Vec<_>>()
        .join(" · ");
    let benchmark_artifacts = payload
        .benchmark_mode
        .benchmark_artifacts
        .iter()
        .map(|artifact| format!("<code>{}</code>", escape_html(artifact)))
        .collect::<Vec<_>>()
        .join(" · ");
    let benchmark_commands = payload
        .benchmark_mode
        .copy_commands
        .iter()
        .map(|cmd| format!("<code>{}</code>", escape_html(cmd)))
        .collect::<Vec<_>>()
        .join(" · ");
    let index_counts = render_index_counts(&payload.frontier_index.counts);
    let index_commands = render_review_work_owned_commands(&payload.frontier_index.copy_commands);
    let queue_count = |lane_id: &str| {
        payload
            .queues
            .iter()
            .find(|queue| queue.lane_id == lane_id)
            .map(|queue| queue.count)
            .unwrap_or(0)
    };

    let body = format!(
        r#"<section class="wb-hero" aria-label="Review work queues">
  <div class="wb-hero__grid">
    <div>
      <h2>Review work queues</h2>
      <p>This page is read-only. It gathers reviewer-facing blockers from source records, entity flags, proposals, Diff Packs, task state, and outside-review files. Viewing it does not count as review and does not mutate frontier state.</p>
      <div class="wb-action-row">
        <a class="wb-button" href="/review/inbox">Open review inbox</a>
        <a class="wb-button wb-button--quiet" href="/tasks">Open tasks</a>
        <a class="wb-button wb-button--quiet" href="/source-inbox">Open source inbox</a>
        <a class="wb-button wb-button--quiet" href="/diff-packs">Open Diff Packs</a>
        <a class="wb-button wb-button--quiet" href="/review/work.json">Open JSON</a>
      </div>
    </div>
    <div class="wb-status-panel" aria-label="Review work summary">
      <div><span>Frontier</span><strong>{frontier_id}</strong></div>
      <div><span>Open rows</span><strong>{total_open}</strong></div>
      <div><span>Source review</span><strong>{source_count}</strong></div>
      <div><span>Proposal review</span><strong>{proposal_count}</strong></div>
      <div><span>Task closure</span><strong>{task_count}</strong></div>
      <div><span>Proof packet</span><strong>{proof_status}</strong></div>
    </div>
  </div>
</section>
<div class="wb-card">
  <h3>Queue summary</h3>
  <table class="wb-table">
    <thead><tr><th>queue</th><th>count</th><th>examples</th><th>operator artifacts</th><th>validators</th><th>boundary</th><th>next step</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div>
<div class="wb-card">
  <h3>Validation commands</h3>
  <p>{validation_commands}</p>
  <p>Run these after human review artifacts are actually returned. This page only reports the current queue.</p>
</div>
<div class="wb-card">
  <h3>{index_title}</h3>
  <p>Workbench reads index counts when the rebuildable database is present. If the database is missing, it falls back to canonical frontier files.</p>
  <dl class="wb-meta">
    <dt>present</dt><dd>{index_present}</dd>
    <dt>source</dt><dd>{index_source}</dd>
    <dt>database is authority</dt><dd>{index_database_is_authority}</dd>
    <dt>canonical state</dt><dd>{index_canonical_state}</dd>
    <dt>fallback counts from files</dt><dd>{index_fallback}</dd>
  </dl>
  <p>{index_counts}</p>
  <p>{index_commands}</p>
  <p>{index_boundary}</p>
</div>
<div class="wb-card">
  <h3>Action queue submit path</h3>
  <p><code>review/frontier-action-queue.v1.json</code> carries local commands for <strong>Submit as reviewable state</strong>. Each submit descriptor names <code>reviewer:solo-maintainer</code>, creates proposal or review-event state, and does not silently accept agent output.</p>
  <h4>Proposal preview commands</h4>
  <p>{proposal_preview_commands}</p>
  <h4>Explicit reviewer actions</h4>
  <p>{explicit_reviewer_actions}</p>
  <p>{submit_boundary}</p>
</div>
<div class="wb-card">
  <h3>Frontier graph navigation</h3>
  <p>Graph neighborhoods are derived review material. They help locate source debt, proof packet files, guided tours, and impact paths. The workbench exposes copy commands only and does not mutate frontier state.</p>
  <h4>Graph artifacts</h4>
  <p>{graph_artifacts}</p>
  <h4>Graph neighborhoods</h4>
  <p>{graph_commands}</p>
  <p>{graph_boundary}</p>
</div>
<div class="wb-card">
  <h3>{benchmark_title}</h3>
  <p>Use these local artifacts to inspect graph-backed answers, the matched paper-RAG baseline, the blind scoring pack, and the local error analysis. The page exposes copy benchmark commands only.</p>
  <h4>Benchmark artifacts</h4>
  <p>{benchmark_artifacts}</p>
  <h4>Benchmark commands</h4>
  <p>{benchmark_commands}</p>
  <p>{benchmark_boundary}</p>
</div>"#,
        frontier_id = escape_html(&payload.frontier_id),
        total_open = payload.total_open,
        source_count = queue_count("source_review"),
        proposal_count = queue_count("proposal_review"),
        task_count = queue_count("task_closure"),
        proof_status = escape_html(&payload.proof_status),
        rows = rows,
        validation_commands = validation_commands,
        index_title = escape_html(payload.frontier_index.title),
        index_present = payload.frontier_index.present,
        index_source = escape_html(payload.frontier_index.source),
        index_database_is_authority = payload.frontier_index.database_is_authority,
        index_canonical_state = escape_html(payload.frontier_index.canonical_state),
        index_fallback = payload.frontier_index.fallback_counts_from_files,
        index_counts = index_counts,
        index_commands = index_commands,
        index_boundary = escape_html(payload.frontier_index.boundary),
        proposal_preview_commands = proposal_preview_commands,
        explicit_reviewer_actions = explicit_reviewer_actions,
        submit_boundary = escape_html(payload.action_queue_submit.boundary),
        graph_artifacts = graph_artifacts,
        graph_commands = graph_commands,
        graph_boundary = escape_html(payload.frontier_graph.boundary),
        benchmark_title = escape_html(payload.benchmark_mode.title),
        benchmark_artifacts = benchmark_artifacts,
        benchmark_commands = benchmark_commands,
        benchmark_boundary = escape_html(payload.benchmark_mode.boundary),
    );
    Html(shell(
        "review-work",
        "Review work · Vela Workbench",
        "Workbench",
        "Review work queues",
        &body,
    ))
    .into_response()
}

async fn page_review_work_json(State(state): State<AppState>) -> Response {
    match build_review_work_payload(&state.repo_path) {
        Ok(payload) => Json(payload).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "schema": "vela.workbench.review_work_error.v0.1",
                "ok": false,
                "error": e,
            })),
        )
            .into_response(),
    }
}

fn first_user_demo_payload(repo_path: &Path) -> serde_json::Value {
    serde_json::json!({
        "schema": "vela.workbench.first_user_demo.v0.1",
        "title": "First-user demo",
        "frontier_path": repo_path.display().to_string(),
        "read_only": true,
        "counts_as_review": false,
        "mutates_frontier": false,
        "artifacts": [
            "dist/outsider-review-demo/manifest.v1.json",
            "dist/outsider-review-demo/README.md",
            "benchmarks/frontier-graph-navigation.v1.json",
            "benchmarks/frontier-graph-navigation-answers.v1.json",
            "benchmarks/frontier-graph-navigation-paper-rag-baseline.v1.json",
            "benchmarks/frontier-graph-blind-scoring-pack.v1.json",
            "docs/GRAPH_NATIVE_BENCHMARK_PUBLIC_DEMO_AUDIT_v0.488.md",
            "projects/anti-amyloid-translation/proof/manifest.json"
        ],
        "steps": [
            {
                "id": "start_here",
                "label": "start here",
                "href": "/demo/first-user",
                "command": "sed -n '1,180p' dist/outsider-review-demo/README.md"
            },
            {
                "id": "review_work",
                "label": "review work",
                "href": "/review/work",
                "command": "jq '.summary, .claim_boundary' dist/outsider-review-demo/manifest.v1.json"
            },
            {
                "id": "proof",
                "label": "proof packet",
                "href": "/proof",
                "command": "jq '.summary // ., .claim_boundary // empty' projects/anti-amyloid-translation/proof/manifest.json"
            },
            {
                "id": "decision",
                "label": "decision brief",
                "href": "/decision",
                "command": "jq '.questions[] | {id, state, supporting_findings, gap_findings}' projects/anti-amyloid-translation/decision/decision-brief.v1.json"
            },
            {
                "id": "benchmark",
                "label": "benchmark packet",
                "href": "/review/work",
                "command": "jq '.cases[] | {case_id, arms: [.arms[].blind_id]}' benchmarks/frontier-graph-blind-scoring-pack.v1.json"
            }
        ],
        "claim_boundary": {
            "local_demo_only": true,
            "claims_external_validation": false,
            "claims_external_adoption": false,
            "claims_scientific_discovery": false,
            "claims_target_validation": false,
            "claims_treatment_advice": false,
            "tracked_frontier_mutated": false
        },
        "boundary_text": "read_only=true; counts_as_review=false; mutates_frontier=false; claims_external_validation=false"
    })
}

async fn page_first_user_demo(State(state): State<AppState>) -> Response {
    let payload = first_user_demo_payload(&state.repo_path);
    let steps = payload
        .get("steps")
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_default();
    let rows = steps
        .iter()
        .map(|step| {
            let label = step.get("label").and_then(|v| v.as_str()).unwrap_or("step");
            let href = step.get("href").and_then(|v| v.as_str()).unwrap_or("/");
            let command = step
                .get("command")
                .and_then(|v| v.as_str())
                .unwrap_or("none");
            format!(
                r#"<tr><td>{label}</td><td><a href="{href}">{href}</a></td><td><code>{command}</code></td></tr>"#,
                label = escape_html(label),
                href = escape_html(href),
                command = escape_html(command)
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let artifacts = payload
        .get("artifacts")
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|value| value.as_str())
        .map(|artifact| format!("<code>{}</code>", escape_html(artifact)))
        .collect::<Vec<_>>()
        .join(" · ");
    let body = format!(
        r#"<section class="wb-hero" aria-label="First-user demo">
  <div class="wb-hero__grid">
    <div>
      <h2>First-user demo</h2>
      <p>This read-only page gives a first reviewer the path through the outsider demo, review work, proof packet, decision brief, and benchmark packet.</p>
      <div class="wb-action-row">
        <a class="wb-button" href="/review/work">Open review work</a>
        <a class="wb-button wb-button--quiet" href="/proof">Open proof</a>
        <a class="wb-button wb-button--quiet" href="/decision">Open decision brief</a>
        <a class="wb-button wb-button--quiet" href="/demo/first-user.json">Open JSON</a>
      </div>
    </div>
    <div class="wb-status-panel" aria-label="First-user demo boundary">
      <div><span>read_only</span><strong>true</strong></div>
      <div><span>counts_as_review</span><strong>false</strong></div>
      <div><span>claims_external_validation</span><strong>false</strong></div>
    </div>
  </div>
</section>
<div class="wb-card">
  <h3>Demo steps</h3>
  <table class="wb-table">
    <thead><tr><th>step</th><th>surface</th><th>copy command</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div>
<div class="wb-card">
  <h3>Demo artifacts</h3>
  <p>{artifacts}</p>
  <p>Boundary: read_only=true; counts_as_review=false; mutates_frontier=false; claims_external_validation=false.</p>
</div>"#,
        rows = rows,
        artifacts = artifacts,
    );
    Html(shell(
        "first-user-demo",
        "First-user demo · Vela Workbench",
        "Workbench",
        "First-user demo",
        &body,
    ))
    .into_response()
}

async fn page_first_user_demo_json(State(state): State<AppState>) -> Response {
    Json(first_user_demo_payload(&state.repo_path)).into_response()
}

fn score_return_preview_payload(repo_path: &Path) -> serde_json::Value {
    serde_json::json!({
        "schema": "vela.workbench.score_return_preview.v0.1",
        "title": "Score-return preview",
        "frontier_path": repo_path.display().to_string(),
        "read_only": true,
        "review_status": "source_material",
        "input_artifact": "benchmarks/public/score-returns/inbox/external-score-return.import-preview.v1.json",
        "source_template": "benchmarks/public/score-returns/external-scorer-return.template.v3.json",
        "task_reference": "benchmarks/public/external-scorer-packet.v3.json",
        "validation_status": {
            "artifact": "benchmarks/public/score-returns/inbox/external-score-return.import-preview.v1.json",
            "expected_schema": "vela.graph_benchmark_score_return_import_preview.v0.1",
            "preview_only": true
        },
        "task_counts": {
            "expected_cases": 5,
            "expected_arms_per_case": 2,
            "expected_dimensions": 4
        },
        "mutation_boundary": {
            "writes_review_events": false,
            "accepts_frontier_state": false,
            "writes_frontier_state": false
        },
        "claim_boundary": {
            "claims_external_validation": false,
            "claims_general_benchmark_outperformance": false,
            "claims_scientific_discovery": false,
            "claims_target_validation": false,
            "claims_treatment_advice": false
        },
        "boundary_text": "writes_review_events=false; accepts_frontier_state=false; writes_frontier_state=false; claims_external_validation=false",
        "next_actions": [
            {
                "id": "validate",
                "label": "validate return",
                "command": "scripts/import-graph-benchmark-score-return-v4.py benchmarks/public/score-returns/external-scorer-return.template.v3.json --out benchmarks/public/score-returns/inbox/external-score-return.import-preview.v1.json"
            },
            {
                "id": "inspect",
                "label": "inspect preview",
                "command": "jq '.validation, .mutation_boundary' benchmarks/public/score-returns/inbox/external-score-return.import-preview.v1.json"
            },
            {
                "id": "adjudicate_later",
                "label": "adjudicate later",
                "command": "do not write review events from this preview"
            }
        ]
    })
}

async fn page_score_return_preview(State(state): State<AppState>) -> Response {
    let payload = score_return_preview_payload(&state.repo_path);
    let actions = payload
        .get("next_actions")
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|action| {
            let label = action
                .get("label")
                .and_then(|value| value.as_str())
                .unwrap_or("action");
            let command = action
                .get("command")
                .and_then(|value| value.as_str())
                .unwrap_or("none");
            format!(
                r#"<tr><td>{label}</td><td><code>{command}</code></td></tr>"#,
                label = escape_html(label),
                command = escape_html(command)
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let body = format!(
        r#"<section class="wb-hero" aria-label="Score-return preview">
  <div class="wb-hero__grid">
    <div>
      <h2>Score-return preview</h2>
      <p>This read-only page shows the imported scorer return as source material. It is a validation preview, not an accepted review event.</p>
      <div class="wb-action-row">
        <a class="wb-button" href="/demo/score-return.json">Open JSON</a>
        <a class="wb-button wb-button--quiet" href="/demo/first-user">First-user demo</a>
        <a class="wb-button wb-button--quiet" href="/review/work">Review work</a>
      </div>
    </div>
    <div class="wb-status-panel" aria-label="Score-return mutation boundary">
      <div><span>writes_review_events</span><strong>false</strong></div>
      <div><span>accepts_frontier_state</span><strong>false</strong></div>
      <div><span>review_status</span><strong>source_material</strong></div>
    </div>
  </div>
</section>
<div class="wb-card">
  <h3>Preview artifacts</h3>
  <p><code>benchmarks/public/score-returns/inbox/external-score-return.import-preview.v1.json</code></p>
  <p><code>benchmarks/public/score-returns/external-scorer-return.template.v3.json</code></p>
  <p>Boundary: writes_review_events=false; accepts_frontier_state=false; writes_frontier_state=false; claims_external_validation=false.</p>
</div>
<div class="wb-card">
  <h3>Next actions</h3>
  <table class="wb-table">
    <thead><tr><th>action</th><th>command</th></tr></thead>
    <tbody>{actions}</tbody>
  </table>
</div>"#,
        actions = actions,
    );
    Html(shell(
        "score-return-preview",
        "Score-return preview · Vela Workbench",
        "Workbench",
        "Score-return preview",
        &body,
    ))
    .into_response()
}

async fn page_score_return_preview_json(State(state): State<AppState>) -> Response {
    Json(score_return_preview_payload(&state.repo_path)).into_response()
}

fn external_review_return_entries(repo_path: &Path) -> Vec<serde_json::Value> {
    let returned_dir = workspace_root_for(repo_path).join("dist/external-review/returned");
    let mut entries = fs::read_dir(returned_dir)
        .ok()
        .into_iter()
        .flat_map(|entries| entries.filter_map(Result::ok))
        .filter_map(|entry| {
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                return None;
            }
            let rel_path = path
                .strip_prefix(workspace_root_for(repo_path))
                .ok()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| path.display().to_string());
            let value = fs::read_to_string(&path)
                .ok()
                .and_then(|body| serde_json::from_str::<serde_json::Value>(&body).ok())?;
            let task_reviews = value
                .get("task_reviews")
                .and_then(serde_json::Value::as_array)
                .map(Vec::len)
                .unwrap_or(0);
            let friction_items = value
                .get("friction_log")
                .and_then(serde_json::Value::as_array)
                .map(Vec::len)
                .unwrap_or(0);
            Some(serde_json::json!({
                "path": rel_path,
                "schema": value.get("schema").and_then(serde_json::Value::as_str).unwrap_or("unknown"),
                "return_kind": value.get("return_kind").and_then(serde_json::Value::as_str).unwrap_or("unknown"),
                "reviewer_id": value.get("reviewer_id").and_then(serde_json::Value::as_str).unwrap_or(""),
                "task_reviews": task_reviews,
                "friction_items": friction_items
            }))
        })
        .collect::<Vec<_>>();
    entries.sort_by(|a, b| {
        a.get("path")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .cmp(
                b.get("path")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or(""),
            )
    });
    entries
}

fn external_review_packet_payload(repo_path: &Path) -> serde_json::Value {
    let packet_path = "dist/external-review/frontier-review-packet.v1.json";
    let template_path = "dist/external-review/frontier-review-return.template.v1.json";
    let returned_dir = "dist/external-review/returned";
    let packet = load_workspace_json(repo_path, packet_path);
    let template = load_workspace_json(repo_path, template_path);
    let returned = external_review_return_entries(repo_path);
    let real_external_returns = returned
        .iter()
        .filter(|entry| {
            entry.get("return_kind").and_then(serde_json::Value::as_str) == Some("real_external")
        })
        .count();
    let local_rehearsals = returned
        .iter()
        .filter(|entry| {
            entry.get("return_kind").and_then(serde_json::Value::as_str) == Some("local_rehearsal")
        })
        .count();
    let task_count = packet
        .as_ref()
        .and_then(|value| value.get("tasks"))
        .and_then(serde_json::Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    let template_task_reviews = template
        .as_ref()
        .and_then(|value| value.get("task_reviews"))
        .and_then(serde_json::Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    serde_json::json!({
        "schema": "vela.workbench.frontier_review_external.v0.1",
        "title": "External review packet",
        "frontier_path": repo_path.display().to_string(),
        "read_only": true,
        "review_status": "source_material",
        "external_validation_status": if real_external_returns > 0 { "returned_material_present" } else { "absent" },
        "artifacts": {
            "packet": {
                "path": packet_path,
                "present": packet.is_some(),
                "schema": packet.as_ref().and_then(|value| value.get("schema")).and_then(serde_json::Value::as_str).unwrap_or("missing"),
                "task_count": task_count,
                "answer_keys_included": packet.as_ref().and_then(|value| value.get("claim_boundary")).and_then(|boundary| boundary.get("answer_keys_included")).and_then(serde_json::Value::as_bool).unwrap_or(false)
            },
            "return_template": {
                "path": template_path,
                "present": template.is_some(),
                "schema": template.as_ref().and_then(|value| value.get("schema")).and_then(serde_json::Value::as_str).unwrap_or("missing"),
                "task_reviews": template_task_reviews
            },
            "returned_dir": returned_dir
        },
        "return_summary": {
            "returned_files": returned.len(),
            "real_external_returns": real_external_returns,
            "local_rehearsals": local_rehearsals
        },
        "returned_files": returned,
        "mutation_boundary": {
            "writes_review_events": false,
            "accepts_frontier_state": false,
            "writes_frontier_state": false
        },
        "claim_boundary": {
            "claims_external_validation": false,
            "claims_external_review_completed": false,
            "claims_benchmark_outperformance": false,
            "claims_scientific_discovery": false,
            "claims_target_validation": false,
            "claims_treatment_advice": false
        },
        "next_actions": [
            {
                "id": "build_packet",
                "label": "build packet",
                "command": "./scripts/build-frontier-review-external-packet-v1.py"
            },
            {
                "id": "validate_template",
                "label": "validate blank template",
                "command": "./scripts/validate-frontier-review-external-return-v1.py dist/external-review/frontier-review-return.template.v1.json --json"
            },
            {
                "id": "validate_return",
                "label": "validate returned file",
                "command": "./scripts/validate-frontier-review-external-return-v1.py dist/external-review/returned/<return.json> --json"
            },
            {
                "id": "import_preview",
                "label": "build import preview",
                "command": "./scripts/import-frontier-review-external-return-v1.py dist/external-review/returned/<return.json> --out /tmp/frontier-review-import-preview.json"
            }
        ],
        "boundary_text": "read_only=true; writes_review_events=false; accepts_frontier_state=false; claims_external_validation=false"
    })
}

async fn page_external_review_packet(State(state): State<AppState>) -> Response {
    let payload = external_review_packet_payload(&state.repo_path);
    let actions = payload
        .get("next_actions")
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|action| {
            let label = action
                .get("label")
                .and_then(|value| value.as_str())
                .unwrap_or("action");
            let command = action
                .get("command")
                .and_then(|value| value.as_str())
                .unwrap_or("none");
            format!(
                r#"<tr><td>{label}</td><td><code>{command}</code></td></tr>"#,
                label = escape_html(label),
                command = escape_html(command)
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let returned_rows = payload
        .get("returned_files")
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|entry| {
            let path = entry
                .get("path")
                .and_then(|value| value.as_str())
                .unwrap_or("unknown");
            let kind = entry
                .get("return_kind")
                .and_then(|value| value.as_str())
                .unwrap_or("unknown");
            let reviewer = entry
                .get("reviewer_id")
                .and_then(|value| value.as_str())
                .unwrap_or("");
            let reviews = entry
                .get("task_reviews")
                .and_then(|value| value.as_u64())
                .unwrap_or(0);
            let friction = entry
                .get("friction_items")
                .and_then(|value| value.as_u64())
                .unwrap_or(0);
            format!(
                r#"<tr><td><code>{path}</code></td><td>{kind}</td><td>{reviewer}</td><td>{reviews}</td><td>{friction}</td></tr>"#,
                path = escape_html(path),
                kind = escape_html(kind),
                reviewer = escape_html(reviewer),
                reviews = reviews,
                friction = friction
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let returned_rows = if returned_rows.is_empty() {
        r#"<tr><td colspan="5">No returned JSON files found under <code>dist/external-review/returned</code>.</td></tr>"#.to_string()
    } else {
        returned_rows
    };
    let artifacts = payload.get("artifacts").unwrap_or(&serde_json::Value::Null);
    let packet = artifacts.get("packet").unwrap_or(&serde_json::Value::Null);
    let template = artifacts
        .get("return_template")
        .unwrap_or(&serde_json::Value::Null);
    let summary = payload
        .get("return_summary")
        .unwrap_or(&serde_json::Value::Null);
    let task_count = packet
        .get("task_count")
        .and_then(|value| value.as_u64())
        .unwrap_or(0);
    let template_reviews = template
        .get("task_reviews")
        .and_then(|value| value.as_u64())
        .unwrap_or(0);
    let returned_count = summary
        .get("returned_files")
        .and_then(|value| value.as_u64())
        .unwrap_or(0);
    let real_returns = summary
        .get("real_external_returns")
        .and_then(|value| value.as_u64())
        .unwrap_or(0);
    let body = format!(
        r#"<section class="wb-hero" aria-label="External review packet">
  <div class="wb-hero__grid">
    <div>
      <h2>External review packet</h2>
      <p>This read-only page inspects the frontier-review packet, return template, and returned review files. Returns are source material until validated, imported as draft events, and accepted by a maintainer.</p>
      <div class="wb-action-row">
        <a class="wb-button" href="/demo/external-review.json">Open JSON</a>
        <a class="wb-button wb-button--quiet" href="/demo/score-return">Score-return preview</a>
        <a class="wb-button wb-button--quiet" href="/demo/adjudication">Adjudication</a>
        <a class="wb-button wb-button--quiet" href="/review/work">Review work</a>
      </div>
    </div>
    <div class="wb-status-panel" aria-label="External review boundary">
      <div><span>packet tasks</span><strong>{task_count}</strong></div>
      <div><span>template rows</span><strong>{template_reviews}</strong></div>
      <div><span>returned files</span><strong>{returned_count}</strong></div>
      <div><span>real external returns</span><strong>{real_returns}</strong></div>
      <div><span>writes_review_events</span><strong>false</strong></div>
      <div><span>claims_external_validation</span><strong>false</strong></div>
    </div>
  </div>
</section>
<div class="wb-card">
  <h3>Artifacts</h3>
  <p><code>dist/external-review/frontier-review-packet.v1.json</code></p>
  <p><code>dist/external-review/frontier-review-return.template.v1.json</code></p>
  <p><code>dist/external-review/returned</code></p>
  <p>Boundary: read_only=true; writes_review_events=false; accepts_frontier_state=false; claims_external_validation=false.</p>
</div>
<div class="wb-card">
  <h3>Returned files</h3>
  <table class="wb-table">
    <thead><tr><th>file</th><th>kind</th><th>reviewer</th><th>task reviews</th><th>friction</th></tr></thead>
    <tbody>{returned_rows}</tbody>
  </table>
</div>
<div class="wb-card">
  <h3>Copy commands</h3>
  <table class="wb-table">
    <thead><tr><th>action</th><th>command</th></tr></thead>
    <tbody>{actions}</tbody>
  </table>
</div>"#,
        task_count = task_count,
        template_reviews = template_reviews,
        returned_count = returned_count,
        real_returns = real_returns,
        returned_rows = returned_rows,
        actions = actions,
    );
    Html(shell(
        "external-review",
        "External review packet · Vela Workbench",
        "Workbench",
        "External review packet",
        &body,
    ))
    .into_response()
}

async fn page_external_review_packet_json(State(state): State<AppState>) -> Response {
    Json(external_review_packet_payload(&state.repo_path)).into_response()
}

fn external_proof_loop_return_entries(repo_path: &Path) -> Vec<serde_json::Value> {
    let root = workspace_root_for(repo_path).join("dist/external-proof-loop/returned");
    let mut pending = vec![root.clone()];
    let mut entries = Vec::new();
    while let Some(dir) = pending.pop() {
        let Ok(read_dir) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in read_dir.filter_map(Result::ok) {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let rel_path = path
                .strip_prefix(workspace_root_for(repo_path))
                .ok()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| path.display().to_string());
            let value = match fs::read_to_string(&path)
                .ok()
                .and_then(|body| serde_json::from_str::<serde_json::Value>(&body).ok())
            {
                Some(value) => value,
                None => continue,
            };
            let returner = value
                .get("scorer_id")
                .or_else(|| value.get("reviewer_id"))
                .or_else(|| value.get("returner_id"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            let task_scores = value
                .get("task_scores")
                .and_then(serde_json::Value::as_array)
                .map(Vec::len)
                .unwrap_or(0);
            let task_reviews = value
                .get("task_reviews")
                .and_then(serde_json::Value::as_array)
                .map(Vec::len)
                .unwrap_or(0);
            let friction_items = value
                .get("friction_log")
                .or_else(|| value.get("overall_friction"))
                .or_else(|| value.get("items"))
                .and_then(serde_json::Value::as_array)
                .map(Vec::len)
                .unwrap_or(0);
            entries.push(serde_json::json!({
                "path": rel_path,
                "schema": value.get("schema").and_then(serde_json::Value::as_str).unwrap_or("unknown"),
                "return_kind": value.get("return_kind").and_then(serde_json::Value::as_str).unwrap_or("unknown"),
                "returner_id": returner,
                "task_scores": task_scores,
                "task_reviews": task_reviews,
                "friction_items": friction_items
            }));
        }
    }
    entries.sort_by(|a, b| {
        a.get("path")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .cmp(
                b.get("path")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or(""),
            )
    });
    entries
}

fn external_proof_loop_payload(repo_path: &Path) -> serde_json::Value {
    let manifest_path = "dist/external-proof-loop/manifest.v1.json";
    let scorer_pack_path = "benchmarks/public/blind-scorer-pack.v1.json";
    let protocol_pack_path = "dist/protocol-compatibility/manifest.v1.json";
    let validation_path =
        "dist/external-proof-loop/validation/solo-maintainer-return-validation.v1.json";
    let manifest = load_workspace_json(repo_path, manifest_path);
    let scorer_pack = load_workspace_json(repo_path, scorer_pack_path);
    let protocol_pack = load_workspace_json(repo_path, protocol_pack_path);
    let validation_summary = load_workspace_json(repo_path, validation_path);
    let returned = external_proof_loop_return_entries(repo_path);
    let validation_previews = validation_summary
        .as_ref()
        .and_then(|value| value.get("import_previews"))
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let returned_evidence = validation_summary
        .as_ref()
        .and_then(|value| value.get("validations"))
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|validation| {
            let source = validation
                .get("source")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            let source_rel = source
                .split("dist/external-proof-loop/")
                .last()
                .map(|tail| format!("dist/external-proof-loop/{tail}"))
                .unwrap_or_else(|| source.to_string());
            let preview = validation_previews.iter().find(|preview| {
                preview
                    .get("source")
                    .and_then(serde_json::Value::as_str)
                    .map(|preview_source| source.ends_with(preview_source))
                    .unwrap_or(false)
            });
            let summary = validation
                .get("summary")
                .unwrap_or(&serde_json::Value::Null);
            serde_json::json!({
                "source": source_rel,
                "return_class": validation.get("return_class").and_then(serde_json::Value::as_str).unwrap_or("unknown"),
                "validation_ok": validation.get("ok").and_then(serde_json::Value::as_bool).unwrap_or(false),
                "task_scores": summary.get("task_scores").and_then(serde_json::Value::as_u64).unwrap_or(0),
                "task_reviews": summary.get("task_reviews").and_then(serde_json::Value::as_u64).unwrap_or(0),
                "friction_items": summary.get("friction_items").and_then(serde_json::Value::as_u64).unwrap_or(0),
                "import_preview": preview.and_then(|value| value.get("path")).and_then(serde_json::Value::as_str).unwrap_or(""),
                "draft_scores": preview.and_then(|value| value.get("draft_scores")).and_then(serde_json::Value::as_u64).unwrap_or(0),
                "draft_review_events": preview.and_then(|value| value.get("draft_review_events")).and_then(serde_json::Value::as_u64).unwrap_or(0),
                "writes_frontier_state": preview.and_then(|value| value.get("writes_frontier_state")).and_then(serde_json::Value::as_bool).unwrap_or(false)
            })
        })
        .collect::<Vec<_>>();
    let real_returns = returned
        .iter()
        .filter(|entry| {
            matches!(
                entry
                    .get("return_kind")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or(""),
                "scored_return" | "review_return" | "real_external"
            )
        })
        .count();
    let local_rehearsals = returned
        .iter()
        .filter(|entry| {
            entry.get("return_kind").and_then(serde_json::Value::as_str) == Some("local_rehearsal")
        })
        .count();
    let blind_tasks = scorer_pack
        .as_ref()
        .and_then(|value| value.get("tasks"))
        .and_then(serde_json::Value::as_array)
        .map(Vec::len)
        .unwrap_or_else(|| {
            manifest
                .as_ref()
                .and_then(|value| value.get("summary"))
                .and_then(|summary| summary.get("blind_scorer_tasks"))
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0) as usize
        });
    serde_json::json!({
        "schema": "vela.workbench.external_proof_loop.v0.1",
        "title": "External proof loop",
        "frontier_path": repo_path.display().to_string(),
        "read_only": true,
        "review_status": "source_material",
        "external_validation_status": "absent",
        "artifacts": {
            "manifest": {
                "path": manifest_path,
                "present": manifest.is_some(),
                "schema": manifest.as_ref().and_then(|value| value.get("schema")).and_then(serde_json::Value::as_str).unwrap_or("missing")
            },
            "blind_scorer_pack": {
                "path": scorer_pack_path,
                "present": scorer_pack.is_some(),
                "task_count": blind_tasks,
                "answer_keys_included": scorer_pack.as_ref().and_then(|value| value.get("claim_boundary")).and_then(|boundary| boundary.get("answer_key_refs_included")).and_then(serde_json::Value::as_bool).unwrap_or(false)
            },
            "protocol_compatibility": {
                "path": protocol_pack_path,
                "present": protocol_pack.is_some(),
                "schema": protocol_pack.as_ref().and_then(|value| value.get("schema")).and_then(serde_json::Value::as_str).unwrap_or("missing")
            },
            "validation_summary": {
                "path": validation_path,
                "present": validation_summary.is_some(),
                "schema": validation_summary.as_ref().and_then(|value| value.get("schema")).and_then(serde_json::Value::as_str).unwrap_or("missing")
            },
            "returned_dir": "dist/external-proof-loop/returned"
        },
        "return_summary": {
            "returned_files": returned.len(),
            "real_returns": real_returns,
            "local_rehearsals": local_rehearsals,
            "valid_returns": validation_summary.as_ref().and_then(|value| value.get("summary")).and_then(|summary| summary.get("valid_returns")).and_then(serde_json::Value::as_u64).unwrap_or(0),
            "import_previews": validation_summary.as_ref().and_then(|value| value.get("summary")).and_then(|summary| summary.get("import_previews")).and_then(serde_json::Value::as_u64).unwrap_or(0),
            "draft_scores": validation_summary.as_ref().and_then(|value| value.get("summary")).and_then(|summary| summary.get("draft_scores")).and_then(serde_json::Value::as_u64).unwrap_or(0),
            "draft_review_events": validation_summary.as_ref().and_then(|value| value.get("summary")).and_then(|summary| summary.get("draft_review_events")).and_then(serde_json::Value::as_u64).unwrap_or(0)
        },
        "returned_files": returned,
        "returned_evidence": returned_evidence,
        "next_actions": [
            {
                "id": "build_external_loop",
                "label": "build external loop",
                "command": "./scripts/build-external-proof-loop-pack-v1.py"
            },
            {
                "id": "validate_return",
                "label": "validate returned material",
                "command": "./scripts/validate-external-proof-loop-return-v1.py dist/external-proof-loop/returned/<return.json> --json"
            },
            {
                "id": "import_preview",
                "label": "build import preview",
                "command": "./scripts/import-external-proof-loop-return-v1.py dist/external-proof-loop/returned/<return.json> --out /tmp/vela-external-proof-import --json"
            },
            {
                "id": "audit_answer_keys",
                "label": "audit answer-key isolation",
                "command": "./scripts/audit-answer-key-isolation-v1.py --json"
            }
        ],
        "mutation_boundary": {
            "writes_review_events": false,
            "accepts_frontier_state": false,
            "writes_frontier_state": false
        },
        "claim_boundary": {
            "returned_material_is_source_material": true,
            "claims_external_validation": false,
            "claims_benchmark_outperformance": false,
            "claims_clinical_validity": false,
            "claims_scientific_discovery": false,
            "claims_target_validation": false,
            "claims_treatment_advice": false,
            "claims_institutional_adoption": false,
            "claims_release_clean": false
        },
        "boundary_text": "read_only=true; returned_material_is_source_material=true; writes_review_events=false; accepts_frontier_state=false; claims_external_validation=false"
    })
}

async fn page_external_proof_loop(State(state): State<AppState>) -> Response {
    let payload = external_proof_loop_payload(&state.repo_path);
    let actions = payload
        .get("next_actions")
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|action| {
            let label = action
                .get("label")
                .and_then(|value| value.as_str())
                .unwrap_or("action");
            let command = action
                .get("command")
                .and_then(|value| value.as_str())
                .unwrap_or("none");
            format!(
                r#"<tr><td>{label}</td><td><code>{command}</code></td></tr>"#,
                label = escape_html(label),
                command = escape_html(command)
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let returned_rows = payload
        .get("returned_files")
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|entry| {
            let path = entry
                .get("path")
                .and_then(|value| value.as_str())
                .unwrap_or("unknown");
            let kind = entry
                .get("return_kind")
                .and_then(|value| value.as_str())
                .unwrap_or("unknown");
            let returner = entry
                .get("returner_id")
                .and_then(|value| value.as_str())
                .unwrap_or("");
            let scores = entry
                .get("task_scores")
                .and_then(|value| value.as_u64())
                .unwrap_or(0);
            let friction = entry
                .get("friction_items")
                .and_then(|value| value.as_u64())
                .unwrap_or(0);
            format!(
                r#"<tr><td><code>{path}</code></td><td>{kind}</td><td>{returner}</td><td>{scores}</td><td>{friction}</td></tr>"#,
                path = escape_html(path),
                kind = escape_html(kind),
                returner = escape_html(returner),
                scores = scores,
                friction = friction
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let returned_rows = if returned_rows.is_empty() {
        r#"<tr><td colspan="5">No returned JSON files found under <code>dist/external-proof-loop/returned</code>.</td></tr>"#.to_string()
    } else {
        returned_rows
    };
    let returned_evidence_rows = payload
        .get("returned_evidence")
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|entry| {
            let source = entry
                .get("source")
                .and_then(|value| value.as_str())
                .unwrap_or("unknown");
            let class = entry
                .get("return_class")
                .and_then(|value| value.as_str())
                .unwrap_or("unknown");
            let valid = entry
                .get("validation_ok")
                .and_then(|value| value.as_bool())
                .unwrap_or(false);
            let preview = entry
                .get("import_preview")
                .and_then(|value| value.as_str())
                .unwrap_or("");
            let draft_scores = entry
                .get("draft_scores")
                .and_then(|value| value.as_u64())
                .unwrap_or(0);
            let draft_reviews = entry
                .get("draft_review_events")
                .and_then(|value| value.as_u64())
                .unwrap_or(0);
            let friction = entry
                .get("friction_items")
                .and_then(|value| value.as_u64())
                .unwrap_or(0);
            format!(
                r#"<tr><td><code>{source}</code></td><td>{class}</td><td>{valid}</td><td>{draft_scores}</td><td>{draft_reviews}</td><td>{friction}</td><td><code>{preview}</code></td></tr>"#,
                source = escape_html(source),
                class = escape_html(class),
                valid = valid,
                draft_scores = draft_scores,
                draft_reviews = draft_reviews,
                friction = friction,
                preview = escape_html(preview)
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let returned_evidence_rows = if returned_evidence_rows.is_empty() {
        r#"<tr><td colspan="7">No validation summary found for returned evidence.</td></tr>"#
            .to_string()
    } else {
        returned_evidence_rows
    };
    let artifacts = payload.get("artifacts").unwrap_or(&serde_json::Value::Null);
    let manifest = artifacts
        .get("manifest")
        .unwrap_or(&serde_json::Value::Null);
    let scorer = artifacts
        .get("blind_scorer_pack")
        .unwrap_or(&serde_json::Value::Null);
    let summary = payload
        .get("return_summary")
        .unwrap_or(&serde_json::Value::Null);
    let blind_tasks = scorer
        .get("task_count")
        .and_then(|value| value.as_u64())
        .unwrap_or(0);
    let returned_count = summary
        .get("returned_files")
        .and_then(|value| value.as_u64())
        .unwrap_or(0);
    let real_returns = summary
        .get("real_returns")
        .and_then(|value| value.as_u64())
        .unwrap_or(0);
    let local_rehearsals = summary
        .get("local_rehearsals")
        .and_then(|value| value.as_u64())
        .unwrap_or(0);
    let valid_returns = summary
        .get("valid_returns")
        .and_then(|value| value.as_u64())
        .unwrap_or(0);
    let draft_scores = summary
        .get("draft_scores")
        .and_then(|value| value.as_u64())
        .unwrap_or(0);
    let draft_review_events = summary
        .get("draft_review_events")
        .and_then(|value| value.as_u64())
        .unwrap_or(0);
    let manifest_present = manifest
        .get("present")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let body = format!(
        r#"<section class="wb-hero" aria-label="External proof loop">
  <div class="wb-hero__grid">
    <div>
      <h2>External proof loop</h2>
      <p>This read-only page inspects the external proof loop packet, blind scorer pack, protocol compatibility pack, returned files, and import-preview commands. Returned material is source material until explicit review.</p>
      <div class="wb-action-row">
        <a class="wb-button" href="/demo/external-proof-loop.json">Open JSON</a>
        <a class="wb-button wb-button--quiet" href="/demo/external-review">External review</a>
        <a class="wb-button wb-button--quiet" href="/demo/score-return">Score-return preview</a>
        <a class="wb-button wb-button--quiet" href="/review/work">Review work</a>
      </div>
    </div>
    <div class="wb-status-panel" aria-label="External proof loop boundary">
      <div><span>manifest present</span><strong>{manifest_present}</strong></div>
      <div><span>blind tasks</span><strong>{blind_tasks}</strong></div>
      <div><span>returned files</span><strong>{returned_count}</strong></div>
      <div><span>valid returns</span><strong>{valid_returns}</strong></div>
      <div><span>draft scores</span><strong>{draft_scores}</strong></div>
      <div><span>draft reviews</span><strong>{draft_review_events}</strong></div>
      <div><span>local rehearsals</span><strong>{local_rehearsals}</strong></div>
      <div><span>real returns</span><strong>{real_returns}</strong></div>
      <div><span>writes_review_events</span><strong>false</strong></div>
      <div><span>claims_external_validation</span><strong>false</strong></div>
    </div>
  </div>
</section>
<div class="wb-card">
  <h3>Artifacts</h3>
  <p><code>dist/external-proof-loop/manifest.v1.json</code></p>
  <p><code>benchmarks/public/blind-scorer-pack.v1.json</code></p>
  <p><code>dist/protocol-compatibility/manifest.v1.json</code></p>
  <p><code>dist/external-proof-loop/returned</code></p>
  <p><code>dist/external-proof-loop/validation/solo-maintainer-return-validation.v1.json</code></p>
  <p>Boundary: read_only=true; returned_material_is_source_material=true; writes_review_events=false; accepts_frontier_state=false; claims_external_validation=false.</p>
</div>
<div class="wb-card">
  <h3>Returned evidence inbox</h3>
  <p>Returned material is split into local rehearsal returns and real outside returns. Solo-maintainer returns stay source material, not external validation. The return-to-draft path validates returned material, previews draft events, and still writes no trusted state.</p>
  <table class="wb-table">
    <thead><tr><th>source</th><th>class</th><th>valid</th><th>draft scores</th><th>draft reviews</th><th>friction</th><th>import preview</th></tr></thead>
    <tbody>{returned_evidence_rows}</tbody>
  </table>
</div>
<div class="wb-card">
  <h3>Return-to-draft path</h3>
  <p>This path is read-only. It separates validation, mutation boundary, draft events, and next command before any accepted frontier state can exist.</p>
  <table class="wb-table">
    <thead><tr><th>step</th><th>purpose</th><th>artifact or command</th></tr></thead>
    <tbody>
      <tr><td>validation</td><td>Check the returned file shape and source-material boundary.</td><td><code>dist/external-proof-loop/validation/solo-maintainer-return-validation.v1.json</code></td></tr>
      <tr><td>mutation boundary</td><td>Confirm writes_review_events=false and accepts_frontier_state=false.</td><td><code>read_only=true</code></td></tr>
      <tr><td>draft events</td><td>Preview review events without adding trusted state.</td><td><code>draft_review_events</code></td></tr>
      <tr><td>next command</td><td>Build an import preview for the selected return.</td><td><code>./scripts/import-external-proof-loop-return-v1.py dist/external-proof-loop/returned/&lt;return.json&gt; --out /tmp/vela-external-proof-import --json</code></td></tr>
    </tbody>
  </table>
</div>
<div class="wb-card">
  <h3>Returned files</h3>
  <table class="wb-table">
    <thead><tr><th>file</th><th>kind</th><th>returner</th><th>task scores</th><th>friction</th></tr></thead>
    <tbody>{returned_rows}</tbody>
  </table>
</div>
<div class="wb-card">
  <h3>Copy commands</h3>
  <table class="wb-table">
    <thead><tr><th>action</th><th>command</th></tr></thead>
    <tbody>{actions}</tbody>
  </table>
</div>"#,
        manifest_present = manifest_present,
        blind_tasks = blind_tasks,
        returned_count = returned_count,
        valid_returns = valid_returns,
        draft_scores = draft_scores,
        draft_review_events = draft_review_events,
        local_rehearsals = local_rehearsals,
        real_returns = real_returns,
        returned_evidence_rows = returned_evidence_rows,
        returned_rows = returned_rows,
        actions = actions,
    );
    Html(shell(
        "external-proof-loop",
        "External proof loop · Vela Workbench",
        "Workbench",
        "External proof loop",
        &body,
    ))
    .into_response()
}

async fn page_external_proof_loop_json(State(state): State<AppState>) -> Response {
    Json(external_proof_loop_payload(&state.repo_path)).into_response()
}

async fn page_frontier_benchmarks(State(state): State<AppState>) -> Response {
    let suite = load_workspace_json(
        &state.repo_path,
        "benchmarks/suites/frontier-review-v1.json",
    )
    .unwrap_or_else(|| serde_json::json!({}));
    let baseline = load_workspace_json(
        &state.repo_path,
        "benchmarks/results/paper-rag-v2-local.json",
    )
    .unwrap_or_else(|| serde_json::json!({}));
    let error_analysis = load_workspace_json(
        &state.repo_path,
        "benchmarks/results/frontier-review-v2-error-analysis.json",
    )
    .unwrap_or_else(|| serde_json::json!({}));
    let scorer = load_workspace_json(
        &state.repo_path,
        "benchmarks/public/blind-scorer-pack.v2.json",
    )
    .unwrap_or_else(|| serde_json::json!({}));
    let baseline_summary = baseline.get("summary").unwrap_or(&serde_json::Value::Null);
    let error_summary = error_analysis
        .get("summary")
        .unwrap_or(&serde_json::Value::Null);
    let scorer_summary = scorer.get("summary").unwrap_or(&serde_json::Value::Null);
    let body = format!(
        r#"<section class="wb-hero" aria-label="Frontier benchmarks">
  <div class="wb-hero__grid">
    <div>
      <h2>Frontier benchmarks</h2>
      <p>Frozen local benchmark material compares Vela-backed frontier review with a paper-RAG v2 local baseline for inspectability, source grounding, caveats, counterweights, and reviewability.</p>
      <div class="wb-action-row">
        <a class="wb-button" href="/frontier/questions">Questions</a>
        <a class="wb-button wb-button--quiet" href="/frontier/answer-paths">Answer paths</a>
        <a class="wb-button wb-button--quiet" href="/frontier/returns">Returns</a>
      </div>
    </div>
    <div class="wb-status-panel" aria-label="Benchmark boundary">
      <div><span>suite tasks</span><strong>{suite_tasks}</strong></div>
      <div><span>paper-RAG v2 local baseline</span><strong>{baseline_tasks}</strong></div>
      <div><span>blind scorer tasks</span><strong>{scorer_tasks}</strong></div>
      <div><span>error records</span><strong>{error_records}</strong></div>
      <div><span>claims_external_validation</span><strong>false</strong></div>
    </div>
  </div>
</section>
<div class="wb-card">
  <h3>Benchmark artifacts</h3>
  <p><code>benchmarks/suites/frontier-review-v1.json</code></p>
  <p><code>benchmarks/results/paper-rag-v2-local.json</code></p>
  <p><code>benchmarks/results/frontier-review-v2-error-analysis.json</code></p>
  <p><code>benchmarks/public/blind-scorer-pack.v2.json</code></p>
  <p>Boundary: local_comparison_only=true; hidden_answer_keys=true; claims_external_validation=false; claims_benchmark_outperformance=false.</p>
</div>"#,
        suite_tasks = suite
            .get("task_count")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        baseline_tasks = json_u64(baseline_summary, "task_count"),
        scorer_tasks = json_u64(scorer_summary, "task_count"),
        error_records = json_u64(error_summary, "error_record_count"),
    );
    Html(shell(
        "frontier-benchmarks",
        "Frontier benchmarks · Vela Workbench",
        "Workbench",
        "Frontier benchmarks",
        &body,
    ))
    .into_response()
}

fn frontier_answer_book_payload(repo_path: &Path) -> serde_json::Value {
    load_workspace_json(
        repo_path,
        "projects/anti-amyloid-translation/review/frontier-answer-book.v1.json",
    )
    .unwrap_or_else(|| {
        serde_json::json!({
            "schema": "vela.workbench.frontier_answer_book.v0.1",
            "frontier": "projects/anti-amyloid-translation",
            "status": "missing",
            "answers": [],
            "summary": {
                "answer_count": 0,
                "supporting_finding_refs": 0,
                "counterweight_finding_refs": 0
            },
            "claim_boundary": {
                "claims_answer_book_complete_v1_local": false,
                "claims_external_validation": false,
                "claims_treatment_advice": false,
                "claims_target_validation": false
            }
        })
    })
}

fn frontier_use_map_payload(repo_path: &Path) -> serde_json::Value {
    load_workspace_json(
        repo_path,
        "projects/anti-amyloid-translation/review/frontier-use-map.v1.json",
    )
    .unwrap_or_else(|| {
        serde_json::json!({
            "schema": "vela.workbench.frontier_use_map.v0.1",
            "frontier": "projects/anti-amyloid-translation",
            "status": "missing",
            "questions": [],
            "operator_entrypoints": [],
            "summary": {
                "question_count": 0,
                "covered_question_count": 0,
                "findings": 0,
                "sources": 0,
                "evidence_atoms": 0
            },
            "claim_boundary": {
                "claims_frontier_usable_v1_local": false,
                "claims_external_validation": false,
                "claims_treatment_advice": false,
                "claims_target_validation": false
            }
        })
    })
}

fn frontier_answer_paths_payload(repo_path: &Path) -> serde_json::Value {
    attach_frontier_index_backing(
        load_workspace_json(
            repo_path,
            "projects/anti-amyloid-translation/review/answer-evidence-paths.v1.json",
        )
        .unwrap_or_else(|| {
            serde_json::json!({
                "schema": "vela.workbench.answer_evidence_paths.v0.1",
                "frontier": "projects/anti-amyloid-translation",
                "status": "missing",
                "summary": {
                    "answer_count": 0,
                    "path_count": 0,
                    "total_supporting_finding_refs": 0,
                    "total_counterweight_finding_refs": 0,
                    "total_source_refs": 0,
                    "total_evidence_atom_refs": 0
                },
                "paths": [],
                "claim_boundary": {
                    "mutates_frontier_state": false,
                    "claims_external_validation": false,
                    "claims_benchmark_outperformance": false,
                    "claims_treatment_advice": false,
                    "claims_target_validation": false
                }
            })
        }),
        repo_path,
        "answer-evidence-paths.v1.json",
    )
}

fn frontier_decision_paths_payload(repo_path: &Path) -> serde_json::Value {
    load_workspace_json(
        repo_path,
        "projects/anti-amyloid-translation/review/decision-paths.v1.json",
    )
    .unwrap_or_else(|| {
        serde_json::json!({
            "schema": "vela.anti_amyloid_decision_paths.v1",
            "status": "missing",
            "summary": {
                "path_count": 0,
                "paths_with_full_chain": 0,
                "paths_with_human_verification_context": 0,
                "paths_with_next_action": 0
            },
            "decision_paths": [],
            "claim_boundary": {
                "claims_external_validation": false,
                "claims_treatment_advice": false,
                "claims_target_validation": false,
                "mutates_frontier_state": false
            }
        })
    })
}

fn decision_path_by_id(payload: &serde_json::Value, answer_id: &str) -> Option<serde_json::Value> {
    let expected = format!("decision_path:{answer_id}");
    payload
        .get("decision_paths")
        .and_then(serde_json::Value::as_array)
        .and_then(|paths| {
            paths
                .iter()
                .find(|path| {
                    json_str(path, "decision_path_id") == expected
                        || path
                            .get("question")
                            .map(|question| json_str(question, "question_id") == answer_id)
                            .unwrap_or(false)
                })
                .cloned()
        })
}

fn frontier_questions_payload(repo_path: &Path) -> serde_json::Value {
    let answer_paths = frontier_answer_paths_payload(repo_path);
    let paths = answer_paths
        .get("paths")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let questions = paths
        .iter()
        .map(|path| {
            let answer_id = json_str(path, "answer_id");
            serde_json::json!({
                "question_id": answer_id,
                "question": json_str(path, "question"),
                "answer": json_str(path, "answer"),
                "interpretation": json_str(path, "interpretation"),
                "answer_path_route": format!("/frontier/answer-paths/{answer_id}"),
                "answer_path_json_route": format!("/frontier/answer-paths/{answer_id}.json"),
                "supporting_findings": path
                    .get("supporting_findings")
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!([])),
                "counterweight_findings": path
                    .get("counterweight_findings")
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!([])),
                "source_health": path
                    .get("locator_health")
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!({})),
                "remaining_caveats": path
                    .get("remaining_caveats")
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!([])),
                "operator_next_action": path
                    .get("operator_next_action")
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!({})),
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "schema": "vela.workbench.frontier_questions.v0.1",
        "frontier": "projects/anti-amyloid-translation",
        "summary": {
            "question_count": questions.len(),
            "answer_path_count": json_u64(
                answer_paths.get("summary").unwrap_or(&serde_json::Value::Null),
                "path_count",
            ),
            "paths_with_stable_source_majority": json_u64(
                answer_paths.get("summary").unwrap_or(&serde_json::Value::Null),
                "paths_with_stable_source_majority",
            ),
            "paths_with_visible_source_debt": json_u64(
                answer_paths.get("summary").unwrap_or(&serde_json::Value::Null),
                "paths_with_visible_source_debt",
            ),
        },
        "questions": questions,
        "index_backing": answer_paths
            .get("index_backing")
            .cloned()
            .unwrap_or_else(|| frontier_index_backing(repo_path, "answer-evidence-paths.v1.json")),
        "claim_boundary": {
            "mutates_frontier_state": false,
            "claims_external_validation": false,
            "claims_benchmark_outperformance": false,
            "claims_treatment_advice": false,
            "claims_target_validation": false,
        }
    })
}

fn json_str<'a>(value: &'a serde_json::Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
}

fn json_u64(value: &serde_json::Value, key: &str) -> u64 {
    value
        .get(key)
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0)
}

fn json_array_len(value: &serde_json::Value, key: &str) -> usize {
    value
        .get(key)
        .and_then(serde_json::Value::as_array)
        .map_or(0, Vec::len)
}

fn json_bool(value: &serde_json::Value, key: &str) -> bool {
    value
        .get(key)
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

fn render_frontier_index_backing(payload: &serde_json::Value) -> String {
    let index = payload
        .get("index_backing")
        .unwrap_or(&serde_json::Value::Null);
    let present = json_bool(index, "present");
    let title = if present {
        "index-backed"
    } else {
        "index unavailable"
    };
    let source = json_str(index, "source");
    let database_path = json_str(index, "database_path");
    let fallback_source = json_str(index, "fallback_source");
    let fallback = json_bool(index, "fallback_counts_from_files");
    let chip_class = if present {
        "wb-chip wb-chip--ok"
    } else {
        "wb-chip wb-chip--warn"
    };
    format!(
        r#"<div class="wb-card">
  <h3>Index backing</h3>
  <p><span class="{chip_class}">{title}</span> source: <code>{source}</code> · database: <code>{database_path}</code> · fallback: <code>{fallback_source}</code>.</p>
  <p><code>database_is_authority=false</code> · <code>fallback_counts_from_files={fallback}</code>. The index is a rebuildable read model over frontier files and accepted events.</p>
</div>"#,
        chip_class = chip_class,
        title = title,
        source = escape_html(source),
        database_path = escape_html(database_path),
        fallback_source = escape_html(fallback_source),
        fallback = fallback,
    )
}

fn render_finding_links(ids: &[serde_json::Value]) -> String {
    ids.iter()
        .filter_map(serde_json::Value::as_str)
        .map(|id| {
            format!(
                r#"<a class="wb-chip" href="/findings/{href}">{id}</a>"#,
                href = urlencode_path(id),
                id = escape_html(id)
            )
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn render_finding_link_from_str(id: &str) -> String {
    format!(
        r#"<a class="wb-chip" href="/findings/{href}">{id}</a>"#,
        href = urlencode_path(id),
        id = escape_html(id)
    )
}

fn early_ad_v32_artifact(repo_path: &Path, name: &str) -> serde_json::Value {
    load_workspace_json(
        repo_path,
        &format!("projects/anti-amyloid-translation/factory/{name}"),
    )
    .unwrap_or_else(|| serde_json::json!({"ok": false, "status": "missing"}))
}

fn early_ad_v32_question_freeze_payload(repo_path: &Path) -> serde_json::Value {
    early_ad_v32_artifact(repo_path, "early-ad-v32-reviewer-question-freeze.v1.json")
}

fn early_ad_v32_answer_trails_payload(repo_path: &Path) -> serde_json::Value {
    early_ad_v32_artifact(repo_path, "early-ad-v32-answer-trails.v1.json")
}

fn early_ad_v32_baseline_pack_payload(repo_path: &Path) -> serde_json::Value {
    early_ad_v32_artifact(repo_path, "early-ad-v32-baseline-pack.v1.json")
}

fn early_ad_v32_comparison_ledger_payload(repo_path: &Path) -> serde_json::Value {
    early_ad_v32_artifact(repo_path, "early-ad-v32-comparison-score-ledger.v1.json")
}

fn early_ad_v32_decision_briefs_payload(repo_path: &Path) -> serde_json::Value {
    early_ad_v32_artifact(repo_path, "early-ad-v32-decision-briefs.v1.json")
}

fn json_array(value: &serde_json::Value, key: &str) -> Vec<serde_json::Value> {
    value
        .get(key)
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn json_string_array(value: &serde_json::Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(serde_json::Value::as_array)
        .map(|rows| {
            rows.iter()
                .filter_map(serde_json::Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn json_i64_at(value: &serde_json::Value, keys: &[&str]) -> i64 {
    let mut cursor = value;
    for key in keys {
        cursor = cursor.get(*key).unwrap_or(&serde_json::Value::Null);
    }
    cursor.as_i64().unwrap_or(0)
}

fn early_ad_v32_row_by<'a>(
    rows: &'a [serde_json::Value],
    key: &str,
    expected: &str,
) -> Option<&'a serde_json::Value> {
    rows.iter().find(|row| json_str(row, key) == expected)
}

fn early_ad_v32_reviewer_demo_payload(repo_path: &Path) -> serde_json::Value {
    let question_freeze = early_ad_v32_question_freeze_payload(repo_path);
    let answers = early_ad_v32_answer_trails_payload(repo_path);
    let baseline = early_ad_v32_baseline_pack_payload(repo_path);
    let comparison = early_ad_v32_comparison_ledger_payload(repo_path);
    let briefs = early_ad_v32_decision_briefs_payload(repo_path);

    let answer_rows = json_array(&answers, "answer_trails");
    let baseline_rows = json_array(&baseline, "baseline_answers");
    let comparison_rows = json_array(&comparison, "comparison_rows");
    let brief_rows = json_array(&briefs, "decision_briefs");

    let questions = answer_rows
        .iter()
        .map(|answer| {
            let question_id = json_str(answer, "question_id");
            let baseline = early_ad_v32_row_by(&baseline_rows, "question_id", question_id);
            let comparison = early_ad_v32_row_by(&comparison_rows, "question_id", question_id);
            let brief = early_ad_v32_row_by(&brief_rows, "question_id", question_id);
            serde_json::json!({
                "question_id": question_id,
                "question": json_str(answer, "question"),
                "lane": json_str(answer, "lane"),
                "route": format!("/frontier/reviewer-demo/questions/{question_id}"),
                "json_route": format!("/frontier/reviewer-demo/questions/{question_id}.json"),
                "answer_id": json_str(answer, "answer_id"),
                "baseline_id": baseline.map(|row| json_str(row, "baseline_id")).unwrap_or(""),
                "comparison_id": comparison.map(|row| json_str(row, "comparison_id")).unwrap_or(""),
                "decision_brief_path": brief.map(|row| json_str(row, "brief_path")).unwrap_or(""),
                "score_delta": comparison
                    .and_then(|row| row.get("score_delta"))
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!({})),
                "supporting_finding_count": json_array_len(answer, "supporting_finding_ids"),
                "source_count": json_array_len(answer, "source_ids"),
                "evidence_atom_count": json_array_len(answer, "evidence_atom_ids"),
                "tension_count": json_array_len(answer, "tension_ids"),
                "gap_task_count": json_array_len(answer, "gap_task_ids"),
            })
        })
        .collect::<Vec<_>>();

    let ok = json_bool(&question_freeze, "ok")
        && json_bool(&answers, "ok")
        && json_bool(&baseline, "ok")
        && json_bool(&comparison, "ok")
        && json_bool(&briefs, "ok")
        && questions.len() == 30;

    serde_json::json!({
        "schema": "vela.workbench.early_ad_v32_reviewer_demo.v1",
        "frontier": "projects/anti-amyloid-translation",
        "status": if ok { "ready" } else { "incomplete" },
        "ok": ok,
        "derived_from": {
            "question_freeze": "projects/anti-amyloid-translation/factory/early-ad-v32-reviewer-question-freeze.v1.json",
            "answer_trails": "projects/anti-amyloid-translation/factory/early-ad-v32-answer-trails.v1.json",
            "baseline_pack": "projects/anti-amyloid-translation/factory/early-ad-v32-baseline-pack.v1.json",
            "comparison_score_ledger": "projects/anti-amyloid-translation/factory/early-ad-v32-comparison-score-ledger.v1.json",
            "decision_briefs": "projects/anti-amyloid-translation/factory/early-ad-v32-decision-briefs.v1.json"
        },
        "summary": {
            "frozen_questions": json_u64(question_freeze.get("summary").unwrap_or(&serde_json::Value::Null), "reviewer_questions"),
            "answer_trails": json_u64(answers.get("summary").unwrap_or(&serde_json::Value::Null), "answer_trails"),
            "baseline_answers": json_u64(baseline.get("summary").unwrap_or(&serde_json::Value::Null), "baseline_answers"),
            "comparison_rows": json_u64(comparison.get("summary").unwrap_or(&serde_json::Value::Null), "comparisons"),
            "decision_briefs": json_u64(briefs.get("summary").unwrap_or(&serde_json::Value::Null), "decision_briefs"),
            "answered_questions": questions.len(),
            "proof_export_status": "pending_v32_packet"
        },
        "questions": questions,
        "claim_boundary": {
            "claims_treatment_advice": false,
            "claims_clinical_validity": false,
            "claims_target_validation": false,
            "claims_external_validation": false,
            "claims_benchmark_outperformance": false,
            "claims_scientific_discovery": false,
            "mutates_trusted_frontier_state": false
        }
    })
}

fn early_ad_v32_reviewer_demo_question_payload(
    repo_path: &Path,
    question_id: &str,
) -> Option<serde_json::Value> {
    let question_freeze = early_ad_v32_question_freeze_payload(repo_path);
    let answers = early_ad_v32_answer_trails_payload(repo_path);
    let baseline = early_ad_v32_baseline_pack_payload(repo_path);
    let comparison = early_ad_v32_comparison_ledger_payload(repo_path);
    let briefs = early_ad_v32_decision_briefs_payload(repo_path);

    let question_rows = json_array(&question_freeze, "questions");
    let answer_rows = json_array(&answers, "answer_trails");
    let baseline_rows = json_array(&baseline, "baseline_answers");
    let comparison_rows = json_array(&comparison, "comparison_rows");
    let brief_rows = json_array(&briefs, "decision_briefs");

    let answer = early_ad_v32_row_by(&answer_rows, "question_id", question_id)?.clone();
    let question = early_ad_v32_row_by(&question_rows, "question_id", question_id)
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let baseline = early_ad_v32_row_by(&baseline_rows, "question_id", question_id)
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let comparison = early_ad_v32_row_by(&comparison_rows, "question_id", question_id)
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let brief = early_ad_v32_row_by(&brief_rows, "question_id", question_id)
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));

    Some(serde_json::json!({
        "schema": "vela.workbench.early_ad_v32_reviewer_demo_question.v1",
        "frontier": "projects/anti-amyloid-translation",
        "question_id": question_id,
        "question": question,
        "answer": answer,
        "baseline": baseline,
        "comparison": comparison,
        "decision_brief": brief,
        "claim_boundary": {
            "claims_treatment_advice": false,
            "claims_clinical_validity": false,
            "claims_target_validation": false,
            "claims_external_validation": false,
            "claims_benchmark_outperformance": false,
            "claims_scientific_discovery": false,
            "mutates_trusted_frontier_state": false
        }
    }))
}

fn render_code_list(values: &[String]) -> String {
    if values.is_empty() {
        return "<li>none recorded</li>".to_string();
    }
    values
        .iter()
        .map(|value| format!("<li><code>{}</code></li>", escape_html(value)))
        .collect::<Vec<_>>()
        .join("")
}

fn render_v32_summary_card(label: &str, value: u64, suffix: &str) -> String {
    format!(
        r#"<div><div class="wb-stat__num">{value}</div><div class="wb-stat__label">{label}{suffix}</div></div>"#,
        value = value,
        label = escape_html(label),
        suffix = escape_html(suffix),
    )
}

fn render_dimension_scores(comparison: &serde_json::Value) -> String {
    let scores = comparison
        .get("dimension_scores")
        .and_then(serde_json::Value::as_object)
        .cloned()
        .unwrap_or_default();
    let mut keys = scores.keys().cloned().collect::<Vec<_>>();
    keys.sort();
    keys.iter()
        .map(|key| {
            let row = scores.get(key).unwrap_or(&serde_json::Value::Null);
            format!(
                r#"<tr><td>{dimension}</td><td><code>{vela}</code></td><td><code>{baseline}</code></td><td>{basis}</td></tr>"#,
                dimension = escape_html(key),
                vela = json_u64(row, "vela"),
                baseline = json_u64(row, "baseline"),
                basis = escape_html(json_str(row, "basis")),
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

fn early_ad_v33_frontiergraph_payload(repo_path: &Path) -> serde_json::Value {
    load_workspace_json(
        repo_path,
        "projects/anti-amyloid-translation/factory/early-ad-v33-frontiergraph.v1.json",
    )
    .unwrap_or_else(|| {
        serde_json::json!({
            "schema": "vela.early_ad_v33_frontiergraph.v1",
            "frontier": "projects/anti-amyloid-translation",
            "status": "missing",
            "ok": false,
            "summary": {
                "derived_nodes": 0,
                "derived_edges": 0,
                "saved_traversals": 0
            },
            "nodes": [],
            "edges": [],
            "saved_traversals": [],
            "hotspots": [],
            "claim_boundary": {
                "graph_is_derived": true,
                "claims_treatment_advice": false,
                "claims_clinical_validity": false,
                "claims_target_validation": false,
                "claims_external_validation": false,
                "claims_benchmark_outperformance": false,
                "claims_scientific_discovery": false
            }
        })
    })
}

fn frontier_graph_node_by_id(
    payload: &serde_json::Value,
    node_id: &str,
) -> Option<serde_json::Value> {
    payload
        .get("nodes")
        .and_then(serde_json::Value::as_array)
        .and_then(|nodes| {
            nodes
                .iter()
                .find(|node| json_str(node, "id") == node_id)
                .cloned()
        })
}

fn frontier_graph_traversal_by_id(
    payload: &serde_json::Value,
    traversal_id: &str,
) -> Option<serde_json::Value> {
    payload
        .get("saved_traversals")
        .and_then(serde_json::Value::as_array)
        .and_then(|rows| {
            rows.iter()
                .find(|row| json_str(row, "traversal_id") == traversal_id)
                .cloned()
        })
}

fn frontier_graph_edges_for_node(
    payload: &serde_json::Value,
    node_id: &str,
    direction: &str,
) -> Vec<serde_json::Value> {
    payload
        .get("edges")
        .and_then(serde_json::Value::as_array)
        .map(|edges| {
            edges
                .iter()
                .filter(|edge| match direction {
                    "incoming" => json_str(edge, "target") == node_id,
                    "outgoing" => json_str(edge, "source") == node_id,
                    _ => json_str(edge, "source") == node_id || json_str(edge, "target") == node_id,
                })
                .take(80)
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

fn frontier_graph_traversals_for_node(
    payload: &serde_json::Value,
    node_id: &str,
) -> Vec<serde_json::Value> {
    payload
        .get("saved_traversals")
        .and_then(serde_json::Value::as_array)
        .map(|rows| {
            rows.iter()
                .filter(|row| {
                    row.get("node_sequence")
                        .and_then(serde_json::Value::as_array)
                        .map(|nodes| nodes.iter().any(|node| node.as_str() == Some(node_id)))
                        .unwrap_or(false)
                })
                .take(20)
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

fn frontier_graph_node_detail_payload(
    repo_path: &Path,
    node_id: &str,
) -> Option<serde_json::Value> {
    let payload = early_ad_v33_frontiergraph_payload(repo_path);
    let node = frontier_graph_node_by_id(&payload, node_id)?;
    Some(serde_json::json!({
        "schema": "vela.workbench.early_ad_v33_frontiergraph_node.v1",
        "frontier": "projects/anti-amyloid-translation",
        "node": node,
        "incoming_edges": frontier_graph_edges_for_node(&payload, node_id, "incoming"),
        "outgoing_edges": frontier_graph_edges_for_node(&payload, node_id, "outgoing"),
        "saved_traversals": frontier_graph_traversals_for_node(&payload, node_id),
        "claim_boundary": payload
            .get("claim_boundary")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}))
    }))
}

fn frontier_graph_traversal_detail_payload(
    repo_path: &Path,
    traversal_id: &str,
) -> Option<serde_json::Value> {
    let payload = early_ad_v33_frontiergraph_payload(repo_path);
    let traversal = frontier_graph_traversal_by_id(&payload, traversal_id)?;
    let node_ids = traversal
        .get("node_sequence")
        .and_then(serde_json::Value::as_array)
        .map(|rows| {
            rows.iter()
                .filter_map(serde_json::Value::as_str)
                .map(ToOwned::to_owned)
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    let nodes = payload
        .get("nodes")
        .and_then(serde_json::Value::as_array)
        .map(|rows| {
            rows.iter()
                .filter(|node| node_ids.contains(json_str(node, "id")))
                .cloned()
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let edges = payload
        .get("edges")
        .and_then(serde_json::Value::as_array)
        .map(|rows| {
            rows.iter()
                .filter(|edge| {
                    node_ids.contains(json_str(edge, "source"))
                        && node_ids.contains(json_str(edge, "target"))
                })
                .take(160)
                .cloned()
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Some(serde_json::json!({
        "schema": "vela.workbench.early_ad_v33_frontiergraph_traversal.v1",
        "frontier": "projects/anti-amyloid-translation",
        "traversal": traversal,
        "nodes": nodes,
        "edges": edges,
        "claim_boundary": payload
            .get("claim_boundary")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}))
    }))
}

fn render_graph_edges(edges: &[serde_json::Value]) -> String {
    if edges.is_empty() {
        return r#"<tr><td colspan="4">No edges recorded.</td></tr>"#.to_string();
    }
    edges
        .iter()
        .map(|edge| {
            format!(
                r#"<tr><td><code>{source}</code></td><td>{relation}</td><td><code>{target}</code></td><td>{evidence}</td></tr>"#,
                source = escape_html(json_str(edge, "source")),
                relation = escape_html(json_str(edge, "relation")),
                target = escape_html(json_str(edge, "target")),
                evidence = escape_html(json_str(edge, "evidence")),
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

fn early_ad_v34_scientist_demo_payload(repo_path: &Path) -> serde_json::Value {
    load_workspace_json(
        repo_path,
        "projects/anti-amyloid-translation/factory/early-ad-v34-scientist-demo-paths.v1.json",
    )
    .unwrap_or_else(|| {
        serde_json::json!({
            "schema": "vela.early_ad_v34_scientist_demo_paths.v1",
            "frontier": "projects/anti-amyloid-translation",
            "status": "missing",
            "ok": false,
            "summary": {
                "demo_paths": 0,
                "derived_nodes": 0,
                "derived_edges": 0
            },
            "demo_paths": [],
            "claim_boundary": {
                "claims_treatment_advice": false,
                "claims_clinical_validity": false,
                "claims_target_validation": false,
                "claims_external_validation": false,
                "claims_benchmark_outperformance": false,
                "claims_scientific_discovery": false
            }
        })
    })
}

fn scientist_demo_path_by_id(
    payload: &serde_json::Value,
    path_id: &str,
) -> Option<serde_json::Value> {
    payload
        .get("demo_paths")
        .and_then(serde_json::Value::as_array)
        .and_then(|rows| {
            rows.iter()
                .find(|row| json_str(row, "path_id") == path_id)
                .cloned()
        })
}

fn scientist_demo_path_detail_payload(
    repo_path: &Path,
    path_id: &str,
) -> Option<serde_json::Value> {
    let payload = early_ad_v34_scientist_demo_payload(repo_path);
    let demo_path = scientist_demo_path_by_id(&payload, path_id)?;
    Some(serde_json::json!({
        "schema": "vela.workbench.early_ad_v34_scientist_demo_path.v1",
        "frontier": "projects/anti-amyloid-translation",
        "demo_path": demo_path,
        "claim_boundary": payload
            .get("claim_boundary")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}))
    }))
}

async fn page_frontier_scientist_demo(State(state): State<AppState>) -> Response {
    let payload = early_ad_v34_scientist_demo_payload(&state.repo_path);
    let summary = payload.get("summary").unwrap_or(&serde_json::Value::Null);
    let paths = json_array(&payload, "demo_paths")
        .iter()
        .map(|path| {
            format!(
                r#"<div class="wb-card">
  <h3>{title}</h3>
  <p>{question}</p>
  <p>{why}</p>
  <p>Local comparison delta: <code>{delta}</code>. Baseline: <code>{baseline}</code>.</p>
  <div class="wb-action-row">
    <a class="wb-button" href="{route}">Open path</a>
    <a class="wb-button wb-button--quiet" href="{graph_route}">Open FrontierGraph</a>
    <a class="wb-button wb-button--quiet" href="{review_route}">Reviewer answer</a>
  </div>
</div>"#,
                title = escape_html(json_str(path, "title")),
                question = escape_html(json_str(path, "scientist_question")),
                why = escape_html(json_str(path, "why_it_matters")),
                delta = json_i64_at(
                    path.get("baseline_comparison")
                        .unwrap_or(&serde_json::Value::Null),
                    &["local_proxy_delta"],
                ),
                baseline = escape_html(json_str(
                    path.get("baseline_comparison")
                        .unwrap_or(&serde_json::Value::Null),
                    "baseline_id",
                )),
                route = escape_html(json_str(path, "route")),
                graph_route = escape_html(json_str(path, "frontier_graph_route")),
                review_route = escape_html(json_str(path, "reviewer_question_route")),
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let demo_paths = json_u64(summary, "demo_paths");
    let derived_nodes = json_u64(summary, "derived_nodes");
    let derived_edges = json_u64(summary, "derived_edges");
    let body = format!(
        r#"<section class="wb-hero" aria-label="Early AD scientist demo">
  <div class="wb-hero__grid">
    <div>
      <h2>Early AD scientist demo</h2>
      <p>Open the frontier, inspect the DAG, follow guided paths, compare the baseline answer, and end at proof refs without opening raw JSON.</p>
      <p>{demo_paths} guided paths, {derived_nodes} graph nodes, and {derived_edges} graph edges are ready for review.</p>
      <div class="wb-action-row">
        <a class="wb-button" href="/frontier/graph">Open FrontierGraph</a>
        <a class="wb-button wb-button--quiet" href="/frontier/reviewer-demo">Reviewer demo</a>
        <a class="wb-button wb-button--quiet" href="/frontier/demo.json">Open JSON</a>
        <a class="wb-button wb-button--quiet" href="/frontier/proof">Proof packet</a>
      </div>
    </div>
    <div class="wb-status-panel" aria-label="Scientist demo status">
      <div><span>status</span><strong>{status}</strong></div>
      <div><span>guided paths</span><strong>{demo_paths}</strong></div>
      <div><span>graph nodes</span><strong>{derived_nodes}</strong></div>
      <div><span>graph edges</span><strong>{derived_edges}</strong></div>
      <div><span>claims_treatment_advice</span><strong>false</strong></div>
    </div>
  </div>
</section>
<div class="wb-card">
  <h3>Boundary</h3>
  <p>This demo does not claim treatment advice, clinical validity, target validation, external validation, benchmark outperformance, or scientific discovery.</p>
</div>
{paths}"#,
        status = escape_html(json_str(&payload, "status")),
        demo_paths = demo_paths,
        derived_nodes = derived_nodes,
        derived_edges = derived_edges,
        paths = paths,
    );
    Html(shell(
        "frontier-demo",
        "Early AD scientist demo · Vela Workbench",
        "Workbench",
        "Early AD scientist demo",
        &body,
    ))
    .into_response()
}

async fn page_frontier_scientist_demo_json(State(state): State<AppState>) -> Response {
    Json(early_ad_v34_scientist_demo_payload(&state.repo_path)).into_response()
}

async fn page_frontier_scientist_demo_path_detail(
    State(state): State<AppState>,
    AxumPath(path_id): AxumPath<String>,
) -> Response {
    let wants_json = path_id.ends_with(".json");
    let clean_path_id = path_id
        .strip_suffix(".json")
        .unwrap_or(path_id.as_str())
        .to_string();
    let Some(payload) = scientist_demo_path_detail_payload(&state.repo_path, &clean_path_id) else {
        return if wants_json {
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "scientist demo path not found"})),
            )
                .into_response()
        } else {
            (
                StatusCode::NOT_FOUND,
                Html(shell(
                    "frontier-demo",
                    "Scientist demo path not found · Vela Workbench",
                    "Workbench",
                    "Scientist demo path not found",
                    "<div class=\"wb-card\"><p>Path not found.</p></div>",
                )),
            )
                .into_response()
        };
    };
    if wants_json {
        return Json(payload).into_response();
    }
    let path = payload.get("demo_path").unwrap_or(&serde_json::Value::Null);
    let sections = path
        .get("readable_sections")
        .unwrap_or(&serde_json::Value::Null);
    let baseline = path
        .get("baseline_comparison")
        .unwrap_or(&serde_json::Value::Null);
    let body = format!(
        r#"<div class="wb-card">
  <h3>Scientist demo path</h3>
  <p><code>{path_id}</code></p>
  <p>{question}</p>
</div>
<div class="wb-card">
  <h3>Why it matters</h3>
  <p>{why}</p>
</div>
<div class="wb-card">
  <h3>Bounded answer</h3>
  <blockquote>{answer}</blockquote>
</div>
<div class="wb-card">
  <h3>Baseline comparison</h3>
  <p>Baseline: <code>{baseline_id}</code>. Comparison: <code>{comparison_id}</code>. Local proxy delta: <code>{delta}</code>.</p>
  <div class="wb-action-row">
    <a class="wb-button" href="{graph_route}">Open FrontierGraph traversal</a>
    <a class="wb-button wb-button--quiet" href="{review_route}">Reviewer answer</a>
  </div>
</div>
<div class="wb-grid">
  <div class="wb-card"><h3>Supporting findings</h3><ul>{supporting}</ul></div>
  <div class="wb-card"><h3>Counterweights</h3><ul>{counterweights}</ul></div>
  <div class="wb-card"><h3>Source records</h3><ul>{sources}</ul></div>
  <div class="wb-card"><h3>Evidence atoms</h3><ul>{atoms}</ul></div>
  <div class="wb-card"><h3>Dependency links</h3><ul>{links}</ul></div>
  <div class="wb-card"><h3>Evidence tensions</h3><ul>{tensions}</ul></div>
  <div class="wb-card"><h3>Gap tasks</h3><ul>{gaps}</ul></div>
  <div class="wb-card"><h3>Proof refs</h3><ul>{proof_refs}</ul></div>
</div>
<div class="wb-card">
  <h3>Boundary</h3>
  <p>This path is review material. It does not claim treatment advice, clinical validity, target validation, external validation, benchmark outperformance, or scientific discovery.</p>
</div>"#,
        path_id = escape_html(json_str(path, "path_id")),
        question = escape_html(json_str(path, "scientist_question")),
        why = escape_html(json_str(path, "why_it_matters")),
        answer = escape_html(json_str(path, "bounded_answer")),
        baseline_id = escape_html(json_str(baseline, "baseline_id")),
        comparison_id = escape_html(json_str(baseline, "comparison_id")),
        delta = json_i64_at(baseline, &["local_proxy_delta"]),
        graph_route = escape_html(json_str(path, "frontier_graph_route")),
        review_route = escape_html(json_str(path, "reviewer_question_route")),
        supporting = render_code_list(&json_string_array(sections, "supporting_findings")),
        counterweights = render_code_list(&json_string_array(sections, "counterweights")),
        sources = render_code_list(&json_string_array(sections, "source_records")),
        atoms = render_code_list(&json_string_array(sections, "evidence_atoms")),
        links = render_code_list(&json_string_array(sections, "dependency_links")),
        tensions = render_code_list(&json_string_array(sections, "evidence_tensions")),
        gaps = render_code_list(&json_string_array(sections, "gap_tasks")),
        proof_refs = render_code_list(&json_string_array(sections, "proof_refs")),
    );
    Html(shell(
        "frontier-demo",
        "Scientist demo path · Vela Workbench",
        "Workbench",
        "Scientist demo path",
        &body,
    ))
    .into_response()
}

fn render_traversal_links(rows: &[serde_json::Value]) -> String {
    if rows.is_empty() {
        return "<li>none recorded</li>".to_string();
    }
    rows.iter()
        .map(|row| {
            let traversal_id = json_str(row, "traversal_id");
            format!(
                r#"<li><a href="/frontier/graph/traversals/{href}"><code>{id}</code></a> · {question}</li>"#,
                href = urlencode_path(traversal_id),
                id = escape_html(traversal_id),
                question = escape_html(json_str(row, "question")),
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

async fn page_frontier_graph(State(state): State<AppState>) -> Response {
    let payload = early_ad_v33_frontiergraph_payload(&state.repo_path);
    let summary = payload.get("summary").unwrap_or(&serde_json::Value::Null);
    let hotspots = json_array(&payload, "hotspots")
        .iter()
        .take(12)
        .map(|row| {
            let node_id = json_str(row, "node_id");
            format!(
                r#"<tr><td><a href="/frontier/graph/nodes/{href}"><code>{id}</code></a></td><td>{kind}</td><td><code>{degree}</code></td><td>{label}</td></tr>"#,
                href = urlencode_path(node_id),
                id = escape_html(node_id),
                kind = escape_html(json_str(row, "kind")),
                degree = json_u64(row, "degree"),
                label = escape_html(json_str(row, "label")),
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let traversals = json_array(&payload, "saved_traversals")
        .iter()
        .take(12)
        .map(|row| {
            let traversal_id = json_str(row, "traversal_id");
            format!(
                r#"<tr><td><a href="/frontier/graph/traversals/{href}"><code>{id}</code></a></td><td><code>{question_id}</code></td><td>{question}</td><td><code>{nodes}</code> nodes</td></tr>"#,
                href = urlencode_path(traversal_id),
                id = escape_html(traversal_id),
                question_id = escape_html(json_str(row, "question_id")),
                question = escape_html(json_str(row, "question")),
                nodes = json_array_len(row, "node_sequence"),
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let derived_nodes = json_u64(summary, "derived_nodes");
    let derived_edges = json_u64(summary, "derived_edges");
    let saved = json_u64(summary, "saved_traversals");
    let body = format!(
        r#"<section class="wb-hero" aria-label="Early AD v3.3 FrontierGraph">
  <div class="wb-hero__grid">
    <div>
      <h2>Early AD v3.3 FrontierGraph</h2>
      <p>The frontier DAG is the primary object. Questions are saved traversals over findings, source records, evidence atoms, typed links, tensions, gaps, and proof refs.</p>
      <p>{derived_nodes} derived nodes, {derived_edges} derived edges, and {saved} saved traversals are available. The graph is derived and does not mutate trusted frontier state.</p>
      <div class="wb-action-row">
        <a class="wb-button" href="/frontier/graph.json">Open JSON</a>
        <a class="wb-button wb-button--quiet" href="/frontier/reviewer-demo">Reviewer demo</a>
        <a class="wb-button wb-button--quiet" href="/frontier/decision-grade">Decision-grade state</a>
      </div>
    </div>
    <div class="wb-status-panel" aria-label="FrontierGraph status">
      <div><span>status</span><strong>{status}</strong></div>
      <div><span>derived nodes</span><strong>{derived_nodes}</strong></div>
      <div><span>derived edges</span><strong>{derived_edges}</strong></div>
      <div><span>saved traversals</span><strong>{saved}</strong></div>
      <div><span>graph is derived</span><strong>true</strong></div>
    </div>
  </div>
</section>
<div class="wb-card">
  <h3>Boundary</h3>
  <p>The graph is derived. It does not claim treatment advice, clinical validity, target validation, external validation, benchmark outperformance, or scientific discovery.</p>
</div>
<div class="wb-card">
  <h3>Hotspots</h3>
  <table class="wb-table"><thead><tr><th>node</th><th>kind</th><th>degree</th><th>label</th></tr></thead><tbody>{hotspots}</tbody></table>
</div>
<div class="wb-card">
  <h3>Saved traversals</h3>
  <table class="wb-table"><thead><tr><th>traversal</th><th>question</th><th>text</th><th>size</th></tr></thead><tbody>{traversals}</tbody></table>
</div>"#,
        status = escape_html(json_str(&payload, "status")),
        derived_nodes = derived_nodes,
        derived_edges = derived_edges,
        saved = saved,
        hotspots = hotspots,
        traversals = traversals,
    );
    Html(shell(
        "frontier-graph",
        "Early AD v3.3 FrontierGraph · Vela Workbench",
        "Workbench",
        "Early AD v3.3 FrontierGraph",
        &body,
    ))
    .into_response()
}

async fn page_frontier_graph_json(State(state): State<AppState>) -> Response {
    Json(early_ad_v33_frontiergraph_payload(&state.repo_path)).into_response()
}

async fn page_frontier_graph_node_detail(
    State(state): State<AppState>,
    AxumPath(node_id): AxumPath<String>,
) -> Response {
    let wants_json = node_id.ends_with(".json");
    let clean_node_id = node_id
        .strip_suffix(".json")
        .unwrap_or(node_id.as_str())
        .to_string();
    let Some(payload) = frontier_graph_node_detail_payload(&state.repo_path, &clean_node_id) else {
        return if wants_json {
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "frontier graph node not found"})),
            )
                .into_response()
        } else {
            (
                StatusCode::NOT_FOUND,
                Html(shell(
                    "frontier-graph",
                    "FrontierGraph node not found · Vela Workbench",
                    "Workbench",
                    "FrontierGraph node not found",
                    "<div class=\"wb-card\"><p>Node not found.</p></div>",
                )),
            )
                .into_response()
        };
    };
    if wants_json {
        return Json(payload).into_response();
    }
    let node = payload.get("node").unwrap_or(&serde_json::Value::Null);
    let incoming = json_array(&payload, "incoming_edges");
    let outgoing = json_array(&payload, "outgoing_edges");
    let traversals = json_array(&payload, "saved_traversals");
    let body = format!(
        r#"<div class="wb-card">
  <h3>FrontierGraph node</h3>
  <p><code>{node_id}</code> · kind <code>{kind}</code></p>
  <p>{label}</p>
  <p>Path: <code>{path}</code></p>
</div>
<div class="wb-card">
  <h3>Saved traversals</h3>
  <ul>{traversal_links}</ul>
</div>
<div class="wb-card">
  <h3>Incoming edges</h3>
  <table class="wb-table"><thead><tr><th>source</th><th>relation</th><th>target</th><th>evidence</th></tr></thead><tbody>{incoming_rows}</tbody></table>
</div>
<div class="wb-card">
  <h3>Outgoing edges</h3>
  <table class="wb-table"><thead><tr><th>source</th><th>relation</th><th>target</th><th>evidence</th></tr></thead><tbody>{outgoing_rows}</tbody></table>
</div>
<div class="wb-card">
  <h3>Boundary</h3>
  <p>This node view is a derived graph lens. It does not claim treatment advice, clinical validity, target validation, external validation, benchmark outperformance, or scientific discovery.</p>
</div>"#,
        node_id = escape_html(json_str(node, "id")),
        kind = escape_html(json_str(node, "kind")),
        label = escape_html(json_str(node, "label")),
        path = escape_html(json_str(node, "path")),
        traversal_links = render_traversal_links(&traversals),
        incoming_rows = render_graph_edges(&incoming),
        outgoing_rows = render_graph_edges(&outgoing),
    );
    Html(shell(
        "frontier-graph",
        "FrontierGraph node · Vela Workbench",
        "Workbench",
        "FrontierGraph node",
        &body,
    ))
    .into_response()
}

async fn page_frontier_graph_traversal_detail(
    State(state): State<AppState>,
    AxumPath(traversal_id): AxumPath<String>,
) -> Response {
    let wants_json = traversal_id.ends_with(".json");
    let clean_traversal_id = traversal_id
        .strip_suffix(".json")
        .unwrap_or(traversal_id.as_str())
        .to_string();
    let Some(payload) =
        frontier_graph_traversal_detail_payload(&state.repo_path, &clean_traversal_id)
    else {
        return if wants_json {
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "frontier graph traversal not found"})),
            )
                .into_response()
        } else {
            (
                StatusCode::NOT_FOUND,
                Html(shell(
                    "frontier-graph",
                    "Saved traversal not found · Vela Workbench",
                    "Workbench",
                    "Saved traversal not found",
                    "<div class=\"wb-card\"><p>Traversal not found.</p></div>",
                )),
            )
                .into_response()
        };
    };
    if wants_json {
        return Json(payload).into_response();
    }
    let traversal = payload.get("traversal").unwrap_or(&serde_json::Value::Null);
    let sections = traversal
        .get("sections")
        .unwrap_or(&serde_json::Value::Null);
    let edges = json_array(&payload, "edges");
    let body = format!(
        r#"<div class="wb-card">
  <h3>Saved traversal</h3>
  <p><code>{traversal_id}</code> · question <code>{question_id}</code> · answer <code>{answer_id}</code></p>
  <p>{question}</p>
</div>
<div class="wb-grid">
  <div class="wb-card"><h3>Supporting findings</h3><ul>{supporting}</ul></div>
  <div class="wb-card"><h3>Counterweights</h3><ul>{counterweights}</ul></div>
  <div class="wb-card"><h3>Source records</h3><ul>{sources}</ul></div>
  <div class="wb-card"><h3>Evidence atoms</h3><ul>{atoms}</ul></div>
  <div class="wb-card"><h3>Dependency links</h3><ul>{links}</ul></div>
  <div class="wb-card"><h3>Evidence tensions</h3><ul>{tensions}</ul></div>
  <div class="wb-card"><h3>Gap tasks</h3><ul>{gaps}</ul></div>
  <div class="wb-card"><h3>Proof refs</h3><ul>{proof_refs}</ul></div>
</div>
<div class="wb-card">
  <h3>Traversal edges</h3>
  <table class="wb-table"><thead><tr><th>source</th><th>relation</th><th>target</th><th>evidence</th></tr></thead><tbody>{edge_rows}</tbody></table>
</div>
<div class="wb-card">
  <h3>Boundary</h3>
  <p>This traversal is a saved graph path over derived state. It does not claim treatment advice, clinical validity, target validation, external validation, benchmark outperformance, or scientific discovery.</p>
</div>"#,
        traversal_id = escape_html(json_str(traversal, "traversal_id")),
        question_id = escape_html(json_str(traversal, "question_id")),
        answer_id = escape_html(json_str(traversal, "answer_id")),
        question = escape_html(json_str(traversal, "question")),
        supporting = render_code_list(&json_string_array(sections, "supporting_findings")),
        counterweights = render_code_list(&json_string_array(sections, "counterweights")),
        sources = render_code_list(&json_string_array(sections, "source_records")),
        atoms = render_code_list(&json_string_array(sections, "evidence_atoms")),
        links = render_code_list(&json_string_array(sections, "dependency_links")),
        tensions = render_code_list(&json_string_array(sections, "evidence_tensions")),
        gaps = render_code_list(&json_string_array(sections, "gap_tasks")),
        proof_refs = render_code_list(&json_string_array(sections, "proof_refs")),
        edge_rows = render_graph_edges(&edges),
    );
    Html(shell(
        "frontier-graph",
        "Saved traversal · Vela Workbench",
        "Workbench",
        "Saved traversal",
        &body,
    ))
    .into_response()
}

async fn page_frontier_reviewer_demo(State(state): State<AppState>) -> Response {
    let payload = early_ad_v32_reviewer_demo_payload(&state.repo_path);
    let summary = payload.get("summary").unwrap_or(&serde_json::Value::Null);
    let questions = json_array(&payload, "questions");
    let rows = questions
        .iter()
        .map(|question| {
            let route = json_str(question, "route");
            let score = question
                .get("score_delta")
                .unwrap_or(&serde_json::Value::Null);
            format!(
                r#"<tr><td><a href="{route}"><code>{question_id}</code></a></td><td>{lane}</td><td>{question_text}</td><td><code>{delta}</code></td><td><code>{findings}</code> findings · <code>{atoms}</code> atoms · <code>{tensions}</code> tensions</td></tr>"#,
                route = escape_html(route),
                question_id = escape_html(json_str(question, "question_id")),
                lane = escape_html(json_str(question, "lane")),
                question_text = escape_html(json_str(question, "question")),
                delta = json_i64_at(score, &["total"]),
                findings = json_u64(question, "supporting_finding_count"),
                atoms = json_u64(question, "evidence_atom_count"),
                tensions = json_u64(question, "tension_count"),
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let body = format!(
        r#"<section class="wb-hero" aria-label="Early AD v3.2 reviewer demo">
  <div class="wb-hero__grid">
    <div>
      <h2>Early AD v3.2 reviewer demo</h2>
      <p>Start from a frozen question, inspect the bounded Vela answer trail, compare it with the matched baseline, then follow evidence, tensions, gaps, and proof refs.</p>
      <div class="wb-action-row">
        <a class="wb-button" href="/frontier/reviewer-demo.json">Open JSON</a>
        <a class="wb-button wb-button--quiet" href="/frontier/decision-grade">Decision-grade state</a>
        <a class="wb-button wb-button--quiet" href="/frontier/proof">Proof</a>
      </div>
      <p>{questions} frozen questions, {answers} answer trails, {baselines} baseline answers, {comparisons} comparison rows, and {briefs} decision briefs are available in this local demo.</p>
    </div>
    <div class="wb-status-panel" aria-label="Reviewer demo status">
      <div><span>status</span><strong>{status}</strong></div>
      <div><span>questions</span><strong>{questions}</strong></div>
      <div><span>answers</span><strong>{answers}</strong></div>
      <div><span>baselines</span><strong>{baselines}</strong></div>
      <div><span>comparisons</span><strong>{comparisons}</strong></div>
      <div><span>briefs</span><strong>{briefs}</strong></div>
    </div>
  </div>
</section>
<div class="wb-stats">
  {frozen_card}
  {answers_card}
  {baseline_card}
  {comparison_card}
  {brief_card}
</div>
<div class="wb-card">
  <h3>Boundary</h3>
  <p>This demo is review material. It does not claim treatment advice, clinical validity, target validation, external validation, benchmark outperformance, or scientific discovery.</p>
</div>
<div class="wb-card">
  <h3>Answered reviewer questions</h3>
  <table class="wb-table">
    <thead><tr><th>question</th><th>lane</th><th>text</th><th>delta</th><th>trail state</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div>"#,
        status = escape_html(json_str(&payload, "status")),
        questions = json_u64(summary, "frozen_questions"),
        answers = json_u64(summary, "answer_trails"),
        baselines = json_u64(summary, "baseline_answers"),
        comparisons = json_u64(summary, "comparison_rows"),
        briefs = json_u64(summary, "decision_briefs"),
        frozen_card = render_v32_summary_card(
            "frozen questions",
            json_u64(summary, "frozen_questions"),
            ""
        ),
        answers_card =
            render_v32_summary_card("answer trails", json_u64(summary, "answer_trails"), ""),
        baseline_card = render_v32_summary_card(
            "baseline answers",
            json_u64(summary, "baseline_answers"),
            ""
        ),
        comparison_card =
            render_v32_summary_card("comparison rows", json_u64(summary, "comparison_rows"), ""),
        brief_card =
            render_v32_summary_card("decision briefs", json_u64(summary, "decision_briefs"), ""),
        rows = rows,
    );
    Html(shell(
        "frontier-reviewer-demo",
        "Early AD v3.2 reviewer demo · Vela Workbench",
        "Workbench",
        "Early AD v3.2 reviewer demo",
        &body,
    ))
    .into_response()
}

async fn page_frontier_reviewer_demo_json(State(state): State<AppState>) -> Response {
    Json(early_ad_v32_reviewer_demo_payload(&state.repo_path)).into_response()
}

async fn page_frontier_reviewer_demo_question_detail(
    State(state): State<AppState>,
    AxumPath(question_id): AxumPath<String>,
) -> Response {
    let wants_json = question_id.ends_with(".json");
    let clean_question_id = question_id
        .strip_suffix(".json")
        .unwrap_or(question_id.as_str())
        .to_string();
    let Some(payload) =
        early_ad_v32_reviewer_demo_question_payload(&state.repo_path, &clean_question_id)
    else {
        return if wants_json {
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "reviewer demo question not found"})),
            )
                .into_response()
        } else {
            (
                StatusCode::NOT_FOUND,
                Html(shell(
                    "frontier-reviewer-demo",
                    "Reviewer demo question not found · Vela Workbench",
                    "Workbench",
                    "Reviewer demo question not found",
                    "<div class=\"wb-card\"><p>Question not found.</p></div>",
                )),
            )
                .into_response()
        };
    };
    if wants_json {
        return Json(payload).into_response();
    }

    let answer = payload.get("answer").unwrap_or(&serde_json::Value::Null);
    let baseline = payload.get("baseline").unwrap_or(&serde_json::Value::Null);
    let comparison = payload
        .get("comparison")
        .unwrap_or(&serde_json::Value::Null);
    let score = comparison
        .get("score_delta")
        .unwrap_or(&serde_json::Value::Null);
    let brief = payload
        .get("decision_brief")
        .unwrap_or(&serde_json::Value::Null);
    let body = format!(
        r#"<div class="wb-card">
  <h3>Question</h3>
  <p>{question}</p>
  <p><code>{question_id}</code> · lane <code>{lane}</code> · brief <code>{brief_path}</code></p>
</div>
<div class="wb-card">
  <h3>Vela answer trail</h3>
  <blockquote>{answer_text}</blockquote>
  <p>Answer: <code>{answer_id}</code>. Trail: <code>{trail}</code>.</p>
</div>
<div class="wb-card">
  <h3>Matched baseline</h3>
  <blockquote>{baseline_text}</blockquote>
  <p>Baseline: <code>{baseline_id}</code>. Kind: <code>{baseline_kind}</code>.</p>
</div>
<div class="wb-card">
  <h3>Score row</h3>
  <p>Local proxy score: Vela <code>{vela_total}</code>, baseline <code>{baseline_total}</code>, delta <code>{delta}</code>. Interpretation: <code>{interpretation}</code>.</p>
  <table class="wb-table">
    <thead><tr><th>dimension</th><th>Vela</th><th>baseline</th><th>basis</th></tr></thead>
    <tbody>{dimension_rows}</tbody>
  </table>
</div>
<div class="wb-grid">
  <div class="wb-card"><h3>Supporting findings</h3><ul>{supporting}</ul></div>
  <div class="wb-card"><h3>Counterweights</h3><ul>{counterweights}</ul></div>
  <div class="wb-card"><h3>Source records</h3><ul>{sources}</ul></div>
  <div class="wb-card"><h3>Evidence atoms</h3><ul>{atoms}</ul></div>
  <div class="wb-card"><h3>Dependency links</h3><ul>{links}</ul></div>
  <div class="wb-card"><h3>Evidence tensions</h3><ul>{tensions}</ul></div>
  <div class="wb-card"><h3>Gap tasks</h3><ul>{gaps}</ul></div>
  <div class="wb-card"><h3>Proof refs</h3><ul>{proof_refs}</ul></div>
</div>
<div class="wb-card">
  <h3>Caveats</h3>
  <ul>{caveats}</ul>
</div>
<div class="wb-card">
  <h3>Next review action</h3>
  <p>{next_action}</p>
</div>
<div class="wb-card">
  <h3>Boundary</h3>
  <p>This question detail is review material. It does not claim treatment advice, clinical validity, target validation, external validation, benchmark outperformance, or scientific discovery.</p>
</div>"#,
        question = escape_html(json_str(answer, "question")),
        question_id = escape_html(json_str(&payload, "question_id")),
        lane = escape_html(json_str(answer, "lane")),
        brief_path = escape_html(json_str(brief, "brief_path")),
        answer_text = escape_html(json_str(answer, "answer")),
        answer_id = escape_html(json_str(answer, "answer_id")),
        trail = escape_html(json_str(answer, "v31_trail_id")),
        baseline_text = escape_html(json_str(baseline, "baseline_answer")),
        baseline_id = escape_html(json_str(baseline, "baseline_id")),
        baseline_kind = escape_html(json_str(baseline, "baseline_kind")),
        vela_total = json_i64_at(score, &["vela_total"]),
        baseline_total = json_i64_at(score, &["baseline_total"]),
        delta = json_i64_at(score, &["total"]),
        interpretation = escape_html(json_str(score, "interpretation")),
        dimension_rows = render_dimension_scores(comparison),
        supporting = render_code_list(&json_string_array(answer, "supporting_finding_ids")),
        counterweights = render_code_list(&json_string_array(answer, "counterweight_finding_ids")),
        sources = render_code_list(&json_string_array(answer, "source_ids")),
        atoms = render_code_list(&json_string_array(answer, "evidence_atom_ids")),
        links = render_code_list(&json_string_array(answer, "dependency_link_ids")),
        tensions = render_code_list(&json_string_array(answer, "tension_ids")),
        gaps = render_code_list(&json_string_array(answer, "gap_task_ids")),
        proof_refs = render_code_list(&json_string_array(answer, "proof_packet_refs")),
        caveats = render_code_list(&json_string_array(answer, "caveats")),
        next_action = escape_html(json_str(answer, "next_review_action")),
    );
    Html(shell(
        "frontier-reviewer-demo",
        "Early AD v3.2 reviewer question · Vela Workbench",
        "Workbench",
        &format!("Reviewer question: {}", escape_html(&clean_question_id)),
        &body,
    ))
    .into_response()
}

fn answer_path_query(answer_path: &str) -> String {
    if answer_path.is_empty() {
        String::new()
    } else {
        format!("?answer_path={}", urlencode_path(answer_path))
    }
}

fn answer_path_return_panel(answer_path: &str) -> String {
    if answer_path.is_empty() {
        return String::new();
    }
    let path = urlencode_path(answer_path);
    format!(
        r#"<div class="wb-card">
  <h3>Return to answer path</h3>
  <p>This page was opened from <code>{answer_path}</code>.</p>
  <p>answer path source context and verification records stay visible while inspecting linked findings and sources.</p>
  <div class="wb-action-row">
    <a class="wb-button" href="/frontier/answer-paths/{path}">Answer path</a>
    <a class="wb-button wb-button--quiet" href="/frontier/questions/{path}">Question</a>
  </div>
</div>"#,
        answer_path = escape_html(answer_path),
        path = path,
    )
}

fn render_finding_link_from_str_with_answer_path(id: &str, answer_path: &str) -> String {
    format!(
        r#"<a class="wb-chip" href="/findings/{href}{query}">{id}</a>"#,
        href = urlencode_path(id),
        query = answer_path_query(answer_path),
        id = escape_html(id)
    )
}

async fn page_frontier_answer_book(State(state): State<AppState>) -> Response {
    let payload = frontier_answer_book_payload(&state.repo_path);
    let summary = payload.get("summary").unwrap_or(&serde_json::Value::Null);
    let answers = payload
        .get("answers")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let answer_cards = answers
        .iter()
        .map(|answer| {
            let support = answer
                .get("supporting_finding_ids")
                .and_then(serde_json::Value::as_array)
                .map(|ids| render_finding_links(ids))
                .unwrap_or_default();
            let counterweights = answer
                .get("counterweight_finding_ids")
                .and_then(serde_json::Value::as_array)
                .map(|ids| render_finding_links(ids))
                .unwrap_or_default();
            let coverage = answer.get("coverage").unwrap_or(&serde_json::Value::Null);
            format!(
                r#"<div class="wb-card">
  <h3>{id}</h3>
  <p>{question}</p>
  <blockquote>{answer_text}</blockquote>
  <p><strong>Interpretation</strong>: {interpretation}</p>
  <p><span class="wb-chip wb-chip--ok">support</span> {support}</p>
  <p><span class="wb-chip wb-chip--warn">counterweight</span> {counterweights}</p>
  <p>Coverage: <code>{findings}</code> findings · <code>{sources}</code> sources · <code>{atoms}</code> evidence atoms.</p>
</div>"#,
                id = escape_html(json_str(answer, "id")),
                question = escape_html(json_str(answer, "question")),
                answer_text = escape_html(json_str(answer, "answer")),
                interpretation = escape_html(json_str(answer, "interpretation")),
                support = support,
                counterweights = counterweights,
                findings = json_u64(coverage, "finding_count"),
                sources = json_u64(coverage, "source_count"),
                atoms = json_u64(coverage, "evidence_atom_count"),
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let answer_count = json_u64(summary, "answer_count");
    let support_refs = json_u64(summary, "supporting_finding_refs");
    let counterweight_refs = json_u64(summary, "counterweight_finding_refs");
    let status = json_str(&payload, "status");
    let body = format!(
        r#"<section class="wb-hero" aria-label="Frontier answer book">
  <div class="wb-hero__grid">
    <div>
      <h2>Anti-amyloid answer book</h2>
      <p>Eight bounded answers summarize the completed frontier. Each answer keeps support, counterweights, source coverage, and claim boundaries visible.</p>
      <div class="wb-action-row">
        <a class="wb-button" href="/frontier/answer-book.json">Open JSON</a>
        <a class="wb-button wb-button--quiet" href="/frontier/use-map">Use map</a>
        <a class="wb-button wb-button--quiet" href="/proof">Proof</a>
        <a class="wb-button wb-button--quiet" href="/demo/external-proof-loop">External loop</a>
      </div>
    </div>
    <div class="wb-status-panel" aria-label="Answer book status">
      <div><span>status</span><strong>{status}</strong></div>
      <div><span>answers</span><strong>{answer_count}</strong></div>
      <div><span>support refs</span><strong>{support_refs}</strong></div>
      <div><span>counterweights</span><strong>{counterweight_refs}</strong></div>
      <div><span>claims_external_validation</span><strong>false</strong></div>
      <div><span>claims_treatment_advice</span><strong>false</strong></div>
    </div>
  </div>
</section>
<div class="wb-card">
  <h3>Boundary</h3>
  <p>Answer-book status is local frontier evidence. It does not claim treatment advice, clinical validity, target validation, scientific discovery, benchmark outperformance, or external validation.</p>
</div>
{answer_cards}"#,
        status = escape_html(status),
        answer_count = answer_count,
        support_refs = support_refs,
        counterweight_refs = counterweight_refs,
        answer_cards = answer_cards,
    );
    Html(shell(
        "frontier-answer-book",
        "Anti-amyloid answer book · Vela Workbench",
        "Workbench",
        "Anti-amyloid answer book",
        &body,
    ))
    .into_response()
}

async fn page_frontier_answer_book_json(State(state): State<AppState>) -> Response {
    Json(frontier_answer_book_payload(&state.repo_path)).into_response()
}

async fn page_frontier_use_map(State(state): State<AppState>) -> Response {
    let payload = frontier_use_map_payload(&state.repo_path);
    let summary = payload.get("summary").unwrap_or(&serde_json::Value::Null);
    let questions = payload
        .get("questions")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let question_cards = questions
        .iter()
        .map(|question| {
            let starters = question
                .get("top_finding_ids")
                .and_then(serde_json::Value::as_array)
                .map(|ids| render_finding_links(ids))
                .unwrap_or_default();
            format!(
                r#"<div class="wb-card">
  <h3>{id}</h3>
  <p>{question_text}</p>
  <p><span class="wb-chip wb-chip--ok">{status}</span> <code>{findings}</code> findings · <code>{linked}</code> linked · <code>{sources}</code> sources · <code>{atoms}</code> evidence atoms.</p>
  <p>Start with: {starters}</p>
</div>"#,
                id = escape_html(json_str(question, "id")),
                question_text = escape_html(json_str(question, "question")),
                status = escape_html(json_str(question, "status")),
                findings = json_u64(question, "finding_count"),
                linked = json_u64(question, "linked_finding_count"),
                sources = json_u64(question, "source_count"),
                atoms = json_u64(question, "evidence_atom_count"),
                starters = starters,
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let entrypoints = payload
        .get("operator_entrypoints")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|entry| {
            format!(
                r#"<tr><td>{id}</td><td><code>{command}</code></td><td>{purpose}</td></tr>"#,
                id = escape_html(json_str(entry, "id")),
                command = escape_html(json_str(entry, "command")),
                purpose = escape_html(json_str(entry, "purpose")),
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let status = json_str(&payload, "status");
    let question_count = json_u64(summary, "question_count");
    let covered = json_u64(summary, "covered_question_count");
    let findings = json_u64(summary, "findings");
    let sources = json_u64(summary, "sources");
    let atoms = json_u64(summary, "evidence_atoms");
    let body = format!(
        r#"<section class="wb-hero" aria-label="Frontier use map">
  <div class="wb-hero__grid">
    <div>
      <h2>Anti-amyloid use map</h2>
      <p>Start from a scientific question, then inspect the relevant findings, sources, evidence atoms, answer-book entries, and proof path.</p>
      <div class="wb-action-row">
        <a class="wb-button" href="/frontier/use-map.json">Open JSON</a>
        <a class="wb-button wb-button--quiet" href="/frontier/answer-book">Answer book</a>
        <a class="wb-button wb-button--quiet" href="/findings">Findings</a>
        <a class="wb-button wb-button--quiet" href="/sources">Sources</a>
      </div>
    </div>
    <div class="wb-status-panel" aria-label="Use map status">
      <div><span>status</span><strong>{status}</strong></div>
      <div><span>questions</span><strong>{covered}/{question_count}</strong></div>
      <div><span>findings</span><strong>{findings}</strong></div>
      <div><span>sources</span><strong>{sources}</strong></div>
      <div><span>evidence atoms</span><strong>{atoms}</strong></div>
      <div><span>claims_external_validation</span><strong>false</strong></div>
    </div>
  </div>
</section>
{question_cards}
<div class="wb-card">
  <h3>Operator entrypoints</h3>
  <table class="wb-table">
    <thead><tr><th>id</th><th>command</th><th>purpose</th></tr></thead>
    <tbody>{entrypoints}</tbody>
  </table>
</div>"#,
        status = escape_html(status),
        covered = covered,
        question_count = question_count,
        findings = findings,
        sources = sources,
        atoms = atoms,
        question_cards = question_cards,
        entrypoints = entrypoints,
    );
    Html(shell(
        "frontier-use-map",
        "Anti-amyloid use map · Vela Workbench",
        "Workbench",
        "Anti-amyloid use map",
        &body,
    ))
    .into_response()
}

async fn page_frontier_use_map_json(State(state): State<AppState>) -> Response {
    Json(frontier_use_map_payload(&state.repo_path)).into_response()
}

fn answer_path_by_id(payload: &serde_json::Value, answer_id: &str) -> Option<serde_json::Value> {
    payload
        .get("paths")
        .and_then(serde_json::Value::as_array)
        .and_then(|paths| {
            paths
                .iter()
                .find(|path| json_str(path, "answer_id") == answer_id)
                .cloned()
        })
}

fn answer_path_with_boundary(
    payload: &serde_json::Value,
    answer_id: &str,
) -> Option<serde_json::Value> {
    let mut path = answer_path_by_id(payload, answer_id)?;
    if let Some(obj) = path.as_object_mut() {
        obj.insert(
            "claim_boundary".to_string(),
            payload
                .get("claim_boundary")
                .cloned()
                .unwrap_or_else(|| serde_json::json!({})),
        );
        obj.insert(
            "index_backing".to_string(),
            payload
                .get("index_backing")
                .cloned()
                .unwrap_or_else(|| serde_json::json!({})),
        );
    }
    Some(path)
}

fn frontier_question_by_id(
    payload: &serde_json::Value,
    question_id: &str,
) -> Option<serde_json::Value> {
    payload
        .get("questions")
        .and_then(serde_json::Value::as_array)
        .and_then(|questions| {
            questions
                .iter()
                .find(|question| json_str(question, "question_id") == question_id)
                .cloned()
        })
}

fn frontier_question_with_boundary(
    payload: &serde_json::Value,
    question_id: &str,
) -> Option<serde_json::Value> {
    let mut question = frontier_question_by_id(payload, question_id)?;
    if let Some(obj) = question.as_object_mut() {
        obj.insert(
            "claim_boundary".to_string(),
            payload
                .get("claim_boundary")
                .cloned()
                .unwrap_or_else(|| serde_json::json!({})),
        );
        obj.insert(
            "index_backing".to_string(),
            payload
                .get("index_backing")
                .cloned()
                .unwrap_or_else(|| serde_json::json!({})),
        );
    }
    Some(question)
}

async fn page_frontier_questions(State(state): State<AppState>) -> Response {
    let payload = frontier_questions_payload(&state.repo_path);
    let decision_paths = frontier_decision_paths_payload(&state.repo_path);
    let summary = payload.get("summary").unwrap_or(&serde_json::Value::Null);
    let mut questions = payload
        .get("questions")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    questions.sort_by_key(|question| {
        let question_id = json_str(question, "question_id");
        decision_path_by_id(&decision_paths, question_id)
            .map(|decision| json_u64(&decision, "reviewer_priority"))
            .unwrap_or(u64::MAX)
    });
    let cards = questions
        .iter()
        .map(|question| {
            let question_id = json_str(question, "question_id");
            let decision = decision_path_by_id(&decision_paths, question_id)
                .unwrap_or_else(|| serde_json::json!({}));
            let verification = decision
                .get("verification_context")
                .unwrap_or(&serde_json::Value::Null);
            let health = question
                .get("source_health")
                .unwrap_or(&serde_json::Value::Null);
            let support = question
                .get("supporting_findings")
                .and_then(serde_json::Value::as_array)
                .map_or(0, Vec::len);
            let counter = question
                .get("counterweight_findings")
                .and_then(serde_json::Value::as_array)
                .map_or(0, Vec::len);
            format!(
                r#"<div class="wb-card">
  <h3>{id}</h3>
  <p>{question_text}</p>
  <p><span class="wb-chip wb-chip--ok">support</span> <code>{support}</code> findings · <span class="wb-chip wb-chip--warn">counterweight</span> <code>{counter}</code> findings.</p>
  <p>reviewer priority: <code>{priority}</code> · verification records: <code>{verification_records}</code>.</p>
  <p>source health: <code>{stable}</code> stable · <code>{preserved}</code> preserved · next action: inspect answer path.</p>
  <div class="wb-action-row">
    <a class="wb-button" href="/frontier/questions/{href}">Open question</a>
    <a class="wb-button wb-button--quiet" href="{answer_path}">Answer path</a>
    <a class="wb-button wb-button--quiet" href="{answer_path_json}">JSON</a>
  </div>
</div>"#,
                id = escape_html(question_id),
                question_text = escape_html(json_str(question, "question")),
                support = support,
                counter = counter,
                priority = json_u64(&decision, "reviewer_priority"),
                verification_records = json_u64(verification, "verification_records"),
                stable = json_u64(health, "stable_sources"),
                preserved = json_u64(health, "preserved_locator_only_sources"),
                href = urlencode_path(question_id),
                answer_path = escape_html(json_str(question, "answer_path_route")),
                answer_path_json = escape_html(json_str(question, "answer_path_json_route")),
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let index_backing = render_frontier_index_backing(&payload);
    let body = format!(
        r#"<section class="wb-hero" aria-label="Anti-amyloid questions">
  <div class="wb-hero__grid">
    <div>
      <h2>Anti-amyloid questions</h2>
      <p>Start from a question, then inspect the answer, supporting findings, counterweights, source health, caveats, and next action. The list uses reviewer-priority ordering from source debt, answer confidence, verification records, and return history.</p>
      <div class="wb-action-row">
        <a class="wb-button" href="/frontier/questions.json">Open JSON</a>
        <a class="wb-button wb-button--quiet" href="/frontier/answer-paths">Answer paths</a>
        <a class="wb-button wb-button--quiet" href="/frontier/answer-book">Answer book</a>
        <a class="wb-button wb-button--quiet" href="/frontier/use-map">Use map</a>
      </div>
    </div>
    <div class="wb-status-panel" aria-label="Question status">
      <div><span>questions</span><strong>{question_count}</strong></div>
      <div><span>answer paths</span><strong>{answer_path_count}</strong></div>
      <div><span>stable-majority paths</span><strong>{stable_majority}</strong></div>
      <div><span>visible source debt</span><strong>{visible_debt}</strong></div>
      <div><span>claims_external_validation</span><strong>false</strong></div>
    </div>
  </div>
</section>
{index_backing}
{cards}"#,
        question_count = json_u64(summary, "question_count"),
        answer_path_count = json_u64(summary, "answer_path_count"),
        stable_majority = json_u64(summary, "paths_with_stable_source_majority"),
        visible_debt = json_u64(summary, "paths_with_visible_source_debt"),
        index_backing = index_backing,
        cards = cards,
    );
    Html(shell(
        "frontier-questions",
        "Anti-amyloid questions · Vela Workbench",
        "Workbench",
        "Anti-amyloid questions",
        &body,
    ))
    .into_response()
}

async fn page_frontier_questions_json(State(state): State<AppState>) -> Response {
    Json(frontier_questions_payload(&state.repo_path)).into_response()
}

async fn page_frontier_question_detail(
    State(state): State<AppState>,
    AxumPath(question_id): AxumPath<String>,
) -> Response {
    let payload = frontier_questions_payload(&state.repo_path);
    let wants_json = question_id.ends_with(".json");
    let clean_question_id = question_id
        .strip_suffix(".json")
        .unwrap_or(question_id.as_str())
        .to_string();
    if wants_json {
        return match frontier_question_with_boundary(&payload, &clean_question_id) {
            Some(question) => Json(question).into_response(),
            None => (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "question not found"})),
            )
                .into_response(),
        };
    }
    let Some(question) = frontier_question_by_id(&payload, &clean_question_id) else {
        return (
            StatusCode::NOT_FOUND,
            Html(shell(
                "frontier-questions",
                "Question not found · Vela Workbench",
                "Workbench",
                "Question not found",
                "<div class=\"wb-card\"><p>Question not found.</p></div>",
            )),
        )
            .into_response();
    };
    let health = question
        .get("source_health")
        .unwrap_or(&serde_json::Value::Null);
    let support = question
        .get("supporting_findings")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|finding| render_finding_link_from_str(json_str(finding, "finding_id")))
        .collect::<Vec<_>>()
        .join(" ");
    let counterweights = question
        .get("counterweight_findings")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|finding| render_finding_link_from_str(json_str(finding, "finding_id")))
        .collect::<Vec<_>>()
        .join(" ");
    let caveats = question
        .get("remaining_caveats")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(serde_json::Value::as_str)
        .map(|caveat| format!("<li>{}</li>", escape_html(caveat)))
        .collect::<Vec<_>>()
        .join("");
    let body = format!(
        r#"<section class="wb-hero" aria-label="Frontier question">
  <div class="wb-hero__grid">
    <div>
      <h2>Question: {id}</h2>
      <p>{question_text}</p>
      <blockquote>{answer}</blockquote>
      <div class="wb-action-row">
        <a class="wb-button" href="/frontier/questions/{href}.json">Open JSON</a>
        <a class="wb-button wb-button--quiet" href="{answer_path}">Answer path</a>
        <a class="wb-button wb-button--quiet" href="/frontier/questions">All questions</a>
      </div>
    </div>
    <div class="wb-status-panel" aria-label="Question source health">
      <div><span>source health</span><strong>{stable}/{total}</strong></div>
      <div><span>preserved</span><strong>{preserved}</strong></div>
      <div><span>missing</span><strong>{missing}</strong></div>
      <div><span>claims_external_validation</span><strong>false</strong></div>
    </div>
  </div>
</section>
<div class="wb-card">
  <h3>supporting findings</h3>
  <p>{support}</p>
  <h3>counterweights</h3>
  <p>{counterweights}</p>
</div>
<div class="wb-card">
  <h3>remaining caveats</h3>
  <ul>{caveats}</ul>
</div>"#,
        id = escape_html(json_str(&question, "question_id")),
        href = urlencode_path(json_str(&question, "question_id")),
        question_text = escape_html(json_str(&question, "question")),
        answer = escape_html(json_str(&question, "answer")),
        answer_path = escape_html(json_str(&question, "answer_path_route")),
        stable = json_u64(health, "stable_sources"),
        total = json_u64(health, "total_sources"),
        preserved = json_u64(health, "preserved_locator_only_sources"),
        missing = json_u64(health, "missing_locator_sources"),
        support = support,
        counterweights = counterweights,
        caveats = caveats,
    );
    Html(shell(
        "frontier-questions",
        "Frontier question · Vela Workbench",
        "Workbench",
        "Frontier question",
        &body,
    ))
    .into_response()
}

async fn page_frontier_answer_paths(State(state): State<AppState>) -> Response {
    let payload = frontier_answer_paths_payload(&state.repo_path);
    let summary = payload.get("summary").unwrap_or(&serde_json::Value::Null);
    let paths = payload
        .get("paths")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let cards = paths
        .iter()
        .map(|path| {
            let health = path
                .get("locator_health")
                .unwrap_or(&serde_json::Value::Null);
            format!(
                r#"<div class="wb-card">
  <h3>{id}</h3>
  <p>{question}</p>
  <p><span class="wb-chip wb-chip--ok">support</span> <code>{support}</code> findings · <span class="wb-chip wb-chip--warn">counterweight</span> <code>{counter}</code> findings.</p>
  <p>source trails: <code>{sources}</code> sources · <code>{atoms}</code> evidence atoms · locator health <code>{stable}</code> stable / <code>{preserved}</code> preserved.</p>
  <div class="wb-action-row">
    <a class="wb-button" href="/frontier/answer-paths/{href}">Open path</a>
    <a class="wb-button wb-button--quiet" href="/frontier/answer-paths/{href}.json">JSON</a>
  </div>
</div>"#,
                id = escape_html(json_str(path, "answer_id")),
                question = escape_html(json_str(path, "question")),
                support = path
                    .get("supporting_findings")
                    .and_then(serde_json::Value::as_array)
                    .map_or(0, Vec::len),
                counter = path
                    .get("counterweight_findings")
                    .and_then(serde_json::Value::as_array)
                    .map_or(0, Vec::len),
                sources = path
                    .get("source_trails")
                    .and_then(serde_json::Value::as_array)
                    .map_or(0, Vec::len),
                atoms = path
                    .get("evidence_atoms")
                    .and_then(serde_json::Value::as_array)
                    .map_or(0, Vec::len),
                stable = json_u64(health, "stable_sources"),
                preserved = json_u64(health, "preserved_locator_only_sources"),
                href = urlencode_path(json_str(path, "answer_id")),
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let index_backing = render_frontier_index_backing(&payload);
    let body = format!(
        r#"<section class="wb-hero" aria-label="Anti-amyloid answer paths">
  <div class="wb-hero__grid">
    <div>
      <h2>Anti-amyloid answer paths</h2>
      <p>Each answer path joins the bounded answer to support, counterweights, source trails, evidence atoms, locator health, remaining caveats, and next actions.</p>
      <div class="wb-action-row">
        <a class="wb-button" href="/frontier/answer-paths.json">Open JSON</a>
        <a class="wb-button wb-button--quiet" href="/frontier/answer-book">Answer book</a>
        <a class="wb-button wb-button--quiet" href="/frontier/use-map">Use map</a>
      </div>
    </div>
    <div class="wb-status-panel" aria-label="Answer path status">
      <div><span>paths</span><strong>{path_count}</strong></div>
      <div><span>support refs</span><strong>{support_refs}</strong></div>
      <div><span>counterweights</span><strong>{counter_refs}</strong></div>
      <div><span>source refs</span><strong>{source_refs}</strong></div>
      <div><span>evidence atoms</span><strong>{atom_refs}</strong></div>
      <div><span>claims_external_validation</span><strong>false</strong></div>
    </div>
  </div>
</section>
{index_backing}
{cards}"#,
        path_count = json_u64(summary, "path_count"),
        support_refs = json_u64(summary, "total_supporting_finding_refs"),
        counter_refs = json_u64(summary, "total_counterweight_finding_refs"),
        source_refs = json_u64(summary, "total_source_refs"),
        atom_refs = json_u64(summary, "total_evidence_atom_refs"),
        index_backing = index_backing,
        cards = cards,
    );
    Html(shell(
        "frontier-answer-paths",
        "Anti-amyloid answer paths · Vela Workbench",
        "Workbench",
        "Anti-amyloid answer paths",
        &body,
    ))
    .into_response()
}

async fn page_frontier_answer_paths_json(State(state): State<AppState>) -> Response {
    Json(frontier_answer_paths_payload(&state.repo_path)).into_response()
}

fn frontier_decision_grade_payload(repo_path: &Path) -> serde_json::Value {
    load_frontier_json(
        repo_path,
        "factory/early-ad-v31-decision-grade-frontier.v1.json",
    )
    .unwrap_or_else(|| {
        serde_json::json!({
            "schema": "vela.early_ad_v31_decision_grade_frontier.v1",
            "ok": false,
            "status": "missing",
            "summary": {
                "high_weight_claims": 0,
                "explicit_evidence_tensions": 0,
                "gap_tasks": 0,
                "frozen_benchmark_questions": 0,
                "decision_trails": 0
            },
            "decision_trails": [],
            "claim_boundary": {
                "claims_external_validation": false,
                "claims_benchmark_outperformance": false,
                "claims_treatment_advice": false,
                "claims_target_validation": false,
                "claims_clinical_validity": false,
                "claims_scientific_discovery": false,
                "mutates_trusted_frontier_state": false
            }
        })
    })
}

async fn page_frontier_decision_grade(State(state): State<AppState>) -> Response {
    let payload = frontier_decision_grade_payload(&state.repo_path);
    let summary = payload.get("summary").unwrap_or(&serde_json::Value::Null);
    let trails = payload
        .get("decision_trails")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let trail_cards = trails
        .iter()
        .take(10)
        .map(|trail| {
            let findings = trail
                .get("supporting_finding_ids")
                .and_then(serde_json::Value::as_array)
                .cloned()
                .unwrap_or_default();
            let finding_links = findings
                .iter()
                .take(5)
                .filter_map(serde_json::Value::as_str)
                .map(render_finding_link_from_str)
                .collect::<Vec<_>>()
                .join(" ");
            let proof_ref = trail
                .get("proof_packet_refs")
                .and_then(serde_json::Value::as_array)
                .and_then(|refs| refs.first())
                .and_then(serde_json::Value::as_str)
                .unwrap_or("projects/anti-amyloid-translation/proof/latest.json");
            format!(
                r#"<div class="wb-card">
  <h3>{slug}</h3>
  <p>{question}</p>
  <p><code>{findings}</code> findings · <code>{atoms}</code> evidence atoms · <code>{sources}</code> sources · <code>{tensions}</code> tensions · <code>{gap_tasks}</code> gap tasks.</p>
  <p>{finding_links}</p>
  <p>proof: <code>{proof_ref}</code></p>
  <div class="wb-action-row">
    <a class="wb-button" href="/frontier/decision-grade/{href}">Open trail</a>
    <a class="wb-button wb-button--quiet" href="/frontier/decision-grade/{href}.json">JSON</a>
  </div>
</div>"#,
                slug = escape_html(json_str(trail, "slug")),
                question = escape_html(json_str(trail, "question")),
                findings = json_array_len(trail, "supporting_finding_ids"),
                atoms = json_array_len(trail, "evidence_atom_ids"),
                sources = json_array_len(trail, "source_ids"),
                tensions = json_array_len(trail, "tension_ids"),
                gap_tasks = json_array_len(trail, "gap_task_ids"),
                finding_links = finding_links,
                proof_ref = escape_html(proof_ref),
                href = urlencode_path(json_str(trail, "slug")),
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let lane_rows = payload
        .get("summary")
        .and_then(|summary| summary.get("lanes"))
        .and_then(serde_json::Value::as_object)
        .map(|lanes| {
            lanes
                .iter()
                .map(|(lane, count)| {
                    format!(
                        r#"<tr><td><code>{lane}</code></td><td>{count}</td></tr>"#,
                        lane = escape_html(lane),
                        count = count.as_u64().unwrap_or(0),
                    )
                })
                .collect::<Vec<_>>()
                .join("")
        })
        .unwrap_or_else(|| r#"<tr><td colspan="2">No lane summary.</td></tr>"#.to_string());
    let status = json_str(&payload, "status");
    let body = format!(
        r#"<section class="wb-hero" aria-label="Decision-grade frontier">
  <div class="wb-hero__grid">
    <div>
      <h2>Decision-grade frontier</h2>
      <p>Early AD v3.1 turns the large source lake and trusted frontier shards into reviewable decision trails. It does not claim treatment advice, clinical validity, target validation, external validation, benchmark outperformance, or scientific discovery.</p>
      <div class="wb-action-row">
        <a class="wb-button" href="/frontier/decision-grade.json">Open JSON</a>
        <a class="wb-button wb-button--quiet" href="/frontier/questions">Questions</a>
        <a class="wb-button wb-button--quiet" href="/frontier/answer-paths">Answer paths</a>
        <a class="wb-button wb-button--quiet" href="/proof">Proof</a>
      </div>
    </div>
    <div class="wb-status-panel" aria-label="Decision-grade status">
      <div><span>status</span><strong>{status}</strong></div>
      <div><span>claims</span><strong>{claims}</strong></div>
      <div><span>tensions</span><strong>{tensions}</strong></div>
      <div><span>gap tasks</span><strong>{gap_tasks}</strong></div>
      <div><span>benchmark questions</span><strong>{questions}</strong></div>
      <div><span>decision trails</span><strong>{trails}</strong></div>
    </div>
  </div>
</section>
<div class="wb-stats">
  <div><div class="wb-stat__num">{claims}</div><div class="wb-stat__label">100 high-weight claims</div></div>
  <div><div class="wb-stat__num">{tensions}</div><div class="wb-stat__label">50 explicit evidence tensions</div></div>
  <div><div class="wb-stat__num">{gap_tasks}</div><div class="wb-stat__label">50 gap tasks</div></div>
  <div><div class="wb-stat__num">{questions}</div><div class="wb-stat__label">25 frozen benchmark questions</div></div>
  <div><div class="wb-stat__num">{trails}</div><div class="wb-stat__label">10 decision trails</div></div>
</div>
<div class="wb-card">
  <h3>Boundary</h3>
  <p>This surface is read-only review material. It does not mutate trusted frontier state and does not claim treatment advice, clinical validity, target validation, external validation, benchmark outperformance, or scientific discovery.</p>
</div>
<div class="wb-card">
  <h3>Lane coverage</h3>
  <table class="wb-table"><thead><tr><th>lane</th><th>claims</th></tr></thead><tbody>{lane_rows}</tbody></table>
</div>
<section aria-label="Decision trails">
  {trail_cards}
</section>"#,
        status = escape_html(status),
        claims = json_u64(summary, "high_weight_claims"),
        tensions = json_u64(summary, "explicit_evidence_tensions"),
        gap_tasks = json_u64(summary, "gap_tasks"),
        questions = json_u64(summary, "frozen_benchmark_questions"),
        trails = json_u64(summary, "decision_trails"),
        lane_rows = lane_rows,
        trail_cards = trail_cards,
    );
    Html(shell(
        "frontier-decision-grade",
        "Decision-grade frontier · Vela Workbench",
        "Workbench",
        "Decision-grade frontier",
        &body,
    ))
    .into_response()
}

async fn page_frontier_decision_grade_json(State(state): State<AppState>) -> Response {
    Json(frontier_decision_grade_payload(&state.repo_path)).into_response()
}

fn decision_trail_by_slug(
    payload: &serde_json::Value,
    trail_slug: &str,
) -> Option<serde_json::Value> {
    payload
        .get("decision_trails")
        .and_then(serde_json::Value::as_array)
        .and_then(|trails| {
            trails
                .iter()
                .find(|trail| json_str(trail, "slug") == trail_slug)
                .cloned()
        })
}

fn json_array_strings(value: &serde_json::Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(serde_json::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn json_string_vec_contains(values: &[String], needle: &str) -> bool {
    values.iter().any(|value| value == needle)
}

fn decision_trail_detail_payload(
    payload: &serde_json::Value,
    trail_slug: &str,
    repo_path: &Path,
) -> Option<serde_json::Value> {
    let trail = decision_trail_by_slug(payload, trail_slug)?;
    let finding_ids = json_array_strings(&trail, "supporting_finding_ids");
    let dependency_link_ids = json_array_strings(&trail, "dependency_link_ids");
    let tension_ids = json_array_strings(&trail, "tension_ids");
    let gap_task_ids = json_array_strings(&trail, "gap_task_ids");
    let claim_boundary = trail
        .get("claim_boundary")
        .cloned()
        .or_else(|| payload.get("claim_boundary").cloned())
        .unwrap_or_else(|| serde_json::json!({}));
    let high_weight_claims = payload
        .get("high_weight_claims")
        .and_then(serde_json::Value::as_array)
        .map(|claims| {
            claims
                .iter()
                .filter(|claim| {
                    let finding_id = json_str(claim, "finding_id");
                    !finding_id.is_empty() && json_string_vec_contains(&finding_ids, finding_id)
                })
                .cloned()
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let evidence_tensions = payload
        .get("explicit_evidence_tensions")
        .and_then(serde_json::Value::as_array)
        .map(|tensions| {
            tensions
                .iter()
                .filter(|tension| {
                    let tension_id = json_str(tension, "tension_id");
                    !tension_id.is_empty() && json_string_vec_contains(&tension_ids, tension_id)
                })
                .cloned()
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let gap_tasks = payload
        .get("gap_tasks")
        .and_then(serde_json::Value::as_array)
        .map(|tasks| {
            tasks
                .iter()
                .filter(|task| {
                    let task_id = json_str(task, "task_id");
                    !task_id.is_empty() && json_string_vec_contains(&gap_task_ids, task_id)
                })
                .cloned()
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let status = json_str(&trail, "status").to_string();
    let proof_packet_refs = json_array_strings(&trail, "proof_packet_refs");
    let (evidence_atoms, source_records) = decision_trail_frontier_rows(repo_path, &trail);
    Some(serde_json::json!({
        "schema": "vela.early_ad_v31_decision_trail_detail.v1",
        "frontier": payload
            .get("frontier")
            .cloned()
            .unwrap_or_else(|| serde_json::json!("projects/anti-amyloid-translation")),
        "status": status,
        "trail": trail,
        "high_weight_claims": high_weight_claims,
        "dependency_link_ids": dependency_link_ids,
        "evidence_atoms": evidence_atoms,
        "source_records": source_records,
        "evidence_tensions": evidence_tensions,
        "gap_tasks": gap_tasks,
        "proof_packet_refs": proof_packet_refs,
        "claim_boundary": claim_boundary,
    }))
}

fn decision_trail_frontier_rows(
    repo_path: &Path,
    trail: &serde_json::Value,
) -> (Vec<serde_json::Value>, Vec<serde_json::Value>) {
    let evidence_atom_ids = json_array_strings(trail, "evidence_atom_ids")
        .into_iter()
        .collect::<BTreeSet<_>>();
    let mut source_ids = json_array_strings(trail, "source_ids")
        .into_iter()
        .collect::<BTreeSet<_>>();

    let evidence_atoms =
        load_sharded_json_rows_by_id(repo_path, "evidence_atoms", &evidence_atom_ids)
            .into_iter()
            .take(24)
            .map(|atom| {
                let source_id = json_str(&atom, "source_id");
                if !source_id.is_empty() {
                    source_ids.insert(source_id.to_string());
                }
                serde_json::json!({
                    "id": json_str(&atom, "id"),
                    "finding_id": json_str(&atom, "finding_id"),
                    "source_id": source_id,
                    "locator": json_str(&atom, "locator"),
                    "human_verified": json_bool(&atom, "human_verified"),
                    "supports_or_challenges": json_str(&atom, "supports_or_challenges"),
                    "measurement_or_claim": json_str(&atom, "measurement_or_claim"),
                })
            })
            .collect::<Vec<_>>();

    let source_records = load_sharded_json_rows_by_id(repo_path, "sources", &source_ids)
        .iter()
        .take(24)
        .map(|source| {
            serde_json::json!({
                "id": json_str(source, "id"),
                "title": json_str(source, "title"),
                "source_type": json_str(source, "source_type"),
                "locator": json_str(source, "locator"),
                "finding_count": source
                    .get("finding_ids")
                    .and_then(serde_json::Value::as_array)
                    .map_or(0, Vec::len),
            })
        })
        .collect::<Vec<_>>();
    (evidence_atoms, source_records)
}

fn resolve_frontier_state_path(repo_path: &Path, raw_path: &str) -> PathBuf {
    let path = PathBuf::from(raw_path);
    if path.is_absolute() {
        return path;
    }
    let local = repo_path.join(&path);
    if local.exists() {
        return local;
    }
    path
}

fn load_sharded_json_rows_by_id(
    repo_path: &Path,
    item_type: &str,
    ids: &BTreeSet<String>,
) -> Vec<serde_json::Value> {
    if ids.is_empty() {
        return Vec::new();
    }
    let manifest = load_frontier_json(
        repo_path,
        "frontier-state-shards/frontier-state-manifest.v1.json",
    )
    .unwrap_or_else(|| serde_json::json!({"shards": []}));
    let mut rows = Vec::new();
    let Some(shards) = manifest.get("shards").and_then(serde_json::Value::as_array) else {
        return rows;
    };
    for shard in shards {
        if shard.get("item_type").and_then(serde_json::Value::as_str) != Some(item_type) {
            continue;
        }
        let Some(raw_path) = shard.get("path").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let path = resolve_frontier_state_path(repo_path, raw_path);
        let Ok(body) = fs::read_to_string(path) else {
            continue;
        };
        for line in body.lines().filter(|line| !line.trim().is_empty()) {
            let Ok(row) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            let id = json_str(&row, "id");
            if ids.contains(id) {
                rows.push(row);
            }
            if rows.len() >= ids.len() {
                return rows;
            }
        }
    }
    rows
}

fn render_code_chips(values: Vec<String>) -> String {
    values
        .iter()
        .map(|value| format!(r#"<code>{}</code>"#, escape_html(value)))
        .collect::<Vec<_>>()
        .join(" ")
}

fn render_source_links(values: Vec<String>) -> String {
    values
        .iter()
        .map(|source_id| {
            format!(
                r#"<a class="wb-chip" href="/sources/{href}">{source_id}</a>"#,
                href = urlencode_path(source_id),
                source_id = escape_html(source_id),
            )
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn render_decision_trail_claim_rows(claims: &[serde_json::Value]) -> String {
    claims
        .iter()
        .map(|claim| {
            format!(
                r#"<tr><td>{finding}</td><td><code>{lane}</code></td><td><code>{weight}</code></td><td>{assertion}</td></tr>"#,
                finding = render_finding_link_from_str(json_str(claim, "finding_id")),
                lane = escape_html(json_str(claim, "lane")),
                weight = claim
                    .get("decision_weight")
                    .and_then(serde_json::Value::as_f64)
                    .unwrap_or(0.0),
                assertion = escape_html(json_str(claim, "assertion")),
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

fn render_decision_trail_tension_rows(tensions: &[serde_json::Value]) -> String {
    tensions
        .iter()
        .map(|tension| {
            format!(
                r#"<tr><td><code>{id}</code></td><td>{source}</td><td>{target}</td><td>{rationale}</td></tr>"#,
                id = escape_html(json_str(tension, "tension_id")),
                source = render_finding_link_from_str(json_str(tension, "source_finding_id")),
                target = render_finding_link_from_str(json_str(tension, "target_finding_id")),
                rationale = escape_html(json_str(tension, "rationale")),
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

fn render_decision_trail_gap_rows(tasks: &[serde_json::Value]) -> String {
    tasks
        .iter()
        .map(|task| {
            format!(
                r#"<tr><td><code>{id}</code></td><td>{gap}</td><td>{action}</td></tr>"#,
                id = escape_html(json_str(task, "task_id")),
                gap = escape_html(json_str(task, "gap")),
                action = escape_html(json_str(task, "review_action")),
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

fn render_decision_trail_evidence_rows(atoms: &[serde_json::Value]) -> String {
    if atoms.is_empty() {
        return r#"<tr><td colspan="5">No evidence atom rows were loaded for this trail.</td></tr>"#
            .to_string();
    }
    atoms
        .iter()
        .map(|atom| {
            format!(
                r#"<tr><td><code>{id}</code></td><td>{finding}</td><td>{source}</td><td>{locator}</td><td>{claim}</td></tr>"#,
                id = escape_html(json_str(atom, "id")),
                finding = render_finding_link_from_str(json_str(atom, "finding_id")),
                source = render_source_links(vec![json_str(atom, "source_id").to_string()]),
                locator = escape_html(&truncate(json_str(atom, "locator"), 84)),
                claim = escape_html(&truncate(json_str(atom, "measurement_or_claim"), 130)),
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

fn render_decision_trail_source_rows(sources: &[serde_json::Value]) -> String {
    if sources.is_empty() {
        return r#"<tr><td colspan="5">No source records were loaded for this trail.</td></tr>"#
            .to_string();
    }
    sources
        .iter()
        .map(|source| {
            format!(
                r#"<tr><td>{source_id}</td><td>{title}</td><td><code>{kind}</code></td><td>{locator}</td><td>{findings}</td></tr>"#,
                source_id = render_source_links(vec![json_str(source, "id").to_string()]),
                title = escape_html(&truncate(json_str(source, "title"), 96)),
                kind = escape_html(json_str(source, "source_type")),
                locator = escape_html(&truncate(json_str(source, "locator"), 84)),
                findings = json_u64(source, "finding_count"),
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

async fn page_frontier_decision_trail_detail(
    State(state): State<AppState>,
    AxumPath(trail_slug): AxumPath<String>,
) -> Response {
    let payload = frontier_decision_grade_payload(&state.repo_path);
    let wants_json = trail_slug.ends_with(".json");
    let clean_slug = trail_slug
        .strip_suffix(".json")
        .unwrap_or(trail_slug.as_str())
        .to_string();
    let Some(detail) = decision_trail_detail_payload(&payload, &clean_slug, &state.repo_path)
    else {
        if wants_json {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "decision trail not found"})),
            )
                .into_response();
        }
        return (
            StatusCode::NOT_FOUND,
            Html(shell(
                "frontier-decision-grade",
                "Decision trail not found · Vela Workbench",
                "Workbench",
                "Decision trail not found",
                "<div class=\"wb-card\"><p>Decision trail not found.</p></div>",
            )),
        )
            .into_response();
    };
    if wants_json {
        return Json(detail).into_response();
    }
    let trail = detail.get("trail").unwrap_or(&serde_json::Value::Null);
    let claims = detail
        .get("high_weight_claims")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let evidence_atoms = detail
        .get("evidence_atoms")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let source_records = detail
        .get("source_records")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let tensions = detail
        .get("evidence_tensions")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let gap_tasks = detail
        .get("gap_tasks")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let caveats = trail
        .get("caveats")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(serde_json::Value::as_str)
        .map(|caveat| format!("<li>{}</li>", escape_html(caveat)))
        .collect::<Vec<_>>()
        .join("");
    let finding_links = json_array_strings(trail, "supporting_finding_ids")
        .iter()
        .map(|finding_id| render_finding_link_from_str(finding_id))
        .collect::<Vec<_>>()
        .join(" ");
    let body = format!(
        r#"<section class="wb-hero" aria-label="Decision trail detail">
  <div class="wb-hero__grid">
    <div>
      <h2>Decision trail: {slug}</h2>
      <p>{question}</p>
      <div class="wb-action-row">
        <a class="wb-button" href="/frontier/decision-grade/{href}.json">Open JSON</a>
        <a class="wb-button wb-button--quiet" href="/frontier/decision-grade">All trails</a>
        <a class="wb-button wb-button--quiet" href="/proof">Proof</a>
      </div>
    </div>
    <div class="wb-status-panel" aria-label="Decision trail status">
      <div><span>status</span><strong>{status}</strong></div>
      <div><span>findings</span><strong>{findings}</strong></div>
      <div><span>sources</span><strong>{sources}</strong></div>
      <div><span>evidence atoms</span><strong>{atoms}</strong></div>
      <div><span>dependency links</span><strong>{dependency_links}</strong></div>
      <div><span>tensions</span><strong>{tensions}</strong></div>
      <div><span>gap tasks</span><strong>{gap_tasks}</strong></div>
    </div>
  </div>
</section>
<div class="wb-card">
  <h3>Boundary</h3>
  <p>This read-only decision trail does not claim treatment advice, clinical validity, target validation, external validation, benchmark outperformance, or scientific discovery.</p>
</div>
<div class="wb-card">
  <h3>Source ids</h3>
  <p>{source_ids}</p>
  <h3>Evidence atom ids</h3>
  <p>{evidence_atom_ids}</p>
  <h3>Dependency link ids</h3>
  <p>{dependency_link_ids}</p>
  <h3>Proof refs</h3>
  <p>{proof_refs}</p>
  <h3>Caveats</h3>
  <ul>{caveats}</ul>
</div>
<div class="wb-card">
  <h3>Evidence atom rows</h3>
  <table class="wb-table">
    <thead><tr><th>atom</th><th>finding</th><th>source</th><th>locator</th><th>claim</th></tr></thead>
    <tbody>{evidence_rows}</tbody>
  </table>
</div>
<div class="wb-card">
  <h3>Source records</h3>
  <table class="wb-table">
    <thead><tr><th>source</th><th>title</th><th>type</th><th>locator</th><th>findings</th></tr></thead>
    <tbody>{source_rows}</tbody>
  </table>
</div>
<div class="wb-card">
  <h3>Supporting findings</h3>
  <p>{finding_links}</p>
  <table class="wb-table">
    <thead><tr><th>finding</th><th>lane</th><th>weight</th><th>assertion</th></tr></thead>
    <tbody>{claim_rows}</tbody>
  </table>
</div>
<div class="wb-card">
  <h3>Evidence tensions</h3>
  <table class="wb-table">
    <thead><tr><th>id</th><th>source</th><th>target</th><th>rationale</th></tr></thead>
    <tbody>{tension_rows}</tbody>
  </table>
</div>
<div class="wb-card">
  <h3>Gap tasks</h3>
  <table class="wb-table">
    <thead><tr><th>id</th><th>gap</th><th>review action</th></tr></thead>
    <tbody>{gap_rows}</tbody>
  </table>
</div>"#,
        slug = escape_html(json_str(trail, "slug")),
        href = urlencode_path(json_str(trail, "slug")),
        question = escape_html(json_str(trail, "question")),
        status = escape_html(json_str(trail, "status")),
        findings = json_array_len(trail, "supporting_finding_ids"),
        sources = json_array_len(trail, "source_ids"),
        atoms = json_array_len(trail, "evidence_atom_ids"),
        dependency_links = json_array_len(trail, "dependency_link_ids"),
        tensions = json_array_len(trail, "tension_ids"),
        gap_tasks = json_array_len(trail, "gap_task_ids"),
        source_ids = render_source_links(json_array_strings(trail, "source_ids")),
        evidence_atom_ids = render_code_chips(json_array_strings(trail, "evidence_atom_ids")),
        dependency_link_ids = render_code_chips(json_array_strings(trail, "dependency_link_ids")),
        proof_refs = render_code_chips(json_array_strings(trail, "proof_packet_refs")),
        caveats = caveats,
        finding_links = finding_links,
        evidence_rows = render_decision_trail_evidence_rows(&evidence_atoms),
        source_rows = render_decision_trail_source_rows(&source_records),
        claim_rows = render_decision_trail_claim_rows(&claims),
        tension_rows = render_decision_trail_tension_rows(&tensions),
        gap_rows = render_decision_trail_gap_rows(&gap_tasks),
    );
    Html(shell(
        "frontier-decision-grade",
        "Decision trail · Vela Workbench",
        "Workbench",
        "Decision trail",
        &body,
    ))
    .into_response()
}

async fn page_frontier_answer_path_detail(
    State(state): State<AppState>,
    AxumPath(answer_id): AxumPath<String>,
) -> Response {
    let payload = frontier_answer_paths_payload(&state.repo_path);
    let wants_json = answer_id.ends_with(".json");
    let clean_answer_id = answer_id
        .strip_suffix(".json")
        .unwrap_or(answer_id.as_str())
        .to_string();
    if wants_json {
        return match answer_path_with_boundary(&payload, &clean_answer_id) {
            Some(path) => Json(path).into_response(),
            None => (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "answer path not found"})),
            )
                .into_response(),
        };
    }
    let Some(path) = answer_path_by_id(&payload, &clean_answer_id) else {
        return (
            StatusCode::NOT_FOUND,
            Html(shell(
                "frontier-answer-paths",
                "Answer path not found · Vela Workbench",
                "Workbench",
                "Answer path not found",
                "<div class=\"wb-card\"><p>Answer path not found.</p></div>",
            )),
        )
            .into_response();
    };
    let decision_paths = frontier_decision_paths_payload(&state.repo_path);
    let answer_id = json_str(&path, "answer_id").to_string();
    let decision_path =
        decision_path_by_id(&decision_paths, &answer_id).unwrap_or_else(|| serde_json::json!({}));
    let verification = decision_path
        .get("verification_context")
        .unwrap_or(&serde_json::Value::Null);
    let copyable = json_str(&decision_path, "copyable_bounded_answer");
    let health = path
        .get("locator_health")
        .unwrap_or(&serde_json::Value::Null);
    let support = path
        .get("supporting_findings")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|finding| {
            render_finding_link_from_str_with_answer_path(
                json_str(finding, "finding_id"),
                &answer_id,
            )
        })
        .collect::<Vec<_>>()
        .join(" ");
    let counterweights = path
        .get("counterweight_findings")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|finding| {
            render_finding_link_from_str_with_answer_path(
                json_str(finding, "finding_id"),
                &answer_id,
            )
        })
        .collect::<Vec<_>>()
        .join(" ");
    let caveats = path
        .get("remaining_caveats")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(serde_json::Value::as_str)
        .map(|caveat| format!("<li>{}</li>", escape_html(caveat)))
        .collect::<Vec<_>>()
        .join("");
    let trails = path
        .get("source_trails")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default()
        .iter()
        .take(24)
        .map(|trail| {
            let finding_ids = trail
                .get("finding_ids")
                .and_then(serde_json::Value::as_array)
                .cloned()
                .unwrap_or_default()
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(|finding_id| render_finding_link_from_str_with_answer_path(finding_id, &answer_id))
                .collect::<Vec<_>>()
                .join(" ");
            format!(
                r#"<tr><td><a href="/sources/{source_href}{answer_query}"><code>{source_id}</code></a></td><td>{health}</td><td>{findings}</td><td><code>{atoms}</code></td></tr>"#,
                source_href = urlencode_path(json_str(trail, "source_id")),
                answer_query = answer_path_query(&answer_id),
                source_id = escape_html(json_str(trail, "source_id")),
                health = escape_html(json_str(trail, "locator_health")),
                findings = finding_ids,
                atoms = trail
                    .get("evidence_atom_ids")
                    .and_then(serde_json::Value::as_array)
                    .map_or(0, Vec::len),
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let body = format!(
        r#"<section class="wb-hero" aria-label="Answer evidence path">
  <div class="wb-hero__grid">
    <div>
      <h2>Evidence path: {id}</h2>
      <p>{question}</p>
      <blockquote>{answer}</blockquote>
      <div class="wb-action-row">
        <a class="wb-button" href="/frontier/answer-paths/{href}.json">Open JSON</a>
        <a class="wb-button wb-button--quiet" href="/frontier/answer-paths">All paths</a>
        <a class="wb-button wb-button--quiet" href="/frontier/questions/{href}">Question</a>
        <a class="wb-button wb-button--quiet" href="/frontier/answer-book">Answer book</a>
      </div>
    </div>
    <div class="wb-status-panel" aria-label="Path locator health">
      <div><span>locator health</span><strong>{stable}/{total}</strong></div>
      <div><span>preserved</span><strong>{preserved}</strong></div>
      <div><span>missing</span><strong>{missing}</strong></div>
      <div><span>claims_external_validation</span><strong>false</strong></div>
    </div>
  </div>
</section>
<div class="wb-card">
  <h3>Decision path</h3>
  <p>reviewer priority: <code>{priority}</code> · verification records: <code>{verification_records}</code>.</p>
  <h3>copyable bounded answer</h3>
  <pre><code>{copyable}</code></pre>
</div>
<div class="wb-card">
  <h3>Support</h3>
  <p>{support}</p>
  <h3>Counterweights</h3>
  <p>{counterweights}</p>
</div>
<div class="wb-card">
  <h3>remaining caveats</h3>
  <ul>{caveats}</ul>
</div>
<div class="wb-card">
  <h3>source trails</h3>
  <table class="wb-table">
    <thead><tr><th>source</th><th>locator health</th><th>findings</th><th>evidence atoms</th></tr></thead>
    <tbody>{trails}</tbody>
  </table>
</div>"#,
        id = escape_html(&answer_id),
        href = urlencode_path(&answer_id),
        question = escape_html(json_str(&path, "question")),
        answer = escape_html(json_str(&path, "answer")),
        priority = json_u64(&decision_path, "reviewer_priority"),
        verification_records = json_u64(verification, "verification_records"),
        copyable = escape_html(copyable),
        stable = json_u64(health, "stable_sources"),
        total = json_u64(health, "total_sources"),
        preserved = json_u64(health, "preserved_locator_only_sources"),
        missing = json_u64(health, "missing_locator_sources"),
        support = support,
        counterweights = counterweights,
        caveats = caveats,
        trails = trails,
    );
    Html(shell(
        "frontier-answer-paths",
        "Answer evidence path · Vela Workbench",
        "Workbench",
        "Answer evidence path",
        &body,
    ))
    .into_response()
}

fn adjudication_cockpit_payload(repo_path: &Path) -> serde_json::Value {
    serde_json::json!({
        "schema": "vela.workbench.adjudication_cockpit.v0.1",
        "title": "Adjudication cockpit",
        "frontier_path": repo_path.display().to_string(),
        "read_only": true,
        "artifacts": [
            "benchmarks/public/score-returns/inbox/filled-score-return-rehearsal.import-preview.v1.json",
            "benchmarks/public/score-returns/review-event-drafts/score-return.review-event-drafts.v1.json",
            "benchmarks/public/score-returns/score-return-adjudication-ledger.v1.json",
            "benchmarks/frontier-graph-navigation-tasks.v2.json",
            "dist/outsider-review-demo/readiness.v2.json"
        ],
        "mutation_boundary": {
            "writes_review_events": false,
            "accepts_frontier_state": false,
            "writes_frontier_state": false
        },
        "claim_boundary": {
            "claims_external_validation": false,
            "claims_general_benchmark_outperformance": false,
            "claims_scientific_discovery": false,
            "claims_target_validation": false,
            "claims_treatment_advice": false
        },
        "boundary_text": "writes_review_events=false; accepts_frontier_state=false; writes_frontier_state=false; claims_external_validation=false",
        "steps": [
            {
                "id": "inspect_return",
                "label": "inspect return import",
                "command": "jq '.validation, .mutation_boundary' benchmarks/public/score-returns/inbox/filled-score-return-rehearsal.import-preview.v1.json"
            },
            {
                "id": "inspect_drafts",
                "label": "inspect draft review events",
                "command": "jq '.draft_review_events[] | {event_id, task_id, status}' benchmarks/public/score-returns/review-event-drafts/score-return.review-event-drafts.v1.json"
            },
            {
                "id": "inspect_ledger",
                "label": "inspect adjudication ledger",
                "command": "jq '.rows[] | {task_id, draft_event_id, adjudication_status}' benchmarks/public/score-returns/score-return-adjudication-ledger.v1.json"
            }
        ]
    })
}

async fn page_adjudication_cockpit(State(state): State<AppState>) -> Response {
    let payload = adjudication_cockpit_payload(&state.repo_path);
    let artifacts = payload
        .get("artifacts")
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|value| value.as_str())
        .map(|artifact| format!("<code>{}</code>", escape_html(artifact)))
        .collect::<Vec<_>>()
        .join(" · ");
    let rows = payload
        .get("steps")
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|step| {
            let label = step.get("label").and_then(|v| v.as_str()).unwrap_or("step");
            let command = step
                .get("command")
                .and_then(|v| v.as_str())
                .unwrap_or("none");
            format!(
                r#"<tr><td>{label}</td><td><code>{command}</code></td></tr>"#,
                label = escape_html(label),
                command = escape_html(command)
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let body = format!(
        r#"<section class="wb-hero" aria-label="Adjudication cockpit">
  <div class="wb-hero__grid">
    <div>
      <h2>Adjudication cockpit</h2>
      <p>This read-only page shows source returns, draft review events, and the adjudication ledger without writing accepted state.</p>
      <div class="wb-action-row">
        <a class="wb-button" href="/demo/adjudication.json">Open JSON</a>
        <a class="wb-button wb-button--quiet" href="/demo/score-return">Score-return preview</a>
        <a class="wb-button wb-button--quiet" href="/review/work">Review work</a>
      </div>
    </div>
    <div class="wb-status-panel" aria-label="Adjudication cockpit boundary">
      <div><span>writes_review_events</span><strong>false</strong></div>
      <div><span>accepts_frontier_state</span><strong>false</strong></div>
      <div><span>read_only</span><strong>true</strong></div>
    </div>
  </div>
</section>
<div class="wb-card">
  <h3>Adjudication artifacts</h3>
  <p>{artifacts}</p>
  <p>Boundary: writes_review_events=false; accepts_frontier_state=false; writes_frontier_state=false; claims_external_validation=false.</p>
</div>
<div class="wb-card">
  <h3>Inspection steps</h3>
  <table class="wb-table">
    <thead><tr><th>step</th><th>command</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div>"#,
        artifacts = artifacts,
        rows = rows,
    );
    Html(shell(
        "adjudication-cockpit",
        "Adjudication cockpit · Vela Workbench",
        "Workbench",
        "Adjudication cockpit",
        &body,
    ))
    .into_response()
}

async fn page_adjudication_cockpit_json(State(state): State<AppState>) -> Response {
    Json(adjudication_cockpit_payload(&state.repo_path)).into_response()
}

async fn page_review_inbox(
    State(state): State<AppState>,
    Query(filter): Query<InboxFilter>,
) -> Response {
    let project = match repo::load_from_path(&state.repo_path) {
        Ok(p) => p,
        Err(e) => return error_page("review", "Could not load frontier", &e),
    };

    let locator_gaps: Vec<&vela_protocol::sources::EvidenceAtom> = project
        .evidence_atoms
        .iter()
        .filter(|a| a.locator.is_none())
        .take(20)
        .collect();
    let span_gaps: Vec<&FindingBundle> = project
        .findings
        .iter()
        .filter(|f| f.evidence.evidence_spans.is_empty())
        .take(20)
        .collect();
    let entity_gaps: Vec<&FindingBundle> = project
        .findings
        .iter()
        .filter(|f| f.assertion.entities.iter().any(|e| e.needs_review))
        .take(20)
        .collect();
    let link_gaps: Vec<&FindingBundle> = project
        .findings
        .iter()
        .filter(|f| f.links.is_empty())
        .take(20)
        .collect();

    // v0.59: findings pending review surface. Anything without a
    // review_state, or stuck in NeedsRevision, is reviewer work.
    // Accepted/Contested/Rejected findings have a recorded verdict
    // and are not in the queue.
    //
    // v0.64: optional `?source=<prefix>` query-string filter. Matches
    // a finding's DOI or PMID (case-insensitive prefix) so a reviewer
    // can walk all findings sourced from one paper.
    let source_filter = filter.source.trim().to_ascii_lowercase();
    let matches_source_filter = |f: &FindingBundle| -> bool {
        if source_filter.is_empty() {
            return true;
        }
        let doi_match = f
            .provenance
            .doi
            .as_deref()
            .map(|d| d.to_ascii_lowercase())
            .map(|d| {
                d.starts_with(&source_filter) || format!("doi:{d}").starts_with(&source_filter)
            })
            .unwrap_or(false);
        let pmid_match = f
            .provenance
            .pmid
            .as_deref()
            .map(|p| p.to_ascii_lowercase())
            .map(|p| {
                p.starts_with(&source_filter) || format!("pmid:{p}").starts_with(&source_filter)
            })
            .unwrap_or(false);
        doi_match || pmid_match
    };
    let promote_pending: Vec<&FindingBundle> = project
        .findings
        .iter()
        .filter(|f| {
            matches!(
                f.flags.review_state,
                None | Some(vela_protocol::bundle::ReviewState::NeedsRevision)
            )
        })
        .filter(|f| matches_source_filter(f))
        .take(20)
        .collect();
    let total_promote = project
        .findings
        .iter()
        .filter(|f| {
            matches!(
                f.flags.review_state,
                None | Some(vela_protocol::bundle::ReviewState::NeedsRevision)
            )
        })
        .count();

    // F1: federation conflicts surfaced in the inbox. Read-only
    // listing; resolution happens through subsequent reviewer
    // actions on the affected finding (revise / caveat / reject /
    // finding.reviewed contested).
    let federation_conflicts: Vec<&vela_protocol::events::StateEvent> = project
        .events
        .iter()
        .filter(|e| e.kind == "frontier.conflict_detected")
        .rev()
        .take(20)
        .collect();
    let total_conflicts = project
        .events
        .iter()
        .filter(|e| e.kind == "frontier.conflict_detected")
        .count();

    let total_locator = project
        .evidence_atoms
        .iter()
        .filter(|a| a.locator.is_none())
        .count();
    let total_span = project
        .findings
        .iter()
        .filter(|f| f.evidence.evidence_spans.is_empty())
        .count();
    let total_entity = project
        .findings
        .iter()
        .filter(|f| f.assertion.entities.iter().any(|e| e.needs_review))
        .count();
    let total_link = project
        .findings
        .iter()
        .filter(|f| f.links.is_empty())
        .count();
    let mut missing_attestation_count = 0usize;
    let mut first_missing_attestation_pack = "none".to_string();
    for pack in list_released_diff_packs(&project, &state.repo_path) {
        let review_summary = pack.review_summary(&state.repo_path);
        let missing = reviewer_identity::missing_roles_for_target(
            &state.repo_path,
            &pack.pack_id,
            &review_summary.required_reviewers,
        )
        .unwrap_or_else(|_| review_summary.required_reviewers.clone());
        if !missing.is_empty() {
            missing_attestation_count += missing.len();
            if first_missing_attestation_pack == "none" {
                first_missing_attestation_pack = pack.pack_id;
            }
        }
    }
    let proposal_state_counts =
        project
            .proposals
            .iter()
            .fold(BTreeMap::<&str, usize>::new(), |mut counts, proposal| {
                *counts.entry(proposal.status.as_str()).or_insert(0) += 1;
                counts
            });
    let pending_proposals = proposal_state_counts
        .get("pending_review")
        .copied()
        .unwrap_or(0);
    let needs_revision_proposals = proposal_state_counts
        .get("needs_revision")
        .copied()
        .unwrap_or(0);
    let latest_proposal = project
        .proposals
        .iter()
        .max_by(|a, b| a.created_at.cmp(&b.created_at));
    let latest_proposal_age = latest_proposal
        .and_then(|proposal| review_age_label(&proposal.created_at))
        .unwrap_or_else(|| "n/a".to_string());
    let latest_proposal_id = latest_proposal
        .map(|proposal| proposal.id.as_str())
        .unwrap_or("none");
    let proof_status = project.proof_state.latest_packet.status.as_str();
    let proof_age = project
        .proof_state
        .latest_packet
        .generated_at
        .as_deref()
        .and_then(review_age_label)
        .unwrap_or_else(|| "n/a".to_string());
    let proof_cli = if proof_status == "fresh" || proof_status == "ready" {
        "vela proof FRONTIER --out /tmp/proof-packet"
    } else {
        "vela proof FRONTIER --out /tmp/proof-packet --record-proof-state"
    };
    let selected_group = if filter.group.trim().is_empty() {
        "all"
    } else {
        filter.group.trim()
    };
    let selected_sort = if filter.sort.trim().is_empty() {
        "impact"
    } else {
        filter.sort.trim()
    };

    let mut body = String::new();
    // V3 follow-on: source filter form. Submits via GET so the URL
    // is shareable/bookmarkable. No JS.
    body.push_str(&format!(
        r#"<form method="get" action="/review/inbox" style="margin:0 0 0.6rem 0;display:flex;flex-wrap:wrap;gap:0.5rem;align-items:center;min-width:0;">
<label for="wb-source-filter" style="color:var(--ink-3);font-size:0.86rem;">Filter pending review by source:</label>
<input id="wb-source-filter" name="source" value="{source_val}" placeholder="doi:10.1056/ or pmid:36811" style="flex:1 1 16rem;max-width:100%;min-width:0;">
<label for="wb-group-filter" style="color:var(--ink-3);font-size:0.86rem;">Group</label>
<select id="wb-group-filter" name="group">
  {group_options}
</select>
<label for="wb-sort-filter" style="color:var(--ink-3);font-size:0.86rem;">Sort</label>
<select id="wb-sort-filter" name="sort">
  {sort_options}
</select>
<button type="submit">Apply filter</button>
{clear_link}
</form>"#,
        source_val = escape_html(&filter.source),
        group_options = select_options(
            selected_group,
            &[
                ("all", "all queues"),
                ("source_issue", "source issue"),
                ("entity_issue", "entity issue"),
                ("proposal_state", "proposal state"),
                ("proof_freshness", "proof freshness"),
                ("decision_impact", "decision impact"),
                ("missing_attestation", "missing attestation"),
            ],
        ),
        sort_options = select_options(
            selected_sort,
            &[
                ("impact", "impact"),
                ("age", "review age"),
                ("status", "status"),
            ],
        ),
        clear_link = if filter.source.trim().is_empty() {
            String::new()
        } else {
            r#"<a href="/review/inbox" style="color:var(--ink-3);">Clear</a>"#.to_string()
        },
    ));
    body.push_str(
        r#"<p style="margin:0 0 1rem 0;color:var(--ink-3);font-size:0.86rem;">For blocker totals across source records, entity flags, proposals, Diff Packs, outside review, tasks, and proof refresh, open <a href="/review/work">review work queues</a>.</p>"#,
    );
    let source_issue_count = total_locator + total_span;
    let source_issue_object = locator_gaps
        .first()
        .map(|atom| atom.id.as_str())
        .or_else(|| span_gaps.first().map(|finding| finding.id.as_str()))
        .unwrap_or("none");
    let entity_issue_object = entity_gaps
        .first()
        .map(|finding| finding.id.as_str())
        .unwrap_or("none");
    let decision_object = link_gaps
        .first()
        .map(|finding| finding.id.as_str())
        .unwrap_or("none");
    let policy_summary = vela_protocol::frontier_policy::load_policy_summary(&state.repo_path).ok();
    let policy_requirement_label = |operation_class: &str, kind: &str, downstream: bool| {
        let req = vela_protocol::frontier_policy::review_requirement_for_operation(
            policy_summary.as_ref(),
            operation_class,
            kind,
            downstream,
        );
        format!(
            "{} · {} reviewer{} · {}",
            req.review_class,
            req.required_reviewer_count,
            if req.required_reviewer_count == 1 {
                ""
            } else {
                "s"
            },
            req.reviewer_roles.join(", ")
        )
    };
    let source_policy = policy_requirement_label("repair_locator", "source.repair", false);
    let entity_policy = policy_requirement_label("resolve_entity", "entity.resolve", false);
    let proposal_policy = policy_requirement_label("add_finding", "proposal.review", false);
    let proof_policy =
        policy_requirement_label("request_downstream_review", "proof.freshness", true);
    let impact_policy =
        policy_requirement_label("request_downstream_review", "decision.impact", true);
    let attestation_policy =
        policy_requirement_label("record_attestation", "diff_pack.attestation", true);
    body.push_str(&format!(
        r#"<div class="wb-card" aria-label="Review queue groups">
  <h3>Review queue groups</h3>
  <p>Selected frontier <code>{frontier}</code>. Current view: <code>{group}</code>, sorted by <code>{sort}</code>.</p>
  <table class="wb-table">
    <thead><tr><th>queue</th><th>count</th><th>object id</th><th>decision class</th><th>evidence/source status</th><th>policy requirement</th><th>review age</th><th>CLI equivalent</th></tr></thead>
    <tbody>
      <tr><td>source issue</td><td>{source_count}</td><td><code>{source_object}</code></td><td>repair</td><td>locator/span evidence</td><td>{source_policy}</td><td>n/a</td><td><code>vela locator-repair FRONTIER &lt;atom&gt; --reviewer reviewer:you --reason &lt;reason&gt;</code></td></tr>
      <tr><td>entity issue</td><td>{entity_count}</td><td><code>{entity_object}</code></td><td>resolve</td><td>entity candidate</td><td>{entity_policy}</td><td>n/a</td><td><code>vela entity-resolve FRONTIER &lt;finding&gt; --reviewer reviewer:you --reason &lt;reason&gt;</code></td></tr>
      <tr><td>proposal state</td><td>{proposal_count}</td><td><code>{proposal_object}</code></td><td>accept/reject/revise</td><td>{pending} pending, {needs_revision} needs revision</td><td>{proposal_policy}</td><td>{proposal_age}</td><td><code>vela proposals preview FRONTIER {proposal_object} --reviewer reviewer:you --json</code></td></tr>
      <tr><td>proof freshness</td><td>1</td><td><code>{frontier}</code></td><td>regenerate</td><td><code>{proof_status}</code></td><td>{proof_policy}</td><td>{proof_age}</td><td><code>{proof_cli}</code></td></tr>
      <tr><td>decision impact</td><td>{impact_count}</td><td><code>{impact_object}</code></td><td>link/review</td><td>typed-link coverage</td><td>{impact_policy}</td><td>n/a</td><td><code>vela review FRONTIER {impact_object} --status accepted --reviewer reviewer:you --reason &lt;reason&gt; --apply</code></td></tr>
      <tr><td>missing attestation</td><td>{missing_attestation_count}</td><td><code>{missing_attestation_object}</code></td><td>role-scoped attestation</td><td>Diff Pack role coverage</td><td>{attestation_policy}</td><td>n/a</td><td><code>vela attest FRONTIER {missing_attestation_object} --reviewer reviewer:you --role domain_reviewer --reason &lt;reason&gt;</code></td></tr>
    </tbody>
  </table>
</div>"#,
        frontier = escape_html(&project.frontier_id()),
        group = escape_html(selected_group),
        sort = escape_html(selected_sort),
        source_count = source_issue_count,
        source_object = escape_html(source_issue_object),
        source_policy = escape_html(&source_policy),
        entity_count = total_entity,
        entity_object = escape_html(entity_issue_object),
        entity_policy = escape_html(&entity_policy),
        proposal_count = pending_proposals + needs_revision_proposals,
        proposal_object = escape_html(latest_proposal_id),
        proposal_policy = escape_html(&proposal_policy),
        pending = pending_proposals,
        needs_revision = needs_revision_proposals,
        proposal_age = escape_html(&latest_proposal_age),
        proof_status = escape_html(proof_status),
        proof_policy = escape_html(&proof_policy),
        proof_age = escape_html(&proof_age),
        proof_cli = escape_html(proof_cli),
        impact_count = total_link,
        impact_object = escape_html(decision_object),
        impact_policy = escape_html(&impact_policy),
        missing_attestation_count = missing_attestation_count,
        missing_attestation_object = escape_html(&first_missing_attestation_pack),
        attestation_policy = escape_html(&attestation_policy),
    ));
    body.push_str(r#"<div class="wb-stats">"#);
    for (n, label) in [
        (total_locator, "missing locator"),
        (total_span, "missing span"),
        (total_entity, "needs review"),
        (total_link, "no links"),
        (total_promote, "pending review"),
        (total_conflicts, "federation conflicts"),
        (missing_attestation_count, "missing attestation"),
    ] {
        body.push_str(&format!(
            r#"<div><div class="wb-stat__num">{n}</div><div class="wb-stat__label">{label}</div></div>"#
        ));
    }
    body.push_str("</div>");

    // V3.2: reviewer-throughput dashboard. Honest metrics from the
    // canonical event log + proposal trail. Read-only; no new event
    // kinds. Empty-frontier safe (an empty event list yields zeros,
    // not panics).
    let cutoff_seven_days = chrono::Utc::now() - chrono::Duration::days(7);
    let events_last_7d: Vec<&vela_protocol::events::StateEvent> = project
        .events
        .iter()
        .filter(|e| {
            chrono::DateTime::parse_from_rfc3339(&e.timestamp)
                .map(|dt| dt.with_timezone(&chrono::Utc) >= cutoff_seven_days)
                .unwrap_or(false)
        })
        .collect();
    let total_events_7d = events_last_7d.len();
    let mut kind_counts: std::collections::BTreeMap<&str, usize> =
        std::collections::BTreeMap::new();
    for e in &events_last_7d {
        *kind_counts.entry(e.kind.as_str()).or_insert(0) += 1;
    }
    let mut top_kinds: Vec<(&str, usize)> = kind_counts.into_iter().collect();
    top_kinds.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    let top_kinds: Vec<(&str, usize)> = top_kinds.into_iter().take(5).collect();

    // Median proposal-to-event latency. For each proposal that has
    // an applied_event_id, look up the corresponding event's
    // timestamp and compare against the proposal's created_at.
    let event_by_id: std::collections::HashMap<&str, &vela_protocol::events::StateEvent> =
        project.events.iter().map(|e| (e.id.as_str(), e)).collect();
    let mut latencies_sec: Vec<i64> = Vec::new();
    let mut applied_count: usize = 0;
    let mut pending_count: usize = 0;
    for p in &project.proposals {
        match p.status.as_str() {
            "applied" => {
                applied_count += 1;
                // v0.67: read against `drafted_at` when present (the
                // agent draft moment) and fall back to `created_at`
                // (the canonical-store moment). Pre-v0.67 proposals
                // load with `drafted_at: None`; the dashboard reads
                // their `created_at` as before, so back-compat
                // holds.
                let queue_start = p.drafted_at.as_deref().unwrap_or(p.created_at.as_str());
                if let Some(eid) = p.applied_event_id.as_deref()
                    && let Some(ev) = event_by_id.get(eid)
                    && let (Ok(c), Ok(a)) = (
                        chrono::DateTime::parse_from_rfc3339(queue_start),
                        chrono::DateTime::parse_from_rfc3339(&ev.timestamp),
                    )
                {
                    let secs = (a.timestamp() - c.timestamp()).max(0);
                    latencies_sec.push(secs);
                }
            }
            "pending_review" => pending_count += 1,
            _ => {}
        }
    }
    latencies_sec.sort_unstable();
    let median_latency_sec = if latencies_sec.is_empty() {
        None
    } else {
        Some(latencies_sec[latencies_sec.len() / 2])
    };
    let median_latency_label = match median_latency_sec {
        None => "n/a".to_string(),
        Some(s) if s < 60 => format!("{s}s"),
        Some(s) if s < 3600 => format!("{}m", s / 60),
        Some(s) if s < 86400 => format!("{}h", s / 3600),
        Some(s) => format!("{}d", s / 86400),
    };
    let total_proposals = project.proposals.len();
    let applied_pct = if total_proposals == 0 {
        0
    } else {
        (applied_count * 100) / total_proposals
    };

    body.push_str(r#"<div class="wb-card"><h3>Throughput, last 7 days</h3>"#);
    body.push_str(&format!(
        r#"<p style="color:var(--ink-3);font-size:0.86rem;">{total_events_7d} canonical events in the last 7 days. {applied_count} of {total_proposals} proposals applied ({applied_pct}%); {pending_count} still pending. Median time from proposal to applied event: <code>{median_latency_label}</code>.</p>"#
    ));
    if !top_kinds.is_empty() {
        body.push_str(r#"<table class="wb-table"><thead><tr><th>kind</th><th>count (7d)</th></tr></thead><tbody>"#);
        for (k, n) in &top_kinds {
            body.push_str(&format!(
                r#"<tr><td><code>{kind}</code></td><td>{n}</td></tr>"#,
                kind = escape_html(k),
            ));
        }
        body.push_str("</tbody></table>");
    } else {
        body.push_str(
            r#"<p style="color:var(--ink-3);">No canonical events in the last 7 days. Quiet frontier or fresh seed.</p>"#,
        );
    }
    body.push_str("</div>");

    let render_atom = |a: &vela_protocol::sources::EvidenceAtom| {
        format!(
            r#"<tr><td><code>{aid}</code></td><td><code>{fid}</code></td><td><a href="/review/locator-repair/{aid}">repair →</a></td></tr>"#,
            aid = escape_html(&a.id),
            fid = escape_html(&a.finding_id),
        )
    };
    // V3 follow-on (#4): pass the full assertion as a `title`
    // attribute so a hover surfaces it without breaking the table
    // layout. The visible cell still truncates at 80 chars.
    let render_finding = |f: &FindingBundle, route: &str| {
        format!(
            r#"<tr><td><code>{fid}</code></td><td title="{full}">{txt}</td><td><a href="/review/{route}/{fid}">repair →</a></td></tr>"#,
            fid = escape_html(&f.id),
            txt = escape_html(&truncate(&f.assertion.text, 80)),
            full = escape_html(&f.assertion.text),
        )
    };

    body.push_str(r#"<div class="wb-card"><h3>Locator gaps</h3><table class="wb-table"><thead><tr><th>atom</th><th>finding</th><th></th></tr></thead><tbody>"#);
    for a in &locator_gaps {
        body.push_str(&render_atom(a));
    }
    body.push_str("</tbody></table></div>");

    body.push_str(r#"<div class="wb-card"><h3>Span gaps</h3><table class="wb-table"><thead><tr><th>finding</th><th>assertion</th><th></th></tr></thead><tbody>"#);
    for f in &span_gaps {
        body.push_str(&render_finding(f, "span-repair"));
    }
    body.push_str("</tbody></table></div>");

    body.push_str(r#"<div class="wb-card"><h3>Entity gaps</h3><table class="wb-table"><thead><tr><th>finding</th><th>assertion</th><th></th></tr></thead><tbody>"#);
    for f in &entity_gaps {
        body.push_str(&render_finding(f, "entity-resolve"));
    }
    body.push_str("</tbody></table></div>");

    body.push_str(r#"<div class="wb-card"><h3>Link gaps (findings without typed links)</h3><table class="wb-table"><thead><tr><th>finding</th><th>assertion</th></tr></thead><tbody>"#);
    for f in &link_gaps {
        body.push_str(&format!(
            r#"<tr><td><code>{fid}</code></td><td>{txt}</td></tr>"#,
            fid = escape_html(&f.id),
            txt = escape_html(&truncate(&f.assertion.text, 80)),
        ));
    }
    body.push_str("</tbody></table></div>");

    body.push_str(r#"<div class="wb-card"><h3>Findings pending review</h3>"#);
    if promote_pending.is_empty() {
        body.push_str(
            r#"<p style="color:var(--ink-3);">No findings without a recorded review verdict. Every finding has been promoted to accepted-core, contested, needs_revision, or rejected.</p>"#,
        );
    } else {
        body.push_str(r#"<p style="color:var(--ink-3);font-size:0.86rem;">Each promote submission lands as a signed canonical `finding.review` event under the configured reviewer id. No bulk affordance; one finding per submission.</p>"#);
        body.push_str(r#"<table class="wb-table"><thead><tr><th>finding</th><th>assertion</th><th>source</th><th>state</th><th></th></tr></thead><tbody>"#);
        for f in &promote_pending {
            let state_label = match &f.flags.review_state {
                Some(vela_protocol::bundle::ReviewState::NeedsRevision) => "needs_revision",
                None => "(unset)",
                _ => "(other)",
            };
            // V3.3 pain point 1: surface DOI/PMID + year inline so
            // the reviewer can triage by source without clicking
            // through.
            let source_ref =
                if let Some(doi) = f.provenance.doi.as_deref().filter(|s| !s.is_empty()) {
                    format!("<code>doi:{}</code>", escape_html(doi))
                } else if let Some(pmid) = f.provenance.pmid.as_deref().filter(|s| !s.is_empty()) {
                    format!("<code>pmid:{}</code>", escape_html(pmid))
                } else {
                    "<span style=\"color:var(--ink-3);\">none</span>".to_string()
                };
            let year_ref = f
                .provenance
                .year
                .map(|y| format!(" · {y}"))
                .unwrap_or_default();
            body.push_str(&format!(
                r#"<tr><td><code>{fid}</code></td><td title="{full}">{txt}</td><td>{src}{year}</td><td><code>{state}</code></td><td><a href="/review/promote/{fid}">promote →</a></td></tr>"#,
                fid = escape_html(&f.id),
                txt = escape_html(&truncate(&f.assertion.text, 80)),
                full = escape_html(&f.assertion.text),
                src = source_ref,
                year = year_ref,
                state = state_label,
            ));
        }
        body.push_str("</tbody></table>");
    }
    body.push_str("</div>");

    body.push_str(r#"<div class="wb-card"><h3>Federation conflicts</h3>"#);
    if federation_conflicts.is_empty() {
        body.push_str(
            r#"<p style="color:var(--ink-3);">No frontier.conflict_detected events on this frontier yet. Conflicts surface here when `vela federation sync` produces divergence with a peer's view.</p>"#,
        );
    } else {
        body.push_str(r#"<p style="color:var(--ink-3);font-size:0.86rem;">Each conflict pairs a `frontier.conflict_detected` event (the original detection) with an optional `frontier.conflict_resolved` event (the reviewer's verdict). One resolution per detection; the original event is never modified.</p>"#);
        body.push_str(r#"<table class="wb-table"><thead><tr><th>peer</th><th>finding</th><th>kind</th><th>when</th><th>state</th><th></th></tr></thead><tbody>"#);
        // v0.59: index resolved events by their conflict_event_id so
        // the row can show resolved status without re-scanning the
        // event log per row.
        let resolved_index: std::collections::HashSet<String> = project
            .events
            .iter()
            .filter(|e| e.kind == "frontier.conflict_resolved")
            .filter_map(|e| {
                e.payload
                    .get("conflict_event_id")
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
            })
            .collect();
        for ev in &federation_conflicts {
            let peer = ev
                .payload
                .get("peer_id")
                .and_then(|v| v.as_str())
                .unwrap_or("?")
                .to_string();
            let fid = ev
                .payload
                .get("finding_id")
                .and_then(|v| v.as_str())
                .unwrap_or("?")
                .to_string();
            let conflict_kind = ev
                .payload
                .get("kind")
                .and_then(|v| v.as_str())
                .unwrap_or("?")
                .to_string();
            let resolved = resolved_index.contains(&ev.id);
            let (state_label, action_cell) = if resolved {
                (
                    "<code>resolved</code>",
                    "<span style=\"color:var(--ink-3);\">recorded</span>".to_string(),
                )
            } else {
                (
                    "<code>open</code>",
                    format!(
                        r#"<a href="/review/conflict-resolve/{cid}">resolve →</a>"#,
                        cid = escape_html(&ev.id),
                    ),
                )
            };
            body.push_str(&format!(
                r#"<tr><td><code>{peer}</code></td><td><code>{fid}</code></td><td>{kind}</td><td><code>{ts}</code></td><td>{state}</td><td>{action}</td></tr>"#,
                peer = escape_html(&peer),
                fid = escape_html(&fid),
                kind = escape_html(&conflict_kind),
                ts = escape_html(&ev.timestamp[..10.min(ev.timestamp.len())]),
                state = state_label,
                action = action_cell,
            ));
        }
        body.push_str("</tbody></table>");
    }
    body.push_str("</div>");

    let html = shell(
        "review",
        "Inbox · Vela Workbench",
        "Workbench",
        "Inbox",
        &body,
    );
    Html(html).into_response()
}

fn review_session_payload(project: &Project) -> serde_json::Value {
    let mut reviewed: Vec<&StateProposal> = project
        .proposals
        .iter()
        .filter(|proposal| proposal.reviewed_by.is_some() || proposal.decision_reason.is_some())
        .collect();
    reviewed.sort_by(|a, b| {
        b.reviewed_at
            .as_deref()
            .unwrap_or(b.created_at.as_str())
            .cmp(a.reviewed_at.as_deref().unwrap_or(a.created_at.as_str()))
    });

    let mut accepted = 0usize;
    let mut rejected = 0usize;
    let mut needs_revision = 0usize;
    let mut reviewers = BTreeMap::<String, usize>::new();
    let mut changed_objects = Vec::new();
    let mut decisions = Vec::new();
    let mut start_time: Option<String> = None;

    for proposal in &reviewed {
        match proposal.status.as_str() {
            "accepted" | "applied" => accepted += 1,
            "rejected" => rejected += 1,
            "needs_revision" => needs_revision += 1,
            _ => {}
        }
        if let Some(reviewer) = proposal.reviewed_by.as_deref() {
            *reviewers.entry(reviewer.to_string()).or_insert(0) += 1;
        }
        if start_time
            .as_ref()
            .is_none_or(|current| proposal.created_at < *current)
        {
            start_time = Some(proposal.created_at.clone());
        }
        changed_objects.push(format!("{}:{}", proposal.target.r#type, proposal.target.id));
        decisions.push(serde_json::json!({
            "proposal_id": proposal.id,
            "status": proposal.status,
            "reviewer": proposal.reviewed_by,
            "reason": proposal.decision_reason,
            "reviewed_at": proposal.reviewed_at,
            "target": {
                "type": proposal.target.r#type,
                "id": proposal.target.id,
            },
            "applied_event_id": proposal.applied_event_id,
        }));
    }
    changed_objects.sort();
    changed_objects.dedup();

    let source_repairs = project
        .events
        .iter()
        .filter(|event| event.kind.contains("locator") || event.kind.contains("source"))
        .count();
    let entity_repairs = project
        .events
        .iter()
        .filter(|event| event.kind.contains("entity"))
        .count();
    let span_repairs = project
        .events
        .iter()
        .filter(|event| event.kind.contains("span"))
        .count();
    let proof_status = project.proof_state.latest_packet.status.clone();
    let stale_proof = proof_status != "fresh" && proof_status != "ready";

    serde_json::json!({
        "schema": "vela.workbench.review_session.v0.1",
        "frontier_id": project.frontier_id(),
        "start_time": start_time,
        "reviewers": reviewers,
        "changed_objects": changed_objects,
        "counts": {
            "accepted": accepted,
            "rejected": rejected,
            "needs_revision": needs_revision,
            "source_repairs": source_repairs,
            "entity_repairs": entity_repairs,
            "span_repairs": span_repairs,
            "stale_proof_state": stale_proof,
        },
        "proof_freshness": {
            "status": proof_status,
            "stale_reason": project.proof_state.stale_reason,
            "generated_at": project.proof_state.latest_packet.generated_at,
            "snapshot_hash": project.proof_state.latest_packet.snapshot_hash,
            "event_log_hash": project.proof_state.latest_packet.event_log_hash,
        },
        "decisions": decisions,
    })
}

async fn page_review_session(State(state): State<AppState>) -> Response {
    let project = match repo::load_from_path(&state.repo_path) {
        Ok(p) => p,
        Err(e) => return error_page("review", "Could not load frontier", &e),
    };
    let payload = review_session_payload(&project);
    let counts = payload.get("counts").unwrap_or(&serde_json::Value::Null);
    let decisions = payload
        .get("decisions")
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_default();
    let mut rows = String::new();
    for decision in decisions.iter().take(50) {
        let proposal_id = decision
            .get("proposal_id")
            .and_then(|value| value.as_str())
            .unwrap_or("unknown");
        let status = decision
            .get("status")
            .and_then(|value| value.as_str())
            .unwrap_or("unknown");
        let reviewer = decision
            .get("reviewer")
            .and_then(|value| value.as_str())
            .unwrap_or("unreviewed");
        let reason = decision
            .get("reason")
            .and_then(|value| value.as_str())
            .unwrap_or("no reason recorded");
        let target_type = decision
            .get("target")
            .and_then(|target| target.get("type"))
            .and_then(|value| value.as_str())
            .unwrap_or("object");
        let target_id = decision
            .get("target")
            .and_then(|target| target.get("id"))
            .and_then(|value| value.as_str())
            .unwrap_or("unknown");
        rows.push_str(&format!(
            r#"<tr><td><a href="/proposals/{proposal}/preview"><code>{proposal}</code></a></td><td><code>{status}</code></td><td><code>{target_type}:{target_id}</code></td><td><code>{reviewer}</code></td><td>{reason}</td></tr>"#,
            proposal = escape_html(proposal_id),
            status = escape_html(status),
            target_type = escape_html(target_type),
            target_id = escape_html(target_id),
            reviewer = escape_html(reviewer),
            reason = escape_html(reason),
        ));
    }
    if rows.is_empty() {
        rows.push_str(
            r#"<tr><td colspan="5">No reviewed proposals are recorded for this frontier.</td></tr>"#,
        );
    }
    let proof_status = payload
        .get("proof_freshness")
        .and_then(|proof| proof.get("status"))
        .and_then(|value| value.as_str())
        .unwrap_or("unknown");
    let body = format!(
        r#"<div class="wb-card">
  <h3>Review session</h3>
  <p>Local-only summary for <code>{frontier}</code>. Export the same state as <a href="/review/session.json">JSON</a>.</p>
</div>
<div class="wb-stats">
  <div><div class="wb-stat__num">{accepted}</div><div class="wb-stat__label">accepted</div></div>
  <div><div class="wb-stat__num">{rejected}</div><div class="wb-stat__label">rejected</div></div>
  <div><div class="wb-stat__num">{needs_revision}</div><div class="wb-stat__label">needs revision</div></div>
  <div><div class="wb-stat__num">{source_repairs}</div><div class="wb-stat__label">source repairs</div></div>
  <div><div class="wb-stat__num">{entity_repairs}</div><div class="wb-stat__label">entity repairs</div></div>
  <div><div class="wb-stat__num">{span_repairs}</div><div class="wb-stat__label">span repairs</div></div>
  <div><div class="wb-stat__num">{proof_status}</div><div class="wb-stat__label">proof freshness</div></div>
</div>
<div class="wb-card">
  <h3>Decisions</h3>
  <table class="wb-table"><thead><tr><th>proposal</th><th>decision</th><th>object</th><th>reviewer</th><th>reason</th></tr></thead><tbody>{rows}</tbody></table>
</div>"#,
        frontier = escape_html(&project.frontier_id()),
        accepted = counts
            .get("accepted")
            .and_then(|value| value.as_u64())
            .unwrap_or(0),
        rejected = counts
            .get("rejected")
            .and_then(|value| value.as_u64())
            .unwrap_or(0),
        needs_revision = counts
            .get("needs_revision")
            .and_then(|value| value.as_u64())
            .unwrap_or(0),
        source_repairs = counts
            .get("source_repairs")
            .and_then(|value| value.as_u64())
            .unwrap_or(0),
        entity_repairs = counts
            .get("entity_repairs")
            .and_then(|value| value.as_u64())
            .unwrap_or(0),
        span_repairs = counts
            .get("span_repairs")
            .and_then(|value| value.as_u64())
            .unwrap_or(0),
        proof_status = escape_html(proof_status),
        rows = rows,
    );
    Html(shell(
        "review",
        "Review session",
        "Workbench",
        "Review session",
        &body,
    ))
    .into_response()
}

async fn page_review_session_json(State(state): State<AppState>) -> Response {
    match repo::load_from_path(&state.repo_path) {
        Ok(project) => Json(review_session_payload(&project)).into_response(),
        Err(e) => error_page("review", "Could not load frontier", &e),
    }
}

async fn page_review_locator_repair(
    AxumPath(atom_id): AxumPath<String>,
    State(state): State<AppState>,
    Query(q): Query<ErrorTokenQuery>,
) -> Response {
    let project = match repo::load_from_path(&state.repo_path) {
        Ok(p) => p,
        Err(e) => return error_page("review", "Could not load frontier", &e),
    };
    let Some(atom) = project.evidence_atoms.iter().find(|a| a.id == atom_id) else {
        return error_page("review", "Atom not found", &atom_id);
    };
    let parent_locator = project
        .sources
        .iter()
        .find(|s| s.id == atom.source_id)
        .map(|s| s.locator.clone())
        .unwrap_or_default();
    // W1.5: replay typed values + validator error if redirected
    // back from a failed POST.
    let cached = q
        .error
        .as_deref()
        .and_then(|tok| take_form_state(&state, tok));
    let (locator_val, reviewer_val, reason_val, banner) = match cached {
        Some(FormState::LocatorRepair {
            locator,
            reviewer,
            reason,
            error,
            ..
        }) => (locator, reviewer, reason, render_error_banner(&error)),
        _ => (
            parent_locator.clone(),
            default_reviewer(),
            "Mechanical evidence-atom locator repair from parent source.".to_string(),
            String::new(),
        ),
    };
    let preview = render_mutation_preview(
        "Repair evidence atom locator",
        &atom.id,
        "proposal kind evidence_atom.locator_repair",
        "sets the evidence atom locator when the validator accepts it",
    );
    let body = format!(
        r#"{datalist}{banner}{preview}<div class="wb-card"><h3>Locator repair</h3>
<p>Atom <code>{aid}</code> on finding <code>{fid}</code>.</p>
<p>Parent source <code>{sid}</code> carries locator <code>{loc}</code>.</p>
<form method="post" action="/review/locator-repair">
<input type="hidden" name="atom_id" value="{aid_safe}">
<p><label>Locator <input name="locator" value="{loc_safe}" style="width:36rem;"></label></p>
<p><label>Reviewer <input name="reviewer" value="{rev}" list="vela-actors"></label></p>
<p><label>Reason <input name="reason" value="{reason_safe}" style="width:36rem;"></label></p>
<p><button type="submit">Apply</button> <a href="/review/inbox" style="margin-left:1rem;color:var(--ink-3);">Cancel</a></p>
</form></div>"#,
        datalist = actor_datalist(&project),
        banner = banner,
        preview = preview,
        aid = escape_html(&atom.id),
        aid_safe = escape_html(&atom.id),
        fid = escape_html(&atom.finding_id),
        sid = escape_html(&atom.source_id),
        loc = escape_html(&parent_locator),
        loc_safe = escape_html(&locator_val),
        rev = escape_html(&reviewer_val),
        reason_safe = escape_html(&reason_val),
    );
    let html = shell(
        "review",
        "Locator repair · Vela Workbench",
        "Workbench",
        "Locator repair",
        &body,
    );
    Html(html).into_response()
}

async fn post_review_locator_repair(
    State(state): State<AppState>,
    Form(form): Form<LocatorRepairForm>,
) -> Response {
    match state::repair_evidence_atom_locator(
        &state.repo_path,
        &form.atom_id,
        Some(&form.locator),
        &form.reviewer,
        &form.reason,
        true,
    ) {
        Ok(_) => Redirect::to("/review/inbox").into_response(),
        Err(e) => {
            // W1.5: preserve form values + bubble the validator
            // message inline instead of returning a 500.
            let token = store_form_state(
                &state,
                FormState::LocatorRepair {
                    atom_id: form.atom_id.clone(),
                    locator: form.locator.clone(),
                    reviewer: form.reviewer.clone(),
                    reason: form.reason.clone(),
                    error: e,
                },
            );
            let url = format!(
                "/review/locator-repair/{aid}?error={tok}",
                aid = urlencode_path(&form.atom_id),
                tok = token,
            );
            Redirect::to(&url).into_response()
        }
    }
}

async fn page_review_span_repair(
    AxumPath(finding_id): AxumPath<String>,
    State(state): State<AppState>,
    Query(q): Query<ErrorTokenQuery>,
) -> Response {
    let project = match repo::load_from_path(&state.repo_path) {
        Ok(p) => p,
        Err(e) => return error_page("review", "Could not load frontier", &e),
    };
    let Some(f) = project.findings.iter().find(|f| f.id == finding_id) else {
        return error_page("review", "Finding not found", &finding_id);
    };
    // Best-effort: pull abstract from cached source-fetch if present
    let cache_text = lookup_cached_abstract(&state.repo_path, f);
    let pre_text = cache_text.as_deref().unwrap_or("");
    let cache_note = if cache_text.is_some() {
        r#"<p style="color:var(--ink-3);font-size:0.86rem;">text pre-filled from sources/cache/</p>"#
    } else {
        ""
    };
    // W1.5: replay typed values from a failed POST if present.
    let cached = q
        .error
        .as_deref()
        .and_then(|tok| take_form_state(&state, tok));
    let (section_val, text_val, reviewer_val, reason_val, banner) = match cached {
        Some(FormState::SpanRepair {
            section,
            text,
            reviewer,
            reason,
            error,
            ..
        }) => (section, text, reviewer, reason, render_error_banner(&error)),
        _ => (
            "abstract".to_string(),
            pre_text.to_string(),
            default_reviewer(),
            "Reviewer-verified evidence span.".to_string(),
            String::new(),
        ),
    };
    let preview = render_mutation_preview(
        "Repair finding evidence span",
        &f.id,
        "proposal kind finding.span_repair",
        "appends one evidence span to the finding when the validator accepts it",
    );
    let body = format!(
        r#"{banner}{preview}<div class="wb-card"><h3>Span repair</h3>
<p>Finding <code>{fid}</code>.</p>
<p style="font-size:0.92rem;color:var(--ink-2);">{assertion}</p>
<form method="post" action="/review/span-repair">
<input type="hidden" name="finding_id" value="{fid_safe}">
<p><label>Section <input name="section" value="{section_safe}"></label></p>
<p><label>Text<br><textarea name="text" rows="6" style="width:36rem;">{text}</textarea></label></p>
{cache_note}
<p><label>Reviewer <input name="reviewer" value="{rev}" list="vela-actors"></label></p>
<p><label>Reason <input name="reason" value="{reason_safe}" style="width:36rem;"></label></p>
<p><button type="submit">Apply</button> <a href="/review/inbox" style="margin-left:1rem;color:var(--ink-3);">Cancel</a></p>
</form></div>"#,
        banner = banner,
        preview = preview,
        fid = escape_html(&f.id),
        fid_safe = escape_html(&f.id),
        assertion = escape_html(&f.assertion.text),
        section_safe = escape_html(&section_val),
        text = escape_html(&text_val),
        cache_note = cache_note,
        rev = escape_html(&reviewer_val),
        reason_safe = escape_html(&reason_val),
    );
    let body = format!("{}{}", actor_datalist(&project), body);
    let html = shell(
        "review",
        "Span repair · Vela Workbench",
        "Workbench",
        "Span repair",
        &body,
    );
    Html(html).into_response()
}

async fn post_review_span_repair(
    State(state): State<AppState>,
    Form(form): Form<SpanRepairForm>,
) -> Response {
    match state::repair_finding_span(
        &state.repo_path,
        &form.finding_id,
        &form.section,
        &form.text,
        &form.reviewer,
        &form.reason,
        true,
    ) {
        Ok(_) => Redirect::to("/review/inbox").into_response(),
        Err(e) => {
            let token = store_form_state(
                &state,
                FormState::SpanRepair {
                    finding_id: form.finding_id.clone(),
                    section: form.section.clone(),
                    text: form.text.clone(),
                    reviewer: form.reviewer.clone(),
                    reason: form.reason.clone(),
                    error: e,
                },
            );
            let url = format!(
                "/review/span-repair/{fid}?error={tok}",
                fid = urlencode_path(&form.finding_id),
                tok = token,
            );
            Redirect::to(&url).into_response()
        }
    }
}

async fn page_review_entity_resolve(
    AxumPath(finding_id): AxumPath<String>,
    State(state): State<AppState>,
    Query(q): Query<ErrorTokenQuery>,
) -> Response {
    let project = match repo::load_from_path(&state.repo_path) {
        Ok(p) => p,
        Err(e) => return error_page("review", "Could not load frontier", &e),
    };
    let Some(f) = project.findings.iter().find(|f| f.id == finding_id) else {
        return error_page("review", "Finding not found", &finding_id);
    };
    let unresolved: Vec<_> = f
        .assertion
        .entities
        .iter()
        .filter(|e| e.needs_review)
        .collect();
    if unresolved.is_empty() {
        return error_page(
            "review",
            "Nothing to resolve",
            "All entities on this finding are already resolved.",
        );
    }
    // W1.5: a single entity-resolve POST failure pre-fills exactly
    // the per-entity form whose submission was rejected; the
    // others render with their defaults.
    let cached_entity_state = q
        .error
        .as_deref()
        .and_then(|tok| take_form_state(&state, tok));
    let cached = match cached_entity_state {
        Some(FormState::EntityResolve {
            entity_name,
            source,
            id,
            confidence,
            matched_name,
            reviewer,
            reason,
            error,
            ..
        }) => Some((
            entity_name,
            source,
            id,
            confidence,
            matched_name,
            reviewer,
            reason,
            error,
        )),
        _ => None,
    };
    let banner = cached
        .as_ref()
        .map(|c| render_error_banner(&c.7))
        .unwrap_or_default();
    let mut forms = String::new();
    let source_options = |selected: &str| -> String {
        let opts = [
            ("hgnc", "HGNC (gene)"),
            ("uniprot", "UniProt (protein)"),
            ("mesh", "MeSH (disease/concept)"),
            ("uberon", "UBERON (anatomy)"),
            ("cl", "CL (cell type)"),
            ("drugbank", "DrugBank (compound)"),
            ("vela", "vela: (custom)"),
        ];
        let mut out = String::new();
        for (val, label) in opts {
            let sel = if val == selected { " selected" } else { "" };
            out.push_str(&format!(r#"<option value="{val}"{sel}>{label}</option>"#));
        }
        out
    };
    for ent in &unresolved {
        let (source_val, id_val, conf_val, matched_val, reviewer_val, reason_val) =
            match cached.as_ref() {
                Some(c) if c.0 == ent.name => (
                    c.1.clone(),
                    c.2.clone(),
                    c.3,
                    c.4.clone().unwrap_or_default(),
                    c.5.clone(),
                    c.6.clone(),
                ),
                _ => (
                    "hgnc".to_string(),
                    String::new(),
                    0.95,
                    String::new(),
                    default_reviewer(),
                    "Resolved against canonical biological databases.".to_string(),
                ),
            };
        let target = format!("{}:{}", f.id, ent.name);
        let preview = render_mutation_preview(
            "Resolve finding entity",
            &target,
            "proposal kind finding.entity_resolve",
            "sets entity resolution metadata and clears the entity review flag when the validator accepts it",
        );
        forms.push_str(&format!(
            r#"{preview}<div class="wb-card"><h3>{name} <span class="wb-chip wb-chip--warn">{etype}</span></h3>
<form method="post" action="/review/entity-resolve">
<input type="hidden" name="finding_id" value="{fid}">
<input type="hidden" name="entity_name" value="{name_safe}">
<p><label>Source <select name="source">
{src_opts}
</select></label></p>
<p><label>ID <input name="id" value="{id_val}" placeholder="e.g. 8804 or P05067"></label></p>
<p><label>Confidence <input name="confidence" type="number" min="0" max="1" step="0.01" value="{conf_val}"></label></p>
<p><label>Matched name <input name="matched_name" value="{matched_val}" placeholder="optional"></label></p>
<input type="hidden" name="resolution_method" value="manual">
<p><label>Reviewer <input name="reviewer" value="{rev}" list="vela-actors"></label></p>
<p><label>Reason <input name="reason" value="{reason_safe}" style="width:36rem;"></label></p>
<p><button type="submit">Apply</button> <a href="/review/inbox" style="margin-left:1rem;color:var(--ink-3);">Cancel</a></p>
</form></div>"#,
            preview = preview,
            name = escape_html(&ent.name),
            name_safe = escape_html(&ent.name),
            etype = escape_html(&ent.entity_type),
            fid = escape_html(&f.id),
            src_opts = source_options(&source_val),
            id_val = escape_html(&id_val),
            conf_val = conf_val,
            matched_val = escape_html(&matched_val),
            rev = escape_html(&reviewer_val),
            reason_safe = escape_html(&reason_val),
        ));
    }
    let body = format!(
        r#"{banner}<div class="wb-card"><h3>Entity resolution for <code>{fid}</code></h3>
<p style="font-size:0.92rem;color:var(--ink-2);">{assertion}</p>
<p>{n} unresolved entities below.</p>
</div>{forms}"#,
        banner = banner,
        fid = escape_html(&f.id),
        assertion = escape_html(&f.assertion.text),
        n = unresolved.len(),
        forms = forms,
    );
    let body = format!("{}{}", actor_datalist(&project), body);
    let html = shell(
        "review",
        "Entity resolve · Vela Workbench",
        "Workbench",
        "Entity resolve",
        &body,
    );
    Html(html).into_response()
}

async fn post_review_entity_resolve(
    State(state): State<AppState>,
    Form(form): Form<EntityResolveForm>,
) -> Response {
    match state::resolve_finding_entity(
        &state.repo_path,
        &form.finding_id,
        &form.entity_name,
        &form.source,
        &form.id,
        form.confidence,
        form.matched_name.as_deref(),
        &form.resolution_method,
        &form.reviewer,
        &form.reason,
        true,
    ) {
        Ok(_) => Redirect::to("/review/inbox").into_response(),
        Err(e) => {
            let token = store_form_state(
                &state,
                FormState::EntityResolve {
                    finding_id: form.finding_id.clone(),
                    entity_name: form.entity_name.clone(),
                    source: form.source.clone(),
                    id: form.id.clone(),
                    confidence: form.confidence,
                    matched_name: form.matched_name.clone(),
                    resolution_method: form.resolution_method.clone(),
                    reviewer: form.reviewer.clone(),
                    reason: form.reason.clone(),
                    error: e,
                },
            );
            let url = format!(
                "/review/entity-resolve/{fid}?error={tok}",
                fid = urlencode_path(&form.finding_id),
                tok = token,
            );
            Redirect::to(&url).into_response()
        }
    }
}

// v0.59: promote-to-accepted-core write surface. Mirror of the
// `vela review` CLI; emits a canonical `finding.review` event
// under the configured reviewer identity.
async fn page_review_promote(
    AxumPath(finding_id): AxumPath<String>,
    State(state): State<AppState>,
    Query(q): Query<ErrorTokenQuery>,
) -> Response {
    let project = match repo::load_from_path(&state.repo_path) {
        Ok(p) => p,
        Err(e) => return error_page("review", "Could not load frontier", &e),
    };
    let Some(f) = project.findings.iter().find(|f| f.id == finding_id) else {
        return error_page("review", "Finding not found", &finding_id);
    };
    let current_state = match &f.flags.review_state {
        Some(vela_protocol::bundle::ReviewState::Accepted) => "accepted",
        Some(vela_protocol::bundle::ReviewState::Contested) => "contested",
        Some(vela_protocol::bundle::ReviewState::NeedsRevision) => "needs_revision",
        Some(vela_protocol::bundle::ReviewState::Rejected) => "rejected",
        None => "(unset)",
    };
    let assertion = escape_html(&f.assertion.text);
    let confidence = f.confidence.score;
    // V3.3 pain point 1+2: surface source attribution and evidence
    // spans inline. The reviewer should never need to click through
    // to verify the literal text behind an assertion before
    // promoting.
    let source_block = {
        let mut parts: Vec<String> = Vec::new();
        if let Some(doi) = f.provenance.doi.as_deref() {
            parts.push(format!("<code>doi:{}</code>", escape_html(doi)));
        }
        if let Some(pmid) = f.provenance.pmid.as_deref() {
            parts.push(format!("<code>pmid:{}</code>", escape_html(pmid)));
        }
        if let Some(y) = f.provenance.year {
            parts.push(format!("{y}"));
        }
        if let Some(j) = f.provenance.journal.as_deref()
            && !j.is_empty()
        {
            parts.push(escape_html(j));
        }
        if parts.is_empty() {
            "<span style=\"color:var(--ink-3);\">no source metadata</span>".to_string()
        } else {
            parts.join(" · ")
        }
    };
    let mut spans_block = String::new();
    if f.evidence.evidence_spans.is_empty() {
        spans_block.push_str(
            r#"<p style="color:var(--ink-3);font-size:0.86rem;">No evidence_spans attached. Repair the span via /review/span-repair before promoting if the source has retrievable text.</p>"#,
        );
    } else {
        spans_block.push_str(r#"<p style="color:var(--ink-3);font-size:0.86rem;margin-top:0.6rem;">Verbatim evidence spans attached to this finding. The reviewer's verdict should be readable as a one-step inference from these spans.</p>"#);
        // evidence_spans are stored as serde_json::Value; pull
        // section + text by key. Skip any malformed span rather than
        // crashing the page.
        for s in &f.evidence.evidence_spans {
            let section = s
                .get("section")
                .and_then(|v| v.as_str())
                .unwrap_or("(unsectioned)");
            let text = s.get("text").and_then(|v| v.as_str()).unwrap_or("");
            if text.is_empty() {
                continue;
            }
            spans_block.push_str(&format!(
                r#"<blockquote style="color:var(--ink-2);font-size:0.9rem;margin:0.4rem 0 0.6rem 0;border-left:2px solid var(--ink-4);padding-left:0.8rem;"><strong>[{section}]</strong> {text}</blockquote>"#,
                section = escape_html(section),
                text = escape_html(text),
            ));
        }
    }
    // W1.5: replay form values from a failed POST.
    let cached = q
        .error
        .as_deref()
        .and_then(|tok| take_form_state(&state, tok));
    let (status_val, reviewer_val, reason_val, banner) = match cached {
        Some(FormState::Promote {
            status,
            reviewer,
            reason,
            error,
            ..
        }) => (status, reviewer, reason, render_error_banner(&error)),
        _ => (
            "accepted".to_string(),
            default_reviewer(),
            String::new(),
            String::new(),
        ),
    };
    let status_options = {
        let opts = ["accepted", "contested", "needs_revision", "rejected"];
        let mut out = String::new();
        for v in opts {
            let sel = if v == status_val { " selected" } else { "" };
            out.push_str(&format!(r#"<option value="{v}"{sel}>{v}</option>"#));
        }
        out
    };
    let preview = render_mutation_preview(
        "Record finding review",
        &f.id,
        "proposal kind finding.review",
        "emits a reviewer event and sets the finding review state to the selected status when the validator accepts it",
    );
    let body = format!(
        r#"{banner}{preview}<div class="wb-card"><h3>Promote to accepted-core</h3>
<p>Finding <code>{fid}</code> · <a href="/findings/{fid}">inspect full record →</a></p>
<p>Source: {src}</p>
<p>Current review state: <code>{current}</code> · raw confidence: <code>{conf:.2}</code></p>
<p style="font-weight:500;margin-top:0.6rem;">Assertion</p>
<blockquote style="color:var(--ink-1);font-size:0.95rem;margin:0.2rem 0 0.6rem 0;border-left:2px solid var(--ink-4);padding-left:0.8rem;">{assertion}</blockquote>
<p style="font-weight:500;margin-top:0.6rem;">Evidence</p>
{spans_block}
<form method="post" action="/review/promote" style="margin-top:0.6rem;">
<input type="hidden" name="finding_id" value="{fid_safe}">
<p><label>Status
<select name="status">
{status_options}
</select>
</label></p>
<p><label>Reviewer <input name="reviewer" value="{rev}" list="vela-actors" required></label></p>
<p><label>Reason <input name="reason" value="{reason_safe}" placeholder="Reviewer's verdict rationale (cite the evidence span and the calibration anchor)" style="width:36rem;" required></label></p>
<p style="color:var(--ink-3);font-size:0.86rem;">Submission lands as a signed canonical `finding.review` event under the configured reviewer id. No silent edits; the event is replayable from `.vela/events/`.</p>
<p><button type="submit">Apply</button> <a href="/review/inbox" style="margin-left:1rem;color:var(--ink-3);">Cancel</a></p>
</form></div>"#,
        banner = banner,
        preview = preview,
        fid = escape_html(&f.id),
        fid_safe = escape_html(&f.id),
        current = current_state,
        conf = confidence,
        assertion = assertion,
        src = source_block,
        spans_block = spans_block,
        status_options = status_options,
        rev = escape_html(&reviewer_val),
        reason_safe = escape_html(&reason_val),
    );
    let body = format!("{}{}", actor_datalist(&project), body);
    let html = shell(
        "review",
        "Promote to accepted-core · Vela Workbench",
        "Workbench",
        "Promote to accepted-core",
        &body,
    );
    Html(html).into_response()
}

async fn post_review_promote(
    State(state): State<AppState>,
    Form(form): Form<PromoteForm>,
) -> Response {
    let options = state::ReviewOptions {
        status: form.status.clone(),
        reason: form.reason.clone(),
        reviewer: form.reviewer.clone(),
    };
    match state::review_finding(&state.repo_path, &form.finding_id, options, true) {
        Ok(_) => Redirect::to("/review/inbox").into_response(),
        Err(e) => {
            let token = store_form_state(
                &state,
                FormState::Promote {
                    finding_id: form.finding_id.clone(),
                    status: form.status.clone(),
                    reviewer: form.reviewer.clone(),
                    reason: form.reason.clone(),
                    error: e,
                },
            );
            let url = format!(
                "/review/promote/{fid}?error={tok}",
                fid = urlencode_path(&form.finding_id),
                tok = token,
            );
            Redirect::to(&url).into_response()
        }
    }
}

// v0.59: federation conflict-resolution write surface.
async fn page_review_conflict_resolve(
    AxumPath(conflict_event_id): AxumPath<String>,
    State(state): State<AppState>,
    Query(q): Query<ErrorTokenQuery>,
) -> Response {
    let project = match repo::load_from_path(&state.repo_path) {
        Ok(p) => p,
        Err(e) => return error_page("review", "Could not load frontier", &e),
    };
    let Some(conflict) = project
        .events
        .iter()
        .find(|e| e.id == conflict_event_id && e.kind == "frontier.conflict_detected")
    else {
        return error_page(
            "review",
            "Conflict event not found",
            &format!(
                "No `frontier.conflict_detected` event with id '{conflict_event_id}' on this frontier."
            ),
        );
    };
    // Refuse to render the form if a resolution event already
    // exists for this conflict; doctrine is one resolution per
    // conflict event.
    let already_resolved = project.events.iter().any(|e| {
        e.kind == "frontier.conflict_resolved"
            && e.payload.get("conflict_event_id").and_then(|v| v.as_str())
                == Some(&conflict_event_id)
    });
    if already_resolved {
        return error_page(
            "review",
            "Conflict already resolved",
            &format!(
                "Conflict event '{conflict_event_id}' already has a recorded resolution. The resolution event lives in the log; reviewers do not amend prior verdicts."
            ),
        );
    }
    let peer = conflict
        .payload
        .get("peer_id")
        .and_then(|v| v.as_str())
        .unwrap_or("?")
        .to_string();
    let finding_ref = conflict
        .payload
        .get("finding_id")
        .and_then(|v| v.as_str())
        .unwrap_or("?")
        .to_string();
    let kind = conflict
        .payload
        .get("kind")
        .and_then(|v| v.as_str())
        .unwrap_or("?")
        .to_string();
    let detail = conflict
        .payload
        .get("detail")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    // W1.5: replay form values from a failed POST.
    let cached = q
        .error
        .as_deref()
        .and_then(|tok| take_form_state(&state, tok));
    let (note_val, winning_val, reviewer_val, banner) = match cached {
        Some(FormState::ConflictResolve {
            resolution_note,
            winning_proposal_id,
            reviewer,
            error,
            ..
        }) => (
            resolution_note,
            winning_proposal_id.unwrap_or_default(),
            reviewer,
            render_error_banner(&error),
        ),
        _ => (
            String::new(),
            String::new(),
            default_reviewer(),
            String::new(),
        ),
    };
    let preview = render_mutation_preview(
        "Resolve frontier conflict",
        &conflict_event_id,
        "event kind frontier.conflict_resolved",
        "appends one conflict-resolution event; the original conflict event is not modified",
    );
    let body = format!(
        r#"{banner}{preview}<div class="wb-card"><h3>Resolve federation conflict</h3>
<p>Conflict event <code>{cid}</code></p>
<p>Detected by sync with peer <code>{peer}</code> on <code>{fid}</code> with kind <code>{kind}</code>.</p>
<p style="color:var(--ink-2);font-size:0.92rem;">{detail}</p>
<form method="post" action="/review/conflict-resolve">
<input type="hidden" name="conflict_event_id" value="{cid_safe}">
<p><label>Resolution note <input name="resolution_note" value="{note_safe}" placeholder="Reviewer's verdict and rationale" style="width:36rem;" required></label></p>
<p><label>Winning proposal id (optional) <input name="winning_proposal_id" value="{winning_safe}" placeholder="vpr_..." style="width:24rem;"></label></p>
<p><label>Reviewer <input name="reviewer" value="{rev}" list="vela-actors"></label></p>
<p style="color:var(--ink-3);font-size:0.86rem;">Submission lands as a signed canonical `frontier.conflict_resolved` event paired with the conflict by id. The original conflict event is not modified; one resolution per conflict.</p>
<p><button type="submit">Apply</button> <a href="/review/inbox" style="margin-left:1rem;color:var(--ink-3);">Cancel</a></p>
</form></div>"#,
        banner = banner,
        preview = preview,
        cid = escape_html(&conflict_event_id),
        cid_safe = escape_html(&conflict_event_id),
        peer = escape_html(&peer),
        fid = escape_html(&finding_ref),
        kind = escape_html(&kind),
        detail = escape_html(&detail),
        note_safe = escape_html(&note_val),
        winning_safe = escape_html(&winning_val),
        rev = escape_html(&reviewer_val),
    );
    let body = format!("{}{}", actor_datalist(&project), body);
    let html = shell(
        "review",
        "Resolve conflict · Vela Workbench",
        "Workbench",
        "Resolve conflict",
        &body,
    );
    Html(html).into_response()
}

async fn post_review_conflict_resolve(
    State(state): State<AppState>,
    Form(form): Form<ConflictResolveForm>,
) -> Response {
    let winning_proposal_id = form
        .winning_proposal_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    match state::resolve_frontier_conflict(
        &state.repo_path,
        &form.conflict_event_id,
        &form.resolution_note,
        &form.reviewer,
        winning_proposal_id,
        true,
    ) {
        Ok(_) => Redirect::to("/review/inbox").into_response(),
        Err(e) => {
            let token = store_form_state(
                &state,
                FormState::ConflictResolve {
                    conflict_event_id: form.conflict_event_id.clone(),
                    resolution_note: form.resolution_note.clone(),
                    winning_proposal_id: form.winning_proposal_id.clone(),
                    reviewer: form.reviewer.clone(),
                    error: e,
                },
            );
            let url = format!(
                "/review/conflict-resolve/{cid}?error={tok}",
                cid = urlencode_path(&form.conflict_event_id),
                tok = token,
            );
            Redirect::to(&url).into_response()
        }
    }
}

// v0.71: replication deposit write surface. Reviewer attaches a
// Replication record (target finding + outcome + conditions +
// source) via state::deposit_replication, which emits a
// canonical replication.deposited event under the configured
// reviewer id and pushes onto Project.replications. Idempotent
// per content-addressed `vrep_*` id.
async fn page_review_replication_add(
    AxumPath(finding_id): AxumPath<String>,
    State(state): State<AppState>,
    Query(error_q): Query<ErrorTokenQuery>,
) -> Response {
    let project = match repo::load_from_path(&state.repo_path) {
        Ok(p) => p,
        Err(e) => return error_page("review", "Could not load frontier", &e),
    };
    let Some(f) = project.findings.iter().find(|f| f.id == finding_id) else {
        return error_page("review", "Finding not found", &finding_id);
    };
    let cached = error_q
        .error
        .as_deref()
        .and_then(|tok| take_form_state(&state, tok));
    let (outcome, attempted_by, conditions_text, source_title, doi, pmid, note, error_html) =
        if let Some(FormState::ReplicationAdd {
            outcome,
            attempted_by,
            conditions_text,
            source_title,
            doi,
            pmid,
            note,
            error,
            ..
        }) = cached
        {
            (
                outcome,
                attempted_by,
                conditions_text,
                source_title,
                doi,
                pmid,
                note,
                render_error_banner(&error),
            )
        } else {
            (
                "replicated".to_string(),
                default_reviewer(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
            )
        };
    let assertion = escape_html(&f.assertion.text);
    let preview = render_mutation_preview(
        "Deposit replication record",
        &f.id,
        "event kind replication.deposited",
        "appends one replication record and its event when the validator accepts it",
    );
    let body = format!(
        r#"{datalist}{error_html}{preview}<div class="wb-card"><h3>Add replication</h3>
<p>Finding <code>{fid}</code> · <a href="/findings/{fid}">inspect full record →</a></p>
<blockquote style="color:var(--ink-2);font-size:0.92rem;margin:0.4rem 0 0.8rem 0;border-left:2px solid var(--ink-4);padding-left:0.8rem;">{assertion}</blockquote>
<form method="post" action="/review/replication-add" style="margin-top:0.6rem;">
<input type="hidden" name="finding_id" value="{fid_safe}">
<p><label>Outcome
<select name="outcome">
<option value="replicated"{sel_rep}>replicated</option>
<option value="failed"{sel_fail}>failed</option>
<option value="partial"{sel_part}>partial</option>
<option value="inconclusive"{sel_inc}>inconclusive</option>
</select>
</label></p>
<p><label>Attempted by <input name="attempted_by" value="{attempted_by_safe}" list="vela-actors" required></label></p>
<p><label>Conditions <input name="conditions_text" value="{conditions_safe}" placeholder="model system, species, in vitro/vivo, dosing" style="width:36rem;" required></label></p>
<p><label>Source title <input name="source_title" value="{source_title_safe}" placeholder="Replicating paper or lab notebook" style="width:36rem;" required></label></p>
<p><label>DOI <input name="doi" value="{doi_safe}" placeholder="10.1038/..."></label> <label>PMID <input name="pmid" value="{pmid_safe}"></label></p>
<p><label>Note <input name="note" value="{note_safe}" placeholder="Reviewer note (esp. partial/inconclusive outcomes)" style="width:36rem;"></label></p>
<p style="color:var(--ink-3);font-size:0.86rem;">Submission lands as a signed canonical `replication.deposited` event under the configured reviewer id. The substrate refuses duplicate deposits at the content-addressed `vrep_*` id.</p>
<p><button type="submit">Apply</button> <a href="/review/inbox" style="margin-left:1rem;color:var(--ink-3);">Cancel</a></p>
</form></div>"#,
        datalist = actor_datalist(&project),
        error_html = error_html,
        preview = preview,
        fid = escape_html(&f.id),
        fid_safe = escape_html(&f.id),
        assertion = assertion,
        attempted_by_safe = escape_html(&attempted_by),
        conditions_safe = escape_html(&conditions_text),
        source_title_safe = escape_html(&source_title),
        doi_safe = escape_html(&doi),
        pmid_safe = escape_html(&pmid),
        note_safe = escape_html(&note),
        sel_rep = if outcome == "replicated" {
            " selected"
        } else {
            ""
        },
        sel_fail = if outcome == "failed" { " selected" } else { "" },
        sel_part = if outcome == "partial" {
            " selected"
        } else {
            ""
        },
        sel_inc = if outcome == "inconclusive" {
            " selected"
        } else {
            ""
        },
    );
    let html = shell(
        "review",
        "Add replication · Vela Workbench",
        "Workbench",
        "Add replication",
        &body,
    );
    Html(html).into_response()
}

async fn post_review_replication_add(
    State(state): State<AppState>,
    Form(form): Form<ReplicationAddForm>,
) -> Response {
    use vela_protocol::bundle::{Conditions, Evidence, Extraction, Provenance, Replication};

    let evidence = Evidence {
        evidence_type: "experimental".to_string(),
        model_system: String::new(),
        species: None,
        method: "manual".to_string(),
        sample_size: None,
        effect_size: None,
        p_value: None,
        replicated: form.outcome == "replicated",
        replication_count: None,
        evidence_spans: Vec::new(),
    };
    let lower = form.conditions_text.to_lowercase();
    let conditions = Conditions {
        text: form.conditions_text.clone(),
        species_verified: Vec::new(),
        species_unverified: Vec::new(),
        in_vitro: lower.contains("in vitro"),
        in_vivo: lower.contains("in vivo"),
        human_data: lower.contains("human"),
        clinical_trial: lower.contains("clinical trial") || lower.contains("phase"),
        concentration_range: None,
        duration: None,
        age_group: None,
        cell_type: None,
    };
    let provenance = Provenance {
        title: form.source_title.clone(),
        source_type: "lab_notebook".to_string(),
        doi: if form.doi.trim().is_empty() {
            None
        } else {
            Some(form.doi.trim().to_string())
        },
        pmid: if form.pmid.trim().is_empty() {
            None
        } else {
            Some(form.pmid.trim().to_string())
        },
        pmc: None,
        openalex_id: None,
        url: None,
        authors: Vec::new(),
        year: None,
        journal: None,
        license: None,
        publisher: None,
        funders: Vec::new(),
        extraction: Extraction::default(),
        review: None,
        citation_count: None,
    };
    let rep = Replication::new(
        form.finding_id.clone(),
        form.attempted_by.clone(),
        form.outcome.clone(),
        evidence,
        conditions,
        provenance,
        form.note.clone(),
    );
    match state::deposit_replication(
        &state.repo_path,
        rep,
        &form.attempted_by,
        "Replication deposit via local Workbench",
    ) {
        Ok(_) => Redirect::to("/review/inbox").into_response(),
        Err(e) => {
            let token = store_form_state(
                &state,
                FormState::ReplicationAdd {
                    finding_id: form.finding_id.clone(),
                    outcome: form.outcome.clone(),
                    attempted_by: form.attempted_by.clone(),
                    conditions_text: form.conditions_text.clone(),
                    source_title: form.source_title.clone(),
                    doi: form.doi.clone(),
                    pmid: form.pmid.clone(),
                    note: form.note.clone(),
                    error: e,
                },
            );
            let url = format!(
                "/review/replication-add/{fid}?error={tok}",
                fid = urlencode_path(&form.finding_id),
                tok = token,
            );
            Redirect::to(&url).into_response()
        }
    }
}

// v0.71: prediction deposit write surface. Reviewer attaches a
// falsifiable Prediction record (claim, resolves-by deadline,
// resolution criterion, expected outcome) via
// state::deposit_prediction. Idempotent per content-addressed
// `vpred_*` id.
async fn page_review_prediction_add(
    AxumPath(finding_id): AxumPath<String>,
    State(state): State<AppState>,
    Query(error_q): Query<ErrorTokenQuery>,
) -> Response {
    let project = match repo::load_from_path(&state.repo_path) {
        Ok(p) => p,
        Err(e) => return error_page("review", "Could not load frontier", &e),
    };
    let Some(f) = project.findings.iter().find(|f| f.id == finding_id) else {
        return error_page("review", "Finding not found", &finding_id);
    };
    let cached = error_q
        .error
        .as_deref()
        .and_then(|tok| take_form_state(&state, tok));
    let (
        claim_text,
        resolves_by,
        resolution_criterion,
        expected_outcome,
        made_by,
        confidence,
        conditions_text,
        error_html,
    ) = if let Some(FormState::PredictionAdd {
        claim_text,
        resolves_by,
        resolution_criterion,
        expected_outcome,
        made_by,
        confidence,
        conditions_text,
        error,
        ..
    }) = cached
    {
        (
            claim_text,
            resolves_by,
            resolution_criterion,
            expected_outcome,
            made_by,
            confidence,
            conditions_text,
            render_error_banner(&error),
        )
    } else {
        (
            String::new(),
            String::new(),
            String::new(),
            "affirmed".to_string(),
            default_reviewer(),
            0.7,
            String::new(),
            String::new(),
        )
    };
    let assertion = escape_html(&f.assertion.text);
    let preview = render_mutation_preview(
        "Deposit prediction record",
        &f.id,
        "event kind prediction.deposited",
        "appends one prediction record and its event when the validator accepts it",
    );
    let body = format!(
        r#"{datalist}{error_html}{preview}<div class="wb-card"><h3>Add prediction</h3>
<p>Finding <code>{fid}</code> · <a href="/findings/{fid}">inspect full record →</a></p>
<blockquote style="color:var(--ink-2);font-size:0.92rem;margin:0.4rem 0 0.8rem 0;border-left:2px solid var(--ink-4);padding-left:0.8rem;">{assertion}</blockquote>
<form method="post" action="/review/prediction-add" style="margin-top:0.6rem;">
<input type="hidden" name="finding_id" value="{fid_safe}">
<p><label>Falsifiable claim <input name="claim_text" value="{claim_safe}" placeholder="What you expect to be true" style="width:36rem;" required></label></p>
<p><label>Resolves by (RFC 3339 or empty for open-ended) <input name="resolves_by" value="{rb_safe}" placeholder="2027-06-30T00:00:00Z" style="width:24rem;"></label></p>
<p><label>Resolution criterion <input name="resolution_criterion" value="{rc_safe}" placeholder="We will know this resolved when..." style="width:36rem;" required></label></p>
<p><label>Expected outcome
<select name="expected_outcome">
<option value="affirmed"{sel_aff}>affirmed</option>
<option value="falsified"{sel_fal}>falsified</option>
</select>
</label></p>
<p><label>Made by <input name="made_by" value="{made_by_safe}" list="vela-actors" required></label></p>
<p><label>Prior belief (0..1) <input name="confidence" type="number" step="0.01" min="0" max="1" value="{conf:.2}" required></label></p>
<p><label>Conditions <input name="conditions_text" value="{cond_safe}" placeholder="When this prediction applies" style="width:36rem;"></label></p>
<p style="color:var(--ink-3);font-size:0.86rem;">Submission lands as a signed canonical `prediction.deposited` event. Brier scoring runs at resolution time; calibration is part of the proof.</p>
<p><button type="submit">Apply</button> <a href="/review/inbox" style="margin-left:1rem;color:var(--ink-3);">Cancel</a></p>
</form></div>"#,
        datalist = actor_datalist(&project),
        error_html = error_html,
        preview = preview,
        fid = escape_html(&f.id),
        fid_safe = escape_html(&f.id),
        assertion = assertion,
        claim_safe = escape_html(&claim_text),
        rb_safe = escape_html(&resolves_by),
        rc_safe = escape_html(&resolution_criterion),
        made_by_safe = escape_html(&made_by),
        conf = confidence,
        cond_safe = escape_html(&conditions_text),
        sel_aff = if expected_outcome == "affirmed" {
            " selected"
        } else {
            ""
        },
        sel_fal = if expected_outcome == "falsified" {
            " selected"
        } else {
            ""
        },
    );
    let html = shell(
        "review",
        "Add prediction · Vela Workbench",
        "Workbench",
        "Add prediction",
        &body,
    );
    Html(html).into_response()
}

async fn post_review_prediction_add(
    State(state): State<AppState>,
    Form(form): Form<PredictionAddForm>,
) -> Response {
    use vela_protocol::bundle::{Conditions, ExpectedOutcome, Prediction};
    use chrono::Utc;

    let lower = form.conditions_text.to_lowercase();
    let conditions = Conditions {
        text: form.conditions_text.clone(),
        species_verified: Vec::new(),
        species_unverified: Vec::new(),
        in_vitro: lower.contains("in vitro"),
        in_vivo: lower.contains("in vivo"),
        human_data: lower.contains("human"),
        clinical_trial: lower.contains("clinical trial") || lower.contains("phase"),
        concentration_range: None,
        duration: None,
        age_group: None,
        cell_type: None,
    };
    let expected = match form.expected_outcome.as_str() {
        "affirmed" => ExpectedOutcome::Affirmed,
        "falsified" => ExpectedOutcome::Falsified,
        _ => ExpectedOutcome::Affirmed,
    };
    let resolves_by = if form.resolves_by.trim().is_empty() {
        None
    } else {
        Some(form.resolves_by.trim().to_string())
    };
    let predicted_at = Utc::now().to_rfc3339();
    let pred = Prediction::new(
        form.claim_text.clone(),
        vec![form.finding_id.clone()],
        Some(predicted_at),
        resolves_by,
        form.resolution_criterion.clone(),
        expected,
        form.made_by.clone(),
        form.confidence,
        conditions,
    );
    match state::deposit_prediction(
        &state.repo_path,
        pred,
        &form.made_by,
        "Prediction deposit via local Workbench",
    ) {
        Ok(_) => Redirect::to("/review/inbox").into_response(),
        Err(e) => {
            let token = store_form_state(
                &state,
                FormState::PredictionAdd {
                    finding_id: form.finding_id.clone(),
                    claim_text: form.claim_text.clone(),
                    resolves_by: form.resolves_by.clone(),
                    resolution_criterion: form.resolution_criterion.clone(),
                    expected_outcome: form.expected_outcome.clone(),
                    made_by: form.made_by.clone(),
                    confidence: form.confidence,
                    conditions_text: form.conditions_text.clone(),
                    error: e,
                },
            );
            let url = format!(
                "/review/prediction-add/{fid}?error={tok}",
                fid = urlencode_path(&form.finding_id),
                tok = token,
            );
            Redirect::to(&url).into_response()
        }
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        return s.to_string();
    }
    let mut out: String = s.chars().take(n).collect();
    out.push('…');
    out
}

fn lookup_cached_abstract(repo_path: &Path, finding: &FindingBundle) -> Option<String> {
    use sha2::{Digest, Sha256};
    // Reproduces vela source-fetch's normalize + cache key.
    let candidates = [
        finding.provenance.doi.as_ref().map(|d| format!("doi:{d}")),
        finding
            .provenance
            .pmid
            .as_ref()
            .map(|p| format!("pmid:{p}")),
    ];
    for opt in candidates.iter().flatten() {
        let hash = format!("{:x}", Sha256::digest(opt.as_bytes()));
        let p = repo_path
            .join("sources")
            .join("cache")
            .join(format!("{hash}.json"));
        if !p.is_file() {
            continue;
        }
        if let Ok(body) = std::fs::read_to_string(&p)
            && let Ok(value) = serde_json::from_str::<serde_json::Value>(&body)
            && let Some(abstract_text) = value.get("abstract").and_then(|v| v.as_str())
            && !abstract_text.is_empty()
        {
            return Some(abstract_text.to_string());
        }
    }
    None
}

// ============================================================================
// v0.174: review-thread surface (read-only list + detail).
// ============================================================================

async fn page_threads_list(State(state): State<AppState>) -> Response {
    let project = match repo::load_from_path(&state.repo_path) {
        Ok(p) => p,
        Err(e) => return error_page("threads", "Could not load frontier", &e),
    };
    let label = frontier_label(&project);
    let threads = vela_edge::review_thread::load_all_threads(&state.repo_path);

    let stats = format!(
        r#"<div class="wb-stats">
  <div><div class="wb-stat__num">{count}</div><div class="wb-stat__label">threads</div></div>
  <div><div class="wb-stat__num">{messages}</div><div class="wb-stat__label">messages</div></div>
  <div><div class="wb-stat__num">{vpr}</div><div class="wb-stat__label">on proposals</div></div>
  <div><div class="wb-stat__num">{vf}</div><div class="wb-stat__label">on findings</div></div>
</div>"#,
        count = threads.len(),
        messages = threads.iter().map(|t| t.messages.len()).sum::<usize>(),
        vpr = threads
            .iter()
            .filter(|t| matches!(
                t.target_kind,
                vela_edge::review_thread::ThreadTargetKind::Proposal
            ))
            .count(),
        vf = threads
            .iter()
            .filter(|t| matches!(
                t.target_kind,
                vela_edge::review_thread::ThreadTargetKind::Finding
            ))
            .count(),
    );

    let rows = if threads.is_empty() {
        r#"<p class="wb-empty">No review threads yet. Create one with <code>vela review-thread create &lt;target&gt; --frontier-id &lt;vfr_…&gt; --out &lt;frontier&gt;/.vela/review-threads/&lt;thread_id&gt;.json</code>. The workbench reads from that directory.</p>"#
            .to_string()
    } else {
        let body: String = threads
            .iter()
            .map(|t| {
                let target_kind = match t.target_kind {
                    vela_edge::review_thread::ThreadTargetKind::Proposal => "proposal",
                    vela_edge::review_thread::ThreadTargetKind::Finding => "finding",
                    vela_edge::review_thread::ThreadTargetKind::DiffPack => "diff_pack",
                };
                let last_activity = t
                    .messages
                    .last()
                    .map(|m| m.posted_at.as_str())
                    .unwrap_or("n/a");
                format!(
                    r#"<tr>
  <td><a href="/threads/{tid}"><code>{tid}</code></a></td>
  <td>{kind}</td>
  <td><code>{target}</code></td>
  <td>{count}</td>
  <td>{created}</td>
  <td>{last}</td>
</tr>"#,
                    tid = escape_html(&t.thread_id),
                    kind = target_kind,
                    target = escape_html(&t.target_id),
                    count = t.messages.len(),
                    created = escape_html(&t.created_at),
                    last = escape_html(last_activity),
                )
            })
            .collect();
        format!(
            r#"<table class="wb-table">
  <thead><tr>
    <th>thread</th><th>kind</th><th>target</th><th>messages</th><th>created</th><th>last activity</th>
  </tr></thead>
  <tbody>{body}</tbody>
</table>"#,
            body = body,
        )
    };

    let body = format!(
        r#"<p class="wb-card">Review threads are append-only, signed comment chains on a proposal or finding. The substrate-side write surface lives at <code>vela review-thread post</code>; this page is read-only.</p>
{stats}
{rows}"#,
        stats = stats,
        rows = rows,
    );

    Html(shell(
        "threads",
        &format!("Threads · {label}"),
        "11 · Threads",
        "Review threads",
        &body,
    ))
    .into_response()
}

async fn page_thread_detail(
    State(state): State<AppState>,
    AxumPath(thread_id): AxumPath<String>,
) -> Response {
    let project = match repo::load_from_path(&state.repo_path) {
        Ok(p) => p,
        Err(e) => return error_page("threads", "Could not load frontier", &e),
    };
    let label = frontier_label(&project);
    let thread = match vela_edge::review_thread::load_thread(&state.repo_path, &thread_id) {
        Some(t) => t,
        None => return error_page("threads", "Thread not found", &thread_id),
    };

    let target_kind = match thread.target_kind {
        vela_edge::review_thread::ThreadTargetKind::Proposal => "proposal",
        vela_edge::review_thread::ThreadTargetKind::Finding => "finding",
        vela_edge::review_thread::ThreadTargetKind::DiffPack => "diff_pack",
    };

    let messages_html: String = if thread.messages.is_empty() {
        r#"<p class="wb-empty">No messages yet.</p>"#.to_string()
    } else {
        thread
            .messages
            .iter()
            .enumerate()
            .map(|(i, m)| {
                let verified = m
                    .verify()
                    .map(|_| r#"<span class="wb-chip wb-chip--ok">signature ok</span>"#)
                    .unwrap_or(r#"<span class="wb-chip wb-chip--warn">signature missing or invalid</span>"#);
                let parent = m
                    .parent_message_id
                    .as_ref()
                    .map(|p| format!(r#"<div class="wb-msg__parent">reply to <code>{}</code></div>"#, escape_html(p)))
                    .unwrap_or_default();
                format!(
                    r#"<article class="wb-msg" id="m{i}">
  <header class="wb-msg__head">
    <code class="wb-msg__id">{id}</code>
    <span class="wb-msg__author">{author}</span>
    <time class="wb-msg__time">{posted}</time>
    {verified}
  </header>
  {parent}
  <div class="wb-msg__body">{body}</div>
</article>"#,
                    i = i,
                    id = escape_html(&m.message_id),
                    author = escape_html(&m.author_actor_id),
                    posted = escape_html(&m.posted_at),
                    verified = verified,
                    parent = parent,
                    body = escape_html(&m.body),
                )
            })
            .collect()
    };

    let body = format!(
        r#"<dl class="wb-meta">
  <dt>target</dt><dd>{kind} <code>{target}</code></dd>
  <dt>frontier</dt><dd><code>{frontier}</code></dd>
  <dt>thread id</dt><dd><code>{tid}</code></dd>
  <dt>created</dt><dd>{created}</dd>
  <dt>messages</dt><dd>{count}</dd>
</dl>
<style>
  .wb-meta {{ display: grid; grid-template-columns: max-content 1fr; gap: 0.2rem 0.8rem; margin: 0 0 1rem 0; font-size: 0.9rem; }}
  .wb-meta dt {{ color: var(--ink-2, #6b665d); }}
  .wb-meta dd {{ margin: 0; }}
  .wb-msg {{ border: 1px solid var(--rule-2, #d8d4cc); padding: 0.85rem 1rem; margin: 0 0 0.85rem 0; }}
  .wb-msg__head {{ display: flex; align-items: center; gap: 0.6rem; flex-wrap: wrap; margin-bottom: 0.4rem; font-size: 0.85rem; color: var(--ink-2, #6b665d); }}
  .wb-msg__id {{ font-family: ui-monospace, Menlo, monospace; }}
  .wb-msg__author {{ font-weight: 600; color: var(--ink-1, #1a1a1a); }}
  .wb-msg__parent {{ font-size: 0.78rem; color: var(--ink-3, #a09a8d); margin-bottom: 0.3rem; }}
  .wb-msg__body {{ white-space: pre-wrap; line-height: 1.55; }}
  .wb-empty {{ color: var(--ink-3, #a09a8d); font-style: italic; }}
</style>
{messages}
<p class="wb-foot">Post a reply with <code>vela review-thread post &lt;thread.json&gt; --author-actor-id &lt;vac_…&gt; --key &lt;key.hex&gt; --message "&lt;text&gt;"</code>.</p>"#,
        kind = target_kind,
        target = escape_html(&thread.target_id),
        frontier = escape_html(&thread.frontier_id),
        tid = escape_html(&thread.thread_id),
        created = escape_html(&thread.created_at),
        count = thread.messages.len(),
        messages = messages_html,
    );

    Html(shell(
        "threads",
        &format!("Thread {thread_id} · {label}"),
        "11 · Threads",
        &format!("Thread on {target_kind} {}", thread.target_id),
        &body,
    ))
    .into_response()
}

// ── v0.203 Diff Pack reviewer surface ────────────────────────────────

/// v0.222: load packs by walking the canonical `released_diff_packs`
/// field on `Project` and resolving each entry to a full
/// `ScientificDiffPack` on disk. Packs that exist on disk but lack a
/// `diff_pack.released` event are skipped; the substrate field is
/// the source of truth for "which packs are released," and disk
/// files are the backing store for body details (member proposals,
/// signature). Pre-v0.222 the workbench walked disk directly, which
/// surfaced unreleased drafts as if they were canonical.
fn list_released_diff_packs(project: &Project, repo_path: &Path) -> Vec<ScientificDiffPack> {
    let dir = repo_path.join(".vela").join("diff_packs");
    let mut out: Vec<ScientificDiffPack> = Vec::new();
    for rec in &project.released_diff_packs {
        let path = dir.join(format!("{}.json", rec.pack_id));
        let Ok(body) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(pack) = serde_json::from_str::<ScientificDiffPack>(&body) else {
            continue;
        };
        out.push(pack);
    }
    out.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    out
}

async fn page_diff_packs_list(State(state): State<AppState>) -> Response {
    let project = match repo::load_from_path(&state.repo_path) {
        Ok(p) => p,
        Err(e) => return error_page("diff-packs", "Could not load frontier", &e),
    };
    let packs = list_released_diff_packs(&project, &state.repo_path);
    let rows: String = if packs.is_empty() {
        r#"<tr><td colspan="5" class="wb-empty">No Diff Packs on this frontier. Build one with <code>vela diff-pack create</code> or the vela_agent Python SDK.</td></tr>"#.to_string()
    } else {
        packs
            .iter()
            .map(|p| {
                let latest = diff_pack_review::latest_for_pack(&state.repo_path, &p.pack_id);
                let verdict_chip = match latest {
                    Some(v) => match v.verdict {
                        DiffPackVerdict::Accept => {
                            r#"<span class="wb-chip wb-chip--ok">pending: accepted</span>"#
                        }
                        DiffPackVerdict::Reject => {
                            r#"<span class="wb-chip wb-chip--lost">pending: rejected</span>"#
                        }
                        DiffPackVerdict::Revise => {
                            r#"<span class="wb-chip wb-chip--warn">pending: revision requested</span>"#
                        }
                    },
                    None => r#"<span class="wb-chip wb-chip--warn">unreviewed</span>"#,
                };
                format!(
                    r#"<tr>
  <td><a href="/diff-packs/{id}"><code>{id_short}</code></a></td>
  <td>{summary}</td>
  <td><code>{kind}</code></td>
  <td>{n}</td>
  <td>{chip}</td>
</tr>"#,
                    id = escape_html(&p.pack_id),
                    id_short = escape_html(&p.pack_id),
                    summary = escape_html(&p.summary),
                    kind = escape_html(&p.aggregate_kind),
                    n = p.proposals.len(),
                    chip = verdict_chip,
                )
            })
            .collect()
    };
    let body = format!(
        r#"<p>{count} Diff Pack{plural} on this frontier. Localhost-only reviewer surface; verdicts are written to <code>.vela/pending_verdicts/</code> and promoted to canonical events at v0.205.</p>
<table class="wb-table">
  <thead>
    <tr><th>pack</th><th>summary</th><th>kind</th><th>members</th><th>status</th></tr>
  </thead>
  <tbody>
    {rows}
  </tbody>
</table>"#,
        count = packs.len(),
        plural = if packs.len() == 1 { "" } else { "s" },
        rows = rows,
    );
    Html(shell(
        "diff-packs",
        "Diff Packs",
        "12 · Diff packs",
        "Scientific Diff Packs",
        &body,
    ))
    .into_response()
}

fn diff_pack_verdict_review_state(verdict: DiffPackVerdict) -> &'static str {
    match verdict {
        DiffPackVerdict::Accept => "accepted",
        DiffPackVerdict::Reject => "rejected",
        DiffPackVerdict::Revise => "revision requested",
    }
}

async fn page_diff_pack_detail(
    AxumPath(pack_id): AxumPath<String>,
    State(state): State<AppState>,
) -> Response {
    let pack_path = state
        .repo_path
        .join(".vela")
        .join("diff_packs")
        .join(format!("{pack_id}.json"));
    let body_raw = match std::fs::read_to_string(&pack_path) {
        Ok(s) => s,
        Err(e) => {
            return error_page(
                "diff-packs",
                "Pack not found",
                &format!("{}: {e}", pack_path.display()),
            );
        }
    };
    let pack: ScientificDiffPack = match serde_json::from_str(&body_raw) {
        Ok(p) => p,
        Err(e) => return error_page("diff-packs", "Could not parse pack", &e.to_string()),
    };
    if let Err(e) = pack.verify() {
        return error_page("diff-packs", "Pack signature does not verify", &e);
    }
    let project_for_events = repo::load_from_path(&state.repo_path).ok();

    // Resolve every member proposal stub from
    // .vela/agent_proposals/<vpr>.json. The canonical
    // .vela/proposals/ directory holds substrate-validated
    // StateProposal records loaded by repo::load_from_path; SDK
    // stubs are a distinct producer-side primitive.
    let prop_dir = state.repo_path.join(".vela").join("agent_proposals");
    let members_html: String = pack
        .proposals
        .iter()
        .enumerate()
        .map(|(idx, vpr)| {
            let path = prop_dir.join(format!("{vpr}.json"));
            let payload = match std::fs::read_to_string(&path) {
                Ok(text) => match serde_json::from_str::<serde_json::Value>(&text) {
                    Ok(v) => serde_json::to_string_pretty(&v).unwrap_or(text),
                    Err(_) => text,
                },
                Err(_) => format!(
                    "(no SDK stub on disk for {}; member is referenced by id only)",
                    vpr
                ),
            };
            format!(
                r#"<div class="wb-card">
  <h3><span class="wb-chip wb-chip--warn">{idx:02}</span><code>{vpr}</code></h3>
  <pre class="wb-pre">{payload}</pre>
</div>"#,
                idx = idx + 1,
                vpr = escape_html(vpr),
                payload = escape_html(&payload),
            )
        })
        .collect();

    let pending = diff_pack_review::latest_for_pack(&state.repo_path, &pack.pack_id);
    let pending_html = match &pending {
        Some(v) => {
            let review_state = diff_pack_verdict_review_state(v.verdict);
            format!(
                r#"<div class="wb-card"><p><strong>Existing pending verdict</strong> <code>{vid}</code>: review state <code>{review_state}</code> by <code>{actor}</code> at {at}. Reason: {reason}</p><p class="wb-meta__note">A re-submission below will replace this verdict (idempotent on identical inputs).</p></div>"#,
                vid = escape_html(&v.verdict_id),
                review_state = escape_html(review_state),
                actor = escape_html(&v.reviewer_actor),
                at = escape_html(&v.at),
                reason = escape_html(&v.reason),
            )
        }
        None => String::new(),
    };
    let canonical_event_rows = project_for_events
        .as_ref()
        .map(|project| {
            project
                .events
                .iter()
                .filter(|event| event.kind == "diff_pack.reviewed")
                .filter(|event| {
                    event
                        .payload
                        .get("pack_id")
                        .or_else(|| event.payload.get("diff_pack_id"))
                        .and_then(|value| value.as_str())
                        == Some(pack.pack_id.as_str())
                })
                .rev()
                .take(8)
                .map(|event| {
                    let state = event
                        .payload
                        .get("review_state")
                        .or_else(|| event.payload.get("verdict"))
                        .and_then(|value| value.as_str())
                        .unwrap_or("reviewed");
                    let actor = event
                        .payload
                        .get("reviewer")
                        .or_else(|| event.payload.get("actor"))
                        .and_then(|value| value.as_str())
                        .unwrap_or(event.actor.id.as_str());
                    let reason = event
                        .payload
                        .get("reason")
                        .and_then(|value| value.as_str())
                        .unwrap_or(event.reason.as_str());
                    format!(
                        r#"<tr><td><code>{id}</code></td><td><code>{state}</code></td><td><code>{actor}</code></td><td>{reason}</td><td><code>{at}</code></td></tr>"#,
                        id = escape_html(&event.id),
                        state = escape_html(state),
                        actor = escape_html(actor),
                        reason = escape_html(reason),
                        at = escape_html(&event.timestamp),
                    )
                })
                .collect::<String>()
        })
        .unwrap_or_default();
    let canonical_events_html = if canonical_event_rows.is_empty() {
        r#"<div class="wb-card"><h3>Canonical verdict events</h3><p class="wb-empty">No canonical <code>diff_pack.reviewed</code> event has been emitted for this pack yet. Promote a pending verdict with <code>vela diff-pack promote-verdicts FRONTIER --json</code>.</p></div>"#.to_string()
    } else {
        format!(
            r#"<div class="wb-card"><h3>Canonical verdict events</h3><table class="wb-table"><thead><tr><th>event</th><th>state</th><th>actor</th><th>reason</th><th>at</th></tr></thead><tbody>{canonical_event_rows}</tbody></table></div>"#
        )
    };

    let agent_run = pack
        .agent_run
        .as_deref()
        .map(|a| {
            format!(
                r#"<dt>agent run</dt><dd><code>{}</code></dd>"#,
                escape_html(a)
            )
        })
        .unwrap_or_default();
    let parent_pack = pack
        .parent_pack
        .as_deref()
        .map(|p| {
            format!(
                r#"<dt>parent pack</dt><dd><a href="/diff-packs/{p_safe}"><code>{p_safe}</code></a></dd>"#,
                p_safe = escape_html(p),
            )
        })
        .unwrap_or_default();
    let signer = pack
        .signer_pubkey_hex
        .as_deref()
        .map(|s| {
            format!(
                r#"<dt>signed by</dt><dd><code>{}</code></dd>"#,
                escape_html(s)
            )
        })
        .unwrap_or_else(|| r#"<dt>signed by</dt><dd>(unsigned)</dd>"#.to_string());

    let review_summary = pack.review_summary(&state.repo_path);
    let evidence_ci_html = match evidence_ci::run_diff_pack(&state.repo_path, &pack.pack_id) {
        Ok(report) => {
            let group_summary = render_evidence_ci_groups(&report);
            let issue_rows: String = report
                .checks
                .iter()
                .filter(|check| check.status != evidence_ci::EvidenceCiStatus::Passed)
                .take(12)
                .map(|check| {
                    format!(
                        r#"<tr><td>{status}</td><td><code>{id}</code></td><td><code>{target}</code></td><td>{message}</td></tr>"#,
                        status = escape_html(match check.status {
                            evidence_ci::EvidenceCiStatus::Passed => "pass",
                            evidence_ci::EvidenceCiStatus::Warning => "warn",
                            evidence_ci::EvidenceCiStatus::Failed => "fail",
                        }),
                        id = escape_html(&check.id),
                        target = escape_html(&check.target_id),
                        message = escape_html(&check.message),
                    )
                })
                .collect();
            let issue_table = if issue_rows.is_empty() {
                r#"<p class="wb-empty">No Evidence CI warnings or failures for this pack.</p>"#
                    .to_string()
            } else {
                format!(
                    r#"<table class="wb-table"><thead><tr><th>status</th><th>check</th><th>target</th><th>message</th></tr></thead><tbody>{issue_rows}</tbody></table>"#
                )
            };
            format!(
                r#"<section class="wb-card">
  <h2>Evidence CI</h2>
  <p class="wb-meta__note">Evidence CI checks whether this proposed state change is ready for review. It does not accept scientific state.</p>
  <dl class="wb-meta">
    <dt>status</dt><dd>{status}</dd>
    <dt>checks</dt><dd>{total}</dd>
    <dt>release-blocking checks</dt><dd>{release_blocking}</dd>
    <dt>review warnings</dt><dd>{review_warning}</dd>
    <dt>info checks</dt><dd>{info}</dd>
    <dt>warnings</dt><dd>{warnings}</dd>
    <dt>release-blocking failures</dt><dd>{blocking}</dd>
    <dt>CLI</dt><dd><code>vela diff-pack validate {frontier_path} {pack_id} --evidence-ci --json</code></dd>
  </dl>
  {group_summary}
  {issue_table}
</section>"#,
                status = if report.ok { "ready" } else { "blocked" },
                total = report.summary.total,
                release_blocking = report.summary.release_blocking,
                review_warning = report.summary.review_warning,
                info = report.summary.info,
                warnings = report.summary.warnings,
                blocking = report.summary.release_blocking_failed,
                frontier_path = escape_html(&state.repo_path.display().to_string()),
                pack_id = escape_html(&pack.pack_id),
                group_summary = group_summary,
                issue_table = issue_table,
            )
        }
        Err(e) => format!(
            r#"<section class="wb-card">
  <h2>Evidence CI</h2>
  <p>Could not run Evidence CI for this pack: {}</p>
</section>"#,
            escape_html(&e)
        ),
    };
    let render_list = |items: &[String]| -> String {
        if items.is_empty() {
            return r#"<p class="wb-empty">No explicit records in this pack.</p>"#.to_string();
        }
        let rows: String = items
            .iter()
            .map(|item| format!(r#"<li>{}</li>"#, escape_html(item)))
            .collect();
        format!(r#"<ul class="wb-list">{rows}</ul>"#)
    };
    let operations_html = if review_summary.proposed_operations.is_empty() {
        r#"<p class="wb-empty">No proposed operations resolved.</p>"#.to_string()
    } else {
        let rows: String = review_summary
            .proposed_operations
            .iter()
            .map(|op| {
                let preview = op.preview_counts.as_ref().map(|counts| {
                    format!(
                        "findings {:+}, artifacts {:+}, events {:+}",
                        counts.findings_delta, counts.artifacts_delta, counts.events_delta
                    )
                }).unwrap_or_else(|| "referenced by id".to_string());
                let requirements = if op.review_requirements.is_empty() {
                    "local review".to_string()
                } else {
                    op.review_requirements.join(", ")
                };
                let policy = format!(
                    "{} · {} reviewer{} · roles: {} · reason: {} · agents: {}",
                    op.review_class,
                    op.required_reviewer_count.max(1),
                    if op.required_reviewer_count == 1 { "" } else { "s" },
                    if op.required_reviewer_roles.is_empty() {
                        "local_reviewer".to_string()
                    } else {
                        op.required_reviewer_roles.join(", ")
                    },
                    if op.required_reason_fields.is_empty() {
                        "reason".to_string()
                    } else {
                        op.required_reason_fields.join(", ")
                    },
                    if op.allowed_agent_actions.is_empty() {
                        "none".to_string()
                    } else {
                        op.allowed_agent_actions.join(", ")
                    }
                );
                format!(
                    r#"<tr><td><code>{proposal}</code></td><td>{class}</td><td>{kind}</td><td>{target}</td><td>{preview}</td><td>{requirements}</td><td>{policy}</td><td>{summary}</td></tr>"#,
                    proposal = escape_html(&op.proposal_id),
                    class = escape_html(&op.operation_class),
                    kind = escape_html(&op.kind),
                    target = escape_html(op.target_id.as_deref().unwrap_or("")),
                    preview = escape_html(&preview),
                    requirements = escape_html(&requirements),
                    policy = escape_html(&policy),
                    summary = escape_html(&op.summary),
                )
            })
            .collect();
        format!(
            r#"<table class="wb-table"><thead><tr><th>proposal</th><th>operation</th><th>kind</th><th>target</th><th>preview</th><th>review</th><th>policy requirement</th><th>review note</th></tr></thead><tbody>{rows}</tbody></table>"#
        )
    };
    let cli_html = if review_summary.cli_equivalents.is_empty() {
        r#"<p class="wb-empty">No CLI equivalents available.</p>"#.to_string()
    } else {
        let rows: String = review_summary
            .cli_equivalents
            .iter()
            .map(|(name, cmd)| {
                format!(
                    r#"<dt>{}</dt><dd><code>{}</code></dd>"#,
                    escape_html(name),
                    escape_html(cmd)
                )
            })
            .collect();
        format!(r#"<dl class="wb-meta">{rows}</dl>"#)
    };
    let review_session_html = if review_summary.review_session_commands.is_empty() {
        r#"<p class="wb-empty">No review-session commands available.</p>"#.to_string()
    } else {
        let rows: String = review_summary
            .review_session_commands
            .iter()
            .map(|(name, cmd)| {
                format!(
                    r#"<dt>{}</dt><dd><code>{}</code></dd>"#,
                    escape_html(name),
                    escape_html(cmd)
                )
            })
            .collect();
        format!(
            r#"<p class="wb-meta__note">Scope: <code>{}</code>. Sessions are local review records; they do not accept frontier state.</p><dl class="wb-meta">{rows}</dl>"#,
            escape_html(&review_summary.review_session_scope)
        )
    };
    let attestations = reviewer_identity::attestations_for_target(&state.repo_path, &pack.pack_id)
        .unwrap_or_default();
    let missing_attestations = reviewer_identity::missing_roles_for_target(
        &state.repo_path,
        &pack.pack_id,
        &review_summary.required_reviewers,
    )
    .unwrap_or_else(|_| review_summary.required_reviewers.clone());
    let attestation_rows = if attestations.is_empty() {
        r#"<p class="wb-empty">No scoped attestations recorded for this Diff Pack.</p>"#.to_string()
    } else {
        let rows: String = attestations
            .iter()
            .map(|attestation| {
                let scopes = attestation
                    .reviewer
                    .declared_scopes
                    .iter()
                    .map(|scope| scope.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                format!(
                    r#"<tr><td><code>{id}</code></td><td><code>{reviewer}</code></td><td>{role}</td><td>{scopes}</td><td>{reason}</td></tr>"#,
                    id = escape_html(&attestation.attestation_id),
                    reviewer = escape_html(&attestation.reviewer.reviewer_id),
                    role = escape_html(&attestation.reviewer.role),
                    scopes = escape_html(&scopes),
                    reason = escape_html(&attestation.reason),
                )
            })
            .collect();
        format!(
            r#"<table class="wb-table"><thead><tr><th>attestation</th><th>reviewer</th><th>role</th><th>scope</th><th>reason</th></tr></thead><tbody>{rows}</tbody></table>"#
        )
    };
    let missing_html = if missing_attestations.is_empty() {
        r#"<p class="wb-empty">Required reviewer roles are attested for this local target.</p>"#
            .to_string()
    } else {
        render_list(&missing_attestations)
    };
    let attest_command = format!(
        "vela attest {} {} --scope domain_relevance --reviewer reviewer:you --role domain_reviewer --reason 'bounded role-specific attestation'",
        state.repo_path.display(),
        pack.pack_id
    );
    let attestation_html = format!(
        r#"<section class="wb-card">
  <h2>Scoped attestations</h2>
  <p class="wb-meta__note">Attestations are role-scoped local review records. They do not imply global consensus or institutional multi-signature approval.</p>
  <h3>Missing required attestations</h3>
  {missing_html}
  <h3>Recorded attestations</h3>
  {attestation_rows}
  <h3>CLI</h3>
  <pre class="wb-pre">{attest_command}</pre>
  <h3>Record local attestation</h3>
  <form method="post" action="/diff-packs/{pack_id}/attest" class="wb-actions">
    <input name="reviewer" required pattern="[^:]+:.+" placeholder="reviewer:you" aria-label="Reviewer id">
    <input name="role" required placeholder="domain_reviewer" aria-label="Reviewer role">
    <select name="scope" aria-label="Attestation scope">
      <option value="domain_relevance">domain_relevance</option>
      <option value="method_review">method_review</option>
      <option value="source_extraction">source_extraction</option>
      <option value="translation_clarity">translation_clarity</option>
    </select>
    <input name="reason" required minlength="12" placeholder="Bounded role-specific reason." aria-label="Attestation reason">
    <button type="submit">Record attestation</button>
  </form>
</section>"#,
        missing_html = missing_html,
        attestation_rows = attestation_rows,
        attest_command = escape_html(&attest_command),
        pack_id = escape_html(&pack.pack_id),
    );
    let review_sections = format!(
        r#"<section class="wb-card wb-review-grammar">
  <h2>Review grammar</h2>
  <p class="wb-meta__note">Scientific Diff Packs are reviewable proposed state changes. They are not accepted frontier state until local review emits canonical events.</p>
  <h3>Source artifacts</h3>
  {sources}
  <h3>Proposed operations</h3>
  {operations}
  <h3>Affected findings</h3>
  {affected}
  <h3>Evidence deltas</h3>
  {evidence}
  <h3>Confidence deltas</h3>
  {confidence}
  <h3>Contradiction effects</h3>
  {contradictions}
  <h3>Downstream impacts</h3>
  {impacts}
  <h3>Validation results</h3>
  {validation}
  <h3>Required reviewers</h3>
  {reviewers}
  <h3>Review session handoff</h3>
  {review_session}
  <h3>CLI equivalents</h3>
  {cli}
</section>"#,
        sources = render_list(&review_summary.source_artifacts),
        operations = operations_html,
        affected = render_list(&review_summary.affected_findings),
        evidence = render_list(&review_summary.evidence_deltas),
        confidence = render_list(&review_summary.confidence_deltas),
        contradictions = render_list(&review_summary.contradiction_effects),
        impacts = render_list(&review_summary.downstream_impacts),
        validation = render_list(&review_summary.validation_results),
        reviewers = render_list(&review_summary.required_reviewers),
        review_session = review_session_html,
        cli = cli_html,
    );

    let actions = format!(
        r#"<div class="wb-card">
  <h3>Verdict</h3>
  <p>The verdict is recorded as a pending reviewer intent in
  <code>.vela/pending_verdicts/&lt;vpv_id&gt;.json</code> until v0.205 promotes
  it to a canonical <code>diff_pack.reviewed</code> event. Per doctrine, no public
  web surface accepts verdicts; this page only responds on 127.0.0.1. Policy requires a typed reviewer id and bounded reason before any verdict is recorded. Solo-maintainer verdicts also require an explicit local-authority confirmation.</p>
  <div class="wb-actions">
    <form method="post" action="/diff-packs/{id}/accept">
      <input name="reviewer" required pattern="[^:]+:.+" placeholder="{reviewer}" aria-label="Reviewer id">
      <input name="reason" required minlength="12" placeholder="Bounded reviewer reason." aria-label="Decision reason">
      <label><input type="checkbox" name="solo_maintainer_scope" value="confirmed"> Solo-maintainer local authority only</label>
      <button type="submit">Accept pack</button>
    </form>
    <form method="post" action="/diff-packs/{id}/revise">
      <input name="reviewer" required pattern="[^:]+:.+" placeholder="{reviewer}" aria-label="Reviewer id">
      <input name="reason" required minlength="12" placeholder="Bounded reviewer reason." aria-label="Decision reason">
      <label><input type="checkbox" name="solo_maintainer_scope" value="confirmed"> Solo-maintainer local authority only</label>
      <button type="submit">Request revision</button>
    </form>
    <form method="post" action="/diff-packs/{id}/reject">
      <input name="reviewer" required pattern="[^:]+:.+" placeholder="{reviewer}" aria-label="Reviewer id">
      <input name="reason" required minlength="12" placeholder="Bounded reviewer reason." aria-label="Decision reason">
      <label><input type="checkbox" name="solo_maintainer_scope" value="confirmed"> Solo-maintainer local authority only</label>
      <button type="submit">Reject pack</button>
    </form>
  </div>
</div>"#,
        id = escape_html(&pack.pack_id),
        reviewer = escape_html(&default_reviewer()),
    );

    let mut session_objects = Vec::with_capacity(pack.proposals.len() + 1);
    session_objects.push(pack.pack_id.clone());
    session_objects.extend(pack.proposals.iter().cloned());
    let session_rail = reviewer_session_rail_html(
        &state.repo_path,
        &format!("diff_pack:{}", pack.pack_id),
        &session_objects,
    );
    let body = format!(
        r#"<dl class="wb-meta">
  <dt>summary</dt><dd>{summary}</dd>
  <dt>pack id</dt><dd><code>{pid}</code></dd>
  <dt>frontier</dt><dd><code>{fid}</code></dd>
  <dt>aggregate kind</dt><dd><code>{kind}</code></dd>
  <dt>created</dt><dd>{created}</dd>
  <dt>members</dt><dd>{n}</dd>
  {agent_run}
  {parent_pack}
  {signer}
</dl>
<style>
  .wb-meta {{ display: grid; grid-template-columns: max-content 1fr; gap: 0.2rem 0.8rem; margin: 0 0 1rem 0; font-size: 0.9rem; }}
  .wb-meta dt {{ color: var(--ink-2, #6b665d); }}
  .wb-meta dd {{ margin: 0; }}
  .wb-meta__note {{ font-size: 0.78rem; color: var(--ink-2, #6b665d); }}
  .wb-list {{ margin: 0 0 0.8rem 1rem; padding: 0; font-size: 0.88rem; line-height: 1.45; }}
  .wb-pre {{ background: var(--bg-3, #ebe6dd); padding: 0.6rem 0.85rem; font-size: 0.78rem; font-family: ui-monospace, Menlo, monospace; line-height: 1.5; overflow-x: auto; white-space: pre; border-radius: 2px; }}
  .wb-empty {{ color: var(--ink-3, #a09a8d); font-style: italic; text-align: center; padding: 1rem; }}
  .wb-review-grammar h3 {{ margin-top: 1rem; }}
</style>
{pending_html}
{canonical_events_html}
{session_rail}
{evidence_ci_html}
{attestation_html}
{review_sections}
<h2>Member proposals</h2>
{members_html}
{actions}"#,
        summary = escape_html(&pack.summary),
        pid = escape_html(&pack.pack_id),
        fid = escape_html(&pack.frontier_id),
        kind = escape_html(&pack.aggregate_kind),
        created = escape_html(&pack.created_at),
        n = pack.proposals.len(),
        canonical_events_html = canonical_events_html,
        session_rail = session_rail,
        evidence_ci_html = evidence_ci_html,
        attestation_html = attestation_html,
    );
    Html(shell(
        "diff-packs",
        &format!("Diff Pack {pack_id}"),
        "12 · Diff packs",
        &pack.summary,
        &body,
    ))
    .into_response()
}

#[derive(Debug, Deserialize)]
struct DiffPackVerdictForm {
    reviewer: Option<String>,
    reason: Option<String>,
    solo_maintainer_scope: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DiffPackAttestationForm {
    reviewer: Option<String>,
    role: Option<String>,
    scope: Option<String>,
    reason: Option<String>,
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn do_diff_pack_verdict(
    state: &AppState,
    pack_id: &str,
    verdict: DiffPackVerdict,
    form: DiffPackVerdictForm,
) -> Response {
    let reviewer = form
        .reviewer
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let reason = form
        .reason
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let (Some(reviewer), Some(reason)) = (reviewer, reason) else {
        return error_page(
            "diff-packs",
            "Policy requirement missing",
            "Reviewer identity and decision reason are required before recording a Diff Pack verdict.",
        );
    };
    if !reviewer.contains(':') {
        return error_page(
            "diff-packs",
            "Policy requirement missing",
            "Reviewer identity must be a typed actor id such as reviewer:you.",
        );
    }
    if reason.len() < 12 {
        return error_page(
            "diff-packs",
            "Policy requirement missing",
            "Decision reason must be at least 12 characters.",
        );
    }
    if reviewer == "reviewer:solo-maintainer"
        && form.solo_maintainer_scope.as_deref() != Some("confirmed")
    {
        return error_page(
            "diff-packs",
            "Policy requirement missing",
            "Solo-maintainer verdicts require confirming the local authority boundary.",
        );
    }
    let at = now_rfc3339();
    match diff_pack_review::record_at_path(
        &state.repo_path,
        pack_id,
        verdict,
        reviewer.as_str(),
        reason.as_str(),
        &at,
    ) {
        Ok(_) => Redirect::to(&format!("/diff-packs/{pack_id}")).into_response(),
        Err(e) => error_page("diff-packs", "Could not record verdict", &e),
    }
}

async fn post_diff_pack_accept(
    AxumPath(pack_id): AxumPath<String>,
    State(state): State<AppState>,
    Form(form): Form<DiffPackVerdictForm>,
) -> Response {
    do_diff_pack_verdict(&state, &pack_id, DiffPackVerdict::Accept, form)
}

async fn post_diff_pack_reject(
    AxumPath(pack_id): AxumPath<String>,
    State(state): State<AppState>,
    Form(form): Form<DiffPackVerdictForm>,
) -> Response {
    do_diff_pack_verdict(&state, &pack_id, DiffPackVerdict::Reject, form)
}

async fn post_diff_pack_revise(
    AxumPath(pack_id): AxumPath<String>,
    State(state): State<AppState>,
    Form(form): Form<DiffPackVerdictForm>,
) -> Response {
    do_diff_pack_verdict(&state, &pack_id, DiffPackVerdict::Revise, form)
}

async fn post_diff_pack_attest(
    AxumPath(pack_id): AxumPath<String>,
    State(state): State<AppState>,
    Form(form): Form<DiffPackAttestationForm>,
) -> Response {
    let reviewer = form
        .reviewer
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let role = form
        .role
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let scope = form
        .scope
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let reason = form
        .reason
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let (Some(reviewer), Some(role), Some(scope), Some(reason)) = (reviewer, role, scope, reason)
    else {
        return error_page(
            "diff-packs",
            "Policy requirement missing",
            "Reviewer id, role, scope, and reason are required before recording an attestation.",
        );
    };
    let scopes = match reviewer_identity::parse_scopes(&[scope]) {
        Ok(scopes) => scopes,
        Err(e) => return error_page("diff-packs", "Could not record attestation", &e),
    };
    match reviewer_identity::record(
        &state.repo_path,
        reviewer_identity::AttestationInput {
            target_id: pack_id.clone(),
            scopes,
            reviewer_id: reviewer,
            role,
            reason,
            orcid: None,
            ror: None,
            proof_id: None,
            signature: None,
        },
    ) {
        Ok(_) => Redirect::to(&format!("/diff-packs/{pack_id}")).into_response(),
        Err(e) => error_page("diff-packs", "Could not record attestation", &e),
    }
}

// ── v0.219 Conflicts surface ─────────────────────────────────────────

/// Walk pending verdicts and pack members to surface candidate
/// contradictions: two verdicts on distinct packs with overlapping
/// member sets and opposing outcomes. Pure read; mirrors the
/// `vela conflict detect` CLI helper.
fn detect_candidate_conflicts(repo_path: &Path) -> Vec<serde_json::Value> {
    use vela_protocol::diff_pack_review;
    let pending = diff_pack_review::list_at_path(repo_path);
    let mut pack_members: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    for pv in &pending {
        if pack_members.contains_key(&pv.pack_id) {
            continue;
        }
        let path = repo_path
            .join(".vela")
            .join("diff_packs")
            .join(format!("{}.json", pv.pack_id));
        if let Ok(body) = std::fs::read_to_string(&path)
            && let Ok(v) = serde_json::from_str::<serde_json::Value>(&body)
            && let Some(arr) = v.get("proposals").and_then(serde_json::Value::as_array)
        {
            let members: Vec<String> = arr
                .iter()
                .filter_map(|m| m.as_str().map(String::from))
                .collect();
            pack_members.insert(pv.pack_id.clone(), members);
        }
    }
    let mut candidates: Vec<serde_json::Value> = Vec::new();
    for i in 0..pending.len() {
        for j in (i + 1)..pending.len() {
            let a = &pending[i];
            let b = &pending[j];
            if a.pack_id == b.pack_id {
                continue;
            }
            if a.verdict.canonical() == b.verdict.canonical() {
                continue;
            }
            let members_a = pack_members.get(&a.pack_id);
            let members_b = pack_members.get(&b.pack_id);
            if let (Some(ma), Some(mb)) = (members_a, members_b) {
                let shared: Vec<&String> = ma.iter().filter(|m| mb.contains(m)).collect();
                if shared.is_empty() {
                    continue;
                }
                candidates.push(serde_json::json!({
                    "verdicts": [a.verdict_id, b.verdict_id],
                    "packs": [a.pack_id, b.pack_id],
                    "outcomes": [a.verdict.canonical(), b.verdict.canonical()],
                    "reviewers": [a.reviewer_actor, b.reviewer_actor],
                    "shared_member_ids": shared
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>(),
                }));
            }
        }
    }
    candidates
}

/// Walk .vela/verdict_conflicts/<vdc_id>.json. Returns parsed
/// VerdictConflict bodies sorted newest-first by resolved_at.
fn list_resolved_conflicts(repo_path: &Path) -> Vec<vela_protocol::verdict_conflict::VerdictConflict> {
    use vela_protocol::verdict_conflict::VerdictConflict;
    let dir = repo_path.join(".vela").join("verdict_conflicts");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut out: Vec<VerdictConflict> = Vec::new();
    for e in entries.flatten() {
        let p = e.path();
        if p.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        if let Ok(body) = std::fs::read_to_string(&p)
            && let Ok(c) = serde_json::from_str::<VerdictConflict>(&body)
        {
            out.push(c);
        }
    }
    out.sort_by(|a, b| b.resolved_at.cmp(&a.resolved_at));
    out
}

async fn page_conflicts_list(State(state): State<AppState>) -> Response {
    let _ = match repo::load_from_path(&state.repo_path) {
        Ok(p) => p,
        Err(e) => return error_page("conflicts", "Could not load frontier", &e),
    };
    let candidates = detect_candidate_conflicts(&state.repo_path);
    let resolved = list_resolved_conflicts(&state.repo_path);

    let candidates_html: String = if candidates.is_empty() {
        r#"<div class="wb-empty">No contradicting pending verdicts on this frontier.</div>"#
            .to_string()
    } else {
        candidates
            .iter()
            .enumerate()
            .map(|(idx, c)| {
                let verdicts = c
                    .get("verdicts")
                    .and_then(serde_json::Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str())
                            .collect::<Vec<_>>()
                            .join(" vs ")
                    })
                    .unwrap_or_default();
                let packs = c
                    .get("packs")
                    .and_then(serde_json::Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str())
                            .collect::<Vec<_>>()
                            .join(" vs ")
                    })
                    .unwrap_or_default();
                let outcomes = c
                    .get("outcomes")
                    .and_then(serde_json::Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str())
                            .collect::<Vec<_>>()
                            .join(" vs ")
                    })
                    .unwrap_or_default();
                let shared = c
                    .get("shared_member_ids")
                    .and_then(serde_json::Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str())
                            .map(|s| format!("<code>{}</code>", escape_html(s)))
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .unwrap_or_default();
                let reviewers = c
                    .get("reviewers")
                    .and_then(serde_json::Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str())
                            .collect::<Vec<_>>()
                            .join(" + ")
                    })
                    .unwrap_or_default();
                format!(
                    r#"<div class="wb-card">
  <h3><span class="wb-chip wb-chip--warn">candidate {idx:02}</span> {verdicts}</h3>
  <p><strong>Packs:</strong> <code>{packs}</code></p>
  <p><strong>Outcomes:</strong> {outcomes}</p>
  <p><strong>Reviewers:</strong> {reviewers}</p>
  <p><strong>Shared members:</strong> {shared}</p>
  <p class="wb-meta__note">To resolve, run:</p>
  <pre class="wb-pre">vela conflict resolve {path} \
  --verdicts "{verdicts_csv}" \
  --shared-members "{shared_csv}" \
  --mode owner_override \
  --resolver "reviewer:&lt;your-actor-id&gt;" \
  --winning "&lt;vpv_id&gt;" \
  --key /path/to/reviewer.key</pre>
</div>"#,
                    idx = idx + 1,
                    verdicts = escape_html(&verdicts),
                    packs = escape_html(&packs),
                    outcomes = escape_html(&outcomes),
                    reviewers = escape_html(&reviewers),
                    shared = shared,
                    path = escape_html(&state.repo_path.display().to_string()),
                    verdicts_csv = escape_html(
                        &c.get("verdicts")
                            .and_then(serde_json::Value::as_array)
                            .map(|a| a
                                .iter()
                                .filter_map(|v| v.as_str())
                                .collect::<Vec<_>>()
                                .join(","))
                            .unwrap_or_default()
                    ),
                    shared_csv = escape_html(
                        &c.get("shared_member_ids")
                            .and_then(serde_json::Value::as_array)
                            .map(|a| a
                                .iter()
                                .filter_map(|v| v.as_str())
                                .collect::<Vec<_>>()
                                .join(","))
                            .unwrap_or_default()
                    ),
                )
            })
            .collect()
    };

    let resolved_html: String = if resolved.is_empty() {
        r#"<div class="wb-empty">No resolved conflicts yet.</div>"#.to_string()
    } else {
        resolved
            .iter()
            .map(|c| {
                let chip_class = match c.resolution_mode {
                    vela_protocol::verdict_conflict::ResolutionMode::Majority => "wb-chip--ok",
                    vela_protocol::verdict_conflict::ResolutionMode::OwnerOverride => "wb-chip--ok",
                    vela_protocol::verdict_conflict::ResolutionMode::Escalation => "wb-chip--warn",
                };
                let winner_html = match &c.winning_verdict_id {
                    Some(w) => format!(
                        r#"<p><strong>Winner:</strong> <code>{}</code></p>"#,
                        escape_html(w)
                    ),
                    None => r#"<p class="wb-meta__note">No winner; resolution opened a new review cycle.</p>"#.to_string(),
                };
                let rationale_html = match &c.rationale {
                    Some(r) => format!(
                        r#"<p class="wb-meta__note"><em>{}</em></p>"#,
                        escape_html(r)
                    ),
                    None => String::new(),
                };
                format!(
                    r#"<div class="wb-card">
  <h3><span class="wb-chip {chip_class}">{mode}</span><code>{cid}</code></h3>
  <p><strong>Verdicts:</strong> {verdicts}</p>
  <p><strong>Shared members:</strong> {members}</p>
  <p><strong>Resolved by:</strong> <code>{actor}</code> at <code>{at}</code></p>
  {winner_html}
  {rationale_html}
</div>"#,
                    chip_class = chip_class,
                    mode = c.resolution_mode.canonical(),
                    cid = escape_html(&c.conflict_id),
                    verdicts = c
                        .verdicts
                        .iter()
                        .map(|v| format!("<code>{}</code>", escape_html(v)))
                        .collect::<Vec<_>>()
                        .join(", "),
                    members = c
                        .shared_member_ids
                        .iter()
                        .map(|m| format!("<code>{}</code>", escape_html(m)))
                        .collect::<Vec<_>>()
                        .join(", "),
                    actor = escape_html(&c.resolution_actor),
                    at = escape_html(&c.resolved_at),
                    winner_html = winner_html,
                    rationale_html = rationale_html,
                )
            })
            .collect()
    };

    let body = format!(
        r#"<p>v0.218 verdict-conflict surface. Candidates are detected
when two pending verdicts on distinct packs share ≥1 member with
opposing outcomes. Resolution flows through the CLI
(<code>vela conflict resolve</code>) per the existing pending-verdict
	doctrine. This page renders the read side.</p>

<style>
  .wb-pre {{ background: var(--bg-3, #ebe6dd); padding: 0.6rem 0.85rem; font-size: 0.78rem; font-family: ui-monospace, Menlo, monospace; line-height: 1.5; overflow-x: auto; white-space: pre; border-radius: 2px; }}
  .wb-meta__note {{ font-size: 0.82rem; color: var(--ink-2, #6b665d); }}
  .wb-empty {{ color: var(--ink-3, #a09a8d); font-style: italic; text-align: center; padding: 1rem; }}
</style>

<h2 class="wb-title" style="font-size:1.1rem; margin-top:1.5rem;">Candidate contradictions ({n_candidates})</h2>
{candidates_html}

<h2 class="wb-title" style="font-size:1.1rem; margin-top:1.5rem;">Resolved conflicts ({n_resolved})</h2>
{resolved_html}"#,
        n_candidates = candidates.len(),
        n_resolved = resolved.len(),
        candidates_html = candidates_html,
        resolved_html = resolved_html,
    );

    Html(shell(
        "conflicts",
        "Conflicts",
        "13 · Conflicts",
        "Verdict conflicts",
        &body,
    ))
    .into_response()
}

// ── v0.229: unified verdict timeline ─────────────────────────────────

#[derive(Debug, Clone)]
struct VerdictTimelineRow {
    at: String,
    kind: &'static str,
    pack_id: String,
    actor: String,
    verdict_or_mode: String,
    extra: String,
}

async fn page_verdicts_timeline(State(state): State<AppState>) -> Response {
    let project = match repo::load_from_path(&state.repo_path) {
        Ok(p) => p,
        Err(e) => return error_page("verdicts", "Could not load frontier", &e),
    };

    let mut rows: Vec<VerdictTimelineRow> = Vec::new();

    // (1) Pending verdicts on disk: vpv_* awaiting promotion.
    for pv in diff_pack_review::list_at_path(&state.repo_path) {
        rows.push(VerdictTimelineRow {
            at: pv.at.clone(),
            kind: "pending",
            pack_id: pv.pack_id.clone(),
            actor: pv.reviewer_actor.clone(),
            verdict_or_mode: match pv.verdict {
                DiffPackVerdict::Accept => "accept".to_string(),
                DiffPackVerdict::Reject => "reject".to_string(),
                DiffPackVerdict::Revise => "revise".to_string(),
            },
            extra: pv.reason.chars().take(80).collect(),
        });
    }

    // (2) Resolved verdicts on packs: from project.released_diff_packs.
    for rec in &project.released_diff_packs {
        if let Some(v) = rec.verdict.as_ref() {
            rows.push(VerdictTimelineRow {
                at: rec
                    .verdict_event_id
                    .as_ref()
                    .map(|_| rec.released_at.clone())
                    .unwrap_or_else(|| rec.released_at.clone()),
                kind: "settled",
                pack_id: rec.pack_id.clone(),
                actor: rec.reviewer_actor.clone().unwrap_or_default(),
                verdict_or_mode: format!("{v:?}").to_lowercase(),
                extra: format!(
                    "{} applied, {} sdk-only",
                    rec.applied_members.len(),
                    rec.sdk_only_members.len()
                ),
            });
        }
    }

    // (3) Resolved verdict conflicts: vdc_* resolutions. Walks both
    // the canonical substrate field (populated when a
    // verdict_conflict.resolved event landed on the log) AND the
    // on-disk `.vela/verdict_conflicts/` directory, deduplicating
    // by conflict_id. The disk fallback covers pre-v0.218
    // scaffolders that wrote vdc_* directly without emitting a
    // canonical event.
    let mut seen_conflicts: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut all_conflicts: Vec<vela_protocol::verdict_conflict::VerdictConflict> =
        project.verdict_conflicts.clone();
    for c in list_resolved_conflicts(&state.repo_path) {
        if !all_conflicts.iter().any(|x| x.conflict_id == c.conflict_id) {
            all_conflicts.push(c);
        }
    }
    for c in &all_conflicts {
        if !seen_conflicts.insert(c.conflict_id.clone()) {
            continue;
        }
        rows.push(VerdictTimelineRow {
            at: c.resolved_at.clone(),
            kind: "contested",
            pack_id: c
                .shared_member_ids
                .first()
                .cloned()
                .unwrap_or_else(|| "(shared members)".to_string()),
            actor: c.resolution_actor.clone(),
            verdict_or_mode: c.resolution_mode.canonical().to_string(),
            extra: format!(
                "winner {} of {} verdicts",
                c.winning_verdict_id.clone().unwrap_or_default(),
                c.verdicts.len()
            ),
        });
    }

    // Sort newest first.
    rows.sort_by(|a, b| b.at.cmp(&a.at));

    let pending_n = rows.iter().filter(|r| r.kind == "pending").count();
    let settled_n = rows.iter().filter(|r| r.kind == "settled").count();
    let contested_n = rows.iter().filter(|r| r.kind == "contested").count();

    let rows_html: String = if rows.is_empty() {
        r#"<tr><td colspan="6" class="wb-empty">No verdicts in flight, settled, or contested on this frontier.</td></tr>"#.to_string()
    } else {
        rows.iter()
            .map(|r| {
                let chip_class = match r.kind {
                    "pending" => "wb-chip wb-chip--warn",
                    "settled" => "wb-chip wb-chip--ok",
                    "contested" => "wb-chip wb-chip--lost",
                    _ => "wb-chip",
                };
                format!(
                    r#"<tr>
  <td><code>{at}</code></td>
  <td><span class="{chip_class}">{kind}</span></td>
  <td><code>{pack_id}</code></td>
  <td><code>{actor}</code></td>
  <td><code>{vm}</code></td>
  <td>{extra}</td>
</tr>"#,
                    at = escape_html(&r.at),
                    chip_class = chip_class,
                    kind = r.kind,
                    pack_id = escape_html(&r.pack_id),
                    actor = escape_html(&r.actor),
                    vm = escape_html(&r.verdict_or_mode),
                    extra = escape_html(&r.extra),
                )
            })
            .collect()
    };

    let body = format!(
        r#"<p class="wb-lede">A unified timeline of every verdict-affecting record on this frontier. Pending verdicts ({pending}) await promotion through <code>vela diff-pack promote-verdicts</code>. Settled verdicts ({settled}) are recorded on the canonical event log. Contested verdicts ({contested}) carry a signed <code>vdc_*</code> resolution. Substrate-honest: no verdict is silently overwritten.</p>
<table class="wb-table">
  <thead>
    <tr><th>at</th><th>state</th><th>pack / member</th><th>actor</th><th>verdict / mode</th><th>detail</th></tr>
  </thead>
  <tbody>
    {rows_html}
  </tbody>
</table>"#,
        pending = pending_n,
        settled = settled_n,
        contested = contested_n,
        rows_html = rows_html,
    );

    Html(shell(
        "verdicts",
        "Verdicts",
        "14 · Verdicts",
        "Verdict timeline",
        &body,
    ))
    .into_response()
}
