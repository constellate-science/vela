//! Static renderer for read-only frontier share packages.

use vela_protocol::bundle::ReviewState;
use vela_protocol::project::Project;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StaticShareReport {
    pub ok: bool,
    pub package: String,
    pub out: String,
    pub frontier_id: String,
    pub generated_at: String,
    pub files_written: usize,
}

#[derive(Debug)]
struct StaticShareContext {
    package: PathBuf,
    frontier_id: String,
    package_created_at: String,
    rendered_at: String,
    project: Project,
    manifest: Value,
    health: Value,
    evidence_ci: Value,
    source_inbox: Value,
    source_snapshots: Value,
    source_locator_audit: Value,
    tasks: Value,
    review_sessions: Value,
    canonical_verdict_events: Value,
    reviewer_packet: Value,
    proof_state: Value,
}

pub fn render(package: &Path, out: &Path) -> Result<StaticShareReport, String> {
    let context = load_context(package)?;
    if out.exists() {
        fs::remove_dir_all(out).map_err(|e| format!("remove existing static share site: {e}"))?;
    }
    fs::create_dir_all(out.join("assets"))
        .map_err(|e| format!("create static share assets dir: {e}"))?;

    let mut files_written = 0usize;
    write_file(&out.join("assets").join("style.css"), &css())?;
    files_written += 1;
    write_file(&out.join("index.html"), &render_index(&context))?;
    files_written += 1;
    write_file(
        &out.join("reviewer-packet.html"),
        &render_reviewer_packet(&context),
    )?;
    files_written += 1;
    write_file(&out.join("findings.html"), &render_findings(&context))?;
    files_written += 1;
    write_file(&out.join("sources.html"), &render_sources(&context))?;
    files_written += 1;
    write_file(&out.join("tasks.html"), &render_tasks(&context))?;
    files_written += 1;
    write_file(
        &out.join("diff-packs.html"),
        &render_file_list(&context, "Diff packs", "diff-packs"),
    )?;
    files_written += 1;
    write_file(
        &out.join("review-packets.html"),
        &render_file_list(&context, "Review packets", "review-packets"),
    )?;
    files_written += 1;
    write_file(
        &out.join("review-sessions.html"),
        &render_review_sessions(&context),
    )?;
    files_written += 1;
    write_file(&out.join("evidence-ci.html"), &render_evidence_ci(&context))?;
    files_written += 1;
    write_file(&out.join("proof.html"), &render_proof(&context))?;
    files_written += 1;
    write_file(&out.join("manifest.html"), &render_manifest(&context))?;
    files_written += 1;

    Ok(StaticShareReport {
        ok: true,
        package: package.display().to_string(),
        out: out.display().to_string(),
        frontier_id: context.frontier_id,
        generated_at: context.rendered_at,
        files_written,
    })
}

fn load_context(package: &Path) -> Result<StaticShareContext, String> {
    let manifest: Value = read_json(&package.join("manifest.json"))?;
    let frontier_id = manifest
        .get("frontier_id")
        .and_then(|v| v.as_str())
        .unwrap_or("(unset)")
        .to_string();
    let package_created_at = manifest
        .get("created_at")
        .and_then(|v| v.as_str())
        .unwrap_or("(unknown)")
        .to_string();
    Ok(StaticShareContext {
        package: package.to_path_buf(),
        frontier_id,
        package_created_at,
        rendered_at: chrono::Utc::now().to_rfc3339(),
        project: read_json(&package.join("frontier.json"))?,
        manifest,
        health: read_json(&package.join("frontier-health.json"))?,
        evidence_ci: read_json(&package.join("evidence-ci.json"))?,
        source_inbox: read_json(&package.join("source-inbox.json"))?,
        source_snapshots: read_json(&package.join("source-snapshots").join("index.json"))?,
        source_locator_audit: read_json(&package.join("source-locator-audit.json"))?,
        tasks: read_json(&package.join("tasks.json"))?,
        review_sessions: read_json(&package.join("review-sessions.json"))?,
        canonical_verdict_events: read_json(&package.join("canonical-verdict-events.json"))?,
        reviewer_packet: read_json(&package.join("reviewer-packet.json"))?,
        proof_state: read_json(&package.join("proof-state.json"))?,
    })
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("parse {}: {e}", path.display()))
}

fn write_file(path: &Path, body: &str) -> Result<(), String> {
    fs::write(path, body).map_err(|e| format!("write {}: {e}", path.display()))
}

fn page(context: &StaticShareContext, title: &str, active: &str, body: &str) -> String {
    format!(
        "<!doctype html>
<html lang=\"en\">
<head>
<meta charset=\"utf-8\">
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
<title>{title}</title>
<link rel=\"icon\" href=\"data:,\">
<link rel=\"stylesheet\" href=\"assets/style.css\">
</head>
<body>
<header class=\"shell-head\">
  <div>
    <p class=\"eyebrow\">Vela share package</p>
    <h1>{title}</h1>
    <p class=\"meta\"><code>{frontier_id}</code> · rendered {rendered_at}</p>
  </div>
  <nav aria-label=\"Static share navigation\">
    {nav}
  </nav>
</header>
<main>
  <section class=\"notice\">
    <strong>Read-only package.</strong> This page is for inspection only. It is not medical advice or field consensus.
    <a href=\"manifest.html\">Manifest</a>
  </section>
  {body}
</main>
<footer>
  <span>package generated {package_created_at}</span>
  <span><code>{frontier_id}</code></span>
</footer>
</body>
</html>",
        title = esc(title),
        frontier_id = esc(&context.frontier_id),
        rendered_at = esc(&context.rendered_at),
        package_created_at = esc(&context.package_created_at),
        nav = nav(active),
        body = body,
    )
}

fn nav(active: &str) -> String {
    let links = [
        ("index", "index.html", "Overview"),
        ("reviewer-packet", "reviewer-packet.html", "Reviewer packet"),
        ("findings", "findings.html", "Findings"),
        ("sources", "sources.html", "Sources"),
        ("tasks", "tasks.html", "Tasks"),
        ("diff-packs", "diff-packs.html", "Diff packs"),
        ("review-packets", "review-packets.html", "Review packets"),
        ("review-sessions", "review-sessions.html", "Review sessions"),
        ("evidence-ci", "evidence-ci.html", "Evidence CI"),
        ("proof", "proof.html", "Proof"),
        ("manifest", "manifest.html", "Manifest"),
    ];
    links
        .iter()
        .map(|(key, href, label)| {
            let class = if *key == active {
                " class=\"active\""
            } else {
                ""
            };
            format!("<a{class} href=\"{href}\">{label}</a>")
        })
        .collect::<Vec<_>>()
        .join("")
}

fn render_index(context: &StaticShareContext) -> String {
    let metrics = context.health.get("metrics").unwrap_or(&Value::Null);
    let evidence_summary = context.evidence_ci.get("summary").unwrap_or(&Value::Null);
    let body = format!(
        "<section class=\"panel\">
  <div class=\"section-head\"><h2>Overview</h2></div>
  <p>{name}</p>
  <div class=\"grid\">
    {card_findings}
    {card_sources}
    {card_tasks}
    {card_events}
  </div>
</section>
<section class=\"panel\">
  <div class=\"section-head\"><h2>Reviewer packet</h2></div>
  <p>{review_task}</p>
  <table>
    <tr><th>Diff packs</th><td>{diff_packs}</td></tr>
    <tr><th>Review packets</th><td>{review_packets}</td></tr>
    <tr><th>Source-inbox records</th><td>{source_records}</td></tr>
    <tr><th>Reviewer notes</th><td><code>{notes}</code></td></tr>
  </table>
</section>
<section class=\"panel\">
  <div class=\"section-head\"><h2>Health</h2></div>
  <table>
    <tr><th>Proof status</th><td>{proof_status}</td></tr>
    <tr><th>Active tasks</th><td>{active_tasks}</td></tr>
    <tr><th>Awaiting review</th><td>{awaiting_review}</td></tr>
    <tr><th>Evidence CI failures</th><td>{evidence_failures}</td></tr>
    <tr><th>Evidence CI warnings</th><td>{evidence_warnings}</td></tr>
  </table>
</section>",
        name = esc(&context.project.project.name),
        card_findings = stat_card("Findings", context.project.findings.len()),
        card_sources = stat_card(
            "Source inbox",
            context
                .source_inbox
                .get("total")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as usize,
        ),
        card_tasks = stat_card(
            "Tasks",
            context
                .tasks
                .get("total")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as usize,
        ),
        card_events = stat_card("Events", context.project.events.len()),
        review_task = field(&context.reviewer_packet, "review_task"),
        diff_packs = context
            .reviewer_packet
            .get("diff_pack_scope")
            .map(|v| num(v, "count"))
            .unwrap_or(0),
        review_packets = context
            .reviewer_packet
            .get("review_packets")
            .map(|v| num(v, "count"))
            .unwrap_or(0),
        source_records = context
            .reviewer_packet
            .get("source_scope")
            .map(|v| num(v, "source_inbox_records"))
            .unwrap_or(0),
        notes = field(&context.reviewer_packet, "reviewer_notes_template"),
        proof_status = esc(metrics
            .get("proof_status")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")),
        active_tasks = num(metrics, "active_tasks"),
        awaiting_review = num(metrics, "awaiting_review_tasks"),
        evidence_failures = num(evidence_summary, "failed"),
        evidence_warnings = num(evidence_summary, "warnings"),
    );
    page(context, "Overview", "index", &body)
}

fn render_reviewer_packet(context: &StaticShareContext) -> String {
    let first_pass = string_list(&context.reviewer_packet, "first_pass_commands");
    let local_commands = string_list(&context.reviewer_packet, "local_frontier_commands");
    let diff_pack_ids = context
        .reviewer_packet
        .get("diff_pack_scope")
        .and_then(|v| v.get("ids"))
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str())
                .map(|item| format!("<code>{}</code>", esc(item)))
                .collect::<Vec<_>>()
                .join(", ")
        })
        .filter(|items| !items.is_empty())
        .unwrap_or_else(|| "none".to_string());
    let body = format!(
        "<section class=\"panel\">
  <div class=\"section-head\"><h2>Reviewer packet</h2></div>
  <p>{review_task}</p>
  <table>
    <tr><th>Read-only</th><td>{read_only}</td></tr>
    <tr><th>Sources</th><td>{source_records} source-inbox record(s), {registered_sources} registered frontier source(s)</td></tr>
    <tr><th>Diff Pack ids</th><td>{diff_pack_ids}</td></tr>
    <tr><th>Review packet files</th><td>{review_packets}</td></tr>
    <tr><th>Proof state</th><td>{proof_state}</td></tr>
    <tr><th>Friction log</th><td>{friction}</td></tr>
  </table>
</section>
<section class=\"panel\">
  <div class=\"section-head\"><h2>First pass commands</h2></div>
  <pre>{first_pass}</pre>
</section>
<section class=\"panel\">
  <div class=\"section-head\"><h2>Local frontier commands</h2></div>
  <pre>{local_commands}</pre>
</section>",
        review_task = field(&context.reviewer_packet, "review_task"),
        read_only = context
            .reviewer_packet
            .get("read_only")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        source_records = context
            .reviewer_packet
            .get("source_scope")
            .map(|v| num(v, "source_inbox_records"))
            .unwrap_or(0),
        registered_sources = context
            .reviewer_packet
            .get("source_scope")
            .map(|v| num(v, "registered_sources"))
            .unwrap_or(0),
        diff_pack_ids = diff_pack_ids,
        review_packets = context
            .reviewer_packet
            .get("review_packets")
            .map(|v| num(v, "count"))
            .unwrap_or(0),
        proof_state = context
            .reviewer_packet
            .get("proof")
            .and_then(|v| v.get("state"))
            .map(|v| field(v, "status"))
            .unwrap_or_default(),
        friction = context
            .reviewer_packet
            .get("friction_log")
            .and_then(|v| v.get("included"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        first_pass = esc(&first_pass),
        local_commands = esc(&local_commands),
    );
    page(context, "Reviewer packet", "reviewer-packet", &body)
}

fn render_findings(context: &StaticShareContext) -> String {
    let mut rows = String::new();
    for finding in &context.project.findings {
        rows.push_str(&format!(
            "<tr><td><code>{id}</code></td><td>{status}</td><td>{confidence:.2}</td><td>{assertion}</td></tr>",
            id = esc(&finding.id),
            status = esc(review_status(finding.flags.review_state.as_ref())),
            confidence = finding.confidence.score,
            assertion = esc(&truncate(&finding.assertion.text, 220)),
        ));
    }
    let body = format!(
        "<section class=\"panel\">
  <div class=\"section-head\"><h2>Findings</h2></div>
  <table>
    <thead><tr><th>Id</th><th>Review state</th><th>Confidence</th><th>Assertion</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</section>",
        rows = rows
    );
    page(context, "Findings", "findings", &body)
}

fn render_sources(context: &StaticShareContext) -> String {
    let records = context
        .source_inbox
        .get("records")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let mut rows = String::new();
    for record in records {
        rows.push_str(&format!(
            "<tr><td><code>{id}</code></td><td>{state}</td><td>{kind}</td><td>{title}</td><td><code>{locator}</code></td></tr>",
            id = field(&record, "id"),
            state = field(&record, "state"),
            kind = field(&record, "source_type"),
            title = field(&record, "title"),
            locator = field(&record, "locator"),
        ));
    }
    if rows.is_empty() {
        rows.push_str("<tr><td colspan=\"5\">No source-inbox records in this package.</td></tr>");
    }
    let body = format!(
        "<section class=\"panel\">
  <div class=\"section-head\"><h2>Sources</h2></div>
  <p>{registered} registered frontier source(s). Source-inbox records are review work before evidence atoms.</p>
  <table>
    <tr><th>Snapshot files copied</th><td>{copied}</td></tr>
    <tr><th>Unavailable source artifacts</th><td>{unavailable}</td></tr>
    <tr><th>Locator review debt</th><td>{locator_debt}</td></tr>
    <tr><th>Resolvable sources</th><td>{resolvable}</td></tr>
    <tr><th>Cited-unavailable sources</th><td>{cited_unavailable}</td></tr>
    <tr><th>Broken click-throughs</th><td>{broken}</td></tr>
    <tr><th>Source state</th><td>{source_state}</td></tr>
  </table>
  <table>
    <thead><tr><th>Id</th><th>State</th><th>Type</th><th>Title</th><th>Locator</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</section>",
        registered = context.project.sources.len(),
        copied = num(&context.source_snapshots, "copied"),
        unavailable = num(&context.source_snapshots, "unavailable"),
        locator_debt = num(&context.source_locator_audit, "review_debt"),
        resolvable = num(&context.source_locator_audit, "resolvable_sources"),
        cited_unavailable = num(&context.source_locator_audit, "cited_unavailable_sources_count"),
        broken = num(&context.source_locator_audit, "broken_click_throughs"),
        source_state = if num(&context.source_locator_audit, "broken_click_throughs") > 0 {
            "broken click-throughs present: dead reviewer clicks"
        } else if num(&context.source_locator_audit, "cited_unavailable_sources_count") > 0 {
            "no broken click-throughs; cited-unavailable sources are honest review debt"
        } else {
            "current"
        },
        rows = rows
    );
    page(context, "Sources", "sources", &body)
}

fn render_tasks(context: &StaticShareContext) -> String {
    let tasks = context
        .tasks
        .get("tasks")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let mut rows = String::new();
    for task in tasks {
        rows.push_str(&format!(
            "<tr><td><code>{id}</code></td><td>{status}</td><td>{risk}</td><td>{objective}</td></tr>",
            id = field(&task, "id"),
            status = field(&task, "status"),
            risk = field(&task, "risk_class"),
            objective = field(&task, "objective"),
        ));
    }
    if rows.is_empty() {
        rows.push_str("<tr><td colspan=\"4\">No frontier tasks in this package.</td></tr>");
    }
    let body = format!(
        "<section class=\"panel\">
  <div class=\"section-head\"><h2>Tasks</h2></div>
  <table>
    <thead><tr><th>Id</th><th>Status</th><th>Risk</th><th>Objective</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</section>",
        rows = rows
    );
    page(context, "Tasks", "tasks", &body)
}

fn render_file_list(context: &StaticShareContext, title: &str, dir: &str) -> String {
    let mut rows = String::new();
    for file in list_files(&context.package.join(dir)) {
        rows.push_str(&format!(
            "<tr><td><code>{}</code></td></tr>",
            esc(&file.display().to_string())
        ));
    }
    if rows.is_empty() {
        rows.push_str("<tr><td>No files in this package section.</td></tr>");
    }
    let body = format!(
        "<section class=\"panel\">
  <div class=\"section-head\"><h2>{title}</h2></div>
  <table><thead><tr><th>Packaged file</th></tr></thead><tbody>{rows}</tbody></table>
</section>",
        title = esc(title),
        rows = rows
    );
    let active = if dir == "diff-packs" {
        "diff-packs"
    } else {
        "review-packets"
    };
    page(context, title, active, &body)
}

fn render_review_sessions(context: &StaticShareContext) -> String {
    let sessions = context
        .review_sessions
        .get("sessions")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let mut rows = String::new();
    for session in sessions {
        rows.push_str(&format!(
            "<tr><td><code>{id}</code></td><td>{status}</td><td>{reviewer}</td><td>{scope}</td><td>{objects}</td></tr>",
            id = field(&session, "id"),
            status = field(&session, "status"),
            reviewer = field(&session, "reviewer_id"),
            scope = field(&session, "scope"),
            objects = session
                .get("objects_reviewed")
                .and_then(|v| v.as_array())
                .map(|items| items.len())
                .unwrap_or(0),
        ));
    }
    if rows.is_empty() {
        rows.push_str("<tr><td colspan=\"5\">No review sessions in this package.</td></tr>");
    }
    let body = format!(
        "<section class=\"panel\">
  <div class=\"section-head\"><h2>Review sessions</h2></div>
  <p>Local reviewer sessions are included as read-only records. They do not accept frontier state.</p>
  <table>
    <thead><tr><th>Id</th><th>Status</th><th>Reviewer</th><th>Scope</th><th>Objects</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</section>",
        rows = rows
    );
    page(context, "Review sessions", "review-sessions", &body)
}

fn render_evidence_ci(context: &StaticShareContext) -> String {
    let summary = context.evidence_ci.get("summary").unwrap_or(&Value::Null);
    let group_rows = summary
        .get("groups")
        .and_then(|v| v.as_array())
        .map(|groups| {
            groups
                .iter()
                .map(|group| {
                    format!(
                        "<tr><td><code>{group}</code></td><td>{total}</td><td>{release_blocking}</td><td>{review_warning}</td><td>{info}</td><td>{blocking}</td></tr>",
                        group = field(group, "group"),
                        total = num(group, "total"),
                        release_blocking = num(group, "release_blocking"),
                        review_warning = num(group, "review_warning"),
                        info = num(group, "info"),
                        blocking = num(group, "release_blocking_failed"),
                    )
                })
                .collect::<String>()
        })
        .filter(|rows| !rows.is_empty())
        .unwrap_or_else(|| {
            "<tr><td colspan=\"6\">No Evidence CI group summaries in this package.</td></tr>"
                .to_string()
        });
    let checks = context
        .evidence_ci
        .get("checks")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let mut rows = String::new();
    for check in checks.iter().take(80) {
        rows.push_str(&format!(
            "<tr><td>{status}</td><td><code>{id}</code></td><td><code>{target}</code></td><td>{message}</td></tr>",
            status = field(check, "status"),
            id = field(check, "id"),
            target = field(check, "target_id"),
            message = field(check, "message"),
        ));
    }
    if rows.is_empty() {
        rows.push_str("<tr><td colspan=\"4\">No Evidence CI checks in this package.</td></tr>");
    }
    let body = format!(
        "<section class=\"panel\">
  <div class=\"section-head\"><h2>Evidence CI</h2></div>
  <p>Evidence CI checks review readiness. It does not accept scientific state.</p>
  <div class=\"grid\">
    {total}
    {failed}
    {warnings}
    {blocking}
  </div>
  <h3>Group summaries</h3>
  <table>
    <thead><tr><th>Group</th><th>Checks</th><th>Release blocking</th><th>Review warnings</th><th>Info</th><th>Blocking failures</th></tr></thead>
    <tbody>{group_rows}</tbody>
  </table>
  <table>
    <thead><tr><th>Status</th><th>Check</th><th>Target</th><th>Message</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</section>",
        total = stat_card("Checks", num(summary, "total") as usize),
        failed = stat_card("Failed", num(summary, "failed") as usize),
        warnings = stat_card("Warnings", num(summary, "warnings") as usize),
        blocking = stat_card(
            "Release blocking",
            num(summary, "release_blocking_failed") as usize,
        ),
        group_rows = group_rows,
        rows = rows
    );
    page(context, "Evidence CI", "evidence-ci", &body)
}

fn render_proof(context: &StaticShareContext) -> String {
    let mut rows = String::new();
    for file in list_files(&context.package.join("proof-packet")) {
        rows.push_str(&format!(
            "<tr><td><code>{}</code></td></tr>",
            esc(&file.display().to_string())
        ));
    }
    let body = format!(
        "<section class=\"panel\">
  <div class=\"section-head\"><h2>Proof</h2></div>
  <p>Validate this packet from the package root with <code>vela packet validate proof-packet</code>.</p>
  <table>
    <tr><th>Package proof state</th><td>{proof_state}</td></tr>
    <tr><th>Frontier proof state</th><td>{frontier_proof_state}</td></tr>
    <tr><th>Stale</th><td>{stale}</td></tr>
    <tr><th>Review debt</th><td>{review_debt}</td></tr>
    <tr><th>Canonical verdict events</th><td>{canonical_events}</td></tr>
    <tr><th>Proof packet present</th><td>{proof_present}</td></tr>
  </table>
  <table><thead><tr><th>Proof-packet file</th></tr></thead><tbody>{rows}</tbody></table>
</section>",
        proof_state = field(&context.proof_state, "package_status"),
        frontier_proof_state = field(&context.proof_state, "status"),
        stale = context
            .proof_state
            .get("stale")
            .and_then(|v| v.as_bool())
            .unwrap_or(true),
        review_debt = context
            .proof_state
            .get("review_debt")
            .map(|v| {
                format!(
                    "awaiting review {awaiting}, missing attestations {attestations}, source issues {sources}",
                    awaiting = num(v, "awaiting_review_tasks"),
                    attestations = num(v, "missing_attestations"),
                    sources = num(v, "source_inbox_issues")
                )
            })
            .unwrap_or_else(|| "unknown".to_string()),
        canonical_events = num(&context.canonical_verdict_events, "count"),
        proof_present = context
            .proof_state
            .get("proof_packet_present")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        rows = rows
    );
    page(context, "Proof", "proof", &body)
}

fn render_manifest(context: &StaticShareContext) -> String {
    let mut rows = String::new();
    for file in context
        .manifest
        .get("files")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
    {
        rows.push_str(&format!(
            "<tr><td><code>{path}</code></td><td>{bytes}</td><td><code>{sha}</code></td></tr>",
            path = field(file, "path"),
            bytes = file.get("bytes").and_then(|v| v.as_u64()).unwrap_or(0),
            sha = field(file, "sha256"),
        ));
    }
    let body = format!(
        "<section class=\"panel\">
  <div class=\"section-head\"><h2>Manifest</h2></div>
  <table>
    <thead><tr><th>Path</th><th>Bytes</th><th>SHA-256</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</section>",
        rows = rows
    );
    page(context, "Manifest", "manifest", &body)
}

fn list_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    list_files_inner(dir, dir, &mut files);
    files.sort();
    files
}

fn list_files_inner(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            list_files_inner(root, &path, out);
        } else if path.is_file() {
            out.push(path.strip_prefix(root).unwrap_or(&path).to_path_buf());
        }
    }
}

fn stat_card(label: &str, value: usize) -> String {
    format!(
        "<div class=\"stat\"><span>{}</span><strong>{}</strong></div>",
        esc(label),
        value
    )
}

fn field(value: &Value, key: &str) -> String {
    esc(value.get(key).and_then(|v| v.as_str()).unwrap_or(""))
}

fn num(value: &Value, key: &str) -> u64 {
    value.get(key).and_then(|v| v.as_u64()).unwrap_or(0)
}

fn string_list(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str())
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default()
}

fn review_status(status: Option<&ReviewState>) -> &'static str {
    match status {
        Some(ReviewState::Accepted) => "accepted",
        Some(ReviewState::Contested) => "contested",
        Some(ReviewState::NeedsRevision) => "needs_revision",
        Some(ReviewState::Rejected) => "rejected",
        None => "unreviewed",
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        return s.to_string();
    }
    let mut out: String = s.chars().take(n).collect();
    out.push_str("...");
    out
}

fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

fn css() -> String {
    r#":root {
  --surface-dark: #08111C;
  --background: #F7F4EC;
  --panel: #FFFDF7;
  --ink: #18212B;
  --muted: #66727F;
  --line: rgba(8, 17, 28, 0.14);
  --gold: #C8A45D;
  --mono: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace;
  --ui: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  --serif: "Lyon Display", Canela, "Source Serif 4", Georgia, serif;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--background);
  color: var(--ink);
  font: 14px/1.45 var(--ui);
}
a { color: inherit; text-decoration-color: var(--gold); text-underline-offset: 3px; }
.shell-head {
  background: var(--surface-dark);
  color: #F7F4EC;
  display: grid;
  grid-template-columns: minmax(0, 1fr);
  gap: 20px;
  padding: 28px;
  border-bottom: 1px solid rgba(200, 164, 93, 0.35);
}
.shell-head h1 {
  font: 400 30px/1.08 var(--serif);
  margin: 4px 0 6px;
  letter-spacing: 0;
}
.eyebrow, .meta, footer {
  margin: 0;
  color: rgba(247, 244, 236, 0.68);
}
nav {
  display: flex;
  gap: 6px;
  flex-wrap: wrap;
  align-content: start;
}
nav a {
  border: 1px solid rgba(247, 244, 236, 0.18);
  border-radius: 999px;
  padding: 6px 10px;
  text-decoration: none;
  color: rgba(247, 244, 236, 0.82);
}
nav a.active {
  border-color: var(--gold);
  color: #F7F4EC;
}
main {
  max-width: 1180px;
  margin: 0 auto;
  padding: 24px;
}
.notice {
  border: 1px solid rgba(200, 164, 93, 0.5);
  background: rgba(200, 164, 93, 0.11);
  border-radius: 12px;
  padding: 12px 14px;
  margin-bottom: 18px;
}
.panel {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 12px;
  padding: 18px;
  margin-bottom: 18px;
}
.section-head {
  border-top: 1px solid transparent;
  border-image: linear-gradient(90deg, rgba(200, 164, 93, 0.75), rgba(8, 17, 28, 0.05)) 1;
  padding-top: 10px;
  margin-bottom: 12px;
}
h2 {
  font: 400 22px/1.15 var(--serif);
  margin: 0;
  letter-spacing: 0;
}
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 10px;
}
.stat {
  border: 1px solid var(--line);
  border-radius: 10px;
  padding: 12px;
  background: #FBF8EF;
}
.stat span {
  display: block;
  color: var(--muted);
  margin-bottom: 6px;
}
.stat strong {
  font: 400 28px/1 var(--serif);
}
table {
  width: 100%;
  max-width: 100%;
  border-collapse: collapse;
  display: block;
  overflow-x: auto;
}
th, td {
  text-align: left;
  vertical-align: top;
  border-bottom: 1px solid var(--line);
  padding: 9px 8px;
}
th {
  color: var(--muted);
  font-weight: 600;
}
code {
  font-family: var(--mono);
  font-size: 12px;
  overflow-wrap: anywhere;
}
footer {
  background: var(--surface-dark);
  display: flex;
  justify-content: space-between;
  gap: 12px;
  padding: 16px 28px;
}
@media (min-width: 860px) {
  .shell-head {
    grid-template-columns: minmax(0, 1fr) auto;
    align-items: end;
  }
}
"#
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use vela_protocol::frontier_repo::{self, InitOptions};
    use vela_protocol::repo;
    use crate::share_package;
    use tempfile::TempDir;

    #[test]
    fn renders_required_static_files() {
        let tmp = TempDir::new().unwrap();
        let frontier = tmp.path().join("frontier");
        frontier_repo::initialize(
            &frontier,
            InitOptions {
                name: "Static test",
                template: "adoption-frontier",
                initialize_git: false,
            },
        )
        .unwrap();
        let project = repo::load_from_path(&frontier).unwrap();
        let package = tmp.path().join("package");
        fs::create_dir_all(package.join("proof-packet")).unwrap();
        fs::create_dir_all(package.join("source-snapshots")).unwrap();
        fs::create_dir_all(package.join("diff-packs")).unwrap();
        fs::create_dir_all(package.join("review-packets")).unwrap();
        fs::write(package.join("proof-packet").join("manifest.json"), "{}\n").unwrap();
        fs::write(
            package.join("frontier.json"),
            serde_json::to_string_pretty(&project).unwrap(),
        )
        .unwrap();
        fs::write(package.join("frontier-health.json"), "{\"metrics\":{}}\n").unwrap();
        fs::write(package.join("evidence-ci.json"), "{\"summary\":{}}\n").unwrap();
        fs::write(
            package.join("review-sessions.json"),
            "{\"total\":0,\"sessions\":[]}\n",
        )
        .unwrap();
        fs::write(
            package.join("proof-state.json"),
            "{\"status\":\"packet_exported\",\"proof_packet_present\":true}\n",
        )
        .unwrap();
        fs::write(package.join("adoption-transcript.md"), "transcript\n").unwrap();
        fs::write(
            package.join("source-inbox.json"),
            "{\"total\":0,\"records\":[]}\n",
        )
        .unwrap();
        fs::write(
            package.join("source-snapshots").join("index.json"),
            "{\"schema\":\"vela.source_snapshots.v0.2\",\"copied\":0,\"unavailable\":0,\"snapshots\":[],\"unavailable_sources\":[]}\n",
        )
        .unwrap();
        fs::write(
            package.join("source-locator-audit.json"),
            "{\"schema\":\"vela.source_locator_audit.v0.2\",\"review_debt\":0}\n",
        )
        .unwrap();
        fs::write(
            package.join("canonical-verdict-events.json"),
            "{\"schema\":\"vela.canonical_verdict_events.v0.2\",\"count\":0,\"events\":[]}\n",
        )
        .unwrap();
        fs::write(package.join("tasks.json"), "{\"total\":0,\"tasks\":[]}\n").unwrap();
        fs::write(
            package.join("reviewer-packet.json"),
            "{\"read_only\":true,\"review_task\":\"Inspect the package.\",\"first_pass_commands\":[],\"local_frontier_commands\":[]}\n",
        )
        .unwrap();
        fs::write(package.join("reviewer-notes-template.md"), "notes\n").unwrap();
        fs::write(
            package.join("manifest.json"),
            serde_json::json!({
                "schema": share_package::SHARE_MANIFEST_SCHEMA,
                "frontier_id": "vfr_static_test",
                "created_at": "2026-05-14T00:00:00Z",
                "read_only": true,
                "files": [
                    {"path": "frontier.json", "bytes": 2, "sha256": "sha256:test"}
                ]
            })
            .to_string(),
        )
        .unwrap();

        let out = tmp.path().join("site");
        let report = render(&package, &out).unwrap();
        assert!(report.ok);
        for file in [
            "index.html",
            "findings.html",
            "sources.html",
            "tasks.html",
            "diff-packs.html",
            "review-packets.html",
            "proof.html",
            "manifest.html",
            "assets/style.css",
        ] {
            assert!(out.join(file).is_file(), "{file}");
        }
        let html = fs::read_to_string(out.join("index.html")).unwrap();
        assert!(html.contains("Read-only package"));
        assert!(html.contains("not medical advice or field consensus"));
    }
}
