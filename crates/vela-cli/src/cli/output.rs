//! Shared CLI output and failure helpers: the `print_*` family, the
//! `fail*` exits, and small formatting utilities. Moved verbatim from
//! `cli/mod.rs`; behavior unchanged.

use super::*;

pub(crate) fn wrap_line(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    let mut out = String::new();
    let mut line_len = 0usize;
    for word in text.split_whitespace() {
        let word_len = word.chars().count();
        if line_len > 0 && line_len + 1 + word_len > max_chars {
            out.push('\n');
            out.push_str("              ");
            out.push_str(word);
            line_len = word_len;
        } else {
            if line_len > 0 {
                out.push(' ');
                line_len += 1;
            }
            out.push_str(word);
            line_len += word_len;
        }
    }
    out
}

// ── v0.42 daily-driver triad ────────────────────────────────────────

pub(crate) fn frontier_label(p: &vela_protocol::project::Project) -> String {
    if p.project.name.trim().is_empty() {
        "(unnamed)".to_string()
    } else {
        p.project.name.clone()
    }
}

pub(crate) fn fmt_timestamp(ts: &str) -> String {
    // RFC 3339 → "MM-DD HH:MM" for human reading. Falls back to first
    // 16 chars if parsing fails (which is enough to be readable).
    chrono::DateTime::parse_from_rfc3339(ts)
        .map(|dt| dt.format("%m-%d %H:%M").to_string())
        .unwrap_or_else(|_| ts.chars().take(16).collect())
}

pub(crate) fn print_signal_summary(report: &signals::SignalReport, strict: bool) {
    println!();
    println!("  {}", "SIGNALS".dimmed());
    println!("  {}", style::tick_row(60));
    println!("  total signals:   {}", report.signals.len());
    println!("  proof readiness: {}", report.proof_readiness.status);
    if !report.review_queue.is_empty() {
        println!("  review queue:    {} items", report.review_queue.len());
    }
    if strict && report.proof_readiness.status != "ready" {
        println!(
            "  {} proof readiness has blocking signals.",
            style::lost("strict check failed")
        );
    }
}

pub(crate) fn print_tool_check_report(report: &Value) {
    let summary = report.get("summary").unwrap_or(&Value::Null);
    let frontier = report.get("frontier").unwrap_or(&Value::Null);
    println!();
    println!("  {}", "VELA · SERVE · CHECK-TOOLS".dimmed());
    println!("  {}", style::tick_row(60));
    println!(
        "frontier: {}",
        frontier
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
    );
    println!(
        "findings: {}",
        frontier
            .get("findings")
            .and_then(Value::as_u64)
            .unwrap_or_default()
    );
    println!(
        "checks: {} passed, {} failed",
        summary
            .get("passed")
            .and_then(Value::as_u64)
            .unwrap_or_default(),
        summary
            .get("failed")
            .and_then(Value::as_u64)
            .unwrap_or_default()
    );
    if let Some(tools) = report.get("tools").and_then(Value::as_array) {
        let names = tools
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(", ");
        println!("tools: {names}");
    }
    if let Some(checks) = report.get("checks").and_then(Value::as_array) {
        for check in checks {
            let status = if check.get("ok").and_then(Value::as_bool) == Some(true) {
                style::ok("ok")
            } else {
                style::lost("lost")
            };
            println!(
                "  {} {}",
                status,
                check
                    .get("tool")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
            );
        }
    }
    if let Some(adoption) = report.get("adoption").and_then(Value::as_object) {
        println!();
        println!("adoption:");
        println!(
            "  status: {}",
            if adoption.get("ok").and_then(Value::as_bool) == Some(true) {
                "ok"
            } else {
                "needs attention"
            }
        );
        if let Some(prompt) = adoption.get("prompt").and_then(Value::as_str) {
            println!("  prompt: {prompt}");
        }
        if let Some(config) = adoption.get("mcp_config") {
            println!(
                "  mcp: {}",
                serde_json::to_string(config).expect("serialize mcp config")
            );
        }
    }
}

pub(crate) fn print_state_report(report: &state::StateCommandReport, json_output: bool) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(report).expect("failed to serialize state command report")
        );
    } else {
        println!("{}", report.message);
        println!("  frontier: {}", report.frontier);
        println!("  finding:  {}", report.finding_id);
        println!("  proposal: {}", report.proposal_id);
        println!("  status:   {}", report.proposal_status);
        if let Some(event_id) = &report.applied_event_id {
            println!("  event:    {}", event_id);
        }
        println!("  wrote:    {}", report.wrote_to);
    }
}

pub(crate) fn print_history(payload: &Value) {
    let finding = payload.get("finding").unwrap_or(&Value::Null);
    println!("state-transition history");
    println!(
        "  finding: {}",
        finding
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
    );
    println!(
        "  assertion: {}",
        finding
            .get("assertion")
            .and_then(Value::as_str)
            .unwrap_or("")
    );
    // v0.326: a confidence number never stands alone. The payload
    // carries explicit score/basis/reviewed (Confidence serializes as
    // a bare score) so an unreviewed operator prior cannot read as
    // adjudicated evidence.
    let conf_score = payload
        .get("confidence_score")
        .and_then(Value::as_f64)
        .unwrap_or_default();
    let conf_basis = payload
        .get("confidence_basis")
        .and_then(Value::as_str)
        .unwrap_or("unspecified");
    let reviewed = payload
        .get("reviewed")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let reviewed_by_kind = payload
        .get("reviewed_by_kind")
        .and_then(Value::as_str)
        .unwrap_or("none");
    println!(
        "  confidence: {conf_score:.3}  (basis: {conf_basis}) [reviewed: {reviewed} by {reviewed_by_kind}]"
    );
    if conf_score >= 0.7 && !reviewed {
        println!("  note: confidence >=0.70 on an unreviewed basis — not adjudicated evidence");
    }
    // v0.324: the human-facing review/confidence counts must reflect
    // the canonical `.vela/events/` log, not the legacy
    // `review_events` / `confidence_updates` collections (which stay
    // separate by design). Before this, an applied `finding.reviewed`
    // / `finding.caveated` / `finding.confidence_revised` verdict
    // flipped the finding flag but lineage still printed
    // `review events: 0`, telling a reviewer their action did nothing.
    let canonical_events = payload.get("events").and_then(Value::as_array);
    let count_event_kinds = |kinds: &[&str]| -> usize {
        canonical_events.map_or(0, |events| {
            events
                .iter()
                .filter(|e| {
                    e.get("kind")
                        .and_then(Value::as_str)
                        .is_some_and(|k| kinds.contains(&k))
                })
                .count()
        })
    };
    let legacy_reviews = payload
        .get("review_events")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let legacy_updates = payload
        .get("confidence_updates")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let reviews = legacy_reviews
        + count_event_kinds(&[
            "finding.reviewed",
            "finding.caveated",
            "finding.noted",
            "finding.rejected",
            "finding.retracted",
        ]);
    let updates = legacy_updates + count_event_kinds(&["finding.confidence_revised"]);
    let annotations = finding
        .get("annotations")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let sources = payload
        .get("sources")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let atoms = payload
        .get("evidence_atoms")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let conditions = payload
        .get("condition_records")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let proposals = payload
        .get("proposals")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let events = payload
        .get("events")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    println!("  review events:      {reviews}");
    println!("  confidence updates: {updates}");
    println!("  annotations:        {annotations}");
    println!("  sources:            {sources}");
    println!("  evidence atoms:     {atoms}");
    println!("  condition records:  {conditions}");
    println!("  proposals:          {proposals}");
    println!("  canonical events:   {events}");
    if let Some(status) = payload
        .get("proof_state")
        .and_then(|value| value.get("latest_packet"))
        .and_then(|value| value.get("status"))
        .and_then(Value::as_str)
    {
        println!("  proof state:        {status}");
    }
    let legacy_list = payload
        .get("review_events")
        .and_then(Value::as_array)
        .filter(|a| !a.is_empty());
    if let Some(events) = legacy_list {
        for event in events.iter().take(8) {
            println!(
                "  - {} {} {}",
                event
                    .get("reviewed_at")
                    .and_then(Value::as_str)
                    .unwrap_or(""),
                event.get("id").and_then(Value::as_str).unwrap_or(""),
                event.get("reason").and_then(Value::as_str).unwrap_or("")
            );
        }
    } else if let Some(events) = canonical_events {
        // Legacy collection empty: list the canonical review-ish
        // verdicts so the detail matches the count above.
        let review_kinds = [
            "finding.reviewed",
            "finding.caveated",
            "finding.noted",
            "finding.rejected",
            "finding.retracted",
            "finding.confidence_revised",
        ];
        for event in events
            .iter()
            .filter(|e| {
                e.get("kind")
                    .and_then(Value::as_str)
                    .is_some_and(|k| review_kinds.contains(&k))
            })
            .take(8)
        {
            println!(
                "  - {} {} {} {}",
                event.get("timestamp").and_then(Value::as_str).unwrap_or(""),
                event.get("kind").and_then(Value::as_str).unwrap_or(""),
                event.get("id").and_then(Value::as_str).unwrap_or(""),
                event.get("reason").and_then(Value::as_str).unwrap_or("")
            );
        }
    }
}

pub(crate) fn fail(message: &str) -> ! {
    // Route through the one output contract: under --json (set_mode by
    // the running command) even this generic failure is a JSON envelope
    // with the right exit code, never stray prose.
    crate::ui::fail_with(crate::ui::ErrorKind::Domain, message, None)
}

/// A lookup that found nothing. Exit 3; the hint names the discovery verb.
pub(crate) fn fail_not_found<T>(message: &str, hint: &str) -> T {
    crate::ui::fail_with(crate::ui::ErrorKind::NotFound, message, Some(hint))
}

/// A wrong invocation. Exit 2; the hint shows the corrected command.
pub(crate) fn fail_usage<T>(message: &str, hint: &str) -> T {
    crate::ui::fail_with(crate::ui::ErrorKind::Usage, message, Some(hint))
}

/// Validate that a CLI string argument is one of the allowed enum values.
/// On mismatch, prints a friendly error naming the flag and the valid set
/// and exits with code 1. Used at finding-add time so users learn before
/// strict validation rejects the resulting frontier.
pub(crate) fn validate_enum_arg(flag: &str, value: &str, valid: &[&str]) {
    if !valid.contains(&value) {
        fail(&format!(
            "invalid {flag} '{value}'. Valid: {}",
            valid.join(", ")
        ));
    }
}

pub(crate) fn fail_return<T>(message: &str) -> T {
    fail(message)
}

/// Print a value as pretty JSON to stdout. The single, deduplicated form of
/// the `println!("{}", serde_json::to_string_pretty(&x).expect(...))` idiom
/// that recurs across the `--json` paths of most handlers.
pub(crate) fn print_json<T: Serialize + ?Sized>(value: &T) {
    println!(
        "{}",
        serde_json::to_string_pretty(value).expect("serialize json output")
    );
}

pub(crate) fn print_engine_verdict(v: &proposals::EngineVerdict) {
    match v.status.as_str() {
        "pass" => {
            println!("  {} evidence-ci: clean", style::ok("engine"));
        }
        "warn" => {
            println!(
                "  {} evidence-ci: {} new review warning(s)",
                style::warn("engine"),
                v.new_warnings.len()
            );
            for w in v.new_warnings.iter().take(6) {
                println!("    {}", style::dim(w));
            }
        }
        "forced" => {
            println!(
                "  {} gate overridden: {} new blocking, {} new warning(s) — recorded in decision reason",
                style::warn("engine"),
                v.new_blocking.len(),
                v.new_warnings.len()
            );
        }
        other => {
            println!("  {} evidence-ci: {}", style::warn("engine"), other);
        }
    }
}
