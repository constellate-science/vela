//! The windowed frontier diff (`vela frontier diff`) and its ISO-week
//! helpers. Moved verbatim from `cli/mod.rs`.

use super::*;

/// v0.32: structured diff of findings added/updated/contradicted in a
/// time window. Read-only over canonical state; does not modify the
/// frontier and does not need a signing key.
///
/// Window resolution priority: `--since` > `--week` > current ISO week.
/// If `--since` is given, the upper bound is "now" (UTC); the diff
/// covers `[since, now)`. If `--week` is given (or defaulted), the
/// window is `[Mon 00:00 UTC, next Mon 00:00 UTC)`.
pub(crate) fn cmd_frontier_diff(
    frontier: &Path,
    since: Option<&str>,
    week: Option<&str>,
    json: bool,
) {
    let project = repo::load_from_path(frontier).unwrap_or_else(|e| fail_return(&e));

    // ── Resolve the window ──
    let now = chrono::Utc::now();
    let (window_start, window_end, week_label): (
        chrono::DateTime<chrono::Utc>,
        chrono::DateTime<chrono::Utc>,
        Option<String>,
    ) = if let Some(s) = since {
        let parsed = chrono::DateTime::parse_from_rfc3339(s)
            .map(|d| d.with_timezone(&chrono::Utc))
            .unwrap_or_else(|e| fail_return(&format!("invalid --since timestamp '{s}': {e}")));
        (parsed, now, None)
    } else {
        let key = week
            .map(str::to_owned)
            .unwrap_or_else(|| iso_week_key_for(now.date_naive()));
        let (start, end) = iso_week_bounds(&key)
            .unwrap_or_else(|e| fail_return(&format!("invalid --week '{key}': {e}")));
        (start, end, Some(key))
    };

    // ── Bucket findings ──
    let mut added: Vec<&vela_protocol::bundle::FindingBundle> = Vec::new();
    let mut updated: Vec<&vela_protocol::bundle::FindingBundle> = Vec::new();
    let mut new_contradictions: Vec<&vela_protocol::bundle::FindingBundle> = Vec::new();
    let mut cumulative: usize = 0;

    for f in &project.findings {
        let created = chrono::DateTime::parse_from_rfc3339(&f.created)
            .map(|d| d.with_timezone(&chrono::Utc))
            .ok();
        let updated_ts = f
            .updated
            .as_deref()
            .and_then(|u| chrono::DateTime::parse_from_rfc3339(u).ok())
            .map(|d| d.with_timezone(&chrono::Utc));

        if let Some(c) = created
            && c < window_end
        {
            cumulative += 1;
        }

        if let Some(c) = created
            && c >= window_start
            && c < window_end
        {
            added.push(f);
            let is_tension = f.flags.contested || f.assertion.assertion_type == "tension";
            if is_tension {
                new_contradictions.push(f);
            }
            continue;
        }
        if let Some(u) = updated_ts
            && u >= window_start
            && u < window_end
        {
            updated.push(f);
        }
    }

    // ── Render ──
    let summary_for = |list: &[&vela_protocol::bundle::FindingBundle]| -> Vec<serde_json::Value> {
        list.iter()
            .map(|f| {
                json!({
                    "id": f.id,
                    "assertion": f.assertion.text,
                    "evidence_type": f.evidence.evidence_type,
                    "confidence": f.confidence.score,
                    "doi": f.provenance.doi,
                })
            })
            .collect()
    };

    let payload = json!({
        "ok": true,
        "command": "frontier.diff",
        "frontier": frontier.display().to_string(),
        "frontier_id": project.frontier_id,
        "window": {
            "start": window_start.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "end": window_end.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "iso_week": week_label,
        },
        "totals": {
            "added": added.len(),
            "updated": updated.len(),
            "new_contradictions": new_contradictions.len(),
            "cumulative_claims": cumulative,
        },
        "added": summary_for(&added),
        "updated": summary_for(&updated),
        "new_contradictions": summary_for(&new_contradictions),
    });

    if json {
        print_json(&payload);
        return;
    }

    let label = week_label
        .clone()
        .unwrap_or_else(|| format!("since {}", window_start.format("%Y-%m-%d %H:%M UTC")));
    println!();
    println!(
        "  {}",
        format!("VELA · FRONTIER · DIFF · {label}")
            .to_uppercase()
            .dimmed()
    );
    println!("  {}", style::tick_row(60));
    println!(
        "  range:           {} → {}",
        window_start.format("%Y-%m-%d %H:%M"),
        window_end.format("%Y-%m-%d %H:%M")
    );
    println!("  added:           {}", added.len());
    println!("  updated:         {}", updated.len());
    println!("  contradictions:  {}", new_contradictions.len());
    println!("  cumulative:      {cumulative}");
    if added.is_empty() && updated.is_empty() {
        println!();
        println!("  (quiet window — no findings added or updated)");
    } else {
        println!();
        println!("  added:");
        for f in &added {
            println!(
                "    · {}  {}",
                f.id.dimmed(),
                truncate(&f.assertion.text, 88)
            );
        }
        if !updated.is_empty() {
            println!();
            println!("  updated:");
            for f in &updated {
                println!(
                    "    · {}  {}",
                    f.id.dimmed(),
                    truncate(&f.assertion.text, 88)
                );
            }
        }
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(n.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

/// ISO 8601 week key in `YYYY-Www` form for a given calendar date.
fn iso_week_key_for(d: chrono::NaiveDate) -> String {
    use chrono::Datelike;
    let iso = d.iso_week();
    format!("{:04}-W{:02}", iso.year(), iso.week())
}

/// Resolve `YYYY-Www` to its UTC bounds:
/// `[Monday 00:00 UTC, next Monday 00:00 UTC)`.
fn iso_week_bounds(
    key: &str,
) -> Result<(chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>), String> {
    let (year_str, week_str) = key
        .split_once("-W")
        .ok_or_else(|| format!("expected YYYY-Www, got '{key}'"))?;
    let year: i32 = year_str
        .parse()
        .map_err(|e| format!("bad year in '{key}': {e}"))?;
    let week: u32 = week_str
        .parse()
        .map_err(|e| format!("bad week in '{key}': {e}"))?;
    let monday = chrono::NaiveDate::from_isoywd_opt(year, week, chrono::Weekday::Mon)
        .ok_or_else(|| format!("invalid ISO week: {key}"))?;
    let next_monday = monday + chrono::Duration::days(7);
    let start = monday.and_hms_opt(0, 0, 0).expect("00:00 valid").and_utc();
    let end = next_monday
        .and_hms_opt(0, 0, 0)
        .expect("00:00 valid")
        .and_utc();
    Ok((start, end))
}
