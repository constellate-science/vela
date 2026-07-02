//! `vela check` payload assembly and hashing plumbing: schema/lint/replay
//! diagnostics, repair-plan derivation, sensitive-path scanning, and the
//! frontier hash helpers. Moved verbatim from `cli/mod.rs`.

use super::*;

#[allow(clippy::too_many_arguments)]
/// v0.113: walk a frontier path and return any files whose names
/// match shapes commonly associated with secrets: literal extensions
/// (`*.key`, `*.pem`, `*.p12`) and substring patterns (`private`,
/// `secret`, `credential`). Skips standard noise (`.git/`, `target/`,
/// `node_modules/`, `dist/`, `build/`). Used by `vela check --strict`
/// and by `scripts/test-secret-audit.sh`. Closes part of
/// THREAT_MODEL.md A17 with active detection on top of the passive
/// .gitignore exclusion shipped at v0.111.1.
pub fn scan_for_sensitive_paths(root: &Path) -> Vec<PathBuf> {
    let mut hits: Vec<PathBuf> = Vec::new();
    let skip_dirs: &[&str] = &[".git", "target", "node_modules", "dist", "build"];
    let bad_exts: &[&str] = &["key", "pem", "p12", "pfx"];
    let bad_substrings: &[&str] = &["private", "secret", "credential"];
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name_os = path.file_name();
            let Some(name) = name_os.and_then(|n| n.to_str()) else {
                continue;
            };
            let lower = name.to_lowercase();
            if path.is_dir() {
                if skip_dirs.contains(&name) {
                    continue;
                }
                stack.push(path);
                continue;
            }
            // .pub and .pubkey files are public-key material; skip.
            if lower.ends_with(".pub") || lower.ends_with(".pubkey") {
                continue;
            }
            // public.key by name is an Ed25519 PUBLIC key; safe.
            if lower == "public.key" {
                continue;
            }
            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .map(str::to_lowercase)
                .unwrap_or_default();
            let mut hit = false;
            if bad_exts.iter().any(|x| ext == *x) {
                hit = true;
            }
            if bad_substrings.iter().any(|s| lower.contains(s)) {
                hit = true;
            }
            if hit {
                hits.push(path);
            }
        }
    }
    hits.sort();
    hits
}

pub(crate) fn check_json_payload(src: &Path, schema_only: bool, strict: bool) -> Value {
    let report = validate::validate(src);
    let loaded = repo::load_from_path(src).ok();
    let (method_report, graph_report) = if schema_only {
        (None, None)
    } else if let Some(frontier) = loaded.as_ref() {
        (
            Some(lint::lint(frontier, None, None)),
            Some(lint::lint_frontier(frontier)),
        )
    } else {
        (None, None)
    };
    let source_hash = hash_path(src).unwrap_or_else(|_| "unavailable".to_string());
    let mut diagnostics = Vec::new();
    diagnostics.extend(report.errors.iter().map(|e| {
        json!({
            "severity": "error",
            "rule_id": "schema",
            "finding_id": null,
            "file": &e.file,
            "field_path": null,
            "message": &e.error,
            "suggestion": schema_error_suggestion(&e.error),
            "fixable": schema_error_fix(&e.error),
            "normalize_action": schema_error_action(&e.error),
        })
    }));
    for (check_id, lint_report) in [
        ("methodology", method_report.as_ref()),
        ("frontier_graph", graph_report.as_ref()),
    ] {
        if let Some(lint_report) = lint_report {
            diagnostics.extend(lint_report.diagnostics.iter().map(|d| {
                json!({
                    "severity": d.severity.to_string(),
                    "rule_id": &d.rule_id,
                    "check": check_id,
                    "finding_id": &d.finding_id,
                    "field_path": null,
                    "message": &d.message,
                    "suggestion": &d.suggestion,
                    "fixable": false,
                    "normalize_action": null,
                })
            }));
        }
    }
    let method_errors = method_report.as_ref().map_or(0, |r| r.errors);
    let method_warnings = method_report.as_ref().map_or(0, |r| r.warnings);
    let method_infos = method_report.as_ref().map_or(0, |r| r.infos);
    let graph_errors = graph_report.as_ref().map_or(0, |r| r.errors);
    let graph_warnings = graph_report.as_ref().map_or(0, |r| r.warnings);
    let graph_infos = graph_report.as_ref().map_or(0, |r| r.infos);
    let replay_report = loaded.as_ref().map(events::replay_report);
    let state_integrity_report = if schema_only {
        loaded.as_ref().map(state_integrity::analyze)
    } else {
        state_integrity::analyze_path(src).ok()
    };
    if let Some(replay) = replay_report.as_ref()
        && !replay.ok
    {
        diagnostics.extend(replay.conflicts.iter().map(|conflict| {
            json!({
                "severity": "error",
                "rule_id": "event_replay",
                "check": "events",
                "finding_id": null,
                "field_path": null,
                "message": conflict,
                "suggestion": "Inspect canonical state events and repair the frontier event log before proof export.",
                "fixable": false,
                "normalize_action": null,
            })
        }));
    }
    // Review-decision parity: a stored proposal status with no signed,
    // replayable decision event behind it is a tamper-evidence failure.
    let parity_conflicts: Vec<String> = loaded
        .as_ref()
        .map(vela_protocol::proposals::verify_proposal_decision_parity)
        .unwrap_or_default();
    if !parity_conflicts.is_empty() {
        diagnostics.extend(parity_conflicts.iter().map(|conflict| {
            json!({
                "severity": "error",
                "rule_id": "review_decision_parity",
                "check": "proposals",
                "finding_id": null,
                "field_path": null,
                "message": conflict,
                "suggestion": "Every decided proposal must have a signed review.* event (or, for accepts, its domain event). Re-issue the decision through `vela accept` / `vela proposals reject`.",
                "fixable": false,
                "normalize_action": null,
            })
        }));
    }
    // Activity/state boundary: an activity-plane id (vac_/vrr_) in a
    // lineage-bearing position of accepted state is a soundness break (activity
    // is non-authoritative). Counted as a hard error, strict or not.
    let activity_leaks: Vec<(String, String)> = loaded
        .as_ref()
        .map(|f| {
            vela_protocol::activity::activity_ids_in_lineage(&f.findings, &f.verifier_attachments)
        })
        .unwrap_or_default();
    diagnostics.extend(activity_leaks.iter().map(|(holder, atom)| {
        json!({
            "severity": "error",
            "rule_id": "activity_state_boundary",
            "check": "lineage",
            "finding_id": holder,
            "field_path": null,
            "message": format!(
                "{holder} references activity-plane id {atom} in a lineage-bearing position; activity is non-authoritative and cannot enter accepted lineage"
            ),
            "suggestion": "Remove the activity id from the finding link / verifier attachment; reference the trace by content address in the activity plane instead.",
            "fixable": false,
            "normalize_action": null,
        })
    }));
    let activity_leak_errors = activity_leaks.len();
    let event_errors = replay_report
        .as_ref()
        .map_or(0, |replay| usize::from(!replay.ok))
        + usize::from(!parity_conflicts.is_empty());
    let state_integrity_errors = state_integrity_report
        .as_ref()
        .map_or(0, |report| report.structural_errors.len());
    let (source_registry, evidence_atoms, conditions, proposal_summary, proof_state) = loaded
        .as_ref()
        .map(|frontier| {
            (
                sources::source_summary(frontier),
                sources::evidence_summary(frontier),
                sources::condition_summary(frontier),
                proposals::summary(frontier),
                proposals::proof_state_json(&frontier.proof_state),
            )
        })
        .unwrap_or_else(|| {
            (
                sources::SourceRegistrySummary::default(),
                sources::EvidenceAtomSummary::default(),
                sources::ConditionSummary::default(),
                proposals::ProposalSummary::default(),
                Value::Null,
            )
        });
    if let Some(frontier) = loaded.as_ref()
        && !schema_only
    {
        let projection = sources::derive_projection(frontier);
        let existing_sources = frontier
            .sources
            .iter()
            .map(|source| source.id.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        let existing_atoms = frontier
            .evidence_atoms
            .iter()
            .map(|atom| atom.id.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        let existing_conditions = frontier
            .condition_records
            .iter()
            .map(|record| record.id.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        for source in projection
            .sources
            .iter()
            .filter(|source| !existing_sources.contains(source.id.as_str()))
        {
            diagnostics.push(json!({
                "severity": "warning",
                "rule_id": "missing_source_record",
                "check": "source_registry",
                "finding_id": source.finding_ids.first(),
                "field_path": "sources",
                "message": format!("Source record {} is derivable but not materialized in frontier state.", source.id),
                "suggestion": "Run `vela frontier materialize` to regenerate derived views before proof export.",
                "fixable": true,
                "normalize_action": "materialize_source_record",
            }));
        }
        for atom in projection
            .evidence_atoms
            .iter()
            .filter(|atom| !existing_atoms.contains(atom.id.as_str()))
        {
            diagnostics.push(json!({
                "severity": "warning",
                "rule_id": "missing_evidence_atom",
                "check": "evidence_atoms",
                "finding_id": atom.finding_id,
                "field_path": "evidence_atoms",
                "message": format!("Evidence atom {} is derivable but not materialized in frontier state.", atom.id),
                "suggestion": "Run `vela normalize` to materialize evidence atoms before proof export.",
                "fixable": true,
                "normalize_action": "materialize_evidence_atom",
            }));
        }
        for condition in projection
            .condition_records
            .iter()
            .filter(|condition| !existing_conditions.contains(condition.id.as_str()))
        {
            diagnostics.push(json!({
                "severity": "warning",
                "rule_id": "condition_record_missing",
                "check": "conditions",
                "finding_id": condition.finding_id,
                "field_path": "condition_records",
                "message": format!("Condition record {} is derivable but not materialized in frontier state.", condition.id),
                "suggestion": "Run `vela normalize` to materialize condition boundaries before proof export.",
                "fixable": true,
                "normalize_action": "materialize_condition_record",
            }));
        }
        for proposal in frontier.proposals.iter().filter(|proposal| {
            matches!(proposal.status.as_str(), "accepted" | "applied")
                && proposal
                    .reviewed_by
                    .as_deref()
                    .is_none_or(proposals::is_placeholder_reviewer)
        }) {
            diagnostics.push(json!({
                "severity": "error",
                "rule_id": "reviewer_identity_missing",
                "check": "proposals",
                "finding_id": proposal.target.id,
                "field_path": "proposals[].reviewed_by",
                "message": format!("Accepted or applied proposal {} uses a missing or placeholder reviewer identity.", proposal.id),
                "suggestion": "Accept the proposal with a stable named reviewer id before strict proof use.",
                "fixable": false,
                "normalize_action": null,
            }));
        }
    }
    let signal_report = loaded
        .as_ref()
        .map(|frontier| signals::analyze(frontier, &diagnostics))
        .unwrap_or_else(empty_signal_report);
    let errors = report.errors.len()
        + method_errors
        + graph_errors
        + event_errors
        + state_integrity_errors
        + activity_leak_errors;
    let warnings = method_warnings + graph_warnings + signal_report.proof_readiness.warnings;
    let infos = method_infos + graph_infos;
    let strict_blockers = signal_report
        .signals
        .iter()
        .filter(|signal| signal.blocks.iter().any(|block| block == "strict_check"))
        .count();
    let fixable = diagnostics
        .iter()
        .filter(|d| d.get("fixable").and_then(Value::as_bool).unwrap_or(false))
        .count();
    let ok = errors == 0 && (!strict || (warnings == 0 && strict_blockers == 0));

    json!({
        "ok": ok,
        "command": "check",
        "schema_version": project::VELA_SCHEMA_VERSION,
        "source": {
            "path": src.display().to_string(),
            "hash": format!("sha256:{source_hash}"),
        },
        "summary": {
            "status": if ok { "pass" } else { "fail" },
            "checked_findings": report.total_files,
            "valid_findings": report.valid,
            "invalid_findings": report.invalid,
            "errors": errors,
            "warnings": warnings,
            "info": infos,
            "fixable": fixable,
            "strict": strict,
            "schema_only": schema_only,
        },
        "checks": [
            {
                "id": "schema",
                "status": if report.invalid == 0 { "pass" } else { "fail" },
                "checked": report.total_files,
                "failed": report.invalid,
                "errors": report.errors.iter().map(|e| json!({
                    "file": e.file,
                    "message": e.error,
                })).collect::<Vec<_>>(),
            },
            {
                "id": "methodology",
                "status": if method_errors == 0 { "pass" } else { "fail" },
                "checked": method_report.as_ref().map_or(0, |r| r.findings_checked),
                "failed": method_errors,
                "warnings": method_warnings,
                "info": method_infos,
                "skipped": schema_only,
            },
            {
                "id": "frontier_graph",
                "status": if graph_errors == 0 { "pass" } else { "fail" },
                "checked": graph_report.as_ref().map_or(0, |r| r.findings_checked),
                "failed": graph_errors,
                "warnings": graph_warnings,
                "info": graph_infos,
                "skipped": schema_only,
            },
            {
                "id": "signals",
                "status": if strict_blockers == 0 { "pass" } else { "fail" },
                "checked": signal_report.signals.len(),
                "failed": strict_blockers,
                "warnings": signal_report.proof_readiness.warnings,
                "skipped": loaded.is_none(),
                "blockers": signal_report.signals.iter()
                    .filter(|s| s.blocks.iter().any(|b| b == "strict_check"))
                    .map(|s| json!({
                        "id": s.id,
                        "kind": s.kind,
                        "severity": s.severity,
                        "reason": s.reason,
                    }))
                    .collect::<Vec<_>>(),
            },
            {
                "id": "events",
                "status": if replay_report.as_ref().is_none_or(|replay| replay.ok) { "pass" } else { "fail" },
                "checked": replay_report.as_ref().map_or(0, |replay| replay.event_log.count),
                "failed": event_errors,
                "skipped": schema_only || loaded.is_none(),
            },
            {
                "id": "state_integrity",
                "status": if state_integrity_report.as_ref().is_none_or(|report| report.status != "fail") { "pass" } else { "fail" },
                "checked": state_integrity_report.as_ref().map_or(0, |report| report.summary.get("events").copied().unwrap_or_default()),
                "failed": state_integrity_errors,
                "skipped": schema_only || loaded.is_none(),
            }
        ],
        "event_log": replay_report.as_ref().map(|replay| &replay.event_log),
        "replay": replay_report,
        "state_integrity": state_integrity_report,
        "source_registry": source_registry,
        "evidence_atoms": evidence_atoms,
        "conditions": conditions,
        "proposals": proposal_summary,
        "proof_state": proof_state,
        "diagnostics": diagnostics,
        "signals": signal_report.signals,
        "review_queue": signal_report.review_queue,
        "proof_readiness": signal_report.proof_readiness,
        "repair_plan": build_repair_plan(&diagnostics),
    })
}

pub(crate) fn save_recorded_proof_state(
    frontier: &Path,
    loaded: &project::Project,
) -> Result<(), String> {
    // For a split `.vela` repo, the canonical proof state lives in
    // .vela/proof-state.json — what `load` and Evidence CI's `proof.freshness`
    // read. `proof_load_path` resolves a repo to its compatibility
    // `frontier.json`, so a naive file-patch here would record the proof state
    // into that snapshot only and leave the canonical .vela state stale (the
    // observed three-source divergence). When the target is a repo dir, or a
    // `frontier.json` sitting inside one, save through the canonical repo path
    // so .vela/proof-state.json and the regenerated lock both reflect the
    // export.
    let repo_dir = if frontier.is_dir() && frontier.join(".vela").is_dir() {
        Some(frontier.to_path_buf())
    } else if frontier.is_file()
        && frontier.file_name().is_some_and(|n| n == "frontier.json")
        && frontier.parent().is_some_and(|p| p.join(".vela").is_dir())
    {
        frontier.parent().map(Path::to_path_buf)
    } else {
        None
    };
    if let Some(dir) = repo_dir {
        return repo::save_to_path(&dir, loaded);
    }

    if !frontier.is_file() {
        return repo::save_to_path(frontier, loaded);
    }

    let raw = std::fs::read_to_string(frontier)
        .map_err(|e| format!("Failed to read frontier '{}': {e}", frontier.display()))?;
    let proof_state = serde_json::to_value(&loaded.proof_state)
        .map_err(|e| format!("serialize proof_state: {e}"))?;
    let stats = serde_json::to_value(&loaded.stats).map_err(|e| format!("serialize stats: {e}"))?;
    let updated = replace_top_level_json_field(&raw, "proof_state", &proof_state)
        .and_then(|next| replace_top_level_json_field(&next, "stats", &stats))?;
    let rendered = if updated.ends_with('\n') {
        updated
    } else {
        format!("{updated}\n")
    };
    std::fs::write(frontier, rendered)
        .map_err(|e| format!("Failed to write frontier '{}': {e}", frontier.display()))
}

pub(crate) fn hash_path(path: &Path) -> Result<String, String> {
    let mut hasher = Sha256::new();
    if path.is_file() {
        let bytes = std::fs::read(path)
            .map_err(|e| format!("Failed to read {} for hashing: {e}", path.display()))?;
        hasher.update(&bytes);
    } else if path.is_dir() {
        let mut files = Vec::new();
        collect_hash_files(path, path, &mut files)?;
        files.sort();
        for rel in files {
            hasher.update(rel.to_string_lossy().as_bytes());
            let bytes = std::fs::read(path.join(&rel))
                .map_err(|e| format!("Failed to read {} for hashing: {e}", rel.display()))?;
            hasher.update(bytes);
        }
    } else {
        return Err(format!("Cannot hash missing path {}", path.display()));
    }
    Ok(format!("{:x}", hasher.finalize()))
}

pub(crate) fn load_frontier_or_fail(path: &Path) -> project::Project {
    repo::load_from_path(path).unwrap_or_else(|e| {
        fail_return(&format!(
            "Failed to load frontier '{}': {e}",
            path.display()
        ))
    })
}

pub(crate) fn hash_path_or_fail(path: &Path) -> String {
    hash_path(path).unwrap_or_else(|e| {
        fail_return(&format!(
            "Failed to hash frontier '{}': {e}",
            path.display()
        ))
    })
}

fn collect_hash_files(root: &Path, dir: &Path, files: &mut Vec<PathBuf>) -> Result<(), String> {
    for entry in
        std::fs::read_dir(dir).map_err(|e| format!("Failed to read {}: {e}", dir.display()))?
    {
        let entry = entry.map_err(|e| format!("Failed to read directory entry: {e}"))?;
        let path = entry.path();
        if path.is_dir() {
            collect_hash_files(root, &path, files)?;
        } else if path.is_file() {
            files.push(
                path.strip_prefix(root)
                    .map_err(|e| e.to_string())?
                    .to_path_buf(),
            );
        }
    }
    Ok(())
}

fn schema_error_suggestion(error: &str) -> &'static str {
    if schema_error_action(error).is_some() {
        "Run `vela normalize` to repair deterministic frontier state."
    } else {
        "Inspect and correct the referenced frontier field."
    }
}

fn schema_error_fix(error: &str) -> bool {
    schema_error_action(error).is_some()
}

fn schema_error_action(error: &str) -> Option<&'static str> {
    if error.contains("stats.findings")
        || error.contains("stats.links")
        || error.contains("Invalid compiler")
        || error.contains("Invalid vela_version")
        || error.contains("Invalid schema")
    {
        Some("normalize_metadata_and_stats")
    } else if error.contains("does not match content-address") {
        Some("rewrite_ids")
    } else {
        None
    }
}

fn build_repair_plan(diagnostics: &[Value]) -> Vec<Value> {
    let mut actions = std::collections::BTreeMap::<String, usize>::new();
    for diagnostic in diagnostics {
        if let Some(action) = diagnostic.get("normalize_action").and_then(Value::as_str) {
            *actions.entry(action.to_string()).or_default() += 1;
        }
    }
    actions
        .into_iter()
        .map(|(action, count)| {
            let command = if action == "rewrite_ids" {
                "vela normalize <frontier> --write --rewrite-ids --id-map id-map.json"
            } else {
                "vela normalize <frontier> --write"
            };
            json!({
                "action": action,
                "count": count,
                "command": command,
            })
        })
        .collect()
}

fn empty_signal_report() -> signals::SignalReport {
    signals::SignalReport {
        schema: "vela.signals.v0".to_string(),
        frontier: "unavailable".to_string(),
        signals: Vec::new(),
        review_queue: Vec::new(),
        proof_readiness: signals::ProofReadiness {
            status: "unavailable".to_string(),
            blockers: 0,
            warnings: 0,
            caveats: vec!["Frontier could not be loaded for signal analysis.".to_string()],
        },
    }
}
