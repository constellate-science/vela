//! The MCP tool-handler bodies: the ten released tools (`orient`,
//! `finding`, `search`, `graph`, `verify`, `propose`, `decide`, `work`,
//! `objects`, `external`) and the underlying per-concept tool functions
//! they compose. Moved verbatim from `server/serve.rs`; the dispatch,
//! envelope, and profile gate stay there.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use reqwest::Client;
use serde_json::{Value, json};
use tokio::sync::Mutex;

use vela_edge::signals;
use vela_protocol::events;
use vela_protocol::project::Project;
use vela_protocol::sources;
use vela_protocol::state;

use super::serve::{ToolError, ToolOutput, clamp_limit, decode_cursor, parse_payload};

/// `orient` — one-call situational awareness: stats, verification posture,
/// ranked open targets, gap-flagged findings, the recent event tail, the
/// agent-object summary (when a frontier directory is known), and — when
/// `problem` is given — the full task briefing (task packet merged with the
/// problem exploration).
pub(crate) fn tool_orient(
    args: &Value,
    project: &Project,
    source_path: Option<&Path>,
) -> ToolOutput {
    let limit = clamp_limit(args, 12, 100);
    let mut notes = Vec::new();

    let stats = parse_payload(tool_frontier_stats(project))?;

    let targets = vela_edge::frontier_next::frontier_next(project, source_path, limit);
    if source_path.is_none() {
        notes.push(
            "campaign-seed lane skipped: this transport serves no frontier directory \
             (hosted or merged mode), so open targets list only review and verify lanes"
                .to_string(),
        );
    }

    // Gap-flagged findings — the review leads that used to be `list_gaps`.
    let gap_findings: Vec<&vela_protocol::bundle::FindingBundle> = project
        .findings
        .iter()
        .filter(|finding| finding.flags.gap)
        .collect();
    let gap_total = gap_findings.len();
    let gaps: Vec<Value> = gap_findings
        .into_iter()
        .take(limit)
        .map(|finding| {
            json!({
                "id": finding.id,
                "assertion": trunc(&finding.assertion.text, 160),
                "confidence": finding.confidence.score,
                "conditions": trunc(&finding.conditions.text, 120),
            })
        })
        .collect();
    if gap_total > gaps.len() {
        notes.push(format!(
            "gaps truncated to {} of {gap_total}; raise `limit` or use `search` to page",
            gaps.len()
        ));
    }

    // Recent event tail, chronological.
    let recent_events: Vec<Value> = project
        .events
        .iter()
        .rev()
        .take(limit)
        .map(|event| {
            json!({
                "id": event.id,
                "kind": event.kind,
                "target": event.target,
                "actor": event.actor,
                "timestamp": event.timestamp,
            })
        })
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();

    // Agent-object counts (packs, attestations, evaluations, conflicts) when
    // the server knows its frontier directory.
    let objects_summary = match source_path {
        Some(path) => {
            let summary_args = json!({"frontier_path": path.display().to_string()});
            match parse_payload(vela_edge::vela_agent_mcp::frontier_summary(&summary_args)) {
                Ok(v) => v.get("summary").cloned().unwrap_or(v),
                Err(e) => {
                    notes.push(format!("agent-object summary unavailable: {}", e.message));
                    Value::Null
                }
            }
        }
        None => {
            notes.push(
                "agent-object summary skipped: no frontier directory on this transport".to_string(),
            );
            Value::Null
        }
    };

    // The one-problem briefing: the task packet's entry contract merged with
    // the exploration payload (obligations, rests-on, dependents, staleness).
    let briefing = match args.get("problem").and_then(Value::as_str) {
        None => Value::Null,
        Some(problem) => {
            let mut packet = build_task_packet(
                problem,
                project,
                source_path,
                default_decl_graph_path().as_deref(),
            )
            .map_err(ToolError::classify)?;
            let explore =
                parse_payload(tool_frontier_explore(&json!({"problem": problem}), project))?;
            if let Value::Object(map) = &mut packet {
                map.remove("tool");
                for key in ["obligations", "rests_on", "dependents", "staleness"] {
                    if let Some(v) = explore.get(key) {
                        map.insert(key.to_string(), v.clone());
                    }
                }
            }
            packet
        }
    };

    let data = json!({
        "frontier": stats.get("frontier"),
        "stats": stats.get("stats"),
        "verification": {
            "proof_state": stats.get("proof_state"),
            "events": stats.get("events"),
            "proposals": stats.get("proposals"),
        },
        "signals": stats.get("signals"),
        "open_targets": targets,
        "gaps": {"total": gap_total, "items": gaps},
        "recent_events": recent_events,
        "agent_objects": objects_summary,
        "briefing": briefing,
    });
    Ok((data, notes))
}

/// `finding` — one finding's full context, with opt-in merges of its event
/// history, direct dependents, and graph neighborhood.
pub(crate) fn tool_finding(args: &Value, project: &Project) -> ToolOutput {
    let id = args
        .get("id")
        .and_then(Value::as_str)
        .filter(|s| s.len() >= 3)
        .ok_or_else(|| ToolError::invalid("finding requires `id` (a vf_… id, minLength 3)"))?;
    let mut base = parse_payload(tool_get_finding(&json!({"id": id}), project))?;

    let includes: Vec<&str> = args
        .get("include")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let mut notes = Vec::new();
    for inc in includes {
        let merged = match inc {
            "history" => parse_payload(tool_get_finding_history(&json!({"id": id}), project))?,
            "dependents" => parse_payload(tool_list_dependents(
                &json!({"finding_id": id, "transitive": false}),
                project,
            ))?,
            "neighborhood" => {
                parse_payload(tool_frontier_context(&json!({"finding_id": id}), project))?
            }
            other => {
                return Err(
                    ToolError::invalid(format!("unknown include entry '{other}'"))
                        .with_hint("valid entries: history, dependents, neighborhood"),
                );
            }
        };
        if let Value::Object(map) = &mut base {
            map.insert(inc.to_string(), merged);
        }
        notes.push(format!("merged `{inc}` payload"));
    }
    Ok((base, notes))
}

/// `search` — structured text search over findings, sources, and evidence
/// atoms, with stable offset cursoring (the cursor is an opaque offset into
/// the result order: findings, then sources, then evidence, in frontier
/// order).
pub(crate) fn tool_search(args: &Value, project: &Project) -> ToolOutput {
    let query = args
        .get("query")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|q| !q.is_empty())
        .ok_or_else(|| ToolError::invalid("search requires `query` (non-empty string)"))?;
    let q = query.to_lowercase();
    let ty = args.get("type").and_then(Value::as_str).unwrap_or("any");
    if !matches!(ty, "finding" | "source" | "evidence" | "any") {
        return Err(ToolError::invalid(format!("unknown search type '{ty}'"))
            .with_hint("valid types: finding, source, evidence, any"));
    }
    let entity = args
        .get("entity")
        .and_then(Value::as_str)
        .map(str::to_lowercase);
    let limit = clamp_limit(args, 24, 200);
    let offset = decode_cursor(args)?;
    let mut notes = Vec::new();

    let mut matches: Vec<Value> = Vec::new();
    if matches!(ty, "finding" | "any") {
        for finding in &project.findings {
            let text_hit = finding.assertion.text.to_lowercase().contains(&q)
                || finding.conditions.text.to_lowercase().contains(&q)
                || finding
                    .assertion
                    .entities
                    .iter()
                    .any(|e| e.name.to_lowercase().contains(&q));
            let entity_hit = entity.as_ref().is_none_or(|needle| {
                finding
                    .assertion
                    .entities
                    .iter()
                    .any(|e| e.name.to_lowercase().contains(needle))
            });
            if text_hit && entity_hit {
                matches.push(json!({
                    "kind": "finding",
                    "id": finding.id,
                    "assertion": trunc(&finding.assertion.text, 160),
                    "assertion_type": finding.assertion.assertion_type,
                    "confidence": finding.confidence.score,
                    "gap": finding.flags.gap,
                    "contested": finding.flags.contested,
                    "source": finding.provenance.title,
                }));
            }
        }
    }
    if entity.is_some() && ty != "finding" {
        notes.push("`entity` filters findings only; source/evidence lanes skipped".to_string());
    }
    if matches!(ty, "source" | "any") && entity.is_none() {
        for source in &project.sources {
            let hit = source.title.to_lowercase().contains(&q)
                || source.id.to_lowercase().contains(&q)
                || source.locator.to_lowercase().contains(&q)
                || source
                    .doi
                    .as_deref()
                    .is_some_and(|d| d.to_lowercase().contains(&q));
            if hit {
                matches.push(json!({
                    "kind": "source",
                    "id": source.id,
                    "title": source.title,
                    "doi": source.doi,
                    "source_type": source.source_type,
                    "finding_ids": source.finding_ids,
                }));
            }
        }
    }
    if matches!(ty, "evidence" | "any") && entity.is_none() {
        for atom in &project.evidence_atoms {
            let hit = atom.measurement_or_claim.to_lowercase().contains(&q)
                || atom.id.to_lowercase().contains(&q);
            if hit {
                matches.push(json!({
                    "kind": "evidence",
                    "id": atom.id,
                    "excerpt": trunc(&atom.measurement_or_claim, 160),
                    "finding_id": atom.finding_id,
                    "source_id": atom.source_id,
                    "supports_or_challenges": atom.supports_or_challenges,
                }));
            }
        }
    }

    let total = matches.len();
    let page: Vec<Value> = matches.into_iter().skip(offset).take(limit).collect();
    let next_cursor = if offset + page.len() < total {
        Some((offset + page.len()).to_string())
    } else {
        None
    };
    if next_cursor.is_some() {
        notes.push(format!(
            "{} more matches remain; pass next_cursor to continue",
            total - offset - page.len()
        ));
    }
    let data = json!({
        "query": query,
        "type": ty,
        "total": total,
        "returned": page.len(),
        "matches": page,
        "next_cursor": next_cursor,
    });
    Ok((data, notes))
}

/// `graph` — traverse / impact / contradictions over the typed claim graph.
pub(crate) fn tool_graph(args: &Value, project: &Project) -> ToolOutput {
    let mode = args
        .get("mode")
        .and_then(Value::as_str)
        .unwrap_or("traverse");
    let root = args.get("root").and_then(Value::as_str);
    let limit = clamp_limit(args, 100, 500);
    let edge_kinds: Vec<String> = args
        .get("edge_kinds")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    for kind in &edge_kinds {
        if vela_protocol::frontier_graph::EdgeKind::parse(kind).is_none() {
            return Err(ToolError::invalid(format!("unknown edge kind '{kind}'")).with_hint(
                "valid kinds: supports, contradicts, depends_on, derived_from, replicates, specializes",
            ));
        }
    }
    let mut notes = Vec::new();

    match mode {
        "contradictions" => {
            // Raw contradiction/dispute links, then the first-class vcx_
            // objects, in one list; `first_class` distinguishes them.
            let lookup: HashMap<&str, &vela_protocol::bundle::FindingBundle> = project
                .findings
                .iter()
                .map(|finding| (finding.id.as_str(), finding))
                .collect();
            let mut rows: Vec<Value> = Vec::new();
            for finding in &project.findings {
                for link in &finding.links {
                    if matches!(link.link_type.as_str(), "contradicts" | "disputes") {
                        let target_assertion = lookup
                            .get(link.target.as_str())
                            .map(|f| trunc(&f.assertion.text, 120));
                        rows.push(json!({
                            "first_class": false,
                            "source": finding.id,
                            "source_assertion": trunc(&finding.assertion.text, 120),
                            "target": link.target,
                            "target_assertion": target_assertion,
                            "link_type": link.link_type,
                            "note": link.note,
                        }));
                    }
                }
            }
            let raw_total = rows.len();
            let first_class =
                parse_payload(tool_contradictions(&json!({"limit": limit}), project))?;
            let fc_rows = first_class
                .get("contradictions")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            for mut c in fc_rows {
                if let Value::Object(map) = &mut c {
                    map.insert("first_class".to_string(), json!(true));
                }
                rows.push(c);
            }
            let total = rows.len();
            rows.truncate(limit);
            if total > rows.len() {
                notes.push(format!(
                    "rows truncated to {} of {total}; raise `limit`",
                    rows.len()
                ));
            }
            let data = json!({
                "mode": "contradictions",
                "total": total,
                "raw_link_total": raw_total,
                "candidate_total": first_class.get("candidate_contradictions"),
                "reviewed_total": first_class.get("reviewed_contradictions"),
                "returned": rows.len(),
                "rows": rows,
            });
            Ok((data, notes))
        }
        "impact" => {
            let root = root.ok_or_else(|| {
                ToolError::invalid("mode=impact requires `root` (a vf_… finding id)")
            })?;
            let direction = match args.get("direction").and_then(Value::as_str) {
                None | Some("both") => "both",
                Some("up") => "up",
                Some("down") => "down",
                Some(other) => {
                    return Err(ToolError::invalid(format!("unknown direction '{other}'"))
                        .with_hint("valid directions: up, down, both"));
                }
            };
            let mut impact_args = json!({"finding": root, "impact": direction});
            if !edge_kinds.is_empty() {
                impact_args["kinds"] = json!(edge_kinds.join(","));
            }
            let blast = parse_payload(tool_blast_radius(&impact_args, project))?;
            let cascade = parse_payload(tool_propagate_retraction(
                &json!({"finding_id": root}),
                project,
            ))?;
            let data = json!({
                "mode": "impact",
                "root": root,
                "direction": direction,
                "blast_radius": blast,
                "retraction_cascade": cascade,
            });
            Ok((data, notes))
        }
        "traverse" => match root {
            None => {
                let mut summary = parse_payload(tool_frontier_graph(&json!({}), project))?;
                if !edge_kinds.is_empty() {
                    let mut by_kind = Vec::new();
                    for kind in &edge_kinds {
                        let detail = parse_payload(tool_frontier_graph(
                            &json!({"kind": kind, "limit": limit}),
                            project,
                        ))?;
                        by_kind.push(json!({
                            "kind": kind,
                            "edges": detail.get("matched_edges"),
                        }));
                    }
                    if let Value::Object(map) = &mut summary {
                        map.insert("edges_by_kind".to_string(), json!(by_kind));
                    }
                }
                if let Value::Object(map) = &mut summary {
                    map.insert("mode".to_string(), json!("traverse"));
                }
                Ok((summary, notes))
            }
            Some(root) => {
                let max_hops = args
                    .get("max_hops")
                    .and_then(Value::as_u64)
                    .unwrap_or(2)
                    .clamp(1, 6);
                let deep = parse_payload(tool_deep_trace(
                    &json!({
                        "finding_id": root,
                        "max_hops": max_hops,
                        "limit_per_hop": limit,
                    }),
                    project,
                ))?;
                let chain = parse_payload(tool_trace_evidence_chain(
                    &json!({"finding_id": root, "depth": max_hops}),
                    project,
                ))?;
                if !edge_kinds.is_empty() {
                    notes.push(
                        "edge_kinds is not applied in traverse mode; the traversal follows \
                         all declared kinds"
                            .to_string(),
                    );
                }
                let data = json!({
                    "mode": "traverse",
                    "root": root,
                    "max_hops": max_hops,
                    "traversal": deep,
                    "evidence_chain": chain,
                });
                Ok((data, notes))
            }
        },
        other => Err(ToolError::invalid(format!("unknown graph mode '{other}'"))
            .with_hint("valid modes: traverse, impact, contradictions")),
    }
}

/// `verify` — the frozen verifiers over a local frontier checkout.
pub(crate) fn tool_verify(args: &Value) -> ToolOutput {
    if args
        .get("frontier_path")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err(ToolError::invalid("verify requires `frontier_path`"));
    }
    let payload = match args.get("mode").and_then(Value::as_str) {
        Some("strict") => parse_payload(vela_edge::vela_agent_mcp::check_run(args))?,
        Some("witness") => parse_payload(vela_edge::vela_agent_mcp::reproduce_run(args))?,
        _ => {
            return Err(ToolError::invalid("verify requires `mode`")
                .with_hint("strict = validation + reducer replay + signature signals; witness = re-verify stored witnesses"));
        }
    };
    Ok((payload, Vec::new()))
}

/// `propose` — the draft write surface: one tool, five kinds, all landing as
/// pending proposals through the same signed path the narrow propose_* tools
/// used.
pub(crate) async fn tool_propose(
    args: &Value,
    frontier: &Arc<Mutex<Project>>,
    source_path: Option<&Path>,
) -> ToolOutput {
    let kind = args
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| ToolError::invalid("propose requires `kind`"))?;
    let target = args
        .get("target")
        .and_then(Value::as_str)
        .filter(|t| t.starts_with("vf_"))
        .ok_or_else(|| ToolError::invalid("propose requires `target` (a vf_… finding id)"))?;
    // The underlying write path reads `target_finding_id`.
    let mut legacy = args.clone();
    legacy["target_finding_id"] = json!(target);

    let result = match kind {
        "review" => {
            write_tool_propose(
                &legacy,
                frontier,
                source_path,
                "finding.review",
                |args| {
                    let status = args
                        .get("status")
                        .and_then(Value::as_str)
                        .ok_or("propose kind=review requires `status`")?;
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
            .await
        }
        "note" => {
            write_tool_propose(
                &legacy,
                frontier,
                source_path,
                "finding.note",
                |args| build_note_payload(args, "propose kind=note"),
                false,
            )
            .await
        }
        // apply_note: propose-and-apply in one signed call, gated on the
        // actor's `tier="auto-notes"` registration. Tiers permit
        // review-context kinds only; never state-changing kinds.
        "apply_note" => {
            write_tool_propose(
                &legacy,
                frontier,
                source_path,
                "finding.note",
                |args| build_note_payload(args, "propose kind=apply_note"),
                true,
            )
            .await
        }
        "revise_confidence" => {
            write_tool_propose(
                &legacy,
                frontier,
                source_path,
                "finding.confidence_revise",
                |args| {
                    let new_score = args
                        .get("new_score")
                        .and_then(Value::as_f64)
                        .ok_or("propose kind=revise_confidence requires `new_score`")?;
                    if !(0.0..=1.0).contains(&new_score) {
                        return Err(format!("new_score {new_score} out of [0.0, 1.0]"));
                    }
                    Ok(json!({"new_score": new_score}))
                },
                false,
            )
            .await
        }
        "retract" => {
            write_tool_propose(
                &legacy,
                frontier,
                source_path,
                "finding.retract",
                |_args| Ok(json!({})),
                false,
            )
            .await
        }
        other => {
            return Err(
                ToolError::invalid(format!("unknown propose kind '{other}'"))
                    .with_hint("valid kinds: review, note, revise_confidence, retract, apply_note"),
            );
        }
    };
    Ok((parse_payload(result)?, Vec::new()))
}

/// `decide` — accept/reject a pending proposal as the named (registered,
/// key-holding) reviewer. Maintainer-profile only; the profile gate refuses
/// everyone else before this runs.
pub(crate) async fn tool_decide(
    args: &Value,
    frontier: &Arc<Mutex<Project>>,
    source_path: Option<&Path>,
) -> ToolOutput {
    let action = match args.get("action").and_then(Value::as_str) {
        Some("accept") => "accept",
        Some("reject") => "reject",
        _ => {
            return Err(ToolError::invalid(
                "decide requires `action` (accept or reject)",
            ));
        }
    };
    if args
        .get("proposal_id")
        .and_then(Value::as_str)
        .is_none_or(|p| !p.starts_with("vpr_"))
    {
        return Err(ToolError::invalid(
            "decide requires `proposal_id` (a vpr_… id)",
        ));
    }
    if args
        .get("reason")
        .and_then(Value::as_str)
        .is_none_or(|r| r.trim().is_empty())
    {
        return Err(ToolError::invalid("decide requires a non-empty `reason`"));
    }
    let result = write_tool_decision(args, frontier, source_path, action).await;
    Ok((parse_payload(result)?, Vec::new()))
}

/// `work` — the agent work loop: claim a lease, land a record as a pending
/// proposal, or sign an attestation + diff pack. All three sign under the
/// agent's own auto-minted session key; none finalizes state.
pub(crate) fn tool_work(args: &Value) -> ToolOutput {
    if args
        .get("frontier_path")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err(ToolError::invalid("work requires `frontier_path`"));
    }
    let result = match args.get("action").and_then(Value::as_str) {
        Some("claim") => {
            let actor = args
                .get("agent_actor")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if !actor.starts_with("agent:") && !actor.starts_with("ci:") {
                return Err(ToolError::invalid(
                    "work action=claim requires `agent_actor` matching ^(agent:|ci:)",
                ));
            }
            vela_edge::vela_agent_mcp::claim_task(args)
        }
        Some("record") => {
            if args
                .get("record_path")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
            {
                return Err(ToolError::invalid(
                    "work action=record requires `record_path` (a vrc_… record JSON)",
                ));
            }
            vela_edge::vela_agent_mcp::record_propose(args)
        }
        Some("pack") => {
            if args
                .get("summary")
                .and_then(Value::as_str)
                .is_none_or(|s| s.trim().is_empty())
            {
                return Err(ToolError::invalid(
                    "work action=pack requires a non-empty `summary`",
                ));
            }
            vela_edge::vela_agent_mcp::submit_diff_pack(args)
        }
        _ => {
            return Err(ToolError::invalid("work requires `action`")
                .with_hint("valid actions: claim, record, pack"));
        }
    };
    Ok((parse_payload(result)?, Vec::new()))
}

/// `objects` — read the content-addressed agent objects on a frontier
/// checkout's `.vela/` tree: one by id, or a cursor-paginated listing.
pub(crate) fn tool_objects(args: &Value) -> ToolOutput {
    let frontier_path = args
        .get("frontier_path")
        .and_then(Value::as_str)
        .filter(|p| !p.is_empty())
        .ok_or_else(|| ToolError::invalid("objects requires `frontier_path`"))?;
    let ty = args.get("type").and_then(Value::as_str).ok_or_else(|| {
        ToolError::invalid("objects requires `type`")
            .with_hint("valid types: pack, attestation, evaluation, conflict, tool_descriptor")
    })?;
    let target = args.get("target").and_then(Value::as_str);

    if let Some(id) = args.get("id").and_then(Value::as_str) {
        let fetch = match ty {
            "pack" => vela_edge::vela_agent_mcp::get_pack(
                &json!({"frontier_path": frontier_path, "pack_id": id}),
            ),
            "attestation" => vela_edge::vela_agent_mcp::get_attestation(
                &json!({"frontier_path": frontier_path, "attestation_id": id}),
            ),
            "evaluation" => vela_edge::vela_agent_mcp::get_evaluation(
                &json!({"frontier_path": frontier_path, "evaluation_id": id}),
            ),
            "conflict" => vela_edge::vela_agent_mcp::get_conflict(
                &json!({"frontier_path": frontier_path, "conflict_id": id}),
            ),
            "tool_descriptor" => vela_edge::vela_agent_mcp::get_tool_descriptor(
                &json!({"frontier_path": frontier_path, "descriptor_id": id}),
            ),
            other => {
                return Err(ToolError::invalid(format!("unknown object type '{other}'"))
                    .with_hint(
                        "valid types: pack, attestation, evaluation, conflict, tool_descriptor",
                    ));
            }
        };
        let object = parse_payload(fetch)?;
        return Ok((json!({"type": ty, "id": id, "object": object}), Vec::new()));
    }

    let (listed, key) = match ty {
        "pack" => {
            let mut list_args = json!({"frontier_path": frontier_path});
            if let Some(pending) = args.get("only_pending").and_then(Value::as_bool) {
                list_args["only_pending"] = json!(pending);
            }
            (vela_edge::vela_agent_mcp::list_packs(&list_args), "packs")
        }
        "attestation" => (
            vela_edge::vela_agent_mcp::list_attestations(&json!({"frontier_path": frontier_path})),
            "attestations",
        ),
        "evaluation" => {
            let mut list_args = json!({"frontier_path": frontier_path});
            if let Some(t) = target {
                list_args["target_descriptor_id"] = json!(t);
            }
            (
                vela_edge::vela_agent_mcp::list_evaluations(&list_args),
                "evaluations",
            )
        }
        "conflict" => {
            let mut list_args = json!({"frontier_path": frontier_path});
            if let Some(t) = target {
                list_args["resolution_mode"] = json!(t);
            }
            (
                vela_edge::vela_agent_mcp::list_conflicts(&list_args),
                "conflicts",
            )
        }
        "tool_descriptor" => (
            vela_edge::vela_agent_mcp::list_tool_descriptors(
                &json!({"frontier_path": frontier_path}),
            ),
            "descriptors",
        ),
        other => {
            return Err(
                ToolError::invalid(format!("unknown object type '{other}'")).with_hint(
                    "valid types: pack, attestation, evaluation, conflict, tool_descriptor",
                ),
            );
        }
    };
    let listing = parse_payload(listed)?;
    let items = listing
        .get(key)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let total = items.len();
    let limit = clamp_limit(args, 50, 200);
    let offset = decode_cursor(args)?;
    let page: Vec<Value> = items.into_iter().skip(offset).take(limit).collect();
    let next_cursor = if offset + page.len() < total {
        Some((offset + page.len()).to_string())
    } else {
        None
    };
    let mut notes = Vec::new();
    if next_cursor.is_some() {
        notes.push(format!(
            "{} more objects remain; pass next_cursor to continue",
            total - offset - page.len()
        ));
    }
    let data = json!({
        "type": ty,
        "total": total,
        "returned": page.len(),
        "items": page,
        "next_cursor": next_cursor,
    });
    Ok((data, notes))
}

/// `external` — external services: PubMed prior-art counts, nanopublication
/// export.
pub(crate) async fn tool_external(args: &Value, project: &Project, client: &Client) -> ToolOutput {
    match args.get("service").and_then(Value::as_str) {
        Some("pubmed") => {
            if args
                .get("query")
                .and_then(Value::as_str)
                .is_none_or(|q| q.trim().is_empty())
            {
                return Err(ToolError::invalid(
                    "external service=pubmed requires a non-empty `query`",
                ));
            }
            Ok((
                parse_payload(tool_check_pubmed(args, client).await)?,
                Vec::new(),
            ))
        }
        Some("nanopub") => {
            if args
                .get("finding_id")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
            {
                return Err(ToolError::invalid(
                    "external service=nanopub requires `finding_id`",
                ));
            }
            Ok((
                parse_payload(tool_nanopublication(args, project))?,
                Vec::new(),
            ))
        }
        _ => Err(ToolError::invalid("external requires `service`")
            .with_hint("valid services: pubmed, nanopub")),
    }
}

/// Phase β (v0.6): build the `finding.note` proposal payload from
/// caller args. Accepts the required `text` plus an optional structured
/// `provenance` object whose at-least-one-identifier rule is enforced
/// here at the API boundary, so the same validation runs whether the
/// caller is `propose` kind=note or kind=apply_note.
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

/// Phase Q-w (v0.5): shared body for the `decide` accept/reject actions.
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

pub(crate) fn tool_search_findings(args: &Value, frontier: &Project) -> Result<String, String> {
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
        // Causal closure walks depends/supports edges only (contradicts/extends
        // are excluded), so transitive dependents are the findings that
        // ultimately rest on the target through its evidence chain.
        let mut closure: Vec<String> = downstream_dependents(frontier, &target.id)
            .into_iter()
            .collect();
        closure.sort();
        let transitive_total = closure.len();
        closure.truncate(limit);
        payload["transitive_dependents"] = json!(transitive_total);
        payload["transitive_returned"] = json!(closure.len());
        payload["transitive_ids"] = json!(closure);
    }

    serde_json::to_string_pretty(&payload).map_err(|e| format!("Serialization error: {e}"))
}

/// Transitive downstream-dependent closure of `start`: every finding that
/// (transitively) `depends`/`supports` `start` through the declared link graph.
/// Cross-frontier `vf_X@vfr_Y` targets resolve to the bare `vf_X` node when it
/// is present in the merged project (`serve --frontiers <dir>`). Excludes
/// `start` itself.
///
/// This is the exact downstream-reachable closure the former `CausalGraph`
/// computed: same edge predicate (`depends`/`supports` only), same bare-id
/// resolution, same transitive children walk.
fn downstream_dependents(frontier: &Project, start: &str) -> std::collections::HashSet<String> {
    use std::collections::{HashMap, HashSet, VecDeque};

    let nodes: HashSet<&str> = frontier.findings.iter().map(|f| f.id.as_str()).collect();

    // children[target] = findings that directly depend on / support `target`.
    let mut children: HashMap<&str, Vec<&str>> = HashMap::new();
    for f in &frontier.findings {
        for link in &f.links {
            if !matches!(link.link_type.as_str(), "depends" | "supports") {
                continue;
            }
            let resolved = vela_protocol::bundle::bare_finding_id(&link.target);
            if !nodes.contains(resolved) {
                continue;
            }
            children.entry(resolved).or_default().push(f.id.as_str());
        }
    }

    let mut seen: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<&str> = VecDeque::new();
    if let Some(cs) = children.get(start) {
        queue.extend(cs.iter().copied());
    }
    while let Some(node) = queue.pop_front() {
        if !seen.insert(node.to_string()) {
            continue;
        }
        if let Some(cs) = children.get(node) {
            for &c in cs {
                if !seen.contains(c) {
                    queue.push_back(c);
                }
            }
        }
    }
    seen
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
/// MCP `orient` tool's problem briefing is built from this. It
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
pub(crate) fn tool_nanopublication(args: &Value, frontier: &Project) -> Result<String, String> {
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
            // Cross-frontier resolution, consistent with FrontierGraph and
            // the causal closure: a `vf_X@vfr_Y` target resolves to the bare
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
    use crate::serve::ToolErrorKind;
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

    /// The rewired transitive closure follows only `depends`/`supports`,
    /// ignoring `implies` (cross-problem reductions) and `contradicts`.
    #[test]
    fn transitive_closure_excludes_implies_and_contradicts() {
        let typed = |target: &str, kind: &str| {
            let mut l = link_to(target);
            l.link_type = kind.into();
            l
        };
        // f3 (root). f2 supports f3. f1 depends f2. fX implies f3 (ignored).
        // fY contradicts f3 (ignored).
        let f3 = synth_finding(3, vec![]);
        let f2 = synth_finding(2, vec![typed(&f3.id, "supports")]);
        let f1 = synth_finding(1, vec![typed(&f2.id, "depends")]);
        let fx = synth_finding(10, vec![typed(&f3.id, "implies")]);
        let fy = synth_finding(11, vec![typed(&f3.id, "contradicts")]);
        let f3_id = f3.id.clone();
        let mut project = assemble("equiv", vec![], 0, 0, "test");
        project.findings = vec![f3, f2, f1, fx, fy];

        // f3's downstream is {f2, f1}; implies/contradicts dependents excluded.
        let d3 = downstream_dependents(&project, &f3_id);
        assert_eq!(d3.len(), 2);
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

    /// The `search` tool pages with a stable opaque cursor: page one plus
    /// next_cursor, page two resumes where page one stopped, and the tail
    /// page carries no cursor.
    #[test]
    fn search_pages_with_stable_cursor() {
        let findings: Vec<_> = (0..5).map(|i| synth_finding(i, vec![])).collect();
        let ids: Vec<String> = findings.iter().map(|f| f.id.clone()).collect();
        let mut project = assemble("srch", vec![], 0, 0, "test");
        project.findings = findings;

        let (page1, _) = tool_search(&json!({"query": "Synthetic", "limit": 2}), &project).unwrap();
        assert_eq!(page1["total"], 5);
        assert_eq!(page1["returned"], 2);
        assert_eq!(page1["matches"][0]["id"], ids[0]);
        let cursor = page1["next_cursor"].as_str().unwrap().to_string();

        let (page2, _) = tool_search(
            &json!({"query": "Synthetic", "limit": 2, "cursor": cursor}),
            &project,
        )
        .unwrap();
        assert_eq!(page2["matches"][0]["id"], ids[2]);

        let (tail, _) = tool_search(
            &json!({"query": "Synthetic", "limit": 2, "cursor": page2["next_cursor"]}),
            &project,
        )
        .unwrap();
        assert_eq!(tail["returned"], 1);
        assert!(tail["next_cursor"].is_null());

        // A cursor this server never issued is an INVALID_ARG, not a 500.
        let err = tool_search(
            &json!({"query": "Synthetic", "cursor": "vev_bogus"}),
            &project,
        )
        .unwrap_err();
        assert_eq!(err.kind, ToolErrorKind::InvalidArg);
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
