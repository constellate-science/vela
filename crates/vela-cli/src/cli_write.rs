use crate::cli::{
    fail, fail_return, print_json,
};
use crate::cli::{
    confirm_action,
    parse_task_status, print_state_report, print_task,
    sign_and_apply,
};
use crate::cli_commands::*;
use colored::Colorize;
use serde_json::json;
use std::path::PathBuf;
use vela_edge::frontier_task;
use vela_protocol::cli_style as style;
use vela_protocol::proposals;
use vela_protocol::repo;

pub(crate) fn cmd_proposals(action: ProposalAction) {
    match action {
        ProposalAction::List {
            frontier,
            status,
            json,
        } => {
            let frontier_state =
                repo::load_from_path(&frontier).unwrap_or_else(|e| fail_return(&e));
            let proposals_list = proposals::list(&frontier_state, status.as_deref());
            let payload = json!({
                "ok": true,
                "command": "proposals.list",
                "frontier": frontier_state.project.name,
                "status_filter": status,
                "summary": proposals::summary(&frontier_state),
                "proposals": proposals_list,
            });
            if json {
                print_json(&payload);
            } else {
                println!("vela proposals list");
                println!("  frontier: {}", frontier_state.project.name);
                println!(
                    "  proposals: {}",
                    payload["proposals"].as_array().map_or(0, Vec::len)
                );
            }
        }
        ProposalAction::Show {
            frontier,
            proposal_id,
            json,
        } => {
            let frontier_state =
                repo::load_from_path(&frontier).unwrap_or_else(|e| fail_return(&e));
            let proposal =
                proposals::show(&frontier_state, &proposal_id).unwrap_or_else(|e| fail_return(&e));
            let payload = json!({
                "ok": true,
                "command": "proposals.show",
                "frontier": frontier_state.project.name,
                "proposal": proposal,
            });
            if json {
                print_json(&payload);
            } else {
                println!("vela proposals show");
                println!("  frontier: {}", frontier_state.project.name);
                println!("  proposal: {}", proposal_id);
                println!("  kind: {}", proposal.kind);
                println!("  status: {}", proposal.status);
            }
        }
        ProposalAction::Preview {
            frontier,
            proposal_id,
            reviewer,
            json,
        } => {
            let preview = proposals::preview_at_path(&frontier, &proposal_id, &reviewer)
                .unwrap_or_else(|e| fail_return(&e));
            let payload = json!({
                "ok": true,
                "command": "proposals.preview",
                "frontier": frontier.display().to_string(),
                "preview": preview,
            });
            if json {
                print_json(&payload);
            } else {
                println!("vela proposals preview");
                println!("  proposal: {}", proposal_id);
                println!("  kind: {}", preview.kind);
                println!(
                    "  findings: {} -> {}",
                    preview.findings_before, preview.findings_after
                );
                println!(
                    "  artifacts: {} -> {}",
                    preview.artifacts_before, preview.artifacts_after
                );
                println!(
                    "  events: {} -> {}",
                    preview.events_before, preview.events_after
                );
                if !preview.changed_findings.is_empty() {
                    println!(
                        "  findings changed: {}",
                        preview.changed_findings.join(", ")
                    );
                }
                if !preview.changed_artifacts.is_empty() {
                    println!(
                        "  artifacts changed: {}",
                        preview.changed_artifacts.join(", ")
                    );
                }
                if !preview.event_kinds.is_empty() {
                    println!("  event kinds: {}", preview.event_kinds.join(", "));
                }
                println!("  event: {}", preview.applied_event_id);
            }
        }
        ProposalAction::Import {
            frontier,
            source,
            json,
        } => {
            let report =
                proposals::import_from_path(&frontier, &source).unwrap_or_else(|e| fail_return(&e));
            let payload = json!({
                "ok": true,
                "command": "proposals.import",
                "frontier": frontier.display().to_string(),
                "source": source.display().to_string(),
                "summary": {
                    "imported": report.imported,
                    "applied": report.applied,
                    "rejected": report.rejected,
                    "duplicates": report.duplicates,
                },
            });
            if json {
                print_json(&payload);
            } else {
                println!(
                    "Imported {} proposals into {}",
                    report.imported, report.wrote_to
                );
            }
        }
        ProposalAction::Validate { source, json } => {
            let report = proposals::validate_source(&source).unwrap_or_else(|e| fail_return(&e));
            let payload = json!({
                "ok": report.ok,
                "command": "proposals.validate",
                "source": source.display().to_string(),
                "summary": {
                    "checked": report.checked,
                    "valid": report.valid,
                    "invalid": report.invalid,
                },
                "proposal_ids": report.proposal_ids,
                "errors": report.errors,
            });
            if json {
                print_json(&payload);
            } else if report.ok {
                println!("{} validated {} proposals", style::ok("ok"), report.valid);
            } else {
                println!(
                    "{} validated {} proposals, {} invalid",
                    style::lost("lost"),
                    report.valid,
                    report.invalid
                );
                for error in &report.errors {
                    println!("  · {error}");
                }
                std::process::exit(1);
            }
        }
        ProposalAction::Export {
            frontier,
            output,
            status,
            json,
        } => {
            let count = proposals::export_to_path(&frontier, &output, status.as_deref())
                .unwrap_or_else(|e| fail_return(&e));
            let payload = json!({
                "ok": true,
                "command": "proposals.export",
                "frontier": frontier.display().to_string(),
                "output": output.display().to_string(),
                "status": status,
                "exported": count,
            });
            if json {
                print_json(&payload);
            } else {
                println!("sealed · {count} proposals · {}", output.display());
            }
        }
        ProposalAction::Accept {
            frontier,
            proposal_id,
            reviewer,
            reason,
            key,
            json,
        } => {
            let reviewer = crate::cli_identity::resolve_actor(reviewer.as_deref());
            let signing_key = crate::cli_identity::resolve_signing_key_opt(key.as_deref());
            let event_id = proposals::accept_at_path_signed(
                &frontier,
                &proposal_id,
                &reviewer,
                &reason,
                signing_key.as_ref(),
            )
            .unwrap_or_else(|e| fail_return(&e));
            let payload = json!({
                "ok": true,
                "command": "proposals.accept",
                "frontier": frontier.display().to_string(),
                "proposal_id": proposal_id,
                "reviewer": reviewer,
                "applied_event_id": event_id,
            });
            if json {
                print_json(&payload);
            } else {
                println!(
                    "{} accepted and applied proposal {}",
                    style::ok("ok"),
                    proposal_id
                );
                println!("  event: {}", event_id);
            }
        }
        ProposalAction::Reject {
            frontier,
            proposal_id,
            reviewer,
            reason,
            key,
            json,
        } => {
            let reviewer = crate::cli_identity::resolve_actor(reviewer.as_deref());
            let signing_key = crate::cli_identity::resolve_signing_key_opt(key.as_deref());
            proposals::reject_at_path_signed(
                &frontier,
                &proposal_id,
                &reviewer,
                &reason,
                signing_key.as_ref(),
            )
            .unwrap_or_else(|e| fail_return(&e));
            let payload = json!({
                "ok": true,
                "command": "proposals.reject",
                "frontier": frontier.display().to_string(),
                "proposal_id": proposal_id,
                "reviewer": reviewer,
                "status": "rejected",
                "signed": signing_key.is_some(),
            });
            if json {
                print_json(&payload);
            } else {
                println!(
                    "{} rejected proposal {}{}",
                    style::warn("rejected"),
                    proposal_id,
                    if signing_key.is_some() {
                        " (signed review.rejected event)"
                    } else {
                        ""
                    }
                );
            }
        }
        ProposalAction::BackfillReviews { frontier, json } => {
            let count =
                proposals::backfill_reviews_at_path(&frontier).unwrap_or_else(|e| fail_return(&e));
            let payload = json!({
                "ok": true,
                "command": "proposals.backfill-reviews",
                "frontier": frontier.display().to_string(),
                "synthesized": count,
            });
            if json {
                print_json(&payload);
            } else {
                println!(
                    "{} backfilled {} legacy review event(s) on {}",
                    style::ok("ok"),
                    count,
                    frontier.display()
                );
            }
        }
    }
}

/// Phase R (v0.5): walk the local Workbench draft queue. The Workbench
/// browser writes unsigned drafts to a queue file; this CLI is the only
/// place where the actor's private key reads its drafts and signs them.
/// The browser never sees the key.
pub(crate) fn cmd_queue(action: QueueAction) {
    use vela_edge::queue;
    match action {
        QueueAction::List { queue_file, json } => {
            let path = queue_file.unwrap_or_else(queue::default_queue_path);
            let q = queue::load(&path).unwrap_or_else(|e| fail_return(&e));
            if json {
                let payload = json!({
                    "ok": true,
                    "command": "queue.list",
                    "queue_file": path.display().to_string(),
                    "schema": q.schema,
                    "actions": q.actions,
                });
                print_json(&payload);
            } else {
                println!();
                println!(
                    "  {}",
                    format!("VELA · QUEUE · LIST · {}", path.display())
                        .to_uppercase()
                        .dimmed()
                );
                println!("  {}", style::tick_row(60));
                if q.actions.is_empty() {
                    println!("  (queue is empty)");
                } else {
                    for (idx, action) in q.actions.iter().enumerate() {
                        println!(
                            "  [{idx}] {} → {}  queued {}",
                            action.kind,
                            action.frontier.display(),
                            action.queued_at
                        );
                    }
                }
            }
        }
        QueueAction::Clear { queue_file, json } => {
            let path = queue_file.unwrap_or_else(queue::default_queue_path);
            let dropped = queue::clear(&path).unwrap_or_else(|e| fail_return(&e));
            if json {
                let payload = json!({
                    "ok": true,
                    "command": "queue.clear",
                    "queue_file": path.display().to_string(),
                    "dropped": dropped,
                });
                print_json(&payload);
            } else {
                println!("{} dropped {dropped} queued action(s)", style::ok("ok"));
            }
        }
        QueueAction::Sign {
            actor,
            key,
            queue_file,
            yes_to_all,
            json,
        } => {
            let path = queue_file.unwrap_or_else(queue::default_queue_path);
            let q = queue::load(&path).unwrap_or_else(|e| fail_return(&e));
            if q.actions.is_empty() {
                if json {
                    println!("{}", json!({"ok": true, "signed": 0, "remaining": 0}));
                } else {
                    println!("{} queue is empty", style::ok("ok"));
                }
                return;
            }
            let actor = crate::cli_identity::resolve_actor(actor.as_deref());
            let signing_key = crate::cli_identity::resolve_signing_key(key.as_deref());
            let mut signed_count = 0usize;
            let mut remaining = Vec::new();
            for action in q.actions.iter() {
                if !yes_to_all && !confirm_action(action) {
                    remaining.push(action.clone());
                    continue;
                }
                match sign_and_apply(&signing_key, &actor, action) {
                    Ok(report) => {
                        signed_count += 1;
                        if !json {
                            println!(
                                "{} {} on {}  →  {}",
                                style::ok("signed"),
                                action.kind,
                                action.frontier.display(),
                                report
                            );
                        }
                    }
                    Err(error) => {
                        // Keep failed actions in the queue so the user can retry.
                        remaining.push(action.clone());
                        if !json {
                            eprintln!(
                                "{} {} on {}: {error}",
                                style::warn("failed"),
                                action.kind,
                                action.frontier.display()
                            );
                        }
                    }
                }
            }
            queue::replace_actions(&path, remaining.clone()).unwrap_or_else(|e| fail_return(&e));
            if json {
                let payload = json!({
                    "ok": true,
                    "command": "queue.sign",
                    "signed": signed_count,
                    "remaining": remaining.len(),
                });
                print_json(&payload);
            } else {
                println!(
                    "{} signed {signed_count} action(s); {} remaining in queue",
                    style::ok("ok"),
                    remaining.len()
                );
            }
        }
    }
}

pub(crate) fn cmd_task(action: TaskAction) {
    match action {
        TaskAction::Create {
            frontier,
            task_type,
            objective,
            inputs,
            risk_class,
            blockers,
            acceptance_criteria,
            status,
            json,
        } => {
            let status = parse_task_status(&status);
            let task = frontier_task::create_task(
                &frontier,
                task_type,
                objective,
                inputs,
                risk_class,
                blockers,
                acceptance_criteria,
                status,
            )
            .unwrap_or_else(|e| fail_return(&format!("task create failed: {e}")));
            print_task(&task, json);
        }
        TaskAction::List {
            frontier,
            status,
            json,
        } => {
            let mut list = frontier_task::list_tasks(&frontier)
                .unwrap_or_else(|e| fail_return(&format!("task list failed: {e}")));
            if let Some(status) = status {
                let status = parse_task_status(&status);
                list.tasks.retain(|task| task.status == status);
                list.total = list.tasks.len();
            }
            if json {
                print_json(&list);
            } else if list.tasks.is_empty() {
                println!("{} no local frontier tasks", style::warn("task.list"));
            } else {
                println!(
                    "{} {} task(s) · {}",
                    style::ok("task.list"),
                    list.tasks.len(),
                    list.frontier_id
                );
                for task in &list.tasks {
                    println!(
                        "  {} {} {} · {}",
                        task.id, task.status, task.risk_class, task.objective
                    );
                }
            }
        }
        TaskAction::Show {
            frontier,
            task_id,
            json,
        } => {
            let task = frontier_task::load_task(&frontier, &task_id)
                .unwrap_or_else(|e| fail_return(&format!("task show failed: {e}")));
            print_task(&task, json);
        }
        TaskAction::Claim {
            frontier,
            task_id,
            reviewer,
            json,
        } => {
            let task = frontier_task::claim_task(&frontier, &task_id, reviewer)
                .unwrap_or_else(|e| fail_return(&format!("task claim failed: {e}")));
            print_task(&task, json);
        }
        TaskAction::Execute {
            frontier,
            task_id,
            actor,
            json,
        } => {
            let report = vela_edge::code_executor::execute_task(&frontier, &task_id, &actor)
                .unwrap_or_else(|e| fail_return(&format!("task execute failed: {e}")));
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                println!(
                    "· reproduction {} (exit {}) — {} proposal(s) pending review",
                    report.outcome,
                    report.exit_code,
                    report.proposal_ids.len()
                );
                for id in &report.proposal_ids {
                    println!("    {id}");
                }
            }
        }
        TaskAction::Close {
            frontier,
            task_id,
            status,
            reason,
            json,
        } => {
            let status = parse_task_status(&status);
            let task = frontier_task::close_task(&frontier, &task_id, status, reason)
                .unwrap_or_else(|e| fail_return(&format!("task close failed: {e}")));
            print_task(&task, json);
        }
        TaskAction::SetStatus {
            frontier,
            task_id,
            status,
            json,
        } => {
            let status = parse_task_status(&status);
            let task = frontier_task::set_task_status(&frontier, &task_id, status)
                .unwrap_or_else(|e| fail_return(&format!("task status failed: {e}")));
            print_task(&task, json);
        }
    }
}

// ── Finding-verb handlers (shared by the top-level alias + `vela finding`) ──
// Extracted so `vela note …` (hidden top-level) and `vela finding note …`
// (canonical) dispatch to one body.

pub(crate) fn cmd_finding_note(
    frontier: PathBuf,
    finding_id: String,
    text: String,
    author: String,
    apply: bool,
    json: bool,
) {
    let report = vela_protocol::state::add_note(&frontier, &finding_id, &text, &author, apply)
        .unwrap_or_else(|e| fail_return(&e));
    print_state_report(&report, json);
}

pub(crate) fn cmd_finding_caveat(
    frontier: PathBuf,
    finding_id: String,
    text: String,
    author: String,
    apply: bool,
    json: bool,
) {
    let report =
        vela_protocol::state::caveat_finding(&frontier, &finding_id, &text, &author, apply)
            .unwrap_or_else(|e| fail_return(&e));
    print_state_report(&report, json);
}

pub(crate) fn cmd_finding_revise(
    frontier: PathBuf,
    finding_id: String,
    confidence: f64,
    reason: String,
    reviewer: String,
    apply: bool,
    json: bool,
) {
    let report = vela_protocol::state::revise_confidence(
        &frontier,
        &finding_id,
        vela_protocol::state::ReviseOptions {
            confidence,
            reason,
            reviewer,
        },
        apply,
    )
    .unwrap_or_else(|e| fail_return(&e));
    print_state_report(&report, json);
}

pub(crate) fn cmd_finding_reject(
    frontier: PathBuf,
    finding_id: String,
    reason: String,
    reviewer: String,
    apply: bool,
    json: bool,
) {
    let report =
        vela_protocol::state::reject_finding(&frontier, &finding_id, &reviewer, &reason, apply)
            .unwrap_or_else(|e| fail_return(&e));
    print_state_report(&report, json);
}

pub(crate) fn cmd_finding_retract(
    source: PathBuf,
    finding_id: String,
    reason: String,
    reviewer: String,
    apply: bool,
    json: bool,
) {
    let report =
        vela_protocol::state::retract_finding(&source, &finding_id, &reviewer, &reason, apply)
            .unwrap_or_else(|e| fail_return(&e));
    print_state_report(&report, json);
}

/// `vela recommend` — a maintainer's signed "recommend accept" on a proposal,
/// consumed by owner/maintainer accepts. Moved verbatim from the run_command
/// dispatch (B7 inline-arm extraction; behavior-identical).
pub(crate) fn cmd_recommend(
    frontier: PathBuf,
    proposal_id: String,
    by: Option<String>,
    key: Option<PathBuf>,
    reason: String,
    json: bool,
) {
    let by = crate::cli_identity::resolve_actor(by.as_deref());
    let signing_key = crate::cli_identity::resolve_signing_key(key.as_deref());
    let mut project = repo::load_from_path(&frontier).unwrap_or_else(|e| fail_return(&e));
    if !project.proposals.iter().any(|p| p.id == proposal_id) {
        fail(&format!(
            "proposal {proposal_id} not found in {} — run `vela status {}` to list pending proposals, or check the frontier path",
            frontier.display(),
            frontier.display()
        ));
    }
    let target = project
        .proposals
        .iter()
        .find(|p| p.id == proposal_id)
        .map(|p| p.target.id.clone())
        .unwrap();
    let mut event = vela_protocol::events::new_finding_event(
        vela_protocol::events::FindingEventInput {
            kind: "proposal.recommended",
            finding_id: &target,
            actor_id: &by,
            actor_type: vela_protocol::events::actor_kind(&by),
            reason: &reason,
            before_hash: "sha256:null",
            after_hash: "sha256:null",
            payload: serde_json::json!({
                "proposal_id": proposal_id,
                "verdict": "recommend_accept",
            }),
            caveats: Vec::new(),
            timestamp: None,
        },
    );
    vela_protocol::reducer::apply_event(&mut project, &event)
        .unwrap_or_else(|e| fail_return(&e));
    event.signature = Some(
        vela_protocol::sign::sign_event(&event, &signing_key)
            .unwrap_or_else(|e| fail_return(&e)),
    );
    project.events.push(event);
    repo::save_to_path(&frontier, &project).unwrap_or_else(|e| fail_return(&e));
    let payload =
        json!({"ok": true, "command": "recommend", "proposal_id": proposal_id, "by": by});
    if json {
        print_json(&payload);
    } else {
        println!(
            "{} recommendation recorded on {proposal_id} (signed; consumed by owner/maintainer accepts)",
            style::ok("ok")
        );
    }
}

/// `vela claim` — lease an obligation finding for a bounded TTL (signed).
/// Moved verbatim from the run_command dispatch (B7 inline-arm extraction).
pub(crate) fn cmd_claim(
    frontier: PathBuf,
    obligation: String,
    ttl: u64,
    by: Option<String>,
    key: Option<PathBuf>,
    json: bool,
) {
    let by = crate::cli_identity::resolve_actor(by.as_deref());
    let signing_key = crate::cli_identity::resolve_signing_key(key.as_deref());
    let pubkey = hex::encode(signing_key.verifying_key().to_bytes());
    let mut project = repo::load_from_path(&frontier).unwrap_or_else(|e| fail_return(&e));
    if !project.findings.iter().any(|f| f.id == obligation) {
        fail(&format!("obligation finding {obligation} not found"));
    }
    let mut event = vela_protocol::events::new_finding_event(
        vela_protocol::events::FindingEventInput {
            kind: "attempt.claimed",
            finding_id: &obligation,
            actor_id: &by,
            actor_type: vela_protocol::events::actor_kind(&by),
            reason: "obligation lease",
            before_hash: "sha256:null",
            after_hash: "sha256:null",
            payload: serde_json::json!({
                "obligation_id": obligation,
                "lease_ttl_seconds": ttl,
                "claimant_actor": by,
                "claimant_pubkey": pubkey,
            }),
            caveats: Vec::new(),
            timestamp: None,
        },
    );
    vela_protocol::reducer::apply_event(&mut project, &event)
        .unwrap_or_else(|e| fail_return(&e));
    event.signature = Some(
        vela_protocol::sign::sign_event(&event, &signing_key)
            .unwrap_or_else(|e| fail_return(&e)),
    );
    project.events.push(event);
    repo::save_to_path(&frontier, &project).unwrap_or_else(|e| fail_return(&e));
    let payload = json!({
        "ok": true, "command": "claim", "obligation": obligation,
        "by": by, "ttl_seconds": ttl,
    });
    if json {
        print_json(&payload);
    } else {
        println!(
            "{} leased {obligation} to {by} for {ttl}s (signed)",
            style::ok("ok")
        );
    }
}

/// `vela register-statement` — timestamp a statement's priority (signed).
/// Moved verbatim from the run_command dispatch (B7 inline-arm extraction).
pub(crate) fn cmd_register_statement(
    frontier: PathBuf,
    statement_file: Option<PathBuf>,
    hash: Option<String>,
    informal_ref: String,
    finding: Option<String>,
    by: Option<String>,
    key: Option<PathBuf>,
    json: bool,
) {
    let by = crate::cli_identity::resolve_actor(by.as_deref());
    let signing_key = crate::cli_identity::resolve_signing_key(key.as_deref());
    let statement_hash = match (&statement_file, &hash) {
        (Some(p), _) => {
            use sha2::Digest;
            let bytes = std::fs::read(p)
                .unwrap_or_else(|e| fail_return(&format!("read {}: {e}", p.display())));
            hex::encode(sha2::Sha256::digest(&bytes))
        }
        (None, Some(h)) => h.trim().to_string(),
        (None, None) => fail_return("pass --statement-file or --hash"),
    };
    let mut project = repo::load_from_path(&frontier).unwrap_or_else(|e| fail_return(&e));
    // Gap 5: the optional finding-to-registration edge. When
    // `--finding` is given it must name a real finding; the
    // vf_ id lands inside the statement.registered payload (a
    // payload field on the existing kind, never a new kind)
    // and the event targets that finding.
    if let Some(vf) = &finding
        && !project.findings.iter().any(|f| &f.id == vf)
    {
        fail_return::<()>(&format!("--finding {vf} not found in this frontier"));
    }
    let target_id = finding.clone().unwrap_or_else(|| {
        project
            .findings
            .first()
            .map(|f| f.id.clone())
            .unwrap_or_else(|| "vf_genesis".to_string())
    });
    let mut payload = serde_json::json!({
        "statement_hash": statement_hash,
        "informal_ref": informal_ref,
    });
    if let Some(vf) = &finding {
        payload["finding_id"] = serde_json::json!(vf);
    }
    let mut event = vela_protocol::events::new_finding_event(
        vela_protocol::events::FindingEventInput {
            kind: "statement.registered",
            finding_id: &target_id,
            actor_id: &by,
            actor_type: vela_protocol::events::actor_kind(&by),
            reason: "statement priority registration",
            before_hash: "sha256:null",
            after_hash: "sha256:null",
            payload,
            caveats: Vec::new(),
            timestamp: None,
        },
    );
    vela_protocol::reducer::apply_event(&mut project, &event)
        .unwrap_or_else(|e| fail_return(&e));
    event.signature = Some(
        vela_protocol::sign::sign_event(&event, &signing_key)
            .unwrap_or_else(|e| fail_return(&e)),
    );
    project.events.push(event);
    repo::save_to_path(&frontier, &project).unwrap_or_else(|e| fail_return(&e));
    let payload = json!({
        "ok": true, "command": "register_statement",
        "statement_hash": statement_hash, "informal_ref": informal_ref,
        "finding_id": finding,
    });
    if json {
        print_json(&payload);
    } else {
        println!("{} registered statement {statement_hash}", style::ok("ok"));
    }
}

/// `vela attest-statement` — a reviewer's signed faithfulness verdict on a
/// finding's formalization. Moved verbatim from the run_command dispatch
/// (B7 inline-arm extraction; the attestation itself is pre-signed inside
/// `att`, so the wrapping event is not separately signed — unchanged).
#[allow(clippy::too_many_arguments)]
pub(crate) fn cmd_attest_statement(
    frontier: PathBuf,
    target: String,
    informal_ref: String,
    formal_ref: String,
    formal_file: Option<PathBuf>,
    formal_hash: Option<String>,
    verdict: String,
    note: String,
    by: Option<String>,
    key: Option<PathBuf>,
    json: bool,
) {
    use vela_protocol::statement_attestation::{
        AttestationDraft, FaithfulnessVerdict, StatementAttestation,
    };
    let by = crate::cli_identity::resolve_actor(by.as_deref());
    let signing_key = crate::cli_identity::resolve_signing_key(key.as_deref());
    let fh = match (&formal_file, &formal_hash) {
        (Some(p), _) => {
            use sha2::Digest;
            let bytes = std::fs::read(p).unwrap_or_else(|e| {
                fail_return(&format!("read formal file {}: {e}", p.display()))
            });
            hex::encode(sha2::Sha256::digest(&bytes))
        }
        (None, Some(h)) => h.trim().to_string(),
        (None, None) => fail_return("pass --formal-file or --formal-hash"),
    };
    let v = match verdict.as_str() {
        "faithful" => FaithfulnessVerdict::Faithful,
        "variant" => FaithfulnessVerdict::Variant,
        "unfaithful" => FaithfulnessVerdict::Unfaithful,
        other => fail_return(&format!(
            "verdict must be faithful|variant|unfaithful, got '{other}'"
        )),
    };
    let att = StatementAttestation::build(
        AttestationDraft {
            target: target.clone(),
            informal_ref,
            formal_ref,
            formal_statement_hash: fh,
            verdict: v,
            note,
            attested_by: by.clone(),
            attested_at: chrono::Utc::now().to_rfc3339(),
        },
        &signing_key,
    )
    .unwrap_or_else(|e| fail_return(&e));

    let mut project = repo::load_from_path(&frontier).unwrap_or_else(|e| fail_return(&e));
    if !project.findings.iter().any(|f| f.id == target) {
        fail(&format!("target finding {target} not found in frontier"));
    }
    let event = vela_protocol::events::new_finding_event(
        vela_protocol::events::FindingEventInput {
            kind: "statement.attested",
            finding_id: &target,
            actor_id: &by,
            actor_type: vela_protocol::events::actor_kind(&by),
            reason: "statement-faithfulness attestation",
            before_hash: "sha256:null",
            after_hash: "sha256:null",
            payload: serde_json::json!({ "attestation": att }),
            caveats: Vec::new(),
            timestamp: None,
        },
    );
    vela_protocol::reducer::apply_event(&mut project, &event)
        .unwrap_or_else(|e| fail_return(&e));
    project.events.push(event);
    repo::save_to_path(&frontier, &project).unwrap_or_else(|e| fail_return(&e));
    let payload = json!({
        "ok": true,
        "command": "attest_statement",
        "attestation_id": att.id,
        "target": target,
        "verdict": verdict,
        "attested_by": by,
    });
    if json {
        print_json(&payload);
    } else {
        println!(
            "{} statement attestation {} ({verdict}) recorded on {target}",
            style::ok("ok"),
            att.id
        );
    }
}
