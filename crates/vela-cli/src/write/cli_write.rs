use crate::cli::{confirm_action, print_state_report, sign_and_apply};
use crate::cli::{fail, fail_return, print_json};
use crate::cli_commands::*;
use colored::Colorize;
use serde_json::json;
use std::path::PathBuf;
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
    let mut event =
        vela_protocol::events::new_finding_event(vela_protocol::events::FindingEventInput {
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
        });
    vela_protocol::reducer::apply_event(&mut project, &event).unwrap_or_else(|e| fail_return(&e));
    event.signature = Some(
        vela_protocol::sign::sign_event(&event, &signing_key).unwrap_or_else(|e| fail_return(&e)),
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

/// `vela attest <frontier> <finding_id> --verdict ...`: write a signed
/// statement-faithfulness attestation (`vsa_`) — the human judgment that a
/// FORMAL statement faithfully encodes an INFORMAL problem. Reserved for
/// `reviewer:` actors by design: `StatementAttestation::build` refuses any
/// agent, so a model can PROPOSE a finding but never attest that a
/// formalization means what a human meant. Mirrors `cmd_claim`'s
/// load -> event -> apply -> sign -> save path; the reducer
/// (`apply_statement_attested`) re-verifies the attestation signature.
#[allow(clippy::too_many_arguments)]
pub(crate) fn cmd_attest_faithfulness(
    frontier: PathBuf,
    target: String,
    verdict: String,
    informal_ref: String,
    formal_ref: String,
    formal_statement_hash: String,
    note: String,
    reviewer: Option<String>,
    key: Option<PathBuf>,
    json: bool,
) {
    use vela_protocol::statement_attestation::{
        AttestationDraft, FaithfulnessVerdict, StatementAttestation,
    };
    let by = crate::cli_identity::resolve_actor(reviewer.as_deref());
    if !by.starts_with("reviewer:") {
        fail(&format!(
            "attest: statement faithfulness is human judgment by design; reviewer must be a reviewer: actor, got '{by}'"
        ));
    }
    let signing_key = crate::cli_identity::resolve_signing_key(key.as_deref());
    let verdict_enum = match verdict.to_ascii_lowercase().as_str() {
        "faithful" => FaithfulnessVerdict::Faithful,
        "variant" => FaithfulnessVerdict::Variant,
        "unfaithful" => FaithfulnessVerdict::Unfaithful,
        other => fail_return(&format!(
            "attest: --verdict must be faithful|variant|unfaithful, got '{other}'"
        )),
    };
    let mut project = repo::load_from_path(&frontier).unwrap_or_else(|e| fail_return(&e));
    if !project.findings.iter().any(|f| f.id == target) {
        fail(&format!(
            "attest: target finding {target} not found in frontier"
        ));
    }
    let att = StatementAttestation::build(
        AttestationDraft {
            target: target.clone(),
            informal_ref,
            formal_ref,
            formal_statement_hash,
            verdict: verdict_enum,
            note,
            attested_by: by.clone(),
            attested_at: chrono::Utc::now().to_rfc3339(),
        },
        &signing_key,
    )
    .unwrap_or_else(|e| fail_return(&format!("attest: {e}")));
    let attestation_id = att.id.clone();
    let mut event =
        vela_protocol::events::new_finding_event(vela_protocol::events::FindingEventInput {
            kind: "statement.attested",
            finding_id: &target,
            actor_id: &by,
            actor_type: vela_protocol::events::actor_kind(&by),
            reason: "statement faithfulness attestation",
            before_hash: "sha256:null",
            after_hash: "sha256:null",
            payload: serde_json::json!({ "attestation": att }),
            caveats: Vec::new(),
            timestamp: None,
        });
    vela_protocol::reducer::apply_event(&mut project, &event).unwrap_or_else(|e| fail_return(&e));
    event.signature = Some(
        vela_protocol::sign::sign_event(&event, &signing_key).unwrap_or_else(|e| fail_return(&e)),
    );
    project.events.push(event);
    repo::save_to_path(&frontier, &project).unwrap_or_else(|e| fail_return(&e));
    let payload = json!({
        "ok": true, "command": "attest.faithfulness",
        "attestation_id": attestation_id, "target": target,
        "verdict": verdict, "by": by,
    });
    if json {
        print_json(&payload);
    } else {
        println!(
            "{} attested {attestation_id} for {target} ({verdict}) by {by} (signed)",
            style::ok("ok"),
        );
    }
}

/// `vela attest <frontier> <finding_id> --proof ...`: attach a `lean_kernel`
/// CI verification to a proof finding. It records that the hosted Lean proof
/// compiled clean against its pinned toolchain (axiom footprint kernel-only),
/// as attested by CI, NOT an independent reproduction. A single such attachment
/// carries no `independent_of` and no adversarial probe, so it deliberately
/// fails the verifier gate's G1/G3: it reads "attested by CI", never "verified".
/// Drafts a `verifier.attach` proposal exactly like `vela attach`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn cmd_attest_proof(
    frontier: PathBuf,
    target: String,
    solver: String,
    verifier_actor: String,
    axioms_clean: bool,
    note: String,
    reviewer: Option<String>,
    json: bool,
) {
    use vela_protocol::verifier_attachment::{
        claim_digest, AttachmentDraft, AttachmentOutcome, MatchToClaim, MethodIntegrity,
        VerifierAttachment, VerifierMethod,
    };
    let reviewer = crate::cli_identity::resolve_actor(reviewer.as_deref());
    let project = repo::load_from_path(&frontier).unwrap_or_else(|e| fail_return(&e));
    let claim = match project.findings.iter().find(|f| f.id == target) {
        Some(f) => f.assertion.text.clone(),
        None => fail_return(&format!("attest: target finding {target} not found in frontier")),
    };
    let integrity = if axioms_clean {
        MethodIntegrity::Sound
    } else {
        MethodIntegrity::Compromised
    };
    let att = VerifierAttachment::build(AttachmentDraft {
        target: target.clone(),
        claim_digest: claim_digest(&claim),
        verifier_method: VerifierMethod::LeanKernel,
        solver_id: solver,
        independent_of: Vec::new(),
        match_to_claim: MatchToClaim {
            matches: true,
            checker_actor: verifier_actor.clone(),
        },
        adversarial_probes: Vec::new(),
        outcome: AttachmentOutcome::Passed,
        verifier_actor,
        note,
    })
    .and_then(|a| a.with_method_integrity(integrity))
    .unwrap_or_else(|e| fail_return(&format!("attest: {e}")));
    let attachment_id = att.id.clone();
    let att_value = serde_json::to_value(&att)
        .unwrap_or_else(|e| fail_return(&format!("serialize attachment: {e}")));
    let actor_type = if reviewer.starts_with("agent:") {
        "agent"
    } else {
        "human"
    };
    let proposal = vela_protocol::proposals::new_proposal(
        "verifier.attach",
        vela_protocol::events::StateTarget {
            r#type: "finding".to_string(),
            id: target.clone(),
        },
        reviewer,
        actor_type,
        "lean_kernel CI attestation",
        serde_json::json!({ "attachment": att_value }),
        Vec::new(),
        Vec::new(),
    );
    let result = vela_protocol::proposals::create_or_apply(&frontier, proposal, true)
        .unwrap_or_else(|e| fail_return(&e));
    let applied = result.applied_event_id.is_some();
    let payload = json!({
        "ok": true, "command": "attest.proof",
        "attachment_id": attachment_id, "target": target,
        "method": "lean_kernel", "integrity": integrity.as_str(),
        "proposal_id": result.proposal_id, "applied": applied,
    });
    if json {
        print_json(&payload);
    } else {
        println!(
            "{} attached {attachment_id} (lean_kernel, {}) to {target}\n  proposal {}{}",
            style::ok("ok"),
            integrity.as_str(),
            result.proposal_id,
            if applied {
                " (applied)"
            } else {
                " (pending, run vela accept)"
            },
        );
    }
}
