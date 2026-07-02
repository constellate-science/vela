use crate::serve;
use vela_edge::frontier_health;
use vela_edge::lint;
use vela_edge::reviewer_identity;
use vela_edge::signals;
use vela_edge::state_integrity;
use vela_edge::validate;
use vela_protocol::bundle;
use vela_protocol::diff;
use vela_protocol::events;
use vela_protocol::evidence_ci;
use vela_protocol::frontier_repo;
use vela_protocol::project;
use vela_protocol::proposals;
use vela_protocol::repo;
use vela_protocol::sign;
use vela_protocol::sources;
use vela_protocol::state;

use std::path::{Path, PathBuf};

use clap::Parser;
use colored::Colorize;

use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use vela_protocol::cli_style as style;

#[derive(Parser)]
#[command(name = "vela", version)]
#[command(about = "Portable frontier state for science")]
struct Cli {
    /// Suppress hint/advice lines (VELA_ADVICE=0 does the same).
    #[arg(long, global = true)]
    quiet: bool,
    #[command(subcommand)]
    command: Commands,
}

pub(crate) use crate::cli_admin::*;
pub(crate) use crate::cli_check::*;
use crate::cli_commands::*;
pub(crate) use crate::cli_engine::*;
pub(crate) use crate::cli_finding::*;
pub(crate) use crate::cli_frontier::*;
pub(crate) use crate::cli_proof::*;
pub(crate) use crate::cli_read::*;
pub(crate) use crate::cli_registry::*;
pub(crate) use crate::cli_write::*;

mod frontier_audit;
mod json_edit;
mod session;
#[cfg(test)]
mod tests;
pub(crate) use frontier_audit::*;
pub(crate) use json_edit::*;
pub(crate) use session::*;

pub async fn run_command() {
    dotenvy::dotenv().ok();

    let cli = Cli::parse();
    crate::ui::set_quiet(cli.quiet);
    match cli.command {
        Commands::Check {
            source,
            schema,
            stats,
            evidence,
            conformance,
            conformance_dir,
            all,
            schema_only,
            strict,
            fix,
            json,
        } => {
            if evidence {
                // `check --evidence` folds in the standalone `evidence-ci` verb,
                // routing to the same handler. A source/frontier is required.
                let frontier = source.unwrap_or_else(|| {
                    fail_return("check --evidence needs a frontier path (e.g. `vela check <frontier> --evidence`)")
                });
                cmd_evidence_ci(&frontier, json);
            } else {
                cmd_check(
                    source.as_deref(),
                    schema,
                    stats,
                    conformance,
                    &conformance_dir,
                    all,
                    schema_only,
                    strict,
                    fix,
                    json,
                );
            }
        }
        Commands::Doctor {
            frontier,
            port,
            json,
        } => cmd_doctor(frontier.as_deref(), port, json),
        Commands::Proof {
            frontier,
            out,
            template,
            record_proof_state,
            json,
        } => cmd_proof(&frontier, &out, &template, record_proof_state, json),
        Commands::Serve {
            frontier,
            frontiers,
            backend,
            http,
            setup,
            check_tools,
            adoption,
            profile,
            json,
        } => {
            if setup {
                cmd_mcp_setup(frontier.as_deref(), frontiers.as_deref());
            } else if check_tools {
                let source =
                    serve::ProjectSource::from_args(frontier.as_deref(), frontiers.as_deref());
                match serve::check_tools(source, adoption) {
                    Ok(report) => {
                        if json {
                            print_json(&report);
                        } else {
                            print_tool_check_report(&report);
                        }
                    }
                    Err(e) => fail(&format!("Tool check failed: {e}")),
                }
            } else {
                let mcp_profile = vela_edge::tool_registry::McpProfile::parse(&profile)
                    .unwrap_or_else(|e| fail_return(&e));
                let source =
                    serve::ProjectSource::from_args(frontier.as_deref(), frontiers.as_deref());
                if let Some(port) = http {
                    serve::run_http(source, backend.as_deref(), port, mcp_profile).await;
                } else {
                    serve::run(source, backend.as_deref(), mcp_profile).await;
                }
            }
        }
        Commands::Status { frontier, json } => {
            cmd_status(&crate::ui::resolve_frontier(frontier), json)
        }
        Commands::Log {
            frontier,
            finding_id,
            limit,
            kind,
            as_of,
            json,
        } => {
            let (frontier, finding_id) =
                crate::ui::resolve_frontier_with_id(frontier, finding_id, &["vf_"]);
            if let Some(vf) = finding_id {
                let payload = state::history_as_of(&frontier, &vf, as_of.as_deref())
                    .unwrap_or_else(|e| fail_return(&e));
                if json {
                    print_json(&payload);
                } else {
                    print_history(&payload);
                }
            } else {
                cmd_log(&frontier, limit, kind.as_deref(), json);
            }
        }
        Commands::Inbox {
            frontier,
            kind,
            limit,
            json,
        } => cmd_inbox(
            &crate::ui::resolve_frontier(frontier),
            kind.as_deref(),
            limit,
            json,
        ),
        Commands::Gate { action } => cmd_gate(action),
        Commands::Agents { action } => crate::cli_agents::cmd_agents(action),
        Commands::Foundry { action } => crate::cli_engine::cmd_foundry(action),
        Commands::Completions { shell } => {
            use clap::CommandFactory;
            let mut cmd = Cli::command();
            let name = cmd.get_name().to_string();
            let shell_kind: clap_complete::Shell = match shell.as_str() {
                "bash" => clap_complete::Shell::Bash,
                "zsh" => clap_complete::Shell::Zsh,
                "fish" => clap_complete::Shell::Fish,
                other => fail_return(&format!(
                    "unsupported shell '{other}'. Valid: bash, zsh, fish"
                )),
            };
            clap_complete::generate(shell_kind, &mut cmd, name, &mut std::io::stdout());
        }

        Commands::Attach {
            frontier,
            target,
            attachment_file,
            proof,
            solver,
            verifier_actor,
            axioms_clean,
            undischarged_hypothesis,
            note,
            reviewer,
            reason,
            json,
        } => {
            // Proof mode: BUILD a lean_kernel attachment and land it (the
            // mode that used to live on the retired `attest --proof`).
            if proof {
                cmd_attach_lean_proof(
                    frontier,
                    target,
                    solver.unwrap_or_else(|| "lean4@4.29.1".to_string()),
                    verifier_actor.unwrap_or_else(|| {
                        fail_return("attach: --verifier-actor is required with --proof")
                    }),
                    axioms_clean,
                    undischarged_hypothesis,
                    note.unwrap_or_else(|| fail_return("attach: --note is required with --proof")),
                    None,
                    json,
                );
                return;
            }
            let attachment_file = attachment_file
                .unwrap_or_else(|| fail_return("attach: --attachment-file is required"));
            // Reviewer authority defaults from `vela id`.
            let reviewer = crate::cli_identity::resolve_actor(reviewer.as_deref());
            cmd_attach(
                &frontier,
                &target,
                &attachment_file,
                &reviewer,
                &reason,
                json,
            )
        }
        Commands::Reproduce { path, json } => cmd_reproduce(&path, json),
        Commands::Id { action } => cmd_id(action),
        Commands::Queue { action } => cmd_queue(action),
        Commands::Actor { action } => cmd_actor(action),
        Commands::Frontier { action } => cmd_frontier(action),
        Commands::Hub { action } => cmd_hub(action),
        Commands::Init {
            path,
            name,
            template,
            no_git,
            json,
        } => cmd_init(&path, &name, &template, !no_git, json),
        Commands::Diff {
            target,
            frontier_b,
            frontier,
            reviewer,
            json,
            quiet,
        } => {
            // v0.701: arg-order-insensitive. A `vpr_*` id in EITHER positional
            // routes to proposal preview; the other positional (or `--frontier`,
            // else `.`) is the frontier. So `vela diff <frontier> <vpr_>`,
            // `vela diff <vpr_> <frontier>`, and `vela diff <vpr_>` all work — no
            // more "Path does not exist" when the args are transposed.
            let first = target.clone();
            let vpr = if target.starts_with("vpr_") {
                Some(target.clone())
            } else if frontier_b.as_deref().is_some_and(|s| s.starts_with("vpr_")) {
                frontier_b.clone()
            } else {
                None
            };
            if let Some(target) = vpr {
                let frontier_root = frontier
                    .clone()
                    .or_else(|| {
                        // the positional that is NOT the proposal id, if any
                        if first.starts_with("vpr_") {
                            frontier_b.clone().map(std::path::PathBuf::from)
                        } else {
                            Some(std::path::PathBuf::from(&first))
                        }
                    })
                    .unwrap_or_else(|| std::path::PathBuf::from("."));
                let preview = proposals::preview_at_path(&frontier_root, &target, &reviewer)
                    .unwrap_or_else(|e| fail_return(&e));
                // The Engine's prospective read: what Evidence CI would say if
                // this proposal were accepted. Best-effort — a hiccup here must
                // never break the diff itself.
                let verdict = proposals::preview_engine_verdict(&frontier_root, &target).ok();
                let engine_json = verdict.as_ref().map(|v| {
                    json!({
                        "verdict": v.status,
                        "new_blocking": v.new_blocking,
                        "new_warnings": v.new_warnings,
                        "release_blocking_failed": v.release_blocking_failed,
                        "warnings": v.warnings,
                    })
                });
                let payload = json!({
                    "ok": true,
                    "command": "diff.proposal",
                    "frontier": frontier_root.display().to_string(),
                    "proposal_id": target,
                    "preview": preview,
                    "engine": engine_json,
                });
                if json {
                    print_json(&payload);
                } else {
                    // The reviewer's one-screen answer to "what would this
                    // change, and what does it actually SAY": the proposal's
                    // own text, the shape delta, the engine's prospective
                    // verdict with the warnings NAMED, and the decision verb.
                    let proposal = repo::load_from_path(&frontier_root).ok().and_then(|proj| {
                        let found = proj.proposals.iter().find(|p| p.id == target).cloned();
                        let pack = proj
                            .released_diff_packs
                            .iter()
                            .filter(|r| r.verdict.is_none())
                            .find(|r| r.member_proposals.iter().any(|m| m == &target))
                            .map(|r| r.pack_id.clone());
                        found.map(|p| (p, pack))
                    });
                    println!();
                    println!(
                        "  {}",
                        format!("VELA · DIFF · {target}").to_uppercase().dimmed()
                    );
                    println!("  {}", vela_protocol::cli_style::tick_row(60));
                    let pack_id = match &proposal {
                        Some((p, pack)) => {
                            println!("  kind:      {}   by {}", p.kind, p.actor.id);
                            let reason: String = p.reason.chars().take(90).collect();
                            if !reason.is_empty() {
                                println!("  reason:    {reason}");
                            }
                            if let Some(text) = p
                                .payload
                                .pointer("/finding/assertion/text")
                                .and_then(serde_json::Value::as_str)
                            {
                                println!("  proposes:  {}", wrap_line(text, 78));
                            }
                            pack.clone()
                        }
                        None => {
                            println!("  kind:      {}", preview.kind);
                            None
                        }
                    };
                    println!(
                        "  shape:     findings {} -> {} · events {} -> {} · artifacts {} -> {}",
                        preview.findings_before,
                        preview.findings_after,
                        preview.events_before,
                        preview.events_after,
                        preview.artifacts_before,
                        preview.artifacts_after,
                    );
                    if !preview.changed_findings.is_empty() {
                        println!("  changes:   {}", preview.changed_findings.join(", "));
                    }
                    if let Some(v) = &verdict {
                        match v.status.as_str() {
                            "pass" => println!("  engine:    evidence-ci clean if accepted"),
                            "warn" => {
                                println!(
                                    "  engine:    {} new review warning(s) if accepted",
                                    v.new_warnings.len()
                                );
                                for w in v.new_warnings.iter().take(5) {
                                    println!("    · {w}");
                                }
                                if v.new_warnings.len() > 5 {
                                    println!("    … +{} more", v.new_warnings.len() - 5);
                                }
                            }
                            "blocked" => {
                                println!(
                                    "  engine:    WOULD BLOCK — {} new release-blocking failure(s)",
                                    v.new_blocking.len()
                                );
                                for b in v.new_blocking.iter().take(5) {
                                    println!("    · {b}");
                                }
                            }
                            other => println!("  engine:    {other}"),
                        }
                    }
                    println!();
                    match pack_id {
                        Some(pack) => println!(
                            "  decide:    vela accept . --pack {pack}    (this proposal rides its pack)"
                        ),
                        None => println!(
                            "  decide:    vela accept . --id {target}    (or: vela proposals reject . {target} --reason \"…\")"
                        ),
                    }
                    println!();
                }
            } else {
                let b_str = frontier_b.unwrap_or_else(|| {
                    fail_return(
                        "diff: two-frontier mode needs a second positional (filesystem path or `vfr_*` id); for proposal preview pass a `vpr_*` id",
                    )
                });
                // v0.140: when either side is a `vfr_*` id, pull
                // the frontier through the registry into a temp
                // dir and run the diff against the pulled path.
                // The tempdir lives for the duration of the diff
                // and is reclaimed on drop.
                let _tmp = if target.starts_with("vfr_") || b_str.starts_with("vfr_") {
                    Some(
                        tempfile::Builder::new()
                            .prefix("vela-diff-")
                            .tempdir()
                            .unwrap_or_else(|e| {
                                fail_return(&format!("tempdir for vfr resolve: {e}"))
                            }),
                    )
                } else {
                    None
                };
                let resolve_side = |side: &str, _slot: &str| -> std::path::PathBuf {
                    if side.starts_with("vfr_") {
                        fail_return(
                            "diff by vfr_ id used the retired hub transport; `git clone` the \
                             frontier repo and pass its path instead",
                        )
                    } else {
                        std::path::PathBuf::from(side)
                    }
                };
                let frontier_a = resolve_side(&target, "a");
                let frontier_b_path = resolve_side(&b_str, "b");
                diff::run(&frontier_a, &frontier_b_path, json, quiet);
            }
        }
        Commands::Record {
            target,
            claim,
            r#type,
            artifacts,
            caveats,
            verifier_runs,
            actor,
            key,
            out,
            propose,
            json,
        } => cmd_record(
            &target,
            claim,
            r#type,
            artifacts,
            caveats,
            verifier_runs,
            actor,
            key,
            out,
            propose,
            json,
        ),
        Commands::Pack {
            frontier,
            pack_id,
            summary,
            from_pending,
            ids,
            aggregate_kind,
            actor,
            json,
        } => {
            let (frontier, pack_id) =
                crate::ui::resolve_frontier_with_id(frontier, pack_id, &["vsd_"]);
            crate::ui::set_mode("pack", json);
            cmd_pack(
                &frontier,
                pack_id,
                summary,
                from_pending,
                ids,
                aggregate_kind,
                actor,
                json,
            )
        }
        Commands::Proposals { action } => cmd_proposals(action),
        Commands::Finding { command } => match command {
            FindingCommands::Add {
                frontier,
                assertion,
                r#type,
                source,
                source_type,
                author,
                confidence,
                evidence_type,
                evidence_span,
                gap,
                negative_space,
                doi,
                year,
                url,
                source_authors,
                conditions_text,
                json,
                apply,
                replication_attestation,
            } => {
                validate_enum_arg("--type", &r#type, bundle::VALID_ASSERTION_TYPES);
                let replication_attestation = if let Some(p) = replication_attestation {
                    let raw = std::fs::read_to_string(&p).unwrap_or_else(|e| {
                        fail_return(&format!("--replication-attestation {}: {e}", p.display()))
                    });
                    Some(
                        serde_json::from_str::<serde_json::Value>(&raw).unwrap_or_else(|e| {
                            fail_return(&format!("--replication-attestation parse: {e}"))
                        }),
                    )
                } else {
                    None
                };
                validate_enum_arg(
                    "--evidence-type",
                    &evidence_type,
                    bundle::VALID_EVIDENCE_TYPES,
                );
                validate_enum_arg(
                    "--source-type",
                    &source_type,
                    bundle::VALID_PROVENANCE_SOURCE_TYPES,
                );
                let parsed_evidence_spans = parse_evidence_spans(&evidence_span);
                let parsed_source_authors = source_authors
                    .map(|s| {
                        s.split(';')
                            .map(|a| a.trim().to_string())
                            .filter(|a| !a.is_empty())
                            .collect()
                    })
                    .unwrap_or_default();
                let report = state::add_finding(
                    &frontier,
                    state::FindingDraftOptions {
                        text: assertion,
                        assertion_type: r#type,
                        source,
                        source_type,
                        author,
                        confidence,
                        evidence_type,
                        doi,
                        year,
                        url,
                        source_authors: parsed_source_authors,
                        conditions_text,
                        evidence_spans: parsed_evidence_spans,
                        gap,
                        negative_space,
                        replication_attestation,
                    },
                    apply,
                )
                .unwrap_or_else(|e| fail_return(&e));
                print_state_report(&report, json);
            }
            FindingCommands::Show {
                frontier,
                finding_id,
                json,
            } => cmd_finding_show(&frontier, &finding_id, json),
            FindingCommands::Supersede {
                frontier,
                old_id,
                assertion,
                r#type,
                source,
                source_type,
                author,
                reason,
                confidence,
                evidence_type,
                doi,
                year,
                url,
                source_authors,
                conditions_text,
                json,
                apply,
            } => {
                validate_enum_arg("--type", &r#type, bundle::VALID_ASSERTION_TYPES);
                validate_enum_arg(
                    "--evidence-type",
                    &evidence_type,
                    bundle::VALID_EVIDENCE_TYPES,
                );
                validate_enum_arg(
                    "--source-type",
                    &source_type,
                    bundle::VALID_PROVENANCE_SOURCE_TYPES,
                );
                let parsed_source_authors = source_authors
                    .map(|s| {
                        s.split(';')
                            .map(|a| a.trim().to_string())
                            .filter(|a| !a.is_empty())
                            .collect()
                    })
                    .unwrap_or_default();
                let report = state::supersede_finding(
                    &frontier,
                    &old_id,
                    &reason,
                    state::FindingDraftOptions {
                        text: assertion,
                        assertion_type: r#type,
                        source,
                        source_type,
                        author,
                        confidence,
                        evidence_type,
                        doi,
                        year,
                        url,
                        source_authors: parsed_source_authors,
                        conditions_text,
                        evidence_spans: Vec::new(),
                        gap: false,
                        negative_space: false,
                        replication_attestation: None,
                    },
                    apply,
                )
                .unwrap_or_else(|e| fail_return(&e));
                print_state_report(&report, json);
            }
            FindingCommands::Note {
                frontier,
                finding_id,
                text,
                author,
                apply,
                json,
            } => cmd_finding_note(frontier, finding_id, text, author, apply, json),
            FindingCommands::Caveat {
                frontier,
                finding_id,
                text,
                author,
                apply,
                json,
            } => cmd_finding_caveat(frontier, finding_id, text, author, apply, json),
            FindingCommands::Revise {
                frontier,
                finding_id,
                confidence,
                reason,
                reviewer,
                apply,
                json,
            } => cmd_finding_revise(
                frontier, finding_id, confidence, reason, reviewer, apply, json,
            ),
            FindingCommands::Reject {
                frontier,
                finding_id,
                reason,
                reviewer,
                apply,
                json,
            } => cmd_finding_reject(frontier, finding_id, reason, reviewer, apply, json),
            FindingCommands::Retract {
                source,
                finding_id,
                reason,
                reviewer,
                apply,
                json,
            } => cmd_finding_retract(source, finding_id, reason, reviewer, apply, json),
            FindingCommands::Link { action } => cmd_link(action),
        },

        // v0.74: alias verb dispatch. Each arm calls into an
        // existing canonical-event emission path.
        Commands::Propose {
            frontier,
            finding_id,
            status,
            reason,
            reviewer,
            apply,
            sign,
            key,
            co_author,
            generated_by,
            json,
        } => {
            // Reviewer and reason auto-resolve from managed identity / a sane
            // default, so the happy path is just
            // `vela propose <frontier> <vf> --status …`.
            let reviewer = crate::cli_identity::resolve_actor(reviewer.as_deref());
            let reason = reason.unwrap_or_else(|| format!("marked {status}"));
            if sign {
                // One-step solo path: record the proposal, then accept and sign
                // it under one key in a single command (the git-commit analogue).
                let options = state::ReviewOptions {
                    status: status.clone(),
                    reason: reason.clone(),
                    reviewer: reviewer.clone(),
                };
                let draft = state::review_finding(&frontier, &finding_id, options, false)
                    .unwrap_or_else(|e| fail_return(&e));
                let signing_key = crate::cli_identity::resolve_signing_key_opt(key.as_deref());
                let provenance = crate::cli_identity::resolve_co_author_provenance(
                    co_author.as_deref(),
                    generated_by.as_deref(),
                );
                let outcome = proposals::accept_at_path_engine(
                    &frontier,
                    &draft.proposal_id,
                    &reviewer,
                    &reason,
                    proposals::AcceptOptions {
                        strict: false,
                        force: false,
                        signing_key,
                        custody_verified: false,
                        provenance,
                    },
                )
                .unwrap_or_else(|e| fail_return(&e));
                print_json(&serde_json::json!({
                    "ok": true,
                    "command": "propose.sign",
                    "finding_id": finding_id,
                    "proposal_id": draft.proposal_id,
                    "event_id": outcome.event_id,
                    "signed": true,
                }));
                return;
            }
            let options = state::ReviewOptions {
                status: status.clone(),
                reason,
                reviewer,
            };
            let report = state::review_finding(&frontier, &finding_id, options, apply)
                .unwrap_or_else(|e| fail_return(&e));
            print_state_report(&report, json);
        }

        Commands::Accept {
            frontier,
            proposal_id,
            reviewer,
            reason,
            key,
            strict,
            force,
            co_author,
            generated_by,
            pack,
            all_pending,
            ids,
            kinds,
            limit,
            dry_run,
            no_reconcile,
            no_commit,
            no_push,
            json,
        } => {
            let (frontier, proposal_id) =
                crate::ui::resolve_frontier_with_id(frontier, proposal_id, &["vpr_"]);
            crate::ui::set_mode("accept", json);
            let publish_opts = crate::config::git_publish::PublishOptions::new(no_commit, no_push);
            // Pack mode: one decision for a whole changeset.
            if let Some(pack_id) = pack {
                let reviewer = crate::cli_identity::resolve_actor(reviewer.as_deref());
                let signing_key = crate::cli_identity::resolve_signing_key_opt(key.as_deref());
                let reason = reason
                    .clone()
                    .unwrap_or_else(|| format!("accepted pack {pack_id}"));
                let (report, verdict_event) =
                    vela_protocol::released_diff_pack::accept_pack_at_path(
                        &frontier,
                        &pack_id,
                        &reviewer,
                        &reason,
                        proposals::AcceptOptions {
                            strict,
                            force,
                            signing_key,
                            custody_verified: false,
                            provenance: crate::cli_identity::resolve_co_author_provenance(
                                co_author.as_deref(),
                                generated_by.as_deref(),
                            ),
                        },
                        dry_run,
                    )
                    .unwrap_or_else(|e| fail_return(&e));
                if json {
                    print_json(&json!({
                        "ok": report.failed.is_empty(),
                        "command": "accept",
                        "pack": pack_id,
                        "accepted": report.accepted_proposal_ids,
                        "failed": report.failed.len(),
                        "dry_run": report.dry_run,
                        "verdict_event": verdict_event,
                    }));
                } else {
                    println!(
                        "{} pack {pack_id}: {} member(s) accepted{}{}",
                        style::ok("ok"),
                        report.accepted_proposal_ids.len(),
                        if report.failed.is_empty() {
                            String::new()
                        } else {
                            format!(", {} FAILED", report.failed.len())
                        },
                        if report.dry_run { " (dry-run)" } else { "" }
                    );
                    if let Some(ev) = verdict_event {
                        println!("  verdict event: {ev}");
                    }
                }
                if !report.gated && !report.dry_run && !no_reconcile {
                    let _ = vela_protocol::frontier_repo::materialize(&frontier);
                }
                if !report.gated && !report.dry_run {
                    crate::config::git_publish::publish_decision(
                        &frontier,
                        &format!(
                            "accept: pack {pack_id} ({} member(s))",
                            report.accepted_proposal_ids.len()
                        ),
                        &report.accepted_proposal_ids,
                        &publish_opts,
                    );
                }
                return;
            }
            // Batch mode: every selected proposal in one signed pass
            if all_pending || !ids.is_empty() {
                let reason = reason
                    .clone()
                    .unwrap_or_else(|| "accepted via batch review".to_string());
                let reviewer = crate::cli_identity::resolve_actor(reviewer.as_deref());
                // Sign with the configured identity's key (managed-identity model):
                // key custody, not the typed name, is the accept authority.
                let signing_key = crate::cli_identity::resolve_signing_key_opt(None);
                if !all_pending && ids.is_empty() {
                    fail_return::<()>(
                        "accept-batch: pass --all-pending and/or one or more --id <proposal_id>",
                    );
                }
                // Resolve the selection by loading the frontier once for the id
                // list; the batch fn reloads, but resolving here keeps the
                // selection logic (pending filter, kind filter, limit) in one
                // place and lets --dry-run report the exact set.
                let loaded = repo::load_from_path(&frontier).unwrap_or_else(|e| fail_return(&e));
                let kind_filter: std::collections::BTreeSet<&str> =
                    kinds.iter().map(|s| s.as_str()).collect();
                let mut selected: Vec<String> = Vec::new();
                let mut seen: std::collections::BTreeSet<String> =
                    std::collections::BTreeSet::new();
                // Explicit ids first, in the order given.
                for id in &ids {
                    if seen.insert(id.clone()) {
                        selected.push(id.clone());
                    }
                }
                if all_pending {
                    for p in &loaded.proposals {
                        let pending = p.status == "pending_review" && p.applied_event_id.is_none();
                        let kind_ok =
                            kind_filter.is_empty() || kind_filter.contains(p.kind.as_str());
                        if pending && kind_ok && seen.insert(p.id.clone()) {
                            selected.push(p.id.clone());
                        }
                    }
                }
                if limit > 0 && selected.len() > limit {
                    selected.truncate(limit);
                }
                if selected.is_empty() {
                    fail_return::<()>("accept-batch: no proposals matched the selection");
                }

                let report = proposals::accept_batch_at_path(
                    &frontier,
                    &selected,
                    &reviewer,
                    &reason,
                    proposals::AcceptOptions {
                        strict,
                        force,
                        signing_key,
                        custody_verified: false,
                        provenance: crate::cli_identity::resolve_co_author_provenance(None, None),
                    },
                    dry_run,
                )
                .unwrap_or_else(|e| fail_return(&e));

                let v = &report.verdict;
                let payload = json!({
                    "ok": !report.gated,
                    "command": "accept-batch",
                    "frontier": frontier.display().to_string(),
                    "dry_run": report.dry_run,
                    "gated": report.gated,
                    "selected": selected.len(),
                    "accepted": report.accepted_proposal_ids.len(),
                    "already_applied": report.already_applied,
                    "failed": report.failed.iter().map(|(id, e)| json!({"id": id, "error": e})).collect::<Vec<_>>(),
                    "reviewer": reviewer,
                    "event_ids": report.event_ids,
                    "engine": {
                        "verdict": v.status,
                        "new_blocking": v.new_blocking,
                        "new_warnings": v.new_warnings,
                        "forced": v.forced,
                        "strict": v.strict,
                        "release_blocking_failed": v.release_blocking_failed,
                        "warnings": v.warnings,
                    },
                });
                if json {
                    print_json(&payload);
                } else if report.gated {
                    println!(
                        "{} Engine gate BLOCKED the batch of {} — nothing persisted",
                        style::lost("blocked"),
                        report.accepted_proposal_ids.len()
                    );
                    print_engine_verdict(v);
                    println!("  re-run with --force to override, or resolve the checks first");
                } else {
                    let verb = if report.dry_run {
                        "would accept"
                    } else {
                        "accepted"
                    };
                    println!(
                        "{} {} {} proposal(s) in one pass{}",
                        style::ok("ok"),
                        verb,
                        report.accepted_proposal_ids.len(),
                        if report.dry_run {
                            " (dry-run: nothing written)"
                        } else {
                            ""
                        }
                    );
                    if report.already_applied > 0 {
                        println!("  {} already applied (skipped)", report.already_applied);
                    }
                    if !report.failed.is_empty() {
                        println!("  {} failed:", report.failed.len());
                        for (id, e) in report.failed.iter().take(10) {
                            println!("    {id}: {e}");
                        }
                        if report.failed.len() > 10 {
                            println!("    … and {} more", report.failed.len() - 10);
                        }
                    }
                    print_engine_verdict(v);
                }
                // Reconcile derived views in the same pass, so the reviewer is not
                // left to run `vela proof` + `vela frontier materialize` by hand
                // after a batch accept. Skipped on dry-run / gated / --no-reconcile.
                if !report.gated && !report.dry_run && !no_reconcile {
                    let _ = vela_protocol::frontier_repo::materialize(&frontier);
                    if !json {
                        println!("  reconciled derived views (frontier.json, vela.lock, proof)");
                    }
                }
                if !report.gated && !report.dry_run {
                    crate::config::git_publish::publish_decision(
                        &frontier,
                        &format!(
                            "accept: {} proposal(s) in one signed pass",
                            report.accepted_proposal_ids.len()
                        ),
                        &report.event_ids,
                        &publish_opts,
                    );
                }
                return;
            }
            let proposal_id = proposal_id.unwrap_or_else(|| {
                fail_usage(
                    "accept: pass a vpr_… id, or --all-pending / --id for batch, or --pack vsd_… for a changeset",
                    "run `vela inbox .` first — it lists the pending vpr_/vsd_ ids and the exact accept command",
                )
            });
            let reviewer = crate::cli_identity::resolve_actor(reviewer.as_deref());
            let reason = reason.unwrap_or_else(|| "accepted via review".to_string());
            let signing_key = crate::cli_identity::resolve_signing_key_opt(key.as_deref());
            let provenance = crate::cli_identity::resolve_co_author_provenance(
                co_author.as_deref(),
                generated_by.as_deref(),
            );
            // The Engine runs Evidence CI on the post-accept state and gates
            // the acceptance on the regression it would introduce.
            let outcome = proposals::accept_at_path_engine(
                &frontier,
                &proposal_id,
                &reviewer,
                &reason,
                proposals::AcceptOptions {
                    strict,
                    force,
                    signing_key,
                    custody_verified: false,
                    provenance,
                },
            )
            .unwrap_or_else(|e| fail_return(&e));
            let v = &outcome.verdict;

            let payload = json!({
                "ok": true,
                "command": "accept",
                "frontier": frontier.display().to_string(),
                "proposal_id": proposal_id,
                "reviewer": reviewer,
                "applied_event_id": outcome.event_id,
                "engine": {
                    "verdict": v.status,
                    "new_blocking": v.new_blocking,
                    "new_warnings": v.new_warnings,
                    "forced": v.forced,
                    "strict": v.strict,
                    "release_blocking_failed": v.release_blocking_failed,
                    "warnings": v.warnings,
                },
            });
            if json {
                print_json(&payload);
            } else {
                println!(
                    "{} accepted and applied proposal {}",
                    style::ok("ok"),
                    proposal_id
                );
                println!("  event: {}", outcome.event_id);
                print_engine_verdict(v);
            }
            crate::config::git_publish::publish_decision(
                &frontier,
                &format!("accept: {proposal_id}"),
                std::slice::from_ref(&outcome.event_id),
                &publish_opts,
            );
        }

        Commands::Review {
            frontier,
            no_commit,
            no_push,
            target_id,
            scopes,
            reviewer,
            role,
            reason,
            orcid,
            ror,
            event,
            attester,
            scope_note,
            proof_id,
            signature,
            key,
            fidelity,
            informal_ref,
            formal_ref,
            formal_statement_hash,
            note,
            batch,
            json,
        } => {
            // Fidelity batch mode: sign a whole verdict file under one key
            // read and one save. Checked before the single --fidelity path.
            let (frontier, target_id) = crate::ui::resolve_frontier_with_id(
                frontier,
                target_id,
                &["vev_", "vsd_", "vrp_", "vpf_", "vf_"],
            );
            crate::ui::set_mode("review", json);
            let publish_opts = crate::config::git_publish::PublishOptions::new(no_commit, no_push);
            if let Some(batch) = batch {
                cmd_review_fidelity_batch(frontier.clone(), batch, reviewer, key, json);
                crate::config::git_publish::publish_decision(
                    &frontier,
                    "review: fidelity verdict batch",
                    &[],
                    &publish_opts,
                );
                return;
            }
            // Statement-fidelity mode: a signed `vsa_` human verdict on
            // whether the formal statement encodes the informal problem.
            // Keyed on --fidelity so the reviewer-identity and per-event
            // modes below are untouched.
            if let Some(fidelity) = fidelity {
                let target = target_id.clone().unwrap_or_else(|| {
                    fail_return("review: positional <finding-id> is required with --fidelity")
                });
                cmd_review_fidelity(
                    frontier.clone(),
                    target,
                    fidelity,
                    informal_ref.unwrap_or_else(|| {
                        fail_return("review: --informal-ref is required with --fidelity")
                    }),
                    formal_ref.unwrap_or_else(|| {
                        fail_return("review: --formal-ref is required with --fidelity")
                    }),
                    formal_statement_hash.unwrap_or_else(|| {
                        fail_return("review: --formal-statement-hash is required with --fidelity")
                    }),
                    note.unwrap_or_else(|| {
                        fail_return("review: --note is required with --fidelity")
                    }),
                    reviewer,
                    key,
                    json,
                );
                crate::config::git_publish::publish_decision(
                    &frontier,
                    "review: statement-fidelity verdict",
                    &[],
                    &publish_opts,
                );
                return;
            }
            if let Some(target_id) = target_id {
                let parsed_scopes = reviewer_identity::parse_scopes(&scopes)
                    .unwrap_or_else(|e| fail_return(&format!("review: {e}")));
                let reviewer = reviewer.unwrap_or_else(|| {
                    fail_return("review: --reviewer is required for target attestations")
                });
                let role = role.unwrap_or_else(|| {
                    fail_return("review: --role is required for target attestations")
                });
                let reason = reason.unwrap_or_else(|| {
                    fail_return("review: --reason is required for target attestations")
                });
                let report = reviewer_identity::record(
                    &frontier,
                    reviewer_identity::AttestationInput {
                        target_id,
                        scopes: parsed_scopes,
                        reviewer_id: reviewer,
                        role,
                        reason,
                        orcid,
                        ror,
                        proof_id,
                        signature,
                    },
                )
                .unwrap_or_else(|e| fail_return(&format!("attest failed: {e}")));
                if json {
                    print_json(&report);
                } else {
                    println!(
                        "{} {} -> {}",
                        style::ok("attest"),
                        report.attestation.attestation_id,
                        report.attestation.target_id
                    );
                    if let Some(event_id) = &report.attestation.canonical_event_id {
                        println!("  event: {}", event_id);
                    }
                    println!("  path: {}", report.path);
                }
                crate::config::git_publish::publish_decision(
                    &frontier,
                    &format!("review: attestation on {}", report.attestation.target_id),
                    report.attestation.canonical_event_id.clone().as_slice(),
                    &publish_opts,
                );
                return;
            }
            // v0.80.1: per-event mode. When --event is supplied,
            // emit an attestation.recorded canonical event
            // targeting the named event id.
            if let Some(target_event_id) = event {
                let attester_id = attester.unwrap_or_else(|| {
                    fail_return("attest: --attester is required in per-event mode")
                });
                let scope = scope_note.unwrap_or_else(|| {
                    fail_return("attest: --scope-note is required in per-event mode")
                });
                let attestation_event_id = state::record_attestation(
                    &frontier,
                    &target_event_id,
                    &attester_id,
                    &scope,
                    proof_id.as_deref(),
                    signature.as_deref(),
                )
                .unwrap_or_else(|e| fail_return(&e));
                if json {
                    let payload = json!({
                        "ok": true,
                        "command": "attest.event",
                        "frontier": frontier.display().to_string(),
                        "target_event_id": target_event_id,
                        "attestation_event_id": attestation_event_id,
                        "attester_id": attester_id,
                    });
                    print_json(&payload);
                } else {
                    println!(
                        "{} attested {} by {} ({})",
                        style::ok("ok"),
                        target_event_id,
                        attester_id,
                        attestation_event_id
                    );
                }
                return;
            }
            // v0.74 frontier-wide path: --key required.
            let key_path = key.unwrap_or_else(|| {
                fail_return(
                    "attest: --key is required in frontier-wide mode (or pass --event for per-event mode)",
                )
            });
            let count = sign::sign_registered_events(&frontier, &key_path)
                .unwrap_or_else(|e| fail_return(&e));
            let payload = json!({
                "ok": true,
                "command": "attest",
                "frontier": frontier.display().to_string(),
                "private_key": key_path.display().to_string(),
                "signed": count,
            });
            if json {
                print_json(&payload);
            } else {
                println!(
                    "{} {count} event(s) in {}",
                    style::ok("attested"),
                    frontier.display()
                );
            }
        }
    }
}

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

/// Shared success print for `vela id create` / `vela id import`: shows the
/// identity and the single line a maintainer runs to register it, so the
/// onboarding handoff is one copy-paste.
pub(crate) fn print_identity_created(identity: &crate::cli_identity::Identity, json: bool) {
    if json {
        print_json(&json!({
            "ok": true,
            "command": "id.create",
            "actor_id": identity.actor_id,
            "actor_type": identity.actor_type,
            "pubkey": identity.pubkey,
            "key_path": identity.key_path,
            "hub_url": identity.hub_url,
        }));
        return;
    }
    println!("{} identity · {}", style::ok("ready"), identity.actor_id);
    println!("  public key: {}", identity.pubkey);
    println!("  key file:   {}", identity.key_path);
    println!("  hub:        {}", identity.hub_url);
    println!();
    println!("Next: a maintainer registers you on a frontier with");
    println!(
        "  vela actor add <frontier> {} --pubkey {}",
        identity.actor_id, identity.pubkey
    );
    println!("Then `vela propose` and `vela accept` need no key flags.");
}

pub(crate) fn cmd_id_keygen(out: std::path::PathBuf, json: bool) {
    {
        {
            let public_key = sign::generate_keypair(&out).unwrap_or_else(|e| fail_return(&e));
            let payload = json!({
                "ok": true,
                "command": "id.keygen",
                "output_dir": out.display().to_string(),
                "public_key": public_key,
            });
            if json {
                print_json(&payload);
            } else {
                println!("{} keypair · {}", style::ok("generated"), out.display());
                println!("  public key: {public_key}");
            }
        }
    }
}

pub(crate) fn cmd_id_sign(
    frontier: std::path::PathBuf,
    key: Option<std::path::PathBuf>,
    json: bool,
) {
    {
        {
            let key_path =
                crate::cli_identity::resolve_key_path(key.as_deref()).unwrap_or_else(|| {
                    fail_return("no signing key: pass --key <path> or run `vela id create` once")
                });
            let count = sign::sign_registered_events(&frontier, &key_path)
                .unwrap_or_else(|e| fail_return(&e));
            let payload = json!({
                "ok": true,
                "command": "id.sign",
                "frontier": frontier.display().to_string(),
                "private_key": key_path.display().to_string(),
                "signed": count,
            });
            if json {
                print_json(&payload);
            } else {
                println!(
                    "{} {count} event(s) in {}",
                    style::ok("signed"),
                    frontier.display()
                );
            }
        }
    }
}

/// v0.146: derive the on-disk owner-epoch chain transcript path
/// for a given frontier. Sits at
/// `<frontier-dir>/.vela/governance/chain.json` regardless of
/// whether the input is a frontier file or a frontier directory.
pub(crate) fn governance_chain_path(frontier: &Path) -> PathBuf {
    let dir = if frontier.is_dir() {
        frontier.to_path_buf()
    } else if let Some(parent) = frontier.parent() {
        parent.to_path_buf()
    } else {
        PathBuf::from(".")
    };
    dir.join(".vela").join("governance").join("chain.json")
}

pub(crate) fn parse_signing_key(hex_str: &str) -> ed25519_dalek::SigningKey {
    let bytes = hex::decode(hex_str)
        .unwrap_or_else(|e| fail_return(&format!("invalid private-key hex: {e}")));
    let key_bytes: [u8; 32] = bytes
        .try_into()
        .unwrap_or_else(|_| fail_return("private key must be 32 bytes"));
    ed25519_dalek::SigningKey::from_bytes(&key_bytes)
}

pub(crate) fn confirm_action(action: &vela_edge::queue::QueuedAction) -> bool {
    use std::io::{self, BufRead, Write};
    let mut stdout = io::stdout().lock();
    let _ = writeln!(
        stdout,
        "  sign {} on {}? [y/N] ",
        action.kind,
        action.frontier.display()
    );
    let _ = stdout.flush();
    drop(stdout);
    let stdin = io::stdin();
    let mut line = String::new();
    if stdin.lock().read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim().to_lowercase().as_str(), "y" | "yes")
}

/// Sign and apply a queued action. Returns a short summary string on
/// success (the resulting `vpr_…` or `vev_…`). The action is signed
/// locally and applied via the same `proposals::*_at_path` functions the
/// CLI uses — no HTTP roundtrip required.
pub(crate) fn sign_and_apply(
    signing_key: &ed25519_dalek::SigningKey,
    actor: &str,
    action: &vela_edge::queue::QueuedAction,
) -> Result<String, String> {
    use vela_protocol::events::StateTarget;
    use vela_protocol::proposals;
    let args = &action.args;
    match action.kind.as_str() {
        "propose_review" | "propose_note" | "propose_revise_confidence" | "propose_retract" => {
            let kind = match action.kind.as_str() {
                "propose_review" => "finding.review",
                "propose_note" => "finding.note",
                "propose_revise_confidence" => "finding.confidence_revise",
                "propose_retract" => "finding.retract",
                _ => unreachable!(),
            };
            let target_id = args
                .get("target_finding_id")
                .and_then(Value::as_str)
                .ok_or("target_finding_id missing")?;
            let reason = args
                .get("reason")
                .and_then(Value::as_str)
                .ok_or("reason missing")?;
            let payload = match action.kind.as_str() {
                "propose_review" => {
                    let status = args
                        .get("status")
                        .and_then(Value::as_str)
                        .ok_or("status missing")?;
                    json!({"status": status})
                }
                "propose_note" => {
                    let text = args
                        .get("text")
                        .and_then(Value::as_str)
                        .ok_or("text missing")?;
                    json!({"text": text})
                }
                "propose_revise_confidence" => {
                    let new_score = args
                        .get("new_score")
                        .and_then(Value::as_f64)
                        .ok_or("new_score missing")?;
                    json!({"new_score": new_score})
                }
                "propose_retract" => json!({}),
                _ => unreachable!(),
            };
            let created_at = args
                .get("created_at")
                .and_then(Value::as_str)
                .map(String::from)
                .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
            let mut proposal = proposals::new_proposal(
                kind,
                StateTarget {
                    r#type: "finding".to_string(),
                    id: target_id.to_string(),
                },
                actor,
                "human",
                reason,
                payload,
                Vec::new(),
                Vec::new(),
            );
            proposal.created_at = created_at;
            proposal.id = proposals::proposal_id(&proposal);
            // Sign the proposal locally to validate parity with what the
            // server-side write tool would have signed; the queue-sign
            // path applies via the local file, not via HTTP.
            let _signature = vela_protocol::sign::sign_proposal(&proposal, signing_key)?;
            let result = proposals::create_or_apply(&action.frontier, proposal, false)
                .map_err(|e| format!("create_or_apply: {e}"))?;
            Ok(format!("proposal {}", result.proposal_id))
        }
        "accept_proposal" | "reject_proposal" => {
            let proposal_id = args
                .get("proposal_id")
                .and_then(Value::as_str)
                .ok_or("proposal_id missing")?;
            let reason = args
                .get("reason")
                .and_then(Value::as_str)
                .ok_or("reason missing")?;
            let timestamp = args
                .get("timestamp")
                .and_then(Value::as_str)
                .map(String::from)
                .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
            // Sign for parity; `accept_at_path`/`reject_at_path` apply locally.
            let preimage = json!({
                "action": if action.kind == "accept_proposal" { "accept" } else { "reject" },
                "proposal_id": proposal_id,
                "reviewer_id": actor,
                "reason": reason,
                "timestamp": timestamp,
            });
            let bytes = vela_protocol::canonical::to_canonical_bytes(&preimage)?;
            use ed25519_dalek::Signer;
            let _signature = hex::encode(signing_key.sign(&bytes).to_bytes());
            if action.kind == "accept_proposal" {
                let event_id = vela_protocol::proposals::accept_at_path_signed(
                    &action.frontier,
                    proposal_id,
                    actor,
                    reason,
                    Some(signing_key),
                )
                .map_err(|e| format!("accept_at_path: {e}"))?;
                Ok(format!("event {event_id}"))
            } else {
                vela_protocol::proposals::reject_at_path_signed(
                    &action.frontier,
                    proposal_id,
                    actor,
                    reason,
                    Some(signing_key),
                )
                .map_err(|e| format!("reject_at_path: {e}"))?;
                Ok(format!("rejected {proposal_id}"))
            }
        }
        other => Err(format!("unsupported queued action kind '{other}'")),
    }
}

/// v0.8: frontier-level metadata commands. Manages cross-frontier
/// dependency declarations on a frontier file. The substrate enforces
/// that any link target of the form `vf_…@vfr_…` references a declared
/// dependency; these commands edit the declaration list.
/// v0.9: typed link addition. Until v0.9 the only way to add a link
/// was to hand-edit JSON; this command is the CLI on-ramp. Links go
/// directly onto `findings[i].links` (links are not a state-changing
/// proposal kind in v0).
fn cmd_link(action: LinkAction) {
    use vela_protocol::bundle::{Link, LinkRef};
    match action {
        LinkAction::Add {
            frontier,
            from,
            to,
            r#type,
            note,
            inferred_by,
            no_check_target,
            json,
        } => {
            validate_enum_arg("--type", &r#type, bundle::VALID_LINK_TYPES);
            if !["compiler", "reviewer", "author"].contains(&inferred_by.as_str()) {
                fail(&format!(
                    "invalid --inferred-by '{inferred_by}'. Valid: compiler, reviewer, author"
                ));
            }
            let parsed = LinkRef::parse(&to).unwrap_or_else(|e| {
                fail(&format!(
                    "invalid --to '{to}': {e}. Expected vf_<hex> or vf_<hex>@vfr_<hex>"
                ))
            });
            let mut p = repo::load_from_path(&frontier).unwrap_or_else(|e| fail_return(&e));
            let source_idx = p
                .findings
                .iter()
                .position(|f| f.id == from)
                .unwrap_or_else(|| {
                    fail_return(&format!("--from finding '{from}' not in frontier"))
                });
            if let LinkRef::Local { vf_id } = &parsed
                && !p.findings.iter().any(|f| &f.id == vf_id)
            {
                fail(&format!(
                    "local --to target '{vf_id}' not in frontier; add the target finding first"
                ));
            }
            if let LinkRef::Cross { vfr_id, .. } = &parsed
                && p.dep_for_vfr(vfr_id).is_none()
            {
                fail(&format!(
                    "cross-frontier --to references vfr_id '{vfr_id}' but no matching dep is declared. Run `vela frontier add-dep {vfr_id} --locator <url> --snapshot <hash>` first."
                ));
            }

            // v0.16: best-effort cross-frontier target-status check. The
            // substrate doctrine is "client verifies on read", but at
            // link-add time it's worth a one-shot fetch to warn the user
            // if their target has been superseded. Failure to fetch is
            // a hint, not a hard error — the link still records.
            let mut target_warning: Option<String> = None;
            if let LinkRef::Cross {
                vfr_id: target_vfr,
                vf_id: target_vf,
            } = &parsed
                && !no_check_target
                && let Some(dep) = p.dep_for_vfr(target_vfr)
                && let Some(locator) = dep.locator.as_deref()
                && (locator.starts_with("http://") || locator.starts_with("https://"))
            {
                let client = reqwest::blocking::Client::builder()
                    .timeout(std::time::Duration::from_secs(15))
                    .build()
                    .ok();
                if let Some(client) = client
                    && let Ok(resp) = client.get(locator).send()
                    && resp.status().is_success()
                    && let Ok(dep_project) = resp.json::<vela_protocol::project::Project>()
                {
                    if let Some(target_finding) =
                        dep_project.findings.iter().find(|f| &f.id == target_vf)
                    {
                        if target_finding.flags.superseded {
                            target_warning = Some(format!(
                                "warn · cross-frontier target '{target_vf}' in '{target_vfr}' has flags.superseded = true. \
You may be linking to outdated wording. Inspect the supersedes chain to find the current finding. \
Use --no-check-target to skip this check."
                            ));
                        }
                    } else {
                        target_warning = Some(format!(
                            "warn · cross-frontier target '{target_vf}' not found in dep '{target_vfr}' (fetched from {locator}). \
The target may have been removed or never existed in the pinned snapshot."
                        ));
                    }
                }
            }

            let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
            let link = Link {
                target: to.clone(),
                link_type: r#type.clone(),
                note: note.clone(),
                inferred_by: inferred_by.clone(),
                created_at: now,
                mechanism: None,
            };
            p.findings[source_idx].links.push(link);
            project::recompute_stats(&mut p);
            repo::save_to_path(&frontier, &p).unwrap_or_else(|e| fail_return(&e));
            let payload = json!({
                "ok": true,
                "command": "link.add",
                "frontier": frontier.display().to_string(),
                "from": from,
                "to": to,
                "type": r#type,
                "cross_frontier": parsed.is_cross_frontier(),
            });
            if json {
                let mut p2 = payload.clone();
                if let Some(w) = &target_warning
                    && let serde_json::Value::Object(m) = &mut p2
                {
                    m.insert(
                        "target_warning".to_string(),
                        serde_json::Value::String(w.clone()),
                    );
                }
                print_json(&p2);
            } else {
                println!(
                    "{} {} --[{}]--> {}{}",
                    style::ok("link"),
                    from,
                    r#type,
                    to,
                    if parsed.is_cross_frontier() {
                        " (cross-frontier)"
                    } else {
                        ""
                    }
                );
                if let Some(w) = target_warning {
                    println!("  {w}");
                }
            }
        }
    }
}

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

/// v0.146: verify the owner-epoch chain transcript for a frontier.
pub(crate) fn cmd_verify_chain(frontier: PathBuf, artifacts: PathBuf, json: bool) {
    use vela_edge::governance::{
        ChainStatus, GovernancePolicy, OwnerEpochChain, OwnerRotateAttestationBundle,
        OwnerRotateProposal, verify_chain,
    };

    let chain_path = governance_chain_path(&frontier);
    if !chain_path.exists() {
        // Legacy entry (pre-v0.144): no chain file.
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "ok": true,
                    "command": "registry.verify-chain",
                    "frontier": frontier.display().to_string(),
                    "chain_status": "legacy",
                    "reason": format!("no chain file at {}", chain_path.display()),
                }))
                .expect("serialize legacy")
            );
        } else {
            println!(
                "{} chain status: legacy ({} not present)",
                style::ok("verify-chain"),
                chain_path.display()
            );
        }
        return;
    }

    let chain_raw = std::fs::read_to_string(&chain_path)
        .unwrap_or_else(|e| fail_return(&format!("read chain: {e}")));
    let chain: OwnerEpochChain = serde_json::from_str(&chain_raw)
        .unwrap_or_else(|e| fail_return(&format!("parse chain: {e}")));

    // Load artifacts up front so the closure-borrow stays simple.
    let mut policies: std::collections::HashMap<String, GovernancePolicy> =
        std::collections::HashMap::new();
    let mut proposals: std::collections::HashMap<String, OwnerRotateProposal> =
        std::collections::HashMap::new();
    let mut bundles: std::collections::HashMap<String, OwnerRotateAttestationBundle> =
        std::collections::HashMap::new();

    for transition in &chain.transitions {
        let policy_path = artifacts.join(format!("{}.json", transition.policy_id));
        let proposal_path = artifacts.join(format!("{}.json", transition.proposal_id));
        let bundle_path = artifacts.join(format!("{}.json", transition.bundle_id));

        if !policies.contains_key(&transition.policy_id) {
            let raw = std::fs::read_to_string(&policy_path).unwrap_or_else(|e| {
                fail_return(&format!("read policy {}: {e}", policy_path.display()))
            });
            let p: GovernancePolicy = serde_json::from_str(&raw)
                .unwrap_or_else(|e| fail_return(&format!("parse policy: {e}")));
            policies.insert(transition.policy_id.clone(), p);
        }
        if !proposals.contains_key(&transition.proposal_id) {
            let raw = std::fs::read_to_string(&proposal_path).unwrap_or_else(|e| {
                fail_return(&format!("read proposal {}: {e}", proposal_path.display()))
            });
            let p: OwnerRotateProposal = serde_json::from_str(&raw)
                .unwrap_or_else(|e| fail_return(&format!("parse proposal: {e}")));
            proposals.insert(transition.proposal_id.clone(), p);
        }
        if !bundles.contains_key(&transition.bundle_id) {
            let raw = std::fs::read_to_string(&bundle_path).unwrap_or_else(|e| {
                fail_return(&format!("read bundle {}: {e}", bundle_path.display()))
            });
            let b: OwnerRotateAttestationBundle = serde_json::from_str(&raw)
                .unwrap_or_else(|e| fail_return(&format!("parse bundle: {e}")));
            bundles.insert(transition.bundle_id.clone(), b);
        }
    }

    let frontier_data = repo::load_from_path(&frontier).unwrap_or_else(|e| fail_return(&e));
    let revocation = FrontierRevocation {
        map: frontier_data
            .actors
            .iter()
            .filter_map(|a| a.revoked_at.as_ref().map(|r| (a.id.clone(), r.clone())))
            .collect(),
    };
    let now = chrono::Utc::now().to_rfc3339();

    let status = verify_chain(&chain, &policies, &proposals, &bundles, &revocation, &now);

    let status_str = match status {
        ChainStatus::Bootstrap => "bootstrap",
        ChainStatus::Verified => "verified",
        ChainStatus::Legacy => "legacy",
        ChainStatus::Broken => "broken",
    };

    if json {
        let payload = json!({
            "ok": !matches!(status, ChainStatus::Broken),
            "command": "registry.verify-chain",
            "frontier": frontier.display().to_string(),
            "chain_status": status_str,
            "transition_count": chain.transitions.len(),
            "current_epoch": chain.transitions.last().map_or(0, |t| t.owner_epoch),
        });
        print_json(&payload);
    } else {
        println!(
            "{} chain status: {} ({} transition(s))",
            style::ok("verify-chain"),
            status_str,
            chain.transitions.len()
        );
        if let Some(t) = chain.transitions.last() {
            println!(
                "  current epoch: {}  policy: {}  bundle: {}",
                t.owner_epoch, t.policy_id, t.bundle_id
            );
        }
    }

    if matches!(status, ChainStatus::Broken) {
        std::process::exit(1);
    }
}

/// Revocation lookup backed by the frontier's actor records.
pub(crate) struct FrontierRevocation {
    pub(crate) map: std::collections::HashMap<String, String>,
}

impl vela_edge::governance::ActorRevocationLookup for FrontierRevocation {
    fn revoked_at(&self, actor_id: &str) -> Option<&str> {
        self.map.get(actor_id).map(String::as_str)
    }
}

/// Parse a witness file: either a bare `vela_verify::Witness`, or an
/// object with a `witness` field wrapping one (a record that ships its
/// construction).
pub(crate) fn parse_witness(raw: &str) -> Result<vela_verify::Witness, String> {
    if let Ok(w) = serde_json::from_str::<vela_verify::Witness>(raw) {
        return Ok(w);
    }
    let value: Value = serde_json::from_str(raw).map_err(|e| e.to_string())?;
    if let Some(inner) = value.get("witness") {
        return serde_json::from_value(inner.clone()).map_err(|e| e.to_string());
    }
    Err("not a witness (missing recognized `kind`, and no `witness` field)".to_string())
}

/// Collect witness files for `vela reproduce`: a single file, or every
/// `*.witness.json` under a directory (preferring a `witnesses/` subdir).
pub(crate) fn collect_witness_files(path: &Path) -> Vec<PathBuf> {
    if path.is_file() {
        return vec![path.to_path_buf()];
    }
    let root = {
        let sub = path.join("witnesses");
        if sub.is_dir() {
            sub
        } else {
            path.to_path_buf()
        }
    };
    let mut out = Vec::new();
    collect_witness_files_into(&root, &mut out);
    out.sort();
    out
}

fn collect_witness_files_into(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            collect_witness_files_into(&p, out);
        } else if p
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.ends_with(".witness.json"))
        {
            out.push(p);
        }
    }
}

/// `vela pack` — create or show a changeset. Creating bundles PENDING
/// proposals into one reviewable `vsd_` unit; showing renders members and
/// verdict state. Packing groups; a human key decides.
#[allow(clippy::too_many_arguments)]
pub(crate) fn cmd_pack(
    frontier: &Path,
    pack_id: Option<String>,
    summary: Option<String>,
    from_pending: bool,
    ids: Vec<String>,
    aggregate_kind: String,
    actor: Option<String>,
    json: bool,
) {
    // ── show mode ─────────────────────────────────────────────────────────
    if let Some(pid) = pack_id {
        let project = repo::load_from_path(frontier)
            .unwrap_or_else(|e| fail_return(&format!("load frontier: {e}")));
        let Some(rec) = project
            .released_diff_packs
            .iter()
            .find(|r| r.pack_id == pid)
        else {
            fail(&format!("pack {pid} not found"));
        };
        if json {
            print_json(&json!({
                "ok": true,
                "command": "pack.show",
                "pack": rec,
            }));
        } else {
            println!();
            println!(
                "  {}",
                format!("VELA · PACK · {pid}").to_uppercase().dimmed()
            );
            println!("  {}", vela_protocol::cli_style::tick_row(60));
            println!("  summary:  {}", rec.summary);
            println!(
                "  verdict:  {}",
                rec.verdict
                    .as_ref()
                    .map(|v| format!("{v:?}"))
                    .unwrap_or_else(|| "pending".to_string())
            );
            println!("  released: {}", rec.released_at);
            println!("  members ({}):", rec.member_proposals.len());
            for m in &rec.member_proposals {
                let (kind, text) = project
                    .proposals
                    .iter()
                    .find(|p| &p.id == m)
                    .map(|p| {
                        let text = p
                            .payload
                            .pointer("/finding/assertion/text")
                            .and_then(serde_json::Value::as_str)
                            .filter(|t| !t.is_empty())
                            .unwrap_or(&p.reason)
                            .chars()
                            .take(72)
                            .collect::<String>();
                        (p.kind.clone(), text)
                    })
                    .unwrap_or_default();
                println!("    · {m}  {kind:<13}  {text}");
            }
            if rec.verdict.is_none() {
                println!();
                println!(
                    "  decide:   vela accept . --pack {pid}    (preview a member: vela diff <vpr_id>)"
                );
            }
        }
        return;
    }

    // ── create mode ───────────────────────────────────────────────────────
    let summary =
        summary.unwrap_or_else(|| fail_return("pack: --summary is required to create a pack"));
    let members: Vec<String> = if from_pending {
        let project = repo::load_from_path(frontier)
            .unwrap_or_else(|e| fail_return(&format!("load frontier: {e}")));
        let in_undecided: std::collections::BTreeSet<String> = project
            .released_diff_packs
            .iter()
            .filter(|r| r.verdict.is_none())
            .flat_map(|r| r.member_proposals.iter().cloned())
            .collect();
        project
            .proposals
            .iter()
            .filter(|p| {
                p.status == "pending_review"
                    && p.applied_event_id.is_none()
                    && !in_undecided.contains(&p.id)
            })
            .map(|p| p.id.clone())
            .collect()
    } else {
        ids
    };
    let actor_id = crate::cli_identity::resolve_actor(actor.as_deref());
    let report = vela_protocol::released_diff_pack::release_pack_at_path(
        frontier,
        &summary,
        &aggregate_kind,
        &members,
        &actor_id,
    )
    .unwrap_or_else(|e| fail_return(&e));
    if json {
        print_json(&json!({
            "ok": true,
            "command": "pack",
            "pack_id": report.pack_id,
            "event_id": report.event_id,
            "members": report.members,
        }));
    } else {
        println!(
            "{} {} released ({} member(s)) — review with `vela pack {} {}` \
             and decide with `vela accept {} --pack {}`",
            style::ok("pack"),
            report.pack_id,
            report.members.len(),
            frontier.display(),
            report.pack_id,
            frontier.display(),
            report.pack_id,
        );
    }
}

/// `vela record` — the one-verb activity-record surface. A frontier dir
/// records; a vrc_ JSON file validates; `--propose <dir>` lands the
/// validated record as a PENDING proposal. Deciding stays with a human key.
#[allow(clippy::too_many_arguments)]
pub(crate) fn cmd_record(
    target: &Path,
    claim: Option<String>,
    assertion_type: String,
    artifacts: Vec<String>,
    caveats: Vec<String>,
    verifier_runs: Vec<String>,
    actor: Option<String>,
    key: Option<std::path::PathBuf>,
    out: Option<std::path::PathBuf>,
    propose: Option<std::path::PathBuf>,
    json: bool,
) {
    use vela_protocol::record::{
        ActivityRecord, ActivityRecordDraft, RecordArtifact, RecordVerifierRun,
    };

    fn hash_file(path: &std::path::Path) -> Result<String, String> {
        use sha2::{Digest, Sha256};
        let bytes = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        Ok(hex::encode(Sha256::digest(&bytes)))
    }

    // ── validate mode: the target is a vrc_ JSON file ─────────────────────
    if target.is_file() {
        let raw = std::fs::read_to_string(target)
            .unwrap_or_else(|e| fail_return(&format!("read {}: {e}", target.display())));
        let rc: ActivityRecord = serde_json::from_str(&raw)
            .unwrap_or_else(|e| fail_return(&format!("record parse: {e}")));
        let signed = rc.verify().unwrap_or_else(|e| fail_return(&e));
        // Locators are frontier-relative; the record usually lives in
        // <frontier>/records/. Try the propose target, the record's dir,
        // its parent (the frontier), then cwd.
        let mut roots: Vec<std::path::PathBuf> = Vec::new();
        if let Some(fr) = &propose {
            roots.push(fr.clone());
        }
        if let Some(dir) = target.parent() {
            roots.push(dir.to_path_buf());
            if let Some(up) = dir.parent() {
                roots.push(up.to_path_buf());
            }
        }
        roots.push(std::path::PathBuf::from("."));
        let mut missing = Vec::new();
        let mut mismatched = Vec::new();
        for atom in &rc.artifacts {
            let mut state = "missing";
            for root in &roots {
                match hash_file(&root.join(&atom.locator)) {
                    Ok(h) if h == atom.sha256 => {
                        state = "ok";
                        break;
                    }
                    Ok(_) => state = "mismatched",
                    Err(_) => {}
                }
            }
            match state {
                "ok" => {}
                "mismatched" => mismatched.push(atom.locator.clone()),
                _ => missing.push(atom.locator.clone()),
            }
        }
        let ok = missing.is_empty() && mismatched.is_empty();
        if !ok {
            for l in &missing {
                eprintln!("  missing artifact: {l}");
            }
            for l in &mismatched {
                eprintln!("  HASH MISMATCH: {l}");
            }
            fail("record validation failed");
        }
        // ── optional landing: --propose <frontier> ────────────────────────
        if let Some(frontier) = propose {
            let project = repo::load_from_path(&frontier)
                .unwrap_or_else(|e| fail_return(&format!("load frontier: {e}")));
            if project.frontier_id() != rc.frontier_id {
                fail(&format!(
                    "record is for {}, this frontier is {}",
                    rc.frontier_id,
                    project.frontier_id()
                ));
            }
            let head_now = vela_protocol::events::event_log_hash(&project.events);
            let staleness = if head_now == rc.against_head {
                "recorded against the current head".to_string()
            } else {
                format!(
                    "recorded against head {}…, current head {}… — review the delta",
                    &rc.against_head[..rc.against_head.len().min(16)],
                    &head_now[..head_now.len().min(16)]
                )
            };
            let report = state::add_finding(
                &frontier,
                rc.to_finding_draft(&staleness, signed),
                false, // NEVER applies: a record lands pending
            )
            .unwrap_or_else(|e| fail_return(&format!("record propose: {e}")));
            if json {
                print_json(&json!({
                    "ok": true,
                    "command": "record.propose",
                    "record": rc.id,
                    "proposal_id": report.proposal_id,
                    "status": report.proposal_status,
                    "signed": signed,
                }));
            } else {
                println!(
                    "{} {} landed as proposal {} ({}) — a human key decides from here",
                    style::ok("record"),
                    rc.id,
                    report.proposal_id,
                    report.proposal_status
                );
            }
            return;
        }
        if json {
            print_json(&json!({
                "ok": true,
                "command": "record.validate",
                "id": rc.id,
                "signed": signed,
                "artifacts_verified": rc.artifacts.len(),
            }));
        } else {
            println!(
                "{} {} valid ({} artifact(s) re-derived, {})",
                style::ok("record"),
                rc.id,
                rc.artifacts.len(),
                if signed { "signed" } else { "UNSIGNED" }
            );
        }
        return;
    }

    // ── record mode: the target is a frontier dir ─────────────────────────
    let claim = claim.unwrap_or_else(|| {
        fail_return("record mode needs --claim (or pass a vrc_ JSON file to validate)")
    });
    if artifacts.is_empty() {
        fail("record mode needs at least one --artifact <path[:kind]>");
    }
    if caveats.is_empty() {
        fail("record mode needs at least one --caveat (what this does NOT establish)");
    }
    let project = repo::load_from_path(target)
        .unwrap_or_else(|e| fail_return(&format!("load frontier: {e}")));
    let vfr = project.frontier_id();
    let head = vela_protocol::events::event_log_hash(&project.events);
    let mut atoms = Vec::new();
    for spec in &artifacts {
        let (path_str, kind) = match spec.rsplit_once(':') {
            Some((p, k)) if !k.contains('/') && !k.contains('\\') => (p.to_string(), k.to_string()),
            _ => (spec.clone(), "witness".to_string()),
        };
        let path = std::path::Path::new(&path_str);
        let sha =
            hash_file(path).unwrap_or_else(|e| fail_return(&format!("--artifact {spec}: {e}")));
        let locator = path
            .strip_prefix(target)
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| path_str.clone());
        atoms.push(RecordArtifact {
            kind,
            locator,
            sha256: sha,
            note: String::new(),
        });
    }
    let mut runs = Vec::new();
    for spec in &verifier_runs {
        let parts: Vec<&str> = spec.splitn(4, ':').collect();
        if parts.len() < 3 {
            fail(&format!(
                "--verifier-run must be method:outcome:logfile[:solver], got '{spec}'"
            ));
        }
        let output_hash = hash_file(std::path::Path::new(parts[2]))
            .unwrap_or_else(|e| fail_return(&format!("--verifier-run {spec}: {e}")));
        runs.push(RecordVerifierRun {
            method: parts[0].to_string(),
            outcome: parts[1].to_string(),
            output_hash,
            solver: parts.get(3).map(|s| s.to_string()).unwrap_or_default(),
        });
    }
    let emitted_by = crate::cli_identity::resolve_actor(actor.as_deref());
    // Custody: an agent-/ci-actor record NEVER auto-resolves the configured
    // (human) identity key. An agent signs only with a key passed
    // EXPLICITLY (its own); otherwise the record is honestly unsigned.
    let signing_key =
        if key.is_none() && (emitted_by.starts_with("agent:") || emitted_by.starts_with("ci:")) {
            None
        } else {
            crate::cli_identity::resolve_signing_key_opt(key.as_deref())
        };
    let record = ActivityRecord::build(
        ActivityRecordDraft {
            frontier_id: vfr,
            against_head: head,
            assertion: claim,
            assertion_type,
            artifacts: atoms,
            verifier_runs: runs,
            caveats,
            emitted_by,
            emitted_at: chrono::Utc::now().to_rfc3339(),
        },
        signing_key.as_ref(),
    )
    .unwrap_or_else(|e| fail_return(&e));
    let dest = out.unwrap_or_else(|| target.join("records").join(format!("{}.json", record.id)));
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .unwrap_or_else(|e| fail_return(&format!("mkdir {}: {e}", parent.display())));
    }
    std::fs::write(
        &dest,
        serde_json::to_string_pretty(&record).unwrap_or_else(|e| fail_return(&e.to_string())),
    )
    .unwrap_or_else(|e| fail_return(&format!("write {}: {e}", dest.display())));
    let signed = !record.signature.is_empty();
    if json {
        print_json(&json!({
            "ok": true,
            "command": "record",
            "id": record.id,
            "signed": signed,
            "frontier_id": record.frontier_id,
            "against_head": record.against_head,
            "artifacts": record.artifacts.len(),
            "wrote_to": dest.display().to_string(),
        }));
    } else {
        println!(
            "{} {} recorded ({} artifact(s), {}) -> {}",
            style::ok("record"),
            record.id,
            record.artifacts.len(),
            if signed { "signed" } else { "UNSIGNED" },
            dest.display()
        );
        if !signed {
            eprintln!(
                "  note: unsigned — valid to carry and propose; a reviewer sees signed=false"
            );
        }
    }
}

fn cmd_init(path: &Path, name: &str, template: &str, initialize_git: bool, json_output: bool) {
    if path.join(".vela").exists() {
        fail(&format!(
            "already initialized: {} exists",
            path.join(".vela").display()
        ));
    }
    let payload = frontier_repo::initialize(
        path,
        frontier_repo::InitOptions {
            name,
            template,
            initialize_git,
        },
    )
    .unwrap_or_else(|e| fail_return(&e));
    let hooks = scaffold_git_hooks(path);
    if json_output {
        print_json(&payload);
    } else {
        println!(
            "{} initialized frontier repository in {}",
            style::ok("ok"),
            path.display()
        );
        if hooks {
            println!("  git hooks installed (.vela/hooks): pre-push runs the strict check");
        }
    }
}

/// Versioned git hooks: local CI before the Action sees the push, and
/// derived views that can never lag the committed store. Written under
/// `.vela/hooks` (committed with the repo) and activated via
/// `core.hooksPath`; a clone re-activates with one config line, which
/// `vela doctor` suggests.
fn scaffold_git_hooks(path: &Path) -> bool {
    if !path.join(".git").exists() {
        return false;
    }
    let hooks_dir = path.join(".vela/hooks");
    if std::fs::create_dir_all(&hooks_dir).is_err() {
        return false;
    }
    let pre_commit = r#"#!/bin/sh
# vela pre-commit: the committed store must never lead its derived views
# (CI holds them to hash parity). If events are staged, re-materialize
# and stage the views alongside them.
if git diff --cached --name-only | grep -q "\.vela/events/"; then
  if command -v vela >/dev/null 2>&1; then
    root="$(git rev-parse --show-toplevel)"
    vela frontier materialize "$root" >/dev/null 2>&1 &&       git add "$root/frontier.json" "$root/vela.lock" "$root/proof" 2>/dev/null
  fi
fi
exit 0
"#;
    let pre_push = r#"#!/bin/sh
# vela pre-push: hold the push to the same strict bar CI will.
command -v vela >/dev/null 2>&1 || exit 0
root="$(git rev-parse --show-toplevel)"
if ! vela check "$root" --strict >/dev/null 2>&1; then
  echo "vela pre-push: strict check failed — push aborted."
  echo "  inspect: vela check $root --strict"
  echo "  bypass (CI will still refuse): git push --no-verify"
  exit 1
fi
exit 0
"#;
    let ok = std::fs::write(hooks_dir.join("pre-commit"), pre_commit).is_ok()
        && std::fs::write(hooks_dir.join("pre-push"), pre_push).is_ok();
    if !ok {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for name in ["pre-commit", "pre-push"] {
            let _ = std::fs::set_permissions(
                hooks_dir.join(name),
                std::fs::Permissions::from_mode(0o755),
            );
        }
    }
    std::process::Command::new("git")
        .arg("-C")
        .arg(path)
        .args(["config", "core.hooksPath", ".vela/hooks"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn cmd_mcp_setup(source: Option<&Path>, frontiers: Option<&Path>) {
    let source_desc = source
        .map(|p| p.display().to_string())
        .or_else(|| frontiers.map(|p| p.display().to_string()))
        .unwrap_or_else(|| "frontier.json".to_string());
    // Emit the read-only profile by default (memo §9.1): the safe MCP surface
    // an agent should get unless a human starts a scoped draft/maintainer
    // session. Matches the `.mcp.json` that `vela agents sync` generates.
    let args = if let Some(path) = source {
        format!(r#""serve", "{}", "--profile", "read-only""#, path.display())
    } else if let Some(path) = frontiers {
        format!(
            r#""serve", "--frontiers", "{}", "--profile", "read-only""#,
            path.display()
        )
    } else {
        r#""serve", "frontier.json", "--profile", "read-only""#.to_string()
    };
    println!(
        r#"Add this MCP server configuration to your client:

{{
  "mcpServers": {{
    "vela": {{
      "command": "vela",
      "args": [{args}]
    }}
  }}
}}

Source: {source_desc}"#
    );
}

pub(crate) fn parse_evidence_spans(inputs: &[String]) -> Vec<Value> {
    inputs
        .iter()
        .filter_map(|input| {
            let trimmed = input.trim();
            if trimmed.is_empty() {
                return None;
            }
            if trimmed.starts_with('{') {
                match serde_json::from_str::<Value>(trimmed) {
                    Ok(value @ Value::Object(_)) => return Some(value),
                    Ok(_) | Err(_) => {
                        eprintln!(
                            "{} evidence span JSON should be an object; storing as text",
                            style::warn("warn")
                        );
                    }
                }
            }
            Some(json!({
                "section": "curator_source",
                "text": trimmed,
            }))
        })
        .collect()
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

fn print_tool_check_report(report: &Value) {
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

#[derive(Debug, Serialize)]
pub struct ProofTrace {
    pub trace_version: String,
    pub command: Vec<String>,
    pub source: String,
    pub source_hash: String,
    pub schema_version: String,
    pub checked_artifacts: Vec<String>,
    pub benchmark: Option<Value>,
    pub packet_manifest: String,
    pub packet_validation: String,
    pub caveats: Vec<String>,
    pub status: String,
    pub trace_path: String,
}

// The strict v0.700 command surface. Every name here is a live clap
// subcommand in `cli_commands.rs::Commands` (plus the pre-clap
// intercepts: `help`, `version`, `proof verify|explain`,
// `claim state|trust|pack`). This list is the allowlist `run_from_args`
// consults before handing off to clap; it must advertise nothing the
// binary cannot run.
/// Commands intentionally withheld from the released surface. A DENY list,
/// not an ALLOW list: hiding a command here is safe (the worst case is a
/// real command stays unreachable until removed from the list), whereas the
/// old hand-maintained allowlist had the opposite, dangerous failure mode —
/// a NEW command silently 404'd ("unknown or non-release command") until
/// someone remembered to add its string. Empty today.
const RELEASE_DENY: &[&str] = &[];

/// Commands that stay fully callable + dispatchable but are curated OUT of the
/// `vela help advanced` menu (`strict_help_text`) to keep the presented surface
/// minimal and coherent. This is presentation only: every name here still
/// resolves through `is_science_subcommand`, so the gate scripts, the web app,
/// MCP/serve, and any existing invocation keep working unchanged. The
/// completeness guard (`every_subcommand_is_documented_in_advanced_help`) skips
/// these so the curated menu can shrink without losing the "no command is
/// silently undocumented" protection for the canonical set.
const DEPRECATED_FROM_HELP: &[&str] = &["queue", "completions"];

/// Whether `name` is a released top-level command the dispatcher will hand
/// to clap. Derived from the clap command tree (`Cli::command()`), not a
/// hand-maintained list, so a newly-added subcommand — or any of its
/// aliases — is accepted the instant it exists. `surface.rs`'s unit tests
/// pin this to the enum so the derivation can never silently drop a
/// command. (Pre-clap intercepts like `claim state` / `proof verify` are
/// matched in `run_from_args` before this gate, so they need no entry.)
/// The released top-level command names + aliases, derived once from the
/// clap tree and memoized. Building the full command tree is not free, so
/// caching keeps `is_science_subcommand` O(1) per dispatch instead of
/// rebuilding ~226 nodes every call.
fn released_command_names() -> &'static std::collections::HashSet<String> {
    use std::sync::OnceLock;
    static NAMES: OnceLock<std::collections::HashSet<String>> = OnceLock::new();
    NAMES.get_or_init(|| {
        use clap::CommandFactory;
        let mut set = std::collections::HashSet::new();
        for c in Cli::command().get_subcommands() {
            set.insert(c.get_name().to_string());
            for a in c.get_all_aliases() {
                set.insert(a.to_string());
            }
        }
        set
    })
}

pub fn is_science_subcommand(name: &str) -> bool {
    if RELEASE_DENY.contains(&name) {
        return false;
    }
    released_command_names().contains(name)
}

fn print_strict_help() {
    print!("{}", strict_help_text());
}

/// The curated, grouped command reference (`vela help advanced`). Kept
/// hand-curated for legibility — clap's flat alphabetical dump is worse UX —
/// but `mod surface_tests` asserts every released subcommand appears here,
/// so it can never silently omit a newly-added command (the drift the old
/// hand-maintained allowlist suffered, now caught at the help layer too).
fn strict_help_text() -> String {
    let deprecated_line = DEPRECATED_FROM_HELP.join(", ");
    format!(
        r#"Vela {}
Version control for scientific state.
Agents propose. Verifiers reproduce. Humans accept. Git publishes.

Usage:
  vela <COMMAND>

Setup (once):
  id            Your key + identity (create/show/import/keygen/sign); then no
                --key/--as flags. `id sign` re-signs your unsigned events.
  init          Initialize a new frontier repo (git-native: .vela is committed,
                CI gate + agent charter + MCP scaffolded)

The loop:
  status        One-screen frontier state
  inbox         Pending proposals awaiting a human key
  log           Recent signed events; `vela log <dir> <vf_>` = one finding's history
  diff          Two frontiers, or one pending proposal previewed
  record        Record activity into a portable claim packet (vrc_): claim +
                hashed artifacts + caveats; --propose lands it pending review
  propose       Draft the common finding.review proposal
  review        Signed human judgments: statement-fidelity verdicts (--fidelity,
                --batch) and role-scoped reviewer attestations
  accept        Apply proposals under your key; --all-pending/--id for the batch,
                --pack vsd_… for one atomic changeset decision
  pack          Bundle pending proposals into a changeset (vsd_) — the
                pull-request analogue; `vela pack . vsd_…` shows one
  proposals     The full proposal store: list/show/preview/import/validate/export/
                accept/reject
  attach        Bind mechanical verifier evidence (or --proof lean_kernel) to a finding

Verify:
  check         The full trust gate: replay, signatures, parity (--strict)
  reproduce     Re-verify stored witnesses from scratch (frozen verifiers)
  proof         Export a proof packet; `proof verify` re-checks one, `proof explain`
  gate          Claim-level verification gate (grade/check/vocab/backfill/auto-admit)

Publish (git push IS publication):
  hub           The index: register-git (bind repo->vfr once), witness-check,
                verify-chain, verify-log

Nouns (run `vela <noun> --help`):
  finding       The core primitive: add/show/supersede/note/caveat/revise/reject/retract/link
  frontier      Repo-level: new/materialize/add-dep/list-deps/diff/release/audit
  actor         Frontier-registered identities: add/list/rotate
  agents        VELA.md charter adapters: sync/doctor/diff
  serve         MCP + HTTP read surface (profiles: read-only/draft/maintainer)

Projections (read-only):
  state         Claim-state cell, trust vector, packs, evidence diff, anchors
  atlas         Cross-frontier math atlas projections
  policy        Governance policy: show/seal/test/evaluate
  doctor        First-user diagnosis of checkout/frontier/proof/serve
  foundry       The discovery/prover plane: run/targets/ablate, campaign,
                lean, attempt, transfer, experiment

Off-menu (reachable, intentionally undocumented here): {}
"#,
        env!("CARGO_PKG_VERSION"),
        deprecated_line,
    )
}

// Bare `vela` (no args) opens a session against the nearest `.vela/`
// repo, walking up from cwd. The session prints a one-screen
// dashboard, then accepts single-letter verb shortcuts or
// natural-language questions routed through `cmd_ask`.
//
// Doctrine: this is the daily-driver entry, not a kitchen-sink IDE.
// Single screen, no scroll, no full TUI redraw. Each verb spawns the
// existing kernel command and prints its output inline. The session
// stays out of the user's way: type something, get an answer, type
// again. OpenCode/Claude Code shape.

pub fn run_from_args() {
    style::init();
    let args = std::env::args().collect::<Vec<_>>();
    match args.get(1).map(String::as_str) {
        // v0.47: bare `vela` opens a session against the nearest
        // `.vela/` repo. The 30+ subcommand list is still there for
        // direct invocation; the session is the daily-driver entry.
        None => {
            run_session();
            return;
        }
        Some("-h" | "--help" | "help") => {
            // v0.47: top-level help shows the daily flow. The full
            // 30+ subcommand list lives behind `vela help advanced`.
            if args.get(2).map(String::as_str) == Some("advanced") {
                print_strict_help();
            } else {
                print_session_help();
            }
            return;
        }
        Some("-V" | "--version" | "version") => {
            println!("vela {}", env!("CARGO_PKG_VERSION"));
            return;
        }
        Some("policy") => {
            crate::cli_policy::run(&args);
            return;
        }
        Some("proof") if args.get(2).map(String::as_str) == Some("verify") => {
            let json = args.iter().any(|arg| arg == "--json");
            let frontier = args
                .iter()
                .skip(3)
                .find(|arg| !arg.starts_with('-'))
                .map(PathBuf::from)
                .inspect(|p| {
                    // An exported proof-packet DIR (has manifest.json but no
                    // .vela/) verifies via the packet validator — the path
                    // packets themselves stamp into their receipts.
                    if p.join("manifest.json").exists() && !p.join(".vela").is_dir() {
                        crate::cli_read::cmd_verify(p, json);
                        std::process::exit(0);
                    }
                })
                .unwrap_or_else(|| {
                    eprintln!(
                        "{} proof verify requires a frontier repo",
                        style::err_prefix()
                    );
                    std::process::exit(2);
                });
            cmd_proof_verify(&frontier, json);
            return;
        }
        Some("proof") if args.get(2).map(String::as_str) == Some("explain") => {
            let frontier = args
                .iter()
                .skip(3)
                .find(|arg| !arg.starts_with('-'))
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    eprintln!(
                        "{} proof explain requires a frontier repo",
                        style::err_prefix()
                    );
                    std::process::exit(2);
                });
            cmd_proof_explain(&frontier);
            return;
        }
        // The state projections: `vela state <frontier> [vf_]` (claim-state),
        // `vela state trust|pack|diff …` (trust vector, claim pack, Evidence
        // Diff), and the math-atlas anchor links `vela state
        // anchor|anchors|unanchor`. Intercepted ahead of the clap dispatcher
        // (mirroring `proof verify`). The internal parsers still speak the
        // historical `claim <mode>` argv shape, so the argv is rewritten:
        // bare `vela state X` becomes `claim state X`.
        Some("state") => {
            let mode = args.get(2).map(String::as_str);
            let mut rewritten: Vec<String> = vec![args[0].clone(), "claim".to_string()];
            match mode {
                Some("trust" | "pack" | "diff") => {
                    rewritten.extend(args[2..].iter().cloned());
                    crate::cli_claim::run(&rewritten);
                }
                Some("anchor" | "anchors" | "unanchor") => {
                    rewritten.extend(args[2..].iter().cloned());
                    crate::cli_claim::run_anchor(&rewritten);
                }
                _ => {
                    rewritten.push("state".to_string());
                    rewritten.extend(args[2..].iter().cloned());
                    crate::cli_claim::run(&rewritten);
                }
            }
            return;
        }
        // Math Atlas projection: `vela atlas <frontier>...`. Read-only,
        // cross-frontier; unions claims into cells by HardIdentity anchors.
        Some("atlas") => {
            crate::cli_atlas::run(&args);
            return;
        }
        Some(cmd) if !is_science_subcommand(cmd) => {
            eprintln!(
                "{} unknown or non-release command: {cmd}",
                style::err_prefix()
            );
            eprintln!("run `vela --help` for the strict v0 command surface.");
            std::process::exit(2);
        }
        Some(_) => {}
    }
    let runtime = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    runtime.block_on(run_command());
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
