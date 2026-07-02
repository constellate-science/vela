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

mod checks;
mod frontier_audit;
mod frontier_diff;
mod governance;
mod identity;
mod json_edit;
mod lifecycle;
mod links;
mod output;
mod records;
mod session;
mod surface;
#[cfg(test)]
mod tests;
pub(crate) use checks::*;
pub(crate) use frontier_audit::*;
pub(crate) use frontier_diff::*;
pub(crate) use governance::*;
pub(crate) use identity::*;
pub(crate) use json_edit::*;
pub(crate) use lifecycle::*;
pub(crate) use links::*;
pub(crate) use output::*;
pub(crate) use records::*;
pub(crate) use session::*;
pub(crate) use surface::*;
// Preserve the crate-public paths these two had when they lived in mod.rs.
pub use checks::scan_for_sensitive_paths;
pub use surface::is_science_subcommand;

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
                let reviewer = crate::cli_identity::resolve_decision_actor(reviewer.as_deref());
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
                let reviewer = crate::cli_identity::resolve_decision_actor(reviewer.as_deref());
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
            let reviewer = crate::cli_identity::resolve_decision_actor(reviewer.as_deref());
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
