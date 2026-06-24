use crate::serve;
use vela_edge::frontier_health;
use vela_edge::frontier_task;
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
    #[command(subcommand)]
    command: Commands,
}

pub(crate) use crate::cli_admin::*;
pub(crate) use crate::cli_check::*;
use crate::cli_commands::*;
pub(crate) use crate::cli_engine::*;
pub(crate) use crate::cli_finding::*;
pub(crate) use crate::cli_frontier::*;
pub(crate) use crate::cli_lean::*;
pub(crate) use crate::cli_proof::*;
pub(crate) use crate::cli_read::*;
pub(crate) use crate::cli_registry::*;
pub(crate) use crate::cli_source_fetch::*;
pub(crate) use crate::cli_write::*;

pub async fn run_command() {
    dotenvy::dotenv().ok();

    match Cli::parse().command {
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
        Commands::Normalize {
            source,
            out,
            write,
            dry_run,
            rewrite_ids,
            id_map,
            resync_provenance,
            json,
        } => cmd_normalize(
            &source,
            out.as_deref(),
            write,
            dry_run,
            rewrite_ids,
            id_map.as_deref(),
            resync_provenance,
            json,
        ),
        Commands::Proof {
            frontier,
            out,
            template,
            gold,
            record_proof_state,
            json,
        } => cmd_proof(
            &frontier,
            &out,
            &template,
            gold.as_deref(),
            record_proof_state,
            json,
        ),
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
        Commands::Status {
            frontier,
            remote,
            json,
        } => cmd_status(&frontier, json, remote),
        Commands::Log {
            frontier,
            limit,
            kind,
            json,
        } => cmd_log(&frontier, limit, kind.as_deref(), json),
        Commands::Inbox {
            frontier,
            kind,
            limit,
            json,
        } => cmd_inbox(&frontier, kind.as_deref(), limit, json),
        Commands::Verify { path, json } => cmd_verify(&path, json),
        Commands::Gate { action } => cmd_gate(action),
        Commands::Agents { action } => crate::cli_agents::cmd_agents(action),
        Commands::Campaign { action } => crate::cli_campaign::cmd_campaign(action),
        Commands::Foundry { action } => crate::cli_engine::cmd_foundry(action),
        Commands::Experiment { action } => crate::cli_experiment::cmd_experiment(action),
        Commands::Attack {
            frontier,
            top,
            json,
        } => crate::cli_atlas::run_attack(&frontier, top, json),
        Commands::Explore {
            frontier,
            finding,
            hops,
            json,
        } => crate::cli_atlas::run_explore(&frontier, &finding, hops, json),

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

        Commands::Claim {
            frontier,
            obligation,
            ttl,
            by,
            key,
            json,
        } => cmd_claim(frontier, obligation, ttl, by, key, json),

        Commands::Attach {
            frontier,
            target,
            attachment_file,
            reviewer,
            reason,
            json,
        } => {
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
        Commands::Sign { action } => cmd_sign(action),
        Commands::Id { action } => cmd_id(action),
        Commands::Publish {
            frontier,
            to,
            license,
            json,
        } => {
            // The friendly "share my work" verb: a full publish to the
            // identity hub, with owner+key resolved from the profile inside
            // the registry handler. Full (not delta) so it always succeeds.
            let hub = crate::cli_identity::resolve_hub(to.as_deref());
            cmd_registry(RegistryAction::Publish {
                frontier,
                owner: None,
                key: None,
                locator: None,
                to: Some(hub),
                license,
                json,
            });
        }
        Commands::Clone {
            target,
            dest,
            from,
            blobs_from,
            json,
        } => {
            let hub = crate::cli_identity::resolve_hub(from.as_deref());
            crate::cli_registry::cmd_clone(&target, dest, &hub, blobs_from.as_deref(), json);
        }
        Commands::Actor { action } => cmd_actor(action),
        Commands::Frontier { action } => cmd_frontier(action),
        Commands::Queue { action } => cmd_queue(action),
        Commands::Registry { action } => cmd_registry(action),
        Commands::Pull {
            frontier,
            from,
            json,
        } => {
            let hub = crate::cli_identity::resolve_hub(from.as_deref());
            crate::cli_registry::cmd_pull(&frontier, &hub, json);
        }
        Commands::Workspace { action } => crate::cli_registry::cmd_workspace(action),
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
            from,
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
                    println!("vela diff · proposal preview");
                    println!("  proposal: {}", target);
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
                    if let Some(v) = &verdict {
                        match v.status.as_str() {
                            "pass" => println!("  engine: evidence-ci clean if accepted"),
                            "warn" => println!(
                                "  engine: {} new review warning(s) if accepted",
                                v.new_warnings.len()
                            ),
                            "blocked" => println!(
                                "  engine: WOULD BLOCK — {} new release-blocking failure(s)",
                                v.new_blocking.len()
                            ),
                            other => println!("  engine: {other}"),
                        }
                    }
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
                let resolve_side = |side: &str, slot: &str| -> std::path::PathBuf {
                    if side.starts_with("vfr_") {
                        let tmp = _tmp.as_ref().expect("tempdir initialized above");
                        let dest = tmp.path().join(format!("{slot}-{side}.json"));
                        resolve_vfr_to_path(side, from.as_deref(), &dest)
                            .unwrap_or_else(|e| fail_return(&e));
                        dest
                    } else {
                        std::path::PathBuf::from(side)
                    }
                };
                let frontier_a = resolve_side(&target, "a");
                let frontier_b_path = resolve_side(&b_str, "b");
                diff::run(&frontier_a, &frontier_b_path, json, quiet);
            }
        }
        Commands::Proposals { action } => cmd_proposals(action),
        Commands::Lean { action } => cmd_lean(action),
        Commands::Attempt { action } => crate::cli_lean::cmd_attempt(action),
        Commands::Transfer { action } => crate::cli_lean::cmd_transfer(action),
        Commands::Task { action } => cmd_task(action),
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
            FindingCommands::CausalSet {
                frontier,
                finding_id,
                claim,
                grade,
                actor,
                reason,
                json,
            } => {
                if !bundle::VALID_CAUSAL_CLAIMS.contains(&claim.as_str()) {
                    fail(&format!(
                        "invalid --claim '{claim}'; valid: {:?}",
                        bundle::VALID_CAUSAL_CLAIMS
                    ));
                }
                if let Some(g) = grade.as_deref()
                    && !bundle::VALID_CAUSAL_EVIDENCE_GRADES.contains(&g)
                {
                    fail(&format!(
                        "invalid --grade '{g}'; valid: {:?}",
                        bundle::VALID_CAUSAL_EVIDENCE_GRADES
                    ));
                }
                let report = state::set_causal(
                    &frontier,
                    &finding_id,
                    &claim,
                    grade.as_deref(),
                    &actor,
                    &reason,
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
        Commands::History {
            frontier,
            finding_id,
            json,
            as_of,
        } => {
            let payload = state::history_as_of(&frontier, &finding_id, as_of.as_deref())
                .unwrap_or_else(|e| fail_return(&e));
            if json {
                print_json(&payload);
            } else {
                print_history(&payload);
            }
        }

        // v0.74: alias verb dispatch. Each arm calls into an
        // existing canonical-event emission path.
        Commands::Ingest {
            path,
            frontier,
            backend,
            actor,
            dry_run,
            json,
        } => {
            cmd_ingest(
                &path,
                &frontier,
                backend.as_deref(),
                actor.as_deref(),
                dry_run,
                json,
            )
            .await
        }

        Commands::Propose {
            frontier,
            finding_id,
            status,
            reason,
            reviewer,
            apply,
            json,
        } => {
            // Mirror the existing `Commands::Review` arm: emit a
            // finding.review proposal under reviewer authority. Reviewer and
            // reason auto-resolve from managed identity / a sane default, so
            // the happy path is just `vela propose <frontier> <vf> --status …`.
            let reviewer = crate::cli_identity::resolve_actor(reviewer.as_deref());
            let reason = reason.unwrap_or_else(|| format!("marked {status}"));
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
            push,
            to,
            json,
        } => {
            let reviewer = crate::cli_identity::resolve_actor(reviewer.as_deref());
            let reason = reason.unwrap_or_else(|| "accepted via review".to_string());
            let signing_key = crate::cli_identity::resolve_signing_key_opt(key.as_deref());
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
                },
            )
            .unwrap_or_else(|e| fail_return(&e));
            let v = &outcome.verdict;

            // P3.4: after applying the accept locally, optionally deliver the
            // same human signature to the hub. Best-effort — a hub failure
            // never unwinds the local accept (which is already on disk).
            let mut hub_result = serde_json::Value::Null;
            if push || to.is_some() {
                hub_result = deliver_accept_to_hub(
                    &frontier,
                    &proposal_id,
                    &reviewer,
                    &reason,
                    key.as_deref(),
                    to.as_deref(),
                    json,
                );
            }

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
                "hub": hub_result,
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
        }

        Commands::Land {
            frontier,
            target,
            reason,
            reviewer,
            key,
            json,
        } => {
            // Resolve the target to a pending proposal id. A `vpr_` is taken as
            // the proposal directly; a `vf_` finding id resolves to its pending
            // finding.add proposal (the one-step "land this finding" ergonomic).
            let proposal_id = if target.starts_with("vpr_") {
                target.clone()
            } else {
                let source = repo::detect(&frontier).unwrap_or_else(|e| fail_return(&e));
                let proj = repo::load(&source).unwrap_or_else(|e| fail_return(&e));
                proj.proposals
                    .iter()
                    .find(|p| {
                        p.applied_event_id.is_none()
                            && p.kind == "finding.add"
                            && p.target.id == target
                    })
                    .map(|p| p.id.clone())
                    .unwrap_or_else(|| {
                        fail_return(&format!(
                            "no pending finding.add proposal for {target} in {}",
                            frontier.display()
                        ))
                    })
            };
            let reviewer = crate::cli_identity::resolve_actor(reviewer.as_deref());
            let reason = reason.unwrap_or_else(|| "landed via review".to_string());
            let signing_key = crate::cli_identity::resolve_signing_key_opt(key.as_deref());
            let outcome = proposals::accept_at_path_engine(
                &frontier,
                &proposal_id,
                &reviewer,
                &reason,
                proposals::AcceptOptions {
                    strict: false,
                    force: false,
                    signing_key,
                    custody_verified: false,
                },
            )
            .unwrap_or_else(|e| fail_return(&e));
            if json {
                print_json(&json!({
                    "ok": true, "command": "land", "target": target,
                    "proposal_id": proposal_id, "reviewer": reviewer,
                    "applied_event_id": outcome.event_id,
                    "engine_verdict": outcome.verdict.status,
                }));
            } else {
                println!(
                    "{} landed {} (proposal {})",
                    style::ok("ok"),
                    target,
                    proposal_id
                );
                println!("  event: {}", outcome.event_id);
                print_engine_verdict(&outcome.verdict);
            }
        }

        Commands::AcceptBatch {
            frontier,
            all_pending,
            ids,
            kinds,
            limit,
            reviewer,
            reason,
            strict,
            force,
            dry_run,
            no_reconcile,
            json,
        } => {
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
            let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
            // Explicit ids first, in the order given.
            for id in &ids {
                if seen.insert(id.clone()) {
                    selected.push(id.clone());
                }
            }
            if all_pending {
                for p in &loaded.proposals {
                    let pending = p.status == "pending_review" && p.applied_event_id.is_none();
                    let kind_ok = kind_filter.is_empty() || kind_filter.contains(p.kind.as_str());
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
        }

        Commands::Attest {
            frontier,
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
            json,
        } => {
            if let Some(target_id) = target_id {
                let parsed_scopes = reviewer_identity::parse_scopes(&scopes)
                    .unwrap_or_else(|e| fail_return(&format!("attest: {e}")));
                let reviewer = reviewer.unwrap_or_else(|| {
                    fail_return("attest: --reviewer is required for target attestations")
                });
                let role = role.unwrap_or_else(|| {
                    fail_return("attest: --role is required for target attestations")
                });
                let reason = reason.unwrap_or_else(|| {
                    fail_return("attest: --reason is required for target attestations")
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
            let count =
                sign::sign_frontier(&frontier, &key_path).unwrap_or_else(|e| fail_return(&e));
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
                    "{} {count} findings in {}",
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

/// File-extension dispatcher for `vela ingest`. Routes one path or
/// stable identifier URI to the right deterministic backing path:
///
/// - `doi:` / `pmid:` / `nct:` URI -> `cmd_source_fetch` (metadata only).
/// - JSON file or folder of JSON (Carina-shaped artifact packet) ->
///   `cmd_artifact_to_state`.
///
/// The LLM compile routes (.pdf/.md/.csv/code-dir) were removed with the
/// agent layer: ingest is a deterministic verb, not a model call.
async fn cmd_ingest(
    path: &str,
    frontier: &Path,
    _backend: Option<&str>,
    actor: Option<&str>,
    _dry_run: bool,
    json: bool,
) {
    // Stable identifier URI: dispatch to source-fetch.
    let lowered = path.trim().to_lowercase();
    if lowered.starts_with("doi:") || lowered.starts_with("pmid:") || lowered.starts_with("nct:") {
        cmd_source_fetch(path.trim(), None, None, false, json).await;
        if !json {
            eprintln!();
            eprintln!(
                "  vela ingest · note: doi:/pmid:/nct: URIs only fetch metadata; no frontier state was written."
            );
            eprintln!(
                "  next: turn this paper into a proposal with `vela finding add {} --assertion '...' --author 'reviewer:you' --apply`",
                frontier.display()
            );
        }
        return;
    }

    let p = std::path::PathBuf::from(path);
    if !p.exists() {
        fail(&format!(
            "ingest: path '{path}' does not exist (and is not a doi:/pmid:/nct: URI)"
        ));
    }

    let actor_id = actor.unwrap_or("agent:vela-ingest-bot");
    if p.is_file() {
        let is_json = p
            .extension()
            .and_then(|s| s.to_str())
            .map(|s| s.eq_ignore_ascii_case("json"))
            .unwrap_or(false);
        if !is_json {
            fail(
                "ingest: only .json artifact packets and doi:/pmid:/nct: URIs are ingestable; \
                 the LLM compile routes (.pdf/.md/.csv) were removed with the agent layer",
            );
        }
        cmd_artifact_to_state(frontier, &p, actor_id, false, json);
        return;
    }

    if p.is_dir() {
        let mut json_count = 0usize;
        if let Ok(entries) = std::fs::read_dir(&p) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file()
                    && path
                        .extension()
                        .and_then(|s| s.to_str())
                        .map(|s| s.eq_ignore_ascii_case("json"))
                        .unwrap_or(false)
                {
                    cmd_artifact_to_state(frontier, &path, actor_id, false, json);
                    json_count += 1;
                }
            }
        }
        if json_count == 0 {
            fail(
                "ingest: no .json artifact packets in folder; only JSON packets and \
                 doi:/pmid:/nct: URIs are ingestable",
            );
        }
        return;
    }

    fail(&format!(
        "ingest: path '{path}' is neither a file nor a directory"
    ));
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
                "suggestion": "Every decided proposal must have a signed review.* event (or, for accepts, its domain event). Run `vela proposals backfill-reviews` for legacy frontiers, or re-issue the decision through `vela accept` / `vela proposals reject`.",
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
    let signature_report = loaded
        .as_ref()
        .and_then(|frontier| sign::verify_frontier_data(frontier, None).ok());
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
                "suggestion": "Run `vela normalize` to materialize source records before proof export.",
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
        for atom in projection
            .evidence_atoms
            .iter()
            .filter(|atom| atom.locator.is_none())
        {
            diagnostics.push(json!({
                "severity": "warning",
                "rule_id": "missing_evidence_locator",
                "check": "evidence_atoms",
                "finding_id": atom.finding_id,
                "field_path": "evidence_atoms[].locator",
                "message": format!("Evidence atom {} has no source locator.", atom.id),
                "suggestion": "Add or verify evidence spans, table rows, pages, sections, or run locators.",
                "fixable": false,
                "normalize_action": null,
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
        "signatures": signature_report,
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

fn replace_top_level_json_field(raw: &str, field: &str, value: &Value) -> Result<String, String> {
    let Some((key_start, value_start, value_end)) = find_top_level_json_field(raw, field) else {
        return Err(format!("top-level JSON field '{field}' not found"));
    };
    let field_indent = raw[..key_start]
        .rsplit_once('\n')
        .map(|(_, tail)| tail.chars().count())
        .unwrap_or(key_start);
    let continuation_indent = " ".repeat(field_indent + 2);
    let rendered = serde_json::to_string_pretty(value)
        .map_err(|e| format!("serialize field '{field}': {e}"))?
        .replace('\n', &format!("\n{continuation_indent}"));

    let mut out = String::with_capacity(raw.len() + rendered.len());
    out.push_str(&raw[..value_start]);
    out.push_str(&rendered);
    out.push_str(&raw[value_end..]);
    Ok(out)
}

fn find_top_level_json_field(raw: &str, field: &str) -> Option<(usize, usize, usize)> {
    let bytes = raw.as_bytes();
    let mut depth = 0usize;
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => {
                let key_start = index;
                let key_end = json_string_end(raw, index)?;
                if depth == 1 && &raw[index + 1..key_end - 1] == field {
                    let colon = next_non_ws(raw, key_end)?;
                    if bytes.get(colon) == Some(&b':') {
                        let value_start = next_non_ws(raw, colon + 1)?;
                        let value_end = json_value_end(raw, value_start)?;
                        return Some((key_start, value_start, value_end));
                    }
                }
                index = key_end;
            }
            b'{' | b'[' => {
                depth += 1;
                index += 1;
            }
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
                index += 1;
            }
            _ => index += 1,
        }
    }
    None
}

fn json_string_end(raw: &str, start: usize) -> Option<usize> {
    let bytes = raw.as_bytes();
    let mut escaped = false;
    let mut index = start + 1;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' if !escaped => escaped = true,
            b'"' if !escaped => return Some(index + 1),
            _ => escaped = false,
        }
        index += 1;
    }
    None
}

fn json_value_end(raw: &str, start: usize) -> Option<usize> {
    let bytes = raw.as_bytes();
    match bytes.get(start)? {
        b'"' => json_string_end(raw, start),
        b'{' | b'[' => {
            let mut depth = 0usize;
            let mut index = start;
            while index < bytes.len() {
                match bytes[index] {
                    b'"' => index = json_string_end(raw, index)?,
                    b'{' | b'[' => {
                        depth += 1;
                        index += 1;
                    }
                    b'}' | b']' => {
                        depth = depth.saturating_sub(1);
                        index += 1;
                        if depth == 0 {
                            return Some(index);
                        }
                    }
                    _ => index += 1,
                }
            }
            None
        }
        _ => {
            let mut index = start;
            while index < bytes.len() && !matches!(bytes[index], b',' | b'}' | b']' | b'\n') {
                index += 1;
            }
            Some(raw[..index].trim_end().len())
        }
    }
}

fn next_non_ws(raw: &str, start: usize) -> Option<usize> {
    raw.as_bytes()[start..]
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .map(|offset| start + offset)
}

// ── v0.42 daily-driver triad ────────────────────────────────────────

pub(crate) fn answer(project: &vela_protocol::project::Project, q: &str, json: bool) {
    let lower = q.to_lowercase();

    // Pattern: pending / inbox.
    if lower.contains("pending")
        || lower.contains("inbox")
        || lower.contains("queue")
        || lower.contains("to review")
    {
        let pending: Vec<&vela_protocol::proposals::StateProposal> = project
            .proposals
            .iter()
            .filter(|p| p.status == "pending_review")
            .collect();
        let mut by_kind: std::collections::BTreeMap<String, usize> = Default::default();
        for p in &pending {
            *by_kind.entry(p.kind.clone()).or_insert(0) += 1;
        }
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "answer": "pending",
                    "total": pending.len(),
                    "by_kind": by_kind,
                }))
                .unwrap()
            );
        } else {
            println!("  {} pending proposals.", pending.len());
            for (k, n) in &by_kind {
                println!("    · {n:>3}  {k}");
            }
            if pending.is_empty() {
                println!("  Inbox is clean.");
            } else {
                println!("  Run `vela inbox <frontier>` to triage.");
            }
        }
        return;
    }

    // Pattern: underidentified / conditional / audit.
    if lower.contains("underident")
        || lower.contains("audit")
        || lower.contains("identif")
        || lower.contains("causal")
    {
        let entries = vela_edge::causal_reasoning::audit_frontier(project);
        let summary = vela_edge::causal_reasoning::summarize_audit(&entries);
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "answer": "audit",
                    "summary": {
                        "identified": summary.identified,
                        "conditional": summary.conditional,
                        "underidentified": summary.underidentified,
                        "underdetermined": summary.underdetermined,
                    },
                }))
                .unwrap()
            );
        } else {
            println!(
                "  Causal audit: {} identified · {} conditional · {} underidentified · {} underdetermined.",
                summary.identified,
                summary.conditional,
                summary.underidentified,
                summary.underdetermined,
            );
            if summary.underidentified > 0 {
                println!(
                    "  The {} underidentified findings are concrete review items:",
                    summary.underidentified
                );
                for e in entries
                    .iter()
                    .filter(|e| {
                        matches!(
                            e.verdict,
                            vela_edge::causal_reasoning::Identifiability::Underidentified
                        )
                    })
                    .take(8)
                {
                    let txt: String = e.assertion_text.chars().take(70).collect();
                    println!("    · {}  {}", e.finding_id, txt);
                }
            }
        }
        return;
    }

    // Pattern: recent / changed / log.
    if lower.contains("recent")
        || lower.contains("changed")
        || lower.contains("latest")
        || lower.contains("happen")
    {
        let mut events: Vec<&vela_protocol::events::StateEvent> = project.events.iter().collect();
        events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        events.truncate(8);
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "answer": "recent_events",
                    "events": events.iter().map(|e| json!({
                        "id": e.id, "kind": e.kind, "timestamp": e.timestamp,
                        "actor": e.actor.id, "target": e.target.id,
                    })).collect::<Vec<_>>(),
                }))
                .unwrap()
            );
        } else {
            println!("  Most recent {} events:", events.len());
            for e in &events {
                let when = fmt_timestamp(&e.timestamp);
                println!("    · {when}  {:<28}  {}", e.kind, e.target.id);
            }
        }
        return;
    }

    // Pattern: how many / count.
    if lower.starts_with("how many") || lower.contains("count") || lower.contains("total") {
        let n = project.findings.len();
        let evs = project.events.len();
        let actors = project.actors.len();
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "answer": "counts",
                    "findings": n,
                    "events": evs,
                    "actors": actors,
                    "datasets": project.datasets.len(),
                    "code_artifacts": project.code_artifacts.len(),
                }))
                .unwrap()
            );
        } else {
            println!("  {n} findings · {evs} events · {actors} actors.");
            println!(
                "  {} datasets · {} code artifacts.",
                project.datasets.len(),
                project.code_artifacts.len(),
            );
        }
        return;
    }

    // Fallback.
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "answer": "unknown_question",
                "question": q,
                "hint": "Try: pending, audit, recent, how many."
            }))
            .unwrap()
        );
    } else {
        println!("  Don't know how to route that question yet.");
        println!("  Try: pending · audit · recent · how many");
    }
}

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

fn cmd_artifact_to_state(
    frontier: &Path,
    packet: &Path,
    actor: &str,
    apply_artifacts: bool,
    json: bool,
) {
    let report = vela_edge::artifact_to_state::import_packet_at_path(
        frontier,
        packet,
        actor,
        apply_artifacts,
    )
    .unwrap_or_else(|e| fail_return(&e));
    if json {
        print_json(&report);
    } else {
        println!("vela artifact-to-state");
        println!("  packet: {}", report.packet_id);
        println!("  frontier: {}", report.frontier);
        println!("  artifact proposals: {}", report.artifact_proposals);
        println!("  finding proposals: {}", report.finding_proposals);
        println!("  gap proposals: {}", report.gap_proposals);
        println!(
            "  applied artifact events: {}",
            report.applied_artifact_events
        );
        println!(
            "  pending truth proposals: {}",
            report.pending_truth_proposals
        );
    }
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
    println!("Then `vela publish`, `vela propose`, and `vela accept` need no key flags.");
}

fn cmd_sign(action: SignAction) {
    match action {
        SignAction::GenerateKeypair { out, json } => {
            let public_key = sign::generate_keypair(&out).unwrap_or_else(|e| fail_return(&e));
            let payload = json!({
                "ok": true,
                "command": "sign.generate-keypair",
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
        SignAction::Apply {
            frontier,
            private_key,
            json,
        } => {
            let count =
                sign::sign_frontier(&frontier, &private_key).unwrap_or_else(|e| fail_return(&e));
            let payload = json!({
                "ok": true,
                "command": "sign.apply",
                "frontier": frontier.display().to_string(),
                "private_key": private_key.display().to_string(),
                "signed": count,
            });
            if json {
                print_json(&payload);
            } else {
                println!(
                    "{} {count} findings in {}",
                    style::ok("signed"),
                    frontier.display()
                );
            }
        }
        SignAction::Verify {
            frontier,
            public_key,
            json,
        } => {
            let report = sign::verify_frontier(&frontier, public_key.as_deref())
                .unwrap_or_else(|e| fail_return(&e));
            if json {
                print_json(&report);
            } else {
                println!();
                println!(
                    "  {}",
                    format!("VELA · SIGN · VERIFY · {}", frontier.display())
                        .to_uppercase()
                        .dimmed()
                );
                println!("  {}", style::tick_row(60));
                println!("  total findings:   {}", report.total_findings);
                println!("  signed:           {}", report.signed);
                println!("  unsigned:         {}", report.unsigned);
                println!("  valid:            {}", report.valid);
                println!("  invalid:          {}", report.invalid);
                if report.findings_with_threshold > 0 {
                    println!("  with threshold:   {}", report.findings_with_threshold);
                    println!("  jointly accepted: {}", report.jointly_accepted);
                }
            }
        }
        SignAction::ThresholdSet {
            frontier,
            finding_id,
            to,
            json,
        } => {
            if to == 0 {
                fail("--to must be >= 1");
            }
            let mut project = repo::load_from_path(&frontier).unwrap_or_else(|e| fail_return(&e));
            let Some(idx) = project.findings.iter().position(|f| f.id == finding_id) else {
                fail(&format!("finding '{finding_id}' not present in frontier"));
            };
            project.findings[idx].flags.signature_threshold = Some(to);
            // Re-derive the joint-accept flag immediately; if the
            // existing signature pool already meets the threshold, the
            // finding becomes jointly_accepted on the same write.
            sign::refresh_jointly_accepted(&mut project);
            let met = project.findings[idx].flags.jointly_accepted;
            repo::save_to_path(&frontier, &project).unwrap_or_else(|e| fail_return(&e));

            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": true,
                        "command": "sign.threshold-set",
                        "finding_id": finding_id,
                        "threshold": to,
                        "jointly_accepted": met,
                        "frontier": frontier.display().to_string(),
                    }))
                    .expect("failed to serialize sign.threshold-set")
                );
            } else {
                println!(
                    "{} signature_threshold={to} on {finding_id} ({})",
                    style::ok("set"),
                    if met {
                        "jointly accepted"
                    } else {
                        "awaiting signatures"
                    }
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

/// Default local registry path (`~/.vela/registry/entries.json`).
/// Free helper so non-`cmd_registry` callers can resolve it too.
pub(crate) fn default_registry_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home)
        .join(".vela")
        .join("registry")
        .join("entries.json")
}

/// v0.140: resolve a `vfr_*` registry id to a concrete frontier
/// path on disk. Loads the registry (local or hub URL), looks up
/// the latest matching entry, fetches its substrate to `dest`,
/// and runs the same verify-pull check `registry pull` uses. The
/// caller is responsible for the lifetime of `dest` (typically a
/// tempdir entry that is dropped after the consumer is done).
fn resolve_vfr_to_path(vfr_id: &str, from: Option<&str>, dest: &Path) -> Result<(), String> {
    use vela_protocol::registry;
    let registry_data = match from {
        Some(loc) if loc.starts_with("http") => registry::load_any(loc)?,
        Some(loc) => {
            let p = registry::resolve_local(loc)?;
            registry::load_local(&p)?
        }
        None => {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            let p = PathBuf::from(home)
                .join(".vela")
                .join("registry")
                .join("entries.json");
            registry::load_local(&p)?
        }
    };
    let entry = registry::find_latest(&registry_data, vfr_id)
        .ok_or_else(|| format!("{vfr_id} not found in registry"))?;
    registry::fetch_frontier_to_prefer_event_hub(&entry, from, dest)
        .map_err(|e| format!("fetch frontier for {vfr_id}: {e}"))?;
    registry::verify_pull(&entry, dest)
        .map_err(|e| format!("pull verification failed for {vfr_id}: {e}"))?;
    Ok(())
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
You may be linking to outdated wording. Pull --transitive and inspect the supersedes chain to find the current finding. \
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

/// v0.158: tag the current frontier state as a versioned release.
pub(crate) fn cmd_frontier_release(
    frontier: PathBuf,
    name: String,
    notes: Option<String>,
    previous: Option<String>,
    json: bool,
) {
    use vela_edge::frontier_release::{FrontierRelease, ReleaseDraft};

    let project = repo::load_from_path(&frontier).unwrap_or_else(|e| fail_return(&e));
    let frontier_id = project.frontier_id();
    let snapshot_hash = events::snapshot_hash(&project);
    let event_log_hash = events::event_log_hash(&project.events);

    // Derive releases dir + chain on the latest existing release
    // (if no --previous was supplied).
    let releases_dir = releases_dir_for(&frontier);
    let chained_previous = if previous.is_some() {
        previous
    } else {
        latest_release_id(&releases_dir)
    };

    // Owner epoch: the chain transcript at v0.146 has it. If
    // present, take the latest transition's owner_epoch;
    // otherwise default to 0 (bootstrap).
    let owner_epoch = derive_owner_epoch(&frontier);

    let draft = ReleaseDraft {
        frontier_id: frontier_id.clone(),
        name,
        notes,
        owner_epoch,
        snapshot_hash,
        event_log_hash,
        governance_policy_id: None,
        previous_release: chained_previous,
        released_at: chrono::Utc::now().to_rfc3339(),
    };
    let release = FrontierRelease::from_draft(draft).unwrap_or_else(|e| fail_return(&e));

    if let Err(e) = std::fs::create_dir_all(&releases_dir) {
        fail(&format!("create releases dir: {e}"));
    }
    let path = releases_dir.join(format!("{}.json", release.release_id));
    let body = serde_json::to_string_pretty(&release).expect("serialize frontier release");
    std::fs::write(&path, format!("{body}\n"))
        .unwrap_or_else(|e| fail_return(&format!("write {}: {e}", path.display())));

    if json {
        let payload = json!({
            "ok": true,
            "command": "frontier.release",
            "release_id": release.release_id,
            "frontier_id": release.frontier_id,
            "name": release.name,
            "owner_epoch": release.owner_epoch,
            "snapshot_hash": release.snapshot_hash,
            "event_log_hash": release.event_log_hash,
            "previous_release": release.previous_release,
            "released_at": release.released_at,
            "out": path.display().to_string(),
        });
        print_json(&payload);
    } else {
        println!(
            "{} released {} ({}) of {}",
            style::ok("release"),
            release.release_id,
            release.name,
            release.frontier_id
        );
        println!("  owner_epoch:   {}", release.owner_epoch);
        println!("  snapshot:      {}", release.snapshot_hash);
        println!("  event_log:     {}", release.event_log_hash);
        if let Some(prev) = &release.previous_release {
            println!("  previous:      {}", prev);
        }
        println!("  out:           {}", path.display());
    }
}

/// v0.158: list every release recorded for a frontier.
pub(crate) fn cmd_frontier_releases(frontier: PathBuf, json: bool) {
    use vela_edge::frontier_release::FrontierRelease;

    let releases_dir = releases_dir_for(&frontier);
    let mut releases: Vec<FrontierRelease> = Vec::new();
    if releases_dir.exists() {
        for entry in std::fs::read_dir(&releases_dir)
            .unwrap_or_else(|e| fail_return(&format!("read releases dir: {e}")))
        {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            let raw = match std::fs::read_to_string(&path) {
                Ok(r) => r,
                Err(_) => continue,
            };
            if let Ok(r) = serde_json::from_str::<FrontierRelease>(&raw) {
                releases.push(r);
            }
        }
    }
    releases.sort_by(|a, b| b.released_at.cmp(&a.released_at));

    if json {
        let payload = json!({
            "ok": true,
            "command": "frontier.releases",
            "frontier": frontier.display().to_string(),
            "release_count": releases.len(),
            "releases": releases,
        });
        print_json(&payload);
    } else {
        println!(
            "{} {} release(s) for {}",
            style::ok("releases"),
            releases.len(),
            frontier.display()
        );
        for r in &releases {
            println!("  {}  {}  (epoch {})", r.release_id, r.name, r.owner_epoch);
            println!("    released_at: {}", r.released_at);
            if let Some(prev) = &r.previous_release {
                println!("    previous:    {}", prev);
            }
        }
    }
}

pub(crate) fn cmd_frontier_audit(frontier: PathBuf, json_out: bool) {
    let project = repo::load_from_path(&frontier).unwrap_or_else(|e| fail_return(&e));
    let strict_check = check_json_payload(&frontier, false, true);
    let proof = frontier_repo::proof_verify(&frontier).unwrap_or_else(|e| {
        json!({
            "ok": false,
            "command": "proof.verify",
            "frontier": frontier.display().to_string(),
            "error": e,
        })
    });
    let evidence = evidence_ci::run_frontier(&frontier).unwrap_or_else(|e| fail_return(&e));
    let health = frontier_health::analyze(&frontier).unwrap_or_else(|e| fail_return(&e));
    let mut review_work = crate::review_work::build_review_work_json(&frontier)
        .map(Some)
        .unwrap_or_else(|e| {
            Some(json!({
                "ok": false,
                "command": "review-work",
                "frontier_path": frontier.display().to_string(),
                "error": e,
            }))
        });

    let provenance = vela_protocol::reducer::classify_provenance(&project);
    let fully_event_sourced = provenance.fully_event_sourced();
    let event_source = json!({
        "fully_event_sourced": fully_event_sourced,
        "inline": provenance.inline.len(),
        "proposal_backed": provenance.proposal_backed.len(),
        "remnant": provenance.remnant.len(),
        "actors": provenance.actors,
        "proposals": provenance.proposals,
        "pins": {
            // What still keeps a derived view committed to git.
            "findings_dir": provenance.remnant.len(),
            "proposals_dir": provenance.proposal_backed.len(),
        },
        "note": if fully_event_sourced {
            "events/ reduces to the whole finding set; findings/ + proposals/ are pure caches, safe to decommit once verify_replay is green"
        } else {
            "some finding bodies live only in findings/ (remnants) or proposals/ (proposal-backed asserts); migrate them to inline asserts before decommitting"
        },
    });

    let strict_ok = json_bool(&strict_check, "ok");
    let proof_ok = json_bool(&proof, "ok");
    let evidence_ok = evidence.ok;
    let health_ok = health.ok;
    let review_work_by_lane = review_work_by_lane(review_work.as_ref());
    if let Some(Value::Object(payload)) = review_work.as_mut() {
        payload.insert("by_lane".to_string(), review_work_by_lane);
    }
    let review_work_open = review_work_total_open(review_work.as_ref());
    let strict_check_summary = compact_strict_check(&strict_check);
    let evidence_ci_summary = compact_evidence_ci(&evidence);
    let quality_tier = frontier_audit_tier(
        strict_ok,
        proof_ok,
        evidence_ok,
        health_ok,
        review_work_open,
    );
    let release_blockers = frontier_audit_release_blockers(
        &strict_check,
        &proof,
        &evidence,
        &health,
        review_work.as_ref(),
    );
    let ok = strict_ok && proof_ok && evidence_ok && health_ok;

    let payload = json!({
        "ok": ok,
        "command": "frontier.audit",
        "checked_at": chrono::Utc::now().to_rfc3339(),
        "quality_tier": quality_tier,
        "release_blockers": release_blockers,
        "frontier": {
            "id": project.frontier_id(),
            "name": &project.project.name,
            "path": frontier.display().to_string(),
            "compiled_at": &project.project.compiled_at,
        },
        "summary": {
            "findings": project.stats.findings,
            "sources": project.stats.source_count,
            "evidence_atoms": project.stats.evidence_atom_count,
            "events": project.stats.event_count,
            "links": project.stats.links,
            "strict_check_ok": strict_ok,
            "proof_ok": proof_ok,
            "evidence_ci_ok": evidence_ok,
            "health_ok": health_ok,
            "review_work_open": review_work_open,
            "proof_status": &project.proof_state.latest_packet.status,
            "evidence_ci_failures": evidence.summary.release_blocking_failed,
            "evidence_ci_warnings": evidence.summary.warnings,
            "health_issues": health.issues.len(),
        },
        "stats": &project.stats,
        "event_source": event_source,
        "strict_check": strict_check_summary,
        "proof": proof,
        "evidence_ci": evidence_ci_summary,
        "frontier_health": health,
        "review_work": review_work,
        "caveats": [
            "Frontier audit is a readiness report. It is not a truth verdict.",
            "Review-work queues are read-only and do not count as review.",
            "Outside-review lanes are reported only when returned artifacts exist."
        ],
    });

    if json_out {
        print_json(&payload);
        return;
    }

    let status = if ok {
        style::ok("frontier.audit")
    } else {
        style::warn("frontier.audit")
    };
    println!();
    println!("  {}", "Vela · frontier audit".dimmed());
    println!("  {}", style::tick_row(60));
    println!("  {status} {quality_tier}");
    println!("  frontier:        {}", project.frontier_id());
    println!("  path:            {}", frontier.display());
    println!(
        "  stats:           {} findings · {} sources · {} evidence atoms · {} events · {} links",
        project.stats.findings,
        project.stats.source_count,
        project.stats.evidence_atom_count,
        project.stats.event_count,
        project.stats.links
    );
    println!(
        "  event-sourced:   {} ({} inline · {} proposal-backed · {} remnant)",
        if fully_event_sourced {
            style::ok("fully")
        } else {
            style::warn("partial")
        },
        provenance.inline.len(),
        provenance.proposal_backed.len(),
        provenance.remnant.len()
    );
    println!(
        "  strict check:    {}",
        if strict_ok {
            style::ok("pass")
        } else {
            style::lost("fail")
        }
    );
    println!(
        "  proof verify:    {} ({})",
        if proof_ok {
            style::ok("pass")
        } else {
            style::lost("fail")
        },
        project.proof_state.latest_packet.status
    );
    println!(
        "  Evidence CI:     {} · {} failures · {} warnings",
        if evidence_ok {
            style::ok("pass")
        } else {
            style::lost("fail")
        },
        evidence.summary.release_blocking_failed,
        evidence.summary.warnings
    );
    println!(
        "  health:          {} · {} issue(s)",
        if health_ok {
            style::ok("pass")
        } else {
            style::warn("attention")
        },
        health.issues.len()
    );
    println!("  review work:     {review_work_open} open row(s)");
    println!("  boundary:        read-only. This does not count as review.");
}

fn json_bool(value: &Value, key: &str) -> bool {
    value.get(key).and_then(Value::as_bool) == Some(true)
}

fn review_work_total_open(value: Option<&Value>) -> usize {
    value
        .and_then(|payload| payload.get("total_open"))
        .and_then(Value::as_u64)
        .unwrap_or(0) as usize
}

fn review_work_by_lane(value: Option<&Value>) -> Value {
    let mut lanes = serde_json::Map::new();
    if let Some(queues) = value
        .and_then(|payload| payload.get("queues"))
        .and_then(Value::as_array)
    {
        for queue in queues {
            if let Some(lane_id) = queue.get("lane_id").and_then(Value::as_str) {
                lanes.insert(lane_id.to_string(), queue.clone());
            }
        }
    }
    Value::Object(lanes)
}

fn frontier_audit_release_blockers(
    strict_check: &Value,
    proof: &Value,
    evidence: &evidence_ci::EvidenceCiReport,
    health: &frontier_health::FrontierHealthReport,
    review_work: Option<&Value>,
) -> Value {
    let mut blockers = Vec::new();

    if !json_bool(strict_check, "ok") {
        blockers.push(json!({
            "id": "strict_check",
            "title": "strict check",
            "severity": "release_blocker",
            "detail": "Strict check failed.",
            "count": strict_check
                .get("diagnostics")
                .and_then(Value::as_array)
                .map_or(0, Vec::len),
        }));
    }

    if !json_bool(proof, "ok") {
        blockers.push(json!({
            "id": "proof_verify",
            "title": "proof verify",
            "severity": "release_blocker",
            "detail": proof
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("Proof verification failed."),
        }));
    }

    if !evidence.ok {
        blockers.push(json!({
            "id": "evidence_ci",
            "title": "Evidence CI",
            "severity": "release_blocker",
            "detail": "Evidence CI has release-blocking failures.",
            "count": evidence.summary.release_blocking_failed,
        }));
    }

    if !health.ok {
        blockers.push(json!({
            "id": "frontier_health",
            "title": "frontier health",
            "severity": "release_blocker",
            "detail": "Frontier health requires attention.",
            "count": health.issues.len(),
        }));
    }

    if review_work
        .and_then(|payload| payload.get("ok"))
        .and_then(Value::as_bool)
        == Some(false)
    {
        blockers.push(json!({
            "id": "review_work",
            "title": "review work",
            "severity": "release_blocker",
            "detail": review_work
                .and_then(|payload| payload.get("error"))
                .and_then(Value::as_str)
                .unwrap_or("Review-work queues could not be read."),
        }));
    }

    Value::Array(blockers)
}

fn compact_strict_check(report: &Value) -> Value {
    json!({
        "ok": report.get("ok").cloned().unwrap_or(Value::Bool(false)),
        "command": report.get("command").cloned().unwrap_or(Value::String("check".to_string())),
        "summary": report.get("summary").cloned().unwrap_or(Value::Null),
        "checks": report.get("checks").cloned().unwrap_or(Value::Array(Vec::new())),
        "proof_readiness": report.get("proof_readiness").cloned().unwrap_or(Value::Null),
        "state_integrity": report.get("state_integrity").cloned().unwrap_or(Value::Null),
        "diagnostic_count": report
            .get("diagnostics")
            .and_then(Value::as_array)
            .map_or(0, Vec::len),
        "review_queue_count": report
            .get("review_queue")
            .and_then(Value::as_array)
            .map_or(0, Vec::len),
    })
}

fn compact_evidence_ci(report: &evidence_ci::EvidenceCiReport) -> Value {
    json!({
        "ok": report.ok,
        "command": &report.command,
        "frontier_id": &report.frontier_id,
        "frontier_path": &report.frontier_path,
        "checked_at": &report.checked_at,
        "scope": &report.scope,
        "summary": &report.summary,
        "caveats": &report.caveats,
    })
}

fn frontier_audit_tier(
    strict_ok: bool,
    proof_ok: bool,
    evidence_ok: bool,
    health_ok: bool,
    review_work_open: usize,
) -> &'static str {
    if strict_ok && proof_ok && evidence_ok && health_ok && review_work_open == 0 {
        "release_ready"
    } else if strict_ok && proof_ok && evidence_ok {
        "release_clean_with_open_review_work"
    } else if proof_ok && evidence_ok {
        "review_ready"
    } else {
        "blocked"
    }
}

fn releases_dir_for(frontier: &Path) -> PathBuf {
    let dir = if frontier.is_dir() {
        frontier.to_path_buf()
    } else if let Some(parent) = frontier.parent() {
        parent.to_path_buf()
    } else {
        PathBuf::from(".")
    };
    dir.join(".vela").join("releases")
}

fn latest_release_id(releases_dir: &Path) -> Option<String> {
    use vela_edge::frontier_release::FrontierRelease;
    if !releases_dir.exists() {
        return None;
    }
    let mut latest: Option<(String, String)> = None;
    if let Ok(entries) = std::fs::read_dir(releases_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            let raw = match std::fs::read_to_string(&path) {
                Ok(r) => r,
                Err(_) => continue,
            };
            if let Ok(r) = serde_json::from_str::<FrontierRelease>(&raw) {
                let pick = latest
                    .as_ref()
                    .map(|(_, ts)| ts.as_str() < r.released_at.as_str())
                    .unwrap_or(true);
                if pick {
                    latest = Some((r.release_id, r.released_at));
                }
            }
        }
    }
    latest.map(|(id, _)| id)
}

fn derive_owner_epoch(frontier: &Path) -> u64 {
    let chain_path = if frontier.is_dir() {
        frontier.join(".vela").join("governance").join("chain.json")
    } else if let Some(parent) = frontier.parent() {
        parent.join(".vela").join("governance").join("chain.json")
    } else {
        return 0;
    };
    if !chain_path.exists() {
        return 0;
    }
    let raw = match std::fs::read_to_string(&chain_path) {
        Ok(r) => r,
        Err(_) => return 0,
    };
    let v: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(_) => return 0,
    };
    v.get("transitions")
        .and_then(|t| t.as_array())
        .and_then(|arr| arr.last())
        .and_then(|t| t.get("owner_epoch"))
        .and_then(|e| e.as_u64())
        .unwrap_or(0)
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

pub(crate) fn parse_task_status(status: &str) -> frontier_task::FrontierTaskStatus {
    status
        .parse()
        .unwrap_or_else(|e| fail_return(&format!("invalid task status: {e}")))
}

pub(crate) fn print_task(task: &frontier_task::FrontierTask, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(task).expect("serialize task")
        );
    } else {
        println!(
            "{} {} {} · {}",
            style::ok("task"),
            task.id,
            task.status,
            task.objective
        );
        println!("  frontier: {}", task.frontier_id);
        println!("  type:     {}", task.task_type);
        println!("  risk:     {}", task.risk_class);
        if !task.inputs.is_empty() {
            println!("  inputs:   {}", task.inputs.join(", "));
        }
        if !task.blockers.is_empty() {
            println!("  blockers: {}", task.blockers.join(", "));
        }
        if !task.acceptance_criteria.is_empty() {
            println!("  accept:   {}", task.acceptance_criteria.join(" · "));
        }
        if let Some(reviewer) = &task.claimed_by {
            println!("  claimed:  {reviewer}");
        }
        if let Some(reason) = &task.closed_reason {
            println!("  reason:   {reason}");
        }
    }
}

/// v0.153: handle `vela registry verify-all`.
pub(crate) fn cmd_verify_all(from: Option<PathBuf>, json: bool) {
    use vela_protocol::registry;

    let registry_path = match from {
        Some(p) => registry::resolve_local(p.to_str().unwrap_or_default())
            .unwrap_or_else(|e| fail_return(&e)),
        None => default_registry_path(),
    };
    let registry_data = registry::load_local(&registry_path).unwrap_or_else(|e| fail_return(&e));

    #[derive(serde::Serialize)]
    struct EntryReport {
        vfr_id: String,
        signature_ok: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    }

    let mut reports: Vec<EntryReport> = Vec::new();
    let mut pass = 0usize;
    let mut fail = 0usize;
    for entry in &registry_data.entries {
        match registry::verify_entry(entry) {
            Ok(true) => {
                pass += 1;
                reports.push(EntryReport {
                    vfr_id: entry.vfr_id.clone(),
                    signature_ok: true,
                    error: None,
                });
            }
            Ok(false) => {
                fail += 1;
                reports.push(EntryReport {
                    vfr_id: entry.vfr_id.clone(),
                    signature_ok: false,
                    error: Some("signature did not verify against owner_pubkey".to_string()),
                });
            }
            Err(e) => {
                fail += 1;
                reports.push(EntryReport {
                    vfr_id: entry.vfr_id.clone(),
                    signature_ok: false,
                    error: Some(e),
                });
            }
        }
    }

    let ok = fail == 0;
    let payload = json!({
        "ok": ok,
        "command": "registry.verify-all",
        "registry": registry_path.display().to_string(),
        "entry_count": registry_data.entries.len(),
        "pass": pass,
        "fail": fail,
        "entries": reports,
    });
    if json {
        print_json(&payload);
    } else {
        println!(
            "{} verify-all over {}: {} pass, {} fail",
            style::ok("registry"),
            registry_path.display(),
            pass,
            fail
        );
        for r in &reports {
            let badge = if r.signature_ok { "ok" } else { "FAIL" };
            println!("  {badge}  {}", r.vfr_id);
            if let Some(e) = &r.error {
                println!("        {e}");
            }
        }
    }
    if !ok {
        std::process::exit(1);
    }
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
    if json_output {
        print_json(&payload);
    } else {
        println!(
            "{} initialized frontier repository in {}",
            style::ok("ok"),
            path.display()
        );
    }
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

pub(crate) fn append_packet_json_file(
    packet_dir: &Path,
    relative_path: &str,
    value: &Value,
) -> Result<(), String> {
    let content = serde_json::to_vec_pretty(value)
        .map_err(|e| format!("Failed to serialize packet JSON file: {e}"))?;
    let path = packet_dir.join(relative_path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create {}: {e}", parent.display()))?;
    }
    std::fs::write(&path, &content)
        .map_err(|e| format!("Failed to write {}: {e}", path.display()))?;
    let entry = json!({
        "path": relative_path,
        "sha256": hex::encode(Sha256::digest(&content)),
        "bytes": content.len(),
    });

    for manifest_name in ["manifest.json", "packet.lock.json"] {
        let manifest_path = packet_dir.join(manifest_name);
        let data = std::fs::read_to_string(&manifest_path)
            .map_err(|e| format!("Failed to read {}: {e}", manifest_path.display()))?;
        let mut manifest: Value = serde_json::from_str(&data)
            .map_err(|e| format!("Failed to parse {}: {e}", manifest_path.display()))?;
        let array_key = if manifest_name == "manifest.json" {
            "included_files"
        } else {
            "files"
        };
        let files = manifest
            .get_mut(array_key)
            .and_then(Value::as_array_mut)
            .ok_or_else(|| format!("{} missing {array_key} array", manifest_path.display()))?;
        files.retain(|file| {
            file.get("path")
                .and_then(Value::as_str)
                .is_none_or(|path| path != relative_path)
        });
        files.push(entry.clone());
        std::fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&manifest)
                .map_err(|e| format!("Failed to serialize {}: {e}", manifest_path.display()))?,
        )
        .map_err(|e| format!("Failed to write {}: {e}", manifest_path.display()))?;
    }

    let lock_path = packet_dir.join("packet.lock.json");
    let lock_content = std::fs::read(&lock_path)
        .map_err(|e| format!("Failed to read {}: {e}", lock_path.display()))?;
    let lock_entry = json!({
        "path": "packet.lock.json",
        "sha256": hex::encode(Sha256::digest(&lock_content)),
        "bytes": lock_content.len(),
    });
    let manifest_path = packet_dir.join("manifest.json");
    let data = std::fs::read_to_string(&manifest_path)
        .map_err(|e| format!("Failed to read {}: {e}", manifest_path.display()))?;
    let mut manifest: Value = serde_json::from_str(&data)
        .map_err(|e| format!("Failed to parse {}: {e}", manifest_path.display()))?;
    let files = manifest
        .get_mut("included_files")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| format!("{} missing included_files array", manifest_path.display()))?;
    files.retain(|file| {
        file.get("path")
            .and_then(Value::as_str)
            .is_none_or(|path| path != "packet.lock.json")
    });
    files.push(lock_entry);
    std::fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest)
            .map_err(|e| format!("Failed to serialize {}: {e}", manifest_path.display()))?,
    )
    .map_err(|e| format!("Failed to write {}: {e}", manifest_path.display()))?;
    Ok(())
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
const DEPRECATED_FROM_HELP: &[&str] = &[
    "normalize",
    "experiment",
    "attach",
    "attempt",
    "transfer",
    "lean",
    "queue",
    "completions",
];

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

Usage:
  vela <COMMAND>

Setup (once):
  id            Set up your key + identity once (then no --key/--actor/--hub flags)
  init          Initialize a new frontier repo
  clone         Clone a frontier from the hub into a working tree (reproduces + extends)

Producer loop (clone -> reproduce -> ingest -> propose -> publish):
  reproduce     Re-verify stored witnesses from scratch (frozen exact verifiers)
  ingest        Ingest a paper, dataset, or Carina packet (dispatches by file type)
  propose       Create a finding.review proposal
  publish       Push a frontier to the hub (owner/key/hub from your identity; alias: push)

Sync:
  status        One-screen frontier state; --remote compares against the hub upstream
  pull          Fast-forward a local checkout from its hub remote (no silent merge)
  log           Recent canonical state events
  diff          Preview a `vpr_*` proposal, or compare two frontier files
  history       State-transition replay for one finding

Review (maintainers):
  inbox         Triage list of pending proposals
  propose       Create a finding.review proposal (the review verb)
  accept        Apply a proposal under your reviewer key
  accept-batch  Apply several pending proposals under one reviewer decision
  land          Land a result in one step: accept a vpr_ proposal or a vf_ finding's pending add
  attest        Sign findings under your private key
  proposals     Inspect, validate, export, import, accept, or reject write proposals

Verify:
  check         Validate a frontier, repo, or proof packet (--strict, --evidence, --conformance)
  gate          Verification gate: deliverable-grade + verifier-attachment checks
  reproduce     Re-verify stored witnesses from scratch (frozen exact verifiers)
  proof         Export and validate a proof packet (`proof verify`, `proof explain`)
  verify        Re-hash and validate a proof packet (manifest + proof-trace chain)

Work next (discovery):
  attack        Ranked "what to work on next" queue from the dark-matter boundary
  explore       A finding's neighbourhood: what it rests on / what rests on it, within --hops
  campaign      Discovery engine: search verifier-gated constructions, verify, propose
  foundry       One unattended compounding turn: produce -> frozen-verify -> auto-admit

Inspect (read-only):
  doctor        Diagnose first-user checkout, frontier, proof, and serve readiness
  claim state   Derive the Claim-State Cell for a finding (Belnap status, deps, obligations)
  claim trust   Derive the Trust Vector for a finding (absent fields shown as absent)
  claim pack    Bundle state + trust + reproduce command + event ids (citable claim pack)
  claim diff    Evidence Diff: a proposal's before/after effect on a claim + downstream impact

Nouns (subcommand groups; run `vela <noun> --help`):
  frontier      Scaffold (`new`), materialize, and manage frontier metadata + deps
  finding       Per-finding verbs: add, review, note, caveat, revise, reject, retract, link, supersede
  registry      Publish, pull, list; maintainer add/remove, deprecate, rotate-owner
  actor         Register Ed25519 publisher identities in a frontier
  sign          Signing and signature verification
  agents        Generate agent-config adapters from VELA.md (sync | doctor | diff)
  workspace     List/add/remove checked-out frontiers + their hub remotes (the gate reads this)
  task          Create, list, claim, and close local frontier tasks
  serve         Serve a read-only frontier over MCP stdio or HTTP (the local review server)

Specialist and legacy commands stay callable but are out of this menu
(run `vela <name> --help`): {}.

Quick start (the demo):
  vela init demo --name "Your bounded question"
  vela ingest paper.pdf --frontier demo
  vela propose demo <vf_id> --status accepted --reason "..." --reviewer reviewer:you --apply
  vela diff <vpr_id> --frontier demo
  vela accept demo <vpr_id> --reviewer reviewer:you --reason "applied"
  vela serve demo --http 8787

Substrate health:
  vela frontier materialize my-frontier --json
  vela frontier audit my-frontier --json
  vela status my-frontier --json
  vela proof verify my-frontier --json
  vela check my-frontier --strict --json

Monolithic frontier file:
  vela frontier new frontier.json --name "Your bounded question"
  vela finding add frontier.json --assertion "..." --author "reviewer:demo" --apply
  vela check frontier.json --json
  FINDING_ID=$(jq -r '.findings[0].id' frontier.json)
  vela propose frontier.json "$FINDING_ID" --status contested --reason "Mouse-only evidence" --apply

Publish your own frontier (see docs/PUBLISHING.md):
  vela frontier new ./frontier.json --name "Your bounded question"
  vela finding add ./frontier.json --assertion "..." --author "reviewer:you" --apply
  vela sign generate-keypair --out keys
  vela actor add ./frontier.json reviewer:you --pubkey "$(cat keys/public.key)"
  vela registry publish ./frontier.json --owner reviewer:you --key keys/private.key \
      --to https://hub.constellate.science
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

/// Walk up from `cwd` looking for a `.vela/` directory. Returns the
/// first parent that contains one, or `None` if none found.
fn find_vela_repo() -> Option<PathBuf> {
    let mut cur = std::env::current_dir().ok()?;
    loop {
        if cur.join(".vela").is_dir() {
            return Some(cur);
        }
        if !cur.pop() {
            return None;
        }
    }
}

fn print_session_help() {
    println!();
    println!(
        "  Vela {} · Version control for scientific state.",
        env!("CARGO_PKG_VERSION")
    );
    println!();
    println!("  USAGE");
    println!("    vela              Open a session against the nearest .vela/ repo");
    println!("    vela <command>    Run a specific subcommand");
    println!("    vela help advanced   Full subcommand list (30+ commands)");
    println!();
    println!("  SETUP (once)");
    println!(
        "    id create         Generate your key + identity; then no --key/--actor/--hub flags"
    );
    println!("    init <dir>        Start a new frontier repo (vs clone, which joins one)");
    println!();
    println!("  PRODUCER LOOP (the git-style path: clone, reproduce, propose, push)");
    println!("    clone <vfr|url>   Clone a published frontier from the hub into a working tree");
    println!(
        "    reproduce <dir>   Re-verify the cloned witnesses from scratch (frozen verifiers)"
    );
    println!("    ingest <path>     Ingest a paper, dataset, or Carina packet");
    println!("    propose           Create a finding.review proposal");
    println!(
        "    publish <dir>     Push your frontier to the hub (alias: push); owner/key/hub from id"
    );
    println!();
    println!("  SYNC");
    println!(
        "    status            One-screen frontier state; status --remote vs the hub upstream"
    );
    println!(
        "    pull <dir>        Fast-forward a local checkout from its hub remote (no silent merge)"
    );
    println!("    log               Recent canonical state events");
    println!();
    println!("  REVIEW (maintainers)");
    println!("    inbox             Pending review proposals");
    println!("    propose <vf>      Create/apply a finding.review proposal (the review verb)");
    println!("    diff <vpr_id>     Preview a pending proposal vs current frontier");
    println!("    accept <vpr_id>   Apply a proposal under your reviewer key");
    println!(
        "    accept-batch      Accept all pending in one signed, reconciled pass (--all-pending)"
    );
    println!("    attest            Sign findings under your private key");
    println!();
    println!("  VERIFY");
    println!("    gate check <vf>                    Trust-gate status for one finding");
    println!("    reproduce <dir>                    Re-verify stored witnesses from scratch");
    println!(
        "    registry verify-log <vfr>          Independently verify a hub's transparency log"
    );
    println!("    claim state <vf>                   Claim-State Cell (Belnap status, deps)");
    println!();
    println!("  In session, type a single letter for a quick verb, or any");
    println!("  question in plain text. `q` or `exit` quits.");
    println!();
}

pub(crate) fn print_session_dashboard(project: &vela_protocol::project::Project, repo_path: &Path) {
    use vela_edge::causal_reasoning::{audit_frontier, summarize_audit};

    let label = frontier_label(project);
    let vfr = project.frontier_id();
    let vfr_short = vfr.chars().take(16).collect::<String>();

    let mut pending = 0usize;
    let mut by_kind: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for p in &project.proposals {
        if p.status == "pending_review" {
            pending += 1;
            *by_kind.entry(p.kind.clone()).or_insert(0) += 1;
        }
    }

    let audit = audit_frontier(project);
    let audit_summary = summarize_audit(&audit);

    println!();
    let version = vela_protocol::project::VELA_COMPILER_VERSION
        .strip_prefix("vela/")
        .unwrap_or(vela_protocol::project::VELA_COMPILER_VERSION);
    println!(
        "  {}",
        format!("VELA · {version} · {label}")
            .to_uppercase()
            .dimmed()
    );
    println!("  {}", style::tick_row(60));
    println!(
        "  vfr_id     {}…   repo  {}",
        vfr_short,
        repo_path.display()
    );
    println!(
        "  findings   {:>4}     events   {}     proposals pending  {}",
        project.findings.len(),
        project.events.len(),
        pending
    );

    if pending > 0 {
        let parts: Vec<String> = by_kind.iter().map(|(k, n)| format!("{n} {k}")).collect();
        println!("  {}     · {}", style::warn("inbox"), parts.join("  "));
    }
    if audit_summary.underidentified > 0 || audit_summary.conditional > 0 {
        println!(
            "  {}     · {} underidentified · {} conditional",
            if audit_summary.underidentified > 0 {
                style::lost("audit")
            } else {
                style::warn("audit")
            },
            audit_summary.underidentified,
            audit_summary.conditional,
        );
    }
    println!();
    println!("  type a verb or ask anything:");
    println!("    i  inbox (pending)    l  log (recent)        s  refresh status");
    println!("    h  help (more verbs)  q  quit");
    println!();
}

/// Run a single verb shortcut. Returns true if the verb was recognized.
fn run_session_verb(verb: &str, repo_path: &Path) -> bool {
    match verb {
        "i" | "inbox" => {
            let action = ProposalAction::List {
                frontier: repo_path.to_path_buf(),
                status: Some("pending_review".into()),
                json: false,
            };
            cmd_proposals(action);
            true
        }
        "l" | "log" => {
            cmd_log(repo_path, 10, None, false);
            true
        }
        "s" | "status" | "refresh" => {
            // Reload + re-render dashboard.
            match repo::load_from_path(repo_path) {
                Ok(p) => print_session_dashboard(&p, repo_path),
                Err(e) => eprintln!("{} {e}", style::err_prefix()),
            }
            true
        }
        "h" | "help" | "?" => {
            print_session_help();
            true
        }
        _ => false,
    }
}

fn run_session() {
    let repo_path = match find_vela_repo() {
        Some(p) => p,
        None => {
            println!();
            println!(
                "  {}",
                "VELA · NO FRONTIER FOUND IN CWD OR ANY PARENT".dimmed()
            );
            println!("  {}", style::tick_row(60));
            println!("  Run `vela init` here to create a frontier, or cd into one.");
            println!("  Or run `vela help` for the command list.");
            println!();
            return;
        }
    };

    let project = match repo::load_from_path(&repo_path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{} failed to load .vela/ repo: {e}", style::err_prefix());
            std::process::exit(1);
        }
    };

    print_session_dashboard(&project, &repo_path);

    use std::io::{BufRead, Write};
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    loop {
        print!("  > ");
        stdout.flush().ok();
        let mut line = String::new();
        if stdin.lock().read_line(&mut line).is_err() {
            break;
        }
        let input = line.trim();
        if input.is_empty() {
            continue;
        }
        if matches!(input, "q" | "quit" | "exit") {
            break;
        }
        if run_session_verb(input, &repo_path) {
            continue;
        }
        // Fall through: treat as natural-language question.
        let project = match repo::load_from_path(&repo_path) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{} {e}", style::err_prefix());
                continue;
            }
        };
        answer(&project, input, false);
    }
}

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
        // Read-only claim projections: `vela claim {state,trust,pack,diff}`.
        // Intercepted ahead of the clap dispatcher (mirroring `proof
        // verify`) so they never collide with the existing
        // `vela claim <frontier> <obligation>` lease command. Pure
        // derivations over the accepted log — no writes, no new events.
        // `diff` is the Evidence Diff: a proposal's before/after effect.
        Some("claim")
            if matches!(
                args.get(2).map(String::as_str),
                Some("state" | "trust" | "pack" | "diff")
            ) =>
        {
            crate::cli_claim::run(&args);
            return;
        }
        // Math-atlas anchor links: `vela claim anchor|anchors|unanchor`.
        // `anchor`/`unanchor` WRITE a signed `val_` event (attach/retract an
        // external-catalogue anchor); `anchors` lists (read). Kept on a
        // separate arm so the read-only projections above stay pure.
        Some("claim")
            if matches!(
                args.get(2).map(String::as_str),
                Some("anchor" | "anchors" | "unanchor")
            ) =>
        {
            crate::cli_claim::run_anchor(&args);
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
    eprintln!("{} {message}", style::err_prefix());
    std::process::exit(1);
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

/// Render an Engine verdict under an accept (human output). Quiet on a
/// clean pass so the common case stays uncluttered; speaks up for
/// warnings and forced overrides.
/// P3.4: deliver a locally-applied accept to the hub under key custody. The
/// human has already signed + applied the accept on disk; this re-signs the
/// canonical accept preimage and POSTs it so the hub records the same
/// decision. Best-effort and non-fatal: any failure is logged, the local
/// accept stands, and the returned JSON reports the outcome.
fn deliver_accept_to_hub(
    frontier: &std::path::Path,
    proposal_id: &str,
    reviewer: &str,
    reason: &str,
    key: Option<&std::path::Path>,
    to: Option<&str>,
    json: bool,
) -> serde_json::Value {
    let Some(signing_key) = crate::cli_identity::resolve_signing_key_opt(key) else {
        if !json {
            eprintln!(
                "  ! --push needs a signing key (--key or `vela id create`); local accept applied, hub delivery skipped"
            );
        }
        return json!({"ok": false, "error": "no signing key for hub delivery"});
    };
    let hub = crate::cli_identity::resolve_hub(to);
    let project = match repo::load_from_path(frontier) {
        Ok(p) => p,
        Err(e) => return json!({"ok": false, "error": format!("load frontier: {e}")}),
    };
    let vfr = project.frontier_id();
    let preimage = match proposals::accept_preimage_bytes(&vfr, proposal_id, reviewer, reason) {
        Ok(b) => b,
        Err(e) => return json!({"ok": false, "error": format!("accept preimage: {e}")}),
    };
    let sig_hex = hex::encode(sign::sign_bytes(&signing_key, &preimage));
    let pk_hex = sign::pubkey_hex(&signing_key);
    match vela_protocol::registry::post_accept_to_hub(
        &hub,
        &vfr,
        proposal_id,
        reason,
        &pk_hex,
        &sig_hex,
    ) {
        Ok((status, text)) => {
            let ok = (200..300).contains(&status);
            if !json {
                if ok {
                    println!("  hub:   delivered accept to {hub} (HTTP {status})");
                } else {
                    eprintln!("  ! hub accept delivery failed (HTTP {status}): {text}");
                    // The hub re-derives the reviewer id from the SIGNER KEY,
                    // not the --reviewer string. A signature-blaming 401 almost
                    // always means the key registers as a different actor than
                    // the name that was signed over.
                    if status == 401 && text.contains("does not verify") {
                        eprintln!(
                            "    hint: the hub identifies the reviewer by your signing KEY, not the \
                             --reviewer name '{reviewer}'. Re-run with --reviewer set to the actor \
                             your key is registered under on this frontier, or fix your `vela id` profile."
                        );
                    }
                    eprintln!("    the local accept is applied; re-run with --push to retry.");
                }
            }
            json!({"ok": ok, "http_status": status, "hub": hub})
        }
        Err(e) => {
            if !json {
                eprintln!("  ! hub accept delivery failed: {e}");
                eprintln!("    the local accept is applied; re-run with --push to retry.");
            }
            json!({"ok": false, "error": e, "hub": hub})
        }
    }
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

#[cfg(test)]
mod surface_tests {
    //! Pins the released command surface to the clap enum, so the
    //! drift that silently broke `id` and `publish` this cycle (a real
    //! command rejected as "unknown or non-release") can never recur, and
    //! so the curated `help advanced` reference can never omit a command.
    use super::*;
    use clap::CommandFactory;

    /// Building the ~226-node clap tree needs more than a default test
    /// thread's 2 MiB stack (it is fine on the 8 MiB main thread, where the
    /// CLI actually runs), so each test runs its body on a roomy stack.
    fn on_big_stack(f: impl FnOnce() + Send + 'static) {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(f)
            .unwrap()
            .join()
            .unwrap();
    }

    fn released_names() -> Vec<String> {
        Cli::command()
            .get_subcommands()
            .map(|c| c.get_name().to_string())
            .collect()
    }

    #[test]
    fn every_clap_subcommand_is_released() {
        on_big_stack(|| {
            for name in released_names() {
                assert!(
                    is_science_subcommand(&name),
                    "clap exposes subcommand `{name}` but is_science_subcommand rejects it \
                     (a RELEASE_DENY entry, or a derivation bug) — it would 404 at dispatch"
                );
            }
        });
    }

    #[test]
    fn every_subcommand_is_documented_in_advanced_help() {
        on_big_stack(|| {
            let help = strict_help_text();
            for name in released_names() {
                // Commands curated out of the menu (DEPRECATED_FROM_HELP) stay
                // callable but are intentionally not listed; the guard applies
                // only to the canonical surface.
                if DEPRECATED_FROM_HELP.contains(&name.as_str()) {
                    continue;
                }
                let listed = help.lines().any(|l| {
                    let t = l.trim_start();
                    t == name || t.starts_with(&format!("{name} "))
                });
                assert!(
                    listed,
                    "subcommand `{name}` is not listed in `vela help advanced` \
                     (strict_help_text) — add a row so the reference stays complete, \
                     or add it to DEPRECATED_FROM_HELP if it is intentionally off-menu"
                );
            }
        });
    }

    /// The v0.700 released command set. A regression guard: later
    /// consolidation batches may NEST these (keeping a hidden top-level
    /// alias) but must never make one unreachable. `is_science_subcommand`
    /// counts aliases, so a nested-with-alias command still passes here.
    const V0700_BASELINE: &[&str] = &[
        "accept",
        "accept-batch",
        "actor",
        "attach",
        "attempt",
        "attest",
        "check",
        "claim",
        "completions",
        "diff",
        "doctor",
        "finding",
        "frontier",
        "gate",
        "history",
        "id",
        "inbox",
        "ingest",
        "init",
        "lean",
        "log",
        "normalize",
        "proof",
        "proposals",
        "propose",
        "publish",
        "queue",
        "registry",
        "reproduce",
        "serve",
        "sign",
        "status",
        "task",
        "transfer",
        "verify",
    ];

    #[test]
    fn v0700_baseline_commands_stay_reachable() {
        on_big_stack(|| {
            for name in V0700_BASELINE {
                assert!(
                    is_science_subcommand(name),
                    "v0.700 command `{name}` is no longer reachable — a consolidation \
                     dropped it instead of nesting-with-alias"
                );
            }
        });
    }
}
