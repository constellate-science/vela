use vela_protocol::{
    adoption_log, adoption_transcript, benchmark, bridge, bundle, carina_validate, conformance,
    correction_return, decision, diff, doctor, events, evidence_ci, export,
    frontier_health, frontier_incident, frontier_repo, frontier_task, impact, index_db, lint,
    normalize, packet, project, propagate, proposals, repo, research_trace, review, review_packet,
    review_session, reviewer_identity, search, share_package, sign, signals, source_inbox,
    source_resolver, sources, state, state_integrity, static_share, task_workspace, tensions,
    validate,
};
use crate::serve;

use std::collections::BTreeMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::OnceLock;

use clap::Parser;
use colored::Colorize;

use vela_protocol::cli_style as style;
use reqwest::Client;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[derive(Parser)]
#[command(name = "vela", version)]
#[command(about = "Portable frontier state for science")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

pub(crate) use crate::cli_bridge_kit::*;
pub(crate) use crate::cli_causal::*;
pub(crate) use crate::cli_check::*;
use crate::cli_commands::*;
pub(crate) use crate::cli_diff_pack::*;
pub(crate) use crate::cli_federation::*;
pub(crate) use crate::cli_finding::*;
pub(crate) use crate::cli_frontier::*;
pub(crate) use crate::cli_lean::*;
pub(crate) use crate::cli_owner_rotate::*;
pub(crate) use crate::cli_registry::*;
pub(crate) use crate::cli_source_fetch::*;

pub async fn run_command() {
    dotenvy::dotenv().ok();

    match Cli::parse().command {
        Commands::Scout {
            folder,
            frontier,
            backend,
            dry_run,
            json,
        } => {
            cmd_scout(&folder, &frontier, backend.as_deref(), dry_run, json).await;
        }
        Commands::CompileNotes {
            vault,
            frontier,
            backend,
            max_files,
            max_items_per_category,
            dry_run,
            json,
        } => {
            cmd_compile_notes(
                &vault,
                &frontier,
                backend.as_deref(),
                max_files,
                max_items_per_category,
                dry_run,
                json,
            )
            .await;
        }
        Commands::CompileCode {
            root,
            frontier,
            backend,
            max_files,
            dry_run,
            json,
        } => {
            cmd_compile_code(
                &root,
                &frontier,
                backend.as_deref(),
                max_files,
                dry_run,
                json,
            )
            .await;
        }
        Commands::CompileData {
            root,
            frontier,
            backend,
            sample_rows,
            dry_run,
            json,
        } => {
            cmd_compile_data(
                &root,
                &frontier,
                backend.as_deref(),
                sample_rows,
                dry_run,
                json,
            )
            .await;
        }
        Commands::ReviewPending {
            frontier,
            backend,
            max_proposals,
            batch_size,
            dry_run,
            json,
        } => {
            cmd_review_pending(
                &frontier,
                backend.as_deref(),
                max_proposals,
                batch_size,
                dry_run,
                json,
            )
            .await;
        }
        Commands::FindTensions {
            frontier,
            backend,
            max_findings,
            dry_run,
            json,
        } => {
            cmd_find_tensions(&frontier, backend.as_deref(), max_findings, dry_run, json).await;
        }
        Commands::PlanExperiments {
            frontier,
            backend,
            max_findings,
            dry_run,
            json,
        } => {
            cmd_plan_experiments(&frontier, backend.as_deref(), max_findings, dry_run, json).await;
        }
        Commands::Check {
            source,
            schema,
            stats,
            conformance,
            conformance_dir,
            all,
            schema_only,
            strict,
            fix,
            json,
        } => cmd_check(
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
        ),
        Commands::Integrity {
            frontier,
            json,
            strict,
        } => cmd_integrity(&frontier, json, strict),
        Commands::Impact {
            frontier,
            finding_id,
            depth,
            json,
        } => cmd_impact(&frontier, &finding_id, depth, json),
        Commands::Discord {
            frontier,
            json,
            kind,
        } => cmd_discord(&frontier, json, kind.as_deref()),
        Commands::EvidenceCi { frontier, json } => cmd_evidence_ci(&frontier, json),
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
        Commands::Repo { action } => cmd_repo(action),
        Commands::Serve {
            frontier,
            frontiers,
            backend,
            http,
            setup,
            check_tools,
            adoption,
            json,
            workbench,
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
                let source =
                    serve::ProjectSource::from_args(frontier.as_deref(), frontiers.as_deref());
                // Phase R: --workbench implies HTTP and serves web/.
                let resolved_port = if workbench {
                    Some(http.unwrap_or(3848))
                } else {
                    http
                };
                if let Some(port) = resolved_port {
                    serve::run_http(source, backend.as_deref(), port, workbench).await;
                } else {
                    serve::run(source, backend.as_deref()).await;
                }
            }
        }
        Commands::Status { frontier, json } => cmd_status(&frontier, json),
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
        Commands::Ask {
            frontier,
            question,
            json,
        } => cmd_ask(&frontier, &question.join(" "), json),
        Commands::Stats { frontier, json } => {
            if json {
                print_stats_json(&frontier);
            } else {
                cmd_stats(&frontier);
            }
        }
        Commands::Search {
            source,
            query,
            entity,
            r#type,
            all,
            limit,
            json,
        } => cmd_search(
            source.as_deref(),
            &query,
            entity.as_deref(),
            r#type.as_deref(),
            all.as_deref(),
            limit,
            json,
        ),
        Commands::Tensions {
            source,
            both_high,
            cross_domain,
            top,
            json,
        } => cmd_tensions(&source, both_high, cross_domain, top, json),
        Commands::Gaps { action } => cmd_gaps(action),
        Commands::Bridge {
            inputs,
            novelty,
            top,
        } => cmd_bridge(&inputs, novelty, top).await,
        Commands::Export {
            frontier,
            format,
            output,
        } => export::run(&frontier, &format, output.as_deref()),
        Commands::Packet { action } => cmd_packet(action),
        Commands::Trace { action } => cmd_trace(action),
        Commands::CorrectionReturn { action } => cmd_correction_return(action),
        Commands::Verify { path, json } => cmd_verify(&path, json),
        Commands::Bench {
            frontier,
            gold,
            candidate,
            sources,
            threshold,
            report,
            entity_gold,
            link_gold,
            suite,
            suite_ready,
            min_f1,
            min_precision,
            min_recall,
            no_thresholds,
            json,
        } => {
            // v0.26 VelaBench routing: presence of `--candidate`
            // selects the agent state-update scorer. The legacy
            // extraction harness keeps every other invocation
            // unchanged.
            if let Some(cand) = candidate.clone() {
                let Some(g) = gold.clone() else {
                    eprintln!(
                        "{} `vela bench --candidate <…>` requires `--gold <…>`",
                        style::err_prefix()
                    );
                    std::process::exit(2);
                };
                cmd_agent_bench(
                    &g,
                    &cand,
                    sources.as_deref(),
                    threshold,
                    report.as_deref(),
                    json,
                );
            } else {
                cmd_bench(BenchArgs {
                    frontier,
                    gold,
                    entity_gold,
                    link_gold,
                    suite,
                    suite_ready,
                    min_f1,
                    min_precision,
                    min_recall,
                    no_thresholds,
                    json,
                });
            }
        }
        Commands::Conformance { dir } => {
            let _ = conformance::run(&dir);
        }
        Commands::Gate { action } => cmd_gate(action),
        Commands::Attach {
            frontier,
            target,
            attachment_file,
            reviewer,
            reason,
            json,
        } => cmd_attach(&frontier, &target, &attachment_file, &reviewer, &reason, json),
        Commands::Reproduce { path, json } => cmd_reproduce(&path, json),
        Commands::Version => println!("vela {}", env!("CARGO_PKG_VERSION")),
        Commands::Sign { action } => cmd_sign(action),
        Commands::Actor { action } => cmd_actor(action),
        Commands::Federation { action } => cmd_federation(action),
        Commands::Causal { action } => cmd_causal(action),
        Commands::Frontier { action } => cmd_frontier(action),
        Commands::Queue { action } => cmd_queue(action),
        Commands::Registry { action } => cmd_registry(action),
        Commands::Init {
            path,
            name,
            template,
            no_git,
            json,
        } => cmd_init(&path, &name, &template, !no_git, json),
        Commands::Quickstart {
            path,
            name,
            reviewer,
            assertion,
            keys_out,
            json,
        } => cmd_quickstart(
            &path,
            &name,
            &reviewer,
            assertion.as_deref(),
            keys_out.as_deref(),
            json,
        ),
        Commands::Agent { action } => cmd_agent(action),
        Commands::Lock { path, check, json } => cmd_lock(&path, check, json),
        Commands::Doc { path, out, json } => cmd_doc(&path, out.as_deref(), json),
        Commands::Import { frontier, into } => cmd_import(&frontier, into.as_deref()),
        Commands::Diff {
            target,
            frontier_b,
            frontier,
            reviewer,
            from,
            json,
            quiet,
        } => {
            // v0.74.3: if the first positional looks like a
            // proposal id, route to proposals preview. Otherwise
            // treat it as a frontier path or `vfr_*` registry id
            // and run the two-frontier diff (v0.140 cross-frontier).
            if target.starts_with("vpr_") {
                let frontier_root = frontier
                    .clone()
                    .or_else(|| frontier_b.clone().map(std::path::PathBuf::from))
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
        Commands::SearchIndex { action } => cmd_search_index(action).await,
        Commands::Index { action } => cmd_index(action).await,
        Commands::Citation {
            target,
            frontier,
            format,
            locator,
            out,
            json,
        } => cmd_citation(target, frontier, format, locator, out, json),
        Commands::Credit {
            frontier,
            out,
            json,
        } => cmd_credit(frontier, out, json),
        Commands::Handle { handle, site, json } => cmd_handle_resolve(handle, site, json),
        Commands::Lean { action } => cmd_lean(action),
        Commands::Attempt { action } => crate::cli_lean::cmd_attempt(action),
        Commands::DiffPack { action } => cmd_diff_pack(action),
        Commands::Policy { action } => cmd_policy(action),
        Commands::Task { action } => cmd_task(action),
        Commands::ReviewPacket { action } => cmd_review_packet(action),
        Commands::ReviewSession { action } => cmd_review_session(action),
        Commands::SourceInbox { action } => cmd_source_inbox(action),
        Commands::Adoption { action } => cmd_adoption(action),
        Commands::Share { action } => cmd_share(action),
        Commands::Controller { action } => cmd_controller(action),
        Commands::Incident { action } => cmd_incident(action),
        Commands::Tool { action } => cmd_tool(action),
        Commands::Eval { action } => cmd_eval(action),
        Commands::Conflict { action } => cmd_conflict(action),
        Commands::Hub { action } => cmd_hub_spec(action),
        Commands::ReviewThread { action } => cmd_review_thread(action),
        Commands::Preprint {
            frontier,
            released_at,
            out,
            json,
        } => cmd_preprint(frontier, released_at, out, json),
        Commands::Crossref {
            frontier,
            release,
            member,
            prefix,
            depositor_name,
            depositor_email,
            resource_url,
            title,
            description,
            license,
            xml,
            out,
            json,
        } => cmd_crossref(
            frontier,
            release,
            member,
            prefix,
            depositor_name,
            depositor_email,
            resource_url,
            title,
            description,
            license,
            xml,
            out,
            json,
        ),
        Commands::ArtifactToState {
            frontier,
            packet,
            actor,
            apply_artifacts,
            json,
        } => cmd_artifact_to_state(&frontier, &packet, &actor, apply_artifacts, json),
        Commands::BridgeKit { action } => cmd_bridge_kit(action).await,
        Commands::SourceAdapter { action } => cmd_source_adapter(action).await,
        Commands::RuntimeAdapter { action } => cmd_runtime_adapter(action),
        Commands::Link { action } => cmd_link(action),
        Commands::Workbench {
            path,
            port,
            no_open,
        } => {
            if let Err(e) = crate::workbench::run(path, port, !no_open).await {
                fail(&e);
            }
        }
        Commands::Bridges { action } => cmd_bridges(action),
        Commands::Entity { action } => cmd_entity(action),
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
                entities,
                entities_reviewed,
                evidence_span,
                gap,
                negative_space,
                doi,
                pmid,
                year,
                journal,
                url,
                source_authors,
                conditions_text,
                species,
                in_vivo,
                in_vitro,
                human_data,
                clinical_trial,
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
                let parsed_entities = parse_entities(&entities);
                let parsed_evidence_spans = parse_evidence_spans(&evidence_span);
                for (name, etype) in &parsed_entities {
                    if !bundle::VALID_ENTITY_TYPES.contains(&etype.as_str()) {
                        fail(&format!(
                            "invalid entity type '{}' for '{}'. Valid: {}",
                            etype,
                            name,
                            bundle::VALID_ENTITY_TYPES.join(", "),
                        ));
                    }
                }
                let parsed_source_authors = source_authors
                    .map(|s| {
                        s.split(';')
                            .map(|a| a.trim().to_string())
                            .filter(|a| !a.is_empty())
                            .collect()
                    })
                    .unwrap_or_default();
                let parsed_species = species
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
                        entities: parsed_entities,
                        doi,
                        pmid,
                        year,
                        journal,
                        url,
                        source_authors: parsed_source_authors,
                        conditions_text,
                        species: parsed_species,
                        in_vivo,
                        in_vitro,
                        human_data,
                        clinical_trial,
                        entities_reviewed,
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
                entities,
                doi,
                pmid,
                year,
                journal,
                url,
                source_authors,
                conditions_text,
                species,
                in_vivo,
                in_vitro,
                human_data,
                clinical_trial,
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
                let parsed_entities = parse_entities(&entities);
                for (name, etype) in &parsed_entities {
                    if !bundle::VALID_ENTITY_TYPES.contains(&etype.as_str()) {
                        fail(&format!(
                            "invalid entity type '{}' for '{}'. Valid: {}",
                            etype,
                            name,
                            bundle::VALID_ENTITY_TYPES.join(", "),
                        ));
                    }
                }
                let parsed_source_authors = source_authors
                    .map(|s| {
                        s.split(';')
                            .map(|a| a.trim().to_string())
                            .filter(|a| !a.is_empty())
                            .collect()
                    })
                    .unwrap_or_default();
                let parsed_species = species
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
                        entities: parsed_entities,
                        doi,
                        pmid,
                        year,
                        journal,
                        url,
                        source_authors: parsed_source_authors,
                        conditions_text,
                        species: parsed_species,
                        in_vivo,
                        in_vitro,
                        human_data,
                        clinical_trial,
                        entities_reviewed: false,
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
        },
        Commands::Review {
            frontier,
            finding_id,
            status,
            reason,
            reviewer,
            apply,
            json,
        } => {
            let status = status.unwrap_or_else(|| fail_return("--status is required for review"));
            let reason = reason.unwrap_or_else(|| fail_return("--reason is required for review"));
            let report = state::review_finding(
                &frontier,
                &finding_id,
                state::ReviewOptions {
                    status,
                    reason,
                    reviewer,
                },
                apply,
            )
            .unwrap_or_else(|e| fail_return(&e));
            print_state_report(&report, json);
        }
        Commands::Note {
            frontier,
            finding_id,
            text,
            author,
            apply,
            json,
        } => {
            let report = state::add_note(&frontier, &finding_id, &text, &author, apply)
                .unwrap_or_else(|e| fail_return(&e));
            print_state_report(&report, json);
        }
        Commands::Caveat {
            frontier,
            finding_id,
            text,
            author,
            apply,
            json,
        } => {
            let report = state::caveat_finding(&frontier, &finding_id, &text, &author, apply)
                .unwrap_or_else(|e| fail_return(&e));
            print_state_report(&report, json);
        }
        Commands::Revise {
            frontier,
            finding_id,
            confidence,
            reason,
            reviewer,
            apply,
            json,
        } => {
            let report = state::revise_confidence(
                &frontier,
                &finding_id,
                state::ReviseOptions {
                    confidence,
                    reason,
                    reviewer,
                },
                apply,
            )
            .unwrap_or_else(|e| fail_return(&e));
            print_state_report(&report, json);
        }
        Commands::Reject {
            frontier,
            finding_id,
            reason,
            reviewer,
            apply,
            json,
        } => {
            let report = state::reject_finding(&frontier, &finding_id, &reviewer, &reason, apply)
                .unwrap_or_else(|e| fail_return(&e));
            print_state_report(&report, json);
        }
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
        Commands::ImportEvents { source, into, json } => {
            let report =
                review::import_review_events(&source, &into).unwrap_or_else(|e| fail_return(&e));
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": true,
                        "command": "import-events",
                        "source": report.source,
                        "target": into.display().to_string(),
                        "summary": {
                            "imported": report.imported,
                            "new": report.new,
                            "duplicate": report.duplicate,
                            "canonical_events_imported": report.events_imported,
                            "canonical_events_new": report.events_new,
                            "canonical_events_duplicate": report.events_duplicate,
                        }
                    }))
                    .expect("failed to serialize import-events response")
                );
            } else {
                println!("{report}");
            }
        }
        Commands::Retract {
            source,
            finding_id,
            reason,
            reviewer,
            apply,
            json,
        } => {
            let report = state::retract_finding(&source, &finding_id, &reviewer, &reason, apply)
                .unwrap_or_else(|e| fail_return(&e));
            print_state_report(&report, json);
        }
        Commands::LocatorRepair {
            frontier,
            atom_id,
            locator,
            reviewer,
            reason,
            apply,
            json,
        } => {
            cmd_locator_repair(
                &frontier,
                &atom_id,
                locator.as_deref(),
                &reviewer,
                &reason,
                apply,
                json,
            );
        }
        Commands::SourceFetch {
            identifier,
            cache,
            out,
            refresh,
            json,
        } => {
            cmd_source_fetch(&identifier, cache.as_deref(), out.as_deref(), refresh, json).await;
        }
        Commands::SpanRepair {
            frontier,
            finding_id,
            section,
            text,
            reviewer,
            reason,
            apply,
            json,
        } => {
            cmd_span_repair(
                &frontier,
                &finding_id,
                &section,
                &text,
                &reviewer,
                &reason,
                apply,
                json,
            );
        }
        Commands::ProofAdd {
            frontier,
            target_finding,
            tool,
            tool_version,
            script_path,
            name,
            reviewer,
            reason,
            json,
        } => {
            cmd_proof_add(
                &frontier,
                &target_finding,
                &tool,
                &tool_version,
                &script_path,
                &name,
                &reviewer,
                &reason,
                json,
            );
        }
        Commands::ProofAttestVerification {
            proof_id,
            tool,
            tool_version,
            script_locator,
            lake_manifest_hash,
            verifier_output_hash,
            status,
            verifier_actor,
            key,
            out,
            json,
        } => cmd_proof_attest_verification(
            proof_id,
            tool,
            tool_version,
            script_locator,
            lake_manifest_hash,
            verifier_output_hash,
            status,
            verifier_actor,
            key,
            out,
            json,
        ),
        Commands::ProofVerifyAttestation { record, json } => {
            cmd_proof_verify_attestation(record, json)
        }
        Commands::EntityAdd {
            frontier,
            finding_id,
            entity,
            entity_type,
            reviewer,
            reason,
            apply,
            json,
        } => {
            let report = state::add_finding_entity(
                &frontier,
                &finding_id,
                &entity,
                &entity_type,
                &reviewer,
                &reason,
                apply,
            )
            .unwrap_or_else(|e| fail_return(&e));
            print_state_report(&report, json);
        }
        Commands::EntityResolve {
            frontier,
            finding_id,
            entity,
            source,
            id,
            confidence,
            matched_name,
            resolution_method,
            reviewer,
            reason,
            apply,
            json,
        } => {
            cmd_entity_resolve(
                &frontier,
                &finding_id,
                &entity,
                &source,
                &id,
                confidence,
                matched_name.as_deref(),
                &resolution_method,
                &reviewer,
                &reason,
                apply,
                json,
            );
        }
        Commands::Propagate {
            frontier,
            retract,
            reduce_confidence,
            to,
            output,
        } => cmd_propagate(&frontier, retract, reduce_confidence, to, output.as_deref()),
        Commands::Replicate {
            frontier,
            target,
            outcome,
            by,
            conditions,
            source_title,
            doi,
            pmid,
            sample_size,
            note,
            previous_attempt,
            no_cascade,
            json,
        } => cmd_replicate(
            &frontier,
            &target,
            &outcome,
            &by,
            &conditions,
            &source_title,
            doi.as_deref(),
            pmid.as_deref(),
            sample_size.as_deref(),
            &note,
            previous_attempt.as_deref(),
            no_cascade,
            json,
        ),
        Commands::Replications {
            frontier,
            target,
            json,
        } => cmd_replications(&frontier, target.as_deref(), json),
        Commands::DatasetAdd {
            frontier,
            name,
            version,
            content_hash,
            url,
            license,
            source_title,
            doi,
            row_count,
            json,
        } => cmd_dataset_add(
            &frontier,
            &name,
            version.as_deref(),
            &content_hash,
            url.as_deref(),
            license.as_deref(),
            &source_title,
            doi.as_deref(),
            row_count,
            json,
        ),
        Commands::Datasets { frontier, json } => cmd_datasets(&frontier, json),
        Commands::CodeAdd {
            frontier,
            language,
            repo_url,
            commit,
            path,
            content_hash,
            line_start,
            line_end,
            entry_point,
            json,
        } => cmd_code_add(
            &frontier,
            &language,
            repo_url.as_deref(),
            commit.as_deref(),
            &path,
            &content_hash,
            line_start,
            line_end,
            entry_point.as_deref(),
            json,
        ),
        Commands::CodeArtifacts { frontier, json } => cmd_code_artifacts(&frontier, json),
        Commands::ArtifactAdd {
            frontier,
            kind,
            name,
            file,
            url,
            content_hash,
            media_type,
            license,
            source_title,
            source_url,
            doi,
            target,
            metadata,
            access_tier,
            deposited_by,
            reason,
            json,
        } => cmd_artifact_add(
            &frontier,
            &kind,
            &name,
            file.as_deref(),
            url.as_deref(),
            content_hash.as_deref(),
            media_type.as_deref(),
            license.as_deref(),
            source_title.as_deref(),
            source_url.as_deref(),
            doi.as_deref(),
            target,
            metadata,
            &access_tier,
            &deposited_by,
            &reason,
            json,
        ),
        Commands::Artifacts {
            frontier,
            target,
            json,
        } => cmd_artifacts(&frontier, target.as_deref(), json),
        Commands::ArtifactAudit { frontier, json } => cmd_artifact_audit(&frontier, json),
        Commands::DecisionBrief { frontier, json } => cmd_decision_brief(&frontier, json),
        Commands::ReviewWork { frontier, json } => cmd_review_work(&frontier, json),
        Commands::TrialSummary { frontier, json } => cmd_trial_summary(&frontier, json),
        Commands::SourceVerification { frontier, json } => cmd_source_verification(&frontier, json),
        Commands::SourceIngestPlan { frontier, json } => cmd_source_ingest_plan(&frontier, json),
        Commands::ClinicalTrialImport {
            frontier,
            nct_id,
            input_json,
            target,
            deposited_by,
            reason,
            license,
            json,
        } => {
            cmd_clinical_trial_import(
                &frontier,
                &nct_id,
                input_json.as_deref(),
                target,
                &deposited_by,
                &reason,
                &license,
                json,
            )
            .await
        }
        Commands::NegativeResultAdd {
            frontier,
            kind,
            deposited_by,
            reason,
            conditions_text,
            notes,
            target,
            endpoint,
            intervention,
            comparator,
            population,
            n_enrolled,
            power,
            ci_lower,
            ci_upper,
            effect_size_threshold,
            registry_id,
            reagent,
            observation,
            attempts,
            source_title,
            doi,
            url,
            year,
            json,
        } => cmd_negative_result_add(
            &frontier,
            &kind,
            &deposited_by,
            &reason,
            &conditions_text,
            &notes,
            target,
            endpoint.as_deref(),
            intervention.as_deref(),
            comparator.as_deref(),
            population.as_deref(),
            n_enrolled,
            power,
            ci_lower,
            ci_upper,
            effect_size_threshold,
            registry_id.as_deref(),
            reagent.as_deref(),
            observation.as_deref(),
            attempts,
            &source_title,
            doi.as_deref(),
            url.as_deref(),
            year,
            json,
        ),
        Commands::NegativeResults {
            frontier,
            target,
            json,
        } => cmd_negative_results(&frontier, target.as_deref(), json),
        Commands::TrajectoryCreate {
            frontier,
            deposited_by,
            reason,
            target,
            notes,
            json,
        } => cmd_trajectory_create(&frontier, &deposited_by, &reason, target, &notes, json),
        Commands::TrajectoryStep {
            frontier,
            trajectory_id,
            kind,
            description,
            actor,
            reason,
            reference,
            json,
        } => cmd_trajectory_step(
            &frontier,
            &trajectory_id,
            &kind,
            &description,
            &actor,
            &reason,
            reference,
            json,
        ),
        Commands::Trajectories {
            frontier,
            target,
            json,
        } => cmd_trajectories(&frontier, target.as_deref(), json),
        Commands::TierSet {
            frontier,
            object_type,
            object_id,
            tier,
            actor,
            reason,
            json,
        } => cmd_tier_set(
            &frontier,
            &object_type,
            &object_id,
            &tier,
            &actor,
            &reason,
            json,
        ),
        Commands::Predict {
            frontier,
            by,
            claim,
            criterion,
            resolves_by,
            confidence,
            target,
            outcome,
            conditions,
            json,
        } => cmd_predict(
            &frontier,
            &by,
            &claim,
            &criterion,
            resolves_by.as_deref(),
            confidence,
            &target,
            &outcome,
            &conditions,
            json,
        ),
        Commands::Resolve {
            frontier,
            prediction,
            outcome,
            matched,
            by,
            confidence,
            source_title,
            doi,
            json,
        } => cmd_resolve(
            &frontier,
            &prediction,
            &outcome,
            matched,
            &by,
            confidence,
            &source_title,
            doi.as_deref(),
            json,
        ),
        Commands::Predictions {
            frontier,
            by,
            open,
            json,
        } => cmd_predictions(&frontier, by.as_deref(), open, json),
        Commands::Calibration {
            frontier,
            actor,
            json,
        } => cmd_calibration(&frontier, actor.as_deref(), json),
        Commands::PredictionsExpire {
            frontier,
            now,
            dry_run,
            json,
        } => cmd_predictions_expire(&frontier, now.as_deref(), dry_run, json),
        Commands::Consensus {
            frontier,
            target,
            weighting,
            causal_claim,
            causal_grade_min,
            json,
        } => cmd_consensus(
            &frontier,
            &target,
            &weighting,
            causal_claim.as_deref(),
            causal_grade_min.as_deref(),
            json,
        ),

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
            // finding.review proposal under reviewer authority.
            let options = state::ReviewOptions {
                status: status.clone(),
                reason: reason.clone(),
                reviewer: reviewer.clone(),
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
            strict,
            force,
            json,
        } => {
            // The Engine runs Evidence CI on the post-accept state and gates
            // the acceptance on the regression it would introduce.
            let outcome = proposals::accept_at_path_engine(
                &frontier,
                &proposal_id,
                &reviewer,
                &reason,
                proposals::AcceptOptions { strict, force },
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
            json,
        } => {
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
                proposals::AcceptOptions { strict, force },
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

        Commands::Lineage {
            frontier,
            finding_id,
            as_of,
            json,
        } => {
            // Mirror Commands::History at cli.rs:3231.
            let payload = state::history_as_of(&frontier, &finding_id, as_of.as_deref())
                .unwrap_or_else(|e| fail_return(&e));
            if json {
                print_json(&payload);
            } else {
                print_history(&payload);
            }
        }

        Commands::Carina { action } => cmd_carina(action),

        Commands::Atlas { action } => cmd_atlas(action).await,

        Commands::Constellation { action } => cmd_constellation(action).await,
    }
}

/// v0.78: handler for `vela atlas <action>`. Routes through the
/// binary-installed handlers (registered in `vela-cli/src/main.rs`)
/// so the substrate library stays free of the `vela-atlas`
/// dependency.
async fn cmd_atlas(action: AtlasAction) {
    match action {
        AtlasAction::Init {
            name,
            frontiers,
            domain,
            scope_note,
            atlases_root,
            json,
        } => match ATLAS_INIT_HANDLER.get() {
            Some(handler) => {
                handler(atlases_root, name, domain, scope_note, frontiers, json).await;
            }
            None => fail("vela atlas init: handler not registered (built without vela-atlas)"),
        },
        AtlasAction::Materialize {
            name,
            atlases_root,
            json,
        } => match ATLAS_MATERIALIZE_HANDLER.get() {
            Some(handler) => handler(atlases_root, name, json).await,
            None => fail("vela atlas materialize: handler not registered"),
        },
        AtlasAction::Serve {
            name,
            atlases_root,
            port,
            no_open,
        } => {
            // v0.78 stub: route to the per-frontier Workbench for
            // the first composing frontier in the manifest.
            // Atlas-level Workbench page lands in v0.79+.
            match ATLAS_SERVE_HANDLER.get() {
                Some(handler) => handler(atlases_root, name, port, !no_open).await,
                None => fail("vela atlas serve: handler not registered"),
            }
        }
        AtlasAction::Update {
            name,
            add_frontier,
            remove_vfr_id,
            atlases_root,
            json,
        } => match ATLAS_UPDATE_HANDLER.get() {
            Some(handler) => {
                handler(atlases_root, name, add_frontier, remove_vfr_id, json).await;
            }
            None => fail("vela atlas update: handler not registered"),
        },
    }
}

/// v0.82: handler for `vela constellation <action>`. Routes
/// through binary-installed handlers calling into the
/// `vela-constellation` crate.
async fn cmd_constellation(action: ConstellationAction) {
    match action {
        ConstellationAction::Init {
            name,
            atlases,
            scope_note,
            constellations_root,
            json,
        } => match CONSTELLATION_INIT_HANDLER.get() {
            Some(handler) => {
                handler(constellations_root, name, scope_note, atlases, json).await;
            }
            None => fail(
                "vela constellation init: handler not registered (built without vela-constellation)",
            ),
        },
        ConstellationAction::Materialize {
            name,
            constellations_root,
            json,
        } => match CONSTELLATION_MATERIALIZE_HANDLER.get() {
            Some(handler) => handler(constellations_root, name, json).await,
            None => fail("vela constellation materialize: handler not registered"),
        },
        ConstellationAction::Serve {
            name,
            constellations_root,
            port,
            no_open,
        } => match CONSTELLATION_SERVE_HANDLER.get() {
            Some(handler) => handler(constellations_root, name, port, !no_open).await,
            None => fail("vela constellation serve: handler not registered"),
        },
    }
}

/// v0.75: handler for `vela carina <action>`. Each branch reaches
/// into the bundled schemas under `embedded/carina-schemas/`.
fn cmd_carina(action: CarinaAction) {
    match action {
        CarinaAction::List { json } => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": true,
                        "command": "carina.list",
                        "primitives": carina_validate::PRIMITIVE_NAMES,
                    }))
                    .expect("failed to serialize carina.list")
                );
            } else {
                println!("Carina primitives bundled with this build:");
                for name in carina_validate::PRIMITIVE_NAMES {
                    println!("  · {name}");
                }
            }
        }
        CarinaAction::Schema { primitive } => match carina_validate::schema_text(&primitive) {
            Some(text) => print!("{text}"),
            None => fail(&format!("carina: unknown primitive '{primitive}'")),
        },
        CarinaAction::Validate {
            path,
            primitive,
            json,
        } => {
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| fail_return(&format!("read {}: {e}", path.display())));
            let value: Value = serde_json::from_str(&text)
                .unwrap_or_else(|e| fail_return(&format!("parse {}: {e}", path.display())));
            // If the file is a primitives.v0.X.json aggregate,
            // validate every entry under `primitives`. Otherwise
            // validate the value as one primitive.
            // Each report entry: (input key, validation result with
            // optional detected-primitive name in the Ok branch).
            type CarinaValidateOutcome = Result<Option<&'static str>, Vec<String>>;
            let mut report: Vec<(String, CarinaValidateOutcome)> = Vec::new();
            if value.get("primitives").and_then(Value::as_object).is_some() && primitive.is_none() {
                let primitives = value.get("primitives").and_then(Value::as_object).unwrap();
                for (key, child) in primitives {
                    let outcome = carina_validate::validate(key, child)
                        .map(|()| carina_validate::detect_primitive(child));
                    report.push((key.clone(), outcome));
                }
            } else {
                let outcome = match primitive.as_deref() {
                    Some(name) => carina_validate::validate(name, &value).map(|()| {
                        carina_validate::PRIMITIVE_NAMES
                            .iter()
                            .copied()
                            .find(|p| *p == name)
                    }),
                    None => carina_validate::validate_auto(&value).map(Some),
                };
                let label = primitive.clone().unwrap_or_else(|| "<auto>".to_string());
                report.push((label, outcome));
            }

            let total = report.len();
            let pass = report.iter().filter(|(_, r)| r.is_ok()).count();
            let fail = total - pass;

            if json {
                let entries: Vec<Value> = report
                    .iter()
                    .map(|(label, r)| match r {
                        Ok(name) => json!({
                            "key": label,
                            "primitive": name,
                            "ok": true,
                        }),
                        Err(errs) => json!({
                            "key": label,
                            "ok": false,
                            "errors": errs,
                        }),
                    })
                    .collect();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": fail == 0,
                        "command": "carina.validate",
                        "file": path.display().to_string(),
                        "total": total,
                        "passed": pass,
                        "failed": fail,
                        "entries": entries,
                    }))
                    .expect("failed to serialize carina.validate")
                );
            } else {
                for (label, r) in &report {
                    match r {
                        Ok(Some(name)) => println!("  {} {label} (as {name})", style::ok("ok")),
                        Ok(None) => println!("  {} {label}", style::ok("ok")),
                        Err(errs) => {
                            println!("  {} {label}", style::lost("fail"));
                            for e in errs {
                                println!("      {e}");
                            }
                        }
                    }
                }
                println!();
                if fail == 0 {
                    println!("{} {pass}/{total} valid", style::ok("carina.validate"));
                } else {
                    println!(
                        "{} {pass}/{total} valid · {fail} failed",
                        style::lost("carina.validate")
                    );
                }
            }

            if fail > 0 {
                std::process::exit(1);
            }
        }
    }
}

/// v0.117: register a Carina Proof primitive (`vpf_*`) against a
/// finding. Hashes the proof script with sha256, builds a Carina
/// `Proof` JSON object (validated against the bundled
/// `proof.schema.json`), then deposits an artifact carrying the
/// proof metadata under the v0.75.6 pattern: `kind: source_file`,
/// `metadata.carina_kind: proof_script`, `metadata.carina_proof_tool`,
/// `metadata.carina_proof_tool_version`. The artifact event is
/// signed under the reviewer's actor id via `state::add_artifact`.
/// Returns a JSON envelope with the `vpf_*` id, the `va_*` id, the
/// applied event id, and the script's content hash.
#[allow(clippy::too_many_arguments)]
fn cmd_proof_add(
    frontier: &Path,
    target_finding: &str,
    tool: &str,
    tool_version: &str,
    script_path: &Path,
    name: &str,
    reviewer: &str,
    reason: &str,
    json_output: bool,
) {
    use std::collections::BTreeMap;

    // 1. Validate the target finding shape.
    if !target_finding.starts_with("vf_") {
        fail(&format!(
            "--target-finding must be a vf_* finding id; got `{target_finding}`"
        ));
    }
    // 2. Validate the tool against the proof.schema.json enum.
    let valid_tools = [
        "lean4", "coq", "isabelle", "agda", "metamath", "rocq", "other",
    ];
    if !valid_tools.contains(&tool) {
        fail(&format!(
            "--tool `{tool}` not in {valid_tools:?}; see embedded/carina-schemas/proof.schema.json"
        ));
    }

    // 3. Read + hash the proof script.
    let script_bytes = std::fs::read(script_path)
        .unwrap_or_else(|e| fail_return(&format!("read {}: {e}", script_path.display())));
    let script_hash_hex = hex::encode(Sha256::digest(&script_bytes));
    let script_locator = format!("sha256:{script_hash_hex}");

    // 4. Compute the vpf_* id deterministically from script hash +
    // tool + target_finding so re-running with the same inputs is
    // a stable no-op.
    let vpf_preimage = format!("{script_locator}|{tool}|{tool_version}|{target_finding}");
    let vpf_id = format!(
        "vpf_{}",
        &hex::encode(Sha256::digest(vpf_preimage.as_bytes()))[..16]
    );

    // 5. Build the Carina Proof primitive and validate it against
    // the bundled schema. The Rust validator stays authoritative.
    let verified_at = chrono::Utc::now().to_rfc3339();
    let proof_primitive = json!({
        "schema": "carina.proof.v0.3",
        "id": vpf_id,
        "tool": tool,
        "tool_version": tool_version,
        "script_locator": script_locator,
        // No verifier-output capture yet; reviewers attest the
        // proof verifies under their own toolchain. Future cycles
        // may auto-capture `lake build` output and hash it here.
        "verifier_output_hash": format!("sha256:{}", "0".repeat(64)),
        "verified_at": verified_at,
        "target_finding_id": target_finding,
    });
    if let Err(errs) = carina_validate::validate("proof", &proof_primitive) {
        fail(&format!(
            "constructed Proof primitive does not validate against proof.schema.json:\n  - {}",
            errs.join("\n  - ")
        ));
    }

    // 6. Build the Artifact (mirrors the v0.75.6 sidon-sets pattern).
    let mut metadata: BTreeMap<String, Value> = BTreeMap::new();
    metadata.insert(
        "carina_kind".to_string(),
        Value::String("proof_script".to_string()),
    );
    metadata.insert(
        "carina_proof_tool".to_string(),
        Value::String(tool.to_string()),
    );
    metadata.insert(
        "carina_proof_tool_version".to_string(),
        Value::String(tool_version.to_string()),
    );
    metadata.insert("carina_proof_id".to_string(), Value::String(vpf_id.clone()));
    metadata.insert(
        "carina_proof_target_finding".to_string(),
        Value::String(target_finding.to_string()),
    );

    let media_type = match tool {
        "lean4" | "rocq" => Some("text/x-lean".to_string()),
        "coq" => Some("text/x-coq".to_string()),
        "isabelle" => Some("text/x-isabelle".to_string()),
        "agda" => Some("text/x-agda".to_string()),
        "metamath" => Some("text/x-metamath".to_string()),
        _ => None,
    };

    let provenance = vela_protocol::bundle::Provenance {
        source_type: "code_repository".to_string(),
        doi: None,
        pmid: None,
        pmc: None,
        openalex_id: None,
        url: None,
        title: format!("Proof script for {target_finding} ({tool} {tool_version})"),
        authors: Vec::new(),
        year: None,
        journal: None,
        license: Some("Apache-2.0 OR MIT".to_string()),
        publisher: None,
        funders: Vec::new(),
        extraction: vela_protocol::bundle::Extraction::default(),
        review: None,
        citation_count: None,
    };

    let artifact_id = vela_protocol::bundle::Artifact::content_address(
        "source_file",
        name,
        &format!("sha256:{script_hash_hex}"),
        None,
        Some(&script_path.display().to_string()),
    );

    let artifact = vela_protocol::bundle::Artifact {
        id: artifact_id.clone(),
        kind: "source_file".to_string(),
        name: name.to_string(),
        content_hash: format!("sha256:{script_hash_hex}"),
        size_bytes: Some(script_bytes.len() as u64),
        media_type,
        storage_mode: "pointer".to_string(),
        locator: Some(script_path.display().to_string()),
        source_url: None,
        license: Some("Apache-2.0 OR MIT".to_string()),
        target_findings: vec![target_finding.to_string()],
        source_id: None,
        provenance,
        metadata,
        review_state: None,
        retracted: false,
        access_tier: vela_protocol::access_tier::AccessTier::default(),
        created: verified_at.clone(),
    };

    // 7. Deposit via the existing state::add_artifact path. This
    // emits an artifact.asserted canonical event signed under the
    // reviewer's actor id.
    let report = state::add_artifact(frontier, artifact, reviewer, reason)
        .unwrap_or_else(|e| fail_return(&e));

    // 8. Emit the JSON envelope or a human-readable summary.
    let payload = json!({
        "ok": true,
        "command": "proof-add",
        "frontier": frontier.display().to_string(),
        "target_finding": target_finding,
        "tool": tool,
        "tool_version": tool_version,
        "script_path": script_path.display().to_string(),
        "script_locator": script_locator,
        "size_bytes": script_bytes.len(),
        "vpf_id": vpf_id,
        "va_id": artifact_id,
        "applied_event_id": report.applied_event_id,
        "verified_at": verified_at,
        "reviewer": reviewer,
    });

    if json_output {
        print_json(&payload);
    } else {
        println!(
            "{} proof artifact deposited for {target_finding}",
            style::ok("ok")
        );
        println!("  vpf_id:   {vpf_id}");
        println!("  va_id:    {artifact_id}");
        println!("  locator:  {script_locator}");
        println!("  tool:     {tool} {tool_version}");
        if let Some(eid) = &report.applied_event_id {
            println!("  event:    {eid}");
        }
    }
}

/// v0.35 / v0.38.2: print consensus over claim-similar findings,
/// optionally filtered by causal claim type / minimum study grade.
fn cmd_consensus(
    frontier: &Path,
    target: &str,
    weighting_str: &str,
    causal_claim: Option<&str>,
    causal_grade_min: Option<&str>,
    json: bool,
) {
    use vela_protocol::bundle::{CausalClaim, CausalEvidenceGrade};

    if !target.starts_with("vf_") {
        fail(&format!("target `{target}` is not a vf_ finding id"));
    }
    let scheme =
        vela_protocol::aggregate::WeightingScheme::parse(weighting_str).unwrap_or_else(|e| fail_return(&e));

    let parsed_claim = match causal_claim {
        None => None,
        Some("correlation") => Some(CausalClaim::Correlation),
        Some("mediation") => Some(CausalClaim::Mediation),
        Some("intervention") => Some(CausalClaim::Intervention),
        Some(other) => fail_return(&format!(
            "invalid --causal-claim '{other}'; valid: correlation | mediation | intervention"
        )),
    };
    let parsed_grade = match causal_grade_min {
        None => None,
        Some("theoretical") => Some(CausalEvidenceGrade::Theoretical),
        Some("observational") => Some(CausalEvidenceGrade::Observational),
        Some("quasi_experimental") => Some(CausalEvidenceGrade::QuasiExperimental),
        Some("rct") => Some(CausalEvidenceGrade::Rct),
        Some(other) => fail_return(&format!(
            "invalid --causal-grade-min '{other}'; valid: theoretical | observational | quasi_experimental | rct"
        )),
    };
    let filter = vela_protocol::aggregate::AggregateFilter {
        causal_claim: parsed_claim,
        causal_grade_min: parsed_grade,
    };
    let project = repo::load_from_path(frontier).unwrap_or_else(|e| fail_return(&e));

    let result = vela_protocol::aggregate::consensus_for_with_filter(&project, target, scheme, &filter)
        .unwrap_or_else(|| fail_return(&format!("target `{target}` not in frontier")));

    if json {
        print_json(&result);
        return;
    }

    println!();
    println!(
        "  {}",
        format!(
            "VELA · CONSENSUS · {} ({})",
            result.target, result.weighting
        )
        .to_uppercase()
        .dimmed()
    );
    println!("  {}", style::tick_row(60));
    println!(
        "  target:           {}",
        truncate(&result.target_assertion, 80)
    );
    println!("  similar findings: {}", result.n_findings);
    println!(
        "  consensus:        {:.3}  ({:.3} – {:.3} 95% credible)",
        result.consensus_confidence, result.credible_interval_lo, result.credible_interval_hi
    );
    println!();
    println!("  constituents (sorted by weight):");
    let mut sorted = result.constituents.clone();
    sorted.sort_by(|a, b| {
        b.weight
            .partial_cmp(&a.weight)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    for c in sorted.iter().take(10) {
        let repls = if c.n_replications > 0 {
            format!("  ({}r {}f)", c.n_replicated, c.n_failed_replications)
        } else {
            String::new()
        };
        println!(
            "    · w={:.2}  raw={:.2}  adj={:.2}{}",
            c.weight, c.raw_score, c.adjusted_score, repls
        );
        println!("        {}", truncate(&c.assertion_text, 88));
    }
    if result.constituents.len() > 10 {
        println!("    ... ({} more)", result.constituents.len() - 10);
    }
}

/// v0.34: parse the `--outcome` CLI string into a structured
/// `ExpectedOutcome`. Accepted forms:
///   - `affirmed` / `falsified`
///   - `quant:VALUE±TOL UNITS`  (e.g. `quant:0.4±0.1 SD`)
///   - `cat:LABEL`              (e.g. `cat:full_approval`)
fn parse_expected_outcome(s: &str) -> Result<vela_protocol::bundle::ExpectedOutcome, String> {
    let trimmed = s.trim();
    if trimmed.eq_ignore_ascii_case("affirmed") {
        return Ok(vela_protocol::bundle::ExpectedOutcome::Affirmed);
    }
    if trimmed.eq_ignore_ascii_case("falsified") {
        return Ok(vela_protocol::bundle::ExpectedOutcome::Falsified);
    }
    if let Some(rest) = trimmed.strip_prefix("cat:") {
        return Ok(vela_protocol::bundle::ExpectedOutcome::Categorical {
            value: rest.to_string(),
        });
    }
    if let Some(rest) = trimmed.strip_prefix("quant:") {
        let (vt, units) = rest.split_once(' ').unwrap_or((rest, ""));
        let (val_s, tol_s) = vt
            .split_once('±')
            .or_else(|| vt.split_once("+/-"))
            .ok_or_else(|| format!("expected `quant:VALUE±TOL UNITS`, got `quant:{rest}`"))?;
        let value: f64 = val_s
            .parse()
            .map_err(|e| format!("bad quant value `{val_s}`: {e}"))?;
        let tolerance: f64 = tol_s
            .parse()
            .map_err(|e| format!("bad quant tolerance `{tol_s}`: {e}"))?;
        return Ok(vela_protocol::bundle::ExpectedOutcome::Quantitative {
            value,
            tolerance,
            units: units.to_string(),
        });
    }
    Err(format!(
        "unknown outcome `{s}`; expected one of: affirmed | falsified | quant:V±T units | cat:label"
    ))
}

/// v0.34: append a Prediction to a frontier and persist it.
#[allow(clippy::too_many_arguments)]
fn cmd_predict(
    frontier: &Path,
    by: &str,
    claim: &str,
    criterion: &str,
    resolves_by: Option<&str>,
    confidence: f64,
    target_csv: &str,
    outcome: &str,
    conditions_text: &str,
    json: bool,
) {
    if !(0.0..=1.0).contains(&confidence) {
        fail(&format!("confidence must be in [0, 1]; got {confidence}"));
    }
    let expected = parse_expected_outcome(outcome).unwrap_or_else(|e| fail_return(&e));

    let mut project = repo::load_from_path(frontier).unwrap_or_else(|e| fail_return(&e));

    let targets: Vec<String> = target_csv
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    for t in &targets {
        if !t.starts_with("vf_") {
            fail(&format!("target `{t}` is not a vf_ id"));
        }
        if !project.findings.iter().any(|f| f.id == *t) {
            fail(&format!("target `{t}` not present in frontier"));
        }
    }

    let lower = conditions_text.to_lowercase();
    let conditions = vela_protocol::bundle::Conditions {
        text: conditions_text.to_string(),
        species_verified: Vec::new(),
        species_unverified: Vec::new(),
        in_vitro: lower.contains("in vitro"),
        in_vivo: lower.contains("in vivo"),
        human_data: lower.contains("human") || lower.contains("clinical"),
        clinical_trial: lower.contains("clinical trial") || lower.contains("phase "),
        concentration_range: None,
        duration: None,
        age_group: None,
        cell_type: None,
    };

    let prediction = vela_protocol::bundle::Prediction::new(
        claim.to_string(),
        targets,
        None,
        resolves_by.map(|s| s.to_string()),
        criterion.to_string(),
        expected,
        by.to_string(),
        confidence,
        conditions,
    );

    if project.predictions.iter().any(|p| p.id == prediction.id) {
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "ok": false,
                    "command": "predict",
                    "reason": "prediction_already_exists",
                    "id": prediction.id,
                }))
                .expect("serialize")
            );
        } else {
            println!(
                "{} prediction {} already exists in {}; skipping.",
                style::warn("predict"),
                prediction.id,
                frontier.display()
            );
        }
        return;
    }

    let new_id = prediction.id.clone();
    project.predictions.push(prediction);
    repo::save_to_path(frontier, &project).unwrap_or_else(|e| fail_return(&e));

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": true,
                "command": "predict",
                "id": new_id,
                "made_by": by,
                "confidence": confidence,
                "frontier": frontier.display().to_string(),
            }))
            .expect("serialize predict result")
        );
    } else {
        println!();
        println!(
            "  {}",
            format!("VELA · PREDICT · {}", new_id)
                .to_uppercase()
                .dimmed()
        );
        println!("  {}", style::tick_row(60));
        println!("  by:           {by}");
        println!("  confidence:   {confidence:.3}");
        if let Some(d) = resolves_by {
            println!("  resolves by:  {d}");
        }
        println!("  outcome:      {outcome}");
        println!("  claim:        {}", truncate(claim, 88));
        println!();
        println!(
            "  {} prediction recorded in {}",
            style::ok("ok"),
            frontier.display()
        );
    }
}

/// v0.34: append a Resolution that closes out a Prediction.
#[allow(clippy::too_many_arguments)]
fn cmd_resolve(
    frontier: &Path,
    prediction_id: &str,
    actual_outcome: &str,
    matched: bool,
    by: &str,
    confidence: f64,
    source_title: &str,
    doi: Option<&str>,
    json: bool,
) {
    if !prediction_id.starts_with("vpred_") {
        fail(&format!("prediction `{prediction_id}` is not a vpred_ id"));
    }
    if !(0.0..=1.0).contains(&confidence) {
        fail(&format!("confidence must be in [0, 1]; got {confidence}"));
    }
    let mut project = repo::load_from_path(frontier).unwrap_or_else(|e| fail_return(&e));
    if !project.predictions.iter().any(|p| p.id == prediction_id) {
        fail(&format!(
            "prediction `{prediction_id}` not present in frontier"
        ));
    }

    let evidence = vela_protocol::bundle::Evidence {
        evidence_type: "experimental".to_string(),
        model_system: String::new(),
        species: None,
        method: "prediction_resolution".to_string(),
        sample_size: None,
        effect_size: None,
        p_value: None,
        replicated: false,
        replication_count: None,
        evidence_spans: if source_title.is_empty() {
            Vec::new()
        } else {
            vec![serde_json::json!({"text": source_title})]
        },
    };

    // If the resolver provided source provenance, embed it via the
    // evidence span (the Resolution carries Evidence; for v0.34 we
    // keep the structure minimal). DOI flows through evidence_spans
    // commentary; richer linking lands in v0.34.x.
    let _ = doi; // currently unused — placeholder for v0.34.x.

    let resolution = vela_protocol::bundle::Resolution::new(
        prediction_id.to_string(),
        actual_outcome.to_string(),
        matched,
        by.to_string(),
        evidence,
        confidence,
    );

    if project.resolutions.iter().any(|r| r.id == resolution.id) {
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "ok": false,
                    "command": "resolve",
                    "reason": "resolution_already_exists",
                    "id": resolution.id,
                }))
                .expect("serialize")
            );
        } else {
            println!(
                "{} resolution {} already exists in {}; skipping.",
                style::warn("resolve"),
                resolution.id,
                frontier.display()
            );
        }
        return;
    }

    let new_id = resolution.id.clone();
    project.resolutions.push(resolution);
    repo::save_to_path(frontier, &project).unwrap_or_else(|e| fail_return(&e));

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": true,
                "command": "resolve",
                "id": new_id,
                "prediction": prediction_id,
                "matched": matched,
                "frontier": frontier.display().to_string(),
            }))
            .expect("serialize resolve result")
        );
    } else {
        println!();
        println!(
            "  {}",
            format!("VELA · RESOLVE · {}", new_id)
                .to_uppercase()
                .dimmed()
        );
        println!("  {}", style::tick_row(60));
        println!("  prediction:   {prediction_id}");
        println!(
            "  matched:      {}",
            if matched {
                style::ok("yes")
            } else {
                style::lost("no")
            }
        );
        println!("  by:           {by}");
        println!("  outcome:      {}", truncate(actual_outcome, 80));
        println!();
        println!(
            "  {} resolution recorded in {}",
            style::ok("ok"),
            frontier.display()
        );
    }
}

/// v0.34: list predictions, with resolution state.
fn cmd_predictions(frontier: &Path, by: Option<&str>, open: bool, json: bool) {
    let project = repo::load_from_path(frontier).unwrap_or_else(|e| fail_return(&e));

    let resolved_ids: std::collections::HashSet<&str> = project
        .resolutions
        .iter()
        .map(|r| r.prediction_id.as_str())
        .collect();

    let mut filtered: Vec<&vela_protocol::bundle::Prediction> = project
        .predictions
        .iter()
        .filter(|p| by.is_none_or(|b| p.made_by == b))
        .filter(|p| !open || !resolved_ids.contains(p.id.as_str()))
        .collect();
    filtered.sort_by(|a, b| {
        a.resolves_by
            .as_deref()
            .unwrap_or("9999")
            .cmp(b.resolves_by.as_deref().unwrap_or("9999"))
    });

    if json {
        let payload: Vec<serde_json::Value> = filtered
            .iter()
            .map(|p| {
                json!({
                    "id": p.id,
                    "claim_text": p.claim_text,
                    "made_by": p.made_by,
                    "confidence": p.confidence,
                    "predicted_at": p.predicted_at,
                    "resolves_by": p.resolves_by,
                    "expected_outcome": p.expected_outcome,
                    "resolved": resolved_ids.contains(p.id.as_str()),
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": true,
                "command": "predictions",
                "frontier": frontier.display().to_string(),
                "count": payload.len(),
                "predictions": payload,
            }))
            .expect("serialize predictions")
        );
        return;
    }

    println!();
    println!(
        "  {}",
        format!("VELA · PREDICTIONS · {}", frontier.display())
            .to_uppercase()
            .dimmed()
    );
    println!("  {}", style::tick_row(60));
    if filtered.is_empty() {
        println!("  (no predictions matching filters)");
        return;
    }
    for p in &filtered {
        let resolved = resolved_ids.contains(p.id.as_str());
        let chip = if resolved {
            style::ok("resolved")
        } else {
            style::warn("open")
        };
        let deadline = p.resolves_by.as_deref().unwrap_or("(no deadline)");
        println!(
            "  · {}  {}  by {}  → {}",
            p.id.dimmed(),
            chip,
            p.made_by,
            deadline,
        );
        println!("      claim:      {}", truncate(&p.claim_text, 90));
        println!("      confidence: {:.2}", p.confidence);
    }
}

/// v0.34: print calibration scores per actor.
/// v0.40.1: Walk every prediction whose deadline has passed and mark
/// them as `expired_unresolved`. Emits one
/// `prediction.expired_unresolved` event per newly-expired prediction.
fn cmd_predictions_expire(frontier: &Path, now_override: Option<&str>, dry_run: bool, json: bool) {
    use chrono::DateTime;

    let now_dt = match now_override {
        Some(s) => DateTime::parse_from_rfc3339(s)
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .unwrap_or_else(|e| fail_return(&format!("invalid --now '{s}': {e}"))),
        None => chrono::Utc::now(),
    };

    let mut project = repo::load_from_path(frontier).unwrap_or_else(|e| fail_return(&e));
    if dry_run {
        // Run on a clone so we don't actually mutate.
        let mut probe = repo::load_from_path(frontier).unwrap_or_else(|e| fail_return(&e));
        let report = vela_protocol::calibration::expire_overdue_predictions(&mut probe, now_dt);
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "ok": true,
                    "command": "predictions.expire",
                    "dry_run": true,
                    "report": report,
                }))
                .expect("serialize predictions.expire (dry-run)")
            );
        } else {
            println!(
                "{} dry-run @ {}: {} would expire, {} already expired, {} resolved, {} still open",
                style::ok("ok"),
                report.now,
                report.newly_expired.len(),
                report.already_expired.len(),
                report.already_resolved.len(),
                report.still_open.len(),
            );
            for id in &report.newly_expired {
                println!("  · {id}");
            }
        }
        return;
    }

    let report = vela_protocol::calibration::expire_overdue_predictions(&mut project, now_dt);
    repo::save_to_path(frontier, &project).unwrap_or_else(|e| fail_return(&e));

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": true,
                "command": "predictions.expire",
                "report": report,
            }))
            .expect("serialize predictions.expire")
        );
    } else {
        println!(
            "{} @ {}: {} newly expired, {} already expired, {} resolved, {} still open",
            style::ok("expired"),
            report.now,
            report.newly_expired.len(),
            report.already_expired.len(),
            report.already_resolved.len(),
            report.still_open.len(),
        );
        for id in &report.newly_expired {
            println!("  · {id}");
        }
    }
}

fn cmd_calibration(frontier: &Path, actor: Option<&str>, json: bool) {
    let project = repo::load_from_path(frontier).unwrap_or_else(|e| fail_return(&e));
    let records = match actor {
        Some(a) => {
            vela_protocol::calibration::calibration_for_actor(a, &project.predictions, &project.resolutions)
                .map(|r| vec![r])
                .unwrap_or_default()
        }
        None => vela_protocol::calibration::calibration_records(&project.predictions, &project.resolutions),
    };

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": true,
                "command": "calibration",
                "frontier": frontier.display().to_string(),
                "filter_actor": actor,
                "records": records,
            }))
            .expect("serialize calibration")
        );
        return;
    }

    println!();
    println!(
        "  {}",
        format!("VELA · CALIBRATION · {}", frontier.display())
            .to_uppercase()
            .dimmed()
    );
    println!("  {}", style::tick_row(60));
    if records.is_empty() {
        println!("  (no calibration records)");
        return;
    }
    for r in &records {
        println!("  · {}", r.actor);
        println!(
            "      predictions: {}  resolved: {}  hits: {}",
            r.n_predictions, r.n_resolved, r.n_hit
        );
        match r.hit_rate {
            Some(h) => println!("      hit rate:    {:.1}%", h * 100.0),
            None => println!("      hit rate:    n/a"),
        }
        match r.brier_score {
            Some(b) => println!(
                "      brier:       {:.4}  (lower is better; 0.25 = chance)",
                b
            ),
            None => println!("      brier:       n/a"),
        }
        match r.log_score {
            Some(l) => println!(
                "      log score:   {:.4}  (higher is better; 0 = perfect)",
                l
            ),
            None => println!("      log score:   n/a"),
        }
    }
}

/// v0.33: append a Dataset record to a frontier and persist it.
#[allow(clippy::too_many_arguments)]
fn cmd_dataset_add(
    frontier: &Path,
    name: &str,
    version: Option<&str>,
    content_hash: &str,
    url: Option<&str>,
    license: Option<&str>,
    source_title: &str,
    doi: Option<&str>,
    row_count: Option<u64>,
    json: bool,
) {
    let mut project = repo::load_from_path(frontier).unwrap_or_else(|e| fail_return(&e));

    let provenance = vela_protocol::bundle::Provenance {
        source_type: "data_release".to_string(),
        doi: doi.map(|s| s.to_string()),
        pmid: None,
        pmc: None,
        openalex_id: None,
        url: url.map(|s| s.to_string()),
        title: source_title.to_string(),
        authors: Vec::new(),
        year: None,
        journal: None,
        license: license.map(|s| s.to_string()),
        publisher: None,
        funders: Vec::new(),
        extraction: vela_protocol::bundle::Extraction {
            method: "manual_curation".to_string(),
            model: None,
            model_version: None,
            extracted_at: chrono::Utc::now().to_rfc3339(),
            extractor_version: env!("CARGO_PKG_VERSION").to_string(),
        },
        review: None,
        citation_count: None,
    };

    let mut dataset = vela_protocol::bundle::Dataset::new(
        name.to_string(),
        version.map(|s| s.to_string()),
        content_hash.to_string(),
        url.map(|s| s.to_string()),
        license.map(|s| s.to_string()),
        provenance,
    );
    dataset.row_count = row_count;

    if project.datasets.iter().any(|d| d.id == dataset.id) {
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "ok": false,
                    "command": "dataset.add",
                    "reason": "dataset_already_exists",
                    "id": dataset.id,
                }))
                .expect("serialize")
            );
        } else {
            println!(
                "{} dataset {} already exists in {}; skipping.",
                style::warn("dataset"),
                dataset.id,
                frontier.display()
            );
        }
        return;
    }

    let new_id = dataset.id.clone();
    project.datasets.push(dataset);
    repo::save_to_path(frontier, &project).unwrap_or_else(|e| fail_return(&e));

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": true,
                "command": "dataset.add",
                "id": new_id,
                "name": name,
                "version": version,
                "frontier": frontier.display().to_string(),
            }))
            .expect("failed to serialize dataset.add result")
        );
    } else {
        println!();
        println!(
            "  {}",
            format!("VELA · DATASET · {}", new_id)
                .to_uppercase()
                .dimmed()
        );
        println!("  {}", style::tick_row(60));
        println!("  name:          {name}");
        if let Some(v) = version {
            println!("  version:       {v}");
        }
        println!("  content_hash:  {content_hash}");
        if let Some(u) = url {
            println!("  url:           {u}");
        }
        println!("  source:        {source_title}");
        println!();
        println!(
            "  {} dataset recorded in {}",
            style::ok("ok"),
            frontier.display()
        );
    }
}

/// v0.49: deposit a NegativeResult through `state::add_negative_result`.
/// Builds the kind-specific payload, validates the variant fields up
/// front (so a missing `--power` for a registered_trial deposit fails
/// at the CLI boundary rather than deep in the validator), and prints
/// either a stable JSON envelope or a formatted summary.
#[allow(clippy::too_many_arguments)]
fn cmd_negative_result_add(
    frontier: &Path,
    kind: &str,
    deposited_by: &str,
    reason: &str,
    conditions_text: &str,
    notes: &str,
    targets: Vec<String>,
    endpoint: Option<&str>,
    intervention: Option<&str>,
    comparator: Option<&str>,
    population: Option<&str>,
    n_enrolled: Option<u32>,
    power: Option<f64>,
    ci_lower: Option<f64>,
    ci_upper: Option<f64>,
    effect_size_threshold: Option<f64>,
    registry_id: Option<&str>,
    reagent: Option<&str>,
    observation: Option<&str>,
    attempts: Option<u32>,
    source_title: &str,
    doi: Option<&str>,
    url: Option<&str>,
    year: Option<i32>,
    json: bool,
) {
    let nr_kind = match kind {
        "registered_trial" => {
            let endpoint =
                endpoint.unwrap_or_else(|| fail_return("--endpoint required for registered_trial"));
            let intervention = intervention
                .unwrap_or_else(|| fail_return("--intervention required for registered_trial"));
            let comparator = comparator
                .unwrap_or_else(|| fail_return("--comparator required for registered_trial"));
            let population = population
                .unwrap_or_else(|| fail_return("--population required for registered_trial"));
            let n_enrolled = n_enrolled
                .unwrap_or_else(|| fail_return("--n-enrolled required for registered_trial"));
            let power =
                power.unwrap_or_else(|| fail_return("--power required for registered_trial"));
            let ci_lower =
                ci_lower.unwrap_or_else(|| fail_return("--ci-lower required for registered_trial"));
            let ci_upper =
                ci_upper.unwrap_or_else(|| fail_return("--ci-upper required for registered_trial"));
            vela_protocol::bundle::NegativeResultKind::RegisteredTrial {
                endpoint: endpoint.to_string(),
                intervention: intervention.to_string(),
                comparator: comparator.to_string(),
                population: population.to_string(),
                n_enrolled,
                power,
                effect_size_ci: (ci_lower, ci_upper),
                effect_size_threshold,
                registry_id: registry_id.map(|s| s.to_string()),
            }
        }
        "exploratory" => {
            let reagent =
                reagent.unwrap_or_else(|| fail_return("--reagent required for exploratory"));
            let observation = observation
                .unwrap_or_else(|| fail_return("--observation required for exploratory"));
            let attempts =
                attempts.unwrap_or_else(|| fail_return("--attempts required for exploratory"));
            vela_protocol::bundle::NegativeResultKind::Exploratory {
                reagent: reagent.to_string(),
                observation: observation.to_string(),
                attempts,
            }
        }
        other => fail_return(&format!(
            "--kind must be 'registered_trial' or 'exploratory', got '{other}'"
        )),
    };

    let conditions = vela_protocol::bundle::Conditions {
        text: conditions_text.to_string(),
        species_verified: Vec::new(),
        species_unverified: Vec::new(),
        in_vitro: false,
        in_vivo: false,
        human_data: false,
        clinical_trial: matches!(kind, "registered_trial"),
        concentration_range: None,
        duration: None,
        age_group: None,
        cell_type: None,
    };

    let provenance = vela_protocol::bundle::Provenance {
        source_type: if matches!(kind, "registered_trial") {
            "clinical_trial".to_string()
        } else {
            "lab_notebook".to_string()
        },
        doi: doi.map(|s| s.to_string()),
        pmid: None,
        pmc: None,
        openalex_id: None,
        url: url.map(|s| s.to_string()),
        title: source_title.to_string(),
        authors: Vec::new(),
        year,
        journal: None,
        license: None,
        publisher: None,
        funders: Vec::new(),
        extraction: vela_protocol::bundle::Extraction {
            method: "manual_curation".to_string(),
            model: None,
            model_version: None,
            extracted_at: chrono::Utc::now().to_rfc3339(),
            extractor_version: env!("CARGO_PKG_VERSION").to_string(),
        },
        review: None,
        citation_count: None,
    };

    let report = state::add_negative_result(
        frontier,
        nr_kind,
        targets,
        deposited_by,
        conditions,
        provenance,
        notes,
        reason,
    )
    .unwrap_or_else(|e| fail_return(&e));

    if json {
        print_json(&report);
    } else {
        println!();
        println!(
            "  {}",
            format!("VELA · NEGATIVE-RESULT · {}", report.finding_id)
                .to_uppercase()
                .dimmed()
        );
        println!("  {}", style::tick_row(60));
        println!("  kind:           {kind}");
        println!("  deposited_by:   {deposited_by}");
        if let Some(ev) = &report.applied_event_id {
            println!("  event:          {ev}");
        }
        println!(
            "  {} negative_result deposited in {}",
            style::ok("ok"),
            frontier.display()
        );
    }
}

/// v0.49: list NegativeResults in a frontier, optionally filtered by
/// the `vf_*` finding they bear against.
fn cmd_negative_results(frontier: &Path, target: Option<&str>, json: bool) {
    let project = repo::load_from_path(frontier).unwrap_or_else(|e| fail_return(&e));
    let filtered: Vec<&vela_protocol::bundle::NegativeResult> = project
        .negative_results
        .iter()
        .filter(|nr| {
            target
                .map(|t| nr.target_findings.iter().any(|f| f == t))
                .unwrap_or(true)
        })
        .collect();

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": true,
                "command": "negative_results",
                "frontier": frontier.display().to_string(),
                "count": filtered.len(),
                "negative_results": filtered,
            }))
            .expect("serialize negative_results")
        );
        return;
    }

    if filtered.is_empty() {
        println!("  no negative_results in {}", frontier.display());
        return;
    }

    println!();
    println!(
        "  {} ({})",
        "VELA · NEGATIVE RESULTS".dimmed(),
        filtered.len()
    );
    println!("  {}", style::tick_row(60));
    for nr in &filtered {
        let kind_label = match &nr.kind {
            vela_protocol::bundle::NegativeResultKind::RegisteredTrial {
                endpoint, power, ..
            } => format!("trial · {endpoint} · power {power:.2}"),
            vela_protocol::bundle::NegativeResultKind::Exploratory {
                reagent, attempts, ..
            } => format!("exploratory · {reagent} · {attempts} attempts"),
        };
        let retracted = if nr.retracted { " [retracted]" } else { "" };
        let review = nr
            .review_state
            .as_ref()
            .map(|s| format!(" [{s:?}]"))
            .unwrap_or_default();
        println!("  {}{}{}", nr.id, retracted, review);
        println!("    {kind_label}");
        if !nr.target_findings.is_empty() {
            println!("    targets: {}", nr.target_findings.join(", "));
        }
    }
    println!();
}

/// v0.51: re-classify a kernel object's read-side access tier.
#[allow(clippy::too_many_arguments)]
fn cmd_tier_set(
    frontier: &Path,
    object_type: &str,
    object_id: &str,
    tier: &str,
    actor: &str,
    reason: &str,
    json: bool,
) {
    let parsed_tier =
        vela_protocol::access_tier::AccessTier::parse(tier).unwrap_or_else(|e| fail_return(&e));
    let report = state::set_tier(frontier, object_type, object_id, parsed_tier, actor, reason)
        .unwrap_or_else(|e| fail_return(&e));

    if json {
        print_json(&report);
    } else {
        println!();
        println!(
            "  {}",
            format!("VELA · TIER · {}", object_id)
                .to_uppercase()
                .dimmed()
        );
        println!("  {}", style::tick_row(60));
        println!("  object_type:    {object_type}");
        println!("  new_tier:       {}", parsed_tier.canonical());
        println!("  actor:          {actor}");
        if let Some(ev) = &report.applied_event_id {
            println!("  event:          {ev}");
        }
        println!("  {} tier set in {}", style::ok("ok"), frontier.display());
    }
}

/// v0.50: open a Trajectory.
#[allow(clippy::too_many_arguments)]
fn cmd_trajectory_create(
    frontier: &Path,
    deposited_by: &str,
    reason: &str,
    targets: Vec<String>,
    notes: &str,
    json: bool,
) {
    let report = state::create_trajectory(frontier, targets, deposited_by, notes, reason)
        .unwrap_or_else(|e| fail_return(&e));

    if json {
        print_json(&report);
    } else {
        println!();
        println!(
            "  {}",
            format!("VELA · TRAJECTORY · {}", report.finding_id)
                .to_uppercase()
                .dimmed()
        );
        println!("  {}", style::tick_row(60));
        println!("  deposited_by:   {deposited_by}");
        if let Some(ev) = &report.applied_event_id {
            println!("  event:          {ev}");
        }
        println!(
            "  {} trajectory opened in {}",
            style::ok("ok"),
            frontier.display()
        );
    }
}

/// v0.50: append a step to a Trajectory.
#[allow(clippy::too_many_arguments)]
fn cmd_trajectory_step(
    frontier: &Path,
    trajectory_id: &str,
    kind: &str,
    description: &str,
    actor: &str,
    reason: &str,
    references: Vec<String>,
    json: bool,
) {
    let parsed_kind = match kind {
        // v0.50 legacy kinds
        "hypothesis" => vela_protocol::bundle::TrajectoryStepKind::Hypothesis,
        "tried" => vela_protocol::bundle::TrajectoryStepKind::Tried,
        "ruled_out" => vela_protocol::bundle::TrajectoryStepKind::RuledOut,
        "observed" => vela_protocol::bundle::TrajectoryStepKind::Observed,
        "refined" => vela_protocol::bundle::TrajectoryStepKind::Refined,
        // v0.194 vision-taxonomy kinds
        "question" => vela_protocol::bundle::TrajectoryStepKind::Question,
        "context" => vela_protocol::bundle::TrajectoryStepKind::Context,
        "data" => vela_protocol::bundle::TrajectoryStepKind::Data,
        "tool" => vela_protocol::bundle::TrajectoryStepKind::Tool,
        "model" => vela_protocol::bundle::TrajectoryStepKind::Model,
        "expert" => vela_protocol::bundle::TrajectoryStepKind::Expert,
        "decision" => vela_protocol::bundle::TrajectoryStepKind::Decision,
        "protocol" => vela_protocol::bundle::TrajectoryStepKind::Protocol,
        "output" => vela_protocol::bundle::TrajectoryStepKind::Output,
        "review" => vela_protocol::bundle::TrajectoryStepKind::Review,
        "risk" => vela_protocol::bundle::TrajectoryStepKind::Risk,
        "outcome" => vela_protocol::bundle::TrajectoryStepKind::Outcome,
        other => fail_return(&format!(
            "--kind must be one of: hypothesis|tried|ruled_out|observed|refined (v0.50 legacy) or question|context|data|tool|model|expert|decision|protocol|output|review|risk|outcome (v0.194 vision-taxonomy), got '{other}'"
        )),
    };
    let report = state::append_trajectory_step(
        frontier,
        trajectory_id,
        parsed_kind,
        description,
        actor,
        references,
        reason,
    )
    .unwrap_or_else(|e| fail_return(&e));

    if json {
        print_json(&report);
    } else {
        println!();
        println!(
            "  {}",
            format!("VELA · STEP · {}", report.finding_id)
                .to_uppercase()
                .dimmed()
        );
        println!("  {}", style::tick_row(60));
        println!("  trajectory:     {trajectory_id}");
        println!("  kind:           {kind}");
        println!("  actor:          {actor}");
        println!(
            "  {} step appended in {}",
            style::ok("ok"),
            frontier.display()
        );
    }
}

/// v0.50: list Trajectories in a frontier.
fn cmd_trajectories(frontier: &Path, target: Option<&str>, json: bool) {
    let project = repo::load_from_path(frontier).unwrap_or_else(|e| fail_return(&e));
    let filtered: Vec<&vela_protocol::bundle::Trajectory> = project
        .trajectories
        .iter()
        .filter(|t| {
            target
                .map(|tg| t.target_findings.iter().any(|f| f == tg))
                .unwrap_or(true)
        })
        .collect();

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": true,
                "command": "trajectories",
                "frontier": frontier.display().to_string(),
                "count": filtered.len(),
                "trajectories": filtered,
            }))
            .expect("serialize trajectories")
        );
        return;
    }

    if filtered.is_empty() {
        println!("  no trajectories in {}", frontier.display());
        return;
    }

    println!();
    println!("  {} ({})", "VELA · TRAJECTORIES".dimmed(), filtered.len());
    println!("  {}", style::tick_row(60));
    for t in &filtered {
        let retracted = if t.retracted { " [retracted]" } else { "" };
        let review = t
            .review_state
            .as_ref()
            .map(|s| format!(" [{s:?}]"))
            .unwrap_or_default();
        println!("  {}{}{}", t.id, retracted, review);
        println!(
            "    {} step(s){}",
            t.steps.len(),
            if t.target_findings.is_empty() {
                String::new()
            } else {
                format!(" · targets: {}", t.target_findings.join(", "))
            }
        );
        for step in &t.steps {
            // v0.194: delegate to canonical() so adding new enum
            // variants doesn't require updating this site.
            let label = step.kind.canonical();
            let preview: String = step.description.chars().take(80).collect();
            println!("      [{label}] {preview}");
        }
    }
    println!();
}

/// v0.33: list datasets in a frontier.
fn cmd_datasets(frontier: &Path, json: bool) {
    let project = repo::load_from_path(frontier).unwrap_or_else(|e| fail_return(&e));
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": true,
                "command": "datasets",
                "frontier": frontier.display().to_string(),
                "count": project.datasets.len(),
                "datasets": project.datasets,
            }))
            .expect("serialize datasets")
        );
        return;
    }
    println!();
    println!(
        "  {}",
        format!("VELA · DATASETS · {}", frontier.display())
            .to_uppercase()
            .dimmed()
    );
    println!("  {}", style::tick_row(60));
    if project.datasets.is_empty() {
        println!("  (no datasets registered)");
        return;
    }
    for ds in &project.datasets {
        let v = ds
            .version
            .as_deref()
            .map(|s| format!("@{s}"))
            .unwrap_or_default();
        println!("  · {}  {}{}", ds.id.dimmed(), ds.name, v);
        if let Some(u) = &ds.url {
            println!("      url:    {}", truncate(u, 80));
        }
        println!("      hash:   {}", truncate(&ds.content_hash, 80));
    }
}

/// v0.33: append a CodeArtifact record to a frontier and persist it.
#[allow(clippy::too_many_arguments)]
fn cmd_code_add(
    frontier: &Path,
    language: &str,
    repo_url: Option<&str>,
    commit: Option<&str>,
    path: &str,
    content_hash: &str,
    line_start: Option<u32>,
    line_end: Option<u32>,
    entry_point: Option<&str>,
    json: bool,
) {
    let mut project = repo::load_from_path(frontier).unwrap_or_else(|e| fail_return(&e));

    let line_range = match (line_start, line_end) {
        (Some(a), Some(b)) => Some((a, b)),
        (Some(a), None) => Some((a, a)),
        _ => None,
    };

    let artifact = vela_protocol::bundle::CodeArtifact::new(
        language.to_string(),
        repo_url.map(|s| s.to_string()),
        commit.map(|s| s.to_string()),
        path.to_string(),
        line_range,
        content_hash.to_string(),
        entry_point.map(|s| s.to_string()),
    );

    if project.code_artifacts.iter().any(|c| c.id == artifact.id) {
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "ok": false,
                    "command": "code.add",
                    "reason": "artifact_already_exists",
                    "id": artifact.id,
                }))
                .expect("serialize")
            );
        } else {
            println!(
                "{} code artifact {} already exists in {}; skipping.",
                style::warn("code"),
                artifact.id,
                frontier.display()
            );
        }
        return;
    }

    let new_id = artifact.id.clone();
    project.code_artifacts.push(artifact);
    repo::save_to_path(frontier, &project).unwrap_or_else(|e| fail_return(&e));

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": true,
                "command": "code.add",
                "id": new_id,
                "language": language,
                "path": path,
                "frontier": frontier.display().to_string(),
            }))
            .expect("failed to serialize code.add result")
        );
    } else {
        println!();
        println!(
            "  {}",
            format!("VELA · CODE · {}", new_id).to_uppercase().dimmed()
        );
        println!("  {}", style::tick_row(60));
        println!("  language:      {language}");
        if let Some(r) = repo_url {
            println!("  repo:          {r}");
        }
        if let Some(c) = commit {
            println!("  commit:        {c}");
        }
        println!("  path:          {path}");
        if let Some((a, b)) = line_range {
            println!("  lines:         {a}-{b}");
        }
        println!("  content_hash:  {content_hash}");
        println!();
        println!(
            "  {} code artifact recorded in {}",
            style::ok("ok"),
            frontier.display()
        );
    }
}

/// v0.33: list code artifacts in a frontier.
fn cmd_code_artifacts(frontier: &Path, json: bool) {
    let project = repo::load_from_path(frontier).unwrap_or_else(|e| fail_return(&e));
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": true,
                "command": "code-artifacts",
                "frontier": frontier.display().to_string(),
                "count": project.code_artifacts.len(),
                "code_artifacts": project.code_artifacts,
            }))
            .expect("serialize code-artifacts")
        );
        return;
    }
    println!();
    println!(
        "  {}",
        format!("VELA · CODE · {}", frontier.display())
            .to_uppercase()
            .dimmed()
    );
    println!("  {}", style::tick_row(60));
    if project.code_artifacts.is_empty() {
        println!("  (no code artifacts registered)");
        return;
    }
    for c in &project.code_artifacts {
        let lr = c
            .line_range
            .map(|(a, b)| format!(":{a}-{b}"))
            .unwrap_or_default();
        println!("  · {}  {} {}{}", c.id.dimmed(), c.language, c.path, lr);
        if let Some(r) = &c.repo_url {
            println!("      repo:   {}", truncate(r, 80));
        }
        if let Some(g) = &c.git_commit {
            println!("      commit: {g}");
        }
    }
}

fn sha256_for_bytes(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn sha256_hex_part(content_hash: &str) -> &str {
    content_hash.strip_prefix("sha256:").unwrap_or(content_hash)
}

fn artifact_blob_locator(frontier: &Path, content_hash: &str, bytes: &[u8]) -> Option<String> {
    let Ok(repo::VelaSource::VelaRepo(root)) = repo::detect(frontier) else {
        return None;
    };
    let hex = sha256_hex_part(content_hash);
    let rel = format!(".vela/artifact-blobs/sha256/{hex}");
    let path = root.join(&rel);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap_or_else(|e| {
            fail(&format!(
                "Failed to create artifact blob directory {}: {e}",
                parent.display()
            ))
        });
    }
    if !path.is_file() {
        std::fs::write(&path, bytes)
            .unwrap_or_else(|e| fail(&format!("Failed to write artifact blob: {e}")));
    }
    Some(rel)
}

fn parse_metadata_pairs(pairs: Vec<String>) -> BTreeMap<String, Value> {
    let mut out = BTreeMap::new();
    for pair in pairs {
        let Some((key, value)) = pair.split_once('=') else {
            fail(&format!("--metadata must be key=value, got {pair:?}"));
        };
        let key = key.trim();
        if key.is_empty() {
            fail("--metadata key must be non-empty");
        }
        out.insert(key.to_string(), Value::String(value.trim().to_string()));
    }
    out
}

fn artifact_source_type(kind: &str) -> &'static str {
    match kind {
        "clinical_trial_record" | "protocol" => "clinical_trial",
        "dataset" => "data_release",
        "model_output" => "model_output",
        "registry_record" => "database_record",
        "lab_file" => "lab_notebook",
        _ => "database_record",
    }
}

fn artifact_provenance(
    kind: &str,
    title: &str,
    url: Option<&str>,
    doi: Option<&str>,
    license: Option<&str>,
) -> vela_protocol::bundle::Provenance {
    vela_protocol::bundle::Provenance {
        source_type: artifact_source_type(kind).to_string(),
        doi: doi.map(str::to_string),
        pmid: None,
        pmc: None,
        openalex_id: None,
        url: url.map(str::to_string),
        title: title.to_string(),
        authors: Vec::new(),
        year: None,
        journal: None,
        license: license.map(str::to_string),
        publisher: None,
        funders: Vec::new(),
        extraction: vela_protocol::bundle::Extraction {
            method: "artifact_deposit".to_string(),
            model: None,
            model_version: None,
            extracted_at: chrono::Utc::now().to_rfc3339(),
            extractor_version: env!("CARGO_PKG_VERSION").to_string(),
        },
        review: None,
        citation_count: None,
    }
}

#[allow(clippy::too_many_arguments)]
fn cmd_artifact_add(
    frontier: &Path,
    kind: &str,
    name: &str,
    file: Option<&Path>,
    url: Option<&str>,
    content_hash: Option<&str>,
    media_type: Option<&str>,
    license: Option<&str>,
    source_title: Option<&str>,
    source_url: Option<&str>,
    doi: Option<&str>,
    target: Vec<String>,
    metadata: Vec<String>,
    access_tier: &str,
    deposited_by: &str,
    reason: &str,
    json_out: bool,
) {
    let tier =
        vela_protocol::access_tier::AccessTier::parse(access_tier).unwrap_or_else(|e| fail_return(&e));
    let mut size_bytes = None;
    let mut storage_mode = "pointer".to_string();
    let mut locator = url.map(str::to_string);
    let mut computed_hash = content_hash.map(str::to_string);

    if let Some(path) = file {
        let bytes = std::fs::read(path)
            .unwrap_or_else(|e| fail(&format!("Failed to read artifact file: {e}")));
        let actual_hash = sha256_for_bytes(&bytes);
        if let Some(expected) = content_hash {
            let expected_hex = sha256_hex_part(expected);
            let actual_hex = sha256_hex_part(&actual_hash);
            if !expected_hex.eq_ignore_ascii_case(actual_hex) {
                fail(&format!(
                    "--content-hash does not match file bytes: expected {expected}, got {actual_hash}"
                ));
            }
        }
        size_bytes = Some(bytes.len() as u64);
        computed_hash = Some(actual_hash.clone());
        if let Some(rel) = artifact_blob_locator(frontier, &actual_hash, &bytes) {
            storage_mode = "local_blob".to_string();
            locator = Some(rel);
        } else {
            storage_mode = "local_file".to_string();
            locator = Some(path.display().to_string());
        }
    }

    let Some(content_hash) = computed_hash else {
        fail("Provide --content-hash unless --file is present.");
    };
    let content_hash_for_print = content_hash.clone();
    if file.is_none() && url.is_some() {
        storage_mode = "remote".to_string();
    }

    let source_url_effective = source_url.or(url);
    let source_title = source_title.unwrap_or(name);
    let provenance = artifact_provenance(kind, source_title, source_url_effective, doi, license);
    let metadata = parse_metadata_pairs(metadata);
    let artifact = vela_protocol::bundle::Artifact::new(
        kind.to_string(),
        name.to_string(),
        content_hash,
        size_bytes,
        media_type.map(str::to_string),
        storage_mode,
        locator,
        source_url_effective.map(str::to_string),
        license.map(str::to_string),
        target,
        provenance,
        metadata,
        tier,
    )
    .unwrap_or_else(|e| fail_return(&e));

    let artifact_id = artifact.id.clone();
    let report = state::add_artifact(frontier, artifact, deposited_by, reason)
        .unwrap_or_else(|e| fail_return(&e));

    if json_out {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": true,
                "command": "artifact.add",
                "id": artifact_id,
                "frontier": frontier.display().to_string(),
                "event": report.applied_event_id,
            }))
            .expect("serialize artifact.add")
        );
    } else {
        println!();
        println!(
            "  {}",
            format!("VELA · ARTIFACT · {}", artifact_id)
                .to_uppercase()
                .dimmed()
        );
        println!("  {}", style::tick_row(60));
        println!("  kind:          {kind}");
        println!("  name:          {name}");
        println!("  hash:          {content_hash_for_print}");
        println!(
            "  {} artifact recorded in {}",
            style::ok("ok"),
            frontier.display()
        );
    }
}

fn cmd_artifacts(frontier: &Path, target: Option<&str>, json_out: bool) {
    let project = repo::load_from_path(frontier).unwrap_or_else(|e| fail_return(&e));
    let filtered: Vec<&vela_protocol::bundle::Artifact> = project
        .artifacts
        .iter()
        .filter(|artifact| {
            target
                .map(|t| artifact.target_findings.iter().any(|f| f == t))
                .unwrap_or(true)
        })
        .collect();

    if json_out {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": true,
                "command": "artifacts",
                "frontier": frontier.display().to_string(),
                "count": filtered.len(),
                "artifacts": filtered,
            }))
            .expect("serialize artifacts")
        );
        return;
    }

    println!();
    println!(
        "  {}",
        format!("VELA · ARTIFACTS · {}", frontier.display())
            .to_uppercase()
            .dimmed()
    );
    println!("  {}", style::tick_row(60));
    if filtered.is_empty() {
        println!("  (no artifacts registered)");
        return;
    }
    for artifact in filtered {
        println!(
            "  · {}  {} · {}",
            artifact.id.dimmed(),
            artifact.kind,
            artifact.name
        );
        if let Some(locator) = &artifact.locator {
            println!("      locator: {}", truncate(locator, 88));
        }
        if !artifact.target_findings.is_empty() {
            println!("      targets: {}", artifact.target_findings.join(", "));
        }
    }
}

fn cmd_artifact_audit(frontier: &Path, json_out: bool) {
    let project = repo::load_from_path(frontier).unwrap_or_else(|e| fail_return(&e));
    let audit = vela_protocol::artifact_audit::audit_artifacts(frontier, &project);
    if json_out {
        print_json(&audit);
        if !audit.ok {
            std::process::exit(1);
        }
        return;
    }

    println!();
    println!(
        "  {}",
        format!("VELA · ARTIFACT AUDIT · {}", frontier.display())
            .to_uppercase()
            .dimmed()
    );
    println!("  {}", style::tick_row(60));
    println!("  artifacts: {}", audit.artifact_count);
    println!("  checked local blobs: {}", audit.checked_local_blobs);
    println!("  local blob bytes: {}", audit.local_blob_bytes);
    if !audit.by_kind.is_empty() {
        let kinds = audit
            .by_kind
            .iter()
            .map(|(kind, count)| format!("{kind}:{count}"))
            .collect::<Vec<_>>()
            .join(", ");
        println!("  kinds: {kinds}");
    }
    if audit.ok {
        println!("  {} artifact audit passed.", style::ok("ok"));
        return;
    }
    for issue in &audit.issues {
        println!(
            "  {} {} {}: {}",
            style::lost("invalid"),
            issue.id,
            issue.field,
            issue.message
        );
    }
    std::process::exit(1);
}

fn cmd_decision_brief(frontier: &Path, json_out: bool) {
    let project = repo::load_from_path(frontier).unwrap_or_else(|e| fail_return(&e));
    let report = decision::load_decision_brief(frontier, &project);
    if json_out {
        print_json(&report);
        if !report.ok {
            std::process::exit(1);
        }
        return;
    }
    println!();
    println!(
        "  {}",
        format!("VELA · DECISION BRIEF · {}", project.project.name)
            .to_uppercase()
            .dimmed()
    );
    println!("  {}", style::tick_row(60));
    if !report.ok {
        print_projection_issues(&report.issues, report.error.as_deref());
        std::process::exit(1);
    }
    let brief = report
        .projection
        .as_ref()
        .expect("ok decision report carries projection");
    // v0.326: a curated qualitative confidence word ("high") must
    // never stand without the measured substrate next to it. This
    // does not edit the curated brief; it surfaces reality beside it.
    let s = &project.stats;
    let substrate = format!(
        "substrate: {hi}/{n} findings >=0.80, avg {avg:.2}, {hr} human-reviewed, {ar} agent-reviewed",
        hi = s.confidence_distribution.high_gt_80,
        n = s.findings,
        avg = s.avg_confidence,
        hr = s.human_reviewed,
        ar = s.agent_reviewed,
    );
    if let Some(boundary) = &brief.projection_boundary {
        println!(
            "  projection boundary: {} · reviewer profile: {} · medical guidance: {} · outside review claimed: {}",
            boundary.status,
            boundary.reviewer_profile,
            boundary.counts_as_medical_guidance,
            boundary.outside_review_claimed
        );
        println!(
            "  agent confidence policy: {}",
            wrap_line(&boundary.agent_confidence_policy, 82)
        );
    }
    for question in &brief.questions {
        println!("  · {} · {}", question.id.dimmed(), question.title);
        println!("      answer: {}", wrap_line(&question.short_answer, 82));
        println!("      caveat: {}", wrap_line(&question.caveat, 82));
        println!(
            "      confidence (stated): {} — {}",
            question.confidence, substrate
        );
        let stated_high = question.confidence.to_lowercase().contains("high");
        if stated_high && s.confidence_distribution.high_gt_80 == 0 {
            println!(
                "      decision-readiness: NOT decision-ready — stated confidence exceeds the measured substrate (0 findings >=0.80)"
            );
        }
        println!("      support: {}", question.supporting_findings.join(", "));
        if !question.tension_findings.is_empty() {
            println!("      tensions: {}", question.tension_findings.join(", "));
        }
        if !question.gap_findings.is_empty() {
            println!("      gaps: {}", question.gap_findings.join(", "));
        }
        if !question.artifact_ids.is_empty() {
            println!("      artifacts: {}", question.artifact_ids.join(", "));
        }
        if !question.evidence_basis.is_empty() {
            println!("      source-backed basis:");
            for basis in &question.evidence_basis {
                println!(
                    "        · {} {} via {}",
                    basis.role.dimmed(),
                    basis.finding_id,
                    basis.source_locator
                );
                println!(
                    "          review: {}; caveat: {}",
                    basis.review_status,
                    wrap_line(&basis.caveat, 72)
                );
            }
        }
        println!(
            "      would change: {}",
            wrap_line(&question.what_would_change_this_answer, 82)
        );
    }
}

fn cmd_review_work(frontier: &Path, json_out: bool) {
    let payload = crate::workbench::build_review_work_json(frontier)
        .unwrap_or_else(|e| fail_return(&format!("review work failed: {e}")));
    if json_out {
        print_json(&payload);
        return;
    }

    let frontier_name = payload
        .get("frontier_name")
        .and_then(Value::as_str)
        .unwrap_or("frontier");
    let frontier_id = payload
        .get("frontier_id")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let total_open = payload
        .get("total_open")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let proof_status = payload
        .get("proof_status")
        .and_then(Value::as_str)
        .unwrap_or("unknown");

    println!();
    println!(
        "  {}",
        format!("Vela · review work · {frontier_name}").dimmed()
    );
    println!("  {}", style::tick_row(60));
    println!("  frontier: {frontier_id}");
    println!("  open rows: {total_open}");
    println!("  proof packet: {proof_status}");
    println!(
        "  boundary: read-only. This does not count as review and does not mutate frontier state."
    );

    if let Some(queues) = payload.get("queues").and_then(Value::as_array) {
        for queue in queues {
            let title = queue
                .get("title")
                .and_then(Value::as_str)
                .unwrap_or("queue");
            let count = queue.get("count").and_then(Value::as_u64).unwrap_or(0);
            let boundary = queue.get("boundary").and_then(Value::as_str).unwrap_or("");
            let examples = queue
                .get("examples")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .take(6)
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_else(|| "none".to_string());
            let artifacts = queue
                .get("operator_artifacts")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .take(6)
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_else(|| "none".to_string());
            println!();
            println!("  · {title}: {count}");
            if !examples.is_empty() {
                println!("      examples: {examples}");
            }
            if !artifacts.is_empty() {
                println!("      artifacts: {artifacts}");
            }
            if !boundary.is_empty() {
                println!("      boundary: {}", wrap_line(boundary, 78));
            }
        }
    }

    let commands = payload
        .get("validation_commands")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_else(|| "none".to_string());
    println!();
    println!("  validation commands: {commands}");
}

fn cmd_trial_summary(frontier: &Path, json_out: bool) {
    let project = repo::load_from_path(frontier).unwrap_or_else(|e| fail_return(&e));
    let report = decision::load_trial_outcomes(frontier, &project);
    if json_out {
        print_json(&report);
        if !report.ok {
            std::process::exit(1);
        }
        return;
    }
    println!();
    println!(
        "  {}",
        format!("VELA · TRIAL SUMMARY · {}", project.project.name)
            .to_uppercase()
            .dimmed()
    );
    println!("  {}", style::tick_row(60));
    if !report.ok {
        print_projection_issues(&report.issues, report.error.as_deref());
        std::process::exit(1);
    }
    let outcomes = report
        .projection
        .as_ref()
        .expect("ok trial report carries projection");
    for row in &outcomes.rows {
        println!("  · {} · {} ({})", row.id.dimmed(), row.program, row.drug);
        println!("      population: {}", wrap_line(&row.population, 82));
        println!("      endpoint: {}", wrap_line(&row.primary_endpoint, 82));
        println!("      cognition: {}", wrap_line(&row.cognitive_result, 82));
        println!("      biomarker: {}", wrap_line(&row.biomarker_result, 82));
        println!("      risk: {}", wrap_line(&row.aria_or_safety_result, 82));
        println!("      status: {}", wrap_line(&row.regulatory_status, 82));
        if !row.finding_ids.is_empty() {
            println!("      findings: {}", row.finding_ids.join(", "));
        }
        if !row.artifact_ids.is_empty() {
            println!("      artifacts: {}", row.artifact_ids.join(", "));
        }
    }
}

fn cmd_source_verification(frontier: &Path, json_out: bool) {
    let project = repo::load_from_path(frontier).unwrap_or_else(|e| fail_return(&e));
    let report = decision::load_source_verification(frontier, &project);
    if json_out {
        print_json(&report);
        if !report.ok {
            std::process::exit(1);
        }
        return;
    }
    println!();
    println!(
        "  {}",
        format!("VELA · SOURCE VERIFICATION · {}", project.project.name)
            .to_uppercase()
            .dimmed()
    );
    println!("  {}", style::tick_row(60));
    if !report.ok {
        print_projection_issues(&report.issues, report.error.as_deref());
        std::process::exit(1);
    }
    let verification = report
        .projection
        .as_ref()
        .expect("ok source verification report carries projection");
    println!("  verified_at: {}", verification.verified_at);
    for source in &verification.sources {
        println!("  · {} · {}", source.id.dimmed(), source.title);
        println!("      agency: {}", source.agency);
        println!("      url: {}", truncate(&source.url, 88));
        println!("      status: {}", wrap_line(&source.current_status, 82));
    }
}

fn cmd_source_ingest_plan(frontier: &Path, json_out: bool) {
    let project = repo::load_from_path(frontier).unwrap_or_else(|e| fail_return(&e));
    let report = decision::load_source_ingest_plan(frontier, &project);
    if json_out {
        print_json(&report);
        if !report.ok {
            std::process::exit(1);
        }
        return;
    }
    println!();
    println!(
        "  {}",
        format!("VELA · SOURCE INGEST PLAN · {}", project.project.name)
            .to_uppercase()
            .dimmed()
    );
    println!("  {}", style::tick_row(60));
    if !report.ok {
        print_projection_issues(&report.issues, report.error.as_deref());
        std::process::exit(1);
    }
    let plan = report
        .projection
        .as_ref()
        .expect("ok source ingest plan report carries projection");
    println!("  verified_at: {}", plan.verified_at);
    println!("  entries: {}", plan.entries.len());
    for entry in &plan.entries {
        println!(
            "  · {} · {} · {} · {}",
            entry.id.dimmed(),
            entry.category,
            entry.priority,
            entry.ingest_status
        );
        println!("      name: {}", wrap_line(&entry.name, 82));
        println!("      locator: {}", truncate(&entry.locator, 88));
        println!("      use: {}", wrap_line(&entry.target_use, 82));
        if let Some(id) = &entry.current_frontier_artifact_id {
            println!("      artifact: {id}");
        }
        if !entry.target_findings.is_empty() {
            println!("      findings: {}", entry.target_findings.join(", "));
        }
    }
}

fn print_projection_issues(issues: &[decision::ProjectionIssue], error: Option<&str>) {
    if let Some(error) = error {
        println!("  {} {error}", style::lost("unavailable"));
    }
    for issue in issues {
        println!(
            "  {} {}: {}",
            style::lost("invalid"),
            issue.path,
            issue.message
        );
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

fn clinical_str<'a>(study: &'a Value, pointer: &str) -> Option<&'a str> {
    study.pointer(pointer).and_then(Value::as_str)
}

fn clinical_string_array(study: &Value, pointer: &str) -> Vec<String> {
    study
        .pointer(pointer)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn clinical_named_array(study: &Value, pointer: &str, field: &str) -> Vec<String> {
    study
        .pointer(pointer)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.get(field).and_then(Value::as_str))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn insert_string_vec_metadata(
    metadata: &mut BTreeMap<String, Value>,
    key: &str,
    values: Vec<String>,
) {
    if values.is_empty() {
        return;
    }
    metadata.insert(
        key.to_string(),
        Value::Array(values.into_iter().map(Value::String).collect()),
    );
}

async fn cmd_clinical_trial_import(
    frontier: &Path,
    nct_id: &str,
    input_json: Option<&Path>,
    target: Vec<String>,
    deposited_by: &str,
    reason: &str,
    license: &str,
    json_out: bool,
) {
    let api_url = format!("https://clinicaltrials.gov/api/v2/studies/{nct_id}");
    let raw = if let Some(path) = input_json {
        std::fs::read_to_string(path)
            .unwrap_or_else(|e| fail(&format!("Failed to read ClinicalTrials.gov JSON: {e}")))
    } else {
        let response = reqwest::get(&api_url).await.unwrap_or_else(|e| {
            fail(&format!(
                "Failed to fetch ClinicalTrials.gov record {nct_id}: {e}"
            ))
        });
        let response = response.error_for_status().unwrap_or_else(|e| {
            fail(&format!(
                "Failed to fetch ClinicalTrials.gov record {nct_id}: {e}"
            ))
        });
        response.text().await.unwrap_or_else(|e| {
            fail(&format!(
                "Failed to read ClinicalTrials.gov record {nct_id}: {e}"
            ))
        })
    };
    let study: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|e| fail(&format!("Failed to parse ClinicalTrials.gov JSON: {e}")));
    let canonical_bytes = vela_protocol::canonical::to_canonical_bytes(&study)
        .unwrap_or_else(|e| fail(&format!("Failed to canonicalize trial JSON: {e}")));
    let content_hash = sha256_for_bytes(&canonical_bytes);
    let locator = artifact_blob_locator(frontier, &content_hash, &canonical_bytes)
        .unwrap_or_else(|| api_url.clone());
    let storage_mode = if locator.starts_with(".vela/") {
        "local_blob"
    } else {
        "remote"
    };

    let parsed_nct = clinical_str(&study, "/protocolSection/identificationModule/nctId")
        .unwrap_or(nct_id)
        .to_string();
    let title = clinical_str(&study, "/protocolSection/identificationModule/briefTitle")
        .or_else(|| {
            clinical_str(
                &study,
                "/protocolSection/identificationModule/officialTitle",
            )
        })
        .unwrap_or(nct_id);
    let public_url = format!("https://clinicaltrials.gov/study/{parsed_nct}");
    let mut metadata = BTreeMap::new();
    metadata.insert("nct_id".to_string(), Value::String(parsed_nct.clone()));
    metadata.insert(
        "source_api".to_string(),
        Value::String("clinicaltrials.gov-v2".to_string()),
    );
    metadata.insert(
        "retrieved_at".to_string(),
        Value::String(chrono::Utc::now().to_rfc3339()),
    );
    for (key, pointer) in [
        (
            "overall_status",
            "/protocolSection/statusModule/overallStatus",
        ),
        (
            "start_date",
            "/protocolSection/statusModule/startDateStruct/date",
        ),
        (
            "completion_date",
            "/protocolSection/statusModule/completionDateStruct/date",
        ),
    ] {
        if let Some(value) = clinical_str(&study, pointer) {
            metadata.insert(key.to_string(), Value::String(value.to_string()));
        }
    }
    insert_string_vec_metadata(
        &mut metadata,
        "phases",
        clinical_string_array(&study, "/protocolSection/designModule/phases"),
    );
    insert_string_vec_metadata(
        &mut metadata,
        "conditions",
        clinical_string_array(&study, "/protocolSection/conditionsModule/conditions"),
    );
    insert_string_vec_metadata(
        &mut metadata,
        "interventions",
        clinical_named_array(
            &study,
            "/protocolSection/armsInterventionsModule/interventions",
            "name",
        ),
    );
    insert_string_vec_metadata(
        &mut metadata,
        "primary_outcomes",
        clinical_named_array(
            &study,
            "/protocolSection/outcomesModule/primaryOutcomes",
            "measure",
        ),
    );
    if let Some(has_results) = study.get("hasResults").and_then(Value::as_bool) {
        metadata.insert("has_results".to_string(), Value::Bool(has_results));
    }

    let provenance = artifact_provenance(
        "clinical_trial_record",
        title,
        Some(&public_url),
        None,
        Some(license),
    );
    let artifact = vela_protocol::bundle::Artifact::new(
        "clinical_trial_record",
        title.to_string(),
        content_hash,
        Some(canonical_bytes.len() as u64),
        Some("application/json".to_string()),
        storage_mode.to_string(),
        Some(locator),
        Some(public_url.clone()),
        Some(license.to_string()),
        target,
        provenance,
        metadata,
        vela_protocol::access_tier::AccessTier::Public,
    )
    .unwrap_or_else(|e| fail_return(&e));
    let artifact_id = artifact.id.clone();
    let report = state::add_artifact(frontier, artifact, deposited_by, reason)
        .unwrap_or_else(|e| fail_return(&e));

    if json_out {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": true,
                "command": "clinical-trial-import",
                "nct_id": parsed_nct,
                "id": artifact_id,
                "frontier": frontier.display().to_string(),
                "event": report.applied_event_id,
                "source_url": public_url,
            }))
            .expect("serialize clinical-trial-import")
        );
    } else {
        println!();
        println!(
            "  {}",
            format!("VELA · CLINICAL TRIAL · {}", artifact_id)
                .to_uppercase()
                .dimmed()
        );
        println!("  {}", style::tick_row(60));
        println!("  nct_id:        {parsed_nct}");
        println!("  title:         {}", truncate(title, 96));
        println!("  source:        {public_url}");
        println!(
            "  {} trial record imported into {}",
            style::ok("ok"),
            frontier.display()
        );
    }
}

/// v0.32: append a Replication attempt to a frontier.
///
/// Validates the outcome label, builds a `Replication` with a fresh
/// content-addressed id, persists it, and prints either a structured
/// JSON receipt or a human summary. Refuses to write if the target
/// finding is not present in the frontier.
#[allow(clippy::too_many_arguments)]
fn cmd_replicate(
    frontier: &Path,
    target: &str,
    outcome: &str,
    attempted_by: &str,
    conditions_text: &str,
    source_title: &str,
    doi: Option<&str>,
    pmid: Option<&str>,
    sample_size: Option<&str>,
    note: &str,
    previous_attempt: Option<&str>,
    no_cascade: bool,
    json: bool,
) {
    if !vela_protocol::bundle::VALID_REPLICATION_OUTCOMES.contains(&outcome) {
        fail(&format!(
            "invalid outcome '{outcome}'; valid: {:?}",
            vela_protocol::bundle::VALID_REPLICATION_OUTCOMES
        ));
    }
    if !target.starts_with("vf_") {
        fail(&format!("target '{target}' is not a vf_ finding id"));
    }

    let mut project = repo::load_from_path(frontier).unwrap_or_else(|e| fail_return(&e));

    if !project.findings.iter().any(|f| f.id == target) {
        fail(&format!(
            "target finding '{target}' not present in frontier '{}'",
            frontier.display()
        ));
    }

    // Build the conditions, evidence, provenance for the replication.
    // Conditions text is what enters the content-address preimage; we
    // also lift in_vivo/in_vitro/human_data flags from common keywords
    // so confidence math behaves sensibly downstream.
    let lower = conditions_text.to_lowercase();
    let conditions = vela_protocol::bundle::Conditions {
        text: conditions_text.to_string(),
        species_verified: Vec::new(),
        species_unverified: Vec::new(),
        in_vitro: lower.contains("in vitro") || lower.contains("ipsc"),
        in_vivo: lower.contains("in vivo") || lower.contains("mouse") || lower.contains("rat"),
        human_data: lower.contains("human")
            || lower.contains("clinical")
            || lower.contains("patient"),
        clinical_trial: lower.contains("clinical trial") || lower.contains("phase "),
        concentration_range: None,
        duration: None,
        age_group: None,
        cell_type: None,
    };

    let evidence = vela_protocol::bundle::Evidence {
        evidence_type: "experimental".to_string(),
        model_system: String::new(),
        species: None,
        method: "replication_attempt".to_string(),
        sample_size: sample_size.map(|s| s.to_string()),
        effect_size: None,
        p_value: None,
        replicated: outcome == "replicated",
        replication_count: None,
        evidence_spans: Vec::new(),
    };

    let provenance = vela_protocol::bundle::Provenance {
        source_type: "published_paper".to_string(),
        doi: doi.map(|s| s.to_string()),
        pmid: pmid.map(|s| s.to_string()),
        pmc: None,
        openalex_id: None,
        url: None,
        title: source_title.to_string(),
        authors: Vec::new(),
        year: None,
        journal: None,
        license: None,
        publisher: None,
        funders: Vec::new(),
        extraction: vela_protocol::bundle::Extraction {
            method: "manual_curation".to_string(),
            model: None,
            model_version: None,
            extracted_at: chrono::Utc::now().to_rfc3339(),
            extractor_version: env!("CARGO_PKG_VERSION").to_string(),
        },
        review: None,
        citation_count: None,
    };

    let mut rep = vela_protocol::bundle::Replication::new(
        target.to_string(),
        attempted_by.to_string(),
        outcome.to_string(),
        evidence,
        conditions,
        provenance,
        note.to_string(),
    );
    rep.previous_attempt = previous_attempt.map(|s| s.to_string());

    // Refuse to write if the same vrep_id already exists (idempotent
    // re-runs are safe; conflicts surface here).
    if project.replications.iter().any(|r| r.id == rep.id) {
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "ok": false,
                    "command": "replicate",
                    "reason": "replication_already_exists",
                    "id": rep.id,
                }))
                .expect("serialize")
            );
        } else {
            println!(
                "{} replication {} already exists in {}; skipping.",
                style::warn("replicate"),
                rep.id,
                frontier.display()
            );
        }
        return;
    }

    let new_id = rep.id.clone();
    project.replications.push(rep);

    // v0.36.2: trigger the replication-aware propagation cascade. The
    // target's confidence is recomputed from the now-updated
    // `project.replications` collection (closes the A.1 loop) and
    // dependents are flagged for review with `upstream_replication_*`.
    // `inconclusive` outcomes do not cascade; we still call propagate
    // so the source-side recompute always runs.
    let cascade_result = if no_cascade {
        None
    } else {
        let result = propagate::propagate_correction(
            &mut project,
            target,
            propagate::PropagationAction::ReplicationOutcome {
                outcome: outcome.to_string(),
                vrep_id: new_id.clone(),
            },
        );
        // Persist propagation events into the canonical review log.
        // Without this, the events are emitted to stdout and lost.
        project.review_events.extend(result.events.clone());
        project::recompute_stats(&mut project);
        Some(result)
    };

    repo::save_to_path(frontier, &project).unwrap_or_else(|e| fail_return(&e));

    if json {
        let cascade_json = cascade_result.as_ref().map(|r| {
            json!({
                "affected": r.affected,
                "events": r.events.len(),
            })
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": true,
                "command": "replicate",
                "id": new_id,
                "target": target,
                "outcome": outcome,
                "attempted_by": attempted_by,
                "cascade": cascade_json,
                "frontier": frontier.display().to_string(),
            }))
            .expect("failed to serialize replicate result")
        );
    } else {
        println!();
        println!(
            "  {}",
            format!("VELA · REPLICATE · {}", new_id)
                .to_uppercase()
                .dimmed()
        );
        println!("  {}", style::tick_row(60));
        println!("  target:        {target}");
        println!("  outcome:       {outcome}");
        println!("  attempted by:  {attempted_by}");
        println!("  conditions:    {conditions_text}");
        println!("  source:        {source_title}");
        if let Some(d) = doi {
            println!("  doi:           {d}");
        }
        println!();
        println!(
            "  {} replication recorded in {}",
            style::ok("ok"),
            frontier.display()
        );
        if let Some(result) = cascade_result {
            println!(
                "  {} cascade: {} dependent(s) flagged, {} review event(s) recorded",
                style::ok("ok"),
                result.affected,
                result.events.len()
            );
        } else {
            println!("  {} cascade skipped (--no-cascade)", style::warn("info"));
        }
    }
}

/// v0.32: list replications in a frontier, optionally filtered by target.
fn cmd_replications(frontier: &Path, target: Option<&str>, json: bool) {
    let project = repo::load_from_path(frontier).unwrap_or_else(|e| fail_return(&e));
    let filtered: Vec<&vela_protocol::bundle::Replication> = project
        .replications
        .iter()
        .filter(|r| target.is_none_or(|t| r.target_finding == t))
        .collect();

    if json {
        let payload = json!({
            "ok": true,
            "command": "replications",
            "frontier": frontier.display().to_string(),
            "filter_target": target,
            "count": filtered.len(),
            "replications": filtered,
        });
        print_json(&payload);
        return;
    }

    println!();
    let header = match target {
        Some(t) => format!("VELA · REPLICATIONS · {t}"),
        None => format!("VELA · REPLICATIONS · {}", frontier.display()),
    };
    println!("  {}", header.to_uppercase().dimmed());
    println!("  {}", style::tick_row(60));
    if filtered.is_empty() {
        println!("  (no replications recorded)");
        return;
    }
    for rep in &filtered {
        let outcome_chip = match rep.outcome.as_str() {
            "replicated" => style::ok(&rep.outcome),
            "failed" => style::lost(&rep.outcome),
            "partial" => style::warn(&rep.outcome),
            _ => rep.outcome.clone().normal().to_string(),
        };
        println!(
            "  · {}  {}  by {}",
            rep.id.dimmed(),
            outcome_chip,
            rep.attempted_by
        );
        println!("      target:     {}", rep.target_finding);
        if !rep.conditions.text.is_empty() {
            println!("      conditions: {}", truncate(&rep.conditions.text, 80));
        }
        if !rep.provenance.title.is_empty() {
            println!("      source:     {}", truncate(&rep.provenance.title, 80));
        }
    }
}

/// v0.74: file-extension dispatcher for `vela ingest`. Routes one
/// path or stable identifier URI to the right backing path.
///
/// - `doi:` / `pmid:` / `nct:` URI -> `cmd_source_fetch`.
/// - JSON file (Carina-shaped artifact packet) -> `cmd_artifact_to_state`.
/// - PDF file or folder of PDFs -> `cmd_scout`. Folder is the
///   supported shape today; single-file mode lands in v0.74.2.
/// - Markdown file or folder -> `cmd_compile_notes`.
/// - CSV / TSV file or folder -> `cmd_compile_data`.
/// - Other directory -> `cmd_compile_code`.
///
/// No new substrate logic; just routing under one verb.
async fn cmd_ingest(
    path: &str,
    frontier: &Path,
    backend: Option<&str>,
    actor: Option<&str>,
    dry_run: bool,
    json: bool,
) {
    // Stable identifier URI: dispatch to source-fetch.
    let lowered = path.trim().to_lowercase();
    if lowered.starts_with("doi:") || lowered.starts_with("pmid:") || lowered.starts_with("nct:") {
        cmd_source_fetch(path.trim(), None, None, false, json).await;
        // v0.102: source-fetch only retrieves metadata into a local
        // cache; it does not create frontier state. Without this hint,
        // a fresh user thinks `vela ingest doi:...` "ingested the
        // paper" because the success-shaped output looks like a
        // proposal landed. It didn't. Tell them what to do next.
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

    // Single-file vs folder + extension routing.
    let ext = p
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| s.to_ascii_lowercase());

    if p.is_file() {
        match ext.as_deref() {
            Some("pdf") => {
                // v0.74.2: discover_files now accepts a single file
                // and returns a one-element vec, so we can pass
                // the PDF path itself directly to scout.
                cmd_scout(&p, frontier, backend, dry_run, json).await;
            }
            Some("md") | Some("markdown") => {
                // compile-notes also routes through discover_files
                // which handles the single-file case as of v0.74.2.
                cmd_compile_notes(&p, frontier, backend, None, None, dry_run, json).await;
            }
            Some("csv") | Some("tsv") => {
                // compile-data routes through discover_files; pass
                // the file path directly (v0.74.2).
                cmd_compile_data(&p, frontier, backend, None, dry_run, json).await;
            }
            Some("json") => {
                // Carina artifact packet path. Requires an actor id.
                let actor_id = actor.unwrap_or("agent:vela-ingest-bot");
                cmd_artifact_to_state(frontier, &p, actor_id, false, json);
            }
            other => {
                fail(&format!(
                    "ingest: unsupported file type '{}' (expected .pdf, .md, .csv, .tsv, .json, or a doi:/pmid:/nct: URI)",
                    other.unwrap_or("(none)")
                ));
            }
        }
        return;
    }

    if p.is_dir() {
        // v0.99: count files per handlable extension across the
        // first level. If multiple content types are present,
        // dispatch each handler in sequence rather than dropping
        // the non-dominant types silently. The previous v0.74
        // behavior picked one dominant type and ignored the rest,
        // which silently dropped mixed-source folders.
        let mut pdf_count = 0usize;
        let mut md_count = 0usize;
        let mut data_count = 0usize;
        let mut json_count = 0usize;
        let mut unhandled_exts: std::collections::BTreeSet<String> =
            std::collections::BTreeSet::new();
        if let Ok(entries) = std::fs::read_dir(&p) {
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }
                if let Some(name) = entry.file_name().to_str()
                    && let Some(dot) = name.rfind('.')
                {
                    let ext = name[dot + 1..].to_ascii_lowercase();
                    match ext.as_str() {
                        "pdf" => pdf_count += 1,
                        "md" | "markdown" => md_count += 1,
                        "csv" | "tsv" => data_count += 1,
                        "json" => json_count += 1,
                        other => {
                            // Track the unhandled extensions so we can
                            // report them at the end. Skip dotfiles.
                            if !name.starts_with('.') {
                                unhandled_exts.insert(other.to_string());
                            }
                        }
                    }
                }
            }
        }

        let dispatched_types = (pdf_count > 0) as usize
            + (md_count > 0) as usize
            + (data_count > 0) as usize
            + (json_count > 0) as usize;

        if dispatched_types == 0 {
            // No handlable content; treat as a code repo (the
            // pre-v0.99 fallback path).
            cmd_compile_code(&p, frontier, backend, None, dry_run, json).await;
            return;
        }

        if dispatched_types > 1 {
            eprintln!(
                "  vela ingest · folder has multiple handlable types; running each in sequence"
            );
            eprintln!(
                "    pdf:{pdf_count}  md:{md_count}  csv/tsv:{data_count}  json:{json_count}"
            );
        }

        // Dispatch in a stable order: PDFs first (richest content),
        // then notes, then data, then carina packets. Each handler
        // only opens files matching its own extension via
        // discover_files; non-matching files are silently skipped
        // by the inner handler, so dispatching all four against the
        // same folder is safe and idempotent on per-extension subsets.
        if pdf_count > 0 {
            cmd_scout(&p, frontier, backend, dry_run, json).await;
        }
        if md_count > 0 {
            cmd_compile_notes(&p, frontier, backend, None, None, dry_run, json).await;
        }
        if data_count > 0 {
            cmd_compile_data(&p, frontier, backend, None, dry_run, json).await;
        }
        if json_count > 0 {
            // Carina artifact packets are file-at-a-time. Walk the
            // directory and import each .json individually.
            let actor_id = actor.unwrap_or("agent:vela-ingest-bot");
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
                    }
                }
            }
        }

        if !unhandled_exts.is_empty() {
            let kinds: Vec<String> = unhandled_exts.into_iter().collect();
            eprintln!(
                "  vela ingest · skipped {} file extension(s) with no handler: {}",
                kinds.len(),
                kinds.join(", ")
            );
        }
        return;
    }

    fail(&format!(
        "ingest: path '{path}' is neither a file nor a directory"
    ));
}

#[allow(clippy::too_many_arguments)]
/// v0.25 Agent Inbox: dispatches the registered datasets handler.
async fn cmd_compile_data(
    root: &Path,
    frontier: &Path,
    backend: Option<&str>,
    sample_rows: Option<usize>,
    dry_run: bool,
    json_out: bool,
) {
    match DATASETS_HANDLER.get() {
        Some(handler) => {
            handler(
                root.to_path_buf(),
                frontier.to_path_buf(),
                backend.map(String::from),
                sample_rows,
                dry_run,
                json_out,
            )
            .await;
        }
        None => {
            eprintln!(
                "{} `vela compile-data` requires the vela CLI binary; the library is unwired without a registered datasets handler.",
                style::err_prefix()
            );
            std::process::exit(1);
        }
    }
}

/// v0.28 Agent Inbox: dispatches the registered reviewer-agent
/// handler.
async fn cmd_review_pending(
    frontier: &Path,
    backend: Option<&str>,
    max_proposals: Option<usize>,
    batch_size: usize,
    dry_run: bool,
    json_out: bool,
) {
    match REVIEWER_HANDLER.get() {
        Some(handler) => {
            handler(
                frontier.to_path_buf(),
                backend.map(String::from),
                max_proposals,
                batch_size,
                dry_run,
                json_out,
            )
            .await;
        }
        None => {
            eprintln!(
                "{} `vela review-pending` requires the vela CLI binary; the library is unwired without a registered reviewer handler.",
                style::err_prefix()
            );
            std::process::exit(1);
        }
    }
}

/// v0.28 Agent Inbox: dispatches the registered contradiction-finder
/// handler.
async fn cmd_find_tensions(
    frontier: &Path,
    backend: Option<&str>,
    max_findings: Option<usize>,
    dry_run: bool,
    json_out: bool,
) {
    match TENSIONS_HANDLER.get() {
        Some(handler) => {
            handler(
                frontier.to_path_buf(),
                backend.map(String::from),
                max_findings,
                dry_run,
                json_out,
            )
            .await;
        }
        None => {
            eprintln!(
                "{} `vela find-tensions` requires the vela CLI binary; the library is unwired without a registered tensions handler.",
                style::err_prefix()
            );
            std::process::exit(1);
        }
    }
}

/// v0.28 Agent Inbox: dispatches the registered experiment-planner
/// handler.
async fn cmd_plan_experiments(
    frontier: &Path,
    backend: Option<&str>,
    max_findings: Option<usize>,
    dry_run: bool,
    json_out: bool,
) {
    match EXPERIMENTS_HANDLER.get() {
        Some(handler) => {
            handler(
                frontier.to_path_buf(),
                backend.map(String::from),
                max_findings,
                dry_run,
                json_out,
            )
            .await;
        }
        None => {
            eprintln!(
                "{} `vela plan-experiments` requires the vela CLI binary; the library is unwired without a registered experiments handler.",
                style::err_prefix()
            );
            std::process::exit(1);
        }
    }
}

/// v0.24 Agent Inbox: dispatches the registered code-analyst
/// handler.
async fn cmd_compile_code(
    root: &Path,
    frontier: &Path,
    backend: Option<&str>,
    max_files: Option<usize>,
    dry_run: bool,
    json_out: bool,
) {
    match CODE_HANDLER.get() {
        Some(handler) => {
            handler(
                root.to_path_buf(),
                frontier.to_path_buf(),
                backend.map(String::from),
                max_files,
                dry_run,
                json_out,
            )
            .await;
        }
        None => {
            eprintln!(
                "{} `vela compile-code` requires the vela CLI binary; the library is unwired without a registered code handler.",
                style::err_prefix()
            );
            std::process::exit(1);
        }
    }
}

/// v0.23 Agent Inbox: dispatches the registered notes-compiler
/// handler. Same rationale as `cmd_scout` — the substrate stays
/// agent-free; the `vela` CLI binary registers the handler at
/// startup.
async fn cmd_compile_notes(
    vault: &Path,
    frontier: &Path,
    backend: Option<&str>,
    max_files: Option<usize>,
    max_items_per_category: Option<usize>,
    dry_run: bool,
    json_out: bool,
) {
    match NOTES_HANDLER.get() {
        Some(handler) => {
            handler(
                vault.to_path_buf(),
                frontier.to_path_buf(),
                backend.map(String::from),
                max_files,
                max_items_per_category,
                dry_run,
                json_out,
            )
            .await;
        }
        None => {
            eprintln!(
                "{} `vela compile-notes` requires the vela CLI binary; the library is unwired without a registered notes handler.",
                style::err_prefix()
            );
            std::process::exit(1);
        }
    }
}

/// v0.22 Agent Inbox: dispatches the registered scout handler. The
/// substrate library does not import `vela-scientist` (it would induce
/// a Cargo cycle); the `vela` CLI binary in `crates/vela-cli`
/// registers a handler at startup that calls into the scientist
/// crate. Running the lib directly without that registration prints
/// a clear error.
async fn cmd_scout(
    folder: &Path,
    frontier: &Path,
    backend: Option<&str>,
    dry_run: bool,
    json_out: bool,
) {
    match SCOUT_HANDLER.get() {
        Some(handler) => {
            handler(
                folder.to_path_buf(),
                frontier.to_path_buf(),
                backend.map(String::from),
                dry_run,
                json_out,
            )
            .await;
        }
        None => {
            eprintln!(
                "{} `vela scout` requires the vela CLI binary; the library is unwired without a registered scout handler.",
                style::err_prefix()
            );
            std::process::exit(1);
        }
    }
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
    let event_errors = replay_report
        .as_ref()
        .map_or(0, |replay| usize::from(!replay.ok));
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
    let errors =
        report.errors.len() + method_errors + graph_errors + event_errors + state_integrity_errors;
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

#[allow(clippy::too_many_arguments)]
fn cmd_normalize(
    source: &Path,
    out: Option<&Path>,
    write: bool,
    dry_run: bool,
    rewrite_ids: bool,
    id_map: Option<&Path>,
    resync_provenance: bool,
    json_output: bool,
) {
    if write && out.is_some() {
        fail("Use either --write or --out, not both.");
    }
    if dry_run && (write || out.is_some()) {
        fail("--dry-run cannot be combined with --write or --out.");
    }
    if id_map.is_some() && !rewrite_ids {
        fail("--id-map requires --rewrite-ids.");
    }

    let detected = repo::detect(source).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(1);
    });
    if matches!(detected, repo::VelaSource::PacketDir(_)) {
        fail(
            "Cannot normalize a proof packet directory. Export a new packet from frontier state instead.",
        );
    }
    let mut frontier = repo::load(&detected).unwrap_or_else(|e| fail_return(&e));
    // Phase J: every v0.4 frontier carries a `frontier.created` genesis
    // event in events[0]. That's identity metadata, not a substantive
    // mutation, so it doesn't disqualify normalization. Any non-genesis
    // canonical event still blocks normalize.
    let has_substantive_events = frontier
        .events
        .iter()
        .any(|event| event.kind != "frontier.created");
    if has_substantive_events && (write || out.is_some()) {
        fail(
            "Refusing to normalize a frontier with canonical events. Normalize before proposal-backed writes, or create a new reviewed transition for the intended change.",
        );
    }
    let source_hash = hash_path(source).unwrap_or_else(|_| "unavailable".to_string());
    let before_stats = serde_json::to_value(&frontier.stats).unwrap_or(Value::Null);
    let (entity_type_fixes, entity_name_fixes) =
        normalize::normalize_findings(&mut frontier.findings);
    let confidence_updates =
        bundle::recompute_all_confidence(&mut frontier.findings, &frontier.replications);
    // Phase N: optionally rewrite finding.provenance from the canonical
    // SourceRecord. The source registry is the authority; provenance is
    // the denormalized cache.
    let provenance_resync_count = if resync_provenance {
        sources::resync_provenance_from_sources(&mut frontier)
    } else {
        0
    };
    let before_source_count = frontier.sources.len();
    let before_evidence_atom_count = frontier.evidence_atoms.len();
    let before_condition_record_count = frontier.condition_records.len();

    let mut id_rewrites = Vec::new();
    if rewrite_ids {
        let mut id_map_values = std::collections::BTreeMap::<String, String>::new();
        for finding in &frontier.findings {
            let expected =
                bundle::FindingBundle::content_address(&finding.assertion, &finding.provenance);
            if expected != finding.id {
                id_map_values.insert(finding.id.clone(), expected);
            }
        }
        let new_ids = id_map_values
            .values()
            .map(String::as_str)
            .collect::<std::collections::HashSet<_>>();
        if new_ids.len() != id_map_values.len() {
            fail("Refusing to rewrite IDs because two findings map to the same content address.");
        }
        for finding in &mut frontier.findings {
            if let Some(new_id) = id_map_values.get(&finding.id) {
                id_rewrites.push(json!({"old": finding.id, "new": new_id}));
                finding.previous_version = Some(finding.id.clone());
                finding.id = new_id.clone();
            }
        }
        for finding in &mut frontier.findings {
            for link in &mut finding.links {
                if let Some(new_target) = id_map_values.get(&link.target) {
                    link.target = new_target.clone();
                }
            }
        }
        if let Some(path) = id_map {
            std::fs::write(
                path,
                serde_json::to_string_pretty(&id_map_values)
                    .expect("failed to serialize normalize id map"),
            )
            .unwrap_or_else(|e| fail(&format!("Failed to write {}: {e}", path.display())));
        }
    }

    sources::materialize_project(&mut frontier);
    let source_records_materialized = frontier.sources.len().saturating_sub(before_source_count);
    let evidence_atoms_materialized = frontier
        .evidence_atoms
        .len()
        .saturating_sub(before_evidence_atom_count);
    let condition_records_materialized = frontier
        .condition_records
        .len()
        .saturating_sub(before_condition_record_count);
    let after_stats = serde_json::to_value(&frontier.stats).unwrap_or(Value::Null);
    let id_rewrite_count = id_rewrites.len();
    let wrote_to = if write {
        repo::save(&detected, &frontier).unwrap_or_else(|e| fail(&e));
        Some(source.display().to_string())
    } else if let Some(out_path) = out {
        repo::save_to_path(out_path, &frontier).unwrap_or_else(|e| fail(&e));
        Some(out_path.display().to_string())
    } else {
        None
    };
    let wrote = wrote_to.is_some();
    let planned_changes = entity_type_fixes
        + entity_name_fixes
        + confidence_updates
        + id_rewrite_count
        + source_records_materialized
        + evidence_atoms_materialized
        + condition_records_materialized
        + provenance_resync_count;
    let payload = json!({
        "ok": true,
        "command": "normalize",
        "schema_version": project::VELA_SCHEMA_VERSION,
        "source": {
            "path": source.display().to_string(),
            "hash": format!("sha256:{source_hash}"),
        },
        "dry_run": wrote_to.is_none(),
        "wrote_to": wrote_to,
        "summary": {
            "planned": planned_changes,
            "safe": planned_changes,
            "unsafe": 0,
            "applied": if wrote { planned_changes } else { 0 },
        },
        "changes": {
            "entity_type_fixes": entity_type_fixes,
            "entity_name_fixes": entity_name_fixes,
            "confidence_updates": confidence_updates,
            "id_rewrites": id_rewrite_count,
            "source_records_materialized": source_records_materialized,
            "evidence_atoms_materialized": evidence_atoms_materialized,
            "condition_records_materialized": condition_records_materialized,
            "provenance_resyncs": provenance_resync_count,
            "stats_changed": before_stats != after_stats,
        },
        "id_rewrites": id_rewrites,
        "repair_plan": if wrote { Vec::<Value>::new() } else {
            vec![json!({
                "action": "apply_normalization",
                "command": "vela normalize <frontier> --out frontier.normalized.json"
            })]
        },
    });
    if json_output {
        print_json(&payload);
    } else if let Some(path) = payload.get("wrote_to").and_then(Value::as_str) {
        println!("{} normalized frontier written to {path}", style::ok("ok"));
        println!(
            "  entity type fixes: {}, entity name fixes: {}, confidence updates: {}, id rewrites: {}",
            entity_type_fixes, entity_name_fixes, confidence_updates, id_rewrite_count
        );
    } else {
        println!("normalize dry run for {}", source.display());
        println!(
            "  would apply entity type fixes: {}, entity name fixes: {}, confidence updates: {}, id rewrites: {}",
            entity_type_fixes, entity_name_fixes, confidence_updates, id_rewrite_count
        );
    }
}

fn cmd_proof(
    frontier: &Path,
    out: &Path,
    template: &str,
    gold: Option<&Path>,
    record_proof_state: bool,
    json_output: bool,
) {
    // The template is a label on the exported packet; the packet content is
    // derived from frontier state and is domain-neutral. `generic` exists so
    // a non-biomedical frontier (e.g. the Erdős open-problem frontier) gets a
    // domain-appropriate label rather than being forced under `bbb-alzheimer`.
    const SUPPORTED_TEMPLATES: &[&str] = &["bbb-alzheimer", "generic"];
    if !SUPPORTED_TEMPLATES.contains(&template) {
        fail(&format!(
            "Unsupported proof template '{template}'. Supported: {}",
            SUPPORTED_TEMPLATES.join(", ")
        ));
    }
    let proof_frontier = proof_load_path(frontier);
    let mut loaded = load_frontier_or_fail(&proof_frontier);
    let source_hash = hash_path_or_fail(&proof_frontier);
    let export_record = export::export_packet_with_source(&loaded, Some(frontier), out)
        .unwrap_or_else(|e| fail(&e));
    let benchmark_summary = gold.map(|gold_path| {
        let summary = benchmark::run_suite(gold_path).unwrap_or_else(|e| {
            fail(&format!(
                "Failed to run proof benchmark '{}': {e}",
                gold_path.display()
            ))
        });
        append_packet_json_file(out, "benchmark-summary.json", &summary).unwrap_or_else(|e| {
            fail(&format!("Failed to write benchmark summary: {e}"));
        });
        if summary.get("ok").and_then(Value::as_bool) != Some(true) {
            fail(&format!(
                "Proof benchmark failed for {}",
                gold_path.display()
            ));
        }
        summary
    });
    let validation_summary = packet::validate(out).unwrap_or_else(|e| {
        fail(&format!("Proof packet validation failed: {e}"));
    });
    proposals::record_proof_export(
        &mut loaded,
        proposals::ProofPacketRecord {
            generated_at: export_record.generated_at.clone(),
            snapshot_hash: export_record.snapshot_hash.clone(),
            event_log_hash: export_record.event_log_hash.clone(),
            packet_manifest_hash: export_record.packet_manifest_hash.clone(),
        },
    );
    project::recompute_stats(&mut loaded);
    if record_proof_state {
        save_recorded_proof_state(&proof_frontier, &loaded).unwrap_or_else(|e| fail(&e));
    }
    let signal_report = signals::analyze(&loaded, &[]);
    if json_output {
        let payload = json!({
            "ok": true,
            "command": "proof",
            "schema_version": project::VELA_SCHEMA_VERSION,
            "recorded_proof_state": record_proof_state,
            "frontier": {
                "name": &loaded.project.name,
                "source": frontier.display().to_string(),
                "loaded_from": proof_frontier.display().to_string(),
                "hash": format!("sha256:{source_hash}"),
            },
            "template": template,
            "gold": gold.map(|p| p.display().to_string()),
            "benchmark": benchmark_summary,
            "output": out.display().to_string(),
            "packet": {
                "manifest_path": out.join("manifest.json").display().to_string(),
            },
            "validation": {
                "status": "ok",
                "summary": validation_summary,
            },
            "proposals": proposals::summary(&loaded),
            "proof_state": loaded.proof_state,
            "signals": signal_report.signals,
            "review_queue": signal_report.review_queue,
            "proof_readiness": signal_report.proof_readiness,
            "trace_path": out.join("proof-trace.json").display().to_string(),
        });
        print_json(&payload);
    } else {
        println!("vela proof");
        println!("  source:   {}", frontier.display());
        if proof_frontier != frontier {
            println!("  loaded:   {}", proof_frontier.display());
        }
        println!("  template: {template}");
        println!("  output:   {}", out.display());
        println!("  trace:    {}", out.join("proof-trace.json").display());
        println!(
            "  proof state: {}",
            if record_proof_state {
                "recorded"
            } else {
                "not recorded"
            }
        );
        println!();
        println!("{validation_summary}");
    }
}

fn proof_load_path(frontier: &Path) -> PathBuf {
    if frontier.is_dir() {
        let compatibility_snapshot = frontier.join("frontier.json");
        if compatibility_snapshot.is_file() {
            return compatibility_snapshot;
        }
    }
    frontier.to_path_buf()
}

fn save_recorded_proof_state(frontier: &Path, loaded: &project::Project) -> Result<(), String> {
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

/// v0.42: One-screen status. The `git status` analogue.
fn cmd_status(path: &Path, json: bool) {
    let project = repo::load_from_path(path).unwrap_or_else(|e| fail_return(&e));

    // Inbox counts.
    let mut pending_total = 0usize;
    let mut pending_by_kind: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    for p in &project.proposals {
        if p.status == "pending_review" {
            pending_total += 1;
            *pending_by_kind.entry(p.kind.clone()).or_insert(0) += 1;
        }
    }

    // Causal audit summary.
    let audit = vela_protocol::causal_reasoning::audit_frontier(&project);
    let audit_summary = vela_protocol::causal_reasoning::summarize_audit(&audit);

    // Federation health: peers + last sync.
    let mut last_sync: Option<&vela_protocol::events::StateEvent> = None;
    let mut last_conflict: Option<&vela_protocol::events::StateEvent> = None;
    let mut total_conflicts = 0usize;
    for e in &project.events {
        match e.kind.as_str() {
            "frontier.synced_with_peer" => {
                if last_sync
                    .map(|prev| e.timestamp > prev.timestamp)
                    .unwrap_or(true)
                {
                    last_sync = Some(e);
                }
            }
            "frontier.conflict_detected" => {
                total_conflicts += 1;
                if last_conflict
                    .map(|prev| e.timestamp > prev.timestamp)
                    .unwrap_or(true)
                {
                    last_conflict = Some(e);
                }
            }
            _ => {}
        }
    }

    // Replication health.
    let mut targets_with_success = std::collections::HashSet::new();
    let mut failed_replications = 0usize;
    for r in &project.replications {
        if r.outcome == "replicated" {
            targets_with_success.insert(r.target_finding.clone());
        } else if r.outcome == "failed" {
            failed_replications += 1;
        }
    }

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": true,
                "command": "status",
                "frontier": frontier_label(&project),
                "vfr_id": project.frontier_id(),
                "findings": project.findings.len(),
                "events": project.events.len(),
                "actors": project.actors.len(),
                "peers": project.peers.len(),
                "inbox": {
                    "pending_total": pending_total,
                    "pending_by_kind": pending_by_kind,
                },
                "causal_audit": {
                    "identified": audit_summary.identified,
                    "conditional": audit_summary.conditional,
                    "underidentified": audit_summary.underidentified,
                    "underdetermined": audit_summary.underdetermined,
                },
                "replications": {
                    "total": project.replications.len(),
                    "findings_with_success": targets_with_success.len(),
                    "failed": failed_replications,
                },
                "federation": {
                    "peers": project.peers.len(),
                    "last_sync": last_sync.map(|e| e.timestamp.clone()),
                    "last_conflict": last_conflict.map(|e| e.timestamp.clone()),
                    "total_conflicts": total_conflicts,
                },
            }))
            .expect("serialize status")
        );
        return;
    }

    println!();
    println!(
        "  {}",
        format!("VELA · STATUS · {}", path.display())
            .to_uppercase()
            .dimmed()
    );
    println!("  {}", style::tick_row(60));
    println!();
    println!("  frontier:    {}", frontier_label(&project));
    println!("  vfr_id:      {}", project.frontier_id());
    println!(
        "  findings:    {}    events: {}    peers: {}    actors: {}",
        project.findings.len(),
        project.events.len(),
        project.peers.len(),
        project.actors.len(),
    );
    println!();
    if pending_total > 0 {
        println!(
            "  {}  {pending_total} pending proposals",
            style::warn("inbox")
        );
        for (k, n) in &pending_by_kind {
            println!("    · {n:>3}  {k}");
        }
    } else {
        println!("  {}  inbox clean", style::ok("ok"));
    }
    println!();
    if audit_summary.underidentified > 0 || audit_summary.conditional > 0 {
        let chip = if audit_summary.underidentified > 0 {
            style::lost("audit")
        } else {
            style::warn("audit")
        };
        println!(
            "  {}  identified {} · conditional {} · underidentified {} · underdetermined {}",
            chip,
            audit_summary.identified,
            audit_summary.conditional,
            audit_summary.underidentified,
            audit_summary.underdetermined,
        );
        if audit_summary.underidentified > 0 {
            println!(
                "    next: vela causal audit {} --problems-only",
                path.display()
            );
        }
    } else if audit_summary.underdetermined == 0 {
        println!(
            "  {}  causal audit: all {} identified",
            style::ok("ok"),
            audit_summary.identified
        );
    } else {
        println!(
            "  {}  causal audit: {} identified, {} ungraded",
            style::warn("audit"),
            audit_summary.identified,
            audit_summary.underdetermined,
        );
    }
    println!();
    if !project.replications.is_empty() {
        println!(
            "  {}  {} records · {} findings replicated · {} failed",
            style::ok("replications"),
            project.replications.len(),
            targets_with_success.len(),
            failed_replications,
        );
    }
    if project.peers.is_empty() {
        println!(
            "  {}  no federation peers registered",
            style::warn("federation")
        );
    } else {
        let last = last_sync
            .map(|e| fmt_timestamp(&e.timestamp))
            .unwrap_or_else(|| "never".to_string());
        let chip = if total_conflicts > 0 {
            style::warn("federation")
        } else {
            style::ok("federation")
        };
        println!(
            "  {}  {} peer(s) · last sync {} · {} conflict events",
            chip,
            project.peers.len(),
            last,
            total_conflicts,
        );
    }
    println!();
}

/// v0.42: Recent canonical events. The `git log` analogue.
fn cmd_log(path: &Path, limit: usize, kind_filter: Option<&str>, json: bool) {
    let project = repo::load_from_path(path).unwrap_or_else(|e| fail_return(&e));
    let mut events: Vec<&vela_protocol::events::StateEvent> = project
        .events
        .iter()
        .filter(|e| match kind_filter {
            Some(k) => e.kind.contains(k),
            None => true,
        })
        .collect();
    events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    events.truncate(limit);

    if json {
        let payload: Vec<_> = events
            .iter()
            .map(|e| {
                json!({
                    "id": e.id,
                    "kind": e.kind,
                    "actor": e.actor.id,
                    "target": &e.target.id,
                    "target_type": &e.target.r#type,
                    "timestamp": e.timestamp,
                    "reason": e.reason,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": true,
                "command": "log",
                "events": payload,
            }))
            .expect("serialize log")
        );
        return;
    }

    println!();
    println!(
        "  {}",
        format!("VELA · LOG · {}  (latest {})", path.display(), events.len())
            .to_uppercase()
            .dimmed()
    );
    println!("  {}", style::tick_row(60));
    if events.is_empty() {
        println!("  (no events)");
        return;
    }
    for e in &events {
        let when = fmt_timestamp(&e.timestamp);
        let target_short = if e.target.id.len() > 22 {
            format!("{}…", &e.target.id[..21])
        } else {
            e.target.id.clone()
        };
        let reason: String = e.reason.chars().take(70).collect();
        println!(
            "  {:<19}  {:<32}  {:<24}  {}",
            when, e.kind, target_short, reason
        );
    }
    println!();
}

/// v0.42: Pending-proposals triage. The thing you sit down to review.
fn cmd_inbox(path: &Path, kind_filter: Option<&str>, limit: usize, json: bool) {
    let project = repo::load_from_path(path).unwrap_or_else(|e| fail_return(&e));

    // Collect reviewer-agent score map (composite shown alongside each
    // proposal where present).
    let mut score_map: std::collections::HashMap<String, (f64, f64, f64, f64)> =
        std::collections::HashMap::new();
    for p in &project.proposals {
        if p.kind != "finding.note" {
            continue;
        }
        if p.actor.id != "agent:reviewer-agent" {
            continue;
        }
        let reason = &p.reason;
        let Some(target) = reason.split_whitespace().find(|s| s.starts_with("vpr_")) else {
            continue;
        };
        let text = p.payload.get("text").and_then(|v| v.as_str()).unwrap_or("");
        let extract = |k: &str| -> f64 {
            let pat = format!("{k} ");
            text.find(&pat)
                .and_then(|idx| text[idx + pat.len()..].split_whitespace().next())
                .and_then(|t| t.parse::<f64>().ok())
                .unwrap_or(0.0)
        };
        score_map.insert(
            target.to_string(),
            (
                extract("plausibility"),
                extract("evidence"),
                extract("scope"),
                extract("duplicate-risk"),
            ),
        );
    }

    let mut pending: Vec<&vela_protocol::proposals::StateProposal> = project
        .proposals
        .iter()
        .filter(|p| {
            p.status == "pending_review"
                && match kind_filter {
                    Some(k) => p.kind.contains(k),
                    None => true,
                }
        })
        .collect();
    // Sort: high reviewer-agent composite first, then untyped.
    pending.sort_by(|a, b| {
        let sa = score_map
            .get(&a.id)
            .map(|(p, e, s, d)| 0.4 * p + 0.3 * e + 0.2 * s - 0.3 * d);
        let sb = score_map
            .get(&b.id)
            .map(|(p, e, s, d)| 0.4 * p + 0.3 * e + 0.2 * s - 0.3 * d);
        sb.partial_cmp(&sa).unwrap_or(std::cmp::Ordering::Equal)
    });
    pending.truncate(limit);

    if json {
        let payload: Vec<_> = pending
            .iter()
            .map(|p| {
                let assertion_text = p
                    .payload
                    .get("finding")
                    .and_then(|f| f.get("assertion"))
                    .and_then(|a| a.get("text"))
                    .and_then(|t| t.as_str());
                let assertion_type = p
                    .payload
                    .get("finding")
                    .and_then(|f| f.get("assertion"))
                    .and_then(|a| a.get("type"))
                    .and_then(|t| t.as_str());
                let composite = score_map
                    .get(&p.id)
                    .map(|(pl, e, s, d)| 0.4 * pl + 0.3 * e + 0.2 * s - 0.3 * d);
                json!({
                    "proposal_id": p.id,
                    "kind": p.kind,
                    "actor": p.actor,
                    "reason": p.reason,
                    "assertion_text": assertion_text,
                    "assertion_type": assertion_type,
                    "reviewer_composite": composite,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": true,
                "command": "inbox",
                "shown": pending.len(),
                "proposals": payload,
            }))
            .expect("serialize inbox")
        );
        return;
    }

    println!();
    println!(
        "  {}",
        format!(
            "VELA · INBOX · {}  ({} pending shown)",
            path.display(),
            pending.len()
        )
        .to_uppercase()
        .dimmed()
    );
    println!("  {}", style::tick_row(60));
    if pending.is_empty() {
        println!("  (inbox clean)");
        return;
    }
    for p in &pending {
        let assertion_text = p
            .payload
            .get("finding")
            .and_then(|f| f.get("assertion"))
            .and_then(|a| a.get("text"))
            .and_then(|t| t.as_str())
            .unwrap_or("");
        let assertion_type = p
            .payload
            .get("finding")
            .and_then(|f| f.get("assertion"))
            .and_then(|a| a.get("type"))
            .and_then(|t| t.as_str())
            .unwrap_or("");
        let composite = score_map
            .get(&p.id)
            .map(|(pl, e, s, d)| 0.4 * pl + 0.3 * e + 0.2 * s - 0.3 * d);
        let score_str = composite
            .map(|c| format!("[{:.2}]", c))
            .unwrap_or_else(|| "[—]   ".to_string());
        let kind_short = if p.kind.len() > 12 {
            format!("{}…", &p.kind[..11])
        } else {
            p.kind.clone()
        };
        let summary: String = if !assertion_text.is_empty() {
            assertion_text.chars().take(80).collect()
        } else {
            p.reason.chars().take(80).collect()
        };
        println!(
            "  {}  {}  {:<13}  {:<18}  {}",
            score_str, p.id, kind_short, assertion_type, summary
        );
    }
    println!();
}

/// v0.42: Conversational substrate access. Thin REPL over kernel
/// queries. Doesn't pretend to be an agent — every answer comes from
/// a structured query the kernel can produce deterministically. The
/// goal is fluency, not magic.
fn cmd_ask(path: &Path, question: &str, json: bool) {
    let project = repo::load_from_path(path).unwrap_or_else(|e| fail_return(&e));

    if question.trim().is_empty() {
        // REPL mode.
        use std::io::{BufRead, Write};
        println!();
        println!(
            "  {}",
            format!("VELA · ASK · {}", path.display())
                .to_uppercase()
                .dimmed()
        );
        println!("  {}", style::tick_row(60));
        println!("  Ask a question. Type `exit` to quit.");
        println!("  Examples:");
        println!("    · what's pending?");
        println!("    · what's underidentified?");
        println!("    · how many findings?");
        println!("    · what changed recently?");
        println!("    · who has what calibration?");
        println!();
        let stdin = std::io::stdin();
        let mut stdout = std::io::stdout();
        loop {
            print!("  ask> ");
            stdout.flush().ok();
            let mut line = String::new();
            if stdin.lock().read_line(&mut line).is_err() {
                break;
            }
            let q = line.trim();
            if q.is_empty() {
                continue;
            }
            if matches!(q, "exit" | "quit" | "q") {
                break;
            }
            answer(&project, q, false);
        }
        return;
    }

    answer(&project, question, json);
}

fn answer(project: &vela_protocol::project::Project, q: &str, json: bool) {
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
        let entries = vela_protocol::causal_reasoning::audit_frontier(project);
        let summary = vela_protocol::causal_reasoning::summarize_audit(&entries);
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
                            vela_protocol::causal_reasoning::Identifiability::Underidentified
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
        let peers = project.peers.len();
        let actors = project.actors.len();
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "answer": "counts",
                    "findings": n,
                    "events": evs,
                    "peers": peers,
                    "actors": actors,
                    "replications": project.replications.len(),
                    "predictions": project.predictions.len(),
                }))
                .unwrap()
            );
        } else {
            println!("  {n} findings · {evs} events · {actors} actors · {peers} peers.");
            println!(
                "  {} replications · {} predictions · {} datasets · {} code artifacts.",
                project.replications.len(),
                project.predictions.len(),
                project.datasets.len(),
                project.code_artifacts.len(),
            );
        }
        return;
    }

    // Pattern: calibration.
    if lower.contains("calibration") || lower.contains("brier") || lower.contains("predict") {
        let records =
            vela_protocol::calibration::calibration_records(&project.predictions, &project.resolutions);
        if json {
            println!("{}", serde_json::to_string_pretty(&records).unwrap());
        } else if records.is_empty() {
            println!("  No predictions yet. The calibration ledger is empty.");
        } else {
            println!("  Calibration over {} actor(s):", records.len());
            for r in &records {
                let brier = r
                    .brier_score
                    .map(|b| format!("{:.3}", b))
                    .unwrap_or_else(|| "—".into());
                println!(
                    "    · {:<28}  predictions {} · resolved {} · expired {} · Brier {}",
                    r.actor, r.n_predictions, r.n_resolved, r.n_expired, brier
                );
            }
        }
        return;
    }

    // Pattern: federation / peers / sync.
    if lower.contains("peer")
        || lower.contains("federat")
        || lower.contains("sync")
        || lower.contains("conflict")
    {
        let mut total_conflicts = 0usize;
        for e in &project.events {
            if e.kind == "frontier.conflict_detected" {
                total_conflicts += 1;
            }
        }
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "answer": "federation",
                    "peers": project.peers.iter().map(|p| &p.id).collect::<Vec<_>>(),
                    "total_conflicts": total_conflicts,
                }))
                .unwrap()
            );
        } else {
            println!("  {} peer(s) registered:", project.peers.len());
            for p in &project.peers {
                println!("    · {:<24}  {}", p.id, p.url);
            }
            println!("  {total_conflicts} conflict events on the canonical log.");
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
                "hint": "Try: pending, audit, recent, how many, calibration, peers."
            }))
            .unwrap()
        );
    } else {
        println!("  Don't know how to route that question yet.");
        println!("  Try: pending · audit · recent · how many · calibration · peers");
    }
}

fn frontier_label(p: &vela_protocol::project::Project) -> String {
    if p.project.name.trim().is_empty() {
        "(unnamed)".to_string()
    } else {
        p.project.name.clone()
    }
}

fn fmt_timestamp(ts: &str) -> String {
    // RFC 3339 → "MM-DD HH:MM" for human reading. Falls back to first
    // 16 chars if parsing fails (which is enough to be readable).
    chrono::DateTime::parse_from_rfc3339(ts)
        .map(|dt| dt.format("%m-%d %H:%M").to_string())
        .unwrap_or_else(|_| ts.chars().take(16).collect())
}

fn cmd_stats(path: &Path) {
    if print_stats_from_shards_human(path) {
        return;
    }

    let frontier = load_frontier_or_fail(path);
    let s = &frontier.stats;
    println!();
    println!("  {}", "FRONTIER · V0.36.0".dimmed());
    println!("  {}", frontier.project.name.bold());
    println!("  {}", style::tick_row(60));
    println!("  id:             {}", frontier.frontier_id());
    println!("  compiled:       {}", frontier.project.compiled_at);
    println!("  papers:         {}", frontier.project.papers_processed);
    println!("  findings:       {}", s.findings);
    println!("  links:          {}", s.links);
    println!("  replicated:     {}", s.replicated);
    println!("  avg confidence: {}", s.avg_confidence);
    println!("  gaps:           {}", s.gaps);
    println!("  contested:      {}", s.contested);
    println!("  reviewed:       {}", s.human_reviewed);
    println!("  proposals:      {}", s.proposal_count);
    println!(
        "  recorded proof: {}",
        frontier.proof_state.latest_packet.status
    );
    if frontier.proof_state.latest_packet.status != "never_exported" {
        println!(
            "  proof note:     recorded frontier metadata; packet files are checked by `vela packet validate`"
        );
    }
    if !s.categories.is_empty() {
        println!();
        println!("  {}", "categories".dimmed());
        let mut categories = s.categories.iter().collect::<Vec<_>>();
        categories.sort_by(|a, b| b.1.cmp(a.1));
        for (category, count) in categories {
            println!("    {category}: {}", count);
        }
    }
    println!();
    println!("  {}", style::tick_row(60));
    println!();
}

fn print_stats_from_shards_human(path: &Path) -> bool {
    let Ok((manifest_path, manifest)) = load_frontier_shards_manifest(path) else {
        return false;
    };
    if manifest.get("schema").and_then(Value::as_str) != Some("vela.frontier_state_shards.v1") {
        return false;
    }
    let stats = manifest.get("stats").cloned().unwrap_or(Value::Null);
    let source_snapshot = source_frontier_json_summary(&manifest);
    let frontier_bytes = source_snapshot
        .get("current_byte_count")
        .or_else(|| source_snapshot.get("declared_byte_count"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let max_shard_bytes = json_path_u64(&manifest, &["storage", "max_shard_byte_count"]);
    if max_shard_bytes == 0 || max_shard_bytes >= 50_000_000 || frontier_bytes >= 100_000_000 {
        return false;
    }

    println!();
    println!("  {}", "Vela · frontier stats".dimmed());
    println!("  {}", style::tick_row(60));
    if let Some(id) = manifest.get("frontier_id").and_then(Value::as_str) {
        println!("  id:             {id}");
    }
    println!("  source:         frontier state shards");
    println!("  manifest:       {}", manifest_path.display());
    println!(
        "  snapshot:       {} bytes ({})",
        frontier_bytes,
        frontier_json_status(frontier_bytes)
    );
    println!("  findings:       {}", json_path_u64(&stats, &["findings"]));
    println!(
        "  sources:        {}",
        json_path_u64(&stats, &["source_count"])
    );
    println!(
        "  evidence atoms: {}",
        json_path_u64(&stats, &["evidence_atom_count"])
    );
    println!("  links:          {}", json_path_u64(&stats, &["links"]));
    println!("  gaps:           {}", json_path_u64(&stats, &["gaps"]));
    println!(
        "  contested:      {}",
        json_path_u64(&stats, &["contested"])
    );
    println!(
        "  reviewed:       {}",
        json_path_u64(&stats, &["human_reviewed"])
    );
    println!(
        "  events:         {}",
        json_path_u64(&stats, &["event_count"])
    );
    println!();
    println!("  {}", style::tick_row(60));
    println!();
    true
}

fn cmd_proposals(action: ProposalAction) {
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
            json,
        } => {
            let event_id = proposals::accept_at_path(&frontier, &proposal_id, &reviewer, &reason)
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
            json,
        } => {
            proposals::reject_at_path(&frontier, &proposal_id, &reviewer, &reason)
                .unwrap_or_else(|e| fail_return(&e));
            let payload = json!({
                "ok": true,
                "command": "proposals.reject",
                "frontier": frontier.display().to_string(),
                "proposal_id": proposal_id,
                "reviewer": reviewer,
                "status": "rejected",
            });
            if json {
                print_json(&payload);
            } else {
                println!(
                    "{} rejected proposal {}",
                    style::warn("rejected"),
                    proposal_id
                );
            }
        }
    }
}

fn cmd_artifact_to_state(
    frontier: &Path,
    packet: &Path,
    actor: &str,
    apply_artifacts: bool,
    json: bool,
) {
    let report =
        vela_protocol::artifact_to_state::import_packet_at_path(frontier, packet, actor, apply_artifacts)
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

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ProvenanceVerificationReport {
    pub(crate) command: String,
    pub(crate) packet: String,
    pub(crate) identifiers: Vec<ProvenanceVerificationEntry>,
    pub(crate) resolved_count: usize,
    pub(crate) unresolved_count: usize,
    pub(crate) skipped_count: usize,
    /// v0.126: when `--cross-check` is requested, this carries one
    /// entry per artifact that resolved on at least two sources.
    /// Records per-source title + first-author and a per-pair
    /// agreement signal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) cross_check: Option<Vec<CrossCheckEntry>>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ProvenanceVerificationEntry {
    pub(crate) identifier: String,
    pub(crate) kind: String,
    pub(crate) status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) note: Option<String>,
    /// v0.126: populated when status == "resolved" and the upstream
    /// response carried a title. Used by the `--cross-check` mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) title: Option<String>,
    /// v0.126: populated when status == "resolved" and the upstream
    /// response carried at least one author. Lowercased last-name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) first_author: Option<String>,
}

/// v0.126: per-artifact cross-source agreement record.
/// An artifact resolves through one or more sources; this struct
/// captures whether the sources agree on title and first-author.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct CrossCheckEntry {
    /// All identifiers that resolved for this artifact.
    pub(crate) identifiers: Vec<String>,
    /// One entry per resolved source.
    pub(crate) sources: Vec<CrossCheckSource>,
    /// "agree" when all sources match (normalized); "title_mismatch",
    /// "author_mismatch", "both_mismatch" otherwise; "insufficient"
    /// when fewer than 2 sources resolved.
    pub(crate) consensus: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) note: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct CrossCheckSource {
    pub(crate) source: String,
    pub(crate) identifier: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) first_author: Option<String>,
}

/// v0.108.3: walk a packet's artifacts and candidate-claim
/// source_refs, extract recognized DOI/PMID identifiers, ask
/// the upstream registry whether each one resolves. Closes
/// part of THREAT_MODEL.md A6 (citation poisoning).
pub(crate) async fn verify_packet_provenance(packet_path: &Path) -> ProvenanceVerificationReport {
    use vela_protocol::artifact_to_state::ArtifactPacket;
    let raw = std::fs::read_to_string(packet_path)
        .unwrap_or_else(|e| fail_return(&format!("read packet: {e}")));
    let parsed: ArtifactPacket =
        serde_json::from_str(&raw).unwrap_or_else(|e| fail_return(&format!("parse packet: {e}")));
    let packet = parsed
        .validate()
        .unwrap_or_else(|e| fail_return(&format!("validate packet: {e}")));

    // Collect candidate identifiers from every locator and source_ref.
    let mut candidates: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for artifact in &packet.artifacts {
        if let Some(ident) = extract_identifier(&artifact.locator) {
            candidates.insert(ident);
        }
    }
    for claim in &packet.candidate_claims {
        for source_ref in &claim.source_refs {
            if let Some(ident) = extract_identifier(source_ref) {
                candidates.insert(ident);
            }
        }
    }

    let client = reqwest::Client::builder()
        .user_agent("vela/0.108 (+https://github.com/vela-science/vela)")
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap_or_else(|e| fail_return(&format!("build http client: {e}")));

    let mut entries: Vec<ProvenanceVerificationEntry> = Vec::new();
    let mut resolved = 0usize;
    let mut unresolved = 0usize;
    let mut skipped = 0usize;
    for candidate in &candidates {
        let entry = if let Some(doi) = candidate.strip_prefix("doi:") {
            verify_doi(&client, doi).await
        } else if let Some(pmid) = candidate.strip_prefix("pmid:") {
            verify_pmid(&client, pmid).await
        } else if let Some(s2_id) = candidate.strip_prefix("s2:") {
            verify_s2(&client, s2_id).await
        } else if let Some(arxiv_id) = candidate.strip_prefix("arxiv:") {
            verify_arxiv(&client, arxiv_id).await
        } else {
            ProvenanceVerificationEntry {
                identifier: candidate.clone(),
                kind: "unknown".to_string(),
                status: "skipped".to_string(),
                note: Some("no recognized identifier prefix".to_string()),
                title: None,
                first_author: None,
            }
        };
        match entry.status.as_str() {
            "resolved" => resolved += 1,
            "unresolved" => unresolved += 1,
            _ => skipped += 1,
        }
        entries.push(entry);
    }

    ProvenanceVerificationReport {
        command: "bridge-kit.verify-provenance".to_string(),
        packet: packet_path.display().to_string(),
        identifiers: entries,
        resolved_count: resolved,
        unresolved_count: unresolved,
        skipped_count: skipped,
        cross_check: None,
    }
}

/// v0.126: cross-source agreement pass over an already-verified
/// provenance report. Looks at packet artifacts that carry more than
/// one identifier across sources (e.g., a paper with both a DOI and
/// an ArXiv id) and emits one `CrossCheckEntry` per such artifact
/// recording per-source title + first-author and a consensus
/// signal. Sources that did not return a title or first-author are
/// skipped in the comparison. Two sources with matching normalized
/// title AND first-author count as agreement; mismatches surface
/// the disagreement with which fields disagree.
pub(crate) async fn cross_check_packet_provenance(
    packet_path: &Path,
    report: &mut ProvenanceVerificationReport,
) {
    use vela_protocol::artifact_to_state::ArtifactPacket;
    // Re-read the packet to discover which identifiers cluster on
    // the same artifact. The first pass treated each identifier
    // independently; the cross-check pass groups by artifact id.
    let raw = std::fs::read_to_string(packet_path)
        .unwrap_or_else(|e| fail_return(&format!("read packet: {e}")));
    let parsed: ArtifactPacket =
        serde_json::from_str(&raw).unwrap_or_else(|e| fail_return(&format!("parse packet: {e}")));
    let packet = parsed
        .validate()
        .unwrap_or_else(|e| fail_return(&format!("validate packet: {e}")));

    // Index resolved entries by canonical identifier.
    let by_ident: std::collections::HashMap<String, &ProvenanceVerificationEntry> = report
        .identifiers
        .iter()
        .filter(|e| e.status == "resolved")
        .map(|e| (e.identifier.clone(), e))
        .collect();

    let mut cross_entries: Vec<CrossCheckEntry> = Vec::new();
    for artifact in &packet.artifacts {
        // Collect every recognized identifier that appears in this
        // artifact's locator (the packet contract only carries one
        // locator per artifact today, so we cannot detect a cluster
        // here in the strict sense yet). For now, the cross-check
        // pass surfaces single-source artifacts with "insufficient"
        // consensus; multi-identifier clusters can be added once the
        // packet contract carries them.
        let Some(ident) = extract_identifier(&artifact.locator) else {
            continue;
        };
        let Some(entry) = by_ident.get(&ident) else {
            continue;
        };
        let source = CrossCheckSource {
            source: entry.kind.clone(),
            identifier: entry.identifier.clone(),
            title: entry.title.clone(),
            first_author: entry.first_author.clone(),
        };
        cross_entries.push(CrossCheckEntry {
            identifiers: vec![entry.identifier.clone()],
            sources: vec![source],
            consensus: "insufficient".to_string(),
            note: Some("only one source resolved for this artifact".to_string()),
        });
    }

    // Also scan candidate-claims for identifier clusters. Each
    // candidate-claim source_refs list may carry several
    // identifiers for the same underlying paper; if it does, the
    // cluster is a real cross-source agreement opportunity.
    for claim in &packet.candidate_claims {
        let mut cluster_idents: Vec<String> = Vec::new();
        let mut cluster_sources: Vec<CrossCheckSource> = Vec::new();
        for source_ref in &claim.source_refs {
            let Some(ident) = extract_identifier(source_ref) else {
                continue;
            };
            let Some(entry) = by_ident.get(&ident) else {
                continue;
            };
            cluster_idents.push(entry.identifier.clone());
            cluster_sources.push(CrossCheckSource {
                source: entry.kind.clone(),
                identifier: entry.identifier.clone(),
                title: entry.title.clone(),
                first_author: entry.first_author.clone(),
            });
        }
        if cluster_sources.len() >= 2 {
            // Compare pairwise: every pair must agree on both title
            // and first-author (when both populated) for the cluster
            // to count as "agree". If any pair disagrees on title,
            // record title_mismatch; on author, author_mismatch.
            let mut title_mismatch = false;
            let mut author_mismatch = false;
            for i in 0..cluster_sources.len() {
                for j in (i + 1)..cluster_sources.len() {
                    let a = &cluster_sources[i];
                    let b = &cluster_sources[j];
                    if let (Some(ta), Some(tb)) = (&a.title, &b.title)
                        && ta != tb
                    {
                        title_mismatch = true;
                    }
                    if let (Some(la), Some(lb)) = (&a.first_author, &b.first_author) {
                        // v0.126: prefix-tolerant agreement so
                        // PubMed esummary's "Family Initial" format
                        // (e.g. "Jumper J" normalized to "j" by the
                        // last-token rule) still agrees with
                        // Crossref's full "Jumper". Either string
                        // being a prefix of the other counts as
                        // agreement; only when both are populated
                        // and neither is a prefix do we flag
                        // mismatch.
                        if !la.is_empty()
                            && !lb.is_empty()
                            && !la.starts_with(lb.as_str())
                            && !lb.starts_with(la.as_str())
                        {
                            author_mismatch = true;
                        }
                    }
                }
            }
            let consensus = match (title_mismatch, author_mismatch) {
                (false, false) => "agree".to_string(),
                (true, false) => "title_mismatch".to_string(),
                (false, true) => "author_mismatch".to_string(),
                (true, true) => "both_mismatch".to_string(),
            };
            cross_entries.push(CrossCheckEntry {
                identifiers: cluster_idents,
                sources: cluster_sources,
                consensus,
                note: None,
            });
        }
    }

    report.cross_check = Some(cross_entries);
}

/// Extract a recognizable identifier from an artifact locator or
/// candidate-claim source_ref. Returns canonical `doi:<doi>` or
/// `pmid:<pmid>` form, or None when the string carries no
/// resolvable identifier.
fn extract_identifier(s: &str) -> Option<String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return None;
    }
    // Already prefixed.
    if trimmed.starts_with("doi:")
        || trimmed.starts_with("pmid:")
        || trimmed.starts_with("s2:")
        || trimmed.starts_with("arxiv:")
    {
        return Some(trimmed.to_string());
    }
    // doi.org / dx.doi.org URL forms.
    for prefix in ["https://doi.org/", "http://doi.org/", "https://dx.doi.org/"] {
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            return Some(format!("doi:{rest}"));
        }
    }
    // PubMed URL forms.
    for prefix in [
        "https://pubmed.ncbi.nlm.nih.gov/",
        "http://pubmed.ncbi.nlm.nih.gov/",
    ] {
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            let pmid = rest.trim_end_matches('/');
            return Some(format!("pmid:{pmid}"));
        }
    }
    // v0.118: Semantic Scholar URL forms. Two shapes are common:
    // the paper page (/paper/<paperId>) and the API URL
    // (api.semanticscholar.org/graph/v1/paper/<paperId>). Both
    // resolve to the same paperId, which is what we normalize to.
    for prefix in [
        "https://www.semanticscholar.org/paper/",
        "http://www.semanticscholar.org/paper/",
        "https://api.semanticscholar.org/graph/v1/paper/",
        "https://api.semanticscholar.org/v1/paper/",
    ] {
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            let s2_id = rest
                .split('/')
                .next_back()
                .unwrap_or(rest)
                .split('?')
                .next()
                .unwrap_or(rest);
            if !s2_id.is_empty() {
                return Some(format!("s2:{s2_id}"));
            }
        }
    }
    // v0.119: ArXiv URL forms. The canonical paper URL is
    // arxiv.org/abs/<id>; alternates include /pdf/<id>(.pdf) and
    // the legacy hep-th/9711200-style category slugs. All resolve
    // to the same paper id (modulo version suffix vN).
    for prefix in [
        "https://arxiv.org/abs/",
        "http://arxiv.org/abs/",
        "https://arxiv.org/pdf/",
        "http://arxiv.org/pdf/",
        "https://www.arxiv.org/abs/",
    ] {
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            let arxiv_id = rest
                .trim_end_matches('/')
                .trim_end_matches(".pdf")
                .split('?')
                .next()
                .unwrap_or(rest);
            if !arxiv_id.is_empty() {
                return Some(format!("arxiv:{arxiv_id}"));
            }
        }
    }
    // Bare DOI shape: "10.<numbers>/<rest>".
    if trimmed.starts_with("10.") && trimmed.contains('/') && !trimmed.contains(' ') {
        return Some(format!("doi:{trimmed}"));
    }
    None
}

async fn verify_doi(client: &reqwest::Client, doi: &str) -> ProvenanceVerificationEntry {
    let url = format!("https://api.crossref.org/works/{doi}");
    match client.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => {
            // v0.126: capture title + first-author from the Crossref
            // response so the cross-check mode can compare across
            // sources.
            let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
            let title = body
                .pointer("/message/title/0")
                .and_then(serde_json::Value::as_str)
                .map(normalize_title);
            let first_author = body
                .pointer("/message/author/0/family")
                .and_then(serde_json::Value::as_str)
                .map(normalize_last_name);
            ProvenanceVerificationEntry {
                identifier: format!("doi:{doi}"),
                kind: "doi".to_string(),
                status: "resolved".to_string(),
                note: None,
                title,
                first_author,
            }
        }
        Ok(resp) => ProvenanceVerificationEntry {
            identifier: format!("doi:{doi}"),
            kind: "doi".to_string(),
            status: "unresolved".to_string(),
            note: Some(format!("crossref returned {}", resp.status())),
            title: None,
            first_author: None,
        },
        Err(e) => ProvenanceVerificationEntry {
            identifier: format!("doi:{doi}"),
            kind: "doi".to_string(),
            status: "skipped".to_string(),
            note: Some(format!("crossref unreachable: {e}")),
            title: None,
            first_author: None,
        },
    }
}

/// v0.126: normalize a title for cross-source comparison. Lower-cases,
/// trims, collapses whitespace, and drops punctuation. The
/// substrate-honest comparison: titles from Crossref vs PubMed
/// frequently differ in capitalization, trailing periods, smart
/// quotes, or whitespace runs.
fn normalize_title(s: &str) -> String {
    let lower = s.to_lowercase();
    let stripped: String = lower
        .chars()
        .filter(|c| c.is_alphanumeric() || c.is_whitespace())
        .collect();
    stripped.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// v0.126: normalize a person's name (or last-name field) for
/// cross-source comparison. The substrate's most common shape is
/// "Family, Given" or just "Family"; we extract the last
/// whitespace-separated token or the substring before the first
/// comma, lowercased.
fn normalize_last_name(s: &str) -> String {
    let trimmed = s.trim();
    let candidate = if let Some(comma_idx) = trimmed.find(',') {
        &trimmed[..comma_idx]
    } else if let Some(last_space) = trimmed.rsplit_once(' ') {
        last_space.1
    } else {
        trimmed
    };
    candidate
        .to_lowercase()
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-')
        .collect()
}

async fn verify_pmid(client: &reqwest::Client, pmid: &str) -> ProvenanceVerificationEntry {
    let url = format!(
        "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esummary.fcgi?db=pubmed&id={pmid}&retmode=json"
    );
    match client.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => {
            // PubMed esummary returns 200 even for nonexistent ids;
            // we have to inspect the result body for the id key.
            let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
            let result = body.get("result");
            let uids = result
                .and_then(|r| r.get("uids"))
                .and_then(|u| u.as_array());
            let resolved = uids.is_some_and(|a| !a.is_empty());
            if resolved {
                // v0.126: extract title + first-author from the
                // eutils esummary response. The record is keyed by
                // the pmid string under `result`.
                let record = result.and_then(|r| r.get(pmid));
                let title = record
                    .and_then(|r| r.get("title"))
                    .and_then(serde_json::Value::as_str)
                    .map(normalize_title);
                let first_author = record
                    .and_then(|r| r.get("authors"))
                    .and_then(serde_json::Value::as_array)
                    .and_then(|a| a.first())
                    .and_then(|a| a.get("name"))
                    .and_then(serde_json::Value::as_str)
                    .map(normalize_last_name);
                ProvenanceVerificationEntry {
                    identifier: format!("pmid:{pmid}"),
                    kind: "pmid".to_string(),
                    status: "resolved".to_string(),
                    note: None,
                    title,
                    first_author,
                }
            } else {
                ProvenanceVerificationEntry {
                    identifier: format!("pmid:{pmid}"),
                    kind: "pmid".to_string(),
                    status: "unresolved".to_string(),
                    note: Some("eutils returned empty uids".to_string()),
                    title: None,
                    first_author: None,
                }
            }
        }
        Ok(resp) => ProvenanceVerificationEntry {
            identifier: format!("pmid:{pmid}"),
            kind: "pmid".to_string(),
            status: "unresolved".to_string(),
            note: Some(format!("eutils returned {}", resp.status())),
            title: None,
            first_author: None,
        },
        Err(e) => ProvenanceVerificationEntry {
            identifier: format!("pmid:{pmid}"),
            kind: "pmid".to_string(),
            status: "skipped".to_string(),
            note: Some(format!("eutils unreachable: {e}")),
            title: None,
            first_author: None,
        },
    }
}

/// v0.118: verify a Semantic Scholar paper id against the public
/// Graph API. Accepts S2 paper-id shapes including the 40-char hex
/// (corpusId), the SHA, or `DOI:<doi>`-style query strings. Returns
/// `resolved` when the API returns 200 with a paperId in the body,
/// `unresolved` when 404 or empty, `skipped` when the network is
/// unreachable (gates honor skips).
async fn verify_s2(client: &reqwest::Client, s2_id: &str) -> ProvenanceVerificationEntry {
    let url = format!("https://api.semanticscholar.org/graph/v1/paper/{s2_id}");
    match client.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => {
            let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
            let has_paper_id = body
                .get("paperId")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|v| !v.is_empty());
            if has_paper_id {
                // v0.126: title + first-author from the S2 graph
                // response. Title is at `.title`; first author's
                // last name comes from `.authors[0].name` (S2's
                // name field is typically "Given Family").
                let title = body
                    .get("title")
                    .and_then(serde_json::Value::as_str)
                    .map(normalize_title);
                let first_author = body
                    .get("authors")
                    .and_then(serde_json::Value::as_array)
                    .and_then(|a| a.first())
                    .and_then(|a| a.get("name"))
                    .and_then(serde_json::Value::as_str)
                    .map(normalize_last_name);
                ProvenanceVerificationEntry {
                    identifier: format!("s2:{s2_id}"),
                    kind: "s2".to_string(),
                    status: "resolved".to_string(),
                    note: None,
                    title,
                    first_author,
                }
            } else {
                ProvenanceVerificationEntry {
                    identifier: format!("s2:{s2_id}"),
                    kind: "s2".to_string(),
                    status: "unresolved".to_string(),
                    note: Some("semantic scholar returned 200 with no paperId".to_string()),
                    title: None,
                    first_author: None,
                }
            }
        }
        Ok(resp) => ProvenanceVerificationEntry {
            identifier: format!("s2:{s2_id}"),
            kind: "s2".to_string(),
            status: "unresolved".to_string(),
            note: Some(format!("semantic scholar returned {}", resp.status())),
            title: None,
            first_author: None,
        },
        Err(e) => ProvenanceVerificationEntry {
            identifier: format!("s2:{s2_id}"),
            kind: "s2".to_string(),
            status: "skipped".to_string(),
            note: Some(format!("semantic scholar unreachable: {e}")),
            title: None,
            first_author: None,
        },
    }
}

/// v0.119: verify an ArXiv paper id against the public Atom API.
/// Accepts ArXiv ids in canonical new form (`<YYMM>.<NNNN>`(`vN`)?)
/// or legacy form (`<category>/<YYMMNNN>`). Returns `resolved` when
/// the Atom feed contains at least one `<entry>` element naming a
/// paper id; `unresolved` when 4xx or empty feed; `skipped` on
/// network errors. The ArXiv export API has lighter rate-limiting
/// than Semantic Scholar; gates honor the skip-on-network-fail
/// contract.
async fn verify_arxiv(client: &reqwest::Client, arxiv_id: &str) -> ProvenanceVerificationEntry {
    let url = format!("https://export.arxiv.org/api/query?id_list={arxiv_id}&max_results=1");
    match client.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => {
            let body = resp.text().await.unwrap_or_default();
            // The Atom feed for an unresolved id still returns 200
            // but with `<opensearch:totalResults>0</...>` and zero
            // `<entry>` elements. Inspect for the entry tag.
            let has_entry = body.contains("<entry>") || body.contains("<entry ");
            // Also require an arxiv:id-style tag inside the entry
            // to distinguish empty feeds with a default <entry>
            // wrapper.
            let has_id_url = body.contains("http://arxiv.org/abs/");
            if has_entry && has_id_url {
                // v0.126: extract title + first-author from the
                // Atom feed. Atom titles wrap in <title> and the
                // first author's name lives in
                // <entry>...<author><name>FAMILY GIVEN</name>.
                // The substrate's normalize_last_name picks the
                // final whitespace-separated token, which matches
                // ArXiv's "First Last" convention. A more robust
                // parse would use quick-xml; this conservative
                // string match is enough for the agreement signal.
                let title = atom_inner_text(&body, "<entry>", "<title>", "</title>")
                    .as_deref()
                    .map(normalize_title);
                let first_author = atom_inner_text(&body, "<author>", "<name>", "</name>")
                    .as_deref()
                    .map(normalize_last_name);
                ProvenanceVerificationEntry {
                    identifier: format!("arxiv:{arxiv_id}"),
                    kind: "arxiv".to_string(),
                    status: "resolved".to_string(),
                    note: None,
                    title,
                    first_author,
                }
            } else {
                ProvenanceVerificationEntry {
                    identifier: format!("arxiv:{arxiv_id}"),
                    kind: "arxiv".to_string(),
                    status: "unresolved".to_string(),
                    note: Some("arxiv returned 200 with no matching entry".to_string()),
                    title: None,
                    first_author: None,
                }
            }
        }
        Ok(resp) => ProvenanceVerificationEntry {
            identifier: format!("arxiv:{arxiv_id}"),
            kind: "arxiv".to_string(),
            status: "unresolved".to_string(),
            note: Some(format!("arxiv returned {}", resp.status())),
            title: None,
            first_author: None,
        },
        Err(e) => ProvenanceVerificationEntry {
            identifier: format!("arxiv:{arxiv_id}"),
            kind: "arxiv".to_string(),
            status: "skipped".to_string(),
            note: Some(format!("arxiv unreachable: {e}")),
            title: None,
            first_author: None,
        },
    }
}

/// v0.126: extract the inner text of an Atom XML element nested
/// inside a scope element. `scope_open` (e.g. `<entry>`) bounds the
/// search; `open` / `close` (e.g. `<title>` / `</title>`) bracket
/// the text. Returns the first occurrence inside the scope, with
/// surrounding whitespace trimmed. Returns None when any anchor is
/// missing. Conservative: does not parse attributes or handle CDATA.
fn atom_inner_text(body: &str, scope_open: &str, open: &str, close: &str) -> Option<String> {
    let scope_start = body.find(scope_open)?;
    let after_scope = &body[scope_start..];
    let open_idx = after_scope.find(open)?;
    let after_open = &after_scope[open_idx + open.len()..];
    let close_idx = after_open.find(close)?;
    Some(after_open[..close_idx].trim().to_string())
}

async fn cmd_source_adapter(action: SourceAdapterAction) {
    match action {
        SourceAdapterAction::Run {
            frontier,
            adapter,
            actor,
            entries,
            priority,
            include_excluded,
            allow_partial,
            dry_run,
            input_dir,
            apply_artifacts,
            write_inbox,
            json,
        } => {
            let report = vela_protocol::source_adapters::run(
                &frontier,
                vela_protocol::source_adapters::SourceAdapterRunOptions {
                    adapter,
                    actor,
                    entries,
                    priority,
                    include_excluded,
                    allow_partial,
                    dry_run,
                    input_dir,
                    apply_artifacts,
                    write_inbox,
                },
            )
            .await
            .unwrap_or_else(|e| fail_return(&e));
            if json {
                print_json(&report);
            } else {
                println!("vela source-adapter run");
                println!("  adapter: {}", report.adapter);
                println!("  run: {}", report.run_id);
                println!("  frontier: {}", report.frontier);
                println!("  selected entries: {}", report.selected_entries);
                println!("  fetched records: {}", report.fetched_records);
                println!("  changed records: {}", report.changed_records);
                println!("  unchanged records: {}", report.unchanged_records);
                println!("  failed records: {}", report.failed_records.len());
                if let Some(packet_id) = report.packet_id {
                    println!("  packet: {packet_id}");
                }
                println!("  artifact proposals: {}", report.artifact_proposals);
                println!("  review note proposals: {}", report.review_note_proposals);
                println!("  source inbox records: {}", report.source_inbox_ids.len());
                println!("  applied events: {}", report.applied_event_ids.len());
            }
        }
    }
}

fn cmd_runtime_adapter(action: RuntimeAdapterAction) {
    match action {
        RuntimeAdapterAction::Run {
            frontier,
            adapter,
            input,
            actor,
            dry_run,
            apply_artifacts,
            write_inbox,
            json,
        } => {
            let report = vela_protocol::runtime_adapters::run(
                &frontier,
                vela_protocol::runtime_adapters::RuntimeAdapterRunOptions {
                    adapter,
                    input,
                    actor,
                    dry_run,
                    apply_artifacts,
                    write_inbox,
                },
            )
            .unwrap_or_else(|e| fail_return(&e));
            if json {
                print_json(&report);
            } else {
                println!("vela runtime-adapter run");
                println!("  adapter: {}", report.adapter);
                println!("  run: {}", report.run_id);
                println!("  frontier: {}", report.frontier);
                if let Some(packet_id) = report.packet_id {
                    println!("  packet: {packet_id}");
                }
                println!("  artifact proposals: {}", report.artifact_proposals);
                println!("  finding proposals: {}", report.finding_proposals);
                println!("  gap proposals: {}", report.gap_proposals);
                println!("  review note proposals: {}", report.review_note_proposals);
                println!(
                    "  applied artifact events: {}",
                    report.applied_artifact_events
                );
                println!(
                    "  pending truth proposals: {}",
                    report.pending_truth_proposals
                );
                println!("  source inbox records: {}", report.source_inbox_ids.len());
            }
        }
    }
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

fn cmd_actor(action: ActorAction) {
    match action {
        ActorAction::Add {
            frontier,
            id,
            pubkey,
            tier,
            orcid,
            clearance,
            json,
        } => {
            // Validate the pubkey shape before mutating the frontier.
            let trimmed = pubkey.trim();
            if trimmed.len() != 64 || hex::decode(trimmed).is_err() {
                fail("Public key must be 64 hex characters (32-byte Ed25519 pubkey).");
            }
            // v0.43: Validate ORCID shape if supplied. Stored in bare form.
            let orcid_normalized = orcid
                .as_deref()
                .map(|s| sign::validate_orcid(s).unwrap_or_else(|e| fail_return(&e)));
            // v0.51: parse clearance up front so a typo fails at the
            // CLI boundary rather than silently degrading.
            let clearance: Option<vela_protocol::access_tier::AccessTier> = clearance.as_deref().map(|s| {
                vela_protocol::access_tier::AccessTier::parse(s).unwrap_or_else(|e| fail_return(&e))
            });

            let mut project = repo::load_from_path(&frontier).unwrap_or_else(|e| fail_return(&e));
            if project.actors.iter().any(|actor| actor.id == id) {
                fail(&format!(
                    "Actor '{id}' already registered in this frontier."
                ));
            }
            project.actors.push(sign::ActorRecord {
                id: id.clone(),
                public_key: trimmed.to_string(),
                algorithm: "ed25519".to_string(),
                created_at: chrono::Utc::now().to_rfc3339(),
                tier: tier.clone(),
                orcid: orcid_normalized.clone(),
                access_clearance: clearance,
                revoked_at: None,
                revoked_reason: None,
            });
            repo::save_to_path(&frontier, &project).unwrap_or_else(|e| fail_return(&e));
            let payload = json!({
                "ok": true,
                "command": "actor.add",
                "frontier": frontier.display().to_string(),
                "actor_id": id,
                "public_key": trimmed,
                "tier": tier,
                "orcid": orcid_normalized,
                "registered_count": project.actors.len(),
            });
            if json {
                print_json(&payload);
            } else {
                let tier_suffix = tier
                    .as_deref()
                    .map_or_else(String::new, |t| format!(" tier={t}"));
                println!(
                    "{} actor {} (pubkey {}{tier_suffix})",
                    style::ok("registered"),
                    id,
                    &trimmed[..16]
                );
            }
        }
        ActorAction::Rotate {
            frontier,
            id,
            new_id,
            new_pubkey,
            reason,
            json,
        } => {
            // v0.127: validate the new pubkey shape up front.
            let trimmed = new_pubkey.trim();
            if trimmed.len() != 64 || hex::decode(trimmed).is_err() {
                fail("--new-pubkey must be 64 hex characters (32-byte Ed25519 pubkey).");
            }
            if reason.trim().is_empty() {
                fail("--reason must be non-empty (record why the rotation is happening).");
            }
            if id == new_id {
                fail("--id and --new-id must differ; rotation registers a fresh actor record.");
            }

            let mut project = repo::load_from_path(&frontier).unwrap_or_else(|e| fail_return(&e));

            // The new id must not already exist.
            if project.actors.iter().any(|a| a.id == new_id) {
                fail(&format!(
                    "Refusing to rotate: actor '{new_id}' is already registered."
                ));
            }

            // The old id must exist and must not already be revoked.
            let now = chrono::Utc::now().to_rfc3339();
            let mut found_old = false;
            let mut old_pubkey_prefix: Option<String> = None;
            for actor in project.actors.iter_mut() {
                if actor.id == id {
                    if actor.revoked_at.is_some() {
                        fail(&format!(
                            "Refusing to rotate: actor '{id}' is already revoked at {}.",
                            actor.revoked_at.as_deref().unwrap_or("?")
                        ));
                    }
                    actor.revoked_at = Some(now.clone());
                    actor.revoked_reason = Some(reason.clone());
                    old_pubkey_prefix = Some(actor.public_key[..16].to_string());
                    found_old = true;
                }
            }
            if !found_old {
                fail(&format!(
                    "Cannot rotate: actor '{id}' is not registered in this frontier."
                ));
            }

            // Register the new actor record.
            project.actors.push(sign::ActorRecord {
                id: new_id.clone(),
                public_key: trimmed.to_string(),
                algorithm: "ed25519".to_string(),
                created_at: now.clone(),
                tier: None,
                orcid: None,
                access_clearance: None,
                revoked_at: None,
                revoked_reason: None,
            });

            repo::save_to_path(&frontier, &project).unwrap_or_else(|e| fail_return(&e));

            let payload = json!({
                "ok": true,
                "command": "actor.rotate",
                "frontier": frontier.display().to_string(),
                "retired_actor_id": id,
                "retired_pubkey_prefix": old_pubkey_prefix,
                "new_actor_id": new_id,
                "new_pubkey": trimmed,
                "revoked_at": now,
                "reason": reason,
            });
            if json {
                print_json(&payload);
            } else {
                println!(
                    "{} actor {} retired (pubkey {}...), {} registered (pubkey {}...)",
                    style::ok("rotated"),
                    id,
                    old_pubkey_prefix.as_deref().unwrap_or("?"),
                    new_id,
                    &trimmed[..16]
                );
                println!("  revoked_at: {now}");
                println!("  reason:     {reason}");
            }
        }
        ActorAction::List { frontier, json } => {
            let project = repo::load_from_path(&frontier).unwrap_or_else(|e| fail_return(&e));
            if json {
                let payload = json!({
                    "ok": true,
                    "command": "actor.list",
                    "frontier": frontier.display().to_string(),
                    "actors": project.actors,
                });
                print_json(&payload);
            } else {
                println!();
                println!(
                    "  {}",
                    format!("VELA · ACTOR · LIST · {}", frontier.display())
                        .to_uppercase()
                        .dimmed()
                );
                println!("  {}", style::tick_row(60));
                if project.actors.is_empty() {
                    println!("  (no actors registered)");
                } else {
                    for actor in &project.actors {
                        println!(
                            "  {:<28} {}…  registered {}",
                            actor.id,
                            &actor.public_key[..16],
                            actor.created_at
                        );
                    }
                }
            }
        }
        ActorAction::LookupOrcid {
            orcid,
            register_on,
            id,
            pubkey,
            json,
        } => cmd_actor_lookup_orcid(orcid, register_on, id, pubkey, json),
    }
}

/// v0.155: resolve an ORCID via the ORCID public API + optionally
/// register the resolved person as an actor on a frontier.
fn cmd_actor_lookup_orcid(
    orcid: String,
    register_on: Option<PathBuf>,
    id: Option<String>,
    pubkey: Option<String>,
    json: bool,
) {
    // Normalize ORCID via the existing v0.43 validator.
    let normalized = sign::validate_orcid(&orcid).unwrap_or_else(|e| fail_return(&e));

    // Call the public ORCID API (`https://pub.orcid.org/v3.0/...`).
    let client = reqwest::blocking::Client::builder()
        .user_agent("vela-cli/0.155 (https://github.com/vela-science/vela)")
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap_or_else(|e| fail_return(&format!("http client init: {e}")));
    let url = format!("https://pub.orcid.org/v3.0/{normalized}/person");
    let resp_result = client.get(&url).header("Accept", "application/json").send();

    let (status_label, name, affiliation, note) = match resp_result {
        Ok(resp) if resp.status().is_success() => match resp.json::<serde_json::Value>() {
            Ok(body) => {
                let given = body
                    .pointer("/name/given-names/value")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let family = body
                    .pointer("/name/family-name/value")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let display_name = format!("{given} {family}").trim().to_string();
                let affil_opt = body
                    .pointer("/employments/employment-summary/0/organization/name")
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
                    .or_else(|| {
                        body.pointer("/educations/education-summary/0/organization/name")
                            .and_then(|v| v.as_str())
                            .map(str::to_string)
                    });
                (
                    "resolved",
                    if display_name.is_empty() {
                        None
                    } else {
                        Some(display_name)
                    },
                    affil_opt,
                    None,
                )
            }
            Err(e) => ("parse_error", None, None, Some(format!("parse: {e}"))),
        },
        Ok(resp) => (
            "http_error",
            None,
            None,
            Some(format!("HTTP {}", resp.status())),
        ),
        Err(e) => ("unreachable", None, None, Some(format!("{e}"))),
    };

    let unreachable = status_label == "unreachable";

    // Optionally auto-register the actor on the supplied frontier.
    let mut registered_summary: Option<serde_json::Value> = None;
    if let Some(frontier_path) = register_on {
        let actor_id = id.unwrap_or_else(|| {
            fail_return("--register-on requires --id (stable actor id like `reviewer:will-blair`).")
        });
        let pubkey_hex = pubkey.unwrap_or_else(|| {
            fail_return("--register-on requires --pubkey (64 hex chars Ed25519).")
        });
        let trimmed = pubkey_hex.trim();
        if trimmed.len() != 64 || hex::decode(trimmed).is_err() {
            fail("--pubkey must be 64 hex characters (32-byte Ed25519 pubkey).");
        }
        let mut project = repo::load_from_path(&frontier_path).unwrap_or_else(|e| fail_return(&e));
        if project.actors.iter().any(|a| a.id == actor_id) {
            fail(&format!(
                "Actor '{actor_id}' already registered in this frontier."
            ));
        }
        project.actors.push(sign::ActorRecord {
            id: actor_id.clone(),
            public_key: trimmed.to_string(),
            algorithm: "ed25519".to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
            tier: None,
            orcid: Some(normalized.clone()),
            access_clearance: None,
            revoked_at: None,
            revoked_reason: None,
        });
        repo::save_to_path(&frontier_path, &project)
            .unwrap_or_else(|e| fail_return(&format!("save: {e}")));
        registered_summary = Some(json!({
            "frontier": frontier_path.display().to_string(),
            "actor_id": actor_id,
            "pubkey": trimmed,
            "orcid": normalized,
        }));
    }

    let payload = json!({
        "ok": !unreachable,
        "command": "actor.lookup-orcid",
        "orcid": normalized,
        "status": status_label,
        "name": name,
        "affiliation": affiliation,
        "note": note,
        "registered": registered_summary,
    });
    if json {
        print_json(&payload);
    } else {
        match status_label {
            "resolved" => {
                println!("{} resolved ORCID {normalized}", style::ok("orcid"),);
                if let Some(n) = &name {
                    println!("  name:        {n}");
                }
                if let Some(a) = &affiliation {
                    println!("  affiliation: {a}");
                }
                if let Some(reg) = &registered_summary {
                    println!(
                        "  registered:  actor {} on {}",
                        reg.get("actor_id").and_then(|v| v.as_str()).unwrap_or("?"),
                        reg.get("frontier").and_then(|v| v.as_str()).unwrap_or("?")
                    );
                }
            }
            other => {
                eprintln!(
                    "warn · ORCID lookup {other}: {}",
                    note.as_deref().unwrap_or("(no detail)")
                );
            }
        }
    }
    if unreachable {
        std::process::exit(0); // Skip-gracefully: offline ORCID is not a hard error
    }
}

/// v0.46: Cross-frontier bridge runtime — derive, list, show,
/// confirm, and refute first-class `vbr_<id>` records.
fn cmd_bridges(action: BridgesAction) {
    use vela_protocol::bridge::{Bridge, BridgeStatus, derive_bridges};
    use std::collections::HashMap;

    fn bridges_dir(frontier: &Path) -> PathBuf {
        frontier.join(".vela/bridges")
    }

    fn load_bridge(frontier: &Path, id: &str) -> Result<Bridge, String> {
        let path = bridges_dir(frontier).join(format!("{id}.json"));
        if !path.is_file() {
            return Err(format!("bridge not found: {id}"));
        }
        let data = std::fs::read_to_string(&path).map_err(|e| format!("read {id}: {e}"))?;
        serde_json::from_str(&data).map_err(|e| format!("parse {id}: {e}"))
    }

    fn save_bridge(frontier: &Path, b: &Bridge) -> Result<(), String> {
        let dir = bridges_dir(frontier);
        std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir bridges/: {e}"))?;
        let path = dir.join(format!("{}.json", b.id));
        let data = serde_json::to_string_pretty(b).map_err(|e| format!("serialize bridge: {e}"))?;
        std::fs::write(&path, format!("{data}\n")).map_err(|e| format!("write bridge: {e}"))
    }

    /// v0.67: shared default for the agent-driven write paths
    /// (bridge confirm/refute).
    fn default_reviewer_id() -> String {
        std::env::var("VELA_REVIEWER_ID").unwrap_or_else(|_| "reviewer:will-blair".to_string())
    }

    /// v0.67: emit a `bridge.reviewed` canonical event into the
    /// frontier's `.vela/events/` directory so federation sync can
    /// propagate the verdict. The bridge file mutation is the
    /// projection; this event is the authority.
    ///
    /// v0.73: tightens the spec gap surfaced in v0.72. Before
    /// emission, the function asks `validate_bridge_reviewed_against_state`
    /// to confirm the bridge is present on this frontier. The
    /// signature-pure validator already rejects bad payload shapes;
    /// this second pass rejects bridge_ids that don't exist locally.
    fn emit_bridge_reviewed_event(
        frontier: &Path,
        bridge_id: &str,
        status: &str,
        reviewer_id: &str,
        note: Option<&str>,
    ) -> Result<(), String> {
        let mut payload = serde_json::json!({
            "bridge_id": bridge_id,
            "status": status,
        });
        if let Some(n) = note
            && !n.trim().is_empty()
        {
            payload["note"] = serde_json::Value::String(n.to_string());
        }
        // v0.73: state-aware validation.
        let known_ids: Vec<String> = list_bridges(frontier)
            .unwrap_or_default()
            .into_iter()
            .map(|b| b.id)
            .collect();
        vela_protocol::events::validate_bridge_reviewed_against_state(&payload, &known_ids)?;
        let event = vela_protocol::events::new_bridge_reviewed_event(
            bridge_id,
            reviewer_id,
            "human",
            &format!("Bridge {status} by {reviewer_id}"),
            payload,
            Vec::new(),
        );
        let events_dir = frontier.join(".vela/events");
        std::fs::create_dir_all(&events_dir).map_err(|e| format!("mkdir .vela/events: {e}"))?;
        let event_path = events_dir.join(format!("{}.json", event.id));
        let data =
            serde_json::to_string_pretty(&event).map_err(|e| format!("serialize event: {e}"))?;
        std::fs::write(&event_path, format!("{data}\n")).map_err(|e| format!("write event: {e}"))
    }

    fn list_bridges(frontier: &Path) -> Result<Vec<Bridge>, String> {
        let dir = bridges_dir(frontier);
        if !dir.is_dir() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&dir).map_err(|e| format!("read bridges/: {e}"))? {
            let entry = entry.map_err(|e| format!("read entry: {e}"))?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            let data = std::fs::read_to_string(&path).map_err(|e| format!("read {path:?}: {e}"))?;
            let b: Bridge =
                serde_json::from_str(&data).map_err(|e| format!("parse {path:?}: {e}"))?;
            out.push(b);
        }
        out.sort_by(|a, b| {
            b.finding_refs
                .len()
                .cmp(&a.finding_refs.len())
                .then(a.entity_name.cmp(&b.entity_name))
        });
        Ok(out)
    }

    match action {
        BridgesAction::Derive {
            frontier_a,
            label_a,
            frontier_b,
            label_b,
            json,
        } => {
            let a = repo::load_from_path(&frontier_a).unwrap_or_else(|e| fail_return(&e));
            let b = repo::load_from_path(&frontier_b).unwrap_or_else(|e| fail_return(&e));
            let now = chrono::Utc::now().to_rfc3339();
            let new_bridges =
                derive_bridges(&[(label_a.as_str(), &a), (label_b.as_str(), &b)], &now);

            // Merge: preserve status from existing bridges with the
            // same vbr_<id> (we don't blindly overwrite a Confirmed
            // bridge with a fresh Derived one).
            let existing = list_bridges(&frontier_a).unwrap_or_default();
            let existing_by_id: HashMap<String, Bridge> =
                existing.iter().map(|b| (b.id.clone(), b.clone())).collect();
            let mut written = 0;
            let mut preserved = 0;
            let mut new_ids = Vec::new();
            for mut bridge in new_bridges {
                if let Some(prev) = existing_by_id.get(&bridge.id)
                    && prev.status != BridgeStatus::Derived
                {
                    // Reviewer judgment is sticky.
                    bridge.status = prev.status;
                    bridge.derived_at = prev.derived_at.clone();
                    preserved += 1;
                }
                save_bridge(&frontier_a, &bridge).unwrap_or_else(|e| fail_return(&e));
                new_ids.push(bridge.id.clone());
                written += 1;
            }

            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": true,
                        "command": "bridges.derive",
                        "frontier_a": frontier_a.display().to_string(),
                        "frontier_b": frontier_b.display().to_string(),
                        "bridges_written": written,
                        "reviewer_judgments_preserved": preserved,
                        "ids": new_ids,
                    }))
                    .expect("serialize bridges.derive")
                );
                return;
            }

            println!();
            println!(
                "  {}",
                format!("VELA · BRIDGES · DERIVE · {} ↔ {}", label_a, label_b)
                    .to_uppercase()
                    .dimmed()
            );
            println!("  {}", style::tick_row(60));
            println!("  {}  {} bridge(s) materialized", style::ok("ok"), written);
            if preserved > 0 {
                println!(
                    "  {}  {} reviewer judgment(s) preserved",
                    style::ok("kept"),
                    preserved
                );
            }
            for id in new_ids.iter().take(10) {
                println!("    · {id}");
            }
            if new_ids.len() > 10 {
                println!("    … and {} more", new_ids.len() - 10);
            }
            println!();
        }
        BridgesAction::List {
            frontier,
            status,
            json,
        } => {
            let mut bridges = list_bridges(&frontier).unwrap_or_else(|e| fail_return(&e));
            if let Some(s) = status.as_deref() {
                let want = match s.to_lowercase().as_str() {
                    "derived" => BridgeStatus::Derived,
                    "confirmed" => BridgeStatus::Confirmed,
                    "refuted" => BridgeStatus::Refuted,
                    other => fail_return(&format!(
                        "unknown bridge status '{other}' (try derived|confirmed|refuted)"
                    )),
                };
                bridges.retain(|b| b.status == want);
            }
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": true,
                        "command": "bridges.list",
                        "frontier": frontier.display().to_string(),
                        "count": bridges.len(),
                        "bridges": bridges,
                    }))
                    .expect("serialize bridges.list")
                );
                return;
            }
            println!();
            println!(
                "  {}",
                format!("VELA · BRIDGES · LIST · {}", frontier.display())
                    .to_uppercase()
                    .dimmed()
            );
            println!("  {}", style::tick_row(60));
            println!("  {} bridge(s)", bridges.len());
            for b in &bridges {
                let chip = match b.status {
                    BridgeStatus::Derived => style::warn("derived"),
                    BridgeStatus::Confirmed => style::ok("confirmed"),
                    BridgeStatus::Refuted => style::lost("refuted"),
                };
                println!();
                println!(
                    "  {chip}  {}  {} ↔ findings:{}",
                    b.id,
                    b.entity_name,
                    b.finding_refs.len()
                );
                println!("    frontiers: {}", b.frontiers.join(", "));
                if let Some(t) = &b.tension {
                    println!("    tension:   {t}");
                }
            }
            println!();
        }
        BridgesAction::Show {
            frontier,
            bridge_id,
            json,
        } => {
            let b = load_bridge(&frontier, &bridge_id).unwrap_or_else(|e| fail_return(&e));
            if json {
                print_json(&b);
                return;
            }
            println!();
            println!(
                "  {}",
                format!("VELA · BRIDGES · SHOW · {}", b.id)
                    .to_uppercase()
                    .dimmed()
            );
            println!("  {}", style::tick_row(60));
            println!("  entity:    {}", b.entity_name);
            println!("  status:    {:?}", b.status);
            println!("  frontiers: {}", b.frontiers.join(", "));
            if !b.frontier_ids.is_empty() {
                println!("  frontier_ids: {}", b.frontier_ids.join(", "));
            }
            if let Some(t) = &b.tension {
                println!("  tension:   {t}");
            }
            println!("  derived_at: {}", b.derived_at);
            println!("  finding refs ({}):", b.finding_refs.len());
            for r in &b.finding_refs {
                let dir = r.direction.as_deref().unwrap_or("—");
                let truncated: String = r.assertion_text.chars().take(72).collect();
                println!(
                    "    · [{}] {} (conf={:.2}, dir={})",
                    r.frontier, r.finding_id, r.confidence, dir
                );
                println!("      {truncated}");
            }
            println!();
        }
        BridgesAction::Confirm {
            frontier,
            bridge_id,
            reviewer,
            note,
            json,
        } => {
            let mut b = load_bridge(&frontier, &bridge_id).unwrap_or_else(|e| fail_return(&e));
            let reviewer_id = reviewer.unwrap_or_else(default_reviewer_id);
            b.status = BridgeStatus::Confirmed;
            save_bridge(&frontier, &b).unwrap_or_else(|e| fail_return(&e));
            // v0.67: emit canonical event so federation sync
            // propagates the verdict. The bridge file mutation above
            // is the projection; this event is the authority.
            let _ = emit_bridge_reviewed_event(
                &frontier,
                &bridge_id,
                "confirmed",
                &reviewer_id,
                note.as_deref(),
            );
            if json {
                print_json(&b);
                return;
            }
            println!();
            println!("  {}  {} now confirmed", style::ok("confirmed"), b.id);
            println!();
        }
        BridgesAction::Refute {
            frontier,
            bridge_id,
            reviewer,
            note,
            json,
        } => {
            let mut b = load_bridge(&frontier, &bridge_id).unwrap_or_else(|e| fail_return(&e));
            let reviewer_id = reviewer.unwrap_or_else(default_reviewer_id);
            b.status = BridgeStatus::Refuted;
            save_bridge(&frontier, &b).unwrap_or_else(|e| fail_return(&e));
            let _ = emit_bridge_reviewed_event(
                &frontier,
                &bridge_id,
                "refuted",
                &reviewer_id,
                note.as_deref(),
            );
            if json {
                print_json(&b);
                return;
            }
            println!();
            println!("  {}  {} now refuted", style::lost("refuted"), b.id);
            println!();
        }
    }
}

/// v0.70: Push a single locally-resolved
/// `frontier.conflict_resolved` event to the peer hub's intake
/// endpoint. The reviewer is the only one who can sign the push —
/// the browser/Workbench never sees the key, same as for proposal
/// signing under Phase R.
///
/// Substrate doctrine: one event per push (no bulk), the hub
/// verifies the signature against an actor record on its own copy
/// of the frontier, the hub refuses unpaired or already-resolved
/// events. The CLI does the matching work locally to fail fast
/// when the consumer's own log is missing the resolution.
pub(crate) fn cmd_federation_push_resolution(
    frontier: PathBuf,
    conflict_event_id: String,
    to: String,
    key: Option<PathBuf>,
    vfr_id: Option<String>,
    json: bool,
) {
    use vela_protocol::canonical;
    use vela_protocol::sign;

    let project = repo::load_from_path(&frontier).unwrap_or_else(|e| fail_return(&e));

    let Some(peer) = project.peers.iter().find(|p| p.id == to).cloned() else {
        fail(&format!(
            "peer '{to}' not in registry; run `vela federation peer-add` first"
        ));
    };

    // Locate the resolution event paired with conflict_event_id.
    let Some(resolution) = project
        .events
        .iter()
        .find(|e| {
            e.kind == "frontier.conflict_resolved"
                && e.payload.get("conflict_event_id").and_then(|v| v.as_str())
                    == Some(conflict_event_id.as_str())
        })
        .cloned()
    else {
        fail(&format!(
            "no frontier.conflict_resolved event paired with conflict {conflict_event_id} in {}",
            frontier.display()
        ));
    };

    // Resolve the actor record so we know which public key to send
    // and which key file to load.
    let actor_id = resolution.actor.id.clone();
    let Some(actor) = project.actors.iter().find(|a| a.id == actor_id) else {
        fail(&format!(
            "resolution event's actor.id ({actor_id}) is not in the frontier's actor registry; \
             register the reviewer with `vela actor add` before pushing"
        ));
    };

    // Resolve the private key path. Caller can pass --key explicitly;
    // otherwise look in the conventional locations.
    let key_path = key.unwrap_or_else(|| {
        let home = std::env::var("HOME").unwrap_or_default();
        let base = PathBuf::from(home)
            .join(".config")
            .join("vela")
            .join("keys");
        let safe_id = actor.id.replace([':', '/'], "_");
        let by_actor = base.join(format!("{safe_id}.key"));
        if by_actor.exists() {
            by_actor
        } else {
            base.join("private.key")
        }
    });

    let signing_key = sign::load_signing_key_from_path(&key_path).unwrap_or_else(|e| {
        fail_return(&format!(
            "load private key from {}: {e}",
            key_path.display()
        ))
    });
    let pubkey_hex = sign::pubkey_hex(&signing_key);
    if !pubkey_hex.eq_ignore_ascii_case(&actor.public_key) {
        fail(&format!(
            "private key at {} does not match actor {}'s registered public key. \
             Loaded pubkey {}, expected {}.",
            key_path.display(),
            actor.id,
            &pubkey_hex[..16],
            &actor.public_key[..16]
        ));
    }

    // Sign canonical bytes. Same preimage `verify_event_signature`
    // checks on the hub side.
    let signature_hex = sign::sign_event(&resolution, &signing_key)
        .unwrap_or_else(|e| fail_return(&format!("sign event: {e}")));

    // The wire body is the canonical event JSON without the
    // signature field; the signature travels in the header. This
    // keeps the body byte-exact with what the hub will canonicalize
    // for verification.
    let mut body = resolution.clone();
    body.signature = None;
    let body_value =
        serde_json::to_value(&body).unwrap_or_else(|e| fail_return(&format!("serialize: {e}")));
    let _canonical_check = canonical::to_canonical_bytes(&body_value)
        .unwrap_or_else(|e| fail_return(&format!("canonicalize: {e}")));

    let target_vfr = vfr_id.unwrap_or_else(|| project.frontier_id());
    let url = format!(
        "{}/entries/{}/events",
        peer.url.trim_end_matches('/'),
        target_vfr
    );

    // Same blocking-thread escape pattern as the rest of federation.rs.
    let url_owned = url.clone();
    let pubkey_owned = pubkey_hex.clone();
    let signature_owned = signature_hex.clone();
    let body_owned = body_value.clone();
    let response: Result<(u16, String), String> = std::thread::spawn(move || {
        let client = reqwest::blocking::Client::new();
        let resp = client
            .post(&url_owned)
            .header("X-Vela-Signer-Pubkey", &pubkey_owned)
            .header("X-Vela-Signature", &signature_owned)
            .json(&body_owned)
            .send()
            .map_err(|e| format!("HTTP POST {url_owned}: {e}"))?;
        let status = resp.status().as_u16();
        let text = resp.text().unwrap_or_default();
        Ok((status, text))
    })
    .join()
    .map_err(|_| "push thread panicked".to_string())
    .unwrap_or_else(|e| fail_return(&e));

    let (status, text) = response.unwrap_or_else(|e| fail_return(&e));
    let parsed: serde_json::Value =
        serde_json::from_str(&text).unwrap_or_else(|_| json!({ "raw": text }));

    let accepted = matches!(status, 200..=202);
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": accepted,
                "command": "federation.push-resolution",
                "frontier": frontier.display().to_string(),
                "peer_id": to,
                "url": url,
                "conflict_event_id": conflict_event_id,
                "event_id": resolution.id,
                "actor_id": actor.id,
                "http_status": status,
                "response": parsed,
            }))
            .expect("serialize federation.push-resolution")
        );
    } else if accepted {
        println!(
            "{} resolution {} pushed to {} (HTTP {})",
            style::ok("ok"),
            &resolution.id[..16.min(resolution.id.len())],
            to,
            status
        );
        println!("  url:    {url}");
        println!("  signer: {} (actor {})", &pubkey_hex[..16], actor.id);
    } else {
        println!("{} push refused (HTTP {})", style::lost("rejected"), status);
        println!("  url:      {url}");
        println!("  response: {text}");
        std::process::exit(1);
    }
}

/// Phase R (v0.5): walk the local Workbench draft queue. The Workbench
/// browser writes unsigned drafts to a queue file; this CLI is the only
/// place where the actor's private key reads its drafts and signs them.
/// The browser never sees the key.
fn cmd_queue(action: QueueAction) {
    use vela_protocol::queue;
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
            let key_hex = std::fs::read_to_string(&key)
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|e| fail_return(&format!("read key {}: {e}", key.display())));
            let signing_key = parse_signing_key(&key_hex);
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

fn confirm_action(action: &vela_protocol::queue::QueuedAction) -> bool {
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
fn sign_and_apply(
    signing_key: &ed25519_dalek::SigningKey,
    actor: &str,
    action: &vela_protocol::queue::QueuedAction,
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
                let event_id =
                    vela_protocol::proposals::accept_at_path(&action.frontier, proposal_id, actor, reason)
                        .map_err(|e| format!("accept_at_path: {e}"))?;
                Ok(format!("event {event_id}"))
            } else {
                vela_protocol::proposals::reject_at_path(&action.frontier, proposal_id, actor, reason)
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
/// v0.19: bundled entity resolution. See `vela_protocol::entity_resolve` for the
/// table + algorithm. CLI surface is two subcommands: `resolve` (mutates
/// the frontier file) and `list` (read-only inspection of the table).
fn cmd_entity(action: EntityAction) {
    use vela_protocol::entity_resolve;
    match action {
        EntityAction::Resolve {
            frontier,
            force,
            json,
        } => {
            let mut p = repo::load_from_path(&frontier).unwrap_or_else(|e| fail_return(&e));
            let report = entity_resolve::resolve_frontier(&mut p, force);
            repo::save_to_path(&frontier, &p).unwrap_or_else(|e| fail_return(&e));
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true,
                        "command": "entity.resolve",
                        "frontier_path": frontier.display().to_string(),
                        "report": report,
                    }))
                    .expect("serialize")
                );
            } else {
                println!(
                    "{} resolved {} of {} entities ({} already, {} unresolved) across {} findings",
                    style::ok("entity"),
                    report.resolved,
                    report.total_entities,
                    report.already_resolved,
                    report.unresolved_count,
                    report.findings_touched,
                );
                let unresolved_summary: std::collections::BTreeSet<&str> = report
                    .per_finding
                    .iter()
                    .flat_map(|f| f.unresolved.iter().map(String::as_str))
                    .collect();
                if !unresolved_summary.is_empty() {
                    let take = unresolved_summary.iter().take(8).collect::<Vec<_>>();
                    println!(
                        "  unresolved (first {}): {}",
                        take.len(),
                        take.iter().copied().cloned().collect::<Vec<_>>().join(", ")
                    );
                }
            }
        }
        EntityAction::List { json } => {
            let entries: Vec<serde_json::Value> = entity_resolve::iter_bundled()
                .map(|(name, etype, source, id)| {
                    serde_json::json!({
                        "canonical_name": name,
                        "entity_type": etype,
                        "source": source,
                        "id": id,
                    })
                })
                .collect();
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true,
                        "command": "entity.list",
                        "count": entries.len(),
                        "entries": entries,
                    }))
                    .expect("serialize")
                );
            } else {
                println!("{} {} bundled entries", style::ok("entity"), entries.len());
                for e in &entries {
                    println!(
                        "  {:32}  {:18}  {} {}",
                        e["canonical_name"].as_str().unwrap_or("?"),
                        e["entity_type"].as_str().unwrap_or("?"),
                        e["source"].as_str().unwrap_or("?"),
                        e["id"].as_str().unwrap_or("?"),
                    );
                }
            }
        }
    }
}

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

fn resolve_frontier_shards_manifest(frontier: &Path) -> Result<PathBuf, String> {
    let manifest_name = "frontier-state-manifest.v1.json";
    if frontier.is_file() && frontier.file_name().and_then(|s| s.to_str()) == Some(manifest_name) {
        return Ok(frontier.to_path_buf());
    }
    if frontier.is_dir() {
        let repo_manifest = frontier.join("frontier-state-shards").join(manifest_name);
        if repo_manifest.is_file() {
            return Ok(repo_manifest);
        }
        let direct_manifest = frontier.join(manifest_name);
        if direct_manifest.is_file() {
            return Ok(direct_manifest);
        }
    }
    if frontier.file_name().and_then(|s| s.to_str()) == Some("frontier.json")
        && let Some(parent) = frontier.parent() {
            let manifest = parent.join("frontier-state-shards").join(manifest_name);
            if manifest.is_file() {
                return Ok(manifest);
            }
        }
    Err(format!(
        "no frontier state shard manifest found for {}; expected frontier-state-shards/{manifest_name}",
        frontier.display()
    ))
}

fn json_path_u64(value: &Value, path: &[&str]) -> u64 {
    let mut cursor = value;
    for key in path {
        cursor = match cursor.get(*key) {
            Some(next) => next,
            None => return 0,
        };
    }
    cursor.as_u64().unwrap_or(0)
}

fn json_path_str<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut cursor = value;
    for key in path {
        cursor = cursor.get(*key)?;
    }
    cursor.as_str()
}

fn load_frontier_shards_manifest(frontier: &Path) -> Result<(PathBuf, Value), String> {
    let manifest_path = resolve_frontier_shards_manifest(frontier)?;
    let raw = std::fs::read_to_string(&manifest_path).unwrap_or_else(|e| {
        fail_return(&format!(
            "failed to read shard manifest '{}': {e}",
            manifest_path.display()
        ))
    });
    let manifest: Value = serde_json::from_str(&raw).unwrap_or_else(|e| {
        fail_return(&format!(
            "failed to parse shard manifest '{}': {e}",
            manifest_path.display()
        ))
    });
    Ok((manifest_path, manifest))
}

fn frontier_json_status(frontier_bytes: u64) -> &'static str {
    if frontier_bytes >= 100_000_000 {
        "over_hard_limit"
    } else if frontier_bytes >= 90_000_000 {
        "near_hard_limit"
    } else if frontier_bytes >= 50_000_000 {
        "above_recommended"
    } else {
        "ok"
    }
}

fn source_frontier_json_summary(manifest: &Value) -> Value {
    let source_frontier_path = json_path_str(manifest, &["source_frontier_json", "path"])
        .map(PathBuf::from)
        .or_else(|| json_path_str(manifest, &["frontier"]).map(PathBuf::from));
    let declared_frontier_bytes = json_path_u64(manifest, &["source_frontier_json", "byte_count"]);
    let current_frontier_bytes = source_frontier_path
        .as_ref()
        .and_then(|path| std::fs::metadata(path).ok())
        .map(|metadata| metadata.len());
    let frontier_bytes = current_frontier_bytes.unwrap_or(declared_frontier_bytes);
    let source_frontier_current = current_frontier_bytes
        .map(|current| current == declared_frontier_bytes)
        .unwrap_or(false);

    json!({
        "path": source_frontier_path.as_ref().map(|path| path.display().to_string()),
        "declared_byte_count": declared_frontier_bytes,
        "current_byte_count": current_frontier_bytes,
        "current_matches_manifest": source_frontier_current,
        "status": frontier_json_status(frontier_bytes),
        "github_recommended_bytes": 50_000_000_u64,
        "repo_caution_bytes": 90_000_000_u64,
        "github_hard_bytes": 100_000_000_u64,
    })
}

pub(crate) fn cmd_frontier_shards(frontier: PathBuf, json_out: bool) {
    let (manifest_path, manifest) =
        load_frontier_shards_manifest(&frontier).unwrap_or_else(|e| fail_return(&e));
    let compatibility_snapshot = source_frontier_json_summary(&manifest);
    let frontier_bytes = compatibility_snapshot
        .get("current_byte_count")
        .or_else(|| compatibility_snapshot.get("declared_byte_count"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let max_shard_bytes = json_path_u64(&manifest, &["storage", "max_shard_byte_count"]);
    let shard_count = json_path_u64(&manifest, &["storage", "shard_count"]);
    let records_in_shards = json_path_u64(&manifest, &["storage", "records_in_shards"]);
    let item_counts = manifest
        .get("storage")
        .and_then(|v| v.get("item_counts"))
        .cloned()
        .unwrap_or(Value::Null);
    let stats = manifest.get("stats").cloned().unwrap_or(Value::Null);
    let claim_boundary = manifest
        .get("claim_boundary")
        .cloned()
        .unwrap_or(Value::Null);
    let authority = manifest.get("authority").cloned().unwrap_or(Value::Null);
    let ok = manifest.get("schema").and_then(Value::as_str)
        == Some("vela.frontier_state_shards.v1")
        && max_shard_bytes > 0
        && max_shard_bytes < 50_000_000
        && frontier_bytes < 100_000_000;

    let payload = json!({
        "ok": ok,
        "command": "frontier.shards",
        "manifest": manifest_path.display().to_string(),
        "schema": manifest.get("schema").cloned().unwrap_or(Value::Null),
        "frontier_id": manifest.get("frontier_id").cloned().unwrap_or(Value::Null),
        "source_frontier_json": compatibility_snapshot,
        "storage": {
            "format": json_path_str(&manifest, &["storage", "format"]).unwrap_or(""),
            "shard_count": shard_count,
            "records_in_shards": records_in_shards,
            "max_shard_byte_count": max_shard_bytes,
            "item_counts": item_counts,
        },
        "stats": stats,
        "authority": authority,
        "claim_boundary": claim_boundary,
        "caveats": [
            "This command inspects the shard manifest and filesystem metadata only.",
            "frontier.json remains a compatibility snapshot for proof replay and export.",
            "Sharded records are trusted only to the extent that the recorded proof state and frontier checks are fresh."
        ],
    });

    if json_out {
        print_json(&payload);
        return;
    }

    let status = if ok {
        style::ok("frontier.shards")
    } else {
        style::warn("frontier.shards")
    };
    println!();
    println!("  {}", "Vela · frontier shards".dimmed());
    println!("  {}", style::tick_row(60));
    println!("  {status}");
    println!("  manifest:       {}", manifest_path.display());
    if let Some(id) = manifest.get("frontier_id").and_then(Value::as_str) {
        println!("  frontier:       {id}");
    }
    println!("  shards:         {shard_count}");
    println!("  records:        {records_in_shards}");
    println!("  max shard:      {max_shard_bytes} bytes");
    println!(
        "  frontier.json:  {} bytes ({})",
        frontier_bytes,
        frontier_json_status(frontier_bytes)
    );
    println!("  {}", style::tick_row(60));
    println!();
}

/// v0.158: tag the current frontier state as a versioned release.
pub(crate) fn cmd_frontier_release(
    frontier: PathBuf,
    name: String,
    notes: Option<String>,
    previous: Option<String>,
    json: bool,
) {
    use vela_protocol::frontier_release::{FrontierRelease, ReleaseDraft};

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
    use vela_protocol::frontier_release::FrontierRelease;

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
    let mut review_work = crate::workbench::build_review_work_json(&frontier)
        .map(Some)
        .unwrap_or_else(|e| {
            Some(json!({
                "ok": false,
                "command": "review-work",
                "frontier_path": frontier.display().to_string(),
                "error": e,
            }))
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

pub(crate) fn cmd_frontier_health(frontier: PathBuf, json: bool) {
    let report = frontier_health::analyze(&frontier).unwrap_or_else(|e| fail_return(&e));
    if json {
        print_json(&report);
        return;
    }

    let status = if report.ok {
        style::ok("frontier.health")
    } else {
        style::warn("frontier.health")
    };
    println!("{status} {}", report.frontier_id);
    println!("  proof:              {}", report.metrics.proof_status);
    println!(
        "  tasks:              {} active · {} blocked · {} awaiting review",
        report.metrics.active_tasks,
        report.metrics.blocked_tasks,
        report.metrics.awaiting_review_tasks
    );
    println!(
        "  diff packs:         {} pending · {} accepted · {} rejected · {} revision",
        report.metrics.pending_diff_packs,
        report.metrics.accepted_diff_packs,
        report.metrics.rejected_diff_packs,
        report.metrics.revision_requested_diff_packs
    );
    println!(
        "  Evidence CI:        {} failures · {} warnings",
        report.metrics.evidence_ci_failures, report.metrics.evidence_ci_warnings
    );
    println!(
        "  source inbox:       {} issue(s)",
        report.metrics.source_inbox_issues
    );
    println!(
        "  missing attest:     {} role(s) across {} target(s)",
        report.metrics.missing_attestations, report.metrics.missing_attestation_targets
    );
    if report.issues.is_empty() {
        println!("  issues:             none");
    } else {
        println!("  issues:");
        for issue in &report.issues {
            println!(
                "    {} {} · {} ({})",
                issue.severity, issue.count, issue.label, issue.href
            );
        }
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
    use vela_protocol::frontier_release::FrontierRelease;
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

fn cmd_repo(action: RepoAction) {
    match action {
        RepoAction::Status { frontier, json } => {
            let payload = frontier_repo::repo_status(&frontier).unwrap_or_else(|e| fail_return(&e));
            if json {
                print_json(&payload);
            } else {
                let summary = payload.get("summary").unwrap_or(&Value::Null);
                let freshness = payload.get("freshness").unwrap_or(&Value::Null);
                println!("vela repo status");
                println!("  frontier: {}", frontier.display());
                println!(
                    "  events:   {}",
                    summary
                        .get("accepted_events")
                        .and_then(Value::as_u64)
                        .unwrap_or_default()
                );
                println!(
                    "  open proposals: {}",
                    summary
                        .get("open_proposals")
                        .and_then(Value::as_u64)
                        .unwrap_or_default()
                );
                println!(
                    "  state:    {}",
                    freshness
                        .get("materialized_state")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown")
                );
                println!(
                    "  proof:    {}",
                    freshness
                        .get("proof")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown")
                );
            }
        }
        RepoAction::Doctor { frontier, json } => {
            let payload = frontier_repo::repo_doctor(&frontier).unwrap_or_else(|e| fail_return(&e));
            if json {
                print_json(&payload);
            } else {
                let ok = payload.get("ok").and_then(Value::as_bool) == Some(true);
                let issues = payload
                    .get("issues")
                    .and_then(Value::as_array)
                    .map_or(0, Vec::len);
                println!("vela repo doctor");
                println!("  frontier: {}", frontier.display());
                println!("  status:   {}", if ok { "ok" } else { "needs attention" });
                println!("  issues:   {issues}");
            }
        }
    }
}

fn cmd_doctor(frontier: Option<&Path>, port: u16, json_output: bool) {
    let report = doctor::run(frontier, port);
    if json_output {
        print_json(&report);
    } else {
        println!("vela doctor");
        println!("  binary:      {}", report.binary_version);
        println!("  frontier:    {}", report.frontier_path);
        println!("  kind:        {}", report.frontier_kind);
        println!(
            "  policy:      {}",
            if report.policy_ok {
                "ok"
            } else {
                "needs attention"
            }
        );
        println!("  proof:       {}", report.proof_status);
        println!(
            "  evidence ci: {}",
            if report.evidence_ci_ok {
                "ok"
            } else {
                "needs attention"
            }
        );
        println!(
            "  workbench:   port {} {}",
            report.workbench_port,
            if report.workbench_port_available {
                "available"
            } else {
                "unavailable"
            }
        );
        if !report.blocking.is_empty() {
            println!("  blocking:    {}", report.blocking.join(", "));
        }
        if !report.warnings.is_empty() {
            println!("  warnings:    {}", report.warnings.join(", "));
        }
        println!();
        println!("next:");
        for command in &report.next_commands {
            println!("  {command}");
        }
        if let Some(config) = &report.mcp_config {
            println!();
            println!("mcp:");
            println!(
                "  {}",
                serde_json::to_string(config).expect("serialize mcp config")
            );
        }
    }
    if !report.blocking.is_empty() {
        std::process::exit(1);
    }
}

fn cmd_proof_verify(frontier: &Path, json_output: bool) {
    let payload = frontier_repo::proof_verify(frontier).unwrap_or_else(|e| fail_return(&e));
    if json_output {
        print_json(&payload);
        if payload.get("ok").and_then(Value::as_bool) != Some(true) {
            std::process::exit(1);
        }
    } else {
        let ok = payload.get("ok").and_then(Value::as_bool) == Some(true);
        println!("vela proof verify");
        println!("  frontier: {}", frontier.display());
        println!("  status:   {}", if ok { "ok" } else { "failed" });
        if let Some(issues) = payload.get("issues").and_then(Value::as_array) {
            for issue in issues {
                if let Some(message) = issue.get("message").and_then(Value::as_str) {
                    println!("  issue:    {message}");
                }
            }
        }
        if !ok {
            std::process::exit(1);
        }
    }
}

fn cmd_proof_explain(frontier: &Path) {
    let text = frontier_repo::proof_explain(frontier).unwrap_or_else(|e| fail_return(&e));
    print!("{text}");
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
                    "pmid": f.provenance.pmid,
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

/// v0.151: handle `vela proof-attest-verification ...`.
#[allow(clippy::too_many_arguments)]
fn cmd_proof_attest_verification(
    proof_id: String,
    tool: String,
    tool_version: String,
    script_locator: String,
    lake_manifest_hash: Option<String>,
    verifier_output_hash: String,
    status: String,
    verifier_actor: String,
    key: PathBuf,
    out: PathBuf,
    json: bool,
) {
    use vela_protocol::proof_verification::{ProofVerification, VerificationDraft};

    let key_hex = std::fs::read_to_string(&key)
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|e| fail_return(&format!("read key: {e}")));
    let sk = parse_signing_key(&key_hex);

    let draft = VerificationDraft {
        proof_id,
        tool,
        tool_version,
        script_locator,
        lake_manifest_hash,
        verifier_output_hash,
        status,
        verified_at: chrono::Utc::now().to_rfc3339(),
        verifier_actor,
    };
    let record = ProofVerification::build(draft, &sk).unwrap_or_else(|e| fail_return(&e));

    let body = serde_json::to_string_pretty(&record).expect("serialize proof verification record");
    std::fs::write(&out, format!("{body}\n"))
        .unwrap_or_else(|e| fail_return(&format!("write {}: {e}", out.display())));

    if json {
        let payload = json!({
            "ok": true,
            "command": "proof-attest-verification",
            "verification_id": record.verification_id,
            "proof_id": record.proof_id,
            "tool": record.tool,
            "tool_version": record.tool_version,
            "status": record.status,
            "verifier_actor": record.verifier_actor,
            "out": out.display().to_string(),
        });
        print_json(&payload);
    } else {
        println!(
            "{} attested {} verifying {} ({} {})",
            style::ok("proof"),
            record.verification_id,
            record.proof_id,
            record.tool,
            record.tool_version
        );
        println!("  status:               {}", record.status);
        println!("  verifier_actor:       {}", record.verifier_actor);
        println!("  verifier_output_hash: {}", record.verifier_output_hash);
        println!("  out:                  {}", out.display());
    }
}

/// v0.151: handle `vela proof-verify-attestation <record>`.
fn cmd_proof_verify_attestation(record: PathBuf, json: bool) {
    use vela_protocol::proof_verification::ProofVerification;

    let raw = std::fs::read_to_string(&record)
        .unwrap_or_else(|e| fail_return(&format!("read record: {e}")));
    let parsed: ProofVerification =
        serde_json::from_str(&raw).unwrap_or_else(|e| fail_return(&format!("parse record: {e}")));

    if let Err(e) = parsed.verify() {
        if json {
            let payload = json!({
                "ok": false,
                "command": "proof-verify-attestation",
                "verification_id": parsed.verification_id,
                "error": e,
            });
            print_json(&payload);
        } else {
            eprintln!("err · {e}");
        }
        std::process::exit(1);
    }

    if json {
        let payload = json!({
            "ok": true,
            "command": "proof-verify-attestation",
            "verification_id": parsed.verification_id,
            "proof_id": parsed.proof_id,
            "tool": parsed.tool,
            "tool_version": parsed.tool_version,
            "status": parsed.status,
            "verifier_actor": parsed.verifier_actor,
            "verifier_pubkey": parsed.verifier_pubkey,
        });
        print_json(&payload);
    } else {
        println!(
            "{} verification {} ok ({} {} verified {})",
            style::ok("verify"),
            parsed.verification_id,
            parsed.tool,
            parsed.tool_version,
            parsed.proof_id
        );
    }
}

/// v0.157: handle `vela credit <frontier>`.
fn cmd_credit(frontier: PathBuf, out: Option<PathBuf>, json: bool) {
    use vela_protocol::credit::build_ledger;

    let project = repo::load_from_path(&frontier).unwrap_or_else(|e| fail_return(&e));
    let now = chrono::Utc::now().to_rfc3339();
    let ledger = build_ledger(&project, &now);
    let body = serde_json::to_string_pretty(&ledger).expect("serialize credit ledger");

    if let Some(out_path) = out {
        std::fs::write(&out_path, format!("{body}\n"))
            .unwrap_or_else(|e| fail_return(&format!("write {}: {e}", out_path.display())));
        if json {
            let payload = json!({
                "ok": true,
                "command": "credit",
                "frontier_id": ledger.frontier_id,
                "contributor_count": ledger.contributor_count,
                "out": out_path.display().to_string(),
            });
            print_json(&payload);
        } else {
            println!(
                "{} credit ledger for {}: {} contributor(s) -> {}",
                style::ok("credit"),
                ledger.frontier_id,
                ledger.contributor_count,
                out_path.display()
            );
        }
    } else if json {
        println!("{body}");
    } else {
        println!(
            "  vela credit · {} · {} contributor(s)",
            ledger.frontier_id, ledger.contributor_count
        );
        println!();
        for c in &ledger.contributors {
            print!("  {}", c.actor_id);
            if let Some(orcid) = &c.orcid {
                print!("  (ORCID {orcid})");
            }
            println!("  · {} event(s)", c.event_count);
            for role in &c.roles {
                let count = c.role_counts.get(role).copied().unwrap_or(0);
                println!("    · {role} ({count})");
            }
        }
    }
}

/// v0.168: handle `vela review-thread ...`. Substrate-honest
/// review threads on proposals or findings; append-only,
/// signed, content-addressed.
fn cmd_review_thread(action: ReviewThreadCli) {
    use vela_protocol::review_thread::{MessageDraft, ReviewMessage, ReviewThread, ThreadTargetKind};

    match action {
        ReviewThreadCli::Create {
            target,
            frontier_id,
            out,
            json,
        } => {
            let kind: ThreadTargetKind = if target.starts_with("vpr_") {
                ThreadTargetKind::Proposal
            } else if target.starts_with("vf_") {
                ThreadTargetKind::Finding
            } else if target.starts_with("vsd_") {
                ThreadTargetKind::DiffPack
            } else {
                fail_return(&format!(
                    "target must start with `vpr_`, `vf_`, or `vsd_`, got `{target}`"
                ))
            };
            let thread = ReviewThread::new(
                kind,
                target.clone(),
                frontier_id.clone(),
                chrono::Utc::now().to_rfc3339(),
            )
            .unwrap_or_else(|e| fail_return(&e));
            let body = serde_json::to_string_pretty(&thread).expect("serialize thread");
            std::fs::write(&out, format!("{body}\n"))
                .unwrap_or_else(|e| fail_return(&format!("write {}: {e}", out.display())));
            if json {
                let payload = json!({
                    "ok": true,
                    "command": "review-thread.create",
                    "thread_id": thread.thread_id,
                    "target": target,
                    "frontier_id": frontier_id,
                    "out": out.display().to_string(),
                });
                print_json(&payload);
            } else {
                println!(
                    "{} {} on {} -> {}",
                    style::ok("review-thread.create"),
                    thread.thread_id,
                    target,
                    out.display()
                );
            }
        }
        ReviewThreadCli::Post {
            thread,
            author_actor_id,
            key,
            message,
            parent,
            json,
        } => {
            let body = std::fs::read_to_string(&thread)
                .unwrap_or_else(|e| fail_return(&format!("read {}: {e}", thread.display())));
            let mut t: ReviewThread = serde_json::from_str(&body)
                .unwrap_or_else(|e| fail_return(&format!("parse thread: {e}")));
            let key_hex = std::fs::read_to_string(&key)
                .unwrap_or_else(|e| fail_return(&format!("read key {}: {e}", key.display())));
            let key_bytes = hex::decode(key_hex.trim())
                .unwrap_or_else(|e| fail_return(&format!("decode key hex: {e}")));
            let key_arr: [u8; 32] = key_bytes
                .try_into()
                .unwrap_or_else(|_| fail_return("signing key must be 32 bytes"));
            let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_arr);
            let msg = ReviewMessage::build(
                MessageDraft {
                    thread_id: t.thread_id.clone(),
                    author_actor_id,
                    body: message,
                    parent_message_id: parent,
                    posted_at: chrono::Utc::now().to_rfc3339(),
                },
                &signing_key,
            )
            .unwrap_or_else(|e| fail_return(&e));
            let message_id = msg.message_id.clone();
            t.append_message(msg)
                .unwrap_or_else(|e| fail_return(&format!("append: {e}")));
            let serialized = serde_json::to_string_pretty(&t).expect("serialize thread");
            std::fs::write(&thread, format!("{serialized}\n"))
                .unwrap_or_else(|e| fail_return(&format!("write {}: {e}", thread.display())));
            if json {
                let payload = json!({
                    "ok": true,
                    "command": "review-thread.post",
                    "thread_id": t.thread_id,
                    "message_id": message_id,
                    "message_count": t.messages.len(),
                });
                print_json(&payload);
            } else {
                println!(
                    "{} {} -> thread {} ({} message(s))",
                    style::ok("review-thread.post"),
                    message_id,
                    t.thread_id,
                    t.messages.len()
                );
            }
        }
        ReviewThreadCli::Verify { thread, json } => {
            let body = std::fs::read_to_string(&thread)
                .unwrap_or_else(|e| fail_return(&format!("read {}: {e}", thread.display())));
            let t: ReviewThread = serde_json::from_str(&body)
                .unwrap_or_else(|e| fail_return(&format!("parse thread: {e}")));
            let mut errors = Vec::new();
            for (i, m) in t.messages.iter().enumerate() {
                if let Err(e) = m.verify() {
                    errors.push(format!("message {i} ({}): {e}", m.message_id));
                }
            }
            if !errors.is_empty() {
                fail(&format!(
                    "review-thread.verify failed: {} error(s)\n  {}",
                    errors.len(),
                    errors.join("\n  ")
                ));
            }
            if json {
                let payload = json!({
                    "ok": true,
                    "command": "review-thread.verify",
                    "thread_id": t.thread_id,
                    "message_count": t.messages.len(),
                });
                print_json(&payload);
            } else {
                println!(
                    "{} {} ({} message(s)) verifies",
                    style::ok("review-thread.verify"),
                    t.thread_id,
                    t.messages.len()
                );
            }
        }
    }
}

/// v0.167: handle `vela hub ...`. Build + validate hub-spec
/// primitive records.
fn cmd_hub_spec(action: HubSpecCli) {
    use vela_protocol::hub_spec::{HubSpec, HubSpecDraft};

    match action {
        HubSpecCli::Declare {
            hub_id,
            display_name,
            base_url,
            operator_pubkey_hex,
            substrate_version,
            contact,
            latest_checkpoint,
            out,
            json,
        } => {
            let spec = HubSpec::from_draft(HubSpecDraft {
                hub_id,
                display_name,
                base_url,
                operator_pubkey_hex,
                substrate_version,
                contact,
                latest_checkpoint,
                declared_at: chrono::Utc::now().to_rfc3339(),
            })
            .unwrap_or_else(|e| fail_return(&e));
            let body = serde_json::to_string_pretty(&spec).expect("serialize hub spec");
            if let Some(path) = out {
                std::fs::write(&path, format!("{body}\n"))
                    .unwrap_or_else(|e| fail_return(&format!("write {}: {e}", path.display())));
                if json {
                    let payload = json!({
                        "ok": true,
                        "command": "hub.declare",
                        "spec_id": spec.spec_id,
                        "hub_id": spec.hub_id,
                        "base_url": spec.base_url,
                        "out": path.display().to_string(),
                    });
                    print_json(&payload);
                } else {
                    println!(
                        "{} {} ({}) -> {}",
                        style::ok("hub.declare"),
                        spec.spec_id,
                        spec.hub_id,
                        path.display()
                    );
                }
            } else {
                println!("{body}");
            }
        }
        HubSpecCli::Validate { spec, json } => {
            let body = std::fs::read_to_string(&spec)
                .unwrap_or_else(|e| fail_return(&format!("read {}: {e}", spec.display())));
            let parsed: HubSpec = serde_json::from_str(&body)
                .unwrap_or_else(|e| fail_return(&format!("parse hub spec: {e}")));
            // Re-derive id from a fresh draft.
            let rebuilt = HubSpec::from_draft(vela_protocol::hub_spec::HubSpecDraft {
                hub_id: parsed.hub_id.clone(),
                display_name: parsed.display_name.clone(),
                base_url: parsed.base_url.clone(),
                operator_pubkey_hex: parsed.operator_pubkey_hex.clone(),
                substrate_version: parsed.substrate_version.clone(),
                contact: parsed.contact.clone(),
                latest_checkpoint: parsed.latest_checkpoint.clone(),
                declared_at: parsed.declared_at.clone(),
            })
            .unwrap_or_else(|e| fail_return(&format!("rebuild for validation: {e}")));
            if rebuilt.spec_id != parsed.spec_id {
                fail(&format!(
                    "spec_id mismatch: declared {}, rebuilt {}",
                    parsed.spec_id, rebuilt.spec_id
                ));
            }
            if json {
                let payload = json!({
                    "ok": true,
                    "command": "hub.validate",
                    "spec_id": parsed.spec_id,
                    "hub_id": parsed.hub_id,
                });
                print_json(&payload);
            } else {
                println!(
                    "{} {} ({}) validates",
                    style::ok("hub.validate"),
                    parsed.spec_id,
                    parsed.hub_id
                );
            }
        }
    }
}

fn cmd_policy(action: PolicyAction) {
    match action {
        PolicyAction::Check { frontier, json } => {
            let summary = vela_protocol::frontier_policy::load_policy_summary(&frontier)
                .unwrap_or_else(|e| fail_return(&format!("policy check failed: {e}")));
            if json {
                print_json(&summary);
            } else {
                println!(
                    "{} frontier policy {}",
                    if summary.ok {
                        style::ok("policy.check")
                    } else {
                        style::warn("policy.check")
                    },
                    summary.frontier_id.as_deref().unwrap_or("unknown-frontier")
                );
                println!("  documents: {}", summary.documents.len());
                if !summary.missing_required.is_empty() {
                    println!("  missing:   {}", summary.missing_required.join(", "));
                }
                println!("  hash:      {}", summary.canonical_json_sha256);
            }
        }
    }
}

fn cmd_task(action: TaskAction) {
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
            let report = vela_protocol::code_executor::execute_task(&frontier, &task_id, &actor)
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
        TaskAction::Workspace { action } => cmd_task_workspace(action),
    }
}

fn cmd_task_workspace(action: TaskWorkspaceAction) {
    match action {
        TaskWorkspaceAction::Init {
            frontier,
            task_id,
            json,
        } => {
            let status = task_workspace::init_workspace(&frontier, &task_id)
                .unwrap_or_else(|e| fail_return(&format!("task workspace init failed: {e}")));
            print_task_workspace_status(&status, json);
        }
        TaskWorkspaceAction::Status {
            frontier,
            task_id,
            json,
        } => {
            let status = task_workspace::workspace_status(&frontier, &task_id)
                .unwrap_or_else(|e| fail_return(&format!("task workspace status failed: {e}")));
            print_task_workspace_status(&status, json);
        }
    }
}

fn cmd_review_packet(action: ReviewPacketAction) {
    match action {
        ReviewPacketAction::Build {
            frontier,
            task_id,
            out,
            json,
        } => {
            let build = review_packet::build(&frontier, &task_id, Some(&out))
                .unwrap_or_else(|e| fail_return(&format!("review-packet build failed: {e}")));
            if json {
                let payload = serde_json::json!({
                    "ok": true,
                    "command": "review-packet.build",
                    "packet": build.packet,
                    "out": out.display().to_string(),
                });
                print_json(&payload);
            } else {
                println!(
                    "{} {} -> {}",
                    style::ok("review-packet.build"),
                    build.packet.packet_id,
                    out.display()
                );
                println!("  workspace markdown: {}", build.packet.markdown_path);
                println!("  workspace json:     {}", build.packet.json_path);
            }
        }
    }
}

fn cmd_review_session(action: ReviewSessionAction) {
    match action {
        ReviewSessionAction::Start {
            frontier,
            reviewer,
            scope,
            transcript,
            json,
        } => {
            let session = review_session::start(&frontier, reviewer, scope, transcript)
                .unwrap_or_else(|e| fail_return(&format!("review-session start failed: {e}")));
            print_review_session(&session, json);
        }
        ReviewSessionAction::Note {
            frontier,
            session_id,
            object,
            note,
            json,
        } => {
            let session = review_session::add_note(&frontier, &session_id, object, note)
                .unwrap_or_else(|e| fail_return(&format!("review-session note failed: {e}")));
            print_review_session(&session, json);
        }
        ReviewSessionAction::Close {
            frontier,
            session_id,
            decision,
            reason,
            follow_up_tasks,
            json,
        } => {
            let decision = decision
                .parse::<review_session::ReviewSessionStatus>()
                .unwrap_or_else(|e| fail_return(&e));
            let session =
                review_session::close(&frontier, &session_id, decision, reason, follow_up_tasks)
                    .unwrap_or_else(|e| fail_return(&format!("review-session close failed: {e}")));
            print_review_session(&session, json);
        }
        ReviewSessionAction::List { frontier, json } => {
            let list = review_session::list(&frontier)
                .unwrap_or_else(|e| fail_return(&format!("review-session list failed: {e}")));
            if json {
                print_json(&list);
            } else if list.sessions.is_empty() {
                println!(
                    "{} no local review sessions",
                    style::warn("review-session.list")
                );
            } else {
                println!(
                    "{} {} session(s) · {} open",
                    style::ok("review-session.list"),
                    list.total,
                    list.open
                );
                for session in &list.sessions {
                    println!(
                        "  {} {} {} · {}",
                        session.id, session.status, session.reviewer_id, session.scope
                    );
                }
            }
        }
        ReviewSessionAction::Show {
            frontier,
            session_id,
            json,
        } => {
            let session = review_session::load(&frontier, &session_id)
                .unwrap_or_else(|e| fail_return(&format!("review-session show failed: {e}")));
            print_review_session(&session, json);
        }
    }
}

fn cmd_source_inbox(action: SourceInboxAction) {
    match action {
        SourceInboxAction::Add {
            frontier,
            source_id,
            title,
            locator,
            source_type,
            state,
            risk_class,
            content_hash,
            notes,
            json,
        } => {
            let state = parse_source_inbox_state(&state);
            let record = source_inbox::add_record(
                &frontier,
                source_inbox::SourceInboxAddOptions {
                    source_id,
                    title,
                    locator,
                    source_type,
                    state,
                    risk_class,
                    content_hash,
                    notes,
                    metadata: BTreeMap::new(),
                },
            )
            .unwrap_or_else(|e| fail_return(&format!("source inbox add failed: {e}")));
            print_source_inbox_record(&record, json);
        }
        SourceInboxAction::List {
            frontier,
            state,
            json,
        } => {
            let mut list = source_inbox::list_records(&frontier)
                .unwrap_or_else(|e| fail_return(&format!("source inbox list failed: {e}")));
            if let Some(filter) = state {
                match filter.as_str() {
                    "task-linked" | "linked-to-task" => {
                        list.records
                            .retain(|record| record.linked_task_id.is_some());
                    }
                    "stale" => {
                        list.records.retain(|record| {
                            chrono::DateTime::parse_from_rfc3339(&record.updated_at)
                                .ok()
                                .map(|updated| {
                                    chrono::Utc::now()
                                        .signed_duration_since(updated.with_timezone(&chrono::Utc))
                                        .num_days()
                                        > 30
                                })
                                .unwrap_or(false)
                        });
                    }
                    "rejected" => {
                        list.records.clear();
                    }
                    other => {
                        let state = parse_source_inbox_state(other);
                        list.records.retain(|record| record.state == state);
                    }
                }
                list.total = list.records.len();
            }
            if json {
                print_json(&list);
            } else if list.records.is_empty() && list.rejected_imports.is_empty() {
                println!(
                    "{} no local source inbox records",
                    style::warn("source-inbox.list")
                );
            } else {
                println!(
                    "{} {} source record(s) · {}",
                    style::ok("source-inbox.list"),
                    list.records.len(),
                    list.frontier_id
                );
                for record in &list.records {
                    let task = record.linked_task_id.as_deref().unwrap_or("no-task");
                    println!(
                        "  {} {} {} · {} · {}",
                        record.id, record.state, record.risk_class, task, record.title
                    );
                }
                if !list.rejected_imports.is_empty() {
                    println!("  rejected import row(s): {}", list.rejected_imports.len());
                    for row in list.rejected_imports.iter().take(8) {
                        println!("    row {} · {}", row.row_number, row.reason);
                    }
                }
            }
        }
        SourceInboxAction::Verify {
            frontier,
            record_id,
            reviewer,
            reason,
            json,
        } => {
            let record = source_inbox::verify_record(&frontier, &record_id, reviewer, reason)
                .unwrap_or_else(|e| fail_return(&format!("source inbox verify failed: {e}")));
            print_source_inbox_record(&record, json);
        }
        SourceInboxAction::CreateTask {
            frontier,
            record_id,
            objective,
            status,
            json,
        } => {
            let status = parse_task_status(&status);
            let result =
                source_inbox::create_task_from_record(&frontier, &record_id, objective, status)
                    .unwrap_or_else(|e| {
                        fail_return(&format!("source inbox create-task failed: {e}"))
                    });
            if json {
                print_json(&result);
            } else {
                println!(
                    "{} {} -> {}",
                    style::ok("source-inbox.create-task"),
                    result.record.id,
                    result.task.id
                );
                println!(
                    "  policy: {} · {} reviewer(s)",
                    result.review_requirement.review_class,
                    result.review_requirement.required_reviewer_count
                );
            }
        }
        SourceInboxAction::Resolve {
            frontier,
            doi,
            pmid,
            pmcid,
            nct,
            url,
            local_path,
            fetch_metadata,
            json,
        } => {
            let result = source_resolver::resolve_into_inbox(
                &frontier,
                source_resolver::SourceResolveRequest {
                    doi,
                    pmid,
                    pmcid,
                    nct,
                    url,
                    local_path,
                    fetch_metadata,
                },
            )
            .unwrap_or_else(|e| fail_return(&format!("source inbox resolve failed: {e}")));
            if json {
                print_json(&result);
            } else {
                println!(
                    "{} {} -> {}",
                    style::ok("source-inbox.resolve"),
                    result.normalized_locator,
                    result.record.id
                );
                println!("  status: {}", result.resolution_status);
                for caveat in &result.caveats {
                    println!("  caveat: {caveat}");
                }
            }
        }
        SourceInboxAction::Import {
            frontier,
            from,
            format,
            json,
        } => {
            let report = source_resolver::import_into_inbox(&frontier, &from, format.as_deref())
                .unwrap_or_else(|e| fail_return(&format!("source inbox import failed: {e}")));
            if json {
                print_json(&report);
            } else {
                println!(
                    "{} created={} existing={} invalid={} needs_review={}",
                    style::ok("source-inbox.import"),
                    report.created,
                    report.existing,
                    report.invalid,
                    report.needs_review
                );
                if let Some(path) = &report.rejected_path {
                    println!("  rejected rows: {path}");
                }
            }
        }
    }
}

fn cmd_adoption(action: AdoptionAction) {
    match action {
        AdoptionAction::Transcript {
            frontier,
            out,
            json,
        } => {
            let transcript = if let Some(out) = out.as_ref() {
                adoption_transcript::write_markdown(&frontier, out)
            } else {
                adoption_transcript::build(&frontier)
            }
            .unwrap_or_else(|e| fail_return(&format!("adoption transcript failed: {e}")));
            if json {
                print_json(&transcript);
            } else {
                print!("{}", transcript.markdown);
            }
        }
        AdoptionAction::Log {
            frontier,
            step,
            category,
            kind,
            note,
            json,
        } => {
            let record = adoption_log::log_with_category(
                &frontier,
                &step,
                category.as_deref(),
                &kind,
                &note,
            )
            .unwrap_or_else(|e| fail_return(&format!("adoption log failed: {e}")));
            if json {
                print_json(&record);
            } else {
                println!(
                    "{} {} · {} · {}",
                    style::ok("adoption.log"),
                    record.id,
                    record.step,
                    record.kind
                );
            }
        }
        AdoptionAction::LogClassify {
            frontier,
            record_id,
            category,
            json,
        } => {
            let record = adoption_log::classify(&frontier, &record_id, &category)
                .unwrap_or_else(|e| fail_return(&format!("adoption log-classify failed: {e}")));
            print_adoption_friction_record(&record, json);
        }
        AdoptionAction::LogLinkTask {
            frontier,
            record_id,
            task_id,
            json,
        } => {
            let record = adoption_log::link_task(&frontier, &record_id, &task_id)
                .unwrap_or_else(|e| fail_return(&format!("adoption log-link-task failed: {e}")));
            print_adoption_friction_record(&record, json);
        }
        AdoptionAction::LogFollowUpTask {
            frontier,
            record_id,
            objective,
            status,
            json,
        } => {
            let status = parse_task_status(&status);
            let result =
                adoption_log::create_follow_up_task(&frontier, &record_id, objective, status)
                    .unwrap_or_else(|e| {
                        fail_return(&format!("adoption log-follow-up-task failed: {e}"))
                    });
            if json {
                print_json(&result);
            } else {
                println!(
                    "{} {} -> {}",
                    style::ok("adoption.log-follow-up-task"),
                    result.record.id,
                    result.task.id
                );
            }
        }
        AdoptionAction::LogClose {
            frontier,
            record_id,
            reason,
            json,
        } => {
            let record = adoption_log::close(&frontier, &record_id, &reason)
                .unwrap_or_else(|e| fail_return(&format!("adoption log-close failed: {e}")));
            print_adoption_friction_record(&record, json);
        }
        AdoptionAction::LogList { frontier, json } => {
            let list = adoption_log::list(&frontier)
                .unwrap_or_else(|e| fail_return(&format!("adoption log-list failed: {e}")));
            if json {
                print_json(&list);
            } else if list.records.is_empty() {
                println!(
                    "{} no local adoption friction records",
                    style::warn("adoption.log-list")
                );
            } else {
                println!(
                    "{} {} record(s)",
                    style::ok("adoption.log-list"),
                    list.records.len()
                );
                for record in &list.records {
                    println!(
                        "  {} {} {} · {}",
                        record.id, record.step, record.kind, record.note
                    );
                }
            }
        }
    }
}

fn print_adoption_friction_record(record: &adoption_log::AdoptionFrictionRecord, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(record).expect("serialize adoption friction record")
        );
    } else {
        println!(
            "{} {} · {} · {} · {}",
            style::ok("adoption.friction"),
            record.id,
            record.status,
            record.category,
            record.kind
        );
    }
}

fn cmd_share(action: ShareAction) {
    match action {
        ShareAction::Build {
            frontier,
            out,
            include_friction_log,
            json,
        } => {
            let report = share_package::build_with_options(
                &frontier,
                &out,
                share_package::ShareBuildOptions {
                    include_friction_log,
                },
            )
            .unwrap_or_else(|e| fail_return(&format!("share build failed: {e}")));
            if json {
                print_json(&report);
            } else {
                println!(
                    "{} {} · {} file(s)",
                    style::ok("share.build"),
                    report.out,
                    report.files
                );
                println!("  manifest: {}", report.manifest_path);
                println!("  verify: vela share inspect {} --json", report.out);
            }
        }
        ShareAction::Inspect { package, json } => {
            let report = share_package::inspect(&package)
                .unwrap_or_else(|e| fail_return(&format!("share inspect failed: {e}")));
            if json {
                print_json(&report);
            } else if report.ok {
                println!(
                    "{} {} · {} file(s)",
                    style::ok("share.inspect"),
                    report.path,
                    report.files
                );
            } else {
                println!("{}", style::warn("share.inspect failed"));
                for mismatch in &report.mismatches {
                    println!("  {mismatch}");
                }
                if !report.proof_packet_present {
                    println!("  proof packet missing");
                }
            }
            if !report.ok {
                std::process::exit(1);
            }
        }
        ShareAction::Render { package, out, json } => {
            let report = static_share::render(&package, &out)
                .unwrap_or_else(|e| fail_return(&format!("share render failed: {e}")));
            if json {
                print_json(&report);
            } else {
                println!(
                    "{} {} · {} file(s)",
                    style::ok("share.render"),
                    report.out,
                    report.files_written
                );
                println!("  open: {}/index.html", report.out);
            }
        }
    }
}

fn cmd_controller(action: ControllerAction) {
    match action {
        ControllerAction::Run {
            frontier,
            kind,
            dry_run,
            json,
        } => {
            let kind = parse_controller_kind(&kind);
            let report = frontier_task::run(&frontier, kind, dry_run)
                .unwrap_or_else(|e| fail_return(&format!("controller run failed: {e}")));
            if json {
                print_json(&report);
            } else {
                let mode = if report.dry_run { "dry-run" } else { "write" };
                println!(
                    "{} {} · {} · {} proposal(s)",
                    style::ok("controller.run"),
                    report.kind,
                    mode,
                    report.proposals.len()
                );
                if report.proposals.is_empty() {
                    println!("  tasks: no local task needed");
                } else {
                    for proposal in &report.proposals {
                        println!(
                            "  {} {} {} · {}",
                            proposal.action,
                            proposal.task_id,
                            proposal.risk_class,
                            proposal.objective
                        );
                    }
                }
                println!(
                    "  task summary: {} -> {} active",
                    report.task_summary_before.active, report.task_summary_after.active
                );
            }
        }
    }
}

fn cmd_incident(action: IncidentAction) {
    match action {
        IncidentAction::Open {
            frontier,
            kind,
            severity,
            title,
            reason,
            reviewer,
            source_id,
            finding_id,
            json,
        } => {
            let incident_type = parse_incident_type(&kind);
            let result = frontier_incident::open_incident(
                &frontier,
                frontier_incident::FrontierIncidentOpenOptions {
                    incident_type,
                    severity,
                    title,
                    reason,
                    opened_by: reviewer,
                    source_id,
                    finding_id,
                    metadata: BTreeMap::new(),
                },
            )
            .unwrap_or_else(|e| fail_return(&format!("incident open failed: {e}")));
            if json {
                print_json(&result);
            } else {
                println!(
                    "{} {} · {} · {} task(s)",
                    style::ok("incident.open"),
                    result.incident.id,
                    result.incident.incident_type,
                    result.tasks.len()
                );
                println!(
                    "  affected: {} finding(s), {} evidence atom(s), {} source(s)",
                    result.impact.affected_findings.len(),
                    result.impact.affected_evidence_atoms.len(),
                    result.impact.affected_sources.len()
                );
                for task in &result.tasks {
                    println!("  task: {} · {}", task.id, task.objective);
                }
            }
        }
        IncidentAction::List {
            frontier,
            status,
            json,
        } => {
            let mut list = frontier_incident::list_incidents(&frontier)
                .unwrap_or_else(|e| fail_return(&format!("incident list failed: {e}")));
            if let Some(status) = status {
                let status = parse_incident_status(&status);
                list.incidents.retain(|incident| incident.status == status);
                list.total = list.incidents.len();
            }
            if json {
                print_json(&list);
            } else if list.incidents.is_empty() {
                println!(
                    "{} no local frontier incidents",
                    style::warn("incident.list")
                );
            } else {
                println!(
                    "{} {} incident(s) · {}",
                    style::ok("incident.list"),
                    list.incidents.len(),
                    list.frontier_id
                );
                for incident in &list.incidents {
                    println!(
                        "  {} {} {} · {}",
                        incident.id, incident.status, incident.incident_type, incident.title
                    );
                }
            }
        }
        IncidentAction::Close {
            frontier,
            incident_id,
            reviewer,
            reason,
            json,
        } => {
            let incident =
                frontier_incident::close_incident(&frontier, &incident_id, reviewer, reason)
                    .unwrap_or_else(|e| fail_return(&format!("incident close failed: {e}")));
            print_incident(&incident, json);
        }
        IncidentAction::Impact {
            frontier,
            source_id,
            json,
        } => {
            let report = frontier_incident::retraction_impact(&frontier, &source_id)
                .unwrap_or_else(|e| fail_return(&format!("incident impact failed: {e}")));
            if json {
                print_json(&report);
            } else {
                println!(
                    "{} {} · {} finding(s)",
                    style::ok("incident.impact"),
                    report.source_id,
                    report.affected_findings.len()
                );
                println!(
                    "  evidence atoms: {} · sources: {}",
                    report.affected_evidence_atoms.len(),
                    report.affected_sources.len()
                );
                for finding_id in &report.affected_findings {
                    println!("  finding: {finding_id}");
                }
            }
        }
    }
}

fn parse_task_status(status: &str) -> frontier_task::FrontierTaskStatus {
    status
        .parse()
        .unwrap_or_else(|e| fail_return(&format!("invalid task status: {e}")))
}

fn parse_incident_type(kind: &str) -> frontier_incident::FrontierIncidentType {
    kind.parse()
        .unwrap_or_else(|e| fail_return(&format!("invalid incident type: {e}")))
}

fn parse_incident_status(status: &str) -> frontier_incident::FrontierIncidentStatus {
    status
        .parse()
        .unwrap_or_else(|e| fail_return(&format!("invalid incident status: {e}")))
}

fn parse_controller_kind(kind: &str) -> frontier_task::FrontierControllerKind {
    kind.parse()
        .unwrap_or_else(|e| fail_return(&format!("invalid controller kind: {e}")))
}

fn parse_source_inbox_state(status: &str) -> source_inbox::SourceInboxState {
    status
        .parse()
        .unwrap_or_else(|e| fail_return(&format!("invalid source inbox state: {e}")))
}

fn print_source_inbox_record(record: &source_inbox::SourceInboxRecord, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(record).expect("serialize source inbox record")
        );
    } else {
        println!(
            "{} {} {} · {}",
            style::ok("source-inbox"),
            record.id,
            record.state,
            record.title
        );
        println!("  locator: {}", record.locator);
        println!("  type:    {}", record.source_type);
        println!("  risk:    {}", record.risk_class);
        if let Some(task_id) = &record.linked_task_id {
            println!("  task:    {task_id}");
        }
    }
}

fn print_review_session(session: &review_session::ReviewSession, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(session).expect("serialize review session")
        );
    } else {
        println!(
            "{} {} {} · {}",
            style::ok("review-session"),
            session.id,
            session.status,
            session.scope
        );
        println!("  reviewer: {}", session.reviewer_id);
        println!("  objects:  {}", session.objects_reviewed.len());
        println!("  notes:    {}", session.notes.len());
        if let Some(ended_at) = &session.ended_at {
            println!("  ended:    {ended_at}");
        }
        if let Some(decision) = session.decisions.last() {
            println!("  decision: {} · {}", decision.decision, decision.reason);
        }
    }
}

fn print_incident(incident: &frontier_incident::FrontierIncident, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(incident).expect("serialize incident")
        );
    } else {
        println!(
            "{} {} {} · {}",
            style::ok("incident"),
            incident.id,
            incident.status,
            incident.title
        );
        println!("  type:     {}", incident.incident_type);
        println!("  severity: {}", incident.severity);
        println!(
            "  affected: {} finding(s)",
            incident.affected_findings.len()
        );
    }
}

fn print_task_workspace_status(status: &task_workspace::TaskWorkspaceStatus, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(status).expect("serialize task workspace status")
        );
    } else {
        let state = if status.exists { "ready" } else { "missing" };
        println!(
            "{} {} {}",
            style::ok("task.workspace"),
            status.task_id,
            state
        );
        println!("  frontier:  {}", status.frontier_id);
        println!("  path:      {}", status.workspace_path);
        println!("  dirs:      {}", status.directories.len());
        println!("  files:     {}", status.files.len());
        println!("  sources:   {}", status.source_artifacts.len());
        if let Some(hash) = &status.frontier_snapshot_sha256 {
            println!("  snapshot:  {hash}");
        }
    }
}

fn print_task(task: &frontier_task::FrontierTask, json: bool) {
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

/// v0.199: handle `vela tool` — register / show / verify a Tool
/// Descriptor (`vtd_*`).
fn cmd_tool(action: ToolCliAction) {
    use vela_protocol::tool_descriptor::{CallingConvention, DescriptorDraft, ToolDescriptor};

    match action {
        ToolCliAction::Register {
            tool_name,
            tool_version,
            provider,
            calling_convention,
            input_schema,
            output_schema,
            evidence_url,
            cited_in_findings,
            out,
            json,
        } => {
            let conv = match calling_convention.as_str() {
                "http_json" => CallingConvention::HttpJson,
                "python_callable" => CallingConvention::PythonCallable,
                "cli_subprocess" => CallingConvention::CliSubprocess,
                "mcp_server" => CallingConvention::McpServer,
                other => fail_return(&format!(
                    "calling_convention must be one of http_json | python_callable | cli_subprocess | mcp_server; got `{other}`"
                )),
            };
            let input_bytes = std::fs::read_to_string(&input_schema)
                .unwrap_or_else(|e| fail_return(&format!("read {}: {e}", input_schema.display())));
            let input_json: serde_json::Value = serde_json::from_str(&input_bytes)
                .unwrap_or_else(|e| fail_return(&format!("parse input_schema: {e}")));
            let output_bytes = std::fs::read_to_string(&output_schema)
                .unwrap_or_else(|e| fail_return(&format!("read {}: {e}", output_schema.display())));
            let output_json: serde_json::Value = serde_json::from_str(&output_bytes)
                .unwrap_or_else(|e| fail_return(&format!("parse output_schema: {e}")));
            let draft = DescriptorDraft {
                tool_name,
                tool_version,
                provider,
                calling_convention: conv,
                input_schema: input_json,
                output_schema: output_json,
                evidence_url,
                cited_in_findings,
            };
            let descriptor = ToolDescriptor::build(draft).unwrap_or_else(|e| fail_return(&e));
            let body = serde_json::to_string_pretty(&descriptor).expect("serialize descriptor");
            if let Some(parent) = out.parent() {
                std::fs::create_dir_all(parent)
                    .unwrap_or_else(|e| fail_return(&format!("create {}: {e}", parent.display())));
            }
            std::fs::write(&out, format!("{body}\n"))
                .unwrap_or_else(|e| fail_return(&format!("write {}: {e}", out.display())));
            if json {
                let payload = json!({
                    "ok": true,
                    "command": "tool.register",
                    "descriptor_id": descriptor.descriptor_id,
                    "tool_name": descriptor.tool_name,
                    "tool_version": descriptor.tool_version,
                    "provider": descriptor.provider,
                    "out": out.display().to_string(),
                });
                print_json(&payload);
            } else {
                println!(
                    "{} {} {}@{} ({}) -> {}",
                    style::ok("tool.register"),
                    descriptor.descriptor_id,
                    descriptor.tool_name,
                    descriptor.tool_version,
                    descriptor.provider,
                    out.display()
                );
            }
        }
        ToolCliAction::Show { descriptor, json } => {
            let body = std::fs::read_to_string(&descriptor)
                .unwrap_or_else(|e| fail_return(&format!("read {}: {e}", descriptor.display())));
            let d: ToolDescriptor = serde_json::from_str(&body)
                .unwrap_or_else(|e| fail_return(&format!("parse descriptor: {e}")));
            if json {
                println!("{body}");
            } else {
                println!(
                    "{} {}\n  tool:     {}@{}\n  provider: {}\n  conv:     {}",
                    style::ok("tool.show"),
                    d.descriptor_id,
                    d.tool_name,
                    d.tool_version,
                    d.provider,
                    d.calling_convention.canonical()
                );
                if let Some(url) = &d.evidence_url {
                    println!("  evidence: {url}");
                }
                if !d.cited_in_findings.is_empty() {
                    println!("  cited in:");
                    for vf in &d.cited_in_findings {
                        println!("    - {vf}");
                    }
                }
            }
        }
        ToolCliAction::Verify { descriptor, json } => {
            let body = std::fs::read_to_string(&descriptor)
                .unwrap_or_else(|e| fail_return(&format!("read {}: {e}", descriptor.display())));
            let d: ToolDescriptor = serde_json::from_str(&body)
                .unwrap_or_else(|e| fail_return(&format!("parse descriptor: {e}")));
            d.verify()
                .unwrap_or_else(|e| fail_return(&format!("verify failed: {e}")));
            if json {
                let payload = json!({
                    "ok": true,
                    "command": "tool.verify",
                    "descriptor_id": d.descriptor_id,
                });
                print_json(&payload);
            } else {
                println!(
                    "{} {} verifies ({}@{})",
                    style::ok("tool.verify"),
                    d.descriptor_id,
                    d.tool_name,
                    d.tool_version
                );
            }
        }
    }
}

/// v0.200: handle `vela eval` — record / show / verify an
/// Evaluation Record (`ver_*`).
fn cmd_eval(action: EvalCliAction) {
    use vela_protocol::evaluation_record::{
        EvaluationKind, EvaluationRecord, Outcome, RecordDraft, TargetKind,
    };

    fn parse_target_kind(s: &str) -> TargetKind {
        match s {
            "vsd" => TargetKind::Vsd,
            "vtr" => TargetKind::Vtr,
            "vf" => TargetKind::Vf,
            "vpf" => TargetKind::Vpf,
            "vtd" => TargetKind::Vtd,
            "vaa" => TargetKind::Vaa,
            other => fail_return(&format!(
                "target_kind must be one of vsd | vtr | vf | vpf | vtd | vaa; got `{other}`"
            )),
        }
    }
    fn parse_eval_kind(s: &str) -> EvaluationKind {
        match s {
            "replication" => EvaluationKind::Replication,
            "benchmark" => EvaluationKind::Benchmark,
            "validation" => EvaluationKind::Validation,
            "peer_review" => EvaluationKind::PeerReview,
            other => fail_return(&format!(
                "evaluation_kind must be one of replication | benchmark | validation | peer_review; got `{other}`"
            )),
        }
    }
    fn parse_outcome(s: &str) -> Outcome {
        match s {
            "succeeded" => Outcome::Succeeded,
            "failed" => Outcome::Failed,
            "partial" => Outcome::Partial,
            "inconclusive" => Outcome::Inconclusive,
            other => fail_return(&format!(
                "outcome must be one of succeeded | failed | partial | inconclusive; got `{other}`"
            )),
        }
    }

    match action {
        EvalCliAction::Record {
            target_kind,
            target_id,
            evaluation_kind,
            outcome,
            evaluator,
            evidence_refs,
            benchmark_id,
            score,
            notes,
            key,
            out,
            json,
        } => {
            let draft = RecordDraft {
                target_kind: parse_target_kind(&target_kind),
                target_id,
                evaluation_kind: parse_eval_kind(&evaluation_kind),
                outcome: parse_outcome(&outcome),
                evaluator_actor: evaluator,
                evaluated_at: chrono::Utc::now().to_rfc3339(),
                evidence_refs,
                benchmark_id,
                score,
                notes,
            };
            let mut record = EvaluationRecord::build(draft).unwrap_or_else(|e| fail_return(&e));
            if let Some(key_path) = key {
                let key_hex = std::fs::read_to_string(&key_path).unwrap_or_else(|e| {
                    fail_return(&format!("read key {}: {e}", key_path.display()))
                });
                let key_bytes = hex::decode(key_hex.trim())
                    .unwrap_or_else(|e| fail_return(&format!("decode key hex: {e}")));
                let key_arr: [u8; 32] = key_bytes
                    .try_into()
                    .unwrap_or_else(|_| fail_return("signing key must be 32 bytes"));
                let signing = ed25519_dalek::SigningKey::from_bytes(&key_arr);
                record.sign(&signing);
            }
            let body = serde_json::to_string_pretty(&record).expect("serialize record");
            if let Some(parent) = out.parent() {
                std::fs::create_dir_all(parent)
                    .unwrap_or_else(|e| fail_return(&format!("create {}: {e}", parent.display())));
            }
            std::fs::write(&out, format!("{body}\n"))
                .unwrap_or_else(|e| fail_return(&format!("write {}: {e}", out.display())));
            if json {
                let payload = json!({
                    "ok": true,
                    "command": "eval.record",
                    "record_id": record.record_id,
                    "target_id": record.target_id,
                    "outcome": record.outcome.canonical(),
                    "signed": record.signature.is_some(),
                    "out": out.display().to_string(),
                });
                print_json(&payload);
            } else {
                println!(
                    "{} {} {} {} -> {}",
                    style::ok("eval.record"),
                    record.record_id,
                    record.target_id,
                    record.outcome.canonical(),
                    out.display()
                );
            }
        }
        EvalCliAction::Show { record, json } => {
            let body = std::fs::read_to_string(&record)
                .unwrap_or_else(|e| fail_return(&format!("read {}: {e}", record.display())));
            let r: EvaluationRecord = serde_json::from_str(&body)
                .unwrap_or_else(|e| fail_return(&format!("parse record: {e}")));
            if json {
                println!("{body}");
            } else {
                println!(
                    "{} {}\n  target:    {} {}\n  kind:      {}\n  outcome:   {}\n  evaluator: {}\n  at:        {}",
                    style::ok("eval.show"),
                    r.record_id,
                    r.target_kind.canonical(),
                    r.target_id,
                    r.evaluation_kind.canonical(),
                    r.outcome.canonical(),
                    r.evaluator_actor,
                    r.evaluated_at
                );
                if let Some(b) = &r.benchmark_id {
                    println!("  benchmark: {b}");
                }
                if let Some(s) = r.score {
                    println!("  score:     {s}");
                }
                if r.signature.is_some() {
                    println!(
                        "  signed by: {}",
                        r.signer_pubkey_hex.as_deref().unwrap_or("?")
                    );
                }
            }
        }
        EvalCliAction::Verify { record, json } => {
            let body = std::fs::read_to_string(&record)
                .unwrap_or_else(|e| fail_return(&format!("read {}: {e}", record.display())));
            let r: EvaluationRecord = serde_json::from_str(&body)
                .unwrap_or_else(|e| fail_return(&format!("parse record: {e}")));
            r.verify()
                .unwrap_or_else(|e| fail_return(&format!("verify failed: {e}")));
            if json {
                let payload = json!({
                    "ok": true,
                    "command": "eval.verify",
                    "record_id": r.record_id,
                    "signed": r.signature.is_some(),
                });
                print_json(&payload);
            } else {
                println!(
                    "{} {} verifies ({}, {})",
                    style::ok("eval.verify"),
                    r.record_id,
                    r.outcome.canonical(),
                    if r.signature.is_some() {
                        "signed"
                    } else {
                        "unsigned"
                    }
                );
            }
        }
    }
}

/// v0.218: handle `vela conflict` — detect / resolve / list
/// Verdict Conflicts on a frontier.
fn cmd_conflict(action: ConflictCliAction) {
    use vela_protocol::diff_pack_review;
    use vela_protocol::verdict_conflict::{ConflictDraft, ResolutionMode, VerdictConflict};

    match action {
        ConflictCliAction::Detect { frontier, json } => {
            // Scan .vela/pending_verdicts/<vpv>.json for contradictions.
            // Two verdicts contradict when:
            //   * they target distinct packs (different pack_id),
            //   * the packs share at least one member vpr_*,
            //   * the verdict outcomes are different (accept vs reject,
            //     or accept vs revise, or reject vs revise).
            let pending = diff_pack_review::list_at_path(&frontier);
            // Load every pack referenced so we know its members.
            let mut pack_members: std::collections::HashMap<String, Vec<String>> =
                std::collections::HashMap::new();
            for pv in &pending {
                if pack_members.contains_key(&pv.pack_id) {
                    continue;
                }
                let path = frontier
                    .join(".vela")
                    .join("diff_packs")
                    .join(format!("{}.json", pv.pack_id));
                if let Ok(body) = std::fs::read_to_string(&path)
                    && let Ok(v) = serde_json::from_str::<Value>(&body)
                    && let Some(arr) = v.get("proposals").and_then(Value::as_array)
                {
                    let members: Vec<String> = arr
                        .iter()
                        .filter_map(|m| m.as_str().map(String::from))
                        .collect();
                    pack_members.insert(pv.pack_id.clone(), members);
                }
            }
            // Compare every pair of pending verdicts.
            let mut candidates: Vec<Value> = Vec::new();
            for i in 0..pending.len() {
                for j in (i + 1)..pending.len() {
                    let a = &pending[i];
                    let b = &pending[j];
                    if a.pack_id == b.pack_id {
                        continue;
                    }
                    if a.verdict.canonical() == b.verdict.canonical() {
                        continue;
                    }
                    let members_a = pack_members.get(&a.pack_id);
                    let members_b = pack_members.get(&b.pack_id);
                    if let (Some(ma), Some(mb)) = (members_a, members_b) {
                        let shared: Vec<&String> = ma.iter().filter(|m| mb.contains(m)).collect();
                        if shared.is_empty() {
                            continue;
                        }
                        candidates.push(json!({
                            "verdicts": [a.verdict_id, b.verdict_id],
                            "packs": [a.pack_id, b.pack_id],
                            "outcomes": [a.verdict.canonical(), b.verdict.canonical()],
                            "reviewers": [a.reviewer_actor, b.reviewer_actor],
                            "shared_member_ids": shared
                                .iter()
                                .map(|s| s.as_str())
                                .collect::<Vec<_>>(),
                        }));
                    }
                }
            }
            if json {
                let payload = json!({
                    "ok": true,
                    "command": "conflict.detect",
                    "frontier": frontier.display().to_string(),
                    "candidate_count": candidates.len(),
                    "candidates": candidates,
                });
                print_json(&payload);
            } else if candidates.is_empty() {
                println!(
                    "{} {} no contradicting verdicts detected",
                    style::ok("conflict.detect"),
                    frontier.display()
                );
            } else {
                println!(
                    "{} {} {} candidate conflict(s):",
                    style::warn("conflict.detect"),
                    frontier.display(),
                    candidates.len()
                );
                for c in &candidates {
                    let verdicts = c
                        .get("verdicts")
                        .and_then(Value::as_array)
                        .map(|a| {
                            a.iter()
                                .filter_map(|v| v.as_str())
                                .collect::<Vec<_>>()
                                .join(" vs ")
                        })
                        .unwrap_or_default();
                    let shared_count = c
                        .get("shared_member_ids")
                        .and_then(Value::as_array)
                        .map_or(0, Vec::len);
                    println!("  {verdicts} (shared members: {shared_count})");
                }
            }
        }
        ConflictCliAction::Resolve {
            frontier,
            verdicts,
            shared_members,
            mode,
            resolver,
            winning,
            rationale,
            key,
            json,
        } => {
            let resolution_mode = match mode.as_str() {
                "majority" => ResolutionMode::Majority,
                "owner_override" => ResolutionMode::OwnerOverride,
                "escalation" => ResolutionMode::Escalation,
                other => fail_return(&format!(
                    "mode must be one of majority|owner_override|escalation; got `{other}`"
                )),
            };
            let project = repo::load_from_path(&frontier).unwrap_or_else(|e| fail_return(&e));
            let frontier_id = project.frontier_id().to_string();
            let draft = ConflictDraft {
                frontier_id: frontier_id.clone(),
                verdicts: verdicts.clone(),
                shared_member_ids: shared_members,
                resolution_mode,
                resolution_actor: resolver,
                resolved_at: chrono::Utc::now().to_rfc3339(),
                winning_verdict_id: winning,
                rationale,
            };
            let mut conflict = VerdictConflict::build(draft).unwrap_or_else(|e| fail_return(&e));
            if let Some(key_path) = key {
                let key_hex = std::fs::read_to_string(&key_path).unwrap_or_else(|e| {
                    fail_return(&format!("read key {}: {e}", key_path.display()))
                });
                let key_bytes = hex::decode(key_hex.trim())
                    .unwrap_or_else(|e| fail_return(&format!("decode key hex: {e}")));
                let key_arr: [u8; 32] = key_bytes
                    .try_into()
                    .unwrap_or_else(|_| fail_return("signing key must be 32 bytes"));
                let signing = ed25519_dalek::SigningKey::from_bytes(&key_arr);
                conflict.sign(&signing);
            }
            // Persist the vdc_* under .vela/verdict_conflicts/.
            let dir = frontier.join(".vela").join("verdict_conflicts");
            std::fs::create_dir_all(&dir)
                .unwrap_or_else(|e| fail_return(&format!("create {}: {e}", dir.display())));
            let out_path = dir.join(format!("{}.json", conflict.conflict_id));
            let body = serde_json::to_string_pretty(&conflict).expect("serialize conflict");
            std::fs::write(&out_path, format!("{body}\n"))
                .unwrap_or_else(|e| fail_return(&format!("write {}: {e}", out_path.display())));
            if json {
                let payload = json!({
                    "ok": true,
                    "command": "conflict.resolve",
                    "conflict_id": conflict.conflict_id,
                    "frontier_id": frontier_id,
                    "verdicts": verdicts,
                    "resolution_mode": conflict.resolution_mode.canonical(),
                    "out": out_path.display().to_string(),
                });
                print_json(&payload);
            } else {
                println!(
                    "{} {} {} -> {}",
                    style::ok("conflict.resolve"),
                    conflict.conflict_id,
                    conflict.resolution_mode.canonical(),
                    out_path.display()
                );
            }
        }
        ConflictCliAction::List { frontier, json } => {
            let dir = frontier.join(".vela").join("verdict_conflicts");
            let mut out: Vec<VerdictConflict> = Vec::new();
            if let Ok(entries) = std::fs::read_dir(&dir) {
                for e in entries.flatten() {
                    let p = e.path();
                    if p.extension().and_then(|s| s.to_str()) != Some("json") {
                        continue;
                    }
                    if let Ok(body) = std::fs::read_to_string(&p)
                        && let Ok(c) = serde_json::from_str::<VerdictConflict>(&body)
                    {
                        out.push(c);
                    }
                }
            }
            out.sort_by(|a, b| b.resolved_at.cmp(&a.resolved_at));
            if json {
                let payload = json!({
                    "ok": true,
                    "command": "conflict.list",
                    "frontier": frontier.display().to_string(),
                    "conflicts": out,
                });
                print_json(&payload);
            } else {
                println!(
                    "{} {} {} resolved conflict(s)",
                    style::ok("conflict.list"),
                    frontier.display(),
                    out.len()
                );
                for c in &out {
                    println!(
                        "  {} {} ({} verdicts, {} shared members)",
                        c.conflict_id,
                        c.resolution_mode.canonical(),
                        c.verdicts.len(),
                        c.shared_member_ids.len()
                    );
                }
            }
        }
    }
}

/// v0.163: handle `vela preprint <frontier>`. Renders a Markdown
/// preprint body for the frontier.
fn cmd_preprint(frontier: PathBuf, released_at: Option<String>, out: Option<PathBuf>, json: bool) {
    use vela_protocol::preprint::render_preprint;

    let project = repo::load_from_path(&frontier).unwrap_or_else(|e| fail_return(&e));
    let stamp = released_at.unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
    let body = render_preprint(&project, &stamp);

    if let Some(out_path) = out {
        std::fs::write(&out_path, &body)
            .unwrap_or_else(|e| fail_return(&format!("write {}: {e}", out_path.display())));
        if json {
            let payload = json!({
                "ok": true,
                "command": "preprint",
                "frontier_id": project.frontier_id(),
                "released_at": stamp,
                "bytes": body.len(),
                "out": out_path.display().to_string(),
            });
            print_json(&payload);
        } else {
            println!(
                "{} preprint for {} -> {} ({} bytes)",
                style::ok("preprint"),
                project.frontier_id(),
                out_path.display(),
                body.len()
            );
        }
    } else {
        println!("{body}");
    }
}

/// v0.163: handle `vela handle <id>`. Classifies a persistent
/// identifier and prints the resolved kind + canonical URL.
fn cmd_handle_resolve(handle: String, site: String, json: bool) {
    use vela_protocol::resolver::resolve;

    let resolved = resolve(&handle, &site);
    if json {
        print_json(&resolved);
        return;
    }
    println!("  handle  {}", resolved.handle);
    println!("  kind    {}", resolved.label);
    match resolved.url {
        Some(u) => println!("  url     {u}"),
        None => println!("  url     (unknown handle shape)"),
    }
}

/// v0.162: handle `vela crossref --frontier <path> ...`. Generates
/// a Crossref deposit manifest for a frontier release. The
/// substrate emits the deposit body; submission to Crossref is the
/// operator's responsibility under their own member account.
#[allow(clippy::too_many_arguments)]
fn cmd_crossref(
    frontier: PathBuf,
    release: Option<String>,
    member: String,
    prefix: String,
    depositor_name: String,
    depositor_email: String,
    resource_url: String,
    title: Option<String>,
    description: Option<String>,
    license: Option<String>,
    xml: bool,
    out: Option<PathBuf>,
    json: bool,
) {
    use vela_protocol::credit::build_ledger;
    use vela_protocol::crossref::{CrossrefDepositManifest, DepositInput, Depositor};
    use vela_protocol::frontier_release::FrontierRelease;

    let project = repo::load_from_path(&frontier).unwrap_or_else(|e| fail_return(&e));
    let releases_dir = releases_dir_for(&frontier);
    let release_id = release.or_else(|| latest_release_id(&releases_dir));
    let release_id = match release_id {
        Some(id) => id,
        None => fail_return(
            "no release found: pass --release <vfrr_*> or cut one first with `vela frontier release --name v1.0`",
        ),
    };
    let release_path = releases_dir.join(format!("{release_id}.json"));
    let release_raw = std::fs::read_to_string(&release_path)
        .unwrap_or_else(|e| fail_return(&format!("read {}: {e}", release_path.display())));
    let release: FrontierRelease = serde_json::from_str(&release_raw)
        .unwrap_or_else(|e| fail_return(&format!("parse release {release_id}: {e}")));

    let now = chrono::Utc::now().to_rfc3339();
    let ledger = build_ledger(&project, &now);
    let resolved_title = title.unwrap_or_else(|| project.project.name.clone());

    let manifest = CrossrefDepositManifest::from_input(DepositInput {
        release: &release,
        title: resolved_title,
        resource_url,
        member_id: member,
        prefix,
        depositor: Depositor {
            name: depositor_name,
            email: depositor_email,
        },
        description,
        license,
        ledger: Some(&ledger),
        deposited_at: now,
    })
    .unwrap_or_else(|e| fail_return(&e));

    let body = if xml {
        manifest.to_crossref_xml()
    } else {
        serde_json::to_string_pretty(&manifest).expect("serialize crossref manifest")
    };

    if let Some(out_path) = out {
        std::fs::write(&out_path, format!("{body}\n"))
            .unwrap_or_else(|e| fail_return(&format!("write {}: {e}", out_path.display())));
        if json {
            let payload = json!({
                "ok": true,
                "command": "crossref",
                "release_id": manifest.release.release_id,
                "frontier_id": manifest.release.frontier_id,
                "suggested_doi": manifest.suggested_doi,
                "contributor_count": manifest.contributors.len(),
                "out": out_path.display().to_string(),
                "format": if xml { "xml" } else { "json" },
            });
            print_json(&payload);
        } else {
            println!(
                "{} crossref deposit for {} ({} contributor(s)) -> {} [{}]",
                style::ok("crossref"),
                manifest.release.release_id,
                manifest.contributors.len(),
                out_path.display(),
                if xml { "xml" } else { "json" }
            );
        }
    } else {
        println!("{body}");
    }
}

/// v0.156: handle `vela citation <target> --format <fmt>`.
fn cmd_citation(
    target: String,
    frontier: Option<PathBuf>,
    format: String,
    locator: Option<String>,
    out: Option<PathBuf>,
    json: bool,
) {
    use vela_protocol::citation::{CitationFormat, render_finding, render_frontier};

    let fmt = CitationFormat::parse(&format).unwrap_or_else(|e| fail_return(&e));

    // Two modes: frontier path | finding id.
    let body = if target.starts_with("vf_") {
        // Finding mode: require --frontier and look up the
        // finding inside that frontier's bundle list.
        let frontier_path = frontier.unwrap_or_else(|| {
            fail_return(
                "rendering a finding citation requires --frontier <path>; \
                 pass the frontier the finding lives in.",
            )
        });
        let project = repo::load_from_path(&frontier_path).unwrap_or_else(|e| fail_return(&e));
        let finding = project
            .findings
            .iter()
            .find(|f| f.id == target)
            .cloned()
            .unwrap_or_else(|| {
                fail_return(&format!(
                    "finding `{target}` not found in frontier `{}`",
                    frontier_path.display()
                ))
            });
        render_finding(&project, &finding, fmt)
    } else {
        // Frontier mode: target IS the frontier path.
        let frontier_path = PathBuf::from(&target);
        let project = repo::load_from_path(&frontier_path).unwrap_or_else(|e| fail_return(&e));
        render_frontier(&project, fmt, locator.as_deref())
    };

    if let Some(out_path) = out {
        std::fs::write(&out_path, &body)
            .unwrap_or_else(|e| fail_return(&format!("write {}: {e}", out_path.display())));
        if json {
            let payload = json!({
                "ok": true,
                "command": "citation",
                "target": target,
                "format": format,
                "out": out_path.display().to_string(),
                "byte_count": body.len(),
            });
            print_json(&payload);
        } else {
            println!(
                "{} citation {} -> {} ({} bytes)",
                style::ok("citation"),
                target,
                out_path.display(),
                body.len()
            );
        }
    } else {
        // Default: print to stdout. --json wraps the body in a
        // JSON envelope; otherwise dumps the raw citation text.
        if json {
            let payload = json!({
                "ok": true,
                "command": "citation",
                "target": target,
                "format": format,
                "body": body,
            });
            print_json(&payload);
        } else {
            print!("{body}");
        }
    }
}

/// v0.149: handle `vela search-index {build|query}` via
/// registered handlers (the substrate-side vela-search crate
/// is wired in from vela-cli's main.rs).
async fn cmd_search_index(action: SearchAction) {
    match action {
        SearchAction::Build {
            frontiers,
            out,
            include_bootstrap,
            include_broken,
            json,
        } => match SEARCH_BUILD_HANDLER.get() {
            Some(handler) => {
                handler(frontiers, out, include_bootstrap, include_broken, json).await;
            }
            None => fail("search build handler not registered"),
        },
        SearchAction::Query {
            query,
            index,
            kind,
            entity,
            status,
            frontier_id,
            source_id,
            chain_status,
            limit,
            json,
        } => match SEARCH_QUERY_HANDLER.get() {
            Some(handler) => {
                handler(
                    query,
                    index,
                    kind,
                    entity,
                    status,
                    frontier_id,
                    source_id,
                    chain_status,
                    limit,
                    json,
                )
                .await;
            }
            None => fail("search query handler not registered"),
        },
    }
}

async fn cmd_index(action: IndexAction) {
    match action {
        IndexAction::Build { frontier, json } => {
            let report = index_db::build(&frontier)
                .await
                .unwrap_or_else(|e| fail_return(&e));
            print_index_payload("index build", &report, json);
        }
        IndexAction::Status { frontier, json } => {
            let report = index_db::status(&frontier)
                .await
                .unwrap_or_else(|e| fail_return(&e));
            print_index_payload("index status", &report, json);
        }
        IndexAction::Query {
            frontier,
            kind,
            q,
            limit,
            json,
        } => {
            let report = index_db::query(&frontier, &kind, &q, limit)
                .await
                .unwrap_or_else(|e| fail_return(&e));
            print_index_payload("index query", &report, json);
        }
    }
}

fn print_index_payload(label: &str, payload: &Value, json_output: bool) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(payload).expect("failed to serialize index payload")
        );
        return;
    }
    println!("vela {label}");
    if let Some(path) = payload.pointer("/database/path").and_then(Value::as_str) {
        println!("  database: {path}");
    }
    if let Some(ok) = payload.pointer("/integrity/ok").and_then(Value::as_bool) {
        println!("  integrity: {}", if ok { "ok" } else { "needs repair" });
    }
    if let Some(counts) = payload.get("counts").and_then(Value::as_object) {
        for key in ["findings", "sources", "evidence_atoms", "links", "events"] {
            if let Some(count) = counts.get(key).and_then(Value::as_i64) {
                println!("  {key}: {count}");
            }
        }
    }
    if let Some(results) = payload.get("results").and_then(Value::as_array) {
        println!("  results: {}", results.len());
        for result in results.iter().take(10) {
            let id = result.get("id").and_then(Value::as_str).unwrap_or("");
            let label = result
                .get("assertion")
                .or_else(|| result.get("title"))
                .and_then(Value::as_str)
                .unwrap_or("");
            println!("  - {id} {label}");
        }
    }
}

/// v0.148: handle `vela registry hub-federation status`.
pub(crate) fn cmd_hub_federation(action: HubFederationAction) {
    use vela_protocol::checkpoint::RegistryCheckpoint;

    match action {
        HubFederationAction::Status { sources, json } => {
            if sources.len() < 2 {
                fail("--source requires at least two id=url pairs (comma-separated or repeated).");
            }

            #[derive(serde::Serialize)]
            struct SourceResponse {
                id: String,
                url: String,
                status: String,
                #[serde(skip_serializing_if = "Option::is_none")]
                checkpoint_id: Option<String>,
                #[serde(skip_serializing_if = "Option::is_none")]
                registry_root: Option<String>,
                #[serde(skip_serializing_if = "Option::is_none")]
                sequence: Option<u64>,
                #[serde(skip_serializing_if = "Option::is_none")]
                hub_id: Option<String>,
                #[serde(skip_serializing_if = "Option::is_none")]
                note: Option<String>,
            }

            let client = reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .build()
                .unwrap_or_else(|e| fail_return(&format!("http client init: {e}")));

            let mut responses: Vec<SourceResponse> = Vec::new();
            let mut root_counts: std::collections::BTreeMap<(String, u64), usize> =
                std::collections::BTreeMap::new();

            for entry in &sources {
                let (id, url) = match entry.split_once('=') {
                    Some(pair) => pair,
                    None => {
                        responses.push(SourceResponse {
                            id: entry.clone(),
                            url: String::new(),
                            status: "malformed".to_string(),
                            checkpoint_id: None,
                            registry_root: None,
                            sequence: None,
                            hub_id: None,
                            note: Some("source must be `id=url`".to_string()),
                        });
                        continue;
                    }
                };

                // Fetch the checkpoint JSON. Two transports: file://
                // for local files, https?:// for hub endpoints.
                let body_result: Result<String, String> =
                    if let Some(path) = url.strip_prefix("file://") {
                        std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))
                    } else if url.starts_with("http://") || url.starts_with("https://") {
                        match client.get(url).send() {
                            Ok(resp) if resp.status().is_success() => {
                                resp.text().map_err(|e| format!("body: {e}"))
                            }
                            Ok(resp) => Err(format!("HTTP {}", resp.status())),
                            Err(e) => Err(format!("{e}")),
                        }
                    } else {
                        Err(format!("unsupported url scheme: {url}"))
                    };

                match body_result {
                    Ok(body) => match serde_json::from_str::<RegistryCheckpoint>(&body) {
                        Ok(cp) => {
                            // Re-derive the id to catch tampered signatures.
                            let derived = cp.derive_id().unwrap_or_else(|_| String::new());
                            if derived != cp.checkpoint_id {
                                responses.push(SourceResponse {
                                    id: id.to_string(),
                                    url: url.to_string(),
                                    status: "id_mismatch".to_string(),
                                    checkpoint_id: Some(cp.checkpoint_id.clone()),
                                    registry_root: None,
                                    sequence: None,
                                    hub_id: Some(cp.hub_id.clone()),
                                    note: Some(format!(
                                        "id mismatch: stored {}, derived {}",
                                        cp.checkpoint_id, derived
                                    )),
                                });
                            } else {
                                *root_counts
                                    .entry((cp.registry_root.clone(), cp.sequence))
                                    .or_insert(0) += 1;
                                responses.push(SourceResponse {
                                    id: id.to_string(),
                                    url: url.to_string(),
                                    status: "ok".to_string(),
                                    checkpoint_id: Some(cp.checkpoint_id),
                                    registry_root: Some(cp.registry_root),
                                    sequence: Some(cp.sequence),
                                    hub_id: Some(cp.hub_id),
                                    note: None,
                                });
                            }
                        }
                        Err(e) => responses.push(SourceResponse {
                            id: id.to_string(),
                            url: url.to_string(),
                            status: "parse_error".to_string(),
                            checkpoint_id: None,
                            registry_root: None,
                            sequence: None,
                            hub_id: None,
                            note: Some(format!("parse: {e}")),
                        }),
                    },
                    Err(e) => responses.push(SourceResponse {
                        id: id.to_string(),
                        url: url.to_string(),
                        status: "unreachable".to_string(),
                        checkpoint_id: None,
                        registry_root: None,
                        sequence: None,
                        hub_id: None,
                        note: Some(e),
                    }),
                }
            }

            // Consensus on (registry_root, sequence).
            let resolved_count = responses.iter().filter(|r| r.status == "ok").count();
            let consensus = if resolved_count < 2 {
                "insufficient"
            } else if root_counts.len() == 1 {
                "unanimous"
            } else {
                let max = root_counts.values().copied().max().unwrap_or(0);
                if max * 2 > resolved_count {
                    "majority"
                } else {
                    "split"
                }
            };

            let payload = json!({
                "ok": consensus == "unanimous" || consensus == "majority",
                "command": "registry.federation.status",
                "sources_queried": sources.len(),
                "sources_resolved": resolved_count,
                "distinct_roots": root_counts.len(),
                "consensus": consensus,
                "responses": responses,
            });

            if json {
                print_json(&payload);
            } else {
                println!(
                    "{} federation status across {} source(s): {}",
                    style::ok("registry"),
                    sources.len(),
                    consensus
                );
                for r in &responses {
                    let summary = match (&r.registry_root, r.sequence) {
                        (Some(root), Some(seq)) => {
                            format!("seq {seq} root {}...", &root[..root.len().min(23)])
                        }
                        _ => r.note.clone().unwrap_or_default(),
                    };
                    println!("  {} {} ({})  {summary}", r.status, r.id, r.url);
                }
            }
            if consensus == "split" {
                std::process::exit(1);
            }
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

/// v0.147: handle `vela registry checkpoint {create|verify}`.
pub(crate) fn cmd_checkpoint(action: CheckpointAction) {
    use vela_protocol::checkpoint::{CheckpointDraft, RegistryCheckpoint};
    use vela_protocol::registry;

    match action {
        CheckpointAction::Create {
            from,
            hub_id,
            sequence,
            previous,
            key,
            out,
            json,
        } => {
            let registry_path = registry::resolve_local(from.to_str().unwrap_or_default())
                .unwrap_or_else(|e| fail_return(&e));
            let registry_data =
                registry::load_local(&registry_path).unwrap_or_else(|e| fail_return(&e));

            let key_hex = std::fs::read_to_string(&key)
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|e| fail_return(&format!("read key: {e}")));
            let sk = parse_signing_key(&key_hex);

            let draft = CheckpointDraft {
                hub_id,
                sequence,
                previous_checkpoint: previous,
                created_at: chrono::Utc::now().to_rfc3339(),
            };
            let checkpoint = RegistryCheckpoint::build(&registry_data, draft, &sk)
                .unwrap_or_else(|e| fail_return(&e));

            let body = serde_json::to_string_pretty(&checkpoint).expect("serialize checkpoint");
            std::fs::write(&out, format!("{body}\n"))
                .unwrap_or_else(|e| fail_return(&format!("write {}: {e}", out.display())));

            if json {
                let payload = json!({
                    "ok": true,
                    "command": "registry.checkpoint.create",
                    "checkpoint_id": checkpoint.checkpoint_id,
                    "hub_id": checkpoint.hub_id,
                    "sequence": checkpoint.sequence,
                    "entry_count": checkpoint.entry_count,
                    "registry_root": checkpoint.registry_root,
                    "previous_checkpoint": checkpoint.previous_checkpoint,
                    "signer_pubkey": checkpoint.signer_pubkey,
                    "out": out.display().to_string(),
                });
                print_json(&payload);
            } else {
                println!(
                    "{} checkpoint {} sequence {} over {} entries",
                    style::ok("registry"),
                    checkpoint.checkpoint_id,
                    checkpoint.sequence,
                    checkpoint.entry_count
                );
                println!("  registry_root: {}", checkpoint.registry_root);
                println!("  signer pubkey: {}...", &checkpoint.signer_pubkey[..16]);
                println!("  out:           {}", out.display());
            }
        }
        CheckpointAction::Verify {
            checkpoint,
            registry,
            json,
        } => {
            let cp_raw = std::fs::read_to_string(&checkpoint).unwrap_or_else(|e| {
                fail_return(&format!("read checkpoint {}: {e}", checkpoint.display()))
            });
            let cp: RegistryCheckpoint = serde_json::from_str(&cp_raw)
                .unwrap_or_else(|e| fail_return(&format!("parse checkpoint: {e}")));
            let registry_path = registry::resolve_local(registry.to_str().unwrap_or_default())
                .unwrap_or_else(|e| fail_return(&e));
            let registry_data =
                registry::load_local(&registry_path).unwrap_or_else(|e| fail_return(&e));

            if let Err(e) = cp.verify(&registry_data) {
                if json {
                    let payload = json!({
                        "ok": false,
                        "command": "registry.checkpoint.verify",
                        "checkpoint_id": cp.checkpoint_id,
                        "error": e,
                    });
                    print_json(&payload);
                } else {
                    eprintln!("err · {e}");
                }
                std::process::exit(1);
            }

            if json {
                let payload = json!({
                    "ok": true,
                    "command": "registry.checkpoint.verify",
                    "checkpoint_id": cp.checkpoint_id,
                    "hub_id": cp.hub_id,
                    "sequence": cp.sequence,
                    "entry_count": cp.entry_count,
                    "registry_root": cp.registry_root,
                    "signer_pubkey": cp.signer_pubkey,
                });
                print_json(&payload);
            } else {
                println!(
                    "{} checkpoint {} verified (sequence {}, {} entries)",
                    style::ok("verify"),
                    cp.checkpoint_id,
                    cp.sequence,
                    cp.entry_count
                );
            }
        }
    }
}

/// v0.146: verify the owner-epoch chain transcript for a frontier.
pub(crate) fn cmd_verify_chain(frontier: PathBuf, artifacts: PathBuf, json: bool) {
    use vela_protocol::governance::{
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

impl vela_protocol::governance::ActorRevocationLookup for FrontierRevocation {
    fn revoked_at(&self, actor_id: &str) -> Option<&str> {
        self.map.get(actor_id).map(String::as_str)
    }
}

/// v0.144: handle `vela registry governance {init|show|validate}`.
pub(crate) fn cmd_governance(action: GovernanceAction) {
    use vela_protocol::governance::{GovernancePolicy, PolicyDraft, Quorum};

    match action {
        GovernanceAction::Init {
            frontier,
            threshold,
            eligible,
            bootstrap,
            owner_epoch,
            current_owner_counts,
            attestation_ttl_hours,
            out,
            json,
        } => {
            let frontier_data = repo::load_from_path(&frontier).unwrap_or_else(|e| fail_return(&e));
            let frontier_id = frontier_data.frontier_id().to_string();

            let resolved_owner_epoch = match (bootstrap, owner_epoch) {
                (true, None) => 0,
                (true, Some(e)) if e != 0 => {
                    fail_return("--bootstrap requires --owner-epoch 0 (or omit --owner-epoch).")
                }
                (true, Some(e)) => e,
                (false, None) => fail_return(
                    "--owner-epoch is required for non-bootstrap policies (or pass --bootstrap).",
                ),
                (false, Some(e)) => e,
            };

            if eligible.is_empty() {
                fail("--eligible must list at least one actor id (comma-separated).");
            }

            let draft = PolicyDraft {
                frontier_id,
                owner_epoch: resolved_owner_epoch,
                bootstrap_epoch: if bootstrap { 0 } else { resolved_owner_epoch },
                rotate_quorum: Quorum {
                    threshold,
                    eligible_actors: eligible,
                    current_owner_counts,
                    role_constraints: None,
                    timelock_hours: None,
                },
                emergency_quorum: None,
                policy_update_quorum: None,
                attestation_ttl_hours,
                created_at: chrono::Utc::now().to_rfc3339(),
            };
            let policy = GovernancePolicy::from_draft(draft).unwrap_or_else(|e| fail_return(&e));

            let body = serde_json::to_string_pretty(&policy).expect("serialize governance policy");

            if let Some(path) = out {
                std::fs::write(&path, format!("{body}\n"))
                    .unwrap_or_else(|e| fail_return(&format!("write {}: {e}", path.display())));
                if json {
                    let payload = json!({
                        "ok": true,
                        "command": "registry.governance.init",
                        "policy_id": policy.policy_id,
                        "frontier_id": policy.frontier_id,
                        "owner_epoch": policy.owner_epoch,
                        "bootstrap_epoch": policy.bootstrap_epoch,
                        "out": path.display().to_string(),
                    });
                    print_json(&payload);
                } else {
                    println!(
                        "{} governance policy {} (epoch {}, bootstrap_epoch {}) -> {}",
                        style::ok("registry"),
                        policy.policy_id,
                        policy.owner_epoch,
                        policy.bootstrap_epoch,
                        path.display()
                    );
                    println!("  threshold:   {}", policy.rotate_quorum.threshold);
                    println!(
                        "  eligible:    {}",
                        policy.rotate_quorum.eligible_actors.join(", ")
                    );
                    println!(
                        "  current_owner_counts: {}",
                        policy.rotate_quorum.current_owner_counts
                    );
                }
            } else {
                // No --out: print policy JSON to stdout (the
                // envelope is JSON whether --json was passed or
                // not; the flag is for the summary, not the body).
                println!("{body}");
            }
        }
        GovernanceAction::Show { policy, json } => {
            let raw = std::fs::read_to_string(&policy)
                .unwrap_or_else(|e| fail_return(&format!("read {}: {e}", policy.display())));
            let parsed: GovernancePolicy = serde_json::from_str(&raw)
                .unwrap_or_else(|e| fail_return(&format!("parse policy: {e}")));
            if json {
                print_json(&parsed);
            } else {
                println!("  vela registry governance policy");
                println!("  policy_id:        {}", parsed.policy_id);
                println!("  frontier_id:      {}", parsed.frontier_id);
                println!("  owner_epoch:      {}", parsed.owner_epoch);
                println!("  bootstrap_epoch:  {}", parsed.bootstrap_epoch);
                println!("  rotate threshold: {}", parsed.rotate_quorum.threshold);
                println!(
                    "  eligible:         {}",
                    parsed.rotate_quorum.eligible_actors.join(", ")
                );
                println!(
                    "  current_owner_counts: {}",
                    parsed.rotate_quorum.current_owner_counts
                );
                if let Some(q) = &parsed.emergency_quorum {
                    println!("  emergency threshold: {}", q.threshold);
                }
                if let Some(q) = &parsed.policy_update_quorum {
                    println!("  policy_update threshold: {}", q.threshold);
                }
                println!("  attestation_ttl_hours: {}", parsed.attestation_ttl_hours);
                println!("  created_at:       {}", parsed.created_at);
            }
        }
        GovernanceAction::Validate { policy, json } => {
            let raw = std::fs::read_to_string(&policy)
                .unwrap_or_else(|e| fail_return(&format!("read {}: {e}", policy.display())));
            let parsed: GovernancePolicy = serde_json::from_str(&raw)
                .unwrap_or_else(|e| fail_return(&format!("parse policy: {e}")));
            if let Err(e) = parsed.validate() {
                if json {
                    let payload = json!({
                        "ok": false,
                        "command": "registry.governance.validate",
                        "policy_id": parsed.policy_id,
                        "error": e,
                    });
                    print_json(&payload);
                } else {
                    eprintln!("err · {e}");
                }
                std::process::exit(1);
            }
            if let Err(e) = parsed.verify_content_address() {
                if json {
                    let payload = json!({
                        "ok": false,
                        "command": "registry.governance.validate",
                        "policy_id": parsed.policy_id,
                        "error": e,
                    });
                    print_json(&payload);
                } else {
                    eprintln!("err · {e}");
                }
                std::process::exit(1);
            }
            if json {
                let payload = json!({
                    "ok": true,
                    "command": "registry.governance.validate",
                    "policy_id": parsed.policy_id,
                    "frontier_id": parsed.frontier_id,
                    "owner_epoch": parsed.owner_epoch,
                    "bootstrap_epoch": parsed.bootstrap_epoch,
                });
                print_json(&payload);
            } else {
                println!(
                    "{} governance policy {} valid (epoch {})",
                    style::ok("validate"),
                    parsed.policy_id,
                    parsed.owner_epoch
                );
            }
        }
    }
}

fn print_stats_json(path: &Path) {
    if let Ok((manifest_path, manifest)) = load_frontier_shards_manifest(path) {
        let max_shard_bytes = json_path_u64(&manifest, &["storage", "max_shard_byte_count"]);
        let compatibility_snapshot = source_frontier_json_summary(&manifest);
        let frontier_bytes = compatibility_snapshot
            .get("current_byte_count")
            .or_else(|| compatibility_snapshot.get("declared_byte_count"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        if manifest.get("schema").and_then(Value::as_str) == Some("vela.frontier_state_shards.v1")
            && max_shard_bytes > 0
            && max_shard_bytes < 50_000_000
            && frontier_bytes < 100_000_000
        {
            let payload = json!({
                "ok": true,
                "command": "stats",
                "schema_version": project::VELA_SCHEMA_VERSION,
                "frontier": {
                    "id": manifest.get("frontier_id").cloned().unwrap_or(Value::Null),
                    "source": path.display().to_string(),
                    "source_mode": "frontier_state_shards",
                    "manifest": manifest_path.display().to_string(),
                    "compatibility_snapshot": compatibility_snapshot,
                },
                "stats": manifest.get("stats").cloned().unwrap_or(Value::Null),
                "storage": {
                    "format": json_path_str(&manifest, &["storage", "format"]).unwrap_or(""),
                    "shard_count": json_path_u64(&manifest, &["storage", "shard_count"]),
                    "records_in_shards": json_path_u64(&manifest, &["storage", "records_in_shards"]),
                    "max_shard_byte_count": max_shard_bytes,
                    "item_counts": manifest
                        .get("storage")
                        .and_then(|v| v.get("item_counts"))
                        .cloned()
                        .unwrap_or(Value::Null),
                },
                "authority": manifest.get("authority").cloned().unwrap_or(Value::Null),
                "claim_boundary": manifest.get("claim_boundary").cloned().unwrap_or(Value::Null),
                "caveats": [
                    "Stats were read from frontier state shards.",
                    "frontier.json remains the compatibility snapshot for proof replay and export.",
                    "Use `vela integrity` when proof freshness matters."
                ],
            });
            print_json(&payload);
            return;
        }
    }

    let frontier = load_frontier_or_fail(path);
    let source_hash = hash_path_or_fail(path);
    let payload = json!({
        "ok": true,
        "command": "stats",
        "schema_version": project::VELA_SCHEMA_VERSION,
        "frontier": {
            "name": &frontier.project.name,
            "description": &frontier.project.description,
            "source": path.display().to_string(),
            "hash": format!("sha256:{source_hash}"),
            "compiled_at": &frontier.project.compiled_at,
            "compiler": &frontier.project.compiler,
            "papers_processed": frontier.project.papers_processed,
            "errors": frontier.project.errors,
        },
        "stats": frontier.stats,
        "proposals": proposals::summary(&frontier),
        "proof_state": frontier.proof_state,
    });
    print_json(&payload);
}

fn cmd_search(
    source: Option<&Path>,
    query: &str,
    entity: Option<&str>,
    assertion_type: Option<&str>,
    all: Option<&Path>,
    limit: usize,
    json_output: bool,
) {
    if let Some(dir) = all {
        search::run_all(dir, query, entity, assertion_type, limit);
        return;
    }
    let Some(src) = source else {
        fail("Provide --source <frontier> or --all <directory>.");
    };
    if json_output {
        let results = search::search(src, query, entity, assertion_type, limit);
        let loaded = load_frontier_or_fail(src);
        let source_hash = hash_path_or_fail(src);
        let payload = json!({
            "ok": true,
            "command": "search",
            "schema_version": project::VELA_SCHEMA_VERSION,
            "query": query,
            "frontier": {
                "name": &loaded.project.name,
                "source": src.display().to_string(),
                "hash": format!("sha256:{source_hash}"),
            },
            "filters": {
                "entity": entity,
                "assertion_type": assertion_type,
                "limit": limit,
            },
            "count": results.len(),
            "results": results.iter().map(|result| json!({
                "id": &result.id,
                "score": result.score,
                "assertion": &result.assertion,
                "assertion_type": &result.assertion_type,
                "confidence": result.confidence,
                "entities": &result.entities,
                "doi": &result.doi,
            })).collect::<Vec<_>>()
        });
        print_json(&payload);
    } else {
        search::run(src, query, entity, assertion_type, limit);
    }
}

fn cmd_tensions(source: &Path, both_high: bool, cross_domain: bool, top: usize, json_output: bool) {
    let frontier = load_frontier_or_fail(source);
    let result = tensions::analyze(&frontier, both_high, cross_domain, top);
    if json_output {
        let source_hash = hash_path_or_fail(source);
        let payload = json!({
            "ok": true,
            "command": "tensions",
            "schema_version": project::VELA_SCHEMA_VERSION,
            "frontier": {
                "name": &frontier.project.name,
                "source": source.display().to_string(),
                "hash": format!("sha256:{source_hash}"),
            },
            "filters": {
                "both_high": both_high,
                "cross_domain": cross_domain,
                "top": top,
            },
            "count": result.len(),
            "tensions": result.iter().map(|t| json!({
                "score": t.score,
                "resolved": t.resolved,
                "superseding_id": &t.superseding_id,
                "finding_a": {
                    "id": &t.finding_a.id,
                    "assertion": &t.finding_a.assertion,
                    "confidence": t.finding_a.confidence,
                    "assertion_type": &t.finding_a.assertion_type,
                    "citation_count": t.finding_a.citation_count,
                    "contradicts_count": t.finding_a.contradicts_count,
                },
                "finding_b": {
                    "id": &t.finding_b.id,
                    "assertion": &t.finding_b.assertion,
                    "confidence": t.finding_b.confidence,
                    "assertion_type": &t.finding_b.assertion_type,
                    "citation_count": t.finding_b.citation_count,
                    "contradicts_count": t.finding_b.contradicts_count,
                }
            })).collect::<Vec<_>>()
        });
        print_json(&payload);
    } else {
        tensions::print_tensions(&result);
    }
}

fn cmd_gaps(action: GapsAction) {
    match action {
        GapsAction::Rank {
            frontier,
            top,
            domain,
            json,
        } => cmd_gap_rank(&frontier, top, domain.as_deref(), json),
    }
}

fn cmd_gap_rank(frontier_path: &Path, top: usize, domain: Option<&str>, json_output: bool) {
    let frontier = load_frontier_or_fail(frontier_path);
    let mut ranked = frontier
        .findings
        .iter()
        .filter(|finding| finding.flags.gap || finding.flags.negative_space)
        .filter(|finding| {
            domain.is_none_or(|domain| {
                finding
                    .assertion
                    .text
                    .to_lowercase()
                    .contains(&domain.to_lowercase())
                    || finding
                        .assertion
                        .entities
                        .iter()
                        .any(|entity| entity.name.to_lowercase().contains(&domain.to_lowercase()))
            })
        })
        .map(|finding| {
            let dependency_count = frontier
                .findings
                .iter()
                .flat_map(|candidate| candidate.links.iter())
                .filter(|link| link.target == finding.id)
                .count();
            let score = dependency_count as f64 + finding.confidence.score;
            json!({
                "id": &finding.id,
                "kind": "candidate_gap_review_lead",
                "assertion": &finding.assertion.text,
                "score": score,
                "dependency_count": dependency_count,
                "confidence": finding.confidence.score,
                "evidence_type": &finding.evidence.evidence_type,
                "entities": finding.assertion.entities.iter().map(|e| &e.name).collect::<Vec<_>>(),
                "recommended_action": "Review source scope and missing evidence before treating this as an experiment target.",
                "caveats": ["Candidate gap rankings are review leads, not guaranteed underexplored areas or experiment targets."],
            })
        })
        .collect::<Vec<_>>();
    ranked.sort_by(|a, b| {
        b.get("score")
            .and_then(Value::as_f64)
            .partial_cmp(&a.get("score").and_then(Value::as_f64))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    ranked.truncate(top);
    if json_output {
        let source_hash = hash_path_or_fail(frontier_path);
        let payload = json!({
            "ok": true,
            "command": "gaps rank",
            "schema_version": project::VELA_SCHEMA_VERSION,
            "frontier": {
                "name": &frontier.project.name,
                "source": frontier_path.display().to_string(),
                "hash": format!("sha256:{source_hash}"),
            },
            "filters": {
                "top": top,
                "domain": domain,
            },
            "count": ranked.len(),
            "ranking_label": "candidate gap review leads",
            "caveats": ["These rankings are navigation signals over flagged findings, not scientific conclusions."],
            "review_leads": ranked.clone(),
            "gaps": ranked,
        });
        print_json(&payload);
    } else {
        println!();
        println!("  {}", "CANDIDATE GAP REVIEW LEADS".dimmed());
        println!("  {}", style::tick_row(60));
        println!("  review source scope; these are not guaranteed experiment targets.");
        println!();
        for (idx, gap) in ranked.iter().enumerate() {
            println!(
                "  {}. [{}] score={} {}",
                idx + 1,
                gap["id"].as_str().unwrap_or("?"),
                gap["score"].as_f64().unwrap_or(0.0),
                gap["assertion"].as_str().unwrap_or("")
            );
        }
    }
}

async fn cmd_bridge(inputs: &[PathBuf], check_novelty: bool, top_n: usize) {
    if inputs.len() < 2 {
        fail("need at least 2 frontier files for bridge detection.");
    }
    println!();
    println!("  {}", "VELA · BRIDGE · V0.36.0".dimmed());
    println!("  {}", style::tick_row(60));
    println!("  loading {} frontiers...", inputs.len());
    let mut named_projects = Vec::<(String, project::Project)>::new();
    let mut total_findings = 0;
    for path in inputs {
        let frontier = load_frontier_or_fail(path);
        let name = path
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        println!("  {} · {} findings", name, frontier.stats.findings);
        total_findings += frontier.stats.findings;
        named_projects.push((name, frontier));
    }
    let refs = named_projects
        .iter()
        .map(|(name, frontier)| (name.as_str(), frontier))
        .collect::<Vec<_>>();
    let mut bridges = bridge::detect_bridges(&refs);
    if check_novelty && !bridges.is_empty() {
        let client = Client::new();
        let check_count = bridges.len().min(top_n);
        println!("  running rough PubMed prior-art checks for top {check_count} bridges...");
        for bridge_item in bridges.iter_mut().take(check_count) {
            let query = bridge::novelty_query(&bridge_item.entity_name, bridge_item);
            match bridge::check_novelty(&client, &query).await {
                Ok(count) => bridge_item.pubmed_count = Some(count),
                Err(e) => eprintln!(
                    "  {} prior-art check failed for {}: {e}",
                    style::err_prefix(),
                    bridge_item.entity_name
                ),
            }
            tokio::time::sleep(std::time::Duration::from_millis(350)).await;
        }
    }
    print!("{}", bridge::format_report(&bridges, total_findings));
}

struct BenchArgs {
    frontier: Option<PathBuf>,
    gold: Option<PathBuf>,
    entity_gold: Option<PathBuf>,
    link_gold: Option<PathBuf>,
    suite: Option<PathBuf>,
    suite_ready: bool,
    min_f1: Option<f64>,
    min_precision: Option<f64>,
    min_recall: Option<f64>,
    no_thresholds: bool,
    json: bool,
}

/// v0.26 VelaBench: compare a candidate frontier (typically agent-
/// generated) against a gold frontier. Pure data comparison —
/// no LLM call, no network, deterministic. Exits non-zero when
/// the composite falls below `threshold` (default 0.0 = report only).
fn cmd_agent_bench(
    gold: &Path,
    candidate: &Path,
    sources: Option<&Path>,
    threshold: Option<f64>,
    report_path: Option<&Path>,
    json_out: bool,
) {
    let input = vela_protocol::agent_bench::BenchInput {
        gold_path: gold.to_path_buf(),
        candidate_path: candidate.to_path_buf(),
        sources: sources.map(Path::to_path_buf),
        threshold: threshold.unwrap_or(0.0),
    };
    let report = match vela_protocol::agent_bench::run(input) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{} bench failed: {e}", style::err_prefix());
            std::process::exit(1);
        }
    };

    let json = serde_json::to_string_pretty(&report).unwrap_or_default();
    if let Some(path) = report_path
        && let Err(e) = std::fs::write(path, &json)
    {
        eprintln!(
            "{} failed to write report to {}: {e}",
            style::err_prefix(),
            path.display()
        );
    }

    if json_out {
        println!("{json}");
    } else {
        println!();
        println!("  {}", "VELA · BENCH · AGENT STATE-UPDATE".dimmed());
        println!("  {}", style::tick_row(60));
        print!("{}", vela_protocol::agent_bench::render_pretty(&report));
        println!();
    }

    if !report.pass {
        std::process::exit(1);
    }
}

fn cmd_bench(args: BenchArgs) {
    if args.suite_ready {
        let suite_path = args
            .suite
            .unwrap_or_else(|| PathBuf::from("benchmarks/suites/bbb-core.json"));
        let payload =
            benchmark::suite_ready_report(&suite_path).unwrap_or_else(|e| fail_return(&e));
        print_json(&payload);
        if payload.get("ok").and_then(Value::as_bool) != Some(true) {
            std::process::exit(1);
        }
        return;
    }
    if let Some(suite_path) = args.suite {
        let payload = benchmark::run_suite(&suite_path).unwrap_or_else(|e| fail_return(&e));
        if args.json {
            print_json(&payload);
        } else {
            let ok = payload.get("ok").and_then(Value::as_bool) == Some(true);
            let metrics = payload.get("metrics").unwrap_or(&Value::Null);
            println!();
            println!("  {}", "VELA · BENCH · SUITE".dimmed());
            println!("  {}", style::tick_row(60));
            println!("  suite: {}", suite_path.display());
            println!(
                "  status: {}",
                if ok {
                    style::ok("pass")
                } else {
                    style::lost("fail")
                }
            );
            println!(
                "  tasks: {}/{} passed",
                metrics
                    .get("tasks_passed")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
                metrics
                    .get("tasks_total")
                    .and_then(Value::as_u64)
                    .unwrap_or(0)
            );
        }
        if payload.get("ok").and_then(Value::as_bool) != Some(true) {
            std::process::exit(1);
        }
        return;
    }

    let frontier = args
        .frontier
        .unwrap_or_else(|| PathBuf::from("frontiers/bbb-alzheimer.json"));
    let thresholds = benchmark::BenchmarkThresholds {
        min_f1: if args.no_thresholds {
            None
        } else {
            args.min_f1.or(Some(0.05))
        },
        min_precision: if args.no_thresholds {
            None
        } else {
            args.min_precision
        },
        min_recall: if args.no_thresholds {
            None
        } else {
            args.min_recall
        },
        ..Default::default()
    };
    if let Some(path) = args.link_gold {
        print_benchmark_or_exit(benchmark::task_envelope(
            &frontier,
            None,
            benchmark::BenchmarkMode::Link,
            Some(&path),
            &thresholds,
            None,
        ));
    } else if let Some(path) = args.entity_gold {
        print_benchmark_or_exit(benchmark::task_envelope(
            &frontier,
            None,
            benchmark::BenchmarkMode::Entity,
            Some(&path),
            &thresholds,
            None,
        ));
    } else if let Some(path) = args.gold {
        if args.json {
            print_benchmark_or_exit(benchmark::task_envelope(
                &frontier,
                None,
                benchmark::BenchmarkMode::Finding,
                Some(&path),
                &thresholds,
                None,
            ));
        } else {
            benchmark::run(&frontier, &path, false);
        }
    } else {
        fail("Provide --suite, --gold, --entity-gold, or --link-gold.");
    }
}

fn print_benchmark_or_exit(result: Result<Value, String>) {
    let payload = result.unwrap_or_else(|e| fail_return(&e));
    print_json(&payload);
    if payload.get("ok").and_then(Value::as_bool) != Some(true) {
        std::process::exit(1);
    }
}

fn cmd_packet(action: PacketAction) {
    let (result, json_output) = match action {
        PacketAction::Inspect { path, json } => (packet::inspect(&path), json),
        PacketAction::Validate { path, json } => (packet::validate(&path), json),
    };
    match result {
        Ok(output) if json_output => {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "ok": true,
                    "command": "packet",
                    "result": output,
                }))
                .expect("failed to serialize packet response")
            );
        }
        Ok(output) => println!("{output}"),
        Err(e) => fail(&e),
    }
}

fn cmd_trace(action: TraceAction) {
    match action {
        TraceAction::Validate { path, json } => {
            let report =
                research_trace::validate_trace_file(&path).unwrap_or_else(|e| fail_return(&e));
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": true,
                        "command": "trace.validate",
                        "trace": report.trace,
                        "summary": report.summary,
                    }))
                    .expect("failed to serialize trace validation")
                );
            } else {
                println!("vela trace validate");
                println!("  trace:    {}", report.trace.trace_id);
                println!("  sources:  {}", report.summary.source_inputs);
                println!(
                    "  outputs:  {}",
                    report.summary.candidate_findings + report.summary.open_needs
                );
                println!("  verifiers: {}", report.summary.verifier_attachments);
            }
        }
        TraceAction::Propose {
            path,
            frontier,
            out,
            json,
        } => {
            let loaded = load_frontier_or_fail(&frontier);
            let proposals = research_trace::proposals_from_trace_file(&path, &loaded)
                .unwrap_or_else(|e| fail_return(&e));
            if let Some(parent) = out.parent() {
                std::fs::create_dir_all(parent).unwrap_or_else(|e| {
                    fail(&format!(
                        "Failed to create proposal output dir {}: {e}",
                        parent.display()
                    ))
                });
            }
            let body = serde_json::to_string_pretty(&proposals)
                .expect("failed to serialize trace proposals");
            std::fs::write(&out, format!("{body}\n"))
                .unwrap_or_else(|e| fail(&format!("Failed to write {}: {e}", out.display())));
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": true,
                        "command": "trace.propose",
                        "trace": path.display().to_string(),
                        "frontier": frontier.display().to_string(),
                        "out": out.display().to_string(),
                        "proposal_count": proposals.len(),
                    }))
                    .expect("failed to serialize trace proposal response")
                );
            } else {
                println!("vela trace propose");
                println!("  trace:     {}", path.display());
                println!("  frontier:  {}", frontier.display());
                println!("  proposals: {}", proposals.len());
                println!("  out:       {}", out.display());
            }
        }
    }
}

fn cmd_correction_return(action: CorrectionReturnAction) {
    match action {
        CorrectionReturnAction::Validate { path, json } => {
            let report = correction_return::validate_correction_return_file(&path)
                .unwrap_or_else(|e| fail_return(&e));
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": true,
                        "command": "correction-return.validate",
                        "correction_return": report.correction_return,
                        "summary": report.summary,
                    }))
                    .expect("failed to serialize correction-return validation")
                );
            } else {
                println!("vela correction-return validate");
                println!("  frontier:    {}", report.correction_return.frontier);
                println!("  corrections: {}", report.summary.corrections);
                println!("  artifacts:   {}", report.summary.supporting_artifacts);
                println!("  gates:       {}", report.summary.verification_runs);
            }
        }
        CorrectionReturnAction::Propose {
            path,
            frontier,
            out,
            json,
        } => {
            let loaded = load_frontier_or_fail(&frontier);
            let proposals =
                correction_return::proposals_from_correction_return_file(&path, &loaded)
                    .unwrap_or_else(|e| fail_return(&e));
            if let Some(parent) = out.parent() {
                std::fs::create_dir_all(parent).unwrap_or_else(|e| {
                    fail(&format!(
                        "Failed to create proposal output dir {}: {e}",
                        parent.display()
                    ))
                });
            }
            let body = serde_json::to_string_pretty(&proposals)
                .expect("failed to serialize correction-return proposals");
            std::fs::write(&out, format!("{body}\n"))
                .unwrap_or_else(|e| fail(&format!("Failed to write {}: {e}", out.display())));
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": true,
                        "command": "correction-return.propose",
                        "correction_return": path.display().to_string(),
                        "frontier": frontier.display().to_string(),
                        "out": out.display().to_string(),
                        "proposal_count": proposals.len(),
                    }))
                    .expect("failed to serialize correction-return proposal response")
                );
            } else {
                println!("vela correction-return propose");
                println!("  return:    {}", path.display());
                println!("  frontier:  {}", frontier.display());
                println!("  proposals: {}", proposals.len());
                println!("  out:       {}", out.display());
            }
        }
    }
}

/// `vela verify <packet_dir>` — same code path as
/// `vela packet validate`, surfaced under a friendlier top-level name.
/// Reads every file in the manifest, recomputes SHA-256, validates the
/// proof-trace chain. Exit 0 on all-match, 1 on any mismatch.
fn cmd_verify(path: &Path, json_output: bool) {
    let result = packet::validate(path);
    match result {
        Ok(output) if json_output => {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "ok": true,
                    "command": "verify",
                    "result": output,
                }))
                .expect("failed to serialize verify response")
            );
        }
        Ok(output) => {
            println!("{output}");
            println!(
                "\nverify: ok\n  every file in the manifest matched its claimed sha256.\n  pull this packet on another machine, run the same command, see the same line."
            );
        }
        Err(e) => fail(&e),
    }
}

fn cmd_attach(
    frontier: &std::path::Path,
    target: &str,
    attachment_file: &std::path::Path,
    reviewer: &str,
    reason: &str,
    json: bool,
) {
    use vela_protocol::events::StateTarget;
    let body = match std::fs::read_to_string(attachment_file) {
        Ok(b) => b,
        Err(e) => fail(&format!("read {}: {e}", attachment_file.display())),
    };
    let att_value: Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => fail(&format!("parse attachment JSON: {e}")),
    };
    let actor_type = if reviewer.starts_with("agent:") {
        "agent"
    } else {
        "human"
    };
    let proposal = proposals::new_proposal(
        "verifier.attach",
        StateTarget {
            r#type: "finding".to_string(),
            id: target.to_string(),
        },
        reviewer,
        actor_type,
        reason,
        json!({ "attachment": att_value }),
        Vec::new(),
        Vec::new(),
    );
    match proposals::create_or_apply(frontier, proposal, true) {
        Ok(result) => {
            let event = result.applied_event_id.clone().unwrap_or_default();
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "command": "attach",
                        "target": target,
                        "proposal_id": result.proposal_id,
                        "event_id": event,
                        "applied": result.applied_event_id.is_some(),
                    }))
                    .expect("serialize attach response")
                );
            } else {
                println!(
                    "· ok attached verifier evidence to {target}\n  proposal {}\n  event {event}",
                    result.proposal_id
                );
            }
        }
        Err(e) => fail(&format!("attach: {e}")),
    }
}

fn cmd_gate(action: GateAction) {
    use vela_protocol::deliverable_grade::{self, DeliverableGrade, GradeGate};
    use vela_protocol::verifier_attachment::{
        self, GateStatus, ProbeKind, VerifierAttachment, VerifierMethod,
    };
    match action {
        GateAction::Grade { claim, grade, json } => {
            let gate = deliverable_grade::grade_gate(&claim, grade.as_deref());
            let passed = gate.passed();
            if json {
                let grade_str = match &gate {
                    GradeGate::Ok(g) => Some(g.as_str().to_string()),
                    _ => grade.clone(),
                };
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "command": "gate grade",
                        "passed": passed,
                        "grade": grade_str,
                        "reason": gate.reason(),
                    }))
                    .expect("serialize gate grade response")
                );
            } else if passed {
                println!("gate grade: ok");
                if let GradeGate::Ok(g) = gate {
                    println!("  deliverable_grade: {g}  (claim text consistent with grade)");
                }
            } else {
                eprintln!("gate grade: REJECTED\n  {}", gate.reason());
            }
            if !passed {
                std::process::exit(1);
            }
        }
        GateAction::Check {
            claim,
            attachments,
            json,
        } => {
            let raw = std::fs::read_to_string(&attachments)
                .unwrap_or_else(|e| fail_return(&format!("read {}: {e}", attachments.display())));
            let atts: Vec<VerifierAttachment> = serde_json::from_str(&raw).unwrap_or_else(|e| {
                fail_return(&format!(
                    "parse {} as a JSON array of VerifierAttachment: {e}",
                    attachments.display()
                ))
            });
            // G4: every attachment must be structurally sound before the
            // gate reasons over it.
            for a in &atts {
                if let Err(e) = a.verify() {
                    fail(&format!("attachment {} is malformed: {e}", a.id));
                }
            }
            let digest = verifier_attachment::claim_digest(&claim);
            let outcome = verifier_attachment::derive_gate_status(&digest, &atts);
            let verified = outcome.status == GateStatus::Verified;
            if json {
                let status = match outcome.status {
                    GateStatus::Verified => "verified",
                    GateStatus::NeedsVerification => "needs_verification",
                    GateStatus::Refuted => "refuted",
                };
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "command": "gate check",
                        "claim_digest": digest,
                        "attachments": atts.len(),
                        "status": status,
                        "reasons": outcome.reasons,
                    }))
                    .expect("serialize gate check response")
                );
            } else {
                println!("gate check: {} attachment(s) over claim {digest}", atts.len());
                match outcome.status {
                    GateStatus::Verified => println!(
                        "  status: VERIFIED\n  >=2 independent matched attachments + a surviving adversarial probe."
                    ),
                    GateStatus::Refuted => {
                        println!("  status: REFUTED");
                        for r in &outcome.reasons {
                            println!("    - {r}");
                        }
                    }
                    GateStatus::NeedsVerification => {
                        println!("  status: needs_verification");
                        for r in &outcome.reasons {
                            println!("    - {r}");
                        }
                    }
                }
            }
            if !verified {
                std::process::exit(1);
            }
        }
        GateAction::Vocab { json } => {
            let grades: Vec<&str> = DeliverableGrade::ALL.iter().map(|g| g.as_str()).collect();
            let methods: Vec<&str> = VerifierMethod::ALL.iter().map(|m| m.as_str()).collect();
            let probes = [
                ProbeKind::CounterexampleSearch,
                ProbeKind::CaseBConfig,
                ProbeKind::BoundaryDualFeasibility,
                ProbeKind::FiniteSizeExtrapolation,
                ProbeKind::IndependentReimplementation,
            ];
            let probe_kinds: Vec<&str> = probes.iter().map(|p| p.as_str()).collect();
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "command": "gate vocab",
                        "deliverable_grades": grades,
                        "solve_grades": DeliverableGrade::ALL
                            .iter()
                            .filter(|g| g.is_solve())
                            .map(|g| g.as_str())
                            .collect::<Vec<_>>(),
                        "verifier_methods": methods,
                        "probe_kinds": probe_kinds,
                    }))
                    .expect("serialize gate vocab response")
                );
            } else {
                println!("deliverable grades ({}):", grades.len());
                for g in DeliverableGrade::ALL {
                    let mark = if g.is_solve() { " (solve)" } else { "" };
                    println!("  {}{mark}", g.as_str());
                }
                println!("\nverifier methods ({}):", methods.len());
                for m in &methods {
                    println!("  {m}");
                }
                println!("\nadversarial probe kinds ({}):", probe_kinds.len());
                for p in &probe_kinds {
                    println!("  {p}");
                }
            }
        }
    }
}

/// `vela reproduce` — re-verify stored witnesses from scratch with the
/// frozen exact verifiers. Trust is never self-reported.
fn cmd_reproduce(path: &Path, json_output: bool) {
    let files = collect_witness_files(path);
    if files.is_empty() {
        fail(&format!(
            "no witnesses found at {} (expected a `*.witness.json` file, or a directory containing them / a `witnesses/` subdir)",
            path.display()
        ));
    }
    let mut results: Vec<Value> = Vec::new();
    let mut passed = 0usize;
    let mut failed = 0usize;
    for file in &files {
        let raw = match std::fs::read_to_string(file) {
            Ok(r) => r,
            Err(e) => {
                failed += 1;
                if !json_output {
                    println!("  FAIL  {}  ·  read error: {e}", file.display());
                }
                results.push(json!({"path": file.display().to_string(), "ok": false, "message": format!("read error: {e}")}));
                continue;
            }
        };
        let witness = match parse_witness(&raw) {
            Ok(w) => w,
            Err(e) => {
                failed += 1;
                if !json_output {
                    println!("  FAIL  {}  ·  parse error: {e}", file.display());
                }
                results.push(json!({"path": file.display().to_string(), "ok": false, "message": format!("parse error: {e}")}));
                continue;
            }
        };
        let outcome = vela_verify::verify_witness(&witness);
        if outcome.ok {
            passed += 1;
        } else {
            failed += 1;
        }
        if !json_output {
            let status = if outcome.ok { "ok  " } else { "FAIL" };
            println!(
                "  {status}  {} [{}]  ·  {}",
                file.display(),
                witness.kind(),
                outcome.message
            );
        }
        results.push(json!({
            "path": file.display().to_string(),
            "kind": witness.kind(),
            "ok": outcome.ok,
            "message": outcome.message,
        }));
    }
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "command": "reproduce",
                "witnesses": files.len(),
                "passed": passed,
                "failed": failed,
                "results": results,
            }))
            .expect("serialize reproduce response")
        );
    } else {
        println!();
        if failed == 0 {
            println!(
                "  reproduce: ok ({passed}/{}) — every witness re-verified from scratch by the frozen verifiers.",
                files.len()
            );
        } else {
            println!(
                "  reproduce: FAIL ({failed}/{} did not re-verify). Investigate before trusting.",
                files.len()
            );
        }
    }
    if failed > 0 {
        std::process::exit(1);
    }
}

/// Parse a witness file: either a bare `vela_verify::Witness`, or an
/// object with a `witness` field wrapping one (a record that ships its
/// construction).
fn parse_witness(raw: &str) -> Result<vela_verify::Witness, String> {
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
fn collect_witness_files(path: &Path) -> Vec<PathBuf> {
    if path.is_file() {
        return vec![path.to_path_buf()];
    }
    let root = {
        let sub = path.join("witnesses");
        if sub.is_dir() { sub } else { path.to_path_buf() }
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

/// v0.103: end-to-end first-run wizard. Composes `vela init`, `vela
/// sign generate-keypair`, `vela actor add`, and `vela finding add
/// --apply` into a single command. Each step shells out to the
/// current binary so the wizard's behavior matches running the
/// commands directly. Failure of any step aborts; partial state is
/// left on disk for the user to inspect.
/// v0.131: scaffold an AI-agent identity kit. Generates an Ed25519
/// keypair via the existing `sign generate-keypair` path, writes
/// the agent's portable record to `agents/<slug>/actor.json`
/// (`id: agent:<slug>-<date>`, `type: agent`, `public_key: ...`),
/// plus a minimal `agent.yaml` config naming the framework. The
/// substrate-honest contract: the agent record is portable — a
/// reviewer can register it into any frontier with
/// `vela actor add <frontier> <agent_id> --pubkey <hex>`. The
/// agent has no special privilege at registration time; its
/// proposals flow through the same reviewer-gated truth-claim
/// discipline as any other actor.
fn cmd_agent(action: AgentAction) {
    use std::process::Command;
    match action {
        AgentAction::Init {
            name,
            framework,
            out,
            json,
        } => {
            let slug = name.trim();
            if slug.is_empty() {
                fail("agent name must be non-empty");
            }
            // Conservative slug validation: lowercase alphanumeric +
            // hyphens. Reject path traversal, spaces, etc.
            if !slug
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            {
                fail("agent name must be lowercase alphanumeric + hyphens");
            }
            let valid_frameworks = [
                "claude-code",
                "claude-api",
                "langchain",
                "openai",
                "agent4science",
                "scienceclaw",
                "custom",
            ];
            if !valid_frameworks.contains(&framework.as_str()) {
                fail(&format!(
                    "--framework must be one of: {}",
                    valid_frameworks.join(", ")
                ));
            }

            let target = out
                .clone()
                .unwrap_or_else(|| PathBuf::from("agents").join(slug));
            if target.exists() {
                fail(&format!(
                    "agent directory already exists: {}",
                    target.display()
                ));
            }
            let keys_dir = target.join("keys");
            std::fs::create_dir_all(&keys_dir)
                .unwrap_or_else(|e| fail_return(&format!("create {}: {e}", keys_dir.display())));

            // Generate a keypair via the existing CLI surface. This
            // keeps the agent kit's keypair generation byte-identical
            // to `vela sign generate-keypair`.
            let exe = std::env::current_exe()
                .unwrap_or_else(|e| fail_return(&format!("cannot locate current executable: {e}")));
            let keys_out_str = keys_dir.to_string_lossy().into_owned();
            let kp_out = Command::new(&exe)
                .args(["sign", "generate-keypair", "--out", &keys_out_str, "--json"])
                .output()
                .unwrap_or_else(|e| fail_return(&format!("sign.generate-keypair: spawn: {e}")));
            if !kp_out.status.success() {
                let stderr = String::from_utf8_lossy(&kp_out.stderr);
                fail(&format!("sign.generate-keypair failed:\n{stderr}"));
            }
            let kp_json: Value = serde_json::from_slice(&kp_out.stdout)
                .unwrap_or_else(|e| fail_return(&format!("sign.generate-keypair bad json: {e}")));
            let public_key = kp_json
                .get("public_key")
                .and_then(Value::as_str)
                .unwrap_or_else(|| fail_return("sign.generate-keypair: missing public_key"))
                .to_string();

            let date = chrono::Utc::now().format("%Y-%m-%d").to_string();
            let agent_id = format!("agent:{slug}-{date}");
            let now = chrono::Utc::now().to_rfc3339();

            // actor.json — the substrate's portable record. A
            // reviewer feeds this into `vela actor add` to register
            // the agent in a specific frontier.
            let actor_record = json!({
                "schema": "vela.agent_kit.actor.v0.1",
                "id": agent_id,
                "public_key": public_key,
                "algorithm": "ed25519",
                "actor_type": "agent",
                "created_at": now,
                "framework": framework,
                "name": slug,
            });
            std::fs::write(
                target.join("actor.json"),
                serde_json::to_vec_pretty(&actor_record).expect("serialize actor.json"),
            )
            .unwrap_or_else(|e| fail_return(&format!("write actor.json: {e}")));

            // agent.yaml — minimal config; framework + workflow notes.
            let yaml = format!(
                "# v0.131: portable AI-agent kit scaffolded by `vela agent init`.\n\
                 # The substrate makes the agent-draft / human-verdict\n\
                 # distinction load-bearing. See docs/AI_ATTRIBUTION.md.\n\
                 \n\
                 schema: vela.agent_kit.v0.1\n\
                 id: {agent_id}\n\
                 name: {slug}\n\
                 framework: {framework}\n\
                 created_at: {now}\n\
                 \n\
                 # Workflow:\n\
                 # 1. A human reviewer registers this agent in a frontier:\n\
                 #      vela actor add <frontier> '{agent_id}' \\\n\
                 #        --pubkey {public_key}\n\
                 # 2. The agent reads frontier state through the MCP\n\
                 #    server: `vela serve <frontier>` (stdio JSON-RPC).\n\
                 #    Tools include frontier_stats, search_findings,\n\
                 #    get_finding, list_events.\n\
                 # 3. The agent drafts proposals signed under the\n\
                 #    keypair in keys/ via `vela propose ...` or by\n\
                 #    POSTing to `vela serve --http`.\n\
                 # 4. A human reviewer adjudicates each proposal.\n\
                 #    No agent-drafted proposal becomes accepted state\n\
                 #    without a signed human verdict.\n"
            );
            std::fs::write(target.join("agent.yaml"), yaml)
                .unwrap_or_else(|e| fail_return(&format!("write agent.yaml: {e}")));

            let payload = json!({
                "ok": true,
                "command": "agent.init",
                "agent_id": agent_id,
                "name": slug,
                "framework": framework,
                "public_key": public_key,
                "keys_dir": keys_dir.display().to_string(),
                "actor_json": target.join("actor.json").display().to_string(),
                "agent_yaml": target.join("agent.yaml").display().to_string(),
            });
            if json {
                print_json(&payload);
            } else {
                println!("{} scaffolded agent {}", style::ok("agent.init"), agent_id);
                println!("  framework:  {framework}");
                println!("  public_key: {}", &public_key[..16]);
                println!("  out:        {}", target.display());
                println!();
                println!("  next: register this agent in a frontier:");
                println!(
                    "    vela actor add <frontier> '{agent_id}' --pubkey {}",
                    &public_key[..16]
                );
                println!("  see docs/AGENT_QUICKSTART.md for the full workflow.");
            }
        }
        AgentAction::List { root, json } => {
            let mut entries: Vec<Value> = Vec::new();
            if root.is_dir() {
                for entry in std::fs::read_dir(&root)
                    .unwrap_or_else(|e| fail_return(&format!("read {}: {e}", root.display())))
                {
                    let entry = match entry {
                        Ok(e) => e,
                        Err(_) => continue,
                    };
                    let actor_json = entry.path().join("actor.json");
                    if !actor_json.is_file() {
                        continue;
                    }
                    if let Ok(text) = std::fs::read_to_string(&actor_json)
                        && let Ok(v) = serde_json::from_str::<Value>(&text)
                    {
                        entries.push(v);
                    }
                }
            }
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": true,
                        "command": "agent.list",
                        "root": root.display().to_string(),
                        "agents": entries,
                    }))
                    .expect("failed to serialize agent.list")
                );
            } else {
                println!("agents under {}: {}", root.display(), entries.len());
                for a in &entries {
                    let id = a.get("id").and_then(Value::as_str).unwrap_or("?");
                    let fw = a.get("framework").and_then(Value::as_str).unwrap_or("?");
                    println!("  · {id}  framework={fw}");
                }
            }
        }
    }
}

fn cmd_quickstart(
    path: &Path,
    name: &str,
    reviewer: &str,
    assertion: Option<&str>,
    keys_out: Option<&Path>,
    json_output: bool,
) {
    use std::process::Command;

    if path.join(".vela").exists() {
        fail(&format!(
            "already initialized: {} exists",
            path.join(".vela").display()
        ));
    }

    let exe = std::env::current_exe()
        .unwrap_or_else(|e| fail_return(&format!("cannot locate current executable: {e}")));
    let keys_dir = keys_out
        .map(Path::to_path_buf)
        .unwrap_or_else(|| path.join("keys"));
    let assertion_text =
        assertion.unwrap_or("Quickstart placeholder claim. Replace with your real assertion.");

    let run_step = |label: &str, args: &[&str]| -> std::process::Output {
        let out = Command::new(&exe)
            .args(args)
            .output()
            .unwrap_or_else(|e| fail_return(&format!("{label}: failed to spawn: {e}")));
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            fail(&format!("{label} failed:\n{stderr}"));
        }
        out
    };

    // Step 1: init the frontier.
    run_step(
        "init",
        &[
            "init",
            path.to_string_lossy().as_ref(),
            "--name",
            name,
            "--no-git",
            "--json",
        ],
    );

    // Step 2: generate keypair.
    let keys_out_str = keys_dir.to_string_lossy().into_owned();
    let keypair_out = run_step(
        "sign.generate-keypair",
        &[
            "sign",
            "generate-keypair",
            "--out",
            keys_out_str.as_ref(),
            "--json",
        ],
    );
    let keypair_json: serde_json::Value = serde_json::from_slice(&keypair_out.stdout)
        .unwrap_or_else(|e| fail_return(&format!("sign.generate-keypair: bad json: {e}")));
    let public_key = keypair_json
        .get("public_key")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| fail_return("sign.generate-keypair: missing public_key in output"))
        .to_string();

    // Step 3: register the reviewer actor.
    run_step(
        "actor.add",
        &[
            "actor",
            "add",
            path.to_string_lossy().as_ref(),
            reviewer,
            "--pubkey",
            public_key.as_str(),
            "--json",
        ],
    );

    // Step 4: add and apply the first finding.
    let finding_out = run_step(
        "finding.add",
        &[
            "finding",
            "add",
            path.to_string_lossy().as_ref(),
            "--assertion",
            assertion_text,
            "--author",
            reviewer,
            "--apply",
            "--json",
        ],
    );
    let finding_json: serde_json::Value = serde_json::from_slice(&finding_out.stdout)
        .unwrap_or_else(|e| fail_return(&format!("finding.add: bad json: {e}")));
    let finding_id = finding_json
        .get("finding_id")
        .and_then(|v| v.as_str())
        .map(str::to_string);

    if json_output {
        let payload = json!({
            "ok": true,
            "command": "quickstart",
            "frontier": path.display().to_string(),
            "name": name,
            "reviewer": reviewer,
            "public_key": public_key,
            "keys_dir": keys_dir.display().to_string(),
            "finding_id": finding_id,
            "next_steps": [
                format!("vela serve {}", path.display()),
                format!(
                    "vela ingest <paper.pdf|doi:...> --frontier {}",
                    path.display()
                ),
                format!("vela log {}", path.display()),
            ],
        });
        print_json(&payload);
        return;
    }

    println!();
    println!(
        "  {}",
        format!("VELA · QUICKSTART · {}", path.display())
            .to_uppercase()
            .dimmed()
    );
    println!("  {}", style::tick_row(60));
    println!("  frontier:  {}", path.display());
    println!("  name:      {name}");
    println!("  reviewer:  {reviewer}");
    println!("  keys:      {}", keys_dir.display());
    println!("  pubkey:    {}…", &public_key[..16]);
    if let Some(id) = finding_id.as_deref() {
        println!("  finding:   {id}");
    }
    println!();
    println!("  {}", style::ok("done"));
    println!("  next:");
    println!("    vela serve {}", path.display());
    println!(
        "    vela ingest <paper.pdf|doi:10.xxx|pmid:xxx> --frontier {}",
        path.display()
    );
    println!("    vela log {}", path.display());
    println!();
}

/// v0.109: regenerate or verify the frontier's vela.lock.
/// Default mode runs `frontier_repo::materialize` which rebuilds
/// the lock from current state. `--check` reads the existing
/// lock and verifies on-disk hashes match the recorded values
/// without writing anything; exits 1 on drift.
fn cmd_lock(path: &Path, check: bool, json_output: bool) {
    if check {
        cmd_lock_check(path, json_output);
        return;
    }
    let payload = vela_protocol::frontier_repo::materialize(path).unwrap_or_else(|e| fail_return(&e));
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": true,
                "command": "lock",
                "path": path.display().to_string(),
                "snapshot_hash": payload.get("snapshot_hash"),
                "event_log_hash": payload.get("event_log_hash"),
                "proposal_state_hash": payload.get("proposal_state_hash"),
            }))
            .expect("failed to serialize lock report")
        );
        return;
    }
    println!();
    println!(
        "  {}",
        format!("VELA · LOCK · {}", path.display())
            .to_uppercase()
            .dimmed()
    );
    println!("  {}", style::tick_row(60));
    println!(
        "  snapshot_hash:        {}",
        payload
            .get("snapshot_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("?")
    );
    println!(
        "  event_log_hash:       {}",
        payload
            .get("event_log_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("?")
    );
    println!(
        "  proposal_state_hash:  {}",
        payload
            .get("proposal_state_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("?")
    );
    println!();
    println!("  {}", style::ok("locked"));
}

fn cmd_lock_check(path: &Path, json_output: bool) {
    use vela_protocol::frontier_repo::read_lock;
    let lock = read_lock(path).unwrap_or_else(|e| fail_return(&e));
    let Some(lock) = lock else {
        fail("lock --check: no vela.lock found at path");
    };
    let project = repo::load_from_path(path).unwrap_or_else(|e| fail_return(&e));
    let current_snapshot = format!("sha256:{}", vela_protocol::events::snapshot_hash(&project));
    let current_event_log = format!("sha256:{}", vela_protocol::events::event_log_hash(&project.events));
    let mut drift: Vec<String> = Vec::new();
    if lock.snapshot_hash != current_snapshot {
        drift.push(format!(
            "snapshot_hash: lock={} current={}",
            lock.snapshot_hash, current_snapshot
        ));
    }
    if lock.event_log_hash != current_event_log {
        drift.push(format!(
            "event_log_hash: lock={} current={}",
            lock.event_log_hash, current_event_log
        ));
    }
    let ok = drift.is_empty();
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": ok,
                "command": "lock.check",
                "path": path.display().to_string(),
                "drift": drift,
                "lock_snapshot_hash": lock.snapshot_hash,
                "current_snapshot_hash": current_snapshot,
                "lock_event_log_hash": lock.event_log_hash,
                "current_event_log_hash": current_event_log,
                "dependency_count": lock.dependencies.len(),
            }))
            .expect("failed to serialize lock check report")
        );
    } else {
        println!();
        println!(
            "  {}",
            format!("VELA · LOCK · CHECK · {}", path.display())
                .to_uppercase()
                .dimmed()
        );
        println!("  {}", style::tick_row(60));
        if ok {
            println!("  snapshot_hash:        {}", lock.snapshot_hash);
            println!("  event_log_hash:       {}", lock.event_log_hash);
            println!("  dependencies pinned:  {}", lock.dependencies.len());
            println!();
            println!("  {} on-disk state matches vela.lock", style::ok("ok"));
        } else {
            println!("  {} drift detected:", style::err_prefix());
            for d in &drift {
                println!("    - {d}");
            }
        }
    }
    if !ok {
        std::process::exit(1);
    }
}

/// v0.110: write a static HTML documentation site for the
/// frontier at `path`. Output lands in `<path>/doc/` by default
/// or in the user-supplied `--out` directory. Cargo's docs.rs
/// analog for scientific state.
fn cmd_doc(path: &Path, out: Option<&Path>, json_output: bool) {
    let project = repo::load_from_path(path).unwrap_or_else(|e| fail_return(&e));
    let out_dir = out
        .map(Path::to_path_buf)
        .unwrap_or_else(|| path.join("doc"));
    let report =
        vela_protocol::doc_render::write_site(&project, &out_dir).unwrap_or_else(|e| fail_return(&e));
    if json_output {
        print_json(&report);
        return;
    }
    println!();
    println!(
        "  {}",
        format!("VELA · DOC · {}", path.display())
            .to_uppercase()
            .dimmed()
    );
    println!("  {}", style::tick_row(60));
    println!("  frontier_id:        {}", report.frontier_id);
    println!("  out:                {}", report.out);
    println!("  files written:      {}", report.files_written);
    println!("  findings:           {}", report.findings_documented);
    println!("  events:             {}", report.events_documented);
    println!();
    println!(
        "  {} open {}/index.html in a browser",
        style::ok("ok"),
        report.out
    );
}

fn cmd_import(frontier_path: &Path, into: Option<&Path>) {
    let frontier = repo::load_from_path(frontier_path).unwrap_or_else(|e| fail_return(&e));
    let target = into
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from(frontier.project.name.replace(' ', "-").to_lowercase()));
    repo::init_repo(&target, &frontier).unwrap_or_else(|e| fail(&e));
    println!(
        "{} {} findings · {}",
        style::ok("imported"),
        frontier.findings.len(),
        target.display()
    );
}

fn cmd_locator_repair(
    path: &Path,
    atom_id: &str,
    locator_override: Option<&str>,
    reviewer: &str,
    reason: &str,
    apply: bool,
    json_output: bool,
) {
    let report = state::repair_evidence_atom_locator(
        path,
        atom_id,
        locator_override,
        reviewer,
        reason,
        apply,
    )
    .unwrap_or_else(|e| fail_return(&e));
    print_state_report(&report, json_output);
}

fn cmd_span_repair(
    path: &Path,
    finding_id: &str,
    section: &str,
    text: &str,
    reviewer: &str,
    reason: &str,
    apply: bool,
    json_output: bool,
) {
    let report =
        state::repair_finding_span(path, finding_id, section, text, reviewer, reason, apply)
            .unwrap_or_else(|e| fail_return(&e));
    print_state_report(&report, json_output);
}

#[allow(clippy::too_many_arguments)]
fn cmd_entity_resolve(
    path: &Path,
    finding_id: &str,
    entity_name: &str,
    source: &str,
    id: &str,
    confidence: f64,
    matched_name: Option<&str>,
    resolution_method: &str,
    reviewer: &str,
    reason: &str,
    apply: bool,
    json_output: bool,
) {
    let report = state::resolve_finding_entity(
        path,
        finding_id,
        entity_name,
        source,
        id,
        confidence,
        matched_name,
        resolution_method,
        reviewer,
        reason,
        apply,
    )
    .unwrap_or_else(|e| fail_return(&e));
    print_state_report(&report, json_output);
}

fn cmd_propagate(
    path: &Path,
    retract: Option<String>,
    reduce_confidence: Option<String>,
    to: Option<f64>,
    output: Option<&Path>,
) {
    let mut frontier = load_frontier_or_fail(path);
    let (finding_id, action, label) = if let Some(id) = retract {
        (id, propagate::PropagationAction::Retracted, "retraction")
    } else if let Some(id) = reduce_confidence {
        let score = to.unwrap_or_else(|| fail_return("--reduce-confidence requires --to <score>"));
        if !(0.0..=1.0).contains(&score) {
            fail("--to must be between 0.0 and 1.0");
        }
        (
            id,
            propagate::PropagationAction::ConfidenceReduced { new_score: score },
            "confidence reduction",
        )
    } else {
        fail("specify --retract <id> or --reduce-confidence <id> --to <score>");
    };
    if !frontier.findings.iter().any(|f| f.id == finding_id) {
        fail(&format!("finding not found: {finding_id}"));
    }
    let result = propagate::propagate_correction(&mut frontier, &finding_id, action);
    // v0.36.2: persist propagation events into the canonical review
    // log. Pre-v0.36.2 these were emitted to stdout and lost — the
    // kernel forgot why a finding was flagged the moment the command
    // returned.
    frontier.review_events.extend(result.events.clone());
    project::recompute_stats(&mut frontier);
    propagate::print_result(&result, label, &finding_id);
    let out = output.unwrap_or(path);
    repo::save_to_path(out, &frontier).expect("Failed to save frontier");
    println!("  output: {}", out.display());
}

fn cmd_mcp_setup(source: Option<&Path>, frontiers: Option<&Path>) {
    let source_desc = source
        .map(|p| p.display().to_string())
        .or_else(|| frontiers.map(|p| p.display().to_string()))
        .unwrap_or_else(|| "frontier.json".to_string());
    let args = if let Some(path) = source {
        format!(r#""serve", "{}""#, path.display())
    } else if let Some(path) = frontiers {
        format!(r#""serve", "--frontiers", "{}""#, path.display())
    } else {
        r#""serve", "frontier.json""#.to_string()
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

fn parse_entities(input: &str) -> Vec<(String, String)> {
    if input.trim().is_empty() {
        return Vec::new();
    }
    input
        .split(',')
        .filter_map(|pair| {
            let parts = pair.trim().splitn(2, ':').collect::<Vec<_>>();
            if parts.len() == 2 {
                Some((parts[0].trim().to_string(), parts[1].trim().to_string()))
            } else {
                eprintln!(
                    "{} skipping malformed entity '{}'",
                    style::warn("warn"),
                    pair.trim()
                );
                None
            }
        })
        .collect()
}

fn parse_evidence_spans(inputs: &[String]) -> Vec<Value> {
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

fn hash_path(path: &Path) -> Result<String, String> {
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

fn hash_path_or_fail(path: &Path) -> String {
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

fn cmd_integrity(frontier: &Path, json: bool, strict: bool) {
    let mut report = state_integrity::analyze_path(frontier).unwrap_or_else(|e| fail_return(&e));
    // CI gate: --strict treats warnings as failures. Promote the reported status
    // so the JSON and the exit code both reflect the gate; default behaviour is
    // unchanged (informational, exit 0).
    let strict_fail =
        strict && (!report.structural_errors.is_empty() || !report.warnings.is_empty());
    if strict_fail {
        report.status = "fail".to_string();
    }
    if json {
        print_json(&report);
    } else {
        println!("vela integrity");
        println!("  frontier: {}", frontier.display());
        println!("  status: {}", report.status);
        println!("  proof freshness: {}", report.proof_freshness);
        println!("  structural errors: {}", report.structural_errors.len());
        for error in report.structural_errors.iter().take(8) {
            println!("  - {}: {}", error.rule_id, error.message);
        }
        println!("  warnings: {}", report.warnings.len());
        for warning in report.warnings.iter().take(8) {
            println!("  ~ {}: {}", warning.rule_id, warning.message);
        }
        if strict {
            println!("  strict: warnings treated as failures");
        }
    }
    if strict_fail {
        std::process::exit(1);
    }
}

fn cmd_impact(frontier: &Path, finding_id: &str, depth: Option<usize>, json: bool) {
    let report =
        impact::analyze_path(frontier, finding_id, depth).unwrap_or_else(|e| fail_return(&e));
    if json {
        print_json(&report);
    } else {
        println!("vela impact");
        println!("  finding: {}", report.target.id);
        println!("  frontier: {}", report.frontier.vfr_id);
        println!("  direct dependents: {}", report.summary.direct_dependents);
        println!("  downstream: {}", report.summary.total_downstream);
        println!("  open proposals: {}", report.summary.open_proposals);
        println!("  accepted events: {}", report.summary.accepted_events);
        println!("  proof: {}", report.summary.proof_status);
    }
}

fn cmd_discord(frontier: &Path, json: bool, kind_filter: Option<&str>) {
    use vela_protocol::discord::DiscordKind;
    use vela_protocol::discord_compute::compute_discord_assignment;

    let project = repo::load_from_path(frontier).unwrap_or_else(|e| fail_return(&e));
    let assignment = compute_discord_assignment(&project);
    let support = assignment.frontier_support();

    // Build the per-finding rows: only those with non-empty discord
    // (i.e. those in support), filtered by kind if requested.
    let mut rows: Vec<(String, Vec<String>)> = Vec::new();
    for context in support.iter() {
        let set = assignment.get(context);
        let kinds: Vec<String> = set.iter().map(|k| k.as_str().to_string()).collect();
        if let Some(filter) = kind_filter
            && !kinds.iter().any(|k| k == filter)
        {
            continue;
        }
        rows.push((context.clone(), kinds));
    }

    // Per-kind histogram across the full assignment (independent of
    // the row filter, so the histogram reflects the substrate's real
    // discord landscape).
    let mut histogram: std::collections::BTreeMap<&'static str, usize> =
        std::collections::BTreeMap::new();
    for kind in DiscordKind::ALL {
        let count = assignment
            .iter()
            .filter(|(_, set)| set.contains(*kind))
            .count();
        if count > 0 {
            histogram.insert(kind.as_str(), count);
        }
    }

    let total_findings = project.findings.len();
    let frontier_id = project
        .frontier_id
        .clone()
        .unwrap_or_else(|| String::from("<unknown>"));

    if json {
        let row_value = |row: &(String, Vec<String>)| {
            serde_json::json!({
                "finding_id": row.0,
                "discord_kinds": row.1,
            })
        };
        let report = serde_json::json!({
            "frontier_id": frontier_id,
            "total_findings": total_findings,
            "frontier_support_size": support.len(),
            "filtered_row_count": rows.len(),
            "filter_kind": kind_filter,
            "histogram": histogram,
            "rows": rows.iter().map(row_value).collect::<Vec<_>>(),
        });
        print_json(&report);
        return;
    }

    println!("vela discord");
    println!("  frontier: {frontier_id}");
    println!("  total findings: {total_findings}");
    println!(
        "  frontier support (any discord): {} of {}",
        support.len(),
        total_findings
    );
    if let Some(k) = kind_filter {
        println!("  filter: kind = {k}");
    }
    println!();
    if histogram.is_empty() {
        println!("  no discord detected.");
    } else {
        println!("  discord histogram:");
        for (k, n) in &histogram {
            println!("    {n:>4}  {k}");
        }
    }
    if !rows.is_empty() {
        println!();
        println!("  findings with discord (showing up to 50):");
        for (fid, kinds) in rows.iter().take(50) {
            println!("    {fid}  ·  {}", kinds.join(", "));
        }
        if rows.len() > 50 {
            println!("    ... and {} more", rows.len() - 50);
        }
    }
}

fn cmd_evidence_ci(frontier: &Path, json: bool) {
    let report = evidence_ci::run_frontier(frontier)
        .unwrap_or_else(|e| fail_return(&format!("evidence-ci failed: {e}")));
    if json {
        print_json(&report);
        return;
    }
    let status = if report.ok {
        style::ok("evidence-ci")
    } else {
        style::lost("evidence-ci")
    };
    println!(
        "{} {} · {} checks, {} warning(s), {} release-blocking failure(s)",
        status,
        report.frontier_id,
        report.summary.total,
        report.summary.warnings,
        report.summary.release_blocking_failed
    );
    for check in report
        .checks
        .iter()
        .filter(|check| check.status != evidence_ci::EvidenceCiStatus::Passed)
        .take(40)
    {
        println!(
            "  {} {} {}: {}",
            match check.status {
                evidence_ci::EvidenceCiStatus::Passed => style::ok("pass"),
                evidence_ci::EvidenceCiStatus::Warning => style::warn("warn"),
                evidence_ci::EvidenceCiStatus::Failed => style::lost("fail"),
            },
            check.id,
            check.target_id,
            check.message
        );
    }
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

fn append_packet_json_file(
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

fn print_state_report(report: &state::StateCommandReport, json_output: bool) {
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

fn print_history(payload: &Value) {
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

const SCIENCE_SUBCOMMANDS: &[&str] = &[
    "compile-notes",
    "compile-code",
    "compile-data",
    "review-pending",
    "find-tensions",
    "plan-experiments",
    "scout",
    "check",
    "normalize",
    "integrity",
    "impact",
    "discord",
    "evidence-ci",
    "doctor",
    "quickstart",
    "proof",
    "repo",
    "serve",
    "stats",
    "search",
    "search-index",
    "index",
    "citation",
    "credit",
    "crossref",
    "handle",
    "hub",
    "lean",
    "attempt",
    "diff-pack",
    "policy",
    "controller",
    "incident",
    "review-packet",
    "review-session",
    "source-inbox",
    "adoption",
    "share",
    "tool",
    "eval",
    "conflict",
    "preprint",
    "review-thread",
    "proof-attest-verification",
    "proof-verify-attestation",
    "tensions",
    "gaps",
    "bridge",
    "export",
    "packet",
    "trace",
    "correction-return",
    "bench",
    "conformance",
    "gate",
    "reproduce",
    "version",
    "sign",
    "actor",
    "frontier",
    "queue",
    "registry",
    "init",
    "import",
    "lock",
    "doc",
    "diff",
    "proposals",
    "finding",
    "link",
    "entity",
    "review",
    "note",
    "caveat",
    "revise",
    "reject",
    "history",
    "import-events",
    "retract",
    "propagate",
    // v0.32: replication as a first-class kernel object.
    "replicate",
    "replications",
    // v0.33: computational provenance — datasets and code as
    // first-class kernel objects.
    "dataset-add",
    "datasets",
    "code-add",
    "code-artifacts",
    "artifact-add",
    "artifact-to-state",
    "bridge-kit",
    "source-adapter",
    "task",
    "runtime-adapter",
    "artifacts",
    "artifact-audit",
    "decision-brief",
    "review-work",
    "trial-summary",
    "source-verification",
    "source-ingest-plan",
    "clinical-trial-import",
    // v0.49: NegativeResult deposits (registered_trial + exploratory).
    "negative-result-add",
    "negative-results",
    // v0.50: Trajectory — search-path deposits.
    "trajectory-create",
    "trajectory-step",
    "trajectories",
    // v0.51: dual-use access tier classification.
    "tier-set",
    // v0.56: mechanical evidence-atom locator repair.
    "locator-repair",
    // v0.57: mechanical finding-level span repair.
    "span-repair",
    // v0.57: entity resolution.
    "entity-resolve",
    // v0.79: append a new entity tag to an existing finding.
    "entity-add",
    // v0.117: register a Carina Proof primitive (vpf_*) against a finding.
    "proof-add",
    // v0.131: scaffold an AI-agent identity kit (agent init / list).
    "agent",
    // v0.57: external source fetch (Crossref / PubMed / CT.gov).
    "source-fetch",
    // v0.34: predictions and resolutions — the epistemic accountability
    // ledger.
    "predict",
    "resolve",
    "predictions",
    "predictions-expire",
    "calibration",
    // v0.35: inference layer — consensus aggregation over claim-similar
    // findings.
    "consensus",
    // v0.39: federation — peer registry + sync runtime.
    "federation",
    // v0.40: causal reasoning — identifiability audit.
    "causal",
    // v0.42: daily-driver triad + conversational REPL. The
    // "git status / git log / inbox" of the substrate, plus a
    // thin natural-language router over the same kernel queries.
    "status",
    "log",
    "inbox",
    "ask",
    // v0.46: cross-frontier bridge runtime.
    "bridges",
    // v0.48: local workbench web app.
    "workbench",
    // v0.49: friendlier alias for `vela packet validate <path>`.
    "verify",
    // v0.74: top-level alias verbs that surface the daily flow
    // (init/ingest/propose/diff/accept/attest/log/lineage/serve)
    // without burying the verbs inside subcommand groups.
    "ingest",
    "propose",
    "accept",
    "accept-batch",
    "attach",
    "attest",
    "lineage",
    // v0.75: Carina spec deliverable (list/schema/validate
    // against the 14 bundled primitive schemas).
    "carina",
    // v0.78: Atlas-level surface (init / materialize / serve).
    // Routes through handlers the binary installs.
    "atlas",
    // v0.82: Constellation-level surface (init / materialize /
    // serve). Network of Atlases (vco_*).
    "constellation",
];

pub fn is_science_subcommand(name: &str) -> bool {
    SCIENCE_SUBCOMMANDS.contains(&name)
}

fn print_strict_help() {
    println!(
        r#"Vela {}
Version control for scientific state.

Usage:
  vela <COMMAND>

Core flow (v0.74):
  init          Initialize a split frontier repo
  ingest        Ingest a paper, dataset, or Carina packet (dispatches by file type)
  propose       Create a finding.review proposal
  diff          Preview a `vpr_*` proposal, or compare two frontier files
  accept        Apply a proposal under reviewer authority
  attest        Sign findings under your private key
  log           Recent canonical state events
  lineage       State-transition replay for one finding
  serve         Local Workbench (findings, evidence, diff, lineage)

Read-only inspection:
  check         Validate a frontier, repo, or proof packet
  integrity     Check accepted frontier state integrity
  impact        Report downstream finding impact
  normalize     Apply deterministic frontier-state repairs
  proof         Export and validate a proof packet
  repo          Inspect split frontier repository status and shape
  doctor        Diagnose first-user checkout, frontier, proof, and Workbench readiness
  stats         Show frontier statistics
  search        Search findings
  index         Build and query the local frontier index database
  tensions      List candidate contradictions and tensions
  gaps          Inspect and rank candidate gap review leads
  bridge        Find candidate cross-domain connections
  review-work   Show read-only review-work queues

Advanced (proposal-creation, agent inboxes, federation):
  scout              Run Literature Scout against a folder of PDFs (writes proposals)
  compile-notes      Run Notes Compiler against a Markdown vault (writes proposals)
  compile-code       Run Code & Notebook Analyst against a research repo (writes proposals)
  compile-data       Run Datasets agent against a folder of CSV/TSV data (writes proposals)
  review-pending     Run Reviewer Agent: score every pending proposal (writes notes)
  find-tensions      Run Contradiction Finder: surface real contradictions among findings
  plan-experiments   Run Experiment Planner: propose experiments for open questions / hypotheses
  export        Export frontier artifacts
  packet        Inspect or validate proof packets
  trace         Validate research traces and draft review proposals
  correction-return
                Validate returned corrections and draft review proposals
  bench         Run deterministic benchmark gates
  conformance   Run protocol conformance vectors
  gate          Verification gate: deliverable-grade + verifier-attachment checks
  reproduce     Re-verify stored witnesses from scratch (frozen exact verifiers)
  sign          Optional signing and signature verification
  runtime-adapter
                Normalize external runtime exports into reviewable proposals
  version       Show version information
  import        Import frontier.json into a .vela repo
  proposals     Inspect, validate, export, import, accept, or reject write proposals
  artifact-to-state
                Import a Carina artifact packet as reviewable proposals
  bridge-kit
                Validate Carina artifact packets before importing runtime output
  source-adapter
                Run reviewed source adapters into artifact-to-state proposals
  source-inbox
                Manage local source-material records before evidence review
  adoption
                Build first external adoption transcripts
  share
                Build and inspect read-only frontier share packages
  controller
                Reconcile local frontier signals into review tasks
  incident      Open, list, close, and inspect local frontier incidents
  evidence-ci   Check source, evidence, condition, confidence, and policy review readiness
  task          Create, list, claim, and close local frontier tasks
  review-packet
                Build local review packets for task workspaces
  review-session
                Record local outside-review sessions over frontier objects
  policy        Check frontier-owned evidence, review, confidence, and agent policy
  finding       Add or manage finding bundles as frontier state
  link          Add typed links between findings (incl. cross-frontier vf_at-vfr targets)
  entity        Resolve unresolved entities against a bundled common-entity table (v0.19)
  frontier      Scaffold (`new`), materialize, and manage frontier metadata + deps
  actor         Register Ed25519 publisher identities in a frontier
  registry      Publish, list, or pull frontiers (open hub at https://vela-hub.fly.dev)
  review        Create a review proposal or review interactively
  note          Add a lightweight note to a finding
  caveat        Create an explicit caveat proposal
  revise        Create a confidence revision proposal
  reject        Create a rejection proposal
  history       Show state-transition history for one finding (v0.74 alias: `lineage`)
  import-events  Import review/state events from a packet or JSON file
  retract       Create a retraction proposal
  propagate     Simulate impact over declared dependency links
  artifact-add  Register a content-addressed artifact
  artifacts     List content-addressed artifacts
  artifact-audit Audit artifact locators, hashes, references, and profiles
  decision-brief Show the validated decision brief projection
  review-work Show read-only review-work queues
  trial-summary Show the validated trial outcome projection
  source-verification Show the validated source verification projection
  source-ingest-plan Show the validated source ingest plan
  clinical-trial-import  Import a ClinicalTrials.gov record as an artifact
  locator-repair Mechanically repair an evidence atom's missing source locator
  span-repair    Mechanically repair a finding's missing evidence span
  entity-resolve Resolve a finding entity to a canonical id
  source-fetch   Fetch metadata + abstract for a doi:/pmid:/nct: source
  atlas         Compose multiple frontiers into a domain-level Atlas (vat_*) (v0.78+)
  constellation Compose multiple Atlases into a cross-domain Constellation (vco_*) (v0.82+)

Quick start (the demo):
  vela init demo --name "Your bounded question"
  vela ingest paper.pdf --frontier demo
  vela propose demo <vf_id> --status accepted --reason "..." --reviewer reviewer:you --apply
  vela diff <vpr_id> --frontier demo
  vela accept demo <vpr_id> --reviewer reviewer:you --reason "applied"
  vela serve --path demo

Substrate health:
  vela frontier materialize my-frontier --json
  vela frontier audit my-frontier --json
  vela repo status my-frontier --json
  vela proof verify my-frontier --json
  vela check my-frontier --strict --json

Monolithic frontier file:
  vela frontier new frontier.json --name "Your bounded question"
  vela finding add frontier.json --assertion "..." --author "reviewer:demo" --apply
  vela check frontier.json --json
  FINDING_ID=$(jq -r '.findings[0].id' frontier.json)
  vela review frontier.json "$FINDING_ID" --status contested --reason "Mouse-only evidence" --reviewer reviewer:demo --apply

Publish your own frontier (see docs/PUBLISHING.md):
  vela frontier new ./frontier.json --name "Your bounded question"
  vela finding add ./frontier.json --assertion "..." --author "reviewer:you" --apply
  vela sign generate-keypair --out keys
  vela actor add ./frontier.json reviewer:you --pubkey "$(cat keys/public.key)"
  vela registry publish ./frontier.json --owner reviewer:you --key keys/private.key \
      --to https://vela-hub.fly.dev
"#,
        env!("CARGO_PKG_VERSION")
    );
}

/// v0.22 Agent Inbox: pluggable handler for `vela scout`.
///
/// The substrate library can't import `vela-scientist` (cyclic
/// dependency), so the scout dispatch in this module looks up a
/// handler installed by the binary at startup. The `vela` CLI in
/// `crates/vela-cli` registers a real handler via
/// `register_scout_handler`. Library callers that want scout
/// behaviour install their own.
pub type ScoutHandler = fn(
    folder: PathBuf,
    frontier: PathBuf,
    backend: Option<String>,
    dry_run: bool,
    json: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>>;

static SCOUT_HANDLER: OnceLock<ScoutHandler> = OnceLock::new();

/// Install the scout handler. Idempotent — second registrations are
/// silently ignored so a misbehaving consumer can't unseat the
/// binary's wiring mid-run.
pub fn register_scout_handler(handler: ScoutHandler) {
    let _ = SCOUT_HANDLER.set(handler);
}

/// v0.78: pluggable handler for `vela atlas init`. The binary in
/// `vela-cli/src/main.rs` installs a real handler that calls into
/// the `vela-atlas` crate.
pub type AtlasInitHandler = fn(
    atlases_root: PathBuf,
    name: String,
    domain: String,
    scope_note: Option<String>,
    frontiers: Vec<PathBuf>,
    json: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>>;

static ATLAS_INIT_HANDLER: OnceLock<AtlasInitHandler> = OnceLock::new();

pub fn register_atlas_init_handler(handler: AtlasInitHandler) {
    let _ = ATLAS_INIT_HANDLER.set(handler);
}

/// v0.149: pluggable handler for `vela search build`.
pub type SearchBuildHandler = fn(
    frontiers: Vec<PathBuf>,
    out: PathBuf,
    include_bootstrap: bool,
    include_broken: bool,
    json: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>>;

static SEARCH_BUILD_HANDLER: OnceLock<SearchBuildHandler> = OnceLock::new();

pub fn register_search_build_handler(handler: SearchBuildHandler) {
    let _ = SEARCH_BUILD_HANDLER.set(handler);
}

/// v0.149: pluggable handler for `vela search query`.
#[allow(clippy::too_many_arguments)]
pub type SearchQueryHandler = fn(
    query: String,
    index: Option<PathBuf>,
    kind: Option<String>,
    entity: Option<String>,
    status: Option<String>,
    frontier_id: Option<String>,
    source_id: Option<String>,
    chain_status: Option<String>,
    limit: Option<usize>,
    json: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>>;

static SEARCH_QUERY_HANDLER: OnceLock<SearchQueryHandler> = OnceLock::new();

pub fn register_search_query_handler(handler: SearchQueryHandler) {
    let _ = SEARCH_QUERY_HANDLER.set(handler);
}

/// v0.78: pluggable handler for `vela atlas materialize`.
pub type AtlasMaterializeHandler =
    fn(atlases_root: PathBuf, name: String, json: bool) -> Pin<Box<dyn Future<Output = ()> + Send>>;

static ATLAS_MATERIALIZE_HANDLER: OnceLock<AtlasMaterializeHandler> = OnceLock::new();

pub fn register_atlas_materialize_handler(handler: AtlasMaterializeHandler) {
    let _ = ATLAS_MATERIALIZE_HANDLER.set(handler);
}

/// v0.78: pluggable handler for `vela atlas serve`. v0.78 stub
/// delegates to the per-frontier Workbench for the first
/// composing frontier. Dedicated Atlas-level Workbench page is
/// v0.79+.
pub type AtlasServeHandler = fn(
    atlases_root: PathBuf,
    name: String,
    port: u16,
    open_browser: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>>;

static ATLAS_SERVE_HANDLER: OnceLock<AtlasServeHandler> = OnceLock::new();

pub fn register_atlas_serve_handler(handler: AtlasServeHandler) {
    let _ = ATLAS_SERVE_HANDLER.set(handler);
}

/// v0.81.2: pluggable handler for `vela atlas update`. Lets the
/// binary update an Atlas's composing-frontier list without the
/// rm-and-init dance. The handler re-computes the Atlas's
/// content-addressed id and writes the updated manifest.
pub type AtlasUpdateHandler = fn(
    atlases_root: PathBuf,
    name: String,
    add_frontier: Vec<PathBuf>,
    remove_vfr_id: Vec<String>,
    json: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>>;

static ATLAS_UPDATE_HANDLER: OnceLock<AtlasUpdateHandler> = OnceLock::new();

pub fn register_atlas_update_handler(handler: AtlasUpdateHandler) {
    let _ = ATLAS_UPDATE_HANDLER.set(handler);
}

/// v0.82: Constellation-level handlers. Mirror the Atlas
/// pattern one layer up. The binary registers handlers that
/// call into the `vela-constellation` crate.
pub type ConstellationInitHandler = fn(
    constellations_root: PathBuf,
    name: String,
    scope_note: Option<String>,
    atlases: Vec<PathBuf>,
    json: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>>;

static CONSTELLATION_INIT_HANDLER: OnceLock<ConstellationInitHandler> = OnceLock::new();

pub fn register_constellation_init_handler(handler: ConstellationInitHandler) {
    let _ = CONSTELLATION_INIT_HANDLER.set(handler);
}

pub type ConstellationMaterializeHandler = fn(
    constellations_root: PathBuf,
    name: String,
    json: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>>;

static CONSTELLATION_MATERIALIZE_HANDLER: OnceLock<ConstellationMaterializeHandler> =
    OnceLock::new();

pub fn register_constellation_materialize_handler(handler: ConstellationMaterializeHandler) {
    let _ = CONSTELLATION_MATERIALIZE_HANDLER.set(handler);
}

pub type ConstellationServeHandler = fn(
    constellations_root: PathBuf,
    name: String,
    port: u16,
    open_browser: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>>;

static CONSTELLATION_SERVE_HANDLER: OnceLock<ConstellationServeHandler> = OnceLock::new();

pub fn register_constellation_serve_handler(handler: ConstellationServeHandler) {
    let _ = CONSTELLATION_SERVE_HANDLER.set(handler);
}

/// v0.23 Agent Inbox: pluggable handler for `vela compile-notes`.
/// Same OnceLock pattern as the scout handler; the binary
/// registers it at startup.
pub type NotesHandler = fn(
    vault: PathBuf,
    frontier: PathBuf,
    backend: Option<String>,
    max_files: Option<usize>,
    max_items_per_category: Option<usize>,
    dry_run: bool,
    json: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>>;

static NOTES_HANDLER: OnceLock<NotesHandler> = OnceLock::new();

/// Install the notes-compiler handler. Idempotent.
pub fn register_notes_handler(handler: NotesHandler) {
    let _ = NOTES_HANDLER.set(handler);
}

/// v0.24 Agent Inbox: pluggable handler for `vela compile-code`.
pub type CodeHandler = fn(
    root: PathBuf,
    frontier: PathBuf,
    backend: Option<String>,
    max_files: Option<usize>,
    dry_run: bool,
    json: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>>;

static CODE_HANDLER: OnceLock<CodeHandler> = OnceLock::new();

/// Install the code-analyst handler. Idempotent.
pub fn register_code_handler(handler: CodeHandler) {
    let _ = CODE_HANDLER.set(handler);
}

/// v0.25 Agent Inbox: pluggable handler for `vela compile-data`.
pub type DatasetsHandler = fn(
    root: PathBuf,
    frontier: PathBuf,
    backend: Option<String>,
    sample_rows: Option<usize>,
    dry_run: bool,
    json: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>>;

static DATASETS_HANDLER: OnceLock<DatasetsHandler> = OnceLock::new();

/// Install the datasets handler. Idempotent.
pub fn register_datasets_handler(handler: DatasetsHandler) {
    let _ = DATASETS_HANDLER.set(handler);
}

/// v0.28 Agent Inbox: handler for `vela review-pending`.
pub type ReviewerHandler = fn(
    frontier: PathBuf,
    backend: Option<String>,
    max_proposals: Option<usize>,
    batch_size: usize,
    dry_run: bool,
    json: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>>;

static REVIEWER_HANDLER: OnceLock<ReviewerHandler> = OnceLock::new();

/// Install the reviewer-agent handler. Idempotent.
pub fn register_reviewer_handler(handler: ReviewerHandler) {
    let _ = REVIEWER_HANDLER.set(handler);
}

/// v0.28 Agent Inbox: handler for `vela find-tensions`.
pub type TensionsHandler = fn(
    frontier: PathBuf,
    backend: Option<String>,
    max_findings: Option<usize>,
    dry_run: bool,
    json: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>>;

static TENSIONS_HANDLER: OnceLock<TensionsHandler> = OnceLock::new();

/// Install the contradiction-finder handler. Idempotent.
pub fn register_tensions_handler(handler: TensionsHandler) {
    let _ = TENSIONS_HANDLER.set(handler);
}

/// v0.28 Agent Inbox: handler for `vela plan-experiments`.
pub type ExperimentsHandler = fn(
    frontier: PathBuf,
    backend: Option<String>,
    max_findings: Option<usize>,
    dry_run: bool,
    json: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>>;

static EXPERIMENTS_HANDLER: OnceLock<ExperimentsHandler> = OnceLock::new();

/// Install the experiment-planner handler. Idempotent.
pub fn register_experiments_handler(handler: ExperimentsHandler) {
    let _ = EXPERIMENTS_HANDLER.set(handler);
}

// ── v0.47: session entry ─────────────────────────────────────────────
//
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
    println!("  CORE FLOW (v0.74)");
    println!("    init              Initialize a split frontier repo");
    println!("    ingest <path>     Ingest a paper, dataset, or Carina packet");
    println!("    propose           Create a finding.review proposal");
    println!("    diff <vpr_id>     Preview a pending proposal vs current frontier");
    println!("    accept <vpr_id>   Apply a proposal under reviewer authority");
    println!("    attest            Sign findings under your private key");
    println!("    log               Recent canonical state events");
    println!("    lineage <vf_id>   State-transition replay for one finding");
    println!("    serve             Local Workbench (find, evidence, diff, lineage)");
    println!();
    println!("  DAILY ALSO-RANS");
    println!("    status            One-screen frontier health");
    println!("    frontier audit    Strict check, proof, Evidence CI, health, review work");
    println!("    inbox             Pending review proposals");
    println!("    review            Review a proposal interactively");
    println!("    ask <question>    Plain-text query against the frontier");
    println!();
    println!("  REASONING (Pearl 1 → 2 → 3)");
    println!("    causal audit                       Per-finding identifiability");
    println!("    causal effect <src> --on <tgt>     Pairwise back-door / front-door");
    println!("    causal counterfactual <src> --target <tgt> --set-to <0..1>");
    println!();
    println!("  COMPOSITION");
    println!("    bridge <a> <b>                     Cross-frontier hypotheses");
    println!("    consensus <vf>                     Field consensus over similar claims");
    println!();
    println!("  PUBLISH");
    println!("    registry publish                   Push a signed manifest to the hub");
    println!("    federation peer-add                Federate with another hub");
    println!();
    println!("  In session, type a single letter for a quick verb, or any");
    println!("  question in plain text. `q` or `exit` quits.");
    println!();
}

fn print_session_dashboard(project: &vela_protocol::project::Project, repo_path: &Path) {
    use vela_protocol::causal_reasoning::{audit_frontier, summarize_audit};

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

    let bridges_dir = repo_path.join(".vela/bridges");
    let mut bridge_total = 0usize;
    let mut bridge_confirmed = 0usize;
    let mut bridge_derived = 0usize;
    if bridges_dir.is_dir()
        && let Ok(entries) = std::fs::read_dir(&bridges_dir)
    {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            bridge_total += 1;
            if let Ok(data) = std::fs::read_to_string(&path)
                && let Ok(b) = serde_json::from_str::<vela_protocol::bridge::Bridge>(&data)
            {
                match b.status {
                    vela_protocol::bridge::BridgeStatus::Confirmed => bridge_confirmed += 1,
                    vela_protocol::bridge::BridgeStatus::Derived => bridge_derived += 1,
                    _ => {}
                }
            }
        }
    }

    let mut targets_with_success = std::collections::HashSet::new();
    let mut failed_replications = 0usize;
    for r in &project.replications {
        if r.outcome == "replicated" {
            targets_with_success.insert(r.target_finding.clone());
        } else if r.outcome == "failed" {
            failed_replications += 1;
        }
    }

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
    if bridge_total > 0 {
        println!(
            "  {}   · {} total · {} confirmed · {} awaiting review",
            style::ok("bridges"),
            bridge_total,
            bridge_confirmed,
            bridge_derived
        );
    }
    if !project.replications.is_empty() {
        println!(
            "  {} · {} records · {} findings replicated · {} failed",
            style::ok("replications"),
            project.replications.len(),
            targets_with_success.len(),
            failed_replications,
        );
    }

    println!();
    println!("  type a verb or ask anything:");
    println!("    a  audit problems     i  inbox (pending)     b  bridges");
    println!("    g  causal graph       l  log (recent)        c  counterfactuals");
    println!("    s  refresh status     h  help (more verbs)   q  quit");
    println!();
}

/// Run a single verb shortcut. Returns true if the verb was recognized.
fn run_session_verb(verb: &str, repo_path: &Path) -> bool {
    match verb {
        "a" | "audit" => {
            let action = CausalAction::Audit {
                frontier: repo_path.to_path_buf(),
                problems_only: true,
                json: false,
            };
            cmd_causal(action);
            true
        }
        "i" | "inbox" => {
            let action = ProposalAction::List {
                frontier: repo_path.to_path_buf(),
                status: Some("pending_review".into()),
                json: false,
            };
            cmd_proposals(action);
            true
        }
        "b" | "bridges" => {
            let action = BridgesAction::List {
                frontier: repo_path.to_path_buf(),
                status: None,
                json: false,
            };
            cmd_bridges(action);
            true
        }
        "g" | "graph" => {
            let action = CausalAction::Graph {
                frontier: repo_path.to_path_buf(),
                node: None,
                json: false,
            };
            cmd_causal(action);
            true
        }
        "l" | "log" => {
            cmd_log(repo_path, 10, None, false);
            true
        }
        "c" | "counterfactual" | "counterfactuals" => {
            // No specific source/target — print the live pairs the
            // user can run counterfactual queries against.
            let project = match repo::load_from_path(repo_path) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("{} {e}", style::err_prefix());
                    return true;
                }
            };
            println!();
            println!("  {}", "VELA · COUNTERFACTUAL · LIVE PAIRS".dimmed());
            println!("  {}", style::tick_row(60));
            // Walk every finding's `depends`/`supports` links; a live
            // counterfactual pair is (target, child) where the link
            // from child to target carries a mechanism.
            let mut pairs = 0usize;
            for child in &project.findings {
                for link in &child.links {
                    if !matches!(link.link_type.as_str(), "depends" | "supports") {
                        continue;
                    }
                    if link.mechanism.is_none() {
                        continue;
                    }
                    let parent = link
                        .target
                        .split_once(':')
                        .map_or(link.target.as_str(), |(_, r)| r);
                    pairs += 1;
                    if pairs <= 10 {
                        println!("    · do({parent}) → {}", child.id);
                    }
                }
            }
            if pairs == 0 {
                println!("  no mechanism-annotated edges found.");
                println!("  add a mechanism via the link's `mechanism` field; see /counterfactual");
            } else {
                println!();
                println!("  {pairs} live pair(s). Run with:");
                println!("    vela causal counterfactual <repo> <src> --target <tgt> --set-to 0.5");
            }
            println!();
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
fn validate_enum_arg(flag: &str, value: &str, valid: &[&str]) {
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
fn print_engine_verdict(v: &proposals::EngineVerdict) {
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
