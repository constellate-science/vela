use crate::serve;
use vela_edge::benchmark;
use vela_edge::carina_validate;
use vela_edge::conformance;
use vela_edge::doctor;
use vela_edge::export;
use vela_edge::frontier_health;
use vela_edge::frontier_task;
use vela_edge::lint;
use vela_edge::normalize;
use vela_edge::packet;
use vela_edge::review;
use vela_edge::reviewer_identity;
use vela_edge::search;
use vela_edge::signals;
use vela_edge::state_integrity;
use vela_edge::tensions;
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

pub(crate) use crate::cli_check::*;
use crate::cli_commands::*;
pub(crate) use crate::cli_finding::*;
pub(crate) use crate::cli_frontier::*;
pub(crate) use crate::cli_lean::*;
pub(crate) use crate::cli_registry::*;
pub(crate) use crate::cli_source_fetch::*;

pub async fn run_command() {
    dotenvy::dotenv().ok();

    match Cli::parse().command {
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
        Commands::Serve {
            frontier,
            frontiers,
            backend,
            http,
            setup,
            check_tools,
            adoption,
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
                let source =
                    serve::ProjectSource::from_args(frontier.as_deref(), frontiers.as_deref());
                if let Some(port) = http {
                    serve::run_http(source, backend.as_deref(), port).await;
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
        Commands::Export {
            frontier,
            format,
            output,
        } => export::run(&frontier, &format, output.as_deref()),
        Commands::Verify { path, json } => cmd_verify(&path, json),
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
        } => cmd_attach(
            &frontier,
            &target,
            &attachment_file,
            &reviewer,
            &reason,
            json,
        ),
        Commands::Reproduce { path, json } => cmd_reproduce(&path, json),
        Commands::Version => println!("vela {}", env!("CARGO_PKG_VERSION")),
        Commands::Sign { action } => cmd_sign(action),
        Commands::Actor { action } => cmd_actor(action),
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
        Commands::Lean { action } => cmd_lean(action),
        Commands::Attempt { action } => crate::cli_lean::cmd_attempt(action),
        Commands::Transfer { action } => crate::cli_lean::cmd_transfer(action),
        Commands::RetroImpact {
            record,
            frontier,
            json,
        } => cmd_retro_impact(&record, &frontier, json),
        Commands::Task { action } => cmd_task(action),
        Commands::Hub { action } => cmd_hub_spec(action),
        Commands::Preprint {
            frontier,
            released_at,
            out,
            json,
        } => cmd_preprint(frontier, released_at, out, json),
        Commands::ArtifactToState {
            frontier,
            packet,
            actor,
            apply_artifacts,
            json,
        } => cmd_artifact_to_state(&frontier, &packet, &actor, apply_artifacts, json),
        Commands::Link { action } => cmd_link(action),
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
        Commands::ReviewWork { frontier, json } => cmd_review_work(&frontier, json),

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

        Commands::Carina { action } => cmd_carina(action),
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

fn cmd_review_work(frontier: &Path, json_out: bool) {
    let payload = crate::review_work::build_review_work_json(frontier)
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
    // derived from frontier state and is domain-neutral.
    const SUPPORTED_TEMPLATES: &[&str] = &["generic"];
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
    let audit = vela_edge::causal_reasoning::audit_frontier(&project);
    let audit_summary = vela_edge::causal_reasoning::summarize_audit(&audit);

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
            vela_edge::calibration::calibration_records(&project.predictions, &project.resolutions);
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
            let clearance: Option<vela_protocol::access_tier::AccessTier> =
                clearance.as_deref().map(|s| {
                    vela_protocol::access_tier::AccessTier::parse(s)
                        .unwrap_or_else(|e| fail_return(&e))
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
    }
}

/// Phase R (v0.5): walk the local Workbench draft queue. The Workbench
/// browser writes unsigned drafts to a queue file; this CLI is the only
/// place where the actor's private key reads its drafts and signs them.
/// The browser never sees the key.
fn cmd_queue(action: QueueAction) {
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

fn confirm_action(action: &vela_edge::queue::QueuedAction) -> bool {
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
                let event_id = vela_protocol::proposals::accept_at_path(
                    &action.frontier,
                    proposal_id,
                    actor,
                    reason,
                )
                .map_err(|e| format!("accept_at_path: {e}"))?;
                Ok(format!("event {event_id}"))
            } else {
                vela_protocol::proposals::reject_at_path(
                    &action.frontier,
                    proposal_id,
                    actor,
                    reason,
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
/// v0.19: bundled entity resolution. See `vela_edge::entity_resolve` for the
/// table + algorithm. CLI surface is two subcommands: `resolve` (mutates
/// the frontier file) and `list` (read-only inspection of the table).
fn cmd_entity(action: EntityAction) {
    use vela_edge::entity_resolve;
    match action {
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
        && let Some(parent) = frontier.parent()
    {
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

/// v0.167: handle `vela hub ...`. Build + validate hub-spec
/// primitive records.
fn cmd_hub_spec(action: HubSpecCli) {
    use vela_edge::hub_spec::{HubSpec, HubSpecDraft};

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
            let rebuilt = HubSpec::from_draft(vela_edge::hub_spec::HubSpecDraft {
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

fn parse_task_status(status: &str) -> frontier_task::FrontierTaskStatus {
    status
        .parse()
        .unwrap_or_else(|e| fail_return(&format!("invalid task status: {e}")))
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

/// v0.163: handle `vela preprint <frontier>`. Renders a Markdown
/// preprint body for the frontier.
fn cmd_preprint(frontier: PathBuf, released_at: Option<String>, out: Option<PathBuf>, json: bool) {
    use vela_edge::preprint::render_preprint;

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
    use vela_edge::deliverable_grade::{self, DeliverableGrade, GradeGate};
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
                println!(
                    "gate check: {} attachment(s) over claim {digest}",
                    atts.len()
                );
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
    let payload =
        vela_protocol::frontier_repo::materialize(path).unwrap_or_else(|e| fail_return(&e));
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
    let current_event_log = format!(
        "sha256:{}",
        vela_protocol::events::event_log_hash(&project.events)
    );
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
        vela_edge::doc_render::write_site(&project, &out_dir).unwrap_or_else(|e| fail_return(&e));
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

fn cmd_retro_impact(record: &str, frontier: &Path, json: bool) {
    let project = load_frontier_or_fail(frontier);
    let impact = vela_edge::dependency_oracle::dependency_impact(&project, record);
    if json {
        print_json(&serde_json::to_value(&impact).unwrap_or_default());
    } else {
        println!(
            "impact {}: {} record(s) rest on it ({} gate-verified); {} direct",
            record,
            impact.weight,
            impact.verified_weight,
            impact.direct_dependents.len()
        );
    }
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
    "transfer",
    "retro-impact",
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
                && let Ok(b) = serde_json::from_str::<vela_edge::bridge::Bridge>(&data)
            {
                match b.status {
                    vela_edge::bridge::BridgeStatus::Confirmed => bridge_confirmed += 1,
                    vela_edge::bridge::BridgeStatus::Derived => bridge_derived += 1,
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
