//! `cmd_diff_pack` and its handler logic, split out of cli.rs.

use crate::cli::{fail, fail_return, print_json};

use crate::cli_commands::DiffPackAction;
use vela_protocol::cli_style as style;
use vela_protocol::{evidence_ci, repo, reviewer_identity};
use serde_json::json;

/// v0.193: handle `vela diff-pack <action>`. Build, show, or
/// verify a Scientific Diff Pack (`vsd_*`).
pub(crate) fn cmd_diff_pack(action: DiffPackAction) {
    use vela_protocol::scientific_diff::{PackDraft, ScientificDiffPack};

    match action {
        DiffPackAction::Create {
            frontier,
            proposals,
            summary,
            aggregate_kind,
            agent_run,
            parent_pack,
            key,
            out,
            json,
        } => {
            let project = repo::load_from_path(&frontier).unwrap_or_else(|e| fail_return(&e));
            // Validate that every cited proposal exists on the
            // frontier. The pack is meaningless if it cites a
            // proposal that isn't there.
            for vpr in &proposals {
                let found = project.proposals.iter().any(|p| &p.id == vpr);
                if !found {
                    fail(&format!(
                        "proposal `{vpr}` not found on frontier `{}`",
                        project.frontier_id()
                    ));
                }
            }
            let draft = PackDraft {
                frontier_id: project.frontier_id().to_string(),
                created_at: chrono::Utc::now().to_rfc3339(),
                summary,
                proposals,
                aggregate_kind,
                agent_run,
                parent_pack,
            };
            let mut pack = ScientificDiffPack::build(draft).unwrap_or_else(|e| fail_return(&e));
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
                pack.sign(&signing);
            }
            let body = serde_json::to_string_pretty(&pack).expect("serialize pack");
            if let Some(parent) = out.parent() {
                std::fs::create_dir_all(parent)
                    .unwrap_or_else(|e| fail_return(&format!("create {}: {e}", parent.display())));
            }
            std::fs::write(&out, format!("{body}\n"))
                .unwrap_or_else(|e| fail_return(&format!("write {}: {e}", out.display())));
            if json {
                let payload = json!({
                    "ok": true,
                    "command": "diff-pack.create",
                    "pack_id": pack.pack_id,
                    "frontier_id": pack.frontier_id,
                    "members": pack.proposals.len(),
                    "signed": pack.signature.is_some(),
                    "out": out.display().to_string(),
                });
                print_json(&payload);
            } else {
                println!(
                    "{} {} ({} member{}) -> {}",
                    style::ok("diff-pack"),
                    pack.pack_id,
                    pack.proposals.len(),
                    if pack.proposals.len() == 1 { "" } else { "s" },
                    out.display()
                );
            }
        }
        DiffPackAction::Show { pack, json } => {
            let body = std::fs::read_to_string(&pack)
                .unwrap_or_else(|e| fail_return(&format!("read {}: {e}", pack.display())));
            let p: ScientificDiffPack = serde_json::from_str(&body)
                .unwrap_or_else(|e| fail_return(&format!("parse pack: {e}")));
            if json {
                println!("{body}");
            } else {
                println!(
                    "{} {}\n  frontier: {}\n  summary:  {}\n  kind:     {}\n  members:  {}",
                    style::ok("diff-pack.show"),
                    p.pack_id,
                    p.frontier_id,
                    p.summary,
                    p.aggregate_kind,
                    p.proposals.len()
                );
                for (i, vpr) in p.proposals.iter().enumerate() {
                    println!("    {:2}. {}", i + 1, vpr);
                }
                if let Some(agent) = &p.agent_run {
                    println!("  agent_run: {agent}");
                }
                if let Some(parent) = &p.parent_pack {
                    println!("  parent_pack: {parent}");
                }
                if p.signature.is_some() {
                    println!(
                        "  signed by: {}",
                        p.signer_pubkey_hex.as_deref().unwrap_or("?")
                    );
                }
            }
        }
        DiffPackAction::Inspect {
            frontier,
            pack_id,
            json,
        } => {
            let pack_path = frontier
                .join(".vela")
                .join("diff_packs")
                .join(format!("{pack_id}.json"));
            let body = std::fs::read_to_string(&pack_path)
                .unwrap_or_else(|e| fail_return(&format!("read {}: {e}", pack_path.display())));
            let p: ScientificDiffPack = serde_json::from_str(&body)
                .unwrap_or_else(|e| fail_return(&format!("parse pack: {e}")));
            p.verify()
                .unwrap_or_else(|e| fail_return(&format!("verify failed: {e}")));
            let summary = p.review_summary(&frontier);
            if json {
                let mut payload = serde_json::to_value(&summary).expect("serialize summary");
                if let Some(obj) = payload.as_object_mut() {
                    obj.insert(
                        "command".to_string(),
                        serde_json::Value::String("diff-pack.inspect".to_string()),
                    );
                    let missing = reviewer_identity::missing_roles_for_target(
                        &frontier,
                        &summary.pack_id,
                        &summary.required_reviewers,
                    )
                    .unwrap_or_else(|_| summary.required_reviewers.clone());
                    obj.insert(
                        "missing_required_roles".to_string(),
                        serde_json::json!(missing),
                    );
                }
                print_json(&payload);
            } else {
                println!(
                    "{} {}\n  summary: {}\n  operations: {}\n  affected findings: {}\n  required reviewers: {}",
                    style::ok("diff-pack.inspect"),
                    summary.pack_id,
                    summary.summary,
                    summary.proposed_operations.len(),
                    summary.affected_findings.len(),
                    summary.required_reviewers.join(", ")
                );
                for op in &summary.proposed_operations {
                    println!(
                        "    {} {} {} {}",
                        op.proposal_id,
                        op.operation_class,
                        op.kind,
                        op.target_id.as_deref().unwrap_or("")
                    );
                }
            }
        }
        DiffPackAction::Verify { pack, json } => {
            let body = std::fs::read_to_string(&pack)
                .unwrap_or_else(|e| fail_return(&format!("read {}: {e}", pack.display())));
            let p: ScientificDiffPack = serde_json::from_str(&body)
                .unwrap_or_else(|e| fail_return(&format!("parse pack: {e}")));
            p.verify()
                .unwrap_or_else(|e| fail_return(&format!("verify failed: {e}")));
            if json {
                let payload = json!({
                    "ok": true,
                    "command": "diff-pack.verify",
                    "pack_id": p.pack_id,
                    "signed": p.signature.is_some(),
                });
                print_json(&payload);
            } else {
                println!(
                    "{} {} verifies ({} member{}, {})",
                    style::ok("diff-pack.verify"),
                    p.pack_id,
                    p.proposals.len(),
                    if p.proposals.len() == 1 { "" } else { "s" },
                    if p.signature.is_some() {
                        "signed"
                    } else {
                        "unsigned"
                    }
                );
            }
        }
        DiffPackAction::Validate {
            frontier,
            pack_id,
            evidence_ci: run_evidence_ci,
            json,
        } => {
            if run_evidence_ci {
                let report = evidence_ci::run_diff_pack(&frontier, &pack_id)
                    .unwrap_or_else(|e| fail_return(&format!("diff-pack validate failed: {e}")));
                if json {
                    print_json(&report);
                } else {
                    let status = if report.ok {
                        style::ok("diff-pack.validate")
                    } else {
                        style::lost("diff-pack.validate")
                    };
                    println!(
                        "{} {} · {} checks, {} release-blocking failure(s)",
                        status,
                        pack_id,
                        report.summary.total,
                        report.summary.release_blocking_failed
                    );
                }
            } else {
                let pack_path = frontier
                    .join(".vela")
                    .join("diff_packs")
                    .join(format!("{pack_id}.json"));
                let body = std::fs::read_to_string(&pack_path)
                    .unwrap_or_else(|e| fail_return(&format!("read {}: {e}", pack_path.display())));
                let p: ScientificDiffPack = serde_json::from_str(&body)
                    .unwrap_or_else(|e| fail_return(&format!("parse pack: {e}")));
                p.verify()
                    .unwrap_or_else(|e| fail_return(&format!("verify failed: {e}")));
                if json {
                    let payload = json!({
                        "ok": true,
                        "command": "diff-pack.validate",
                        "pack_id": p.pack_id,
                        "evidence_ci": false,
                    });
                    print_json(&payload);
                } else {
                    println!("{} {} verifies", style::ok("diff-pack.validate"), p.pack_id);
                }
            }
        }
        DiffPackAction::BackfillRelease { frontier, json } => {
            use vela_protocol::diff_pack_release;
            let reports = diff_pack_release::backfill_all(&frontier)
                .unwrap_or_else(|e| fail_return(&format!("backfill-release failed: {e}")));
            let created = reports.iter().filter(|r| r.created).count();
            if json {
                let payload = json!({
                    "ok": true,
                    "command": "diff-pack.backfill-release",
                    "created": created,
                    "total": reports.len(),
                    "reports": reports.iter().map(|r| json!({
                        "pack_id": r.pack_id,
                        "event_id": r.event_id,
                        "created": r.created,
                    })).collect::<Vec<_>>(),
                });
                print_json(&payload);
            } else {
                println!(
                    "{} {} pack(s) on disk; {} new release event(s) emitted",
                    style::ok("diff-pack.backfill-release"),
                    reports.len(),
                    created
                );
                for r in &reports {
                    if r.created {
                        println!("  + {} -> {}", r.pack_id, r.event_id);
                    } else {
                        println!("  = {} (existing {})", r.pack_id, r.event_id);
                    }
                }
            }
        }
        DiffPackAction::PromoteVerdicts { frontier, json } => {
            use vela_protocol::diff_pack_promote;
            let reports = diff_pack_promote::promote_all(&frontier)
                .unwrap_or_else(|e| fail_return(&format!("promote-verdicts failed: {e}")));
            if json {
                let payload = json!({
                    "ok": true,
                    "command": "diff-pack.promote-verdicts",
                    "promoted": reports.iter().map(|r| json!({
                        "verdict_id": r.verdict_id,
                        "pack_id": r.pack_id,
                        "verdict": r.verdict.canonical(),
                        "event_id": r.event_id,
                        "applied_members": r.applied_members,
                        "sdk_only_members": r.sdk_only_members,
                    })).collect::<Vec<_>>(),
                });
                print_json(&payload);
            } else {
                println!(
                    "{} {} verdict(s) promoted",
                    style::ok("diff-pack.promote-verdicts"),
                    reports.len()
                );
                for r in &reports {
                    println!(
                        "  {} {} -> {} ({} applied, {} sdk-only)",
                        r.pack_id,
                        r.verdict.canonical(),
                        r.event_id,
                        r.applied_members.len(),
                        r.sdk_only_members.len()
                    );
                }
            }
        }
        DiffPackAction::WitnessCheck {
            pack_id,
            hubs,
            json,
        } => {
            if !pack_id.starts_with("vsd_") {
                fail(&format!("pack_id must start with `vsd_`, got `{pack_id}`"));
            }
            if hubs.is_empty() {
                fail("--hubs requires at least one hub URL");
            }

            // GET <hub>/diff-packs/<pack_id> from each hub; collect
            // canonical-bytes hashes for comparison.
            let client = reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .build()
                .unwrap_or_else(|e| fail_return(&format!("http client: {e}")));

            #[derive(serde::Serialize)]
            struct HubResult {
                hub: String,
                status: String,
                body_sha256: Option<String>,
                signature: Option<String>,
                http_status: Option<u16>,
                error: Option<String>,
            }

            let mut results: Vec<HubResult> = Vec::new();
            for hub in &hubs {
                let url = format!("{}/diff-packs/{}", hub.trim_end_matches('/'), pack_id);
                match client.get(&url).send() {
                    Ok(resp) => {
                        let code = resp.status();
                        if !code.is_success() {
                            results.push(HubResult {
                                hub: hub.clone(),
                                status: if code.as_u16() == 404 {
                                    "missing".to_string()
                                } else {
                                    "error".to_string()
                                },
                                body_sha256: None,
                                signature: None,
                                http_status: Some(code.as_u16()),
                                error: None,
                            });
                            continue;
                        }
                        match resp.text() {
                            Ok(body) => {
                                let body_hash = {
                                    use sha2::{Digest, Sha256};
                                    hex::encode(Sha256::digest(body.as_bytes()))
                                };
                                let sig = serde_json::from_str::<serde_json::Value>(&body)
                                    .ok()
                                    .and_then(|v| {
                                        v.get("signature")
                                            .and_then(|s| s.as_str())
                                            .map(String::from)
                                    });
                                results.push(HubResult {
                                    hub: hub.clone(),
                                    status: "present".to_string(),
                                    body_sha256: Some(body_hash),
                                    signature: sig,
                                    http_status: Some(code.as_u16()),
                                    error: None,
                                });
                            }
                            Err(e) => results.push(HubResult {
                                hub: hub.clone(),
                                status: "error".to_string(),
                                body_sha256: None,
                                signature: None,
                                http_status: Some(code.as_u16()),
                                error: Some(format!("read body: {e}")),
                            }),
                        }
                    }
                    Err(e) => results.push(HubResult {
                        hub: hub.clone(),
                        status: "unreachable".to_string(),
                        body_sha256: None,
                        signature: None,
                        http_status: None,
                        error: Some(format!("{e}")),
                    }),
                }
            }

            // Classify: verified (all present + same signature),
            // split (present but different signatures), partial
            // (some missing), unreachable (network errors).
            let present: Vec<&HubResult> =
                results.iter().filter(|r| r.status == "present").collect();
            let verdict = if present.is_empty() {
                "no-witness".to_string()
            } else if present.len() < results.len() {
                "partial".to_string()
            } else {
                // All present — compare signatures byte-for-byte.
                let first_sig = present[0].signature.as_deref().unwrap_or("");
                let all_match = present
                    .iter()
                    .all(|r| r.signature.as_deref().unwrap_or("") == first_sig);
                if all_match {
                    "verified".to_string()
                } else {
                    "split".to_string()
                }
            };

            if json {
                let payload = json!({
                    "ok": verdict == "verified",
                    "command": "diff-pack.witness-check",
                    "pack_id": pack_id,
                    "verdict": verdict,
                    "hubs": results,
                });
                print_json(&payload);
            } else {
                let glyph = match verdict.as_str() {
                    "verified" => style::ok("witness-check"),
                    _ => style::warn("witness-check"),
                };
                println!("{} {} {} (hubs={})", glyph, pack_id, verdict, hubs.len());
                for r in &results {
                    let detail = match (&r.signature, &r.error) {
                        (Some(s), _) => format!("sig={}...", &s[..16.min(s.len())]),
                        (_, Some(e)) => format!("error: {e}"),
                        _ => String::new(),
                    };
                    println!("  {} {} {}", r.hub, r.status, detail);
                }
            }
        }
    }
}
