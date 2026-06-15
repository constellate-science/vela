//! `cmd_registry` and its handler logic, split out of cli.rs.

use crate::cli::{
    cmd_verify_all, cmd_verify_chain, fail, fail_return, parse_signing_key, print_json,
};
use crate::cli_commands::*;
use colored::Colorize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use vela_edge::incremental_ingest;
use vela_protocol::bundle;
use vela_protocol::cli_style as style;
use vela_protocol::events;
use vela_protocol::repo;
use vela_protocol::sign;

/// Phase S (v0.5): registry CLI — publish/pull a frontier through a
/// signed manifest. Verifiable distribution: any third party can pull
/// and confirm the snapshot and event-log hashes match what the owner
/// signed.
pub(crate) fn cmd_registry(action: RegistryAction) {
    use vela_protocol::registry;
    let default_registry = || -> PathBuf {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home)
            .join(".vela")
            .join("registry")
            .join("entries.json")
    };
    match action {
        RegistryAction::VerifyLog {
            vfr_id,
            hub,
            event,
            pubkey,
            json,
        } => crate::cli_log_verify::cmd_verify_log(
            &vfr_id,
            &hub,
            event.as_deref(),
            pubkey.as_deref(),
            json,
        ),
        RegistryAction::VerifyAll { from, json } => cmd_verify_all(from, json),
        RegistryAction::VerifyChain {
            frontier,
            artifacts,
            json,
        } => cmd_verify_chain(frontier, artifacts, json),
        RegistryAction::Maintainer {
            action,
            vfr_id,
            to,
            maintainer,
            key,
            reason,
            json,
        } => {
            let hub = to.trim_end_matches('/').to_string();
            if action == "list" {
                let url = format!("{hub}/entries/{vfr_id}/maintainers");
                let text = {
                    let u = url.clone();
                    std::thread::spawn(move || -> Result<String, String> {
                        reqwest::blocking::get(&u)
                            .map_err(|e| format!("GET {u}: {e}"))?
                            .text()
                            .map_err(|e| e.to_string())
                    })
                    .join()
                    .unwrap_or_else(|_| fail_return("thread panicked"))
                    .unwrap_or_else(|e| fail_return(&e))
                };
                println!("{text}");
                return;
            }
            if !matches!(action.as_str(), "add" | "remove") {
                fail("action must be add|remove|list");
            }
            let signing_key = crate::cli_identity::resolve_signing_key_opt(key.as_deref())
                .unwrap_or_else(|| {
                    fail_return("add/remove needs a key — pass --key or run `vela id create`")
                });
            let m = maintainer.unwrap_or_else(|| fail_return("--maintainer required"));
            let maintainer_pubkey = if std::path::Path::new(&m).exists() {
                std::fs::read_to_string(&m)
                    .map(|s| s.trim().to_string())
                    .unwrap_or_else(|e| fail_return(&format!("read maintainer key: {e}")))
            } else {
                m.trim().to_string()
            };
            let mut rec = vela_protocol::registry::MaintainerActionRecord {
                schema: vela_protocol::registry::MAINTAINER_ACTION_SCHEMA.to_string(),
                vfr_id: vfr_id.clone(),
                action: action.clone(),
                maintainer_pubkey,
                authorized_at: chrono::Utc::now().to_rfc3339(),
                reason,
                signature: String::new(),
                signer_pubkey_hex: hex::encode(signing_key.verifying_key().to_bytes()),
            };
            rec.signature = vela_protocol::registry::sign_maintainer_action(&rec, &signing_key)
                .unwrap_or_else(|e| fail_return(&format!("sign: {e}")));
            let url = format!("{hub}/entries/{vfr_id}/maintainers");
            let body = serde_json::to_value(&rec)
                .unwrap_or_else(|e| fail_return(&format!("serialize: {e}")));
            let (status, text) = {
                let u = url.clone();
                std::thread::spawn(move || -> Result<(u16, String), String> {
                    let resp = reqwest::blocking::Client::new()
                        .post(&u)
                        .json(&body)
                        .send()
                        .map_err(|e| format!("POST {u}: {e}"))?;
                    Ok((resp.status().as_u16(), resp.text().unwrap_or_default()))
                })
                .join()
                .unwrap_or_else(|_| fail_return("thread panicked"))
                .unwrap_or_else(|e| fail_return(&e))
            };
            let payload: serde_json::Value =
                serde_json::from_str(&text).unwrap_or_else(|_| serde_json::json!({"raw": text}));
            if json {
                print_json(
                    &serde_json::json!({"ok": status < 300, "status": status, "response": payload}),
                );
            } else if status < 300 {
                println!(
                    "{} maintainer {action} recorded on {vfr_id}",
                    style::ok("ok")
                );
            } else {
                fail(&format!("maintainer {action} failed ({status}): {payload}"));
            }
        }
        RegistryAction::RotateOwner {
            vfr_id,
            to,
            key,
            new_owner,
            reason,
            json,
        } => {
            let signing_key = crate::cli_identity::resolve_signing_key(key.as_deref());
            let signer_pubkey = hex::encode(signing_key.verifying_key().to_bytes());
            let new_owner_pubkey = if std::path::Path::new(&new_owner).exists() {
                std::fs::read_to_string(&new_owner)
                    .map(|s| s.trim().to_string())
                    .unwrap_or_else(|e| fail_return(&format!("read new owner key: {e}")))
            } else {
                new_owner.trim().to_string()
            };
            let mut rec = vela_protocol::registry::OwnerRotationRecord {
                schema: vela_protocol::registry::OWNER_ROTATION_SCHEMA.to_string(),
                vfr_id: vfr_id.clone(),
                new_owner_pubkey,
                rotated_at: chrono::Utc::now().to_rfc3339(),
                reason: reason.clone(),
                signature: String::new(),
                signer_pubkey_hex: signer_pubkey,
            };
            rec.signature = vela_protocol::registry::sign_rotation(&rec, &signing_key)
                .unwrap_or_else(|e| fail_return(&format!("sign: {e}")));
            let hub = to.trim_end_matches('/').to_string();
            let url = format!("{hub}/entries/{vfr_id}/rotate-owner");
            let body = serde_json::to_value(&rec)
                .unwrap_or_else(|e| fail_return(&format!("serialize: {e}")));
            let (status, text) = {
                let u = url.clone();
                std::thread::spawn(move || -> Result<(u16, String), String> {
                    let resp = reqwest::blocking::Client::new()
                        .post(&u)
                        .json(&body)
                        .send()
                        .map_err(|e| format!("POST {u}: {e}"))?;
                    let status = resp.status().as_u16();
                    let text = resp.text().map_err(|e| format!("read response: {e}"))?;
                    Ok((status, text))
                })
                .join()
                .unwrap_or_else(|_| fail_return("rotate-owner request thread panicked"))
                .unwrap_or_else(|e| fail_return(&e))
            };
            let payload: serde_json::Value =
                serde_json::from_str(&text).unwrap_or_else(|_| serde_json::json!({"raw": text}));
            if json {
                print_json(&serde_json::json!({
                    "ok": status < 300,
                    "command": "registry.rotate_owner",
                    "vfr_id": vfr_id,
                    "status": status,
                    "response": payload,
                }));
            } else if status < 300 {
                println!(
                    "{} rotated owner of {vfr_id} on {hub} — the successor key is now the effective owner",
                    style::ok("ok")
                );
            } else {
                fail(&format!("rotate-owner failed ({status}): {payload}"));
            }
        }
        RegistryAction::Deprecate {
            vfr_id,
            to,
            key,
            reason,
            json,
        } => {
            let signing_key = crate::cli_identity::resolve_signing_key(key.as_deref());
            let signer_pubkey = hex::encode(signing_key.verifying_key().to_bytes());
            let mut rec = vela_protocol::registry::DeprecationRecord {
                schema: vela_protocol::registry::DEPRECATION_SCHEMA.to_string(),
                vfr_id: vfr_id.clone(),
                deprecated_at: chrono::Utc::now().to_rfc3339(),
                reason: reason.clone(),
                signature: String::new(),
                signer_pubkey_hex: signer_pubkey,
            };
            rec.signature = vela_protocol::registry::sign_deprecation(&rec, &signing_key)
                .unwrap_or_else(|e| fail_return(&format!("sign: {e}")));
            let hub = to.trim_end_matches('/').to_string();
            let url = format!("{hub}/entries/{vfr_id}/deprecate");
            let body = serde_json::to_value(&rec)
                .unwrap_or_else(|e| fail_return(&format!("serialize: {e}")));
            let (status, text) = {
                let u = url.clone();
                std::thread::spawn(move || -> Result<(u16, String), String> {
                    let resp = reqwest::blocking::Client::new()
                        .post(&u)
                        .json(&body)
                        .send()
                        .map_err(|e| format!("POST {u}: {e}"))?;
                    let status = resp.status().as_u16();
                    let text = resp.text().map_err(|e| format!("read response: {e}"))?;
                    Ok((status, text))
                })
                .join()
                .unwrap_or_else(|_| fail_return("deprecate request thread panicked"))
                .unwrap_or_else(|e| fail_return(&e))
            };
            let payload: serde_json::Value =
                serde_json::from_str(&text).unwrap_or_else(|_| serde_json::json!({"raw": text}));
            if json {
                print_json(&serde_json::json!({
                    "ok": status < 300,
                    "command": "registry.deprecate",
                    "vfr_id": vfr_id,
                    "status": status,
                    "response": payload,
                }));
            } else if status < 300 {
                println!(
                    "{} deprecated {vfr_id} on {hub} (auditable at /entries/{vfr_id}/status)",
                    style::ok("ok")
                );
            } else {
                fail(&format!("deprecate failed ({status}): {payload}"));
            }
        }
        RegistryAction::Propose {
            vfr_id,
            to,
            key,
            actor,
            actor_type,
            kind,
            reason,
            payload,
            source_refs,
            caveats,
            json,
        } => {
            // 1. Resolve identity: proposer key + actor + hub fall back to
            //    the configured `vela id` profile when flags are omitted.
            let signing_key = crate::cli_identity::resolve_signing_key(key.as_deref());
            let signer_pubkey = hex::encode(signing_key.verifying_key().to_bytes());
            let actor = crate::cli_identity::resolve_actor(actor.as_deref());
            let to = crate::cli_identity::resolve_hub(to.as_deref());

            // 2. Read the payload (file or `-` for stdin) and parse as JSON.
            let payload_str = if payload.as_os_str() == "-" {
                use std::io::Read;
                let mut s = String::new();
                std::io::stdin()
                    .read_to_string(&mut s)
                    .unwrap_or_else(|e| fail_return(&format!("read stdin payload: {e}")));
                s
            } else {
                std::fs::read_to_string(&payload).unwrap_or_else(|e| {
                    fail_return(&format!("read payload {}: {e}", payload.display()))
                })
            };
            let payload_value: Value = serde_json::from_str(payload_str.trim())
                .unwrap_or_else(|e| fail_return(&format!("payload is not valid JSON: {e}")));

            // 3. Build the proposal with the protocol's own constructor so the
            //    content-addressed id AND the signed preimage match exactly
            //    what the hub recomputes and verifies (no drift possible).
            let target = events::StateTarget {
                r#type: "frontier".to_string(),
                id: vfr_id.clone(),
            };
            let proposal = vela_protocol::proposals::new_proposal(
                kind,
                target,
                actor.clone(),
                actor_type,
                reason,
                payload_value,
                source_refs,
                caveats,
            );
            let signature_hex = sign::sign_proposal(&proposal, &signing_key)
                .unwrap_or_else(|e| fail_return(&format!("sign proposal: {e}")));

            // 4. POST to the OPEN submission endpoint. Body = the serialized
            //    proposal; the signature rides in headers so the body stays
            //    byte-equal to the canonical preimage the hub re-derives.
            let hub = to.trim_end_matches('/').to_string();
            let url = format!("{hub}/entries/{vfr_id}/proposals");
            let body = serde_json::to_value(&proposal)
                .unwrap_or_else(|e| fail_return(&format!("serialize proposal: {e}")));
            let (status, text) = {
                let u = url.clone();
                let pk = signer_pubkey.clone();
                let sig = signature_hex.clone();
                std::thread::spawn(move || -> Result<(u16, String), String> {
                    let resp = reqwest::blocking::Client::new()
                        .post(&u)
                        .header("X-Vela-Signer-Pubkey", &pk)
                        .header("X-Vela-Signature", &sig)
                        .json(&body)
                        .send()
                        .map_err(|e| format!("POST {u}: {e}"))?;
                    let s = resp.status().as_u16();
                    Ok((s, resp.text().unwrap_or_default()))
                })
                .join()
                .map_err(|_| "propose thread panicked".to_string())
                .and_then(|r| r)
                .unwrap_or_else(|e| fail_return(&e))
            };

            let ok = status == 200 || status == 202;
            let hub_response =
                serde_json::from_str::<Value>(&text).unwrap_or(Value::String(text.clone()));
            let payload_out = json!({
                "ok": ok,
                "command": "registry.propose",
                "vfr_id": vfr_id.clone(),
                "hub": hub.clone(),
                "proposal_id": proposal.id.clone(),
                "actor": actor.clone(),
                "signer_pubkey": signer_pubkey.clone(),
                "http_status": status,
                "hub_response": hub_response,
            });
            if json {
                print_json(&payload_out);
            } else if ok {
                println!(
                    "{} proposed {} to {vfr_id} on {hub} (HTTP {status})",
                    style::ok("registry"),
                    proposal.id
                );
                println!("  signer:  {} ({}…)", actor, &signer_pubkey[..16]);
                println!("  status:  enqueued to pending_review");
                println!(
                    "  next:    a registered reviewer accepts via \
                     POST /entries/{vfr_id}/proposals/{}/accept",
                    proposal.id
                );
            } else {
                fail_return::<()>(&format!("hub rejected proposal (HTTP {status}): {text}"));
            }
        }
        RegistryAction::WitnessCheck { vfr_id, hubs, json } => {
            // v0.129: A11 mitigation. Pull `vfr_id` from every named
            // hub, canonicalize each entry, compare. Reports per-hub
            // canonical hash plus consensus signal:
            //   `unanimous`  — every hub returned byte-identical
            //                   canonical bytes.
            //   `majority`   — most hubs agree; some diverge.
            //   `split`      — no hub has a majority.
            //   `insufficient` — fewer than 2 hubs responded.
            if hubs.len() < 2 {
                fail("--hubs requires at least two hub URLs (comma-separated).");
            }
            let client = reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_else(|e| fail_return(&format!("http client init: {e}")));

            #[derive(serde::Serialize)]
            struct HubResponse {
                hub: String,
                status: String,
                #[serde(skip_serializing_if = "Option::is_none")]
                canonical_hash: Option<String>,
                #[serde(skip_serializing_if = "Option::is_none")]
                note: Option<String>,
            }

            let mut responses: Vec<HubResponse> = Vec::new();
            let mut hash_counts: std::collections::BTreeMap<String, usize> =
                std::collections::BTreeMap::new();

            for hub_url in &hubs {
                let base = hub_url.trim_end_matches('/');
                let url = format!("{base}/entries/{vfr_id}");
                match client.get(&url).send() {
                    Ok(resp) if resp.status().is_success() => {
                        match resp.json::<serde_json::Value>() {
                            Ok(entry) => {
                                // Canonicalize via the substrate's
                                // canonical-bytes helper so hub-side
                                // key ordering or whitespace
                                // differences do not falsely split.
                                let canonical =
                                    vela_protocol::canonical::to_canonical_bytes(&entry)
                                        .unwrap_or_else(|e| {
                                            fail_return(&format!("canonicalize: {e}"))
                                        });
                                let hash =
                                    format!("sha256:{}", hex::encode(Sha256::digest(&canonical)));
                                *hash_counts.entry(hash.clone()).or_insert(0) += 1;
                                responses.push(HubResponse {
                                    hub: base.to_string(),
                                    status: "ok".to_string(),
                                    canonical_hash: Some(hash),
                                    note: None,
                                });
                            }
                            Err(e) => responses.push(HubResponse {
                                hub: base.to_string(),
                                status: "parse_error".to_string(),
                                canonical_hash: None,
                                note: Some(format!("parse: {e}")),
                            }),
                        }
                    }
                    Ok(resp) => responses.push(HubResponse {
                        hub: base.to_string(),
                        status: "http_error".to_string(),
                        canonical_hash: None,
                        note: Some(format!("HTTP {}", resp.status())),
                    }),
                    Err(e) => responses.push(HubResponse {
                        hub: base.to_string(),
                        status: "unreachable".to_string(),
                        canonical_hash: None,
                        note: Some(format!("{e}")),
                    }),
                }
            }

            // Consensus signal.
            let resolved_count = responses
                .iter()
                .filter(|r| r.canonical_hash.is_some())
                .count();
            let consensus = if resolved_count < 2 {
                "insufficient".to_string()
            } else if hash_counts.len() == 1 {
                "unanimous".to_string()
            } else {
                let max = hash_counts.values().copied().max().unwrap_or(0);
                if max * 2 > resolved_count {
                    "majority".to_string()
                } else {
                    "split".to_string()
                }
            };

            let payload = json!({
                "ok": consensus == "unanimous" || consensus == "majority",
                "command": "registry.witness-check",
                "vfr_id": vfr_id,
                "hubs_queried": hubs.len(),
                "hubs_resolved": resolved_count,
                "distinct_canonical_hashes": hash_counts.len(),
                "consensus": consensus,
                "responses": responses,
            });

            if json {
                print_json(&payload);
            } else {
                println!(
                    "{} witness-check {} across {} hub(s): {}",
                    style::ok("registry"),
                    vfr_id,
                    hubs.len(),
                    consensus
                );
                for r in &responses {
                    let hash_display = r
                        .canonical_hash
                        .as_deref()
                        .map(|h| h.chars().take(16).collect::<String>())
                        .unwrap_or_else(|| r.note.clone().unwrap_or_default());
                    println!("  {} {} {hash_display}", r.status, r.hub);
                }
            }
            if consensus == "split" {
                std::process::exit(1);
            }
        }
        RegistryAction::List { from, json } => {
            // Phase γ-hub (v0.7): `--from <https://...>` fetches the
            // registry over HTTPS; bare paths and file:// resolve locally.
            let (label, registry_data) = match &from {
                Some(loc) if loc.starts_with("http") => (
                    loc.clone(),
                    registry::load_any(loc).unwrap_or_else(|e| fail_return(&e)),
                ),
                Some(loc) => {
                    let p = registry::resolve_local(loc).unwrap_or_else(|e| fail_return(&e));
                    (
                        p.display().to_string(),
                        registry::load_local(&p).unwrap_or_else(|e| fail_return(&e)),
                    )
                }
                None => {
                    let p = default_registry();
                    (
                        p.display().to_string(),
                        registry::load_local(&p).unwrap_or_else(|e| fail_return(&e)),
                    )
                }
            };
            let r = registry_data;
            let path_label = label;
            if json {
                let payload = json!({
                    "ok": true,
                    "command": "registry.list",
                    "registry": path_label,
                    "entry_count": r.entries.len(),
                    "entries": r.entries,
                });
                print_json(&payload);
            } else {
                println!();
                println!(
                    "  {}",
                    format!("VELA · REGISTRY · LIST · {}", path_label)
                        .to_uppercase()
                        .dimmed()
                );
                println!("  {}", style::tick_row(60));
                if r.entries.is_empty() {
                    println!("  (registry is empty)");
                } else {
                    for entry in &r.entries {
                        println!(
                            "  {} {} ({})  by {}  published {}",
                            entry.vfr_id,
                            entry.name,
                            entry.network_locator,
                            entry.owner_actor_id,
                            entry.signed_publish_at
                        );
                    }
                }
            }
        }
        RegistryAction::Append {
            frontier,
            to,
            key,
            limit,
            json,
        } => {
            let signing_key = crate::cli_identity::resolve_signing_key(key.as_deref());
            let signer_pubkey = hex::encode(signing_key.verifying_key().to_bytes());
            let to = crate::cli_identity::resolve_hub(to.as_deref());

            let project = repo::load_from_path(&frontier).unwrap_or_else(|e| fail_return(&e));
            let vfr = project.frontier_id();
            let hub = to.trim_end_matches('/').to_string();

            // 1. The hub's current event-log tail is the optimistic-concurrency
            //    parent. Fetch it from the registry entry.
            let entry_url = format!("{hub}/entries/{vfr}");
            let parent_hash = {
                let u = entry_url.clone();
                std::thread::spawn(move || -> Result<String, String> {
                    let resp = reqwest::blocking::Client::new()
                        .get(&u)
                        .send()
                        .map_err(|e| format!("GET {u}: {e}"))?;
                    if !resp.status().is_success() {
                        return Err(format!("hub returned {} for {u}", resp.status().as_u16()));
                    }
                    let v: Value = resp.json().map_err(|e| format!("parse entry: {e}"))?;
                    v.get("latest_event_log_hash")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                        .ok_or_else(|| "entry missing latest_event_log_hash".to_string())
                })
                .join()
                .map_err(|_| "fetch thread panicked".to_string())
                .and_then(|r| r)
                .unwrap_or_else(|e| fail_return(&e))
            };

            // 2. Delta: the local event prefix whose hash equals the hub's tail;
            //    everything after it is new. A miss means local history has
            //    diverged from the hub (rebuild or re-publish first).
            let mut base: Option<usize> = None;
            for k in 0..=project.events.len() {
                if events::event_log_hash(&project.events[..k]) == parent_hash {
                    base = Some(k);
                    break;
                }
            }
            let base = base.unwrap_or_else(|| {
                fail_return(&format!(
                    "local frontier diverged from the hub: no event prefix matches the hub tail \
                     {parent_hash}. Re-pull or full-publish first."
                ))
            });
            let mut new_events: Vec<events::StateEvent> = project.events[base..].to_vec();
            if limit > 0 && new_events.len() > limit {
                new_events.truncate(limit);
            }
            if new_events.is_empty() {
                let msg = json!({"ok": true, "command": "registry-append", "vfr_id": vfr,
                    "appended": 0, "note": "hub is already up to date"});
                println!(
                    "{}",
                    if json {
                        msg.to_string()
                    } else {
                        format!("{} hub already up to date ({vfr})", style::ok("ok"))
                    }
                );
                return;
            }

            // 3. Pair each finding.asserted event with its finding; the rest go
            //    as event-only records.
            let finding_by_id: std::collections::HashMap<&str, &bundle::FindingBundle> = project
                .findings
                .iter()
                .map(|f| (f.id.as_str(), f))
                .collect();
            let batch: Vec<incremental_ingest::AppendRecord> = new_events
                .iter()
                .map(|e| {
                    let paired = (e.kind == "finding.asserted")
                        .then(|| finding_by_id.get(e.target.id.as_str()))
                        .flatten();
                    match paired {
                        Some(f) => incremental_ingest::AppendRecord::Finding {
                            finding: Box::new((*f).clone()),
                            event: Box::new(e.clone()),
                        },
                        None => incremental_ingest::AppendRecord::EventOnly {
                            event: Box::new(e.clone()),
                        },
                    }
                })
                .collect();

            // 4. Sign the preimage EXACTLY as the hub reconstructs it: a json!
            //    object over {action, vfr_id, parent_event_log_hash, batch}.
            let batch_value = serde_json::to_value(&batch)
                .unwrap_or_else(|e| fail_return(&format!("serialize batch: {e}")));
            let preimage = json!({
                "action": "append",
                "vfr_id": vfr,
                "parent_event_log_hash": parent_hash,
                "batch": batch_value,
            });
            let preimage_bytes = serde_json::to_vec(&preimage)
                .unwrap_or_else(|e| fail_return(&format!("preimage: {e}")));
            let signature_hex =
                hex::encode(ed25519_dalek::Signer::sign(&signing_key, &preimage_bytes).to_bytes());

            // 5. POST to the append endpoint.
            let append_url = format!("{hub}/entries/{vfr}/append");
            let body = json!({"parent_event_log_hash": parent_hash, "batch": batch_value});
            let (status, text) = {
                let u = append_url.clone();
                let pk = signer_pubkey.clone();
                let sig = signature_hex.clone();
                std::thread::spawn(move || -> Result<(u16, String), String> {
                    let resp = reqwest::blocking::Client::new()
                        .post(&u)
                        .header("X-Vela-Signer-Pubkey", &pk)
                        .header("X-Vela-Signature", &sig)
                        .json(&body)
                        .send()
                        .map_err(|e| format!("POST {u}: {e}"))?;
                    let s = resp.status().as_u16();
                    Ok((s, resp.text().unwrap_or_default()))
                })
                .join()
                .map_err(|_| "append thread panicked".to_string())
                .and_then(|r| r)
                .unwrap_or_else(|e| fail_return(&e))
            };

            if status == 200 {
                if json {
                    println!("{text}");
                } else {
                    println!(
                        "{} appended {} record(s) to {vfr} on {hub}",
                        style::ok("ok"),
                        new_events.len()
                    );
                    println!("  {text}");
                }
            } else if status == 409 {
                fail_return::<()>(&format!(
                    "conflict (409): the hub tail moved under us — re-run to pick up the new \
                     parent. {text}"
                ));
            } else {
                fail_return::<()>(&format!("hub rejected append (HTTP {status}): {text}"));
            }
        }

        RegistryAction::Publish {
            frontier,
            owner,
            key,
            locator,
            to,
            license,
            json,
        } => {
            // Resolve identity: owner + key fall back to the configured
            // `vela id` profile when the flags are omitted.
            let owner = crate::cli_identity::resolve_actor(owner.as_deref());
            let signing_key = crate::cli_identity::resolve_signing_key(key.as_deref());
            let derived = hex::encode(signing_key.verifying_key().to_bytes());

            // Load frontier and look up (or auto-register) the owner.
            let mut frontier_data =
                repo::load_from_path(&frontier).unwrap_or_else(|e| fail_return(&e));

            let pubkey = match frontier_data.actors.iter().find(|actor| actor.id == owner) {
                Some(actor) => actor.public_key.clone(),
                None => {
                    // v0.101 auto-bootstrap, v0.339 made read-only: an
                    // unregistered owner who supplies a valid private key is
                    // registered on the *in-memory* frontier for this publish
                    // — enough to sign and hash the manifest — but the on-disk
                    // frontier is NEVER rewritten. Publish is a read-only
                    // operation with respect to the corpus: a read operation
                    // must not migrate-and-rewrite canonical files. To persist
                    // the actor durably, run `vela actor add` explicitly.
                    eprintln!(
                        "  vela registry publish · registering actor {owner} for this publish only \
                         (derived pubkey {}); the on-disk frontier is left untouched. Run \
                         `vela actor add` to register it durably.",
                        &derived[..16]
                    );
                    frontier_data.actors.push(sign::ActorRecord {
                        id: owner.clone(),
                        public_key: derived.clone(),
                        algorithm: "ed25519".to_string(),
                        created_at: chrono::Utc::now().to_rfc3339(),
                        tier: None,
                        orcid: None,
                        access_clearance: None,
                        revoked_at: None,
                        revoked_reason: None,
                    });
                    derived.clone()
                }
            };

            // Compute snapshot+event_log hashes over the in-memory frontier
            // (including any in-memory owner registration above) so the
            // published manifest matches the inline substrate the hub re-hashes.
            let snapshot_hash = events::snapshot_hash(&frontier_data);
            let event_log_hash = events::event_log_hash(&frontier_data.events);
            let vfr_id = frontier_data.frontier_id();
            let name = frontier_data.project.name.clone();

            // Sanity check: pubkey on disk matches pubkey in the registry.
            if derived != pubkey {
                fail(&format!(
                    "private key does not match registered pubkey for owner '{owner}'"
                ));
            }

            // Phase A2 (v0.7): when `--to` is an HTTPS URL we POST the
            // signed entry to a hub; otherwise we resolve a local file
            // and append. v0.55: the locator can be auto-filled when
            // publishing to a remote hub: the hub's own
            // `/entries/<vfr>/snapshot` endpoint is the canonical fetch
            // location once substrate is promoted into event/projection
            // tables.
            let to_is_remote = matches!(
                to.as_deref(),
                Some(loc) if loc.starts_with("http://") || loc.starts_with("https://")
            );
            let resolved_locator = match locator {
                Some(l) => l,
                None => {
                    if to_is_remote {
                        let hub = to.as_deref().unwrap().trim_end_matches('/');
                        let hub_root = hub.trim_end_matches("/entries");
                        format!("{hub_root}/entries/{vfr_id}/snapshot")
                    } else {
                        fail_return(
                            "--locator is required for local publishes; pass e.g. \
                             --locator file:///path/to/frontier.json or an HTTPS URL.",
                        )
                    }
                }
            };

            let mut entry = registry::RegistryEntry {
                schema: registry::ENTRY_SCHEMA.to_string(),
                vfr_id: vfr_id.clone(),
                name: name.clone(),
                owner_actor_id: owner.clone(),
                owner_pubkey: pubkey,
                latest_snapshot_hash: snapshot_hash,
                latest_event_log_hash: event_log_hash,
                network_locator: resolved_locator,
                license: license.clone(),
                signed_publish_at: chrono::Utc::now().to_rfc3339(),
                signature: String::new(),
            };
            entry.signature =
                registry::sign_entry(&entry, &signing_key).unwrap_or_else(|e| fail_return(&e));

            let (registry_label, duplicate) = if to_is_remote {
                let hub_url = to.clone().unwrap();
                // v0.55: include the substrate inline so the hub can
                // verify hashes, store the snapshot export, and promote
                // event/projection rows for live reads.
                let resp = registry::publish_remote(&entry, &hub_url, Some(&frontier_data))
                    .unwrap_or_else(|e| fail_return(&e));
                (hub_url, resp.duplicate)
            } else {
                let registry_path = match &to {
                    Some(loc) => registry::resolve_local(loc).unwrap_or_else(|e| fail_return(&e)),
                    None => default_registry(),
                };
                registry::publish_entry(&registry_path, entry.clone())
                    .unwrap_or_else(|e| fail_return(&e));
                (registry_path.display().to_string(), false)
            };

            let payload = json!({
                "ok": true,
                "command": "registry.publish",
                "registry": registry_label,
                "vfr_id": vfr_id,
                "name": name,
                "owner": owner,
                "snapshot_hash": entry.latest_snapshot_hash,
                "event_log_hash": entry.latest_event_log_hash,
                "signed_publish_at": entry.signed_publish_at,
                "signature": entry.signature,
                "duplicate": duplicate,
            });
            if json {
                print_json(&payload);
            } else {
                let dup_suffix = if duplicate { " (duplicate, no-op)" } else { "" };
                println!(
                    "{} published {vfr_id} → {}{}",
                    style::ok("registry"),
                    registry_label,
                    dup_suffix
                );
                println!("  snapshot:  {}", entry.latest_snapshot_hash);
                println!("  event_log: {}", entry.latest_event_log_hash);
                println!("  signature: {}…", &entry.signature[..16]);
            }
        }
        RegistryAction::OwnerRotate {
            frontier,
            current_owner,
            new_owner,
            new_key,
            reason,
            locator,
            to,
            json,
        } => {
            if reason.trim().is_empty() {
                fail("--reason must be non-empty (record why the rotation is happening).");
            }
            if current_owner == new_owner {
                fail(
                    "--current-owner and --new-owner must differ; rotation registers a fresh owner actor record.",
                );
            }

            // Read and parse the new owner's private key first so
            // we can derive the new pubkey before we mutate the
            // frontier.
            let key_hex = std::fs::read_to_string(&new_key)
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|e| {
                    fail_return(&format!("read new key {}: {e}", new_key.display()))
                });
            let signing_key = parse_signing_key(&key_hex);
            let derived = hex::encode(signing_key.verifying_key().to_bytes());

            let mut frontier_data =
                repo::load_from_path(&frontier).unwrap_or_else(|e| fail_return(&e));

            // Revoke the current owner. Must exist and not already be revoked.
            let now = chrono::Utc::now().to_rfc3339();
            let mut retired_pubkey_prefix: Option<String> = None;
            let mut found_current = false;
            for actor in frontier_data.actors.iter_mut() {
                if actor.id == current_owner {
                    if actor.revoked_at.is_some() {
                        fail(&format!(
                            "Refusing to rotate: actor '{current_owner}' is already revoked at {}.",
                            actor.revoked_at.as_deref().unwrap_or("?")
                        ));
                    }
                    actor.revoked_at = Some(now.clone());
                    actor.revoked_reason = Some(reason.clone());
                    retired_pubkey_prefix = Some(actor.public_key[..16].to_string());
                    found_current = true;
                }
            }
            if !found_current {
                fail(&format!(
                    "Cannot rotate: actor '{current_owner}' is not registered in this frontier."
                ));
            }

            // Register the new owner actor record. Auto-bootstrap
            // if the id is not already present (mirrors the publish
            // auto-registration path from v0.101). If it IS already
            // present, the pubkey must match the derived pubkey.
            let new_pubkey = match frontier_data.actors.iter().find(|a| a.id == new_owner) {
                Some(existing) => {
                    if existing.revoked_at.is_some() {
                        fail(&format!(
                            "Refusing to rotate: target actor '{new_owner}' is already revoked at {}.",
                            existing.revoked_at.as_deref().unwrap_or("?")
                        ));
                    }
                    if existing.public_key != derived {
                        fail(&format!(
                            "private key does not match registered pubkey for new owner '{new_owner}'"
                        ));
                    }
                    existing.public_key.clone()
                }
                None => {
                    frontier_data.actors.push(sign::ActorRecord {
                        id: new_owner.clone(),
                        public_key: derived.clone(),
                        algorithm: "ed25519".to_string(),
                        created_at: now.clone(),
                        tier: None,
                        orcid: None,
                        access_clearance: None,
                        revoked_at: None,
                        revoked_reason: None,
                    });
                    derived.clone()
                }
            };

            repo::save_to_path(&frontier, &frontier_data)
                .unwrap_or_else(|e| fail_return(&format!("save rotation: {e}")));

            // Re-publish under the new owner credentials. Mirrors
            // the RegistryAction::Publish path verbatim so the hub
            // sees a normal signed entry under the new pubkey.
            let snapshot_hash = events::snapshot_hash(&frontier_data);
            let event_log_hash = events::event_log_hash(&frontier_data.events);
            let vfr_id = frontier_data.frontier_id();
            let name = frontier_data.project.name.clone();

            let to_is_remote = matches!(
                to.as_deref(),
                Some(loc) if loc.starts_with("http://") || loc.starts_with("https://")
            );
            let resolved_locator = match locator {
                Some(l) => l,
                None => {
                    if to_is_remote {
                        let hub = to.as_deref().unwrap().trim_end_matches('/');
                        let hub_root = hub.trim_end_matches("/entries");
                        format!("{hub_root}/entries/{vfr_id}/snapshot")
                    } else {
                        fail_return(
                            "--locator is required for local publishes; pass e.g. \
                             --locator file:///path/to/frontier.json or an HTTPS URL.",
                        )
                    }
                }
            };

            let mut entry = registry::RegistryEntry {
                schema: registry::ENTRY_SCHEMA.to_string(),
                vfr_id: vfr_id.clone(),
                name: name.clone(),
                owner_actor_id: new_owner.clone(),
                owner_pubkey: new_pubkey,
                latest_snapshot_hash: snapshot_hash,
                latest_event_log_hash: event_log_hash,
                network_locator: resolved_locator,
                license: None,
                signed_publish_at: chrono::Utc::now().to_rfc3339(),
                signature: String::new(),
            };
            entry.signature =
                registry::sign_entry(&entry, &signing_key).unwrap_or_else(|e| fail_return(&e));

            let (registry_label, duplicate) = if to_is_remote {
                let hub_url = to.clone().unwrap();
                let resp = registry::publish_remote(&entry, &hub_url, Some(&frontier_data))
                    .unwrap_or_else(|e| fail_return(&e));
                (hub_url, resp.duplicate)
            } else {
                let registry_path = match &to {
                    Some(loc) => registry::resolve_local(loc).unwrap_or_else(|e| fail_return(&e)),
                    None => default_registry(),
                };
                registry::publish_entry(&registry_path, entry.clone())
                    .unwrap_or_else(|e| fail_return(&e));
                (registry_path.display().to_string(), false)
            };

            let payload = json!({
                "ok": true,
                "command": "registry.owner_rotate",
                "registry": registry_label,
                "vfr_id": vfr_id,
                "name": name,
                "retired_owner": current_owner,
                "retired_pubkey_prefix": retired_pubkey_prefix,
                "new_owner": new_owner,
                "new_pubkey": derived,
                "revoked_at": now,
                "reason": reason,
                "snapshot_hash": entry.latest_snapshot_hash,
                "event_log_hash": entry.latest_event_log_hash,
                "signed_publish_at": entry.signed_publish_at,
                "signature": entry.signature,
                "duplicate": duplicate,
            });
            if json {
                print_json(&payload);
            } else {
                println!(
                    "{} owner rotated: {} (pubkey {}...) retired, {} (pubkey {}...) active",
                    style::ok("registry"),
                    current_owner,
                    retired_pubkey_prefix.as_deref().unwrap_or("?"),
                    new_owner,
                    &derived[..16]
                );
                println!("  revoked_at: {now}");
                println!("  reason:     {reason}");
                let dup_suffix = if duplicate { " (duplicate, no-op)" } else { "" };
                println!("  registry:   {vfr_id} → {registry_label}{dup_suffix}");
                println!("  signature:  {}…", &entry.signature[..16]);
            }
        }
        RegistryAction::Pull {
            vfr_id,
            from,
            out,
            transitive,
            depth,
            json,
        } => {
            // Phase γ-hub (v0.7): both the registry and the frontier
            // can live behind https:// now. Local file:// and bare-path
            // remain supported.
            let (registry_label, registry_data) = match &from {
                Some(loc) if loc.starts_with("http") => (
                    loc.clone(),
                    registry::load_any(loc).unwrap_or_else(|e| fail_return(&e)),
                ),
                Some(loc) => {
                    let p = registry::resolve_local(loc).unwrap_or_else(|e| fail_return(&e));
                    (
                        p.display().to_string(),
                        registry::load_local(&p).unwrap_or_else(|e| fail_return(&e)),
                    )
                }
                None => {
                    let p = default_registry();
                    (
                        p.display().to_string(),
                        registry::load_local(&p).unwrap_or_else(|e| fail_return(&e)),
                    )
                }
            };
            let entry = registry::find_latest(&registry_data, &vfr_id)
                .unwrap_or_else(|| fail_return(&format!("{vfr_id} not found in registry")));

            if transitive {
                // v0.8: --transitive walks the dep graph. `out` is
                // interpreted as a directory; the primary lands at
                // out/<vfr>.json, deps at out/<dep_vfr>.json.
                let result = registry::pull_transitive(&registry_data, &vfr_id, &out, depth)
                    .unwrap_or_else(|e| fail_return(&format!("transitive pull failed: {e}")));

                let dep_paths_json: serde_json::Value = serde_json::Value::Object(
                    result
                        .deps
                        .iter()
                        .map(|(k, v)| (k.clone(), serde_json::json!(v.display().to_string())))
                        .collect(),
                );
                let payload = json!({
                    "ok": true,
                    "command": "registry.pull",
                    "registry": registry_label,
                    "vfr_id": vfr_id,
                    "transitive": true,
                    "depth": depth,
                    "out_dir": out.display().to_string(),
                    "primary": result.primary_path.display().to_string(),
                    "verified": result.verified,
                    "deps": dep_paths_json,
                });
                if json {
                    print_json(&payload);
                } else {
                    println!(
                        "{} pulled {vfr_id} (transitive) → {}",
                        style::ok("registry"),
                        out.display()
                    );
                    println!("  verified {} frontier(s):", result.verified.len());
                    for v in &result.verified {
                        println!("    · {v}");
                    }
                    println!("  every cross-frontier dependency's pinned snapshot hash matched");
                }
                return;
            }

            // Fetch the frontier from its locator (file:// or https://)
            // and verify hashes + signature.
            registry::fetch_frontier_to_prefer_event_hub(&entry, from.as_deref(), &out)
                .unwrap_or_else(|e| fail_return(&format!("fetch frontier: {e}")));
            registry::verify_pull(&entry, &out).unwrap_or_else(|e| {
                let _ = std::fs::remove_file(&out);
                fail_return(&format!("pull verification failed: {e}"))
            });

            let payload = json!({
                "ok": true,
                "command": "registry.pull",
                "registry": registry_label,
                "vfr_id": vfr_id,
                "out": out.display().to_string(),
                "snapshot_hash": entry.latest_snapshot_hash,
                "event_log_hash": entry.latest_event_log_hash,
                "verified": true,
            });
            if json {
                print_json(&payload);
            } else {
                println!(
                    "{} pulled {vfr_id} → {}",
                    style::ok("registry"),
                    out.display()
                );
                println!("  verified snapshot+event_log hashes match registry; signature ok");
            }
        }
    }
}
