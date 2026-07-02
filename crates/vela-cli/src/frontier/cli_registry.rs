//! `cmd_registry` and its handler logic, split out of cli.rs.

use crate::cli::{cmd_verify_chain, fail, fail_return, print_json};
use crate::cli_commands::*;
use serde_json::json;
use sha2::{Digest, Sha256};
use vela_protocol::cli_style as style;

/// Phase S (v0.5): registry CLI — publish/pull a frontier through a
/// The registry surface after the ADR 0001 Phase 2 transport cut: index
/// reads, transparency-log verification, and the one owner-signed act —
/// binding a frontier's git remote. Publication itself is `git push`.
pub(crate) fn cmd_registry(action: RegistryAction) {
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
        RegistryAction::VerifyChain {
            frontier,
            artifacts,
            json,
        } => cmd_verify_chain(frontier, artifacts, json),
        RegistryAction::RegisterGit {
            vfr_id,
            remote,
            r#ref,
            subdir,
            to,
            key,
            json,
        } => {
            let signing_key = crate::cli_identity::resolve_signing_key(key.as_deref());
            let signer_pubkey = hex::encode(signing_key.verifying_key().to_bytes());
            let mut rec = vela_protocol::registry::GitRemoteRegistration {
                schema: vela_protocol::registry::GIT_REMOTE_SCHEMA.to_string(),
                vfr_id: vfr_id.clone(),
                git_remote: remote.clone(),
                git_ref: r#ref.clone(),
                git_subdir: subdir.clone(),
                registered_at: chrono::Utc::now().to_rfc3339(),
                signature: String::new(),
                signer_pubkey_hex: signer_pubkey,
            };
            rec.signature = vela_protocol::registry::sign_git_remote(&rec, &signing_key)
                .unwrap_or_else(|e| fail_return(&format!("sign: {e}")));
            let hub = crate::cli_identity::resolve_hub(to.as_deref())
                .trim_end_matches('/')
                .to_string();
            let url = format!("{hub}/entries/{vfr_id}/git-remote");
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
                .unwrap_or_else(|_| fail_return("register-git request thread panicked"))
                .unwrap_or_else(|e| fail_return(&e))
            };
            let payload: serde_json::Value =
                serde_json::from_str(&text).unwrap_or_else(|_| serde_json::json!({"raw": text}));
            if json {
                print_json(&serde_json::json!({
                    "ok": status < 300,
                    "command": "registry.register-git",
                    "vfr_id": vfr_id,
                    "git_remote": remote,
                    "status": status,
                    "response": payload,
                }));
            } else if status < 300 {
                println!(
                    "{} registered {vfr_id} -> {remote} on {hub}; git push is now publication \
                     (the hub re-derives the index on its next ingest sweep)",
                    style::ok("ok")
                );
            } else {
                fail(&format!("register-git failed ({status}): {payload}"));
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
    }
}
