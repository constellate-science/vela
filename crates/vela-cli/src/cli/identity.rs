//! Identity and signing helpers: `vela id` keygen/sign, signing-key
//! parsing, queued-action confirmation and sign-and-apply. Moved verbatim
//! from `cli/mod.rs`.

use super::*;

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
