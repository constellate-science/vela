//! `cmd_owner_rotate_governed` and its handler logic, split out of cli.rs.

use crate::cli::{
    FrontierRevocation, default_registry_path, fail, fail_return, governance_chain_path,
    parse_signing_key, print_json,
};
use crate::cli_commands::*;
use vela_protocol::cli_style as style;
use vela_protocol::events;
use vela_protocol::repo;
use vela_protocol::sign;
use serde_json::json;

/// v0.145: handle `vela registry owner-rotate-governed {propose|attest|apply}`.
pub(crate) fn cmd_owner_rotate_governed(action: OwnerRotateGovernedAction) {
    use vela_edge::governance::{
        AttestationEntry, GovernancePolicy, OwnerRotateAttestationBundle, OwnerRotateProposal,
        ProposalDraft, verify_quorum,
    };
    use vela_protocol::registry;
    use ed25519_dalek::Signer;

    match action {
        OwnerRotateGovernedAction::Propose {
            frontier,
            old_owner,
            new_owner,
            new_pubkey_hex,
            target_epoch,
            previous_entry_hash,
            policy,
            reason,
            ttl_hours,
            out,
            json,
        } => {
            if target_epoch == 0 {
                fail("--target-epoch must be >= 1; the first governed rotation produces epoch 1.");
            }
            if new_pubkey_hex.len() != 64 || hex::decode(&new_pubkey_hex).is_err() {
                fail("--new-pubkey-hex must be 64 hex chars (32-byte Ed25519 pubkey).");
            }
            let frontier_data = repo::load_from_path(&frontier).unwrap_or_else(|e| fail_return(&e));
            let frontier_id = frontier_data.frontier_id().to_string();

            let policy_raw = std::fs::read_to_string(&policy)
                .unwrap_or_else(|e| fail_return(&format!("read policy: {e}")));
            let policy_obj: GovernancePolicy = serde_json::from_str(&policy_raw)
                .unwrap_or_else(|e| fail_return(&format!("parse policy: {e}")));
            policy_obj
                .verify_content_address()
                .unwrap_or_else(|e| fail_return(&e));

            let old_actor = frontier_data
                .actors
                .iter()
                .find(|a| a.id == old_owner)
                .unwrap_or_else(|| {
                    fail_return(&format!(
                        "old owner `{old_owner}` is not registered in the frontier"
                    ))
                });
            let old_pubkey = old_actor.public_key.clone();

            let now = chrono::Utc::now();
            let expires = now + chrono::Duration::hours(i64::from(ttl_hours));

            let draft = ProposalDraft {
                frontier_id,
                old_owner_actor_id: old_owner,
                old_owner_pubkey: old_pubkey,
                new_owner_actor_id: new_owner,
                new_owner_pubkey: new_pubkey_hex,
                owner_epoch: target_epoch,
                previous_registry_entry_hash: previous_entry_hash,
                governance_policy_id: policy_obj.policy_id.clone(),
                reason,
                created_at: now.to_rfc3339(),
                expires_at: expires.to_rfc3339(),
                nonce: hex::encode(rand::random::<[u8; 8]>()),
            };
            let proposal =
                OwnerRotateProposal::from_draft(draft).unwrap_or_else(|e| fail_return(&e));

            let body =
                serde_json::to_string_pretty(&proposal).expect("serialize owner-rotate proposal");
            std::fs::write(&out, format!("{body}\n"))
                .unwrap_or_else(|e| fail_return(&format!("write {}: {e}", out.display())));

            let preimage_hash = proposal.preimage_hash().unwrap_or_else(|e| fail_return(&e));
            if json {
                let payload = json!({
                    "ok": true,
                    "command": "registry.owner-rotate-governed.propose",
                    "proposal_id": proposal.proposal_id,
                    "frontier_id": proposal.frontier_id,
                    "target_epoch": proposal.owner_epoch,
                    "governance_policy_id": proposal.governance_policy_id,
                    "proposal_preimage_hash": preimage_hash,
                    "expires_at": proposal.expires_at,
                    "out": out.display().to_string(),
                });
                print_json(&payload);
            } else {
                println!(
                    "{} proposed owner rotation: {} (target epoch {})",
                    style::ok("registry"),
                    proposal.proposal_id,
                    proposal.owner_epoch
                );
                println!("  preimage hash:  {preimage_hash}");
                println!("  policy:         {}", proposal.governance_policy_id);
                println!("  expires_at:     {}", proposal.expires_at);
                println!("  out:            {}", out.display());
            }
        }
        OwnerRotateGovernedAction::Attest {
            proposal,
            attester_id,
            key,
            bundle,
            json,
        } => {
            let proposal_raw = std::fs::read_to_string(&proposal)
                .unwrap_or_else(|e| fail_return(&format!("read proposal: {e}")));
            let proposal_obj: OwnerRotateProposal = serde_json::from_str(&proposal_raw)
                .unwrap_or_else(|e| fail_return(&format!("parse proposal: {e}")));
            // Re-derive proposal id and assert match.
            let derived = proposal_obj.derive_id().unwrap_or_else(|e| fail_return(&e));
            if derived != proposal_obj.proposal_id {
                fail(&format!(
                    "proposal id mismatch: stored `{}`, derived `{}`",
                    proposal_obj.proposal_id, derived
                ));
            }

            let key_hex = std::fs::read_to_string(&key)
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|e| fail_return(&format!("read key: {e}")));
            let sk = parse_signing_key(&key_hex);
            let pubkey_hex = hex::encode(sk.verifying_key().to_bytes());

            let preimage = proposal_obj
                .preimage_bytes()
                .unwrap_or_else(|e| fail_return(&e));
            let sig = sk.sign(&preimage);

            let entry = AttestationEntry {
                attester_id: attester_id.clone(),
                attester_pubkey: pubkey_hex.clone(),
                judgment: "approve_owner_rotate".to_string(),
                signature: hex::encode(sig.to_bytes()),
                signed_at: chrono::Utc::now().to_rfc3339(),
            };

            // Load existing bundle if present; else start fresh.
            let existing: Option<OwnerRotateAttestationBundle> = if bundle.exists() {
                let raw = std::fs::read_to_string(&bundle)
                    .unwrap_or_else(|e| fail_return(&format!("read bundle: {e}")));
                Some(
                    serde_json::from_str(&raw)
                        .unwrap_or_else(|e| fail_return(&format!("parse bundle: {e}"))),
                )
            } else {
                None
            };

            let mut attestations: Vec<AttestationEntry> = existing
                .as_ref()
                .map(|b| b.attestations.clone())
                .unwrap_or_default();
            // Idempotency: replace any existing entry from the same
            // attester_id under the same proposal.
            attestations.retain(|a| a.attester_id != attester_id);
            attestations.push(entry);

            let new_bundle = OwnerRotateAttestationBundle::new(&proposal_obj, attestations)
                .unwrap_or_else(|e| fail_return(&e));

            let body =
                serde_json::to_string_pretty(&new_bundle).expect("serialize attestation bundle");
            std::fs::write(&bundle, format!("{body}\n"))
                .unwrap_or_else(|e| fail_return(&format!("write {}: {e}", bundle.display())));

            if json {
                let payload = json!({
                    "ok": true,
                    "command": "registry.owner-rotate-governed.attest",
                    "bundle_id": new_bundle.bundle_id,
                    "proposal_id": new_bundle.proposal_id,
                    "attester_id": attester_id,
                    "attester_pubkey": pubkey_hex,
                    "attestation_count": new_bundle.attestations.len(),
                    "bundle": bundle.display().to_string(),
                });
                print_json(&payload);
            } else {
                println!(
                    "{} attested {} ({} attestation(s) total)",
                    style::ok("attest"),
                    new_bundle.bundle_id,
                    new_bundle.attestations.len()
                );
                println!("  attester:    {attester_id}");
                println!("  pubkey:      {}...", &pubkey_hex[..16]);
                println!("  bundle:      {}", bundle.display());
            }
        }
        OwnerRotateGovernedAction::Apply {
            frontier,
            proposal,
            bundle,
            policy,
            new_key,
            locator,
            to,
            json,
        } => {
            // Load proposal, bundle, policy.
            let proposal_obj: OwnerRotateProposal = serde_json::from_str(
                &std::fs::read_to_string(&proposal)
                    .unwrap_or_else(|e| fail_return(&format!("read proposal: {e}"))),
            )
            .unwrap_or_else(|e| fail_return(&format!("parse proposal: {e}")));
            let bundle_obj: OwnerRotateAttestationBundle = serde_json::from_str(
                &std::fs::read_to_string(&bundle)
                    .unwrap_or_else(|e| fail_return(&format!("read bundle: {e}"))),
            )
            .unwrap_or_else(|e| fail_return(&format!("parse bundle: {e}")));
            let policy_obj: GovernancePolicy = serde_json::from_str(
                &std::fs::read_to_string(&policy)
                    .unwrap_or_else(|e| fail_return(&format!("read policy: {e}"))),
            )
            .unwrap_or_else(|e| fail_return(&format!("parse policy: {e}")));
            policy_obj
                .verify_content_address()
                .unwrap_or_else(|e| fail_return(&e));

            // Build the revocation lookup from the frontier's actors.
            let mut frontier_data =
                repo::load_from_path(&frontier).unwrap_or_else(|e| fail_return(&e));
            let revocation = FrontierRevocation {
                map: frontier_data
                    .actors
                    .iter()
                    .filter_map(|a| a.revoked_at.as_ref().map(|r| (a.id.clone(), r.clone())))
                    .collect(),
            };

            let now = chrono::Utc::now().to_rfc3339();
            let report = verify_quorum(&proposal_obj, &bundle_obj, &policy_obj, &revocation, &now)
                .unwrap_or_else(|e| fail_return(&format!("quorum verification failed: {e}")));

            // The proposal's new_owner_pubkey must match the
            // supplied --new-key. Read the key, derive the pubkey,
            // compare.
            let key_hex = std::fs::read_to_string(&new_key)
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|e| fail_return(&format!("read new key: {e}")));
            let sk = parse_signing_key(&key_hex);
            let derived_pubkey = hex::encode(sk.verifying_key().to_bytes());
            if derived_pubkey != proposal_obj.new_owner_pubkey {
                fail(&format!(
                    "--new-key derives to pubkey `{}`, but proposal declares new_owner_pubkey `{}`",
                    derived_pubkey, proposal_obj.new_owner_pubkey
                ));
            }

            // Mutate the frontier: revoke the current owner, register
            // (or promote) the new owner. Mirrors the v0.138 rotate
            // path.
            let mut retired_pubkey_prefix: Option<String> = None;
            for actor in frontier_data.actors.iter_mut() {
                if actor.id == proposal_obj.old_owner_actor_id {
                    if actor.revoked_at.is_some() {
                        fail(&format!(
                            "refusing to apply: old owner `{}` is already revoked at {}",
                            actor.id,
                            actor.revoked_at.as_deref().unwrap_or("?")
                        ));
                    }
                    actor.revoked_at = Some(now.clone());
                    actor.revoked_reason = Some(proposal_obj.reason.clone());
                    retired_pubkey_prefix = Some(actor.public_key[..16].to_string());
                }
            }

            if !frontier_data
                .actors
                .iter()
                .any(|a| a.id == proposal_obj.new_owner_actor_id)
            {
                frontier_data.actors.push(sign::ActorRecord {
                    id: proposal_obj.new_owner_actor_id.clone(),
                    public_key: proposal_obj.new_owner_pubkey.clone(),
                    algorithm: "ed25519".to_string(),
                    created_at: now.clone(),
                    tier: None,
                    orcid: None,
                    access_clearance: None,
                    revoked_at: None,
                    revoked_reason: None,
                });
            }

            repo::save_to_path(&frontier, &frontier_data)
                .unwrap_or_else(|e| fail_return(&format!("save rotation: {e}")));

            // Re-publish under the new owner key. Mirrors the
            // v0.138 publish path with the rotated entry pointing
            // at the new owner pubkey.
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
                owner_actor_id: proposal_obj.new_owner_actor_id.clone(),
                owner_pubkey: proposal_obj.new_owner_pubkey.clone(),
                latest_snapshot_hash: snapshot_hash,
                latest_event_log_hash: event_log_hash,
                network_locator: resolved_locator,
                license: None,
                signed_publish_at: chrono::Utc::now().to_rfc3339(),
                signature: String::new(),
            };
            entry.signature = registry::sign_entry(&entry, &sk).unwrap_or_else(|e| fail_return(&e));

            let (registry_label, duplicate) = if to_is_remote {
                let hub_url = to.clone().unwrap();
                let resp = registry::publish_remote(&entry, &hub_url, Some(&frontier_data))
                    .unwrap_or_else(|e| fail_return(&e));
                (hub_url, resp.duplicate)
            } else {
                let registry_path = match &to {
                    Some(loc) => registry::resolve_local(loc).unwrap_or_else(|e| fail_return(&e)),
                    None => default_registry_path(),
                };
                registry::publish_entry(&registry_path, entry.clone())
                    .unwrap_or_else(|e| fail_return(&e));
                (registry_path.display().to_string(), false)
            };

            // v0.146: append a transition to the owner-epoch chain
            // transcript sitting at <frontier-dir>/.vela/governance/chain.json.
            // The chain is the audit transcript a consumer pulls
            // and replays to verify the entire epoch chain from
            // genesis to the current entry.
            let chain_path = governance_chain_path(&frontier);
            let mut chain = if chain_path.exists() {
                let raw = std::fs::read_to_string(&chain_path).unwrap_or_else(|e| {
                    fail_return(&format!("read chain {}: {e}", chain_path.display()))
                });
                serde_json::from_str::<vela_edge::governance::OwnerEpochChain>(&raw)
                    .unwrap_or_else(|e| fail_return(&format!("parse chain: {e}")))
            } else {
                vela_edge::governance::OwnerEpochChain::new(vfr_id.clone())
            };
            let transition = vela_edge::governance::ChainTransition {
                owner_epoch: proposal_obj.owner_epoch,
                policy_id: policy_obj.policy_id.clone(),
                proposal_id: proposal_obj.proposal_id.clone(),
                bundle_id: bundle_obj.bundle_id.clone(),
                previous_entry_hash: proposal_obj.previous_registry_entry_hash.clone(),
                new_owner_actor_id: proposal_obj.new_owner_actor_id.clone(),
                new_owner_pubkey: proposal_obj.new_owner_pubkey.clone(),
                signed_at: now.clone(),
            };
            chain
                .append(transition)
                .unwrap_or_else(|e| fail_return(&format!("append chain: {e}")));
            if let Some(parent) = chain_path.parent() {
                std::fs::create_dir_all(parent).unwrap_or_else(|e| {
                    fail_return(&format!("create chain dir {}: {e}", parent.display()))
                });
            }
            let chain_json =
                serde_json::to_string_pretty(&chain).expect("serialize owner-epoch chain");
            std::fs::write(&chain_path, format!("{chain_json}\n")).unwrap_or_else(|e| {
                fail_return(&format!("write chain {}: {e}", chain_path.display()))
            });

            let payload = json!({
                "ok": true,
                "command": "registry.owner-rotate-governed.apply",
                "proposal_id": proposal_obj.proposal_id,
                "bundle_id": bundle_obj.bundle_id,
                "policy_id": policy_obj.policy_id,
                "quorum_report": report,
                "vfr_id": vfr_id,
                "name": name,
                "retired_owner": proposal_obj.old_owner_actor_id,
                "retired_pubkey_prefix": retired_pubkey_prefix,
                "new_owner": proposal_obj.new_owner_actor_id,
                "new_pubkey": derived_pubkey,
                "registry": registry_label,
                "signature": entry.signature,
                "duplicate": duplicate,
                "chain_file": chain_path.display().to_string(),
                "chain_length": chain.transitions.len(),
            });
            if json {
                print_json(&payload);
            } else {
                println!(
                    "{} governed rotation applied: {} -> {} (epoch {})",
                    style::ok("registry"),
                    proposal_obj.old_owner_actor_id,
                    proposal_obj.new_owner_actor_id,
                    proposal_obj.owner_epoch
                );
                println!(
                    "  approving signers: {}",
                    report.approving_signers.join(", ")
                );
                println!("  threshold:         {}", report.threshold);
                println!("  bundle:            {}", bundle_obj.bundle_id);
                println!("  registry:          {}", registry_label);
                println!("  signature:         {}…", &entry.signature[..16]);
            }
        }
    }
}
