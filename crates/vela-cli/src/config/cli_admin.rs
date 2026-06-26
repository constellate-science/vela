use crate::cli::print_identity_created;
use crate::cli::{fail, fail_return, parse_signing_key, print_json};
use crate::cli_commands::*;
use colored::Colorize;
use serde_json::json;
use vela_protocol::cli_style as style;
use vela_protocol::repo;
use vela_protocol::sign;

pub(crate) fn cmd_id(action: IdAction) {
    use crate::cli_identity::{
        DEFAULT_HUB, Identity, identity_path, load_identity, save_identity, vela_home,
    };
    match action {
        IdAction::Create {
            handle,
            agent,
            hub,
            force,
            json,
        } => {
            if load_identity().is_some() && !force {
                fail(&format!(
                    "an identity already exists ({}). Run `vela id show`, or pass --force to overwrite.",
                    identity_path().display()
                ));
            }
            let handle = handle
                .or_else(|| std::env::var("USER").ok())
                .map(|h| h.trim().to_string())
                .filter(|h| !h.is_empty())
                .unwrap_or_else(|| "anon".to_string());
            let actor_type = if agent { "agent" } else { "human" };
            let actor_id = format!("{}:{}", if agent { "agent" } else { "reviewer" }, handle);
            let key_dir = vela_home().join("keys").join(&handle);
            let pubkey = sign::generate_keypair(&key_dir).unwrap_or_else(|e| fail_return(&e));
            let key_path = key_dir.join("private.key");
            let hub_url = hub.unwrap_or_else(|| DEFAULT_HUB.to_string());
            let identity = Identity {
                version: "1.0".to_string(),
                actor_id: actor_id.clone(),
                actor_type: actor_type.to_string(),
                key_path: key_path.display().to_string(),
                pubkey: pubkey.clone(),
                hub_url: hub_url.clone(),
            };
            save_identity(&identity).unwrap_or_else(|e| fail_return(&e));
            print_identity_created(&identity, json);
        }
        IdAction::Import {
            key,
            handle,
            agent,
            hub,
            force,
            json,
        } => {
            if load_identity().is_some() && !force {
                fail(&format!(
                    "an identity already exists ({}). Run `vela id show`, or pass --force to overwrite.",
                    identity_path().display()
                ));
            }
            let hex = std::fs::read_to_string(&key)
                .unwrap_or_else(|e| fail_return(&format!("read key {}: {e}", key.display())));
            let signing = parse_signing_key(hex.trim());
            let pubkey = hex::encode(signing.verifying_key().to_bytes());
            let handle = handle
                .or_else(|| std::env::var("USER").ok())
                .map(|h| h.trim().to_string())
                .filter(|h| !h.is_empty())
                .unwrap_or_else(|| "anon".to_string());
            let actor_id = format!("{}:{}", if agent { "agent" } else { "reviewer" }, handle);
            let identity = Identity {
                version: "1.0".to_string(),
                actor_id: actor_id.clone(),
                actor_type: if agent { "agent" } else { "human" }.to_string(),
                key_path: key.display().to_string(),
                pubkey: pubkey.clone(),
                hub_url: hub.unwrap_or_else(|| DEFAULT_HUB.to_string()),
            };
            save_identity(&identity).unwrap_or_else(|e| fail_return(&e));
            print_identity_created(&identity, json);
        }
        IdAction::Show { json } => {
            let Some(identity) = load_identity() else {
                if json {
                    print_json(&json!({"ok": false, "configured": false}));
                } else {
                    println!(
                        "{} no identity configured — run `vela id create --handle <your-name>`",
                        style::warn("none")
                    );
                }
                return;
            };
            if json {
                print_json(&json!({
                    "ok": true,
                    "configured": true,
                    "actor_id": identity.actor_id,
                    "actor_type": identity.actor_type,
                    "pubkey": identity.pubkey,
                    "key_path": identity.key_path,
                    "hub_url": identity.hub_url,
                }));
            } else {
                println!("{}", style::ok("identity"));
                println!("  actor:  {}", identity.actor_id);
                println!("  pubkey: {}", identity.pubkey);
                println!("  key:    {}", identity.key_path);
                println!("  hub:    {}", identity.hub_url);
            }
        }
    }
}

pub(crate) fn cmd_actor(action: ActorAction) {
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
            // Default id + pubkey to the configured identity (`vela id`), so
            // `vela actor add <frontier>` registers you without typing a 64-char
            // hex key. The pubkey is stored by `vela id` for exactly this.
            let pubkey = pubkey
                .or_else(|| crate::cli_identity::load_identity().map(|i| i.pubkey))
                .unwrap_or_else(|| {
                    fail("no --pubkey given and no configured identity; run `vela id import` / `vela id create`, or pass --pubkey")
                });
            let id = crate::cli_identity::resolve_actor(id.as_deref());
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
