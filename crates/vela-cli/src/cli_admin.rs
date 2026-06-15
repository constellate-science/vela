#![allow(unused_imports)]
use crate::cli::{
    collect_witness_files, default_registry_path, fail, fail_return, load_frontier_or_fail,
    parse_signing_key, parse_witness, print_json, print_signal_summary,
};
use crate::cli::{fmt_timestamp, frontier_label, print_identity_created};
use crate::cli_commands::*;
use crate::cli_identity::{
    DEFAULT_HUB, Identity, identity_path, load_identity, save_identity, vela_home,
};
use crate::serve;
use clap::Parser;
use colored::Colorize;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
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
use vela_protocol::cli_style as style;
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
pub(crate) fn cmd_agent(action: AgentAction) {
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

/// v0.167: handle `vela hub ...`. Build + validate hub-spec
/// primitive records.
pub(crate) fn cmd_hub_spec(action: HubSpecCli) {
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
