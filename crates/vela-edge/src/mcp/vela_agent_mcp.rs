//! v0.206: MCP adapter for the vela_agent SDK surface.
//!
//! Exposes two write-side tools over JSON-RPC stdio: a one-shot
//! `vela_agent_submit_diff_pack` that signs a vaa_* attestation +
//! a vsd_* pack in one call, and `vela_agent_open_trajectory` that
//! writes a vtr_* with N steps.
//!
//! Stateless: each call is one-shot. The agent does its own
//! bookkeeping client-side (mirroring the Python SDK's run lifecycle)
//! and only invokes Vela when ready to submit a complete unit.
//!
//! Signing key: read from `VELA_AGENT_KEY_HEX` env var. If unset,
//! the write-side tools refuse to operate. **No silent unsigned
//! submissions.**

use crate::agent_attestation::{AgentAttestation, AttestationDraft, ToolCall};
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use vela_protocol::scientific_diff::{PackDraft, ScientificDiffPack};

const AGENT_KEY_ENV: &str = "VELA_AGENT_KEY_HEX";

// ----------------------------------------------------------------------------
// v0.214: read-side helpers. None of these require a signing key.
// ----------------------------------------------------------------------------

fn read_one_artifact(frontier_path: &Path, subdir: &str, id: &str) -> Result<String, String> {
    let path = if frontier_path.is_dir() {
        frontier_path
            .join(".vela")
            .join(subdir)
            .join(format!("{id}.json"))
    } else {
        frontier_path
            .parent()
            .unwrap_or(Path::new("."))
            .join(".vela")
            .join(subdir)
            .join(format!("{id}.json"))
    };
    std::fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))
}

fn list_artifacts(frontier_path: &Path, subdir: &str, prefix: &str) -> Vec<Value> {
    let dir = if frontier_path.is_dir() {
        frontier_path.join(".vela").join(subdir)
    } else {
        frontier_path
            .parent()
            .unwrap_or(Path::new("."))
            .join(".vela")
            .join(subdir)
    };
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut paths: Vec<std::path::PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("json"))
        .filter(|p| {
            p.file_stem()
                .and_then(|s| s.to_str())
                .map(|s| s.starts_with(prefix))
                .unwrap_or(false)
        })
        .collect();
    paths.sort();
    let mut out: Vec<Value> = Vec::new();
    for p in paths {
        if let Ok(body) = std::fs::read_to_string(&p)
            && let Ok(v) = serde_json::from_str::<Value>(&body)
        {
            out.push(v);
        }
    }
    out
}

fn frontier_path_arg(args: &Value) -> Result<PathBuf, String> {
    args.get("frontier_path")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .ok_or_else(|| "frontier_path required".to_string())
}

/// `vela_agent_get_pack` — fetch a single Diff Pack by id.
pub fn get_pack(args: &Value) -> Result<String, String> {
    let frontier = frontier_path_arg(args)?;
    let pack_id = args
        .get("pack_id")
        .and_then(Value::as_str)
        .ok_or("pack_id required")?;
    if !pack_id.starts_with("vsd_") {
        return Err(format!("pack_id must start with `vsd_`, got `{pack_id}`"));
    }
    let body = read_one_artifact(&frontier, "diff_packs", pack_id)?;
    Ok(body)
}

/// `vela_agent_list_packs` — list every Diff Pack on a frontier.
pub fn list_packs(args: &Value) -> Result<String, String> {
    let frontier = frontier_path_arg(args)?;
    let packs = list_artifacts(&frontier, "diff_packs", "vsd_");
    let only_pending = args
        .get("only_pending")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let filtered: Vec<Value> = if only_pending {
        packs
            .into_iter()
            .filter(|p| p.get("signature").is_some() && p.get("applied_event_id").is_none())
            .collect()
    } else {
        packs
    };
    Ok(serde_json::to_string_pretty(&json!({
        "ok": true,
        "count": filtered.len(),
        "packs": filtered,
    }))
    .unwrap_or_default())
}

/// `vela_agent_get_attestation` — fetch a single Agent Attestation.
pub fn get_attestation(args: &Value) -> Result<String, String> {
    let frontier = frontier_path_arg(args)?;
    let vaa_id = args
        .get("attestation_id")
        .and_then(Value::as_str)
        .ok_or("attestation_id required")?;
    if !vaa_id.starts_with("vaa_") {
        return Err(format!(
            "attestation_id must start with `vaa_`, got `{vaa_id}`"
        ));
    }
    let body = read_one_artifact(&frontier, "agent_attestations", vaa_id)?;
    Ok(body)
}

/// `vela_agent_frontier_summary` — quick counts: which primitives
/// exist on this frontier. Useful as the first call in a multi-turn
/// agent session.
pub fn frontier_summary(args: &Value) -> Result<String, String> {
    let frontier = frontier_path_arg(args)?;
    let diff_packs = list_artifacts(&frontier, "diff_packs", "vsd_");
    let pending_packs: usize = diff_packs
        .iter()
        .filter(|p| p.get("signature").is_some() && p.get("applied_event_id").is_none())
        .count();
    let attestations = list_artifacts(&frontier, "agent_attestations", "vaa_");
    let tool_descriptors = list_artifacts(&frontier, "tool_descriptors", "vtd_");
    let evaluations = list_artifacts(&frontier, "evaluations", "ver_");
    let verdict_conflicts = list_artifacts(&frontier, "verdict_conflicts", "vdc_");
    Ok(serde_json::to_string_pretty(&json!({
        "ok": true,
        "summary": {
            "diff_packs": diff_packs.len(),
            "pending_packs": pending_packs,
            "attestations": attestations.len(),
            "tool_descriptors": tool_descriptors.len(),
            "evaluations": evaluations.len(),
            "verdict_conflicts": verdict_conflicts.len(),
        }
    }))
    .unwrap_or_default())
}

// ----------------------------------------------------------------------------
// v0.220: read-tool parity for tool descriptors, evaluations, conflicts.
// ----------------------------------------------------------------------------

/// `vela_agent_get_tool_descriptor` — fetch a single Tool Descriptor.
pub fn get_tool_descriptor(args: &Value) -> Result<String, String> {
    let frontier = frontier_path_arg(args)?;
    let vtd_id = args
        .get("descriptor_id")
        .and_then(Value::as_str)
        .ok_or("descriptor_id required")?;
    if !vtd_id.starts_with("vtd_") {
        return Err(format!(
            "descriptor_id must start with `vtd_`, got `{vtd_id}`"
        ));
    }
    let body = read_one_artifact(&frontier, "tool_descriptors", vtd_id)?;
    Ok(body)
}

/// `vela_agent_get_evaluation` — fetch a single Evaluation Record.
pub fn get_evaluation(args: &Value) -> Result<String, String> {
    let frontier = frontier_path_arg(args)?;
    let ver_id = args
        .get("evaluation_id")
        .and_then(Value::as_str)
        .ok_or("evaluation_id required")?;
    if !ver_id.starts_with("ver_") {
        return Err(format!(
            "evaluation_id must start with `ver_`, got `{ver_id}`"
        ));
    }
    let body = read_one_artifact(&frontier, "evaluations", ver_id)?;
    Ok(body)
}

/// `vela_agent_list_evaluations` — list every Evaluation Record on a
/// frontier, optionally filtered by target descriptor.
pub fn list_evaluations(args: &Value) -> Result<String, String> {
    let frontier = frontier_path_arg(args)?;
    let evals = list_artifacts(&frontier, "evaluations", "ver_");
    let target_descriptor = args
        .get("target_descriptor_id")
        .and_then(Value::as_str)
        .map(String::from);
    let filtered: Vec<Value> = match target_descriptor {
        Some(td) => evals
            .into_iter()
            .filter(|e| {
                e.get("target_kind").and_then(Value::as_str) == Some("tool_descriptor")
                    && e.get("target_id").and_then(Value::as_str) == Some(td.as_str())
            })
            .collect(),
        None => evals,
    };
    Ok(serde_json::to_string_pretty(&json!({
        "ok": true,
        "count": filtered.len(),
        "evaluations": filtered,
    }))
    .unwrap_or_default())
}

/// `vela_agent_get_conflict` — fetch a single resolved Verdict Conflict.
pub fn get_conflict(args: &Value) -> Result<String, String> {
    let frontier = frontier_path_arg(args)?;
    let vdc_id = args
        .get("conflict_id")
        .and_then(Value::as_str)
        .ok_or("conflict_id required")?;
    if !vdc_id.starts_with("vdc_") {
        return Err(format!(
            "conflict_id must start with `vdc_`, got `{vdc_id}`"
        ));
    }
    let body = read_one_artifact(&frontier, "verdict_conflicts", vdc_id)?;
    Ok(body)
}

/// `vela_agent_list_conflicts` — list every resolved Verdict Conflict
/// on a frontier, optionally filtered by resolution_mode.
pub fn list_conflicts(args: &Value) -> Result<String, String> {
    let frontier = frontier_path_arg(args)?;
    let conflicts = list_artifacts(&frontier, "verdict_conflicts", "vdc_");
    let mode = args
        .get("resolution_mode")
        .and_then(Value::as_str)
        .map(String::from);
    let filtered: Vec<Value> = match mode {
        Some(m) => conflicts
            .into_iter()
            .filter(|c| c.get("resolution_mode").and_then(Value::as_str) == Some(m.as_str()))
            .collect(),
        None => conflicts,
    };
    Ok(serde_json::to_string_pretty(&json!({
        "ok": true,
        "count": filtered.len(),
        "conflicts": filtered,
    }))
    .unwrap_or_default())
}

fn signing_key_from_env() -> Result<SigningKey, String> {
    let hex_str = std::env::var(AGENT_KEY_ENV).map_err(|_| {
        format!("{AGENT_KEY_ENV} not set; vela_agent_* tools require an Ed25519 signing key")
    })?;
    let bytes = hex::decode(hex_str.trim()).map_err(|e| format!("decode {AGENT_KEY_ENV}: {e}"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| format!("{AGENT_KEY_ENV} must be 32 hex bytes"))?;
    Ok(SigningKey::from_bytes(&arr))
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn canonical_json_hash(v: &Value) -> String {
    match vela_protocol::canonical::to_canonical_bytes(v) {
        Ok(bytes) => sha256_hex(&bytes),
        Err(_) => sha256_hex(b""),
    }
}

fn frontier_id_from_path(path: &Path) -> Result<String, String> {
    let frontier_json = if path.is_dir() {
        path.join("frontier.json")
    } else {
        path.to_path_buf()
    };
    let body = std::fs::read_to_string(&frontier_json)
        .map_err(|e| format!("read {}: {e}", frontier_json.display()))?;
    let v: Value = serde_json::from_str(&body).map_err(|e| format!("parse frontier.json: {e}"))?;
    let fid = v
        .get("frontier_id")
        .and_then(Value::as_str)
        .or_else(|| {
            v.get("frontier")
                .and_then(|p| p.get("id"))
                .and_then(Value::as_str)
        })
        .ok_or("no frontier_id in frontier.json")?;
    Ok(fid.to_string())
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn derive_proposal_id(kind: &str, payload: &Value, at: &str, actor: &str) -> String {
    let canonical = serde_json::to_string(payload).unwrap_or_default();
    let preimage = format!("{kind}|{canonical}|{at}|{actor}");
    format!("vpr_{}", &sha256_hex(preimage.as_bytes())[..16])
}

/// `vela_agent_submit_diff_pack` MCP tool. One-shot: builds a
/// signed AgentAttestation envelope and a signed ScientificDiffPack
/// bundling N proposals, writes both to the frontier's `.vela/`
/// tree, and returns the resulting ids.
///
/// Arguments (JSON):
///   {
///     "frontier_path": String,
///     "agent_actor": String (must start with "agent:"),
///     "model_name": String, "model_version": String,
///     "prompt": String? (hashed server-side),
///     "started_at": String, "finished_at": String,
///     "total_tokens": Number,
///     "tool_calls": [{
///       "tool_name": String, "input": Value, "output": Value,
///       "duration_ms": Number
///     }],
///     "proposals": [{"kind": String, "payload": Value}],
///     "summary": String, "aggregate_kind": String,
///     "parent_attestation": String?, "parent_pack": String?,
///   }
pub fn submit_diff_pack(args: &Value) -> Result<String, String> {
    let key = signing_key_from_env()?;

    let frontier_path: PathBuf = args
        .get("frontier_path")
        .and_then(Value::as_str)
        .ok_or("frontier_path required")?
        .into();
    let frontier_id = frontier_id_from_path(&frontier_path)?;

    let agent_actor = args
        .get("agent_actor")
        .and_then(Value::as_str)
        .ok_or("agent_actor required")?;
    let model_name = args
        .get("model_name")
        .and_then(Value::as_str)
        .ok_or("model_name required")?;
    let model_version = args
        .get("model_version")
        .and_then(Value::as_str)
        .ok_or("model_version required")?;
    let started_at = args
        .get("started_at")
        .and_then(Value::as_str)
        .map(String::from)
        .unwrap_or_else(now_rfc3339);
    let finished_at = args
        .get("finished_at")
        .and_then(Value::as_str)
        .map(String::from)
        .unwrap_or_else(now_rfc3339);
    let total_tokens = args
        .get("total_tokens")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let prompt_hash = args
        .get("prompt")
        .and_then(Value::as_str)
        .map(|p| sha256_hex(p.as_bytes()));
    let parent_attestation = args
        .get("parent_attestation")
        .and_then(Value::as_str)
        .map(String::from);
    let parent_pack = args
        .get("parent_pack")
        .and_then(Value::as_str)
        .map(String::from);
    let summary = args
        .get("summary")
        .and_then(Value::as_str)
        .ok_or("summary required")?
        .to_string();
    let aggregate_kind = args
        .get("aggregate_kind")
        .and_then(Value::as_str)
        .ok_or("aggregate_kind required")?
        .to_string();

    // Tool calls.
    let tool_calls_json = args.get("tool_calls").and_then(Value::as_array);
    let mut tool_calls: Vec<ToolCall> = Vec::new();
    if let Some(calls) = tool_calls_json {
        for c in calls {
            let tool_name = c
                .get("tool_name")
                .and_then(Value::as_str)
                .ok_or("tool_call.tool_name required")?
                .to_string();
            let input = c.get("input").cloned().unwrap_or(Value::Null);
            let output = c.get("output").cloned().unwrap_or(Value::Null);
            let duration_ms = c.get("duration_ms").and_then(Value::as_u64).unwrap_or(0);
            tool_calls.push(ToolCall {
                tool_name,
                input_hash: canonical_json_hash(&input),
                output_hash: canonical_json_hash(&output),
                duration_ms,
            });
        }
    }

    // Proposals.
    let proposals_json = args
        .get("proposals")
        .and_then(Value::as_array)
        .ok_or("proposals required")?;
    if proposals_json.is_empty() {
        return Err("proposals must contain at least one entry".to_string());
    }

    let mut output_hashes: Vec<String> = Vec::new();
    let mut proposal_ids: Vec<String> = Vec::new();
    let mut stub_writes: Vec<(String, Value)> = Vec::new();
    for p in proposals_json {
        let kind = p
            .get("kind")
            .and_then(Value::as_str)
            .ok_or("proposal.kind required")?
            .to_string();
        let payload = p.get("payload").cloned().unwrap_or(Value::Null);
        let proposed_at = now_rfc3339();
        let pid = derive_proposal_id(&kind, &payload, &proposed_at, agent_actor);
        let stub = json!({
            "schema": "vela.agent_sdk.proposal_stub.v0.1",
            "proposal_id": pid,
            "kind": kind,
            "payload": payload,
            "proposed_at": proposed_at,
            "actor": agent_actor,
            "meta": {},
        });
        output_hashes.push(canonical_json_hash(&payload));
        proposal_ids.push(pid.clone());
        stub_writes.push((pid, stub));
    }

    // Build the attestation.
    let attestation = AgentAttestation::build(
        AttestationDraft {
            agent_actor: agent_actor.to_string(),
            model_name: model_name.to_string(),
            model_version: model_version.to_string(),
            started_at,
            finished_at: finished_at.clone(),
            total_tokens,
            tool_calls,
            output_hashes,
            prompt_hash,
            parent_attestation,
        },
        &key,
    )?;

    // Build + sign the pack.
    let pack_draft = PackDraft {
        frontier_id: frontier_id.clone(),
        created_at: finished_at,
        summary,
        proposals: proposal_ids.clone(),
        aggregate_kind,
        agent_run: Some(attestation.attestation_id.clone()),
        parent_pack,
    };
    let mut pack = ScientificDiffPack::build(pack_draft)?;
    pack.sign(&key);

    // Write artifacts to disk.
    let vela_dir = if frontier_path.is_dir() {
        frontier_path.join(".vela")
    } else {
        frontier_path
            .parent()
            .unwrap_or(Path::new("."))
            .join(".vela")
    };
    let att_dir = vela_dir.join("agent_attestations");
    let pack_dir = vela_dir.join("diff_packs");
    let prop_dir = vela_dir.join("agent_proposals");
    for d in [&att_dir, &pack_dir, &prop_dir] {
        std::fs::create_dir_all(d).map_err(|e| format!("create {}: {e}", d.display()))?;
    }
    let att_path = att_dir.join(format!("{}.json", attestation.attestation_id));
    let pack_path = pack_dir.join(format!("{}.json", pack.pack_id));
    let att_body =
        serde_json::to_string_pretty(&attestation).map_err(|e| format!("serialize vaa: {e}"))?;
    let pack_body =
        serde_json::to_string_pretty(&pack).map_err(|e| format!("serialize vsd: {e}"))?;
    std::fs::write(&att_path, format!("{att_body}\n"))
        .map_err(|e| format!("write {}: {e}", att_path.display()))?;
    std::fs::write(&pack_path, format!("{pack_body}\n"))
        .map_err(|e| format!("write {}: {e}", pack_path.display()))?;
    for (pid, stub) in stub_writes {
        let path = prop_dir.join(format!("{pid}.json"));
        let body =
            serde_json::to_string_pretty(&stub).map_err(|e| format!("serialize stub: {e}"))?;
        std::fs::write(&path, format!("{body}\n"))
            .map_err(|e| format!("write {}: {e}", path.display()))?;
    }

    Ok(serde_json::to_string_pretty(&json!({
        "ok": true,
        "frontier_id": frontier_id,
        "attestation_id": attestation.attestation_id,
        "pack_id": pack.pack_id,
        "proposal_ids": proposal_ids,
        "wrote": {
            "attestation": att_path.display().to_string(),
            "pack": pack_path.display().to_string(),
        }
    }))
    .unwrap_or_default())
}

/// `vela_claim_task` — lease an open obligation so other swarm agents route
/// around it. Emits a signed `attempt.claimed` event (the agent's OWN key
/// via VELA_AGENT_KEY_HEX; never a human's). One live lease per obligation;
/// expiry = claimed_at + ttl, computed at read time. Coordination, not
/// authority: a lease decides nothing.
pub fn claim_task(args: &Value) -> Result<String, String> {
    let key = signing_key_from_env()?;
    let frontier_path: PathBuf = args
        .get("frontier_path")
        .and_then(Value::as_str)
        .ok_or("frontier_path required")?
        .into();
    let obligation = args
        .get("obligation_id")
        .and_then(Value::as_str)
        .ok_or("obligation_id required (a vf_… finding id)")?;
    let agent_actor = args
        .get("agent_actor")
        .and_then(Value::as_str)
        .ok_or("agent_actor required")?;
    if !agent_actor.starts_with("agent:") && !agent_actor.starts_with("ci:") {
        return Err("claim_task is for agent:/ci: actors".to_string());
    }
    let ttl = args
        .get("ttl_seconds")
        .and_then(Value::as_u64)
        .unwrap_or(86_400);
    let pubkey = hex::encode(key.verifying_key().to_bytes());
    let mut project = vela_protocol::repo::load_from_path(&frontier_path)
        .map_err(|e| format!("load frontier: {e}"))?;
    // An obligation is usually a finding (vf_…) but may be an EXTERNAL
    // work target (e.g. `erdos:443` — a problem with no finding yet).
    // External ids must be namespaced so a typo'd vf_ id can't slip.
    let is_finding = project.findings.iter().any(|f| f.id == obligation);
    let is_external = obligation.contains(':')
        && !obligation.starts_with("vf_")
        && obligation
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '.' | '_' | '-'));
    if !is_finding && !is_external {
        return Err(format!(
            "obligation {obligation} is neither a finding on this frontier nor a              namespaced external target (e.g. erdos:443)"
        ));
    }
    // Refuse a live competing lease (route-around, not fight).
    let now = chrono::Utc::now().to_rfc3339();
    if let Some(live) = project.attempt_claims.iter().find(|c| {
        c.obligation_id == obligation
            && chrono::DateTime::parse_from_rfc3339(&c.claimed_at)
                .map(|t| {
                    (t + chrono::Duration::seconds(c.lease_ttl_seconds as i64)).to_rfc3339() > now
                })
                .unwrap_or(false)
    }) {
        return Ok(serde_json::json!({
            "ok": false,
            "already_claimed_by": live.claimant_actor,
            "claimed_at": live.claimed_at,
            "ttl_seconds": live.lease_ttl_seconds,
        })
        .to_string());
    }
    let mut event =
        vela_protocol::events::new_finding_event(vela_protocol::events::FindingEventInput {
            kind: "attempt.claimed",
            finding_id: obligation,
            actor_id: agent_actor,
            actor_type: vela_protocol::events::actor_kind(agent_actor),
            reason: "obligation lease (swarm coordination)",
            before_hash: "sha256:null",
            after_hash: "sha256:null",
            payload: serde_json::json!({
                "obligation_id": obligation,
                "lease_ttl_seconds": ttl,
                "claimant_actor": agent_actor,
                "claimant_pubkey": pubkey,
            }),
            caveats: Vec::new(),
            timestamp: None,
        });
    vela_protocol::reducer::apply_event(&mut project, &event)?;
    event.signature = Some(vela_protocol::sign::sign_event(&event, &key)?);
    project.events.push(event);
    vela_protocol::repo::save_to_path(&frontier_path, &project)
        .map_err(|e| format!("save: {e}"))?;
    Ok(serde_json::json!({
        "ok": true,
        "obligation": obligation,
        "claimed_by": agent_actor,
        "ttl_seconds": ttl,
    })
    .to_string())
}

/// `vela_check_run` — hold the LOCAL frontier to the one strict bar
/// (validation + strict reducer replay + signature signals), over MCP. The
/// agent's "does this frontier pass the gate right now?" question, answered
/// by the same bundle the hub's ingestor enforces.
pub fn check_run(args: &Value) -> Result<String, String> {
    let frontier_path: PathBuf = args
        .get("frontier_path")
        .and_then(Value::as_str)
        .ok_or("frontier_path required")?
        .into();
    match crate::verify::verify_frontier_strict(&frontier_path) {
        Ok((project, fid)) => Ok(serde_json::json!({
            "ok": true,
            "frontier_id": fid,
            "findings": project.findings.len(),
            "events": project.events.len(),
            "note": "strict bar held: validation + reducer replay + signature signals",
        })
        .to_string()),
        Err(e) => Ok(serde_json::json!({
            "ok": false,
            "error": e,
        })
        .to_string()),
    }
}

/// `vela_reproduce_run` — re-verify a frontier's stored witnesses from
/// scratch with the frozen exact verifiers, over MCP. Walks
/// `witnesses/*.witness.json` (or any `*.witness.json` under the path).
pub fn reproduce_run(args: &Value) -> Result<String, String> {
    let path: PathBuf = args
        .get("frontier_path")
        .and_then(Value::as_str)
        .ok_or("frontier_path required")?
        .into();
    let mut files: Vec<PathBuf> = Vec::new();
    let mut roots = vec![path.clone()];
    if path.join("witnesses").is_dir() {
        roots.push(path.join("witnesses"));
    }
    for root in roots {
        if root.is_file() {
            files.push(root);
            continue;
        }
        if let Ok(rd) = std::fs::read_dir(&root) {
            for e in rd.flatten() {
                let p = e.path();
                if p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.ends_with(".witness.json"))
                {
                    files.push(p);
                }
            }
        }
    }
    files.sort();
    files.dedup();
    if files.is_empty() {
        return Ok(serde_json::json!({
            "ok": false,
            "error": format!("no *.witness.json under {}", path.display()),
        })
        .to_string());
    }
    let mut passed = 0usize;
    let mut failures: Vec<Value> = Vec::new();
    for f in &files {
        let outcome = std::fs::read_to_string(f)
            .map_err(|e| format!("read: {e}"))
            .and_then(|raw| {
                serde_json::from_str::<vela_verify::Witness>(&raw)
                    .map_err(|e| format!("parse: {e}"))
            })
            .map(|w| vela_verify::verify_witness(&w));
        match outcome {
            Ok(r) if r.ok => passed += 1,
            Ok(r) => failures.push(serde_json::json!({
                "witness": f.display().to_string(),
                "message": r.message,
            })),
            Err(e) => failures.push(serde_json::json!({
                "witness": f.display().to_string(),
                "message": e,
            })),
        }
    }
    Ok(serde_json::json!({
        "ok": failures.is_empty(),
        "passed": passed,
        "failed": failures.len(),
        "failures": failures,
    })
    .to_string())
}

/// `vela_record_propose` — land an activity record (vrc_) on the LOCAL
/// frontier as a pending proposal. The git-native agent write path: the
/// agent works in the repo, the record becomes a reviewable proposal,
/// `git push` publishes, the hub re-indexes. Never decides — the proposal
/// waits for a human key.
pub fn record_propose(args: &Value) -> Result<String, String> {
    let frontier_path: PathBuf = args
        .get("frontier_path")
        .and_then(Value::as_str)
        .ok_or("frontier_path required")?
        .into();
    let record_path: PathBuf = args
        .get("record_path")
        .and_then(Value::as_str)
        .ok_or("record_path required")?
        .into();
    let raw = std::fs::read_to_string(&record_path)
        .map_err(|e| format!("read {}: {e}", record_path.display()))?;
    let rc: vela_protocol::record::ActivityRecord =
        serde_json::from_str(&raw).map_err(|e| format!("record parse: {e}"))?;
    let signed = rc.verify()?;
    let project = vela_protocol::repo::load_from_path(&frontier_path)
        .map_err(|e| format!("load frontier: {e}"))?;
    if project.frontier_id() != rc.frontier_id {
        return Err(format!(
            "record is for {}, this frontier is {}",
            rc.frontier_id,
            project.frontier_id()
        ));
    }
    let head_now = vela_protocol::events::event_log_hash(&project.events);
    let staleness = if head_now == rc.against_head {
        "recorded against the current head".to_string()
    } else {
        format!(
            "recorded against head {}…, current head {}… — review the delta",
            &rc.against_head[..rc.against_head.len().min(16)],
            &head_now[..head_now.len().min(16)]
        )
    };
    let report = vela_protocol::state::add_finding(
        &frontier_path,
        rc.to_finding_draft(&staleness, signed),
        false, // pending only: an MCP client never applies state
    )?;
    Ok(serde_json::json!({
        "ok": true,
        "record": rc.id,
        "signed": signed,
        "proposal_id": report.proposal_id,
        "status": report.proposal_status,
        "note": "pending; a human key accepts. git push publishes.",
    })
    .to_string())
}

// Note: the write-side tools here mutate VELA_AGENT_KEY_HEX (the
// env-driven signing key for submit_diff_pack), which cannot run
// safely under cargo's parallel test runner because env mutation is
// `unsafe` in modern Rust editions. The submit_diff_pack signed
// roundtrip is exercised end-to-end by the bash gate
// `scripts/test-mcp-server.sh` instead, which spawns the server with
// a controlled env.
