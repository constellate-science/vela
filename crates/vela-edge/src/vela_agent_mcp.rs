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
use vela_protocol::bundle::{Trajectory, TrajectoryStep, TrajectoryStepKind};
use vela_protocol::scientific_diff::{PackDraft, ScientificDiffPack};
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

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

/// `vela_agent_list_trajectories` — list every Trajectory on a frontier.
pub fn list_trajectories(args: &Value) -> Result<String, String> {
    let frontier = frontier_path_arg(args)?;
    let trajs = list_artifacts(&frontier, "trajectories", "vtr_");
    Ok(serde_json::to_string_pretty(&json!({
        "ok": true,
        "count": trajs.len(),
        "trajectories": trajs,
    }))
    .unwrap_or_default())
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
    let trajectories = list_artifacts(&frontier, "trajectories", "vtr_");
    let tool_descriptors = list_artifacts(&frontier, "tool_descriptors", "vtd_");
    let evaluations = list_artifacts(&frontier, "evaluations", "ver_");
    let verdict_conflicts = list_artifacts(&frontier, "verdict_conflicts", "vdc_");
    Ok(serde_json::to_string_pretty(&json!({
        "ok": true,
        "summary": {
            "diff_packs": diff_packs.len(),
            "pending_packs": pending_packs,
            "attestations": attestations.len(),
            "trajectories": trajectories.len(),
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

fn step_kind_from_str(s: &str) -> Option<TrajectoryStepKind> {
    match s {
        "hypothesis" => Some(TrajectoryStepKind::Hypothesis),
        "tried" => Some(TrajectoryStepKind::Tried),
        "ruled_out" => Some(TrajectoryStepKind::RuledOut),
        "observed" => Some(TrajectoryStepKind::Observed),
        "refined" => Some(TrajectoryStepKind::Refined),
        "question" => Some(TrajectoryStepKind::Question),
        "context" => Some(TrajectoryStepKind::Context),
        "data" => Some(TrajectoryStepKind::Data),
        "tool" => Some(TrajectoryStepKind::Tool),
        "model" => Some(TrajectoryStepKind::Model),
        "expert" => Some(TrajectoryStepKind::Expert),
        "decision" => Some(TrajectoryStepKind::Decision),
        "protocol" => Some(TrajectoryStepKind::Protocol),
        "output" => Some(TrajectoryStepKind::Output),
        "review" => Some(TrajectoryStepKind::Review),
        "risk" => Some(TrajectoryStepKind::Risk),
        "outcome" => Some(TrajectoryStepKind::Outcome),
        _ => None,
    }
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

/// `vela_agent_open_trajectory` MCP tool. Writes a vtr_* with N
/// steps to `.vela/trajectories/<vtr_id>.json`. Does not require a
/// signing key (trajectories are content-addressed but unsigned —
/// the chain of custody for who deposited them lives in the
/// `deposited_by` actor id).
///
/// Arguments (JSON):
///   {
///     "frontier_path": String,
///     "target_findings": [String]?,
///     "deposited_by": String,
///     "notes": String?,
///     "steps": [{"kind": String, "description": String,
///                "references": [String]?, "actor": String?}],
///   }
pub fn open_trajectory(args: &Value) -> Result<String, String> {
    let frontier_path: PathBuf = args
        .get("frontier_path")
        .and_then(Value::as_str)
        .ok_or("frontier_path required")?
        .into();
    let target_findings: Vec<String> = args
        .get("target_findings")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let deposited_by = args
        .get("deposited_by")
        .and_then(Value::as_str)
        .ok_or("deposited_by required")?
        .to_string();
    let notes = args
        .get("notes")
        .and_then(Value::as_str)
        .map(String::from)
        .unwrap_or_default();
    let created = now_rfc3339();

    let id = Trajectory::content_address(&target_findings, &deposited_by, &created);

    let steps_json = args
        .get("steps")
        .and_then(Value::as_array)
        .ok_or("steps required (at least one)")?;
    let mut steps: Vec<TrajectoryStep> = Vec::new();
    for s in steps_json {
        let kind_str = s
            .get("kind")
            .and_then(Value::as_str)
            .ok_or("step.kind required")?;
        let kind = step_kind_from_str(kind_str)
            .ok_or_else(|| format!("unknown step kind `{kind_str}`"))?;
        let description = s
            .get("description")
            .and_then(Value::as_str)
            .ok_or("step.description required")?
            .to_string();
        let actor = s
            .get("actor")
            .and_then(Value::as_str)
            .map(String::from)
            .unwrap_or_else(|| deposited_by.clone());
        let references: Vec<String> = s
            .get("references")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let step = TrajectoryStep::new(&id, kind, description, actor, None, references);
        steps.push(step);
    }

    let traj = Trajectory {
        id: id.clone(),
        target_findings,
        deposited_by,
        created,
        steps,
        notes,
        review_state: None,
        retracted: false,
        access_tier: Default::default(),
    };

    let vela_dir = if frontier_path.is_dir() {
        frontier_path.join(".vela")
    } else {
        frontier_path
            .parent()
            .unwrap_or(Path::new("."))
            .join(".vela")
    };
    let dir = vela_dir.join("trajectories");
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let path = dir.join(format!("{id}.json"));
    let body =
        serde_json::to_string_pretty(&traj).map_err(|e| format!("serialize trajectory: {e}"))?;
    std::fs::write(&path, format!("{body}\n"))
        .map_err(|e| format!("write {}: {e}", path.display()))?;

    Ok(serde_json::to_string_pretty(&json!({
        "ok": true,
        "trajectory_id": id,
        "steps": traj.steps.len(),
        "wrote": path.display().to_string(),
    }))
    .unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn fixture_frontier() -> tempfile::TempDir {
        let tmp = tempdir().unwrap();
        std::fs::write(
            tmp.path().join("frontier.json"),
            r#"{"frontier_id":"vfr_5076e7b3ff8e6b0f"}"#,
        )
        .unwrap();
        tmp
    }

    // Note: tests that mutate VELA_AGENT_KEY_HEX (the env-driven
    // signing-key for submit_diff_pack) cannot run safely under
    // cargo's parallel test runner because env mutation is
    // `unsafe` in modern Rust editions. The submit_diff_pack
    // signed-roundtrip is exercised end-to-end by the bash gate
    // `scripts/test-mcp-server.sh` instead, which spawns the
    // server with a controlled env.

    #[test]
    fn open_trajectory_writes_file() {
        let tmp = fixture_frontier();
        let args = json!({
            "frontier_path": tmp.path().display().to_string(),
            "deposited_by": "agent:t",
            "notes": "test",
            "steps": [
                {"kind": "question", "description": "what does this do?"},
                {"kind": "output", "description": "produces a trajectory"}
            ],
        });
        let out = open_trajectory(&args).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        let tid = v["trajectory_id"].as_str().unwrap();
        assert!(tid.starts_with("vtr_"));
        let path = tmp
            .path()
            .join(".vela")
            .join("trajectories")
            .join(format!("{tid}.json"));
        assert!(path.is_file());
    }
}
