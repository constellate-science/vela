use crate::cli::{
    append_packet_json_file, fail, fail_return, hash_path_or_fail, load_frontier_or_fail,
    parse_signing_key, print_json, save_recorded_proof_state,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use vela_edge::benchmark;
use vela_edge::carina_validate;
use vela_edge::export;
use vela_edge::packet;
use vela_edge::signals;
use vela_protocol::cli_style as style;
use vela_protocol::frontier_repo;
use vela_protocol::project;
use vela_protocol::proposals;
use vela_protocol::state;

pub(crate) fn cmd_proof(
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
pub(crate) fn cmd_proof_add(
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
        kind: "source_file".into(),
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

pub(crate) fn cmd_proof_verify(frontier: &Path, json_output: bool) {
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

pub(crate) fn cmd_proof_explain(frontier: &Path) {
    let text = frontier_repo::proof_explain(frontier).unwrap_or_else(|e| fail_return(&e));
    print!("{text}");
}

/// v0.151: handle `vela proof-attest-verification ...`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn cmd_proof_attest_verification(
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

    // Identity-resolution EXEMPTION (B2): `--key` stays mandatory here by
    // design. This records a THIRD-PARTY external verifier's signed output
    // (e.g. a CI Action's own key), which is deliberately NOT the operator's
    // `vela id` identity — defaulting it to the local profile would
    // mis-attribute the attestation. Keep the explicit key read.
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
pub(crate) fn cmd_proof_verify_attestation(record: PathBuf, json: bool) {
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

pub(crate) fn proof_load_path(frontier: &Path) -> PathBuf {
    if frontier.is_dir() {
        let compatibility_snapshot = frontier.join("frontier.json");
        if compatibility_snapshot.is_file() {
            return compatibility_snapshot;
        }
    }
    frontier.to_path_buf()
}
