use crate::cli::{
    fail, fail_return, hash_path_or_fail, load_frontier_or_fail, print_json,
    save_recorded_proof_state,
};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use vela_edge::export;
use vela_edge::packet;
use vela_edge::signals;
use vela_protocol::frontier_repo;
use vela_protocol::project;
use vela_protocol::proposals;

pub(crate) fn cmd_proof(
    frontier: &Path,
    out: &Path,
    template: &str,
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

pub(crate) fn proof_load_path(frontier: &Path) -> PathBuf {
    if frontier.is_dir() {
        let compatibility_snapshot = frontier.join("frontier.json");
        if compatibility_snapshot.is_file() {
            return compatibility_snapshot;
        }
    }
    frontier.to_path_buf()
}
