//! Conformance test runner — validates an implementation against test vectors.
//!
//! Reads JSON test vector files from a directory and runs each case against
//! Vela's actual implementation, reporting pass/fail for each.

use std::path::Path;

use colored::Colorize;

use vela_protocol::cli_style as style;

use vela_protocol::bundle::*;
use vela_protocol::project;
use vela_protocol::propagate::{self, PropagationAction};

/// Run all conformance test vectors in the given directory.
/// Returns (passed, failed) counts.
pub fn run(dir: &Path) -> (usize, usize) {
    let mut passed = 0usize;
    let mut failed = 0usize;

    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| {
            eprintln!(
                "{} failed to read directory {}: {e}",
                style::err_prefix(),
                dir.display()
            );
            std::process::exit(1);
        })
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "json"))
        .collect();
    entries.sort_by_key(|e| e.path());

    if entries.is_empty() {
        eprintln!("no .json test vector files found in {}", dir.display());
        std::process::exit(1);
    }

    for entry in &entries {
        let path = entry.path();
        let content = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            eprintln!(
                "{} failed to read {}: {e}",
                style::err_prefix(),
                path.display()
            );
            std::process::exit(1);
        });
        let suite: serde_json::Value = serde_json::from_str(&content).unwrap_or_else(|e| {
            eprintln!(
                "{} failed to parse {}: {e}",
                style::err_prefix(),
                path.display()
            );
            std::process::exit(1);
        });

        let suite_name = suite["suite"].as_str().unwrap_or("unknown");
        let cases = suite["cases"].as_array();

        // Not a suite-vector file (e.g. `conformance/` also carries the
        // cross-impl contract files consumed by verify.py and the Rust
        // vector tests). Skip quietly; the summary line names the real
        // contract when nothing here is runnable.
        if cases.is_none() {
            continue;
        }

        println!();
        println!(
            "  {}",
            format!("SUITE · {suite_name}").to_uppercase().dimmed()
        );
        println!("  {}", style::tick_row(60));

        for case in cases.unwrap() {
            let name = case["name"].as_str().unwrap_or("unnamed");
            let input = &case["input"];
            let expected = &case["expected_output"];

            let result = match suite_name {
                "id-generation" => run_id_generation(input, expected),
                "retraction-propagation" => run_retraction_propagation(input, expected),
                "replication-cascade" => run_retraction_propagation(input, expected),
                "directory-layout" => run_directory_layout(input, expected),
                "proposal-idempotency" => run_proposal_idempotency(input, expected),
                "note-provenance" => run_proposal_idempotency(input, expected),
                "registry-publish-pull" => run_registry_publish_pull(input, expected),
                "auto-apply-tier" => run_auto_apply_tier(input, expected),
                _ => {
                    eprintln!("  {} unknown suite: {suite_name}", style::err_prefix());
                    Err("unknown suite".into())
                }
            };

            match result {
                Ok(()) => {
                    println!("  {} {name}", style::ok("ok"));
                    passed += 1;
                }
                Err(msg) => {
                    println!("  {} {name}: {msg}", style::lost("lost"));
                    failed += 1;
                }
            }
        }
    }

    println!();
    if passed == 0 && failed == 0 {
        println!(
            "  no runnable suite vectors in {} — the cross-impl conformance contract is `conformance/verify.py` (reducer fixtures) plus the Rust vector tests in `crates/vela-protocol/tests/`.",
            dir.display()
        );
    } else if failed == 0 {
        println!(
            "  {} all {passed} conformance tests passed.",
            style::ok("ok")
        );
    } else {
        println!(
            "  {} {passed} passed, {failed} failed.",
            style::lost("lost")
        );
    }

    (passed, failed)
}

// ── ID generation ───────────────────────────────────────────────────────

fn run_id_generation(
    input: &serde_json::Value,
    expected: &serde_json::Value,
) -> Result<(), String> {
    let assertion: Assertion = serde_json::from_value(input["assertion"].clone())
        .map_err(|e| format!("parse assertion: {e}"))?;
    let evidence: Evidence = serde_json::from_value(input["evidence"].clone())
        .map_err(|e| format!("parse evidence: {e}"))?;
    let conditions: Conditions = serde_json::from_value(input["conditions"].clone())
        .map_err(|e| format!("parse conditions: {e}"))?;
    let confidence: Confidence = serde_json::from_value(input["confidence"].clone())
        .map_err(|e| format!("parse confidence: {e}"))?;
    let provenance: Provenance = serde_json::from_value(input["provenance"].clone())
        .map_err(|e| format!("parse provenance: {e}"))?;

    let flags = if input.get("flags").is_some() {
        serde_json::from_value(input["flags"].clone()).unwrap_or_else(|_| default_flags())
    } else {
        default_flags()
    };

    let bundle = FindingBundle::new(
        assertion, evidence, conditions, confidence, provenance, flags,
    );

    let expected_id = expected["id"].as_str().ok_or("missing expected id")?;
    if bundle.id != expected_id {
        return Err(format!("expected {expected_id}, got {}", bundle.id));
    }

    if let Some(len) = expected["id_length"].as_u64()
        && bundle.id.len() != len as usize
    {
        return Err(format!("expected id length {len}, got {}", bundle.id.len()));
    }

    if let Some(prefix) = expected["prefix"].as_str()
        && !bundle.id.starts_with(prefix)
    {
        return Err(format!("expected prefix {prefix}, got {}", &bundle.id[..3]));
    }

    Ok(())
}

// ── Simulated dependency impact ─────────────────────────────────────────

fn run_retraction_propagation(
    input: &serde_json::Value,
    expected: &serde_json::Value,
) -> Result<(), String> {
    let findings_val = input["findings"]
        .as_array()
        .ok_or("missing findings array")?;

    let bundles: Vec<FindingBundle> = findings_val
        .iter()
        .map(|v| {
            let id = v["id"].as_str().unwrap_or("").to_string();
            let conf = v["confidence"].as_f64().unwrap_or(0.7);
            let links: Vec<Link> = v["links"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .map(|l| Link {
                            target: l["target"].as_str().unwrap_or("").to_string(),
                            link_type: l["type"].as_str().unwrap_or("depends").to_string(),
                            note: String::new(),
                            inferred_by: "test".into(),
                            created_at: String::new(),
                            mechanism: None,
                        })
                        .collect()
                })
                .unwrap_or_default();

            FindingBundle {
                id,
                version: 1,
                previous_version: None,
                assertion: Assertion {
                    text: "Test".into(),
                    assertion_type: "mechanism".into(),
                    entities: vec![],
                    relation: None,
                    direction: None,
                    causal_claim: None,
                    causal_evidence_grade: None,
                },
                evidence: Evidence {
                    evidence_type: "experimental".into(),
                    model_system: String::new(),
                    method: String::new(),
                    replicated: false,
                    replication_count: None,
                    evidence_spans: vec![],
                },
                conditions: Conditions {
                    text: String::new(),
                    duration: None,
                },
                confidence: Confidence::raw(conf, "test", 0.85),
                provenance: Provenance {
                    source_type: "published_paper".into(),
                    doi: None,
                    url: None,
                    title: "Test".into(),
                    authors: vec![],
                    year: Some(2025),
                    license: None,
                    publisher: None,
                    funders: vec![],
                    extraction: Extraction::default(),
                    review: None,
                },
                flags: default_flags(),
                links,
                annotations: vec![],
                attachments: vec![],
                created: String::new(),
                updated: None,
                access_tier: vela_protocol::access_tier::AccessTier::Public,
            }
        })
        .collect();

    let action_val = &input["action"];
    let finding_id = action_val["finding_id"].as_str().unwrap_or("");
    let action_type = action_val["type"].as_str().unwrap_or("");

    let mut corr = project::assemble("test", bundles, 1, 0, "test");

    let action = match action_type {
        "retracted" => PropagationAction::Retracted,
        "confidence_reduced" => {
            let new_score = action_val["new_score"].as_f64().unwrap_or(0.5);
            PropagationAction::ConfidenceReduced { new_score }
        }
        _ => return Err(format!("unknown action type: {action_type}")),
    };

    let result = propagate::propagate_correction(&mut corr, finding_id, action);

    if let Some(retracted) = expected["source_retracted"].as_bool()
        && retracted
    {
        let source = corr.findings.iter().find(|f| f.id == finding_id);
        if let Some(s) = source
            && !s.flags.retracted
        {
            return Err("source finding not marked as retracted".into());
        }
    }

    if let Some(count) = expected["affected_count"].as_u64()
        && result.affected != count as usize
    {
        return Err(format!(
            "expected {count} affected, got {}",
            result.affected
        ));
    }

    if let Some(max) = expected["affected_at_most"].as_u64()
        && result.affected > max as usize
    {
        return Err(format!(
            "expected at most {max} affected, got {}",
            result.affected
        ));
    }

    if let Some(conf) = expected["source_confidence"].as_f64() {
        let source = corr.findings.iter().find(|f| f.id == finding_id);
        if let Some(s) = source
            && (s.confidence.score - conf).abs() > 0.001
        {
            return Err(format!(
                "expected source confidence {conf}, got {}",
                s.confidence.score
            ));
        }
    }

    if let Some(contested) = expected["contested_findings"].as_array() {
        for cid in contested {
            let cid_str = cid.as_str().unwrap_or("");
            let f = corr.findings.iter().find(|f| f.id == cid_str);
            if let Some(f) = f {
                if !f.flags.contested {
                    return Err(format!("finding {cid_str} not marked as contested"));
                }
            } else {
                return Err(format!("finding {cid_str} not found"));
            }
        }
    }

    Ok(())
}

// ── Directory layout ────────────────────────────────────────────────────

fn run_directory_layout(
    input: &serde_json::Value,
    expected: &serde_json::Value,
) -> Result<(), String> {
    // This is a structural test — we verify the expected paths list is consistent
    // with the inputs, not against the filesystem.
    let finding_count = input["finding_count"].as_u64().unwrap_or(0) as usize;

    if let Some(paths) = expected["required_paths"].as_array() {
        // Must have .vela/config.toml
        let has_config = paths
            .iter()
            .any(|p| p.as_str() == Some(".vela/config.toml"));
        if !has_config {
            return Err("required_paths missing .vela/config.toml".into());
        }

        for required in [".vela/findings/", ".vela/events/", ".vela/proposals/"] {
            let present = paths.iter().any(|p| p.as_str() == Some(required));
            if finding_count == 0 && !present {
                return Err(format!("required_paths missing {required}"));
            }
        }

        // Count finding files.
        let finding_files: Vec<_> = paths
            .iter()
            .filter_map(|p| p.as_str())
            .filter(|p| p.starts_with(".vela/findings/vf_"))
            .collect();

        if finding_files.len() != finding_count {
            return Err(format!(
                "expected {} finding files, got {}",
                finding_count,
                finding_files.len()
            ));
        }
    }

    if let Some(count) = expected["finding_file_count"].as_u64()
        && count as usize != finding_count
    {
        return Err(format!(
            "finding_file_count {count} != input finding_count {finding_count}"
        ));
    }

    Ok(())
}

// ── Helpers ─────────────────────────────────────────────────────────────

fn default_flags() -> Flags {
    Flags::default()
}

// ── Phase U (v0.5): proposal-idempotency suite ─────────────────────────

fn run_proposal_idempotency(
    input: &serde_json::Value,
    expected: &serde_json::Value,
) -> Result<(), String> {
    use vela_protocol::proposals::{StateProposal, proposal_id};
    // Construct a proposal with a fixed `created_at`; the substrate
    // claim is that the resulting `vpr_…` does NOT depend on
    // `created_at`. To prove it, compute the id with two distinct
    // timestamps and assert equality.
    let mut proposal_a = StateProposal {
        schema: input["schema"].as_str().unwrap_or("").to_string(),
        id: String::new(),
        kind: input["kind"].as_str().unwrap_or("").into(),
        target: serde_json::from_value(input["target"].clone())
            .map_err(|e| format!("parse target: {e}"))?,
        actor: serde_json::from_value(input["actor"].clone())
            .map_err(|e| format!("parse actor: {e}"))?,
        created_at: "2026-01-01T00:00:00Z".to_string(),
        drafted_at: None,
        reason: input["reason"].as_str().unwrap_or("").to_string(),
        payload: input["payload"].clone(),
        source_refs: input["source_refs"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default(),
        status: "pending_review".to_string(),
        reviewed_by: None,
        reviewed_at: None,
        decision_reason: None,
        applied_event_id: None,
        caveats: input["caveats"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default(),
        agent_run: None,
    };
    let id_a = proposal_id(&proposal_a);

    let mut proposal_b = proposal_a.clone();
    proposal_b.created_at = "2099-12-31T23:59:59Z".to_string();
    let id_b = proposal_id(&proposal_b);

    if id_a != id_b {
        return Err(format!(
            "proposal_id depends on created_at: {id_a} vs {id_b}"
        ));
    }

    proposal_a.id = id_a.clone();
    let prefix = expected["prefix"].as_str().unwrap_or("vpr_");
    if !proposal_a.id.starts_with(prefix) {
        return Err(format!(
            "id '{}' does not start with '{prefix}'",
            proposal_a.id
        ));
    }
    if let Some(expected_len) = expected["id_length"].as_u64()
        && proposal_a.id.len() as u64 != expected_len
    {
        return Err(format!(
            "id length {} != expected {expected_len}",
            proposal_a.id.len()
        ));
    }
    if let Some(expected_id) = expected["id"].as_str()
        && proposal_a.id != expected_id
    {
        return Err(format!(
            "id '{}' != expected '{expected_id}'",
            proposal_a.id
        ));
    }
    Ok(())
}

// ── Phase δ (v0.6): auto-apply-tier suite ──────────────────────────────

fn run_auto_apply_tier(
    input: &serde_json::Value,
    expected: &serde_json::Value,
) -> Result<(), String> {
    use vela_protocol::sign::{ActorRecord, actor_can_auto_apply};
    let tier = input["tier"].as_str().map(String::from);
    let kind = input["kind"]
        .as_str()
        .ok_or("auto-apply-tier input missing `kind`")?;
    let actor = ActorRecord {
        id: "test".to_string(),
        public_key: "0".repeat(64),
        algorithm: "ed25519".to_string(),
        created_at: "2026-04-25T00:00:00Z".to_string(),
        tier,
        orcid: None,
        access_clearance: None,
        revoked_at: None,
        revoked_reason: None,
    };
    let actual = actor_can_auto_apply(&actor, kind);
    let want = expected["permits"]
        .as_bool()
        .ok_or("auto-apply-tier expected.permits must be a boolean")?;
    if actual != want {
        return Err(format!(
            "actor_can_auto_apply(tier={:?}, kind={}) returned {}; expected {}",
            input["tier"], kind, actual, want
        ));
    }
    Ok(())
}

// ── Phase U (v0.5): registry-publish-pull suite ────────────────────────

fn run_registry_publish_pull(
    input: &serde_json::Value,
    expected: &serde_json::Value,
) -> Result<(), String> {
    use sha2::{Digest, Sha256};
    use vela_protocol::registry::{RegistryEntry, entry_signing_bytes};
    let entry: RegistryEntry = serde_json::from_value({
        let mut v = input.clone();
        v["signature"] = serde_json::Value::String(String::new());
        v
    })
    .map_err(|e| format!("parse entry: {e}"))?;
    let bytes = entry_signing_bytes(&entry)?;
    let actual_hash = hex::encode(Sha256::digest(&bytes));
    if let Some(expected_hash) = expected["preimage_sha256"].as_str()
        && actual_hash != expected_hash
    {
        return Err(format!(
            "canonical preimage sha256 mismatch: actual={actual_hash}, expected={expected_hash}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_flags_are_all_false() {
        let f = default_flags();
        assert!(!f.gap);
        assert!(!f.retracted);
        assert!(!f.contested);
    }
}
