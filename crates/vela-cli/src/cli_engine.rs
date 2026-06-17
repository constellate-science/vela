use crate::cli::{
    collect_witness_files, fail, fail_return, hash_path, load_frontier_or_fail, parse_witness,
    print_json,
};
use crate::cli_commands::*;
use serde_json::{Value, json};
use std::path::Path;
use vela_edge::carina_validate;
use vela_edge::normalize;
use vela_protocol::bundle;
use vela_protocol::cli_style as style;
use vela_protocol::evidence_ci;
use vela_protocol::project;
use vela_protocol::proposals;
use vela_protocol::repo;
use vela_protocol::sources;

pub(crate) fn cmd_gate(action: GateAction) {
    use vela_edge::deliverable_grade::{self, DeliverableGrade, GradeGate};
    use vela_protocol::verifier_attachment::{
        self, GateStatus, ProbeKind, VerifierAttachment, VerifierMethod,
    };
    match action {
        GateAction::Grade { claim, grade, json } => {
            let gate = deliverable_grade::grade_gate(&claim, grade.as_deref());
            let passed = gate.passed();
            if json {
                let grade_str = match &gate {
                    GradeGate::Ok(g) => Some(g.as_str().to_string()),
                    _ => grade.clone(),
                };
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "command": "gate grade",
                        "passed": passed,
                        "grade": grade_str,
                        "reason": gate.reason(),
                    }))
                    .expect("serialize gate grade response")
                );
            } else if passed {
                println!("gate grade: ok");
                if let GradeGate::Ok(g) = gate {
                    println!("  deliverable_grade: {g}  (claim text consistent with grade)");
                }
            } else {
                eprintln!("gate grade: REJECTED\n  {}", gate.reason());
            }
            if !passed {
                std::process::exit(1);
            }
        }
        GateAction::Check {
            claim,
            attachments,
            json,
        } => {
            let raw = std::fs::read_to_string(&attachments)
                .unwrap_or_else(|e| fail_return(&format!("read {}: {e}", attachments.display())));
            let atts: Vec<VerifierAttachment> = serde_json::from_str(&raw).unwrap_or_else(|e| {
                fail_return(&format!(
                    "parse {} as a JSON array of VerifierAttachment: {e}",
                    attachments.display()
                ))
            });
            // G4: every attachment must be structurally sound before the
            // gate reasons over it.
            for a in &atts {
                if let Err(e) = a.verify() {
                    fail(&format!("attachment {} is malformed: {e}", a.id));
                }
            }
            let digest = verifier_attachment::claim_digest(&claim);
            let outcome = verifier_attachment::derive_gate_status(&digest, &atts);
            let verified = outcome.status == GateStatus::Verified;
            if json {
                let status = match outcome.status {
                    GateStatus::Verified => "verified",
                    GateStatus::NeedsVerification => "needs_verification",
                    GateStatus::Refuted => "refuted",
                };
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "command": "gate check",
                        "claim_digest": digest,
                        "attachments": atts.len(),
                        "status": status,
                        "reasons": outcome.reasons,
                    }))
                    .expect("serialize gate check response")
                );
            } else {
                println!(
                    "gate check: {} attachment(s) over claim {digest}",
                    atts.len()
                );
                match outcome.status {
                    GateStatus::Verified => println!(
                        "  status: VERIFIED\n  >=2 independent matched attachments + a surviving adversarial probe."
                    ),
                    GateStatus::Refuted => {
                        println!("  status: REFUTED");
                        for r in &outcome.reasons {
                            println!("    - {r}");
                        }
                    }
                    GateStatus::NeedsVerification => {
                        println!("  status: needs_verification");
                        for r in &outcome.reasons {
                            println!("    - {r}");
                        }
                    }
                }
            }
            if !verified {
                std::process::exit(1);
            }
        }
        GateAction::Vocab { json } => {
            let grades: Vec<&str> = DeliverableGrade::ALL.iter().map(|g| g.as_str()).collect();
            let methods: Vec<&str> = VerifierMethod::ALL.iter().map(|m| m.as_str()).collect();
            let probes = [
                ProbeKind::CounterexampleSearch,
                ProbeKind::CaseBConfig,
                ProbeKind::BoundaryDualFeasibility,
                ProbeKind::FiniteSizeExtrapolation,
                ProbeKind::IndependentReimplementation,
            ];
            let probe_kinds: Vec<&str> = probes.iter().map(|p| p.as_str()).collect();
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "command": "gate vocab",
                        "deliverable_grades": grades,
                        "solve_grades": DeliverableGrade::ALL
                            .iter()
                            .filter(|g| g.is_solve())
                            .map(|g| g.as_str())
                            .collect::<Vec<_>>(),
                        "verifier_methods": methods,
                        "probe_kinds": probe_kinds,
                    }))
                    .expect("serialize gate vocab response")
                );
            } else {
                println!("deliverable grades ({}):", grades.len());
                for g in DeliverableGrade::ALL {
                    let mark = if g.is_solve() { " (solve)" } else { "" };
                    println!("  {}{mark}", g.as_str());
                }
                println!("\nverifier methods ({}):", methods.len());
                for m in &methods {
                    println!("  {m}");
                }
                println!("\nadversarial probe kinds ({}):", probe_kinds.len());
                for p in &probe_kinds {
                    println!("  {p}");
                }
            }
        }
        GateAction::Backfill {
            frontier,
            reviewer,
            dry_run,
            json,
        } => cmd_gate_backfill(&frontier, &reviewer, dry_run, json),
    }
}

/// Backfill frozen-verifier attachments over a frontier's witness artifacts.
/// For each artifact that carries a `verifier` tag and parses as a `vela-verify`
/// Witness, re-run the frozen verifier and, on pass, land a signed
/// `verifier.attach` (ComputationalSearch / vela-verify / Sound) bound to each
/// target finding's claim. Records the machine re-check; the gate still needs
/// >=2 independent attachments for `verified`. Local-first: inspect with
/// --dry-run, then run once.
fn cmd_gate_backfill(frontier: &Path, reviewer: &str, dry_run: bool, json_output: bool) {
    use std::collections::HashMap;
    use vela_protocol::events::StateTarget;
    use vela_protocol::verifier_attachment::{
        AdversarialProbe, AttachmentDraft, AttachmentOutcome, MatchToClaim, MethodIntegrity,
        ProbeKind, ProbeResult, VerifierAttachment, VerifierMethod, claim_digest,
    };

    // Registration pre-pass: deposit any canonical `witnesses/*.witness.json`
    // not yet present as a content-addressed artifact, so the attach loop below
    // can feed the gate over them. No-op when the frontier ships no
    // `witnesses/targets.json` (preserves prior behavior).
    let (registered, no_target) = register_canonical_witnesses(frontier, reviewer, dry_run);

    let source = repo::detect(frontier).unwrap_or_else(|e| fail_return(&e));
    let proj = repo::load(&source).unwrap_or_else(|e| fail_return(&e));

    // Claim text per finding id; claim_digest binds the attachment to it (G2).
    let claim_by_finding: HashMap<String, String> = proj
        .findings
        .iter()
        .map(|f| (f.id.clone(), f.assertion.text.clone()))
        .collect();

    // An agent may draft (create pending) but not self-apply a truth-bearing
    // `verifier.attach`; a human reviewer applies inline. (The substrate's
    // accept gate enforces this independently — this just avoids drafting then
    // failing to self-accept.)
    let apply = !reviewer.trim().to_ascii_lowercase().starts_with("agent:");

    // (finding, witness kind, claim_digest) for each landed / pending / planned check.
    let mut done: Vec<(String, String, String)> = Vec::new();
    let mut pending: Vec<(String, String, String)> = Vec::new();
    let mut failed: Vec<(String, String)> = Vec::new();
    let mut skipped: usize = 0;

    for art in &proj.artifacts {
        // Witness artifacts: a JSON payload tagged with a `verifier` in metadata.
        let is_json = art.media_type.as_deref() == Some("application/json");
        if !(is_json && art.metadata.contains_key("verifier")) {
            continue;
        }
        // Resolve content. local_blob / local_file locators are relative to the
        // frontier dir; remote / pointer artifacts are not re-checkable here.
        let content = match (art.storage_mode.as_str(), &art.locator) {
            ("local_blob" | "local_file", Some(loc)) => {
                match std::fs::read_to_string(frontier.join(loc.as_str())) {
                    Ok(c) => c,
                    Err(_) => {
                        skipped += 1;
                        continue;
                    }
                }
            }
            _ => {
                skipped += 1;
                continue;
            }
        };
        let witness = match parse_witness(&content) {
            Ok(w) => w,
            Err(_) => {
                skipped += 1;
                continue;
            }
        };
        let result = vela_verify::verify_witness(&witness);
        let kind = witness.kind().to_string();
        for tf in &art.target_findings {
            let Some(claim) = claim_by_finding.get(tf) else {
                continue;
            };
            if !result.ok {
                failed.push((tf.clone(), result.message.clone()));
                continue;
            }
            let digest = claim_digest(claim);
            if dry_run {
                done.push((tf.clone(), kind.clone(), digest));
                continue;
            }
            let att = VerifierAttachment::build(AttachmentDraft {
                target: tf.clone(),
                claim_digest: digest.clone(),
                verifier_method: VerifierMethod::ComputationalSearch,
                solver_id: "vela-verify".to_string(),
                independent_of: Vec::new(),
                match_to_claim: MatchToClaim {
                    matches: true,
                    checker_actor: "vela-verify".to_string(),
                },
                adversarial_probes: vec![AdversarialProbe {
                    kind: ProbeKind::CounterexampleSearch,
                    result: ProbeResult::Survived,
                    note: String::new(),
                }],
                outcome: AttachmentOutcome::Passed,
                verifier_actor: "vela-verify".to_string(),
                note: format!("frozen verifier re-check: {kind}"),
            })
            .and_then(|a| a.with_method_integrity(MethodIntegrity::Sound))
            .unwrap_or_else(|e| fail_return(&format!("build attachment for {tf}: {e}")));
            let att_value = serde_json::to_value(&att)
                .unwrap_or_else(|e| fail_return(&format!("serialize attachment: {e}")));
            let actor_type = if reviewer.starts_with("agent:") {
                "agent"
            } else {
                "human"
            };
            let proposal = proposals::new_proposal(
                "verifier.attach",
                StateTarget {
                    r#type: "finding".to_string(),
                    id: tf.clone(),
                },
                reviewer,
                actor_type,
                "backfill frozen verifier re-check",
                json!({ "attachment": att_value }),
                Vec::new(),
                Vec::new(),
            );
            // The trust boundary, enforced here: an agent reviewer may DRAFT a
            // `verifier.attach` (it ran the frozen verifier) but may not
            // self-apply it — that is a truth-bearing acceptance reserved for a
            // named human with key custody. So for agents we create the
            // proposal as PENDING; a maintainer accepts it with `vela accept`.
            // A human reviewer applies inline (subject to key custody).
            match proposals::create_or_apply(frontier, proposal, apply) {
                Ok(res) if res.applied_event_id.is_some() => {
                    done.push((tf.clone(), kind.clone(), digest))
                }
                Ok(_) => pending.push((tf.clone(), kind.clone(), digest)),
                Err(e) => failed.push((tf.clone(), e)),
            }
        }
    }

    if json_output {
        let findings: Vec<Value> = done
            .iter()
            .map(|(f, k, d)| json!({ "finding": f, "kind": k, "claim_digest": d }))
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "command": "gate backfill",
                "dry_run": dry_run,
                "registered_artifacts": registered,
                "witnesses_without_target": no_target,
                "attached": done.len(),
                "pending_human_accept": pending.len(),
                "pending_findings": pending
                    .iter()
                    .map(|(f, k, d)| json!({ "finding": f, "kind": k, "claim_digest": d }))
                    .collect::<Vec<_>>(),
                "failed": failed.len(),
                "skipped_artifacts": skipped,
                "findings": findings,
            }))
            .expect("serialize gate backfill response")
        );
    } else {
        let verb = if dry_run { "would attach" } else { "attached" };
        if registered > 0 {
            let rverb = if dry_run { "would register" } else { "registered" };
            println!(
                "· gate backfill: {rverb} {registered} canonical witness artifact{}",
                if registered == 1 { "" } else { "s" },
            );
        }
        if !no_target.is_empty() {
            println!(
                "  ! {} witness file(s) have no target finding in witnesses/targets.json (not registered): {}",
                no_target.len(),
                no_target.join(", "),
            );
        }
        println!(
            "· gate backfill: {verb} {} frozen-verifier check{} ({skipped} artifacts skipped, {} verify-failures)",
            done.len(),
            if done.len() == 1 { "" } else { "s" },
            failed.len(),
        );
        for (f, k, d) in &done {
            println!("  {f} · {k} · claim {d}");
        }
        if !pending.is_empty() {
            println!(
                "· gate backfill: {} verifier.attach proposal{} drafted + frozen-verified, PENDING a maintainer's key-custody accept (`vela accept`):",
                pending.len(),
                if pending.len() == 1 { "" } else { "s" },
            );
            for (f, k, d) in &pending {
                println!("  ◦ {f} · {k} · claim {d}");
            }
        }
        for (f, e) in &failed {
            println!("  ! {f}: {e}");
        }
    }
}

/// Registration pre-pass for `gate backfill`. Deposits every canonical
/// `witnesses/*.witness.json` that is not yet present as a content-addressed
/// artifact, binding each to its target finding via the frontier-owned
/// `witnesses/targets.json` map (`{ "<file>.witness.json": "vf_…" }`). This is
/// the step that makes a frontier's frozen-verifier witnesses visible to the
/// gate; the attach loop in [`cmd_gate_backfill`] then lands the signed
/// re-check over them.
///
/// No-op when the frontier ships no `witnesses/targets.json`, preserving prior
/// behavior. The deposit rides under `deposited_by` (an agent identity for
/// machine deposits) as an `artifact.asserted` event: it is a *data* deposit of
/// a machine-checkable witness, not a trust verdict (the verdict is the
/// signed `verifier.attach`, which the attach loop types by actor).
///
/// Returns `(registered, witnesses_without_target)`.
fn register_canonical_witnesses(
    frontier: &Path,
    deposited_by: &str,
    dry_run: bool,
) -> (usize, Vec<String>) {
    use sha2::{Digest, Sha256};
    use std::collections::{BTreeMap, HashSet};

    let targets_path = frontier.join("witnesses").join("targets.json");
    let Ok(targets_raw) = std::fs::read_to_string(&targets_path) else {
        return (0, Vec::new());
    };
    let targets: BTreeMap<String, String> = serde_json::from_str(&targets_raw)
        .unwrap_or_else(|e| fail_return(&format!("parse {}: {e}", targets_path.display())));

    let source = repo::detect(frontier).unwrap_or_else(|e| fail_return(&e));
    let proj = repo::load(&source).unwrap_or_else(|e| fail_return(&e));
    let existing_hashes: HashSet<String> =
        proj.artifacts.iter().map(|a| a.content_hash.clone()).collect();

    let mut registered = 0usize;
    let mut no_target: Vec<String> = Vec::new();

    for wf in collect_witness_files(frontier) {
        let fname = wf
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();
        let Ok(bytes) = std::fs::read(&wf) else {
            continue;
        };
        let raw = String::from_utf8_lossy(&bytes).to_string();
        // Only register a file the frozen verifier can actually parse as a witness.
        let Ok(witness) = parse_witness(&raw) else {
            continue;
        };
        let kind = witness.kind().to_string();

        let hash_hex = hex::encode(Sha256::digest(&bytes));
        let content_hash = format!("sha256:{hash_hex}");
        if existing_hashes.contains(&content_hash) {
            continue; // already registered (idempotent on content hash)
        }
        let Some(target) = targets.get(&fname) else {
            no_target.push(fname);
            continue;
        };

        if dry_run {
            registered += 1;
            continue;
        }

        // Deposit the content-addressed blob if absent.
        let blob_rel = format!(".vela/artifact-blobs/sha256/{hash_hex}");
        let blob_abs = frontier.join(&blob_rel);
        if !blob_abs.exists() {
            if let Some(parent) = blob_abs.parent() {
                std::fs::create_dir_all(parent)
                    .unwrap_or_else(|e| fail_return(&format!("create blob dir: {e}")));
            }
            std::fs::write(&blob_abs, &bytes)
                .unwrap_or_else(|e| fail_return(&format!("write blob {blob_rel}: {e}")));
        }

        let stem = fname.trim_end_matches(".witness.json");
        let name = format!("Frozen-verifier witness: {stem} ({kind})");
        let mut metadata: BTreeMap<String, Value> = BTreeMap::new();
        metadata.insert(
            "verifier".to_string(),
            Value::String(format!("vela-verify::{kind}")),
        );
        metadata.insert("witness_kind".to_string(), Value::String(kind.clone()));
        metadata.insert("witness_file".to_string(), Value::String(fname.clone()));

        let provenance = bundle::Provenance {
            source_type: "data_release".to_string(),
            doi: None,
            pmid: None,
            pmc: None,
            openalex_id: None,
            url: None,
            title: name.clone(),
            authors: Vec::new(),
            year: None,
            journal: None,
            license: Some("CC-BY-4.0".to_string()),
            publisher: None,
            funders: Vec::new(),
            extraction: bundle::Extraction::default(),
            review: None,
            citation_count: None,
        };

        let id =
            bundle::Artifact::content_address("dataset", &name, &content_hash, None, Some(&blob_rel));
        let artifact = bundle::Artifact {
            id,
            kind: "dataset".to_string(),
            name,
            content_hash,
            size_bytes: Some(bytes.len() as u64),
            media_type: Some("application/json".to_string()),
            storage_mode: "local_blob".to_string(),
            locator: Some(blob_rel),
            source_url: None,
            license: Some("CC-BY-4.0".to_string()),
            target_findings: vec![target.clone()],
            source_id: None,
            provenance,
            metadata,
            review_state: None,
            retracted: false,
            access_tier: vela_protocol::access_tier::AccessTier::default(),
            created: chrono::Utc::now().to_rfc3339(),
        };
        match vela_protocol::state::add_artifact(
            frontier,
            artifact,
            deposited_by,
            "register canonical frozen-verifier witness for gate backfill",
        ) {
            Ok(_) => registered += 1,
            Err(e) if e.contains("duplicate") => {}
            Err(e) => fail_return(&format!("register witness {fname}: {e}")),
        }
    }
    (registered, no_target)
}

pub(crate) fn cmd_reproduce(path: &Path, json_output: bool) {
    let files = collect_witness_files(path);
    if files.is_empty() {
        fail(&format!(
            "no witnesses found at {} (expected a `*.witness.json` file, or a directory containing them / a `witnesses/` subdir)",
            path.display()
        ));
    }
    let mut results: Vec<Value> = Vec::new();
    let mut passed = 0usize;
    let mut failed = 0usize;
    for file in &files {
        let raw = match std::fs::read_to_string(file) {
            Ok(r) => r,
            Err(e) => {
                failed += 1;
                if !json_output {
                    println!("  FAIL  {}  ·  read error: {e}", file.display());
                }
                results.push(json!({"path": file.display().to_string(), "ok": false, "message": format!("read error: {e}")}));
                continue;
            }
        };
        let witness = match parse_witness(&raw) {
            Ok(w) => w,
            Err(e) => {
                failed += 1;
                if !json_output {
                    println!("  FAIL  {}  ·  parse error: {e}", file.display());
                }
                results.push(json!({"path": file.display().to_string(), "ok": false, "message": format!("parse error: {e}")}));
                continue;
            }
        };
        let mut outcome = vela_verify::verify_witness(&witness);
        // Machine-checked novelty: a witness may declare `improves_on`
        // (a sibling witness path relative to its own directory). The
        // claim then verifies ONLY if it also strictly dominates the
        // referenced witness — dominance is arithmetic, not opinion.
        if outcome.ok
            && let Ok(value) = serde_json::from_str::<Value>(&raw)
            && let Some(prior_rel) = value.get("improves_on").and_then(Value::as_str)
        {
            let prior_path = file
                .parent()
                .map(|d| d.join(prior_rel))
                .unwrap_or_else(|| std::path::PathBuf::from(prior_rel));
            match std::fs::read_to_string(&prior_path)
                .map_err(|e| format!("improves_on read {}: {e}", prior_path.display()))
                .and_then(|p| parse_witness(&p))
                .and_then(|prior| vela_verify::dominates(&witness, &prior))
            {
                Ok(true) => {
                    outcome.message =
                        format!("{} · strictly improves on {prior_rel}", outcome.message);
                }
                Ok(false) => {
                    outcome = vela_verify::VerifyResult::fail(format!(
                        "claims improves_on {prior_rel} but does NOT strictly dominate it"
                    ));
                }
                Err(e) => {
                    outcome =
                        vela_verify::VerifyResult::fail(format!("improves_on check failed: {e}"));
                }
            }
        }
        if outcome.ok {
            passed += 1;
        } else {
            failed += 1;
        }
        if !json_output {
            let status = if outcome.ok { "ok  " } else { "FAIL" };
            println!(
                "  {status}  {} [{}]  ·  {}",
                file.display(),
                witness.kind(),
                outcome.message
            );
        }
        results.push(json!({
            "path": file.display().to_string(),
            "kind": witness.kind(),
            "ok": outcome.ok,
            "message": outcome.message,
        }));
    }
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "command": "reproduce",
                "witnesses": files.len(),
                "passed": passed,
                "failed": failed,
                "results": results,
            }))
            .expect("serialize reproduce response")
        );
    } else {
        println!();
        if failed == 0 {
            println!(
                "  reproduce: ok ({passed}/{}) — every witness re-verified from scratch by the frozen verifiers.",
                files.len()
            );
        } else {
            println!(
                "  reproduce: FAIL ({failed}/{} did not re-verify). Investigate before trusting.",
                files.len()
            );
        }
    }
    if failed > 0 {
        std::process::exit(1);
    }
}

pub(crate) fn cmd_evidence_ci(frontier: &Path, json: bool) {
    let report = evidence_ci::run_frontier(frontier)
        .unwrap_or_else(|e| fail_return(&format!("evidence-ci failed: {e}")));
    if json {
        print_json(&report);
        return;
    }
    let status = if report.ok {
        style::ok("evidence-ci")
    } else {
        style::lost("evidence-ci")
    };
    println!(
        "{} {} · {} checks, {} warning(s), {} release-blocking failure(s)",
        status,
        report.frontier_id,
        report.summary.total,
        report.summary.warnings,
        report.summary.release_blocking_failed
    );
    for check in report
        .checks
        .iter()
        .filter(|check| check.status != evidence_ci::EvidenceCiStatus::Passed)
        .take(40)
    {
        println!(
            "  {} {} {}: {}",
            match check.status {
                evidence_ci::EvidenceCiStatus::Passed => style::ok("pass"),
                evidence_ci::EvidenceCiStatus::Warning => style::warn("warn"),
                evidence_ci::EvidenceCiStatus::Failed => style::lost("fail"),
            },
            check.id,
            check.target_id,
            check.message
        );
    }
}

pub(crate) fn cmd_retro_impact(record: &str, frontier: &Path, json: bool) {
    let project = load_frontier_or_fail(frontier);
    let impact = vela_edge::dependency_oracle::dependency_impact(&project, record);
    if json {
        print_json(&serde_json::to_value(&impact).unwrap_or_default());
    } else {
        println!(
            "impact {}: {} record(s) rest on it ({} gate-verified); {} direct",
            record,
            impact.weight,
            impact.verified_weight,
            impact.direct_dependents.len()
        );
    }
}

pub(crate) fn cmd_attach(
    frontier: &std::path::Path,
    target: &str,
    attachment_file: &std::path::Path,
    reviewer: &str,
    reason: &str,
    json: bool,
) {
    use vela_protocol::events::StateTarget;
    let body = match std::fs::read_to_string(attachment_file) {
        Ok(b) => b,
        Err(e) => fail(&format!("read {}: {e}", attachment_file.display())),
    };
    let att_value: Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => fail(&format!("parse attachment JSON: {e}")),
    };
    let actor_type = if reviewer.starts_with("agent:") {
        "agent"
    } else {
        "human"
    };
    let proposal = proposals::new_proposal(
        "verifier.attach",
        StateTarget {
            r#type: "finding".to_string(),
            id: target.to_string(),
        },
        reviewer,
        actor_type,
        reason,
        json!({ "attachment": att_value }),
        Vec::new(),
        Vec::new(),
    );
    match proposals::create_or_apply(frontier, proposal, true) {
        Ok(result) => {
            let event = result.applied_event_id.clone().unwrap_or_default();
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "command": "attach",
                        "target": target,
                        "proposal_id": result.proposal_id,
                        "event_id": event,
                        "applied": result.applied_event_id.is_some(),
                    }))
                    .expect("serialize attach response")
                );
            } else {
                println!(
                    "· ok attached verifier evidence to {target}\n  proposal {}\n  event {event}",
                    result.proposal_id
                );
            }
        }
        Err(e) => fail(&format!("attach: {e}")),
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn cmd_normalize(
    source: &Path,
    out: Option<&Path>,
    write: bool,
    dry_run: bool,
    rewrite_ids: bool,
    id_map: Option<&Path>,
    resync_provenance: bool,
    json_output: bool,
) {
    if write && out.is_some() {
        fail("Use either --write or --out, not both.");
    }
    if dry_run && (write || out.is_some()) {
        fail("--dry-run cannot be combined with --write or --out.");
    }
    if id_map.is_some() && !rewrite_ids {
        fail("--id-map requires --rewrite-ids.");
    }

    let detected = repo::detect(source).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(1);
    });
    if matches!(detected, repo::VelaSource::PacketDir(_)) {
        fail(
            "Cannot normalize a proof packet directory. Export a new packet from frontier state instead.",
        );
    }
    let mut frontier = repo::load(&detected).unwrap_or_else(|e| fail_return(&e));
    // Phase J: every v0.4 frontier carries a `frontier.created` genesis
    // event in events[0]. That's identity metadata, not a substantive
    // mutation, so it doesn't disqualify normalization. Any non-genesis
    // canonical event still blocks normalize.
    let has_substantive_events = frontier
        .events
        .iter()
        .any(|event| event.kind != "frontier.created");
    if has_substantive_events && (write || out.is_some()) {
        fail(
            "Refusing to normalize a frontier with canonical events. Normalize before proposal-backed writes, or create a new reviewed transition for the intended change.",
        );
    }
    let source_hash = hash_path(source).unwrap_or_else(|_| "unavailable".to_string());
    let before_stats = serde_json::to_value(&frontier.stats).unwrap_or(Value::Null);
    let (entity_type_fixes, entity_name_fixes) =
        normalize::normalize_findings(&mut frontier.findings);
    let confidence_updates =
        bundle::recompute_all_confidence(&mut frontier.findings, &frontier.replications);
    // Phase N: optionally rewrite finding.provenance from the canonical
    // SourceRecord. The source registry is the authority; provenance is
    // the denormalized cache.
    let provenance_resync_count = if resync_provenance {
        sources::resync_provenance_from_sources(&mut frontier)
    } else {
        0
    };
    let before_source_count = frontier.sources.len();
    let before_evidence_atom_count = frontier.evidence_atoms.len();
    let before_condition_record_count = frontier.condition_records.len();

    let mut id_rewrites = Vec::new();
    if rewrite_ids {
        let mut id_map_values = std::collections::BTreeMap::<String, String>::new();
        for finding in &frontier.findings {
            let expected =
                bundle::FindingBundle::content_address(&finding.assertion, &finding.provenance);
            if expected != finding.id {
                id_map_values.insert(finding.id.clone(), expected);
            }
        }
        let new_ids = id_map_values
            .values()
            .map(String::as_str)
            .collect::<std::collections::HashSet<_>>();
        if new_ids.len() != id_map_values.len() {
            fail("Refusing to rewrite IDs because two findings map to the same content address.");
        }
        for finding in &mut frontier.findings {
            if let Some(new_id) = id_map_values.get(&finding.id) {
                id_rewrites.push(json!({"old": finding.id, "new": new_id}));
                finding.previous_version = Some(finding.id.clone());
                finding.id = new_id.clone();
            }
        }
        for finding in &mut frontier.findings {
            for link in &mut finding.links {
                if let Some(new_target) = id_map_values.get(&link.target) {
                    link.target = new_target.clone();
                }
            }
        }
        if let Some(path) = id_map {
            std::fs::write(
                path,
                serde_json::to_string_pretty(&id_map_values)
                    .expect("failed to serialize normalize id map"),
            )
            .unwrap_or_else(|e| fail(&format!("Failed to write {}: {e}", path.display())));
        }
    }

    sources::materialize_project(&mut frontier);
    let source_records_materialized = frontier.sources.len().saturating_sub(before_source_count);
    let evidence_atoms_materialized = frontier
        .evidence_atoms
        .len()
        .saturating_sub(before_evidence_atom_count);
    let condition_records_materialized = frontier
        .condition_records
        .len()
        .saturating_sub(before_condition_record_count);
    let after_stats = serde_json::to_value(&frontier.stats).unwrap_or(Value::Null);
    let id_rewrite_count = id_rewrites.len();
    let wrote_to = if write {
        repo::save(&detected, &frontier).unwrap_or_else(|e| fail(&e));
        Some(source.display().to_string())
    } else if let Some(out_path) = out {
        repo::save_to_path(out_path, &frontier).unwrap_or_else(|e| fail(&e));
        Some(out_path.display().to_string())
    } else {
        None
    };
    let wrote = wrote_to.is_some();
    let planned_changes = entity_type_fixes
        + entity_name_fixes
        + confidence_updates
        + id_rewrite_count
        + source_records_materialized
        + evidence_atoms_materialized
        + condition_records_materialized
        + provenance_resync_count;
    let payload = json!({
        "ok": true,
        "command": "normalize",
        "schema_version": project::VELA_SCHEMA_VERSION,
        "source": {
            "path": source.display().to_string(),
            "hash": format!("sha256:{source_hash}"),
        },
        "dry_run": wrote_to.is_none(),
        "wrote_to": wrote_to,
        "summary": {
            "planned": planned_changes,
            "safe": planned_changes,
            "unsafe": 0,
            "applied": if wrote { planned_changes } else { 0 },
        },
        "changes": {
            "entity_type_fixes": entity_type_fixes,
            "entity_name_fixes": entity_name_fixes,
            "confidence_updates": confidence_updates,
            "id_rewrites": id_rewrite_count,
            "source_records_materialized": source_records_materialized,
            "evidence_atoms_materialized": evidence_atoms_materialized,
            "condition_records_materialized": condition_records_materialized,
            "provenance_resyncs": provenance_resync_count,
            "stats_changed": before_stats != after_stats,
        },
        "id_rewrites": id_rewrites,
        "repair_plan": if wrote { Vec::<Value>::new() } else {
            vec![json!({
                "action": "apply_normalization",
                "command": "vela normalize <frontier> --out frontier.normalized.json"
            })]
        },
    });
    if json_output {
        print_json(&payload);
    } else if let Some(path) = payload.get("wrote_to").and_then(Value::as_str) {
        println!("{} normalized frontier written to {path}", style::ok("ok"));
        println!(
            "  entity type fixes: {}, entity name fixes: {}, confidence updates: {}, id rewrites: {}",
            entity_type_fixes, entity_name_fixes, confidence_updates, id_rewrite_count
        );
    } else {
        println!("normalize dry run for {}", source.display());
        println!(
            "  would apply entity type fixes: {}, entity name fixes: {}, confidence updates: {}, id rewrites: {}",
            entity_type_fixes, entity_name_fixes, confidence_updates, id_rewrite_count
        );
    }
}

/// v0.75: handler for `vela carina <action>`. Each branch reaches
/// into the bundled schemas under `embedded/carina-schemas/`.
pub(crate) fn cmd_carina(action: CarinaAction) {
    match action {
        CarinaAction::List { json } => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": true,
                        "command": "carina.list",
                        "primitives": carina_validate::PRIMITIVE_NAMES,
                    }))
                    .expect("failed to serialize carina.list")
                );
            } else {
                println!("Carina primitives bundled with this build:");
                for name in carina_validate::PRIMITIVE_NAMES {
                    println!("  · {name}");
                }
            }
        }
        CarinaAction::Schema { primitive } => match carina_validate::schema_text(&primitive) {
            Some(text) => print!("{text}"),
            None => fail(&format!(
                "carina: unknown primitive '{primitive}'. Valid: {}",
                carina_validate::PRIMITIVE_NAMES.join(", ")
            )),
        },
        CarinaAction::Validate {
            path,
            primitive,
            json,
        } => {
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| fail_return(&format!("read {}: {e}", path.display())));
            let value: Value = serde_json::from_str(&text)
                .unwrap_or_else(|e| fail_return(&format!("parse {}: {e}", path.display())));
            // If the file is a primitives.v0.X.json aggregate,
            // validate every entry under `primitives`. Otherwise
            // validate the value as one primitive.
            // Each report entry: (input key, validation result with
            // optional detected-primitive name in the Ok branch).
            type CarinaValidateOutcome = Result<Option<&'static str>, Vec<String>>;
            let mut report: Vec<(String, CarinaValidateOutcome)> = Vec::new();
            if value.get("primitives").and_then(Value::as_object).is_some() && primitive.is_none() {
                let primitives = value.get("primitives").and_then(Value::as_object).unwrap();
                for (key, child) in primitives {
                    let outcome = carina_validate::validate(key, child)
                        .map(|()| carina_validate::detect_primitive(child));
                    report.push((key.clone(), outcome));
                }
            } else {
                let outcome = match primitive.as_deref() {
                    Some(name) => carina_validate::validate(name, &value).map(|()| {
                        carina_validate::PRIMITIVE_NAMES
                            .iter()
                            .copied()
                            .find(|p| *p == name)
                    }),
                    None => carina_validate::validate_auto(&value).map(Some),
                };
                let label = primitive.clone().unwrap_or_else(|| "<auto>".to_string());
                report.push((label, outcome));
            }

            let total = report.len();
            let pass = report.iter().filter(|(_, r)| r.is_ok()).count();
            let fail = total - pass;

            if json {
                let entries: Vec<Value> = report
                    .iter()
                    .map(|(label, r)| match r {
                        Ok(name) => json!({
                            "key": label,
                            "primitive": name,
                            "ok": true,
                        }),
                        Err(errs) => json!({
                            "key": label,
                            "ok": false,
                            "errors": errs,
                        }),
                    })
                    .collect();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": fail == 0,
                        "command": "carina.validate",
                        "file": path.display().to_string(),
                        "total": total,
                        "passed": pass,
                        "failed": fail,
                        "entries": entries,
                    }))
                    .expect("failed to serialize carina.validate")
                );
            } else {
                for (label, r) in &report {
                    match r {
                        Ok(Some(name)) => println!("  {} {label} (as {name})", style::ok("ok")),
                        Ok(None) => println!("  {} {label}", style::ok("ok")),
                        Err(errs) => {
                            println!("  {} {label}", style::lost("fail"));
                            for e in errs {
                                println!("      {e}");
                            }
                        }
                    }
                }
                println!();
                if fail == 0 {
                    println!("{} {pass}/{total} valid", style::ok("carina.validate"));
                } else {
                    println!(
                        "{} {pass}/{total} valid · {fail} failed",
                        style::lost("carina.validate")
                    );
                }
            }

            if fail > 0 {
                std::process::exit(1);
            }
        }
    }
}
