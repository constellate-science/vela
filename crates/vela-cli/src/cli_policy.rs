//! `vela policy` — policy-bound acceptance, the human-governance friction fix.
//!
//! A human signs ONE scoped `AcceptancePolicy`; this command runs the deterministic
//! evaluator (`acceptance_policy::evaluate`) over real proposals/findings and emits a
//! `DecisionCertificate` per item — `permit` / `defer` / `deny` — WITHOUT applying
//! anything (SHADOW). It proves the autonomy before any authority is granted: no new
//! event kind, no accept-wire change. The assurance level fed to the policy is
//! DERIVED from the frozen gate (`derive_gate_status` / `exact_lane_attachment_admit`),
//! never self-asserted — policy decides authority, the gate decides evidence.
//!
//!   vela policy show <policy.json>
//!   vela policy test <policy.json> <context.json>
//!   vela policy evaluate <frontier> --policy <policy.json> [--finding <vf>] [--json]

use std::path::Path;

use serde_json::json;
use vela_protocol::acceptance_policy::{
    AcceptancePolicy, AuthorityMode, DecisionCertificate, PolicyContext, EVALUATOR_VERSION,
    evaluate,
};
use vela_protocol::bundle::FindingBundle;
use vela_protocol::project::Project;
use vela_protocol::repo;
use vela_protocol::verifier_attachment::{
    claim_digest, derive_gate_status, exact_lane_attachment_admit,
};

use crate::cli::{fail, print_json};

pub(crate) fn run(args: &[String]) {
    match args.get(2).map(String::as_str) {
        Some("show") => cmd_show(args),
        Some("seal") => cmd_seal(args),
        Some("test") => cmd_test(args),
        Some("evaluate") => cmd_evaluate(args),
        _ => fail(
            "usage: vela policy <show <policy.json> | seal <policy.json> | test <policy.json> <context.json> | evaluate <frontier> --policy <policy.json> [--finding <vf>] [--json]>",
        ),
    }
}

fn load_policy(path: &str) -> AcceptancePolicy {
    let raw = std::fs::read_to_string(path).unwrap_or_else(|e| fail(&format!("read {path}: {e}")));
    serde_json::from_str(&raw).unwrap_or_else(|e| fail(&format!("parse {path}: {e}")))
}

fn cmd_show(args: &[String]) {
    let path = args.get(3).map(String::as_str).unwrap_or_else(|| fail("usage: vela policy show <policy.json>"));
    let p = load_policy(path);
    print_json(&json!({
        "policy_id": p.id,
        "id_valid": p.id_is_valid(),
        "frontier_id": p.frontier_id,
        "epoch": p.epoch,
        "issued_by": p.issued_by,
        "quorum": { "threshold": p.quorum.threshold, "eligible_roles": p.quorum.eligible_roles },
        "rules": p.rules.iter().map(|r| json!({
            "id": r.id, "effect": r.effect.as_str(), "claim_classes": r.claim_classes,
        })).collect::<Vec<_>>(),
        "default": p.default.as_str(),
        "expires_at": p.expires_at,
        "revoked": p.revocation_ref.is_some(),
    }));
}

/// Compute the content-addressed `vap_` id of a drafted policy and write it back.
/// This is a producer helper: a human drafts the rules, seals to fix the id, then
/// signs the sealed file (the signature is the act of governance). Sealing alone
/// grants no authority — it only makes the policy tamper-evident.
fn cmd_seal(args: &[String]) {
    let path = args
        .get(3)
        .map(String::as_str)
        .unwrap_or_else(|| fail("usage: vela policy seal <policy.json>"));
    let mut p = load_policy(path);
    p.id = p.content_address();
    let body = serde_json::to_vec(&p).unwrap_or_else(|e| fail(&format!("serialize: {e}")));
    std::fs::write(path, &body).unwrap_or_else(|e| fail(&format!("write {path}: {e}")));
    if !p.id_is_valid() {
        fail("internal: sealed id failed self-check");
    }
    println!("  sealed {} → {} ({} bytes)", path, p.id, body.len());
}

fn cmd_test(args: &[String]) {
    let pol = args.get(3).map(String::as_str).unwrap_or_else(|| fail("usage: vela policy test <policy.json> <context.json>"));
    let ctxp = args.get(4).map(String::as_str).unwrap_or_else(|| fail("usage: vela policy test <policy.json> <context.json>"));
    let policy = load_policy(pol);
    let raw = std::fs::read_to_string(ctxp).unwrap_or_else(|e| fail(&format!("read {ctxp}: {e}")));
    let ctx: PolicyContext = serde_json::from_str(&raw).unwrap_or_else(|e| fail(&format!("parse {ctxp}: {e}")));
    let now = chrono::Utc::now().to_rfc3339();
    let d = evaluate(&policy, &ctx, &now);
    print_json(&serde_json::to_value(&d).unwrap_or_else(|e| fail(&format!("serialize: {e}"))));
}

/// Classify a claim into a structural class from its assertion text. Conservative:
/// an unrecognized claim is "unknown" (and the engine then defers, never permits).
fn classify(text: &str) -> &'static str {
    let t = text.to_lowercase();
    if t.contains("a309370") || t.contains("sidon") {
        "sidon_lower_bound"
    } else if t.contains("lean") || t.contains("formaliz") || t.contains("theorem") {
        "formal_theorem"
    } else if t.contains("oeis ") || t.contains("oeis:") {
        "oeis_sequence"
    } else if t.contains("erdős problem") || t.contains("erdos problem") {
        "erdos_problem"
    } else {
        "unknown"
    }
}

/// Derive the bounded policy context for a finding from FROZEN evidence (the gate),
/// not self-assertion. Assurance: A3 if the exact-lane admit passes (gate Verified +
/// independent + sound + faithful), A2 if the gate is merely Verified, A1 if any
/// matched attachment exists, else A0.
fn build_context(project: &Project, finding: &FindingBundle) -> PolicyContext {
    let digest = claim_digest(&finding.assertion.text);
    let atts = &project.verifier_attachments;
    let gate = derive_gate_status(&digest, atts);
    let (admit, _) = exact_lane_attachment_admit(&digest, atts);
    // Assurance derived from the frozen gate (never self-asserted): A3 when the
    // exact-lane admit clears (Verified + independent + sound + faithful), A2 when
    // merely Verified, else A0.
    let assurance_level = if admit {
        3
    } else if gate.is_verified() {
        2
    } else {
        0
    };
    // The exact-lane admit already requires MethodIntegrity::Sound + failure-domain
    // independence among the matched attachments, so it is the honest source for both.
    let method_integrity_sound = admit;
    PolicyContext {
        claim_class: classify(&finding.assertion.text).to_string(),
        assurance_level,
        // A bounded exact scientific transition (I2) when assured; else metadata-ish.
        impact_tier: if assurance_level >= 2 { 2 } else { 1 },
        changed_findings: 1,
        // Single-finding shadow eval: dependents are not recomputed here (the live
        // accept path will fill this from the frontier graph). Conservative 0 keeps
        // the exact-witness lane within bound; a real cascade would defer.
        downstream_dependents: 0,
        // Shadow-evaluating an EXISTING accepted finding: no claim-language mutation.
        assertion_text_mutated: false,
        target_contested: false,
        governance_mutation: false,
        independence_satisfied: admit,
        method_integrity_sound,
        // Shadow: the actor/credential layer (passkey/keyless) is Phase 1; treat the
        // local operator as valid so the routing logic is exercised honestly.
        credential_valid: true,
        has_unknown_fields: false,
    }
}

fn cmd_evaluate(args: &[String]) {
    let flag = |name: &str| -> Option<String> {
        args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
    };
    let frontier = args
        .iter()
        .skip(3)
        .find(|a| !a.starts_with('-'))
        .map(String::as_str)
        .unwrap_or_else(|| fail("usage: vela policy evaluate <frontier> --policy <policy.json> [--finding <vf>] [--json]"));
    let pol = flag("--policy").unwrap_or_else(|| fail("--policy <policy.json> is required"));
    let only = flag("--finding");
    let json_out = args.iter().any(|a| a == "--json");

    let policy = load_policy(&pol);
    let project = repo::load_from_path(Path::new(frontier)).unwrap_or_else(|e| fail(&e));
    if std::env::var("VELA_POLICY_DEBUG").is_ok() {
        eprintln!(
            "[debug] loaded {} findings, {} verifier_attachments",
            project.findings.len(),
            project.verifier_attachments.len()
        );
    }
    let now = chrono::Utc::now().to_rfc3339();

    let mut permit = 0usize;
    let mut defer = 0usize;
    let mut deny = 0usize;
    let mut rows: Vec<serde_json::Value> = Vec::new();
    for f in &project.findings {
        if let Some(want) = &only
            && &f.id != want
        {
            continue;
        }
        let ctx = build_context(&project, f);
        let decision = evaluate(&policy, &ctx, &now);
        match decision.outcome {
            vela_protocol::acceptance_policy::Outcome::Permit => permit += 1,
            vela_protocol::acceptance_policy::Outcome::Defer => defer += 1,
            vela_protocol::acceptance_policy::Outcome::Deny => deny += 1,
        }
        let cert = DecisionCertificate::build(
            &decision,
            &policy.frontier_id,
            &f.id,
            "shadow",
            "shadow",
            AuthorityMode::PolicyDelegation,
            policy.issued_by.clone(),
            "service:vela-policy-engine",
            "exact_construction_dual_check_v1",
            ctx.assurance_level,
            &claim_digest(&f.assertion.text),
            ctx.impact_tier,
            true,
        );
        rows.push(json!({
            "finding": f.id,
            "claim_class": ctx.claim_class,
            "assurance_level": ctx.assurance_level,
            "outcome": decision.outcome.as_str(),
            "matched_rules": decision.matched_rule_ids,
            "reasons": decision.reasons,
            "decision_certificate": cert.id,
        }));
    }

    if json_out {
        print_json(&json!({
            "object": "vela.policy_shadow_eval.v1",
            "mode": "shadow",
            "frontier": frontier,
            "policy_id": policy.id,
            "evaluator": EVALUATOR_VERSION,
            "now": now,
            "summary": { "permit": permit, "defer": defer, "deny": deny, "total": rows.len() },
            "decisions": rows,
        }));
        return;
    }
    println!(
        "· policy shadow-eval over {frontier} (policy {}) — {} findings: {permit} permit, {defer} defer, {deny} deny",
        policy.id, rows.len()
    );
    for r in rows.iter().take(20) {
        println!(
            "  [{}] {} ({}, A{}) {}",
            r["outcome"].as_str().unwrap_or(""),
            r["finding"].as_str().unwrap_or(""),
            r["claim_class"].as_str().unwrap_or(""),
            r["assurance_level"].as_u64().unwrap_or(0),
            if r["outcome"] == "permit" {
                format!("← {}", r["matched_rules"][0].as_str().unwrap_or(""))
            } else {
                format!("← {}", r["reasons"][0].as_str().unwrap_or(""))
            }
        );
    }
    println!("\nSHADOW: nothing applied. A human signs the policy once; the engine would route the rest.");
}
