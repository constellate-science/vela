//! Gate conformance — the fail-closed reject-vectors.
//!
//! `conformance/gate-vectors.json` is the portable spec of the
//! verification gate: a set of (claim, attachments) cases with the
//! `gate_status` each must derive, plus grade-gate cases. This test runs
//! the canonical Rust implementation
//! ([`vela_protocol::verifier_attachment::derive_gate_status`] and
//! [`vela_protocol::deliverable_grade::grade_gate`]) against every vector,
//! so the reject-vectors (zero attachments → needs_verification,
//! passed-but-unmatched, refuted probe) are pinned as a contract any
//! implementation of the gate must satisfy.

use std::path::PathBuf;

use serde_json::Value;
use vela_protocol::deliverable_grade::grade_gate;
use vela_protocol::verifier_attachment::{
    claim_digest, derive_gate_status, AdversarialProbe, AttachmentDraft, AttachmentOutcome,
    GateStatus, MatchToClaim, ProbeKind, ProbeResult, VerifierAttachment, VerifierMethod,
};

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("conformance")
        .join("gate-vectors.json")
}

fn build_attachment(spec: &Value, claim: &str, prior_ids: &[String]) -> VerifierAttachment {
    let method = VerifierMethod::parse(spec["method"].as_str().unwrap())
        .expect("vector uses a known verifier_method");
    let solver = spec["solver"].as_str().unwrap().to_string();
    let matched = spec["matched"].as_bool().unwrap();
    // An unmatched attachment is bound to a *different* claim digest, so
    // it is passed_but_unmatched against the target claim.
    let digest = if matched {
        claim_digest(claim)
    } else {
        claim_digest("a completely different claim than the target")
    };
    let outcome = match spec["outcome"].as_str().unwrap() {
        "passed" => AttachmentOutcome::Passed,
        "failed" => AttachmentOutcome::Failed,
        other => panic!("unknown outcome {other}"),
    };
    let probes = match spec["probe"].as_str().unwrap() {
        "survived" => vec![AdversarialProbe {
            kind: ProbeKind::CounterexampleSearch,
            result: ProbeResult::Survived,
            note: String::new(),
        }],
        "refuted" => vec![AdversarialProbe {
            kind: ProbeKind::CounterexampleSearch,
            result: ProbeResult::Refuted,
            note: String::new(),
        }],
        "none" => vec![],
        other => panic!("unknown probe {other}"),
    };
    let independent_of: Vec<String> = spec["independent_of"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| prior_ids[i.as_u64().unwrap() as usize].clone())
        .collect();
    VerifierAttachment::build(AttachmentDraft {
        target: "vf_0123456789abcdef".to_string(),
        claim_digest: digest,
        verifier_method: method,
        solver_id: solver,
        independent_of,
        match_to_claim: MatchToClaim {
            matches: matched,
            checker_actor: "conformance".to_string(),
        },
        adversarial_probes: probes,
        outcome,
        verifier_actor: "conformance".to_string(),
        note: String::new(),
    })
    .expect("attachment builds")
}

#[test]
fn gate_status_reject_vectors() {
    let raw = std::fs::read_to_string(vectors_path()).expect("read gate-vectors.json");
    let doc: Value = serde_json::from_str(&raw).expect("parse gate-vectors.json");

    for v in doc["gate_status_vectors"].as_array().unwrap() {
        let name = v["name"].as_str().unwrap();
        let claim = v["claim"].as_str().unwrap();
        let mut attachments: Vec<VerifierAttachment> = Vec::new();
        let mut ids: Vec<String> = Vec::new();
        for spec in v["attachments"].as_array().unwrap() {
            let att = build_attachment(spec, claim, &ids);
            ids.push(att.id.clone());
            attachments.push(att);
        }
        let outcome = derive_gate_status(&claim_digest(claim), &attachments);
        let got = match outcome.status {
            GateStatus::Verified => "verified",
            GateStatus::NeedsVerification => "needs_verification",
            GateStatus::Refuted => "refuted",
        };
        let expected = v["expected"].as_str().unwrap();
        assert_eq!(
            got, expected,
            "gate vector '{name}': expected {expected}, got {got} (reasons: {:?})",
            outcome.reasons
        );
    }
}

#[test]
fn grade_gate_vectors() {
    let raw = std::fs::read_to_string(vectors_path()).expect("read gate-vectors.json");
    let doc: Value = serde_json::from_str(&raw).expect("parse gate-vectors.json");

    for v in doc["grade_gate_vectors"].as_array().unwrap() {
        let name = v["name"].as_str().unwrap();
        let claim = v["claim"].as_str().unwrap();
        let grade = v["grade"].as_str();
        let expected_pass = v["expected_pass"].as_bool().unwrap();
        let got = grade_gate(claim, grade).passed();
        assert_eq!(
            got, expected_pass,
            "grade vector '{name}': expected pass={expected_pass}, got {got}"
        );
    }
}
