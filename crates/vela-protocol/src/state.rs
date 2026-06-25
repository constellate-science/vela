//! Non-interactive frontier state transitions.
//!
//! Write commands are proposal-first. Pending proposals are review artifacts;
//! accepted proposals become canonical state events through one reducer.

use std::path::Path;

use chrono::Utc;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::bundle::{
    Artifact, Assertion, Author, Conditions, Confidence, ConfidenceKind, ConfidenceMethod,
    Evidence, Extraction, FindingBundle, Flags, Provenance, Review,
};
use crate::events::{self, NULL_HASH, StateActor, StateEvent, StateTarget};
use crate::project::{self, Project};
use crate::proposals::{self, StateProposal};
use crate::reducer;
use crate::repo;

#[derive(Debug, Clone, Serialize)]
pub struct StateCommandReport {
    pub ok: bool,
    pub command: String,
    pub frontier: String,
    pub finding_id: String,
    pub proposal_id: String,
    pub proposal_status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub applied_event_id: Option<String>,
    pub wrote_to: String,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct FindingDraftOptions {
    pub text: String,
    pub assertion_type: String,
    pub source: String,
    pub source_type: String,
    pub author: String,
    pub confidence: f64,
    pub evidence_type: String,
    /// v0.11: structured provenance — populates the existing `Provenance`
    /// fields instead of jamming everything into `title`. Each is optional
    /// so `vela finding add` callers don't have to know all of them up front;
    /// the substrate has the fields, the CLI just exposes them.
    // populated by CLI; consumed by build_add_finding_proposal
    pub doi: Option<String>,
    pub year: Option<i32>,
    pub url: Option<String>,
    /// Authors of the source artifact (the paper/preprint/etc).
    /// Distinct from `author` above, which is the Vela actor doing the curation.
    pub source_authors: Vec<String>,
    /// v0.11: structured conditions — replaces the placeholder
    /// "Manually added finding; requires evidence review…" that was on
    /// every manually-added finding in v0.10. Each field independently optional.
    pub conditions_text: Option<String>,
    pub evidence_spans: Vec<Value>,
    pub gap: bool,
    pub negative_space: bool,
    /// v0.339: optional replication attestation for verified circuit-claim
    /// findings. When present it is attached to the finding.add proposal
    /// payload as a sibling of `finding`, where the trusted-reviewer-agent
    /// gate (proposals.rs) reads it: an `agent:replicator` author may
    /// auto-accept the finding iff this attestation passes the deterministic
    /// predicate. None for ordinary human-curated findings.
    pub replication_attestation: Option<Value>,
}

#[derive(Debug, Clone)]
pub struct ReviewOptions {
    pub status: String,
    pub reason: String,
    pub reviewer: String,
}

#[derive(Debug, Clone)]
pub struct ReviseOptions {
    pub confidence: f64,
    pub reason: String,
    pub reviewer: String,
}

pub fn add_finding(
    path: &Path,
    options: FindingDraftOptions,
    apply: bool,
) -> Result<StateCommandReport, String> {
    validate_score(options.confidence)?;
    let proposal = build_add_finding_proposal(options)?;
    let result = proposals::create_or_apply(path, proposal, apply)?;
    let frontier = repo::load_from_path(path)?;
    Ok(StateCommandReport {
        ok: true,
        command: "finding.add".to_string(),
        frontier: frontier.project.name,
        finding_id: result.finding_id,
        proposal_id: result.proposal_id,
        proposal_status: result.status.clone(),
        applied_event_id: result.applied_event_id,
        wrote_to: path.display().to_string(),
        message: if result.status == "applied" {
            "Finding proposal applied".to_string()
        } else {
            "Finding proposal recorded".to_string()
        },
    })
}

pub fn review_finding(
    path: &Path,
    finding_id: &str,
    options: ReviewOptions,
    apply: bool,
) -> Result<StateCommandReport, String> {
    let proposal = proposals::new_proposal(
        "finding.review",
        events::StateTarget {
            r#type: "finding".to_string(),
            id: finding_id.to_string(),
        },
        options.reviewer.clone(),
        "human",
        options.reason.clone(),
        json!({"status": options.status}),
        Vec::new(),
        Vec::new(),
    );
    let result = proposals::create_or_apply(path, proposal, apply)?;
    let frontier = repo::load_from_path(path)?;
    Ok(StateCommandReport {
        ok: true,
        command: "review".to_string(),
        frontier: frontier.project.name,
        finding_id: result.finding_id,
        proposal_id: result.proposal_id,
        proposal_status: result.status,
        applied_event_id: result.applied_event_id,
        wrote_to: path.display().to_string(),
        message: if apply {
            "Review proposal applied".to_string()
        } else {
            "Review proposal recorded".to_string()
        },
    })
}

pub fn add_note(
    path: &Path,
    finding_id: &str,
    text: &str,
    author: &str,
    apply: bool,
) -> Result<StateCommandReport, String> {
    let proposal = proposals::new_proposal(
        "finding.note",
        events::StateTarget {
            r#type: "finding".to_string(),
            id: finding_id.to_string(),
        },
        author.to_string(),
        "human",
        text.to_string(),
        json!({"text": text}),
        Vec::new(),
        Vec::new(),
    );
    let result = proposals::create_or_apply(path, proposal, apply)?;
    let frontier = repo::load_from_path(path)?;
    Ok(StateCommandReport {
        ok: true,
        command: "note".to_string(),
        frontier: frontier.project.name,
        finding_id: result.finding_id,
        proposal_id: result.proposal_id,
        proposal_status: result.status,
        applied_event_id: result.applied_event_id,
        wrote_to: path.display().to_string(),
        message: if apply {
            "Note proposal applied".to_string()
        } else {
            "Note proposal recorded".to_string()
        },
    })
}

pub fn caveat_finding(
    path: &Path,
    finding_id: &str,
    text: &str,
    author: &str,
    apply: bool,
) -> Result<StateCommandReport, String> {
    let proposal = proposals::new_proposal(
        "finding.caveat",
        events::StateTarget {
            r#type: "finding".to_string(),
            id: finding_id.to_string(),
        },
        author.to_string(),
        "human",
        text.to_string(),
        json!({"text": text}),
        Vec::new(),
        Vec::new(),
    );
    let result = proposals::create_or_apply(path, proposal, apply)?;
    let frontier = repo::load_from_path(path)?;
    Ok(StateCommandReport {
        ok: true,
        command: "caveat".to_string(),
        frontier: frontier.project.name,
        finding_id: result.finding_id,
        proposal_id: result.proposal_id,
        proposal_status: result.status,
        applied_event_id: result.applied_event_id,
        wrote_to: path.display().to_string(),
        message: if apply {
            "Caveat proposal applied".to_string()
        } else {
            "Caveat proposal recorded".to_string()
        },
    })
}

pub fn revise_confidence(
    path: &Path,
    finding_id: &str,
    options: ReviseOptions,
    apply: bool,
) -> Result<StateCommandReport, String> {
    validate_score(options.confidence)?;
    let proposal = proposals::new_proposal(
        "finding.confidence_revise",
        events::StateTarget {
            r#type: "finding".to_string(),
            id: finding_id.to_string(),
        },
        options.reviewer.clone(),
        "human",
        options.reason.clone(),
        json!({"confidence": options.confidence}),
        Vec::new(),
        Vec::new(),
    );
    let result = proposals::create_or_apply(path, proposal, apply)?;
    let frontier = repo::load_from_path(path)?;
    Ok(StateCommandReport {
        ok: true,
        command: "revise".to_string(),
        frontier: frontier.project.name,
        finding_id: result.finding_id,
        proposal_id: result.proposal_id,
        proposal_status: result.status,
        applied_event_id: result.applied_event_id,
        wrote_to: path.display().to_string(),
        message: if apply {
            "Confidence revision applied".to_string()
        } else {
            "Confidence revision proposal recorded".to_string()
        },
    })
}

pub fn reject_finding(
    path: &Path,
    finding_id: &str,
    reviewer: &str,
    reason: &str,
    apply: bool,
) -> Result<StateCommandReport, String> {
    let proposal = proposals::new_proposal(
        "finding.reject",
        events::StateTarget {
            r#type: "finding".to_string(),
            id: finding_id.to_string(),
        },
        reviewer.to_string(),
        "human",
        reason.to_string(),
        json!({"status": "rejected"}),
        Vec::new(),
        Vec::new(),
    );
    let result = proposals::create_or_apply(path, proposal, apply)?;
    let frontier = repo::load_from_path(path)?;
    Ok(StateCommandReport {
        ok: true,
        command: "reject".to_string(),
        frontier: frontier.project.name,
        finding_id: result.finding_id,
        proposal_id: result.proposal_id,
        proposal_status: result.status,
        applied_event_id: result.applied_event_id,
        wrote_to: path.display().to_string(),
        message: if apply {
            "Rejection proposal applied".to_string()
        } else {
            "Rejection proposal recorded".to_string()
        },
    })
}

/// v0.80.1: Per-event attestation. Emit an
/// `attestation.recorded` canonical event pointing at a target
/// `vev_*` id, recording who attested it, the scope, and an
/// optional Carina Proof primitive id + Ed25519 signature.
/// Append-only: re-attesting the same target event by the same
/// attester writes a new attestation event (each carries a
/// unique id).
pub fn record_attestation(
    path: &Path,
    target_event_id: &str,
    attester_id: &str,
    scope_note: &str,
    proof_id: Option<&str>,
    signature: Option<&str>,
) -> Result<String, String> {
    record_scoped_attestation(
        path,
        target_event_id,
        ScopedAttestationInput {
            attester_id,
            scope_note,
            scopes: &[],
            reviewer_role: None,
            orcid: None,
            ror: None,
            proof_id,
            signature,
            attestation_id: None,
        },
    )
}

pub struct ScopedAttestationInput<'a> {
    pub attester_id: &'a str,
    pub scope_note: &'a str,
    pub scopes: &'a [String],
    pub reviewer_role: Option<&'a str>,
    pub orcid: Option<&'a str>,
    pub ror: Option<&'a str>,
    pub proof_id: Option<&'a str>,
    pub signature: Option<&'a str>,
    pub attestation_id: Option<&'a str>,
}

pub fn record_scoped_attestation(
    path: &Path,
    target_event_id: &str,
    input: ScopedAttestationInput<'_>,
) -> Result<String, String> {
    if !target_event_id.starts_with("vev_") {
        return Err(format!(
            "target_event_id must start with 'vev_', got '{target_event_id}'"
        ));
    }
    if input.attester_id.trim().is_empty() {
        return Err("attester_id must be non-empty".to_string());
    }
    if input.scope_note.trim().is_empty() {
        return Err("scope_note must be non-empty".to_string());
    }
    if let Some(p) = input.proof_id
        && !p.starts_with("vpf_")
    {
        return Err(format!(
            "proof_id must start with 'vpf_' when present, got '{p}'"
        ));
    }
    let mut frontier = repo::load_from_path(path)?;
    // Verify target event exists (defensive; replay-only validators
    // don't enforce existence but the emission path should).
    if !frontier.events.iter().any(|e| e.id == target_event_id) {
        return Err(format!(
            "target event '{target_event_id}' not found in frontier"
        ));
    }
    let mut payload = json!({
        "target_event_id": target_event_id,
        "attester_id": input.attester_id,
        "scope_note": input.scope_note,
        "signed_at": chrono::Utc::now().to_rfc3339(),
    });
    if !input.scopes.is_empty() {
        payload["scopes"] = json!(input.scopes);
    }
    if let Some(role) = input.reviewer_role {
        payload["reviewer_role"] = json!(role);
    }
    if let Some(orcid) = input.orcid {
        payload["orcid"] = json!(orcid);
    }
    if let Some(ror) = input.ror {
        payload["ror"] = json!(ror);
    }
    if let Some(attestation_id) = input.attestation_id {
        payload["attestation_id"] = json!(attestation_id);
    }
    if let Some(p) = input.proof_id {
        payload["proof_id"] = json!(p);
    }
    if let Some(s) = input.signature {
        payload["signature"] = json!(s);
    }
    let actor_type = if input.attester_id.starts_with("agent:") {
        "agent"
    } else {
        "human"
    };
    let mut event = events::StateEvent {
        schema: events::EVENT_SCHEMA.to_string(),
        id: String::new(),
        kind: "attestation.recorded".into(),
        target: events::StateTarget {
            r#type: "event".to_string(),
            id: target_event_id.to_string(),
        },
        actor: events::StateActor {
            id: input.attester_id.to_string(),
            r#type: actor_type.to_string(),
        },
        timestamp: chrono::Utc::now().to_rfc3339(),
        reason: input.scope_note.to_string(),
        before_hash: events::NULL_HASH.to_string(),
        after_hash: events::NULL_HASH.to_string(),
        payload,
        caveats: Vec::new(),
        signature: None,
        schema_artifact_id: None,
    };
    event.id = events::compute_event_id(&event);
    let event_id = event.id.clone();
    frontier.events.push(event);
    repo::save_to_path(path, &frontier)?;
    Ok(event_id)
}

/// v0.57: Mechanically repair a missing evidence-span on a finding by
/// appending a `{section, text}` span. The proposal lands as a
/// `finding.span_repair` and the canonical event as
/// `finding.span_repaired`.
pub fn repair_finding_span(
    path: &Path,
    finding_id: &str,
    section: &str,
    text: &str,
    reviewer: &str,
    reason: &str,
    apply: bool,
) -> Result<StateCommandReport, String> {
    let frontier_view = repo::load_from_path(path)?;
    let _ = frontier_view
        .findings
        .iter()
        .find(|f| f.id == finding_id)
        .ok_or_else(|| format!("Finding not found: {finding_id}"))?;
    let trimmed_section = section.trim();
    let trimmed_text = text.trim();
    if trimmed_section.is_empty() {
        return Err("--section must be non-empty".to_string());
    }
    if trimmed_text.is_empty() {
        return Err("--text must be non-empty".to_string());
    }
    let proposal = proposals::new_proposal(
        "finding.span_repair",
        events::StateTarget {
            r#type: "finding".to_string(),
            id: finding_id.to_string(),
        },
        reviewer,
        "human",
        reason,
        json!({
            "section": trimmed_section,
            "text": trimmed_text,
        }),
        Vec::new(),
        Vec::new(),
    );
    let result = proposals::create_or_apply(path, proposal, apply)?;
    Ok(StateCommandReport {
        ok: true,
        command: "span-repair".to_string(),
        frontier: frontier_view.project.name,
        finding_id: finding_id.to_string(),
        proposal_id: result.proposal_id,
        proposal_status: result.status,
        applied_event_id: result.applied_event_id,
        wrote_to: path.display().to_string(),
        message: if apply {
            "Span repair applied".to_string()
        } else {
            "Span repair proposal recorded".to_string()
        },
    })
}

/// v0.56: Mechanically repair a missing evidence-atom locator by
/// copying the locator from the parent source record. If `locator` is
/// `None` the resolver pulls the value from `frontier.sources` for the
/// atom's parent. The proposal carries both the resolved locator and
/// the source id it was derived from so a fresh replay reconstructs
/// the derivation without re-resolving.
pub fn repair_evidence_atom_locator(
    path: &Path,
    atom_id: &str,
    locator_override: Option<&str>,
    reviewer: &str,
    reason: &str,
    apply: bool,
) -> Result<StateCommandReport, String> {
    let frontier_view = repo::load_from_path(path)?;
    let atom = frontier_view
        .evidence_atoms
        .iter()
        .find(|atom| atom.id == atom_id)
        .ok_or_else(|| format!("Evidence atom not found: {atom_id}"))?;
    if let Some(existing) = &atom.locator {
        return Err(format!(
            "Evidence atom {atom_id} already carries locator '{existing}'"
        ));
    }
    let source_id = atom.source_id.clone();
    let locator = match locator_override {
        Some(value) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                return Err("--locator value must be non-empty".to_string());
            }
            trimmed.to_string()
        }
        None => {
            let source = frontier_view
                .sources
                .iter()
                .find(|source| source.id == source_id)
                .ok_or_else(|| {
                    format!(
                        "Cannot resolve locator for atom {atom_id}: parent source {source_id} not in frontier"
                    )
                })?;
            let trimmed = source.locator.trim();
            if trimmed.is_empty() {
                return Err(format!(
                    "Cannot resolve locator for atom {atom_id}: parent source {source_id} has an empty locator"
                ));
            }
            trimmed.to_string()
        }
    };
    let proposal = proposals::new_proposal(
        "evidence_atom.locator_repair",
        events::StateTarget {
            r#type: "evidence_atom".to_string(),
            id: atom_id.to_string(),
        },
        reviewer,
        "human",
        reason,
        json!({
            "locator": locator,
            "source_id": source_id,
        }),
        Vec::new(),
        Vec::new(),
    );
    let result = proposals::create_or_apply(path, proposal, apply)?;
    Ok(StateCommandReport {
        ok: true,
        command: "locator-repair".to_string(),
        frontier: frontier_view.project.name,
        finding_id: atom_id.to_string(),
        proposal_id: result.proposal_id,
        proposal_status: result.status,
        applied_event_id: result.applied_event_id,
        wrote_to: path.display().to_string(),
        message: if apply {
            "Locator repair applied".to_string()
        } else {
            "Locator repair proposal recorded".to_string()
        },
    })
}

pub fn retract_finding(
    path: &Path,
    finding_id: &str,
    reviewer: &str,
    reason: &str,
    apply: bool,
) -> Result<StateCommandReport, String> {
    let frontier = repo::load_from_path(path)?;
    find_finding_index(&frontier, finding_id)?;
    let proposal = proposals::new_proposal(
        "finding.retract",
        events::StateTarget {
            r#type: "finding".to_string(),
            id: finding_id.to_string(),
        },
        reviewer,
        "human",
        reason,
        json!({}),
        Vec::new(),
        vec!["Retraction impact is simulated over declared dependency links.".to_string()],
    );
    let result = proposals::create_or_apply(path, proposal, apply)?;
    Ok(StateCommandReport {
        ok: true,
        command: "retract".to_string(),
        frontier: frontier.project.name,
        finding_id: result.finding_id,
        proposal_id: result.proposal_id,
        proposal_status: result.status,
        applied_event_id: result.applied_event_id,
        wrote_to: path.display().to_string(),
        message: if apply {
            "Retraction proposal applied".to_string()
        } else {
            "Retraction proposal recorded".to_string()
        },
    })
}

/// v0.38: Set or revise a finding's `causal_claim` and (optionally)
/// `causal_evidence_grade`. Appends an `assertion.reinterpreted_causal`
/// event capturing the prior reading, the new reading, and the actor.
/// Bypasses the proposal flow because (a) the mutation is local and
/// reversible by another call, and (b) the schema layer ships ahead of
/// the reasoning surface — the next milestone will route this through
/// proposals once the do-calculus layer needs it.
pub fn set_causal(
    path: &Path,
    finding_id: &str,
    new_claim: &str,
    new_grade: Option<&str>,
    actor: &str,
    reason: &str,
) -> Result<StateCommandReport, String> {
    use crate::bundle::{CausalClaim, CausalEvidenceGrade};

    let mut frontier: Project = repo::load_from_path(path)?;
    let idx = frontier
        .findings
        .iter()
        .position(|f| f.id == finding_id)
        .ok_or_else(|| format!("Finding not found: {finding_id}"))?;

    // Capture the prior reading for the event payload.
    let before = json!({
        "claim": frontier.findings[idx].assertion.causal_claim,
        "grade": frontier.findings[idx].assertion.causal_evidence_grade,
    });

    let parsed_claim = match new_claim {
        "correlation" => CausalClaim::Correlation,
        "mediation" => CausalClaim::Mediation,
        "intervention" => CausalClaim::Intervention,
        other => return Err(format!("invalid causal claim '{other}'")),
    };
    let parsed_grade = match new_grade {
        None => None,
        Some("rct") => Some(CausalEvidenceGrade::Rct),
        Some("quasi_experimental") => Some(CausalEvidenceGrade::QuasiExperimental),
        Some("observational") => Some(CausalEvidenceGrade::Observational),
        Some("theoretical") => Some(CausalEvidenceGrade::Theoretical),
        Some(other) => return Err(format!("invalid causal evidence grade '{other}'")),
    };

    let before_hash = events::finding_hash(&frontier.findings[idx]);
    frontier.findings[idx].assertion.causal_claim = Some(parsed_claim);
    if let Some(g) = parsed_grade {
        frontier.findings[idx].assertion.causal_evidence_grade = Some(g);
    }
    let after_hash = events::finding_hash(&frontier.findings[idx]);

    let after = json!({
        "claim": new_claim,
        "grade": new_grade,
    });

    // Synthesize a deterministic proposal_id over the mutation.
    let proposal_id = format!(
        "vpr_{}",
        &hex::encode(Sha256::digest(
            format!(
                "{finding_id}|{actor}|{before_hash}|{after_hash}|{}",
                Utc::now().to_rfc3339()
            )
            .as_bytes()
        ))[..16]
    );

    let event = events::new_finding_event(events::FindingEventInput {
        kind: "assertion.reinterpreted_causal",
        finding_id,
        actor_id: actor,
        actor_type: events::actor_kind(actor),
        reason,
        before_hash: &before_hash,
        after_hash: &after_hash,
        payload: json!({
            "proposal_id": proposal_id,
            "before": before,
            "after": after,
        }),
        caveats: Vec::new(),
        timestamp: None,
    });
    let event_id = event.id.clone();
    frontier.events.push(event);

    repo::save_to_path(path, &frontier)?;

    Ok(StateCommandReport {
        ok: true,
        command: "causal_set".to_string(),
        frontier: frontier.project.name,
        finding_id: finding_id.to_string(),
        proposal_id,
        proposal_status: "applied".to_string(),
        applied_event_id: Some(event_id),
        wrote_to: path.display().to_string(),
        message: format!("Causal claim set to {new_claim}"),
    })
}

/// Deposit a generic content-addressed artifact and emit an
/// `artifact.asserted` canonical event. The full artifact is carried
/// inline on the event payload so a future replay reconstructs the
/// artifact table without reading `.vela/artifacts`.
pub fn add_artifact(
    path: &Path,
    artifact: Artifact,
    deposited_by: &str,
    reason: &str,
) -> Result<StateCommandReport, String> {
    if deposited_by.trim().is_empty() {
        return Err("deposited_by must be a non-empty actor id".to_string());
    }
    if reason.trim().is_empty() {
        return Err("reason must be non-empty".to_string());
    }

    let mut frontier: Project = repo::load_from_path(path)?;
    let artifact_id = artifact.id.clone();

    if frontier.artifacts.iter().any(|a| a.id == artifact_id) {
        return Err(format!(
            "Refusing to add duplicate artifact with existing id {artifact_id}"
        ));
    }

    let proposal_id = format!(
        "vpr_{}",
        &hex::encode(Sha256::digest(
            format!("{artifact_id}|{deposited_by}|{}", Utc::now().to_rfc3339()).as_bytes()
        ))[..16]
    );

    let artifact_value = serde_json::to_value(&artifact)
        .map_err(|e| format!("failed to serialize artifact: {e}"))?;

    let mut event = StateEvent {
        schema: events::EVENT_SCHEMA.to_string(),
        id: String::new(),
        kind: events::EVENT_KIND_ARTIFACT_ASSERTED.into(),
        target: StateTarget {
            r#type: "artifact".to_string(),
            id: artifact_id.clone(),
        },
        actor: StateActor {
            id: deposited_by.to_string(),
            // Honest actor typing: an `agent:` depositor is an agent, not a
            // human. Artifact deposit is provenance (not a truth verdict), so
            // an agent may do it — but the event must not mislabel who did.
            r#type: if deposited_by
                .trim()
                .to_ascii_lowercase()
                .starts_with("agent:")
            {
                "agent".to_string()
            } else {
                "human".to_string()
            },
        },
        timestamp: Utc::now().to_rfc3339(),
        reason: reason.to_string(),
        before_hash: NULL_HASH.to_string(),
        after_hash: NULL_HASH.to_string(),
        payload: json!({
            "proposal_id": proposal_id,
            "artifact": artifact_value,
        }),
        caveats: Vec::new(),
        signature: None,
        schema_artifact_id: None,
    };
    event.id = events::compute_event_id(&event);
    let event_id = event.id.clone();

    events::validate_event_payload(event.kind.as_str(), &event.payload)?;
    reducer::apply_event(&mut frontier, &event)?;
    frontier.events.push(event);

    repo::save_to_path(path, &frontier)?;

    Ok(StateCommandReport {
        ok: true,
        command: "artifact.add".to_string(),
        frontier: frontier.project.name,
        finding_id: artifact_id,
        proposal_id,
        proposal_status: "applied".to_string(),
        applied_event_id: Some(event_id),
        wrote_to: path.display().to_string(),
        message: "Artifact deposited".to_string(),
    })
}

pub fn history(path: &Path, finding_id: &str) -> Result<Value, String> {
    history_as_of(path, finding_id, None)
}

/// v0.55: time-travel replay. When `as_of` is `Some(ts)`, the returned
/// `events` / `review_events` / `confidence_updates` are filtered to
/// records whose timestamp is `<= ts` (RFC3339 lexicographic compare),
/// the `confidence` field reports the **score at that time** (last
/// confidence update at-or-before cutoff, or genesis if none), and a
/// `replayed_at_score` field surfaces it explicitly so a caller doesn't
/// need to walk the updates array.
pub fn history_as_of(path: &Path, finding_id: &str, as_of: Option<&str>) -> Result<Value, String> {
    let frontier = repo::load_from_path(path)?;
    let context = finding_context(&frontier, finding_id)?;
    let finding = context
        .get("finding")
        .ok_or_else(|| format!("Finding not found: {finding_id}"))?;

    let cutoff = as_of.map(|s| s.to_string());
    let filter_by_ts = |arr: Option<&Value>, ts_field: &str| -> Value {
        let Some(v) = arr else {
            return Value::Array(Vec::new());
        };
        let Some(items) = v.as_array() else {
            return Value::Array(Vec::new());
        };
        match &cutoff {
            None => Value::Array(items.clone()),
            Some(c) => Value::Array(
                items
                    .iter()
                    .filter(|item| {
                        item.get(ts_field)
                            .and_then(Value::as_str)
                            .map(|t| t <= c.as_str())
                            .unwrap_or(true)
                    })
                    .cloned()
                    .collect(),
            ),
        }
    };

    let events_filtered = filter_by_ts(context.get("events"), "timestamp");
    let review_events_filtered = filter_by_ts(context.get("review_events"), "reviewed_at");
    let confidence_updates_filtered = filter_by_ts(context.get("confidence_updates"), "updated_at");

    // Score at cutoff: last confidence update at-or-before cutoff. If the
    // finding is at its genesis confidence, fall back to the current score
    // from the bundle (it never changed).
    let score_at = if let Some(arr) = confidence_updates_filtered.as_array() {
        let mut sorted: Vec<&Value> = arr.iter().collect();
        sorted.sort_by(|a, b| {
            let ta = a.get("updated_at").and_then(Value::as_str).unwrap_or("");
            let tb = b.get("updated_at").and_then(Value::as_str).unwrap_or("");
            ta.cmp(tb)
        });
        sorted
            .last()
            .and_then(|u| u.get("new_score"))
            .cloned()
            .unwrap_or_else(|| {
                finding
                    .pointer("/confidence/score")
                    .cloned()
                    .unwrap_or(Value::Null)
            })
    } else {
        finding
            .pointer("/confidence/score")
            .cloned()
            .unwrap_or(Value::Null)
    };

    Ok(json!({
        "ok": true,
        "command": "history",
        "frontier": frontier.project.name,
        "as_of": cutoff,
        "finding": {
            "id": finding.get("id"),
            "assertion": finding.pointer("/assertion/text"),
            "confidence": finding.pointer("/confidence/score"),
            "flags": finding.get("flags"),
            "annotations": finding.get("annotations"),
        },
        "replayed_at_score": score_at,
        "confidence_score": context.get("confidence_score"),
        "confidence_basis": context.get("confidence_basis"),
        "reviewed": context.get("reviewed"),
        "reviewed_by_kind": context.get("reviewed_by_kind"),
        "review_events": review_events_filtered,
        "confidence_updates": confidence_updates_filtered,
        "sources": context.get("sources"),
        "evidence_atoms": context.get("evidence_atoms"),
        "condition_records": context.get("condition_records"),
        "proposals": context.get("proposals"),
        "events": events_filtered,
        "proof_state": frontier.proof_state,
    }))
}

pub fn finding_context(frontier: &Project, finding_id: &str) -> Result<Value, String> {
    let finding = frontier
        .findings
        .iter()
        .find(|finding| finding.id == finding_id)
        .ok_or_else(|| format!("Finding not found: {finding_id}"))?;
    // Legacy `.vela/reviews/` records. The canonical reviewer verdicts
    // live in the `.vela/events/` log (exposed as `events` below); this
    // collection is deliberately the legacy side and stays separate.
    let reviews = frontier
        .review_events
        .iter()
        .filter(|event| event.finding_id == finding_id)
        .collect::<Vec<_>>();
    let confidence_updates = frontier
        .confidence_updates
        .iter()
        .filter(|update| update.finding_id == finding_id)
        .collect::<Vec<_>>();
    let source_records = frontier
        .sources
        .iter()
        .filter(|source| source.finding_ids.iter().any(|id| id == finding_id))
        .collect::<Vec<_>>();
    let evidence_atoms = frontier
        .evidence_atoms
        .iter()
        .filter(|atom| atom.finding_id == finding_id)
        .collect::<Vec<_>>();
    let condition_records = frontier
        .condition_records
        .iter()
        .filter(|record| record.finding_id == finding_id)
        .collect::<Vec<_>>();
    // v0.326: `Confidence` serializes as a bare score, so a consumer
    // of the finding payload cannot see the basis or reviewed-state. A
    // confidence number must never stand alone — surface the basis and
    // the (actor-classified) review state explicitly.
    let review = finding.provenance.review.as_ref();
    let reviewed = review.map(|r| r.reviewed).unwrap_or(false);
    let reviewed_by_kind = review
        .and_then(|r| r.reviewer.as_deref())
        .map(crate::events::actor_kind);
    Ok(json!({
        "finding": finding,
        "review_events": reviews,
        "confidence_updates": confidence_updates,
        "confidence_score": finding.confidence.score,
        "confidence_basis": finding.confidence.basis,
        "reviewed": reviewed,
        "reviewed_by_kind": reviewed_by_kind,
        "sources": source_records,
        "evidence_atoms": evidence_atoms,
        "condition_records": condition_records,
        "proposals": proposals::proposals_for_finding(frontier, finding_id),
        "events": events::events_for_finding(frontier, finding_id),
        "proof_state": frontier.proof_state,
        // Phase 1A: the verification trust tier (candidate / schema_checked /
        // machine_verified / accepted). A read-only projection; machine_verified
        // is the deterministic exact-lane admission and is DISTINCT from a human
        // `accepted` (canonical-state landing via key custody). Every surface
        // that renders this must keep the two visually + semantically separate.
        "trust_tier": proposals::derive_trust_tier(frontier, finding_id).as_str(),
    }))
}

pub fn state_transitions(frontier: &Project) -> Value {
    let mut transitions = Vec::new();
    if !frontier.events.is_empty() {
        for event in &frontier.events {
            transitions.push(json!({
                "kind": event.kind,
                "id": event.id,
                "target": event.target,
                "actor": event.actor,
                "timestamp": event.timestamp,
                "reason": event.reason,
                "before_hash": event.before_hash,
                "after_hash": event.after_hash,
                "payload": event.payload,
                "caveats": event.caveats,
            }));
        }
        transitions.sort_by(|a, b| {
            a.get("timestamp")
                .and_then(Value::as_str)
                .cmp(&b.get("timestamp").and_then(Value::as_str))
        });
        return json!({
            "schema": "vela.state-transitions.v1",
            "frontier": frontier.project.name,
            "source": "canonical_events",
            "transitions": transitions,
        });
    }
    for event in &frontier.review_events {
        transitions.push(json!({
            "kind": "review_event",
            "id": event.id,
            "target": {"type": "finding", "id": event.finding_id},
            "actor": event.reviewer,
            "timestamp": event.reviewed_at,
            "action": event.action,
            "reason": event.reason,
            "state_change": event.state_change,
        }));
    }
    for update in &frontier.confidence_updates {
        transitions.push(json!({
            "kind": "confidence_update",
            "id": confidence_update_id(update),
            "target": {"type": "finding", "id": update.finding_id},
            "actor": update.updated_by,
            "timestamp": update.updated_at,
            "action": "confidence_revised",
            "reason": update.basis,
            "state_change": {
                "previous_score": update.previous_score,
                "new_score": update.new_score,
            },
        }));
    }
    transitions.sort_by(|a, b| {
        a.get("timestamp")
            .and_then(Value::as_str)
            .cmp(&b.get("timestamp").and_then(Value::as_str))
    });
    json!({
        "schema": "vela.state-transitions.v0",
        "frontier": frontier.project.name,
        "transitions": transitions,
    })
}

/// Build a content-addressed FindingBundle from CLI-supplied options.
/// Shared by `finding.add` and v0.14 `finding.supersede`.
fn build_finding_bundle(options: &FindingDraftOptions) -> FindingBundle {
    let now = Utc::now().to_rfc3339();
    let assertion = Assertion {
        text: options.text.clone(),
        assertion_type: options.assertion_type.clone(),
        entities: vec![],
        relation: None,
        direction: None,
        causal_claim: None,
        causal_evidence_grade: None,
    };
    let evidence = Evidence {
        evidence_type: options.evidence_type.clone(),
        model_system: String::new(),
        method: if options.evidence_type == "experimental" {
            "manual state transition; control details require source inspection".to_string()
        } else {
            "manual state transition".to_string()
        },
        replicated: false,
        replication_count: None,
        evidence_spans: options.evidence_spans.clone(),
    };
    let conditions = Conditions {
        text: options.conditions_text.clone().unwrap_or_else(|| {
            "Manually added finding; requires evidence review before scientific use.".to_string()
        }),
        duration: None,
    };
    let confidence = Confidence {
        kind: ConfidenceKind::FrontierEpistemic,
        score: options.confidence,
        basis: "operator-supplied frontier prior; review required".to_string(),
        method: ConfidenceMethod::ExpertJudgment,
        components: None,
        extraction_confidence: 1.0,
    };
    let source_authors = if options.source_authors.is_empty() {
        vec![Author {
            name: options.author.clone(),
            orcid: None,
        }]
    } else {
        options
            .source_authors
            .iter()
            .map(|name| Author {
                name: name.clone(),
                orcid: None,
            })
            .collect()
    };
    let provenance = Provenance {
        source_type: options.source_type.clone(),
        doi: options.doi.clone(),
        url: options.url.clone(),
        title: options.source.clone(),
        authors: source_authors,
        year: options.year,
        license: None,
        publisher: None,
        funders: Vec::new(),
        extraction: Extraction {
            method: "manual_curation".to_string(),
            model: None,
            model_version: None,
            extracted_at: now,
            extractor_version: project::VELA_COMPILER_VERSION.to_string(),
        },
        review: Some(Review {
            reviewed: false,
            reviewer: None,
            reviewed_at: None,
            corrections: Vec::new(),
        }),
    };
    let flags = Flags {
        gap: options.gap,
        negative_space: options.negative_space,
        ..Default::default()
    };
    FindingBundle::new(
        assertion, evidence, conditions, confidence, provenance, flags,
    )
}

/// v0.14: build the proposal that supersedes `old_id` with a new finding bundle.
pub fn supersede_finding(
    path: &Path,
    old_id: &str,
    reason: &str,
    options: FindingDraftOptions,
    apply: bool,
) -> Result<StateCommandReport, String> {
    validate_score(options.confidence)?;
    if reason.trim().is_empty() {
        return Err("--reason is required for finding supersede".to_string());
    }
    let new_finding = build_finding_bundle(&options);
    if new_finding.id == old_id {
        return Err(
            "supersede new assertion must produce a different content address than the old finding (change assertion text, type, or provenance to derive a distinct vf_…)"
                .to_string(),
        );
    }
    let proposal = proposals::new_proposal(
        "finding.supersede",
        events::StateTarget {
            r#type: "finding".to_string(),
            id: old_id.to_string(),
        },
        options.author.clone(),
        "human",
        reason.to_string(),
        json!({"new_finding": new_finding}),
        Vec::new(),
        Vec::new(),
    );
    let result = proposals::create_or_apply(path, proposal, apply)?;
    let frontier = repo::load_from_path(path)?;
    Ok(StateCommandReport {
        ok: true,
        command: "finding.supersede".to_string(),
        frontier: frontier.project.name,
        finding_id: result.finding_id,
        proposal_id: result.proposal_id,
        proposal_status: result.status.clone(),
        applied_event_id: result.applied_event_id,
        wrote_to: path.display().to_string(),
        message: if result.status == "applied" {
            "Supersede proposal applied".to_string()
        } else {
            "Supersede proposal recorded".to_string()
        },
    })
}

fn build_add_finding_proposal(options: FindingDraftOptions) -> Result<StateProposal, String> {
    let now = Utc::now().to_rfc3339();
    let assertion = Assertion {
        text: options.text.clone(),
        assertion_type: options.assertion_type.clone(),
        entities: vec![],
        relation: None,
        direction: None,
        causal_claim: None,
        causal_evidence_grade: None,
    };
    let evidence = Evidence {
        evidence_type: options.evidence_type.clone(),
        model_system: String::new(),
        method: if options.evidence_type == "experimental" {
            "manual state transition; control details require source inspection".to_string()
        } else {
            "manual state transition".to_string()
        },
        replicated: false,
        replication_count: None,
        evidence_spans: options.evidence_spans.clone(),
    };
    // v0.11: conditions text falls back to the v0.10 placeholder only when
    // the caller didn't supply --conditions-text. The placeholder is a
    // signal to a reviewer that scope needs to be added; once a real
    // conditions string is provided, the placeholder isn't useful.
    let conditions = Conditions {
        text: options.conditions_text.clone().unwrap_or_else(|| {
            "Manually added finding; requires evidence review before scientific use.".to_string()
        }),
        duration: None,
    };
    let confidence = Confidence {
        kind: ConfidenceKind::FrontierEpistemic,
        score: options.confidence,
        basis: "operator-supplied frontier prior; review required".to_string(),
        method: ConfidenceMethod::ExpertJudgment,
        components: None,
        extraction_confidence: 1.0,
    };
    // v0.11: structured provenance. Source authors (the paper's authors)
    // are distinct from the Vela actor that curated the finding. When
    // --authors is omitted, fall back to the curator-as-author shape used
    // pre-v0.11 so existing scripts keep working.
    let source_authors = if options.source_authors.is_empty() {
        vec![Author {
            name: options.author.clone(),
            orcid: None,
        }]
    } else {
        options
            .source_authors
            .iter()
            .map(|name| Author {
                name: name.clone(),
                orcid: None,
            })
            .collect()
    };
    let provenance = Provenance {
        source_type: options.source_type.clone(),
        doi: options.doi.clone(),
        url: options.url.clone(),
        title: options.source.clone(),
        authors: source_authors,
        year: options.year,
        license: None,
        publisher: None,
        funders: Vec::new(),
        extraction: Extraction {
            method: "manual_curation".to_string(),
            model: None,
            model_version: None,
            extracted_at: now.clone(),
            extractor_version: project::VELA_COMPILER_VERSION.to_string(),
        },
        review: Some(Review {
            reviewed: false,
            reviewer: None,
            reviewed_at: None,
            corrections: Vec::new(),
        }),
    };
    let flags = Flags {
        gap: options.gap,
        negative_space: options.negative_space,
        ..Default::default()
    };
    let finding = FindingBundle::new(
        assertion, evidence, conditions, confidence, provenance, flags,
    );
    let finding_id = finding.id.clone();
    // An agent author (e.g. `agent:replicator`) registers as an agent actor.
    let actor_type = if options.author.starts_with("agent:") {
        "agent"
    } else {
        "human"
    };
    // v0.339: a replication attestation rides as a sibling of `finding` so the
    // accept gate can verify it without changing the finding.add shape.
    let payload = match options.replication_attestation {
        Some(att) => json!({"finding": finding, "replication_attestation": att}),
        None => json!({"finding": finding}),
    };
    Ok(proposals::new_proposal(
        "finding.add",
        events::StateTarget {
            r#type: "finding".to_string(),
            id: finding_id,
        },
        options.author,
        actor_type,
        "Manual finding added to frontier state",
        payload,
        Vec::new(),
        vec!["Manual findings require evidence review before scientific use.".to_string()],
    ))
}

fn find_finding_index(frontier: &Project, finding_id: &str) -> Result<usize, String> {
    frontier
        .findings
        .iter()
        .position(|finding| finding.id == finding_id)
        .ok_or_else(|| format!("Finding not found: {finding_id}"))
}

fn confidence_update_id(update: &crate::bundle::ConfidenceUpdate) -> String {
    let hash = Sha256::digest(
        format!(
            "{}|{}|{}|{}|{}",
            update.finding_id,
            update.previous_score,
            update.new_score,
            update.updated_by,
            update.updated_at
        )
        .as_bytes(),
    );
    format!("cu_{}", &hex::encode(hash)[..16])
}

fn validate_score(score: f64) -> Result<(), String> {
    if (0.0..=1.0).contains(&score) {
        Ok(())
    } else {
        Err("--confidence must be between 0.0 and 1.0".to_string())
    }
}

#[cfg(test)]
mod v0_11_finding_tests {
    use super::*;
    use crate::bundle;

    fn base_options() -> FindingDraftOptions {
        FindingDraftOptions {
            text: "Test claim".to_string(),
            assertion_type: "mechanism".to_string(),
            source: "Test 2024".to_string(),
            source_type: "published_paper".to_string(),
            author: "reviewer:test".to_string(),
            confidence: 0.5,
            evidence_type: "experimental".to_string(),
            doi: None,
            year: None,
            url: None,
            source_authors: Vec::new(),
            conditions_text: None,
            evidence_spans: Vec::new(),
            gap: false,
            negative_space: false,
            replication_attestation: None,
        }
    }

    #[test]
    fn provenance_flags_populate_structured_fields() {
        let mut opts = base_options();
        opts.doi = Some("10.1056/NEJMoa2212948".to_string());
        opts.year = Some(2023);
        opts.url = Some("https://nejm.org/...".to_string());
        opts.source_authors = vec!["van Dyck CH".to_string(), "Swanson CJ".to_string()];
        let proposal = build_add_finding_proposal(opts).unwrap();
        let finding: bundle::FindingBundle =
            serde_json::from_value(proposal.payload["finding"].clone()).unwrap();
        assert_eq!(
            finding.provenance.doi.as_deref(),
            Some("10.1056/NEJMoa2212948")
        );
        assert_eq!(finding.provenance.year, Some(2023));
        assert_eq!(
            finding.provenance.url.as_deref(),
            Some("https://nejm.org/...")
        );
        assert_eq!(
            finding
                .provenance
                .authors
                .iter()
                .map(|a| a.name.as_str())
                .collect::<Vec<_>>(),
            vec!["van Dyck CH", "Swanson CJ"],
        );
    }

    #[test]
    fn conditions_flags_populate_structured_fields() {
        let mut opts = base_options();
        opts.conditions_text = Some("Phase 3 RCT, 18 mo".to_string());
        let proposal = build_add_finding_proposal(opts).unwrap();
        let finding: bundle::FindingBundle =
            serde_json::from_value(proposal.payload["finding"].clone()).unwrap();
        assert_eq!(finding.conditions.text, "Phase 3 RCT, 18 mo");
    }

    #[test]
    fn reviewed_entities_spans_and_gap_flags_populate_structured_fields() {
        let mut opts = base_options();
        opts.evidence_spans = vec![json!({
            "section": "abstract",
            "text": "Lecanemab slowed decline under early symptomatic AD trial conditions."
        })];
        opts.gap = true;
        opts.negative_space = true;

        let proposal = build_add_finding_proposal(opts).unwrap();
        let finding: bundle::FindingBundle =
            serde_json::from_value(proposal.payload["finding"].clone()).unwrap();

        assert_eq!(finding.evidence.evidence_spans.len(), 1);
        assert_eq!(
            finding.evidence.evidence_spans[0]["section"].as_str(),
            Some("abstract")
        );
        assert!(finding.flags.gap);
        assert!(finding.flags.negative_space);
    }

    #[test]
    fn omitted_flags_fall_back_to_pre_v011_shape() {
        let proposal = build_add_finding_proposal(base_options()).unwrap();
        let finding: bundle::FindingBundle =
            serde_json::from_value(proposal.payload["finding"].clone()).unwrap();
        // Pre-v0.11 placeholder remains when --conditions-text is omitted.
        assert!(
            finding
                .conditions
                .text
                .starts_with("Manually added finding")
        );
        // No --source-authors → curator fills the authors slot, as in v0.10.
        assert_eq!(finding.provenance.authors.len(), 1);
        assert_eq!(finding.provenance.authors[0].name, "reviewer:test");
        // None of the new optional provenance fields populated.
        assert!(finding.provenance.doi.is_none());
        assert!(finding.provenance.year.is_none());
        assert!(finding.provenance.url.is_none());
    }
}

#[cfg(test)]
mod v0_38_causal_tests {
    use super::*;
    use crate::bundle::{CausalClaim, CausalEvidenceGrade};
    use tempfile::tempdir;

    fn seed_frontier(dir: &Path) -> std::path::PathBuf {
        let path = dir.join("frontier.json");
        let opts = FindingDraftOptions {
            text: "X causes Y".to_string(),
            assertion_type: "mechanism".to_string(),
            source: "test".to_string(),
            source_type: "published_paper".to_string(),
            author: "reviewer:test".to_string(),
            confidence: 0.5,
            evidence_type: "experimental".to_string(),
            doi: None,
            year: Some(2025),
            url: None,
            source_authors: Vec::new(),
            conditions_text: None,
            evidence_spans: Vec::new(),
            gap: false,
            negative_space: false,
            replication_attestation: None,
        };
        let proposal = build_add_finding_proposal(opts).unwrap();
        let finding: FindingBundle =
            serde_json::from_value(proposal.payload["finding"].clone()).unwrap();
        let project = project::assemble("Test", vec![finding], 1, 0, "test causal frontier");
        repo::save_to_path(&path, &project).unwrap();
        path
    }

    #[test]
    fn set_causal_writes_fields_and_appends_event() {
        let dir = tempdir().unwrap();
        let path = seed_frontier(dir.path());
        let project = repo::load_from_path(&path).unwrap();
        let finding_id = project.findings[0].id.clone();

        let report = set_causal(
            &path,
            &finding_id,
            "intervention",
            Some("rct"),
            "reviewer:test",
            "phase 3 RCT supports do(X=x) reading",
        )
        .unwrap();
        assert!(report.applied_event_id.is_some());

        let after = repo::load_from_path(&path).unwrap();
        let f = &after.findings[0];
        assert_eq!(f.assertion.causal_claim, Some(CausalClaim::Intervention));
        assert_eq!(
            f.assertion.causal_evidence_grade,
            Some(CausalEvidenceGrade::Rct)
        );

        let last_event = after.events.last().expect("an event was appended");
        assert_eq!(last_event.kind, "assertion.reinterpreted_causal");
        assert_eq!(last_event.target.id, finding_id);
        assert_eq!(last_event.payload["after"]["claim"], "intervention");
        assert_eq!(last_event.payload["after"]["grade"], "rct");
    }

    #[test]
    fn set_causal_rejects_invalid_claim() {
        let dir = tempdir().unwrap();
        let path = seed_frontier(dir.path());
        let project = repo::load_from_path(&path).unwrap();
        let finding_id = project.findings[0].id.clone();
        let err =
            set_causal(&path, &finding_id, "magic", None, "reviewer:test", "test").unwrap_err();
        assert!(err.contains("invalid causal claim"));
    }

    #[test]
    fn set_causal_preserves_grade_when_only_claim_changes() {
        let dir = tempdir().unwrap();
        let path = seed_frontier(dir.path());
        let project = repo::load_from_path(&path).unwrap();
        let finding_id = project.findings[0].id.clone();

        // First set both.
        set_causal(
            &path,
            &finding_id,
            "correlation",
            Some("observational"),
            "reviewer:test",
            "initial reading",
        )
        .unwrap();
        // Then revise just the claim. Grade should persist.
        set_causal(
            &path,
            &finding_id,
            "mediation",
            None,
            "reviewer:test",
            "refined reading",
        )
        .unwrap();
        let after = repo::load_from_path(&path).unwrap();
        let f = &after.findings[0];
        assert_eq!(f.assertion.causal_claim, Some(CausalClaim::Mediation));
        assert_eq!(
            f.assertion.causal_evidence_grade,
            Some(CausalEvidenceGrade::Observational)
        );
        // Two events appended (one per call).
        let causal_events: usize = after
            .events
            .iter()
            .filter(|e| e.kind == "assertion.reinterpreted_causal")
            .count();
        assert_eq!(causal_events, 2);
    }
}
