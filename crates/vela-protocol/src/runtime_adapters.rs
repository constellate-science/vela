//! External runtime adapters that normalize upstream artifacts into Carina packets.
//!
//! Runtime systems can generate artifacts, posts, comments, and reviews. Vela
//! treats those records as source material: adapters convert them into
//! `carina.artifact_packet.v0.1`, then route through the existing
//! artifact-to-state proposal path. Artifact records may be applied immediately;
//! truth-changing finding, gap, and review-note proposals remain reviewable.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::artifact_to_state::{
    ARTIFACT_PACKET_SCHEMA, ArtifactPacket, ImportIdempotency, PacketArtifact,
    PacketCandidateClaim, PacketOpenNeed, PacketProducer,
};
use crate::canonical;
use crate::events::StateTarget;
use crate::proposals::{self, AgentRun};
use crate::source_inbox;
use crate::{artifact_to_state, repo};

pub const SCIENCECLAW_ARTIFACT_V1: &str = "scienceclaw-artifact-v1";
pub const AGENT_DISCOURSE_V1: &str = "agent-discourse-v1";

/// v0.76.2: Agent4Science-shape review packet adapter (stub).
///
/// The Gowers (2026-05-08) post argues for a path where AI-produced
/// results land in a venue moderated by human certification. This
/// adapter is the wire format for ingesting one Agent4Science-style
/// review packet (`carina.review_packet.v0.1`) as a proposal queued
/// for human-reviewer adjudication. The substrate does not auto-apply
/// the verdict; a reviewer signs an accept event under their own key.
///
/// See `docs/RELAY.md` for the contract and `docs/AI_ATTRIBUTION.md`
/// for the doctrine.
pub const AGENT4SCIENCE_REVIEW_V1: &str = "agent4science-review-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeAdapterRunOptions {
    pub adapter: String,
    pub input: PathBuf,
    pub actor: String,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub apply_artifacts: bool,
    #[serde(default)]
    pub write_inbox: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeAdapterRunReport {
    pub ok: bool,
    pub command: String,
    pub adapter: String,
    pub run_id: String,
    pub frontier: String,
    pub input: String,
    pub dry_run: bool,
    pub artifact_proposals: usize,
    pub finding_proposals: usize,
    pub gap_proposals: usize,
    #[serde(default)]
    pub review_note_proposals: usize,
    pub applied_artifact_events: usize,
    pub pending_truth_proposals: usize,
    pub proposal_ids: Vec<String>,
    #[serde(default)]
    pub review_proposal_ids: Vec<String>,
    pub applied_event_ids: Vec<String>,
    #[serde(default)]
    pub source_inbox_ids: Vec<String>,
    pub idempotency: ImportIdempotency,
    pub trusted_state_effect: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packet_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packet_path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
struct ScienceClawExport {
    schema: String,
    #[serde(default)]
    run_id: String,
    producer: PacketProducer,
    topic: String,
    created_at: String,
    #[serde(default)]
    artifacts: Vec<PacketArtifact>,
    #[serde(default)]
    candidate_claims: Vec<PacketCandidateClaim>,
    #[serde(default)]
    open_needs: Vec<PacketOpenNeed>,
    #[serde(default)]
    caveats: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct AgentDiscourseExport {
    schema: String,
    thread_id: String,
    runtime: DiscourseRuntime,
    topic: String,
    created_at: String,
    #[serde(default)]
    posts: Vec<DiscoursePost>,
    #[serde(default)]
    comments: Vec<DiscourseComment>,
    #[serde(default)]
    reviews: Vec<DiscourseReview>,
    #[serde(default)]
    open_needs: Vec<PacketOpenNeed>,
}

#[derive(Debug, Clone, Deserialize)]
struct DiscourseRuntime {
    id: String,
    name: String,
}

#[derive(Debug, Clone, Deserialize)]
struct DiscoursePost {
    id: String,
    title: String,
    assertion: String,
    #[serde(default)]
    body: String,
    locator: String,
    content_hash: String,
    #[serde(default)]
    conditions: Vec<String>,
    #[serde(default)]
    confidence: Option<f64>,
    #[serde(default)]
    source_refs: Vec<String>,
    #[serde(default)]
    target_finding_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct DiscourseComment {
    id: String,
    post_id: String,
    body: String,
    locator: String,
    content_hash: String,
    #[serde(default)]
    target_finding_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct DiscourseReview {
    id: String,
    post_id: String,
    decision: String,
    body: String,
    locator: String,
    content_hash: String,
    #[serde(default)]
    target_finding_id: Option<String>,
}

#[derive(Debug, Clone)]
struct ReviewSignal {
    external_id: String,
    parent_id: String,
    target_finding_id: String,
    locator: String,
    body: String,
    decision: Option<String>,
}

#[derive(Debug, Clone)]
struct NormalizedRuntimePacket {
    packet: ArtifactPacket,
    review_signals: Vec<ReviewSignal>,
}

pub fn run(
    frontier_path: &Path,
    options: RuntimeAdapterRunOptions,
) -> Result<RuntimeAdapterRunReport, String> {
    if options.actor.trim().is_empty() {
        return Err("actor must be non-empty".to_string());
    }

    let frontier = repo::load_from_path(frontier_path)?;
    let input_path = resolve_input_path(&options.input)?;
    let input_value = read_json(&input_path)?;
    let run_id = run_id(&options.adapter, &input_value);
    let normalized = normalize_packet(&options.adapter, input_value, &run_id)?;
    let packet = normalized.packet.validate()?;
    let frontier_name = frontier.project.name.clone();

    if options.dry_run {
        return Ok(RuntimeAdapterRunReport {
            ok: true,
            command: "runtime-adapter.run".to_string(),
            adapter: options.adapter,
            run_id,
            frontier: frontier_name,
            input: input_path.display().to_string(),
            dry_run: true,
            artifact_proposals: 0,
            finding_proposals: 0,
            gap_proposals: 0,
            review_note_proposals: 0,
            applied_artifact_events: 0,
            pending_truth_proposals: 0,
            proposal_ids: Vec::new(),
            review_proposal_ids: Vec::new(),
            applied_event_ids: Vec::new(),
            source_inbox_ids: Vec::new(),
            idempotency: ImportIdempotency {
                packet_hash: packet_hash(&packet),
                duplicate_packet: false,
                skipped_existing_proposals: Vec::new(),
                skipped_existing_artifacts: Vec::new(),
            },
            trusted_state_effect: "none".to_string(),
            packet_id: Some(packet.packet_id),
            packet_path: None,
            run_path: None,
        });
    }

    let run_dir = runtime_runs_dir(frontier_path)?.join(&run_id);
    fs::create_dir_all(&run_dir).map_err(|e| {
        format!(
            "create runtime adapter run dir '{}': {e}",
            run_dir.display()
        )
    })?;
    fs::write(
        run_dir.join("input.json"),
        serde_json::to_vec_pretty(&read_json(&input_path)?)
            .map_err(|e| format!("serialize runtime adapter input: {e}"))?,
    )
    .map_err(|e| {
        format!(
            "write runtime adapter input '{}': {e}",
            input_path.display()
        )
    })?;

    let packet_path = run_dir.join("artifact-packet.json");
    fs::write(
        &packet_path,
        serde_json::to_vec_pretty(&packet).map_err(|e| format!("serialize packet: {e}"))?,
    )
    .map_err(|e| format!("write artifact packet '{}': {e}", packet_path.display()))?;

    let import_report = artifact_to_state::import_packet_at_path(
        frontier_path,
        &packet_path,
        &options.actor,
        options.apply_artifacts,
    )?;
    update_import_agent_runs(
        frontier_path,
        &import_report.proposal_ids,
        &options.adapter,
        &run_id,
        &packet.packet_id,
        &input_path,
    )?;
    let review_proposal_ids = create_review_note_proposals(
        frontier_path,
        &options,
        &run_id,
        &packet.packet_id,
        &normalized.review_signals,
    )?;
    let mut proposal_ids = import_report.proposal_ids.clone();
    proposal_ids.extend(review_proposal_ids.clone());
    let source_inbox_ids = if options.write_inbox {
        write_runtime_source_inbox_records(frontier_path, &options.adapter, &run_id, &packet)?
    } else {
        Vec::new()
    };

    let final_run = json!({
        "schema": "vela.runtime-adapter-run.v1",
        "run_id": run_id,
        "adapter": options.adapter,
        "frontier": frontier_name,
        "input": input_path.display().to_string(),
        "started_at": packet.created_at,
        "packet_id": packet.packet_id,
        "packet_path": "artifact-packet.json",
        "artifact_proposals": import_report.artifact_proposals,
        "finding_proposals": import_report.finding_proposals,
        "gap_proposals": import_report.gap_proposals,
        "review_note_proposals": review_proposal_ids.len(),
        "proposal_ids": proposal_ids,
        "review_proposal_ids": review_proposal_ids,
        "source_inbox_ids": source_inbox_ids,
        "applied_event_ids": import_report.applied_event_ids,
        "idempotency": import_report.idempotency,
        "trusted_state_effect": import_report.trusted_state_effect,
        "external_runtime": external_runtime_summary(&packet),
    });
    fs::write(
        run_dir.join("run.json"),
        serde_json::to_vec_pretty(&final_run).map_err(|e| format!("serialize run: {e}"))?,
    )
    .map_err(|e| format!("write runtime adapter run '{}': {e}", run_dir.display()))?;

    Ok(RuntimeAdapterRunReport {
        ok: true,
        command: "runtime-adapter.run".to_string(),
        adapter: options.adapter,
        run_id,
        frontier: frontier_name,
        input: input_path.display().to_string(),
        dry_run: false,
        artifact_proposals: import_report.artifact_proposals,
        finding_proposals: import_report.finding_proposals,
        gap_proposals: import_report.gap_proposals,
        review_note_proposals: review_proposal_ids.len(),
        applied_artifact_events: import_report.applied_artifact_events,
        pending_truth_proposals: import_report.pending_truth_proposals,
        proposal_ids,
        review_proposal_ids,
        applied_event_ids: import_report.applied_event_ids,
        source_inbox_ids,
        idempotency: import_report.idempotency,
        trusted_state_effect: import_report.trusted_state_effect,
        packet_id: Some(packet.packet_id),
        packet_path: Some(packet_path),
        run_path: Some(run_dir),
    })
}

fn packet_hash(packet: &ArtifactPacket) -> String {
    let bytes = canonical::to_canonical_bytes(packet).unwrap_or_default();
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn write_runtime_source_inbox_records(
    frontier_path: &Path,
    adapter: &str,
    run_id: &str,
    packet: &ArtifactPacket,
) -> Result<Vec<String>, String> {
    let mut ids = Vec::new();
    for artifact in &packet.artifacts {
        let inbox = source_inbox::upsert_adapter_record(
            frontier_path,
            adapter,
            run_id,
            &artifact.id,
            &artifact.id,
            &artifact.title,
            &artifact.locator,
            &artifact.kind,
            &artifact.content_hash,
            "runtime_material",
        )?;
        ids.push(inbox.id);
    }
    ids.sort();
    ids.dedup();
    Ok(ids)
}

fn normalize_packet(
    adapter: &str,
    input: Value,
    run_id: &str,
) -> Result<NormalizedRuntimePacket, String> {
    match adapter {
        SCIENCECLAW_ARTIFACT_V1 => normalize_scienceclaw(input, run_id),
        AGENT_DISCOURSE_V1 => normalize_agent_discourse(input, run_id),
        AGENT4SCIENCE_REVIEW_V1 => normalize_agent4science_review(input, run_id),
        _ => Err(format!("unsupported runtime adapter '{adapter}'")),
    }
}

/// v0.76.2: Agent4Science review-packet shape.
///
/// ```json
/// {
///   "schema": "carina.review_packet.v0.1",
///   "review_id": "rev_<hex>",
///   "target_finding_id": "vf_<hex>",
///   "verdict": "accepted | needs_revision | contested | rejected",
///   "reasoning": "...",
///   "reviewer": {"id": "reviewer:...", "type": "human" | "agent"},
///   "evidence": [{"locator": "...", "span": "..."}],
///   "signature": "ed25519:..."
/// }
/// ```
///
/// Stub: parses the shape, validates required fields, and emits one
/// ReviewSignal pointing at the target finding so the existing
/// `create_review_note_proposals` pipeline writes a `finding.note`
/// proposal recording the verdict. The substrate does not turn the
/// verdict into an accept event; a reviewer must sign that
/// separately. See `docs/AI_ATTRIBUTION.md`.
#[derive(Debug, Clone, serde::Deserialize)]
struct Agent4ScienceReviewPacket {
    schema: String,
    review_id: String,
    target_finding_id: String,
    verdict: String,
    reasoning: String,
    reviewer: Agent4ScienceReviewer,
    #[serde(default)]
    evidence: Vec<Agent4ScienceEvidence>,
    #[serde(default)]
    signature: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct Agent4ScienceReviewer {
    id: String,
    #[serde(rename = "type")]
    actor_type: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct Agent4ScienceEvidence {
    locator: String,
    /// Optional source-span text. The stub doesn't propagate it
    /// downstream yet; future revisions can carry it onto the
    /// generated proposal's evidence_spans.
    #[serde(default)]
    #[allow(dead_code)]
    span: Option<String>,
}

const AGENT4SCIENCE_REVIEW_SCHEMA: &str = "carina.review_packet.v0.1";

fn normalize_agent4science_review(
    input: Value,
    run_id: &str,
) -> Result<NormalizedRuntimePacket, String> {
    let packet: Agent4ScienceReviewPacket = serde_json::from_value(input)
        .map_err(|e| format!("parse agent4science review packet: {e}"))?;
    if packet.schema != AGENT4SCIENCE_REVIEW_SCHEMA {
        return Err(format!(
            "unsupported agent4science review schema '{}', expected '{AGENT4SCIENCE_REVIEW_SCHEMA}'",
            packet.schema
        ));
    }
    if !packet.target_finding_id.starts_with("vf_") {
        return Err(format!(
            "target_finding_id must start with 'vf_', got '{}'",
            packet.target_finding_id
        ));
    }
    if !["accepted", "needs_revision", "contested", "rejected"].contains(&packet.verdict.as_str()) {
        return Err(format!("verdict '{}' not in allowlist", packet.verdict));
    }
    if !["human", "agent"].contains(&packet.reviewer.actor_type.as_str()) {
        return Err(format!(
            "reviewer.type '{}' must be 'human' or 'agent'",
            packet.reviewer.actor_type
        ));
    }

    // The stub maps the verdict + reasoning into a single review signal
    // so the existing pipeline drafts a finding.note proposal under
    // `agent:agent4science-review-bot` (or the supplied reviewer id).
    // A human reviewer adjudicates the verdict by writing a separate
    // `finding.review` proposal + accept event.
    let body = format!(
        "Agent4Science review {}: {}. Reasoning: {}.",
        packet.review_id, packet.verdict, packet.reasoning
    );
    let locator = packet
        .evidence
        .first()
        .map(|e| e.locator.clone())
        .unwrap_or_else(|| format!("agent4science:review:{}", packet.review_id));

    let mut metadata = BTreeMap::new();
    metadata.insert("external_object_kind".to_string(), json!("review_packet"));
    metadata.insert(
        "external_object_id".to_string(),
        json!(packet.review_id.clone()),
    );
    metadata.insert("verdict".to_string(), json!(packet.verdict.clone()));
    metadata.insert("reviewer_id".to_string(), json!(packet.reviewer.id.clone()));
    metadata.insert(
        "reviewer_type".to_string(),
        json!(packet.reviewer.actor_type.clone()),
    );
    metadata.insert(
        "target_findings".to_string(),
        json!([packet.target_finding_id.clone()]),
    );
    if let Some(sig) = &packet.signature {
        metadata.insert("signature".to_string(), json!(sig));
    }

    let content_hash = format!("sha256:{}", hex::encode(Sha256::digest(body.as_bytes())));

    let artifact = PacketArtifact {
        id: packet.review_id.clone(),
        // Use `source_file` (one of VALID_ARTIFACT_KINDS in
        // bundle.rs); the AGENT_DISCOURSE_V1 adapter does the same
        // for review records. The agent4science-specific shape is
        // captured in metadata.external_object_kind.
        kind: "source_file".to_string(),
        title: format!("Agent4Science review {}", packet.review_id),
        locator: locator.clone(),
        content_hash,
        parents: Vec::new(),
        metadata,
    };

    let review_signals = vec![ReviewSignal {
        external_id: packet.review_id.clone(),
        parent_id: packet.review_id.clone(),
        target_finding_id: packet.target_finding_id.clone(),
        locator,
        body: body.clone(),
        decision: Some(packet.verdict.clone()),
    }];

    let inner_packet = ArtifactPacket {
        schema: ARTIFACT_PACKET_SCHEMA.to_string(),
        packet_id: packet_id(AGENT4SCIENCE_REVIEW_V1, run_id, &packet.review_id),
        producer: PacketProducer {
            kind: packet.reviewer.actor_type.clone(),
            id: packet.reviewer.id.clone(),
            name: format!("agent4science:{}", packet.reviewer.id),
        },
        topic: "agent4science.review".to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
        artifacts: vec![artifact],
        candidate_claims: Vec::new(),
        open_needs: Vec::new(),
        caveats: bridge_caveats(vec![
            "Agent4Science review packets are review signals, not canonical truth. A human reviewer must sign an accept event."
                .to_string(),
        ]),
    };

    Ok(NormalizedRuntimePacket {
        packet: with_runtime_metadata(inner_packet, AGENT4SCIENCE_REVIEW_V1, run_id),
        review_signals,
    })
}

fn normalize_scienceclaw(input: Value, run_id: &str) -> Result<NormalizedRuntimePacket, String> {
    if input.get("schema").and_then(Value::as_str) == Some(ARTIFACT_PACKET_SCHEMA) {
        let packet: ArtifactPacket =
            serde_json::from_value(input).map_err(|e| format!("parse artifact packet: {e}"))?;
        return Ok(NormalizedRuntimePacket {
            packet: with_runtime_metadata(packet, SCIENCECLAW_ARTIFACT_V1, run_id),
            review_signals: Vec::new(),
        });
    }

    let export: ScienceClawExport =
        serde_json::from_value(input).map_err(|e| format!("parse ScienceClaw export: {e}"))?;
    if export.schema != "scienceclaw.artifact_export.v1" {
        return Err(format!(
            "unsupported ScienceClaw export schema '{}'",
            export.schema
        ));
    }
    let packet = ArtifactPacket {
        schema: ARTIFACT_PACKET_SCHEMA.to_string(),
        packet_id: packet_id(SCIENCECLAW_ARTIFACT_V1, run_id, &export.run_id),
        producer: export.producer,
        topic: export.topic,
        created_at: export.created_at,
        artifacts: export.artifacts,
        candidate_claims: export.candidate_claims,
        open_needs: export.open_needs,
        caveats: bridge_caveats(export.caveats),
    };
    Ok(NormalizedRuntimePacket {
        packet: with_runtime_metadata(packet, SCIENCECLAW_ARTIFACT_V1, run_id),
        review_signals: Vec::new(),
    })
}

fn normalize_agent_discourse(
    input: Value,
    run_id: &str,
) -> Result<NormalizedRuntimePacket, String> {
    let export: AgentDiscourseExport =
        serde_json::from_value(input).map_err(|e| format!("parse agent discourse export: {e}"))?;
    if export.schema != "agent_discourse.v1" {
        return Err(format!(
            "unsupported agent discourse export schema '{}'",
            export.schema
        ));
    }

    let mut artifacts = Vec::new();
    let mut candidate_claims = Vec::new();
    let mut review_signals = Vec::new();

    for post in &export.posts {
        let mut metadata = BTreeMap::new();
        metadata.insert("external_object_kind".to_string(), json!("post"));
        metadata.insert("external_object_id".to_string(), json!(post.id));
        metadata.insert("body".to_string(), json!(post.body));
        if let Some(target) = &post.target_finding_id {
            metadata.insert("target_findings".to_string(), json!([target]));
        }
        artifacts.push(PacketArtifact {
            id: post.id.clone(),
            kind: "model_output".to_string(),
            title: post.title.clone(),
            locator: post.locator.clone(),
            content_hash: post.content_hash.clone(),
            parents: Vec::new(),
            metadata,
        });
        candidate_claims.push(PacketCandidateClaim {
            id: format!("claim_{}", post.id),
            assertion: post.assertion.clone(),
            assertion_type: "therapeutic".to_string(),
            evidence_artifact_ids: vec![post.id.clone()],
            source_refs: source_refs_with_locator(&post.source_refs, &post.locator),
            conditions: post.conditions.clone(),
            confidence: post.confidence.unwrap_or(0.5),
            caveats: vec![
                "Agent discourse post is a candidate claim; reviewer acceptance required."
                    .to_string(),
            ],
        });
    }

    for comment in &export.comments {
        let mut metadata = BTreeMap::new();
        metadata.insert("external_object_kind".to_string(), json!("comment"));
        metadata.insert("external_object_id".to_string(), json!(comment.id));
        metadata.insert("body".to_string(), json!(comment.body));
        if let Some(target) = &comment.target_finding_id {
            metadata.insert("target_findings".to_string(), json!([target]));
            review_signals.push(ReviewSignal {
                external_id: comment.id.clone(),
                parent_id: comment.post_id.clone(),
                target_finding_id: target.clone(),
                locator: comment.locator.clone(),
                body: comment.body.clone(),
                decision: None,
            });
        }
        artifacts.push(PacketArtifact {
            id: comment.id.clone(),
            kind: "source_file".to_string(),
            title: format!("Discourse comment {}", comment.id),
            locator: comment.locator.clone(),
            content_hash: comment.content_hash.clone(),
            parents: vec![comment.post_id.clone()],
            metadata,
        });
    }

    for review in &export.reviews {
        let mut metadata = BTreeMap::new();
        metadata.insert("external_object_kind".to_string(), json!("review"));
        metadata.insert("external_object_id".to_string(), json!(review.id));
        metadata.insert("decision".to_string(), json!(review.decision));
        metadata.insert("body".to_string(), json!(review.body));
        if let Some(target) = &review.target_finding_id {
            metadata.insert("target_findings".to_string(), json!([target]));
            review_signals.push(ReviewSignal {
                external_id: review.id.clone(),
                parent_id: review.post_id.clone(),
                target_finding_id: target.clone(),
                locator: review.locator.clone(),
                body: review.body.clone(),
                decision: Some(review.decision.clone()),
            });
        }
        artifacts.push(PacketArtifact {
            id: review.id.clone(),
            kind: "source_file".to_string(),
            title: format!("Discourse review {}", review.id),
            locator: review.locator.clone(),
            content_hash: review.content_hash.clone(),
            parents: vec![review.post_id.clone()],
            metadata,
        });
    }

    let packet = ArtifactPacket {
        schema: ARTIFACT_PACKET_SCHEMA.to_string(),
        packet_id: packet_id(AGENT_DISCOURSE_V1, run_id, &export.thread_id),
        producer: PacketProducer {
            kind: "agent".to_string(),
            id: format!("agent:{}", export.runtime.id),
            name: export.runtime.name,
        },
        topic: export.topic,
        created_at: export.created_at,
        artifacts,
        candidate_claims,
        open_needs: export.open_needs,
        caveats: bridge_caveats(vec![
            "Agent discourse is upstream review signal, not canonical truth.".to_string(),
        ]),
    };
    Ok(NormalizedRuntimePacket {
        packet: with_runtime_metadata(packet, AGENT_DISCOURSE_V1, run_id),
        review_signals,
    })
}

fn create_review_note_proposals(
    frontier_path: &Path,
    options: &RuntimeAdapterRunOptions,
    run_id: &str,
    packet_id: &str,
    review_signals: &[ReviewSignal],
) -> Result<Vec<String>, String> {
    let mut ids = Vec::new();
    for signal in review_signals {
        let text = match &signal.decision {
            Some(decision) => format!(
                "External runtime review {} on {} recorded decision '{}': {}. Treat this as review signal until a Vela reviewer accepts a state transition.",
                signal.external_id, signal.parent_id, decision, signal.body
            ),
            None => format!(
                "External runtime comment {} on {}: {}. Treat this as review signal until a Vela reviewer accepts a state transition.",
                signal.external_id, signal.parent_id, signal.body
            ),
        };
        let mut proposal = proposals::new_proposal(
            "finding.note",
            StateTarget {
                r#type: "finding".to_string(),
                id: signal.target_finding_id.clone(),
            },
            options.actor.clone(),
            actor_type(&options.actor),
            format!(
                "Import external runtime review signal {} from packet {}",
                signal.external_id, packet_id
            ),
            json!({
                "text": text,
                "runtime_adapter": options.adapter,
                "runtime_adapter_run_id": run_id,
                "artifact_packet_id": packet_id,
                "external_object_id": signal.external_id,
                "parent_external_object_id": signal.parent_id,
                "decision": signal.decision,
                "locator": signal.locator,
            }),
            vec![
                signal.locator.clone(),
                format!("runtime_adapter_run:{run_id}"),
                format!("runtime_packet:{packet_id}"),
            ],
            bridge_caveats(vec![
                "External comments and reviews are not canonical attestations.".to_string(),
            ]),
        );
        proposal.agent_run = Some(agent_run(&options.adapter, run_id, packet_id));
        let result = proposals::create_or_apply(frontier_path, proposal, false)?;
        ids.push(result.proposal_id);
    }
    Ok(ids)
}

fn update_import_agent_runs(
    frontier_path: &Path,
    proposal_ids: &[String],
    adapter: &str,
    run_id: &str,
    packet_id: &str,
    input_path: &Path,
) -> Result<(), String> {
    let mut frontier = repo::load_from_path(frontier_path)?;
    for proposal in &mut frontier.proposals {
        if proposal_ids.iter().any(|id| id == &proposal.id) {
            let mut run = proposal
                .agent_run
                .clone()
                .unwrap_or_else(|| agent_run(adapter, run_id, packet_id));
            run.model = format!("runtime-adapter:{adapter}");
            run.run_id = run_id.to_string();
            run.context
                .insert("runtime_adapter".to_string(), adapter.to_string());
            run.context
                .insert("runtime_adapter_run_id".to_string(), run_id.to_string());
            run.context
                .insert("artifact_packet_id".to_string(), packet_id.to_string());
            run.context
                .insert("input".to_string(), input_path.display().to_string());
            proposal.agent_run = Some(run);
        }
    }
    repo::save_to_path(frontier_path, &frontier)
}

fn with_runtime_metadata(
    mut packet: ArtifactPacket,
    adapter: &str,
    run_id: &str,
) -> ArtifactPacket {
    for artifact in &mut packet.artifacts {
        artifact
            .metadata
            .insert("runtime_adapter".to_string(), json!(adapter));
        artifact
            .metadata
            .insert("runtime_adapter_run_id".to_string(), json!(run_id));
        artifact
            .metadata
            .insert("external_runtime".to_string(), json!(packet.producer.name));
    }
    packet
}

fn bridge_caveats(mut caveats: Vec<String>) -> Vec<String> {
    caveats
        .push("External runtime output is source material until reviewer acceptance.".to_string());
    caveats.push(
        "External upvotes, comments, reviews, and agent confidence do not grant canonical authority."
            .to_string(),
    );
    caveats.sort();
    caveats.dedup();
    caveats
}

fn source_refs_with_locator(source_refs: &[String], locator: &str) -> Vec<String> {
    let mut refs = source_refs.to_vec();
    refs.push(locator.to_string());
    refs.sort();
    refs.dedup();
    refs
}

fn external_runtime_summary(packet: &ArtifactPacket) -> Value {
    json!({
        "producer": packet.producer,
        "topic": packet.topic,
        "artifact_count": packet.artifacts.len(),
        "candidate_claim_count": packet.candidate_claims.len(),
        "open_need_count": packet.open_needs.len(),
    })
}

fn actor_type(actor: &str) -> String {
    if actor.starts_with("agent:") {
        "agent".to_string()
    } else {
        "human".to_string()
    }
}

fn agent_run(adapter: &str, run_id: &str, packet_id: &str) -> AgentRun {
    let mut context = BTreeMap::new();
    context.insert("runtime_adapter".to_string(), adapter.to_string());
    context.insert("runtime_adapter_run_id".to_string(), run_id.to_string());
    context.insert("artifact_packet_id".to_string(), packet_id.to_string());
    AgentRun {
        agent: adapter.to_string(),
        model: format!("runtime-adapter:{adapter}"),
        run_id: run_id.to_string(),
        started_at: Utc::now().to_rfc3339(),
        finished_at: None,
        context,
        tool_calls: Vec::new(),
        permissions: None,
    }
}

fn runtime_runs_dir(frontier_path: &Path) -> Result<PathBuf, String> {
    match repo::detect(frontier_path)? {
        repo::VelaSource::VelaRepo(root) => Ok(root.join("ingest").join("runtime-runs")),
        repo::VelaSource::ProjectFile(path) => path
            .parent()
            .map(|parent| parent.join("ingest").join("runtime-runs"))
            .ok_or_else(|| format!("frontier file '{}' has no parent", path.display())),
        repo::VelaSource::PacketDir(dir) => Ok(dir.join("ingest").join("runtime-runs")),
    }
}

fn resolve_input_path(input: &Path) -> Result<PathBuf, String> {
    if input.is_file() {
        return Ok(input.to_path_buf());
    }
    if !input.is_dir() {
        return Err(format!(
            "runtime adapter input '{}' not found",
            input.display()
        ));
    }
    let default = input.join("runtime-export.json");
    if default.is_file() {
        return Ok(default);
    }
    let mut candidates = fs::read_dir(input)
        .map_err(|e| format!("read runtime adapter input dir '{}': {e}", input.display()))?
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
        .collect::<Vec<_>>();
    candidates.sort();
    candidates.into_iter().next().ok_or_else(|| {
        format!(
            "runtime adapter input dir '{}' has no JSON files",
            input.display()
        )
    })
}

fn read_json(path: &Path) -> Result<Value, String> {
    let bytes = fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("parse {}: {e}", path.display()))
}

fn run_id(adapter: &str, value: &Value) -> String {
    let bytes = canonical::to_canonical_bytes(&json!({
        "adapter": adapter,
        "input": value,
    }))
    .unwrap_or_default();
    format!("rir_{}", &hex::encode(Sha256::digest(bytes))[..16])
}

fn packet_id(adapter: &str, run_id: &str, external_id: &str) -> String {
    let bytes = canonical::to_canonical_bytes(&json!({
        "adapter": adapter,
        "run_id": run_id,
        "external_id": external_id,
    }))
    .unwrap_or_default();
    format!("cap_{}", &hex::encode(Sha256::digest(bytes))[..16])
}
