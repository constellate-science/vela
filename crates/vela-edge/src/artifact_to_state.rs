//! Import agent-produced artifact packets as reviewable frontier state.
//!
//! The adapter is intentionally local and schema-driven. It accepts a
//! ScienceClaw-shaped artifact DAG packet, converts artifacts into
//! reviewable `artifact.assert` proposals, and converts candidate
//! claims/open needs into `finding.add` proposals. Agent output is
//! source material until reviewers accept the resulting proposals.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use vela_protocol::access_tier::AccessTier;
use vela_protocol::bundle::{
    Artifact, Assertion, Author, Conditions, Confidence, ConfidenceKind, ConfidenceMethod, Entity,
    Evidence, Extraction, FindingBundle, Flags, Provenance, Review, valid_artifact_kind,
};
use vela_protocol::events::StateTarget;
use vela_protocol::project;
use vela_protocol::proposals::{self, AgentRun, StateProposal};

pub const ARTIFACT_PACKET_SCHEMA: &str = "carina.artifact_packet.v0.1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ArtifactPacket {
    pub schema: String,
    pub packet_id: String,
    pub producer: PacketProducer,
    pub topic: String,
    pub created_at: String,
    #[serde(default)]
    pub artifacts: Vec<PacketArtifact>,
    #[serde(default)]
    pub candidate_claims: Vec<PacketCandidateClaim>,
    #[serde(default)]
    pub open_needs: Vec<PacketOpenNeed>,
    #[serde(default)]
    pub caveats: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PacketProducer {
    pub kind: String,
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PacketArtifact {
    pub id: String,
    #[serde(alias = "artifact_type")]
    pub kind: String,
    #[serde(alias = "name")]
    pub title: String,
    pub locator: String,
    pub content_hash: String,
    #[serde(default)]
    pub parents: Vec<String>,
    #[serde(default)]
    pub metadata: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PacketCandidateClaim {
    pub id: String,
    pub assertion: String,
    pub assertion_type: String,
    #[serde(default)]
    pub evidence_artifact_ids: Vec<String>,
    #[serde(default)]
    pub source_refs: Vec<String>,
    #[serde(default)]
    pub conditions: Vec<String>,
    pub confidence: f64,
    #[serde(default)]
    pub caveats: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PacketOpenNeed {
    pub id: String,
    pub question: String,
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImportIdempotency {
    pub packet_hash: String,
    pub duplicate_packet: bool,
    #[serde(default)]
    pub skipped_existing_proposals: Vec<String>,
    #[serde(default)]
    pub skipped_existing_artifacts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactToStateReport {
    pub ok: bool,
    pub command: String,
    pub packet_id: String,
    pub frontier: String,
    pub artifact_proposals: usize,
    pub finding_proposals: usize,
    pub gap_proposals: usize,
    pub applied_artifact_events: usize,
    pub pending_truth_proposals: usize,
    pub proposal_ids: Vec<String>,
    pub applied_event_ids: Vec<String>,
    pub idempotency: ImportIdempotency,
    pub trusted_state_effect: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BridgeKitValidationReport {
    pub ok: bool,
    pub command: String,
    pub source: String,
    pub packet_count: usize,
    pub valid_packet_count: usize,
    pub invalid_packet_count: usize,
    #[serde(default)]
    pub errors: Vec<String>,
    pub packets: Vec<BridgeKitPacketReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BridgeKitPacketReport {
    pub path: String,
    pub ok: bool,
    pub packet_id: Option<String>,
    pub producer_id: Option<String>,
    pub artifact_count: usize,
    pub candidate_claim_count: usize,
    pub open_need_count: usize,
    #[serde(default)]
    pub errors: Vec<String>,
}

impl ArtifactPacket {
    pub fn from_path(path: &Path) -> Result<Self, String> {
        let bytes = fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        serde_json::from_slice(&bytes)
            .map_err(|e| format!("parse artifact packet {}: {e}", path.display()))
    }

    pub fn validate(self) -> Result<Self, String> {
        if self.schema != ARTIFACT_PACKET_SCHEMA {
            return Err(format!(
                "Unsupported artifact packet schema '{}'",
                self.schema
            ));
        }
        if !self.packet_id.starts_with("cap_") {
            return Err("packet_id must start with cap_".to_string());
        }
        if self.producer.id.trim().is_empty() {
            return Err("producer.id must be non-empty".to_string());
        }
        if self.topic.trim().is_empty() {
            return Err("topic must be non-empty".to_string());
        }
        if self.created_at.trim().is_empty() {
            return Err("created_at must be non-empty".to_string());
        }
        if self.artifacts.is_empty() {
            return Err("artifact packet must include at least one artifact".to_string());
        }

        let mut artifact_ids = BTreeSet::new();
        for artifact in &self.artifacts {
            if !artifact_ids.insert(artifact.id.clone()) {
                return Err(format!("duplicate artifact id {}", artifact.id));
            }
            if artifact.id.trim().is_empty() {
                return Err("artifact.id must be non-empty".to_string());
            }
            if !valid_artifact_kind(&artifact.kind) {
                return Err(format!(
                    "artifact {} has unsupported kind '{}'",
                    artifact.id, artifact.kind
                ));
            }
            if artifact.title.trim().is_empty() {
                return Err(format!("artifact {} title must be non-empty", artifact.id));
            }
            if artifact.locator.trim().is_empty() {
                return Err(format!(
                    "artifact {} locator must be non-empty",
                    artifact.id
                ));
            }
            normalize_packet_hash(&artifact.content_hash)?;
        }

        for artifact in &self.artifacts {
            for parent in &artifact.parents {
                if !artifact_ids.contains(parent) {
                    return Err(format!(
                        "artifact {} references unknown parent {}",
                        artifact.id, parent
                    ));
                }
                if parent == &artifact.id {
                    return Err(format!("artifact {} cannot parent itself", artifact.id));
                }
            }
        }

        for claim in &self.candidate_claims {
            if claim.id.trim().is_empty() {
                return Err("candidate_claim.id must be non-empty".to_string());
            }
            if claim.assertion.trim().is_empty() {
                return Err(format!("candidate claim {} assertion is empty", claim.id));
            }
            if !(0.0..=1.0).contains(&claim.confidence) {
                return Err(format!(
                    "candidate claim {} confidence must be between 0.0 and 1.0",
                    claim.id
                ));
            }
            if claim.evidence_artifact_ids.is_empty() {
                return Err(format!(
                    "candidate claim {} must reference at least one artifact",
                    claim.id
                ));
            }
            for artifact_id in &claim.evidence_artifact_ids {
                if !artifact_ids.contains(artifact_id) {
                    return Err(format!(
                        "candidate claim {} references unknown artifact {}",
                        claim.id, artifact_id
                    ));
                }
            }
        }

        for need in &self.open_needs {
            if need.id.trim().is_empty() {
                return Err("open_need.id must be non-empty".to_string());
            }
            if need.question.trim().is_empty() || need.rationale.trim().is_empty() {
                return Err(format!(
                    "open need {} requires question and rationale",
                    need.id
                ));
            }
        }

        Ok(self)
    }
}

pub fn validate_bridge_kit_path(path: &Path) -> BridgeKitValidationReport {
    let mut errors = Vec::new();
    let mut packet_paths = Vec::new();

    if path.is_dir() {
        match fs::read_dir(path) {
            Ok(entries) => {
                for entry in entries.flatten() {
                    let candidate = entry.path();
                    if candidate.extension().and_then(|ext| ext.to_str()) == Some("json") {
                        packet_paths.push(candidate);
                    }
                }
                packet_paths.sort();
                if packet_paths.is_empty() {
                    errors.push(format!("no JSON packet files found in {}", path.display()));
                }
            }
            Err(e) => errors.push(format!("read directory {}: {e}", path.display())),
        }
    } else {
        packet_paths.push(path.to_path_buf());
    }

    let packets = packet_paths
        .iter()
        .map(|packet_path| validate_bridge_kit_packet(packet_path))
        .collect::<Vec<_>>();
    let packet_count = packets.len();
    let valid_packet_count = packets.iter().filter(|packet| packet.ok).count();
    let invalid_packet_count = packets.iter().filter(|packet| !packet.ok).count();
    let ok = errors.is_empty() && packet_count > 0 && invalid_packet_count == 0;

    BridgeKitValidationReport {
        ok,
        command: "bridge-kit.validate".to_string(),
        source: path.display().to_string(),
        packet_count,
        valid_packet_count,
        invalid_packet_count,
        errors,
        packets,
    }
}

fn validate_bridge_kit_packet(path: &Path) -> BridgeKitPacketReport {
    match ArtifactPacket::from_path(path).and_then(|packet| packet.validate()) {
        Ok(packet) => BridgeKitPacketReport {
            path: path.display().to_string(),
            ok: true,
            packet_id: Some(packet.packet_id),
            producer_id: Some(packet.producer.id),
            artifact_count: packet.artifacts.len(),
            candidate_claim_count: packet.candidate_claims.len(),
            open_need_count: packet.open_needs.len(),
            errors: Vec::new(),
        },
        Err(e) => BridgeKitPacketReport {
            path: path.display().to_string(),
            ok: false,
            packet_id: None,
            producer_id: None,
            artifact_count: 0,
            candidate_claim_count: 0,
            open_need_count: 0,
            errors: vec![e],
        },
    }
}

pub fn import_packet_at_path(
    frontier_path: &Path,
    packet_path: &Path,
    actor_id: &str,
    apply_artifacts: bool,
) -> Result<ArtifactToStateReport, String> {
    if actor_id.trim().is_empty() {
        return Err("actor must be non-empty".to_string());
    }
    let packet = ArtifactPacket::from_path(packet_path)?.validate()?;
    let packet_hash = packet_hash(&packet);
    let before_frontier = vela_protocol::repo::load_from_path(frontier_path)?;
    // Dedup key is the CONTENT-ADDRESSED target id (vf_/va_), not the freshly
    // minted per-call proposal id (which is why the previous identity check
    // never matched and re-ingest duplicated everything). A target already
    // present as a finding, an artifact, or an existing proposal is not
    // re-proposed — so re-ingesting an unchanged packet is a no-op, and only
    // genuinely new claims become new proposals.
    let mut seen_targets = before_frontier
        .findings
        .iter()
        .map(|finding| finding.id.clone())
        .chain(before_frontier.artifacts.iter().map(|a| a.id.clone()))
        .chain(
            before_frontier
                .proposals
                .iter()
                .map(|p| p.target.id.clone()),
        )
        .collect::<BTreeSet<_>>();
    let mut proposal_ids = Vec::new();
    let mut applied_event_ids = Vec::new();
    let mut skipped_existing_proposals = Vec::new();
    let mut skipped_existing_artifacts = Vec::new();
    let mut artifact_proposals = 0usize;
    let mut finding_proposals = 0usize;
    let mut gap_proposals = 0usize;
    // Link each artifact to the findings it is evidence for — but only when the
    // findings will be reviewed alongside it (not --apply-artifacts). An applied
    // artifact must not target still-PENDING, non-canonical proposal findings, or
    // it would dangle; in that mode it lands unlinked and the link is established
    // when the findings are accepted.
    let mut artifact_targets: BTreeMap<String, Vec<String>> = BTreeMap::new();
    if !apply_artifacts {
        for claim in &packet.candidate_claims {
            let finding_id = claim_to_finding(&packet, claim, false)?.id;
            for artifact_id in &claim.evidence_artifact_ids {
                artifact_targets
                    .entry(artifact_id.clone())
                    .or_default()
                    .push(finding_id.clone());
            }
        }
    }

    for artifact in &packet.artifacts {
        let target_findings = artifact_targets
            .get(&artifact.id)
            .cloned()
            .unwrap_or_else(|| artifact_metadata_target_findings(artifact));
        let proposal = artifact_proposal(&packet, artifact, actor_id, &target_findings)?;
        if !seen_targets.insert(proposal.target.id.clone()) {
            skipped_existing_artifacts.push(proposal.target.id.clone());
            continue;
        }
        artifact_proposals += 1;
        let result = proposals::create_or_apply(frontier_path, proposal, apply_artifacts)?;
        proposal_ids.push(result.proposal_id);
        if let Some(event_id) = result.applied_event_id {
            applied_event_ids.push(event_id);
        }
    }

    for claim in &packet.candidate_claims {
        let proposal = claim_proposal(&packet, claim, actor_id)?;
        if !seen_targets.insert(proposal.target.id.clone()) {
            skipped_existing_proposals.push(proposal.target.id.clone());
            continue;
        }
        finding_proposals += 1;
        let result = proposals::create_or_apply(frontier_path, proposal, false)?;
        proposal_ids.push(result.proposal_id);
    }

    for need in &packet.open_needs {
        let proposal = need_proposal(&packet, need, actor_id)?;
        if !seen_targets.insert(proposal.target.id.clone()) {
            skipped_existing_proposals.push(proposal.target.id.clone());
            continue;
        }
        gap_proposals += 1;
        let result = proposals::create_or_apply(frontier_path, proposal, false)?;
        proposal_ids.push(result.proposal_id);
    }

    let frontier = vela_protocol::repo::load_from_path(frontier_path)?;
    skipped_existing_proposals.sort();
    skipped_existing_proposals.dedup();
    skipped_existing_artifacts.sort();
    skipped_existing_artifacts.dedup();
    let generated_proposals = artifact_proposals + finding_proposals + gap_proposals;
    let total_skipped = skipped_existing_proposals.len() + skipped_existing_artifacts.len();
    let trusted_state_effect = if applied_event_ids.is_empty() {
        "none"
    } else {
        "artifact_only"
    }
    .to_string();
    Ok(ArtifactToStateReport {
        ok: true,
        command: "artifact-to-state".to_string(),
        packet_id: packet.packet_id,
        frontier: frontier.project.name,
        artifact_proposals,
        finding_proposals,
        gap_proposals,
        applied_artifact_events: applied_event_ids.len(),
        pending_truth_proposals: finding_proposals + gap_proposals,
        proposal_ids,
        applied_event_ids,
        idempotency: ImportIdempotency {
            packet_hash,
            duplicate_packet: generated_proposals == 0 && total_skipped > 0,
            skipped_existing_proposals,
            skipped_existing_artifacts,
        },
        trusted_state_effect,
    })
}

fn packet_hash(packet: &ArtifactPacket) -> String {
    let bytes = vela_protocol::canonical::to_canonical_bytes(packet).unwrap_or_default();
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn artifact_proposal(
    packet: &ArtifactPacket,
    artifact: &PacketArtifact,
    actor_id: &str,
    target_findings: &[String],
) -> Result<StateProposal, String> {
    let vela_artifact = to_vela_artifact(packet, artifact, target_findings)?;
    let artifact_id = vela_artifact.id.clone();
    let mut proposal = proposals::new_proposal(
        "artifact.assert",
        StateTarget {
            r#type: "artifact".to_string(),
            id: artifact_id,
        },
        actor_id,
        actor_type(&packet.producer.kind),
        format!(
            "Import artifact {} from artifact packet {}",
            artifact.id, packet.packet_id
        ),
        json!({
            "artifact": vela_artifact,
            "artifact_packet": packet_reference(packet),
            "external_artifact_id": artifact.id,
            "parent_artifact_ids": artifact.parents,
        }),
        source_refs_for_artifact(packet, artifact),
        packet.caveats.clone(),
    );
    proposal.agent_run = Some(agent_run(packet));
    Ok(proposal)
}

fn claim_proposal(
    packet: &ArtifactPacket,
    claim: &PacketCandidateClaim,
    actor_id: &str,
) -> Result<StateProposal, String> {
    let finding = claim_to_finding(packet, claim, false)?;
    let finding_id = finding.id.clone();
    let mut caveats = packet.caveats.clone();
    caveats.extend(claim.caveats.clone());
    caveats.push("Agent output is source material until reviewer acceptance.".to_string());
    let mut source_refs = claim.source_refs.clone();
    source_refs.push(format!("artifact_packet:{}", packet.packet_id));
    source_refs.extend(
        claim
            .evidence_artifact_ids
            .iter()
            .map(|id| format!("packet_artifact:{id}")),
    );
    source_refs.sort();
    source_refs.dedup();

    let mut proposal = proposals::new_proposal(
        "finding.add",
        StateTarget {
            r#type: "finding".to_string(),
            id: finding_id,
        },
        actor_id,
        actor_type(&packet.producer.kind),
        format!(
            "Candidate claim {} imported from artifact packet {}",
            claim.id, packet.packet_id
        ),
        json!({
            "finding": finding,
            "artifact_packet": packet_reference(packet),
            "candidate_claim_id": claim.id,
            "evidence_artifact_ids": claim.evidence_artifact_ids,
        }),
        source_refs,
        caveats,
    );
    proposal.agent_run = Some(agent_run(packet));
    Ok(proposal)
}

fn need_proposal(
    packet: &ArtifactPacket,
    need: &PacketOpenNeed,
    actor_id: &str,
) -> Result<StateProposal, String> {
    let finding = need_to_gap_finding(packet, need)?;
    let finding_id = finding.id.clone();
    let mut caveats = packet.caveats.clone();
    caveats
        .push("Open need imported as a gap proposal; it is not an answered finding.".to_string());
    let mut proposal = proposals::new_proposal(
        "finding.add",
        StateTarget {
            r#type: "finding".to_string(),
            id: finding_id,
        },
        actor_id,
        actor_type(&packet.producer.kind),
        format!(
            "Open need {} imported from artifact packet {}",
            need.id, packet.packet_id
        ),
        json!({
            "finding": finding,
            "artifact_packet": packet_reference(packet),
            "open_need_id": need.id,
        }),
        vec![format!("artifact_packet:{}", packet.packet_id)],
        caveats,
    );
    proposal.agent_run = Some(agent_run(packet));
    Ok(proposal)
}

fn to_vela_artifact(
    packet: &ArtifactPacket,
    artifact: &PacketArtifact,
    target_findings: &[String],
) -> Result<Artifact, String> {
    let mut metadata = artifact.metadata.clone();
    metadata.insert("external_artifact_id".to_string(), json!(artifact.id));
    metadata.insert("artifact_packet_id".to_string(), json!(packet.packet_id));
    metadata.insert("producer_agent".to_string(), json!(packet.producer.id));
    metadata.insert("parent_artifact_ids".to_string(), json!(artifact.parents));
    metadata.insert("topic".to_string(), json!(packet.topic));

    let mut artifact = Artifact::new(
        artifact.kind.clone(),
        artifact.title.clone(),
        artifact.content_hash.clone(),
        None,
        Some("application/json".to_string()),
        "remote",
        Some(artifact.locator.clone()),
        Some(artifact.locator.clone()),
        Some("public source locator; no restricted bytes deposited".to_string()),
        target_findings.to_vec(),
        packet_provenance(
            packet,
            &artifact.title,
            Some(artifact.locator.clone()),
            source_type_for_artifact(&artifact.kind),
        ),
        metadata,
        AccessTier::Public,
    )?;
    artifact.created = packet.created_at.clone();
    Ok(artifact)
}

fn claim_to_finding(
    packet: &ArtifactPacket,
    claim: &PacketCandidateClaim,
    gap: bool,
) -> Result<FindingBundle, String> {
    let evidence_spans = claim
        .evidence_artifact_ids
        .iter()
        .map(|artifact_id| {
            json!({
                "artifact_packet_id": packet.packet_id,
                "artifact_id": artifact_id,
                "candidate_claim_id": claim.id,
            })
        })
        .collect::<Vec<_>>();
    let mut finding = FindingBundle::new(
        Assertion {
            text: claim.assertion.clone(),
            assertion_type: claim.assertion_type.clone(),
            entities: Vec::<Entity>::new(),
            relation: None,
            direction: None,
            causal_claim: None,
            causal_evidence_grade: None,
        },
        Evidence {
            evidence_type: "computational".to_string(),
            model_system: "agent artifact packet".to_string(),
            species: None,
            method: "ScienceClaw-shaped artifact packet import".to_string(),
            sample_size: None,
            effect_size: None,
            p_value: None,
            replicated: false,
            replication_count: None,
            evidence_spans,
        },
        Conditions {
            text: if claim.conditions.is_empty() {
                "Agent-imported candidate claim; scope requires review.".to_string()
            } else {
                claim.conditions.join("; ")
            },
            species_verified: Vec::new(),
            species_unverified: Vec::new(),
            in_vitro: false,
            in_vivo: false,
            human_data: false,
            clinical_trial: false,
            concentration_range: None,
            duration: None,
            age_group: None,
            cell_type: None,
        },
        Confidence {
            kind: ConfidenceKind::FrontierEpistemic,
            score: claim.confidence,
            basis: "agent-imported candidate claim; reviewer acceptance required".to_string(),
            method: ConfidenceMethod::ExpertJudgment,
            components: None,
            extraction_confidence: 0.7,
        },
        packet_provenance(
            packet,
            &claim.id,
            claim.source_refs.first().cloned(),
            "model_output",
        ),
        Flags {
            gap,
            ..Default::default()
        },
    );
    finding.created = packet.created_at.clone();
    Ok(finding)
}

fn need_to_gap_finding(
    packet: &ArtifactPacket,
    need: &PacketOpenNeed,
) -> Result<FindingBundle, String> {
    let claim = PacketCandidateClaim {
        id: need.id.clone(),
        assertion: need.question.clone(),
        assertion_type: "open_question".to_string(),
        evidence_artifact_ids: packet
            .artifacts
            .first()
            .map(|a| vec![a.id.clone()])
            .unwrap_or_default(),
        source_refs: vec![format!("artifact_packet:{}", packet.packet_id)],
        conditions: vec![need.rationale.clone()],
        confidence: 0.4,
        caveats: vec!["Open need, not an accepted result.".to_string()],
    };
    claim_to_finding(packet, &claim, true)
}

fn packet_provenance(
    packet: &ArtifactPacket,
    title: &str,
    url: Option<String>,
    source_type: &str,
) -> Provenance {
    Provenance {
        source_type: source_type.to_string(),
        doi: None,
        pmid: None,
        pmc: None,
        openalex_id: None,
        url,
        title: format!("{} · {}", packet.packet_id, title),
        authors: vec![Author {
            name: packet.producer.name.clone(),
            orcid: None,
        }],
        year: None,
        journal: None,
        license: None,
        publisher: Some("artifact packet".to_string()),
        funders: Vec::new(),
        extraction: Extraction {
            method: "artifact_to_state_import".to_string(),
            model: Some(packet.producer.id.clone()),
            model_version: None,
            extracted_at: packet.created_at.clone(),
            extractor_version: project::VELA_COMPILER_VERSION.to_string(),
        },
        review: Some(Review {
            reviewed: false,
            reviewer: None,
            reviewed_at: None,
            corrections: Vec::new(),
        }),
        citation_count: None,
    }
}

fn packet_reference(packet: &ArtifactPacket) -> Value {
    json!({
        "schema": packet.schema,
        "packet_id": packet.packet_id,
        "producer": packet.producer,
        "topic": packet.topic,
        "created_at": packet.created_at,
    })
}

fn source_refs_for_artifact(packet: &ArtifactPacket, artifact: &PacketArtifact) -> Vec<String> {
    let mut refs = vec![
        format!("artifact_packet:{}", packet.packet_id),
        artifact.locator.clone(),
    ];
    refs.extend(
        artifact
            .parents
            .iter()
            .map(|id| format!("parent_artifact:{id}")),
    );
    refs.sort();
    refs.dedup();
    refs
}

fn artifact_metadata_target_findings(artifact: &PacketArtifact) -> Vec<String> {
    artifact
        .metadata
        .get("target_findings")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .filter(|id| id.starts_with("vf_"))
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn agent_run(packet: &ArtifactPacket) -> AgentRun {
    let mut context = BTreeMap::new();
    context.insert("artifact_packet_id".to_string(), packet.packet_id.clone());
    context.insert("topic".to_string(), packet.topic.clone());
    context.insert("producer_name".to_string(), packet.producer.name.clone());
    AgentRun {
        agent: packet.producer.id.clone(),
        model: "external-artifact-runtime".to_string(),
        run_id: packet.packet_id.clone(),
        started_at: packet.created_at.clone(),
        finished_at: None,
        context,
        tool_calls: Vec::new(),
        permissions: None,
    }
}

fn source_type_for_artifact(kind: &str) -> &'static str {
    match kind {
        "clinical_trial_record" => "clinical_trial",
        "registry_record" => "database_record",
        "model_output" | "table" | "figure" | "code" | "notebook" => "model_output",
        "dataset" => "data_release",
        "protocol" | "supplement" | "source_file" | "lab_file" | "other" => "database_record",
        _ => "database_record",
    }
}

fn actor_type(kind: &str) -> &'static str {
    match kind {
        "human" | "reviewer" => "human",
        _ => "agent",
    }
}

fn normalize_packet_hash(value: &str) -> Result<String, String> {
    let trimmed = value.trim();
    let hex = trimmed.strip_prefix("sha256:").unwrap_or(trimmed);
    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!(
            "content_hash must be sha256:<64hex> or 64 hex chars, got {trimmed:?}"
        ));
    }
    Ok(format!("sha256:{}", hex.to_ascii_lowercase()))
}
