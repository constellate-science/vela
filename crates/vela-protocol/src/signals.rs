//! Derived frontier signals.
//!
//! Signals are read-only projections over frontier state. They are not a second
//! source of truth and are intentionally safe to recompute from the frontier,
//! diagnostics, proof traces, or benchmark output.

#![allow(clippy::module_name_repetitions)]

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::project::{self, Project};
use crate::proposals;
use crate::sources;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignalTarget {
    pub r#type: String,
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignalItem {
    pub id: String,
    pub kind: String,
    pub severity: String,
    pub target: SignalTarget,
    pub reason: String,
    pub recommended_action: String,
    pub blocks: Vec<String>,
    pub caveats: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReviewQueueItem {
    pub id: String,
    pub priority: String,
    pub priority_score: u32,
    pub target: SignalTarget,
    pub signal_ids: Vec<String>,
    pub reasons: Vec<String>,
    pub recommended_action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofReadiness {
    pub status: String,
    pub blockers: usize,
    pub warnings: usize,
    pub caveats: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalReport {
    pub schema: String,
    pub frontier: String,
    pub signals: Vec<SignalItem>,
    pub review_queue: Vec<ReviewQueueItem>,
    pub proof_readiness: ProofReadiness,
}

pub fn analyze(frontier: &Project, diagnostics: &[Value]) -> SignalReport {
    let mut signals = Vec::new();

    for diagnostic in diagnostics {
        let severity = diagnostic
            .get("severity")
            .and_then(Value::as_str)
            .unwrap_or("info");
        let rule_id = diagnostic
            .get("rule_id")
            .and_then(Value::as_str)
            .unwrap_or("check_error");
        if severity == "error"
            || matches!(
                rule_id,
                "missing_source_record"
                    | "missing_evidence_atom"
                    | "missing_evidence_locator"
                    | "condition_record_missing"
            )
        {
            let id = format!("sig_diagnostic_{}", signals.len() + 1);
            signals.push(SignalItem {
                id,
                kind: match rule_id {
                    "event_replay" => "event_replay_conflict",
                    "missing_source_record" => "missing_source_record",
                    "missing_evidence_atom" => "missing_evidence_atom",
                    "missing_evidence_locator" => "missing_evidence_locator",
                    "condition_record_missing" => "condition_record_missing",
                    "reviewer_identity_missing" => "reviewer_identity_missing",
                    _ => "check_error",
                }
                .to_string(),
                severity: severity.to_string(),
                target: SignalTarget {
                    r#type: diagnostic
                        .get("finding_id")
                        .and_then(Value::as_str)
                        .map_or("frontier", |_| "finding")
                        .to_string(),
                    id: diagnostic
                        .get("finding_id")
                        .and_then(Value::as_str)
                        .unwrap_or(&frontier.project.name)
                        .to_string(),
                },
                reason: diagnostic
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("Frontier validation error.")
                    .to_string(),
                recommended_action: diagnostic
                    .get("suggestion")
                    .and_then(Value::as_str)
                    .unwrap_or("Inspect and correct the referenced frontier field.")
                    .to_string(),
                blocks: if rule_id == "missing_evidence_locator" {
                    vec!["proof_ready".to_string()]
                } else {
                    vec!["strict_check".to_string(), "proof_ready".to_string()]
                },
                caveats: vec![],
            });
        }
    }

    let projection = sources::derive_projection(frontier);
    let source_by_id = projection
        .sources
        .iter()
        .map(|source| (source.id.as_str(), source))
        .collect::<BTreeMap<_, _>>();
    let reviewed_finding_ids = frontier
        .events
        .iter()
        .filter(|event| {
            event.target.r#type == "finding"
                && event.actor.id.starts_with("reviewer:")
                && matches!(
                    event.kind.as_str(),
                    "finding.asserted" | "finding.reviewed" | "finding.caveated"
                )
        })
        .map(|event| event.target.id.as_str())
        .collect::<BTreeSet<_>>();

    for source in &projection.sources {
        if source.content_hash.is_none()
            && matches!(
                source.source_type.as_str(),
                "pdf"
                    | "jats"
                    | "csv"
                    | "text"
                    | "note"
                    | "agent_trace"
                    | "benchmark_output"
                    | "notebook_entry"
                    | "experiment_log"
                    | "synthetic_report"
            )
        {
            signals.push(SignalItem {
                id: signal_id("source_hash_missing", &source.id),
                kind: "source_hash_missing".to_string(),
                severity: "info".to_string(),
                target: SignalTarget {
                    r#type: "source".to_string(),
                    id: source.id.clone(),
                },
                reason: "Source record has no content hash for a local or generated artifact."
                    .to_string(),
                recommended_action:
                    "Recompile from the local corpus or add a source content hash before relying on this source."
                        .to_string(),
                blocks: vec![],
                caveats: vec!["Source identity and scientific confidence are separate.".to_string()],
            });
        }

        if source.source_type == "agent_trace" {
            signals.push(SignalItem {
                id: signal_id("agent_trace_unverified", &source.id),
                kind: "agent_trace_unverified".to_string(),
                severity: "warning".to_string(),
                target: SignalTarget {
                    r#type: "source".to_string(),
                    id: source.id.clone(),
                },
                reason: "Agent trace source requires review before it can support active frontier state."
                    .to_string(),
                recommended_action:
                    "Verify the trace against primary evidence and add review before proof use."
                        .to_string(),
                blocks: vec!["strict_check".to_string(), "proof_ready".to_string()],
                caveats: vec!["Agent traces are source artifacts, not scientific truth.".to_string()],
            });
        }

        if source.source_type == "synthetic_report"
            && !source
                .finding_ids
                .iter()
                .any(|finding_id| reviewed_finding_ids.contains(finding_id.as_str()))
        {
            signals.push(SignalItem {
                id: signal_id("synthetic_source_requires_review", &source.id),
                kind: "synthetic_source_requires_review".to_string(),
                severity: "warning".to_string(),
                target: SignalTarget {
                    r#type: "source".to_string(),
                    id: source.id.clone(),
                },
                reason: "Synthetic report source requires human review and primary-source grounding."
                    .to_string(),
                recommended_action:
                    "Use synthetic reports as review leads unless evidence atoms trace back to primary sources."
                        .to_string(),
                blocks: vec!["strict_check".to_string(), "proof_ready".to_string()],
                caveats: vec!["Synthetic sources should not silently become evidence.".to_string()],
            });
        }
    }

    for atom in &projection.evidence_atoms {
        if atom.locator.is_none() {
            signals.push(SignalItem {
                id: signal_id("missing_evidence_locator", &atom.id),
                kind: "missing_evidence_locator".to_string(),
                severity: "warning".to_string(),
                target: SignalTarget {
                    r#type: "finding".to_string(),
                    id: atom.finding_id.clone(),
                },
                reason:
                    "Evidence atom lacks a span, table row, page, section, run, or metric locator."
                        .to_string(),
                recommended_action:
                    "Verify the exact source location or keep this as a weak review lead."
                        .to_string(),
                blocks: vec!["proof_ready".to_string()],
                caveats: vec![
                    "A source citation is weaker than a located evidence atom.".to_string(),
                ],
            });
        }

        if !atom.human_verified
            && source_by_id
                .get(atom.source_id.as_str())
                .is_some_and(|source| sources::is_synthetic_source(source))
            && !reviewed_finding_ids.contains(atom.finding_id.as_str())
        {
            signals.push(SignalItem {
                id: signal_id("synthetic_source_requires_review", &atom.id),
                kind: "synthetic_source_requires_review".to_string(),
                severity: "warning".to_string(),
                target: SignalTarget {
                    r#type: "finding".to_string(),
                    id: atom.finding_id.clone(),
                },
                reason: "Evidence atom is linked to an unverified synthetic or agent source."
                    .to_string(),
                recommended_action:
                    "Attach primary evidence or review the atom before proof export.".to_string(),
                blocks: vec!["strict_check".to_string(), "proof_ready".to_string()],
                caveats: vec![
                    "Generated traces can guide review but are not trusted evidence.".to_string(),
                ],
            });
        }
    }

    for record in &projection.condition_records {
        if record.text.trim().is_empty() {
            signals.push(SignalItem {
                id: signal_id("missing_conditions", &record.id),
                kind: "missing_conditions".to_string(),
                severity: "warning".to_string(),
                target: SignalTarget {
                    r#type: "finding".to_string(),
                    id: record.finding_id.clone(),
                },
                reason: "Finding has no declared condition boundary.".to_string(),
                recommended_action:
                    "Add the species, model system, assay, comparator, endpoint, or scope that bounds the finding."
                        .to_string(),
                blocks: vec!["strict_check".to_string(), "proof_ready".to_string()],
                caveats: vec!["A finding without conditions is incomplete frontier state.".to_string()],
            });
        }

        if record.comparator_status == "missing_or_unclear"
            && (record.exposure_or_efficacy == "efficacy" || record.exposure_or_efficacy == "both")
        {
            signals.push(SignalItem {
                id: signal_id("missing_comparator", &record.id),
                kind: "missing_comparator".to_string(),
                severity: "info".to_string(),
                target: SignalTarget {
                    r#type: "finding".to_string(),
                    id: record.finding_id.clone(),
                },
                reason: "Condition record does not declare a comparator or baseline.".to_string(),
                recommended_action:
                    "Review whether the evidence supports the asserted direction without a declared comparator."
                        .to_string(),
                blocks: vec![],
                caveats: vec![
                    "Comparator absence is a review signal, not automatic disproof.".to_string(),
                ],
            });
        }

        if record.exposure_or_efficacy == "both" {
            signals.push(SignalItem {
                id: signal_id("exposure_efficacy_overgeneralization", &record.id),
                kind: "condition_loss_risk".to_string(),
                severity: "info".to_string(),
                target: SignalTarget {
                    r#type: "finding".to_string(),
                    id: record.finding_id.clone(),
                },
                reason: "Exposure and efficacy language appear in the same condition boundary."
                    .to_string(),
                recommended_action:
                    "Keep exposure, functional delivery, and therapeutic efficacy separate unless the source directly supports the broader claim."
                        .to_string(),
                blocks: vec![],
                caveats: vec![
                    "Vela flags possible overgeneralization; reviewers decide the final scope."
                        .to_string(),
                ],
            });
        }

        if record.translation_scope == "animal_model"
            && record
                .caveats
                .iter()
                .any(|caveat| caveat.contains("human translation"))
        {
            signals.push(SignalItem {
                id: signal_id("mouse_human_translation_risk", &record.id),
                kind: "condition_loss_risk".to_string(),
                severity: "info".to_string(),
                target: SignalTarget {
                    r#type: "finding".to_string(),
                    id: record.finding_id.clone(),
                },
                reason: "Animal-model evidence is adjacent to human translation language."
                    .to_string(),
                recommended_action:
                    "Preserve the animal-model scope unless human data are explicitly attached."
                        .to_string(),
                blocks: vec![],
                caveats: vec![
                    "Mouse or animal evidence should not silently become a human claim."
                        .to_string(),
                ],
            });
        }
    }

    // Build a set of finding IDs that have at least one evidence atom
    // attached. Used by the source-grounding doctrine invariant below.
    let evidence_grounded: BTreeSet<&str> = projection
        .evidence_atoms
        .iter()
        .map(|atom| atom.finding_id.as_str())
        .collect();

    for finding in &frontier.findings {
        if finding.provenance.doi.is_none()
            && finding.provenance.pmid.is_none()
            && finding.provenance.title.trim().is_empty()
        {
            signals.push(SignalItem {
                id: signal_id("weak_provenance", &finding.id),
                kind: "weak_provenance".to_string(),
                severity: "warning".to_string(),
                target: SignalTarget {
                    r#type: "finding".to_string(),
                    id: finding.id.clone(),
                },
                reason: "Finding lacks DOI, PMID, and source title fallback.".to_string(),
                recommended_action:
                    "Add source metadata or mark the finding as unresolved before proof export."
                        .to_string(),
                blocks: vec!["strict_check".to_string(), "proof_ready".to_string()],
                caveats: vec!["Provenance is separate from confidence.".to_string()],
            });
        }

        // Doctrine line 3: a finding without conditions is incomplete.
        // Strict check blocker when both conditions.text is empty AND no
        // scope flag is set, AND the finding is not theoretical (theoretical
        // findings can be scope-free by nature).
        let scope_declared = finding.conditions.in_vivo
            || finding.conditions.in_vitro
            || finding.conditions.human_data
            || finding.conditions.clinical_trial;
        if finding.conditions.text.trim().is_empty()
            && !scope_declared
            && finding.assertion.assertion_type != "theoretical"
            && !finding.flags.retracted
        {
            signals.push(SignalItem {
                id: signal_id("conditions_undeclared", &finding.id),
                kind: "conditions_undeclared".to_string(),
                severity: "error".to_string(),
                target: SignalTarget {
                    r#type: "finding".to_string(),
                    id: finding.id.clone(),
                },
                reason:
                    "Finding has no condition text and no scope flag (in_vivo/in_vitro/human_data/clinical_trial)."
                        .to_string(),
                recommended_action:
                    "Declare at least one scope flag and condition text, or mark the finding theoretical."
                        .to_string(),
                blocks: vec!["strict_check".to_string(), "proof_ready".to_string()],
                caveats: vec![
                    "A finding without conditions is doctrinally incomplete state."
                        .to_string(),
                ],
            });
        }

        // Doctrine line 4: a result without provenance is not evidence.
        // Strict-check blocker when an active finding has no evidence atom.
        if !finding.flags.retracted && !evidence_grounded.contains(finding.id.as_str()) {
            signals.push(SignalItem {
                id: signal_id("evidence_atom_missing", &finding.id),
                kind: "evidence_atom_missing".to_string(),
                severity: "error".to_string(),
                target: SignalTarget {
                    r#type: "finding".to_string(),
                    id: finding.id.clone(),
                },
                reason:
                    "Active finding has no materialized evidence atom in the source-evidence map."
                        .to_string(),
                recommended_action:
                    "Run `vela normalize` to materialize evidence atoms, or attach explicit evidence spans."
                        .to_string(),
                blocks: vec!["strict_check".to_string(), "proof_ready".to_string()],
                caveats: vec![
                    "A citation alone is not evidence in the v0.3 substrate.".to_string(),
                ],
            });
        }

        // Doctrine line 5: an agent trace is not truth.
        // Strict-check blocker when source_type implies the claim came from
        // a non-peer-reviewed source (model_output, expert_assertion,
        // agent_trace) AND the finding has not been reviewed.
        let agent_typed = matches!(
            finding.provenance.source_type.as_str(),
            "model_output" | "expert_assertion" | "agent_trace"
        );
        let has_review = finding
            .provenance
            .review
            .as_ref()
            .is_some_and(|r| r.reviewed)
            || finding.flags.review_state.is_some()
            || reviewed_finding_ids.contains(finding.id.as_str());
        if agent_typed && !has_review && !finding.flags.gap && !finding.flags.retracted {
            signals.push(SignalItem {
                id: signal_id("agent_typed_unreviewed", &finding.id),
                kind: "agent_typed_unreviewed".to_string(),
                severity: "warning".to_string(),
                target: SignalTarget {
                    r#type: "finding".to_string(),
                    id: finding.id.clone(),
                },
                reason: format!(
                    "Source type '{}' requires explicit review before strict acceptance.",
                    finding.provenance.source_type
                ),
                recommended_action:
                    "Run `vela review --apply` against this finding or flag it as gap before strict use."
                        .to_string(),
                blocks: vec!["strict_check".to_string(), "proof_ready".to_string()],
                caveats: vec![
                    "Agent traces, expert assertions, and model outputs are sources, not truth."
                        .to_string(),
                ],
            });
        }

        if finding.evidence.evidence_spans.is_empty() {
            signals.push(SignalItem {
                id: signal_id("missing_evidence_span", &finding.id),
                kind: "missing_evidence_span".to_string(),
                severity: "warning".to_string(),
                target: SignalTarget {
                    r#type: "finding".to_string(),
                    id: finding.id.clone(),
                },
                reason: "Finding has no verified evidence span attached.".to_string(),
                recommended_action:
                    "Verify the assertion against source text and add evidence spans where possible."
                        .to_string(),
                blocks: vec!["proof_ready".to_string()],
                caveats: vec!["Missing spans do not imply the assertion is false.".to_string()],
            });
        }

        if finding.conditions.text.trim().is_empty() {
            signals.push(SignalItem {
                id: signal_id("missing_conditions", &finding.id),
                kind: "missing_conditions".to_string(),
                severity: "warning".to_string(),
                target: SignalTarget {
                    r#type: "finding".to_string(),
                    id: finding.id.clone(),
                },
                reason: "Finding has no explicit condition boundary.".to_string(),
                recommended_action:
                    "Add species, model system, assay, regimen, population, or scope conditions."
                        .to_string(),
                blocks: vec!["proof_ready".to_string()],
                caveats: vec![
                    "Condition loss is a common source of overgeneralized scientific claims."
                        .to_string(),
                ],
            });
        }

        if finding.conditions.text.trim().is_empty()
            && contains_condition_sensitive_claim(&finding.assertion.text)
        {
            signals.push(SignalItem {
                id: signal_id("condition_loss_risk", &finding.id),
                kind: "condition_loss_risk".to_string(),
                severity: "warning".to_string(),
                target: SignalTarget {
                    r#type: "finding".to_string(),
                    id: finding.id.clone(),
                },
                reason: "Finding uses condition-sensitive language without explicit condition boundaries."
                    .to_string(),
                recommended_action:
                    "Separate exposure, efficacy, species, assay, payload, endpoint, and translation scope."
                        .to_string(),
                blocks: vec!["strict_check".to_string(), "proof_ready".to_string()],
                caveats: vec![
                    "Vela should flag overgeneralization rather than smooth it into a summary."
                        .to_string(),
                ],
            });
        }

        if finding
            .assertion
            .entities
            .iter()
            .any(|entity| entity.needs_review)
        {
            signals.push(SignalItem {
                id: signal_id("needs_human_review", &finding.id),
                kind: "needs_human_review".to_string(),
                severity: "warning".to_string(),
                target: SignalTarget {
                    r#type: "finding".to_string(),
                    id: finding.id.clone(),
                },
                reason: "Finding contains unresolved or low-confidence entity resolution."
                    .to_string(),
                recommended_action:
                    "Review entity names, types, identifiers, and source grounding before proof use."
                        .to_string(),
                blocks: vec!["strict_check".to_string(), "proof_ready".to_string()],
                caveats: vec!["Entity review status is separate from assertion confidence.".to_string()],
            });
        }

        if finding.provenance.extraction.method.contains("fallback")
            || finding.provenance.extraction.method.contains("rough")
            || finding.provenance.extraction.method.contains("abstract")
        {
            signals.push(SignalItem {
                id: signal_id("rough_source_extraction", &finding.id),
                kind: "rough_source_extraction".to_string(),
                severity: "warning".to_string(),
                target: SignalTarget {
                    r#type: "finding".to_string(),
                    id: finding.id.clone(),
                },
                reason: format!(
                    "Finding was produced by extraction mode '{}'.",
                    finding.provenance.extraction.method
                ),
                recommended_action:
                    "Inspect the source text and mark caveats or review status before treating this as durable state."
                        .to_string(),
                blocks: vec!["proof_ready".to_string()],
                caveats: vec![
                    "Rough extraction can be useful as a review lead, not as a scientific conclusion."
                        .to_string(),
                ],
            });
        }

        if matches!(
            finding.provenance.source_type.as_str(),
            "model_output" | "summary" | "synthesis"
        ) && !reviewed_finding_ids.contains(finding.id.as_str())
        {
            signals.push(SignalItem {
                id: signal_id("synthesis_used_as_source", &finding.id),
                kind: "synthesis_used_as_source".to_string(),
                severity: "warning".to_string(),
                target: SignalTarget {
                    r#type: "finding".to_string(),
                    id: finding.id.clone(),
                },
                reason: "Finding provenance indicates synthesized text or model output as source."
                    .to_string(),
                recommended_action:
                    "Trace this finding back to primary source evidence or mark it as a review lead."
                        .to_string(),
                blocks: vec!["strict_check".to_string(), "proof_ready".to_string()],
                caveats: vec![
                    "Derived synthesis should not silently become primary evidence.".to_string(),
                ],
            });
        }

        if finding.flags.contested && finding.confidence.score >= 0.8 {
            signals.push(SignalItem {
                id: signal_id("contested_high_confidence", &finding.id),
                kind: "contested_high_confidence".to_string(),
                severity: "warning".to_string(),
                target: SignalTarget {
                    r#type: "finding".to_string(),
                    id: finding.id.clone(),
                },
                reason: "Finding is contested while carrying high confidence.".to_string(),
                recommended_action:
                    "Review contradiction links, provenance, and confidence components."
                        .to_string(),
                blocks: vec!["proof_ready".to_string()],
                caveats: vec![
                    "Candidate tensions are review surfaces, not definitive contradictions."
                        .to_string(),
                ],
            });
        }
    }

    // Phase N (v0.4): provenance authority. `Project.sources` is
    // canonical; `FindingBundle.provenance` is a denormalized cache.
    // Drift between the two is a strict-mode failure — the source
    // record wins, and the finding must be rewritten via
    // `vela normalize --resync-provenance`.
    let mut by_doi: BTreeMap<String, &crate::sources::SourceRecord> = BTreeMap::new();
    let mut by_pmid: BTreeMap<String, &crate::sources::SourceRecord> = BTreeMap::new();
    let mut duplicate_dois: BTreeSet<String> = BTreeSet::new();
    let mut duplicate_pmids: BTreeSet<String> = BTreeSet::new();
    for source in &frontier.sources {
        if let Some(doi) = source.doi.as_deref() {
            let key = doi.to_lowercase();
            if by_doi.insert(key.clone(), source).is_some() {
                duplicate_dois.insert(key);
            }
        }
        if let Some(pmid) = source.pmid.as_deref() {
            let key = pmid.to_string();
            if by_pmid.insert(key.clone(), source).is_some() {
                duplicate_pmids.insert(key);
            }
        }
    }
    for key in &duplicate_dois {
        by_doi.remove(key);
    }
    for key in &duplicate_pmids {
        by_pmid.remove(key);
    }
    for finding in &frontier.findings {
        if finding.flags.retracted {
            continue;
        }
        let source = finding
            .provenance
            .doi
            .as_deref()
            .map(str::to_lowercase)
            .and_then(|k| by_doi.get(&k).copied())
            .or_else(|| {
                finding
                    .provenance
                    .pmid
                    .as_deref()
                    .and_then(|k| by_pmid.get(k).copied())
            });
        let Some(source) = source else { continue };

        let mut diffs: Vec<String> = Vec::new();
        if !source.title.is_empty() && source.title != finding.provenance.title {
            diffs.push(format!(
                "title differs (source='{}', cached='{}')",
                truncate(&source.title, 60),
                truncate(&finding.provenance.title, 60)
            ));
        }
        if source.year.is_some() && source.year != finding.provenance.year {
            diffs.push(format!(
                "year differs (source={:?}, cached={:?})",
                source.year, finding.provenance.year
            ));
        }
        if !diffs.is_empty() {
            signals.push(SignalItem {
                id: signal_id("provenance_drift", &finding.id),
                kind: "provenance_drift".to_string(),
                severity: "error".to_string(),
                target: SignalTarget {
                    r#type: "finding".to_string(),
                    id: finding.id.clone(),
                },
                reason: format!(
                    "Cached finding.provenance disagrees with canonical source: {}",
                    diffs.join("; ")
                ),
                recommended_action:
                    "Run `vela normalize --resync-provenance --write` to regenerate finding.provenance from the canonical SourceRecord."
                        .to_string(),
                blocks: vec!["strict_check".to_string(), "proof_ready".to_string()],
                caveats: vec![
                    "sources is the authority; provenance is the cache."
                        .to_string(),
                ],
            });
        }
    }

    // Phase M (v0.4): registered actors must sign their canonical
    // events. Once an actor.id appears in `frontier.actors`, every
    // canonical event referencing that actor.id MUST carry a signature
    // that verifies against the registered public key. Unregistered
    // actor.ids fall back to the legacy placeholder-rejection rule.
    if !frontier.actors.is_empty() {
        let registry: BTreeMap<&str, &crate::sign::ActorRecord> = frontier
            .actors
            .iter()
            .map(|actor| (actor.id.as_str(), actor))
            .collect();
        for event in &frontier.events {
            if event.actor.r#type != "human" {
                continue;
            }
            let Some(actor_record) = registry.get(event.actor.id.as_str()) else {
                continue;
            };
            // v0.127: A7 mitigation. If the actor's key is revoked at
            // or before this event's timestamp, the signature is
            // rejected regardless of whether it would otherwise
            // verify. Historical signatures (events with timestamp
            // strictly before revoked_at) remain valid: the
            // substrate does not retroactively invalidate canonical
            // history.
            if actor_record.is_revoked_at(event.timestamp.as_str()) {
                signals.push(SignalItem {
                    id: signal_id("post_revocation_signature", &event.id),
                    kind: "post_revocation_signature".to_string(),
                    severity: "error".to_string(),
                    target: SignalTarget {
                        r#type: "event".to_string(),
                        id: event.id.clone(),
                    },
                    reason: format!(
                        "Event {} carries a signature from actor '{}' whose key was revoked at {} (event timestamp {}).",
                        event.id,
                        event.actor.id,
                        actor_record.revoked_at.as_deref().unwrap_or("?"),
                        event.timestamp
                    ),
                    recommended_action:
                        "Reject this event. The signing key was revoked at-or-before the event timestamp; verify the rotation chain and re-sign under the current actor key."
                            .to_string(),
                    blocks: vec!["strict_check".to_string()],
                    caveats: Vec::new(),
                });
                continue;
            }
            let pubkey = actor_record.public_key.as_str();
            let invalid = match event.signature.as_deref() {
                None => Some("missing".to_string()),
                Some(_) => match crate::sign::verify_event_signature(event, pubkey) {
                    Ok(true) => None,
                    Ok(false) => Some("does not verify".to_string()),
                    Err(err) => Some(err),
                },
            };
            if let Some(reason) = invalid {
                signals.push(SignalItem {
                    id: signal_id("unsigned_registered_actor", &event.id),
                    kind: "unsigned_registered_actor".to_string(),
                    severity: "error".to_string(),
                    target: SignalTarget {
                        r#type: "event".to_string(),
                        id: event.id.clone(),
                    },
                    reason: format!(
                        "Event {} from registered actor '{}' has invalid signature: {reason}.",
                        event.id, event.actor.id
                    ),
                    recommended_action:
                        "Sign the event with the registered Ed25519 key before strict acceptance."
                            .to_string(),
                    blocks: vec!["strict_check".to_string(), "proof_ready".to_string()],
                    caveats: vec![
                        "Registered actors are bound to their public key; unsigned writes break that binding."
                            .to_string(),
                    ],
                });
            }
        }
    }

    let proposal_summary = proposals::summary(frontier);
    for duplicate in &proposal_summary.duplicate_ids {
        signals.push(SignalItem {
            id: signal_id("proposal_conflict", duplicate),
            kind: "proposal_conflict".to_string(),
            severity: "error".to_string(),
            target: SignalTarget {
                r#type: "frontier".to_string(),
                id: frontier.project.name.clone(),
            },
            reason: format!("Duplicate proposal id detected: {duplicate}."),
            recommended_action: "Remove or rename the duplicate proposal before applying writes."
                .to_string(),
            blocks: vec!["strict_check".to_string(), "proof_ready".to_string()],
            caveats: vec![],
        });
    }
    for target in &proposal_summary.invalid_targets {
        signals.push(SignalItem {
            id: signal_id("proposal_conflict", target),
            kind: "proposal_conflict".to_string(),
            severity: "error".to_string(),
            target: SignalTarget {
                r#type: "finding".to_string(),
                id: target.clone(),
            },
            reason: format!("Proposal target does not exist in frontier state: {target}."),
            recommended_action:
                "Fix the proposal target or remove the orphan proposal before applying writes."
                    .to_string(),
            blocks: vec!["strict_check".to_string(), "proof_ready".to_string()],
            caveats: vec![],
        });
    }
    for proposal in frontier
        .proposals
        .iter()
        .filter(|proposal| proposal.status == "pending_review")
    {
        signals.push(SignalItem {
            id: signal_id("pending_proposal_review", &proposal.id),
            kind: "pending_proposal_review".to_string(),
            severity: "warning".to_string(),
            target: SignalTarget {
                r#type: proposal.target.r#type.clone(),
                id: proposal.target.id.clone(),
            },
            reason: format!(
                "Pending {} proposal requires review before frontier truth changes.",
                proposal.kind
            ),
            recommended_action:
                "Review the proposal and accept or reject it before strict proof use.".to_string(),
            blocks: vec!["strict_check".to_string(), "proof_ready".to_string()],
            caveats: vec!["Pending proposals are not active frontier state.".to_string()],
        });
    }
    for proposal in frontier
        .proposals
        .iter()
        .filter(|proposal| proposal.status == "applied")
    {
        signals.push(SignalItem {
            id: signal_id("proposal_applied", &proposal.id),
            kind: "proposal_applied".to_string(),
            severity: "info".to_string(),
            target: SignalTarget {
                r#type: proposal.target.r#type.clone(),
                id: proposal.target.id.clone(),
            },
            reason: format!("Applied proposal {} changed frontier state.", proposal.id),
            recommended_action:
                "Re-export proof artifacts if this proposal materially changes what reviewers should inspect."
                    .to_string(),
            blocks: vec![],
            caveats: vec![],
        });
    }
    for proposal in frontier.proposals.iter().filter(|proposal| {
        matches!(proposal.status.as_str(), "accepted" | "applied")
            && proposal
                .reviewed_by
                .as_deref()
                .is_none_or(proposals::is_placeholder_reviewer)
    }) {
        signals.push(SignalItem {
            id: signal_id("reviewer_identity_missing", &proposal.id),
            kind: "reviewer_identity_missing".to_string(),
            severity: "error".to_string(),
            target: SignalTarget {
                r#type: proposal.target.r#type.clone(),
                id: proposal.target.id.clone(),
            },
            reason: format!(
                "Accepted or applied proposal {} lacks a stable named reviewer identity.",
                proposal.id
            ),
            recommended_action:
                "Re-accept the proposal with a stable named reviewer id before strict proof use."
                    .to_string(),
            blocks: vec!["strict_check".to_string(), "proof_ready".to_string()],
            caveats: vec![
                "Placeholder reviewer ids do not satisfy the v0 trust boundary.".to_string(),
            ],
        });
    }
    if frontier.proof_state.latest_packet.status == "stale" {
        signals.push(SignalItem {
            id: signal_id("stale_proof_packet", &frontier.project.name),
            kind: "stale_proof_packet".to_string(),
            severity: "warning".to_string(),
            target: SignalTarget {
                r#type: "frontier".to_string(),
                id: frontier.project.name.clone(),
            },
            reason: frontier
                .proof_state
                .stale_reason
                .clone()
                .unwrap_or_else(|| "Proof packet is stale relative to current frontier state.".to_string()),
            recommended_action:
                "Run `vela proof` again to export a packet that matches the current frontier snapshot."
                    .to_string(),
            blocks: vec!["strict_check".to_string(), "proof_ready".to_string()],
            caveats: vec!["Packet validation can still pass for stale but internally consistent packets.".to_string()],
        });
    }

    let review_queue = build_review_queue(frontier, &signals);
    let proof_readiness = build_proof_readiness(&signals);

    SignalReport {
        schema: "vela.signals.v0".to_string(),
        frontier: frontier.project.name.clone(),
        signals,
        review_queue,
        proof_readiness,
    }
}

pub fn quality_table(frontier: &Project, report: &SignalReport) -> Value {
    let mut by_kind = BTreeMap::<String, usize>::new();
    let mut by_severity = BTreeMap::<String, usize>::new();
    let proposal_summary = proposals::summary(frontier);
    for signal in &report.signals {
        *by_kind.entry(signal.kind.clone()).or_default() += 1;
        *by_severity.entry(signal.severity.clone()).or_default() += 1;
    }

    json!({
        "schema": "vela.quality-table.v0",
        "frontier": frontier.project.name,
        "stats": frontier.stats,
        "event_log": {
            "events": frontier.events.len(),
            "review_events_projection": frontier.review_events.len(),
            "confidence_updates_projection": frontier.confidence_updates.len(),
        },
        "signals": {
            "total": report.signals.len(),
            "by_kind": by_kind,
            "by_severity": by_severity,
        },
        "review_queue": {
            "items": report.review_queue.len(),
            "high_priority": report.review_queue.iter().filter(|item| item.priority == "high").count(),
        },
        "proposals": proposal_summary,
        "proof_state": frontier.proof_state,
        "proof_readiness": report.proof_readiness,
        "caveats": [
            "Signals are derived from frontier state and should be recomputed after edits.",
            "Candidate gaps, bridges, and tensions require human review.",
            "A clean quality table is not proof of scientific truth."
        ],
    })
}

pub fn ro_crate_metadata(frontier: &Project, files: &[String]) -> Value {
    let graph_files: Vec<Value> = files
        .iter()
        .map(|path| {
            json!({
                "@id": path,
                "@type": "File",
                "name": path,
            })
        })
        .collect();

    let mut graph = vec![
        json!({
            "@id": "ro-crate-metadata.jsonld",
            "@type": "CreativeWork",
            "about": {"@id": "./"}
        }),
        json!({
            "@id": "./",
            "@type": "Dataset",
            "name": format!("{} proof packet", frontier.project.name),
            "description": frontier.project.description,
            "dateCreated": frontier.project.compiled_at,
            "conformsTo": {"@id": project::VELA_SCHEMA_URL},
            "hasPart": files.iter().map(|path| json!({"@id": path})).collect::<Vec<_>>()
        }),
    ];
    graph.extend(graph_files);
    graph.extend(frontier.artifacts.iter().map(|artifact| {
        json!({
            "@id": artifact.id,
            "@type": "CreativeWork",
            "name": artifact.name,
            "encodingFormat": artifact.media_type,
            "sha256": artifact.content_hash,
            "url": artifact.source_url.as_ref().or(artifact.locator.as_ref()),
            "license": artifact.license,
        })
    }));

    json!({
        "@context": "https://w3id.org/ro/crate/1.2/context",
        "@graph": graph,
    })
}

fn build_review_queue(frontier: &Project, signals: &[SignalItem]) -> Vec<ReviewQueueItem> {
    let link_counts = frontier
        .findings
        .iter()
        .map(|finding| {
            let outgoing = finding.links.len() as u32;
            let incoming = frontier
                .findings
                .iter()
                .flat_map(|other| &other.links)
                .filter(|link| link.target == finding.id)
                .count() as u32;
            (finding.id.clone(), outgoing + incoming)
        })
        .collect::<BTreeMap<_, _>>();

    let mut by_target = BTreeMap::<String, Vec<&SignalItem>>::new();
    for signal in signals {
        if signal.target.r#type == "finding" {
            by_target
                .entry(signal.target.id.clone())
                .or_default()
                .push(signal);
        }
    }

    let mut queue = by_target
        .into_iter()
        .map(|(target_id, grouped)| {
            let signal_score = grouped
                .iter()
                .map(|signal| signal_weight(signal))
                .sum::<u32>();
            let centrality_score = link_counts.get(&target_id).copied().unwrap_or(0).min(25);
            let priority_score = signal_score + centrality_score;
            let priority = if grouped
                .iter()
                .any(|signal| signal.blocks.iter().any(|block| block == "strict_check"))
            {
                "high"
            } else if grouped
                .iter()
                .any(|signal| signal.blocks.iter().any(|block| block == "proof_ready"))
            {
                "medium"
            } else {
                "low"
            };
            ReviewQueueItem {
                id: format!("rq_{}", target_id.trim_start_matches("vf_")),
                priority: priority.to_string(),
                priority_score,
                target: SignalTarget {
                    r#type: "finding".to_string(),
                    id: target_id,
                },
                signal_ids: grouped.iter().map(|signal| signal.id.clone()).collect(),
                reasons: grouped.iter().map(|signal| signal.reason.clone()).collect(),
                recommended_action: grouped
                    .first()
                    .map(|signal| signal.recommended_action.clone())
                    .unwrap_or_else(|| "Review finding state.".to_string()),
            }
        })
        .collect::<Vec<_>>();
    queue.sort_by(|a, b| {
        b.priority_score
            .cmp(&a.priority_score)
            .then_with(|| a.target.id.cmp(&b.target.id))
    });
    queue
}

fn signal_weight(signal: &SignalItem) -> u32 {
    let severity = match signal.severity.as_str() {
        "error" => 100,
        "warning" => 30,
        _ => 10,
    };
    let kind = match signal.kind.as_str() {
        "check_error" => 100,
        "contested_high_confidence" => 70,
        "proposal_conflict" => 80,
        "pending_proposal_review" => 50,
        "weak_provenance" => 45,
        "missing_evidence_span" => 35,
        _ => 10,
    };
    let blocker = if signal.blocks.iter().any(|block| block == "strict_check") {
        30
    } else if signal.blocks.iter().any(|block| block == "proof_ready") {
        15
    } else {
        0
    };
    severity + kind + blocker
}

fn build_proof_readiness(signals: &[SignalItem]) -> ProofReadiness {
    let blockers = signals
        .iter()
        .filter(|signal| signal.blocks.iter().any(|block| block == "proof_ready"))
        .count();
    let warnings = signals
        .iter()
        .filter(|signal| signal.severity == "warning")
        .count();
    ProofReadiness {
        status: if blockers == 0 {
            "ready".to_string()
        } else {
            "needs_review".to_string()
        },
        blockers,
        warnings,
        caveats: vec![
            "Proof readiness means packet state is reviewable, not scientifically settled."
                .to_string(),
        ],
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let head: String = s.chars().take(n).collect();
        format!("{head}…")
    }
}

fn signal_id(kind: &str, finding_id: &str) -> String {
    format!("sig_{kind}_{}", finding_id.trim_start_matches("vf_"))
}

fn contains_condition_sensitive_claim(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    [
        "delivery",
        "efficacy",
        "therapeutic",
        "clinical",
        "human",
        "mouse",
        "mice",
        "assay",
        "endpoint",
        "payload",
        "exposure",
        "translation",
    ]
    .iter()
    .any(|term| lower.contains(term))
}

#[cfg(test)]
mod tests {
    use crate::bundle::{
        Assertion, Conditions, Confidence, Evidence, FindingBundle, Flags, Provenance,
    };

    use super::*;

    fn minimal_finding(id: &str) -> FindingBundle {
        let assertion = Assertion {
            text: "LRP1 transport is altered in Alzheimer models.".to_string(),
            assertion_type: "mechanism".to_string(),
            entities: vec![],
            relation: None,
            direction: None,
            causal_claim: None,
            causal_evidence_grade: None,
        };
        let provenance = Provenance {
            source_type: "published_paper".to_string(),
            doi: None,
            pmid: None,
            pmc: None,
            openalex_id: None,
            url: None,
            title: String::new(),
            authors: vec![],
            year: Some(2020),
            journal: None,
            license: None,
            publisher: None,
            funders: vec![],
            extraction: Default::default(),
            review: None,
            citation_count: None,
        };
        FindingBundle {
            id: id.to_string(),
            version: 1,
            previous_version: None,
            assertion,
            evidence: Evidence {
                evidence_type: "experimental".to_string(),
                model_system: "mouse".to_string(),
                species: Some("Mus musculus".to_string()),
                method: "test".to_string(),
                sample_size: None,
                effect_size: None,
                p_value: None,
                replicated: false,
                replication_count: None,
                evidence_spans: vec![],
            },
            conditions: Conditions {
                text: String::new(),
                species_verified: vec![],
                species_unverified: vec![],
                in_vitro: false,
                in_vivo: true,
                human_data: false,
                clinical_trial: false,
                concentration_range: None,
                duration: None,
                age_group: None,
                cell_type: None,
            },
            confidence: Confidence::raw(0.9, "test".to_string(), 0.9),
            provenance,
            flags: Flags {
                gap: false,
                negative_space: false,
                contested: true,
                retracted: false,
                declining: false,
                gravity_well: false,
                review_state: None,
                superseded: false,
                signature_threshold: None,
                jointly_accepted: false,
            },
            links: vec![],
            annotations: vec![],
            attachments: vec![],
            created: "2026-01-01T00:00:00Z".to_string(),
            updated: None,

            access_tier: crate::access_tier::AccessTier::Public,
        }
    }

    #[test]
    fn weak_and_contested_findings_emit_review_signals() {
        let frontier = project::assemble("test", vec![minimal_finding("vf_abc")], 1, 0, "test");
        let report = analyze(&frontier, &[]);
        assert!(report.signals.iter().any(|s| s.kind == "weak_provenance"));
        assert!(
            report
                .signals
                .iter()
                .any(|s| s.kind == "missing_evidence_span")
        );
        assert!(
            report
                .signals
                .iter()
                .any(|s| s.kind == "contested_high_confidence")
        );
        assert_eq!(report.review_queue.len(), 1);
    }
}
