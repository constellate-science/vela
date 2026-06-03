//! # Contradiction Finder (v0.28)
//!
//! Walks `frontier.findings` (signed canonical state, not
//! proposals), batches them into pairwise comparisons, asks
//! `claude -p` to identify real contradictions, and emits one
//! `finding.add` proposal of `assertion.type =
//! "cross_finding_tension"` per detected pair. Distinct from
//! Notes Compiler's `tension` (within-note, researcher-noted) so
//! the Workbench can show which agent flagged which kind.
//!
//! Doctrine: this agent reads the substrate but writes nothing
//! canonical. Every detected tension is a proposal a human
//! reviews before becoming state. The substrate's `links` array
//! could also represent contradictions, but that's an additional
//! kind we'd need to validate; emitting a free-standing `tension`
//! finding keeps the substrate untouched.
//!
//! Scope discipline (v0.28):
//! * **Within-frontier only.** Cross-frontier tension detection
//!   waits for a v0.30+ slice (the substrate already supports
//!   cross-frontier links via v0.8 `vfr_id` syntax; the agent
//!   side just needs a multi-frontier scout).
//! * **Pairwise batching.** One model call per batch of up to 12
//!   findings. The model returns explicit pairs; the agent
//!   emits one tension per pair.
//! * **Idempotent re-runs.** Tensions whose claim text matches
//!   an existing tension proposal in the frontier are skipped.

use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use vela_protocol::bundle::{
    Assertion, Conditions, Confidence, Evidence, Extraction, FindingBundle, Flags, Provenance,
};
use vela_protocol::project::Project;
use vela_protocol::proposals::StateProposal;
use vela_protocol::repo;

use crate::agent::{AgentContext, agent_run_meta, build_finding_add_proposal};
use crate::llm_cli::{ClaudeCall, run_structured};

pub const AGENT_TENSIONS: &str = "contradiction-finder";

const BATCH_SIZE: usize = 12;

#[derive(Debug, Clone)]
pub struct TensionsInput {
    pub frontier_path: PathBuf,
    pub model: Option<String>,
    pub cli_command: String,
    pub apply: bool,
    /// Per-run cap on findings considered. Default 60.
    pub max_findings: Option<usize>,
}

impl Default for TensionsInput {
    fn default() -> Self {
        Self {
            frontier_path: PathBuf::new(),
            model: None,
            cli_command: "claude".to_string(),
            apply: true,
            max_findings: Some(60),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkippedBatch {
    pub batch: usize,
    pub reason: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TensionsReport {
    pub run: vela_protocol::proposals::AgentRun,
    pub frontier_path: String,
    pub apply: bool,
    pub findings_seen: usize,
    pub batches_processed: usize,
    pub tensions_emitted: usize,
    pub proposals_written: usize,
    pub skipped: Vec<SkippedBatch>,
}

pub async fn run(input: TensionsInput) -> Result<TensionsReport, String> {
    let mut frontier: Project = repo::load_from_path(&input.frontier_path)
        .map_err(|e| format!("load frontier {}: {e}", input.frontier_path.display()))?;

    let cap = input.max_findings.unwrap_or(usize::MAX);
    let findings: Vec<&FindingBundle> = frontier
        .findings
        .iter()
        .filter(|f| !f.flags.retracted)
        .take(cap)
        .collect();
    let findings_seen = findings.len();

    let ctx = AgentContext::new(
        AGENT_TENSIONS,
        input.frontier_path.clone(),
        input.frontier_path.clone(),
        input.model.clone(),
        input.cli_command.clone(),
    );
    let extra = BTreeMap::from([("findings_seen".to_string(), findings_seen.to_string())]);
    let mut report = TensionsReport {
        run: agent_run_meta(&ctx, extra),
        frontier_path: input.frontier_path.display().to_string(),
        apply: input.apply,
        findings_seen,
        batches_processed: 0,
        tensions_emitted: 0,
        proposals_written: 0,
        skipped: Vec::new(),
    };

    // Collect existing cross-finding-tension claim text to avoid
    // duplicates. We only dedupe against this agent's type so a
    // notes-derived `tension` doesn't shadow a Contradiction Finder
    // pair (different evidence + different review intent).
    let existing_tensions: HashSet<String> = frontier
        .proposals
        .iter()
        .filter_map(|p| {
            p.payload
                .get("finding")
                .and_then(|f| f.get("assertion"))
                .and_then(|a| {
                    let t = a.get("type").and_then(|v| v.as_str()).unwrap_or("");
                    if t == "cross_finding_tension" {
                        a.get("text").and_then(|v| v.as_str()).map(String::from)
                    } else {
                        None
                    }
                })
        })
        .collect();
    let existing_finding_ids: HashSet<String> =
        frontier.findings.iter().map(|f| f.id.clone()).collect();
    let existing_proposal_ids: HashSet<String> =
        frontier.proposals.iter().map(|p| p.id.clone()).collect();

    let mut new_proposals: Vec<StateProposal> = Vec::new();

    for (batch_idx, chunk) in findings.chunks(BATCH_SIZE).enumerate() {
        let pairs = match call_tensions(chunk, &input) {
            Ok(p) => p,
            Err(e) => {
                report.skipped.push(SkippedBatch {
                    batch: batch_idx,
                    reason: format!("model call failed: {e}"),
                });
                continue;
            }
        };
        report.batches_processed += 1;

        for p in pairs {
            // Translate batch-local indices to finding ids.
            if p.a >= chunk.len() || p.b >= chunk.len() || p.a == p.b {
                continue;
            }
            let f_a = chunk[p.a];
            let f_b = chunk[p.b];
            let bundle = lift_tension(f_a, f_b, &p.why);
            if existing_tensions.contains(&bundle.assertion.text) {
                continue;
            }
            if existing_finding_ids.contains(&bundle.id) {
                continue;
            }
            let proposal = build_finding_add_proposal(
                &bundle,
                &ctx,
                &format!("{} ↔ {}", f_a.id, f_b.id),
                &p.why,
                &[],
                &report.run,
            );
            if existing_proposal_ids.contains(&proposal.id) {
                continue;
            }
            new_proposals.push(proposal);
            report.tensions_emitted += 1;
        }
    }

    if input.apply && !new_proposals.is_empty() {
        for p in new_proposals.drain(..) {
            report.proposals_written += 1;
            frontier.proposals.push(p);
        }
        repo::save_to_path(&input.frontier_path, &frontier)
            .map_err(|e| format!("save frontier: {e}"))?;
    } else {
        report.proposals_written = new_proposals.len();
    }

    report.run.finished_at = Some(Utc::now().to_rfc3339());
    Ok(report)
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ModelOutput {
    #[serde(default)]
    pairs: Vec<TensionPair>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct TensionPair {
    a: usize,
    b: usize,
    #[serde(default)]
    why: String,
}

fn call_tensions(
    chunk: &[&FindingBundle],
    input: &TensionsInput,
) -> Result<Vec<TensionPair>, String> {
    let user_prompt = build_user_prompt(chunk);
    let system_prompt = build_system_prompt();
    let schema = output_schema_json();

    let mut call = ClaudeCall::new(system_prompt, &user_prompt, &schema);
    call.cli_command = &input.cli_command;
    call.model = input.model.as_deref();
    let value = run_structured(call)?;
    let parsed: ModelOutput = serde_json::from_value(value.clone())
        .map_err(|e| format!("parse tensions output: {e}\nvalue: {value}"))?;
    Ok(parsed.pairs)
}

fn build_system_prompt() -> &'static str {
    r#"You are Contradiction Finder, an analyst inside the Vela
scientific protocol. You read a numbered list of scientific
findings and identify pairs that *actually* contradict each other.

A real contradiction satisfies all three:
1. Both findings make claims about the same domain (overlapping
   organism / intervention / phenotype).
2. The claims cannot both be true given consistent definitions.
3. The disagreement is not just terminology or scope drift.

Output strict JSON matching the schema. For each detected
contradiction, return:
  a, b — zero-based indices into the input list
  why  — one short sentence explaining the disagreement

Rules:
1. Pairs must be unordered-distinct: emit (a < b) only.
2. Soft tensions (replication failures, scope mismatches) DO
   count if the claims directly oppose. Be liberal with the
   "tension" label but conservative about claiming "contradicts".
3. Empty `pairs` array is acceptable. Prefer 0–4 high-quality
   pairs per batch over many speculative ones.
4. Output the JSON object directly — no markdown fences."#
}

fn build_user_prompt(chunk: &[&FindingBundle]) -> String {
    let lines: Vec<String> = chunk
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let claim = &f.assertion.text;
            let kind = &f.assertion.assertion_type;
            let evidence_count = f.evidence.evidence_spans.len();
            format!("[{i}] type:{kind} ev:{evidence_count} → {claim}")
        })
        .collect();
    format!(
        "Findings (numbered):\n{}\n\nReturn the JSON object with `pairs` of contradictions.",
        lines.join("\n")
    )
}

fn output_schema_json() -> String {
    serde_json::json!({
        "type": "object",
        "properties": {
            "pairs": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "a":   { "type": "integer", "minimum": 0 },
                        "b":   { "type": "integer", "minimum": 0 },
                        "why": { "type": "string" }
                    },
                    "required": ["a", "b", "why"]
                }
            }
        },
        "required": ["pairs"]
    })
    .to_string()
}

fn lift_tension(a: &FindingBundle, b: &FindingBundle, why: &str) -> FindingBundle {
    let assertion_text = format!(
        "Cross-finding tension: \"{}\" vs \"{}\". Why: {why}",
        a.assertion.text, b.assertion.text
    );
    let assertion = Assertion {
        text: assertion_text,
        // v0.28.x: distinct from notes-compiler's `tension` (which is
        // a within-note contradiction surfaced by the researcher);
        // this is a model-detected pair across two signed findings.
        // Friction #6 fix: same chip color, different label, so the
        // Workbench can show which agent flagged which kind.
        assertion_type: "cross_finding_tension".to_string(),
        entities: Vec::new(),
        relation: None,
        direction: None,
        causal_claim: None,
        causal_evidence_grade: None,
    };
    let evidence = Evidence {
        evidence_type: "tension_pair".to_string(),
        model_system: String::new(),
        species: None,
        method: "contradiction_finder".to_string(),
        sample_size: None,
        effect_size: None,
        p_value: None,
        replicated: false,
        replication_count: None,
        evidence_spans: vec![
            serde_json::json!({ "section": "side_a", "finding_id": a.id, "text": a.assertion.text }),
            serde_json::json!({ "section": "side_b", "finding_id": b.id, "text": b.assertion.text }),
        ],
    };
    let conditions = Conditions {
        text: String::new(),
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
    };
    let confidence = Confidence::raw(0.0, "contradiction_finder: pair surfaced for review", 0.7);
    let provenance = Provenance {
        source_type: "agent_inference".to_string(),
        doi: None,
        pmid: None,
        pmc: None,
        openalex_id: None,
        url: None,
        title: format!("Contradiction Finder: {} ↔ {}", a.id, b.id),
        authors: Vec::new(),
        year: None,
        journal: None,
        license: None,
        publisher: None,
        funders: Vec::new(),
        extraction: Extraction {
            method: "contradiction_finder_via_claude_cli".to_string(),
            model: None,
            model_version: None,
            extracted_at: chrono::Utc::now().to_rfc3339(),
            extractor_version: "vela-scientist::contradiction-finder/v0.28".to_string(),
        },
        review: None,
        citation_count: None,
    };
    let mut flags = Flags {
        contested: true,
        ..Flags::default()
    };
    let _ = &mut flags;
    FindingBundle::new(
        assertion, evidence, conditions, confidence, provenance, flags,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use vela_protocol::bundle::{
        Assertion as A, Conditions as C, Confidence as Cf, Evidence as E, Extraction as Ex,
        Flags as F, Provenance as P,
    };

    fn finding(id: &str, claim: &str) -> FindingBundle {
        FindingBundle {
            id: id.to_string(),
            version: 1,
            previous_version: None,
            assertion: A {
                text: claim.to_string(),
                assertion_type: "mechanism".to_string(),
                entities: Vec::new(),
                relation: None,
                direction: None,
                causal_claim: None,
                causal_evidence_grade: None,
            },
            evidence: E {
                evidence_type: "test".to_string(),
                model_system: String::new(),
                species: None,
                method: "t".to_string(),
                sample_size: None,
                effect_size: None,
                p_value: None,
                replicated: false,
                replication_count: None,
                evidence_spans: Vec::new(),
            },
            conditions: C {
                text: String::new(),
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
            confidence: Cf::raw(0.5, "t", 0.7),
            provenance: P {
                source_type: "t".to_string(),
                doi: None,
                pmid: None,
                pmc: None,
                openalex_id: None,
                url: None,
                title: "t".to_string(),
                authors: Vec::new(),
                year: None,
                journal: None,
                license: None,
                publisher: None,
                funders: Vec::new(),
                extraction: Ex {
                    method: "t".to_string(),
                    model: None,
                    model_version: None,
                    extracted_at: String::new(),
                    extractor_version: "t".to_string(),
                },
                review: None,
                citation_count: None,
            },
            flags: F::default(),
            links: Vec::new(),
            annotations: Vec::new(),
            attachments: Vec::new(),
            created: String::new(),
            updated: None,

            access_tier: vela_protocol::access_tier::AccessTier::Public,
        }
    }

    #[test]
    fn lift_tension_marks_contested() {
        let a = finding("vf_a", "X increases Y");
        let b = finding("vf_b", "X decreases Y");
        let t = lift_tension(&a, &b, "opposite directions on the same intervention");
        assert_eq!(t.assertion.assertion_type, "cross_finding_tension");
        assert!(t.flags.contested);
        assert_eq!(t.evidence.evidence_spans.len(), 2);
        assert!(t.assertion.text.contains("X increases Y"));
        assert!(t.assertion.text.contains("X decreases Y"));
    }
}
