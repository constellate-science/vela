//! # Experiment Planner (v0.28)
//!
//! Reads `frontier.findings` filtered to `assertion.type ∈
//! {open_question, hypothesis}`, optionally clusters by topic, and
//! emits `finding.add` proposals of `assertion.type =
//! "experiment_intent"` (the v0.24 type from Code Analyst). Each
//! proposal carries the experiment description, its
//! `hypothesis_link` (the originating finding id), and an
//! `expected_change` description.
//!
//! Doctrine: this agent doesn't run experiments — it surfaces
//! experiments a researcher could run that would, if executed,
//! resolve the targeted question or hypothesis. Humans review
//! and prioritize.
//!
//! Scope discipline (v0.28):
//! * **Open questions + hypotheses only.** Doesn't operate over
//!   `candidate_finding` or `analysis_run` types — those already
//!   have evidence; experiments target uncertainty.
//! * **One LLM call per finding considered.** Simpler audit
//!   trail. Future v0.30+ can batch.
//! * **Idempotent.** Skips if an experiment_intent proposal
//!   already references the source finding id.

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

pub const AGENT_EXPERIMENTS: &str = "experiment-planner";

#[derive(Debug, Clone)]
pub struct ExperimentsInput {
    pub frontier_path: PathBuf,
    pub model: Option<String>,
    pub cli_command: String,
    pub apply: bool,
    /// Per-run cap on findings considered. Default 20.
    pub max_findings: Option<usize>,
}

impl Default for ExperimentsInput {
    fn default() -> Self {
        Self {
            frontier_path: PathBuf::new(),
            model: None,
            cli_command: "claude".to_string(),
            apply: true,
            max_findings: Some(20),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkippedFinding {
    pub finding_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExperimentsReport {
    pub run: vela_protocol::proposals::AgentRun,
    pub frontier_path: String,
    pub apply: bool,
    pub questions_seen: usize,
    pub hypotheses_seen: usize,
    pub experiments_emitted: usize,
    pub proposals_written: usize,
    pub skipped: Vec<SkippedFinding>,
}

pub async fn run(input: ExperimentsInput) -> Result<ExperimentsReport, String> {
    let mut frontier: Project = repo::load_from_path(&input.frontier_path)
        .map_err(|e| format!("load frontier {}: {e}", input.frontier_path.display()))?;

    let cap = input.max_findings.unwrap_or(usize::MAX);
    let mut all_candidates: Vec<FindingBundle> = frontier.findings.clone();
    for p in &frontier.proposals {
        if p.kind == "finding.add"
            && let Some(v) = p.payload.get("finding")
            && let Ok(b) = serde_json::from_value::<FindingBundle>(v.clone())
        {
            all_candidates.push(b);
        }
    }
    let mut questions = 0usize;
    let mut hypotheses = 0usize;
    let candidates: Vec<FindingBundle> = all_candidates
        .into_iter()
        .filter(|f| {
            matches!(
                f.assertion.assertion_type.as_str(),
                "open_question" | "hypothesis"
            )
        })
        .inspect(|f| match f.assertion.assertion_type.as_str() {
            "open_question" => questions += 1,
            "hypothesis" => hypotheses += 1,
            _ => {}
        })
        .take(cap)
        .collect();

    let ctx = AgentContext::new(
        AGENT_EXPERIMENTS,
        input.frontier_path.clone(),
        input.frontier_path.clone(),
        input.model.clone(),
        input.cli_command.clone(),
    );
    let extra = BTreeMap::from([
        ("questions_seen".to_string(), questions.to_string()),
        ("hypotheses_seen".to_string(), hypotheses.to_string()),
    ]);
    let mut report = ExperimentsReport {
        run: agent_run_meta(&ctx, extra),
        frontier_path: input.frontier_path.display().to_string(),
        apply: input.apply,
        questions_seen: questions,
        hypotheses_seen: hypotheses,
        experiments_emitted: 0,
        proposals_written: 0,
        skipped: Vec::new(),
    };

    // Skip findings that already have experiment_intent proposals
    // referencing them (idempotent).
    let already_planned: HashSet<String> = frontier
        .proposals
        .iter()
        .filter_map(|p| {
            let kind = p
                .payload
                .get("finding")
                .and_then(|f| f.get("assertion"))
                .and_then(|a| a.get("type"))
                .and_then(|t| t.as_str())?;
            if kind == "experiment_intent" {
                p.payload
                    .get("finding")
                    .and_then(|f| f.get("evidence"))
                    .and_then(|e| e.get("evidence_spans"))
                    .and_then(|spans| spans.as_array())
                    .and_then(|arr| {
                        arr.iter().find_map(|span| {
                            span.get("hypothesis_link")
                                .and_then(|v| v.as_str())
                                .map(String::from)
                        })
                    })
            } else {
                None
            }
        })
        .collect();
    let existing_finding_ids: HashSet<String> =
        frontier.findings.iter().map(|f| f.id.clone()).collect();
    let existing_proposal_ids: HashSet<String> =
        frontier.proposals.iter().map(|p| p.id.clone()).collect();

    let mut new_proposals: Vec<StateProposal> = Vec::new();

    for finding in &candidates {
        if already_planned.contains(&finding.id) {
            report.skipped.push(SkippedFinding {
                finding_id: finding.id.clone(),
                reason: "experiment already planned for this id".to_string(),
            });
            continue;
        }

        let plan = match call_planner(finding, &input) {
            Ok(p) => p,
            Err(e) => {
                report.skipped.push(SkippedFinding {
                    finding_id: finding.id.clone(),
                    reason: format!("model call failed: {e}"),
                });
                continue;
            }
        };

        for exp in plan.experiments {
            let bundle = lift_experiment(&exp, finding);
            if existing_finding_ids.contains(&bundle.id) {
                continue;
            }
            let proposal = build_finding_add_proposal(
                &bundle,
                &ctx,
                &finding.id,
                &exp.expected_change,
                &[],
                &report.run,
            );
            if existing_proposal_ids.contains(&proposal.id) {
                continue;
            }
            new_proposals.push(proposal);
            report.experiments_emitted += 1;
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
struct PlanOutput {
    #[serde(default)]
    experiments: Vec<ExperimentSpec>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ExperimentSpec {
    intent: String,
    #[serde(default)]
    method: String,
    #[serde(default)]
    expected_change: String,
    #[serde(default)]
    confounders: Vec<String>,
}

fn call_planner(finding: &FindingBundle, input: &ExperimentsInput) -> Result<PlanOutput, String> {
    let user_prompt = build_user_prompt(finding);
    let system_prompt = build_system_prompt();
    let schema = output_schema_json();

    let mut call = ClaudeCall::new(system_prompt, &user_prompt, &schema);
    call.cli_command = &input.cli_command;
    call.model = input.model.as_deref();
    let value = run_structured(call)?;
    serde_json::from_value(value.clone())
        .map_err(|e| format!("parse planner output: {e}\nvalue: {value}"))
}

fn build_system_prompt() -> &'static str {
    r#"You are Experiment Planner, an agent inside the Vela
scientific protocol. You read one open question or hypothesis from
a frontier and propose 1–3 specific experiments that, if run,
would resolve or significantly update the targeted uncertainty.

Each experiment must include:
  intent          — one sentence describing the experiment.
  method          — concrete method or assay (e.g.
                    "western blot quantification of tau in
                    hippocampal lysates", "behavioral Morris water
                    maze with n>=12 per group").
  expected_change — what the data would need to show to favor
                    one side over the other ("if effect_size > 1.5
                    in n>=20, the hypothesis is supported").
  confounders     — short list of confounders that would
                    invalidate the result.

Rules:
1. Be concrete. "Run more experiments" is not an experiment.
   Specify the assay, the comparison, the effect size that would
   matter.
2. Stay close to the targeted finding. Don't wander into
   adjacent fields.
3. Prefer 1–3 high-quality experiments over 6 vague ones.
4. Output the JSON object directly — no markdown fences."#
}

fn build_user_prompt(f: &FindingBundle) -> String {
    let evidence_count = f.evidence.evidence_spans.len();
    let conditions = if !f.conditions.text.is_empty() {
        format!("\nConditions: {}", f.conditions.text)
    } else {
        String::new()
    };
    format!(
        "Finding id: {}\nType: {}\nClaim: {}\nExisting evidence spans: {evidence_count}{conditions}\n\nPropose experiments that would resolve this finding's uncertainty. Return the JSON object.",
        f.id, f.assertion.assertion_type, f.assertion.text
    )
}

fn output_schema_json() -> String {
    serde_json::json!({
        "type": "object",
        "properties": {
            "experiments": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "intent":          { "type": "string" },
                        "method":          { "type": "string" },
                        "expected_change": { "type": "string" },
                        "confounders":     { "type": "array", "items": { "type": "string" } }
                    },
                    "required": ["intent"]
                }
            }
        },
        "required": ["experiments"]
    })
    .to_string()
}

fn lift_experiment(exp: &ExperimentSpec, source: &FindingBundle) -> FindingBundle {
    let assertion = Assertion {
        text: exp.intent.clone(),
        assertion_type: "experiment_intent".to_string(),
        entities: Vec::new(),
        relation: None,
        direction: None,
        causal_claim: None,
        causal_evidence_grade: None,
    };
    let mut spans: Vec<serde_json::Value> = Vec::new();
    spans.push(serde_json::json!({
        "section": "method",
        "text": exp.method.clone()
    }));
    if !exp.expected_change.is_empty() {
        spans.push(serde_json::json!({
            "section": "expected_change",
            "text": exp.expected_change.clone()
        }));
    }
    if !exp.confounders.is_empty() {
        spans.push(serde_json::json!({
            "section": "confounders",
            "items": exp.confounders.clone()
        }));
    }
    spans.push(serde_json::json!({
        "section": "hypothesis_link",
        "hypothesis_link": source.id.clone(),
        "source_claim": source.assertion.text.clone()
    }));
    let evidence = Evidence {
        evidence_type: "experiment_intent".to_string(),
        model_system: String::new(),
        species: None,
        method: "experiment_planner".to_string(),
        sample_size: None,
        effect_size: None,
        p_value: None,
        replicated: false,
        replication_count: None,
        evidence_spans: spans,
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
    let confidence = Confidence::raw(
        0.0,
        "experiment_planner: proposed experiment, not yet run",
        0.7,
    );
    let provenance = Provenance {
        source_type: "agent_inference".to_string(),
        doi: None,
        pmid: None,
        pmc: None,
        openalex_id: None,
        url: None,
        title: format!("Experiment Planner: {}", source.id),
        authors: Vec::new(),
        year: None,
        journal: None,
        license: None,
        publisher: None,
        funders: Vec::new(),
        extraction: Extraction {
            method: "experiment_planner_via_claude_cli".to_string(),
            model: None,
            model_version: None,
            extracted_at: chrono::Utc::now().to_rfc3339(),
            extractor_version: "vela-scientist::experiment-planner/v0.28".to_string(),
        },
        review: None,
        citation_count: None,
    };
    let flags = Flags {
        gap: true,
        ..Flags::default()
    };
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

    fn finding(id: &str, claim: &str, kind: &str) -> FindingBundle {
        FindingBundle {
            id: id.to_string(),
            version: 1,
            previous_version: None,
            assertion: A {
                text: claim.to_string(),
                assertion_type: kind.to_string(),
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
    fn lift_experiment_attaches_hypothesis_link() {
        let source = finding("vf_q1", "Why does X vary?", "open_question");
        let exp = ExperimentSpec {
            intent: "Run cohort study with stratified sampling".to_string(),
            method: "Stratified sampling on age + dose, n>=20 per stratum".to_string(),
            expected_change: "Effect size variance < 0.3 if X is dose-dependent".to_string(),
            confounders: vec!["batch effect".to_string()],
        };
        let b = lift_experiment(&exp, &source);
        assert_eq!(b.assertion.assertion_type, "experiment_intent");
        assert!(b.flags.gap);
        let has_link = b
            .evidence
            .evidence_spans
            .iter()
            .any(|s| s.get("hypothesis_link").and_then(|v| v.as_str()) == Some("vf_q1"));
        assert!(has_link);
    }
}
