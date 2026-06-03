//! # Code & Notebook Analyst (v0.24)
//!
//! Walks a research repo — `.ipynb` notebooks, `.py` / `.R` /
//! `.jl` / `.qmd` / `.Rmd` scripts — and emits analyses,
//! code-derived findings, and experiment intents as `finding.add`
//! `StateProposal`s tagged `agent_run.agent = "code-analyst"`.
//!
//! Why a separate agent (vs. just feeding everything to Notes
//! Compiler)? Code carries different signal: a snippet of pandas
//! that produced a number is a citable artifact, not a note.
//! Reviewer should see what the model claims the code computed,
//! the line range it cites, and (when present) the verbatim
//! output text — same auditability as Literature Scout's evidence
//! quotes from a paper.
//!
//! Scope discipline (v0.24):
//! * **No execution.** Read-only. The agent never runs Python or
//!   imports anything from the user's repo.
//! * **No AST parsing.** Scripts go in as text, capped at 12k chars.
//!   A future v0.27 can add language-aware function/class
//!   extraction if the dogfood says it matters.
//! * **One model call per file.** Same per-call cost cap as Scout.
//! * **`text/plain` outputs only.** Notebook image / HTML outputs
//!   are dropped at parse time.

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

use crate::agent::{
    AgentContext, agent_run_meta, build_finding_add_proposal, discover_files_recursive,
};
use crate::llm_cli::{ClaudeCall, run_structured};
use crate::notebook::{parse_ipynb, render_for_prompt};

pub const AGENT_CODE_ANALYST: &str = "code-analyst";

#[derive(Debug, Clone)]
pub struct CodeAnalystInput {
    /// Repo / folder root. Recursive walk; skips `.git`,
    /// `node_modules`, `target`, `dist`, `__pycache__`, `.venv`,
    /// `venv`, `build`.
    pub root: PathBuf,
    pub frontier_path: PathBuf,
    pub model: Option<String>,
    pub cli_command: String,
    pub apply: bool,
    /// Per-run cap on files processed. Default: 30.
    pub max_files: Option<usize>,
}

impl Default for CodeAnalystInput {
    fn default() -> Self {
        Self {
            root: PathBuf::new(),
            frontier_path: PathBuf::new(),
            model: None,
            cli_command: "claude".to_string(),
            apply: true,
            max_files: Some(30),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkippedSource {
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CodeAnalystReport {
    pub run: vela_protocol::proposals::AgentRun,
    pub root: String,
    pub frontier_path: String,
    pub apply: bool,
    pub files_seen: usize,
    pub notebooks_processed: usize,
    pub scripts_processed: usize,
    pub analyses_emitted: usize,
    pub code_findings_emitted: usize,
    pub experiment_intents_emitted: usize,
    pub proposals_written: usize,
    pub skipped: Vec<SkippedSource>,
}

pub async fn run(input: CodeAnalystInput) -> Result<CodeAnalystReport, String> {
    let extensions = ["ipynb", "py", "r", "jl", "qmd", "rmd"];
    let skip_dirs = [
        ".git",
        "node_modules",
        "target",
        "dist",
        "__pycache__",
        ".venv",
        "venv",
        "build",
        ".pytest_cache",
    ];
    let mut files = discover_files_recursive(&input.root, &extensions, &skip_dirs)?;
    let total_seen = files.len();
    if let Some(cap) = input.max_files
        && files.len() > cap
    {
        files.truncate(cap);
    }

    let mut frontier: Project = repo::load_from_path(&input.frontier_path)
        .map_err(|e| format!("load frontier {}: {e}", input.frontier_path.display()))?;

    let ctx = AgentContext::new(
        AGENT_CODE_ANALYST,
        input.frontier_path.clone(),
        input.root.clone(),
        input.model.clone(),
        input.cli_command.clone(),
    );
    let extra = BTreeMap::from([
        ("files_seen".to_string(), total_seen.to_string()),
        ("files_capped_to".to_string(), files.len().to_string()),
    ]);
    let mut report = CodeAnalystReport {
        run: agent_run_meta(&ctx, extra),
        root: input.root.display().to_string(),
        frontier_path: input.frontier_path.display().to_string(),
        apply: input.apply,
        files_seen: total_seen,
        ..Default::default()
    };

    let existing_finding_ids: HashSet<String> =
        frontier.findings.iter().map(|f| f.id.clone()).collect();
    let existing_proposal_ids: HashSet<String> =
        frontier.proposals.iter().map(|p| p.id.clone()).collect();
    let mut new_proposals: Vec<StateProposal> = Vec::new();

    for path in &files {
        let label = path.display().to_string();
        let basename = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("source")
            .to_string();
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .map(str::to_ascii_lowercase)
            .unwrap_or_default();

        let body = if ext == "ipynb" {
            match parse_ipynb(path) {
                Ok(nb) => {
                    report.notebooks_processed += 1;
                    render_for_prompt(&nb, 12_000)
                }
                Err(e) => {
                    report.skipped.push(SkippedSource {
                        path: label,
                        reason: format!("notebook parse failed: {e}"),
                    });
                    continue;
                }
            }
        } else {
            match std::fs::read_to_string(path) {
                Ok(s) if !s.trim().is_empty() => {
                    report.scripts_processed += 1;
                    s.chars().take(12_000).collect()
                }
                Ok(_) => {
                    report.skipped.push(SkippedSource {
                        path: label,
                        reason: "empty file".to_string(),
                    });
                    continue;
                }
                Err(e) => {
                    report.skipped.push(SkippedSource {
                        path: label,
                        reason: format!("read failed: {e}"),
                    });
                    continue;
                }
            }
        };

        let model_output = match call_analyst(&body, &basename, &ext, &input) {
            Ok(v) => v,
            Err(e) => {
                report.skipped.push(SkippedSource {
                    path: label,
                    reason: format!("model call failed: {e}"),
                });
                continue;
            }
        };

        for a in model_output.analyses {
            let bundle = lift_analysis(&a, &basename, &ext);
            stage(
                &mut new_proposals,
                bundle,
                a.purpose,
                &basename,
                &existing_finding_ids,
                &existing_proposal_ids,
                &mut report.skipped,
                &ctx,
                &report.run,
            );
            report.analyses_emitted += 1;
        }
        for c in model_output.code_findings {
            let bundle = lift_code_finding(&c, &basename, &ext);
            stage(
                &mut new_proposals,
                bundle,
                String::new(),
                &basename,
                &existing_finding_ids,
                &existing_proposal_ids,
                &mut report.skipped,
                &ctx,
                &report.run,
            );
            report.code_findings_emitted += 1;
        }
        for e in model_output.experiment_intents {
            let bundle = lift_experiment_intent(&e, &basename, &ext);
            stage(
                &mut new_proposals,
                bundle,
                e.expected_change,
                &basename,
                &existing_finding_ids,
                &existing_proposal_ids,
                &mut report.skipped,
                &ctx,
                &report.run,
            );
            report.experiment_intents_emitted += 1;
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

#[allow(clippy::too_many_arguments)]
fn stage(
    new_proposals: &mut Vec<StateProposal>,
    finding: FindingBundle,
    rationale: String,
    source_label: &str,
    existing_finding_ids: &HashSet<String>,
    existing_proposal_ids: &HashSet<String>,
    skipped: &mut Vec<SkippedSource>,
    ctx: &AgentContext,
    run: &vela_protocol::proposals::AgentRun,
) {
    if existing_finding_ids.contains(&finding.id) {
        skipped.push(SkippedSource {
            path: format!("{source_label}#{}", finding.id),
            reason: "finding id already in frontier".to_string(),
        });
        return;
    }
    let proposal = build_finding_add_proposal(&finding, ctx, source_label, &rationale, &[], run);
    if existing_proposal_ids.contains(&proposal.id) {
        skipped.push(SkippedSource {
            path: format!("{source_label}#{}", proposal.id),
            reason: "proposal id already in frontier".to_string(),
        });
        return;
    }
    new_proposals.push(proposal);
}

// ---------- Model interface ----------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ModelOutput {
    #[serde(default)]
    analyses: Vec<MAnalysis>,
    #[serde(default)]
    code_findings: Vec<MCodeFinding>,
    #[serde(default)]
    experiment_intents: Vec<MExperimentIntent>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct MAnalysis {
    purpose: String,
    #[serde(default)]
    dataset_or_input: String,
    #[serde(default)]
    method: String,
    #[serde(default)]
    key_result: String,
    #[serde(default)]
    files: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct MCodeFinding {
    claim: String,
    #[serde(default)]
    derived_from: String,
    #[serde(default)]
    code_excerpt: String,
    #[serde(default)]
    output_excerpt: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct MExperimentIntent {
    intent: String,
    #[serde(default)]
    hypothesis_link: String,
    #[serde(default)]
    expected_change: String,
}

fn call_analyst(
    body: &str,
    basename: &str,
    ext: &str,
    input: &CodeAnalystInput,
) -> Result<ModelOutput, String> {
    let user_prompt = build_user_prompt(body, basename, ext);
    let system_prompt = build_system_prompt();
    let schema = output_schema_json();

    let mut call = ClaudeCall::new(system_prompt, &user_prompt, &schema);
    call.cli_command = &input.cli_command;
    call.model = input.model.as_deref();
    let value = run_structured(call)?;
    let parsed: ModelOutput = serde_json::from_value(value.clone())
        .map_err(|e| format!("parse model output: {e}\nvalue: {value}"))?;
    Ok(parsed)
}

fn build_system_prompt() -> &'static str {
    r#"You are Code Analyst, an extractor agent inside the Vela
scientific protocol. You read one source file at a time
(Jupyter notebook or script in Python / R / Julia / Quarto / Rmd)
and propose three kinds of reviewable items as strict JSON
matching the provided JSON Schema exactly:

  analyses           — what the file actually does, end-to-end:
                       its purpose, the dataset or input it reads,
                       the method it applies, and the key result
                       (in one sentence). One per logically distinct
                       analysis in the file.
  code_findings      — claims the code makes that a reviewer should
                       audit. Each carries a verbatim ≤200-char
                       `code_excerpt` from the file and a verbatim
                       ≤200-char `output_excerpt` if a notebook
                       output is present. `derived_from` is the file
                       name and (for notebooks) the cell index, e.g.
                       "analysis.ipynb#cell[3]".
  experiment_intents — concrete next experiments the code suggests:
                       a hyperparameter sweep, an additional cohort,
                       a comparison missing from the current run.
                       Each has an `intent`, an optional
                       `hypothesis_link` (a hypothesis the experiment
                       would test), and an `expected_change` (what
                       you'd expect the data to show).

Rules:
1. Each item must be specific to what's actually in the file —
   no generalities about the field. If the file just loads data,
   that's `analyses=[{purpose: "load X data", method: "pandas
   read_csv", ...}]`, not a list of dataset_summary claims.
2. `code_excerpt` and `output_excerpt` must be near-verbatim from
   the file or its outputs. Trim to 200 chars but do not paraphrase.
3. Empty arrays are acceptable. Prefer 1–4 high-quality items per
   category over many vague ones.
4. Output the JSON object directly — no markdown fences, no prose."#
}

fn build_user_prompt(body: &str, basename: &str, ext: &str) -> String {
    format!(
        "Source file: {basename} (kind: {ext})\n\nFile content follows.\n\n---\n{body}\n---\n\nReturn the JSON object."
    )
}

fn output_schema_json() -> String {
    serde_json::json!({
        "type": "object",
        "properties": {
            "analyses": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "purpose":          { "type": "string" },
                        "dataset_or_input": { "type": "string" },
                        "method":           { "type": "string" },
                        "key_result":       { "type": "string" },
                        "files":            { "type": "array", "items": { "type": "string" } }
                    },
                    "required": ["purpose"]
                }
            },
            "code_findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "claim":          { "type": "string" },
                        "derived_from":   { "type": "string" },
                        "code_excerpt":   { "type": "string" },
                        "output_excerpt": { "type": "string" }
                    },
                    "required": ["claim", "code_excerpt"]
                }
            },
            "experiment_intents": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "intent":          { "type": "string" },
                        "hypothesis_link": { "type": "string" },
                        "expected_change": { "type": "string" }
                    },
                    "required": ["intent"]
                }
            }
        }
    })
    .to_string()
}

// ---------- Lift helpers ----------

fn base_extraction() -> Extraction {
    Extraction {
        method: "code_analyst_via_claude_cli".to_string(),
        model: None,
        model_version: None,
        extracted_at: chrono::Utc::now().to_rfc3339(),
        extractor_version: "vela-scientist::code-analyst/v0.24".to_string(),
    }
}

fn base_provenance(label: &str, ext: &str) -> Provenance {
    let source_type = match ext {
        "ipynb" => "jupyter_notebook",
        "py" | "r" | "jl" | "qmd" | "rmd" => "research_script",
        _ => "research_code",
    }
    .to_string();
    Provenance {
        source_type,
        doi: None,
        pmid: None,
        pmc: None,
        openalex_id: None,
        url: None,
        title: label.to_string(),
        authors: Vec::new(),
        year: None,
        journal: None,
        license: None,
        publisher: None,
        funders: Vec::new(),
        extraction: base_extraction(),
        review: None,
        citation_count: None,
    }
}

fn base_flags() -> Flags {
    Flags::default()
}

fn base_conditions() -> Conditions {
    Conditions {
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
    }
}

fn lift_analysis(a: &MAnalysis, label: &str, ext: &str) -> FindingBundle {
    let mut spans: Vec<serde_json::Value> = Vec::new();
    if !a.method.is_empty() {
        spans.push(serde_json::json!({ "section": "method", "text": a.method.clone() }));
    }
    if !a.key_result.is_empty() {
        spans.push(serde_json::json!({ "section": "key_result", "text": a.key_result.clone() }));
    }
    let evidence = Evidence {
        evidence_type: "code_derived".to_string(),
        model_system: a.dataset_or_input.clone(),
        species: None,
        method: "code_analyst".to_string(),
        sample_size: None,
        effect_size: None,
        p_value: None,
        replicated: false,
        replication_count: None,
        evidence_spans: spans,
    };
    let assertion = Assertion {
        text: a.purpose.clone(),
        assertion_type: "analysis_run".to_string(),
        entities: Vec::new(),
        relation: None,
        direction: None,
        causal_claim: None,
        causal_evidence_grade: None,
    };
    let confidence = Confidence::raw(
        0.4,
        "code_analyst: analysis described from source code",
        0.7,
    );
    FindingBundle::new(
        assertion,
        evidence,
        base_conditions(),
        confidence,
        base_provenance(label, ext),
        base_flags(),
    )
}

fn lift_code_finding(c: &MCodeFinding, label: &str, ext: &str) -> FindingBundle {
    let mut spans: Vec<serde_json::Value> = Vec::new();
    if !c.code_excerpt.is_empty() {
        spans.push(serde_json::json!({
            "section": "code",
            "derived_from": c.derived_from.clone(),
            "text": c.code_excerpt.clone()
        }));
    }
    if !c.output_excerpt.is_empty() {
        spans.push(serde_json::json!({
            "section": "output",
            "text": c.output_excerpt.clone()
        }));
    }
    let evidence = Evidence {
        evidence_type: "code_derived".to_string(),
        model_system: String::new(),
        species: None,
        method: "code_analyst".to_string(),
        sample_size: None,
        effect_size: None,
        p_value: None,
        replicated: false,
        replication_count: None,
        evidence_spans: spans,
    };
    let assertion = Assertion {
        text: c.claim.clone(),
        assertion_type: "code_derived".to_string(),
        entities: Vec::new(),
        relation: None,
        direction: None,
        causal_claim: None,
        causal_evidence_grade: None,
    };
    let confidence = Confidence::raw(0.5, "code_analyst: claim with code+output evidence", 0.7);
    FindingBundle::new(
        assertion,
        evidence,
        base_conditions(),
        confidence,
        base_provenance(label, ext),
        base_flags(),
    )
}

fn lift_experiment_intent(e: &MExperimentIntent, label: &str, ext: &str) -> FindingBundle {
    let evidence = Evidence {
        evidence_type: "experiment_intent".to_string(),
        model_system: String::new(),
        species: None,
        method: "code_analyst".to_string(),
        sample_size: None,
        effect_size: None,
        p_value: None,
        replicated: false,
        replication_count: None,
        evidence_spans: if e.hypothesis_link.is_empty() {
            Vec::new()
        } else {
            vec![serde_json::json!({ "hypothesis_link": e.hypothesis_link.clone() })]
        },
    };
    let assertion = Assertion {
        text: e.intent.clone(),
        assertion_type: "experiment_intent".to_string(),
        entities: Vec::new(),
        relation: None,
        direction: None,
        causal_claim: None,
        causal_evidence_grade: None,
    };
    let confidence = Confidence::raw(0.0, "code_analyst: proposed experiment, not yet run", 0.7);
    let mut flags = base_flags();
    flags.gap = true;
    FindingBundle::new(
        assertion,
        evidence,
        base_conditions(),
        confidence,
        base_provenance(label, ext),
        flags,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lift_analysis_uses_analysis_run_type() {
        let a = MAnalysis {
            purpose: "Group studies by intervention and compute mean effect_size".to_string(),
            dataset_or_input: "../data/bbb_studies.csv".to_string(),
            method: "pandas groupby + mean".to_string(),
            key_result: "TfR-shuttle 2.4, FUS 1.8, Mannitol 0.9".to_string(),
            files: vec!["analysis.py".to_string()],
        };
        let b = lift_analysis(&a, "analysis.py", "py");
        assert_eq!(b.assertion.assertion_type, "analysis_run");
        assert!(b.id.starts_with("vf_"));
        assert_eq!(b.provenance.source_type, "research_script");
    }

    #[test]
    fn lift_code_finding_attaches_code_and_output_spans() {
        let c = MCodeFinding {
            claim: "TfR-shuttle effect size is 33% larger than FUS".to_string(),
            derived_from: "analysis.py:line 4".to_string(),
            code_excerpt: r#"df.groupby("intervention")["effect_size"].mean()"#.to_string(),
            output_excerpt: "TfR-shuttle 2.4\nFUS 1.8\nMannitol 0.9".to_string(),
        };
        let b = lift_code_finding(&c, "analysis.py", "py");
        assert_eq!(b.assertion.assertion_type, "code_derived");
        assert_eq!(b.evidence.evidence_spans.len(), 2);
    }
}
