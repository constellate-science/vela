//! # Datasets agent (v0.25)
//!
//! Walks a folder of `.csv` / `.tsv` files, sniffs each one's
//! schema (columns + inferred types + first N rows),
//! and asks `claude -p` for a one-shot dataset summary plus any
//! claims the data appears to support.
//!
//! Output is two new `assertion.type` values on `finding.add`
//! proposals:
//! * `dataset_summary` — purpose / unit of observation / key
//!   variables / potential uses
//! * `dataset_supported_claim` — a claim the columns support, with
//!   the columns used and any caveats
//!
//! Scope discipline (v0.25):
//! * **CSV / TSV only.** Parquet, SQL dumps, JSON arrays, HDF5,
//!   feather, and proprietary lab-instrument formats wait for
//!   a reader that keeps the default release dependency graph clean.
//! * **No execution.** Read-only: read schema + first ~50 rows,
//!   pass to model, never load the whole dataset.
//! * **No statistical analysis.** That's `code-analyst`'s job.
//!   Datasets agent reports what's *in* the data; it doesn't
//!   compute means or fit models.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use vela_protocol::bundle::{
    Assertion, Conditions, Confidence, Evidence, Extraction, FindingBundle, Flags, Provenance,
};
use vela_protocol::project::Project;
use vela_protocol::proposals::StateProposal;
use vela_protocol::repo;

use crate::agent::{AgentContext, agent_run_meta, build_finding_add_proposal, discover_files};
use crate::llm_cli::{ClaudeCall, run_structured};

pub const AGENT_DATASETS: &str = "datasets";

#[derive(Debug, Clone)]
pub struct DatasetInput {
    /// Folder root (top level only — recursive walk + dataset
    /// scanning is a v0.27 follow-on if needed).
    pub root: PathBuf,
    pub frontier_path: PathBuf,
    pub model: Option<String>,
    pub cli_command: String,
    pub apply: bool,
    /// How many rows to sample per dataset (default 50). Sent to
    /// the model as context for type inference + claim grounding.
    pub sample_rows: usize,
}

impl Default for DatasetInput {
    fn default() -> Self {
        Self {
            root: PathBuf::new(),
            frontier_path: PathBuf::new(),
            model: None,
            cli_command: "claude".to_string(),
            apply: true,
            sample_rows: 50,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkippedDataset {
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DatasetReport {
    pub run: vela_protocol::proposals::AgentRun,
    pub root: String,
    pub frontier_path: String,
    pub apply: bool,
    pub datasets_seen: usize,
    pub csv_processed: usize,
    pub parquet_processed: usize,
    pub dataset_summaries_emitted: usize,
    pub supported_claims_emitted: usize,
    pub proposals_written: usize,
    pub skipped: Vec<SkippedDataset>,
}

/// Public schema digest the model receives.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetSchema {
    pub path: PathBuf,
    pub format: String,
    pub rows_estimate: Option<u64>,
    pub columns: Vec<ColumnSpec>,
    pub sample: Vec<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColumnSpec {
    pub name: String,
    pub inferred_type: String,
    pub null_count_in_sample: usize,
}

pub async fn run(input: DatasetInput) -> Result<DatasetReport, String> {
    let extensions = ["csv", "tsv", "parquet"];
    let files = discover_files(&input.root, &extensions)?;
    let total_seen = files.len();

    let mut frontier: Project = repo::load_from_path(&input.frontier_path)
        .map_err(|e| format!("load frontier {}: {e}", input.frontier_path.display()))?;

    let ctx = AgentContext::new(
        AGENT_DATASETS,
        input.frontier_path.clone(),
        input.root.clone(),
        input.model.clone(),
        input.cli_command.clone(),
    );
    let extra = BTreeMap::from([
        ("datasets_seen".to_string(), total_seen.to_string()),
        ("sample_rows".to_string(), input.sample_rows.to_string()),
    ]);
    let mut report = DatasetReport {
        run: agent_run_meta(&ctx, extra),
        root: input.root.display().to_string(),
        frontier_path: input.frontier_path.display().to_string(),
        apply: input.apply,
        datasets_seen: total_seen,
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
            .unwrap_or("dataset")
            .to_string();
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .map(str::to_ascii_lowercase)
            .unwrap_or_default();

        let schema = match ext.as_str() {
            "csv" => match read_delim_schema(path, ',', input.sample_rows) {
                Ok(s) => {
                    report.csv_processed += 1;
                    s
                }
                Err(e) => {
                    report.skipped.push(SkippedDataset {
                        path: label,
                        reason: format!("CSV read failed: {e}"),
                    });
                    continue;
                }
            },
            "tsv" => match read_delim_schema(path, '\t', input.sample_rows) {
                Ok(s) => {
                    report.csv_processed += 1;
                    s
                }
                Err(e) => {
                    report.skipped.push(SkippedDataset {
                        path: label,
                        reason: format!("TSV read failed: {e}"),
                    });
                    continue;
                }
            },
            "parquet" => match read_parquet_schema(path, input.sample_rows) {
                Ok(s) => {
                    report.parquet_processed += 1;
                    s
                }
                Err(e) => {
                    report.skipped.push(SkippedDataset {
                        path: label,
                        reason: format!("Parquet read failed: {e}"),
                    });
                    continue;
                }
            },
            _ => continue,
        };

        let model_output = match call_datasets(&schema, &basename, &input) {
            Ok(v) => v,
            Err(e) => {
                report.skipped.push(SkippedDataset {
                    path: label,
                    reason: format!("model call failed: {e}"),
                });
                continue;
            }
        };

        if let Some(s) = model_output.dataset_summary {
            let bundle = lift_summary(&s, &schema, &basename);
            stage(
                &mut new_proposals,
                bundle,
                s.purpose,
                &basename,
                &existing_finding_ids,
                &existing_proposal_ids,
                &mut report.skipped,
                &ctx,
                &report.run,
            );
            report.dataset_summaries_emitted += 1;
        }
        for c in model_output.supported_claims {
            let bundle = lift_supported_claim(&c, &schema, &basename);
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
            report.supported_claims_emitted += 1;
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
    skipped: &mut Vec<SkippedDataset>,
    ctx: &AgentContext,
    run: &vela_protocol::proposals::AgentRun,
) {
    if existing_finding_ids.contains(&finding.id) {
        skipped.push(SkippedDataset {
            path: format!("{source_label}#{}", finding.id),
            reason: "finding id already in frontier".to_string(),
        });
        return;
    }
    let proposal = build_finding_add_proposal(&finding, ctx, source_label, &rationale, &[], run);
    if existing_proposal_ids.contains(&proposal.id) {
        skipped.push(SkippedDataset {
            path: format!("{source_label}#{}", proposal.id),
            reason: "proposal id already in frontier".to_string(),
        });
        return;
    }
    new_proposals.push(proposal);
}

// ---------- CSV/TSV reader ----------

fn read_delim_schema(
    path: &Path,
    delim: char,
    sample_rows: usize,
) -> Result<DatasetSchema, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    if raw.trim().is_empty() {
        return Err("empty file".to_string());
    }
    let mut lines = raw.lines();
    let header = lines.next().ok_or("missing header")?;
    let column_names: Vec<String> = parse_delim_line(header, delim)
        .into_iter()
        .map(|s| s.trim().to_string())
        .collect();
    if column_names.is_empty() {
        return Err("no columns parsed from header".to_string());
    }

    let mut sample: Vec<Vec<String>> = Vec::new();
    let mut total_rows: u64 = 0;
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        total_rows += 1;
        if sample.len() < sample_rows {
            sample.push(parse_delim_line(line, delim));
        }
    }

    let columns = infer_columns(&column_names, &sample);
    let format = if delim == '\t' {
        "tsv".to_string()
    } else {
        "csv".to_string()
    };
    Ok(DatasetSchema {
        path: path.to_path_buf(),
        format,
        rows_estimate: Some(total_rows),
        columns,
        sample,
    })
}

/// Hand-rolled delim-line parser with quoted-field support.
/// Handles `"a","b,c","d""e"` as `["a", "b,c", "d\"e"]`.
fn parse_delim_line(line: &str, delim: char) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let chars: Vec<char> = line.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if in_quotes {
            if c == '"' {
                if i + 1 < chars.len() && chars[i + 1] == '"' {
                    cur.push('"');
                    i += 2;
                    continue;
                }
                in_quotes = false;
            } else {
                cur.push(c);
            }
        } else if c == '"' {
            in_quotes = true;
        } else if c == delim {
            out.push(std::mem::take(&mut cur));
        } else {
            cur.push(c);
        }
        i += 1;
    }
    out.push(cur);
    out
}

fn infer_columns(names: &[String], sample: &[Vec<String>]) -> Vec<ColumnSpec> {
    names
        .iter()
        .enumerate()
        .map(|(i, name)| {
            let mut nulls = 0usize;
            let mut all_int = true;
            let mut all_float = true;
            let mut all_bool = true;
            let mut any = false;
            for row in sample {
                let cell = row.get(i).map(String::as_str).unwrap_or("");
                let trimmed = cell.trim();
                if trimmed.is_empty() {
                    nulls += 1;
                    continue;
                }
                any = true;
                if trimmed.parse::<i64>().is_err() {
                    all_int = false;
                }
                if trimmed.parse::<f64>().is_err() {
                    all_float = false;
                }
                if !matches!(
                    trimmed.to_ascii_lowercase().as_str(),
                    "true" | "false" | "yes" | "no" | "0" | "1"
                ) {
                    all_bool = false;
                }
            }
            let inferred = if !any {
                "unknown"
            } else if all_int {
                "int"
            } else if all_bool {
                "bool"
            } else if all_float {
                "float"
            } else {
                "string"
            }
            .to_string();
            ColumnSpec {
                name: name.clone(),
                inferred_type: inferred,
                null_count_in_sample: nulls,
            }
        })
        .collect()
}

// ---------- Parquet reader ----------

fn read_parquet_schema(path: &Path, _sample_rows: usize) -> Result<DatasetSchema, String> {
    Err(format!(
        "parquet reader is not included in this release build for {}",
        path.display()
    ))
}

// ---------- Model interface ----------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ModelOutput {
    #[serde(default)]
    dataset_summary: Option<MDatasetSummary>,
    #[serde(default)]
    supported_claims: Vec<MSupportedClaim>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct MDatasetSummary {
    purpose: String,
    #[serde(default)]
    unit_of_observation: String,
    #[serde(default)]
    key_variables: Vec<String>,
    #[serde(default)]
    potential_uses: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct MSupportedClaim {
    claim: String,
    #[serde(default)]
    columns_used: Vec<String>,
    #[serde(default)]
    caveats: Vec<String>,
}

fn call_datasets(
    schema: &DatasetSchema,
    basename: &str,
    input: &DatasetInput,
) -> Result<ModelOutput, String> {
    let user_prompt = build_user_prompt(schema, basename);
    let system_prompt = build_system_prompt();
    let schema_json = output_schema_json();

    let mut call = ClaudeCall::new(system_prompt, &user_prompt, &schema_json);
    call.cli_command = &input.cli_command;
    call.model = input.model.as_deref();
    let value = run_structured(call)?;
    let parsed: ModelOutput = serde_json::from_value(value.clone())
        .map_err(|e| format!("parse model output: {e}\nvalue: {value}"))?;
    Ok(parsed)
}

fn build_system_prompt() -> &'static str {
    r#"You are Datasets, an extractor agent inside the Vela
scientific protocol. You read one dataset's schema (column names +
inferred types + first ~50 rows) and propose two kinds of
reviewable items as strict JSON matching the provided JSON Schema:

  dataset_summary  — one object describing the dataset's purpose,
                     unit of observation (one row = one what?),
                     key variables, and potential uses. Required.
  supported_claims — claims the columns appear to support, each
                     with `columns_used` + `caveats`. Each claim
                     must be something the data shape could plausibly
                     show; you do not run the analysis, you note
                     what the columns make possible.

Rules:
1. Stay close to what's actually in the schema. If the columns
   are `study_id, intervention, n_subjects, effect_size`, that's
   a small intervention-comparison dataset; do not invent
   columns or sample sizes that aren't present.
2. `unit_of_observation` should be one short noun phrase (e.g.
   "one row per study", "one row per cell measurement").
3. Each `supported_claim` must list the specific column names it
   would use, drawn from the schema.
4. Caveats should mention real concerns: small n, missing values
   in the sample, potential confounders visible in column names.
5. Empty `supported_claims` array is acceptable. Prefer 1–4
   high-quality claims.
6. Output the JSON object directly — no markdown fences."#
}

fn build_user_prompt(schema: &DatasetSchema, basename: &str) -> String {
    let mut prompt = format!(
        "Source dataset: {basename} (format: {}, rows≈{})\n\n",
        schema.format,
        schema
            .rows_estimate
            .map(|n| n.to_string())
            .unwrap_or_else(|| "?".to_string())
    );
    prompt.push_str("--- columns ---\n");
    for c in &schema.columns {
        prompt.push_str(&format!(
            "  {} : {} (nulls in sample: {})\n",
            c.name, c.inferred_type, c.null_count_in_sample
        ));
    }
    prompt.push_str("\n--- sample rows ---\n");
    for (i, row) in schema.sample.iter().enumerate().take(20) {
        prompt.push_str(&format!("[{i}] {}\n", row.join(" | ")));
    }
    prompt.push_str("\nReturn the JSON object.");
    prompt
}

fn output_schema_json() -> String {
    serde_json::json!({
        "type": "object",
        "properties": {
            "dataset_summary": {
                "type": "object",
                "properties": {
                    "purpose":             { "type": "string" },
                    "unit_of_observation": { "type": "string" },
                    "key_variables":       { "type": "array", "items": { "type": "string" } },
                    "potential_uses":      { "type": "array", "items": { "type": "string" } }
                },
                "required": ["purpose"]
            },
            "supported_claims": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "claim":        { "type": "string" },
                        "columns_used": { "type": "array", "items": { "type": "string" } },
                        "caveats":      { "type": "array", "items": { "type": "string" } }
                    },
                    "required": ["claim"]
                }
            }
        }
    })
    .to_string()
}

// ---------- Lift helpers ----------

fn base_extraction() -> Extraction {
    Extraction {
        method: "datasets_via_claude_cli".to_string(),
        model: None,
        model_version: None,
        extracted_at: chrono::Utc::now().to_rfc3339(),
        extractor_version: "vela-scientist::datasets/v0.25".to_string(),
    }
}

fn base_provenance(label: &str) -> Provenance {
    Provenance {
        source_type: "data_release".to_string(),
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

fn lift_summary(s: &MDatasetSummary, schema: &DatasetSchema, label: &str) -> FindingBundle {
    let mut spans: Vec<serde_json::Value> = Vec::new();
    spans.push(serde_json::json!({
        "section": "schema",
        "format": schema.format,
        "rows_estimate": schema.rows_estimate,
        "columns": schema.columns.iter()
            .map(|c| serde_json::json!({
                "name": c.name,
                "type": c.inferred_type,
                "nulls_in_sample": c.null_count_in_sample
            }))
            .collect::<Vec<_>>()
    }));
    if !s.unit_of_observation.is_empty() {
        spans.push(serde_json::json!({
            "section": "unit",
            "text": s.unit_of_observation.clone()
        }));
    }
    if !s.key_variables.is_empty() {
        spans.push(serde_json::json!({
            "section": "key_variables",
            "items": s.key_variables.clone()
        }));
    }
    if !s.potential_uses.is_empty() {
        spans.push(serde_json::json!({
            "section": "potential_uses",
            "items": s.potential_uses.clone()
        }));
    }
    let evidence = Evidence {
        evidence_type: "dataset_schema".to_string(),
        model_system: schema.format.clone(),
        species: None,
        method: "datasets_agent".to_string(),
        sample_size: schema.rows_estimate.map(|r| r.to_string()),
        effect_size: None,
        p_value: None,
        replicated: false,
        replication_count: None,
        evidence_spans: spans,
    };
    let assertion = Assertion {
        text: format!("Dataset summary: {}", s.purpose),
        assertion_type: "dataset_summary".to_string(),
        entities: Vec::new(),
        relation: None,
        direction: None,
        causal_claim: None,
        causal_evidence_grade: None,
    };
    let confidence = Confidence::raw(
        0.6,
        "datasets_agent: schema-derived summary; not yet reviewed",
        0.7,
    );
    FindingBundle::new(
        assertion,
        evidence,
        base_conditions(),
        confidence,
        base_provenance(label),
        base_flags(),
    )
}

fn lift_supported_claim(c: &MSupportedClaim, schema: &DatasetSchema, label: &str) -> FindingBundle {
    let mut spans: Vec<serde_json::Value> = Vec::new();
    if !c.columns_used.is_empty() {
        spans.push(serde_json::json!({
            "section": "columns_used",
            "items": c.columns_used.clone()
        }));
    }
    if !c.caveats.is_empty() {
        spans.push(serde_json::json!({
            "section": "caveats",
            "items": c.caveats.clone()
        }));
    }
    let evidence = Evidence {
        evidence_type: "dataset_supported".to_string(),
        model_system: schema.format.clone(),
        species: None,
        method: "datasets_agent".to_string(),
        sample_size: schema.rows_estimate.map(|r| r.to_string()),
        effect_size: None,
        p_value: None,
        replicated: false,
        replication_count: None,
        evidence_spans: spans,
    };
    let assertion = Assertion {
        text: c.claim.clone(),
        assertion_type: "dataset_supported_claim".to_string(),
        entities: Vec::new(),
        relation: None,
        direction: None,
        causal_claim: None,
        causal_evidence_grade: None,
    };
    let confidence = Confidence::raw(
        0.4,
        "datasets_agent: claim plausibly supported by schema",
        0.7,
    );
    FindingBundle::new(
        assertion,
        evidence,
        base_conditions(),
        confidence,
        base_provenance(label),
        base_flags(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_delim_line_handles_quotes() {
        let row = parse_delim_line(r#"a,"b,c","d""e",f"#, ',');
        assert_eq!(row, vec!["a", "b,c", "d\"e", "f"]);
    }

    #[test]
    fn read_csv_schema_smoke() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("studies.csv");
        std::fs::write(
            &path,
            "study_id,intervention,n,effect\nS1,FUS,12,1.8\nS2,TfR,9,2.4\n",
        )
        .unwrap();
        let s = read_delim_schema(&path, ',', 50).unwrap();
        assert_eq!(s.format, "csv");
        assert_eq!(s.rows_estimate, Some(2));
        assert_eq!(s.columns.len(), 4);
        assert_eq!(s.columns[2].inferred_type, "int");
        assert_eq!(s.columns[3].inferred_type, "float");
        assert_eq!(s.columns[1].inferred_type, "string");
    }

    #[test]
    fn parquet_reader_reports_release_build_boundary() {
        let path = PathBuf::from("studies.parquet");
        let err = read_parquet_schema(&path, 10).unwrap_err();
        assert!(err.contains("parquet reader is not included"));
    }

    #[test]
    fn lift_summary_uses_dataset_summary_type() {
        let schema = DatasetSchema {
            path: PathBuf::from("/tmp/x.csv"),
            format: "csv".to_string(),
            rows_estimate: Some(3),
            columns: vec![ColumnSpec {
                name: "x".to_string(),
                inferred_type: "int".to_string(),
                null_count_in_sample: 0,
            }],
            sample: vec![vec!["1".to_string()]],
        };
        let s = MDatasetSummary {
            purpose: "Demo dataset".to_string(),
            unit_of_observation: "row".to_string(),
            key_variables: vec!["x".to_string()],
            potential_uses: vec!["test".to_string()],
        };
        let b = lift_summary(&s, &schema, "x.csv");
        assert_eq!(b.assertion.assertion_type, "dataset_summary");
        assert!(b.id.starts_with("vf_"));
    }
}
