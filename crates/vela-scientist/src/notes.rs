//! # Notes Compiler (v0.23)
//!
//! Walks a folder of Markdown / Obsidian notes, extracts open
//! questions, hypotheses, candidate findings, and tensions, and
//! writes them into the target frontier as `finding.add`
//! `StateProposal`s tagged with the agent's `AgentRun`.
//!
//! The Notes Compiler complements Literature Scout: where Scout
//! reads the published literature, the Compiler reads what's in the
//! researcher's own head — the working notes that capture
//! intuitions, open puzzles, and bets in flight. Both feed the same
//! Inbox; reviewers see proposals from each grouped by their run.
//!
//! Scope discipline (v0.23):
//! * **Markdown only.** `.md` and `.markdown` files; recursive walk
//!   skips `.git`, `.obsidian`, `node_modules`, `target`, `dist`.
//! * **YAML frontmatter is parsed.** Any leading `---\n…\n---\n`
//!   block becomes part of the user prompt; the body follows.
//! * **Wikilinks captured.** `[[Note Name]]` references and
//!   standard `[text](url)` links are extracted into the prompt so
//!   the model can reason about cross-note structure.
//! * **One model call per note.** Each note → one `claude -p` call.
//! * **Always proposes, never applies.** Same as Literature Scout.

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

pub const AGENT_NOTES_COMPILER: &str = "notes-compiler";

/// Inputs to a single Notes Compiler run.
#[derive(Debug, Clone)]
pub struct NotesInput {
    /// Vault or folder of Markdown notes. Recursive walk; hidden
    /// dirs and `.git`/`.obsidian`/`node_modules`/`target`/`dist`
    /// skipped.
    pub vault: PathBuf,
    /// Frontier file the proposals will be appended to.
    pub frontier_path: PathBuf,
    /// Optional model alias (`sonnet`, `opus`, …). `None` lets the
    /// user's session pick.
    pub model: Option<String>,
    /// Path to the `claude` CLI. Defaults to `"claude"` on PATH.
    pub cli_command: String,
    /// When `false`, dry-run (no proposals persisted).
    pub apply: bool,
    /// Per-run cap on files processed. Default: 50. Prevents
    /// accidental quota blowups on huge vaults.
    pub max_files: Option<usize>,
    /// Per-note cap on items emitted in *each* category
    /// (open_questions, hypotheses, candidate_findings, tensions).
    /// Default: 4 — a busy 600-word note can yield 6+ open questions
    /// and 4+ hypotheses, drowning the Inbox; this trims to the
    /// strongest items the model returns. Friction #2 fix from sim-
    /// user pass.
    pub max_items_per_category: Option<usize>,
}

impl Default for NotesInput {
    fn default() -> Self {
        Self {
            vault: PathBuf::new(),
            frontier_path: PathBuf::new(),
            model: None,
            cli_command: "claude".to_string(),
            apply: true,
            max_files: Some(50),
            max_items_per_category: Some(4),
        }
    }
}

/// One file the Compiler skipped (with a human-readable reason).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkippedNote {
    pub path: String,
    pub reason: String,
}

/// Summary returned to the CLI / Workbench.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NotesReport {
    pub run: vela_protocol::proposals::AgentRun,
    pub vault: String,
    pub frontier_path: String,
    pub apply: bool,
    pub notes_seen: usize,
    pub notes_processed: usize,
    pub open_questions_emitted: usize,
    pub hypotheses_emitted: usize,
    pub candidate_findings_emitted: usize,
    pub tensions_emitted: usize,
    pub proposals_written: usize,
    pub skipped: Vec<SkippedNote>,
}

/// Top-level entry point.
pub async fn run(input: NotesInput) -> Result<NotesReport, String> {
    let extensions = ["md", "markdown"];
    let skip_dirs = [".git", ".obsidian", "node_modules", "target", "dist"];
    let mut notes = discover_files_recursive(&input.vault, &extensions, &skip_dirs)?;
    let total_seen = notes.len();
    if let Some(cap) = input.max_files
        && notes.len() > cap
    {
        notes.truncate(cap);
    }

    let mut frontier: Project = repo::load_from_path(&input.frontier_path)
        .map_err(|e| format!("load frontier {}: {e}", input.frontier_path.display()))?;

    let ctx = AgentContext::new(
        AGENT_NOTES_COMPILER,
        input.frontier_path.clone(),
        input.vault.clone(),
        input.model.clone(),
        input.cli_command.clone(),
    );
    let extra = BTreeMap::from([
        ("notes_seen".to_string(), total_seen.to_string()),
        ("notes_capped_to".to_string(), notes.len().to_string()),
    ]);
    let mut report = NotesReport {
        run: agent_run_meta(&ctx, extra),
        vault: input.vault.display().to_string(),
        frontier_path: input.frontier_path.display().to_string(),
        apply: input.apply,
        notes_seen: total_seen,
        ..Default::default()
    };

    let existing_finding_ids: HashSet<String> =
        frontier.findings.iter().map(|f| f.id.clone()).collect();
    let existing_proposal_ids: HashSet<String> =
        frontier.proposals.iter().map(|p| p.id.clone()).collect();

    let mut new_proposals: Vec<StateProposal> = Vec::new();

    for note_path in &notes {
        let label = note_path.display().to_string();
        let raw = match std::fs::read_to_string(note_path) {
            Ok(s) if !s.trim().is_empty() => s,
            Ok(_) => {
                report.skipped.push(SkippedNote {
                    path: label,
                    reason: "empty file".to_string(),
                });
                continue;
            }
            Err(e) => {
                report.skipped.push(SkippedNote {
                    path: label,
                    reason: format!("read failed: {e}"),
                });
                continue;
            }
        };

        let parsed = parse_note(&raw);
        let basename = note_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("note.md")
            .to_string();

        let mut model_output = match call_compiler(&parsed, &basename, &input) {
            Ok(v) => v,
            Err(e) => {
                report.skipped.push(SkippedNote {
                    path: label,
                    reason: format!("model call failed: {e}"),
                });
                continue;
            }
        };

        if let Some(cap) = input.max_items_per_category {
            model_output.open_questions.truncate(cap);
            model_output.hypotheses.truncate(cap);
            model_output.candidate_findings.truncate(cap);
            model_output.tensions.truncate(cap);
        }

        report.notes_processed += 1;

        for q in model_output.open_questions {
            let bundle = lift_open_question(&q, &basename);
            stage(
                &mut new_proposals,
                bundle,
                q.context,
                &basename,
                &existing_finding_ids,
                &existing_proposal_ids,
                &mut report.skipped,
                &ctx,
                &report.run,
            );
            report.open_questions_emitted += 1;
        }
        for h in model_output.hypotheses {
            let bundle = lift_hypothesis(&h, &basename);
            stage(
                &mut new_proposals,
                bundle,
                h.basis,
                &basename,
                &existing_finding_ids,
                &existing_proposal_ids,
                &mut report.skipped,
                &ctx,
                &report.run,
            );
            report.hypotheses_emitted += 1;
        }
        for c in model_output.candidate_findings {
            let bundle = lift_candidate_finding(&c, &basename);
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
            report.candidate_findings_emitted += 1;
        }
        for t in model_output.tensions {
            let bundle = lift_tension(&t, &basename);
            stage(
                &mut new_proposals,
                bundle,
                t.why,
                &basename,
                &existing_finding_ids,
                &existing_proposal_ids,
                &mut report.skipped,
                &ctx,
                &report.run,
            );
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

#[allow(clippy::too_many_arguments)]
fn stage(
    new_proposals: &mut Vec<StateProposal>,
    finding: FindingBundle,
    rationale: String,
    source_label: &str,
    existing_finding_ids: &HashSet<String>,
    existing_proposal_ids: &HashSet<String>,
    skipped: &mut Vec<SkippedNote>,
    ctx: &AgentContext,
    run: &vela_protocol::proposals::AgentRun,
) {
    if existing_finding_ids.contains(&finding.id) {
        skipped.push(SkippedNote {
            path: format!("{source_label}#{}", finding.id),
            reason: "finding id already in frontier".to_string(),
        });
        return;
    }
    let proposal = build_finding_add_proposal(&finding, ctx, source_label, &rationale, &[], run);
    if existing_proposal_ids.contains(&proposal.id) {
        skipped.push(SkippedNote {
            path: format!("{source_label}#{}", proposal.id),
            reason: "proposal id already in frontier".to_string(),
        });
        return;
    }
    new_proposals.push(proposal);
}

// ---------- Parser ----------

#[derive(Debug, Clone)]
struct ParsedNote {
    frontmatter: String, // verbatim block (may be empty)
    body: String,
    wikilinks: Vec<String>,
    md_links: Vec<(String, String)>, // (text, url)
}

fn parse_note(raw: &str) -> ParsedNote {
    let mut frontmatter = String::new();
    let body;
    if let Some(rest) = raw.strip_prefix("---\n")
        && let Some(end) = rest.find("\n---\n")
    {
        frontmatter = rest[..end].to_string();
        body = rest[end + 5..].to_string();
    } else {
        body = raw.to_string();
    }

    let wikilinks = extract_wikilinks(&body);
    let md_links = extract_md_links(&body);
    ParsedNote {
        frontmatter,
        body,
        wikilinks,
        md_links,
    }
}

fn extract_wikilinks(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'['
            && bytes[i + 1] == b'['
            && let Some(end) = text[i + 2..].find("]]")
        {
            let target = &text[i + 2..i + 2 + end];
            let display = target.split('|').next().unwrap_or(target).trim();
            if !display.is_empty() {
                out.push(display.to_string());
            }
            i = i + 2 + end + 2;
            continue;
        }
        i += 1;
    }
    out.sort();
    out.dedup();
    out
}

fn extract_md_links(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'['
            && let Some(close_text) = text[i + 1..].find(']')
        {
            let after = i + 1 + close_text + 1;
            if after < bytes.len()
                && bytes[after] == b'('
                && let Some(close_url) = text[after + 1..].find(')')
            {
                let label = text[i + 1..i + 1 + close_text].to_string();
                let url = text[after + 1..after + 1 + close_url].to_string();
                if !label.is_empty() && !url.is_empty() {
                    out.push((label, url));
                }
                i = after + 1 + close_url + 1;
                continue;
            }
        }
        i += 1;
    }
    out
}

// ---------- Model interface ----------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ModelOutput {
    #[serde(default)]
    open_questions: Vec<MOpenQuestion>,
    #[serde(default)]
    hypotheses: Vec<MHypothesis>,
    #[serde(default)]
    candidate_findings: Vec<MCandidateFinding>,
    #[serde(default)]
    tensions: Vec<MTension>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct MOpenQuestion {
    question: String,
    #[serde(default)]
    context: String,
    #[serde(default)]
    linked_notes: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct MHypothesis {
    statement: String,
    #[serde(default)]
    basis: String,
    #[serde(default)]
    predictions: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct MCandidateFinding {
    claim: String,
    #[serde(default)]
    evidence: String,
    #[serde(default)]
    source_notes: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct MTension {
    claim_a: String,
    claim_b: String,
    #[serde(default)]
    why: String,
}

fn call_compiler(
    parsed: &ParsedNote,
    basename: &str,
    input: &NotesInput,
) -> Result<ModelOutput, String> {
    let user_prompt = build_user_prompt(parsed, basename);
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
    r#"You are Notes Compiler, an extractor agent inside the Vela
scientific protocol. You read a researcher's working notes (a
single Markdown file at a time) and propose four kinds of
reviewable items as strict JSON, matching the provided JSON
Schema exactly:

  open_questions     — specific, testable scientific questions the
                       note raises but does not answer.
  hypotheses         — provisional statements with falsifiable
                       predictions.
  candidate_findings — claims the note treats as fact, with an
                       evidence quote from the note text.
  tensions           — explicit pairs of claims in disagreement,
                       with a one-sentence reason.

Rules:
1. Each item must be specific. "What is the role of X in Y?" is
   good; "study amyloid" is not.
2. A candidate_finding must include a near-verbatim quote from the
   note (≤300 chars) as `evidence`.
3. A hypothesis must include at least one falsifiable prediction.
4. A tension must explicitly cite both claims; do not invent
   disagreement that the note does not support.
5. Each category may be empty. Prefer 1–4 high-quality items per
   category over many vague ones.
6. Output the JSON object directly — no markdown fences, no prose."#
}

fn build_user_prompt(parsed: &ParsedNote, basename: &str) -> String {
    let body_trim: String = parsed.body.chars().take(10_000).collect();
    let mut prompt = format!("Source note: {basename}\n");
    if !parsed.frontmatter.is_empty() {
        prompt.push_str("\n--- frontmatter ---\n");
        prompt.push_str(&parsed.frontmatter);
        prompt.push('\n');
    }
    if !parsed.wikilinks.is_empty() {
        prompt.push_str("\n--- wikilinks ---\n");
        for w in &parsed.wikilinks {
            prompt.push_str(&format!("[[{w}]]\n"));
        }
    }
    if !parsed.md_links.is_empty() {
        prompt.push_str("\n--- markdown links ---\n");
        for (label, url) in &parsed.md_links {
            prompt.push_str(&format!("[{label}]({url})\n"));
        }
    }
    prompt.push_str("\n--- body ---\n");
    prompt.push_str(&body_trim);
    prompt.push_str("\n---\n\nReturn the JSON object.");
    prompt
}

fn output_schema_json() -> String {
    serde_json::json!({
        "type": "object",
        "properties": {
            "open_questions": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "question":     { "type": "string" },
                        "context":      { "type": "string" },
                        "linked_notes": { "type": "array", "items": { "type": "string" } }
                    },
                    "required": ["question"]
                }
            },
            "hypotheses": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "statement":   { "type": "string" },
                        "basis":       { "type": "string" },
                        "predictions": { "type": "array", "items": { "type": "string" } }
                    },
                    "required": ["statement"]
                }
            },
            "candidate_findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "claim":        { "type": "string" },
                        "evidence":     { "type": "string" },
                        "source_notes": { "type": "array", "items": { "type": "string" } }
                    },
                    "required": ["claim", "evidence"]
                }
            },
            "tensions": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "claim_a": { "type": "string" },
                        "claim_b": { "type": "string" },
                        "why":     { "type": "string" }
                    },
                    "required": ["claim_a", "claim_b"]
                }
            }
        }
    })
    .to_string()
}

// ---------- Lift helpers ----------

fn base_extraction() -> Extraction {
    Extraction {
        method: "notes_compiler_via_claude_cli".to_string(),
        model: None,
        model_version: None,
        extracted_at: chrono::Utc::now().to_rfc3339(),
        extractor_version: "vela-scientist::notes-compiler/v0.23".to_string(),
    }
}

fn base_provenance(label: &str) -> Provenance {
    Provenance {
        source_type: "researcher_notes".to_string(),
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

fn empty_evidence() -> Evidence {
    Evidence {
        evidence_type: "extracted_from_notes".to_string(),
        model_system: String::new(),
        species: None,
        method: "notes_compiler".to_string(),
        sample_size: None,
        effect_size: None,
        p_value: None,
        replicated: false,
        replication_count: None,
        evidence_spans: Vec::new(),
    }
}

fn lift_open_question(q: &MOpenQuestion, label: &str) -> FindingBundle {
    let mut evidence = empty_evidence();
    if !q.context.is_empty() {
        evidence.evidence_spans = vec![serde_json::json!({ "text": q.context.clone() })];
    }
    let assertion = Assertion {
        text: q.question.clone(),
        assertion_type: "open_question".to_string(),
        entities: Vec::new(),
        relation: None,
        direction: None,
        causal_claim: None,
        causal_evidence_grade: None,
    };
    let confidence = Confidence::raw(0.0, "notes_compiler: open question, no evidence yet", 0.7);
    FindingBundle::new(
        assertion,
        evidence,
        base_conditions(),
        confidence,
        base_provenance(label),
        base_flags(),
    )
}

fn lift_hypothesis(h: &MHypothesis, label: &str) -> FindingBundle {
    let mut evidence = empty_evidence();
    if !h.basis.is_empty() {
        evidence.evidence_spans = vec![serde_json::json!({ "text": h.basis.clone() })];
    }
    let predictions = if h.predictions.is_empty() {
        String::new()
    } else {
        format!(" Predictions: {}", h.predictions.join("; "))
    };
    let assertion = Assertion {
        text: format!("{}{predictions}", h.statement),
        assertion_type: "hypothesis".to_string(),
        entities: Vec::new(),
        relation: None,
        direction: None,
        causal_claim: None,
        causal_evidence_grade: None,
    };
    let confidence = Confidence::raw(
        0.4,
        "notes_compiler: provisional hypothesis with predictions",
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

fn lift_candidate_finding(c: &MCandidateFinding, label: &str) -> FindingBundle {
    let mut evidence = empty_evidence();
    if !c.evidence.is_empty() {
        evidence.evidence_spans = vec![serde_json::json!({ "text": c.evidence.clone() })];
    }
    let assertion = Assertion {
        text: c.claim.clone(),
        assertion_type: "candidate_finding".to_string(),
        entities: Vec::new(),
        relation: None,
        direction: None,
        causal_claim: None,
        causal_evidence_grade: None,
    };
    let confidence = Confidence::raw(
        0.5,
        "notes_compiler: candidate finding from researcher's notes",
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

fn lift_tension(t: &MTension, label: &str) -> FindingBundle {
    let evidence = empty_evidence();
    let mut flags = base_flags();
    flags.contested = true;
    let why = if t.why.is_empty() {
        String::new()
    } else {
        format!(" Why: {}", t.why)
    };
    let assertion = Assertion {
        text: format!("Tension: \"{}\" vs \"{}\".{why}", t.claim_a, t.claim_b),
        assertion_type: "tension".to_string(),
        entities: Vec::new(),
        relation: None,
        direction: None,
        causal_claim: None,
        causal_evidence_grade: None,
    };
    let confidence = Confidence::raw(0.0, "notes_compiler: tension surfaced for review", 0.7);
    FindingBundle::new(
        assertion,
        evidence,
        base_conditions(),
        confidence,
        base_provenance(label),
        flags,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_note_handles_frontmatter_and_links() {
        let raw = r#"---
title: BBB notes
tags: [bbb, focused-ultrasound]
---

# BBB delivery

See [[Lecanemab dosing]] for related work.
Compare to [Marston 2019](https://example.org/marston).
"#;
        let parsed = parse_note(raw);
        assert!(parsed.frontmatter.contains("title: BBB notes"));
        assert!(parsed.body.contains("# BBB delivery"));
        assert_eq!(parsed.wikilinks, vec!["Lecanemab dosing".to_string()]);
        assert_eq!(parsed.md_links.len(), 1);
        assert_eq!(parsed.md_links[0].0, "Marston 2019");
    }

    #[test]
    fn lift_open_question_uses_open_question_type() {
        let q = MOpenQuestion {
            question: "Why does X vary 10-fold across cohorts?".to_string(),
            context: "Observed in three cohorts so far".to_string(),
            linked_notes: vec![],
        };
        let b = lift_open_question(&q, "test.md");
        assert_eq!(b.assertion.assertion_type, "open_question");
        assert!(b.id.starts_with("vf_"));
    }
}
