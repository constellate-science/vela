//! # Literature Scout extractor — `claude -p` backend
//!
//! Shells out to the user's locally-installed `claude` CLI in
//! print-mode (one-shot, non-interactive) to ask the model to
//! extract candidate findings from a paper's plain text.
//!
//! Why not the existing `vela-protocol::ingest::ingest_text_via_llm`?
//! That path requires an `ANTHROPIC_API_KEY` (or another raw-API
//! provider env var). On a Pro/Max OAuth subscription there *is*
//! no API key — usage is metered against the user's Claude Code
//! session. Routing through `claude -p` reuses that session's
//! auth and quota, which is the doctrinally correct default for
//! v0.22: the scout runs in the same trust context as the user.
//!
//! What this is NOT: it's not a generic LLM client. It hard-codes
//! a focused Literature-Scout prompt and a strict output schema.
//! Other agents (Notes Compiler, Code Analyst) will get their own
//! extractors with their own prompts.

use std::path::Path;

use serde::{Deserialize, Serialize};
use vela_protocol::bundle::{
    Assertion, Conditions, Confidence, Evidence, Extraction, FindingBundle, Flags, Provenance,
};

use crate::llm_cli::{ClaudeCall, run_structured};

/// One candidate the model returned, before we lift it into a
/// `FindingBundle`. Mirrors the JSON schema we hand to `claude`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelCandidate {
    pub claim: String,
    #[serde(default)]
    pub assertion_type: String,
    #[serde(default)]
    pub rationale: String,
    #[serde(default)]
    pub evidence_snippet: String,
    #[serde(default)]
    pub scope: ModelScope,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModelScope {
    #[serde(default)]
    pub organism: String,
    #[serde(default)]
    pub disease_context: String,
    #[serde(default)]
    pub intervention: String,
}

/// Public entry point — one paper in, candidate findings out.
///
/// `model` is passed to `claude --model <model>`; `None` lets the
/// session's default model decide (cheapest sensible).
///
/// The function returns `(rationale_per_candidate, FindingBundle)`
/// pairs so the scout can attach the model's prose rationale to
/// the resulting `StateProposal.reason` field without losing the
/// FindingBundle's clean structure.
pub fn extract_via_claude_cli(
    text: &str,
    source_path: &Path,
    model: Option<&str>,
    cli_command: &str,
) -> Result<Vec<(String, FindingBundle)>, String> {
    let label = source_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("paper.pdf")
        .to_string();

    // Trim to ~12k chars (~3k tokens) — enough for an abstract +
    // intro + a few sections, well within Sonnet's window. The
    // existing legacy extractor caps at 8k chars; a slight bump
    // is safe with `claude` since the user is paying with their
    // session quota and the cost floor scales with model, not
    // input length.
    let trimmed: String = text.chars().take(12_000).collect();

    let user_prompt = build_user_prompt(&label, &trimmed);
    let system_prompt = build_system_prompt();
    let schema = output_schema_json();

    let mut call = ClaudeCall::new(&system_prompt, &user_prompt, &schema);
    call.cli_command = cli_command;
    call.model = model;
    let findings_value = run_structured(call)?;

    let arr = findings_value
        .get("findings")
        .and_then(|v| v.as_array())
        .cloned()
        .ok_or_else(|| format!("structured_output has no `findings` array: {findings_value}"))?;

    let mut out = Vec::new();
    for raw in arr {
        let candidate: ModelCandidate = serde_json::from_value(raw.clone())
            .map_err(|e| format!("parse model candidate: {e}\nvalue: {raw}"))?;
        let bundle = lift_to_bundle(&candidate, &label);
        out.push((candidate.rationale, bundle));
    }
    Ok(out)
}

fn build_system_prompt() -> String {
    r#"You are Literature Scout, an extractor agent inside the Vela
scientific protocol. Your job is to read a single paper's plain
text and propose candidate scientific findings as strict JSON,
matching the provided JSON Schema exactly.

Rules:
1. Each finding must be one specific, testable scientific claim —
   not a topic, not a paragraph summary. "X increases Y under
   condition Z" is good. "This paper studies X" is not.
2. Stay close to the paper. Do not generalize. Scope each claim
   tightly: the organism, disease context, and intervention used.
3. `evidence_snippet` must be a short verbatim or near-verbatim
   excerpt from the paper text (≤300 chars). It pins the claim to
   the source so a human reviewer can audit.
4. `rationale` is one short sentence explaining why this is a
   distinct finding worth proposing.
5. Prefer 1–4 high-quality candidates over many vague ones. Empty
   array is acceptable if no clean findings are extractable.
6. Output the JSON object directly, no markdown fences, no prose."#
        .to_string()
}

fn build_user_prompt(label: &str, text: &str) -> String {
    format!(
        "Source file: {label}\n\nPaper text follows. Extract candidate findings.\n\n---\n{text}\n---\n\nReturn the JSON object."
    )
}

fn output_schema_json() -> String {
    serde_json::json!({
        "type": "object",
        "properties": {
            "findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "claim": { "type": "string" },
                        "assertion_type": {
                            "type": "string",
                            "enum": [
                                "mechanism",
                                "therapeutic",
                                "methodological",
                                "observational"
                            ]
                        },
                        "rationale": { "type": "string" },
                        "evidence_snippet": { "type": "string" },
                        "scope": {
                            "type": "object",
                            "properties": {
                                "organism": { "type": "string" },
                                "disease_context": { "type": "string" },
                                "intervention": { "type": "string" }
                            }
                        }
                    },
                    "required": ["claim", "rationale", "evidence_snippet"]
                }
            }
        },
        "required": ["findings"]
    })
    .to_string()
}

/// Lift a model candidate into a `FindingBundle` with sane defaults.
/// The content-addressed `vf_…` id is computed from the assertion
/// text + type + provenance title so the same paper + same claim
/// yields the same id across runs.
fn lift_to_bundle(c: &ModelCandidate, label: &str) -> FindingBundle {
    let assertion_type = if c.assertion_type.is_empty() {
        "mechanism".to_string()
    } else {
        c.assertion_type.clone()
    };
    let assertion = Assertion {
        text: c.claim.clone(),
        assertion_type,
        entities: Vec::new(),
        relation: None,
        direction: None,
        causal_claim: None,
        causal_evidence_grade: None,
    };
    let evidence = Evidence {
        evidence_type: "extracted_from_paper".to_string(),
        model_system: c.scope.intervention.clone(),
        species: if c.scope.organism.is_empty() {
            None
        } else {
            Some(c.scope.organism.clone())
        },
        method: "literature_scout".to_string(),
        sample_size: None,
        effect_size: None,
        p_value: None,
        replicated: false,
        replication_count: None,
        evidence_spans: if c.evidence_snippet.is_empty() {
            Vec::new()
        } else {
            vec![serde_json::json!({ "text": c.evidence_snippet.clone() })]
        },
    };
    let conditions = Conditions {
        text: c.scope.disease_context.clone(),
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
        0.5,
        "literature_scout: extracted candidate; not yet reviewed",
        0.7,
    );
    let provenance = Provenance {
        source_type: "preprint_or_paper".to_string(),
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
        extraction: Extraction {
            method: "literature_scout_via_claude_cli".to_string(),
            model: None,
            model_version: None,
            extracted_at: chrono::Utc::now().to_rfc3339(),
            extractor_version: "vela-scientist/v0.22-1".to_string(),
        },
        review: None,
        citation_count: None,
    };
    let flags = Flags::default();
    FindingBundle::new(
        assertion, evidence, conditions, confidence, provenance, flags,
    )
}
