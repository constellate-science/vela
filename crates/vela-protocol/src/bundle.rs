//! Content-addressed finding bundles: the atomic object of the Vela protocol.

use std::collections::BTreeMap;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Valid entity types per schema. Single source of truth shared by the validator
/// and the `vela finding add` CLI; do not duplicate.
///
/// v0.10 added domain-neutral entries — `particle`, `instrument`, `dataset`,
/// `quantity` — surfaced by the first non-bio frontier on the public hub
/// (Nakamura's dark-matter constraints). The biology-leaning entries remain
/// for back-compat; the additions widen expressiveness without churn.
pub const VALID_ENTITY_TYPES: &[&str] = &[
    // bio (pre-v0.10)
    "gene",
    "protein",
    "compound",
    "disease",
    "cell_type",
    "organism",
    "pathway",
    "assay",
    "anatomical_structure",
    // domain-neutral (v0.10)
    "particle",
    "instrument",
    "dataset",
    "quantity",
    // escape valve
    "other",
];

/// Valid assertion types per schema.
///
/// v0.10 added `measurement` and `exclusion` for measurement-heavy domains
/// (physics, chemistry, climate, materials) where the substance of a
/// finding is a numerical value or an exclusion limit at a confidence level.
pub const VALID_ASSERTION_TYPES: &[&str] = &[
    "mechanism",
    "therapeutic",
    "diagnostic",
    "epidemiological",
    "observational",
    "review",
    "methodological",
    "computational",
    "theoretical",
    "negative",
    // v0.10
    "measurement",
    "exclusion",
    // v0.30: Notes Compiler emits these for proposals derived from
    // researcher zettelkasten / Obsidian vaults. They become canonical
    // findings on accept; rejecting them at the validator would force a
    // post-hoc rewrite that breaks content-addressed ids. The semantic
    // intent: `tension` = a theoretical claim about a field-level
    // contradiction (paired claims that don't reconcile); `open_question`
    // = an unresolved framing the agent surfaced; `hypothesis` = a
    // provisional candidate claim awaiting evidence. The notes-compiler
    // proposals doc covers how these are produced.
    "tension",
    "open_question",
    "hypothesis",
    "candidate_finding",
];

/// Valid artifact kinds for the generic `Artifact` kernel object.
///
/// `Dataset` and `CodeArtifact` remain as stronger, typed legacy objects.
/// `Artifact` is the shared substrate path for files and records that need
/// durable byte or pointer provenance before a domain-specific object exists.
pub const VALID_ARTIFACT_KINDS: &[&str] = &[
    "dataset",
    "clinical_trial_record",
    "protocol",
    "supplement",
    "notebook",
    "code",
    "model_output",
    "table",
    "figure",
    "registry_record",
    "lab_file",
    "source_file",
    "other",
];

pub fn valid_artifact_kind(kind: &str) -> bool {
    VALID_ARTIFACT_KINDS.contains(&kind)
}

/// Valid evidence types per schema.
pub const VALID_EVIDENCE_TYPES: &[&str] = &[
    "experimental",
    "observational",
    "computational",
    "theoretical",
    "meta_analysis",
    "systematic_review",
    "case_report",
    // v0.30: Notes Compiler — the evidence span lives in the researcher's
    // zettelkasten note rather than a primary literature passage.
    // Treated as an `expert_assertion`-shaped evidence kind.
    "extracted_from_notes",
];

/// Valid provenance source types per schema.
///
/// v0.10 added `data_release` for instrument runs, observation campaigns,
/// and dataset versions that are themselves the substantive object — distinct
/// from the paper that reports them (XENONnT SR0, Planck data releases,
/// JWST observation runs, LHC analysis releases).
pub const VALID_PROVENANCE_SOURCE_TYPES: &[&str] = &[
    "published_paper",
    "preprint",
    "clinical_trial",
    "lab_notebook",
    "model_output",
    "expert_assertion",
    "database_record",
    // v0.10
    "data_release",
    // v0.30: notes-compiler proposals cite the source markdown note
    // by filename. Distinct from `lab_notebook` (which implies a
    // dated lab workbook entry with primary observations) and
    // `expert_assertion` (which implies a named expert's claim).
    "researcher_notes",
];

/// Valid link types per protocol §5.
///
/// T7 (FrontierGraph substrate) extends the vocabulary with the
/// relation kinds the typed-edge layer reasons over. The conceptual
/// T7 set is SUPPORTS / CONTRADICTS / DEPENDS_ON / DERIVED_FROM /
/// IMPROVES / GENERALIZES / SPECIALIZES / SUPERSEDES; the existing
/// lowercase strings already cover DEPENDS_ON (`depends`) and
/// DERIVED_FROM (`synthesized_from`), so only the three genuinely new
/// concepts are added here. `extends` and `replicates` predate T7 and
/// stay. No redundant aliases — the FrontierGraph EdgeKind layer maps
/// strings to the canonical T7 vocabulary.
pub const VALID_LINK_TYPES: &[&str] = &[
    "supports",
    "contradicts",
    "extends",
    "depends",
    "replicates",
    "supersedes",
    "synthesized_from",
    // T7 additions:
    "improves",
    "generalizes",
    "specializes",
    // cross-domain transfer (vtr_):
    "discharges",
];

/// The local finding id of a link target, stripping any cross-frontier
/// `@vfr_…` suffix. A `vf_X@vfr_Y` target resolves to `vf_X`; a plain
/// `vf_X` is returned unchanged. Single source of truth for the
/// resolution the graph builders and read tools all rely on.
#[must_use]
pub fn bare_finding_id(target: &str) -> &str {
    target.split('@').next().unwrap_or(target)
}

/// A resolved identifier from a scientific database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedId {
    /// The database source (mesh, uniprot, pubchem, chebi, go, ncbi_gene).
    pub source: String,
    /// The identifier value (e.g., "D000544", "Q6ZSS7", "24752728").
    pub id: String,
    /// Confidence in this resolution (0.0-1.0).
    pub confidence: f64,
    /// The matched name in the source database.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_name: Option<String>,
}

/// How an entity was resolved to its canonical form (v0.2.0 schema).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionMethod {
    ExactMatch,
    FuzzyMatch,
    LlmInference,
    Manual,
}

impl std::fmt::Display for ResolutionMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolutionMethod::ExactMatch => write!(f, "exact_match"),
            ResolutionMethod::FuzzyMatch => write!(f, "fuzzy_match"),
            ResolutionMethod::LlmInference => write!(f, "llm_inference"),
            ResolutionMethod::Manual => write!(f, "manual"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entity {
    pub name: String,
    #[serde(rename = "type")]
    pub entity_type: String,
    /// Deprecated: flat identifiers map. Retained for backward compatibility with
    /// older frontier JSON files. New code should use `canonical_id` and `candidates`.
    #[serde(default)]
    pub identifiers: serde_json::Map<String, serde_json::Value>,
    /// The primary resolved identifier (if resolved).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical_id: Option<ResolvedId>,
    /// Alternative resolution candidates with scores.
    #[serde(default)]
    pub candidates: Vec<ResolvedId>,
    /// Known aliases for this entity (e.g., NLRP3 = cryopyrin = NALP3).
    #[serde(default)]
    pub aliases: Vec<String>,
    /// How this resolution was performed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution_provenance: Option<String>,
    #[serde(default = "default_one")]
    pub resolution_confidence: f64,
    /// How the entity was resolved: exact_match, fuzzy_match, llm_inference, manual.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution_method: Option<ResolutionMethod>,
    /// Species context for orthologs (e.g., "Homo sapiens" vs "Mus musculus" for APP).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub species_context: Option<String>,
    /// True when resolution_confidence < 0.8 and the match needs human review.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub needs_review: bool,
}

fn default_one() -> f64 {
    1.0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    #[serde(rename = "type")]
    pub evidence_type: String,
    #[serde(default)]
    pub model_system: String,
    pub species: Option<String>,
    #[serde(default)]
    pub method: String,
    pub sample_size: Option<String>,
    pub effect_size: Option<String>,
    pub p_value: Option<String>,
    #[serde(default)]
    pub replicated: bool,
    pub replication_count: Option<u32>,
    #[serde(default)]
    pub evidence_spans: Vec<serde_json::Value>,
}

/// v0.33: Dataset as a first-class kernel object.
///
/// A `Dataset` is a versioned, content-addressed reference to data
/// that anchors empirical claims. Before v0.33, datasets were strings
/// in `Provenance.title` or entity-typed mentions in assertions —
/// a claim could say "we used ADNI" without anchoring which release
/// of ADNI the analysis ran against, and re-running the same code on
/// a refreshed cohort silently produced a "different" claim.
///
/// `vd_<id>` is content-addressed over `name + version + content_hash
/// + url`. Two dataset records with the same name but different
/// versions get distinct ids; two records pointing at the same
/// snapshot collapse to the same id. Claims can reference the exact
/// bytes they rest on, not only a dataset name in prose.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dataset {
    /// `vd_<16hex>`, content-addressed; see `Dataset::content_address`.
    pub id: String,
    /// Human-readable name (e.g. "ADNI", "TRAILBLAZER-ALZ", "MIMIC-IV").
    pub name: String,
    /// Semantic version or release tag (e.g. "ADNI-3", "v2.2", "SR0").
    /// Two entries differing only in version are distinct kernel objects.
    pub version: Option<String>,
    /// Optional column-level schema as `(name, type)` pairs. For
    /// non-tabular datasets, leave empty.
    #[serde(default)]
    pub schema: Vec<(String, String)>,
    /// Number of rows / observations / records, when known.
    pub row_count: Option<u64>,
    /// SHA-256 of the canonical contents, when computable. For
    /// large datasets stored remotely, this is the publisher's
    /// declared content hash; integrity verification is the puller's
    /// job (same pattern as `vfr_*` snapshots).
    pub content_hash: String,
    /// Where the dataset is reachable (https URL, file://, s3://, etc.).
    pub url: Option<String>,
    /// License identifier or URL (e.g. "CC-BY-4.0", a Crossref license).
    pub license: Option<String>,
    /// Provenance of the dataset itself — typically the paper or release
    /// that publishes it. Reuses `Provenance` for shape parity with
    /// findings.
    pub provenance: Provenance,
    /// RFC 3339 creation timestamp.
    pub created: String,
}

impl Dataset {
    /// Compute the content-addressed ID per v0.33 spec:
    /// `SHA-256(name | version | content_hash | url)`.
    /// Returns first 16 hex chars prefixed with "vd_".
    pub fn content_address(
        name: &str,
        version: Option<&str>,
        content_hash: &str,
        url: Option<&str>,
    ) -> String {
        let preimage = format!(
            "{}|{}|{}|{}",
            name,
            version.unwrap_or(""),
            content_hash,
            url.unwrap_or("")
        );
        let hash = Sha256::digest(preimage.as_bytes());
        format!("vd_{}", &hex::encode(hash)[..16])
    }

    /// Construct a new Dataset with a freshly-derived id and `created`
    /// timestamp set to now.
    pub fn new(
        name: impl Into<String>,
        version: Option<String>,
        content_hash: impl Into<String>,
        url: Option<String>,
        license: Option<String>,
        provenance: Provenance,
    ) -> Self {
        let n = name.into();
        let h = content_hash.into();
        let id = Self::content_address(&n, version.as_deref(), &h, url.as_deref());
        Self {
            id,
            name: n,
            version,
            schema: Vec::new(),
            row_count: None,
            content_hash: h,
            url,
            license,
            provenance,
            created: Utc::now().to_rfc3339(),
        }
    }
}

/// v0.33: CodeArtifact as a first-class kernel object.
///
/// A `CodeArtifact` is a content-addressed pointer at a specific
/// region of source code (a function, a notebook cell, a script, a
/// pipeline step) at a specific git commit. Before v0.33, code was
/// captured as a string in `Evidence.method` — "we ran a logistic
/// regression" — with no way for a reader to verify which code
/// produced the result, or to re-run it.
///
/// `vc_<id>` is content-addressed over `repo_url + git_commit + path
/// + line_range + content_hash`. The same code at two commits gets
/// two records (the relevant historical fact); the same code in two
/// paths in the same repo also gets two records (location matters
/// for re-execution).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeArtifact {
    /// `vc_<16hex>`, content-addressed; see `CodeArtifact::content_address`.
    pub id: String,
    /// Source language: `python` / `r` / `julia` / `rust` / `bash`,
    /// etc. Not validated against a closed allow-list — code provenance
    /// should accept whatever language the analysis was actually in.
    pub language: String,
    /// Repository URL (e.g. `https://github.com/constellate-science/vela`).
    pub repo_url: Option<String>,
    /// Specific git commit (40-char SHA preferred). Required for
    /// reproducibility; `None` means "unpinned" and weakens the
    /// substrate claim.
    pub git_commit: Option<String>,
    /// Path within the repository (e.g. `crates/vela-scientist/src/notes.rs`).
    pub path: String,
    /// Optional line range as `(start, end)`, both inclusive.
    pub line_range: Option<(u32, u32)>,
    /// SHA-256 of the snippet body. Decouples the artifact from the
    /// repository's external state — even if a repo is deleted, the
    /// content_hash remains anchored.
    pub content_hash: String,
    /// Optional entry point: function name, notebook cell id, or
    /// `__main__`. Used by re-execution tooling.
    pub entry_point: Option<String>,
    /// RFC 3339 creation timestamp.
    pub created: String,
}

impl CodeArtifact {
    /// Compute the content-addressed ID per v0.33 spec:
    /// `SHA-256(repo_url | git_commit | path | line_range | content_hash)`.
    /// Returns first 16 hex chars prefixed with "vc_".
    pub fn content_address(
        repo_url: Option<&str>,
        git_commit: Option<&str>,
        path: &str,
        line_range: Option<(u32, u32)>,
        content_hash: &str,
    ) -> String {
        let lr = line_range
            .map(|(a, b)| format!("{a}-{b}"))
            .unwrap_or_default();
        let preimage = format!(
            "{}|{}|{}|{}|{}",
            repo_url.unwrap_or(""),
            git_commit.unwrap_or(""),
            path,
            lr,
            content_hash
        );
        let hash = Sha256::digest(preimage.as_bytes());
        format!("vc_{}", &hex::encode(hash)[..16])
    }

    /// Construct a new CodeArtifact with a freshly-derived id and
    /// `created` timestamp.
    pub fn new(
        language: impl Into<String>,
        repo_url: Option<String>,
        git_commit: Option<String>,
        path: impl Into<String>,
        line_range: Option<(u32, u32)>,
        content_hash: impl Into<String>,
        entry_point: Option<String>,
    ) -> Self {
        let p = path.into();
        let h = content_hash.into();
        let id = Self::content_address(
            repo_url.as_deref(),
            git_commit.as_deref(),
            &p,
            line_range,
            &h,
        );
        Self {
            id,
            language: language.into(),
            repo_url,
            git_commit,
            path: p,
            line_range,
            content_hash: h,
            entry_point,
            created: Utc::now().to_rfc3339(),
        }
    }
}

/// Generic content-addressed artifact.
///
/// This is the common substrate object for records and files that are not
/// only papers: trial registry snapshots, protocols, supplements, notebooks,
/// tables, figures, model outputs, lab files, and dataset manifests. Typed
/// objects such as `Dataset` and `CodeArtifact` still exist because they
/// carry stronger domain-specific fields. `Artifact` gives every byte or
/// pointer the same minimum durability contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    /// `va_<16hex>`, content-addressed over kind, name, hash, source, and
    /// locator.
    pub id: String,
    /// One of `VALID_ARTIFACT_KINDS`.
    pub kind: String,
    /// Human-readable label.
    pub name: String,
    /// SHA-256 commitment. Convention: `sha256:<64hex>`.
    pub content_hash: String,
    /// Byte count when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
    /// MIME type or close equivalent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    /// `local_blob`, `local_file`, `remote`, or `pointer`.
    pub storage_mode: String,
    /// Local relative path, file path, HTTPS URL, S3 URL, or registry locator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locator: Option<String>,
    /// Original upstream URL or accession, distinct from a mirrored blob path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_url: Option<String>,
    /// License identifier, URL, or access terms note.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    /// Findings this artifact directly bears on.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub target_findings: Vec<String>,
    /// Pointer to the source record that described this artifact, if one
    /// already exists in `sources`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
    /// Artifact-level provenance. The source record may be a registry,
    /// repository, dataset portal, protocol page, or paper.
    pub provenance: Provenance,
    /// Structured adapter metadata such as NCT id, outcomes, accession ids,
    /// version tags, or retrieval timestamps.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, Value>,
    /// Review lifecycle for the artifact itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_state: Option<ReviewState>,
    #[serde(default)]
    pub retracted: bool,
    #[serde(default)]
    pub access_tier: crate::access_tier::AccessTier,
    /// RFC 3339 creation timestamp.
    pub created: String,
}

impl Artifact {
    pub fn content_address(
        kind: &str,
        name: &str,
        content_hash: &str,
        source_url: Option<&str>,
        locator: Option<&str>,
    ) -> String {
        let preimage = format!(
            "{}|{}|{}|{}|{}",
            kind,
            name,
            content_hash,
            source_url.unwrap_or(""),
            locator.unwrap_or("")
        );
        let hash = Sha256::digest(preimage.as_bytes());
        format!("va_{}", &hex::encode(hash)[..16])
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: impl Into<String>,
        name: impl Into<String>,
        content_hash: impl Into<String>,
        size_bytes: Option<u64>,
        media_type: Option<String>,
        storage_mode: impl Into<String>,
        locator: Option<String>,
        source_url: Option<String>,
        license: Option<String>,
        target_findings: Vec<String>,
        provenance: Provenance,
        metadata: BTreeMap<String, Value>,
        access_tier: crate::access_tier::AccessTier,
    ) -> Result<Self, String> {
        let kind = kind.into();
        if !valid_artifact_kind(&kind) {
            return Err(format!(
                "artifact kind '{kind}' is not supported; valid: {}",
                VALID_ARTIFACT_KINDS.join(", ")
            ));
        }
        let name = name.into();
        if name.trim().is_empty() {
            return Err("artifact name must be non-empty".to_string());
        }
        let content_hash = normalize_sha256(content_hash.into())?;
        let storage_mode = storage_mode.into();
        if !matches!(
            storage_mode.as_str(),
            "local_blob" | "local_file" | "remote" | "pointer"
        ) {
            return Err(format!(
                "artifact storage_mode '{storage_mode}' is not supported; valid: local_blob, local_file, remote, pointer"
            ));
        }
        let id = Self::content_address(
            &kind,
            &name,
            &content_hash,
            source_url.as_deref(),
            locator.as_deref(),
        );
        Ok(Self {
            id,
            kind,
            name,
            content_hash,
            size_bytes,
            media_type,
            storage_mode,
            locator,
            source_url,
            license,
            target_findings,
            source_id: None,
            provenance,
            metadata,
            review_state: None,
            retracted: false,
            access_tier,
            created: Utc::now().to_rfc3339(),
        })
    }
}

fn normalize_sha256(value: String) -> Result<String, String> {
    let trimmed = value.trim();
    let hex = trimmed.strip_prefix("sha256:").unwrap_or(trimmed);
    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!(
            "content_hash must be sha256:<64hex> or 64 hex chars, got {trimmed:?}"
        ));
    }
    Ok(format!("sha256:{}", hex.to_ascii_lowercase()))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Conditions {
    #[serde(default)]
    pub text: String,
    #[serde(default)]
    pub species_verified: Vec<String>,
    #[serde(default)]
    pub species_unverified: Vec<String>,
    #[serde(default)]
    pub in_vitro: bool,
    #[serde(default)]
    pub in_vivo: bool,
    #[serde(default)]
    pub human_data: bool,
    #[serde(default)]
    pub clinical_trial: bool,
    pub concentration_range: Option<String>,
    pub duration: Option<String>,
    pub age_group: Option<String>,
    pub cell_type: Option<String>,
}

/// Structured breakdown of frontier epistemic confidence (v0.2.0).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceComponents {
    /// Derived from evidence.type (meta_analysis=0.95, systematic_review=0.90,
    /// experimental=0.80, observational=0.65, computational=0.55, case_report=0.40,
    /// theoretical=0.30).
    #[serde(alias = "evidence_grade")]
    pub evidence_strength: f64,
    /// 1.0 if replicated with high count, 0.7 if not replicated.
    /// When replicated: min(1.0, 0.7 + 0.1 * replication_count).
    #[serde(alias = "replication_factor")]
    pub replication_strength: f64,
    /// Derived from sample_size: >1000 -> 1.0, >100 -> 0.9, >30 -> 0.8,
    /// >10 -> 0.7, <=10 or null -> 0.6.
    pub sample_strength: f64,
    /// human_data=1.0, in_vivo=0.8, in_vitro=0.6, else=0.5.
    #[serde(alias = "species_relevance")]
    pub model_relevance: f64,
    /// Reduces score when finding is contested. 0.15 if contested, else 0.0.
    #[serde(alias = "contradiction_penalty")]
    pub review_penalty: f64,
    /// Additive calibration signal layered on top of the deterministic support score.
    #[serde(default)]
    pub calibration_adjustment: f64,
    /// v0.38.1: causal-claim × evidence-grade compatibility multiplier.
    /// Defaults to 1.0 — neutral — when either field is `None` (the
    /// pre-v0.38 case). RCT bumps any claim slightly; an observational-
    /// grade *intervention* claim gets a meaningful penalty (the
    /// design doesn't actually support the claim being made).
    #[serde(default = "default_causal_consistency")]
    pub causal_consistency: f64,
    /// Confidence formula version stamp. v0.3 introduced this; v0.4
    /// bumps it to "v0.4" for the same scoring formula recomputed
    /// against substrate-level changes (genesis events, signed actors,
    /// canonical/derived split — none of which alter scoring math).
    /// v0.38.1 bumps to "v0.7" for the addition of `causal_consistency`.
    /// A second implementation may refuse to interpret components
    /// computed with an unknown formula version.
    #[serde(default = "default_formula_version")]
    pub formula_version: String,
}

fn default_causal_consistency() -> f64 {
    1.0
}

fn default_formula_version() -> String {
    "v0.8".to_string()
}

/// Confidence method: how the score was determined.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum ConfidenceMethod {
    /// Computed from structured frontier support components (v0.2.0).
    Computed,
    /// A human expert assigned it.
    ExpertJudgment,
    /// Legacy import path for confidence seeded before component breakdown existed.
    #[default]
    LlmInitial,
}

/// Semantic category of the confidence score stored on the frontier.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ConfidenceKind {
    /// Bounded epistemic support for the finding as currently represented in frontier state.
    #[default]
    FrontierEpistemic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Confidence {
    /// Semantic meaning of `score`. v0 emits `frontier_epistemic`.
    #[serde(default)]
    pub kind: ConfidenceKind,
    pub score: f64,
    pub basis: String,
    /// How this score was determined.
    #[serde(default)]
    pub method: ConfidenceMethod,
    /// Structured component breakdown required by the current schema.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub components: Option<ConfidenceComponents>,
    /// Confidence in the extraction itself (separate from scientific confidence).
    #[serde(default = "default_extraction_conf")]
    pub extraction_confidence: f64,
}

fn default_extraction_conf() -> f64 {
    0.85
}

impl Confidence {
    /// Construct a `Confidence` with a raw score and basis string but
    /// without the structured `components` breakdown. The agent layer
    /// uses this when an LLM produces a single confidence value; the
    /// computed deterministic components arrive later via
    /// `compute_confidence`.
    ///
    /// Renamed from `legacy()` in v0.36; the previous name was a
    /// historical accident (the constructor was never actually
    /// deprecated, just misnamed when the structured components shipped
    /// alongside it).
    pub fn raw(score: f64, basis: impl Into<String>, extraction_confidence: f64) -> Self {
        Self {
            kind: ConfidenceKind::FrontierEpistemic,
            score,
            basis: basis.into(),
            method: ConfidenceMethod::LlmInitial,
            components: None,
            extraction_confidence,
        }
    }
}

/// Compute frontier epistemic confidence from evidence and condition fields.
/// Returns a fully populated Confidence with components and aggregate score,
/// using a deterministic, auditable support computation.
///
/// Back-compat wrapper: derives `n_replicated` from the legacy
/// `Evidence.replicated` / `Evidence.replication_count` scalars, with
/// `n_failed` and `n_partial` defaulting to zero. Use
/// `Project::compute_confidence_for` when the v0.32 `Replication`
/// collection is available — that's the authoritative path.
pub fn compute_confidence(
    evidence: &Evidence,
    conditions: &Conditions,
    contested: bool,
) -> Confidence {
    let n_replicated = if evidence.replicated {
        evidence.replication_count.unwrap_or(1)
    } else {
        0
    };
    compute_confidence_from_components(
        evidence,
        conditions,
        contested,
        n_replicated,
        0,
        0,
        None,
        None,
    )
}

/// v0.38.1: causal-claim × evidence-grade compatibility multiplier.
/// An RCT supports any claim slightly better than baseline; an
/// observational study weakly supports correlation; an *intervention*
/// claim from observational data gets a meaningful penalty (the
/// design doesn't actually identify the causal effect being claimed).
/// Returns `1.0` when either field is `None` — the pre-v0.38 case is
/// neutral.
#[must_use]
pub fn causal_consistency_multiplier(
    claim: Option<CausalClaim>,
    grade: Option<CausalEvidenceGrade>,
) -> f64 {
    use CausalClaim::*;
    use CausalEvidenceGrade::*;
    let (Some(c), Some(g)) = (claim, grade) else {
        return 1.0;
    };
    match (c, g) {
        // RCT: gold standard. Slight bump for any claim it supports.
        (_, Rct) => 1.10,
        // Correlation: any reasonable design supports it.
        (Correlation, _) => 1.0,
        // Mediation: needs design that handles confounders.
        (Mediation, QuasiExperimental) => 1.05,
        (Mediation, Observational) => 0.85,
        (Mediation, Theoretical) => 0.90,
        // Intervention: the strongest claim. Without RCT or strong
        // QE, the design under-supports the assertion.
        (Intervention, QuasiExperimental) => 0.90,
        (Intervention, Observational) => 0.65,
        (Intervention, Theoretical) => 0.75,
    }
}

/// Pure-math kernel for the frontier-epistemic confidence formula. Takes
/// replication counts and (v0.38.1) the optional causal typing as inputs
/// so the same math drives both the legacy scalar path
/// (`compute_confidence`) and the v0.32+ Project-aware path
/// (`Project::compute_confidence_for`).
///
/// Replication strength schedule:
/// `clamp(0.7 + 0.1 * n_replicated + 0.05 * n_partial - 0.10 * n_failed, 0.4, 1.0)`
///
/// Floor at 0.4 keeps a single failed replication from zeroing out the
/// computation; ceiling at 1.0 caps the bonus from accumulated successes.
/// `inconclusive` outcomes do not move the score (deliberate — they
/// represent methodological ambiguity, not evidence).
///
/// v0.38.1: a `causal_consistency` factor multiplies the support
/// product. `None` for either field is neutral (pre-v0.38 frontiers
/// behave identically). See `causal_consistency_multiplier`.
#[must_use]
pub fn compute_confidence_from_components(
    evidence: &Evidence,
    _conditions: &Conditions,
    contested: bool,
    n_replicated: u32,
    n_failed: u32,
    n_partial: u32,
    causal_claim: Option<CausalClaim>,
    causal_evidence_grade: Option<CausalEvidenceGrade>,
) -> Confidence {
    let evidence_strength = match evidence.evidence_type.as_str() {
        "meta_analysis" => 0.95,
        "systematic_review" => 0.90,
        "experimental" => 0.80,
        "observational" => 0.65,
        "computational" => 0.55,
        "case_report" => 0.40,
        "theoretical" => 0.30,
        _ => 0.50,
    };

    let replication_strength = (0.7 + 0.1 * f64::from(n_replicated) + 0.05 * f64::from(n_partial)
        - 0.10 * f64::from(n_failed))
    .clamp(0.4, 1.0);

    // v0.701: math-native core. The empirical sample-size and
    // model-relevance signals (clinical `Conditions`, sample sizes) are
    // not part of a math finding, so these collapse to the domain-neutral
    // baseline the all-default branch always produced. The fields they
    // read are removed from the schema in the A5 migration.
    let sample_strength = 0.6;
    let model_relevance = 0.5;

    let review_penalty = if contested { 0.15 } else { 0.0 };
    let calibration_adjustment = 0.0;
    let causal_consistency = causal_consistency_multiplier(causal_claim, causal_evidence_grade);

    let raw = evidence_strength
        * replication_strength
        * model_relevance
        * sample_strength
        * causal_consistency
        - review_penalty
        + calibration_adjustment;
    let score = raw.clamp(0.0, 1.0);
    let score = (score * 1000.0).round() / 1000.0;

    let components = ConfidenceComponents {
        evidence_strength,
        replication_strength,
        sample_strength,
        model_relevance,
        review_penalty,
        calibration_adjustment,
        causal_consistency,
        formula_version: "v0.7".to_string(),
    };

    let basis = format!(
        "frontier_epistemic: evidence={:.2} * replication={:.2} * model={:.2} * sample={:.2} * causal={:.2} - review_penalty={:.2} + calibration={:.2} = {:.3}",
        evidence_strength,
        replication_strength,
        model_relevance,
        sample_strength,
        causal_consistency,
        review_penalty,
        calibration_adjustment,
        score,
    );

    Confidence {
        kind: ConfidenceKind::FrontierEpistemic,
        score,
        basis,
        method: ConfidenceMethod::Computed,
        components: Some(components),
        extraction_confidence: default_extraction_conf(),
    }
}

/// Recompute confidence scores for all findings in a slice. Returns the
/// number of findings whose score changed by more than 0.001. Replication
/// counts derive from the scalar `Evidence.replicated` /
/// `Evidence.replication_count` fields.
pub fn recompute_all_confidence(findings: &mut [FindingBundle]) -> usize {
    let mut changed = 0;
    for bundle in findings.iter_mut() {
        let old_score = bundle.confidence.score;
        let extraction_conf = bundle.confidence.extraction_confidence;
        // Replication counts derive from the legacy scalar `Evidence`
        // fields (`replicated` / `replication_count`).
        let (n_repl, n_failed, n_partial) = if bundle.evidence.replicated {
            (bundle.evidence.replication_count.unwrap_or(1), 0, 0)
        } else {
            (0, 0, 0)
        };
        let mut new_conf = compute_confidence_from_components(
            &bundle.evidence,
            &bundle.conditions,
            bundle.flags.contested,
            n_repl,
            n_failed,
            n_partial,
            bundle.assertion.causal_claim,
            bundle.assertion.causal_evidence_grade,
        );
        // Preserve the extraction confidence from the original extraction.
        new_conf.extraction_confidence = extraction_conf;
        if (new_conf.score - old_score).abs() > 0.001 {
            changed += 1;
        }
        bundle.confidence = new_conf;
    }
    changed
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Extraction {
    #[serde(default = "default_extraction_method")]
    pub method: String,
    pub model: Option<String>,
    pub model_version: Option<String>,
    #[serde(default)]
    pub extracted_at: String,
    #[serde(default = "default_extractor_version")]
    pub extractor_version: String,
}

fn default_extraction_method() -> String {
    "llm_extraction".into()
}
fn default_extractor_version() -> String {
    "vela/0.2.0".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Review {
    #[serde(default)]
    pub reviewed: bool,
    pub reviewer: Option<String>,
    pub reviewed_at: Option<String>,
    #[serde(default)]
    pub corrections: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Author {
    pub name: String,
    pub orcid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provenance {
    #[serde(default = "default_source_type")]
    pub source_type: String,
    pub doi: Option<String>,
    pub pmid: Option<String>,
    pub pmc: Option<String>,
    pub openalex_id: Option<String>,
    /// v0.11: generic source URL when none of the structured identifiers
    /// fit (preprint server URL, dataset landing page, talk recording, etc.).
    /// Skipped when None so pre-v0.11 frontiers serialise byte-identically.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub authors: Vec<Author>,
    pub year: Option<i32>,
    pub journal: Option<String>,
    /// License URL (e.g., Creative Commons), typically from Crossref.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    /// Publisher name, typically from Crossref.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publisher: Option<String>,
    /// Funding sources, typically from Crossref.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub funders: Vec<String>,
    #[serde(default)]
    pub extraction: Extraction,
    pub review: Option<Review>,
    /// Citation count of the source paper (from OpenAlex).
    #[serde(default)]
    pub citation_count: Option<u64>,
}

fn default_source_type() -> String {
    "published_paper".into()
}

/// Typed review state. Replaces the v0.2 `flags.contested: bool` collapse
/// of three semantically distinct review judgments. Doctrine line 6:
/// "scientific disagreement should remain live state."
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewState {
    /// Review verdict was "accepted" or "approved" — finding stands.
    Accepted,
    /// Review verdict was "contested" — disagreement preserved as live state.
    Contested,
    /// Review verdict was "needs_revision" — finding stays but flagged for
    /// confidence revision or condition refinement.
    NeedsRevision,
    /// Review verdict was "rejected" — finding kept for replay history but
    /// not treated as active state.
    Rejected,
}

impl ReviewState {
    /// Whether `flags.contested` should be true given this review_state.
    /// Backwards-compat shim: contested is the v0.2 derived bit.
    #[must_use]
    pub fn implies_contested(&self) -> bool {
        matches!(
            self,
            ReviewState::Contested | ReviewState::NeedsRevision | ReviewState::Rejected
        )
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Flags {
    #[serde(default)]
    pub gap: bool,
    #[serde(default)]
    pub negative_space: bool,
    /// Derived from `review_state` for backward compatibility. Code that
    /// reads `flags.contested` still works; new code should read
    /// `review_state` for the typed verdict.
    #[serde(default)]
    pub contested: bool,
    #[serde(default)]
    pub retracted: bool,
    #[serde(default)]
    pub declining: bool,
    #[serde(default)]
    pub gravity_well: bool,
    /// Typed review verdict (v0.3+). When set, drives `flags.contested`
    /// for backward compatibility. `None` means no review verdict has
    /// been recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_state: Option<ReviewState>,
    /// v0.14: true once a newer content-addressed finding supersedes
    /// this one via the `finding.supersede` proposal kind. The newer
    /// finding carries a `supersedes` link back to this finding's id.
    /// Skipped when false so pre-v0.14 frontiers serialize byte-identically.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub superseded: bool,
    /// v0.37: minimum number of unique valid signatures required for
    /// this finding to qualify as `jointly_accepted`. `None` (the
    /// default) preserves single-sig semantics — any one valid
    /// signature is accepted. When `Some(k)`, the finding only counts
    /// as joint-accepted once `k` distinct registered actors have
    /// each contributed a valid Ed25519 signature over the canonical
    /// finding bytes. Pre-v0.37 frontiers omit the field; loading is
    /// backward-compatible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_threshold: Option<u32>,
    /// v0.37: true once at least `signature_threshold` unique actors
    /// have signed this finding. Set by the verify pass; not written
    /// directly by any other code path. Skipped when false so pre-v0.37
    /// frontiers serialize byte-identically.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub jointly_accepted: bool,
}

/// v0.38: Pearlian causal typing for an assertion. The kernel's
/// pre-v0.38 record carried only `direction: Some("positive" |
/// "negative")` — enough to know that "X covaries with Y" but not
/// whether the speaker meant correlation, mediation, or intervention.
/// In real review work those are different epistemic claims with
/// different evidence requirements; conflating them produced silent
/// over-claiming.
///
/// This release lands the schema layer. The reasoning surface
/// (do-calculus, identifiability, derived bridges that propagate
/// causal vs correlational claims separately) ships in a follow-up.
/// The same staging used v0.32 (Replication as object) → v0.36.1
/// (Project.replications becomes the source of truth for confidence).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CausalClaim {
    /// "X covaries with Y" — no claim about generative direction.
    Correlation,
    /// "X mediates Y → Z" — pathway claim, weaker than intervention.
    Mediation,
    /// "Setting X=x changes Y" — Pearl's `do(X=x)`.
    Intervention,
}

/// v0.38: study-design grade backing a causal claim.
/// The grade is what makes the difference between "the data is
/// consistent with X causing Y" (Observational) and "X causes Y"
/// (Rct). The kernel carries the design label so reviewers can
/// re-grade without re-extracting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CausalEvidenceGrade {
    /// Randomized controlled trial. Strongest grade for intervention claims.
    Rct,
    /// Mendelian randomization, instrumental variables, regression
    /// discontinuity, natural experiments, etc.
    QuasiExperimental,
    /// Cohort, case-control, cross-sectional. Identifies association
    /// only without further design assumptions.
    Observational,
    /// Computational simulation, theoretical model, mathematical proof.
    Theoretical,
}

/// Valid string forms for serialized `CausalClaim`. The kernel
/// validates against this on load.
pub const VALID_CAUSAL_CLAIMS: &[&str] = &["correlation", "mediation", "intervention"];

/// Valid string forms for serialized `CausalEvidenceGrade`.
pub const VALID_CAUSAL_EVIDENCE_GRADES: &[&str] =
    &["rct", "quasi_experimental", "observational", "theoretical"];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Assertion {
    pub text: String,
    #[serde(rename = "type")]
    pub assertion_type: String,
    #[serde(default)]
    pub entities: Vec<Entity>,
    pub relation: Option<String>,
    pub direction: Option<String>,
    /// v0.38: the kind of causal claim this assertion makes. `None`
    /// means the kernel hasn't been told yet — the legacy default for
    /// pre-v0.38 findings. `Some(Correlation)` is the safe minimum
    /// claim; `Some(Intervention)` is the strongest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub causal_claim: Option<CausalClaim>,
    /// v0.38: study-design grade backing the causal claim. Drives the
    /// reasoning layer's identifiability checks (deferred). Pre-v0.38
    /// findings omit the field; loading is backward-compatible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub causal_evidence_grade: Option<CausalEvidenceGrade>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Link {
    pub target: String,
    #[serde(rename = "type")]
    pub link_type: String,
    #[serde(default)]
    pub note: String,
    #[serde(default = "default_compiler")]
    pub inferred_by: String,
    /// When this link was created (immutable timestamp). Uses serde default for backward compat.
    #[serde(default)]
    pub created_at: String,
    /// v0.45: optional structural causal mechanism on a `depends` /
    /// `supports` edge. When present, the edge participates in
    /// counterfactual (Pearl level 3) queries via twin-network
    /// construction. Edges without a mechanism still participate in
    /// level 2 (back-door / front-door identification); they simply
    /// can't answer twin-network counterfactuals.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mechanism: Option<Mechanism>,
}

fn default_compiler() -> String {
    "compiler".into()
}

/// v0.45: structural causal mechanism on a directed edge.
///
/// A `Mechanism` captures *how* a parent finding determines a child's
/// value, not just that a dependency exists. With mechanisms in place,
/// the kernel can answer counterfactual (Pearl level 3) queries: "given
/// that we observed X under parent=p, what would X have been under
/// parent=p'?" via twin-network construction.
///
/// Doctrine: mechanisms are deliberately coarse. Science rarely warrants
/// precise functional forms; what we need is enough algebraic structure
/// to propagate counterfactual perturbations sign-and-magnitude. Five
/// shapes cover the empirical distribution of biology / clinical claims:
///
/// - `Linear { sign, slope }`: dY = slope * dX (with sign packing the
///   direction; slope is a unitless effect-size on the [0,1] confidence
///   scale).
/// - `Monotonic { sign }`: dY agrees with sign(dX) but magnitude is
///   ungraded (used when direction is known but effect-size isn't).
/// - `Threshold { sign, threshold }`: parent must cross `threshold` for
///   any child response (binary above/below).
/// - `Saturating { sign, half_max }`: hyperbolic / Hill-style; large dX
///   above `half_max` produces vanishing dY.
/// - `Unknown`: explicitly annotated as causally connected but
///   mechanism unspecified. Twin-network treats this as opaque (the
///   counterfactual is reported as `MechanismUnspecified`).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Mechanism {
    Linear {
        sign: MechanismSign,
        /// Effect-size on [0, 1] confidence scale.
        slope: f64,
    },
    Monotonic {
        sign: MechanismSign,
    },
    Threshold {
        sign: MechanismSign,
        threshold: f64,
    },
    Saturating {
        sign: MechanismSign,
        half_max: f64,
    },
    Unknown,
}

/// v0.45: causal direction on a `Mechanism`.
///
/// `Positive`: parent confidence ↑ ⇒ child confidence ↑.
/// `Negative`: parent confidence ↑ ⇒ child confidence ↓.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MechanismSign {
    Positive,
    Negative,
}

impl MechanismSign {
    #[must_use]
    pub fn as_f64(self) -> f64 {
        match self {
            Self::Positive => 1.0,
            Self::Negative => -1.0,
        }
    }
}

impl Mechanism {
    /// Apply this mechanism to a parent perturbation `delta_x`,
    /// returning the implied child perturbation `delta_y` on the
    /// confidence scale. Returns `None` for `Unknown`.
    #[must_use]
    pub fn apply(&self, delta_x: f64) -> Option<f64> {
        match *self {
            Self::Linear { sign, slope } => Some(sign.as_f64() * slope * delta_x),
            Self::Monotonic { sign } => {
                Some(sign.as_f64() * delta_x.signum() * delta_x.abs().min(1.0))
            }
            Self::Threshold { sign, threshold } => {
                if delta_x.abs() >= threshold {
                    Some(sign.as_f64() * delta_x.signum())
                } else {
                    Some(0.0)
                }
            }
            Self::Saturating { sign, half_max } => {
                // Hill-style: delta_y = sign * dx / (|dx| + half_max), bounded to [-1,1]
                let denom = delta_x.abs() + half_max.max(1e-9);
                Some(sign.as_f64() * delta_x / denom)
            }
            Self::Unknown => None,
        }
    }
}

/// v0.8: typed reference resolved from `Link.target`.
///
/// Targets stay opaque `String` on the wire (canonical-JSON stable). At
/// validation/render time callers parse via `LinkRef::parse`. The
/// `Local` variant is the v0–v0.7 shape; `Cross` is new in v0.8 and
/// requires the dependent frontier to declare a matching `vfr_id` in
/// `frontier.dependencies`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkRef {
    /// `vf_<16hex>` — the target finding lives in this same frontier.
    Local { vf_id: String },
    /// `vf_<16hex>@vfr_<16hex>` — the target finding lives in a
    /// different frontier. Strict validation requires the `vfr_id` to
    /// appear in `Project.frontier.dependencies`.
    Cross { vf_id: String, vfr_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkParseError {
    Empty,
    BadVfPrefix,
    BadVfrPrefix,
    EmptyVfId,
    EmptyVfrId,
    TooManyAtSigns,
}

impl std::fmt::Display for LinkParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LinkParseError::Empty => write!(f, "empty link target"),
            LinkParseError::BadVfPrefix => write!(f, "link target must start with 'vf_'"),
            LinkParseError::BadVfrPrefix => {
                write!(f, "cross-frontier suffix must start with 'vfr_'")
            }
            LinkParseError::EmptyVfId => write!(f, "link target's vf_ id is empty"),
            LinkParseError::EmptyVfrId => write!(f, "cross-frontier vfr_ id is empty"),
            LinkParseError::TooManyAtSigns => {
                write!(f, "link target has more than one '@' separator")
            }
        }
    }
}

impl std::error::Error for LinkParseError {}

impl LinkRef {
    /// Parse `vf_<id>` or `vf_<id>@vfr_<id>` into a typed reference.
    /// Treats inputs as opaque hex-ish blobs — does not validate hex
    /// length or character set, since the substrate's content-address
    /// derivation already handles that.
    pub fn parse(s: &str) -> Result<Self, LinkParseError> {
        if s.is_empty() {
            return Err(LinkParseError::Empty);
        }
        let mut parts = s.split('@');
        let local = parts.next().ok_or(LinkParseError::Empty)?;
        let remote = parts.next();
        if parts.next().is_some() {
            return Err(LinkParseError::TooManyAtSigns);
        }
        let vf_id = local
            .strip_prefix("vf_")
            .ok_or(LinkParseError::BadVfPrefix)?;
        if vf_id.is_empty() {
            return Err(LinkParseError::EmptyVfId);
        }
        match remote {
            None => Ok(LinkRef::Local {
                vf_id: local.to_string(),
            }),
            Some(r) => {
                let vfr_id = r.strip_prefix("vfr_").ok_or(LinkParseError::BadVfrPrefix)?;
                if vfr_id.is_empty() {
                    return Err(LinkParseError::EmptyVfrId);
                }
                Ok(LinkRef::Cross {
                    vf_id: local.to_string(),
                    vfr_id: r.to_string(),
                })
            }
        }
    }

    /// Round-trip: format back to the canonical wire string.
    pub fn format(&self) -> String {
        match self {
            LinkRef::Local { vf_id } => vf_id.clone(),
            LinkRef::Cross { vf_id, vfr_id } => format!("{vf_id}@{vfr_id}"),
        }
    }

    /// True if this reference points outside the current frontier.
    pub fn is_cross_frontier(&self) -> bool {
        matches!(self, LinkRef::Cross { .. })
    }
}

#[cfg(test)]
mod link_ref_tests {
    use super::*;

    #[test]
    fn parses_local_vf_id() {
        let r = LinkRef::parse("vf_abc123").unwrap();
        assert_eq!(
            r,
            LinkRef::Local {
                vf_id: "vf_abc123".into()
            }
        );
        assert_eq!(r.format(), "vf_abc123");
        assert!(!r.is_cross_frontier());
    }

    #[test]
    fn parses_cross_frontier_target() {
        let r = LinkRef::parse("vf_abc@vfr_def").unwrap();
        assert_eq!(
            r,
            LinkRef::Cross {
                vf_id: "vf_abc".into(),
                vfr_id: "vfr_def".into(),
            }
        );
        assert_eq!(r.format(), "vf_abc@vfr_def");
        assert!(r.is_cross_frontier());
    }

    #[test]
    fn rejects_empty() {
        assert_eq!(LinkRef::parse(""), Err(LinkParseError::Empty));
    }

    #[test]
    fn rejects_missing_vf_prefix() {
        assert_eq!(LinkRef::parse("xx_abc"), Err(LinkParseError::BadVfPrefix));
    }

    #[test]
    fn rejects_empty_vf_id() {
        assert_eq!(LinkRef::parse("vf_"), Err(LinkParseError::EmptyVfId));
    }

    #[test]
    fn rejects_missing_vfr_prefix_after_at() {
        assert_eq!(
            LinkRef::parse("vf_abc@xxx_def"),
            Err(LinkParseError::BadVfrPrefix)
        );
    }

    #[test]
    fn rejects_empty_vfr_id() {
        assert_eq!(
            LinkRef::parse("vf_abc@vfr_"),
            Err(LinkParseError::EmptyVfrId)
        );
    }

    #[test]
    fn rejects_double_at() {
        assert_eq!(
            LinkRef::parse("vf_abc@vfr_def@x"),
            Err(LinkParseError::TooManyAtSigns)
        );
    }

    #[test]
    fn round_trips_real_ids() {
        for s in [
            "vf_d0a962d3251133dd",
            "vf_d0a962d3251133dd@vfr_7344e96c0f2669d5",
        ] {
            assert_eq!(LinkRef::parse(s).unwrap().format(), s);
        }
    }
}

/// A lightweight annotation on a finding — like a comment on a line of code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Annotation {
    /// Content-addressed ID (ann_{hash}).
    pub id: String,
    /// The annotation text.
    pub text: String,
    /// Who wrote it (ORCID preferred).
    pub author: String,
    /// When it was created (RFC 3339).
    pub timestamp: String,
    /// Phase β (v0.6): structured provenance for the annotation.
    /// Optional. When present, encodes which paper / preprint / extract
    /// span produced this note. Reviewers query by these fields:
    /// "show every annotation from PMID 25378646" works because the
    /// identifier is structure, not prose.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<ProvenanceRef>,
}

/// Phase β (v0.6): structured provenance reference attached to an
/// annotation (or any future note-shaped object). At least one
/// identifying field (`doi`, `pmid`, `title`) must be set when the
/// provenance is present; an all-empty `ProvenanceRef` is rejected by
/// `validate_event_payload`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProvenanceRef {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doi: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pmid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Verbatim quote / extraction span from the source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span: Option<String>,
}

impl ProvenanceRef {
    /// True iff at least one identifying field is set. Used by
    /// `validate_event_payload` to reject all-empty `provenance: {}` objects.
    #[must_use]
    pub fn has_identifier(&self) -> bool {
        self.doi.is_some() || self.pmid.is_some() || self.title.is_some()
    }
}

/// A file attached to a finding (dataset, figure, supplementary material).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attachment {
    pub filename: String,
    pub label: Option<String>,
    pub path: String,
    pub size_bytes: u64,
    pub mime_type: Option<String>,
    pub attached_at: String,
    pub attached_by: Option<String>,
}

// ── REVIEW layer: content-addressed review events ──────────────────────────

/// A review event is a content-addressed record of human judgment on a finding.
/// Like a Git commit, it records who, when, what changed, and why.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewEvent {
    /// Content-addressed ID of this review event.
    pub id: String,
    /// Optional workspace-relative origin for repo-scoped reviews.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace: Option<String>,
    /// ID of the finding being reviewed.
    pub finding_id: String,
    /// The reviewer (ORCID preferred).
    pub reviewer: String,
    /// When the review happened (RFC 3339).
    pub reviewed_at: String,
    /// Optional review scope for richer curation workflows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Optional status for the review event (for example: accepted).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// What action was taken.
    pub action: ReviewAction,
    /// Human-readable reason.
    #[serde(default)]
    pub reason: String,
    /// Supporting findings or artifacts considered during review.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_considered: Vec<ReviewEvidence>,
    /// Optional structured interpretation update payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_change: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReviewEvidence {
    pub finding_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// The action taken in a review event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ReviewAction {
    /// Finding approved as correct.
    Approved,
    /// Finding interpretation was qualified to narrow or constrain the claim.
    Qualified { target: String },
    /// Finding corrected — a specific field was changed.
    Corrected {
        field: String,
        original: String,
        corrected: String,
    },
    /// Finding flagged with a specific flag type.
    Flagged { flag_type: String },
    /// Finding disputed — reviewer disagrees with the claim.
    Disputed {
        counter_evidence: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        counter_doi: Option<String>,
    },
}

// ── Interpretation layer: mutable confidence updates ───────────────────────

/// A confidence update is a mutable interpretation layer event.
/// The finding's evidence is immutable; the confidence assessment can evolve.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceUpdate {
    pub finding_id: String,
    pub previous_score: f64,
    pub new_score: f64,
    pub basis: String,
    /// Who or what produced this update (e.g., "grounding_pass", "reviewer:0000-0001-2345-6789").
    pub updated_by: String,
    /// When this update was produced (RFC 3339).
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingBundle {
    pub id: String,
    #[serde(default = "default_version")]
    pub version: u32,
    pub previous_version: Option<String>,
    pub assertion: Assertion,
    pub evidence: Evidence,
    pub conditions: Conditions,
    pub confidence: Confidence,
    pub provenance: Provenance,
    pub flags: Flags,
    #[serde(default)]
    pub links: Vec<Link>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub annotations: Vec<Annotation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<Attachment>,
    pub created: String,
    pub updated: Option<String>,
    /// v0.51: Read-side access tier. Default `Public` — pre-v0.51
    /// findings load with `Public` and serialize byte-identically
    /// (skip-if-public). Mutated through `tier.set` events; gated in
    /// MCP/HTTP read paths via `access_tier::redact_for_actor`. NOT
    /// part of the content-address preimage — re-classifying a
    /// finding does not mint a new id.
    #[serde(default, skip_serializing_if = "is_public_tier")]
    pub access_tier: crate::access_tier::AccessTier,
}

fn is_public_tier(tier: &crate::access_tier::AccessTier) -> bool {
    matches!(tier, crate::access_tier::AccessTier::Public)
}

fn default_version() -> u32 {
    1
}

impl FindingBundle {
    /// Create a new finding bundle with a content-addressed ID.
    /// Normalize text for content-addressing: lowercase, collapse whitespace,
    /// strip trailing punctuation. Matches the v0.2.0 schema specification.
    /// Public since v0.32 so `Replication::content_address` can reuse the
    /// same canonicalization rule for its conditions preimage.
    pub fn normalize_text(s: &str) -> String {
        let lower = s.to_lowercase();
        // Collapse all runs of whitespace into a single space
        let collapsed: String = lower.split_whitespace().collect::<Vec<_>>().join(" ");
        // Strip trailing punctuation (., ;, :, !, ?)
        collapsed
            .trim_end_matches(['.', ';', ':', '!', '?'])
            .to_string()
    }

    /// Compute the content-addressed ID per v0.2.0 spec:
    /// SHA-256(normalize(assertion.text) + "|" + assertion.type + "|" + (provenance.doi || provenance.pmid || provenance.title))
    /// Returns first 16 hex chars prefixed with "vf_".
    pub fn content_address(assertion: &Assertion, provenance: &Provenance) -> String {
        let norm_text = Self::normalize_text(&assertion.text);
        let prov_id = provenance
            .doi
            .as_deref()
            .or(provenance.pmid.as_deref())
            .unwrap_or(&provenance.title);
        let preimage = format!("{}|{}|{}", norm_text, assertion.assertion_type, prov_id);
        let hash = Sha256::digest(preimage.as_bytes());
        format!("vf_{}", &hex::encode(hash)[..16])
    }

    pub fn new(
        assertion: Assertion,
        evidence: Evidence,
        conditions: Conditions,
        confidence: Confidence,
        provenance: Provenance,
        flags: Flags,
    ) -> Self {
        let now = Utc::now().to_rfc3339();
        let id = Self::content_address(&assertion, &provenance);

        Self {
            id,
            version: 1,
            previous_version: None,
            assertion,
            evidence,
            conditions,
            confidence,
            provenance,
            flags,
            links: Vec::new(),
            annotations: Vec::new(),
            attachments: Vec::new(),
            created: now,
            updated: None,
            access_tier: crate::access_tier::AccessTier::Public,
        }
    }

    pub fn add_link(&mut self, target_id: &str, link_type: &str, note: &str) {
        self.links.push(Link {
            target: target_id.to_string(),
            link_type: link_type.to_string(),
            note: note.to_string(),
            inferred_by: "compiler".to_string(),
            created_at: Utc::now().to_rfc3339(),
            mechanism: None,
        });
    }

    pub fn add_link_with_source(
        &mut self,
        target_id: &str,
        link_type: &str,
        note: &str,
        inferred_by: &str,
    ) {
        self.links.push(Link {
            target: target_id.to_string(),
            link_type: link_type.to_string(),
            note: note.to_string(),
            inferred_by: inferred_by.to_string(),
            created_at: Utc::now().to_rfc3339(),
            mechanism: None,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_assertion() -> Assertion {
        Assertion {
            text: "NLRP3 activates IL-1B".into(),
            assertion_type: "mechanism".into(),
            entities: vec![Entity {
                name: "NLRP3".into(),
                entity_type: "protein".into(),
                identifiers: serde_json::Map::new(),
                canonical_id: None,
                candidates: vec![],
                aliases: vec![],
                resolution_provenance: None,
                resolution_confidence: 1.0,
                resolution_method: None,
                species_context: None,
                needs_review: false,
            }],
            relation: Some("activates".into()),
            direction: Some("positive".into()),
            causal_claim: None,
            causal_evidence_grade: None,
        }
    }

    fn sample_evidence() -> Evidence {
        Evidence {
            evidence_type: "experimental".into(),
            model_system: "mouse".into(),
            species: Some("Mus musculus".into()),
            method: "Western blot".into(),
            sample_size: Some("n=30".into()),
            effect_size: None,
            p_value: Some("p<0.05".into()),
            replicated: true,
            replication_count: Some(3),
            evidence_spans: vec![],
        }
    }

    fn sample_conditions() -> Conditions {
        Conditions {
            text: "In vitro, mouse microglia".into(),
            species_verified: vec!["Mus musculus".into()],
            species_unverified: vec![],
            in_vitro: true,
            in_vivo: false,
            human_data: false,
            clinical_trial: false,
            concentration_range: None,
            duration: None,
            age_group: None,
            cell_type: Some("microglia".into()),
        }
    }

    fn sample_confidence() -> Confidence {
        Confidence {
            kind: ConfidenceKind::FrontierEpistemic,
            score: 0.85,
            basis: "Experimental with replication".into(),
            method: ConfidenceMethod::LlmInitial,
            components: None,
            extraction_confidence: 0.9,
        }
    }

    fn sample_provenance() -> Provenance {
        Provenance {
            source_type: "published_paper".into(),
            doi: Some("10.1234/test".into()),
            pmid: None,
            pmc: None,
            openalex_id: None,
            url: None,
            title: "Test Paper".into(),
            authors: vec![Author {
                name: "Smith J".into(),
                orcid: None,
            }],
            year: Some(2024),
            journal: Some("Nature".into()),
            license: None,
            publisher: None,
            funders: vec![],
            extraction: Extraction::default(),
            review: None,
            citation_count: Some(100),
        }
    }

    fn sample_flags() -> Flags {
        Flags {
            gap: false,
            negative_space: false,
            contested: false,
            retracted: false,
            declining: false,
            gravity_well: false,
            review_state: None,
            superseded: false,
            signature_threshold: None,
            jointly_accepted: false,
        }
    }

    // ── Content-addressed ID tests ───────────────────────────────────

    #[test]
    fn same_content_same_id() {
        let b1 = FindingBundle::new(
            sample_assertion(),
            sample_evidence(),
            sample_conditions(),
            sample_confidence(),
            sample_provenance(),
            sample_flags(),
        );
        let b2 = FindingBundle::new(
            sample_assertion(),
            sample_evidence(),
            sample_conditions(),
            sample_confidence(),
            sample_provenance(),
            sample_flags(),
        );
        assert_eq!(b1.id, b2.id);
    }

    #[test]
    fn different_content_different_id() {
        let b1 = FindingBundle::new(
            sample_assertion(),
            sample_evidence(),
            sample_conditions(),
            sample_confidence(),
            sample_provenance(),
            sample_flags(),
        );
        let mut different_assertion = sample_assertion();
        different_assertion.text = "Completely different claim".into();
        let b2 = FindingBundle::new(
            different_assertion,
            sample_evidence(),
            sample_conditions(),
            sample_confidence(),
            sample_provenance(),
            sample_flags(),
        );
        assert_ne!(b1.id, b2.id);
    }

    #[test]
    fn id_starts_with_vf_prefix() {
        let b = FindingBundle::new(
            sample_assertion(),
            sample_evidence(),
            sample_conditions(),
            sample_confidence(),
            sample_provenance(),
            sample_flags(),
        );
        assert!(b.id.starts_with("vf_"));
        assert_eq!(b.id.len(), 3 + 16); // "vf_" + 16 hex chars
    }

    #[test]
    fn new_bundle_version_is_one() {
        let b = FindingBundle::new(
            sample_assertion(),
            sample_evidence(),
            sample_conditions(),
            sample_confidence(),
            sample_provenance(),
            sample_flags(),
        );
        assert_eq!(b.version, 1);
        assert!(b.previous_version.is_none());
    }

    #[test]
    fn new_bundle_has_no_links() {
        let b = FindingBundle::new(
            sample_assertion(),
            sample_evidence(),
            sample_conditions(),
            sample_confidence(),
            sample_provenance(),
            sample_flags(),
        );
        assert!(b.links.is_empty());
    }

    #[test]
    fn new_bundle_has_created_timestamp() {
        let b = FindingBundle::new(
            sample_assertion(),
            sample_evidence(),
            sample_conditions(),
            sample_confidence(),
            sample_provenance(),
            sample_flags(),
        );
        assert!(!b.created.is_empty());
        assert!(b.updated.is_none());
    }

    // ── add_link tests ───────────────────────────────────────────────

    #[test]
    fn add_link_works() {
        let mut b = FindingBundle::new(
            sample_assertion(),
            sample_evidence(),
            sample_conditions(),
            sample_confidence(),
            sample_provenance(),
            sample_flags(),
        );
        b.add_link("target_id", "extends", "shared entity");
        assert_eq!(b.links.len(), 1);
        assert_eq!(b.links[0].target, "target_id");
        assert_eq!(b.links[0].link_type, "extends");
        assert_eq!(b.links[0].note, "shared entity");
        assert_eq!(b.links[0].inferred_by, "compiler");
    }

    #[test]
    fn add_link_with_source_works() {
        let mut b = FindingBundle::new(
            sample_assertion(),
            sample_evidence(),
            sample_conditions(),
            sample_confidence(),
            sample_provenance(),
            sample_flags(),
        );
        b.add_link_with_source(
            "target_id",
            "contradicts",
            "opposite direction",
            "entity_overlap",
        );
        assert_eq!(b.links.len(), 1);
        assert_eq!(b.links[0].inferred_by, "entity_overlap");
    }

    #[test]
    fn multiple_links_accumulate() {
        let mut b = FindingBundle::new(
            sample_assertion(),
            sample_evidence(),
            sample_conditions(),
            sample_confidence(),
            sample_provenance(),
            sample_flags(),
        );
        b.add_link("t1", "extends", "note1");
        b.add_link("t2", "contradicts", "note2");
        b.add_link("t3", "supports", "note3");
        assert_eq!(b.links.len(), 3);
    }

    // ── ReviewEvent creation test ────────────────────────────────────

    #[test]
    fn review_event_creation() {
        let event = ReviewEvent {
            id: "rev_abc123".into(),
            workspace: None,
            finding_id: "vf_abc".into(),
            reviewer: "0000-0001-2345-6789".into(),
            reviewed_at: "2024-01-01T00:00:00Z".into(),
            scope: None,
            status: None,
            action: ReviewAction::Approved,
            reason: "Looks correct".into(),
            evidence_considered: vec![],
            state_change: None,
        };
        assert_eq!(event.finding_id, "vf_abc");
        assert_eq!(event.reviewer, "0000-0001-2345-6789");
    }

    #[test]
    fn review_action_corrected() {
        let action = ReviewAction::Corrected {
            field: "direction".into(),
            original: "positive".into(),
            corrected: "negative".into(),
        };
        if let ReviewAction::Corrected {
            field,
            original,
            corrected,
        } = action
        {
            assert_eq!(field, "direction");
            assert_eq!(original, "positive");
            assert_eq!(corrected, "negative");
        } else {
            panic!("Expected Corrected variant");
        }
    }

    #[test]
    fn review_action_disputed() {
        let action = ReviewAction::Disputed {
            counter_evidence: "Later study contradicts".into(),
            counter_doi: Some("10.1234/counter".into()),
        };
        if let ReviewAction::Disputed {
            counter_evidence,
            counter_doi,
        } = action
        {
            assert_eq!(counter_evidence, "Later study contradicts");
            assert_eq!(counter_doi, Some("10.1234/counter".into()));
        } else {
            panic!("Expected Disputed variant");
        }
    }

    // ── ConfidenceUpdate creation test ───────────────────────────────

    #[test]
    fn confidence_update_creation() {
        let update = ConfidenceUpdate {
            finding_id: "vf_abc".into(),
            previous_score: 0.7,
            new_score: 0.85,
            basis: "grounded".into(),
            updated_by: "grounding_pass".into(),
            updated_at: "2024-01-01T00:00:00Z".into(),
        };
        assert_eq!(update.previous_score, 0.7);
        assert_eq!(update.new_score, 0.85);
        assert_eq!(update.updated_by, "grounding_pass");
    }

    // ── Serialization round-trip test ────────────────────────────────

    #[test]
    fn finding_serializes_and_deserializes() {
        let b = FindingBundle::new(
            sample_assertion(),
            sample_evidence(),
            sample_conditions(),
            sample_confidence(),
            sample_provenance(),
            sample_flags(),
        );
        let json = serde_json::to_string(&b).unwrap();
        let b2: FindingBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(b.id, b2.id);
        assert_eq!(b.assertion.text, b2.assertion.text);
        assert_eq!(b.confidence.score, b2.confidence.score);
    }

    #[test]
    fn valid_entity_types_list() {
        // Pre-v0.10 (bio) entries
        for t in ["gene", "protein", "compound", "other"] {
            assert!(VALID_ENTITY_TYPES.contains(&t), "missing {t}");
        }
        // v0.10 domain-neutral additions
        for t in ["particle", "instrument", "dataset", "quantity"] {
            assert!(VALID_ENTITY_TYPES.contains(&t), "missing {t}");
        }
        assert_eq!(VALID_ENTITY_TYPES.len(), 14);
    }

    #[test]
    fn v0_10_assertion_and_source_extensions() {
        assert!(VALID_ASSERTION_TYPES.contains(&"measurement"));
        assert!(VALID_ASSERTION_TYPES.contains(&"exclusion"));
        assert!(VALID_PROVENANCE_SOURCE_TYPES.contains(&"data_release"));
    }

    // ── Different fields change the ID ───────────────────────────────

    #[test]
    fn confidence_does_not_affect_id() {
        // v0.2.0: confidence is the mutable interpretation layer, not part of content address
        let b1 = FindingBundle::new(
            sample_assertion(),
            sample_evidence(),
            sample_conditions(),
            sample_confidence(),
            sample_provenance(),
            sample_flags(),
        );
        let mut conf2 = sample_confidence();
        conf2.score = 0.5;
        let b2 = FindingBundle::new(
            sample_assertion(),
            sample_evidence(),
            sample_conditions(),
            conf2,
            sample_provenance(),
            sample_flags(),
        );
        assert_eq!(b1.id, b2.id);
    }

    #[test]
    fn flags_do_not_affect_id() {
        let b1 = FindingBundle::new(
            sample_assertion(),
            sample_evidence(),
            sample_conditions(),
            sample_confidence(),
            sample_provenance(),
            sample_flags(),
        );
        let mut flags2 = sample_flags();
        flags2.gap = true;
        flags2.contested = true;
        let b2 = FindingBundle::new(
            sample_assertion(),
            sample_evidence(),
            sample_conditions(),
            sample_confidence(),
            sample_provenance(),
            flags2,
        );
        // Flags are NOT in the content hash, so IDs should be the same
        assert_eq!(b1.id, b2.id);
    }

    #[test]
    fn different_assertion_text_different_id() {
        let b1 = FindingBundle::new(
            sample_assertion(),
            sample_evidence(),
            sample_conditions(),
            sample_confidence(),
            sample_provenance(),
            sample_flags(),
        );
        let mut assertion2 = sample_assertion();
        assertion2.assertion_type = "therapeutic".into();
        let b2 = FindingBundle::new(
            assertion2,
            sample_evidence(),
            sample_conditions(),
            sample_confidence(),
            sample_provenance(),
            sample_flags(),
        );
        assert_ne!(b1.id, b2.id);
    }

    #[test]
    fn different_doi_different_id() {
        let b1 = FindingBundle::new(
            sample_assertion(),
            sample_evidence(),
            sample_conditions(),
            sample_confidence(),
            sample_provenance(),
            sample_flags(),
        );
        let mut prov2 = sample_provenance();
        prov2.doi = Some("10.5678/other".into());
        let b2 = FindingBundle::new(
            sample_assertion(),
            sample_evidence(),
            sample_conditions(),
            sample_confidence(),
            prov2,
            sample_flags(),
        );
        assert_ne!(b1.id, b2.id);
    }

    // ── v0.2.0 content-addressing determinism ───────────────────────

    #[test]
    fn content_address_is_deterministic_across_runs() {
        // Two independent extraction runs with the same assertion text,
        // assertion type, and DOI must produce the same finding ID.
        let assertion1 = Assertion {
            text: "Mitochondrial dysfunction precedes amyloid plaque formation.".into(),
            assertion_type: "mechanism".into(),
            entities: vec![],
            relation: None,
            direction: None,
            causal_claim: None,
            causal_evidence_grade: None,
        };
        let prov1 = Provenance {
            source_type: "published_paper".into(),
            doi: Some("10.1038/s41586-023-06789-1".into()),
            pmid: None,
            pmc: None,
            openalex_id: None,
            url: None,
            title: "Mitochondria in AD".into(),
            authors: vec![],
            year: Some(2023),
            journal: None,
            license: None,
            publisher: None,
            funders: vec![],
            extraction: Extraction::default(),
            review: None,
            citation_count: None,
        };

        // Different entities, evidence, conditions, confidence -- should NOT matter
        let assertion2 = Assertion {
            text: "Mitochondrial dysfunction precedes amyloid plaque formation.".into(),
            assertion_type: "mechanism".into(),
            entities: vec![Entity {
                name: "mitochondria".into(),
                entity_type: "anatomical_structure".into(),
                identifiers: serde_json::Map::new(),
                canonical_id: None,
                candidates: vec![],
                aliases: vec![],
                resolution_provenance: None,
                resolution_confidence: 1.0,
                resolution_method: None,
                species_context: None,
                needs_review: false,
            }],
            relation: Some("precedes".into()),
            direction: Some("positive".into()),
            causal_claim: None,
            causal_evidence_grade: None,
        };
        let prov2 = Provenance {
            source_type: "published_paper".into(),
            doi: Some("10.1038/s41586-023-06789-1".into()),
            pmid: Some("37654321".into()),
            pmc: None,
            openalex_id: None,
            url: None,
            title: "Different title".into(),
            authors: vec![Author {
                name: "Jones A".into(),
                orcid: None,
            }],
            year: Some(2023),
            journal: Some("Nature".into()),
            license: None,
            publisher: None,
            funders: vec![],
            extraction: Extraction::default(),
            review: None,
            citation_count: Some(50),
        };

        let id1 = FindingBundle::content_address(&assertion1, &prov1);
        let id2 = FindingBundle::content_address(&assertion2, &prov2);
        assert_eq!(
            id1, id2,
            "Same assertion text + type + DOI must produce same ID"
        );
    }

    #[test]
    fn content_address_normalizes_whitespace_and_punctuation() {
        let assertion1 = Assertion {
            text: "  NLRP3  activates   IL-1B.  ".into(),
            assertion_type: "mechanism".into(),
            entities: vec![],
            relation: None,
            direction: None,
            causal_claim: None,
            causal_evidence_grade: None,
        };
        let assertion2 = Assertion {
            text: "NLRP3 activates IL-1B".into(),
            assertion_type: "mechanism".into(),
            entities: vec![],
            relation: None,
            direction: None,
            causal_claim: None,
            causal_evidence_grade: None,
        };
        let prov = sample_provenance();
        let id1 = FindingBundle::content_address(&assertion1, &prov);
        let id2 = FindingBundle::content_address(&assertion2, &prov);
        assert_eq!(
            id1, id2,
            "Whitespace and trailing punctuation should be normalized away"
        );
    }

    #[test]
    fn content_address_falls_back_to_title_when_no_doi_or_pmid() {
        let assertion = sample_assertion();
        let mut prov = sample_provenance();
        prov.doi = None;
        prov.pmid = None;
        prov.title = "Fallback Title".into();
        let id = FindingBundle::content_address(&assertion, &prov);
        assert!(id.starts_with("vf_"));
        assert_eq!(id.len(), 19); // "vf_" + 16 hex chars

        // Same title -> same ID
        let mut prov2 = sample_provenance();
        prov2.doi = None;
        prov2.pmid = None;
        prov2.title = "Fallback Title".into();
        let id2 = FindingBundle::content_address(&assertion, &prov2);
        assert_eq!(id, id2);
    }

    #[test]
    fn content_address_prefers_doi_over_pmid_over_title() {
        let assertion = sample_assertion();

        let mut prov_doi = sample_provenance();
        prov_doi.doi = Some("10.1234/test".into());
        prov_doi.pmid = Some("12345".into());
        prov_doi.title = "Title".into();

        let mut prov_pmid = sample_provenance();
        prov_pmid.doi = None;
        prov_pmid.pmid = Some("12345".into());
        prov_pmid.title = "Title".into();

        let mut prov_title = sample_provenance();
        prov_title.doi = None;
        prov_title.pmid = None;
        prov_title.title = "Title".into();

        let id_doi = FindingBundle::content_address(&assertion, &prov_doi);
        let id_pmid = FindingBundle::content_address(&assertion, &prov_pmid);
        let id_title = FindingBundle::content_address(&assertion, &prov_title);

        // All three should be different since the provenance component differs
        assert_ne!(id_doi, id_pmid, "DOI vs PMID should differ");
        assert_ne!(id_pmid, id_title, "PMID vs title should differ");
        assert_ne!(id_doi, id_title, "DOI vs title should differ");
    }

    // ── compute_confidence tests ────────────────────────────────────

    #[test]
    fn compute_confidence_meta_analysis_human() {
        let evidence = Evidence {
            evidence_type: "meta_analysis".into(),
            model_system: "human cohorts".into(),
            species: Some("Homo sapiens".into()),
            method: "meta-analysis".into(),
            sample_size: Some("n=5000".into()),
            effect_size: None,
            p_value: None,
            replicated: true,
            replication_count: Some(5),
            evidence_spans: vec![],
        };
        let conditions = Conditions {
            text: String::new(),
            species_verified: vec![],
            species_unverified: vec![],
            in_vitro: false,
            in_vivo: false,
            human_data: true,
            clinical_trial: false,
            concentration_range: None,
            duration: None,
            age_group: None,
            cell_type: None,
        };
        let conf = compute_confidence(&evidence, &conditions, false);
        assert_eq!(conf.method, ConfidenceMethod::Computed);
        assert_eq!(conf.kind, ConfidenceKind::FrontierEpistemic);
        assert!(conf.components.is_some());
        let c = conf.components.unwrap();
        assert!((c.evidence_strength - 0.95).abs() < 0.001);
        assert!((c.replication_strength - 1.0).abs() < 0.001); // 0.7 + 0.1*5 = 1.2 -> clamped to 1.0
        // v0.701: sample/model collapsed to the domain-neutral constants.
        assert!((c.sample_strength - 0.6).abs() < 0.001);
        assert!((c.model_relevance - 0.5).abs() < 0.001);
        assert!((c.review_penalty - 0.0).abs() < 0.001);
        assert!((c.calibration_adjustment - 0.0).abs() < 0.001);
        // 0.95 * 1.0 * 0.5 * 0.6 - 0.0 = 0.285
        assert!((conf.score - 0.285).abs() < 0.001);
    }

    #[test]
    fn compute_confidence_theoretical_no_replication() {
        let evidence = Evidence {
            evidence_type: "theoretical".into(),
            model_system: "computational".into(),
            species: None,
            method: "simulation".into(),
            sample_size: None,
            effect_size: None,
            p_value: None,
            replicated: false,
            replication_count: None,
            evidence_spans: vec![],
        };
        let conditions = Conditions {
            text: String::new(),
            species_verified: vec![],
            species_unverified: vec![],
            in_vitro: false,
            in_vivo: false,
            human_data: false,
            clinical_trial: false,
            concentration_range: None,
            duration: None,
            age_group: None,
            cell_type: None,
        };
        let conf = compute_confidence(&evidence, &conditions, false);
        let c = conf.components.unwrap();
        assert!((c.evidence_strength - 0.30).abs() < 0.001);
        assert!((c.replication_strength - 0.70).abs() < 0.001);
        assert!((c.sample_strength - 0.60).abs() < 0.001);
        assert!((c.model_relevance - 0.50).abs() < 0.001);
        // 0.30 * 0.70 * 0.50 * 0.60 = 0.063
        assert!((conf.score - 0.063).abs() < 0.001);
    }

    #[test]
    fn compute_confidence_contested_penalty() {
        let evidence = Evidence {
            evidence_type: "experimental".into(),
            model_system: "mouse".into(),
            species: Some("Mus musculus".into()),
            method: "Western blot".into(),
            sample_size: Some("n=30".into()),
            effect_size: None,
            p_value: None,
            replicated: false,
            replication_count: None,
            evidence_spans: vec![],
        };
        let conditions = Conditions {
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
        };
        let uncontested = compute_confidence(&evidence, &conditions, false);
        let contested = compute_confidence(&evidence, &conditions, true);
        assert!((contested.score - (uncontested.score - 0.15)).abs() < 0.001);
    }

    #[test]
    fn compute_confidence_v010_deserialize_compat() {
        // Simulate an older JSON confidence object (no method, no components).
        let json = r#"{"score": 0.75, "basis": "legacy seeded confidence", "extraction_confidence": 0.85}"#;
        let conf: Confidence = serde_json::from_str(json).unwrap();
        assert!((conf.score - 0.75).abs() < 0.001);
        assert_eq!(conf.kind, ConfidenceKind::FrontierEpistemic);
        assert_eq!(conf.method, ConfidenceMethod::LlmInitial); // default
        assert!(conf.components.is_none());
    }

    #[test]
    fn compute_confidence_components_deserialize_legacy_names() {
        let json = r#"{
            "score": 0.75,
            "basis": "legacy components",
            "method": "computed",
            "components": {
                "evidence_grade": 0.8,
                "replication_factor": 0.7,
                "sample_strength": 0.6,
                "species_relevance": 0.8,
                "contradiction_penalty": 0.15
            },
            "extraction_confidence": 0.85
        }"#;
        let conf: Confidence = serde_json::from_str(json).unwrap();
        let components = conf.components.unwrap();
        assert!((components.evidence_strength - 0.8).abs() < 0.001);
        assert!((components.replication_strength - 0.7).abs() < 0.001);
        assert!((components.sample_strength - 0.6).abs() < 0.001);
        assert!((components.model_relevance - 0.8).abs() < 0.001);
        assert!((components.review_penalty - 0.15).abs() < 0.001);
        assert!((components.calibration_adjustment - 0.0).abs() < 0.001);
    }

    #[test]
    fn compute_confidence_serializes_new_component_names_and_kind() {
        let conf = compute_confidence(&sample_evidence(), &sample_conditions(), false);
        let value = serde_json::to_value(&conf).unwrap();
        assert_eq!(value["kind"], "frontier_epistemic");
        let components = &value["components"];
        assert!(components.get("evidence_strength").is_some());
        assert!(components.get("replication_strength").is_some());
        assert!(components.get("model_relevance").is_some());
        assert!(components.get("review_penalty").is_some());
        assert!(components.get("calibration_adjustment").is_some());
        assert!(components.get("evidence_grade").is_none());
        assert!(components.get("replication_factor").is_none());
        assert!(components.get("species_relevance").is_none());
        assert!(components.get("contradiction_penalty").is_none());
    }

    #[test]
    fn recompute_all_updates_findings() {
        let mut b = FindingBundle::new(
            sample_assertion(),
            sample_evidence(),
            sample_conditions(),
            sample_confidence(),
            sample_provenance(),
            sample_flags(),
        );
        // Original score is a seeded prior. The computed frontier support should differ.
        let old_score = b.confidence.score;
        assert!((old_score - 0.85).abs() < 0.001);
        let changed = recompute_all_confidence(std::slice::from_mut(&mut b));
        assert_eq!(b.confidence.method, ConfidenceMethod::Computed);
        assert!(b.confidence.components.is_some());
        // experimental=0.80, replicated(3)=min(1.0,0.7+0.3)=1.0; model + sample
        // collapsed to the v0.701 constants 0.5 and 0.6.
        // 0.80 * 1.0 * 0.5 * 0.6 = 0.24
        assert!((b.confidence.score - 0.24).abs() < 0.001);
        assert_eq!(changed, 1);
    }

    // ── v0.38.1 causal-consistency tests ─────────────────────────────

    #[test]
    fn causal_multiplier_neutral_when_either_field_none() {
        assert!((causal_consistency_multiplier(None, None) - 1.0).abs() < 1e-12);
        assert!(
            (causal_consistency_multiplier(Some(CausalClaim::Intervention), None) - 1.0).abs()
                < 1e-12
        );
        assert!(
            (causal_consistency_multiplier(None, Some(CausalEvidenceGrade::Rct)) - 1.0).abs()
                < 1e-12
        );
    }

    #[test]
    fn rct_grade_bumps_any_claim() {
        for c in [
            CausalClaim::Correlation,
            CausalClaim::Mediation,
            CausalClaim::Intervention,
        ] {
            assert!(
                (causal_consistency_multiplier(Some(c), Some(CausalEvidenceGrade::Rct)) - 1.10)
                    .abs()
                    < 1e-12,
                "RCT should bump claim {c:?}"
            );
        }
    }

    #[test]
    fn observational_intervention_gets_strong_penalty() {
        let m = causal_consistency_multiplier(
            Some(CausalClaim::Intervention),
            Some(CausalEvidenceGrade::Observational),
        );
        assert!(
            (m - 0.65).abs() < 1e-12,
            "intervention from observational should be 0.65, got {m}"
        );
    }

    #[test]
    fn correlation_neutral_under_any_grade() {
        for g in [
            CausalEvidenceGrade::QuasiExperimental,
            CausalEvidenceGrade::Observational,
            CausalEvidenceGrade::Theoretical,
        ] {
            let m = causal_consistency_multiplier(Some(CausalClaim::Correlation), Some(g));
            assert!(
                (m - 1.0).abs() < 1e-12,
                "correlation should be neutral for grade {g:?}, got {m}"
            );
        }
    }

    #[test]
    fn confidence_score_unchanged_for_pre_v0_38_findings() {
        // Backward compat: a finding with no causal fields produces
        // exactly the same score as before v0.38.1 (when n_replicated=0
        // legacy ⇔ replicated=false scalar).
        let mut e = sample_evidence();
        e.replicated = false;
        e.replication_count = None;
        let c = sample_conditions();
        let score_legacy_path = compute_confidence(&e, &c, false).score;
        let score_kernel_path =
            compute_confidence_from_components(&e, &c, false, 0, 0, 0, None, None).score;
        assert!((score_legacy_path - score_kernel_path).abs() < 1e-12);
        // And the components carry the neutral 1.0 multiplier.
        let conf = compute_confidence_from_components(&e, &c, false, 0, 0, 0, None, None);
        let cc = conf.components.unwrap().causal_consistency;
        assert!((cc - 1.0).abs() < 1e-12);
    }

    #[test]
    fn intervention_from_observational_drops_score_meaningfully() {
        // Same evidence + conditions, two readings: neutral vs
        // intervention-from-observational. The latter should drop.
        let e = sample_evidence();
        let c = sample_conditions();
        let neutral = compute_confidence_from_components(&e, &c, false, 0, 0, 0, None, None);
        let observational_intervention = compute_confidence_from_components(
            &e,
            &c,
            false,
            0,
            0,
            0,
            Some(CausalClaim::Intervention),
            Some(CausalEvidenceGrade::Observational),
        );
        let drop = neutral.score - observational_intervention.score;
        assert!(
            drop > 0.05,
            "observational-intervention should drop score noticeably; got {drop}"
        );
    }

    #[test]
    fn parses_bbb_review_event_with_richer_schema() {
        let raw = include_str!("../embedded/tests/fixtures/legacy/rev_001_bbb_correction.json");
        let review: ReviewEvent = serde_json::from_str(raw).unwrap();

        assert_eq!(review.id, "rev_001_bbb_correction");
        assert_eq!(review.workspace.as_deref(), Some("projects/bbb-flagship"));
        assert_eq!(review.scope.as_deref(), Some("bbb_opening_trusted_subset"));
        assert_eq!(review.status.as_deref(), Some("accepted"));
        assert!(matches!(
            review.action,
            ReviewAction::Qualified { ref target } if target == "trusted_interpretation"
        ));
        assert_eq!(review.evidence_considered.len(), 3);
        assert_eq!(
            review.evidence_considered[0].role.as_deref(),
            Some("qualifier")
        );
        assert_eq!(
            review
                .state_change
                .as_ref()
                .and_then(|value| value.get("assumption_retired"))
                .and_then(|value| value.as_str()),
            Some("safe opening implies therapeutic efficacy")
        );
    }

    #[test]
    fn artifact_requires_sha256_and_stable_kind() {
        let artifact = Artifact::new(
            "clinical_trial_record",
            "AHEAD 3-45",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            Some(42),
            Some("application/json".into()),
            "local_blob",
            Some(".vela/artifact-blobs/sha256/aaaaaaaa".into()),
            Some("https://clinicaltrials.gov/study/NCT04468659".into()),
            Some("ClinicalTrials.gov public record".into()),
            vec!["vf_demo".into()],
            sample_provenance(),
            BTreeMap::new(),
            crate::access_tier::AccessTier::Public,
        )
        .unwrap();

        assert!(artifact.id.starts_with("va_"));
        assert_eq!(
            artifact.content_hash,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(artifact.kind, "clinical_trial_record");
    }
}
