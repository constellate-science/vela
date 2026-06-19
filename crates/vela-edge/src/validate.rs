//! Schema validation for finding bundles in a frontier or VelaRepo.

use std::collections::HashSet;
use std::path::Path;

use chrono::DateTime;
use colored::Colorize;

use serde::{Deserialize, Serialize};
use vela_protocol::cli_style as style;

use crate::lint;
use crate::normalize;
use crate::packet;
use vela_protocol::bundle::{
    ConfidenceMethod, FindingBundle, VALID_ASSERTION_TYPES, VALID_ENTITY_TYPES,
    VALID_EVIDENCE_TYPES, VALID_LINK_TYPES, VALID_PROVENANCE_SOURCE_TYPES,
};
use vela_protocol::repo;

const VALID_EXTRACT_METHODS: &[&str] = &[
    "llm_extraction",
    "manual_curation",
    "database_import",
    "hybrid",
    // v0.30: agent-specific extraction tags. Distinguished from generic
    // `llm_extraction` because they carry the agent's identity
    // (notes-compiler vs scout vs reviewer) — useful for downstream
    // provenance audits that want "all proposals from compile-notes."
    "notes_compiler_via_claude_cli",
    "scout_via_claude_cli",
    "artifact_to_state_import",
];

const VALID_LINK_INFERRED_BY: &[&str] = &["compiler", "reviewer", "author"];

/// A single validation error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationError {
    pub file: String,
    pub error: String,
}

/// Summary of a validation run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationReport {
    pub total_files: usize,
    pub valid: usize,
    pub invalid: usize,
    pub errors: Vec<ValidationError>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Fixability {
    Safe,
    ManualReview,
    NotFixable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QualityCheckOptions {
    pub schema: bool,
    pub lint: bool,
    pub graph: bool,
    pub repair_plan: bool,
}

impl Default for QualityCheckOptions {
    fn default() -> Self {
        Self {
            schema: true,
            lint: true,
            graph: true,
            repair_plan: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QualityDiagnostic {
    pub check_id: String,
    pub severity: String,
    pub rule_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finding_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggestion: Option<String>,
    pub fixability: Fixability,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QualityCheckSection {
    pub id: String,
    pub status: String,
    pub checked: usize,
    pub failed: usize,
    pub diagnostics: Vec<QualityDiagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QualitySummary {
    pub status: String,
    pub checked_findings: usize,
    pub valid_findings: usize,
    pub invalid_findings: usize,
    pub errors: usize,
    pub warnings: usize,
    pub info: usize,
    pub safe_repairs: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RepairPlanItem {
    pub id: String,
    pub finding_id: String,
    pub path: String,
    pub action: String,
    pub before: serde_json::Value,
    pub after: serde_json::Value,
    pub safe: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RepairPlan {
    pub deterministic: bool,
    pub safe_items: usize,
    pub items: Vec<RepairPlanItem>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QualityCheckReport {
    pub ok: bool,
    pub command: String,
    pub schema_version: String,
    pub source: String,
    pub source_kind: String,
    pub summary: QualitySummary,
    pub checks: Vec<QualityCheckSection>,
    pub repair_plan: RepairPlan,
}

/// Reusable report API for `vela check --json` style consumers.
///
/// The report combines schema validation, statistical lint diagnostics, graph
/// diagnostics, and deterministic safe normalization repairs.
pub fn quality_report(source_path: &Path, options: QualityCheckOptions) -> QualityCheckReport {
    let source = source_path.display().to_string();
    let source_kind = repo::detect(source_path)
        .map(|s| source_kind(&s).to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let validation = if options.schema {
        validate(source_path)
    } else {
        ValidationReport {
            total_files: 0,
            valid: 0,
            invalid: 0,
            errors: Vec::new(),
        }
    };

    let mut checks = Vec::new();
    if options.schema {
        checks.push(schema_section(&validation));
    }

    let mut repair_items = Vec::new();
    let mut loaded_findings = None;
    if let Ok(frontier) = repo::load_from_path(source_path) {
        loaded_findings = Some(frontier.findings.len());
        if options.lint {
            checks.push(lint_section("lint", lint::lint(&frontier, None, None)));
        }
        if options.graph {
            checks.push(lint_section("graph", lint::lint_frontier(&frontier)));
        }
        if options.repair_plan {
            repair_items = normalize::plan_project_changes(&frontier)
                .into_iter()
                .enumerate()
                .map(|(idx, change)| RepairPlanItem {
                    id: format!("repair_{:04}", idx + 1),
                    finding_id: change.finding_id,
                    path: change.path,
                    action: change.description,
                    before: change.before,
                    after: change.after,
                    safe: change.safe,
                })
                .collect();
        }
    } else if !options.schema {
        checks.push(QualityCheckSection {
            id: "load".to_string(),
            status: "fail".to_string(),
            checked: 0,
            failed: 1,
            diagnostics: vec![QualityDiagnostic {
                check_id: "load".to_string(),
                severity: "error".to_string(),
                rule_id: "load".to_string(),
                finding_id: None,
                file: Some(source.clone()),
                path: None,
                message: "Failed to load frontier source".to_string(),
                suggestion: Some(
                    "Provide a frontier JSON file, VelaRepo, or packet directory".to_string(),
                ),
                fixability: Fixability::ManualReview,
            }],
        });
    }

    let errors = checks
        .iter()
        .flat_map(|c| c.diagnostics.iter())
        .filter(|d| d.severity == "error")
        .count();
    let warnings = checks
        .iter()
        .flat_map(|c| c.diagnostics.iter())
        .filter(|d| d.severity == "warning")
        .count();
    let info = checks
        .iter()
        .flat_map(|c| c.diagnostics.iter())
        .filter(|d| d.severity == "info")
        .count();
    let status = if errors > 0 {
        "fail"
    } else if warnings > 0 || info > 0 {
        "warn"
    } else {
        "pass"
    };
    let safe_repairs = repair_items.iter().filter(|item| item.safe).count();

    QualityCheckReport {
        ok: errors == 0,
        command: "check".to_string(),
        schema_version: vela_protocol::project::VELA_SCHEMA_VERSION.to_string(),
        source,
        source_kind,
        summary: QualitySummary {
            status: status.to_string(),
            checked_findings: if options.schema {
                validation.total_files
            } else {
                loaded_findings.unwrap_or(0)
            },
            valid_findings: if options.schema {
                validation.valid
            } else {
                loaded_findings.unwrap_or(0)
            },
            invalid_findings: if options.schema {
                validation.invalid
            } else {
                errors
            },
            errors,
            warnings,
            info,
            safe_repairs,
        },
        checks,
        repair_plan: RepairPlan {
            deterministic: true,
            safe_items: safe_repairs,
            items: repair_items,
        },
    }
}

pub fn quality_report_json(
    source_path: &Path,
    options: QualityCheckOptions,
) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(&quality_report(source_path, options))
}

fn schema_section(report: &ValidationReport) -> QualityCheckSection {
    let diagnostics = report
        .errors
        .iter()
        .map(|error| QualityDiagnostic {
            check_id: "schema".to_string(),
            severity: "error".to_string(),
            rule_id: schema_rule_id(&error.error).to_string(),
            finding_id: if error.file.starts_with("vf_") {
                Some(error.file.clone())
            } else {
                None
            },
            file: Some(error.file.clone()),
            path: None,
            message: error.error.clone(),
            suggestion: schema_suggestion(&error.error).map(str::to_string),
            fixability: schema_fixability(&error.error),
        })
        .collect::<Vec<_>>();

    QualityCheckSection {
        id: "schema".to_string(),
        status: if diagnostics.is_empty() {
            "pass".to_string()
        } else {
            "fail".to_string()
        },
        checked: report.total_files,
        failed: report.invalid,
        diagnostics,
    }
}

fn lint_section(id: &str, report: lint::LintReport) -> QualityCheckSection {
    let failed = report
        .diagnostics
        .iter()
        .filter(|d| d.severity == lint::Severity::Error)
        .count();
    let diagnostics = report
        .diagnostics
        .into_iter()
        .map(|diagnostic| QualityDiagnostic {
            check_id: id.to_string(),
            severity: diagnostic.severity.to_string(),
            rule_id: diagnostic.rule_id.clone(),
            finding_id: Some(diagnostic.finding_id),
            file: None,
            path: None,
            message: diagnostic.message,
            suggestion: Some(diagnostic.suggestion),
            fixability: lint_fixability(&diagnostic.rule_id),
        })
        .collect::<Vec<_>>();

    QualityCheckSection {
        id: id.to_string(),
        status: if failed > 0 {
            "fail".to_string()
        } else if diagnostics.is_empty() {
            "pass".to_string()
        } else {
            "warn".to_string()
        },
        checked: report.findings_checked,
        failed,
        diagnostics,
    }
}

fn schema_rule_id(message: &str) -> &'static str {
    if message.contains("Invalid entity type") {
        "schema.entity_type"
    } else if message.contains("Invalid assertion type") {
        "schema.assertion_type"
    } else if message.contains("Invalid evidence type") {
        "schema.evidence_type"
    } else if message.contains("does not match content-address") {
        "schema.content_address"
    } else if message.contains("Duplicate finding ID") {
        "schema.duplicate_id"
    } else if message.contains("does not exist in frontier") {
        "schema.link_target"
    } else if message.contains("not RFC3339") {
        "schema.timestamp"
    } else if message.contains("Project stats.") {
        "schema.project_stats"
    } else if message.contains("Packet validation failed") {
        "schema.packet"
    } else if message.contains("Failed to load") {
        "schema.load"
    } else {
        "schema"
    }
}

fn schema_suggestion(message: &str) -> Option<&'static str> {
    if message.contains("Invalid entity type") {
        Some("Run the normalization plan/apply API to map entity types to schema vocabulary")
    } else if message.contains("Project stats.") {
        Some("Reassemble or resave the frontier after applying content changes")
    } else if message.contains("does not match content-address") {
        Some(
            "Recompute finding IDs and update dependent links only after reviewing the identity change",
        )
    } else if message.contains("does not exist in frontier") {
        Some("Remove the broken link or add the missing target finding")
    } else {
        None
    }
}

fn schema_fixability(message: &str) -> Fixability {
    if message.contains("Invalid entity type") {
        Fixability::Safe
    } else if message.contains("Packet validation failed") || message.contains("Failed to load") {
        Fixability::NotFixable
    } else {
        Fixability::ManualReview
    }
}

fn lint_fixability(rule_id: &str) -> Fixability {
    match rule_id {
        "orphan"
        | "missing_crossref"
        | "unresolved_contradiction"
        | "critical_gap"
        | "fragile_anchor"
        | "stale_superseded"
        | "L001"
        | "L002"
        | "L003"
        | "L004"
        | "L005"
        | "L006"
        | "L007"
        | "L008"
        | "L009"
        | "L010" => Fixability::ManualReview,
        _ => Fixability::NotFixable,
    }
}

fn source_kind(source: &repo::VelaSource) -> &'static str {
    match source {
        repo::VelaSource::ProjectFile(_) => "project_file",
        repo::VelaSource::VelaRepo(_) => "vela_repo",
        repo::VelaSource::PacketDir(_) => "packet_dir",
    }
}

/// Validate all findings in a frontier against the schema.
pub fn validate(source_path: &Path) -> ValidationReport {
    let source_label = source_path.display().to_string();
    let frontier = match repo::load_from_path(source_path) {
        Ok(c) => c,
        Err(e) => {
            return ValidationReport {
                total_files: 0,
                valid: 0,
                invalid: 0,
                errors: vec![ValidationError {
                    file: source_path.display().to_string(),
                    error: format!("Failed to load: {e}"),
                }],
            };
        }
    };

    let mut errors: Vec<ValidationError> = Vec::new();
    let mut seen_ids: HashSet<String> = HashSet::new();
    let all_ids: HashSet<String> = frontier.findings.iter().map(|f| f.id.clone()).collect();
    // v0.8: declared cross-frontier dependencies. Any link target of
    // the form `vf_X@vfr_Y` must reference a Y in this set.
    let declared_deps: HashSet<String> = frontier
        .cross_frontier_deps()
        .filter_map(|d| d.vfr_id.clone())
        .collect();

    if matches!(
        repo::detect(source_path),
        Ok(repo::VelaSource::PacketDir(_))
    ) && let Err(packet_err) = packet::validate(source_path)
    {
        errors.push(ValidationError {
            file: source_label.clone(),
            error: format!("Packet validation failed: {packet_err}"),
        });
    }

    validate_project_metadata(&frontier, source_path, &mut errors);

    // v0.8: every cross-frontier dep must declare both a locator and
    // a pinned snapshot hash. Without those the dep can be neither
    // fetched nor verified, so a strict reader rejects.
    for dep in frontier.cross_frontier_deps() {
        let Some(vfr) = &dep.vfr_id else { continue };
        if dep.locator.as_deref().unwrap_or("").is_empty() {
            errors.push(ValidationError {
                file: source_label.clone(),
                error: format!("Cross-frontier dependency '{vfr}' is missing 'locator'"),
            });
        }
        if dep.pinned_snapshot_hash.as_deref().unwrap_or("").is_empty() {
            errors.push(ValidationError {
                file: source_label.clone(),
                error: format!(
                    "Cross-frontier dependency '{vfr}' is missing 'pinned_snapshot_hash'"
                ),
            });
        }
    }

    for finding in &frontier.findings {
        let file_label = &finding.id;
        validate_finding(
            finding,
            file_label,
            &all_ids,
            &declared_deps,
            &mut seen_ids,
            &mut errors,
        );
    }

    let invalid_count = errors.iter().map(|e| &e.file).collect::<HashSet<_>>().len();
    let valid_count = frontier.findings.len().saturating_sub(invalid_count);

    ValidationReport {
        total_files: frontier.findings.len(),
        valid: valid_count,
        invalid: invalid_count,
        errors,
    }
}

fn validate_finding(
    finding: &FindingBundle,
    file_label: &str,
    all_ids: &HashSet<String>,
    declared_deps: &HashSet<String>,
    seen_ids: &mut HashSet<String>,
    errors: &mut Vec<ValidationError>,
) {
    // Check ID pattern: vf_ + 16 hex chars
    let id_valid = finding.id.starts_with("vf_")
        && finding.id.len() == 19
        && finding.id[3..].chars().all(|c| c.is_ascii_hexdigit());
    if !id_valid {
        errors.push(ValidationError {
            file: file_label.to_string(),
            error: format!(
                "Invalid ID format '{}': expected vf_ + 16 hex chars",
                finding.id
            ),
        });
    }

    // Duplicate ID check
    if !seen_ids.insert(finding.id.clone()) {
        errors.push(ValidationError {
            file: file_label.to_string(),
            error: format!("Duplicate finding ID '{}'", finding.id),
        });
    }

    // Required fields presence (these are enforced by Rust types, but
    // check for empty strings which indicate missing data)
    if finding.assertion.text.is_empty() {
        errors.push(ValidationError {
            file: file_label.to_string(),
            error: "Assertion text is empty".to_string(),
        });
    }

    if finding.created.is_empty() {
        errors.push(ValidationError {
            file: file_label.to_string(),
            error: "Created timestamp is empty".to_string(),
        });
    }
    if !finding.created.is_empty() && DateTime::parse_from_rfc3339(&finding.created).is_err() {
        errors.push(ValidationError {
            file: file_label.to_string(),
            error: format!("Created timestamp '{}' is not RFC3339", finding.created),
        });
    }
    if let Some(updated) = &finding.updated
        && !updated.is_empty()
        && DateTime::parse_from_rfc3339(updated).is_err()
    {
        errors.push(ValidationError {
            file: file_label.to_string(),
            error: format!("Updated timestamp '{}' is not RFC3339", updated),
        });
    }

    let expected_id = FindingBundle::content_address(&finding.assertion, &finding.provenance);
    if finding.id != expected_id {
        errors.push(ValidationError {
            file: file_label.to_string(),
            error: format!(
                "Finding id '{}' does not match content-address '{}'",
                finding.id, expected_id
            ),
        });
    }

    // Confidence score range
    if !(0.0..=1.0).contains(&finding.confidence.score) {
        errors.push(ValidationError {
            file: file_label.to_string(),
            error: format!(
                "Confidence score {} is outside 0.0-1.0 range",
                finding.confidence.score
            ),
        });
    }

    // Assertion type validation
    if !VALID_ASSERTION_TYPES.contains(&finding.assertion.assertion_type.as_str()) {
        errors.push(ValidationError {
            file: file_label.to_string(),
            error: format!(
                "Invalid assertion type '{}'. Valid: {}",
                finding.assertion.assertion_type,
                VALID_ASSERTION_TYPES.join(", "),
            ),
        });
    }

    // Evidence type validation
    if !VALID_EVIDENCE_TYPES.contains(&finding.evidence.evidence_type.as_str()) {
        errors.push(ValidationError {
            file: file_label.to_string(),
            error: format!(
                "Invalid evidence type '{}'. Valid: {}",
                finding.evidence.evidence_type,
                VALID_EVIDENCE_TYPES.join(", "),
            ),
        });
    }

    for entity in &finding.assertion.entities {
        if !VALID_ENTITY_TYPES.contains(&entity.entity_type.as_str()) {
            errors.push(ValidationError {
                file: file_label.to_string(),
                error: format!(
                    "Invalid entity type '{}' for entity '{}'. Valid: {}",
                    entity.entity_type,
                    entity.name,
                    VALID_ENTITY_TYPES.join(", "),
                ),
            });
        }
    }

    if !VALID_PROVENANCE_SOURCE_TYPES.contains(&finding.provenance.source_type.as_str()) {
        errors.push(ValidationError {
            file: file_label.to_string(),
            error: format!(
                "Invalid source_type '{}'. Valid: {}",
                finding.provenance.source_type,
                VALID_PROVENANCE_SOURCE_TYPES.join(", "),
            ),
        });
    }

    if !VALID_EXTRACT_METHODS.contains(&finding.provenance.extraction.method.as_str()) {
        errors.push(ValidationError {
            file: file_label.to_string(),
            error: format!(
                "Invalid extraction method '{}'. Valid: {}",
                finding.provenance.extraction.method,
                VALID_EXTRACT_METHODS.join(", "),
            ),
        });
    }

    if finding.confidence.method == ConfidenceMethod::Computed
        && finding.confidence.components.is_none()
    {
        errors.push(ValidationError {
            file: file_label.to_string(),
            error: "Computed confidence must include components".to_string(),
        });
    }

    // Link targets must either reference an existing in-frontier vf_id
    // (`vf_…`) or, in v0.8+, a vf_id in a declared cross-frontier dep
    // (`vf_…@vfr_…`).
    for link in &finding.links {
        match vela_protocol::bundle::LinkRef::parse(&link.target) {
            Err(e) => {
                errors.push(ValidationError {
                    file: file_label.to_string(),
                    error: format!("Invalid link target '{}': {e}", link.target),
                });
            }
            Ok(vela_protocol::bundle::LinkRef::Local { vf_id }) => {
                // Old shape: must be vf_ + 16 hex (19 chars total) and
                // exist in the current frontier.
                let id_well_formed =
                    vf_id.len() == 19 && vf_id[3..].chars().all(|c| c.is_ascii_hexdigit());
                if !id_well_formed {
                    errors.push(ValidationError {
                        file: file_label.to_string(),
                        error: format!("Invalid link target format '{}'", link.target),
                    });
                } else if !all_ids.contains(&vf_id) {
                    errors.push(ValidationError {
                        file: file_label.to_string(),
                        error: format!("Link target '{}' does not exist in frontier", link.target),
                    });
                }
            }
            Ok(vela_protocol::bundle::LinkRef::Cross { vf_id, vfr_id }) => {
                // v0.8 cross-frontier link: well-formed ids, plus the
                // referenced vfr_id must appear in
                // `frontier.dependencies`. We don't verify the remote's
                // snapshot_hash here — that's the registry's job at
                // pull time. Validation only enforces declaration.
                let vf_well_formed =
                    vf_id.len() == 19 && vf_id[3..].chars().all(|c| c.is_ascii_hexdigit());
                let vfr_well_formed =
                    vfr_id.len() == 20 && vfr_id[4..].chars().all(|c| c.is_ascii_hexdigit());
                if !vf_well_formed {
                    errors.push(ValidationError {
                        file: file_label.to_string(),
                        error: format!(
                            "Invalid cross-frontier link target '{}': vf_ part must be 19 chars (vf_ + 16 hex)",
                            link.target
                        ),
                    });
                }
                if !vfr_well_formed {
                    errors.push(ValidationError {
                        file: file_label.to_string(),
                        error: format!(
                            "Invalid cross-frontier link target '{}': vfr_ part must be 20 chars (vfr_ + 16 hex)",
                            link.target
                        ),
                    });
                }
                if vfr_well_formed && !declared_deps.contains(&vfr_id) {
                    errors.push(ValidationError {
                        file: file_label.to_string(),
                        error: format!(
                            "Cross-frontier link target '{}' references undeclared dependency '{}'; add it via `vela frontier add-dep`",
                            link.target, vfr_id
                        ),
                    });
                }
            }
        }
        if link.created_at.is_empty() {
            errors.push(ValidationError {
                file: file_label.to_string(),
                error: format!("Link created_at is empty for target '{}'", link.target),
            });
        } else if DateTime::parse_from_rfc3339(&link.created_at).is_err() {
            errors.push(ValidationError {
                file: file_label.to_string(),
                error: format!("Link created_at '{}' is not RFC3339", link.created_at),
            });
        }
        if !VALID_LINK_TYPES.contains(&link.link_type.as_str()) {
            errors.push(ValidationError {
                file: file_label.to_string(),
                error: format!("Invalid link type '{}'", link.link_type),
            });
        }
        if !VALID_LINK_INFERRED_BY.contains(&link.inferred_by.as_str()) {
            errors.push(ValidationError {
                file: file_label.to_string(),
                error: format!("Invalid link inferred_by '{}'", link.inferred_by),
            });
        }
    }
}

fn validate_project_metadata(
    frontier: &vela_protocol::project::Project,
    source_path: &Path,
    errors: &mut Vec<ValidationError>,
) {
    // `vela_version` and `schema` are publisher-claimed, like the compiler
    // stamp. Pre-v0.10 frontiers (BBB at v0.8.0, the v0.8 conformance vector)
    // must continue to validate under newer binaries without recomputing
    // their content-addressed identity. v0.10's enum extensions are additive,
    // so any pre-v0.10 schema URL listed in `KNOWN_SCHEMA_URLS` validates
    // against the current code.
    const KNOWN_VELA_VERSIONS: &[&str] = &["0.8.0", "0.10.0"];
    const KNOWN_SCHEMA_URLS: &[&str] = &[
        "https://vela.science/schema/finding-bundle/v0.8.0",
        "https://vela.science/schema/finding-bundle/v0.10.0",
    ];
    if !KNOWN_VELA_VERSIONS.contains(&frontier.vela_version.as_str()) {
        errors.push(ValidationError {
            file: source_path.display().to_string(),
            error: format!(
                "Unknown vela_version '{}': expected one of {}",
                frontier.vela_version,
                KNOWN_VELA_VERSIONS.join(", "),
            ),
        });
    }
    if !KNOWN_SCHEMA_URLS.contains(&frontier.schema.as_str()) {
        errors.push(ValidationError {
            file: source_path.display().to_string(),
            error: format!(
                "Unknown schema '{}': expected one of {}",
                frontier.schema,
                KNOWN_SCHEMA_URLS.join(", "),
            ),
        });
    }
    // The compiler stamp is publisher-claimed — it records which binary
    // *produced* the canonical bytes, not which binary may validate them.
    // We require the `vela/X.Y.Z` shape (so it's still a structured field
    // and not free-form prose) but allow any version, current or older,
    // so frontiers compiled with a v0.7 binary continue to validate under
    // a v0.9 binary without churning their content-addressed identity.
    if !frontier.project.compiler.starts_with("vela/")
        || frontier.project.compiler.len() <= "vela/".len()
    {
        errors.push(ValidationError {
            file: source_path.display().to_string(),
            error: format!(
                "Invalid compiler '{}': expected 'vela/X.Y.Z'",
                frontier.project.compiler,
            ),
        });
    }
    if frontier.project.compiled_at.is_empty() {
        errors.push(ValidationError {
            file: source_path.display().to_string(),
            error: "Project compiled_at is empty".to_string(),
        });
    } else if DateTime::parse_from_rfc3339(&frontier.project.compiled_at).is_err() {
        errors.push(ValidationError {
            file: source_path.display().to_string(),
            error: format!(
                "Project compiled_at '{}' is not RFC3339",
                frontier.project.compiled_at
            ),
        });
    }

    let expected_links: usize = frontier.findings.iter().map(|f| f.links.len()).sum();
    if frontier.stats.findings != frontier.findings.len() {
        errors.push(ValidationError {
            file: source_path.display().to_string(),
            error: format!(
                "Project stats.findings {} does not match findings length {}",
                frontier.stats.findings,
                frontier.findings.len()
            ),
        });
    }
    if frontier.stats.links != expected_links {
        errors.push(ValidationError {
            file: source_path.display().to_string(),
            error: format!(
                "Project stats.links {} does not match aggregated links {}",
                frontier.stats.links, expected_links
            ),
        });
    }
}

/// CLI entry point for `vela validate`.
pub fn run(source: &Path) {
    let report = validate(source);

    println!();
    println!("  {}", "VELA · VALIDATE".dimmed());
    println!("  {}", style::tick_row(60));
    println!("  total findings: {}", report.total_files);
    println!(
        "  valid:           {}",
        style::moss(report.valid.to_string())
    );
    println!(
        "  invalid:         {}",
        if report.invalid > 0 {
            style::madder(report.invalid.to_string()).to_string()
        } else {
            report.invalid.to_string()
        }
    );

    if !report.errors.is_empty() {
        println!();
        println!("  {}", "ERRORS".dimmed());
        for err in &report.errors {
            println!(
                "  {} {} · {}",
                style::madder("-"),
                err.file.dimmed(),
                err.error
            );
        }
    } else {
        println!("\n  {} all findings valid.", style::ok("ok"));
    }

    if report.invalid > 0 {
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use tempfile::TempDir;
    use vela_protocol::bundle::*;
    use vela_protocol::project;

    fn make_valid_finding(seed: &str) -> FindingBundle {
        let assertion = Assertion {
            text: format!("Test assertion {}", seed),
            assertion_type: "mechanism".into(),
            entities: vec![],
            relation: None,
            direction: None,
            causal_claim: None,
            causal_evidence_grade: None,
        };
        let provenance = Provenance {
            source_type: "published_paper".into(),
            doi: Some(format!("10.0000/{}", seed)),
            pmid: None,
            pmc: None,
            openalex_id: None,
            url: None,
            title: format!("Test {seed}"),
            authors: vec![],
            year: Some(2024),
            journal: None,
            license: None,
            publisher: None,
            funders: vec![],
            extraction: Extraction {
                method: "llm_extraction".into(),
                model: None,
                model_version: None,
                extracted_at: "1970-01-01T00:00:00Z".to_string(),
                extractor_version: "vela/0.2.0".to_string(),
            },
            review: None,
            citation_count: None,
        };
        let mut finding = FindingBundle::new(
            assertion,
            Evidence {
                evidence_type: "experimental".into(),
                model_system: String::new(),
                species: None,
                method: String::new(),
                sample_size: None,
                effect_size: None,
                p_value: None,
                replicated: false,
                replication_count: None,
                evidence_spans: vec![],
            },
            Conditions {
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
            },
            Confidence::raw(0.85, "test", 0.9),
            provenance,
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
            },
        );
        finding.id = FindingBundle::content_address(&finding.assertion, &finding.provenance);
        finding
    }

    fn write_frontier(dir: &Path, findings: Vec<FindingBundle>) -> std::path::PathBuf {
        let c = project::assemble("test", findings, 1, 0, "Test");
        let path = dir.join("test.json");
        let json = serde_json::to_string_pretty(&c).unwrap();
        std::fs::write(&path, json).unwrap();
        path
    }

    fn write_project(dir: &Path, frontier: &project::Project) -> std::path::PathBuf {
        let path = dir.join("test.json");
        let json = serde_json::to_string_pretty(frontier).unwrap();
        std::fs::write(&path, json).unwrap();
        path
    }

    #[test]
    fn valid_frontier_passes() {
        let tmp = TempDir::new().unwrap();
        let path = write_frontier(
            tmp.path(),
            vec![
                make_valid_finding("vf_0000000000000001"),
                make_valid_finding("vf_0000000000000002"),
            ],
        );
        let report = validate(&path);
        assert_eq!(report.total_files, 2);
        assert_eq!(report.valid, 2);
        assert_eq!(report.invalid, 0);
        assert!(report.errors.is_empty());
    }

    #[test]
    fn project_metadata_validation() {
        let tmp = TempDir::new().unwrap();
        let mut c = project::assemble(
            "test",
            vec![make_valid_finding("vf_0000000000000001")],
            1,
            0,
            "Test",
        );
        c.vela_version = "0.1.0".into();
        let path = write_project(tmp.path(), &c);
        let report = validate(&path);
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.error.contains("Unknown vela_version"))
        );
    }

    #[test]
    fn invalid_provenance_source_type_detected() {
        let tmp = TempDir::new().unwrap();
        let mut f = make_valid_finding("vf_0000000000000001");
        f.provenance.source_type = "invalid_source".into();
        let path = write_frontier(tmp.path(), vec![f]);
        let report = validate(&path);
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.error.contains("Invalid source_type"))
        );
    }

    #[test]
    fn invalid_extraction_method_detected() {
        let tmp = TempDir::new().unwrap();
        let mut f = make_valid_finding("vf_0000000000000001");
        f.provenance.extraction.method = "invalid_method".into();
        let path = write_frontier(tmp.path(), vec![f]);
        let report = validate(&path);
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.error.contains("Invalid extraction method"))
        );
    }

    #[test]
    fn invalid_computed_confidence_components_detected() {
        let tmp = TempDir::new().unwrap();
        let mut f = make_valid_finding("vf_0000000000000001");
        f.confidence.method = ConfidenceMethod::Computed;
        f.confidence.components = None;
        let path = write_frontier(tmp.path(), vec![f]);
        let report = validate(&path);
        assert!(report.errors.iter().any(|e| {
            e.error
                .contains("Computed confidence must include components")
        }));
    }

    #[test]
    fn invalid_content_address_detected() {
        let tmp = TempDir::new().unwrap();
        let mut f = make_valid_finding("vf_0000000000000001");
        f.id = "vf_0000000000000002".into();
        let path = write_frontier(tmp.path(), vec![f]);
        let report = validate(&path);
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.error.contains("does not match content-address"))
        );
    }

    #[test]
    fn invalid_link_type_detected() {
        let tmp = TempDir::new().unwrap();
        let mut f = make_valid_finding("vf_link_type");
        let target = f.id.clone();
        f.links.push(Link {
            target,
            link_type: "bad_type".into(),
            note: String::new(),
            inferred_by: "compiler".into(),
            created_at: Utc::now().to_rfc3339(),
            mechanism: None,
        });
        let path = write_frontier(tmp.path(), vec![f]);
        let report = validate(&path);
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.error.contains("Invalid link type"))
        );
    }

    #[test]
    fn t7_link_types_are_accepted() {
        // The T7 additions (improves/generalizes/specializes) must
        // pass link-type validation alongside the legacy vocabulary.
        for link_type in ["improves", "generalizes", "specializes"] {
            let tmp = TempDir::new().unwrap();
            let mut f = make_valid_finding("vf_t7_link");
            let target = f.id.clone();
            f.links.push(Link {
                target,
                link_type: link_type.into(),
                note: String::new(),
                inferred_by: "reviewer".into(),
                created_at: Utc::now().to_rfc3339(),
                mechanism: None,
            });
            let path = write_frontier(tmp.path(), vec![f]);
            let report = validate(&path);
            assert!(
                !report
                    .errors
                    .iter()
                    .any(|e| e.error.contains("Invalid link type")),
                "link type {link_type} should be valid"
            );
        }
    }

    #[test]
    fn invalid_id_format_detected() {
        let tmp = TempDir::new().unwrap();
        let mut f = make_valid_finding("bad_id");
        f.id = "bad_id".into();
        let path = write_frontier(tmp.path(), vec![f]);
        let report = validate(&path);
        assert!(report.invalid > 0);
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.error.contains("Invalid ID format"))
        );
    }

    #[test]
    fn invalid_confidence_detected() {
        let tmp = TempDir::new().unwrap();
        let mut f = make_valid_finding("vf_0000000000000001");
        f.confidence.score = 1.5;
        let path = write_frontier(tmp.path(), vec![f]);
        let report = validate(&path);
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.error.contains("Confidence score"))
        );
    }

    #[test]
    fn invalid_assertion_type_detected() {
        let tmp = TempDir::new().unwrap();
        let mut f = make_valid_finding("vf_0000000000000001");
        f.assertion.assertion_type = "bogus_type".into();
        let path = write_frontier(tmp.path(), vec![f]);
        let report = validate(&path);
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.error.contains("Invalid assertion type"))
        );
    }

    #[test]
    fn invalid_evidence_type_detected() {
        let tmp = TempDir::new().unwrap();
        let mut f = make_valid_finding("vf_0000000000000001");
        f.evidence.evidence_type = "anecdotal".into();
        let path = write_frontier(tmp.path(), vec![f]);
        let report = validate(&path);
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.error.contains("Invalid evidence type"))
        );
    }

    #[test]
    fn broken_link_target_detected() {
        let tmp = TempDir::new().unwrap();
        let mut f = make_valid_finding("vf_0000000000000001");
        f.links.push(Link {
            target: "vf_deadbeefdeadbeef".into(),
            link_type: "extends".into(),
            note: String::new(),
            inferred_by: "compiler".into(),
            created_at: Utc::now().to_rfc3339(),
            mechanism: None,
        });
        let path = write_frontier(tmp.path(), vec![f]);
        let report = validate(&path);
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.error.contains("does not exist"))
        );
    }

    #[test]
    fn duplicate_id_detected() {
        let tmp = TempDir::new().unwrap();
        let f1 = make_valid_finding("vf_0000000000000001");
        let f2 = make_valid_finding("vf_0000000000000001");
        let path = write_frontier(tmp.path(), vec![f1, f2]);
        let report = validate(&path);
        assert!(report.errors.iter().any(|e| e.error.contains("Duplicate")));
    }

    #[test]
    fn invalid_entity_type_detected_and_marked_fixable() {
        let tmp = TempDir::new().unwrap();
        let mut f = make_valid_finding("vf_0000000000000001");
        f.assertion.entities.push(Entity {
            // Invalid type (coerces to anatomical_structure) + a name with
            // surrounding whitespace (trims): two distinct safe repairs.
            name: "  Sidon set  ".into(),
            entity_type: "biological_barrier".into(),
            identifiers: serde_json::Map::new(),
            canonical_id: None,
            candidates: vec![],
            aliases: vec![],
            resolution_provenance: None,
            resolution_confidence: 1.0,
            resolution_method: None,
            species_context: None,
            needs_review: false,
        });
        f.id = FindingBundle::content_address(&f.assertion, &f.provenance);
        let path = write_frontier(tmp.path(), vec![f]);

        let report = quality_report(&path, QualityCheckOptions::default());

        assert!(
            report
                .checks
                .iter()
                .flat_map(|check| check.diagnostics.iter())
                .any(|diagnostic| diagnostic.rule_id == "schema.entity_type"
                    && diagnostic.fixability == Fixability::Safe)
        );
        assert!(report.repair_plan.safe_items >= 2);
    }

    #[test]
    fn quality_report_includes_schema_lint_and_graph_sections() {
        let tmp = TempDir::new().unwrap();
        let mut f = make_valid_finding("vf_0000000000000001");
        f.evidence.sample_size = Some("n=4".into());
        f.evidence.replicated = false;
        f.confidence.score = 0.9;
        f.id = FindingBundle::content_address(&f.assertion, &f.provenance);
        let path = write_frontier(tmp.path(), vec![f]);

        let report = quality_report(&path, QualityCheckOptions::default());

        assert!(report.checks.iter().any(|check| check.id == "schema"));
        assert!(report.checks.iter().any(|check| check.id == "lint"));
        assert!(report.checks.iter().any(|check| check.id == "graph"));
        assert!(
            report
                .checks
                .iter()
                .flat_map(|check| check.diagnostics.iter())
                .any(|diagnostic| diagnostic.rule_id == "L001")
        );
        assert!(
            report
                .checks
                .iter()
                .flat_map(|check| check.diagnostics.iter())
                .any(|diagnostic| diagnostic.rule_id == "orphan")
        );
    }

    // ── v0.8: cross-frontier link validation ──────────────────────────

    fn make_finding_with_link(seed: &str, target: &str) -> FindingBundle {
        let mut f = make_valid_finding(seed);
        f.links = vec![Link {
            target: target.to_string(),
            link_type: "extends".to_string(),
            note: String::new(),
            inferred_by: "compiler".to_string(),
            created_at: "2024-01-01T00:00:00Z".to_string(),
            mechanism: None,
        }];
        f
    }

    #[test]
    fn cross_frontier_link_with_declared_dep_passes() {
        let tmp = TempDir::new().unwrap();
        let target_vfr = "vfr_0000000000000aaa";
        let f1 = make_valid_finding("vf_0000000000000001");
        let f2 = make_finding_with_link(
            "vf_0000000000000002",
            &format!("vf_0000000000000003@{target_vfr}"),
        );
        let mut c = project::assemble("test", vec![f1, f2], 1, 0, "Test");
        c.project.dependencies.push(project::ProjectDependency {
            name: "ext-frontier".into(),
            source: "vela.hub".into(),
            version: None,
            pinned_hash: None,
            vfr_id: Some(target_vfr.into()),
            locator: Some("https://example.test/ext.json".into()),
            pinned_snapshot_hash: Some("a".repeat(64)),
        });
        let path = write_project(tmp.path(), &c);
        let report = validate(&path);
        let cross_errors: Vec<_> = report
            .errors
            .iter()
            .filter(|e| e.error.contains("cross-frontier") || e.error.contains("undeclared"))
            .collect();
        assert!(
            cross_errors.is_empty(),
            "expected no cross-frontier errors, got: {cross_errors:?}",
        );
    }

    #[test]
    fn cross_frontier_link_without_declared_dep_fails() {
        let tmp = TempDir::new().unwrap();
        let f = make_finding_with_link(
            "vf_0000000000000001",
            "vf_0000000000000002@vfr_0000000000000bbb",
        );
        let path = write_frontier(tmp.path(), vec![f]);
        let report = validate(&path);
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.error.contains("undeclared dependency")),
            "expected undeclared-dep error, got: {:?}",
            report.errors
        );
    }

    #[test]
    fn cross_frontier_dep_without_locator_or_snapshot_fails() {
        let tmp = TempDir::new().unwrap();
        let mut c = project::assemble(
            "test",
            vec![make_valid_finding("vf_0000000000000001")],
            1,
            0,
            "Test",
        );
        c.project.dependencies.push(project::ProjectDependency {
            name: "incomplete-dep".into(),
            source: "vela.hub".into(),
            version: None,
            pinned_hash: None,
            vfr_id: Some("vfr_0000000000000ccc".into()),
            locator: None,
            pinned_snapshot_hash: None,
        });
        let path = write_project(tmp.path(), &c);
        let report = validate(&path);
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.error.contains("missing 'locator'")),
            "expected missing-locator error",
        );
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.error.contains("missing 'pinned_snapshot_hash'")),
            "expected missing-snapshot error",
        );
    }

    #[test]
    fn malformed_cross_frontier_link_target_fails() {
        let tmp = TempDir::new().unwrap();
        // bad: vfr_ part is not 16 hex chars
        let f = make_finding_with_link("vf_0000000000000001", "vf_0000000000000002@vfr_too_short");
        let path = write_frontier(tmp.path(), vec![f]);
        let report = validate(&path);
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.error.contains("vfr_ part must be 20 chars")),
            "expected malformed-vfr error, got: {:?}",
            report.errors
        );
    }
}
