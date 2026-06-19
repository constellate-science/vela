//! Stage 3: NORMALIZE — deduplicate entities, constrain types to schema.

use vela_protocol::bundle::FindingBundle;
use vela_protocol::project::Project;
use vela_protocol::repo::{self, VelaSource};
use vela_protocol::sources;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::path::Path;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizeOptions {
    /// When true, compute the same deterministic plan without writing changes.
    pub dry_run: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NormalizeChangeKind {
    EntityType,
    EntityName,
    DuplicateEntity,
    FindingId,
    LinkTarget,
    SourceRecord,
    EvidenceAtom,
    ConditionRecord,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NormalizeChange {
    pub kind: NormalizeChangeKind,
    pub finding_id: String,
    pub path: String,
    pub before: Value,
    pub after: Value,
    pub safe: bool,
    pub description: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizeSummary {
    pub planned: usize,
    pub safe: usize,
    pub unsafe_count: usize,
    pub applied: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NormalizeReport {
    pub source: String,
    pub source_kind: String,
    pub dry_run: bool,
    pub refused: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refusal_reason: Option<String>,
    pub summary: NormalizeSummary,
    pub changes: Vec<NormalizeChange>,
}

impl NormalizeReport {
    fn refused(source: &Path, source_kind: &str, dry_run: bool, reason: String) -> Self {
        Self {
            source: source.display().to_string(),
            source_kind: source_kind.to_string(),
            dry_run,
            refused: true,
            refusal_reason: Some(reason),
            summary: NormalizeSummary::default(),
            changes: Vec::new(),
        }
    }
}

/// Normalize an entity type to canonical form. Domain-general: lower-case
/// and collapse surrounding whitespace only. The pre-math-wedge biology
/// type table (mapping LLM-invented types onto a fixed schema vocabulary)
/// lived here; a frontier's type coercion belongs in its own ingest
/// config, not hard-coded into the substrate.
pub fn entity_type(raw: &str) -> String {
    raw.trim().to_lowercase()
}

/// Normalize an entity name to canonical form. Domain-general: collapse
/// surrounding whitespace only. Domain-specific alias tables (the
/// pre-math-wedge biology vocabulary lived here) belong in a frontier's
/// own ingest config, not hard-coded into the substrate.
pub fn entity_name(name: &str) -> String {
    name.trim().to_string()
}

/// Build a deterministic, safe repair plan for a loaded frontier.
pub fn plan_project(frontier: &Project) -> NormalizeReport {
    let changes = plan_project_changes(frontier);
    report_from_changes("<loaded>", "loaded", true, false, None, changes, 0)
}

/// Build a deterministic repair plan for a loaded frontier, including content
/// address and internal link updates implied by entity normalization.
pub fn plan_project_changes(frontier: &Project) -> Vec<NormalizeChange> {
    let mut changes = plan_findings(&frontier.findings);
    let id_map = normalized_id_map(&frontier.findings);
    let projection = sources::derive_projection(frontier);

    for (finding_index, bundle) in frontier.findings.iter().enumerate() {
        if let Some(new_id) = id_map.get(&bundle.id) {
            changes.push(NormalizeChange {
                kind: NormalizeChangeKind::FindingId,
                finding_id: bundle.id.clone(),
                path: format!("findings[{finding_index}].id"),
                before: json!(bundle.id),
                after: json!(new_id),
                safe: true,
                description: "Rewrite finding ID to match normalized content address".to_string(),
            });
        }

        for (link_index, link) in bundle.links.iter().enumerate() {
            if let Some(new_target) = id_map.get(&link.target) {
                changes.push(NormalizeChange {
                    kind: NormalizeChangeKind::LinkTarget,
                    finding_id: bundle.id.clone(),
                    path: format!("findings[{finding_index}].links[{link_index}].target"),
                    before: json!(link.target),
                    after: json!(new_target),
                    safe: true,
                    description:
                        "Rewrite internal link target after normalized content-address update"
                            .to_string(),
                });
            }
        }
    }

    let current_source_ids = frontier
        .sources
        .iter()
        .map(|source| source.id.as_str())
        .collect::<HashSet<_>>();
    for source in &projection.sources {
        if !current_source_ids.contains(source.id.as_str()) {
            changes.push(NormalizeChange {
                kind: NormalizeChangeKind::SourceRecord,
                finding_id: source.finding_ids.first().cloned().unwrap_or_default(),
                path: format!("sources[{}]", source.id),
                before: Value::Null,
                after: json!(source),
                safe: true,
                description: "Materialize derived source record from finding provenance"
                    .to_string(),
            });
        }
    }

    let current_atom_ids = frontier
        .evidence_atoms
        .iter()
        .map(|atom| atom.id.as_str())
        .collect::<HashSet<_>>();
    for atom in &projection.evidence_atoms {
        if !current_atom_ids.contains(atom.id.as_str()) {
            changes.push(NormalizeChange {
                kind: NormalizeChangeKind::EvidenceAtom,
                finding_id: atom.finding_id.clone(),
                path: format!("evidence_atoms[{}]", atom.id),
                before: Value::Null,
                after: json!(atom),
                safe: true,
                description:
                    "Materialize derived evidence atom linking source, evidence, and finding"
                        .to_string(),
            });
        }
    }

    let current_condition_ids = frontier
        .condition_records
        .iter()
        .map(|record| record.id.as_str())
        .collect::<HashSet<_>>();
    for record in &projection.condition_records {
        if !current_condition_ids.contains(record.id.as_str()) {
            changes.push(NormalizeChange {
                kind: NormalizeChangeKind::ConditionRecord,
                finding_id: record.finding_id.clone(),
                path: format!("condition_records[{}]", record.id),
                before: Value::Null,
                after: json!(record),
                safe: true,
                description:
                    "Materialize derived condition boundary used for review and proof checks"
                        .to_string(),
            });
        }
    }

    changes
}

/// Build a deterministic, safe repair plan for findings.
pub fn plan_findings(bundles: &[FindingBundle]) -> Vec<NormalizeChange> {
    let mut changes = Vec::new();

    for (finding_index, bundle) in bundles.iter().enumerate() {
        let mut seen = HashSet::new();

        for (entity_index, entity) in bundle.assertion.entities.iter().enumerate() {
            let normalized_name = entity_name(&entity.name);
            let normalized_type = entity_type(&entity.entity_type);
            let dedupe_key = (normalized_name.to_lowercase(), normalized_type.clone());
            let entity_path =
                format!("findings[{finding_index}].assertion.entities[{entity_index}]");

            if !seen.insert(dedupe_key) {
                changes.push(NormalizeChange {
                    kind: NormalizeChangeKind::DuplicateEntity,
                    finding_id: bundle.id.clone(),
                    path: entity_path,
                    before: json!({
                        "name": entity.name,
                        "type": entity.entity_type,
                    }),
                    after: Value::Null,
                    safe: true,
                    description: "Remove duplicate entity after canonical name/type normalization"
                        .to_string(),
                });
                continue;
            }

            if normalized_type != entity.entity_type {
                changes.push(NormalizeChange {
                    kind: NormalizeChangeKind::EntityType,
                    finding_id: bundle.id.clone(),
                    path: format!("{entity_path}.type"),
                    before: json!(entity.entity_type),
                    after: json!(normalized_type),
                    safe: true,
                    description: "Map entity type to the finding-bundle schema vocabulary"
                        .to_string(),
                });
            }

            if normalized_name != entity.name {
                changes.push(NormalizeChange {
                    kind: NormalizeChangeKind::EntityName,
                    finding_id: bundle.id.clone(),
                    path: format!("{entity_path}.name"),
                    before: json!(entity.name),
                    after: json!(normalized_name),
                    safe: true,
                    description: "Map common biomedical alias to canonical display name"
                        .to_string(),
                });
            }
        }
    }

    changes
}

/// Plan normalization for a source path without writing changes.
pub fn plan_source(source_path: &Path) -> Result<NormalizeReport, String> {
    normalize_source(source_path, NormalizeOptions { dry_run: true })
}

/// Apply safe normalization repairs to a source path.
///
/// Packet directories are immutable review artifacts; applying directly to one
/// returns a refused report instead of writing into the packet.
pub fn apply_source(source_path: &Path) -> Result<NormalizeReport, String> {
    normalize_source(source_path, NormalizeOptions { dry_run: false })
}

/// Plan or apply normalization for a source path.
pub fn normalize_source(
    source_path: &Path,
    options: NormalizeOptions,
) -> Result<NormalizeReport, String> {
    let source = repo::detect(source_path)?;
    let source_kind = source_kind(&source);

    if matches!(source, VelaSource::PacketDir(_)) && !options.dry_run {
        return Ok(NormalizeReport::refused(
            source_path,
            source_kind,
            options.dry_run,
            "Refusing to normalize a frontier packet directory in place; export a new packet from a normalized frontier instead.".to_string(),
        ));
    }

    let mut frontier = repo::load(&source)?;
    let changes = plan_project_changes(&frontier);
    let applied = if options.dry_run {
        0
    } else {
        apply_project_safe_normalizations(&mut frontier)?;
        repo::save(&source, &frontier)?;
        changes.iter().filter(|c| c.safe).count()
    };

    Ok(report_from_changes(
        &source_path.display().to_string(),
        source_kind,
        options.dry_run,
        false,
        None,
        changes,
        applied,
    ))
}

fn report_from_changes(
    source: &str,
    source_kind: &str,
    dry_run: bool,
    refused: bool,
    refusal_reason: Option<String>,
    changes: Vec<NormalizeChange>,
    applied: usize,
) -> NormalizeReport {
    let safe = changes.iter().filter(|c| c.safe).count();
    let unsafe_count = changes.len().saturating_sub(safe);
    NormalizeReport {
        source: source.to_string(),
        source_kind: source_kind.to_string(),
        dry_run,
        refused,
        refusal_reason,
        summary: NormalizeSummary {
            planned: changes.len(),
            safe,
            unsafe_count,
            applied,
        },
        changes,
    }
}

fn source_kind(source: &VelaSource) -> &'static str {
    match source {
        VelaSource::ProjectFile(_) => "project_file",
        VelaSource::VelaRepo(_) => "vela_repo",
        VelaSource::PacketDir(_) => "packet_dir",
    }
}

fn apply_project_safe_normalizations(frontier: &mut Project) -> Result<usize, String> {
    let planned = plan_project_changes(frontier)
        .into_iter()
        .filter(|change| change.safe)
        .count();

    normalize_bundle_entities(&mut frontier.findings);
    rewrite_content_ids(&mut frontier.findings)?;
    sources::materialize_project(frontier);

    Ok(planned)
}

fn normalize_bundle_entities(bundles: &mut [FindingBundle]) {
    for bundle in bundles.iter_mut() {
        for entity in bundle.assertion.entities.iter_mut() {
            entity.entity_type = entity_type(&entity.entity_type);
            entity.name = entity_name(&entity.name);
        }

        let mut seen = HashSet::new();
        bundle.assertion.entities.retain(|entity| {
            let key = (entity.name.to_lowercase(), entity.entity_type.clone());
            seen.insert(key)
        });
    }
}

fn normalized_id_map(bundles: &[FindingBundle]) -> std::collections::BTreeMap<String, String> {
    let mut id_map = std::collections::BTreeMap::new();
    for bundle in bundles {
        let mut normalized = bundle.clone();
        normalize_bundle_entities(std::slice::from_mut(&mut normalized));
        let expected =
            FindingBundle::content_address(&normalized.assertion, &normalized.provenance);
        if expected != bundle.id {
            id_map.insert(bundle.id.clone(), expected);
        }
    }
    id_map
}

fn rewrite_content_ids(bundles: &mut [FindingBundle]) -> Result<(), String> {
    let mut id_map = std::collections::BTreeMap::new();
    let mut final_ids = HashSet::new();

    for bundle in bundles.iter() {
        let expected = FindingBundle::content_address(&bundle.assertion, &bundle.provenance);
        if !final_ids.insert(expected.clone()) {
            return Err(format!(
                "Refusing to rewrite IDs because normalized content address '{}' is duplicated",
                expected
            ));
        }
        if expected != bundle.id {
            id_map.insert(bundle.id.clone(), expected);
        }
    }

    for bundle in bundles.iter_mut() {
        if let Some(new_id) = id_map.get(&bundle.id) {
            bundle.id = new_id.clone();
        }
        for link in &mut bundle.links {
            if let Some(new_target) = id_map.get(&link.target) {
                link.target = new_target.clone();
            }
        }
    }

    Ok(())
}

/// Normalize all findings: fix entity types and names, deduplicate entities within findings.
pub fn normalize_findings(bundles: &mut [FindingBundle]) -> (usize, usize) {
    let mut type_fixes = 0usize;
    let mut name_fixes = 0usize;

    for b in bundles.iter_mut() {
        for e in b.assertion.entities.iter_mut() {
            let new_type = entity_type(&e.entity_type);
            if new_type != e.entity_type {
                e.entity_type = new_type;
                type_fixes += 1;
            }

            let new_name = entity_name(&e.name);
            if new_name != e.name {
                e.name = new_name;
                name_fixes += 1;
            }
        }

        // Deduplicate entities
        let mut seen = std::collections::HashSet::new();
        b.assertion.entities.retain(|e| {
            let key = (e.name.to_lowercase(), e.entity_type.clone());
            seen.insert(key)
        });
    }

    (type_fixes, name_fixes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vela_protocol::bundle::*;

    fn make_entity(name: &str, etype: &str) -> Entity {
        Entity {
            name: name.into(),
            entity_type: etype.into(),
            identifiers: serde_json::Map::new(),
            canonical_id: None,
            candidates: vec![],
            aliases: vec![],
            resolution_provenance: None,
            resolution_confidence: 1.0,
            resolution_method: None,
            species_context: None,
            needs_review: false,
        }
    }

    fn make_finding_with_entities(entities: Vec<Entity>) -> FindingBundle {
        FindingBundle {
            id: "test".into(),
            version: 1,
            previous_version: None,
            assertion: Assertion {
                text: "Test".into(),
                assertion_type: "mechanism".into(),
                entities,
                relation: None,
                direction: None,
                causal_claim: None,
                causal_evidence_grade: None,
            },
            evidence: Evidence {
                evidence_type: "experimental".into(),
                model_system: String::new(),
                method: String::new(),
                replicated: false,
                replication_count: None,
                evidence_spans: vec![],
            },
            conditions: Conditions {
                text: String::new(),
                duration: None,
            },
            confidence: Confidence::raw(0.8, "seeded prior", 0.85),
            provenance: Provenance {
                source_type: "published_paper".into(),
                doi: None,
                url: None,
                title: "Test".into(),
                authors: vec![],
                year: Some(2024),
                license: None,
                publisher: None,
                funders: vec![],
                extraction: Extraction::default(),
                review: None,
            },
            flags: Flags {
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
            links: vec![],
            annotations: vec![],
            attachments: vec![],
            created: String::new(),
            updated: None,

            access_tier: vela_protocol::access_tier::AccessTier::Public,
        }
    }

    // ── entity_type tests ────────────────────────────────────────────

    #[test]
    fn entity_type_is_domain_general_lower_and_trim() {
        // No hard-coded biology coercion table: types lower-case and
        // trim, otherwise pass through unchanged.
        assert_eq!(entity_type("structure"), "structure");
        assert_eq!(entity_type("Sidon set"), "sidon set");
        assert_eq!(entity_type("  PRIME GAP  "), "prime gap");
        assert_eq!(entity_type(""), "");
    }

    // ── entity_name tests ────────────────────────────────────────────

    #[test]
    fn entity_name_is_domain_general_trim_only() {
        // No hard-coded alias table: names pass through, with only
        // surrounding whitespace collapsed.
        assert_eq!(entity_name("Sidon set"), "Sidon set");
        assert_eq!(entity_name("  B_2[g] sequence  "), "B_2[g] sequence");
        assert_eq!(entity_name("A309370"), "A309370");
    }

    // ── normalize_findings tests ─────────────────────────────────────

    #[test]
    fn normalize_fixes_types_and_names() {
        // Types lower-case; names are trimmed. No biology coercion.
        let mut bundles = vec![make_finding_with_entities(vec![
            make_entity("  Sidon set  ", "Structure"),
            make_entity("  prime gap  ", "Condition"),
        ])];
        let (type_fixes, name_fixes) = normalize_findings(&mut bundles);
        assert_eq!(type_fixes, 2);
        assert_eq!(name_fixes, 2);
        assert_eq!(bundles[0].assertion.entities[0].name, "Sidon set");
        assert_eq!(bundles[0].assertion.entities[0].entity_type, "structure");
        assert_eq!(bundles[0].assertion.entities[1].name, "prime gap");
        assert_eq!(bundles[0].assertion.entities[1].entity_type, "condition");
    }

    #[test]
    fn deduplication_removes_duplicate_entities() {
        let mut bundles = vec![make_finding_with_entities(vec![
            make_entity("A309370", "sequence"),
            make_entity("a309370", "sequence"), // same name different case
            make_entity("A309370", "set"),      // same name different type = kept
        ])];
        let (_tf, _nf) = normalize_findings(&mut bundles);
        assert_eq!(bundles[0].assertion.entities.len(), 2); // sequence + set
    }

    #[test]
    fn normalize_no_changes_returns_zero() {
        let mut bundles = vec![make_finding_with_entities(vec![make_entity(
            "A309370", "sequence",
        )])];
        let (type_fixes, name_fixes) = normalize_findings(&mut bundles);
        assert_eq!(type_fixes, 0);
        assert_eq!(name_fixes, 0);
    }

    #[test]
    fn normalize_empty_bundles() {
        let mut bundles: Vec<FindingBundle> = vec![];
        let (tf, nf) = normalize_findings(&mut bundles);
        assert_eq!(tf, 0);
        assert_eq!(nf, 0);
    }

    #[test]
    fn plan_findings_reports_safe_entity_repairs() {
        let bundles = vec![make_finding_with_entities(vec![
            // Mixed-case type triggers a lower-case EntityType repair;
            // the trailing whitespace triggers an EntityName repair.
            make_entity("  prime gap  ", "Structure"),
            // Same name + same canonical type as the first entity once
            // both are normalized: a DuplicateEntity repair.
            make_entity("prime gap", "structure"),
        ])];

        let plan = plan_findings(&bundles);

        assert!(
            plan.iter()
                .any(|change| change.kind == NormalizeChangeKind::EntityType)
        );
        assert!(
            plan.iter()
                .any(|change| change.kind == NormalizeChangeKind::EntityName)
        );
        assert!(
            plan.iter()
                .any(|change| change.kind == NormalizeChangeKind::DuplicateEntity)
        );
        assert!(plan.iter().all(|change| change.safe));
    }

    #[test]
    fn source_dry_run_does_not_write() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("frontier.json");
        let frontier = vela_protocol::project::assemble(
            "test",
            vec![make_finding_with_entities(vec![make_entity(
                "  Sidon set  ",
                "structure",
            )])],
            1,
            0,
            "test",
        );
        std::fs::write(&path, serde_json::to_string_pretty(&frontier).unwrap()).unwrap();

        let report = plan_source(&path).unwrap();
        let saved: vela_protocol::project::Project =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();

        assert!(report.dry_run);
        assert_eq!(report.summary.applied, 0);
        assert_eq!(
            saved.findings[0].assertion.entities[0].entity_type,
            "structure"
        );
    }

    #[test]
    fn source_apply_writes_safe_repairs() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("frontier.json");
        let frontier = vela_protocol::project::assemble(
            "test",
            vec![make_finding_with_entities(vec![make_entity(
                "  Sidon set  ",
                "structure",
            )])],
            1,
            0,
            "test",
        );
        std::fs::write(&path, serde_json::to_string_pretty(&frontier).unwrap()).unwrap();

        let report = apply_source(&path).unwrap();
        let saved: vela_protocol::project::Project =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();

        assert!(!report.dry_run);
        assert_eq!(report.summary.applied, report.summary.safe);
        assert_eq!(
            saved.findings[0].assertion.entities[0].entity_type,
            "structure"
        );
        assert_eq!(saved.findings[0].assertion.entities[0].name, "Sidon set");
        assert_eq!(
            saved.findings[0].id,
            FindingBundle::content_address(
                &saved.findings[0].assertion,
                &saved.findings[0].provenance,
            )
        );
    }

    #[test]
    fn source_apply_refuses_packet_directory() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(
            tmp.path().join("manifest.json"),
            r#"{"packet_format":"vela.frontier-packet"}"#,
        )
        .unwrap();

        let report = apply_source(tmp.path()).unwrap();

        assert!(report.refused);
        assert_eq!(report.source_kind, "packet_dir");
        assert!(report.refusal_reason.unwrap().contains("Refusing"));
    }
}
