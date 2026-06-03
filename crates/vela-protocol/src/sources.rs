//! Source registry and evidence atom projections.
//!
//! Sources identify imported artifacts. Evidence atoms identify the exact
//! source-grounded unit that bears on a finding. Both are safe to derive from
//! legacy finding bundles when older frontiers do not persist them yet.

use std::collections::{BTreeMap, BTreeSet};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::bundle::{FindingBundle, Provenance};
use crate::project::Project;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceRecord {
    pub id: String,
    pub source_type: String,
    pub locator: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub authors: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub year: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doi: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pmid: Option<String>,
    #[serde(default)]
    pub imported_at: String,
    #[serde(default)]
    pub extraction_mode: String,
    #[serde(default)]
    pub source_quality: String,
    #[serde(default)]
    pub caveats: Vec<String>,
    #[serde(default)]
    pub finding_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceAtom {
    pub id: String,
    pub source_id: String,
    pub finding_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locator: Option<String>,
    pub evidence_type: String,
    pub measurement_or_claim: String,
    pub supports_or_challenges: String,
    pub condition_refs: Vec<String>,
    pub extraction_method: String,
    pub human_verified: bool,
    pub caveats: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConditionRecord {
    pub id: String,
    pub finding_id: String,
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub species: Option<String>,
    pub model_system: String,
    pub method: String,
    pub in_vitro: bool,
    pub in_vivo: bool,
    pub human_data: bool,
    pub clinical_trial: bool,
    pub exposure_or_efficacy: String,
    pub comparator_status: String,
    pub translation_scope: String,
    pub caveats: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceRegistrySummary {
    pub count: usize,
    pub source_types: BTreeMap<String, usize>,
    pub low_quality_count: usize,
    pub missing_hash_count: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceAtomSummary {
    pub count: usize,
    pub missing_locator_count: usize,
    pub unverified_count: usize,
    pub synthetic_source_count: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConditionSummary {
    pub count: usize,
    pub missing_text_count: usize,
    pub missing_comparator_count: usize,
    pub exposure_efficacy_risk_count: usize,
    pub translation_scopes: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceEvidenceProjection {
    pub sources: Vec<SourceRecord>,
    pub evidence_atoms: Vec<EvidenceAtom>,
    pub condition_records: Vec<ConditionRecord>,
}

/// Phase N: rewrite each finding's `provenance` (title, year, authors,
/// journal, license, publisher, funders) from the canonical
/// SourceRecord that matches by DOI / PMID / title. Returns the count
/// of findings whose provenance changed.
///
/// Doctrine: `Project.sources` is canonical; `FindingBundle.provenance`
/// is the denormalized cache. When they disagree, the source wins.
pub fn resync_provenance_from_sources(project: &mut Project) -> usize {
    use crate::bundle::Author;
    let mut by_doi: BTreeMap<String, &SourceRecord> = BTreeMap::new();
    let mut by_pmid: BTreeMap<String, &SourceRecord> = BTreeMap::new();
    let mut by_title: BTreeMap<String, &SourceRecord> = BTreeMap::new();
    for source in &project.sources {
        if let Some(doi) = source.doi.as_deref() {
            by_doi.insert(doi.to_lowercase(), source);
        }
        if let Some(pmid) = source.pmid.as_deref() {
            by_pmid.insert(pmid.to_string(), source);
        }
        if !source.title.trim().is_empty() {
            by_title.insert(normalize_title_key(&source.title), source);
        }
    }

    let mut updated = 0usize;
    for finding in &mut project.findings {
        let source: Option<&SourceRecord> = finding
            .provenance
            .doi
            .as_deref()
            .map(str::to_lowercase)
            .and_then(|key| by_doi.get(&key).copied())
            .or_else(|| {
                finding
                    .provenance
                    .pmid
                    .as_deref()
                    .and_then(|key| by_pmid.get(key).copied())
            })
            .or_else(|| {
                if finding.provenance.title.trim().is_empty() {
                    None
                } else {
                    by_title
                        .get(&normalize_title_key(&finding.provenance.title))
                        .copied()
                }
            });

        let Some(source) = source else { continue };
        let mut changed = false;

        if !source.title.is_empty() && source.title != finding.provenance.title {
            finding.provenance.title = source.title.clone();
            changed = true;
        }
        if source.year.is_some() && source.year != finding.provenance.year {
            finding.provenance.year = source.year;
            changed = true;
        }
        if !source.authors.is_empty() {
            let derived: Vec<Author> = source
                .authors
                .iter()
                .map(|name| Author {
                    name: name.clone(),
                    orcid: None,
                })
                .collect();
            let differs = derived.len() != finding.provenance.authors.len()
                || derived
                    .iter()
                    .zip(finding.provenance.authors.iter())
                    .any(|(a, b)| a.name != b.name);
            if differs {
                finding.provenance.authors = derived;
                changed = true;
            }
        }
        if changed {
            updated += 1;
        }
    }
    updated
}

fn normalize_title_key(title: &str) -> String {
    title
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

pub fn materialize_project(project: &mut Project) {
    let projection = derive_projection(project);
    project.sources = projection.sources;
    project.evidence_atoms = projection.evidence_atoms;
    project.condition_records = projection.condition_records;
    crate::project::recompute_stats(project);
}

pub fn derive_projection(project: &Project) -> SourceEvidenceProjection {
    let sources = derive_source_records(project);
    let condition_records = derive_condition_records(project);
    let evidence_atoms = derive_evidence_atoms(project, &sources, &condition_records);
    SourceEvidenceProjection {
        sources,
        evidence_atoms,
        condition_records,
    }
}

pub fn source_summary(project: &Project) -> SourceRegistrySummary {
    let sources = if project.sources.is_empty() {
        derive_source_records(project)
    } else {
        project.sources.clone()
    };
    let mut source_types = BTreeMap::new();
    let mut low_quality_count = 0usize;
    let mut missing_hash_count = 0usize;
    for source in &sources {
        *source_types.entry(source.source_type.clone()).or_default() += 1;
        if matches!(
            source.source_quality.as_str(),
            "low" | "rough" | "needs_review" | "synthetic"
        ) {
            low_quality_count += 1;
        }
        if source.content_hash.is_none() {
            missing_hash_count += 1;
        }
    }
    SourceRegistrySummary {
        count: sources.len(),
        source_types,
        low_quality_count,
        missing_hash_count,
    }
}

pub fn evidence_summary(project: &Project) -> EvidenceAtomSummary {
    let projection;
    let (atoms, source_records): (&[EvidenceAtom], &[SourceRecord]) =
        if project.evidence_atoms.is_empty() || project.sources.is_empty() {
            projection = derive_projection(project);
            (&projection.evidence_atoms, &projection.sources)
        } else {
            (&project.evidence_atoms, &project.sources)
        };
    let source_map = source_records
        .iter()
        .map(|source| (source.id.as_str(), source))
        .collect::<BTreeMap<_, _>>();
    let mut missing_locator_count = 0usize;
    let mut unverified_count = 0usize;
    let mut synthetic_source_count = 0usize;
    for atom in atoms {
        if atom.locator.as_deref().is_none_or(str::is_empty) {
            missing_locator_count += 1;
        }
        if !atom.human_verified {
            unverified_count += 1;
        }
        if source_map
            .get(atom.source_id.as_str())
            .is_some_and(|source| is_synthetic_source(source))
        {
            synthetic_source_count += 1;
        }
    }
    EvidenceAtomSummary {
        count: atoms.len(),
        missing_locator_count,
        unverified_count,
        synthetic_source_count,
    }
}

pub fn condition_summary(project: &Project) -> ConditionSummary {
    let records = if project.condition_records.is_empty() {
        derive_condition_records(project)
    } else {
        project.condition_records.clone()
    };
    let mut translation_scopes = BTreeMap::new();
    let mut missing_text_count = 0usize;
    let mut missing_comparator_count = 0usize;
    let mut exposure_efficacy_risk_count = 0usize;
    for record in &records {
        *translation_scopes
            .entry(record.translation_scope.clone())
            .or_default() += 1;
        if record.text.trim().is_empty() {
            missing_text_count += 1;
        }
        if record.comparator_status == "missing_or_unclear" {
            missing_comparator_count += 1;
        }
        if record.exposure_or_efficacy == "both" {
            exposure_efficacy_risk_count += 1;
        }
    }
    ConditionSummary {
        count: records.len(),
        missing_text_count,
        missing_comparator_count,
        exposure_efficacy_risk_count,
        translation_scopes,
    }
}

pub fn source_map(project: &Project) -> BTreeMap<&str, &SourceRecord> {
    let mut map = BTreeMap::new();
    for source in &project.sources {
        map.insert(source.id.as_str(), source);
    }
    map
}

pub fn condition_records_for_finding<'a>(
    project: &'a Project,
    finding_id: &str,
) -> Vec<&'a ConditionRecord> {
    project
        .condition_records
        .iter()
        .filter(|record| record.finding_id == finding_id)
        .collect()
}

pub fn evidence_atoms_for_finding<'a>(
    project: &'a Project,
    finding_id: &str,
) -> Vec<&'a EvidenceAtom> {
    project
        .evidence_atoms
        .iter()
        .filter(|atom| atom.finding_id == finding_id)
        .collect()
}

pub fn sources_for_finding<'a>(project: &'a Project, finding_id: &str) -> Vec<&'a SourceRecord> {
    let atoms = evidence_atoms_for_finding(project, finding_id);
    let ids = atoms
        .iter()
        .map(|atom| atom.source_id.as_str())
        .collect::<BTreeSet<_>>();
    project
        .sources
        .iter()
        .filter(|source| {
            source.finding_ids.iter().any(|id| id == finding_id) || ids.contains(source.id.as_str())
        })
        .collect()
}

pub fn source_evidence_map(project: &Project) -> Value {
    source_evidence_map_from_atoms(&project.evidence_atoms)
}

pub fn source_evidence_map_from_atoms(evidence_atoms: &[EvidenceAtom]) -> Value {
    let mut by_source = BTreeMap::<String, Vec<Value>>::new();
    for atom in evidence_atoms {
        by_source
            .entry(atom.source_id.clone())
            .or_default()
            .push(json!({
                "evidence_atom_id": atom.id,
                "finding_id": atom.finding_id,
                "locator": atom.locator,
                "supports_or_challenges": atom.supports_or_challenges,
                "human_verified": atom.human_verified,
                "caveats": atom.caveats,
            }));
    }
    json!({
        "schema": "vela.source-evidence-map.v0",
        "sources": by_source,
    })
}

pub fn condition_matrix(records: &[ConditionRecord]) -> Value {
    let rows = records
        .iter()
        .map(|record| {
            json!({
                "condition_id": record.id,
                "finding_id": record.finding_id,
                "text": record.text,
                "species": record.species,
                "model_system": record.model_system,
                "method": record.method,
                "human_data": record.human_data,
                "clinical_trial": record.clinical_trial,
                "exposure_or_efficacy": record.exposure_or_efficacy,
                "comparator_status": record.comparator_status,
                "translation_scope": record.translation_scope,
                "caveats": record.caveats,
            })
        })
        .collect::<Vec<_>>();
    json!({
        "schema": "vela.condition-matrix.v0",
        "conditions": rows,
    })
}

pub fn attach_local_source_details(
    project: &mut Project,
    finding_hashes: &BTreeMap<String, String>,
    finding_source_types: &BTreeMap<String, String>,
) {
    if finding_hashes.is_empty() && finding_source_types.is_empty() {
        return;
    }
    let mut remap = BTreeMap::<String, String>::new();
    for source in &mut project.sources {
        let hashes = source
            .finding_ids
            .iter()
            .filter_map(|finding_id| finding_hashes.get(finding_id))
            .collect::<BTreeSet<_>>();
        if hashes.len() == 1
            && let Some(hash) = hashes.into_iter().next().cloned()
        {
            source.content_hash = Some(hash);
        }
        let source_types = source
            .finding_ids
            .iter()
            .filter_map(|finding_id| finding_source_types.get(finding_id))
            .collect::<BTreeSet<_>>();
        if source_types.len() == 1
            && let Some(source_type) = source_types.into_iter().next()
        {
            source.source_type = normalize_source_type(source_type);
        }
        let old_id = source.id.clone();
        source.id = source_id(
            &source.source_type,
            &source.locator,
            source.content_hash.as_deref(),
            source.doi.as_deref(),
            source.pmid.as_deref(),
            &source.title,
        );
        if source.id != old_id {
            remap.insert(old_id, source.id.clone());
        }
    }
    if remap.is_empty() {
        crate::project::recompute_stats(project);
        return;
    }
    for atom in &mut project.evidence_atoms {
        if let Some(new_source_id) = remap.get(&atom.source_id) {
            atom.source_id = new_source_id.clone();
            atom.id = evidence_atom_id(
                &atom.source_id,
                &atom.finding_id,
                atom.locator.as_deref(),
                &atom.measurement_or_claim,
                &atom.evidence_type,
            );
        }
    }
    crate::project::recompute_stats(project);
}

pub fn source_record_for_finding(finding: &FindingBundle) -> SourceRecord {
    let source_type = normalize_source_type(&finding.provenance.source_type);
    let locator = source_locator(&finding.provenance, &finding.id);
    let content_hash = derived_local_source_hash(finding, &source_type, &locator);
    let id = source_id(
        &source_type,
        &locator,
        content_hash.as_deref(),
        finding.provenance.doi.as_deref(),
        finding.provenance.pmid.as_deref(),
        &finding.provenance.title,
    );
    let mut caveats = Vec::new();
    if source_type == "synthetic_report" || source_type == "agent_trace" {
        caveats.push("source requires human review before being treated as evidence".to_string());
    }
    if finding.provenance.title.trim().is_empty()
        && finding.provenance.doi.is_none()
        && finding.provenance.pmid.is_none()
    {
        caveats.push("weak source metadata; locator derived from finding id".to_string());
    }
    let source_quality = if caveats.is_empty()
        && !finding.provenance.extraction.method.contains("fallback")
        && !finding.provenance.extraction.method.contains("rough")
    {
        "declared".to_string()
    } else if source_type == "synthetic_report" || source_type == "agent_trace" {
        "synthetic".to_string()
    } else {
        "needs_review".to_string()
    };
    SourceRecord {
        id,
        source_type,
        locator,
        content_hash,
        title: finding.provenance.title.clone(),
        authors: finding
            .provenance
            .authors
            .iter()
            .map(|author| author.name.clone())
            .collect(),
        year: finding.provenance.year,
        doi: finding.provenance.doi.clone(),
        pmid: finding.provenance.pmid.clone(),
        imported_at: finding.provenance.extraction.extracted_at.clone(),
        extraction_mode: finding.provenance.extraction.method.clone(),
        source_quality,
        caveats,
        finding_ids: vec![finding.id.clone()],
    }
}

fn derived_local_source_hash(
    finding: &FindingBundle,
    source_type: &str,
    locator: &str,
) -> Option<String> {
    if !matches!(
        source_type,
        "csv"
            | "text"
            | "note"
            | "agent_trace"
            | "benchmark_output"
            | "notebook_entry"
            | "experiment_log"
            | "synthetic_report"
    ) {
        return None;
    }

    let preimage = json!({
        "schema": "vela.source.synthetic-commitment.v1",
        "finding_id": finding.id,
        "source_type": source_type,
        "locator": locator,
        "title": finding.provenance.title,
        "url": finding.provenance.url,
        "extraction_method": finding.provenance.extraction.method,
        "extracted_at": finding.provenance.extraction.extracted_at,
        "extractor_version": finding.provenance.extraction.extractor_version,
    });
    let bytes = serde_json::to_vec(&preimage).expect("source commitment is serializable");
    Some(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn derive_source_records(project: &Project) -> Vec<SourceRecord> {
    let mut by_id = BTreeMap::<String, SourceRecord>::new();

    for finding in &project.findings {
        let mut record = source_record_for_finding(finding);
        if let Some(existing) = matching_existing_source(project, &record) {
            record.source_type = existing.source_type.clone();
            if existing.content_hash.is_some() {
                record.content_hash = existing.content_hash.clone();
            }
            record.id = source_id(
                &record.source_type,
                &record.locator,
                record.content_hash.as_deref(),
                record.doi.as_deref(),
                record.pmid.as_deref(),
                &record.title,
            );
            for caveat in &existing.caveats {
                push_unique(&mut record.caveats, caveat);
            }
        }
        by_id
            .entry(record.id.clone())
            .and_modify(|existing| push_unique(&mut existing.finding_ids, &finding.id))
            .or_insert(record);
    }

    for existing in &project.sources {
        by_id
            .entry(existing.id.clone())
            .or_insert_with(|| existing.clone());
    }

    by_id.into_values().collect()
}

fn matching_existing_source<'a>(
    project: &'a Project,
    record: &SourceRecord,
) -> Option<&'a SourceRecord> {
    project.sources.iter().find(|existing| {
        existing
            .finding_ids
            .iter()
            .any(|id| record.finding_ids.iter().any(|record_id| record_id == id))
            || (existing.locator == record.locator
                && existing.title == record.title
                && existing.doi == record.doi
                && existing.pmid == record.pmid)
    })
}

fn derive_evidence_atoms(
    project: &Project,
    sources: &[SourceRecord],
    condition_records: &[ConditionRecord],
) -> Vec<EvidenceAtom> {
    let source_by_finding = sources
        .iter()
        .flat_map(|source| {
            source
                .finding_ids
                .iter()
                .map(move |finding_id| (finding_id.as_str(), source))
        })
        .collect::<BTreeMap<_, _>>();
    let mut atoms = BTreeMap::<String, EvidenceAtom>::new();
    for finding in &project.findings {
        let source = source_by_finding
            .get(finding.id.as_str())
            .copied()
            .cloned()
            .unwrap_or_else(|| source_record_for_finding(finding));
        let source_id = source.id.clone();
        if finding.evidence.evidence_spans.is_empty() {
            let atom = weak_atom(finding, &source_id, condition_records);
            atoms.insert(atom.id.clone(), atom);
            continue;
        }
        for (span_index, span) in finding.evidence.evidence_spans.iter().enumerate() {
            let (locator, claim) = span_locator_and_claim(span, span_index);
            let mut caveats = Vec::new();
            if locator.is_none() {
                caveats.push("missing evidence locator".to_string());
            }
            if finding.conditions.text.trim().is_empty() {
                caveats.push("condition boundary missing on parent finding".to_string());
            }
            let atom = EvidenceAtom {
                id: evidence_atom_id(
                    &source_id,
                    &finding.id,
                    locator.as_deref(),
                    &claim,
                    &finding.evidence.evidence_type,
                ),
                source_id: source_id.clone(),
                finding_id: finding.id.clone(),
                locator,
                evidence_type: finding.evidence.evidence_type.clone(),
                measurement_or_claim: claim,
                supports_or_challenges: "supports".to_string(),
                condition_refs: condition_refs(finding, condition_records),
                extraction_method: finding.provenance.extraction.method.clone(),
                human_verified: finding
                    .provenance
                    .review
                    .as_ref()
                    .is_some_and(|review| review.reviewed),
                caveats,
            };
            atoms.insert(atom.id.clone(), atom);
        }
    }
    // v0.56: When a persisted atom shares an id with a derived one,
    // merge field-by-field so reducer-applied repairs survive
    // re-derivation. The derive pass produces weak atoms (locator
    // None, "missing evidence locator" caveat) for findings whose
    // evidence_spans are empty. After an `evidence_atom.locator_repaired`
    // event lands, the persisted atom carries `locator: Some(...)`
    // and no longer carries the missing-locator caveat. Without this
    // merge step, re-derivation would silently overwrite the repair
    // because the existing entry-or-insert pattern preferred the
    // derived weak atom on id collision.
    for existing in &project.evidence_atoms {
        let id = existing.id.clone();
        match atoms.get_mut(&id) {
            None => {
                atoms.insert(id, existing.clone());
            }
            Some(derived) => {
                if existing.locator.is_some() && derived.locator.is_none() {
                    derived.locator = existing.locator.clone();
                    derived.caveats.retain(|c| c != "missing evidence locator");
                }
                if existing.human_verified && !derived.human_verified {
                    derived.human_verified = true;
                }
            }
        }
    }
    atoms.into_values().collect()
}

fn derive_condition_records(project: &Project) -> Vec<ConditionRecord> {
    let mut records = BTreeMap::<String, ConditionRecord>::new();
    for finding in &project.findings {
        let record = condition_record_for_finding(finding);
        records.insert(record.id.clone(), record);
    }
    for existing in &project.condition_records {
        records
            .entry(existing.id.clone())
            .or_insert_with(|| existing.clone());
    }
    records.into_values().collect()
}

pub fn condition_record_for_finding(finding: &FindingBundle) -> ConditionRecord {
    let text = finding.conditions.text.trim().to_string();
    let species = finding
        .conditions
        .species_verified
        .first()
        .cloned()
        .or_else(|| finding.evidence.species.clone());
    let combined = format!(
        "{} {} {} {} {}",
        finding.assertion.text,
        finding.evidence.evidence_type,
        finding.evidence.model_system,
        finding.evidence.method,
        text
    );
    let exposure_or_efficacy = exposure_or_efficacy(&combined);
    let comparator_status = comparator_status(&combined, finding);
    let translation_scope = translation_scope(finding, &combined);
    let mut caveats = Vec::new();
    if text.is_empty() {
        caveats.push("condition boundary missing".to_string());
    }
    if comparator_status == "missing_or_unclear" {
        caveats.push("comparator or baseline missing or unclear".to_string());
    }
    if exposure_or_efficacy == "both" {
        caveats.push(
            "exposure and efficacy language both present; review for overgeneralization"
                .to_string(),
        );
    }
    if translation_scope == "animal_model" && mentions_human_translation(&combined) {
        caveats.push(
            "animal-model evidence is being discussed near human translation language".to_string(),
        );
    }
    ConditionRecord {
        id: condition_record_id(finding),
        finding_id: finding.id.clone(),
        text,
        species,
        model_system: finding.evidence.model_system.clone(),
        method: finding.evidence.method.clone(),
        in_vitro: finding.conditions.in_vitro,
        in_vivo: finding.conditions.in_vivo,
        human_data: finding.conditions.human_data,
        clinical_trial: finding.conditions.clinical_trial,
        exposure_or_efficacy,
        comparator_status,
        translation_scope,
        caveats,
    }
}

fn weak_atom(
    finding: &FindingBundle,
    source_id: &str,
    condition_records: &[ConditionRecord],
) -> EvidenceAtom {
    let claim = finding.assertion.text.clone();
    EvidenceAtom {
        id: evidence_atom_id(
            source_id,
            &finding.id,
            None,
            &claim,
            &finding.evidence.evidence_type,
        ),
        source_id: source_id.to_string(),
        finding_id: finding.id.clone(),
        locator: None,
        evidence_type: finding.evidence.evidence_type.clone(),
        measurement_or_claim: claim,
        supports_or_challenges: "unknown".to_string(),
        condition_refs: condition_refs(finding, condition_records),
        extraction_method: finding.provenance.extraction.method.clone(),
        human_verified: false,
        caveats: vec!["missing evidence locator".to_string()],
    }
}

fn span_locator_and_claim(span: &Value, span_index: usize) -> (Option<String>, String) {
    if let Some(text) = span.as_str() {
        let trimmed = text.trim().to_string();
        let locator = if trimmed.is_empty() {
            None
        } else {
            Some(format!("span:{span_index}"))
        };
        return (locator, trimmed);
    }
    if let Some(object) = span.as_object() {
        let claim = object
            .get("text")
            .or_else(|| object.get("quote"))
            .or_else(|| object.get("claim"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();
        let mut parts = Vec::new();
        for key in [
            "source", "section", "page", "row", "table", "figure", "start", "end",
        ] {
            if let Some(value) = object.get(key) {
                let rendered = value
                    .as_str()
                    .map(str::to_string)
                    .unwrap_or_else(|| value.to_string());
                if !rendered.trim().is_empty() {
                    parts.push(format!("{key}:{rendered}"));
                }
            }
        }
        let locator = if parts.is_empty() {
            Some(format!("span:{span_index}"))
        } else {
            Some(parts.join("|"))
        };
        let claim = if claim.is_empty() {
            span.to_string()
        } else {
            claim
        };
        return (locator, claim);
    }
    (Some(format!("span:{span_index}")), span.to_string())
}

fn condition_refs(finding: &FindingBundle, condition_records: &[ConditionRecord]) -> Vec<String> {
    if let Some(record) = condition_records
        .iter()
        .find(|record| record.finding_id == finding.id)
    {
        return vec![record.id.clone()];
    }
    let text = finding.conditions.text.trim();
    if text.is_empty() {
        vec![format!("finding:{}", finding.id)]
    } else {
        vec![condition_record_id(finding)]
    }
}

pub fn condition_record_id(finding: &FindingBundle) -> String {
    let input = format!(
        "{}|{}|{}|{}|{}",
        finding.id,
        finding.conditions.text.trim(),
        finding.evidence.model_system,
        finding.evidence.method,
        finding.evidence.species.clone().unwrap_or_default()
    );
    format!("vcnd_{}", short_hash(input.as_bytes()))
}

fn exposure_or_efficacy(text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    let exposure = [
        "exposure",
        "uptake",
        "transport",
        "delivery",
        "penetration",
        "brain level",
        "biodistribution",
        "concentration",
    ]
    .iter()
    .any(|needle| lower.contains(needle));
    let efficacy = [
        "efficacy",
        "therapeutic",
        "functional",
        "cognition",
        "survival",
        "clinical",
        "symptom",
        "outcome",
    ]
    .iter()
    .any(|needle| lower.contains(needle));
    match (exposure, efficacy) {
        (true, true) => "both",
        (true, false) => "exposure",
        (false, true) => "efficacy",
        (false, false) => "unknown",
    }
    .to_string()
}

fn comparator_status(text: &str, finding: &FindingBundle) -> String {
    let lower = text.to_ascii_lowercase();
    if [
        "control",
        "comparator",
        "compared",
        "versus",
        "relative to",
        "baseline",
        "vs ",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
        || finding.evidence.effect_size.is_some()
        || finding.evidence.p_value.is_some()
    {
        "declared"
    } else {
        "missing_or_unclear"
    }
    .to_string()
}

fn translation_scope(finding: &FindingBundle, text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    if finding.conditions.clinical_trial || finding.conditions.human_data {
        return "human".to_string();
    }
    if finding.conditions.in_vivo
        || finding
            .evidence
            .species
            .as_deref()
            .is_some_and(|species| !species.to_ascii_lowercase().contains("human"))
    {
        return "animal_model".to_string();
    }
    if finding.conditions.in_vitro
        || lower.contains("cell")
        || lower.contains("in vitro")
        || lower.contains("organoid")
    {
        return "in_vitro".to_string();
    }
    if lower.contains("benchmark")
        || lower.contains("dataset")
        || lower.contains("simulation")
        || lower.contains("computational")
    {
        return "computational".to_string();
    }
    "unspecified".to_string()
}

fn mentions_human_translation(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    ["human", "clinical", "patient", "therapeutic efficacy"]
        .iter()
        .any(|needle| lower.contains(needle))
}

fn normalize_source_type(source_type: &str) -> String {
    match source_type {
        "published_paper" | "paper" => "paper",
        "database_record" | "curated_csv" | "csv" => "csv",
        "pdf" => "pdf",
        "jats" | "jats_xml" => "jats",
        "text" | "markdown" => "text",
        "note" => "note",
        "doi" | "doi_list" => "doi",
        "agent_trace" => "agent_trace",
        "benchmark_output" => "benchmark_output",
        "notebook_entry" => "notebook_entry",
        "experiment_log" => "experiment_log",
        "model_output" | "summary" | "synthesis" | "synthetic_report" => "synthetic_report",
        _ => "paper",
    }
    .to_string()
}

fn source_locator(provenance: &Provenance, finding_id: &str) -> String {
    provenance
        .doi
        .as_ref()
        .map(|doi| format!("doi:{doi}"))
        .or_else(|| provenance.pmid.as_ref().map(|pmid| format!("pmid:{pmid}")))
        .or_else(|| provenance.pmc.as_ref().map(|pmc| format!("pmc:{pmc}")))
        .or_else(|| {
            (!provenance.title.trim().is_empty()).then(|| format!("title:{}", provenance.title))
        })
        .unwrap_or_else(|| format!("unknown-source:{finding_id}"))
}

pub fn source_id(
    source_type: &str,
    locator: &str,
    content_hash: Option<&str>,
    doi: Option<&str>,
    pmid: Option<&str>,
    title: &str,
) -> String {
    let mut input = String::new();
    input.push_str(source_type);
    input.push('|');
    input.push_str(locator);
    input.push('|');
    input.push_str(content_hash.unwrap_or(""));
    input.push('|');
    input.push_str(doi.unwrap_or(""));
    input.push('|');
    input.push_str(pmid.unwrap_or(""));
    input.push('|');
    input.push_str(title);
    format!("vs_{}", short_hash(input.as_bytes()))
}

pub fn evidence_atom_id(
    source_id: &str,
    finding_id: &str,
    locator: Option<&str>,
    measurement_or_claim: &str,
    evidence_type: &str,
) -> String {
    let input = format!(
        "{source_id}|{finding_id}|{}|{measurement_or_claim}|{evidence_type}",
        locator.unwrap_or("")
    );
    format!("vea_{}", short_hash(input.as_bytes()))
}

pub fn is_synthetic_source(source: &SourceRecord) -> bool {
    matches!(
        source.source_type.as_str(),
        "synthetic_report" | "agent_trace"
    )
}

pub fn source_has_canonical_locator(source: &SourceRecord) -> bool {
    let locator = source.locator.trim();
    !locator.is_empty()
        && !locator.starts_with("unknown-source:")
        && (locator.starts_with("doi:")
            || locator.starts_with("pmid:")
            || locator.starts_with("pmc:")
            || locator.starts_with("url:")
            || locator.starts_with("title:")
            || source.doi.is_some()
            || source.pmid.is_some()
            || source.content_hash.is_some())
}

pub fn now_imported_at_fallback(value: &str) -> String {
    if value.trim().is_empty() {
        Utc::now().to_rfc3339()
    } else {
        value.to_string()
    }
}

fn push_unique(values: &mut Vec<String>, value: &str) {
    if !values.iter().any(|existing| existing == value) {
        values.push(value.to_string());
        values.sort();
    }
}

fn short_hash(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    hex::encode(&digest[..8])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::*;

    fn finding_with_span(span: Value) -> FindingBundle {
        FindingBundle {
            id: "vf_test".to_string(),
            version: 1,
            previous_version: None,
            assertion: Assertion {
                text: "TfR targeting increases apparent brain exposure in mice.".to_string(),
                assertion_type: "mechanism".to_string(),
                entities: Vec::new(),
                relation: None,
                direction: None,
                causal_claim: None,
                causal_evidence_grade: None,
            },
            evidence: Evidence {
                evidence_type: "experimental".to_string(),
                model_system: "mouse".to_string(),
                species: Some("Mus musculus".to_string()),
                method: "in vivo exposure assay".to_string(),
                sample_size: None,
                effect_size: None,
                p_value: None,
                replicated: false,
                replication_count: None,
                evidence_spans: vec![span],
            },
            conditions: Conditions {
                text: "Mouse exposure assay; not human therapeutic efficacy.".to_string(),
                species_verified: vec!["Mus musculus".to_string()],
                species_unverified: Vec::new(),
                in_vitro: false,
                in_vivo: true,
                human_data: false,
                clinical_trial: false,
                concentration_range: None,
                duration: None,
                age_group: None,
                cell_type: None,
            },
            confidence: Confidence::raw(0.6, "test", 0.8),
            provenance: Provenance {
                source_type: "published_paper".to_string(),
                doi: Some("10.0000/test".to_string()),
                pmid: None,
                pmc: None,
                openalex_id: None,
                url: None,
                title: "Test paper".to_string(),
                authors: vec![],
                year: Some(2026),
                journal: None,
                license: None,
                publisher: None,
                funders: vec![],
                extraction: Extraction::default(),
                review: None,
                citation_count: None,
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
            links: Vec::new(),
            annotations: vec![],
            attachments: vec![],
            created: "2026-01-01T00:00:00Z".to_string(),
            updated: None,

            access_tier: crate::access_tier::AccessTier::Public,
        }
    }

    #[test]
    fn projection_distinguishes_sources_from_evidence_atoms() {
        let finding = finding_with_span(json!({
            "text": "Brain exposure increased in mice.",
            "section": "results",
            "page": 4
        }));
        let project = crate::project::assemble("test", vec![finding], 1, 0, "test");
        let projection = derive_projection(&project);
        assert_eq!(projection.sources.len(), 1);
        assert_eq!(projection.evidence_atoms.len(), 1);
        assert_eq!(projection.condition_records.len(), 1);
        assert!(projection.sources[0].id.starts_with("vs_"));
        assert!(projection.evidence_atoms[0].id.starts_with("vea_"));
        assert!(projection.condition_records[0].id.starts_with("vcnd_"));
        assert_eq!(
            projection.evidence_atoms[0].source_id,
            projection.sources[0].id
        );
        assert_eq!(
            projection.evidence_atoms[0].condition_refs,
            vec![projection.condition_records[0].id.clone()]
        );
        assert_eq!(
            projection.evidence_atoms[0].locator.as_deref(),
            Some("section:results|page:4")
        );
    }

    #[test]
    fn missing_span_creates_weak_atom_with_caveat() {
        let mut finding = finding_with_span(json!({"text": "unused"}));
        finding.evidence.evidence_spans.clear();
        let project = crate::project::assemble("test", vec![finding], 1, 0, "test");
        let projection = derive_projection(&project);
        assert_eq!(projection.evidence_atoms.len(), 1);
        assert!(projection.evidence_atoms[0].locator.is_none());
        assert_eq!(
            projection.evidence_atoms[0].supports_or_challenges,
            "unknown"
        );
        assert!(
            projection.evidence_atoms[0]
                .caveats
                .iter()
                .any(|c| c == "missing evidence locator")
        );
    }

    #[test]
    fn condition_record_flags_exposure_efficacy_boundary() {
        let finding = finding_with_span(json!({
            "text": "Brain exposure and therapeutic efficacy increased in mice.",
            "section": "results"
        }));
        let record = condition_record_for_finding(&finding);
        assert_eq!(record.exposure_or_efficacy, "both");
        assert_eq!(record.translation_scope, "animal_model");
        assert!(
            record
                .caveats
                .iter()
                .any(|caveat| caveat.contains("overgeneralization"))
        );
    }

    #[test]
    fn generated_sources_receive_local_commitment_hashes() {
        let mut finding = finding_with_span(json!({
            "text": "Agent-derived synthesis should be review scoped.",
            "section": "summary"
        }));
        finding.provenance.source_type = "model_output".to_string();
        finding.provenance.title = "cap_demo - claim_001".to_string();
        finding.provenance.url = Some("artifact_packet:cap_demo".to_string());
        finding.provenance.extraction.method = "artifact_to_state_import".to_string();
        finding.provenance.extraction.extracted_at = "2026-05-06T00:00:00Z".to_string();
        finding.provenance.extraction.extractor_version = "vela/0.55.0".to_string();

        let record = source_record_for_finding(&finding);

        assert_eq!(record.source_type, "synthetic_report");
        assert!(
            record
                .content_hash
                .as_deref()
                .is_some_and(|hash| hash.starts_with("sha256:") && hash.len() == 71)
        );
        assert!(record.id.starts_with("vs_"));
    }

    #[test]
    fn published_paper_sources_do_not_receive_synthetic_hashes() {
        let finding = finding_with_span(json!({
            "text": "Brain exposure increased in mice.",
            "section": "results"
        }));

        let record = source_record_for_finding(&finding);

        assert_eq!(record.source_type, "paper");
        assert!(record.content_hash.is_none());
    }
}
