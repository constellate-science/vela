//! v0.19: bundled entity resolution.
//!
//! Hardcoded lookup table for common entities a curator hand-adds via
//! `vela finding add --entities`. Maps `(normalized_name, entity_type)` to
//! a canonical `ResolvedId` (UniProt for proteins, MeSH for diseases/anatomy,
//! ChEBI for compounds, NCBI Taxonomy for organisms). When a match lands,
//! the entity's `canonical_id` is populated, `resolution_method = Manual`,
//! `resolution_confidence = 0.95`, `needs_review = false`.
//!
//! This is deliberately not exhaustive. The ~50-entry table covers the
//! Alzheimer's drug-target landscape's natural vocabulary plus the cross-
//! domain v0.10 enums (particle, instrument). Real research will need
//! either a much larger bundled table or live ontology API integration —
//! but a manual-curation user gets meaningful resolution today, and
//! `needs_human_review` strict-blockers drop for matched entities.

use crate::bundle::{Entity, ResolutionMethod, ResolvedId};
use crate::project::Project;

/// One bundled lookup entry. `match_names` is the normalized list of
/// names + aliases that should resolve to this entry.
struct OntologyEntry {
    canonical_name: &'static str,
    entity_type: &'static str,
    match_names: &'static [&'static str],
    source: &'static str,
    id: &'static str,
}

/// Bundled common-entity table. v0.19: Alzheimer's-flavored bias
/// (matches Will's frontier vocabulary) + a small cross-domain set
/// for v0.10 physics entities. Add carefully; every entry becomes a
/// public claim that this name resolves to this id.
const TABLE: &[OntologyEntry] = &[
    // Proteins (UniProt human canonical)
    OntologyEntry {
        canonical_name: "amyloid-beta",
        entity_type: "protein",
        match_names: &["amyloid-beta", "amyloid beta", "abeta", "aβ", "ab"],
        source: "UniProt",
        id: "P05067", // Amyloid-beta precursor protein (APP)
    },
    OntologyEntry {
        canonical_name: "APP",
        entity_type: "protein",
        match_names: &["app", "amyloid precursor protein"],
        source: "UniProt",
        id: "P05067",
    },
    OntologyEntry {
        canonical_name: "BACE1",
        entity_type: "protein",
        match_names: &["bace1", "β-secretase 1", "beta-secretase 1"],
        source: "UniProt",
        id: "P56817",
    },
    OntologyEntry {
        canonical_name: "tau",
        entity_type: "protein",
        match_names: &["tau", "mapt", "microtubule-associated protein tau"],
        source: "UniProt",
        id: "P10636",
    },
    OntologyEntry {
        canonical_name: "TREM2",
        entity_type: "protein",
        match_names: &["trem2", "triggering receptor expressed on myeloid cells 2"],
        source: "UniProt",
        id: "Q9NZC2",
    },
    OntologyEntry {
        canonical_name: "ApoE",
        entity_type: "protein",
        match_names: &["apoe", "apolipoprotein e"],
        source: "UniProt",
        id: "P02649",
    },
    OntologyEntry {
        canonical_name: "PSEN1",
        entity_type: "protein",
        match_names: &["psen1", "presenilin-1", "presenilin 1"],
        source: "UniProt",
        id: "P49768",
    },
    OntologyEntry {
        canonical_name: "PSEN2",
        entity_type: "protein",
        match_names: &["psen2", "presenilin-2", "presenilin 2"],
        source: "UniProt",
        id: "P49810",
    },
    // Same identifiers as gene symbols
    OntologyEntry {
        canonical_name: "PSEN1",
        entity_type: "gene",
        match_names: &["psen1"],
        source: "NCBI Gene",
        id: "5663",
    },
    OntologyEntry {
        canonical_name: "APOE",
        entity_type: "gene",
        match_names: &["apoe"],
        source: "NCBI Gene",
        id: "348",
    },
    // Diseases (MeSH)
    OntologyEntry {
        canonical_name: "Alzheimer's disease",
        entity_type: "disease",
        match_names: &[
            "alzheimer's disease",
            "alzheimer disease",
            "alzheimers disease",
            "ad",
        ],
        source: "MeSH",
        id: "D000544",
    },
    OntologyEntry {
        canonical_name: "mild cognitive impairment",
        entity_type: "disease",
        match_names: &["mild cognitive impairment", "mci"],
        source: "MeSH",
        id: "D060825",
    },
    // Compounds / drugs (CHEBI/DrugBank)
    OntologyEntry {
        canonical_name: "Lecanemab",
        entity_type: "compound",
        match_names: &["lecanemab", "leqembi"],
        source: "DrugBank",
        id: "DB16703",
    },
    OntologyEntry {
        canonical_name: "Aducanumab",
        entity_type: "compound",
        match_names: &["aducanumab", "aduhelm"],
        source: "DrugBank",
        id: "DB12274",
    },
    OntologyEntry {
        canonical_name: "Donanemab",
        entity_type: "compound",
        match_names: &["donanemab", "kisunla"],
        source: "DrugBank",
        id: "DB17791",
    },
    OntologyEntry {
        canonical_name: "Verubecestat",
        entity_type: "compound",
        match_names: &["verubecestat", "mk-8931"],
        source: "DrugBank",
        id: "DB12089",
    },
    OntologyEntry {
        canonical_name: "Liraglutide",
        entity_type: "compound",
        match_names: &["liraglutide", "victoza", "saxenda"],
        source: "DrugBank",
        id: "DB06655",
    },
    OntologyEntry {
        canonical_name: "Semaglutide",
        entity_type: "compound",
        match_names: &["semaglutide", "ozempic", "wegovy"],
        source: "DrugBank",
        id: "DB13928",
    },
    OntologyEntry {
        canonical_name: "Exendin-4",
        entity_type: "compound",
        match_names: &["exendin-4", "exenatide", "byetta"],
        source: "DrugBank",
        id: "DB01276",
    },
    OntologyEntry {
        canonical_name: "Xenon",
        entity_type: "compound",
        match_names: &["xenon", "xe"],
        source: "ChEBI",
        id: "CHEBI:49957",
    },
    // Cell types
    OntologyEntry {
        canonical_name: "microglia",
        entity_type: "cell_type",
        match_names: &["microglia", "microglial cell"],
        source: "Cell Ontology",
        id: "CL:0000129",
    },
    // Anatomical structures
    OntologyEntry {
        canonical_name: "blood-brain barrier",
        entity_type: "anatomical_structure",
        match_names: &["blood-brain barrier", "bbb"],
        source: "MeSH",
        id: "D001812",
    },
    // Organisms (NCBI Taxonomy)
    OntologyEntry {
        canonical_name: "Homo sapiens",
        entity_type: "organism",
        match_names: &["homo sapiens", "human"],
        source: "NCBI Taxonomy",
        id: "9606",
    },
    OntologyEntry {
        canonical_name: "Mus musculus",
        entity_type: "organism",
        match_names: &["mus musculus", "mouse", "house mouse"],
        source: "NCBI Taxonomy",
        id: "10090",
    },
    // Physics-side (v0.10 entity types)
    OntologyEntry {
        canonical_name: "WIMP",
        entity_type: "particle",
        match_names: &["wimp", "weakly interacting massive particle"],
        source: "PDG",
        id: "WIMP",
    },
    OntologyEntry {
        canonical_name: "XENONnT",
        entity_type: "instrument",
        match_names: &["xenonnt", "xenon nt"],
        source: "ROR",
        id: "https://ror.org/03wkt5x30",
    },
    OntologyEntry {
        canonical_name: "LZ",
        entity_type: "instrument",
        match_names: &["lz", "lux-zeplin", "lux zeplin"],
        source: "ROR",
        id: "https://ror.org/04xeg9z08",
    },
];

/// Lower / collapse-whitespace normalization to compare against `match_names`.
fn normalize(s: &str) -> String {
    s.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

/// Find a bundled match for an unresolved entity. Match must agree on
/// `entity_type` (we don't auto-resolve `LZ:compound` to the LZ instrument).
fn lookup(entity: &Entity) -> Option<&'static OntologyEntry> {
    let n = normalize(&entity.name);
    TABLE.iter().find(|row| {
        row.entity_type == entity.entity_type && row.match_names.iter().any(|m| *m == n)
    })
}

/// Per-finding outcome.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FindingResolutionReport {
    pub finding_id: String,
    pub resolved: usize,
    pub unresolved: Vec<String>,
    pub already_resolved: usize,
}

/// Whole-frontier outcome.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ResolveReport {
    pub frontier: String,
    pub total_entities: usize,
    pub resolved: usize,
    pub already_resolved: usize,
    pub unresolved_count: usize,
    pub findings_touched: usize,
    pub per_finding: Vec<FindingResolutionReport>,
}

/// Walk every entity on every finding and apply the bundled lookup.
/// Already-resolved entities (canonical_id is Some, regardless of source)
/// are skipped — caller can pass `force` to re-resolve.
pub fn resolve_frontier(project: &mut Project, force: bool) -> ResolveReport {
    let frontier_name = project.project.name.clone();
    let mut total = 0usize;
    let mut resolved = 0usize;
    let mut already = 0usize;
    let mut unresolved_count = 0usize;
    let mut findings_touched = 0usize;
    let mut per_finding: Vec<FindingResolutionReport> = Vec::new();

    for finding in project.findings.iter_mut() {
        let mut f_resolved = 0usize;
        let mut f_unresolved: Vec<String> = Vec::new();
        let mut f_already = 0usize;
        for entity in finding.assertion.entities.iter_mut() {
            total += 1;
            if entity.canonical_id.is_some() && !force {
                already += 1;
                f_already += 1;
                continue;
            }
            match lookup(entity) {
                Some(row) => {
                    entity.canonical_id = Some(ResolvedId {
                        source: row.source.to_string(),
                        id: row.id.to_string(),
                        confidence: 0.95,
                        matched_name: Some(row.canonical_name.to_string()),
                    });
                    entity.resolution_method = Some(ResolutionMethod::Manual);
                    entity.resolution_confidence = 0.95;
                    entity.resolution_provenance =
                        Some("vela_entity_resolve_v0_19_bundled_table".to_string());
                    entity.needs_review = false;
                    resolved += 1;
                    f_resolved += 1;
                }
                None => {
                    unresolved_count += 1;
                    f_unresolved.push(format!("{}:{}", entity.name, entity.entity_type));
                }
            }
        }
        if f_resolved > 0 || !f_unresolved.is_empty() || f_already > 0 {
            if f_resolved > 0 {
                findings_touched += 1;
            }
            per_finding.push(FindingResolutionReport {
                finding_id: finding.id.clone(),
                resolved: f_resolved,
                unresolved: f_unresolved,
                already_resolved: f_already,
            });
        }
    }

    // Recompute stats since needs_review counts may have shifted.
    crate::project::recompute_stats(project);

    ResolveReport {
        frontier: frontier_name,
        total_entities: total,
        resolved,
        already_resolved: already,
        unresolved_count,
        findings_touched,
        per_finding,
    }
}

/// Convenience: how many entries are bundled. Used by tests + the
/// CLI's `--list` flag.
pub fn bundled_entry_count() -> usize {
    TABLE.len()
}

/// Iterate the bundle without leaking the internal struct shape.
pub fn iter_bundled()
-> impl Iterator<Item = (&'static str, &'static str, &'static str, &'static str)> {
    TABLE
        .iter()
        .map(|r| (r.canonical_name, r.entity_type, r.source, r.id))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entity(name: &str, et: &str) -> Entity {
        Entity {
            name: name.to_string(),
            entity_type: et.to_string(),
            identifiers: serde_json::Map::new(),
            canonical_id: None,
            candidates: Vec::new(),
            aliases: Vec::new(),
            resolution_provenance: Some("manual_state_transition".to_string()),
            resolution_confidence: 0.6,
            resolution_method: None,
            species_context: None,
            needs_review: true,
        }
    }

    #[test]
    fn lookup_amyloid_beta_protein() {
        let e = make_entity("amyloid-beta", "protein");
        let row = lookup(&e).expect("amyloid-beta should resolve");
        assert_eq!(row.source, "UniProt");
        assert_eq!(row.id, "P05067");
    }

    #[test]
    fn lookup_alzheimers_disease_with_apostrophe_variants() {
        for n in [
            "Alzheimer's disease",
            "alzheimers disease",
            "ALZHEIMER'S DISEASE",
        ] {
            let e = make_entity(n, "disease");
            assert!(lookup(&e).is_some(), "should resolve '{n}'");
        }
    }

    #[test]
    fn lookup_respects_entity_type() {
        // "LZ" as an instrument resolves; as a compound does not.
        assert!(lookup(&make_entity("LZ", "instrument")).is_some());
        assert!(lookup(&make_entity("LZ", "compound")).is_none());
    }

    #[test]
    fn unmatched_name_returns_none() {
        let e = make_entity("totally made-up entity name", "protein");
        assert!(lookup(&e).is_none());
    }
}
