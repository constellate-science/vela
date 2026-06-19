//! Atlas source adapters: external catalogues → `SourceRecord`s, the native
//! production path that replaces the synthetic-id Python prototypes
//! (`scripts/atlas/ingest_*.py`). Each adapter reads one catalogue of
//! per-problem records; `vela atlas ingest-source` turns them into real,
//! content-addressed finding bundles plus signed `anchor.attached` events.
//!
//! Scope: the simple per-problem sources (formal-conjectures Lean corpus,
//! AlphaProof Nexus). The Tao adapter (`ingest_tao.py`) also synthesizes the
//! OEIS sequence frontier and the cross-frontier reference bridge, which is
//! materially more involved; it stays a Python prototype for now.

use std::path::Path;

use vela_protocol::bundle::{
    Assertion, Conditions, Confidence, ConfidenceKind, ConfidenceMethod, Evidence, Extraction,
    FindingBundle, Flags, Provenance,
};

/// One external-catalogue record an adapter yields. The namespace and role are
/// supplied by the command (`--namespace`), so a record is just the id + claim.
pub struct SourceRecord {
    /// Catalogue id digits (e.g. "40" for Erdős #40).
    pub external_id: String,
    /// Human-readable claim text (carries the declared status).
    pub assertion_text: String,
    /// Assertion type tag (e.g. "lean-formalization").
    pub assertion_type: String,
    /// Cross-problem reduction targets in the SAME namespace (e.g. ["28"] when
    /// this problem's Lean file proves `implies_erdos_28`). The command resolves
    /// these to a typed `implies` link once all finding ids are known. Sparse —
    /// see `scan_cross_problem_edges.py` (today: 2 across the whole corpus).
    pub implies: Vec<String>,
}

/// Build a real, content-addressed finding bundle from a source record. The id
/// derives from `normalize(text)+type+provenance` via
/// `FindingBundle::content_address` (not a hash of an arbitrary string), so it
/// is reproducible and collision-safe. `created` is pinned so regeneration is
/// deterministic. The finding rides as a genesis remnant (no introducing event
/// needed — see `reducer::seed_genesis_with_remnants`); the anchor is the signed
/// part.
pub fn build_finding(rec: &SourceRecord, source_tag: &str) -> FindingBundle {
    let assertion = Assertion {
        text: rec.assertion_text.clone(),
        assertion_type: rec.assertion_type.clone(),
        entities: vec![],
        relation: None,
        direction: None,
        causal_claim: None,
        causal_evidence_grade: None,
    };
    let evidence = Evidence {
        evidence_type: "catalogue".into(),
        model_system: "n/a".into(),
        method: source_tag.into(),
        replicated: false,
        replication_count: None,
        evidence_spans: vec![],
    };
    let conditions = Conditions {
        text: String::new(),
        duration: None,
    };
    let confidence = Confidence {
        kind: ConfidenceKind::FrontierEpistemic,
        score: 0.5,
        basis: "external catalogue record".into(),
        method: ConfidenceMethod::LlmInitial,
        components: None,
        extraction_confidence: 1.0,
    };
    let provenance = Provenance {
        source_type: "catalogue".into(),
        doi: None,
        url: None,
        // The content-address prov id; unique per record so ids never collide.
        title: format!("{source_tag}:{}", rec.external_id),
        authors: vec![],
        year: None,
        license: None,
        publisher: None,
        funders: vec![],
        extraction: Extraction::default(),
        review: None,
    };
    let mut bundle = FindingBundle::new(
        assertion,
        evidence,
        conditions,
        confidence,
        provenance,
        Flags::default(),
    );
    bundle.created = "2026-06-16T00:00:00Z".into();
    bundle
}

/// `.lean` files in `dir` whose stem matches a predicate, sorted for determinism.
fn lean_files(dir: &Path) -> Result<Vec<std::path::PathBuf>, String> {
    let mut out: Vec<_> = std::fs::read_dir(dir)
        .map_err(|e| format!("read dir {}: {e}", dir.display()))?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("lean"))
        .collect();
    out.sort();
    Ok(out)
}

/// Leading ASCII digits of `s` after an optional prefix, e.g. "40" from "40",
/// "152" from "erdos_152", "12" from "erdos_12.parts.i".
fn leading_number(stem: &str) -> Option<String> {
    let s = stem.strip_prefix("erdos_").unwrap_or(stem);
    let digits: String = s.chars().take_while(char::is_ascii_digit).collect();
    (!digits.is_empty()).then_some(digits)
}

/// Cross-problem reduction targets named in a Lean file: every distinct `M` in
/// `implies_erdos_<M>` other than the file's own problem `self_id` (drop
/// self-loops). The honest reduction structure of the formalized corpus.
fn implied_problems(text: &str, self_id: &str) -> Vec<String> {
    const MARK: &str = "implies_erdos_";
    let mut out: Vec<String> = Vec::new();
    let mut rest = text;
    while let Some(pos) = rest.find(MARK) {
        rest = &rest[pos + MARK.len()..];
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        if !digits.is_empty() && digits != self_id && !out.contains(&digits) {
            out.push(digits);
        }
    }
    out
}

/// formal-conjectures: `<dir>/N.lean` is the Lean formalization of Erdős #N; its
/// `@[category research solved|open]` annotation is the declared status.
pub fn read_formal(dir: &Path, rev: &str) -> Result<Vec<SourceRecord>, String> {
    let mut out = Vec::new();
    for path in lean_files(dir)? {
        let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        if !stem.chars().all(|c| c.is_ascii_digit()) || stem.is_empty() {
            continue; // numbered problem files only
        }
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        let status = if text.contains("category research open") {
            "open"
        } else if text.contains("category research solved") {
            "solved"
        } else {
            "open"
        };
        out.push(SourceRecord {
            external_id: stem.to_string(),
            assertion_text: format!(
                "Erdős Problem #{stem}: Lean formalization in \
                 google-deepmind/formal-conjectures (ErdosProblems/{stem}.lean @ {rev}), \
                 declared status '{status}'."
            ),
            assertion_type: "lean-formalization".into(),
            implies: implied_problems(&text, stem),
        });
    }
    Ok(out)
}

/// AlphaProof Nexus: `<dir>/erdos_<N>*.lean` variant formalizations of Erdős #N.
/// A corroborating member (status from the namespace, not a new resolution word).
pub fn read_alphaproof(dir: &Path, rev: &str) -> Result<Vec<SourceRecord>, String> {
    let mut out = Vec::new();
    for path in lean_files(dir)? {
        let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        let Some(n) = leading_number(stem) else {
            continue;
        };
        let fname = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        out.push(SourceRecord {
            external_id: n.clone(),
            assertion_text: format!(
                "Erdős Problem #{n}: AlphaProof Nexus variant formalization \
                 ({fname} @ {rev}). A corroborating Lean artifact."
            ),
            assertion_type: "lean-formalization".into(),
            implies: Vec::new(),
        });
    }
    Ok(out)
}

/// OEIS adapter: read an `ErdosOEIS` catalogue (a JSON document with a
/// `sequences` map of `A###### -> { id, name, terms }`, e.g.
/// `examples/erdos-problems/sources/oeis.v1.json`) and yield one record per
/// sequence. The native counterpart of the OEIS pass in
/// `scripts/atlas/ingest_tao.py`; deterministic (sorted by id). Fetching is out
/// of scope: this reads a local catalogue file, so the result is reproducible.
pub fn read_oeis(input: &Path, _rev: &str) -> Result<Vec<SourceRecord>, String> {
    let raw =
        std::fs::read_to_string(input).map_err(|e| format!("read {}: {e}", input.display()))?;
    let doc: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| format!("parse {}: {e}", input.display()))?;
    let seqs = doc
        .get("sequences")
        .and_then(|v| v.as_object())
        .ok_or_else(|| format!("{}: missing `sequences` object", input.display()))?;
    let mut out: Vec<SourceRecord> = Vec::new();
    for (id, entry) in seqs {
        let name = entry
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();
        if id.is_empty() || name.is_empty() {
            continue;
        }
        out.push(SourceRecord {
            external_id: id.clone(),
            assertion_text: format!("OEIS {id}: {name}"),
            assertion_type: "oeis-sequence".into(),
            implies: vec![],
        });
    }
    // BTreeMap-style determinism: serde_json object iteration is already sorted,
    // but sort explicitly so the contract does not depend on that.
    out.sort_by(|a, b| a.external_id.cmp(&b.external_id));
    if out.is_empty() {
        return Err(format!("{}: no usable sequences", input.display()));
    }
    Ok(out)
}

/// HorizonMath adapter: read a `HorizonMathCatalog` (a JSON document with a
/// `problems` array of verifier-attackable open problems, each
/// `{id, domain, level, statement, verifier_kind, incumbent{value,direction,basis}, status}`,
/// e.g. `data/horizonmath/catalog.json`) and yield one record per problem. Each
/// problem carries its frozen-verifier kind, its incumbent (value-to-beat), and
/// its declared status in the assertion text, so the ingested finding is a
/// faithful target for the foundry to attack. Deterministic (sorted by id); reads
/// a local catalogue file, so the result is reproducible (no network).
pub fn read_horizonmath(input: &Path, _rev: &str) -> Result<Vec<SourceRecord>, String> {
    let raw =
        std::fs::read_to_string(input).map_err(|e| format!("read {}: {e}", input.display()))?;
    let doc: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| format!("parse {}: {e}", input.display()))?;
    let problems = doc
        .get("problems")
        .and_then(|v| v.as_array())
        .ok_or_else(|| format!("{}: missing `problems` array", input.display()))?;
    let mut out: Vec<SourceRecord> = Vec::new();
    for p in problems {
        let id = p.get("id").and_then(|v| v.as_str()).unwrap_or("").trim();
        let statement = p
            .get("statement")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();
        if id.is_empty() || statement.is_empty() {
            continue;
        }
        let domain = p.get("domain").and_then(|v| v.as_str()).unwrap_or("");
        let level = p.get("level").and_then(|v| v.as_str()).unwrap_or("");
        let verifier = p
            .get("verifier_kind")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let status = p.get("status").and_then(|v| v.as_str()).unwrap_or("open");
        // Incumbent: the value-to-beat. A scalar `value` when one exists, else the
        // descriptive `basis` (per-parameter families have no single value).
        let inc = p.get("incumbent");
        let direction = inc
            .and_then(|i| i.get("direction"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let value = inc.and_then(|i| i.get("value")).and_then(|v| {
            if v.is_null() {
                None
            } else {
                Some(v.to_string())
            }
        });
        let basis = inc
            .and_then(|i| i.get("basis"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let incumbent_str = match &value {
            Some(v) => format!("incumbent {v} (direction {direction}; {basis})"),
            None => format!("incumbent per-parameter (direction {direction}; {basis})"),
        };
        out.push(SourceRecord {
            external_id: id.to_string(),
            assertion_text: format!(
                "HorizonMath/{id} [{domain}, level {level}]: {statement} \
                 Verifier: {verifier}. {incumbent_str}. Status: {status}."
            ),
            assertion_type: "horizonmath-problem".into(),
            implies: Vec::new(),
        });
    }
    out.sort_by(|a, b| a.external_id.cmp(&b.external_id));
    if out.is_empty() {
        return Err(format!("{}: no usable problems", input.display()));
    }
    Ok(out)
}

/// Formal-Conjectures (FULL corpus): read the staged `nodes.json` index (one
/// entry per `.lean` file: `{title, erdos, has_statement, path}`) under `dir`
/// and derive each statement-bearing file's declared status from its real
/// `@[category research open|solved]` annotations. The full-corpus counterpart
/// of `read_formal` (which reads only the numbered `ErdosProblems/N.lean`
/// files). Erdős-tagged files carry the Erdős number in the assertion text (the
/// HardIdentity join into the `erdos` namespace happens at compile/join time).
/// Deterministic (sorted by path); offline (reads the local Lean tree).
pub fn read_formal_corpus(dir: &Path, rev: &str) -> Result<Vec<SourceRecord>, String> {
    let index_path = dir.join("nodes.json");
    let raw = std::fs::read_to_string(&index_path)
        .map_err(|e| format!("read {}: {e}", index_path.display()))?;
    let doc: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| format!("parse {}: {e}", index_path.display()))?;
    let nodes = doc
        .as_array()
        .ok_or_else(|| format!("{}: expected a JSON array of nodes", index_path.display()))?;
    let mut out: Vec<SourceRecord> = Vec::new();
    for node in nodes {
        // Infra files (no statement) are not conjectures — skip them.
        if !node
            .get("has_statement")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            continue;
        }
        let rel = node
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();
        let title = node
            .get("title")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();
        if rel.is_empty() {
            continue;
        }
        let erdos = node
            .get("erdos")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        // Status from the real category annotations in the file. `research open`
        // wins (an unresolved conjecture in a file with mixed categories is open);
        // a file with only API/test/textbook statements is exposition, not a
        // research conjecture.
        let text = std::fs::read_to_string(dir.join(rel)).unwrap_or_default();
        let status = if text.contains("@[category research open") {
            "open"
        } else if text.contains("@[category research solved") {
            "solved"
        } else {
            "exposition"
        };
        let ext = rel
            .strip_prefix("formal-conjectures-main/")
            .unwrap_or(rel)
            .to_string();
        let erdos_note = match &erdos {
            Some(e) => format!(" Erdős #{e}."),
            None => String::new(),
        };
        out.push(SourceRecord {
            external_id: ext,
            assertion_text: format!(
                "Formal-Conjectures: {title} ({rel} @ {rev}), declared status '{status}'.{erdos_note}"
            ),
            assertion_type: "lean-formalization".into(),
            implies: implied_problems(&text, erdos.as_deref().unwrap_or("")),
        });
    }
    out.sort_by(|a, b| a.external_id.cmp(&b.external_id));
    if out.is_empty() {
        return Err(format!(
            "{}: no statement-bearing nodes",
            index_path.display()
        ));
    }
    Ok(out)
}

/// Dispatch an adapter by name.
pub fn read_adapter(adapter: &str, input: &Path, rev: &str) -> Result<Vec<SourceRecord>, String> {
    match adapter {
        "formal" => read_formal(input, rev),
        "formal_corpus" => read_formal_corpus(input, rev),
        "alphaproof" => read_alphaproof(input, rev),
        "oeis" => read_oeis(input, rev),
        "horizonmath" => read_horizonmath(input, rev),
        other => Err(format!(
            "unknown adapter '{other}' (supported: formal | formal_corpus | alphaproof | oeis | horizonmath; tao stays scripts/atlas/ingest_tao.py)"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leading_number_handles_alphaproof_filenames() {
        assert_eq!(leading_number("erdos_152").as_deref(), Some("152"));
        assert_eq!(leading_number("erdos_12.parts.i").as_deref(), Some("12"));
        assert_eq!(
            leading_number("erdos_125.variants.positive_lower_density").as_deref(),
            Some("125")
        );
        assert_eq!(leading_number("40").as_deref(), Some("40"));
        assert_eq!(leading_number("readme"), None);
    }

    #[test]
    fn implied_problems_finds_cross_refs_and_drops_self_loops() {
        let text = "theorem erdos_40.variants.implies_erdos_28 : ... \n import «28»";
        assert_eq!(implied_problems(text, "40"), vec!["28".to_string()]);
        // self-loop dropped
        assert!(implied_problems("erdos_90 implies_erdos_90", "90").is_empty());
        // none
        assert!(implied_problems("no refs here", "5").is_empty());
    }

    #[test]
    fn read_oeis_parses_sequences_deterministically() {
        let dir = std::env::temp_dir().join(format!("vela_oeis_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("oeis.v1.json");
        std::fs::write(
            &f,
            r#"{"object":"ErdosOEIS","sequences":{
                "A000040":{"id":"A000040","name":"The prime numbers.","terms":"2,3,5"},
                "A000001":{"id":"A000001","name":"Number of groups of order n.","terms":"0,1,1"},
                "A999999":{"id":"A999999","name":"","terms":""}
            }}"#,
        )
        .unwrap();
        let recs = read_oeis(&f, "test").unwrap();
        assert_eq!(recs.len(), 2, "empty-name sequence dropped");
        assert_eq!(recs[0].external_id, "A000001", "sorted by id");
        assert_eq!(recs[1].external_id, "A000040");
        assert_eq!(recs[0].assertion_type, "oeis-sequence");
        assert!(recs[1].assertion_text.contains("The prime numbers."));
        // a finding built from it is content-addressed like any other adapter record.
        assert!(build_finding(&recs[0], "oeis").id.starts_with("vf_"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn read_formal_corpus_derives_status_and_skips_infra() {
        let dir = std::env::temp_dir().join(format!("vela_fc_test_{}", std::process::id()));
        let tree = dir.join("formal-conjectures-main/FormalConjectures/Demo");
        std::fs::create_dir_all(&tree).unwrap();
        let open_rel = "formal-conjectures-main/FormalConjectures/Demo/Open.lean";
        let solved_rel = "formal-conjectures-main/FormalConjectures/Demo/Solved.lean";
        std::fs::write(
            dir.join(open_rel),
            "@[category research open, AMS 11]\ntheorem o : True := trivial\n",
        )
        .unwrap();
        std::fs::write(
            dir.join(solved_rel),
            "@[category research solved, AMS 5]\ntheorem s : True := trivial\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("nodes.json"),
            format!(
                r#"[
                  {{"title":"Open One","erdos":"42","has_statement":true,"path":"{open_rel}"}},
                  {{"title":"Solved One","erdos":null,"has_statement":true,"path":"{solved_rel}"}},
                  {{"title":"Infra","erdos":null,"has_statement":false,"path":"x.lean"}}
                ]"#
            ),
        )
        .unwrap();
        let recs = read_formal_corpus(&dir, "fc@test").unwrap();
        assert_eq!(recs.len(), 2, "infra node (no statement) skipped");
        // sorted by external id ("...Open.lean" < "...Solved.lean")
        assert!(recs[0].assertion_text.contains("declared status 'open'"));
        assert!(recs[0].assertion_text.contains("Erdős #42."));
        assert!(recs[1].assertion_text.contains("declared status 'solved'"));
        assert_eq!(recs[0].assertion_type, "lean-formalization");
        assert!(
            build_finding(&recs[0], "formal_corpus")
                .id
                .starts_with("vf_")
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn read_horizonmath_parses_problems_deterministically() {
        let dir = std::env::temp_dir().join(format!("vela_hm_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("catalog.json");
        std::fs::write(
            &f,
            r#"{"object":"HorizonMathCatalog","problems":[
                {"id":"hm-cap-8","domain":"finite_geometry","level":"challenging",
                 "statement":"Cap set in F_3^8.","verifier_kind":"cap","status":"open",
                 "incumbent":{"value":512,"direction":"max","basis":"FunSearch 2023"}},
                {"id":"hm-diff-triangle-7-5","domain":"combinatorial_design","level":"likely_solvable",
                 "statement":"DTS(7,5): minimize scope.","verifier_kind":"diff_triangle","status":"open",
                 "incumbent":{"value":112,"direction":"min","basis":"memo"}},
                {"id":"hm-sidon-range","domain":"additive_combinatorics","level":"challenging",
                 "statement":"Sidon set, maximize size.","verifier_kind":"sidon","status":"open",
                 "incumbent":{"value":null,"direction":"max","basis":"OEIS A309370"}},
                {"id":"","statement":"","verifier_kind":"x"}
            ]}"#,
        )
        .unwrap();
        let recs = read_horizonmath(&f, "test").unwrap();
        assert_eq!(recs.len(), 3, "empty-id/statement problem dropped");
        assert_eq!(recs[0].external_id, "hm-cap-8", "sorted by id");
        assert_eq!(recs[1].external_id, "hm-diff-triangle-7-5");
        assert_eq!(recs[0].assertion_type, "horizonmath-problem");
        // scalar incumbent is carried; per-parameter (null value) reads as such.
        assert!(
            recs[0]
                .assertion_text
                .contains("incumbent 512 (direction max")
        );
        assert!(
            recs[2]
                .assertion_text
                .contains("incumbent per-parameter (direction max")
        );
        assert!(recs[1].assertion_text.contains("Verifier: diff_triangle"));
        // a finding built from it is content-addressed like any other adapter record.
        assert!(build_finding(&recs[0], "horizonmath").id.starts_with("vf_"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn build_finding_is_content_addressed_and_deterministic() {
        let rec = SourceRecord {
            external_id: "40".into(),
            assertion_text: "Erdős Problem #40: declared status 'solved'.".into(),
            assertion_type: "lean-formalization".into(),
            implies: vec![],
        };
        let a = build_finding(&rec, "formal");
        let b = build_finding(&rec, "formal");
        assert_eq!(a.id, b.id, "same record → same content-addressed id");
        assert!(a.id.starts_with("vf_"));
        assert_eq!(a.created, "2026-06-16T00:00:00Z", "created is pinned");
    }
}
