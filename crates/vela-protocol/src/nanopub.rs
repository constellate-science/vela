//! Nanopublication export.
//!
//! A [nanopublication](https://nanopub.net) is the closest existing
//! standard to a Vela finding: a small, self-contained, content-
//! addressed knowledge-graph unit with three named graphs — an
//! *assertion* (the claim), a *provenance* graph (how it came to be),
//! and a *publication-info* graph (metadata about the unit) — plus a
//! head that ties them together. Vela's `vf_*` is a richer, typed,
//! gated cousin; emitting nanopublication TriG lets a frontier
//! interoperate with the FAIR / semantic-web science ecosystem
//! instead of being a silo.
//!
//! This is a faithful but pragmatic export: a single finding becomes
//! one nanopublication anchored on its content-addressed `vf_*` id.
//! (Real nanopublications also mint a trusty-URI hash over the RDF;
//! the `vf_*` id is already a content hash and serves as the stable
//! anchor here.)

use crate::bundle::FindingBundle;

/// Escape a string for use inside a Turtle/TriG double-quoted literal.
fn lit(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(c),
        }
    }
    out
}

/// Render a finding as a nanopublication in TriG. Deterministic: the
/// same finding and frontier id always produce byte-identical output.
#[must_use]
pub fn finding_to_nanopub_trig(finding: &FindingBundle, frontier_id: &str) -> String {
    let base = format!("https://w3id.org/vela/np/{}", finding.id);
    let p = &finding.provenance;

    // Provenance source: prefer a resolvable URI (DOI, then PubMed),
    // else fall back to the title as a literal.
    let derived_from = if let Some(doi) = p.doi.as_deref().filter(|d| !d.is_empty()) {
        format!("<https://doi.org/{}>", doi.trim())
    } else if let Some(pmid) = p.pmid.as_deref().filter(|m| !m.is_empty()) {
        format!("<https://pubmed.ncbi.nlm.nih.gov/{}/>", pmid.trim())
    } else {
        format!("\"{}\"", lit(&p.title))
    };

    let mut s = String::new();
    s.push_str("@prefix this: <");
    s.push_str(&base);
    s.push_str("> .\n");
    s.push_str("@prefix sub: <");
    s.push_str(&base);
    s.push_str("#> .\n");
    s.push_str("@prefix np: <http://www.nanopub.org/nschema#> .\n");
    s.push_str("@prefix prov: <http://www.w3.org/ns/prov#> .\n");
    s.push_str("@prefix dct: <http://purl.org/dc/terms/> .\n");
    s.push_str("@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .\n");
    s.push_str("@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .\n");
    s.push_str("@prefix vela: <https://vela.science/ns#> .\n\n");

    // Head: declare the nanopub and point at its three graphs.
    s.push_str("sub:Head {\n");
    s.push_str("  this: a np:Nanopublication ;\n");
    s.push_str("    np:hasAssertion sub:assertion ;\n");
    s.push_str("    np:hasProvenance sub:provenance ;\n");
    s.push_str("    np:hasPublicationInfo sub:pubinfo .\n");
    s.push_str("}\n\n");

    // Assertion: the claim itself.
    s.push_str("sub:assertion {\n");
    s.push_str("  sub:finding a vela:Finding ;\n");
    s.push_str(&format!("    rdfs:label \"{}\" ;\n", lit(&finding.assertion.text)));
    s.push_str(&format!(
        "    vela:findingId \"{}\" ;\n",
        lit(&finding.id)
    ));
    s.push_str(&format!(
        "    vela:assertionType \"{}\" ;\n",
        lit(&finding.assertion.assertion_type)
    ));
    s.push_str(&format!(
        "    vela:confidence \"{}\"^^xsd:decimal .\n",
        finding.confidence.score
    ));
    s.push_str("}\n\n");

    // Provenance: how the assertion came to be.
    s.push_str("sub:provenance {\n");
    s.push_str(&format!("  sub:assertion prov:wasDerivedFrom {derived_from} ;\n"));
    s.push_str(&format!(
        "    vela:method \"{}\" ;\n",
        lit(&finding.evidence.method)
    ));
    s.push_str(&format!(
        "    vela:evidenceType \"{}\" .\n",
        lit(&finding.evidence.evidence_type)
    ));
    s.push_str("}\n\n");

    // Publication info: metadata about the nanopub unit.
    s.push_str("sub:pubinfo {\n");
    s.push_str("  this: vela:schema \"vela.finding.nanopub.v0.1\" ;\n");
    s.push_str(&format!("    vela:frontier \"{}\" ;\n", lit(frontier_id)));
    if !finding.created.is_empty() {
        s.push_str(&format!(
            "    dct:created \"{}\"^^xsd:dateTime ;\n",
            lit(&finding.created)
        ));
    }
    if let Some(year) = p.year {
        s.push_str(&format!("    dct:date \"{year}\" ;\n"));
    }
    s.push_str("    dct:creator vela:frontier-substrate .\n");
    s.push_str("}\n");

    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::project::reverse_dep_index_tests::synth_finding;

    fn finding_with_provenance(id: &str, text: &str, doi: Option<&str>) -> FindingBundle {
        let mut f = synth_finding(0, vec![]);
        f.id = id.to_string();
        f.assertion.text = text.to_string();
        f.provenance.doi = doi.map(str::to_string);
        f.provenance.pmid = None;
        f
    }

    #[test]
    fn emits_four_named_graphs_and_core_triples() {
        let f = finding_with_provenance(
            "vf_1111111111111111",
            "Tau drives neurodegeneration",
            Some("10.1000/xyz"),
        );
        let trig = finding_to_nanopub_trig(&f, "vfr_test");

        // The four nanopublication graphs.
        assert!(trig.contains("sub:Head {"));
        assert!(trig.contains("sub:assertion {"));
        assert!(trig.contains("sub:provenance {"));
        assert!(trig.contains("sub:pubinfo {"));
        assert!(trig.contains("a np:Nanopublication"));

        // Core content.
        assert!(trig.contains("Tau drives neurodegeneration"));
        assert!(trig.contains("vela:findingId \"vf_1111111111111111\""));
        assert!(trig.contains("prov:wasDerivedFrom <https://doi.org/10.1000/xyz>"));
        assert!(trig.contains("vela:frontier \"vfr_test\""));
        assert!(trig.contains("vela.finding.nanopub.v0.1"));
    }

    #[test]
    fn falls_back_to_pubmed_then_title_for_provenance() {
        let mut f =
            finding_with_provenance("vf_2222222222222222", "claim", None);
        f.provenance.pmid = Some("12345".into());
        let trig = finding_to_nanopub_trig(&f, "vfr_x");
        assert!(trig.contains("<https://pubmed.ncbi.nlm.nih.gov/12345/>"));
    }

    #[test]
    fn escapes_quotes_in_literals() {
        let f = finding_with_provenance(
            "vf_3333333333333333",
            "a \"quoted\" claim",
            Some("10.1/q"),
        );
        let trig = finding_to_nanopub_trig(&f, "vfr_x");
        assert!(trig.contains("a \\\"quoted\\\" claim"));
    }

    #[test]
    fn is_deterministic() {
        let f = finding_with_provenance("vf_4444444444444444", "claim", Some("10.1/d"));
        assert_eq!(
            finding_to_nanopub_trig(&f, "vfr_x"),
            finding_to_nanopub_trig(&f, "vfr_x")
        );
    }
}
