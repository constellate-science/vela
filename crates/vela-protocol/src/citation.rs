//! v0.156: citation export. Render a Vela frontier or finding as
//! BibTeX, RIS, or CSL-JSON. The output is downstream-tooling-
//! ready: BibTeX feeds into LaTeX bibliography lists; RIS into
//! Zotero / EndNote / Mendeley; CSL-JSON into Pandoc + most
//! reference managers.
//!
//! Substrate-honest framing: the substrate ships citation
//! rendering against the canonical Project + finding state. It
//! does not mint identifiers (DOIs live at v0.160; arXiv ids
//! live on the source paper). A Vela frontier is rendered as
//! `@software` (BibTeX) / `TY  - DATA` (RIS) / `type: software`
//! (CSL-JSON). A single finding inside a frontier is rendered
//! as `@misc` / `TY  - GEN` / `type: article-journal` when a
//! DOI is present on the provenance.

use crate::bundle::FindingBundle;
use crate::project::Project;

/// Citation output formats. The CLI takes a lowercase string;
/// the dispatcher routes to the matching renderer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CitationFormat {
    Bibtex,
    Ris,
    CslJson,
}

impl CitationFormat {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "bibtex" | "bib" => Ok(CitationFormat::Bibtex),
            "ris" => Ok(CitationFormat::Ris),
            "csl" | "csl-json" | "csljson" | "json" => Ok(CitationFormat::CslJson),
            other => Err(format!(
                "unknown citation format `{other}`. Valid: bibtex, ris, csl-json"
            )),
        }
    }
}

/// Render a whole frontier as a citation. Frontier-as-citation
/// shape:
///
///   type     = software (or dataset)
///   title    = project.name
///   authors  = actors registered in the frontier (ORDER:
///              actors_array as-listed; revoked actors are
///              excluded)
///   year     = first 4 chars of project.created_at
///   id       = frontier_id (vfr_*)
///   url      = `vela://frontier/<vfr_id>` (substrate-internal)
///              OR the network_locator the operator provides
pub fn render_frontier(
    project: &Project,
    format: CitationFormat,
    network_locator: Option<&str>,
) -> String {
    let vfr_id = project.frontier_id();
    let title = project.project.name.clone();
    let year = project
        .project
        .compiled_at
        .get(..4)
        .unwrap_or("")
        .to_string();
    let authors: Vec<String> = project
        .actors
        .iter()
        .filter(|a| a.revoked_at.is_none())
        .map(|a| a.id.clone())
        .collect();
    let url = network_locator
        .map(str::to_string)
        .unwrap_or_else(|| format!("vela://frontier/{vfr_id}"));

    match format {
        CitationFormat::Bibtex => render_frontier_bibtex(&vfr_id, &title, &authors, &year, &url),
        CitationFormat::Ris => render_frontier_ris(&vfr_id, &title, &authors, &year, &url),
        CitationFormat::CslJson => render_frontier_csl(&vfr_id, &title, &authors, &year, &url),
    }
}

/// Render a single finding as a citation. Finding-as-citation:
///
///   type     = article-journal (if provenance.doi present)
///              else misc
///   title    = assertion.text
///   authors  = provenance.source_authors (if present)
///   year     = provenance.year (if present)
///   doi      = provenance.doi (if present)
///   id       = finding_id (vf_*)
///   url      = doi.org URL if doi, else vela://frontier/...
pub fn render_finding(
    project: &Project,
    finding: &FindingBundle,
    format: CitationFormat,
) -> String {
    let vfr_id = project.frontier_id();
    let title = finding.assertion.text.clone();
    let id = finding.id.clone();
    let year = finding
        .provenance
        .year
        .map(|y| y.to_string())
        .unwrap_or_default();
    let authors: Vec<String> = finding
        .provenance
        .authors
        .iter()
        .map(|a| a.name.clone())
        .collect();
    let doi = finding.provenance.doi.clone();
    let pmid = finding.provenance.pmid.clone();
    let url = doi
        .as_ref()
        .map(|d| format!("https://doi.org/{d}"))
        .or_else(|| {
            pmid.as_ref()
                .map(|p| format!("https://pubmed.ncbi.nlm.nih.gov/{p}/"))
        })
        .unwrap_or_else(|| format!("vela://frontier/{vfr_id}/finding/{id}"));

    match format {
        CitationFormat::Bibtex => {
            render_finding_bibtex(&id, &title, &authors, &year, doi.as_deref(), &url)
        }
        CitationFormat::Ris => {
            render_finding_ris(&id, &title, &authors, &year, doi.as_deref(), &url)
        }
        CitationFormat::CslJson => {
            render_finding_csl(&id, &title, &authors, &year, doi.as_deref(), &url)
        }
    }
}

// --- BibTeX renderers ---

fn render_frontier_bibtex(
    vfr_id: &str,
    title: &str,
    authors: &[String],
    year: &str,
    url: &str,
) -> String {
    let authors_joined = if authors.is_empty() {
        "Vela Substrate".to_string()
    } else {
        authors.join(" and ")
    };
    format!(
        "@software{{{key},\n  title = {{{title}}},\n  author = {{{author}}},\n  year = {{{year}}},\n  url = {{{url}}},\n  note = {{Vela frontier {vfr_id}}}\n}}\n",
        key = vfr_id,
        title = bibtex_escape(title),
        author = bibtex_escape(&authors_joined),
        year = year,
        url = url,
        vfr_id = vfr_id,
    )
}

fn render_finding_bibtex(
    finding_id: &str,
    title: &str,
    authors: &[String],
    year: &str,
    doi: Option<&str>,
    url: &str,
) -> String {
    let kind = if doi.is_some() { "article" } else { "misc" };
    let authors_joined = if authors.is_empty() {
        "(unattributed)".to_string()
    } else {
        authors.join(" and ")
    };
    let doi_line = doi
        .map(|d| format!("  doi = {{{d}}},\n"))
        .unwrap_or_default();
    format!(
        "@{kind}{{{key},\n  title = {{{title}}},\n  author = {{{author}}},\n  year = {{{year}}},\n{doi_line}  url = {{{url}}}\n}}\n",
        kind = kind,
        key = finding_id,
        title = bibtex_escape(title),
        author = bibtex_escape(&authors_joined),
        year = year,
        doi_line = doi_line,
        url = url,
    )
}

fn bibtex_escape(s: &str) -> String {
    // Minimal escaping: keep braces balanced, escape leading-
    // capital protection by keeping the value inside the
    // outer braces.
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

// --- RIS renderers ---

fn render_frontier_ris(
    vfr_id: &str,
    title: &str,
    authors: &[String],
    year: &str,
    url: &str,
) -> String {
    let mut out = String::new();
    out.push_str("TY  - DATA\n");
    out.push_str(&format!("ID  - {vfr_id}\n"));
    out.push_str(&format!("TI  - {title}\n"));
    for a in authors {
        out.push_str(&format!("AU  - {a}\n"));
    }
    if !year.is_empty() {
        out.push_str(&format!("PY  - {year}\n"));
    }
    out.push_str(&format!("UR  - {url}\n"));
    out.push_str(&format!("N1  - Vela frontier {vfr_id}\n"));
    out.push_str("ER  -\n");
    out
}

fn render_finding_ris(
    finding_id: &str,
    title: &str,
    authors: &[String],
    year: &str,
    doi: Option<&str>,
    url: &str,
) -> String {
    let ty = if doi.is_some() { "JOUR" } else { "GEN" };
    let mut out = String::new();
    out.push_str(&format!("TY  - {ty}\n"));
    out.push_str(&format!("ID  - {finding_id}\n"));
    out.push_str(&format!("TI  - {title}\n"));
    for a in authors {
        out.push_str(&format!("AU  - {a}\n"));
    }
    if !year.is_empty() {
        out.push_str(&format!("PY  - {year}\n"));
    }
    if let Some(d) = doi {
        out.push_str(&format!("DO  - {d}\n"));
    }
    out.push_str(&format!("UR  - {url}\n"));
    out.push_str("ER  -\n");
    out
}

// --- CSL-JSON renderers ---

fn render_frontier_csl(
    vfr_id: &str,
    title: &str,
    authors: &[String],
    year: &str,
    url: &str,
) -> String {
    let issued = if year.is_empty() {
        serde_json::json!({})
    } else {
        let parsed = year.parse::<i64>().unwrap_or(0);
        serde_json::json!({"date-parts": [[parsed]]})
    };
    let author_array: Vec<serde_json::Value> = authors
        .iter()
        .map(|a| serde_json::json!({"literal": a}))
        .collect();
    let entry = serde_json::json!({
        "id": vfr_id,
        "type": "software",
        "title": title,
        "author": author_array,
        "issued": issued,
        "URL": url,
        "note": format!("Vela frontier {vfr_id}"),
    });
    let mut out = serde_json::to_string_pretty(&[entry]).unwrap_or_else(|_| "[]".to_string());
    out.push('\n');
    out
}

fn render_finding_csl(
    finding_id: &str,
    title: &str,
    authors: &[String],
    year: &str,
    doi: Option<&str>,
    url: &str,
) -> String {
    let csl_type = if doi.is_some() {
        "article-journal"
    } else {
        "article"
    };
    let issued = if year.is_empty() {
        serde_json::json!({})
    } else {
        let parsed = year.parse::<i64>().unwrap_or(0);
        serde_json::json!({"date-parts": [[parsed]]})
    };
    let author_array: Vec<serde_json::Value> = authors
        .iter()
        .map(|a| serde_json::json!({"literal": a}))
        .collect();
    let mut entry = serde_json::json!({
        "id": finding_id,
        "type": csl_type,
        "title": title,
        "author": author_array,
        "issued": issued,
        "URL": url,
    });
    if let Some(d) = doi {
        entry["DOI"] = serde_json::Value::String(d.to_string());
    }
    let mut out = serde_json::to_string_pretty(&[entry]).unwrap_or_else(|_| "[]".to_string());
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_format_accepts_aliases() {
        assert_eq!(
            CitationFormat::parse("bibtex").unwrap(),
            CitationFormat::Bibtex
        );
        assert_eq!(
            CitationFormat::parse("bib").unwrap(),
            CitationFormat::Bibtex
        );
        assert_eq!(CitationFormat::parse("RIS").unwrap(), CitationFormat::Ris);
        assert_eq!(
            CitationFormat::parse("csl-json").unwrap(),
            CitationFormat::CslJson
        );
        assert_eq!(
            CitationFormat::parse("csl").unwrap(),
            CitationFormat::CslJson
        );
    }

    #[test]
    fn parse_format_rejects_unknown() {
        assert!(CitationFormat::parse("apa").is_err());
    }
}
