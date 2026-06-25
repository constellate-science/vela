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

// --- BibTeX renderers ---
// --- RIS renderers ---
// --- CSL-JSON renderers ---
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
