//! v0.163: preprint export. Render a frontier as a Markdown
//! preprint with abstract, contributors (CRediT block), findings
//! as evidence sections, and a citation block (BibTeX). Pure
//! derivation from the substrate state.
//!
//! Substrate-honest framing: the substrate emits a publish-ready
//! Markdown manuscript; the author is free to extend it with
//! narrative prose before submission, but the evidence + citation
//! + contributor block stay content-addressed against the
//! frontier state.

use crate::citation::{CitationFormat, render_frontier as render_citation};
use crate::credit::build_ledger;
use vela_protocol::project::Project;

/// Render a frontier as a Markdown preprint body. The `released_at`
/// timestamp pins which substrate state the preprint quotes (used
/// for the credit-ledger snapshot and the footer).
pub fn render_preprint(project: &Project, released_at: &str) -> String {
    let mut out = String::new();
    let title = &project.project.name;
    out.push_str(&format!("# {title}\n\n"));

    let frontier_id = project.frontier_id();
    out.push_str(&format!("**Frontier:** `{frontier_id}`  \n"));
    out.push_str(&format!("**Released:** {released_at}  \n"));
    out.push_str(&format!(
        "**Findings:** {} total  \n",
        project.findings.len()
    ));
    out.push('\n');

    if !project.project.description.is_empty() {
        out.push_str("## Abstract\n\n");
        out.push_str(&project.project.description);
        out.push_str("\n\n");
    }

    // Contributors / CRediT.
    let ledger = build_ledger(project, released_at);
    if !ledger.contributors.is_empty() {
        out.push_str("## Contributors\n\n");
        for c in &ledger.contributors {
            let orcid = match &c.orcid {
                Some(o) => format!(" (ORCID: {o})"),
                None => String::new(),
            };
            out.push_str(&format!(
                "- **{}**{orcid} · {} event(s)\n",
                c.actor_id, c.event_count
            ));
            for role in &c.roles {
                let count = c.role_counts.get(role).copied().unwrap_or(0);
                out.push_str(&format!("    - {role} ({count})\n"));
            }
        }
        out.push('\n');
    }

    // Findings as evidence sections.
    out.push_str("## Evidence\n\n");
    if project.findings.is_empty() {
        out.push_str("_No findings yet on this frontier._\n\n");
    } else {
        for f in &project.findings {
            out.push_str(&format!("### {}\n\n", f.assertion.text));
            out.push_str(&format!("- **Finding:** `{}`  \n", f.id));
            if let Some(doi) = &f.provenance.doi {
                out.push_str(&format!("- **DOI:** [{doi}](https://doi.org/{doi})  \n"));
            }
            if let Some(year) = f.provenance.year {
                out.push_str(&format!("- **Year:** {year}  \n"));
            }
            if !f.provenance.authors.is_empty() {
                let authors: Vec<String> = f
                    .provenance
                    .authors
                    .iter()
                    .map(|a| a.name.clone())
                    .collect();
                out.push_str(&format!("- **Authors:** {}  \n", authors.join(", ")));
            }
            out.push('\n');
        }
    }

    // Citation block.
    out.push_str("## Citation\n\n");
    out.push_str("```bibtex\n");
    out.push_str(&render_citation(project, CitationFormat::Bibtex, None));
    out.push_str("```\n\n");

    // Footer.
    out.push_str("---\n\n");
    out.push_str(&format!(
        "Generated from Vela frontier `{frontier_id}` at {released_at}.  \n"
    ));
    out.push_str(&format!(
        "Substrate-side state at <https://vela-site.fly.dev/frontier/{frontier_id}>.\n"
    ));

    out
}
