//! v0.123: Vela Relay — the adapter layer between external scientific
//! activity (papers, agent runtime artifacts, hypothesis discourse,
//! review packets) and Vela proposals.
//!
//! This crate is the library + binary packaging of the substrate's
//! adapter contract. The four adapter shapes documented in
//! `docs/RELAY.md` are:
//!
//! 1. **paper-to-Vela** — Crossref / PubMed / Semantic Scholar / ArXiv
//!    metadata fetch normalized into a Carina artifact packet, then
//!    funneled through `vela bridge-kit verify-provenance` or
//!    `vela ingest doi:* | pmid:* | s2:* | arxiv:*`.
//! 2. **artifact-to-Vela** — ScienceClaw artifact exports normalized
//!    via `vela-protocol::artifact_to_state` and consumed by
//!    `vela artifact-to-state` / `vela runtime-adapter run`.
//! 3. **hypothesis-to-Vela** — agent discourse (posts, comments,
//!    links) normalized via the `AGENT_DISCOURSE_V1` runtime adapter
//!    into proposals.
//! 4. **review-to-Vela** — Agent4Science review packets normalized via
//!    the `AGENT4SCIENCE_REVIEW_V1` runtime adapter into attestation
//!    proposals.
//!
//! The substrate-side implementation of every adapter lives in
//! `vela-protocol` (`source_adapters.rs` and `runtime_adapters.rs`).
//! This crate re-exports the relevant types so downstream Rust users
//! can implement custom adapters against the same contract without
//! taking a full `vela-protocol` dependency.
//!
//! ## Library surface
//!
//! [`AdapterShape`] enumerates the four canonical adapter shapes.
//! [`describe`] returns a human-readable contract summary for one
//! shape. The binary's `--list` flag prints all four.
//!
//! ## Re-exports
//!
//! - [`vela_edge::artifact_to_state::ArtifactPacket`] — input/output type for the artifact-to-vela shape.
//! - [`vela_edge::source_adapters`] — the source-adapter spec table.
//! - [`vela_edge::runtime_adapters`] — the runtime-adapter spec table.
//!
//! Doctrine: this crate does not implement adapters itself. It
//! exposes the four-shape contract so the substrate's adapter
//! ecosystem can grow without touching the kernel crate.

pub use vela_edge::artifact_to_state;
pub use vela_edge::runtime_adapters;
pub use vela_edge::source_adapters;

/// v0.142: paper-to-vela end-to-end. See `paper::paper_to_vela`.
pub mod paper;

/// The four canonical adapter shapes the Vela Relay layer carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterShape {
    PaperToVela,
    ArtifactToVela,
    HypothesisToVela,
    ReviewToVela,
}

impl AdapterShape {
    /// All four shapes in the documented order.
    pub const ALL: &'static [AdapterShape] = &[
        AdapterShape::PaperToVela,
        AdapterShape::ArtifactToVela,
        AdapterShape::HypothesisToVela,
        AdapterShape::ReviewToVela,
    ];

    /// The slug used on the binary's CLI.
    pub fn slug(&self) -> &'static str {
        match self {
            AdapterShape::PaperToVela => "paper-to-vela",
            AdapterShape::ArtifactToVela => "artifact-to-vela",
            AdapterShape::HypothesisToVela => "hypothesis-to-vela",
            AdapterShape::ReviewToVela => "review-to-vela",
        }
    }

    /// Map a CLI slug back to a shape variant.
    pub fn from_slug(s: &str) -> Option<AdapterShape> {
        AdapterShape::ALL.iter().copied().find(|sh| sh.slug() == s)
    }
}

/// A summary of one adapter shape's contract.
#[derive(Debug, Clone)]
pub struct AdapterContract {
    pub shape: AdapterShape,
    pub input: &'static str,
    pub output: &'static str,
    pub canonical_cli: &'static str,
    pub backing_module: &'static str,
}

/// Describe one adapter shape's input, output, and canonical CLI surface.
pub fn describe(shape: AdapterShape) -> AdapterContract {
    match shape {
        AdapterShape::PaperToVela => AdapterContract {
            shape,
            input: "Crossref / PubMed / Semantic Scholar / ArXiv metadata (DOI, PMID, S2 paperId, arxiv id, or URL)",
            output: "Carina artifact + finding proposal envelope (vpr_*)",
            canonical_cli: "vela bridge-kit verify-provenance · vela ingest <doi:* | pmid:* | s2:* | arxiv:*>",
            backing_module: "crates/vela-protocol/src/source_adapters.rs · cli.rs::verify_packet_provenance",
        },
        AdapterShape::ArtifactToVela => AdapterContract {
            shape,
            input: "ScienceClaw artifact export (JSON), Carina artifact packet (carina.artifact_packet.v0.1)",
            output: "Carina artifact + finding + gap proposals",
            canonical_cli: "vela artifact-to-state · vela runtime-adapter run scienceclaw-artifact-v1",
            backing_module: "crates/vela-protocol/src/artifact_to_state.rs · runtime_adapters.rs::SCIENCECLAW_ARTIFACT_V1",
        },
        AdapterShape::HypothesisToVela => AdapterContract {
            shape,
            input: "Agent discourse export (post / comment / review / link records)",
            output: "Carina artifact + finding + review-note proposals",
            canonical_cli: "vela runtime-adapter run agent-discourse-v1",
            backing_module: "crates/vela-protocol/src/runtime_adapters.rs::AGENT_DISCOURSE_V1",
        },
        AdapterShape::ReviewToVela => AdapterContract {
            shape,
            input: "Agent4Science-style review packet (assertion id + verdict + evidence + reviewer key)",
            output: "Carina attestation proposal",
            canonical_cli: "vela runtime-adapter run agent4science-review-v1",
            backing_module: "crates/vela-protocol/src/runtime_adapters.rs::AGENT4SCIENCE_REVIEW_V1",
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_four_shapes_enumerated() {
        assert_eq!(AdapterShape::ALL.len(), 4);
    }

    #[test]
    fn round_trip_slugs() {
        for shape in AdapterShape::ALL {
            let slug = shape.slug();
            assert_eq!(AdapterShape::from_slug(slug), Some(*shape));
        }
    }

    #[test]
    fn unknown_slug_rejected() {
        assert_eq!(AdapterShape::from_slug("bogus-adapter"), None);
    }

    #[test]
    fn describe_returns_contract_for_every_shape() {
        for shape in AdapterShape::ALL {
            let c = describe(*shape);
            assert_eq!(c.shape, *shape);
            assert!(!c.input.is_empty());
            assert!(!c.output.is_empty());
            assert!(!c.canonical_cli.is_empty());
            assert!(!c.backing_module.is_empty());
        }
    }
}
