//! v0.163: persistent-identifier resolver. Given a handle that
//! references something inside or adjacent to the substrate,
//! resolve it to a structured `ResolvedRef`: the kind of object
//! (frontier, release, finding, etc.), a canonical site URL, and
//! a short label.
//!
//! Substrate-honest framing: this is a pure derivation from the
//! handle's shape — the substrate does not need to round-trip to
//! a hub to give a useful answer. For `vfr_*` ids the resolver
//! points at the live site's `/frontier/<vfr>` route; for DOIs it
//! points at `https://doi.org/<doi>`; for arXiv ids it points at
//! `https://arxiv.org/abs/<id>`. Two consumers parsing the same
//! handle produce byte-identical `ResolvedRef` records.

use serde::{Deserialize, Serialize};

pub const RESOLVE_SCHEMA: &str = "vela.resolved_ref.v0.1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HandleKind {
    Frontier,
    FrontierRelease,
    Finding,
    Proposal,
    Bridge,
    Atlas,
    Constellation,
    Actor,
    Artifact,
    ProofPrimitive,
    ProofVerification,
    GovernancePolicy,
    OwnerRotateProposal,
    AttestationBundle,
    RegistryCheckpoint,
    SearchIndex,
    Doi,
    ArxivId,
    Orcid,
    Unknown,
}

impl HandleKind {
    pub fn label(self) -> &'static str {
        match self {
            HandleKind::Frontier => "frontier",
            HandleKind::FrontierRelease => "frontier-release",
            HandleKind::Finding => "finding",
            HandleKind::Proposal => "proposal",
            HandleKind::Bridge => "bridge",
            HandleKind::Atlas => "atlas",
            HandleKind::Constellation => "constellation",
            HandleKind::Actor => "actor",
            HandleKind::Artifact => "artifact",
            HandleKind::ProofPrimitive => "proof-primitive",
            HandleKind::ProofVerification => "proof-verification",
            HandleKind::GovernancePolicy => "governance-policy",
            HandleKind::OwnerRotateProposal => "owner-rotate-proposal",
            HandleKind::AttestationBundle => "attestation-bundle",
            HandleKind::RegistryCheckpoint => "registry-checkpoint",
            HandleKind::SearchIndex => "search-index",
            HandleKind::Doi => "doi",
            HandleKind::ArxivId => "arxiv-id",
            HandleKind::Orcid => "orcid",
            HandleKind::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResolvedRef {
    pub schema: String,
    pub handle: String,
    pub kind: HandleKind,
    /// Canonical URL to follow. None when the handle is well-
    /// formed but the substrate has no opinion about where to
    /// resolve it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Short human-readable label for the resolved kind.
    pub label: String,
}

/// Resolve a handle against the substrate URL conventions. The
/// `site_base` is the live-site origin (e.g. `https://app.constellate.science`).
pub fn resolve(handle: &str, site_base: &str) -> ResolvedRef {
    let trimmed = handle.trim();
    let base = site_base.trim_end_matches('/');

    let (kind, url) = classify(trimmed, base);

    ResolvedRef {
        schema: RESOLVE_SCHEMA.to_string(),
        handle: trimmed.to_string(),
        kind,
        url,
        label: kind.label().to_string(),
    }
}

fn classify(h: &str, base: &str) -> (HandleKind, Option<String>) {
    // Substrate prefixes are content-addressed; their shape alone
    // is enough to dispatch.
    if let Some(rest) = h.strip_prefix("vfr_")
        && is_hex_id(rest)
    {
        return (HandleKind::Frontier, Some(format!("{base}/frontier/{h}")));
    }
    if let Some(rest) = h.strip_prefix("vfrr_")
        && is_hex_id(rest)
    {
        return (
            HandleKind::FrontierRelease,
            Some(format!("{base}/release/{h}")),
        );
    }
    if h.starts_with("vf_") && is_hex_id(&h[3..]) {
        return (HandleKind::Finding, Some(format!("{base}/finding/{h}")));
    }
    if h.starts_with("vpr_") && is_hex_id(&h[4..]) {
        return (HandleKind::Proposal, Some(format!("{base}/proposal/{h}")));
    }
    if h.starts_with("vbr_") && is_hex_id(&h[4..]) {
        return (HandleKind::Bridge, Some(format!("{base}/bridge/{h}")));
    }
    if h.starts_with("vat_") && is_hex_id(&h[4..]) {
        return (HandleKind::Atlas, Some(format!("{base}/atlases/{h}")));
    }
    if h.starts_with("vct_") && is_hex_id(&h[4..]) {
        return (
            HandleKind::Constellation,
            Some(format!("{base}/constellations/{h}")),
        );
    }
    if h.starts_with("vac_") && is_hex_id(&h[4..]) {
        return (HandleKind::Actor, Some(format!("{base}/actors/{h}")));
    }
    if h.starts_with("va_") && is_hex_id(&h[3..]) {
        return (HandleKind::Artifact, Some(format!("{base}/artifact/{h}")));
    }
    if h.starts_with("vpf_") && is_hex_id(&h[4..]) {
        return (
            HandleKind::ProofPrimitive,
            Some(format!("{base}/proof/{h}")),
        );
    }
    if h.starts_with("vpv_") && is_hex_id(&h[4..]) {
        return (
            HandleKind::ProofVerification,
            Some(format!("{base}/proof-verification/{h}")),
        );
    }
    if h.starts_with("vgp_") && is_hex_id(&h[4..]) {
        return (
            HandleKind::GovernancePolicy,
            Some(format!("{base}/governance/{h}")),
        );
    }
    if h.starts_with("vop_") && is_hex_id(&h[4..]) {
        return (
            HandleKind::OwnerRotateProposal,
            Some(format!("{base}/governance/proposal/{h}")),
        );
    }
    if h.starts_with("vab_") && is_hex_id(&h[4..]) {
        return (
            HandleKind::AttestationBundle,
            Some(format!("{base}/governance/bundle/{h}")),
        );
    }
    if h.starts_with("vrc_") && is_hex_id(&h[4..]) {
        return (
            HandleKind::RegistryCheckpoint,
            Some(format!("{base}/checkpoint/{h}")),
        );
    }
    if h.starts_with("vsi_") && is_hex_id(&h[4..]) {
        return (HandleKind::SearchIndex, Some(format!("{base}/search/{h}")));
    }

    // DOI: starts with `10.` and contains a `/`.
    if h.starts_with("10.") && h.contains('/') {
        return (HandleKind::Doi, Some(format!("https://doi.org/{h}")));
    }
    // arXiv post-2007: NNNN.NNNNN(vN). Pre-2007: archive/NNNNNNN.
    if is_arxiv(h) {
        return (
            HandleKind::ArxivId,
            Some(format!("https://arxiv.org/abs/{h}")),
        );
    }
    // ORCID: 4 groups of 4 digits / hyphens; final char can be X.
    if is_orcid(h) {
        return (HandleKind::Orcid, Some(format!("https://orcid.org/{h}")));
    }
    (HandleKind::Unknown, None)
}

fn is_hex_id(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn is_arxiv(s: &str) -> bool {
    // Strip an optional vN trailer.
    let core = match s.rfind('v') {
        Some(i) if i > 0 && s[i + 1..].chars().all(|c| c.is_ascii_digit()) => &s[..i],
        _ => s,
    };
    // Post-2007: NNNN.NNNNN with optional 5th digit.
    if let Some((a, b)) = core.split_once('.')
        && a.len() == 4
        && (b.len() == 4 || b.len() == 5)
    {
        return a.chars().all(|c| c.is_ascii_digit()) && b.chars().all(|c| c.is_ascii_digit());
    }
    // Pre-2007: subject-class/NNNNNNN.
    if let Some((sub, num)) = core.split_once('/') {
        return !sub.is_empty()
            && sub.chars().all(|c| c.is_ascii_alphabetic() || c == '-')
            && num.len() == 7
            && num.chars().all(|c| c.is_ascii_digit());
    }
    false
}

fn is_orcid(s: &str) -> bool {
    let groups: Vec<&str> = s.split('-').collect();
    if groups.len() != 4 {
        return false;
    }
    for (i, g) in groups.iter().enumerate() {
        if g.len() != 4 {
            return false;
        }
        let chars: Vec<char> = g.chars().collect();
        for (j, c) in chars.iter().enumerate() {
            let is_last = i == 3 && j == 3;
            if is_last {
                if !(c.is_ascii_digit() || *c == 'X') {
                    return false;
                }
            } else if !c.is_ascii_digit() {
                return false;
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "https://app.constellate.science";

    #[test]
    fn resolves_frontier() {
        let r = resolve("vfr_abcdef0123456789", BASE);
        assert_eq!(r.kind, HandleKind::Frontier);
        assert_eq!(
            r.url.as_deref(),
            Some("https://app.constellate.science/frontier/vfr_abcdef0123456789")
        );
    }

    #[test]
    fn resolves_release() {
        let r = resolve("vfrr_deadbeef0000aaaa", BASE);
        assert_eq!(r.kind, HandleKind::FrontierRelease);
    }

    #[test]
    fn resolves_doi() {
        let r = resolve("10.1234/abc.def", BASE);
        assert_eq!(r.kind, HandleKind::Doi);
        assert_eq!(r.url.as_deref(), Some("https://doi.org/10.1234/abc.def"));
    }

    #[test]
    fn resolves_arxiv_new() {
        let r = resolve("2403.01234", BASE);
        assert_eq!(r.kind, HandleKind::ArxivId);
        let v = resolve("2403.01234v2", BASE);
        assert_eq!(v.kind, HandleKind::ArxivId);
    }

    #[test]
    fn resolves_arxiv_old() {
        let r = resolve("math/0701234", BASE);
        assert_eq!(r.kind, HandleKind::ArxivId);
    }

    #[test]
    fn resolves_orcid() {
        let r = resolve("0000-0001-2345-6789", BASE);
        assert_eq!(r.kind, HandleKind::Orcid);
        assert_eq!(
            r.url.as_deref(),
            Some("https://orcid.org/0000-0001-2345-6789")
        );
        let x = resolve("0000-0001-2345-678X", BASE);
        assert_eq!(x.kind, HandleKind::Orcid);
    }

    #[test]
    fn unknown_handle() {
        let r = resolve("not a real handle", BASE);
        assert_eq!(r.kind, HandleKind::Unknown);
        assert_eq!(r.url, None);
    }

    #[test]
    fn rejects_bad_hex() {
        let r = resolve("vfr_NOTHEX", BASE);
        assert_eq!(r.kind, HandleKind::Unknown);
    }

    #[test]
    fn round_trips_via_json() {
        let r = resolve("vat_abc123def4567890", BASE);
        let json = serde_json::to_string(&r).expect("ser");
        let back: ResolvedRef = serde_json::from_str(&json).expect("de");
        assert_eq!(r, back);
    }
}
