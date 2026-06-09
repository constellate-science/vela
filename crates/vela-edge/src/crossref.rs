//! v0.162: Crossref deposit manifest. Generate a deposit-ready
//! manifest for a Vela frontier release that an operator can hand
//! off to Crossref (or any equivalent DOI registrar) to mint a DOI
//! against. The substrate does not call Crossref's API itself;
//! minting a DOI requires a Crossref member account, member id,
//! and depositor credentials that live outside the substrate.
//!
//! Substrate-honest framing: the manifest is *derived* from the
//! frontier release state. It pins title, identifier (vfrr_*),
//! resource-url, contributors (when declared via v0.155/0.157),
//! and the release timestamp into a Crossref-compatible JSON
//! shape. The same release-id produces the same manifest bytes
//! modulo a depositor-supplied member id + a chosen prefix.
//!
//! Two outputs:
//!   - JSON manifest: portable, human-readable, what `vela
//!     crossref deposit` emits by default. A consumer can pipe
//!     this into any DOI-broker that accepts CSL-JSON-ish input.
//!   - Crossref deposit XML (subset of the official schema): the
//!     `vela crossref deposit --xml` path emits a dataset-deposit
//!     XML fragment matching Crossref schema 5.3.1 with the
//!     dataset record type.

use crate::credit::CreditLedger;
use crate::frontier_release::FrontierRelease;
use serde::{Deserialize, Serialize};

pub const DEPOSIT_SCHEMA: &str = "vela.crossref_deposit_manifest.v0.1";

/// JSON manifest body. Inputs the operator pre-fills: member id,
/// prefix, depositor name + email. Outputs everything the
/// deposit needs minus the actual DOI assignment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CrossrefDepositManifest {
    pub schema: String,
    /// Crossref member id (operator-supplied).
    pub member_id: String,
    /// DOI prefix the operator is authorized to mint under
    /// (e.g. "10.5555"). The full DOI is suggested as
    /// `<prefix>/vela.<vfrr_id-short>` but the depositor is free
    /// to choose another suffix.
    pub prefix: String,
    /// Operator submitting the deposit.
    pub depositor: Depositor,
    /// The release being deposited.
    pub release: ReleaseRef,
    /// Title for the deposit (display).
    pub title: String,
    /// Resource URL the DOI resolves to (operator-supplied; the
    /// substrate suggests `<site>/frontier/<vfr>/release/<vfrr>`).
    pub resource_url: String,
    /// Suggested DOI (operator can override before submission).
    pub suggested_doi: String,
    /// Contributors (CRediT roles included when known).
    pub contributors: Vec<DepositContributor>,
    /// ISO 8601 deposit timestamp.
    pub deposited_at: String,
    /// Optional abstract / description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Optional license SPDX id (rendered as licenseRef in
    /// downstream XML).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Depositor {
    pub name: String,
    pub email: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleaseRef {
    pub release_id: String,
    pub frontier_id: String,
    pub owner_epoch: u64,
    pub snapshot_hash: String,
    pub event_log_hash: String,
    pub released_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DepositContributor {
    /// Substrate actor id.
    pub actor_id: String,
    /// ORCID id, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub orcid: Option<String>,
    /// CRediT roles aggregated from the ledger (CASRAI 2014
    /// vocabulary).
    pub credit_roles: Vec<String>,
    /// Total event count attributable to this actor across the
    /// frontier's canonical event log.
    pub event_count: u64,
}

/// Input for building a deposit manifest. The release ref is the
/// substrate-authoritative pin; the rest is depositor-supplied.
#[derive(Debug, Clone)]
pub struct DepositInput<'a> {
    pub release: &'a FrontierRelease,
    pub title: String,
    pub resource_url: String,
    pub member_id: String,
    pub prefix: String,
    pub depositor: Depositor,
    pub description: Option<String>,
    pub license: Option<String>,
    pub ledger: Option<&'a CreditLedger>,
    pub deposited_at: String,
}

impl CrossrefDepositManifest {
    pub fn from_input(input: DepositInput<'_>) -> Result<Self, String> {
        if input.member_id.trim().is_empty() {
            return Err("member_id must be non-empty".to_string());
        }
        if input.prefix.trim().is_empty() {
            return Err("prefix must be non-empty (e.g. `10.5555`)".to_string());
        }
        if !input.prefix.starts_with("10.") {
            return Err(format!(
                "prefix must start with `10.` per DOI Handbook, got `{}`",
                input.prefix
            ));
        }
        if input.depositor.name.trim().is_empty() {
            return Err("depositor.name must be non-empty".to_string());
        }
        if input.depositor.email.trim().is_empty() {
            return Err("depositor.email must be non-empty".to_string());
        }
        if input.resource_url.trim().is_empty() {
            return Err("resource_url must be non-empty".to_string());
        }
        let release = input.release;
        let short = release.release_id.trim_start_matches("vfrr_");
        let suggested_doi = format!("{}/vela.{}", input.prefix, short);
        let contributors = match input.ledger {
            Some(l) => l
                .contributors
                .iter()
                .map(|c| DepositContributor {
                    actor_id: c.actor_id.clone(),
                    orcid: c.orcid.clone(),
                    credit_roles: c.roles.clone(),
                    event_count: c.event_count,
                })
                .collect(),
            None => Vec::new(),
        };
        Ok(CrossrefDepositManifest {
            schema: DEPOSIT_SCHEMA.to_string(),
            member_id: input.member_id,
            prefix: input.prefix,
            depositor: input.depositor,
            release: ReleaseRef {
                release_id: release.release_id.clone(),
                frontier_id: release.frontier_id.clone(),
                owner_epoch: release.owner_epoch,
                snapshot_hash: release.snapshot_hash.clone(),
                event_log_hash: release.event_log_hash.clone(),
                released_at: release.released_at.clone(),
            },
            title: input.title,
            resource_url: input.resource_url,
            suggested_doi,
            contributors,
            deposited_at: input.deposited_at,
            description: input.description,
            license: input.license,
        })
    }

    /// Render the manifest as a Crossref deposit XML fragment.
    /// Targets Crossref schema 5.3.1, `dataset` record type. The
    /// rendered XML is a subset suitable for a depositor to wrap
    /// in a `<doi_batch>` envelope with their member-supplied
    /// `<head>` block.
    pub fn to_crossref_xml(&self) -> String {
        let mut s = String::new();
        s.push_str("<database>\n");
        s.push_str("  <database_metadata language=\"en\">\n");
        s.push_str(&format!(
            "    <titles><title>{}</title></titles>\n",
            xml_escape(&self.title)
        ));
        if let Some(desc) = &self.description {
            s.push_str(&format!(
                "    <description>{}</description>\n",
                xml_escape(desc)
            ));
        }
        s.push_str("  </database_metadata>\n");
        s.push_str("  <dataset dataset_type=\"record\">\n");
        if !self.contributors.is_empty() {
            s.push_str("    <contributors>\n");
            for (i, c) in self.contributors.iter().enumerate() {
                let role = if i == 0 { "first" } else { "additional" };
                s.push_str(&format!(
                    "      <person_name sequence=\"{}\" contributor_role=\"author\">\n",
                    role
                ));
                let display = c.actor_id.trim_start_matches("vac_");
                s.push_str(&format!(
                    "        <given_name>{}</given_name>\n",
                    xml_escape(display)
                ));
                s.push_str(&format!(
                    "        <surname>{}</surname>\n",
                    xml_escape(&c.actor_id)
                ));
                if let Some(o) = &c.orcid {
                    s.push_str(&format!(
                        "        <ORCID authenticated=\"false\">https://orcid.org/{}</ORCID>\n",
                        xml_escape(o)
                    ));
                }
                s.push_str("      </person_name>\n");
            }
            s.push_str("    </contributors>\n");
        }
        s.push_str(&format!(
            "    <titles><title>{}</title></titles>\n",
            xml_escape(&self.title)
        ));
        let year = self.release.released_at.get(0..4).unwrap_or("0000");
        s.push_str(&format!(
            "    <database_date>\n      <publication_date media_type=\"online\"><year>{}</year></publication_date>\n    </database_date>\n",
            xml_escape(year)
        ));
        s.push_str("    <doi_data>\n");
        s.push_str(&format!(
            "      <doi>{}</doi>\n",
            xml_escape(&self.suggested_doi)
        ));
        s.push_str(&format!(
            "      <resource>{}</resource>\n",
            xml_escape(&self.resource_url)
        ));
        s.push_str("    </doi_data>\n");
        s.push_str("  </dataset>\n");
        s.push_str("</database>\n");
        s
    }
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frontier_release::ReleaseDraft;

    fn release_fixture() -> FrontierRelease {
        FrontierRelease::from_draft(ReleaseDraft {
            frontier_id: "vfr_abc123def4567890".to_string(),
            name: "v1.0".to_string(),
            notes: None,
            owner_epoch: 1,
            snapshot_hash: "sha256:aaaa".to_string(),
            event_log_hash: "sha256:bbbb".to_string(),
            governance_policy_id: None,
            previous_release: None,
            released_at: "2026-05-11T00:00:00Z".to_string(),
        })
        .expect("release builds")
    }

    fn depositor_fixture() -> Depositor {
        Depositor {
            name: "Test Depositor".to_string(),
            email: "test@example.org".to_string(),
        }
    }

    #[test]
    fn manifest_round_trips() {
        let release = release_fixture();
        let m = CrossrefDepositManifest::from_input(DepositInput {
            release: &release,
            title: "Test frontier".to_string(),
            resource_url: "https://example.org/frontier/vfr_abc".to_string(),
            member_id: "12345".to_string(),
            prefix: "10.5555".to_string(),
            depositor: depositor_fixture(),
            description: None,
            license: Some("MIT".to_string()),
            ledger: None,
            deposited_at: "2026-05-11T00:00:00Z".to_string(),
        })
        .expect("manifest builds");
        assert_eq!(m.schema, DEPOSIT_SCHEMA);
        assert!(m.suggested_doi.starts_with("10.5555/vela."));
        let json = serde_json::to_string(&m).expect("serializes");
        let back: CrossrefDepositManifest = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(m, back);
    }

    #[test]
    fn rejects_bad_prefix() {
        let release = release_fixture();
        let err = CrossrefDepositManifest::from_input(DepositInput {
            release: &release,
            title: "Test".to_string(),
            resource_url: "https://example.org".to_string(),
            member_id: "12345".to_string(),
            prefix: "not-a-prefix".to_string(),
            depositor: depositor_fixture(),
            description: None,
            license: None,
            ledger: None,
            deposited_at: "2026-05-11T00:00:00Z".to_string(),
        });
        assert!(err.is_err());
    }

    #[test]
    fn xml_includes_doi_and_resource() {
        let release = release_fixture();
        let m = CrossrefDepositManifest::from_input(DepositInput {
            release: &release,
            title: "Vela <test>".to_string(),
            resource_url: "https://example.org/x".to_string(),
            member_id: "12345".to_string(),
            prefix: "10.5555".to_string(),
            depositor: depositor_fixture(),
            description: Some("a & b".to_string()),
            license: None,
            ledger: None,
            deposited_at: "2026-05-11T00:00:00Z".to_string(),
        })
        .expect("manifest builds");
        let xml = m.to_crossref_xml();
        assert!(xml.contains("<doi>10.5555/vela."));
        assert!(xml.contains("<resource>https://example.org/x</resource>"));
        assert!(xml.contains("Vela &lt;test&gt;"));
        assert!(xml.contains("a &amp; b"));
        assert!(xml.contains("<year>2026</year>"));
    }
}
