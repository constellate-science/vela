//! `vpol_`: a content-addressed verification policy.
//!
//! The gate (`derive_gate_status`, G1-G5) is pure CODE. Without naming the exact
//! policy that produced a status, a future Vela could replay the log but not the
//! same MEANING of "verified". A `vpol_` fixes that: the gate's rules are a
//! content-addressed object, so every verification summary carries the policy id
//! and digest it was derived under, and "verified" stays replayable. See
//! `docs/TRUST_MODEL_REDESIGN.md` section 7.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const POLICY_SCHEMA: &str = "vela.policy.v1";

/// One named gate rule. Documentation of what the policy checks; the executable
/// check stays in `derive_gate_status`, and the digest binds this description to
/// that version of the gate.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRule {
    pub id: String,
    pub description: String,
}

/// A content-addressed verification policy.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationPolicy {
    pub schema: String,
    /// `vpol_` + first 16 hex of the canonical digest.
    pub id: String,
    pub name: String,
    pub version: String,
    pub rules: Vec<PolicyRule>,
    /// sha256 of the canonical body with `id` and `canonical_digest` empty.
    pub canonical_digest: String,
}

impl VerificationPolicy {
    #[must_use]
    pub fn build(name: &str, version: &str, rules: Vec<PolicyRule>) -> Self {
        let mut policy = VerificationPolicy {
            schema: POLICY_SCHEMA.to_string(),
            id: String::new(),
            name: name.to_string(),
            version: version.to_string(),
            rules,
            canonical_digest: String::new(),
        };
        policy.canonical_digest = policy.derive_digest();
        policy.id = format!("vpol_{}", &policy.canonical_digest[..16]);
        policy
    }

    fn derive_digest(&self) -> String {
        let mut c = self.clone();
        c.id = String::new();
        c.canonical_digest = String::new();
        let bytes = crate::canonical::to_canonical_bytes(&c).unwrap_or_default();
        hex::encode(Sha256::digest(bytes))
    }
}

/// THE canonical gate policy: the G1-G5 rules `derive_gate_status` applies, as a
/// content-addressed object. Every verification summary names this policy's id
/// and digest, so the status it carries is replayable in meaning, not just in
/// the log. Changing the gate's rules necessarily changes this digest.
#[must_use]
pub fn canonical_gate_policy() -> VerificationPolicy {
    let rule = |id: &str, description: &str| PolicyRule {
        id: id.to_string(),
        description: description.to_string(),
    };
    VerificationPolicy::build(
        "vela-gate",
        "G1-G5/v1",
        vec![
            rule(
                "G1",
                "at least two independent matched verifier attachments; independence binds to a sibling vva_ witness id, never to the shared claim digest",
            ),
            rule(
                "G2",
                "every counted attachment matches the current claim digest",
            ),
            rule(
                "G3",
                "at least one surviving adversarial probe and no refuting probe",
            ),
            rule(
                "G4",
                "every counted attachment's id content-addresses its body",
            ),
            rule(
                "G5",
                "method integrity is sound: no forbidden axiom and no failed kernel re-check",
            ),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_policy_is_content_addressed_and_stable() {
        let a = canonical_gate_policy();
        let b = canonical_gate_policy();
        assert!(a.id.starts_with("vpol_"));
        assert_eq!(a.canonical_digest.len(), 64);
        // Deterministic: the policy id is a pure function of the rules, so two
        // builds agree and any rule change would move the digest.
        assert_eq!(a, b);
        assert_eq!(a.id[5..], a.canonical_digest[..16]);
    }
}
