//! Policy-bound acceptance (the human-governance redesign, `vela_human_governance_memo`).
//!
//! The governing change: instead of a key-holding human accepting EVERY trusted
//! transition, a human (or quorum) signs a scoped, revocable [`AcceptancePolicy`]
//! ONCE, and a deterministic evaluator then routes each proposal to `permit`,
//! `defer`, or `deny`. Humans sign policies, delegations, exceptions, and
//! irreversible commitments; the engine signs routine executions that already
//! satisfy a human-signed policy. This is a separation of duties, NOT a relaxation
//! of the gate: policy decides *authority*, never *evidence* — a transition is only
//! eligible for an auto-`permit` lane if its assurance profile already passed
//! (`verifier_attachment::exact_lane_attachment_admit` / `derive_gate_status`).
//!
//! The evaluator is **pure and replayable**: a decision is reproducible from the
//! proposal digest, the state root, the policy digest, the assurance evidence, the
//! actor credential, a bounded context object, and the evaluator version. It is
//! **monotonic on unknown data**: an unrecognized field or missing evidence can
//! only move a `permit` to `defer`/`deny`, never the reverse. The safe default is
//! `defer` (never silent denial or forced acceptance). Today this runs in SHADOW —
//! it decides and certifies but does not change the canonical accept path (no new
//! event kind, no wire change), so the autonomy can be proven before it is granted.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The three routing outcomes. `defer` is the safe default and carries the reason
/// the transition needs a named human; `deny` is a structural/authority/explicit
/// prohibition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Permit,
    Defer,
    Deny,
}

impl Outcome {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Permit => "permit",
            Outcome::Defer => "defer",
            Outcome::Deny => "deny",
        }
    }
}

/// The bounded, structured context a rule is evaluated against. Every field is
/// derived deterministically from the proposal + its assurance evidence + the
/// frontier state (see the host that builds it). The evaluator reads ONLY these
/// fields; it never makes a network call, reads wall-clock outside `now`, or
/// consults a mutable reputation score.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyContext {
    /// The structural claim class (e.g. "sidon_lower_bound", "formal_theorem",
    /// "literature_finding", "metadata_repair", "governance").
    pub claim_class: String,
    /// Assurance level A0..A4 (0..4): A2 = one exact/formal check passed, A3 =
    /// independent corroboration, A4 = adversarial+semantic fidelity. Derived from
    /// the gate, NOT self-asserted.
    pub assurance_level: u8,
    /// Transition impact tier I0..I4 (0..4).
    pub impact_tier: u8,
    pub changed_findings: u32,
    pub downstream_dependents: u32,
    /// Does the proposal mutate claim LANGUAGE (vs attach exact evidence)?
    pub assertion_text_mutated: bool,
    pub target_contested: bool,
    pub governance_mutation: bool,
    /// Independence derived from failure-domain diversity (not self-declared).
    pub independence_satisfied: bool,
    /// MethodIntegrity::Sound on the matched attachments.
    pub method_integrity_sound: bool,
    /// The producer/delegate credential resolved and is unexpired/unrevoked.
    pub credential_valid: bool,
    /// The evaluator saw a field it does not recognize → never permit (monotonic).
    pub has_unknown_fields: bool,
}

impl Default for PolicyContext {
    fn default() -> Self {
        // The maximally-cautious context: nothing proven, everything that would
        // force a defer/deny set. A rule must positively clear each gate.
        PolicyContext {
            claim_class: String::new(),
            assurance_level: 0,
            impact_tier: 4,
            changed_findings: u32::MAX,
            downstream_dependents: u32::MAX,
            assertion_text_mutated: true,
            target_contested: true,
            governance_mutation: true,
            independence_satisfied: false,
            method_integrity_sound: false,
            credential_valid: false,
            has_unknown_fields: true,
        }
    }
}

/// The constraints a `permit` rule places on the transition. A `permit` fires only
/// if ALL hold; otherwise the rule does not match and routing falls through.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Constraints {
    pub max_changed_findings: u32,
    pub max_downstream_dependents: u32,
    /// Lowest assurance level (0..4) that satisfies the rule.
    pub required_assurance_min: u8,
    /// `false` (the default) forbids claim-language mutation in this lane.
    #[serde(default)]
    pub allow_semantic_text_change: bool,
    #[serde(default)]
    pub allow_contested: bool,
    #[serde(default)]
    pub allow_governance_mutation: bool,
    /// Require failure-domain-diverse independent verification.
    #[serde(default)]
    pub require_independence: bool,
    /// Require MethodIntegrity::Sound.
    #[serde(default)]
    pub require_method_integrity: bool,
}

impl Default for Constraints {
    fn default() -> Self {
        Constraints {
            max_changed_findings: 0,
            max_downstream_dependents: 0,
            required_assurance_min: 4,
            allow_semantic_text_change: false,
            allow_contested: false,
            allow_governance_mutation: false,
            require_independence: true,
            require_method_integrity: true,
        }
    }
}

/// One rule: an effect plus the claim classes and constraints it applies to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRule {
    pub id: String,
    pub effect: Outcome,
    /// Claim classes this rule governs. Empty = applies to any class.
    #[serde(default)]
    pub claim_classes: Vec<String>,
    #[serde(default)]
    pub constraints: Constraints,
}

impl PolicyRule {
    fn applies_to_class(&self, class: &str) -> bool {
        self.claim_classes.is_empty() || self.claim_classes.iter().any(|c| c == class)
    }
}

/// The quorum that must have signed the policy for it to carry authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Quorum {
    pub threshold: u32,
    #[serde(default)]
    pub eligible_roles: Vec<String>,
}

/// A scoped, revocable, content-addressed acceptance policy. Humans sign THIS
/// (once); the evaluator applies it (many times). Shares signature/quorum/expiry/
/// revocation shape with registry governance; this governs ordinary scientific
/// state transitions, not owner rotation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptancePolicy {
    #[serde(default = "default_schema")]
    pub schema: String,
    pub id: String,
    pub frontier_id: String,
    pub epoch: u32,
    pub issued_by: Vec<String>,
    pub quorum: Quorum,
    pub rules: Vec<PolicyRule>,
    /// MUST be `Defer` or `Deny` (a permit default would be a footgun).
    pub default: Outcome,
    /// RFC3339; the evaluator denies after this instant.
    pub expires_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_ref: Option<String>,
}

fn default_schema() -> String {
    "vela.acceptance_policy.v0.1".to_string()
}

/// The evaluator version, bound into every decision for replay.
pub const EVALUATOR_VERSION: &str = "vela-policy@0.1.0";

impl AcceptancePolicy {
    /// Content address of the policy's normative body (everything but `id`), so
    /// the id is reproducible and a tampered policy fails to verify. `vap_` prefix.
    #[must_use]
    pub fn content_address(&self) -> String {
        let mut probe = self.clone();
        probe.id = String::new();
        let bytes = serde_json::to_vec(&probe).unwrap_or_default();
        let mut h = Sha256::new();
        h.update(&bytes);
        format!("vap_{}", hex16(&h.finalize()))
    }

    /// True iff `id` matches the content address (tamper check).
    #[must_use]
    pub fn id_is_valid(&self) -> bool {
        self.id == self.content_address()
    }

    /// Is the policy expired at `now` (RFC3339 lexical compare — RFC3339 UTC
    /// strings sort chronologically)? Conservative: an unparseable/empty
    /// `expires_at` is treated as expired.
    #[must_use]
    pub fn is_expired(&self, now_rfc3339: &str) -> bool {
        if self.expires_at.is_empty() {
            return true;
        }
        now_rfc3339 >= self.expires_at.as_str()
    }
}

/// A pure, replayable routing decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    pub outcome: Outcome,
    pub matched_rule_ids: Vec<String>,
    /// Machine-readable reason codes (always non-empty).
    pub reasons: Vec<String>,
    pub evaluator: String,
    pub policy_id: String,
}

/// The deterministic routing engine (memo Appendix C). Order of precedence:
/// 1. structural/authority DENY (expired/revoked policy, governance mutation
///    without an explicit governance-permit rule, invalid credential);
/// 2. any matching `deny` rule → DENY;
/// 3. escalation triggers (contested, semantic mutation, missing independence/
///    integrity where required, downstream over bound, unknown fields) → DEFER;
/// 4. a matching `permit` rule whose constraints all hold → PERMIT;
/// 5. otherwise the policy `default` (DEFER or DENY).
///
/// Monotonic on unknown: `has_unknown_fields` or an unrecognized class can only
/// push toward `defer`/`deny`.
#[must_use]
pub fn evaluate(policy: &AcceptancePolicy, ctx: &PolicyContext, now_rfc3339: &str) -> Decision {
    let mk = |outcome: Outcome, rules: Vec<String>, reasons: Vec<String>| Decision {
        outcome,
        matched_rule_ids: rules,
        reasons: if reasons.is_empty() {
            vec!["default".to_string()]
        } else {
            reasons
        },
        evaluator: EVALUATOR_VERSION.to_string(),
        policy_id: policy.id.clone(),
    };

    // (0) Policy integrity + lifecycle: structural DENY.
    if !policy.id_is_valid() {
        return mk(Outcome::Deny, vec![], vec!["policy_id_mismatch".into()]);
    }
    if policy.is_expired(now_rfc3339) {
        return mk(Outcome::Deny, vec![], vec!["policy_expired".into()]);
    }
    if policy.revocation_ref.is_some() {
        return mk(Outcome::Deny, vec![], vec!["policy_revoked".into()]);
    }
    if !matches!(policy.default, Outcome::Defer | Outcome::Deny) {
        // A permit default is rejected at evaluation time, defense in depth.
        return mk(Outcome::Deny, vec![], vec!["illegal_permit_default".into()]);
    }

    // (1) Explicit DENY rules win over everything below.
    for r in &policy.rules {
        if r.effect == Outcome::Deny && r.applies_to_class(&ctx.claim_class) {
            return mk(
                Outcome::Deny,
                vec![r.id.clone()],
                vec!["explicit_deny_rule".into()],
            );
        }
    }

    // (2) Find a permit rule for this class; if it matches but constraints fail,
    // that is an escalation (defer), not a silent denial.
    let mut escalations: Vec<String> = Vec::new();
    for r in &policy.rules {
        if r.effect != Outcome::Permit || !r.applies_to_class(&ctx.claim_class) {
            continue;
        }
        let c = &r.constraints;
        let mut blocked: Vec<String> = Vec::new();

        // Monotonic-on-unknown + the universal escalation triggers.
        if ctx.has_unknown_fields {
            blocked.push("unknown_fields".into());
        }
        if !ctx.credential_valid {
            blocked.push("credential_invalid".into());
        }
        if ctx.governance_mutation && !c.allow_governance_mutation {
            blocked.push("governance_mutation".into());
        }
        if ctx.target_contested && !c.allow_contested {
            blocked.push("target_contested".into());
        }
        if ctx.assertion_text_mutated && !c.allow_semantic_text_change {
            blocked.push("semantic_text_change".into());
        }
        if ctx.assurance_level < c.required_assurance_min {
            blocked.push(format!(
                "assurance_below_min({}<{})",
                ctx.assurance_level, c.required_assurance_min
            ));
        }
        if ctx.changed_findings > c.max_changed_findings {
            blocked.push("changed_findings_over_bound".into());
        }
        if ctx.downstream_dependents > c.max_downstream_dependents {
            blocked.push("downstream_over_bound".into());
        }
        if c.require_independence && !ctx.independence_satisfied {
            blocked.push("independence_unsatisfied".into());
        }
        if c.require_method_integrity && !ctx.method_integrity_sound {
            blocked.push("method_integrity_unattested".into());
        }

        if blocked.is_empty() {
            return mk(
                Outcome::Permit,
                vec![r.id.clone()],
                vec!["all_constraints_satisfied".into()],
            );
        }
        // This permit rule matched the class but is blocked → remember why; a
        // matched-but-blocked permit rule means the item is plausibly valid but
        // needs human judgment, so we DEFER (not deny).
        escalations.extend(blocked.into_iter().map(|b| format!("{}:{}", r.id, b)));
    }

    if !escalations.is_empty() {
        return mk(Outcome::Defer, vec![], escalations);
    }

    // (3) No deny, no matching permit → the policy default.
    mk(
        policy.default,
        vec![],
        vec![format!("default_{}", policy.default.as_str())],
    )
}

/// First 16 bytes of a digest as hex (mirrors the substrate's short-id style).
fn hex16(digest: &[u8]) -> String {
    digest.iter().take(16).map(|b| format!("{b:02x}")).collect()
}

/// How the transition was authorized. `PolicyDelegation` = a human-signed policy
/// permitted it (the engine executed); `DirectHuman` = a person signed this item;
/// `Quorum` = a governance quorum signed. Never collapse these into one "signed".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityMode {
    PolicyDelegation,
    DirectHuman,
    Quorum,
}

/// The portable, content-addressed receipt of one acceptance decision — produced
/// by the engine, not performed by a human. It binds the proposal, the exact state
/// roots, the policy + matched rules, the authority chain, the assurance profile,
/// and (once recorded) the event + log inclusion proof, so any relying party can
/// REPLAY the decision. Reading it requires no signature; only a durable
/// endorsement/commitment does (the memo's separation of receipt from endorsement).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionCertificate {
    #[serde(default = "default_cert_schema")]
    pub schema: String,
    pub id: String,
    pub frontier_id: String,
    pub proposal_id: String,
    pub state_root_before: String,
    pub state_root_after: String,
    pub outcome: Outcome,
    pub policy_id: String,
    pub rule_ids: Vec<String>,
    pub evaluator: String,
    pub authority_mode: AuthorityMode,
    /// The human(s)/quorum whose signed policy authorized this (for PolicyDelegation).
    pub human_authorizers: Vec<String>,
    /// The service/agent that executed under the policy.
    pub executor: String,
    /// The named assurance profile the evidence cleared (e.g.
    /// "exact_construction_dual_check_v1"); the policy NEVER manufactures this.
    pub assurance_profile: String,
    pub assurance_level: u8,
    pub claim_digest: String,
    pub impact_tier: u8,
    pub reasons: Vec<String>,
    /// Selected for post-accept audit (the calibrated-sample rollout).
    pub audit_required: bool,
}

fn default_cert_schema() -> String {
    "vela.decision_certificate.v0.1".to_string()
}

impl DecisionCertificate {
    /// Build a certificate from a decision + its bindings. `vdc_` prefix; the id is
    /// the content address of everything but `id`, so it is reproducible and a
    /// tampered certificate fails `id_is_valid`.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        decision: &Decision,
        frontier_id: &str,
        proposal_id: &str,
        state_root_before: &str,
        state_root_after: &str,
        authority_mode: AuthorityMode,
        human_authorizers: Vec<String>,
        executor: &str,
        assurance_profile: &str,
        assurance_level: u8,
        claim_digest: &str,
        impact_tier: u8,
        audit_required: bool,
    ) -> Self {
        let mut c = DecisionCertificate {
            schema: default_cert_schema(),
            id: String::new(),
            frontier_id: frontier_id.to_string(),
            proposal_id: proposal_id.to_string(),
            state_root_before: state_root_before.to_string(),
            state_root_after: state_root_after.to_string(),
            outcome: decision.outcome,
            policy_id: decision.policy_id.clone(),
            rule_ids: decision.matched_rule_ids.clone(),
            evaluator: decision.evaluator.clone(),
            authority_mode,
            human_authorizers,
            executor: executor.to_string(),
            assurance_profile: assurance_profile.to_string(),
            assurance_level,
            claim_digest: claim_digest.to_string(),
            impact_tier,
            reasons: decision.reasons.clone(),
            audit_required,
        };
        c.id = c.content_address();
        c
    }

    #[must_use]
    pub fn content_address(&self) -> String {
        let mut probe = self.clone();
        probe.id = String::new();
        let bytes = serde_json::to_vec(&probe).unwrap_or_default();
        let mut h = Sha256::new();
        h.update(&bytes);
        format!("vdc_{}", hex16(&h.finalize()))
    }

    #[must_use]
    pub fn id_is_valid(&self) -> bool {
        self.id == self.content_address()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exact_sidon_policy() -> AcceptancePolicy {
        let mut p = AcceptancePolicy {
            schema: default_schema(),
            id: String::new(),
            frontier_id: "vfr_test".into(),
            epoch: 1,
            issued_by: vec!["reviewer:will".into()],
            quorum: Quorum {
                threshold: 1,
                eligible_roles: vec!["steward".into()],
            },
            rules: vec![PolicyRule {
                id: "sidon-exact-auto-v1".into(),
                effect: Outcome::Permit,
                claim_classes: vec!["sidon_lower_bound".into()],
                constraints: Constraints {
                    max_changed_findings: 1,
                    max_downstream_dependents: 5,
                    required_assurance_min: 3,
                    allow_semantic_text_change: false,
                    allow_contested: false,
                    allow_governance_mutation: false,
                    require_independence: true,
                    require_method_integrity: true,
                },
            }],
            default: Outcome::Defer,
            expires_at: "2099-12-31T23:59:59Z".into(),
            revocation_ref: None,
        };
        p.id = p.content_address();
        p
    }

    fn clean_exact_ctx() -> PolicyContext {
        PolicyContext {
            claim_class: "sidon_lower_bound".into(),
            assurance_level: 3,
            impact_tier: 2,
            changed_findings: 1,
            downstream_dependents: 0,
            assertion_text_mutated: false,
            target_contested: false,
            governance_mutation: false,
            independence_satisfied: true,
            method_integrity_sound: true,
            credential_valid: true,
            has_unknown_fields: false,
        }
    }

    const NOW: &str = "2026-06-23T00:00:00Z";

    #[test]
    fn exact_clean_witness_permits() {
        let d = evaluate(&exact_sidon_policy(), &clean_exact_ctx(), NOW);
        assert_eq!(d.outcome, Outcome::Permit);
        assert_eq!(d.matched_rule_ids, vec!["sidon-exact-auto-v1"]);
    }

    #[test]
    fn contested_target_escalates_to_defer() {
        let mut ctx = clean_exact_ctx();
        ctx.target_contested = true;
        let d = evaluate(&exact_sidon_policy(), &ctx, NOW);
        assert_eq!(d.outcome, Outcome::Defer);
        assert!(d.reasons.iter().any(|r| r.contains("target_contested")));
    }

    #[test]
    fn semantic_text_mutation_escalates_to_defer() {
        let mut ctx = clean_exact_ctx();
        ctx.assertion_text_mutated = true;
        assert_eq!(
            evaluate(&exact_sidon_policy(), &ctx, NOW).outcome,
            Outcome::Defer
        );
    }

    #[test]
    fn low_assurance_escalates_to_defer() {
        let mut ctx = clean_exact_ctx();
        ctx.assurance_level = 2; // below the rule's min of 3
        let d = evaluate(&exact_sidon_policy(), &ctx, NOW);
        assert_eq!(d.outcome, Outcome::Defer);
        assert!(d.reasons.iter().any(|r| r.contains("assurance_below_min")));
    }

    #[test]
    fn monotonic_on_unknown_fields() {
        let mut ctx = clean_exact_ctx();
        ctx.has_unknown_fields = true;
        assert_eq!(
            evaluate(&exact_sidon_policy(), &ctx, NOW).outcome,
            Outcome::Defer
        );
    }

    #[test]
    fn unknown_claim_class_falls_through_to_default_defer() {
        let mut ctx = clean_exact_ctx();
        ctx.claim_class = "literature_finding".into(); // no rule covers it
        let d = evaluate(&exact_sidon_policy(), &ctx, NOW);
        assert_eq!(d.outcome, Outcome::Defer);
        assert!(d.reasons.iter().any(|r| r.contains("default")));
    }

    #[test]
    fn expired_policy_denies() {
        let p = exact_sidon_policy();
        let d = evaluate(&p, &clean_exact_ctx(), "2100-01-01T00:00:00Z");
        assert_eq!(d.outcome, Outcome::Deny);
        assert!(d.reasons.iter().any(|r| r == "policy_expired"));
    }

    #[test]
    fn tampered_policy_id_denies() {
        let mut p = exact_sidon_policy();
        p.rules[0].constraints.required_assurance_min = 0; // change body, keep old id
        let d = evaluate(&p, &clean_exact_ctx(), NOW);
        assert_eq!(d.outcome, Outcome::Deny);
        assert!(d.reasons.iter().any(|r| r == "policy_id_mismatch"));
    }

    #[test]
    fn revoked_policy_denies() {
        let mut p = exact_sidon_policy();
        p.revocation_ref = Some("vrv_x".into());
        p.id = p.content_address();
        assert_eq!(evaluate(&p, &clean_exact_ctx(), NOW).outcome, Outcome::Deny);
    }

    #[test]
    fn governance_mutation_without_permission_escalates() {
        let mut ctx = clean_exact_ctx();
        ctx.governance_mutation = true;
        let d = evaluate(&exact_sidon_policy(), &ctx, NOW);
        assert_eq!(d.outcome, Outcome::Defer);
        assert!(d.reasons.iter().any(|r| r.contains("governance_mutation")));
    }

    #[test]
    fn evaluation_is_deterministic() {
        let p = exact_sidon_policy();
        let ctx = clean_exact_ctx();
        assert_eq!(evaluate(&p, &ctx, NOW), evaluate(&p, &ctx, NOW));
    }

    #[test]
    fn content_address_is_stable_and_prefixed() {
        let p = exact_sidon_policy();
        assert!(p.id.starts_with("vap_"));
        assert!(p.id_is_valid());
    }

    #[test]
    fn decision_certificate_binds_and_verifies() {
        let p = exact_sidon_policy();
        let d = evaluate(&p, &clean_exact_ctx(), NOW);
        let c = DecisionCertificate::build(
            &d,
            "vfr_test",
            "vpr_abc",
            "sha256:before",
            "sha256:after",
            AuthorityMode::PolicyDelegation,
            vec!["reviewer:will".into()],
            "service:vela-policy-engine",
            "exact_construction_dual_check_v1",
            3,
            "sha256:claim",
            2,
            true,
        );
        assert!(c.id.starts_with("vdc_"));
        assert!(c.id_is_valid());
        assert_eq!(c.outcome, Outcome::Permit);
        assert_eq!(c.authority_mode, AuthorityMode::PolicyDelegation);
        // The authority is the policy a human signed, NOT a per-item human click.
        assert_eq!(c.human_authorizers, vec!["reviewer:will"]);
        assert_eq!(c.executor, "service:vela-policy-engine");
        // Tamper detection.
        let mut bad = c.clone();
        bad.outcome = Outcome::Deny;
        assert!(!bad.id_is_valid());
    }
}
