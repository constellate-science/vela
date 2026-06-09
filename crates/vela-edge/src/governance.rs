//! v0.144: Registry governance policy. Per-frontier policy object
//! declaring who can authorize owner rotation, what threshold of
//! distinct attestations is required, and (during bootstrap only)
//! whether the current registry owner alone can satisfy quorum.
//!
//! This cycle ships the data shape + content-addressing + validation
//! rules. The binding to `vela registry owner-rotate` ships in v0.145.
//!
//! Schema: `vela.registry_governance_policy.v0.1`. Embedded JSON
//! Schema lives at
//! `crates/vela-protocol/embedded/carina-schemas/registry_governance_policy.schema.json`.
//!
//! Policy ids are content-addressed: `vgp_` + first 16 hex of
//! sha256 over canonical bytes of the policy (with the
//! `policy_id` and `valid_from_entry_hash` fields excluded from the
//! preimage so the id remains derivable from policy contents alone).
//!
//! ## Scoping decisions baked into v0.144
//!
//! 1. **Bootstrap epoch**. `bootstrap_epoch = 0` policies MAY set
//!    `current_owner_counts: true` (the only way a freshly published
//!    frontier with no quorum yet can authorize its first rotation).
//!    Any successor policy at `owner_epoch >= 1` MUST set
//!    `current_owner_counts: false`; the validator rejects otherwise.
//!
//! 2. **Threshold floor**. Threshold MUST be >= 1 and MUST NOT exceed
//!    the eligible-actors count.
//!
//! 3. **No duplicates**. Eligible actor ids must be unique within
//!    each quorum's list. Duplicates would inflate quorum at
//!    verification time (a single signer with two registered ids
//!    cannot satisfy two slots).
//!
//! 4. **Policy update monotonicity**. The optional `policy_update_quorum`
//!    threshold MUST be >= the `rotate_quorum` threshold so a
//!    compromised owner cannot weaken governance via a unilateral
//!    policy update.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Schema constant for the governance policy primitive.
pub const POLICY_SCHEMA: &str = "vela.registry_governance_policy.v0.1";

/// v0.145: schema constant for owner-rotate proposals.
pub const OWNER_ROTATE_PROPOSAL_SCHEMA: &str = "vela.owner_rotate_proposal.v0.1";

/// v0.145: schema constant for owner-rotate attestation bundles.
pub const OWNER_ROTATE_BUNDLE_SCHEMA: &str = "vela.owner_rotate_attestation_bundle.v0.1";

/// v0.146: schema constant for owner-epoch chain transcripts.
pub const OWNER_EPOCH_CHAIN_SCHEMA: &str = "vela.owner_epoch_chain.v0.1";

/// The full governance policy object. Serialized as
/// `vela.registry_governance_policy.v0.1` JSON.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GovernancePolicy {
    pub schema: String,
    /// Content-addressed policy id (`vgp_*`). Derived from the
    /// policy body excluding `policy_id` and `valid_from_entry_hash`.
    pub policy_id: String,
    /// Frontier this policy governs.
    pub frontier_id: String,
    /// Owner epoch this policy is authoritative for.
    pub owner_epoch: u64,
    /// Epoch at which this policy was first content-addressed.
    /// `bootstrap_epoch == owner_epoch` for bootstrap (genesis)
    /// policies. The bootstrap relaxation
    /// (`current_owner_counts: true`) is permitted only when
    /// `bootstrap_epoch == 0` AND `owner_epoch == 0`.
    pub bootstrap_epoch: u64,
    /// Optional hash of the registry entry the policy first attaches
    /// to. Populated when binding the policy; excluded from the
    /// content-address preimage so the id remains derivable from
    /// policy semantics alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from_entry_hash: Option<String>,
    pub rotate_quorum: Quorum,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub emergency_quorum: Option<Quorum>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_update_quorum: Option<Quorum>,
    /// How long a governance attestation remains valid after
    /// signing. Default 168 hours (one week).
    #[serde(default = "default_attestation_ttl_hours")]
    pub attestation_ttl_hours: u32,
    pub created_at: String,
}

fn default_attestation_ttl_hours() -> u32 {
    168
}

/// One quorum specification: threshold + eligible signer ids +
/// whether the current registry owner counts toward this quorum.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Quorum {
    pub threshold: u32,
    pub eligible_actors: Vec<String>,
    pub current_owner_counts: bool,
    /// Optional per-role minimum counts within the satisfying
    /// quorum. Verification ignores roles not present in the
    /// frontier's actor records; the v0.145 verifier reads roles
    /// from the actor registry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role_constraints: Option<RoleConstraints>,
    /// Timelock applied to actions authorized by this quorum (in
    /// hours). Zero or absent means immediate. Used by emergency
    /// and policy-update quorums; ignored for the standard rotate
    /// quorum.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timelock_hours: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RoleConstraints {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_domain_maintainers: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_registry_stewards: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_independent_stewards: Option<u32>,
}

/// Builder input: everything needed to construct a governance
/// policy except its derived `policy_id`.
#[derive(Debug, Clone)]
pub struct PolicyDraft {
    pub frontier_id: String,
    pub owner_epoch: u64,
    pub bootstrap_epoch: u64,
    pub rotate_quorum: Quorum,
    pub emergency_quorum: Option<Quorum>,
    pub policy_update_quorum: Option<Quorum>,
    pub attestation_ttl_hours: u32,
    pub created_at: String,
}

impl GovernancePolicy {
    /// Build a policy from a draft, deriving the content-addressed
    /// `policy_id` from canonical bytes of the body. Validates the
    /// policy and returns an error if any rule is violated.
    pub fn from_draft(draft: PolicyDraft) -> Result<Self, String> {
        let mut policy = GovernancePolicy {
            schema: POLICY_SCHEMA.to_string(),
            policy_id: String::new(),
            frontier_id: draft.frontier_id,
            owner_epoch: draft.owner_epoch,
            bootstrap_epoch: draft.bootstrap_epoch,
            valid_from_entry_hash: None,
            rotate_quorum: draft.rotate_quorum,
            emergency_quorum: draft.emergency_quorum,
            policy_update_quorum: draft.policy_update_quorum,
            attestation_ttl_hours: draft.attestation_ttl_hours,
            created_at: draft.created_at,
        };
        policy.policy_id = policy.derive_id()?;
        policy.validate()?;
        Ok(policy)
    }

    /// Compute the content-addressed `vgp_*` id from the policy body.
    /// Excludes `policy_id` and `valid_from_entry_hash` from the
    /// preimage so the id is derivable from policy semantics alone.
    pub fn derive_id(&self) -> Result<String, String> {
        let mut preimage = self.clone();
        preimage.policy_id = String::new();
        preimage.valid_from_entry_hash = None;
        let bytes = vela_protocol::canonical::to_canonical_bytes(&preimage)
            .map_err(|e| format!("canonicalize policy: {e}"))?;
        let digest = Sha256::digest(&bytes);
        Ok(format!("vgp_{}", &hex::encode(digest)[..16]))
    }

    /// Validate the policy against the v0.144 rules. Returns an
    /// error string describing the first violation found.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != POLICY_SCHEMA {
            return Err(format!(
                "policy.schema must be `{POLICY_SCHEMA}`, got `{}`",
                self.schema
            ));
        }
        if !self.policy_id.starts_with("vgp_") {
            return Err(format!(
                "policy.policy_id must start with `vgp_`, got `{}`",
                self.policy_id
            ));
        }
        if !self.frontier_id.starts_with("vfr_") {
            return Err(format!(
                "policy.frontier_id must start with `vfr_`, got `{}`",
                self.frontier_id
            ));
        }
        if self.attestation_ttl_hours == 0 {
            return Err("policy.attestation_ttl_hours must be >= 1".to_string());
        }
        if self.bootstrap_epoch > self.owner_epoch {
            return Err(format!(
                "policy.bootstrap_epoch ({}) must be <= owner_epoch ({})",
                self.bootstrap_epoch, self.owner_epoch
            ));
        }
        validate_quorum(&self.rotate_quorum, "rotate_quorum")?;
        if let Some(q) = &self.emergency_quorum {
            validate_quorum(q, "emergency_quorum")?;
        }
        if let Some(q) = &self.policy_update_quorum {
            validate_quorum(q, "policy_update_quorum")?;
            if q.threshold < self.rotate_quorum.threshold {
                return Err(format!(
                    "policy_update_quorum.threshold ({}) must be >= rotate_quorum.threshold ({}); \
                     a lower threshold lets a compromised quorum weaken governance",
                    q.threshold, self.rotate_quorum.threshold
                ));
            }
        }

        // Bootstrap relaxation: current_owner_counts == true is
        // permitted ONLY for bootstrap_epoch == 0 AND owner_epoch == 0
        // policies. Any non-bootstrap policy that sets it must be
        // rejected so a compromised current owner cannot ride a
        // policy update to make themselves single-signer for
        // rotation.
        let is_bootstrap = self.bootstrap_epoch == 0 && self.owner_epoch == 0;
        if self.rotate_quorum.current_owner_counts && !is_bootstrap {
            return Err(format!(
                "rotate_quorum.current_owner_counts = true is only permitted for bootstrap \
                 policies (bootstrap_epoch == 0 AND owner_epoch == 0); got bootstrap_epoch={}, \
                 owner_epoch={}",
                self.bootstrap_epoch, self.owner_epoch
            ));
        }

        Ok(())
    }

    /// Re-derive the id and assert it matches the stored value.
    /// Used by consumers loading a policy from disk or the wire.
    pub fn verify_content_address(&self) -> Result<(), String> {
        let derived = self.derive_id()?;
        if derived != self.policy_id {
            return Err(format!(
                "policy_id mismatch: stored `{}`, derived `{}`",
                self.policy_id, derived
            ));
        }
        Ok(())
    }
}

fn validate_quorum(q: &Quorum, label: &str) -> Result<(), String> {
    if q.threshold == 0 {
        return Err(format!("{label}.threshold must be >= 1"));
    }
    if q.eligible_actors.is_empty() {
        return Err(format!("{label}.eligible_actors must be non-empty"));
    }
    let count = q.eligible_actors.len() as u32;
    if q.threshold > count {
        return Err(format!(
            "{label}.threshold ({}) cannot exceed eligible_actors count ({})",
            q.threshold, count
        ));
    }
    // Reject duplicate eligible actor ids within the same quorum.
    let mut seen = std::collections::BTreeSet::new();
    for actor in &q.eligible_actors {
        if !seen.insert(actor) {
            return Err(format!(
                "{label}.eligible_actors contains duplicate id `{actor}`; each actor counts once \
                 toward quorum"
            ));
        }
    }
    if let Some(rc) = &q.role_constraints {
        let total_min: u32 = rc.min_domain_maintainers.unwrap_or(0)
            + rc.min_registry_stewards.unwrap_or(0)
            + rc.min_independent_stewards.unwrap_or(0);
        if total_min > q.threshold {
            return Err(format!(
                "{label}.role_constraints sum ({total_min}) exceeds threshold ({}); the \
                 constraints cannot be satisfied within a quorum of that size",
                q.threshold
            ));
        }
    }
    Ok(())
}

// v0.145: owner-rotate proposal + attestation bundle + quorum verification.

/// Content-addressed proposal binding a specific owner rotation.
/// Governance attestations sign the canonical preimage of this
/// object so they cannot be replayed against a different
/// frontier, owner, key, policy, or registry entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OwnerRotateProposal {
    pub schema: String,
    pub proposal_id: String,
    pub frontier_id: String,
    pub old_owner_actor_id: String,
    pub old_owner_pubkey: String,
    pub new_owner_actor_id: String,
    pub new_owner_pubkey: String,
    pub owner_epoch: u64,
    pub previous_registry_entry_hash: String,
    pub governance_policy_id: String,
    pub reason: String,
    pub created_at: String,
    pub expires_at: String,
    pub nonce: String,
}

/// Builder input for a proposal (everything except the derived id).
#[derive(Debug, Clone)]
pub struct ProposalDraft {
    pub frontier_id: String,
    pub old_owner_actor_id: String,
    pub old_owner_pubkey: String,
    pub new_owner_actor_id: String,
    pub new_owner_pubkey: String,
    pub owner_epoch: u64,
    pub previous_registry_entry_hash: String,
    pub governance_policy_id: String,
    pub reason: String,
    pub created_at: String,
    pub expires_at: String,
    pub nonce: String,
}

impl OwnerRotateProposal {
    /// Build a proposal from a draft, deriving the content-
    /// addressed `vop_*` id from canonical bytes of the body.
    pub fn from_draft(draft: ProposalDraft) -> Result<Self, String> {
        if draft.owner_epoch == 0 {
            return Err(
                "owner_epoch must be >= 1; the first governed rotation produces owner_epoch=1"
                    .to_string(),
            );
        }
        if draft.reason.trim().is_empty() {
            return Err("reason must be non-empty".to_string());
        }
        let mut proposal = OwnerRotateProposal {
            schema: OWNER_ROTATE_PROPOSAL_SCHEMA.to_string(),
            proposal_id: String::new(),
            frontier_id: draft.frontier_id,
            old_owner_actor_id: draft.old_owner_actor_id,
            old_owner_pubkey: draft.old_owner_pubkey,
            new_owner_actor_id: draft.new_owner_actor_id,
            new_owner_pubkey: draft.new_owner_pubkey,
            owner_epoch: draft.owner_epoch,
            previous_registry_entry_hash: draft.previous_registry_entry_hash,
            governance_policy_id: draft.governance_policy_id,
            reason: draft.reason,
            created_at: draft.created_at,
            expires_at: draft.expires_at,
            nonce: draft.nonce,
        };
        proposal.proposal_id = proposal.derive_id()?;
        Ok(proposal)
    }

    /// Compute the content-addressed `vop_*` id over canonical bytes
    /// of the body with `proposal_id` zeroed.
    pub fn derive_id(&self) -> Result<String, String> {
        let mut preimage = self.clone();
        preimage.proposal_id = String::new();
        let bytes = vela_protocol::canonical::to_canonical_bytes(&preimage)
            .map_err(|e| format!("canonicalize proposal: {e}"))?;
        let digest = Sha256::digest(&bytes);
        Ok(format!("vop_{}", &hex::encode(digest)[..16]))
    }

    /// Canonical preimage bytes used as the message body for
    /// governance attestation signatures. Excludes `proposal_id`
    /// so the preimage is computed from semantics alone.
    pub fn preimage_bytes(&self) -> Result<Vec<u8>, String> {
        let mut preimage = self.clone();
        preimage.proposal_id = String::new();
        vela_protocol::canonical::to_canonical_bytes(&preimage)
            .map_err(|e| format!("canonicalize proposal preimage: {e}"))
    }

    /// The `sha256:<hex>` string used as the
    /// `proposal_preimage_hash` field in attestation bundles.
    pub fn preimage_hash(&self) -> Result<String, String> {
        let bytes = self.preimage_bytes()?;
        let digest = Sha256::digest(&bytes);
        Ok(format!("sha256:{}", hex::encode(digest)))
    }
}

/// Aggregate of detached signatures over a proposal's preimage.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OwnerRotateAttestationBundle {
    pub schema: String,
    pub bundle_id: String,
    pub proposal_id: String,
    pub proposal_preimage_hash: String,
    pub attestations: Vec<AttestationEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttestationEntry {
    pub attester_id: String,
    pub attester_pubkey: String,
    pub judgment: String,
    pub signature: String,
    pub signed_at: String,
}

impl OwnerRotateAttestationBundle {
    /// Build a bundle from a set of attestations, deriving the
    /// content-addressed `vab_*` id from canonical bytes of the
    /// body.
    pub fn new(
        proposal: &OwnerRotateProposal,
        attestations: Vec<AttestationEntry>,
    ) -> Result<Self, String> {
        let preimage_hash = proposal.preimage_hash()?;
        let mut bundle = OwnerRotateAttestationBundle {
            schema: OWNER_ROTATE_BUNDLE_SCHEMA.to_string(),
            bundle_id: String::new(),
            proposal_id: proposal.proposal_id.clone(),
            proposal_preimage_hash: preimage_hash,
            attestations,
        };
        bundle.bundle_id = bundle.derive_id()?;
        Ok(bundle)
    }

    pub fn derive_id(&self) -> Result<String, String> {
        let mut preimage = self.clone();
        preimage.bundle_id = String::new();
        let bytes = vela_protocol::canonical::to_canonical_bytes(&preimage)
            .map_err(|e| format!("canonicalize bundle: {e}"))?;
        let digest = Sha256::digest(&bytes);
        Ok(format!("vab_{}", &hex::encode(digest)[..16]))
    }
}

/// Per-actor revocation lookup. The verifier needs to know whether
/// an attester was revoked at the time they signed. v0.145 takes
/// an inline closure so the substrate can plug in its actor record
/// model without `governance.rs` depending on `project::Project`.
pub trait ActorRevocationLookup {
    fn revoked_at(&self, actor_id: &str) -> Option<&str>;
}

/// Result of a successful quorum verification.
#[derive(Debug, Clone, Serialize)]
pub struct QuorumReport {
    pub proposal_id: String,
    pub bundle_id: String,
    pub policy_id: String,
    pub threshold: u32,
    pub approving_signers: Vec<String>,
    pub current_owner_counted: bool,
}

/// Verify that an attestation bundle satisfies the policy's
/// `rotate_quorum`. Returns `Ok(QuorumReport)` when quorum is met,
/// or a human-readable error string naming the first violation.
///
/// Checks performed (in order):
///
/// 1. Schema constants match.
/// 2. Bundle's `proposal_id` and `proposal_preimage_hash` match the
///    proposal.
/// 3. Proposal's `governance_policy_id` matches the policy.
/// 4. Policy's `frontier_id` and `owner_epoch` match the proposal.
/// 5. Each attestation's signature verifies against
///    `proposal.preimage_bytes()` under the attester's pubkey.
/// 6. Each attester is in the policy's `rotate_quorum.eligible_actors`
///    (or is the current owner AND `current_owner_counts` is true).
/// 7. Duplicate `attester_id` entries count once.
/// 8. Each attester is not revoked at `signed_at` (per the lookup).
/// 9. The number of unique approving signers meets the threshold.
pub fn verify_quorum(
    proposal: &OwnerRotateProposal,
    bundle: &OwnerRotateAttestationBundle,
    policy: &GovernancePolicy,
    revocation: &(impl ActorRevocationLookup + ?Sized),
    now: &str,
) -> Result<QuorumReport, String> {
    if proposal.schema != OWNER_ROTATE_PROPOSAL_SCHEMA {
        return Err(format!(
            "proposal.schema must be `{OWNER_ROTATE_PROPOSAL_SCHEMA}`, got `{}`",
            proposal.schema
        ));
    }
    if bundle.schema != OWNER_ROTATE_BUNDLE_SCHEMA {
        return Err(format!(
            "bundle.schema must be `{OWNER_ROTATE_BUNDLE_SCHEMA}`, got `{}`",
            bundle.schema
        ));
    }
    if bundle.proposal_id != proposal.proposal_id {
        return Err(format!(
            "bundle.proposal_id `{}` does not match proposal.proposal_id `{}`",
            bundle.proposal_id, proposal.proposal_id
        ));
    }
    let expected_hash = proposal.preimage_hash()?;
    if bundle.proposal_preimage_hash != expected_hash {
        return Err(format!(
            "bundle.proposal_preimage_hash mismatch: stored `{}`, derived `{}`",
            bundle.proposal_preimage_hash, expected_hash
        ));
    }
    if proposal.governance_policy_id != policy.policy_id {
        return Err(format!(
            "proposal.governance_policy_id `{}` does not match policy.policy_id `{}`",
            proposal.governance_policy_id, policy.policy_id
        ));
    }
    if policy.frontier_id != proposal.frontier_id {
        return Err(format!(
            "policy.frontier_id `{}` does not match proposal.frontier_id `{}`",
            policy.frontier_id, proposal.frontier_id
        ));
    }
    // The policy must be the one governing the epoch *prior* to the
    // proposed rotation. proposal.owner_epoch is the target epoch.
    // policy.owner_epoch must equal proposal.owner_epoch - 1.
    if policy.owner_epoch + 1 != proposal.owner_epoch {
        return Err(format!(
            "proposal.owner_epoch ({}) must equal policy.owner_epoch ({}) + 1",
            proposal.owner_epoch, policy.owner_epoch
        ));
    }
    // Expiry check: now must be <= expires_at.
    if now > proposal.expires_at.as_str() {
        return Err(format!(
            "proposal expired at {} (now: {})",
            proposal.expires_at, now
        ));
    }

    let preimage_bytes = proposal.preimage_bytes()?;

    // Build eligibility set + lookup of attester -> pubkey policy
    // expects. The actor registry on the frontier carries the
    // authoritative pubkey per attester id; v0.145 takes the
    // attester_pubkey from the bundle entry itself and refuses
    // any pair whose attester_id is not in the eligible set.
    let eligible: std::collections::BTreeSet<&str> = policy
        .rotate_quorum
        .eligible_actors
        .iter()
        .map(String::as_str)
        .collect();

    let mut approving_signers: std::collections::BTreeSet<String> =
        std::collections::BTreeSet::new();
    let mut current_owner_counted = false;

    for att in &bundle.attestations {
        if att.judgment != "approve_owner_rotate" {
            continue;
        }
        // Eligibility check.
        let is_eligible = eligible.contains(att.attester_id.as_str());
        let is_current_owner = att.attester_id == proposal.old_owner_actor_id;
        if !is_eligible && !(is_current_owner && policy.rotate_quorum.current_owner_counts) {
            return Err(format!(
                "attester `{}` is not in rotate_quorum.eligible_actors and the policy does not \
                 admit the current owner (current_owner_counts=false)",
                att.attester_id
            ));
        }
        // Revocation check.
        if let Some(revoked_at) = revocation.revoked_at(&att.attester_id)
            && revoked_at.as_bytes() <= att.signed_at.as_bytes()
        {
            return Err(format!(
                "attester `{}` was revoked at {} (>= signed_at {})",
                att.attester_id, revoked_at, att.signed_at
            ));
        }
        // Pubkey shape + signature check.
        let pk_bytes = hex::decode(&att.attester_pubkey)
            .map_err(|e| format!("attester `{}` pubkey not hex: {e}", att.attester_id))?;
        if pk_bytes.len() != 32 {
            return Err(format!(
                "attester `{}` pubkey must be 32 bytes (got {})",
                att.attester_id,
                pk_bytes.len()
            ));
        }
        let pk = ed25519_dalek::VerifyingKey::from_bytes(
            pk_bytes
                .as_slice()
                .try_into()
                .map_err(|e| format!("attester `{}` pubkey: {e}", att.attester_id))?,
        )
        .map_err(|e| format!("attester `{}` pubkey malformed: {e}", att.attester_id))?;
        let sig_bytes = hex::decode(&att.signature)
            .map_err(|e| format!("attester `{}` signature not hex: {e}", att.attester_id))?;
        if sig_bytes.len() != 64 {
            return Err(format!(
                "attester `{}` signature must be 64 bytes (got {})",
                att.attester_id,
                sig_bytes.len()
            ));
        }
        let sig = ed25519_dalek::Signature::from_bytes(
            sig_bytes
                .as_slice()
                .try_into()
                .map_err(|e| format!("attester `{}` signature: {e}", att.attester_id))?,
        );
        use ed25519_dalek::Verifier;
        pk.verify(&preimage_bytes, &sig).map_err(|e| {
            format!(
                "attester `{}` signature does not verify against proposal preimage: {e}",
                att.attester_id
            )
        })?;

        // Distinct-signer counting: same attester_id appearing twice
        // counts once.
        if approving_signers.insert(att.attester_id.clone()) && is_current_owner {
            current_owner_counted = true;
        }
    }

    let count = approving_signers.len() as u32;
    if count < policy.rotate_quorum.threshold {
        return Err(format!(
            "quorum not met: {} distinct approving signer(s); threshold is {}",
            count, policy.rotate_quorum.threshold
        ));
    }

    Ok(QuorumReport {
        proposal_id: proposal.proposal_id.clone(),
        bundle_id: bundle.bundle_id.clone(),
        policy_id: policy.policy_id.clone(),
        threshold: policy.rotate_quorum.threshold,
        approving_signers: approving_signers.into_iter().collect(),
        current_owner_counted,
    })
}

// v0.146: owner epoch chain transcript + chain verification.

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OwnerEpochChain {
    pub schema: String,
    pub frontier_id: String,
    pub transitions: Vec<ChainTransition>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChainTransition {
    pub owner_epoch: u64,
    pub policy_id: String,
    pub proposal_id: String,
    pub bundle_id: String,
    pub previous_entry_hash: String,
    pub new_owner_actor_id: String,
    pub new_owner_pubkey: String,
    pub signed_at: String,
}

impl OwnerEpochChain {
    pub fn new(frontier_id: String) -> Self {
        OwnerEpochChain {
            schema: OWNER_EPOCH_CHAIN_SCHEMA.to_string(),
            frontier_id,
            transitions: Vec::new(),
        }
    }

    /// Append a transition to the chain. Returns an error if the
    /// owner_epoch is not strictly one greater than the last
    /// transition (gaps and re-applies are rejected; the apply
    /// step is the only writer).
    pub fn append(&mut self, t: ChainTransition) -> Result<(), String> {
        let expected_epoch = self
            .transitions
            .last()
            .map_or(1, |last| last.owner_epoch + 1);
        if t.owner_epoch != expected_epoch {
            return Err(format!(
                "chain transition owner_epoch {} does not match expected {}",
                t.owner_epoch, expected_epoch
            ));
        }
        self.transitions.push(t);
        Ok(())
    }
}

/// Status enum returned by `verify_chain`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainStatus {
    /// Chain has zero transitions (frontier is at owner_epoch 0,
    /// running under the bootstrap policy with no governed
    /// rotations yet).
    Bootstrap,
    /// Every transition verifies cleanly against its policy +
    /// proposal + bundle inputs.
    Verified,
    /// The chain is missing or malformed; the consumer should
    /// treat the entry as legacy (pre-v0.144) or refuse trust as
    /// the audit posture dictates.
    Legacy,
    /// At least one transition failed verification. The error
    /// string accompanies this status.
    Broken,
}

/// Verify an entire owner-epoch chain. The verifier walks every
/// transition and re-runs `verify_quorum` against the supplied
/// policy/proposal/bundle maps. The maps are keyed by content-
/// addressed id; missing keys produce `ChainStatus::Broken`.
///
/// Checks performed per transition:
///
/// - Transition `owner_epoch` is strictly one greater than the
///   previous (chain starts at 1, no gaps, no rewinds).
/// - `transition.policy_id == policy.policy_id`
/// - `transition.proposal_id == proposal.proposal_id`
/// - `transition.bundle_id == bundle.bundle_id`
/// - `transition.previous_entry_hash == proposal.previous_registry_entry_hash`
/// - `transition.new_owner_pubkey == proposal.new_owner_pubkey`
/// - Full `verify_quorum` check succeeds for the transition.
pub fn verify_chain(
    chain: &OwnerEpochChain,
    policies: &std::collections::HashMap<String, GovernancePolicy>,
    proposals: &std::collections::HashMap<String, OwnerRotateProposal>,
    bundles: &std::collections::HashMap<String, OwnerRotateAttestationBundle>,
    revocation: &dyn ActorRevocationLookup,
    now: &str,
) -> ChainStatus {
    if chain.schema != OWNER_EPOCH_CHAIN_SCHEMA {
        return ChainStatus::Broken;
    }
    if chain.transitions.is_empty() {
        return ChainStatus::Bootstrap;
    }
    let mut expected_epoch = 1u64;
    for transition in &chain.transitions {
        if transition.owner_epoch != expected_epoch {
            return ChainStatus::Broken;
        }
        let policy = match policies.get(&transition.policy_id) {
            Some(p) => p,
            None => return ChainStatus::Broken,
        };
        let proposal = match proposals.get(&transition.proposal_id) {
            Some(p) => p,
            None => return ChainStatus::Broken,
        };
        let bundle = match bundles.get(&transition.bundle_id) {
            Some(b) => b,
            None => return ChainStatus::Broken,
        };
        if proposal.previous_registry_entry_hash != transition.previous_entry_hash {
            return ChainStatus::Broken;
        }
        if proposal.new_owner_pubkey != transition.new_owner_pubkey {
            return ChainStatus::Broken;
        }
        if verify_quorum(proposal, bundle, policy, revocation, now).is_err() {
            return ChainStatus::Broken;
        }
        expected_epoch += 1;
    }
    ChainStatus::Verified
}

/// Empty `ActorRevocationLookup` impl for tests + scaffolds where
/// no actor has been revoked.
pub struct EmptyRevocation;

impl ActorRevocationLookup for EmptyRevocation {
    fn revoked_at(&self, _actor_id: &str) -> Option<&str> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;

    fn rotate_q(threshold: u32, actors: &[&str], current_owner_counts: bool) -> Quorum {
        Quorum {
            threshold,
            eligible_actors: actors.iter().map(|s| (*s).to_string()).collect(),
            current_owner_counts,
            role_constraints: None,
            timelock_hours: None,
        }
    }

    fn good_draft() -> PolicyDraft {
        PolicyDraft {
            frontier_id: "vfr_deadbeefdeadbeef".to_string(),
            owner_epoch: 0,
            bootstrap_epoch: 0,
            rotate_quorum: rotate_q(
                1,
                &["reviewer:alice"],
                true, // bootstrap: current owner counts
            ),
            emergency_quorum: None,
            policy_update_quorum: None,
            attestation_ttl_hours: 168,
            created_at: "2026-05-10T00:00:00+00:00".to_string(),
        }
    }

    #[test]
    fn from_draft_derives_policy_id() {
        let policy = GovernancePolicy::from_draft(good_draft()).unwrap();
        assert!(policy.policy_id.starts_with("vgp_"));
        assert_eq!(policy.policy_id.len(), 20); // "vgp_" + 16 hex
        policy.verify_content_address().unwrap();
    }

    #[test]
    fn policy_id_deterministic_over_same_body() {
        let a = GovernancePolicy::from_draft(good_draft()).unwrap();
        let b = GovernancePolicy::from_draft(good_draft()).unwrap();
        assert_eq!(a.policy_id, b.policy_id);
    }

    #[test]
    fn policy_id_differs_when_threshold_differs() {
        let mut draft = good_draft();
        draft.rotate_quorum = rotate_q(2, &["reviewer:alice", "reviewer:bob"], true);
        let a = GovernancePolicy::from_draft(draft).unwrap();
        let b = GovernancePolicy::from_draft(good_draft()).unwrap();
        assert_ne!(a.policy_id, b.policy_id);
    }

    #[test]
    fn duplicate_eligible_actor_rejected() {
        let mut draft = good_draft();
        draft.rotate_quorum = rotate_q(2, &["reviewer:alice", "reviewer:alice"], true);
        let err = GovernancePolicy::from_draft(draft).unwrap_err();
        assert!(
            err.contains("duplicate"),
            "expected duplicate error, got: {err}"
        );
    }

    #[test]
    fn threshold_above_eligible_count_rejected() {
        let mut draft = good_draft();
        draft.rotate_quorum = rotate_q(5, &["reviewer:alice"], true);
        let err = GovernancePolicy::from_draft(draft).unwrap_err();
        assert!(
            err.contains("cannot exceed"),
            "expected threshold/count error, got: {err}"
        );
    }

    #[test]
    fn non_bootstrap_current_owner_counts_rejected() {
        let mut draft = good_draft();
        draft.bootstrap_epoch = 0;
        draft.owner_epoch = 1; // non-bootstrap
        draft.rotate_quorum = rotate_q(1, &["reviewer:alice"], true);
        let err = GovernancePolicy::from_draft(draft).unwrap_err();
        assert!(
            err.contains("bootstrap"),
            "expected bootstrap-only error, got: {err}"
        );
    }

    #[test]
    fn policy_update_quorum_below_rotate_quorum_rejected() {
        let mut draft = good_draft();
        draft.owner_epoch = 1; // non-bootstrap (so current_owner_counts must be false)
        draft.rotate_quorum = rotate_q(3, &["a", "b", "c", "d"], false);
        draft.policy_update_quorum = Some(rotate_q(2, &["a", "b", "c", "d"], false));
        let err = GovernancePolicy::from_draft(draft).unwrap_err();
        assert!(
            err.contains("policy_update_quorum"),
            "expected policy-update floor error, got: {err}"
        );
    }

    // --- v0.145 quorum verification tests ---

    fn fresh_keypair() -> (ed25519_dalek::SigningKey, String) {
        use rand::rngs::OsRng;
        let sk = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let pk_hex = hex::encode(sk.verifying_key().to_bytes());
        (sk, pk_hex)
    }

    fn build_test_policy(
        threshold: u32,
        actors: &[&str],
        owner_epoch: u64,
        current_owner_counts: bool,
        bootstrap: bool,
    ) -> GovernancePolicy {
        GovernancePolicy::from_draft(PolicyDraft {
            frontier_id: "vfr_test123".to_string(),
            owner_epoch,
            bootstrap_epoch: if bootstrap { 0 } else { owner_epoch },
            rotate_quorum: rotate_q(threshold, actors, current_owner_counts),
            emergency_quorum: None,
            policy_update_quorum: None,
            attestation_ttl_hours: 168,
            created_at: "2026-05-10T00:00:00+00:00".to_string(),
        })
        .unwrap()
    }

    fn build_test_proposal(policy: &GovernancePolicy, target_epoch: u64) -> OwnerRotateProposal {
        OwnerRotateProposal::from_draft(ProposalDraft {
            frontier_id: policy.frontier_id.clone(),
            old_owner_actor_id: "owner:current".to_string(),
            old_owner_pubkey: "00".repeat(32),
            new_owner_actor_id: "owner:new".to_string(),
            new_owner_pubkey: "11".repeat(32),
            owner_epoch: target_epoch,
            previous_registry_entry_hash: format!("sha256:{}", "0".repeat(64)),
            governance_policy_id: policy.policy_id.clone(),
            reason: "test rotation".to_string(),
            created_at: "2026-05-10T00:00:00+00:00".to_string(),
            expires_at: "2099-01-01T00:00:00+00:00".to_string(),
            nonce: "deadbeef".to_string(),
        })
        .unwrap()
    }

    fn sign_attestation(
        proposal: &OwnerRotateProposal,
        attester_id: &str,
        sk: &ed25519_dalek::SigningKey,
    ) -> AttestationEntry {
        let preimage = proposal.preimage_bytes().unwrap();
        let sig = sk.sign(&preimage);
        AttestationEntry {
            attester_id: attester_id.to_string(),
            attester_pubkey: hex::encode(sk.verifying_key().to_bytes()),
            judgment: "approve_owner_rotate".to_string(),
            signature: hex::encode(sig.to_bytes()),
            signed_at: "2026-05-10T01:00:00+00:00".to_string(),
        }
    }

    #[test]
    fn quorum_succeeds_when_threshold_met() {
        let (sk_a, _) = fresh_keypair();
        let (sk_b, _) = fresh_keypair();
        let policy = build_test_policy(2, &["reviewer:alice", "reviewer:bob"], 0, false, true);
        // Use a target epoch of 1 so policy.owner_epoch (0) + 1 == proposal.owner_epoch (1).
        let proposal = build_test_proposal(&policy, 1);
        let bundle = OwnerRotateAttestationBundle::new(
            &proposal,
            vec![
                sign_attestation(&proposal, "reviewer:alice", &sk_a),
                sign_attestation(&proposal, "reviewer:bob", &sk_b),
            ],
        )
        .unwrap();
        let report = verify_quorum(
            &proposal,
            &bundle,
            &policy,
            &EmptyRevocation,
            "2026-05-10T02:00:00+00:00",
        )
        .unwrap();
        assert_eq!(report.threshold, 2);
        assert_eq!(report.approving_signers.len(), 2);
    }

    #[test]
    fn quorum_fails_when_threshold_not_met() {
        let (sk_a, _) = fresh_keypair();
        let policy = build_test_policy(2, &["reviewer:alice", "reviewer:bob"], 0, false, true);
        let proposal = build_test_proposal(&policy, 1);
        let bundle = OwnerRotateAttestationBundle::new(
            &proposal,
            vec![sign_attestation(&proposal, "reviewer:alice", &sk_a)],
        )
        .unwrap();
        let err = verify_quorum(
            &proposal,
            &bundle,
            &policy,
            &EmptyRevocation,
            "2026-05-10T02:00:00+00:00",
        )
        .unwrap_err();
        assert!(err.contains("quorum not met"), "got: {err}");
    }

    #[test]
    fn duplicate_attester_counted_once() {
        let (sk_a, _) = fresh_keypair();
        let policy = build_test_policy(2, &["reviewer:alice", "reviewer:bob"], 0, false, true);
        let proposal = build_test_proposal(&policy, 1);
        // alice signs twice; bundle should still fail to meet threshold=2.
        let bundle = OwnerRotateAttestationBundle::new(
            &proposal,
            vec![
                sign_attestation(&proposal, "reviewer:alice", &sk_a),
                sign_attestation(&proposal, "reviewer:alice", &sk_a),
            ],
        )
        .unwrap();
        let err = verify_quorum(
            &proposal,
            &bundle,
            &policy,
            &EmptyRevocation,
            "2026-05-10T02:00:00+00:00",
        )
        .unwrap_err();
        assert!(err.contains("quorum not met"), "got: {err}");
    }

    #[test]
    fn ineligible_attester_rejected() {
        let (sk_x, _) = fresh_keypair();
        let policy = build_test_policy(1, &["reviewer:alice"], 0, false, true);
        let proposal = build_test_proposal(&policy, 1);
        let bundle = OwnerRotateAttestationBundle::new(
            &proposal,
            vec![sign_attestation(&proposal, "reviewer:not-in-list", &sk_x)],
        )
        .unwrap();
        let err = verify_quorum(
            &proposal,
            &bundle,
            &policy,
            &EmptyRevocation,
            "2026-05-10T02:00:00+00:00",
        )
        .unwrap_err();
        assert!(err.contains("not in"), "got: {err}");
    }

    #[test]
    fn wrong_signature_rejected() {
        let (sk_a, _) = fresh_keypair();
        let (sk_other, _) = fresh_keypair();
        let policy = build_test_policy(1, &["reviewer:alice"], 0, false, true);
        let proposal = build_test_proposal(&policy, 1);
        let mut entry = sign_attestation(&proposal, "reviewer:alice", &sk_a);
        // Replace the signature with one from a different key (against
        // a different preimage; the signature itself is well-formed
        // but does not verify under attester_pubkey).
        let bogus = sk_other.sign(b"unrelated");
        entry.signature = hex::encode(bogus.to_bytes());
        let bundle = OwnerRotateAttestationBundle::new(&proposal, vec![entry]).unwrap();
        let err = verify_quorum(
            &proposal,
            &bundle,
            &policy,
            &EmptyRevocation,
            "2026-05-10T02:00:00+00:00",
        )
        .unwrap_err();
        assert!(err.contains("does not verify"), "got: {err}");
    }

    struct OneRevoked {
        actor: String,
        at: String,
    }

    impl ActorRevocationLookup for OneRevoked {
        fn revoked_at(&self, actor_id: &str) -> Option<&str> {
            if actor_id == self.actor {
                Some(&self.at)
            } else {
                None
            }
        }
    }

    #[test]
    fn revoked_attester_rejected() {
        let (sk_a, _) = fresh_keypair();
        let policy = build_test_policy(1, &["reviewer:alice"], 0, false, true);
        let proposal = build_test_proposal(&policy, 1);
        let bundle = OwnerRotateAttestationBundle::new(
            &proposal,
            vec![sign_attestation(&proposal, "reviewer:alice", &sk_a)],
        )
        .unwrap();
        let revoked_lookup = OneRevoked {
            actor: "reviewer:alice".to_string(),
            at: "2026-05-10T00:30:00+00:00".to_string(),
        };
        let err = verify_quorum(
            &proposal,
            &bundle,
            &policy,
            &revoked_lookup,
            "2026-05-10T02:00:00+00:00",
        )
        .unwrap_err();
        assert!(err.contains("revoked"), "got: {err}");
    }

    #[test]
    fn expired_proposal_rejected() {
        let (sk_a, _) = fresh_keypair();
        let policy = build_test_policy(1, &["reviewer:alice"], 0, false, true);
        let mut proposal = build_test_proposal(&policy, 1);
        proposal.expires_at = "2026-05-09T00:00:00+00:00".to_string();
        proposal.proposal_id = proposal.derive_id().unwrap();
        let bundle = OwnerRotateAttestationBundle::new(
            &proposal,
            vec![sign_attestation(&proposal, "reviewer:alice", &sk_a)],
        )
        .unwrap();
        let err = verify_quorum(
            &proposal,
            &bundle,
            &policy,
            &EmptyRevocation,
            "2026-05-10T02:00:00+00:00",
        )
        .unwrap_err();
        assert!(err.contains("expired"), "got: {err}");
    }

    #[test]
    fn proposal_pinned_to_correct_epoch() {
        let (sk_a, _) = fresh_keypair();
        let policy = build_test_policy(1, &["reviewer:alice"], 0, false, true);
        // Target epoch 3 against a policy at epoch 0: should fail
        // (policy + 1 != proposal).
        let proposal = build_test_proposal(&policy, 3);
        let bundle = OwnerRotateAttestationBundle::new(
            &proposal,
            vec![sign_attestation(&proposal, "reviewer:alice", &sk_a)],
        )
        .unwrap();
        let err = verify_quorum(
            &proposal,
            &bundle,
            &policy,
            &EmptyRevocation,
            "2026-05-10T02:00:00+00:00",
        )
        .unwrap_err();
        assert!(err.contains("must equal policy.owner_epoch"), "got: {err}");
    }

    #[test]
    fn role_constraints_exceeding_threshold_rejected() {
        let mut draft = good_draft();
        draft.owner_epoch = 1;
        draft.rotate_quorum = Quorum {
            threshold: 2,
            eligible_actors: vec!["a".into(), "b".into(), "c".into()],
            current_owner_counts: false,
            role_constraints: Some(RoleConstraints {
                min_domain_maintainers: Some(2),
                min_registry_stewards: Some(2),
                min_independent_stewards: None,
            }),
            timelock_hours: None,
        };
        let err = GovernancePolicy::from_draft(draft).unwrap_err();
        assert!(
            err.contains("role_constraints"),
            "expected role-constraint error, got: {err}"
        );
    }
}
