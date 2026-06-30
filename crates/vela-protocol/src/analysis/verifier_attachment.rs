//! Verifier attachments (`vva_`) and the derived verification gate.
//!
//! ## The hole this closes
//!
//! Everywhere else the substrate is careful: a finding is content
//! addressed, an event is signed, a proof verification carries a
//! verifier's signature ([`crate::proof_verification`]). But the step
//! from "the log says this finding is accepted" to "the *claim* is
//! actually true" was never gated. A reviewer's `finding.reviewed →
//! accepted` event records a *human verdict*; it says nothing about
//! whether an independent verifier ever re-derived the result. The
//! Erdős dogfooding made the cost concrete: 47 of 76 records marked
//! "verified" carried an empty verification field, and the promote
//! path trusted every one.
//!
//! ## The fix: a noun, then a derived gate
//!
//! A [`VerifierAttachment`] is the missing noun — a content-addressed,
//! standalone object (the [`crate::bundle`] `Replication` precedent:
//! first-class, targets a finding by id, never a mutable field on it).
//! It binds *one* verifier's judgment to the *exact* claim it checked,
//! by [`claim_digest`]. [`crate::proof_verification::ProofVerification`]
//! and [`crate::lean_verification`] are two instances of one such
//! method (`lean_kernel`); exact combinatorial recompute is another.
//!
//! The gate, [`derive_gate_status`], is a *function of the
//! attachments*, exactly as [`crate::status_provenance`] derives Belnap
//! status from provenance polynomials and never persists it. There is
//! deliberately **no setter** on [`GateStatus`]: a finding cannot be
//! stamped "verified", it can only *derive* as verified from
//! attachments that satisfy four conditions:
//!
//! - **G1 independence** — ≥2 matched attachments by *different*
//!   `(verifier_method, solver_id)`, with at least one naming another in
//!   `independent_of`. The declaration is one-directional by necessity:
//!   the `vva_` id content-addresses the whole body *including*
//!   `independent_of`, so a mutual 2-cycle (A names B, B names A) is a
//!   hash circularity and cannot be constructed. Independence is a
//!   *declared, auditable* property, not a cryptographic one — a single
//!   producer controls every field; the real diversity signal is
//!   distinct `(method, solver)` here and distinct `implementation_id`
//!   in the exact lane. One self-confirmed run never suffices.
//! - **G2 claim-match** — every passing attachment is bound to the
//!   *current* claim digest and declares `match_to_claim.matches`. A
//!   proof that checks a *different* statement is `passed_but_unmatched`
//!   and counts for nothing.
//! - **G3 adversarial** — at least one adversarial probe present and
//!   *none* refuted. A refuted probe drives the status to `Refuted`.
//! - **G4 well-formed + id-integrity** — attachments are structurally
//!   valid (`vva_` ids, parseable methods) AND their stored id
//!   content-addresses their body (`derive_id() == id`). An attachment
//!   whose id is forged or has drifted from its body is excluded from
//!   the matched set: admission re-derives integrity from frozen
//!   content, it never trusts a self-asserted id.
//!
//! Like Belnap status, the gate is orthogonal to the human review
//! verdict ([`crate::bundle::ReviewState`]) and to Bayesian confidence
//! ([`crate::confidence`]). A finding may be reviewer-`Accepted` and
//! still gate `NeedsVerification` — that gap is the point, and the
//! thing the substrate previously hid.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const ATTACHMENT_SCHEMA: &str = "vela.verifier_attachment.v0.1";

/// The independent ways a claim can be checked. Two attachments by
/// different methods are stronger evidence than two runs of the same
/// method — G1 independence keys on this plus `solver_id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifierMethod {
    /// Re-run the combinatorial search / re-check a witness exactly.
    ComputationalSearch,
    /// Recompute an LP bound from its dual (a second solver).
    LpDualRecompute,
    /// A SAT/UNSAT certificate checked independently.
    SatUnsatCert,
    /// The Lean (or other proof-assistant) kernel accepts the term.
    /// [`crate::proof_verification`] / [`crate::lean_verification`]
    /// are instances of this method.
    LeanKernel,
    /// Re-derive a numeric result by exact arithmetic in a second tool.
    ExactArithmeticRecompute,
    /// Corroboration against an independent published source.
    LiteratureCorroboration,
    /// A human referee's structured judgment.
    ManualReferee,
}

impl VerifierMethod {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ComputationalSearch => "computational_search",
            Self::LpDualRecompute => "lp_dual_recompute",
            Self::SatUnsatCert => "sat_unsat_cert",
            Self::LeanKernel => "lean_kernel",
            Self::ExactArithmeticRecompute => "exact_arithmetic_recompute",
            Self::LiteratureCorroboration => "literature_corroboration",
            Self::ManualReferee => "manual_referee",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "computational_search" => Self::ComputationalSearch,
            "lp_dual_recompute" => Self::LpDualRecompute,
            "sat_unsat_cert" => Self::SatUnsatCert,
            "lean_kernel" => Self::LeanKernel,
            "exact_arithmetic_recompute" => Self::ExactArithmeticRecompute,
            "literature_corroboration" => Self::LiteratureCorroboration,
            "manual_referee" => Self::ManualReferee,
            _ => return None,
        })
    }

    pub const ALL: [VerifierMethod; 7] = [
        Self::ComputationalSearch,
        Self::LpDualRecompute,
        Self::SatUnsatCert,
        Self::LeanKernel,
        Self::ExactArithmeticRecompute,
        Self::LiteratureCorroboration,
        Self::ManualReferee,
    ];
}

/// The kinds of adversarial probe a verifier can run against a claim.
/// G3 requires at least one to be present and surviving.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeKind {
    /// Search directly for a counterexample to the claim.
    CounterexampleSearch,
    /// Exercise the adversarial "Case B" configuration that broke an
    /// earlier over-claim.
    CaseBConfig,
    /// Check dual feasibility at the boundary of an LP bound.
    BoundaryDualFeasibility,
    /// Extrapolate a finite-size result and test it does not collapse.
    FiniteSizeExtrapolation,
    /// Re-implement the construction independently and compare.
    IndependentReimplementation,
    /// Statement-faithfulness: throw a prover at the formalized statement S
    /// AND its negation ¬S. Both provable ⇒ the formalization is
    /// vacuous/contradictory (misformalized). Also flags a statement that is
    /// trivially provable, or a proof that uses no hypothesis. A `Refuted`
    /// result here means the *verification claim* is unfaithful, not that the
    /// underlying mathematics is false — and it drives the gate to Refuted so
    /// a green kernel seal can never stand on a statement that does not mean
    /// what it claims.
    FormalismFidelity,
}

impl ProbeKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CounterexampleSearch => "counterexample_search",
            Self::CaseBConfig => "case_b_config",
            Self::BoundaryDualFeasibility => "boundary_dual_feasibility",
            Self::FiniteSizeExtrapolation => "finite_size_extrapolation",
            Self::IndependentReimplementation => "independent_reimplementation",
            Self::FormalismFidelity => "formalism_fidelity",
        }
    }
}

/// The outcome of a single adversarial probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeResult {
    /// The claim survived the probe.
    Survived,
    /// The probe *refuted* the claim. A single refuting probe drives
    /// the whole gate to [`GateStatus::Refuted`].
    Refuted,
}

/// One adversarial probe run against the claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdversarialProbe {
    pub kind: ProbeKind,
    pub result: ProbeResult,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,
}

/// Whether the verifier confirmed it checked the *exact* frozen claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchToClaim {
    /// The verifier asserts its check is of the target claim verbatim,
    /// not a weaker or different statement.
    pub matches: bool,
    /// Who performed the match check.
    pub checker_actor: String,
}

/// The verifier's top-line outcome, before the gate's claim-match and
/// independence reasoning. `Passed` means the method accepted; it does
/// *not* by itself mean the claim is verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttachmentOutcome {
    Passed,
    Failed,
}

/// A method-specific integrity claim layered on top of [`AttachmentOutcome`].
///
/// `Passed` says the method accepted; this says whether the method ran
/// *soundly*. A Lean proof can pass `lake build` yet depend on
/// `native_decide` (compiler trust) or `sorry` — sound elaboration, unsound
/// kernel claim. The producer that mints a `lean_kernel` attachment sets this
/// from the [`crate::tcb_policy::AxiomVerdict`] of the underlying
/// verification, so the gate can refuse compromised methods without ever
/// importing Lean specifics (G5).
///
/// Default is [`MethodIntegrity::Unattested`], serialized as *absent* so
/// pre-existing `vva_` records re-derive their content-addressed id
/// unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MethodIntegrity {
    /// No method-specific integrity claim is made (legacy, or a method for
    /// which integrity is not applicable). Neither trusted nor rejected.
    #[default]
    Unattested,
    /// The method self-certifies clean (e.g. the Lean axiom set is
    /// `KernelClean`, or an independent recompute matched).
    Sound,
    /// The method ran but its integrity check failed (a forbidden/unlisted
    /// Lean axiom, a failed external kernel re-check, a solver in an
    /// untrusted mode). Excluded from the matched set by the gate.
    Compromised,
}

impl MethodIntegrity {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unattested => "unattested",
            Self::Sound => "sound",
            Self::Compromised => "compromised",
        }
    }

    /// Used by `skip_serializing_if` so the default serializes as absent,
    /// keeping legacy `vva_` ids stable.
    #[must_use]
    pub fn is_unattested(&self) -> bool {
        *self == Self::Unattested
    }
}

/// A single verifier's judgment, content-addressed and bound to the
/// exact claim it checked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierAttachment {
    pub schema: String,
    /// `vva_<16hex>`, derived from the canonical body (id field empty).
    pub id: String,
    /// The finding (`vf_…`) or claim object this attaches to.
    pub target: String,
    /// [`claim_digest`] of the exact claim text checked. G2 compares
    /// this to the current claim's digest.
    pub claim_digest: String,
    pub verifier_method: VerifierMethod,
    /// Identifies the independent solver/tool that produced this check
    /// (e.g. `cp-sat`, `pulp-cbc`, `lean4@4.29.1`). G1 independence
    /// keys on `(verifier_method, solver_id)`.
    pub solver_id: String,
    /// Ids of *other* attachments this one declares itself independent
    /// of. G1 requires the matched set to declare independence one-
    /// directionally (>=1 declaration); a mutual 2-cycle is unconstructable
    /// because the id content-addresses this field. Reference EARLIER-built
    /// attachments only, so the referenced id is final before this one is built.
    #[serde(default)]
    pub independent_of: Vec<String>,
    pub match_to_claim: MatchToClaim,
    #[serde(default)]
    pub adversarial_probes: Vec<AdversarialProbe>,
    pub outcome: AttachmentOutcome,
    /// Method-specific integrity (G5). Absent on legacy records; a
    /// `Compromised` attachment is excluded from the matched set.
    #[serde(default, skip_serializing_if = "MethodIntegrity::is_unattested")]
    pub method_integrity: MethodIntegrity,
    pub verifier_actor: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,
    /// Monoculture provenance (optional; absent on legacy records):
    /// which IMPLEMENTATION produced this run. N runs of one frozen
    /// binary are replication; N independent implementations are
    /// diversity — the gate's reasons distinguish them.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub implementation_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub toolchain_hash: String,
    /// Undischarged hypotheses the proof assumes (optional; absent on legacy
    /// records, so their ids are byte-unchanged). For a `lean_kernel` attachment
    /// these are the problem-defined named propositions the theorem takes as
    /// parameters — e.g. a `(h : DensityHypothesis)` standing for an unproven
    /// prime-gaps result, or `(h : DukeTheoremStatement)`. The proof is then
    /// `sorry`-free and `#print axioms`-clean yet establishes the claim only
    /// CONDITIONALLY: the hypothesis is a parameter, not an axiom, so the axiom
    /// check cannot see it. A non-empty list demotes the gate (this attachment
    /// cannot be an unconditional verification). Each entry is `"name : type"`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub undischarged_hypotheses: Vec<String>,
}

/// Fields a caller supplies; the id and schema are derived.
#[derive(Debug, Clone)]
pub struct AttachmentDraft {
    pub target: String,
    pub claim_digest: String,
    pub verifier_method: VerifierMethod,
    pub solver_id: String,
    pub independent_of: Vec<String>,
    pub match_to_claim: MatchToClaim,
    pub adversarial_probes: Vec<AdversarialProbe>,
    pub outcome: AttachmentOutcome,
    pub verifier_actor: String,
    pub note: String,
}

/// The digest of a claim, binding an attachment to the exact text it
/// checked. `sha256(trimmed claim)`, first 16 hex chars — the same
/// rule as `canopus_trust.py::claim_digest`, so digests match across
/// the Rust and Python implementations.
#[must_use]
pub fn claim_digest(claim: &str) -> String {
    let digest = Sha256::digest(claim.trim().as_bytes());
    hex::encode(digest)[..16].to_string()
}

/// A deterministic, non-forgeable toolchain fingerprint for an attachment: the
/// verifier-method class pinned to the attachment schema version. Two
/// attachments from the same verifier TOOLCHAIN share it (replication of one
/// checker); a Lean kernel and a frozen computational search differ (genuine
/// toolchain diversity). Unlike `solver_id` — a free string the producing agent
/// chooses — it is derived from the method, so a cosmetic rename cannot fake a
/// "distinct" toolchain. The exact-lane independence reasoning surfaces it as
/// corroborating evidence; the at-enable tightening can promote it from a
/// reported signal to a hard distinctness requirement.
#[must_use]
pub fn derive_toolchain_hash(method: &VerifierMethod) -> String {
    let tag = format!("{ATTACHMENT_SCHEMA}:{method:?}");
    hex::encode(Sha256::digest(tag.as_bytes()))[..16].to_string()
}

impl VerifierAttachment {
    /// Build an attachment, deriving its content-addressed id from the
    /// canonical body. Mirrors the id-from-signed-body pattern in
    /// [`crate::proof_verification`].
    pub fn build(draft: AttachmentDraft) -> Result<Self, String> {
        if !draft.target.starts_with("vf_") && !draft.target.starts_with("vfr_") {
            return Err(format!(
                "attachment target should be a finding (`vf_`) or frontier-claim (`vfr_`) id; got `{}`",
                draft.target
            ));
        }
        let mut att = VerifierAttachment {
            schema: ATTACHMENT_SCHEMA.to_string(),
            id: String::new(),
            target: draft.target,
            claim_digest: draft.claim_digest,
            verifier_method: draft.verifier_method,
            solver_id: draft.solver_id,
            independent_of: draft.independent_of,
            match_to_claim: draft.match_to_claim,
            adversarial_probes: draft.adversarial_probes,
            outcome: draft.outcome,
            method_integrity: MethodIntegrity::Unattested,
            verifier_actor: draft.verifier_actor,
            note: draft.note,
            implementation_id: String::new(),
            toolchain_hash: derive_toolchain_hash(&draft.verifier_method),
            undischarged_hypotheses: Vec::new(),
        };
        att.id = att.derive_id()?;
        Ok(att)
    }

    /// Set the method integrity and re-derive the content-addressed id.
    /// The Lean producer calls this with the [`crate::tcb_policy::AxiomVerdict`]
    /// mapped through [`crate::lean_verification::LeanVerification::to_attachment_integrity`].
    /// Because integrity is part of the canonical body, a `Sound`/`Compromised`
    /// attachment necessarily has a different id than its `Unattested` form.
    pub fn with_method_integrity(mut self, integrity: MethodIntegrity) -> Result<Self, String> {
        self.method_integrity = integrity;
        self.id = self.derive_id()?;
        Ok(self)
    }

    /// Set the implementation id and re-derive the content-addressed id.
    /// `implementation_id` is part of the canonical body, so a producer that
    /// records which implementation ran (the exact-lane monoculture guard reads
    /// it) must set it through this builder rather than by field assignment, or
    /// the stored id would no longer content-address the body and the gate's G4
    /// id-integrity check would exclude the attachment. Apply it AFTER
    /// `with_method_integrity` (it is the last mutation) so the id is final.
    pub fn with_implementation_id(mut self, implementation_id: &str) -> Result<Self, String> {
        self.implementation_id = implementation_id.to_string();
        self.id = self.derive_id()?;
        Ok(self)
    }

    /// Record the undischarged hypotheses the proof assumes and re-derive the id.
    /// Part of the canonical body (like `method_integrity`), so it must be set
    /// through this builder, not by field assignment, or the gate's G4 id-integrity
    /// check would exclude the attachment. A non-empty list makes the attachment
    /// CONDITIONAL: `derive_gate_status` will not let it reach `Verified`.
    pub fn with_undischarged_hypotheses(mut self, hyps: Vec<String>) -> Result<Self, String> {
        self.undischarged_hypotheses = hyps;
        self.id = self.derive_id()?;
        Ok(self)
    }

    /// Re-derive the content-addressed id from the canonical body with
    /// the id field zeroed.
    pub fn derive_id(&self) -> Result<String, String> {
        let mut preimage = self.clone();
        preimage.id = String::new();
        let bytes = crate::canonical::to_canonical_bytes(&preimage)
            .map_err(|e| format!("canonicalize attachment preimage: {e}"))?;
        let digest = Sha256::digest(&bytes);
        Ok(format!("vva_{}", &hex::encode(digest)[..16]))
    }

    /// Structural validity (G4): schema, id prefix, and id integrity.
    pub fn verify(&self) -> Result<(), String> {
        if self.schema != ATTACHMENT_SCHEMA {
            return Err(format!(
                "attachment.schema must be `{ATTACHMENT_SCHEMA}`, got `{}`",
                self.schema
            ));
        }
        if !self.id.starts_with("vva_") {
            return Err(format!(
                "attachment id must start with `vva_`, got `{}`",
                self.id
            ));
        }
        let derived = self.derive_id()?;
        if derived != self.id {
            return Err(format!(
                "attachment id mismatch: stored `{}`, derived `{}`",
                self.id, derived
            ));
        }
        Ok(())
    }

    /// Whether this attachment is well-formed *and* matches the given
    /// claim digest with `outcome = passed`, `match_to_claim`, and an
    /// integrity that is not `Compromised` (G5).
    fn is_passing_match(&self, current_digest: &str) -> bool {
        self.is_base_match(current_digest) && self.method_integrity != MethodIntegrity::Compromised
    }

    /// True iff the stored id content-addresses the body (`derive_id() == id`).
    /// The gate re-derives this for every matched attachment so admission rests
    /// on frozen content, never on a forgeable self-asserted id. (No production
    /// path called `verify()` before; the gate now closes that hole itself.)
    fn has_valid_id(&self) -> bool {
        self.derive_id().is_ok_and(|d| d == self.id)
    }

    /// Passed, claim-matched, well-prefixed — the *claim binding*, before the
    /// id-integrity (G4) and method-integrity (G5) checks. Used to surface a
    /// forged-id or compromised attachment with a precise reason rather than
    /// silently dropping it into `passed_but_unmatched` (G2).
    fn is_claim_bound(&self, current_digest: &str) -> bool {
        self.id.starts_with("vva_")
            && self.outcome == AttachmentOutcome::Passed
            && self.claim_digest == current_digest
            && self.match_to_claim.matches
    }

    /// Well-formed, passed, claim-matched, AND id-integral (G4) — everything but
    /// the method-integrity check. The integrity check is the only thing
    /// distinguishing a passing match (G5 ok) from a compromised one (G5 excluded).
    fn is_base_match(&self, current_digest: &str) -> bool {
        self.is_claim_bound(current_digest) && self.has_valid_id()
    }

    /// Whether this attachment would have matched the claim but is excluded
    /// solely because its method integrity is `Compromised` (G5 reason).
    fn is_compromised_match(&self, current_digest: &str) -> bool {
        self.is_base_match(current_digest) && self.method_integrity == MethodIntegrity::Compromised
    }
}

/// The derived verification status of a finding. There is no
/// constructor that sets this directly — it is only ever the return
/// value of [`derive_gate_status`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateStatus {
    /// The default. Not enough independent, matched, probed evidence.
    NeedsVerification,
    /// G1–G4 all satisfied.
    Verified,
    /// An adversarial probe refuted the claim. Terminal until the
    /// claim is revised.
    Refuted,
}

/// The full outcome of the gate: a status plus the reasons it is not
/// [`GateStatus::Verified`] (empty exactly when verified).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateOutcome {
    pub status: GateStatus,
    pub reasons: Vec<String>,
}

impl GateOutcome {
    #[must_use]
    pub fn is_verified(&self) -> bool {
        self.status == GateStatus::Verified
    }
}

/// Derive the gate status of a claim from its verifier attachments.
///
/// This is the substrate's answer to "is this claim verified?" — a
/// pure function of `(current_claim_digest, attachments)`, never a
/// stored flag. Implements G1–G4. A finding with `payload.status =
/// accepted` and **zero** attachments derives to `NeedsVerification`,
/// not `Verified` — the exact bug class the gate exists to prevent.
#[must_use]
pub fn derive_gate_status(
    current_claim_digest: &str,
    attachments: &[VerifierAttachment],
) -> GateOutcome {
    let mut reasons = Vec::new();

    let passed: Vec<&VerifierAttachment> = attachments
        .iter()
        .filter(|a| a.outcome == AttachmentOutcome::Passed)
        .collect();

    // G2 claim-match: a passing attachment bound to a different claim,
    // or not declaring a match, is `passed_but_unmatched` and counts
    // for nothing.
    let matched: Vec<&VerifierAttachment> = attachments
        .iter()
        .filter(|a| a.is_passing_match(current_claim_digest))
        .collect();

    // Monoculture observation: when the matched set agrees but every run
    // names the SAME implementation, say so — N runs of one binary are
    // replication, not implementation diversity. NB: pushing a reason here
    // DOES demote (status is Verified iff `reasons` is empty), so a single-
    // implementation matched set derives `NeedsVerification`.
    {
        let impls: std::collections::HashSet<&str> = matched
            .iter()
            .map(|a| a.implementation_id.as_str())
            .filter(|s| !s.is_empty())
            .collect();
        if matched.len() >= 2 && impls.len() == 1 {
            reasons.push(format!(
                "monoculture: {} matched run(s) all from implementation '{}' — independent implementations would strengthen this",
                matched.len(),
                impls.iter().next().unwrap()
            ));
        }
    }

    // G5 method-integrity: an attachment that *would* match the claim but
    // ran with a compromised method (e.g. a forbidden Lean axiom such as
    // `native_decide`/`sorry`, or a failed external kernel re-check) is
    // excluded from the matched set. A `lean_kernel` proof that trusts the
    // compiler can therefore never push a finding to Verified.
    let compromised = attachments
        .iter()
        .filter(|a| a.is_compromised_match(current_claim_digest))
        .count();
    if compromised > 0 {
        reasons.push(format!(
            "G5: {compromised} attachment(s) excluded — method integrity compromised \
             (e.g. forbidden Lean axiom or failed kernel re-check)"
        ));
    }

    // Conditional-proof guard: a matched attachment whose proof is conditional on
    // undischarged hypotheses (a theorem parameter `(h : DensityHypothesis)`
    // standing for an unproven result) establishes the claim only CONDITIONALLY.
    // `#print axioms` cannot see this — the hypothesis is a parameter, not an
    // axiom — so `method_integrity` may be `Sound` and the kernel clean while the
    // proof still assumes a deep result. The gate refuses to call such an
    // attachment an unconditional verification. (Empty on every legacy record, so
    // this never changes a stored finding's status.)
    let conditional: Vec<&str> = matched
        .iter()
        .filter(|a| !a.undischarged_hypotheses.is_empty())
        .flat_map(|a| a.undischarged_hypotheses.iter().map(String::as_str))
        .collect();
    if !conditional.is_empty() {
        reasons.push(format!(
            "conditional: matched attachment(s) prove the claim only under undischarged \
             hypotheses [{}] — `#print axioms`-clean but not an unconditional verification",
            conditional.join("; ")
        ));
    }

    // G4 id-integrity: an attachment that *would* match the claim but whose
    // stored id does not content-address its body (forged or drifted) is
    // excluded from the matched set. `verify()` was never called on the
    // write path, so the gate re-derives integrity here — a self-asserted
    // `vva_` id can never push a finding to Verified on its own say-so.
    let id_invalid = attachments
        .iter()
        .filter(|a| a.is_claim_bound(current_claim_digest) && !a.has_valid_id())
        .count();
    if id_invalid > 0 {
        reasons.push(format!(
            "G4: {id_invalid} attachment(s) excluded — id does not content-address the body \
             (forged or drifted; derive_id() != id)"
        ));
    }

    // Genuine claim mismatch: passed, but neither matched, compromised, nor
    // id-invalid (wrong claim digest, or match_to_claim=false).
    if passed.len() > matched.len() + compromised + id_invalid {
        reasons.push(
            "G2: an attachment passed but is unmatched to the current claim (passed_but_unmatched)"
                .to_string(),
        );
    }

    // G1 independence: ≥2 matched attachments by different method/solver,
    // with at least one declaring independence (one-directional; mutual is a
    // hash circularity over the content-addressed id).
    if matched.len() < 2 {
        reasons.push(format!(
            "G1: need >=2 matched independent attachments, have {}",
            matched.len()
        ));
    } else {
        let distinct_methods: std::collections::BTreeSet<(VerifierMethod, &str)> = matched
            .iter()
            .map(|a| (a.verifier_method, a.solver_id.as_str()))
            .collect();
        if distinct_methods.len() < 2 {
            reasons.push(
                "G1: >=2 attachments but all share one method/solver (not independent)".to_string(),
            );
        } else {
            let ids: std::collections::BTreeSet<&str> =
                matched.iter().map(|a| a.id.as_str()).collect();
            let declares_independence = matched.iter().any(|a| {
                a.independent_of
                    .iter()
                    .any(|other| other != &a.id && ids.contains(other.as_str()))
            });
            if !declares_independence {
                reasons.push(
                    "G1: attachments do not declare independence (independent_of)".to_string(),
                );
            }
        }
    }

    // G3 adversarial: a refuted probe is terminal; otherwise need >=1
    // surviving probe across the matched set.
    let probes: Vec<&AdversarialProbe> = matched
        .iter()
        .flat_map(|a| a.adversarial_probes.iter())
        .collect();
    if probes.iter().any(|p| p.result == ProbeResult::Refuted) {
        return GateOutcome {
            status: GateStatus::Refuted,
            reasons: vec![
                "G3: an adversarial probe REFUTED the claim -> status is refuted".to_string(),
            ],
        };
    }
    if probes.is_empty() {
        reasons.push("G3: no surviving adversarial probe attached (need >=1)".to_string());
    }

    // G4 well-formed: every matched attachment is structurally valid.
    for a in &matched {
        if !a.id.starts_with("vva_") {
            reasons.push(format!("G4: malformed attachment id `{}`", a.id));
        }
    }

    let status = if reasons.is_empty() {
        GateStatus::Verified
    } else {
        GateStatus::NeedsVerification
    };
    GateOutcome { status, reasons }
}

/// The deterministic attachment-level decision for **exact-lane
/// auto-admission** (Phase 1A, the de-human-gate). This is the trust
/// predicate the `policy.auto_admitted` event materializes: it is frozen
/// audited Rust, never a model, so "no AI in the trust path" stays literally
/// true while the human is removed from the rote kernel-clean admit.
///
/// It is **strictly stronger** than [`derive_gate_status`] reaching
/// `Verified` — it never admits anything the gate would not, and it adds the
/// guards a human reviewer would otherwise apply. Each guard closes a concrete
/// red-team attack the bare `Verified` check leaves open:
///
///   1. the gate must already be [`GateStatus::Verified`] (inherits G1-G5:
///      >=2 matched independent attachments, claim-bound, no compromised
///      method, no refuted probe).
///   2. **every matched attachment is [`MethodIntegrity::Sound`]** — reject
///      the legacy `Unattested` default the gate otherwise tolerates (the gate
///      only *excludes* `Compromised`). Closes the smuggled-axiom /
///      unaudited-legacy attack.
///   3. **a [`ProbeKind::FormalismFidelity`] probe is PRESENT and Survived**
///      on the matched set, and none is Refuted. The gate's G3 accepts *any*
///      surviving probe, so a vacuous or misformalized statement with only a
///      `CounterexampleSearch` probe passes it. Auto-admit demands the
///      faithfulness probe explicitly (absent != safe).
///   4. **declared independence**: at least one matched attachment names
///      another matched attachment in `independent_of` (one-directional). This
///      cannot be mutual: the `vva_` id content-addresses the body *including*
///      `independent_of`, so a 2-cycle is a hash circularity (the prior "mutual"
///      rule made this lane unreachable for every honestly-built pair). The
///      declaration is a consistency/audit signal, not cryptographic
///      independence — a single producer controls every field; the real
///      diversity teeth are guards 5 (distinct implementations) and the gate's
///      G1 (distinct method/solver). Do NOT re-tighten this to mutual.
///   5. **not an implementation monoculture**: the matched set carries >=2
///      distinct non-empty `implementation_id`s. N runs of one binary are
///      replication, not independent verification; the gate only *warns*.
///
/// Every matched attachment is also id-integral (G4: `derive_id() == id`),
/// inherited from the gate's `is_base_match`, so a forged-id attachment can
/// never enter the matched set this predicate reasons over.
///
/// Proposal-level guards (synthetic-source signal, live frontier
/// contradiction, proposal kind) are applied by the caller in `proposals.rs`,
/// which has the `StateProposal`/`Project` context this primitive does not.
/// Returns `(admit, reasons)`; `reasons` is non-empty exactly when refused.
pub fn exact_lane_attachment_admit(
    current_claim_digest: &str,
    attachments: &[VerifierAttachment],
) -> (bool, Vec<String>) {
    let mut reasons = Vec::new();

    // Guard 1: the existing frozen gate must reach Verified.
    let gate = derive_gate_status(current_claim_digest, attachments);
    if gate.status != GateStatus::Verified {
        reasons.push(format!(
            "exact-lane: gate not Verified ({:?}): {}",
            gate.status,
            gate.reasons.join("; ")
        ));
        return (false, reasons);
    }

    // The matched set is exactly the gate's notion of "counts toward Verified".
    let matched: Vec<&VerifierAttachment> = attachments
        .iter()
        .filter(|a| a.is_passing_match(current_claim_digest))
        .collect();
    // Verified implies matched.len() >= 2, but never assume it.
    if matched.len() < 2 {
        reasons.push("exact-lane: fewer than 2 matched attachments".to_string());
        return (false, reasons);
    }

    // Guard 2: reject the Unattested legacy default; require Sound on all.
    if let Some(bad) = matched
        .iter()
        .find(|a| a.method_integrity != MethodIntegrity::Sound)
    {
        reasons.push(format!(
            "exact-lane: attachment `{}` is not MethodIntegrity::Sound ({:?}); auto-admit requires Sound (a human must clear Unattested)",
            bad.id, bad.method_integrity
        ));
        return (false, reasons);
    }

    // Guard 3: a FormalismFidelity probe must be PRESENT and Survived, and
    // none may be Refuted (a Refuted one already forces the gate to Refuted,
    // but assert it independently of gate internals).
    let mut ff_survived = false;
    for a in &matched {
        for p in &a.adversarial_probes {
            if p.kind == ProbeKind::FormalismFidelity {
                match p.result {
                    ProbeResult::Survived => ff_survived = true,
                    ProbeResult::Refuted => {
                        reasons
                            .push("exact-lane: a FormalismFidelity probe is Refuted".to_string());
                        return (false, reasons);
                    }
                }
            }
        }
    }
    if !ff_survived {
        reasons.push(
            "exact-lane: no present-and-Survived FormalismFidelity probe (faithfulness unproven; \
             absent does not count as safe)"
                .to_string(),
        );
        return (false, reasons);
    }

    // Guard 4: declared independence — at least one matched attachment names
    // another matched attachment in `independent_of` (one-directional, the same
    // form the gate's G1 accepts). Mutual is impossible: the vva_ id
    // content-addresses the body INCLUDING independent_of, so a 2-cycle is a
    // hash circularity; requiring it (as this guard once did) made the whole
    // lane unreachable for every honestly-built pair. The teeth are guard 5
    // (distinct implementations) and G1 (distinct method/solver), not this
    // declaration. Re-derived from the same `matched` set the gate verified.
    let ids: std::collections::BTreeSet<&str> = matched.iter().map(|a| a.id.as_str()).collect();
    let declares_independence = matched.iter().any(|a| {
        a.independent_of
            .iter()
            .any(|other| other != &a.id && ids.contains(other.as_str()))
    });
    if !declares_independence {
        reasons.push(
            "exact-lane: no matched attachment declares independent_of another (need >=1 \
             one-directional declaration)"
                .to_string(),
        );
        return (false, reasons);
    }

    // Guard 5: not an implementation monoculture.
    let impls: std::collections::BTreeSet<&str> = matched
        .iter()
        .map(|a| a.implementation_id.as_str())
        .filter(|s| !s.is_empty())
        .collect();
    if impls.len() < 2 {
        reasons.push(
            "exact-lane: implementation monoculture (need >=2 distinct implementation_id; N runs \
             of one binary are replication, not independent verification)"
                .to_string(),
        );
        return (false, reasons);
    }

    (true, reasons)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn match_to(actor: &str) -> MatchToClaim {
        MatchToClaim {
            matches: true,
            checker_actor: actor.to_string(),
        }
    }

    fn surviving_probe() -> AdversarialProbe {
        AdversarialProbe {
            kind: ProbeKind::CounterexampleSearch,
            result: ProbeResult::Survived,
            note: String::new(),
        }
    }

    fn attach(
        digest: &str,
        method: VerifierMethod,
        solver: &str,
        independent_of: Vec<String>,
        probes: Vec<AdversarialProbe>,
    ) -> VerifierAttachment {
        VerifierAttachment::build(AttachmentDraft {
            target: "vf_0123456789abcdef".to_string(),
            claim_digest: digest.to_string(),
            verifier_method: method,
            solver_id: solver.to_string(),
            independent_of,
            match_to_claim: match_to("checker"),
            adversarial_probes: probes,
            outcome: AttachmentOutcome::Passed,
            verifier_actor: "Opus 4.8".to_string(),
            note: String::new(),
        })
        .unwrap()
    }

    fn ff_survived() -> AdversarialProbe {
        AdversarialProbe {
            kind: ProbeKind::FormalismFidelity,
            result: ProbeResult::Survived,
            note: String::new(),
        }
    }

    /// Build a fully-specified attachment with a GENUINELY VALID id: every
    /// id-bearing field (integrity, implementation_id) is set through the
    /// re-deriving builders, never by post-build mutation, so `verify()` holds.
    /// `independent_of` is set at build time, so reference EARLIER-built ids.
    #[allow(clippy::too_many_arguments)]
    fn attach_full(
        digest: &str,
        method: VerifierMethod,
        solver: &str,
        independent_of: Vec<String>,
        probes: Vec<AdversarialProbe>,
        integrity: MethodIntegrity,
        impl_id: &str,
    ) -> VerifierAttachment {
        let mut a = attach(digest, method, solver, independent_of, probes);
        if integrity != MethodIntegrity::Unattested {
            a = a.with_method_integrity(integrity).unwrap();
        }
        if !impl_id.is_empty() {
            a = a.with_implementation_id(impl_id).unwrap();
        }
        a
    }

    /// A pair of attachments that SHOULD pass exact-lane auto-admit: two
    /// matched, `Sound`, distinct-implementation runs, each carrying a Survived
    /// FormalismFidelity probe, with ONE-DIRECTIONAL declared independence (a2
    /// names a1 — mutual is a hash circularity, see Guard 4). Both ids are
    /// genuinely content-valid. Each red-team test below degrades exactly one
    /// property and asserts the predicate refuses while the bare gate often
    /// still says Verified.
    fn admit_pair(digest: &str) -> (VerifierAttachment, VerifierAttachment) {
        // a1 is built first so its id is final before a2 references it.
        let a1 = attach_full(
            digest,
            VerifierMethod::ComputationalSearch,
            "cp-sat",
            vec![],
            vec![ff_survived()],
            MethodIntegrity::Sound,
            "impl-cp-sat",
        );
        let a2 = attach_full(
            digest,
            VerifierMethod::ExactArithmeticRecompute,
            "pari-gp",
            vec![a1.id.clone()],
            vec![ff_survived()],
            MethodIntegrity::Sound,
            "impl-pari",
        );
        (a1, a2)
    }

    #[test]
    fn exact_lane_happy_path_admits() {
        let digest = claim_digest("claim X");
        let (a1, a2) = admit_pair(&digest);
        // The admitting pair is GENUINELY id-valid — built through build() +
        // the re-deriving builders, not by mutating ids in memory.
        a1.verify().expect("a1 content-addresses its body");
        a2.verify().expect("a2 content-addresses its body");
        assert_eq!(
            derive_gate_status(&digest, &[a1.clone(), a2.clone()]).status,
            GateStatus::Verified
        );
        let (admit, reasons) = exact_lane_attachment_admit(&digest, &[a1, a2]);
        assert!(admit, "should auto-admit, refused for: {reasons:?}");
        assert!(reasons.is_empty());
    }

    // The forged-id attack the relaxed Guard 4 must not open: a single actor
    // hand-authors two attachments whose ids do NOT content-address their
    // bodies (here, mutual independence declarations added without re-deriving,
    // exactly the unconstructable-honestly 2-cycle). G4 id-integrity excludes
    // them from the matched set, so the gate never reaches Verified and the
    // exact lane refuses. Without the id-integrity check this pair would admit.
    #[test]
    fn exact_lane_refuses_forged_id_pair() {
        let digest = claim_digest("claim X");
        let (mut a1, mut a2) = admit_pair(&digest);
        // Hand-author a mutual 2-cycle with arbitrary `vva_` ids — the form an
        // attacker writes directly as JSON, which build() can never mint (the id
        // content-addresses independent_of). Neither id matches its body.
        a1.id = "vva_forged00000a1".to_string();
        a2.id = "vva_forged00000a2".to_string();
        a1.independent_of = vec![a2.id.clone()];
        a2.independent_of = vec![a1.id.clone()];
        assert!(a1.verify().is_err(), "forged a1 must fail id-integrity");
        assert!(a2.verify().is_err(), "forged a2 must fail id-integrity");
        assert_eq!(
            derive_gate_status(&digest, &[a1.clone(), a2.clone()]).status,
            GateStatus::NeedsVerification,
            "forged-id attachments must not reach Verified"
        );
        let (admit, reasons) = exact_lane_attachment_admit(&digest, &[a1, a2]);
        assert!(!admit, "forged-id pair must never auto-admit");
        assert!(reasons.iter().any(|r| r.contains("G4")
            || r.contains("content-address")
            || r.contains("not Verified")));
    }

    // Attack 1: a vacuous / misformalized statement whose only probe is a
    // CounterexampleSearch. The gate's G3 accepts any survived probe, so it
    // says Verified; auto-admit demands the FormalismFidelity probe.
    #[test]
    fn exact_lane_refuses_without_formalism_fidelity_probe() {
        let digest = claim_digest("claim X");
        // A vacuous/misformalized statement whose only probe is a
        // CounterexampleSearch — built id-valid, no FormalismFidelity probe.
        let a1 = attach_full(
            &digest,
            VerifierMethod::ComputationalSearch,
            "cp-sat",
            vec![],
            vec![surviving_probe()],
            MethodIntegrity::Sound,
            "impl-cp-sat",
        );
        let a2 = attach_full(
            &digest,
            VerifierMethod::ExactArithmeticRecompute,
            "pari-gp",
            vec![a1.id.clone()],
            vec![surviving_probe()],
            MethodIntegrity::Sound,
            "impl-pari",
        );
        assert_eq!(
            derive_gate_status(&digest, &[a1.clone(), a2.clone()]).status,
            GateStatus::Verified,
            "the bare gate tolerates a missing fidelity probe"
        );
        let (admit, reasons) = exact_lane_attachment_admit(&digest, &[a1, a2]);
        assert!(!admit);
        assert!(reasons.iter().any(|r| r.contains("FormalismFidelity")));
    }

    // Attack 2: a Refuted fidelity probe must never auto-admit (it also drives
    // the gate itself to Refuted).
    #[test]
    fn exact_lane_refuses_refuted_formalism_fidelity() {
        let digest = claim_digest("claim X");
        let a1 = attach_full(
            &digest,
            VerifierMethod::ComputationalSearch,
            "cp-sat",
            vec![],
            vec![AdversarialProbe {
                kind: ProbeKind::FormalismFidelity,
                result: ProbeResult::Refuted,
                note: String::new(),
            }],
            MethodIntegrity::Sound,
            "impl-cp-sat",
        );
        let a2 = attach_full(
            &digest,
            VerifierMethod::ExactArithmeticRecompute,
            "pari-gp",
            vec![a1.id.clone()],
            vec![ff_survived()],
            MethodIntegrity::Sound,
            "impl-pari",
        );
        let (admit, reasons) = exact_lane_attachment_admit(&digest, &[a1, a2]);
        assert!(!admit);
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("Refuted") || r.contains("not Verified"))
        );
    }

    // Attack 3: the legacy Unattested integrity default. The gate's G5 only
    // excludes Compromised, so Unattested still drives Verified; auto-admit
    // demands Sound on every matched attachment.
    #[test]
    fn exact_lane_refuses_unattested_integrity() {
        let digest = claim_digest("claim X");
        let a1 = attach_full(
            &digest,
            VerifierMethod::ComputationalSearch,
            "cp-sat",
            vec![],
            vec![ff_survived()],
            MethodIntegrity::Unattested,
            "impl-cp-sat",
        );
        let a2 = attach_full(
            &digest,
            VerifierMethod::ExactArithmeticRecompute,
            "pari-gp",
            vec![a1.id.clone()],
            vec![ff_survived()],
            MethodIntegrity::Sound,
            "impl-pari",
        );
        assert_eq!(
            derive_gate_status(&digest, &[a1.clone(), a2.clone()]).status,
            GateStatus::Verified,
            "the bare gate tolerates Unattested integrity"
        );
        let (admit, reasons) = exact_lane_attachment_admit(&digest, &[a1, a2]);
        assert!(!admit);
        assert!(reasons.iter().any(|r| r.contains("Sound")));
    }

    // Attack 4: a Compromised method (gate excludes it, dropping below 2).
    #[test]
    fn exact_lane_refuses_compromised_method() {
        let digest = claim_digest("claim X");
        let a1 = attach_full(
            &digest,
            VerifierMethod::ComputationalSearch,
            "cp-sat",
            vec![],
            vec![ff_survived()],
            MethodIntegrity::Compromised,
            "impl-cp-sat",
        );
        let a2 = attach_full(
            &digest,
            VerifierMethod::ExactArithmeticRecompute,
            "pari-gp",
            vec![a1.id.clone()],
            vec![ff_survived()],
            MethodIntegrity::Sound,
            "impl-pari",
        );
        let (admit, _r) = exact_lane_attachment_admit(&digest, &[a1, a2]);
        assert!(!admit);
    }

    // Attack 5: NO declared independence at all. One-directional is now the
    // accepted (and only constructable) form, so the refusal case is the
    // absence of any declaration — caught by the gate's G1, inherited via
    // Guard 1. (Mutual independence is a hash circularity; see Guard 4.)
    #[test]
    fn exact_lane_refuses_when_no_independence_declared() {
        let digest = claim_digest("claim X");
        let a1 = attach_full(
            &digest,
            VerifierMethod::ComputationalSearch,
            "cp-sat",
            vec![],
            vec![ff_survived()],
            MethodIntegrity::Sound,
            "impl-cp-sat",
        );
        let a2 = attach_full(
            &digest,
            VerifierMethod::ExactArithmeticRecompute,
            "pari-gp",
            vec![], // neither names the other
            vec![ff_survived()],
            MethodIntegrity::Sound,
            "impl-pari",
        );
        assert_eq!(
            derive_gate_status(&digest, &[a1.clone(), a2.clone()]).status,
            GateStatus::NeedsVerification,
            "no declaration fails the gate's G1"
        );
        let (admit, reasons) = exact_lane_attachment_admit(&digest, &[a1, a2]);
        assert!(!admit);
        assert!(reasons.iter().any(|r| r.contains("independ")));
    }

    // Attack 6: implementation monoculture (N runs of one binary). With
    // genuinely id-valid attachments, a single shared implementation_id trips
    // the gate's own monoculture observation, which (any reason => not Verified)
    // demotes to NeedsVerification — so the refusal arrives via Guard 1 (gate
    // not Verified) carrying the "monoculture" reason, before exact-lane Guard 5
    // is reached. Guard 5 remains as defense-in-depth for any future gate that
    // stops demoting on monoculture.
    #[test]
    fn exact_lane_refuses_implementation_monoculture() {
        let digest = claim_digest("claim X");
        let a1 = attach_full(
            &digest,
            VerifierMethod::ComputationalSearch,
            "cp-sat",
            vec![],
            vec![ff_survived()],
            MethodIntegrity::Sound,
            "same-binary",
        );
        let a2 = attach_full(
            &digest,
            VerifierMethod::ExactArithmeticRecompute,
            "pari-gp",
            vec![a1.id.clone()],
            vec![ff_survived()],
            MethodIntegrity::Sound,
            "same-binary",
        );
        let (admit, reasons) = exact_lane_attachment_admit(&digest, &[a1, a2]);
        assert!(!admit);
        assert!(reasons.iter().any(|r| r.contains("monoculture")));
    }

    // Attack 7: a lone attachment (no independence at all).
    #[test]
    fn exact_lane_refuses_single_attachment() {
        let digest = claim_digest("claim X");
        let (a1, _a2) = admit_pair(&digest);
        let (admit, _r) = exact_lane_attachment_admit(&digest, &[a1]);
        assert!(!admit);
    }

    // Attack 8: claim-digest drift. Attachments bound to a superseded claim
    // must not auto-admit a revised statement.
    #[test]
    fn exact_lane_refuses_on_claim_digest_drift() {
        let digest = claim_digest("claim X");
        let (a1, a2) = admit_pair(&digest);
        let revised = claim_digest("claim X, revised");
        let (admit, _r) = exact_lane_attachment_admit(&revised, &[a1, a2]);
        assert!(
            !admit,
            "attachments bound to the old digest must not admit the revised claim"
        );
    }

    #[test]
    fn accepted_finding_with_zero_attachments_is_needs_verification() {
        // The headline bug class: the reducer may mark a finding
        // `accepted` from a self-reported payload, but with no verifier
        // attachments the GATE derives NeedsVerification, never Verified.
        let digest = claim_digest("a Sidon set of size 33 in [0,256]");
        let outcome = derive_gate_status(&digest, &[]);
        assert_eq!(outcome.status, GateStatus::NeedsVerification);
        assert!(!outcome.is_verified());
    }

    #[test]
    fn single_attachment_fails_g1() {
        let digest = claim_digest("claim X");
        let a = attach(
            &digest,
            VerifierMethod::ComputationalSearch,
            "cp-sat",
            vec![],
            vec![surviving_probe()],
        );
        let outcome = derive_gate_status(&digest, &[a]);
        assert_eq!(outcome.status, GateStatus::NeedsVerification);
        assert!(outcome.reasons.iter().any(|r| r.starts_with("G1")));
    }

    #[test]
    fn two_independent_matched_probed_attachments_verify() {
        let digest = claim_digest("claim X");
        let a1 = attach(
            &digest,
            VerifierMethod::ComputationalSearch,
            "cp-sat",
            vec![],
            vec![surviving_probe()],
        );
        let a2 = attach(
            &digest,
            VerifierMethod::ExactArithmeticRecompute,
            "pari-gp",
            vec![a1.id.clone()],
            vec![surviving_probe()],
        );
        let outcome = derive_gate_status(&digest, &[a1, a2]);
        assert_eq!(
            outcome.status,
            GateStatus::Verified,
            "{:?}",
            outcome.reasons
        );
        assert!(outcome.reasons.is_empty());
    }

    #[test]
    fn undischarged_hypothesis_demotes_to_needs_verification() {
        // The 678 trap: an otherwise-verifying pair, but one attachment proves the
        // claim only under an undischarged hypothesis (a theorem parameter standing
        // for an unproven result). It is sorry-free and `#print axioms`-clean —
        // nothing in G1-G5 catches it — yet the gate must refuse Verified.
        let digest = claim_digest("claim X");
        let a1 = attach(
            &digest,
            VerifierMethod::ComputationalSearch,
            "cp-sat",
            vec![],
            vec![surviving_probe()],
        );
        let a2 = attach(
            &digest,
            VerifierMethod::ExactArithmeticRecompute,
            "lean4@4.29.1",
            vec![a1.id.clone()],
            vec![surviving_probe()],
        )
        .with_undischarged_hypotheses(vec!["h_density : DensityHypothesis".to_string()])
        .unwrap();
        // id still content-addresses the body after the builder mutation (G4).
        assert!(a2.verify().is_ok());
        let outcome = derive_gate_status(&digest, &[a1, a2]);
        assert_eq!(
            outcome.status,
            GateStatus::NeedsVerification,
            "{:?}",
            outcome.reasons
        );
        assert!(
            outcome
                .reasons
                .iter()
                .any(|r| r.contains("conditional") && r.contains("DensityHypothesis")),
            "{:?}",
            outcome.reasons
        );
    }

    #[test]
    fn two_attachments_same_method_fail_independence() {
        let digest = claim_digest("claim X");
        let a1 = attach(
            &digest,
            VerifierMethod::ComputationalSearch,
            "cp-sat",
            vec![],
            vec![surviving_probe()],
        );
        let a2 = attach(
            &digest,
            VerifierMethod::ComputationalSearch,
            "cp-sat",
            vec![a1.id.clone()],
            vec![surviving_probe()],
        );
        let outcome = derive_gate_status(&digest, &[a1, a2]);
        assert_eq!(outcome.status, GateStatus::NeedsVerification);
        assert!(
            outcome
                .reasons
                .iter()
                .any(|r| r.contains("same") || r.contains("one method/solver"))
        );
    }

    #[test]
    fn refuted_probe_drives_refuted() {
        let digest = claim_digest("claim X");
        let refuting = AdversarialProbe {
            kind: ProbeKind::CaseBConfig,
            result: ProbeResult::Refuted,
            note: "Case B breaks it".to_string(),
        };
        let a1 = attach(
            &digest,
            VerifierMethod::ComputationalSearch,
            "cp-sat",
            vec![],
            vec![surviving_probe()],
        );
        let a2 = attach(
            &digest,
            VerifierMethod::LpDualRecompute,
            "pulp-cbc",
            vec![a1.id.clone()],
            vec![refuting],
        );
        let outcome = derive_gate_status(&digest, &[a1, a2]);
        assert_eq!(outcome.status, GateStatus::Refuted);
    }

    #[test]
    fn passed_but_unmatched_does_not_count() {
        let digest = claim_digest("claim X");
        let wrong_digest = claim_digest("a different claim Y");
        // Two passing attachments, but both bound to the wrong claim.
        let a1 = attach(
            &wrong_digest,
            VerifierMethod::ComputationalSearch,
            "cp-sat",
            vec![],
            vec![surviving_probe()],
        );
        let a2 = attach(
            &wrong_digest,
            VerifierMethod::LpDualRecompute,
            "pulp-cbc",
            vec![a1.id.clone()],
            vec![surviving_probe()],
        );
        let outcome = derive_gate_status(&digest, &[a1, a2]);
        assert_eq!(outcome.status, GateStatus::NeedsVerification);
        assert!(outcome.reasons.iter().any(|r| r.starts_with("G2")));
    }

    #[test]
    fn no_probe_fails_g3() {
        let digest = claim_digest("claim X");
        let a1 = attach(
            &digest,
            VerifierMethod::ComputationalSearch,
            "cp-sat",
            vec![],
            vec![],
        );
        let a2 = attach(
            &digest,
            VerifierMethod::LpDualRecompute,
            "pulp-cbc",
            vec![a1.id.clone()],
            vec![],
        );
        let outcome = derive_gate_status(&digest, &[a1, a2]);
        assert_eq!(outcome.status, GateStatus::NeedsVerification);
        assert!(outcome.reasons.iter().any(|r| r.starts_with("G3")));
    }

    #[test]
    fn formalism_fidelity_refuted_drives_refuted() {
        // A FormalismFidelity probe that refutes (statement and negation both
        // provable => misformalized) drives the whole gate to Refuted, so a
        // kernel-clean proof of an unfaithful statement cannot stand.
        let digest = claim_digest("claim X");
        let fidelity_refuted = AdversarialProbe {
            kind: ProbeKind::FormalismFidelity,
            result: ProbeResult::Refuted,
            note: "statement and its negation both provable".to_string(),
        };
        let a1 = attach(
            &digest,
            VerifierMethod::LeanKernel,
            "lean4@4.29.1",
            vec![],
            vec![fidelity_refuted],
        );
        let a2 = attach(
            &digest,
            VerifierMethod::ComputationalSearch,
            "cp-sat",
            vec![a1.id.clone()],
            vec![surviving_probe()],
        );
        let outcome = derive_gate_status(&digest, &[a1, a2]);
        assert_eq!(outcome.status, GateStatus::Refuted);
    }

    #[test]
    fn compromised_attachment_excluded_from_matched() {
        // Two attachments that would otherwise verify, but the second ran a
        // compromised method (e.g. a native_decide Lean proof). It is
        // excluded from the matched set, so the finding falls back to
        // NeedsVerification with a G5 reason — never Verified.
        let digest = claim_digest("claim X");
        let a1 = attach(
            &digest,
            VerifierMethod::ComputationalSearch,
            "cp-sat",
            vec![],
            vec![surviving_probe()],
        );
        let a2 = attach(
            &digest,
            VerifierMethod::LeanKernel,
            "lean4@4.29.1",
            vec![a1.id.clone()],
            vec![surviving_probe()],
        )
        .with_method_integrity(MethodIntegrity::Compromised)
        .unwrap();
        let outcome = derive_gate_status(&digest, &[a1, a2]);
        assert_eq!(outcome.status, GateStatus::NeedsVerification);
        assert!(outcome.reasons.iter().any(|r| r.starts_with("G5")));
        // and it must NOT be misreported as a plain claim mismatch
        assert!(!outcome.reasons.iter().any(|r| r.starts_with("G2")));
    }

    #[test]
    fn sound_attachment_still_verifies() {
        // Regression: explicitly marking integrity Sound on both legs keeps
        // the finding Verified (the field defaults out, ids stay stable).
        let digest = claim_digest("claim X");
        let a1 = attach(
            &digest,
            VerifierMethod::ComputationalSearch,
            "cp-sat",
            vec![],
            vec![surviving_probe()],
        )
        .with_method_integrity(MethodIntegrity::Sound)
        .unwrap();
        let a2 = attach(
            &digest,
            VerifierMethod::LeanKernel,
            "lean4@4.29.1",
            vec![a1.id.clone()],
            vec![surviving_probe()],
        )
        .with_method_integrity(MethodIntegrity::Sound)
        .unwrap();
        let outcome = derive_gate_status(&digest, &[a1, a2]);
        assert_eq!(
            outcome.status,
            GateStatus::Verified,
            "{:?}",
            outcome.reasons
        );
    }

    #[test]
    fn unattested_integrity_serializes_absent_and_id_is_stable() {
        // Legacy-id stability: an Unattested attachment must serialize
        // without a method_integrity key, so a record minted before this
        // field existed re-derives the same vva_ id.
        let digest = claim_digest("claim X");
        let a = attach(
            &digest,
            VerifierMethod::ComputationalSearch,
            "cp-sat",
            vec![],
            vec![surviving_probe()],
        );
        let json = serde_json::to_string(&a).unwrap();
        assert!(
            !json.contains("method_integrity"),
            "default must serialize absent: {json}"
        );
        a.verify().unwrap();
    }

    #[test]
    fn build_is_content_addressed_and_verifies() {
        let digest = claim_digest("claim X");
        let a = attach(
            &digest,
            VerifierMethod::ComputationalSearch,
            "cp-sat",
            vec![],
            vec![surviving_probe()],
        );
        assert!(a.id.starts_with("vva_"));
        a.verify().unwrap();
    }

    #[test]
    fn tampered_id_rejected() {
        let digest = claim_digest("claim X");
        let mut a = attach(
            &digest,
            VerifierMethod::ComputationalSearch,
            "cp-sat",
            vec![],
            vec![surviving_probe()],
        );
        a.solver_id = "totally-different".to_string();
        assert!(a.verify().is_err());
    }

    #[test]
    fn claim_digest_matches_python_rule() {
        // sha256("claim X")[:16] — same as canopus_trust.py.
        let d = claim_digest("  claim X  ");
        assert_eq!(d.len(), 16);
        // trimming is part of the rule
        assert_eq!(d, claim_digest("claim X"));
    }
}
