//! Trusted Computing Base policy (`vtcb_`) for proof-assistant verification.
//!
//! ## The hole this closes
//!
//! A Lean `lake build` succeeding says only that the *elaborator* accepted
//! the term. It says nothing about *which axioms* the proof leaned on. A
//! proof closed by `native_decide` trusts the compiler (`Lean.ofReduceBool`,
//! `Lean.trustCompiler`), not the kernel; a proof with `sorry` carries
//! `sorryAx`. Both type-check and both would, before this module, sail
//! through the gate as `lean_kernel`-verified. That is the single largest
//! reward-hack surface in the verifier leg.
//!
//! ## The fix: a content-addressed axiom policy
//!
//! A [`TcbPolicy`] is the reusable noun naming what a kernel-clean proof is
//! allowed to depend on: an allowlist (the three standard classical axioms),
//! a forbidden list (compiler-trust and `sorry`), the external kernel
//! re-checker, and the toolchain pins. It is content-addressed via
//! [`crate::canonical::sha256_canonical`] (the `vva_` derive-id pattern), so
//! every theorem judged under the same policy references one stable
//! `vtcb_` id, and a change to the policy is visible as a change to that id.
//!
//! [`TcbPolicy::classify`] is the load-bearing check: given the axioms
//! `#print axioms <decl>` reported, it returns whether the proof is
//! kernel-clean, used a forbidden axiom, or used an unlisted one. The
//! per-record axiom result lives on [`crate::lean_verification::LeanVerification`];
//! the policy lives here.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const TCB_SCHEMA: &str = "vela.tcb_policy.v0.1";

/// The standard classical axioms a kernel-clean Lean proof may depend on.
/// Anything outside this set (and anything in [`FORBIDDEN_AXIOMS`]) demotes
/// the proof from kernel-verified.
pub const DEFAULT_ALLOWED_AXIOMS: &[&str] = &["propext", "Classical.choice", "Quot.sound"];

/// Axioms whose presence is an automatic failure regardless of the allowlist.
/// `native_decide` surfaces as `Lean.ofReduceBool` (+ `Lean.trustCompiler`);
/// `sorry` surfaces as `sorryAx`; `decide +kernel := false`/`reduceBool` as
/// `Lean.reduceBool`. These are compiler-trust or proof-holes, never kernel
/// proofs.
pub const FORBIDDEN_AXIOMS: &[&str] = &[
    "sorryAx",
    "Lean.ofReduceBool",
    "Lean.trustCompiler",
    "Lean.reduceBool",
];

/// The verdict of classifying an observed axiom set against a policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AxiomVerdict {
    /// Every observed axiom is in `allowed_axioms` and none is forbidden.
    KernelClean,
    /// At least one observed axiom is in `forbidden_axioms`
    /// (`sorryAx` / `Lean.ofReduceBool` / …). Hard fail.
    ForbiddenAxiom,
    /// No forbidden axiom, but at least one observed axiom is outside the
    /// allowlist (e.g. a custom `axiom` the development introduced).
    /// Compiler-clean but not policy-clean.
    UnlistedAxiom,
}

impl AxiomVerdict {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::KernelClean => "kernel_clean",
            Self::ForbiddenAxiom => "forbidden_axiom",
            Self::UnlistedAxiom => "unlisted_axiom",
        }
    }

    /// True only for [`AxiomVerdict::KernelClean`]. The gate treats every
    /// other verdict as a compromised method.
    #[must_use]
    pub fn is_clean(self) -> bool {
        self == Self::KernelClean
    }
}

/// A content-addressed axiom + kernel-checker policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TcbPolicy {
    pub schema: String,
    /// `vtcb_<16hex>`, derived from the canonical body (id field empty).
    pub tcb_id: String,
    /// Sorted, deduped allowlist of axiom names.
    pub allowed_axioms: Vec<String>,
    /// Sorted, deduped forbidden axiom names.
    pub forbidden_axioms: Vec<String>,
    /// External kernel re-checker, e.g. "lean4checker", "lean4lean", or
    /// "none" when no independent re-check ran.
    pub kernel_checker: String,
    /// Re-checker version pin, e.g. "lean4checker@v4.29.1" ("" when none).
    pub kernel_checker_version: String,
    /// Lean toolchain pin, e.g. "leanprover/lean4:v4.29.1".
    pub lean_toolchain: String,
    /// Mathlib revision (commit or tag).
    pub mathlib_revision: String,
}

/// Fields a caller supplies; schema and id are derived.
#[derive(Debug, Clone)]
pub struct TcbDraft {
    pub allowed_axioms: Vec<String>,
    pub forbidden_axioms: Vec<String>,
    pub kernel_checker: String,
    pub kernel_checker_version: String,
    pub lean_toolchain: String,
    pub mathlib_revision: String,
}

fn sorted_deduped(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v.dedup();
    v
}

impl TcbPolicy {
    /// Build a policy, sorting/deduping the axiom lists and deriving the
    /// content-addressed `vtcb_` id.
    pub fn build(draft: TcbDraft) -> Result<Self, String> {
        let mut policy = TcbPolicy {
            schema: TCB_SCHEMA.to_string(),
            tcb_id: String::new(),
            allowed_axioms: sorted_deduped(draft.allowed_axioms),
            forbidden_axioms: sorted_deduped(draft.forbidden_axioms),
            kernel_checker: draft.kernel_checker,
            kernel_checker_version: draft.kernel_checker_version,
            lean_toolchain: draft.lean_toolchain,
            mathlib_revision: draft.mathlib_revision,
        };
        policy.tcb_id = policy.derive_id()?;
        Ok(policy)
    }

    /// The canonical default policy: the three classical axioms allowed, the
    /// standard compiler-trust/`sorry` set forbidden, pinned to the given
    /// toolchain/mathlib/checker.
    pub fn default_for(
        lean_toolchain: &str,
        mathlib_revision: &str,
        kernel_checker: &str,
        kernel_checker_version: &str,
    ) -> Result<Self, String> {
        Self::build(TcbDraft {
            allowed_axioms: DEFAULT_ALLOWED_AXIOMS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            forbidden_axioms: FORBIDDEN_AXIOMS.iter().map(|s| (*s).to_string()).collect(),
            kernel_checker: kernel_checker.to_string(),
            kernel_checker_version: kernel_checker_version.to_string(),
            lean_toolchain: lean_toolchain.to_string(),
            mathlib_revision: mathlib_revision.to_string(),
        })
    }

    /// Re-derive the content-addressed id from the canonical body with the
    /// id field zeroed (the `vva_` pattern).
    pub fn derive_id(&self) -> Result<String, String> {
        let mut preimage = self.clone();
        preimage.tcb_id = String::new();
        let bytes = crate::canonical::to_canonical_bytes(&preimage)
            .map_err(|e| format!("canonicalize tcb policy preimage: {e}"))?;
        let digest = Sha256::digest(&bytes);
        Ok(format!("vtcb_{}", &hex::encode(digest)[..16]))
    }

    /// Schema, id prefix, and id integrity.
    pub fn verify(&self) -> Result<(), String> {
        if self.schema != TCB_SCHEMA {
            return Err(format!(
                "tcb.schema must be `{TCB_SCHEMA}`, got `{}`",
                self.schema
            ));
        }
        if !self.tcb_id.starts_with("vtcb_") {
            return Err(format!(
                "tcb id must start with `vtcb_`, got `{}`",
                self.tcb_id
            ));
        }
        let derived = self.derive_id()?;
        if derived != self.tcb_id {
            return Err(format!(
                "tcb id mismatch: stored `{}`, derived `{}`",
                self.tcb_id, derived
            ));
        }
        Ok(())
    }

    /// Classify an observed axiom set against this policy.
    ///
    /// Forbidden axioms take precedence (a `sorryAx` proof that also uses
    /// `propext` is still [`AxiomVerdict::ForbiddenAxiom`]). Then any axiom
    /// outside the allowlist yields [`AxiomVerdict::UnlistedAxiom`]; an empty
    /// or fully-allowed set is [`AxiomVerdict::KernelClean`].
    #[must_use]
    pub fn classify(&self, observed_axioms: &[String]) -> AxiomVerdict {
        if observed_axioms
            .iter()
            .any(|a| self.forbidden_axioms.iter().any(|f| f == a))
        {
            return AxiomVerdict::ForbiddenAxiom;
        }
        if observed_axioms
            .iter()
            .any(|a| !self.allowed_axioms.iter().any(|allowed| allowed == a))
        {
            return AxiomVerdict::UnlistedAxiom;
        }
        AxiomVerdict::KernelClean
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_policy() -> TcbPolicy {
        TcbPolicy::default_for(
            "leanprover/lean4:v4.29.1",
            "v4.29.1",
            "lean4checker",
            "lean4checker@v4.29.1",
        )
        .expect("build default policy")
    }

    #[test]
    fn allowlist_parse_roundtrips_and_sorts() {
        let p = TcbPolicy::build(TcbDraft {
            allowed_axioms: vec!["Quot.sound".into(), "propext".into(), "propext".into()],
            forbidden_axioms: vec!["sorryAx".into()],
            kernel_checker: "none".into(),
            kernel_checker_version: String::new(),
            lean_toolchain: "leanprover/lean4:v4.29.1".into(),
            mathlib_revision: "v4.29.1".into(),
        })
        .unwrap();
        assert_eq!(p.allowed_axioms, vec!["Quot.sound", "propext"]); // sorted + deduped
    }

    #[test]
    fn classify_kernel_clean() {
        let p = default_policy();
        let observed = vec!["propext".to_string(), "Classical.choice".to_string()];
        assert_eq!(p.classify(&observed), AxiomVerdict::KernelClean);
    }

    #[test]
    fn classify_empty_is_kernel_clean() {
        let p = default_policy();
        assert_eq!(p.classify(&[]), AxiomVerdict::KernelClean);
    }

    #[test]
    fn classify_rejects_native_decide() {
        // The load-bearing reject-vector: native_decide surfaces as
        // Lean.ofReduceBool (+ Lean.trustCompiler) and must be ForbiddenAxiom.
        let p = default_policy();
        let observed = vec![
            "Lean.ofReduceBool".to_string(),
            "Lean.trustCompiler".to_string(),
        ];
        assert_eq!(p.classify(&observed), AxiomVerdict::ForbiddenAxiom);
    }

    #[test]
    fn classify_rejects_sorry() {
        let p = default_policy();
        assert_eq!(
            p.classify(&["sorryAx".to_string()]),
            AxiomVerdict::ForbiddenAxiom
        );
    }

    #[test]
    fn classify_forbidden_beats_allowed() {
        let p = default_policy();
        let observed = vec!["propext".to_string(), "sorryAx".to_string()];
        assert_eq!(p.classify(&observed), AxiomVerdict::ForbiddenAxiom);
    }

    #[test]
    fn classify_unlisted() {
        let p = default_policy();
        assert_eq!(
            p.classify(&["MyDev.customAxiom".to_string()]),
            AxiomVerdict::UnlistedAxiom
        );
    }

    #[test]
    fn tcb_id_is_content_addressed_and_verifies() {
        let p = default_policy();
        assert!(p.tcb_id.starts_with("vtcb_"));
        p.verify().unwrap();
    }

    #[test]
    fn tcb_id_changes_with_allowlist() {
        let p1 = default_policy();
        let p2 = TcbPolicy::build(TcbDraft {
            allowed_axioms: vec!["propext".into()], // narrower
            forbidden_axioms: FORBIDDEN_AXIOMS.iter().map(|s| (*s).to_string()).collect(),
            kernel_checker: "lean4checker".into(),
            kernel_checker_version: "lean4checker@v4.29.1".into(),
            lean_toolchain: "leanprover/lean4:v4.29.1".into(),
            mathlib_revision: "v4.29.1".into(),
        })
        .unwrap();
        assert_ne!(p1.tcb_id, p2.tcb_id);
    }

    #[test]
    fn tampered_policy_fails_verify() {
        let mut p = default_policy();
        p.allowed_axioms.push("sorryAx".to_string());
        assert!(p.verify().is_err());
    }
}
