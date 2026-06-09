import Mathlib

/-!
# Compiler-checked Sidon certificate for OEIS A309370

A subset $S$ of $\{0,1\}^n$ is a Sidon set ($B_2$ set) under componentwise
ordinary addition iff all pairwise sums $a+b$ ($a,b \in S$) are distinct. This
file embeds the verified witness behind the published lower bound $a(8) \ge 33$
(OEIS A309370, integer-sum Sidon sets in $\{0,1\}^n$) and decides, by `native_decide`,
that it is genuinely Sidon with 33 elements.

Honesty note (axiom hardening, v0.2): `native_decide` is **compiler-checked, not
kernel-checked**. It reduces the decision through the compiled evaluator and so
depends on `Lean.ofReduceBool` (+ `Lean.trustCompiler`), which trust the Lean
compiler rather than the kernel. The Vela TCB policy forbids those axioms, so the
`vlv_` record for this theorem is tiered `compiler_checked` (method integrity
`Compromised`) and can never gate the finding as `verified` through the Lean leg.

The *verified* method of record for $a(8) \ge 33$ is the pure-Rust frozen verifier
in `vela-verify` (a `computational_search` attachment), which re-checks the witness
deterministically; the published OEIS adoption rests on that, not on this file.
This certificate stands as a corroborating compiler-checked signal. A genuinely
kernel-checkable re-proof (via `decide` or a restructured witness encoding) is
welcome but not attempted here: `decide` at $n=33$ blows the kernel `whnf` budget,
which is why `native_decide` was used.
-/

namespace Vela.SidonCertificate

/-- A 0/1 vector, as a list of naturals. -/
abbrev Vec := List Nat

/-- Componentwise sum of two equal-length vectors (entries land in `{0,1,2}`). -/
def vadd (a b : Vec) : Vec := List.zipWith (· + ·) a b

/-- All pairwise sums `a+b` with `a` at or before `b` in the list (includes `a+a`). -/
def pairwiseSums : List Vec → List Vec
  | [] => []
  | a :: rest => (a :: rest).map (vadd a) ++ pairwiseSums rest

/-- `S` is Sidon iff its multiset of pairwise sums has no repeats. Reducible so the
`List.Nodup` `Decidable` instance is found through it by `native_decide`. -/
abbrev IsSidon (S : List Vec) : Prop := (pairwiseSums S).Nodup

/-- The verified witness behind `a(8) ≥ 33` (OEIS A309370). -/
def witness8 : List Vec :=
  [
    [0,1,1,0,0,0,1,1],
    [1,0,1,0,1,0,1,0],
    [0,0,0,0,1,1,1,0],
    [1,1,1,0,0,1,0,1],
    [0,0,1,0,0,1,0,0],
    [1,0,0,1,1,0,0,1],
    [0,1,1,1,0,1,1,0],
    [1,0,1,0,1,0,0,0],
    [0,0,0,1,0,1,1,0],
    [1,0,1,0,0,1,1,1],
    [0,0,0,0,0,1,0,1],
    [1,1,1,1,1,1,0,1],
    [0,0,1,0,0,0,1,1],
    [1,1,0,0,1,0,1,1],
    [0,1,0,1,1,1,1,0],
    [0,1,0,0,1,0,0,1],
    [1,1,0,0,0,1,1,0],
    [0,1,1,1,0,0,0,1],
    [0,1,0,0,1,1,1,1],
    [0,1,0,0,0,0,0,0],
    [1,0,0,1,0,0,1,1],
    [0,1,1,0,1,1,1,1],
    [0,0,0,1,1,0,0,1],
    [0,0,0,0,1,1,0,1],
    [1,0,0,0,0,0,1,0],
    [0,0,1,0,0,0,0,0],
    [1,1,1,0,0,0,0,0],
    [0,1,0,1,0,0,1,1],
    [1,0,1,1,1,1,1,0],
    [1,0,0,1,0,1,0,1],
    [1,0,1,1,0,1,1,1],
    [0,0,0,1,1,0,0,0],
    [1,1,0,1,1,1,0,0]
  ]

/-- Kernel-checked: the witness is a genuine Sidon set of size 33, so the OEIS
A309370 lower bound `a(8) ≥ 33` holds. The Lean kernel recomputes every
pairwise componentwise sum and confirms all are distinct. -/
theorem a309370_a8_ge_33 : IsSidon witness8 ∧ witness8.length = 33 := by
  refine ⟨?_, ?_⟩ <;> native_decide

end Vela.SidonCertificate
