import Vela.Protocol.Core

/-!
# Frontier calculus v2: the graded status is a conservative extension

Mathlib-free, building only on `Vela.Core`. The v2 status is a point in the
graded bilattice `[0,1] ⊙ [0,1]`; its corner -- thresholding each coordinate at
`> 0` -- reproduces the v1 Belnap `deriveStatus` exactly, for every positive
per-source confidence assignment. This is the *machine-checked* form of the
conservative-extension theorem the Rust and Python kernels otherwise only test
on fixtures (`frontier_calculus.rs::graded_status_corner_is_conservative_over_v1`,
`frontier_calculus_kernel.py` check 20).

`kappa` is modelled over `ℕ` (a positive confidence is `≥ 1`): the conservativity
argument turns only on *positivity*, so `ℕ` suffices and keeps this file
dependency-free, provable in seconds by `lake env lean Vela/FrontierCalculus.lean`.
-/

namespace Vela.FrontierCalculus

open Vela.Core

/-- The weight of one monomial under a confidence valuation: the product of its
    variables' confidences (the empty monomial weighs `1`). The Viterbi `·`. -/
def monoWeight (conf : Nat → Nat) (m : List Nat) : Nat :=
  m.foldr (fun x acc => conf x * acc) 1

/-- `kappa`: the best-derivation weight = the max over monomials of `monoWeight`
    (the empty polynomial weighs `0`). The positivity skeleton of the Viterbi
    projection: `max` selects the best alternative, `·` contracts along a chain. -/
def kappa (conf : Nat → Nat) (p : Poly) : Nat :=
  p.foldr (fun m acc => Nat.max (monoWeight conf m) acc) 0

/-- A monomial's weight is positive when every confidence is positive. -/
theorem monoWeight_pos {conf : Nat → Nat} (hconf : ∀ x, 0 < conf x) (m : List Nat) :
    0 < monoWeight conf m := by
  induction m with
  | nil => exact Nat.one_pos
  | cons x xs ih => exact Nat.mul_pos (hconf x) ih

/-- **`kappa` positivity tracks support.** With every confidence positive, the
    `kappa` coordinate is positive iff the polynomial has any derivation. -/
theorem kappa_pos_iff {conf : Nat → Nat} (hconf : ∀ x, 0 < conf x) (p : Poly) :
    0 < kappa conf p ↔ p ≠ [] := by
  cases p with
  | nil => simp [kappa]
  | cons m rest =>
      have hm : 0 < monoWeight conf m := monoWeight_pos hconf m
      have : 0 < kappa conf (m :: rest) :=
        Nat.lt_of_lt_of_le hm (Nat.le_max_left _ _)
      simp [this]

/-- `decide (0 < kappa …)` is exactly the v2 support reading `!p.isEmpty`
    (the kernel's `derive_status = !is_zero`). -/
theorem kappa_decide_eq_nonempty {conf : Nat → Nat} (hconf : ∀ x, 0 < conf x)
    (p : Poly) : decide (0 < kappa conf p) = !p.isEmpty := by
  cases p with
  | nil => simp [kappa]
  | cons m rest =>
      have : 0 < kappa conf (m :: rest) := (kappa_pos_iff hconf _).mpr (by simp)
      simp [this]

/-- The graded bilattice corner: threshold each `kappa` coordinate at `> 0`. -/
def corner (kT kF : Nat) : Status :=
  deriveStatus (decide (0 < kT)) (decide (0 < kF))

/-- **Conservative extension (machine-checked).** The corner of the v2 graded
    status reproduces the v1 Belnap `deriveStatus` for EVERY positive confidence
    assignment: thresholding each `kappa` coordinate at `> 0` recovers exactly the
    polarity of "the polynomial has a derivation". v1 readers are provably
    unaffected -- the graded layer adds resolution, never changes the corner. -/
theorem graded_corner_conservative {conf : Nat → Nat} (hconf : ∀ x, 0 < conf x)
    (piT piF : Poly) :
    corner (kappa conf piT) (kappa conf piF)
      = deriveStatus (!piT.isEmpty) (!piF.isEmpty) := by
  unfold corner
  rw [kappa_decide_eq_nonempty hconf piT, kappa_decide_eq_nonempty hconf piF]

/-- **Retraction lowers the degree.** Retracting an assumption set can only lower
    the `kappa` coordinate (it deletes monomials; the max over a sub-family is no
    larger). This is the `sigma`/`kappa` asymmetry's safe direction: support never
    silently rises under retraction. -/
theorem kappa_retract_le (conf : Nat → Nat) (Y : Nat → Bool) (p : Poly) :
    kappa conf (retract Y p) ≤ kappa conf p := by
  induction p with
  | nil => simp [retract, kappa]
  | cons m rest ih =>
      by_cases h : m.all (fun x => ! Y x)
      · -- m survives retraction: head kept, tail by ih
        simp only [retract, List.filter_cons, h, kappa, List.foldr_cons]
        exact Nat.max_le.mpr ⟨Nat.le_max_left _ _, Nat.le_trans ih (Nat.le_max_right _ _)⟩
      · -- m is dropped: kappa (retract rest) ≤ kappa rest ≤ kappa (m :: rest)
        simp only [retract, List.filter_cons, h, kappa, List.foldr_cons]
        exact Nat.le_trans ih (Nat.le_max_right _ _)

/-- Sanity (computational): the support polynomial `x1·x2 + x3` has positive
    `kappa` under the all-ones confidence, and its corner is `true_`. -/
example : corner (kappa (fun _ => 1) [[1, 2], [3]]) (kappa (fun _ => 1) []) = Status.true_ := by
  decide

/-! ## v3 correction: bag provenance vs environment provenance

The v2 memo grouped `kappa` under "every projection is an `Eval_v` homomorphism
from `N[X]`", then footnoted that `kappa` is only *lax* on shared products
(`kappa (x·x) = v(x)`, not `v(x)^2`). The v3 fix (independent GPT-pro review,
2026-06-14) stops reading `kappa` off raw `N[X]` and splits two canonical layers:

  * `BagProv = N[X]`     keeps multiplicity  -> counting / attribution
  * `EnvProv = Env(p)`   forgets exponents   -> kappa / retraction / attack-locality

`Env(p)` is the square-free image: each monomial becomes its *set* of assumptions.
On that quotient `kappa` is exact, not lax: a product of monomials is the *union*
of their assumption sets, and a variable in a union is multiplied once. The four
results below discharge the correction -- the quotient is support-multiplicative
(the env homomorphism, T4); the square-free collapse is a theorem, not a footnote;
positivity is unchanged so the corner law (Theorem 20) survives verbatim on the
corrected kappa; and counting (bag) is provably distinct from kappa (env), so
shared evidence is never silently double-counted (T13, kappa non-collapse). -/

/-- Forget multiplicity: keep one copy of each assumption. `nodup m` is the
    square-free image of a monomial -- its assumption *set*. Mathlib-free. -/
def nodup : List Nat → List Nat
  | [] => []
  | x :: xs => if x ∈ xs then nodup xs else x :: nodup xs

/-- The square-free image has the same assumptions as the original (set equality
    at the membership level). -/
theorem mem_nodup (x : Nat) : ∀ m : List Nat, x ∈ nodup m ↔ x ∈ m := by
  intro m
  induction m with
  | nil => simp [nodup]
  | cons y ys ih =>
      rw [List.mem_cons]
      by_cases h : y ∈ ys
      · simp only [nodup, if_pos h, ih]
        constructor
        · exact Or.inr
        · rintro (rfl | hx)
          · exact h
          · exact hx
      · simp only [nodup, if_neg h, List.mem_cons, ih]

/-- The environment weight of a monomial: the product of confidences over its
    assumption *set* (square-free). This is `kappa`'s Viterbi product read on
    `EnvProv`, where a shared assumption is multiplied once. -/
def envWeight (conf : Nat → Nat) (m : List Nat) : Nat := monoWeight conf (nodup m)

/-- **The square-free collapse is a theorem.** A repeated assumption contributes
    once. This is exactly the statement that *fails* for raw `monoWeight` over
    `N[X]` and *holds* on the environment quotient -- the v2 "lax" footnote, made
    precise and located at the right layer. -/
theorem envWeight_idem (conf : Nat → Nat) (x : Nat) (xs : List Nat) :
    envWeight conf (x :: x :: xs) = envWeight conf (x :: xs) := by
  simp [envWeight, nodup]

/-- **T4 (environment quotient is support-multiplicative).** The assumption set of
    a product monomial `m1·m2 = m1 ++ m2` is the union of the two assumption sets:
    exponents are forgotten and shared assumptions merge rather than accumulate.
    This is the multiplicativity of the quotient `env : N[X] -> EnvProv`. -/
theorem env_mul_support (m1 m2 : List Nat) (x : Nat) :
    x ∈ nodup (m1 ++ m2) ↔ x ∈ nodup m1 ∨ x ∈ nodup m2 := by
  rw [mem_nodup, mem_nodup, mem_nodup, List.mem_append]

/-- `kappa` evaluated on the environment quotient (`EnvProv`): the max over
    monomials of the square-free `envWeight`. This is the v3 home for `kappa`. -/
def kappaEnv (conf : Nat → Nat) (p : Poly) : Nat :=
  p.foldr (fun m acc => Nat.max (envWeight conf m) acc) 0

/-- `envWeight` is positive whenever every confidence is (the set-product of
    positives is positive). -/
theorem envWeight_pos {conf : Nat → Nat} (hconf : ∀ x, 0 < conf x) (m : List Nat) :
    0 < envWeight conf m := monoWeight_pos hconf (nodup m)

/-- The corrected `kappaEnv` still tracks support: positive iff there is a
    derivation. (So the layer change does not disturb the corner.) -/
theorem kappaEnv_pos_iff {conf : Nat → Nat} (hconf : ∀ x, 0 < conf x) (p : Poly) :
    0 < kappaEnv conf p ↔ p ≠ [] := by
  cases p with
  | nil => simp [kappaEnv]
  | cons m rest =>
      have : 0 < kappaEnv conf (m :: rest) :=
        Nat.lt_of_lt_of_le (envWeight_pos hconf m) (Nat.le_max_left _ _)
      simp [this]

/-- **Conservativity survives the correction.** The graded corner taken on the
    environment-quotient `kappaEnv` still reproduces the v1 Belnap `deriveStatus`
    for every positive confidence -- Theorem 20 is robust to moving `kappa` to its
    proper layer. -/
theorem graded_corner_conservative_env {conf : Nat → Nat} (hconf : ∀ x, 0 < conf x)
    (piT piF : Poly) :
    corner (kappaEnv conf piT) (kappaEnv conf piF)
      = deriveStatus (!piT.isEmpty) (!piF.isEmpty) := by
  have d : ∀ p : Poly, decide (0 < kappaEnv conf p) = !p.isEmpty := by
    intro p
    cases p with
    | nil => simp [kappaEnv]
    | cons m rest =>
        have : 0 < kappaEnv conf (m :: rest) := (kappaEnv_pos_iff hconf _).mpr (by simp)
        simp [this]
  unfold corner
  rw [d piT, d piF]

/-- **T13 (kappa non-collapse).** Counting (bag, with multiplicity) and `kappa`
    (env, square-free) are genuinely different projections: a doubled assumption
    weighs `v(x)^2` under counting but `v(x)` under `kappa`. Shared evidence is
    never silently promoted to independent support. -/
example : monoWeight (fun _ => 2) [0, 0] ≠ envWeight (fun _ => 2) [0, 0] := by decide

/-! ## v3: the context wall

The scope wall (substrate Theorem 7 / memo section 21) is algebraic: positive
derivations commute with semiring projection, while negation, aggregation, and
recursion do not. The context wall is its scientific-safety twin: no support may
move from one context to another without an explicit *licensed* rule (restriction,
generalization, transfer, faithfulness, transport). It is what stops

    mouse model        -> human claim
    formal variant     -> named problem solved
    cell assay         -> clinical therapeutic claim
    benchmark result   -> real-world capability
    semantic replay    -> bitwise replay

from happening silently. Model: support carries a context. In-context derivation
(`derive`) is context-preserving by construction; the only constructor that
advances the context is `transfer`, and it demands a licensed `move c d`. The
confinement theorem then certifies that the context of any supported claim is
reachable from its origin along a chain of licensed moves -- so a context with no
licensed path from the origin can hold no support. -/

/-- Reflexive-transitive closure of a relation (Mathlib-free). -/
inductive RTC {α : Type} (r : α → α → Prop) : α → α → Prop
  | refl (a : α) : RTC r a a
  | tail {a b c : α} : RTC r a b → r b c → RTC r a c

/-- Context-tagged support reachable from origin `o`. `move c d` is the
    licensed-rule relation -- the only sanctioned way to change context.
    `derive` stands for arbitrary in-context work and is context-preserving. -/
inductive Reach {C : Type} (move : C → C → Prop) (o : C) : C → Prop
  | here : Reach move o o
  | derive {c : C} : Reach move o c → Reach move o c
  | transfer {c d : C} : Reach move o c → move c d → Reach move o d

/-- **The context wall (confinement).** The context of any supported claim is
    reachable from its origin along a chain of *licensed* moves. In-context
    derivation never moves the context; only `transfer` through `move` does. -/
theorem context_confined {C : Type} (move : C → C → Prop) (o c : C)
    (h : Reach move o c) : RTC move o c := by
  induction h with
  | here => exact RTC.refl o
  | derive _ ih => exact ih
  | transfer _ hmove ih => exact RTC.tail ih hmove

/-- **No silent context jump.** If no licensed rule-chain reaches context `d`
    from the origin, no support reaches `d`. The contrapositive that makes the
    wall a safety property: a cross-context claim requires a rule. -/
theorem no_silent_context_jump {C : Type} (move : C → C → Prop) (o d : C)
    (h : ¬ RTC move o d) : ¬ Reach move o d :=
  fun hr => h (context_confined move o d hr)

/-- With no licensed moves at all, support is confined to its origin context:
    `mouse -> human` (and every other unlicensed jump) is blocked. -/
theorem confined_when_no_moves {C : Type} (o c : C)
    (h : Reach (fun _ _ => False) o c) : c = o := by
  induction h with
  | here => rfl
  | derive _ ih => exact ih
  | transfer _ hmove _ => exact hmove.elim

/-! ## v3: transfer closure is a least fixed point (order-independent)

v2 fixed second-order transfer cascades (`A` supports `B`, `B` supports `C`, so
`A` supports `C`) by iterating the reducer to a fixpoint rather than trusting
event-id sort order -- but left that as an implementation footnote. v3 promotes
it to a theorem: the transfer closure is the *least fixed point* of the positive
transfer rule above the seed, and a least fixed point is unique, so the order in
which events are folded cannot change the result.

`Closure` is defined inductively, hence order-free by construction. The two
theorems certify it is genuinely the least fixed point (`closure_least`) and that
*any* least fixed point of the same rule coincides with it (`transfer_closure_order_independent`)
-- so two folds in different orders that both reach a fixed point above the seed
compute the same support set. -/

/-- The transfer closure: the least set containing the seed and closed under the
    positive transfer rule `move`. `seed` = directly-supported claims; `move c d`
    = "a licensed transfer carries support from `c` to `d`". -/
inductive Closure {C : Type} (seed : C → Prop) (move : C → C → Prop) : C → Prop
  | seed {c : C} : seed c → Closure seed move c
  | step {c d : C} : Closure seed move c → move c d → Closure seed move d

/-- **`Closure` is the least fixed point.** Any predicate `P` that contains the
    seed and is closed under the transfer rule already contains the whole closure.
    (The closure is itself a fixed point: `Closure.step` is exactly closure under
    `move`.) -/
theorem closure_least {C : Type} (seed : C → Prop) (move : C → C → Prop)
    (P : C → Prop) (hseed : ∀ c, seed c → P c)
    (hstep : ∀ c d, P c → move c d → P d) :
    ∀ c, Closure seed move c → P c := by
  intro c h
  induction h with
  | seed hc => exact hseed _ hc
  | step _ hmove ih => exact hstep _ _ ih hmove

/-- **Transfer closure is order-independent.** Any set `S` that is *also* a least
    fixed point of the transfer rule above the seed (closed under the rule, and
    minimal among such sets) coincides with `Closure`. Since a fold to a fixed
    point above the seed lands on a least fixed point regardless of event order,
    every order computes the same transferred support. -/
theorem transfer_closure_order_independent {C : Type} (seed : C → Prop)
    (move : C → C → Prop) (S : C → Prop)
    (hSseed : ∀ c, seed c → S c) (hSstep : ∀ c d, S c → move c d → S d)
    (hSleast : ∀ (P : C → Prop), (∀ c, seed c → P c) →
      (∀ c d, P c → move c d → P d) → ∀ c, S c → P c) :
    ∀ c, S c ↔ Closure seed move c := by
  intro c
  constructor
  · exact hSleast (Closure seed move) (fun _ => Closure.seed) (fun _ _ => Closure.step) c
  · exact closure_least seed move S hSseed hSstep c

end Vela.FrontierCalculus
