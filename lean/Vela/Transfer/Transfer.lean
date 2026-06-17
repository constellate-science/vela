/-!
# Vela Theorem 23: cross-frontier transfer soundness (the constellation layer)

The substrate theorems (`Vela.Provenance`: T2, T3, T4) are SINGLE-frontier. This file adds the
CONSTELLATION layer: the formal relation BETWEEN frontiers, which is Vela's distinctive edge
(discoveries that live in the connections, invisible to single-frontier search).

A frontier exposes a type of candidate objects and a `verified` predicate -- its frozen verifier.
A TRANSFER between frontiers is a map that PRESERVES verification: a *verifier-homomorphism*. Two
guarantees:

* **Theorem 23 (cross-frontier transfer soundness)** `transfer_sound`: a verified object in `A` transfers to a
  verified object in `B`.
* **Frontiers + transfers form a category** (`Transfer.id`, `Transfer.comp`), so transfers chain;
  a path of bridges composes into one transfer.

Real instances produced this session (the empirical grounding, not metaphor):
* Sidon (B_2) sets `{0,1}^n`  →  B_h sets  (the packed-encoding map; verifier = `verify_bh`).
* the `[8,4,4]` extended Hamming code  →  the E8 kissing configuration (Construction A; verifier
  = `verify_kissing`), which reproduced the proven optimum `K(8)=240`.

This is NOT new mathematics -- it is a category of objects-with-verifiers and verification-preserving
maps. The contribution is that it is the formal specification of the cross-frontier moat, and it is
machine-checked. It is deliberately Mathlib-free so it compiles standalone.
-/

namespace Vela

universe u v w

/-- A frontier: a type of candidate objects together with a frozen verification predicate. -/
structure Frontier where
  Obj : Type u
  verified : Obj → Prop

/-- A transfer between frontiers is a verifier-homomorphism: a map of candidate objects that
    sends verified objects to verified objects. -/
structure Transfer (A B : Frontier) where
  toFun : A.Obj → B.Obj
  sound : ∀ o : A.Obj, A.verified o → B.verified (toFun o)

/-- **Theorem 23 (cross-frontier transfer soundness).** A verified object in `A` transfers, along any
    verifier-homomorphism `T : A → B`, to a verified object in `B`. -/
theorem transfer_sound {A B : Frontier} (T : Transfer A B)
    {o : A.Obj} (h : A.verified o) : B.verified (T.toFun o) :=
  T.sound o h

/-- The identity transfer (every object to itself; verification preserved trivially). -/
def Transfer.id (A : Frontier) : Transfer A A where
  toFun := fun o => o
  sound := fun _ h => h

/-- Transfers compose: a verifier-homomorphism `A → B` followed by `B → C` is a
    verifier-homomorphism `A → C`. With `Transfer.id` this makes frontiers a category. -/
def Transfer.comp {A B C : Frontier} (S : Transfer A B) (T : Transfer B C) : Transfer A C where
  toFun := fun o => T.toFun (S.toFun o)
  sound := fun o h => T.sound _ (S.sound o h)

/-- Composition of transfers is function composition on objects (functoriality on objects). -/
@[simp] theorem Transfer.comp_toFun {A B C : Frontier}
    (S : Transfer A B) (T : Transfer B C) (o : A.Obj) :
    (S.comp T).toFun o = T.toFun (S.toFun o) := rfl

/-- Identity is a left unit for composition (on objects). -/
@[simp] theorem Transfer.id_comp {A B : Frontier} (T : Transfer A B) (o : A.Obj) :
    ((Transfer.id A).comp T).toFun o = T.toFun o := rfl

/-- Identity is a right unit for composition (on objects). -/
@[simp] theorem Transfer.comp_id {A B : Frontier} (T : Transfer A B) (o : A.Obj) :
    (T.comp (Transfer.id B)).toFun o = T.toFun o := rfl

/-- Composition is associative (on objects). -/
@[simp] theorem Transfer.comp_assoc {A B C D : Frontier}
    (R : Transfer A B) (S : Transfer B C) (T : Transfer C D) (o : A.Obj) :
    ((R.comp S).comp T).toFun o = (R.comp (S.comp T)).toFun o := rfl

/-- **Frontier reduction along a transfer.** Model a frontier question as a predicate `q` on
    `B`'s objects together with the demand that it be witnessed by a verified object. If a verified
    object in `A` transfers to a `B`-object satisfying `q`, then `q` is *closed*: a verified witness
    for it exists. (This is how a resolved finding in one frontier removes discord in a connected
    one.) -/
theorem transfer_closes {A B : Frontier} (T : Transfer A B)
    (q : B.Obj → Prop) {o : A.Obj}
    (h : A.verified o) (hq : q (T.toFun o)) :
    ∃ b : B.Obj, B.verified b ∧ q b :=
  ⟨T.toFun o, transfer_sound T h, hq⟩

/-- Sanity: the constellation is non-vacuous -- every frontier has at least the identity transfer,
    and transfer soundness fires on it. -/
example (A : Frontier) {o : A.Obj} (h : A.verified o) :
    A.verified ((Transfer.id A).toFun o) := transfer_sound (Transfer.id A) h

/-! ## A concrete transfer with genuine (non-definitional) soundness

`transfer_sound` above is the *contract* (definitional). To show the constellation layer carries
real content -- not an axiom over an opaque reducer, the failure mode audited out of the descriptor
theorems -- here is a fully-proven verifier-homomorphism between two genuine combinatorial frontiers.
The soundness proof is a real argument (membership unfolding + arithmetic): no `axiom`, no `opaque`,
no `sorry`. -/

/-- A Sidon set over `List Nat`: every coincidence of pairwise sums comes from the same pair. -/
def SidonList (S : List Nat) : Prop :=
  ∀ a ∈ S, ∀ b ∈ S, ∀ c ∈ S, ∀ d ∈ S, a + b = c + d → (a = c ∧ b = d) ∨ (a = d ∧ b = c)

/-- The integer-Sidon frontier. -/
def sidonFrontier : Frontier := { Obj := List Nat, verified := SidonList }

/-- Translation preserves the Sidon property -- a genuine, computed soundness lemma. -/
theorem sidon_translate_sound (t : Nat) {S : List Nat} (h : SidonList S) :
    SidonList (S.map (· + t)) := by
  intro a ha b hb c hc d hd hsum
  rw [List.mem_map] at ha hb hc hd
  obtain ⟨a', ha', rfl⟩ := ha
  obtain ⟨b', hb', rfl⟩ := hb
  obtain ⟨c', hc', rfl⟩ := hc
  obtain ⟨d', hd', rfl⟩ := hd
  have hsum' : a' + b' = c' + d' := by omega
  rcases h a' ha' b' hb' c' hc' d' hd' hsum' with ⟨h1, h2⟩ | ⟨h1, h2⟩
  · exact Or.inl ⟨by omega, by omega⟩
  · exact Or.inr ⟨by omega, by omega⟩

/-- Translation by `t` is a concrete verifier-homomorphism on the Sidon frontier: a transfer whose
    `sound` field is a real theorem, not an axiom. The constellation layer with content. -/
def translateTransfer (t : Nat) : Transfer sidonFrontier sidonFrontier where
  toFun := fun S => S.map (· + t)
  sound := fun _ h => sidon_translate_sound t h

/-- Transfer soundness fires on it with genuine content: translating a verified Sidon set yields a
    verified Sidon set. -/
example {S : List Nat} (h : SidonList S) (t : Nat) :
    sidonFrontier.verified ((translateTransfer t).toFun S) :=
  transfer_sound (translateTransfer t) h

/-! ## A second, genuinely CROSS-frontier transfer (distinct sums ⇄ distinct differences)

The translation transfer above stays inside one frontier. Here are two *different* combinatorial
frontiers bridged by a proven verifier-homomorphism — the kind of bridge the moat theorem
(`Vela/HeteroAccumulation.lean`) consumes. A **Golomb ruler** is a set whose pairwise *differences*
are distinct; written additively (to avoid `Nat` truncated subtraction), `a - b = c - d` becomes
`a + d = b + c`. The classical fact is that distinct-sums and distinct-differences are the *same*
condition on a set. We prove both directions, so the two frontiers are verifier-isomorphic via the
identity map: a record on either is, with no recomputation, a record on the other. -/

/-- A Golomb-ruler set over `List Nat`: every coincidence of pairwise differences (in additive form)
    comes from the same pair. -/
def GolombList (S : List Nat) : Prop :=
  ∀ a ∈ S, ∀ b ∈ S, ∀ c ∈ S, ∀ d ∈ S, a + d = b + c → (a = b ∧ c = d) ∨ (a = c ∧ b = d)

/-- The distinct-differences (Golomb-ruler) frontier. -/
def golombFrontier : Frontier := { Obj := List Nat, verified := GolombList }

/-- **Distinct sums ⇒ distinct differences.** A real reindexing of the Sidon hypothesis: instantiate
    `a + b = c + d` at the permuted arguments `(a, d, b, c)`. No `Nat` subtraction, no axiom. -/
theorem sidon_to_golomb_sound {S : List Nat} (h : SidonList S) : GolombList S := by
  intro a ha b hb c hc d hd hdiff
  -- hdiff : a + d = b + c, which is the Sidon premise at (a, d, b, c)
  rcases h a ha d hd b hb c hc hdiff with ⟨h1, h2⟩ | ⟨h1, h2⟩
  · exact Or.inl ⟨h1, by omega⟩
  · exact Or.inr ⟨by omega, by omega⟩

/-- **Distinct differences ⇒ distinct sums.** The converse reindexing, so the bridge is an isomorphism
    of verifiers, not just a one-way map. -/
theorem golomb_to_sidon_sound {S : List Nat} (h : GolombList S) : SidonList S := by
  intro a ha b hb c hc d hd hsum
  -- hsum : a + b = c + d, which is the Golomb premise at (a, d, c, b)
  have hg : a + b = c + d := hsum
  rcases h a ha d hd c hc b hb (by omega) with ⟨h1, h2⟩ | ⟨h1, h2⟩
  · exact Or.inr ⟨by omega, by omega⟩
  · exact Or.inl ⟨h1, by omega⟩

/-- The cross-frontier transfer `Sidon → Golomb`: identity on the underlying set, soundness the real
    theorem `sidon_to_golomb_sound`. A genuine second entry in the sound-transfer registry, between
    *distinct* frontiers. -/
def sidonToGolomb : Transfer sidonFrontier golombFrontier where
  toFun := fun S => S
  sound := fun _ h => sidon_to_golomb_sound h

/-- The reverse transfer `Golomb → Sidon`. -/
def golombToSidon : Transfer golombFrontier sidonFrontier where
  toFun := fun S => S
  sound := fun _ h => golomb_to_sidon_sound h

/-- The bridge fires: a verified Sidon record is, with no recomputation, a verified Golomb ruler. -/
example {S : List Nat} (h : SidonList S) : golombFrontier.verified (sidonToGolomb.toFun S) :=
  transfer_sound sidonToGolomb h

/-- Round-trip is the identity on objects: composing the two bridges returns the original set, so the
    frontiers are genuinely verifier-isomorphic (not merely connected one way). -/
@[simp] theorem sidon_golomb_roundtrip {S : List Nat} :
    (golombToSidon.toFun (sidonToGolomb.toFun S)) = S := rfl

end Vela
