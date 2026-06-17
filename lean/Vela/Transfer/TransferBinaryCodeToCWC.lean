import Vela.Transfer.TransferCWCtoDNA

/-!
# Cross-frontier transfer: Binary code → Constant-Weight Code (fixed-weight subcode)

The pro model's #3 (LinearCode → CWC via fixed-weight subcode) does not actually need linearity: filtering
ANY binary minimum-distance-`d` code to its weight-`w` words yields a constant-weight code `CWC(n,d,w)`.
This file formalizes that as a transfer whose map is a genuine *filter* (not the identity), with a real
soundness proof (Mathlib-free, no `sorry`/`axiom`).

This is the bridge that turns linear-code tables into constant-weight (and thence, via `cwcToDna`, DNA)
witnesses — including the famous route the extended binary Golay code `[24,12,8]` takes to its 759
weight-8 octads `= CWC(24,8,8)`, exhibited operationally through the frozen verifiers in
`scripts/transfer_golay_to_dna_demo.py`.
-/

namespace Vela.TransferBinaryCodeToCWC

open Vela Vela.TransferCWCtoDNA

/-- The binary-code frontier `(n, d)`: binary words of length `n`, pairwise Hamming distance `≥ d`
    (no weight constraint). Linear codes over GF(2) are instances. -/
def IsBinaryCode (n d : Nat) (C : List (List Nat)) : Prop :=
  (∀ x ∈ C, x.length = n) ∧
  (∀ x ∈ C, ∀ a ∈ x, a ≤ 1) ∧
  (∀ x ∈ C, ∀ y ∈ C, x ≠ y → d ≤ Ham x y)

def binCodeFrontier (n d : Nat) : Frontier := { Obj := List (List Nat), verified := IsBinaryCode n d }

/-- The transfer map: keep exactly the codewords of Hamming weight `w`. -/
def fixedWeight (w : Nat) (C : List (List Nat)) : List (List Nat) :=
  C.filter (fun x => Wt x == w)

/-- **Soundness of binary-code → CWC.** The weight-`w` subcode of a binary distance-`d` code is a
    constant-weight code `CWC(n,d,w)`: filtering preserves length, binariness, and pairwise distance,
    and enforces weight `w`. -/
theorem bincode_to_cwc_sound (n d w : Nat) (C : List (List Nat)) (h : IsBinaryCode n d C) :
    IsCWC n d w (fixedWeight w C) := by
  obtain ⟨hlen, hbin, hdist⟩ := h
  refine ⟨?_, ?_, ?_, ?_⟩
  · intro x hx
    rw [fixedWeight, List.mem_filter] at hx
    exact hlen x hx.1
  · intro x hx a ha
    rw [fixedWeight, List.mem_filter] at hx
    exact hbin x hx.1 a ha
  · intro x hx
    rw [fixedWeight, List.mem_filter] at hx
    exact eq_of_beq hx.2
  · intro x hx y hy hxy
    rw [fixedWeight, List.mem_filter] at hx hy
    exact hdist x hx.1 y hy.1 hxy

/-- The cross-frontier transfer `BinaryCode(n,d) → CWC(n,d,w)`, via the fixed-weight filter. -/
def binCodeToCWC (n d w : Nat) : Transfer (binCodeFrontier n d) (cwcFrontier n d w) where
  toFun := fixedWeight w
  sound := fun C h => bincode_to_cwc_sound n d w C h

/-- **Composition** `BinaryCode → CWC → DNA` (filter, then the identity DNA embedding). Side condition
    `d ≤ n`. Turns a binary linear-code table directly into a DNA-code construction. -/
def binCodeToDNA (n d w : Nat) (hdn : d ≤ n) :
    Transfer (binCodeFrontier n d) (dnaFrontier n d w) :=
  (binCodeToCWC n d w).comp (cwcToDna n d w hdn)

/-- The composed bridge fires: a verified binary distance-`d` code yields, after filter-then-embed, a
    verified DNA code on its weight-`w` words. -/
example (n d w : Nat) (hdn : d ≤ n) {C : List (List Nat)} (h : IsBinaryCode n d C) :
    (dnaFrontier n d w).verified ((binCodeToDNA n d w hdn).toFun C) :=
  transfer_sound (binCodeToDNA n d w hdn) h

end Vela.TransferBinaryCodeToCWC
