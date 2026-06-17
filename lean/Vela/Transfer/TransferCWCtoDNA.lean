import Vela.Transfer.Transfer

/-!
# Cross-frontier transfer: Constant-Weight Code → DNA Code (the pro model's #1)

A compute-model research pass ranked `ConstantWeightCode → DNACode` as the highest-leverage transfer:
it turns the large body of constant-weight / design / code constructions into DNA-code witnesses, it
handles fixed GC content, and it satisfies the reverse-complement distance constraint essentially for
free. This file formalizes it with a genuine `sound` proof (Mathlib-free, no `sorry`/`axiom`).

Symbols follow the frozen `verify_construction.py` DNA convention `0=A, 1=C, 2=G, 3=T`. A binary
constant-weight word over `{0,1}` *is already* a DNA word over `{A,C}` (the map is the identity on the
underlying symbol list — like `sidonToGolomb`). The content is that, viewed as DNA:

* Hamming distance is unchanged (identity), so the minimum-distance bound transfers directly;
* GC content equals the binary weight `w` (only `C=1` contributes GC; there are no `G=2` symbols);
* the reverse complement of an `{A,C}` word lies in `{T,G} = {3,2}`, so it differs from every `{A,C}`
  word at *every* coordinate — reverse-complement distance is the full length `n ≥ d` (side condition
  `d ≤ n`, which holds for any code).

The catalog gate is unchanged: a record-unlock additionally requires the mapped word list to pass the
frozen `verify_constantweight` then `verify_dnacode`, recorded as a session delta — not asserted here.
-/

namespace Vela.TransferCWCtoDNA

open Vela

/-- Hamming distance on equal-length symbol words. -/
def Ham : List Nat → List Nat → Nat
  | [], _ => 0
  | _, [] => 0
  | a :: as, b :: bs => (if a = b then 0 else 1) + Ham as bs

/-- Binary Hamming weight: count of nonzero symbols. -/
def Wt : List Nat → Nat
  | [] => 0
  | a :: as => (if a = 0 then 0 else 1) + Wt as

/-- DNA GC content: count of `C = 1` and `G = 2`. -/
def GC : List Nat → Nat
  | [] => 0
  | a :: as => (if a = 1 ∨ a = 2 then 1 else 0) + GC as

/-- Nucleotide complement: `A(0) ↔ T(3)`, `C(1) ↔ G(2)`. -/
def comp (a : Nat) : Nat := if a = 0 then 3 else if a = 1 then 2 else if a = 2 then 1 else 0

/-- Reverse complement of a DNA word. -/
def RevComp (x : List Nat) : List Nat := (x.map comp).reverse

/-- On binary words, GC content equals Hamming weight (only `C=1` contributes GC; no `G=2`). -/
theorem gc_eq_wt_of_binary (x : List Nat) (h : ∀ a ∈ x, a ≤ 1) : GC x = Wt x := by
  induction x with
  | nil => rfl
  | cons a as ih =>
    have ha : a ≤ 1 := h a List.mem_cons_self
    have has : ∀ b ∈ as, b ≤ 1 := fun b hb => h b (List.mem_cons_of_mem a hb)
    have iha := ih has
    rcases (show a = 0 ∨ a = 1 by omega) with rfl | rfl
    · simp [GC, Wt, iha]
    · simp [GC, Wt, iha]

/-- If every symbol of `x` is `≤ 1` and every symbol of `z` is `≥ 2`, the two equal-length words
    differ at every coordinate, so their Hamming distance is the full length. -/
theorem ham_all_diff (x : List Nat) :
    ∀ (z : List Nat), x.length = z.length →
      (∀ a ∈ x, a ≤ 1) → (∀ b ∈ z, 2 ≤ b) → Ham x z = x.length := by
  induction x with
  | nil => intro z _ _ _; simp [Ham]
  | cons a as ih =>
    intro z hlen hx hz
    cases z with
    | nil => simp at hlen
    | cons b bs =>
      have ha : a ≤ 1 := hx a List.mem_cons_self
      have hb : 2 ≤ b := hz b List.mem_cons_self
      have hne : ¬ (a = b) := by omega
      have hlens : as.length = bs.length := by simpa using hlen
      have hxs : ∀ c ∈ as, c ≤ 1 := fun c hc => hx c (List.mem_cons_of_mem a hc)
      have hzs : ∀ c ∈ bs, 2 ≤ c := fun c hc => hz c (List.mem_cons_of_mem b hc)
      have hrec := ih bs hlens hxs hzs
      simp only [Ham, if_neg hne, List.length_cons]
      omega

/-- A binary word and the reverse complement of a binary word differ everywhere: Hamming distance is
    the full length. (The reverse complement of an `{A,C}` word lies in `{G,T} = {2,3}`.) -/
theorem ham_revcomp (x y : List Nat) (hlen : x.length = y.length)
    (hx : ∀ a ∈ x, a ≤ 1) (hy : ∀ a ∈ y, a ≤ 1) :
    Ham x (RevComp y) = x.length := by
  apply ham_all_diff x (RevComp y)
  · rw [RevComp, List.length_reverse, List.length_map]; exact hlen
  · exact hx
  · intro b hb
    rw [RevComp, List.mem_reverse, List.mem_map] at hb
    obtain ⟨a, ha, rfl⟩ := hb
    have hle : a ≤ 1 := hy a ha
    rcases (show a = 0 ∨ a = 1 by omega) with rfl | rfl <;> decide

/-- The constant-weight-code frontier with parameters `(n, d, w)`: binary words of length `n` and
    weight `w`, pairwise Hamming distance `≥ d`. -/
def IsCWC (n d w : Nat) (C : List (List Nat)) : Prop :=
  (∀ x ∈ C, x.length = n) ∧
  (∀ x ∈ C, ∀ a ∈ x, a ≤ 1) ∧
  (∀ x ∈ C, Wt x = w) ∧
  (∀ x ∈ C, ∀ y ∈ C, x ≠ y → d ≤ Ham x y)

/-- The DNA-code frontier `(n, d, w)`: words of length `n`, GC content `w`, pairwise distance `≥ d`,
    and reverse-complement distance `≥ d` (matching `verify_dnacode` with `gc=(w,w)`, `rev_comp=True`). -/
def IsDNA (n d w : Nat) (C : List (List Nat)) : Prop :=
  (∀ x ∈ C, x.length = n) ∧
  (∀ x ∈ C, GC x = w) ∧
  (∀ x ∈ C, ∀ y ∈ C, x ≠ y → d ≤ Ham x y) ∧
  (∀ x ∈ C, ∀ y ∈ C, d ≤ Ham x (RevComp y))

def cwcFrontier (n d w : Nat) : Frontier := { Obj := List (List Nat), verified := IsCWC n d w }
def dnaFrontier (n d w : Nat) : Frontier := { Obj := List (List Nat), verified := IsDNA n d w }

/-- **Soundness of the CWC → DNA map** (identity on the symbol list). A verified constant-weight code
    is, viewed over the DNA alphabet, a verified DNA code with GC `= w` and full reverse-complement
    distance. Side condition `d ≤ n` (true for any code). -/
theorem cwc_to_dna_sound (n d w : Nat) (hdn : d ≤ n) (C : List (List Nat))
    (h : IsCWC n d w C) : IsDNA n d w C := by
  obtain ⟨hlen, hbin, hwt, hdist⟩ := h
  refine ⟨hlen, ?_, hdist, ?_⟩
  · intro x hx
    rw [gc_eq_wt_of_binary x (hbin x hx)]; exact hwt x hx
  · intro x hx y hy
    have hxlen := hlen x hx
    have key : Ham x (RevComp y) = x.length :=
      ham_revcomp x y (by rw [hxlen, hlen y hy]) (hbin x hx) (hbin y hy)
    rw [key, hxlen]; exact hdn

/-- The cross-frontier transfer `ConstantWeightCode(n,d,w) → DNACode(n,d,w)`: identity on the underlying
    word list, with a genuine soundness proof (no axiom). The pro model's highest-leverage bridge. -/
def cwcToDna (n d w : Nat) (hdn : d ≤ n) : Transfer (cwcFrontier n d w) (dnaFrontier n d w) where
  toFun := fun C => C
  sound := fun C h => cwc_to_dna_sound n d w hdn C h

/-- Transfer soundness fires with genuine content: a verified constant-weight code transfers to a
    verified DNA code. -/
example (n d w : Nat) (hdn : d ≤ n) {C : List (List Nat)} (h : IsCWC n d w C) :
    (dnaFrontier n d w).verified ((cwcToDna n d w hdn).toFun C) :=
  transfer_sound (cwcToDna n d w hdn) h

end Vela.TransferCWCtoDNA
