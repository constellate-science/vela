import Mathlib

/-!
# Vela replay-index theorem (Theorem 7)

This file formalizes the v0.105 O(N) replay optimization as a
machine-checked structural guarantee.

## The substrate optimization

Pre-v0.105 every per-kind apply function in `reducer.rs` ran
`state.findings.iter().position(|f| f.id == id)` to find its
target. At N findings replayed over N events, this was O(N^2).
v0.105 added a per-replay finding-id index built once at the
start of `replay_from_genesis` and updated in lockstep with
`finding.asserted` pushes, so every per-kind apply does an O(1)
lookup instead of a linear scan.

Findings are append-only in the substrate (the reducer never
removes them), so positions stored in the index remain valid for
the life of a replay. Theorem 7 proves this is sound: maintaining
the index by inserting on append agrees with rebuilding the index
from scratch on the new list.

## Two load-bearing properties

1. `lookup_append_miss`: appending an element with a fresh key
   does not change the lookup result for any other key.
2. `lookup_append_hit`: appending an element `x` whose key
   was not previously present makes lookup of that key return
   `some xs.length`, exactly the position the substrate inserts
   into the index after the push.

Together these prove that the in-place index maintenance Vela
performs (`idx.insert(finding.id.clone(), position)` after
`state.findings.push(finding)`) is semantically identical to
rebuilding the index from `state.findings` on every event.

## What is and is not formalized

This is a structural theorem under an abstract key function. It
proves the load-bearing semantic properties of the substrate's
index-maintenance rule. It does not prove the runtime complexity
(Lean does not model HashMap costs) or the Rust implementation
correctness of `build_finding_index`. The Rust function is
exercised by `crates/vela-protocol/tests/replay_perf.rs`; this
Lean theorem is the algebraic guarantee that the perf test is
pinning.
-/

namespace Vela.ReplayIndex

variable {X : Type*} {K : Type*} [DecidableEq K]

/-- Linear-scan lookup. Walks the list left to right and returns
the position of the first element whose key matches. Defined
explicitly (rather than via `List.findIdx?`) so the proofs
below work directly by structural induction without fighting
Lean's hidden offset accumulator. -/
def lookup (xs : List X) (key : X → K) (k : K) : Option Nat :=
  match xs with
  | [] => none
  | y :: ys =>
      if key y = k then some 0
      else (lookup ys key k).map (· + 1)

@[simp] theorem lookup_nil (key : X → K) (k : K) :
    lookup ([] : List X) key k = none := rfl

@[simp] theorem lookup_cons_match
    (y : X) (ys : List X) (key : X → K) (k : K)
    (h : key y = k) :
    lookup (y :: ys) key k = some 0 := by
  simp [lookup, h]

@[simp] theorem lookup_cons_miss
    (y : X) (ys : List X) (key : X → K) (k : K)
    (h : key y ≠ k) :
    lookup (y :: ys) key k = (lookup ys key k).map (· + 1) := by
  simp [lookup, h]

/-- **Lemma**: appending an element with a fresh key (no existing
element shares the key) does not change the lookup result for any
key different from the appended one. -/
theorem lookup_append_miss
    (xs : List X) (x : X) (key : X → K) (k : K)
    (hk : k ≠ key x) :
    lookup (xs ++ [x]) key k = lookup xs key k := by
  induction xs with
  | nil =>
    -- [] ++ [x] = [x]; lookup [x] for k ≠ key x recurses to none.
    have hxk : key x ≠ k := fun h => hk h.symm
    simp [lookup_cons_miss x [] key k hxk]
  | cons y ys ih =>
    by_cases hky : key y = k
    · -- Head matches: both lookups return some 0.
      simp [lookup_cons_match y _ key k hky]
    · -- Head doesn't match: both recurse, IH closes the gap.
      simp [lookup_cons_miss y _ key k hky, ih]

/-- **Lemma**: appending an element with a fresh key produces a
list whose lookup at the appended key returns the position right
after the previous end of the list, i.e. `xs.length`. -/
theorem lookup_append_hit
    (xs : List X) (x : X) (key : X → K)
    (hfresh : ∀ y ∈ xs, key y ≠ key x) :
    lookup (xs ++ [x]) key (key x) = some xs.length := by
  induction xs with
  | nil =>
    -- [] ++ [x] = [x]; lookup [x] for key x is some 0 = some [].length.
    simp [lookup_cons_match x [] key (key x) rfl]
  | cons y ys ih =>
    have hy : key y ≠ key x := hfresh y (by simp)
    have hys : ∀ z ∈ ys, key z ≠ key x := fun z hz =>
      hfresh z (by simp [hz])
    have ih' := ih hys
    -- key y ≠ key x, so the head check fails and we recurse.
    simp [lookup_cons_miss y _ key (key x) hy, ih']

/-- **Theorem 7 (replay-index correctness)**: maintaining the
finding-id index by inserting on every `finding.asserted` push
agrees with rebuilding the index from scratch on the new
findings list. After pushing a new finding `x` at position
`xs.length`, the lookup function over the new list behaves as:

- looking up the new key returns `some xs.length` (the appended
  position); and
- looking up any other key returns the same answer it would have
  on the pre-append list.

This is the substrate's load-bearing claim that
`idx.insert(finding.id.clone(), position)` after
`state.findings.push(finding)` keeps the index in sync with
state. -/
theorem theorem7_index_maintenance_under_append
    (xs : List X) (x : X) (key : X → K)
    (hfresh : ∀ y ∈ xs, key y ≠ key x) (k : K) :
    lookup (xs ++ [x]) key k =
      (if k = key x then some xs.length else lookup xs key k) := by
  by_cases hk : k = key x
  · subst hk
    simp [lookup_append_hit xs x key hfresh]
  · simp [hk, lookup_append_miss xs x key k hk]

end Vela.ReplayIndex
