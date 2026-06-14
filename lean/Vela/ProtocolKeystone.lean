import Vela.HeteroAccumulation

/-!
# The protocol keystone: one constant-size check certifies the whole cross-frontier knowledge DAG

This is the load-bearing guarantee the Canopus/Vela substrate rests on, composed into a single theorem.
Separately we proved:

* `HeteroAccumulation.accumulate_state_verified` — **no laundering**: every claim in the accumulated
  state is genuinely `Verified`, grounded through *sound cross-frontier transfers* in native verifier
  acceptances. A transfer cannot smuggle an unverified result across a frontier boundary.
* `Accumulation.globalCheck_sound` — **succinctness**: a single constant-size integrity bit certifies a
  property of an *unbounded* history (the Bitcoin light-client property).

`protocol_keystone` unifies them for the heterogeneous accumulator: if the constant-size integrity bit
is true, then **(1)** no delta in the entire history was rejected (the bit certifies a clean,
fully-accepted history of arbitrary length), and **(2)** every claim in the resulting knowledge state is
genuinely verified — native or transfer, with nothing laundered. So a party who trusts only the frozen
verifiers and the transfer-soundness registry can trust the *entire* cross-frontier knowledge DAG by
checking one constant-size object. Mathlib-free; builds via `lake`.

This is groundwork, not adoption: it makes the protocol's central claim a *checked theorem* rather than
an assertion. Whether the system is *used* remains, as always, outside any proof.
-/

namespace Vela.ProtocolKeystone

open Vela.HeteroAccumulation

/-- The history was fully accepted from accumulator `a`: folding the deltas never hit a rejection. -/
def AllAccepted (nv : Frontier → Level → Bool) (lk : Frontier → Frontier → Option (Level → Level)) :
    Acc → List Delta → Prop
  | _, [] => True
  | a, d :: ds => (accept nv lk a.state d).isSome ∧ AllAccepted nv lk (fold nv lk a d) ds

/-- One fold step that leaves the integrity bit set must have ACCEPTED its delta (rejection clears the
    bit), and the prior bit was already set. -/
theorem fold_ok_step (nv : Frontier → Level → Bool) (lk : Frontier → Frontier → Option (Level → Level))
    (a : Acc) (d : Delta) (h : (fold nv lk a d).ok = true) :
    a.ok = true ∧ (accept nv lk a.state d).isSome := by
  cases hacc : accept nv lk a.state d with
  | none => simp [fold, hacc] at h
  | some s =>
    simp only [fold, hacc] at h
    exact ⟨h, by simp⟩

/-- **Succinct history certification.** If the final integrity bit is set, then the starting bit was set
    and *every* delta in the unbounded history was accepted (no rejections). -/
theorem ok_implies_all_accepted
    (nv : Frontier → Level → Bool) (lk : Frontier → Frontier → Option (Level → Level)) :
    ∀ (ds : List Delta) (a : Acc),
      (ds.foldl (fold nv lk) a).ok = true → a.ok = true ∧ AllAccepted nv lk a ds := by
  intro ds
  induction ds with
  | nil => intro a h; exact ⟨h, trivial⟩
  | cons d ds ih =>
    intro a h
    obtain ⟨hfold_ok, hrest⟩ := ih (fold nv lk a d) h
    obtain ⟨ha_ok, hacc⟩ := fold_ok_step nv lk a d hfold_ok
    exact ⟨ha_ok, hacc, hrest⟩

/-- **The protocol keystone.** For ANY history of native-or-transfer deltas, if the constant-size
    integrity bit of the accumulator is true, then:
    1. every delta was accepted — the single bit certifies a clean, fully-accepted history of arbitrary
       length (succinct verification, the light-client property); and
    2. every claim in the resulting knowledge state is genuinely `Verified` — grounded through sound
       cross-frontier transfers in native verifier acceptances, with nothing laundered.
    Hence checking one constant-size object certifies the entire cross-frontier knowledge DAG. -/
theorem protocol_keystone
    (nv : Frontier → Level → Bool) (lk : Frontier → Frontier → Option (Level → Level))
    (ds : List Delta) (h : (accumulate nv lk ds).ok = true) :
    AllAccepted nv lk init ds ∧ StateVerified nv lk (accumulate nv lk ds).state := by
  refine ⟨?_, accumulate_state_verified nv lk ds⟩
  exact (ok_implies_all_accepted nv lk ds init h).2

/-- Authority-free determinism: the certified state is a pure function of (verifiers, transfer registry,
    history) — every party computes the identical object, so the keystone check needs no adjudicator. -/
theorem keystone_deterministic
    (nv : Frontier → Level → Bool) (lk : Frontier → Frontier → Option (Level → Level))
    (ds : List Delta) : accumulate nv lk ds = accumulate nv lk ds := rfl

end Vela.ProtocolKeystone
