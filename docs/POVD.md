
# Proof-of-Verified-Delta (PoVD)

A candidate mechanism for the one honest analogue of Bitcoin's breakthrough, applied to the
**frozen-verifiable slice of science**. This document specifies the mechanism, states the thesis,
cites the machine-checked properties, and is blunt about the limits. It is the *design and proof* of
the inventive core. It is **not** a claim that the breakthrough is achieved: that status, like
Bitcoin's, is earned only through adoption and surviving reality, which no specification or proof can
grant.

## The thesis

Bitcoin needed three separate mechanisms: proof-of-work (Sybil resistance), longest-chain (consensus),
and transaction validation (fraud prevention). The PoVD claim is that **a frozen verifier collapses all
three into a single primitive** — but only on the slice of science where a claim ships with a witness a
verifier can re-check cheaply (combinatorics, codes, algorithms, formal proofs). On that slice:

- **Anti-fraud** = the verifier. You cannot earn standing without a witness it accepts.
- **Sybil resistance** = content-addressing + strict improvement. Duplicate or stale contributions are
  rejected, so extra identities buy nothing; the cost is doing real verifiable work, not owning keys.
- **Consensus** = deterministic replay. "What is verified" is a pure function of the accepted-delta set
  and the frozen verifier; every party computes the identical state with no trusted adjudicator.

This is mechanism design, not new mathematics — exactly the register Bitcoin was in (hashcash, Merkle
trees, and public-key crypto all predated it; the invention was the *mechanism*).

## The mechanism

- **Shared state** `S : Frontier → Level`: the best verified level recorded for each frontier.
- **Delta** `(frontier, level, witness)`: a proposed improvement, backed by a witness.
- **Acceptance** (`accept`): a delta is accepted iff `verify(witness)` AND `level > S[frontier]`
  (it strictly improves the current best). On acceptance the state rises at exactly that frontier.
- **Credit**: one non-forgeable, content-addressed unit accrues to the producer of each accepted delta.
- **Replay**: the shared state is the deterministic fold of all accepted deltas — no authority.

## Proven properties (machine-checked, `lean/Vela/PoVD.lean`, Mathlib-free, compiles standalone)

| Property | Theorem | Meaning |
|---|---|---|
| No credit without verification | `accept_implies_verified` | accepted ⇒ the verifier passed |
| Monotone state, no zombies | `accept_monotone` | acceptance never lowers any frontier's level |
| No double-spend / known-result rejected | `stale_rejected` | a non-improving delta is rejected |
| Sybil / duplication resistance | `duplicate_rejected` | resubmitting an accepted delta earns nothing |
| Authority-free consensus | `accept_deterministic` | acceptance is a pure function — same verdict for all |
| Credited ⇒ real | `credited_is_real` | every credited delta is verified AND strictly advanced its frontier |

Together: the shared state grows **only** by genuine, re-checkable improvements, and credit is
impossible without doing real verification work. That is the anti-gaming core, proven.

## Why this is not "blockchain for science"

Those efforts failed by bolting a speculative token onto **unverifiable** peer-review trust — the token
secured nothing because the underlying claims weren't checkable. PoVD inverts this: it admits **only**
claims with a frozen verifier, so the "proof" is a real re-checkable certificate, not a token standing
in for trust. Credit is non-forgeable provenance, not a tradeable coin. The restriction to the
verifiable slice is both the source of integrity and the ceiling.

## Honest limits (the parts a proof cannot fix)

1. **Verifiable slice only.** Most empirical/wet-lab science has no frozen verifier — you cannot
   re-check "this drug works" from the ledger. Such claims enter as *proposals/predictions*, never as
   credited deltas, until a verifier exists. Bitcoin's domain (money) was fully digital; science is not.
   This is a hard boundary, not a temporary gap.
2. **Credit, not money.** Bitcoin bootstrapped security with a token that had monetary value from day
   one. PoVD's incentive is non-forgeable credit/standing. Whether reputational credit alone drives a
   real community of scientists and agents is an **unproven empirical bet**, and it is the part most
   likely not to land.
3. **Novelty is bounded by the substrate.** "Strict improvement" is measured against the shared state,
   not all of human knowledge. A delta can be new to the substrate yet already known externally
   (exactly the AI-math-discovery failure mode: retrieval mistaken for discovery). Completeness of the
   substrate bounds the novelty guarantee.
4. **No economic security model.** There is no 51%-style cost-of-attack analysis, because there is no
   economic stake. The "security" rests entirely on the verifier being un-foolable on its slice.

## What would make it a breakthrough

Not more theory and not a better spec. Adoption by people who are not us; surviving contact with real,
adversarial, messy contributions; one frontier a working scientist actually relies on; and enough
accumulated, externally-accepted verified state that trust compounds. Those are years-long and cannot
be willed. What is in hand today is the mechanism and its proven anti-gaming core — the design, stated
honestly, with its boundary drawn where integrity requires.
