# Status planes — the canonical vocabulary map

Vela speaks about a record on **four distinct planes**. Each is a separate,
legitimate projection over the same replayed state. They share some words
("open", "contested", "disproved"/"refuted"), and that overlap is the single
biggest source of vocabulary drift. This document is the canonical map: what
each plane means, what type carries it, which surface shows it, and the rule
that governs how they relate.

**The governing rule:** the planes are projections, not synonyms. They can
disagree by design, and Vela never collapses them into one scalar "confidence"
(memo §8, §16.5). A surface must always make clear *which plane* it is showing.

---

## Plane 1 — Resolution (descriptive, cross-source)

What the **source databases declare** about a problem. This is a join over what
others say, not a Vela verdict.

- Words: `open` · `proved` · `solved` · `disproved` · `contested` · `undeclared`
- Type: `atlas::AtlasCell.status` (substrate), `AtlasStatus` (web `lib/atlas.ts`)
- Surfaced on: the **Map** (state lens, labelled "cross-database resolution"),
  the **Concordance**
- Authority: none. `contested` here means the sources disagree on the
  resolution word; it is a reconciliation queue, not an adjudication.

## Plane 2 — Finding state (product, per-finding, derived)

The **platform's own read of a single finding**, derived from its review verdict
plus its recomputed verifier gate. This is the product vocabulary (memo §6) —
what the UI says *about a finding*.

- Words: `open` · `established` · `refuted` · `contested` · `fragile`
- Type: `frontier_graph::FindingState`
- Surfaced on: the **Boundary** tab, the per-frontier claim **graph**
- Authority: derived, recomputed on read. `established` = reviewer-accepted OR
  a passing verifier-gate attachment; `fragile` = established but thin;
  `refuted` = a rejected verdict or a gate refutation; `contested` = a contested
  verdict or a recorded contradiction. Orthogonal to Plane 1: a problem can be
  Resolution=`disproved` (a source says so) while its Finding state is `open`
  (Vela holds no review verdict or attachment for it yet). That is not a
  contradiction; it is two planes.

## Plane 3 — Epistemic support (formal, provenance)

The **bilattice/Belnap status** computed from the support and refute provenance
polynomials and their exact κ coordinates. The formal trust calculus underneath
the product words.

- Words: `True` · `False` · `Both` · `None` (Belnap corners) + support κ /
  refutation κ (exact rationals)
- Type: `status_provenance::BelnapStatus`, `frontier_calculus::BilatticePoint`
- Surfaced on: `vela claim state`; the trust internals
- Authority: a pure function of the recorded support/refute monomials
  (Theorem 3). Never persisted. `Both` here is the formal join of support and
  refutation, which is *not* the same event as a Plane-2 `contested` review
  verdict.

## Plane 4 — Review lifecycle / protocol signals (process)

Where a **change** sits in the propose → review → accept → seal pipeline, and the
protocol event signals. About the *process*, not the claim's truth.

- Words: `raw` · `proposed` · `reviewed` · `accepted` · `banked` · `sealed` ·
  `contested` · `retracted` · `leased` · `replayed` (and the rest of
  `lib/signal-code.ts`)
- Type: web `signal-code` / `StateChip`; substrate `review.*` events,
  `StateProposal.status`
- Authority: the signed event log. `contested` here is a review *event*, the
  upstream of a Plane-2 contested finding.

---

## Shared-word table (always qualify by plane)

| word | Plane 1 Resolution | Plane 2 Finding state | Plane 3 Epistemic | Plane 4 Lifecycle |
|---|---|---|---|---|
| open | sources record no resolution | no verdict/gate yet | — | — |
| contested | sources disagree | contested verdict / contradiction | `Both` corner | a review event |
| disproved / refuted | a source recorded a refutation | rejected verdict or gate refutation | `False` corner | — |
| proved / solved / established | a source recorded a proof/solution | reviewer-accepted or gate-verified | `True` corner | `accepted`/`sealed` |

When writing copy or a label, name the plane: "cross-database resolution"
(Plane 1), "finding state" (Plane 2), "support" (Plane 3), "review" (Plane 4).
Never let a bare word imply all four.

---

## Domain terms that are NOT status words

- **"Erdős Problem #N"** is a domain proper noun (the problem's name). It stays
  in finding *content*; it is not the Plane-1 word "problem".
- **Product nav/chrome** uses the memo §1 nouns: Finding · Frontier · Evidence ·
  Attempt · Submission · Review · Workspace · Run · Registry · Atlas. "problems"
  is retired from product chrome (the catalogue is **Frontiers**).

## "claim" vs "finding" — the resolved rule

These are **not** synonyms, and the apparent doubling was web-only drift (now
fixed: the product surfaces say *finding* for the record and *assertion* for the
proposition it carries).

- **Finding** = the *record*: the deposited `FindingBundle` (`vf_`) with its
  assertion, evidence, provenance, confidence, and links. This is the product
  noun, used everywhere a person reads about the unit.
- **claim** is retained ONLY where it is not a finding-synonym:
  1. the **formal claim-context cell** `z = (q, c)` and the **Claim-State Cell**
     projection (`frontier_calculus`, `vela claim state`) — a proposition under
     a scope, a defined object distinct from a bundle;
  2. the **verb "to claim"**: `vela claim <frontier> <obligation>` leases an open
     obligation. You claim (lease) an obligation; you do not "find" one.
  3. `verifier_attachment::claim_digest` — the sha256 of an assertion string,
     byte-matched to Python's `canopus_trust.py::claim_digest`. Renaming it
     would break cross-implementation content-addressing.

`vela finding` and `vela claim` are deliberately distinct CLI commands (the
finding record vs. the lease verb / cell projection), not duplicates.

See `frontier_graph::FindingState` for Plane 2 and `frontier_calculus` for
Plane 3.
