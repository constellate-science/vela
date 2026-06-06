# The verification gate

The substrate makes the *log* trustworthy: every change is signed over
content-addressed bytes and replays to the same state on any machine. That is
necessary and not sufficient. A signed event can still carry an overstated
claim, a proof of the wrong statement, or a single self-confirming run dressed
up as "verified". The gate is the layer that decides what counts as verified,
and it is deliberately separate from both the human review verdict and Bayesian
confidence.

The design follows one rule the codebase already uses for Belnap status
(`status_provenance`): **derive, never store.** Verification status is a pure
function of the evidence attached to a claim. There is no setter. A claim cannot
be stamped verified; it can only derive as verified from attachments that
satisfy four conditions.

## Verifier attachments (`vva_`)

A `VerifierAttachment` (`crate::verifier_attachment`) is a standalone,
content-addressed object — the `Replication` (`vrep_`) precedent, not a mutable
field on the finding. Each attachment is one verifier's judgment, bound to the
exact claim it checked by `claim_digest` (`sha256(trimmed claim)[..16]`, the same
rule as the Python reference). It records:

- `verifier_method` — one of the closed set (`computational_search`,
  `lp_dual_recompute`, `sat_unsat_cert`, `lean_kernel`,
  `exact_arithmetic_recompute`, `literature_corroboration`, `manual_referee`).
  `proof_verification` and `lean_verification` are instances of `lean_kernel`.
- `solver_id` — the independent tool that produced the check (`cp-sat`,
  `pulp-cbc`, `lean4@4.29.1`).
- `independent_of` — ids of other attachments this one declares independence
  from.
- `match_to_claim` — the verifier's assertion that it checked the target claim
  verbatim, not a weaker statement.
- `adversarial_probes` — probes run against the claim, each surviving or
  refuting.
- `outcome` — `passed` or `failed`.

## The four conditions

`derive_gate_status(current_claim_digest, attachments)` returns
`needs_verification`, `verified`, or `refuted`, with the reasons it is not
verified.

- **G1 independence** — at least two *matched* attachments by different
  `(verifier_method, solver_id)`, mutually declaring `independent_of`. One run,
  or two runs of the same method, never suffices.
- **G2 claim-match** — every passing attachment is bound to the current claim
  digest with `match_to_claim.matches`. A passing attachment bound to a
  different claim is `passed_but_unmatched` and counts for nothing.
- **G3 adversarial** — at least one probe present across the matched set and
  none refuted. A single refuting probe drives the whole gate to `refuted`.
- **G4 well-formed** — matched attachments are structurally valid, content-
  addressed (`vva_…`), and verify their own id.

A claim with zero attachments derives to `needs_verification`, even if a
reviewer accepted it. That is the bug class the gate exists to prevent: in the
Erdős dogfooding, 47 of 76 "verified" records carried an empty verification
field and were trusted anyway.

## Deliverable grade

`crate::deliverable_grade` is the orthogonal anti-inflation axis: *what was
delivered*, independent of how strong the evidence is. The taxonomy runs from
`unconditional_solve` and `conditional_solve` (the only two that license
solve-language) through `improved_published_bound`, `verified_reduction`,
`obstruction_map`, `partial_proof`, `extends_prior_work`, `new_oeis_term`,
`lean_fragment`, down to `honest_null` and `retracted`.

`grade_gate(claim, grade)` requires a grade and blocks solve-language ("solve",
"resolves #", "first to solve", …) in the claim text unless the grade is a
solve. A bound improvement may not call itself a resolution.

## CLI

```sh
vela gate vocab
vela gate grade --claim "This resolves #647 with an improved bound." \
  --grade improved_published_bound          # exit 1: solve-language mismatch
vela gate check --claim "<exact claim>" --attachments attachments.json
```

`vela gate check` reads a JSON array of `VerifierAttachment`, verifies each is
well-formed, derives the status against the claim digest, and exits non-zero
unless the status is `verified`. It is distinct from `vela verify`, which checks
that a proof packet is byte-for-byte what was signed — the log guarantee, not
the claim guarantee.
