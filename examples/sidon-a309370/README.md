# Sidon sets — OEIS A309370 (a worked, re-verifiable reference)

[OEIS A309370](https://oeis.org/A309370) records the largest known **Sidon
set in `{0,1}^n`**: a set of binary vectors of length `n` whose pairwise
sums `a + b` (componentwise, over the integers) are all distinct. `a(n)` is
the maximum size known.

This directory ships nine improved lower bounds, `a(8)` through `a(16)`, as
**witnesses anyone can re-verify from scratch** — no trust in the producer.
They were the first external adoption of frontier state from this
substrate: the bounds were approved into OEIS A309370 by an editor.

| n | this bound `a(n) ≥` | previous recorded |
|---|---|---|
| 8 | 33 | 32 |
| 9 | 46 | 45 |
| 10 | 65 | 63 |
| 11 | 88 | 87 |
| 12 | 121 | 120 |
| 13 | 185 | 169 |
| 14 | 257 | 237 |
| 15 | 357 | 334 |
| 16 | 502 | 472 |

## Re-verify it yourself

Every claim ships its construction in `witnesses/*.witness.json`. The frozen
verifier (`vela-verify`) re-checks each one — all pairwise sums distinct,
and the construction's size equals the claimed bound:

```sh
vela reproduce examples/sidon-a309370
```

```
  ok  …/sidon-a08.witness.json [sidon]  ·  Sidon verified: 33 points, 561 pairwise sums all distinct (size 33 = claimed)
  …
  reproduce: ok (9/9) — every witness re-verified from scratch by the frozen verifiers.
```

Corrupt any witness (drop a point, flip a bit, inflate `claimed_size`) and
`vela reproduce` exits non-zero. The verifier is pure and deterministic, so
you get the same verdict on any machine.

## How a witness earns *verified* state

Re-verification is the evidence, not the verdict. A bound becomes `verified`
frontier state only through the gate
(`vela_protocol::verifier_attachment::derive_gate_status`), which wants:

1. **≥2 independent matched verifier attachments** — by *different*
   method/solver (e.g. this exact-construction recompute **and** an
   independent re-implementation), each bound to the exact claim digest;
2. **a surviving adversarial probe** (a counterexample search that did not
   refute it);
3. all of it **well-formed and content-addressed**.

The path is: a proposer deposits the construction → `vela reproduce`
re-checks it → that recompute is recorded as an `exact_construction`
attachment (`vva_…`) → a second independent attachment + a surviving probe
→ `derive_gate_status` returns `verified` → the bound banks as state a
field holds to be true. With zero attachments a claim sits at
`needs_verification`, even if a reviewer accepted it. See the repo `README`
("The verification gate") and `docs/VERIFICATION_GATE.md`.

## Witness format

```json
{ "kind": "sidon", "oeis": "A309370", "claim": "a(8) >= 33",
  "n": 8, "claimed_size": 33, "points": [[0,1,1,0,0,0,1,1], …] }
```

`kind`, `n`, `points`, and `claimed_size` are read by the verifier; `oeis`
and `claim` are human annotations. The same `*.witness.json` shape works for
the other frozen verifiers (`golomb`, `cap`, `bh`, `covering`,
`constant_weight`, `costas`, `linear_code`).
