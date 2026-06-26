# Sidon sets (a worked, re-verifiable reference)

A **Sidon set in `{0,1}^n`** is a set of binary vectors of length `n` whose
pairwise sums `a + b` (componentwise, over the integers) are all distinct. The
maximum known size for each `n` is the lower-bound frontier this directory
records.

This ships eighteen witnesses, `a(7)` through `a(24)`, as constructions
**anyone can re-verify from scratch** with no trust in the producer. The
improved `a(8)`..`a(16)` bounds here were the first external adoption of
frontier state from this substrate (approved into [OEIS A309370](https://oeis.org/A309370)
by an editor); `a(17)`..`a(24)` extend the same family.

## Re-verify it yourself

Every claim ships its construction in `witnesses/*.witness.json`. The frozen
verifier (`vela-verify`) re-checks each one: all pairwise sums distinct, and the
construction's size equals the claimed bound.

```sh
vela reproduce examples/sidon-sets
```

```
  reproduce: ok (18/18) — every witness re-verified from scratch by the frozen verifiers.
```

Corrupt any witness (drop a point, flip a bit, inflate `claimed_size`) and
`vela reproduce` exits non-zero. The verifier is pure and deterministic, so you
get the same verdict on any machine.

This directory is the reproducible witness set. The full signed frontier (the
event log, proposals, reviews, and provenance) is the maintained frontier on the
hub; see the repository `README` ("The verification gate") for how a witness
earns `verified` state through `≥2` independent attachments and a surviving
adversarial probe.
