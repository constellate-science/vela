# Erdős problem certificates (re-verifiable references)

This directory ships thirty-two certificates for problems from the
[Erdős problems](https://www.erdosproblems.com/) corpus, each one a witness a
**frozen exact verifier can re-check from scratch**, with no trust in the
producer. They are finite confirmations and exact-construction or
impossibility certificates, not claimed full solutions.

The witnesses span the Erdős verifier kinds in `vela-verify`, including:
interval-product covers (`interval_product`, #1056), distinct partial sums
(`distinct_partial_sums`), binomial deficiency (`binom_deficiency`, #1093),
Kummer no-carry (`kummer_no_carry`, #684), min-binomial-gcd (`min_binom_gcd`,
#700), an UNSAT certificate (`unsat_cert`, #617 shape), and the Erdős–Straus
unit-fraction decomposition (`unit_fraction_decomp`, #242).

## Re-verify it yourself

```sh
vela reproduce examples/erdos-problems
```

```
  reproduce: ok (32/32) — every witness re-verified from scratch by the frozen verifiers.
```

Each witness carries its construction; the matching frozen verifier re-derives
the check and confirms the claim. Corrupt any witness and `vela reproduce`
exits non-zero. The verifiers are pure and deterministic, so the verdict is the
same on any machine.

This is the reproducible certificate set. The full signed frontier (the event
log, proposals, reviews, obligations, and provenance) is the maintained
frontier on the hub; see the repository `README` for how a certificate earns
`verified` state through the gate.
