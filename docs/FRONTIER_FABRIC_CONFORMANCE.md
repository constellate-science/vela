# Frontier Fabric Conformance Laws

These are implementation obligations. They are not theorems about the free lineage carrier.

## Law 1: no hidden state

No authoritative status, confidence, trust, cost, frontier, gap, rank, or transfer value may be emitted unless it binds to:

```text
presentation root
lineage or circuit root
active-view root
adapter and evaluator ids
valuation, policy, coverage, or utility inputs
canonical output
replay receipt
```

The executable predicate fails when an authoritative value lacks a reproducing observation packet.

## Law 2: no model authority

A packet signed by a model or agent must have:

```text
state_effect = none
authority_claim = proposal_only
```

It may not carry an accepted event id or authoritative evidence label.

## Law 3: no silent transfer

Every context or domain movement names:

```text
transfer lane
source and target contexts
assumptions
preserved and lost coordinates
certificate or target-receipt requirements
human acceptance
```

## Law 4: no silent evidence upgrade

A target evidence class appears only from a target-domain receipt. Source evidence may remain in lineage but cannot manufacture the target class.

## Law 5: gap provenance

Every gap names:

```text
adapter id
obligation-generator id
coverage-model root
discharge evaluator
presentation and view roots
```

A UI may not describe unsupported free-form model output as a canonical knowledge gap.

## Law 6: no completeness claim without a universe

The product may say:

```text
open under adapter A and coverage model C
```

It may not say:

```text
all unknowns in this field
```

unless a domain-specific proof establishes completeness relative to a finite declared universe.

## Law 7: ranking non-interference

Opportunity, transfer leverage, expected information gain, novelty, citation, model score, and funding priority may order work. They may not alter accepted support, evidence class, confidence, or trust coordinates.

## Law 8: target-check binding

A target receipt binds to:

```text
candidate id
target claim and context
artifact digest
verifier id and executable digest
configuration and tolerance
output digest
```

## Law 9: human acceptance

Every accepted clause and active-view restriction has an eligible human signature. Models may draft review material but may not supply the acceptance key.

## Law 10: failure memory

A failed candidate affects accepted state only through an accepted failure event. Failure packets name the attempted obligation, method, inputs, cost, and failure reason.

## Law 11: adapter immutability

Historical state cites content-addressed adapter versions. An adapter update cannot reinterpret earlier packets silently.

## Law 12: query completeness labeling

Support, environment, and hitting-set packets state whether their result is:

```text
complete exact
bounded exact
approximate
one witness only
```

The product may not present a bounded or approximate query as exhaustive.
