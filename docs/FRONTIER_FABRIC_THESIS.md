# Breakthrough thesis: a record, a map, and an extension loop

## 1. Mission

The mission is to make the frontiers of mathematics and science readable, writable, correctable, and extendable.

The literature records activity. A frontier records the current state of a question, the routes that support it, the gaps that block it, and the actions that could move it.

No single model, ontology, institution, or verifier can represent all scientific domains. A shared protocol can still provide a common state and intervention layer if it preserves domain differences rather than erasing them. Representation can be domain-general while autonomous acceptance remains restricted to domains with adequate target receipts and human authorization.

## 2. The architecture

The system has three responsibilities.

### Vela: record

Vela stores accepted scientific state as context-scoped composed lineage:

```text
Γ_P : H -> N[X]
```

`H` contains claim-context-polarity cells. `X` contains primitive assumption, artifact, receipt, transfer, policy, and acceptance atoms. Addition means alternative support routes. Multiplication means joint dependence.

Historical state changes by `append`. Active state changes by `restrict`. Authoritative values are emitted only by proof-carrying `observe` operations.

### Constellate: map

Constellate derives a frontier map from Vela state and declared domain adapters.

An adapter generates a finite or enumerable obligation universe `Ω_A(P, ν)`. Each obligation names a target cell, context, discharge evaluator, verifier profile, and generator. An obligation is open when its discharge predicate is false under the active view.

```text
G_A(P, ν) = { o in Ω_A(P, ν) | discharge_o(ρ_ν Γ_P) = false }
```

These open obligations are the tractable meaning of knowledge dark matter.

### Extension engines: extend

Humans, search programs, theorem provers, neural operators, graph models, symbolic regressors, natural-law models, and laboratory planners may propose candidates against the frontier map.

A candidate has no state effect. It becomes an accepted route only after the target domain produces the required receipt and a human key accepts the transition.

```text
map -> propose -> target check -> human accept -> append -> new map
```

## 3. The central breakthrough candidate

The candidate contribution is not a universal scientific AI. It is a universal boundary between scientific search and scientific state:

> Every domain may use any search method it wants, but accepted state, gaps, transfers, and authoritative observations must compile through one intervention-aware kernel and one typed adapter contract.

This permits aggressive learned search without putting a model in the trust path. It also permits cross-domain transfer without treating source evidence as target evidence.

## 4. Why mapping frontiers can improve extension

A frontier map creates four forms of leverage.

1. **Work inheritance.** A producer begins from the current accepted state and failure memory rather than reconstructing it.
2. **Gap visibility.** Open obligations become addressable work objects with explicit discharge conditions.
3. **Frontier migration.** Discharging one obligation can expose its declared successors, so the actionable boundary moves outward rather than merely shrinking a checklist.
4. **Transfer reuse.** A certified or target-checked bridge can expose a source result to every compatible target adapter.
5. **Action selection.** Structural impact, expected information gain, cost, and downstream unlocks can be computed over the same map while remaining separate from trust.

This does not guarantee discovery. It changes the search process from repeated private reconstruction to cumulative public state.

## 5. The limits are part of the design

The system cannot infer all unknown unknowns. Gaps are relative to declared obligation generators, coverage schemas, relation types, and contexts.

The system cannot treat transfer learning as proof. Domain adaptation can fail when source and target conditionals differ even if representations look invariant. Learned transfers therefore require target checks.

The system cannot make every domain exact. Exact proofs, computational replay, instrument traces, statistical estimates, and human attestations remain different evidence classes.

The system cannot scale by expanding every provenance polynomial or enumerating every minimal environment. Production stores lineage circuits and returns query-specific proof packets.

## 6. The domain-general interface

A `DomainAdapter` is both declarative and executable. It names:

```text
domain profile and evidence ceiling
context dimensions
artifact compiler
verifier profiles
obligation generators
candidate generators
transfer lanes
observation evaluators
export surfaces
```

Adapters may be added without changing the kernel. Cross-domain bridges may be added without creating silent trust conversion.

## 7. AI and natural-law models

AI belongs in the extension layer.

Neural operators can propose maps between function spaces and interpolate across PDE parameter regimes. Symbolic regression and SINDy can propose governing equations. Universal differential equations can represent unknown terms inside known dynamics. Natural-law models can learn high-value representations or heuristics from scientific data and simulations. Graph models can suggest missing relations and transfer opportunities. Language models can extract, normalize, and propose.

Every such system emits a candidate packet with model, code, data, calibration, domain-of-validity, assumptions, and target-receipt requirements. None can append accepted state directly.

The record can later become high-quality training data for those systems because it preserves accepted routes, failed attempts, corrections, contexts, and target outcomes.

## 8. Falsification

The architecture fails as a platform strategy if domain tools prefer to export static artifacts while no external tool consumes frontier roots, obligations, transfer packets, support functions, or correction state.

The transfer thesis fails if adapter-generated bridges do not reduce repeated search or unlock accepted target results.

The gap thesis fails if obligation maps do not change what producers work on or if experts consistently reject their declared coverage universes as irrelevant.

The mission is not validated by schema count. It is validated when independent producers repeatedly read a map, extend it, and leave the next producer a better starting state.
