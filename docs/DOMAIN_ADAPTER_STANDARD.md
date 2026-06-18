# DomainAdapter Standard v2

## 1. Purpose

A DomainAdapter connects a scientific domain to the shared kernel and frontier map. The adapter preserves local semantics while conforming to common state, correction, transfer, and observation rules.

A profile is declarative policy. An adapter is the executable realization of that policy.

## 2. Required interface

```text
compile(activity, profile) -> proposal packets
verify(candidate, verifier_profile) -> receipt packets
obligations(state, view, coverage_model) -> obligation packets
transfer(source_state, target_context, lane) -> transfer or candidate packets
observe(state, view, evaluator) -> observation packets
```

Human acceptance is not an adapter method.

## 3. Manifest fields

The content-addressed manifest names:

```text
adapter id and schema version
domain profile and evidence class
context dimensions
compiler id
verifier profiles and receipt kinds
obligation generators
candidate generators
allowed transfer lanes
observation evaluators
capabilities
```

Every candidate generator must declare `state_effect = none`.

## 4. Adapter correctness obligations

A conformant adapter preserves:

```text
identity      exact artifacts, receipts, and contexts are content-addressed
binding       receipts bind to the candidate and target claim
context       every context movement is explicit
rank          accepted clauses remain finite and strictly ranked
positivity    core lineage uses only alternative and joint dependence
ceiling       evidence labels do not exceed the domain profile
human control an eligible human accepts every state extension
replay        authoritative outputs bind to roots and evaluator inputs
gap provenance every obligation names its generator and coverage boundary
```


## 5. Conservative installation

An adapter is installed into a fresh profile namespace. Installing its manifest
and independent presentation must not alter lineage in any existing profile.
The conformance suite checks this by forming a disjoint union and comparing each
side's lineage before and after. Cross-profile effects require an explicit,
accepted bridge clause.

## 6. Extension points

Adapters may add:

```text
domain-specific artifact schemas
verifier plugins
coverage models
obligation subtypes
candidate-generator plugins
transfer certificates
observation evaluators
venue exporters
safety and access policies
```

They may not add a second authoritative state store or bypass append/restrict/observe.

## 7. Evidence classes

The fabric keeps the existing classes:

```text
exact
replay
trace
estimate
attestation
```

A domain may define finer coordinates inside a class. Cross-class bridges create candidates until the target class supplies its own receipt.

## 8. Adapter lifecycle

```text
draft -> conformance -> admitted -> versioned -> deprecated
```

An incompatible adapter update receives a new id. Historical packets retain the old adapter id and remain replayable.

## 9. Reference adapters

The package includes eight examples:

```text
formal mathematics
exact combinatorics
software validation
numerical simulation
model evaluation
experimental trace
observational estimate
human attestation
```

They demonstrate extensibility. They do not claim that all corresponding production systems are already integrated.
