# Transfer calculus

## 1. Transfer is not one operation

Scientific transfer ranges from theorem-preserving maps to weak analogies. Treating all of it as one edge type is unsafe. The fabric uses three lanes.

## 2. Lane 1: certified transfer

A certified transfer carries a verifier-preservation proof or exact checker certificate.

```text
verified_A(o) -> verified_B(T(o))
```

Examples include:

- translating a Sidon set by a fixed vector;
- converting an exact code certificate into another exact representation under a proved construction;
- transporting a Lean theorem through a proved equivalence;
- compiling a formal specification into code together with a verified compiler theorem.

After human acceptance, the target route may inherit source verification. The route still contains the transfer and certificate atoms, so later restriction propagates.

## 3. Lane 2: target-checked transfer

A target-checked transfer uses source knowledge to propose a target artifact, but source verification does not imply target verification.

Examples include:

- a neural operator extrapolating to a new PDE parameter regime;
- a model-generated material evaluated by DFT or experiment;
- a theorem suggesting an algorithm that must pass software tests;
- a simulation proposing an experimental intervention;
- transfer learning from one dataset or population to another.

The target adapter names the required receipts. The target cell receives its evidence class only after those receipts pass and a human accepts the transition.

## 4. Lane 3: exploratory transfer

An exploratory transfer is a hypothesis, analogy, candidate bridge, experiment plan, or search heuristic. It has no state effect.

This is the default lane for language-model analogies, graph embeddings, unsupervised domain adaptation, and natural-law hypotheses when no target check has occurred.

## 5. Why learned transfer needs a target check

A representation can look invariant across domains while the conditional relation required for the task changes. Domain-adaptation theory and counterexamples show that source accuracy plus marginal representation alignment is not sufficient under conditional shift.

A learned transfer packet therefore records:

```text
source and target domains
source and target contexts
model and data roots
assumed invariances
support or overlap diagnostics
known conditional shifts
calibration and OOD receipts
required target receipts
```

The protocol never interprets “transferable embedding” as “preserved scientific truth.”

## 6. Transfer composition

Certified transfers compose inside the verifier-preserving category.

Target-checked and exploratory transfers compose only as candidate paths. Each target boundary retains its own receipt requirement. A chain cannot skip an intermediate check by citing a strong source.

```text
formal theorem
  -> algorithm candidate
  -> software replay receipt
  -> simulation candidate
  -> numerical replay receipt
  -> experiment candidate
  -> instrument trace
```

Each arrow retains its source lineage. Each new evidence class comes from the target domain.

## 7. Transfer leverage

A transfer is valuable when one verified source route can discharge or cheaply generate many target obligations.

A scheduling projection may estimate:

```text
transfer_leverage = expected downstream obligations discharged / target verification cost
```

This is a decision metric, not a trust coordinate. It must be computed from a root-bound frontier map and declared target costs.

## 8. Fixture

The conformance fixture exercises two lanes:

1. `certified`: componentwise translation of `{0,1,4}` to `{10,11,14}` preserves the Sidon property.
2. `target_checked`: a neural-operator candidate for a heat-equation parameter cell remains state-neutral until a semantic replay receipt passes and a human accepts it.
