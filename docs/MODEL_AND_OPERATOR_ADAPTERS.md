# Model and operator adapters

## 1. Role of learned systems

Learned systems extend the search frontier. They do not define accepted state.

Every model adapter emits a `CandidatePacket` with:

```text
model class and model id
weights, code, and training-data roots
base observation and frontier-map roots
source cells and target cell
proposed artifact
assumptions and domain of validity
calibration and OOD receipts
known failure modes
required target receipts
state_effect = none
```

## 2. Neural operators

Neural operators learn maps between function spaces rather than only finite-dimensional vectors. They are useful for parametric PDEs, inverse problems, surrogate simulation, and control because one trained model can propose solutions across discretizations and parameter settings.

A neural-operator adapter should record:

```text
input and output function spaces
equation or operator family
boundary and initial-condition family
training parameter measure
discretizations and resolution range
normalization and architecture
weights and code roots
held-out operator error
residual checks
stability and conservation diagnostics
OOD detector and declared support
```

The adapter emits candidate fields or operators. A numerical or experimental target profile supplies the evidence receipt.

Universal approximation is not universal scientific validity. Operator-learning theory also contains complexity lower bounds. Performance may fail when the operator family or data distribution is too complex or outside the learned support.

## 3. Natural-law models

A Natural Law Model is a domain-specific scientific model trained on experimental data or physics-based simulations to learn underlying phenomena, useful latent structure, or high-fidelity heuristics.

Constellate treats an NLM as an extension engine with four possible outputs:

```text
candidate law or symbolic relation
candidate object or design
candidate transfer between contexts
candidate experiment or observation
```

Vela records the model lineage and target outcome. The NLM does not certify its own law.

The data contract is as important as the model contract. Training snapshots should be generated from root-bound state exports containing contexts, receipts, negative results, failed routes, corrections, and active-view policy.

## 4. Symbolic regression and SINDy

Symbolic regression and sparse identification methods can produce interpretable candidate equations from trajectories. Universal differential equations can place learned components inside partially known dynamics.

These methods are valuable gap generators:

```text
observed residual
  -> candidate missing term
  -> registered law obligation
  -> held-out prediction or experiment
  -> accepted or failed route
```

Model fit alone does not establish causal mechanism, domain invariance, or physical truth.

## 5. Graph models

Graph neural networks and representation models can operate over the frontier graph to propose:

- missing relations;
- analogous obligations;
- candidate bridge paths;
- high-fragility dependency clusters;
- likely duplicate claims;
- experimental or theorem-transfer opportunities.

Their outputs are candidate packets. Claim identity, context movement, and bridge acceptance remain signed and retractable events.

## 6. Language models

Language models are useful for extraction, normalization, schema mapping, hypothesis generation, proof search, code generation, and review assistance.

They are never a verifier or acceptance authority. A language model may propose a clause. It may not choose that the clause entered accepted state.

## 7. Generative design models

Materials, molecules, proteins, algorithms, and experimental designs can be generated against target constraints. The generated object moves through the target domain’s validation ladder.

```text
generated candidate
  -> cheap computational screen
  -> higher-fidelity simulation
  -> reproducible software receipt
  -> experiment or synthesis
  -> target observation or estimate
```

Each stage is a distinct cell and evidence class. The fabric preserves the full chain rather than promoting the original model score.

## 8. Model learning from the record

The state fabric can support three training exports:

1. **Accepted-state export:** active accepted cells and their support routes.
2. **Correction export:** challenges, retractions, repairs, and scope changes.
3. **Search export:** obligations, failed attempts, costs, and accepted outcomes.

These enable retrieval, transfer learning, active learning, and policy optimization without making the model’s predictions authoritative.
