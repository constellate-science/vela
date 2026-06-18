# Scaling architecture

## 1. Denotational polynomial, operational circuit

`Γ_P : H -> N[X]` is the mathematical semantics. Production must not expand every polynomial.

The operational representation is a canonical content-addressed lineage circuit with nodes:

```text
Atom(x)
Add(children)
Mul(children)
Zero
One
```

Shared subderivations are stored once. Appending a clause adds a small number of nodes and invalidates only the forward dependency cone.

## 2. Minimal environments are query objects

Enumerating every minimal support environment can be exponential. Minimal hitting-set search is also computationally hard in general.

The production rule is:

- store the lineage circuit as the source of truth;
- materialize small antichains only when bounded;
- otherwise compile Boolean intervention semantics to a BDD, ZDD, d-DNNF, SAT, or equivalent query representation;
- return a query-specific `SupportFunctionPacket` or `HittingSetPacket` with a verifier receipt;
- never imply that an omitted environment was proved absent unless the packet certifies completeness.

## 3. Sharding

State is partitioned by stable routing keys:

```text
domain profile
context namespace
frontier id
policy or access channel
```

Each shard commits to:

```text
event-log root
presentation root
lineage-circuit root
adapter-registry root
view roots
```

A global map is a Merkle forest over shard roots. Cross-shard bridges cite exact source roots.

## 4. Incremental frontier maps

Obligation generators are deterministic indexes over accepted state and declared coverage models. On append, the system recomputes:

```text
the appended head cells
their forward dependency cones
obligations whose generators subscribe to those cells or contexts
ranks and observations affected by the changed map
```

The extension-locality theorem bounds the scientific-state recomputation. Adapter subscriptions bound the planning-layer recomputation.

## 5. Federation

Hubs exchange immutable packets and roots. They may apply different active views and ranking policies while preserving historical lineage.

Federation requires:

```text
content-addressed adapter manifests
canonical packet bytes
down-closed event dependencies
root consistency proofs
explicit forks on policy divergence
portable signer and authority policies
```

## 6. Artifact and model storage

Large artifacts, datasets, weights, raw traces, and simulations live in content-addressed object stores. Kernel packets contain roots and retrieval descriptors.

Model adapters must bind:

```text
training snapshot root
weights root
code and environment root
calibration and OOD packet ids
output artifact root
```

## 7. Query APIs

The stable API surface is small:

```text
observe(cell_or_frontier, view)
obligations(frontier, adapter_set, view)
candidates(obligation)
propose(packet)
accept(packet, human_key)
restrict(view_decision)
explain(cell, query)
```

Domain-specific convenience APIs compile to this surface.

## 8. Training exports

Constellate can produce root-bound training datasets from the state fabric:

```text
accepted routes and contexts
support/refute pairs
failed candidates and reasons
challenge and repair trajectories
obligation-to-outcome histories
transfer attempts and target checks
```

Exports carry the source roots and filter policy so models can be retrained or audited against the exact state snapshot.

## 9. Complexity honesty

The architecture does not make global scientific reasoning cheap. It makes the expensive parts explicit and cacheable.

Expected hard regions include:

```text
minimal-transversal enumeration
claim identity and ontology alignment
large cross-domain transfer search
causal identification
experimental design under model uncertainty
model evaluation under distribution shift
```

Learned ranking can prioritize these computations. It cannot remove their proof or validation obligations.
