# Record, map, extend

## 1. One system, three responsibilities

```text
RECORD   accepted state and correction semantics          Vela
MAP      current open obligations and transfer structure  Constellate
EXTEND   candidate generation and target validation       adapters and engines
```

Keeping these responsibilities separate avoids two recurrent failures.

First, a generated hypothesis must not become accepted state merely because a model ranked it highly. Second, a database of accepted claims cannot by itself identify what is missing without a declared notion of coverage.

## 2. Record

The record is the Scientific State Kernel:

```text
P = (H, X, R, rank)
Γ_P : H -> N[X]
```

The kernel supports three lawful verbs:

```text
append    add a human-accepted route
restrict  deactivate named atoms under a signed view
observe   emit a root-bound deterministic read
```

All historical support routes remain available for audit. Restrictions do not erase history.

## 3. Map

A frontier map is a derived object:

```text
M_A(P, ν) = (Ω_A(P, ν), G_A(P, ν), bridges, failures, action descriptors)
```

It is bound to:

```text
presentation root
active-view root
adapter id and version
obligation-generator ids
frontier-map root
```

A map is not authoritative scientific state. It is a replayable planning view over state plus declared domain contracts.

## 4. Extend

An extension engine reads an observation and frontier map, then emits candidates.

```text
candidate = generator(observation, frontier_map, objective)
```

A candidate packet records the base root so stale proposals remain visible. The target adapter decides which receipts are required. A human acceptance event appends the resulting clause.

Rejected candidates may append failure memory through a separate accepted failure event. They do not disappear into agent logs.

## 5. The closed loop

```text
observe current state
  -> derive frontier map
  -> lease an obligation
  -> generate or transfer a candidate
  -> run target verifier, replay, experiment, or analysis
  -> accept or reject
  -> append result or failure
  -> recompute only the affected forward cone
```

## 6. Vela and Constellate product boundary

Vela exposes stable protocol objects, roots, replay, views, observation packets, and accepted transitions.

Constellate exposes questions, frontier maps, gaps, transfer paths, work queues, action ranks, model proposals, and venue-specific views.

Constellate may evolve rapidly. Vela remains the narrow waist.
