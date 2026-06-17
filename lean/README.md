# Vela — Lean theorem formalization

A Lean 4 / Mathlib project: the machine-checked core of the Vela substrate. The
numbered substrate guarantees, the frontier-calculus suite, and the cross-domain
transfer chain are all kernel-checked with no `sorry` and no `axiom` beyond
Lean's standard `propext` / `Classical.choice` / `Quot.sound` (audited by
`Vela/AxiomAudit.lean`).

## Layout

Modules are grouped by domain under `Vela/`:

| dir | what it holds |
|---|---|
| `Vela/Protocol/` | state, replay, log, reducer, provenance, canonical ordering |
| `Vela/Crypto/` | signing, signatures, multi-sig, canonical/event/frontier ids, checkpoints, attestation |
| `Vela/Accumulation/` | proof-carrying accumulation: folding, sumcheck, PoVD, the protocol keystone |
| `Vela/Governance/` | proposals, diff packs, governed quorum, verdict conflicts, owner epochs, descriptors |
| `Vela/Transfer/` | the cross-domain transfer chain (binary-code → CWC → DNA, classical → CSS, …) |
| `Vela/Frontier/` | the frontier calculus |
| `Vela/Constructions/` | verified math construction certs (Sidon — the OEIS A309370 cert, Erdős-Ginzburg-Ziv) |

`Vela/CoreTheorems.lean` (the theorem aggregator) and `Vela/AxiomAudit.lean`
(the `#print axioms` harness) stay at the `Vela/` root. `Vela.lean` is the build
root and imports the aggregator, the frontier calculus, and the Sidon certificate.

## Build / verify

```bash
cd lean && lake build      # builds Vela.lean and its closure
```

`lake build` is incremental once Mathlib is cached. The full bundle is the
machine-checked half of the trust story; the frozen Rust verifiers
(`vela reproduce`) are the other half.
