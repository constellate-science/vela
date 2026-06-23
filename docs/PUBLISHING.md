# Publishing Vela frontiers

This document defines the public release path for frontier state. It
covers three distribution surfaces:

- GitHub release artifacts: immutable files, proof packets, manifests,
  and checksums.
- Hub mirror: signed transport for a live `vfr_*` entry.
- Optional dataset-style mirror: a Hugging Face dataset repository or
  equivalent archive carrying the same release pack.

The local frontier remains the authority. A mirror helps other people
find and verify state. It does not make the science true.

## Contents

- Current reference package
- GitHub release artifact pack
- Checksum verification
- Hub mirror
- Optional dataset-style mirror
- Citation
- License
- Release gate
- Verify Vela yourself (5 minutes, no trust required)
- Verified results ledger
- Frontier PR: the knowledge pull request
- Sidon Producer Profile v1

## Current reference package

The public demo frontier in this repository is:

```text
examples/sidon-a309370/
```

It is the public subset of the Sidon-set frontier of record (OEIS
A309370): verified witnesses plus the replay machinery to re-check
them. Read these files first:

- `examples/sidon-a309370/README.md`
- `docs/PROTOCOL.md` (the wire spec)
- `docs/VERIFICATION.md` (when a claim earns `verified`)

## GitHub release artifact pack

Build the binary and prove the package replays before assembling
release assets:

```bash
cargo build --release --bin vela

# every claimed construction re-checks from the stored witnesses
./target/release/vela reproduce examples/sidon-a309370

# frontier quality + strict signals
./target/release/vela check <frontier> --strict --json

# export a proof packet for the release
./target/release/vela proof <frontier> --out /tmp/<frontier>-proof-packet
```

A release pack is a directory of immutable files with a top-level
checksum manifest. The minimum set:

- the frontier state file (`frontier.json` or the frontier repo archive)
- the proof packet (`tar -czf <frontier>-proof-packet.tar.gz ...`)
- `CITATION.cff`
- `LICENSE-APACHE`, `LICENSE-MIT`
- `SHA256SUMS` (`shasum -a 256 <files> > SHA256SUMS`)

Use a GitHub release when you want a citable frozen package. Upload
the files as release assets for the matching tag.

## Checksum verification

Every release pack has a top-level `SHA256SUMS` file. Verify before
using the pack:

```bash
shasum -a 256 -c SHA256SUMS
```

Then validate the proof packet:

```bash
tar -xzf sidon-a309370-proof-packet.tar.gz
vela verify sidon-a309370-proof-packet   # replay + hash + signature check
```

This proves that the packet is internally replayable and hash-bound.
It does not prove the claims matter; it proves they are what was
signed.

## Hub mirror

The public hub mirrors signed frontier state:

```text
https://hub.constellate.science
```

For a fresh frontier file, publish with:

```bash
vela sign generate-keypair --out keys
vela actor add ./frontier.json reviewer:you \
  --pubkey "$(cat keys/public.key)"

vela registry publish ./frontier.json \
  --owner reviewer:you \
  --key keys/private.key \
  --to https://hub.constellate.science \
  --json
```

For split frontier repositories, materialize and lock before
publishing a snapshot:

```bash
vela frontier materialize <frontier>
vela lock <frontier>
vela check <frontier> --strict --json
vela proof <frontier> --out /tmp/<frontier>-proof
```

The hub can withhold or go stale. It should not be treated as the
scientific authority. Consumers should verify with `vela registry pull`,
`vela check`, and `vela verify`.

## Optional dataset-style mirror

A Hugging Face mirror is optional. Treat it as a dataset-style
distribution of the same GitHub release assets, not a different source
of truth. Mirror the release pack bytes unchanged, including
`SHA256SUMS`, `CITATION.cff`, and both license files, and write the
dataset card to:

- Lead with the frontier scope and current claim boundary.
- Link the GitHub release tag that produced the mirror.
- Include the checksum verification commands.
- Preserve the license fields from the frontier manifest.
- State that hub mirrors are transport, not authority.

## Citation

For software metadata, start with `CITATION.cff`. For a frontier
release, also cite the release tag plus the frontier state:

```text
Vela contributors. <Frontier name>. Vela release <tag>. Frontier
state package, proof packet, and review trail.
```

Include:

- GitHub release URL.
- Hub `vfr_*` entry if published.
- Snapshot hash from the proof packet manifest.
- Access date for mirrors.

Do not cite Vela as resolving the science. Cite it as a reviewable
frontier state package.

## License

Repository code is dual-licensed Apache-2.0 OR MIT. See
`LICENSE-APACHE` and `LICENSE-MIT`.

Frontier manifests declare their own content/data licenses, for
example:

```yaml
license:
  content: CC-BY-4.0
  code: Apache-2.0
  data: varies
```

Source papers and external data retain their original terms. Vela
stores source identity, locators, evidence spans, and artifact
records; it should not redistribute license-restricted source bytes
unless the artifact license permits it.

## Release gate

Before publishing:

```bash
cargo test --workspace
python3 conformance/verify.py
vela check <frontier> --strict --json
vela reproduce examples/sidon-a309370
```

The gate is intentionally boring: replay, conformance, strict checks.
If any step fails, the packaged artifacts may still be useful for
review, but the release is not certified.

## Verify Vela yourself (5 minutes, no trust required)

The public-facing path for a consumer who wants to check, not trust, the released state.

You do not need to trust the authors, read the papers, or rerun any discovery. This section lets you check
the core of Vela on your own machine, and then try to break it.

### The one idea

A scientific claim is routable across domains only through a **machine-checked verifier-homomorphism**:
a transfer `T : A → B` is admitted only when Lean proves `V_A(x) ⇒ V_B(T(x))`. So verified knowledge
composes and travels across fields, and an invalid claim cannot be laundered across a boundary, because
the bridge is a theorem. Frozen verifiers are the only trust anchor; everything else is a proposer.

### Check the core (one command)

```
./scripts/full-conformance.sh --mode=ci
```

It builds the frozen Rust verifiers, re-verifies every stored witness from scratch (`vela reproduce`),
runs the Lean build (the transfer and keystone theorems must compile, or the gate fails), and asserts the
Python and Rust trust gates agree on the frozen conformance vectors. Exits 0 only if all of that holds on
your machine. Read the canonical six files it rests on (`docs/CANON.md`) and you have read Vela.

### Re-verify a result directly

The witnesses are content-addressed JSON; the verifier trusts neither us nor the producer. Re-check any
frontier from scratch with the frozen Rust verifiers:

```
vela reproduce examples/sidon-sets        # 18/18: every pairwise-sum set recomputed, all distinct
vela reproduce examples/erdos-problems    # 21/21: each Erdős certificate re-checked from the witness
vela gate check <finding-id>              # the trust-gate status for one finding
```

(If `vela` is not on your path, build it once: `cargo build -p vela-cli --release`, then use
`./target/release/vela`.) For the Lean proofs alone: install `elan`, then `cd lean && lake build`.

### Try to break it

We want adversarial attempts. A successful break is one where the gate **accepts** something it
shouldn't:

- forge a native witness (a "Sidon set" that isn't, an interval-product certificate with a wrong prime):
  edit a file under `examples/sidon-sets/witnesses/` and re-run `vela reproduce` on it;
- tamper a transfer's target so it differs from `map(source)`;
- launder: get an invalid claim into one frontier and route it into another across a transfer edge.

If you find an accept that should be a reject, that is a real bug and we want it. If you cannot, the gate
held.

### What we are asking

Not agreement, not endorsement. One thing: re-verify a claim you care about, in a domain with a checkable
verifier, and see whether checking a witness is easier than trusting a PDF or rerunning the work. If it
is, you have used the protocol, and that, not any proof, is what turns this from a verified core into
infrastructure.

### Honest scope

Verified core, not a finished product. Most frontier verifiers are exact integer/combinatorial checks,
not arithmetic circuits. Witnesses are JSON, not yet a hardened wire format. The succinct
proof-of-state-validity layer (the PCK keystone) is proven in Lean (`lean/Vela/Accumulation/ProtocolKeystone.lean`) but
the cryptographic instantiation is a research residual. The one thing no proof can supply is the one we
are asking you for: an outside user.

## Verified results ledger

What the system has actually produced and machine-checked, with the re-verify command for each line.

Everything the system has actually produced and **machine-checked**, with the command to re-verify each
line yourself. Categorized honestly: what beats a cited external baseline, what is a machine-checked
certificate, and what is a proven cross-frontier transfer. Nothing here asks for trust; every line is
checkable on your own machine.

**Re-verify the whole verifiable core in one command:**

```
./scripts/full-conformance.sh --mode=ci
```

It builds the frozen Rust verifiers, re-checks every stored witness from scratch (`vela reproduce`),
runs the Lean build, and asserts Python↔Rust gate parity. Or re-check a single frontier directly:

```
vela reproduce examples/sidon-sets        # 18/18 Sidon witnesses
vela reproduce examples/erdos-problems    # 21/21 Erdős certificates
```

The always-current results surface is the live [`/results`](https://app.constellate.science/results) page,
which folds over the signed record and external registries (nothing self-reported, nothing counted by hand).

### A. Constructions that exceed a cited external baseline (Sidon A309370)

Maximal Sidon subsets of `{0,1}^n` (all pairwise sums distinct). The lower bounds below were re-verified
from scratch by the frozen `sidon` verifier and the improvements over the OEIS best-known bounds were
web-confirmed (`docs/history/SIDON_A309370_CONFIRMED.md`); n=8..24 are now **OEIS-accepted** on A309370.

| n | a(n) ≥ | Cited OEIS baseline | Check |
|---|---|---|---|
| 16 | 505 | 472 (+33) | `vela reproduce examples/sidon-sets` |
| 17 | 712 | 662 (+50) | (same; re-verifies all 18 witnesses) |
| 18 | 1010 | 864 (+146) | (same) |

The verified ladder runs a(7)=24, a(8)=33, a(9)=47, a(10)=66, a(11)=92, a(12)=133, a(13)=185, a(14)=257,
a(15)=364, a(16)=505, a(17)=712, a(18)=1010, a(19)=1435, a(20)=1989, a(21)=2694, a(22)=3770, a(23)=5179,
a(24)=7179. Each witness re-verifies its full pairwise-sum set from scratch (e.g. a(24): 7179 points,
25,772,610 sums all distinct). Canonical witnesses live in `examples/sidon-sets/witnesses/*.witness.json`;
the public OEIS mirror is [willblair0708/verified-combinatorics](https://github.com/willblair0708/verified-combinatorics).

### B. Machine-checked certificates (Erdős problems)

Exact certificates for cells on Erdős problems, each re-checked by a frozen Rust verifier kind from the
witness alone (`vela reproduce examples/erdos-problems`, 21/21):

| Problem | Certificate | Kind |
|---|---|---|
| #1056 (k=5..14) | consecutive intervals with product ≡ 1 mod p (p = 71 … 10,428,007) | `interval_product` |
| #1093 | deficiency table (ELS93 + three new examples), Kummer-defined δ recomputed exactly | `binom_deficiency` |
| #1094 | exception-set enumeration, 142,469 candidates checked for k ≤ 40, exception set of 14 matches exactly | `binom_exception_enum` |
| #203 | partial CRT cover, 20 prime rows verified | `crt_partial_cover` |
| #617 | balanced 2-coloring of K₅, all 10 triples see both colors | `balanced_coloring` |
| #684 | f(Mₖ−1) > k for 10 values of k, zero Kummer carries | `kummer_no_carry` |
| #700 | f(n) = min gcd(n, C(n,k)) verified for 11 cases | `min_binom_gcd` |
| (PHP) | UNSAT certificate, empty clause derived by RUP (LRAT) | `unsat_cert` |

These are verified certificates for specific cells, not solutions to the open problems; the problems
themselves remain open (the certificates bank exact, re-runnable evidence on the attacked sub-cases).

### C. Machine-checked transfers (Lean, no `sorry`/`axiom`)

Cross-frontier verifier-homomorphisms whose soundness is proven, so a verified result on the source is a
verified result on the target. This is the moat: knowledge that is routable because the bridge is a
theorem, and an invalid claim cannot be laundered across a boundary. Re-check with the Lean build
(`cd lean && lake build`, or the gate's `lean-build` tier).

| Transfer | Theorem | File |
|---|---|---|
| Sidon ⇄ Golomb (both directions) | `sidon_to_golomb_sound`, `golomb_to_sidon_sound` | `lean/Vela/Transfer/Transfer.lean` |
| ConstantWeightCode → DNACode | `cwcToDna` | `lean/Vela/Transfer/TransferCWCtoDNA.lean` |
| Packing → CWC (→ DNA) | `packingToCWC`, `packingToDNA` | `lean/Vela/Transfer/TransferPackingToCWC.lean` |
| BinaryCode → CWC (fixed-weight filter) | `binCodeToCWC`, `binCodeToDNA` | `lean/Vela/Transfer/TransferBinaryCodeToCWC.lean` |
| Costas array → Golomb ruler | `costas_to_golomb` | `lean/Vela/Transfer/TransferCostasToGolomb.lean` |
| Sylvester Hadamard → CWC (weight n/2, distance n/2) | `weight_eq`, `distance_eq` | `lean/Vela/Transfer/TransferHadamardToCWC.lean` |
| OA → CWC (one-hot; weight k, distance 2·col-diffs) | `onehot_weight`, `onehot_distance` | `lean/Vela/Transfer/TransferOAtoCWC.lean` |
| Constant-weight family → d-disjunct (group testing) | `packing_is_disjunct` | `lean/Vela/Transfer/TransferPackingToDisjunct.lean` |
| Classical codes → CSS quantum code (Hx·Hzᵀ=0) | `css_commute` | `lean/Vela/Transfer/TransferClassicalToCSS.lean` |
| MDS/Reed–Solomon → threshold secret sharing | `shares_determine_polynomial`, `secret_recovered` | `lean/Vela/Transfer/TransferMDSToSecretSharing.lean` |
| Hypergraph product → valid quantum-LDPC code (any classical H) | `hgp_css_precondition` | `lean/Vela/Transfer/TransferHypergraphProduct.lean` |
| Hypergraph product over any char-2 commutative ring | `hgp_css_precondition_ring` | `lean/Vela/Transfer/TransferHypergraphProductRing.lean` |
| Lifted/balanced product → valid CSS | `lifted_css_precondition` | `lean/Vela/Transfer/TransferLiftedProduct.lean` |

The group-testing transfer (`packing_is_disjunct`) reaches from pure math into a verified pooling design
for non-adaptive diagnostics: a constant-weight family with intersection ≤ λ is d-disjunct whenever
dλ < w. Math into medicine, with the same verifier-homomorphism discipline.

### D. Protocol guarantees (Lean-proven)

| Guarantee | Theorem | File |
|---|---|---|
| One constant-size check certifies the whole cross-frontier DAG | (keystone) | `lean/Vela/Accumulation/ProtocolKeystone.lean` |
| Transfers never launder an invalid claim across frontiers | (hetero-accumulation soundness) | `lean/Vela/Accumulation/HeteroAccumulation.lean` |
| Loader = reducer (state is a fold over the signed log; no silent drops) | — | `vendor/vela/crates/vela-protocol` (`verify_replay`) |

`AxiomAudit.lean` guards the proof library against stray `sorry`/`axiom` in the load-bearing theorems;
the `lean-build` gate tier fails on a broken proof.

### E. Quantum-code frontier

The deep frontier lives as a canonical Vela frontier at `projects/quantum-codes/.vela` (browse it on the
platform, or `vela frontier audit projects/quantum-codes`). Stabilizer/CSS codes are admitted only when a
classical input meets the Lean-proven CSS precondition `Hx·Hzᵀ = 0` (`TransferClassicalToCSS.lean`,
`TransferHypergraphProduct.lean`, `TransferLiftedProduct.lean`), so a verified classical code becomes a
verified quantum code by the proven route, not by trusted search. Honest scope: the recorded codes are
frozen-verified and within the quantum Singleton bound; the five-qubit `[[5,1,3]]` meets the bound with
equality (provably distance-optimal). Beating best-known tables for non-MDS parameters is the open
research residual, not a claim made here.

### Historical (Canopus Python-era, consolidated)

An earlier program ran the same verifier-gated discipline as a body of Python scripts: cross-domain gates
across seven scientific domains (RNA structure, molecular optimization, materials stability, single-cell
benchmarks, ADMET, protein function), a PMO discovery loop, the cross-frontier "constellation"
amplification, and a full PCK/KTP succinct-proof-of-state protocol stack. That work was consolidated in
commit `cca007958` (the cut-over to the frozen Rust verifiers + `vela reproduce`). Its **proven core
survives** as the Lean library (`lean/Vela/`, 74 proofs, including the folding and sum-check soundness
cores `FoldingSoundness.lean` / `SumcheckSoundness.lean`) and the canonical frontiers; the demonstration
scripts were retired. The narrative of that program is preserved in `docs/history/` and the git history.

### How to challenge any of this

A successful break is the gate **accepting** something it should reject. Tamper a stored witness (flip a
point in a Sidon set, alter an interval-product certificate) and run `vela reproduce` on its frontier: the
frozen verifier must reject it. Forge a transfer's target so it differs from `map(source)`; try to route
an invalid source claim into another frontier. If you find an accept that should be a reject, that is a
real bug and we want it. See the full adversarial guide in §Verify Vela yourself (5 minutes, no trust required). If you cannot, the
result stands.

## Frontier PR: the knowledge pull request

The verb for proposing a change to frontier state, the shape every release and hub write follows.

A **Frontier PR** is the name for what Vela already does: a proposed change to
what a frontier's record says, that earns its way in through checks and review
before it becomes accepted state. It is the GitHub pull-request shape applied to
scientific frontier state. No new mechanism; this names the existing flow so
agents and contributors have a verb.

```
knowledge change → Frontier PR → verification checks → review → accept → frontier state update
```

### The flow, by command

1. **Open it.** A proposed transition is a signed `vpr_` proposal.
   - Local: `vela propose <frontier> <vf_id> --status accepted --reviewer reviewer:you --reason "…"`
     (or `vela note` / `vela finding add` without `--apply` to leave it pending).
   - Over the wire to the hub: `vela registry propose <vfr_id> --to https://hub.constellate.science --key <key> --actor reviewer:you --reason "…" --payload finding.json`.
   - The proposal is content-addressed and signed over the exact canonical bytes
     the hub re-derives. Admission to the *log* rests on the signature, never on
     claimed identity.

2. **Check it.** The PR carries its verification, not a promise of it.
   - A construction ships a `*.witness.json`; `vela reproduce` re-checks it with
     the frozen verifiers. A claim with ≥2 independent matched verifier
     attachments + a surviving probe derives `verified` at the gate
     (`vela gate check`); with zero, it sits at `needs_verification` even after a
     reviewer accepts it.
   - A formal claim carries a faithfulness attestation
     (`vela attest --scope formalism-fidelity`) so the formal statement is
     attested to match the informal one.

3. **Review it.** A scoped human decision is the merge authority.
   - `vela proposals list <frontier> --status pending_review`, then
     `vela proposals accept <frontier> <vpr_id> --reviewer reviewer:you --reason "…"`
     (or `reject`). Review is scoped: an `attest` records exactly what was
     checked ("I reviewed the LRAT certificate, not the reduction"), never a bare
     "approved."

4. **Merge it.** The accept is the signed canonical event; the frontier's state
   is the deterministic replay of its event log including that event.

### What is a Frontier PR right now

The 105 LLM-drafted semantic edges sitting in
`examples/erdos-problems` as pending `note` proposals are open Frontier PRs:
attributed to their producer, carrying their justification, and explicitly *not*
adjudicated until a reviewer accepts each one. That is the shape: proposed,
checkable, reviewable, never auto-merged, never an AI signature.

### Why it is not just a wiki edit

A wiki edit overwrites. A Frontier PR is a *typed, signed state transition* with
its verification attached and its review scoped, replayable forever, and
reversible only by another recorded event (a `supersede` or a `ResolutionEvent`),
never by silent overwrite. The history of what was tried, what failed, and what
was disputed is preserved, because the log is the state.

## Sidon Producer Profile v1

The certificate-kind constraints behind the A309370 reference package: how an accepted lower bound is shaped, gated, and replayed.

### 1. Scope

This profile applies the finite, positive, ranked Scientific State Kernel to one live frontier: lower bounds for OEIS A309370, Sidon sets in the binary cube.

It does not define a new general scientific protocol. It constrains existing Vela operations for one certificate kind whose verifier is exact and inexpensive.

### 2. State model

A profile presentation contains two ranked cell kinds:

```text
rank 0: verified-witness(artifact_digest)
rank 1: lower-bound(n, k, support)
```

An accepted result emits two positive clauses:

```text
verified-witness(w)
  <- artifact(w)
     · verifier_A(receipt_A)
     · verifier_B(receipt_B)
     · probes(probe_receipts)
     · gate(g)
     · acceptance_event(e)

lower-bound(n,k)
  <- verified-witness(w)
     · statement(claim_digest)
     · rule(sidon-lower-bound-v1)
```

The compiler derives:

```text
Γ_P : H -> N[X]
```

Alternative accepted witnesses add polynomial terms. Joint dependencies multiply. The production implementation may store a canonical circuit, but its interpretation must equal the expanded fixture semantics.

### 3. Three lawful verbs

#### 3.1 Append

A human-signed `AcceptancePacket` appends an accepted event and its two clauses. Append may add historical lineage. It may not remove earlier events, clauses, or monomials.

#### 3.2 Restrict

A `ChallengePacket` is a proposal and has no state effect. A human-signed `ViewDecisionPacket` applies a named atom substitution under a view policy.

Restriction changes:

```text
active_view_root
active support environments
observed frontier values
```

Restriction does not change:

```text
presentation_root
circuit_root
historical lineage_root
```

#### 3.3 Observe

An `ObservationPacket` is an authoritative read only when it carries:

```text
presentation_root
circuit_root
lineage_root
active_view_root
evaluator_id
evaluator_inputs
canonical_output
replay_receipt
```

The replay receipt commits to the input-root digest, evaluator digest, and output digest.

### 4. Root-pinned work

Every `TaskPacket` carries a `base_state` commitment:

```text
observation_id
presentation_root
circuit_root
lineage_root
active_view_root
evaluator_id
evaluator_inputs_digest
canonical_output_digest
```

A `ResultPacket` must repeat this object byte-for-byte. The gate may not rewrite it.

### 5. Staleness

Acceptance compares the result's base observation with the current decision observation.

Allowed outcomes are:

```text
fresh
stale_revalidated_as_improvement
stale_revalidated_as_confirmation
```

There is no silent rebase. A stale result that is neither a current improvement nor an explicitly allowed confirmation is rejected.

The conformance fixture issues two tasks at the same root. Producer A lands first. Producer B's size-7 result is then accepted only as `stale_revalidated_as_confirmation` against the new root.

### 6. Verification gate

The result artifact is bound to a claim digest and artifact digest. The reference gate requires:

1. pair-sum uniqueness by hash-set membership;
2. pair-sum uniqueness by base-3 encoding, sorting, and adjacent comparison;
3. distinct method families;
4. distinct executable source digests;
5. exact claim and artifact digest match;
6. rejection of duplicate-point, claimed-size, and semantic pair-sum-collision negative controls.

This is **algorithmic diversity**, not proof of statistical or organizational independence. Production policy may impose stronger separation.

### 7. Support functions and correction

`env(Γ_P(h))` gives the minimal assumption environments for a cell.

A `SupportFunctionPacket` carries both historical and active minimal environments. A challenge set kills a target exactly when it hits every active minimal environment at the challenged root.

A challenge remains non-authoritative until a reviewer accepts a `ViewDecisionPacket`.

A repair occurs through one of two lawful operations:

- append a newly accepted alternative environment; or
- issue a separate human view decision that re-enables previously disabled atoms under policy.

The fixture uses the first. The `RepairPacket` explains restoration but does not itself mutate lineage.

### 8. Packet identity and signature

The packet body excludes `packet_id` and `signature`. Values are encoded with the profile's canonical JSON subset:

```text
null, Boolean, integer, NFC string, array, string-keyed object
```

Floats are forbidden.

The packet ID is a full SHA-256 content identifier. The Ed25519 signature covers a domain-separated preimage containing the packet ID and canonical body. Unknown schema versions and unknown packet fields fail closed.

### 9. Operational packets versus scientific state

Tasks and leases coordinate work but do not alter scientific state. Results, gate receipts, and challenges are proposals or evidence. Historical state changes only through accepted append events. Active state changes only through accepted view decisions. Reads become authoritative only through ObservationPackets.

### 10. Conformance

A conformant implementation must reproduce the fixture's roots and trace:

```text
6 -> 7 -> 7 -> 6 -> 7
```

It must also reject the negative no-hidden-state fixture and preserve historical lineage across restriction.

### 11. Rust realization (status)

The profile is realized in Rust at `crates/vela-protocol/src/sidon_profile/`
(modules `canonical` · `packets` · `kernel` · `evaluator` · `producer`) and
surfaced through `vela sidon`. Every layer is conformance-pinned to the Python
reference and to the landed fixtures:

- **canonical + packets** — recompute all 25 fixture packet IDs and re-verify
  every Ed25519 signature (`tests/sidon_profile_conformance.rs`).
- **kernel + evaluator** — replay each snapshot's four roots, canonical output,
  and digests; reproduce the `6,7,7,6,7` trace; the restrict-kill and
  append-repair through the bag-lineage environments
  (`tests/sidon_profile_kernel_conformance.rs`).
- **producer** — `make_support_function` / `make_observation` / `make_task` /
  `make_result` regenerate the genesis observation, task, and result *byte for
  byte*, signatures included (`tests/sidon_profile_producer_conformance.rs`).

`vela sidon submit WITNESS --base-observation OBS --key K --actor A` emits the
signed `ResultPacket` a producer proposes; `vela sidon observe --presentation P
--key K --actor A` emits the authoritative `ObservationPacket` (which replays
from the presentation it names). Both sign with the caller's own key. Packets
emitted by the Rust CLI are accepted by the independent Python
`verify_signed_packet`.

Not yet realized in Rust: the reviewer-side constructors
(gate/acceptance/challenge/view/repair) — where the **production gate runs the
frozen `vela-verify` Sidon verifier**, not the fixture's hashed Python
executables; the live-frontier reducer (accepted findings → presentation); and
the hub observation endpoint that mints `bounds.json` carrying the observation
id.
