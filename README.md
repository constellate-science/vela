# Vela

Version control for scientific state, with a gate on what counts as verified.
An open protocol and reference implementation.

Sixty seconds, no trust required:

```sh
cargo build --release
./target/release/vela reproduce examples/sidon-a309370
```

That command re-verifies every stored witness from scratch with frozen exact
verifiers — same input, same answer, on any machine, forever. No model, no
judgment, no reputation. Everything else in this repository exists to make
results that pass that bar durable, signed, and composable.

Vela compiles research artifacts (papers, notes, runs, proofs) into a versioned
*frontier*: a signed, content-addressed, replayable record of what a field
currently holds to be true. The unit it tracks is the *change* to that state,
not the document that triggered it.

Two things are separate here, and the separation is the point:

- **The log is trustworthy by construction.** Every change is signed over
  content-addressed bytes and replays to the same state on any machine. This is
  necessary, and it is not sufficient.
- **A claim only becomes *verified* by passing the gate.** Not by a proposer's
  say-so, not by an LLM judge, not by a single confirming run. The gate wants at
  least two independent matched verifier attachments — by different method and
  solver, each bound to the exact claim — plus one surviving adversarial probe.
  With zero attachments a claim sits at `needs_verification`, even after a
  reviewer accepts it.

The gate is what kept the Erdős dogfooding from banking 47 "verified" records
that carried an empty verification field. Nine Sidon-set records that did pass
it were later approved into [OEIS A309370](https://oeis.org/A309370) by an
outside editor: the first external adoption of frontier state from this
substrate.

This repository is the open core of the [Constellate](https://constellate.science)
ecosystem: the protocol, the reference reducer, the CLI, the hub, and the
conformance suite. Dual-licensed under Apache-2.0 OR MIT.

## The verification gate

A claim is `draft` by default and reaches `verified` only through
`verifier_attachment::derive_gate_status`, a pure function of the attachments
with no setter. The status cannot drift out of sync with the evidence because it
is never stored, only derived — the discipline `status_provenance` already
applies to Belnap polarity. Four conditions, each tied to a real failure it
would have caught:

- **G1 independence** — ≥2 matched attachments by *different* method/solver,
  mutually declaring `independent_of`. One self-confirmed run never suffices.
- **G2 claim-match** — every passing attachment is bound to the current claim
  digest. A proof of a *different* statement is `passed_but_unmatched` and counts
  for nothing.
- **G3 adversarial** — at least one probe present and none refuted. A refuted
  probe drives the status to `refuted`.
- **G4 well-formed** — attachments are structurally valid and content-addressed
  (`vva_…`).

Alongside it, `deliverable_grade` blocks solve-language ("resolves #647", "first
to solve") in a claim's text unless the grade is an actual solve. A bound
improvement may not call itself a resolution.

```sh
vela gate vocab                      # the grade / method / probe vocabularies
vela gate grade --claim "..." --grade improved_published_bound
vela gate check --claim "..." --attachments attachments.json
vela reproduce examples/sidon-a309370   # re-verify every stored witness from scratch
```

Verification status is orthogonal to the human review verdict and to Bayesian
confidence. A finding can be reviewer-accepted and still gate
`needs_verification`; that gap is information the substrate used to hide.

## What is here

| Path | What it is |
|------|------------|
| `crates/vela-protocol` | The reference reducer — the normative state-transition function. |
| `crates/vela-cli` | The `vela` command-line tool. |
| `crates/vela-verify` | Frozen, independent exact verifiers (Sidon, Golomb, cap, B_h, covering, constant-weight, Costas, linear codes, and the Erdős certificate kinds: interval-product #1056, CRT partial cover #203, Kummer no-carry #684, min-binom-gcd #700, binomial deficiency #1093, exception enumeration #1094) — the reference verifier registry behind the gate and `vela reproduce`. |
| `crates/vela-hub` | The federation hub: registry plus signed propose / accept. |
| `clients/` | Standalone Python + TypeScript reducers — the second and third conformance implementations of the reference reducer. |
| `bindings/` | Python HTTP SDK: a client for `vela serve --http` (read endpoints + signed write tools). Not a reducer. |
| `conformance/` | The cross-implementation test-vector suite (reducer fixtures + gate reject-vectors). |
| `examples/sidon-a309370` | A worked, re-verifiable reference: the OEIS A309370 Sidon records you can re-check with `vela reproduce`. |
| `frontiers/sidon-sets` | The external-producer on-ramp: poll `bounds.json` for the current best Sidon bound per n, beat one, and `python3 submit.py witness.json` writes a signed transition with your key. The frictionless second-signer path; see its `README.md`. |
| `lean/` | Machine-checked proofs of the governance-soundness theorems, plus `SidonCertificate.lean` (a kernel-checked vcert). |
| `schema/` | Carina kernel schemas. |

## Build

```sh
cargo build --release
./target/release/vela --help
vela completions zsh > ~/.zfunc/_vela   # shell completions (bash/zsh/fish)
```

## The working loop

```sh
vela status <frontier>          # one screen: replay verdict, proposals, leases, judgment
vela serve <frontier>           # MCP tools incl. task_packet (the agent entry contract)
vela claim <frontier> <id> ...  # lease an obligation before long work
vela reproduce <frontier>       # frozen verifiers re-check every witness
vela accept <frontier> <vpr> --key ...        # keyed authority lands state
vela attest-statement ...       # signed human faithfulness verdict (vsa_)
vela export --venue oeis|nanopub <frontier>   # venue-native projections
```

An agent may propose; only a key-holding human accepts. Failures are
signed ledger entries, not noise.

The Rust reducer is the normative reference; the Python and TypeScript reducers
track it against the conformance vectors in `conformance/`.

## Contribute to a live frontier

Anyone with a keypair can deposit a signed transition into the public registry
in one command:

```sh
vela sign generate-keypair --out ~/.config/vela/keys
vela registry propose <vfr_id> --to https://hub.constellate.science \
  --key ~/.config/vela/keys/private.key --actor reviewer:your-handle \
  --reason "..." --payload finding.json
```

A proposal is admitted to the *log* on the strength of its signature over
content-addressed bytes, never on claimed identity. Admission to the log is not
verification: the claim still has to earn `verified` at the gate above before it
counts as state a field holds to be true.

## Live

- Specification: https://constellate.science/specification
- Platform: https://app.constellate.science
- Hub / API: https://hub.constellate.science

## License

Dual-licensed under Apache-2.0 OR MIT, at your option.
