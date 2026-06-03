# Vela

Version control for scientific state. An open protocol and reference
implementation.

Vela compiles research artifacts (papers, notes, runs, proofs) into a versioned
*frontier*: a signed, content-addressed, replayable record of what a field
currently holds to be true. The unit it tracks is the *change* to that state,
not the document that triggered it.

This repository is the open core of the [Constellate](https://constellate.science)
ecosystem: the protocol, the reference reducer, the CLI, the hub, and the
conformance suite. Dual-licensed under Apache-2.0 OR MIT.

## What is here

| Path | What it is |
|------|------------|
| `crates/vela-protocol` | The reference reducer — the normative state-transition function. |
| `crates/vela-cli` | The `vela` command-line tool. |
| `crates/vela-hub` | The federation hub: registry plus signed propose / accept. |
| `crates/vela-atlas` `-constellation` `-relay` `-scientist` `-search` | Composition, federation, ingest adapters, and query. |
| `bindings/`, `clients/` | Python and TypeScript reducers. |
| `conformance/` | The cross-implementation test-vector suite. |
| `lean/` | Machine-checked proofs of the governance-soundness theorems. |
| `schema/`, `schemas/` | Carina kernel schemas. |

## Build

```sh
cargo build --release
./target/release/vela --help
```

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

A proposal is admitted on the strength of its signature over content-addressed
bytes, never on claimed identity.

## Live

- Specification: https://constellate.science/specification
- Platform: https://app.constellate.science
- Hub / API: https://hub.constellate.science

## License

Dual-licensed under Apache-2.0 OR MIT, at your option.
