# vela-relay

Vela Relay: the adapter layer between external scientific activity and
Vela proposals.

This crate is the library + binary packaging of the substrate's
four-adapter contract documented in
[`docs/RELAY.md`](https://github.com/vela-science/vela/blob/main/docs/RELAY.md):

| Shape | Input | Output | Backing module |
|---|---|---|---|
| `paper-to-vela` | Crossref / PubMed / Semantic Scholar / ArXiv | Carina artifact + finding proposal | `vela-protocol::source_adapters` |
| `artifact-to-vela` | ScienceClaw artifact export | artifact + finding + gap proposals | `vela-protocol::artifact_to_state` |
| `hypothesis-to-vela` | Agent discourse export | artifact + finding + review-note proposals | `vela-protocol::runtime_adapters::AGENT_DISCOURSE_V1` |
| `review-to-vela` | Agent4Science review packet | attestation proposal | `vela-protocol::runtime_adapters::AGENT4SCIENCE_REVIEW_V1` |

## Install

```bash
cargo install vela-relay
```

This installs the `vela-relay` binary. The substrate's actual
adapter logic lives in [`vela-protocol`]; this crate is the
discoverable published surface plus a library re-export of the
four-shape contract for downstream Rust users.

## Use

```bash
vela-relay list
vela-relay describe paper-to-vela --json
vela-relay version
```

For real adapter runs, use the canonical Vela CLI subcommands the
binary points at:

```bash
vela bridge-kit verify-provenance packet.json
vela artifact-to-state packet.json
vela runtime-adapter run scienceclaw-artifact-v1 --input export.json
vela runtime-adapter run agent-discourse-v1 --input discourse.json
```

## Library

```rust
use vela_relay::{AdapterShape, describe};

for shape in AdapterShape::ALL {
    let contract = describe(*shape);
    println!("{}: {}", contract.shape.slug(), contract.canonical_cli);
}
```

The crate also re-exports `vela_protocol::artifact_to_state`,
`source_adapters`, and `runtime_adapters` so downstream Rust users
can implement custom adapters against the same contract.

## Doctrine

This crate does not implement adapters itself. It exposes the
four-shape contract so the substrate's adapter ecosystem can grow
without touching the kernel crate. Adapter implementations live in
`vela-protocol`; doctrinal source of truth is `docs/RELAY.md` plus
`docs/BRIDGE_KIT.md`.

## License

Apache-2.0 OR MIT, same as the rest of the Vela workspace.
