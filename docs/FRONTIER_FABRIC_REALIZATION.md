# Frontier Fabric: realization status

This records what of the Frontier Fabric v2.1 architecture is realized in
production Rust versus what is landed as an executable reference, and the one
consolidation decision that keeps the trust path single.

## The one-canonical decision

There is exactly **one production canonical scheme**:
`vela.canonical-json-subset.v1` (NFC, float-free, domain-prefixed sha256). The
shipped `vela-protocol::sidon_profile` and the OEIS-referenced bounds use it, so
the production record, packets, observations, and frontier-map roots all derive
from the same scheme.

The fabric reference at `research/frontier-fabric-v2/` is a self-contained
research artifact and uses its own domain tag
(`vela.scientific-state-fabric.canonical.v1`) for its own fixtures, exactly as
any reference implementation does. It is **not** in the production trust path.
The architecture (record/map/extend, typed evidence classes, no-silent-upgrade
bridges) is adopted; its canonical tag is not. This avoids forking the content
addressing the shipped slice and external venues already depend on.

## Realized in production Rust

| Layer | Where | Conformance |
|---|---|---|
| Record: canonical + signed packets | `sidon_profile::{canonical,packets}` | recompute 25 fixture ids + sigs |
| Record: kernel `Gamma_P`, four roots, environments | `sidon_profile::kernel` | replay every snapshot; trace 6,7,7,6,7 |
| Record: evaluator + observation replay | `sidon_profile::evaluator` | best-bound output + digests |
| Record: producer constructors | `sidon_profile::producer` | regenerate genesis observation/task/result byte-for-byte |
| Map: obligations + frontier map | `sidon_profile::frontier` | latent/open/discharged migration over live Sidon cells; positive-gap monotonicity |
| Surface | `vela sidon observe / submit / frontier-map` | cross-verified by the Python reference |

The `record -> map -> extend` loop is real in the shipped binary for the exact
Sidon profile: `frontier-map` shows the next bound to beat at each n;
`submit` emits the signed result pinned to the current observation; human
acceptance appends; the obligation closes by replay.

## Reference / contract only (no production Rust yet)

The broader fabric (eight DomainAdapter manifests, certified/target-checked/
exploratory transfer lanes, model and operator adapters, trace/estimate
profiles, the sharded query backend) lands as the executable reference +
conformance under `research/frontier-fabric-v2/`, gated by
`scripts/check-frontier-fabric-v2.sh`. Per the package's own landing plan, these
become production Rust only when a named producer requires them. Models stay
outside accepted state.

## Doctrine

The canonical doctrine docs (typed evidence classes and admission ceilings,
no-silent-upgrade, the `record/map/extend` split, gap-identifiability relative to
a declared obligation universe) are in `docs/FRONTIER_FABRIC_*`,
`docs/DOMAIN_ADAPTER_STANDARD.md`, `docs/FRONTIER_MAP.md`,
`docs/TRANSFER_CALCULUS.md`, and `docs/MODEL_AND_OPERATOR_ADAPTERS.md`. They make
the thesis scope boundary enforceable: the autonomous discovery loop is admitted
only for exact, in-software-verifier profiles under a cost ceiling.
