# vela-verify

Frozen, independent **exact verifiers** for combinatorial and
coding-theory witnesses.

A discovery proposer (human or agent) is untrusted: it returns an explicit
construction, and this crate re-checks it deterministically before any
claim is recorded. Corrupting a witness must fail the verifier — that is
the property the tests pin. A passing verify here is the evidence an
`exact_construction` verifier attachment attests to in the trust gate
(`vela_protocol::verifier_attachment`), and the kernel `vela reproduce`
re-runs from scratch.

The verifiers are pure (no I/O, no randomness) and dependency-light (serde
only), so a third party gets byte-identical verdicts.

## Verifiers

| kind | check |
|------|-------|
| `sidon` | `{0,1}^n`, all pairwise sums distinct |
| `golomb` | integer marks, all pairwise differences distinct |
| `cap` | `F_3^n`, no three points collinear |
| `bh` | `{0,1}^n`, all `h`-fold sums distinct |
| `covering` | `C(v,k,t)`, every `t`-subset covered |
| `constant_weight` | `A(n,d,w)`, weight `w`, pairwise distance `>= d` |
| `costas` | permutation, displacement vectors distinct |
| `linear_code` | `[n,k,d]_q` (q prime), min weight `>= claimed_d` |

## Witness format

```json
{ "kind": "sidon", "n": 8, "points": [[0,1,1,0,0,0,1,1], ...], "claimed_size": 33 }
```

`claimed_size` (where present) is cross-checked: the construction must
pass AND have exactly that many elements, so a record can't claim a larger
set than the witness it ships.

Ported from the campaign's `scripts/verify_construction.py`; the Python
reference and this Rust port agree on every witness.
