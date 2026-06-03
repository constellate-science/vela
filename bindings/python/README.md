# vela-python

Python SDK for [Vela](https://github.com/vela-science/vela) v0.5+ — a single-file
client for `vela serve --http`.

## Install

The SDK is a single Python module. Add `bindings/python` to your `PYTHONPATH` or
copy `vela/__init__.py` into your project. Dependencies: `requests`,
`cryptography`.

```bash
pip install requests cryptography
```

A `pip install vela-python` flow ships in a later release; for now the canonical
import path is the file in this directory.

## Quick start

Start a local Vela frontier server:

```bash
vela serve frontiers/bbb-alzheimer.json --http 3848
```

Use the SDK to read state and write signed proposals:

```python
from vela import Actor, Frontier

# An actor's identity = stable id + Ed25519 private key.
# Register via `vela actor add <frontier> <id> --pubkey <hex>` first.
actor = Actor.from_hex_key(
    actor_id="reviewer:will-blair",
    private_key_hex=open("./private.key").read().strip(),
)

f = Frontier.connect("http://localhost:3848")

# Reads — no identity required.
print(f.stats())
hits = f.findings(query="amyloid", limit=5)

# Writes — every call carries a signed canonical preimage.
proposal = f.propose_review(
    finding_id="vf_08c81dd507f6a047",
    status="contested",
    reason="conditions narrower than claim",
    actor=actor,
)
print(proposal.id, proposal.status)

# Apply a pending proposal.
event_id = f.accept(proposal.id, reviewer=actor, reason="reviewed and accepted")

# Stream new events past a cursor (for agent loops).
cursor = None
for event in f.events_since(cursor):
    print(event.kind, event.target.id)
    cursor = event.id
```

## Doctrine

- **Idempotency is a substrate property.** `propose_*` calls are idempotent at
  the substrate layer: a retry with identical content (same actor, target,
  reason, payload) returns the same `vpr_…` and the server returns the
  existing record without duplicating state. This is intentional —
  agent loops can retry safely without per-call deduplication logic.
- **Signing is the bind.** Every write is signed by a registered actor's
  Ed25519 key. Unsigned or wrong-signature requests are rejected by the
  server. The SDK signs locally; the key never leaves the calling process.
- **Canonical JSON is normative.** The SDK and the Rust kernel both
  derive `vpr_…` and signatures from the same canonical-JSON preimage rule
  (sorted keys at every depth, no whitespace, finite numbers, UTF-8
  verbatim). Two implementations agree byte-for-byte; the conformance
  validator at `scripts/cross_impl_conformance.py` proves it.

## See also

- `examples/python-agent/extract_and_propose.py` — end-to-end paper →
  Claude extraction → finding proposal pipeline.
- `docs/MCP.md` — the underlying MCP/HTTP tool reference.
