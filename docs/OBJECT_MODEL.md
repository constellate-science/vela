# Vela — the object model

*What the words mean. A node, an edge, a finding, a frontier, an anchor, a
transfer, the atlas. Written once because the question keeps coming back: what is
a finding versus a node versus all the other stuff.*

## The one line

A node is a dot someone else drew. A finding is a result Vela personally checked.

Everything below is that distinction, made precise.

## The six words

**node** — a pin on the map. A known object, ingested from a source: an OEIS
sequence, a Mathlib declaration, an Erdős problem. Cheap to make, so there are
many (about 809k). A node is a *claim of existence*, nothing more. When a node is
labeled "verified" it usually means the source it came from was already checked
(Mathlib's kernel proved that declaration), not that Vela did anything. Ingesting
a node copies a fact. It does not vouch for it.

**edge** — a wire between two pins. `A depends on B`, `A implies B`, `A reduces to
B`. This is the connective tissue: the Mathlib declaration-dependency graph, the
module import graph, the cross-source identity joins, the cross-problem
reductions. Edges are what make "mapping the frontier" real rather than a field of
unconnected dots. An edge between two Lean declarations is admissible only if the
proof actually invokes the premise (kernel-checkable, never asserted).

**finding** (`vf_`) — a result Vela itself ran through a frozen verifier and a
human key-custody accept, with full provenance and a deterministic replay. This is
the trusted layer, and it is deliberately small (about 2,541) because each one
costs a verification anyone can re-run. A finding is not a node that got promoted.
It is a different kind of object: a node is "this exists in a corpus"; a finding
is "Vela re-checked this and will stand behind it."

**frontier** (`vfr_`) — a governed domain. A question (Sidon sets, the Erdős
corpus, the formal-conjectures Lean repo) together with its findings, its open
obligations, and its append-only signed event log. The frontier is the unit of
governance: state changes only through accepted events on its log.

**anchor** (`val_`) — a signed cross-namespace identity link. The join key. When
an OEIS sequence and an Erdős problem are the same mathematical object, an anchor
says so, and the atlas merges them into one cell. Two grades: `HardIdentity` (the
same object, merge them) and `SearchOnly` (a candidate, surface it, never
auto-merge). The hard grade is reserved for the unambiguous cases.

**transfer** (`vtr_`) — a verifier-homomorphism. A result proved in one domain
discharging a premise of an open problem in another, checked by a kernel theorem,
not asserted. Six exist; lighting them up is the moat work.

## The derived layer

**atlas** — the projection over all of it. `atlas::project` runs union-find over
the anchors plus context and produces the cells, the cross-source joins, the
field rollups, the blast-radius cascades. The atlas is **derived**: it is
regenerated from the authoritative log, never edited by hand, never the source of
truth. If the atlas and the event log disagree, the log wins and the atlas is
rebuilt.

## Authoritative versus derived

The single most important split. Two of these you can never lose without losing
truth; the rest you can throw away and rebuild from them.

| layer | objects | status |
|---|---|---|
| **authoritative** | the event log, finding bundles (`vf_`), signed anchors (`val_`), signed transfers (`vtr_`) | the source of truth; signed; append-only; replayable byte-for-byte |
| **derived** | atlas cells, edges, blast-radius, Belnap status, the κ provenance weight | regenerable projections; a pure function of the authoritative layer |

A node is mostly the cheap end of this table: an ingested pin whose trust, if any,
is borrowed from its source. A finding is the expensive end: a result that carries
its own verification.

## Why the map looked small

The honest diagnosis (2026-06-22): about 809k nodes but, for a long time, only
about 1,624 edges and about 2,541 findings. The map was almost all pins and almost
no wires, and the one question a producer actually asks ("what is the most
attackable open target?") had no command. The fix was never "ingest more nodes."
Nodes are cheap and already plentiful. The work is edges (the connective graph),
queryability (`vela attack`, `vela explore`), and wiring what is already ingested
into the view. The trusted finding layer stays small on purpose: it is the part
Vela personally checked.

## One-primitive discipline

Findings, links, and anchors only. Do not invent a new object type per source (the
founder-abstraction-trap). A new science is a new frontier with the same three
states (known / attackable / dark) and the same join kinds, not a new schema. The
atlas stays a pure derived projection. No fabricated edges.

## See also

- [PROTOCOL.md](PROTOCOL.md) — the normative wire spec: events, bundles, ids.
- [THEORY.md](THEORY.md) — the formal core and the frontier calculus.
- [CANON.md](../../../docs/CANON.md) — the front door and the canonical set.
