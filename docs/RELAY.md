# Relay: adapter contract

The adapters that turn outside-Vela activity into Carina-shaped
input. A *relay* is the connector between an external system
(a paper, a runtime, a hypothesis network, a review network)
and Vela's reviewable proposal queue. The substrate ships four
adapter shapes today; this doc names the contract each one
satisfies and the existing modules that implement it.

Doctrine: a relay never writes a canonical event. It produces
proposals or content-addressed artifacts. A reviewer's signed
event is the only way a proposal becomes accepted-core.

## Four shapes

| Shape | Inbound source | Backing module | CLI verb |
|---|---|---|---|
| paper | Paper or registry record by stable id (`doi:`, `pmid:`, `nct:`) | `crates/vela-protocol/src/source_adapters.rs` (`CLINICALTRIALS_GOV_V2`, `REGULATORY_DOCUMENTS_V1`) and the `source-fetch` path | `vela source-fetch <id>`, `vela ingest doi:...` |
| artifact | ScienceClaw-shaped runtime artifact (DAG: claims, supports, openNeeds) | `runtime_adapters.rs` (`SCIENCECLAW_ARTIFACT_V1`) + `artifact_to_state.rs` | `vela artifact-to-state <packet>` |
| hypothesis | Beach-style discourse threads (claims posted as messages) | `runtime_adapters.rs` (`AGENT_DISCOURSE_V1`) | `vela runtime-adapter run agent-discourse-v1 <packet>` |
| review | Agent4Science-shape review packets (assertion id + verdict + reviewer key + evidence) | `runtime_adapters.rs` (`AGENT4SCIENCE_REVIEW_V1`, v0.76 stub) | `vela runtime-adapter run agent4science-review-v1 <packet>` |

Each row's "Backing module" produces `StateProposal` records;
the proposal queue is the single landing zone. A reviewer
adjudicates each proposal under `reviewer:<id>` (or
`agent:<id>` for an agent-drafted verdict that still needs a
human countersign in the v0.76.6 attribution doctrine).

## Contract per shape

### paper-to-Vela

**Input.** A stable identifier (`doi:`, `pmid:`, `nct:<id>`) or
a registry-shaped JSON document (e.g. ClinicalTrials.gov v2
record, regulatory document with structured fields).

**Output.** One or more `Artifact` records (kind:
`source_record`) appended to `Project.artifacts`, plus
optional `finding.add` proposals if the adapter is configured
to draft candidate findings from the source content.

**Modules.**
- `crates/vela-protocol/src/source_adapters.rs`: ClinicalTrials.gov v2,
  regulatory documents. Hash-on-fetch; cache to
  `<frontier>/sources/cache/<sha256>.json`.
- `crates/vela-protocol/src/cli.rs::cmd_source_fetch`: surface
  for raw metadata + abstract by stable id.

**Example.**
```bash
vela ingest doi:10.1038/s41586-020-2247-3 --frontier ./demo
vela ingest pmid:32451440 --frontier ./demo
vela ingest nct:NCT04639050 --frontier ./demo
```

### artifact-to-Vela

**Input.** A Carina artifact packet (`carina.artifact_packet.v0.X`)
shaped as `{artifact, candidate_claims[], open_needs[]}`. The
ScienceClaw runtime emits this shape natively; other runtimes
can wrap their output in the same packet.

**Output.** Always: an `Artifact` record applied immediately
(content-addressed, replay-safe). Optionally: `finding.add` and
`question.add` proposals for the candidate claims and open
needs, marked pending until reviewer adjudication.

**Modules.**
- `crates/vela-protocol/src/runtime_adapters.rs::SCIENCECLAW_ARTIFACT_V1`.
- `crates/vela-protocol/src/artifact_to_state.rs`: lift point
  from the kernel-interchange shape (lightweight Carina) to
  the typed pole (Rust structs in `bundle.rs`).

**Example.**
```bash
vela artifact-to-state ./demo \
    examples/bridge-kit/sample-packet.json \
    --actor agent:scienceclaw-runtime
```

### hypothesis-to-Vela

**Input.** A discourse thread shaped as a sequence of posts
where each post has an author, timestamp, claim text, and
optional citations. The Beach hypothesis network is the
canonical example; any agent-discourse runtime that produces
the same shape can flow through.

**Output.** `finding.add` proposals tagged with `agent_run`
metadata pointing back to the originating thread post id. No
artifact is applied; the discourse-thread URL is recorded as a
locator on each proposal's evidence.

**Modules.**
- `crates/vela-protocol/src/runtime_adapters.rs::AGENT_DISCOURSE_V1`.

### review-to-Vela (v0.76.2 stub)

**Input.** An Agent4Science-shape review packet:
```json
{
  "schema": "carina.review_packet.v0.1",
  "review_id": "rev_<hex>",
  "target_finding_id": "vf_<hex>",
  "verdict": "accepted" | "needs_revision" | "contested" | "rejected",
  "reasoning": "Free text explaining the verdict.",
  "reviewer": {"id": "reviewer:<name>", "type": "human" | "agent"},
  "evidence": [{"locator": "...", "span": "..."}],
  "signature": "ed25519:..."
}
```

**Output.** A `finding.review` proposal under the supplied
reviewer id, pending acceptance. The substrate does not
auto-apply the verdict; a human reviewer (or the same agent
under explicit authority) signs the accept event.

**Module.**
`crates/vela-protocol/src/runtime_adapters.rs::AGENT4SCIENCE_REVIEW_V1`
(v0.76.2 stub; the wire format is documented and a parser is
shipped, but no integration with a live Agent4Science network
is implied).

**Example.**
```bash
vela runtime-adapter run agent4science-review-v1 \
    review-packet.json \
    --frontier ./demo
```

## Doctrine guards

- **A relay never writes a canonical event directly.** Every
  outside-Vela activity lands as a proposal. Acceptance is a
  separate signed step under reviewer authority.
- **Content-addressing for artifacts is mandatory.** The hash
  binds the proposal to the exact input bytes; later disputes
  about provenance can re-derive against the same hash.
- **Actor type must be honest.** `agent:` for agent-drafted
  proposals, `human:` only when a real human is at the
  keyboard. The substrate does not enforce this; reviewer
  discipline does. See `docs/AI_ATTRIBUTION.md` (v0.76.6) for
  the doctrine.
- **Idempotency.** Re-running a relay against the same input
  must produce the same hashes and the same proposal ids
  (content-addressing makes this true automatically). A
  re-run does not duplicate proposals if the dedupe key
  matches an existing entry.

## What relays do not do

- Decide truth.
- Auto-apply truth-changing proposals (no relay opens an
  accept event under reviewer keys).
- Pull from authenticated systems without explicit credential
  configuration. The shipped adapters fetch only from public
  endpoints (ClinicalTrials.gov, PubMed, doi.org) and read
  local files for the artifact / discourse / review packets.

## Adding a new relay

The substrate's relay pattern is uniform:

1. Define the input wire format as a Carina-shaped JSON
   schema (or a `.proto` if you prefer; a JSON schema goes
   under `examples/carina-kernel/schemas/relay-<name>.schema.json`).
2. Add an entry in `runtime_adapters.rs` or `source_adapters.rs`
   under a `<NAME>_V<N>` constant + a parser function.
3. Output is always proposals or artifacts. Never canonical
   events.
4. Cover with a unit test that round-trips a sample packet
   through to expected proposal ids.
5. Document the shape here.

Cross-link from `docs/PROTOCOL.md`, `docs/CARINA.md`, and the
`vela --help advanced` listing.

## Packaging (v0.123 - v0.142)

The Relay layer ships as its own published crate:

```bash
cargo install vela-relay
vela-relay list             # enumerate the four shapes
vela-relay describe paper-to-vela --json
```

The `vela-relay` binary is the discoverable surface; it
enumerates the four adapter shapes and points at the canonical
Vela CLI subcommand that implements each. The substrate's
actual adapter logic stays in `vela-protocol`
(`source_adapters.rs`, `runtime_adapters.rs`,
`artifact_to_state.rs`), and `vela-relay` re-exports those
types so downstream Rust users can implement custom adapters
against the same contract.

The library surface is `AdapterShape::ALL` plus the
`describe(shape) -> AdapterContract` function. The binary
prints to stdout or emits a JSON envelope under `--json`.

### `paper-to-vela` (v0.142)

The first adapter shape ships an end-to-end implementation in
the binary itself:

```bash
vela-relay paper-to-vela arxiv:1706.03762
vela-relay paper-to-vela doi:10.1038/nature14539 --out vpr.json
vela-relay paper-to-vela pmid:25719668
vela-relay paper-to-vela s2:649def34f8be52c8b66281af98ae884c09aef38b
```

The command resolves the identifier through the matching
upstream registry (Crossref / ArXiv / PubMed / Semantic Scholar
respectively) and emits a `vpr_*` proposal envelope to stdout
or to `--out <path>`. The envelope shape is:

```json
{
  "schema": "vela.proposal.v0.1",
  "vpr_id": "vpr_<16-hex>",
  "kind": "paper.ingested",
  "target": { "type": "source", "id": "source:<identifier>" },
  "actor": { "id": "agent:vela-relay", "type": "agent" },
  "created_at": "<rfc3339>",
  "reason": "vela-relay paper-to-vela: <identifier> resolved via <source>",
  "payload": {
    "identifier": "<identifier>",
    "source": "crossref" | "arxiv" | "pubmed" | "semantic-scholar",
    "title": "<paper title>",
    "authors": ["<author>", ...],
    "year": <int>
  }
}
```

The `vpr_id` is `vpr_` + 16-char prefix of
`sha256(canonical_bytes(kind + target_id + payload))`; the
envelope is content-addressed by the identifier + source +
normalized metadata, so re-running the same command twice
produces the same `vpr_id` modulo Crossref / ArXiv / PubMed /
S2 returning the same metadata. A reviewer pipes the envelope
into `vela artifact-to-state` (or stores it as a reviewer
artifact) for substrate-side acceptance.

The substrate's full verifier logic — cross-source agreement,
provenance scoring, etc. — lives in
`vela bridge-kit verify-provenance` (see `docs/PROTOCOL.md`).
The `vela-relay` binary stays intentionally light; it does the
fetch + normalize + envelope step end-to-end so the discoverable
surface is real, not a contract listing.

The other three shapes (`artifact-to-vela`, `hypothesis-to-vela`,
`review-to-vela`) remain documented contracts pointing at the
canonical Vela CLI subcommands that implement each. Future
cycles may extend the binary with end-to-end paths for them
too.

## See also

- `docs/PROTOCOL.md`. The normative event semantics relays
  ultimately feed.
- `docs/CARINA.md`. The kernel primitives and JSON Schemas
  relays read and write.
- `docs/AI_ATTRIBUTION.md`. The agent-vs-human doctrine that
  shapes who can write what.
- `docs/EVENT_LOG.md`. What a reviewer sees after relay output
  becomes a canonical event.
