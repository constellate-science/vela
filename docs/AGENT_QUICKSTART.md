# AI-agent quickstart

This document describes the on-ramp for an AI agent that wants to read frontier state and draft proposals against a Vela frontier. The substrate-honest contract: every agent-drafted truth claim flows through the same reviewer-gated discipline as every other proposal. No agent has a privileged write path.

Humans reviewing a frontier should start at the verification gate ([VERIFICATION.md](VERIFICATION.md)) and the [publishing guide](PUBLISHING.md); this is the agent on-ramp.

## Contents

- One-command scaffold (v0.131)
- Workflow
- Produce a witness with the discovery engine
- Key management for the agent
- Doctrine
- Learn Vela in ten minutes
- MCP server
- Frontier Context Protocol (FCP)
- Python SDK (vela-agent)
- CLI JSON contracts
- See also

## One-command scaffold (v0.131)

```bash
vela agent init <slug> --framework <name>
```

Where `<slug>` is a lowercase-alphanumeric-hyphens name and `<name>` is one of:

- `claude-code`: agent running inside Claude Code CLI
- `claude-api`: agent driving the Anthropic API directly
- `langchain`: LangChain-shaped agent
- `openai`: OpenAI Assistants / function-calling shape
- `agent4science`: Agent4Science review-packet emitter
- `scienceclaw`: ScienceClaw artifact-packet emitter
- `custom`: none of the above

This produces a portable kit under `agents/<slug>/`:

```
agents/test-bot/
├── actor.json        # the substrate-side actor record
├── agent.yaml        # framework config + workflow notes
└── keys/
    ├── private.key   # Ed25519 private key
    └── public.key    # Ed25519 public key (64 hex chars)
```

`actor.json` carries:

```json
{
  "schema": "vela.agent_kit.actor.v0.1",
  "id": "agent:test-bot-2026-05-10",
  "public_key": "<64 hex chars>",
  "algorithm": "ed25519",
  "actor_type": "agent",
  "created_at": "2026-05-10T12:34:56+00:00",
  "framework": "claude-code",
  "name": "test-bot"
}
```

The `agent:<slug>-<date>` id is the canonical form. The substrate makes the `agent:` prefix load-bearing via the v0.76.6 AI-attribution doctrine; agent-drafted proposals carry it on `actor.id`, and the reviewer's verdict carries `reviewer:` on the accepting event.

## Workflow

### 1. Register the agent in a target frontier

A human reviewer on the target frontier reads `actor.json` and registers the agent:

```bash
vela actor add <frontier> 'agent:test-bot-2026-05-10' \
  --pubkey <64-hex-public-key>
```

The agent now has the right to draft proposals against `<frontier>`. It does not have the right to accept its own proposals; that is the reviewer's exclusive privilege.

### 2. Read frontier state through MCP

```bash
vela serve <frontier>           # stdio JSON-RPC (MCP)
vela serve <frontier> --http 3848    # HTTP variant
```

The MCP server exposes a 19-tool catalog covering:

- `frontier_stats`: counts, replay state, signals, proof readiness
- `search_findings`: text / entity / assertion-type query
- `get_finding`: single-finding detail incl. evidence + lineage
- `list_events`: cursor-paginated canonical event log
- … plus 15 others. See "§MCP server" for the full table.

The agent's existing MCP client (Claude Code, Claude Desktop, etc.) configures the connection per `vela serve --setup`.

### 3. Draft proposals

Two paths:

**Through the CLI:**

```bash
vela propose note <frontier> <vf_id> \
  --text "Agent note text" \
  --author 'agent:test-bot-2026-05-10'
```

The proposal lands in the frontier's `.vela/proposals/` as a pending entry under the agent's actor id.

**Through HTTP (when `vela serve --http` is running):**

POST `/api/propose-note` with the canonical preimage signed by the agent's private key. The signature is verified server-side against the registered `public_key`; unsigned or wrong-signature posts are rejected.

### 4. Wait for human verdict

The proposal sits in `vela inbox <frontier>` until a reviewer adjudicates. Acceptance writes a signed canonical event under the reviewer's identity; the agent's proposal becomes part of replayable state. The substrate's truth-claim discipline does not promote agent-drafted assertions without a signed human verdict.

## Produce a witness with the discovery engine

For verifier-gated construction kinds, you do not need to hand-write a witness; the discovery engine searches for one and verifies it in the same step:

```bash
# search and report (writes nothing)
vela foundry campaign search rook_directions --n 16
# search, write the verified witness, and propose it (pending; no key needed)
vela foundry campaign run gf2_sidon --n 12 --frontier <frontier> --propose --as <agent-id>
```

Searchable kinds: `gf2_sidon`, `union_free`, `rook_directions`, `sidon`, `bh` (with `--h`), `golomb`, `costas`. The search is deterministic (the same `--seed` reproduces the same witness), and every find is re-checked by the frozen `vela-verify` before it is reported, so a reported find always passes `vela reproduce`. `--propose` lands a key-free `finding.add` that waits for a human verdict (step 4); it does not promote the claim. The engine certifies lower bounds: it extends the less-explored ranges and will under-perform the algebraic optima behind the largest records, which is exactly where a stronger search wins.

## Key management for the agent

The Ed25519 private key in `agents/<slug>/keys/private.key` is the agent's signing credential. Treat it like a deployment secret:

- Never commit `keys/` to a public repository. The substrate's `.gitignore` excludes `keys/` and `*.key` patterns globally (THREAT_MODEL.md A17).
- If the key is compromised, rotate it via the substrate's standard primitive:
  ```bash
  vela actor rotate <frontier> \
    --id 'agent:test-bot-2026-05-10' \
    --new-id 'agent:test-bot-2026-05-15-v2' \
    --new-pubkey <new-64-hex> \
    --reason "Key rotation: agent infra rotation"
  ```
  Historical signatures by the retired key remain valid in canonical history; new signatures are rejected by the signals layer (`post_revocation_signature` blocker, v0.127).

## Doctrine

- **The substrate makes the agent-draft / human-verdict distinction load-bearing.** Every event carries `actor.type` ∈ `{human, agent}`. Reviewers always know whether they are looking at an agent's claim or another reviewer's claim.
- **Agents have no privileged accept path.** Their proposals flow through the same review queue as a human reviewer's proposals.
- **Cryptographic identity is required.** An agent's keypair is what binds its signature to its actor id. Without the keypair, the agent cannot sign; without the registered public key, the substrate rejects the signature.
- **Confidence is bounded.** Agent-drafted proposals can claim any confidence the framework supplies; the substrate's truth-claim discipline does not promote the claim to accepted state until a reviewer's verdict says so.

## Learn Vela in ten minutes

The short orientation walkthrough, ported from LEARN.md. It uses the live Erdős frontier.

Vela is version control for scientific state: signed append-only event logs per research frontier, deterministic replay, frozen verifiers, and human judgment recorded as signed objects.

### Sixty seconds: verify what we claim

The public `examples/` ship the witness sets, so `vela reproduce` works straight
from a clone. The full event log (for `check`, `status`, and `serve`) lives in
the frontier's git repo (`constellate-science/vela-frontiers` for the canonical
examples); `git clone` it — the committed `.vela/events` is the authority.

```bash
cargo build --release --bin vela            # in vendor/vela
vela reproduce examples/erdos-problems      # frozen verifiers re-check every witness (32/32)
vela reproduce examples/sidon-sets          # and the Sidon witnesses (18/18)
# then, against a frontier cloned from the hub:
vela check  <frontier>                      # full event-log replay
vela status <frontier>                      # one-screen truth
```

`reproduce` re-verifies every banked witness (Sidon sets, LRAT certificates, balanced colorings) from scratch in under a second, with nothing to trust. `check` replays the full event log through the one reducer and confirms the materialized state matches byte-for-byte; it runs against the maintained frontier, which carries the 1,200+ signed events the public witness set summarizes.

### Ten minutes: the working loop

1. **Read the frontier.** `vela status` shows replay health, pending proposals, live leases, and signed judgment counts. Problem pages render the same state at app.constellate.science/erdos/617 (append `/packet.json` for the machine twin).
2. **Pull a task packet.** `vela serve examples/erdos-problems` exposes MCP tools; `task_packet` for a problem number returns the statement, allowed outputs mapped to verifiers, banked do-not-regrind routes, and open targets ranked by what rests on them.
3. **Coordinate long work out-of-band** (an issue, a claim comment); the CLI lease verb is retired.
4. **Produce a state transition.** A witness that passes `vela reproduce`, a finding proposed via `vela propose`, or a signed attempt (failures included: they are ledger entries, not noise).
5. **Authority is custody.** An agent may propose; only a key-holding human accepts (`vela accept --key`). Statement fidelity is a separate signed verdict (`vela review --fidelity …`): the kernel proves the formal statement follows; only a human attests it is the problem anyone meant.

### The objects

| Prefix | Object | Trust |
|---|---|---|
| `vsx_` | scratch blob | none (content-addressed parking) |
| `vat_` | signed attempt | provenance only |
| `vpr_` | pending proposal | shape-validated |
| `vf_`  | accepted finding | replay-verified, receipt archived |
| `vsa_` | statement attestation | human-signed judgment |
| `vtr_` | verifier-homomorphism transfer | Lean-audited |

Everything else (docs/PROMOTION_LADDER.md, docs/VERIFICATION.md, docs/MIRROR.md) builds on this loop.

## MCP server

The full tool catalog and transport contract, ported from MCP.md.

`vela serve` exposes the Vela substrate as an MCP server (JSON-RPC 2.0, spec v2024-11-05) and as an HTTP API. Same tools, two transports.

The server runs on stdio for MCP clients (Claude Desktop, Claude Code, any spec-compliant client) and on HTTP when invoked with `--http <port>`.

### Connection

#### MCP stdio
```bash
vela serve examples/erdos-problems
```
Wire to a Claude Desktop config or any MCP-aware host.

#### HTTP
```bash
vela serve examples/erdos-problems --http 3848
```
Endpoints listed below.

### Tools

The server registers 18 tools. Read tools require no identity. Write tools require the caller to be a registered actor (`vela actor add`) and to sign the canonical preimage with the actor's Ed25519 key.

#### Read tools (10)

| Tool | Purpose |
| --- | --- |
| `frontier_stats` | Counts, confidence distribution, gaps, categories. |
| `search_findings` | Free-text + entity/type filter over findings. |
| `get_finding` | Full finding bundle by id. |
| `list_gaps` | Findings flagged as gap review leads. |
| `list_contradictions` | Contradiction/dispute links. |
| `find_bridges` | Cross-domain entities (≥N categories). |
| `check_pubmed` | Rough PubMed prior-art count. |
| `apply_observer` | Rerank findings under a policy. |
| `propagate_retraction` | Simulate cascade impact (read-only). |
| `trace_evidence_chain` | Evidence lineage for a finding. |

#### Phase Q-r read tool (1)

| Tool | Purpose |
| --- | --- |
| `list_events_since` | Cursor-paginated read over the canonical event log. Used by agent loops to learn outcomes; used by public consumers to track diffs. |

#### Phase Q-w write tools (6)

Each requires `actor_id` + `target_finding_id` (or `proposal_id`) + `reason` + `signature`. The `signature` is hex-encoded Ed25519 over the canonical preimage of the proposal (or decision action).

| Tool | Purpose |
| --- | --- |
| `propose_review` | Create `finding.review` proposal (`status` ∈ accepted/approved/contested/needs_revision/rejected). |
| `propose_note` | Attach a `finding.note` annotation. Optional `provenance: {doi?, pmid?, title?, span?}` (Phase β, v0.6). |
| `propose_and_apply_note` | One-call propose+apply for `finding.note`. Requires `actor.tier="auto-notes"` (Phase α, v0.6). |
| `propose_revise_confidence` | `finding.confidence_revise` with `new_score` ∈ [0,1]. |
| `propose_retract` | `finding.retract` (cascade-emitting on apply). |
| `accept_proposal` | Apply pending proposal as the registered reviewer. |
| `reject_proposal` | Reject pending proposal. |

Idempotency is a substrate property (Phase P): retrying a `propose_*` with identical content returns the same `vpr_…` and the server returns the existing record without duplicating state. Same property holds for `propose_and_apply_note`: identical content yields the same `vpr_…` and the same `applied_event_id`.

**Tier-gated auto-apply (Phase α, v0.6).** `propose_and_apply_note` is the only `propose_and_apply_*` variant in v0.6, by design. Tiers permit review-context kinds only; never state-changing kinds. See [`docs/TIERS.md`](history/TIERS.md) for the doctrine.

### HTTP endpoints

```
GET  /api/frontier            — full project view (findings, sources, events, ...)
GET  /api/findings?query=...  — markdown-formatted search results
GET  /api/findings/{id}       — single finding bundle
GET  /api/proof               — proof freshness, packet hashes, readiness
GET  /api/contradictions      — contradiction links
GET  /api/observer/{policy}   — reranked findings under a policy
GET  /api/propagate/{id}      — simulated retraction cascade
GET  /api/hypotheses          — cross-domain entity bridges
GET  /api/stats               — frontier stats summary
GET  /api/frontiers           — (multi-frontier mode) list all frontiers
GET  /api/pubmed?query=...    — PubMed prior-art lookup
GET  /api/events?since=…&limit=…  — cursor-paginated event log read (Phase Q-r)
POST /api/queue               — append unsigned draft action (Phase R)
GET  /api/tools               — tool registry (17 tools)
POST /api/tool                — RPC-style tool invocation (read or write)
```

Write semantics: `POST /api/tool` with `{"name": "<write_tool>", "arguments": {...}}`. Each write tool's argument schema is in `tool_registry.rs`.

### Regression gate (v0.130)

`scripts/test-mcp-server.sh` exercises the MCP stdio interface end-to-end against a fresh quickstart frontier. Four checks:

1. `initialize` handshake returns the expected `protocolVersion` and `serverInfo.name == "vela"`.
2. `tools/list` returns ≥ 5 tools including `frontier_stats`, `search_findings`, `get_finding`.
3. `tools/call frontier_stats` returns a structured response with `data.events.count >= 1` for the quickstart frontier.
4. An unknown method returns the JSON-RPC error code `-32601` (Method not found) per the spec.

The gate spawns `vela serve <frontier>` as a subprocess and drives stdio JSON-RPC from a small Python harness. Pinned into `run-all-gates.sh` quick + full sets.

### MCP doctrine

- **Reads are open.** No auth on read tools/endpoints. Agents and public consumers use the same surface.
- **Writes are bound.** Every write requires a registered actor's signature over the canonical preimage; unsigned or wrong-signature requests are rejected.
- **Canonical JSON is normative.** Two implementations of the protocol must produce byte-identical signing bytes and content-addressed IDs; the conformance vectors at `tests/conformance/` and the Python validator at `scripts/cross_impl_conformance.py` pin this property.

## Frontier Context Protocol (FCP)

The query surface of the frontier compiler, ported from FRONTIER_CONTEXT_PROTOCOL.md: structured questions over signed scientific state, the way a Language Server answers structured questions over code.

### Why this exists

Code-intelligence systems (LSP, CodeGraph, CodeQL) earned their leverage by giving an agent an **external symbolic map** instead of a pile of text: it stops scanning blindly and starts asking precise questions, *go to definition*, *find references*, *call hierarchy*, *diagnostics*. Vela is the same move for science. A frontier is compiled into typed, provenance-bearing, verifier-aware state (an event log reduced to a `FrontierState`, projected to a `FrontierGraph`), and the FCP is the protocol an agent speaks to that state.

The FCP is not a new wire format. It is a **naming** of the tool surface that already exists, exposed over MCP (`vela serve`), so the capability set is legible and complete rather than an undifferentiated bag of 40+ tools. Each tool is one question; the table below is the contract.

### The capability map

LSP gave editors a fixed vocabulary of questions. Here is the frontier equivalent, mapped to the tools that answer it. Tool names are exact (`vendor/vela/crates/vela-edge/src/tool_registry.rs`); handlers live in `vendor/vela/crates/vela-cli/src/serve.rs`.

| LSP capability | Frontier question | Tool(s) |
|---|---|---|
| Hover / quick-info | Brief me on this problem without re-reading handoff prose | `frontier_explore`, `task_packet`, `context` |
| Go to definition | Resolve this claim / finding and its state | `get_finding`, `frontier_explore` |
| Find references | What evidence supports this, what uses it | `trace_evidence_chain`, `list_dependents`, `search_findings` |
| **Call hierarchy** | **What this rests on, what rests on it (the dependency hierarchy / blast radius)** | **`blast_radius`**, `deep_trace`, `list_dependents`, `find_bridges` |
| Type hierarchy | Generalize / specialize lineage; line claims up against shared properties | `frontier_graph` (generalizes/specializes), `frontier_compare` |
| Diagnostics | Contradictions, gaps (unproven obligations), staleness, single points of failure | `contradictions`, `list_contradictions`, `list_gaps`, `frontier_explore`, `blast_radius` |
| Workspace symbols | Search every frontier object, not just documents | `search_findings`, `frontier_stats`, `find_bridges` |
| Document history | The event lineage of a finding; what changed since a checkpoint | `get_finding_history`, `list_events_since` |
| Code action (propose) | Propose a note, revision, review, retraction; submit to the hub | `propose_note`, `propose_revise_confidence`, `propose_review`, `propose_retract`, `propagate_retraction`, `vela_agent_propose_to_hub`, `vela_agent_submit_diff_pack` |
| Accept / reject (the gate) | Key-holder accepts or rejects a proposed transition | `accept_proposal`, `reject_proposal` |
| Interop export | Emit a claim as a nanopublication-shaped unit | `nanopublication` |
| Agent contract | The entry pack, evaluations, conflicts, trajectories for an agent run | `task_packet`, the `vela_agent_*` family |

The newest entry is **`blast_radius`** (this is the dependency-impact / call-hierarchy question the memo flagged as the first "wow"): given a finding, it returns what it rests on (upstream support), what rests on it (downstream, the impact if it moved), and the **single points of failure** on its support, the minimal set whose removal collapses it. Reachability is directional over the typed support edges (`supports`, `depends_on`, `derived_from`, `discharges`); the dominators come from `FrontierGraph::support_dominators`. CLI mirror: `vela atlas blast-radius <frontier> <finding> [--impact up|down|both]`. The same question is a gesture on the map (`/atlas/math/map`): select a node and its blast radius lights up, cool for what it rests on, warm for what it lifts.

The impact is read through the **frontier calculus**, not by counting nodes. The center carries its canonical bilattice status `(support κ, refute κ)` from `derive_status_provenance`, and each dependent's support κ is min-propagated along the *required*-premise edges (`depends_on`/`derived_from`/`discharges`) using the kernel's **Bottleneck semiring** ("a chain is as strong as its weakest premise"). The center's support is then retracted (κ → 0, the retraction theorem), κ is recomputed, and `delta_kappa` is the true drop. A dependent reachable only through corroborating `supports` is *not* a bottleneck, so its Δκ is 0 and it is pruned: the calculus removes what mere reachability overcounts. `support_killed` marks a dependent the center is a single point of failure for (κ → 0).

### Authority ranking (what an agent should trust)

The FCP is not "better RAG." Retrieval is ranked by **epistemic authority**, and the high-authority tiers are graph and provenance queries, not vector recall:

1. Accepted state transitions, passing verifier attachments, signed reviews (the gate).
2. Validated extractions, canonicalized claims, schema-valid evidence atoms.
3. Vector / similarity recall, unreviewed summaries, heuristic edges.

An agent answers from tiers 1–2 first (exact id, graph traversal, provenance path) and only falls to raw artifact reading when the structured layer cannot answer. Every FCP tool that returns a relation carries an honest claim boundary: edges are **declared links, candidates, not adjudicated truth**, and structural impact (a result being in a blast radius) is **not** a claim that the result is wrong.

### Boundaries

- **Read vs write.** Tools carry a `PermissionLevel`; the read tier never mutates state. The write tier (`propose_*`) only ever creates a *proposed* transition. **No AI is in the trust path**: a proposal is unsigned and pending until a key-holder runs `accept_proposal`, which signs with a custody key an AI does not hold.
- **The graph is a projection.** Every FCP answer is recomputed from the event log on read; nothing here is a mutable store of truth. A better reducer later yields better answers from the same events.
- **Scope.** The protocol is domain-general, but the discovery loop it serves fires only where a cheap, deterministic verifier exists (formal math, combinatorics, benchmark replay). See `docs/CORE_DOCTRINE.md`.

### Relation to the memo

This formalizes §3.3 ("LSP as a product clue") and §13 ("Agent interface") of the codegraph memo, grounded in the tools that exist rather than aspirational ones. The section-by-section reconciliation of that memo against the built substrate is in [`MEMO_RECONCILIATION.md`](history/MEMO_RECONCILIATION.md).

## Python SDK (vela-agent)

For agents that want to emit signed substrate artifacts directly from Python, ported from AGENT_SDK.md.

Status: v0.196. Composes the [v0.193 Scientific Diff Pack](../crates/vela-protocol/src/scientific_diff.rs), [v0.194 Trajectory taxonomy](../crates/vela-protocol/src/bundle.rs), and [v0.195 Agent Attestation envelope](../crates/vela-protocol/src/agent_attestation.rs).

The SDK lets any LLM agent (Claude, Codex, a Python-orchestrated bench tool) submit a coherent change-set to a Vela frontier in roughly five lines. Mirrors the substrate's canonical-bytes id derivation and Ed25519 signing exactly, so a Python-emitted `vsd_*` or `vaa_*` verifies byte-for-byte under the Rust `vela` CLI; there is a regression test (`test-agent-sdk.sh`) that builds a pack with the Python SDK and verifies it with the Rust binary on every cycle.

### Install

```
pip install vela-state==0.196.0
```

`vela_agent` ships in the same wheel as `vela-state`. The single dependency is `pynacl` (for Ed25519). Python 3.10+.

### Five-line shape

```python
from nacl.signing import SigningKey
from vela_agent import VelaAgent

agent = VelaAgent(
    model_name="claude-opus-4.7",
    model_version="claude-opus-4.7-20260411",
    frontier_path="examples/erdos-problems",
    signing_key=SigningKey.generate(),
    actor="agent:literature_scout",
)
agent.open_run(prompt="reconcile sister findings on the same Erdős problem")
agent.add_proposal(kind="finding.add", payload={...})
agent.record_tool_call(tool_name="search_arxiv", input_obj={...}, output_obj={...}, duration_ms=420)
vaa_id, vsd_id = agent.submit_diff_pack(summary="...", aggregate_kind="finding.cluster_revision")
```

`submit_diff_pack` does four things atomically:

1. Closes the open run.
2. Builds and signs a `vaa_*` Agent Attestation envelope (pins model, version, tool calls, output hashes, prompt hash).
3. Bundles every proposal queued under the run into a `vsd_*` Scientific Diff Pack and signs it.
4. Writes both records plus per-proposal stubs under the frontier's `.vela/` tree.

Resulting layout:

```
.vela/
  agent_attestations/<vaa_id>.json   # signed vaa_*
  diff_packs/<vsd_id>.json           # signed vsd_* carrying agent_run=vaa_*
  proposals/<vpr_id>.json            # SDK-shape proposal stubs
  trajectories/<vtr_id>.json         # optional: from open_trajectory(...)
```

### What the SDK does not do

Substrate-honesty: every claim runnable or rejected.

- **The SDK does not vouch for correctness.** It packages, signs, and writes. A reviewer still reads the Diff Pack and accepts or rejects through the same keyed accept path a human-authored proposal flows through.
- **Proposal stubs are not canonical proposals yet.** They carry an SDK-derived `vpr_*` id and the original payload. The Diff Pack references them by id; the actual reducer-side `proposal.submitted` event is emitted when a downstream tool (a future `vela propose --from-sdk-stub` arm) walks the stub directory.
- **No auto-acceptance.** v0.196 ships the producer side. The reviewer side remains the v0.174 review-thread surface plus the v0.198 (next cycle) `/diff-packs/[id]` detail page.
- **No agent-runtime integration.** The SDK is harness-agnostic: it does not run Claude or wire up MCP servers. You orchestrate the model; the SDK records what happened.

### Trajectory helpers

The full v0.194 step taxonomy (Question, Context, Data, Tool, Model, Expert, Decision, Protocol, Output, Review, Risk, Outcome, plus the five legacy kinds) is available through `open_trajectory`:

```python
from vela_agent import open_trajectory
from vela_agent.primitives import TrajectoryStepKind

traj = open_trajectory(target_findings=["vf_..."], deposited_by="agent:literature_scout")
traj.append(kind=TrajectoryStepKind.QUESTION, description="Does X replicate?")
traj.append(kind=TrajectoryStepKind.TOOL, description="search_arxiv for ...")
traj.append(kind=TrajectoryStepKind.MODEL, description="claude drafted under vaa_*", references=[vaa_id])
traj.append(kind=TrajectoryStepKind.OUTPUT, description="diff pack submitted", references=[vsd_id])
traj.save_to_frontier("examples/erdos-problems")
```

The `references` field on a step can hold any kernel-object id; the SDK does not enforce that the citation resolves on the receiving frontier (that's a substrate-side concern handled by the v0.194 taxonomy gate).

### Three example agents

All three are runnable as `python -m vela_agent.examples.<name> <frontier_path> --frontier-id vfr_...`:

- **literature_scout**: proposes a new finding from a sample arxiv abstract. Records two tool calls + opens a small trajectory citing both the `vaa_*` and the `vsd_*`.
- **replication_checker**: opens a trajectory with the full Question / Protocol / Data / Tool / Output / Review path and submits an `evidence.refresh` Diff Pack.
- **correction_proposer**: submits a `correction.batch` pack with two proposals: a confidence revision and a contradicting-evidence pointer.

### Cross-impl pin

The substrate ships two pinned constants the Python SDK must reproduce:

- `crates/vela-protocol/src/scientific_diff.rs::cross_impl_python_sdk_pinned_id` asserts `vsd_cd2a0071e7ffbffd` for a fixed (frontier_id, proposals, summary, aggregate_kind, created_at).
- `crates/vela-protocol/src/agent_attestation.rs::cross_impl_python_sdk_pinned_id` asserts `vaa_db61cc709fc3e69b` for a fixed input + an all-zeros signing key.

The Python tests at `clients/python/vela_agent/tests/test_primitives.py` assert the same constants. Any byte-level drift in either implementation flags on the next gate run.

## CLI JSON contracts

The stable `--json` output contracts, ported from CLI_JSON.md. These contracts are for machine consumption by tests, demos, agents, and release automation, for the strict core Vela release.

JSON output MUST be:

- valid UTF-8 JSON on stdout only
- free of ANSI color, progress text, tables, and prose wrappers
- one top-level JSON object per command
- deterministic for the same frontier input and command arguments, except for explicitly documented generated timestamps
- conservative about candidate outputs: gaps, tensions, bridges, observer views, and prior-art checks are navigation signals, not scientific conclusions

Errors MUST be emitted on stderr and use a non-zero exit code. If a command can produce a structured JSON error, it SHOULD use:

```json
{
  "ok": false,
  "command": "check",
  "error": {
    "code": "frontier_load_failed",
    "message": "Failed to load frontier"
  }
}
```

The successful top-level envelope is:

```json
{
  "ok": true,
  "command": "stats",
  "schema_version": "0.2.0",
  "frontier": {
    "name": "erdos-problems",
    "source": "examples/erdos-problems",
    "hash": "sha256:..."
  }
}
```

`frontier.hash` is the SHA-256 digest of the canonical frontier state used by the command. For a monolithic `frontier.json`, hash the file bytes. For a frontier directory, hash the deterministic manifest of included frontier files: relative path, byte length, and file SHA-256, sorted by relative path.

### `vela status <frontier> --json`

Returns aggregate frontier metadata and statistics.

```json
{
  "ok": true,
  "command": "stats",
  "schema_version": "0.2.0",
  "frontier": {
    "name": "erdos-problems",
    "description": "Erdős problems frontier",
    "source": "examples/erdos-problems",
    "hash": "sha256:...",
    "compiled_at": "2026-04-22T00:00:00Z",
    "compiler": "vela/0.2.0",
    "papers_processed": 10,
    "errors": 0
  },
  "stats": {
    "findings": 48,
    "links": 121,
    "replicated": 12,
    "unreplicated": 36,
    "avg_confidence": 0.742,
    "gaps": 7,
    "negative_space": 2,
    "contested": 4,
    "human_reviewed": 3,
    "review_event_count": 1,
    "confidence_update_count": 0,
    "source_count": 10,
    "evidence_atom_count": 48,
    "condition_record_count": 48,
    "categories": {
      "mechanism": 24,
      "therapeutic": 9
    },
    "link_types": {
      "supports": 73,
      "contradicts": 5,
      "depends": 18
    },
    "confidence_distribution": {
      "high_gt_80": 11,
      "medium_60_80": 30,
      "low_lt_60": 7
    }
  }
}
```

Stable fields are `frontier`, `stats`, and all nested stat keys shown above. Maps such as `categories` and `link_types` MAY contain additional keys.

### `vela bridge-kit validate <packet-or-dir> --json`

Validates one `carina.artifact_packet.v0.1` packet or every JSON packet in a directory. Validation checks schema, packet identity, producer identity, artifact locators, content hashes, parent references, candidate-claim evidence references, and open-need fields. It writes nothing to the frontier.

```json
{
  "ok": true,
  "command": "bridge-kit.validate",
  "source": "examples/bridge-kit/packet.json",
  "packet_count": 1,
  "valid_packet_count": 1,
  "invalid_packet_count": 0,
  "errors": [],
  "packets": [
    {
      "path": "examples/bridge-kit/packet.json",
      "ok": true,
      "packet_id": "cap_bridge_kit_minimal_demo",
      "producer_id": "agent:external-runtime-demo",
      "artifact_count": 1,
      "candidate_claim_count": 1,
      "open_need_count": 1,
      "errors": []
    }
  ]
}
```

Invalid packets return the same envelope with `ok: false`, non-zero `invalid_packet_count`, and exact per-packet validation errors.

### `vela check <frontier> --json`

Returns validation status for schema, stats lint, and optional conformance checks. By default, `check` runs the release-safe checks for the supplied frontier. Explicit flags narrow or expand the check set.

```json
{
  "ok": true,
  "command": "check",
  "schema_version": "0.2.0",
  "frontier": {
    "name": "erdos-problems",
    "source": "examples/erdos-problems",
    "hash": "sha256:..."
  },
  "summary": {
    "status": "pass",
    "checked_findings": 48,
    "valid_findings": 48,
    "invalid_findings": 0,
    "errors": 0,
    "warnings": 0,
    "info": 0
  },
  "checks": [
    {
      "id": "schema",
      "status": "pass",
      "checked": 48,
      "failed": 0,
      "diagnostics": []
    },
    {
      "id": "stats",
      "status": "pass",
      "checked": 48,
      "failed": 0,
      "diagnostics": []
    }
  ],
  "event_log": {
    "count": 3,
    "kinds": {"finding.reviewed": 1, "finding.caveated": 1, "finding.confidence_revised": 1},
    "first_timestamp": "2026-04-22T00:00:00Z",
    "last_timestamp": "2026-04-22T00:00:00Z",
    "duplicate_ids": [],
    "orphan_targets": []
  },
  "replay": {
    "ok": true,
    "status": "ok",
    "baseline_hash": null,
    "replayed_hash": "sha256:...",
    "current_hash": "sha256:...",
    "conflicts": [],
    "applied_events": 3
  },
  "source_registry": {
    "count": 10,
    "source_types": {"paper": 8, "csv": 2},
    "low_quality_count": 0,
    "missing_hash_count": 8
  },
  "evidence_atoms": {
    "count": 48,
    "missing_locator_count": 0,
    "unverified_count": 44,
    "synthetic_source_count": 0
  },
  "conditions": {
    "count": 48,
    "missing_text_count": 0,
    "missing_comparator_count": 33,
    "exposure_efficacy_risk_count": 0,
    "translation_scopes": {
      "animal_model": 32,
      "human": 15,
      "in_vitro": 1
    }
  },
  "proposals": {
    "total": 2,
    "pending_review": 1,
    "accepted": 0,
    "rejected": 0,
    "applied": 1
  },
  "proof_state": {
    "latest_packet": {"status": "current"},
    "last_event_at_export": "2026-04-22T00:00:00Z",
    "stale_reason": null
  },
  "signals": [],
  "review_queue": [
    {
      "id": "rq_0123456789abcdef",
      "priority": "high",
      "priority_score": 120,
      "target": {"type": "finding", "id": "vf_0123456789abcdef"},
      "signal_ids": ["sig_missing_evidence_span_0123456789abcdef"],
      "reasons": ["Finding has no verified evidence span attached."],
      "recommended_action": "Verify the assertion against source text and add evidence spans where possible."
    }
  ],
  "proof_readiness": {
    "status": "ready",
    "blockers": 0,
    "warnings": 0,
    "caveats": []
  }
}
```

`summary.status` is one of `pass`, `warn`, or `fail`. `event_log` summarizes canonical state events. `replay.status` is `ok`, `no_events`, or `conflict`. `source_registry` summarizes source artifacts, while `evidence_atoms` summarizes the source-grounded spans, rows, measurements, or weak provenance atoms attached to findings. `proposals` summarizes the review queue, and `proof_state` reports whether the latest proof packet is current, stale, or missing. Conflicts fail `check`, and `--strict` also fails on blocking proof-readiness signals. Diagnostics use this shape:

```json
{
  "severity": "error",
  "rule_id": "content_addressed_id",
  "finding_id": "vf_0123456789abcdef",
  "file": "vf_0123456789abcdef",
  "message": "Finding id does not match content-address",
  "suggestion": "Recompute the finding id from assertion and provenance"
}
```

`severity` is one of `error`, `warning`, or `info`.

### `vela proof <frontier> --out <dir> --json`

Builds and validates a proof packet. The JSON response summarizes the generated packet and points to the deterministic proof trace described in [`TRACE_FORMAT.md`](history/TRACE_FORMAT.md). By default this command does not write back to the input frontier; `--record-proof-state` is an advanced local bookkeeping flag that records `proof_state.latest_packet` after successful packet validation.

```json
{
  "ok": true,
  "command": "proof",
  "schema_version": "0.2.0",
  "recorded_proof_state": false,
  "frontier": {
    "name": "erdos-problems",
    "source": "examples/erdos-problems",
    "hash": "sha256:..."
  },
  "template": "erdos-problems",
  "output": "proof-packet",
  "packet": {
    "manifest_path": "proof-packet/manifest.json"
  },
  "validation": {
    "status": "ok",
    "summary": "vela packet validate\n  root: proof-packet\n  status: ok\n  checked_files: 38\n  project: Erdős problems"
  },
  "signals": [],
  "review_queue": [],
  "proof_readiness": {
    "status": "ready",
    "blockers": 0,
    "warnings": 0,
    "caveats": []
  },
  "trace_path": "proof-packet/proof-trace.json"
}
```

`validation.status` is `ok` or `failed`. A failed validation MUST exit non-zero.

### Paper-folder fixture sidecars

The checked-in paper-folder fixture carries the sidecars that the old local corpus bootstrap produced:

- `compile-report.json`
- `quality-table.json`
- `frontier-quality.md`

These artifacts are review aids. The durable trust boundary is still accepted proposals and canonical events.

`compile-report.json` uses:

```json
{
  "schema": "vela.compile-report.v0",
  "command": "compile",
  "source": {
    "path": "./papers",
    "mode": "local_corpus"
  },
  "output": {
    "frontier": "frontier.json"
  },
  "summary": {
    "files_seen": 4,
    "accepted": 4,
    "skipped": 0,
    "errors": 0,
    "findings": 11,
    "links": 11
  },
  "source_coverage": {
    "csv": 1,
    "text": 1,
    "jats": 1,
    "pdf": 1
  },
  "extraction_modes": {
    "curated_csv": 1,
    "offline_text": 1
  },
  "sources": [
    {
      "path": "papers/example.pdf",
      "source_type": "pdf",
      "status": "accepted",
      "extraction_mode": "offline_pdf",
      "findings": 3,
      "diagnostics": {
        "page_count": 2,
        "text_chars": 424,
        "word_count": 61,
        "text_quality": "thin_text",
        "detected_title": "Example paper",
        "detected_doi": null,
        "caveats": ["pdf source has limited extractable text; verify evidence spans before use."]
      },
      "warnings": []
    }
  ],
  "warnings": [],
  "artifacts": {
    "compile_report": "compile-report.json",
    "quality_table": "quality-table.json",
    "frontier_quality": "frontier-quality.md"
  }
}
```

`quality-table.json` is a review aid with one row per finding. It is not a scientific quality score. Rows include source file, span status, provenance completeness, frontier confidence components, extraction confidence, entity resolution status, caveats, and a recommended review action.

### `vela bench <frontier> --gold <file> --json`

Measures frontier drift against a frozen gold set. In finding mode this includes extraction-alignment metrics, but passing the benchmark is release discipline, not a claim that compile quality is the v0 proof.

```json
{
  "ok": true,
  "command": "bench",
  "benchmark_type": "finding",
  "mode": "finding",
  "suite_id": null,
  "task_id": null,
  "schema_version": "0.2.0",
  "frontier": {
    "name": "erdos-problems",
    "source": "examples/erdos-problems",
    "hash": "sha256:..."
  },
  "gold": {
    "path": "benchmarks/gold-50.json",
    "hash": "sha256:...",
    "items": 50
  },
  "metrics": {
    "total_frontier_findings": 48,
    "total_gold_findings": 8,
    "matched": 8,
    "total_frontier_matched": 8,
    "unmatched_gold": 0,
    "unmatched_frontier": 40,
    "exact_id_matches": 8,
    "precision": 0.167,
    "recall": 1.0,
    "f1": 0.286,
    "entity_accuracy": 1.0,
    "assertion_type_accuracy": 1.0,
    "confidence_calibration": 1.0
  },
  "thresholds": {
    "min_f1": 0.28,
    "min_precision": 0.15,
    "min_recall": 1.0
  },
  "failures": [],
  "match_details": [
    {
      "gold_id": "vf_...",
      "frontier_id": "vf_...",
      "gold_text": "a(16) >= 505 for the largest Sidon subset of {0,1}^16",
      "frontier_text": "the maximum Sidon subset of {0,1}^16 contains at least 505 points",
      "similarity": 0.429,
      "entity_overlap": 0.667,
      "assertion_type_match": true,
      "confidence_in_range": true,
      "exact_id_match": true
    }
  ]
}
```

For `--entity-gold`, set `benchmark_type` to `entity`. For `--link-gold`, set `benchmark_type` to `link`. Those modes MUST keep the same envelope and put mode-specific scores under `metrics`.

### `vela bench --suite <file> --json`

Runs a suite of finding, entity, link, and workflow benchmark tasks. Each task uses the same single-mode envelope described above.

```json
{
  "ok": true,
  "command": "bench",
  "benchmark_type": "suite",
  "schema_version": "0.2.0",
  "suite": {
    "id": "erdos-bounds-gate-v0",
    "name": "Erdős bounds quality gate",
    "path": "benchmarks/suites/erdos-core.json",
    "tasks": 4
  },
  "frontier": {
    "name": "erdos-problems",
    "source": "examples/erdos-problems",
    "hash": "sha256:..."
  },
  "metrics": {
    "tasks_total": 4,
    "tasks_passed": 4,
    "tasks_failed": 0,
    "standard_candles": 14
  },
  "standard_candles": {
    "definition": "Reviewed gold fixtures used as calibration anchors for release drift, not proof of scientific superiority.",
    "items": []
  },
  "failures": [],
  "tasks": [
    {
      "ok": true,
      "command": "bench",
      "benchmark_type": "finding",
      "mode": "finding",
      "suite_id": "erdos-bounds-gate-v0",
      "task_id": "erdos-findings",
      "metrics": {}
    }
  ]
}
```

`vela bench --suite <file> --suite-ready` returns a compact JSON readiness report over the same suite tasks.

Benchmark scores are regression signals for a frozen fixture. They are not claims about field-level scientific completeness.

### `vela serve <frontier> --check-tools --json`

Checks the read-only MCP/HTTP frontier tool surface and exits without starting a server. Without `--json`, the command prints a short human summary.

```json
{
  "ok": true,
  "command": "serve --check-tools",
  "schema": "vela.tool-check.v0",
  "frontier": {
    "name": "papers",
    "findings": 11,
    "links": 11
  },
  "summary": {
    "checks": 9,
    "passed": 9,
    "failed": 0
  },
  "tool_count": 9,
  "tools": [
    "frontier_stats",
    "search_findings",
    "list_gaps",
    "list_contradictions",
    "find_bridges",
    "apply_observer",
    "propagate_retraction",
    "get_finding",
    "trace_evidence_chain"
  ],
  "registered_tool_count": 10,
  "registered_tools": [
    "frontier_stats",
    "search_findings",
    "get_finding",
    "list_gaps",
    "list_contradictions",
    "find_bridges",
    "check_pubmed",
    "apply_observer",
    "propagate_retraction",
    "trace_evidence_chain"
  ],
  "checks": [
    {
      "tool": "frontier_stats",
      "ok": true,
      "data": {},
      "markdown": "{...}",
      "has_data": true,
      "has_markdown": true,
      "has_signals": true,
      "has_caveats": true,
      "signals": [],
      "caveats": [],
      "duration_ms": 0
    }
  ],
  "failures": []
}
```

### Finding search (read surface)

Ranked finding matches for a query are read through `vela serve` / MCP (`search_findings`); the JSON shape below is the response contract.

```json
{
  "ok": true,
  "command": "search",
  "schema_version": "0.2.0",
  "frontier": {
    "name": "erdos-problems",
    "source": "examples/erdos-problems",
    "hash": "sha256:..."
  },
  "query": "A309370 Sidon lower bound",
  "filters": {
    "entity": null,
    "assertion_type": null,
    "limit": 20
  },
  "count": 2,
  "results": [
    {
      "id": "vf_0123456789abcdef",
      "score": 5.5,
      "assertion": "the recorded witness is a Sidon set in {0,1}^16",
      "assertion_type": "mechanism",
      "confidence": 0.84,
      "entities": ["A309370", "Sidon set", "{0,1}^n"],
      "doi": "10.0000/example"
    }
  ]
}
```

`score` is a search relevance score, not confidence. Result ordering is by descending `score`; ties SHOULD be broken by finding ID for deterministic output.

### Candidate tensions (read surface)

Candidate contradiction/tension pairs are read through `vela serve` / MCP (`list_contradictions`); the JSON shape below is the response contract.

```json
{
  "ok": true,
  "command": "tensions",
  "schema_version": "0.2.0",
  "frontier": {
    "name": "erdos-problems",
    "source": "examples/erdos-problems",
    "hash": "sha256:..."
  },
  "filters": {
    "both_high": true,
    "cross_domain": false,
    "top": 20
  },
  "count": 1,
  "tensions": [
    {
      "score": 70.0,
      "resolved": false,
      "superseding_id": null,
      "finding_a": {
        "id": "vf_0123456789abcdef",
        "assertion": "the a(17) >= 712 witness is a valid Sidon set",
        "confidence": 0.9,
        "assertion_type": "mechanism",
        "citation_count": 50,
        "contradicts_count": 1
      },
      "finding_b": {
        "id": "vf_fedcba9876543210",
        "assertion": "the a(17) >= 712 witness has a repeated pairwise sum",
        "confidence": 0.85,
        "assertion_type": "therapeutic",
        "citation_count": 32,
        "contradicts_count": 1
      },
      "caveat": "Candidate contradiction inferred from typed links; inspect both findings before treating it as resolved or unresolved."
    }
  ]
}
```

`score` is a prioritization heuristic. It must not be described as truth, agreement, or severity without human review.

### `vela gaps rank <frontier> --json`

Returns candidate gap review-lead rankings. These are navigation signals over flagged findings, not scientific conclusions or guaranteed experiment targets.

```json
{
  "ok": true,
  "command": "gaps rank",
  "schema_version": "0.2.0",
  "frontier": {
    "name": "erdos-problems",
    "source": "examples/erdos-problems",
    "hash": "sha256:..."
  },
  "filters": {
    "top": 5,
    "domain": null
  },
  "count": 1,
  "ranking_label": "candidate gap review leads",
  "caveats": [
    "These rankings are navigation signals over flagged findings, not scientific conclusions."
  ],
  "review_leads": [
    {
      "id": "vf_0123456789abcdef",
      "kind": "candidate_gap_review_lead",
      "assertion": "lower bounds for a(n) with n >= 25 remain unattempted",
      "score": 3.4,
      "dependency_count": 5,
      "confidence": 0.68,
      "evidence_type": "observational",
      "entities": ["A309370", "Sidon set"],
      "recommended_action": "Review source scope and missing evidence before treating this as an experiment target.",
      "caveats": [
        "Candidate gap rankings are review leads, not guaranteed underexplored areas or experiment targets."
      ]
    }
  ],
  "gaps": [
    {
      "id": "vf_0123456789abcdef",
      "kind": "candidate_gap_review_lead",
      "assertion": "lower bounds for a(n) with n >= 25 remain unattempted",
      "score": 3.4,
      "dependency_count": 5,
      "confidence": 0.68,
      "evidence_type": "observational",
      "entities": ["A309370", "Sidon set"],
      "recommended_action": "Review source scope and missing evidence before treating this as an experiment target.",
      "caveats": [
        "Candidate gap rankings are review leads, not guaranteed underexplored areas or experiment targets."
      ]
    }
  ]
}
```

`score` is a deterministic review-prioritization heuristic:

```text
dependency_count + finding confidence
```

Cost labels are rough planning placeholders and MUST NOT be treated as budget estimates for release claims.

### State transition commands

The release write surface records durable frontier state transitions through proposal-first writes. These commands do not delete history.

```bash
vela finding add frontier.json --assertion "..." --author reviewer:demo --json
vela propose frontier.json vf_0123 --status contested --reason "..." --reviewer reviewer:demo --json
vela note frontier.json vf_0123 --text "..." --author reviewer:demo --json
vela caveat frontier.json vf_0123 --text "..." --author reviewer:demo --json
vela revise frontier.json vf_0123 --confidence 0.42 --reason "..." --reviewer reviewer:demo --json
vela reject frontier.json vf_0123 --reason "..." --reviewer reviewer:demo --json
vela retract frontier.json vf_0123 --reason "..." --reviewer reviewer:demo --json
vela proposals list frontier.json --status pending_review --json
vela proposals accept frontier.json vpr_0123456789abcdef --reviewer reviewer:demo --reason "Accepted after review" --json
vela log frontier.json vf_0123 --json
```

`finding add`, `propose`, `note`, `caveat`, `revise`, `reject`, and `retract` create `vela.proposal.v0.1` records by default. `--apply` accepts and applies the proposal locally in one step. Applied proposals append a canonical `vela.event.v0.1` event and then save the materialized frontier snapshot. They return this stable envelope:

```json
{
  "ok": true,
  "command": "finding.add",
  "frontier": "erdos-problems",
  "finding_id": "vf_0123456789abcdef",
  "proposal_id": "vpr_0123456789abcdef",
  "proposal_status": "pending_review",
  "applied_event_id": null,
  "wrote_to": "frontier.json",
  "message": "Finding proposal recorded"
}
```

`history` returns the current finding snapshot plus canonical events, compatibility review/confidence projections, and annotations:

```json
{
  "ok": true,
  "command": "history",
  "frontier": "erdos-problems",
  "finding": {
    "id": "vf_0123456789abcdef",
    "assertion": "the witness {0,1,4,...} is Sidon in {0,1}^16",
    "confidence": 0.42,
    "flags": {},
    "annotations": []
  },
  "events": [],
  "review_events": [],
  "confidence_updates": [],
  "proposals": []
}
```

Proof packets include canonical events at `events/events.json`, replay status at `events/replay-report.json`, the combined derived log at `state-transitions.json`, proposal records at `proposals/proposals.json`, and compatibility projection files under `reviews/`.

### Release tests

Release tests should assert field presence and types, not exact pretty-printing. The legacy `benchmark` command is intentionally absent; use `bench`.

## See also

- `docs/AI_ATTRIBUTION.md`: full agent-vs-human-reviewer doctrine (Gowers-shaped).
- "§MCP server" (above): the full tool catalog.
- "§Frontier Context Protocol (FCP)" (above): the LSP-shaped query surface.
- "§Python SDK (vela-agent)" (above): the five-line producer SDK.
- "§CLI JSON contracts" (above): the stable `--json` envelopes.
- `docs/RELAY.md`: the four-adapter shape contract; agents typically work through `paper-to-vela` / `hypothesis-to-vela` / `review-to-vela`.
- `scripts/test-agent-init.sh`: the regression gate this on-ramp is pinned against.
