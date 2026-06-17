# AI-agent quickstart

This document describes the on-ramp for an AI agent that wants to read frontier state and draft proposals against a Vela frontier. The substrate-honest contract: every agent-drafted truth claim flows through the same reviewer-gated discipline as every other proposal. No agent has a privileged write path.

Humans reviewing a frontier should start at [REVIEWER_PLAYBOOK](REVIEWER_PLAYBOOK.md) instead; this is the agent on-ramp.

## One-command scaffold (v0.131)

```bash
vela agent init <slug> --framework <name>
```

Where `<slug>` is a lowercase-alphanumeric-hyphens name and `<name>` is one of:

- `claude-code` — agent running inside Claude Code CLI
- `claude-api` — agent driving the Anthropic API directly
- `langchain` — LangChain-shaped agent
- `openai` — OpenAI Assistants / function-calling shape
- `agent4science` — Agent4Science review-packet emitter
- `scienceclaw` — ScienceClaw artifact-packet emitter
- `custom` — none of the above

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

- `frontier_stats` — counts, replay state, signals, proof readiness
- `search_findings` — text / entity / assertion-type query
- `get_finding` — single-finding detail incl. evidence + lineage
- `list_events` — cursor-paginated canonical event log
- … plus 15 others. See `docs/MCP.md` for the full table.

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

For verifier-gated construction kinds, you do not need to hand-write a witness — the discovery engine searches for one and verifies it in the same step:

```bash
# search and report (writes nothing)
vela campaign search rook_directions --n 16
# search, write the verified witness, and propose it (pending; no key needed)
vela campaign run gf2_sidon --n 12 --frontier <frontier> --propose --reviewer <agent-id>
```

Searchable kinds: `gf2_sidon`, `union_free`, `rook_directions`, `sidon`, `bh` (with `--h`), `golomb`, `costas`. The search is deterministic — the same `--seed` reproduces the same witness — and every find is re-checked by the frozen `vela-verify` before it is reported, so a reported find always passes `vela reproduce`. `--propose` lands a key-free `finding.add` that waits for a human verdict (step 4); it does not promote the claim. The engine certifies lower bounds: it extends the less-explored ranges and will under-perform the algebraic optima behind the largest records, which is exactly where a stronger search wins.

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

## See also

- `docs/AI_ATTRIBUTION.md` — full agent-vs-human-reviewer doctrine (Gowers-shaped).
- `docs/MCP.md` — the 19-tool catalog.
- `docs/RELAY.md` — the four-adapter shape contract; agents typically work through `paper-to-vela` / `hypothesis-to-vela` / `review-to-vela`.
- `scripts/test-agent-init.sh` — the regression gate this on-ramp is pinned against.
