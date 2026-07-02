# The agent contract

Vela is built to be driven by agents the way git is driven by hands:
**agents propose, verifiers reproduce, humans accept, git publishes.**
This is the whole on-ramp. Every agent-drafted truth claim flows through
the same reviewer-gated discipline as every other proposal; no agent has a
privileged write path, and the engine refuses agent actors on every
decision verb.

## The rules (engine-enforced; also your instructions)

Agents may:

- inspect state: `vela status . --json`, `vela inbox .`, `vela log .`,
  `vela check . --strict`, `vela state <dir> <vf_>`, `vela diff <vpr_>`
- record activity: `vela record . --claim … --artifact … --caveat …`
- draft proposals: `vela finding add . --as agent:<you> …`,
  `vela record <vrc_file> --propose .`, `vela propose …`
- attach mechanical verifier evidence: `vela attach . --target <vf_> …`
- run the frozen verifiers: `vela reproduce .`
- rebuild derived views: `vela frontier materialize .`

Agents may not — the engine refuses these for `agent:`/`ci:` actors:

- `vela accept`, `vela review`, `vela proposals reject`, `vela id sign` —
  key-custody human decisions, every one
- sign anything with a human's key (an agent-actor `record` never
  auto-resolves the configured human key; it signs only with a key passed
  explicitly, or stays honestly unsigned)

Always export `VELA_ACTOR_ID=agent:<your-name>` and pass
`--as agent:<your-name>` on writes. Never run bare decision verbs.

The identity grammar, in full: `--as <actor>` is THE acting-identity flag
on every write verb. `--author` exists only on `finding add`/`finding
supersede` (the claim's author, distinct from who is acting), and
`--verifier-actor` names the mechanical identity a frozen-verifier
attachment is drafted for (e.g. `agent:vela-verify`). Nothing else names
an identity.

## The loop, end to end

```bash
export VELA_ACTOR_ID=agent:demo

vela status . --json      # where the frontier stands: findings by status,
                          # verdict distribution, replay integrity, inbox,
                          # and a `next` hint
vela record . \
  --claim "a(17) >= 292 for the Sidon frontier" \
  --artifact witnesses/a17.json \
  --caveat "lower bound only; optimality not established"
                          # -> records/vrc_<id>.json (content-addressed,
                          #    head-pinned, artifact-hashed)
vela record records/vrc_<id>.json --propose .
                          # -> pending proposal; a human key decides
vela check . --strict     # the full trust gate, locally
git push                  # publication: CI re-derives the frontier and the
                          # hub re-indexes from the repo
```

A human then runs `vela inbox .` and `vela accept . --all-pending` (their
key) — and the decision publishes itself: materialize, commit, push, hub
re-index, in the one act. That boundary is the product, not a limitation.

## MCP: the same loop for tool-calling agents

No clone at all? The public hub IS an MCP server: add
`https://hub.constellate.science/mcp` (streamable HTTP, no auth) to any
MCP client and you get the read-only tool surface over every live
frontier. Writes and verifier runs still happen in a clone — the hosted
endpoint cannot mutate state under any configuration.

Any frontier scaffolded by `vela init` ships `.mcp.json`; any client
opening the repo gets the read-only profile:

```json
{ "mcpServers": { "vela": { "command": "vela",
    "args": ["serve", ".", "--profile", "read-only"] } } }
```

Profiles nest: `read-only` ⊂ `draft` ⊂ `maintainer`. Read-only exposes no
mutating tool (a unit test enforces this); `draft` adds the propose family;
accept/reject live only in `maintainer`, behind a human session.

The tools that answer the agent questions:

| Question | Tool |
|---|---|
| What frontier am I on / what is accepted? | `frontier_stats`, `context`, `frontier_explore`, `search_findings`, `get_finding` |
| What should I work on? | `task_packet` (the agent entry contract), `list_gaps` |
| What is contested / what breaks if X falls? | `contradictions`, `blast_radius`, `deep_trace`, `trace_evidence_chain` |
| Does the frontier pass the gate right now? | `vela_check_run` — the same strict bundle the hub's ingestor enforces |
| Do the witnesses actually reproduce? | `vela_reproduce_run` — frozen-verifier re-check, per witness |
| How do I submit work? | `vela_record_propose` (draft profile) — lands a vrc_ record as a pending proposal |
| What happened since I last looked? | `list_events_since`, `get_finding_history` |

## JSON contracts

Every porcelain verb takes `--json` and emits a stable object with `ok`,
`command`, and command-specific fields. The two an agent reads most:

- `vela status . --json` → `findings.by_status` (accepted / contested /
  retracted / superseded — never one green check), `judgment.by_verdict`,
  `replay.ok`, `inbox.pending_total`, `proof.status`, `next`.
- `vela check . --strict --json` → the gate verdict with signals and the
  review queue.

## Discovery (optional, off-porcelain)

The verifier-gated discovery engine lives under `vela foundry`:
`foundry campaign search <kind> --n <n>` searches, the frozen verifier is
the gate, `--propose` lands the result as a pending proposal. Attempts,
transfers, Lean anchoring, and experiment receipts are
`foundry attempt|transfer|lean|experiment …`.

## Swarms (many agents, one frontier)

The loop scales by composition, not new machinery:

1. **Claim before long work**: `vela_claim_task` (MCP, draft profile)
   leases an obligation under your OWN agent key — minted automatically
   at `~/.vela/agents/<actor>/` from your `VELA_ACTOR_ID` the first time
   you claim, no key step needed (`VELA_AGENT_KEY_HEX` overrides). A
   live competing lease returns `already_claimed_by` — route around it.
   A lease coordinates; it never decides. Lifecycle: the `attempt.claimed` event carries a TTL
   (default 24h); an expired lease is simply ignored by the next claimer,
   and landing your pack is what closes the work — there is no unclaim
   ceremony. Obligation ids may be frontier-external and namespaced
   (`erdos:443`); strict replay treats such leases as coordination, not
   orphaned targets.
2. **Watch, don't poll blind**: `GET /entries/{vfr}/events/stream?since=<cursor>`
   (SSE, cursor-resumable) streams what changed.
3. **One pack per session**: bundle your session's proposals into a
   changeset — `vela pack . --summary "…" --from-pending` — so the
   reviewer judges your work as one unit (`vela accept . --pack vsd_…`).
4. **Policy-bound lanes**: when the frontier carries a signed acceptance
   policy (`vela status . --json → .policy.mode == "live"`), mechanical
   kinds (repairs, artifact provenance) auto-admit under the sealed
   `vap_` policy id — the policy can only tighten the frozen verifier
   floor, and truth-bearing claims stay human-keyed no matter what.

## Python SDK

`clients/python/vela_agent` wraps the read surface and proposal drafting
for Python-native agents. Note: its hub-publish helper predates the
git-native cutover (git push is publication now); prefer the CLI/MCP loop
above for writes.

## Doctrine, one paragraph

Activity is not state. A model run, a notebook, a record, a search hit —
all of it is source material until a proposal passes review and a human
key signs the accept. The log is trustworthy by construction; a claim
becomes trusted state only through the gate. Your job as an agent is to
make the reviewer's decision easy: hash-bound artifacts, honest caveats,
reproducible verifier runs — and never to make the decision yourself.

See also: [PROTOCOL.md](PROTOCOL.md) (the object model and record spec),
[VERIFICATION.md](VERIFICATION.md) (the gate), [HUB.md](HUB.md)
(git-native publication), [THREAT_MODEL.md](THREAT_MODEL.md).
