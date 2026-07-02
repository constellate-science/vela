# The Vela CLI

Version control for scientific state. One sentence holds the whole
surface: **agents propose, verifiers reproduce, humans accept, git
publishes.**

The porcelain is 25 visible verbs, pinned by a both-directions test
(`crates/vela-cli/src/cli/tests.rs`): a verb cannot appear or disappear
without the baseline changing on purpose. Three read-only projections
(`state`, `atlas`, `policy`) are dispatched ahead of the parser, and the
discovery plane nests under `foundry`. Every porcelain verb takes
`--json` and emits a stable object with `ok` and `command` fields.

## Setup (once)

| Verb | What it does |
|---|---|
| `id` | Your key + identity: `create`, `show`, `import`, `keygen`, `sign`. After `vela id create`, no `--key`/`--as` flags are needed for your own writes; `id sign` re-signs your historical unsigned events. |
| `init` | Initialize a git-native frontier repo: `.vela/` is committed, the CI gate, agent charter (`VELA.md`), and `.mcp.json` are scaffolded. |

## The loop

| Verb | What it does |
|---|---|
| `status` | One-screen frontier state: findings by status, verdicts, replay integrity, inbox count, policy mode, and a `next` hint. |
| `inbox` | Pending proposals awaiting a human key, grouped by pack. |
| `log` | Recent signed events; `vela log <dir> <vf_>` is one finding's history. |
| `diff` | Two frontiers, or one pending proposal previewed. |
| `record` | Record activity into a portable claim packet (`vrc_`): a claim, hashed artifacts, and required caveats. `--propose` lands it as a pending proposal. |
| `propose` | Draft the common `finding.review` proposal. |
| `review` | Signed human judgments: statement-fidelity verdicts (`--fidelity`, `--batch`) and role-scoped reviewer attestations. |
| `accept` | Apply proposals under your key: `--all-pending`, `--id vpr_…`, or `--pack vsd_…` for one atomic changeset decision. |
| `pack` | Bundle pending proposals into a changeset (`vsd_`) — the pull-request analogue. `vela pack . vsd_…` shows one. |
| `proposals` | The full proposal store: list/show/preview/import/validate/export/accept/reject. |
| `attach` | Bind mechanical verifier evidence (or `--proof lean_kernel`) to a finding. |

## Verify

| Verb | What it does |
|---|---|
| `check` | The full trust gate: replay, signatures, parity. `--strict` is the same bar the hub's ingestor holds a repo to. |
| `reproduce` | Re-verify stored witnesses from scratch with the frozen verifiers. |
| `proof` | Export a proof packet; `proof verify` re-checks one, `proof explain` narrates it. |
| `gate` | Claim-level verification gate: grade/check/vocab/backfill/auto-admit. |

## Publish

| Verb | What it does |
|---|---|
| `hub` | The index: `register-git` binds a repo to its `vfr_` once (the one owner-signed act), after which `git push` IS publication. `witness-check`, `verify-chain`, `verify-log` hold hubs honest. |

## Nouns

| Verb | What it does |
|---|---|
| `finding` | The core primitive: add/show/supersede/note/caveat/revise/reject/retract/link. |
| `frontier` | Repo-level: new/materialize/add-dep/list-deps/diff/release/audit. |
| `actor` | Frontier-registered identities: add/list/rotate. |
| `agents` | `VELA.md` charter adapters: sync/doctor/diff (AGENTS.md, CLAUDE.md, .mcp.json are generated, never hand-edited). |
| `serve` | MCP (stdio, and streamable HTTP at `--http`'s `/mcp`) + HTTP read surface. Profiles nest: `read-only` ⊂ `draft` ⊂ `maintainer`. The public hub serves the same read-only surface at `hub.constellate.science/mcp`. |
| `doctor` | First-user diagnosis of checkout/frontier/proof/serve. |
| `foundry` | The discovery plane: `campaign`, `lean-*`, `attempt`, `transfer`, `experiment`. Search proposes; the frozen verifier is the gate. |

## Projections (read-only, dispatched ahead of the parser)

| Verb | What it does |
|---|---|
| `state` | Claim-state cell for one finding; `state trust`, `state pack`, `state diff` (Evidence Diff), anchors; `--as-of <RFC3339>` answers "what did we hold on this date". |
| `atlas` | Cross-frontier math-atlas projections. |
| `policy` | Governance policy: show/seal/test/evaluate. |

## Identity grammar

`--as <actor>` is THE acting-identity flag on every write verb.
`--author` exists only on `finding add`/`finding supersede` (the claim's
author, distinct from who is acting). `--verifier-actor` names the
mechanical identity a frozen-verifier attachment is drafted for. Nothing
else names an identity. The engine refuses `agent:`/`ci:` actors on
`accept`, `review`, `proposals reject`, and `id sign` — decisions are
key-custody human acts.

## Worked example: record → propose → pack → accept

```bash
# the agent's session (VELA_ACTOR_ID=agent:demo)
vela record . \
  --claim "a(17) >= 292 for the Sidon frontier" \
  --artifact witnesses/a17.json \
  --caveat "lower bound only; optimality not established"
vela record records/vrc_<id>.json --propose .
vela pack . --summary "a(17) lower-bound attack" --from-pending
vela check . --strict
git push                        # publication; the hub re-indexes

# the human's session (their key)
vela inbox .                    # packs awaiting one decision
vela diff vpr_<id>              # preview any member
vela accept . --pack vsd_<id>   # one atomic verdict for the changeset
```

## Policy tiers (shadow / staged / live)

A frontier may carry a sealed acceptance policy (`vap_` id,
`policies/active.json`). `vela status . --json` reports
`policy.mode`:

- **shadow** — no sealed policy on the frontier; the engine's built-in
  conservative kind-allowlist is the only mechanical lane.
- **staged** — a sealed policy sits at `.vela/policies/active.json` but
  is unsigned; advisory only, one human signature activates it.
- **live** — a `PolicySignatureRecord` (`active.sig.json`) signed by a
  human reviewer key activates it; mechanical proposal kinds (span
  repairs, artifact provenance) auto-admit with the `vap_` id stamped
  into the event.

A policy can only TIGHTEN the frozen-verifier floor. Truth-bearing
claims stay human-keyed in every mode; there is no configuration in
which an agent's proposal becomes accepted state without a human key.

## See also

[AGENT_QUICKSTART.md](AGENT_QUICKSTART.md) (the agent contract),
[PROTOCOL.md](PROTOCOL.md) (events, objects, ids),
[VERIFICATION.md](VERIFICATION.md) (what the gate holds),
[HUB.md](HUB.md) (the index and git-native publication).
