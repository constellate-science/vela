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
| `accept` | Apply proposals under your key: `--all-pending`, `--id vpr_…`, or `--pack vsd_…` for one atomic changeset decision. The decision self-publishes (see below). |
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
| `serve` | The frontier as an MCP server (stdio, or `/mcp` over `--http`) with ten agent-first tools; profiles nest `read-only` (7) ⊂ `draft` (9) ⊂ `maintainer` (10). The hub hosts the clone-free subset (5) at `hub.constellate.science/mcp`. |
| `doctor` | First-user diagnosis of checkout/frontier/proof/serve. |
| `foundry` | The discovery plane: `campaign`, `lean-*`, `attempt`, `transfer`, `experiment`. Search proposes; the frozen verifier is the gate. |

## Projections (read-only, dispatched ahead of the parser)

| Verb | What it does |
|---|---|
| `state` | Claim-state cell for one finding; `state trust`, `state pack`, `state diff` (Evidence Diff), anchors; `--as-of <RFC3339>` answers "what did we hold on this date". |
| `atlas` | Cross-frontier math-atlas projections. |
| `policy` | Governance policy: show/seal/test/evaluate. |

## Decisions self-publish

Once your key has signed, everything that follows is mechanical
consequence, and the verb finishes it: `accept`, `review`,
`proposals reject`, `id sign`, and the policy auto-admit lane end by
materializing derived views, committing the store with a canonical
message that binds the signed event ids, and pushing. One intention,
one act — the signed decision can never again rot uncommitted on one
machine. `--no-commit` / `--no-push` hold publication per-call;
`vela id` config (`git_commit` / `git_push`: `auto` | `off`) sets the
default; `VELA_NO_PUBLISH=1` disables globally (the conformance gate
sets it). Nothing is ever auto-signed: publication only carries events
a key already signed. `vela status` warns about any store state that
predates this (`unpublished: N store file(s)…`), and `frontier next`
ranks stranded state above all other work.

`vela init` scaffolds versioned git hooks (`.vela/hooks`, activated via
`core.hooksPath`): pre-commit re-materializes views when events are
staged (committed store can never lead its views), pre-push holds the
push to the same strict bar CI enforces.

## The output contract

One grammar, enforced by one module (`crates/vela-cli/src/ui.rs`):

- **Frontier discovery**: the `[frontier]` positional is optional on the
  daily verbs — omitted, it is discovered by walking upward from the
  current directory, exactly like git finds `.git`. An object id in the
  frontier slot shifts automatically (`vela accept vpr_x` works).
- **Exit codes**: 0 ok · 1 domain failure (gate red, verify fail) ·
  2 usage · 3 not found · 4 custody refused · 5 already exists. An agent
  that knows WHY a call failed can self-correct without parsing prose.
- **JSON guarantee**: under `--json`, every outcome — including every
  failure — is one JSON object `{ok, command, error?{kind,message,hint}}`.
  No prose ever leaks into a `--json` stream.
- **Hints**: errors carry a `hint:` line naming the exact next command;
  `--quiet` or `VELA_ADVICE=0` silences hints without touching messages.
- **Flags mean one thing**: `--as` = acting identity (all writes);
  `--key` = path to an Ed25519 private key, hex seed (defaults to your
  `vela id`); `--as-of` = RFC3339 instant. The same help text renders on
  every verb that carries the flag.

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
vela accept . --pack vsd_<id>   # one act: signed, materialized,
                                # committed, pushed, re-indexed
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
