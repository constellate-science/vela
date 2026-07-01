# Vela Hub

**Role (build-borrow / ADR 0001): the hub is an INDEX over git-replayed state,
not the authority.** The authoritative source of a frontier is its git repo (the
committed `.vela/events` log in `constellate-science/vela-frontiers`), reproducible
from a clean clone. The hub is a convenience layer: cross-frontier search,
reverse-dependency lookup, producer/reviewer pages, projection and event-stream
APIs, and the editorial "live" filter. It does not own byte custody (git + LFS
do), and it is not the write authority for acceptance (a reviewer's signed
`review.accepted` event in a PR is). Its write endpoints are now limited to index
population: the git-ingestion lane is LIVE — an owner binds a repo once
(`vela registry register-git <vfr> --remote <url>`, or POST
`/entries/{vfr}/git-remote` with a signed `vela.frontier-git-remote.v0.1`
record), and the hub re-derives the index by fetching the repo, strictly
replaying the committed `.vela/events` log (validation + reducer replay +
signature signals; a tampered signed event is refused with "id does not
re-derive"), and promoting through the same gate as the legacy publish,
with `authority_mode='git_ingested'`. `git push` is publication; the
legacy signed publish remains as a deprecated index-population lane.

The hub is the public HTTP surface for signed frontier publications.
The signed registry entry is the publish receipt. Live reads come from
verified event and projection tables, and snapshot blobs remain derived
export artifacts.

Clients verify locally on read, so a compromised hub can withhold or
reorder, but cannot fabricate or tamper without breaking signatures and
hashes.

The public hub is **<https://hub.constellate.science>**.

## Doctrine

- **Event-first reads.** `frontier_events` preserves the exact event
  array order used for `latest_event_log_hash`. `frontier_objects` and
  `frontiers.materialized_snapshot_json` are projections from verified
  substrate.
- **The signature is the bind, not access control.** Anyone with an
  Ed25519 key can publish their own `vfr_id`. There is no allowlist of
  pubkeys on the public v0 hub.
- **Snapshots are exports.** `GET /entries/{vfr_id}/snapshot` serves a
  derived materialized snapshot. `?redirect=cdn` may return the
  content-addressed object-storage copy when one exists.
- **Broken latest rows do not go live.** A latest registry row that
  fails fetch, signature, schema, snapshot-hash, or event-log
  verification remains visible in registry history but is not promoted
  to `frontiers`.

## Endpoints

| Endpoint | Behavior |
|---|---|
| `GET /` | Banner + endpoint list + version. |
| `GET /healthz` | Liveness; reports DB reachability. |
| `GET /entries` | Live frontiers, returned as manifest-compatible JSON for older clients. |
| `GET /entries/{vfr_id}` | One live frontier entry. HTML reads the hub projection and renders findings inline. |
| `GET /entries/{vfr_id}/events?since=<event_id>&limit=<n>&kind=&target=` | Cursor-paginated canonical event log ordered by `seq`. Unknown cursors return 400. |
| `GET /entries/{vfr_id}/events/stream?since=<event_id>` | Server-sent event stream. Emits backlog, then heartbeat while idle. |
| `GET /frontier/{vfr_id}/inbox` | Agent-facing alias for the event stream. |
| `GET /entries/{vfr_id}/snapshot` | Derived materialized snapshot JSON. `?redirect=cdn` redirects to the immutable blob when available. |
| `GET /entries/{vfr_id}/findings/{vf_id}` | Single-finding view: claim, conditions, evidence, links. Cross-frontier links navigate when dependencies are published. |
| `POST /entries` | Publish a signed manifest. Inline `substrate` is verified and decomposed into event/projection tables. |

`POST /entries` body shape: a registry entry matching
`vela.registry-entry.v0.1`, optionally with a sibling `substrate`
object. The signed preimage is still the registry entry alone. The hub
verifies the signature, verifies the substrate hashes against the
manifest, stores snapshot metadata when object storage is configured,
then promotes events and projections. See
[REGISTRY.md](REGISTRY.md#manifest-format).

### v0.8: cross-frontier composition

A frontier published to the hub may declare cross-frontier dependencies
in its `frontier.dependencies` array, pinning each remote frontier by
`vfr_id` and `pinned_snapshot_hash`. Findings in the dependent frontier
can then link to findings in the dep via `vf_<id>@vfr_<id>` link
targets. The hub renders such links as clickable navigation between
entries; clients use `vela registry pull <vfr> --transitive --from
https://hub.constellate.science/entries` to fetch and verify the whole chain.

The hub does not invent cross-frontier answers at storage time.
Resolution happens client-side at pull time, where the canonical-JSON
snapshot pin is the integrity guarantee.

Idempotency: `(vfr_id, signature)` is unique. Re-POSTing identical
canonical bytes returns 200 with `duplicate=true`; the row is not
duplicated. Two CLI runs spaced apart produce *different* manifests
(each gets a fresh `signed_publish_at`), so both rows persist and the
latest-publish-wins read returns the newer.

## Publishing

```bash
vela registry publish frontier.json \
  --owner reviewer:my-id \
  --key ~/.vela/keys/private.key \
  --to https://hub.constellate.science
```

When publishing to an HTTP hub, the CLI includes the frontier substrate
inline and auto-fills the manifest locator as the hub snapshot endpoint.
The hub verifies the signature, snapshot hash, and event-log hash before
promoting the frontier. The owner must already be registered as an actor
in the frontier with a matching pubkey.

## Pulling

```bash
vela registry list --from https://hub.constellate.science/entries
vela registry pull vfr_… --from https://hub.constellate.science/entries --out ./pulled.json
```

For an HTTP hub, `pull` first fetches
`/entries/{vfr_id}/snapshot`, which is the event/projection-derived
read path. It falls back to the entry's `network_locator` only when
talking to older hubs that do not expose the snapshot endpoint. It always verifies
signature, snapshot hash, and event-log hash before keeping the file.

## Hub as remote (the `.vela/` decommit)

A frontier's `.vela/` store is to Vela what `.git/` is to git: a local store
that is **not committed**. Each canonical frontier carries its own
`.gitignore` with `/.vela/`, so git tracks only the working tree (README,
`frontier.yaml`, `SCOPE.md`, `witnesses/`, `sources/`) and the `.vela/` event
log lives on the hub. This makes the hub the **remote of record** and the local
`.vela/` a reconstructible cache, exactly as `git clone` / `git checkout`
rebuild a working tree from a remote.

- **What is on the hub.** The science core — events, findings, proposals, and
  content-addressed artifact blobs (witnesses + proof packets) — is uploaded by
  `vela publish`. Everything else in `.vela/` (policy, releases, evaluations,
  tool descriptors) is content-addressed into a signed **extras manifest**:
  each loose file's hash is collected into an `ExtrasManifest` whose digest
  rides in the signed `RegistryEntry.extras_manifest_hash`. That hash sits
  **outside** `snapshot_hash` / `event_log_hash` (the canonical-bytes anchors
  never move), so the extras travel as a complete byte-for-byte backup without
  perturbing the integrity hashes. The result: a published frontier on the hub
  is a complete backup of its committed-and-uncommitted state.
- **What is never backed up.** `LOCAL_ONLY_DIRS` (`tasks/`, `workspaces/`) are
  per-machine scratch — the worktree analogue. They are neither committed nor
  hub-backed and are excluded from the extras manifest by `collect_extras`.
- **The read side.** `vela clone <vfr|url>` reconstructs the full working
  `.vela/` tree (event log + materialized `frontier.json` + witness/proof
  sidecars fetched by content hash + `vela.lock`). `scripts/hydrate-frontiers.sh`
  does the same for a monorepo checkout whose `.vela/` is absent. Both are no-ops
  when `.vela/` is already present.
- **The registry.** `scripts/workspace.json` is the git-style index of
  checked-out frontiers and their hub remotes (`vela workspace add` writes it).
  The conformance gate discovers its frontiers from it and fails closed if any
  decommitted frontier is missing from it, so a cold clone and the gate always
  agree on what is canonical.

## Release verification boundary

Two distinct senses of "source of truth" must not be conflated:

- **Byte custody (the git-remote sense).** Since the `.vela/` decommit, the
  hub IS the canonical store for a frontier's event-log bytes and witness
  blobs; the local `.vela/` is a reconstructible cache (see "Hub as remote"
  below). `vela clone` repopulates it from the hub the way `git checkout`
  populates a working tree. In this sense the hub is the remote of record.
- **Scientific verdict (the trust sense).** The hub is signed transport. It is
  NOT the arbiter of what is true. Release checks can prove that the published
  `examples/sidon-sets` frontier id matches the expected snapshot and event-log
  hashes, but the authority for *correctness* still comes from re-deriving local
  frontier state, the signed events, and frozen-verifier proof-packet validation
  on a clean clone. A hub that served tampered bytes would simply fail to
  reproduce. The hub stores; the verifiers judge.

The live gate is operator-driven so normal clean clones do not need
network credentials:

```bash
VELA_HUB_RELEASE_CHECK=1 ./tests/test-hub-release-boundary.sh
```

Multi-hub witness checks remain optional. Set both environment variables
when two hubs are expected to carry the same witness pack:

```bash
VELA_HUB_URLS=https://hub.constellate.science,https://vela-hub-eu.fly.dev \
  VELA_WITNESS_PACK_ID=vsd_b6647b7d9bee0b0e \
  ./scripts/test-multi-hub-witness.sh
```

Agreement means the hubs returned byte-equivalent signed material. It
does not make either hub authoritative.

## CI bot actors (the BBB pattern)

A bot is just an actor whose private key lives in a CI secret. The
substrate already treats signing identity as portable — there is no
distinction between "human signs" and "bot signs."

```bash
# 1. Generate a keypair locally.
vela sign generate-keypair --out ~/.vela/keys/my-bot

# 2. Register the pubkey in the frontier with a tier.
vela actor add path/to/frontier.json reviewer:my-bot \
  --pubkey "$(cat ~/.vela/keys/my-bot/public.key)" \
  --tier auto-notes

# 3. Push the private key into a GitHub Actions secret.
gh secret set MY_BOT_KEY --repo me/repo < ~/.vela/keys/my-bot/private.key

# 4. Wipe the local copy. The secret is now the only authoritative
#    custodian. Rotation = generate a new key, update the frontier,
#    re-push the secret, commit. There is no "read out" of the secret.
rm ~/.vela/keys/my-bot/private.key
```

The BBB living-repo workflow at
[`.github/workflows/bbb-living-repo.yml`](../.github/workflows/bbb-living-repo.yml)
is a worked example.

## Self-hosting

The hub is one Rust binary plus a SQL backend — Postgres for production
or SQLite for low-volume self-hosted use (v0.21).

### SQLite (self-hosted, zero infrastructure)

```bash
cargo build --release -p vela-hub
VELA_HUB_DATABASE_URL="sqlite:///path/to/your-hub.db" \
  ./target/release/vela-hub
```

That's the whole setup. The hub auto-creates the schema on first
startup (`CREATE TABLE IF NOT EXISTS …`); subsequent runs reuse the
file. Ideal for a laptop hub mirroring the public one for offline use,
a small institution publishing one corpus, or anyone running the
federation pattern from §Federation without a Postgres dependency.

The SQLite backend serves every endpoint the Postgres one does:
`GET /entries`, `GET /entries/{vfr_id}`,
`GET /entries/{vfr_id}/events`, `GET /entries/{vfr_id}/depends-on`,
`POST /entries`, `vela registry pull --from`, `vela registry mirror --to`.
Verified end-to-end against the public hub: pulling a BBB-mirrored
frontier from a SQLite hub returns byte-identical bytes with
`verified=true`, same as pulling from `hub.constellate.science`.

### Postgres (production)

For higher concurrency / larger data, point at a Postgres URL instead
and apply this schema once:

```sql
CREATE TABLE registry_entries (
  id BIGSERIAL PRIMARY KEY,
  vfr_id TEXT NOT NULL,
  schema TEXT NOT NULL,
  name TEXT NOT NULL,
  owner_actor_id TEXT NOT NULL,
  owner_pubkey TEXT NOT NULL,
  latest_snapshot_hash TEXT NOT NULL,
  latest_event_log_hash TEXT NOT NULL,
  network_locator TEXT NOT NULL,
  signed_publish_at TIMESTAMPTZ NOT NULL,
  signature TEXT NOT NULL,
  raw_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_entries_vfr_id ON registry_entries (vfr_id);
CREATE INDEX idx_entries_signed_publish_at ON registry_entries (signed_publish_at DESC);
CREATE UNIQUE INDEX uq_entries_vfr_signature ON registry_entries (vfr_id, signature);

-- Snapshot metadata is content-addressed by snapshot_hash. Bulk bytes
-- may live in object storage (Tigris/R2/S3) at blob_url, but snapshots
-- are derived exports. Live reads use frontiers/frontier_events/
-- frontier_objects after event-first promotion.
CREATE TABLE frontier_snapshots (
  snapshot_hash TEXT PRIMARY KEY,
  schema_version TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  blob_url TEXT NOT NULL,
  content_type TEXT NOT NULL DEFAULT 'application/json',
  inserted_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_snapshots_inserted_at ON frontier_snapshots (inserted_at DESC);

CREATE TABLE frontiers (
  vfr_id TEXT PRIMARY KEY,
  registry_entry_id BIGINT REFERENCES registry_entries(id),
  name TEXT NOT NULL,
  owner_actor_id TEXT NOT NULL,
  owner_pubkey TEXT NOT NULL,
  latest_snapshot_hash TEXT NOT NULL,
  latest_event_log_hash TEXT NOT NULL,
  schema_version TEXT NOT NULL,
  signed_publish_at TIMESTAMPTZ NOT NULL,
  snapshot_blob_url TEXT NOT NULL DEFAULT '',
  snapshot_size_bytes BIGINT NOT NULL DEFAULT 0,
  findings_count BIGINT NOT NULL DEFAULT 0,
  events_count BIGINT NOT NULL DEFAULT 0,
  sources_count BIGINT NOT NULL DEFAULT 0,
  evidence_atoms_count BIGINT NOT NULL DEFAULT 0,
  condition_records_count BIGINT NOT NULL DEFAULT 0,
  materialized_snapshot_json JSONB NOT NULL,
  authority_mode TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'live',
  inserted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE frontier_events (
  vfr_id TEXT NOT NULL REFERENCES frontiers(vfr_id) ON DELETE CASCADE,
  seq BIGINT NOT NULL,
  event_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  target_type TEXT NOT NULL,
  target_id TEXT NOT NULL,
  actor_id TEXT NOT NULL,
  event_timestamp TIMESTAMPTZ NOT NULL,
  raw_json JSONB NOT NULL,
  inserted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (vfr_id, seq),
  UNIQUE (vfr_id, event_id)
);

CREATE TABLE frontier_objects (
  vfr_id TEXT NOT NULL REFERENCES frontiers(vfr_id) ON DELETE CASCADE,
  object_type TEXT NOT NULL,
  object_id TEXT NOT NULL,
  seq BIGINT NOT NULL DEFAULT 0,
  target_id TEXT,
  raw_json JSONB NOT NULL,
  inserted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (vfr_id, object_type, object_id)
);

CREATE TABLE frontier_publish_audit (
  id BIGSERIAL PRIMARY KEY,
  vfr_id TEXT NOT NULL,
  registry_entry_id BIGINT REFERENCES registry_entries(id),
  latest_snapshot_hash TEXT NOT NULL,
  signed_publish_at TIMESTAMPTZ NOT NULL,
  status TEXT NOT NULL,
  error TEXT,
  authority_mode TEXT,
  findings_count BIGINT NOT NULL DEFAULT 0,
  events_count BIGINT NOT NULL DEFAULT 0,
  sources_count BIGINT NOT NULL DEFAULT 0,
  evidence_atoms_count BIGINT NOT NULL DEFAULT 0,
  condition_records_count BIGINT NOT NULL DEFAULT 0,
  verified_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

The executable schema source is
[`crates/vela-hub/src/db.rs`](../crates/vela-hub/src/db.rs) in
`POSTGRES_EVENT_FIRST_SCHEMA`. Use that constant or the backfill binary
for real migrations so indexes stay in sync with code.

### Event-first backfill

```bash
VELA_HUB_DATABASE_URL="postgres://..." \
  cargo run -p vela-hub --bin vela-hub-backfill-event-first -- --dry-run

VELA_HUB_DATABASE_URL="postgres://..." \
  cargo run -p vela-hub --bin vela-hub-backfill-event-first
```

The backfill selects the latest registry row per `vfr_id`. It fetches
from `frontier_snapshots.blob_url` when present and otherwise from
`network_locator`, verifies the registry signature, snapshot hash,
event-log hash, and schema, then promotes only verified rows. Failed
latest rows get `frontier_publish_audit.status = 'failed'` and do not
appear in `/entries`.

Direct Postgres publish helpers are intentionally absent after the
event-first cutover. New publishes go through `POST /entries` so
signature verification, snapshot hashing, event decomposition, audit
recording, and projection promotion happen in one path.

Deploy:

```bash
flyctl launch --no-deploy --config crates/vela-hub/fly.toml \
  --dockerfile crates/vela-hub/Dockerfile --copy-config \
  --name <your-hub-name> --org <your-org> --region <region>
flyctl secrets import --config crates/vela-hub/fly.toml < /path/to/prod.env
flyctl deploy --config crates/vela-hub/fly.toml \
  --dockerfile crates/vela-hub/Dockerfile .
```

The runtime needs only `VELA_HUB_DATABASE_URL`. Local dev can fall
back to `~/.vela/hub.env`. Other platforms work identically — the hub
is platform-agnostic; swap the runtime.

## Production runbook

Use these checks before and after any hub deploy:

```bash
cargo build --release -p vela-hub -p vela-protocol
curl -fsS https://hub.constellate.science/healthz | jq
curl -fsS https://hub.constellate.science/entries/vfr_496956067dc5ad79 | jq '.vfr_id'
curl -fsS 'https://hub.constellate.science/entries/vfr_496956067dc5ad79/events?limit=1' | jq '.events[0].id'
```

The Sidon-sets frontier (`examples/sidon-sets`, `vfr_496956067dc5ad79`, the
keystone OEIS-adoption frontier) is the public canary. It must be live,
pullable, snapshot-verified, and event-feed verified before a deploy is
considered healthy.

Deploy the hub:

```bash
flyctl deploy --config crates/vela-hub/fly.toml \
  --dockerfile crates/vela-hub/Dockerfile --depot=true .
```

**Always pass `--depot=true`.** `vela-hub` lives in the `vela-237` org, but
flyctl's default remote builder is the `fly-builder-*` app in the (currently
suspended) `personal` org — deploys without `--depot` route to that dead
builder and fail with `error releasing builder: deadline_exceeded`. Depot
provisions a fresh managed builder scoped to the app's org and sidesteps the
fallback entirely. (The single-threaded `CARGO_BUILD_JOBS=1` in the Dockerfile
makes the final `vela-protocol`/`vela-hub` crates the slow part, ~6 min; it
guards against OOM on a small fly-builder. Depot builders have ample RAM, so if
the personal org is ever un-suspended this can be raised for faster builds.)

Rollback:

```bash
flyctl releases --config crates/vela-hub/fly.toml
flyctl deploy --config crates/vela-hub/fly.toml \
  --image <previous-image>
```

If a latest registry row fails verification, do not patch around it in
the database. Republish the frontier through `POST /entries` or run the
event-first backfill after the source locator is repaired. The failed row
belongs in `frontier_publish_audit`; it should not be promoted to
`frontiers`.

Nightly or pre-demo audit:

```bash
./scripts/full-conformance.sh --mode=ci
```

The gate hydrates every published frontier from the hub, reproduces the
canonical witnesses from scratch (`reproduce-sidon`, `reproduce-erdos`),
round-trips a cold clone (`clone-roundtrip-*`), and verifies decision
projections, artifact manifests, snapshot hashes, and event reads.

## Operational notes

- **Production credentials are not dev credentials.** The Fly secret
  is a Postgres role scoped to the hub schema tables and sequences. The
  dev sandbox URL in `~/.vela/hub.env` is for local testing.
- **Never paste connection strings into chat or commits.** If the URL
  ever appears in conversation, rotate the role's password.
- **Bot key rotation.** Generate a new keypair, run `vela actor add`
  to register the new pubkey in the frontier (replacing the old
  entry — `actor add` overwrites by id), commit, then update the CI
  secret. The old key stops being trusted as soon as the frontier
  re-publishes.
- **Hub compromise.** Anyone consuming the hub verifies the manifest's
  signature against `owner_pubkey` and the frontier's hashes against
  the manifest. The hub controls *availability*, not *authenticity*.

## Federation (capability, not active deploy)

Hub-to-hub federation is a *capability* of the protocol, not an
operational requirement. The doctrinal claim — *the signature is the
bind, not the hub identity* — was empirically validated end-to-end in
v0.20 against a second hub instance (`vela-hub-2`, since retired during
the current release consolidation: one canonical public hub at
<https://hub.constellate.science>, federation peers spun up by institutions
that need them).

The federation primitive remains:

```bash
vela registry mirror <vfr_id> \
  --from https://hub.constellate.science \
  --to https://your-hub.example.com
```

Mechanism: GET the signed manifest from `from/entries/{vfr_id}`, POST
the same bytes to `to/entries`. Both hubs validate the manifest's
Ed25519 signature against the embedded `owner_pubkey`. Mirroring is a
no-op for authenticity — neither hub gains any signing role.

What was validated end-to-end (the federation mechanism is unchanged; the
fixtures it was first proven on were the pre-consolidation AD cluster, since
retired):

- Multiple fixture frontiers mirrored cleanly between hub-1 and a peer.
- Re-mirroring the same vfr returns `duplicate=true` from the
  destination (idempotent on the `(vfr_id, signature)` unique
  constraint).
- `vela registry pull` against either hub produced byte-identical
  bytes with same `verified=true`.
- Snapshot hashes matched across hubs for the same vfr_id.

The public live list is now the math-wedge frontiers: Sidon sets
(`vfr_496956067dc5ad79`), Erdős problems, quantum codes, formal
conjectures, benchmark state, and the Erdős certificate lanes (see
`scripts/workspace.json` for the canonical registry). The retired AD
frontiers are gone from the hub; the mirror primitive is identical for any
frontier.

What this unblocks for any institution that runs its own peer:

- **Resilience:** mirror the public hub to a backup ahead of time and
  keep `vela registry pull` working if the public hub is unreachable.
- **Seeding:** a fresh hub instance can be primed from the public one
  without any signing roundtrip.
- **Independent deploys:** mirror the public hub's content for offline
  / air-gapped use, then publish your own frontiers independently.
- **The right substrate property:** pulling a frontier doesn't require
  trusting a single hub. Any hub serving the bytes is sufficient
  because the signature is over the publisher's content, not the
  serving infrastructure.

What is intentionally *not* shipped here:

- A second always-on operational peer. Federation is a capability for
  institutions that want their own hub; it is not "high availability"
  for the public hub. If the public hub needs HA, that is a hosting
  decision (Fly autoscale, Neon read replicas), not a federation one.
- Automatic mirror (cron-style sync between hubs). The `mirror`
  primitive is the building block; an automated mirror is one bash
  loop or one CI job around it. Defer until someone runs it manually
  enough to feel the friction.
- Hub-A-discovers-hub-B / cross-hub queries (e.g. "which hubs have a
  copy of this vfr_id"). Each hub stays autonomous; clients pick which
  hub to talk to.

## What is deferred

Each of these is enabled by what's shipped, but not in scope:

- Hub-hosted frontier blobs. The locator is wherever the publisher
  hosts the file.
- Webhooks. SSE is live for event reads.
- Per-pubkey rate limits, allowlists, abuse handling. Add when abuse
  exists.
- A real domain (e.g. `hub.vela.science`). The Fly URLs are sufficient.
