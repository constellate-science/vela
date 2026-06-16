# Vela Hub

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

## Release verification boundary

The hub is signed transport. It is not the scientific source of truth.
Release checks can prove that the published anti-amyloid frontier id
matches the expected snapshot and event-log hashes, but the authority
still comes from local frontier state, signed events, and proof packet
validation.

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
./scripts/audit-live-frontiers.sh --frontier vfr_5076e7b3ff8e6b0f --json | jq
curl -fsS https://hub.constellate.science/healthz | jq
curl -fsS https://hub.constellate.science/entries/vfr_5076e7b3ff8e6b0f | jq '.vfr_id'
curl -fsS 'https://hub.constellate.science/entries/vfr_5076e7b3ff8e6b0f/events?limit=1' | jq '.events[0].id'
```

The focused anti-amyloid frontier is the public canary. It must be live,
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
./tests/test-anti-amyloid-p0-gates.sh
```

This gate verifies the focused frontier, decision projections, artifact
manifests, current-source freshness, hub pullability, snapshot hashes,
and event reads.

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

What was validated end-to-end before the consolidation:

- 3 fixture frontiers (legacy BBB proof fixture, BBB-extension, Will's
  Alzheimer's drug-target landscape) mirrored cleanly between hub-1 and
  a peer.
- Re-mirroring the same vfr returns `duplicate=true` from the
  destination (idempotent on the `(vfr_id, signature)` unique
  constraint).
- `vela registry pull` against either hub produced byte-identical
  bytes with same `verified=true`.

After the public-frontier clamp on 2026-05-07, BBB-extension and Will's
drug-target landscape are retained as local fixtures and registry
history, but their `frontiers.status` rows are `archived`. The public
live list now contains only the focused anti-amyloid frontier and the
broad Alzheimer reservoir.
- Snapshot hashes matched across hubs for the same vfr_id.

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
