# Cross-frontier search

Arc 4 ships `vela-search` as the seventh workspace crate
(v0.149) and `/search` + `/api/search.json` on the site
(v0.150).

## Substrate primitive

`vela search-index build <frontiers...> --out <path>` walks
each frontier path, derives chain status from
`<frontier>/.vela/governance/chain.json` (legacy / bootstrap /
verified / broken), and emits a content-addressed `vsi_*`
index JSON over findings + actors.

`vela search-index query <q> --index <path>` runs a lowercased
substring match + per-filter narrowing.

## Inclusion rules

- Strict mode (default): skips frontiers whose chain is
  `legacy`, `bootstrap`, or `broken`.
- `--include-bootstrap`: admits bootstrap + legacy frontiers.
- `--include-broken`: admits broken chains too (ops dashboards).

## Doctrine

The index is a **derived view**, never authority. Two
consumers who run `build` against the same frontiers produce
byte-identical indices (stable ordering by `(kind,
frontier_id, target_id)`). The canonical state stays in
registry + frontier event logs.

## Site surface

- `/search` page renders the first 100 results statically + a
  full client-side filter over the bundled in-memory payload.
- `/api/search.json` serves the full index as JSON for agent
  consumers + downstream dashboards.

The site's TypeScript loader at `site/src/lib/search.ts` is a
parallel of the Rust crate; two consumers (one building the
site, one running `vela search-index build`) produce parallel
indices over the same underlying frontiers. The TS parallel
keeps the site buildable without the Rust binary, which matters
for the Fly.io build container.

## Future extensions

- Convergence: future cycle can have the site read the
  Rust-produced index file directly rather than re-implementing
  the loader in TypeScript.
- Index-hash declaration in checkpoints: v0.151+ cycles can
  embed the index hash inside the registry checkpoint so the
  site can cross-check the index against the most recent
  signed checkpoint.
- Per-shard splits: if the payload grows large enough that
  the inline JSON impacts page weight, the loader can split
  into per-frontier shards keyed by `vfr_*`.
- Filter by proof status: the v0.152 verification records
  surface on `/theorems/[id]`; a future cycle adds a search
  filter for `proof_status=verified` over findings linked to
  proofs.
