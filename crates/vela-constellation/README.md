# vela-constellation

Vela Constellation layer: a network of connected Atlases across
scientific domains.

The Constellation primitive is Carina v0.5 (the sixteenth Carina
type). Atlas (`vat_*`) stays the unit of reviewer-confirmed
bridges; Constellation (`vco_*`) is a read-only composition over
per-Atlas snapshots.

## Substrate stack

```
Frontier (vfr_*)        bounded reviewable state, unit of replay
    │
Atlas (vat_*)           living domain map, unit of bridges
    │
Constellation (vco_*)   cross-domain map, read-only over Atlases
```

## What this crate ships at v0.81

- `ConstellationManifest`: typed
  `constellations/<name>/manifest.yaml`.
- `ConstellationSnapshot`: the materialized cross-Atlas view.
- `init_constellation()`: scaffolds a new Constellation pointing
  at one or more Atlases by `vat_*` id.
- `materialize_constellation()`: reads each composing Atlas's
  `snapshot.json` (re-materializing on demand for freshness),
  sums findings + events + bridges across, and writes
  `snapshot.json` + `index.html` for the Constellation.

## See also

- `docs/MISSION_ATLAS.md` for the doctrine.
- `examples/carina-kernel/schemas/constellation.schema.json`
  for the v0.5 Carina schema.
- `crates/vela-atlas/` for the Atlas layer this crate composes
  over.

## License

Dual-licensed under Apache-2.0 OR MIT.
