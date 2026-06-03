# vela-atlas

Vela Atlas layer: a living, versioned map of a scientific domain
composed of one or more Vela frontiers.

The Atlas primitive is Carina v0.4 (the fifteenth Carina type).
Frontier (`vfr_*`) stays the substrate-level unit of replay; an
Atlas (`vat_*`) is a read-only composition over per-frontier event
logs.

## What this crate ships at v0.78

- `AtlasManifest`: typed `atlases/<name>/manifest.yaml`.
- `Atlas` + `AtlasSnapshot`: the materialized composition view.
- `init_atlas()`: scaffolds a new Atlas pointing at one or more
  existing frontiers; computes a content-addressed `vat_*` id.
- `materialize_atlas()`: reads composing frontiers, unions
  accepted-core findings, computes a composition hash, writes
  `snapshot.json`.

The CLI surface (`vela atlas init / materialize / serve`) lives
in the `vela-cli` crate and routes through this library.

## Doctrine

- An Atlas does not rewrite frontier history. Composing two
  frontiers into an Atlas is read-only over their event logs.
- The composition hash is sha256 over the manifest's
  composing-frontier ids + confirmed bridges; running
  `materialize_atlas` twice on the same manifest produces the
  same hash.
- Atlas-level federation, signing, and the Workbench surface
  are v0.79+.

## See also

- `docs/MISSION_ATLAS.md` for the doctrine.
- `docs/PLAN_v0.78.md` for the work that landed this crate.
- `examples/carina-kernel/schemas/atlas.schema.json` for the
  Carina v0.4 Atlas schema.
- `examples/carina-kernel/primitives.v0.4.json` for the example
  Atlas composing brain-tumor-translation and
  anti-amyloid-translation.

## License

Dual-licensed under Apache-2.0 OR MIT.
