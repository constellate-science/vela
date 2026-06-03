# vela-search

Build-time content-addressed index over registered Vela frontiers. Indexes findings + actors with substring search + per-filter narrowing.

The index is a derived view; the canonical state stays in the registry + frontier event logs. See [docs/SEARCH.md](https://github.com/vela-science/vela/blob/main/docs/SEARCH.md).

## Usage

```rust
let cfg = vela_search::IndexerConfig {
    include_bootstrap: false,
    include_broken: false,
};
let index = vela_search::build_index(&frontier_paths, &cfg, &now)?;
let hits = vela_search::search(&index, "apoe4", &vela_search::SearchFilters::default());
```

Shipped with Vela Arc 4 (v0.149) of the substrate.
