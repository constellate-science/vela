# HorizonMath — verifier-attackable target catalog

`catalog.json` stages the **verifier-attackable subset** of the HorizonMath
benchmark: open/research mathematics problems that map to a frozen Vela verifier
(a `vela campaign` kind) and carry a real incumbent (the value-to-beat). It is
the target surface the foundry attacks, the same role `frontiers/sidon-sets/bounds.json`
plays for Sidon, generalized across verifier families.

Each problem records `{id, domain, level, statement, verifier_kind, params,
incumbent{value, direction, basis}, status, source}`. `source` is the honest
provenance: `horizonmath` for the difference-triangle flagship (DTS(7,5),
value-to-beat 112, from the Constellate ingestion memo), `constructions_board`
/ `oeis` for the construction families whose incumbents come from the live
[Open Constructions board](../../../apps/web/app/constructions/page.tsx) and OEIS.

This is **not** the full 101-problem corpus. The corpus-level facts (101
problems, 91 unsolved, 8 domains, the level counts) are recorded under `corpus`;
the problems with no frozen Vela verifier are deferred, not fabricated.

## Ingest

```bash
vela atlas ingest-source --adapter horizonmath \
  --input frontiers/horizonmath/catalog.json \
  --out examples/horizonmath/frontier.json \
  --namespace horizonmath --rev hm-2026-06
```

Deterministic and offline: the adapter (`read_horizonmath`) reads this file,
mints content-addressed finding bundles (genesis remnants), attaches signed
`anchor.attached` events, then gates on `verify_replay`. Same catalog in, same
frontier out. The materialized `frontier.json` is a regenerable view; this
catalog is the canonical source.
