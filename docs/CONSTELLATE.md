# Constellate

Open infrastructure for cumulative science.

## What this name means

**Constellate** is the umbrella ecosystem name. It is a verb. It
means *to unite into a cluster, or to set as if with
constellations* (Merriam-Webster). The word is a noun in
disguise: it names what the ecosystem does, not what it is.

Science begins as scattered light: papers, datasets, lab
results, failed experiments, reviews, AI-agent outputs,
hypotheses, clinical observations, student curiosity, expert
memory. None of that automatically compounds. **Constellate**
is the system that turns scattered scientific activity into
findings, evidence, proposals, diffs, attestations, events,
Atlases, frontiers, and replayable scientific state.

The one-line vision:

> Constellate turns scientific activity into scientific state.

The longer one:

> Constellate turns scattered scientific light into living maps
> of what humanity knows, does not know, and should do next.

## The hierarchy

| Layer | What it is | Reified as |
|---|---|---|
| **Constellate** | The public ecosystem; the movement; the foundation; the umbrella organization | constellate.science (planned) |
| **Vela** | The protocol that moves activity into state | `vela-protocol`, `vela-cli`, `vela-hub`, `vela-scientist` crates; `vela` binary |
| **Carina** | The kernel of primitive types and schemas | `examples/carina-kernel/` schemas; embedded in `vela-protocol` |
| **Atlas** | A living, versioned map of a scientific domain composed of one or more frontiers | `vat_*`; `vela-atlas` crate |
| **Constellation** | A network of connected Atlases across domains | `vco_*`; `vela-constellation` crate |
| **Frontier** | The bounded, reviewable state over one scientific question | `vfr_*`; substrate-level unit of replay |

The verb **constellate** describes the act. The noun
**Constellation** describes one of the things you get when you
do it. They are the same word family, not a collision.

## Why this is the right umbrella

- **Action vs object.** Sidera, Navis, Atlas, Firmament are
  beautiful nouns. Constellate is a verb. The ecosystem's
  proposition is *activity → state*, which is a transformation,
  which a verb captures and a noun does not.
- **Contains the whole story in one word.** Scattered light →
  connected structure → navigable science → cumulative state.
- **Absorbs the Borrowed Light essay.** The essay names the
  problem (preserving artifacts but not state) and the
  Constellate framing names the response. The essay can live
  inside the umbrella without being the umbrella.
- **Engineering name preserved.** Vela stays as the protocol.
  No code rename. The substrate is unchanged. Constellate is
  the public-facing layer above it.

## Disambiguation: JSTOR Constellate

[constellate.org](https://constellate.org/) is JSTOR/ITHAKA's
text-and-data-mining tool for educators and researchers, live
since 2020. It is a different product:

| Property | JSTOR Constellate | Constellate (this) |
|---|---|---|
| What | TDM tool for academic content analysis | Open protocol + ecosystem for cumulative scientific state |
| Audience | Educators, students, librarians | Researchers, agents, labs, institutions, contributors |
| Inputs | JSTOR / academic full-text corpora | Papers, agent artifacts, datasets, lab outputs, reviews, hypotheses |
| Outputs | Notebooks, lessons, datasets for analysis | Signed canonical events, replayable frontier state, living Atlases |
| Domain | constellate.org | constellate.science (planned) |

The category overlap is "scholarly tooling," but the product
shape is different. We acknowledge the namesake; we
differentiate by being the protocol layer (event-sourced,
replayable, content-addressed, multi-actor) rather than a
content-mining tool.

## What lives in the Constellate ecosystem

```
Constellate
├── Vela Protocol           (vela-protocol, vela-cli, vela-hub)
├── Carina Kernel           (specs + 17 primitives)
├── Atlases                 (vat_*; living domain maps)
├── Constellations          (vco_*; cross-domain networks)
├── Frontiers               (vfr_*; bounded reviewable state)
├── Navigator               (Workbench; review surface)
├── Registry                (federation; canonical record)
├── Relay                   (adapters: paper, artifact, hypothesis, review)
├── Observatory             (institutional intelligence)
├── Studio                  (education + contributor onboarding)
└── Commons                 (governance, standards, stewardship)
```

Some pieces are real today
(`vela-protocol`, `vela-cli`, `vela-hub`, `vela-atlas`,
`vela-constellation`); some are namespace-reserved on
crates.io (`vela-relay`, `vela-navigator`, `vela-registry`,
`vela-canopus`, `vela-observatory`); some are
ecosystem-layer-only and ride later cycles
(Studio, Commons, public Navigator product, hosted
Observatory).

## What does NOT change

- Engineering names. The Vela substrate stays Vela. The
  GitHub repo stays at `vela-science/vela`. The published
  crates stay `vela-protocol` / `vela-cli` / etc.
- Doctrine. No silent edits. Agents draft, reviewers attest,
  the substrate records. Append-only. Replay-deterministic.
  Per-frontier state. No public-site write surface.
- The Carina kernel + substrate primitives. 16 Carina types.
  9 canonical event kinds. All identifiers (`vf_*`, `vfr_*`,
  `vat_*`, `vco_*`, `vbr_*`, `vev_*`, `vpr_*`, `vpf_*`)
  unchanged.

## What does change (over time)

- Public-facing brand at `constellate.science` (when
  registered). Engineering docs continue to live at
  `vela-site.fly.dev` or get a redirect.
- Ecosystem language in public framing: "Constellate is open
  infrastructure for cumulative science. Built on the Vela
  protocol and the Carina kernel."
- Future ecosystem-layer crates use the `constellate-` prefix
  where the layer is genuinely above Vela (Studio, Commons,
  hosted Observatory) rather than a substrate primitive.

## Relationship to Borrowed Light

The Borrowed Light essay names the missing layer in science:
preservation of state, not just artifacts. Constellate is the
infrastructure that makes that layer concrete. The essay
remains a separate writing surface (borrowedlight.org); the
Constellate ecosystem is what the essay's argument compiles
into.

## Final framing

Borrowed Light is the essay.
Constellate is the ecosystem.
Vela is the protocol.
Carina is the kernel.
Atlas, Constellation, Frontier are the things you build with it.

That is the stack.

## See also

- `docs/MISSION_ATLAS.md`. Atlas as the next-layer-up
  composition over frontiers.
- `docs/AI_ATTRIBUTION.md`. The agent-vs-human-reviewer
  doctrine that scales unchanged from frontier to Atlas to
  Constellation.
- `docs/PROTOCOL.md`. Normative event semantics inside Vela.
- `docs/CARINA.md`. The kernel primitives and schemas.
- `docs/RELAY.md`. The four adapter shapes that produce
  reviewable proposals.
- `docs/EVENT_LOG.md`. The canonical event log walkthrough.
