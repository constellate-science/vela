# ID prefix registry

Every content-addressed object in the substrate carries a short
`v*_` prefix in front of its hex digest. This file is the authoritative
meaning of each live prefix. Prefixes are load-bearing: they appear
inside signed preimages and stored event logs, so **live prefixes are
never renamed** — collisions are documented here as known debt instead.

The naming dictionary in the frontier-calculus writeup defers to this
table.

## Protocol objects (canonical state)

| prefix | object | Rust home |
|---|---|---|
| `vf_` | finding | `bundle.rs`, replayed in `reducer.rs` |
| `vfr_` | frontier | `project.rs` |
| `vev_` | signed canonical event | `events.rs` |
| `vpr_` | proposal | `proposals.rs` |
| `vat_` | **attempt** (banked attempt deposit) | `attempt.rs` |
| `vre_` | attempt resolution event | `attempt.rs` |
| `vtr_` | **cross-domain transfer** | `transfer.rs` |
| `vsa_` | statement attestation (faithfulness) | `statement_attestation.rs` |
| `vatt_` | reviewer attestation (identity) | `reviewer_identity.rs` (vela-edge) |
| `vva_` | verifier attachment | `verifier_attachment.rs` |
| `vpf_` | Carina Proof primitive | `state.rs` / `events.rs` |
| `vpv_` | proof-verification record | `proof_verification.rs` |
| `vlv_` | Lean verification record | `lean_verification.rs` |
| `vtcb_` | Lean trusted-computing-base policy | `tcb_policy.rs` |
| `vla_` | Lean theorem anchor | `lean_anchors.rs` (vela-edge) |
| `vsd_` | scientific diff pack | `released_diff_pack.rs` |
| `vfrr_` | frontier release | `frontier_template.rs` / releases |
| `vnr_` | negative result | `bundle.rs` |
| `vrep_` | replication | `bundle.rs` |
| `vpred_` | prediction | `bundle.rs` |
| `vres_` | prediction resolution | `bundle.rs` |
| `va_` | content-addressed artifact | `state.rs` |
| `vd_` | dataset artifact | `state.rs` |
| `vc_` | code artifact | `state.rs` |
| `vea_` | evidence atom | `sources.rs` / `reducer.rs` |
| `vbr_` | bridge (cross-frontier hypothesis) | `bridge.rs` (vela-edge) |
| `vcx_` | contradiction (T7 object) | `contradiction.rs` |
| `vdc_` | verdict conflict | `verdict_conflict.rs` |
| `ven_` | endorsement | `endorsement.rs` |
| `vib_` | producer identity binding | `identity.rs` |
| `vir_` | identity revocation | `identity.rs` |
| `vrt_` | research trace | `research_trace.rs` (vela-edge) |
| `vtri_` | trial outcome record | `carina_validate.rs` (vela-edge) |
| `vtd_` | tool descriptor | `tool_registry.rs` (vela-edge) |
| `vaa_` | agent attestation | `bundle.rs` / `scientific_diff.rs` |
| `vtask_` | local frontier task | `frontier_task.rs` (vela-edge) |
| `vsrcin_` | source-inbox record (legacy writer removed; ids still replay) | `source_inbox.rs` (vela-edge) |
| `vrm_` | review-thread message (legacy writer removed) | historical logs only |
| `vrs_` | review session (legacy writer removed) | historical logs only |
| `vrp_` | review packet | `reviewer_identity.rs` (role-scoped target) |
| `vaf_` | friction record (legacy writer removed) | historical logs only |
| `vinc_` | incident record (legacy writer removed) | historical logs only |
| `vex_` | experiment (Carina primitive) | `attempt.rs` references |
| `vsx_` | hub untrusted scratch entry (`vela stash`) | vela-hub scratch tier |
| `vhs_` | federated-hub spec | `hub_spec.rs` |

## Registry / governance objects

| prefix | object |
|---|---|
| `vgp_` | registry governance policy |
| `vop_` | owner-rotate proposal |
| `vab_` | owner-rotate attestation bundle |
| `vrc_` | registry checkpoint |
| `vac_` | actor handle |
| `vsi_` | search index |

## Composition handles (Carina spec tier)

| prefix | object |
|---|---|
| `vat_` | Carina **atlas** primitive (see collision below) |
| `vct_` / `vco_` | Carina constellation primitive (`vct_` in the handle resolver, `vco_` in the schema) |

## Known collisions (documented debt — do not rename)

1. **`vat_` — attempt vs. Carina atlas.** The authoritative protocol
   sense is the *attempt* (`attempt.rs`, signed deposits verified by
   `vela attempt`). The Carina spec tier reuses `vat_` for the atlas
   primitive (`embedded/carina-schemas/atlas.schema.json`,
   `vela carina validate --primitive atlas`), and the handle resolver
   (`resolver.rs`) still maps bare `vat_<hex>` handles to atlas URLs.
   Both are live (attempts in the event log; atlas in the shipped
   Carina schema set), so neither side can be renamed without breaking
   stored ids. Treat bare-`vat_` handle resolution as ambiguous.

2. **`vtr_` — transfer vs. trajectory.** The authoritative protocol
   sense is the *cross-domain transfer* (`transfer.rs`, verified by
   `vela transfer`). The trajectory object
   (`schema/trajectory.v0.1.0.json`, `trajectory.*` event kinds, the
   `vela_agent_open_trajectory` MCP tool) also mints `vtr_<16hex>` ids.
   The trajectory CLI surface was removed in v0.700 but the event kinds
   remain normative and historical logs contain `vtr_` trajectory ids,
   so the prefix cannot be reclaimed. Disambiguate by context: a
   `vtr_` inside `.vela/trajectories/` or a `trajectory.*` event is a
   trajectory; everywhere else it is a transfer.

3. **`vsa_` vs. `vatt_` — two attestations.** Not an id collision but a
   recurring vocabulary trap: `vsa_` is the *statement* attestation
   (does the formal statement faithfully encode the informal problem),
   `vatt_` is the *reviewer identity* attestation. The bare word
   "attestation" is banned in spec prose; always qualify as
   "statement attestation (`vsa_`)" or "reviewer attestation
   (`vatt_`)". (`vaa_` agent attestations and `vab_` owner-rotate
   bundles are further, distinct attestation-shaped objects.)
