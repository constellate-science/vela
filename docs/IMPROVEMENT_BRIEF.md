# vela-oss improvement brief (from dogfooding audit)

I now have a complete, code-grounded picture of both repos. The audits are accurate. Let me synthesize the brief.

---

# IMPROVEMENT BRIEF — vela-oss: ship the trust gate the dogfooding proved is the product

## 1. THE THESIS GAP

The OSS proves the **log** is trustworthy and never proves the **claim** is. Every "verify" verb in the repo is signature verification of an attestation, never re-running the math: `crates/vela-protocol/src/proof_verification.rs:1-12` and `lean_verification.rs:1-17` both say in their own doc-comments that "the substrate does NOT run the verifier" — a consumer checks an Ed25519 signature and "trust[s] the verifier's judgment." A single signed attestation *is* a verified record. Meanwhile `reducer.rs:430-438` (`apply_finding_reviewed`) stamps `ReviewState::Accepted` straight from `payload.status == "accepted"` with zero attachment requirement — the exact "stamp before earning" anti-pattern. The one true quorum gate in the repo, `proposals.rs::replication_attestation_passes` (line 2820), reads self-reported booleans (`held_out_prompts`, `second_model_confirmed`) and is scoped only to the `agent:replicator` auto-accept path with no claim-digest binding. The internal campaign's actual product — `gate_verified()` in `scripts/canopus_trust.py:81-117` (G1 independence + G2 claim-match + G3 surviving adversarial probe + G4 well-formed), `grade_gate()` (line 119), the honest GRADES taxonomy, `reproduce.py`'s from-scratch re-verification of every witness, and `SidonCertificate.lean`'s `native_decide` cert — is **entirely absent**. Shipping it converts vela-oss from "signed version control for science" (a commodity) into "the layer where a claim becomes trusted only by independent re-derivation + a surviving probe" (the differentiated thing that caught every overclaim and fed the first OEIS adoption).

## 2. MAKE THE TRUST GATE FIRST-CLASS

It must be **all four** — a protocol object, a derived reducer rule, a CLI pair, and a conformance vector — because the dogfooding proved a gate that is only one of these leaks.

- **Protocol object (new crate `crates/vela-verify`):** Promote `VerifierAttachment` (`vva_`) to a first-class primitive. The current `research_trace.rs:85` `TraceVerifierAttachment` is 4 fields short — `{id, kind, locator, content_hash, verifies}` — a flat provenance receipt that can never *count* or *diversify*. Port `make_attachment` from `canopus_trust.py:63-78` verbatim in shape:
  ```
  vva_: { target_claim_id, claim_digest, verifier_method, solver_id,
          independent_of: [vva_…], match_to_claim: {matches, checker_actor},
          adversarial_probes: [{kind, result}], outcome }
  ```
  `proof_verification.rs` (`vpv_`) and `lean_verification.rs` (`vlv_`) become two *methods* (`lean_kernel`, `exact_construction`) that emit a `vva_`, not standalone verdicts.

- **Reducer rule (normative, in `vela-protocol`):** Add `derive_gate_status()` that **computes** `verified | needs_verification | refuted` as a pure function of the attachment set — G1 (≥2 matched attachments by different `(method, solver)`, mutually declaring `independent_of`), G2 (`claim_digest` match), G3 (≥1 probe, none `refuted`; a refuted probe forces `refuted`), G4 (well-formed). This is *exactly* the doctrine `status_provenance.rs` already encodes for Belnap polarity ("Status is never persisted independently of the polynomials that justify it") — extend that proven pattern from evidence polarity to the quorum gate. A lone signed `vpv_` never yields verified.

- **CLI:** `vela verify <finding>` runs the gate over the finding's attachments and prints which of G1–G4 fail (mirror `canopus_trust.py __main__`). `vela bank <finding>` refuses unless the gate passes, then emits the verified state transition and the `adoption_log` entry. Generalize `proposals.rs::replication_attestation_passes` off its booleans onto the `vva_` set and have both commands call it.

- **Documented standard:** `docs/TRUST_GATE.md` (docs/ currently holds *one* file). State the invariant — "verified is a gate output, never self-asserted; trust is earned via ≥2 independent attachments + a surviving adversarial probe" — and map each of G1–G4 to the real overclaim it caught (the phantom +48 Sidon reduced to 9, the #699 0-sorry-but-unmatched Lean proof, the finite-size illusion).

## 3. THE CONTRIBUTION WORKFLOW

The canonical end-to-end flow `vela-oss` must ship: **produce → verify (re-run, don't trust) → bank (through the gate) → adopt (submit)**. Today the on-ramp ends at signature-deposit — `README.md:38-52` shows `vela registry propose` and stops; the value begins exactly where the README ends. What's missing to let an external scientist do it:

1. **`vela reproduce`** — re-runs a registered exact verifier over every stored witness *from scratch*, exits non-zero on any failure (mirror `reproduce.py`). Right now the OSS cannot re-run a single verifier; `grep -r "Sidon\|Golomb\|Costas\|cap.set" crates/*/src` returns empty. This command is what makes the trust non-self-reported.
2. **A frozen exact-verifier registry** in `vela-verify` (start with Sidon + Golomb + linear-code, the three with shipped records), ported from `scripts/verify_construction.py`. Each emits a `vva_` attachment.
3. **`vela contribute`** — one command wrapping produce→verify→bank, with `CONTRIBUTING.md` walking it using **OEIS A309370 as the worked example** (the repo's real adoption proof point — currently invisible).
4. The terminus already exists (`adoption_log.rs`) but is disconnected from any gate; wire it so `vela bank` is the only thing that writes a verified transition into it.

## 4. PRIMITIVES TO ADD — protocol-level vs reference-app-level

| Primitive | Level | Why |
|---|---|---|
| **VerifierAttachment `vva_`** | **Protocol** (kernel) | It's the load-bearing noun; everything else is a predicate over a set of these. Schema: new `schema/verifier-attachment.v0.1.json`. |
| **`derive_gate_status()` / gate_verified** | **Protocol** (reducer) | "verified is an output" must be a normative reducer guarantee, not an app convention, or a second implementation can launder. |
| **`deliverable_grade` enum + `grade_gate`** | **Protocol** (reducer lint) | Port `GRADES`/`SOLVE_LANGUAGE` from `canopus_trust.py:37-45` verbatim. Block solve-language in claim text unless the grade ∈ `SOLVE_GRADES`. `events.rs` already validates `CausalEvidenceGrade`; this is the *solve/null* axis (orthogonal — `CausalEvidenceGrade` answers evidence-strength, a different question). Cheapest high-leverage change: pure enum + string check. |
| **Attempt-ledger** | **Reference-app** | The ledger (`canopus_attempts.py`) is a campaign-management surface; the protocol only needs the attachments and findings it produces. Keep it out of the kernel. |
| **FrontierGraph edge tier** | **Protocol** (small) | Add `tier` + `needs_accept` to `frontier_graph.rs:34` `EdgeKind` (or split into `kind` + `tier`). `build_frontier_graph_v5.py:54` proves the shape: tier-1 verified vs tier-2 draft, "never laundered." This lets "agent drafts, human accepts" be expressed in the kernel. |
| **Witness/result certificate `vcert`** | **Protocol** (schema) + Lean | Bind `{claim_digest, target_id, verifier_method, verifier_output_hash, toolchain+mathlib pin}`. Generalize `lean_anchors.rs:37` `THEOREMS` from a hardcoded 34-element static array into a registry that accepts contribution-level declarations. Ship `SidonCertificate.lean` into `vela-oss/lean/` as the worked `native_decide` example. |

## 5. HARDENING

- **The gate_status-before-attachments bug class (learning #4):** make it structurally impossible, not just fixed. `gate_status` must have **no setter** — it's only ever a return value of `derive_gate_status(attachments)`, recomputed on every attachment deposit and every read, exactly as `status_provenance.rs` recomputes Belnap status. Add a reducer test asserting that depositing a finding with `payload.status: "accepted"` and zero attachments yields `needs_verification`, not `Accepted` — that test fails against today's `reducer.rs:430-438` and is the regression lock.
- **Split conformance into two tracks.** Track A (replay-determinism) exists. Add **Track B (verification-soundness)**: the current 12 fixtures only assert reducer state-mutation agreement — a conformant impl could pass all of them while accepting a phantom Sidon +48 record, because nothing requires *rejecting* anything. Add **adversarial reject-vectors** per verifier kind (a tampered witness MUST fail; a claim-mismatch MUST fail; one attachment MUST NOT verify; two-independent + surviving probe MUST verify; a refuted probe MUST force `refuted`). Register the gate predicate in `conformance/spec-surface.v1.json` (today it lists `replication.deposited` and `finding.reviewed` but no gate predicate). This is what makes "Vela-compatible" mean "catches overclaims" instead of "agrees on how to stamp."
- **Amend `conformance/README.md`** to scope the current contract as replay-agreement only and point at Track B, so no fourth implementer believes a green replay run means their accepts are earned.

## 6. WHAT TO CUT / FINISH / DOCUMENT

- **README is off-message — rewrite it (highest-ROI single edit).** `grep` of `README.md` for `verif|gate|grade|reproduce|adversarial|adopt` returns nothing; it leads with "compiles research artifacts into a versioned frontier" and "admitted on the strength of its signature." That advertises the commodity half and hides the product. Lead instead with: *trust is earned, not asserted — a claim becomes verified only after ≥2 independent attachments by different method/solver AND a surviving adversarial probe; most honest output is nulls/partials/reductions; the value path is produce→verify→bank→adopt*, citing the 9 OEIS A309370 records. Demote (don't delete) the signature line: signature is necessary, not sufficient.
- **Fix doc-rot in one sweep.** Source comments reference files that don't exist: `proof_verification.rs:11-12` cites `docs/PROOF_VERIFICATION.md` + `.github/workflows/verify-carina-proofs.yml` (no `.github/` dir exists); `Cargo.toml:24,29` and the relay/search Cargo.toml `documentation=` fields point at `docs/RELAY.md`/`docs/SEARCH.md` (404); `lean/README.md` references `docs/THEORY_AUDIT.md` + `docs/PROTOCOL_GUARANTEES.md` (absent); `bindings/python/README.md` cites `scripts/cross_impl_conformance.py` + `examples/python-agent/` (no `scripts/` or `examples/` dir). Either create or delete each reference. A repo whose own Cargo links 404 reads half-built — fatal for an open-protocol play.
- **Consolidate scatter.** Fold `schemas/knowledge_packet.schema.json` into `schema/` and delete the orphan dir. Clarify in the README table that `bindings/` is an HTTP SDK and only `clients/` are reducers (today's table says "Python and TypeScript reducers" for both). Land the `vela-cli` `try_handle_atlas_r2_verify_intercept` primitives into the protocol dispatcher or document the seam.
- **Decide on the 15 `Transfer*.lean` files.** Internal memory records the transfer-amplification thesis (Law 9) as *falsified* — transfers give no discovery amplification. Don't ship Lean proofs of soundness for a discovery mechanism the team no longer believes amplifies discovery; either reframe them as structural-composition proofs (honest) or cut them.

## 7. PRIORITIZED ROADMAP (top 8, impact/effort)

| # | Change | Impact | Effort | Files |
|---|---|---|---|---|
| 1 | **`deliverable_grade` enum + `grade_gate`** in reducer | High | **S** | `bundle.rs`, `events.rs`, `reducer.rs`; port `canopus_trust.py:37-45,119-130` |
| 2 | **README rewrite** to verifier-first story | High | **S** | `README.md` |
| 3 | **`vva_` VerifierAttachment** primitive + schema | High | **M** | new `crates/vela-verify`, `schema/verifier-attachment.v0.1.json`; port `canopus_trust.py:63-78` |
| 4 | **`derive_gate_status()`** reducer rule (G1–G4), no setter | High | **M** | `reducer.rs:430-438`, new gate module; mirror `status_provenance.rs` |
| 5 | **`vela verify` / `vela bank`** CLI | High | **M** | `cli_commands.rs`, `cli_check.rs`; generalize `proposals.rs:2820` |
| 6 | **Frozen exact verifiers + `vela reproduce`** | High | **M-L** | `crates/vela-verify`; port `verify_construction.py` + `reproduce.py` |
| 7 | **Track-B conformance reject-vectors** + gate predicate | High | **M** | `conformance/fixtures/`, `spec-surface.v1.json`, `README.md` |
| 8 | **`SidonCertificate.lean` + `vcert` registry** in CI closure | Med | **M** | `lean/Vela/`, generalize `lean_anchors.rs:37`; `CONTRIBUTING.md` w/ A309370 |

**FIRST 3 TO BUILD NOW:**
1. **`grade_gate` + `deliverable_grade` enum** (#1) — a day, pure enum+string check, zero new infrastructure, and it's the credibility moat that is 100% absent today. Lands the anti-inflation discipline as a protocol guarantee.
2. **`vva_` VerifierAttachment + `derive_gate_status()`** (#3+#4 together) — the load-bearing pair. Without the attachment object the gate has nothing to be a predicate *over*; without the derived status the bug class stays open. Build them as one PR in a new `crates/vela-verify`, with the reducer test that asserts "zero attachments → `needs_verification`."
3. **`vela verify` / `vela bank`** (#5) — exposes the gate as the on-ramp and gives the produce→verify→bank flow a CLI terminus into `adoption_log`.

---

**The single highest-leverage thing to build first:** the `vva_` VerifierAttachment primitive plus a reducer-derived `derive_gate_status()` (G1 independence + G2 claim-digest + G3 surviving probe + G4 well-formed) with **no setter on `gate_status`**. The OSS already has every ingredient — single attestations in `proof_verification.rs`, a boolean quorum in `proposals.rs`, and derived-not-persisted status in `status_provenance.rs` — but has never assembled them into the gate. Assembling them is the one change that turns a finding-store-with-receipts into the verifier-gated trust kernel the dogfooding proved is the actual product, and it structurally kills the gate_status-before-attachments bug at the same time.

Key file references — OSS: `/Users/williamblair/personal/vela-oss/crates/vela-protocol/src/{proof_verification.rs:1-12, lean_verification.rs:1-17, reducer.rs:415-440, proposals.rs:2767-2854, status_provenance.rs:1-60, research_trace.rs:85-91, frontier_graph.rs:34, lean_anchors.rs:37, bundle.rs:2066}`, `conformance/{fixtures/, spec-surface.v1.json, README.md}`, `README.md`, `docs/` (single file). Internal: `/Users/williamblair/personal/vela/scripts/{canopus_trust.py:37-130, canopus_attempts.py:46-74, verify_construction.py, reproduce.py, build_frontier_graph_v5.py:54}`, `lean/Vela/SidonCertificate.lean`.