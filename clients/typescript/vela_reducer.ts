#!/usr/bin/env -S bun run
//
// Vela reducer — third implementation, TypeScript stdlib-only.
//
// What this proves: the per-kind reducer mutation rules are protocol,
// not a Rust artifact and not a Python artifact. Three independent
// implementations of the reducer (this TypeScript one, the stdlib
// Python one in clients/python/vela_reducer.py, and the Rust one in
// crates/vela-protocol/src/reducer.rs) must produce byte-equivalent
// post-replay finding state from the same canonical event log on the
// same genesis findings. If any pair disagrees, one of the three is
// wrong.
//
// Usage:
//   bun  clients/typescript/vela_reducer.ts <fixture-or-dir> [--json]
//   node --experimental-strip-types clients/typescript/vela_reducer.ts <fixture-or-dir>
//   deno run --allow-read clients/typescript/vela_reducer.ts <fixture-or-dir>
//
// Exit codes:
//   0  — every fixture's expected_states matched after TS replay
//   1  — at least one fixture mismatched (cross-implementation drift)
//   2  — fixture directory empty, malformed, or unreadable
//
// This implementation deliberately uses only Node-compatible stdlib
// (fs, path) so a reviewer can read it end to end and reason about
// whether it's doing the same thing the Rust + Python reducers do.
// The matching Rust source is documented inline next to each apply_*
// function; the matching Python source has identical function names.
//
// Fixture schema: vela.science/schema/cross-impl-reducer-fixture/v3
// Generator: crates/vela-protocol/tests/cross_impl_reducer_fixtures.rs

import { readFileSync, statSync, readdirSync } from "node:fs";
import { join, resolve, basename } from "node:path";
import { argv, exit, stdout, stderr } from "node:process";

// ── Shared types ───────────────────────────────────────────────────

type Json = string | number | boolean | null | Json[] | { [k: string]: Json };
type Finding = { [k: string]: Json } & { id?: string };
type Artifact = { [k: string]: Json } & { id?: string };
type Event = {
  id?: string;
  kind?: string;
  payload?: { [k: string]: Json };
  target?: { id?: string; type?: string };
  actor?: { id?: string };
  timestamp?: string;
  reason?: string;
  [k: string]: Json | undefined;
};

// Full reducer state. The TS reducer used to track findings only; it
// now includes current non-finding collections so `tier.set` and
// `artifact.*` events participate in the cross-impl byte-equivalence
// promise.
interface ReducerState {
  findings: Finding[];
  artifacts: Artifact[];
}

// ── Per-kind reducer rules ─────────────────────────────────────────
//
// Each function mirrors a `fn apply_finding_*` in the Rust source at
// crates/vela-protocol/src/reducer.rs and the Python reducer at
// clients/python/vela_reducer.py. The mutation rules are kept in
// sync by the cross-impl fixture test:
//   crates/vela-protocol/tests/cross_impl_reducer_fixtures.rs

// ReviewState → contested mapping. Mirrors `ReviewState::implies_contested`
// in bundle.rs:1278-1288.
const _CONTESTED_REVIEW_STATES = new Set([
  "contested",
  "needs_revision",
  "rejected",
]);

function _findFinding(state: Finding[], findingId: string): Finding | undefined {
  return state.find((f) => f.id === findingId);
}

function _ensureFlags(f: Finding): { [k: string]: Json } {
  if (!f.flags || typeof f.flags !== "object" || Array.isArray(f.flags)) {
    f.flags = {};
  }
  return f.flags as { [k: string]: Json };
}

function _ensureAnnotations(f: Finding): Json[] {
  if (!Array.isArray(f.annotations)) f.annotations = [];
  return f.annotations as Json[];
}

function _ensureConfidence(f: Finding): { [k: string]: Json } {
  if (
    !f.confidence ||
    typeof f.confidence !== "object" ||
    Array.isArray(f.confidence)
  ) {
    f.confidence = {};
  }
  return f.confidence as { [k: string]: Json };
}

function _deepClone<T>(x: T): T {
  return JSON.parse(JSON.stringify(x));
}

// Key-order-independent JSON for cross-impl comparison. The Python and
// Rust effect rows can serialize keys in any order; what matters is
// the value at each key. Sort keys at every level before stringifying.
function canonicalJson(x: unknown): string {
  function sort(v: unknown): unknown {
    if (Array.isArray(v)) return v.map(sort);
    if (v && typeof v === "object") {
      const obj = v as { [k: string]: unknown };
      const out: { [k: string]: unknown } = {};
      for (const k of Object.keys(obj).sort()) out[k] = sort(obj[k]);
      return out;
    }
    return v;
  }
  return JSON.stringify(sort(x));
}

// Mirror of reducer.rs::apply_finding_asserted.
// For v0.3+ frontiers a genesis event may carry the finding inline at
// payload.finding; for legacy frontiers the finding is already in
// state from genesis and this is a no-op.
function applyFindingAsserted(state: Finding[], event: Event): void {
  const payload = event.payload ?? {};
  const finding = payload.finding as Finding | undefined;
  if (!finding) return;
  if (state.some((f) => f.id === finding.id)) return;
  state.push(_deepClone(finding));
}

// Mirror of reducer.rs::apply_finding_reviewed.
// Sets flags.review_state from the snake_case status; sets
// flags.contested per ReviewState::implies_contested.
// Accepts both 'accepted' and 'approved' (Rust accepts both).
function applyFindingReviewed(state: Finding[], event: Event): void {
  const payload = event.payload ?? {};
  const status = payload.status;
  if (typeof status !== "string") {
    throw new Error("finding.reviewed missing payload.status");
  }
  const findingId = event.target?.id ?? "";
  const f = _findFinding(state, findingId);
  if (!f) {
    throw new Error(`finding.reviewed targets unknown finding ${findingId}`);
  }
  const flags = _ensureFlags(f);
  if (status === "accepted" || status === "approved") {
    flags.review_state = "accepted";
    flags.contested = false;
  } else if (status === "contested") {
    flags.review_state = "contested";
    flags.contested = true;
  } else if (status === "needs_revision") {
    flags.review_state = "needs_revision";
    flags.contested = true;
  } else if (status === "rejected") {
    flags.review_state = "rejected";
    flags.contested = true;
  } else {
    throw new Error(`unsupported review status ${JSON.stringify(status)}`);
  }
}

// Mirror of reducer.rs::apply_finding_annotation.
// Idempotent on annotation_id. Adds an Annotation with id, text,
// author=event.actor.id, timestamp=event.timestamp.
function applyFindingAnnotation(state: Finding[], event: Event): void {
  const payload = event.payload ?? {};
  const text = payload.text;
  const annotationId = payload.annotation_id;
  if (typeof text !== "string" || typeof annotationId !== "string") {
    throw new Error("annotation event missing text or annotation_id");
  }
  const findingId = event.target?.id ?? "";
  const f = _findFinding(state, findingId);
  if (!f) {
    throw new Error(`annotation event targets unknown finding ${findingId}`);
  }
  const annotations = _ensureAnnotations(f);
  if (
    annotations.some((a) => (a as { [k: string]: Json }).id === annotationId)
  ) {
    return;
  }
  annotations.push({
    id: annotationId,
    text,
    author: event.actor?.id ?? "",
    timestamp: event.timestamp ?? "",
    provenance: payload.provenance ?? null,
  });
}

// Mirror of reducer.rs::apply_finding_confidence_revised.
// Sets confidence.score, basis, method=expert_judgment.
function applyFindingConfidenceRevised(state: Finding[], event: Event): void {
  const payload = event.payload ?? {};
  const newScore = payload.new_score;
  const previous = (payload.previous_score as number | undefined) ?? 0.0;
  if (typeof newScore !== "number") {
    throw new Error("finding.confidence_revised missing payload.new_score");
  }
  const findingId = event.target?.id ?? "";
  const f = _findFinding(state, findingId);
  if (!f) {
    throw new Error(
      `confidence_revised targets unknown finding ${findingId}`,
    );
  }
  const conf = _ensureConfidence(f);
  conf.score = newScore;
  conf.basis =
    `expert revision from ${previous.toFixed(3)} to ${newScore.toFixed(3)}: ` +
    `${event.reason ?? ""}`;
  conf.method = "expert_judgment";
}

// Mirror of reducer.rs::apply_finding_rejected. Sets contested=true.
function applyFindingRejected(state: Finding[], event: Event): void {
  const findingId = event.target?.id ?? "";
  const f = _findFinding(state, findingId);
  if (!f) {
    throw new Error(`finding.rejected targets unknown finding ${findingId}`);
  }
  _ensureFlags(f).contested = true;
}

// Mirror of reducer.rs::apply_finding_retracted. Sets retracted=true.
function applyFindingRetracted(state: Finding[], event: Event): void {
  const findingId = event.target?.id ?? "";
  const f = _findFinding(state, findingId);
  if (!f) {
    throw new Error(`finding.retracted targets unknown finding ${findingId}`);
  }
  _ensureFlags(f).retracted = true;
}

// Mirror of reducer.rs::apply_finding_dependency_invalidated.
// Sets contested=true and appends a deterministic annotation whose
// id encodes the upstream cascade event and the depth.
//
// Rust shape:
//   annotation_id = format!("ann_dep_{}_{}", &event.id[4..], depth);
// The "vev_" prefix on event.id is stripped by [4..] — TS does
// the same with .slice(4).
function applyFindingDependencyInvalidated(
  state: Finding[],
  event: Event,
): void {
  const payload = event.payload ?? {};
  const upstream = (payload.upstream_finding_id as string | undefined) ?? "?";
  const depth = (payload.depth as number | undefined) ?? 1;
  const findingId = event.target?.id ?? "";
  const f = _findFinding(state, findingId);
  if (!f) {
    throw new Error(
      `finding.dependency_invalidated targets unknown finding ${findingId}`,
    );
  }
  _ensureFlags(f).contested = true;
  const eventId = event.id ?? "";
  const eventTail = eventId.startsWith("vev_") ? eventId.slice(4) : eventId;
  const annotationId = `ann_dep_${eventTail}_${depth}`;
  const annotations = _ensureAnnotations(f);
  if (
    annotations.some((a) => (a as { [k: string]: Json }).id === annotationId)
  ) {
    return;
  }
  annotations.push({
    id: annotationId,
    text: `Upstream ${upstream} retracted (cascade depth ${depth}).`,
    author: event.actor?.id ?? "",
    timestamp: event.timestamp ?? "",
    provenance: null,
  });
}

// v0.49+v0.50+v0.51 mirror functions: each mutates the appropriate
// sub-collection in ReducerState. Idempotent on duplicate ids.

function applyArtifactAsserted(state: Artifact[], event: Event): void {
  const payload = event.payload ?? {};
  const artifact = payload.artifact as Artifact | undefined;
  if (!artifact) return;
  if (state.some((a) => a.id === artifact.id)) return;
  state.push(_deepClone(artifact));
}

function applyArtifactReviewed(state: Artifact[], event: Event): void {
  const payload = event.payload ?? {};
  const status = payload.status;
  if (typeof status !== "string") {
    throw new Error("artifact.reviewed missing payload.status");
  }
  const id = event.target?.id ?? "";
  const artifact = state.find((a) => a.id === id);
  if (!artifact) {
    throw new Error(`artifact.reviewed targets unknown id ${id}`);
  }
  if (status === "accepted" || status === "approved") {
    artifact.review_state = "accepted";
  } else if (
    status === "contested" ||
    status === "needs_revision" ||
    status === "rejected"
  ) {
    artifact.review_state = status;
  } else {
    throw new Error(`unsupported review status ${JSON.stringify(status)}`);
  }
}

function applyArtifactRetracted(state: Artifact[], event: Event): void {
  const id = event.target?.id ?? "";
  const artifact = state.find((a) => a.id === id);
  if (!artifact) {
    throw new Error(`artifact.retracted targets unknown id ${id}`);
  }
  artifact.retracted = true;
}

function applyFindingSpanRepaired(findings: Finding[], event: Event): void {
  if (event.target?.type !== "finding") {
    throw new Error("finding.span_repaired target.type must be 'finding'");
  }
  const findingId = event.target?.id ?? "";
  if (!findingId) throw new Error("finding.span_repaired missing target.id");
  const payload = event.payload ?? {};
  const section = payload.section;
  const text = payload.text;
  if (typeof section !== "string" || section.length === 0) {
    throw new Error("finding.span_repaired missing payload.section");
  }
  if (typeof text !== "string" || text.length === 0) {
    throw new Error("finding.span_repaired missing payload.text");
  }
  const finding = findings.find((f) => f.id === findingId);
  if (!finding) {
    throw new Error(`finding.span_repaired targets unknown finding ${findingId}`);
  }
  const evidence = (finding.evidence ?? {}) as { [k: string]: Json };
  finding.evidence = evidence;
  const spans = Array.isArray(evidence.evidence_spans)
    ? (evidence.evidence_spans as Json[])
    : [];
  evidence.evidence_spans = spans;
  const alreadyPresent = spans.some((span) => {
    if (!span || typeof span !== "object" || Array.isArray(span)) return false;
    return span.section === section && span.text === text;
  });
  if (!alreadyPresent) spans.push({ section, text });
}

function applyFindingEntityResolved(findings: Finding[], event: Event): void {
  if (event.target?.type !== "finding") {
    throw new Error("finding.entity_resolved target.type must be 'finding'");
  }
  const findingId = event.target?.id ?? "";
  const payload = event.payload ?? {};
  const entityName = payload.entity_name;
  const source = payload.source;
  const idValue = payload.id;
  const confidence = payload.confidence;
  if (
    !findingId ||
    typeof entityName !== "string" ||
    entityName.length === 0 ||
    typeof source !== "string" ||
    source.length === 0 ||
    typeof idValue !== "string" ||
    idValue.length === 0
  ) {
    throw new Error("finding.entity_resolved missing required string fields");
  }
  if (typeof confidence !== "number") {
    throw new Error("finding.entity_resolved missing payload.confidence");
  }
  const finding = findings.find((f) => f.id === findingId);
  if (!finding) {
    throw new Error(`finding.entity_resolved targets unknown finding ${findingId}`);
  }
  const assertion = (finding.assertion ?? {}) as { [k: string]: Json };
  const entities = assertion.entities as Json[] | undefined;
  if (!Array.isArray(entities)) {
    throw new Error(`finding.entity_resolved entity ${entityName} not in finding ${findingId}`);
  }
  const entity = entities.find((e) => {
    if (!e || typeof e !== "object" || Array.isArray(e)) return false;
    return e.name === entityName;
  }) as { [k: string]: Json } | undefined;
  if (!entity) {
    throw new Error(`finding.entity_resolved entity ${entityName} not in finding ${findingId}`);
  }
  const canonical: { [k: string]: Json } = {
    source,
    id: idValue,
    confidence,
  };
  if (
    typeof payload.matched_name === "string" &&
    payload.matched_name.length > 0
  ) {
    canonical.matched_name = payload.matched_name;
  }
  entity.canonical_id = canonical;
  entity.resolution_method =
    typeof payload.resolution_method === "string"
      ? payload.resolution_method
      : "manual";
  entity.resolution_provenance =
    typeof payload.resolution_provenance === "string"
      ? payload.resolution_provenance
      : "delegated_human_curation";
  entity.resolution_confidence = confidence;
  entity.needs_review = false;
}

// v0.51: tier.set mutates access_tier on the matched object. The
// payload carries object_type so the dispatcher knows which
// collection to mutate; we re-check inside this function for
// independent verification.
function applyTierSet(state: ReducerState, event: Event): void {
  const payload = event.payload ?? {};
  const objType = payload.object_type;
  const objId = payload.object_id;
  const newTier = payload.new_tier;
  if (
    typeof objType !== "string" ||
    typeof objId !== "string" ||
    typeof newTier !== "string"
  ) {
    throw new Error(
      "tier.set requires payload.{object_type, object_id, new_tier}",
    );
  }
  if (!["public", "restricted", "classified"].includes(newTier)) {
    throw new Error(`tier.set invalid new_tier ${JSON.stringify(newTier)}`);
  }
  let collection: { id?: string; access_tier?: Json }[];
  if (objType === "finding") collection = state.findings;
  else if (objType === "artifact") collection = state.artifacts;
  else throw new Error(`tier.set unsupported object_type ${objType}`);
  const obj = collection.find((o) => o.id === objId);
  if (!obj) {
    throw new Error(`tier.set targets unknown ${objType} ${objId}`);
  }
  obj.access_tier = newTier;
}

function applyEvent(state: ReducerState, event: Event): void {
  const kind = event.kind ?? "";
  if (kind === "frontier.created") return; // structural anchor
  else if (kind === "finding.asserted")
    applyFindingAsserted(state.findings, event);
  else if (kind === "finding.reviewed")
    applyFindingReviewed(state.findings, event);
  else if (kind === "finding.noted" || kind === "finding.caveated")
    applyFindingAnnotation(state.findings, event);
  else if (kind === "finding.confidence_revised")
    applyFindingConfidenceRevised(state.findings, event);
  else if (kind === "finding.rejected")
    applyFindingRejected(state.findings, event);
  else if (kind === "finding.retracted")
    applyFindingRetracted(state.findings, event);
  else if (kind === "finding.dependency_invalidated")
    applyFindingDependencyInvalidated(state.findings, event);
  else if (kind === "artifact.asserted")
    applyArtifactAsserted(state.artifacts, event);
  else if (kind === "artifact.reviewed")
    applyArtifactReviewed(state.artifacts, event);
  else if (kind === "artifact.retracted")
    applyArtifactRetracted(state.artifacts, event);
  else if (kind === "tier.set") applyTierSet(state, event);
  else if (kind === "finding.span_repaired")
    applyFindingSpanRepaired(state.findings, event);
  else if (kind === "finding.entity_resolved")
    applyFindingEntityResolved(state.findings, event);
  // v0.82: cross-impl reducer parity for newer protocol kinds. The
  // following events do not touch any field the TS effect-digest
  // captures (id, retracted, contested, review_state,
  // confidence_score, annotation_ids, access_tier on findings; the
  // analogous projections on artifacts). The Rust reducer is canonical
  // and recomputes derived structures from the event log directly
  // (attestations, finding.entities). Treating them as no-ops here
  // keeps the third-implementation reducer-effects digest
  // byte-identical with Rust + Python.
  else if (kind === "attestation.recorded") return; // audit-only
  else if (kind === "finding.entity_added") return; // entity list outside digest
  // Side-table / federation arms. Each mutates a collection the Rust +
  // Python reducers keep outside the digested collections
  // (released_diff_packs, verdict_conflicts, contradictions,
  // evidence_atoms, and the frontier-observation log). The cross-impl
  // effect-digest covers findings / artifacts only, so these are
  // no-ops here. Mirrors reducer.rs::apply_diff_pack_released /
  // apply_diff_pack_reviewed / apply_verdict_conflict_resolved /
  // apply_contradiction_resolved and the v0.39+ federation no-ops.
  else if (kind === "diff_pack.released") return;
  else if (kind === "diff_pack.reviewed") return;
  else if (kind === "verdict_conflict.resolved") return;
  else if (kind === "contradiction.resolved") return;
  else if (kind === "evidence_atom.locator_repaired") return;
  else if (kind === "frontier.synced_with_peer") return;
  else if (kind === "frontier.conflict_detected") return;
  else if (kind === "frontier.conflict_resolved") return;
  // verifier attachment bound to a finding: mutates the Project-level
  // verifier_attachments sidecar; no-op on the findings digest. Rust mirror
  // is reducer.rs::apply_verifier_attachment_added.
  else if (kind === "verifier_attachment.added") return;
  // Supersession: flip flags.superseded on the OLD (target) finding.
  // The replacement's body enters via loader genesis seeding, never the
  // reducer (thin payload). Rust mirror: reducer.rs::apply_finding_superseded.
  else if (kind === "finding.superseded") {
    applyFindingSuperseded(state.findings, event);
  }
  // Statement-faithfulness attestation: side-table upsert in Rust; no-op
  // on the findings digest here. Rust mirror: apply_statement_attested.
  else if (kind === "statement.attested") return;
  // Obligation lease + priority registration: side-table upserts in Rust;
  // no-ops on the findings digest here.
  else if (kind === "attempt.claimed" || kind === "statement.registered")
    return;
  // Causal re-grading from payload.after ({claim, grade}). Rust mirror:
  // reducer.rs::apply_assertion_reinterpreted_causal.
  else if (kind === "assertion.reinterpreted_causal") {
    applyAssertionReinterpretedCausal(state.findings, event);
  }
  // Audit-only / writerless kinds: validated at emit, no projected
  // state on replay (explicit no-op arms in the Rust reducer).
  else if (
    kind === "frontier.observation_reviewed" ||
    kind === "correction_return.review" ||
    kind === "research_trace.review" ||
    kind === "key.revoke"
  )
    return;
  else
    throw new Error(`reducer: unsupported event kind ${JSON.stringify(kind)}`);
}

// ── Reducer-effects digest ─────────────────────────────────────────
//
// Mirror of `finding_state` in
// crates/vela-protocol/tests/cross_impl_reducer_fixtures.rs.
// Captures only the fields the reducer mutates so cross-impl agreement
// is testable without serializing the full Project struct.

interface FindingEffectRow {
  id: string;
  retracted: boolean;
  contested: boolean;
  review_state: string;
  confidence_score: string;
  annotation_ids: string[];
  access_tier: string;
}

interface ArtifactEffectRow {
  id: string;
  kind: string;
  retracted: boolean;
  review_state: string;
  access_tier: string;
}

function findingEffects(findings: Finding[]): FindingEffectRow[] {
  const sorted = [...findings].sort((a, b) =>
    (a.id ?? "").localeCompare(b.id ?? ""),
  );
  return sorted.map((f) => {
    const flags = (f.flags ?? {}) as { [k: string]: Json };
    const reviewState = (flags.review_state as string | undefined) ?? "none";
    const confidence = (f.confidence ?? {}) as { [k: string]: Json };
    const annotations = (f.annotations ?? []) as { id?: string }[];
    const annotationIds = annotations
      .map((a) => a.id ?? "")
      .sort((x, y) => x.localeCompare(y));
    const score = Number(confidence.score ?? 0.0);
    const accessTier = (f.access_tier as string | undefined) ?? "public";
    return {
      id: f.id ?? "",
      retracted: Boolean(flags.retracted ?? false),
      contested: Boolean(flags.contested ?? false),
      review_state: reviewState,
      confidence_score: score.toFixed(6),
      annotation_ids: annotationIds,
      access_tier: accessTier,
    };
  });
}

function artifactEffects(artifacts: Artifact[]): ArtifactEffectRow[] {
  const sorted = [...artifacts].sort((a, b) =>
    (a.id ?? "").localeCompare(b.id ?? ""),
  );
  return sorted.map((a) => ({
    id: a.id ?? "",
    kind: (a.kind as string | undefined) ?? "",
    retracted: Boolean(a.retracted ?? false),
    review_state: (a.review_state as string | undefined) ?? "none",
    access_tier: (a.access_tier as string | undefined) ?? "public",
  }));
}

// ── Fixture verification ───────────────────────────────────────────

interface FixtureResult {
  path: string;
  frontierIdx: number;
  findings: number;
  artifacts: number;
  events: number;
  cascadeDepth: number;
  matched: number;
  diffs: {
    collection: string;
    id: string;
    issue: string;
    expected?: unknown;
    actual?: unknown;
  }[];
  ok: boolean;
  error: string | null;
}

// v0.106.5+: extended verifier reads fixture_version "4" with all current
// expected collections. Falls back to v1/v2 for backward-compat.
function verifyFixture(path: string): FixtureResult {
  const result: FixtureResult = {
    path,
    frontierIdx: -1,
    findings: 0,
    artifacts: 0,
    events: 0,
    cascadeDepth: 0,
    matched: 0,
    diffs: [],
    ok: false,
    error: null,
  };
  let fx: { [k: string]: Json };
  try {
    fx = JSON.parse(readFileSync(path, "utf8"));
  } catch (e) {
    result.error = `unreadable fixture: ${(e as Error).message}`;
    return result;
  }
  const fxVersion = String(fx.fixture_version ?? "");
  if (
    fxVersion !== "5" &&
    fxVersion !== "4" &&
    fxVersion !== "3" &&
    fxVersion !== "2" &&
    fxVersion !== "1"
  ) {
    result.error = `unsupported fixture_version ${JSON.stringify(fx.fixture_version)}; expected '1', '2', '3', '4', or '5'`;
    return result;
  }
  result.frontierIdx = Number(fx.frontier_idx ?? -1);
  const stats = (fx.stats ?? {}) as { [k: string]: Json };
  result.findings = Number(stats.findings ?? 0);
  result.artifacts = Number(stats.artifacts ?? 0);
  result.events = Number(stats.events ?? 0);
  result.cascadeDepth = Number(stats.cascade_depth ?? 0);

  const state: ReducerState = {
    findings: _deepClone((fx.genesis_findings as Finding[]) ?? []),
    artifacts: [],
  };
  const eventLog = (fx.event_log as Event[]) ?? [];
  const expectedFindings = (fx.expected_states as FindingEffectRow[]) ?? [];
  const expectedArtifacts =
    (fx.expected_artifacts as ArtifactEffectRow[]) ?? [];

  for (const event of eventLog) {
    try {
      applyEvent(state, event);
    } catch (e) {
      result.error =
        `reducer error on event ${event.id ?? "?"} (${event.kind ?? "?"}): ` +
        (e as Error).message;
      return result;
    }
  }

  // For v1 fixtures, the access_tier field will be missing from
  // expected_states; strip it from actual rows so the comparison
  // doesn't false-fail. v2 fixtures include it.
  const stripV1 = fxVersion === "1";

  const actualF = findingEffects(state.findings).map((r) =>
    stripV1
      ? ({
          id: r.id,
          retracted: r.retracted,
          contested: r.contested,
          review_state: r.review_state,
          confidence_score: r.confidence_score,
          annotation_ids: r.annotation_ids,
        } as unknown as FindingEffectRow)
      : r,
  );
  const actualA = artifactEffects(state.artifacts);

  diffCollection("findings", actualF, expectedFindings, result);
  if (fxVersion === "3" || fxVersion === "4" || fxVersion === "5") {
    diffCollection("artifacts", actualA, expectedArtifacts, result);
  }

  let totalExpected = expectedFindings.length;
  if (fxVersion === "3" || fxVersion === "4" || fxVersion === "5")
    totalExpected += expectedArtifacts.length;
  result.ok = result.diffs.length === 0 && result.matched === totalExpected;
  return result;
}

function diffCollection(
  name: string,
  actual: { id: string }[],
  expected: { id: string }[],
  result: FixtureResult,
): void {
  const actualById = new Map(actual.map((r) => [r.id, r]));
  const expectedById = new Map(expected.map((r) => [r.id, r]));
  const allIds = [
    ...new Set([...actualById.keys(), ...expectedById.keys()]),
  ].sort();
  for (const id of allIds) {
    const a = actualById.get(id);
    const e = expectedById.get(id);
    if (!a) {
      result.diffs.push({
        collection: name,
        id,
        issue: "missing in ts output",
        expected: e,
      });
    } else if (!e) {
      result.diffs.push({
        collection: name,
        id,
        issue: "extra in ts output",
        actual: a,
      });
    } else if (canonicalJson(a) !== canonicalJson(e)) {
      result.diffs.push({
        collection: name,
        id,
        issue: "mismatch",
        expected: e,
        actual: a,
      });
    } else {
      result.matched += 1;
    }
  }
}

function renderText(results: FixtureResult[]): string {
  const lines: string[] = [];
  lines.push("vela reducer (typescript · stdlib · third implementation)");
  for (const r of results) {
    const status = r.ok ? "ok" : "FAIL";
    const totalExpected = r.findings + r.artifacts;
    lines.push(
      `  ${status.padEnd(4)} · frontier ${String(r.frontierIdx).padStart(2, "0")} · ` +
        `${r.matched}/${totalExpected} (${r.findings}f/${r.artifacts}a) · ` +
        `${r.events} events · cascade depth ${r.cascadeDepth}`,
    );
    if (r.error) lines.push(`          error: ${r.error}`);
    for (const d of r.diffs.slice(0, 5)) {
      lines.push(
        `          · [${d.collection}] ${d.id}: ${d.issue}`,
      );
      if (d.expected && d.actual) {
        const exp = d.expected as { [k: string]: Json };
        const act = d.actual as { [k: string]: Json };
        const allKeys = [
          ...new Set([...Object.keys(exp), ...Object.keys(act)]),
        ].sort();
        for (const k of allKeys) {
          if (JSON.stringify(exp[k]) !== JSON.stringify(act[k])) {
            lines.push(
              `              ${k}: expected=${JSON.stringify(exp[k])} actual=${JSON.stringify(act[k])}`,
            );
          }
        }
      }
    }
    if (r.diffs.length > 5) {
      lines.push(`          (… ${r.diffs.length - 5} more)`);
    }
  }
  if (results.every((r) => r.ok)) {
    lines.push("");
    lines.push("reducer: ok");
    lines.push(
      "  every event-log replay through the typescript reducer produced",
    );
    lines.push(
      "  the same reducer-effects state the rust and python reducers produced.",
    );
    lines.push(
      "  the per-kind mutation rules are now confirmed across three",
    );
    lines.push("  independent implementations.");
  }
  return lines.join("\n");
}

function collectFixtures(target: string): string[] {
  const abs = resolve(target);
  let stat;
  try {
    stat = statSync(abs);
  } catch {
    return [];
  }
  if (stat.isFile()) return [abs];
  if (stat.isDirectory()) {
    return readdirSync(abs)
      .filter((f) => f.startsWith("cascade-fixture-") && f.endsWith(".json"))
      .sort()
      .map((f) => join(abs, f));
  }
  return [];
}

function main(args: string[]): number {
  let jsonMode = false;
  const positional: string[] = [];
  for (const a of args) {
    if (a === "--json") jsonMode = true;
    else if (a === "-h" || a === "--help") {
      stdout.write(
        "usage: vela_reducer.ts <fixture-or-dir> [--json]\n" +
          "  Verify byte-equivalent reducer state against the rust implementation.\n",
      );
      return 0;
    } else positional.push(a);
  }
  const target = positional[0];
  if (!target) {
    stderr.write("error: missing fixture path\n");
    return 2;
  }

  const fixtures = collectFixtures(target);
  if (fixtures.length === 0) {
    stderr.write(`error: no cascade-fixture-*.json found at ${target}\n`);
    return 2;
  }

  const results = fixtures.map(verifyFixture);

  if (jsonMode) {
    stdout.write(
      JSON.stringify(
        {
          ok: results.every((r) => r.ok),
          fixtures: results.map((r) => ({
            path: basename(r.path),
            frontier_idx: r.frontierIdx,
            ok: r.ok,
            findings: r.findings,
            artifacts: r.artifacts,
            events: r.events,
            cascade_depth: r.cascadeDepth,
            matched: r.matched,
            diffs: r.diffs,
            error: r.error,
          })),
          verifier:
            "vela_reducer.ts · typescript stdlib · third implementation",
        },
        null,
        2,
      ) + "\n",
    );
  } else {
    stdout.write(renderText(results) + "\n");
  }

  return results.every((r) => r.ok) ? 0 : 1;
}

exit(main(argv.slice(2)));

function applyFindingSuperseded(findings: Finding[], event: StateEvent): void {
  const findingId = event.target?.id;
  const f = findings.find((x) => x.id === findingId);
  if (!f) {
    throw new Error(`finding.superseded targets unknown finding ${findingId}`);
  }
  if (!f.flags) f.flags = {} as Finding["flags"];
  (f.flags as { superseded?: boolean }).superseded = true;
}

function applyAssertionReinterpretedCausal(
  findings: Finding[],
  event: StateEvent,
): void {
  const findingId = event.target?.id;
  const payload = (event.payload ?? {}) as {
    after?: { claim?: string; grade?: string | null };
  };
  const claim = payload.after?.claim;
  if (
    claim !== "correlation" &&
    claim !== "mediation" &&
    claim !== "intervention"
  ) {
    throw new Error(`invalid causal claim ${JSON.stringify(claim)}`);
  }
  const grade = payload.after?.grade ?? null;
  if (
    grade !== null &&
    grade !== "rct" &&
    grade !== "quasi_experimental" &&
    grade !== "observational" &&
    grade !== "theoretical"
  ) {
    throw new Error(`invalid causal evidence grade ${JSON.stringify(grade)}`);
  }
  const f = findings.find((x) => x.id === findingId);
  if (!f) {
    throw new Error(
      `assertion.reinterpreted_causal targets unknown finding ${findingId}`,
    );
  }
  const assertion = f.assertion as unknown as {
    causal_claim?: string;
    causal_evidence_grade?: string;
  };
  assertion.causal_claim = claim;
  if (grade !== null) assertion.causal_evidence_grade = grade;
}
