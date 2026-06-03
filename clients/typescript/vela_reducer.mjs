#!/usr/bin/env node
// Vela reducer — third implementation (TypeScript / ES module, no
// dependencies). Companion to the Rust reducer at
// crates/vela-protocol/src/reducer.rs and the Python reducer at
// clients/python/vela_reducer.py.
//
// The doctrine the cascade test header states:
//   "two implementations of the reducer must agree on the mutation
//    rules per kind"
// — we now ship three. The Python one was the first cross-impl
// confirmation; this one is the second, in a different runtime
// (V8 / Node) with a different number-format model. If three
// independent implementations agree byte-for-byte on the post-replay
// finding state for the same fixtures, the per-kind mutation rules
// are unambiguously protocol, not artifact.
//
// Usage:
//   node vela_reducer.mjs path/to/cascade-fixture-00.json
//   node vela_reducer.mjs path/to/fixtures/   # walks all *.json
//   node vela_reducer.mjs --json path/to/fixture.json
//
// Exit codes:
//   0 — every fixture's expected_states matched after JS replay
//   1 — at least one fixture mismatched (cross-impl drift)
//   2 — fixture directory empty, malformed, or unreadable
//
// Stdlib only (Node ≥ 18; uses fs, path, url, process). No npm install,
// no transpile, no bundle. The matching Rust reducer lines are cited
// inline next to each apply_* function.

import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, basename, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// ── Per-kind reducer rules ────────────────────────────────────────────
//
// Each function mirrors `fn apply_finding_*` in
// crates/vela-protocol/src/reducer.rs. Order and shape match the
// Python implementation in clients/python/vela_reducer.py one-to-one
// so a reviewer can diff them.

const CONTESTED_REVIEW_STATES = new Set([
  "contested",
  "needs_revision",
  "rejected",
]);

function findFinding(state, findingId) {
  return state.find((f) => f && f.id === findingId) || null;
}

function ensureFlags(f) {
  if (!f.flags || typeof f.flags !== "object") f.flags = {};
  return f.flags;
}

function ensureAnnotations(f) {
  if (!Array.isArray(f.annotations)) f.annotations = [];
  return f.annotations;
}

function ensureConfidence(f) {
  if (!f.confidence || typeof f.confidence !== "object") f.confidence = {};
  return f.confidence;
}

function applyFindingAsserted(state, event) {
  // reducer.rs::apply_finding_asserted — for v0.3+ frontiers a
  // genesis-shape event may carry the finding inline at
  // payload.finding; legacy frontiers already have the finding from
  // genesis and this is a no-op.
  const finding = (event.payload || {}).finding;
  if (!finding) return;
  if (state.some((f) => f && f.id === finding.id)) return;
  state.push(structuredClone(finding));
}

function applyFindingReviewed(state, event) {
  // reducer.rs::apply_finding_reviewed — sets review_state and
  // contested per ReviewState::implies_contested.
  const status = (event.payload || {}).status;
  if (typeof status !== "string") {
    throw new Error("finding.reviewed missing payload.status");
  }
  const findingId = (event.target || {}).id;
  const f = findFinding(state, findingId);
  if (!f) {
    throw new Error(`finding.reviewed targets unknown finding ${findingId}`);
  }
  const flags = ensureFlags(f);
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

function applyFindingAnnotation(state, event) {
  // reducer.rs::apply_finding_annotation — idempotent on annotation_id.
  const payload = event.payload || {};
  const text = payload.text;
  const annotationId = payload.annotation_id;
  if (typeof text !== "string" || typeof annotationId !== "string") {
    throw new Error("annotation event missing text or annotation_id");
  }
  const findingId = (event.target || {}).id;
  const f = findFinding(state, findingId);
  if (!f) {
    throw new Error(`annotation event targets unknown finding ${findingId}`);
  }
  const annotations = ensureAnnotations(f);
  if (annotations.some((a) => a && a.id === annotationId)) return;
  annotations.push({
    id: annotationId,
    text,
    author: (event.actor || {}).id || "",
    timestamp: event.timestamp || "",
    provenance: payload.provenance ?? null,
  });
}

function applyFindingConfidenceRevised(state, event) {
  // reducer.rs::apply_finding_confidence_revised — sets score, basis,
  // method=expert_judgment.
  const payload = event.payload || {};
  const newScore = payload.new_score;
  const previous = typeof payload.previous_score === "number" ? payload.previous_score : 0.0;
  if (typeof newScore !== "number") {
    throw new Error("finding.confidence_revised missing payload.new_score");
  }
  const findingId = (event.target || {}).id;
  const f = findFinding(state, findingId);
  if (!f) {
    throw new Error(`confidence_revised targets unknown finding ${findingId}`);
  }
  const conf = ensureConfidence(f);
  conf.score = newScore;
  conf.basis = `expert revision from ${previous.toFixed(3)} to ${newScore.toFixed(3)}: ${event.reason || ""}`;
  conf.method = "expert_judgment";
}

function applyFindingRejected(state, event) {
  // reducer.rs::apply_finding_rejected — sets contested = true.
  const findingId = (event.target || {}).id;
  const f = findFinding(state, findingId);
  if (!f) {
    throw new Error(`finding.rejected targets unknown finding ${findingId}`);
  }
  ensureFlags(f).contested = true;
}

function applyFindingRetracted(state, event) {
  // reducer.rs::apply_finding_retracted — sets retracted = true.
  const findingId = (event.target || {}).id;
  const f = findFinding(state, findingId);
  if (!f) {
    throw new Error(`finding.retracted targets unknown finding ${findingId}`);
  }
  ensureFlags(f).retracted = true;
}

function applyFindingDependencyInvalidated(state, event) {
  // reducer.rs::apply_finding_dependency_invalidated — sets contested
  // and appends a deterministic annotation:
  //   annotation_id = format!("ann_dep_{}_{}", &event.id[4..], depth);
  // The Python and JS implementations both strip the "vev_" prefix
  // (4 chars) the same way to keep the annotation_id byte-equal.
  const payload = event.payload || {};
  const upstream = payload.upstream_finding_id || "?";
  const depth = typeof payload.depth === "number" ? payload.depth : 1;
  const findingId = (event.target || {}).id;
  const f = findFinding(state, findingId);
  if (!f) {
    throw new Error(`dependency_invalidated targets unknown finding ${findingId}`);
  }
  ensureFlags(f).contested = true;
  const eventId = event.id || "";
  const eventTail = eventId.startsWith("vev_") ? eventId.slice(4) : eventId;
  const annotationId = `ann_dep_${eventTail}_${depth}`;
  const annotations = ensureAnnotations(f);
  if (annotations.some((a) => a && a.id === annotationId)) return;
  annotations.push({
    id: annotationId,
    text: `Upstream ${upstream} retracted (cascade depth ${depth}).`,
    author: (event.actor || {}).id || "",
    timestamp: event.timestamp || "",
    provenance: null,
  });
}

function applyEvent(state, event) {
  switch (event.kind) {
    case "frontier.created":
      return; // structural anchor, no mutation
    case "finding.asserted":
      return applyFindingAsserted(state, event);
    case "finding.reviewed":
      return applyFindingReviewed(state, event);
    case "finding.noted":
    case "finding.caveated":
      return applyFindingAnnotation(state, event);
    case "finding.confidence_revised":
      return applyFindingConfidenceRevised(state, event);
    case "finding.rejected":
      return applyFindingRejected(state, event);
    case "finding.retracted":
      return applyFindingRetracted(state, event);
    case "finding.dependency_invalidated":
      return applyFindingDependencyInvalidated(state, event);
    default:
      throw new Error(`reducer: unsupported event kind ${JSON.stringify(event.kind)}`);
  }
}

// ── Reducer-effects digest ────────────────────────────────────────────
//
// Mirror of `finding_state` in
// crates/vela-protocol/tests/cross_impl_reducer_fixtures.rs and of
// `reducer_effects` in clients/python/vela_reducer.py. The score is
// formatted to 6 decimals so float64 noise doesn't cross the
// implementation boundary (Rust uses {:.6}, Python uses :.6f, JS uses
// .toFixed(6) — all three produce the same string for the same f64).

function reducerEffects(state) {
  const sorted = [...state].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  return sorted.map((f) => {
    const flags = f.flags || {};
    const review_state = flags.review_state || "none";
    const confidence = f.confidence || {};
    const annotations = Array.isArray(f.annotations) ? f.annotations : [];
    const annotation_ids = annotations
      .map((a) => (a && a.id) || "")
      .sort();
    const score = Number(confidence.score ?? 0);
    return {
      id: f.id || "",
      retracted: Boolean(flags.retracted),
      contested: Boolean(flags.contested),
      review_state,
      confidence_score: score.toFixed(6),
      annotation_ids,
    };
  });
}

// ── Fixture verification ──────────────────────────────────────────────

function deepEqual(a, b) {
  if (a === b) return true;
  if (typeof a !== typeof b) return false;
  if (Array.isArray(a)) {
    if (!Array.isArray(b) || a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) if (!deepEqual(a[i], b[i])) return false;
    return true;
  }
  if (a && typeof a === "object") {
    if (!b || typeof b !== "object") return false;
    const ak = Object.keys(a).sort();
    const bk = Object.keys(b).sort();
    if (ak.length !== bk.length) return false;
    for (let i = 0; i < ak.length; i++) {
      if (ak[i] !== bk[i]) return false;
      if (!deepEqual(a[ak[i]], b[bk[i]])) return false;
    }
    return true;
  }
  return false;
}

function verifyFixture(path) {
  const result = {
    path,
    frontier_idx: -1,
    findings: 0,
    events: 0,
    cascade_depth: 0,
    matched: 0,
    diffs: [],
    ok: false,
    error: null,
  };
  let fx;
  try {
    fx = JSON.parse(readFileSync(path, "utf8"));
  } catch (e) {
    result.error = `unreadable fixture: ${e && e.message}`;
    return result;
  }
  if (fx.fixture_version !== "1") {
    result.error = `unsupported fixture_version ${JSON.stringify(fx.fixture_version)}`;
    return result;
  }
  result.frontier_idx = fx.frontier_idx ?? -1;
  result.findings = (fx.stats && fx.stats.findings) || 0;
  result.events = (fx.stats && fx.stats.events) || 0;
  result.cascade_depth = (fx.stats && fx.stats.cascade_depth) || 0;

  const state = structuredClone(fx.genesis_findings || []);
  const log = fx.event_log || [];
  const expected = fx.expected_states || [];

  for (const event of log) {
    try {
      applyEvent(state, event);
    } catch (e) {
      result.error = `reducer error on event ${event.id || "?"} (${event.kind || "?"}): ${e && e.message}`;
      return result;
    }
  }

  const actual = reducerEffects(state);
  const actualById = new Map(actual.map((f) => [f.id, f]));
  const expectedById = new Map(expected.map((f) => [f.id, f]));
  const allIds = [...new Set([...actualById.keys(), ...expectedById.keys()])].sort();
  for (const fid of allIds) {
    const a = actualById.get(fid);
    const e = expectedById.get(fid);
    if (!a) {
      result.diffs.push({ id: fid, issue: "missing in js output", expected: e });
    } else if (!e) {
      result.diffs.push({ id: fid, issue: "extra in js output", actual: a });
    } else if (!deepEqual(a, e)) {
      result.diffs.push({ id: fid, issue: "mismatch", expected: e, actual: a });
    } else {
      result.matched++;
    }
  }
  result.ok = result.diffs.length === 0 && result.matched === expected.length;
  return result;
}

function renderText(results) {
  const lines = [];
  lines.push("vela reducer (typescript / node · third implementation)");
  for (const r of results) {
    const status = r.ok ? "ok" : "FAIL";
    lines.push(
      `  ${status.padEnd(4)} · frontier ${String(r.frontier_idx).padStart(2, "0")} · ` +
        `${r.matched}/${r.findings} findings · ${r.events} events · cascade depth ${r.cascade_depth}`
    );
    if (r.error) lines.push(`          error: ${r.error}`);
    for (const d of r.diffs.slice(0, 5)) {
      lines.push(`          · ${d.id || "?"}: ${d.issue}`);
      if (d.expected && d.actual) {
        const keys = [...new Set([...Object.keys(d.expected), ...Object.keys(d.actual)])].sort();
        for (const k of keys) {
          if (JSON.stringify(d.expected[k]) !== JSON.stringify(d.actual[k])) {
            lines.push(
              `              ${k}: expected=${JSON.stringify(d.expected[k])} actual=${JSON.stringify(d.actual[k])}`
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
    lines.push("  every event-log replay through the typescript reducer produced");
    lines.push("  the same per-finding state the rust and python reducers produced.");
    lines.push("  the per-kind mutation rules now have three independent");
    lines.push("  implementations that agree byte-for-byte.");
  }
  return lines.join("\n");
}

function collectFixtures(target) {
  const st = statSync(target);
  if (st.isFile()) return [target];
  if (st.isDirectory()) {
    return readdirSync(target)
      .filter((n) => /^cascade-fixture-.*\.json$/.test(n))
      .sort()
      .map((n) => join(target, n));
  }
  return [];
}

function main(argv) {
  let asJson = false;
  const positional = [];
  for (const a of argv) {
    if (a === "--json") asJson = true;
    else positional.push(a);
  }
  if (positional.length !== 1) {
    process.stderr.write("usage: vela_reducer.mjs [--json] <fixture-or-dir>\n");
    return 2;
  }
  const target = resolve(positional[0]);
  let fixtures;
  try {
    fixtures = collectFixtures(target);
  } catch (e) {
    process.stderr.write(`error: ${e && e.message}\n`);
    return 2;
  }
  if (!fixtures.length) {
    process.stderr.write(`error: no cascade-fixture-*.json found at ${target}\n`);
    return 2;
  }
  const results = fixtures.map(verifyFixture);
  if (asJson) {
    process.stdout.write(
      JSON.stringify(
        {
          ok: results.every((r) => r.ok),
          fixtures: results,
          verifier: "vela_reducer.mjs · node esm · third implementation",
        },
        null,
        2
      ) + "\n"
    );
  } else {
    process.stdout.write(renderText(results) + "\n");
  }
  return results.every((r) => r.ok) ? 0 : 1;
}

const __filename = fileURLToPath(import.meta.url);
if (process.argv[1] && resolve(process.argv[1]) === resolve(__filename)) {
  process.exit(main(process.argv.slice(2)));
}
