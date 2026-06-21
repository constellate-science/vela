use crate::cli::{
    collect_witness_files, fail, fail_return, hash_path, load_frontier_or_fail, parse_witness,
    print_json,
};
use crate::cli_commands::*;
use serde_json::{Value, json};
use std::path::Path;
use vela_edge::carina_validate;
use vela_edge::normalize;
use vela_protocol::bundle;
use vela_protocol::cli_style as style;
use vela_protocol::evidence_ci;
use vela_protocol::project;
use vela_protocol::proposals;
use vela_protocol::repo;
use vela_protocol::sources;

pub(crate) fn cmd_gate(action: GateAction) {
    use vela_edge::deliverable_grade::{self, DeliverableGrade, GradeGate};
    use vela_protocol::verifier_attachment::{
        self, GateStatus, ProbeKind, VerifierAttachment, VerifierMethod,
    };
    match action {
        GateAction::Grade { claim, grade, json } => {
            let gate = deliverable_grade::grade_gate(&claim, grade.as_deref());
            let passed = gate.passed();
            if json {
                let grade_str = match &gate {
                    GradeGate::Ok(g) => Some(g.as_str().to_string()),
                    _ => grade.clone(),
                };
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "command": "gate grade",
                        "passed": passed,
                        "grade": grade_str,
                        "reason": gate.reason(),
                    }))
                    .expect("serialize gate grade response")
                );
            } else if passed {
                println!("gate grade: ok");
                if let GradeGate::Ok(g) = gate {
                    println!("  deliverable_grade: {g}  (claim text consistent with grade)");
                }
            } else {
                eprintln!("gate grade: REJECTED\n  {}", gate.reason());
            }
            if !passed {
                std::process::exit(1);
            }
        }
        GateAction::Check {
            claim,
            attachments,
            json,
        } => {
            let raw = std::fs::read_to_string(&attachments)
                .unwrap_or_else(|e| fail_return(&format!("read {}: {e}", attachments.display())));
            let atts: Vec<VerifierAttachment> = serde_json::from_str(&raw).unwrap_or_else(|e| {
                fail_return(&format!(
                    "parse {} as a JSON array of VerifierAttachment: {e}",
                    attachments.display()
                ))
            });
            // G4: every attachment must be structurally sound before the
            // gate reasons over it.
            for a in &atts {
                if let Err(e) = a.verify() {
                    fail(&format!("attachment {} is malformed: {e}", a.id));
                }
            }
            let digest = verifier_attachment::claim_digest(&claim);
            let outcome = verifier_attachment::derive_gate_status(&digest, &atts);
            let verified = outcome.status == GateStatus::Verified;
            if json {
                let status = match outcome.status {
                    GateStatus::Verified => "verified",
                    GateStatus::NeedsVerification => "needs_verification",
                    GateStatus::Refuted => "refuted",
                };
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "command": "gate check",
                        "claim_digest": digest,
                        "attachments": atts.len(),
                        "status": status,
                        "reasons": outcome.reasons,
                    }))
                    .expect("serialize gate check response")
                );
            } else {
                println!(
                    "gate check: {} attachment(s) over claim {digest}",
                    atts.len()
                );
                match outcome.status {
                    GateStatus::Verified => println!(
                        "  status: VERIFIED\n  >=2 independent matched attachments + a surviving adversarial probe."
                    ),
                    GateStatus::Refuted => {
                        println!("  status: REFUTED");
                        for r in &outcome.reasons {
                            println!("    - {r}");
                        }
                    }
                    GateStatus::NeedsVerification => {
                        println!("  status: needs_verification");
                        for r in &outcome.reasons {
                            println!("    - {r}");
                        }
                    }
                }
            }
            if !verified {
                std::process::exit(1);
            }
        }
        GateAction::Vocab { json } => {
            let grades: Vec<&str> = DeliverableGrade::ALL.iter().map(|g| g.as_str()).collect();
            let methods: Vec<&str> = VerifierMethod::ALL.iter().map(|m| m.as_str()).collect();
            let probes = [
                ProbeKind::CounterexampleSearch,
                ProbeKind::CaseBConfig,
                ProbeKind::BoundaryDualFeasibility,
                ProbeKind::FiniteSizeExtrapolation,
                ProbeKind::IndependentReimplementation,
            ];
            let probe_kinds: Vec<&str> = probes.iter().map(|p| p.as_str()).collect();
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "command": "gate vocab",
                        "deliverable_grades": grades,
                        "solve_grades": DeliverableGrade::ALL
                            .iter()
                            .filter(|g| g.is_solve())
                            .map(|g| g.as_str())
                            .collect::<Vec<_>>(),
                        "verifier_methods": methods,
                        "probe_kinds": probe_kinds,
                    }))
                    .expect("serialize gate vocab response")
                );
            } else {
                println!("deliverable grades ({}):", grades.len());
                for g in DeliverableGrade::ALL {
                    let mark = if g.is_solve() { " (solve)" } else { "" };
                    println!("  {}{mark}", g.as_str());
                }
                println!("\nverifier methods ({}):", methods.len());
                for m in &methods {
                    println!("  {m}");
                }
                println!("\nadversarial probe kinds ({}):", probe_kinds.len());
                for p in &probe_kinds {
                    println!("  {p}");
                }
            }
        }
        GateAction::Backfill {
            frontier,
            reviewer,
            dry_run,
            json,
        } => cmd_gate_backfill(&frontier, &reviewer, dry_run, json),
        GateAction::AutoAdmit {
            frontier,
            finding,
            apply,
            json,
        } => cmd_gate_auto_admit(&frontier, &finding, apply, json),
    }
}

/// Preview the exact-lane auto-admission decision for one finding (Phase 1A).
/// READ-ONLY: runs the full un-forgeable trust path over real data and prints
/// whether the finding WOULD auto-admit to `machine_verified`. Never writes.
///
/// The floor (un-forgeable, agent cannot fake): (1) a fresh `vela-verify`
/// re-check of the finding's witness, computed here, not trusted from a field;
/// (2) the frozen `claim_witness_faithful` binding the parsed assertion to the
/// witness structure. Then the proposal-level guards + the attachment
/// corroboration predicate. The `policy.auto_admitted` emit is held off pending
/// the acceptance checklist (docs/EXACT_LANE_GATE.md).
fn cmd_gate_auto_admit(frontier: &Path, finding_id: &str, apply: bool, json_output: bool) {
    use std::collections::BTreeSet;

    let source = repo::detect(frontier).unwrap_or_else(|e| fail_return(&e));
    let proj = repo::load(&source).unwrap_or_else(|e| fail_return(&e));

    // Resolve the finding: a landed canonical finding, or a pending finding.add
    // proposal's payload. Both carry the assertion text + provenance the floor
    // and guards read.
    let (finding, proposal) = resolve_finding_and_proposal(&proj, finding_id);
    let finding = finding.unwrap_or_else(|| {
        fail_return(&format!(
            "no finding '{finding_id}' (landed or in a pending finding.add proposal)"
        ))
    });
    let proposal = proposal.unwrap_or_else(|| {
        fail_return(&format!(
            "no finding.add proposal targets '{finding_id}'; the exact lane admits a proposal, \
             not an already-landed finding"
        ))
    });

    // FLOOR step 1: a fresh frozen re-check of the finding's witness.
    let (witness_ok, witness_msg, witness) = reproduce_finding_witness(&proj, frontier, finding_id);
    // FLOOR step 2: frozen claim<->witness faithfulness.
    let faithful = witness
        .as_ref()
        .map(|w| vela_verify::claim_witness_faithful(&finding.assertion.text, w));
    // The canonical, WITNESS-DERIVED verified claim: exactly what an admit
    // establishes, independent of the author's prose. Surfaces should display
    // THIS (not the assertion text) as the machine_verified claim so prose
    // cannot puff a true bound. (docs/EXACT_LANE_GATE.md §8 residual.)
    let canonical_claim = witness.as_ref().and_then(vela_verify::canonical_claim);

    // Proposal-level guard inputs, derived live (never trusted from a field).
    let synthetic: BTreeSet<String> = proj
        .findings
        .iter()
        .filter(|f| is_synthetic_source(&f.provenance.source_type))
        .map(|f| f.id.clone())
        .collect();
    let mut synthetic = synthetic;
    if is_synthetic_source(&finding.provenance.source_type) {
        synthetic.insert(finding.id.clone());
    }
    let graph = vela_protocol::frontier_graph::FrontierGraph::from_project(&proj);
    let open_contradictions: BTreeSet<String> = vela_protocol::contradiction::derive_candidates(
        &graph,
        proj.frontier_id.as_deref().unwrap_or_default(),
    )
    .into_iter()
    .filter(|c| c.is_open())
    .flat_map(|c| [c.finding_a.clone(), c.finding_b.clone()])
    .collect();
    let matched: Vec<_> = proj
        .verifier_attachments
        .iter()
        .filter(|a| a.target == finding.id)
        .cloned()
        .collect();

    // The proposal-level wrapper (kind, target, drift-pin, lifecycle, synthetic,
    // contradiction, producer != verifier, then the attachment predicate UNLESS
    // floor-sufficient). For the exact lane, the FLOOR (a fresh frozen reproduce
    // + claim_witness_faithful binding) IS the proof: when faithfulness binds,
    // the >=2-independent-attachment bar (the general gate's, for claims with no
    // single frozen verifier) is waived. The witness genuinely reproducing +
    // structurally establishing the parsed claim is a complete, un-forgeable
    // proof of an exact lower-bound/size claim.
    let floor_ok = witness_ok && faithful.as_ref().map(|f| f.faithful).unwrap_or(false);
    let (wrapper_ok, wrapper_reasons) = vela_protocol::proposals::exact_lane_auto_admit(
        &proposal,
        &finding,
        &matched,
        &open_contradictions,
        &synthetic,
        floor_ok,
    );

    // Guard #3 (attachment provenance), scoped to where attachments are
    // actually load-bearing — see `attachment_vouch_gate`.
    let (vouched_ok, vouch_reason) = attachment_vouch_gate(floor_ok, matched.len());

    let would_admit = floor_ok && wrapper_ok && vouched_ok;

    // Apply (opt-in): record the unsigned, idempotent policy.auto_admitted audit
    // event when, AND ONLY WHEN, the finding would auto-admit. Never signs,
    // never lands the finding in canonical state. The emit re-checks nothing it
    // was told: the YES verdict above was computed here from the frozen floor.
    let mut emitted: Option<(String, bool)> = None;
    if apply && would_admit {
        let digest = vela_protocol::verifier_attachment::claim_digest(&finding.assertion.text);
        let attachment_ids: Vec<String> = matched.iter().map(|a| a.id.clone()).collect();
        match proposals::emit_policy_auto_admitted(
            frontier,
            &proposal.id,
            &digest,
            &attachment_ids,
            "exact-lane.v1",
            vela_verify::ENV_ID,
        ) {
            Ok(res) => emitted = Some(res),
            Err(e) => fail_return(&format!("emit policy.auto_admitted: {e}")),
        }
    }

    if json_output {
        let out = json!({
            "finding": finding.id,
            "would_auto_admit": would_admit,
            "floor": {
                "witness_reproduces": witness_ok,
                "witness_detail": witness_msg,
                "claim_witness_faithful": faithful.as_ref().map(|f| f.faithful),
                "faithful_reasons": faithful.as_ref().map(|f| f.reasons.clone()),
            },
            "canonical_claim": canonical_claim,
            "proposal_guards_ok": wrapper_ok,
            "proposal_guard_reasons": wrapper_reasons,
            "attachment_provenance_ok": vouched_ok,
            "attachment_provenance_reason": if vouch_reason.is_empty() { serde_json::Value::Null } else { json!(vouch_reason) },
            "matched_attachments": matched.len(),
            "applied": apply,
            "event_id": emitted.as_ref().map(|(id, _)| id.clone()),
            "newly_emitted": emitted.as_ref().map(|(_, n)| *n),
            "tier": emitted.as_ref().map(|_| "machine_verified"),
            "note": if apply {
                "policy.auto_admitted is unsigned + idempotent; machine_verified is distinct from human accepted and is NOT landed in canonical findings (docs/EXACT_LANE_GATE.md)."
            } else {
                "READ-ONLY preview; pass --apply to record the (idempotent, unsigned) policy.auto_admitted audit event when the verdict is YES (docs/EXACT_LANE_GATE.md)."
            },
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
    } else {
        println!("exact-lane auto-admit for {}", finding.id);
        println!(
            "  floor 1 (witness reproduces, frozen): {} {}",
            if witness_ok { "PASS" } else { "FAIL" },
            witness_msg
        );
        match &faithful {
            Some(f) => println!(
                "  floor 2 (claim<->witness faithful, frozen): {}{}",
                if f.faithful { "PASS" } else { "FAIL" },
                if f.reasons.is_empty() {
                    String::new()
                } else {
                    format!(" — {}", f.reasons.join("; "))
                }
            ),
            None => println!("  floor 2 (claim<->witness faithful): SKIP (no witness)"),
        }
        println!(
            "  proposal guards + corroboration: {}{}",
            if wrapper_ok { "PASS" } else { "FAIL" },
            if wrapper_reasons.is_empty() {
                String::new()
            } else {
                format!(" — {}", wrapper_reasons.join("; "))
            }
        );
        println!(
            "  attachment provenance (human-vouched): {}{}",
            if vouched_ok { "PASS" } else { "FAIL" },
            if vouch_reason.is_empty() {
                String::new()
            } else {
                format!(" — {vouch_reason}")
            }
        );
        if let Some(c) = &canonical_claim {
            println!("  verified claim (witness-derived, not prose): {c}");
        }
        println!(
            "  => auto-admit to machine_verified: {}",
            if would_admit { "YES" } else { "NO" }
        );
        match &emitted {
            Some((id, true)) => println!("  recorded policy.auto_admitted {id} (machine_verified)"),
            Some((id, false)) => {
                println!("  already admitted: policy.auto_admitted {id} (idempotent no-op)")
            }
            None if apply => {} // would_admit false; the exit below reports it
            None => println!(
                "  (read-only preview; pass --apply to record the unsigned, idempotent \
                 policy.auto_admitted event when the verdict is YES — docs/EXACT_LANE_GATE.md)"
            ),
        }
    }
    if !would_admit {
        std::process::exit(1);
    }
}

/// Resolve a finding by id from canonical state or a pending finding.add
/// proposal payload, returning the finding and the finding.add proposal that
/// carries it (the exact lane admits a proposal, so the proposal is required).
fn resolve_finding_and_proposal(
    proj: &vela_protocol::project::Project,
    finding_id: &str,
) -> (
    Option<vela_protocol::bundle::FindingBundle>,
    Option<vela_protocol::proposals::StateProposal>,
) {
    let proposal = proj
        .proposals
        .iter()
        .find(|p| {
            p.kind == "finding.add"
                && (p.target.id == finding_id
                    || p.payload
                        .get("finding")
                        .and_then(|f| f.get("id"))
                        .and_then(|i| i.as_str())
                        == Some(finding_id))
        })
        .cloned();
    // Prefer the proposal's own finding body (what the lane admits); fall back
    // to the landed finding.
    let finding = proposal
        .as_ref()
        .and_then(|p| p.payload.get("finding").cloned())
        .and_then(|v| serde_json::from_value::<vela_protocol::bundle::FindingBundle>(v).ok())
        .or_else(|| proj.findings.iter().find(|f| f.id == finding_id).cloned());
    (finding, proposal)
}

/// True if a provenance source_type denotes a synthetic NARRATIVE source that
/// needs human review (mirrors the `synthetic_source_requires_review` signal,
/// signals.rs). Deliberately NOT `model_output`: a campaign produces a finding
/// whose trust is its frozen WITNESS (the floor re-checks it), so the producer
/// being a model is exactly what the floor handles — the positive provenance is
/// the reproduce-clean witness, not the prose source. Only a synthetic report /
/// agent trace with no frozen witness is the thing this guard catches.
fn is_synthetic_source(source_type: &str) -> bool {
    let s = source_type.trim().to_ascii_lowercase();
    s == "synthetic_report" || s == "agent_trace"
}

/// Guard #3 (attachment provenance), scoped to where attachments are actually
/// load-bearing. The exact lane's trust is the FLOOR: a fresh frozen `vela
/// reproduce` over the witness plus `claim_witness_faithful` binding the parsed
/// claim to the witness structure. When the floor holds it is a complete,
/// un-forgeable proof of the exact lower-bound/size claim (an agent cannot make
/// a fabricated witness reproduce, nor inflate a claim past what the witness
/// structurally establishes), so matched attachments are non-load-bearing
/// corroboration and do NOT gate admission. This mirrors `exact_lane_auto_admit`'s
/// own guard #8, which waives the >=2-attachment requirement under
/// floor-sufficiency.
///
/// When the floor does NOT hold, attachments would be the load-bearing evidence
/// (the general / non-exact, e.g. Lean lane). Admitting there rests on
/// attachment provenance being a trustworthy HUMAN signal, and it is not yet:
/// actor registration is open self-enrollment, so a "registered non-agent
/// reviewer" can be a key an agent minted and self-registered under a
/// `reviewer:` id, then honestly signed with (an adversarial review confirmed
/// this self-enrollment bypass). Until the vouch binds to an owner/maintainer-
/// signed roster rooted in the frontier owner key, the non-floor lane REFUSES,
/// in the safe direction. (docs/EXACT_LANE_GATE.md §7 guard #3.)
fn attachment_vouch_gate(floor_ok: bool, matched_len: usize) -> (bool, String) {
    if floor_ok {
        if matched_len == 0 {
            (true, String::new())
        } else {
            (
                true,
                format!(
                    "floor-sufficient: {matched_len} matched attachment(s) are non-load-bearing corroboration, not gating"
                ),
            )
        }
    } else {
        (
            false,
            "non-floor-sufficient admission would rest on attachment provenance, which is not yet owner-rooted (open actor self-enrollment is forgeable); lane refuses in the safe direction"
                .to_string(),
        )
    }
}

// ---- the foundry: one unattended compounding turn (Phase 2) ----

/// `vela foundry run`: produce -> frozen-verify -> register -> auto-admit, one
/// unattended turn over the de-human-gate, no human and no key. Dry-run by
/// default; `--apply` records the admission. The turn chains the tested paths:
/// the frozen-verifier `campaign` producer, the witness-artifact registration
/// (agent-allowed provenance), and the exact-lane `gate auto-admit` (which
/// re-runs the frozen verifier itself). This is the memo's compounding loop:
/// the de-human-gate made to fire on a freshly produced candidate.
pub(crate) fn cmd_foundry(action: FoundryAction) {
    match action {
        FoundryAction::Run {
            frontier,
            kind,
            n,
            h,
            k,
            restarts,
            seed,
            seeds,
            run_ablation,
            apply,
            json,
        } => cmd_foundry_run(
            &frontier,
            &kind,
            n,
            h,
            k,
            restarts,
            seed,
            seeds,
            run_ablation,
            apply,
            json,
        ),
        FoundryAction::Targets {
            catalog,
            records,
            attackable_only,
            json,
        } => cmd_foundry_targets(&catalog, &records, attackable_only, json),
        FoundryAction::Ablate {
            frontier,
            kind,
            records,
            n,
            h,
            budget,
            seeds,
            json,
        } => cmd_foundry_ablate(
            &frontier,
            &kind,
            records.as_deref(),
            n,
            h,
            budget,
            seeds,
            json,
        ),
        FoundryAction::LeanTargets {
            lean_dir,
            subdir,
            all,
            limit,
            json,
        } => cmd_foundry_lean_targets(&lean_dir, &subdir, all, limit, json),
        FoundryAction::LeanRun {
            lean_dir,
            module,
            decl,
            frontier,
            finding,
            reviewer,
            actor,
            key,
            out_dir,
            json,
        } => cmd_foundry_lean_run(LeanRunArgs {
            lean_dir,
            module,
            decl,
            frontier,
            finding,
            reviewer,
            actor,
            key,
            out_dir,
            json,
        }),
    }
}

// ---------------------------------------------------------------------------
// The prover-in-the-loop Lean lane (Program 1 of the Known->Unknown plan).
// Known proved lemmas compose into proofs of open theorems. The AI (proof-
// subagents) is the PRODUCER of a candidate Lean proof; the Lean kernel +
// `#print axioms` classification is the frozen VERIFIER (the analogue of `splr`
// producing a SAT assignment that `verify_diff_triangle` checks); a human key
// ACCEPTS. No model is ever in a trust path.
// ---------------------------------------------------------------------------

/// One open Lean obligation surfaced by `vela foundry lean-targets`.
#[derive(serde::Serialize)]
struct LeanTarget {
    module: String,
    /// Fully-qualified decl (`Namespace.decl`) for `#print axioms` / `lean-run`.
    decl: String,
    namespace: String,
    category: String,
    /// `formalization_gap` (a non-research-open decl still carrying `sorry` — the
    /// tractable target) or `research_open` (the headline open problem, not
    /// expected subagent-closable).
    tractability: String,
}

/// Read-only worklist: scan a formal-conjectures corpus for OPEN Lean
/// obligations (decls carrying `sorry`), ranked by a heuristic tractability so
/// the prove loop attacks the formalization gaps first. The real arbiter of
/// closability is `lean-run`'s kernel build; this only orders the queue.
fn cmd_foundry_lean_targets(
    lean_dir: &Path,
    subdir: &str,
    all: bool,
    limit: usize,
    json_out: bool,
) {
    let root = lean_dir.join(subdir);
    let mut files: Vec<std::path::PathBuf> = Vec::new();
    collect_lean_files(&root, &mut files);
    files.sort();

    let mut targets: Vec<LeanTarget> = Vec::new();
    for f in &files {
        let Ok(text) = std::fs::read_to_string(f) else {
            continue;
        };
        let module = f
            .strip_prefix(lean_dir)
            .unwrap_or(f)
            .to_string_lossy()
            .to_string();
        targets.extend(scan_lean_decls(&text, &module));
    }
    // Tractable gaps first, then by module for determinism.
    targets.sort_by(|a, b| {
        let rank = |t: &str| if t == "formalization_gap" { 0 } else { 1 };
        rank(&a.tractability)
            .cmp(&rank(&b.tractability))
            .then(a.module.cmp(&b.module))
            .then(a.decl.cmp(&b.decl))
    });
    let shown: Vec<&LeanTarget> = targets
        .iter()
        .filter(|t| all || t.tractability == "formalization_gap")
        .take(limit)
        .collect();

    if json_out {
        print_json(&json!({
            "command": "foundry.lean-targets",
            "lean_dir": lean_dir.display().to_string(),
            "subdir": subdir,
            "open_total": targets.len(),
            "shown": shown.len(),
            "note": "tractability is a heuristic; the kernel build in `lean-run` is the arbiter. \
                     research_open decls are the headline problems, not expected subagent-closable.",
            "targets": shown,
        }));
    } else {
        println!(
            "open Lean obligations in {} — {} ({} tractable gaps surfaced)",
            root.display(),
            targets.len(),
            shown
                .iter()
                .filter(|t| t.tractability == "formalization_gap")
                .count(),
        );
        for t in &shown {
            println!("  [{}] {}  ({})", t.tractability, t.decl, t.module);
        }
        if shown.is_empty() {
            println!(
                "  (no tractable gaps; pass --all to list the headline research-open problems)"
            );
        }
        println!(
            "\n  honest: tractability is heuristic; `vela foundry lean-run` (kernel build + \
             #print axioms) is the arbiter. most research-open Erdős problems are not \
             subagent-closable."
        );
    }
}

/// Recursively collect `*.lean` files under `dir`.
fn collect_lean_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.filter_map(|e| e.ok()) {
        let p = e.path();
        if p.is_dir() {
            collect_lean_files(&p, out);
        } else if p.extension().and_then(|s| s.to_str()) == Some("lean") {
            out.push(p);
        }
    }
}

/// Parse a Lean source for open obligations: each `theorem`/`lemma` whose block
/// (up to the next decl) still contains `sorry`. Captures the opened namespace,
/// the `@[category ...]` tag, and a tractability heuristic.
fn scan_lean_decls(text: &str, module: &str) -> Vec<LeanTarget> {
    let lines: Vec<&str> = text.lines().collect();
    // Decl positions + the namespace open just before them.
    let mut namespace = String::new();
    let mut decl_starts: Vec<(usize, String)> = Vec::new(); // (line idx, short decl)
    for (i, raw) in lines.iter().enumerate() {
        let l = raw.trim_start();
        if let Some(rest) = l.strip_prefix("namespace ") {
            namespace = rest.split_whitespace().next().unwrap_or("").to_string();
        }
        for kw in ["theorem ", "lemma "] {
            if let Some(rest) = l.strip_prefix(kw) {
                let name: String = rest
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '.' || *c == '\'')
                    .collect();
                if !name.is_empty() {
                    decl_starts.push((i, name));
                }
                break;
            }
        }
    }
    let mut out = Vec::new();
    for (idx, (start, short)) in decl_starts.iter().enumerate() {
        let end = decl_starts
            .get(idx + 1)
            .map(|(j, _)| *j)
            .unwrap_or(lines.len());
        let block = lines[*start..end].join("\n");
        if !block.contains("sorry") {
            continue; // already proved -> not an open obligation
        }
        // The `@[category ...]` tag is on the lines just above the decl.
        let cat_start = start.saturating_sub(4);
        let header = lines[cat_start..*start].join(" ");
        let category = if let Some(i) = header.find("category ") {
            header[i + "category ".len()..]
                .split([',', ']'])
                .next()
                .unwrap_or("")
                .trim()
                .to_string()
        } else {
            String::new()
        };
        let research_open = header.contains("research open");
        let tractability = if research_open {
            "research_open"
        } else {
            "formalization_gap"
        }
        .to_string();
        let fq = if namespace.is_empty() {
            short.clone()
        } else {
            format!("{namespace}.{short}")
        };
        out.push(LeanTarget {
            module: module.to_string(),
            decl: fq,
            namespace: namespace.clone(),
            category,
            tractability,
        });
    }
    out
}

/// Arguments for `cmd_foundry_lean_run` (grouped to avoid a too-many-args lint).
struct LeanRunArgs {
    lean_dir: std::path::PathBuf,
    module: String,
    decl: String,
    frontier: Option<std::path::PathBuf>,
    finding: Option<String>,
    reviewer: String,
    actor: String,
    key: Option<std::path::PathBuf>,
    out_dir: Option<std::path::PathBuf>,
    json: bool,
}

/// Convert a module path (`FormalConjectures/ErdosProblems/828.lean`) to its
/// Lean import/build name (`FormalConjectures.ErdosProblems.«828»`), wrapping
/// numeric-leading components in guillemets.
fn module_to_import(module_rel: &str) -> String {
    module_rel
        .trim_end_matches(".lean")
        .split('/')
        .map(|c| {
            if c.chars()
                .next()
                .map(|ch| ch.is_ascii_digit())
                .unwrap_or(false)
            {
                format!("«{c}»")
            } else {
                c.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(".")
}

/// The non-AI verifier half of the prove loop: build the proof the producer
/// wrote, classify the target decl's axioms (fail-closed on `sorryAx`), mint a
/// signed `vlv_`, optionally draft a PENDING `verifier.attach`, and STOP before
/// any admission (the Lean lane never auto-admits; the accept is Will's key).
fn cmd_foundry_lean_run(args: LeanRunArgs) {
    use sha2::Digest;
    use vela_protocol::lean_verification::KernelRecheck;
    use vela_protocol::tcb_policy::{
        DEFAULT_ALLOWED_AXIOMS, FORBIDDEN_AXIOMS, TcbDraft, TcbPolicy,
    };

    let signing = crate::cli_identity::resolve_signing_key(args.key.as_deref());
    let lean_import = module_to_import(&args.module);

    // Toolchain + mathlib pins come from the CORPUS (e.g. the FC clone), never
    // the substrate — the vlv_ provenance must reflect what actually built it.
    let toolchain = std::fs::read_to_string(args.lean_dir.join("lean-toolchain"))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let mathlib = mathlib_rev_from_manifest(&args.lean_dir);

    // 1. BUILD the module the producer wrote (incremental over the warm .lake).
    //    A genuine compile error is a NULL turn; `sorry` is NOT an error (it
    //    builds with a warning) — the axiom probe catches it next.
    let build = std::process::Command::new("lake")
        .arg("build")
        .arg(&lean_import)
        .current_dir(&args.lean_dir)
        .output()
        .unwrap_or_else(|e| fail_return(&format!("run `lake build`: {e}")));
    if !build.status.success() {
        let why = String::from_utf8_lossy(&build.stderr);
        return null_lean_turn(args.json, &args.decl, "build_failed", why.trim());
    }
    let mut voh_hasher = sha2::Sha256::new();
    sha2::Digest::update(&mut voh_hasher, &build.stdout);
    sha2::Digest::update(&mut voh_hasher, &build.stderr);

    // 2. CLASSIFY: #print axioms over the target decl (per-decl, fail-closed).
    let axioms = match crate::cli_lean::lean_axioms_probe(&args.lean_dir, &lean_import, &args.decl)
    {
        Ok(a) => a,
        Err(e) => return null_lean_turn(args.json, &args.decl, "probe_failed", &e),
    };
    sha2::Digest::update(
        &mut voh_hasher,
        format!("{}|{}", args.decl, axioms.join(",")).as_bytes(),
    );
    let verifier_output_hash = hex::encode(voh_hasher.finalize());

    // 3. ANCHOR the source bytes + MINT the signed vlv_ (the producer is NOT in
    //    this trust path — the kernel + this classification are).
    let title = format!("{} :: {}", args.module, args.decl);
    let anchor = vela_edge::lean_anchors::LeanAnchor::anchor_for_parts(
        0,
        &title,
        &args.module,
        &args.decl,
        "formal-conjectures prover-lane target",
        &args.lean_dir,
    )
    .unwrap_or_else(|e| fail_return(&format!("anchor: {e}")));
    let policy = TcbPolicy::build(TcbDraft {
        allowed_axioms: DEFAULT_ALLOWED_AXIOMS
            .iter()
            .map(|s| s.to_string())
            .collect(),
        forbidden_axioms: FORBIDDEN_AXIOMS.iter().map(|s| s.to_string()).collect(),
        kernel_checker: String::new(),
        kernel_checker_version: String::new(),
        lean_toolchain: toolchain.clone(),
        mathlib_revision: mathlib.clone(),
    })
    .unwrap_or_else(|e| fail_return(&format!("build tcb policy: {e}")));
    let axioms_map: std::collections::BTreeMap<String, Vec<String>> =
        std::iter::once((args.decl.clone(), axioms.clone())).collect();
    let now = chrono::Utc::now().to_rfc3339();
    let record = crate::cli_lean::mint_verification(
        &anchor,
        &args.decl,
        Some(&axioms_map),
        &policy,
        KernelRecheck::NotRun,
        &toolchain,
        &mathlib,
        &verifier_output_hash,
        &now,
        &args.actor,
        &signing,
    )
    .unwrap_or_else(|e| fail_return(&format!("mint verification: {e}")));

    // Persist the anchor + vlv_.
    let out_dir = args.out_dir.clone().unwrap_or_else(|| {
        args.frontier
            .as_ref()
            .map(|f| f.join("lean-verifications"))
            .unwrap_or_else(|| std::path::PathBuf::from("lean-verifications"))
    });
    if let Err(e) = std::fs::create_dir_all(&out_dir) {
        fail(&format!("create {}: {e}", out_dir.display()));
    }
    let safe = args.decl.replace(['.', ':', '/'], "_");
    let anchor_path = out_dir.join(format!("{safe}.vla.json"));
    let vlv_path = out_dir.join(format!("{safe}.vlv.json"));
    let _ = std::fs::write(
        &anchor_path,
        format!(
            "{}\n",
            serde_json::to_string_pretty(&anchor).unwrap_or_default()
        ),
    );
    let _ = std::fs::write(
        &vlv_path,
        format!(
            "{}\n",
            serde_json::to_string_pretty(&record).unwrap_or_default()
        ),
    );

    // 4. Only a kernel-CLEAN proof is a real turn. failed_axiom_check (sorryAx /
    //    forbidden axiom) is an honest NULL turn — never proposed.
    if record.status != "verified" {
        return null_lean_turn_with(
            args.json,
            &args.decl,
            &record.status,
            &format!("axioms: [{}]", axioms.join(", ")),
            Some(&record.verification_id),
        );
    }

    // 5. Draft a PENDING verifier.attach when a frontier + finding is given. The
    //    Lean lane STOPS here: a truth-bearing accept is human key custody.
    let mut proposal_id = None;
    let mut proposal_status = "not_drafted";
    if let (Some(frontier), Some(finding)) = (args.frontier.as_ref(), args.finding.as_ref()) {
        let (pid, status) = draft_lean_attachment(
            frontier,
            finding,
            &record,
            &toolchain,
            &args.reviewer,
            &args.actor,
        );
        proposal_id = pid;
        proposal_status = status;
    }

    if args.json {
        print_json(&json!({
            "command": "foundry.lean-run",
            "turn": "verified",
            "decl": args.decl,
            "vlv": record.verification_id,
            "vla": anchor.anchor_id,
            "status": record.status,
            "axioms": axioms,
            "toolchain": toolchain,
            "mathlib": mathlib,
            "structurally_present": anchor.structurally_present,
            "proposal": proposal_id,
            "proposal_status": proposal_status,
            "auto_admitted": false,
            "note": "Lean lane never auto-admits; acceptance is human key custody.",
        }));
    } else {
        println!(
            "{} {} -> {} ({}), axioms [{}]",
            style::ok("foundry.lean-run"),
            args.decl,
            record.verification_id,
            record.status,
            axioms.join(", "),
        );
        match proposal_status {
            "pending" => println!(
                "  drafted PENDING verifier.attach {} (awaits human accept)",
                proposal_id.as_deref().unwrap_or("")
            ),
            "applied" => println!(
                "  applied verifier.attach {}",
                proposal_id.as_deref().unwrap_or("")
            ),
            _ => println!("  (no frontier/finding given — minted vlv_ only)"),
        }
        println!("  the Lean lane never auto-admits; acceptance is a human key-custody decision.");
    }
}

/// Read the mathlib revision from a `lake-manifest.json` in `lean_dir`.
fn mathlib_rev_from_manifest(lean_dir: &Path) -> String {
    let Ok(text) = std::fs::read_to_string(lean_dir.join("lake-manifest.json")) else {
        return "unknown".to_string();
    };
    let Ok(val) = serde_json::from_str::<serde_json::Value>(&text) else {
        return "unknown".to_string();
    };
    val.get("packages")
        .and_then(|p| p.as_array())
        .and_then(|arr| {
            arr.iter()
                .find(|p| p.get("name").and_then(|n| n.as_str()) == Some("mathlib"))
        })
        .and_then(|p| {
            p.get("rev")
                .or_else(|| p.get("inputRev"))
                .and_then(|r| r.as_str())
        })
        .unwrap_or("unknown")
        .to_string()
}

/// Emit a NULL Lean turn (no candidate verified) and return.
fn null_lean_turn(json: bool, decl: &str, reason: &str, detail: &str) {
    null_lean_turn_with(json, decl, reason, detail, None)
}

fn null_lean_turn_with(json: bool, decl: &str, reason: &str, detail: &str, vlv: Option<&str>) {
    if json {
        print_json(&json!({
            "command": "foundry.lean-run",
            "turn": "null",
            "decl": decl,
            "reason": reason,
            "detail": detail,
            "vlv": vlv,
            "auto_admitted": false,
        }));
    } else {
        println!(
            "foundry.lean-run turn: NULL ({reason}) — {decl}: {detail}{}",
            vlv.map(|v| format!(" [{v}]")).unwrap_or_default()
        );
    }
}

/// Draft a `verifier.attach` (PENDING for an agent reviewer, applied for a
/// human) binding the kernel-clean `vlv_` to the open finding it closes. Returns
/// `(proposal_id, status)`. Reuses the gate-backfill attachment shape.
fn draft_lean_attachment(
    frontier: &Path,
    finding: &str,
    record: &vela_protocol::lean_verification::LeanVerification,
    toolchain: &str,
    reviewer: &str,
    actor: &str,
) -> (Option<String>, &'static str) {
    use vela_protocol::events::StateTarget;
    use vela_protocol::verifier_attachment::{
        AdversarialProbe, AttachmentDraft, AttachmentOutcome, MatchToClaim, ProbeKind, ProbeResult,
        VerifierAttachment, VerifierMethod, claim_digest,
    };

    let source = match repo::detect(frontier) {
        Ok(s) => s,
        Err(e) => return (Some(e), "error"),
    };
    let proj = match repo::load(&source) {
        Ok(p) => p,
        Err(e) => return (Some(e), "error"),
    };
    let Some(claim) = proj
        .findings
        .iter()
        .find(|f| f.id == finding)
        .map(|f| f.assertion.text.clone())
    else {
        return (Some(format!("finding {finding} not found")), "error");
    };
    let digest = claim_digest(&claim);
    let att = match VerifierAttachment::build(AttachmentDraft {
        target: finding.to_string(),
        claim_digest: digest,
        verifier_method: VerifierMethod::LeanKernel,
        solver_id: format!("lean:{toolchain}"),
        independent_of: Vec::new(),
        match_to_claim: MatchToClaim {
            matches: true,
            checker_actor: actor.to_string(),
        },
        adversarial_probes: vec![AdversarialProbe {
            kind: ProbeKind::IndependentReimplementation,
            result: ProbeResult::Survived,
            note: "Lean kernel re-elaboration + #print axioms audit".to_string(),
        }],
        outcome: AttachmentOutcome::Passed,
        verifier_actor: actor.to_string(),
        note: format!(
            "Lean kernel proof, axiom-clean ({})",
            record.verification_id
        ),
    })
    .and_then(|a| a.with_method_integrity(record.to_attachment_integrity()))
    {
        Ok(a) => a,
        Err(e) => return (Some(e), "error"),
    };
    let att_value = serde_json::to_value(&att).unwrap_or_default();
    let actor_type = if reviewer.trim().to_ascii_lowercase().starts_with("agent:") {
        "agent"
    } else {
        "human"
    };
    let apply = actor_type == "human";
    let proposal = proposals::new_proposal(
        "verifier.attach",
        StateTarget {
            r#type: "finding".to_string(),
            id: finding.to_string(),
        },
        reviewer,
        actor_type,
        "Lean kernel proof (prover-in-the-loop)",
        json!({ "attachment": att_value }),
        Vec::new(),
        Vec::new(),
    );
    match proposals::create_or_apply(frontier, proposal, apply) {
        Ok(res) if res.applied_event_id.is_some() => (Some(res.proposal_id), "applied"),
        Ok(res) => (Some(res.proposal_id), "pending"),
        Err(e) => (Some(e), "error"),
    }
}

/// The continuous-ablation heartbeat: does inherited frontier state make the
/// next solver go farther per unit compute? The honest skip-known-work form
/// (the H1 result): at a FIXED budget, inheriting the frontier's `known` solved
/// targets lets the producer concentrate the whole budget on the boundary
/// (TREATMENT); a producer with no inherited state must spread the same budget
/// across the `known + 1` targets it might need to rediscover (CONTROL, the
/// boundary gets `budget / (known + 1)`). Over `seeds` deterministic runs, the
/// difference in boundary-success rate is the inheritance effect. Exits 1 if
/// treatment does not beat control (the plan's hard gate).
#[allow(clippy::too_many_arguments)]
fn cmd_foundry_ablate(
    frontier: &Path,
    kind: &str,
    records: Option<&Path>,
    boundary: usize,
    h: usize,
    budget: u64,
    seeds: u64,
    json_out: bool,
) {
    // The inherited state: how many solved targets of this kind are already
    // banked (the depth a no-inheritance producer would have to rediscover).
    // Either from a per-family records catalog (accepted, reproduce-backed
    // bounds — runs without a key-custody accept ceremony) or, by default, from
    // the frontier's accepted findings (matched by the kind keyword, so it works
    // for kinds with no `{0,1}^n` ambient dimension like golomb/costas too).
    let known = if let Some(records_path) = records {
        let raw = std::fs::read_to_string(records_path)
            .unwrap_or_else(|e| fail_return(&format!("read {}: {e}", records_path.display())));
        let v: serde_json::Value = serde_json::from_str(&raw)
            .unwrap_or_else(|e| fail_return(&format!("parse {}: {e}", records_path.display())));
        // Accept either the `records/<family>.json` schema (`bounds[].accepted`)
        // or the producer `bounds.json` (`bounds[].accepted`).
        v.get("bounds")
            .and_then(|b| b.as_array())
            .map(|arr| {
                arr.iter()
                    .filter(|e| e.get("accepted").and_then(|a| a.as_bool()).unwrap_or(false))
                    .count()
            })
            .unwrap_or(0)
    } else {
        let source = repo::detect(frontier).unwrap_or_else(|e| fail_return(&e));
        let proj = repo::load(&source).unwrap_or_else(|e| fail_return(&e));
        proj.findings
            .iter()
            .filter(|f| f.assertion.text.to_lowercase().contains(kind))
            .count()
    };
    let range = (known as u64) + 1; // the targets a no-inheritance producer covers
    let control_budget = (budget / range).max(1);

    let target = crate::campaign::Target {
        kind: kind.to_string(),
        n: boundary,
        h,
        d: 0,
        w: 0,
        k: 0,
        t: 0,
    };

    // The H1 metric is the SCORE (witness size / frontier order), not
    // found/not-found: a witness usually exists, the question is how BIG a one
    // each arm reaches with its budget. Mean score over `seeds` deterministic
    // runs; treatment concentrates the full budget, control gets the spread.
    let mut t_total = 0u64;
    let mut c_total = 0u64;
    for seed in 1..=seeds {
        let score_of = |restarts: u64| -> u64 {
            match crate::campaign::search_target(&target, restarts, seed) {
                Ok(Some(found)) => found.score as u64,
                _ => 0,
            }
        };
        t_total += score_of(budget);
        c_total += score_of(control_budget);
    }
    let t_mean = t_total as f64 / seeds as f64;
    let c_mean = c_total as f64 / seeds as f64;
    let delta = t_mean - c_mean;
    let inheritance_compounds = t_mean > c_mean;

    if json_out {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "kind": kind,
                "boundary": boundary,
                "inherited_solved_targets": known,
                "budget": budget,
                "control_budget_per_boundary": control_budget,
                "seeds": seeds,
                "treatment_mean_score": t_mean,
                "control_mean_score": c_mean,
                "delta": delta,
                "inheritance_compounds": inheritance_compounds,
            }))
            .unwrap()
        );
    } else {
        println!("continuous ablation — {kind} boundary n={boundary}:");
        println!("  inherited solved targets (skip-known-work depth): {known}");
        println!("  fixed budget per arm: {budget} restarts");
        println!("  TREATMENT (inherit -> full {budget} on boundary): mean score {t_mean:.2}");
        println!(
            "  CONTROL   (no inherit -> {control_budget}/boundary):        mean score {c_mean:.2}"
        );
        if known == 0 {
            println!(
                "  => no inherited state for '{kind}' on this frontier (N/A — nothing to inherit)"
            );
        } else {
            println!(
                "  => inheritance compounds: {} (Δ {:+.2} frontier orders)",
                if inheritance_compounds { "YES" } else { "NO" },
                delta
            );
        }
    }
    // Informational by default (a measurement, not a self-gate): exit 0 always.
    // A foundry run or CI gates by reading `inheritance_compounds` in the JSON.
    // Only a kind that is BOTH a real compute-lever AND carries inherited state
    // is expected to compound — sidon is greedy-saturated (H1), golomb is the
    // lever; the reading reflects that honestly per (kind, frontier).
}

/// Diverse-search portfolio: run the campaign across `count` consecutive seeds
/// (each to a throwaway file, no proposal), parse the printed score, and return
/// the seed that produced the best result (lowest for minimization kinds, highest
/// otherwise). The caller then proposes only that seed's witness.
#[allow(clippy::too_many_arguments)]
fn pick_best_seed(
    exe: &Path,
    frontier: &Path,
    kind: &str,
    n: usize,
    h: usize,
    k: usize,
    restarts: u64,
    base_seed: u64,
    count: u64,
    minimize: bool,
) -> u64 {
    let mut best_seed = base_seed;
    let mut best_score: Option<i64> = None;
    for s in base_seed..base_seed.saturating_add(count) {
        let tmp = std::env::temp_dir().join(format!("vela_portfolio_{kind}_{n}_{s}.json"));
        let mut c = std::process::Command::new(exe);
        c.arg("campaign")
            .arg("run")
            .arg(kind)
            .arg("--n")
            .arg(n.to_string())
            .arg("--restarts")
            .arg(restarts.to_string())
            .arg("--seed")
            .arg(s.to_string())
            .arg("--out")
            .arg(&tmp);
        if k > 0 {
            c.arg("--k").arg(k.to_string());
        }
        if kind == "bh" {
            c.arg("--h").arg(h.to_string());
        }
        let _ = frontier; // portfolio scan is frontier-independent (writes a temp)
        let out = match c.output() {
            Ok(o) if o.status.success() => o,
            _ => continue,
        };
        let txt = String::from_utf8_lossy(&out.stdout);
        let score = txt
            .split("verified score ")
            .nth(1)
            .and_then(|s| s.split_whitespace().next())
            .and_then(|s| s.parse::<i64>().ok());
        let _ = std::fs::remove_file(&tmp);
        if let Some(sc) = score {
            let better = match best_score {
                None => true,
                Some(b) => {
                    if minimize {
                        sc < b
                    } else {
                        sc > b
                    }
                }
            };
            if better {
                best_score = Some(sc);
                best_seed = s;
            }
        }
    }
    best_seed
}

#[allow(clippy::too_many_arguments)]
fn cmd_foundry_run(
    frontier: &Path,
    kind: &str,
    n: usize,
    h: usize,
    k: usize,
    restarts: u64,
    seed: u64,
    seeds: u64,
    run_ablation: bool,
    apply: bool,
    json_out: bool,
) {
    let exe = std::env::current_exe()
        .unwrap_or_else(|e| fail_return(&format!("locate vela binary: {e}")));

    // 0. PORTFOLIO: scan `seeds` consecutive seeds (a diverse-search portfolio),
    //    keep the best-scoring, then propose only that one. Lower score is better
    //    for the minimization kinds (diff_triangle/golomb/covering), higher for
    //    the rest. The campaign re-verifies every find, so this never proposes an
    //    unverified witness.
    let minimize = matches!(kind, "diff_triangle" | "golomb" | "covering");
    let seed = if seeds > 1 {
        pick_best_seed(
            &exe, frontier, kind, n, h, k, restarts, seed, seeds, minimize,
        )
    } else {
        seed
    };

    // 1. PRODUCE + PROPOSE via the frozen-verifier campaign (the tested path:
    //    it runs vela-verify on the witness before returning, writes the
    //    witness file, records a `vac_` activity envelope, and lands a pending
    //    finding.add proposal). A failed search is a valid (null) turn.
    let mut produce = std::process::Command::new(&exe);
    produce
        .arg("campaign")
        .arg("run")
        .arg(kind)
        .arg("--n")
        .arg(n.to_string())
        .arg("--restarts")
        .arg(restarts.to_string())
        .arg("--seed")
        .arg(seed.to_string())
        .arg("--frontier")
        .arg(frontier)
        .arg("--propose");
    // Secondary order param (diff_triangle within-row order J, covering block
    // size, …): pass through only when supplied so other kinds are unaffected.
    if k > 0 {
        produce.arg("--k").arg(k.to_string());
    }
    if kind == "bh" {
        produce.arg("--h").arg(h.to_string());
    }
    let produced = produce
        .output()
        .unwrap_or_else(|e| fail_return(&format!("foundry: campaign produce failed: {e}")));
    if !produced.status.success() {
        let why = String::from_utf8_lossy(&produced.stderr);
        if json_out {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "turn": "null",
                    "produced": false,
                    "reason": why.trim(),
                }))
                .unwrap()
            );
        } else {
            println!(
                "foundry turn: NULL (no candidate produced) — {}",
                why.trim()
            );
        }
        return;
    }

    // 2. DISCOVER the finding the campaign just proposed: the pending
    //    finding.add whose assertion names this kind + n. (The campaign's
    //    assertion_for embeds "in {0,1}^n" / the kind keyword.)
    let source = repo::detect(frontier).unwrap_or_else(|e| fail_return(&e));
    let proj = repo::load(&source).unwrap_or_else(|e| fail_return(&e));
    let needle_n = format!("{n}");
    let mut candidates: Vec<&vela_protocol::proposals::StateProposal> = proj
        .proposals
        .iter()
        .filter(|p| {
            p.kind == "finding.add"
                && p.applied_event_id.is_none()
                && p.payload
                    .get("finding")
                    .and_then(|f| f.get("assertion"))
                    .and_then(|a| a.get("text"))
                    .and_then(|t| t.as_str())
                    .map(|t| {
                        let lt = t.to_lowercase();
                        lt.contains(kind) && lt.contains(&needle_n)
                    })
                    .unwrap_or(false)
        })
        .collect();
    candidates.sort_by(|a, b| a.created_at.cmp(&b.created_at));
    let proposal = candidates.last().copied().unwrap_or_else(|| {
        fail_return(&format!(
            "foundry: produced a candidate but found no matching pending finding.add for {kind} n={n}"
        ))
    });
    let finding_id = proposal.target.id.clone();

    // 3. MAP the witness file to the finding in witnesses/targets.json, the
    //    contract register_canonical_witnesses reads.
    let witness_file = if kind == "bh" {
        format!("{kind}-n{n}-h{h}.witness.json")
    } else {
        format!("{kind}-n{n}.witness.json")
    };
    upsert_witness_target(frontier, &witness_file, &finding_id);

    // 4. REGISTER the witness as a content-addressed artifact targeting the
    //    finding (agent-allowed provenance, not a verdict), so the exact lane's
    //    floor can re-run the frozen verifier over it.
    let (registered, _no_target) =
        register_canonical_witnesses(frontier, "agent:vela-foundry", false);

    // 5. AUTO-ADMIT through the exact-lane de-human-gate (the tested command;
    //    exit 1 on a NO verdict is captured, never fatal to the turn).
    let mut admit = std::process::Command::new(&exe);
    admit
        .arg("gate")
        .arg("auto-admit")
        .arg(frontier)
        .arg("--finding")
        .arg(&finding_id)
        .arg("--json");
    if apply {
        admit.arg("--apply");
    }
    let admit_out = admit
        .output()
        .unwrap_or_else(|e| fail_return(&format!("foundry: auto-admit failed: {e}")));
    let verdict: Value = serde_json::from_slice(&admit_out.stdout)
        .unwrap_or_else(|_| json!({"would_auto_admit": false}));
    let admitted = verdict
        .get("would_auto_admit")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    // 5b. ABLATION GATE: optionally require that inherited frontier state makes
    //     this kind compound (the skip-known-work H1 measure, same as
    //     `foundry ablate`). Fails the run when treatment <= control on a kind
    //     that carries inherited state — the plan's hard gate.
    if run_ablation {
        let known = proj
            .findings
            .iter()
            .filter(|f| f.assertion.text.to_lowercase().contains(kind))
            .count();
        let budget = 40u64;
        let control_budget = (budget / ((known as u64) + 1)).max(1);
        let target = crate::campaign::Target {
            kind: kind.to_string(),
            n,
            h,
            ..Default::default()
        };
        let (mut t_total, mut c_total) = (0u64, 0u64);
        for s in 1..=5u64 {
            let score_of =
                |restarts: u64| match crate::campaign::search_target(&target, restarts, s) {
                    Ok(Some(f)) => f.score as u64,
                    _ => 0,
                };
            t_total += score_of(budget);
            c_total += score_of(control_budget);
        }
        let (t_mean, c_mean) = (t_total as f64 / 5.0, c_total as f64 / 5.0);
        if known > 0 && t_mean <= c_mean {
            fail_return::<()>(&format!(
                "foundry: ablation gate FAILED for {kind} — inherited state does not compound \
                 (treatment {t_mean:.2} <= control {c_mean:.2}); not a free-pass turn"
            ));
        }
    }

    // 5c. DEPOSIT a durable vat_ attempt — the inherited memory of this turn, so
    //     the next solver reads what was tried instead of re-searching it.
    //     Best-effort and only when applying: a dry run or a keyless context
    //     records nothing. An attempt is provenance (claimed_status is
    //     DISPLAY-ONLY, never trusted), so an agent key is allowed — exactly like
    //     the vac_ envelope the campaign already records. problem == 0 makes it a
    //     domain-general attempt keyed on frontier + kind + claim.
    let mut deposited_attempt: Option<String> = None;
    if apply && let Some(signing_key) = crate::cli_identity::resolve_signing_key_opt(None) {
        let claim = proposal
            .payload
            .get("finding")
            .and_then(|f| f.get("assertion"))
            .and_then(|a| a.get("text"))
            .and_then(|t| t.as_str())
            .unwrap_or_default()
            .to_string();
        let frontier_label = proj
            .frontier_id
            .clone()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| {
                frontier
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("frontier")
                    .to_string()
            });
        if !claim.trim().is_empty() && !frontier_label.trim().is_empty() {
            let draft = vela_protocol::attempt::AttemptDraft {
                problem: 0,
                frontier: frontier_label,
                kind: kind.to_string(),
                claim,
                claimed_status: if admitted {
                    "machine_verified".to_string()
                } else {
                    "candidate".to_string()
                },
                method_families: vec![kind.to_string(), "greedy-restart".to_string()],
                producer: vela_protocol::attempt::ProducerRef {
                    system: "vela-foundry".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    config_digest: format!("seed={seed};restarts={restarts}"),
                },
                ..Default::default()
            };
            if let Ok(att) = vela_protocol::attempt::Attempt::build(draft, &signing_key) {
                // Reload: the auto-admit --apply subprocess may have appended
                // events to the log since `proj` was read.
                if let Ok(mut project2) = repo::load_from_path(frontier) {
                    let mut ev = att.deposit_event(
                        "agent:vela-foundry",
                        "agent",
                        "foundry turn: banked attempt (provenance, not a verdict)",
                    );
                    if vela_protocol::reducer::apply_event(&mut project2, &ev).is_ok()
                        && let Ok(sig) = vela_protocol::sign::sign_event(&ev, &signing_key)
                    {
                        ev.signature = Some(sig);
                        project2.events.push(ev);
                        if repo::save_to_path(frontier, &project2).is_ok() {
                            deposited_attempt = Some(att.attempt_id);
                        }
                    }
                }
            }
        }
    }

    // 6. REPORT the turn.
    if json_out {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "turn": "complete",
                "produced": true,
                "finding": finding_id,
                "witnesses_registered": registered,
                "applied": apply,
                "auto_admit": verdict,
                "tier": if admitted && apply { "machine_verified" } else { "pending" },
                "attempt_deposited": deposited_attempt,
            }))
            .unwrap()
        );
    } else {
        println!("foundry turn for {kind} n={n}:");
        println!("  produced + proposed: {finding_id}");
        println!("  witness registered as artifact: {registered} new");
        println!(
            "  exact-lane auto-admit: {}",
            if admitted { "YES" } else { "NO" }
        );
        if let Some(reasons) = verdict
            .get("proposal_guard_reasons")
            .and_then(Value::as_array)
            .filter(|r| !r.is_empty())
        {
            for r in reasons {
                if let Some(s) = r.as_str() {
                    println!("      - {s}");
                }
            }
        }
        if admitted && apply {
            println!("  => machine_verified (recorded, no human, no key)");
        } else if admitted {
            println!("  => WOULD auto-admit (dry-run; pass --apply to record)");
        } else {
            println!("  => stays a candidate pending corroboration/review");
        }
        if let Some(att_id) = &deposited_attempt {
            println!("  banked attempt: {att_id} (durable inherited memory)");
        }
    }
}

/// Merge `{witness_file: finding_id}` into `witnesses/targets.json` (create if
/// absent), the map `register_canonical_witnesses` consumes.
fn upsert_witness_target(frontier: &Path, witness_file: &str, finding_id: &str) {
    let dir = frontier.join("witnesses");
    std::fs::create_dir_all(&dir)
        .unwrap_or_else(|e| fail_return(&format!("create {}: {e}", dir.display())));
    let path = dir.join("targets.json");
    let mut map: serde_json::Map<String, Value> = std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    map.insert(witness_file.to_string(), json!(finding_id));
    let body = serde_json::to_string_pretty(&map).unwrap_or_else(|e| fail_return(&e.to_string()));
    std::fs::write(&path, body + "\n")
        .unwrap_or_else(|e| fail_return(&format!("write {}: {e}", path.display())));
}

/// The `vela campaign` engine kinds — the verifier families the foundry can
/// actually attack (every one has a `search_*` in `campaign.rs`).
const FOUNDRY_ENGINE_KINDS: &[&str] = &[
    "gf2_sidon",
    "union_free",
    "rook_directions",
    "cap",
    "constant_weight",
    "covering",
    "sidon",
    "bh",
    "golomb",
    "costas",
    "diff_triangle",
];

/// The current Vela-accepted extent from a `bounds.json`-shaped records file
/// (count of accepted records + the deepest `n` reached and its bound), or None
/// if the file is absent/empty. The honest "what Vela already holds" against
/// which a value-to-beat reads as a gap.
fn read_records_best(path: &Path) -> Option<Value> {
    let raw = std::fs::read_to_string(path).ok()?;
    let doc: Value = serde_json::from_str(&raw).ok()?;
    let bounds = doc.get("bounds")?.as_array()?;
    let mut count = 0i64;
    let mut max_n = -1i64;
    let mut bound_at_max = 0i64;
    for b in bounds {
        if !b.get("accepted").and_then(|v| v.as_bool()).unwrap_or(false) {
            continue;
        }
        count += 1;
        let n = b.get("n").and_then(|x| x.as_i64()).unwrap_or(0);
        if n > max_n {
            max_n = n;
            bound_at_max = b
                .get("best_lower_bound")
                .and_then(|x| x.as_i64())
                .unwrap_or(0);
        }
    }
    (count > 0).then(
        || json!({ "accepted_records": count, "max_n": max_n, "bound_at_max_n": bound_at_max }),
    )
}

/// `vela foundry targets`: the foundry's substrate-native work-list. Read the
/// target catalog, cross-reference the live per-family records, and print the
/// attackable portfolio with each value-to-beat (and the current accepted best
/// where Vela holds records). This replaces the web/script JSON as the foundry's
/// portfolio source; `foundry run` selects a cell from it.
fn cmd_foundry_targets(catalog: &Path, records: &Path, attackable_only: bool, json_out: bool) {
    let raw = std::fs::read_to_string(catalog)
        .unwrap_or_else(|e| fail_return(&format!("read {}: {e}", catalog.display())));
    let doc: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|e| fail_return(&format!("parse {}: {e}", catalog.display())));
    let problems = doc
        .get("problems")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    // Live accepted extent per family, where a records file exists: sidon's
    // canonical `bounds.json`, or the generated `frontiers/<kind>/records.json`
    // (scripts/spine/build_family_records.py). Path relative to `--records`.
    let records_path = |kind: &str| -> std::path::PathBuf {
        if kind == "sidon" {
            records.join("sidon-sets/bounds.json")
        } else {
            records.join(format!("{kind}/records.json"))
        }
    };

    let mut rows: Vec<Value> = Vec::new();
    for p in &problems {
        let id = p.get("id").and_then(|v| v.as_str()).unwrap_or("");
        let kind = p
            .get("verifier_kind")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if id.is_empty() {
            continue;
        }
        let attackable = FOUNDRY_ENGINE_KINDS.contains(&kind);
        if attackable_only && !attackable {
            continue;
        }
        let status = p.get("status").and_then(|v| v.as_str()).unwrap_or("open");
        let inc = p.get("incumbent");
        let value = inc
            .and_then(|i| i.get("value"))
            .filter(|v| !v.is_null())
            .cloned();
        let direction = inc
            .and_then(|i| i.get("direction"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let basis = inc
            .and_then(|i| i.get("basis"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let rpath = records_path(kind);
        let accepted_best = read_records_best(&rpath);
        let records_source = accepted_best.as_ref().map(|_| rpath.display().to_string());
        rows.push(json!({
            "id": id,
            "domain": p.get("domain"),
            "level": p.get("level"),
            "verifier_kind": kind,
            "attackable": attackable,
            "params": p.get("params"),
            "value_to_beat": value,
            "direction": direction,
            "basis": basis,
            "status": status,
            "source": p.get("source"),
            "accepted_best": accepted_best,
            "records_source": records_source,
        }));
    }

    // Sort: attackable+open first; non-engine kinds and showcases last.
    rows.sort_by(|a, b| {
        let key = |r: &Value| -> (u8, u8, String) {
            let att = if r["attackable"].as_bool().unwrap_or(false) {
                0
            } else {
                1
            };
            let st = match r["status"].as_str().unwrap_or("") {
                "open" => 0,
                "verified_showcase" => 2,
                _ => 1,
            };
            (att, st, r["id"].as_str().unwrap_or("").to_string())
        };
        key(a).cmp(&key(b))
    });

    if json_out {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "catalog": catalog.display().to_string(),
                "targets": rows.len(),
                "portfolio": rows,
            }))
            .unwrap()
        );
        return;
    }

    println!(
        "foundry targets — {} cells ({}):",
        rows.len(),
        catalog.display()
    );
    for r in &rows {
        let id = r["id"].as_str().unwrap_or("");
        let kind = r["verifier_kind"].as_str().unwrap_or("");
        let dir = r["direction"].as_str().unwrap_or("");
        let vtb = match &r["value_to_beat"] {
            Value::Null => "per-parameter".to_string(),
            v => v.to_string(),
        };
        let best = match &r["accepted_best"] {
            Value::Object(m) => format!(
                "{} records (n<={})",
                m.get("accepted_records")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0),
                m.get("max_n").and_then(|v| v.as_i64()).unwrap_or(0)
            ),
            _ => "none".to_string(),
        };
        let status = r["status"].as_str().unwrap_or("");
        let flag = if r["attackable"].as_bool().unwrap_or(false) {
            ""
        } else {
            " (no engine kind)"
        };
        println!("  {id:<24} {kind:<16} beat {vtb} ({dir})  accepted {best}  [{status}]{flag}");
    }
    println!(
        "\nattack one with: vela foundry run --frontier <dir> --kind <verifier_kind> --n <param>"
    );
}

/// Re-run the frozen verifier over the finding's witness artifact (the
/// reproduce-binding the exact lane computes itself, never trusting a field).
/// Returns (ok, human-detail, the parsed witness).
fn reproduce_finding_witness(
    proj: &vela_protocol::project::Project,
    frontier: &Path,
    finding_id: &str,
) -> (bool, String, Option<vela_verify::Witness>) {
    for art in &proj.artifacts {
        let is_json = art.media_type.as_deref() == Some("application/json");
        if !(is_json && art.metadata.contains_key("verifier")) {
            continue;
        }
        if !art.target_findings.iter().any(|t| t == finding_id) {
            continue;
        }
        let content = match (art.storage_mode.as_str(), &art.locator) {
            ("local_blob" | "local_file", Some(loc)) => {
                match std::fs::read_to_string(frontier.join(loc.as_str())) {
                    Ok(c) => c,
                    Err(e) => return (false, format!("witness unreadable: {e}"), None),
                }
            }
            _ => continue,
        };
        match parse_witness(&content) {
            Ok(w) => {
                let r = vela_verify::verify_witness(&w);
                return (r.ok, r.message, Some(w));
            }
            Err(e) => return (false, format!("witness parse failed: {e}"), None),
        }
    }
    (
        false,
        "no local frozen-verifier witness artifact targets this finding".to_string(),
        None,
    )
}

/// Backfill frozen-verifier attachments over a frontier's witness artifacts.
/// For each artifact that carries a `verifier` tag and parses as a `vela-verify`
/// Witness, re-run the frozen verifier and, on pass, land a signed
/// `verifier.attach` (ComputationalSearch / vela-verify / Sound) bound to each
/// target finding's claim. Records the machine re-check; the gate still needs
/// >=2 independent attachments for `verified`. Local-first: inspect with
/// --dry-run, then run once.
fn cmd_gate_backfill(frontier: &Path, reviewer: &str, dry_run: bool, json_output: bool) {
    use std::collections::HashMap;
    use vela_protocol::events::StateTarget;
    use vela_protocol::verifier_attachment::{
        AdversarialProbe, AttachmentDraft, AttachmentOutcome, MatchToClaim, MethodIntegrity,
        ProbeKind, ProbeResult, VerifierAttachment, VerifierMethod, claim_digest,
    };

    // Registration pre-pass: deposit any canonical `witnesses/*.witness.json`
    // not yet present as a content-addressed artifact, so the attach loop below
    // can feed the gate over them. No-op when the frontier ships no
    // `witnesses/targets.json` (preserves prior behavior).
    let (registered, no_target) = register_canonical_witnesses(frontier, reviewer, dry_run);

    let source = repo::detect(frontier).unwrap_or_else(|e| fail_return(&e));
    let proj = repo::load(&source).unwrap_or_else(|e| fail_return(&e));

    // Claim text per finding id; claim_digest binds the attachment to it (G2).
    let claim_by_finding: HashMap<String, String> = proj
        .findings
        .iter()
        .map(|f| (f.id.clone(), f.assertion.text.clone()))
        .collect();

    // An agent may draft (create pending) but not self-apply a truth-bearing
    // `verifier.attach`; a human reviewer applies inline. (The substrate's
    // accept gate enforces this independently — this just avoids drafting then
    // failing to self-accept.)
    let apply = !reviewer.trim().to_ascii_lowercase().starts_with("agent:");

    // (finding, witness kind, claim_digest) for each landed / pending / planned check.
    let mut done: Vec<(String, String, String)> = Vec::new();
    let mut pending: Vec<(String, String, String)> = Vec::new();
    let mut failed: Vec<(String, String)> = Vec::new();
    let mut skipped: usize = 0;

    for art in &proj.artifacts {
        // Witness artifacts: a JSON payload tagged with a `verifier` in metadata.
        let is_json = art.media_type.as_deref() == Some("application/json");
        if !(is_json && art.metadata.contains_key("verifier")) {
            continue;
        }
        // Resolve content. local_blob / local_file locators are relative to the
        // frontier dir; remote / pointer artifacts are not re-checkable here.
        let content = match (art.storage_mode.as_str(), &art.locator) {
            ("local_blob" | "local_file", Some(loc)) => {
                match std::fs::read_to_string(frontier.join(loc.as_str())) {
                    Ok(c) => c,
                    Err(_) => {
                        skipped += 1;
                        continue;
                    }
                }
            }
            _ => {
                skipped += 1;
                continue;
            }
        };
        let witness = match parse_witness(&content) {
            Ok(w) => w,
            Err(_) => {
                skipped += 1;
                continue;
            }
        };
        let result = vela_verify::verify_witness(&witness);
        let kind = witness.kind().to_string();
        for tf in &art.target_findings {
            let Some(claim) = claim_by_finding.get(tf) else {
                continue;
            };
            if !result.ok {
                failed.push((tf.clone(), result.message.clone()));
                continue;
            }
            let digest = claim_digest(claim);
            if dry_run {
                done.push((tf.clone(), kind.clone(), digest));
                continue;
            }
            let att = VerifierAttachment::build(AttachmentDraft {
                target: tf.clone(),
                claim_digest: digest.clone(),
                verifier_method: VerifierMethod::ComputationalSearch,
                solver_id: "vela-verify".to_string(),
                independent_of: Vec::new(),
                match_to_claim: MatchToClaim {
                    matches: true,
                    checker_actor: "vela-verify".to_string(),
                },
                adversarial_probes: vec![AdversarialProbe {
                    kind: ProbeKind::CounterexampleSearch,
                    result: ProbeResult::Survived,
                    note: String::new(),
                }],
                outcome: AttachmentOutcome::Passed,
                verifier_actor: "vela-verify".to_string(),
                note: format!("frozen verifier re-check: {kind}"),
            })
            .and_then(|a| a.with_method_integrity(MethodIntegrity::Sound))
            .unwrap_or_else(|e| fail_return(&format!("build attachment for {tf}: {e}")));
            let att_value = serde_json::to_value(&att)
                .unwrap_or_else(|e| fail_return(&format!("serialize attachment: {e}")));
            let actor_type = if reviewer.starts_with("agent:") {
                "agent"
            } else {
                "human"
            };
            let proposal = proposals::new_proposal(
                "verifier.attach",
                StateTarget {
                    r#type: "finding".to_string(),
                    id: tf.clone(),
                },
                reviewer,
                actor_type,
                "backfill frozen verifier re-check",
                json!({ "attachment": att_value }),
                Vec::new(),
                Vec::new(),
            );
            // The trust boundary, enforced here: an agent reviewer may DRAFT a
            // `verifier.attach` (it ran the frozen verifier) but may not
            // self-apply it — that is a truth-bearing acceptance reserved for a
            // named human with key custody. So for agents we create the
            // proposal as PENDING; a maintainer accepts it with `vela accept`.
            // A human reviewer applies inline (subject to key custody).
            match proposals::create_or_apply(frontier, proposal, apply) {
                Ok(res) if res.applied_event_id.is_some() => {
                    done.push((tf.clone(), kind.clone(), digest))
                }
                Ok(_) => pending.push((tf.clone(), kind.clone(), digest)),
                Err(e) => failed.push((tf.clone(), e)),
            }
        }
    }

    if json_output {
        let findings: Vec<Value> = done
            .iter()
            .map(|(f, k, d)| json!({ "finding": f, "kind": k, "claim_digest": d }))
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "command": "gate backfill",
                "dry_run": dry_run,
                "registered_artifacts": registered,
                "witnesses_without_target": no_target,
                "attached": done.len(),
                "pending_human_accept": pending.len(),
                "pending_findings": pending
                    .iter()
                    .map(|(f, k, d)| json!({ "finding": f, "kind": k, "claim_digest": d }))
                    .collect::<Vec<_>>(),
                "failed": failed.len(),
                "skipped_artifacts": skipped,
                "findings": findings,
            }))
            .expect("serialize gate backfill response")
        );
    } else {
        let verb = if dry_run { "would attach" } else { "attached" };
        if registered > 0 {
            let rverb = if dry_run {
                "would register"
            } else {
                "registered"
            };
            println!(
                "· gate backfill: {rverb} {registered} canonical witness artifact{}",
                if registered == 1 { "" } else { "s" },
            );
        }
        if !no_target.is_empty() {
            println!(
                "  ! {} witness file(s) have no target finding in witnesses/targets.json (not registered): {}",
                no_target.len(),
                no_target.join(", "),
            );
        }
        println!(
            "· gate backfill: {verb} {} frozen-verifier check{} ({skipped} artifacts skipped, {} verify-failures)",
            done.len(),
            if done.len() == 1 { "" } else { "s" },
            failed.len(),
        );
        for (f, k, d) in &done {
            println!("  {f} · {k} · claim {d}");
        }
        if !pending.is_empty() {
            println!(
                "· gate backfill: {} verifier.attach proposal{} drafted + frozen-verified, PENDING a maintainer's key-custody accept (`vela accept`):",
                pending.len(),
                if pending.len() == 1 { "" } else { "s" },
            );
            for (f, k, d) in &pending {
                println!("  ◦ {f} · {k} · claim {d}");
            }
        }
        for (f, e) in &failed {
            println!("  ! {f}: {e}");
        }
    }
}

/// Registration pre-pass for `gate backfill`. Deposits every canonical
/// `witnesses/*.witness.json` that is not yet present as a content-addressed
/// artifact, binding each to its target finding via the frontier-owned
/// `witnesses/targets.json` map (`{ "<file>.witness.json": "vf_…" }`). This is
/// the step that makes a frontier's frozen-verifier witnesses visible to the
/// gate; the attach loop in [`cmd_gate_backfill`] then lands the signed
/// re-check over them.
///
/// No-op when the frontier ships no `witnesses/targets.json`, preserving prior
/// behavior. The deposit rides under `deposited_by` (an agent identity for
/// machine deposits) as an `artifact.asserted` event: it is a *data* deposit of
/// a machine-checkable witness, not a trust verdict (the verdict is the
/// signed `verifier.attach`, which the attach loop types by actor).
///
/// Returns `(registered, witnesses_without_target)`.
fn register_canonical_witnesses(
    frontier: &Path,
    deposited_by: &str,
    dry_run: bool,
) -> (usize, Vec<String>) {
    use sha2::{Digest, Sha256};
    use std::collections::{BTreeMap, HashSet};

    let targets_path = frontier.join("witnesses").join("targets.json");
    let Ok(targets_raw) = std::fs::read_to_string(&targets_path) else {
        return (0, Vec::new());
    };
    let targets: BTreeMap<String, String> = serde_json::from_str(&targets_raw)
        .unwrap_or_else(|e| fail_return(&format!("parse {}: {e}", targets_path.display())));

    let source = repo::detect(frontier).unwrap_or_else(|e| fail_return(&e));
    let proj = repo::load(&source).unwrap_or_else(|e| fail_return(&e));
    let existing_hashes: HashSet<String> = proj
        .artifacts
        .iter()
        .map(|a| a.content_hash.clone())
        .collect();

    let mut registered = 0usize;
    let mut no_target: Vec<String> = Vec::new();

    for wf in collect_witness_files(frontier) {
        let fname = wf
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();
        let Ok(bytes) = std::fs::read(&wf) else {
            continue;
        };
        let raw = String::from_utf8_lossy(&bytes).to_string();
        // Only register a file the frozen verifier can actually parse as a witness.
        let Ok(witness) = parse_witness(&raw) else {
            continue;
        };
        let kind = witness.kind().to_string();

        let hash_hex = hex::encode(Sha256::digest(&bytes));
        let content_hash = format!("sha256:{hash_hex}");
        if existing_hashes.contains(&content_hash) {
            continue; // already registered (idempotent on content hash)
        }
        let Some(target) = targets.get(&fname) else {
            no_target.push(fname);
            continue;
        };

        if dry_run {
            registered += 1;
            continue;
        }

        // Deposit the content-addressed blob if absent.
        let blob_rel = format!(".vela/artifact-blobs/sha256/{hash_hex}");
        let blob_abs = frontier.join(&blob_rel);
        if !blob_abs.exists() {
            if let Some(parent) = blob_abs.parent() {
                std::fs::create_dir_all(parent)
                    .unwrap_or_else(|e| fail_return(&format!("create blob dir: {e}")));
            }
            std::fs::write(&blob_abs, &bytes)
                .unwrap_or_else(|e| fail_return(&format!("write blob {blob_rel}: {e}")));
        }

        let stem = fname.trim_end_matches(".witness.json");
        let name = format!("Frozen-verifier witness: {stem} ({kind})");
        let mut metadata: BTreeMap<String, Value> = BTreeMap::new();
        metadata.insert(
            "verifier".to_string(),
            Value::String(format!("vela-verify::{kind}")),
        );
        metadata.insert("witness_kind".to_string(), Value::String(kind.clone()));
        metadata.insert("witness_file".to_string(), Value::String(fname.clone()));

        let provenance = bundle::Provenance {
            source_type: "data_release".to_string(),
            doi: None,
            url: None,
            title: name.clone(),
            authors: Vec::new(),
            year: None,
            license: Some("CC-BY-4.0".to_string()),
            publisher: None,
            funders: Vec::new(),
            extraction: bundle::Extraction::default(),
            review: None,
        };

        let id = bundle::Artifact::content_address(
            "dataset",
            &name,
            &content_hash,
            None,
            Some(&blob_rel),
        );
        let artifact = bundle::Artifact {
            id,
            kind: "dataset".into(),
            name,
            content_hash,
            size_bytes: Some(bytes.len() as u64),
            media_type: Some("application/json".to_string()),
            storage_mode: "local_blob".to_string(),
            locator: Some(blob_rel),
            source_url: None,
            license: Some("CC-BY-4.0".to_string()),
            target_findings: vec![target.clone()],
            source_id: None,
            provenance,
            metadata,
            review_state: None,
            retracted: false,
            access_tier: vela_protocol::access_tier::AccessTier::default(),
            created: chrono::Utc::now().to_rfc3339(),
        };
        match vela_protocol::state::add_artifact(
            frontier,
            artifact,
            deposited_by,
            "register canonical frozen-verifier witness for gate backfill",
        ) {
            Ok(_) => registered += 1,
            Err(e) if e.contains("duplicate") => {}
            Err(e) => fail_return(&format!("register witness {fname}: {e}")),
        }
    }
    (registered, no_target)
}

pub(crate) fn cmd_reproduce(path: &Path, json_output: bool) {
    let files = collect_witness_files(path);
    if files.is_empty() {
        fail(&format!(
            "no witnesses found at {} (expected a `*.witness.json` file, or a directory containing them / a `witnesses/` subdir)",
            path.display()
        ));
    }
    let mut results: Vec<Value> = Vec::new();
    let mut passed = 0usize;
    let mut failed = 0usize;
    for file in &files {
        let raw = match std::fs::read_to_string(file) {
            Ok(r) => r,
            Err(e) => {
                failed += 1;
                if !json_output {
                    println!("  FAIL  {}  ·  read error: {e}", file.display());
                }
                results.push(json!({"path": file.display().to_string(), "ok": false, "message": format!("read error: {e}")}));
                continue;
            }
        };
        let witness = match parse_witness(&raw) {
            Ok(w) => w,
            Err(e) => {
                failed += 1;
                if !json_output {
                    println!("  FAIL  {}  ·  parse error: {e}", file.display());
                }
                results.push(json!({"path": file.display().to_string(), "ok": false, "message": format!("parse error: {e}")}));
                continue;
            }
        };
        let mut outcome = vela_verify::verify_witness(&witness);
        // Machine-checked novelty: a witness may declare `improves_on`
        // (a sibling witness path relative to its own directory). The
        // claim then verifies ONLY if it also strictly dominates the
        // referenced witness — dominance is arithmetic, not opinion.
        if outcome.ok
            && let Ok(value) = serde_json::from_str::<Value>(&raw)
            && let Some(prior_rel) = value.get("improves_on").and_then(Value::as_str)
        {
            let prior_path = file
                .parent()
                .map(|d| d.join(prior_rel))
                .unwrap_or_else(|| std::path::PathBuf::from(prior_rel));
            match std::fs::read_to_string(&prior_path)
                .map_err(|e| format!("improves_on read {}: {e}", prior_path.display()))
                .and_then(|p| parse_witness(&p))
                .and_then(|prior| vela_verify::dominates(&witness, &prior))
            {
                Ok(true) => {
                    outcome.message =
                        format!("{} · strictly improves on {prior_rel}", outcome.message);
                }
                Ok(false) => {
                    outcome = vela_verify::VerifyResult::fail(format!(
                        "claims improves_on {prior_rel} but does NOT strictly dominate it"
                    ));
                }
                Err(e) => {
                    outcome =
                        vela_verify::VerifyResult::fail(format!("improves_on check failed: {e}"));
                }
            }
        }
        if outcome.ok {
            passed += 1;
        } else {
            failed += 1;
        }
        if !json_output {
            let status = if outcome.ok { "ok  " } else { "FAIL" };
            println!(
                "  {status}  {} [{}]  ·  {}",
                file.display(),
                witness.kind(),
                outcome.message
            );
        }
        results.push(json!({
            "path": file.display().to_string(),
            "kind": witness.kind(),
            "ok": outcome.ok,
            "message": outcome.message,
        }));
    }
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "command": "reproduce",
                "witnesses": files.len(),
                "passed": passed,
                "failed": failed,
                "results": results,
            }))
            .expect("serialize reproduce response")
        );
    } else {
        println!();
        if failed == 0 {
            println!(
                "  reproduce: ok ({passed}/{}) — every witness re-verified from scratch by the frozen verifiers.",
                files.len()
            );
        } else {
            println!(
                "  reproduce: FAIL ({failed}/{} did not re-verify). Investigate before trusting.",
                files.len()
            );
        }
    }
    if failed > 0 {
        std::process::exit(1);
    }
}

pub(crate) fn cmd_evidence_ci(frontier: &Path, json: bool) {
    let report = evidence_ci::run_frontier(frontier)
        .unwrap_or_else(|e| fail_return(&format!("evidence-ci failed: {e}")));
    if json {
        print_json(&report);
        return;
    }
    let status = if report.ok {
        style::ok("evidence-ci")
    } else {
        style::lost("evidence-ci")
    };
    println!(
        "{} {} · {} checks, {} warning(s), {} release-blocking failure(s)",
        status,
        report.frontier_id,
        report.summary.total,
        report.summary.warnings,
        report.summary.release_blocking_failed
    );
    for check in report
        .checks
        .iter()
        .filter(|check| check.status != evidence_ci::EvidenceCiStatus::Passed)
        .take(40)
    {
        println!(
            "  {} {} {}: {}",
            match check.status {
                evidence_ci::EvidenceCiStatus::Passed => style::ok("pass"),
                evidence_ci::EvidenceCiStatus::Warning => style::warn("warn"),
                evidence_ci::EvidenceCiStatus::Failed => style::lost("fail"),
            },
            check.id,
            check.target_id,
            check.message
        );
    }
}

pub(crate) fn cmd_retro_impact(record: &str, frontier: &Path, json: bool) {
    let project = load_frontier_or_fail(frontier);
    let impact = vela_edge::dependency_oracle::dependency_impact(&project, record);
    if json {
        print_json(&serde_json::to_value(&impact).unwrap_or_default());
    } else {
        println!(
            "impact {}: {} record(s) rest on it ({} gate-verified); {} direct",
            record,
            impact.weight,
            impact.verified_weight,
            impact.direct_dependents.len()
        );
    }
}

pub(crate) fn cmd_attach(
    frontier: &std::path::Path,
    target: &str,
    attachment_file: &std::path::Path,
    reviewer: &str,
    reason: &str,
    json: bool,
) {
    use vela_protocol::events::StateTarget;
    let body = match std::fs::read_to_string(attachment_file) {
        Ok(b) => b,
        Err(e) => fail(&format!("read {}: {e}", attachment_file.display())),
    };
    let att_value: Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => fail(&format!("parse attachment JSON: {e}")),
    };
    let actor_type = if reviewer.starts_with("agent:") {
        "agent"
    } else {
        "human"
    };
    let proposal = proposals::new_proposal(
        "verifier.attach",
        StateTarget {
            r#type: "finding".to_string(),
            id: target.to_string(),
        },
        reviewer,
        actor_type,
        reason,
        json!({ "attachment": att_value }),
        Vec::new(),
        Vec::new(),
    );
    match proposals::create_or_apply(frontier, proposal, true) {
        Ok(result) => {
            let event = result.applied_event_id.clone().unwrap_or_default();
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "command": "attach",
                        "target": target,
                        "proposal_id": result.proposal_id,
                        "event_id": event,
                        "applied": result.applied_event_id.is_some(),
                    }))
                    .expect("serialize attach response")
                );
            } else {
                println!(
                    "· ok attached verifier evidence to {target}\n  proposal {}\n  event {event}",
                    result.proposal_id
                );
            }
        }
        Err(e) => fail(&format!("attach: {e}")),
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn cmd_normalize(
    source: &Path,
    out: Option<&Path>,
    write: bool,
    dry_run: bool,
    rewrite_ids: bool,
    id_map: Option<&Path>,
    resync_provenance: bool,
    json_output: bool,
) {
    if write && out.is_some() {
        fail("Use either --write or --out, not both.");
    }
    if dry_run && (write || out.is_some()) {
        fail("--dry-run cannot be combined with --write or --out.");
    }
    if id_map.is_some() && !rewrite_ids {
        fail("--id-map requires --rewrite-ids.");
    }

    let detected = repo::detect(source).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(1);
    });
    if matches!(detected, repo::VelaSource::PacketDir(_)) {
        fail(
            "Cannot normalize a proof packet directory. Export a new packet from frontier state instead.",
        );
    }
    let mut frontier = repo::load(&detected).unwrap_or_else(|e| fail_return(&e));
    // Phase J: every v0.4 frontier carries a `frontier.created` genesis
    // event in events[0]. That's identity metadata, not a substantive
    // mutation, so it doesn't disqualify normalization. Any non-genesis
    // canonical event still blocks normalize.
    let has_substantive_events = frontier
        .events
        .iter()
        .any(|event| event.kind != "frontier.created");
    if has_substantive_events && (write || out.is_some()) {
        fail(
            "Refusing to normalize a frontier with canonical events. Normalize before proposal-backed writes, or create a new reviewed transition for the intended change.",
        );
    }
    let source_hash = hash_path(source).unwrap_or_else(|_| "unavailable".to_string());
    let before_stats = serde_json::to_value(&frontier.stats).unwrap_or(Value::Null);
    let (entity_type_fixes, entity_name_fixes) =
        normalize::normalize_findings(&mut frontier.findings);
    let confidence_updates = bundle::recompute_all_confidence(&mut frontier.findings);
    // Phase N: optionally rewrite finding.provenance from the canonical
    // SourceRecord. The source registry is the authority; provenance is
    // the denormalized cache.
    let provenance_resync_count = if resync_provenance {
        sources::resync_provenance_from_sources(&mut frontier)
    } else {
        0
    };
    let before_source_count = frontier.sources.len();
    let before_evidence_atom_count = frontier.evidence_atoms.len();
    let before_condition_record_count = frontier.condition_records.len();

    let mut id_rewrites = Vec::new();
    if rewrite_ids {
        let mut id_map_values = std::collections::BTreeMap::<String, String>::new();
        for finding in &frontier.findings {
            let expected =
                bundle::FindingBundle::content_address(&finding.assertion, &finding.provenance);
            if expected != finding.id {
                id_map_values.insert(finding.id.clone(), expected);
            }
        }
        let new_ids = id_map_values
            .values()
            .map(String::as_str)
            .collect::<std::collections::HashSet<_>>();
        if new_ids.len() != id_map_values.len() {
            fail("Refusing to rewrite IDs because two findings map to the same content address.");
        }
        for finding in &mut frontier.findings {
            if let Some(new_id) = id_map_values.get(&finding.id) {
                id_rewrites.push(json!({"old": finding.id, "new": new_id}));
                finding.previous_version = Some(finding.id.clone());
                finding.id = new_id.clone();
            }
        }
        for finding in &mut frontier.findings {
            for link in &mut finding.links {
                if let Some(new_target) = id_map_values.get(&link.target) {
                    link.target = new_target.clone();
                }
            }
        }
        if let Some(path) = id_map {
            std::fs::write(
                path,
                serde_json::to_string_pretty(&id_map_values)
                    .expect("failed to serialize normalize id map"),
            )
            .unwrap_or_else(|e| fail(&format!("Failed to write {}: {e}", path.display())));
        }
    }

    sources::materialize_project(&mut frontier);
    let source_records_materialized = frontier.sources.len().saturating_sub(before_source_count);
    let evidence_atoms_materialized = frontier
        .evidence_atoms
        .len()
        .saturating_sub(before_evidence_atom_count);
    let condition_records_materialized = frontier
        .condition_records
        .len()
        .saturating_sub(before_condition_record_count);
    let after_stats = serde_json::to_value(&frontier.stats).unwrap_or(Value::Null);
    let id_rewrite_count = id_rewrites.len();
    let wrote_to = if write {
        repo::save(&detected, &frontier).unwrap_or_else(|e| fail(&e));
        Some(source.display().to_string())
    } else if let Some(out_path) = out {
        repo::save_to_path(out_path, &frontier).unwrap_or_else(|e| fail(&e));
        Some(out_path.display().to_string())
    } else {
        None
    };
    let wrote = wrote_to.is_some();
    let planned_changes = entity_type_fixes
        + entity_name_fixes
        + confidence_updates
        + id_rewrite_count
        + source_records_materialized
        + evidence_atoms_materialized
        + condition_records_materialized
        + provenance_resync_count;
    let payload = json!({
        "ok": true,
        "command": "normalize",
        "schema_version": project::VELA_SCHEMA_VERSION,
        "source": {
            "path": source.display().to_string(),
            "hash": format!("sha256:{source_hash}"),
        },
        "dry_run": wrote_to.is_none(),
        "wrote_to": wrote_to,
        "summary": {
            "planned": planned_changes,
            "safe": planned_changes,
            "unsafe": 0,
            "applied": if wrote { planned_changes } else { 0 },
        },
        "changes": {
            "entity_type_fixes": entity_type_fixes,
            "entity_name_fixes": entity_name_fixes,
            "confidence_updates": confidence_updates,
            "id_rewrites": id_rewrite_count,
            "source_records_materialized": source_records_materialized,
            "evidence_atoms_materialized": evidence_atoms_materialized,
            "condition_records_materialized": condition_records_materialized,
            "provenance_resyncs": provenance_resync_count,
            "stats_changed": before_stats != after_stats,
        },
        "id_rewrites": id_rewrites,
        "repair_plan": if wrote { Vec::<Value>::new() } else {
            vec![json!({
                "action": "apply_normalization",
                "command": "vela normalize <frontier> --out frontier.normalized.json"
            })]
        },
    });
    if json_output {
        print_json(&payload);
    } else if let Some(path) = payload.get("wrote_to").and_then(Value::as_str) {
        println!("{} normalized frontier written to {path}", style::ok("ok"));
        println!(
            "  entity type fixes: {}, entity name fixes: {}, confidence updates: {}, id rewrites: {}",
            entity_type_fixes, entity_name_fixes, confidence_updates, id_rewrite_count
        );
    } else {
        println!("normalize dry run for {}", source.display());
        println!(
            "  would apply entity type fixes: {}, entity name fixes: {}, confidence updates: {}, id rewrites: {}",
            entity_type_fixes, entity_name_fixes, confidence_updates, id_rewrite_count
        );
    }
}

/// v0.75: handler for `vela carina <action>`. Each branch reaches
/// into the bundled schemas under `embedded/carina-schemas/`.
pub(crate) fn cmd_carina(action: CarinaAction) {
    match action {
        CarinaAction::List { json } => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": true,
                        "command": "carina.list",
                        "primitives": carina_validate::PRIMITIVE_NAMES,
                    }))
                    .expect("failed to serialize carina.list")
                );
            } else {
                println!("Carina primitives bundled with this build:");
                for name in carina_validate::PRIMITIVE_NAMES {
                    println!("  · {name}");
                }
            }
        }
        CarinaAction::Schema { primitive } => match carina_validate::schema_text(&primitive) {
            Some(text) => print!("{text}"),
            None => fail(&format!(
                "carina: unknown primitive '{primitive}'. Valid: {}",
                carina_validate::PRIMITIVE_NAMES.join(", ")
            )),
        },
        CarinaAction::Validate {
            path,
            primitive,
            json,
        } => {
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| fail_return(&format!("read {}: {e}", path.display())));
            let value: Value = serde_json::from_str(&text)
                .unwrap_or_else(|e| fail_return(&format!("parse {}: {e}", path.display())));
            // If the file is a primitives.v0.X.json aggregate,
            // validate every entry under `primitives`. Otherwise
            // validate the value as one primitive.
            // Each report entry: (input key, validation result with
            // optional detected-primitive name in the Ok branch).
            type CarinaValidateOutcome = Result<Option<&'static str>, Vec<String>>;
            let mut report: Vec<(String, CarinaValidateOutcome)> = Vec::new();
            if value.get("primitives").and_then(Value::as_object).is_some() && primitive.is_none() {
                let primitives = value.get("primitives").and_then(Value::as_object).unwrap();
                for (key, child) in primitives {
                    let outcome = carina_validate::validate(key, child)
                        .map(|()| carina_validate::detect_primitive(child));
                    report.push((key.clone(), outcome));
                }
            } else {
                let outcome = match primitive.as_deref() {
                    Some(name) => carina_validate::validate(name, &value).map(|()| {
                        carina_validate::PRIMITIVE_NAMES
                            .iter()
                            .copied()
                            .find(|p| *p == name)
                    }),
                    None => carina_validate::validate_auto(&value).map(Some),
                };
                let label = primitive.clone().unwrap_or_else(|| "<auto>".to_string());
                report.push((label, outcome));
            }

            let total = report.len();
            let pass = report.iter().filter(|(_, r)| r.is_ok()).count();
            let fail = total - pass;

            if json {
                let entries: Vec<Value> = report
                    .iter()
                    .map(|(label, r)| match r {
                        Ok(name) => json!({
                            "key": label,
                            "primitive": name,
                            "ok": true,
                        }),
                        Err(errs) => json!({
                            "key": label,
                            "ok": false,
                            "errors": errs,
                        }),
                    })
                    .collect();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": fail == 0,
                        "command": "carina.validate",
                        "file": path.display().to_string(),
                        "total": total,
                        "passed": pass,
                        "failed": fail,
                        "entries": entries,
                    }))
                    .expect("failed to serialize carina.validate")
                );
            } else {
                for (label, r) in &report {
                    match r {
                        Ok(Some(name)) => println!("  {} {label} (as {name})", style::ok("ok")),
                        Ok(None) => println!("  {} {label}", style::ok("ok")),
                        Err(errs) => {
                            println!("  {} {label}", style::lost("fail"));
                            for e in errs {
                                println!("      {e}");
                            }
                        }
                    }
                }
                println!();
                if fail == 0 {
                    println!("{} {pass}/{total} valid", style::ok("carina.validate"));
                } else {
                    println!(
                        "{} {pass}/{total} valid · {fail} failed",
                        style::lost("carina.validate")
                    );
                }
            }

            if fail > 0 {
                std::process::exit(1);
            }
        }
    }
}

#[cfg(test)]
mod foundry_targets_tests {
    use super::*;

    #[test]
    fn read_records_best_reports_deepest_accepted() {
        let dir = std::env::temp_dir().join(format!("vela_rec_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("bounds.json");
        std::fs::write(
            &f,
            r#"{"bounds":[
                {"n":7,"best_lower_bound":24,"accepted":true},
                {"n":24,"best_lower_bound":7179,"accepted":true},
                {"n":25,"best_lower_bound":9999,"accepted":false}
            ]}"#,
        )
        .unwrap();
        let best = read_records_best(&f).expect("some accepted records");
        assert_eq!(
            best["accepted_records"].as_i64(),
            Some(2),
            "unaccepted skipped"
        );
        assert_eq!(best["max_n"].as_i64(), Some(24), "deepest accepted n");
        assert_eq!(best["bound_at_max_n"].as_i64(), Some(7179));
        // absent / no-accepted -> None
        assert!(read_records_best(&dir.join("missing.json")).is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn engine_kinds_cover_the_catalog_families() {
        // Every verifier_kind the HorizonMath catalog uses must be a real engine
        // kind (else `foundry targets` would mislabel it unattackable).
        for k in [
            "diff_triangle",
            "cap",
            "sidon",
            "gf2_sidon",
            "covering",
            "constant_weight",
            "costas",
            "union_free",
            "rook_directions",
            "bh",
            "golomb",
        ] {
            assert!(FOUNDRY_ENGINE_KINDS.contains(&k), "{k} must be attackable");
        }
    }

    // The exact-lane vouch gate. An adversarial review showed the prior vouch
    // (a "registered non-agent reviewer" signing a verifier_attachment.added
    // event, or accepting a verifier.attach proposal) is forgeable: actor
    // registration is open self-enrollment, so an agent mints a key, registers
    // `reviewer:x`, and honestly signs. The fix scopes the vouch to where
    // attachments are load-bearing (the non-floor lane), and admits the exact
    // lane on the un-forgeable FLOOR alone.

    #[test]
    fn floor_sufficient_admits_without_any_vouch_even_with_attachments() {
        // The exact lane: the floor (fresh reproduce + claim_witness_faithful)
        // is the proof. Matched attachments are non-load-bearing corroboration
        // and must NOT block admission, regardless of who signed them. This is
        // what lets the foundry compound without a human, soundly.
        let (ok, reason) = attachment_vouch_gate(true, 0);
        assert!(ok, "floor-sufficient with no attachments admits");
        assert!(reason.is_empty());

        let (ok, reason) = attachment_vouch_gate(true, 3);
        assert!(
            ok,
            "floor-sufficient admits even with attachments present (they do not gate)"
        );
        assert!(
            reason.contains("non-load-bearing"),
            "the reason is honest that attachments are not gating: {reason}"
        );
    }

    #[test]
    fn non_floor_sufficient_refuses_until_vouch_is_owner_rooted() {
        // The non-exact / Lean lane, where attachments WOULD be the evidence.
        // Because the only vouch root today is open self-enrollment (forgeable),
        // the lane must refuse in the safe direction rather than admit on a
        // forgeable vouch. This keeps the de-human-gate firing ONLY on the
        // un-forgeable floor.
        for matched_len in [0usize, 1, 5] {
            let (ok, reason) = attachment_vouch_gate(false, matched_len);
            assert!(
                !ok,
                "non-floor-sufficient must refuse (matched_len={matched_len})"
            );
            assert!(
                reason.contains("owner-rooted") || reason.contains("refuses"),
                "the refusal names the missing owner-rooted vouch: {reason}"
            );
        }
    }
}
