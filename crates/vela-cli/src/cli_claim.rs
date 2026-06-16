//! Read-side claim projections: `vela claim {state,trust,pack,diff}`, plus the
//! math-atlas anchor verbs `vela claim {anchor,anchors,unanchor}` (`run_anchor`).
//! The projections never write; `anchor`/`unanchor` are the one write pair here
//! (signed `anchor.attached`/`anchor.retracted` events), kept in their own
//! entrypoint so the projection contract stays pure.
//!
//! These are DERIVED projections over the accepted event log — they
//! never write, never store, and mint no new event kinds. Each loads the
//! repo (`repo::load_from_path`) and recomputes a view from objects the
//! reducer already produced:
//!
//!   - `state`  — the Claim-State Cell (frontier_calculus §4.2 /
//!     STATE_PLANE_MEMO §7.1): claim, context, Belnap-style status,
//!     supersession, dependencies, open obligations, priority. The core
//!     derivation lives in `vela_protocol::evidence_diff::state_cell` so
//!     the hub computes the identical cell.
//!   - `trust`  — the Trust Vector (§7 / §7.2) as a projection over
//!     EXISTING objects. Absent fields render `"absent"`, never invented.
//!   - `pack`   — state + trust + the exact reproduce command + the
//!     event ids that touch the claim: a citable claim pack.
//!   - `diff`   — the Evidence Diff: a proposal's before/after effect on
//!     the target claim plus the downstream claims whose status flips,
//!     from `vela_protocol::evidence_diff::claim_state_delta`, with the
//!     Engine verdict merged in (the CLI holds the frontier path).
//!
//! Dispatched by an intercept in `cli.rs::run_from_args` (mirroring the
//! `proof verify` / atlas-r2 read-only intercepts) so the projections
//! sit ahead of the clap dispatcher and never collide with the existing
//! `vela claim <frontier> <obligation>` lease command.

use std::path::Path;

use serde_json::{Value, json};
use vela_protocol::bundle::FindingBundle;
use vela_protocol::events::actor_kind;
use vela_protocol::evidence_diff::{
    claim_state_delta, find_priority_registration, matched_attachments, state_cell,
};
use vela_protocol::project::Project;
use vela_protocol::repo;
use vela_protocol::verifier_attachment::{AttachmentOutcome, claim_digest, derive_gate_status};

use crate::cli::{fail, print_json};

/// Entry point from the `cli.rs::run_from_args` intercept. `args` is the
/// full `std::env::args()` vector; `args[2]` is the verb
/// (`state`/`trust`/`pack`/`diff`), `args[3]` the frontier, `args[4]` the
/// `vf_…` id (or, for `diff`, the `vpr_…` proposal id).
pub(crate) fn run(args: &[String]) {
    let verb = args.get(2).map(String::as_str).unwrap_or("");
    let json = args.iter().any(|a| a == "--json");
    // Positional operands: the first two non-flag tokens after the verb.
    let positionals: Vec<&str> = args
        .iter()
        .skip(3)
        .filter(|a| !a.starts_with('-'))
        .map(String::as_str)
        .collect();

    // The `diff` projection takes a proposal id (vpr_…), not a finding id,
    // and renders the Evidence Diff.
    if verb == "diff" {
        let frontier = positionals
            .first()
            .copied()
            .unwrap_or_else(|| fail("usage: vela claim diff <frontier> <proposal_id> [--json]"));
        let proposal_id = positionals
            .get(1)
            .copied()
            .unwrap_or_else(|| fail("usage: vela claim diff <frontier> <proposal_id> [--json]"));
        let delta = derive_evidence_diff(Path::new(frontier), proposal_id);
        if json {
            print_json(&delta);
        } else {
            print_diff_human(&delta);
        }
        return;
    }

    let frontier = positionals.first().copied().unwrap_or_else(|| {
        fail(&format!(
            "usage: vela claim {verb} <frontier> <vf_id> [--json]"
        ))
    });
    let vf_id = positionals.get(1).copied().unwrap_or_else(|| {
        fail(&format!(
            "usage: vela claim {verb} <frontier> <vf_id> [--json]"
        ))
    });

    let project = repo::load_from_path(Path::new(frontier)).unwrap_or_else(|e| fail(&e));
    let finding = project
        .findings
        .iter()
        .find(|f| f.id == vf_id)
        .unwrap_or_else(|| fail(&format!("finding {vf_id} not found in {frontier}")));

    match verb {
        "state" => {
            let mut cell = state_cell(&project, finding);
            // Graft the claim's math-atlas anchor links (read-only): the
            // external-catalogue coordinates this claim carries.
            let anchors: Vec<_> = project
                .anchor_links
                .iter()
                .filter(|l| l.target == vf_id)
                .collect();
            if !anchors.is_empty() {
                cell["anchors"] = serde_json::to_value(&anchors).unwrap_or_else(|_| json!([]));
            }
            if json {
                print_json(&cell);
            } else {
                print_state_human(&cell);
            }
        }
        "trust" => {
            let vector = derive_trust_vector(&project, finding);
            if json {
                print_json(&vector);
            } else {
                print_trust_human(&vector);
            }
        }
        "pack" => {
            let pack = derive_pack(&project, finding, frontier);
            // The pack is a citable JSON object; the default render is
            // also JSON so a copy-paste is byte-faithful.
            print_json(&pack);
        }
        other => fail(&format!("unknown claim projection '{other}'")),
    }
}

/// `vela claim anchor|anchors|unanchor` — the math-atlas anchor-link verbs.
///
/// `anchor` attaches a signed `val_` (an external-catalogue anchor: OEIS,
/// Erdős, mathlib, arXiv, MSC) to a claim; `unanchor` retracts one by id;
/// `anchors` lists. The two writes emit `anchor.attached` / `anchor.retracted`
/// events (loader = reducer); this is the un-deferral of frontier-calculus
/// Law 22 (claim-identity is a signed, retractable event, never a silent
/// reducer input).
pub(crate) fn run_anchor(args: &[String]) {
    use vela_protocol::anchor::{Anchor, AnchorKind, AnchorLink, AnchorLinkDraft, JoinPolicy};
    let verb = args.get(2).map(String::as_str).unwrap_or("");
    let json = args.iter().any(|a| a == "--json");
    let positionals: Vec<&str> = args
        .iter()
        .skip(3)
        .filter(|a| !a.starts_with('-'))
        .map(String::as_str)
        .collect();
    let flag = |name: &str| -> Option<String> {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .map(|s| s.to_string())
    };

    let frontier = positionals.first().copied().unwrap_or_else(|| {
        fail("usage: vela claim anchor <frontier> <vf_id> --ns <ns> --id <id> --role <role>")
    });

    // ── anchors: read-only list ──
    if verb == "anchors" {
        let project = repo::load_from_path(Path::new(frontier)).unwrap_or_else(|e| fail(&e));
        let target = positionals.get(1).copied();
        let links: Vec<&AnchorLink> = project
            .anchor_links
            .iter()
            .filter(|l| target.is_none_or(|t| l.target == t))
            .collect();
        if json {
            print_json(&serde_json::to_value(&links).unwrap_or_else(|_| json!([])));
        } else if links.is_empty() {
            println!(
                "no anchor links{}",
                target.map(|t| format!(" on {t}")).unwrap_or_default()
            );
        } else {
            for l in &links {
                println!(
                    "{}  {}  {}:{} #{}  ({:?})",
                    l.id,
                    l.target,
                    l.anchor.namespace,
                    l.anchor.id,
                    l.anchor.role,
                    l.anchor.join_policy
                );
            }
        }
        return;
    }

    // ── unanchor: retract a link by id ──
    if verb == "unanchor" {
        let val_id = positionals
            .get(1)
            .copied()
            .unwrap_or_else(|| fail("usage: vela claim unanchor <frontier> <val_id>"));
        let by = crate::cli_identity::resolve_actor(flag("--reviewer").as_deref());
        let mut project = repo::load_from_path(Path::new(frontier)).unwrap_or_else(|e| fail(&e));
        let target = project
            .anchor_links
            .iter()
            .find(|l| l.id == val_id)
            .map(|l| l.target.clone())
            .unwrap_or_else(|| fail(&format!("anchor link {val_id} not found in {frontier}")));
        let event =
            vela_protocol::events::new_finding_event(vela_protocol::events::FindingEventInput {
                kind: "anchor.retracted",
                finding_id: &target,
                actor_id: &by,
                actor_type: actor_kind(&by),
                reason: "anchor link retracted",
                before_hash: "sha256:null",
                after_hash: "sha256:null",
                payload: json!({ "anchor_link_id": val_id }),
                caveats: Vec::new(),
                timestamp: None,
            });
        vela_protocol::reducer::apply_event(&mut project, &event).unwrap_or_else(|e| fail(&e));
        project.events.push(event);
        repo::save_to_path(Path::new(frontier), &project).unwrap_or_else(|e| fail(&e));
        if json {
            print_json(&json!({"ok": true, "command": "unanchor", "anchor_link_id": val_id}));
        } else {
            println!("ok anchor link {val_id} retracted from {target}");
        }
        return;
    }

    // ── anchor: attach a signed external-catalogue anchor ──
    let vf_id = positionals.get(1).copied().unwrap_or_else(|| {
        fail("usage: vela claim anchor <frontier> <vf_id> --ns <ns> --id <id> --role <role>")
    });
    let ns = flag("--ns")
        .or_else(|| flag("--namespace"))
        .unwrap_or_else(|| fail("--ns is required (oeis|erdos|mathlib|arxiv|msc|dblp)"));
    let ext_id =
        flag("--id").unwrap_or_else(|| fail("--id is required (the external id, e.g. A309370)"));
    let role =
        flag("--role").unwrap_or_else(|| fail("--role is required (e.g. \"lower-bound a(n)\")"));

    // Default kind + join policy by namespace; --kind / --join override.
    // MSC/arXiv/DBLP/DOI are search affordances, never identity (the spec's
    // JoinPolicy gate); OEIS/Erdős/mathlib may induce identity.
    let kind = match flag("--kind").as_deref() {
        None => match ns.as_str() {
            "oeis" => AnchorKind::Sequence,
            "erdos" => AnchorKind::ProblemEntry,
            "mathlib" => AnchorKind::FormalDeclaration,
            "arxiv" => AnchorKind::Work,
            "msc" => AnchorKind::Taxonomy,
            _ => AnchorKind::Statement,
        },
        Some("statement") => AnchorKind::Statement,
        Some("formal_declaration") | Some("decl") => AnchorKind::FormalDeclaration,
        Some("object") | Some("mathematical_object") => AnchorKind::MathematicalObject,
        Some("problem") | Some("problem_entry") => AnchorKind::ProblemEntry,
        Some("work") => AnchorKind::Work,
        Some("taxonomy") => AnchorKind::Taxonomy,
        Some("sequence") => AnchorKind::Sequence,
        Some("dataset") => AnchorKind::Dataset,
        Some(o) => fail(&format!("unknown --kind '{o}'")),
    };
    let join_policy = match flag("--join").as_deref() {
        None => match ns.as_str() {
            "msc" | "arxiv" | "dblp" | "doi" => JoinPolicy::SearchOnly,
            _ => JoinPolicy::HardIdentity,
        },
        Some("hard") | Some("hard_identity") => JoinPolicy::HardIdentity,
        Some("soft") | Some("soft_candidate") => JoinPolicy::SoftCandidate,
        Some("search") | Some("search_only") => JoinPolicy::SearchOnly,
        Some(o) => fail(&format!("unknown --join '{o}' (hard|soft|search)")),
    };

    let by = crate::cli_identity::resolve_actor(flag("--reviewer").as_deref());
    let signing_key =
        crate::cli_identity::resolve_signing_key(flag("--key").as_deref().map(Path::new));
    let mut project = repo::load_from_path(Path::new(frontier)).unwrap_or_else(|e| fail(&e));
    if !project.findings.iter().any(|f| f.id == vf_id) {
        fail(&format!("target finding {vf_id} not found in {frontier}"));
    }

    let link = AnchorLink::build(
        AnchorLinkDraft {
            target: vf_id.to_string(),
            anchor: Anchor {
                namespace: ns.clone(),
                id: ext_id.clone(),
                role: role.clone(),
                kind,
                join_policy,
                namespace_version: flag("--namespace-version"),
                source_revision: flag("--source-revision"),
                statement_fingerprint: flag("--statement-fingerprint"),
            },
            attached_by: by.clone(),
            attached_at: chrono::Utc::now().to_rfc3339(),
        },
        &signing_key,
    )
    .unwrap_or_else(|e| fail(&e));

    let event =
        vela_protocol::events::new_finding_event(vela_protocol::events::FindingEventInput {
            kind: "anchor.attached",
            finding_id: vf_id,
            actor_id: &by,
            actor_type: actor_kind(&by),
            reason: "external-catalogue anchor attached",
            before_hash: "sha256:null",
            after_hash: "sha256:null",
            payload: json!({ "anchor_link": link }),
            caveats: Vec::new(),
            timestamp: None,
        });
    vela_protocol::reducer::apply_event(&mut project, &event).unwrap_or_else(|e| fail(&e));
    project.events.push(event);
    repo::save_to_path(Path::new(frontier), &project).unwrap_or_else(|e| fail(&e));

    if json {
        print_json(&json!({
            "ok": true,
            "command": "anchor",
            "anchor_link_id": link.id,
            "target": vf_id,
            "anchor": { "namespace": ns, "id": ext_id, "role": role },
        }));
    } else {
        println!(
            "ok anchor {} ({ns}:{ext_id} #{role}) attached to {vf_id}",
            link.id
        );
    }
}

/// Compute the Evidence Diff for a proposal and merge in the Engine
/// verdict. `claim_state_delta` is path-free (before/after/downstream);
/// the CLI holds the frontier path, so it can additionally run
/// `preview_engine_verdict` ("what would CI say if accepted?") and graft
/// the result over the placeholder `engine` field.
fn derive_evidence_diff(path: &Path, proposal_id: &str) -> Value {
    let project = repo::load_from_path(path).unwrap_or_else(|e| fail(&e));
    let mut delta = claim_state_delta(&project, proposal_id, "reviewer:evidence-diff-preview")
        .unwrap_or_else(|e| fail(&e));
    // Best-effort engine verdict; a hiccup here must never break the diff.
    if let Ok(verdict) = vela_protocol::proposals::preview_engine_verdict(path, proposal_id) {
        delta["engine"] = json!({
            "available": true,
            "status": verdict.status,
            "new_blocking": verdict.new_blocking,
            "new_warnings": verdict.new_warnings,
            "release_blocking_failed": verdict.release_blocking_failed,
            "warnings": verdict.warnings,
        });
    }
    delta
}

/// Derive the Trust Vector as a projection over EXISTING objects.
/// Scoped to the seven fields the substrate can answer from accepted
/// state; absent fields render `"absent"`, never invented. (§7 / §7.2.)
fn derive_trust_vector(project: &Project, finding: &FindingBundle) -> Value {
    let id = finding.id.as_str();
    let digest = claim_digest(&finding.assertion.text);
    let atts = matched_attachments(project, finding);
    let gate = derive_gate_status(&digest, &atts);

    // log_integrity: whole-log replay verification (frontier-scoped).
    let replay = vela_protocol::reducer::verify_replay(project);
    let log_integrity = json!({
        "result": if replay.ok { "pass" } else { "fail" },
        "note": replay.note,
    });

    // artifact_replay: the outcome of THIS claim's verifier attachments
    // (witness / proof re-checks). Absent when nothing is attached.
    let artifact_replay = if atts.is_empty() {
        Value::String("absent".into())
    } else {
        let passed = atts
            .iter()
            .filter(|a| a.outcome == AttachmentOutcome::Passed)
            .count();
        let failed = atts.len() - passed;
        json!({
            "attachments": atts.len(),
            "passed": passed,
            "failed": failed,
            "methods": atts
                .iter()
                .map(|a| a.verifier_method.as_str())
                .collect::<Vec<_>>(),
        })
    };

    // verifier_gate: the derived G1–G4 gate status (never stored).
    let verifier_gate = json!({
        "status": format!("{:?}", gate.status),
        "reasons": gate.reasons,
    });

    // statement_faithfulness: a vsa_ verdict targeting this finding.
    let statement_faithfulness = project
        .statement_attestations
        .iter()
        .filter(|a| a.target == id)
        .max_by(|a, b| a.attested_at.cmp(&b.attested_at))
        .map(|a| {
            json!({
                "verdict": format!("{:?}", a.verdict),
                "attested_by": a.attested_by,
                "informal_ref": a.informal_ref,
                "formal_ref": a.formal_ref,
            })
        })
        .unwrap_or_else(|| Value::String("absent".into()));

    // human_review: the typed review verdict + the reviewer's provenance.
    let human_review = match finding.flags.review_state.as_ref() {
        None => Value::String("absent".into()),
        Some(state) => {
            let reviewer = latest_review_event(project, id).map(|e| e.actor.id.clone());
            let actor_class = reviewer.as_deref().map(actor_kind);
            json!({
                "review_state": format!("{state:?}"),
                "reviewer": reviewer,
                "actor_class": actor_class,
            })
        }
    };

    // transfer_status: vtr_ records that touch this finding as source or
    // target premise. The full T1–T5 admission re-derivation needs the
    // resolved source gate + theorem verification + domain tags; here we
    // surface the records themselves (touching it) per the projection's
    // scope, with the producer-declared status marked DISPLAY ONLY.
    let transfers: Vec<Value> = project
        .transfers
        .iter()
        .filter(|t| t.source_claim == id || t.target_claim == id)
        .map(|t| {
            json!({
                "transfer_id": t.transfer_id,
                "role": if t.source_claim == id { "source" } else { "target" },
                "source_claim": t.source_claim,
                "target_claim": t.target_claim,
                "kind": format!("{:?}", t.homomorphism.kind),
                "source_gate_status_claimed": t.source_gate_status_claimed,
                "note": "source_gate_status_claimed is DISPLAY ONLY; admission re-derives via derive_transfer_status",
            })
        })
        .collect();
    let transfer_status = if transfers.is_empty() {
        Value::String("absent".into())
    } else {
        Value::Array(transfers)
    };

    // priority: a registered statement hash (the priority timestamp).
    // Exact finding edge first (gap 5), heuristic fallback.
    let priority = find_priority_registration(project, id, &digest)
        .map(|(r, matched_by)| {
            json!({
                "registered": true,
                "statement_hash": r.statement_hash,
                "registered_at": r.registered_at,
                "finding_id": r.finding_id,
                "matched_by": matched_by,
            })
        })
        .unwrap_or_else(|| Value::String("absent".into()));

    json!({
        "projection": "trust_vector",
        "frontier_id": project.frontier_id(),
        "id": id,
        "claim": finding.assertion.text,
        "trust_vector": {
            "log_integrity": log_integrity,
            "artifact_replay": artifact_replay,
            "verifier_gate": verifier_gate,
            "statement_faithfulness": statement_faithfulness,
            "human_review": human_review,
            "transfer_status": transfer_status,
            "priority": priority,
        },
        "law": "no safe universal projection trust_vector -> verified_bool preserves all safety-relevant distinctions",
    })
}

/// Latest `finding.reviewed` event targeting this finding, if any —
/// used to attribute the human/agent provenance of the review verdict.
fn latest_review_event<'a>(
    project: &'a Project,
    id: &str,
) -> Option<&'a vela_protocol::events::StateEvent> {
    project
        .events
        .iter()
        .filter(|e| e.kind == "finding.reviewed" && e.target.id == id)
        .max_by(|a, b| a.timestamp.cmp(&b.timestamp))
}

/// Derive the citable claim pack: state + trust + the exact reproduce
/// command + the event ids that touch the claim.
fn derive_pack(project: &Project, finding: &FindingBundle, frontier: &str) -> Value {
    let id = finding.id.as_str();
    let state = state_cell(project, finding);
    let trust = derive_trust_vector(project, finding);

    // Every canonical event whose target is this finding — the
    // provenance trail a citor can replay.
    let event_ids: Vec<Value> = project
        .events
        .iter()
        .filter(|e| e.target.id == id)
        .map(|e| {
            json!({
                "id": e.id,
                "kind": e.kind,
                "timestamp": e.timestamp,
            })
        })
        .collect();

    json!({
        "projection": "claim_pack",
        "schema": "https://vela.science/schema/claim-pack/v1",
        "frontier_id": project.frontier_id(),
        "id": id,
        "snapshot_hash": vela_protocol::events::snapshot_hash(project),
        "event_log_hash": vela_protocol::events::event_log_hash(&project.events),
        "claim_state": state,
        "trust_vector": trust,
        "reproduce": {
            "command": format!("vela reproduce {frontier}"),
            "gate_command": format!("vela gate {frontier}"),
            "note": "re-verifies stored witnesses from scratch with the frozen exact verifiers",
        },
        "events": event_ids,
    })
}

fn print_state_human(cell: &Value) {
    println!("claim-state cell  {}", cell["id"].as_str().unwrap_or(""));
    println!("  claim:   {}", cell["claim"].as_str().unwrap_or(""));
    println!(
        "  context: {}",
        cell["context"]["conditions"].as_str().unwrap_or("")
    );
    println!(
        "  status:  {} ({})",
        cell["status"]["letter"].as_str().unwrap_or("?"),
        cell["status"]["meaning"].as_str().unwrap_or("")
    );
    if let Some(s) = cell["status"]["support_signals"].as_array()
        && !s.is_empty()
    {
        println!(
            "    support: {}",
            s.iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if let Some(r) = cell["status"]["refute_signals"].as_array()
        && !r.is_empty()
    {
        println!(
            "    refute:  {}",
            r.iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    let sp = &cell["status_provenance"];
    println!(
        "  status (provenance): {} (support: {}, refute: {}){}",
        sp["letter"].as_str().unwrap_or("?"),
        sp["support_poly"].as_str().unwrap_or("0"),
        sp["refute_poly"].as_str().unwrap_or("0"),
        if sp["divergence"].as_bool().unwrap_or(false) {
            "  [DIVERGES from signal-derived status]"
        } else {
            ""
        }
    );
    println!(
        "  superseded: {}",
        cell["supersession"]["superseded"]
            .as_bool()
            .unwrap_or(false)
    );
    println!(
        "  dependencies: {}",
        cell["dependencies"].as_array().map_or(0, Vec::len)
    );
    println!(
        "  open obligations: {}",
        cell["open_obligations"].as_array().map_or(0, Vec::len)
    );
    let prio = if cell["priority_registration"].is_null() {
        "absent"
    } else {
        "registered"
    };
    println!("  priority: {prio}");
    println!("  (run with --json for the full cell)");
}

fn print_diff_human(delta: &Value) {
    println!(
        "evidence diff  {}  →  {}",
        delta["proposal_id"].as_str().unwrap_or(""),
        delta["target"].as_str().unwrap_or("")
    );
    println!("  kind: {}", delta["kind"].as_str().unwrap_or(""));
    let sc = &delta["status_change"];
    println!(
        "  status: {} → {}{}",
        sc["before"].as_str().unwrap_or("?"),
        sc["after"].as_str().unwrap_or("?"),
        if sc["changed"].as_bool().unwrap_or(false) {
            "  [CHANGED]"
        } else {
            ""
        }
    );
    if let Some(d) = delta["downstream"].as_array() {
        println!("  downstream affected: {}", d.len());
        for item in d {
            println!(
                "    {} {} → {}  ({})",
                item["id"].as_str().unwrap_or(""),
                item["before"].as_str().unwrap_or("?"),
                item["after"].as_str().unwrap_or("?"),
                item["reason"].as_str().unwrap_or("")
            );
        }
    }
    let engine = &delta["engine"];
    if engine["available"].as_bool().unwrap_or(false) {
        let nb = engine["new_blocking"].as_array().map_or(0, Vec::len);
        let nw = engine["new_warnings"].as_array().map_or(0, Vec::len);
        println!(
            "  engine: {} ({} new blocking, {} new warnings)",
            engine["status"].as_str().unwrap_or("?"),
            nb,
            nw
        );
    } else {
        println!("  engine: absent (run locally or attempt the accept to see the gate verdict)");
    }
    println!("  (run with --json for the full before/after cells)");
}

fn print_trust_human(vector: &Value) {
    let tv = &vector["trust_vector"];
    println!("trust vector  {}", vector["id"].as_str().unwrap_or(""));
    println!(
        "  log_integrity:         {}",
        tv["log_integrity"]["result"].as_str().unwrap_or("?")
    );
    let ar = &tv["artifact_replay"];
    if ar.is_string() {
        println!("  artifact_replay:       absent");
    } else {
        println!(
            "  artifact_replay:       {} passed / {} failed",
            ar["passed"].as_u64().unwrap_or(0),
            ar["failed"].as_u64().unwrap_or(0)
        );
    }
    println!(
        "  verifier_gate:         {}",
        tv["verifier_gate"]["status"].as_str().unwrap_or("?")
    );
    println!(
        "  statement_faithfulness:{}",
        render_field(&tv["statement_faithfulness"], "verdict")
    );
    println!(
        "  human_review:          {}",
        render_field(&tv["human_review"], "review_state")
    );
    let ts = &tv["transfer_status"];
    if ts.is_string() {
        println!("  transfer_status:       absent");
    } else {
        println!(
            "  transfer_status:       {} record(s)",
            ts.as_array().map_or(0, Vec::len)
        );
    }
    println!(
        "  priority:              {}",
        if tv["priority"].is_string() {
            "absent".to_string()
        } else {
            "registered".to_string()
        }
    );
    println!("  (run with --json for the full vector)");
}

/// Render a trust field that is either the string `"absent"` or an
/// object with a named summary key.
fn render_field(v: &Value, key: &str) -> String {
    if v.is_string() {
        format!(" {}", v.as_str().unwrap_or("absent"))
    } else {
        format!(" {}", v[key].as_str().unwrap_or("present"))
    }
}
