//! `vela atlas` — the Math Atlas surface (spec `docs/research/MATH_ATLAS.md`).
//!
//!   - `vela atlas <frontier>...`     read-only cross-frontier projection (step 3)
//!   - `vela atlas ingest <frontier> --namespace erdos`   bulk-anchor a corpus
//!
//! Ingest is the corpus move: it derives an external-catalogue anchor for every
//! finding that carries one (e.g. "Erdős Problem #N" → `(erdos, N, "problem")`),
//! signs each as a `val_` anchor link, and writes them all in one load/save pass.
//! Anchors are mechanical, retractable annotations (a fact about which external
//! id a claim names), so the ingest is agent-signed, not a human accept. Idempotent:
//! re-running skips findings that already carry the same `(namespace, id, role)`.

use std::path::Path;

use serde_json::json;
use vela_protocol::{
    atlas, boundary,
    frontier_graph::{BlastDirection, EdgeKind, FrontierGraph},
    pathfind, repo,
};

use crate::cli::{fail, print_json};

/// Entry from the `cli.rs::run_from_args` intercept.
pub(crate) fn run(args: &[String]) {
    if args.get(2).map(String::as_str) == Some("ingest") {
        run_ingest(args);
        return;
    }
    if args.get(2).map(String::as_str) == Some("ingest-source") {
        run_ingest_source(args);
        return;
    }
    if args.get(2).map(String::as_str) == Some("frontier") {
        run_frontier(args);
        return;
    }
    if args.get(2).map(String::as_str) == Some("graph") {
        run_graph(args);
        return;
    }
    if args.get(2).map(String::as_str) == Some("boundary") {
        run_boundary(args);
        return;
    }
    if args.get(2).map(String::as_str) == Some("pathfind") {
        run_pathfind(args);
        return;
    }
    if args.get(2).map(String::as_str) == Some("blast-radius") {
        run_blast_radius(args);
        return;
    }
    if args.get(2).map(String::as_str) == Some("decl-build") {
        run_decl_build(args);
        return;
    }
    if args.get(2).map(String::as_str) == Some("decl-blast") {
        run_decl_blast(args);
        return;
    }
    if args.get(2).map(String::as_str) == Some("contradictions") {
        run_contradictions(args);
        return;
    }
    if args.get(2).map(String::as_str) == Some("domains") {
        run_domains(args);
        return;
    }
    let frontiers: Vec<&str> = args
        .iter()
        .skip(2)
        .filter(|a| !a.starts_with('-'))
        .map(String::as_str)
        .collect();
    if frontiers.is_empty() {
        fail(
            "usage: vela atlas <frontier> [<frontier> ...]   |   vela atlas ingest <frontier> --namespace <ns>",
        );
    }
    let projects: Vec<_> = frontiers
        .iter()
        .map(|f| {
            repo::load_from_path(Path::new(f)).unwrap_or_else(|e| fail(&format!("load {f}: {e}")))
        })
        .collect();
    let refs: Vec<&_> = projects.iter().collect();
    let out = atlas::project(&refs);
    print_json(&serde_json::to_value(&out).unwrap_or_else(|e| fail(&format!("serialize: {e}"))));
}

/// `vela atlas domains <frontier>... --domains-of <map.json>` — project the
/// per-domain frontier state (frontier calculus lifted from a single claim to a
/// whole field). `--domains-of` is a JSON object mapping an Erdős problem id to
/// its domains (`{"102": ["additive combinatorics", "sidon sets"], ...}`); each
/// atlas cell is attributed to its problem's domains and the cells' bilattice
/// points are folded by `join_k`. Emits the `DomainAtlas`.
fn run_domains(args: &[String]) {
    let mut frontiers: Vec<&str> = Vec::new();
    let mut domains_of: Option<&str> = None;
    let mut i = 3; // after "atlas domains"
    while i < args.len() {
        if args[i] == "--domains-of" {
            domains_of = args.get(i + 1).map(String::as_str);
            i += 2;
            continue;
        }
        if !args[i].starts_with('-') {
            frontiers.push(&args[i]);
        }
        i += 1;
    }
    let usage =
        "usage: vela atlas domains <frontier> [<frontier> ...] --domains-of <problem-domains.json>";
    let domains_of = domains_of.unwrap_or_else(|| fail(usage));
    if frontiers.is_empty() {
        fail(usage);
    }
    let raw = std::fs::read_to_string(domains_of)
        .unwrap_or_else(|e| fail(&format!("read {domains_of}: {e}")));
    let map: std::collections::BTreeMap<String, Vec<String>> =
        serde_json::from_str(&raw).unwrap_or_else(|e| fail(&format!("parse {domains_of}: {e}")));
    let projects: Vec<_> = frontiers
        .iter()
        .map(|f| {
            repo::load_from_path(Path::new(f)).unwrap_or_else(|e| fail(&format!("load {f}: {e}")))
        })
        .collect();
    let refs: Vec<&_> = projects.iter().collect();
    let atlas = atlas::project(&refs);
    let out = atlas::project_domains(&atlas, &map);
    print_json(&serde_json::to_value(&out).unwrap_or_else(|e| fail(&format!("serialize: {e}"))));
}

/// The digits that follow `keyword` (ASCII, case-insensitive) in `text`, after
/// skipping up to `max_skip` non-digit separators. e.g. `("erdos", 2)` finds the
/// number in "Erdos257", "erdos_257", "Erdős-642" (ASCII match on "erdos").
fn digits_after(text: &str, keyword: &str, max_skip: usize) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    let pos = lower.find(keyword)?;
    let mut chars = text[pos + keyword.len()..].chars().peekable();
    let mut skipped = 0;
    while let Some(&c) = chars.peek() {
        if c.is_ascii_digit() {
            break;
        }
        if skipped >= max_skip {
            return None;
        }
        chars.next();
        skipped += 1;
    }
    let digits: String = chars.take_while(char::is_ascii_digit).collect();
    (!digits.is_empty()).then_some(digits)
}

/// `vela atlas frontier <frontier>...` — the router view: the status landscape,
/// the edge count, and the **stale-open frontier** (problems marked open in one
/// source but resolved in another — the registry-stale wedge, an adoption queue).
fn run_frontier(args: &[String]) {
    let frontiers: Vec<&str> = args
        .iter()
        .skip(3)
        .filter(|a| !a.starts_with('-'))
        .map(String::as_str)
        .collect();
    if frontiers.is_empty() {
        fail("usage: vela atlas frontier <frontier> [<frontier> ...]");
    }
    let projects: Vec<_> = frontiers
        .iter()
        .map(|f| {
            repo::load_from_path(Path::new(f)).unwrap_or_else(|e| fail(&format!("load {f}: {e}")))
        })
        .collect();
    let refs: Vec<&_> = projects.iter().collect();
    let out = atlas::project(&refs);

    let mut by_status: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    let mut stale_open: Vec<serde_json::Value> = Vec::new();
    for c in &out.cells {
        let s = c.status.clone().unwrap_or_else(|| "undeclared".to_string());
        *by_status.entry(s.clone()).or_default() += 1;
        if s == "contested" {
            stale_open.push(json!({
                "handle": c.stable_handle, "members": c.members.len(), "label": c.label,
            }));
        }
    }
    print_json(&json!({
        "frontiers": out.frontiers,
        "cells": out.cells.len(),
        "edges": out.edges.len(),
        "status_landscape": by_status,
        "stale_open_frontier": {
            "note": "open in one source, resolved in another — the registry-stale wedge (an adoption queue)",
            "count": stale_open.len(),
            "cells": stale_open,
        },
    }));
}

/// Load a single frontier project from the path that follows the subcommand,
/// failing with a usage message when absent. Shared by graph/boundary/pathfind.
fn load_one(args: &[String], usage: &str) -> vela_protocol::project::Project {
    let frontier = args
        .iter()
        .skip(3)
        .find(|a| !a.starts_with('-'))
        .unwrap_or_else(|| fail(usage));
    repo::load_from_path(Path::new(frontier))
        .unwrap_or_else(|e| fail(&format!("load {frontier}: {e}")))
}

/// `vela atlas graph <frontier>` — the typed claim-level graph (memo §11):
/// findings as nodes carrying their derived state (open/established/refuted/
/// contested/fragile), typed edges, contradiction-pair count. The richer emit
/// the map renders.
fn run_graph(args: &[String]) {
    let project = load_one(args, "usage: vela atlas graph <frontier>");
    let graph = FrontierGraph::from_project(&project);
    print_json(&graph.to_json());
}

/// `vela atlas boundary <frontier>` — the dark-matter boundary (memo §3):
/// one-premise-away, fragile, contested, stale-open. Each item points at a
/// real finding a submission can be opened against.
fn run_boundary(args: &[String]) {
    let project = load_one(args, "usage: vela atlas boundary <frontier>");
    print_json(&boundary::Boundary::derive(&project).to_json());
}

/// `vela attack <frontier>` (alias `what-next`) — the ranked "what should I work
/// on next" queue, derived from the dark-matter boundary. A flat, ordered list:
/// one-premise-away (closest to done) first, then brittle single-points-of-
/// failure (by blast size), then fragile, contested, stale-open. This is the
/// one-command answer to "what's the most-attackable open target" — the read
/// surface the substrate always had (`boundary::Boundary::derive`) but never
/// exposed as a verb. Pure projection, read-only.
pub(crate) fn run_attack(frontier: &Path, top: usize, json: bool) {
    let project = repo::load_from_path(frontier).unwrap_or_else(|e| fail(&e));
    let b = boundary::Boundary::derive(&project);
    // Ranked flat list: category order is the priority order.
    let mut rows: Vec<(String, String, String, String)> = Vec::new(); // (category, finding, label, reason)
    for it in &b.one_premise_away {
        rows.push((
            "one_premise_away".into(),
            it.finding.clone(),
            it.label.clone(),
            it.reason.clone(),
        ));
    }
    for it in &b.brittle {
        rows.push((
            "brittle".into(),
            it.finding.clone(),
            it.label.clone(),
            format!(
                "single point of failure: {} support via {} ({})",
                it.support_size, it.dominator_label, it.dominator_state
            ),
        ));
    }
    for it in &b.fragile {
        rows.push((
            "fragile".into(),
            it.finding.clone(),
            it.label.clone(),
            it.reason.clone(),
        ));
    }
    for it in &b.contested {
        rows.push((
            "contested".into(),
            it.finding.clone(),
            it.label.clone(),
            it.reason.clone(),
        ));
    }
    for it in &b.stale_open {
        rows.push((
            "stale_open".into(),
            it.finding.clone(),
            it.label.clone(),
            it.reason.clone(),
        ));
    }
    let total = rows.len();
    let shown: Vec<_> = rows.into_iter().take(top).collect();
    if json {
        print_json(&json!({
            "command": "attack",
            "frontier": frontier.display().to_string(),
            "total_attackable": total,
            "shown": shown.len(),
            "queue": shown.iter().enumerate().map(|(i, (cat, f, label, reason))| json!({
                "rank": i + 1, "category": cat, "finding": f, "label": label, "reason": reason,
            })).collect::<Vec<_>>(),
        }));
    } else {
        println!(
            "· attack {} — {total} attackable target(s), showing {}",
            frontier.display(),
            shown.len()
        );
        if shown.is_empty() {
            println!(
                "  (no boundary targets — frontier is either saturated or has no open scaffolding)"
            );
        }
        for (i, (cat, f, label, reason)) in shown.iter().enumerate() {
            let short: String = label.chars().take(78).collect();
            println!("  {:>2}. [{}] {}  {}", i + 1, cat, f, short);
            println!("      {reason}");
        }
    }
}

/// `vela explore <frontier> <finding>` — the neighbourhood of a finding (the MCP
/// `frontier_explore` as a CLI verb): what it rests on, what rests on it, within
/// `--hops`. Read-only projection over the frontier graph.
pub(crate) fn run_explore(frontier: &Path, finding: &str, hops: usize, json: bool) {
    let project = repo::load_from_path(frontier).unwrap_or_else(|e| fail(&e));
    let graph = FrontierGraph::from_project(&project);
    let ex = graph.explore(finding, hops);
    let by_hop: Vec<_> = (0..=ex.max_hop())
        .map(|h| json!({ "hop": h, "nodes": ex.nodes_at(h) }))
        .collect();
    let out = json!({
        "command": "explore",
        "frontier": frontier.display().to_string(),
        "start": finding,
        "hops": hops,
        "node_count": ex.node_count(),
        "max_hop": ex.max_hop(),
        "edge_kind_counts": ex.edge_kind_counts(),
        "by_hop": by_hop,
        "edges": ex.edges,
    });
    if json {
        print_json(&out);
    } else if ex.node_count() == 0 {
        println!("· explore {finding}: not found in this frontier");
    } else if ex.edges.is_empty() {
        println!(
            "· explore {finding}: found, but isolated — no edges within {hops} hop(s) (this frontier has no connective edges yet)"
        );
    } else {
        println!(
            "· explore {finding} — {} node(s) within {hops} hop(s), {} edge(s)",
            ex.node_count(),
            ex.edges.len()
        );
        for h in 1..=ex.max_hop() {
            let ns = ex.nodes_at(h);
            if !ns.is_empty() {
                println!("  hop {h}: {}", ns.join(", "));
            }
        }
        for (k, c) in ex.edge_kind_counts() {
            println!("  {k}: {c}");
        }
    }
}

/// `vela atlas pathfind <frontier> <from> <to>` — the golden thread (memo
/// §11.7): the shortest support/reduction path between two findings. Emits the
/// path, or a `found: false` object when none exists.
fn run_pathfind(args: &[String]) {
    let positional: Vec<&str> = args
        .iter()
        .skip(3)
        .filter(|a| !a.starts_with('-'))
        .map(String::as_str)
        .collect();
    let [frontier, from, to] = positional.as_slice() else {
        fail("usage: vela atlas pathfind <frontier> <from-finding> <to-finding>");
    };
    let project = repo::load_from_path(Path::new(frontier))
        .unwrap_or_else(|e| fail(&format!("load {frontier}: {e}")));
    let graph = FrontierGraph::from_project(&project);
    match pathfind::shortest_path(&graph, from, to, &pathfind::SUPPORT_KINDS) {
        Some(path) => print_json(&path.to_json()),
        None => print_json(&json!({
            "schema": "vela.golden_thread.v0.1",
            "from": from, "to": to, "found": false,
            "note": "no support/reduction path between these findings",
        })),
    }
}

/// `vela atlas blast-radius <frontier> <finding> [--impact up|down|both]
/// [--kinds <csv>]` — the dependency-impact neighborhood (memo §7.3): what the
/// finding rests on (upstream), what rests on it (downstream, the blast radius
/// if it moved), and the single points of failure on its support (the
/// minimal-evidence-cut). The finding resolves by id or assertion substring.
fn run_blast_radius(args: &[String]) {
    let mut frontier: Option<&str> = None;
    let mut finding: Option<&str> = None;
    let mut direction = BlastDirection::Both;
    let mut kinds: Vec<EdgeKind> = Vec::new();
    let mut i = 3; // after "atlas blast-radius"
    while i < args.len() {
        match args[i].as_str() {
            "--impact" => {
                direction = match args.get(i + 1).map(String::as_str) {
                    Some("up") | Some("upstream") => BlastDirection::Upstream,
                    Some("down") | Some("downstream") => BlastDirection::Downstream,
                    _ => BlastDirection::Both,
                };
                i += 2;
            }
            "--kinds" => {
                if let Some(csv) = args.get(i + 1) {
                    kinds = csv.split(',').filter_map(EdgeKind::parse).collect();
                }
                i += 2;
            }
            a if a.starts_with('-') => i += 1,
            a => {
                if frontier.is_none() {
                    frontier = Some(a);
                } else if finding.is_none() {
                    finding = Some(a);
                }
                i += 1;
            }
        }
    }
    let usage = "usage: vela atlas blast-radius <frontier> <finding> [--impact up|down|both] [--kinds <csv>]";
    let frontier = frontier.unwrap_or_else(|| fail(usage));
    let finding = finding.unwrap_or_else(|| fail(usage));
    let project = repo::load_from_path(Path::new(frontier))
        .unwrap_or_else(|e| fail(&format!("load {frontier}: {e}")));
    let graph = FrontierGraph::from_project(&project);
    let center = graph
        .find_node(finding)
        .unwrap_or_else(|| fail(&format!("no finding matching '{finding}' in {frontier}")));
    print_json(
        &graph
            .blast_radius_graded(&project, &center, &kinds, direction)
            .to_json(),
    );
}

/// `vela atlas decl-blast [--edges <jsonl>] [--decl <name>] [--top <N>] [--json]`
/// — the correction proof (memo §1.6) over a REAL premise graph. Loads the
/// Mathlib declaration-dependency graph (`data/mathlib/decl-edges.jsonl`,
/// `from --uses--> to`) as a `FrontierGraph` of `DependsOn` edges and reports the
/// downstream blast radius of retracting one declaration: every transitive
/// dependent that would need re-checking. Lean dependencies are CONJUNCTIVE
/// (a declaration requires every constant it uses), so the structural downstream
/// set IS the impacted set, exactly — there is no alternative route to survive
/// on, the distinction the κ-graded cascade draws on a verifier-gated frontier.
/// With no `--decl`, the highest-in-degree declaration (the highest-leverage
/// retraction) is chosen. This is the demonstration flat Erdős could not give
/// (no premise edges → 0 dependents).
fn run_decl_blast(args: &[String]) {
    use vela_protocol::frontier_graph::{BlastDirection, EdgeKind, FrontierGraph};

    let flag = |name: &str| -> Option<String> {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    let edges_path = flag("--edges").unwrap_or_else(|| "data/mathlib/decl-edges.jsonl".to_string());
    let top: usize = flag("--top").and_then(|s| s.parse().ok()).unwrap_or(15);
    let json_out = args.iter().any(|a| a == "--json");

    // Shared loader: accepts either the raw `decl-edges.jsonl` or the built
    // `decl-graph.v1.json` artifact, and applies the SAME noise-filter + dedup
    // so the retraction target is a real declaration, not a typeclass/core-type.
    let pairs = load_decl_edges(&edges_path)
        .unwrap_or_else(|e| fail(&format!("load decl edges {edges_path}: {e}")));
    if pairs.is_empty() {
        fail(&format!(
            "{edges_path}: no usable decl edges after noise filter"
        ));
    }
    let edges: Vec<(String, String, EdgeKind)> = pairs
        .into_iter()
        .map(|(from, to)| (from, to, EdgeKind::DependsOn))
        .collect();
    let graph = FrontierGraph::from_edges(edges);
    let ranked = graph.in_degree_ranked(&[EdgeKind::DependsOn]);

    let decl = flag("--decl")
        .and_then(|d| graph.find_node(&d))
        .or_else(|| ranked.first().map(|(id, _)| id.clone()))
        .unwrap_or_else(|| fail("no declaration to retract (empty graph)"));

    let blast = graph.blast_radius(&decl, &[EdgeKind::DependsOn], BlastDirection::Downstream);
    let in_deg = ranked
        .iter()
        .find(|(id, _)| *id == decl)
        .map(|(_, d)| *d)
        .unwrap_or(0);

    if json_out {
        print_json(&json!({
            "object": "vela.correction_blast.v1",
            "edges_source": edges_path,
            "nodes": graph.node_count(),
            "edges": graph.edge_count(),
            "retracted": decl,
            "direct_dependency_edges": in_deg,
            "impacted_total": blast.summary.downstream,
            "max_distance": blast.summary.max_downstream_distance,
            "model": "conjunctive premise graph (Lean dependencies): every transitive dependent is impacted; no alternative route survives",
            "impacted": blast.downstream.iter().take(top).map(|n| json!({
                "id": n.id, "distance": n.distance,
            })).collect::<Vec<_>>(),
        }));
        return;
    }

    println!("correction blast-radius — retract `{decl}`");
    println!(
        "  premise graph: {} declarations, {} dependency edges ({})",
        graph.node_count(),
        graph.edge_count(),
        edges_path
    );
    println!("  retracted declaration is referenced by {in_deg} dependency edges");
    println!(
        "  => retracting it impacts {} downstream declarations (max depth {}), every one of which",
        blast.summary.downstream, blast.summary.max_downstream_distance
    );
    println!("     would need re-checking: Lean dependencies are conjunctive, so there is no");
    println!(
        "     alternative route to survive on. History is preserved (a correction mints a new root)."
    );
    if blast.summary.downstream == 0 {
        println!("  (this declaration is a leaf in the loaded slice: nothing depends on it here)");
    }
    for n in blast.downstream.iter().take(top) {
        println!("    - [d{}] {}", n.distance, n.id);
    }
    let shown = top.min(blast.downstream.len());
    if blast.downstream.len() > shown {
        println!("    … and {} more", blast.downstream.len() - shown);
    }
}

/// Slice policy v1 for the Mathlib decl-dependency graph. The raw "uses" edges
/// are dominated by typeclass plumbing + core types (Nat, DecidableEq, Finset,
/// the lattice/SMul instance chain) that EVERY declaration references, so the
/// highest-in-degree node — the "highest-leverage retraction" the correction
/// demo picks — is meaningless noise unless these are dropped. This denylist is
/// explicit + versioned so the slice is reviewable and the artifact is
/// deterministic. It is a LEGIBILITY filter over a projection, not a trust path.
const DECL_NOISE_EXACT: &[&str] = &[
    "Nat",
    "Int",
    "Eq",
    "Iff",
    "Exists",
    "And",
    "Or",
    "Not",
    "True",
    "False",
    "Bool",
    "Prop",
    "Finset",
    "List",
    "Set",
    "Multiset",
    "Subtype",
    "Sigma",
    "Prod",
    "Sum",
    "Option",
    "Quot",
    "Finset.card",
    "Finset.filter",
    "Finset.sum",
    "Finset.image",
    "Finset.instSetLike",
    "LE.le",
    "LT.lt",
    "GE.ge",
    "GT.gt",
    "Membership.mem",
    "SetLike.coe",
    "SetLike.instMembership",
    "HSMul.hSMul",
    "HMul.hMul",
    "HAdd.hAdd",
    "HSub.hSub",
    "HDiv.hDiv",
    "HPow.hPow",
    "Mul.mul",
    "Add.add",
    "OfNat.ofNat",
    "Zero.zero",
    "One.one",
    "Function.comp",
    // Order/algebra typeclasses: structural scaffolding, not theorems a correction
    // would retract. Dropping them pushes the highest-leverage retraction onto a
    // real declaration (a def/lemma) rather than a class.
    "LinearOrder",
    "PartialOrder",
    "Preorder",
    "Lattice",
    "SemilatticeInf",
    "SemilatticeSup",
    "DistribLattice",
    "CompleteLattice",
    "Order",
    "LinearOrder.toLattice",
    "AddMonoid",
    "Monoid",
    "AddCommMonoid",
    "CommMonoid",
    "AddGroup",
    "Group",
    "AddCommGroup",
    "CommGroup",
    "Ring",
    "CommRing",
    "Field",
    "Semiring",
    "CommSemiring",
    "Module",
    "Algebra",
    "Mul",
    "Add",
    "Zero",
    "One",
    "Neg",
    "Inv",
    "Sub",
    "Div",
    "Pow",
    "SMul",
    "Dvd",
    "Fintype",
    "DecidablePred",
    "Nonempty",
    "Finite",
    "Countable",
    "Encodable",
];

/// A target declaration is structural noise (a typeclass instance, a typeclass
/// coercion `X.toY`, a Decidable* witness, or a core type/relation) rather than
/// a theorem/lemma/def worth a correction-cascade node.
fn is_decl_noise(name: &str) -> bool {
    DECL_NOISE_EXACT.contains(&name)
        || name.starts_with("inst")
        || name.starts_with("Decidable")
        || name.contains(".to") // typeclass coercions, e.g. Lattice.toSemilatticeInf
}

/// Load decl-dependency edges from either the raw `decl-edges.jsonl`
/// (`{from,to,kind:"uses"}`) or the built `decl-graph.v1.json` artifact, applying
/// the noise filter + dedup + canonical sort. Deterministic: same input bytes →
/// same edge list. Returns `(from, to)` pairs (every edge is `from DependsOn to`).
pub(crate) fn load_decl_edges(path: &str) -> Result<Vec<(String, String)>, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let mut set: std::collections::BTreeSet<(String, String)> = std::collections::BTreeSet::new();
    // The built artifact is a single JSON object with an `edges` array (it parses
    // as one Value); the raw source is one JSON object per line (it does not).
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw)
        && let Some(edges) = v.get("edges").and_then(|e| e.as_array())
    {
        for e in edges {
            if let (Some(from), Some(to)) = (
                e.get("from").and_then(|x| x.as_str()),
                e.get("to").and_then(|x| x.as_str()),
            ) && from != to
                && !is_decl_noise(to)
            {
                set.insert((from.to_string(), to.to_string()));
            }
        }
        return Ok(set.into_iter().collect());
    }
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let (Some(from), Some(to)) = (
            v.get("from").and_then(|x| x.as_str()),
            v.get("to").and_then(|x| x.as_str()),
        ) else {
            continue;
        };
        if from != to && !is_decl_noise(to) {
            set.insert((from.to_string(), to.to_string()));
        }
    }
    Ok(set.into_iter().collect())
}

/// `vela atlas decl-build [--in <jsonl>] [--out <json>]` — promote the raw
/// `decl-edges.jsonl` slice into a DETERMINISTIC, noise-filtered, deduped,
/// canonically-sorted premise-graph artifact (`decl-graph.v1.json`) that the
/// correction-cascade (`decl-blast`) runs over. Pins `source_sha256` +
/// `slice_policy` so the artifact is a pure function of (input, policy) and the
/// gate can re-derive it. Regenerable projection, NOT a reproduce-pinned
/// frontier — no wire-format change.
fn run_decl_build(args: &[String]) {
    let flag = |name: &str| -> Option<String> {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    let in_path = flag("--in").unwrap_or_else(|| "data/mathlib/decl-edges.jsonl".to_string());
    let out_path = flag("--out").unwrap_or_else(|| "data/mathlib/decl-graph.v1.json".to_string());
    let json_out = args.iter().any(|a| a == "--json");

    let raw =
        std::fs::read_to_string(&in_path).unwrap_or_else(|e| fail(&format!("read {in_path}: {e}")));
    let source_sha256 = {
        use sha2::{Digest, Sha256};
        format!("{:x}", Sha256::digest(raw.as_bytes()))
    };
    let pairs = load_decl_edges(&in_path).unwrap_or_else(|e| fail(&e));
    let nodes: std::collections::BTreeSet<&str> = pairs
        .iter()
        .flat_map(|(a, b)| [a.as_str(), b.as_str()])
        .collect();

    let artifact = json!({
        "schema": "vela.decl-graph.v1",
        "source": in_path,
        "source_sha256": source_sha256,
        "slice_policy": "denylist v1: drop core types + typeclass instances/coercions (inst*, *.to*, Decidable*); dedup; canonical sort. from --uses--> to becomes from DependsOn to.",
        "stats": { "edges": pairs.len(), "nodes": nodes.len() },
        "edges": pairs.iter().map(|(f, t)| json!({ "from": f, "to": t })).collect::<Vec<_>>(),
    });
    let body = serde_json::to_string_pretty(&artifact).unwrap() + "\n";
    std::fs::write(&out_path, &body).unwrap_or_else(|e| fail(&format!("write {out_path}: {e}")));

    if json_out {
        print_json(&json!({
            "object": "vela.decl_graph_build.v1",
            "in": in_path, "out": out_path,
            "source_sha256": source_sha256,
            "edges": pairs.len(), "nodes": nodes.len(),
        }));
        return;
    }
    println!("built decl-graph artifact: {out_path}");
    println!("  source: {in_path} (sha256 {})", &source_sha256[..16]);
    println!(
        "  {} noise-filtered, deduped, canonically-sorted edges over {} declarations",
        pairs.len(),
        nodes.len()
    );
    println!(
        "  the correction cascade (`vela atlas decl-blast --edges {out_path}`) now retracts a"
    );
    println!(
        "  real declaration, not a typeclass instance. Deterministic: re-run yields identical bytes."
    );
}

/// The declared status of a finding parsed from its assertion text, normalized
/// to {open, solved, proved, disproved}. Handles the `declared status 'X'` form
/// (FC / formal corpus) and the Erdős prose form ("remains OPEN", "SOLVED", …).
fn declared_status(text: &str) -> Option<&'static str> {
    let lt = text.to_lowercase();
    let norm = |s: &str| -> Option<&'static str> {
        match s.trim() {
            "open" => Some("open"),
            "solved" => Some("solved"),
            "proved" => Some("proved"),
            "disproved" => Some("disproved"),
            _ => None,
        }
    };
    if let Some(i) = lt.find("declared status '") {
        let rest = &lt[i + "declared status '".len()..];
        if let Some(s) = rest.split('\'').next() {
            return norm(s);
        }
    }
    for (kw, st) in [
        ("disproved", "disproved"),
        ("remains open", "open"),
        ("is solved", "solved"),
        ("is proved", "proved"),
    ] {
        if lt.contains(kw) {
            return norm(st);
        }
    }
    None
}

/// `vela atlas contradictions <frontier>... [--json]` — cross-source concordance
/// (memo tier 3-4): find atlas cells whose members, joined under one anchor
/// (e.g. an Erdős problem and its Formal-Conjectures formalization), declare an
/// INCOMPATIBLE status — one "open", another "solved/proved/disproved". Each is
/// minted as a CANDIDATE `Contradiction` (`vcx_`). Per the contradiction doctrine
/// these are never auto-adjudicated: this is read-only detection, a signal for
/// human review, never a verdict.
fn run_contradictions(args: &[String]) {
    use vela_protocol::bundle::bare_finding_id;
    use vela_protocol::contradiction::Contradiction;

    let frontiers: Vec<&str> = args
        .iter()
        .skip(3)
        .filter(|a| !a.starts_with('-'))
        .map(String::as_str)
        .collect();
    let json_out = args.iter().any(|a| a == "--json");
    if frontiers.is_empty() {
        fail("usage: vela atlas contradictions <frontier> [<frontier> ...] [--json]");
    }
    let projects: Vec<_> = frontiers
        .iter()
        .map(|f| {
            repo::load_from_path(Path::new(f)).unwrap_or_else(|e| fail(&format!("load {f}: {e}")))
        })
        .collect();
    let mut status_of: std::collections::HashMap<String, &'static str> =
        std::collections::HashMap::new();
    for p in &projects {
        for f in &p.findings {
            if let Some(s) = declared_status(&f.assertion.text) {
                status_of.insert(f.id.clone(), s);
            }
        }
    }
    let refs: Vec<&_> = projects.iter().collect();
    let out = atlas::project(&refs);

    let mut found: Vec<serde_json::Value> = Vec::new();
    for cell in &out.cells {
        let mut by_status: std::collections::BTreeMap<&str, String> =
            std::collections::BTreeMap::new();
        for m in &cell.members {
            let bare = bare_finding_id(m);
            if let Some(s) = status_of.get(bare) {
                by_status.entry(*s).or_insert_with(|| bare.to_string());
            }
        }
        let open = by_status.get("open").cloned();
        let resolved = by_status
            .iter()
            .find(|(s, _)| **s != "open")
            .map(|(s, id)| (*s, id.clone()));
        if let (Some(a), Some((rstat, b))) = (open, resolved) {
            let anchor = cell
                .anchors
                .first()
                .map(|an| format!("{}:{}", an.namespace, an.id))
                .unwrap_or_else(|| "spine".to_string());
            let cx = Contradiction::candidate(
                &anchor,
                &a,
                &b,
                &format!("cross-source status conflict: one member 'open', another '{rstat}'"),
            );
            found.push(json!({
                "contradiction_id": cx.contradiction_id,
                "anchor": anchor,
                "label": cell.label.chars().take(80).collect::<String>(),
                "open_member": a,
                "resolved_member": b,
                "resolved_status": rstat,
                "status": "candidate",
            }));
        }
    }

    if json_out {
        print_json(&json!({
            "object": "vela.contradiction_scan.v1",
            "frontiers": frontiers,
            "cells_scanned": out.cells.len(),
            "candidate_contradictions": found.len(),
            "doctrine": "candidates only — never auto-adjudicated; a signal for human review",
            "contradictions": found,
        }));
        return;
    }
    println!(
        "cross-source contradiction scan — {} cells, {} candidate conflicts",
        out.cells.len(),
        found.len()
    );
    for c in &found {
        println!(
            "  {} [{}] {} : open vs {}",
            c["contradiction_id"].as_str().unwrap_or(""),
            c["anchor"].as_str().unwrap_or(""),
            c["label"].as_str().unwrap_or(""),
            c["resolved_status"].as_str().unwrap_or("")
        );
    }
    if found.is_empty() {
        println!("  (no cross-source status conflicts — sources agree where they overlap)");
    } else {
        println!(
            "\ncandidates only — never auto-adjudicated; surfaced for human review (the doctrine)."
        );
    }
}

/// `vela correct` — scientific record repair (memo Program Two). The dependency
/// blast radius of correcting/retracting a finding, read over the frozen
/// Bottleneck-kappa cascade: which downstream findings lose their only support,
/// which are weakened but keep surviving routes, which are unaffected. Read-only
/// analysis; the write (`vela retract`) is key custody.
pub(crate) fn cmd_correct(frontier: &Path, finding: &str, json_out: bool) {
    let project = repo::load_from_path(frontier)
        .unwrap_or_else(|e| fail(&format!("load {}: {e}", frontier.display())));
    let graph = FrontierGraph::from_project(&project);
    let center = graph.find_node(finding).unwrap_or_else(|| {
        fail(&format!(
            "no finding matching '{finding}' in {}",
            frontier.display()
        ))
    });
    let blast = graph.blast_radius_graded(&project, &center, &[], BlastDirection::Downstream);
    if json_out {
        print_json(&blast.to_json());
        return;
    }
    let s = &blast.summary;
    let unaffected = s.downstream_candidates.saturating_sub(s.weakened);
    println!("record repair — correcting {}", blast.structural.center);
    println!("  finding: {}", blast.structural.center_label);
    println!(
        "  current support: belnap '{}'  (support kappa {})",
        blast.center_status.belnap, blast.center_status.support_kappa
    );
    println!(
        "  downstream dependents: {} weakened, {} lose all support, {} unaffected (alternative support survives)",
        s.weakened, s.killed, unaffected
    );
    for g in &blast.impacted {
        let verdict = if g.support_killed {
            "SUPPORT KILLED (the corrected finding was its only route)"
        } else {
            "weakened, but surviving routes remain"
        };
        println!(
            "    - {} [{}]: support kappa {} -> {}  ({verdict})",
            g.id, g.label, g.kappa_before, g.kappa_after
        );
    }
    println!(
        "  history preserved: a correction mints a NEW root; the prior state stays replayable (no rewrite)."
    );
    println!(
        "  to apply the retraction: vela retract {} {}  (key custody)",
        frontier.display(),
        blast.structural.center
    );
}

/// Extract a problem/sequence number from a finding's assertion text. Handles
/// "Erdős Problem #105", "#105", "Problem 105", "Erdos257", "erdos_1150",
/// "A309370" — so the same problem written different ways in different databases
/// lands on the same anchor.
fn extract_id(namespace: &str, text: &str) -> Option<String> {
    match namespace {
        "oeis" => {
            let bytes = text.as_bytes();
            for (i, &b) in bytes.iter().enumerate() {
                if b == b'A' {
                    let digits: String = text[i + 1..]
                        .chars()
                        .take_while(char::is_ascii_digit)
                        .collect();
                    if digits.len() >= 6 {
                        return Some(format!("A{digits}"));
                    }
                }
            }
            None
        }
        _ => digits_after(text, "#", 0)
            .or_else(|| digits_after(text, "erdos", 2))
            .or_else(|| digits_after(text, "problem ", 0)),
    }
}

fn run_ingest(args: &[String]) {
    use vela_protocol::anchor::{Anchor, AnchorKind, JoinPolicy};

    let positionals: Vec<&str> = args
        .iter()
        .skip(3)
        .filter(|a| !a.starts_with('-'))
        .map(String::as_str)
        .collect();
    let frontier = positionals.first().copied().unwrap_or_else(|| {
        fail("usage: vela atlas ingest <frontier> --namespace <erdos|oeis> [--dry-run] [--key <agentkey>] [--actor <agent>]")
    });
    let flag = |name: &str| -> Option<String> {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .map(|s| s.to_string())
    };
    let ns = flag("--namespace").unwrap_or_else(|| fail("--namespace is required (erdos|oeis)"));
    let dry = args.iter().any(|a| a == "--dry-run");
    let actor = flag("--actor").unwrap_or_else(|| "agent:atlas-ingest".to_string());
    let kind = match ns.as_str() {
        "erdos" => AnchorKind::ProblemEntry,
        "oeis" => AnchorKind::Sequence,
        _ => AnchorKind::Statement,
    };
    // The anchor role is part of the join key, so it must be namespace-correct: an
    // OEIS node is a sequence, an Erdős node is a problem. A different source
    // anchoring the same sequence with role "sequence" must land on the same cell.
    let role = match ns.as_str() {
        "oeis" => "sequence",
        _ => "problem",
    }
    .to_string();

    let mut project = repo::load_from_path(Path::new(frontier)).unwrap_or_else(|e| fail(&e));

    // Plan the anchors (idempotent: skip findings already carrying this anchor).
    let mut plan: Vec<(String, Anchor)> = Vec::new();
    let (mut already, mut no_number) = (0usize, 0usize);
    for f in &project.findings {
        let Some(id) = extract_id(&ns, &f.assertion.text) else {
            no_number += 1;
            continue;
        };
        let exists = project.anchor_links.iter().any(|l| {
            l.target == f.id
                && l.anchor.namespace == ns
                && l.anchor.id == id
                && l.anchor.role == role
        });
        if exists {
            already += 1;
            continue;
        }
        plan.push((
            f.id.clone(),
            Anchor {
                namespace: ns.clone(),
                id,
                role: role.clone(),
                kind,
                join_policy: JoinPolicy::HardIdentity,
                namespace_version: None,
                source_revision: None,
                statement_fingerprint: None,
            },
        ));
    }

    if dry {
        let sample: Vec<_> = plan
            .iter()
            .take(8)
            .map(|(t, a)| json!({"target": t, "anchor": format!("{}:{}#{}", a.namespace, a.id, a.role)}))
            .collect();
        print_json(&json!({
            "dry_run": true, "namespace": ns,
            "would_anchor": plan.len(), "already_anchored": already,
            "no_number_skipped": no_number, "sample": sample,
        }));
        return;
    }

    let key = crate::cli_identity::resolve_signing_key(flag("--key").as_deref().map(Path::new));
    let anchored = anchor_findings(&mut project, plan, &actor, &key);
    repo::save_to_path(Path::new(frontier), &project).unwrap_or_else(|e| fail(&e));
    print_json(&json!({
        "ok": true, "namespace": ns, "anchored": anchored,
        "already_anchored": already, "no_number_skipped": no_number, "signer": actor,
    }));
}

/// Attach a planned set of `(finding_id, anchor)` as signed `anchor.attached`
/// events. Shared by `ingest` (text-derived anchors) and `ingest-source`
/// (adapter-derived anchors). Anchors are mechanical, retractable annotations,
/// so agent-signing is in-doctrine (not a human accept). Returns the count.
fn anchor_findings(
    project: &mut vela_protocol::project::Project,
    plan: Vec<(String, vela_protocol::anchor::Anchor)>,
    actor: &str,
    key: &ed25519_dalek::SigningKey,
) -> usize {
    use vela_protocol::anchor::{AnchorLink, AnchorLinkDraft};
    let mut anchored = 0usize;
    for (target, anchor) in plan {
        let link = AnchorLink::build(
            AnchorLinkDraft {
                target: target.clone(),
                anchor,
                attached_by: actor.to_string(),
                attached_at: chrono::Utc::now().to_rfc3339(),
            },
            key,
        )
        .unwrap_or_else(|e| fail(&e));
        let event =
            vela_protocol::events::new_finding_event(vela_protocol::events::FindingEventInput {
                kind: "anchor.attached",
                finding_id: &target,
                actor_id: actor,
                actor_type: vela_protocol::events::actor_kind(actor),
                reason: "atlas ingest: external-catalogue anchor",
                before_hash: "sha256:null",
                after_hash: "sha256:null",
                payload: json!({ "anchor_link": link }),
                caveats: Vec::new(),
                timestamp: None,
            });
        vela_protocol::reducer::apply_event(project, &event).unwrap_or_else(|e| fail(&e));
        project.events.push(event);
        anchored += 1;
    }
    anchored
}

/// `vela atlas ingest-source --adapter <formal|formal_corpus|alphaproof|oeis|horizonmath|identity_seed> --input
/// <dir|file> --out <frontier.json|repo> [--namespace erdos|oeis|horizonmath|formal_conjectures|identity]
/// [--rev <prov>] [--actor <a>] [--key <agentkey>] [--dry-run]` — the native production path that replaces
/// the synthetic-id Python prototypes. Reads a catalogue via a `SourceAdapter`,
/// mints real content-addressed finding bundles (genesis remnants), attaches
/// signed `anchor.attached` events, and writes the repo — then gates on
/// `verify_replay` (the loader-is-reducer round-trip). Content-deterministic:
/// the same source yields the same content-addressed findings/anchors (stable
/// `vf_` ids). The project wrapper (`compiled_at`, the derived `frontier_id`)
/// and the `anchor.attached` event timestamps are stamped at build time, so the
/// repo bytes are not identical run-to-run; these source-ingest views are
/// regenerable, not byte-pinned (the byte-pinned trust is the canonical witness
/// frontiers under `vela reproduce`).
fn run_ingest_source(args: &[String]) {
    use vela_protocol::anchor::{Anchor, AnchorKind, JoinPolicy};

    let flag = |name: &str| -> Option<String> {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .map(|s| s.to_string())
    };
    let adapter = flag("--adapter").unwrap_or_else(|| {
        fail("--adapter is required (formal|formal_corpus|alphaproof|oeis|horizonmath|identity_seed)")
    });
    let input = flag("--input").unwrap_or_else(|| fail("--input <dir> is required"));
    let out = flag("--out").unwrap_or_else(|| fail("--out <frontier.json|repo-dir> is required"));
    let ns = flag("--namespace").unwrap_or_else(|| "erdos".to_string());
    let rev = flag("--rev").unwrap_or_else(|| "unknown".to_string());
    let actor = flag("--actor").unwrap_or_else(|| "agent:atlas-ingest".to_string());
    let dry = args.iter().any(|a| a == "--dry-run");

    let (kind, role) = match ns.as_str() {
        "oeis" => (AnchorKind::Sequence, "sequence"),
        _ => (AnchorKind::ProblemEntry, "problem"),
    };

    let records = crate::atlas_adapters::read_adapter(&adapter, Path::new(&input), &rev)
        .unwrap_or_else(|e| fail(&e));
    if records.is_empty() {
        fail(&format!(
            "adapter '{adapter}' yielded no records from {input}"
        ));
    }

    // Build content-addressed findings (deduped by id) + an anchor plan entry
    // per record. Fresh build each run — these source frontiers are regenerable.
    let mut findings = Vec::new();
    let mut plan: Vec<(String, Anchor)> = Vec::new();
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut id_by_extid: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    for rec in &records {
        let finding = crate::atlas_adapters::build_finding(rec, &adapter);
        let fid = finding.id.clone();
        if !seen.insert(fid.clone()) {
            continue; // duplicate content-address (same text+type+id)
        }
        id_by_extid
            .entry(rec.external_id.clone())
            .or_insert(fid.clone());
        findings.push(finding);
        plan.push((
            fid.clone(),
            Anchor {
                namespace: ns.clone(),
                id: rec.external_id.clone(),
                role: role.to_string(),
                kind,
                join_policy: JoinPolicy::HardIdentity,
                namespace_version: None,
                source_revision: Some(rev.clone()),
                statement_fingerprint: None,
            },
        ));
        // Secondary CROSS-namespace anchors (e.g. an Erdős-tagged FC formalization
        // also anchoring into `erdos`), so the same finding joins the canonical
        // problem cell under HardIdentity — the spine's statement-variant link.
        for (extra_ns, extra_id) in &rec.extra_anchors {
            plan.push((
                fid.clone(),
                Anchor {
                    namespace: extra_ns.clone(),
                    id: extra_id.clone(),
                    role: "problem".to_string(),
                    kind: AnchorKind::ProblemEntry,
                    join_policy: JoinPolicy::HardIdentity,
                    namespace_version: None,
                    source_revision: Some(rev.clone()),
                    statement_fingerprint: None,
                },
            ));
        }
    }

    // Second pass: resolve cross-problem `implies` edges now that every finding
    // id is known. A typed `implies` link from the source finding to the target
    // problem's finding lifts to a real erdos→erdos edge in `vela atlas`. Sparse.
    let mut edges = 0usize;
    for rec in &records {
        if rec.implies.is_empty() {
            continue;
        }
        let Some(src_id) = id_by_extid.get(&rec.external_id).cloned() else {
            continue;
        };
        for tgt_ext in &rec.implies {
            if let Some(tgt_id) = id_by_extid.get(tgt_ext)
                && let Some(f) = findings.iter_mut().find(|f| f.id == src_id)
            {
                f.add_link(
                    tgt_id,
                    "implies",
                    &format!("Lean: erdos_{} implies_erdos_{}", rec.external_id, tgt_ext),
                );
                edges += 1;
            }
        }
    }

    if dry {
        print_json(&json!({
            "dry_run": true, "adapter": adapter, "namespace": ns,
            "records": records.len(), "findings": findings.len(), "anchors": plan.len(),
            "cross_problem_edges": edges,
        }));
        return;
    }

    let mut project = vela_protocol::project::assemble(
        &format!("Atlas source: {adapter}"),
        findings,
        0,
        0,
        &format!("Native atlas source adapter ({adapter}) @ {rev}"),
    );

    let key = crate::cli_identity::resolve_signing_key(flag("--key").as_deref().map(Path::new));
    let anchored = anchor_findings(&mut project, plan, &actor, &key);

    let out_path = Path::new(&out);
    if let Some(parent) = out_path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .unwrap_or_else(|e| fail(&format!("create {}: {e}", parent.display())));
    }
    repo::save_to_path(out_path, &project).unwrap_or_else(|e| fail(&e));

    // Gate: the loader-is-reducer round-trip must hold. Findings ride as genesis
    // remnants (no introducing event); the anchor events replay cleanly.
    let reloaded = repo::load_from_path(out_path).unwrap_or_else(|e| fail(&e));
    let replay = vela_protocol::reducer::verify_replay(&reloaded);

    print_json(&json!({
        "ok": true, "adapter": adapter, "namespace": ns,
        "findings": project.findings.len(), "anchored": anchored,
        "cross_problem_edges": edges,
        "out": out, "verify_replay_ok": replay.ok, "signer": actor,
    }));
}

#[cfg(test)]
mod decl_graph_tests {
    use super::{is_decl_noise, load_decl_edges};

    #[test]
    fn noise_filter_drops_plumbing_keeps_lemmas() {
        // core types, typeclasses, instances, coercions, Decidable* -> noise.
        for n in [
            "Nat",
            "DecidableEq",
            "Finset",
            "LinearOrder",
            "Lattice",
            "instDistribLatticeOfLinearOrder",
            "SemilatticeInf.toPartialOrder",
        ] {
            assert!(is_decl_noise(n), "{n} should be noise");
        }
        // real declarations are kept.
        for n in [
            "Finset.univ",
            "Fintype.exists_card_fiber_lt_of_card_lt_mul",
            "Finset.exists_card_fiber_lt_of_card_lt_mul",
        ] {
            assert!(!is_decl_noise(n), "{n} should be kept");
        }
    }

    #[test]
    fn load_decl_edges_is_deterministic_and_deduped() {
        let dir = std::env::temp_dir().join(format!("vela_declgraph_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("edges.jsonl");
        // Two real edges (one duplicated) + two noise edges; whitespace-varied order.
        std::fs::write(
            &f,
            "{\"from\":\"A\",\"to\":\"B\",\"kind\":\"uses\"}\n\
             {\"from\":\"A\",\"to\":\"Nat\",\"kind\":\"uses\"}\n\
             {\"from\":\"A\",\"to\":\"B\",\"kind\":\"uses\"}\n\
             {\"from\":\"C\",\"to\":\"A\",\"kind\":\"uses\"}\n\
             {\"from\":\"C\",\"to\":\"DecidableEq\",\"kind\":\"uses\"}\n",
        )
        .unwrap();
        let p = f.to_str().unwrap();
        let a = load_decl_edges(p).unwrap();
        let b = load_decl_edges(p).unwrap();
        assert_eq!(a, b, "same input -> same output");
        // Noise dropped (Nat, DecidableEq), duplicate (A,B) collapsed, sorted.
        assert_eq!(
            a,
            vec![
                ("A".to_string(), "B".to_string()),
                ("C".to_string(), "A".to_string())
            ]
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
