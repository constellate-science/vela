//! `cmd_causal` and its handler logic, split out of cli.rs.

use crate::cli::{fail, fail_return};

use crate::cli_commands::CausalAction;
use vela_protocol::cli_style as style;
use vela_protocol::repo;

use colored::Colorize;
use serde_json::json;

/// v0.40: Causal-typing audit over a frontier.
pub(crate) fn cmd_causal(action: CausalAction) {
    use vela_edge::causal_reasoning;

    match action {
        CausalAction::Audit {
            frontier,
            problems_only,
            json,
        } => {
            let project = repo::load_from_path(&frontier).unwrap_or_else(|e| fail_return(&e));
            let mut entries = causal_reasoning::audit_frontier(&project);
            if problems_only {
                entries.retain(|e| e.verdict.needs_reviewer_attention());
            }
            let summary = causal_reasoning::summarize_audit(&entries);

            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": true,
                        "command": "causal.audit",
                        "frontier": frontier.display().to_string(),
                        "summary": summary,
                        "entries": entries,
                    }))
                    .expect("serialize causal.audit")
                );
                return;
            }

            println!();
            println!(
                "  {}",
                format!("VELA · CAUSAL · AUDIT · {}", frontier.display())
                    .to_uppercase()
                    .dimmed()
            );
            println!("  {}", style::tick_row(60));
            println!(
                "  total: {}  identified: {}  conditional: {}  underidentified: {}  underdetermined: {}",
                summary.total,
                summary.identified,
                summary.conditional,
                summary.underidentified,
                summary.underdetermined,
            );
            if entries.is_empty() {
                println!("  (no entries to report)");
                return;
            }
            for e in &entries {
                let chip = match e.verdict {
                    vela_edge::causal_reasoning::Identifiability::Identified => style::ok("identified"),
                    vela_edge::causal_reasoning::Identifiability::Conditional => {
                        style::warn("conditional")
                    }
                    vela_edge::causal_reasoning::Identifiability::Underidentified => {
                        style::lost("underidentified")
                    }
                    vela_edge::causal_reasoning::Identifiability::Underdetermined => {
                        style::warn("underdetermined")
                    }
                };
                let claim = e
                    .causal_claim
                    .map_or("none".to_string(), |c| format!("{c:?}").to_lowercase());
                let grade = e
                    .causal_evidence_grade
                    .map_or("none".to_string(), |g| format!("{g:?}").to_lowercase());
                println!();
                println!("  {chip}  {}  ({}/{})", e.finding_id, claim, grade);
                let assertion_short: String = e.assertion_text.chars().take(78).collect();
                println!("    {assertion_short}");
                println!("    {} {}", style::ok("why:"), e.rationale);
                if e.verdict.needs_reviewer_attention()
                    || matches!(
                        e.verdict,
                        vela_edge::causal_reasoning::Identifiability::Underdetermined
                    )
                {
                    println!("    {} {}", style::ok("fix:"), e.remediation);
                }
            }
        }
        CausalAction::Effect {
            frontier,
            source,
            on: target,
            json,
        } => {
            use vela_protocol::causal_graph::{CausalEffectVerdict, identify_effect};

            let project = repo::load_from_path(&frontier).unwrap_or_else(|e| fail_return(&e));
            let verdict = identify_effect(&project, &source, &target);

            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": true,
                        "command": "causal.effect",
                        "frontier": frontier.display().to_string(),
                        "source": source,
                        "target": target,
                        "verdict": verdict,
                    }))
                    .expect("serialize causal.effect")
                );
                return;
            }

            println!();
            println!(
                "  {}",
                format!("VELA · CAUSAL · EFFECT · {} → {}", source, target)
                    .to_uppercase()
                    .dimmed()
            );
            println!("  {}", style::tick_row(60));
            match verdict {
                CausalEffectVerdict::Identified {
                    adjustment_set,
                    back_door_paths_considered,
                } => {
                    if adjustment_set.is_empty() {
                        println!(
                            "  {}  no back-door adjustment needed",
                            style::ok("identified")
                        );
                    } else {
                        println!("  {}  identified by adjusting on:", style::ok("identified"));
                        for z in &adjustment_set {
                            println!("    · {z}");
                        }
                    }
                    println!(
                        "  back-door paths considered: {}",
                        back_door_paths_considered
                    );
                }
                CausalEffectVerdict::IdentifiedByFrontDoor { mediator_set } => {
                    println!(
                        "  {}  identified via front-door criterion (Pearl 1995 §3.3)",
                        style::ok("identified")
                    );
                    println!("  mediators that intercept all directed paths:");
                    for m in &mediator_set {
                        println!("    · {m}");
                    }
                    println!(
                        "  applies when source-target confounders are unobserved but the mediator chain is."
                    );
                }
                CausalEffectVerdict::NoCausalPath { reason } => {
                    println!("  {}  no causal path: {reason}", style::warn("no_path"));
                }
                CausalEffectVerdict::Underidentified {
                    unblocked_back_door_paths,
                    candidates_tried,
                } => {
                    println!(
                        "  {}  no observational adjustment set found ({} candidates tried)",
                        style::lost("underidentified"),
                        candidates_tried
                    );
                    println!("  open back-door paths:");
                    for path in unblocked_back_door_paths.iter().take(5) {
                        println!("    · {}", path.join(" — "));
                    }
                    println!(
                        "  remediation: either intervene experimentally on {source}, or extend the link graph to make a confounder observable."
                    );
                }
                CausalEffectVerdict::UnknownNode { which } => {
                    fail(&which);
                }
            }
            println!();
        }
        CausalAction::Graph {
            frontier,
            node,
            json,
        } => {
            use vela_protocol::causal_graph::CausalGraph;
            let project = repo::load_from_path(&frontier).unwrap_or_else(|e| fail_return(&e));
            let graph = CausalGraph::from_project(&project);

            // Build a serializable view: each node with its parents
            // and children. Optionally restrict to a single node.
            let nodes: Vec<&str> = if let Some(n) = node.as_deref() {
                if !graph.contains(n) {
                    fail(&format!("node not in frontier: {n}"));
                }
                vec![n]
            } else {
                project.findings.iter().map(|f| f.id.as_str()).collect()
            };

            if json {
                let payload: Vec<_> = nodes
                    .iter()
                    .map(|n| {
                        let parents: Vec<&str> = graph.parents_of(n).collect();
                        let children: Vec<&str> = graph.children_of(n).collect();
                        json!({
                            "node": n,
                            "parents": parents,
                            "children": children,
                        })
                    })
                    .collect();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": true,
                        "command": "causal.graph",
                        "node_count": graph.node_count(),
                        "edge_count": graph.edge_count(),
                        "nodes": payload,
                    }))
                    .expect("serialize causal.graph")
                );
                return;
            }

            println!();
            println!(
                "  {}",
                format!("VELA · CAUSAL · GRAPH · {}", frontier.display())
                    .to_uppercase()
                    .dimmed()
            );
            println!("  {}", style::tick_row(60));
            println!(
                "  {} nodes · {} edges",
                graph.node_count(),
                graph.edge_count()
            );
            println!();
            for n in &nodes {
                let parents: Vec<&str> = graph.parents_of(n).collect();
                let children: Vec<&str> = graph.children_of(n).collect();
                if parents.is_empty() && children.is_empty() && nodes.len() > 1 {
                    continue; // hide isolated nodes when listing all
                }
                println!("  {n}");
                if !parents.is_empty() {
                    println!("    parents:  {}", parents.join(", "));
                }
                if !children.is_empty() {
                    println!("    children: {}", children.join(", "));
                }
            }
        }
        CausalAction::Counterfactual {
            frontier,
            intervene_on,
            set_to,
            target,
            json,
        } => {
            use vela_edge::counterfactual::{
                CounterfactualQuery, CounterfactualVerdict, answer_counterfactual,
            };

            let project = repo::load_from_path(&frontier).unwrap_or_else(|e| fail_return(&e));
            let query = CounterfactualQuery {
                intervene_on: intervene_on.clone(),
                set_to,
                target: target.clone(),
            };
            let verdict = answer_counterfactual(&project, &query);

            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": true,
                        "command": "causal.counterfactual",
                        "frontier": frontier.display().to_string(),
                        "query": query,
                        "verdict": verdict,
                    }))
                    .expect("serialize causal.counterfactual")
                );
                return;
            }

            println!();
            println!(
                "  {}",
                format!(
                    "VELA · CAUSAL · COUNTERFACTUAL · do({intervene_on} := {set_to:.3}) → {target}"
                )
                .to_uppercase()
                .dimmed()
            );
            println!("  {}", style::tick_row(72));
            match verdict {
                CounterfactualVerdict::Resolved {
                    factual,
                    counterfactual,
                    delta,
                    paths_used,
                } => {
                    println!(
                        "  {}  factual: {factual:.3}  counterfactual: {counterfactual:.3}  delta: {delta:+.3}",
                        style::ok("resolved")
                    );
                    println!(
                        "  twin-network propagation through {} causal path(s):",
                        paths_used.len()
                    );
                    for p in paths_used.iter().take(5) {
                        println!("    · {}", p.join(" → "));
                    }
                    println!(
                        "  reading: \"if {intervene_on}'s confidence had been {set_to:.3} \
                        instead of factual, {target}'s confidence would shift by {delta:+.3}.\""
                    );
                }
                CounterfactualVerdict::MechanismUnspecified { unspecified_edges } => {
                    println!(
                        "  {}  causal path exists but {} edge(s) lack a mechanism annotation",
                        style::warn("mechanism_unspecified"),
                        unspecified_edges.len()
                    );
                    for (parent, child) in unspecified_edges.iter().take(8) {
                        println!("    · {parent} → {child}");
                    }
                    println!(
                        "  remediation: annotate one of the link mechanisms (linear / monotonic / threshold / saturating)."
                    );
                }
                CounterfactualVerdict::NoCausalPath { factual } => {
                    println!(
                        "  {}  no directed path from {intervene_on} to {target}; counterfactual = factual = {factual:.3}",
                        style::warn("no_path")
                    );
                }
                CounterfactualVerdict::UnknownNode { which } => {
                    fail(&format!("node not in frontier: {which}"));
                }
                CounterfactualVerdict::InvalidIntervention { reason } => {
                    fail(&reason);
                }
            }
            println!();
        }
    }
}
