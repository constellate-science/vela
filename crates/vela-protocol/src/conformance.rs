//! Conformance test runner — validates an implementation against test vectors.
//!
//! Reads JSON test vector files from a directory and runs each case against
//! Vela's actual implementation, reporting pass/fail for each.

use std::collections::HashSet;
use std::path::Path;

use colored::Colorize;

use crate::cli_style as style;

use crate::bundle::*;
use crate::confidence;
use crate::link;
use crate::observer;
use crate::project;
use crate::propagate::{self, PropagationAction};

/// Run all conformance test vectors in the given directory.
/// Returns (passed, failed) counts.
pub fn run(dir: &Path) -> (usize, usize) {
    let mut passed = 0usize;
    let mut failed = 0usize;

    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| {
            eprintln!(
                "{} failed to read directory {}: {e}",
                style::err_prefix(),
                dir.display()
            );
            std::process::exit(1);
        })
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "json"))
        .collect();
    entries.sort_by_key(|e| e.path());

    if entries.is_empty() {
        eprintln!("no .json test vector files found in {}", dir.display());
        std::process::exit(1);
    }

    for entry in &entries {
        let path = entry.path();
        let content = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            eprintln!(
                "{} failed to read {}: {e}",
                style::err_prefix(),
                path.display()
            );
            std::process::exit(1);
        });
        let suite: serde_json::Value = serde_json::from_str(&content).unwrap_or_else(|e| {
            eprintln!(
                "{} failed to parse {}: {e}",
                style::err_prefix(),
                path.display()
            );
            std::process::exit(1);
        });

        let suite_name = suite["suite"].as_str().unwrap_or("unknown");
        let cases = suite["cases"].as_array();

        if cases.is_none() {
            eprintln!("  no cases found in {}", path.display());
            continue;
        }

        println!();
        println!(
            "  {}",
            format!("SUITE · {suite_name}").to_uppercase().dimmed()
        );
        println!("  {}", style::tick_row(60));

        for case in cases.unwrap() {
            let name = case["name"].as_str().unwrap_or("unnamed");
            let input = &case["input"];
            let expected = &case["expected_output"];

            let result = match suite_name {
                "id-generation" => run_id_generation(input, expected),
                "link-inference" => run_link_inference(input, expected),
                "confidence-scoring" => run_confidence_scoring(input, expected),
                "retraction-propagation" => run_retraction_propagation(input, expected),
                "replication-cascade" => run_retraction_propagation(input, expected),
                "observer-policies" => run_observer_policies(input, expected),
                "directory-layout" => run_directory_layout(input, expected),
                "proposal-idempotency" => run_proposal_idempotency(input, expected),
                "note-provenance" => run_proposal_idempotency(input, expected),
                "registry-publish-pull" => run_registry_publish_pull(input, expected),
                "auto-apply-tier" => run_auto_apply_tier(input, expected),
                _ => {
                    eprintln!("  {} unknown suite: {suite_name}", style::err_prefix());
                    Err("unknown suite".into())
                }
            };

            match result {
                Ok(()) => {
                    println!("  {} {name}", style::ok("ok"));
                    passed += 1;
                }
                Err(msg) => {
                    println!("  {} {name}: {msg}", style::lost("lost"));
                    failed += 1;
                }
            }
        }
    }

    println!();
    if failed == 0 {
        println!(
            "  {} all {passed} conformance tests passed.",
            style::ok("ok")
        );
    } else {
        println!(
            "  {} {passed} passed, {failed} failed.",
            style::lost("lost")
        );
    }

    (passed, failed)
}

// ── ID generation ───────────────────────────────────────────────────────

fn run_id_generation(
    input: &serde_json::Value,
    expected: &serde_json::Value,
) -> Result<(), String> {
    let assertion: Assertion = serde_json::from_value(input["assertion"].clone())
        .map_err(|e| format!("parse assertion: {e}"))?;
    let evidence: Evidence = serde_json::from_value(input["evidence"].clone())
        .map_err(|e| format!("parse evidence: {e}"))?;
    let conditions: Conditions = serde_json::from_value(input["conditions"].clone())
        .map_err(|e| format!("parse conditions: {e}"))?;
    let confidence: Confidence = serde_json::from_value(input["confidence"].clone())
        .map_err(|e| format!("parse confidence: {e}"))?;
    let provenance: Provenance = serde_json::from_value(input["provenance"].clone())
        .map_err(|e| format!("parse provenance: {e}"))?;

    let flags = if input.get("flags").is_some() {
        serde_json::from_value(input["flags"].clone()).unwrap_or_else(|_| default_flags())
    } else {
        default_flags()
    };

    let bundle = FindingBundle::new(
        assertion, evidence, conditions, confidence, provenance, flags,
    );

    let expected_id = expected["id"].as_str().ok_or("missing expected id")?;
    if bundle.id != expected_id {
        return Err(format!("expected {expected_id}, got {}", bundle.id));
    }

    if let Some(len) = expected["id_length"].as_u64()
        && bundle.id.len() != len as usize
    {
        return Err(format!("expected id length {len}, got {}", bundle.id.len()));
    }

    if let Some(prefix) = expected["prefix"].as_str()
        && !bundle.id.starts_with(prefix)
    {
        return Err(format!("expected prefix {prefix}, got {}", &bundle.id[..3]));
    }

    Ok(())
}

// ── Link inference ──────────────────────────────────────────────────────

fn make_test_finding(v: &serde_json::Value) -> FindingBundle {
    let id = v["id"].as_str().unwrap_or("unknown").to_string();
    let direction = v["direction"].as_str().map(|s| s.to_string());
    let doi = v["doi"].as_str().map(|s| s.to_string());
    let year = v["year"].as_i64().unwrap_or(2020) as i32;
    let conf = v["confidence"].as_f64().unwrap_or(0.7);

    let entities: Vec<Entity> = v["entities"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .map(|e| {
                    let aliases: Vec<String> = e["aliases"]
                        .as_array()
                        .map(|a| {
                            a.iter()
                                .filter_map(|s| s.as_str().map(|s| s.to_string()))
                                .collect()
                        })
                        .unwrap_or_default();
                    Entity {
                        name: e["name"].as_str().unwrap_or("").to_string(),
                        entity_type: e["type"].as_str().unwrap_or("other").to_string(),
                        identifiers: serde_json::Map::new(),
                        canonical_id: None,
                        candidates: vec![],
                        aliases,
                        resolution_provenance: None,
                        resolution_confidence: 1.0,
                        resolution_method: None,
                        species_context: None,
                        needs_review: false,
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    FindingBundle {
        id,
        version: 1,
        previous_version: None,
        assertion: Assertion {
            text: "Test finding".to_string(),
            assertion_type: "mechanism".into(),
            entities,
            relation: None,
            direction,
            causal_claim: None,
            causal_evidence_grade: None,
        },
        evidence: Evidence {
            evidence_type: "experimental".into(),
            model_system: String::new(),
            species: None,
            method: String::new(),
            sample_size: None,
            effect_size: None,
            p_value: None,
            replicated: false,
            replication_count: None,
            evidence_spans: vec![],
        },
        conditions: Conditions {
            text: String::new(),
            species_verified: vec![],
            species_unverified: vec![],
            in_vitro: false,
            in_vivo: false,
            human_data: false,
            clinical_trial: false,
            concentration_range: None,
            duration: None,
            age_group: None,
            cell_type: None,
        },
        confidence: Confidence::raw(conf, "test", 0.85),
        provenance: Provenance {
            source_type: "published_paper".into(),
            doi,
            pmid: None,
            pmc: None,
            openalex_id: None,
            url: None,
            title: "Test".into(),
            authors: vec![],
            year: Some(year),
            journal: None,
            license: None,
            publisher: None,
            funders: vec![],
            extraction: Extraction::default(),
            review: None,
            citation_count: None,
        },
        flags: default_flags(),
        links: vec![],
        annotations: vec![],
        attachments: vec![],
        created: String::new(),
        updated: None,
        access_tier: crate::access_tier::AccessTier::Public,
    }
}

fn run_link_inference(
    input: &serde_json::Value,
    expected: &serde_json::Value,
) -> Result<(), String> {
    let findings_val = input["findings"]
        .as_array()
        .ok_or("missing findings array")?;

    let mut bundles: Vec<FindingBundle> = findings_val.iter().map(make_test_finding).collect();
    let count = link::deterministic_links(&mut bundles);

    let expected_count = expected["link_count"].as_u64().unwrap_or(0) as usize;
    if count != expected_count {
        return Err(format!("expected {expected_count} links, got {count}"));
    }

    if let Some(expected_links) = expected["links"].as_array() {
        for el in expected_links {
            let from_id = el["from"].as_str().unwrap_or("");
            let to_id = el["to"].as_str().unwrap_or("");
            let link_type = el["type"].as_str().unwrap_or("");
            let inferred_by = el["inferred_by"].as_str().unwrap_or("");

            let found = bundles.iter().any(|b| {
                b.id == from_id
                    && b.links.iter().any(|l| {
                        l.target == to_id
                            && l.link_type == link_type
                            && (inferred_by.is_empty() || l.inferred_by == inferred_by)
                    })
            });

            if !found {
                return Err(format!(
                    "expected link {from_id} -> {to_id} ({link_type}) not found"
                ));
            }

            // Check note_contains if present.
            if let Some(note_contains) = el["note_contains"].as_str() {
                let has_note = bundles.iter().any(|b| {
                    b.id == from_id
                        && b.links
                            .iter()
                            .any(|l| l.target == to_id && l.note.contains(note_contains))
                });
                if !has_note {
                    return Err(format!(
                        "link {from_id} -> {to_id} note does not contain '{note_contains}'"
                    ));
                }
            }
        }
    }

    Ok(())
}

// ── Confidence scoring ──────────────────────────────────────────────────

fn make_confidence_bundle(v: &serde_json::Value) -> FindingBundle {
    let score = v
        .get("seed_score")
        .and_then(|value| value.as_f64())
        .or_else(|| v.get("llm_score").and_then(|value| value.as_f64()))
        .unwrap_or(0.7);
    let citations = v["citation_count"].as_u64().unwrap_or(0);
    let year = v["year"].as_i64().unwrap_or(2020) as i32;
    let etype = v["evidence_type"].as_str().unwrap_or("experimental");
    let human = v["human_data"].as_bool().unwrap_or(false);
    let has_spans = v["has_evidence_spans"].as_bool().unwrap_or(false);

    let bundle = FindingBundle {
        id: "test".into(),
        version: 1,
        previous_version: None,
        assertion: Assertion {
            text: "Test".into(),
            assertion_type: "mechanism".into(),
            entities: vec![],
            relation: None,
            direction: None,
            causal_claim: None,
            causal_evidence_grade: None,
        },
        evidence: Evidence {
            evidence_type: etype.into(),
            model_system: String::new(),
            species: None,
            method: String::new(),
            sample_size: None,
            effect_size: None,
            p_value: None,
            replicated: false,
            replication_count: None,
            evidence_spans: if has_spans {
                vec![serde_json::json!({"text": "span"})]
            } else {
                vec![]
            },
        },
        conditions: Conditions {
            text: String::new(),
            species_verified: vec![],
            species_unverified: vec![],
            in_vitro: false,
            in_vivo: false,
            human_data: human,
            clinical_trial: false,
            concentration_range: None,
            duration: None,
            age_group: None,
            cell_type: None,
        },
        confidence: Confidence::raw(score, "seeded prior", 0.85),
        provenance: Provenance {
            source_type: "published_paper".into(),
            doi: None,
            pmid: None,
            pmc: None,
            openalex_id: None,
            url: None,
            title: "Test".into(),
            authors: vec![],
            year: Some(year),
            journal: None,
            license: None,
            publisher: None,
            funders: vec![],
            extraction: Extraction::default(),
            review: None,
            citation_count: Some(citations),
        },
        flags: default_flags(),
        links: vec![],
        annotations: vec![],
        attachments: vec![],
        created: String::new(),
        updated: None,
        access_tier: crate::access_tier::AccessTier::Public,
    };

    #[allow(clippy::let_and_return)]
    bundle
}

fn run_confidence_scoring(
    input: &serde_json::Value,
    expected: &serde_json::Value,
) -> Result<(), String> {
    // Check if this is a comparison test.
    if input["comparison"].as_bool().unwrap_or(false) {
        let mut bundle_a = make_confidence_bundle(&input["finding_a"]);
        let mut bundle_b = make_confidence_bundle(&input["finding_b"]);
        bundle_a.id = "a".into();
        bundle_b.id = "b".into();
        let mut bundles = vec![bundle_a, bundle_b];
        confidence::ground_confidence(&mut bundles);

        if expected["a_higher_than_b"].as_bool().unwrap_or(false)
            && bundles[0].confidence.score <= bundles[1].confidence.score
        {
            return Err(format!(
                "expected a ({:.3}) > b ({:.3})",
                bundles[0].confidence.score, bundles[1].confidence.score
            ));
        }
        return Ok(());
    }

    let bundle = make_confidence_bundle(input);
    let mut bundles = vec![bundle];
    confidence::ground_confidence(&mut bundles);
    let score = bundles[0].confidence.score;

    if let Some(range) = expected["score_range"].as_array() {
        let lo = range[0].as_f64().unwrap_or(0.0);
        let hi = range[1].as_f64().unwrap_or(1.0);
        if score < lo || score > hi {
            return Err(format!("score {score:.3} not in range [{lo}, {hi}]"));
        }
    }

    if let Some(floor) = expected["score_at_least"].as_f64()
        && score < floor
    {
        return Err(format!("score {score:.3} below floor {floor}"));
    }

    if let Some(ceil) = expected["score_at_most"].as_f64()
        && score > ceil
    {
        return Err(format!("score {score:.3} above ceiling {ceil}"));
    }

    if let Some(lower) = expected["score_lower_than"].as_f64()
        && score >= lower
    {
        return Err(format!("expected score < {lower}, got {score:.3}"));
    }

    if let Some(higher) = expected["score_higher_than"].as_f64()
        && score <= higher
    {
        return Err(format!("expected score > {higher}, got {score:.3}"));
    }

    Ok(())
}

// ── Simulated dependency impact ─────────────────────────────────────────

fn run_retraction_propagation(
    input: &serde_json::Value,
    expected: &serde_json::Value,
) -> Result<(), String> {
    let findings_val = input["findings"]
        .as_array()
        .ok_or("missing findings array")?;

    let bundles: Vec<FindingBundle> = findings_val
        .iter()
        .map(|v| {
            let id = v["id"].as_str().unwrap_or("").to_string();
            let conf = v["confidence"].as_f64().unwrap_or(0.7);
            let links: Vec<Link> = v["links"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .map(|l| Link {
                            target: l["target"].as_str().unwrap_or("").to_string(),
                            link_type: l["type"].as_str().unwrap_or("depends").to_string(),
                            note: String::new(),
                            inferred_by: "test".into(),
                            created_at: String::new(),
                            mechanism: None,
                        })
                        .collect()
                })
                .unwrap_or_default();

            FindingBundle {
                id,
                version: 1,
                previous_version: None,
                assertion: Assertion {
                    text: "Test".into(),
                    assertion_type: "mechanism".into(),
                    entities: vec![],
                    relation: None,
                    direction: None,
                    causal_claim: None,
                    causal_evidence_grade: None,
                },
                evidence: Evidence {
                    evidence_type: "experimental".into(),
                    model_system: String::new(),
                    species: None,
                    method: String::new(),
                    sample_size: None,
                    effect_size: None,
                    p_value: None,
                    replicated: false,
                    replication_count: None,
                    evidence_spans: vec![],
                },
                conditions: Conditions {
                    text: String::new(),
                    species_verified: vec![],
                    species_unverified: vec![],
                    in_vitro: false,
                    in_vivo: false,
                    human_data: false,
                    clinical_trial: false,
                    concentration_range: None,
                    duration: None,
                    age_group: None,
                    cell_type: None,
                },
                confidence: Confidence::raw(conf, "test", 0.85),
                provenance: Provenance {
                    source_type: "published_paper".into(),
                    doi: None,
                    pmid: None,
                    pmc: None,
                    openalex_id: None,
                    url: None,
                    title: "Test".into(),
                    authors: vec![],
                    year: Some(2025),
                    journal: None,
                    license: None,
                    publisher: None,
                    funders: vec![],
                    extraction: Extraction::default(),
                    review: None,
                    citation_count: None,
                },
                flags: default_flags(),
                links,
                annotations: vec![],
                attachments: vec![],
                created: String::new(),
                updated: None,
                access_tier: crate::access_tier::AccessTier::Public,
            }
        })
        .collect();

    let action_val = &input["action"];
    let finding_id = action_val["finding_id"].as_str().unwrap_or("");
    let action_type = action_val["type"].as_str().unwrap_or("");

    let mut corr = project::assemble("test", bundles, 1, 0, "test");

    // v0.36.2: ingest optional `replications` array so the harness can
    // exercise the `ReplicationOutcome` cascade. Each entry produces a
    // canonical `Replication` whose target field aligns with a finding
    // id from the case input.
    if let Some(reps) = input["replications"].as_array() {
        for r in reps {
            let target = r["target_finding"].as_str().unwrap_or("").to_string();
            let outcome = r["outcome"].as_str().unwrap_or("").to_string();
            let attempted_by = r["attempted_by"].as_str().unwrap_or("test:lab").to_string();
            corr.replications.push(crate::bundle::Replication {
                id: format!("vrep_test_{}_{}", target.replace("vf_", ""), outcome),
                target_finding: target,
                attempted_by,
                outcome,
                evidence: Evidence {
                    evidence_type: "experimental".into(),
                    model_system: String::new(),
                    species: None,
                    method: "replication_attempt".into(),
                    sample_size: None,
                    effect_size: None,
                    p_value: None,
                    replicated: false,
                    replication_count: None,
                    evidence_spans: vec![],
                },
                conditions: Conditions {
                    text: String::new(),
                    species_verified: vec![],
                    species_unverified: vec![],
                    in_vitro: false,
                    in_vivo: false,
                    human_data: false,
                    clinical_trial: false,
                    concentration_range: None,
                    duration: None,
                    age_group: None,
                    cell_type: None,
                },
                provenance: Provenance {
                    source_type: "published_paper".into(),
                    doi: None,
                    pmid: None,
                    pmc: None,
                    openalex_id: None,
                    url: None,
                    title: "test".into(),
                    authors: vec![],
                    year: None,
                    journal: None,
                    license: None,
                    publisher: None,
                    funders: vec![],
                    extraction: Extraction::default(),
                    review: None,
                    citation_count: None,
                },
                notes: String::new(),
                created: String::new(),
                previous_attempt: None,
            });
        }
    }

    let action = match action_type {
        "retracted" => PropagationAction::Retracted,
        "confidence_reduced" => {
            let new_score = action_val["new_score"].as_f64().unwrap_or(0.5);
            PropagationAction::ConfidenceReduced { new_score }
        }
        "replication_outcome" => {
            let outcome = action_val["outcome"]
                .as_str()
                .unwrap_or("replicated")
                .to_string();
            let vrep_id = action_val["vrep_id"]
                .as_str()
                .unwrap_or("vrep_testxxxx")
                .to_string();
            PropagationAction::ReplicationOutcome { outcome, vrep_id }
        }
        _ => return Err(format!("unknown action type: {action_type}")),
    };

    let result = propagate::propagate_correction(&mut corr, finding_id, action);

    if let Some(retracted) = expected["source_retracted"].as_bool()
        && retracted
    {
        let source = corr.findings.iter().find(|f| f.id == finding_id);
        if let Some(s) = source
            && !s.flags.retracted
        {
            return Err("source finding not marked as retracted".into());
        }
    }

    if let Some(count) = expected["affected_count"].as_u64()
        && result.affected != count as usize
    {
        return Err(format!(
            "expected {count} affected, got {}",
            result.affected
        ));
    }

    if let Some(max) = expected["affected_at_most"].as_u64()
        && result.affected > max as usize
    {
        return Err(format!(
            "expected at most {max} affected, got {}",
            result.affected
        ));
    }

    if let Some(conf) = expected["source_confidence"].as_f64() {
        let source = corr.findings.iter().find(|f| f.id == finding_id);
        if let Some(s) = source
            && (s.confidence.score - conf).abs() > 0.001
        {
            return Err(format!(
                "expected source confidence {conf}, got {}",
                s.confidence.score
            ));
        }
    }

    if let Some(expected_flags) = expected["flag_types"].as_array() {
        let actual_flags: Vec<String> = result
            .events
            .iter()
            .filter_map(|e| match &e.action {
                crate::bundle::ReviewAction::Flagged { flag_type } => Some(flag_type.clone()),
                _ => None,
            })
            .collect();
        for ef in expected_flags {
            let want = ef.as_str().unwrap_or("");
            if !actual_flags.iter().any(|a| a == want) {
                return Err(format!(
                    "expected flag '{want}' not found in events: {actual_flags:?}"
                ));
            }
        }
    }

    if let Some(contested) = expected["contested_findings"].as_array() {
        for cid in contested {
            let cid_str = cid.as_str().unwrap_or("");
            let f = corr.findings.iter().find(|f| f.id == cid_str);
            if let Some(f) = f {
                if !f.flags.contested {
                    return Err(format!("finding {cid_str} not marked as contested"));
                }
            } else {
                return Err(format!("finding {cid_str} not found"));
            }
        }
    }

    Ok(())
}

// ── Observer policies ───────────────────────────────────────────────────

fn make_observer_finding(v: &serde_json::Value) -> FindingBundle {
    let id = v["id"].as_str().unwrap_or("").to_string();
    let conf = v["confidence"].as_f64().unwrap_or(0.7);
    let clinical_trial = v["clinical_trial"].as_bool().unwrap_or(false);
    let human_data = v["human_data"].as_bool().unwrap_or(false);
    let replicated = v["replicated"].as_bool().unwrap_or(false);
    let year = v["year"].as_i64().unwrap_or(2020) as i32;
    let citations = v["citation_count"].as_u64().unwrap_or(0);
    let has_spans = v["has_spans"].as_bool().unwrap_or(false);
    let assertion_type = v["assertion_type"]
        .as_str()
        .unwrap_or("mechanism")
        .to_string();
    let gap = v["gap"].as_bool().unwrap_or(false);
    let negative_space = v["negative_space"].as_bool().unwrap_or(false);

    FindingBundle {
        id,
        version: 1,
        previous_version: None,
        assertion: Assertion {
            text: "Test assertion".to_string(),
            assertion_type,
            entities: vec![],
            relation: None,
            direction: None,
            causal_claim: None,
            causal_evidence_grade: None,
        },
        evidence: Evidence {
            evidence_type: "experimental".into(),
            model_system: String::new(),
            species: None,
            method: String::new(),
            sample_size: None,
            effect_size: None,
            p_value: None,
            replicated,
            replication_count: None,
            evidence_spans: if has_spans {
                vec![serde_json::json!({"text": "span"})]
            } else {
                vec![]
            },
        },
        conditions: Conditions {
            text: String::new(),
            species_verified: vec![],
            species_unverified: vec![],
            in_vitro: false,
            in_vivo: false,
            human_data,
            clinical_trial,
            concentration_range: None,
            duration: None,
            age_group: None,
            cell_type: None,
        },
        confidence: Confidence::raw(conf, "test", 0.85),
        provenance: Provenance {
            source_type: "published_paper".into(),
            doi: None,
            pmid: None,
            pmc: None,
            openalex_id: None,
            url: None,
            title: "Test".into(),
            authors: vec![],
            year: Some(year),
            journal: None,
            license: None,
            publisher: None,
            funders: vec![],
            extraction: Extraction::default(),
            review: None,
            citation_count: Some(citations),
        },
        flags: Flags {
            gap,
            negative_space,
            ..Flags::default()
        },
        links: vec![],
        annotations: vec![],
        attachments: vec![],
        created: String::new(),
        updated: None,
        access_tier: crate::access_tier::AccessTier::Public,
    }
}

fn run_observer_policies(
    input: &serde_json::Value,
    expected: &serde_json::Value,
) -> Result<(), String> {
    let policy_name = input["policy"].as_str().ok_or("missing policy name")?;
    let findings_val = input["findings"]
        .as_array()
        .ok_or("missing findings array")?;

    let bundles: Vec<FindingBundle> = findings_val.iter().map(make_observer_finding).collect();

    let policy = observer::policy_by_name(policy_name)
        .ok_or_else(|| format!("unknown policy: {policy_name}"))?;

    let view = observer::observe(&bundles, &[], &policy);

    if let Some(count) = expected["hidden_count"].as_u64()
        && view.hidden != count as usize
    {
        return Err(format!("expected {count} hidden, got {}", view.hidden));
    }

    if let Some(all_visible) = expected["all_visible"].as_bool()
        && all_visible
        && view.hidden != 0
    {
        return Err(format!("expected all visible, got {} hidden", view.hidden));
    }

    if let Some(ranking) = expected["ranking"].as_array() {
        let view_ids: Vec<&str> = view
            .findings
            .iter()
            .map(|f| f.finding_id.as_str())
            .collect();
        for (i, expected_id) in ranking.iter().enumerate() {
            let eid = expected_id.as_str().unwrap_or("");
            if i >= view_ids.len() {
                return Err(format!(
                    "expected rank {} to be {eid}, but only {} visible",
                    i + 1,
                    view_ids.len()
                ));
            }
            if view_ids[i] != eid {
                return Err(format!(
                    "expected rank {} to be {eid}, got {}",
                    i + 1,
                    view_ids[i]
                ));
            }
        }
    }

    if let Some(hidden_ids) = expected["hidden_ids"].as_array() {
        let visible: HashSet<&str> = view
            .findings
            .iter()
            .map(|f| f.finding_id.as_str())
            .collect();
        for hid in hidden_ids {
            let hid_str = hid.as_str().unwrap_or("");
            if visible.contains(hid_str) {
                return Err(format!("{hid_str} should be hidden but is visible"));
            }
        }
    }

    if let Some(true) = expected["f1_rank_better_than_f2"].as_bool() {
        let f1_rank = view
            .findings
            .iter()
            .find(|f| f.finding_id == "f1")
            .map(|f| f.rank);
        let f2_rank = view
            .findings
            .iter()
            .find(|f| f.finding_id == "f2")
            .map(|f| f.rank);
        match (f1_rank, f2_rank) {
            (Some(r1), Some(r2)) if r1 < r2 => {}
            (Some(r1), Some(r2)) => {
                return Err(format!("expected f1 (rank {r1}) < f2 (rank {r2})"));
            }
            _ => return Err("f1 or f2 not found in visible findings".into()),
        }
    }

    Ok(())
}

// ── Directory layout ────────────────────────────────────────────────────

fn run_directory_layout(
    input: &serde_json::Value,
    expected: &serde_json::Value,
) -> Result<(), String> {
    // This is a structural test — we verify the expected paths list is consistent
    // with the inputs, not against the filesystem.
    let finding_count = input["finding_count"].as_u64().unwrap_or(0) as usize;

    if let Some(paths) = expected["required_paths"].as_array() {
        // Must have .vela/config.toml
        let has_config = paths
            .iter()
            .any(|p| p.as_str() == Some(".vela/config.toml"));
        if !has_config {
            return Err("required_paths missing .vela/config.toml".into());
        }

        for required in [".vela/findings/", ".vela/events/", ".vela/proposals/"] {
            let present = paths.iter().any(|p| p.as_str() == Some(required));
            if finding_count == 0 && !present {
                return Err(format!("required_paths missing {required}"));
            }
        }

        // Count finding files.
        let finding_files: Vec<_> = paths
            .iter()
            .filter_map(|p| p.as_str())
            .filter(|p| p.starts_with(".vela/findings/vf_"))
            .collect();

        if finding_files.len() != finding_count {
            return Err(format!(
                "expected {} finding files, got {}",
                finding_count,
                finding_files.len()
            ));
        }
    }

    if let Some(count) = expected["finding_file_count"].as_u64()
        && count as usize != finding_count
    {
        return Err(format!(
            "finding_file_count {count} != input finding_count {finding_count}"
        ));
    }

    Ok(())
}

// ── Helpers ─────────────────────────────────────────────────────────────

fn default_flags() -> Flags {
    Flags::default()
}

// ── Phase U (v0.5): proposal-idempotency suite ─────────────────────────

fn run_proposal_idempotency(
    input: &serde_json::Value,
    expected: &serde_json::Value,
) -> Result<(), String> {
    use crate::proposals::{StateProposal, proposal_id};
    // Construct a proposal with a fixed `created_at`; the substrate
    // claim is that the resulting `vpr_…` does NOT depend on
    // `created_at`. To prove it, compute the id with two distinct
    // timestamps and assert equality.
    let mut proposal_a = StateProposal {
        schema: input["schema"].as_str().unwrap_or("").to_string(),
        id: String::new(),
        kind: input["kind"].as_str().unwrap_or("").to_string(),
        target: serde_json::from_value(input["target"].clone())
            .map_err(|e| format!("parse target: {e}"))?,
        actor: serde_json::from_value(input["actor"].clone())
            .map_err(|e| format!("parse actor: {e}"))?,
        created_at: "2026-01-01T00:00:00Z".to_string(),
        drafted_at: None,
        reason: input["reason"].as_str().unwrap_or("").to_string(),
        payload: input["payload"].clone(),
        source_refs: input["source_refs"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default(),
        status: "pending_review".to_string(),
        reviewed_by: None,
        reviewed_at: None,
        decision_reason: None,
        applied_event_id: None,
        caveats: input["caveats"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default(),
        agent_run: None,
    };
    let id_a = proposal_id(&proposal_a);

    let mut proposal_b = proposal_a.clone();
    proposal_b.created_at = "2099-12-31T23:59:59Z".to_string();
    let id_b = proposal_id(&proposal_b);

    if id_a != id_b {
        return Err(format!(
            "proposal_id depends on created_at: {id_a} vs {id_b}"
        ));
    }

    proposal_a.id = id_a.clone();
    let prefix = expected["prefix"].as_str().unwrap_or("vpr_");
    if !proposal_a.id.starts_with(prefix) {
        return Err(format!(
            "id '{}' does not start with '{prefix}'",
            proposal_a.id
        ));
    }
    if let Some(expected_len) = expected["id_length"].as_u64()
        && proposal_a.id.len() as u64 != expected_len
    {
        return Err(format!(
            "id length {} != expected {expected_len}",
            proposal_a.id.len()
        ));
    }
    if let Some(expected_id) = expected["id"].as_str()
        && proposal_a.id != expected_id
    {
        return Err(format!(
            "id '{}' != expected '{expected_id}'",
            proposal_a.id
        ));
    }
    Ok(())
}

// ── Phase δ (v0.6): auto-apply-tier suite ──────────────────────────────

fn run_auto_apply_tier(
    input: &serde_json::Value,
    expected: &serde_json::Value,
) -> Result<(), String> {
    use crate::sign::{ActorRecord, actor_can_auto_apply};
    let tier = input["tier"].as_str().map(String::from);
    let kind = input["kind"]
        .as_str()
        .ok_or("auto-apply-tier input missing `kind`")?;
    let actor = ActorRecord {
        id: "test".to_string(),
        public_key: "0".repeat(64),
        algorithm: "ed25519".to_string(),
        created_at: "2026-04-25T00:00:00Z".to_string(),
        tier,
        orcid: None,
        access_clearance: None,
        revoked_at: None,
        revoked_reason: None,
    };
    let actual = actor_can_auto_apply(&actor, kind);
    let want = expected["permits"]
        .as_bool()
        .ok_or("auto-apply-tier expected.permits must be a boolean")?;
    if actual != want {
        return Err(format!(
            "actor_can_auto_apply(tier={:?}, kind={}) returned {}; expected {}",
            input["tier"], kind, actual, want
        ));
    }
    Ok(())
}

// ── Phase U (v0.5): registry-publish-pull suite ────────────────────────

fn run_registry_publish_pull(
    input: &serde_json::Value,
    expected: &serde_json::Value,
) -> Result<(), String> {
    use crate::registry::{RegistryEntry, entry_signing_bytes};
    use sha2::{Digest, Sha256};
    let entry: RegistryEntry = serde_json::from_value({
        let mut v = input.clone();
        v["signature"] = serde_json::Value::String(String::new());
        v
    })
    .map_err(|e| format!("parse entry: {e}"))?;
    let bytes = entry_signing_bytes(&entry)?;
    let actual_hash = hex::encode(Sha256::digest(&bytes));
    if let Some(expected_hash) = expected["preimage_sha256"].as_str()
        && actual_hash != expected_hash
    {
        return Err(format!(
            "canonical preimage sha256 mismatch: actual={actual_hash}, expected={expected_hash}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_flags_are_all_false() {
        let f = default_flags();
        assert!(!f.gap);
        assert!(!f.retracted);
        assert!(!f.contested);
    }
}
