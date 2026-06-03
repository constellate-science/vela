use serde_json::json;
use vela_protocol::bundle::{
    Assertion, Conditions, Confidence, ConfidenceKind, ConfidenceMethod, Evidence, Extraction,
    FindingBundle, Flags, Link, Provenance,
};
use vela_protocol::events::{self, FindingEventInput, NULL_HASH};
use vela_protocol::impact;
use vela_protocol::project;

fn finding(label: &str) -> FindingBundle {
    let assertion = Assertion {
        text: format!("Impact fixture finding {label}"),
        assertion_type: "mechanism".to_string(),
        entities: Vec::new(),
        relation: None,
        direction: None,
        causal_claim: None,
        causal_evidence_grade: None,
    };
    let provenance = Provenance {
        source_type: "published_paper".to_string(),
        doi: Some(format!("10.0000/impact.{label}")),
        pmid: None,
        pmc: None,
        openalex_id: None,
        url: Some(format!("https://example.org/impact/{label}")),
        title: format!("Impact fixture {label}"),
        authors: Vec::new(),
        year: Some(2026),
        journal: None,
        license: None,
        publisher: None,
        funders: Vec::new(),
        extraction: Extraction::default(),
        review: None,
        citation_count: None,
    };
    let mut bundle = FindingBundle::new(
        assertion,
        Evidence {
            evidence_type: "experimental".to_string(),
            model_system: "human".to_string(),
            species: Some("Homo sapiens".to_string()),
            method: "manual".to_string(),
            sample_size: None,
            effect_size: None,
            p_value: None,
            replicated: false,
            replication_count: None,
            evidence_spans: Vec::new(),
        },
        Conditions {
            text: "human BBB context".to_string(),
            species_verified: vec!["Homo sapiens".to_string()],
            species_unverified: Vec::new(),
            in_vitro: false,
            in_vivo: false,
            human_data: true,
            clinical_trial: false,
            concentration_range: None,
            duration: None,
            age_group: None,
            cell_type: None,
        },
        Confidence {
            kind: ConfidenceKind::FrontierEpistemic,
            score: 0.5,
            basis: "fixture".to_string(),
            method: ConfidenceMethod::ExpertJudgment,
            components: None,
            extraction_confidence: 1.0,
        },
        provenance,
        Flags::default(),
    );
    bundle.created = "2026-05-07T00:00:00Z".to_string();
    bundle
}

#[test]
fn impact_report_includes_direct_and_transitive_dependents_without_mutation() {
    let root = finding("root");
    let mut child = finding("child");
    let mut grandchild = finding("grandchild");
    child.links.push(Link {
        target: root.id.clone(),
        link_type: "depends".to_string(),
        note: "child depends on root".to_string(),
        inferred_by: "test".to_string(),
        created_at: "2026-05-07T00:00:00Z".to_string(),
        mechanism: None,
    });
    grandchild.links.push(Link {
        target: child.id.clone(),
        link_type: "supports".to_string(),
        note: "grandchild follows child".to_string(),
        inferred_by: "test".to_string(),
        created_at: "2026-05-07T00:00:00Z".to_string(),
        mechanism: None,
    });
    let mut frontier = project::assemble(
        "impact frontier",
        vec![root.clone(), child.clone(), grandchild.clone()],
        0,
        0,
        "test",
    );
    frontier.frontier_id = Some("vfr_impact_test".to_string());
    for finding in [&root, &child, &grandchild] {
        frontier.events.push(events::new_finding_event(FindingEventInput {
            kind: "finding.asserted",
            finding_id: &finding.id,
            actor_id: "reviewer:test",
            actor_type: "human",
            reason: "fixture genesis",
            before_hash: NULL_HASH,
            after_hash: &events::finding_hash(finding),
            payload: json!({"proposal_id": format!("vpr_{}", &finding.id[3..]), "finding": finding}),
            caveats: Vec::new(),
        }));
    }
    let before = serde_json::to_value(&frontier).expect("frontier json");

    let report = impact::analyze(&frontier, &root.id, Some(10)).expect("impact report");

    assert_eq!(report.schema, "vela.impact_report.v0.1");
    assert_eq!(report.target.id, root.id);
    assert_eq!(report.summary.direct_dependents, 1);
    assert_eq!(report.summary.total_downstream, 2);
    assert_eq!(report.downstream[0].finding_id, child.id);
    assert_eq!(report.downstream[0].depth, 1);
    assert_eq!(report.downstream[1].finding_id, grandchild.id);
    assert_eq!(report.downstream[1].depth, 2);
    assert_eq!(
        serde_json::to_value(&frontier).expect("frontier json"),
        before
    );
}

#[test]
fn impact_depth_one_excludes_transitive_dependents() {
    let root = finding("root_depth");
    let mut child = finding("child_depth");
    let mut grandchild = finding("grandchild_depth");
    child.links.push(Link {
        target: root.id.clone(),
        link_type: "depends".to_string(),
        note: "child depends on root".to_string(),
        inferred_by: "test".to_string(),
        created_at: "2026-05-07T00:00:00Z".to_string(),
        mechanism: None,
    });
    grandchild.links.push(Link {
        target: child.id.clone(),
        link_type: "depends".to_string(),
        note: "grandchild depends on child".to_string(),
        inferred_by: "test".to_string(),
        created_at: "2026-05-07T00:00:00Z".to_string(),
        mechanism: None,
    });
    let frontier = project::assemble(
        "impact depth frontier",
        vec![root.clone(), child.clone(), grandchild],
        0,
        0,
        "test",
    );

    let report = impact::analyze(&frontier, &root.id, Some(1)).expect("impact report");

    assert_eq!(report.summary.direct_dependents, 1);
    assert_eq!(report.summary.total_downstream, 1);
    assert_eq!(report.downstream.len(), 1);
    assert_eq!(report.downstream[0].finding_id, child.id);
}
