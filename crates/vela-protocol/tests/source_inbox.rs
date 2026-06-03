use tempfile::tempdir;
use vela_protocol::frontier_repo::{self, InitOptions};
use vela_protocol::frontier_task::FrontierTaskStatus;
use vela_protocol::source_inbox::{
    SourceInboxAddOptions, SourceInboxState, add_record, create_task_from_record,
    derive_source_inbox_id, list_records, verify_record,
};

fn init_frontier() -> tempfile::TempDir {
    let tmp = tempdir().unwrap();
    frontier_repo::initialize(
        tmp.path(),
        InitOptions {
            name: "Source inbox test frontier",
            template: "disease-frontier",
            initialize_git: false,
        },
    )
    .unwrap();
    tmp
}

#[test]
fn creates_verifies_and_routes_source_record_to_task() {
    let tmp = init_frontier();
    let record = add_record(
        tmp.path(),
        SourceInboxAddOptions {
            source_id: Some("source.demo".to_string()),
            title: "Demo source".to_string(),
            locator: "doi:10.5555/demo".to_string(),
            source_type: "paper".to_string(),
            state: SourceInboxState::Discovered,
            risk_class: "source_repair".to_string(),
            content_hash: None,
            notes: vec!["Candidate source material only.".to_string()],
            metadata: Default::default(),
        },
    )
    .unwrap();

    assert!(record.id.starts_with("vsrcin_"));
    assert!(
        tmp.path()
            .join(".vela/source-inbox")
            .join(format!("{}.json", record.id))
            .exists()
    );

    let verified = verify_record(
        tmp.path(),
        &record.id,
        "reviewer:source-test".to_string(),
        "Locator resolves to the intended source.".to_string(),
    )
    .unwrap();
    assert_eq!(verified.state, SourceInboxState::Verified);
    assert!(verified.verified_at.is_some());

    let result = create_task_from_record(
        tmp.path(),
        &record.id,
        Some("Review the demo source for one claim.".to_string()),
        FrontierTaskStatus::Eligible,
    )
    .unwrap();
    assert_eq!(result.task.task_type, "source_ingestion");
    assert_eq!(result.record.linked_task_id, Some(result.task.id.clone()));
    assert_eq!(result.review_requirement.review_class, "source_repair");

    let list = list_records(tmp.path()).unwrap();
    assert_eq!(list.total, 1);
    assert_eq!(list.records[0].linked_task_id, Some(result.task.id));
}

#[test]
fn source_inbox_ids_are_stable_for_same_seed() {
    let draft = vela_protocol::source_inbox::SourceInboxDraft {
        frontier_id: "vfr_demo".to_string(),
        source_id: Some("source.demo".to_string()),
        title: "Demo source".to_string(),
        locator: "doi:10.5555/demo".to_string(),
        source_type: "paper".to_string(),
        risk_class: "source_repair".to_string(),
    };
    assert_eq!(
        derive_source_inbox_id(&draft).unwrap(),
        derive_source_inbox_id(&draft).unwrap()
    );
}
