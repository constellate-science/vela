use tempfile::tempdir;
use vela_protocol::frontier_repo::{self, InitOptions};
use vela_protocol::frontier_task::{
    FrontierTaskDraft, FrontierTaskStatus, create_task, derive_task_id, list_tasks,
};

fn init_frontier() -> tempfile::TempDir {
    let tmp = tempdir().unwrap();
    frontier_repo::initialize(
        tmp.path(),
        InitOptions {
            name: "Task test frontier",
            template: "disease-frontier",
            initialize_git: false,
        },
    )
    .unwrap();
    tmp
}

#[test]
fn creates_and_lists_local_frontier_tasks() {
    let tmp = init_frontier();
    let task = create_task(
        tmp.path(),
        "source_ingestion".to_string(),
        "Review whether this source changes the support finding.".to_string(),
        vec!["doi:10.5555/demo".to_string(), "vf_demo".to_string()],
        "source_repair".to_string(),
        vec!["vtask_blocked".to_string()],
        vec!["source is anchored".to_string()],
        FrontierTaskStatus::Eligible,
    )
    .unwrap();

    assert!(task.id.starts_with("vtask_"));
    assert_eq!(task.status, FrontierTaskStatus::Eligible);
    assert_eq!(task.task_type, "source_ingestion");
    assert!(
        tmp.path()
            .join(".vela/tasks")
            .join(format!("{}.json", task.id))
            .exists()
    );

    let list = list_tasks(tmp.path()).unwrap();
    assert_eq!(list.total, 1);
    assert_eq!(list.tasks[0].id, task.id);
    assert_eq!(list.tasks[0].blockers, vec!["vtask_blocked".to_string()]);
}

#[test]
fn task_ids_are_stable_for_same_seed() {
    let draft = FrontierTaskDraft {
        frontier_id: "vfr_tasktest".to_string(),
        task_type: "contradiction_resolution".to_string(),
        objective: "Resolve conflicting evidence for one claim.".to_string(),
        inputs: vec!["vf_a".to_string(), "vf_b".to_string()],
        risk_class: "contradiction_change".to_string(),
        blockers: vec![],
        acceptance_criteria: vec!["decision is reviewable".to_string()],
    };
    assert_eq!(
        derive_task_id(&draft).unwrap(),
        derive_task_id(&draft).unwrap()
    );
}
