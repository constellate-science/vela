use std::fs;
use std::path::{Path, PathBuf};

use tempfile::tempdir;
use vela_protocol::frontier_task::{self, FrontierTaskStatus};
use vela_protocol::review_packet;
use vela_protocol::task_workspace;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .to_path_buf()
}

fn copy_dir(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).expect("create copied frontier");
    for entry in fs::read_dir(src).expect("read source dir") {
        let entry = entry.expect("read entry");
        let path = entry.path();
        let target = dst.join(entry.file_name());
        if path.is_dir() {
            copy_dir(&path, &target);
        } else {
            fs::copy(&path, &target).expect("copy file");
        }
    }
}

#[test]
fn review_packet_builds_task_handoff_from_diff_pack() {
    let tmp = tempdir().unwrap();
    let frontier = tmp.path().join("frontier");
    copy_dir(&repo_root().join("examples/early-ad"), &frontier);

    let task = frontier_task::create_task(
        &frontier,
        "source_ingestion".to_string(),
        "Review the early AD diff pack before accepting frontier state.".to_string(),
        vec!["diff-pack:vsd_be61da0cdcba08ed".to_string()],
        "decision_impact".to_string(),
        vec![],
        vec!["Evidence CI is reviewed.".to_string()],
        FrontierTaskStatus::AwaitingReview,
    )
    .expect("create task");
    task_workspace::init_workspace(&frontier, &task.id).expect("init workspace");

    let out = tmp.path().join("review-packet.md");
    let build = review_packet::build(&frontier, &task.id, Some(&out)).expect("build packet");

    assert!(build.packet.packet_id.starts_with("vrp_"));
    assert_eq!(build.packet.task.id, task.id);
    assert_eq!(
        build.packet.diff_pack.as_ref().map(|p| p.pack_id.as_str()),
        Some("vsd_be61da0cdcba08ed")
    );
    assert!(build.packet.evidence_ci.total > 0);
    assert!(build.markdown.contains("## Evidence CI"));
    assert!(build.markdown.contains("request revision"));
    assert!(build.markdown.contains("vela packet validate"));
    assert!(out.exists());
    assert!(
        frontier
            .join(".vela/workspaces")
            .join(&task.id)
            .join("review_packet.md")
            .exists()
    );
    assert!(
        frontier
            .join(".vela/workspaces")
            .join(&task.id)
            .join("review_packet.json")
            .exists()
    );
}
