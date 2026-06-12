//! Review-work data payload for `vela review-work` — extracted from the
//! retired local Workbench UI module. Pure data: builds the JSON queues a
//! frontier's reviewers act on, with no HTML/serving.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde::Serialize;

use vela_edge::frontier_health;
use vela_edge::frontier_task;
use vela_edge::index_db_schema;
use vela_edge::source_inbox;
use vela_protocol::project::Project;
use vela_protocol::repo;

#[derive(Debug, Clone, Serialize)]
struct ReviewWorkPayload {
    schema: &'static str,
    frontier_id: String,
    frontier_name: String,
    frontier_path: String,
    read_only: bool,
    counts_as_review: bool,
    mutates_frontier: bool,
    total_open: usize,
    proof_status: String,
    validation_commands: Vec<&'static str>,
    frontier_index: ReviewWorkFrontierIndex,
    frontier_graph: ReviewWorkGraphNavigation,
    benchmark_mode: ReviewWorkBenchmarkMode,
    action_queue_submit: ReviewWorkSubmitPath,
    queues: Vec<ReviewWorkQueue>,
}

#[derive(Debug, Clone, Serialize)]
struct ReviewWorkGraphNavigation {
    title: &'static str,
    graph_artifacts: Vec<&'static str>,
    copy_commands: Vec<&'static str>,
    boundary: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct ReviewWorkFrontierIndex {
    title: &'static str,
    present: bool,
    source: &'static str,
    database_path: String,
    report_path: String,
    database_is_authority: bool,
    canonical_state: &'static str,
    fallback_counts_from_files: bool,
    counts: BTreeMap<String, usize>,
    copy_commands: Vec<String>,
    boundary: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct ReviewWorkBenchmarkMode {
    title: &'static str,
    benchmark_artifacts: Vec<&'static str>,
    copy_commands: Vec<&'static str>,
    boundary: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct ReviewWorkSubmitPath {
    source: &'static str,
    proposal_preview_commands: Vec<&'static str>,
    explicit_reviewer_actions: Vec<&'static str>,
    boundary: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct ReviewWorkQueue {
    lane_id: &'static str,
    title: &'static str,
    count: usize,
    examples: Vec<String>,
    operator_artifacts: Vec<&'static str>,
    validation_commands: Vec<&'static str>,
    boundary: &'static str,
    next_href: &'static str,
    next_label: &'static str,
    reviewer_authority_required: bool,
}

fn build_review_work_frontier_index(
    repo_path: &Path,
    project: &Project,
) -> ReviewWorkFrontierIndex {
    let db_path = repo_path
        .join(".vela")
        .join("index")
        .join("frontier-index.sqlite");
    let report_path = repo_path
        .join(".vela")
        .join("index")
        .join("frontier-index.report.v1.json");
    let mut counts = BTreeMap::new();
    let present = db_path.is_file() && report_path.is_file();
    let mut source = "canonical_frontier_files";
    let mut fallback_counts_from_files = true;

    if present
        && let Ok(body) = fs::read_to_string(&report_path)
        && let Ok(report) = serde_json::from_str::<serde_json::Value>(&body)
        && let Some(index_counts) = report.get("counts").and_then(serde_json::Value::as_object)
    {
        for key in [
            "findings",
            "sources",
            "evidence_atoms",
            "links",
            "events",
            "proposals",
            "proof_files",
            "score_returns",
            "benchmark_rows",
        ] {
            if let Some(count) = index_counts
                .get(key)
                .and_then(serde_json::Value::as_u64)
                .map(|count| count as usize)
            {
                counts.insert(key.to_string(), count);
            }
        }
        source = "frontier_index";
        fallback_counts_from_files = false;
    }

    if fallback_counts_from_files {
        counts.insert("findings".to_string(), project.findings.len());
        counts.insert("sources".to_string(), project.sources.len());
        counts.insert("evidence_atoms".to_string(), project.evidence_atoms.len());
        counts.insert("links".to_string(), project.stats.links);
        counts.insert("events".to_string(), project.events.len());
        counts.insert("proposals".to_string(), project.proposals.len());
    }

    ReviewWorkFrontierIndex {
        title: "Frontier index database",
        present,
        source,
        database_path: db_path.display().to_string(),
        report_path: report_path.display().to_string(),
        database_is_authority: false,
        canonical_state: index_db_schema::CANONICAL_STATE,
        fallback_counts_from_files,
        counts,
        copy_commands: vec![
            format!("vela status {} --json", repo_path.display()),
            format!("vela stats {} --json", repo_path.display()),
            format!(
                "vela search <query> --source {} --json",
                repo_path.display()
            ),
        ],
        boundary: "The database is a rebuildable read model. Canonical state remains frontier files and accepted events.",
    }
}

fn review_work_validation_commands() -> Vec<&'static str> {
    vec![
        "validate-strict-signal-return.sh",
        "validate-strict-signal-action-map.sh",
    ]
}

fn review_work_queue_validation_commands(lane_id: &str) -> Vec<&'static str> {
    match lane_id {
        "source_review" | "entity_review" | "proposal_review" | "strict_signal_review" => vec![
            "validate-strict-signal-return.sh",
            "validate-strict-signal-action-map.sh",
            "validate-strict-signal-completion.sh",
        ],
        "outside_review" => vec![
            "validate-outside-review-return.sh",
            "validate-outside-review-action-map.sh",
        ],
        "task_closure" => vec!["validate-strict-signal-completion.sh"],
        "post_review_refresh" => vec!["vela proof verify"],
        _ => Vec::new(),
    }
}

fn outside_review_files(repo_path: &Path) -> Vec<String> {
    let review_dir = repo_path.join("review");
    let mut files = Vec::new();
    let Ok(entries) = fs::read_dir(&review_dir) else {
        return files;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if name.starts_with("outside-review") && name.ends_with(".md") {
            files.push(name.to_string());
        }
    }
    files.sort();
    files
}

fn local_diff_pack_ids(repo_path: &Path) -> Vec<String> {
    let diff_pack_dir = repo_path.join(".vela").join("diff_packs");
    let mut ids = Vec::new();
    let Ok(entries) = fs::read_dir(&diff_pack_dir) else {
        return ids;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.extension().is_some_and(|ext| ext == "json") {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
            continue;
        };
        ids.push(stem.to_string());
    }
    ids.sort();
    ids
}

fn build_review_work_payload(repo_path: &Path) -> Result<ReviewWorkPayload, String> {
    let project = repo::load_from_path(repo_path)?;
    let source_list = source_inbox::list_records(repo_path)?;
    let task_list = frontier_task::list_tasks(repo_path)?;
    let health = frontier_health::analyze(repo_path)?;
    let frontier_index = build_review_work_frontier_index(repo_path, &project);

    let source_review: Vec<String> = source_list
        .records
        .iter()
        .filter(|record| {
            matches!(
                record.state,
                source_inbox::SourceInboxState::Discovered
                    | source_inbox::SourceInboxState::Retrieved
            )
        })
        .map(|record| record.id.clone())
        .collect();
    let entity_review: Vec<String> = project
        .findings
        .iter()
        .filter(|finding| {
            finding
                .assertion
                .entities
                .iter()
                .any(|entity| entity.needs_review)
        })
        .map(|finding| finding.id.clone())
        .collect();
    let proposal_review: Vec<String> = project
        .proposals
        .iter()
        .filter(|proposal| proposal.status == "pending_review")
        .map(|proposal| proposal.id.clone())
        .collect();
    let mut strict_signal_examples = entity_review.iter().take(4).cloned().collect::<Vec<_>>();
    strict_signal_examples.extend(proposal_review.iter().take(4).cloned());

    let diff_pack_examples = local_diff_pack_ids(repo_path);
    let diff_pack_blockers =
        health.metrics.pending_diff_packs + health.metrics.missing_attestations;
    let diff_pack_examples = if diff_pack_blockers == 0 {
        Vec::new()
    } else {
        diff_pack_examples
    };
    let task_closure: Vec<String> = task_list
        .tasks
        .iter()
        .filter(|task| !task.status.is_terminal())
        .map(|task| task.id.clone())
        .collect();
    let outside_review = outside_review_files(repo_path);
    let proof_refresh_count = if matches!(
        project.proof_state.latest_packet.status.as_str(),
        "fresh" | "current" | "ready"
    ) {
        0
    } else {
        1
    };
    let validation_commands = review_work_validation_commands();
    let frontier_id = project.frontier_id();
    let proof_status = project.proof_state.latest_packet.status.clone();
    let frontier_name = project.project.name.clone();

    let queues = vec![
        ReviewWorkQueue {
            lane_id: "source_review",
            title: "source review",
            count: source_review.len(),
            examples: source_review.iter().take(8).cloned().collect(),
            operator_artifacts: vec!["review/decision-corpus-queue.v1.md"],
            validation_commands: review_work_queue_validation_commands("source_review"),
            boundary: "Source records are not evidence until reviewed into frontier state.",
            next_href: "/source-inbox",
            next_label: "Open source inbox",
            reviewer_authority_required: true,
        },
        ReviewWorkQueue {
            lane_id: "entity_review",
            title: "entity review",
            count: entity_review.len(),
            examples: entity_review.iter().take(8).cloned().collect(),
            operator_artifacts: vec!["review/strict-signal-remediation.v1.md"],
            validation_commands: review_work_queue_validation_commands("entity_review"),
            boundary: "Entity flags mark candidates that still need human normalization.",
            next_href: "/review/inbox?group=entity_issue",
            next_label: "Open entity queue",
            reviewer_authority_required: true,
        },
        ReviewWorkQueue {
            lane_id: "proposal_review",
            title: "proposal review",
            count: proposal_review.len(),
            examples: proposal_review.iter().take(12).cloned().collect(),
            operator_artifacts: vec![
                "review/decision-adjudication-queue.v1.md",
                "review/strict-signal-remediation.v1.md",
            ],
            validation_commands: review_work_queue_validation_commands("proposal_review"),
            boundary: "Pending proposals are runtime output until a reviewer applies or rejects them.",
            next_href: "/proposals",
            next_label: "Open proposals",
            reviewer_authority_required: true,
        },
        ReviewWorkQueue {
            lane_id: "outside_review",
            title: "outside review",
            count: outside_review.len(),
            examples: outside_review.iter().take(4).cloned().collect(),
            operator_artifacts: vec![
                "review/outside-review-2026-q3.md",
                "docs/templates/outside-review-return.md",
                "docs/templates/outside-review-action-map.md",
            ],
            validation_commands: review_work_queue_validation_commands("outside_review"),
            boundary: "Outside review packets must be dispatched and returned outside this read-only page.",
            next_href: "/review/inbox",
            next_label: "Open review inbox",
            reviewer_authority_required: true,
        },
        ReviewWorkQueue {
            lane_id: "diff_pack_attestation",
            title: "Diff Pack attestation",
            count: diff_pack_blockers,
            examples: diff_pack_examples.iter().take(8).cloned().collect(),
            operator_artifacts: vec!["review/diff-pack-attestation.v1.md"],
            validation_commands: review_work_queue_validation_commands("diff_pack_attestation"),
            boundary: "Missing role attestations block release promotion.",
            next_href: "/diff-packs",
            next_label: "Open Diff Packs",
            reviewer_authority_required: true,
        },
        ReviewWorkQueue {
            lane_id: "strict_signal_review",
            title: "strict-signal review",
            count: entity_review.len() + proposal_review.len(),
            examples: strict_signal_examples,
            operator_artifacts: vec!["review/strict-signal-remediation.v1.md"],
            validation_commands: review_work_queue_validation_commands("strict_signal_review"),
            boundary: "Strict signals are candidates for source-grounded review, not accepted frontier truth.",
            next_href: "/review/inbox",
            next_label: "Open review inbox",
            reviewer_authority_required: true,
        },
        ReviewWorkQueue {
            lane_id: "task_closure",
            title: "task closure",
            count: task_closure.len(),
            examples: task_closure.iter().take(12).cloned().collect(),
            operator_artifacts: vec!["review/task-closure.v1.md"],
            validation_commands: review_work_queue_validation_commands("task_closure"),
            boundary: "Tasks are operational work units; closure does not rewrite reviewed findings.",
            next_href: "/tasks",
            next_label: "Open tasks",
            reviewer_authority_required: true,
        },
        ReviewWorkQueue {
            lane_id: "post_review_refresh",
            title: "post-review refresh",
            count: proof_refresh_count,
            examples: vec![frontier_id.clone()],
            operator_artifacts: vec!["proof/latest.json", "proof/hashes.json"],
            validation_commands: review_work_queue_validation_commands("post_review_refresh"),
            boundary: "Proof packets should be refreshed after accepted frontier changes.",
            next_href: "/proof",
            next_label: "Open proof",
            reviewer_authority_required: false,
        },
    ];
    let total_open = queues.iter().map(|queue| queue.count).sum();

    Ok(ReviewWorkPayload {
        schema: "vela.workbench.review_work.v0.1",
        frontier_id,
        frontier_name,
        frontier_path: repo_path.display().to_string(),
        read_only: true,
        counts_as_review: false,
        mutates_frontier: false,
        total_open,
        proof_status,
        validation_commands,
        frontier_index,
        frontier_graph: ReviewWorkGraphNavigation {
            title: "Frontier graph navigation",
            graph_artifacts: vec![
                ".vela/graph/frontier-graph.v1.json",
                ".vela/graph/impact-index.v1.json",
                ".vela/graph/guided-tours.v1.json",
            ],
            copy_commands: vec![
                "jq '.summary, .claim_boundary' .vela/graph/frontier-graph.v1.json",
                "jq '.finding_neighborhoods[0:5]' .vela/graph/impact-index.v1.json",
                "jq '.tours[] | {id,title,steps: (.steps | length)}' .vela/graph/guided-tours.v1.json",
            ],
            boundary: "copy commands only; graph navigation does not mutate frontier state",
        },
        benchmark_mode: ReviewWorkBenchmarkMode {
            title: "Graph benchmark mode",
            benchmark_artifacts: vec![
                "benchmarks/frontier-graph-navigation-answers.v1.json",
                "benchmarks/frontier-graph-navigation-paper-rag-baseline.v1.json",
                "benchmarks/frontier-graph-blind-scoring-pack.v1.json",
                "benchmarks/frontier-graph-benchmark-error-analysis.v1.json",
            ],
            copy_commands: vec![
                "jq '.summary' benchmarks/frontier-graph-navigation-answers.v1.json",
                "jq '.summary' benchmarks/frontier-graph-blind-scoring-pack.v1.json",
            ],
            boundary: "copy benchmark commands only; this read-only review mode does not score external validation and does not mutate frontier state",
        },
        action_queue_submit: ReviewWorkSubmitPath {
            source: "review/frontier-action-queue.v1.json",
            proposal_preview_commands: vec![
                "vela proposals validate review/correction-return-proposals.v1.json --json",
                "vela proposals import <frontier> review/correction-return-proposals.v1.json --json",
            ],
            explicit_reviewer_actions: vec![
                "vela proposals accept <frontier> <proposal-id> --reviewer reviewer:solo-maintainer --reason \"Accept returned correction into observation review history.\" --json",
                "vela proposals reject <frontier> <proposal-id> --reviewer reviewer:solo-maintainer --reason \"Reject returned correction for now.\" --json",
            ],
            boundary: "Proposal previews and reviewer actions are commands to copy. The review-work page does not execute them.",
        },
        queues,
    })
}

pub(crate) fn build_review_work_json(repo_path: &Path) -> Result<serde_json::Value, String> {
    let payload = build_review_work_payload(repo_path)?;
    serde_json::to_value(payload).map_err(|e| format!("serialize review work: {e}"))
}
