//! Portable activity records and changesets: `vela record`, `vela pack`,
//! and witness-file collection for `vela reproduce`. Moved verbatim from
//! `cli/mod.rs`.

use super::*;

/// Parse a witness file: either a bare `vela_verify::Witness`, or an
/// object with a `witness` field wrapping one (a record that ships its
/// construction).
pub(crate) fn parse_witness(raw: &str) -> Result<vela_verify::Witness, String> {
    if let Ok(w) = serde_json::from_str::<vela_verify::Witness>(raw) {
        return Ok(w);
    }
    let value: Value = serde_json::from_str(raw).map_err(|e| e.to_string())?;
    if let Some(inner) = value.get("witness") {
        return serde_json::from_value(inner.clone()).map_err(|e| e.to_string());
    }
    Err("not a witness (missing recognized `kind`, and no `witness` field)".to_string())
}

/// Collect witness files for `vela reproduce`: a single file, or every
/// `*.witness.json` under a directory (preferring a `witnesses/` subdir).
pub(crate) fn collect_witness_files(path: &Path) -> Vec<PathBuf> {
    if path.is_file() {
        return vec![path.to_path_buf()];
    }
    let root = {
        let sub = path.join("witnesses");
        if sub.is_dir() {
            sub
        } else {
            path.to_path_buf()
        }
    };
    let mut out = Vec::new();
    collect_witness_files_into(&root, &mut out);
    out.sort();
    out
}

fn collect_witness_files_into(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            collect_witness_files_into(&p, out);
        } else if p
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.ends_with(".witness.json"))
        {
            out.push(p);
        }
    }
}

/// `vela pack` — create or show a changeset. Creating bundles PENDING
/// proposals into one reviewable `vsd_` unit; showing renders members and
/// verdict state. Packing groups; a human key decides.
#[allow(clippy::too_many_arguments)]
pub(crate) fn cmd_pack(
    frontier: &Path,
    pack_id: Option<String>,
    summary: Option<String>,
    from_pending: bool,
    ids: Vec<String>,
    aggregate_kind: String,
    actor: Option<String>,
    json: bool,
) {
    // ── show mode ─────────────────────────────────────────────────────────
    if let Some(pid) = pack_id {
        let project = repo::load_from_path(frontier)
            .unwrap_or_else(|e| fail_return(&format!("load frontier: {e}")));
        let Some(rec) = project
            .released_diff_packs
            .iter()
            .find(|r| r.pack_id == pid)
        else {
            fail(&format!("pack {pid} not found"));
        };
        if json {
            print_json(&json!({
                "ok": true,
                "command": "pack.show",
                "pack": rec,
            }));
        } else {
            println!();
            println!(
                "  {}",
                format!("VELA · PACK · {pid}").to_uppercase().dimmed()
            );
            println!("  {}", vela_protocol::cli_style::tick_row(60));
            println!("  summary:  {}", rec.summary);
            println!(
                "  verdict:  {}",
                rec.verdict
                    .as_ref()
                    .map(|v| format!("{v:?}"))
                    .unwrap_or_else(|| "pending".to_string())
            );
            println!("  released: {}", rec.released_at);
            println!("  members ({}):", rec.member_proposals.len());
            for m in &rec.member_proposals {
                let (kind, text) = project
                    .proposals
                    .iter()
                    .find(|p| &p.id == m)
                    .map(|p| {
                        let text = p
                            .payload
                            .pointer("/finding/assertion/text")
                            .and_then(serde_json::Value::as_str)
                            .filter(|t| !t.is_empty())
                            .unwrap_or(&p.reason)
                            .chars()
                            .take(72)
                            .collect::<String>();
                        (p.kind.clone(), text)
                    })
                    .unwrap_or_default();
                println!("    · {m}  {kind:<13}  {text}");
            }
            if rec.verdict.is_none() {
                println!();
                println!(
                    "  decide:   vela accept . --pack {pid}    (preview a member: vela diff <vpr_id>)"
                );
            }
        }
        return;
    }

    // ── create mode ───────────────────────────────────────────────────────
    let summary =
        summary.unwrap_or_else(|| fail_return("pack: --summary is required to create a pack"));
    let members: Vec<String> = if from_pending {
        let project = repo::load_from_path(frontier)
            .unwrap_or_else(|e| fail_return(&format!("load frontier: {e}")));
        let in_undecided: std::collections::BTreeSet<String> = project
            .released_diff_packs
            .iter()
            .filter(|r| r.verdict.is_none())
            .flat_map(|r| r.member_proposals.iter().cloned())
            .collect();
        project
            .proposals
            .iter()
            .filter(|p| {
                p.status == "pending_review"
                    && p.applied_event_id.is_none()
                    && !in_undecided.contains(&p.id)
            })
            .map(|p| p.id.clone())
            .collect()
    } else {
        ids
    };
    let actor_id = crate::cli_identity::resolve_actor(actor.as_deref());
    let report = vela_protocol::released_diff_pack::release_pack_at_path(
        frontier,
        &summary,
        &aggregate_kind,
        &members,
        &actor_id,
    )
    .unwrap_or_else(|e| fail_return(&e));
    if json {
        print_json(&json!({
            "ok": true,
            "command": "pack",
            "pack_id": report.pack_id,
            "event_id": report.event_id,
            "members": report.members,
        }));
    } else {
        println!(
            "{} {} released ({} member(s)) — review with `vela pack {} {}` \
             and decide with `vela accept {} --pack {}`",
            style::ok("pack"),
            report.pack_id,
            report.members.len(),
            frontier.display(),
            report.pack_id,
            frontier.display(),
            report.pack_id,
        );
    }
}

/// `vela record` — the one-verb activity-record surface. A frontier dir
/// records; a vrc_ JSON file validates; `--propose <dir>` lands the
/// validated record as a PENDING proposal. Deciding stays with a human key.
#[allow(clippy::too_many_arguments)]
pub(crate) fn cmd_record(
    target: &Path,
    claim: Option<String>,
    assertion_type: String,
    artifacts: Vec<String>,
    caveats: Vec<String>,
    verifier_runs: Vec<String>,
    actor: Option<String>,
    key: Option<std::path::PathBuf>,
    out: Option<std::path::PathBuf>,
    propose: Option<std::path::PathBuf>,
    json: bool,
) {
    use vela_protocol::record::{
        ActivityRecord, ActivityRecordDraft, RecordArtifact, RecordVerifierRun,
    };

    fn hash_file(path: &std::path::Path) -> Result<String, String> {
        use sha2::{Digest, Sha256};
        let bytes = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        Ok(hex::encode(Sha256::digest(&bytes)))
    }

    // ── validate mode: the target is a vrc_ JSON file ─────────────────────
    if target.is_file() {
        let raw = std::fs::read_to_string(target)
            .unwrap_or_else(|e| fail_return(&format!("read {}: {e}", target.display())));
        let rc: ActivityRecord = serde_json::from_str(&raw)
            .unwrap_or_else(|e| fail_return(&format!("record parse: {e}")));
        let signed = rc.verify().unwrap_or_else(|e| fail_return(&e));
        // Locators are frontier-relative; the record usually lives in
        // <frontier>/records/. Try the propose target, the record's dir,
        // its parent (the frontier), then cwd.
        let mut roots: Vec<std::path::PathBuf> = Vec::new();
        if let Some(fr) = &propose {
            roots.push(fr.clone());
        }
        if let Some(dir) = target.parent() {
            roots.push(dir.to_path_buf());
            if let Some(up) = dir.parent() {
                roots.push(up.to_path_buf());
            }
        }
        roots.push(std::path::PathBuf::from("."));
        let mut missing = Vec::new();
        let mut mismatched = Vec::new();
        for atom in &rc.artifacts {
            let mut state = "missing";
            for root in &roots {
                match hash_file(&root.join(&atom.locator)) {
                    Ok(h) if h == atom.sha256 => {
                        state = "ok";
                        break;
                    }
                    Ok(_) => state = "mismatched",
                    Err(_) => {}
                }
            }
            match state {
                "ok" => {}
                "mismatched" => mismatched.push(atom.locator.clone()),
                _ => missing.push(atom.locator.clone()),
            }
        }
        let ok = missing.is_empty() && mismatched.is_empty();
        if !ok {
            for l in &missing {
                eprintln!("  missing artifact: {l}");
            }
            for l in &mismatched {
                eprintln!("  HASH MISMATCH: {l}");
            }
            fail("record validation failed");
        }
        // ── optional landing: --propose <frontier> ────────────────────────
        if let Some(frontier) = propose {
            let project = repo::load_from_path(&frontier)
                .unwrap_or_else(|e| fail_return(&format!("load frontier: {e}")));
            if project.frontier_id() != rc.frontier_id {
                fail(&format!(
                    "record is for {}, this frontier is {}",
                    rc.frontier_id,
                    project.frontier_id()
                ));
            }
            let head_now = vela_protocol::events::event_log_hash(&project.events);
            let staleness = if head_now == rc.against_head {
                "recorded against the current head".to_string()
            } else {
                format!(
                    "recorded against head {}…, current head {}… — review the delta",
                    &rc.against_head[..rc.against_head.len().min(16)],
                    &head_now[..head_now.len().min(16)]
                )
            };
            let report = state::add_finding(
                &frontier,
                rc.to_finding_draft(&staleness, signed),
                false, // NEVER applies: a record lands pending
            )
            .unwrap_or_else(|e| fail_return(&format!("record propose: {e}")));
            if json {
                print_json(&json!({
                    "ok": true,
                    "command": "record.propose",
                    "record": rc.id,
                    "proposal_id": report.proposal_id,
                    "status": report.proposal_status,
                    "signed": signed,
                }));
            } else {
                println!(
                    "{} {} landed as proposal {} ({}) — a human key decides from here",
                    style::ok("record"),
                    rc.id,
                    report.proposal_id,
                    report.proposal_status
                );
            }
            return;
        }
        if json {
            print_json(&json!({
                "ok": true,
                "command": "record.validate",
                "id": rc.id,
                "signed": signed,
                "artifacts_verified": rc.artifacts.len(),
            }));
        } else {
            println!(
                "{} {} valid ({} artifact(s) re-derived, {})",
                style::ok("record"),
                rc.id,
                rc.artifacts.len(),
                if signed { "signed" } else { "UNSIGNED" }
            );
        }
        return;
    }

    // ── record mode: the target is a frontier dir ─────────────────────────
    let claim = claim.unwrap_or_else(|| {
        fail_return("record mode needs --claim (or pass a vrc_ JSON file to validate)")
    });
    if artifacts.is_empty() {
        fail("record mode needs at least one --artifact <path[:kind]>");
    }
    if caveats.is_empty() {
        fail("record mode needs at least one --caveat (what this does NOT establish)");
    }
    let project = repo::load_from_path(target)
        .unwrap_or_else(|e| fail_return(&format!("load frontier: {e}")));
    let vfr = project.frontier_id();
    let head = vela_protocol::events::event_log_hash(&project.events);
    let mut atoms = Vec::new();
    for spec in &artifacts {
        let (path_str, kind) = match spec.rsplit_once(':') {
            Some((p, k)) if !k.contains('/') && !k.contains('\\') => (p.to_string(), k.to_string()),
            _ => (spec.clone(), "witness".to_string()),
        };
        let path = std::path::Path::new(&path_str);
        let sha =
            hash_file(path).unwrap_or_else(|e| fail_return(&format!("--artifact {spec}: {e}")));
        let locator = path
            .strip_prefix(target)
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| path_str.clone());
        atoms.push(RecordArtifact {
            kind,
            locator,
            sha256: sha,
            note: String::new(),
        });
    }
    let mut runs = Vec::new();
    for spec in &verifier_runs {
        let parts: Vec<&str> = spec.splitn(4, ':').collect();
        if parts.len() < 3 {
            fail(&format!(
                "--verifier-run must be method:outcome:logfile[:solver], got '{spec}'"
            ));
        }
        let output_hash = hash_file(std::path::Path::new(parts[2]))
            .unwrap_or_else(|e| fail_return(&format!("--verifier-run {spec}: {e}")));
        runs.push(RecordVerifierRun {
            method: parts[0].to_string(),
            outcome: parts[1].to_string(),
            output_hash,
            solver: parts.get(3).map(|s| s.to_string()).unwrap_or_default(),
        });
    }
    let emitted_by = crate::cli_identity::resolve_actor(actor.as_deref());
    // Custody: an agent-/ci-actor record NEVER auto-resolves the configured
    // (human) identity key. An agent signs only with a key passed
    // EXPLICITLY (its own); otherwise the record is honestly unsigned.
    let signing_key =
        if key.is_none() && (emitted_by.starts_with("agent:") || emitted_by.starts_with("ci:")) {
            None
        } else {
            crate::cli_identity::resolve_signing_key_opt(key.as_deref())
        };
    let record = ActivityRecord::build(
        ActivityRecordDraft {
            frontier_id: vfr,
            against_head: head,
            assertion: claim,
            assertion_type,
            artifacts: atoms,
            verifier_runs: runs,
            caveats,
            emitted_by,
            emitted_at: chrono::Utc::now().to_rfc3339(),
        },
        signing_key.as_ref(),
    )
    .unwrap_or_else(|e| fail_return(&e));
    let dest = out.unwrap_or_else(|| target.join("records").join(format!("{}.json", record.id)));
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .unwrap_or_else(|e| fail_return(&format!("mkdir {}: {e}", parent.display())));
    }
    std::fs::write(
        &dest,
        serde_json::to_string_pretty(&record).unwrap_or_else(|e| fail_return(&e.to_string())),
    )
    .unwrap_or_else(|e| fail_return(&format!("write {}: {e}", dest.display())));
    let signed = !record.signature.is_empty();
    if json {
        print_json(&json!({
            "ok": true,
            "command": "record",
            "id": record.id,
            "signed": signed,
            "frontier_id": record.frontier_id,
            "against_head": record.against_head,
            "artifacts": record.artifacts.len(),
            "wrote_to": dest.display().to_string(),
        }));
    } else {
        println!(
            "{} {} recorded ({} artifact(s), {}) -> {}",
            style::ok("record"),
            record.id,
            record.artifacts.len(),
            if signed { "signed" } else { "UNSIGNED" },
            dest.display()
        );
        if !signed {
            eprintln!(
                "  note: unsigned — valid to carry and propose; a reviewer sees signed=false"
            );
        }
    }
}
