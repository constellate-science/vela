//! `cmd_lean` and its handler logic, split out of cli.rs.

use crate::cli::{fail, fail_return, print_json};
use std::path::PathBuf;
use vela_protocol::cli_style as style;

use serde_json::json;
use sha2::Digest;

use crate::cli_commands::*;

/// v0.164: handle `vela lean ...`. Anchors substrate theorems to
/// their content-addressed source bytes.
pub(crate) fn cmd_lean(action: LeanAction) {
    use vela_edge::lean_anchors::{LeanAnchor, THEOREMS, lean_dir_default};

    match action {
        LeanAction::List { json } => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &THEOREMS
                            .iter()
                            .map(|d| serde_json::json!({
                                "id": d.id,
                                "title": d.title,
                                "module": d.module,
                                "decl": d.decl,
                            }))
                            .collect::<Vec<_>>()
                    )
                    .expect("serialize theorem list")
                );
            } else {
                println!("  registered theorems ({}):", THEOREMS.len());
                for d in THEOREMS {
                    println!("    T{:<2}  {}  ({}::{})", d.id, d.title, d.module, d.decl);
                }
            }
        }
        LeanAction::Anchor {
            id,
            lean_dir,
            out,
            json,
        } => {
            let lean = lean_dir.unwrap_or_else(lean_dir_default);
            let descriptor = THEOREMS
                .iter()
                .find(|d| d.id == id)
                .unwrap_or_else(|| fail_return(&format!("unknown theorem id: T{id}")));
            let anchor =
                LeanAnchor::anchor_for(descriptor, &lean).unwrap_or_else(|e| fail_return(&e));
            let body = serde_json::to_string_pretty(&anchor).expect("serialize anchor");
            if let Some(path) = out {
                std::fs::write(&path, format!("{body}\n"))
                    .unwrap_or_else(|e| fail_return(&format!("write {}: {e}", path.display())));
                if json {
                    let payload = json!({
                        "ok": true,
                        "command": "lean.anchor",
                        "theorem_id": id,
                        "anchor_id": anchor.anchor_id,
                        "module_sha256": anchor.module_sha256,
                        "structurally_present": anchor.structurally_present,
                        "out": path.display().to_string(),
                    });
                    print_json(&payload);
                } else {
                    println!(
                        "{} T{} -> {} ({})",
                        style::ok("lean.anchor"),
                        id,
                        anchor.anchor_id,
                        path.display()
                    );
                }
            } else {
                println!("{body}");
            }
        }
        LeanAction::AnchorAll {
            lean_dir,
            out,
            json,
        } => {
            let lean = lean_dir.unwrap_or_else(lean_dir_default);
            if let Err(e) = std::fs::create_dir_all(&out) {
                fail(&format!("create {}: {e}", out.display()));
            }
            let mut summary = Vec::new();
            for d in THEOREMS {
                let anchor = LeanAnchor::anchor_for(d, &lean).unwrap_or_else(|e| fail_return(&e));
                let body = serde_json::to_string_pretty(&anchor).expect("serialize anchor");
                let path = out.join(format!("T{}.anchor.json", d.id));
                std::fs::write(&path, format!("{body}\n"))
                    .unwrap_or_else(|e| fail_return(&format!("write {}: {e}", path.display())));
                summary.push(serde_json::json!({
                    "theorem_id": d.id,
                    "anchor_id": anchor.anchor_id,
                    "module_sha256": anchor.module_sha256,
                    "structurally_present": anchor.structurally_present,
                    "path": path.display().to_string(),
                }));
            }
            if json {
                let payload = json!({
                    "ok": true,
                    "command": "lean.anchor-all",
                    "anchored": summary.len(),
                    "anchors": summary,
                });
                print_json(&payload);
            } else {
                println!(
                    "{} anchored {} theorem(s) to {}",
                    style::ok("lean.anchor-all"),
                    summary.len(),
                    out.display()
                );
            }
        }
        LeanAction::Keygen {
            key_out,
            pub_out,
            actor,
        } => {
            use rand::rngs::OsRng;
            let signing = ed25519_dalek::SigningKey::generate(&mut OsRng);
            let priv_hex = hex::encode(signing.to_bytes());
            let pub_hex = hex::encode(signing.verifying_key().to_bytes());
            std::fs::write(&key_out, format!("{priv_hex}\n"))
                .unwrap_or_else(|e| fail_return(&format!("write {}: {e}", key_out.display())));
            let pub_record = json!({
                "schema": "vela.lean_verifier_pubkey.v0.1",
                "actor": actor,
                "pubkey_hex": pub_hex,
                "created_at": chrono::Utc::now().to_rfc3339(),
            });
            let body =
                serde_json::to_string_pretty(&pub_record).expect("serialize verifier pubkey");
            std::fs::write(&pub_out, format!("{body}\n"))
                .unwrap_or_else(|e| fail_return(&format!("write {}: {e}", pub_out.display())));
            println!(
                "{} verifier keypair generated; private key -> {}, public spec -> {}",
                style::ok("lean.keygen"),
                key_out.display(),
                pub_out.display()
            );
        }
        LeanAction::VerifyAll {
            anchors_dir,
            out_dir,
            build_log,
            key,
            actor,
            lean_toolchain,
            mathlib_revision,
            axioms_report,
            kernel_recheck_log,
            kernel_checker,
            kernel_checker_version,
            allowed_axioms,
            forbidden_axioms,
            out_tcb,
            json,
        } => {
            use vela_protocol::lean_verification::KernelRecheck;
            use vela_protocol::tcb_policy::{
                DEFAULT_ALLOWED_AXIOMS, FORBIDDEN_AXIOMS, TcbDraft, TcbPolicy,
            };

            let signing = crate::cli_identity::resolve_signing_key(key.as_deref());

            let log_bytes = std::fs::read(&build_log).unwrap_or_else(|e| {
                fail_return(&format!("read build log {}: {e}", build_log.display()))
            });
            let mut hasher = sha2::Sha256::new();
            sha2::Digest::update(&mut hasher, &log_bytes);
            let verifier_output_hash = hex::encode(hasher.finalize());

            let toolchain = lean_toolchain.unwrap_or_else(|| {
                std::fs::read_to_string("lean/lean-toolchain")
                    .map(|s| s.trim().to_string())
                    .unwrap_or_else(|_| "unknown".to_string())
            });
            let mathlib = mathlib_revision.unwrap_or_else(|| {
                std::fs::read_to_string("lean/lakefile.lean")
                    .ok()
                    .and_then(|t| {
                        let needle = "mathlib4.git\" @ \"";
                        let i = t.find(needle)?;
                        let rest = &t[i + needle.len()..];
                        let j = rest.find('"')?;
                        Some(rest[..j].to_string())
                    })
                    .unwrap_or_else(|| "unknown".to_string())
            });

            // Build the TCB policy (allow/forbid lists default to the
            // standard sets) and record it as a content-addressed object.
            let csv = |s: Option<String>, default: &[&str]| -> Vec<String> {
                match s {
                    Some(v) => v
                        .split(',')
                        .map(|x| x.trim().to_string())
                        .filter(|x| !x.is_empty())
                        .collect(),
                    None => default.iter().map(|x| (*x).to_string()).collect(),
                }
            };
            let policy = TcbPolicy::build(TcbDraft {
                allowed_axioms: csv(allowed_axioms, DEFAULT_ALLOWED_AXIOMS),
                forbidden_axioms: csv(forbidden_axioms, FORBIDDEN_AXIOMS),
                kernel_checker: kernel_checker.clone(),
                kernel_checker_version: kernel_checker_version.clone(),
                lean_toolchain: toolchain.clone(),
                mathlib_revision: mathlib.clone(),
            })
            .unwrap_or_else(|e| fail_return(&format!("build tcb policy: {e}")));

            // External kernel re-check outcome.
            let recheck = match &kernel_recheck_log {
                None => KernelRecheck::NotRun,
                Some(p) => match std::fs::read_to_string(p) {
                    Ok(t) if t.contains("KERNEL_RECHECK_FAILED") => KernelRecheck::Failed,
                    Ok(_) => KernelRecheck::Passed,
                    Err(e) => {
                        fail_return(&format!("read kernel re-check log {}: {e}", p.display()))
                    }
                },
            };

            // Per-decl axiom report (absent => axiom-unknown / legacy records).
            let axioms_map = axioms_report.as_ref().map(|p| {
                let t = std::fs::read_to_string(p).unwrap_or_else(|e| {
                    fail_return(&format!("read axioms report {}: {e}", p.display()))
                });
                parse_axioms_report(&t)
            });

            let out = out_dir.unwrap_or_else(|| anchors_dir.clone());
            if let Err(e) = std::fs::create_dir_all(&out) {
                fail(&format!("create {}: {e}", out.display()));
            }
            // Persist the policy object.
            let tcb_path = out_tcb.unwrap_or_else(|| out.join("policy.vtcb.json"));
            std::fs::write(
                &tcb_path,
                format!(
                    "{}\n",
                    serde_json::to_string_pretty(&policy).expect("serialize tcb")
                ),
            )
            .unwrap_or_else(|e| fail_return(&format!("write {}: {e}", tcb_path.display())));

            let now = chrono::Utc::now().to_rfc3339();
            let mut summary = Vec::new();
            let entries: Vec<_> = std::fs::read_dir(&anchors_dir)
                .unwrap_or_else(|e| {
                    fail_return(&format!("read anchors {}: {e}", anchors_dir.display()))
                })
                .filter_map(|r| r.ok())
                .collect();
            let mut anchor_paths: Vec<PathBuf> = entries
                .into_iter()
                .map(|e| e.path())
                .filter(|p| {
                    p.file_name()
                        .and_then(|s| s.to_str())
                        .map(|s| s.starts_with('T') && s.ends_with(".anchor.json"))
                        .unwrap_or(false)
                })
                .collect();
            anchor_paths.sort();

            for path in anchor_paths {
                let body = std::fs::read_to_string(&path)
                    .unwrap_or_else(|e| fail_return(&format!("read {}: {e}", path.display())));
                let anchor: vela_edge::lean_anchors::LeanAnchor = serde_json::from_str(&body)
                    .unwrap_or_else(|e| fail_return(&format!("parse {}: {e}", path.display())));

                // The decl this anchor pins (registry theorems are always present
                // in THEOREMS). `mint_verification` classifies its axioms when a
                // report is present and fails closed if the report omits the decl.
                let decl = THEOREMS
                    .iter()
                    .find(|d| d.id == anchor.theorem_id)
                    .map(|d| d.decl.to_string())
                    .unwrap_or_else(|| {
                        fail_return(&format!(
                            "anchor T{} is not in the theorem registry",
                            anchor.theorem_id
                        ))
                    });
                let record = mint_verification(
                    &anchor,
                    &decl,
                    axioms_map.as_ref(),
                    &policy,
                    recheck,
                    &toolchain,
                    &mathlib,
                    &verifier_output_hash,
                    &now,
                    &actor,
                    &signing,
                )
                .unwrap_or_else(|e| fail_return(&e));
                let record_path = out.join(format!("T{}.vlv.json", anchor.theorem_id));
                let serialized =
                    serde_json::to_string_pretty(&record).expect("serialize verification");
                std::fs::write(&record_path, format!("{serialized}\n")).unwrap_or_else(|e| {
                    fail_return(&format!("write {}: {e}", record_path.display()))
                });
                summary.push(json!({
                    "theorem_id": anchor.theorem_id,
                    "anchor_id": anchor.anchor_id,
                    "verification_id": record.verification_id,
                    "status": record.status,
                    "axiom_verdict": record.axiom_verdict.map(|v| v.as_str()),
                    "out": record_path.display().to_string(),
                }));
            }
            if json {
                let payload = json!({
                    "ok": true,
                    "command": "lean.verify-all",
                    "verified": summary.len(),
                    "verifier_output_hash": verifier_output_hash,
                    "lean_toolchain": toolchain,
                    "mathlib_revision": mathlib,
                    "tcb_id": policy.tcb_id,
                    "kernel_recheck": recheck.as_str(),
                    "records": summary,
                });
                print_json(&payload);
            } else {
                println!(
                    "{} signed {} verification record(s) under {} (toolchain {}, tcb {})",
                    style::ok("lean.verify-all"),
                    summary.len(),
                    out.display(),
                    toolchain,
                    policy.tcb_id,
                );
            }
        }
        LeanAction::VerifyCheck {
            record,
            anchor,
            tcb,
            json,
        } => {
            use vela_protocol::lean_verification::LeanVerification;
            let body = std::fs::read_to_string(&record)
                .unwrap_or_else(|e| fail_return(&format!("read {}: {e}", record.display())));
            let rec: LeanVerification = serde_json::from_str(&body)
                .unwrap_or_else(|e| fail_return(&format!("parse verification: {e}")));
            rec.verify()
                .unwrap_or_else(|e| fail_return(&format!("verify failed: {e}")));
            // Independently re-classify the record's axioms against the policy.
            if let Some(tcb_path) = tcb {
                use vela_protocol::tcb_policy::TcbPolicy;
                let tbody = std::fs::read_to_string(&tcb_path)
                    .unwrap_or_else(|e| fail_return(&format!("read {}: {e}", tcb_path.display())));
                let policy: TcbPolicy = serde_json::from_str(&tbody)
                    .unwrap_or_else(|e| fail_return(&format!("parse tcb policy: {e}")));
                policy
                    .verify()
                    .unwrap_or_else(|e| fail_return(&format!("tcb policy invalid: {e}")));
                if !rec.tcb_id.is_empty() && rec.tcb_id != policy.tcb_id {
                    fail(&format!(
                        "tcb_id mismatch: record cites {}, policy is {}",
                        rec.tcb_id, policy.tcb_id
                    ));
                }
                if let Some(declared) = rec.axiom_verdict {
                    let recomputed = policy.classify(&rec.axioms);
                    if recomputed != declared {
                        fail(&format!(
                            "axiom_verdict mismatch: record declares {}, policy recomputes {}",
                            declared.as_str(),
                            recomputed.as_str()
                        ));
                    }
                }
            }
            if let Some(anchor_path) = anchor {
                let abody = std::fs::read_to_string(&anchor_path).unwrap_or_else(|e| {
                    fail_return(&format!("read {}: {e}", anchor_path.display()))
                });
                let a: vela_edge::lean_anchors::LeanAnchor = serde_json::from_str(&abody)
                    .unwrap_or_else(|e| fail_return(&format!("parse anchor: {e}")));
                if a.anchor_id != rec.anchor_id {
                    fail(&format!(
                        "anchor_id mismatch: record claims {}, anchor file is {}",
                        rec.anchor_id, a.anchor_id
                    ));
                }
                if a.module_sha256 != rec.module_sha256 {
                    fail(&format!(
                        "module_sha256 mismatch: record claims {}, anchor file is {}",
                        rec.module_sha256, a.module_sha256
                    ));
                }
            }
            if json {
                let payload = json!({
                    "ok": true,
                    "command": "lean.verify-check",
                    "verification_id": rec.verification_id,
                    "anchor_id": rec.anchor_id,
                    "theorem_id": rec.theorem_id,
                    "status": rec.status,
                });
                print_json(&payload);
            } else {
                println!(
                    "{} {} (T{}) verifies under {}",
                    style::ok("lean.verify-check"),
                    rec.verification_id,
                    rec.theorem_id,
                    rec.verifier_actor
                );
            }
        }
    }
}

/// Mint one signed `vlv_` LeanVerification for an anchored decl. Shared by
/// `vela lean verify-all` (registry theorems) and `vela foundry lean-run`
/// (formal-conjectures targets). When `axioms_map` is `Some`, the decl's axioms
/// are classified against `policy` and the record is FAILED-CLOSED if the report
/// omits the decl (never silently mint an axiom-unknown `verified`); `None`
/// mints an axiom-unknown legacy-style attestation. The preimage is byte-
/// identical to the prior inline path, so existing `vlv_` ids/signatures are
/// unchanged. The verifier (this code + the Lean kernel) is the trust; the
/// producer of the proof is never in the trust path.
#[allow(clippy::too_many_arguments)]
pub(crate) fn mint_verification(
    anchor: &vela_edge::lean_anchors::LeanAnchor,
    decl: &str,
    axioms_map: Option<&std::collections::BTreeMap<String, Vec<String>>>,
    policy: &vela_protocol::tcb_policy::TcbPolicy,
    recheck: vela_protocol::lean_verification::KernelRecheck,
    toolchain: &str,
    mathlib: &str,
    verifier_output_hash: &str,
    verified_at: &str,
    verifier_actor: &str,
    signing: &ed25519_dalek::SigningKey,
) -> Result<vela_protocol::lean_verification::LeanVerification, String> {
    use vela_protocol::lean_verification::{LeanVerification, VerificationDraft};
    let (status, axioms, verdict, kernel_recheck, axioms_hash, tcb_id) = match axioms_map {
        None => (
            "verified".to_string(),
            Vec::new(),
            None,
            None,
            String::new(),
            String::new(),
        ),
        Some(map) => {
            // Fail closed: a report is present but this decl is absent. Never
            // silently mint an axiom-unknown (and thus possibly `verified`) record.
            let axioms = map.get(decl).cloned().ok_or_else(|| {
                format!(
                    "axioms report has no entry for decl `{decl}`; \
                     refusing to classify it as clean"
                )
            })?;
            let verdict = policy.classify(&axioms);
            let status = axiom_status(verdict, &axioms, recheck).to_string();
            let line_digest = {
                let mut h = sha2::Sha256::new();
                sha2::Digest::update(&mut h, format!("{decl}|{}", axioms.join(",")).as_bytes());
                hex::encode(h.finalize())
            };
            (
                status,
                axioms,
                Some(verdict),
                Some(recheck),
                line_digest,
                policy.tcb_id.clone(),
            )
        }
    };
    LeanVerification::build(
        VerificationDraft {
            anchor_id: anchor.anchor_id.clone(),
            theorem_id: anchor.theorem_id,
            module: anchor.module.clone(),
            module_sha256: anchor.module_sha256.clone(),
            lean_toolchain: toolchain.to_string(),
            mathlib_revision: mathlib.to_string(),
            verifier_output_hash: verifier_output_hash.to_string(),
            status,
            verified_at: verified_at.to_string(),
            verifier_actor: verifier_actor.to_string(),
            tcb_id,
            axioms,
            axiom_verdict: verdict,
            kernel_recheck,
            axioms_output_hash: axioms_hash,
        },
        signing,
    )
}

/// Run `#print axioms <fq_decl>` over a built module in `lean_dir` (e.g. the
/// formal-conjectures clone) via `lake env lean`, returning the sorted, deduped
/// axiom list. A `sorryAx` entry means the decl still carries a proof hole — the
/// honest signal the Lean lane fails closed on. `lean_import` is the dotted
/// import path (numeric components wrapped in guillemets, e.g.
/// `FormalConjectures.ErdosProblems.«828»`). The probe writes a temporary Lean
/// file inside the package so the import resolves against the warm `.lake`
/// build, runs it, and removes it.
pub(crate) fn lean_axioms_probe(
    lean_dir: &std::path::Path,
    lean_import: &str,
    fq_decl: &str,
) -> Result<Vec<String>, String> {
    let stamp = {
        let mut h = sha2::Sha256::new();
        sha2::Digest::update(&mut h, fq_decl.as_bytes());
        hex::encode(h.finalize())[..12].to_string()
    };
    let probe_name = format!("VelaFoundryProbe_{stamp}.lean");
    let probe_path = lean_dir.join(&probe_name);
    let body = format!("import {lean_import}\n#print axioms {fq_decl}\n");
    std::fs::write(&probe_path, body)
        .map_err(|e| format!("write probe {}: {e}", probe_path.display()))?;
    let out = std::process::Command::new("lake")
        .arg("env")
        .arg("lean")
        .arg(&probe_name)
        .current_dir(lean_dir)
        .output();
    let _ = std::fs::remove_file(&probe_path);
    let out = out.map_err(|e| format!("run `lake env lean`: {e}"))?;
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    parse_print_axioms(&combined).ok_or_else(|| {
        format!(
            "#print axioms produced no axiom line for `{fq_decl}` \
             (output: {})",
            combined.trim().chars().take(400).collect::<String>()
        )
    })
}

/// Parse the native `#print axioms <decl>` output. The relevant line is either
/// `'<decl>' depends on axioms: [a, b, c]` or `... does not depend on any
/// axioms`. Returns the sorted, deduped axiom list (empty for the latter), or
/// `None` if no axiom line is present (a build/elaboration error).
fn parse_print_axioms(text: &str) -> Option<Vec<String>> {
    for line in text.lines() {
        let line = line.trim();
        if line.contains("does not depend on any axioms") {
            return Some(Vec::new());
        }
        if let Some(i) = line.find("depends on axioms:") {
            let rest = &line[i + "depends on axioms:".len()..];
            let inside = rest.trim().trim_start_matches('[').trim_end_matches(']');
            let mut list: Vec<String> = inside
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            list.sort();
            list.dedup();
            return Some(list);
        }
    }
    None
}

/// Parse the per-decl axiom report emitted by `lean/Vela/AxiomAudit.lean`.
/// Each relevant line has the form `AXIOMS <decl> | a, b, c` (the axiom list
/// may be empty). Returns a map `decl -> sorted, deduped axiom names`. Lines
/// without the `AXIOMS ` prefix are ignored, so the report can carry other
/// diagnostic output.
pub(crate) fn parse_axioms_report(text: &str) -> std::collections::BTreeMap<String, Vec<String>> {
    let mut map = std::collections::BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("AXIOMS ") else {
            continue;
        };
        let (decl, axioms) = match rest.split_once('|') {
            Some((d, a)) => (d.trim().to_string(), a),
            None => (rest.trim().to_string(), ""),
        };
        let mut list: Vec<String> = axioms
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        list.sort();
        list.dedup();
        map.insert(decl, list);
    }
    map
}

/// Decide the verification status string from the axiom verdict, the observed
/// axioms, and the external kernel re-check:
/// - a `sorryAx` hole is always `failed_axiom_check` (a genuine proof gap);
/// - a proof clean except for compiler-trust axioms (`native_decide` etc.) is
///   the honest `compiler_checked` tier, not a failure;
/// - any other unlisted axiom is `failed_axiom_check` (conservative default);
/// - a kernel-clean proof is `verified`, unless the external re-check failed.
fn axiom_status(
    verdict: vela_protocol::tcb_policy::AxiomVerdict,
    axioms: &[String],
    recheck: vela_protocol::lean_verification::KernelRecheck,
) -> &'static str {
    use vela_protocol::lean_verification::KernelRecheck;
    use vela_protocol::tcb_policy::AxiomVerdict;
    if axioms.iter().any(|a| a == "sorryAx") {
        return "failed_axiom_check";
    }
    match verdict {
        AxiomVerdict::ForbiddenAxiom => "compiler_checked",
        AxiomVerdict::UnlistedAxiom => "failed_axiom_check",
        AxiomVerdict::KernelClean => {
            if recheck == KernelRecheck::Failed {
                "failed_axiom_check"
            } else {
                "verified"
            }
        }
    }
}

/// `vela attempt verify <file>` — round-trip a banked attempt (or a whole
/// ledger) through `Attempt::verify()`: id re-derivation + claim_digest +
/// Ed25519 signature, exactly the checks the reducer runs on deposit.
pub(crate) fn cmd_attempt(action: AttemptAction) {
    use vela_protocol::attempt::Attempt;
    match action {
        AttemptAction::Verify { file, json } => {
            let body = std::fs::read_to_string(&file)
                .unwrap_or_else(|e| fail_return(&format!("read {}: {e}", file.display())));
            let val: serde_json::Value = serde_json::from_str(&body)
                .unwrap_or_else(|e| fail_return(&format!("parse {}: {e}", file.display())));
            // Accept a single Attempt or a {"records": [...]} ledger (v1/v2).
            let records: Vec<serde_json::Value> = val
                .get("records")
                .and_then(|r| r.as_array())
                .cloned()
                .unwrap_or_else(|| vec![val.clone()]);

            let mut verified = 0usize;
            let mut unsigned = 0usize;
            let mut failures: Vec<String> = Vec::new();
            for (i, rv) in records.iter().enumerate() {
                let sig_empty = rv
                    .get("signature")
                    .and_then(|s| s.as_str())
                    .map(str::is_empty)
                    .unwrap_or(true);
                let att: Attempt = match serde_json::from_value(rv.clone()) {
                    Ok(a) => a,
                    Err(e) => {
                        failures.push(format!("record {i}: parse error: {e}"));
                        continue;
                    }
                };
                if sig_empty {
                    unsigned += 1;
                    continue;
                }
                match att.verify() {
                    Ok(()) => verified += 1,
                    Err(e) => failures.push(format!("{}: {e}", att.attempt_id)),
                }
            }

            if json {
                print_json(&json!({
                    "ok": failures.is_empty(),
                    "command": "attempt.verify",
                    "verified": verified,
                    "unsigned": unsigned,
                    "failed": failures.len(),
                    "failures": failures,
                }));
            } else if failures.is_empty() {
                let tail = if unsigned > 0 {
                    format!(" ({unsigned} unsigned, skipped)")
                } else {
                    String::new()
                };
                println!(
                    "{} {} attempt(s) verify{}",
                    style::ok("attempt.verify"),
                    verified,
                    tail
                );
            } else {
                fail(&format!(
                    "{verified} verified, {unsigned} unsigned, {} FAILED:\n  {}",
                    failures.len(),
                    failures.join("\n  ")
                ));
            }
        }
        AttemptAction::List {
            frontier,
            problem,
            kind,
            status,
            json,
        } => {
            let source = vela_protocol::repo::detect(&frontier).unwrap_or_else(|e| fail_return(&e));
            let proj = vela_protocol::repo::load(&source).unwrap_or_else(|e| fail_return(&e));
            let mut rows: Vec<serde_json::Value> = Vec::new();
            for ev in &proj.events {
                if ev.kind != "attempt.deposited" {
                    continue;
                }
                let a = ev.payload.get("attempt").cloned().unwrap_or_default();
                let p = a.get("problem").and_then(|v| v.as_u64());
                let k = a.get("kind").and_then(|v| v.as_str()).unwrap_or("");
                let st = a
                    .get("claimed_status")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if problem.is_some() && p != problem.map(u64::from) {
                    continue;
                }
                if kind.as_deref().is_some_and(|kf| kf != k) {
                    continue;
                }
                if status.as_deref().is_some_and(|sf| sf != st) {
                    continue;
                }
                rows.push(serde_json::json!({
                    "attempt_id": a.get("attempt_id"),
                    "problem": p, "kind": k, "status": st,
                    "claim": a.get("claim"),
                    "method_families": a.get("method_families"),
                    "named_obstructions": a.get("named_obstructions"),
                }));
            }
            if json {
                crate::cli::print_json(&serde_json::json!({
                    "frontier": frontier.display().to_string(),
                    "attempts": rows.len(),
                    "ledger": rows,
                }));
            } else {
                println!(
                    "banked attempts in {} — {} (durable inherited memory)",
                    frontier.display(),
                    rows.len()
                );
                for r in &rows {
                    println!(
                        "  {} [problem {} {}] {}: {}",
                        r["attempt_id"].as_str().unwrap_or(""),
                        r["problem"],
                        r["kind"].as_str().unwrap_or(""),
                        r["status"].as_str().unwrap_or(""),
                        r["claim"]
                            .as_str()
                            .unwrap_or("")
                            .chars()
                            .take(60)
                            .collect::<String>()
                    );
                }
                if rows.is_empty() {
                    println!("  (no banked attempts in this frontier's log)");
                }
            }
        }
    }
}

/// The read-time T1–T5 admission resolver (`vela transfer verify --admit`): the
/// pure `derive_transfer_status` made callable over LIVE state. It resolves A's
/// gate from `frontier`'s accepted attachments (T1), the theorem `vlv_` from
/// `vlv_path` (T2), and the domain tags (T3), then reports the verdict — never a
/// stored boolean, recomputed from already-signed objects. This is the moat's
/// machinery given its caller; the verdict is honest (NeedsVerification until A
/// is gate-verified and the real `vlv_` is bound, Admitted once T1–T5 hold).
fn cmd_transfer_admit(
    records: &[serde_json::Value],
    frontier: Option<&std::path::Path>,
    vlv_path: Option<&std::path::Path>,
    source_domain: Option<&str>,
    target_domain: Option<&str>,
    json: bool,
) {
    use vela_protocol::lean_verification::LeanVerification;
    use vela_protocol::transfer::{DomainTags, Transfer, derive_transfer_status};
    use vela_protocol::verifier_attachment::{GateOutcome, GateStatus, derive_gate_status};

    let rv = records
        .first()
        .unwrap_or_else(|| fail_return("no transfer record to admit"));
    let t: Transfer = serde_json::from_value(rv.clone())
        .unwrap_or_else(|e| fail_return(&format!("parse transfer: {e}")));

    // T1: A's gate, derived from the source frontier's accepted attachments.
    let source_gate: GateOutcome = match frontier {
        Some(fr) => {
            let source = vela_protocol::repo::detect(fr).unwrap_or_else(|e| fail_return(&e));
            let proj = vela_protocol::repo::load(&source).unwrap_or_else(|e| fail_return(&e));
            derive_gate_status(&t.source_claim_digest, &proj.verifier_attachments)
        }
        None => GateOutcome {
            status: GateStatus::NeedsVerification,
            reasons: vec![
                "no --frontier given: A's gate could not be resolved from state".to_string(),
            ],
        },
    };

    // T2: the transfer theorem's vlv_ (Mint with `vela foundry lean-run`).
    let vlv: Option<LeanVerification> = vlv_path.map(|p| {
        let b = std::fs::read_to_string(p)
            .unwrap_or_else(|e| fail_return(&format!("read {}: {e}", p.display())));
        serde_json::from_str(&b)
            .unwrap_or_else(|e| fail_return(&format!("parse vlv {}: {e}", p.display())))
    });

    // T3: domain tags (operator may override; default to the declared types).
    let tags = DomainTags {
        source: source_domain
            .unwrap_or(&t.homomorphism.source_type)
            .to_string(),
        target: target_domain
            .unwrap_or(&t.homomorphism.target_type)
            .to_string(),
    };

    let outcome = derive_transfer_status(&t, &source_gate, vlv.as_ref(), &tags);

    if json {
        print_json(&json!({
            "command": "transfer.verify.admit",
            "transfer_id": t.transfer_id,
            "status": format!("{:?}", outcome.status).to_lowercase(),
            "admitted": outcome.is_admitted(),
            "source_gate": format!("{:?}", source_gate.status).to_lowercase(),
            "source_gate_reasons": source_gate.reasons,
            "reasons": outcome.reasons,
            "domain_tags": { "source": tags.source, "target": tags.target },
            "vlv_resolved": vlv.is_some(),
        }));
    } else {
        let mark = if outcome.is_admitted() {
            style::ok("ADMITTED")
        } else {
            style::lost("not admitted")
        };
        println!(
            "{} transfer {} -> {mark}",
            style::ok("transfer.admit"),
            t.transfer_id
        );
        println!("  source gate (A): {:?}", source_gate.status);
        if outcome.reasons.is_empty() {
            println!("  T1–T5 all satisfied; A's claim discharges B's premise.");
        }
        for r in &outcome.reasons {
            println!("    - {r}");
        }
    }
}

/// Structurally verify cross-domain transfers (`vtr_`): id re-derivation +
/// Ed25519 signature, mirroring `cmd_attempt`. The T1–T5 admission gate
/// (`derive_transfer_status`) runs in the reducer / on read, not here.
pub(crate) fn cmd_transfer(action: TransferAction) {
    use vela_protocol::transfer::Transfer;
    match action {
        TransferAction::Verify {
            file,
            admit,
            frontier,
            vlv,
            source_domain,
            target_domain,
            json,
        } => {
            let body = std::fs::read_to_string(&file)
                .unwrap_or_else(|e| fail_return(&format!("read {}: {e}", file.display())));
            let val: serde_json::Value = serde_json::from_str(&body)
                .unwrap_or_else(|e| fail_return(&format!("parse {}: {e}", file.display())));
            let records: Vec<serde_json::Value> = val
                .get("records")
                .and_then(|r| r.as_array())
                .cloned()
                .unwrap_or_else(|| vec![val.clone()]);

            // --admit: re-derive the T1–T5 admission verdict over real state.
            // This is the read-time `derive_transfer_status` made callable (the
            // moat's machinery had no caller resolving live state). A pure
            // function of already-signed objects, recomputed on read.
            if admit {
                cmd_transfer_admit(
                    &records,
                    frontier.as_deref(),
                    vlv.as_deref(),
                    source_domain.as_deref(),
                    target_domain.as_deref(),
                    json,
                );
                return;
            }

            let mut verified = 0usize;
            let mut unsigned = 0usize;
            let mut failures: Vec<String> = Vec::new();
            for (i, rv) in records.iter().enumerate() {
                let sig_empty = rv
                    .get("signature")
                    .and_then(|s| s.as_str())
                    .map(str::is_empty)
                    .unwrap_or(true);
                let t: Transfer = match serde_json::from_value(rv.clone()) {
                    Ok(t) => t,
                    Err(e) => {
                        failures.push(format!("record {i}: parse error: {e}"));
                        continue;
                    }
                };
                if sig_empty {
                    unsigned += 1;
                    continue;
                }
                match t.verify() {
                    Ok(()) => verified += 1,
                    Err(e) => failures.push(format!("{}: {e}", t.transfer_id)),
                }
            }

            if json {
                print_json(&json!({
                    "ok": failures.is_empty(),
                    "command": "transfer.verify",
                    "verified": verified,
                    "unsigned": unsigned,
                    "failed": failures.len(),
                    "failures": failures,
                }));
            } else if failures.is_empty() {
                let tail = if unsigned > 0 {
                    format!(" ({unsigned} unsigned, skipped)")
                } else {
                    String::new()
                };
                println!(
                    "{} {} transfer(s) verify{}",
                    style::ok("transfer.verify"),
                    verified,
                    tail
                );
            } else {
                fail(&format!(
                    "{verified} verified, {unsigned} unsigned, {} FAILED:\n  {}",
                    failures.len(),
                    failures.join("\n  ")
                ));
            }
        }
        TransferAction::Mint { draft, key, out } => {
            use vela_protocol::transfer::{Transfer, TransferDraft};
            let body = std::fs::read_to_string(&draft)
                .unwrap_or_else(|e| fail_return(&format!("read draft {}: {e}", draft.display())));
            let d: TransferDraft = serde_json::from_str(&body)
                .unwrap_or_else(|e| fail_return(&format!("parse draft {}: {e}", draft.display())));
            let signing = crate::cli_identity::resolve_signing_key(key.as_deref());
            let t = Transfer::build(d, &signing)
                .unwrap_or_else(|e| fail_return(&format!("build transfer: {e}")));
            let json_out = serde_json::to_string_pretty(&t).unwrap_or_default();
            std::fs::write(&out, format!("{json_out}\n"))
                .unwrap_or_else(|e| fail_return(&format!("write {}: {e}", out.display())));
            println!(
                "{} {} -> {}",
                style::ok("transfer.mint"),
                t.transfer_id,
                out.display()
            );
        }
        TransferAction::Registry { dir, json, out } => {
            use vela_protocol::transfer_registry::build_registry;
            let dir = dir.unwrap_or_else(|| std::path::PathBuf::from("examples/transfers"));
            let read = std::fs::read_dir(&dir)
                .unwrap_or_else(|e| fail_return(&format!("read dir {}: {e}", dir.display())));
            let mut files: Vec<std::path::PathBuf> = read
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.to_string_lossy().ends_with(".vtr.json"))
                .collect();
            files.sort();

            let mut transfers: Vec<Transfer> = Vec::new();
            let mut skipped: Vec<String> = Vec::new();
            for f in &files {
                let body = match std::fs::read_to_string(f) {
                    Ok(b) => b,
                    Err(e) => {
                        skipped.push(format!("{}: {e}", f.display()));
                        continue;
                    }
                };
                let val: serde_json::Value = match serde_json::from_str(&body) {
                    Ok(v) => v,
                    Err(e) => {
                        skipped.push(format!("{}: {e}", f.display()));
                        continue;
                    }
                };
                let records = val
                    .get("records")
                    .and_then(|r| r.as_array())
                    .cloned()
                    .unwrap_or_else(|| vec![val]);
                for rv in records {
                    match serde_json::from_value::<Transfer>(rv) {
                        Ok(t) => transfers.push(t),
                        Err(e) => skipped.push(format!("{}: {e}", f.display())),
                    }
                }
            }

            let reg = build_registry(&transfers);
            if let Some(path) = &out {
                let txt = serde_json::to_string_pretty(&reg).unwrap_or_default();
                std::fs::write(path, format!("{txt}\n"))
                    .unwrap_or_else(|e| fail_return(&format!("write {}: {e}", path.display())));
                eprintln!("wrote {} ({} transfers)", path.display(), reg.total);
            }
            if json {
                print_json(&serde_json::to_value(&reg).unwrap_or_default());
            } else if out.is_none() {
                println!(
                    "{} {} transfer(s), {} structurally ok",
                    style::ok("transfer.registry"),
                    reg.total,
                    reg.structural_ok
                );
                println!(
                    "  lanes: {} certified · {} target-checked · {} exploratory",
                    reg.lanes.certified, reg.lanes.target_checked, reg.lanes.exploratory
                );
                for (pair, ids) in &reg.by_domain_pair {
                    println!("  {} ({})", pair, ids.len());
                }
                for r in &reg.records {
                    let mark = if r.structural_ok { "ok" } else { "FAIL" };
                    let thm = r.theorem_id.map(|i| format!(" T{i}")).unwrap_or_default();
                    println!("    [{mark}] {}  {}{thm}", r.transfer_id, r.map_decl);
                }
            }
            if !skipped.is_empty() {
                eprintln!(
                    "note: {} file(s)/record(s) skipped:\n  {}",
                    skipped.len(),
                    skipped.join("\n  ")
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vela_protocol::lean_verification::KernelRecheck;
    use vela_protocol::tcb_policy::{AxiomVerdict, TcbPolicy};

    fn policy() -> TcbPolicy {
        TcbPolicy::default_for("leanprover/lean4:v4.29.1", "v4.29.1", "none", "").unwrap()
    }

    #[test]
    fn parse_print_axioms_clean_and_sorry() {
        let clean = "'Erdos828.foo' depends on axioms: [propext, Classical.choice, Quot.sound]";
        assert_eq!(
            parse_print_axioms(clean).unwrap(),
            vec!["Classical.choice", "Quot.sound", "propext"]
        );
        let none = "'Foo.bar' does not depend on any axioms";
        assert!(parse_print_axioms(none).unwrap().is_empty());
        let sorry = "'Erdos828.erdos_828' depends on axioms: [sorryAx]";
        assert_eq!(parse_print_axioms(sorry).unwrap(), vec!["sorryAx"]);
        // No axiom line (an elaboration error) => None, so the caller fails closed.
        assert!(parse_print_axioms("error: unknown identifier").is_none());
    }

    #[test]
    fn parse_report_keys_by_decl() {
        let text = "noise line\n\
            AXIOMS Vela.Foo.bar | propext, Classical.choice\n\
            AXIOMS Vela.Foo.baz | \n\
            AXIOMS Vela.Foo.qux | Lean.ofReduceBool, Lean.trustCompiler\n";
        let m = parse_axioms_report(text);
        assert_eq!(
            m.get("Vela.Foo.bar").unwrap(),
            &vec!["Classical.choice", "propext"]
        );
        assert!(m.get("Vela.Foo.baz").unwrap().is_empty());
        assert_eq!(
            m.get("Vela.Foo.qux").unwrap(),
            &vec!["Lean.ofReduceBool", "Lean.trustCompiler"]
        );
    }

    #[test]
    fn native_decide_is_compiler_checked_not_failed() {
        let axioms = vec![
            "Lean.ofReduceBool".to_string(),
            "Lean.trustCompiler".to_string(),
        ];
        let verdict = policy().classify(&axioms);
        assert_eq!(verdict, AxiomVerdict::ForbiddenAxiom);
        assert_eq!(
            axiom_status(verdict, &axioms, KernelRecheck::NotRun),
            "compiler_checked"
        );
    }

    #[test]
    fn sorry_is_failed_axiom_check() {
        let axioms = vec!["sorryAx".to_string()];
        let verdict = policy().classify(&axioms);
        assert_eq!(
            axiom_status(verdict, &axioms, KernelRecheck::NotRun),
            "failed_axiom_check"
        );
    }

    #[test]
    fn kernel_clean_verified_unless_recheck_failed() {
        let axioms = vec!["propext".to_string()];
        let verdict = policy().classify(&axioms);
        assert_eq!(
            axiom_status(verdict, &axioms, KernelRecheck::Passed),
            "verified"
        );
        assert_eq!(
            axiom_status(verdict, &axioms, KernelRecheck::NotRun),
            "verified"
        );
        assert_eq!(
            axiom_status(verdict, &axioms, KernelRecheck::Failed),
            "failed_axiom_check"
        );
    }

    #[test]
    fn unlisted_axiom_is_failed() {
        let axioms = vec!["MyDev.customAxiom".to_string()];
        let verdict = policy().classify(&axioms);
        assert_eq!(
            axiom_status(verdict, &axioms, KernelRecheck::NotRun),
            "failed_axiom_check"
        );
    }
}
