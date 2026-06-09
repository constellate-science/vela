//! `cmd_lean` and its handler logic, split out of cli.rs.

use crate::cli::{fail, fail_return, print_json};
use vela_protocol::cli_style as style;
use std::path::PathBuf;

use serde_json::json;
use sha2::Digest;

use crate::cli_commands::*;

/// v0.164: handle `vela lean ...`. Anchors substrate theorems to
/// their content-addressed source bytes.
pub(crate) fn cmd_lean(action: LeanAction) {
    use vela_protocol::lean_anchors::{LeanAnchor, THEOREMS, lean_dir_default};

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
            use vela_protocol::lean_verification::{
                KernelRecheck, LeanVerification, VerificationDraft,
            };
            use vela_protocol::tcb_policy::{
                TcbDraft, TcbPolicy, DEFAULT_ALLOWED_AXIOMS, FORBIDDEN_AXIOMS,
            };

            let key_hex = std::fs::read_to_string(&key)
                .unwrap_or_else(|e| fail_return(&format!("read key {}: {e}", key.display())));
            let key_bytes = hex::decode(key_hex.trim())
                .unwrap_or_else(|e| fail_return(&format!("decode key hex: {e}")));
            let key_arr: [u8; 32] = key_bytes
                .try_into()
                .unwrap_or_else(|_| fail_return("signing key must be 32 bytes"));
            let signing = ed25519_dalek::SigningKey::from_bytes(&key_arr);

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
                    Err(e) => fail_return(&format!("read kernel re-check log {}: {e}", p.display())),
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
                format!("{}\n", serde_json::to_string_pretty(&policy).expect("serialize tcb")),
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
                let anchor: vela_protocol::lean_anchors::LeanAnchor = serde_json::from_str(&body)
                    .unwrap_or_else(|e| fail_return(&format!("parse {}: {e}", path.display())));

                // Classify the theorem's axioms when a report is present.
                let (status, axioms, verdict, kernel_recheck, axioms_hash, tcb_id) =
                    match &axioms_map {
                        None => (
                            "verified".to_string(),
                            Vec::new(),
                            None,
                            None,
                            String::new(),
                            String::new(),
                        ),
                        Some(map) => {
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
                            // Fail closed: a report is present but this decl is
                            // absent. Never silently mint an axiom-unknown
                            // (and thus possibly `verified`) record.
                            let axioms = map.get(&decl).cloned().unwrap_or_else(|| {
                                fail_return(&format!(
                                    "axioms report has no entry for decl `{decl}` (T{}); \
                                     refusing to classify it as clean",
                                    anchor.theorem_id
                                ))
                            });
                            let verdict = policy.classify(&axioms);
                            let status = axiom_status(verdict, &axioms, recheck).to_string();
                            let line_digest = {
                                let mut h = sha2::Sha256::new();
                                sha2::Digest::update(
                                    &mut h,
                                    format!("{decl}|{}", axioms.join(",")).as_bytes(),
                                );
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

                let record = LeanVerification::build(
                    VerificationDraft {
                        anchor_id: anchor.anchor_id.clone(),
                        theorem_id: anchor.theorem_id,
                        module: anchor.module.clone(),
                        module_sha256: anchor.module_sha256.clone(),
                        lean_toolchain: toolchain.clone(),
                        mathlib_revision: mathlib.clone(),
                        verifier_output_hash: verifier_output_hash.clone(),
                        status,
                        verified_at: now.clone(),
                        verifier_actor: actor.clone(),
                        tcb_id,
                        axioms,
                        axiom_verdict: verdict,
                        kernel_recheck,
                        axioms_output_hash: axioms_hash,
                    },
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
                let tbody = std::fs::read_to_string(&tcb_path).unwrap_or_else(|e| {
                    fail_return(&format!("read {}: {e}", tcb_path.display()))
                });
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
                let a: vela_protocol::lean_anchors::LeanAnchor = serde_json::from_str(&abody)
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

/// Parse the per-decl axiom report emitted by `lean/Vela/AxiomAudit.lean`.
/// Each relevant line has the form `AXIOMS <decl> | a, b, c` (the axiom list
/// may be empty). Returns a map `decl -> sorted, deduped axiom names`. Lines
/// without the `AXIOMS ` prefix are ignored, so the report can carry other
/// diagnostic output.
fn parse_axioms_report(text: &str) -> std::collections::BTreeMap<String, Vec<String>> {
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vela_protocol::lean_verification::KernelRecheck;
    use vela_protocol::tcb_policy::{TcbPolicy, AxiomVerdict};

    fn policy() -> TcbPolicy {
        TcbPolicy::default_for("leanprover/lean4:v4.29.1", "v4.29.1", "none", "").unwrap()
    }

    #[test]
    fn parse_report_keys_by_decl() {
        let text = "noise line\n\
            AXIOMS Vela.Foo.bar | propext, Classical.choice\n\
            AXIOMS Vela.Foo.baz | \n\
            AXIOMS Vela.Foo.qux | Lean.ofReduceBool, Lean.trustCompiler\n";
        let m = parse_axioms_report(text);
        assert_eq!(m.get("Vela.Foo.bar").unwrap(), &vec!["Classical.choice", "propext"]);
        assert!(m.get("Vela.Foo.baz").unwrap().is_empty());
        assert_eq!(
            m.get("Vela.Foo.qux").unwrap(),
            &vec!["Lean.ofReduceBool", "Lean.trustCompiler"]
        );
    }

    #[test]
    fn native_decide_is_compiler_checked_not_failed() {
        let axioms = vec!["Lean.ofReduceBool".to_string(), "Lean.trustCompiler".to_string()];
        let verdict = policy().classify(&axioms);
        assert_eq!(verdict, AxiomVerdict::ForbiddenAxiom);
        assert_eq!(axiom_status(verdict, &axioms, KernelRecheck::NotRun), "compiler_checked");
    }

    #[test]
    fn sorry_is_failed_axiom_check() {
        let axioms = vec!["sorryAx".to_string()];
        let verdict = policy().classify(&axioms);
        assert_eq!(axiom_status(verdict, &axioms, KernelRecheck::NotRun), "failed_axiom_check");
    }

    #[test]
    fn kernel_clean_verified_unless_recheck_failed() {
        let axioms = vec!["propext".to_string()];
        let verdict = policy().classify(&axioms);
        assert_eq!(axiom_status(verdict, &axioms, KernelRecheck::Passed), "verified");
        assert_eq!(axiom_status(verdict, &axioms, KernelRecheck::NotRun), "verified");
        assert_eq!(axiom_status(verdict, &axioms, KernelRecheck::Failed), "failed_axiom_check");
    }

    #[test]
    fn unlisted_axiom_is_failed() {
        let axioms = vec!["MyDev.customAxiom".to_string()];
        let verdict = policy().classify(&axioms);
        assert_eq!(axiom_status(verdict, &axioms, KernelRecheck::NotRun), "failed_axiom_check");
    }
}
