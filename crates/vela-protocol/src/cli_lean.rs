//! `cmd_lean` and its handler logic, split out of cli.rs.

use crate::cli::{fail, fail_return, print_json};
use crate::cli_style as style;
use std::path::PathBuf;

use serde_json::json;
use sha2::Digest;

use crate::cli_commands::*;

/// v0.164: handle `vela lean ...`. Anchors substrate theorems to
/// their content-addressed source bytes.
pub(crate) fn cmd_lean(action: LeanAction) {
    use crate::lean_anchors::{LeanAnchor, THEOREMS, lean_dir_default};

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
            json,
        } => {
            use crate::lean_verification::{LeanVerification, VerificationDraft};

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

            let out = out_dir.unwrap_or_else(|| anchors_dir.clone());
            if let Err(e) = std::fs::create_dir_all(&out) {
                fail(&format!("create {}: {e}", out.display()));
            }

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
                let anchor: crate::lean_anchors::LeanAnchor = serde_json::from_str(&body)
                    .unwrap_or_else(|e| fail_return(&format!("parse {}: {e}", path.display())));

                let record = LeanVerification::build(
                    VerificationDraft {
                        anchor_id: anchor.anchor_id.clone(),
                        theorem_id: anchor.theorem_id,
                        module: anchor.module.clone(),
                        module_sha256: anchor.module_sha256.clone(),
                        lean_toolchain: toolchain.clone(),
                        mathlib_revision: mathlib.clone(),
                        verifier_output_hash: verifier_output_hash.clone(),
                        status: "verified".to_string(),
                        verified_at: now.clone(),
                        verifier_actor: actor.clone(),
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
                    "records": summary,
                });
                print_json(&payload);
            } else {
                println!(
                    "{} signed {} verification record(s) under {} (toolchain {})",
                    style::ok("lean.verify-all"),
                    summary.len(),
                    out.display(),
                    toolchain
                );
            }
        }
        LeanAction::VerifyCheck {
            record,
            anchor,
            json,
        } => {
            use crate::lean_verification::LeanVerification;
            let body = std::fs::read_to_string(&record)
                .unwrap_or_else(|e| fail_return(&format!("read {}: {e}", record.display())));
            let rec: LeanVerification = serde_json::from_str(&body)
                .unwrap_or_else(|e| fail_return(&format!("parse verification: {e}")));
            rec.verify()
                .unwrap_or_else(|e| fail_return(&format!("verify failed: {e}")));
            if let Some(anchor_path) = anchor {
                let abody = std::fs::read_to_string(&anchor_path).unwrap_or_else(|e| {
                    fail_return(&format!("read {}: {e}", anchor_path.display()))
                });
                let a: crate::lean_anchors::LeanAnchor = serde_json::from_str(&abody)
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
