//! `vela registry verify-log` — independent verification of a hub's RFC 6962
//! transparency log. Fetches the signed tree head (STH), checks its Ed25519
//! signature against an externally pinned pubkey, recomputes the Merkle root
//! from the event content-address preimages, and (optionally) checks one
//! event's inclusion proof. This is the substrate-honest answer to "can the hub
//! forge or silently drop accepted state?" — the Rust sibling of
//! `clients/python/vela_verify_log.py`, so two independent implementations must
//! agree on the same canonical bytes.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::Value;
use vela_protocol::{canonical, events, merkle};

#[derive(serde::Serialize)]
pub(crate) struct LogReport {
    ok: bool,
    vfr_id: String,
    tree_size: u64,
    root_hash: String,
    signature: String,
    checks: Vec<String>,
}

fn get_json(url: &str) -> Result<Value, String> {
    let resp = reqwest::blocking::get(url).map_err(|e| format!("GET {url}: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("GET {url}: HTTP {}", resp.status()));
    }
    resp.json::<Value>()
        .map_err(|e| format!("parse {url}: {e}"))
}

fn parse_hash(s: &str) -> Result<[u8; 32], String> {
    let h = s.strip_prefix("sha256:").unwrap_or(s);
    hex::decode(h)
        .map_err(|e| format!("bad hash hex: {e}"))?
        .as_slice()
        .try_into()
        .map_err(|_| "hash is not 32 bytes".to_string())
}

fn verifying_key(hex_str: &str) -> Result<VerifyingKey, String> {
    let bytes: [u8; 32] = hex::decode(hex_str)
        .map_err(|e| format!("bad pubkey hex: {e}"))?
        .as_slice()
        .try_into()
        .map_err(|_| "pubkey is not 32 bytes".to_string())?;
    VerifyingKey::from_bytes(&bytes).map_err(|e| format!("invalid pubkey: {e}"))
}

fn fetch_all_events(hub: &str, vfr: &str) -> Result<Vec<Value>, String> {
    let mut out = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let url = match &cursor {
            Some(c) => format!("{hub}/entries/{vfr}/events?limit=1000&cursor={c}"),
            None => format!("{hub}/entries/{vfr}/events?limit=1000"),
        };
        let page = get_json(&url)?;
        if let Some(evs) = page.get("events").and_then(|v| v.as_array()) {
            out.extend(evs.iter().cloned());
        }
        match page.get("next_cursor").and_then(|v| v.as_str()) {
            Some(c) if !c.is_empty() => cursor = Some(c.to_string()),
            _ => break,
        }
    }
    Ok(out)
}

fn leaves_from(evs: &[Value]) -> Result<Vec<Vec<u8>>, String> {
    let mut leaves = Vec::with_capacity(evs.len());
    for v in evs {
        let ev: events::StateEvent =
            serde_json::from_value(v.clone()).map_err(|e| format!("event parse: {e}"))?;
        leaves.push(events::event_content_preimage_bytes(&ev));
    }
    Ok(leaves)
}

fn run(
    vfr: &str,
    hub: &str,
    event: Option<&str>,
    pinned: Option<&str>,
) -> Result<LogReport, String> {
    let hub = hub.trim_end_matches('/');
    let mut checks = Vec::new();

    // 1. Signed tree head.
    let sth_resp = get_json(&format!("{hub}/entries/{vfr}/log/sth"))?;
    let sth = sth_resp.get("sth").ok_or("response missing `sth`")?;
    let tree_size = sth
        .get("tree_size")
        .and_then(|v| v.as_u64())
        .ok_or("sth missing tree_size")?;
    let sth_root = sth
        .get("root_hash")
        .and_then(|v| v.as_str())
        .ok_or("sth missing root_hash")?
        .to_string();
    let sth_root_bytes = parse_hash(&sth_root)?;

    // 2. STH signature: re-canonicalize and Ed25519-verify against the pinned
    //    key (never the key the STH advertises, unless none is pinned).
    let signature;
    if let Some(sig) = sth_resp.get("signature").filter(|s| !s.is_null()) {
        let adv = sig
            .get("pubkey")
            .and_then(|v| v.as_str())
            .ok_or("signature missing pubkey")?;
        if pinned.is_some_and(|p| p != adv) {
            let p = pinned.unwrap();
            return Err(format!(
                "pubkey mismatch: pinned {}… but STH advertises {}…",
                &p[..p.len().min(16)],
                &adv[..adv.len().min(16)]
            ));
        }
        let expected = pinned.unwrap_or(adv);
        let vk = verifying_key(expected)?;
        let sig_hex = sig
            .get("value")
            .and_then(|v| v.as_str())
            .ok_or("signature missing value")?;
        let sig_bytes: [u8; 64] = hex::decode(sig_hex)
            .map_err(|e| format!("bad signature hex: {e}"))?
            .as_slice()
            .try_into()
            .map_err(|_| "signature is not 64 bytes".to_string())?;
        let canon = canonical::to_canonical_bytes(sth)?;
        vk.verify(&canon, &Signature::from_bytes(&sig_bytes))
            .map_err(|e| format!("STH signature INVALID: {e}"))?;
        signature = if pinned.is_some() {
            "verified (pinned pubkey)".to_string()
        } else {
            "verified, UNPINNED — corruption check only; pass --pubkey to bind authenticity"
                .to_string()
        };
        checks.push(format!("STH signature {signature}"));
    } else {
        signature = "unsigned (hub has no signing key)".to_string();
        checks.push(format!("STH is {signature}"));
    }

    // 3. Recompute the Merkle root from every event's content-address preimage
    //    and require it to equal the STH root — proves the hub dropped nothing.
    let evs = fetch_all_events(hub, vfr)?;
    if evs.len() as u64 != tree_size {
        return Err(format!(
            "event count {} != STH tree_size {tree_size}",
            evs.len()
        ));
    }
    let leaves = leaves_from(&evs)?;
    let recomputed = merkle::merkle_root(&leaves);
    if recomputed != sth_root_bytes {
        return Err(format!(
            "recomputed root {} != STH root {sth_root}",
            merkle::to_commitment(&recomputed)
        ));
    }
    checks.push(format!(
        "recomputed Merkle root over {} events matches the STH",
        evs.len()
    ));

    // 4. Optional: one event's RFC 6962 inclusion proof against the STH root.
    if let Some(ev_id) = event {
        let proof = get_json(&format!("{hub}/entries/{vfr}/log/proof/{ev_id}"))?;
        let idx = proof
            .get("leaf_index")
            .and_then(|v| v.as_u64())
            .ok_or("proof missing leaf_index")? as usize;
        let n = proof
            .get("tree_size")
            .and_then(|v| v.as_u64())
            .ok_or("proof missing tree_size")? as usize;
        let path: Vec<[u8; 32]> = proof
            .get("audit_path")
            .and_then(|v| v.as_array())
            .ok_or("proof missing audit_path")?
            .iter()
            .map(|h| {
                h.as_str()
                    .ok_or_else(|| "audit node not a string".to_string())
                    .and_then(parse_hash)
            })
            .collect::<Result<_, _>>()?;
        let id_at_idx = evs
            .get(idx)
            .and_then(|v| v.get("id"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if id_at_idx != ev_id {
            return Err(format!(
                "hub's leaf_index {idx} points at {id_at_idx}, not {ev_id}"
            ));
        }
        let leaf = leaves.get(idx).ok_or("leaf_index out of range")?;
        if !merkle::verify_inclusion(leaf, idx, n, &path, &sth_root_bytes) {
            return Err(format!(
                "inclusion proof for {ev_id} does NOT verify against the STH root"
            ));
        }
        checks.push(format!(
            "{ev_id} included at leaf {idx}/{n}; inclusion proof verifies against the STH root"
        ));
    }

    Ok(LogReport {
        ok: true,
        vfr_id: vfr.to_string(),
        tree_size,
        root_hash: sth_root,
        signature,
        checks,
    })
}

pub(crate) fn cmd_verify_log(
    vfr: &str,
    hub: &str,
    event: Option<&str>,
    pinned_pubkey: Option<&str>,
    json_out: bool,
) {
    // The CLI dispatches inside a tokio runtime; `reqwest::blocking` panics
    // when its own runtime drops in that context. Run the (synchronous)
    // verification on a fresh thread with no ambient runtime.
    let result = std::thread::scope(|s| {
        s.spawn(|| run(vfr, hub, event, pinned_pubkey))
            .join()
            .unwrap_or_else(|_| Err("verification thread panicked".to_string()))
    });
    match result {
        Ok(report) => {
            if json_out {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).unwrap_or_default()
                );
            } else {
                println!("transparency log  {}", report.vfr_id);
                println!("  tree_size  {}", report.tree_size);
                println!("  root       {}", report.root_hash);
                for c in &report.checks {
                    println!("  ✓ {c}");
                }
                println!("OK — the hub's log is internally consistent.");
            }
        }
        Err(e) => {
            if json_out {
                println!("{}", serde_json::json!({ "ok": false, "error": e }));
            } else {
                eprintln!("✗ verify-log: {e}");
            }
            std::process::exit(1);
        }
    }
}
