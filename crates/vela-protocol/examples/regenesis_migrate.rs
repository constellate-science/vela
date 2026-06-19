//! One-shot re-genesis runner for the v0.700 empirical-field strip.
//!
//!   cargo run -p vela-protocol --example regenesis_migrate -- \
//!       <frontier_dir> <signing_key_hex_path> [--apply] [--update-actor-pubkey]
//!
//! Default is a DRY RUN: it re-mints in memory and reports, writing nothing.
//! `--apply` rewrites `.vela/events` (old files deleted, re-minted ones written
//! under their new `vev_` ids), `.vela/proposals`, and `.vela/findings`.
//! `--update-actor-pubkey` rewrites `actors.json` so every actor's public key is
//! the supplied key's pubkey — ONLY for testing with a throwaway key; in
//! production the signer's real key already matches the registered pubkey.
//!
//! KEY CUSTODY: the key is read from the path the operator passes; this runner
//! is the operator's own invocation, never an agent acting on a human's behalf.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use vela_protocol::events::StateEvent;
use vela_protocol::migrate;
use vela_protocol::proposals::StateProposal;
use vela_protocol::sign;

fn read_dir_json<T: serde::de::DeserializeOwned>(dir: &Path) -> Vec<(PathBuf, T)> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for entry in rd.flatten() {
            let p = entry.path();
            if p.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let text = std::fs::read_to_string(&p).expect("read");
            match serde_json::from_str::<T>(&text) {
                Ok(v) => out.push((p, v)),
                Err(e) => panic!("parse {}: {e}", p.display()),
            }
        }
    }
    out
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!(
            "usage: regenesis_migrate <frontier_dir> <key_hex_path> [--apply] [--update-actor-pubkey]"
        );
        std::process::exit(2);
    }
    let dir = PathBuf::from(&args[1]);
    let key_path = PathBuf::from(&args[2]);
    let apply = args.iter().any(|a| a == "--apply");
    let update_pubkey = args.iter().any(|a| a == "--update-actor-pubkey");
    let vela = dir.join(".vela");

    let events_pairs: Vec<(PathBuf, StateEvent)> = read_dir_json(&vela.join("events"));
    let proposal_pairs: Vec<(PathBuf, StateProposal)> = read_dir_json(&vela.join("proposals"));
    let key = sign::load_signing_key_from_path(&key_path).expect("load signing key");

    let events: Vec<StateEvent> = events_pairs.iter().map(|(_, e)| e.clone()).collect();
    let proposals: Vec<StateProposal> = proposal_pairs.iter().map(|(_, p)| p.clone()).collect();

    // Every distinct signing actor in the log maps to the supplied key. (For the
    // math frontiers there is a single signer; a real multi-signer log would pass
    // a per-actor keyring — the migrate API already keys on actor id.)
    let mut actor_keys: HashMap<String, ed25519_dalek::SigningKey> = HashMap::new();
    for e in &events {
        actor_keys
            .entry(e.actor.id.clone())
            .or_insert_with(|| key.clone());
    }

    let result =
        migrate::regenesis_strip_empirical(proposals, events, &actor_keys).expect("regenesis");

    println!(
        "re-genesis: {} events ({} re-minted), {} findings, {} proposals",
        result.events.len(),
        result.reminted,
        result.findings.len(),
        result.proposals.len()
    );

    // Cryptographic self-check: every event we RE-SIGNED (a re-minted finding /
    // evidence-atom state event that carried a signature) must verify under the
    // signing key. Side-table signed events (e.g. verifier_attachment.added) are
    // passed through unchanged, so they keep their ORIGINAL signer's signature —
    // in this throwaway-key test that is not the test key, so they are out of
    // scope here; in production (the real signer's key) they stay valid because
    // their bytes never changed.
    let test_pubkey = sign::pubkey_hex(&key);
    let mut verified = 0usize;
    for e in &result.events {
        let side_table = e.before_hash == "sha256:null" && e.after_hash == "sha256:null";
        if !side_table && e.signature.is_some() {
            match sign::verify_event_signature(e, &test_pubkey) {
                Ok(true) => verified += 1,
                other => panic!("re-signed event {} FAILED verify: {other:?}", e.id),
            }
        }
    }
    println!("signature self-check: {verified} re-signed events all verify under the key ✓");

    if !apply {
        println!("dry run (no files written). pass --apply to write.");
        return;
    }

    // Events: delete the old files, write the re-minted ones under their new ids.
    for (p, _) in &events_pairs {
        std::fs::remove_file(p).ok();
    }
    let events_dir = vela.join("events");
    for e in &result.events {
        let p = events_dir.join(format!("{}.json", e.id));
        std::fs::write(&p, serde_json::to_string_pretty(e).unwrap()).unwrap();
    }
    // Proposals + findings keep their ids; overwrite the bodies in place.
    let prop_dir = vela.join("proposals");
    for pr in &result.proposals {
        std::fs::write(
            prop_dir.join(format!("{}.json", pr.id)),
            serde_json::to_string_pretty(pr).unwrap(),
        )
        .unwrap();
    }
    let find_dir = vela.join("findings");
    for f in &result.findings {
        std::fs::write(
            find_dir.join(format!("{}.json", f.id)),
            serde_json::to_string_pretty(f).unwrap(),
        )
        .unwrap();
    }
    if update_pubkey {
        let newpub = sign::pubkey_hex(&key);
        let actors_path = vela.join("actors.json");
        if let Ok(text) = std::fs::read_to_string(&actors_path) {
            let mut actors: serde_json::Value = serde_json::from_str(&text).unwrap();
            if let Some(arr) = actors.as_array_mut() {
                for a in arr {
                    a["public_key"] = serde_json::json!(newpub);
                }
            }
            std::fs::write(&actors_path, serde_json::to_string_pretty(&actors).unwrap()).unwrap();
        }
    }
    println!("applied to {}", dir.display());
}
