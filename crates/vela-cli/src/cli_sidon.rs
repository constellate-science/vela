//! `vela sidon` — the Sidon Producer Profile surface (the realized
//! finite/positive/ranked Scientific State Kernel for one live frontier:
//! lower bounds for OEIS A309370, Sidon sets in the binary cube).
//!
//! Two producer verbs, both signing with the caller's OWN key (never a
//! maintainer's):
//!   - `submit`  takes a Sidon witness and a base ObservationPacket, and emits
//!     the signed `ResultPacket` a producer proposes — the on-ramp.
//!   - `observe` replays a presentation into the authoritative best-bound
//!     `ObservationPacket`.
//!
//! The packet constructors live in `vela_protocol::sidon_profile::producer` and
//! are conformance-pinned to the Python reference; this module is the thin CLI
//! wrapper that reads inputs, stamps a real timestamp, signs, and prints.

use std::collections::BTreeSet;
use std::path::Path;

use serde_json::{Value, json};

use vela_protocol::sidon_profile::{
    Presentation, make_observation, make_result, make_task, validate_shape,
    verify_observation_replay, verify_signed_packet,
};

use crate::cli::parse_signing_key;
use crate::cli_commands::SidonAction;

fn die(msg: String) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(1);
}

fn read_json(path: &Path) -> Value {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| die(format!("read {}: {e}", path.display())));
    serde_json::from_str(&text).unwrap_or_else(|e| die(format!("parse {}: {e}", path.display())))
}

fn read_key(path: &Path) -> ed25519_dalek::SigningKey {
    let hex = std::fs::read_to_string(path)
        .unwrap_or_else(|e| die(format!("read key {}: {e}", path.display())));
    parse_signing_key(hex.trim())
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

pub(crate) fn cmd_sidon(action: SidonAction) {
    match action {
        SidonAction::Submit {
            witness,
            base_observation,
            key,
            actor,
            json: json_out,
        } => {
            let w = read_json(&witness);
            let (n, points) =
                validate_shape(&w).unwrap_or_else(|e| die(format!("invalid witness: {e}")));
            let obs = read_json(&base_observation);
            // The base observation must be a well-formed, signed observation packet.
            verify_signed_packet(&obs)
                .unwrap_or_else(|e| die(format!("base observation is not a valid packet: {e}")));
            if obs.get("packet_type").and_then(Value::as_str) != Some("observation") {
                die("--base-observation must be an ObservationPacket".to_string());
            }

            let sk = read_key(&key);
            let now = now_rfc3339();
            // The producer pins their submission to the current observation: a
            // self-issued strict-improvement task, then the signed result.
            let task = make_task(&obs, n, "strict_improvement", &sk, &actor, &now)
                .unwrap_or_else(|e| die(format!("build task: {e}")));
            let result = make_result(&task, &w, &sk, &actor, &now)
                .unwrap_or_else(|e| die(format!("build result: {e}")));

            if json_out {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({ "task": task, "result": result }))
                        .unwrap()
                );
            } else {
                let k = points.len();
                println!("signed Sidon result for A309370 n={n}, size {k}");
                println!("  result packet : {}", result["packet_id"].as_str().unwrap());
                println!("  claim         : A309370(n={n}) >= {k}");
                println!(
                    "  pinned to     : {}",
                    obs["packet_id"].as_str().unwrap_or("?")
                );
                println!(
                    "\nPropose it:\n  vela registry propose <vfr> --kind finding.add --payload <(vela sidon submit … --json)"
                );
            }
        }

        SidonAction::Observe {
            presentation,
            key,
            actor,
            json: json_out,
        } => {
            let pj = read_json(&presentation);
            let pres = Presentation::from_json(&pj)
                .unwrap_or_else(|e| die(format!("invalid presentation: {e}")));
            let disabled = BTreeSet::new();
            let sk = read_key(&key);
            let now = now_rfc3339();
            let obs = make_observation(&pres, &disabled, &[], None, &sk, &actor, &now)
                .unwrap_or_else(|e| die(format!("build observation: {e}")));
            // An authoritative read must replay from the presentation it names.
            verify_observation_replay(&obs, &pres, &disabled)
                .unwrap_or_else(|e| die(format!("observation does not replay: {e}")));

            if json_out {
                println!("{}", serde_json::to_string_pretty(&obs).unwrap());
            } else {
                println!(
                    "authoritative observation {}",
                    obs["packet_id"].as_str().unwrap()
                );
                let empty = Vec::new();
                let bounds = obs["canonical_output"]["bounds"].as_array().unwrap_or(&empty);
                if bounds.is_empty() {
                    println!("  (no supported lower-bound cells)");
                }
                for b in bounds {
                    println!(
                        "  A309370(n={}) >= {}",
                        b["n"], b["best_lower_bound"]
                    );
                }
            }
        }
    }
}
