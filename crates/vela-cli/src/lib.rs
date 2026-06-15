//! `vela` — the command-line binary.
//!
//! Hands off to `crate::cli::run_from_args`, after a small read-only
//! verify intercept (conjecture / proof-packet verification).

use colored::Colorize;

// The CLI / serve / workbench surface, relocated out of the
// `vela-protocol` library so the substrate crate stays a pure protocol
// library. These were `vela_protocol::{cli, serve, workbench, cli_*}`
// before; they now live here and reach into the substrate via
// `vela_protocol::*`.
pub mod cli;
mod cli_check;
mod cli_claim;
mod cli_commands;
mod cli_engine;
mod cli_export;
mod cli_finding;
mod cli_frontier;
mod cli_identity;
mod cli_lean;
mod cli_log_verify;
mod cli_proof;
mod cli_read;
mod cli_registry;
mod cli_source_fetch;
mod review_work;
mod serve;

pub fn run() {
    // Atlas R.2 intercept: read-only verifier subcommands for the
    // primitives added in R.1 (v0.338). Live ahead of run_from_args()
    // because the dispatcher in vela-protocol/cli.rs predates these
    // primitives. When the next vela-protocol release lands them in the
    // dispatcher proper, this intercept can be removed.
    if try_handle_atlas_r2_verify_intercept() {
        return;
    }

    crate::cli::run_from_args();
}

fn try_handle_atlas_r2_verify_intercept() -> bool {
    let argv: Vec<String> = std::env::args().collect();
    if argv.len() < 3 {
        return false;
    }
    match (argv[1].as_str(), argv[2].as_str()) {
        ("conjecture", "verify") => {
            handle_conjecture_verify(&argv[3..]);
            true
        }
        ("proof-packet", "verify") => {
            handle_proof_packet_verify(&argv[3..]);
            true
        }
        ("proof-packet", "verify-external") => {
            handle_proof_packet_verify_external(&argv[3..]);
            true
        }
        _ => false,
    }
}

fn handle_conjecture_verify(args: &[String]) {
    let path = match args.first() {
        Some(p) => p,
        None => {
            eprintln!("{} usage: vela conjecture verify <path>", "err ·".red());
            std::process::exit(2);
        }
    };
    let body = match std::fs::read_to_string(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{} read {path}: {e}", "err ·".red());
            std::process::exit(1);
        }
    };
    let conj: vela_edge::conjecture::Conjecture = match serde_json::from_str(&body) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{} parse {path}: {e}", "err ·".red());
            std::process::exit(1);
        }
    };
    if let Err(e) = conj.verify() {
        eprintln!("{} witness signature/id invalid: {e}", "err ·".red());
        std::process::exit(1);
    }
    let cosigs = match conj.verify_cosignatures() {
        Ok(n) => n,
        Err(e) => {
            eprintln!("{} co-signature invalid: {e}", "err ·".red());
            std::process::exit(1);
        }
    };
    println!(
        "  {} {} witness:{} cosigners:{} status:{:?}",
        "conjecture verified".green().bold(),
        conj.id,
        conj.witness.actor_id,
        cosigs,
        conj.status,
    );
}

fn handle_proof_packet_verify(args: &[String]) {
    let path = match args.first() {
        Some(p) => p,
        None => {
            eprintln!("{} usage: vela proof-packet verify <path>", "err ·".red());
            std::process::exit(2);
        }
    };
    let body = match std::fs::read_to_string(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{} read {path}: {e}", "err ·".red());
            std::process::exit(1);
        }
    };
    let packet: vela_edge::proof_packet::ProofPacket = match serde_json::from_str(&body) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{} parse {path}: {e}", "err ·".red());
            std::process::exit(1);
        }
    };
    if let Err(e) = packet.verify() {
        eprintln!("{} packet invalid: {e}", "err ·".red());
        std::process::exit(1);
    }
    println!(
        "  {} {} hash:{} signer:{}",
        "proof packet verified".green().bold(),
        packet.packet_id,
        &packet.packet_hash[..24],
        packet.signer_actor_id,
    );
}

fn handle_proof_packet_verify_external(args: &[String]) {
    let path = match args.first() {
        Some(p) => p,
        None => {
            eprintln!(
                "{} usage: vela proof-packet verify-external <path>",
                "err ·".red()
            );
            std::process::exit(2);
        }
    };
    let body = match std::fs::read_to_string(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{} read {path}: {e}", "err ·".red());
            std::process::exit(1);
        }
    };
    let packet: vela_edge::proof_packet::ProofPacket = match serde_json::from_str(&body) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{} parse {path}: {e}", "err ·".red());
            std::process::exit(1);
        }
    };
    if let Err(e) = packet.verify() {
        eprintln!("{} packet invalid: {e}", "err ·".red());
        std::process::exit(1);
    }
    let n = match packet.verify_external_verifications() {
        Ok(n) => n,
        Err(e) => {
            eprintln!("{} external verification invalid: {e}", "err ·".red());
            std::process::exit(1);
        }
    };
    println!(
        "  {} {} external:{} (signer:{})",
        "proof packet + externals verified".green().bold(),
        packet.packet_id,
        n,
        packet.signer_actor_id,
    );
}
