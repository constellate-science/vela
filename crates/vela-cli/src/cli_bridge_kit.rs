//! `cmd_bridge_kit` and its handler logic, split out of cli.rs.

use crate::cli::{cross_check_packet_provenance, print_json, verify_packet_provenance};
use crate::cli_commands::BridgeKitAction;

pub(crate) async fn cmd_bridge_kit(action: BridgeKitAction) {
    match action {
        BridgeKitAction::Validate { source, json } => {
            let report = vela_edge::artifact_to_state::validate_bridge_kit_path(&source);
            if json {
                print_json(&report);
            } else {
                println!("vela bridge-kit validate");
                println!("  source: {}", report.source);
                println!("  packets: {}", report.packet_count);
                println!("  valid: {}", report.valid_packet_count);
                println!("  invalid: {}", report.invalid_packet_count);
                for packet in &report.packets {
                    if packet.ok {
                        println!(
                            "  ok: {} · {} artifacts · {} claims · {} needs",
                            packet
                                .packet_id
                                .as_deref()
                                .unwrap_or("packet id unavailable"),
                            packet.artifact_count,
                            packet.candidate_claim_count,
                            packet.open_need_count
                        );
                    } else {
                        println!("  invalid: {} · {}", packet.path, packet.errors.join("; "));
                    }
                }
                for error in &report.errors {
                    println!("  error: {error}");
                }
            }
            if !report.ok {
                std::process::exit(1);
            }
        }
        BridgeKitAction::VerifyProvenance {
            packet,
            json,
            cross_check,
        } => {
            let mut report = verify_packet_provenance(&packet).await;
            if cross_check {
                cross_check_packet_provenance(&packet, &mut report).await;
            }
            if json {
                print_json(&report);
            } else {
                println!("vela bridge-kit verify-provenance");
                println!("  packet: {}", report.packet);
                println!("  identifiers: {}", report.identifiers.len());
                println!("  resolved: {}", report.resolved_count);
                println!("  unresolved: {}", report.unresolved_count);
                println!("  skipped: {}", report.skipped_count);
                for entry in &report.identifiers {
                    let status = match entry.status.as_str() {
                        "resolved" => "ok ",
                        "unresolved" => "FAIL",
                        "skipped" => "skip",
                        _ => "?   ",
                    };
                    println!(
                        "  {} {} ({})",
                        status,
                        entry.identifier,
                        entry.note.as_deref().unwrap_or(entry.kind.as_str())
                    );
                }
            }
            if report.unresolved_count > 0 {
                std::process::exit(1);
            }
        }
    }
}
