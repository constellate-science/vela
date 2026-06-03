//! v0.123: `vela-relay` binary — minimal CLI surface for the four
//! adapter shapes. The substrate's actual adapter logic lives in
//! `vela-protocol`; this binary's job is to be the discoverable
//! published surface that points at the right canonical Vela CLI
//! subcommand for each adapter shape.
//!
//! Future cycles may add in-binary execution paths for each shape;
//! the v0.123 cut ships the discoverability layer plus the
//! library-level [`vela_relay::AdapterShape`] enum, which is what
//! downstream Rust users need to build custom adapters against the
//! same contract.

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use serde_json::json;
use vela_relay::paper::paper_to_vela;
use vela_relay::{AdapterShape, describe};

#[derive(Parser)]
#[command(
    name = "vela-relay",
    version,
    about = "Vela Relay: the four-adapter contract between external scientific activity and Vela proposals.",
    long_about = "vela-relay enumerates the four canonical adapter shapes (paper-to-vela, artifact-to-vela, hypothesis-to-vela, review-to-vela) and points at the Vela CLI subcommand that implements each. The substrate's actual adapter logic lives in crates/vela-protocol; this binary is the discoverable published surface."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Emit JSON envelopes instead of human-readable summaries.
    #[arg(long, global = true)]
    json: bool,
}

#[derive(Subcommand)]
enum Command {
    /// List all four adapter shapes with their contracts.
    List,
    /// Describe one adapter shape.
    Describe { shape: String },
    /// v0.142: resolve a `doi:*`, `arxiv:*`, `pmid:*`, or `s2:*`
    /// identifier through the corresponding upstream registry and
    /// emit a `vpr_*` proposal envelope. The envelope can be
    /// piped into `vela artifact-to-state` (or stored as a
    /// reviewer artifact) for substrate-side acceptance.
    PaperToVela {
        /// Paper identifier with prefix, e.g. `doi:10.1038/...`,
        /// `arxiv:1706.03762`, `pmid:12345678`, or `s2:abc1234...`.
        ident: String,
        /// Optional output path. When omitted, the envelope is
        /// printed to stdout.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Print the version of the substrate adapter contract this
    /// binary was built against.
    Version,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match cli.command {
        None | Some(Command::List) => list(cli.json),
        Some(Command::PaperToVela { ident, out }) => {
            run_paper_to_vela(&ident, out.as_deref(), cli.json).await
        }
        Some(Command::Describe { shape }) => match AdapterShape::from_slug(&shape) {
            Some(s) => describe_shape(s, cli.json),
            None => {
                eprintln!(
                    "err · unknown adapter shape: `{shape}`. Valid: {}",
                    AdapterShape::ALL
                        .iter()
                        .map(|s| s.slug())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                std::process::exit(1);
            }
        },
        Some(Command::Version) => {
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": true,
                        "command": "version",
                        "vela_relay_version": env!("CARGO_PKG_VERSION"),
                        "adapter_shapes": AdapterShape::ALL.iter().map(|s| s.slug()).collect::<Vec<_>>(),
                    })).expect("failed to serialize")
                );
            } else {
                println!("vela-relay {}", env!("CARGO_PKG_VERSION"));
            }
        }
    }
}

fn list(json_out: bool) {
    if json_out {
        let shapes: Vec<serde_json::Value> = AdapterShape::ALL
            .iter()
            .map(|s| {
                let c = describe(*s);
                json!({
                    "shape": c.shape.slug(),
                    "input": c.input,
                    "output": c.output,
                    "canonical_cli": c.canonical_cli,
                    "backing_module": c.backing_module,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": true,
                "command": "list",
                "vela_relay_version": env!("CARGO_PKG_VERSION"),
                "shapes": shapes,
            }))
            .expect("failed to serialize")
        );
    } else {
        println!(
            "vela-relay {} - four adapter shapes",
            env!("CARGO_PKG_VERSION")
        );
        println!();
        for s in AdapterShape::ALL {
            let c = describe(*s);
            println!("  {} ", c.shape.slug());
            println!("    in:    {}", c.input);
            println!("    out:   {}", c.output);
            println!("    cli:   {}", c.canonical_cli);
            println!();
        }
        println!(
            "see docs/RELAY.md (https://github.com/vela-science/vela/blob/main/docs/RELAY.md)"
        );
    }
}

async fn run_paper_to_vela(ident: &str, out: Option<&std::path::Path>, json_out: bool) {
    match paper_to_vela(ident).await {
        Ok(env) => {
            let body =
                serde_json::to_string_pretty(&env.envelope).expect("serialize paper envelope");
            if let Some(path) = out {
                if let Err(e) = std::fs::write(path, format!("{body}\n")) {
                    eprintln!("err · write {}: {e}", path.display());
                    std::process::exit(1);
                }
                if json_out {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&json!({
                            "ok": true,
                            "command": "paper-to-vela",
                            "identifier": ident,
                            "source": env.source,
                            "out": path.display().to_string(),
                            "vpr_id": env.envelope.get("vpr_id").cloned(),
                        }))
                        .expect("serialize summary")
                    );
                } else {
                    let title = env.title.as_deref().unwrap_or("(no title)");
                    println!(
                        "paper-to-vela: {ident} resolved via {} -> {}",
                        env.source,
                        path.display()
                    );
                    println!("  title: {title}");
                    if let Some(y) = env.year {
                        println!("  year:  {y}");
                    }
                    if let Some(a) = env.first_author.as_deref() {
                        println!("  first: {a}");
                    }
                }
            } else {
                // No --out: print envelope to stdout (same shape
                // whether --json was passed or not; the envelope
                // is always JSON).
                println!("{body}");
            }
        }
        Err(e) => {
            eprintln!("err · {e}");
            std::process::exit(1);
        }
    }
}

fn describe_shape(s: AdapterShape, json_out: bool) {
    let c = describe(s);
    if json_out {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": true,
                "command": "describe",
                "shape": c.shape.slug(),
                "input": c.input,
                "output": c.output,
                "canonical_cli": c.canonical_cli,
                "backing_module": c.backing_module,
            }))
            .expect("failed to serialize")
        );
    } else {
        println!("{}", c.shape.slug());
        println!("  in:    {}", c.input);
        println!("  out:   {}", c.output);
        println!("  cli:   {}", c.canonical_cli);
        println!("  src:   {}", c.backing_module);
    }
}
