//! `vela` — the command-line binary.
//!
//! Thin entry point. The real work (agent-handler registration + CLI
//! dispatch) lives in the library entry [`vela_cli::run`], so a
//! downstream consumer (e.g. an Atlas/campaign repo that vendors this
//! crate via a submodule) can build its own `vela` binary with a
//! three-line launcher that just calls `vela_cli::run()`.

fn main() {
    vela_cli::run();
}
