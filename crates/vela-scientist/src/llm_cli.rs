//! # `claude -p` shared wrapper
//!
//! One place that knows how to spawn `claude`, hand it a system
//! prompt + user prompt + JSON Schema, parse the envelope, and
//! return validated structured output as a `serde_json::Value`.
//!
//! Each agent (Literature Scout, Notes Compiler, Code Analyst,
//! Datasets, …) defines its own prompts and schema, then calls
//! `run_structured` here. The flag set, the auth path (OAuth via
//! the user's existing Claude Code session), the timeout discipline,
//! and the budget cap all live in one file so doctrine drift is
//! visible in one place.
//!
//! Doctrine reminder: this module does not know what an agent
//! *means*. It just talks to `claude`. Anything domain-shaped lives
//! in the per-agent module.

use std::process::Stdio;

use serde_json::Value;

/// Inputs to one structured `claude -p` call.
///
/// Every field except `system_prompt` / `user_prompt` / `json_schema`
/// has a sensible default; pass references so the caller's owned
/// buffers stay borrow-only.
#[derive(Debug, Clone)]
pub struct ClaudeCall<'a> {
    /// Replaces Claude Code's default system prompt entirely. Use
    /// `--system-prompt` (not `--append-system-prompt`) so the model
    /// behaves as a focused extractor, not a general assistant.
    pub system_prompt: &'a str,
    /// The full user prompt (source label + content).
    pub user_prompt: &'a str,
    /// Stringified JSON Schema for the structured-output validator.
    /// Empty string → no schema constraint (rare; agents almost
    /// always pass one).
    pub json_schema: &'a str,
    /// Optional model alias (e.g. `"sonnet"`, `"opus"`,
    /// `"claude-opus-4-1"`). `None` lets the user's session pick.
    pub model: Option<&'a str>,
    /// Path to the `claude` binary. `"claude"` is the default and
    /// works on any installation that put it on PATH.
    pub cli_command: &'a str,
    /// Hard cap on cost per call. The default is intentionally low
    /// (`0.20`) — agents that need more should pass it explicitly so
    /// the override is visible in code.
    pub max_budget_usd: f64,
}

impl<'a> ClaudeCall<'a> {
    /// Default-shape constructor. Caller fills in only the prompts +
    /// schema; everything else takes the doctrinal default.
    #[must_use]
    pub fn new(system_prompt: &'a str, user_prompt: &'a str, json_schema: &'a str) -> Self {
        Self {
            system_prompt,
            user_prompt,
            json_schema,
            model: None,
            cli_command: "claude",
            max_budget_usd: 0.20,
        }
    }
}

/// Run one `claude -p` call and return the validated structured
/// output as a `serde_json::Value`.
///
/// The call disables tool use (`--allowedTools ""`), skips permission
/// prompts (`--permission-mode dontAsk`), and does not persist the
/// session (`--no-session-persistence`). Auth comes from the user's
/// existing Claude Code OAuth session (no API key required on a
/// Pro/Max subscription).
///
/// Returns:
/// - `Ok(value)` — `value` is `envelope.structured_output` (or
///   `envelope.result`, for older `claude` versions). When that
///   field is itself a JSON-encoded string (also seen on older
///   versions), it gets parsed once more before return.
/// - `Err(string)` — spawn failure, non-zero exit, non-UTF-8
///   stdout, missing/unparseable envelope, or missing structured
///   field. The caller decides whether to skip the file or abort.
///
/// Errors are stringly-typed because the failure surface is small
/// and the caller almost always wraps them into a per-file `skipped`
/// reason for the agent's report.
pub fn run_structured(call: ClaudeCall<'_>) -> Result<Value, String> {
    let mut cmd = std::process::Command::new(call.cli_command);
    cmd.arg("-p")
        .arg(call.user_prompt)
        .arg("--system-prompt")
        .arg(call.system_prompt)
        .arg("--output-format")
        .arg("json")
        .arg("--no-session-persistence")
        .arg("--permission-mode")
        .arg("dontAsk")
        .arg("--allowedTools")
        .arg("");
    if !call.json_schema.is_empty() {
        cmd.arg("--json-schema").arg(call.json_schema);
    }
    if let Some(m) = call.model {
        cmd.arg("--model").arg(m);
    }
    if call.max_budget_usd > 0.0 {
        cmd.arg("--max-budget-usd")
            .arg(format!("{:.2}", call.max_budget_usd));
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let output = cmd
        .output()
        .map_err(|e| format!("spawn {}: {e}", call.cli_command))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let truncated = if stderr.len() > 600 {
            format!("{}…", &stderr[..600])
        } else {
            stderr.into_owned()
        };
        return Err(format!(
            "{} -p exited with {}: {truncated}",
            call.cli_command,
            output.status.code().unwrap_or(-1)
        ));
    }

    let stdout = String::from_utf8(output.stdout)
        .map_err(|e| format!("non-utf8 from {}: {e}", call.cli_command))?;
    let envelope: Value = serde_json::from_str(stdout.trim()).map_err(|e| {
        format!(
            "parse {} json envelope: {e}\noutput: {stdout}",
            call.cli_command
        )
    })?;

    let structured = envelope
        .get("structured_output")
        .or_else(|| envelope.get("result"))
        .cloned()
        .ok_or_else(|| {
            format!(
                "{} response missing structured_output / result field: {envelope}",
                call.cli_command
            )
        })?;

    // Older `claude` versions wrap structured_output as a JSON string
    // even when --json-schema is set. Parse once more if that's what
    // we got back.
    match structured {
        Value::String(s) => serde_json::from_str(&s)
            .map_err(|e| format!("parse structured_output string: {e}\nvalue: {s}")),
        v => Ok(v),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_call_carries_safe_defaults() {
        let call = ClaudeCall::new("sys", "user", r#"{"type":"object"}"#);
        assert_eq!(call.cli_command, "claude");
        assert!(call.model.is_none());
        assert!((call.max_budget_usd - 0.20).abs() < f64::EPSILON);
    }
}
