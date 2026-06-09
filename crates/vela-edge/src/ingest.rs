//! PDF text extraction utility used by the modern Scout agent.
//!
//! The pre-v0.22 file-based ingestion command (`vela ingest --pdf/--csv/...`)
//! lived here together with this function in v0.0–v0.35. With the agent
//! inbox (Scout, Notes Compiler, Code Analyst, Datasets) fully replacing
//! that path in v0.32+, the legacy command was removed in v0.36 and the
//! file collapsed to this single utility.
//!
//! Kept under `vela_protocol::ingest::extract_pdf_text` for backward
//! compatibility with Scout's import; the function is otherwise unrelated
//! to ingestion and could move to `sources.rs` in a later refactor.

use std::path::Path;

/// Extract plain text from a PDF.
///
/// Tries `pdftotext` (poppler-utils) first; falls back to a crude
/// printable-ASCII-run extractor for environments without poppler.
/// Returns `Err` if neither path produces non-empty text.
pub fn extract_pdf_text(path: &Path) -> Result<String, String> {
    // Try pdftotext (poppler-utils).
    if let Ok(output) = std::process::Command::new("pdftotext")
        .arg(path)
        .arg("-")
        .output()
        && output.status.success()
    {
        let text = String::from_utf8_lossy(&output.stdout).to_string();
        if !text.trim().is_empty() {
            return Ok(text);
        }
    }

    // Fallback: read raw bytes and extract printable text runs.
    let bytes = std::fs::read(path).map_err(|e| format!("Failed to read PDF file: {e}"))?;

    // Extract ASCII text runs of length >= 20 (crude but works for most PDFs).
    let mut text = String::new();
    let mut current_run = String::new();
    for &b in &bytes {
        if b.is_ascii_graphic() || b == b' ' || b == b'\n' || b == b'\t' {
            current_run.push(b as char);
        } else {
            if current_run.len() >= 20 {
                text.push_str(&current_run);
                text.push('\n');
            }
            current_run.clear();
        }
    }
    if current_run.len() >= 20 {
        text.push_str(&current_run);
    }

    if text.trim().is_empty() {
        return Err(
            "Could not extract text from PDF. Install pdftotext for better results.".into(),
        );
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn extract_pdf_text_handles_missing_file() {
        let result = extract_pdf_text(Path::new("/nonexistent/file.pdf"));
        assert!(result.is_err());
    }
}
