//! # Jupyter notebook parser
//!
//! Walks an `.ipynb` file's standard nbformat 4 JSON shape and
//! returns its cells as `(kind, source, outputs)` triples that the
//! Code Analyst can include in its prompt.
//!
//! Scope discipline (v0.24):
//! * **nbformat 4 only.** That covers every Jupyter / JupyterLab /
//!   VS Code notebook in the wild today; older formats are rare
//!   and can be migrated.
//! * **`text/plain` outputs only.** `image/*` / `text/html` /
//!   widget JSON are skipped — extracting them well requires
//!   extra deps (image OCR, HTML→text). Empty if the cell never
//!   ran or only emitted images.
//! * **No execution.** Reading a notebook is read-only; the parser
//!   never invokes the kernel.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedNotebook {
    pub path: PathBuf,
    pub cells: Vec<NbCell>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NbCell {
    /// `"code"` or `"markdown"`. Other cell kinds (`raw`, …) are
    /// skipped at parse time so consumers don't need a wildcard.
    pub kind: String,
    /// The cell's source. nbformat stores `source` as either a
    /// string or `Vec<String>`; this field is the joined string.
    pub source: String,
    /// Concatenated `text/plain` outputs from the cell, joined by
    /// blank lines. Empty for markdown cells or cells that haven't
    /// run.
    pub outputs: Vec<String>,
}

pub fn parse_ipynb(path: &Path) -> Result<ParsedNotebook, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let nb: Value =
        serde_json::from_str(&raw).map_err(|e| format!("parse {} as JSON: {e}", path.display()))?;

    let cells_raw = nb
        .get("cells")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{} has no `cells` array", path.display()))?;

    let mut cells = Vec::with_capacity(cells_raw.len());
    for cell in cells_raw {
        let kind = cell.get("cell_type").and_then(Value::as_str).unwrap_or("");
        if kind != "code" && kind != "markdown" {
            continue;
        }
        let source = read_source(cell.get("source"));
        let outputs = if kind == "code" {
            read_outputs(cell.get("outputs"))
        } else {
            Vec::new()
        };
        cells.push(NbCell {
            kind: kind.to_string(),
            source,
            outputs,
        });
    }

    Ok(ParsedNotebook {
        path: path.to_path_buf(),
        cells,
    })
}

fn read_source(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(arr)) => arr
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(""),
        _ => String::new(),
    }
}

fn read_outputs(value: Option<&Value>) -> Vec<String> {
    let Some(Value::Array(arr)) = value else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for output in arr {
        // nbformat: `stream` (text/plain in `.text`),
        // `execute_result` / `display_data` (text/plain in
        // `.data["text/plain"]`), `error` (`traceback`).
        let kind = output
            .get("output_type")
            .and_then(Value::as_str)
            .unwrap_or("");
        match kind {
            "stream" => {
                let text = read_source(output.get("text"));
                if !text.trim().is_empty() {
                    out.push(text.trim().to_string());
                }
            }
            "execute_result" | "display_data" => {
                if let Some(data) = output.get("data") {
                    let plain = data.get("text/plain");
                    let text = read_source(plain);
                    if !text.trim().is_empty() {
                        out.push(text.trim().to_string());
                    }
                }
            }
            "error" => {
                if let Some(tb) = output.get("traceback").and_then(Value::as_array) {
                    let joined = tb
                        .iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join("\n");
                    if !joined.is_empty() {
                        out.push(format!("[error] {joined}"));
                    }
                }
            }
            _ => {}
        }
    }
    out
}

/// Render a parsed notebook as a flat text block suitable for an
/// LLM prompt. Cells are tagged with their kind + index so the
/// model can cite a specific cell back in its `derived_from`
/// field. Outputs follow each code cell, prefixed `>>>`.
pub fn render_for_prompt(nb: &ParsedNotebook, max_chars: usize) -> String {
    let mut out = String::new();
    for (i, cell) in nb.cells.iter().enumerate() {
        out.push_str(&format!("\n--- cell[{i}] {} ---\n", cell.kind));
        out.push_str(&cell.source);
        if !cell.outputs.is_empty() {
            out.push_str("\n--- outputs ---\n");
            for o in &cell.outputs {
                for line in o.lines() {
                    out.push_str(">>> ");
                    out.push_str(line);
                    out.push('\n');
                }
            }
        }
        if out.len() >= max_chars {
            out.truncate(max_chars);
            out.push_str("\n[…truncated]");
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_simple_notebook() {
        let nb = json!({
            "cells": [
                {
                    "cell_type": "markdown",
                    "source": ["# Title\n", "intro line"]
                },
                {
                    "cell_type": "code",
                    "source": "import pandas as pd\ndf = pd.read_csv('x.csv')\nprint(df.head())",
                    "outputs": [
                        {
                            "output_type": "stream",
                            "name": "stdout",
                            "text": "  a  b\n0 1  2\n"
                        }
                    ]
                },
                {
                    "cell_type": "raw",
                    "source": "skip me"
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5
        });
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.ipynb");
        std::fs::write(&path, serde_json::to_string(&nb).unwrap()).unwrap();
        let parsed = parse_ipynb(&path).unwrap();
        assert_eq!(parsed.cells.len(), 2); // raw cell skipped
        assert_eq!(parsed.cells[0].kind, "markdown");
        assert!(parsed.cells[0].source.contains("Title"));
        assert_eq!(parsed.cells[1].kind, "code");
        assert!(parsed.cells[1].source.contains("pandas"));
        assert_eq!(parsed.cells[1].outputs.len(), 1);
        assert!(parsed.cells[1].outputs[0].contains("a  b"));
    }

    #[test]
    fn render_includes_cell_indices() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.ipynb");
        std::fs::write(
            &path,
            serde_json::to_string(&json!({
                "cells": [
                    { "cell_type": "code", "source": "x = 1", "outputs": [] }
                ]
            }))
            .unwrap(),
        )
        .unwrap();
        let parsed = parse_ipynb(&path).unwrap();
        let rendered = render_for_prompt(&parsed, 10_000);
        assert!(rendered.contains("cell[0] code"));
        assert!(rendered.contains("x = 1"));
    }
}
