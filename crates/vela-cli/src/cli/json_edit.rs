//! Surgical top-level JSON-field replacement, byte-preserving the rest of
//! the document. Lets `save_recorded_proof_state` patch a proof packet in
//! place without reserializing (which would reorder keys and break hashes).

use super::*;

pub(crate) fn replace_top_level_json_field(
    raw: &str,
    field: &str,
    value: &Value,
) -> Result<String, String> {
    let Some((key_start, value_start, value_end)) = find_top_level_json_field(raw, field) else {
        return Err(format!("top-level JSON field '{field}' not found"));
    };
    let field_indent = raw[..key_start]
        .rsplit_once('\n')
        .map(|(_, tail)| tail.chars().count())
        .unwrap_or(key_start);
    let continuation_indent = " ".repeat(field_indent + 2);
    let rendered = serde_json::to_string_pretty(value)
        .map_err(|e| format!("serialize field '{field}': {e}"))?
        .replace('\n', &format!("\n{continuation_indent}"));

    let mut out = String::with_capacity(raw.len() + rendered.len());
    out.push_str(&raw[..value_start]);
    out.push_str(&rendered);
    out.push_str(&raw[value_end..]);
    Ok(out)
}

fn find_top_level_json_field(raw: &str, field: &str) -> Option<(usize, usize, usize)> {
    let bytes = raw.as_bytes();
    let mut depth = 0usize;
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => {
                let key_start = index;
                let key_end = json_string_end(raw, index)?;
                if depth == 1 && &raw[index + 1..key_end - 1] == field {
                    let colon = next_non_ws(raw, key_end)?;
                    if bytes.get(colon) == Some(&b':') {
                        let value_start = next_non_ws(raw, colon + 1)?;
                        let value_end = json_value_end(raw, value_start)?;
                        return Some((key_start, value_start, value_end));
                    }
                }
                index = key_end;
            }
            b'{' | b'[' => {
                depth += 1;
                index += 1;
            }
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
                index += 1;
            }
            _ => index += 1,
        }
    }
    None
}

fn json_string_end(raw: &str, start: usize) -> Option<usize> {
    let bytes = raw.as_bytes();
    let mut escaped = false;
    let mut index = start + 1;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' if !escaped => escaped = true,
            b'"' if !escaped => return Some(index + 1),
            _ => escaped = false,
        }
        index += 1;
    }
    None
}

fn json_value_end(raw: &str, start: usize) -> Option<usize> {
    let bytes = raw.as_bytes();
    match bytes.get(start)? {
        b'"' => json_string_end(raw, start),
        b'{' | b'[' => {
            let mut depth = 0usize;
            let mut index = start;
            while index < bytes.len() {
                match bytes[index] {
                    b'"' => index = json_string_end(raw, index)?,
                    b'{' | b'[' => {
                        depth += 1;
                        index += 1;
                    }
                    b'}' | b']' => {
                        depth = depth.saturating_sub(1);
                        index += 1;
                        if depth == 0 {
                            return Some(index);
                        }
                    }
                    _ => index += 1,
                }
            }
            None
        }
        _ => {
            let mut index = start;
            while index < bytes.len() && !matches!(bytes[index], b',' | b'}' | b']' | b'\n') {
                index += 1;
            }
            Some(raw[..index].trim_end().len())
        }
    }
}

fn next_non_ws(raw: &str, start: usize) -> Option<usize> {
    raw.as_bytes()[start..]
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .map(|offset| start + offset)
}
