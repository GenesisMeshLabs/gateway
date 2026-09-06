//! Canonical JSON, byte-compatible with the Python reference implementation.
//!
//! Every signature in Genesis Mesh is taken over the canonical form of a
//! document, so this module must agree with Python exactly or nothing verifies
//! across implementations. Python produces its canonical bytes with:
//!
//! ```python
//! json.dumps(data, sort_keys=True, separators=(",", ":"))
//! ```
//!
//! Three properties follow, and only the first comes free from `serde_json`:
//!
//! 1. **No whitespace** — `,` and `:` with no padding.
//! 2. **Keys sorted** by Unicode code point. `serde_json` serialises *structs*
//!    in declaration order, so we go through [`serde_json::Value`] and sort
//!    explicitly rather than relying on a map implementation detail.
//! 3. **Non-ASCII escaped** as `\uXXXX` — Python's `ensure_ascii=True` default.
//!    `serde_json` does *not* do this; it emits raw UTF-8. A network name like
//!    `mesh-t<e-diaeresis>st` would therefore sign differently in the two
//!    implementations. Code points outside the Basic Multilingual Plane become
//!    a UTF-16 surrogate pair, exactly as Python emits them.

use serde::Serialize;
use serde_json::Value;

use crate::error::{Error, Result};

/// Serialise any value to its canonical JSON string.
pub fn to_canonical_json<T: Serialize + ?Sized>(value: &T) -> Result<String> {
    let v = serde_json::to_value(value)?;
    Ok(canonicalize(&v))
}

/// Serialise to canonical JSON with some top-level keys removed.
///
/// Signed documents sign everything *except* their own signature list, so this
/// is how [`crate::models`] produces signing input.
pub fn to_canonical_json_excluding<T: Serialize + ?Sized>(
    value: &T,
    exclude: &[&str],
) -> Result<String> {
    let mut v = serde_json::to_value(value)?;
    let found = kind_of(&v);
    let obj = v
        .as_object_mut()
        .ok_or(Error::NotAnObject { found })?;
    for key in exclude {
        obj.remove(*key);
    }
    Ok(canonicalize(&v))
}

/// Render an already-parsed [`Value`] in canonical form.
pub fn canonicalize(value: &Value) -> String {
    let mut out = String::new();
    write_value(value, &mut out);
    out
}

fn kind_of(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn write_value(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            // Array order is meaningful and is never sorted.
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            // Sort by Unicode code point, matching Python's sort_keys=True.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable();
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(key, out);
                out.push(':');
                if let Some(v) = map.get(*key) {
                    write_value(v, out);
                }
            }
            out.push('}');
        }
    }
}

/// Write a JSON string literal using Python's `json.dumps` escaping rules.
///
/// Note Python does not escape `/` or DEL (0x7f), so neither do we.
fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => push_u16(c as u16, out),
            c if c.is_ascii() => out.push(c),
            c => {
                let mut buf = [0u16; 2];
                for unit in c.encode_utf16(&mut buf).iter() {
                    push_u16(*unit, out);
                }
            }
        }
    }
    out.push('"');
}

fn push_u16(unit: u16, out: &mut String) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push_str("\\u");
    out.push(HEX[((unit >> 12) & 0xf) as usize] as char);
    out.push(HEX[((unit >> 8) & 0xf) as usize] as char);
    out.push(HEX[((unit >> 4) & 0xf) as usize] as char);
    out.push(HEX[(unit & 0xf) as usize] as char);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sorts_keys_and_strips_whitespace() {
        let v = json!({ "b": 1, "a": 2, "c": { "z": 1, "y": 2 } });
        assert_eq!(canonicalize(&v), r#"{"a":2,"b":1,"c":{"y":2,"z":1}}"#);
    }

    #[test]
    fn preserves_array_order() {
        let v = json!({ "xs": ["c", "a", "b"] });
        assert_eq!(canonicalize(&v), r#"{"xs":["c","a","b"]}"#);
    }

    #[test]
    fn escapes_non_ascii_like_python() {
        let v = json!({ "n": "mesh-t\u{eb}st" });
        // The expected form is ASCII: the two bytes become a \u escape.
        assert_eq!(canonicalize(&v), "{\"n\":\"mesh-t\\u00ebst\"}");
    }

    #[test]
    fn escapes_astral_as_surrogate_pair() {
        let v = json!({ "n": "\u{1F510}" });
        // U+1F510 is above the BMP, so Python emits a surrogate pair.
        assert_eq!(canonicalize(&v), "{\"n\":\"\\ud83d\\udd10\"}");
    }

    #[test]
    fn escapes_control_characters() {
        let v = json!({ "n": "a\nb\u{01}c" });
        assert_eq!(canonicalize(&v), "{\"n\":\"a\\nb\\u0001c\"}");
    }

    #[test]
    fn does_not_escape_solidus() {
        let v = json!({ "u": "https://a/b" });
        assert_eq!(canonicalize(&v), r#"{"u":"https://a/b"}"#);
    }
}
