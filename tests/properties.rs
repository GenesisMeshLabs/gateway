//! Property tests of canonical JSON and of the strict parsing of signed
//! documents.
//!
//! Canonical form is checked against an independent rendering of Python's
//! `json.dumps(value, sort_keys=True, separators=(",", ":"))` (which escapes
//! non-ASCII as `\uXXXX`, astral characters as surrogate pairs), and for
//! round trips. Numbers are integers: the gateway signs no floating-point
//! values, and serde_json renders floats below 1e-4 differently from Python
//! (`0.00001` and `1e-7` against `1e-05` and `1e-07`; the core's
//! `json-exponents` canonical vector).

use genesis_mesh::canonical::{canonicalize, to_canonical_json};
use genesis_mesh::models::JoinCertificate;
use proptest::prelude::*;
use serde_json::{json, Map, Value};

#[path = "support/proptest_config.rs"]
mod proptest_config;

/// Any text, including control characters and characters outside the Basic
/// Multilingual Plane.
fn text() -> impl Strategy<Value = String> {
    prop_oneof![
        prop::collection::vec(any::<char>(), 0..10).prop_map(String::from_iter),
        "[a-c\"\\\\/\u{0}-\u{1f}\u{7f}\u{e9}\u{2028}\u{1f510}]{0,8}",
    ]
}

fn value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(Value::from),
        any::<u64>().prop_map(Value::from),
        text().prop_map(Value::String),
    ];
    leaf.prop_recursive(4, 48, 6, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
            prop::collection::btree_map(text(), inner, 0..6)
                .prop_map(|map| Value::Object(map.into_iter().collect())),
        ]
    })
}

/// Python's `json.dumps` string escaping, written independently: serde_json
/// escapes quotes, backslashes and control characters as Python does
/// (`\b \f \n \r \t`, otherwise `\u00XX`); every non-ASCII character then
/// becomes `\uXXXX` per UTF-16 unit.
fn python_string(s: &str) -> String {
    let mut out = String::new();
    for c in serde_json::to_string(s).unwrap().chars() {
        if c.is_ascii() {
            out.push(c);
        } else {
            for unit in c.encode_utf16(&mut [0; 2]) {
                out.push_str(&format!("\\u{unit:04x}"));
            }
        }
    }
    out
}

fn python_dumps(value: &Value) -> String {
    match value {
        Value::String(s) => python_string(s),
        Value::Array(items) => format!(
            "[{}]",
            items.iter().map(python_dumps).collect::<Vec<_>>().join(",")
        ),
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| a.chars().cmp(b.chars()));
            let members: Vec<String> = keys
                .into_iter()
                .map(|k| format!("{}:{}", python_string(k), python_dumps(&map[k])))
                .collect();
            format!("{{{}}}", members.join(","))
        }
        other => other.to_string(),
    }
}

/// A valid join certificate's members, as JSON text.
fn certificate_members() -> Vec<(&'static str, String)> {
    vec![
        ("cert_id", "\"cert-001\"".into()),
        (
            "node_public_key",
            "\"A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=\"".into(),
        ),
        ("network_name", "\"mesh-alpha\"".into()),
        ("roles", "[\"role:anchor\"]".into()),
        ("issued_at", "\"2026-01-01T12:00:00Z\"".into()),
        ("expires_at", "\"2026-01-08T12:00:00Z\"".into()),
        ("issued_by", "\"na-001\"".into()),
        ("signatures", "[]".into()),
    ]
}

fn object_text(members: &[(&str, String)]) -> String {
    let members: Vec<String> = members
        .iter()
        .map(|(k, v)| format!("{}:{v}", serde_json::to_string(k).unwrap()))
        .collect();
    format!("{{{}}}", members.join(","))
}

proptest! {
    #![proptest_config(proptest_config::config(512))]

    #[test]
    fn canonical_form_is_pythons_json_dumps(value in value()) {
        prop_assert_eq!(canonicalize(&value), python_dumps(&value));
    }

    /// Canonical text is ASCII, parses back to the same value, and is a fixed
    /// point: canonicalizing it again changes nothing.
    #[test]
    fn canonical_form_round_trips(value in value()) {
        let text = canonicalize(&value);
        prop_assert!(text.is_ascii());
        let parsed: Value = serde_json::from_str(&text).unwrap();
        prop_assert_eq!(&parsed, &value);
        prop_assert_eq!(canonicalize(&parsed), text.clone());
        prop_assert_eq!(to_canonical_json(&value).unwrap(), text);
    }

    /// Whitespace and member order in the input never change the canonical
    /// form.
    #[test]
    fn layout_and_member_order_do_not_matter(value in value()) {
        let pretty = serde_json::to_string_pretty(&value).unwrap();
        let reparsed: Value = serde_json::from_str(&pretty).unwrap();
        prop_assert_eq!(canonicalize(&reparsed), canonicalize(&value));
        if let Value::Object(map) = &value {
            let reversed: Map<String, Value> =
                map.iter().rev().map(|(k, v)| (k.clone(), v.clone())).collect();
            prop_assert_eq!(canonicalize(&Value::Object(reversed)), canonicalize(&value));
        }
    }

    /// An integer keeps its decimal lexeme, as Python writes it.
    #[test]
    fn integers_keep_their_decimal_lexeme(signed in any::<i64>(), unsigned in any::<u64>()) {
        prop_assert_eq!(canonicalize(&json!(signed)), signed.to_string());
        prop_assert_eq!(canonicalize(&json!(unsigned)), unsigned.to_string());
        let parsed: Value = serde_json::from_str(&format!("[{signed},{unsigned}]")).unwrap();
        prop_assert_eq!(canonicalize(&parsed), format!("[{signed},{unsigned}]"));
    }

    /// A repeated member keeps its last value, as Python's `json.loads` does,
    /// so both sides canonicalize the same text to the same bytes.
    #[test]
    fn a_repeated_member_keeps_its_last_value_like_python(
        key in text(),
        first in value(),
        last in value(),
        others in prop::collection::btree_map(text(), value(), 0..4),
    ) {
        let others: Vec<(String, Value)> =
            others.into_iter().filter(|(k, _)| *k != key).collect();
        let mut members = vec![format!("{}:{}", serde_json::to_string(&key).unwrap(), first)];
        members.extend(others.iter().map(|(k, v)| format!("{}:{v}", serde_json::to_string(k).unwrap())));
        members.push(format!("{}:{}", serde_json::to_string(&key).unwrap(), last));
        let parsed: Value = serde_json::from_str(&format!("{{{}}}", members.join(","))).unwrap();
        let mut expected: Map<String, Value> = others.into_iter().collect();
        expected.insert(key, last);
        prop_assert_eq!(canonicalize(&parsed), canonicalize(&Value::Object(expected)));
    }

    /// A signed document is parsed strictly: a repeated or unknown member is
    /// refused, whatever its value, so no two readers can see different
    /// documents in the same bytes.
    #[test]
    fn a_certificate_with_a_repeated_or_unknown_member_is_refused(
        at in any::<prop::sample::Index>(),
        unknown in "[a-z_]{1,12}",
        extra in value(),
    ) {
        let members = certificate_members();
        prop_assert!(serde_json::from_str::<JoinCertificate>(&object_text(&members)).is_ok());
        let mut repeated = members.clone();
        let copy = repeated[at.index(repeated.len())].clone();
        repeated.push(copy);
        prop_assert!(serde_json::from_str::<JoinCertificate>(&object_text(&repeated)).is_err());
        if !members.iter().any(|(k, _)| *k == unknown) {
            let mut widened: Vec<(&str, String)> = members.clone();
            let extra = extra.to_string();
            widened.push((unknown.as_str(), extra));
            prop_assert!(serde_json::from_str::<JoinCertificate>(&object_text(&widened)).is_err());
        }
    }
}

/// Unless a random run is asked for, every run draws the same cases (so the
/// merge queue cannot fail on an unlucky draw) and writes no failure files.
#[test]
fn runs_are_deterministic_by_default() {
    use proptest::strategy::ValueTree;
    use proptest::test_runner::{RngSeed, TestRunner};
    if ["PROPTEST_RANDOM", "PROPTEST_RNG_SEED"]
        .iter()
        .any(|name| std::env::var_os(name).is_some_and(|v| !v.is_empty()))
    {
        return;
    }
    let config = proptest_config::config(8);
    assert_eq!(config.rng_seed, RngSeed::Fixed(proptest_config::SEED));
    assert!(config.failure_persistence.is_none());
    let draw = || {
        let mut runner = TestRunner::new(proptest_config::config(8));
        (0..32)
            .map(|_| value().new_tree(&mut runner).unwrap().current())
            .collect::<Vec<_>>()
    };
    assert_eq!(draw(), draw());
}
