//! Shared helpers for the integration tests.
//!
//! Test data is loaded with `serde_json` — a dev-dependency independent of the
//! lexer under test — so a lexer bug cannot hide itself by misreading the
//! vectors that are supposed to catch it.

#![allow(dead_code, clippy::panic, clippy::unwrap_used, clippy::expect_used)]

// Acknowledge dev-dependencies so `unused_crate_dependencies` stays meaningful.
use dwk_proto as _;
use proptest as _;

use std::path::PathBuf;

pub(crate) fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

pub(crate) fn load_vectors(name: &str) -> serde_json::Value {
    let path = repo_root()
        .join("tests")
        .join("protocol")
        .join("vectors")
        .join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{name} is not JSON: {e}"))
}

pub(crate) fn hex_decode(hex: &str) -> Vec<u8> {
    assert!(hex.len().is_multiple_of(2), "odd-length hex");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex digit"))
        .collect()
}

pub(crate) fn input_bytes(vector: &serde_json::Value) -> Vec<u8> {
    if let Some(text) = vector.get("input").and_then(|v| v.as_str()) {
        return text.as_bytes().to_vec();
    }
    hex_decode(vector["input_hex"].as_str().expect("input or input_hex"))
}

pub(crate) fn str_field<'a>(vector: &'a serde_json::Value, key: &str) -> &'a str {
    vector[key]
        .as_str()
        .unwrap_or_else(|| panic!("vector field {key} missing"))
}
