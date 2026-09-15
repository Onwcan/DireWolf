//! JSON Schema construction.
//!
//! Schemas are **emitted from the Rust types**, never hand-written: every
//! [`crate::wire::WireType`] describes itself, and `tools/protogen` writes the
//! result to `schemas/`. That is what makes Rust the single source of truth
//! (ADR-0033) — the schema cannot say something the decoder does not enforce,
//! because the same declaration produces both.
//!
//! The emitted dialect is JSON Schema 2020-12, restricted to a small closed
//! subset the Python generator understands. DireWolf-specific facts a schema
//! cannot express are carried in `x-direwolf-*` annotation keywords, which
//! standard validators ignore and the generator requires.
//!
//! JSON Schema does **not** express, and no emitted schema claims to enforce:
//! duplicate-key rejection, NFC-collision rejection, the depth limit, frame
//! limits, UUIDv7 version bits, or calendar validity of timestamps. Those are
//! lexer and decoder properties, tested directly.

pub mod emit;

use crate::json::{Number, Object, Value};

/// The JSON Schema dialect every emitted schema declares.
pub const DIALECT: &str = "https://json-schema.org/draft/2020-12/schema";

/// Named definitions collected while building a schema, emitted under `$defs`.
#[derive(Debug, Default)]
pub struct Defs {
    entries: Vec<(String, Value)>,
}

impl Defs {
    /// Empty definitions.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Register `name` once, building its schema only on first use, and return
    /// a `$ref` to it.
    pub fn reference(&mut self, name: &str, build: impl FnOnce(&mut Self) -> Value) -> Value {
        if !self.entries.iter().any(|(n, _)| n == name) {
            // Reserve the slot first so recursive references terminate.
            self.entries.push((name.to_owned(), Value::Null));
            let schema = build(self);
            if let Some(slot) = self.entries.iter_mut().find(|(n, _)| n == name) {
                slot.1 = schema;
            }
        }
        obj(vec![("$ref", string(&format!("#/$defs/{name}")))])
    }

    /// Consume into a `$defs` object, sorted by name for deterministic output.
    #[must_use]
    pub fn into_value(mut self) -> Value {
        self.entries.sort_by(|a, b| a.0.cmp(&b.0));
        Value::Object(Object::from_members_unchecked(self.entries))
    }

    /// Whether no definitions were registered.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Build an object from literal members. Keys are compile-time literals chosen
/// by this crate, so collisions are programmer errors caught by the schema
/// tests; a colliding key here is dropped rather than panicking in a library.
#[must_use]
pub fn obj(members: Vec<(&str, Value)>) -> Value {
    let mut out = Object::new();
    for (k, v) in members {
        let _ = out.insert(k.to_owned(), v);
    }
    Value::Object(out)
}

/// A string value.
#[must_use]
pub fn string(s: &str) -> Value {
    Value::String(s.to_owned())
}

/// An integer value. Out-of-range inputs become `0`; callers pass constants.
#[must_use]
pub fn int(i: i64) -> Value {
    Value::Number(Number::from_i64(i).unwrap_or(Number::Int(0)))
}

/// An array of strings.
#[must_use]
pub fn strings(items: &[&str]) -> Value {
    Value::Array(items.iter().map(|s| string(s)).collect())
}

/// Normalise a Rust doc comment into a schema description: trim each line,
/// drop empty leading/trailing lines, join paragraphs with a single newline.
#[must_use]
pub fn description(doc: &str) -> Value {
    let lines: Vec<&str> = doc.lines().map(str::trim).collect();
    let text = lines.join("\n");
    string(text.trim())
}
