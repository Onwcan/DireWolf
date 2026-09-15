//! Typed wire values.
//!
//! Every message field is a [`WireType`]: it decodes itself from a [`Value`]
//! with exact type and bound checks, encodes itself back, and describes itself
//! as JSON Schema. Structs are declared once with `wire_struct!`, which
//! generates all three from the same field list, so the decoder, the encoder
//! and the schema cannot disagree about which fields exist.
//!
//! # Decoding rules, identical across every struct
//!
//! 1. The value must be an object.
//! 2. **Unknown members are examined first**, before any known field is
//!    interpreted. Under [`UnknownFields::Reject`] (DWKP) the first one fails
//!    the message; a key that differs from a known field only by Unicode
//!    normalisation fails as `PROTOCOL_NORMALIZATION_COLLISION`. Under
//!    [`UnknownFields::Preserve`] (DWCP, events) they are kept, in order.
//! 3. Known fields are then decoded in declaration order. A required field that
//!    is absent is `MISSING_FIELD`; an explicit `null` is `NULL_NOT_ALLOWED` for
//!    required and optional fields alike, so an omitted optional field has
//!    exactly one encoding.
//! 4. Cross-field checks run last.
//!
//! The Python bindings follow the same order; the shared invalid-message
//! vectors assert it.

pub mod id;
pub mod macros;
pub mod scalar;

use crate::error::{ErrorCode, ProtocolError, Violation, quote_key};
use crate::json::value::nfc;
use crate::json::{Number, Object, Value};
use crate::schema::Defs;

/// What a decoder does with members its schema does not declare.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownFields {
    /// Fail the message. The DWKP and DWWP rule (ADR-0023).
    Reject,
    /// Keep them for re-emission. The DWCP and event-log rule.
    Preserve,
}

/// Decoding context: the current JSON Pointer.
///
/// The unknown-field policy is deliberately **not** here. It belongs to each
/// type (see [`macros`]), so a DWKP payload cannot be decoded leniently by
/// passing a permissive context.
#[derive(Debug, Default)]
pub struct Cx {
    path: Vec<String>,
}

impl Cx {
    /// A context at the document root.
    #[must_use]
    pub const fn new() -> Self {
        Self { path: Vec::new() }
    }

    /// Descend into a member.
    pub fn push(&mut self, segment: &str) {
        self.path
            .push(segment.replace('~', "~0").replace('/', "~1"));
    }

    /// Return from a member.
    pub fn pop(&mut self) {
        self.path.pop();
    }

    /// The current location as an RFC 6901 JSON Pointer.
    #[must_use]
    pub fn pointer(&self) -> String {
        let mut out = String::new();
        for segment in &self.path {
            out.push('/');
            out.push_str(segment);
        }
        out
    }

    /// A schema violation at the current location.
    #[must_use]
    pub fn violation(&self, violation: Violation, detail: impl Into<String>) -> ProtocolError {
        ProtocolError::schema(violation, &self.pointer(), detail)
    }

    /// A wrong-type violation at the current location.
    #[must_use]
    pub fn wrong_type(&self, expected: &str, got: &Value) -> ProtocolError {
        self.violation(
            Violation::WrongType,
            format!("expected {expected}, found {}", got.type_name()),
        )
    }
}

/// A value that can cross the wire.
pub trait WireType: Sized {
    /// Decode from a parsed value.
    fn decode(value: Value, cx: &mut Cx) -> Result<Self, ProtocolError>;

    /// Encode to a value. Fails only for a preserving type whose extensions
    /// were given a key that collides with a declared field.
    fn encode(&self) -> Result<Value, ProtocolError>;

    /// Describe as a JSON Schema node, registering named definitions in `defs`.
    fn schema(defs: &mut Defs) -> Value;
}

impl WireType for bool {
    fn decode(value: Value, cx: &mut Cx) -> Result<Self, ProtocolError> {
        match value {
            Value::Bool(b) => Ok(b),
            other => Err(cx.wrong_type("boolean", &other)),
        }
    }

    fn encode(&self) -> Result<Value, ProtocolError> {
        Ok(Value::Bool(*self))
    }

    fn schema(_: &mut Defs) -> Value {
        crate::schema::obj(vec![("type", crate::schema::string("boolean"))])
    }
}

/// Split an object into declared and undeclared members, applying the
/// unknown-field policy. Returns the declared members (still in order) and the
/// preserved extensions.
pub fn partition_members(
    object: Object,
    declared: &[&str],
    unknown: UnknownFields,
    cx: &Cx,
) -> Result<(Vec<(String, Value)>, Object), ProtocolError> {
    let mut known = Vec::new();
    let mut extensions = Object::new();
    for (key, value) in object.into_members() {
        if declared.contains(&key.as_str()) {
            known.push((key, value));
            continue;
        }
        let normalized = nfc(&key);
        if let Some(field) = declared.iter().find(|d| nfc(d) == normalized) {
            let pointer = format!(
                "{}/{}",
                cx.pointer(),
                key.replace('~', "~0").replace('/', "~1")
            );
            return Err(ProtocolError::new(
                ErrorCode::NormalizationCollision,
                format!(
                    "key {} differs from declared field {} only by Unicode normalisation",
                    quote_key(&key),
                    quote_key(field)
                ),
            )
            .with_path(&pointer));
        }
        match unknown {
            UnknownFields::Reject => {
                let pointer = format!(
                    "{}/{}",
                    cx.pointer(),
                    key.replace('~', "~0").replace('/', "~1")
                );
                return Err(ProtocolError::schema(
                    Violation::UnknownField,
                    &pointer,
                    format!("unknown field {}", quote_key(&key)),
                ));
            }
            UnknownFields::Preserve => extensions.insert(key, value)?,
        }
    }
    Ok((known, extensions))
}

/// Remove a required field and decode it.
pub fn take_required<T: WireType>(
    members: &mut Vec<(String, Value)>,
    name: &str,
    cx: &mut Cx,
) -> Result<T, ProtocolError> {
    match take(members, name) {
        None => {
            // The path names where the field should have been.
            cx.push(name);
            let err = cx.violation(
                Violation::MissingField,
                format!("missing field {}", quote_key(name)),
            );
            cx.pop();
            Err(err)
        }
        Some(value) => decode_present(value, name, cx),
    }
}

/// Remove an optional field and decode it if present.
pub fn take_optional<T: WireType>(
    members: &mut Vec<(String, Value)>,
    name: &str,
    cx: &mut Cx,
) -> Result<Option<T>, ProtocolError> {
    match take(members, name) {
        None => Ok(None),
        Some(value) => decode_present(value, name, cx).map(Some),
    }
}

fn take(members: &mut Vec<(String, Value)>, name: &str) -> Option<Value> {
    let index = members.iter().position(|(k, _)| k == name)?;
    Some(members.remove(index).1)
}

fn decode_present<T: WireType>(value: Value, name: &str, cx: &mut Cx) -> Result<T, ProtocolError> {
    cx.push(name);
    let result = if value == Value::Null {
        Err(cx.violation(
            Violation::NullNotAllowed,
            "null is not a value; omit an optional field instead",
        ))
    } else {
        T::decode(value, cx)
    };
    cx.pop();
    result
}

/// Read an integer from a value, as the first step of a bounded integer type.
pub fn expect_integer(value: &Value, cx: &Cx) -> Result<i64, ProtocolError> {
    match value {
        Value::Number(Number::Int(i)) => Ok(*i),
        other => Err(cx.wrong_type("integer", other)),
    }
}

/// Read a string from a value.
pub fn expect_string(value: Value, cx: &Cx) -> Result<String, ProtocolError> {
    match value {
        Value::String(s) => Ok(s),
        other => Err(cx.wrong_type("string", &other)),
    }
}
