//! The JSON value model.
//!
//! Deliberately small. Two properties matter:
//!
//! * **Objects preserve member order and can never hold a duplicate key.** The
//!   only ways to build an [`Object`] — the strict lexer and [`Object::insert`]
//!   — both reject a key byte-identical to one already present. There is no
//!   "last key wins" anywhere in this crate.
//! * **Numbers have one representation per value.** An integral value within
//!   ±(2^53 − 1) is always [`Number::Int`], however it was written (`1`, `1.0`,
//!   `1e0`, `-0`); everything else finite is [`Number::Float`]. Structural
//!   equality therefore coincides with numeric equality for I-JSON values, and
//!   canonicalisation cannot depend on how the sender spelled a number.

use crate::error::{ErrorCode, ProtocolError, quote_key};
use crate::limits::MAX_SAFE_INTEGER;

/// A JSON value.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// `null`
    Null,
    /// `true` or `false`
    Bool(bool),
    /// A number.
    Number(Number),
    /// A string of Unicode scalar values (never contains a lone surrogate).
    String(String),
    /// An array.
    Array(Vec<Value>),
    /// An object.
    Object(Object),
}

impl Value {
    /// The JSON type name, for error messages.
    #[must_use]
    pub const fn type_name(&self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::Bool(_) => "boolean",
            Self::Number(Number::Int(_)) => "integer",
            Self::Number(Number::Float(_)) => "number",
            Self::String(_) => "string",
            Self::Array(_) => "array",
            Self::Object(_) => "object",
        }
    }
}

/// A finite JSON number.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Number {
    /// An integral value with magnitude at most 2^53 − 1.
    Int(i64),
    /// Any other finite double. Never NaN, never infinite, never integral
    /// within the safe range (those are [`Number::Int`]).
    Float(f64),
}

impl Number {
    /// Normalise a finite double into its single representation.
    /// Returns `None` for NaN and infinities, which JSON cannot represent.
    #[must_use]
    pub fn from_f64(x: f64) -> Option<Self> {
        if !x.is_finite() {
            return None;
        }
        if x.fract() == 0.0 && x.abs() <= 9_007_199_254_740_991.0 {
            // In range and integral, so the conversion is exact.
            #[allow(clippy::cast_possible_truncation, clippy::as_conversions)]
            let i = x as i64;
            return Some(Self::Int(i));
        }
        Some(Self::Float(x))
    }

    /// An integer, if it is within the safe range.
    #[must_use]
    pub const fn from_i64(i: i64) -> Option<Self> {
        if i.unsigned_abs() <= MAX_SAFE_INTEGER.unsigned_abs() {
            Some(Self::Int(i))
        } else {
            None
        }
    }
}

/// A JSON object whose keys are pairwise distinct.
///
/// Member order is kept for diagnostics and for faithful re-emission of
/// non-canonical documents, but it is **not part of the value**: two objects
/// with the same members in a different order are equal, as RFC 8259 and
/// RFC 8785 both require. Keys are unique, so equality is set equality.
#[derive(Debug, Clone, Default)]
pub struct Object {
    members: Vec<(String, Value)>,
}

impl PartialEq for Object {
    fn eq(&self, other: &Self) -> bool {
        self.members.len() == other.members.len()
            && self.members.iter().all(|(k, v)| other.get(k) == Some(v))
    }
}

impl Object {
    /// An empty object.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            members: Vec::new(),
        }
    }

    /// Append a member, rejecting a key byte-identical to one already present.
    ///
    /// Quadratic in the number of members. That is deliberate at the value
    /// layer, which only encoders use for small, known key sets; the lexer,
    /// which sees attacker-chosen objects, uses a hash index instead.
    pub fn insert(&mut self, key: String, value: Value) -> Result<(), ProtocolError> {
        for (existing, _) in &self.members {
            if existing == &key {
                return Err(ProtocolError::new(
                    ErrorCode::DuplicateKey,
                    format!("duplicate key {}", quote_key(&key)),
                ));
            }
        }
        self.members.push((key, value));
        Ok(())
    }

    /// Members in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &Value)> {
        self.members.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// Number of members.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.members.len()
    }

    /// Whether the object is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// Look up a member by exact key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.members.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    /// Remove and return a member by exact key.
    pub fn remove(&mut self, key: &str) -> Option<Value> {
        let index = self.members.iter().position(|(k, _)| k == key)?;
        Some(self.members.remove(index).1)
    }

    /// Consume into members, in insertion order.
    #[must_use]
    pub fn into_members(self) -> Vec<(String, Value)> {
        self.members
    }

    pub(crate) const fn from_members_unchecked(members: Vec<(String, Value)>) -> Self {
        Self { members }
    }
}

#[cfg(test)]
mod tests {
    use super::{Number, Object, Value};

    #[test]
    fn object_equality_ignores_member_order_but_not_members() {
        let mut a = Object::new();
        a.insert("z".to_owned(), Value::Null).unwrap_or_default();
        a.insert("a".to_owned(), Value::Number(Number::Int(1)))
            .unwrap_or_default();
        let mut b = Object::new();
        b.insert("a".to_owned(), Value::Number(Number::Int(1)))
            .unwrap_or_default();
        b.insert("z".to_owned(), Value::Null).unwrap_or_default();
        assert_eq!(a, b);
        let mut c = b.clone();
        c.insert("extra".to_owned(), Value::Null)
            .unwrap_or_default();
        assert_ne!(a, c);
        let mut d = Object::new();
        d.insert("a".to_owned(), Value::Number(Number::Int(2)))
            .unwrap_or_default();
        d.insert("z".to_owned(), Value::Null).unwrap_or_default();
        assert_ne!(a, d);
    }
}
