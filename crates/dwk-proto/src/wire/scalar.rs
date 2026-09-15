//! Bounded scalar wire types.
//!
//! A raw `u64` or `String` never appears in a message type. Each field has a
//! newtype that states its range or format once, and that statement is used by
//! the decoder, the encoder and the emitted schema alike.
//!
//! String lengths are counted in **Unicode scalar values**, which is what JSON
//! Schema's `maxLength` counts and what Python's `len(str)` returns, so the
//! three agree without conversion.

use crate::error::{ProtocolError, Violation};
use crate::json::{Number, Value};
use crate::limits::MAX_SAFE_INTEGER;
use crate::schema::{Defs, int, obj, string};
use crate::wire::{Cx, WireType, expect_integer, expect_string};

/// Declare a bounded integer newtype.
macro_rules! wire_int {
    ($(#[doc = $doc:literal])* $name:ident($inner:ty), min = $min:expr, max = $max:expr) => {
        $(#[doc = $doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name($inner);

        impl $name {
            /// Smallest permitted value.
            pub const MIN: $inner = $min;
            /// Largest permitted value.
            pub const MAX: $inner = $max;

            /// Construct, returning `None` outside the declared range.
            #[must_use]
            pub fn new(value: $inner) -> Option<Self> {
                (Self::MIN..=Self::MAX).contains(&value).then_some(Self(value))
            }

            /// The inner value.
            #[must_use]
            pub const fn get(self) -> $inner {
                self.0
            }
        }

        impl WireType for $name {
            fn decode(value: Value, cx: &mut Cx) -> Result<Self, ProtocolError> {
                let raw = expect_integer(&value, cx)?;
                <$inner>::try_from(raw).ok().and_then(Self::new).ok_or_else(|| {
                    cx.violation(
                        Violation::OutOfRange,
                        format!(
                            "{} must be within {}..={}",
                            stringify!($name),
                            Self::MIN,
                            Self::MAX
                        ),
                    )
                })
            }

            fn encode(&self) -> Result<Value, ProtocolError> {
                let as_i64 = i64::try_from(self.0).unwrap_or(MAX_SAFE_INTEGER);
                Ok(Value::Number(Number::from_i64(as_i64).unwrap_or(Number::Int(0))))
            }

            fn schema(_: &mut Defs) -> Value {
                obj(vec![
                    ("type", string("integer")),
                    ("minimum", int(i64::try_from(Self::MIN).unwrap_or(0))),
                    ("maximum", int(i64::try_from(Self::MAX).unwrap_or(MAX_SAFE_INTEGER))),
                    ("x-direwolf-type", string(stringify!($name))),
                ])
            }
        }
    };
}

wire_int! {
    /// A protocol version number: the envelope `v`, a `schema_version`, or a
    /// bound of a negotiated range. Version 0 does not exist.
    Version(u16), min = 1, max = u16::MAX
}

wire_int! {
    /// A session lease epoch. Monotonic per session and owned by
    /// `dwkd-authority`, which is the only party that assigns one
    /// (`PROTOCOL.md` §3). A runtime echoes the epoch it was granted; it can
    /// never choose one.
    Epoch(u64), min = 1, max = 9_007_199_254_740_991
}

/// Declare a bounded string newtype with a validator.
///
/// `pattern` is the JSON Schema regex describing exactly what `validate`
/// accepts. The two are written side by side so a reviewer can check them
/// together, and the shared invalid-message vectors check them mechanically
/// against the Python bindings, which enforce `pattern` directly.
macro_rules! wire_text {
    (
        $(#[doc = $doc:literal])*
        $name:ident,
        max_chars = $max:expr,
        pattern = $pattern:expr,
        format = $format:expr,
        validate = $validate:expr
    ) => {
        $(#[doc = $doc])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $name(String);

        impl $name {
            /// Maximum length in Unicode scalar values.
            pub const MAX_CHARS: usize = $max;

            /// Construct, returning `None` if the value is too long or
            /// malformed.
            #[must_use]
            pub fn new(value: impl Into<String>) -> Option<Self> {
                let value = value.into();
                let check: fn(&str) -> bool = $validate;
                (value.chars().count() <= Self::MAX_CHARS && check(&value)).then_some(Self(value))
            }

            /// The string.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl WireType for $name {
            fn decode(value: Value, cx: &mut Cx) -> Result<Self, ProtocolError> {
                let s = expect_string(value, cx)?;
                if s.chars().count() > Self::MAX_CHARS {
                    return Err(cx.violation(
                        Violation::TooLong,
                        format!("{} exceeds {} characters", stringify!($name), Self::MAX_CHARS),
                    ));
                }
                let check: fn(&str) -> bool = $validate;
                if !check(&s) {
                    return Err(cx.violation(
                        Violation::InvalidFormat,
                        format!("{} is not correctly formatted", stringify!($name)),
                    ));
                }
                Ok(Self(s))
            }

            fn encode(&self) -> Result<Value, ProtocolError> {
                Ok(Value::String(self.0.clone()))
            }

            fn schema(_: &mut Defs) -> Value {
                let mut members = vec![
                    ("type", string("string")),
                    ("maxLength", int(i64::try_from(Self::MAX_CHARS).unwrap_or(0))),
                    ("x-direwolf-type", string(stringify!($name))),
                ];
                let pattern: Option<&str> = $pattern;
                if let Some(p) = pattern {
                    members.push(("pattern", string(p)));
                }
                let format: Option<&str> = $format;
                if let Some(f) = format {
                    members.push(("x-direwolf-format", string(f)));
                }
                obj(members)
            }
        }
    };
}

wire_text! {
    /// A message `schema` name: `direwolf` followed by one to six dot-separated
    /// lowercase segments, e.g. `direwolf.lease.acquire`.
    SchemaName,
    max_chars = 128,
    pattern = Some("^direwolf(\\.[a-z][a-z0-9_]{0,31}){1,6}$"),
    format = None,
    validate = valid_schema_name
}

wire_text! {
    /// Free text explaining an error. Informational only: no decision may be
    /// taken on its content, and it is bounded because it is audited.
    Detail,
    max_chars = crate::limits::MAX_ERROR_DETAIL_CHARS,
    pattern = None,
    format = None,
    validate = |_| true
}

impl Detail {
    /// Build from any text, truncating to the limit. Always valid: `Detail`
    /// has no format, only a length.
    #[must_use]
    pub fn truncated(text: &str) -> Self {
        Self(crate::error::truncate_chars(text, Self::MAX_CHARS))
    }
}

wire_text! {
    /// An RFC 6901 JSON Pointer locating an error within a message.
    ErrorPath,
    max_chars = crate::limits::MAX_ERROR_PATH_CHARS,
    pattern = Some("^(/[\\s\\S]*)?$"),
    format = None,
    validate = |s| s.is_empty() || s.starts_with('/')
}

wire_text! {
    /// A sender-chosen key making a side-effecting request idempotent.
    ///
    /// The kernel deduplicates on it (`PROTOCOL.md` §8); its semantics arrive
    /// with the first effect-bearing operation (M9). No M2 operation permits
    /// one.
    IdempotencyKey,
    max_chars = 128,
    pattern = Some("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"),
    format = None,
    validate = valid_idempotency_key
}

wire_text! {
    /// A client-protocol error code. Open-ended by design: DWCP is
    /// forward-compatible, so a client must accept codes newer than itself.
    ClientErrorCode,
    max_chars = 64,
    pattern = Some("^[A-Z][A-Z0-9_]{0,63}$"),
    format = None,
    validate = valid_upper_snake
}

wire_text! {
    /// A UTC timestamp, `YYYY-MM-DDTHH:MM:SS.mmmZ`: RFC 3339 with exactly
    /// millisecond precision and a literal `Z`, so every instant has one
    /// spelling.
    ///
    /// **Advisory.** A timestamp is the sender's claim about its own clock.
    /// Expiry, lease and approval decisions use time the kernel reads itself
    /// (`RELIABILITY.md` §10); nothing on this field may gate authority.
    Timestamp,
    max_chars = 24,
    pattern = Some("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z$"),
    format = Some("rfc3339-utc-millis"),
    validate = valid_timestamp
}

fn valid_schema_name(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("direwolf.") else {
        return false;
    };
    let segments: Vec<&str> = rest.split('.').collect();
    (1..=6).contains(&segments.len())
        && segments.iter().all(|seg| {
            let mut chars = seg.chars();
            matches!(chars.next(), Some('a'..='z'))
                && seg.len() <= 32
                && chars.all(|c| matches!(c, 'a'..='z' | '0'..='9' | '_'))
        })
}

fn valid_idempotency_key(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-'))
}

fn valid_upper_snake(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some('A'..='Z'))
        && chars.all(|c| matches!(c, 'A'..='Z' | '0'..='9' | '_'))
}

fn valid_timestamp(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 24 {
        return false;
    }
    let shape_ok = b.iter().enumerate().all(|(i, c)| match i {
        4 | 7 => *c == b'-',
        10 => *c == b'T',
        13 | 16 => *c == b':',
        19 => *c == b'.',
        23 => *c == b'Z',
        _ => c.is_ascii_digit(),
    });
    if !shape_ok {
        return false;
    }
    let num = |range: std::ops::Range<usize>| -> Option<u32> { s.get(range)?.parse().ok() };
    let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) = (
        num(0..4),
        num(5..7),
        num(8..10),
        num(11..13),
        num(14..16),
        num(17..19),
    ) else {
        return false;
    };
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=days_in_month).contains(&day) && hour < 24 && minute < 60 && second < 60
}

/// Declare a closed string enumeration.
macro_rules! wire_enum {
    (
        $(#[doc = $doc:literal])*
        $name:ident { $( $(#[doc = $vdoc:literal])* $variant:ident = $wire:literal ),+ $(,)? }
    ) => {
        $(#[doc = $doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $name {
            $( $(#[doc = $vdoc])* $variant, )+
        }

        impl $name {
            /// Every variant, in declaration order.
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];

            /// The wire spelling.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $wire,)+ }
            }
        }

        impl $crate::wire::WireType for $name {
            fn decode(
                value: $crate::json::Value,
                cx: &mut $crate::wire::Cx,
            ) -> Result<Self, $crate::error::ProtocolError> {
                let s = $crate::wire::expect_string(value, cx)?;
                Self::ALL.iter().copied().find(|v| v.as_str() == s).ok_or_else(|| {
                    cx.violation(
                        $crate::error::Violation::UnknownVariant,
                        format!("not a {} variant", stringify!($name)),
                    )
                })
            }

            fn encode(&self) -> Result<$crate::json::Value, $crate::error::ProtocolError> {
                Ok($crate::json::Value::String(self.as_str().to_owned()))
            }

            fn schema(_: &mut $crate::schema::Defs) -> $crate::json::Value {
                $crate::schema::obj(vec![
                    ("type", $crate::schema::string("string")),
                    ("enum", $crate::schema::strings(&[$($wire),+])),
                    ("x-direwolf-type", $crate::schema::string(stringify!($name))),
                ])
            }
        }
    };
}

pub(crate) use wire_enum;

#[cfg(test)]
mod tests {
    use super::{valid_schema_name, valid_timestamp};

    #[test]
    fn timestamps_have_exactly_one_spelling_per_instant() {
        assert!(valid_timestamp("2026-09-12T09:14:22.481Z"));
        assert!(valid_timestamp("2024-02-29T23:59:59.999Z"));
        for bad in [
            "2026-09-12T09:14:22Z",      // no milliseconds
            "2026-09-12T09:14:22.4810Z", // too precise
            "2026-09-12T09:14:22.481+00:00",
            "2026-09-12t09:14:22.481z", // lowercase
            "2023-02-29T00:00:00.000Z", // not a leap year
            "1900-02-29T00:00:00.000Z", // century rule
            "2026-13-01T00:00:00.000Z",
            "2026-09-31T00:00:00.000Z",
            "2026-09-12T24:00:00.000Z",
            "2026-09-12T23:59:60.000Z", // leap seconds are not representable
            "2026-09-12T09:14:22.481Z ",
        ] {
            assert!(!valid_timestamp(bad), "{bad}");
        }
        assert!(valid_timestamp("2000-02-29T00:00:00.000Z"), "400-year rule");
    }

    #[test]
    fn schema_names() {
        assert!(valid_schema_name("direwolf.lease.acquire"));
        assert!(valid_schema_name("direwolf.session.lease_acquired"));
        for bad in [
            "direwolf",
            "direwolf.",
            "Direwolf.x",
            "direwolf.Lease",
            "direwolf.1x",
            "other.x",
        ] {
            assert!(!valid_schema_name(bad), "{bad}");
        }
    }
}
