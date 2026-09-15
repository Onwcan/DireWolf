//! Prefixed, time-ordered identifiers.
//!
//! `DATA_MODEL.md` §5: UUIDv7 throughout, prefixed for readability —
//! `run_01J8XQ…`. The text form is `<prefix>_<26 characters>`, where the 26
//! characters are the 128-bit UUID in Crockford base32, most significant bits
//! first.
//!
//! Decoding is exact and has one spelling per identifier: uppercase alphabet
//! only (no `I`/`L`/`O`/`U` aliases, no lowercase), first character `0`–`7`
//! (the top two of 130 encoded bits are zero), and the decoded value must carry
//! the UUID version nibble `7` and the RFC 9562 variant bits `10`. A regex can
//! check the alphabet but not the bits, so the schema pattern is necessary
//! rather than sufficient; the decoder and the Python bindings both check the
//! bits, and the shared vectors assert they agree.
//!
//! Generating identifiers needs a clock and randomness and is not a wire
//! concern. This module only validates them.

use crate::error::{ProtocolError, Violation};
use crate::json::Value;
use crate::schema::{Defs, int, obj, string};
use crate::wire::{Cx, WireType, expect_string};

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Length of the encoded UUID, in characters.
pub const ENCODED_LEN: usize = 26;

/// The schema pattern for the 26-character body.
pub const BODY_PATTERN: &str = "[0-7][0-9A-HJKMNP-TV-Z]{25}";

/// Decode a 26-character Crockford base32 body to a UUIDv7, or `None`.
#[must_use]
pub fn decode_uuid7(body: &str) -> Option<u128> {
    if body.len() != ENCODED_LEN {
        return None;
    }
    let mut value: u128 = 0;
    for (i, byte) in body.bytes().enumerate() {
        let digit = ALPHABET.iter().position(|a| *a == byte)?;
        if i == 0 && digit > 7 {
            return None;
        }
        value = value
            .checked_mul(32)?
            .checked_add(u128::try_from(digit).ok()?)?;
    }
    let version = (value >> 76) & 0xF;
    let variant = (value >> 62) & 0b11;
    (version == 7 && variant == 0b10).then_some(value)
}

/// Encode a 128-bit value as 26 Crockford base32 characters.
#[must_use]
pub fn encode_uuid(value: u128) -> String {
    let mut out = [b'0'; ENCODED_LEN];
    let mut v = value;
    for slot in out.iter_mut().rev() {
        let index = usize::try_from(v & 31).unwrap_or(0);
        *slot = ALPHABET.get(index).copied().unwrap_or(b'0');
        v >>= 5;
    }
    String::from_utf8(out.to_vec()).unwrap_or_default()
}

/// Declare an identifier type with a fixed prefix.
macro_rules! wire_id {
    ($(#[doc = $doc:literal])* $name:ident, $prefix:literal) => {
        $(#[doc = $doc])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(String);

        impl $name {
            /// The prefix, without the underscore.
            pub const PREFIX: &'static str = $prefix;

            /// Parse, returning `None` unless the prefix and body are exact.
            #[must_use]
            pub fn parse(s: &str) -> Option<Self> {
                let body = s.strip_prefix(concat!($prefix, "_"))?;
                decode_uuid7(body).map(|_| Self(s.to_owned()))
            }

            /// Build from a UUIDv7 value; `None` if it is not one.
            #[must_use]
            pub fn from_uuid(value: u128) -> Option<Self> {
                Self::parse(&format!(concat!($prefix, "_{}"), encode_uuid(value)))
            }

            /// The full text form.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl WireType for $name {
            fn decode(value: Value, cx: &mut Cx) -> Result<Self, ProtocolError> {
                let s = expect_string(value, cx)?;
                Self::parse(&s).ok_or_else(|| {
                    cx.violation(
                        Violation::InvalidFormat,
                        concat!("expected a ", $prefix, "_ UUIDv7 identifier"),
                    )
                })
            }

            fn encode(&self) -> Result<Value, ProtocolError> {
                Ok(Value::String(self.0.clone()))
            }

            fn schema(_: &mut Defs) -> Value {
                obj(vec![
                    ("type", string("string")),
                    ("minLength", int(i64::try_from($prefix.len() + 1 + ENCODED_LEN).unwrap_or(0))),
                    ("maxLength", int(i64::try_from($prefix.len() + 1 + ENCODED_LEN).unwrap_or(0))),
                    ("pattern", string(&format!("^{}_{}$", $prefix, BODY_PATTERN))),
                    ("x-direwolf-type", string(stringify!($name))),
                    ("x-direwolf-format", string("uuid7-id")),
                    ("x-direwolf-id-prefix", string($prefix)),
                ])
            }
        }
    };
}

wire_id! {
    /// Identifies one request or response message.
    MessageId, "msg"
}

wire_id! {
    /// Identifies one event record.
    EventId, "evt"
}

wire_id! {
    /// Identifies a session. Sessions are the unit of lease ownership.
    SessionId, "ses"
}

wire_id! {
    /// Identifies a run.
    RunId, "run"
}

/// Any DireWolf identifier: a lowercase prefix of two to eight letters and a
/// UUIDv7 body. Used where the corpus permits any entity to be referenced —
/// `correlation_id` (`PROTOCOL.md` §1 uses a run id) and `causation_id` (a
/// message or an event) — and for the envelope `id` before its prefix is
/// checked against the message type.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AnyId(String);

impl AnyId {
    /// Parse, returning `None` unless the shape is exact.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let (prefix, body) = s.split_once('_')?;
        let prefix_ok =
            (2..=8).contains(&prefix.len()) && prefix.bytes().all(|b| b.is_ascii_lowercase());
        (prefix_ok && decode_uuid7(body).is_some()).then(|| Self(s.to_owned()))
    }

    /// The full text form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The prefix, without the underscore.
    #[must_use]
    pub fn prefix(&self) -> &str {
        self.0.split_once('_').map_or("", |(p, _)| p)
    }
}

impl WireType for AnyId {
    fn decode(value: Value, cx: &mut Cx) -> Result<Self, ProtocolError> {
        let s = expect_string(value, cx)?;
        Self::parse(&s).ok_or_else(|| {
            cx.violation(
                Violation::InvalidFormat,
                "expected a prefixed UUIDv7 identifier",
            )
        })
    }

    fn encode(&self) -> Result<Value, ProtocolError> {
        Ok(Value::String(self.0.clone()))
    }

    fn schema(_: &mut Defs) -> Value {
        obj(vec![
            ("type", string("string")),
            ("maxLength", int(35)),
            ("pattern", string(&format!("^[a-z]{{2,8}}_{BODY_PATTERN}$"))),
            ("x-direwolf-type", string("AnyId")),
            ("x-direwolf-format", string("uuid7-id")),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::{MessageId, SessionId, decode_uuid7, encode_uuid};

    /// A UUIDv7 with version 7 and variant `10`: `0191e2a4-c3b0-7d4e-8f00-0123456789ab`.
    const SAMPLE: u128 = 0x0191_e2a4_c3b0_7d4e_8f00_0123_4567_89ab;

    #[test]
    fn encode_then_decode_is_identity_for_a_real_uuid7() {
        let text = encode_uuid(SAMPLE);
        assert_eq!(text.len(), 26);
        assert_eq!(decode_uuid7(&text), Some(SAMPLE));
    }

    #[test]
    fn prefixes_are_exact() {
        let body = encode_uuid(SAMPLE);
        assert!(SessionId::parse(&format!("ses_{body}")).is_some());
        assert!(SessionId::parse(&format!("run_{body}")).is_none());
        assert!(SessionId::parse(&format!("SES_{body}")).is_none());
        assert!(MessageId::parse(&format!("msg{body}")).is_none());
    }

    #[test]
    fn non_canonical_spellings_are_rejected() {
        let body = encode_uuid(SAMPLE);
        assert!(
            decode_uuid7(&body.to_lowercase()).is_none(),
            "lowercase alias"
        );
        assert!(
            decode_uuid7(&body.replace('0', "O")).is_none(),
            "O alias for 0"
        );
        assert!(decode_uuid7(&format!("{body}0")).is_none(), "too long");
        assert!(
            decode_uuid7(body.get(1..).unwrap_or_default()).is_none(),
            "too short"
        );
        assert!(
            decode_uuid7("80000000000000000000000000").is_none(),
            "above 128 bits"
        );
    }

    #[test]
    fn a_uuid_that_is_not_version_7_is_rejected() {
        let v4 = (SAMPLE & !(0xF << 76)) | (4 << 76);
        assert!(decode_uuid7(&encode_uuid(v4)).is_none());
        let bad_variant = SAMPLE & !(0b11 << 62);
        assert!(decode_uuid7(&encode_uuid(bad_variant)).is_none());
    }
}
