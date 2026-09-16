//! Structured protocol errors.
//!
//! A protocol error says **the bytes did not form a valid message**. It is never
//! a policy decision: a malformed request is not `DENY`, it is not a request at
//! all. Future denials (`direwolf.tool.denied`, M3+) live in a different schema
//! namespace so the two cannot be confused by a caller or an auditor.
//!
//! Errors carry a stable wire code, an optional finer [`Violation`] kind, a JSON
//! Pointer to the offending location, and a short detail string. They never
//! carry parser internals, stack traces, or unbounded attacker-supplied text.

use std::fmt;

use crate::limits::{MAX_ERROR_DETAIL_CHARS, MAX_ERROR_PATH_CHARS};
use crate::version::VersionRange;

/// Stable wire code for a protocol error.
///
/// `PROTOCOL_SCHEMA_VIOLATION` and `PROTOCOL_VERSION_UNSUPPORTED` are the names
/// fixed by ADR-0016 and ADR-0023. The remainder are fixed by ADR-0032 so the
/// lexical failure classes are distinguishable in tests and in the audit log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// A frame declared a body length of zero.
    FrameEmpty,
    /// A frame declared a body longer than [`crate::limits::MAX_FRAME_BODY`].
    FrameTooLarge,
    /// The stream ended part-way through a frame header or body.
    FrameTruncated,
    /// The frame's content-type byte is not one this version understands.
    ContentTypeUnsupported,
    /// The body is not well-formed UTF-8.
    InvalidUtf8,
    /// The body is not a single JSON value under RFC 8259.
    InvalidJson,
    /// An object contains the same key twice, byte for byte.
    DuplicateKey,
    /// Nesting exceeds [`crate::limits::MAX_DEPTH`].
    MaxDepthExceeded,
    /// A number is outside the family's admitted domain (for DWKP: a fraction,
    /// an exponent, or an integer beyond ±(2^53 − 1)).
    NumberOutOfDomain,
    /// The envelope or schema version is not supported by the receiver.
    VersionUnsupported,
    /// The `(type, schema)` pair names no operation this receiver understands.
    UnknownOperation,
    /// The value is well-formed JSON but does not match the message schema.
    SchemaViolation,
}

impl ErrorCode {
    /// Every code, in declaration order. Used for schema emission and tests.
    pub const ALL: [Self; 12] = [
        Self::FrameEmpty,
        Self::FrameTooLarge,
        Self::FrameTruncated,
        Self::ContentTypeUnsupported,
        Self::InvalidUtf8,
        Self::InvalidJson,
        Self::DuplicateKey,
        Self::MaxDepthExceeded,
        Self::NumberOutOfDomain,
        Self::VersionUnsupported,
        Self::UnknownOperation,
        Self::SchemaViolation,
    ];

    /// The wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FrameEmpty => "PROTOCOL_FRAME_EMPTY",
            Self::FrameTooLarge => "PROTOCOL_FRAME_TOO_LARGE",
            Self::FrameTruncated => "PROTOCOL_FRAME_TRUNCATED",
            Self::ContentTypeUnsupported => "PROTOCOL_CONTENT_TYPE_UNSUPPORTED",
            Self::InvalidUtf8 => "PROTOCOL_INVALID_UTF8",
            Self::InvalidJson => "PROTOCOL_INVALID_JSON",
            Self::DuplicateKey => "PROTOCOL_DUPLICATE_KEY",
            Self::MaxDepthExceeded => "PROTOCOL_MAX_DEPTH_EXCEEDED",
            Self::NumberOutOfDomain => "PROTOCOL_NUMBER_OUT_OF_DOMAIN",
            Self::VersionUnsupported => "PROTOCOL_VERSION_UNSUPPORTED",
            Self::UnknownOperation => "PROTOCOL_UNKNOWN_OPERATION",
            Self::SchemaViolation => "PROTOCOL_SCHEMA_VIOLATION",
        }
    }

    /// Parse a wire spelling. Exact, case-sensitive match only.
    #[must_use]
    pub fn from_wire(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.as_str() == s)
    }
}

/// The specific way a value failed its schema. Present only with
/// [`ErrorCode::SchemaViolation`] or [`ErrorCode::VersionUnsupported`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Violation {
    /// A key the schema does not declare (DWKP only; DWCP and events preserve).
    UnknownField,
    /// A required key is absent.
    MissingField,
    /// A key is known to the envelope but not permitted for this operation.
    ForbiddenField,
    /// A value has the wrong JSON type.
    WrongType,
    /// `null` where the schema requires a value. Absence, not `null`, is how an
    /// optional field is omitted: one value, one encoding.
    NullNotAllowed,
    /// An integer outside its declared range.
    OutOfRange,
    /// A string longer than its declared maximum.
    TooLong,
    /// A string that does not match its declared format.
    InvalidFormat,
    /// A string that is not one of an enumeration's variants.
    UnknownVariant,
    /// An array with more items than its declared maximum.
    TooManyItems,
    /// Two fields that must agree do not.
    Inconsistent,
}

impl Violation {
    /// Every violation kind, in declaration order.
    pub const ALL: [Self; 11] = [
        Self::UnknownField,
        Self::MissingField,
        Self::ForbiddenField,
        Self::WrongType,
        Self::NullNotAllowed,
        Self::OutOfRange,
        Self::TooLong,
        Self::InvalidFormat,
        Self::UnknownVariant,
        Self::TooManyItems,
        Self::Inconsistent,
    ];

    /// The wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnknownField => "UNKNOWN_FIELD",
            Self::MissingField => "MISSING_FIELD",
            Self::ForbiddenField => "FORBIDDEN_FIELD",
            Self::WrongType => "WRONG_TYPE",
            Self::NullNotAllowed => "NULL_NOT_ALLOWED",
            Self::OutOfRange => "OUT_OF_RANGE",
            Self::TooLong => "TOO_LONG",
            Self::InvalidFormat => "INVALID_FORMAT",
            Self::UnknownVariant => "UNKNOWN_VARIANT",
            Self::TooManyItems => "TOO_MANY_ITEMS",
            Self::Inconsistent => "INCONSISTENT",
        }
    }

    /// Parse a wire spelling. Exact, case-sensitive match only.
    #[must_use]
    pub fn from_wire(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str() == s)
    }
}

/// A protocol-layer failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolError {
    /// Stable wire code.
    pub code: ErrorCode,
    /// Finer classification for schema and version failures.
    pub violation: Option<Violation>,
    /// RFC 6901 JSON Pointer to the failing location; empty for the root.
    pub path: String,
    /// Byte offset into the input for lexical failures. Diagnostic only; not
    /// sent on the wire.
    pub offset: Option<usize>,
    /// Short human-readable explanation. Bounded; never parser internals.
    pub detail: String,
    /// For [`ErrorCode::VersionUnsupported`]: the range the receiver supports,
    /// so the failure is actionable rather than a dead end (ADR-0016 rule 4).
    pub supported: Option<VersionRange>,
}

impl ProtocolError {
    /// A new error with no path, offset or version range.
    #[must_use]
    pub fn new(code: ErrorCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            violation: None,
            path: String::new(),
            offset: None,
            detail: truncate_chars(&detail.into(), MAX_ERROR_DETAIL_CHARS),
            supported: None,
        }
    }

    /// A schema violation at `path`.
    #[must_use]
    pub fn schema(violation: Violation, path: &str, detail: impl Into<String>) -> Self {
        Self::new(ErrorCode::SchemaViolation, detail)
            .with_violation(violation)
            .with_path(path)
    }

    /// Attach a byte offset.
    #[must_use]
    pub const fn at_offset(mut self, offset: usize) -> Self {
        self.offset = Some(offset);
        self
    }

    /// Attach a violation kind.
    #[must_use]
    pub const fn with_violation(mut self, violation: Violation) -> Self {
        self.violation = Some(violation);
        self
    }

    /// Attach a JSON Pointer path, truncated to a bounded length.
    #[must_use]
    pub fn with_path(mut self, path: &str) -> Self {
        self.path = truncate_chars(path, MAX_ERROR_PATH_CHARS);
        self
    }

    /// Attach the supported version range.
    #[must_use]
    pub const fn with_supported(mut self, supported: VersionRange) -> Self {
        self.supported = Some(supported);
        self
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.code.as_str())?;
        if let Some(v) = self.violation {
            write!(f, " ({})", v.as_str())?;
        }
        if !self.path.is_empty() {
            write!(f, " at {}", self.path)?;
        }
        write!(f, ": {}", self.detail)
    }
}

impl std::error::Error for ProtocolError {}

/// Truncate to at most `max` Unicode scalar values, never splitting one.
#[must_use]
pub fn truncate_chars(s: &str, max: usize) -> String {
    match s.char_indices().nth(max) {
        Some((byte_index, _)) => s.get(..byte_index).unwrap_or_default().to_owned(),
        None => s.to_owned(),
    }
}

/// Render a key for inclusion in an error detail: bounded, with control
/// characters escaped so an attacker-chosen key cannot forge log lines.
#[must_use]
pub fn quote_key(key: &str) -> String {
    let mut out = String::from("\"");
    for c in truncate_chars(key, 64).chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{{{:x}}}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::{ErrorCode, Violation, quote_key, truncate_chars};

    #[test]
    fn wire_spellings_round_trip_and_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for code in ErrorCode::ALL {
            assert_eq!(ErrorCode::from_wire(code.as_str()), Some(code));
            assert!(seen.insert(code.as_str()));
        }
        for v in Violation::ALL {
            assert_eq!(Violation::from_wire(v.as_str()), Some(v));
        }
    }

    #[test]
    fn the_corpus_names_are_exactly_as_adr_0023_spells_them() {
        assert_eq!(
            ErrorCode::SchemaViolation.as_str(),
            "PROTOCOL_SCHEMA_VIOLATION"
        );
        assert_eq!(
            ErrorCode::VersionUnsupported.as_str(),
            "PROTOCOL_VERSION_UNSUPPORTED"
        );
    }

    #[test]
    fn truncation_never_splits_a_scalar_value() {
        assert_eq!(truncate_chars("aéb", 2), "aé");
        assert_eq!(truncate_chars("ab", 5), "ab");
    }

    #[test]
    fn quoted_keys_cannot_inject_newlines_into_logs() {
        let q = quote_key("evil\nkey");
        assert!(!q.contains('\n'));
    }
}
