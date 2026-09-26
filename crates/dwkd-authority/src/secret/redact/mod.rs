//! Return-path redaction (ADR-0046 §21). **Hygiene, not the control**: the
//! control is keeping a secret out of anything a consumer can echo (mode A).
//! This catches accidents — an echoed variable, a broad file read, an error
//! that repeats its input — on **raw bytes, before any encoding**, in every
//! tool output that crosses from effect back towards cognition.
//!
//! Two layers:
//!
//! * **exact** ([`exact`]): the live values of configured secrets, matched by
//!   an in-memory keyed fingerprint — never a retained plaintext, never
//!   persisted — and replaced with `[redacted:<handle>]`;
//! * **known shapes** ([`pattern`]): token formats (GitHub, OpenAI-style,
//!   Slack, AWS keys, PEM private keys, JWTs, bearer credentials, passwords in
//!   connection strings, high-entropy values next to `token=`/`password=`…),
//!   replaced with `[redacted:pattern]`.
//!
//! **What it cannot catch** — stated, not tested as protected: a transformed
//! secret (base64, hex, reversed, ROT13), a secret split across two separate
//! tool results, a secret encoded in a filename, an image or a timing channel,
//! a secret shorter than [`exact::MIN_EXACT_BYTES`], and a new credential the
//! tool minted itself.
//!
//! Precedence is deterministic: overlapping matches merge into one redacted
//! span; its label is the exact handle that starts earliest (then the longest,
//! then the first handle in order), else `pattern`. No byte of a matched span
//! survives, and no unmatched byte is dropped.

pub mod exact;
pub mod pattern;

use std::collections::BTreeMap;

use exact::ExactIndex;
use pattern::PatternClass;

use super::metadata::SecretHandle;

/// What a redacted span was.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HitKind {
    /// A configured secret's exact value.
    Handle(SecretHandle),
    /// A known credential shape.
    Pattern(PatternClass),
}

impl HitKind {
    /// The placeholder written in its place.
    #[must_use]
    pub fn placeholder(&self) -> String {
        match self {
            Self::Handle(handle) => format!("[redacted:{handle}]"),
            Self::Pattern(_) => "[redacted:pattern]".to_owned(),
        }
    }
}

/// A redacted buffer and what was removed from it — counts and kinds, never
/// the bytes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Redaction {
    /// The output, redacted.
    pub bytes: Vec<u8>,
    /// How many spans of each kind were replaced.
    pub hits: BTreeMap<HitKind, u64>,
}

impl Redaction {
    /// Whether anything was replaced.
    #[must_use]
    pub fn redacted(&self) -> bool {
        !self.hits.is_empty()
    }
}

/// One matched span of the input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Span {
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub(crate) kind: HitKind,
}

/// Rank for precedence within a merged span: exact handles first, earliest,
/// longest, then by handle.
fn better(a: &Span, b: &Span) -> bool {
    let rank = |s: &Span| match &s.kind {
        HitKind::Handle(_) => 0u8,
        HitKind::Pattern(_) => 1,
    };
    (rank(a), a.start, core::cmp::Reverse(a.end), &a.kind)
        < (rank(b), b.start, core::cmp::Reverse(b.end), &b.kind)
}

/// Redact `input` against `index` and the known shapes.
#[must_use]
pub fn redact(input: &[u8], index: &ExactIndex) -> Redaction {
    let mut spans = index.find(input);
    spans.extend(pattern::scan(input));
    if spans.is_empty() {
        return Redaction {
            bytes: input.to_vec(),
            hits: BTreeMap::new(),
        };
    }
    spans.sort_by(|a, b| {
        (a.start, core::cmp::Reverse(a.end)).cmp(&(b.start, core::cmp::Reverse(b.end)))
    });
    // Merge overlapping spans; keep the best label of each merged span.
    let mut merged: Vec<Span> = Vec::new();
    for span in spans {
        match merged.last_mut() {
            Some(last) if span.start < last.end => {
                if better(&span, last) {
                    last.kind = span.kind.clone();
                }
                last.end = last.end.max(span.end);
            }
            _ => merged.push(span),
        }
    }
    let mut bytes = Vec::with_capacity(input.len());
    let mut hits: BTreeMap<HitKind, u64> = BTreeMap::new();
    let mut at = 0usize;
    for span in &merged {
        bytes.extend_from_slice(input.get(at..span.start).unwrap_or_default());
        bytes.extend_from_slice(span.kind.placeholder().as_bytes());
        let count = hits.entry(span.kind.clone()).or_insert(0);
        *count = count.saturating_add(1);
        at = span.end;
    }
    bytes.extend_from_slice(input.get(at..).unwrap_or_default());
    Redaction { bytes, hits }
}

#[cfg(test)]
mod tests;
