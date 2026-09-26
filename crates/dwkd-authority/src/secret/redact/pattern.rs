//! Known credential shapes (ADR-0046 §21), matched by explicit scanners over
//! bytes: no regular expressions, so no backtracking; ASCII only, so nothing
//! depends on a locale; and every token run is bounded by [`MAX_TOKEN`].
//!
//! | class | shape |
//! |---|---|
//! | GitHub | `ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_` + ≥ 30 alphanumerics; `github_pat_` + ≥ 22 of `[A-Za-z0-9_]` |
//! | OpenAI-style | `sk-` + ≥ 20 of `[A-Za-z0-9_-]` with a letter and a digit |
//! | Slack | `xox[abprs]-` + ≥ 10 of `[A-Za-z0-9-]` |
//! | AWS access key id | `AKIA`/`ASIA` + exactly 16 of `[A-Z0-9]`, bounded both sides |
//! | PEM private key | `-----BEGIN … PRIVATE KEY-----` through its `-----END … PRIVATE KEY-----` (or to the end of a 16 KiB window) |
//! | JWT | `eyJ` + three dot-separated base64url segments of ≥ 8 |
//! | bearer | `Bearer` + space + ≥ 16 of `[A-Za-z0-9._~+/=-]` (the token only) |
//! | connection string | the password of `scheme://user:password@host` |
//! | keyword | a ≥ 16-character mixed-class value after `password=`, `token:`, `api_key=`… (the value only) |
//!
//! A heuristic, stated as one: a shape is not proof of a credential, and a
//! credential need not have a shape. False positives redact harmless text; a
//! false negative is why this is hygiene, not the control.

use super::{HitKind, Span};

/// The longest token run a scanner follows; a PEM block's window is
/// [`MAX_PEM`].
pub const MAX_TOKEN: usize = 512;
/// The longest PEM block redacted as one span.
pub const MAX_PEM: usize = 16 * 1024;

/// The class of a known-shape match. Recorded in audit; never the bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PatternClass {
    /// A GitHub token.
    GitHub,
    /// An OpenAI-style `sk-` key.
    OpenAi,
    /// A Slack token.
    Slack,
    /// An AWS access key id.
    Aws,
    /// A PEM private key block.
    PemPrivateKey,
    /// A JSON Web Token.
    Jwt,
    /// A bearer credential.
    Bearer,
    /// A password inside a connection string.
    ConnectionString,
    /// A high-entropy value next to a credential keyword.
    Keyword,
}

impl PatternClass {
    /// The stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GitHub => "github",
            Self::OpenAi => "openai",
            Self::Slack => "slack",
            Self::Aws => "aws",
            Self::PemPrivateKey => "pem_private_key",
            Self::Jwt => "jwt",
            Self::Bearer => "bearer",
            Self::ConnectionString => "connection_string",
            Self::Keyword => "keyword",
        }
    }
}

fn is_alnum(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}
fn is_word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}
fn is_dashed(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}
fn is_slack(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-'
}
fn is_aws(b: u8) -> bool {
    b.is_ascii_uppercase() || b.is_ascii_digit()
}
fn is_b64url(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}
fn is_bearer(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'+' | b'/' | b'=' | b'-')
}
fn is_value(b: u8) -> bool {
    b.is_ascii_graphic() && !matches!(b, b'"' | b'\'' | b',' | b';' | b'&' | b'<' | b'>' | b'`')
}

/// The end of the run of `class` bytes starting at `at`, at most `MAX_TOKEN`
/// long. Cached per class so a scan stays linear: every position inside a run
/// already measured reuses its end. One slot per byte class: 0 alphanumeric,
/// 1 word, 2 dashed, 3 Slack, 4 AWS, 5–7 the JWT segments, 8 bearer, 9 value.
struct Runs<'a> {
    input: &'a [u8],
    cache: [(usize, usize); 10],
}

impl<'a> Runs<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            cache: [(usize::MAX, 0); 10],
        }
    }

    fn end(&mut self, slot: usize, at: usize, class: fn(u8) -> bool) -> usize {
        if let Some((start, end)) = self.cache.get(slot).copied()
            && start != usize::MAX
            && start <= at
            && at < end
        {
            return end;
        }
        let limit = at.saturating_add(MAX_TOKEN).min(self.input.len());
        let mut end = at;
        while end < limit && self.input.get(end).is_some_and(|b| class(*b)) {
            end += 1;
        }
        if let Some(entry) = self.cache.get_mut(slot) {
            *entry = (at, end);
        }
        end
    }
}

fn starts_with(input: &[u8], at: usize, prefix: &[u8]) -> bool {
    input
        .get(at..at.saturating_add(prefix.len()))
        .is_some_and(|w| w == prefix)
}

fn starts_with_ignore_case(input: &[u8], at: usize, prefix: &[u8]) -> bool {
    input
        .get(at..at.saturating_add(prefix.len()))
        .is_some_and(|w| w.eq_ignore_ascii_case(prefix))
}

fn boundary_before(input: &[u8], at: usize) -> bool {
    at == 0 || input.get(at - 1).is_none_or(|b| !is_word(*b))
}

fn mixed(value: &[u8]) -> bool {
    let lower = value.iter().any(u8::is_ascii_lowercase);
    let upper = value.iter().any(u8::is_ascii_uppercase);
    let digit = value.iter().any(u8::is_ascii_digit);
    let other = value.iter().any(|b| !b.is_ascii_alphanumeric());
    let classes = [lower, upper, digit, other].iter().filter(|c| **c).count();
    let mut seen = [false; 256];
    let mut distinct = 0usize;
    for b in value {
        if let Some(slot) = seen.get_mut(usize::from(*b))
            && !*slot
        {
            *slot = true;
            distinct += 1;
        }
    }
    classes >= 2 && distinct >= 10
}

const KEYWORDS: &[&[u8]] = &[
    b"password",
    b"passwd",
    b"pwd",
    b"secret",
    b"client_secret",
    b"token",
    b"access_token",
    b"auth_token",
    b"refresh_token",
    b"api_key",
    b"apikey",
    b"api-key",
    b"access_key",
    b"secret_key",
    b"private_key",
];

/// One scan over `input`: the byte-run cache and the spans found so far.
/// Each method looks for its shapes at one position and returns where the
/// scan continues — past the span it found, or `next` unchanged.
struct Scanner<'a> {
    input: &'a [u8],
    runs: Runs<'a>,
    spans: Vec<Span>,
}

impl<'a> Scanner<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            runs: Runs::new(input),
            spans: Vec::new(),
        }
    }

    fn push(&mut self, start: usize, end: usize, class: PatternClass) {
        self.spans.push(Span {
            start,
            end,
            kind: HitKind::Pattern(class),
        });
    }

    /// GitHub, OpenAI-style, Slack and AWS tokens starting at `at`.
    fn prefixed(&mut self, at: usize, mut next: usize) -> usize {
        let input = self.input;
        for prefix in [&b"ghp_"[..], b"gho_", b"ghu_", b"ghs_", b"ghr_"] {
            if starts_with(input, at, prefix) {
                let end = self.runs.end(0, at + 4, is_alnum);
                if end - (at + 4) >= 30 {
                    self.push(at, end, PatternClass::GitHub);
                    next = end;
                }
            }
        }
        if starts_with(input, at, b"github_pat_") {
            let end = self.runs.end(1, at + 11, is_word);
            if end - (at + 11) >= 22 {
                self.push(at, end, PatternClass::GitHub);
                next = end;
            }
        }
        if starts_with(input, at, b"sk-") {
            let end = self.runs.end(2, at + 3, is_dashed);
            let token = input.get(at + 3..end).unwrap_or_default();
            if token.len() >= 20
                && token.iter().any(u8::is_ascii_alphabetic)
                && token.iter().any(u8::is_ascii_digit)
            {
                self.push(at, end, PatternClass::OpenAi);
                next = end;
            }
        }
        if starts_with(input, at, b"xox")
            && input
                .get(at + 3)
                .is_some_and(|b| matches!(b, b'a' | b'b' | b'p' | b'r' | b's'))
            && input.get(at + 4) == Some(&b'-')
        {
            let end = self.runs.end(3, at + 5, is_slack);
            if end - (at + 5) >= 10 {
                self.push(at, end, PatternClass::Slack);
                next = end;
            }
        }
        if starts_with(input, at, b"AKIA") || starts_with(input, at, b"ASIA") {
            let end = self.runs.end(4, at + 4, is_aws);
            if end - (at + 4) == 16 {
                self.push(at, end, PatternClass::Aws);
                next = end;
            }
        }
        next
    }

    /// A JWT or a bearer credential starting at `at`.
    fn structured(&mut self, at: usize, mut next: usize) -> usize {
        let input = self.input;
        if starts_with(input, at, b"eyJ") {
            let first = self.runs.end(5, at, is_b64url);
            if first - at >= 8 && input.get(first) == Some(&b'.') {
                let second = self.runs.end(6, first + 1, is_b64url);
                if second - (first + 1) >= 8 && input.get(second) == Some(&b'.') {
                    let third = self.runs.end(7, second + 1, is_b64url);
                    if third - (second + 1) >= 8 {
                        self.push(at, third, PatternClass::Jwt);
                        next = third;
                    }
                }
            }
        }
        if starts_with_ignore_case(input, at, b"bearer") && input.get(at + 6) == Some(&b' ') {
            let mut token = at + 7;
            while input.get(token) == Some(&b' ') && token < at + 16 {
                token += 1;
            }
            let end = self.runs.end(8, token, is_bearer);
            if end - token >= 16 {
                self.push(token, end, PatternClass::Bearer);
                next = end;
            }
        }
        next
    }

    /// A high-entropy value assigned to a credential keyword at `at`.
    fn keyword(&mut self, at: usize, mut next: usize) -> usize {
        let input = self.input;
        for keyword in KEYWORDS {
            if starts_with_ignore_case(input, at, keyword)
                && input.get(at + keyword.len()).is_none_or(|b| !is_word(*b))
            {
                let mut value = at + keyword.len();
                let mut assigned = false;
                while let Some(b) = input.get(value) {
                    if value > at + keyword.len() + 8 {
                        break;
                    }
                    match b {
                        b'=' | b':' if !assigned => assigned = true,
                        b' ' | b'"' | b'\'' | b'\t' => {}
                        _ => break,
                    }
                    value += 1;
                }
                if assigned {
                    let end = self.runs.end(9, value, is_value);
                    let token = input.get(value..end).unwrap_or_default();
                    if token.len() >= 16 && mixed(token) {
                        self.push(value, end, PatternClass::Keyword);
                        next = next.max(end);
                    }
                }
            }
        }
        next
    }

    /// A PEM private key block starting at `at`.
    fn pem(&mut self, at: usize, next: usize) -> usize {
        let input = self.input;
        if !starts_with(input, at, b"-----BEGIN ") {
            return next;
        }
        let window = input
            .get(at..at.saturating_add(128).min(input.len()))
            .unwrap_or_default();
        let header_end = window
            .iter()
            .position(|b| *b == b'\n')
            .unwrap_or(window.len());
        let header = window.get(..header_end).unwrap_or_default();
        if !header.windows(16).any(|w| w == b"PRIVATE KEY-----") {
            return next;
        }
        let limit = at.saturating_add(MAX_PEM).min(input.len());
        let body = input.get(at..limit).unwrap_or_default();
        let end = body
            .windows(9)
            .position(|w| w == b"-----END ")
            .and_then(|end_at| {
                let tail = body.get(end_at..)?;
                let close = tail.windows(16).position(|w| w == b"PRIVATE KEY-----")?;
                Some(at + end_at + close + 16)
            })
            .unwrap_or(limit);
        self.push(at, end, PatternClass::PemPrivateKey);
        end
    }

    /// The password inside a connection string, `scheme://user:password@host`,
    /// whose `://` is at `at`.
    fn connection_string(&mut self, at: usize) {
        let input = self.input;
        if !starts_with(input, at, b"://") {
            return;
        }
        let limit = at.saturating_add(3 + MAX_TOKEN).min(input.len());
        let mut colon = None;
        let mut cursor = at + 3;
        while cursor < limit {
            match input.get(cursor) {
                Some(b'@') => {
                    if let Some(c) = colon
                        && cursor > c + 1
                    {
                        self.push(c + 1, cursor, PatternClass::ConnectionString);
                    }
                    break;
                }
                Some(b':') if colon.is_none() => colon = Some(cursor),
                Some(b) if b.is_ascii_whitespace() || *b == b'/' || *b == b'?' || *b == b'#' => {
                    break;
                }
                None => break,
                _ => {}
            }
            cursor += 1;
        }
    }
}

/// Every known-shape span in `input`.
pub(crate) fn scan(input: &[u8]) -> Vec<Span> {
    let mut scanner = Scanner::new(input);
    let mut at = 0usize;
    while at < input.len() {
        let mut next = at + 1;
        if boundary_before(input, at) {
            next = scanner.prefixed(at, next);
            next = scanner.structured(at, next);
            next = scanner.keyword(at, next);
        }
        next = scanner.pem(at, next);
        scanner.connection_string(at);
        at = next.max(at + 1);
    }
    scanner.spans
}
