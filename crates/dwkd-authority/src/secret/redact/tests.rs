//! Redaction (ADR-0046 §21). Fixtures are generated at run time from
//! pieces, so no credential-shaped string is committed; assertions compare
//! booleans and redacted forms, never a secret, so a failure prints none.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use zeroize::Zeroizing;

use super::exact::{ExactIndex, MIN_EXACT_BYTES};
use super::pattern::PatternClass;
use super::{HitKind, redact};
use crate::secret::material::SecretMaterial;
use crate::secret::metadata::SecretHandle;

/// One line of the secret evidence (`make secret-broker-evidence`), printed
/// only after the assertions before it held.
fn evidence(suite: &str, case: &str, outcome: &str) {
    println!(
        "SECRET-EVIDENCE {{\"suite\":\"{suite}\",\"case\":\"{case}\",\"outcome\":\"{outcome}\",\"count\":1}}"
    );
}

/// A deterministic synthetic value: `len` alphanumerics from `seed`.
fn synthetic(seed: u64, len: usize) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut state = seed
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    (0..len)
        .map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            ALPHABET[usize::try_from(state >> 58).unwrap() % ALPHABET.len()]
        })
        .collect()
}

fn handle(text: &str) -> SecretHandle {
    SecretHandle::new(text).unwrap()
}

fn material(bytes: &[u8]) -> SecretMaterial {
    SecretMaterial::new(Zeroizing::new(bytes.to_vec())).unwrap()
}

fn index(entries: &[(&str, &[u8])]) -> ExactIndex {
    let mut index = ExactIndex::new().unwrap();
    for (name, value) in entries {
        index.insert(&handle(name), &material(value)).unwrap();
    }
    index
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

#[test]
fn an_exact_live_secret_is_replaced_wherever_it_stands() {
    let secret = synthetic(1, 40);
    let idx = index(&[("github-primary", &secret)]);
    let marker = b"[redacted:github-primary]";
    for (case, input) in [
        ("whole", secret.clone()),
        ("prefix", cat(&[&secret, b" trailing"])),
        ("suffix", cat(&[b"leading ", &secret])),
        ("middle", cat(&[b"a=", &secret, b";b"])),
        (
            "binary",
            cat(&[&[0u8, 255, 10, 0][..], &secret, &[0u8, 1, 2][..]]),
        ),
        ("twice", cat(&[&secret, b"|", &secret])),
    ] {
        let out = redact(&input, &idx);
        assert!(!contains(&out.bytes, &secret), "{case}: the value survived");
        assert!(contains(&out.bytes, marker), "{case}: no placeholder");
        assert!(out.redacted(), "{case}");
    }
    // Unmatched bytes are kept exactly, binary included.
    let input = cat(&[&[0u8, 255][..], &secret, &[7u8][..]]);
    let out = redact(&input, &idx);
    assert_eq!(out.bytes, cat(&[&[0u8, 255][..], marker, &[7u8][..]]));
    assert_eq!(
        out.hits.get(&HitKind::Handle(handle("github-primary"))),
        Some(&1)
    );
    evidence("secret-redaction", "exact-value", "placeholder");
}

#[test]
fn two_secrets_overlaps_and_shared_values_resolve_deterministically() {
    let first = synthetic(2, 24);
    let second = synthetic(3, 24);
    let idx = index(&[("alpha", &first), ("beta", &second)]);
    let out = redact(&cat(&[&first, b" ", &second]), &idx);
    assert_eq!(out.bytes, b"[redacted:alpha] [redacted:beta]");

    // Overlap: the tail of `head` is the start of `tail`. One merged span,
    // labelled by the earliest match; no byte of either survives.
    let head = b"QQQQQQQQWWWWWWWW".to_vec();
    let tail = b"WWWWWWWWEEEEEEEE".to_vec();
    let idx = index(&[("xx", &head), ("yy", &tail)]);
    let out = redact(b"QQQQQQQQWWWWWWWWEEEEEEEE!", &idx);
    assert_eq!(out.bytes, b"[redacted:xx]!");

    // The same value under two handles: the first handle in order wins, every
    // time.
    let shared = synthetic(4, 20);
    let idx = index(&[("zeta", &shared), ("eta", &shared)]);
    for _ in 0..3 {
        assert_eq!(redact(&shared, &idx).bytes, b"[redacted:eta]");
    }
    evidence("secret-redaction", "overlap-precedence", "deterministic");
}

#[test]
fn a_secret_at_any_offset_of_a_large_buffer_is_caught_in_one_pass() {
    // Internal read boundaries do not exist for the authority: it redacts the
    // whole result. Place the value across every 4 KiB boundary of 64 KiB.
    let secret = synthetic(5, 33);
    let idx = index(&[("chunked", &secret)]);
    for boundary in (4096..65536).step_by(4096) {
        let mut buffer = vec![b'.'; 65536];
        let start = boundary - 16;
        buffer[start..start + secret.len()].copy_from_slice(&secret);
        let out = redact(&buffer, &idx);
        assert!(!contains(&out.bytes, &secret), "across {boundary}");
    }
    evidence(
        "secret-redaction",
        "offset-sweep-64KiB",
        "caught-everywhere",
    );
}

#[test]
fn what_redaction_cannot_catch_is_not_claimed() {
    let secret = synthetic(6, 32);
    let idx = index(&[("limits", &secret)]);
    let hex: Vec<u8> = secret
        .iter()
        .flat_map(|b| format!("{b:02x}").into_bytes())
        .collect();
    let reversed: Vec<u8> = secret.iter().rev().copied().collect();
    // The value is 32 bytes; half of it is 16.
    let half = 16;
    for (case, transformed) in [
        ("hex", hex),
        ("reversed", reversed),
        ("first half of a split", secret[..half].to_vec()),
    ] {
        let out = redact(&transformed, &idx);
        assert!(
            !out.hits.contains_key(&HitKind::Handle(handle("limits"))),
            "{case}: a transformed secret is a documented limitation, not a catch"
        );
    }
    // Too short to index: the gap is stated, not hidden.
    let short = &synthetic(7, MIN_EXACT_BYTES - 1);
    let idx = index(&[("short", short)]);
    assert!(idx.is_empty());
    evidence("secret-redaction", "transformed-hex", "NOT-GUARANTEED");
    evidence("secret-redaction", "transformed-reversed", "NOT-GUARANTEED");
    evidence("secret-redaction", "transformed-split", "NOT-GUARANTEED");
    evidence(
        "secret-redaction",
        "short-value-not-indexed",
        "NOT-GUARANTEED",
    );
}

fn github_classic() -> Vec<u8> {
    cat(&[b"gh", b"p_", &synthetic(8, 36)])
}

/// One synthetic input per known shape, assembled here so no file holds a
/// whole token: the class, the input, and the bytes that must not survive
/// (empty where the placeholder alone is checked).
fn shaped_cases() -> Vec<(PatternClass, Vec<u8>, Vec<u8>)> {
    let aws_id = cat(&[b"AK", b"IA", &b"ABCDEFGHIJKLMNOP"[..]]);
    let jwt = cat(&[
        b"ey",
        b"J",
        &synthetic(9, 20),
        b".",
        &synthetic(10, 30),
        b".",
        &synthetic(11, 25),
    ]);
    let pem = cat(&[
        b"-----BEGIN ",
        b"RSA PRIVATE ",
        b"KEY-----\n",
        &synthetic(12, 64),
        b"\n-----END ",
        b"RSA PRIVATE ",
        b"KEY-----",
    ]);
    vec![
        (PatternClass::GitHub, github_classic(), github_classic()),
        (
            PatternClass::GitHub,
            cat(&[b"github", b"_pat_", &synthetic(13, 40)]),
            Vec::new(),
        ),
        (
            PatternClass::OpenAi,
            cat(&[b"s", b"k-proj-", &synthetic(14, 30), b"9"]),
            Vec::new(),
        ),
        (
            PatternClass::Slack,
            cat(&[b"xo", b"xb-", &synthetic(15, 24)]),
            Vec::new(),
        ),
        (
            PatternClass::Aws,
            cat(&[b"key ", &aws_id, b" end"]),
            aws_id.clone(),
        ),
        (PatternClass::Jwt, jwt.clone(), jwt),
        (
            PatternClass::PemPrivateKey,
            cat(&[b"x\n", &pem, b"\ny"]),
            pem,
        ),
        (
            PatternClass::Bearer,
            cat(&[b"Authorization: Bearer ", &synthetic(16, 40)]),
            synthetic(16, 40),
        ),
        (
            PatternClass::ConnectionString,
            b"postgres://app:Tr0ub4dor3xyz@db:5432/x".to_vec(),
            b"Tr0ub4dor3xyz".to_vec(),
        ),
        (
            PatternClass::Keyword,
            cat(&[b"api_key = \"", &synthetic(17, 24), b"\""]),
            synthetic(17, 24),
        ),
    ]
}

#[test]
fn known_shapes_are_redacted() {
    let empty = ExactIndex::empty();
    for (class, input, must_vanish) in shaped_cases() {
        let out = redact(&input, &empty);
        assert!(
            out.hits.contains_key(&HitKind::Pattern(class)),
            "{} not found",
            class.as_str()
        );
        assert!(
            contains(&out.bytes, b"[redacted:pattern]"),
            "{}",
            class.as_str()
        );
        if !must_vanish.is_empty() {
            assert!(
                !contains(&out.bytes, &must_vanish),
                "{} survived",
                class.as_str()
            );
        }
    }
    evidence("secret-redaction", "shape-github", "pattern-placeholder");
    evidence("secret-redaction", "shape-openai", "pattern-placeholder");
    evidence("secret-redaction", "shape-slack", "pattern-placeholder");
    evidence("secret-redaction", "shape-aws", "pattern-placeholder");
    evidence("secret-redaction", "shape-jwt", "pattern-placeholder");
    evidence(
        "secret-redaction",
        "shape-pem-private-key",
        "pattern-placeholder",
    );
    evidence("secret-redaction", "shape-bearer", "pattern-placeholder");
    evidence(
        "secret-redaction",
        "shape-connection-string",
        "pattern-placeholder",
    );
    evidence("secret-redaction", "shape-keyword", "pattern-placeholder");
}

#[test]
fn near_misses_of_known_shapes_are_kept() {
    let empty = ExactIndex::empty();
    for text in [
        &b"sk-learn is a library"[..],
        b"AKIA0123 is too short",
        b"tokenizer=gpt2 works",
        b"password=aaaaaaaaaaaaaaaaaaaaaaaaa",
        b"https://example.com/path@x",
        b"Bearer short",
        b"-----BEGIN PUBLIC KEY-----",
    ] {
        let out = redact(text, &empty);
        assert!(!out.redacted(), "{}", String::from_utf8_lossy(text));
        assert_eq!(out.bytes, text);
    }
    evidence("secret-redaction", "shape-near-misses", "kept");
}

#[test]
fn scanning_the_largest_output_against_a_full_index_is_bounded() {
    // 64 secrets of 64 distinct lengths over a 256 KiB output: O(output x
    // lengths), never O(output x secrets x length).
    let mut idx = ExactIndex::new().unwrap();
    for n in 0..64u64 {
        let len = 8 + usize::try_from(n).unwrap() * 3;
        idx.insert(
            &handle(&format!("s{n}")),
            &material(&synthetic(100 + n, len)),
        )
        .unwrap();
    }
    assert_eq!(idx.len(), 64);
    assert!(
        idx.insert(&handle("one-too-many"), &material(&synthetic(999, 30)))
            .is_err()
    );
    let output = synthetic(1000, 256 * 1024);
    let started = std::time::Instant::now();
    let out = redact(&output, &idx);
    let elapsed = started.elapsed();
    assert_eq!(out.bytes.len(), output.len());
    assert!(elapsed < std::time::Duration::from_secs(20), "{elapsed:?}");
    evidence("secret-redaction", "bound-64-secrets-256KiB", "bounded");
}
