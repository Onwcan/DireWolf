//! Stable-Rust mutation fuzzing over the policy-loader fuzz targets.
//!
//! **Not** coverage-guided fuzzing. A deterministic mutation loop: seeds from
//! the three shipped packs and a small hand-written corpus, mutated by bit
//! flips, splices, truncations, duplications and insertions of
//! TOML-significant tokens. It exists so that every `cargo test` exercises the
//! loader's invariants on stable Rust, on every platform, including machines
//! where libFuzzer is unavailable.
//!
//! Coverage-guided fuzzing is `cargo fuzz` in `fuzz/` (nightly, scheduled CI).
//! Results from the two are reported separately and never conflated — the same
//! rule `dwk-proto`'s harness states, for the same reason.
//!
//! Configuration (environment), matching `dwk-proto`'s:
//!
//! * `DWK_FUZZ_ITERATIONS` — executions per target (default 3 000).
//! * `DWK_FUZZ_SECONDS` — if set, run each target for this long instead.
//! * `DWK_FUZZ_SEED` — PRNG seed (default fixed, so a CI failure reproduces).
//! * `DWK_FUZZ_TARGET` — run only this target.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

// The authority links `toml` for the policy loader. This test binary does not
// use it, and `unused_crate_dependencies` sees the manifest edge rather than
// the target that consumes it. Acknowledged rather than silenced with an
// `#[allow]`, so the lint stays meaningful for the binaries that do use it.
use toml as _;
// Likewise the M3d state layer's storage and wire dependencies.
use dwk_proto as _;
use rusqlite as _;
use sha2 as _;

// As above, for the property-test dev-dependency.
use proptest as _;

mod fuzz_targets;

use std::time::{Duration, Instant};

use dwkd_authority::policy::profiles;

/// xorshift64*, so a failing run reproduces from its seed alone.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            usize::try_from(self.next() % u64::try_from(n).unwrap()).unwrap()
        }
    }
}

/// Tokens a TOML mutator should reach for, so mutants stay near the grammar
/// instead of becoming random bytes that fail at the first character.
const TOKENS: &[&[u8]] = &[
    b"[[rule]]",
    b"[[postcondition]]",
    b"[meta]",
    b"schema_version = 1",
    b"id = \"default\"",
    b"effect = \"ALLOW\"",
    b"effect = \"DENY\"",
    b"effect = \"REQUIRE_APPROVAL\"",
    b"reason = \"NO_MATCHING_RULE\"",
    b"when.verb = ",
    b"when.path_under = ",
    b"when.provisional_effect = ",
    b"unless.standing_grant = true",
    b"obligations = ",
    b"approval.ttl = \"1h\"",
    b"extends = \"base\"",
    b"[",
    b"]",
    b"{",
    b"}",
    b"\"",
    b"=",
    b"\n",
    b".",
    b",",
    b"#",
    b"0",
    b"-1",
    b"1.5",
    b"18446744073709551616",
    b"true",
    b"false",
];

/// Seeds: the three shipped packs, plus inputs that exercise the refusals.
fn seeds() -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = profiles::ALL
        .iter()
        .map(|(_, text)| text.as_bytes().to_vec())
        .collect();
    for extra in [
        "",
        "schema_version = 1\n",
        "schema_version = 1\n[meta]\nname = \"t\"\n[[rule]]\nid = \"default\"\neffect = \"DENY\"\nreason = \"NO_MATCHING_RULE\"\n",
        "schema_version = 1\n[meta]\nname = \"c\"\nextends = \"b\"\n[[rule]]\nid = \"x\"\neffect = \"DENY\"\nreason = \"PROFILE_CEILING\"\nwhen.verb = \"memory.read\"\n",
        "schema_version = 2\n",
        "[[rule]]\n[[rule]]\n[[rule]]\n",
    ] {
        out.push(extra.as_bytes().to_vec());
    }
    out
}

/// One mutation, in place.
fn mutate(rng: &mut Rng, buffer: &mut Vec<u8>) {
    match rng.below(6) {
        // Bit flip.
        0 if !buffer.is_empty() => {
            let index = rng.below(buffer.len());
            buffer[index] ^= 1u8 << rng.below(8);
        }
        // Truncate.
        1 if !buffer.is_empty() => buffer.truncate(rng.below(buffer.len())),
        // Duplicate a span.
        2 if !buffer.is_empty() => {
            let start = rng.below(buffer.len());
            let len = rng.below(buffer.len() - start).min(512);
            let span: Vec<u8> = buffer[start..start + len].to_vec();
            let at = rng.below(buffer.len());
            buffer.splice(at..at, span);
        }
        // Insert a grammar token.
        3 => {
            let token = TOKENS[rng.below(TOKENS.len())];
            let at = rng.below(buffer.len().saturating_add(1));
            buffer.splice(at..at, token.iter().copied());
        }
        // Delete a span.
        4 if !buffer.is_empty() => {
            let start = rng.below(buffer.len());
            let len = rng.below(buffer.len() - start).min(512);
            buffer.drain(start..start + len);
        }
        // Overwrite a byte with a grammar-significant one.
        _ if !buffer.is_empty() => {
            let index = rng.below(buffer.len());
            let token = TOKENS[rng.below(TOKENS.len())];
            buffer[index] = token[0];
        }
        _ => buffer.push(b'\n'),
    }
    // Keep mutants bounded, so the loop stays fast and the size refusal is
    // exercised by the deliberate case below rather than by every mutant.
    buffer.truncate(64 * 1024);
}

fn budget() -> (usize, Option<Duration>) {
    let iterations = std::env::var("DWK_FUZZ_ITERATIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3_000);
    let seconds = std::env::var("DWK_FUZZ_SECONDS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_secs);
    (iterations, seconds)
}

/// The default seed. Fixed, so an unseeded CI failure reproduces exactly.
const DEFAULT_SEED: u64 = 0x5eed_d15e_a5ed_0f01;

fn seed() -> u64 {
    std::env::var("DWK_FUZZ_SEED")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_SEED)
}

fn run(name: &str, body: fn(&[u8])) {
    if std::env::var("DWK_FUZZ_TARGET").is_ok_and(|only| only != name) {
        return;
    }
    let (iterations, seconds) = budget();
    let mut rng = Rng(seed()
        ^ u64::try_from(name.len())
            .unwrap_or(0)
            .wrapping_mul(0x9E37_79B9));
    let corpus = seeds();
    let started = Instant::now();
    let mut executions = 0usize;

    while executions < iterations {
        if seconds.is_some_and(|limit| started.elapsed() >= limit) {
            break;
        }
        let mut buffer = corpus[rng.below(corpus.len())].clone();
        for _ in 0..=rng.below(4) {
            mutate(&mut rng, &mut buffer);
        }
        body(&buffer);
        executions += 1;
    }

    // One deliberate oversized input, so the pre-parse bound is exercised
    // rather than merely present. Cheap because it is refused by length.
    let huge = vec![b'x'; 300 * 1024];
    body(&huge);

    println!(
        "fuzz_smoke[{name}]: {executions} executions in {:?}",
        started.elapsed()
    );
}

#[test]
fn policy_loader_never_panics_and_never_accepts_a_policy_without_a_default() {
    run("policy_loader", fuzz_targets::policy_loader);
}

#[test]
fn policy_evaluation_is_total_over_every_accepted_policy() {
    run("policy_evaluate", fuzz_targets::policy_evaluate);
}
