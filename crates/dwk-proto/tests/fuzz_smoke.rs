//! Stable-Rust mutation fuzzing over the shared fuzz targets.
//!
//! This is **not** coverage-guided fuzzing. It is a deterministic mutation loop:
//! seeds from the golden vectors, mutated by bit flips, splices, truncations,
//! duplications and insertions of JSON-significant tokens. It exists so that
//! every `cargo test` exercises the fuzz invariants on stable Rust, on every
//! platform, including machines where libFuzzer is unavailable.
//!
//! Coverage-guided fuzzing is `cargo fuzz` in `fuzz/` (nightly; scheduled CI).
//! Results from the two are reported separately and never conflated.
//!
//! Configuration (environment):
//!
//! * `DWK_FUZZ_ITERATIONS` — executions per target (default 5 000).
//! * `DWK_FUZZ_SECONDS` — if set, run each target for this long instead.
//! * `DWK_FUZZ_SEED` — PRNG seed (default fixed, so CI failures reproduce).
//! * `DWK_FUZZ_TARGET` — run only this target.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

mod common;
mod fuzz_targets;

use std::time::{Duration, Instant};

use common::{input_bytes, load_vectors};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
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

const TOKENS: &[&[u8]] = &[
    b"{",
    b"}",
    b"[",
    b"]",
    b"\"",
    b":",
    b",",
    b"\\",
    b"\\u",
    b"d800",
    b"0",
    b"-0",
    b"1e400",
    b"9007199254740992",
    b"null",
    b"true",
    b"\x00",
    b"\xff",
    b"\xc3\xa9",
    b"e\xcc\x81",
    b"\"v\":2",
    b"\"schema\":\"direwolf.tool.invoke\"",
    b"\"x_extra\":1",
    b"\"epoch\":0",
    b"\"payload\":null",
    b"\x00\x00\x00\x02\x01{}",
    b"\x00\x10\x00\x01\x01",
    b"\xff\xff\xff\xff\x01",
];

fn seeds() -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for file in ["valid.json", "invalid.json"] {
        for v in load_vectors(file)["vectors"].as_array().unwrap() {
            let bytes = input_bytes(v);
            if let Some(hex) = v.get("frame_hex").and_then(|h| h.as_str()) {
                out.push(common::hex_decode(hex));
            }
            out.push(bytes);
        }
    }
    out
}

fn mutate(rng: &mut Rng, seeds: &[Vec<u8>], input: &[u8]) -> Vec<u8> {
    let mut data = input.to_vec();
    for _ in 0..=rng.below(4) {
        match rng.below(7) {
            0 if !data.is_empty() => {
                let i = rng.below(data.len());
                data[i] ^= 1 << rng.below(8);
            }
            1 if !data.is_empty() => {
                let i = rng.below(data.len());
                data[i] = u8::try_from(rng.next() & 0xff).unwrap();
            }
            2 => {
                let token = TOKENS[rng.below(TOKENS.len())];
                let at = rng.below(data.len() + 1);
                data.splice(at..at, token.iter().copied());
            }
            3 if !data.is_empty() => {
                let start = rng.below(data.len());
                let end = start + rng.below(data.len() - start + 1);
                data.drain(start..end);
            }
            4 if !data.is_empty() => {
                let start = rng.below(data.len());
                let end = start + rng.below((data.len() - start).min(64) + 1);
                let copy = data[start..end].to_vec();
                let at = rng.below(data.len() + 1);
                data.splice(at..at, copy);
            }
            5 => {
                let other = &seeds[rng.below(seeds.len())];
                let cut_a = rng.below(data.len() + 1);
                let cut_b = rng.below(other.len() + 1);
                data.truncate(cut_a);
                data.extend_from_slice(&other[cut_b..]);
            }
            _ => data.truncate(rng.below(data.len() + 1)),
        }
    }
    data
}

#[test]
fn fuzz_targets_hold_under_mutation() {
    let seeds = seeds();
    assert!(seeds.len() > 100);
    let iterations: u64 = std::env::var("DWK_FUZZ_ITERATIONS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5_000);
    let budget = std::env::var("DWK_FUZZ_SECONDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .map(Duration::from_secs);
    let seed: u64 = std::env::var("DWK_FUZZ_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0x5EED_D1EC_0FFE);
    let only = std::env::var("DWK_FUZZ_TARGET").ok();

    for (name, target) in fuzz_targets::TARGETS {
        if only.as_deref().is_some_and(|o| o != *name) {
            continue;
        }
        let mut rng = Rng(seed
            ^ u64::try_from(name.len())
                .unwrap()
                .wrapping_mul(0x9e37_79b9_7f4a_7c15));
        // Every seed unmutated first: the vectors themselves are the first corpus.
        for s in &seeds {
            target(s);
        }
        let started = Instant::now();
        let mut executions: u64 = 0;
        let mut corpus = seeds.clone();
        loop {
            let done = match budget {
                Some(limit) => started.elapsed() >= limit,
                None => executions >= iterations,
            };
            if done {
                break;
            }
            let base = &corpus[rng.below(corpus.len())];
            let input = mutate(&mut rng, &seeds, base);
            target(&input);
            // Keep a bounded, rotating corpus so mutations compound.
            if corpus.len() < 4096 {
                corpus.push(input);
            } else {
                let slot = rng.below(corpus.len());
                corpus[slot] = input;
            }
            executions += 1;
        }
        println!(
            "fuzz-smoke target={name} executions={executions} elapsed_ms={} seeds={} seed={seed}",
            started.elapsed().as_millis(),
            seeds.len()
        );
    }
}
