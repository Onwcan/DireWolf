//! The exact-value index (ADR-0046 §21): which live secrets an output
//! contains, **without keeping their plaintext**.
//!
//! For each secret the index holds its handle, its length, a Rabin–Karp
//! rolling hash of its bytes under a random base modulo the Mersenne prime
//! 2^61 − 1, and an HMAC-SHA-256 tag under a random per-process key. A scan
//! rolls a window of each indexed length over the output; a window whose
//! rolling hash matches is confirmed by recomputing its HMAC tag (a false
//! candidate has probability about 2^-61 per window). Nothing is persisted:
//! the key and every tag die with the process, so no stored verifier becomes
//! an offline dictionary target.
//!
//! What it still is: an equality oracle **inside the authority's memory**. An
//! attacker who can read that memory has the key and the tags and can test
//! guesses against a low-entropy secret — and could read the backend anyway.
//! ADR-0046 §21 records it.
//!
//! Bounds: at most [`MAX_ENTRIES`] secrets (so at most that many distinct
//! lengths), each at least [`MIN_EXACT_BYTES`] and at most
//! [`MAX_SECRET_BYTES`] long; a scan is `O(output × distinct lengths)` plus one
//! HMAC per candidate.

use hmac::{Hmac, KeyInit as _, Mac as _};
use sha2::Sha256;

use super::{HitKind, Span};
use crate::secret::material::{MAX_SECRET_BYTES, SecretMaterial};
use crate::secret::metadata::SecretHandle;

/// The most secrets indexed: the most a configuration may hold.
pub const MAX_ENTRIES: usize = crate::secret::metadata::MAX_SECRETS;
/// The shortest value indexed. A shorter one would redact ordinary text; the
/// known-shape layer still applies to it, and ADR-0046 §21 states the gap.
pub const MIN_EXACT_BYTES: usize = 8;

const P: u64 = (1 << 61) - 1;

fn mul(a: u64, b: u64) -> u64 {
    let product = u128::from(a) * u128::from(b);
    // `product < 2^122`; the Mersenne reduction folds the high bits in.
    let low = u64::try_from(product & u128::from(P)).unwrap_or(0);
    let high = u64::try_from(product >> 61).unwrap_or(0);
    let folded = low + high;
    if folded >= P { folded - P } else { folded }
}

fn add(a: u64, b: u64) -> u64 {
    let sum = a + b;
    if sum >= P { sum - P } else { sum }
}

fn sub(a: u64, b: u64) -> u64 {
    if a >= b { a - b } else { a + P - b }
}

#[derive(Debug)]
struct Entry {
    handle: SecretHandle,
    length: usize,
    rolling: u64,
    tag: [u8; 32],
}

/// The in-memory exact-value index.
pub struct ExactIndex {
    key: zeroize::Zeroizing<[u8; 32]>,
    base: u64,
    entries: Vec<Entry>,
}

impl core::fmt::Debug for ExactIndex {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ExactIndex")
            .field("entries", &self.entries.len())
            .finish_non_exhaustive()
    }
}

/// Why an index could not be built or grown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexError {
    /// The operating system's random source failed.
    NoRandomness,
    /// [`MAX_ENTRIES`] secrets are indexed already.
    Full,
}

impl ExactIndex {
    /// An empty index under a fresh random key and base.
    ///
    /// # Errors
    ///
    /// [`IndexError::NoRandomness`] when the OS random source fails; there is
    /// no fallback to a predictable key.
    pub fn new() -> Result<Self, IndexError> {
        let mut key = zeroize::Zeroizing::new([0u8; 32]);
        getrandom::getrandom(key.as_mut()).map_err(|_| IndexError::NoRandomness)?;
        let mut base = [0u8; 8];
        getrandom::getrandom(&mut base).map_err(|_| IndexError::NoRandomness)?;
        // A base in [256, P): larger than any byte, so distinct windows do not
        // collide by construction of small digits.
        let base = u64::from_le_bytes(base) % (P - 256) + 256;
        Ok(Self {
            key,
            base,
            entries: Vec::new(),
        })
    }

    /// An empty index that matches nothing and needs no randomness: for a
    /// store with no secrets configured, and for tests of the other layer.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            key: zeroize::Zeroizing::new([0u8; 32]),
            base: 257,
            entries: Vec::new(),
        }
    }

    fn tag(&self, bytes: &[u8]) -> [u8; 32] {
        let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(self.key.as_ref()) else {
            return [0u8; 32];
        };
        mac.update(bytes);
        mac.finalize().into_bytes().into()
    }

    fn rolling(&self, bytes: &[u8]) -> u64 {
        bytes
            .iter()
            .fold(0u64, |h, b| add(mul(h, self.base), u64::from(*b)))
    }

    /// Index (or re-index) `handle`'s value. The plaintext is read once and
    /// not kept; a value shorter than [`MIN_EXACT_BYTES`] is not indexed.
    ///
    /// # Errors
    ///
    /// [`IndexError::Full`] at [`MAX_ENTRIES`].
    pub fn insert(
        &mut self,
        handle: &SecretHandle,
        value: &SecretMaterial,
    ) -> Result<(), IndexError> {
        self.remove(handle);
        let bytes = value.expose();
        if bytes.len() < MIN_EXACT_BYTES || bytes.len() > MAX_SECRET_BYTES {
            return Ok(());
        }
        if self.entries.len() >= MAX_ENTRIES {
            return Err(IndexError::Full);
        }
        self.entries.push(Entry {
            handle: handle.clone(),
            length: bytes.len(),
            rolling: self.rolling(bytes),
            tag: self.tag(bytes),
        });
        Ok(())
    }

    /// Forget `handle`.
    pub fn remove(&mut self, handle: &SecretHandle) {
        self.entries.retain(|e| &e.handle != handle);
    }

    /// Whether `handle` is indexed.
    #[must_use]
    pub fn contains(&self, handle: &SecretHandle) -> bool {
        self.entries.iter().any(|e| &e.handle == handle)
    }

    /// How many secrets are indexed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing is indexed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Every exact occurrence of an indexed value in `input`.
    pub(crate) fn find(&self, input: &[u8]) -> Vec<Span> {
        let mut spans = Vec::new();
        let mut lengths: Vec<usize> = self.entries.iter().map(|e| e.length).collect();
        lengths.sort_unstable();
        lengths.dedup();
        for length in lengths {
            if length == 0 || input.len() < length {
                continue;
            }
            // b^(length-1): the weight of the byte leaving the window.
            let mut high = 1u64;
            for _ in 1..length {
                high = mul(high, self.base);
            }
            let Some(first) = input.get(..length) else {
                continue;
            };
            let mut hash = self.rolling(first);
            let mut start = 0usize;
            loop {
                for entry in self
                    .entries
                    .iter()
                    .filter(|e| e.length == length && e.rolling == hash)
                {
                    let end = start + length;
                    let Some(window) = input.get(start..end) else {
                        continue;
                    };
                    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(self.key.as_ref()) else {
                        continue;
                    };
                    mac.update(window);
                    if mac.verify_slice(&entry.tag).is_ok() {
                        spans.push(Span {
                            start,
                            end,
                            kind: HitKind::Handle(entry.handle.clone()),
                        });
                    }
                }
                let (Some(outgoing), Some(incoming)) =
                    (input.get(start), input.get(start + length))
                else {
                    break;
                };
                hash = add(
                    mul(sub(hash, mul(u64::from(*outgoing), high)), self.base),
                    u64::from(*incoming),
                );
                start += 1;
            }
        }
        spans
    }
}
