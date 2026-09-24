//! Domain-separated SHA-256.
//!
//! Every content-derived identity the authority computes — a policy revision,
//! an `AdmitRun` request digest, an audit record hash, a recorded grant — is a
//! SHA-256 over a framed input that begins with a **domain string** naming what
//! is being hashed. Equal bytes hashed for different purposes therefore produce
//! different digests, and a value computed as one kind of identity can never be
//! presented as another.
//!
//! # Framing
//!
//! ```text
//! H = SHA-256( domain || 0x00 || field_1 || field_2 || ... )
//!
//! field := u64be(len(bytes)) || bytes       -- a byte string
//!        | u64be(value)                      -- an integer
//! ```
//!
//! The domain is ASCII with no NUL, so the `0x00` terminates it unambiguously;
//! every variable-length field is length-prefixed, so no two different field
//! sequences can frame to the same bytes. There is no concatenation of
//! unprefixed strings anywhere, which is the ambiguity (`"ab" + "c"` vs
//! `"a" + "bc"`) framing exists to remove.
//!
//! No homemade cryptography: the compression function is `sha2`'s, which is
//! the `RustCrypto` implementation ADR-0035 accepted. This file only frames.

use core::fmt;

use sha2::{Digest as _, Sha256};

/// `policy_revision`: the operator's policy source set, in composition order.
pub(crate) const POLICY_REVISION: &str = "direwolf.policy.revision.v1";
/// The canonical `AdmitRun` request an idempotency key is bound to. `v2`
/// since ADR-0040 took `epoch` out of the bound request, so no digest computed
/// under the old definition can ever equal one computed under this one.
pub(crate) const ADMIT_REQUEST: &str = "direwolf.dwkp.admit_run.request.v2";
/// One audit record, chained to its predecessor.
pub(crate) const AUDIT_RECORD: &str = "direwolf.audit.record.v1";
/// The logical `RunGrant` recorded for an admission.
pub(crate) const RUN_GRANT: &str = "direwolf.run.grant.v1";
/// An agent profile's kernel-owned record.
pub(crate) const AGENT_PROFILE: &str = "direwolf.config.agent_profile.v1";
/// A skill's kernel-owned record.
pub(crate) const SKILL: &str = "direwolf.config.skill.v1";
/// A mode's capability ceiling.
pub(crate) const CEILING: &str = "direwolf.config.ceiling.v1";
/// A store's own identity, fixed at creation.
pub(crate) const STORE_ID: &str = "direwolf.store.id.v1";
/// The bytes an `fs.read` returned, recorded in its outcome so an auditor can
/// check what was delivered without the audit log holding the content (M4b).
pub(crate) const TOOL_CONTENT: &str = "direwolf.tool.fs_read.content.v1";

/// Every domain, for the test that they are pairwise distinct.
#[cfg(test)]
const ALL_DOMAINS: [&str; 9] = [
    POLICY_REVISION,
    ADMIT_REQUEST,
    AUDIT_RECORD,
    RUN_GRANT,
    AGENT_PROFILE,
    SKILL,
    CEILING,
    STORE_ID,
    TOOL_CONTENT,
];

/// A full 256-bit SHA-256 value. Never truncated.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sha256Hash([u8; 32]);

impl Sha256Hash {
    /// Thirty-two zero bytes: the `prev` of the first audit record.
    pub const ZERO: Self = Self([0; 32]);

    /// The raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hexadecimal, 64 characters.
    #[must_use]
    pub fn to_hex(&self) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(64);
        for byte in self.0 {
            for nibble in [byte >> 4, byte & 0x0f] {
                let digit = DIGITS.get(usize::from(nibble)).copied().unwrap_or(b'0');
                out.push(char::from(digit));
            }
        }
        out
    }

    /// Parse exactly 64 lowercase hexadecimal characters. Uppercase is refused:
    /// one value, one spelling, so a stored hash compares as text.
    #[must_use]
    pub fn from_hex(text: &str) -> Option<Self> {
        if text.len() != 64 {
            return None;
        }
        let mut out = [0u8; 32];
        let digits = text.as_bytes();
        for (slot, pair) in out.iter_mut().zip(digits.chunks(2)) {
            let [high, low] = pair else { return None };
            *slot = (nibble(*high)? << 4) | nibble(*low)?;
        }
        Some(Self(out))
    }
}

fn nibble(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    }
}

impl fmt::Debug for Sha256Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sha256Hash({})", self.to_hex())
    }
}

impl fmt::Display for Sha256Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// A framed SHA-256 computation under one domain.
#[derive(Debug, Clone)]
pub(crate) struct DomainHash(Sha256);

impl DomainHash {
    /// Begin a hash in `domain`.
    pub(crate) fn new(domain: &'static str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(domain.as_bytes());
        hasher.update([0u8]);
        Self(hasher)
    }

    /// Append a length-prefixed byte string.
    #[must_use]
    pub(crate) fn bytes(mut self, bytes: &[u8]) -> Self {
        let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        self.0.update(len.to_be_bytes());
        self.0.update(bytes);
        self
    }

    /// Append a length-prefixed UTF-8 string.
    #[must_use]
    pub(crate) fn text(self, text: &str) -> Self {
        self.bytes(text.as_bytes())
    }

    /// Append a fixed-width integer.
    #[must_use]
    pub(crate) fn int(mut self, value: u64) -> Self {
        self.0.update(value.to_be_bytes());
        self
    }

    /// Finish.
    pub(crate) fn finish(self) -> Sha256Hash {
        let output = self.0.finalize();
        let mut bytes = [0u8; 32];
        for (dst, src) in bytes.iter_mut().zip(output.iter()) {
            *dst = *src;
        }
        Sha256Hash(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::{ALL_DOMAINS, DomainHash, Sha256Hash};

    #[test]
    fn the_implementation_is_sha256() {
        // FIPS 180-2 appendix B.1, "abc" -- through the raw algorithm, to show
        // this is SHA-256 and not something that merely looks like it.
        use sha2::{Digest as _, Sha256};
        let raw = Sha256::digest(b"abc");
        let mut bytes = [0u8; 32];
        for (dst, src) in bytes.iter_mut().zip(raw.iter()) {
            *dst = *src;
        }
        assert_eq!(
            Sha256Hash(bytes).to_hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn the_same_bytes_in_different_domains_are_different_digests() {
        let digests: Vec<Sha256Hash> = ALL_DOMAINS
            .iter()
            .map(|domain| DomainHash::new(domain).bytes(b"same").finish())
            .collect();
        for (i, a) in digests.iter().enumerate() {
            for b in digests.iter().skip(i + 1) {
                assert_ne!(a, b, "two domains collided");
            }
        }
        let mut sorted = ALL_DOMAINS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), ALL_DOMAINS.len(), "domain strings repeat");
    }

    #[test]
    fn framing_is_unambiguous() {
        // "ab" + "c" and "a" + "bc" concatenate to the same bytes and must not
        // hash to the same value.
        let one = DomainHash::new(super::RUN_GRANT)
            .text("ab")
            .text("c")
            .finish();
        let two = DomainHash::new(super::RUN_GRANT)
            .text("a")
            .text("bc")
            .finish();
        assert_ne!(one, two);
    }

    #[test]
    fn hex_round_trips_and_has_one_spelling() {
        let hash = DomainHash::new(super::STORE_ID).int(7).finish();
        let hex = hash.to_hex();
        assert_eq!(hex.len(), 64);
        assert_eq!(Sha256Hash::from_hex(&hex), Some(hash));
        assert_eq!(Sha256Hash::from_hex(&hex.to_uppercase()), None);
        assert_eq!(
            Sha256Hash::from_hex(hex.get(..63).unwrap_or_default()),
            None
        );
        assert_eq!(Sha256Hash::from_hex(&format!("{hex}0")), None);
        assert_eq!(Sha256Hash::from_hex(&"g".repeat(64)), None);
        assert_eq!(Sha256Hash::ZERO.to_hex(), "0".repeat(64));
    }
}
