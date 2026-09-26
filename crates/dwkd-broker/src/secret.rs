//! The broker's secret primitives (M4e, [ADR-0046]): reading a value from the
//! one descriptor the authority handed over, the mode A render, and the
//! redaction of an injected value from a launch's output.
//!
//! **The broker holds no long-lived key, and reaches no store.** Every value
//! it ever holds arrived as the read end of a pipe the authority filled and
//! closed before sending it, for one invocation, on one channel. It has no
//! code to open a keychain, an age file or `kernel.db` (TX013, TX025): there
//! is nothing here to hold a key with.
//!
//! | step | refusal |
//! |---|---|
//! | the descriptor is a FIFO, open read-only | `SECRET_DESCRIPTOR` |
//! | non-blocking reads reach end of file: the writer had closed | `SECRET_DESCRIPTOR` (a stalled pipe) |
//! | at least one byte, at most [`MAX_SECRET_BYTES`] | `SECRET_EMPTY`, `SECRET_TOO_LARGE` |
//! | the delivery's own bytes: no CR, LF or NUL in a header; no NUL in a variable | `SECRET_UNSAFE_BYTES` |
//!
//! Every buffer that holds a value is [`Zeroizing`], sized once so it never
//! reallocates (a reallocation would leave a copy behind in freed memory), and
//! dropped — zeroed — at the end of the exchange or, for a launch's output
//! redaction, when both of its streams reach end of file.
//!
//! [ADR-0046]: ../../../docs/adr/0046-m4e-secret-handles-backends-injection-and-redaction.md

use std::os::fd::OwnedFd;
use std::sync::Arc;

use dwk_proto::brokerp::{
    BrokerDone, BrokerRefusal, MAX_SECRET_BYTES, OutcomeResult, SecretEgressAuthorisation,
    SecretHandle,
};
use rustix::fs::{FileType, OFlags};
use rustix::io::Errno;
use zeroize::Zeroizing;

/// Read the value from `fd`: the read end of a pipe whose writer has closed.
///
/// # Errors
///
/// The refusal of the table above. The partial value, if any, is zeroed.
pub(crate) fn read_value(fd: &OwnedFd) -> Result<Zeroizing<Vec<u8>>, BrokerRefusal> {
    let flags = rustix::fs::fcntl_getfl(fd).map_err(|_| BrokerRefusal::SecretDescriptor)?;
    if flags.contains(OFlags::PATH) || flags & OFlags::RWMODE != OFlags::RDONLY {
        return Err(BrokerRefusal::SecretDescriptor);
    }
    let st = rustix::fs::fstat(fd).map_err(|_| BrokerRefusal::SecretDescriptor)?;
    if FileType::from_raw_mode(st.st_mode) != FileType::Fifo {
        return Err(BrokerRefusal::SecretDescriptor);
    }
    // Non-blocking: the authority wrote the whole value and closed its end
    // before sending this one, so the pipe holds the value and then end of
    // file. "Would block" means a writer is still open -- a stalled or
    // substituted pipe -- and nothing waits on it.
    rustix::fs::fcntl_setfl(fd, flags | OFlags::NONBLOCK)
        .map_err(|_| BrokerRefusal::SecretDescriptor)?;
    let mut value = Zeroizing::new(vec![0u8; MAX_SECRET_BYTES.saturating_add(1)]);
    let mut filled = 0usize;
    loop {
        if filled > MAX_SECRET_BYTES {
            return Err(BrokerRefusal::SecretTooLarge);
        }
        let Some(window) = value.get_mut(filled..) else {
            return Err(BrokerRefusal::SecretTooLarge);
        };
        match rustix::io::read(fd, window) {
            Ok(0) => break,
            Ok(n) => filled = filled.saturating_add(n),
            Err(Errno::INTR) => {}
            Err(_) => return Err(BrokerRefusal::SecretDescriptor),
        }
    }
    if filled == 0 {
        return Err(BrokerRefusal::SecretEmpty);
    }
    // Shortening keeps the capacity: the whole allocation is zeroed on drop.
    value.truncate(filled);
    Ok(value)
}

/// `broker.secret_egress`: read the value, refuse one that would break the
/// header, compose `name: prefix value`, and drop the composition — zeroed.
///
/// M4e has no egress consumer (`net.http` and the proxy are M5's): the render
/// is delivered to nothing. What it proves is the secret side of mode A —
/// the value reaches the broker only in this invocation's exchange, as a
/// descriptor, is checked for header safety here as well as in the
/// authority, and is gone when the exchange ends.
pub(crate) fn egress(authorisation: &SecretEgressAuthorisation, fd: &OwnedFd) -> OutcomeResult {
    let value = match read_value(fd) {
        Ok(value) => value,
        Err(refusal) => return OutcomeResult::Refused(refusal),
    };
    crate::crash::point("secret_after_read");
    if value.iter().any(|b| matches!(b, b'\r' | b'\n' | 0)) {
        return OutcomeResult::Refused(BrokerRefusal::SecretUnsafeBytes);
    }
    let name = authorisation.header_name.as_str().as_bytes();
    let prefix = authorisation
        .header_prefix
        .as_ref()
        .map_or(&b""[..], |p| p.as_str().as_bytes());
    let size = name.len() + 2 + prefix.len() + value.len();
    let mut header = Zeroizing::new(Vec::with_capacity(size));
    header.extend_from_slice(name);
    header.extend_from_slice(b": ");
    header.extend_from_slice(prefix);
    header.extend_from_slice(&value);
    // Nothing consumes it until M5. Both buffers are zeroed here.
    drop(header);
    drop(value);
    OutcomeResult::done(BrokerDone::secret_egress())
}

/// An injected value a launch's output is redacted of, for as long as its
/// streams are drained, and the placeholder that replaces it.
pub(crate) struct Needle {
    value: Zeroizing<Vec<u8>>,
    /// The Knuth–Morris–Pratt failure table: it encodes how the value
    /// overlaps itself, so it is zeroed with it.
    failure: Zeroizing<Vec<usize>>,
    placeholder: Vec<u8>,
}

impl core::fmt::Debug for Needle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Needle(..)")
    }
}

impl Needle {
    /// The needle for `value`, reported as `[redacted:<handle>]`. `None` for
    /// an empty value.
    pub(crate) fn new(value: Zeroizing<Vec<u8>>, handle: &SecretHandle) -> Option<Arc<Self>> {
        if value.is_empty() {
            return None;
        }
        let mut failure = Zeroizing::new(vec![0usize; value.len()]);
        let mut k = 0usize;
        for i in 1..value.len() {
            while k > 0 && value.get(i) != value.get(k) {
                k = failure.get(k - 1).copied().unwrap_or(0);
            }
            if value.get(i) == value.get(k) {
                k += 1;
            }
            if let Some(slot) = failure.get_mut(i) {
                *slot = k;
            }
        }
        Some(Arc::new(Self {
            value,
            failure,
            placeholder: format!("[redacted:{}]", handle.as_str()).into_bytes(),
        }))
    }

    /// The value. Crate-internal, for the one launch that delivers it.
    pub(crate) fn value(&self) -> &[u8] {
        &self.value
    }
}

/// The streaming state of one redacted stream: how much of the value the
/// most recent bytes match. The matched bytes are never stored — they are
/// the value's own first `matched` bytes — so no partial copy accumulates.
#[derive(Debug)]
pub(crate) struct Redactor {
    needle: Arc<Needle>,
    matched: usize,
}

impl Redactor {
    /// A redactor for `needle`.
    pub(crate) const fn new(needle: Arc<Needle>) -> Self {
        Self { needle, matched: 0 }
    }

    /// Feed `input`; `emit` receives every byte that is certainly not part of
    /// an occurrence, and the placeholder for each occurrence, in order.
    /// Occurrences do not overlap: after one, matching starts afresh. An
    /// occurrence split across calls is found.
    pub(crate) fn feed(&mut self, input: &[u8], emit: &mut impl FnMut(&[u8])) {
        let value = self.needle.value.as_slice();
        for &byte in input {
            let before = self.matched;
            let mut q = self.matched;
            while q > 0 && value.get(q) != Some(&byte) {
                q = self.needle.failure.get(q - 1).copied().unwrap_or(0);
            }
            if value.get(q) == Some(&byte) {
                q += 1;
            }
            // The window was the value's first `before` bytes plus `byte`; it
            // is now its first `q`. What fell out of it is certainly output.
            let released = before + 1 - q.min(before + 1);
            if q == value.len() {
                // A whole occurrence: nothing of it is released.
                emit(&self.needle.placeholder);
                self.matched = 0;
                continue;
            }
            if released > 0 {
                let old: &[u8] = value.get(..before).unwrap_or_default();
                // The released bytes are the first `released` of `old ++ byte`.
                let from_old = released.min(old.len());
                emit(old.get(..from_old).unwrap_or_default());
                if released > old.len() {
                    emit(&[byte]);
                }
            }
            self.matched = q;
        }
    }

    /// End of the stream: the bytes still held — a prefix of the value that
    /// never completed — are released as output. A value cut short is not the
    /// value; it is not redacted (the documented limitation of exact
    /// matching), and it is at most one byte shorter than it.
    pub(crate) fn finish(&mut self, emit: &mut impl FnMut(&[u8])) {
        let held = self.matched;
        self.matched = 0;
        emit(self.needle.value.get(..held).unwrap_or_default());
    }
}

#[cfg(test)]
mod tests {
    use super::{Needle, Redactor};
    use dwk_proto::brokerp::SecretHandle;
    use zeroize::Zeroizing;

    fn redact(value: &[u8], chunks: &[&[u8]]) -> Vec<u8> {
        let handle = SecretHandle::new("h").unwrap_or_else(|| unreachable!());
        let needle =
            Needle::new(Zeroizing::new(value.to_vec()), &handle).unwrap_or_else(|| unreachable!());
        let mut redactor = Redactor::new(needle);
        let mut out = Vec::new();
        for chunk in chunks {
            redactor.feed(chunk, &mut |b| out.extend_from_slice(b));
        }
        redactor.finish(&mut |b| out.extend_from_slice(b));
        out
    }

    #[test]
    fn every_occurrence_is_replaced_whatever_the_chunking() {
        let value = b"s3cr3t-v4lue-0123456789";
        let mut text = b"head ".to_vec();
        text.extend_from_slice(value);
        text.extend_from_slice(b" mid ");
        text.extend_from_slice(value);
        text.extend_from_slice(value);
        text.extend_from_slice(b" tail");
        let want = b"head [redacted:h] mid [redacted:h][redacted:h] tail".to_vec();
        // Every split point, into two chunks and into single bytes.
        for at in 0..=text.len() {
            let (a, b) = text.split_at(at);
            assert_eq!(redact(value, &[a, b]), want, "split at {at}");
        }
        let bytes: Vec<&[u8]> = text.chunks(1).collect();
        assert_eq!(redact(value, &bytes), want);
    }

    #[test]
    fn self_overlapping_values_and_near_misses_are_exact() {
        // A value that overlaps itself: "aab" in "aaab" occurs once, at 1.
        assert_eq!(redact(b"aab", &[b"aaab"]), b"a[redacted:h]".to_vec());
        assert_eq!(
            redact(b"abab", &[b"abababab"]),
            b"[redacted:h][redacted:h]".to_vec()
        );
        // A prefix that never completes is released unchanged.
        assert_eq!(redact(b"secret", &[b"xsecre"]), b"xsecre".to_vec());
        assert_eq!(
            redact(b"secret", &[b"secrexsecret!"]),
            b"secrex[redacted:h]!".to_vec()
        );
        // Binary around it.
        assert_eq!(
            redact(b"\x00\xffkey\x01", &[b"\x10\x00\xffkey\x01\x02"]),
            b"\x10[redacted:h]\x02".to_vec()
        );
        // Nothing in, nothing out.
        assert!(redact(b"abc", &[]).is_empty());
    }
}
