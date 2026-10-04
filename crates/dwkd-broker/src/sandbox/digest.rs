//! The probe's digest, from outside (M5a, ADR-0047 §8): the bytes the
//! runtime copies out of the container's own root — the file the probe runs
//! from — hashed and compared with the digest the authority pinned. A
//! substituted, patched or truncated probe fails here, before it is run and
//! before anything it could print is read.
//!
//! The runtime hands the file over as a tar stream. Only what this needs of
//! the format is read: 512-byte headers with a valid checksum, extended
//! headers skipped, and exactly one regular file named like the probe. A
//! symbolic link, a directory, a second file or a size past the bound is a
//! `FAIL`; a stream that is not a tar archive is `UNOBSERVABLE`.

use dwk_proto::brokerp::sandbox::Verdict;
use sha2::{Digest as _, Sha256};

/// The largest probe hashed. The real one is a little over a megabyte.
pub(crate) const MAX_PROBE_BYTES: usize = 64 << 20;

/// The most tar bytes read: the probe, its headers and padding.
pub(crate) const MAX_ARCHIVE_BYTES: usize = MAX_PROBE_BYTES + (64 << 10);

const BLOCK: usize = 512;

/// The name the runtime gives the probe's entry: the path's last component.
const PROBE_NAME: &str = "sandbox-probe";

/// The name it gives the relay's (M5b, ADR-0048).
const RELAY_NAME: &str = "sandbox-relay";

/// Where a header's fields are.
struct Header<'a>(&'a [u8]);

impl Header<'_> {
    fn field(&self, from: usize, to: usize) -> Option<&[u8]> {
        let bytes = self.0.get(from..to)?;
        let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
        bytes.get(..end)
    }

    fn octal(&self, from: usize, to: usize) -> Option<usize> {
        let field = self.0.get(from..to)?;
        // Base-256 sizes (the high bit set) are never needed for a bounded
        // file, and are refused.
        if field.first().is_some_and(|b| b & 0x80 != 0) {
            return None;
        }
        let text = core::str::from_utf8(self.field(from, to)?).ok()?;
        let text = text.trim_matches(|c| c == ' ' || c == '\0');
        if text.is_empty() {
            return Some(0);
        }
        usize::from_str_radix(text, 8).ok()
    }

    fn checksum_ok(&self) -> bool {
        let Some(stored) = self.octal(148, 156) else {
            return false;
        };
        let mut sum = 0usize;
        for (index, byte) in self.0.iter().enumerate() {
            let byte = if (148..156).contains(&index) {
                b' '
            } else {
                *byte
            };
            sum = sum.saturating_add(usize::from(byte));
        }
        sum == stored
    }

    fn name(&self) -> Option<String> {
        let name = core::str::from_utf8(self.field(0, 100)?).ok()?;
        let prefix = core::str::from_utf8(self.field(345, 500)?).ok()?;
        Some(if prefix.is_empty() {
            name.to_owned()
        } else {
            format!("{prefix}/{name}")
        })
    }

    fn kind(&self) -> u8 {
        self.0.get(156).copied().unwrap_or(0)
    }
}

/// The one file named `expected_name`, out of `archive`.
fn one_file<'a>(archive: &'a [u8], expected_name: &str) -> Result<&'a [u8], Verdict> {
    let mut at = 0usize;
    let mut found: Option<&[u8]> = None;
    loop {
        let Some(block) = archive.get(at..at.saturating_add(BLOCK)) else {
            // The end-of-archive blocks are optional; a partial block is not.
            return if at == archive.len() {
                found.ok_or(Verdict::Fail)
            } else {
                Err(Verdict::Unobservable)
            };
        };
        if block.iter().all(|b| *b == 0) {
            return found.ok_or(Verdict::Fail);
        }
        let header = Header(block);
        if !header.checksum_ok() {
            return Err(Verdict::Unobservable);
        }
        let size = header.octal(124, 136).ok_or(Verdict::Unobservable)?;
        if size > MAX_PROBE_BYTES {
            return Err(Verdict::Fail);
        }
        let start = at + BLOCK;
        let end = start.checked_add(size).ok_or(Verdict::Unobservable)?;
        let content = archive.get(start..end).ok_or(Verdict::Unobservable)?;
        match header.kind() {
            // Extended headers describe the next entry; the content is all
            // that is hashed, so they are skipped.
            b'x' | b'g' => {}
            b'0' | 0 => {
                let name = header.name().ok_or(Verdict::Unobservable)?;
                let leaf = name.trim_end_matches('/').rsplit('/').next().unwrap_or("");
                if leaf != expected_name || found.is_some() {
                    return Err(Verdict::Fail);
                }
                found = Some(content);
            }
            // A link, a directory, a device: not the probe.
            _ => return Err(Verdict::Fail),
        }
        let padded = size.div_ceil(BLOCK) * BLOCK;
        at = start.checked_add(padded).ok_or(Verdict::Unobservable)?;
    }
}

/// Lowercase hex SHA-256.
fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    let digest = Sha256::digest(bytes);
    let mut text = String::with_capacity(64);
    for byte in digest {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

/// Whether `archive` holds exactly the probe `expected` names.
#[must_use]
pub(crate) fn probe(archive: &[u8], expected: &str) -> Verdict {
    named(archive, PROBE_NAME, expected)
}

/// Whether `archive` holds exactly the relay `expected` names: the same
/// rules, its own name (M5b).
#[must_use]
pub(crate) fn relay(archive: &[u8], expected: &str) -> Verdict {
    named(archive, RELAY_NAME, expected)
}

fn named(archive: &[u8], name: &str, expected: &str) -> Verdict {
    match one_file(archive, name) {
        Ok(file) if hex(file) == expected => Verdict::Pass,
        Ok(_) => Verdict::Fail,
        Err(verdict) => verdict,
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test assertions: a panic is the failure report"
)]
mod tests {
    use dwk_proto::brokerp::sandbox::Verdict;

    use super::{BLOCK, hex, probe, relay};

    /// One ustar entry.
    fn entry(name: &str, kind: u8, content: &[u8]) -> Vec<u8> {
        let mut header = vec![0u8; BLOCK];
        header[..name.len()].copy_from_slice(name.as_bytes());
        header[100..107].copy_from_slice(b"0000755");
        header[108..115].copy_from_slice(b"0000000");
        header[116..123].copy_from_slice(b"0000000");
        let size = format!("{:011o}", content.len());
        header[124..135].copy_from_slice(size.as_bytes());
        header[136..147].copy_from_slice(b"00000000000");
        header[156] = kind;
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        header[148..156].copy_from_slice(b"        ");
        let sum: usize = header.iter().map(|b| usize::from(*b)).sum();
        let sum = format!("{sum:06o}\0 ");
        header[148..156].copy_from_slice(sum.as_bytes());
        let mut out = header;
        out.extend_from_slice(content);
        out.resize(out.len().div_ceil(BLOCK) * BLOCK, 0);
        out
    }

    fn archive(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut out: Vec<u8> = entries.concat();
        out.extend_from_slice(&[0u8; 2 * BLOCK]);
        out
    }

    #[test]
    fn the_exact_probe_passes_and_every_substitution_fails() {
        let bytes = b"\x7fELF the probe".to_vec();
        let want = hex(&bytes);
        let good = archive(&[entry("sandbox-probe", b'0', &bytes)]);
        assert_eq!(probe(&good, &want), Verdict::Pass);
        // Changed bytes.
        let mut changed = bytes.clone();
        changed[5] ^= 1;
        assert_eq!(
            probe(&archive(&[entry("sandbox-probe", b'0', &changed)]), &want),
            Verdict::Fail
        );
        // A substituted file (another probe), a truncated one.
        assert_eq!(
            probe(&archive(&[entry("sandbox-probe", b'0', b"other")]), &want),
            Verdict::Fail
        );
        assert_eq!(
            probe(
                &archive(&[entry("sandbox-probe", b'0', &bytes[..4])]),
                &want
            ),
            Verdict::Fail
        );
        // A symbolic link in its place, a second file, another name.
        assert_eq!(
            probe(&archive(&[entry("sandbox-probe", b'2', b"")]), &want),
            Verdict::Fail
        );
        assert_eq!(
            probe(
                &archive(&[
                    entry("sandbox-probe", b'0', &bytes),
                    entry("sandbox-probe", b'0', &bytes)
                ]),
                &want
            ),
            Verdict::Fail
        );
        assert_eq!(
            probe(&archive(&[entry("other", b'0', &bytes)]), &want),
            Verdict::Fail
        );
        // An extended header before it is skipped.
        let pax = archive(&[
            entry("PaxHeaders/x", b'x', b"20 path=sandbox-probe\n"),
            entry("sandbox-probe", b'0', &bytes),
        ]);
        assert_eq!(probe(&pax, &want), Verdict::Pass);
    }

    #[test]
    fn the_relay_is_its_own_file_and_never_the_probe() {
        let bytes = b"\x7fELF the relay".to_vec();
        let want = hex(&bytes);
        assert_eq!(
            relay(&archive(&[entry("sandbox-relay", b'0', &bytes)]), &want),
            Verdict::Pass
        );
        // The probe's file under the relay's digest, or the relay's under
        // the probe's name: neither passes.
        assert_eq!(
            relay(&archive(&[entry("sandbox-probe", b'0', &bytes)]), &want),
            Verdict::Fail
        );
        assert_eq!(
            probe(&archive(&[entry("sandbox-relay", b'0', &bytes)]), &want),
            Verdict::Fail
        );
    }

    #[test]
    fn a_stream_that_is_not_an_archive_is_unobservable() {
        let bytes = b"\x7fELF".to_vec();
        let want = hex(&bytes);
        let mut bad = archive(&[entry("sandbox-probe", b'0', &bytes)]);
        bad[0] ^= 0xff;
        assert_eq!(probe(&bad, &want), Verdict::Unobservable);
        assert_eq!(probe(&bad[..300], &want), Verdict::Unobservable);
        // Nothing at all is no probe.
        assert_eq!(probe(&[], &want), Verdict::Fail);
        let good = archive(&[entry("sandbox-probe", b'0', &bytes)]);
        assert_eq!(probe(&good[..BLOCK + 2], &want), Verdict::Unobservable);
    }
}
