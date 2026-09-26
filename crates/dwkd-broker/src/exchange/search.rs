//! `fs.search` (M4c, ADR-0044 §6): the offsets at which a literal byte string
//! occurs in the first `max_scan_bytes` of one regular file.
//!
//! **Literal bytes, bounded, and offsets only.** No pattern language, no case
//! folding, no decoding, no excerpt: a needle of at most 1024 bytes is matched
//! byte for byte with Knuth–Morris–Pratt, so the work is linear in the bytes
//! scanned whatever the needle — a crafted needle cannot make the scan
//! quadratic. The file is read in windows that never reach past the scan
//! bound; the end of the file is reported only when a read returned nothing
//! before the bound. Overlapping occurrences are all reported, in ascending
//! order, up to `max_matches`; finding one more stops the scan and says the
//! list was truncated.

use std::os::fd::OwnedFd;

use dwk_proto::brokerp::{
    BrokerDone, BrokerRefusal, FsSearchAuthorisation, FsSearchDone, OutcomeResult,
};
use dwk_proto::wire::list::BoundedList;
use dwk_proto::wire::scalar::ByteCount;
use rustix::io::Errno;

use super::checks::{self, Kind, named};

/// The most bytes one read asks for.
const WINDOW: usize = 64 * 1024;

/// A needle, preprocessed: the longest proper prefix of each prefix that is
/// also its suffix.
#[derive(Debug)]
pub(super) struct Matcher {
    needle: Vec<u8>,
    border: Vec<usize>,
}

impl Matcher {
    /// Preprocess `needle`, which is not empty.
    pub(super) fn new(needle: Vec<u8>) -> Option<Self> {
        if needle.is_empty() {
            return None;
        }
        let mut border = vec![0usize; needle.len()];
        let mut k = 0usize;
        for i in 1..needle.len() {
            let byte = *needle.get(i)?;
            while k > 0 && needle.get(k) != Some(&byte) {
                k = *border.get(k.checked_sub(1)?)?;
            }
            if needle.get(k) == Some(&byte) {
                k = k.checked_add(1)?;
            }
            *border.get_mut(i)? = k;
        }
        Some(Self { needle, border })
    }

    /// The needle's length.
    pub(super) fn len(&self) -> usize {
        self.needle.len()
    }

    /// Advance the state (how many needle bytes are matched) by one byte.
    /// Returns the new state; a state equal to the needle's length is a match.
    pub(super) fn step(&self, mut state: usize, byte: u8) -> usize {
        if state == self.needle.len() {
            state = self.fallback(state);
        }
        while state > 0 && self.needle.get(state) != Some(&byte) {
            state = self.fallback(state);
        }
        if self.needle.get(state) == Some(&byte) {
            state.saturating_add(1)
        } else {
            0
        }
    }

    fn fallback(&self, state: usize) -> usize {
        state
            .checked_sub(1)
            .and_then(|i| self.border.get(i))
            .copied()
            .unwrap_or(0)
    }
}

/// Scan through `read_at` — `pread` in production — for at most `bound`
/// bytes, reporting at most `max_matches` offsets.
pub(super) fn scan(
    matcher: &Matcher,
    bound: u64,
    max_matches: usize,
    mut read_at: impl FnMut(&mut [u8], u64) -> Result<usize, Errno>,
) -> Option<FsSearchDone> {
    let mut window = vec![0u8; WINDOW];
    let mut state = 0usize;
    let mut offsets: Vec<u64> = Vec::new();
    let mut truncated = false;
    let mut scanned: u64 = 0;
    let mut eof_observed = false;
    let needle = u64::try_from(matcher.len()).ok()?;
    'scan: while scanned < bound {
        let room = usize::try_from(bound.checked_sub(scanned)?)
            .unwrap_or(usize::MAX)
            .min(WINDOW);
        let buffer = window.get_mut(..room)?;
        let got = match read_at(buffer, scanned) {
            Ok(0) => {
                eof_observed = true;
                break;
            }
            Ok(n) if n <= room => n,
            Err(Errno::INTR) => continue,
            Ok(_) | Err(_) => return None,
        };
        for (at, byte) in window.get(..got)?.iter().enumerate() {
            state = matcher.step(state, *byte);
            if state == matcher.len() {
                let end = scanned
                    .checked_add(u64::try_from(at).ok()?)?
                    .checked_add(1)?;
                if offsets.len() == max_matches {
                    // One more than may be reported: stop, and say so. The
                    // bytes scanned end with this match.
                    truncated = true;
                    scanned = end;
                    break 'scan;
                }
                offsets.push(end.checked_sub(needle)?);
            }
        }
        scanned = scanned.checked_add(u64::try_from(got).ok()?)?;
    }
    let offsets: Option<Vec<ByteCount>> = offsets.into_iter().map(ByteCount::new).collect();
    Some(FsSearchDone {
        offsets: BoundedList::new(offsets?)?,
        scanned: ByteCount::new(scanned)?,
        eof_observed,
        matches_truncated: truncated,
    })
}

/// `fs.search` through the file the authority opened and proved.
pub(super) fn search(authorisation: &FsSearchAuthorisation, file: &OwnedFd) -> OutcomeResult {
    let want = named(&authorisation.device, &authorisation.inode);
    if let Err(refusal) = checks::readable(file, Kind::File, want) {
        return OutcomeResult::Refused(refusal);
    }
    let Some(matcher) = Matcher::new(authorisation.needle.to_bytes()) else {
        return OutcomeResult::Refused(BrokerRefusal::IoError);
    };
    let bound = u64::from(authorisation.max_scan_bytes.get());
    let max = usize::from(authorisation.max_matches.get());
    match scan(&matcher, bound, max, |window, offset| {
        rustix::io::pread(file, window, offset)
    }) {
        Some(done) => OutcomeResult::done(BrokerDone::search(done)),
        None => OutcomeResult::Refused(BrokerRefusal::ReadFailed),
    }
}

#[cfg(test)]
mod tests {
    use rustix::io::Errno;

    use super::{Matcher, scan};

    fn over(bytes: &[u8]) -> impl FnMut(&mut [u8], u64) -> Result<usize, Errno> + '_ {
        move |window, offset| {
            let start = usize::try_from(offset)
                .unwrap_or(usize::MAX)
                .min(bytes.len());
            let rest = bytes.get(start..).unwrap_or_default();
            let n = rest.len().min(window.len());
            window
                .get_mut(..n)
                .unwrap_or_default()
                .copy_from_slice(rest.get(..n).unwrap_or_default());
            Ok(n)
        }
    }

    fn offsets(
        needle: &[u8],
        haystack: &[u8],
        bound: u64,
        max: usize,
    ) -> (Vec<u64>, u64, bool, bool) {
        let Some(matcher) = Matcher::new(needle.to_vec()) else {
            unreachable!("a needle")
        };
        let Some(done) = scan(&matcher, bound, max, over(haystack)) else {
            unreachable!("a scan")
        };
        (
            done.offsets.iter().map(|o| o.get()).collect(),
            done.scanned.get(),
            done.eof_observed,
            done.matches_truncated,
        )
    }

    fn naive(needle: &[u8], haystack: &[u8]) -> Vec<u64> {
        haystack
            .windows(needle.len())
            .enumerate()
            .filter(|(_, w)| *w == needle)
            .filter_map(|(i, _)| u64::try_from(i).ok())
            .collect()
    }

    #[test]
    fn every_occurrence_overlapping_ones_included_and_nothing_else() {
        assert_eq!(
            offsets(b"aa", b"aaaa", 100, 10),
            (vec![0, 1, 2], 4, true, false)
        );
        assert_eq!(
            offsets(b"abab", b"abababab", 100, 10),
            (vec![0, 2, 4], 8, true, false)
        );
        assert_eq!(offsets(b"x", b"abc", 100, 10), (vec![], 3, true, false));
        // Agreement with the definition on inputs built to defeat a naive
        // failure function.
        let hay: Vec<u8> = b"aabaabaaabaabaab".repeat(9);
        for needle in [&b"aab"[..], b"aabaab", b"abaa", b"aaab", b"baabaa"] {
            assert_eq!(
                offsets(needle, &hay, 10_000, 1000).0,
                naive(needle, &hay),
                "{needle:?}"
            );
        }
    }

    #[test]
    fn the_scan_stops_at_its_bound_and_at_one_match_too_many() {
        // Bounded before the end: the end is not observed, and a match that
        // would cross the bound is not one.
        assert_eq!(offsets(b"cd", b"abcdef", 3, 10), (vec![], 3, false, false));
        assert_eq!(offsets(b"cd", b"abcdef", 4, 10), (vec![2], 4, false, false));
        // More matches than may be reported.
        assert_eq!(
            offsets(b"a", b"aaaaa", 100, 2),
            (vec![0, 1], 3, false, true)
        );
    }

    #[test]
    fn a_match_that_straddles_two_reads_is_found() {
        let mut hay = vec![b'.'; 64 * 1024 - 2];
        hay.extend_from_slice(b"NEEDLE");
        assert_eq!(offsets(b"NEEDLE", &hay, 1 << 20, 4).0, vec![64 * 1024 - 2]);
    }
}
