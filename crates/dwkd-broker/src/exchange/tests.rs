//! The exchange's unit tests: real files and descriptors, no socket.
//!
//! The one file in the broker allowed to open paths besides the listener's own
//! (TX015): it builds the objects the checks are measured against.

use std::io::Write as _;
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt as _;

use dwk_proto::brokerp::{BrokerRefusal, ChannelNonce, FsReadAuthorisation, OutcomeResult};
use dwk_proto::wire::id::InvocationId;
use dwk_proto::wire::scalar::ReadLimit;

use super::{Descriptors, execute, read_bounded, read_within};

fn channel(c: char) -> ChannelNonce {
    match ChannelNonce::new(c.to_string().repeat(32)) {
        Some(channel) => channel,
        None => unreachable!("a channel"),
    }
}

fn invocation() -> InvocationId {
    match InvocationId::parse("inv_01M24BB8G3E0A851TRWE3M8FZF") {
        Some(id) => id,
        None => unreachable!("an id"),
    }
}

struct File(std::path::PathBuf);

impl File {
    fn with(tag: &str, bytes: &[u8]) -> Self {
        let path = std::env::temp_dir().join(format!("dwb-exchange-{tag}-{}", std::process::id()));
        let written = std::fs::File::create(&path).and_then(|mut f| f.write_all(bytes));
        assert!(written.is_ok());
        Self(path)
    }

    fn open(&self) -> OwnedFd {
        match std::fs::File::open(&self.0) {
            Ok(f) => OwnedFd::from(f),
            Err(e) => unreachable!("{e}"),
        }
    }

    fn identity(&self) -> (u64, u64) {
        match std::fs::metadata(&self.0) {
            Ok(m) => (m.dev(), m.ino()),
            Err(e) => unreachable!("{e}"),
        }
    }
}

impl Drop for File {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn authorisation(on: char, identity: (u64, u64), max: u32) -> FsReadAuthorisation {
    let Some(limit) = ReadLimit::new(max) else {
        unreachable!("a limit")
    };
    FsReadAuthorisation::new(channel(on), invocation(), identity.0, identity.1, limit)
}

fn one(fd: OwnedFd) -> Descriptors {
    let mut d = Descriptors::default();
    d.receive(fd);
    d
}

#[test]
fn the_authorised_object_is_read_within_its_bound() {
    let file = File::with("read", b"hello, broker");
    let got = execute(
        &channel('a'),
        &authorisation('a', file.identity(), 5),
        one(file.open()),
    );
    let OutcomeResult::Done(done) = got else {
        unreachable!("{got:?}")
    };
    assert_eq!(done.content.to_bytes(), b"hello");
    assert!(
        !done.eof_observed,
        "five of thirteen: the end was not reached"
    );
    let got = execute(
        &channel('a'),
        &authorisation('a', file.identity(), 13),
        one(file.open()),
    );
    // Exactly the file's length: every byte read, and the end NOT observed,
    // because observing it would take a fourteenth read.
    assert!(
        matches!(got, OutcomeResult::Done(ref d) if !d.eof_observed && d.content.byte_len() == 13)
    );
    // One more than the file holds: the short read is the observation.
    let got = execute(
        &channel('a'),
        &authorisation('a', file.identity(), 14),
        one(file.open()),
    );
    assert!(
        matches!(got, OutcomeResult::Done(ref d) if d.eof_observed && d.content.byte_len() == 13)
    );
}

#[test]
fn every_mismatch_is_refused_before_reading() {
    let file = File::with("refuse", b"secret");
    let id = file.identity();
    let cases = [
        (
            execute(&channel('a'), &authorisation('b', id, 6), one(file.open())),
            BrokerRefusal::ChannelMismatch,
        ),
        (
            execute(
                &channel('a'),
                &authorisation('a', id, 6),
                Descriptors::default(),
            ),
            BrokerRefusal::DescriptorCount,
        ),
        (
            execute(
                &channel('a'),
                &authorisation('a', (id.0, id.1.wrapping_add(1)), 6),
                one(file.open()),
            ),
            BrokerRefusal::IdentityMismatch,
        ),
    ];
    for (got, want) in cases {
        assert_eq!(got, OutcomeResult::Refused(want));
    }
    let mut two = one(file.open());
    two.receive(file.open());
    assert_eq!(
        execute(&channel('a'), &authorisation('a', id, 6), two),
        OutcomeResult::Refused(BrokerRefusal::DescriptorCount)
    );
    let mut truncated = one(file.open());
    truncated.truncated = true;
    assert_eq!(
        execute(&channel('a'), &authorisation('a', id, 6), truncated),
        OutcomeResult::Refused(BrokerRefusal::DescriptorCount)
    );
    let writable = match std::fs::OpenOptions::new().write(true).open(&file.0) {
        Ok(f) => OwnedFd::from(f),
        Err(e) => unreachable!("{e}"),
    };
    assert_eq!(
        execute(&channel('a'), &authorisation('a', id, 6), one(writable)),
        OutcomeResult::Refused(BrokerRefusal::DescriptorNotReadable)
    );
    let dir = match std::fs::File::open(std::env::temp_dir()) {
        Ok(f) => OwnedFd::from(f),
        Err(e) => unreachable!("{e}"),
    };
    assert_eq!(
        execute(&channel('a'), &authorisation('a', id, 6), one(dir)),
        OutcomeResult::Refused(BrokerRefusal::DescriptorNotRegular)
    );
}

#[test]
fn an_empty_file_observes_its_end_and_an_exact_fit_does_not() {
    let empty = File::with("empty", b"");
    let done = read_bounded(&empty.open(), 1);
    assert!(done.is_some_and(|d| d.eof_observed && d.content.byte_len() == 0));
    let exact = File::with("exact", b"abcd");
    let done = read_bounded(&exact.open(), 4);
    assert!(done.is_some_and(|d| !d.eof_observed && d.content.to_bytes() == b"abcd"));
}

/// A file as a byte slice, and every range anyone asked it for.
struct Counted<'a> {
    bytes: &'a [u8],
    /// The furthest byte any read asked for, exclusive.
    furthest: u64,
    /// Every byte handed back, summed.
    served: u64,
    /// At most this many bytes per read: short reads are legal.
    chunk: usize,
}

impl Counted<'_> {
    fn read_at(&mut self, window: &mut [u8], offset: u64) -> usize {
        let len = u64::try_from(window.len()).unwrap_or(u64::MAX);
        self.furthest = self.furthest.max(offset.saturating_add(len));
        let start = usize::try_from(offset)
            .unwrap_or(usize::MAX)
            .min(self.bytes.len());
        let available = self.bytes.get(start..).unwrap_or_default();
        let n = available.len().min(window.len()).min(self.chunk);
        for (dst, src) in window.iter_mut().zip(available.iter().take(n)) {
            *dst = *src;
        }
        self.served = self
            .served
            .saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
        n
    }
}

#[test]
fn a_read_of_n_bytes_never_asks_for_byte_n_plus_one() {
    // A file larger than every bound tested, including the largest M4b
    // allows. Whatever the read sizes the kernel hands back, no read may ask
    // for -- let alone be served -- a byte at or past N.
    let file: Vec<u8> = (0..300 * 1024u32)
        .map(|i| u8::try_from(i % 253).unwrap_or(0))
        .collect();
    let largest = u32::try_from(dwk_proto::limits::MAX_FS_READ_BYTES).unwrap_or(0);
    for n in [1u32, 8, 4096, largest] {
        for chunk in [1usize, 3, 4096, usize::MAX] {
            let mut counted = Counted {
                bytes: &file,
                furthest: 0,
                served: 0,
                chunk,
            };
            let done = read_within(n, |w, o| Ok(counted.read_at(w, o)));
            let Some(done) = done else {
                unreachable!("n={n} chunk={chunk}")
            };
            let bound = usize::try_from(n).unwrap_or(usize::MAX);
            assert_eq!(
                done.content.to_bytes(),
                file.get(..bound).unwrap_or_default()
            );
            assert!(!done.eof_observed, "n={n}: the file is longer");
            assert!(
                counted.furthest <= u64::from(n),
                "n={n} chunk={chunk}: asked up to byte {}",
                counted.furthest
            );
            assert_eq!(counted.served, u64::from(n), "n={n} chunk={chunk}");
        }
    }
    // A file shorter than the bound: the short read is the observed end.
    let mut counted = Counted {
        bytes: b"abc",
        furthest: 0,
        served: 0,
        chunk: usize::MAX,
    };
    let done = read_within(8, |w, o| Ok(counted.read_at(w, o)));
    assert!(done.is_some_and(|d| d.eof_observed && d.content.to_bytes() == b"abc"));
    assert!(counted.furthest <= 8 && counted.served == 3);
}

#[test]
fn a_read_that_claims_more_than_its_window_is_not_trusted() {
    let done = read_within(4, |w, _| Ok(w.len().saturating_add(1)));
    assert!(done.is_none());
}
