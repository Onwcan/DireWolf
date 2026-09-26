//! The exchange's unit tests: real files and descriptors, no socket.
//!
//! The one file in the broker allowed to open paths besides the listener's own
//! (TX015): it builds the objects the checks are measured against.

use std::io::Write as _;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use dwk_proto::brokerp::{
    Authorisation, BrokerRefusal, ChannelNonce, Common, ContentRevision, FsDeleteAuthorisation,
    FsMoveAuthorisation, FsPatchAuthorisation, FsReadAuthorisation, FsReclaimAuthorisation,
    FsWriteAuthorisation, Indeterminate, LeafName, MoveSide, OutcomeResult, PatchEdit, PatchEdits,
    ReclaimState, StagingHolds, StagingOperation,
};
use dwk_proto::wire::id::InvocationId;
use dwk_proto::wire::scalar::{
    ContentDigest, HexContent, PatchLength, PatchOutcome, ReadLimit, StatKind,
};
use sha2::{Digest as _, Sha256};

use super::observe::{read_bounded, read_within};
use super::staging::{self, Record, Staging};
use super::{Descriptors, execute};

/// A process table no filesystem test uses: it cannot start anything (its
/// helper does not exist).
fn no_processes() -> crate::process::Processes {
    crate::process::Processes::for_tests(
        PathBuf::from("/nonexistent/dwkd-broker"),
        0,
        std::time::Duration::from_secs(1),
    )
}
use crate::crash::Step;

/// This process's effective uid, the way the broker learns it: the owner of a
/// file it just created.
fn own_uid() -> u32 {
    let probe = Scratch::new("uid");
    let path = probe.0.join("probe");
    assert!(std::fs::write(&path, b"").is_ok());
    std::fs::metadata(&path).map_or(u32::MAX, |m| m.uid())
}

fn channel(c: char) -> ChannelNonce {
    match ChannelNonce::new(c.to_string().repeat(32)) {
        Some(channel) => channel,
        None => unreachable!("a channel"),
    }
}

fn invocation_n(n: u8) -> InvocationId {
    let text = format!("inv_01M24BB8G3E0A851TRWE3M8FZ{}", char::from(b'A' + n % 20));
    match InvocationId::parse(&text) {
        Some(id) => id,
        None => unreachable!("an id"),
    }
}

fn invocation() -> InvocationId {
    invocation_n(5)
}

/// A private scratch directory, removed with everything in it.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("dwb-{tag}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        assert!(std::fs::create_dir_all(&path).is_ok());
        Self(path)
    }

    fn file(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        let written = std::fs::File::create(&path).and_then(|mut f| f.write_all(bytes));
        assert!(written.is_ok());
        path
    }

    fn dir(&self) -> OwnedFd {
        open_dir(&self.0)
    }

    fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(&self.0)
            .map(|it| {
                it.filter_map(Result::ok)
                    .filter_map(|e| e.file_name().into_string().ok())
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn open(path: &Path) -> OwnedFd {
    match std::fs::File::open(path) {
        Ok(f) => OwnedFd::from(f),
        Err(e) => unreachable!("{e}"),
    }
}

fn open_dir(path: &Path) -> OwnedFd {
    open(path)
}

fn identity(path: &Path) -> (u64, u64) {
    match std::fs::symlink_metadata(path) {
        Ok(m) => (m.dev(), m.ino()),
        Err(e) => unreachable!("{e}"),
    }
}

fn leaf(name: &str) -> LeafName {
    match LeafName::new(name) {
        Some(leaf) => leaf,
        None => unreachable!("a leaf"),
    }
}

fn common(on: char) -> Common {
    Common::new(channel(on), invocation())
}

fn read_authorisation(on: char, identity: (u64, u64), max: u32) -> Authorisation {
    let Some(limit) = ReadLimit::new(max) else {
        unreachable!("a limit")
    };
    Authorisation::FsRead(FsReadAuthorisation::new(
        channel(on),
        invocation(),
        identity.0,
        identity.1,
        limit,
    ))
}

fn descriptors(fds: Vec<OwnedFd>) -> Descriptors {
    let mut d = Descriptors::default();
    for fd in fds {
        d.receive(fd);
    }
    d
}

fn one(fd: OwnedFd) -> Descriptors {
    descriptors(vec![fd])
}

/// Execute one authorisation — and check, on its trace, the durability order
/// of ADR-0044 §10: every operation any test here runs is held to it.
fn run(authorisation: &Authorisation, fds: Vec<OwnedFd>) -> OutcomeResult {
    let uid = own_uid();
    let from = crate::crash::steps().len();
    let got = execute(
        &channel('a'),
        authorisation,
        descriptors(fds),
        uid,
        &no_processes(),
    );
    durable_in_order(crate::crash::steps().get(from..).unwrap_or_default(), &got);
    got
}

/// ADR-0044 §10's durability order, on one operation's trace: after every
/// namespace change, each directory whose entries it changed is `fsync`ed —
/// and a file the broker wrote, before the directory that names it — before
/// the next namespace change, and before any answer but `indeterminate`. An
/// undo may follow the change it undoes directly: that change is never made
/// durable first.
fn durable_in_order(steps: &[Step], answered: &OutcomeResult) {
    assert_eq!(out_of_order(steps, answered), None, "{steps:#?}");
}

/// The first breach of the durability order in `steps`, if any.
fn out_of_order(steps: &[Step], answered: &OutcomeResult) -> Option<String> {
    let mut dirty: Vec<(u64, u64)> = Vec::new();
    let mut files: Vec<&str> = Vec::new();
    for (at, step) in steps.iter().enumerate() {
        match step {
            Step::Point(_) => {}
            Step::Changed(what, dirs) => {
                if !(dirty.is_empty() && files.is_empty()) {
                    return Some(format!(
                        "step {at}, `{what}`, follows a change not yet durable: {dirty:?} {files:?}"
                    ));
                }
                dirty.clone_from(dirs);
                if let Some(file) = what
                    .strip_prefix("create ")
                    .filter(|file| [staging::NEW, staging::RECORD].contains(file))
                {
                    files.push(file);
                }
            }
            Step::Undone(what, dirs) => {
                if !(dirty.iter().all(|d| dirs.contains(d)) && files.is_empty()) {
                    return Some(format!(
                        "step {at}, `{what}`, is not the undo of the change before it: {dirty:?}"
                    ));
                }
                dirty.clone_from(dirs);
            }
            Step::FileSynced(file) => files.retain(|f| f != file),
            Step::Synced(dir) => dirty.retain(|d| d != dir),
        }
    }
    let claims = !matches!(answered, OutcomeResult::Indeterminate(_));
    (claims && !(dirty.is_empty() && files.is_empty())).then(|| {
        format!("answered {answered:?} with a change not yet durable: {dirty:?} {files:?}")
    })
}

fn read_done(got: &OutcomeResult) -> (Vec<u8>, bool) {
    match got {
        OutcomeResult::Done(done) => match &done.fs_read {
            Some(read) => (read.content.to_bytes(), read.eof_observed),
            None => unreachable!("{got:?}"),
        },
        _ => unreachable!("{got:?}"),
    }
}

#[test]
fn the_authorised_object_is_read_within_its_bound() {
    let dir = Scratch::new("read");
    let file = dir.file("f", b"hello, broker");
    let id = identity(&file);
    let got = run(&read_authorisation('a', id, 5), vec![open(&file)]);
    assert_eq!(read_done(&got), (b"hello".to_vec(), false));
    // Exactly the file's length: every byte read, and the end NOT observed,
    // because observing it would take a fourteenth read.
    let got = run(&read_authorisation('a', id, 13), vec![open(&file)]);
    assert_eq!(read_done(&got), (b"hello, broker".to_vec(), false));
    // One more than the file holds: the short read is the observation.
    let got = run(&read_authorisation('a', id, 14), vec![open(&file)]);
    assert_eq!(read_done(&got), (b"hello, broker".to_vec(), true));
}

#[test]
fn every_mismatch_is_refused_before_reading() {
    let dir = Scratch::new("refuse");
    let file = dir.file("f", b"secret");
    let id = identity(&file);
    let own = own_uid();
    let cases = [
        (
            execute(
                &channel('a'),
                &read_authorisation('b', id, 6),
                one(open(&file)),
                own,
                &no_processes(),
            ),
            BrokerRefusal::ChannelMismatch,
        ),
        (
            execute(
                &channel('a'),
                &read_authorisation('a', id, 6),
                Descriptors::default(),
                own,
                &no_processes(),
            ),
            BrokerRefusal::DescriptorCount,
        ),
        (
            execute(
                &channel('a'),
                &read_authorisation('a', (id.0, id.1.wrapping_add(1)), 6),
                one(open(&file)),
                own,
                &no_processes(),
            ),
            BrokerRefusal::IdentityMismatch,
        ),
    ];
    for (got, want) in cases {
        assert_eq!(got, OutcomeResult::Refused(want));
    }
    for fds in [
        vec![open(&file), open(&file)],
        vec![open(&file), open(&file), open(&file)],
    ] {
        assert_eq!(
            run(&read_authorisation('a', id, 6), fds),
            OutcomeResult::Refused(BrokerRefusal::DescriptorCount)
        );
    }
    let mut truncated = one(open(&file));
    truncated.truncated = true;
    assert_eq!(
        execute(
            &channel('a'),
            &read_authorisation('a', id, 6),
            truncated,
            own,
            &no_processes(),
        ),
        OutcomeResult::Refused(BrokerRefusal::DescriptorCount)
    );
    let writable = match std::fs::OpenOptions::new().write(true).open(&file) {
        Ok(f) => OwnedFd::from(f),
        Err(e) => unreachable!("{e}"),
    };
    assert_eq!(
        run(&read_authorisation('a', id, 6), vec![writable]),
        OutcomeResult::Refused(BrokerRefusal::DescriptorNotReadable)
    );
    assert_eq!(
        run(&read_authorisation('a', id, 6), vec![dir.dir()]),
        OutcomeResult::Refused(BrokerRefusal::DescriptorNotRegular)
    );
}

#[test]
fn an_empty_file_observes_its_end_and_an_exact_fit_does_not() {
    let dir = Scratch::new("ends");
    let empty = dir.file("empty", b"");
    let done = read_bounded(&open(&empty), 1);
    assert!(done.is_some_and(|d| d.eof_observed && d.content.byte_len() == 0));
    let exact = dir.file("exact", b"abcd");
    let done = read_bounded(&open(&exact), 4);
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
            let Some((content, eof)) = done else {
                unreachable!("n={n} chunk={chunk}")
            };
            let bound = usize::try_from(n).unwrap_or(usize::MAX);
            assert_eq!(content, file.get(..bound).unwrap_or_default());
            assert!(!eof, "n={n}: the file is longer");
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
    assert!(done.is_some_and(|(c, eof)| eof && c == b"abc"));
    assert!(counted.furthest <= 8 && counted.served == 3);
}

#[test]
fn a_read_that_claims_more_than_its_window_is_not_trusted() {
    let done = read_within(4, |w, _| Ok(w.len().saturating_add(1)));
    assert!(done.is_none());
}

// ---------------------------------------------------------------------------
// M4c: the operations that change names, on the real kernel.
// ---------------------------------------------------------------------------

fn hex(bytes: &[u8]) -> HexContent {
    match HexContent::from_bytes(bytes) {
        Some(hex) => hex,
        None => unreachable!("content"),
    }
}

fn write_authorisation(
    dir: &Scratch,
    name: &str,
    target: Option<(u64, u64)>,
    content: &[u8],
) -> Authorisation {
    Authorisation::FsWrite(FsWriteAuthorisation::new(
        common('a'),
        identity(&dir.0),
        leaf(name),
        target,
        hex(content),
    ))
}

fn refused(got: &OutcomeResult) -> BrokerRefusal {
    match got {
        OutcomeResult::Refused(why) => *why,
        _ => unreachable!("{got:?}"),
    }
}

fn content(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_default()
}

#[test]
fn a_write_replaces_atomically_keeping_the_mode_and_leaves_nothing_behind() {
    let dir = Scratch::new("write");
    let path = dir.file("f", b"old content");
    assert!(std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).is_ok());
    let before = identity(&path);
    let got = run(
        &write_authorisation(&dir, "f", Some(before), b"new"),
        vec![dir.dir()],
    );
    let OutcomeResult::Done(done) = &got else {
        unreachable!("{got:?}")
    };
    assert!(
        done.fs_write
            .as_ref()
            .is_some_and(|w| !w.created && !w.debris)
    );
    assert_eq!(content(&path), b"new");
    assert_ne!(
        identity(&path),
        before,
        "a new file, never written in place"
    );
    let mode = std::fs::metadata(&path).map_or(0, |m| m.permissions().mode() & 0o7777);
    assert_eq!(mode, 0o640, "the replaced file's permission bits");
    assert_eq!(
        dir.names(),
        ["f"],
        "no staging directory, no temporary file"
    );
}

#[test]
fn a_creating_write_never_replaces_and_has_the_contract_mode() {
    let dir = Scratch::new("create");
    let got = run(
        &write_authorisation(&dir, "n", None, b"fresh"),
        vec![dir.dir()],
    );
    assert!(
        matches!(got, OutcomeResult::Done(ref d) if d.fs_write.as_ref().is_some_and(|w| w.created))
    );
    let path = dir.0.join("n");
    assert_eq!(content(&path), b"fresh");
    let mode = std::fs::metadata(&path).map_or(0, |m| m.permissions().mode() & 0o7777);
    assert_eq!(
        mode, 0o660,
        "exactly the created-file mode, whatever the umask; never executable"
    );
    // The name is occupied now: a second creation changes nothing.
    let got = run(
        &write_authorisation(&dir, "n", None, b"other"),
        vec![dir.dir()],
    );
    assert_eq!(refused(&got), BrokerRefusal::TargetOccupied);
    assert_eq!(content(&path), b"fresh");
    assert_eq!(dir.names(), ["n"]);
}

#[test]
fn a_write_to_a_name_that_no_longer_binds_the_target_changes_nothing() {
    let dir = Scratch::new("stale");
    let path = dir.file("f", b"attacker");
    let decoy = identity(&dir.file("decoy", b"x"));
    // The authorisation names another object than the one the name binds.
    let got = run(
        &write_authorisation(&dir, "f", Some(decoy), b"new"),
        vec![dir.dir()],
    );
    assert_eq!(refused(&got), BrokerRefusal::ObjectChanged);
    assert_eq!(content(&path), b"attacker");
    // A multiply-linked target is not replaced: its other names would split.
    let linked = dir.file("linked", b"shared");
    assert!(std::fs::hard_link(&linked, dir.0.join("alias")).is_ok());
    let got = run(
        &write_authorisation(&dir, "linked", Some(identity(&linked)), b"new"),
        vec![dir.dir()],
    );
    assert_eq!(refused(&got), BrokerRefusal::ObjectChanged);
    assert_eq!(content(&linked), b"shared");
    // A setuid, setgid or sticky file is not replaced.
    let special = dir.file("special", b"s");
    assert!(std::fs::set_permissions(&special, std::fs::Permissions::from_mode(0o2644)).is_ok());
    let got = run(
        &write_authorisation(&dir, "special", Some(identity(&special)), b"new"),
        vec![dir.dir()],
    );
    assert_eq!(refused(&got), BrokerRefusal::Unsupported);
    assert_eq!(dir.names(), ["alias", "decoy", "f", "linked", "special"]);
}

fn digest(bytes: &[u8]) -> ContentDigest {
    use std::fmt::Write as _;
    let mut hex = String::new();
    for byte in Sha256::digest(bytes) {
        let _ = write!(hex, "{byte:02x}");
    }
    match ContentDigest::new(hex) {
        Some(digest) => digest,
        None => unreachable!("a digest"),
    }
}

fn revision(bytes: &[u8]) -> ContentRevision {
    let Some(length) = u32::try_from(bytes.len()).ok().and_then(PatchLength::new) else {
        unreachable!("a length")
    };
    ContentRevision {
        sha256: digest(bytes),
        length,
    }
}

fn patch_authorisation(
    dir: &Scratch,
    name: &str,
    base: &[u8],
    post: &[u8],
    edits: &[(u32, u32, &[u8])],
) -> Authorisation {
    let built: Vec<PatchEdit> = edits
        .iter()
        .filter_map(|(offset, delete, insert)| {
            Some(PatchEdit {
                offset: PatchLength::new(*offset)?,
                delete: PatchLength::new(*delete)?,
                insert: HexContent::from_bytes(insert)?,
            })
        })
        .collect();
    let Some(edits) = PatchEdits::new(built) else {
        unreachable!("edits")
    };
    let target = identity(&dir.0.join(name));
    Authorisation::FsPatch(FsPatchAuthorisation::new(
        common('a'),
        identity(&dir.0),
        leaf(name),
        target,
        (revision(base), revision(post), edits),
    ))
}

#[test]
fn a_patch_applies_to_its_base_recognises_its_post_and_refuses_anything_else() {
    let dir = Scratch::new("patch");
    let path = dir.file("f", b"hello, world");
    let authorised = patch_authorisation(
        &dir,
        "f",
        b"hello, world",
        b"hello, there",
        &[(7, 5, b"there")],
    );
    let got = run(&authorised, vec![dir.dir(), open(&path)]);
    assert!(matches!(got, OutcomeResult::Done(ref d)
        if d.fs_patch.as_ref().is_some_and(|p| p.outcome == PatchOutcome::Applied)));
    assert_eq!(content(&path), b"hello, there");
    // The same patch again: the file already holds the post revision.
    let again = run(
        &patch_with_target(&authorised, &path),
        vec![dir.dir(), open(&path)],
    );
    assert!(matches!(again, OutcomeResult::Done(ref d)
        if d.fs_patch.as_ref().is_some_and(|p| p.outcome == PatchOutcome::AlreadyApplied)));
    assert_eq!(content(&path), b"hello, there");
    // Neither revision: a conflict, and nothing changed.
    assert!(std::fs::write(&path, b"something else").is_ok());
    let conflict = patch_authorisation(
        &dir,
        "f",
        b"hello, world",
        b"hello, there",
        &[(7, 5, b"there")],
    );
    let got = run(&conflict, vec![dir.dir(), open(&path)]);
    assert_eq!(refused(&got), BrokerRefusal::Conflict);
    assert_eq!(content(&path), b"something else");
    // Edits that do not produce the post revision: nothing changed.
    assert!(std::fs::write(&path, b"hello, world").is_ok());
    let wrong = patch_authorisation(
        &dir,
        "f",
        b"hello, world",
        b"hello, there",
        &[(7, 5, b"THERE")],
    );
    let got = run(&wrong, vec![dir.dir(), open(&path)]);
    assert_eq!(refused(&got), BrokerRefusal::Conflict);
    assert_eq!(content(&path), b"hello, world");
    assert_eq!(dir.names(), ["f"]);
}

/// The same patch, re-aimed at the file's identity now (a patch replaces the
/// file, so its identity changed).
fn patch_with_target(authorised: &Authorisation, path: &Path) -> Authorisation {
    let Authorisation::FsPatch(p) = authorised else {
        unreachable!("a patch")
    };
    let mut again = p.clone();
    let (device, inode) = identity(path);
    again.target_device = dwk_proto::brokerp::KernelNumber::from_u64(device);
    again.target_inode = dwk_proto::brokerp::KernelNumber::from_u64(inode);
    Authorisation::FsPatch(again)
}

fn move_authorisation(from: &Scratch, old: &str, to: &Scratch, new: &str) -> Authorisation {
    Authorisation::FsMove(FsMoveAuthorisation::new(
        common('a'),
        MoveSide {
            parent: identity(&from.0),
            leaf: leaf(old),
        },
        identity(&from.0.join(old)),
        MoveSide {
            parent: identity(&to.0),
            leaf: leaf(new),
        },
    ))
}

#[test]
fn a_two_descriptor_operation_given_three_is_refused_and_moves_nothing() {
    let dir = Scratch::new("move-three");
    dir.file("a", b"stays");
    let authorised = move_authorisation(&dir, "a", &dir, "b");
    let got = run(&authorised, vec![dir.dir(), dir.dir(), dir.dir()]);
    assert_eq!(refused(&got), BrokerRefusal::DescriptorCount);
    let got = run(&authorised, vec![dir.dir()]);
    assert_eq!(refused(&got), BrokerRefusal::DescriptorCount);
    assert_eq!(dir.names(), ["a"]);
}

#[test]
fn a_move_renames_to_a_vacant_name_and_never_replaces() {
    let dir = Scratch::new("move");
    let path = dir.file("a", b"moving");
    let id = identity(&path);
    let got = run(
        &move_authorisation(&dir, "a", &dir, "b"),
        vec![dir.dir(), dir.dir()],
    );
    assert!(matches!(got, OutcomeResult::Done(ref d) if d.fs_move.is_some()));
    assert_eq!(identity(&dir.0.join("b")), id, "the same object, renamed");
    assert_eq!(dir.names(), ["b"]);
    // An occupied destination: nothing moves, nothing is replaced.
    dir.file("c", b"occupant");
    let got = run(
        &move_authorisation(&dir, "b", &dir, "c"),
        vec![dir.dir(), dir.dir()],
    );
    assert_eq!(refused(&got), BrokerRefusal::TargetOccupied);
    assert_eq!(content(&dir.0.join("c")), b"occupant");
    assert_eq!(content(&dir.0.join("b")), b"moving");
    // Across two directories.
    let other = Scratch::new("move-to");
    let got = run(
        &move_authorisation(&dir, "b", &other, "b"),
        vec![dir.dir(), other.dir()],
    );
    assert!(matches!(got, OutcomeResult::Done(_)));
    assert_eq!(identity(&other.0.join("b")), id);
}

fn delete_authorisation(dir: &Scratch, name: &str, kind: StatKind) -> Authorisation {
    Authorisation::FsDelete(FsDeleteAuthorisation::new(
        common('a'),
        identity(&dir.0),
        leaf(name),
        identity(&dir.0.join(name)),
        kind,
    ))
}

#[test]
fn a_delete_removes_only_the_proved_object_and_only_an_empty_directory() {
    let dir = Scratch::new("delete");
    dir.file("f", b"gone");
    let got = run(
        &delete_authorisation(&dir, "f", StatKind::RegularFile),
        vec![dir.dir()],
    );
    assert!(
        matches!(got, OutcomeResult::Done(ref d) if d.fs_delete.as_ref().is_some_and(|x| !x.debris))
    );
    assert!(
        dir.names().is_empty(),
        "the name and the staging directory are gone"
    );
    // A hard-linked file: this name goes, the other survives.
    let linked = dir.file("linked", b"shared");
    assert!(std::fs::hard_link(&linked, dir.0.join("alias")).is_ok());
    let got = run(
        &delete_authorisation(&dir, "linked", StatKind::RegularFile),
        vec![dir.dir()],
    );
    assert!(matches!(got, OutcomeResult::Done(_)));
    assert_eq!(content(&dir.0.join("alias")), b"shared");
    // An empty directory goes; a non-empty one does not.
    assert!(std::fs::create_dir(dir.0.join("empty")).is_ok());
    let got = run(
        &delete_authorisation(&dir, "empty", StatKind::Directory),
        vec![dir.dir()],
    );
    assert!(matches!(got, OutcomeResult::Done(_)));
    assert!(std::fs::create_dir(dir.0.join("full")).is_ok());
    assert!(std::fs::write(dir.0.join("full/x"), b"x").is_ok());
    let got = run(
        &delete_authorisation(&dir, "full", StatKind::Directory),
        vec![dir.dir()],
    );
    assert_eq!(refused(&got), BrokerRefusal::DirectoryNotEmpty);
    assert_eq!(dir.names(), ["alias", "full"]);
    // The kind stated must be the kind found.
    let got = run(
        &delete_authorisation(&dir, "alias", StatKind::Directory),
        vec![dir.dir()],
    );
    assert_eq!(refused(&got), BrokerRefusal::ObjectChanged);
    assert_eq!(dir.names(), ["alias", "full"]);
}

#[test]
fn a_substituted_object_is_never_deleted_moved_away_or_overwritten() {
    // The authority checked one object; before the broker acts, another is
    // put under the name. Whatever the operation, the substitute survives,
    // byte for byte, under its name.
    let dir = Scratch::new("substitute");
    let checked = dir.file("t", b"checked");
    let checked_id = identity(&checked);
    let write = write_authorisation(&dir, "t", Some(checked_id), b"new");
    let delete = delete_authorisation(&dir, "t", StatKind::RegularFile);
    let moved = move_authorisation(&dir, "t", &dir, "elsewhere");
    // Substitute: the checked file goes, the attacker's arrives.
    assert!(std::fs::rename(&checked, dir.0.join("kept")).is_ok());
    dir.file("t", b"attacker");
    for authorisation in [&write, &delete, &moved] {
        let got = run(
            authorisation,
            vec![dir.dir(), dir.dir()]
                .into_iter()
                .take(usize::from(authorisation.declared_descriptors()))
                .collect(),
        );
        assert_eq!(
            refused(&got),
            BrokerRefusal::ObjectChanged,
            "{authorisation:?}"
        );
        assert_eq!(content(&dir.0.join("t")), b"attacker");
    }
    assert_eq!(dir.names(), ["kept", "t"]);
}

#[test]
fn a_directory_the_broker_may_not_change_is_write_denied_and_untouched() {
    let dir = Scratch::new("denied");
    let path = dir.file("f", b"read only here");
    let id = identity(&path);
    assert!(std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o555)).is_ok());
    let got = run(
        &write_authorisation(&dir, "f", Some(id), b"new"),
        vec![dir.dir()],
    );
    let root = own_uid() == 0;
    assert!(std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o755)).is_ok());
    if !root {
        assert_eq!(refused(&got), BrokerRefusal::WriteDenied);
        assert_eq!(content(&path), b"read only here");
        assert_eq!(dir.names(), ["f"]);
    }
}

// ---------------------------------------------------------------------------
// Races at chosen instants of the broker's own sequence (ADR-0044 §8).
//
// A substitution BEFORE the check made immediately before the change must be
// refused with the change never attempted: the trace of crash points proves
// the namespace call was not reached. A substitution AFTER that check — the
// window no Linux primitive closes — reaches the change, which the check
// after it undoes: no persistent change, but a transient one, which is why the
// permission model excludes untrusted writers. An undo that cannot be proved
// is `indeterminate`, never a refusal.
// ---------------------------------------------------------------------------

/// One line of M4c evidence for `make filesystem-operations-evidence`.
fn fsop(case: &str, outcome: &str) {
    println!(
        "FSOP-EVIDENCE {{\"suite\":\"broker-window\",\"case\":\"{case}\",\"outcome\":\"{outcome}\"}}"
    );
}

/// Put a concurrent writer's file under `name` in `dir`, moving what was there
/// aside.
fn substitute(dir: &Path, name: &str) {
    let aside = dir.join(format!("{name}.aside"));
    assert!(std::fs::rename(dir.join(name), aside).is_ok());
    assert!(std::fs::write(dir.join(name), b"ATTACKER").is_ok());
}

fn attacker_at(path: &Path) -> bool {
    content(path) == b"ATTACKER"
}

fn reached(point: &str) -> bool {
    crate::crash::reached().contains(&point)
}

fn indeterminate(got: &OutcomeResult) -> Indeterminate {
    match got {
        OutcomeResult::Indeterminate(why) => *why,
        _ => unreachable!("{got:?}"),
    }
}

#[test]
fn a_replacement_checks_the_target_immediately_before_the_exchange_and_never_attempts_it() {
    let dir = Scratch::new("check-replace");
    let path = dir.file("t", b"checked");
    let id = identity(&path);
    let root = dir.0.clone();
    crate::crash::race_at("replace.before_check", move || substitute(&root, "t"));
    let got = run(
        &write_authorisation(&dir, "t", Some(id), b"new"),
        vec![dir.dir()],
    );
    assert_eq!(refused(&got), BrokerRefusal::ObjectChanged);
    assert!(reached("replace.before_check"));
    assert!(
        !reached("replace.before_exchange") && !reached("replace.after_exchange"),
        "the exchange was never attempted"
    );
    assert!(attacker_at(&dir.0.join("t")));
    assert_eq!(content(&dir.0.join("t.aside")), b"checked");
    assert_eq!(dir.names(), ["t", "t.aside"], "no staging directory");
    fsop("replace-target-swapped-before-check", "refused-no-exchange");
}

#[test]
fn a_patch_checks_its_base_immediately_before_the_exchange_and_never_attempts_it() {
    let dir = Scratch::new("check-patch");
    let path = dir.file("f", b"hello, world");
    let authorised = patch_authorisation(
        &dir,
        "f",
        b"hello, world",
        b"hello, there",
        &[(7, 5, b"there")],
    );
    let target = path.clone();
    // Rewritten in place, after the broker first proved the base.
    crate::crash::race_at("replace.before_check", move || {
        assert!(std::fs::write(&target, b"hello, WORLD").is_ok());
    });
    let got = run(&authorised, vec![dir.dir(), open(&path)]);
    assert_eq!(refused(&got), BrokerRefusal::Conflict);
    assert!(
        !reached("replace.before_exchange") && !reached("replace.after_exchange"),
        "the exchange was never attempted"
    );
    assert_eq!(
        content(&path),
        b"hello, WORLD",
        "the concurrent write stands"
    );
    assert_eq!(dir.names(), ["f"]);
    fsop("patch-base-rewritten-before-check", "conflict-no-exchange");
}

#[test]
fn a_substitution_after_the_last_check_is_exchanged_back_but_was_transiently_visible() {
    // The window Linux cannot close: after the check, before the exchange.
    let dir = Scratch::new("window-replace");
    let path = dir.file("t", b"checked");
    let id = identity(&path);
    let root = dir.0.clone();
    crate::crash::race_at("replace.before_exchange", move || substitute(&root, "t"));
    let got = run(
        &write_authorisation(&dir, "t", Some(id), b"new"),
        vec![dir.dir()],
    );
    assert_eq!(refused(&got), BrokerRefusal::ObjectChanged);
    // The exchange DID happen and was undone: for that moment the new file
    // was under the name. No persistent change; not no change.
    assert!(reached("replace.after_exchange") && reached("replace.before_restore"));
    assert!(attacker_at(&dir.0.join("t")), "the substitute is back");
    assert_eq!(content(&dir.0.join("t.aside")), b"checked");
    assert_eq!(dir.names(), ["t", "t.aside"], "no staging directory");
    fsop(
        "replace-target-swapped-after-check",
        "transient-exchange-restored",
    );
}

#[test]
fn a_patch_base_rewritten_after_the_last_check_is_exchanged_back_as_a_conflict() {
    let dir = Scratch::new("window-patch");
    let path = dir.file("f", b"hello, world");
    let authorised = patch_authorisation(
        &dir,
        "f",
        b"hello, world",
        b"hello, there",
        &[(7, 5, b"there")],
    );
    let target = path.clone();
    crate::crash::race_at("replace.before_exchange", move || {
        assert!(std::fs::write(&target, b"hello, WORLD").is_ok());
    });
    let got = run(&authorised, vec![dir.dir(), open(&path)]);
    assert_eq!(refused(&got), BrokerRefusal::Conflict);
    assert!(reached("replace.before_restore"));
    assert_eq!(
        content(&path),
        b"hello, WORLD",
        "the concurrent write is not lost"
    );
    assert_eq!(dir.names(), ["f"]);
    fsop(
        "patch-base-rewritten-after-check",
        "transient-exchange-restored-conflict",
    );
}

#[test]
fn a_replacement_whose_restore_fails_is_indeterminate_never_refused() {
    let dir = Scratch::new("restore-replace");
    let path = dir.file("t", b"checked");
    let id = identity(&path);
    let root = dir.0.clone();
    crate::crash::race_at("replace.before_exchange", move || substitute(&root, "t"));
    let root = dir.0.clone();
    // The restore's exchange needs the name; take it away.
    crate::crash::race_at("replace.before_restore", move || {
        assert!(std::fs::remove_file(root.join("t")).is_ok());
    });
    let got = run(
        &write_authorisation(&dir, "t", Some(id), b"new"),
        vec![dir.dir()],
    );
    assert_eq!(indeterminate(&got), Indeterminate::RestoreFailed);
    // The staging directory is kept, holding what the exchange displaced.
    let staging = dir.0.join(format!(".dwkd-{}", invocation().as_str()));
    assert!(
        attacker_at(&staging.join("new")),
        "the displaced object is kept"
    );
    fsop("replace-restore-fails", "indeterminate-restore-failed");
}

#[test]
fn a_creation_checks_the_name_immediately_before_the_rename() {
    let dir = Scratch::new("check-create");
    let root = dir.0.clone();
    crate::crash::race_at("create.before_check", move || {
        assert!(std::fs::write(root.join("n"), b"ATTACKER").is_ok());
    });
    let got = run(
        &write_authorisation(&dir, "n", None, b"new"),
        vec![dir.dir()],
    );
    assert_eq!(refused(&got), BrokerRefusal::TargetOccupied);
    assert!(
        !reached("create.before_rename"),
        "the rename was never attempted"
    );
    assert!(attacker_at(&dir.0.join("n")));
    assert_eq!(dir.names(), ["n"]);
    fsop("create-name-taken-before-check", "refused-no-rename");
}

#[test]
fn a_creation_whose_name_was_taken_after_the_last_check_replaces_nothing() {
    // RENAME_NOREPLACE is an atomic compare on the destination: this window
    // is closed by the kernel, and nothing transient happens either.
    let dir = Scratch::new("window-create");
    let root = dir.0.clone();
    crate::crash::race_at("create.before_rename", move || {
        assert!(std::fs::write(root.join("n"), b"ATTACKER").is_ok());
    });
    let got = run(
        &write_authorisation(&dir, "n", None, b"new"),
        vec![dir.dir()],
    );
    assert_eq!(refused(&got), BrokerRefusal::TargetOccupied);
    assert!(attacker_at(&dir.0.join("n")));
    assert_eq!(dir.names(), ["n"]);
    fsop("create-name-taken-after-check", "noreplace-refused");
}

#[test]
fn a_move_checks_its_source_immediately_before_the_rename() {
    let dir = Scratch::new("check-move");
    dir.file("a", b"checked");
    let authorised = move_authorisation(&dir, "a", &dir, "b");
    let root = dir.0.clone();
    crate::crash::race_at("move.before_check", move || substitute(&root, "a"));
    let got = run(&authorised, vec![dir.dir(), dir.dir()]);
    assert_eq!(refused(&got), BrokerRefusal::ObjectChanged);
    assert!(
        !reached("move.before_rename"),
        "the rename was never attempted"
    );
    assert!(attacker_at(&dir.0.join("a")));
    assert!(!dir.0.join("b").exists());
    fsop("move-source-swapped-before-check", "refused-no-rename");
}

#[test]
fn a_move_that_renamed_another_object_after_the_last_check_renames_it_back() {
    let dir = Scratch::new("window-move");
    dir.file("a", b"checked");
    let authorised = move_authorisation(&dir, "a", &dir, "b");
    let root = dir.0.clone();
    crate::crash::race_at("move.before_rename", move || substitute(&root, "a"));
    let got = run(&authorised, vec![dir.dir(), dir.dir()]);
    assert_eq!(refused(&got), BrokerRefusal::ObjectChanged);
    assert!(reached("move.before_restore"), "renamed, then renamed back");
    assert!(
        attacker_at(&dir.0.join("a")),
        "the substitute is back under its name"
    );
    assert!(!dir.0.join("b").exists(), "nothing left at the destination");
    assert_eq!(content(&dir.0.join("a.aside")), b"checked");
    fsop(
        "move-source-swapped-after-check",
        "transient-rename-restored",
    );
}

#[test]
fn a_move_whose_destination_was_taken_after_the_last_check_replaces_nothing() {
    // The pre-check saw a vacant destination; the writer fills it before the
    // rename. Only RENAME_NOREPLACE stands between the move and that file.
    let dir = Scratch::new("window-move-destination");
    dir.file("a", b"checked");
    let authorised = move_authorisation(&dir, "a", &dir, "b");
    let root = dir.0.clone();
    crate::crash::race_at("move.before_rename", move || {
        assert!(std::fs::write(root.join("b"), b"ATTACKER").is_ok());
    });
    let got = run(&authorised, vec![dir.dir(), dir.dir()]);
    assert_eq!(refused(&got), BrokerRefusal::TargetOccupied);
    assert!(
        attacker_at(&dir.0.join("b")),
        "the destination's occupant survives"
    );
    assert_eq!(
        content(&dir.0.join("a")),
        b"checked",
        "the source did not move"
    );
    fsop("move-destination-taken-after-check", "noreplace-refused");
}

#[test]
fn a_move_whose_restore_fails_is_indeterminate_never_refused() {
    let dir = Scratch::new("restore-move");
    dir.file("a", b"checked");
    let authorised = move_authorisation(&dir, "a", &dir, "b");
    let root = dir.0.clone();
    crate::crash::race_at("move.before_rename", move || substitute(&root, "a"));
    let root = dir.0.clone();
    // The restore renames back without replacing: occupy the source name.
    crate::crash::race_at("move.before_restore", move || {
        assert!(std::fs::write(root.join("a"), b"THIRD").is_ok());
    });
    let got = run(&authorised, vec![dir.dir(), dir.dir()]);
    assert_eq!(indeterminate(&got), Indeterminate::RestoreFailed);
    assert!(attacker_at(&dir.0.join("b")), "nothing was overwritten");
    assert_eq!(content(&dir.0.join("a")), b"THIRD");
    fsop("move-restore-fails", "indeterminate-restore-failed");
}

#[test]
fn a_delete_checks_its_target_immediately_before_taking_it() {
    let dir = Scratch::new("check-delete");
    dir.file("t", b"checked");
    let authorised = delete_authorisation(&dir, "t", StatKind::RegularFile);
    let root = dir.0.clone();
    crate::crash::race_at("delete.before_check", move || substitute(&root, "t"));
    let got = run(&authorised, vec![dir.dir()]);
    assert_eq!(refused(&got), BrokerRefusal::ObjectChanged);
    assert!(!reached("delete.before_stage"), "nothing was taken");
    assert!(attacker_at(&dir.0.join("t")));
    assert_eq!(dir.names(), ["t", "t.aside"], "no staging directory");
    fsop("delete-target-swapped-before-check", "refused-no-stage");
}

#[test]
fn a_delete_that_took_another_object_after_the_last_check_puts_it_back() {
    let dir = Scratch::new("window-delete");
    dir.file("t", b"checked");
    let authorised = delete_authorisation(&dir, "t", StatKind::RegularFile);
    let root = dir.0.clone();
    crate::crash::race_at("delete.before_stage", move || substitute(&root, "t"));
    let got = run(&authorised, vec![dir.dir()]);
    assert_eq!(refused(&got), BrokerRefusal::ObjectChanged);
    assert!(reached("delete.before_restore"), "taken, then put back");
    assert!(
        attacker_at(&dir.0.join("t")),
        "the substitute is back under its name"
    );
    assert_eq!(content(&dir.0.join("t.aside")), b"checked");
    assert_eq!(dir.names(), ["t", "t.aside"], "no staging directory left");
    fsop(
        "delete-target-swapped-after-check",
        "transient-stage-restored",
    );
}

#[test]
fn a_delete_whose_put_back_fails_is_indeterminate_and_keeps_what_it_took() {
    let dir = Scratch::new("restore-delete");
    dir.file("t", b"checked");
    let authorised = delete_authorisation(&dir, "t", StatKind::RegularFile);
    let root = dir.0.clone();
    crate::crash::race_at("delete.before_stage", move || substitute(&root, "t"));
    let root = dir.0.clone();
    crate::crash::race_at("delete.before_restore", move || {
        assert!(std::fs::write(root.join("t"), b"THIRD").is_ok());
    });
    let got = run(&authorised, vec![dir.dir()]);
    assert_eq!(indeterminate(&got), Indeterminate::RestoreFailed);
    let staging = dir.0.join(format!(".dwkd-{}", invocation().as_str()));
    assert!(attacker_at(&staging.join("held")), "what it took is kept");
    assert_eq!(
        content(&dir.0.join("t")),
        b"THIRD",
        "nothing was overwritten"
    );
    fsop("delete-restore-fails", "indeterminate-restore-failed");
}

#[test]
fn a_directory_every_user_may_write_is_refused_and_unchanged() {
    // The permission model excludes untrusted writers; a directory that
    // says anyone may write is not one the broker changes names in.
    let dir = Scratch::new("shared");
    let path = dir.file("t", b"stays");
    let id = identity(&path);
    dir.file("a", b"stays too");
    assert!(std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o777)).is_ok());
    let write = write_authorisation(&dir, "t", Some(id), b"new");
    let create = write_authorisation(&dir, "n", None, b"new");
    let delete = delete_authorisation(&dir, "t", StatKind::RegularFile);
    let moved = move_authorisation(&dir, "a", &dir, "b");
    for authorisation in [&write, &create, &delete, &moved] {
        let got = run(
            authorisation,
            vec![dir.dir(), dir.dir()]
                .into_iter()
                .take(usize::from(authorisation.declared_descriptors()))
                .collect(),
        );
        assert_eq!(
            refused(&got),
            BrokerRefusal::SharedDirectory,
            "{authorisation:?}"
        );
    }
    assert!(std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o755)).is_ok());
    assert_eq!(content(&path), b"stays");
    assert_eq!(dir.names(), ["a", "t"]);
    fsop("shared-directory", "refused-unchanged");
}

// ---------------------------------------------------------------------------
// Reclaiming a staging directory left behind (ADR-0044 §10): every state the
// broker's sequence can stop in, built with the broker's own staging code.
// ---------------------------------------------------------------------------

fn reclaim_authorisation(
    dir: &Scratch,
    operation: StagingOperation,
    target: Option<(u64, u64)>,
) -> Authorisation {
    Authorisation::FsReclaim(FsReclaimAuthorisation::new(
        common('a'),
        identity(&dir.0),
        leaf("t"),
        operation,
        target,
    ))
}

fn reclaim_done(got: &OutcomeResult) -> (ReclaimState, Option<StagingHolds>, Option<(u64, u64)>) {
    match got {
        OutcomeResult::Done(done) => match &done.fs_reclaim {
            Some(r) => (
                r.state,
                r.holds,
                r.held_device
                    .as_ref()
                    .zip(r.held_inode.as_ref())
                    .map(|(d, i)| (d.value(), i.value())),
            ),
            None => unreachable!("{got:?}"),
        },
        _ => unreachable!("{got:?}"),
    }
}

/// A staging directory for [`invocation`] in `dir`, made by the broker's own
/// code, holding `record` if given and the files named.
fn staged(dir: &Scratch, record: Option<&Record>, files: &[(&str, &[u8])]) -> PathBuf {
    let staging = match Staging::make(&dir.dir(), &invocation(), own_uid()) {
        Ok(staging) => staging,
        Err(why) => unreachable!("{why:?}"),
    };
    for (name, bytes) in files {
        assert!(
            std::fs::write(
                dir.0.join(staging::name_for(&invocation())).join(name),
                bytes
            )
            .is_ok()
        );
    }
    if let Some(record) = record {
        assert!(staging.record(record).is_ok());
    }
    dir.0.join(staging::name_for(&invocation()))
}

fn record_of(
    operation: StagingOperation,
    target: Option<(u64, u64)>,
    new: Option<(u64, u64)>,
) -> Record {
    Record {
        invocation: invocation().as_str().to_owned(),
        operation,
        leaf: "t".to_owned(),
        target,
        new,
    }
}

#[test]
fn staging_that_holds_only_the_brokers_own_uncommitted_data_is_removed() {
    let target = (1, 2);
    // Replace: no record yet, only the new file.
    let dir = Scratch::new("reclaim-a");
    staged(&dir, None, &[("new", b"n")]);
    let got = run(
        &reclaim_authorisation(&dir, StagingOperation::Replace, Some(target)),
        vec![dir.dir()],
    );
    assert_eq!(reclaim_done(&got), (ReclaimState::Removed, None, None));
    assert!(dir.names().is_empty());
    // Replace: a record the broker never finished, and the new file.
    let dir = Scratch::new("reclaim-b");
    let path = staged(
        &dir,
        None,
        &[("new", b"n"), ("record", b"direwolf-staging 1\ninvoc")],
    );
    assert!(path.join("record").exists());
    let got = run(
        &reclaim_authorisation(&dir, StagingOperation::Replace, Some(target)),
        vec![dir.dir()],
    );
    assert_eq!(reclaim_done(&got).0, ReclaimState::Removed);
    // Replace: a durable record, and the new file still in staging — the
    // exchange never happened (or was undone).
    let dir = Scratch::new("reclaim-c");
    let path = staged(&dir, None, &[("new", b"n")]);
    let record = record_of(
        StagingOperation::Replace,
        Some(target),
        Some(identity(&path.join("new"))),
    );
    assert!(std::fs::write(path.join("record"), record.text()).is_ok());
    let got = run(
        &reclaim_authorisation(&dir, StagingOperation::Replace, Some(target)),
        vec![dir.dir()],
    );
    assert_eq!(reclaim_done(&got).0, ReclaimState::Removed);
    assert!(dir.names().is_empty());
    // Delete: the record, nothing taken.
    let dir = Scratch::new("reclaim-d");
    staged(
        &dir,
        Some(&record_of(StagingOperation::Delete, Some(target), None)),
        &[],
    );
    let got = run(
        &reclaim_authorisation(&dir, StagingOperation::Delete, Some(target)),
        vec![dir.dir()],
    );
    assert_eq!(reclaim_done(&got).0, ReclaimState::Removed);
    assert!(dir.names().is_empty());
    // Absent: nothing to do.
    let got = run(
        &reclaim_authorisation(&dir, StagingOperation::Delete, Some(target)),
        vec![dir.dir()],
    );
    assert_eq!(reclaim_done(&got).0, ReclaimState::Absent);
    fsop("reclaim-pre-effect-staging", "removed");
}

#[test]
fn staging_that_may_hold_a_workspace_object_or_evidence_is_retained_untouched() {
    let target = (1, 2);
    // Replace: the record, and `new` is not the new file — what the exchange
    // displaced.
    let dir = Scratch::new("retain-a");
    let path = staged(&dir, None, &[("new", b"old content")]);
    let displaced = identity(&path.join("new"));
    let record = record_of(StagingOperation::Replace, Some(target), Some((9, 9)));
    assert!(std::fs::write(path.join("record"), record.text()).is_ok());
    let got = run(
        &reclaim_authorisation(&dir, StagingOperation::Replace, Some(target)),
        vec![dir.dir()],
    );
    assert_eq!(
        reclaim_done(&got),
        (
            ReclaimState::Retained,
            Some(StagingHolds::Displaced),
            Some(displaced)
        )
    );
    assert_eq!(content(&path.join("new")), b"old content", "untouched");
    // Replace: the record and nothing else — the exchange happened.
    let dir = Scratch::new("retain-b");
    staged(
        &dir,
        Some(&record_of(
            StagingOperation::Replace,
            Some(target),
            Some((9, 9)),
        )),
        &[],
    );
    let got = run(
        &reclaim_authorisation(&dir, StagingOperation::Replace, Some(target)),
        vec![dir.dir()],
    );
    assert_eq!(
        reclaim_done(&got),
        (ReclaimState::Retained, Some(StagingHolds::Evidence), None)
    );
    // Create: the record and nothing else — the rename happened.
    let dir = Scratch::new("retain-c");
    staged(
        &dir,
        Some(&record_of(StagingOperation::Create, None, Some((9, 9)))),
        &[],
    );
    let got = run(
        &reclaim_authorisation(&dir, StagingOperation::Create, None),
        vec![dir.dir()],
    );
    assert_eq!(
        reclaim_done(&got),
        (ReclaimState::Retained, Some(StagingHolds::Evidence), None)
    );
    fsop("reclaim-post-effect-staging", "retained");
}

#[test]
fn a_deletes_staging_is_retained_while_it_holds_or_proves_anything() {
    let target = (1, 2);
    // Delete: the object taken out of the workspace.
    let dir = Scratch::new("retain-d");
    let path = staged(
        &dir,
        Some(&record_of(StagingOperation::Delete, Some(target), None)),
        &[("held", b"the user's file")],
    );
    let held = identity(&path.join("held"));
    let got = run(
        &reclaim_authorisation(&dir, StagingOperation::Delete, Some(target)),
        vec![dir.dir()],
    );
    assert_eq!(
        reclaim_done(&got),
        (
            ReclaimState::Retained,
            Some(StagingHolds::Taken),
            Some(held)
        )
    );
    assert_eq!(content(&path.join("held")), b"the user's file", "untouched");
    // Delete: removed, and the mark is the evidence.
    let dir = Scratch::new("retain-e");
    staged(
        &dir,
        Some(&record_of(StagingOperation::Delete, Some(target), None)),
        &[("taken", b"")],
    );
    let got = run(
        &reclaim_authorisation(&dir, StagingOperation::Delete, Some(target)),
        vec![dir.dir()],
    );
    assert_eq!(
        reclaim_done(&got),
        (ReclaimState::Retained, Some(StagingHolds::Evidence), None)
    );
    // Anything the broker never writes.
    let dir = Scratch::new("retain-f");
    staged(&dir, None, &[("new", b"n"), ("junk", b"?")]);
    let got = run(
        &reclaim_authorisation(&dir, StagingOperation::Replace, Some(target)),
        vec![dir.dir()],
    );
    assert_eq!(reclaim_done(&got).1, Some(StagingHolds::Unexpected));
    assert_eq!(dir.names().len(), 1, "kept");
    // A record for another invocation, operation or target.
    let dir = Scratch::new("retain-g");
    staged(
        &dir,
        Some(&record_of(StagingOperation::Delete, Some((7, 7)), None)),
        &[],
    );
    let got = run(
        &reclaim_authorisation(&dir, StagingOperation::Delete, Some(target)),
        vec![dir.dir()],
    );
    assert_eq!(reclaim_done(&got).1, Some(StagingHolds::Unexpected));
    fsop("reclaim-post-effect-staging", "retained");
}

#[test]
fn a_directory_is_never_reclaimed_by_its_spelling_alone() {
    let target = (1, 2);
    let name = staging::name_for(&invocation());
    // Spelled right, but not the broker's: mode 0755.
    let dir = Scratch::new("foreign-a");
    assert!(std::fs::create_dir(dir.0.join(&name)).is_ok());
    assert!(
        std::fs::set_permissions(dir.0.join(&name), std::fs::Permissions::from_mode(0o755)).is_ok()
    );
    let got = run(
        &reclaim_authorisation(&dir, StagingOperation::Delete, Some(target)),
        vec![dir.dir()],
    );
    assert_eq!(reclaim_done(&got).0, ReclaimState::Foreign);
    assert_eq!(dir.names(), std::slice::from_ref(&name));
    // A file, or a symlink, by that name.
    let dir = Scratch::new("foreign-b");
    dir.file(&name, b"x");
    let got = run(
        &reclaim_authorisation(&dir, StagingOperation::Delete, Some(target)),
        vec![dir.dir()],
    );
    assert_eq!(reclaim_done(&got).0, ReclaimState::Foreign);
    let dir = Scratch::new("foreign-c");
    assert!(std::os::unix::fs::symlink("/tmp", dir.0.join(&name)).is_ok());
    let got = run(
        &reclaim_authorisation(&dir, StagingOperation::Delete, Some(target)),
        vec![dir.dir()],
    );
    assert_eq!(reclaim_done(&got).0, ReclaimState::Foreign);
    // Another invocation's staging directory, disposable or not, is never
    // looked at: a reclamation names exactly one.
    let dir = Scratch::new("foreign-d");
    let other = staging::name_for(&invocation_n(9));
    assert!(std::fs::create_dir(dir.0.join(&other)).is_ok());
    assert!(
        std::fs::set_permissions(dir.0.join(&other), std::fs::Permissions::from_mode(0o700))
            .is_ok()
    );
    assert!(std::fs::create_dir(dir.0.join(".dwkd-anything")).is_ok());
    let got = run(
        &reclaim_authorisation(&dir, StagingOperation::Delete, Some(target)),
        vec![dir.dir()],
    );
    assert_eq!(reclaim_done(&got).0, ReclaimState::Absent);
    assert_eq!(dir.names(), [".dwkd-anything".to_owned(), other]);
    fsop("reclaim-by-spelling", "never");
}

// ---------------------------------------------------------------------------
// Durability order (ADR-0044 §10): after every change to a directory's
// entries, that directory is `fsync`ed before the next change and before the
// answer. `run` holds every operation above to it; here each transition's
// exact sequence is pinned. The order of system calls, not a power cut: no
// test here removes power from a device.
// ---------------------------------------------------------------------------

/// One line of M4c evidence for the durability order.
fn durability(case: &str, outcome: &str) {
    println!(
        "FSOP-EVIDENCE {{\"suite\":\"broker-durability\",\"case\":\"{case}\",\"outcome\":\"{outcome}\"}}"
    );
}

/// Run `work` on a thread of its own — its own races, its own trace — and
/// return its answer and every step it took.
fn on_own_thread(
    work: impl FnOnce() -> OutcomeResult + Send + 'static,
) -> (OutcomeResult, Vec<Step>) {
    std::thread::spawn(move || {
        let got = work();
        (got, crate::crash::steps())
    })
    .join()
    .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
}

/// A trace's namespace changes and `fsync`s, each directory named by its role
/// — any directory not named is the staging directory.
fn rendered(steps: &[Step], roles: &[((u64, u64), &str)]) -> Vec<String> {
    let role = |dir: &(u64, u64)| {
        roles
            .iter()
            .find(|(id, _)| id == dir)
            .map_or("staging", |(_, role)| *role)
    };
    let dirs = |dirs: &[(u64, u64)]| dirs.iter().map(role).collect::<Vec<_>>().join("+");
    steps
        .iter()
        .filter_map(|step| match step {
            Step::Point(_) => None,
            Step::Changed(what, changed) | Step::Undone(what, changed) => {
                Some(format!("{what} in {}", dirs(changed)))
            }
            Step::FileSynced(file) => Some(format!("fsync file {file}")),
            Step::Synced(dir) => Some(format!("fsync {}", role(dir))),
        })
        .collect()
}

fn sequence(parts: &[&[&str]]) -> Vec<String> {
    parts
        .iter()
        .flat_map(|part| part.iter().map(|s| (*s).to_owned()))
        .collect()
}

/// A: the staging directory's mode, then its name in the parent.
const MAKE: &[&str] = &["mkdir staging in parent", "fsync staging", "fsync parent"];
/// C: the new file's content, then its entry.
const NEW_FILE: &[&str] = &["create new in staging", "fsync file new", "fsync staging"];
/// B: the record's content, then its entry.
const RECORD_FILE: &[&str] = &[
    "create record in staging",
    "fsync file record",
    "fsync staging",
];
/// H: the staging directory's removal, in the parent.
const RMDIR: &[&str] = &["rmdir staging in parent", "fsync parent"];
/// G: an undone preparation — the record first, each removal durable.
const DISCARD: &[&str] = &[
    "unlink record in staging",
    "fsync staging",
    "unlink new in staging",
    "fsync staging",
];

#[test]
fn every_effect_is_durable_in_every_directory_it_changed_before_the_next_step() {
    // Replace: D, the exchange changes both directories; both are made
    // durable before the clean-up, whose every removal is durable too (G, H).
    let dir = Scratch::new("durable-replace");
    let parent = identity(&dir.0);
    let path = dir.file("t", b"old");
    let authorised = write_authorisation(&dir, "t", Some(identity(&path)), b"new");
    let fd = dir.dir();
    let (got, steps) = on_own_thread(move || run(&authorised, vec![fd]));
    assert!(matches!(got, OutcomeResult::Done(_)), "{got:?}");
    assert_eq!(
        rendered(&steps, &[(parent, "parent")]),
        sequence(&[
            MAKE,
            NEW_FILE,
            RECORD_FILE,
            &[
                "exchange in staging+parent",
                "fsync parent",
                "fsync staging",
                "unlink new in staging",
                "fsync staging",
                "unlink record in staging",
                "fsync staging",
            ],
            RMDIR,
        ])
    );

    // Create: the rename changes both directories.
    let dir = Scratch::new("durable-create");
    let parent = identity(&dir.0);
    let authorised = write_authorisation(&dir, "n", None, b"new");
    let fd = dir.dir();
    let (got, steps) = on_own_thread(move || run(&authorised, vec![fd]));
    assert!(matches!(got, OutcomeResult::Done(_)), "{got:?}");
    assert_eq!(
        rendered(&steps, &[(parent, "parent")]),
        sequence(&[
            MAKE,
            NEW_FILE,
            RECORD_FILE,
            &[
                "rename in staging+parent",
                "fsync parent",
                "fsync staging",
                "unlink record in staging",
                "fsync staging",
            ],
            RMDIR,
        ])
    );

    // Delete: F, the object taken into staging, durable in both directories
    // before it is marked; the mark and the removal durable before the
    // evidence goes; then the evidence, a removal at a time.
    let dir = Scratch::new("durable-delete");
    let parent = identity(&dir.0);
    dir.file("t", b"gone");
    let authorised = delete_authorisation(&dir, "t", StatKind::RegularFile);
    let fd = dir.dir();
    let (got, steps) = on_own_thread(move || run(&authorised, vec![fd]));
    assert!(matches!(got, OutcomeResult::Done(_)), "{got:?}");
    assert_eq!(
        rendered(&steps, &[(parent, "parent")]),
        sequence(&[
            MAKE,
            RECORD_FILE,
            &[
                "stage in parent+staging",
                "fsync parent",
                "fsync staging",
                "create taken in staging",
                "fsync staging",
                "unlink held in staging",
                "fsync staging",
                "unlink record in staging",
                "fsync staging",
                "unlink taken in staging",
                "fsync staging",
            ],
            RMDIR,
        ])
    );
    durability("A-staging-directory-created", "staging-then-parent-fsynced");
    durability("B-record-written", "file-then-staging-fsynced");
    durability("C-new-written", "file-then-staging-fsynced");
    durability("D-exchange-or-rename", "both-directories-fsynced");
    durability(
        "F-taken-into-staging",
        "both-directories-fsynced-before-mark",
    );
}

#[test]
fn every_undo_follows_its_change_directly_and_is_durable_in_both_directories() {
    // E: an undone exchange follows the exchange directly — never made
    // durable first — and the undo is durable in both before the record goes.
    let dir = Scratch::new("durable-undo-replace");
    let parent = identity(&dir.0);
    let path = dir.file("t", b"checked");
    let authorised = write_authorisation(&dir, "t", Some(identity(&path)), b"new");
    let (fd, root) = (dir.dir(), dir.0.clone());
    let (got, steps) = on_own_thread(move || {
        crate::crash::race_at("replace.before_exchange", move || substitute(&root, "t"));
        run(&authorised, vec![fd])
    });
    assert_eq!(refused(&got), BrokerRefusal::ObjectChanged);
    assert_eq!(
        rendered(&steps, &[(parent, "parent")]),
        sequence(&[
            MAKE,
            NEW_FILE,
            RECORD_FILE,
            &[
                "exchange in staging+parent",
                "exchange back in staging+parent",
                "fsync parent",
                "fsync staging",
            ],
            DISCARD,
            RMDIR,
        ])
    );

    // E: a delete that took the wrong object puts it back, the same way.
    let dir = Scratch::new("durable-undo-delete");
    let parent = identity(&dir.0);
    dir.file("t", b"checked");
    let authorised = delete_authorisation(&dir, "t", StatKind::RegularFile);
    let (fd, root) = (dir.dir(), dir.0.clone());
    let (got, steps) = on_own_thread(move || {
        crate::crash::race_at("delete.before_stage", move || substitute(&root, "t"));
        run(&authorised, vec![fd])
    });
    assert_eq!(refused(&got), BrokerRefusal::ObjectChanged);
    assert_eq!(
        rendered(&steps, &[(parent, "parent")]),
        sequence(&[
            MAKE,
            RECORD_FILE,
            &[
                "stage in parent+staging",
                "put back in staging+parent",
                "fsync parent",
                "fsync staging",
                "unlink record in staging",
                "fsync staging",
            ],
            RMDIR,
        ])
    );

    // A move between two directories changes both; so does its undo.
    let (from, to) = (Scratch::new("durable-from"), Scratch::new("durable-to"));
    let roles = [(identity(&from.0), "from"), (identity(&to.0), "to")];
    from.file("a", b"moving");
    let authorised = move_authorisation(&from, "a", &to, "b");
    let fds = vec![from.dir(), to.dir()];
    let (got, steps) = on_own_thread(move || run(&authorised, fds));
    assert!(matches!(got, OutcomeResult::Done(_)), "{got:?}");
    assert_eq!(
        rendered(&steps, &roles),
        ["rename in from+to", "fsync to", "fsync from"]
    );
    from.file("a", b"checked");
    let authorised = move_authorisation(&from, "a", &to, "c");
    let (fds, root) = (vec![from.dir(), to.dir()], from.0.clone());
    let (got, steps) = on_own_thread(move || {
        crate::crash::race_at("move.before_rename", move || substitute(&root, "a"));
        run(&authorised, fds)
    });
    assert_eq!(refused(&got), BrokerRefusal::ObjectChanged);
    assert_eq!(
        rendered(&steps, &roles),
        [
            "rename in from+to",
            "rename back in to+from",
            "fsync from",
            "fsync to"
        ]
    );
    durability("E-undo", "both-directories-fsynced-before-record-removed");
}

#[test]
fn every_removal_from_staging_is_durable_before_the_next() {
    // A refusal before any effect: the preparation undone, record first.
    let dir = Scratch::new("durable-discard");
    let parent = identity(&dir.0);
    let path = dir.file("t", b"checked");
    let authorised = write_authorisation(&dir, "t", Some(identity(&path)), b"new");
    let (fd, root) = (dir.dir(), dir.0.clone());
    let (got, steps) = on_own_thread(move || {
        crate::crash::race_at("replace.before_check", move || substitute(&root, "t"));
        run(&authorised, vec![fd])
    });
    assert_eq!(refused(&got), BrokerRefusal::ObjectChanged);
    assert_eq!(
        rendered(&steps, &[(parent, "parent")]),
        sequence(&[MAKE, NEW_FILE, RECORD_FILE, DISCARD, RMDIR])
    );

    // G, H: a reclamation removes a disposable staging directory the same
    // way — each removal durable, the directory's in the parent.
    let dir = Scratch::new("durable-reclaim");
    let parent = identity(&dir.0);
    let path = staged(&dir, None, &[("new", b"n")]);
    let record = record_of(
        StagingOperation::Replace,
        Some((1, 2)),
        Some(identity(&path.join("new"))),
    );
    assert!(std::fs::write(path.join("record"), record.text()).is_ok());
    let authorised = reclaim_authorisation(&dir, StagingOperation::Replace, Some((1, 2)));
    let fd = dir.dir();
    let (got, steps) = on_own_thread(move || run(&authorised, vec![fd]));
    assert_eq!(reclaim_done(&got).0, ReclaimState::Removed);
    assert_eq!(
        rendered(&steps, &[(parent, "parent")]),
        sequence(&[DISCARD, RMDIR])
    );

    durability("G-staging-entries-removed", "staging-fsynced-after-each");
    durability("H-staging-directory-removed", "parent-fsynced");
}

#[test]
fn the_durability_checker_refuses_a_change_made_before_the_last_was_durable() {
    // The checker `run` applies is itself checked: each rule, broken once.
    let (parent, staging) = ((1, 1), (2, 2));
    let done = OutcomeResult::Refused(BrokerRefusal::Conflict);
    let broken: [&[Step]; 5] = [
        // A change before the last was made durable.
        &[
            Step::Changed("mkdir staging", vec![parent]),
            Step::Changed("create new", vec![staging]),
        ],
        // A file's entry made durable before its content.
        &[
            Step::Changed("create record", vec![staging]),
            Step::Synced(staging),
            Step::Changed("exchange", vec![staging, parent]),
        ],
        // One directory of two made durable.
        &[
            Step::Changed("exchange", vec![staging, parent]),
            Step::Synced(parent),
        ],
        // An "undo" of something else.
        &[
            Step::Changed("create new", vec![staging]),
            Step::Undone("rename back", vec![parent]),
        ],
        // An answer with a removal not yet durable.
        &[Step::Changed("rmdir staging", vec![parent])],
    ];
    for steps in broken {
        assert!(
            out_of_order(steps, &done).is_some(),
            "not caught: {steps:?}"
        );
    }
    // And what it allows: an undo straight after its change, and an
    // `indeterminate` answer, which claims nothing durable.
    let undone = [
        Step::Changed("exchange", vec![staging, parent]),
        Step::Undone("exchange back", vec![staging, parent]),
        Step::Synced(parent),
        Step::Synced(staging),
    ];
    assert_eq!(out_of_order(&undone, &done), None);
    assert_eq!(
        out_of_order(
            &[Step::Changed("exchange", vec![staging, parent])],
            &OutcomeResult::Indeterminate(Indeterminate::RestoreFailed),
        ),
        None
    );
}
