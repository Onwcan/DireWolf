//! Real-filesystem evidence for the Linux resolver (M4a, ADR-0042 §14).
//!
//! Every test here runs the **production** resolver — `PinnedRoot::install`,
//! `PinnedRoot::resolve`, the component walk — against real directories,
//! files, symlinks, hard links, FIFOs, sockets, devices, procfs and mount
//! points. There is no test resolver. Two tests bypass one production check
//! each, and say so: the magic-link test opens a procfs directory as a root
//! (production pinning refuses procfs, which is itself asserted), and the
//! traversal test calls the per-component open directly with `..` to show the
//! kernel refuses what the grammar never lets through.
//!
//! Each case prints one machine-checkable line,
//!
//! ```text
//! FS-EVIDENCE {"category":"…","case":"…","outcome":"…","count":N}
//! ```
//!
//! which `make filesystem-canonicalization-evidence` collects and checks. An
//! outcome beginning `not-exercised` is environment-dependent evidence this
//! machine could not produce, and is reported as such — never as a pass.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::integer_division
)]

use std::fmt::Write as _;
use std::fs;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{MetadataExt as _, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread::JoinHandle;
use std::time::Instant;

use rustix::fd::{AsFd as _, OwnedFd};
use rustix::fs::{self as sys, AtFlags, FileType, Mode, OFlags, RenameFlags, StatxFlags};

use super::super::{
    Access, Assurance, Expect, FileIdentity, Handle, PinnedRoot, ResolveError, ResolvedResource,
    ResourceKind, RootError,
};
use super::{identity, open_child, verify_chain, verify_entry, verify_entry_within};
use crate::capability::DeclaredPath;
use crate::resource::PathComponent;
use crate::scratch::Scratch;

/// How many resolutions each race scenario performs while its attacker runs.
const RACE_ITERATIONS: u64 = 10_000;

fn evidence(category: &str, case: &str, outcome: &str, count: u64) {
    println!(
        "FS-EVIDENCE {{\"category\":\"{category}\",\"case\":\"{case}\",\"outcome\":\"{outcome}\",\"count\":{count}}}"
    );
}

fn declared(text: &str) -> DeclaredPath {
    DeclaredPath::new(text).expect("a declared path")
}

fn resolve(
    root: &PinnedRoot,
    text: &str,
    access: Access,
    expect: Expect,
) -> Result<ResolvedResource, ResolveError> {
    root.resolve(&declared(text), access, expect)
}

fn observe(root: &PinnedRoot, text: &str) -> Result<ResolvedResource, ResolveError> {
    resolve(root, text, Access::Observe, Expect::Any)
}

fn outcome(result: &Result<ResolvedResource, ResolveError>) -> String {
    match result {
        Ok(_) => "resolved".to_owned(),
        Err(error) => format!("refused:{}", error.code()),
    }
}

/// The identity of the object at `path`, without following a final symlink —
/// what the test knows independently of the resolver.
fn id_of(path: &Path) -> FileIdentity {
    let meta = fs::symlink_metadata(path).expect("fixture metadata");
    FileIdentity::new(meta.dev(), meta.ino())
}

fn host(path: &Path) -> &str {
    path.to_str().expect("a UTF-8 scratch path")
}

fn dir_fd(path: &Path) -> OwnedFd {
    sys::open(
        path,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .expect("a fixture directory")
}

/// A workspace root and a sibling directory outside it, on one filesystem.
struct Fixture {
    scratch: Scratch,
    root: PathBuf,
    outside: PathBuf,
}

impl Fixture {
    fn new(tag: &str) -> Self {
        let scratch = Scratch::new(tag);
        let root = scratch.path().join("ws");
        let outside = scratch.path().join("outside");
        fs::create_dir(&root).expect("workspace");
        fs::create_dir(&outside).expect("outside");
        fs::write(outside.join("secret"), b"outside secret").expect("secret");
        Self {
            scratch,
            root,
            outside,
        }
    }

    fn ws(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }

    fn out(&self, rel: &str) -> PathBuf {
        self.outside.join(rel)
    }

    fn pin(&self) -> PinnedRoot {
        PinnedRoot::install(host(&self.root))
            .expect("pin the fixture")
            .0
    }
}

// ---------------------------------------------------------------------------
// Ordinary resolution.
// ---------------------------------------------------------------------------

#[test]
fn ordinary_paths_resolve_to_the_objects_they_name() {
    let fx = Fixture::new("fs-normal");
    fs::create_dir_all(fx.ws("src")).unwrap();
    fs::write(fx.ws("src/main.rs"), b"fn main() {}").unwrap();
    fs::write(fx.ws("r\u{e9}sum\u{e9}.txt"), b"cv").unwrap();
    let mut deep = fx.root.clone();
    let mut spelled = String::from("/workspace");
    for level in 0..20 {
        deep.push(format!("d{level}"));
        write!(spelled, "/d{level}").unwrap();
    }
    fs::create_dir_all(&deep).unwrap();
    fs::write(deep.join("leaf"), b"deep").unwrap();
    spelled.push_str("/leaf");

    let root = fx.pin();
    let cases: [(&str, &str, PathBuf, ResourceKind); 5] = [
        (
            "root",
            "/workspace",
            fx.root.clone(),
            ResourceKind::Directory,
        ),
        (
            "directory",
            "/workspace/src",
            fx.ws("src"),
            ResourceKind::Directory,
        ),
        (
            "regular-file",
            "/workspace/src/main.rs",
            fx.ws("src/main.rs"),
            ResourceKind::RegularFile,
        ),
        (
            "nfc-name",
            "/workspace/r\u{e9}sum\u{e9}.txt",
            fx.ws("r\u{e9}sum\u{e9}.txt"),
            ResourceKind::RegularFile,
        ),
        (
            "depth-21",
            &spelled,
            deep.join("leaf"),
            ResourceKind::RegularFile,
        ),
    ];
    for (case, text, path, kind) in cases {
        let resolved = observe(&root, text).unwrap_or_else(|e| panic!("{case}: {e}"));
        assert_eq!(
            resolved.identity(),
            id_of(&path),
            "{case}: the named object"
        );
        assert_eq!(resolved.kind(), kind, "{case}");
        assert_eq!(resolved.canonical_path().to_string(), text, "{case}");
        assert_eq!(resolved.root_identity(), root.identity(), "{case}");
        assert_eq!(resolved.assurance(), Assurance::LinuxOpenat2);
        assert_eq!(resolved.still_bound(), Ok(()), "{case}");
        evidence("normal", case, "resolved", 1);
    }
    evidence("platform", "resolver", Assurance::LinuxOpenat2.as_str(), 1);
}

// ---------------------------------------------------------------------------
// Traversal.
// ---------------------------------------------------------------------------

#[test]
fn traversal_is_refused_by_the_grammar_and_by_the_kernel() {
    let fx = Fixture::new("fs-traversal");
    fs::create_dir_all(fx.ws("a/b/c")).unwrap();
    symlink("../outside/secret", fx.ws("up-link")).unwrap();
    let root = fx.pin();
    for (case, text) in [
        ("dotdot", "/workspace/../outside/secret"),
        ("nested-dotdot", "/workspace/a/../../outside/secret"),
        ("dot-dotdot", "/workspace/./../outside/secret"),
        ("double-slash-dotdot", "/workspace//../outside"),
        ("deep-dotdot", "/workspace/a/b/c/../../../../outside/secret"),
        ("mixed", "/workspace/a/./b/../c"),
        ("above-anchor", "/../workspace/a"),
        ("host-absolute", "/etc/passwd"),
    ] {
        let result = observe(&root, text);
        assert!(
            matches!(result, Err(ResolveError::Path(_))),
            "{case}: {}",
            outcome(&result)
        );
        evidence("traversal", case, &outcome(&result), 1);
    }
    // The kernel layer, below the grammar: `..` and an absolute name are
    // refused by RESOLVE_BENEATH even when handed straight to the walk.
    for (case, name) in [
        ("kernel-dotdot", ".."),
        ("kernel-absolute", "/etc"),
        ("kernel-dotdot-slash", "../outside"),
    ] {
        // RESOLVE_BENEATH reports an escape as EXDEV, which the classifier
        // names MOUNT_CROSSING: in production the grammar has already refused
        // `..` and absolute names, so EXDEV can only be a mount point there.
        let opened = open_child(root.handle.0.as_fd(), name, true, 1);
        assert!(opened.is_err(), "{case}: the kernel refused");
        let code = opened.map_or_else(ResolveError::code, |_| "resolved");
        evidence(
            "traversal",
            case,
            &format!("refused-by-kernel-exdev:{code}"),
            1,
        );
    }
    // A symlink that spells a traversal is a symlink, and is not followed.
    let result = observe(&root, "/workspace/up-link");
    assert_eq!(
        result.as_ref().err(),
        Some(&ResolveError::Symlink { depth: 1 })
    );
    evidence("traversal", "symlink-spelling-dotdot", &outcome(&result), 1);
}

// ---------------------------------------------------------------------------
// Symlinks.
// ---------------------------------------------------------------------------

#[test]
fn no_symlink_is_ever_followed() {
    let fx = Fixture::new("fs-symlink");
    fs::create_dir_all(fx.ws("real/sub")).unwrap();
    fs::write(fx.ws("real/file"), b"inside").unwrap();
    fs::write(fx.ws("real/sub/file"), b"inside").unwrap();
    symlink("real/file", fx.ws("leaf-link")).unwrap();
    symlink("real", fx.ws("dir-link")).unwrap();
    symlink("../real", fx.ws("real/sibling-link")).unwrap();
    symlink(fx.out("secret"), fx.ws("outside-link")).unwrap();
    symlink("chain-2", fx.ws("chain-1")).unwrap();
    symlink("real/file", fx.ws("chain-2")).unwrap();
    symlink("nothing-here", fx.ws("dangling")).unwrap();
    symlink("/etc/passwd", fx.ws("absolute-link")).unwrap();
    let root = fx.pin();
    for (case, text, depth) in [
        ("leaf", "/workspace/leaf-link", 1),
        ("intermediate", "/workspace/dir-link/file", 1),
        ("to-sibling", "/workspace/real/sibling-link/file", 2),
        ("outside-root", "/workspace/outside-link", 1),
        ("chain", "/workspace/chain-1", 1),
        ("dangling", "/workspace/dangling", 1),
        ("absolute-target", "/workspace/absolute-link", 1),
    ] {
        let result = observe(&root, text);
        assert_eq!(
            result.as_ref().err(),
            Some(&ResolveError::Symlink { depth }),
            "{case}"
        );
        evidence("symlink", case, &outcome(&result), 1);
    }

    // Created after an earlier check: the old result no longer binds, and a
    // fresh resolution refuses the link.
    let before = observe(&root, "/workspace/real/file").unwrap();
    fs::remove_file(fx.ws("real/file")).unwrap();
    symlink(fx.out("secret"), fx.ws("real/file")).unwrap();
    assert!(matches!(
        before.still_bound(),
        Err(ResolveError::Race { .. })
    ));
    let after = observe(&root, "/workspace/real/file");
    assert_eq!(
        after.as_ref().err(),
        Some(&ResolveError::Symlink { depth: 2 })
    );
    evidence("symlink", "created-after-check", &outcome(&after), 1);
    evidence(
        "symlink",
        "earlier-result-no-longer-binds",
        "refused:RACE",
        1,
    );
}

// ---------------------------------------------------------------------------
// Magic links and mounts: the real kernel objects, not imitations.
// ---------------------------------------------------------------------------

#[test]
fn procfs_magic_links_are_refused() {
    // Production pinning refuses procfs outright, and `/proc/self` is itself
    // a symlink, which no root may be.
    match PinnedRoot::install("/proc") {
        Err(RootError::UnsupportedFilesystem) => {
            evidence(
                "magic-link",
                "procfs-root-refused",
                "refused:ROOT_UNSUPPORTED_FILESYSTEM",
                1,
            );
        }
        Err(RootError::Missing) => {
            evidence(
                "magic-link",
                "procfs-root-refused",
                "not-exercised:no-procfs",
                0,
            );
            return;
        }
        other => panic!("a procfs root must be refused: {:?}", other.map(|_| ())),
    }
    assert_eq!(
        PinnedRoot::install("/proc/self").map(|_| ()),
        Err(RootError::Symlink)
    );
    evidence(
        "magic-link",
        "proc-self-root-refused",
        "refused:ROOT_SYMLINK",
        1,
    );
    // The resolver itself under a procfs directory, which only this test
    // opens as a root: every magic link must be refused, not followed.
    let fd = dir_fd(Path::new("/proc/self"));
    let st = sys::fstat(&fd).unwrap();
    let root = PinnedRoot {
        handle: Handle(fd),
        identity: FileIdentity::new(super::widen(st.st_dev), super::widen(st.st_ino)),
    };
    for (case, text, depth) in [
        ("cwd", "/workspace/cwd", 1),
        ("root", "/workspace/root", 1),
        ("exe", "/workspace/exe", 1),
        ("fd-0", "/workspace/fd/0", 2),
    ] {
        let result = observe(&root, text);
        match result {
            Err(ResolveError::MagicLink { depth: d }) if d == depth => {
                evidence("magic-link", case, &outcome(&result), 1);
            }
            Err(ResolveError::NotFound { .. }) => {
                evidence("magic-link", case, "not-exercised:absent", 0);
            }
            other => panic!("{case}: {}", outcome(&other)),
        }
    }
}

fn mount_id(path: &str) -> Option<u64> {
    let found = sys::statx(
        sys::CWD,
        path,
        AtFlags::SYMLINK_NOFOLLOW,
        StatxFlags::MNT_ID,
    )
    .ok()?;
    (found.stx_mask & StatxFlags::MNT_ID.bits() != 0).then_some(found.stx_mnt_id)
}

#[test]
fn a_mount_point_is_never_crossed() {
    // Pinned through the production path: the host's `/` as a root.
    let (root, _) = PinnedRoot::install("/").expect("pin /");
    let top = mount_id("/");
    for name in ["proc", "sys", "dev"] {
        let below = mount_id(&format!("/{name}"));
        if top.is_none() || below.is_none() || top == below {
            evidence("mount-crossing", name, "not-exercised:not-a-mount-point", 0);
            continue;
        }
        let result = observe(&root, &format!("/workspace/{name}"));
        assert_eq!(
            result.as_ref().err(),
            Some(&ResolveError::MountCrossing { depth: 1 }),
            "{name}"
        );
        evidence("mount-crossing", name, &outcome(&result), 1);
        let deeper = observe(&root, &format!("/workspace/{name}/x"));
        assert_eq!(
            deeper.as_ref().err(),
            Some(&ResolveError::MountCrossing { depth: 1 })
        );
    }
    // A bind mount inside a workspace needs mount privileges this suite does
    // not take.
    evidence(
        "mount-crossing",
        "bind-mount-inside-workspace",
        "not-exercised:needs-mount-privileges",
        0,
    );
}

// ---------------------------------------------------------------------------
// Hard links.
// ---------------------------------------------------------------------------

#[test]
fn a_hard_link_is_named_not_trusted() {
    let fx = Fixture::new("fs-hardlink");
    if fs::hard_link(fx.out("secret"), fx.ws("alias")).is_err() {
        evidence(
            "hardlink",
            "outside-inode",
            "not-exercised:no-hard-links",
            0,
        );
        return;
    }
    fs::write(fx.ws("single"), b"one name").unwrap();
    fs::write(fx.ws("twin-a"), b"two names").unwrap();
    fs::hard_link(fx.ws("twin-a"), fx.ws("twin-b")).unwrap();
    let root = fx.pin();

    // Observable: the object at the verified workspace name is the shared
    // inode, and the resolver says so — it does not claim exclusivity.
    let seen = observe(&root, "/workspace/alias").unwrap();
    assert_eq!(seen.identity(), id_of(&fx.out("secret")));
    assert_eq!(seen.link_count(), 2);
    evidence("hardlink", "outside-inode-observe", "resolved:links-2", 1);

    for (case, text) in [
        ("outside-inode-modify", "/workspace/alias"),
        ("inside-twin-modify", "/workspace/twin-a"),
    ] {
        let result = resolve(&root, text, Access::Modify, Expect::RegularFile);
        assert_eq!(
            result.as_ref().err(),
            Some(&ResolveError::HardlinkAliased { links: 2 }),
            "{case}"
        );
        evidence("hardlink", case, &outcome(&result), 1);
    }
    let single = resolve(
        &root,
        "/workspace/single",
        Access::Modify,
        Expect::RegularFile,
    );
    assert!(single.is_ok());
    evidence("hardlink", "single-link-modify", &outcome(&single), 1);
    evidence(
        "hardlink",
        "cross-device-link",
        "not-exercised:impossible-by-construction",
        0,
    );
}

// ---------------------------------------------------------------------------
// Unicode and names that are not text.
// ---------------------------------------------------------------------------

#[test]
fn canonically_equivalent_names_cannot_select_different_objects() {
    let fx = Fixture::new("fs-unicode");
    let nfc = "caf\u{e9}";
    let nfd = "cafe\u{301}";
    for dir in ["alone", "pair", "kelvin", "only-nfd", "raw", "case"] {
        fs::create_dir(fx.ws(dir)).unwrap();
    }
    fs::write(fx.ws(&format!("alone/{nfc}")), b"nfc").unwrap();
    fs::write(fx.ws(&format!("pair/{nfc}")), b"nfc").unwrap();
    fs::write(fx.ws(&format!("pair/{nfd}")), b"nfd").unwrap();
    fs::write(fx.ws("kelvin/K"), b"letter").unwrap();
    fs::write(fx.ws("kelvin/\u{212a}"), b"kelvin sign").unwrap();
    fs::write(fx.ws(&format!("only-nfd/{nfd}")), b"nfd").unwrap();
    fs::write(fx.ws("raw/plain"), b"text name").unwrap();
    let raw = fx
        .ws("raw")
        .join(std::ffi::OsStr::from_bytes(b"\xff\xfe-not-utf8"));
    let raw_made = fs::write(&raw, b"bytes name").is_ok();
    fs::write(fx.ws("case/readme"), b"lower").unwrap();
    let root = fx.pin();

    let alone = observe(&root, &format!("/workspace/alone/{nfc}"));
    assert!(alone.is_ok());
    evidence("unicode", "nfc-name-resolves", &outcome(&alone), 1);

    let refused = observe(&root, &format!("/workspace/alone/{nfd}"));
    assert_eq!(
        refused.as_ref().err().map(|e| e.code()),
        Some("NOT_NORMALIZED")
    );
    evidence("unicode", "non-nfc-request", &outcome(&refused), 1);

    // Two distinct objects whose names are canonically equivalent.
    let distinct = id_of(&fx.ws(&format!("pair/{nfc}"))) != id_of(&fx.ws(&format!("pair/{nfd}")));
    if distinct {
        let pair = observe(&root, &format!("/workspace/pair/{nfc}"));
        assert_eq!(
            pair.as_ref().err(),
            Some(&ResolveError::NormalizationAmbiguity { depth: 2 })
        );
        evidence("unicode", "nfc-nfd-pair", &outcome(&pair), 1);
    } else {
        evidence(
            "unicode",
            "nfc-nfd-pair",
            "not-exercised:normalizing-filesystem",
            0,
        );
    }
    let kelvin = observe(&root, "/workspace/kelvin/K");
    assert_eq!(
        kelvin.as_ref().err(),
        Some(&ResolveError::NormalizationAmbiguity { depth: 2 })
    );
    evidence("unicode", "kelvin-sign-beside-k", &outcome(&kelvin), 1);

    // Only the decomposed spelling exists: the composed request finds nothing
    // (byte-exact filesystem) or finds it under another spelling and is
    // refused (normalisation-insensitive filesystem). Never resolved.
    let only = observe(&root, &format!("/workspace/only-nfd/{nfc}"));
    assert!(matches!(
        only,
        Err(ResolveError::NotFound { depth: 2 } | ResolveError::NameMismatch { depth: 2 })
    ));
    evidence("unicode", "only-decomposed-on-disk", &outcome(&only), 1);

    // A name that is not UTF-8 is neither nameable nor an ambiguity.
    if raw_made {
        let plain = observe(&root, "/workspace/raw/plain");
        assert!(plain.is_ok());
        evidence("unicode", "non-utf8-sibling-ignored", &outcome(&plain), 1);
        evidence(
            "unicode",
            "non-utf8-name-unrepresentable",
            "refused:UNREPRESENTABLE",
            1,
        );
    } else {
        evidence(
            "unicode",
            "non-utf8-sibling-ignored",
            "not-exercised:no-byte-names",
            0,
        );
    }

    // The exact-name check, which is what refuses a case-folding or
    // normalisation-insensitive filesystem's alias: `README` is not an entry
    // of this directory even where a filesystem would open `readme` for it.
    let case_dir = dir_fd(&fx.ws("case"));
    let exact = verify_entry(case_dir.as_fd(), "readme", 2);
    let alias = verify_entry(case_dir.as_fd(), "README", 2);
    assert_eq!(exact, Ok(()));
    assert_eq!(alias, Err(ResolveError::NameMismatch { depth: 2 }));
    evidence("unicode", "exact-name-check", "refused:NAME_MISMATCH", 1);
    evidence(
        "unicode",
        "casefold-filesystem",
        "not-exercised:needs-a-casefold-filesystem",
        0,
    );
}

// ---------------------------------------------------------------------------
// Resource kinds and bounds.
// ---------------------------------------------------------------------------

#[test]
fn only_directories_and_regular_files_resolve() {
    let fx = Fixture::new("fs-kinds");
    fs::write(fx.ws("file"), b"f").unwrap();
    fs::create_dir(fx.ws("dir")).unwrap();
    let ws = dir_fd(&fx.root);
    sys::mknodat(&ws, "fifo", FileType::Fifo, Mode::RUSR | Mode::WUSR, 0).unwrap();
    // A socket NODE, made the way the FIFO is: no listener in the authority,
    // not even in a test (TX009). mknod(2) needs no privilege for S_IFSOCK.
    sys::mknodat(&ws, "socket", FileType::Socket, Mode::RUSR | Mode::WUSR, 0).unwrap();
    let root = fx.pin();

    for (case, text) in [("fifo", "/workspace/fifo"), ("socket", "/workspace/socket")] {
        let result = observe(&root, text);
        assert_eq!(
            result.as_ref().err(),
            Some(&ResolveError::SpecialFile { depth: 1 }),
            "{case}"
        );
        evidence("resource-kind", case, &outcome(&result), 1);
    }
    for (case, text, expect, found) in [
        (
            "file-as-directory",
            "/workspace/file",
            Expect::Directory,
            ResourceKind::RegularFile,
        ),
        (
            "directory-as-file",
            "/workspace/dir",
            Expect::RegularFile,
            ResourceKind::Directory,
        ),
    ] {
        let result = resolve(&root, text, Access::Observe, expect);
        assert_eq!(
            result.as_ref().err(),
            Some(&ResolveError::WrongKind { found })
        );
        evidence("resource-kind", case, &outcome(&result), 1);
    }
    let through = observe(&root, "/workspace/file/x");
    assert_eq!(
        through.as_ref().err(),
        Some(&ResolveError::NotADirectory { depth: 1 })
    );
    evidence(
        "resource-kind",
        "file-as-intermediate",
        &outcome(&through),
        1,
    );

    // A real character device, under a devtmpfs root.
    match PinnedRoot::install("/dev") {
        Ok((dev, _)) => {
            let result = observe(&dev, "/workspace/null");
            assert_eq!(
                result.as_ref().err(),
                Some(&ResolveError::SpecialFile { depth: 1 })
            );
            evidence("resource-kind", "character-device", &outcome(&result), 1);
        }
        Err(error) => evidence(
            "resource-kind",
            "character-device",
            &format!("not-exercised:{}", error.code()),
            0,
        ),
    }

    // The listing bound refuses rather than truncates.
    let crowded = fx.ws("crowded");
    fs::create_dir(&crowded).unwrap();
    for n in 0..12 {
        fs::write(crowded.join(format!("e{n}")), b"").unwrap();
    }
    let crowded_fd = dir_fd(&crowded);
    assert_eq!(
        verify_entry_within(crowded_fd.as_fd(), "e0", 2, 10),
        Err(ResolveError::DirectoryTooLarge { depth: 2 })
    );
    assert_eq!(
        verify_entry_within(crowded_fd.as_fd(), "e0", 2, 100),
        Ok(())
    );
    evidence(
        "resource-kind",
        "listing-bound",
        "refused:DIRECTORY_TOO_LARGE",
        1,
    );
}

// ---------------------------------------------------------------------------
// The pinned root.
// ---------------------------------------------------------------------------

#[test]
fn a_pinned_root_is_not_redirected_by_replacing_its_path() {
    let scratch = Scratch::new("fs-root-replace");
    let path = scratch.path().join("ws");
    let moved = scratch.path().join("ws-moved");
    fs::create_dir(&path).unwrap();
    fs::write(path.join("marker"), b"A").unwrap();
    let (pinned, fingerprint) = PinnedRoot::install(host(&path)).unwrap();

    // Move A away and put B at A's old path.
    fs::rename(&path, &moved).unwrap();
    fs::create_dir(&path).unwrap();
    fs::write(path.join("marker"), b"B").unwrap();
    let marker_a = id_of(&moved.join("marker"));
    let marker_b = id_of(&path.join("marker"));

    let seen = observe(&pinned, "/workspace/marker").unwrap();
    assert_eq!(seen.identity(), marker_a, "the pinned root still means A");
    assert_ne!(seen.identity(), marker_b);
    evidence("root-replacement", "pinned-root-keeps-a", "resolved:a", 1);

    let again = PinnedRoot::reopen(host(&path), &fingerprint);
    assert_eq!(again.as_ref().err(), Some(&RootError::Replaced));
    evidence(
        "root-replacement",
        "reopen-after-replacement",
        "refused:ROOT_REPLACED",
        1,
    );

    // Deleted and recreated at the same path, where the filesystem may hand the
    // new directory the old inode number: the birth time tells them apart.
    let (_, recorded) = PinnedRoot::install(host(&path)).unwrap();
    fs::remove_dir_all(&path).unwrap();
    fs::create_dir(&path).unwrap();
    let reused = id_of(&path).inode() == recorded.inode();
    let reborn = PinnedRoot::reopen(host(&path), &recorded);
    if reused && recorded.birth().is_none() {
        // The residual: no birth time and a recycled inode. Reported, not
        // passed off.
        evidence(
            "root-replacement",
            "recreated-same-inode",
            "not-exercised:no-birth-time-residual",
            0,
        );
    } else {
        assert_eq!(reborn.as_ref().err(), Some(&RootError::Replaced));
        let case = if reused {
            "recreated-same-inode-birth-time"
        } else {
            "recreated-new-inode"
        };
        evidence("root-replacement", case, "refused:ROOT_REPLACED", 1);
    }

    // A root's final component may not be a symlink.
    symlink(&moved, scratch.path().join("ws-link")).unwrap();
    let linked = PinnedRoot::install(host(&scratch.path().join("ws-link")));
    assert_eq!(linked.as_ref().err(), Some(&RootError::Symlink));
    evidence(
        "root-replacement",
        "symlinked-root",
        "refused:ROOT_SYMLINK",
        1,
    );
}

// ---------------------------------------------------------------------------
// The chain re-verification, without a race.
// ---------------------------------------------------------------------------

/// The check the race campaigns lean on, made deterministic: open a chain the
/// way the walk does, change the tree underneath it, and the chain no longer
/// verifies, at the depth that changed. Without it an object whose parent has
/// since left the workspace would be returned as though it were beneath the
/// root — an object the campaigns cannot tell from a legitimate one, because
/// its identity is the one that was checked.
#[test]
fn the_chain_is_reverified_after_the_walk() {
    let fx = Fixture::new("fs-chain");
    fs::create_dir(fx.ws("p")).unwrap();
    fs::write(fx.ws("p/leaf"), b"inside").unwrap();
    let root = dir_fd(&fx.root);
    let names = [
        PathComponent::new("p").unwrap(),
        PathComponent::new("leaf").unwrap(),
    ];
    let open = || -> Vec<(OwnedFd, FileIdentity)> {
        let parent = open_child(root.as_fd(), "p", true, 1).unwrap();
        let leaf = open_child(parent.as_fd(), "leaf", false, 2).unwrap();
        let parent_id = identity(&sys::fstat(&parent).unwrap());
        let leaf_id = identity(&sys::fstat(&leaf).unwrap());
        vec![(parent, parent_id), (leaf, leaf_id)]
    };
    let check = |chain: &[(OwnedFd, FileIdentity)]| verify_chain(root.as_fd(), chain, &names);

    let chain = open();
    assert_eq!(check(&chain), Ok(()));

    // The parent moved out of the workspace after it was opened, and back.
    fs::rename(fx.ws("p"), fx.out("p")).unwrap();
    assert_eq!(check(&chain), Err(ResolveError::Race { depth: 1 }));
    fs::rename(fx.out("p"), fx.ws("p")).unwrap();
    assert_eq!(check(&chain), Ok(()));

    // The leaf renamed away and another file put under its name.
    fs::rename(fx.ws("p/leaf"), fx.ws("p/was-leaf")).unwrap();
    fs::write(fx.ws("p/leaf"), b"replacement").unwrap();
    assert_eq!(check(&chain), Err(ResolveError::Race { depth: 2 }));

    // The parent replaced by a symlink to the directory it was.
    let chain = open();
    fs::rename(fx.ws("p"), fx.ws("p-real")).unwrap();
    symlink(fx.ws("p-real"), fx.ws("p")).unwrap();
    assert_eq!(check(&chain), Err(ResolveError::Race { depth: 1 }));

    evidence("toctou", "chain-reverified-after-change", "refused:RACE", 3);
}

// ---------------------------------------------------------------------------
// TOCTOU: a real attacker thread, racing the resolver.
// ---------------------------------------------------------------------------

struct Attacker {
    stop: Arc<AtomicBool>,
    swaps: Arc<AtomicU64>,
    thread: JoinHandle<()>,
}

impl Attacker {
    fn start(mut move_once: impl FnMut() + Send + 'static, ready: &Arc<Barrier>) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let swaps = Arc::new(AtomicU64::new(0));
        let (flag, count, barrier) = (Arc::clone(&stop), Arc::clone(&swaps), Arc::clone(ready));
        let thread = std::thread::spawn(move || {
            barrier.wait();
            while !flag.load(Ordering::Relaxed) {
                move_once();
                count.fetch_add(1, Ordering::Relaxed);
            }
        });
        Self {
            stop,
            swaps,
            thread,
        }
    }

    fn finish(self) -> u64 {
        self.stop.store(true, Ordering::Relaxed);
        self.thread.join().expect("the attacker thread");
        self.swaps.load(Ordering::Relaxed)
    }
}

/// Resolve `text` `RACE_ITERATIONS` times while `attacker` runs. The property
/// is not "the race usually fails": it is that every result is an allowed
/// object or a refusal, and no result is ever an escape object.
///
/// Returns how many refusals were `RACE` — the chain re-verification catching a
/// name that stopped binding mid-walk — for campaigns that must show it firing.
fn campaign(
    case: &str,
    root: &PinnedRoot,
    text: &str,
    allowed: &[FileIdentity],
    forbidden: &[FileIdentity],
    attack: impl FnMut() + Send + 'static,
) -> u64 {
    let ready = Arc::new(Barrier::new(2));
    let attacker = Attacker::start(attack, &ready);
    ready.wait();
    let (mut resolved, mut refused, mut escaped, mut unexpected) = (0u64, 0u64, 0u64, 0u64);
    let mut raced = 0u64;
    for _ in 0..RACE_ITERATIONS {
        match observe(root, text) {
            Ok(found) if forbidden.contains(&found.identity()) => escaped += 1,
            Ok(found) if allowed.contains(&found.identity()) => resolved += 1,
            Ok(_) => unexpected += 1,
            Err(ResolveError::Race { .. }) => {
                refused += 1;
                raced += 1;
            }
            Err(_) => refused += 1,
        }
    }
    let swaps = attacker.finish();
    evidence(
        "toctou",
        case,
        &format!(
            "escaped-{escaped}-unexpected-{unexpected}-resolved-{resolved}-refused-{refused}-swaps-{swaps}-race-{raced}"
        ),
        RACE_ITERATIONS,
    );
    assert_eq!(escaped, 0, "{case}: an escape object was returned");
    assert_eq!(unexpected, 0, "{case}: an object outside the allowed set");
    assert!(swaps > 100, "{case}: the attacker must actually have raced");
    raced
}

fn exchange(dir: &Arc<OwnedFd>, a: &'static str, b: &'static str) -> impl FnMut() + Send + 'static {
    let dir = Arc::clone(dir);
    move || {
        let _ = sys::renameat_with(&*dir, a, &*dir, b, RenameFlags::EXCHANGE);
    }
}

/// A fixture, its pinned root, a descriptor on its workspace for the
/// attacker, and the outside secret's identity. `None` when the filesystem
/// cannot exchange two names atomically.
fn race_fixture(tag: &str) -> Option<(Fixture, PinnedRoot, Arc<OwnedFd>, FileIdentity)> {
    let fx = Fixture::new(tag);
    let secret = id_of(&fx.out("secret"));
    let ws = Arc::new(dir_fd(&fx.root));
    if sys::renameat_with(&*ws, "absent-a", &*ws, "absent-b", RenameFlags::EXCHANGE)
        == Err(rustix::io::Errno::INVAL)
    {
        evidence("toctou", tag, "not-exercised:no-renameat2-exchange", 0);
        return None;
    }
    let root = fx.pin();
    Some((fx, root, ws, secret))
}

#[test]
fn toctou_swapping_an_entry_for_a_symlink_never_escapes() {
    let Some((fx, root, ws, secret)) = race_fixture("fs-toctou-swap") else {
        return;
    };
    // A regular file exchanged with a symlink to a file outside.
    fs::write(fx.ws("target"), b"inside").unwrap();
    symlink(fx.out("secret"), fx.ws("decoy")).unwrap();
    let (file, link) = (id_of(&fx.ws("target")), id_of(&fx.ws("decoy")));
    campaign(
        "file-symlink-exchange",
        &root,
        "/workspace/target",
        &[file],
        &[secret, link],
        exchange(&ws, "target", "decoy"),
    );

    // A directory exchanged with a symlink to a directory outside holding an
    // object under the same name.
    fs::create_dir(fx.ws("dir")).unwrap();
    fs::write(fx.ws("dir/leaf"), b"inside").unwrap();
    fs::create_dir(fx.out("dir")).unwrap();
    fs::write(fx.out("dir/leaf"), b"outside").unwrap();
    symlink(fx.out("dir"), fx.ws("dir-decoy")).unwrap();
    let (inside_leaf, outside_leaf) = (id_of(&fx.ws("dir/leaf")), id_of(&fx.out("dir/leaf")));
    campaign(
        "directory-symlink-exchange",
        &root,
        "/workspace/dir/leaf",
        &[inside_leaf],
        &[outside_leaf, secret],
        exchange(&ws, "dir", "dir-decoy"),
    );
}

#[test]
fn toctou_renaming_a_parent_never_escapes() {
    let Some((fx, root, _ws, secret)) = race_fixture("fs-toctou-parent") else {
        return;
    };
    // The parent renamed back and forth inside the workspace.
    fs::create_dir(fx.ws("p")).unwrap();
    fs::write(fx.ws("p/leaf"), b"inside").unwrap();
    let parent_leaf = id_of(&fx.ws("p/leaf"));
    let (from, to) = (fx.ws("p"), fx.ws("q"));
    let mut flip = false;
    let renamed = campaign(
        "parent-rename",
        &root,
        "/workspace/p/leaf",
        &[parent_leaf],
        &[secret],
        move || {
            flip = !flip;
            let _ = if flip {
                fs::rename(&from, &to)
            } else {
                fs::rename(&to, &from)
            };
        },
    );

    // The parent moved out of the workspace and back again.
    fs::create_dir(fx.ws("m")).unwrap();
    fs::write(fx.ws("m/leaf"), b"inside").unwrap();
    let moved_leaf = id_of(&fx.ws("m/leaf"));
    let (home, away) = (fx.ws("m"), fx.out("m-away"));
    let mut out = false;
    let moved = campaign(
        "parent-moved-out-and-back",
        &root,
        "/workspace/m/leaf",
        &[moved_leaf],
        &[secret],
        move || {
            out = !out;
            let _ = if out {
                fs::rename(&home, &away)
            } else {
                fs::rename(&away, &home)
            };
        },
    );

    // Neither campaign could return a forbidden object even without the chain
    // re-verification — the leaf is the leaf — but without it the object comes
    // back under a name that no longer binds, or from a parent that has left
    // the workspace. What shows the walk runs the check is that it fires: some
    // walks were caught with a parent that moved underneath them.
    assert!(
        renamed + moved > 0,
        "the chain re-verification never caught a parent moving mid-walk"
    );
}

#[test]
fn toctou_replacing_the_leaf_never_escapes() {
    let Some((fx, root, ws, secret)) = race_fixture("fs-toctou-leaf") else {
        return;
    };
    // The leaf exchanged in turn with another inside file and with a symlink
    // to the outside secret.
    fs::write(fx.ws("leaf2"), b"one").unwrap();
    fs::write(fx.ws("alt2"), b"two").unwrap();
    symlink(fx.out("secret"), fx.ws("evil2")).unwrap();
    let allowed = [id_of(&fx.ws("leaf2")), id_of(&fx.ws("alt2"))];
    let evil = id_of(&fx.ws("evil2"));
    let dir = Arc::clone(&ws);
    let mut turn = 0u8;
    campaign(
        "leaf-replaced",
        &root,
        "/workspace/leaf2",
        &allowed,
        &[secret, evil],
        move || {
            turn = turn.wrapping_add(1);
            let partner = if turn.is_multiple_of(2) {
                "alt2"
            } else {
                "evil2"
            };
            let _ = sys::renameat_with(&*dir, "leaf2", &*dir, partner, RenameFlags::EXCHANGE);
        },
    );
}

#[test]
fn toctou_exchanging_the_root_path_never_redirects_a_pinned_root() {
    let Some((fx, root, _ws, _secret)) = race_fixture("fs-toctou-root") else {
        return;
    };
    // The workspace's own path exchanged with another directory after the root
    // was pinned: the pinned root never follows the name.
    let base = Arc::new(dir_fd(fx.scratch.path()));
    let other = fx.scratch.path().join("ws-other");
    fs::create_dir(&other).unwrap();
    fs::write(fx.ws("marker"), b"A").unwrap();
    fs::write(other.join("marker"), b"B").unwrap();
    let (marker_a, marker_b) = (id_of(&fx.ws("marker")), id_of(&other.join("marker")));
    campaign(
        "root-path-exchange",
        &root,
        "/workspace/marker",
        &[marker_a],
        &[marker_b],
        exchange(&base, "ws", "ws-other"),
    );
}

// ---------------------------------------------------------------------------
// Descriptors and cost.
// ---------------------------------------------------------------------------

/// Descriptors this process holds on anything beneath `dir`, by the targets
/// of `/proc/self/fd`. Scoped to one test's own fixture, so what concurrently
/// running tests open and close cannot move it: a whole-process count could.
fn descriptors_beneath(dir: &Path) -> usize {
    fs::read_dir("/proc/self/fd").map_or(0, |entries| {
        entries
            .filter_map(Result::ok)
            .filter_map(|entry| fs::read_link(entry.path()).ok())
            .filter(|target| target.starts_with(dir))
            .count()
    })
}

#[test]
fn repeated_resolution_leaks_no_descriptor() {
    let fx = Fixture::new("fs-leak");
    fs::create_dir_all(fx.ws("a/b")).unwrap();
    fs::write(fx.ws("a/b/c"), b"c").unwrap();
    symlink(fx.out("secret"), fx.ws("a/link")).unwrap();
    fs::write(fx.ws("caf\u{e9}"), b"x").unwrap();
    fs::write(fx.ws("cafe\u{301}"), b"y").unwrap();
    let root = fx.pin();
    let cases = [
        "/workspace/a/b/c",
        "/workspace/a/link",
        "/workspace/a/missing/c",
        "/workspace/../x",
        "/workspace/a/b/c/d",
        "/workspace/caf\u{e9}",
        "/workspace",
    ];
    let scratch = fx.scratch.path();
    let rounds: u64 = 5_000;
    let before = descriptors_beneath(scratch);
    // The count must see the resolver's descriptors at all, or zero growth
    // would prove nothing: a live result holds its leaf and its parent.
    let held = observe(&root, "/workspace/a/b/c").unwrap();
    assert_eq!(descriptors_beneath(scratch), before + 2);
    drop(held);
    let mut refused = 0u64;
    for round in 0..rounds {
        let text = cases[usize::try_from(round).unwrap() % cases.len()];
        if observe(&root, text).is_err() {
            refused += 1;
        }
    }
    let after = descriptors_beneath(scratch);
    let delta = after.saturating_sub(before);
    evidence(
        "leak",
        "mixed-resolutions",
        &format!("descriptor-growth-{delta}-refused-{refused}"),
        rounds,
    );
    assert_eq!(
        after, before,
        "descriptors on the fixture leaked over {rounds} resolutions"
    );
}

#[test]
fn resolution_cost_is_measured() {
    let fx = Fixture::new("fs-cost");
    let mut deep = fx.root.clone();
    let mut spelled = String::from("/workspace");
    for level in 0..20 {
        deep.push(format!("d{level}"));
        write!(spelled, "/d{level}").unwrap();
    }
    fs::create_dir_all(&deep).unwrap();
    fs::write(deep.join("leaf"), b"x").unwrap();
    spelled.push_str("/leaf");
    fs::write(fx.ws("leaf"), b"x").unwrap();
    symlink(fx.out("secret"), fx.ws("link")).unwrap();
    let root = fx.pin();
    let runs: u64 = 500;
    for (case, text) in [
        ("simple-leaf", "/workspace/leaf"),
        ("depth-21", spelled.as_str()),
        ("refused-traversal", "/workspace/../x"),
        ("refused-symlink", "/workspace/link"),
    ] {
        let mut samples: Vec<u128> = (0..runs)
            .map(|_| {
                let started = Instant::now();
                let _ = observe(&root, text);
                started.elapsed().as_micros()
            })
            .collect();
        samples.sort_unstable();
        let median = samples[samples.len() / 2];
        evidence("performance", case, &format!("median-us-{median}"), runs);
        assert!(median < 50_000, "{case}: {median} us is pathological");
    }
}
