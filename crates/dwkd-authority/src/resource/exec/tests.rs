//! The executable resolver against real files (M4d, ADR-0045 §5): what it
//! accepts, every class it refuses, and the identity it produces — path and
//! digest — checked independently of it.
//!
//! The trees are built with `std` in a private scratch directory owned by the
//! test process, whose uid stands in for the authority's. Two conditions need
//! another principal and are exercised by the hosted cross-uid job instead: a
//! file owned by a third uid, and a file carrying `security.capability`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha256};

use super::{ExecError, MAX_SYMLINKS, Untrusted, resolve};
use crate::scratch::Scratch;

/// A minimal file the resolver reads as native: the ELF magic and some bytes.
/// Nothing here is ever executed.
const ELF: &[u8] = b"\x7fELF\x02\x01\x01\x00direwolf-m4d-test-object";

/// The test's own uid: the owner of a file it just created.
fn own_uid(dir: &Path) -> u32 {
    let probe = dir.join(".uid");
    fs::write(&probe, b"").unwrap();
    let uid = fs::metadata(&probe).unwrap().uid();
    fs::remove_file(&probe).unwrap();
    uid
}

struct Tree {
    scratch: Scratch,
    uid: u32,
}

impl Tree {
    fn new(tag: &str) -> Self {
        let scratch = Scratch::new(tag);
        let uid = own_uid(scratch.path());
        Self { scratch, uid }
    }

    /// The scratch directory's canonical path: the resolver's answer is
    /// canonical, so the comparison must be too.
    fn root(&self) -> PathBuf {
        fs::canonicalize(self.scratch.path()).unwrap()
    }

    fn file(&self, relative: &str, content: &[u8], mode: u32) -> PathBuf {
        let path = self.root().join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&path, content).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    fn resolve(&self, path: &Path) -> Result<super::ResolvedExecutable, ExecError> {
        resolve(path.to_str().unwrap(), self.uid)
    }
}

fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

#[test]
fn a_trusted_native_file_resolves_to_its_canonical_path_and_its_digest() {
    let tree = Tree::new("exec-ok");
    let path = tree.file("bin/tool", ELF, 0o755);
    let resolved = tree.resolve(&path).unwrap();
    assert_eq!(
        resolved.identity().to_string(),
        format!("{}@{}", path.display(), hex(&Sha256::digest(ELF)))
    );
    let meta = fs::metadata(&path).unwrap();
    assert_eq!(resolved.object().inode(), meta.ino());
    assert_eq!(resolved.object().device(), meta.dev());
    assert_eq!(resolved.size(), u64::try_from(ELF.len()).unwrap());
    assert_eq!(resolved.symlinks_followed(), 0);
}

#[test]
fn a_symlink_chain_resolves_to_the_final_object_and_names_its_canonical_path() {
    let tree = Tree::new("exec-links");
    let tool = tree.file("real/lib/tool", ELF, 0o755);
    let root = tree.root();
    fs::create_dir_all(root.join("bin")).unwrap();
    // Relative, with `..`; absolute; a directory link on the way.
    symlink("../real/lib/tool", root.join("bin/relative")).unwrap();
    symlink(&tool, root.join("bin/absolute")).unwrap();
    symlink("real/lib", root.join("libdir")).unwrap();
    symlink("relative", root.join("bin/twice")).unwrap();
    for (spelled, links) in [
        (root.join("bin/relative"), 1),
        (root.join("bin/absolute"), 1),
        (root.join("libdir/tool"), 1),
        (root.join("bin/twice"), 2),
    ] {
        let resolved = tree.resolve(&spelled).unwrap();
        assert_eq!(
            resolved.identity().path().to_string(),
            tool.display().to_string(),
            "{}",
            spelled.display()
        );
        assert_eq!(resolved.symlinks_followed(), links, "{}", spelled.display());
    }
}

#[test]
fn the_symlink_bound_is_exact_and_a_loop_is_refused() {
    let tree = Tree::new("exec-bound");
    let root = tree.root();
    tree.file("tool", ELF, 0o755);
    // link0 -> tool, link{n} -> link{n-1}: link{n} is n+1 links deep.
    symlink("tool", root.join("link0")).unwrap();
    for n in 1..=MAX_SYMLINKS {
        symlink(format!("link{}", n - 1), root.join(format!("link{n}"))).unwrap();
    }
    let at = root.join(format!("link{}", MAX_SYMLINKS - 1));
    assert_eq!(tree.resolve(&at).unwrap().symlinks_followed(), MAX_SYMLINKS);
    let past = root.join(format!("link{MAX_SYMLINKS}"));
    assert_eq!(tree.resolve(&past).err(), Some(ExecError::SymlinkLimit));
    symlink("loop-b", root.join("loop-a")).unwrap();
    symlink("loop-a", root.join("loop-b")).unwrap();
    assert_eq!(
        tree.resolve(&root.join("loop-a")).err(),
        Some(ExecError::SymlinkLimit)
    );
}

#[test]
fn a_script_or_anything_not_native_is_refused_by_its_bytes() {
    let tree = Tree::new("exec-kind");
    for (name, content, expected) in [
        ("script", &b"#!/bin/sh\necho hi\n"[..], ExecError::Script),
        (
            "env-script",
            &b"#!/usr/bin/env python3\n"[..],
            ExecError::Script,
        ),
        ("text", &b"echo hi\n"[..], ExecError::NotNative),
        ("empty", &b""[..], ExecError::NotNative),
        ("short", &b"\x7fE"[..], ExecError::NotNative),
        ("pe", &b"MZ\x90\x00"[..], ExecError::NotNative),
    ] {
        let path = tree.file(name, content, 0o755);
        assert_eq!(tree.resolve(&path).err(), Some(expected), "{name}");
    }
}

#[test]
fn modes_that_let_another_principal_change_the_bytes_are_refused() {
    let tree = Tree::new("exec-mode");
    for (name, mode, expected) in [
        ("plain", 0o644, ExecError::NotExecutable),
        (
            "group-writable",
            0o775,
            ExecError::Untrusted(Untrusted::Writable),
        ),
        (
            "world-writable",
            0o757,
            ExecError::Untrusted(Untrusted::Writable),
        ),
        ("setuid", 0o4755, ExecError::Untrusted(Untrusted::SetId)),
        ("setgid", 0o2755, ExecError::Untrusted(Untrusted::SetId)),
    ] {
        let path = tree.file(name, ELF, mode);
        assert_eq!(tree.resolve(&path).err(), Some(expected), "{name}");
    }
    // The owner's own write bit is the owner's; it is not another principal.
    let owner_writable = tree.file("owner-writable", ELF, 0o755);
    assert!(tree.resolve(&owner_writable).is_ok());
    let execute_only = tree.file("execute-only", ELF, 0o711);
    assert!(tree.resolve(&execute_only).is_ok());
}

#[test]
fn a_directory_another_principal_could_rebind_is_refused_unless_sticky() {
    let tree = Tree::new("exec-dir");
    let path = tree.file("shared/tool", ELF, 0o755);
    let shared = tree.root().join("shared");
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();
    assert_eq!(
        tree.resolve(&path).err(),
        Some(ExecError::Untrusted(Untrusted::Directory))
    );
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o1777)).unwrap();
    assert!(tree.resolve(&path).is_ok());
    // A directory the authority does not own and root does not own either:
    // with a different trusted uid, the test's own directories are foreign.
    assert_eq!(
        resolve(path.to_str().unwrap(), tree.uid.wrapping_add(1)).err(),
        Some(ExecError::Untrusted(Untrusted::Directory))
    );
}

#[test]
fn what_is_not_a_regular_file_at_the_end_of_a_path_is_refused() {
    let tree = Tree::new("exec-shape");
    let root = tree.root();
    fs::create_dir_all(root.join("dir")).unwrap();
    assert_eq!(
        tree.resolve(&root.join("dir")).err(),
        Some(ExecError::NotRegular)
    );
    // A device, root's own and executable by nobody's choice: its type alone
    // refuses it (no listener in the authority, TX009, even to make a socket).
    assert_eq!(
        tree.resolve(Path::new("/dev/null")).err(),
        Some(ExecError::NotRegular)
    );
    let file = tree.file("file", ELF, 0o755);
    assert_eq!(
        tree.resolve(&file.join("below")).err(),
        Some(ExecError::NotADirectory)
    );
    assert_eq!(
        tree.resolve(&root.join("missing")).err(),
        Some(ExecError::NotFound)
    );
    symlink("missing", root.join("dangling")).unwrap();
    assert_eq!(
        tree.resolve(&root.join("dangling")).err(),
        Some(ExecError::NotFound)
    );
}

#[test]
fn the_kernels_own_views_are_refused_whatever_they_point_at() {
    // `/proc/self/exe` names this very test binary, which would otherwise
    // pass every check: procfs is refused by type, not by content.
    let uid = own_uid(Scratch::new("exec-proc").path());
    assert_eq!(
        resolve("/proc/self/exe", uid).err(),
        Some(ExecError::Untrusted(Untrusted::Filesystem))
    );
    assert_eq!(
        resolve("/proc/self/fd/0", uid).err(),
        Some(ExecError::Untrusted(Untrusted::Filesystem))
    );
}

#[test]
fn a_file_past_the_size_bound_is_refused_before_it_is_read() {
    let tree = Tree::new("exec-size");
    let path = tree.file("huge", ELF, 0o755);
    // Sparse: the bound is judged from the size, before any byte is hashed.
    let file = fs::OpenOptions::new().write(true).open(&path).unwrap();
    file.set_len(dwk_proto::limits::MAX_EXECUTABLE_BYTES + 1)
        .unwrap();
    drop(file);
    assert_eq!(tree.resolve(&path).err(), Some(ExecError::TooLarge));
}

#[test]
fn a_spelling_the_grammar_refuses_is_refused_before_anything_is_opened() {
    let tree = Tree::new("exec-spell");
    let path = tree.file("bin/tool", ELF, 0o755);
    let text = path.to_str().unwrap();
    for bad in [
        "tool".to_owned(),
        format!("{text}/"),
        text.replace("/bin/", "/bin/./"),
        text.replace("/bin/", "/bin/../bin/"),
        text.replace("/bin/", "//bin/"),
    ] {
        assert_eq!(
            resolve(&bad, tree.uid).err(),
            Some(ExecError::PathInvalid),
            "{bad}"
        );
    }
    // A link whose target the grammar cannot read.
    let root = tree.root();
    symlink("bad\u{7}name", root.join("control")).unwrap();
    assert_eq!(
        tree.resolve(&root.join("control")).err(),
        Some(ExecError::PathInvalid)
    );
}

#[test]
fn a_real_system_executable_resolves_through_the_hosts_own_links() {
    // `/bin/sh` is a symlink chain on every supported Linux; the identity is
    // the final object's, root-owned and not writable by anyone else.
    let uid = own_uid(Scratch::new("exec-host").path());
    let resolved = resolve("/bin/sh", uid).unwrap();
    let canonical = fs::canonicalize("/bin/sh").unwrap();
    assert_eq!(
        resolved.identity().path().to_string(),
        canonical.display().to_string()
    );
    assert_eq!(
        resolved.identity().digest().to_string(),
        hex(&Sha256::digest(fs::read(&canonical).unwrap()))
    );
}

#[test]
fn the_handoff_opens_the_hashed_object_or_refuses() {
    let tree = Tree::new("exec-handoff");
    let path = tree.file("tool", ELF, 0o755);
    let resolved = tree.resolve(&path).unwrap();
    let object = resolved.object();
    let handoff = resolved.into_exec_handoff().unwrap();
    assert_eq!(handoff.object(), object);
    let (fd, identity) = handoff.into_transfer_descriptor();
    assert_eq!(identity, object);
    let meta = fs::File::from(fd).metadata().unwrap();
    assert_eq!(meta.ino(), object.inode());

    // The name rebound to another object after resolution: refused.
    let resolved = tree.resolve(&path).unwrap();
    let other = tree.file("other", ELF, 0o755);
    fs::rename(&other, &path).unwrap();
    assert_eq!(resolved.into_exec_handoff().err(), Some(ExecError::Race));

    // The object made group-writable after resolution: refused.
    let resolved = tree.resolve(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o775)).unwrap();
    assert_eq!(
        resolved.into_exec_handoff().err(),
        Some(ExecError::Untrusted(Untrusted::Writable))
    );
}

#[test]
fn a_hard_link_is_its_own_canonical_path() {
    let tree = Tree::new("exec-hardlink");
    let original = tree.file("original", ELF, 0o755);
    let alias = tree.root().join("alias");
    fs::hard_link(&original, &alias).unwrap();
    let a = tree.resolve(&original).unwrap();
    let b = tree.resolve(&alias).unwrap();
    // One object, two identities: a policy naming one does not name the other.
    assert_eq!(a.object(), b.object());
    assert_eq!(a.identity().digest(), b.identity().digest());
    assert_ne!(a.identity(), b.identity());
}
