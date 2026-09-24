//! The write-broker permission model, measured on the real kernel (M4c,
//! ADR-0044 §3).
//!
//! The question M4c had to answer before any namespace mutation was written:
//! **does holding a checked directory descriptor let the broker create,
//! rename or remove names in that directory?** It does not. `openat(O_CREAT)`,
//! `mkdirat`, `renameat2` and `unlinkat` check the *calling process's*
//! credentials against the parent directory's permission bits, whatever
//! descriptor names the directory — and a lookup through a directory
//! descriptor still needs search permission on it. A descriptor is a reference
//! to an object, not a grant of the rights to change a directory's names.
//!
//! This file proves it with one identity, which is enough for that question:
//! the owner of a directory whose own bits deny write is refused exactly as a
//! stranger would be, because the same DAC check runs either way. What one
//! identity cannot show — that a *different* uid, the broker's, is granted the
//! mutation by ordinary group or ACL rights and holds them ambiently, by path,
//! without any descriptor — is the cross-uid half, which needs a real second
//! identity and runs in the hosted three-identity job
//! (`tests/permission_cross_uid` in `dwkd-authority`'s foreign suite).
//!
//! Every assertion is on the kernel's own answer to the maintained safe
//! wrapper the broker uses (`rustix`); nothing here is modelled.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

use dwk_proto as _;
// Linux-only, like the operations that digest with it.
#[cfg(target_os = "linux")]
use sha2 as _;

#[cfg(target_os = "linux")]
mod linux {
    use std::os::fd::OwnedFd;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};

    use rustix::fs::{AtFlags, CWD, Dir, Mode, OFlags, RenameFlags};
    use rustix::io::Errno;

    fn evidence(case: &str, outcome: &str) {
        println!(
            "FSOP-EVIDENCE {{\"suite\":\"permission-model\",\"case\":\"{case}\",\"outcome\":\"{outcome}\",\"count\":1}}"
        );
    }

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "dw-perm-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            // Restore search and write so the tree can be removed.
            let _ = restore(&self.0);
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn restore(dir: &Path) -> std::io::Result<()> {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755))?;
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            if std::fs::symlink_metadata(&path)?.is_dir() {
                restore(&path)?;
            }
        }
        Ok(())
    }

    fn chmod(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn open_dir(path: &Path, flags: OFlags) -> OwnedFd {
        rustix::fs::openat(
            CWD,
            path,
            flags | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap()
    }

    fn is_root() -> bool {
        std::fs::metadata("/proc/self").unwrap().uid() == 0
    }

    /// Every namespace mutation the M4c broker would perform, through `fd`.
    fn mutations(fd: &OwnedFd) -> Vec<(&'static str, Result<(), Errno>)> {
        vec![
            (
                "create",
                rustix::fs::openat(
                    fd,
                    "new",
                    OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::CLOEXEC,
                    Mode::from_raw_mode(0o600),
                )
                .map(drop),
            ),
            (
                "mkdir",
                rustix::fs::mkdirat(fd, "newdir", Mode::from_raw_mode(0o700)),
            ),
            (
                "rename-noreplace",
                rustix::fs::renameat_with(fd, "f", fd, "g", RenameFlags::NOREPLACE),
            ),
            (
                "rename-exchange",
                rustix::fs::renameat_with(fd, "f", fd, "other", RenameFlags::EXCHANGE),
            ),
            ("unlink", rustix::fs::unlinkat(fd, "f", AtFlags::empty())),
        ]
    }

    #[test]
    fn a_directory_descriptor_confers_no_right_to_change_its_names() {
        if is_root() {
            // Root's DAC override would answer a different question.
            evidence("descriptor-is-not-a-grant", "not-exercised:running-as-root");
            return;
        }
        let scratch = Scratch::new("grant");
        let d = scratch.0.join("d");
        std::fs::create_dir(&d).unwrap();
        std::fs::write(d.join("f"), b"f").unwrap();
        std::fs::write(d.join("other"), b"other").unwrap();
        // Held while the directory still allowed everything.
        let o_path = open_dir(&d, OFlags::PATH);
        let readable = open_dir(&d, OFlags::RDONLY);

        // r-x: searchable and listable, not writable -- the M4b posture of a
        // read-only workspace.
        chmod(&d, 0o555);
        for (name, fd) in [("o_path", &o_path), ("rdonly", &readable)] {
            for (op, result) in mutations(fd) {
                assert_eq!(result, Err(Errno::ACCESS), "{name} {op} through r-x");
            }
        }
        // A lookup and a read still work: the descriptor names the directory,
        // and read permission on the file is what reading it needs.
        assert!(
            rustix::fs::openat(
                &o_path,
                "f",
                OFlags::RDONLY | OFlags::CLOEXEC,
                Mode::empty()
            )
            .is_ok()
        );
        evidence(
            "descriptor-is-not-a-grant",
            "EACCES-create-mkdir-rename-exchange-unlink",
        );

        // --x missing: a descriptor to the directory does not even allow a
        // lookup through it -- search permission is checked per lookup.
        chmod(&d, 0o000);
        assert_eq!(
            rustix::fs::openat(&o_path, "f", OFlags::PATH | OFlags::CLOEXEC, Mode::empty())
                .map(drop),
            Err(Errno::ACCESS),
            "lookup through a descriptor needs search permission"
        );
        // ...but a directory opened for reading while it allowed reading can
        // still be enumerated: getdents on an open descriptor is not
        // rechecked. (`Dir::read_from` would reopen "." -- a lookup, refused
        // here -- so a lister must consume the descriptor itself, `Dir::new`.)
        assert_eq!(Dir::read_from(&readable).map(drop), Err(Errno::ACCESS));
        let names: Vec<String> = Dir::new(rustix::io::dup(&readable).unwrap())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n != "." && n != "..")
            .collect();
        assert_eq!(names.len(), 2, "{names:?}");
        evidence(
            "lookup-needs-search",
            "EACCES-lookup;getdents-on-open-fd-ok",
        );

        // rwx: every mutation the broker needs succeeds -- through the
        // descriptor, and equally by path. The permission is ambient: it is
        // the directory's bits for the caller's uid, not the descriptor.
        chmod(&d, 0o755);
        let results = mutations(&o_path);
        for (op, result) in &results {
            match *op {
                // `f` was renamed to `g` by the NOREPLACE step, so the
                // exchange and the unlink name a file that is no longer there.
                "rename-exchange" | "unlink" => {
                    assert_eq!(*result, Err(Errno::NOENT), "{op}");
                }
                _ => assert_eq!(*result, Ok(()), "{op}"),
            }
        }
        std::fs::write(d.join("by-path"), b"ambient").unwrap();
        std::fs::remove_file(d.join("by-path")).unwrap();
        evidence(
            "write-bit-is-the-grant",
            "mutations-ok-with-and-without-descriptor",
        );
    }

    #[test]
    fn noreplace_and_exchange_are_atomic_and_supported_here() {
        let scratch = Scratch::new("atomic");
        let d = scratch.0.join("d");
        std::fs::create_dir(&d).unwrap();
        std::fs::write(d.join("a"), b"a").unwrap();
        std::fs::write(d.join("b"), b"b").unwrap();
        let fd = open_dir(&d, OFlags::PATH);
        // NOREPLACE never destroys what occupies the target.
        assert_eq!(
            rustix::fs::renameat_with(&fd, "a", &fd, "b", RenameFlags::NOREPLACE),
            Err(Errno::EXIST)
        );
        assert_eq!(std::fs::read(d.join("b")).unwrap(), b"b");
        // EXCHANGE swaps two names; neither object is destroyed.
        let (ia, ib) = (
            std::fs::metadata(d.join("a")).unwrap().ino(),
            std::fs::metadata(d.join("b")).unwrap().ino(),
        );
        rustix::fs::renameat_with(&fd, "a", &fd, "b", RenameFlags::EXCHANGE).unwrap();
        assert_eq!(std::fs::metadata(d.join("a")).unwrap().ino(), ib);
        assert_eq!(std::fs::metadata(d.join("b")).unwrap().ino(), ia);
        evidence(
            "noreplace-exchange-supported",
            "EEXIST-noreplace;exchange-swaps",
        );
    }
}
