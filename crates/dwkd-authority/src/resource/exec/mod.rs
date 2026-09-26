//! The executable resolver (M4d, [ADR-0045] §5): from an absolute host path to
//! an [`ExecutableIdentity`] — the canonical path of the object found and the
//! SHA-256 of the bytes that object held when it was hashed through the
//! descriptor that was checked.
//!
//! The second canonicaliser `crate::resource` holds, beside [`super::fs`], and
//! the only code in the authority that constructs an [`ExecutableIdentity`]
//! from a resource. Everything else in the crate receives one.
//!
//! # What a path means here
//!
//! | input | outcome |
//! |---|---|
//! | `/usr/bin/git` | the object at that path, if every check below holds |
//! | `git`, `./git`, `` | `EXECUTABLE_PATH_INVALID`: no `PATH` search, ever |
//! | `/usr/bin/../bin/git`, `/usr//bin/git`, `/usr/bin/git/` | `EXECUTABLE_PATH_INVALID`: one spelling per path |
//! | `/bin/ls` where `/bin → usr/bin` and `ls → ../lib/…/ls` | followed, at most [`MAX_SYMLINKS`]; the identity names the final object's canonical path |
//! | a directory, FIFO, socket or device | `EXECUTABLE_NOT_REGULAR` |
//! | a regular file with no execute bit | `EXECUTABLE_NOT_EXECUTABLE` |
//! | `#!/bin/sh …` | `SCRIPT_UNSUPPORTED` |
//! | anything but ELF | `NOT_NATIVE_EXECUTABLE` |
//! | anything under `/proc` or `/sys` | `EXECUTABLE_UNTRUSTED` |
//!
//! **Symlinks are followed, and the result is the final object.** A request
//! may name `/bin/ls`; the identity it resolves to is the canonical path of
//! the file the chain ends at, symlink-free, with every component re-walked
//! without following anything to prove it binds the object that was hashed.
//! Policy and capabilities compare that identity — never the spelling. The
//! cost is stated in ADR-0045 §5: `argv[0]` is the canonical path, so a
//! multi-call binary that dispatches on the **name of a symlink** it was
//! invoked through (busybox applets as symlinks, `clang++`) sees its own
//! canonical name instead. Hard-linked applets keep their names: a hard link
//! is its own canonical path.
//!
//! # The byte-stability contract
//!
//! A digest is only worth pinning if the bytes cannot change behind it. The
//! kernel does not freeze a file an executor holds open (an in-place rewrite
//! of the inode runs the rewritten bytes), so the resolver refuses every
//! object whose bytes some other principal could change:
//!
//! * the file's owner is root or the authority's own uid, and neither group
//!   nor others may write it;
//! * every directory on its canonical path is owned by root or the
//!   authority's uid, and is not writable by group or others unless sticky —
//!   so no other uid can re-point a name the identity names;
//! * no set-user-ID or set-group-ID bit, and no `security.capability`
//!   attribute: executing it would not run with the broker's own privileges;
//! * not on a network or user-space filesystem (NFS, SMB/CIFS, 9P, FUSE, AFS,
//!   Ceph, Coda), whose content a server can change without a local write.
//!
//! What remains is the authority's own uid and root, and the broker re-hashes
//! the descriptor it is handed immediately before execution (ADR-0045 §9), so
//! a change by either between resolution and launch is refused, not run.
//!
//! # What this does not establish
//!
//! The identity is the **executable file's**. The dynamic loader and the
//! shared libraries it maps are resolved by the loader at `execve`, from its
//! own search path; they are not hashed here and their integrity is the
//! host's. A statically linked executable is wholly covered; a dynamically
//! linked one is covered up to its `PT_INTERP` and `DT_NEEDED` objects.
//! ADR-0045 §5 states this limit rather than implying otherwise.
//!
//! [ADR-0045]: ../../../../../docs/adr/0045-m4d-process-execution-broker.md

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux as imp;

#[cfg(not(target_os = "linux"))]
mod unsupported;
#[cfg(not(target_os = "linux"))]
use unsupported as imp;

#[cfg(all(test, target_os = "linux"))]
mod tests;

pub mod argv;

use core::fmt;

use dwk_proto::limits::MAX_EXECUTABLE_PATH_BYTES;

use super::fs::{FileIdentity, single_component};
use super::{CanonicalPath, ExecutableIdentity, PathComponent, Sha256Digest};

/// The most symbolic links one resolution follows. Stricter than the kernel's
/// 40: an executable reached through more is refused, not guessed at.
pub const MAX_SYMLINKS: usize = 32;

/// Why an executable path did not resolve to an identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExecError {
    /// Not one canonical absolute spelling: relative, empty, `.`/`..`, an empty
    /// component, a name the grammar refuses, too long, too deep — or a
    /// symbolic link whose target the grammar cannot read.
    PathInvalid,
    /// Nothing there.
    NotFound,
    /// A component before the last is not a directory.
    NotADirectory,
    /// The object is not a regular file.
    NotRegular,
    /// A regular file with no execute bit.
    NotExecutable,
    /// More than [`MAX_SYMLINKS`] links, or a loop.
    SymlinkLimit,
    /// Some other principal could change the bytes, or executing it would
    /// run with more than the broker's privileges.
    Untrusted(Untrusted),
    /// Larger than [`dwk_proto::limits::MAX_EXECUTABLE_BYTES`].
    TooLarge,
    /// A `#!` script: its interpreter, not it, is what would run.
    Script,
    /// Not an ELF executable.
    NotNative,
    /// The object changed while it was being examined: a component re-bound, the
    /// file's size or change time moved while it was hashed.
    Race,
    /// The authority may not look.
    PermissionDenied,
    /// Anything else the kernel said, by `errno`.
    Io(i32),
    /// No resolver on this platform.
    Unsupported,
}

/// Which trust condition an [`ExecError::Untrusted`] object failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Untrusted {
    /// The file's owner is neither root nor the authority.
    Owner,
    /// Group or others may write the file.
    Writable,
    /// Set-user-ID or set-group-ID.
    SetId,
    /// A `security.capability` attribute: file capabilities.
    Capabilities,
    /// On a network, user-space, proc or sys filesystem.
    Filesystem,
    /// A directory on its canonical path is owned or writable by another
    /// principal.
    Directory,
}

impl Untrusted {
    /// A stable code, for the audit record.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Owner => "OWNER",
            Self::Writable => "WRITABLE",
            Self::SetId => "SET_ID",
            Self::Capabilities => "FILE_CAPABILITIES",
            Self::Filesystem => "FILESYSTEM",
            Self::Directory => "DIRECTORY",
        }
    }
}

impl ExecError {
    /// A stable code, for the audit record.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::PathInvalid => "PATH_INVALID",
            Self::NotFound => "NOT_FOUND",
            Self::NotADirectory => "NOT_A_DIRECTORY",
            Self::NotRegular => "NOT_REGULAR",
            Self::NotExecutable => "NOT_EXECUTABLE",
            Self::SymlinkLimit => "SYMLINK_LIMIT",
            Self::Untrusted(_) => "UNTRUSTED",
            Self::TooLarge => "TOO_LARGE",
            Self::Script => "SCRIPT",
            Self::NotNative => "NOT_NATIVE",
            Self::Race => "RACE",
            Self::PermissionDenied => "PERMISSION_DENIED",
            Self::Io(_) => "IO_ERROR",
            Self::Unsupported => "UNSUPPORTED",
        }
    }
}

impl fmt::Display for ExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Untrusted(why) => write!(f, "UNTRUSTED ({})", why.code()),
            Self::Io(errno) => write!(f, "IO_ERROR (errno {errno})"),
            other => f.write_str(other.code()),
        }
    }
}

impl std::error::Error for ExecError {}

/// A live descriptor this module opened and checked. Never cloned, never
/// rendered.
struct Handle(imp::Fd);

impl fmt::Debug for Handle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Handle(..)")
    }
}

/// What the platform walk found: the canonical components, the object's
/// `O_PATH` handle and its parent's, and what the hash saw.
struct Found {
    canonical: Vec<PathComponent>,
    leaf: imp::Fd,
    parent: imp::Fd,
    object: FileIdentity,
    size: u64,
    digest: [u8; 32],
    symlinks: usize,
}

/// An executable, resolved: its identity, the object it names, and `O_PATH`
/// handles on the object and its parent directory. **Nothing here can execute
/// or read it**: resolution closes the descriptor it hashed through, and an
/// executable descriptor exists only after the intent is durable
/// ([`ResolvedExecutable::into_exec_handoff`]).
#[derive(Debug)]
pub struct ResolvedExecutable {
    identity: ExecutableIdentity,
    object: FileIdentity,
    size: u64,
    symlinks: usize,
    trusted_owner: u32,
    leaf: Handle,
    parent: Handle,
    name: PathComponent,
}

impl ResolvedExecutable {
    /// The identity: canonical path and digest.
    #[must_use]
    pub const fn identity(&self) -> &ExecutableIdentity {
        &self.identity
    }

    /// The object's device and inode.
    #[must_use]
    pub const fn object(&self) -> FileIdentity {
        self.object
    }

    /// Its size when hashed.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// How many symbolic links the resolution followed.
    #[must_use]
    pub const fn symlinks_followed(&self) -> usize {
        self.symlinks
    }

    /// The descriptor the broker executes (step 4 of a launch): the file,
    /// opened for reading relative to its held parent by its one canonical
    /// name — not a path — and proved to be the object that was hashed, still
    /// bound to that name, still regular, executable and trusted. The broker
    /// re-hashes it before execution; this proves only what can be proved
    /// without reading it again.
    ///
    /// # Errors
    ///
    /// [`ExecError::Race`] when the object is no longer the one resolved, and
    /// the trust refusals when its attributes changed.
    pub fn into_exec_handoff(self) -> Result<ExecHandoff, ExecError> {
        let file = imp::open_for_exec(
            &self.leaf.0,
            &self.parent.0,
            &self.name,
            self.object,
            self.trusted_owner,
        )?;
        Ok(ExecHandoff {
            file: Handle(file),
            object: self.object,
            identity: self.identity,
        })
    }
}

/// The checked executable handed to the broker: a descriptor open for reading
/// on the object that was hashed, its identity, and nothing else.
///
/// ```compile_fail
/// // Its descriptor leaves only through the broker link (TX014).
/// use dwkd_authority::resource::exec::ExecHandoff;
/// fn steal(h: ExecHandoff) { let _ = h.into_transfer_descriptor(); }
/// ```
#[derive(Debug)]
pub struct ExecHandoff {
    #[cfg_attr(
        not(target_os = "linux"),
        expect(
            dead_code,
            reason = "the descriptor leaves only through the Linux broker link"
        )
    )]
    file: Handle,
    object: FileIdentity,
    identity: ExecutableIdentity,
}

impl ExecHandoff {
    /// The object's device and inode, as the broker must find them.
    #[must_use]
    pub const fn object(&self) -> FileIdentity {
        self.object
    }

    /// The identity the broker re-proves: canonical path and digest.
    #[must_use]
    pub const fn identity(&self) -> &ExecutableIdentity {
        &self.identity
    }

    /// Release the descriptor to the broker link. The one place it leaves
    /// (TX014).
    #[cfg(target_os = "linux")]
    pub(crate) fn into_transfer_descriptor(self) -> (std::os::fd::OwnedFd, FileIdentity) {
        (self.file.0, self.object)
    }
}

/// Resolve an absolute host path to an executable identity. `trusted_owner`
/// is the authority's own uid: with root, the only owner whose files and
/// directories the identity may rest on.
///
/// Opens `O_PATH` handles only, except the one read-only descriptor the file
/// is hashed through, which is closed before this returns. Call with no SQLite
/// transaction open: hashing reads up to 512 MiB.
///
/// # Errors
///
/// [`ExecError`], naming the class of refusal.
pub fn resolve(text: &str, trusted_owner: u32) -> Result<ResolvedExecutable, ExecError> {
    looked_up();
    let components = parse(text)?;
    let found = imp::resolve(&components, trusted_owner)?;
    let canonical = canonical_path(found.canonical.clone())?;
    if canonical.to_string().len() > MAX_EXECUTABLE_PATH_BYTES {
        return Err(ExecError::PathInvalid);
    }
    let name = found
        .canonical
        .last()
        .cloned()
        .ok_or(ExecError::NotRegular)?;
    Ok(ResolvedExecutable {
        identity: ExecutableIdentity::new(canonical, Sha256Digest::from_bytes(found.digest)),
        object: found.object,
        size: found.size,
        symlinks: found.symlinks,
        trusted_owner,
        leaf: Handle(found.leaf),
        parent: Handle(found.parent),
        name,
    })
}

/// A canonical path from components the grammar or the walk already accepted,
/// within the depth bound.
fn canonical_path(components: Vec<PathComponent>) -> Result<CanonicalPath, ExecError> {
    if components.len() > CanonicalPath::MAX_COMPONENTS {
        return Err(ExecError::PathInvalid);
    }
    Ok(CanonicalPath { components })
}

#[cfg(test)]
thread_local! {
    /// Executable lookups this thread has begun: see
    /// [`lookups_on_this_thread`].
    static LOOKUPS: core::cell::Cell<u64> = const { core::cell::Cell::new(0) };
}

/// Count an executable lookup — in this crate's unit tests; nothing in any
/// other build.
#[cfg_attr(not(test), allow(clippy::missing_const_for_fn))]
fn looked_up() {
    #[cfg(test)]
    LOOKUPS.with(|count| count.set(count.get().saturating_add(1)));
}

/// How many executable resolutions this thread has begun. **Test
/// observation, not an interface**: it proves that a path which must not
/// consult the filesystem — an admission replay, a stored process grant re-read
/// — begins none (ADR-0045 §21). Linux only, like the resolver it counts.
#[cfg(all(test, target_os = "linux"))]
pub(crate) fn lookups_on_this_thread() -> u64 {
    LOOKUPS.with(core::cell::Cell::get)
}

/// The grammar every host path — a request's, a declaration's, a stored
/// identity's, a symbolic link's absolute target — is read by: absolute, at
/// most `PATH_MAX` bytes, at least one component, every component one name
/// the workspace grammar accepts (no empty component, no `.` or `..`, NFC, no
/// control, bidi or invisible character, at most `NAME_MAX`), at most
/// [`CanonicalPath::MAX_COMPONENTS`] of them. Never rewrites.
///
/// # Errors
///
/// [`ExecError::PathInvalid`].
pub(in crate::resource) fn parse(text: &str) -> Result<Vec<PathComponent>, ExecError> {
    if text.len() > MAX_EXECUTABLE_PATH_BYTES {
        return Err(ExecError::PathInvalid);
    }
    let Some(rest) = text.strip_prefix('/') else {
        return Err(ExecError::PathInvalid);
    };
    let mut components = Vec::new();
    for part in rest.split('/') {
        if components.len() == CanonicalPath::MAX_COMPONENTS {
            return Err(ExecError::PathInvalid);
        }
        components.push(single_component(part).map_err(|_| ExecError::PathInvalid)?);
    }
    Ok(components)
}

/// The identity a **stored** record spells — a process the authority itself
/// launched, a grant it resolved and stored — read back by the grammar alone,
/// without looking at any filesystem.
///
/// **Only for re-reading what the authority already resolved and wrote to
/// `kernel.db`.** A new declaration or a new request becomes an identity only
/// through [`resolve`], where the filesystem and the hash supply its meaning.
/// One module may name this function (ADR-0045 §21; the architecture rule
/// beside TX017).
///
/// # Errors
///
/// [`ExecError::PathInvalid`] for a path the grammar refuses or a digest that
/// is not sixty-four lowercase hex characters.
pub(crate) fn stored_executable_identity(
    path: &str,
    sha256: &str,
) -> Result<ExecutableIdentity, ExecError> {
    let canonical = canonical_path(parse(path)?)?;
    let digest = Sha256Digest::parse_hex(sha256).ok_or(ExecError::PathInvalid)?;
    Ok(ExecutableIdentity::new(canonical, digest))
}

#[cfg(test)]
mod grammar_tests {
    use super::{ExecError, parse, stored_executable_identity};

    fn names(text: &str) -> Result<Vec<String>, ExecError> {
        parse(text).map(|c| c.iter().map(|n| n.as_str().to_owned()).collect())
    }

    #[test]
    fn an_absolute_path_is_its_components_and_nothing_else_is_one() {
        assert_eq!(
            names("/usr/bin/git"),
            Ok(vec!["usr".to_owned(), "bin".to_owned(), "git".to_owned()])
        );
        for bad in [
            "",
            "/",
            "git",
            "./git",
            "bin/git",
            "/usr//bin/git",
            "/usr/bin/git/",
            "/usr/./bin/git",
            "/usr/bin/../bin/git",
            "/..",
            "/usr/bin/g\u{0}it",
            "/usr/bin/g\u{7}it",
            "/usr/bin/g\u{202e}it",
            "/usr/bin/cafe\u{301}",
            "/usr/bin/a\\b",
        ] {
            assert_eq!(names(bad), Err(ExecError::PathInvalid), "{bad:?}");
        }
    }

    #[test]
    fn a_path_at_its_bounds_is_accepted_and_one_past_is_not() {
        let at = format!("/{}", "n".repeat(255));
        assert!(names(&at).is_ok());
        assert_eq!(
            names(&format!("/{}", "n".repeat(256))),
            Err(ExecError::PathInvalid)
        );
        let deep = |n: usize| format!("/{}", vec!["d"; n].join("/"));
        assert!(names(&deep(64)).is_ok());
        assert_eq!(names(&deep(65)), Err(ExecError::PathInvalid));
        // PATH_MAX bytes of text: sixteen 255-byte names are 4 096.
        let long = format!("/{}", vec!["n".repeat(254); 17].join("/"));
        assert!(long.len() > 4096);
        assert_eq!(names(&long), Err(ExecError::PathInvalid));
    }

    #[test]
    fn a_stored_identity_reads_back_exactly_or_not_at_all() {
        let digest = "9f".repeat(32);
        let Ok(identity) = stored_executable_identity("/usr/bin/git", &digest) else {
            unreachable!("a stored identity")
        };
        assert_eq!(identity.to_string(), format!("/usr/bin/git@{digest}"));
        for (path, sha) in [
            ("/usr/bin/../git", digest.as_str()),
            ("usr/bin/git", digest.as_str()),
            ("/usr/bin/git", "9F"),
            ("/usr/bin/git", ""),
        ] {
            assert_eq!(
                stored_executable_identity(path, sha).map(|i| i.to_string()),
                Err(ExecError::PathInvalid),
                "{path} {sha}"
            );
        }
        let upper = "9F".repeat(32);
        assert!(stored_executable_identity("/usr/bin/git", &upper).is_err());
    }
}
