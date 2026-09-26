//! Which of this process's descriptors would survive an `exec` (ADR-0045 §12).
//!
//! A descriptor this process opened itself is close-on-exec: `std` and
//! `rustix` open everything `O_CLOEXEC`, and the channel receives with
//! `MSG_CMSG_CLOEXEC`. One it **inherited** need not be — the spike behind
//! ADR-0045 found a terminal's `/dev/ptmx` on fd 7 reaching a target. Safe
//! Rust cannot close or flag a descriptor it was never handed (a
//! `BorrowedFd` from a bare number is `unsafe`), so this finds every such
//! descriptor and the caller **refuses to launch** while one exists: an
//! inherited descriptor is never passed on silently.
//!
//! It reads the kernel's own view of this process — `/proc/self/fd` and each
//! descriptor's `/proc/self/fdinfo/<n>` `flags:` line — never an object of an
//! invocation. The listing's own directory descriptor and the files it reads
//! are opened close-on-exec, so they are not findings, and all are closed
//! before this returns. `/proc` missing or unreadable is an error, and the
//! caller refuses: no answer is not a clean answer.

use std::io;

/// `O_CLOEXEC`, as `/proc/<pid>/fdinfo/<n>` reports it in `flags:` (octal).
const O_CLOEXEC: u32 = 0o2_000_000;

/// Every open descriptor numbered 3 or higher whose close-on-exec flag is
/// clear.
///
/// # Errors
///
/// `/proc/self/fd` or an entry's `fdinfo` could not be read.
pub(crate) fn inheritable() -> io::Result<Vec<u32>> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir("/proc/self/fd")? {
        let entry = entry?;
        let Some(number) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            return Err(io::Error::other("a descriptor name that is not a number"));
        };
        if number < 3 {
            continue;
        }
        let info = match std::fs::read_to_string(format!("/proc/self/fdinfo/{number}")) {
            Ok(info) => info,
            // Closed since the listing: the listing's own descriptor, gone.
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        let flags = info
            .lines()
            .find_map(|line| line.strip_prefix("flags:"))
            .and_then(|value| u32::from_str_radix(value.trim(), 8).ok())
            .ok_or_else(|| io::Error::other("an fdinfo without flags"))?;
        if flags & O_CLOEXEC == 0 {
            found.push(number);
        }
    }
    found.sort_unstable();
    Ok(found)
}

/// The descriptors of the kinds a launch creates — pidfds, pipes and
/// sockets — and the supervision threads alive: for the leak campaign, which
/// must not be confused by what other tests in the same process open.
///
/// # Errors
///
/// `/proc/self/fd` or `/proc/self/task` could not be read.
#[cfg(test)]
pub(crate) fn launch_resources() -> io::Result<(usize, usize)> {
    let mut descriptors = 0usize;
    for entry in std::fs::read_dir("/proc/self/fd")? {
        let Ok(target) = std::fs::read_link(entry?.path()) else {
            continue;
        };
        let target = target.to_string_lossy().into_owned();
        if target.starts_with("anon_inode:[pidfd]") || target.starts_with("pipe:") {
            descriptors = descriptors.saturating_add(1);
        }
    }
    let mut threads = 0usize;
    for task in std::fs::read_dir("/proc/self/task")? {
        let comm = std::fs::read_to_string(task?.path().join("comm")).unwrap_or_default();
        if comm.starts_with("process-") {
            threads = threads.saturating_add(1);
        }
    }
    Ok((descriptors, threads))
}
