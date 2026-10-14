//! What the broker verifies about an exchange worker, from the kernel, before
//! it hands that worker a connection or a credential (D11 hardening,
//! ADR-0053 §§4–5).
//!
//! The worker hardens and confines itself (`super::worker`,
//! `super::confine`) and says so on its control channel: `R`, how its image
//! began, and how the kernel answered each forbidden attempt. That is the
//! worker's word, given before it has read anything from an origin. The
//! broker does not rest on it. It reads the worker's own `/proc/<pid>`
//! entries itself, while the worker waits for its hand-over:
//!
//! | fact | from | required |
//! |---|---|---|
//! | a syscall filter | `status`: `Seccomp`, `Seccomp_filters` | mode 2, at least one filter |
//! | no privilege from any `execve` | `status`: `NoNewPrivs` | 1 |
//! | nobody traces it | `status`: `TracerPid` | 0 |
//! | not dumpable | the owner of `/proc/<pid>/mem` | not the worker's own uid |
//!
//! Non-dumpable is read from the kernel's own consequence: the restricted
//! entries of a non-dumpable process's `/proc/<pid>` -- `mem`, `environ`,
//! `fd` -- belong to root (`proc_pid(5)`; the world-readable directory
//! itself keeps the task's uid, for `ps`), so no process of the broker's
//! uid can open its memory or attach to it from then on. With `TracerPid` 0 at the same moment, nothing of the broker's
//! uid can observe the worker after this check: what was attached before
//! it is refused here, and nothing can attach after it.
//!
//! Each check is a pure function of the text it reads, tested on its own;
//! the real reads are proved on real workers and on deliberately weakened
//! stand-ins (`super::tests`).

/// The first byte of a worker's ready line.
pub(crate) const READY: u8 = b'R';

/// A ready line: how the worker's image began, and each attempt's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Ready {
    /// `PR_GET_DUMPABLE` as the worker first read it, before it changed
    /// anything: 1 (dumpable by its own uid) for an image its uid could
    /// read; for one it could not (an execute-only broker binary),
    /// `fs.suid_dumpable`'s value -- 0 (not dumpable) or 2 (dumpable by root
    /// only), each closed to its uid, or 1; 255 unknown. Reported, never
    /// judged: it is the worker's own word, and the host's posture decides
    /// the window (ADR-0053 §4).
    pub(crate) at_exec: u8,
    /// One code per attempt (`super::confine::Answer::code`): 0 refused.
    pub(crate) answers: Vec<u8>,
}

/// The ready line's length for `attempts` attempts: `R`, the image's
/// dumpable state, the count, and one byte per attempt.
#[must_use]
pub(crate) const fn ready_len(attempts: usize) -> usize {
    3 + attempts
}

/// Encode a ready line.
#[must_use]
pub(crate) fn encode_ready(ready: &Ready) -> Vec<u8> {
    let mut out = vec![
        READY,
        ready.at_exec,
        u8::try_from(ready.answers.len()).unwrap_or(u8::MAX),
    ];
    out.extend_from_slice(&ready.answers);
    out
}

/// Decode a ready line of exactly `attempts` attempts, and require every
/// one refused.
///
/// # Errors
///
/// What was wrong with it.
pub(crate) fn judge_ready(bytes: &[u8], attempts: usize) -> Result<Ready, &'static str> {
    let [tag, at_exec, count, answers @ ..] = bytes else {
        return Err("a short ready line");
    };
    if *tag != READY {
        return Err("not a ready line");
    }
    if usize::from(*count) != attempts || answers.len() != attempts {
        return Err("a ready line with another number of attempts");
    }
    if answers.iter().any(|code| *code != 0) {
        return Err("a forbidden attempt was not refused");
    }
    Ok(Ready {
        at_exec: *at_exec,
        answers: answers.to_vec(),
    })
}

/// One numeric field of `/proc/<pid>/status`, if present and well formed.
fn field(status: &str, name: &str) -> Option<u64> {
    status.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        (key == name).then(|| value.trim().parse::<u64>().ok())?
    })
}

/// Judge a worker's `/proc/<pid>/status`.
///
/// # Errors
///
/// The first requirement it does not meet.
pub(crate) fn judge_status(status: &str) -> Result<(), &'static str> {
    if field(status, "Seccomp") != Some(2) {
        return Err("no syscall filter (Seccomp is not 2)");
    }
    // `Seccomp_filters` since Linux 5.9; where it is reported it must count
    // the worker's own.
    if field(status, "Seccomp_filters").is_some_and(|count| count == 0) {
        return Err("no syscall filter (Seccomp_filters is 0)");
    }
    if field(status, "NoNewPrivs") != Some(1) {
        return Err("no_new_privs is not set");
    }
    if field(status, "TracerPid") != Some(0) {
        return Err("it is traced");
    }
    Ok(())
}

/// Judge the owner of `/proc/<pid>/mem` against the worker's own uid: a
/// dumpable process's restricted entries are its own.
///
/// # Errors
///
/// It is dumpable.
pub(crate) const fn judge_owner(owner: u32, worker_uid: u32) -> Result<(), &'static str> {
    if owner == worker_uid {
        Err("it is dumpable (its /proc/<pid>/mem is its own uid's)")
    } else {
        Ok(())
    }
}

/// Read and judge worker `pid`, a process of this broker's effective uid.
///
/// # Errors
///
/// The first requirement it does not meet, or its `/proc` entries could not
/// be read.
pub(crate) fn worker(pid: u32) -> Result<(), &'static str> {
    let dir = format!("/proc/{pid}");
    let status =
        std::fs::read_to_string(format!("{dir}/status")).map_err(|_| "its status is unreadable")?;
    judge_status(&status)?;
    let owner = rustix::fs::stat(format!("{dir}/mem").as_str())
        .map_err(|_| "its /proc/<pid>/mem is unreadable")?
        .st_uid;
    judge_owner(owner, rustix::process::geteuid().as_raw())
}

#[cfg(test)]
mod tests {
    use super::{Ready, encode_ready, judge_owner, judge_ready, judge_status};

    const CONFINED: &str = "Name:\tdwkd-broker\nUmask:\t0022\nState:\tS (sleeping)\n\
                            TracerPid:\t0\nUid:\t1000\t1000\t1000\t1000\nNoNewPrivs:\t1\n\
                            Seccomp:\t2\nSeccomp_filters:\t1\nSpeculation_Store_Bypass:\tx\n";

    #[test]
    fn a_confined_untraced_worker_passes_and_each_lack_is_named() {
        assert_eq!(judge_status(CONFINED), Ok(()));
        let weakened = |from: &str, to: &str| {
            assert!(CONFINED.contains(from), "{from}");
            judge_status(&CONFINED.replace(from, to))
        };
        for (from, to) in [
            ("Seccomp:\t2", "Seccomp:\t0"),
            ("Seccomp:\t2", "Seccomp:\t1"),
            ("Seccomp:\t2\n", ""),
            ("Seccomp_filters:\t1", "Seccomp_filters:\t0"),
            ("NoNewPrivs:\t1", "NoNewPrivs:\t0"),
            ("NoNewPrivs:\t1\n", ""),
            ("TracerPid:\t0", "TracerPid:\t4242"),
            ("TracerPid:\t0\n", ""),
            ("Seccomp:\t2", "Seccomp:\ttwo"),
        ] {
            assert!(weakened(from, to).is_err(), "{from} -> {to}");
        }
        // A kernel before 5.9 reports no filter count: the mode decides.
        assert_eq!(weakened("Seccomp_filters:\t1\n", ""), Ok(()));
        // A field's name must be the whole key.
        assert!(judge_status(&CONFINED.replace("TracerPid:", "XTracerPid:")).is_err());
    }

    #[test]
    fn a_worker_whose_proc_entries_are_its_own_is_dumpable() {
        assert!(judge_owner(1000, 1000).is_err());
        assert_eq!(judge_owner(0, 1000), Ok(()));
        assert_eq!(judge_owner(65_534, 1000), Ok(()));
    }

    #[test]
    fn a_ready_line_is_believed_only_whole_and_with_every_attempt_refused() {
        let ready = Ready {
            at_exec: 1,
            answers: vec![0; 15],
        };
        let line = encode_ready(&ready);
        assert_eq!(judge_ready(&line, 15), Ok(ready.clone()));
        for cut in 0..line.len() {
            assert!(judge_ready(line.get(..cut).unwrap_or_default(), 15).is_err());
        }
        assert!(judge_ready(&line, 14).is_err(), "another count");
        let mut longer = line.clone();
        longer.push(0);
        assert!(judge_ready(&longer, 15).is_err());
        for (at, code) in [(3, 1), (17, 2)] {
            let mut weakened = line.clone();
            if let Some(byte) = weakened.get_mut(at) {
                *byte = code;
            }
            assert_eq!(
                judge_ready(&weakened, 15),
                Err("a forbidden attempt was not refused")
            );
        }
        let mut other = line;
        if let Some(byte) = other.first_mut() {
            *byte = b'A';
        }
        assert!(judge_ready(&other, 15).is_err());
    }
}
