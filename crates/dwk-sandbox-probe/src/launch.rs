//! The trusted in-image launcher: `launch <profile> [<NAME>] <path>
//! [args...]` (M5d.2 §5a; M5d.3 §7, ADR-0052).
//!
//! It decides nothing. The broker proved its bytes and the target's before
//! the runtime's `exec` started it; the authority chose the profile, the
//! variable and the arguments. It sets what the profile names over the
//! environment's own variables -- which it inherits and never reads -- and
//! executes `<path>` with exactly `[args...]` and `argv[0]` the path,
//! replacing itself. On any failure it executes nothing and exits
//! [`profile::LAUNCH_FAILED`], which the broker never believes as a
//! program's own exit (ADR-0052 §5).
//!
//! **Every profile sets the workspace's umask** (M5d.4, OD-3(a)):
//! [`WORKLOAD_UMASK`], so that what the target makes in the workspace is the
//! workspace group's to read and write and nobody else's. The runtime's
//! `exec` gives a process `0022` and has no option to change it; the target
//! is untrusted and may change its own, which the root's mode makes harmless
//! to every identity outside the group.
//!
//! | profile | sets | the target's descriptors |
//! |---|---|---|
//! | `direct` | nothing but the umask | 0 `/dev/null`, 1, 2 |
//! | `hygiene` | `workspace_exec_hygiene`'s variables | 0 `/dev/null`, 1, 2 |
//! | `secret-fd`, `secret-fd-hygiene` | (and the hygiene variables) | 0 `/dev/null`, 1, 2, and 3: a fresh pipe holding exactly the value |
//! | `secret-env`, `secret-env-hygiene` | `NAME=value` (and the hygiene variables) | 0 `/dev/null`, 1, 2 |
//!
//! **A secret arrives on standard input, framed** (M5d.3): the broker filled
//! a pipe with the value's length ([`profile::SECRET_FRAME_PREFIX_BYTES`],
//! big-endian) and exactly the value, closed it, and started the runtime's
//! client with it as stdin and `--interactive`, the one plan that may say so.
//! The launcher reads to end of file -- nothing past the bound -- and
//! executes nothing unless the frame is exactly one value of 1 to
//! [`MAX_SECRET_BYTES`] bytes. Then its standard input is `/dev/null`, as an
//! ordinary workload's is: the target never reads the frame.
//!
//! **What it does not claim.** A mode B value is in the target's
//! environment, and inherited by every process the target starts without
//! clearing it; mode C's descriptor 3 is inherited by every process the
//! target starts without closing it (measured, ADR-0046 §13). The
//! environment confines that process tree and its init ends it when the
//! invocation does; nothing here confines a credential to one process.
//!
//! Its copy of the value is overwritten before the `exec` (best effort: the
//! `exec` replaces the whole address space in any case), and none is ever
//! printed or placed in an argument.

use std::ffi::OsStr;
use std::io::{Read as _, Write as _};
use std::os::fd::{AsFd as _, AsRawFd as _, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::process::CommandExt as _;
use std::process::{Command, ExitCode};

use dwk_proto::brokerp::sandbox::WORKLOAD_UMASK;
use dwk_proto::brokerp::{MAX_SECRET_BYTES, SECRET_TARGET_FD, valid_secret_env_name};
use dwk_sandbox_profile as profile;
use nix::sys::stat::Mode;

/// How a profile delivers its secret, if it has one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Delivery {
    /// No secret.
    None,
    /// Mode C: descriptor 3.
    Fd,
    /// Mode B: one variable.
    Env,
}

/// The profile's delivery, and whether it sets the hygiene variables.
fn profile_of(name: &str) -> Option<(Delivery, bool)> {
    Some(match name {
        profile::LAUNCH_DIRECT => (Delivery::None, false),
        profile::LAUNCH_HYGIENE => (Delivery::None, true),
        profile::LAUNCH_SECRET_FD => (Delivery::Fd, false),
        profile::LAUNCH_SECRET_FD_HYGIENE => (Delivery::Fd, true),
        profile::LAUNCH_SECRET_ENV => (Delivery::Env, false),
        profile::LAUNCH_SECRET_ENV_HYGIENE => (Delivery::Env, true),
        _ => return None,
    })
}

/// A variable mode B may set: a secret variable's shape and not a
/// process-control name, and none the environment or the hygiene profile
/// already sets.
fn name_allowed(name: &str) -> bool {
    valid_secret_env_name(name) && !profile::sandbox_secret_name_reserved(name)
}

/// Overwrite `bytes`; the read through `black_box` keeps the writes from
/// being treated as dead before the buffer is dropped.
fn wipe(bytes: &mut [u8]) {
    bytes.fill(0);
    std::hint::black_box(&*bytes);
}

/// The one frame on standard input: its value, exactly, or nothing. Reads to
/// end of file from an unbuffered copy of descriptor 0, never more than the
/// largest frame and one byte.
fn read_frame() -> Option<Vec<u8>> {
    let prefix = profile::SECRET_FRAME_PREFIX_BYTES;
    let largest = prefix.checked_add(MAX_SECRET_BYTES)?;
    let mut frame = vec![0u8; largest.checked_add(1)?];
    let stdin = std::io::stdin().as_fd().try_clone_to_owned().ok()?;
    let mut stdin = std::fs::File::from(stdin);
    let mut filled = 0usize;
    let complete = loop {
        let Some(window) = frame.get_mut(filled..) else {
            break false;
        };
        if window.is_empty() {
            // A byte past the largest frame: refused, never truncated.
            break false;
        }
        match stdin.read(window) {
            Ok(0) => break true,
            Ok(n) => filled = filled.saturating_add(n),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break false,
        }
    };
    drop(stdin);
    let length = frame
        .get(..prefix)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .map(u32::from_be_bytes)
        .and_then(|length| usize::try_from(length).ok());
    let exact = complete
        && length.is_some_and(|length| {
            (1..=MAX_SECRET_BYTES).contains(&length) && Some(filled) == length.checked_add(prefix)
        });
    if !exact {
        wipe(&mut frame);
        return None;
    }
    // The value moves to the front of the same allocation, which is then cut
    // to it: no second copy is made.
    frame.copy_within(prefix..filled, 0);
    let value_length = filled - prefix;
    if let Some(rest) = frame.get_mut(value_length..) {
        wipe(rest);
    }
    frame.truncate(value_length);
    Some(frame)
}

/// Standard input becomes `/dev/null`: the target never reads the frame.
fn quiet_stdin() -> Option<()> {
    let null = std::fs::File::open("/dev/null").ok()?;
    nix::unistd::dup2_stdin(&null).ok()?;
    drop(null);
    Some(())
}

/// Mode C: a fresh pipe holding exactly `value`, its writer closed, its read
/// end moved onto `reserved` -- which is descriptor 3 -- with its
/// close-on-exec flag clear (`dup2` clears it). The value fits the pipe's
/// buffer (64 KiB; the value is at most 32 KiB), so the write never waits.
fn secret_on_fd3(value: &[u8], reserved: &mut OwnedFd) -> Option<()> {
    if reserved.as_raw_fd() != SECRET_TARGET_FD {
        return None;
    }
    let (reader, mut writer) = std::io::pipe().ok()?;
    writer.write_all(value).ok()?;
    drop(writer);
    nix::unistd::dup2(&reader, reserved).ok()?;
    drop(reader);
    Some(())
}

/// Whether the only descriptors the target can inherit are 0, 1, 2 and --
/// for mode C -- 3. The listing's own directory descriptor is counted once,
/// so any other descriptor at all refuses.
fn descriptors_closed(delivery: Delivery) -> bool {
    let Ok(entries) = std::fs::read_dir("/proc/self/fd") else {
        return false;
    };
    let mut extra = 0usize;
    for entry in entries {
        let Ok(entry) = entry else {
            return false;
        };
        let number: Option<i32> = entry.file_name().to_str().and_then(|n| n.parse().ok());
        match number {
            Some(0..=2) => {}
            Some(SECRET_TARGET_FD) if delivery == Delivery::Fd => {}
            _ => extra += 1,
        }
    }
    extra <= 1
}

/// `launch <profile> [<NAME>] <path> [args...]`.
pub(crate) fn run(args: &[String]) -> ExitCode {
    let failed = ExitCode::from(profile::LAUNCH_FAILED);
    let Some((name, rest)) = args.split_first() else {
        return failed;
    };
    let Some((delivery, hygiene)) = profile_of(name) else {
        return failed;
    };
    let (variable, rest) = match delivery {
        Delivery::Env => match rest.split_first() {
            Some((variable, rest)) if name_allowed(variable) => (Some(variable), rest),
            _ => return failed,
        },
        Delivery::None | Delivery::Fd => (None, rest),
    };
    let Some((path, rest)) = rest.split_first() else {
        return failed;
    };
    if !path.starts_with('/') {
        return failed;
    }
    let mut command = Command::new(path);
    command.arg0(path).args(rest);
    if hygiene {
        for (variable, value) in profile::HYGIENE_ENVIRONMENT {
            command.env(variable, value);
        }
    }
    // Descriptor 3 is taken first, before anything else can be, and held
    // until the exec: mode C moves its pipe onto it.
    let mut reserved = match delivery {
        Delivery::Fd => match nix::unistd::dup(std::io::stdin()) {
            Ok(fd) => Some(fd),
            Err(_) => return failed,
        },
        Delivery::None | Delivery::Env => None,
    };
    if delivery != Delivery::None {
        let Some(mut value) = read_frame() else {
            return failed;
        };
        let delivered = match (delivery, variable, reserved.as_mut()) {
            (Delivery::Fd, None, Some(reserved)) => secret_on_fd3(&value, reserved),
            // NUL cannot be in a variable; the broker refuses it too.
            (Delivery::Env, Some(variable), None) if !value.contains(&0) => {
                command.env(variable, OsStr::from_bytes(&value));
                Some(())
            }
            _ => None,
        };
        wipe(&mut value);
        drop(value);
        if delivered.is_none() || quiet_stdin().is_none() {
            return failed;
        }
    }
    if !descriptors_closed(delivery) {
        return failed;
    }
    // The workspace's umask, kept across the exec: what the target makes is
    // the group's (M5d.4).
    let _previous = nix::sys::stat::umask(Mode::from_bits_truncate(WORKLOAD_UMASK));
    // `exec` returns only if the kernel refused it.
    let _refused = command.exec();
    drop(reserved);
    failed
}

#[cfg(test)]
mod tests {
    use super::{Delivery, name_allowed, profile_of};
    use dwk_sandbox_profile as profile;

    #[test]
    fn every_profile_is_one_closed_word_and_nothing_else_launches() {
        assert_eq!(
            profile_of(profile::LAUNCH_DIRECT),
            Some((Delivery::None, false))
        );
        assert_eq!(
            profile_of(profile::LAUNCH_HYGIENE),
            Some((Delivery::None, true))
        );
        assert_eq!(
            profile_of(profile::LAUNCH_SECRET_FD),
            Some((Delivery::Fd, false))
        );
        assert_eq!(
            profile_of(profile::LAUNCH_SECRET_FD_HYGIENE),
            Some((Delivery::Fd, true))
        );
        assert_eq!(
            profile_of(profile::LAUNCH_SECRET_ENV),
            Some((Delivery::Env, false))
        );
        assert_eq!(
            profile_of(profile::LAUNCH_SECRET_ENV_HYGIENE),
            Some((Delivery::Env, true))
        );
        for other in [
            "",
            "secret",
            "secret-fd ",
            "SECRET-FD",
            "hygiene-secret-fd",
            "env",
        ] {
            assert_eq!(profile_of(other), None, "{other:?}");
        }
    }

    #[test]
    fn a_secret_variable_is_never_a_control_proxy_or_hygiene_name() {
        assert!(name_allowed("DEPLOY_TOKEN"));
        assert!(name_allowed("GH_TOKEN"));
        for refused in [
            "LD_PRELOAD",
            "PATH",
            "HOME",
            "GIT_CONFIG_GLOBAL",
            "PYTHONSAFEPATH",
            "CARGO_NET_OFFLINE",
            "HTTPS_PROXY",
            "NO_PROXY",
            "ALL_PROXY",
            "lowercase",
            "",
            "A=B",
        ] {
            assert!(!name_allowed(refused), "{refused:?}");
        }
    }
}
