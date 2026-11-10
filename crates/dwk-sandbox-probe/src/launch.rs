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
//! | `hygiene-npm`, `hygiene-pip` | the hygiene variables and npm's or pip's (ADR-0054, ADR-0055; never with a secret); `hygiene-npm` executes nothing unless npm's trust file is present | 0 `/dev/null`, 1, 2 |
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

/// Which fixed variables a profile sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Variables {
    /// None.
    None,
    /// `workspace_exec_hygiene`'s.
    Hygiene,
    /// The hygiene variables and npm's (M5e.5, ADR-0054 §2).
    Npm,
    /// The hygiene variables and pip's (M5e.5, ADR-0055 §2).
    Pip,
}

impl Variables {
    /// Every variable it sets, in order.
    fn set(self) -> Vec<(&'static str, &'static str)> {
        let extra: &[(&str, &str)] = match self {
            Self::None | Self::Hygiene => &[],
            Self::Npm => profile::HYGIENE_NPM_ENVIRONMENT,
            Self::Pip => profile::HYGIENE_PIP_ENVIRONMENT,
        };
        let base: &[(&str, &str)] = match self {
            Self::None => &[],
            Self::Hygiene | Self::Npm | Self::Pip => profile::HYGIENE_ENVIRONMENT,
        };
        base.iter().chain(extra).copied().collect()
    }

    /// The trust file the profile's tool must find before anything runs, if
    /// it names one: npm's (ADR-0054 §4, the owner's OD-E6). npm ignores a
    /// `cafile` it cannot find -- npm 11 reads it through `maybeReadFile`,
    /// which answers nothing on `ENOENT` -- and then trusts Node.js's bundled
    /// roots, so a missing file would not fail closed: the launcher stops
    /// the launch instead. pip refuses a missing `--cert` itself, before it
    /// connects (`requests`: "Could not find a suitable TLS CA certificate
    /// bundle"), which the hosted evidence measures; no other profile names
    /// one.
    const fn trust_file(self) -> Option<&'static str> {
        match self {
            Self::Npm => Some(profile::NPM_TRUST_FILE),
            Self::None | Self::Hygiene | Self::Pip => None,
        }
    }
}

/// Whether `path` is a trust file the tool can use: a regular, non-empty
/// file this process can open. Absent, empty, a directory, a dangling link
/// or unreadable is not one, and the launch executes nothing.
fn trust_present(path: &str) -> bool {
    std::fs::File::open(path)
        .and_then(|file| file.metadata())
        .is_ok_and(|meta| meta.is_file() && meta.len() > 0)
}

/// The profile's delivery, and the variables it sets.
fn profile_of(name: &str) -> Option<(Delivery, Variables)> {
    Some(match name {
        profile::LAUNCH_DIRECT => (Delivery::None, Variables::None),
        profile::LAUNCH_HYGIENE => (Delivery::None, Variables::Hygiene),
        profile::LAUNCH_HYGIENE_NPM => (Delivery::None, Variables::Npm),
        profile::LAUNCH_HYGIENE_PIP => (Delivery::None, Variables::Pip),
        profile::LAUNCH_SECRET_FD => (Delivery::Fd, Variables::None),
        profile::LAUNCH_SECRET_FD_HYGIENE => (Delivery::Fd, Variables::Hygiene),
        profile::LAUNCH_SECRET_ENV => (Delivery::Env, Variables::None),
        profile::LAUNCH_SECRET_ENV_HYGIENE => (Delivery::Env, Variables::Hygiene),
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
    let Some((delivery, variables)) = profile_of(name) else {
        return failed;
    };
    // A tool that would trust another store without its trust file never
    // starts without it (ADR-0054 §4, OD-E6): fail closed here, not in npm.
    if variables
        .trust_file()
        .is_some_and(|file| !trust_present(file))
    {
        return failed;
    }
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
    for (variable, value) in variables.set() {
        command.env(variable, value);
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
    use super::{Delivery, Variables, name_allowed, profile_of, trust_present};
    use dwk_sandbox_profile as profile;

    #[test]
    fn only_npms_profile_needs_its_trust_file_before_it_launches() {
        assert_eq!(Variables::Npm.trust_file(), Some(profile::NPM_TRUST_FILE));
        for variables in [Variables::None, Variables::Hygiene, Variables::Pip] {
            assert_eq!(variables.trust_file(), None, "{variables:?}");
        }
        assert_eq!(profile::NPM_TRUST_FILE, "/etc/direwolf/npm-ca.pem");
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn a_trust_file_is_present_only_when_regular_readable_and_non_empty() {
        let dir = std::env::temp_dir().join(format!("dw-launch-trust-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = |name: &str| dir.join(name).to_str().unwrap().to_owned();
        std::fs::write(dir.join("ca.pem"), b"-----BEGIN CERTIFICATE-----\n").unwrap();
        std::fs::write(dir.join("empty.pem"), b"").unwrap();
        std::fs::create_dir(dir.join("a-directory")).unwrap();
        std::os::unix::fs::symlink(dir.join("gone.pem"), dir.join("dangling.pem")).unwrap();
        std::os::unix::fs::symlink(dir.join("ca.pem"), dir.join("linked.pem")).unwrap();
        assert!(trust_present(&path("ca.pem")));
        assert!(trust_present(&path("linked.pem")));
        for absent in ["gone.pem", "empty.pem", "a-directory", "dangling.pem"] {
            assert!(!trust_present(&path(absent)), "{absent}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn every_profile_is_one_closed_word_and_nothing_else_launches() {
        for (name, expected) in [
            (profile::LAUNCH_DIRECT, (Delivery::None, Variables::None)),
            (
                profile::LAUNCH_HYGIENE,
                (Delivery::None, Variables::Hygiene),
            ),
            (
                profile::LAUNCH_HYGIENE_NPM,
                (Delivery::None, Variables::Npm),
            ),
            (
                profile::LAUNCH_HYGIENE_PIP,
                (Delivery::None, Variables::Pip),
            ),
            (profile::LAUNCH_SECRET_FD, (Delivery::Fd, Variables::None)),
            (
                profile::LAUNCH_SECRET_FD_HYGIENE,
                (Delivery::Fd, Variables::Hygiene),
            ),
            (profile::LAUNCH_SECRET_ENV, (Delivery::Env, Variables::None)),
            (
                profile::LAUNCH_SECRET_ENV_HYGIENE,
                (Delivery::Env, Variables::Hygiene),
            ),
        ] {
            assert_eq!(profile_of(name), Some(expected), "{name}");
        }
        for other in [
            "",
            "secret",
            "secret-fd ",
            "SECRET-FD",
            "hygiene-secret-fd",
            "env",
            "hygiene-npx",
            "hygiene-npm-secret",
            "secret-fd-hygiene-npm",
            "HYGIENE-NPM",
            "npm",
            "pip",
        ] {
            assert_eq!(profile_of(other), None, "{other:?}");
        }
    }

    #[test]
    fn each_profile_sets_exactly_its_variables_the_hygiene_ones_unchanged() {
        assert!(Variables::None.set().is_empty());
        assert_eq!(
            Variables::Hygiene.set(),
            profile::HYGIENE_ENVIRONMENT.to_vec()
        );
        for (variables, extra) in [
            (Variables::Npm, profile::HYGIENE_NPM_ENVIRONMENT),
            (Variables::Pip, profile::HYGIENE_PIP_ENVIRONMENT),
        ] {
            let mut expected = profile::HYGIENE_ENVIRONMENT.to_vec();
            expected.extend_from_slice(extra);
            assert_eq!(variables.set(), expected, "{variables:?}");
        }
        // ADR-0054 §2's eight and ADR-0055 §2's six, each named once.
        assert_eq!(profile::HYGIENE_NPM_ENVIRONMENT.len(), 8);
        assert_eq!(profile::HYGIENE_PIP_ENVIRONMENT.len(), 6);
        for (name, value) in profile::HYGIENE_NPM_ENVIRONMENT {
            assert!(name.starts_with("npm_config_"), "{name}={value}");
        }
        for (name, value) in profile::HYGIENE_PIP_ENVIRONMENT {
            assert!(name.starts_with("PIP_"), "{name}={value}");
        }
    }

    #[test]
    fn npms_user_and_global_configuration_name_two_different_files() {
        // npm 11 refuses to start when one file is named at two levels
        // (`double-loading config "/dev/null"`; run 42858621579, F-NPM-CONFIG).
        let named = |key: &str| {
            profile::HYGIENE_NPM_ENVIRONMENT
                .iter()
                .find(|(name, _)| *name == key)
                .map_or("", |(_, value)| *value)
        };
        let user = named("npm_config_userconfig");
        let global = named("npm_config_globalconfig");
        assert_ne!(user, global);
        assert_eq!(user, "/dev/null");
        // A path under `/dev/null`: no file can ever be there.
        assert_eq!(global, profile::NPM_GLOBALCONFIG);
        assert!(global.starts_with("/dev/null/"), "{global}");
        assert!(!std::path::Path::new(global).exists());
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
