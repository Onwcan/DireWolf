//! The server's startup configuration: operator input, typed, from the
//! command line.
//!
//! Every value the server starts with is on its command line, where the
//! operator who launched it put it. Nothing is read from the environment —
//! a runtime that could set an environment variable for the authority's
//! process could otherwise configure the authority that constrains it — and
//! nothing reaches here over DWKP: no operation configures the server, and
//! none may ([ADR-0041]).
//!
//! The parser is strict in the same way the policy loader is: an unknown flag,
//! a missing value, a repeated single-valued flag or a value outside its
//! bound is a usage error naming the flag, never a silently ignored word.
//!
//! [ADR-0041]: ../../../../../docs/adr/0041-m3e-authenticated-dwkp-transport.md

use core::fmt;
use std::collections::BTreeSet;
use std::path::PathBuf;

use crate::state::{
    ConfigFlags, DEFAULT_LEASE_TTL_MS, MAX_CEILING_CAPABILITIES, MAX_LEASE_TTL_MS,
    MAX_POLICY_SOURCES, MIN_LEASE_TTL_MS, Mode,
};

/// Most uids one peer policy may name. A closed, short list is the point.
pub const MAX_ALLOWED_UIDS: usize = 64;

/// Which peers may speak DWKP to this authority: an explicit, closed set of
/// uids the operator named.
///
/// Kernel identification answers *who connected*; this answers *whether that
/// uid may speak to this authority*. There is no wildcard, no group rule, no
/// user-name match and no exception for root: uid 0 is admitted exactly when
/// it is listed, like any other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerPolicy {
    allowed: BTreeSet<u32>,
    authority_uid_permitted: bool,
}

impl PeerPolicy {
    /// A policy admitting exactly `allowed`.
    ///
    /// `authority_uid_permitted` is the operator's explicit acknowledgement
    /// that the authority's **own** uid may be in the set. A peer with that uid
    /// can open `kernel.db` directly, so the process boundary does not
    /// constrain it; the server refuses such a set unless this is `true`, and
    /// says so on stderr when it is. It exists for development and for tests
    /// on a machine with one user, and it is never implied.
    #[must_use]
    pub fn new(allowed: BTreeSet<u32>, authority_uid_permitted: bool) -> Self {
        Self {
            allowed,
            authority_uid_permitted,
        }
    }

    /// Whether a peer with this kernel-reported uid may speak DWKP.
    #[must_use]
    pub fn allows(&self, uid: u32) -> bool {
        self.allowed.contains(&uid)
    }

    /// The admitted uids, in order.
    #[must_use]
    pub fn uids(&self) -> Vec<u32> {
        self.allowed.iter().copied().collect()
    }

    /// Whether the operator acknowledged admitting the authority's own uid.
    #[must_use]
    pub const fn authority_uid_permitted(&self) -> bool {
        self.authority_uid_permitted
    }
}

/// Where the policy comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyInput {
    /// One of the packs compiled into this build: `safe`, `balanced`, `power`.
    Shipped(String),
    /// The operator's own files, composed as `profile`.
    Files {
        /// The profile to compose, by its `meta.name`.
        profile: String,
        /// Its source files.
        files: Vec<PathBuf>,
    },
}

/// Everything `dwkd-authority serve` starts with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServeConfig {
    /// The authority's private state directory (`kernel.db`, `audit.log`).
    pub state_dir: PathBuf,
    /// The Unix-domain socket the server binds. Absolute; its parent is the
    /// IPC directory, which the authority owns.
    pub socket: PathBuf,
    /// Which kernel-reported uids may speak DWKP.
    pub peers: PeerPolicy,
    /// The policy to install and activate.
    pub policy: PolicyInput,
    /// The mode runs are admitted under.
    pub mode: Mode,
    /// The mode's capability ceiling.
    pub ceiling: Vec<String>,
    /// Operator flags policy may read.
    pub flags: ConfigFlags,
    /// How long a lease lives without a heartbeat.
    pub lease_ttl_ms: u64,
}

/// A command line that does not describe a configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageError(String);

impl UsageError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for UsageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for UsageError {}

/// The `serve` flags, for the help text. One line each.
pub const SERVE_USAGE: &str = "\
    --state-dir <DIR>          the authority's private state directory (required)
    --socket <PATH>            absolute path of the Unix-domain socket to bind (required)
    --allow-uid <UID>          a uid that may speak DWKP; repeat for each (at least one)
    --allow-authority-uid      permit listing the authority's own uid (development only)
    --policy-shipped <NAME>    use a policy pack compiled into this build: safe|balanced|power
    --policy-file <PATH>       an operator policy file; repeat for each (with --policy-profile)
    --policy-profile <NAME>    the profile to compose from the policy files
    --mode <MODE>              safe|balanced|power (required)
    --ceiling <CAPABILITY>     a capability in the mode ceiling; repeat for each
    --lease-ttl-ms <MS>        lease lifetime without a heartbeat (default 60000)
    --allow-host-execution     set the `security.allow_host_execution` policy flag
";

/// Parse the arguments after `serve`.
///
/// # Errors
///
/// [`UsageError`] naming the first flag or value that is wrong.
pub fn parse_serve_args(args: &[String]) -> Result<ServeConfig, UsageError> {
    let mut parsed = Parsed::default();
    let mut rest = args.iter();
    while let Some(flag) = rest.next() {
        parsed.flag(flag, &mut rest)?;
    }
    parsed.finish()
}

/// The flags seen so far.
#[derive(Debug, Default)]
struct Parsed {
    state_dir: Option<PathBuf>,
    socket: Option<PathBuf>,
    uids: BTreeSet<u32>,
    authority_uid_permitted: bool,
    shipped: Option<String>,
    files: Vec<PathBuf>,
    profile: Option<String>,
    mode: Option<Mode>,
    ceiling: Vec<String>,
    lease_ttl_ms: Option<u64>,
    flags: ConfigFlags,
}

impl Parsed {
    /// Apply one flag, taking its value from `rest` if it has one.
    fn flag<'a>(
        &mut self,
        flag: &str,
        rest: &mut impl Iterator<Item = &'a String>,
    ) -> Result<(), UsageError> {
        let mut value = || {
            rest.next()
                .ok_or_else(|| UsageError::new(format!("{flag} needs a value")))
        };
        match flag {
            "--state-dir" => once(&mut self.state_dir, flag, PathBuf::from(value()?)),
            "--socket" => once(&mut self.socket, flag, PathBuf::from(value()?)),
            "--allow-uid" => {
                let uid = parse_uid(value()?)?;
                if !self.uids.insert(uid) {
                    return Err(UsageError::new(format!("--allow-uid {uid} is repeated")));
                }
                bound(self.uids.len(), MAX_ALLOWED_UIDS, flag)
            }
            "--allow-authority-uid" => switch(&mut self.authority_uid_permitted, flag),
            "--policy-shipped" => once(&mut self.shipped, flag, value()?.clone()),
            "--policy-file" => {
                self.files.push(PathBuf::from(value()?));
                bound(self.files.len(), MAX_POLICY_SOURCES, flag)
            }
            "--policy-profile" => once(&mut self.profile, flag, value()?.clone()),
            "--mode" => once(&mut self.mode, flag, parse_mode(value()?)?),
            "--ceiling" => {
                self.ceiling.push(value()?.clone());
                bound(self.ceiling.len(), MAX_CEILING_CAPABILITIES, flag)
            }
            "--lease-ttl-ms" => {
                let ttl = value()?
                    .parse::<u64>()
                    .ok()
                    .filter(|ttl| (MIN_LEASE_TTL_MS..=MAX_LEASE_TTL_MS).contains(ttl))
                    .ok_or_else(|| {
                        UsageError::new(format!(
                            "--lease-ttl-ms must be a whole number of milliseconds in                              {MIN_LEASE_TTL_MS}..={MAX_LEASE_TTL_MS}"
                        ))
                    })?;
                once(&mut self.lease_ttl_ms, flag, ttl)
            }
            "--allow-host-execution" => switch(&mut self.flags.security_allow_host_execution, flag),
            other => Err(UsageError::new(format!(
                "unknown serve argument {}",
                bounded(other)
            ))),
        }
    }

    /// Check what is required and consistent, and build the configuration.
    fn finish(self) -> Result<ServeConfig, UsageError> {
        let state_dir = self
            .state_dir
            .ok_or_else(|| UsageError::new("--state-dir is required"))?;
        let socket = self
            .socket
            .ok_or_else(|| UsageError::new("--socket is required"))?;
        if !socket.is_absolute() {
            return Err(UsageError::new(
                "--socket must be an absolute path: a relative one would mean whatever the                  working directory makes it mean",
            ));
        }
        if self.uids.is_empty() {
            return Err(UsageError::new(
                "at least one --allow-uid is required: there is no default peer",
            ));
        }
        let mode = self
            .mode
            .ok_or_else(|| UsageError::new("--mode is required"))?;
        let policy = match (self.shipped, self.profile, self.files.is_empty()) {
            (Some(name), None, true) => PolicyInput::Shipped(name),
            (None, Some(profile), false) => PolicyInput::Files {
                profile,
                files: self.files,
            },
            (None, None, false) => {
                return Err(UsageError::new(
                    "--policy-file needs --policy-profile: the profile to compose is named,                      never guessed",
                ));
            }
            (None, Some(_), true) => {
                return Err(UsageError::new(
                    "--policy-profile needs at least one --policy-file",
                ));
            }
            (None, None, true) => {
                return Err(UsageError::new(
                    "a policy is required: --policy-shipped, or --policy-file with                      --policy-profile",
                ));
            }
            (Some(_), _, _) => {
                return Err(UsageError::new(
                    "--policy-shipped cannot be combined with --policy-file or --policy-profile",
                ));
            }
        };
        Ok(ServeConfig {
            state_dir,
            socket,
            peers: PeerPolicy::new(self.uids, self.authority_uid_permitted),
            policy,
            mode,
            ceiling: self.ceiling,
            flags: self.flags,
            lease_ttl_ms: self.lease_ttl_ms.unwrap_or(DEFAULT_LEASE_TTL_MS),
        })
    }
}

fn switch(slot: &mut bool, flag: &str) -> Result<(), UsageError> {
    if *slot {
        return Err(UsageError::new(format!("{flag} is repeated")));
    }
    *slot = true;
    Ok(())
}

fn bound(count: usize, max: usize, flag: &str) -> Result<(), UsageError> {
    if count > max {
        return Err(UsageError::new(format!("more than {max} {flag} values")));
    }
    Ok(())
}

fn once<T>(slot: &mut Option<T>, flag: &str, value: T) -> Result<(), UsageError> {
    if slot.is_some() {
        return Err(UsageError::new(format!("{flag} is repeated")));
    }
    *slot = Some(value);
    Ok(())
}

fn parse_uid(text: &str) -> Result<u32, UsageError> {
    // Digits only: no sign, no whitespace, no hex, no user name. A name would
    // have to be resolved through the user database, which is exactly the
    // kind of indirection a peer policy must not have.
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(UsageError::new(format!(
            "--allow-uid takes a numeric uid, not {}",
            bounded(text)
        )));
    }
    text.parse::<u32>()
        .map_err(|_| UsageError::new(format!("--allow-uid {} is out of range", bounded(text))))
}

fn parse_mode(text: &str) -> Result<Mode, UsageError> {
    match text {
        "safe" | "SAFE" => Ok(Mode::Safe),
        "balanced" | "BALANCED" => Ok(Mode::Balanced),
        "power" | "POWER" => Ok(Mode::Power),
        other => Err(UsageError::new(format!(
            "--mode must be safe, balanced or power, not {}",
            bounded(other)
        ))),
    }
}

/// A command-line word, bounded and with control characters escaped, for an
/// error message.
fn bounded(text: &str) -> String {
    let mut out = String::from("`");
    for c in text.chars().take(64) {
        if c.is_control() {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    if text.chars().nth(64).is_some() {
        out.push('…');
    }
    out.push('`');
    out
}

#[cfg(test)]
mod tests {
    use super::{PolicyInput, UsageError, parse_serve_args};
    use crate::state::{DEFAULT_LEASE_TTL_MS, Mode};

    fn args(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| (*w).to_owned()).collect()
    }

    fn base() -> Vec<&'static str> {
        vec![
            "--state-dir",
            "/srv/state",
            "--socket",
            "/run/dw/kernel.sock",
            "--allow-uid",
            "1001",
            "--policy-shipped",
            "balanced",
            "--mode",
            "balanced",
        ]
    }

    fn set<'a>(words: &mut [&'a str], at: usize, value: &'a str) {
        if let Some(slot) = words.get_mut(at) {
            *slot = value;
        }
    }

    fn error(words: &[&str]) -> String {
        match parse_serve_args(&args(words)) {
            Ok(config) => unreachable!("expected a usage error, parsed {config:?}"),
            Err(UsageError(message)) => message,
        }
    }

    #[test]
    fn a_minimal_command_line_parses() {
        let Ok(config) = parse_serve_args(&args(&base())) else {
            unreachable!("the base command line parses")
        };
        assert!(config.peers.allows(1001));
        assert!(!config.peers.allows(0), "root is not implied");
        assert!(!config.peers.authority_uid_permitted());
        assert_eq!(config.mode, Mode::Balanced);
        assert_eq!(config.policy, PolicyInput::Shipped("balanced".to_owned()));
        assert_eq!(config.lease_ttl_ms, DEFAULT_LEASE_TTL_MS);
    }

    #[test]
    fn nothing_has_a_default_that_admits_a_peer() {
        let mut words = base();
        words.drain(4..6);
        assert!(error(&words).contains("--allow-uid"));
    }

    #[test]
    fn a_uid_is_a_number_and_nothing_else() {
        for bad in ["-1", "+1", " 1", "0x10", "root", "", "4294967296"] {
            let mut words = base();
            set(&mut words, 5, bad);
            let message = error(&words);
            assert!(message.contains("--allow-uid"), "{bad:?}: {message}");
        }
        let mut words = base();
        words.extend(["--allow-uid", "1001"]);
        assert!(error(&words).contains("repeated"));
    }

    #[test]
    fn unknown_repeated_and_valueless_flags_are_refused() {
        let mut words = base();
        words.push("--tcp");
        assert!(error(&words).contains("unknown serve argument"));
        let mut words = base();
        words.extend(["--mode", "power"]);
        assert!(error(&words).contains("repeated"));
        let mut words = base();
        words.push("--socket");
        assert!(error(&words).contains("needs a value"));
    }

    #[test]
    fn the_socket_must_be_absolute() {
        let mut words = base();
        set(&mut words, 3, "kernel.sock");
        assert!(error(&words).contains("absolute"));
    }

    #[test]
    fn the_policy_is_named_explicitly_one_way() {
        let mut words = base();
        words.extend(["--policy-file", "/etc/p.toml"]);
        assert!(error(&words).contains("cannot be combined"));

        let mut words = base();
        words.drain(6..8);
        words.extend(["--policy-file", "/etc/p.toml"]);
        assert!(error(&words).contains("--policy-profile"));

        let mut words = base();
        words.drain(6..8);
        words.extend(["--policy-file", "/etc/p.toml", "--policy-profile", "house"]);
        let Ok(config) = parse_serve_args(&args(&words)) else {
            unreachable!("files and a profile parse")
        };
        assert!(matches!(config.policy, PolicyInput::Files { .. }));
    }

    #[test]
    fn the_lease_ttl_is_bounded() {
        for bad in ["0", "999", "600001", "1e3", "-5"] {
            let mut words = base();
            words.extend(["--lease-ttl-ms", bad]);
            assert!(error(&words).contains("--lease-ttl-ms"), "{bad}");
        }
    }

    #[test]
    fn an_error_never_echoes_an_unbounded_or_control_laden_word() {
        let long = "x".repeat(10_000);
        let mut words = base();
        words.push(&long);
        assert!(error(&words).len() < 200);
        let mut words = base();
        words.push("--evil\nline");
        assert!(!error(&words).contains('\n'));
    }
}
