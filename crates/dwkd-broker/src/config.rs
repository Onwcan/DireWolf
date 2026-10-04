//! The broker's command line. Parsed completely before anything is opened.

use core::fmt;
use std::path::PathBuf;

/// What the command line asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Command {
    /// Print the version.
    Version,
    /// Print the usage.
    Help,
    /// Serve the private channel.
    Serve(ServeConfig),
    /// The launch helper (M4d, ADR-0045 §12): one launch, handed over by the
    /// parent broker on the control channel it was spawned with. Takes no
    /// arguments and is not listed in the usage: nothing but the broker
    /// starts it, and started any other way it does nothing.
    ExecHelper,
}

/// How to serve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ServeConfig {
    /// Where to listen. Absolute; its directory is checked before binding.
    pub(crate) socket: PathBuf,
    /// The uid the kernel must report for a connecting peer. Every other peer
    /// is closed before a byte is read from it.
    pub(crate) authority_uid: u32,
    /// The operator's acknowledgement that the authority runs as the broker's
    /// own uid — one user, for development. Reduced assurance, stated at
    /// start-up; never implied.
    pub(crate) shared_uid_permitted: bool,
    /// The operator's acknowledgement that the process may stay dumpable
    /// (M4e): its memory readable by other processes of its uid, for a
    /// development harness that reads its `/proc`. Reduced assurance, stated
    /// at start-up; never implied. `RLIMIT_CORE` is 0 either way.
    pub(crate) dumpable_permitted: bool,
    /// The operator's acknowledgement that the evidence harness's `NO_NETWORK`
    /// environment topology may be built (M5a, ADR-0047 §10). Without it the
    /// broker builds `PROXY_ONLY` environments only (M5b). Stated at
    /// start-up; never implied.
    pub(crate) evidence_topology_permitted: bool,
    /// The egress evidence's fixture file (M5b, ADR-0048): when given, the
    /// proxy resolves names from it instead of the host's resolver, and may
    /// reach the loopback addresses it names. Evidence only — a fixture
    /// origin on loopback is what no production grant may ever reach —
    /// stated loudly at start-up, never implied, and absent from every
    /// production configuration.
    pub(crate) evidence_egress: Option<PathBuf>,
}

/// A command line that does not describe a configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UsageError(String);

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

/// At most this many characters of an argument are echoed in an error.
const ECHO: usize = 64;

fn bounded(text: &str) -> String {
    let mut shown: String = text.chars().take(ECHO).collect();
    if text.chars().count() > ECHO {
        shown.push('…');
    }
    format!("{shown:?}")
}

fn parse_uid(flag: &str, text: &str) -> Result<u32, UsageError> {
    // Digits only: no sign, no whitespace, no hex, no user name. A name would
    // be resolved through the user database, an indirection a peer check must
    // not have.
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(UsageError::new(format!(
            "{flag} takes a numeric uid, not {}",
            bounded(text)
        )));
    }
    text.parse::<u32>()
        .map_err(|_| UsageError::new(format!("{flag} {} is out of range", bounded(text))))
}

/// Parse the arguments after the program name.
pub(crate) fn parse(args: &[String]) -> Result<Command, UsageError> {
    let mut rest = args.iter();
    match rest.next().map(String::as_str) {
        Some("-V" | "--version") if args.len() == 1 => return Ok(Command::Version),
        Some("-h" | "--help") if args.len() == 1 => return Ok(Command::Help),
        Some("exec-helper") if args.len() == 1 => return Ok(Command::ExecHelper),
        Some("serve") => {}
        Some(other) => {
            return Err(UsageError::new(format!(
                "unknown command {}",
                bounded(other)
            )));
        }
        None => return Err(UsageError::new("a command is required")),
    }
    let mut socket: Option<PathBuf> = None;
    let mut authority_uid: Option<u32> = None;
    let mut shared = false;
    let mut dumpable = false;
    let mut evidence_topology = false;
    let mut evidence_egress: Option<PathBuf> = None;
    while let Some(flag) = rest.next() {
        let mut value = || {
            rest.next()
                .ok_or_else(|| UsageError::new(format!("{flag} needs a value")))
        };
        match flag.as_str() {
            "--socket" => {
                let path = PathBuf::from(value()?);
                if socket.replace(path).is_some() {
                    return Err(UsageError::new("--socket is given more than once"));
                }
            }
            "--authority-uid" => {
                let uid = parse_uid(flag, value()?)?;
                if authority_uid.replace(uid).is_some() {
                    return Err(UsageError::new("--authority-uid is given more than once"));
                }
            }
            "--allow-shared-authority-uid" => {
                if shared {
                    return Err(UsageError::new(
                        "--allow-shared-authority-uid is given more than once",
                    ));
                }
                shared = true;
            }
            "--allow-dumpable" => {
                if dumpable {
                    return Err(UsageError::new("--allow-dumpable is given more than once"));
                }
                dumpable = true;
            }
            "--allow-evidence-topology" => {
                if evidence_topology {
                    return Err(UsageError::new(
                        "--allow-evidence-topology is given more than once",
                    ));
                }
                evidence_topology = true;
            }
            "--allow-evidence-egress" => {
                let path = PathBuf::from(value()?);
                if !path.is_absolute() {
                    return Err(UsageError::new(
                        "--allow-evidence-egress needs an absolute path",
                    ));
                }
                if evidence_egress.replace(path).is_some() {
                    return Err(UsageError::new(
                        "--allow-evidence-egress is given more than once",
                    ));
                }
            }
            other => {
                return Err(UsageError::new(format!("unknown flag {}", bounded(other))));
            }
        }
    }
    let Some(socket) = socket else {
        return Err(UsageError::new("--socket is required"));
    };
    if !socket.is_absolute() {
        return Err(UsageError::new("--socket must be an absolute path"));
    }
    let Some(authority_uid) = authority_uid else {
        return Err(UsageError::new(
            "--authority-uid is required: the broker reads from no one else",
        ));
    };
    Ok(Command::Serve(ServeConfig {
        socket,
        authority_uid,
        shared_uid_permitted: shared,
        dumpable_permitted: dumpable,
        evidence_topology_permitted: evidence_topology,
        evidence_egress,
    }))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{Command, ServeConfig, parse};

    /// A socket path that is absolute on this platform: `/b` is not, on
    /// Windows, and the parser is portable even though serving is not.
    fn socket() -> String {
        std::env::temp_dir()
            .join("broker.sock")
            .display()
            .to_string()
    }

    fn args(text: &[&str]) -> Vec<String> {
        let path = socket();
        text.iter()
            .map(|s| {
                if *s == "ABS" {
                    path.clone()
                } else {
                    (*s).to_owned()
                }
            })
            .collect()
    }

    #[test]
    fn serve_needs_an_absolute_socket_and_a_numeric_authority_uid() {
        assert_eq!(
            parse(&args(&[
                "serve",
                "--socket",
                "ABS",
                "--authority-uid",
                "1001"
            ])),
            Ok(Command::Serve(ServeConfig {
                socket: PathBuf::from(socket()),
                authority_uid: 1001,
                shared_uid_permitted: false,
                dumpable_permitted: false,
                evidence_topology_permitted: false,
                evidence_egress: None,
            }))
        );
        for bad in [
            &["serve"][..],
            &["serve", "--socket", "ABS"],
            &["serve", "--authority-uid", "1"],
            &["serve", "--socket", "b.sock", "--authority-uid", "1"],
            &["serve", "--socket", "ABS", "--authority-uid", "root"],
            &["serve", "--socket", "ABS", "--authority-uid", "-1"],
            &["serve", "--socket", "ABS", "--authority-uid", "0x10"],
            &["serve", "--socket", "ABS", "--authority-uid", "4294967296"],
            &[
                "serve",
                "--socket",
                "ABS",
                "--authority-uid",
                "1",
                "--authority-uid",
                "2",
            ],
            &[
                "serve",
                "--socket",
                "ABS",
                "--socket",
                "ABS",
                "--authority-uid",
                "1",
            ],
            &[
                "serve",
                "--socket",
                "ABS",
                "--authority-uid",
                "1",
                "--listen-tcp",
                "x",
            ],
            &["serve", "--socket", "ABS", "--authority-uid"],
            &["frobnicate"],
            &[],
        ] {
            assert!(parse(&args(bad)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_shared_uid_acknowledgement_is_explicit() {
        let parsed = parse(&args(&[
            "serve",
            "--socket",
            "ABS",
            "--authority-uid",
            "7",
            "--allow-shared-authority-uid",
        ]));
        assert!(matches!(
            parsed,
            Ok(Command::Serve(ServeConfig {
                shared_uid_permitted: true,
                ..
            }))
        ));
    }

    #[test]
    fn the_evidence_topology_is_explicit_and_given_once() {
        let base = ["serve", "--socket", "ABS", "--authority-uid", "7"];
        assert!(matches!(
            parse(&args(&base)),
            Ok(Command::Serve(ServeConfig {
                evidence_topology_permitted: false,
                ..
            }))
        ));
        let mut with = base.to_vec();
        with.push("--allow-evidence-topology");
        assert!(matches!(
            parse(&args(&with)),
            Ok(Command::Serve(ServeConfig {
                evidence_topology_permitted: true,
                ..
            }))
        ));
        with.push("--allow-evidence-topology");
        assert!(parse(&args(&with)).is_err());
    }

    #[test]
    fn the_evidence_egress_is_explicit_absolute_and_given_once() {
        let base = ["serve", "--socket", "ABS", "--authority-uid", "7"];
        let fixture = socket();
        let mut with: Vec<String> = args(&base);
        with.push("--allow-evidence-egress".to_owned());
        with.push(fixture.clone());
        assert!(matches!(
            parse(&with),
            Ok(Command::Serve(ServeConfig {
                evidence_egress: Some(ref path),
                ..
            })) if path.to_str() == Some(fixture.as_str())
        ));
        let mut twice = with.clone();
        twice.push("--allow-evidence-egress".to_owned());
        twice.push(fixture);
        assert!(parse(&twice).is_err());
        let mut relative = args(&base);
        relative.push("--allow-evidence-egress".to_owned());
        relative.push("fixture.txt".to_owned());
        assert!(parse(&relative).is_err());
        let mut valueless = args(&base);
        valueless.push("--allow-evidence-egress".to_owned());
        assert!(parse(&valueless).is_err());
    }

    #[test]
    fn version_and_help_take_nothing_else() {
        assert_eq!(parse(&args(&["--version"])), Ok(Command::Version));
        assert_eq!(parse(&args(&["-h"])), Ok(Command::Help));
        assert!(parse(&args(&["--version", "serve"])).is_err());
    }
}
