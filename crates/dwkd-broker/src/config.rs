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
    fn version_and_help_take_nothing_else() {
        assert_eq!(parse(&args(&["--version"])), Ok(Command::Version));
        assert_eq!(parse(&args(&["-h"])), Ok(Command::Help));
        assert!(parse(&args(&["--version", "serve"])).is_err());
    }
}
