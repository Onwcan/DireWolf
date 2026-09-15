//! The `direwolf` binary.
//!
//! # Scope at M1
//!
//! M1 is the repository foundation. The DireWolf command surface — `run`,
//! `chat`, `agent`, `approve`, `memory`, `policy` — belongs to the milestones
//! that build the subsystems behind it (see `docs/ROADMAP.md`), and none of it
//! is stubbed here. A command that exists but cannot work is worse than one
//! that does not exist: it invites callers, scripts and documentation to form
//! around a shape nobody has designed yet.
//!
//! So this binary implements exactly two things, both of which are true today:
//! `--version` and `doctor`.
//!
//! Argument parsing is hand-written. With two commands, a dependency would buy
//! nothing; `clap` is expected at M17 when there is a real hierarchy to
//! describe.

mod build_info;
mod doctor;
mod platform;

use std::process::ExitCode;

/// Exit code for a usage error — an unknown command or flag.
const EXIT_USAGE: u8 = 2;

const USAGE: &str = "\
direwolf - security-first autonomous agent runtime

USAGE:
    direwolf <COMMAND>
    direwolf [--version | --help]

COMMANDS:
    doctor      Report build provenance and host platform facts

OPTIONS:
    -V, --version    Print version and build provenance
    -h, --help       Print this message

The agent command surface (run, chat, agent, approve, memory, policy) is
not implemented: DireWolf is at milestone M1, the repository foundation.
See docs/ROADMAP.md for what each later milestone adds.
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    ExitCode::from(dispatch(&refs))
}

/// Map an argument list to an exit code.
///
/// Separated from `main` so the dispatch table is unit-testable without
/// spawning a process.
fn dispatch(args: &[&str]) -> u8 {
    match args {
        [] | ["-h"] | ["--help"] | ["help"] => {
            print!("{USAGE}");
            0
        }
        ["-V"] | ["--version"] | ["version"] => {
            println!(
                "direwolf {} ({} {})",
                build_info::VERSION,
                build_info::GIT_COMMIT,
                build_info::TARGET
            );
            0
        }
        ["doctor"] => u8::try_from(doctor::run()).unwrap_or(EXIT_USAGE),
        [unknown, ..] => {
            eprintln!("direwolf: unknown command or option: {unknown}");
            eprintln!("Try `direwolf --help`.");
            EXIT_USAGE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{EXIT_USAGE, dispatch};

    #[test]
    fn no_arguments_prints_usage_and_succeeds() {
        assert_eq!(dispatch(&[]), 0);
    }

    #[test]
    fn version_succeeds() {
        assert_eq!(dispatch(&["--version"]), 0);
        assert_eq!(dispatch(&["-V"]), 0);
    }

    #[test]
    fn unknown_command_is_a_usage_error_not_a_silent_success() {
        assert_eq!(dispatch(&["frobnicate"]), EXIT_USAGE);
    }

    /// The unimplemented command surface must stay unimplemented. If one of
    /// these starts succeeding before its owning milestone, it is a stub, and
    /// stubs are what M1 exists to prevent.
    #[test]
    fn agent_command_surface_is_absent() {
        for cmd in [
            "run", "chat", "agent", "approve", "memory", "policy", "init",
        ] {
            assert_eq!(
                dispatch(&[cmd]),
                EXIT_USAGE,
                "`direwolf {cmd}` must not exist before its milestone"
            );
        }
    }
}
