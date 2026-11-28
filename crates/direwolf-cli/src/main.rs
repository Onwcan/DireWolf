//! The `direwolf` binary.
//!
//! # Scope
//!
//! The DireWolf command surface — `run`, `chat`, `agent`, `memory`,
//! `policy` — belongs to the milestones that build the subsystems behind it
//! (see `docs/ROADMAP.md`), and none of it is stubbed here. The authority
//! plane that exists is operated through `dwkd-authority` and `dwkd-broker`
//! (`docs/OPERATIONS.md`), not through this binary. A command that exists but
//! cannot work is worse than one that does not exist: it invites callers,
//! scripts and documentation to form around a shape nobody has designed yet.
//!
//! So this binary implements exactly four things, each true today:
//! `--version`, `doctor`, `models` -- the operator's offline model library
//! (ADR-0072, Proposed), which downloads nothing and serves no inference --
//! and `approve` (M6.3, ADR-0081, Proposed): the trusted approver client,
//! which speaks only to the authority's approver endpoint and records an
//! approval at A1.
//!
//! Argument parsing is hand-written. With a handful of commands, a dependency
//! would buy nothing; `clap` is expected at M17 when there is a real
//! hierarchy to describe.

mod approve;
mod build_info;
mod doctor;
mod models;
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
    approve     The trusted approver client: list, show and decide approval
                requests at the approver endpoint (direwolf approve --help)
    doctor      Report build provenance and host platform facts
    models      The operator's offline model library (direwolf models --help)

OPTIONS:
    -V, --version    Print version and build provenance
    -h, --help       Print this message

The agent command surface (run, chat, agent, memory, policy) is
not implemented: each part belongs to a later milestone. The authority
plane runs as dwkd-authority and dwkd-broker (docs/OPERATIONS.md); see
docs/ROADMAP.md for what is built and what each milestone adds.
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
        ["models", rest @ ..] => models::run(rest),
        ["approve", rest @ ..] => approve::run(rest),
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
    /// stubs are what M1 exists to prevent. `approve` left this list with its
    /// milestone, M6.3 (ADR-0081): see the next test.
    #[test]
    fn agent_command_surface_is_absent() {
        for cmd in ["run", "chat", "agent", "memory", "policy", "init"] {
            assert_eq!(
                dispatch(&[cmd]),
                EXIT_USAGE,
                "`direwolf {cmd}` must not exist before its milestone"
            );
        }
    }

    /// M6.3: `approve` exists -- the trusted approver client -- and refuses
    /// what it does not know as a usage error, never a silent success.
    #[test]
    fn approve_is_the_trusted_client_and_nothing_else() {
        assert_eq!(dispatch(&["approve"]), 0, "its usage");
        assert_eq!(dispatch(&["approve", "--help"]), 0);
        for unknown in [
            &["approve", "frobnicate"][..],
            &["approve", "grant"][..],
            &["approve", "revoke"][..],
            &["approve", "list", "--yes"][..],
        ] {
            assert_eq!(dispatch(unknown), EXIT_USAGE, "{unknown:?}");
        }
    }
}
