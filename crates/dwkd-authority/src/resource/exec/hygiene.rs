//! `workspace_exec_hygiene` for a workload in an execution environment
//! (M5d.2, ADR-0052 §5a): whether the authority can keep the obligation for
//! one invocation, and the arguments it adds when it can.
//!
//! **What is kept, and how.** The obligation neutralises a tool's
//! configuration that comes from *outside the invocation* (SANDBOX.md §4a):
//! git's global and system files and any injected through the environment,
//! Python's user site and the implicit script or working directory on
//! `sys.path`, pytest's cache, Cargo's network, npm's lifecycle scripts. In
//! an environment the broker starts such a workload through the trusted
//! launcher — the digest-pinned probe, proved before every workload — which
//! sets the profile's fixed variables (`dwk_sandbox_profile::HYGIENE_ENVIRONMENT`)
//! and executes the program; the authority adds the per-tool arguments
//! here, before the invocation's own, and records them. No variable comes
//! from the caller and none is spelled on the runtime's command line.
//!
//! **What would undo it** is refused, not tolerated: an invocation whose
//! own arguments override a setting the obligation makes — documented by
//! the tool to take precedence over the environment — cannot have the
//! obligation kept, and is `OBLIGATION_UNENFORCEABLE`:
//!
//! | family | kept by | undone by (refused) |
//! |---|---|---|
//! | `git` | the variables | `-c`, `--config-env`, `--exec-path` before the subcommand; `clone -c`/`--config` |
//! | `python*` | the variables | `-E` among the interpreter's own options |
//! | `pytest`, `py.test` | the variables, and `-p no:cacheprovider` first | `-p cacheprovider` |
//! | `npm`, `npx`, `pnpm`, `yarn`, `bun`, `cargo`, a `cargo-*` subcommand, and the wrappers that run them (`rustup`, `corepack`) | **not kept**: no real-tool evidence in an environment yet | — |
//! | a runner (`env`, `time`, `xargs`, …) or `uv` | the variables | an argument naming one of the tools above to run |
//! | anything else | the variables (it reads none of them) | — |
//!
//! **What it never claims.** A repository's own `.git/config` and hooks, a
//! `conftest.py`, a `build.rs`, a `package.json` script the invocation runs,
//! a script named as an argument: these are workspace content, executed by
//! the tool the run was allowed to start. The obligation does not reach
//! them, and is not a containment: the environment — non-root, no
//! capability, read-only root, its network, its limits — is what bounds
//! them (SANDBOX.md §4a, consequence 1).
//!
//! Pure: nothing but the identity's final component and the arguments.

use crate::resource::ExecutableIdentity;

/// Whether the obligation is kept for one invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hygiene {
    /// Kept: started by the trusted launcher, with these arguments before
    /// the invocation's own.
    Kept {
        /// The tool's own neutralising arguments.
        prefix: &'static [&'static str],
    },
    /// Not kept, and why: the invocation is `OBLIGATION_UNENFORCEABLE`.
    Unenforceable(&'static str),
}

/// pytest's one neutralising argument pair: no cache written into the
/// workspace.
const PYTEST_PREFIX: &[&str] = &["-p", "no:cacheprovider"];

/// git's options that set or inject configuration, or choose where its own
/// programs come from, on the command line: they take precedence over the
/// environment the launcher sets.
const GIT_OVERRIDES: &[&str] = &["-c", "--config-env", "--exec-path"];

/// The tools whose neutralisation has no real-tool evidence in an
/// environment yet (ADR-0052 §5a): their obligation is not kept.
const UNEVIDENCED: &[&str] = &["npm", "npx", "pnpm", "yarn", "bun", "cargo"];

/// The wrappers whose purpose is to run those tools: their obligation is
/// not kept either, whatever they are asked to run.
const TOOLCHAIN_WRAPPERS: &[&str] = &["rustup", "corepack"];

/// Whether `name` is one of the tools with no real-tool evidence, a wrapper
/// of them, or a `cargo-*` subcommand binary (which drives Cargo's builds).
fn unevidenced(name: &str) -> bool {
    UNEVIDENCED.contains(&name) || TOOLCHAIN_WRAPPERS.contains(&name) || name.starts_with("cargo-")
}

/// Whether an argument -- or the value after its `=` -- names such a tool by
/// its last path component: what a runner or `uv run` would execute.
fn names_unevidenced(args: &[&str]) -> bool {
    args.iter().any(|arg| {
        let value = arg.split_once('=').map_or(*arg, |(_, value)| value);
        [*arg, value]
            .iter()
            .any(|text| unevidenced(text.rsplit('/').next().unwrap_or(text)))
    })
}

/// The family's name: the identity's last component.
fn program(executable: &ExecutableIdentity) -> &str {
    executable
        .path()
        .components()
        .last()
        .map_or("", |c| c.as_str())
}

/// `python`, `python3`, `python3.14`: the interpreter by its canonical name.
fn is_python(name: &str) -> bool {
    name.strip_prefix("python")
        .is_some_and(|rest| rest.chars().all(|c| c.is_ascii_digit() || c == '.'))
}

/// Whether `arg` is `option`, as itself or `option=value`, or a one-letter
/// option with its value joined.
fn is_option(arg: &str, option: &str) -> bool {
    arg == option
        || arg.strip_prefix(option).is_some_and(|rest| {
            rest.starts_with('=') || (option.len() == 2 && !option.starts_with("--"))
        })
}

/// git's global options whose value is the next argument.
const GIT_VALUED: &[&str] = &[
    "-C",
    "--git-dir",
    "--work-tree",
    "--namespace",
    "--super-prefix",
    "--list-cmds",
];

/// Whether git's own options -- those before the subcommand -- set or inject
/// configuration, or a `clone` configures the repository it makes (which
/// governs its own checkout's hooks). A subcommand's own `-c` (`grep -c`,
/// `commit -c`) is that subcommand's, not configuration.
fn git_overrides(args: &[&str]) -> bool {
    let mut index = 0;
    while let Some(arg) = args.get(index) {
        if *arg == "--" || !arg.starts_with('-') {
            break;
        }
        if GIT_OVERRIDES.iter().any(|option| is_option(arg, option)) {
            return true;
        }
        if GIT_VALUED.contains(arg) {
            index += 1;
        }
        index += 1;
    }
    args.get(index) == Some(&"clone")
        && args
            .iter()
            .skip(index + 1)
            .any(|arg| is_option(arg, "-c") || is_option(arg, "--config"))
}

/// Whether Python's own options — those before the script, `-c` or `-m` —
/// include `-E`, which ignores every `PYTHON*` variable. An option that
/// takes a value (`-W`, `-X`, `--check-hash-based-pycs`) consumes it.
fn python_ignores_environment(args: &[&str]) -> bool {
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        if *arg == "--" || !arg.starts_with('-') || *arg == "-" {
            return false;
        }
        if let Some(long) = arg.strip_prefix("--") {
            if long == "check-hash-based-pycs" {
                let _ = rest.next();
            }
            continue;
        }
        for (at, letter) in arg.char_indices().skip(1) {
            match letter {
                'E' => return true,
                // The rest of the cluster, or the next argument, is code or
                // a module: what follows is the program's.
                'c' | 'm' => return false,
                // The rest of the cluster, or the next argument, is the
                // option's value.
                'W' | 'X' => {
                    if at + 1 == arg.len() {
                        let _ = rest.next();
                    }
                    break;
                }
                _ => {}
            }
        }
    }
    false
}

/// Whether pytest's arguments load the cache plugin the obligation blocks.
fn pytest_loads_cache(args: &[&str]) -> bool {
    let named = |name: &str| matches!(name, "cacheprovider" | "_pytest.cacheprovider");
    args.iter().enumerate().any(|(index, arg)| {
        (*arg == "-p" && args.get(index + 1).is_some_and(|next| named(next)))
            || arg
                .strip_prefix("-p")
                .is_some_and(|rest| named(rest.strip_prefix('=').unwrap_or(rest)))
    })
}

/// Whether `workspace_exec_hygiene` can be kept for `executable` run with
/// `args` (after `argv[0]`) in an environment.
#[must_use]
pub fn hygiene(executable: &ExecutableIdentity, args: &[&str]) -> Hygiene {
    let name = program(executable);
    if unevidenced(name) {
        return Hygiene::Unenforceable("HYGIENE_NOT_EVIDENCED");
    }
    // A program that runs another one its arguments name: kept only if
    // that one is not a tool the obligation has no evidence for.
    if (super::argv::is_runner(name) || name == "uv") && names_unevidenced(args) {
        return Hygiene::Unenforceable("HYGIENE_NOT_EVIDENCED");
    }
    if name == "git" {
        if git_overrides(args) {
            return Hygiene::Unenforceable("HYGIENE_OVERRIDDEN_BY_ARGV");
        }
        return Hygiene::Kept { prefix: &[] };
    }
    if is_python(name) {
        if python_ignores_environment(args) {
            return Hygiene::Unenforceable("HYGIENE_OVERRIDDEN_BY_ARGV");
        }
        return Hygiene::Kept { prefix: &[] };
    }
    if matches!(name, "pytest" | "py.test") {
        if pytest_loads_cache(args) {
            return Hygiene::Unenforceable("HYGIENE_OVERRIDDEN_BY_ARGV");
        }
        return Hygiene::Kept {
            prefix: PYTEST_PREFIX,
        };
    }
    Hygiene::Kept { prefix: &[] }
}

#[cfg(test)]
mod tests {
    use super::{Hygiene, hygiene};
    use crate::resource::ExecutableIdentity;

    fn at(path: &str) -> ExecutableIdentity {
        let components: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
        crate::resource::synthetic::executable(&components, 0xab)
            .unwrap_or_else(|| unreachable!("{path}"))
    }

    fn kept(path: &str, args: &[&str]) -> Option<&'static [&'static str]> {
        match hygiene(&at(path), args) {
            Hygiene::Kept { prefix } => Some(prefix),
            Hygiene::Unenforceable(_) => None,
        }
    }

    #[test]
    fn git_is_kept_unless_its_command_line_configures_it() {
        assert_eq!(kept("/usr/bin/git", &["status"]), Some(&[][..]));
        assert_eq!(
            kept("/usr/bin/git", &["log", "--oneline", "-5"]),
            Some(&[][..])
        );
        // A subcommand's own `-c` is not configuration.
        assert_eq!(
            kept("/usr/bin/git", &["grep", "-c", "needle"]),
            Some(&[][..])
        );
        assert_eq!(kept("/usr/bin/git", &["commit", "-m", "-c"]), Some(&[][..]));
        assert_eq!(
            kept("/usr/bin/git", &["-C", "/workspace", "status"]),
            Some(&[][..])
        );
        for undo in [
            &["-c", "core.pager=less", "log"][..],
            &["-ccore.pager=less", "log"],
            &["--config-env=core.editor=E", "commit"],
            &["--config-env", "core.editor=E", "commit"],
            &["--exec-path=/tmp", "status"],
            &["clone", "-c", "core.hooksPath=/x", "u"],
            &["clone", "--config=core.hooksPath=/x", "u"],
            &["-C", "/workspace", "-c", "x=y", "status"],
        ] {
            assert_eq!(kept("/usr/bin/git", undo), None, "{undo:?}");
        }
    }

    #[test]
    fn python_is_kept_unless_its_own_options_ignore_the_environment() {
        for ok in [
            &["script.py"][..],
            &["-m", "pytest", "-E"],
            &["-c", "import sys; print(sys.path)", "-E"],
            &["-I", "script.py"],
            &["-B", "-W", "E", "script.py"],
            &["-X", "Eutf8", "script.py"],
            &["--check-hash-based-pycs", "E", "script.py"],
            &["-cE"],
            &["script.py", "-E"],
        ] {
            assert_eq!(kept("/usr/bin/python3.14", ok), Some(&[][..]), "{ok:?}");
        }
        for undo in [
            &["-E", "script.py"][..],
            &["-BE", "-c", "x"],
            &["-sEm", "pip"],
        ] {
            assert_eq!(kept("/usr/bin/python3", undo), None, "{undo:?}");
        }
        assert_eq!(kept("/usr/bin/python", &["-E"]), None);
    }

    #[test]
    fn pytest_gets_its_cache_disabled_unless_the_invocation_loads_it() {
        assert_eq!(
            kept("/usr/local/bin/pytest", &["-q", "tests"]),
            Some(&["-p", "no:cacheprovider"][..])
        );
        assert_eq!(
            kept("/usr/bin/py.test", &["-p", "no:randomly"]),
            Some(&["-p", "no:cacheprovider"][..])
        );
        for undo in [
            &["-p", "cacheprovider"][..],
            &["-pcacheprovider"],
            &["-p=cacheprovider"],
            &["-p", "_pytest.cacheprovider"],
        ] {
            assert_eq!(kept("/usr/local/bin/pytest", undo), None, "{undo:?}");
        }
    }

    #[test]
    fn a_tool_without_real_tool_evidence_is_not_kept() {
        for tool in ["npm", "npx", "pnpm", "yarn", "bun", "cargo"] {
            assert_eq!(
                hygiene(&at(&format!("/usr/bin/{tool}")), &["install"]),
                Hygiene::Unenforceable("HYGIENE_NOT_EVIDENCED"),
                "{tool}"
            );
        }
    }

    #[test]
    fn a_wrapper_or_runner_of_an_unevidenced_tool_is_not_kept() {
        for (path, args) in [
            ("/usr/bin/rustup", &["run", "stable", "cargo", "build"][..]),
            ("/usr/bin/rustup", &["update"]),
            ("/usr/bin/corepack", &["pnpm", "install"]),
            ("/usr/bin/cargo-clippy", &[]),
            ("/usr/bin/env", &["cargo", "build"]),
            (
                "/usr/bin/env",
                &["CARGO_NET_OFFLINE=0", "/usr/bin/cargo", "build"],
            ),
            ("/usr/bin/time", &["npm", "install"]),
            ("/usr/bin/xargs", &["-0", "yarn"]),
            ("/usr/bin/uv", &["run", "cargo", "test"]),
            (
                "/usr/bin/nice",
                &["-n", "5", "/usr/local/bin/bun", "install"],
            ),
        ] {
            assert_eq!(
                hygiene(&at(path), args),
                Hygiene::Unenforceable("HYGIENE_NOT_EVIDENCED"),
                "{path} {args:?}"
            );
        }
        // Not a wrapper: the word is data. A runner of anything else is kept.
        assert_eq!(
            kept("/usr/bin/git", &["commit", "-m", "cargo"]),
            Some(&[][..])
        );
        assert_eq!(kept("/usr/bin/env", &["rg", "-n", "x"]), Some(&[][..]));
        assert_eq!(kept("/usr/bin/uv", &["sync"]), Some(&[][..]));
    }

    #[test]
    fn anything_else_reads_none_of_the_settings_and_is_kept() {
        assert_eq!(kept("/usr/bin/rg", &["-n", "x"]), Some(&[][..]));
        assert_eq!(kept("/opt/tools/fixture", &["-c", "-E"]), Some(&[][..]));
    }
}
