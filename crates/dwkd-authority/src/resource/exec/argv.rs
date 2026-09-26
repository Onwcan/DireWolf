//! The argv classifier (M4d, [ADR-0045] §8): whether an invocation's
//! arguments would be **reinterpreted** by what runs them — the value policy's
//! `when.argv_safe` matches.
//!
//! [`POLICY.md`] §3 is precise about what this is not: it is not a scan for
//! shell metacharacters. `argv` is an array and never reaches a shell, so `$`,
//! `;` and `|` in a commit message are ordinary bytes. It is `REINTERPRETING`
//! only for argv that something would read as a program:
//!
//! | rule | what | example |
//! |---|---|---|
//! | R1 | the executable is an interpreter or a shell | `/usr/bin/python3.14 …`, `/usr/bin/dash …`, `awk`, `make` |
//! | R2 | the executable runs another program named in its argv | `env`, `xargs`, `timeout`, `sudo`, `ssh`, `busybox` |
//! | R3 | an exec-style option or word of a known tool family | `find -exec`, `git -c`, `git <alias>`, `tar --to-command`, `rsync -e`, `cc -B`, `npm run` |
//! | R4 | an argument — or the value after its `=` — whose last path component names an R1 or R2 program | `find . -name sh`, `make SHELL=/bin/bash` |
//!
//! Everything else is `SAFE`. The tables are **closed**: a tool not named is
//! judged by R1, R2 and R4 alone, and an option this table does not know is
//! not assumed dangerous — but every family below errs towards
//! `REINTERPRETING` where its semantics are open-ended (an unknown `git`
//! subcommand may be an alias or `git-<name>` on `PATH`; an unknown `cargo`
//! subcommand is `cargo-<name>`). False positives cost an approval; a false
//! negative would be a silent grant, so this is where the error goes.
//!
//! **What this does not judge.** A tool reading code from the workspace —
//! `cargo build` running `build.rs`, `git` honouring a repository's
//! `core.pager` or hooks — executes workspace content, not argv. That is
//! bounded by the environment profile (`workspace_exec_hygiene`) and, for
//! host execution, by the approval that must precede it; not by this
//! classification, which never claims to.
//!
//! Pure: no filesystem, no environment, nothing but the identity's final
//! component and the arguments.
//!
//! [ADR-0045]: ../../../../../docs/adr/0045-m4d-process-execution-broker.md
//! [`POLICY.md`]: ../../../../../docs/POLICY.md

use crate::resource::ExecutableIdentity;

/// Which rule made argv reinterpreting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Rule {
    /// R1: the executable is an interpreter or a shell.
    Interpreter,
    /// R2: the executable runs a program its argv names.
    Runner,
    /// R3: an exec-style option or word of the executable's family.
    ExecStyle,
    /// R4: an argument names an interpreter, a shell or a runner.
    NamesProgram,
}

impl Rule {
    /// A stable code, for the audit record.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Interpreter => "R1_INTERPRETER",
            Self::Runner => "R2_RUNNER",
            Self::ExecStyle => "R3_EXEC_STYLE",
            Self::NamesProgram => "R4_NAMES_PROGRAM",
        }
    }
}

/// The classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArgvClass {
    /// Nothing in argv would be reinterpreted.
    Safe,
    /// Something would: the rule, and the 0-based index of the argument
    /// (after `argv[0]`) it fired on, if one.
    Reinterpreting {
        /// Which rule.
        rule: Rule,
        /// Which argument, if the rule is about one.
        index: Option<usize>,
    },
}

/// Interpreters and shells, by exact name.
const SHELLS: &[&str] = &[
    "sh",
    "ash",
    "bash",
    "dash",
    "zsh",
    "ksh",
    "ksh93",
    "mksh",
    "pdksh",
    "oksh",
    "yash",
    "fish",
    "csh",
    "tcsh",
    "elvish",
    "nu",
    "xonsh",
    "pwsh",
    "powershell",
    "osh",
    "oil",
    "nodejs",
    "deno",
    "bun",
    "tsx",
    "ts-node",
    "awk",
    "gawk",
    "mawk",
    "nawk",
    "busybox-awk",
    "make",
    "gmake",
    "bmake",
    "expect",
    "java",
    "jshell",
    "irb",
    "Rscript",
    "R",
    "jq-shell",
    "vim",
    "vi",
    "nvim",
    "ex",
    "emacs",
    "ed",
    "gdb",
    "lldb",
    "sed",
    "gsed",
];

/// Interpreters named with a version suffix: `python3.14`, `perl5.38`,
/// `ruby3.3`, `node22`. The suffix is digits, dots and hyphens only.
const VERSIONED: &[&str] = &[
    "python", "pypy", "perl", "ruby", "php", "lua", "luajit", "node", "tclsh", "wish", "guile",
    "julia", "ocaml", "racket", "sbcl", "clisp", "scheme", "gawk",
];

/// The names R4 looks for in an argument: interpreters, shells and runners
/// whose names are not also ordinary words. `time`, `watch`, `script`,
/// `open`, `make` or `fish` in an argument is far more often a word than a
/// program, and R1/R2 still judge them as the executable itself.
const NAMED_PROGRAMS: &[&str] = &[
    "sh",
    "ash",
    "bash",
    "dash",
    "zsh",
    "ksh",
    "ksh93",
    "mksh",
    "pdksh",
    "oksh",
    "yash",
    "csh",
    "tcsh",
    "pwsh",
    "powershell",
    "nodejs",
    "awk",
    "gawk",
    "mawk",
    "nawk",
    "gmake",
    "bmake",
    "osascript",
    "jshell",
    "irb",
    "Rscript",
    "busybox",
    "toybox",
    "coreutils",
    "env",
    "xargs",
    "sudo",
    "su",
    "doas",
    "pkexec",
    "runuser",
    "setpriv",
    "nohup",
    "setsid",
    "nsenter",
    "unshare",
    "chroot",
    "strace",
    "ltrace",
    "gdb",
    "lldb",
    "valgrind",
    "timeout",
    "stdbuf",
    "ionice",
    "chrt",
    "taskset",
    "firejail",
    "bwrap",
    "ssh",
    "sshpass",
    "npx",
    "pipx",
    "uvx",
];

/// Programs whose job is to run another program named in their argv.
const RUNNERS: &[&str] = &[
    "env",
    "xargs",
    "nohup",
    "nice",
    "ionice",
    "chrt",
    "taskset",
    "timeout",
    "time",
    "stdbuf",
    "setsid",
    "chroot",
    "sudo",
    "su",
    "doas",
    "runuser",
    "pkexec",
    "setpriv",
    "unshare",
    "nsenter",
    "strace",
    "ltrace",
    "valgrind",
    "watch",
    "script",
    "flock",
    "parallel",
    "exec",
    "command",
    "systemd-run",
    "runcon",
    "firejail",
    "bwrap",
    "docker",
    "podman",
    "ssh",
    "scp",
    "sftp",
    "sshpass",
    "perf",
    "fakeroot",
    "proot",
    "wine",
    "tmux",
    "screen",
    "entr",
    "npx",
    "pnpx",
    "bunx",
    "uvx",
    "pipx",
    "busybox",
    "toybox",
    "coreutils",
    "catchsegv",
    "numactl",
    "prlimit",
    "sg",
    "newgrp",
    "cgexec",
    "start-stop-daemon",
    "daemonize",
    "dbus-launch",
    "dbus-run-session",
    "systemd-inhibit",
    "caffeinate",
    "qemu-user",
    "faketime",
    "torsocks",
    "proxychains",
    "proxychains4",
    "ssh-agent",
    "gpg-agent",
    "open",
    "xdg-open",
    "at",
    "batch",
    "crontab",
    "chpst",
    "softlimit",
    "setuidgid",
    "envdir",
    "setlock",
    "s6-setuidgid",
    "dumb-init",
    "tini",
    "catatonit",
];

/// A tool family's exec-style options and words.
struct Family {
    names: &'static [&'static str],
    /// An option: matches the argument exactly, as `option=value`, or — for a
    /// single-dash short option — with its value joined (`-Ifoo`).
    options: &'static [&'static str],
    /// A word that makes the family run something wherever it appears.
    words: &'static [&'static str],
    /// Whether the family accepts clustered short options (`-avze ssh`), so a
    /// one-letter option is found anywhere in a single-dash cluster.
    clusters: bool,
}

const FAMILIES: &[Family] = &[
    Family {
        names: &["find", "gfind", "bfs"],
        options: &["-exec", "-execdir", "-ok", "-okdir", "-fprint0"],
        words: &[],
        clusters: false,
    },
    Family {
        names: &["tar", "gtar", "bsdtar"],
        options: &[
            "--to-command",
            "--use-compress-program",
            "-I",
            "--checkpoint-action",
            "--info-script",
            "--new-volume-script",
            "-F",
            "--rsh-command",
            "--rmt-command",
        ],
        words: &[],
        clusters: true,
    },
    Family {
        names: &["rsync"],
        options: &["-e", "--rsh", "--rsync-path", "--daemon"],
        words: &[],
        clusters: true,
    },
    Family {
        names: &["zip"],
        options: &["-TT", "--unzip-command"],
        words: &[],
        clusters: true,
    },
    Family {
        names: &["sort", "gsort"],
        options: &["--compress-program"],
        words: &[],
        clusters: false,
    },
    Family {
        names: &["npm", "pnpm", "yarn", "bun"],
        options: &["--script-shell", "--node-options"],
        words: &[
            "exec",
            "x",
            "run",
            "run-script",
            "dlx",
            "test",
            "start",
            "stop",
            "restart",
            "rebuild",
            "explore",
        ],
        clusters: false,
    },
    Family {
        names: &["go"],
        options: &["-exec", "-toolexec", "-vettool", "--exec"],
        words: &["run", "generate", "tool", "env"],
        clusters: false,
    },
    Family {
        names: &[
            "cc", "c++", "gcc", "g++", "clang", "clang++", "cpp", "ld", "ld.bfd", "ld.gold",
        ],
        options: &[
            "-B",
            "-wrapper",
            "-fplugin",
            "-specs",
            "--specs",
            "-fuse-ld",
            "--ld-path",
            "-Xclang",
            "-plugin",
            "--plugin",
            "-Wl,-plugin",
            "-Wl,--plugin",
        ],
        words: &[],
        clusters: false,
    },
    Family {
        names: &["rustc", "rustdoc"],
        options: &["-C", "--codegen", "-Z", "--extern"],
        words: &[],
        clusters: false,
    },
    Family {
        names: &["uv"],
        options: &[],
        words: &["run", "tool", "tools"],
        clusters: false,
    },
    Family {
        names: &["pip", "pip3"],
        options: &[],
        words: &["install", "download", "wheel"],
        clusters: false,
    },
];

/// `git`'s global options that configure or run something: before the
/// subcommand only, where they mean this.
const GIT_GLOBAL_EXEC: &[&str] = &["-c", "--config-env", "--exec-path"];

/// Options that run something, per `git` subcommand. After the subcommand a
/// short option means that subcommand's thing: `commit -c` reuses a message,
/// `clone -c` sets configuration before fetching.
const GIT_SUBCOMMAND_EXEC: &[(&str, &[&str])] = &[
    (
        "clone",
        &["-u", "--upload-pack", "-c", "--config", "--template"],
    ),
    ("init", &["--template"]),
    ("fetch", &["--upload-pack"]),
    ("pull", &["--upload-pack"]),
    ("ls-remote", &["--upload-pack"]),
    ("push", &["--receive-pack", "--exec"]),
    ("archive", &["--exec"]),
    ("rebase", &["-x", "--exec"]),
    ("grep", &["-O", "--open-files-in-pager"]),
    ("diff", &["--ext-diff", "--textconv"]),
    ("log", &["--ext-diff", "--textconv"]),
    ("show", &["--ext-diff", "--textconv"]),
    ("whatchanged", &["--ext-diff", "--textconv"]),
    ("blame", &["--textconv"]),
    ("cat-file", &["--textconv", "--filters"]),
];

/// `git`'s global options, before the subcommand, and whether each takes the
/// next argument.
const GIT_GLOBALS: &[(&str, bool)] = &[
    ("-C", true),
    ("--git-dir", true),
    ("--work-tree", true),
    ("--namespace", true),
    ("-P", false),
    ("--no-pager", false),
    ("--bare", false),
    ("--no-replace-objects", false),
    ("--literal-pathspecs", false),
    ("--glob-pathspecs", false),
    ("--noglob-pathspecs", false),
    ("--icase-pathspecs", false),
    ("--no-optional-locks", false),
];

/// `git`'s built-in subcommands that run nothing named by argv. An alias, an
/// external `git-<name>`, the subcommands whose job is to run a command
/// (`bisect`, `submodule`, `filter-branch`, `difftool`, `mergetool`,
/// `daemon`, `instaweb`, `send-email`, `credential`), and `config`, which
/// writes what a later invocation will execute, are absent.
const GIT_BUILTINS: &[&str] = &[
    "add",
    "am",
    "annotate",
    "apply",
    "archive",
    "blame",
    "branch",
    "bundle",
    "cat-file",
    "check-attr",
    "check-ignore",
    "checkout",
    "checkout-index",
    "cherry",
    "cherry-pick",
    "clean",
    "clone",
    "commit",
    "commit-tree",
    "count-objects",
    "describe",
    "diff",
    "diff-files",
    "diff-index",
    "diff-tree",
    "fetch",
    "for-each-ref",
    "format-patch",
    "fsck",
    "gc",
    "grep",
    "hash-object",
    "help",
    "init",
    "log",
    "ls-files",
    "ls-remote",
    "ls-tree",
    "merge",
    "merge-base",
    "mv",
    "notes",
    "pull",
    "push",
    "range-diff",
    "read-tree",
    "rebase",
    "reflog",
    "remote",
    "repack",
    "replace",
    "reset",
    "restore",
    "rev-list",
    "rev-parse",
    "revert",
    "rm",
    "shortlog",
    "show",
    "show-ref",
    "sparse-checkout",
    "stash",
    "status",
    "switch",
    "symbolic-ref",
    "tag",
    "update-index",
    "update-ref",
    "verify-commit",
    "verify-tag",
    "version",
    "whatchanged",
    "worktree",
    "write-tree",
];

/// `cargo`'s built-in subcommands. Anything else is `cargo-<name>` found on
/// `PATH`: another executable.
const CARGO_BUILTINS: &[&str] = &[
    "build",
    "b",
    "check",
    "c",
    "clean",
    "doc",
    "d",
    "new",
    "init",
    "add",
    "remove",
    "run",
    "r",
    "test",
    "t",
    "bench",
    "update",
    "search",
    "publish",
    "install",
    "uninstall",
    "fetch",
    "fix",
    "generate-lockfile",
    "help",
    "locate-project",
    "login",
    "logout",
    "metadata",
    "owner",
    "package",
    "pkgid",
    "report",
    "rustc",
    "rustdoc",
    "tree",
    "vendor",
    "verify-project",
    "version",
    "yank",
];

/// `cargo`'s options that configure a runner or a linker.
const CARGO_OPTIONS: &[&str] = &["--config", "-Z"];

/// Whether `name` names an interpreter or a shell.
fn is_interpreter(name: &str) -> bool {
    SHELLS.contains(&name)
        || VERSIONED.iter().any(|base| {
            name.strip_prefix(base).is_some_and(|rest| {
                rest.chars()
                    .all(|c| c.is_ascii_digit() || c == '.' || c == '-')
            })
        })
}

fn is_runner(name: &str) -> bool {
    RUNNERS.contains(&name)
}

/// R4's test: an unambiguous program name, or a versioned interpreter.
fn names_program(name: &str) -> bool {
    NAMED_PROGRAMS.contains(&name)
        || VERSIONED.iter().any(|base| {
            name.strip_prefix(base).is_some_and(|rest| {
                rest.chars()
                    .all(|c| c.is_ascii_digit() || c == '.' || c == '-')
            })
        })
}

/// Whether `arg` is `option`: exactly, as `option=value`, or — a one-letter
/// option — with its value joined (`-Ixz`).
fn is_option(arg: &str, option: &str) -> bool {
    arg == option
        || arg
            .strip_prefix(option)
            .is_some_and(|rest| rest.starts_with('=') || (is_short(option) && !rest.is_empty()))
}

/// A one-letter, single-dash option.
fn is_short(option: &str) -> bool {
    option.len() == 2 && option.starts_with('-') && !option.starts_with("--")
}

/// Whether a one-letter `option` appears in a single-dash cluster (`-avze`).
fn in_cluster(arg: &str, option: &str) -> bool {
    is_short(option)
        && arg.starts_with('-')
        && !arg.starts_with("--")
        && option
            .strip_prefix('-')
            .is_some_and(|letter| arg.get(1..).is_some_and(|cluster| cluster.contains(letter)))
}

/// The last path component of `text`.
fn basename(text: &str) -> &str {
    text.rsplit('/').next().unwrap_or(text)
}

/// Classify `args` (after `argv[0]`) run by `executable`.
#[must_use]
pub fn classify(executable: &ExecutableIdentity, args: &[&str]) -> ArgvClass {
    let program = executable
        .path()
        .components()
        .last()
        .map_or("", |c| c.as_str());
    let fired = |rule, index| ArgvClass::Reinterpreting { rule, index };
    if is_interpreter(program) {
        return fired(Rule::Interpreter, None);
    }
    if is_runner(program) {
        return fired(Rule::Runner, None);
    }
    if let Some(index) = exec_style(program, args) {
        return fired(Rule::ExecStyle, Some(index));
    }
    for (index, arg) in args.iter().enumerate() {
        let value = arg.split_once('=').map_or(*arg, |(_, value)| value);
        if [basename(arg), basename(value)]
            .iter()
            .any(|c| names_program(c))
        {
            return fired(Rule::NamesProgram, Some(index));
        }
    }
    ArgvClass::Safe
}

/// R3: the family's exec-style options and words: the index of the argument
/// that fired, if one did.
fn exec_style(program: &str, args: &[&str]) -> Option<usize> {
    match program {
        "git" => git(args),
        "cargo" => cargo(args),
        _ => {
            let family = FAMILIES.iter().find(|f| f.names.contains(&program))?;
            args.iter().position(|arg| {
                family
                    .options
                    .iter()
                    .any(|o| is_option(arg, o) || (family.clusters && in_cluster(arg, o)))
                    || family.words.contains(arg)
            })
        }
    }
}

fn git(args: &[&str]) -> Option<usize> {
    // The subcommand: the first argument after the global options.
    let mut index = 0usize;
    while let Some(arg) = args.get(index) {
        if GIT_GLOBAL_EXEC.iter().any(|o| is_option(arg, o)) {
            return Some(index);
        }
        if let Some((_, takes)) = GIT_GLOBALS.iter().find(|(option, _)| {
            arg == option || arg.strip_prefix(option).is_some_and(|r| r.starts_with('='))
        }) {
            let joined = arg.contains('=');
            index = index.saturating_add(if *takes && !joined { 2 } else { 1 });
            continue;
        }
        if arg.starts_with('-') {
            // A global option this table does not know.
            return Some(index);
        }
        break;
    }
    match args.get(index) {
        // `git` alone prints its usage.
        None => None,
        Some(subcommand) if GIT_BUILTINS.contains(subcommand) => {
            let options = GIT_SUBCOMMAND_EXEC
                .iter()
                .find(|(name, _)| name == subcommand)
                .map_or(&[][..], |(_, options)| *options);
            let after = index.saturating_add(1);
            args.get(after..)?
                .iter()
                .position(|arg| options.iter().any(|o| is_option(arg, o)))
                .map(|offset| after.saturating_add(offset))
        }
        Some(_) => Some(index),
    }
}

fn cargo(args: &[&str]) -> Option<usize> {
    if let Some(index) = args
        .iter()
        .position(|arg| CARGO_OPTIONS.iter().any(|o| is_option(arg, o)))
    {
        return Some(index);
    }
    // The subcommand: the first argument that is not an option. A toolchain
    // selector (`+nightly`) is rustup's, and names another executable.
    let index = args.iter().position(|arg| !arg.starts_with('-'))?;
    let subcommand = args.get(index)?;
    if subcommand.starts_with('+') || !CARGO_BUILTINS.contains(subcommand) {
        return Some(index);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{ArgvClass, Rule, classify};
    use crate::resource::synthetic;

    fn class(path: &[&str], args: &[&str]) -> ArgvClass {
        let Some(identity) = synthetic::executable(path, 0xab) else {
            unreachable!("a synthetic identity")
        };
        classify(&identity, args)
    }

    fn rule(path: &[&str], args: &[&str]) -> Option<(Rule, Option<usize>)> {
        match class(path, args) {
            ArgvClass::Safe => None,
            ArgvClass::Reinterpreting { rule, index } => Some((rule, index)),
        }
    }

    const GIT: &[&str] = &["usr", "bin", "git"];

    /// `make process-broker-evidence` requires every case (ADR-0045 §22).
    fn evidence(case: &str, outcome: &str) {
        println!(
            "PROC-EVIDENCE {{\"suite\":\"argv-classifier\",\"case\":\"{case}\",\"outcome\":\"{outcome}\",\"count\":1}}"
        );
    }

    #[test]
    fn shell_text_in_an_argument_is_data() {
        // POLICY.md: argv never reaches a shell, so these are ordinary bytes.
        for args in [
            &["commit", "-m", "fix: $HOME; rm -rf / | cat `id` && echo"][..],
            &["log", "--grep=a|b", "--format=%H"],
            &["show", "HEAD~1:src/main.rs"],
            &["add", "--", "*.rs"],
        ] {
            assert_eq!(class(GIT, args), ArgvClass::Safe, "{args:?}");
        }
        assert_eq!(
            class(&["usr", "bin", "ls"], &["-la", "$(id)"]),
            ArgvClass::Safe
        );
        evidence("argv-literal-shell-text-is-data", "Safe");
    }

    #[test]
    fn an_interpreter_or_a_shell_is_reinterpreting_by_its_canonical_name() {
        for path in [
            &["usr", "bin", "dash"][..],
            &["usr", "bin", "bash"],
            &["usr", "bin", "python3.14"],
            &["usr", "bin", "python3"],
            &["usr", "bin", "perl5.40.1"],
            &["usr", "bin", "node"],
            &["usr", "bin", "mawk"],
            &["usr", "bin", "make"],
        ] {
            assert_eq!(
                rule(path, &["--version"]),
                Some((Rule::Interpreter, None)),
                "{path:?}"
            );
        }
        // A near name is not a version suffix.
        assert_eq!(class(&["usr", "bin", "pythonista"], &[]), ArgvClass::Safe);
        evidence("argv-safe-interpreter", "Reinterpreting:Interpreter");
    }

    #[test]
    fn a_runner_is_reinterpreting_whatever_it_runs() {
        for name in [
            "env",
            "xargs",
            "timeout",
            "nice",
            "sudo",
            "ssh",
            "busybox",
            "coreutils",
        ] {
            assert_eq!(
                rule(&["usr", "bin", name], &["true"]),
                Some((Rule::Runner, None)),
                "{name}"
            );
        }
        evidence("argv-safe-runner", "Reinterpreting:Runner");
    }

    #[test]
    fn exec_style_options_fire_where_they_stand() {
        let find = &["usr", "bin", "find"][..];
        assert_eq!(rule(find, &[".", "-name", "x"]), None);
        assert_eq!(
            rule(find, &[".", "-exec", "rm", "{}", ";"]),
            Some((Rule::ExecStyle, Some(1)))
        );
        let tar = &["usr", "bin", "tar"][..];
        assert_eq!(rule(tar, &["-czf", "a.tgz", "src"]), None);
        assert_eq!(
            rule(tar, &["-xf", "a.tar", "--to-command=sh"]),
            Some((Rule::ExecStyle, Some(2)))
        );
        assert_eq!(
            rule(tar, &["-Ixz", "-cf", "a"]),
            Some((Rule::ExecStyle, Some(0)))
        );
        assert_eq!(
            rule(&["usr", "bin", "rsync"], &["-e", "ssh -p 2", "a", "b"]),
            Some((Rule::ExecStyle, Some(0)))
        );
        assert_eq!(
            rule(&["usr", "bin", "gcc"], &["-O2", "-B/tmp/evil", "a.c"]),
            Some((Rule::ExecStyle, Some(1)))
        );
        assert_eq!(
            rule(&["usr", "bin", "npm"], &["run", "build"]),
            Some((Rule::ExecStyle, Some(0)))
        );
        assert_eq!(rule(&["usr", "bin", "npm"], &["ls"]), None);
        evidence("argv-safe-exec-style-option", "Reinterpreting:ExecStyle");
    }

    #[test]
    fn git_runs_nothing_argv_names_unless_configured_aliased_or_external() {
        assert_eq!(rule(GIT, &["status", "--short"]), None);
        assert_eq!(rule(GIT, &["-C", "/workspace", "log", "-1"]), None);
        assert_eq!(rule(GIT, &["--no-pager", "diff"]), None);
        assert_eq!(rule(GIT, &[]), None);
        for (args, index) in [
            (&["-c", "core.pager=less", "log"][..], 0),
            (&["-ccore.sshCommand=x", "fetch"], 0),
            (&["--config-env=core.editor=E", "commit"], 0),
            (&["clone", "--upload-pack=touch /tmp/p", "x"], 1),
            (&["clone", "-c", "core.hooksPath=/x", "u"], 1),
            (&["rebase", "--exec", "true", "main"], 1),
            (&["rebase", "-x", "true"], 1),
            (&["grep", "-Oless", "x"], 1),
            (&["config", "alias.x", "!true"], 0),
            // An alias or an external `git-<name>`.
            (&["st"], 0),
            (&["lfs", "pull"], 0),
            (&["bisect", "run", "make"], 0),
            (&["submodule", "foreach", "echo"], 0),
            (&["filter-branch"], 0),
            (&["--unknown-global", "status"], 0),
        ] {
            assert_eq!(
                rule(GIT, args),
                Some((Rule::ExecStyle, Some(index))),
                "{args:?}"
            );
        }
        evidence(
            "argv-safe-git-config-alias-external",
            "Reinterpreting:ExecStyle",
        );
    }

    #[test]
    fn a_short_option_after_the_subcommand_means_that_subcommands_thing() {
        for args in [
            &["push", "-u", "origin", "main"][..],
            &["clean", "-x", "-f"],
            &["cherry-pick", "-x", "abc"],
            &["commit", "-c", "HEAD"],
            &["grep", "-c", "needle"],
            &["checkout", "-t", "origin/x"],
            &["add", "-u"],
        ] {
            assert_eq!(rule(GIT, args), None, "{args:?}");
        }
    }

    #[test]
    fn a_clustered_short_option_is_found_where_the_family_clusters() {
        let rsync = &["usr", "bin", "rsync"][..];
        assert_eq!(rule(rsync, &["-avz", "a/", "b/"]), None);
        assert_eq!(
            rule(rsync, &["-avze", "ssh -p 2", "a", "b"]),
            Some((Rule::ExecStyle, Some(0)))
        );
        // gcc does not cluster: -DBAR is a definition, not -B.
        assert_eq!(rule(&["usr", "bin", "gcc"], &["-DBAR=1", "a.c"]), None);
    }

    #[test]
    fn cargo_names_an_external_subcommand_or_a_runner_only_explicitly() {
        let cargo = &["home", "u", ".cargo", "bin", "cargo"][..];
        assert_eq!(rule(cargo, &["build", "--release"]), None);
        assert_eq!(rule(cargo, &["test", "-q", "-p", "x"]), None);
        assert_eq!(
            rule(cargo, &["clippy"]),
            Some((Rule::ExecStyle, Some(0))),
            "cargo-clippy is another executable on PATH"
        );
        assert_eq!(
            rule(cargo, &["+nightly", "build"]),
            Some((Rule::ExecStyle, Some(0)))
        );
        assert_eq!(
            rule(cargo, &["build", "--config", "target.x.runner='sh'"]),
            Some((Rule::ExecStyle, Some(1)))
        );
        evidence("argv-safe-cargo-external", "Reinterpreting:ExecStyle");
    }

    #[test]
    fn an_argument_naming_a_shell_or_a_runner_is_reinterpreting() {
        let ls = &["usr", "bin", "ls"][..];
        assert_eq!(rule(ls, &["sh"]), Some((Rule::NamesProgram, Some(0))));
        assert_eq!(
            rule(ls, &["-l", "/bin/bash"]),
            Some((Rule::NamesProgram, Some(1)))
        );
        assert_eq!(
            rule(&["usr", "bin", "cp"], &["SHELL=/usr/bin/zsh", "x"]),
            Some((Rule::NamesProgram, Some(0)))
        );
        // A word that merely contains a program's name does not, and a runner
        // whose name is an ordinary word is judged only as the executable.
        assert_eq!(rule(ls, &["bash-completion", "shell.txt", "envoy"]), None);
        assert_eq!(rule(ls, &["-l", "--sort=time"]), None);
        assert_eq!(rule(GIT, &["commit", "-m", "script"]), None);
        assert_eq!(
            rule(ls, &["python3.12"]),
            Some((Rule::NamesProgram, Some(0)))
        );
        evidence("argv-safe-names-a-program", "Reinterpreting:NamesProgram");
    }
}
