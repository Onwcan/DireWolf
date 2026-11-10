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
//! | `python*` | the variables | `-E` among the interpreter's own options; `-m pip` or `-m ensurepip` (ADR-0055 P3) |
//! | `pytest`, `py.test` | the variables, and `-p no:cacheprovider` first | `-p cacheprovider` |
//! | `npm` | ADR-0054's profile: `ci` and `install` of registry names; its launch's variables, and its prefix first | any other subcommand or spec, and each argument ADR-0054 §3 lists |
//! | `pip`, `pip3`, `pip3.N` | ADR-0055's profile: `install` of named wheels; its launch's variables, and its prefix after the subcommand | any other subcommand or spec, and each argument ADR-0055 §3 lists |
//! | `npx`, `pnpm`, `yarn`, `bun`, `cargo`, a `cargo-*` subcommand, and the wrappers that run them (`rustup`, `corepack`) | **not kept**: no real-tool evidence in an environment yet | — |
//! | a runner (`env`, `time`, `xargs`, …) or `uv` | the variables | an argument naming one of the tools above to run, or `npm` or pip, whose profiles only their own identity reaches |
//! | anything else | the variables (it reads none of them) | — |
//!
//! **npm's and pip's profiles** (ADR-0054, ADR-0055, accepted 2026-11-11 on
//! M5e.5's hosted evidence): `npm` is kept as ADR-0054's profile and `pip`,
//! `pip3`, `pip3.N` as ADR-0055's, each by its own launch and prefix. A
//! profile is reached only by the tool's own identity: a runner or `uv`
//! naming either is refused, and the interpreter may not run `-m pip` or
//! `-m ensurepip` (the M5e.5 handoff's D4). Every other decision is the one
//! the obligation made before them ([`base`]).
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
    /// Kept under npm's or pip's profile (ADR-0054, ADR-0055): started by
    /// the trusted launcher's profile for it, with `prefix` inserted at `at` among the
    /// invocation's own arguments (0: before them all).
    Profiled {
        /// Which profile.
        profile: Profile,
        /// The profile's neutralising arguments.
        prefix: &'static [&'static str],
        /// Where they go: after this many of the invocation's arguments.
        at: usize,
    },
}

/// pytest's one neutralising argument pair: no cache written into the
/// workspace.
const PYTEST_PREFIX: &[&str] = &["-p", "no:cacheprovider"];

/// git's options that set or inject configuration, or choose where its own
/// programs come from, on the command line: they take precedence over the
/// environment the launcher sets.
const GIT_OVERRIDES: &[&str] = &["-c", "--config-env", "--exec-path"];

/// The tools whose neutralisation has no real-tool evidence in an
/// environment yet (ADR-0052 §5a): their obligation is not kept. `npm`
/// left the list with ADR-0054's acceptance; it has a profile instead.
const UNEVIDENCED: &[&str] = &["npx", "pnpm", "yarn", "bun", "cargo"];

/// The wrappers whose purpose is to run those tools: their obligation is
/// not kept either, whatever they are asked to run.
const TOOLCHAIN_WRAPPERS: &[&str] = &["rustup", "corepack"];

/// Whether `name` is one of the tools with no real-tool evidence, a wrapper
/// of them, or a `cargo-*` subcommand binary (which drives Cargo's builds).
fn unevidenced(name: &str) -> bool {
    UNEVIDENCED.contains(&name) || TOOLCHAIN_WRAPPERS.contains(&name) || name.starts_with("cargo-")
}

/// Whether `name` is a tool with a profile of its own (ADR-0054, ADR-0055):
/// reached only by its own identity, never through a runner, which would
/// start it without its launch or its prefix.
fn profiled(name: &str) -> bool {
    name == "npm" || is_pip(name)
}

/// Whether an argument -- or the value after its `=` -- names such a tool, or
/// one with a profile, by its last path component: what a runner or `uv`
/// would execute.
fn names_unevidenced(args: &[&str]) -> bool {
    args.iter().any(|arg| {
        let value = arg.split_once('=').map_or(*arg, |(_, value)| value);
        [*arg, value].iter().any(|text| {
            let name = text.rsplit('/').next().unwrap_or(text);
            unevidenced(name) || profiled(name)
        })
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
/// `args` (after `argv[0]`) in an environment: npm's and pip's profiles
/// (ADR-0054, ADR-0055), and for every other tool [`base`]'s decision. The
/// interpreter may not run pip's module or ensurepip (ADR-0055 P3).
#[must_use]
pub fn hygiene(executable: &ExecutableIdentity, args: &[&str]) -> Hygiene {
    let name = program(executable);
    if name == "npm" {
        return npm(args);
    }
    if is_pip(name) {
        return pip(args);
    }
    if is_python(name) && python_runs_pip(args) {
        return Hygiene::Unenforceable("HYGIENE_NOT_EVIDENCED");
    }
    base(executable, args)
}

/// The obligation's decision for every tool without a profile: the
/// variables, a tool's own neutralising arguments, or a refusal.
fn base(executable: &ExecutableIdentity, args: &[&str]) -> Hygiene {
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

// ---- npm's and pip's profiles (ADR-0054, ADR-0055) ---------------------------

/// The profile a kept invocation was decided under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// ADR-0054: the launcher's npm variables, npm's prefix.
    Npm,
    /// ADR-0055: the launcher's pip variables, pip's prefix after its
    /// subcommand.
    Pip,
}

/// The arguments ADR-0054 §2 puts before npm's own: each pins a setting the
/// workspace's `.npmrc` could otherwise make. npm reads them anywhere.
const NPM_PREFIX: &[&str] = &[
    "--ignore-scripts",
    "--strict-ssl",
    "--no-audit",
    "--no-fund",
    "--no-update-notifier",
];

/// The two subcommands ADR-0054 §1 keeps, by their canonical words.
const NPM_SUBCOMMANDS: &[&str] = &["ci", "install"];

/// npm's long options ADR-0054 §3 refuses, in any spelling: each sets
/// something the profile pins, writes outside the workspace and `/tmp`, or
/// chooses whom npm trusts. npm expands an unambiguous abbreviation of a
/// long option (nopt), so a prefix of one of these is refused too.
const NPM_REFUSED: &[&str] = &[
    "userconfig",
    "globalconfig",
    "global",
    "location",
    "prefix",
    "script-shell",
    "node-options",
    "foreground-scripts",
    "cafile",
    "ca",
];

/// npm's booleans the profile pins `true`: refused negated (`--no-…`) or set
/// to anything else (ADR-0054 §3's `--ignore-scripts=false`,
/// `--strict-ssl=false`).
const NPM_PINNED_TRUE: &[&str] = &["ignore-scripts", "strict-ssl"];

/// npm's shorthands for a refused option: `-g` is `--global`, `-C` is
/// `--prefix`. A cluster naming either is refused.
const NPM_REFUSED_SHORT: &[char] = &['g', 'C'];

/// npm's long options whose value may be the next argument, so that value
/// is not read as the subcommand or a package (`--registry` is allowed,
/// ADR-0054 §3).
const NPM_VALUED: &[&str] = &[
    "registry",
    "loglevel",
    "tag",
    "omit",
    "include",
    "workspace",
    "cache",
];

/// The suffixes npm reads as a tarball on disk rather than a registry name.
const NPM_TARBALL: &[&str] = &[".tgz", ".tar.gz", ".tar"];

/// One long option, as `--name` or `--name=value`: its name and its value.
fn long_option(arg: &str) -> Option<(&str, Option<&str>)> {
    let rest = arg.strip_prefix("--").filter(|r| !r.is_empty())?;
    Some(match rest.split_once('=') {
        Some((name, value)) => (name, Some(value)),
        None => (rest, None),
    })
}

/// Whether `typed` names `option`: exactly, or as an abbreviation the tool
/// would expand to it (fail-closed: any prefix of it).
fn abbreviates(typed: &str, option: &str) -> bool {
    !typed.is_empty() && option.starts_with(typed)
}

/// Whether one npm argument undoes or widens what ADR-0054 §§2-3 pin.
fn npm_undoes(arg: &str) -> bool {
    if let Some(cluster) = arg.strip_prefix('-').filter(|c| !c.starts_with('-')) {
        return cluster.chars().any(|c| NPM_REFUSED_SHORT.contains(&c));
    }
    let Some((name, value)) = long_option(arg) else {
        return false;
    };
    let (negated, base) = name
        .strip_prefix("no-")
        .map_or((false, name), |base| (true, base));
    NPM_REFUSED.iter().any(|option| abbreviates(base, option))
        || NPM_PINNED_TRUE.iter().any(|option| {
            abbreviates(base, option) && (negated || value.is_some_and(|v| v != "true"))
        })
}

/// Whether an npm long option takes the next argument as its value: one
/// of [`NPM_VALUED`], or a scope's own registry (`--@scope:registry`).
fn npm_takes_value(arg: &str) -> bool {
    long_option(arg).is_some_and(|(name, value)| {
        value.is_none()
            && (NPM_VALUED.contains(&name)
                || (name.starts_with('@') && name.ends_with(":registry")))
    })
}

/// One part of an npm package name: lowercase URL-safe characters, not
/// starting with `.` or `_`.
fn npm_name_part(part: &str) -> bool {
    !part.is_empty()
        && part.len() <= 214
        && !part.starts_with(['.', '_'])
        && part.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'.' | b'_' | b'~')
        })
}

/// An exact version, a range or a dist-tag: nothing that names a place.
fn npm_version_part(part: &str) -> bool {
    !part.is_empty()
        && part.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'.' | b'-'
                        | b'+'
                        | b'^'
                        | b'~'
                        | b'<'
                        | b'>'
                        | b'='
                        | b'|'
                        | b' '
                        | b'*'
                        | b'_'
                )
        })
}

/// ADR-0054 §1's registry names: `name` or `@scope/name`, each optionally
/// `@` a version, range or dist-tag. Never a URL, a path, a tarball, a git or
/// hosting shorthand, `file:`, `link:` or an alias (`npm:`).
fn npm_registry_spec(spec: &str) -> bool {
    let (scope, rest) = match spec.strip_prefix('@') {
        Some(scoped) => match scoped.split_once('/') {
            Some((scope, rest)) => (Some(scope), rest),
            None => return false,
        },
        None => (None, spec),
    };
    let (name, version) = match rest.split_once('@') {
        Some((name, version)) => (name, Some(version)),
        None => (rest, None),
    };
    scope.is_none_or(npm_name_part)
        && npm_name_part(name)
        && !NPM_TARBALL.iter().any(|suffix| name.ends_with(suffix))
        && version.is_none_or(npm_version_part)
}

/// ADR-0054: `npm ci` and `npm install` of registry names, the prefix first,
/// everything else refused before an intent.
fn npm(args: &[&str]) -> Hygiene {
    if args.iter().any(|arg| npm_undoes(arg)) {
        return Hygiene::Unenforceable("HYGIENE_OVERRIDDEN_BY_ARGV");
    }
    if args.contains(&"--") {
        return Hygiene::Unenforceable("HYGIENE_NOT_EVIDENCED");
    }
    let mut positional: Vec<&str> = Vec::new();
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        if arg.starts_with('-') {
            if npm_takes_value(arg) {
                let _ = rest.next();
            }
            continue;
        }
        positional.push(arg);
    }
    let Some((subcommand, specs)) = positional.split_first() else {
        return Hygiene::Unenforceable("HYGIENE_NOT_EVIDENCED");
    };
    if !NPM_SUBCOMMANDS.contains(subcommand) {
        return Hygiene::Unenforceable("HYGIENE_NOT_EVIDENCED");
    }
    let kept = match *subcommand {
        "ci" => specs.is_empty(),
        _ => specs.iter().all(|spec| npm_registry_spec(spec)),
    };
    if !kept {
        return Hygiene::Unenforceable("HYGIENE_NOT_EVIDENCED");
    }
    Hygiene::Profiled {
        profile: Profile::Npm,
        prefix: NPM_PREFIX,
        at: 0,
    }
}

/// pip's one trust file in the image (ADR-0055 §5; proposed path). The
/// authority does not link the profile crate, so it is spelled here and
/// held equal to `dwk_sandbox_profile::PIP_TRUST_FILE` by an architecture
/// test.
pub const PIP_TRUST_FILE: &str = "/etc/direwolf/pip-ca.pem";

/// The arguments ADR-0055 §2 adds to pip's own, after its subcommand --
/// `--only-binary` is `install`'s option, which pip refuses before it.
///
/// `--use-deprecated=legacy-certs` (ADR-0055 §5, revised for F-PIP-TRUST):
/// without it pip builds a `truststore` context holding `certifi`'s roots and
/// the system's store, and loads the `--cert` file beside them; with it pip
/// makes no such context, and the `--cert` file is its whole trust. A
/// workload cannot take it back: pip appends each `--use-deprecated` value.
const PIP_PREFIX: &[&str] = &[
    "--only-binary=:all:",
    "--no-cache-dir",
    "--no-input",
    "--disable-pip-version-check",
    "--use-deprecated=legacy-certs",
    "--cert",
    PIP_TRUST_FILE,
];

/// pip's long options ADR-0055 §3 refuses, in any spelling pip expands
/// (optparse takes an unambiguous abbreviation of a long option). With
/// `cache-dir` beside them: an invocation's cache would undo the profile's
/// `--no-cache-dir` exactly as `--no-binary` would undo `--only-binary`.
const PIP_REFUSED: &[&str] = &[
    "no-binary",
    "editable",
    "config-settings",
    "global-option",
    "build-option",
    "no-build-isolation",
    "use-pep517",
    "no-use-pep517",
    "isolated",
    "proxy",
    "trusted-host",
    "cert",
    "client-cert",
    "requirement",
    "constraint",
    "find-links",
    "user",
    "root",
    "prefix",
    "src",
    "cache-dir",
];

/// pip's exact long options that are also prefixes of a refused one: taken
/// as themselves, as pip takes an exact name before an abbreviation.
const PIP_EXACT: &[&str] = &["pre"];

/// pip's short options ADR-0055 §3 refuses: `-r`, `-c`, `-e`, `-f` and
/// `-C` (`--config-settings`), anywhere in a cluster.
const PIP_REFUSED_SHORT: &[char] = &['r', 'c', 'e', 'f', 'C'];

/// pip's short options whose value follows (in the cluster, or as the next
/// argument): `-i` an index, `-t` a target.
const PIP_VALUED_SHORT: &[char] = &['i', 't'];

/// pip's long options whose value may be the next argument.
const PIP_VALUED: &[&str] = &[
    "index-url",
    "extra-index-url",
    "only-binary",
    "target",
    "log",
    "timeout",
    "retries",
    "exists-action",
    "python",
    "keyring-provider",
    "progress-bar",
    "root-user-action",
    "platform",
    "python-version",
    "implementation",
    "abi",
    "upgrade-strategy",
    "report",
    "use-feature",
    "use-deprecated",
];

/// What pip reads as an archive on disk rather than a project's name.
const PIP_ARCHIVE: &[&str] = &[
    ".whl", ".zip", ".tar.gz", ".tgz", ".tar.bz2", ".tbz", ".tar.xz", ".txz", ".tar", ".tar.lz",
    ".tlz",
];

/// One pip long option's verdict, given its value (`=…`, or the next
/// argument's): whether it undoes or widens ADR-0055 §§2-3.
fn pip_long_undoes(name: &str, value: Option<&str>) -> bool {
    if PIP_EXACT.contains(&name) {
        return false;
    }
    if PIP_REFUSED.iter().any(|option| abbreviates(name, option)) {
        return true;
    }
    if abbreviates(name, "only-binary") {
        return value != Some(":all:");
    }
    if abbreviates(name, "index-url") || abbreviates(name, "extra-index-url") {
        return !value.is_some_and(|url| url.starts_with("https://"));
    }
    false
}

/// Whether pip's arguments undo or widen what ADR-0055 pins, and where its
/// subcommand is: `(undone, positional)`, each positional with its index.
fn pip_read<'a>(args: &[&'a str]) -> (bool, Vec<(usize, &'a str)>) {
    let mut positional = Vec::new();
    let mut index = 0;
    while let Some(arg) = args.get(index) {
        let next = args.get(index + 1).copied();
        if let Some((name, value)) = long_option(arg) {
            let takes = value.is_none() && PIP_VALUED.iter().any(|o| abbreviates(name, o));
            if pip_long_undoes(name, value.or(if takes { next } else { None })) {
                return (true, positional);
            }
            index += if takes { 2 } else { 1 };
            continue;
        }
        if let Some(cluster) = arg.strip_prefix('-').filter(|c| !c.is_empty()) {
            for (at, letter) in cluster.char_indices() {
                if PIP_REFUSED_SHORT.contains(&letter) {
                    return (true, positional);
                }
                if PIP_VALUED_SHORT.contains(&letter) {
                    let joined = cluster
                        .get(at + letter.len_utf8()..)
                        .filter(|v| !v.is_empty());
                    let value = joined.or(next);
                    if letter == 'i' && !value.is_some_and(|url| url.starts_with("https://")) {
                        return (true, positional);
                    }
                    if joined.is_none() {
                        index += 1;
                    }
                    break;
                }
            }
            index += 1;
            continue;
        }
        positional.push((index, *arg));
        index += 1;
    }
    (false, positional)
}

/// ADR-0055 §1's names: a project, optional extras, optional version
/// specifiers. Never a path, a URL, an archive, a VCS reference, a direct
/// reference (`name @ url`) or `.`.
fn pip_name_spec(spec: &str) -> bool {
    let end = spec
        .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')))
        .unwrap_or(spec.len());
    let (name, rest) = spec.split_at(end);
    let lower = name.to_ascii_lowercase();
    if !name.starts_with(|c: char| c.is_ascii_alphanumeric())
        || !name.ends_with(|c: char| c.is_ascii_alphanumeric())
        || PIP_ARCHIVE.iter().any(|suffix| lower.ends_with(suffix))
    {
        return false;
    }
    let rest = match rest.strip_prefix('[') {
        Some(extras) => {
            let Some((inside, after)) = extras.split_once(']') else {
                return false;
            };
            let named = inside.split(',').all(|extra| {
                let extra = extra.trim();
                !extra.is_empty()
                    && extra
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
            });
            if !named {
                return false;
            }
            after
        }
        None => rest,
    };
    rest.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || matches!(
                c,
                '.' | '-' | '_' | '*' | '+' | '!' | '=' | '<' | '>' | '~' | ',' | ' '
            )
    })
}

/// `pip`, `pip3`, `pip3.N`: ADR-0055 §1's identities.
fn is_pip(name: &str) -> bool {
    matches!(name, "pip" | "pip3")
        || name
            .strip_prefix("pip3.")
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// ADR-0055: `pip install` of names, wheels only, its prefix after the
/// subcommand, everything else refused before an intent.
fn pip(args: &[&str]) -> Hygiene {
    if args.contains(&"--") {
        return Hygiene::Unenforceable("HYGIENE_NOT_EVIDENCED");
    }
    let (undone, positional) = pip_read(args);
    if undone {
        return Hygiene::Unenforceable("HYGIENE_OVERRIDDEN_BY_ARGV");
    }
    let Some(((at, subcommand), specs)) = positional.split_first() else {
        return Hygiene::Unenforceable("HYGIENE_NOT_EVIDENCED");
    };
    if *subcommand != "install" || specs.is_empty() || !specs.iter().all(|(_, s)| pip_name_spec(s))
    {
        return Hygiene::Unenforceable("HYGIENE_NOT_EVIDENCED");
    }
    Hygiene::Profiled {
        profile: Profile::Pip,
        prefix: PIP_PREFIX,
        at: at + 1,
    }
}

/// Whether Python's own options run pip's module or ensurepip (`-m pip`,
/// `-mpip`, `-Im ensurepip`, a submodule of either): the interpreter's way
/// around the pip profile (ADR-0055 P3; the handoff's D4).
fn python_runs_pip(args: &[&str]) -> bool {
    let module_is_pip =
        |module: &str| matches!(module.split('.').next(), Some("pip" | "ensurepip"));
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
                'c' => return false,
                'm' => {
                    let joined = arg.get(at + 1..).filter(|m| !m.is_empty());
                    return module_is_pip(joined.or_else(|| rest.next().copied()).unwrap_or(""));
                }
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
            Hygiene::Unenforceable(_) | Hygiene::Profiled { .. } => None,
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
        for tool in ["npx", "pnpm", "yarn", "bun", "cargo"] {
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

    // ---- npm's and pip's profiles ---------------------------------------------

    use super::{Profile, base};

    /// Every input the tests above use: the decisions the obligation made
    /// before the profiles, which neither may change for any tool but its own.
    fn today() -> Vec<(&'static str, Vec<&'static str>)> {
        let mut table: Vec<(&'static str, Vec<&'static str>)> = Vec::new();
        for args in [
            &["status"][..],
            &["log", "--oneline", "-5"],
            &["grep", "-c", "needle"],
            &["-c", "core.pager=less", "log"],
            &["clone", "-c", "core.hooksPath=/x", "u"],
            &["--exec-path=/tmp", "status"],
        ] {
            table.push(("/usr/bin/git", args.to_vec()));
        }
        for args in [
            &["script.py"][..],
            &["-m", "pytest", "-E"],
            &["-I", "script.py"],
            &["-E", "script.py"],
            &["-sE", "script.py"],
            &["-c", "import pip"],
        ] {
            table.push(("/usr/bin/python3", args.to_vec()));
        }
        for args in [&["-q", "tests"][..], &["-p", "cacheprovider"]] {
            table.push(("/usr/local/bin/pytest", args.to_vec()));
        }
        for tool in [
            "npx",
            "pnpm",
            "yarn",
            "bun",
            "cargo",
            "rustup",
            "corepack",
            "cargo-clippy",
        ] {
            table.push((
                Box::leak(format!("/usr/bin/{tool}").into_boxed_str()),
                vec!["install"],
            ));
        }
        for (path, args) in [
            ("/usr/bin/env", &["npm", "ci"][..]),
            ("/usr/bin/env", &["/opt/node/bin/npm", "install", "x"]),
            ("/usr/bin/time", &["npm", "install"]),
            ("/usr/bin/xargs", &["-0", "yarn"]),
            ("/usr/bin/uv", &["run", "npm", "ci"]),
            ("/usr/bin/uv", &["sync"]),
            ("/usr/bin/env", &["rg", "-n", "x"]),
            ("/usr/bin/rg", &["-n", "x"]),
            ("/opt/tools/fixture", &["-c", "-E"]),
        ] {
            table.push((path, args.to_vec()));
        }
        table
    }

    #[test]
    fn the_profiles_change_no_tool_but_their_own() {
        for (path, args) in today() {
            assert_eq!(
                hygiene(&at(path), &args),
                base(&at(path), &args),
                "{path} {args:?}"
            );
        }
        // What the two tools were before their profiles: npm refused, pip kept
        // with nothing pip-specific.
        assert_eq!(
            base(&at("/usr/bin/pip"), &["install", "x"]),
            Hygiene::Kept { prefix: &[] }
        );
        assert!(matches!(
            hygiene(&at("/usr/bin/pip"), &["install", "x"]),
            Hygiene::Profiled {
                profile: Profile::Pip,
                ..
            }
        ));
        assert!(matches!(
            hygiene(&at("/opt/node/bin/npm"), &["ci"]),
            Hygiene::Profiled {
                profile: Profile::Npm,
                ..
            }
        ));
    }

    #[test]
    fn a_runner_naming_npm_or_pip_is_refused() {
        // A profile is reached only by the tool's own identity: through a
        // runner the tool would start without its launch or its prefix.
        for (path, args) in [
            ("/usr/bin/env", &["pip", "install", "x"][..]),
            ("/usr/bin/env", &["/opt/python/bin/pip3", "install", "x"]),
            (
                "/usr/bin/env",
                &["PIP_ONLY_BINARY=:none:", "pip", "install", "x"],
            ),
            ("/usr/bin/time", &["pip3.12", "install", "x"]),
            ("/usr/bin/xargs", &["-0", "pip"]),
            ("/usr/bin/uv", &["pip", "install", "x"]),
            ("/usr/bin/uv", &["run", "pip", "install", "x"]),
            ("/usr/bin/env", &["npm", "ci"]),
            (
                "/usr/bin/nice",
                &["-n", "5", "/opt/node/bin/npm", "install"],
            ),
        ] {
            assert_eq!(
                hygiene(&at(path), args),
                Hygiene::Unenforceable("HYGIENE_NOT_EVIDENCED"),
                "{path} {args:?}"
            );
        }
        // Not pip's identity: a runner naming `pipx` or `pip-compile` is kept.
        for (path, args) in [
            ("/usr/bin/env", &["pipx", "run", "x"][..]),
            ("/usr/bin/time", &["pip-compile", "req.in"]),
        ] {
            assert_eq!(
                hygiene(&at(path), args),
                Hygiene::Kept { prefix: &[] },
                "{path} {args:?}"
            );
        }
    }

    fn npm(args: &[&str]) -> Hygiene {
        hygiene(&at("/opt/node/bin/npm"), args)
    }

    fn refused(decided: &Hygiene) -> Option<&'static str> {
        match decided {
            Hygiene::Unenforceable(reason) => Some(reason),
            Hygiene::Kept { .. } | Hygiene::Profiled { .. } => None,
        }
    }

    #[test]
    fn npm_keeps_ci_and_install_of_registry_names_with_its_prefix() {
        assert_eq!(
            npm(&["ci"]),
            Hygiene::Profiled {
                profile: Profile::Npm,
                prefix: &[
                    "--ignore-scripts",
                    "--strict-ssl",
                    "--no-audit",
                    "--no-fund",
                    "--no-update-notifier"
                ],
                at: 0,
            }
        );
        for ok in [
            &["ci", "--registry", "https://r.test:18443/"][..],
            &["--registry=https://r.test/", "ci"],
            &["install"],
            &["install", "left-pad"],
            &["install", "@scope/pkg@^1.2.0"],
            &["install", "pkg@latest", "other@1.0.0"],
            &["install", "pkg@>=1 <2"],
            &[
                "install",
                "--@scope:registry",
                "https://r.test/",
                "@scope/x",
            ],
            &[
                "install",
                "--ignore-scripts",
                "--ignore-scripts=true",
                "--strict-ssl",
                "x",
            ],
            &["install", "--no-audit", "--no-fund", "--no-save", "x"],
            &["install", "--cache", "/tmp/c", "--loglevel", "silly", "x"],
        ] {
            assert!(
                matches!(
                    npm(ok),
                    Hygiene::Profiled {
                        profile: Profile::Npm,
                        at: 0,
                        ..
                    }
                ),
                "{ok:?}: {:?}",
                npm(ok)
            );
        }
    }

    #[test]
    fn npm_refuses_every_other_subcommand_alias_and_separator() {
        for sub in [
            "run",
            "test",
            "start",
            "stop",
            "restart",
            "exec",
            "x",
            "dlx",
            "rebuild",
            "publish",
            "config",
            "explore",
            "pack",
            "link",
            "uninstall",
            "update",
            "i",
            "isntall",
            "add",
        ] {
            assert_eq!(
                refused(&npm(&[sub])),
                Some("HYGIENE_NOT_EVIDENCED"),
                "{sub}"
            );
        }
        for args in [
            &[][..],
            &["--version"],
            &["ci", "extra"],
            &["install", "--", "x"],
            &["--", "ci"],
        ] {
            assert_eq!(
                refused(&npm(args)),
                Some("HYGIENE_NOT_EVIDENCED"),
                "{args:?}"
            );
        }
    }

    #[test]
    fn npm_refuses_every_spec_that_is_not_a_registry_name() {
        for spec in [
            "https://r.test/x.tgz",
            "http://r.test/x",
            "./local",
            "../up",
            "/abs/path",
            "~/home",
            "x.tgz",
            "pkg.tar.gz",
            "x.tar",
            "git+https://h/x.git",
            "git://h/x",
            "github:user/repo",
            "gitlab:u/r",
            "user/repo",
            "file:../x",
            "link:../x",
            "alias@npm:real",
            "pkg@file:x",
            "pkg@https://x",
            "Pkg",
            "_private",
            ".hidden",
            "@scope",
            "@scope/",
            "@Scope/x",
            "pkg#tag",
            "",
        ] {
            assert_eq!(
                refused(&npm(&["install", spec])),
                Some("HYGIENE_NOT_EVIDENCED"),
                "{spec:?}"
            );
        }
    }

    #[test]
    fn npm_refuses_each_argument_that_would_undo_it_in_every_spelling() {
        for undo in [
            "--ignore-scripts=false",
            "--ignore-scripts=0",
            "--no-ignore-scripts",
            "--ignore-s=false",
            "--no-ignore",
            "--userconfig",
            "--userconfig=/workspace/.npmrc",
            "--userc=/x",
            "--globalconfig",
            "--globalconfig=/x",
            "--strict-ssl=false",
            "--no-strict-ssl",
            "--strict=false",
            "-g",
            "-gS",
            "--global",
            "--global=true",
            "--glob",
            "--location",
            "--location=global",
            "--loc=user",
            "--prefix",
            "--prefix=/x",
            "--pre=/x",
            "-C",
            "--script-shell",
            "--script-shell=/bin/sh",
            "--node-options",
            "--node-options=--require=x",
            "--foreground-scripts",
            "--foreground-scripts=true",
            "--cafile",
            "--cafile=/workspace/ca.pem",
            "--ca",
            "--ca=PEM",
        ] {
            assert_eq!(
                refused(&npm(&["install", undo, "x"])),
                Some("HYGIENE_OVERRIDDEN_BY_ARGV"),
                "{undo}"
            );
            assert_eq!(
                refused(&npm(&[undo, "ci"])),
                Some("HYGIENE_OVERRIDDEN_BY_ARGV"),
                "{undo}"
            );
        }
    }

    fn pip(args: &[&str]) -> Hygiene {
        hygiene(&at("/opt/python/bin/pip"), args)
    }

    #[test]
    fn pip_keeps_install_of_names_with_its_prefix_after_the_subcommand() {
        assert_eq!(
            pip(&["install", "x"]),
            Hygiene::Profiled {
                profile: Profile::Pip,
                prefix: &[
                    "--only-binary=:all:",
                    "--no-cache-dir",
                    "--no-input",
                    "--disable-pip-version-check",
                    "--use-deprecated=legacy-certs",
                    "--cert",
                    "/etc/direwolf/pip-ca.pem"
                ],
                at: 1,
            }
        );
        assert!(matches!(
            pip(&["-v", "install", "x"]),
            Hygiene::Profiled { at: 2, .. }
        ));
        assert!(matches!(
            pip(&["--log", "/tmp/l", "install", "x"]),
            Hygiene::Profiled { at: 3, .. }
        ));
        for ok in [
            &["install", "x==1.0"][..],
            &["install", "x>=1,<2", "y[extra,other]"],
            &[
                "install",
                "--index-url",
                "https://r.test:18443/simple/",
                "x",
            ],
            &["install", "--index-url=https://r/simple", "x"],
            &["install", "-i", "https://r/", "x"],
            &["install", "-ihttps://r/", "x"],
            &["install", "--extra-index-url", "https://e/", "x"],
            &["install", "--only-binary", ":all:", "x"],
            &["install", "--only-binary=:all:", "x"],
            &["install", "--target", "/workspace/t", "x"],
            &["install", "-t", "/tmp/t", "x"],
            &["install", "--no-deps", "--pre", "-U", "--no-index", "x"],
            &[
                "install",
                "--no-cache-dir",
                "--retries",
                "0",
                "--timeout",
                "30",
                "x",
            ],
        ] {
            assert!(
                matches!(
                    pip(ok),
                    Hygiene::Profiled {
                        profile: Profile::Pip,
                        ..
                    }
                ),
                "{ok:?}: {:?}",
                pip(ok)
            );
        }
        for path in ["/usr/bin/pip3", "/usr/bin/pip3.12", "/usr/local/bin/pip"] {
            assert!(matches!(
                hygiene(&at(path), &["install", "x"]),
                Hygiene::Profiled {
                    profile: Profile::Pip,
                    ..
                }
            ));
        }
        // Not pip's identity: `pip-compile`, `pip3x`, `pipx` stay today's.
        for path in ["/usr/bin/pip-compile", "/usr/bin/pip3x", "/usr/bin/pipx"] {
            assert_eq!(
                hygiene(&at(path), &["install", "x"]),
                Hygiene::Kept { prefix: &[] },
                "{path}"
            );
        }
    }

    #[test]
    fn pip_refuses_every_other_subcommand_and_an_install_of_nothing() {
        for sub in [
            "download",
            "wheel",
            "uninstall",
            "config",
            "cache",
            "debug",
            "freeze",
            "list",
            "show",
            "check",
            "hash",
            "index",
            "inspect",
            "lock",
            "search",
            "completion",
            "help",
            "i",
            "Install",
        ] {
            assert_eq!(
                refused(&pip(&[sub, "x"])),
                Some("HYGIENE_NOT_EVIDENCED"),
                "{sub}"
            );
        }
        for args in [
            &[][..],
            &["install"],
            &["--version"],
            &["install", "--", "x"],
        ] {
            assert_eq!(
                refused(&pip(args)),
                Some("HYGIENE_NOT_EVIDENCED"),
                "{args:?}"
            );
        }
    }

    #[test]
    fn pip_refuses_every_spec_that_is_not_a_name() {
        for spec in [
            ".",
            "./x",
            "../x",
            "/abs/x",
            "x/y",
            "C:\\x",
            "x.whl",
            "x-1.0-py3-none-any.whl",
            "x.tar.gz",
            "x.zip",
            "x.tgz",
            "https://h/x.whl",
            "git+https://h/x.git",
            "hg+https://h/x",
            "x @ https://h/x.whl",
            "x@https://h/x",
            "file:///x",
            "x; python_version>'3'",
            "-",
            "~/x",
            "x#egg=y",
            "[extra]",
            "x[",
            "",
        ] {
            assert_eq!(
                refused(&pip(&["install", spec])),
                Some("HYGIENE_NOT_EVIDENCED"),
                "{spec:?}"
            );
        }
    }

    #[test]
    fn pip_refuses_each_argument_that_would_undo_or_widen_it() {
        for undo in [
            &["--no-binary", ":all:"][..],
            &["--no-binary=x"],
            &["--no-bin=:all:"],
            &["--only-binary", "x"],
            &["--only-binary=:none:"],
            &["--only-b=x"],
            &["-e", "."],
            &["-e."],
            &["--editable", "."],
            &["--edit=."],
            &["--config-settings", "a=b"],
            &["-C", "a=b"],
            &["-Ca=b"],
            &["--global-option=x"],
            &["--build-option=x"],
            &["--no-build-isolation"],
            &["--use-pep517"],
            &["--no-use-pep517"],
            &["--isolated"],
            &["--isol"],
            &["--proxy", "http://p"],
            &["--proxy=http://p"],
            &["--trusted-host", "h"],
            &["--trusted-host=h"],
            &["--cert", "/workspace/ca.pem"],
            &["--cert=/workspace/ca.pem"],
            &["--client-cert", "/workspace/c.pem"],
            &["-r", "req.txt"],
            &["-rreq.txt"],
            &["--requirement=req.txt"],
            &["-Ur", "req.txt"],
            &["-c", "c.txt"],
            &["--constraint", "c.txt"],
            &["-f", "/workspace/wheels"],
            &["--find-links=https://h/"],
            &["--user"],
            &["--root", "/x"],
            &["--prefix=/x"],
            &["--src", "/x"],
            &["--cache-dir", "/workspace/c"],
            &["--index-url", "http://plain/simple"],
            &["--index-url=http://plain"],
            &["-i", "http://plain"],
            &["-ihttp://plain"],
            &["--extra-index-url", "ftp://x"],
            &["--index-url"],
        ] {
            let mut args = vec!["install"];
            args.extend_from_slice(undo);
            args.push("x");
            assert_eq!(
                refused(&pip(&args)),
                Some("HYGIENE_OVERRIDDEN_BY_ARGV"),
                "{undo:?}"
            );
        }
        for before in [
            &["--isolated"][..],
            &["--cert", "/w/ca.pem"],
            &["--proxy=http://p"],
        ] {
            let mut args = before.to_vec();
            args.extend(["install", "x"]);
            assert_eq!(
                refused(&pip(&args)),
                Some("HYGIENE_OVERRIDDEN_BY_ARGV"),
                "{before:?}"
            );
        }
    }

    #[test]
    fn with_pips_profile_the_interpreter_cannot_run_pip_or_ensurepip() {
        let python = at("/usr/bin/python3");
        for runs in [
            &["-m", "pip", "install", "x"][..],
            &["-mpip", "install"],
            &["-I", "-m", "pip"],
            &["-Im", "pip"],
            &["-Impip"],
            &["-m", "ensurepip"],
            &["-m", "pip._internal"],
            &["-B", "-W", "ignore", "-m", "pip"],
            &["-X", "utf8", "-m", "pip"],
        ] {
            assert_eq!(
                hygiene(&python, runs),
                Hygiene::Unenforceable("HYGIENE_NOT_EVIDENCED"),
                "{runs:?}"
            );
            // Before pip's profile, the interpreter was kept for these.
            assert_eq!(
                base(&python, runs),
                Hygiene::Kept { prefix: &[] },
                "{runs:?}"
            );
        }
        for not in [
            &["-m", "pytest"][..],
            &["-m", "pipx"],
            &["-m", "piptools"],
            &["script.py", "-m", "pip"],
            &["-c", "import pip"],
            &["-m", "mypip"],
        ] {
            assert_eq!(hygiene(&python, not), base(&python, not), "{not:?}");
        }
    }

    #[test]
    fn npx_the_runners_and_the_wrappers_stay_refused() {
        {
            for (path, args) in [
                ("/opt/node/bin/npx", &["cowsay"][..]),
                ("/usr/bin/env", &["npm", "ci"]),
                ("/usr/bin/env", &["/opt/node/bin/npm", "install", "x"]),
                ("/usr/bin/time", &["npm", "install"]),
                ("/usr/bin/uv", &["run", "npm", "ci"]),
                ("/usr/bin/corepack", &["npm", "ci"]),
            ] {
                assert_eq!(
                    hygiene(&at(path), args),
                    Hygiene::Unenforceable("HYGIENE_NOT_EVIDENCED"),
                    "{path} {args:?}"
                );
            }
        }
    }
}
