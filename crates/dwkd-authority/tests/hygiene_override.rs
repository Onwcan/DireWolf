//! Why `workspace_exec_hygiene` is **unenforceable** on the host in M4d
//! (ADR-0045 §11): the attacks, run for real.
//!
//! The obligation promises that an interpreter's auto-loaded configuration is
//! neutralised for the invocation (SANDBOX.md §4a). The only host-side means
//! M4d would have is the environment — `GIT_CONFIG_NOSYSTEM`,
//! `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_CONFIG_COUNT=0`, `PYTHONSAFEPATH`,
//! `PYTHONNOUSERSITE`, and the like. These tests show, with the real tools,
//! that the environment does not deliver the promise:
//!
//! * a repository's own hooks and configuration are workspace content, which
//!   no environment variable turns off: `git commit` runs `.git/hooks`;
//! * the runtime's own argv overrides the environment: `git -c` runs an alias
//!   command, `python3 -c` puts the working directory back on `sys.path`.
//!
//! So the authority denies an action carrying the obligation
//! (`OBLIGATION_UNENFORCEABLE`) instead of claiming it — the unit tests in
//! `src/state/process/tests.rs` show that decision. The harness runs `git`
//! and `python3` directly: this is a property of those tools, not of the
//! broker, and nothing here is product code.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

use dwk_proto as _;
use dwkd_authority as _;
use proptest as _;
use rusqlite as _;
#[cfg(target_os = "linux")]
use rustix as _;
use sha2 as _;
use toml as _;
use unicode_normalization as _;

mod state_support;

#[cfg(target_os = "linux")]
mod linux {
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::Path;
    use std::process::Command;

    use super::state_support::TempDir;

    /// What the environment form of the obligation would set.
    const HYGIENE: &[(&str, &str)] = &[
        ("GIT_CONFIG_COUNT", "0"),
        ("GIT_CONFIG_GLOBAL", "/dev/null"),
        ("GIT_CONFIG_NOSYSTEM", "1"),
        ("PYTHONNOUSERSITE", "1"),
        ("PYTHONSAFEPATH", "1"),
    ];

    fn evidence(case: &str, outcome: &str) {
        println!(
            "PROC-EVIDENCE {{\"suite\":\"hygiene-override\",\"case\":\"{case}\",\"outcome\":\"{outcome}\",\"count\":1}}"
        );
    }

    /// `program args` in `dir` with the base profile and the hygiene variables.
    fn hygienic(dir: &Path, program: &str, args: &[&str]) -> std::process::Output {
        let mut command = Command::new(program);
        command
            .args(args)
            .current_dir(dir)
            .env_clear()
            .env("HOME", "/nonexistent")
            .env("LANG", "C.UTF-8")
            .env(
                "PATH",
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            );
        for (name, value) in HYGIENE {
            command.env(name, value);
        }
        super::state_support::output(&mut command).unwrap()
    }

    fn git_repository(dir: &Path) {
        for args in [
            &["init", "-q"][..],
            &["config", "user.name", "fixture"],
            &["config", "user.email", "fixture@example.invalid"],
        ] {
            assert!(
                hygienic(dir, "/usr/bin/git", args).status.success(),
                "{args:?}"
            );
        }
    }

    #[test]
    fn a_repositorys_own_hook_runs_whatever_the_environment_says() {
        let dir = TempDir::new("hygiene-hook");
        let repo = dir.path();
        git_repository(repo);
        let hook = repo.join(".git/hooks/pre-commit");
        std::fs::write(&hook, "#!/bin/sh\ntouch hook-ran\n").unwrap();
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
        let committed = hygienic(
            repo,
            "/usr/bin/git",
            &["commit", "-q", "--allow-empty", "-m", "x"],
        );
        assert!(committed.status.success(), "{committed:?}");
        assert!(
            repo.join("hook-ran").exists(),
            "the repository's hook ran despite every GIT_CONFIG_* variable"
        );
        evidence(
            "git-repository-hook-despite-env",
            "hook-ran:env-hygiene-bypassed",
        );
    }

    #[test]
    fn the_runtimes_own_argv_overrides_the_environment() {
        let dir = TempDir::new("hygiene-argv");
        let repo = dir.path();
        git_repository(repo);
        // GIT_CONFIG_COUNT=0 and no global configuration: argv configures
        // anyway, and an alias beginning with `!` runs a command.
        let ran = hygienic(
            repo,
            "/usr/bin/git",
            &["-c", "alias.x=!touch alias-ran", "x"],
        );
        assert!(ran.status.success(), "{ran:?}");
        assert!(repo.join("alias-ran").exists());
        evidence(
            "git-argv-config-runs-a-command",
            "alias-ran:env-hygiene-bypassed",
        );

        // PYTHONSAFEPATH=1 keeps the working directory off sys.path — until
        // the argv puts it back.
        std::fs::write(repo.join("planted.py"), "print('planted-imported')\n").unwrap();
        let refused = hygienic(repo, "/usr/bin/python3", &["-c", "import planted"]);
        assert!(!refused.status.success(), "PYTHONSAFEPATH did its part");
        let imported = hygienic(
            repo,
            "/usr/bin/python3",
            &["-c", "import sys; sys.path.insert(0, ''); import planted"],
        );
        assert!(imported.status.success(), "{imported:?}");
        assert_eq!(
            String::from_utf8_lossy(&imported.stdout).trim(),
            "planted-imported"
        );
        evidence(
            "python-argv-restores-cwd-import",
            "imported:env-hygiene-bypassed",
        );
    }
}
