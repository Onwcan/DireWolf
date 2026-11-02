//! Whether a container exists, as the real-runtime evidence asks the
//! runtime's client itself -- the evidence's side of finding F-ABSENT
//! (`docs/M5E_ASSURANCE_PLAN.md` §5a), whose broker side is `sandbox/oci.rs`.
//!
//! The client fails an inspection alike for a container the runtime does not
//! hold and for a runtime it could not ask: Docker's CLI 29.9.2 prints `[]`
//! and exits 1 for both, the reason on stderr only. So a failed inspection is
//! never an absence. A listing of exactly the container's id is the runtime's
//! own answer, and only when the client succeeded: an empty one says the
//! runtime holds no such container. Any other answer fails the test that
//! asked, never passes it.
//!
//! This file is `crates/dwkd-broker/tests/runtime_support/mod.rs` and
//! `crates/dwkd-authority/tests/runtime_support/mod.rs`, byte for byte;
//! `tests/architecture/test_m5e_attribution.py` holds the two equal and every
//! evidence suite's `exists` to this one.

use std::process::Output;

/// Whether the runtime holds container `id`, its full id, by the client's
/// answer to a listing of exactly that id -- `docker` runs the client with
/// the words given. Panics -- a failed test, never "absent" -- when the
/// client failed, or listed anything but nothing or exactly `id`.
pub(crate) fn exists(docker: impl FnOnce(&[&str]) -> Output, id: &str) -> bool {
    // A name or a short id matches no listing by id: it would read as gone.
    assert!(
        id.len() == 64 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
        "not a container's full id: {id:?}"
    );
    let filter = format!("id={id}");
    let out = docker(&[
        "container",
        "ls",
        "--all",
        "--no-trunc",
        "--quiet",
        "--filter",
        &filter,
    ]);
    assert!(
        out.status.success(),
        "the runtime did not answer whether {id} exists, which is never an absence: {}",
        String::from_utf8_lossy(&out.stderr).trim()
    );
    let listed = String::from_utf8(out.stdout).expect("a listing in UTF-8");
    let named: Vec<&str> = listed.lines().filter(|line| !line.is_empty()).collect();
    match named.as_slice() {
        [] => false,
        [only] if *only == id => true,
        other => panic!("a listing of exactly {id} named {other:?}"),
    }
}

mod tests {
    use std::os::unix::process::ExitStatusExt as _;
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::process::{ExitStatus, Output};

    use super::exists;

    /// The client, having exited `code` and printed `stdout` and `stderr`.
    fn client(code: i32, stdout: &[u8], stderr: &str) -> Output {
        Output {
            status: ExitStatus::from_raw(code << 8),
            stdout: stdout.to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    /// What the client answers when it cannot reach the runtime -- Docker's
    /// CLI 29.9.2, observed against a socket that does not exist: an
    /// inspection `[]` and exit 1, a listing nothing and exit 1.
    fn unreachable(args: &[&str]) -> Output {
        let why = "failed to connect to the docker API at unix:///nonexistent/docker.sock";
        match args {
            ["container", "inspect", ..] => client(1, b"[]\n", why),
            _ => client(1, b"", why),
        }
    }

    /// Whether `exists` failed its test rather than answer.
    fn refused(docker: impl FnOnce(&[&str]) -> Output, id: &str) -> bool {
        catch_unwind(AssertUnwindSafe(|| exists(docker, id))).is_err()
    }

    #[test]
    fn a_container_exists_or_is_gone_only_by_a_listing_of_exactly_it_the_runtime_answered() {
        let id = "c".repeat(64);
        let found = exists(
            |args| {
                assert_eq!(
                    args,
                    [
                        "container",
                        "ls",
                        "--all",
                        "--no-trunc",
                        "--quiet",
                        "--filter",
                        &format!("id={id}")
                    ]
                );
                client(0, format!("{id}\n").as_bytes(), "")
            },
            &id,
        );
        assert!(found);
        // The runtime answered and listed nothing: it holds no such container.
        assert!(!exists(|_| client(0, b"", ""), &id));
    }

    #[test]
    fn a_runtime_that_did_not_answer_is_never_an_absence() {
        let id = "c".repeat(64);
        // The negative control: an inspection's exit status -- the helper this
        // replaced -- reads this runtime as "gone".
        let inspected = unreachable(&["container", "inspect", "--format", "{{.Id}}", &id]);
        assert!(!inspected.status.success());
        assert!(refused(unreachable, &id));
        // Any failure of the client, whatever it printed.
        assert!(refused(|_| client(1, b"", ""), &id));
        assert!(refused(
            |_| client(125, format!("{id}\n").as_bytes(), ""),
            &id
        ));
    }

    #[test]
    fn an_answer_other_than_nothing_or_exactly_the_container_fails_its_test() {
        let id = "c".repeat(64);
        let other = "d".repeat(64);
        for listed in [
            format!("{other}\n"),
            format!("{id}\n{other}\n"),
            format!("{id}\n{id}\n"),
            "not an id\n".to_owned(),
        ] {
            assert!(
                refused(|_| client(0, listed.as_bytes(), ""), &id),
                "{listed:?}"
            );
        }
        assert!(refused(|_| client(0, b"\xff\n", ""), &id));
        // A name, a short id or another spelling is refused before the
        // client is asked, never read as gone from an empty listing.
        for name in ["direwolf-0a1b-env", &id[..12], &"C".repeat(64)] {
            assert!(refused(|_| client(0, b"", ""), name), "{name}");
        }
    }
}
