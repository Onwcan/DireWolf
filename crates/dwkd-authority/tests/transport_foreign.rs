//! A real second operating-system user against the real authority (M3e).
//!
//! The only evidence that the server derives identity from the **kernel**:
//! a client process running under another uid connects, and the kernel — not
//! anything the client sends — reports that uid to the server, whose peer
//! policy refuses it before reading a byte. A test that constructed an
//! `AuthenticatedSubject` for another uid inside the server would prove none
//! of this.
//!
//! The harness switches users, never the authority: it runs
//! `tests/authority/foreign_peer_client.py` through `sudo -n -u $DW_PEER_AS`.
//! Where no second identity is available the test is **not exercised**, and it
//! fails rather than passing: it is `#[ignore]`d so that `cargo test` stays
//! runnable on a one-user machine, and `make authority-transport-evidence`
//! selects both tests by name with `--ignored`, requires `DW_PEER_AS`, and
//! fails unless both ran and reported every case. CI's Linux job provides one.
//!
//! The second identity is proven by numbers: the uid a process started as
//! `DW_PEER_AS` reports must differ from this process's and must not be root.
//! The harness opens only what that user must reach -- the fixture root and
//! the client's staging directory, traverse-only (`0711`) -- and asserts that
//! the state directory, `kernel.db`, `audit.log` and the IPC directory are
//! still closed to it. Writes to the state files themselves are attempted as
//! the same user by `make authority-write-probe`.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

use dwk_proto as _;
use proptest as _;
use rusqlite as _;
#[cfg(target_os = "linux")]
use rustix as _;
use sha2 as _;
use toml as _;

mod state_support;
#[cfg(target_os = "linux")]
mod transport_support;

#[cfg(target_os = "linux")]
mod linux {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::time::{Duration, Instant};

    use dwk_proto::dwkp::DwkpBody;
    use dwk_proto::json::{self, ParseOptions, Value};

    use super::state_support::{TempDir, acquire_msg, heartbeat_msg, session};
    use super::transport_support::{
        BIN, Client, Fixture, PROMPT, Server, evidence, handshake, own_uid,
    };

    /// The second identity, proven by numbers, or a failure that says why it
    /// is missing: the user named by `DW_PEER_AS`, and the uid a process
    /// actually started as that user reports -- which must be neither this
    /// process's nor root's. A name is not evidence; two uids are.
    fn peer_user() -> (String, u32) {
        let user = std::env::var("DW_PEER_AS").unwrap_or_default();
        assert!(
            !user.is_empty(),
            "NOT EXERCISED: set DW_PEER_AS to a second user that `sudo -n -u` can switch to \
             (CI uses `nobody`); a cross-uid property is never passed without one"
        );
        let probe = Command::new("sudo")
            .args(["-n", "-u", &user, "id", "-u"])
            .output()
            .expect("sudo runs");
        assert!(
            probe.status.success(),
            "NOT EXERCISED: `sudo -n -u {user}` cannot start a process here: {}",
            String::from_utf8_lossy(&probe.stderr)
        );
        let reported = String::from_utf8_lossy(&probe.stdout).trim().to_owned();
        let uid: u32 = reported
            .parse()
            .unwrap_or_else(|_| panic!("`id -u` as {user} printed {reported:?}"));
        eprintln!(
            "second identity: the authority and this harness run as uid {}; \
             DW_PEER_AS={user} runs as uid {uid}",
            own_uid()
        );
        assert_ne!(
            uid,
            own_uid(),
            "DW_PEER_AS={user} is this process's own uid: that is one identity, not two"
        );
        assert_ne!(
            uid, 0,
            "DW_PEER_AS={user} is root, which is outside the threat model: the hostile peer \
             must be an ordinary local user"
        );
        (user, uid)
    }

    /// Open `dir` to the second identity for traversal only (`0711`): it can
    /// reach a name it already knows -- the socket, the client script -- and
    /// can neither list nor create, remove or rename anything in it. Every
    /// ancestor must already be traversable by others, or the socket would be
    /// unreachable for a reason that has nothing to do with the peer gate.
    fn traversable_only(dir: &Path) {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o711)).unwrap();
        for ancestor in dir.ancestors().skip(1) {
            let mode = std::fs::metadata(ancestor).unwrap().permissions().mode();
            assert!(
                mode & 0o001 != 0,
                "{} is not traversable by other users (mode {mode:o}); place the test's \
                 temporary directory where a second identity can reach it",
                ancestor.display()
            );
        }
    }

    /// What the second identity must never be able to write, after the
    /// harness opened the fixture's root for traversal: the private state
    /// directory, `kernel.db`, `audit.log`, and the IPC naming directory.
    fn assert_authority_state_still_private(fx: &Fixture) {
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o7777;
        let owner = |path: &Path| std::fs::metadata(path).unwrap().uid();
        assert_eq!(
            mode(fx.dir.path()),
            0o711,
            "the fixture root: traverse only"
        );
        let state = fx.state();
        assert_eq!(owner(&state), own_uid());
        assert_eq!(mode(&state) & 0o077, 0, "the state directory is private");
        for file in ["kernel.db", "audit.log"] {
            let path = state.join(file);
            assert_eq!(owner(&path), own_uid(), "{file}");
            assert_eq!(mode(&path) & 0o077, 0, "{file} is private");
        }
        let ipc = fx.socket().parent().unwrap().to_path_buf();
        assert_eq!(
            owner(&ipc),
            own_uid(),
            "the IPC directory is the authority's"
        );
        assert_eq!(
            mode(&ipc) & 0o022,
            0,
            "no one else can write the IPC directory"
        );
    }

    fn python() -> &'static str {
        if Path::new("/usr/bin/python3").exists() {
            "/usr/bin/python3"
        } else {
            "python3"
        }
    }

    /// The client script, copied where the second user can read it.
    fn staged_client(dir: &TempDir) -> PathBuf {
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/authority/foreign_peer_client.py");
        let staged = dir.path().join("foreign_peer_client.py");
        std::fs::copy(&source, &staged).expect("the client script");
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o644)).unwrap();
        staged
    }

    /// Run the client as `user`; its one JSON line. It starts in the staging
    /// directory, which it can traverse, rather than in the harness's own.
    fn run_as(user: &str, script: &Path, args: &[&str]) -> json::Object {
        let output = Command::new("sudo")
            .args(["-n", "-u", user, python()])
            .arg(script)
            .args(args)
            .current_dir(script.parent().unwrap())
            .output()
            .expect("sudo runs the client");
        assert!(
            output.status.success(),
            "the foreign client failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let line = String::from_utf8(output.stdout).unwrap();
        match json::parse(line.trim().as_bytes(), ParseOptions::dwkp()) {
            Ok(Value::Object(object)) => object,
            other => panic!("not a report: {other:?}\n{line}"),
        }
    }

    fn int(object: &json::Object, key: &str) -> u64 {
        match object.get(key) {
            Some(Value::Number(json::Number::Int(n))) => u64::try_from(*n).unwrap(),
            other => panic!("{key}: {other:?}"),
        }
    }

    fn flag(object: &json::Object, key: &str) -> bool {
        matches!(object.get(key), Some(Value::Bool(true)))
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn await_count(fx: &Fixture, event: &str, count: usize) {
        let deadline = Instant::now() + PROMPT;
        while fx.events(event).len() < count {
            assert!(Instant::now() < deadline, "{count} {event} records");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    #[ignore = "needs a second OS identity (DW_PEER_AS); run by `make authority-transport-evidence`"]
    fn a_real_foreign_uid_is_refused_by_the_identity_the_kernel_reports() {
        let (user, peer_uid) = peer_user();
        let fx = Fixture::new("f-peer");
        // The fixture's directory must be traversable for the socket to be
        // reachable at all: this is about the peer gate, not directory modes.
        traversable_only(fx.dir.path());
        let staging = TempDir::new("f-client");
        traversable_only(staging.path());
        let script = staged_client(&staging);
        // The operator lists this process's uid, and only it: the second
        // identity is not in the peer policy.
        let mut server = Server::start(&fx.args(&[]));
        assert_authority_state_still_private(&fx);
        let socket = fx.socket().display().to_string();
        let frame = hex(&handshake(1, 1, 1).to_frame().unwrap());

        // A perfectly valid handshake from the other uid.
        let hello = run_as(&user, &script, &["hello", &socket, &frame]);
        let foreign = u32::try_from(int(&hello, "euid")).unwrap();
        assert_eq!(foreign, peer_uid, "the client runs as the second identity");
        assert_ne!(foreign, own_uid(), "a genuinely different uid");
        assert!(
            flag(&hello, "connected"),
            "the socket was reachable: {hello:?}"
        );
        assert_eq!(int(&hello, "received"), 0, "not one byte came back");
        assert!(flag(&hello, "eof"), "the server closed it");
        await_count(&fx, "transport.peer_refused", 1);
        let refused = fx.events("transport.peer_refused");
        assert_eq!(
            refused[0].int("uid"),
            Some(u64::from(foreign)),
            "the uid the kernel reported is the client's own"
        );
        assert_eq!(refused[0].int("pid"), Some(int(&hello, "pid")));
        assert_eq!(refused[0].text("reason"), Some("uid_not_allowed"));
        evidence(
            "peer",
            "foreign-uid-valid-handshake",
            "peer-gate",
            true,
            true,
        );

        // Malformed bytes from the same uid: still refused unparsed.
        let garbage = run_as(&user, &script, &["garbage", &socket]);
        assert_eq!(int(&garbage, "received"), 0);
        await_count(&fx, "transport.peer_refused", 2);
        assert!(
            fx.events("transport.protocol_violation").is_empty(),
            "nothing from the foreign uid was parsed"
        );
        evidence(
            "peer",
            "foreign-uid-malformed-payload",
            "peer-gate",
            true,
            true,
        );

        // A flood from the foreign uid while the allowed peer keeps working.
        let flood_script = script.clone();
        let flood_user = user.clone();
        let flood_socket = socket.clone();
        let flood_frame = frame.clone();
        let flood = std::thread::spawn(move || {
            run_as(
                &flood_user,
                &flood_script,
                &["flood", &flood_socket, "100", &flood_frame],
            )
        });
        let mut allowed = Client::connect(&fx.socket());
        allowed.handshake();
        let s = session(1);
        let DwkpBody::LeaseGrant(grant) = allowed.call(&acquire_msg(&s)).body else {
            panic!("the allowed peer is served during the flood")
        };
        let flooded = flood.join().unwrap();
        assert_eq!(int(&flooded, "received"), 0);
        assert!(matches!(
            allowed.call(&heartbeat_msg(&s, grant.epoch)).body,
            DwkpBody::Ack(_)
        ));
        std::thread::sleep(Duration::from_millis(500));
        let refusals = fx.events("transport.peer_refused").len();
        assert_eq!(
            refusals, 32,
            "102 refusals in one window write the allowance"
        );
        assert!(
            fx.events("lease.acquired").len() == 1,
            "no authority for the foreign uid"
        );
        assert!(
            fx.events("transport.peer_refused")
                .iter()
                .all(|r| r.int("uid") == Some(u64::from(foreign))),
            "every refusal names the uid the kernel reported, and no other"
        );
        assert!(
            fx.events("run.admitted").is_empty(),
            "no run exists for anyone"
        );
        assert_authority_state_still_private(&fx);
        // The whole chain, as an operator verifies it, once the server is gone.
        server.kill();
        let verified = Command::new(BIN)
            .arg("verify-audit")
            .arg(fx.state())
            .output()
            .expect("verify-audit runs");
        assert!(
            verified.status.success(),
            "{}",
            String::from_utf8_lossy(&verified.stderr)
        );
        assert!(String::from_utf8_lossy(&verified.stdout).contains("chain intact"));
        evidence("peer", "foreign-uid-flood", "peer-gate", true, true);
    }

    #[test]
    #[ignore = "needs a second OS identity (DW_PEER_AS); run by `make authority-transport-evidence`"]
    fn a_foreign_uid_cannot_remove_replace_or_shadow_the_socket() {
        let (user, peer_uid) = peer_user();
        let fx = Fixture::new("f-socket");
        traversable_only(fx.dir.path());
        let staging = TempDir::new("f-client-socket");
        traversable_only(staging.path());
        let script = staged_client(&staging);
        let _server = Server::start(&fx.args(&[]));
        assert_authority_state_still_private(&fx);
        let before = std::fs::symlink_metadata(fx.socket()).unwrap();

        let report = run_as(
            &user,
            &script,
            &["impersonate", &fx.socket().display().to_string()],
        );
        assert_eq!(
            u32::try_from(int(&report, "euid")).unwrap(),
            peer_uid,
            "the attempts ran as the second identity"
        );
        let Some(Value::Array(attempts)) = report.get("attempts") else {
            panic!("attempts: {report:?}")
        };
        assert_eq!(attempts.len(), 7);
        for attempt in attempts {
            let Value::Object(attempt) = attempt else {
                panic!("an attempt")
            };
            let name = match attempt.get("attempt") {
                Some(Value::String(name)) => name.clone(),
                other => panic!("an attempt's name: {other:?}"),
            };
            assert!(
                flag(attempt, "refused"),
                "{name} SUCCEEDED as the foreign uid"
            );
            // Refused for the right reason: the kernel's permission check.
            // Binding at the name finds it occupied first -- and removing the
            // occupant is the unlink above, refused for permission.
            let errno = match attempt.get("errno") {
                Some(Value::String(errno)) => errno.clone(),
                other => panic!("{name}: errno {other:?}"),
            };
            let permission = matches!(errno.as_str(), "EACCES" | "EPERM");
            let occupied = name == "bind a socket at its name" && errno == "EADDRINUSE";
            assert!(
                permission || occupied,
                "{name} was refused with {errno}, not by a permission check"
            );
        }
        assert_authority_state_still_private(&fx);
        // The name is still the authority's, and still answers as it.
        let after = std::fs::symlink_metadata(fx.socket()).unwrap();
        assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
        let mut client = Client::connect(&fx.socket());
        client.handshake();
        evidence(
            "socket",
            "foreign-uid-impersonation",
            "filesystem",
            true,
            false,
        );
    }
}
