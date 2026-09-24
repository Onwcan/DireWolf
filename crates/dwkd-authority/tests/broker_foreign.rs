//! Three real operating-system identities on the M4b channel (ADR-0043).
//!
//! The authority is this process's uid. The broker runs as `DW_BROKER_AS`,
//! started by this harness through `sudo -n -u` -- the harness switches users;
//! the authority never does (TX010). A hostile local process -- the runtime's
//! position -- runs as `DW_PEER_AS`. Each identity is proven by numbers: the
//! uid a process started as that user reports must differ from the others and
//! must not be root.
//!
//! What only this suite can show:
//!
//! * the broker reads the workspace file **only** through the descriptor the
//!   authority sent: its own uid cannot open that file by path;
//! * the broker reads nothing from a peer the kernel reports as any uid but
//!   the authority's, whatever that peer sends;
//! * the authority sends nothing to a listener the kernel reports as any uid
//!   but the broker's;
//! * the broker's identity can neither read nor write the authority's state,
//!   nor speak DWKP to it.
//!
//! Without the identities these tests are `#[ignore]`d, and `make
//! broker-fs-read-evidence` fails as NOT EXERCISED rather than passing. The
//! hosted Linux CI job creates both users and runs them.

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
use unicode_normalization as _;

#[cfg(target_os = "linux")]
mod broker_support;
mod state_support;
#[cfg(target_os = "linux")]
mod transport_support;

#[cfg(target_os = "linux")]
mod linux {
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use dwk_proto::brokerp::{self, ChannelNonce, FsReadAuthorisation};
    use dwk_proto::dwkp::DwkpBody;
    use dwk_proto::json::{self, ParseOptions, Value};
    use dwk_proto::wire::id::InvocationId;
    use dwk_proto::wire::scalar::{ReadLimit, ToolFailureReason};

    use super::broker_support::{Broker, Runtime, Setup, broker_bin, evidence};
    use super::state_support::TempDir;
    use super::transport_support::{Server, handshake, own_uid};

    const SUITE: &str = "broker-foreign";

    /// The user `variable` names, proven by the uid a process started as it
    /// reports: not this process's, not root, not any in `others`.
    fn identity(variable: &str, others: &[u32]) -> (String, u32) {
        let user = std::env::var(variable).unwrap_or_default();
        assert!(
            !user.is_empty(),
            "NOT EXERCISED: set {variable} to a user `sudo -n -u` can switch to; a cross-uid \
             property is never passed without one"
        );
        let probe = super::state_support::output(
            Command::new("sudo").args(["-n", "-u", &user, "id", "-u"]),
        )
        .expect("sudo runs");
        assert!(
            probe.status.success(),
            "NOT EXERCISED: `sudo -n -u {user}` cannot start a process here: {}",
            String::from_utf8_lossy(&probe.stderr)
        );
        let uid: u32 = String::from_utf8_lossy(&probe.stdout)
            .trim()
            .parse()
            .unwrap();
        eprintln!(
            "{variable}={user} runs as uid {uid}; this process is uid {}",
            own_uid()
        );
        assert_ne!(
            uid,
            own_uid(),
            "{variable} is this process's uid: one identity, not two"
        );
        assert_ne!(
            uid, 0,
            "{variable} is root, which is outside the threat model"
        );
        assert!(
            !others.contains(&uid),
            "{variable} shares a uid with another identity"
        );
        (user, uid)
    }

    fn identities() -> ((String, u32), (String, u32)) {
        let broker = identity("DW_BROKER_AS", &[]);
        let peer = identity("DW_PEER_AS", &[broker.1]);
        (broker, peer)
    }

    /// Traverse-only for other users: they can reach a name they know and can
    /// neither list nor change the directory.
    fn traversable_only(dir: &Path) {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o711)).unwrap();
        for ancestor in dir.ancestors().skip(1) {
            let mode = std::fs::metadata(ancestor).unwrap().permissions().mode();
            assert!(
                mode & 0o001 != 0,
                "{} is not traversable by other users (mode {mode:o})",
                ancestor.display()
            );
        }
    }

    fn private(dir: &Path) {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    /// The broker binary and the probe client, copied where other users can
    /// execute and read them.
    struct Staging {
        dir: TempDir,
        broker: PathBuf,
        client: PathBuf,
    }

    fn staging() -> Staging {
        let dir = TempDir::new("m4b-staging");
        traversable_only(dir.path());
        let broker = dir.path().join("dwkd-broker");
        std::fs::copy(broker_bin(), &broker).unwrap();
        std::fs::set_permissions(&broker, std::fs::Permissions::from_mode(0o755)).unwrap();
        let client = dir.path().join("broker_foreign_client.py");
        std::fs::copy(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/authority/broker_foreign_client.py"),
            &client,
        )
        .unwrap();
        std::fs::set_permissions(&client, std::fs::Permissions::from_mode(0o644)).unwrap();
        Staging {
            dir,
            broker,
            client,
        }
    }

    /// A socket directory the broker creates for itself under `/tmp`, whose
    /// owner is root and which is sticky: the broker's ancestor rules accept
    /// it, and every identity can reach a name in it.
    fn broker_socket(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        PathBuf::from(format!("/tmp/dwb-{tag}-{}-{nanos}", std::process::id())).join("broker.sock")
    }

    fn python() -> &'static str {
        if Path::new("/usr/bin/python3").exists() {
            "/usr/bin/python3"
        } else {
            "python3"
        }
    }

    fn run_as(user: &str, staging: &Staging, args: &[&str]) -> json::Object {
        let output = super::state_support::output(
            Command::new("sudo")
                .args(["-n", "-u", user, python()])
                .arg(&staging.client)
                .args(args)
                .current_dir(staging.dir.path()),
        )
        .expect("sudo runs the client");
        assert!(
            output.status.success(),
            "the client failed as {user}: {}",
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

    /// The workspace closed to everyone but the authority; the state and IPC
    /// directories as the authority makes them; the fixture root traverse-only
    /// so the DWKP socket is reachable and the peer gate, not a mode bit, is
    /// what answers.
    fn separated_setup(tag: &str) -> Setup {
        let setup = Setup::new(tag);
        traversable_only(setup.dir.path());
        private(&setup.root);
        private(&setup.outside);
        setup
    }

    #[test]
    #[ignore = "needs DW_BROKER_AS and DW_PEER_AS; run by `make broker-fs-read-evidence`"]
    fn three_identities_read_only_through_the_checked_descriptor() {
        let ((broker_user, broker_uid), (peer_user, peer_uid)) = identities();
        let stage = staging();
        let setup = separated_setup("m4b-3id");
        let socket = broker_socket("3id");
        let broker = Broker::start_as(&broker_user, &stage.broker, &socket, own_uid());
        assert_eq!(
            broker.uid(),
            broker_uid,
            "the broker runs as its own identity"
        );

        // The broker's identity cannot read the workspace file by its path.
        let file = setup.root.join("bytes.bin");
        let by_path = run_as(
            &broker_user,
            &stage,
            &["read-path", &file.display().to_string()],
        );
        assert!(
            flag(&by_path, "refused"),
            "the broker uid read the file by path"
        );
        evidence(SUITE, "broker-uid-cannot-open-by-path", "EACCES", 0);

        // The authority, told the broker's socket and uid, reads through it.
        let mut args = setup.authority_args(None, &[]);
        args.extend([
            "--broker-socket".to_owned(),
            socket.display().to_string(),
            "--broker-uid".to_owned(),
            broker_uid.to_string(),
        ]);
        let _server = Server::start(&args);
        let mut rt = Runtime::admit(&setup.kernel_socket(), 1, &["fs.read:/workspace"]);
        let answer = rt.invoke("/workspace/bytes.bin", 4096);
        let DwkpBody::ToolResult(result) = &answer.body else {
            panic!("{answer:?}\n{}", broker.stderr())
        };
        assert_eq!(
            result.fs_read.content.to_bytes(),
            super::broker_support::every_byte()
        );
        broker.wait_for("executed", 1);
        assert!(
            broker
                .stderr()
                .contains(&format!("event=connection peer_uid={}", own_uid())),
            "{}",
            broker.stderr()
        );
        evidence(SUITE, "three-identity-fs-read", "bytes-exact", 1);

        // The hostile runtime, as its own uid: a hello, a forged authorisation
        // with a descriptor of its own, a flood. Nothing is read from it and
        // nothing is said to it.
        let hello = run_as(
            &peer_user,
            &stage,
            &["hello", &socket.display().to_string()],
        );
        assert_eq!(u32::try_from(int(&hello, "euid")).unwrap(), peer_uid);
        assert!(flag(&hello, "connected"));
        assert_eq!(
            int(&hello, "received"),
            0,
            "the broker said something to the runtime"
        );
        assert!(flag(&hello, "eof"));
        let forged = FsReadAuthorisation::new(
            ChannelNonce::new("0".repeat(32)).unwrap(),
            InvocationId::parse("inv_01M24BB8G4E87TVJX9GX248ADD").unwrap(),
            1,
            1,
            ReadLimit::new(64).unwrap(),
        );
        let frame = hex(&brokerp::encode_frame(&forged).unwrap());
        let forgery = run_as(
            &peer_user,
            &stage,
            &["authorise", &socket.display().to_string(), &frame],
        );
        assert_eq!(int(&forgery, "received"), 0);
        let flood = run_as(
            &peer_user,
            &stage,
            &["flood", &socket.display().to_string(), "50"],
        );
        assert_eq!(int(&flood, "received"), 0);
        broker.wait_for("peer_refused", 52);
        assert!(
            broker
                .stderr()
                .lines()
                .filter(|l| l.contains("peer_refused"))
                .all(|l| l.ends_with(&format!("peer_uid={peer_uid}"))),
            "every refusal names the uid the kernel reported"
        );
        assert_eq!(
            broker.count("executed"),
            1,
            "only the authority's authorisation ran"
        );
        assert_eq!(
            broker.count("malformed"),
            0,
            "nothing from the runtime was parsed"
        );
        evidence(SUITE, "runtime-uid-cannot-reach-broker", "closed-unread", 0);

        // The authority still serves after all that.
        let again = rt.invoke("/workspace/a.txt", 64);
        assert!(matches!(again.body, DwkpBody::ToolResult(_)), "{again:?}");
        drop(broker);
    }

    #[test]
    #[ignore = "needs DW_BROKER_AS and DW_PEER_AS; run by `make broker-fs-read-evidence`"]
    fn a_listener_of_another_identity_is_sent_nothing() {
        let ((_, broker_uid), (peer_user, peer_uid)) = identities();
        let stage = staging();
        let setup = separated_setup("m4b-impostor");
        // A real broker, but run as the runtime's identity, at the socket the
        // authority is configured with. It would read from the authority's
        // uid; the authority must never send it anything.
        let socket = broker_socket("impostor");
        let impostor = Broker::start_as(&peer_user, &stage.broker, &socket, own_uid());
        assert_eq!(impostor.uid(), peer_uid);
        let mut args = setup.authority_args(None, &[]);
        args.extend([
            "--broker-socket".to_owned(),
            socket.display().to_string(),
            "--broker-uid".to_owned(),
            broker_uid.to_string(),
        ]);
        let _server = Server::start(&args);
        let mut rt = Runtime::admit(&setup.kernel_socket(), 1, &["fs.read:/workspace"]);
        let answer = rt.invoke("/workspace/a.txt", 64);
        let DwkpBody::ToolFailed(failure) = &answer.body else {
            panic!("{answer:?}")
        };
        assert_eq!(failure.reason, ToolFailureReason::BrokerUnavailable);
        let failed = setup.events("tool.failed");
        assert_eq!(failed[0].text("broker_failure"), Some("peer_refused"));
        assert_eq!(failed[0].int("observed_uid"), Some(u64::from(peer_uid)));
        // The impostor accepted the connection and got nothing: no
        // authorisation, no descriptor, no invocation.
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert_eq!(impostor.count("executed"), 0);
        assert_eq!(impostor.count("refused invocation"), 0);
        evidence(SUITE, "authority-verifies-broker-uid", "sent-nothing", 0);
    }

    #[test]
    #[ignore = "needs DW_BROKER_AS and DW_PEER_AS; run by `make broker-fs-read-evidence`"]
    fn the_broker_identity_reaches_no_authority_state_and_no_dwkp() {
        let ((broker_user, broker_uid), _) = identities();
        let stage = staging();
        let setup = separated_setup("m4b-probe");
        let _server = Server::start(&setup.authority_args(None, &[]));
        let frame = hex(&handshake(1, 1, 1).to_frame().unwrap());
        let report = run_as(
            &broker_user,
            &stage,
            &[
                "probe-authority",
                &setup.state().display().to_string(),
                &setup.kernel_socket().display().to_string(),
                &frame,
            ],
        );
        assert_eq!(u32::try_from(int(&report, "euid")).unwrap(), broker_uid);
        let Some(Value::Array(attempts)) = report.get("attempts") else {
            panic!("{report:?}")
        };
        assert_eq!(attempts.len(), 5);
        for attempt in attempts {
            let Value::Object(attempt) = attempt else {
                panic!("an attempt")
            };
            assert!(
                flag(attempt, "refused"),
                "{attempt:?} SUCCEEDED as the broker uid"
            );
        }
        assert_eq!(
            int(&report, "dwkp_received"),
            0,
            "the authority answered the broker uid"
        );
        assert!(flag(&report, "dwkp_eof"));
        // The refusal is audited by the authority's worker; wait for it.
        let deadline = std::time::Instant::now() + super::transport_support::PROMPT;
        while !setup
            .events("transport.peer_refused")
            .iter()
            .any(|r| r.int("uid") == Some(u64::from(broker_uid)))
        {
            assert!(
                std::time::Instant::now() < deadline,
                "the peer gate did not record the broker's uid"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        evidence(SUITE, "broker-uid-reaches-no-authority-state", "refused", 0);
        evidence(SUITE, "broker-uid-cannot-speak-dwkp", "closed-unread", 0);
    }
}
