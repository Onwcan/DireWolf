//! The approver endpoint as a real process (F-18 Phase 3.4, ADR-0067,
//! Proposed): `dwkd-authority serve --approver-socket --approver-uid`, a
//! second socket, peers the kernel identifies.
//!
//! What is proved here is an identity boundary and nothing more, because
//! nothing more exists: the endpoint holds no approval operation before M6's
//! registry, so a peer it authenticates is recorded and closed, a peer it
//! does not is refused and recorded, and neither has a byte read or
//! answered.
//!
//! **Two halves.** The same-uid tests run everywhere `cargo test` runs on
//! Linux: this process is the runtime the operator lets speak DWKP, and the
//! approver endpoint refuses it by the uid the kernel reports; a start that
//! would make a runtime, the broker or the authority an approver, or put the
//! endpoint on the DWKP socket, starts nothing. The three-identity test is
//! `#[ignore]`d and run by name by `make authority-transport-evidence` with
//! `DW_PEER_AS` (the runtime) and `DW_APPROVER_AS` (the approver), each
//! proven a distinct, non-root uid by number: the harness switches users
//! through `sudo -n -u`, never the authority. Without both it is NOT
//! EXERCISED, and the task fails rather than passing.
//!
//! The eval `peer-credential-check` runs every ignored test in
//! `transport_foreign.rs` with one second identity; this file is apart from
//! it so that a test needing a third identity never runs there.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

use dwk_proto as _;
#[cfg(target_os = "linux")]
use nix as _;
use proptest as _;
use rusqlite as _;
#[cfg(target_os = "linux")]
use rustix as _;
use sha2 as _;
use toml as _;
use unicode_normalization as _;
// M4e's secret crates (ADR-0046), reached only through the library.
use age as _;
use getrandom as _;
use hmac as _;
#[cfg(any(target_os = "macos", target_os = "windows"))]
use keyring as _;
#[cfg(target_os = "linux")]
use linux_keyutils as _;
use zeroize as _;

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
    use dwkd_authority::state::AuditRecord;

    use super::state_support::{TempDir, acquire_msg, session};
    use super::transport_support::{
        BIN, Client, Fixture, PROMPT, Server, evidence, handshake, own_uid,
    };

    /// The approver socket: a directory of its own beside the DWKP one.
    fn approver_socket(fx: &Fixture) -> PathBuf {
        fx.dir.path().join("approve").join("approver.sock")
    }

    fn text(path: &Path) -> String {
        path.display().to_string()
    }

    /// Poll the audit log until `count` records of `event` exist: the worker
    /// writes a transport record after the connection is closed.
    fn await_events(fx: &Fixture, event: &str, count: usize) -> Vec<AuditRecord> {
        let deadline = Instant::now() + PROMPT;
        loop {
            let records = fx.events(event);
            if records.len() >= count || Instant::now() > deadline {
                assert!(
                    records.len() >= count,
                    "{count} {event} records, found {}",
                    records.len()
                );
                return records;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// The server's stderr once it holds `needle`.
    fn stderr_with(server: &Server, needle: &str) -> String {
        let deadline = Instant::now() + PROMPT;
        loop {
            let text = server.stderr();
            if text.contains(needle) || Instant::now() > deadline {
                return text;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// `serve` with `args`, which must be refused as a usage error: exit 2,
    /// and its stderr.
    fn usage_error(args: &[String]) -> String {
        let output =
            super::state_support::output(Command::new(BIN).args(args).env_clear()).unwrap();
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        String::from_utf8_lossy(&output.stderr).into_owned()
    }

    #[test]
    fn the_runtime_uid_is_refused_at_the_approver_endpoint_and_keeps_its_own_door() {
        let fx = Fixture::new("a-runtime");
        let me = own_uid();
        let approver = approver_socket(&fx);
        let someone_else = me.wrapping_add(1).to_string();
        // This process is the runtime: the operator lets it speak DWKP, and
        // names another uid as the approver.
        let server = Server::start(&fx.args(&[
            "--approver-socket",
            &text(&approver),
            "--approver-uid",
            &someone_else,
        ]));
        let stderr = stderr_with(&server, "approver endpoint at");
        assert!(
            stderr.contains("holds no approval operation before M6"),
            "{stderr}"
        );
        let place = std::fs::metadata(approver.parent().unwrap()).unwrap();
        assert_eq!(place.uid(), me, "the authority's own directory");
        assert_eq!(
            place.permissions().mode() & 0o022,
            0,
            "no one else writes it"
        );

        // A valid DWKP handshake, then garbage: refused unread, unanswered.
        // The server may close before the write lands -- it reads nothing --
        // so a broken pipe is the same refusal.
        let mut client = Client::connect(&approver);
        let _ = client.raw(&handshake(1, 1, 1).to_frame().unwrap());
        assert!(client.recv(PROMPT).is_closed(), "nothing is sent back");
        let mut client = Client::connect(&approver);
        let _ = client.raw(b"\x00\x00\x00\x05\x01{bad}");
        assert!(client.recv(PROMPT).is_closed(), "nothing is sent back");

        let refused = await_events(&fx, "approver.peer_refused", 2);
        for record in &refused {
            assert_eq!(record.int("uid"), Some(u64::from(me)), "the kernel's uid");
            assert_eq!(
                record.int("pid"),
                Some(u64::from(std::process::id())),
                "the kernel's pid for this very process, which it never sent"
            );
            assert_eq!(record.text("reason"), Some("uid_not_an_approver"));
        }
        assert!(
            fx.events("approver.peer_authenticated").is_empty(),
            "a runtime is never an approver"
        );
        assert!(
            fx.events("transport.protocol_violation").is_empty(),
            "nothing it sent was parsed"
        );
        evidence(
            "approver",
            "runtime-uid-refused",
            "approver-gate",
            true,
            true,
        );

        // Its own door is unchanged: it is served there as before.
        let mut runtime = Client::connect(&fx.socket());
        runtime.handshake();
        let s = session(1);
        assert!(
            matches!(runtime.call(&acquire_msg(&s)).body, DwkpBody::LeaseGrant(_)),
            "the runtime's endpoint serves the runtime"
        );
        assert_eq!(
            fx.events("approver.peer_refused").len(),
            2,
            "the DWKP endpoint records nothing as the approver's"
        );
        evidence(
            "approver",
            "runtime-door-unchanged",
            "approver-gate",
            true,
            true,
        );
        drop(server);
    }

    #[test]
    fn the_authority_is_never_an_approver_and_naming_it_starts_nothing() {
        let fx = Fixture::new("a-self");
        let me = own_uid();
        let approver = approver_socket(&fx);
        let opened = fx.events("store.opened").len();
        // The runtime is another uid; the approver named is the authority's
        // own. The parser cannot know that uid; the start does, and refuses
        // before an incarnation begins or anything is bound.
        let refused = Server::try_start(&fx.args_for(
            &[me.wrapping_add(1)],
            &[
                "--approver-socket",
                &text(&approver),
                "--approver-uid",
                &me.to_string(),
            ],
        ));
        let Err((status, stderr)) = refused else {
            panic!("the authority's own uid was made an approver")
        };
        assert_eq!(status.and_then(|s| s.code()), Some(1), "{stderr}");
        assert!(
            stderr.contains(&format!("--approver-uid {me} is the authority's own uid")),
            "{stderr}"
        );
        assert!(stderr.contains("no override"), "{stderr}");
        assert_eq!(
            fx.events("store.opened").len(),
            opened,
            "no incarnation began"
        );
        assert!(!approver.exists(), "no approver socket was bound");
        evidence(
            "approver",
            "authority-uid-never-an-approver",
            "configuration",
            true,
            false,
        );
    }

    #[test]
    fn no_runtime_broker_or_dwkp_socket_is_ever_an_approver() {
        let fx = Fixture::new("a-overlap");
        let me = own_uid().to_string();
        let other = own_uid().wrapping_add(1).to_string();
        let approver = text(&approver_socket(&fx));
        let dwkp = text(&fx.socket());

        // The runtime's uid -- even with the authority's own-uid
        // acknowledgement on the line.
        let stderr =
            usage_error(&fx.args(&["--approver-socket", &approver, "--approver-uid", &me]));
        assert!(
            stderr.contains(&format!("--approver-uid {me} is also an --allow-uid")),
            "{stderr}"
        );
        // The broker's uid, with or without the shared-broker
        // acknowledgement.
        for extra in [&[][..], &["--allow-shared-broker-uid"][..]] {
            let mut args: Vec<&str> = vec![
                "--broker-socket",
                "/run/dw-none/broker.sock",
                "--broker-uid",
                &other,
                "--approver-socket",
                &approver,
                "--approver-uid",
                &other,
            ];
            args.extend_from_slice(extra);
            let stderr = usage_error(&fx.args(&args));
            assert!(
                stderr.contains(&format!("--approver-uid {other} is the --broker-uid")),
                "{stderr}"
            );
        }
        // The DWKP socket itself, as written.
        let stderr = usage_error(&fx.args(&["--approver-socket", &dwkp, "--approver-uid", &other]));
        assert!(stderr.contains("must not be the DWKP socket"), "{stderr}");
        // Half a configuration.
        let stderr = usage_error(&fx.args(&["--approver-uid", &other]));
        assert!(stderr.contains("needs --approver-socket"), "{stderr}");
        assert!(
            !fx.socket().parent().unwrap().exists(),
            "a usage error binds nothing"
        );

        // The DWKP socket by another spelling: the start resolves it and
        // refuses before an incarnation begins.
        let opened = fx.events("store.opened").len();
        let alias = fx
            .dir
            .path()
            .join("ipc")
            .join("..")
            .join("ipc")
            .join("kernel.sock");
        let refused = Server::try_start(&fx.args(&[
            "--approver-socket",
            &text(&alias),
            "--approver-uid",
            &other,
        ]));
        let Err((status, stderr)) = refused else {
            panic!("the approver endpoint was put on the DWKP socket")
        };
        assert_eq!(status.and_then(|s| s.code()), Some(1), "{stderr}");
        assert!(stderr.contains("names the DWKP socket"), "{stderr}");
        assert_eq!(fx.events("store.opened").len(), opened);
        evidence(
            "approver",
            "runtime-broker-or-dwkp-socket-never-an-approver",
            "configuration",
            true,
            false,
        );
    }

    #[test]
    fn the_approver_socket_is_protected_as_the_dwkp_socket_is() {
        let fx = Fixture::new("a-socket");
        let other = own_uid().wrapping_add(1).to_string();
        let approver = approver_socket(&fx);
        let dir = approver.parent().unwrap().to_path_buf();
        let args = fx.args(&[
            "--approver-socket",
            &text(&approver),
            "--approver-uid",
            &other,
        ]);

        // A symlink at the approver socket's name is never followed, and
        // never removed.
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o711)).unwrap();
        let target = fx.dir.path().join("elsewhere.sock");
        std::os::unix::fs::symlink(&target, &approver).unwrap();
        let Err((_, stderr)) = Server::try_start(&args) else {
            panic!("a symlink at the approver socket's name was served")
        };
        assert!(stderr.contains("a symlink"), "{stderr}");
        assert!(std::fs::symlink_metadata(&approver).unwrap().is_symlink());
        std::fs::remove_file(&approver).unwrap();

        // A directory others can write is refused.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o733)).unwrap();
        let Err((_, stderr)) = Server::try_start(&args) else {
            panic!("a writable approver directory was served")
        };
        assert!(stderr.contains("write bit"), "{stderr}");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o711)).unwrap();

        // A killed authority leaves its approver socket behind; the next
        // start recognises its own dead socket, replaces it and refuses the
        // same runtime again.
        let mut server = Server::start(&args);
        server.kill();
        assert!(approver.exists(), "SIGKILL leaves the socket file");
        let server = Server::start(&args);
        let stderr = stderr_with(&server, "dead approver socket");
        assert!(
            stderr.contains("removed this authority's own dead approver socket"),
            "{stderr}"
        );
        let mut client = Client::connect(&approver);
        assert!(client.recv(PROMPT).is_closed());
        await_events(&fx, "approver.peer_refused", 1);

        // A second server cannot take the name while this one holds it.
        let second = Fixture::new("a-socket-2");
        let taken = Server::try_start(&second.args(&[
            "--approver-socket",
            &text(&approver),
            "--approver-uid",
            &other,
        ]));
        let Err((_, stderr)) = taken else {
            panic!("two servers held one approver socket")
        };
        assert!(stderr.contains("another authority"), "{stderr}");
        drop(server);
        evidence(
            "approver",
            "approver-socket-name-protected",
            "filesystem",
            true,
            false,
        );
    }

    /// An `AdmitRun` with `envelope_extra` in its envelope and
    /// `payload_extra` in its payload.
    fn admit_json(
        s: &dwk_proto::wire::id::SessionId,
        epoch: u64,
        envelope_extra: &str,
        payload_extra: &str,
    ) -> String {
        format!(
            r#"{{"v":1,"id":"{id}","type":"request","schema":"direwolf.run.admit","schema_version":1,"ts":"2026-09-22T10:00:00.000Z","session_id":"{session}","epoch":{epoch},"idempotency_key":"claim-key"{envelope_extra},"payload":{{"agent_profile":"researcher","skills":[],"requested_capabilities":["model.call:*"]{payload_extra}}}}}"#,
            id = super::state_support::id("msg", 80_001),
            session = s.as_str(),
        )
    }

    #[test]
    fn a_runtime_cannot_claim_an_approval_an_approver_or_a_human_on_the_wire() {
        // ADR-0067 §5: nothing a runtime sends establishes human
        // authorization. Each claim -- an attended origin, an approval, an
        // approver's identity, a remembered or external agent's approval, a
        // terminal -- is a field no DWKP message has, so the production
        // decoder refuses the message before it reaches the authority; and
        // the approver endpoint's existence changes nothing on this wire.
        let fx = Fixture::new("a-claims");
        let other = own_uid().wrapping_add(1).to_string();
        let approver = approver_socket(&fx);
        let _server = Server::start(&fx.args(&[
            "--approver-socket",
            &text(&approver),
            "--approver-uid",
            &other,
        ]));
        let s = session(2);
        let mut owner = Client::connect(&fx.socket());
        owner.handshake();
        let DwkpBody::LeaseGrant(grant) = owner.call(&acquire_msg(&s)).body else {
            panic!("a lease")
        };
        let e = grant.epoch.get();
        let claims = [
            ("origin", "\"interactive\""),
            ("attended", "true"),
            ("approved", "true"),
            ("approval", "{\"granted\":true}"),
            ("approval_id", "\"apr_0\""),
            ("approval_token", "\"t\""),
            ("approver", "\"uid:0\""),
            ("approver_uid", "0"),
            ("granted_by", "\"uid:0\""),
            ("request_nonce", "\"n\""),
            ("binding_hash", "\"00\""),
            ("remembered_approval", "\"always\""),
            ("auto_approve", "true"),
            ("yolo", "true"),
            ("dangerously_skip_permissions", "true"),
            ("tty", "\"/dev/pts/0\""),
        ];
        for (field, value) in claims {
            for placement in ["envelope", "payload"] {
                let member = format!(r#","{field}":{value}"#);
                let body = if placement == "envelope" {
                    admit_json(&s, e, &member, "")
                } else {
                    admit_json(&s, e, "", &member)
                };
                let mut client = Client::connect(&fx.socket());
                client.handshake();
                client.body(body.as_bytes()).unwrap();
                let message = client.recv(PROMPT).message();
                let DwkpBody::ProtocolError(error) = message.body else {
                    panic!(
                        "{field} in the {placement} was not refused: {:?}",
                        message.body
                    )
                };
                assert_eq!(
                    error.code,
                    dwk_proto::error::ErrorCode::SchemaViolation,
                    "{field} in the {placement}"
                );
                assert_eq!(
                    error.violation,
                    Some(dwk_proto::error::Violation::UnknownField),
                    "{field} in the {placement}"
                );
                assert!(client.recv(PROMPT).is_closed(), "and the connection closed");
            }
        }
        assert!(
            fx.events("run.admitted").is_empty(),
            "no claim reached the authority"
        );
        evidence(
            "approver",
            "approval-claims-undecodable",
            "decoder",
            true,
            true,
        );

        // The honest request admits -- unattended, as every runtime
        // admission is (TX062) -- and no approver record exists.
        let admitted = owner.call(&super::state_support::admit_simple(
            &s,
            grant.epoch,
            "claim-key",
            &["model.call:*"],
        ));
        assert!(
            matches!(admitted.body, DwkpBody::RunGrant(_)),
            "{admitted:?}"
        );
        let runs = fx.events("run.admitted");
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].text("origin"), Some("api"), "never attended");
        assert!(fx.events("approver.peer_authenticated").is_empty());
        evidence(
            "approver",
            "runtime-admission-stays-unattended",
            "state",
            true,
            true,
        );
    }

    #[test]
    fn help_names_the_approver_endpoint_and_what_it_does_not_do() {
        let output =
            super::state_support::output(std::process::Command::new(BIN).arg("--help")).unwrap();
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(output.status.success());
        assert!(text.contains("--approver-socket"), "{text}");
        assert!(text.contains("--approver-uid"), "{text}");
        assert!(text.contains("no approval operation before M6"), "{text}");
        assert!(
            text.contains("never a DWKP peer's, the broker's or the authority's"),
            "{text}"
        );
    }

    // ---------------------------------------------------------------------
    // Three operating-system identities (hosted).
    // ---------------------------------------------------------------------

    /// A user named by `variable`, proven by numbers: the uid a process
    /// started as that user reports must be neither this process's, nor
    /// root's, nor any of `others`. A name is not evidence; distinct uids are.
    fn identity(variable: &str, others: &[u32]) -> (String, u32) {
        let user = std::env::var(variable).unwrap_or_default();
        assert!(
            !user.is_empty(),
            "NOT EXERCISED: set {variable} to a user that `sudo -n -u` can switch to; a \
             cross-uid property is never passed without one"
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
        let reported = String::from_utf8_lossy(&probe.stdout).trim().to_owned();
        let uid: u32 = reported
            .parse()
            .unwrap_or_else(|_| panic!("`id -u` as {user} printed {reported:?}"));
        eprintln!(
            "identity: the authority and this harness run as uid {}; {variable}={user} runs as \
             uid {uid}",
            own_uid()
        );
        assert_ne!(
            uid,
            own_uid(),
            "{variable}={user} is this process's own uid"
        );
        assert_ne!(
            uid, 0,
            "{variable}={user} is root, outside the threat model"
        );
        assert!(
            !others.contains(&uid),
            "{variable}={user} is uid {uid}, an identity already in use here: three \
             identities are needed, not two"
        );
        (user, uid)
    }

    /// Open `dir` for traversal only (`0711`), every ancestor traversable.
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

    fn python() -> &'static str {
        if Path::new("/usr/bin/python3").exists() {
            "/usr/bin/python3"
        } else {
            "python3"
        }
    }

    /// The foreign client script, copied where the other users can read it.
    fn staged_client(dir: &TempDir) -> PathBuf {
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/authority/foreign_peer_client.py");
        let staged = dir.path().join("foreign_peer_client.py");
        std::fs::copy(&source, &staged).expect("the client script");
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o644)).unwrap();
        staged
    }

    /// Run the client as `user`; its one JSON line.
    fn run_as(user: &str, script: &Path, args: &[&str]) -> json::Object {
        let output = super::state_support::output(
            Command::new("sudo")
                .args(["-n", "-u", user, python()])
                .arg(script)
                .args(args)
                .current_dir(script.parent().unwrap()),
        )
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

    /// One answer frame the client read, decoded by the real decoder.
    fn reply(report: &json::Object, index: usize) -> DwkpBody {
        let Some(Value::Array(replies)) = report.get("replies") else {
            panic!("replies: {report:?}")
        };
        let Some(Value::String(hex)) = replies.get(index) else {
            panic!("reply {index}: {report:?}")
        };
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        dwk_proto::dwkp::decode_body(&bytes[5..]).unwrap().body
    }

    /// The client was refused at `report`'s socket: it connected, read
    /// nothing, and saw the server close.
    fn closed_unanswered(report: &json::Object, euid: u32) {
        assert_eq!(
            u32::try_from(int(report, "euid")).unwrap(),
            euid,
            "the client runs as the identity it was meant to: {report:?}"
        );
        assert!(
            flag(report, "connected"),
            "the socket was reachable: {report:?}"
        );
        assert_eq!(int(report, "received"), 0, "not one byte came back");
        assert!(flag(report, "eof"), "the server closed it");
    }

    /// The approver socket cannot be removed, replaced or shadowed by `user`.
    fn cannot_impersonate(user: &str, uid: u32, script: &Path, socket: &Path) {
        let report = run_as(user, script, &["impersonate", &text(socket)]);
        assert_eq!(u32::try_from(int(&report, "euid")).unwrap(), uid);
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
            assert!(flag(attempt, "refused"), "{name} SUCCEEDED as uid {uid}");
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
    }

    #[test]
    #[ignore = "needs three OS identities (DW_PEER_AS, DW_APPROVER_AS); run by `make authority-transport-evidence`"]
    fn an_approver_is_its_own_identity_and_a_runtime_is_never_one() {
        let (runtime, runtime_uid) = identity("DW_PEER_AS", &[]);
        let (approver, approver_uid) = identity("DW_APPROVER_AS", &[runtime_uid]);
        let fx = Fixture::new("a-three");
        traversable_only(fx.dir.path());
        let staging = TempDir::new("a-client");
        traversable_only(staging.path());
        let script = staged_client(&staging);
        let approver_path = approver_socket(&fx);
        // Production's shape: three uids. The runtime may speak DWKP and is
        // not an approver; the approver may reach the approver endpoint and
        // is not a runtime; the authority is neither.
        let mut server = Server::start(&fx.args_for(
            &[runtime_uid],
            &[
                "--approver-socket",
                &text(&approver_path),
                "--approver-uid",
                &approver_uid.to_string(),
            ],
        ));
        let dwkp = text(&fx.socket());
        let approve = text(&approver_path);
        let frame = hex(&handshake(1, 1, 1).to_frame().unwrap());

        // 1. The runtime at the approver endpoint: refused by the uid the
        //    kernel reported, before a byte is read.
        let hello = run_as(&runtime, &script, &["hello", &approve, &frame]);
        closed_unanswered(&hello, runtime_uid);
        let refused = await_events(&fx, "approver.peer_refused", 1);
        assert_eq!(refused[0].int("uid"), Some(u64::from(runtime_uid)));
        assert_eq!(refused[0].int("pid"), Some(int(&hello, "pid")));
        assert_eq!(refused[0].text("reason"), Some("uid_not_an_approver"));
        evidence(
            "approver",
            "cross-uid-runtime-refused",
            "approver-gate",
            true,
            true,
        );

        // 2. The approver at the approver endpoint: authenticated by the
        //    kernel's report, recorded, closed. Nothing it sent was read and
        //    nothing was answered: there is no approval operation yet.
        let hello = run_as(&approver, &script, &["hello", &approve, &frame]);
        closed_unanswered(&hello, approver_uid);
        let authenticated = await_events(&fx, "approver.peer_authenticated", 1);
        assert_eq!(authenticated.len(), 1);
        assert_eq!(authenticated[0].int("uid"), Some(u64::from(approver_uid)));
        assert_eq!(authenticated[0].int("pid"), Some(int(&hello, "pid")));
        assert_eq!(authenticated[0].text("outcome"), Some("closed"));
        assert_eq!(
            authenticated[0].text("reason"),
            Some("no_approval_operation")
        );
        evidence(
            "approver",
            "cross-uid-approver-authenticated-holds-nothing",
            "approver-gate",
            true,
            true,
        );

        // 3. The approver at the runtime's door: not a runtime.
        let hello = run_as(&approver, &script, &["hello", &dwkp, &frame]);
        closed_unanswered(&hello, approver_uid);
        let refused = await_events(&fx, "transport.peer_refused", 1);
        assert_eq!(refused[0].int("uid"), Some(u64::from(approver_uid)));
        evidence(
            "approver",
            "cross-uid-approver-not-a-runtime",
            "peer-gate",
            true,
            true,
        );

        // 4. The runtime at its own door: answered, as before.
        let talk = run_as(&runtime, &script, &["converse", &dwkp, &frame]);
        assert!(
            matches!(reply(&talk, 0), DwkpBody::HandshakeAccepted(_)),
            "{talk:?}"
        );
        evidence(
            "approver",
            "cross-uid-runtime-served-at-its-own-door",
            "peer-gate",
            true,
            false,
        );

        // 5. The authority's own uid at the approver endpoint: refused.
        let mut client = Client::connect(&approver_path);
        let _ = client.raw(&handshake(1, 1, 1).to_frame().unwrap());
        assert!(client.recv(PROMPT).is_closed());
        let refused = await_events(&fx, "approver.peer_refused", 2);
        assert_eq!(refused[1].int("uid"), Some(u64::from(own_uid())));
        evidence(
            "approver",
            "cross-uid-authority-refused",
            "approver-gate",
            true,
            true,
        );

        // 6. Neither the runtime nor the approver can remove, replace or
        //    shadow the approver socket.
        let before = std::fs::symlink_metadata(&approver_path).unwrap();
        cannot_impersonate(&runtime, runtime_uid, &script, &approver_path);
        cannot_impersonate(&approver, approver_uid, &script, &approver_path);
        let after = std::fs::symlink_metadata(&approver_path).unwrap();
        assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
        evidence(
            "approver",
            "cross-uid-approver-socket-not-replaceable",
            "filesystem",
            true,
            false,
        );

        // Nothing anywhere was granted, admitted or approved, and exactly one
        // approver was ever authenticated.
        assert!(fx.events("lease.acquired").is_empty());
        assert!(fx.events("run.admitted").is_empty());
        assert!(fx.events("transport.protocol_violation").is_empty());
        assert_eq!(fx.events("approver.peer_authenticated").len(), 1);
        server.kill();
        let verified =
            super::state_support::output(Command::new(BIN).arg("verify-audit").arg(fx.state()))
                .expect("verify-audit runs");
        assert!(
            verified.status.success(),
            "{}",
            String::from_utf8_lossy(&verified.stderr)
        );
        assert!(String::from_utf8_lossy(&verified.stdout).contains("chain intact"));
    }
}
