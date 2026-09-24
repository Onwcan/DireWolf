//! The authority as a real process: `dwkd-authority serve`, a real socket, a
//! peer the kernel identifies, and the M3d state machine behind it (M3e).
//!
//! **M3e evidence, not M3d evidence.** Every test here spawns the released
//! binary and talks to it from this test process over a Unix-domain socket.
//! Nothing calls `Authority::dispatch` directly; the M3d suites do that, and
//! they stay what they are.
//!
//! Linux only: that is where the server runs. Elsewhere this file proves the
//! server refuses to start and that the platform-independent commands still
//! work.

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

mod state_support;
#[cfg(target_os = "linux")]
mod transport_support;

/// Off Linux the server does not exist: `serve` says so and exits 3 before it
/// creates, opens or starts anything, and the read-only commands still work.
#[cfg(not(target_os = "linux"))]
#[test]
fn off_linux_the_server_refuses_to_start_and_touches_nothing() {
    use std::process::Command;
    let bin = env!("CARGO_BIN_EXE_dwkd-authority");
    let dir = state_support::TempDir::new("unsupported");
    let state = dir.path().join("state");
    let ipc = dir.path().join("ipc");
    let output = state_support::output(
        Command::new(bin)
            .args(["serve", "--state-dir"])
            .arg(&state)
            .arg("--socket")
            .arg(ipc.join("kernel.sock"))
            .args([
                "--allow-uid",
                "1001",
                "--policy-shipped",
                "balanced",
                "--mode",
                "balanced",
            ]),
    )
    .expect("the binary runs");
    assert_eq!(output.status.code(), Some(3), "unsupported is exit 3");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("not"), "{stderr}");
    assert!(!state.exists(), "no state directory was created");
    assert!(!ipc.exists(), "no IPC directory was created");

    for flag in ["--version", "--help"] {
        let output = state_support::output(Command::new(bin).arg(flag)).expect("runs");
        assert!(output.status.success(), "{flag}");
    }
    // verify-audit, on a store an in-process authority created.
    let clock = std::sync::Arc::new(dwkd_authority::state::ManualClock::new(
        state_support::START_MS,
    ));
    let (authority, _) =
        state_support::start(&state, &state_support::balanced(), &clock, None).expect("a store");
    drop(authority);
    let output =
        state_support::output(Command::new(bin).arg("verify-audit").arg(&state)).expect("runs");
    assert!(output.status.success(), "verify-audit works everywhere");
}

#[cfg(target_os = "linux")]
mod linux {
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::time::Duration;

    use dwk_proto::dwkp::{DwkpBody, DwkpMessage};
    use dwk_proto::envelope::MessageType;
    use dwk_proto::wire::scalar::{RefusalReason, RefusedOperation};
    use dwkd_authority::state::{verify_audit_against_store, verify_audit_log};

    use super::state_support::{
        acquire_msg, admit_simple, epoch, heartbeat_msg, query_msg, release_lease_msg,
        release_run_msg, session,
    };
    use super::transport_support::{
        BIN, Client, Fixture, PROMPT, Server, evidence, handshake, own_uid,
    };

    fn refusal(message: &DwkpMessage) -> (RefusedOperation, RefusalReason) {
        match &message.body {
            DwkpBody::AuthorityRefused(refusal) => (refusal.operation, refusal.reason),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    fn granted_run(message: &DwkpMessage) -> dwk_proto::wire::id::RunId {
        match &message.body {
            DwkpBody::RunGrant(grant) => grant.run_id.clone(),
            other => panic!("expected a run grant, got {other:?}"),
        }
    }

    fn lease_epoch(message: &DwkpMessage) -> u64 {
        match &message.body {
            DwkpBody::LeaseGrant(grant) => grant.epoch.get(),
            other => panic!("expected a lease grant, got {other:?}"),
        }
    }

    fn assert_ack(message: &DwkpMessage) {
        assert!(
            matches!(message.body, DwkpBody::Ack(_)),
            "expected an ack, got {:?}",
            message.body
        );
    }

    /// Every answer names its request, carries the authority's own id and the
    /// registry's schema version, and echoes nothing the authority must
    /// generate.
    fn assert_bound(request: &DwkpMessage, response: &DwkpMessage) {
        assert_eq!(response.header.message_type, MessageType::Response);
        assert_eq!(
            response.header.causation_id,
            Some(request.header.id.clone())
        );
        assert_eq!(
            response.header.correlation_id,
            request.header.correlation_id
        );
        assert_ne!(response.header.id, request.header.id);
        assert_eq!(response.header.id.prefix(), "msg");
        assert_eq!(response.header.v.get(), 1);
        assert_eq!(response.header.session_id, None);
        assert_eq!(response.header.run_id, None);
        assert_eq!(response.header.epoch, None);
        assert_eq!(response.header.idempotency_key, None);
        let (_, schema) = response.body.identity();
        let expected = match schema {
            "direwolf.run.grant"
            | "direwolf.authority.effective"
            | "direwolf.authority.refused" => 2,
            _ => 1,
        };
        assert_eq!(
            response.header.schema_version.get(),
            expected,
            "{schema} is sent at its registered version"
        );
    }

    fn call_bound(client: &mut Client, request: &DwkpMessage) -> DwkpMessage {
        let response = client.call(request);
        assert_bound(request, &response);
        response
    }

    #[test]
    fn every_request_crosses_the_real_boundary_and_every_answer_is_bound_to_it() {
        let fx = Fixture::new("t-roundtrip");
        let server = Server::start(&fx.args(&[]));
        assert!(server.ready_line().contains("serving DWKP"));
        let mut client = Client::connect(&fx.socket());

        let hello = handshake(1, 1, 1);
        let accepted = call_bound(&mut client, &hello);
        assert!(matches!(accepted.body, DwkpBody::HandshakeAccepted(_)));

        let s = session(1);
        let lease = call_bound(&mut client, &acquire_msg(&s));
        assert_eq!(lease_epoch(&lease), 1);
        assert_ack(&call_bound(&mut client, &heartbeat_msg(&s, epoch(1))));

        let admit = admit_simple(&s, epoch(1), "roundtrip", &["model.call:*"]);
        let grant = call_bound(&mut client, &admit);
        let run = granted_run(&grant);

        let effective = call_bound(&mut client, &query_msg(&s, &run, epoch(1), None));
        let DwkpBody::EffectiveAuthority(effective) = &effective.body else {
            panic!("effective authority")
        };
        assert_eq!(effective.decision, None, "no proposal, no decision");

        // A proposal is still refused through M3e: the socket does not make
        // canonical facts appear (ADR-0040).
        let proposal = call_bound(
            &mut client,
            &query_msg(&s, &run, epoch(1), Some("fs.read:/etc/passwd")),
        );
        assert_eq!(
            refusal(&proposal),
            (
                RefusedOperation::QueryAuthority,
                RefusalReason::NoCanonicalAction
            )
        );

        assert_ack(&call_bound(
            &mut client,
            &release_run_msg(&s, &run, epoch(1)),
        ));
        assert_ack(&call_bound(&mut client, &release_lease_msg(&s, epoch(1))));

        // The subject the state layer recorded is the kernel-reported uid.
        let acquired = fx.events("lease.acquired");
        assert_eq!(acquired.len(), 1);
        assert_eq!(
            acquired[0].text("subject"),
            Some(format!("uid:{}", own_uid()).as_str())
        );
        for event in [
            "run.admitted",
            "authority.query_refused",
            "run.released",
            "lease.released",
        ] {
            assert_eq!(fx.events(event).len(), 1, "{event}");
        }
        assert!(
            fx.events("authority.decision").is_empty(),
            "nothing was decided"
        );
        drop(server);
        verify_audit_against_store(&fx.state()).expect("the store and the log agree");
    }

    #[test]
    fn an_unlisted_uid_is_refused_before_a_byte_is_read_and_the_kernel_names_it() {
        let fx = Fixture::new("t-peer");
        let me = own_uid();
        // The operator admitted a different uid; the kernel will report ours.
        let _server = Server::start(&fx.args_for(&[me.wrapping_add(1)], &[]));

        // A perfectly valid handshake: refused anyway, unanswered. The server
        // may close before the write lands -- it reads nothing from an
        // unlisted peer -- so a broken pipe here is the same refusal.
        let mut client = Client::connect(&fx.socket());
        let _ = client.raw(&handshake(1, 1, 1).to_frame().unwrap());
        assert!(client.recv(PROMPT).is_closed(), "nothing is sent back");
        // Garbage from the same peer is not parsed deeply enough to answer:
        // no protocol error, which would itself be an oracle.
        let mut client = Client::connect(&fx.socket());
        let _ = client.raw(b"\x00\x00\x00\x05\x01{bad}");
        assert!(client.recv(PROMPT).is_closed());

        let refused = await_events(&fx, "transport.peer_refused", 2);
        for record in &refused {
            assert_eq!(record.int("uid"), Some(u64::from(me)), "the kernel's uid");
            assert_eq!(
                record.int("pid"),
                Some(u64::from(std::process::id())),
                "the kernel's pid for this very process, which it never sent"
            );
        }
        assert!(
            fx.events("transport.protocol_violation").is_empty(),
            "nothing from a refused peer was parsed"
        );
        assert!(fx.events("lease.acquired").is_empty());
        evidence(
            "peer",
            "unlisted-uid-valid-handshake",
            "peer-gate",
            true,
            true,
        );
        evidence(
            "peer",
            "unlisted-uid-malformed-payload",
            "peer-gate",
            true,
            true,
        );
    }

    #[test]
    fn the_authority_uid_is_never_an_implied_peer() {
        let fx = Fixture::new("t-self");
        let opened = fx.events("store.opened").len();
        let refused = Server::try_start(&fx.args_for(&[own_uid()], &[]));
        let Err((status, stderr)) = refused else {
            panic!("the authority's own uid was admitted without acknowledgement")
        };
        assert_eq!(status.and_then(|s| s.code()), Some(1));
        assert!(stderr.contains("authority's own uid"), "{stderr}");
        assert_eq!(
            fx.events("store.opened").len(),
            opened,
            "no incarnation began"
        );
    }

    #[test]
    fn one_uid_on_two_connections_is_one_subject_and_two_holders() {
        let fx = Fixture::new("t-holders");
        let _server = Server::start(&fx.args(&[]));
        let s = session(7);
        let mut a = Client::connect(&fx.socket());
        a.handshake();
        let mut b = Client::connect(&fx.socket());
        b.handshake();

        assert_eq!(lease_epoch(&a.call(&acquire_msg(&s))), 1);
        // B is the same subject and not the same writer.
        assert_eq!(
            refusal(&b.call(&acquire_msg(&s))),
            (RefusedOperation::AcquireLease, RefusalReason::LeaseHeld)
        );
        assert_eq!(
            refusal(&b.call(&heartbeat_msg(&s, epoch(1)))),
            (RefusedOperation::Heartbeat, RefusalReason::StaleEpoch)
        );
        assert_eq!(
            refusal(&b.call(&admit_simple(&s, epoch(1), "b-key", &["model.call:*"]))),
            (RefusedOperation::AdmitRun, RefusalReason::StaleEpoch)
        );
        assert_eq!(
            refusal(&b.call(&release_lease_msg(&s, epoch(1)))),
            (RefusedOperation::ReleaseLease, RefusalReason::StaleEpoch)
        );
        // A is still the writer.
        assert_ack(&a.call(&heartbeat_msg(&s, epoch(1))));

        let acquired = fx.events("lease.acquired");
        let refused = fx.events("lease.refused");
        assert_eq!(acquired.len(), 1);
        assert!(refused.len() >= 3);
        let holder_a = acquired[0].text("holder").unwrap().to_owned();
        let subject = acquired[0].text("subject").unwrap().to_owned();
        for record in &refused {
            assert_eq!(
                record.text("subject"),
                Some(subject.as_str()),
                "one subject"
            );
            assert_ne!(
                record.text("holder"),
                Some(holder_a.as_str()),
                "another holder"
            );
        }
        evidence(
            "fencing",
            "same-uid-second-connection",
            "state-fence",
            true,
            true,
        );
    }

    #[test]
    fn many_connections_from_one_uid_never_share_a_holder() {
        let fx = Fixture::new("t-unique");
        let _server = Server::start(&fx.args(&[]));
        let socket = fx.socket();
        let threads: Vec<_> = (0..24u64)
            .map(|n| {
                let socket = socket.clone();
                std::thread::spawn(move || {
                    let mut client = Client::connect(&socket);
                    client.handshake();
                    assert_eq!(
                        lease_epoch(&client.call(&acquire_msg(&session(100 + n)))),
                        1
                    );
                })
            })
            .collect();
        for thread in threads {
            thread.join().expect("every connection is served");
        }
        let acquired = fx.events("lease.acquired");
        assert_eq!(acquired.len(), 24);
        let holders: std::collections::BTreeSet<_> = acquired
            .iter()
            .map(|r| r.text("holder").unwrap().to_owned())
            .collect();
        let subjects: std::collections::BTreeSet<_> = acquired
            .iter()
            .map(|r| r.text("subject").unwrap().to_owned())
            .collect();
        assert_eq!(holders.len(), 24, "a uid may repeat; a holder may not");
        assert_eq!(subjects.len(), 1);
    }

    #[test]
    fn a_reconnect_inherits_nothing_and_a_disconnect_releases_nothing() {
        let fx = Fixture::new("t-reconnect");
        let _server = Server::start(&fx.args(&["--lease-ttl-ms", "1500"]));
        let s = session(9);
        let mut a = Client::connect(&fx.socket());
        a.handshake();
        assert_eq!(lease_epoch(&a.call(&acquire_msg(&s))), 1);
        let admit = admit_simple(&s, epoch(1), "reconnect-key", &["model.call:*"]);
        let run = granted_run(&a.call(&admit));
        drop(a);

        let mut b = Client::connect(&fx.socket());
        b.handshake();
        assert_eq!(
            refusal(&b.call(&heartbeat_msg(&s, epoch(1)))),
            (RefusedOperation::Heartbeat, RefusalReason::StaleEpoch),
            "the old holder is gone; the new connection is not it"
        );
        assert_eq!(
            refusal(&b.call(&acquire_msg(&s))),
            (RefusedOperation::AcquireLease, RefusalReason::LeaseHeld),
            "disconnecting did not release the lease"
        );
        assert!(fx.events("lease.released").is_empty());
        assert!(fx.events("run.released").is_empty());

        // The lease ends only by the state layer's own rule: expiry.
        std::thread::sleep(Duration::from_millis(1800));
        assert_eq!(lease_epoch(&b.call(&acquire_msg(&s))), 2);
        let replay = admit_simple(&s, epoch(2), "reconnect-key", &["model.call:*"]);
        assert_eq!(
            refusal(&b.call(&replay)),
            (RefusedOperation::AdmitRun, RefusalReason::AdmissionEnded)
        );
        assert_eq!(
            refusal(&b.call(&query_msg(&s, &run, epoch(2), None))),
            (RefusedOperation::QueryAuthority, RefusalReason::UnknownRun)
        );
        assert_eq!(fx.events("run.reaped").len(), 1);
        evidence(
            "fencing",
            "reconnect-inherits-nothing",
            "state-fence",
            true,
            true,
        );
    }

    #[test]
    fn a_connection_left_behind_by_its_own_rotation_is_fenced() {
        let fx = Fixture::new("t-rotation");
        let _server = Server::start(&fx.args(&[]));
        let s = session(11);
        let mut a = Client::connect(&fx.socket());
        a.handshake();
        assert_eq!(lease_epoch(&a.call(&acquire_msg(&s))), 1);
        let admit = admit_simple(&s, epoch(1), "rotation-key", &["model.call:*"]);
        let run = granted_run(&a.call(&admit));
        // The holder rotates its own lease (ADR-0040): epoch 2, the run reaped.
        assert_eq!(lease_epoch(&a.call(&acquire_msg(&s))), 2);

        for (request, operation) in [
            (heartbeat_msg(&s, epoch(1)), RefusedOperation::Heartbeat),
            (
                query_msg(&s, &run, epoch(1), None),
                RefusedOperation::QueryAuthority,
            ),
            (admit.clone(), RefusedOperation::AdmitRun),
            (
                release_run_msg(&s, &run, epoch(1)),
                RefusedOperation::ReleaseRun,
            ),
        ] {
            assert_eq!(
                refusal(&a.call(&request)),
                (operation, RefusalReason::StaleEpoch),
                "{operation:?} at the old epoch"
            );
        }
        // The old key never admits again, and the reaped run stays gone.
        let replay = admit_simple(&s, epoch(2), "rotation-key", &["model.call:*"]);
        assert_eq!(
            refusal(&a.call(&replay)),
            (RefusedOperation::AdmitRun, RefusalReason::AdmissionEnded)
        );
        assert_eq!(
            refusal(&a.call(&query_msg(&s, &run, epoch(2), None))),
            (RefusedOperation::QueryAuthority, RefusalReason::UnknownRun)
        );
        assert_eq!(fx.events("run.admitted").len(), 1, "one logical admission");
        assert_eq!(fx.events("run.reaped").len(), 1);
        evidence(
            "fencing",
            "stale-epoch-after-rotation",
            "state-fence",
            true,
            true,
        );
        evidence("fencing", "old-key-stale-epoch", "state-fence", true, true);
        evidence(
            "fencing",
            "ended-admission-replay",
            "state-fence",
            true,
            true,
        );
    }

    #[test]
    fn a_killed_authority_restarts_over_its_own_dead_socket_and_forgets_every_holder() {
        let fx = Fixture::new("t-restart");
        let mut server = Server::start(&fx.args(&[]));
        let s = session(13);
        let mut a = Client::connect(&fx.socket());
        a.handshake();
        assert_eq!(lease_epoch(&a.call(&acquire_msg(&s))), 1);
        let admit = admit_simple(&s, epoch(1), "restart-key", &["model.call:*"]);
        let run = granted_run(&a.call(&admit));

        server.kill();
        let meta = std::fs::symlink_metadata(fx.socket()).expect("SIGKILL left the socket");
        assert!(meta.file_type().is_socket());
        assert!(
            UnixStream::connect(fx.socket()).is_err(),
            "nothing listens on a dead socket"
        );

        let server = Server::start(&fx.args(&[]));
        assert!(
            server
                .stderr()
                .contains("removed this authority's own dead socket"),
            "{}",
            server.stderr()
        );
        let mut b = Client::connect(&fx.socket());
        b.handshake();
        assert_eq!(
            refusal(&b.call(&heartbeat_msg(&s, epoch(1)))),
            (RefusedOperation::Heartbeat, RefusalReason::StaleEpoch)
        );
        assert_eq!(
            refusal(&b.call(&admit)),
            (RefusedOperation::AdmitRun, RefusalReason::StaleEpoch)
        );
        assert_eq!(lease_epoch(&b.call(&acquire_msg(&s))), 2);
        let replay = admit_simple(&s, epoch(2), "restart-key", &["model.call:*"]);
        assert_eq!(
            refusal(&b.call(&replay)),
            (RefusedOperation::AdmitRun, RefusalReason::AdmissionEnded)
        );
        assert_eq!(
            refusal(&b.call(&query_msg(&s, &run, epoch(2), None))),
            (RefusedOperation::QueryAuthority, RefusalReason::UnknownRun)
        );
        assert_eq!(fx.events("run.admitted").len(), 1);
        let opened = fx.events("store.opened");
        let last = opened.last().expect("store.opened");
        assert_eq!(last.int("leases_invalidated"), Some(1));
        assert_eq!(last.int("runs_reaped"), Some(1));
        drop(b);
        drop(server);
        verify_audit_against_store(&fx.state()).expect("the chain survives the kill");
        evidence("restart", "sigkill-restart", "state-fence", true, true);
    }

    #[test]
    fn a_poisoned_authority_stops_serving() {
        let fx = Fixture::new("t-poison");
        // A file-size limit on the server process, with SIGXFSZ ignored, so the
        // first write past it fails with EFBIG: SQLite reports an I/O error or
        // the audit append fails, and either poisons the store. The harness
        // sets the limit; the authority runs no shell.
        let largest = ["kernel.db", "kernel.db-wal", "audit.log"]
            .iter()
            .filter_map(|name| std::fs::metadata(fx.state().join(name)).ok())
            .map(|meta| meta.len())
            .max()
            .unwrap_or(0);
        let blocks = largest.div_euclid(1024) + 48;
        let script = format!("trap '' XFSZ; ulimit -f {blocks}; exec \"$0\" \"$@\"");
        let mut server = Server::start_wrapped(&["/bin/bash", "-c", &script], &fx.args(&[]));
        let mut client = Client::connect(&fx.socket());
        client.handshake();
        let mut served = 0u64;
        let mut closed = false;
        for n in 0..20_000u64 {
            client.send(&acquire_msg(&session(1_000 + n)));
            match client.recv(PROMPT) {
                super::transport_support::Received::Message(_) => served += 1,
                super::transport_support::Received::Closed => {
                    closed = true;
                    break;
                }
                super::transport_support::Received::TimedOut => panic!("no answer"),
            }
        }
        assert!(
            closed,
            "the connection was closed, unanswered, after {served} answers"
        );
        let status = server
            .wait_exit(PROMPT)
            .expect("the server stops by itself");
        assert_eq!(status.code(), Some(4), "{}", server.stderr());
        assert!(server.stderr().contains("poisoned"), "{}", server.stderr());
        assert!(
            UnixStream::connect(fx.socket()).is_err(),
            "no one answers as the authority any more"
        );
        // The store is not recreated around the failure: the next start
        // re-verifies it, and the chain holds.
        drop(server);
        let restarted = Server::start(&fx.args(&[]));
        drop(restarted);
        verify_audit_log(&fx.state().join("audit.log")).expect("the chain verifies");
        verify_audit_against_store(&fx.state()).expect("and matches the store");
        evidence(
            "poison",
            "poisoned-store-stops-serving",
            "state-fence",
            true,
            true,
        );
    }

    #[test]
    fn the_socket_path_is_never_an_impersonation_path() {
        let fx = Fixture::new("t-socket");
        let ipc = fx.socket().parent().unwrap().to_path_buf();
        let refuse = |why: &str| {
            let Err((status, stderr)) = Server::try_start(&fx.args(&[])) else {
                panic!("started over {why}")
            };
            assert_eq!(status.and_then(|s| s.code()), Some(1), "{why}: {stderr}");
            stderr
        };

        std::fs::create_dir(&ipc).unwrap();
        std::fs::set_permissions(&ipc, std::fs::Permissions::from_mode(0o711)).unwrap();

        // A regular file at the name: refused and left alone.
        std::fs::write(fx.socket(), b"impostor").unwrap();
        assert!(refuse("a regular file").contains("regular file"));
        assert_eq!(std::fs::read(fx.socket()).unwrap(), b"impostor");
        std::fs::remove_file(fx.socket()).unwrap();

        // A symlink at the name, to a live socket elsewhere: refused, not
        // followed, not removed.
        let elsewhere = fx.dir.path().join("elsewhere.sock");
        let decoy = UnixListener::bind(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, fx.socket()).unwrap();
        assert!(refuse("a symlink").contains("symlink"));
        assert!(
            std::fs::symlink_metadata(fx.socket())
                .unwrap()
                .file_type()
                .is_symlink()
        );
        std::fs::remove_file(fx.socket()).unwrap();
        drop(decoy);

        // A live listener that is not the authority: refused.
        let squatter = UnixListener::bind(fx.socket()).unwrap();
        assert!(refuse("a live listener").contains("live socket"));
        drop(squatter);
        std::fs::remove_file(fx.socket()).unwrap();

        // An IPC directory someone else could write.
        std::fs::set_permissions(&ipc, std::fs::Permissions::from_mode(0o773)).unwrap();
        assert!(refuse("a writable directory").contains("write bit"));
        std::fs::set_permissions(&ipc, std::fs::Permissions::from_mode(0o711)).unwrap();

        // The real thing: started, then a second server on the same name is
        // refused by the lock while the first keeps serving.
        let server = Server::start(&fx.args(&[]));
        let meta = std::fs::symlink_metadata(fx.socket()).unwrap();
        assert!(meta.file_type().is_socket());
        assert_eq!(meta.permissions().mode() & 0o777, 0o666);
        let dir = std::fs::symlink_metadata(&ipc).unwrap();
        assert_eq!(dir.uid(), own_uid());
        assert_eq!(
            dir.permissions().mode() & 0o022,
            0,
            "no one else can write it"
        );
        let second = Server::try_start(&fx.args(&[]));
        assert!(second.is_err(), "a second authority on one socket name");
        let mut client = Client::connect(&fx.socket());
        client.handshake();
        drop(server);
        evidence("socket", "same-uid-name-attacks", "filesystem", true, false);
    }

    #[test]
    fn a_bad_command_line_is_a_usage_error_and_starts_nothing() {
        let fx = Fixture::new("t-usage");
        for args in [
            vec!["serve", "--tcp", "127.0.0.1:1"],
            vec![
                "serve",
                "--state-dir",
                "/x",
                "--socket",
                "/y/s",
                "--mode",
                "safe",
            ],
            vec!["frobnicate"],
        ] {
            let output = super::state_support::output(
                std::process::Command::new(BIN).args(&args).env_clear(),
            )
            .unwrap();
            assert_eq!(output.status.code(), Some(2), "{args:?}");
        }
        assert!(!fx.socket().parent().unwrap().exists());
    }

    /// Poll the audit log until `count` records of `event` exist. The server
    /// writes a transport record from its worker after it has closed the
    /// connection, so the client can see the close first.
    pub(super) fn await_events(
        fx: &Fixture,
        event: &str,
        count: usize,
    ) -> Vec<dwkd_authority::state::AuditRecord> {
        let deadline = std::time::Instant::now() + PROMPT;
        loop {
            let records = fx.events(event);
            if records.len() >= count || std::time::Instant::now() > deadline {
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

    #[test]
    fn help_describes_the_server_that_exists() {
        let output =
            super::state_support::output(std::process::Command::new(BIN).arg("--help")).unwrap();
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(output.status.success());
        assert!(text.contains("serve"));
        assert!(!text.contains("not implemented"));
    }
}
