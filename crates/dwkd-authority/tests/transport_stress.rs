//! Resource pressure on the real authority process: bounded connections,
//! slow and silent peers, a peer that never reads, connection storms and
//! replay storms (M3e).
//!
//! The properties are **boundedness and continued service**, not speed: a
//! well-behaved peer is still answered while the others misbehave, nothing
//! widens, nothing deadlocks, and the audit chain still verifies. Durations
//! are asserted only as generous upper bounds on availability controls; no
//! timing number here is a security property.

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
    use std::io::Write as _;
    use std::time::{Duration, Instant};

    use dwk_proto::dwkp::DwkpBody;
    use dwkd_authority::server::MAX_CONNECTIONS;
    use dwkd_authority::state::verify_audit_against_store;

    use super::state_support::{acquire_msg, admit_simple, heartbeat_msg, session};
    use super::transport_support::{Client, Fixture, PROMPT, Received, Server, evidence};

    fn served(fx: &Fixture, n: u64) -> Duration {
        let started = Instant::now();
        let mut client = Client::connect(&fx.socket());
        client.handshake();
        let DwkpBody::LeaseGrant(_) = client.call(&acquire_msg(&session(900_000 + n))).body else {
            panic!("a well-behaved peer is served")
        };
        started.elapsed()
    }

    #[test]
    fn connections_are_bounded_and_the_one_over_the_limit_gets_nothing() {
        let fx = Fixture::new("s-limit");
        let _server = Server::start(&fx.args(&[]));
        let mut held: Vec<Client> = (0..MAX_CONNECTIONS)
            .map(|_| {
                let mut client = Client::connect(&fx.socket());
                client.handshake();
                client
            })
            .collect();
        // One more: accepted by the kernel, identified, then refused by the
        // server before a byte is read — no holder, no answer.
        let mut extra = Client::connect(&fx.socket());
        let _ = extra.raw(
            &super::transport_support::handshake(1, 1, 1)
                .to_frame()
                .unwrap(),
        );
        assert!(extra.recv(PROMPT).is_closed());
        let deadline = Instant::now() + PROMPT;
        while fx.events("transport.connection_refused").is_empty() {
            assert!(Instant::now() < deadline, "the refusal is audited");
            std::thread::sleep(Duration::from_millis(20));
        }
        // A slot frees when a connection ends, and a new peer is served.
        drop(held.pop());
        std::thread::sleep(Duration::from_millis(200));
        assert!(served(&fx, 1) < PROMPT);
        drop(held);
        evidence("stress", "connection-limit", "resource-bound", true, true);
    }

    #[test]
    fn a_slow_or_silent_peer_holds_a_slot_for_a_bounded_time() {
        let fx = Fixture::new("s-slow");
        let _server = Server::start(&fx.args(&[]));

        // Silent: no byte at all. Closed at the handshake deadline.
        let mut silent = Client::connect(&fx.socket());
        // One byte of a header, then nothing: closed at the frame deadline.
        let mut partial = Client::connect(&fx.socket());
        partial.raw(&[0]).unwrap();
        // A trickle: a byte a second. The deadline is for the whole frame.
        let trickle_socket = fx.socket();
        let trickle = std::thread::spawn(move || {
            let mut client = Client::connect(&trickle_socket);
            let started = Instant::now();
            for byte in [0u8, 0, 0, 40, 1, b'{', b'"', b'v', b'"', b':'] {
                if client.raw(&[byte]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(900));
            }
            (client.recv(PROMPT), started.elapsed())
        });

        // Meanwhile a well-behaved peer is answered promptly.
        assert!(served(&fx, 2) < Duration::from_secs(3));

        let started = Instant::now();
        assert!(silent.recv(Duration::from_secs(15)).is_closed());
        assert!(partial.recv(Duration::from_secs(15)).is_closed());
        assert!(
            started.elapsed() < Duration::from_secs(12),
            "bounded, not forever"
        );
        let (received, elapsed) = trickle.join().unwrap();
        assert!(matches!(received, Received::Closed), "{received:?}");
        assert!(elapsed < Duration::from_secs(12), "the trickle was cut off");
        // A timeout is an availability control, not a verdict: not audited,
        // and never an authority refusal.
        assert!(fx.events("lease.refused").is_empty());
        evidence("stress", "slowloris-silent", "resource-bound", true, false);
        evidence(
            "stress",
            "slowloris-partial-frame",
            "resource-bound",
            true,
            false,
        );
    }

    #[test]
    fn a_peer_that_never_reads_loses_its_connection_and_blocks_no_one() {
        let fx = Fixture::new("s-backpressure");
        let _server = Server::start(&fx.args(&[]));
        let mut greedy = Client::connect(&fx.socket());
        greedy.handshake();
        let s = session(3);
        let DwkpBody::LeaseGrant(grant) = greedy.call(&acquire_msg(&s)).body else {
            panic!("leased")
        };
        let request = heartbeat_msg(&s, grant.epoch).to_frame().unwrap();
        let mut stream = greedy.stream().try_clone().unwrap();
        let writer = std::thread::spawn(move || {
            let started = Instant::now();
            // Heartbeats, pipelined, never read: the answers fill the socket
            // until the server's write times out and it closes.
            for _ in 0..200_000 {
                if stream.write_all(&request).is_err() {
                    return (true, started.elapsed());
                }
            }
            (false, started.elapsed())
        });
        std::thread::sleep(Duration::from_millis(500));
        assert!(
            served(&fx, 3) < Duration::from_secs(3),
            "others are still served"
        );
        let (cut_off, elapsed) = writer.join().unwrap();
        assert!(cut_off, "the non-reading peer was disconnected");
        assert!(elapsed < Duration::from_secs(60));
        evidence(
            "stress",
            "response-backpressure",
            "resource-bound",
            true,
            false,
        );
    }

    #[test]
    fn storms_of_connections_and_replays_change_nothing() {
        let fx = Fixture::new("s-storm");
        let server = Server::start(&fx.args(&[]));
        // Connect and vanish, many times: clean ends of stream, not violations.
        for _ in 0..300 {
            drop(Client::connect(&fx.socket()));
        }
        // Garbage, many times: each connection closed and audited, and the
        // audit bounded by the rate limit.
        for _ in 0..80 {
            let mut client = Client::connect(&fx.socket());
            client.handshake();
            let _ = client.raw(b"\x00\x00\x00\x02\x01{]");
            let _ = client.recv(PROMPT);
        }
        // A replay storm of one admission: one run, however often it is asked.
        let mut client = Client::connect(&fx.socket());
        client.handshake();
        let s = session(4);
        let DwkpBody::LeaseGrant(grant) = client.call(&acquire_msg(&s)).body else {
            panic!("leased")
        };
        let admit = admit_simple(&s, grant.epoch, "storm-key", &["model.call:*"]);
        let mut runs = std::collections::BTreeSet::new();
        for _ in 0..150 {
            let DwkpBody::RunGrant(run) = client.call(&admit).body else {
                panic!("a grant")
            };
            runs.insert(run.run_id);
        }
        assert_eq!(runs.len(), 1, "one logical admission");
        assert!(served(&fx, 4) < Duration::from_secs(3));

        // Bounded audit: at most the per-window allowance of violation records.
        std::thread::sleep(Duration::from_millis(300));
        let violations = fx.events("transport.protocol_violation").len();
        assert_eq!(
            violations, 32,
            "80 violations inside one window write exactly the per-window allowance"
        );
        assert_eq!(fx.events("run.admitted").len(), 1);
        drop(client);
        drop(server);
        verify_audit_against_store(&fx.state()).expect("the chain is intact after the storm");
        evidence(
            "stress",
            "connect-disconnect-storm",
            "resource-bound",
            true,
            false,
        );
        evidence("stress", "protocol-abuse-flood", "decoder", true, true);
        evidence("stress", "replay-storm", "state-fence", true, true);
    }
}
