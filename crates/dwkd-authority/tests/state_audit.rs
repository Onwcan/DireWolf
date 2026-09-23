//! The hash-chained audit log: format, verification, corruption detection,
//! and the limit of what a local chain can prove.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

use proptest as _;
#[cfg(target_os = "linux")]
use rustix as _;
use toml as _;
use unicode_normalization as _;

mod state_support;

use std::path::Path;

use dwk_proto::json::{self, Value};
use dwkd_authority::state::{
    AuditLogFault, QUARANTINE_MARKER, RecordFault, Reply, StartError, StoreAuditFault,
    verify_audit_against_store, verify_audit_log,
};
use sha2::{Digest as _, Sha256};
use state_support::{Harness, TempDir, admit_simple, audit_lines, int, raw, record, session, text};

/// A store with a few dozen records of real activity.
fn busy() -> Harness {
    let mut h = Harness::new("audit");
    let s = session(1);
    let a = h.connect(1000);
    let e = h.lease(&a, &s);
    for n in 0..5 {
        let Reply::Done(_) = h
            .authority()
            .admit_run(
                &a,
                &admit_simple(&s, e, &format!("k{n}"), &["model.call:*"]),
            )
            .unwrap()
        else {
            panic!("admitted")
        };
    }
    let b = h.connect(2000);
    let _ = h.authority().acquire_lease(&b, &s).unwrap();
    h.authority().release_lease(&a, &s, e).unwrap();
    h
}

/// The documented formula, re-implemented here from ADR-0039 rather than
/// called: if this and the store disagree, one of them is wrong.
fn chain_hash(prev: &[u8; 32], canonical_without_hash: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"direwolf.audit.record.v1");
    hasher.update([0u8]);
    hasher.update(32u64.to_be_bytes());
    hasher.update(prev);
    hasher.update(
        u64::try_from(canonical_without_hash.len())
            .unwrap()
            .to_be_bytes(),
    );
    hasher.update(canonical_without_hash);
    hasher.finalize().into()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

/// Rewrite one record with a new `prev` (or any other edit), recomputing its
/// hash so the record is internally consistent. Returns the new line and hash.
fn forge(line: &str, prev: [u8; 32], edit: impl FnOnce(&mut json::Object)) -> (String, [u8; 32]) {
    let mut object = record(line);
    object.remove("hash");
    object.remove("prev");
    object
        .insert("prev".to_owned(), Value::String(hex(&prev)))
        .unwrap();
    edit(&mut object);
    let canonical = json::to_canonical_bytes(&Value::Object(object.clone()));
    let hash = chain_hash(&prev, &canonical);
    object
        .insert("hash".to_owned(), Value::String(hex(&hash)))
        .unwrap();
    (
        String::from_utf8(json::to_canonical_bytes(&Value::Object(object))).unwrap(),
        hash,
    )
}

fn write_log(dir: &Path, lines: &[String], trailing: &str) -> std::path::PathBuf {
    let path = dir.join("copy.log");
    let mut body = lines.join("\n");
    if !lines.is_empty() {
        body.push('\n');
    }
    body.push_str(trailing);
    std::fs::write(&path, body).unwrap();
    path
}

#[test]
fn every_record_hash_is_the_documented_formula() {
    let h = busy();
    let lines = audit_lines(&h.state());
    assert!(lines.len() > 10);
    let mut prev = [0u8; 32];
    for (index, line) in lines.iter().enumerate() {
        let object = record(line);
        assert_eq!(int(&object, "v"), Some(1));
        assert_eq!(int(&object, "seq"), Some(i64::try_from(index + 1).unwrap()));
        assert_eq!(text(&object, "prev"), Some(hex(&prev).as_str()));
        let claimed = unhex(text(&object, "hash").unwrap());
        let mut without = object.clone();
        without.remove("hash");
        let recomputed = chain_hash(&prev, &json::to_canonical_bytes(&Value::Object(without)));
        assert_eq!(recomputed, claimed, "record {}", index + 1);
        // One spelling: the line is the canonical encoding of itself.
        assert_eq!(
            json::to_canonical_bytes(&Value::Object(object)),
            line.as_bytes()
        );
        prev = claimed;
    }
    assert_eq!(text(&record(&lines[0]), "event"), Some("store.created"));
}

#[test]
fn the_live_log_verifies_alone_and_against_the_store() {
    let h = busy();
    let summary = verify_audit_log(&h.state().join("audit.log")).unwrap();
    let comparison = verify_audit_against_store(&h.state()).unwrap();
    assert_eq!(summary.records, comparison.log_records);
    assert_eq!(comparison.store_head, comparison.log_records);
    assert_eq!(comparison.store_flushed, comparison.log_records);
    assert_eq!(comparison.pending(), 0);
    assert!(!comparison.pending_torn_tail);
    let head: String = raw(&h.state())
        .query_row("SELECT hash FROM audit_head", [], |r| r.get(0))
        .unwrap();
    assert_eq!(summary.head.to_hex(), head);
}

#[test]
fn the_verifier_reports_each_corruption_exactly() {
    let h = busy();
    let lines = audit_lines(&h.state());
    let tmp = TempDir::new("fixtures");
    let run = |lines: &[String], trailing: &str| {
        verify_audit_log(&write_log(tmp.path(), lines, trailing))
    };

    // Byte flip: at several offsets in several records.
    for (target, offset) in [(1usize, 5usize), (3, 40), (6, 12), (lines.len() - 1, 30)] {
        let mut flipped = lines.clone();
        let mut bytes = flipped[target].clone().into_bytes();
        bytes[offset] ^= 0x01;
        flipped[target] = String::from_utf8_lossy(&bytes).into_owned();
        let Err(AuditLogFault::Record { line, .. }) = run(&flipped, "") else {
            panic!("a flipped byte in record {} went undetected", target + 1)
        };
        assert_eq!(line, u64::try_from(target + 1).unwrap());
    }

    // Deletion of an interior record.
    let mut deleted = lines.clone();
    deleted.remove(2);
    assert_eq!(
        run(&deleted, ""),
        Err(AuditLogFault::Record {
            line: 3,
            fault: RecordFault::Sequence {
                expected: 3,
                found: 4
            }
        })
    );

    // Reordering.
    let mut reordered = lines.clone();
    reordered.swap(2, 3);
    assert_eq!(
        run(&reordered, ""),
        Err(AuditLogFault::Record {
            line: 3,
            fault: RecordFault::Sequence {
                expected: 3,
                found: 4
            }
        })
    );

    // Duplication.
    let mut duplicated = lines.clone();
    duplicated.insert(3, lines[2].clone());
    assert_eq!(
        run(&duplicated, ""),
        Err(AuditLogFault::Record {
            line: 4,
            fault: RecordFault::Sequence {
                expected: 4,
                found: 3
            }
        })
    );

    // A record with a wrong prev whose own hash is internally consistent.
    let mut wrong_prev = lines.clone();
    let (forged, _) = forge(&lines[4], [7u8; 32], |_| {});
    wrong_prev[4] = forged;
    assert_eq!(
        run(&wrong_prev, ""),
        Err(AuditLogFault::Record {
            line: 5,
            fault: RecordFault::PrevMismatch
        })
    );

    // A record whose hash field was replaced.
    let mut wrong_hash = lines.clone();
    let mut object = record(&lines[5]);
    object.remove("hash");
    object
        .insert("hash".to_owned(), Value::String("ab".repeat(32)))
        .unwrap();
    wrong_hash[5] = String::from_utf8(json::to_canonical_bytes(&Value::Object(object))).unwrap();
    assert_eq!(
        run(&wrong_hash, ""),
        Err(AuditLogFault::Record {
            line: 6,
            fault: RecordFault::HashMismatch
        })
    );

    // A truncated final record.
    let mut torn = lines.clone();
    let last = torn.pop().unwrap();
    let cut = &last[..last.len() >> 1];
    assert_eq!(
        run(&torn, cut),
        Err(AuditLogFault::TornTail {
            after_records: u64::try_from(torn.len()).unwrap(),
            bytes: u64::try_from(cut.len()).unwrap()
        })
    );

    // Interior truncation: a record cut short with its newline kept.
    let mut interior = lines.clone();
    let shortened = interior[1].len() - 10;
    interior[1].truncate(shortened);
    assert_eq!(
        run(&interior, ""),
        Err(AuditLogFault::Record {
            line: 2,
            fault: RecordFault::NotJson
        })
    );

    // The same record, re-serialised with whitespace.
    let mut padded = lines.clone();
    padded[2] = format!(" {}", padded[2]);
    assert_eq!(
        run(&padded, ""),
        Err(AuditLogFault::Record {
            line: 3,
            fault: RecordFault::NotCanonical
        })
    );
}

#[test]
fn the_verifier_never_writes() {
    let h = busy();
    let log = h.state().join("audit.log");
    let before = std::fs::read(&log).unwrap();
    let db_before = std::fs::read(h.state().join("kernel.db")).unwrap();
    let _ = verify_audit_log(&log).unwrap();
    let _ = verify_audit_against_store(&h.state()).unwrap();
    assert_eq!(std::fs::read(&log).unwrap(), before);
    assert_eq!(
        std::fs::read(h.state().join("kernel.db")).unwrap(),
        db_before
    );
}

#[test]
fn removing_acknowledged_records_is_detected_against_the_store() {
    let mut h = busy();
    h.stop();
    let lines = audit_lines(&h.state());
    let kept = &lines[..lines.len() - 2];
    std::fs::write(
        h.state().join("audit.log"),
        format!("{}\n", kept.join("\n")),
    )
    .unwrap();
    // Alone, a shorter valid chain is still a valid chain.
    assert!(verify_audit_log(&h.state().join("audit.log")).is_ok());
    // Against the store, the records it acknowledged as durable are missing.
    assert!(matches!(
        verify_audit_against_store(&h.state()),
        Err(StoreAuditFault::Truncated { .. })
    ));
    // And the authority will not start on it.
    assert!(matches!(h.try_restart(), Err(StartError::Audit(_))));
    assert!(h.state().join(QUARANTINE_MARKER).exists());
}

#[test]
fn a_record_the_store_never_committed_is_detected() {
    let mut h = busy();
    h.stop();
    let mut lines = audit_lines(&h.state());
    let last = record(lines.last().unwrap());
    let prev = unhex(text(&last, "hash").unwrap());
    let seq = int(&last, "seq").unwrap() + 1;
    // A well-formed, correctly chained record appended by someone else.
    let (forged, _) = forge(lines.last().unwrap(), prev, |object| {
        object.remove("seq");
        object
            .insert("seq".to_owned(), Value::Number(json::Number::Int(seq)))
            .unwrap();
    });
    lines.push(forged);
    std::fs::write(
        h.state().join("audit.log"),
        format!("{}\n", lines.join("\n")),
    )
    .unwrap();
    assert!(
        verify_audit_log(&h.state().join("audit.log")).is_ok(),
        "chain-valid on its own"
    );
    assert!(matches!(
        verify_audit_against_store(&h.state()),
        Err(StoreAuditFault::AheadOfStore { .. })
    ));
    assert!(matches!(h.try_restart(), Err(StartError::Audit(_))));
}

#[test]
fn a_consistently_rewritten_log_is_caught_by_the_store_copy() {
    let mut h = busy();
    h.stop();
    let lines = audit_lines(&h.state());
    // Rewrite record 4's content and re-chain everything after it: the log
    // alone verifies. The kernel's own copy does not agree.
    let mut rewritten = lines[..3].to_vec();
    let mut prev = unhex(text(&record(&lines[2]), "hash").unwrap());
    for (index, line) in lines.iter().enumerate().skip(3) {
        let (forged, hash) = forge(line, prev, |object| {
            if index == 3 {
                object.remove("ts_ms");
                object
                    .insert("ts_ms".to_owned(), Value::Number(json::Number::Int(1)))
                    .unwrap();
            }
        });
        rewritten.push(forged);
        prev = hash;
    }
    std::fs::write(
        h.state().join("audit.log"),
        format!("{}\n", rewritten.join("\n")),
    )
    .unwrap();
    assert!(verify_audit_log(&h.state().join("audit.log")).is_ok());
    assert_eq!(
        verify_audit_against_store(&h.state()),
        Err(StoreAuditFault::Diverged { seq: 4 })
    );
}

#[test]
fn rewriting_the_log_and_every_local_copy_together_is_not_detected() {
    // The stated limitation, demonstrated rather than asserted: an attacker who
    // can rewrite audit.log AND kernel.db's chain, head and flushed mark,
    // consistently, produces a store every local check accepts. Only a head
    // anchored off-host would catch it, and M3d has none.
    let mut h = busy();
    h.stop();
    let lines = audit_lines(&h.state());
    let mut rewritten = Vec::new();
    let mut prev = [0u8; 32];
    for (index, line) in lines.iter().enumerate() {
        let (forged, hash) = forge(line, prev, |object| {
            if index == 3 {
                object.remove("ts_ms");
                object
                    .insert("ts_ms".to_owned(), Value::Number(json::Number::Int(1)))
                    .unwrap();
            }
        });
        rewritten.push((forged, prev, hash));
        prev = hash;
    }
    let conn = raw(&h.state());
    let triggers: Vec<String> = {
        let mut statement = conn
            .prepare(
                "SELECT sql FROM sqlite_schema WHERE type = 'trigger' AND tbl_name IN \
                 ('audit_chain', 'audit_head', 'audit_state')",
            )
            .unwrap();
        statement
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    };
    let names: Vec<String> = {
        let mut statement = conn
            .prepare(
                "SELECT name FROM sqlite_schema WHERE type = 'trigger' AND tbl_name IN \
                 ('audit_chain', 'audit_head', 'audit_state')",
            )
            .unwrap();
        statement
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    };
    for name in &names {
        conn.execute_batch(&format!("DROP TRIGGER {name};"))
            .unwrap();
    }
    for (index, (line, prev, hash)) in rewritten.iter().enumerate() {
        conn.execute(
            "UPDATE audit_chain SET prev = ?2, hash = ?3, record = ?4 WHERE seq = ?1",
            rusqlite::params![
                i64::try_from(index + 1).unwrap(),
                hex(prev),
                hex(hash),
                line.as_bytes()
            ],
        )
        .unwrap();
    }
    conn.execute("UPDATE audit_head SET hash = ?1", [hex(&prev)])
        .unwrap();
    conn.execute("UPDATE audit_state SET flushed_hash = ?1", [hex(&prev)])
        .unwrap();
    for sql in &triggers {
        conn.execute_batch(&format!("{sql};")).unwrap();
    }
    drop(conn);
    let body: Vec<&str> = rewritten.iter().map(|(line, _, _)| line.as_str()).collect();
    std::fs::write(
        h.state().join("audit.log"),
        format!("{}\n", body.join("\n")),
    )
    .unwrap();

    assert!(verify_audit_log(&h.state().join("audit.log")).is_ok());
    assert!(verify_audit_against_store(&h.state()).is_ok());
    assert!(
        h.try_restart().is_ok(),
        "tamper-evident against a partial rewrite, not tamper-proof against a total one"
    );
}

#[test]
fn a_flipped_byte_in_the_live_log_stops_the_next_start() {
    let mut h = busy();
    h.stop();
    let path = h.state().join("audit.log");
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[200] ^= 0x04;
    std::fs::write(&path, &bytes).unwrap();
    assert!(matches!(h.try_restart(), Err(StartError::Audit(_))));
    assert!(matches!(h.try_restart(), Err(StartError::Quarantined(_))));
}

#[test]
fn trailing_bytes_with_nothing_pending_are_not_a_crash_artefact() {
    let mut h = busy();
    h.stop();
    let path = h.state().join("audit.log");
    let mut bytes = std::fs::read(&path).unwrap();
    bytes.extend_from_slice(br#"{"v":1,"seq":"#);
    std::fs::write(&path, &bytes).unwrap();
    assert!(matches!(
        verify_audit_against_store(&h.state()),
        Err(StoreAuditFault::ForeignTail)
    ));
    assert!(matches!(h.try_restart(), Err(StartError::Audit(_))));
}

#[test]
fn the_operator_verifier_reads_both_files_and_fails_loudly() {
    let mut h = busy();
    h.stop();
    let binary = env!("CARGO_BIN_EXE_dwkd-authority");
    let clean = std::process::Command::new(binary)
        .arg("verify-audit")
        .arg(h.state())
        .output()
        .unwrap();
    assert!(
        clean.status.success(),
        "{}",
        String::from_utf8_lossy(&clean.stderr)
    );
    let stdout = String::from_utf8_lossy(&clean.stdout);
    assert!(stdout.contains("chain intact"), "{stdout}");
    assert!(stdout.contains("pending 0"), "{stdout}");

    let path = h.state().join("audit.log");
    let before = std::fs::read(&path).unwrap();
    let mut bytes = before.clone();
    bytes[150] ^= 0x02;
    std::fs::write(&path, &bytes).unwrap();
    let tampered = std::process::Command::new(binary)
        .arg("verify-audit")
        .arg(h.state())
        .output()
        .unwrap();
    assert_eq!(tampered.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&tampered.stderr).contains("FAILED"));
    assert_eq!(
        std::fs::read(&path).unwrap(),
        bytes,
        "the verifier wrote nothing"
    );
}
