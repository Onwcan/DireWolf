//! `kernel.db` itself: creation, settings, schema versioning, corruption
//! quarantine, and the refusals that keep a store from being recreated.
//!
//! Every test here uses real files. A store that fails to open is inspected
//! afterwards, byte for byte where it matters, to show that the refusal left
//! it as it was found.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

// Linked by the library, unused by this binary. Acknowledged rather than
// silenced, so `unused_crate_dependencies` keeps meaning something.
use proptest as _;
use sha2 as _;
use toml as _;

mod state_support;

use std::sync::Arc;

use dwkd_authority::state::{
    AuditEvent, AuthorityError, KERNEL_SCHEMA_VERSION, ManualClock, PoisonReason,
    QUARANTINE_MARKER, Reply, StartError,
};
use state_support::{
    Harness, START_MS, TempDir, audit_events, balanced, count, raw, session, start,
};

fn sha256_of(path: &std::path::Path) -> Vec<u8> {
    std::fs::read(path).expect("readable")
}

#[test]
fn a_fresh_directory_becomes_a_current_store_and_a_second_start_reuses_it() {
    let mut h = Harness::new("fresh");
    assert!(h.report.created);
    assert_eq!(h.report.schema_version, KERNEL_SCHEMA_VERSION);
    assert_eq!(h.report.incarnation, 1);
    let conn = raw(&h.state());
    let version: i64 = conn
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .unwrap();
    let app: i64 = conn
        .pragma_query_value(None, "application_id", |r| r.get(0))
        .unwrap();
    assert_eq!(version, KERNEL_SCHEMA_VERSION);
    assert_eq!(
        app, 0x4457_4B44,
        "the file is marked as a DireWolf kernel store"
    );
    drop(conn);

    let report = h.restart().clone();
    assert!(!report.created, "an existing store is opened, not created");
    assert_eq!(report.incarnation, 2, "every start is a new incarnation");
    assert_eq!(
        audit_events(&h.state())
            .iter()
            .filter(|e| *e == AuditEvent::StoreCreated.as_str())
            .count(),
        1,
        "the store was created exactly once"
    );
}

#[test]
fn every_storage_setting_reads_back_as_configured() {
    let mut h = Harness::new("pragmas");
    let settings = h.authority().storage_settings().unwrap();
    assert!(settings.journal_mode.eq_ignore_ascii_case("wal"));
    assert_eq!(settings.synchronous, 2, "FULL");
    assert_eq!(settings.fullfsync, 1);
    assert_eq!(settings.foreign_keys, 1);
    assert_eq!(settings.busy_timeout_ms, 5_000);
    assert_eq!(settings.trusted_schema, 0);
    assert_eq!(settings.mmap_size, 0);
    assert!(settings.defensive);
    assert!(settings.no_checkpoint_on_close);
    assert_eq!(settings.user_version, KERNEL_SCHEMA_VERSION);
    // Deliberately left at SQLite's defaults, and stated so.
    assert_eq!(settings.wal_autocheckpoint, 1_000);
    assert_eq!(settings.auto_vacuum, 0);

    // A second handle gets the same settings: they are applied per connection.
    let other = h.authority().handle().unwrap();
    assert_eq!(other.storage_settings().unwrap(), settings);
}

#[test]
fn foreign_keys_refuse_an_orphan_security_record() {
    // The authority's connection enforces them; show SQLite does too for a
    // connection that turns them on, against the real schema.
    let h = Harness::new("fk");
    let conn = raw(&h.state());
    conn.pragma_update(None, "foreign_keys", "ON").unwrap();
    let orphan = conn.execute(
        "INSERT INTO run_grant (cap_id, run_id, ordinal, capability) VALUES ('c', 'no-such-run', 0, 'x')",
        [],
    );
    assert!(orphan.is_err(), "a grant for a run that does not exist");
}

#[test]
fn a_store_from_a_newer_build_is_refused_and_left_untouched() {
    let mut h = Harness::new("future");
    h.stop();
    {
        let conn = raw(&h.state());
        conn.pragma_update(None, "user_version", KERNEL_SCHEMA_VERSION + 1)
            .unwrap();
    }
    let before = sha256_of(&h.state().join("kernel.db"));
    let error = h.try_restart().unwrap_err();
    assert_eq!(
        error,
        StartError::FutureSchema {
            found: KERNEL_SCHEMA_VERSION + 1,
            supported: KERNEL_SCHEMA_VERSION
        }
    );
    assert_eq!(
        sha256_of(&h.state().join("kernel.db")),
        before,
        "not rewritten"
    );
    // Still refused on the next try: nothing "fixed" it.
    assert!(matches!(
        h.try_restart(),
        Err(StartError::FutureSchema { .. })
    ));
}

#[test]
fn a_sqlite_file_that_is_not_a_kernel_store_is_refused() {
    let dir = TempDir::new("foreign");
    let state = dir.state();
    std::fs::create_dir_all(&state).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    {
        let conn = rusqlite::Connection::open(state.join("kernel.db")).unwrap();
        conn.execute_batch("CREATE TABLE notes (body TEXT);")
            .unwrap();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(
            state.join("kernel.db"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    std::fs::write(state.join("audit.log"), b"").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(
            state.join("audit.log"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    let clock = Arc::new(ManualClock::new(START_MS));
    let error = start(&state, &balanced(), &clock, None).unwrap_err();
    assert_eq!(error, StartError::ForeignDatabase);
    let conn = rusqlite::Connection::open(state.join("kernel.db")).unwrap();
    assert_eq!(
        count(&conn, "SELECT count(*) FROM sqlite_schema"),
        1,
        "someone else's database is not migrated into ours"
    );
}

#[test]
fn a_kernel_id_with_no_version_is_malformed() {
    let mut h = Harness::new("malformed");
    h.stop();
    raw(&h.state())
        .pragma_update(None, "user_version", 0)
        .unwrap();
    assert!(matches!(
        h.try_restart(),
        Err(StartError::MalformedSchema(_))
    ));
}

#[test]
fn a_missing_table_is_never_recreated() {
    let mut h = Harness::new("missing-table");
    h.stop();
    raw(&h.state())
        .execute_batch("DROP TABLE run_policy_input;")
        .unwrap();
    let error = h.try_restart().unwrap_err();
    let StartError::MalformedSchema(why) = error else {
        panic!("expected a malformed schema, got {error:?}")
    };
    assert!(why.contains("run_policy_input"), "{why}");
    let conn = raw(&h.state());
    assert_eq!(
        count(
            &conn,
            "SELECT count(*) FROM sqlite_schema WHERE name = 'run_policy_input'"
        ),
        0,
        "the table was not silently recreated"
    );
}

#[test]
fn a_dropped_append_only_trigger_is_refused() {
    let mut h = Harness::new("trigger");
    h.stop();
    raw(&h.state())
        .execute_batch("DROP TRIGGER audit_chain_no_delete;")
        .unwrap();
    assert!(matches!(
        h.try_restart(),
        Err(StartError::MalformedSchema(_))
    ));
}

#[test]
fn missing_critical_state_quarantines() {
    let mut h = Harness::new("critical");
    h.stop();
    {
        let conn = raw(&h.state());
        // The trigger forbids deleting it; an attacker with file access can
        // drop the trigger, delete the row and put the trigger back.
        let sql: String = conn
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE name = 'store_meta_no_delete'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        conn.execute_batch("DROP TRIGGER store_meta_no_delete; DELETE FROM store_meta;")
            .unwrap();
        conn.execute_batch(&format!("{sql};")).unwrap();
    }
    let error = h.try_restart().unwrap_err();
    assert!(
        matches!(error, StartError::Corrupt(ref why) if why.contains("store_meta")),
        "{error:?}"
    );
    assert!(h.state().join(QUARANTINE_MARKER).exists());
    assert!(matches!(h.try_restart(), Err(StartError::Quarantined(_))));
}

#[test]
fn a_file_that_is_not_sqlite_is_quarantined_and_stays_refused() {
    let mut h = Harness::new("notadb");
    h.stop();
    let db = h.state().join("kernel.db");
    let wal = h.state().join("kernel.db-wal");
    let _ = std::fs::remove_file(&wal);
    let _ = std::fs::remove_file(h.state().join("kernel.db-shm"));
    std::fs::write(&db, vec![0x42_u8; 8192]).unwrap();
    let before = sha256_of(&db);
    let error = h.try_restart().unwrap_err();
    assert!(matches!(error, StartError::Corrupt(_)), "{error:?}");
    let marker = h.state().join(QUARANTINE_MARKER);
    assert!(marker.exists(), "a durable marker beside the store");
    assert_eq!(sha256_of(&db), before, "the damaged file was not replaced");
    // And it is not reopened on the next start, even though nothing changed.
    assert!(matches!(h.try_restart(), Err(StartError::Quarantined(_))));
    assert_eq!(sha256_of(&db), before);
}

/// Overwrite `page` (1-based) of `kernel.db` with garbage.
fn damage_page(state: &std::path::Path, page: i64) {
    use std::io::{Seek as _, SeekFrom, Write as _};
    let size = 4096_u64;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(state.join("kernel.db"))
        .unwrap();
    let offset = u64::try_from(page - 1).unwrap() * size;
    file.seek(SeekFrom::Start(offset)).unwrap();
    file.write_all(&vec![0xA5_u8; 4096]).unwrap();
    file.sync_all().unwrap();
}

fn root_page(state: &std::path::Path, table: &str) -> i64 {
    raw(state)
        .query_row(
            "SELECT rootpage FROM sqlite_schema WHERE name = ?1",
            [table],
            |r| r.get(0),
        )
        .unwrap()
}

fn checkpoint(state: &std::path::Path) {
    raw(state)
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))
        .unwrap();
}

#[test]
fn a_damaged_page_found_at_open_quarantines_the_store() {
    let mut h = Harness::new("page-at-open");
    let (caller, s) = (h.connect(1000), session(1));
    h.lease(&caller, &s);
    h.stop();
    checkpoint(&h.state());
    let page = root_page(&h.state(), "session_lease");
    damage_page(&h.state(), page);
    let error = h.try_restart().unwrap_err();
    assert!(matches!(error, StartError::Corrupt(_)), "{error:?}");
    assert!(h.state().join(QUARANTINE_MARKER).exists());
    assert!(matches!(h.try_restart(), Err(StartError::Quarantined(_))));
}

#[test]
fn corruption_observed_after_open_poisons_every_handle_and_stops_all_writes() {
    let mut h = Harness::new("page-after-open");
    let caller = h.connect(1000);
    h.lease(&caller, &session(1));
    // The store is healthy and open. Move everything into the main file, then
    // damage the lease table's root page underneath the running authority.
    checkpoint(&h.state());
    let page = root_page(&h.state(), "session_lease");
    damage_page(&h.state(), page);

    // A fresh connection reads the page from disk and meets the damage.
    let mut fresh = h.authority().handle().unwrap();
    let observed = fresh.acquire_lease(&caller, &session(2));
    assert_eq!(
        observed,
        Err(AuthorityError::Poisoned(PoisonReason::Corrupt))
    );

    // Every handle is poisoned now -- including the one that saw nothing --
    // and fails fast without touching the files.
    let db = h.state().join("kernel.db");
    let wal = h.state().join("kernel.db-wal");
    let db_before = sha256_of(&db);
    let wal_before = std::fs::read(&wal).unwrap_or_default();
    let other = h.connect(1001);
    assert!(matches!(
        h.authority().acquire_lease(&other, &session(3)),
        Err(AuthorityError::Poisoned(PoisonReason::Corrupt))
    ));
    assert!(matches!(
        h.authority().handle(),
        Err(AuthorityError::Poisoned(_))
    ));
    assert_eq!(h.authority().poisoned(), Some(PoisonReason::Corrupt));
    assert!(h.state().join(QUARANTINE_MARKER).exists());

    // Closing every handle does not checkpoint: neither file changes.
    drop(fresh);
    h.stop();
    assert_eq!(sha256_of(&db), db_before, "no write after poisoning");
    assert_eq!(
        std::fs::read(&wal).unwrap_or_default(),
        wal_before,
        "no checkpoint after poisoning"
    );
    assert!(matches!(h.try_restart(), Err(StartError::Quarantined(_))));
}

#[test]
fn a_missing_kernel_db_beside_surviving_state_is_not_a_fresh_start() {
    let mut h = Harness::new("missing-db");
    h.stop();
    std::fs::remove_file(h.state().join("kernel.db")).unwrap();
    let _ = std::fs::remove_file(h.state().join("kernel.db-wal"));
    let _ = std::fs::remove_file(h.state().join("kernel.db-shm"));
    assert!(matches!(h.try_restart(), Err(StartError::Layout(_))));
    assert!(
        !h.state().join("kernel.db").exists(),
        "no empty store was created over the surviving audit log"
    );
}

#[test]
fn a_missing_audit_log_is_not_recreated() {
    let mut h = Harness::new("missing-audit");
    h.stop();
    std::fs::remove_file(h.state().join("audit.log")).unwrap();
    assert!(matches!(h.try_restart(), Err(StartError::Layout(_))));
    assert!(!h.state().join("audit.log").exists());
}

#[test]
fn an_emptied_kernel_db_beside_an_audit_chain_is_refused() {
    let mut h = Harness::new("emptied");
    h.stop();
    let _ = std::fs::remove_file(h.state().join("kernel.db-wal"));
    let _ = std::fs::remove_file(h.state().join("kernel.db-shm"));
    std::fs::write(h.state().join("kernel.db"), b"").unwrap();
    assert!(matches!(h.try_restart(), Err(StartError::Layout(_))));
}

#[test]
fn a_second_authority_on_the_same_directory_is_refused() {
    let h = Harness::new("locked");
    let clock = Arc::new(ManualClock::new(START_MS));
    let error = start(&h.state(), &balanced(), &clock, None).unwrap_err();
    assert_eq!(error, StartError::Locked);
}

#[test]
fn an_invalid_policy_prevents_startup_and_writes_nothing() {
    let dir = TempDir::new("bad-policy");
    let mut config = balanced();
    config.policy.sources[0]
        .text
        .push_str("\n[[rule]]\nid = \"late\"\neffect = \"ALLOW\"\n");
    let clock = Arc::new(ManualClock::new(START_MS));
    let error = start(&dir.state(), &config, &clock, None).unwrap_err();
    assert!(matches!(error, StartError::Policy(_)), "{error:?}");
    assert!(
        !dir.state().exists(),
        "a policy that does not load is a start that does not touch the disk"
    );
}

#[test]
fn a_startup_policy_change_is_a_new_revision_and_a_new_activation() {
    let mut h = Harness::new("policy-change");
    let first = h.report.policy_revision;
    let first_activation = h.report.activation_id;
    h.config.policy = dwkd_authority::state::PolicySet::shipped("safe").unwrap();
    let report = h.restart().clone();
    assert_ne!(report.policy_revision, first);
    assert_eq!(report.activation_id, first_activation + 1);
    // The same configuration again: same revision, same activation.
    let again = h.restart().clone();
    assert_eq!(again.policy_revision, report.policy_revision);
    assert_eq!(again.activation_id, report.activation_id);
    // Both revisions and their sources are kept.
    let conn = raw(&h.state());
    assert_eq!(count(&conn, "SELECT count(*) FROM policy_revision"), 2);
    assert_eq!(count(&conn, "SELECT count(*) FROM policy_source"), 2);
}

#[test]
fn a_tampered_policy_snapshot_is_refused() {
    let mut h = Harness::new("policy-tamper");
    h.stop();
    {
        let conn = raw(&h.state());
        let sql: String = conn
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE name = 'policy_source_no_update'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        conn.execute_batch(
            "DROP TRIGGER policy_source_no_update; \
             UPDATE policy_source SET text = CAST(replace(CAST(text AS TEXT), 'DENY', 'ALLOW') AS BLOB);",
        )
        .unwrap();
        conn.execute_batch(&format!("{sql};")).unwrap();
    }
    let error = h.try_restart().unwrap_err();
    assert!(matches!(error, StartError::Corrupt(_)), "{error:?}");
}

#[test]
fn a_session_epoch_counter_cannot_be_deleted_or_lowered_even_with_file_access() {
    let mut h = Harness::new("epoch-rows");
    let caller = h.connect(1000);
    let s = session(1);
    h.lease(&caller, &s);
    let conn = raw(&h.state());
    assert!(
        conn.execute("DELETE FROM session_lease", []).is_err(),
        "a deleted counter would restart at epoch 1"
    );
    assert!(
        conn.execute("UPDATE session_lease SET epoch = epoch - 1", [])
            .is_err()
    );
}

#[test]
fn append_only_security_history_refuses_update_and_delete() {
    let mut h = Harness::new("append-only");
    let caller = h.connect(1000);
    let s = session(1);
    let e = h.lease(&caller, &s);
    let msg = state_support::admit_simple(&s, e, "k", &["model.call:*"]);
    let Reply::Done(_) = h.authority().admit_run(&caller, &msg).unwrap() else {
        panic!("admitted")
    };
    let conn = raw(&h.state());
    for sql in [
        "UPDATE audit_chain SET record = x'00'",
        "DELETE FROM audit_chain",
        "UPDATE admission_idempotency SET request_digest = 'x'",
        "DELETE FROM admission_idempotency",
        "UPDATE run_grant SET capability = 'model.call:*'",
        "DELETE FROM run_grant",
        "DELETE FROM run",
        "UPDATE run SET subject = 'uid:0'",
        "DELETE FROM policy_revision",
        "UPDATE policy_source SET name = 'x'",
        "DELETE FROM agent_profile",
        "UPDATE audit_head SET seq = 0",
    ] {
        assert!(conn.execute(sql, []).is_err(), "`{sql}` was allowed");
    }
}

#[test]
fn a_run_cannot_be_reactivated_even_by_a_raw_write() {
    let mut h = Harness::new("no-resurrect");
    let caller = h.connect(1000);
    let s = session(1);
    let e = h.lease(&caller, &s);
    let msg = state_support::admit_simple(&s, e, "k", &["model.call:*"]);
    let Reply::Done(admission) = h.authority().admit_run(&caller, &msg).unwrap() else {
        panic!("admitted")
    };
    h.authority()
        .release_run(&caller, &s, admission.run_id(), e)
        .unwrap();
    let conn = raw(&h.state());
    assert!(
        conn.execute("UPDATE run SET state = 'ACTIVE', ended_ms = NULL", [])
            .is_err()
    );
}

#[cfg(unix)]
mod unix {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::sync::Arc;

    use dwkd_authority::state::{ManualClock, StartError};

    use super::state_support::{Harness, START_MS, TempDir, balanced, session, start};

    fn mode(path: &std::path::Path) -> u32 {
        std::fs::symlink_metadata(path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777
    }

    #[test]
    fn the_state_directory_and_every_state_file_are_private() {
        let mut h = Harness::new("modes");
        let caller = h.connect(1000);
        h.lease(&caller, &session(1));
        assert_eq!(mode(&h.state()), 0o700);
        for file in [
            "kernel.db",
            "kernel.db-wal",
            "kernel.db-shm",
            "audit.log",
            "authority.lock",
        ] {
            let path = h.state().join(file);
            assert!(path.exists(), "{file}");
            assert_eq!(mode(&path) & 0o077, 0, "{file} is {:o}", mode(&path));
        }
        let uid = std::fs::metadata(h.state()).unwrap().uid();
        assert_eq!(
            std::fs::metadata(h.state().join("kernel.db"))
                .unwrap()
                .uid(),
            uid
        );
    }

    #[test]
    fn a_group_or_world_accessible_directory_is_refused() {
        let mut h = Harness::new("dir-mode");
        h.stop();
        std::fs::set_permissions(h.state(), std::fs::Permissions::from_mode(0o750)).unwrap();
        assert!(matches!(h.try_restart(), Err(StartError::Permissions(_))));
        std::fs::set_permissions(h.state(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(h.try_restart().is_ok());
    }

    #[test]
    fn a_readable_kernel_db_is_refused() {
        let mut h = Harness::new("file-mode");
        h.stop();
        let db = h.state().join("kernel.db");
        std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(h.try_restart(), Err(StartError::Permissions(_))));
    }

    #[test]
    fn a_symlinked_kernel_db_is_refused_rather_than_followed() {
        let mut h = Harness::new("symlink");
        h.stop();
        let db = h.state().join("kernel.db");
        let elsewhere = h.dir.path().join("elsewhere.db");
        std::fs::rename(&db, &elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &db).unwrap();
        assert!(matches!(h.try_restart(), Err(StartError::Permissions(_))));
    }

    #[test]
    fn a_symlinked_state_directory_is_refused() {
        let dir = TempDir::new("symlink-dir");
        let real = dir.path().join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
        let link = dir.path().join("state");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let clock = Arc::new(ManualClock::new(START_MS));
        assert!(matches!(
            start(&link, &balanced(), &clock, None),
            Err(StartError::Permissions(_))
        ));
    }
}
