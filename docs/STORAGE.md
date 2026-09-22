# Storage

---

## 1. Choice: SQLite

For a local-first, single-node, single-operator runtime, SQLite is the correct default and not a compromise. It is an embedded library (no daemon, no port, no auth surface), a single file (trivially backed up and moved), transactional, extremely well tested, and ships FTS5 for the memory index. Postgres would add an operational dependency to a product whose premise is "runs on your laptop."

Layout:

```
$DIREWOLF_HOME/
  runtime.db          runtime-owned    entities, events, memory, task graph
  runtime.db-wal
  authority/          kernel-owned     0700: the authority's private state directory
    kernel.db         kernel-owned     epochs, leases, runs, grants, policy inputs and
                                       revisions (M3d); approvals, budgets, secrets
                                       index (later milestones)
    kernel.db-wal
    audit.log         kernel-owned     append-only, hash-chained
    authority.lock    kernel-owned     one authority process per directory
  artifacts/          kernel-owned     CAS: <sha[0:2]>/<sha[2:4]>/<sha256>
  policy/             kernel-owned     rule packs (read-only to runtime)
  config/             kernel-owned
  workspaces/         per-workspace
  logs/
```

Permissions are checked at startup and by `direwolf doctor`; the daemon refuses to start if the runtime user can write `kernel.db`, `audit.log` or `policy/`.

**Why the kernel's files are in a directory of their own** (M3d,
[ADR-0039](adr/0039-durable-authority-state.md) §2): the runtime writes
`$DIREWOLF_HOME`, and a user who can write the directory holding `kernel.db`
can replace it by renaming another file over it without ever writing it. The
authority refuses a state directory or state file that is a symlink, carries
any group or other permission bit, or (on Unix) is owned by another uid, and
it never creates a store around a missing piece — `kernel.db` gone beside a
surviving `audit.log`, or the reverse, is refused, not "started fresh". M3d's
authority takes the state directory as a parameter; where it sits under
`$DIREWOLF_HOME` is fixed when the daemon is served (M3e) and packaged. Mode
bits are not the claim: `make authority-write-probe` attempts the writes as
the runtime user and reports NOT EXERCISED where no second user exists.

## 2. Pragmas

```sql
PRAGMA journal_mode  = WAL;        -- concurrent readers with one writer
PRAGMA synchronous   = NORMAL;     -- safe under WAL; FULL for kernel.db and audit
PRAGMA foreign_keys  = ON;
PRAGMA busy_timeout  = 5000;
PRAGMA wal_autocheckpoint = 1000;
PRAGMA cache_size    = -64000;     -- 64 MB
PRAGMA temp_store    = MEMORY;
PRAGMA mmap_size     = 268435456;
```

`kernel.db` uses `synchronous = FULL`. Losing an approval record or a budget debit to a power failure is a security event, and the throughput cost is irrelevant at kernel message rates.

**`kernel.db` has its own settings** ([ADR-0039](adr/0039-durable-authority-state.md) §3), each set and read back, a mismatch refusing the connection: `WAL`, `synchronous = FULL`, `fullfsync = ON`, `foreign_keys = ON`, `busy_timeout = 5000`, `trusted_schema = OFF`, `mmap_size = 0` (an I/O error must arrive as a classifiable error code, not a signal), `SQLITE_DBCONFIG_DEFENSIVE` and `SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE`. It is opened without URI parsing and with `SQLITE_OPEN_NOFOLLOW`. Every table is `STRICT`.

**Connection discipline:** one writer connection with a serialised queue, plus a reader pool. SQLite permits multiple writers with retries; we do not use that, because `SQLITE_BUSY` retry loops under contention produce latency spikes that are indistinguishable from hangs. One writer makes behaviour predictable.

*The kernel store departs from this, deliberately and for now.* M3d gives each authority handle its own connection and serialises writers with `BEGIN IMMEDIATE`; a writer that waits past the busy timeout fails closed with `Busy` and changes nothing. There is no retry loop, so the spike this section warns about becomes a refusal rather than a hang. M3e's server decides whether it needs the queue.

## 3. Corruption handling

Adopted from an observed real-world failure in a comparable system, where writes continued for ~50 minutes after the first structural error, checkpointing pages under wrong page numbers and compounding the damage.

**Quarantine on structural corruption.** On `SQLITE_CORRUPT` or `SQLITE_NOTADB`:

1. The handle is marked poisoned **in memory, immediately**. Every subsequent operation on it fails fast without touching the file.
2. The handle never reopens. No retry, no "maybe it was transient."
3. WAL checkpointing is skipped — checkpointing a corrupt database is how a recoverable problem becomes an unrecoverable one.
4. A durable marker is written **beside** the database, not in it.
5. The runtime enters degraded mode: in-flight runs suspend with checkpoints already on disk; new runs are refused with a specific error.
6. The operator is told exactly what happened and what to run.

For `kernel.db` this is implemented (M3d): extended result codes decide, never
messages; `SQLITE_CORRUPT` and `SQLITE_NOTADB` poison every handle at once and
write `kernel.quarantined` beside the store; an I/O error, or a failure to
write or `fsync` `audit.log`, poisons without the marker, and the next start
re-verifies everything from the files. Point 3 holds because every connection
sets `NO_CKPT_ON_CLOSE`, so dropping a poisoned authority leaves `kernel.db`
byte-identical. The authority never removes the marker, renames the store away
or creates a replacement. Of point 6, what exists is the marker's reason and
the read-only `dwkd-authority verify-audit <state-dir>`; the commands below are
the runtime's, and do not exist yet.

```console
$ direwolf store inspect --db runtime.db
$ direwolf store recover --db runtime.db --out runtime.recovered.db
$ direwolf store repair --check-only
```

**Derived-index corruption is different and recoverable.** FTS5 index corruption does not poison the canonical tables: a `fts_stale` marker is written, the sync triggers are dropped, canonical writes continue, and memory search falls back to `LIKE` with a visible degradation warning until `direwolf memory reindex` runs. Losing search quality is survivable; losing writes is not.

## 4. Migrations

Forward-only, numbered, transactional, each with a declared risk level.

```
migrations/
  0001_initial.sql
  0002_add_taint_level.sql
  0003_memory_provenance.sql        -- risk: high (data transform)
```

```
direwolf migrate status | plan | up [--to N] | verify
```

Rules:

1. **Backup before any `risk: high` migration**, automatically. `runtime.db` is copied via the SQLite backup API (not `cp` — copying a live WAL database produces a corrupt copy).
2. Each migration runs in a transaction; failure rolls back fully.
3. **No destructive column drops in the same release that stops using them.** Deprecate in release N, drop in N+2, so a downgrade remains possible for one release.
4. Post-migration verification queries assert invariants (row counts, no orphans, FTS consistency).
5. The schema version is recorded in `schema_migrations`; a database newer than the binary refuses to open rather than guessing.
6. Kernel and runtime schemas version independently — they are separate stores with separate lifecycles.

**`kernel.db` versions itself differently, and more strictly** ([ADR-0039](adr/0039-durable-authority-state.md) §4). The version is `PRAGMA user_version`, written in the same transaction as the schema it describes, and `PRAGMA application_id` marks the file as a kernel store; there is no second version table to disagree with. A store claiming the current version must contain exactly the objects this build's DDL creates, byte-identical, and nothing else. A newer version, a foreign database, or a missing or extra object is refused, never repaired. Security history is append-only by trigger. Kernel migrations are static SQL applied in one transaction; there is no migration framework and no `risk: high` kernel migration yet, because version 1 is the only version.

**Event schema evolution** is the harder half and is covered in [PROTOCOL.md](PROTOCOL.md) §6: events are data, not rows, and old events must remain readable forever. Upcasters translate at read time; projections are rebuildable from scratch (`direwolf store rebuild-projections`), which is the escape hatch when a projection's shape changes.

## 5. Backup

```console
$ direwolf backup create --out ./backup-2026-09-12.tar.zst
$ direwolf backup verify ./backup-2026-09-12.tar.zst
$ direwolf backup restore ./backup-2026-09-12.tar.zst
```

Uses the SQLite Online Backup API for a consistent snapshot without stopping work, plus the artifact CAS (deduplicated by hash, so incremental backups are cheap) and the audit log. A manifest records per-file hashes and the audit chain head, so a restored backup can be checked for tampering.

**Secrets are not in backups.** `kernel.db` holds the secrets *index*; values live in the OS keychain. A backup is not a credential export, and restoring on a new machine requires re-providing credentials. This is deliberate friction.

## 6. Scale expectations

Sizing for a single operator over a year of heavy use: ~10 k sessions, ~100 k runs, ~10 M events, ~500 k memory items, ~100 GB artifacts. SQLite handles the relational side comfortably; artifacts dominate disk, which is why retention policies and reference-counted GC matter more than query optimisation.

**We are not building for scale we do not have.** The repository interfaces exist because they are how the code is organised, not as a portability layer for a hypothetical Postgres migration. If multi-node deployment ever becomes a real requirement, the honest answer is that it changes the concurrency model ([ARCHITECTURE.md](ARCHITECTURE.md) §15) and the lease mechanism, not merely the database — and that is a redesign, not a driver swap. Pretending otherwise with an abstraction layer would be the "database abstraction theatre" this project explicitly rejects.

## 7. Encryption at rest

| Data | Protection |
|---|---|
| Secret values | OS keychain, or `age`-encrypted with the key in the keychain |
| `kernel.db` | Filesystem permissions (0600, kernel user) |
| `runtime.db` | Filesystem permissions (0600, runtime user) |
| Artifacts | Filesystem permissions; `SECRET`-sensitivity artifacts encrypted at rest |
| Audit log | Permissions + hash chain (integrity, not confidentiality) |
| Backups | Optional `age` encryption, **on by default** when the backup contains `PRIVATE` or `SECRET` data |

**Stated plainly: session content, memory and most artifacts are plaintext on disk.** They are protected by filesystem permissions and by whatever full-disk encryption the OS provides — not by application-level encryption. Encrypting the whole database would break FTS5 indexing and add a key-management problem, for protection that full-disk encryption already provides against the realistic threat (a stolen laptop). Against a local attacker with your user account, application-level encryption of a database your own process must read is close to theatre.

We invent no cryptography: `age` for files, OS APIs for keychains, `rustls` for transport.
