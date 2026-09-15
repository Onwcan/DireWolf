# Storage

---

## 1. Choice: SQLite

For a local-first, single-node, single-operator runtime, SQLite is the correct default and not a compromise. It is an embedded library (no daemon, no port, no auth surface), a single file (trivially backed up and moved), transactional, extremely well tested, and ships FTS5 for the memory index. Postgres would add an operational dependency to a product whose premise is "runs on your laptop."

Layout:

```
$DIREWOLF_HOME/
  runtime.db          runtime-owned    entities, events, memory, task graph
  runtime.db-wal
  kernel.db           kernel-owned     capabilities, approvals, budgets, secrets index
  audit.log           kernel-owned     append-only, hash-chained
  artifacts/          kernel-owned     CAS: <sha[0:2]>/<sha[2:4]>/<sha256>
  policy/             kernel-owned     rule packs (read-only to runtime)
  config/             kernel-owned
  workspaces/         per-workspace
  logs/
```

Permissions are checked at startup and by `direwolf doctor`; the daemon refuses to start if the runtime user can write `kernel.db`, `audit.log` or `policy/`.

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

**Connection discipline:** one writer connection with a serialised queue, plus a reader pool. SQLite permits multiple writers with retries; we do not use that, because `SQLITE_BUSY` retry loops under contention produce latency spikes that are indistinguishable from hangs. One writer makes behaviour predictable.

## 3. Corruption handling

Adopted from an observed real-world failure in a comparable system, where writes continued for ~50 minutes after the first structural error, checkpointing pages under wrong page numbers and compounding the damage.

**Quarantine on structural corruption.** On `SQLITE_CORRUPT` or `SQLITE_NOTADB`:

1. The handle is marked poisoned **in memory, immediately**. Every subsequent operation on it fails fast without touching the file.
2. The handle never reopens. No retry, no "maybe it was transient."
3. WAL checkpointing is skipped — checkpointing a corrupt database is how a recoverable problem becomes an unrecoverable one.
4. A durable marker is written **beside** the database, not in it.
5. The runtime enters degraded mode: in-flight runs suspend with checkpoints already on disk; new runs are refused with a specific error.
6. The operator is told exactly what happened and what to run.

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
