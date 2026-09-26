# ADR-0046: M4e — opaque secret handles, the kernel keyring and age backends, one-shot injection, return-path redaction, and the final M4 security gate

**Status:** Accepted · **Date:** 2026-09-26 · **Amends:** [ADR-0019](0019-language-rationale-v2.md) (the authority's dependency closure grows by the secret backends: measured in §25), [ADR-0018](0018-authority-broker-split.md) (the broker now holds a secret value for one invocation, delivered as a descriptor), [ADR-0039](0039-durable-authority-state.md) (schema version 6: the secret index, bindings, injection ledger and use counts), [ADR-0043](0043-m4b-private-broker-channel-and-brokered-fs-read.md), [ADR-0044](0044-m4c-filesystem-operations-plans-and-atomic-mutation.md) and [ADR-0045](0045-m4d-process-execution-broker.md) (private protocol version 4; return-path redaction of `fs.read` content and process output) · **Refines:** [ADR-0037](0037-capability-specifications-and-canonical-authority-identities.md) (a concrete `secret.use:<handle>` means what the secret index holds), [ADR-0041](0041-m3e-authenticated-dwkp-transport.md) (both daemons refuse to dump core and keep their memory from their own uid)

> **Invariant I3 holds by construction and is measured on real processes: the
> cognition plane never receives a plaintext long-lived credential.** A handle
> is an identifier; nothing on DWKP, in the CLI or anywhere else returns a
> value. A value is read from the OS keychain or an age file **only after** a
> `secret.use:<handle>` action passed both gates and its intent is durable; it
> leaves the authority as the read end of a pipe, once, and the authority's
> copy is zeroed before the broker reads it. Output that echoes a value is
> redacted before it is encoded for the runtime. The runtime's address space,
> every durable file, and both daemons after they handled a value are read
> afterwards, and hold none. M4e ships no egress consumer and no sandbox: the
> secret side of modes A–C is real, and the consumers are M5's.

## Context

M4 is five parts (ADR-0042 §1); this is the last. [SECRETS.md](../SECRETS.md)
set out opaque handles, backends, injection modes A–D and redaction before any
of it existed. M4a–M4d built what secrets need underneath — the resolver, the
private channel, the broker, executable identities — and M4e makes the secret
contract real without pulling M5 (sandboxes, egress) or M6 (approvals) forward.

The design was reviewed at two checkpoints before code: what M4e may own
against M5 and M6 (§1), and which backends and dependencies are feasible
(§§6–8, 25). The operator chose, at those
checkpoints: the kernel keyring as the Linux keychain (not Secret Service),
fingerprinting every configured value once at start for the redaction index
(§21), and age **0.11.5**, pinned exactly (§25).

## Decision

### 1. Scope, and the M4e / M5 / M6 boundary

M4e owns: the metadata and the index; the keychain and age backends; the
material type; the one-shot authority→broker handoff; the mode A render and
the mode B/C **secret injection primitive**; mode selection, consumer and
origin binding; `secret.use` admission and its canonical action; redaction;
the audit events, revocation and use accounting; schema version 6; the
residue, core and runtime-address-space evidence; and the activation of the M4
evals and the final M4 gate.

It does **not** own: the sandbox, network namespaces, `net.http`, the CONNECT
proxy (M5); approvals or standing grants (M6); model egress or provider
credentials (M7); `ChannelSend`; artifacts (M8); a CLI secret command of any
kind. None is implemented or stubbed. Mode A has **no egress consumer** in M4e:
the broker renders the header and drops it (§12). Modes B and C have **no
production caller** before M5: the authority's selector refuses a host spawn
(§15), and the primitive is exercised by a harness playing the authority, as
M4b–M4d's broker evidence is.

### 2. A handle is an identifier

A handle matches `[a-z][a-z0-9._-]{0,63}` and is also a capability label, so
`secret.use:<handle>` parses (ADR-0037). It names, never carries, a value; a
leaked handle grants nothing. Its **meaning is its current revision** (§20): a
run is bound at admission to the revision each concrete handle it was granted
resolved to, and a later revision under the same spelling is a different
secret — a use by that run fails `REPLACED`.

### 3. Metadata: its source, and the index in `kernel.db`

The operator's metadata is a TOML file named by `--secrets-file` (absolute),
read through the trusted-file opener (§8: every directory from `/` owned by
root or the authority and not group/other-writable unless sticky, the file
owned by root or the authority, not group/other-writable, no set-id bit), and
parsed strictly: an unknown member, a duplicate, a missing required field, a
mode's field without the mode, more than 64 secrets or 256 KiB is refused with
the line and field. It holds handles, types, backend references, origins,
header and prefix, the mode allowlist, consumers, the variable name,
`rotate_after`, sensitivity and `revoked` — **never a value**.

The metadata file is the source of truth; `kernel.db` holds its history. At
start the authority records every difference as a new, append-only
`secret_revision` (state `CONFIGURED`, `REVOKED` or `REMOVED`) with the
canonical JSON of the metadata and its SHA-256 — consumer identities as
resolved (§15), no value, no prefix, no length, nothing derived from one.

### 4. No API returns a value; a secret use is not a tool; DWKP does not change

There is no `secret.get`, `secret.read`, `secret.export` or anything like it:
not on DWKP, not private to the runtime, not in the CLI, not for diagnostics,
backup or an administrator. `secret.use` is a capability a containing tool's
action requires, never a tool. **The public protocol is unchanged**: no current
production tool can consume a secret before M5, so no public version 4 was
added; when `net.http` arrives its request will carry
handles only. The public corpus — every emitted schema, every shared vector,
every generated binding — is checked for a member that could carry a value
(`tests/protocol/test_no_secret_value_fields.py`), and TX027/TX030/TX031 keep
the spellings out of the code.

### 5. Admission, stored grants and replay read no value

A NEW concrete `secret.use:<handle>` declaration resolves against the index —
a metadata read inside the admission transaction: configured and unrevoked, or
withheld `NEEDS_CONFIGURED_SECRET`. Like every resource scope since M4b, it is
resolved before profile, skill and ceiling coverage is asked, so an
unconfigured handle is withheld for that reason even where the profile does
not cover it either (before M4e the same request read `NOT_IN_AGENT_PROFILE`;
it is withheld either way). A STORED grant rehydrates from its stored
text, by grammar alone. An admission REPLAY answers the recorded admission.
None touches a backend; a test-only per-thread counter proves zero reads for
all three, and exactly one read for a use (§17).

### 6. The keychain backend

| platform | backend | status |
|---|---|---|
| Linux | the **kernel keyring** (`linux-keyutils` 0.2.5): a `user` key in the authority uid's user keyring, read into a pre-sized zeroizing buffer | exercised: real keyring, round trip, missing, removed, the kernel's own size refusal |
| Windows | the Credential Manager through `keyring` 3.6.3 (`windows-native`), target `direwolf` | exercised by the crate's tests against the real Credential Manager; never served (no DWKP server on Windows) |
| macOS | the login Keychain through `keyring` 3.6.3 (`apple-native`), service `direwolf` | **COMPILE-ONLY**: built and linked, not exercised (a CI keychain may prompt) |

The kernel keyring is per uid: the broker's and the runtime's uids have their
own and cannot search the authority's (measured with three identities, §23).
A `user` key holds at most 32 767 bytes, and a non-root user's keys share a
quota (`/proc/sys/kernel/keys/maxbytes`, 20 000 by default): large values
belong in age files. The authority spawns nothing to reach a keychain — no
`secret-tool`, `security`, `cmdkey`, `pass`, `op`, `vault` (TX010, TX025).
Secret Service/D-Bus was rejected at the checkpoint: it needs a session bus and
an unlocked collection, and pulls an async D-Bus stack into the TCB.

### 7. The `env` and `exec` backends are deferred

`storage = "env"` would keep a plaintext value in the authority's `environ`,
readable from `/proc/<pid>/environ` by its uid, inherited by anything it
starts, and set by whoever started it; `storage = "exec"` would need the
authority to spawn a helper, which it never does (TX010). Both are refused at
load (`BackendDeferred`), with no silent fallback to plaintext.

### 8. The age backend

An age file (`storage = "age"`, an absolute path) is opened by walking from
`/` with `O_PATH | O_NOFOLLOW` (`secret/backend/trusted_file.rs`, TX008):
every directory owned by root or the authority and not group/other-writable
unless sticky; the file regular, owned by root or the authority, no
group/other permission at all, no set-id bit, at most 64 KiB. It is decrypted
by `age` 0.11.5 — no DireWolf cryptography — with the identity from the
keychain entry named by `[age] identity_keychain`: an X25519 identity string
or, with `identity_kind = "scrypt"`, a passphrase. The identity is never in
argv, the workspace, `kernel.db`, `audit.log` or a config value. Plaintext is
read through `take(MAX + 1)` into a zeroizing buffer; a larger value is refused
(`SECRET_TOO_LARGE`), never truncated. Every age error becomes a typed
`SecretError` with no text; none is ever formatted.

### 9. Process hardening: no core, no same-uid reader

Both daemons, first thing at serve start (`server/hardening.rs`,
`dwkd-broker/src/hardening.rs`): `RLIMIT_CORE` = 0 soft and hard, and
`PR_SET_DUMPABLE` = 0 — no core at all (a `core_pattern` pipe handler
included, which the limit alone does not stop), and `/proc/<pid>/{mem,environ,
fd,io,maps}` become root's. A launched target inherits the core limit.
`--allow-dumpable` (both daemons; development only; logged `REDUCED
ASSURANCE`) leaves the flag at 1 for a same-uid harness that reads the
daemons' `/proc` — the M4b–M4d descriptor and I/O evidence uses it; the core
limit holds regardless; the hardened default is measured separately.

**`mlock` and `MADV_DONTDUMP` are NOT implemented**: no safe API for either is
linked, and the workspace forbids `unsafe`. SECRETS.md's claim is corrected.
Swap is therefore a residual risk (§27).

### 10. Secret material

`SecretMaterial` wraps `Zeroizing<Vec<u8>>`, sized once at `MAX + 1` so it
never reallocates; it has no `Clone`, no `Display`, no `Serialize`, prints as
`SecretMaterial(..)`, refuses empty and oversized values, and exposes its bytes
only through a crate-private `expose()` called in three places — the handoff,
the keyed fingerprint, age's identity parser — and the backends' tests
(TX026). The bound
is **32 KiB** (`dwk_proto::brokerp::MAX_SECRET_BYTES`, shared by both daemons):
room for an RSA-8192 PEM key or a short chain, and under a pipe's 64 KiB
buffer so the handoff never blocks. The broker's buffers — the pipe contents,
a mode A header, a launch's needle and the helper's mode B assignment — are
`Zeroizing` too.

### 11. One-shot transport and the private descriptor contract

The value never enters a message. The authority writes it into a fresh pipe
(`std::io::pipe`, close-on-exec), closes the write end, **drops the material**,
and sends the read end by `SCM_RIGHTS` as the **last descriptor** of one
authorisation on one broker-issued channel. The broker checks it is a FIFO,
open read-only, sets it non-blocking and reads to end of file: "would block"
means a writer is still open — a stalled or substituted pipe — and is refused
without waiting. **Private protocol version 4** (the daemons ship together, so
it is the only version either accepts; v3's claims stay true of M4d):

| kind | descriptors, in order | fields besides channel and invocation |
|---|---|---|
| `broker.secret_egress` | the secret pipe | handle, origin, header name, optional prefix |
| `broker.secret_process_start` | executable, working directory, secret pipe | every `process_start` field, handle, delivery (`ENV_AT_SPAWN`/`FD_AT_SPAWN`), variable (mode B only) |

A missing or extra descriptor is `DESCRIPTOR_COUNT` with every descriptor
closed; a reversed order fails the executable's own checks before the value
is read; a directory, a regular file, a writable end or a stalled pipe is
`SECRET_DESCRIPTOR`; empty `SECRET_EMPTY`; oversized `SECRET_TOO_LARGE`; bytes
the delivery cannot carry `SECRET_UNSAFE_BYTES`. Replay on another connection
names another channel (`CHANNEL_MISMATCH`, zero bytes read); a consumed pipe
holds nothing (`SECRET_EMPTY`). No field of any private message can hold a
value or its length; the strict decoder refuses one.

### 12. Mode A: the egress render

The operator's metadata supplies the origins, the header name (an RFC 9110
token) and the prefix (printable ASCII); the request supplies only the handle
and a concrete `host:port`. The authority checks the origin against the
metadata's endpoints with the capability layer's grammar (§15), refuses a
value containing CR, LF or NUL before sending it, and the broker refuses it
again — never sanitises. The broker reads the value once, composes
`Name: prefix value` in a zeroizing buffer, and **drops it**: there is no
consumer until M5's `net.http`, and no claim is made about DNS, redirects,
TLS or IP policy, which land with it. What mode A proves now is the secret
side: gates, durable intent, one read, one handoff, one use, no residue.

### 13. Modes B and C: the secret injection primitive

`broker.secret_process_start` re-proves the executable and working directory
exactly as `process_start` does (ADR-0045), **then** reads the value, then
writes it into a second fresh pipe for the launch helper. Mode B: the helper
reads it and appends `NAME=value` to the target's `envp` (the variable from
the metadata, never `LD_*`, `DYLD_*`, `PATH`, `PYTHON*`, `RUSTC*`, `GIT_*` or
any other process-control variable, checked by both daemons). Mode C: the
helper `dup2`s the pipe onto descriptor 3 — the one descriptor the target may
inherit — without reading it. The helper's memory ends at `execveat`.

**This is not sandbox injection.** The target runs on the host with the
broker's privileges; the production authority never sends this message (§15).
Measured with real targets: the value is in the target's environment (B) or on
its fd 3 (C) and nowhere else — not argv, not the broker's environment, not a
sibling's. **Mode C's descriptor IS inherited by a grandchild** the target
starts without closing it (measured: `os.system` sees fd 3). SECRETS.md's
"not inherited by grandchildren" was untrue and is corrected: containment of a
process tree is M5's.

### 14. Mode D is unreachable

`plaintext_to_model` is refused at load (`ModeUnreachable`): it needs
`security.allow_secret_to_model`, a per-use approval and a critical audit, and
approvals are M6's. There is no test-only path to it. **DEFERRED — UNREACHABLE
UNTIL M6.**

### 15. Mode selection, consumer binding and origin binding

The kernel selects the mode from the metadata's allowlist, the operation, the
consumer, the environment and the origin — never from a request, which has no
field for one. An egress use requires `egress` in the allowlist and an origin
the metadata covers; a spawn requires a consumer whose **executable identity**
(canonical path and SHA-256, resolved when the metadata is loaded) equals the
launch's, and picks `fd_at_spawn` before `env_at_spawn`. Replacing the
consumer's bytes changes its identity: the secret does not follow until the
operator restarts with the metadata. A host spawn is refused
(`INJECTION_MODE_UNAVAILABLE`) in every production build; only the crate's own
tests can enable it. Origins use the endpoint grammar without a new wildcard
language: `api.example.com:443` does not cover `api.example.com.evil.test`,
`evil-api.example.com`, `example.com`, another port, or a userinfo form.

### 16. Output of an injected launch

A secret launch's streams are redacted **while drained**, by a streaming
Knuth–Morris–Pratt matcher over the value that finds an occurrence split
across reads and holds no partial copy (the matched bytes are the value's own
prefix). The retained output never holds the value, so the process table does
not keep an echoed credential until eviction; the placeholder is
`[redacted:<handle>]`. Once retention is full the rest is counted, not
scanned. The needle lives exactly as long as the drains and is zeroed when both
streams end. A value cut short by the stream's end is not the value and is not
redacted (§21).

### 17. The authority's order

`Authority::secret_egress` — an in-process API, **no DWKP route** — runs:
fence, run and key (a replayed key answers the recorded outcome, reading
nothing); the typed request; the metadata and the run's revision; the mode;
`secret.use:<handle>` through both gates and the obligations; the **durable
intent**, audited — one transaction, no backend I/O. Then, with no transaction
open: the backend read; the redaction index learns the value; the header check;
the one-shot pipe and the material zeroed; the broker; then the outcome, the use
count and the audit in one transaction; then the answer.

### 18. The canonical action, policy, approvals and the sandbox

A use needs `secret.use:<handle>` with environment `host`; the capability gate
checks the run's grants, the policy gate the active rules. Only `audit_level`
obligations can be kept; any other denies (`OBLIGATION_UNENFORCEABLE`). The
action carries handle and environment; mode, origin and consumer are decided
by the metadata and recorded in the audit, not policy inputs — policy
predicates over them are not added in M4e. **Every shipped pack denies
`secret.use`** (SAFE by rule, BALANCED and POWER by default); evidence uses a
dedicated operator test policy, never described as shipped behaviour. No
approval exists (M6) and no sandbox (M5); neither is simulated.

### 19. Crash, restart and replay

Crash points R1–R6, R8, R10 and the post-outcome S9 are named in
`CrashPoint::SECRET`, R7 is the broker's `secret_after_read`, and R9 is a
process invocation's `ToolAfterBroker`. Nothing before the intent commits is durable. An intent a
previous incarnation left open is ended `UNKNOWN` at start and **never injected
again**; its run died with the incarnation, so a replay is refused. A broker
restart holds no value and reconstructs none. After every crash point:
no durable plaintext, no second handoff, the use counted only if the outcome
was durable.

### 20. Durable state: schema version 6; revocation; use accounting

Four tables, append-only by trigger, and `run_withheld`'s reasons widened by
`NEEDS_CONFIGURED_SECRET` (a transactional rebuild; tested from v5 with data):
`secret_revision` (consecutive revisions per handle), `secret_run_binding`,
`secret_injection` (one row per use, `INTENT` → `INJECTED`/`FAILED`/`UNKNOWN`
exactly once, unique per subject, session and key) and `secret_use` (a count
that never falls). A revoked or removed handle fails closed for every run,
whatever a stored grant says; an in-flight use is not retroactively killed.
The count and `last_used` move only on a confirmed injection, once per
invocation.

### 21. Redaction

**Hygiene, not the control** — the control is not putting a value where the
runtime can see it. Always on for `fs.read` content and process streams,
applied to raw bytes after the broker's bound is checked and **before** hex
encoding; the raw buffer is zeroed; output lengthened past its bound is cut
and marked (`eof_observed` false, `truncated` true).

* **Exact values.** At start every configured value is read once (§§6–8),
  fingerprinted and dropped. The index holds, per value, its length, a
  Rabin–Karp rolling hash (mod 2^61−1, random base) and an HMAC-SHA256 tag
  under a per-process key from `getrandom` — no value, never persisted. A
  window whose rolling hash matches is confirmed by the tag. At most 64
  values of 8–32 768 bytes; shorter values are not exact-indexed. A value
  whose read failed at start is indexed at its first use.
* **Known shapes**, no regex: GitHub, OpenAI, Slack, AWS key id, JWT, PEM
  private key, `Bearer`, connection-string passwords, and a high-entropy token
  after `password`/`token`/`api_key`-style keywords → `[redacted:pattern]`.
  Near misses (`sk-learn`, short `AKIA`, low-entropy passwords) stay.
* **Bounds**: 64 values, 32 KiB each, 512-byte tokens, 16 KiB PEM blocks; a
  scan is O(output × distinct lengths). The worst case the configuration
  allows — 64 values of 64 lengths over 256 KiB — is run as a test with a
  ceiling.
* **Limitations, measured and kept**: a transformed value (hex, base64,
  reversed, split by a byte) is not guaranteed; a value split across two
  results is not caught; `fs.list` names are not redacted; `fs.search` returns
  offsets, never bytes.
* **Audit**: `secret.redaction_hit` names the handle or the class and a count,
  never bytes.

### 22. Evidence: residue, core, the runtime's address space, durable state

Measured on real processes, `make secret-broker-evidence` (146 cases, each an
evidence line printed after its assertions held):

* **The runtime's address space**: a separate process — re-executed test
  binary, given the socket and paths, never the value — reads files holding the
  live value through the real daemons; its readable memory is then read and
  holds no value. As a peer identity in CI, root reads it.
* **Residue**: after mode A, the authority's library hosted in a separate
  process and the broker hold no value; after modes B and C and the egress
  render, the broker holds none; after redaction, the authority daemon holds no
  raw value. Descriptors closed; no file written.
* **Core**: (A) both production daemons' `limits` show a
  core limit of 0 and their `/proc` is root's; (B) memory snapshots after
  resolution, handoff and drop — same-uid locally, root against the hardened
  daemons in CI — find no value; (C) in CI, with `kernel.core_pattern` pointed
  at a directory, a crashed dumpable control process writes a core and both
  hardened daemons write none.
* **Durable state**: `kernel.db`, its WAL and shared memory, `audit.log`, the
  daemons' logs, the staging and IPC directories hold no value and no 16-byte
  prefix; the workspace holds only the inputs the test wrote.

### 23. Three identities

In CI: the runner as the authority, `dwbroker` as the broker, `nobody` as the
runtime — each proven by its numeric uid. Neither other uid can read the
metadata or an age store, or find the value in its own keyring; the runtime,
running as `nobody`, receives a placeholder; root reads all three processes'
memory; the runtime cannot reach the broker.

### 24. The M4 evals and the final M4 gate

`m4-security` replaces the pending M4 entries: `path-traversal` (the resolver,
six race campaigns, the brokered read after a name swap), `exec-mediation`
(argv, environment, descriptor-bound exec, re-proof, the production floor) and
`secret-boundary` (§22) — each running the real suites and requiring every
listed case. `M4` joins `AVAILABLE_MILESTONES` only now that each has a runner;
the baseline expects all three to pass; meta-tests prove a missing runner is
an error and a missing case, an escape or a value in memory fails. **The final
M4 gate is the `ci` aggregate**, which requires the M3 transport job, every
M4a–M4e evidence job and the eval gate; meta-tests keep each required.

### 25. Dependencies and the TCB

Measured with `cargo tree -p dwkd-authority --target <t> --locked` per
target:

| | Linux x86_64 | Linux aarch64 | macOS | Windows |
|---|---|---|---|---|
| third-party crates linked into the binary (`-e normal,no-proc-macro`), by name | 98 | 98 | 100 | 101 |
| the same, by name and version | 106 | 106 | 108 | 110 |
| crates built, proc macros included (`-e normal,build`), by name and version | 145 | 144 | 146 | 146 |
| proc-macro crates | 12 | 11 | 11 | 12 |

M4d's reviewed list named 27 (the union over targets). The reviewed lists are
now **147** crates that may be linked or run as a macro and **8** that only
build — 155, exactly the build closure's names over every target. Eight crates
appear in two versions (`digest`, `hmac`, `sha2`, `block-buffer`,
`crypto-common`, `cpufeatures`, `rustc-hash`, `self_cell`): age 0.11.5 is
built on the previous RustCrypto generation, the workspace on the current one.
What arrived:

* **Direct**: `age` 0.11.5, `zeroize` 1.9.0, `hmac` 0.13.0, `getrandom` 0.2.17,
  `linux-keyutils` 0.2.5 (Linux), `keyring` 3.6.3 (macOS, Windows), all pinned
  `=`, each named in one module (TX025); `rustix`'s `process` feature (code,
  not crates).
* **age's cryptography**: RustCrypto and dalek (X25519, ChaCha20-Poly1305,
  HKDF, scrypt, PBKDF2).
* **age's localisation**: i18n-embed with Fluent, rust-embed, futures,
  parking_lot. DireWolf never formats an age error, but the code is linked. In
  a **debug** build rust-embed reads age's `i18n/` folder from the Cargo
  registry at run time; release builds embed it.
* **Proc macros** (run on the build machine, not linked): `serde_derive`,
  `thiserror-impl`, `zeroize_derive`, `displaydoc`, `futures-macro`,
  `pin-project-internal`, `i18n-embed-fl`, `i18n-embed-impl`,
  `rust-embed-impl`, `rustversion`, `proc-macro-error-attr2` and, on x86_64,
  `curve25519-dalek-derive`, with `syn`, `quote` and `proc-macro2` beneath
  them — the first derive stack in the closure (ADR-0035 §2 had none);
  `test_boundaries` pins the exact set.
* **Build-only**: `rustc_version`, `semver`, `version_check` join the list.
  On Linux x86_64, 14 crates run a build script; `libsqlite3-sys` is still the
  only one that `links` native code.
* **FFI, no C compiled**: `linux-keyutils` (keyctl through libc),
  `security-framework-sys`/`core-foundation-sys` (macOS).

**DireWolf itself still has zero `unsafe`**; the new crates' `unsafe` is theirs
and is the review's subject. Cargo reports a future-incompatibility warning
for `proc-macro-error2` 2.0.1 (age's localisation macros): a future compiler
may refuse it, which would need an age release, not a DireWolf change. age 0.12.1 was measured and rejected: 138 linked
crates, 13 proc macros, and pre-release post-quantum KEM dependencies.

### 26. Platform contract

Linux is the only platform that serves; everything above is Linux-measured.
Windows: the secret module, redaction and protocol compile and pass their
tests natively, including a real Credential Manager round trip; the authority
serves nothing there. macOS: compiles and passes the platform-independent
tests in CI; the Keychain backend is COMPILE-ONLY; the authority serves
nothing there.

### 27. Residual risks

* A value exists in the authority's memory at start (fingerprinting) and for
  each use until it is zeroed; without `mlock` it can reach swap.
* Third-party copies: age's internal parsing of an identity, and `keyring`'s
  `Vec` on macOS and Windows, are not zeroed by DireWolf.
* The kernel holds the value in the pipe until the broker reads it; root, and
  anything able to ptrace a dumpable process, can read memory.
* A compromised broker sees the value during that invocation (ADR-0018's
  narrowed blast radius); a target holding a mode B or C value is the target's
  business, and its descendants may inherit mode C's descriptor.
* Output is redacted by exact value and known shape only (§21's limitations);
  the hex form of workspace content that happens to hold a value transits the
  authority's JSON decoding un-zeroed.
* `--allow-dumpable` exists; it is logged, and CI's hosted evidence runs the
  hardened default.

### 28. Explicit exclusions

No `env` or `exec` backend, Secret Service, `pass`, `vault` or `op`; no mode D;
no public v4; no `net.http`, proxy, redirect or IP policy; no sandbox, tmpfs or
namespace; no approval, standing grant or secret-to-model flow; no CLI secret
command; no `mlock`, `MADV_DONTDUMP` or custom cryptography; no cross-result
redaction state.

## Consequences

* I3 is a measured property: the runtime's memory, the durable state, argv,
  the broker's environment and both daemons after they handled a value are read.
* The authority's TCB grows by an order of magnitude — the price of age and a
  keychain without a helper process — and the allowlist, the build-only list
  and the proc-macro set are each exact and gated.
* M5 inherits a working secret side: `net.http` will attach an egress
  consumer to §12, and the sandbox will make §13 production.
* Both daemons refuse to dump core by default; same-uid introspection needs an
  explicit, logged switch.

## Alternatives considered

* **Secret Service over D-Bus for Linux** — the desktop standard. Rejected: a
  session bus and an unlocked collection are not available to a daemon, and it
  brings an async D-Bus client into the TCB. The kernel keyring needs neither.
* **An `exec` backend (`pass`, `op`)** — the most flexible. Rejected: the
  authority starts no process (TX010), and a helper's argv and environment are
  exactly where values leak.
* **age 0.12** — current. Rejected at measurement: 138 crates and pre-release
  ML-KEM dependencies.
* **Fingerprint on first use instead of at start** — reads nothing until
  needed, but leaves output unredacted until each secret's first use; the
  operator chose start.
* **Carry the value in the private message** — simpler; rejected because a
  message is logged, retried, and decoded into strings nothing zeroes.
* **Redact with a regex engine** — rejected: a large dependency for a fixed
  set of shapes, and an unbounded matcher on attacker-controlled output.

## Revisit if

* M5 lands: attach `net.http` to the render (§12) and move modes B/C into the
  sandbox (§13); revisit mode C's grandchild inheritance there.
* M6 lands: decide mode D and approval binding over handles.
* A safe `mlock`/`MADV_DONTDUMP` becomes available without `unsafe`.
* age ships a release without the localisation stack, or 0.12's dependencies
  become stable.
