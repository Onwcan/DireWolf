# Roadmap

Dependency-ordered. Every milestone has an objective, dependencies, deliverables, acceptance criteria, tests, adversarial tests and explicit deferrals.

**Rule: no milestone is complete until its adversarial tests pass.** Not "implemented, hardening later" — the hardening is the deliverable.

## Timeline, honestly

A scope freeze without a time axis is a list, not a freeze. Independent review estimated the Rust kernel at **33–40 k lines against a stated 18–25 k**, with the underestimate concentrated in `dwk-net` and the CLI, and put V1 at **24–30 calendar months for three experienced engineers** — M3 through M6 serialise hard, and the "adversarial tests gate the milestone" rule adds roughly 30 % that no one's estimate includes.

We accept that estimate rather than defending the original. The implications are stated rather than absorbed silently:

- **V1 is a ~2-year project for a small team**, not a 12-month one.
- The riskiest assumption — that per-tool-call kernel mediation is both fast enough and *tolerable enough* — was previously first measurable at M17, roughly two years in. That is the worst property a roadmap can have, and **M3.5 exists to fix it.**
- Milestones most likely to slip: **M5** (sandbox *and* egress proxy — two products in one), **M4** (three platforms × path canonicalisation; the Windows column alone is a milestone), **M9** (crash-injection harness across a process boundary), **M2** (Rust data-carrying enums → JSON Schema → typed Python is not plumbing).
- **`evals/` had no owning milestone** while being a merge gate from M3 onward. It is now M2.5.

### M2.5 · Evaluation harness — **COMPLETE**
**Deps:** M2. Runner, fixture repos, recorded-response replay mode, mock `ExecutionEnvironment`, scoring, statistics, and the fault-injection harness that can pause a named process at a named state. **Acceptance:** the security suite's deterministic subset runs in < 5 min on a hosted runner. A merge gate with no builder is not a gate.
**Delivered:** `evals/` — deterministic discovery with stable identifiers, versioned JSONL results plus a human summary, per-suite scoring (no single score), Wilson intervals for repeated runs, a reviewed baseline that CI never rewrites, provenance-checked fixtures, recorded-response replay with no provider anywhere, the hostile-DWKP and compatibility suites over the real decoder, a fault-injection harness proved against a dummy child process, a test-only execution-environment double that `dwcheck` PY003 keeps out of the product, an explicit pending model for suites that need M3+, and a `make eval-check` CI job.
**Result:** acceptance met. The gate subset runs in well under a minute locally (21 evals: 12 pass, 9 pending, 0 fail); the deliberate-failure meta-test proves a known-bad result fails the gate. **M2.5 proves nothing about authority**: every property that needs the kernel, the brokers, the sandbox, approvals or model egress is declared pending, and pending is never a pass.
**Deferred:** live-model evals and the recorded-response corpus (M7); real-process instrumentation of the authority daemon (M3); the vertical-slice measurements, which remain M3.5.

### M3.5 · Vertical slice — the risk-retirement milestone
**Deps:** M3, M4 (partial), M2.5. One tool (`fs.read`), one profile, one approval, end to end: CLI → runtime → kernel → sandbox. **Acceptance:** published measurements of kernel round-trip latency (p50/p99, side-effecting and not), cold start, and the approval count for one pinned realistic task. **This milestone exists to find out whether the product is viable before another eighteen months are spent on it.** If p99 or approval frequency is far outside target, the design changes here, not at M18.

---

## Ordering rationale

The brief's suggested order puts the tool registry (M6) before capabilities and policy (M7). We invert that: **the kernel comes first, before there is anything to constrain.** Retrofitting a privilege boundary is the mistake this whole architecture exists to avoid, and a tool registry built against an in-process check will encode that assumption everywhere.

We also pull **events and the run state machine (M5) before the agent kernel (M4)**, because the loop should be built on top of a durable state machine rather than having one bolted on afterwards.

```
M0 architecture ─ M1 foundation ─ M2 protocol+schemas
                                     ├─ M3 KERNEL CORE (policy, caps, audit)
                                     │     ├─ M4 brokers (fs, exec, secrets)
                                     │     │     └─ M5 sandbox
                                     │     └─ M6 approvals + budgets
                                     └─ M7 providers + model egress
                                           └─ M8 storage + events + run FSM
                                                 └─ M9 agent loop
                                                       ├─ M10 tools
                                                       ├─ M11 context
                                                       ├─ M12 artifacts
                                                       ├─ M13 memory
                                                       ├─ M14 subagents
                                                       ├─ M15 task graph
                                                       ├─ M16 MCP
                                                       └─ M17 CLI + doctor
                                                             └─ M18 V1 HARDENING ── V1.0
```

---

## Phase 1 — Foundation

### M1 · Repository foundation — **COMPLETE**
**Deps:** M0. **Deliverables:** monorepo layout (`crates/` × 3, `runtime/`, `tools/dwcheck/`, `schemas/`, `tests/architecture/`); Rust workspace + Python `uv` workspace, both locked; `make dev` / `make check`; CI (format, lint, types, boundaries, tests on three platforms, `cargo-deny`, `pip-audit`, release build); **Apache-2.0** ([ADR-0030](adr/0030-licence-apache-2.0.md)); `CONTRIBUTING.md`; boundary rules as data in `architecture.toml`, enforced by `dwcheck` ([ADR-0031](adr/0031-repository-layout-and-boundary-enforcement.md)).
**Acceptance:** met. `make dev` and `make check` pass; every declared boundary rule is proved to reject a deliberate violation; every quality gate is proved to reject a bad fixture; the Rust workspace has zero third-party dependencies and no `unsafe`.
**Deferred:** release automation, containers, secret-scanning tooling (GitHub push protection is the M1 mechanism), a PR-body review guard.

### M2 · Protocol and schemas — **COMPLETE**
**Deps:** M1. **Deliverables:** `dwk-proto` types; JSON Schema emission; Python codegen; canonical JSON (RFC 8785); envelope + versioning; framing; event schema registry.
**Acceptance:** round-trip property tests in both languages; **DWKP rejects unknown fields and unknown operations** (and duplicate keys; keys colliding under Unicode normalisation are undeclared members, which is the same rejection by a mechanism that needs no Unicode table — [ADR-0034](adr/0034-protocol-depends-on-no-unicode-database.md)); **DWCP preserves unknown fields**; **the event log retains unknown events verbatim** — three separate tests, per [ADR-0023](adr/0023-dwkp-strict-schema.md), not one blanket assertion; schema-drift CI gate; parser fuzzed ≥ 1 h clean.
**Adversarial:** malformed frames, oversized frames, depth bombs, duplicate keys, non-UTF-8.
**Delivered:** `crates/dwk-proto` — bounded framing, a strict JSON lexer, RFC 8785, the envelope and version negotiation, DWKP/DWCP/event message types, and the DWKP operation inventory (4 operations defined on the wire, 16 reserved with no wire form; [DWKP_OPERATIONS.md](DWKP_OPERATIONS.md)); `tools/protogen` → `schemas/` → `scripts/gen_proto_python.py` → `runtime/src/direwolf/proto/`, over a standard-library wire layer; `make schema` / `make schema-check` and a required CI job; shared golden vectors with a V8 oracle, run by both languages; property tests in both languages; four fuzz targets under libFuzzer and a stable mutation harness, with a weekly and pull-request fuzz workflow; `dwcheck` RS008/RS009/TX002 and dev-dependency-aware RS004/RS006 for the TCB-destined `dwk-proto`; [ADR-0032](adr/0032-wire-contract-framing-strict-json-and-jcs.md) (wire contract, JCS as the one canonical encoding) and [ADR-0033](adr/0033-protocol-source-of-truth-and-tcb-dependencies.md) (source of truth, TCB dependencies).
**Result:** acceptance met. The three compatibility behaviours are separate tests in each language; both languages agree on every shared vector; generation is deterministic and drift fails CI; the parser was fuzzed for **1 h per target with libFuzzer** (cargo-fuzz 0.13.2, AddressSanitizer, debug assertions; `frame_decoder`, `dwkp_decode`, `canonical_roundtrip`, `envelope_version`; ~322 M executions in total) with **no crash, timeout or leak**, plus 1 h of the stable mutation harness (not coverage-guided) with no failure — on Linux (WSL2), 2026-09-15.
**Deferred:** every protocol *semantic* — transport, peer credentials, epoch fencing, lease expiry, dedupe (M3, M8); encoding the approval binding and response MAC (M6, JCS per ADR-0032); DWWP; a maintained secret scanner (evaluated, revisited at M4 — [CONTRIBUTING.md](../CONTRIBUTING.md) "Secrets"); `cargo deny` over `fuzz/Cargo.lock`; verification of bit-for-bit reproducible builds; aligning the Python and Rust Unicode database versions.

---

## Phase 2 — The kernel

### M3 · Kernel core: policy, capabilities, audit — **COMPLETE**
**Deps:** M2. **The most important milestone in the project.**
**Decomposed** into M3a (architecture decisions and wire forms — [ADR-0035](adr/0035-m3-authority-dependency-set.md), [ADR-0036](adr/0036-m3-authority-operations-and-the-capability-wire-form.md); `AdmitRun` carries a mandatory idempotency key, a wire decision is `ALLOW` or `DENY` until M6 can honour a third, and an authority-state refusal is a typed message distinct from both a protocol error and a policy denial), M3b (capabilities and attenuation — the typed vocabulary, the `⊑` lattice, attenuation with no widening path, and the declared-vs-canonical resource split of [ADR-0037](adr/0037-capability-specifications-and-canonical-authority-identities.md)), M3c (the policy engine -- two evaluation phases rather than one, a strict bounded TOML loader, closed typed predicates, reasons and obligations, `extends` restricted to a composition that cannot widen, three shipped packs with adversarial fixture suites, and the 300-rule target measured at a p99 of 3.6 us; [ADR-0038](adr/0038-policy-evaluation-phases-and-composition.md)), M3d (durable authority state -- `kernel.db` in a private state directory, epochs fenced across restarts, leases held by a connection rather than a uid, `AdmitRun` idempotency recorded forever and checked after the fence -- replayed while the run is live, `ADMISSION_ENDED` once it has ended ([ADR-0040](adr/0040-m3d-reconciliation-admission-across-tenures-and-undecidable-proposals.md)) -- kernel-owned policy inputs and a stored, content-derived policy revision, and a hash-chained `audit.log` written through a transactional outbox with a recovery rule for every crash window; [ADR-0039](adr/0039-durable-authority-state.md)) and M3e (the real authority process boundary -- a Unix-domain DWKP server whose peers the kernel identifies before a byte is read, one fresh lease holder per connection, a handshake-first strict transport delegating every request to M3d, and hostile real-process evaluations as the M3 merge gate; [ADR-0041](adr/0041-m3e-authenticated-dwkp-transport.md)). Each stage is verifiable on its own; the acceptance criteria below are the milestone's, not any one stage's.

M3c is also where the authority's third-party dependency closure stops being
empty: five crates, all of them the TOML parser chain, pinned exactly and with
no proc-macro and no native code. M3d adds SQLite and SHA-256: fifteen more
linked crates, among them the 269,376-line SQLite C amalgamation, and five
build-only crates reviewed in a list of their own. M3e adds `rustix`, the
last of [ADR-0035](adr/0035-m3-authority-dependency-set.md)'s set, for peer
credentials -- Linux only, with `linux-raw-sys` beneath it; the exact gate's
union grows to 25 runtime crates because it must also name `errno`,
`windows-sys` and `windows-link`, which no supported build links
([ADR-0041](adr/0041-m3e-authenticated-dwkp-transport.md) §14).

M3d's acceptance evidence is `make authority-state-evidence` (real files:
store refusal and quarantine, fencing, admission, both gates, the audit chain
and its verifier, crash windows A--G in process and in a killed child, and
contention) and `make authority-write-probe`, which attempts the runtime's
forbidden writes as a second operating-system user and reports NOT EXERCISED
rather than passing where no second user exists. What M3d does **not** deliver
is a decision about a proposed action over DWKP -- `QueryAuthority` refuses one
with `NO_CANONICAL_ACTION` until M4 can build the complete canonical action
policy decides on -- nor anything reachable from outside the process.

**M3e delivers the boundary** ([ADR-0041](adr/0041-m3e-authenticated-dwkp-transport.md)): `dwkd-authority serve`,
Linux only, on a Unix-domain socket whose name the runtime cannot remove or
replace; the kernel's peer credentials checked against the operator's uid list
before a byte is read; one fresh lease holder per accepted connection;
handshake first; the production decoder; every request to the M3d dispatcher
unchanged; bounded connections, frames, deadlines and writes; a poisoned store
that stops serving; and transport refusals audited, rate-limited. Its evidence
is `make authority-transport-evidence` -- the real binary, a real socket, a
client in another process, a real second OS user, `SIGKILL` and restart, a
hostile client -- and M3's five evaluations, now active and gating
(`authority-security`). The cross-uid property and the runtime-write probe need
two identities: CI's Linux jobs provide `nobody`, and a one-user workstation
reports them NOT EXERCISED. That hosted run is green
([CI run 35833026692](https://github.com/Onwcan/DireWolf/actions/runs/35833026692),
every job including the cross-uid evidence and the strict M3 eval gate):
**M3 is complete.** M3 itself provides no canonical filesystem resource (M4a's),
no `ToolInvoke`, no execution, no broker effect, no sandbox, no approvals and
no model provider.
**Deliverables:** capability grammar + ⊑ lattice + attenuation; policy engine + TOML rule loader + explanation; three shipped profiles with fixture suites; hash-chained audit; **`dwkd-authority`** DWKP server with peer credential verification and **strict schema rejection** ([ADR-0023](adr/0023-dwkp-strict-schema.md)); epoch fencing (kernel is the epoch authority); `kernel.db` holding **every policy input** ([ADR-0028](adr/0028-policy-input-ownership.md)); the `dwkd-authority`/`dwkd-broker` split and the per-invocation authorisation format ([ADR-0018](adr/0018-authority-broker-split.md)).
**Acceptance:** policy p99 < 200 µs at 300 rules; every decision carries `rule_source`; audit chain verifies; runtime user cannot write `kernel.db` (verified by attempting it).
**Tests:** property tests for all eight lattice properties ([CAPABILITIES.md](CAPABILITIES.md) §3); 10⁶ generated delegation chains, zero escalations; policy fixtures including negative cases.
**Adversarial:** the **hostile DWKP client suite** ([EVALS.md](EVALS.md) §3) — a client that lies in every policy-input field, replays, reorders, omits, skips preconditions, presents stale epochs, and drives every operation directly. Plus forged and replayed tokens, socket impersonation from another uid, policy files with widening `extends`, capability synthesis attempts, and DWKP schema violations (unknown fields, unknown operations, duplicate keys, NFC-colliding keys).
**Deferred:** DSL, distributed policy.

### M4 · Brokers: filesystem, exec, secrets — **COMPLETE** (M4a–M4e complete; see the closure note below)
**Decomposed** ([ADR-0042](adr/0042-m4a-canonical-filesystem-resolution.md) §1) into M4a (the canonical filesystem resource foundation: operator-bound workspace roots pinned by identity, one resolver, canonical identities and checked handles, Linux `openat2` resolution, the portability contract, real-filesystem adversarial evidence), M4b (the private authority → broker channel, single-use per-invocation authorisation, the first `ToolInvoke` and `CanonicalPreview` wire forms, admission resolving filesystem capabilities, `fs.read` end to end), M4c (the remaining filesystem broker operations and their retry and atomicity contracts), M4d (the exec broker: executable identity and hashing, argv normalisation, environment scrubbing, rlimits, descriptor hygiene) and M4e (the secret broker, the redaction index, secret-residue evidence and the final M4 gate). The acceptance criteria below are M4's; **M4 is complete only when all five parts are** — and all five are — and the M4 evaluations are activated by the last of them, M4e.

**M4a — COMPLETE** ([ADR-0042](adr/0042-m4a-canonical-filesystem-resolution.md)) resolves a declared path to the object beneath the run's pinned workspace root, or refuses: `/workspace` is a logical namespace bound by the operator, one per workspace and immutable; each component is opened with `openat2(RESOLVE_BENEATH | NO_SYMLINKS | NO_MAGICLINKS | NO_XDEV)` relative to the previous descriptor, its name verified against its directory (NFC required, never applied; a canonically equivalent sibling is an ambiguity), the chain re-verified, and the checked `O_PATH` descriptor kept for M4b. It performs no tool effect, adds nothing to DWKP, and leaves admission withholding filesystem and process capabilities. Its evidence is `make filesystem-canonicalization-evidence`: the production resolver against real symlinks, magic links, mount points, hard links, Unicode aliases and a replaced root, and six TOCTOU race campaigns that must return zero escape objects. Linux only; there is no fallback walker yet (ADR-0042 §5).

**M4b — COMPLETE** ([ADR-0043](adr/0043-m4b-private-broker-channel-and-brokered-fs-read.md)) performs the first effect, and only `fs.read`. `ToolInvoke` and `CanonicalPreview` have their first wire forms, each one typed call (`fs_read{path, max_bytes}`, at most 256 KiB, hexadecimal content). The authority fences, resolves the path beneath the pinned root (`O_PATH` only), derives `fs.read:<canonical path>?max_bytes=N&no_symlink_targets=true` from the resolver's canonical path, builds the complete canonical action (`HOST`, `byte_count`) and applies both gates; for an allowed action the intent is durable (schema 3, `tool_invocation`) **before** the file is opened read-only relative to its checked parent and proved by identity, and before the broker hears anything. `dwkd-broker` listens on one private socket, reads only from the authority's kernel-reported uid, issues a channel per connection and executes one authorisation per connection — no MAC, no key, no token — with exactly one descriptor sent by `SCM_RIGHTS` (zero or several are refused, every one closed, nothing read), which it re-proves (read-only, regular, same `(dev, ino)`) before a `pread` that never reads past the bound (`eof_observed` is conservative). The authority records the outcome and raises taint to `LOCAL_UNVERIFIED` before it answers; an interrupted invocation is recorded as such by the next start. Admission resolves every concrete `fs.read` path in every mint term through the same resolver; stored grants are re-read, never resolved again; every other filesystem verb and `process` stay withheld. The shipped policy packs deny every read (an unevaluable `~/.ssh` rule: no home anchor yet); a deployment reads files with an operator policy. Evidence is `make broker-fs-read-evidence`, a required Linux CI job with three genuine identities (authority, broker, hostile runtime); locally the three-identity half is NOT EXERCISED. Its hosted three-identity run passed at the M4b commit.

**M4c — COMPLETE** (the required hosted M4c gate passed in CI run 36063242388) ([ADR-0044](adr/0044-m4c-filesystem-operations-plans-and-atomic-mutation.md)) adds `fs.list`, `fs.search`, `fs.stat`, `fs.write`, `fs.patch`, `fs.move` and `fs.delete` (`fs.create` is a capability verb, not a tool). Version 2 of the tool messages is a closed sum of eight typed calls with a mandatory idempotency key on the invocation; version 1 is unchanged and every request is answered in its own version. A call becomes a **canonical plan** — a creating write is `fs.write` and `fs.create`, a move `fs.delete` on its source and `fs.create` on its destination, a patch `fs.read` and `fs.write` — and both gates decide every action; the call proceeds only if all allow, and an obligation this build cannot enforce denies. Targets are existing objects or **vacant names** (a checked parent and one validated component), two types; admission resolves `fs.read`, `fs.list`, `fs.stat`, `fs.write`, `fs.create` and `fs.delete` scopes through the resolver, a vacant scope only for the verbs that create. The broker acts on one validated name in a directory it was handed, never in place: a new file written and synced in a private `0700` staging directory, then `RENAME_EXCHANGE` or `RENAME_NOREPLACE`, every directory it changed synced before the next step; a move is one `NOREPLACE` rename; a delete stages, proves, then unlinks. It checks the name immediately before and after each change and undoes — provably, or else `UNKNOWN` — a change that reached any object it did not prove; Linux has no compare-and-swap of a name against an inode, so the permission model keeps untrusted writers (the runtime's uid among them) out of a write-enabled workspace, and a directory writable by every user is refused. Every staging directory is recorded with its intent and reclaimed only when it provably holds the broker's own uncommitted data, and only beneath the root re-pinned by its fingerprint; one holding a workspace object or the evidence of an effect is retained and identified. A patch's edits insert at most 256 KiB together, derived from the unchanged 1 MiB frame. Changing names needs directory write permission for the broker's own uid — **ambient authority the operator grants** on a write-enabled workspace, stated as such; without it every mutation is `WRITE_DENIED`. Schema 4 persists each tool's retry class (`fs.move`, `fs.delete` non-retryable) and records an effect that is not proved as `UNKNOWN`, which the authority never performs again, live or on restart. Evidence is `make filesystem-operations-evidence`, a required Linux CI job: every tool end to end, previews, compound denials, keys, links, symlinks, the race and crash campaigns, the hostile private-protocol cases, and the write permission model on three genuine identities and a write group; locally the three-identity half is NOT EXERCISED.

**M4d — COMPLETE** (the required hosted M4d gate passed in CI run 36215940771, attempt 2: the final aggregate succeeded, with the three-identity process evidence on authority uid 1001, broker uid 999 and runtime uid 65534) ([ADR-0045](adr/0045-m4d-process-execution-broker.md)). It adds `process.exec`, `process.status` and `process.kill` as version 3 of the tool messages (versions 1 and 2 unchanged), decided as `process.exec`, `process.inspect` and `process.signal` on an **executable identity**: an absolute host path — no `PATH` search — resolved by following at most 32 symlinks to one regular ELF file, which must be changeable only by root or the authority (owner, mode, directories, no set-id, no file capabilities, no network or user-space filesystem), hashed with SHA-256; scripts are refused. `argv[0]` is the canonical path; at most 128 arguments of 8 KiB, 64 KiB in all, each passed as exactly its bytes; `argv_allowlist` binds the first argument and the kernel classifies argv as `SAFE` or `REINTERPRETING` for `when.argv_safe`. The intent (and a `LAUNCHING` process row, schema 5) is durable before any descriptor that could launch exists. The broker re-proves the executable and working-directory descriptors — identity, trust attributes, ELF magic, SHA-256 through the descriptor — and a helper (its own binary, spawned with an empty environment, stdin `/dev/null`, its own process group) applies resource limits, `fchdir`s, arms the parent-death signal, sets `no_new_privs`, refuses if any descriptor would survive, and executes the re-proved descriptor with `execveat(AT_EMPTY_PATH)` — no path, no shell, no `/proc/self/fd`, no `unsafe`; a close-on-exec control socket proves the target, not the helper, was executed. Both streams are drained concurrently to a bound (`max_output_bytes` is the combined bound, at most 256 KiB), the wall clock is 600 s, kill is SIGKILL by pidfd and process group, the table holds 8, and a restarted broker is a new generation whose predecessor's handles are refused. **Every process would run on the host with the broker's privileges, so a launch needs the operator's opt-in and a per-invocation approval; approvals are M6's, so no production build launches anything** — `workspace_exec_hygiene` and `network_deny` are denied as unenforceable on the host. Evidence is `make process-broker-evidence`, a required Linux CI job: the released daemons refusing every launch, the real broker starting real targets (re-proof, races R1–R12, output, kill, table, crash points, restart), hygiene override attacks with the real `git` and `python3`, the authority's state machine against a fake broker (labelled so), and three genuine identities; locally the three-identity half is NOT EXERCISED. At M4d's close M4 was still incomplete, with no secrets and no M4 evaluation active until M4e; M4d itself adds no sandbox (M5) and no approvals (M6).

**M4e — COMPLETE** (the required hosted M4e gate, which is also the final M4 gate, passed in CI run 36390815504, attempt 2: every job and the final `ci` aggregate succeeded) ([ADR-0046](adr/0046-m4e-secret-handles-backends-injection-and-redaction.md)). A secret is an **opaque handle** — an identifier, never a value, whose meaning is its current revision — declared in an operator metadata file read through a trusted-file opener and recorded, with no value, prefix or length, as append-only revisions in `kernel.db` (schema 6, with run bindings, an injection ledger and use counts). **Nothing returns a value**: no DWKP operation, no CLI command, no diagnostic, no administrator path; `secret.use` is a capability a containing action requires, never a tool, and the public protocol is unchanged. Admission, stored grants and replay read no backend (a per-thread counter proves zero reads). Backends: the Linux **kernel keyring** (exercised), the Windows Credential Manager (exercised by the crate's tests, never served), the macOS Keychain (**COMPILE-ONLY**), and **age** files (age 0.11.5, identity from the keychain; no DireWolf cryptography); `env` and `exec` backends are deferred. A value is read only after `secret.use:<handle>` passed both gates and the intent is durable; it leaves the authority as the read end of a pipe on **private protocol version 4**, once, and the authority's copy is zeroed first. Mode A renders the header in the broker and drops it — **no egress consumer until M5's `net.http`**; modes B and C are a **secret injection primitive** exercised by the real broker and real targets, with no production caller (the selector refuses a host spawn) and mode C's descriptor measured as inherited by a grandchild; mode D is unreachable until M6. Consumer binding is by executable identity (path and SHA-256), origin binding by the endpoint grammar. `fs.read` content and process output are **redacted** on raw bytes before encoding — exact values by a keyed in-memory fingerprint, nine known shapes — and an injected launch's streams while they are drained. Both daemons set `RLIMIT_CORE` to 0 and are non-dumpable (`--allow-dumpable` is a logged development switch); `mlock` and `MADV_DONTDUMP` are not implemented. Crash points R1–R10 leave no durable plaintext and never inject twice; an intent left open by a crash is `UNKNOWN`. The authority's linked closure grows from 27 reviewed crates to 98 on Linux (ADR-0046 §25). Evidence is `make secret-broker-evidence`, a required Linux CI job that fails on zero cases: the runtime's address space read after it read files holding live values through the real daemons, residue in both daemons after they handled one, core refusal, durable-state scans, the crash campaign, and three genuine identities with root reading all three processes' memory; locally the three-identity and core-file halves are NOT EXERCISED. The M4 evaluations — `path-traversal`, `exec-mediation`, `secret-boundary` — are active in the `m4-security` gate suite, and the final `ci` aggregate requires every M4a–M4e job and the eval gate. **M4 — COMPLETE.**

**M4 closure — COMPLETE (2026-09-28).** Every part passed its required hosted gate: M4a
and M4b at their own commits (above); M4c in CI run
[36063242388](https://github.com/Onwcan/DireWolf/actions/runs/36063242388); M4d in CI run
[36215940771](https://github.com/Onwcan/DireWolf/actions/runs/36215940771), attempt 2; and
M4e, with the final M4 aggregate, in CI run
[36390815504](https://github.com/Onwcan/DireWolf/actions/runs/36390815504), attempt 2 --
all five M4 evidence jobs, the M3 transport evidence, the three-platform tests and the
evaluation gate, with the `m4-security` evaluations (`path-traversal`, `exec-mediation`,
`secret-boundary`) active and passing. The evaluation harness's own unit test runs only
the harness's deterministic suite; the security suites gate, unscoped, in `make
eval-check`. What M4 does **not** provide is stated once, here: no sandbox or execution
environment and no network path, so secret injection has no consumer (M5); no approvals,
so no production build launches a process (M6); no model provider (M7); no runtime (M9);
and serving on Linux only. **M5 is in progress: M5a and M5b are complete (see M5 below).**

**Deps:** M3. **Deliverables:** canonicaliser (NFC, `openat2` + fallback walker, inode identity -- M4a delivers `openat2` and identity; a fallback walker needs its own ADR); fd-relative fs ops; exec broker with env scrub, rlimits, argv normalisation, executable hashing; secret broker with keychain/age backends and injection modes A–C; redaction index.
**Acceptance:** no path string reaches policy; every op uses the fd it checked; no secret in argv, ever.
**Adversarial:** the full path-traversal set ([EVALS.md](EVALS.md) §3) including Unicode normalisation and TOCTOU swap races in a tight loop; secret-in-output detection; core-dump inspection for secret residue.
**Deferred:** remote fs, Windows-native hardening beyond the fallback walker.

### M5 · Sandbox — **IN PROGRESS** (M5a complete, hosted acceptance passed; M5b complete, hosted acceptance passed; M5c implemented and validated locally, owner review and hosted acceptance pending; M5d–M5e not started)

M5 is two products in one (a sandbox *and* an egress proxy), so it is decomposed like M4
([ADR-0047](adr/0047-m5a-oci-execution-environment-and-measured-assurance.md)). The
milestone-level contract below the slices is unchanged; M5 is complete only when every
slice is, with M5e's gate.

#### M5a · OCI foundation and measured assurance — **COMPLETE**

M5a is complete: the required hosted `sandbox-foundation` job passed on the committed tree in CI run 37154862816.

[ADR-0047](adr/0047-m5a-oci-execution-environment-and-measured-assurance.md).
**Deps:** M4. **Deliverables:** the broker's `ExecutionEnvironment` abstraction (`oci`;
`local` joins at M5d); the `oci-strict` profile as data (`dwk-sandbox-profile`), applied
through the runtime client the authority resolved and hashed, run by the M4d launch helper
with typed argv and a broker-owned empty configuration; DireWolf's own seccomp allowlist
(namespace-free `clone`, `clone3` → `ENOSYS`, `AF_VSOCK` refused); a digest-pinned static
probe with a closed PASS/FAIL/UNOBSERVABLE report; host-side measurement from the
runtime's record; effective = min(declared, measured), no score, refusal on any failed or
unobservable invariant; private protocol version 5 (prepare, measure, destroy, list — no
runtime flag on the wire); schema version 7 (the environment ledger, intent before effect,
one live environment per run); crash windows W1–W7; reconciliation by exact label and
durable record; the test-only `NO_NETWORK` topology. **No public route; production
sandbox execution is not reachable.**
**Acceptance:** `make sandbox-foundation-evidence` on a real OCI runtime — every hard rule
measured PASS from both vantages on a real container; every weakened profile FAILs its
invariants; every tampered probe refused; foreign containers survive; exact orphan
reaping; temporary state does not persist; the authority→broker→runtime lifecycle and its
crash windows; NOT EXERCISED fails. Required hosted job `sandbox-foundation` and gated eval
`m5a-sandbox-foundation`.
**Adversarial:** writable root, root user, privileged, the runtime socket mounted, a
capability added, `no-new-privileges` off, seccomp unconfined or the runtime's default,
host PID/IPC/network, a mutable tag, an extra device, resource limits dropped; a changed,
substituted, malformed, truncated, over-long, extra-field or hanging probe; copied labels,
copied run labels, name-only and partial-label containers; drift after preparation.
**Deferred:** every workload (M5d), any network (M5b), `local` confinement (M5d).

#### M5b · `PROXY_ONLY` topology and CONNECT proxy — **COMPLETE**

M5b is complete: the required hosted `sandbox-egress` job and the gated `m5b-sandbox-egress`
eval passed on the committed tree (`b8cfc5e`) in CI run 37373469608, attempt 2, with M5a's
`sandbox-foundation` job still green. The first hosted run (37243649970) lost the probe's
report in the weakened network cases, where the runner's routes led to silent destinations;
the probe's network checks were bounded before acceptance
([NETWORK_SECURITY.md](NETWORK_SECURITY.md) §1). Locally: Docker Desktop 29.8.1 in WSL2,
8 broker tests and 1 authority test, all 104 cases, nothing left behind.

[ADR-0048](adr/0048-m5b-proxy-only-topology-and-connect-proxy.md).
**Deps:** M5a. **Deliverables (as built):** the `PROXY_ONLY` network
([ADR-0024](adr/0024-sandbox-network-topology.md), realised as ADR-0048 §2): the runtime's
`none` network, `169.254.7.1/32` added to its loopback by a one-shot setup container (the
one DireWolf container with a capability, NET_ADMIN, gone before any workload), and an
unprivileged relay in the same namespace forwarding each connection to a broker socket
mounted into it alone, in a directory whose ACL lets only the relay's uid reach it; the
broker's opaque CONNECT proxy — a strict bounded parser, the run's own exact
`network.https` grants, one pinned resolution on the host, the whole answer
judged by the IP guard (a mixed answer refused outright), the TLS server name agreeing with
the CONNECT host before anything is dialled (ECH refused, TLS only), environment-wide byte
budgets and a tunnel limit at the socket — with no TLS termination, no CA, no trust-store
change and no credential injection; seven new measured invariants (49 in all); private
protocol version 6; labels schema 2 with roles; a broker restart that fails closed; the
evidence-only fixture resolver (`--allow-evidence-egress`). No public route; no workload.
**Acceptance:** `make sandbox-egress-evidence` on a real OCI runtime — from a `PROXY_ONLY`
environment no route exists to any address but the proxy endpoint (every direct TCP, UDP,
DNS, raw, packet, ICMP and virtual-socket attempt refused, with its errno and mechanism);
tunnels through the real relay obey the grant, guard, pin, server name and budgets; every
weakened or drifted topology detected; crashes, restart and foreign resources exact; NOT
EXERCISED fails. Required hosted job `sandbox-egress` and gated eval `m5b-sandbox-egress`.
**Adversarial:** raw, packet and ICMP sockets; direct DNS to external, runtime-embedded and
local-stub resolvers; other peers (link-local neighbour, bridge host, Desktop host, LAN,
metadata, IPv6, IPv4-mapped, NAT64); proxy variables ignored, redirected or pointed at
another peer; address literals, ports and hosts not granted; blocked, mixed, failing,
timing-out and rebinding answers; SNI mismatch, missing, ambiguous and ECH; plain HTTP; a
bridge network, a missing relay, removed proxy variables, a stopped relay, an extra peer, a
fake resolver in the namespace, a setup left running, the socket's directory opened to
other uids, a tampered relay; any uid but the relay's at the broker's socket; and the
fronting residual — carried unseen, bounded by the budget.
**Deferred:** `net.http` (M5c); a workload using the proxy (M5d).

#### M5c · `net.http`, SSRF and redirect policy, credential egress — **IN PROGRESS** (implemented and validated locally; owner security review and hosted acceptance pending)

M5c is implemented in the working tree and its local gates pass, its closeout review
included; it is complete only when its owner accepts
[ADR-0050](adr/0050-m5c-kernel-performed-net-http-ssrf-redirects-and-credential-egress.md)
(Proposed) — its decisions D1–D12, D11's residual among them — and the required hosted
`net-http` job, every multi-identity half and the gated `m5c-net-http` eval pass on the
committed tree.

**Deps:** M5b. **Deliverables (as built, pending acceptance):** ToolInvoke and
CanonicalPreview version 4 with the typed `net.http` call (no address, resolver, proxy,
timeout, trust material or credential value on the wire); one canonical URL parser shared
with the capability grammar (`dwk_proto::wire::url`); the address guard moved to
`dwk_proto::wire::guard` and run by the CONNECT proxy, by `net.http`'s broker side and by the
authority; the authority's per-hop pipeline — canonicalise, grant, resolve only a covered
host, judge the whole answer again, policy for every pinned address, budgets, durable
intent, exchange, outcome, taint, redaction, redirect — with schema version 8
(`net_request`, `net_hop`, `net_idempotency`), crash windows N1–N4 and per-run budgets that
are never refilled; private protocol version 7 (`broker.http_resolve`,
`broker.http_exchange`, `broker.http_credential_exchange`; `broker.secret_egress`
retired); the broker as the HTTPS client (`rustls` with `ring` and Mozilla's roots, the
sans-I/O `ureq-proto` engine, pinned dials only, strict framing, no decoding, deadlines,
never following a redirect); mode A's consumer — a credential attached only at the
request's first origin, each hop its own decided and recorded `secret.use`, through a
fresh one-shot pipe, and an echo of it taken out by the broker before anything of the
response is encoded. The `PROXY_ONLY` tunnel is untouched.
**Acceptance:** `make net-http-evidence` (no internet: real TLS origins, the fixture
resolver, the released broker) — 166 required cases across SSRF and DNS, HTTP and
redirects, TLS, secrets and residue, lifecycle and budgets; `make net-http-mutations` —
six weakened safeguards each caught; M4e's secret evidence moved to `net.http` with every
case kept, and an echoed credential measured nine ways (178 secret cases); required hosted
job `net-http` (also under CPU contention) and gated eval `m5c-net-http`.
**Adversarial:** every guarded range and its IPv4-mapped, NAT64, 6to4 and Teredo shapes; a
mixed answer; metadata names and addresses; address literals in every spelling; userinfo,
case, trailing dots, encoded dot segments, backslashes, port confusion; rebinding within and
across requests; redirects to blocked, mixed, metadata, ungranted and downgraded targets,
loops, the sixth hop, a body resent; malformed, encoded, oversized, header-bomb,
close-delimited and silent responses; wrong-name, expired, self-signed and untrusted
certificates, and the test authority under production trust; a credential across origins,
in the request, echoed back; crashes after resolution, intent and exchange; reused keys;
spent budgets; the shipped packs and taint.
**Residual, pending the owner's acceptance:** an origin that echoes the credential can
leave it in the broker's TLS and HTTP libraries' freed memory (ADR-0050 §20, D11) — never
in a message, the audit, the authority or the runtime's answer — measured and reported.
**Deferred:** package-manager routing (M5d/M5e); model egress (M7); approvals (M6).

#### M5d · Production sandboxed `process.exec` — **NOT STARTED**

**Deps:** M5a, M5b. **Deliverables:** `process.exec` in an environment through the
authority's gates; secret modes B/C wired to sandboxed processes; `workspace_exec_hygiene`
enforceable in the sandbox; the workspace ownership model; the workload wall clock and
disk quota; the `local` environment's confinement; lifecycle integration with runs.
**Acceptance:** a real workload runs only in a measured environment at its required level.
**Adversarial:** full escape suite from a workload; resource exhaustion; persistence.
**Deferred:** approvals for host execution (M6).

#### M5e · The M5 adversarial gate and closeout — **NOT STARTED**

**Deps:** M5a–M5d. **Deliverables:** the complete escape, SSRF and persistence suites as
merge gates; weakened-profile closure for `PROXY_ONLY`; package-manager acceptance
(`pip install`, `npm install` against allowlisted and non-allowlisted registries).
**Acceptance:** the milestone contract below, in full; `M5` joins the available milestones.
**Adversarial:** everything above, together.
**Deferred:** gVisor/Kata/Firecracker, SSH, remote workers.

#### The M5 contract

**Deps:** M4. **Deliverables:** `ExecutionEnvironment` trait; `oci-strict` profile with `PROXY_ONLY` networking ([ADR-0024](adr/0024-sandbox-network-topology.md)); supervisor with lifecycle, limits, reaping, and **re-attach by run-id label** after a container-runtime restart; `local` environment behind opt-in; `AssuranceLevel` surfaced to policy; CONNECT proxy with IP guard, DNS pinning, SNI/host agreement and byte budgets; kernel-performed `net.http`; **measured assurance** ([COMPETITIVE_ANALYSIS.md](COMPETITIVE_ANALYSIS.md) §17 G2) -- an authority-provided, read-only, digest-checked probe run inside each environment checks every hard rule of [SANDBOX.md](SANDBOX.md) §2 as PASS or FAIL (no weighted score), the effective `AssuranceLevel` is the lower of declared and measured, and a failed required invariant refuses the environment and is audited.
**Acceptance:** defaults from [SANDBOX.md](SANDBOX.md) §2 verified at runtime, not merely configured -- by the measured-assurance probe, and a **weakened-profile meta-test for each hard rule** (a bridge network, a writable root, an added capability, unconfined seccomp, a mounted container socket) must make the gate fail; from a `PROXY_ONLY` sandbox, **no route exists to any address but the proxy endpoint** (verified by attempting direct connections and direct DNS); a real package manager (`pip install`, `npm install`) succeeds against an allowlisted registry and fails against a non-allowlisted one; orphan reaping exact; the opaque tunnel's residuals, domain fronting through an allowlisted shared host among them, are stated in [NETWORK_SECURITY.md](NETWORK_SECURITY.md) and bounded by the byte budget (G7).
**Adversarial:** full escape suite; full SSRF suite; resource exhaustion; cross-run persistence attempts; a configuration that looks hardened while the running environment differs; a tampered or substituted assurance probe; a fronted request through an allowlisted shared host, which must stay within its byte budget and connection count.
**Deferred:** gVisor/Kata/Firecracker, SSH, remote workers.

### M6 · Approvals and budgets
**Deps:** M3. **Deliverables:** binding hash; approval registry with scopes, expiry, single-use burn; standing grants with the 90-day cap and `require_untainted_run`; kernel-rendered approval prompts; hierarchical subtractive budget ledger; unattended degradation to DENY.
**Acceptance:** every property test in [APPROVALS.md](APPROVALS.md) §10; burn is atomic under concurrency; prompts contain no model-authored text in the authoritative region.
**Adversarial:** replay, substitution, drift (file/DNS/binary swap), laundering parent↔child, environment swap, fatigue spam, budget amplification via fan-out.

---

## Phase 3 — The runtime

### M7 · Providers and model egress
**Deps:** M3. **Deliverables:** `ModelProvider` interface; kernel model egress with credential injection, privacy-class enforcement, declarative usage extraction, streaming relay; router with health and circuit breakers; and **broad provider coverage**.

**Provider coverage** (a project-owner decision, 2026-10-07; nothing is implemented before M7). DireWolf is model-agnostic and must not trail the serious agent runtimes on provider breadth; the inventory it is measured against, read at the pinned snapshots, is [COMPETITIVE_ANALYSIS.md](COMPETITIVE_ANALYSIS.md) §7a. Every provider sits behind the same `ModelProvider` interface and the same kernel path ([ADR-0020](adr/0020-provider-request-path-v2.md)): the runtime proposes a typed `ModelCall` naming a provider profile and a model; `dwkd-authority` decides the origin, the privacy class and the credential; `dwkd-broker` renders the request from a declarative profile. Coverage is organised by protocol family, not by vendor -- a separate adapter only where protocol, authentication, streaming or metering semantics really differ:

| Family | Named targets | Shape |
|---|---|---|
| Native protocols | Anthropic; OpenAI; Google Gemini API | One adapter each: their request, streaming and usage semantics differ |
| Cloud model platforms | AWS Bedrock; Google Vertex AI; Azure OpenAI / Azure AI Foundry | One platform adapter each. Their authentication -- request signing, short-lived tokens minted from a service identity -- is a kernel-side credential mechanism, never something the runtime builds |
| OpenAI-compatible profiles | OpenRouter; Hugging Face Inference Providers; Groq; Mistral; DeepSeek; xAI; Together AI; Fireworks AI; Cerebras; SambaNova; Perplexity; Cohere | **One** reviewed OpenAI-compatible adapter; each service is a declarative profile (origin, authentication scheme, usage pointers, streaming dialect), admitted only after its compatibility is verified against its own documentation -- a service that needs more gets a native adapter instead |
| Local and self-hosted | **Ollama** (first-class); vLLM; LM Studio; self-hosted Hugging Face serving (Text Generation Inference, Inference Endpoints) | The OpenAI-compatible adapter against an operator-declared origin, or Ollama's own API where M7's ADR prefers it |

**Ollama remains a first-class local provider** (a project-owner requirement, recorded at M3e) -- no longer the only named local target. An Ollama model reference (`<ollama-model-ref>`: any reference the installed Ollama supports, a model name or a model:tag variant) is passed as **data and configuration**, and nothing matches, branches on or hard-codes a model name: `qwen3.8` in the example below is illustrative, and no model is special. **Hugging Face is a first-class target** (a project-owner requirement, 2026-10-07), both hosted and self-hosted: its Inference Providers router (OpenAI-compatible chat completions) and a self-hosted Text Generation Inference or Inference Endpoints deployment (its OpenAI-compatible Messages API). Neither is a privileged path: each is a profile behind the same model egress, origin binding, privacy-class enforcement, credential injection, metering and stream relay as every other provider.

**Breadth never buys authority.** Local use, like every other, must fit the privacy and model-authority model of [MODEL_ROUTING.md](MODEL_ROUTING.md) and [ADR-0020](adr/0020-provider-request-path-v2.md): the kernel performs the egress, the privacy class is kernel-derived ([ADR-0028](adr/0028-policy-input-ownership.md)), and a local endpoint is an origin like any other. No provider adapter, profile or SDK holds a credential, opens a socket or gets a privileged network path; a credential is injected only into a request to the origin it is bound to, and a cross-origin redirect never carries it. **Aggregators and cloud platforms route on their own side** -- OpenRouter, Hugging Face's router, a platform's model catalogue choose the backend that serves a request -- so the origin the kernel authorises is the aggregator's, policy counts whatever it forwards to as reached, and a `LOCAL_ONLY` run reaches none of them; a backend preference sent to an aggregator narrows a request and authorises nothing. **Health and failover are constrained routing**: a fallback is chosen only among the upstreams the run's policy already allows, at its privacy class, never from "any available vendor". Authentication a declarative profile cannot express is M7's own ADR to decide: it extends ADR-0020's profile format by review, or the provider is left out. **`--model` selects intelligence only**, for every provider. Provider and model choice never select or widen policy, capabilities, approvals, the sandbox, the privacy class, taint, standing grants or the authority profile.

**Acceptance:** no provider or model name outside `providers/` (TX001, CI gate); switching provider or model -- within a family and across families -- changes which model answers and nothing that decides authority; a `LOCAL_ONLY` run cannot reach a remote vendor, an aggregator or a cloud platform; a credential is injected only at the origin it is authorised for, and a cross-origin redirect cannot forward it; metering agrees with the usage each family's provider reports; every family's stream canonicalises through `CanonicalDelta`; router health and failover cannot escape the run's allowed upstreams or privacy class; at least one remote native provider, one OpenAI-compatible provider and one local or self-hosted provider work end to end, and the Hugging Face and Ollama paths are both exercised. The evidence is deterministic, recorded contract fixtures per family in ordinary CI; live calls to paid providers are optional integration jobs kept apart from it, never a pull-request requirement.
**Adversarial:** router asked to route to an unauthorised upstream; credential-to-wrong-endpoint; cross-origin redirect credential leak; an aggregator's fallback to a backend the policy excludes; a profile or a model reference crafted to select another provider or origin; a profile declared local whose origin is remote.

### M8 · Storage, events, run state machine
**Deps:** M2, M3. **Deliverables:** `runtime.db` schema + migrations + backup + corruption quarantine; event log + envelope + projections + rebuild; run lifecycle FSM + wait sets; session leases + fencing; idempotent ingress.
**Acceptance:** projections rebuild from scratch; corrupt handle quarantines and stops writing; two runtimes racing a session → exactly one writer, zero stale-epoch effects.
**Adversarial:** duplicate delivery ×3 → one run; corrupt pages injected; clock jumps.

### M9 · Agent kernel (the loop)
**Deps:** M7, M8. **Deliverables:** turn execution; streaming; tool-call dispatch with side-effect-class batching; cancellation and `DRAINING`; loop/repetition detection; checkpoints and resume with re-admission; `UNKNOWN` reconciliation; **runtime-identity network confinement** ([COMPETITIVE_ANALYSIS.md](COMPETITIVE_ANALYSIS.md) §17 G1) -- the runtime is launched with no network route: on Linux, Unix-domain sockets only (a seccomp filter or the service manager's address-family restriction) or an empty network namespace, with the authority socket its only peer. It needs no other: model egress is the authority's (M7).
**Acceptance:** all ~40 crash-injection points resume or fail closed with a specific question; no new side effects after `DRAINING`; from the **real runtime identity**, TCP, UDP, raw and packet sockets, DNS resolution and every connection except the authority socket fail, in a CI job on a genuine separate identity; a platform that cannot enforce the confinement reports reduced assurance rather than assuming it.
**Adversarial:** kill between intent and completion for a `NON_RETRYABLE` tool; cancel mid-write; infinite tool loop; a prompt-injected `socket()` and `getaddrinfo()`; an abstract Unix socket aimed at the broker; an inherited descriptor; a child process spawned to reach the network.

### M10 · Tool registry and core tools
**Deps:** M4, M5, M9. **Deliverables:** registry; the **18** core tools of the canonical inventory ([TOOL_SYSTEM.md](TOOL_SYSTEM.md) §3); output capping, structure-aware excerpting, sanitisation (Unicode TAG, bidi, ANSI, delimiter forgery); policy-driven tool visibility.
**Acceptance:** no tool exceeds its cap; excerpting deterministic and never splits a codepoint; denied tools' schemas absent from the request.
**Adversarial:** 500 MB output; binary output; output containing forged delimiters and nonce guesses; argument injection per tool.

### M11a · Static skills
**Deps:** M3, M11. Manifest parsing; content-hash verification; kernel-side skill registry and trust assignment; capability intersection at admission; progressive disclosure L0/L1/L2; resolution scoring.
**Acceptance:** a skill cannot widen a run's capability set (property test); a modified skill fails its hash and is `QUARANTINED`; the runtime cannot alter a skill's trust level (covered by the hostile-DWKP-client suite).
**Explicitly deferred:** synthesis, validation pipeline, registry, consolidation — all M25 ([SKILLS.md](SKILLS.md) §0).

### M11 · Context engine
**Deps:** M9. **Deliverables:** section ladder, budgeting, eviction, `ContextManifest`, trust fencing with per-run nonce, structured compaction with loss check, quarantined reader.
**Acceptance:** deterministic assembly (hash-asserted); prefix hash constant across 50 turns; P0 never evicted; digest fidelity ≥ 0.95 on the session corpus.

### M12 · Artifacts · M13 · Memory · M14 · Subagents · M15 · Task graph
**Deps:** M11 (M12), M12 (M13), M6+M11 (M14), M14 (M15).
**Highlights:** CAS with kernel-side creation and quarantine; FTS5 memory with RRF, explainability and the promotion gate; subagents with kernel-enforced attenuation, subtractive budgets, workspace isolation and the context firewall; DAG with fan-out/join, retry classes and compensation.
**M13 also adds** ([COMPETITIVE_ANALYSIS.md](COMPETITIVE_ANALYSIS.md) §17 G6) **recall-loop prevention** -- content recalled from memory is never re-extracted as a new candidate -- and **unattended-session gating** -- scheduled and subagent sessions produce no semantic-scope candidate without approval -- both decided from the authority's provenance record, never from a session label the runtime supplies.
**Acceptance:** zero untrusted promotions without approval, including through recall; zero cross-scope leakage; zero escalations across generated delegation trees; merge conflicts surfaced, never silently resolved.
**Adversarial (M13):** recall amplification; re-extraction laundering of a recalled untrusted item; a scheduled run writing memory; a runtime claiming an attended session.
**Deferred:** consolidation, embeddings, dynamic replanning, durable long workflows.

### M16 · MCP client
**Deps:** M10. Kernel-spawned sandboxed servers; untrusted descriptions; `toolset_hash` rug-pull invalidation; per-server capability grants.
**Adversarial:** malicious description; rug pull; oversized results; server attempting network without a grant.

### M17 · CLI and doctor
**Deps:** M9–M16. Full command surface; `doctor` verifying facts not settings, including `doctor --sandbox`, which reports M5's measured assurance; export/import; **`direwolf policy diff`** -- rule-level changes plus the decision delta computed by the same evaluator over the fixture corpus and recorded canonical actions (G4); **`direwolf security demo`** -- a zero-credential scripted hostile runtime that prints each attempt with the audit record that denied it (G5) ([COMPETITIVE_ANALYSIS.md](COMPETITIVE_ANALYSIS.md) §17). The CLI is **not** a `ChannelAdapter` — that claim was retracted in Phase 0.1 ([ARCHITECTURE.md](ARCHITECTURE.md) §27); the interface is designed at M20 against two real channels.
**Acceptance:** startup to first prompt **< 400 ms with a warm kernel daemon, 1–2 s cold** ([PRODUCT_SPEC.md](PRODUCT_SPEC.md) §9 — audit verification is incremental against a signed checkpoint, not O(history), and Python import time dominates the cold path); `doctor` detects a deliberately misconfigured permission by attempting the write that should fail; `policy diff` reports a reorder-only change that alters a first match, an `extends` change and a removed obligation; `security demo` exits non-zero if any attempt succeeds, fails when an attempt is NOT EXERCISED, runs in CI, and fails under a deliberately weakened configuration.
**Ollama launch integration** (a project-owner requirement, recorded at M3e). Target first-class invocation:

```text
ollama launch direwolf --model <ollama-model-ref>
# e.g. ollama launch direwolf --model qwen3.8   -- illustrative only; no model is hard-coded
```

M17 exposes a stable DireWolf launch and configuration contract suitable for Ollama's launcher; validates **arbitrary** Ollama model references rather than one named model; tests the launch path in ordinary CI against a small fixture model, with real Ollama and model smoke tests in dedicated integration and release jobs rather than on every pull request. Ollama's launcher uses an application integration registry: once DireWolf's M7/M17 contract is stable, an upstream integration is proposed so that `direwolf` becomes a first-class launch target. The model reference selects intelligence only -- never policy, capabilities, approvals, sandbox, privacy class or authority profile. (M3e changes nothing in the Ollama repository and adds no Ollama dependency or provider.)

### M18 · V1 hardening → **V1.0**
Full eval suite green; fuzzing soak; 24 h soak runs; performance targets met; docs complete; third-party security review commissioned; **published eval results including failures**.
**Release integrity** ([COMPETITIVE_ANALYSIS.md](COMPETITIVE_ANALYSIS.md) §17 G3), before any binary is distributed: a locked dependency licence inventory per binary and platform; per-platform archives; `THIRD_PARTY_NOTICES` generated per binary and per platform from the locked, linked closure (the root [NOTICE](../NOTICE) states the obligations; `cargo-deny` checks that a licence is allowed, not that its attribution ships); an SBOM in CycloneDX and SPDX; a build-provenance attestation; keyless signing; a reproducibility comparison (deferred since M2).
**Acceptance:** every release archive contains every required licence and notice; the generated notice inventory matches the locked shipped closure; CI fails when a newly shipped dependency has unreviewed licence or notice requirements; each SBOM equals the linked closure of its binary and platform; signature and provenance verify from a clean machine; two independent builds compare equal, or every difference is explained.
**Adversarial:** an allowed-licence dependency whose attribution is missing; a platform-only dependency left out of that platform's notices; a tampered archive; SBOM drift from the lockfile.

---

## Post-V1

| Version | Milestones |
|---|---|
| **V1.1** | M19 gateway · M20 channels (Telegram first) · M21 scheduler + standing intents · M22 optional embeddings |
| **V1.2** | M23 browser (Playwright, sandboxed, quarantined downloads) |
| **V2.0** | M24 memory consolidation · M25 skill learning pipeline · M26 plugins (out-of-process) · M27 web UI · M28 remote workers |
| **V2.x** | Stronger isolation (gVisor/Firecracker) · durable workflows · competitive benchmark publication · skill registry (only with signing and revocation) |

**M28 remote workers** carry the items deferred by the 2026-09-28 re-baseline ([COMPETITIVE_ANALYSIS.md](COMPETITIVE_ANALYSIS.md) §17 G8): a workload identity proved by key possession, not by a bearer token; a signed, single-use remote permit bound to the canonical action digest, the epoch, the broker identity and an expiry, with a durable nonce; an encrypted host–worker transport; and the decision whether authority state spans hosts, taken there and not before.

## Permanently deferred

Autonomous self-modification of policy, kernel or capabilities · fully autonomous privileged skill installation · Kubernetes-first architecture · enterprise SSO/multi-tenancy/billing · becoming a general workflow orchestrator · framework-style agent authoring APIs.

## Milestone template

```markdown
## MN · Name
Objective:            one sentence
Dependencies:         M…
Deliverables:         …
Acceptance criteria:  measurable, checkable
Tests:                unit / integration / property
Adversarial tests:    what an attacker would try
Security checks:      which invariants are re-verified
Performance:          targets
Explicitly deferred:  what this milestone does NOT do
Exit review:          architecture · security · reliability sign-off
```
