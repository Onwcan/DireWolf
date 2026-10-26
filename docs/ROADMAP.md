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
and serving on Linux only. **M5 is in progress: M5a, M5b and M5c are complete (see M5 below).**

**Deps:** M3. **Deliverables:** canonicaliser (NFC, `openat2` + fallback walker, inode identity -- M4a delivers `openat2` and identity; a fallback walker needs its own ADR); fd-relative fs ops; exec broker with env scrub, rlimits, argv normalisation, executable hashing; secret broker with keychain/age backends and injection modes A–C; redaction index.
**Acceptance:** no path string reaches policy; every op uses the fd it checked; no secret in argv, ever.
**Adversarial:** the full path-traversal set ([EVALS.md](EVALS.md) §3) including Unicode normalisation and TOCTOU swap races in a tight loop; secret-in-output detection; core-dump inspection for secret residue.
**Deferred:** remote fs, Windows-native hardening beyond the fallback walker.

### M5 · Sandbox — **IN PROGRESS** (M5a complete, hosted acceptance passed; M5b complete, hosted acceptance passed; M5c complete, ADR-0050 accepted, hosted acceptance passed; M5d complete, ADR-0052 accepted 2026-10-26, hosted acceptance passed; M5e not started — M5 is complete only when M5e meets its own acceptance)

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

#### M5c · `net.http`, SSRF and redirect policy, credential egress — **COMPLETE**

M5c is complete: its owner accepted
[ADR-0050](adr/0050-m5c-kernel-performed-net-http-ssrf-redirects-and-credential-egress.md) on 2026-10-11 — D1–D10 and D12 as built, and D11's one-hop exchange
worker with its residual and the conditions of ADR-0050 §21 — on hosted run [38086715241](https://github.com/Onwcan/DireWolf/actions/runs/38086715241) on
`cc98a71`, which passed all 21 jobs: `net-http` twice (once under CPU contention), the
secret broker with its multi-identity half, the gated `m5c-net-http` eval, M5a, M5b, the
authority boundary, architecture, schemas, dependencies, the three platforms and the
release build. That commit carries the final D11 audit (2026-10-10), which found no defect
and changed no production byte: its worker tests and end-to-end case passed hosted there.
The mutation campaign (`make net-http-mutations`, ten of ten caught) is a local target,
not a hosted job. History: run 37855884386 on the first implementation failed before it
measured anything — its tool probe asked OpenSSL 3.0 for `openssl --version`, which 3.0
refuses; the probe now asks each tool by its own spelling — and run
[37994995963](https://github.com/Onwcan/DireWolf/actions/runs/37994995963) on `7b8ba9d`, the
recovery that moved each hop's TLS and HTTP into an exchange worker, passed all 21 jobs.

**Deps:** M5b. **Deliverables (as built):** ToolInvoke and
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
never following a redirect), each hop's TLS and HTTP in a one-hop exchange worker
(`dwkd-broker http-worker`, hardened, handed only its connection, credential and hop, gone
before the broker answers); mode A's consumer — a credential attached only at the
request's first origin, each hop its own decided and recorded `secret.use`, through a
fresh one-shot pipe, and an echo of it taken out before anything of the response is
encoded. The `PROXY_ONLY` tunnel is untouched.
**Acceptance:** `make net-http-evidence` (no internet: real TLS origins, the fixture
resolver, the released broker) — 179 required cases across SSRF and DNS, HTTP and
redirects, TLS, secrets and residue, the exchange worker's lifecycle, lifecycle and
budgets; `make net-http-mutations` — ten weakened safeguards each caught; M4e's secret
evidence moved to `net.http` with every case kept, and an echoed credential asserted absent
from the broker nine ways (178 secret cases); required hosted job `net-http` (also under
CPU contention) and gated eval `m5c-net-http`.
**Adversarial:** every guarded range and its IPv4-mapped, NAT64, 6to4 and Teredo shapes; a
mixed answer; metadata names and addresses; address literals in every spelling; userinfo,
case, trailing dots, encoded dot segments, backslashes, port confusion; rebinding within and
across requests; redirects to blocked, mixed, metadata, ungranted and downgraded targets,
loops, the sixth hop, a body resent; malformed, encoded, oversized, header-bomb,
close-delimited and silent responses; wrong-name, expired, self-signed and untrusted
certificates, and the test authority under production trust; a credential across origins,
in the request, echoed back; crashes after resolution, intent and exchange; reused keys;
spent budgets; the shipped packs and taint.
**Residual, accepted with D11** (ADR-0050 §§20–21): an origin that echoes the credential
has it in that hop's exchange worker until the worker exits (root or `CAP_SYS_PTRACE` can
read it meanwhile), in the physical pages it freed until the kernel reuses them, and on
swap if a page was swapped out — never in a message, the audit, the authority, the
long-lived broker or the runtime's answer; the worker's startup window before it hardens
itself; and no OS-level network confinement of the worker, whose single connection is a
property of its code.
**Conditions of acceptance** (ADR-0050 §21): the broker runs as its own uid, never root —
enforced at start-up by both daemons; no untrusted workload runs as the broker's uid —
structural today (nothing is launched in production), and **M5d must prove it with real
multi-identity evidence**; a ptrace posture that closes the startup window (Yama
`ptrace_scope` ≥ 1 or an execute-only broker binary) — a **deployment prerequisite,
documented and not yet verified**, whose fail-closed check at the broker's start M5d adds
before any workload runs.
**Deferred:** package-manager routing (M5d/M5e); model egress (M7); approvals (M6).

#### M5d · Production sandboxed `process.exec` — **COMPLETE** (2026-10-26: M5d.1 to M5d.6 built and verified in hosted CI; [ADR-0052](adr/0052-m5d-sandboxed-process-exec.md) accepted 2026-10-26; the closeout below)

**Deps:** M5a, M5b. **Deliverables:** `process.exec` in an environment through the
authority's gates; secret modes B/C wired to sandboxed processes; `workspace_exec_hygiene`
enforceable in the sandbox; the workspace ownership model; the workload wall clock and
disk quota; the `local` environment's confinement; lifecycle integration with runs.
**Interoperability prerequisites** ([ADR-0051](adr/0051-external-agent-interoperability.md), Proposed — no integration in M5d): the escape
suite covers an agent-shaped workload — a long-lived third-party binary with child processes
and network to declared origins only; no workload runs as the broker's uid (the exchange
worker's startup window, ADR-0050 §9); secret modes B/C reach environments, the path an
external agent's own credential would take (M29).
**Carried from M5c's acceptance** ([ADR-0050](adr/0050-m5c-kernel-performed-net-http-ssrf-redirects-and-credential-egress.md) §21): real multi-identity evidence that
no workload runs as the broker's uid or reaches the authority's state or a secret store;
the broker's fail-closed check of its ptrace posture at start, before any workload runs.
**Acceptance:** a real workload runs only in a measured environment at its required level.
**Adversarial:** full escape suite from a workload; resource exhaustion; persistence.
**Deferred:** approvals for host execution (M6); the `local` environment (with M6, by its
own ADR — ADR-0052 OD-7).

**Checkpoints** ([ADR-0052](adr/0052-m5d-sandboxed-process-exec.md) §18; each is
accepted only when its evidence, its mutants and every earlier evidence pass locally and in
hosted CI):

| Checkpoint | Delivers | Status |
|---|---|---|
| **M5d.1** Authorised OCI workload lifecycle | private protocol 8's `broker.workload_run`; the broker's re-judgement of the recorded environment, the executable's digest proved from the image, a fixed plan as uid 10001 in `/workspace`, bounded output, the wall clock, and `reap` by the environment's init; schema 9's workload ledger; `Authority::workload_run` (in-process, no DWKP route) behind both gates for a sandbox action, the measured level, the budget and the obligations; fail-closed environment destruction; the broker's start-up identity and ptrace-posture refusals | **COMPLETE** — built with `make sandbox-workload-evidence` (real containers, an agent-shaped workload) and `make sandbox-workload-mutations` (30 mutants); hosted job `sandbox-workload`, awaiting hosted CI and the owner when built; green with M5d.2 at `3f56e04` (run 39229385310) and in every hosted run since, the last at `d40bc25` (run [40310407743](https://github.com/Onwcan/DireWolf/actions/runs/40310407743)); its decisions approved by the owner, 2026-10-26 (ADR-0052 §19) |
| D11 hardening (a security checkpoint between M5d.1 and M5d.2; [ADR-0053](adr/0053-d11-exchange-worker-confinement-and-secret-memory.md), accepted 2026-10-18) | the HTTPS exchange worker's own syscall filter, measured and proved per worker; the broker vouching for each worker from the kernel before its hand-over; the start-up posture read before every worker; credential hops only where memory cannot reach swap | **ACCEPTED** (2026-10-18, on hosted run [39074450443](https://github.com/Onwcan/DireWolf/actions/runs/39074450443), `4784e05`) -- `make d11-hardening-evidence`, `make d11-hardening-mutations`; required hosted job `d11-hardening`; `net.http` on `x86_64` only (OD-7) |
| **M5d.2** Public sandboxed `process.exec` | the DWKP route (tool messages version 5), the shared idempotency namespace, results naming environment and level; `workspace_exec_hygiene` in the environment; concrete `process.exec:<path>` grants resolved against the image manifest (OD-9); as built also private protocol 9's workload start and collection, schema 10, `serve --sandbox-config` with the authority preparing a run's environment (ADR-0052 §2a) and the probe as the hygiene launcher (§5a) | **COMPLETE** — `make sandbox-workload-evidence` (eleven broker and eleven authority real-container tests, a real DWKP client and the released `serve`), `make sandbox-workload-mutations` (52 mutants); OD-10 and OD-11 approved by the owner (2026-10-19, with conditions); hosted CI green at `3f56e04` (run 39229385310) |
| **M5d.3** Secrets B/C in the sandbox | the trusted launcher over the `exec`'s standard input; mode C's descendants recorded as a residual; as built tool messages version 6 (`credential_handle`, the plan's `spawn_injection`), private protocol 10 (`broker.workload_secret_start`, three descriptors), schema 11 (`workload_secret`), the consumer resolved against the image manifest, TX055–TX056 | **COMPLETE** — built with `make sandbox-secret-evidence` (the authority's pipeline with real keyring values against a fake broker; six broker and four authority real-container tests, a real DWKP client and the released `serve --secrets-file`), `make sandbox-secret-mutations` (22 of 22 killed; M5d.2's 52 of 52 still); hosted CI green at `4cfc9f8` (run 39410907163, 24 of 24 required jobs); OD-4 approved by the owner as built, 2026-10-26 |
| **M5d.4** Workspace ownership and disk quota | OD-3(a): the group 10001, the workload's own gid, a root of mode `2770` owned by root or the authority, nothing repaired; OD-6: a filesystem of its own per workspace, measured by the authority and the probe against the declared quota before preparation and every workload; every launch through the trusted launcher with the umask `0007` (OD-12); brokered changes excluded while a workload may run; `ENOSPC` changing nothing; as built private protocol 11, probe report 3, TX057–TX059 | **COMPLETE** — built with `make sandbox-workspace-evidence` (in process: a real full `tmpfs`, the authority against a fake broker; real containers: the local cases, and the operator-provisioned cases on the hosted `sandbox-workspace` job only — NOT EXERCISED locally), `make sandbox-workspace-mutations` (26 of 26 killed; M5d.2's 52, M5d.3's 22, net.http's 10 and D11's 26 still all killed); hosted CI green at `1c8ccbe` (run [39854518873](https://github.com/Onwcan/DireWolf/actions/runs/39854518873), 25 of 25 required jobs) — the evidence verified, OD-3, OD-6 and OD-12 then still the owner's; **approved by the owner as built, 2026-10-26** |
| **M5d.5** Agent-shaped escape suite and multi-identity evidence | a long-lived agent-shaped workload in `PROXY_ONLY` with declared origins; the hosted three-identity job; as built `make sandbox-agent-evidence` (the released `serve --sandbox-config` over a real DWKP client, the released broker, a real runtime, the M5d.2 tools image with the relay added, local HTTPS origins under a per-run PKI), the required hosted job `sandbox-agent`, `make sandbox-agent-mutations`; no product code, protocol, schema or dependency changed | **COMPLETE** — the one-identity half (3 tests, 50 cases) passing locally and hosted; `make sandbox-agent-mutations` 11 of 11 killed; the three-identity half (`DW_AGENT_PRIVILEGED=1`: three host users, the group 10001, a bounded workspace) NOT EXERCISED locally, hosted-only. **Hosted CI green at `49bb8f8`** (run [40134163102](https://github.com/Onwcan/DireWolf/actions/runs/40134163102), 26 of 26 jobs; the `sandbox-agent` job ran the two three-identity tests, 25 cases) — the evidence verified, OD-5 then still the owner's; **approved by the owner as built (no handle), 2026-10-26** |
| **M5d.6** Closeout | run release destroys its environment; the gated eval; ADR-0052 accepted | **COMPLETE** — M5d.6's hosted CI green at `d3d52e7` (run [40235421487](https://github.com/Onwcan/DireWolf/actions/runs/40235421487), 27 of 27 jobs) — a run's release records its live environment's destruction in the release's own transaction and has the broker remove it (ADR-0052 §8); `make sandbox-release-evidence` (the authority against a fake broker: 8 tests, 31 cases; real containers: 4 tests, 29 cases, over a real DWKP client and the released `serve`), the required hosted job `sandbox-release`, `make sandbox-release-mutations` (10 of 10 killed, each by the authority's state suites, every file restored and checked); the gated eval `m5d-sandbox-exec` passing locally, `M5d` available to the harness (`M5` not). **The closeout** (the owner's decisions, 2026-10-26: OD-1 to OD-9 and OD-12 approved as built, CD-1 to CD-3 taken, ADR-0052 §19): a lease's end records its reaped runs' environments `DESTROYING` in the reaping transaction and removes one at once, a restart destroys a reaped run's `READY` environment (W5 amended), W13, `AcquireLease`, `ReleaseLease` and `ReleaseRun` effect-bearing; the same task now 15 tests, 62 cases against the fake broker and 6 tests, 45 cases with real containers, `make sandbox-release-mutations` 14 of 14 killed; committed at `d40bc25`, hosted CI green (run [40310407743](https://github.com/Onwcan/DireWolf/actions/runs/40310407743), 27 of 27 jobs: the release evidence's 62 and 45 cases, the agent's three-identity and the workspace's privileged halves exercised, `m5d-sandbox-exec` passing); **ADR-0052 accepted 2026-10-26**, the acceptance committed at `09c23dd` and its hosted CI green (run [40320662852](https://github.com/Onwcan/DireWolf/actions/runs/40320662852), 27 of 27 jobs) |

**M5d.1 as built.** The ptrace-posture check carried from M5c is made: the broker reads
Yama's `ptrace_scope` and its own binary's owner and mode at start and refuses to serve
unless one closes the startup window (`--allow-traceable-workers` logs `REDUCED
ASSURANCE`), and refuses outright when its uid or the authority's is a sandbox identity
(10001, 10002). The multi-identity evidence is not: M5d.1 shows separation in one identity,
where the environment's mount namespace names no daemon's state; real users are M5d.5's.
No production host launch exists or is added; the runtime cannot reach a workload.

**M5d.2 as built.** A runtime reaches a workload through `process.exec` at version 5, and only
where the authority decides: with `serve --sandbox-config` the run's `READY` environment (the
authority prepares one on the run's first permitted launch), never the host; without it,
version 4's host floor. The broker starts a workload and answers, and the authority parks the
request and collects it between its other requests, so a long workload holds neither. The
owner approved ADR-0052's two refinements on 2026-10-19, with conditions: the production
environment (§2a, OD-10; a preparation holds the authority's worker for at most the 120 s
environment deadline, about 3 s measured; environments of ended runs are reclaimed and at most
16 are live) and `workspace_exec_hygiene` kept by the probe as a trusted launcher (§5a, OD-11;
`npm`-family tools and `cargo`, directly or through a wrapper, stay refused until evidenced; a
repository's own configuration, hooks and `conftest.py` are contained by the environment, not
neutralised — OCI containment is the boundary). Not exercised by
M5d.2: a workload in `PROXY_ONLY`, three real identities, real secrets in a workload (M5d.3–5).

**M5d.4 as built.** The operator now provisions each workspace as a filesystem of its own and
declares its quota (`[workspace] quota_bytes`); production refuses any other — a host
directory, a root of the wrong owner, group or mode, an authority outside the group — before
the broker hears of it, and never repairs one. The workload, the broker and the authority share
the workspace through group 10001; every launch now passes through the pinned probe, which
sets the umask (a change to M5d.2's `DIRECT` launch, flagged for the owner as OD-12). A
brokered change waits while a workload may be running in its workspace. The evidence
harness's unverified workspace remains for the earlier suites, acknowledged by both daemons
and never evidence of the guarantee. The W9 crash evidence was corrected on the way: the start's
answer precedes the runtime's `exec` by design, so the case now waits for the workload's own
process before it stops the authority.

**M5d.5 as built.** An agent-shaped workload — a plan, two long-lived workers and a daemonised
helper, with the image's Python as a stock HTTPS client that verifies its origin against the
run's test anchor — runs the way a runtime runs one: a real DWKP client, the released
`dwkd-authority serve --sandbox-config` naming `PROXY_ONLY`, the released broker and a real
runtime. It reaches exactly the run's granted synthetic HTTPS origins through the real relay
and CONNECT proxy; every other host, port, CONNECT form, server name, untrusted or misnamed
certificate, direct TCP, UDP and DNS path and rewritten proxy variable is refused, each
attributed to what refused it (the proxy's decision, the namespace's errno, or the agent's own
TLS verification — the agent's guarantee, not DireWolf's). The tunnel limit, both byte budgets,
the wall clock and the run's workload budget hold; `reap` ends everything the agent leaves; a
broker or an authority lost mid-agent leaves `UNKNOWN` and a destroyed environment, and the
same key never runs again. The audit records the grant at the intent and the egress by
disposition at the destruction — counts, not an event per refused attempt. The three-identity
half runs only on the disposable hosted runner (`sandbox-agent`): the authority as the runner,
the broker as `dwbroker`, the DWKP runtime as `dwruntime` through a relay of its own, `nobody`
as a stranger, a bounded workspace of the group 10001 — every uid from the kernel, and every
cross-identity boundary attempted. Not M5d.5: a persistent workload handle (OD-5: none), run
release destroying its environment (M5d.6), and package-manager registries (M5e).

**M5d.6 as built.** A run's release now ends its environment. In the transaction that
records the run `RELEASED`, its live environment is recorded `DESTROYING`; then the broker
removes exactly the container recorded for it, by its labels — in `PROXY_ONLY` its relay and
setup with it, the egress counted by disposition at the destruction. A workload still running
there ends with it and is settled `UNKNOWN`, never rerun; a destruction the broker cannot
confirm stays `DESTROYING` and is completed by the next preparation or at the next start; a
preparation that another handle's release overtook destroys what it made. A fenced, foreign or
repeated release ends nothing, and another run's environment and foreign containers are never
touched. The public contract is unchanged: `ReleaseRun` still answers `Ack` (the release and
its environment's destruction durable, not a confirmed removal) and refuses only
`STALE_EPOCH`. A run a lease's end reaped is not released; its environment is still reclaimed
before the next preparation (ADR-0052 §2a) — until the closeout, below. The gated `m5d-sandbox-exec` eval runs the real
evidence and requires every case at its level with its expected outcome. Not M5d.6: the
complete M5 escape and registry gate (M5e), and ADR-0052's acceptance (the owner's).

**The M5d closeout as built** (the owner's decisions of 2026-10-26, ADR-0052 §19). OD-1 to
OD-9 and OD-12 are approved as built; OD-10 and OD-11 keep their 2026-10-19 approvals. What a
lease's end reaps now ends with it: in the transaction that records a run `REAPED` — a
holder's `ReleaseLease`, an `AcquireLease` that rotates, takes over or re-acquires the lease —
its live environment is recorded `DESTROYING`, reason `REAPED`, before the broker is told
anything, and the request then removes **at most one** environment, holding the worker for at
most the 120 s environment deadline (OD-10's bound, confirmed for this path); the rest are
removed by the next preparation or the next start. A restart destroys every reaped run's
`READY` environment instead of measuring it again (ADR-0047 §12's W5, amended by ADR-0052); a
crash after the reaping commits is W13, completed at restart. A workload running in a reaped
run's environment ends with it, settled `UNKNOWN`, its key never run again, and a new holder
inherits nothing. Every public answer is unchanged (CD-1: `Ack` says the destruction is
durable, not that the removal was confirmed); `AcquireLease`, `ReleaseLease` and `ReleaseRun`
are `effect_bearing` in the registry, still with an empty payload and no idempotency key
(CD-2). A lease that only expires reaps nothing, so its runs stay fenced and their environments
idle until the session is acquired again or the authority restarts — a documented residual; no
expiry sweep was added (CD-3). A second residual, found in the review and accepted by the owner (2026-10-26):
what a lease's end leaves `DESTROYING` holds back brokered changes in the workspace it shares
(`SHARED_DIRECTORY`, M5d.4's exclusion, unrelaxed) until a later preparation or a restart
removes it. Not the closeout change itself: ADR-0052's acceptance and M5d's completion,
which followed its hosted run (below); M5e.

**M5d complete (2026-10-26).** M5d is complete on the record of [ADR-0052](adr/0052-m5d-sandboxed-process-exec.md), accepted on
2026-10-26 by the owner: M5d.1 to M5d.6 built and each verified in hosted CI (the table
above). The final implementation, committed at `d40bc25`, passed hosted run
[40310407743](https://github.com/Onwcan/DireWolf/actions/runs/40310407743) — 27 of 27 jobs, among them `sandbox-release` (62
fake-broker and 45 real-container cases), `sandbox-agent` (50 one-identity cases and, on
the hosted runner, 25 across three host identities), `sandbox-workspace` (its privileged,
operator-provisioned half), `sandbox-workload`, `sandbox-secret`, `sandbox-foundation`,
`sandbox-egress`, D11 hardening, the dependency audit and the strict eval gate with
`m5d-sandbox-exec`. The acceptance, committed at `09c23dd`, passed hosted run
[40320662852](https://github.com/Onwcan/DireWolf/actions/runs/40320662852) — 27 of 27 jobs, the accepted-ADR history check
included. Every owner decision is taken: OD-1 to OD-9 and OD-12 approved on 2026-10-26,
OD-10 and OD-11 on 2026-10-19 with their conditions, and the closeout's CD-1 to CD-3
(ADR-0052 §19); no implementation or approval blocker remains. M5d is accepted with its
limits stated: a lease that only expires ends nothing until its session is acquired again
or the authority restarts; a lease's end that leaves destructions pending holds brokered
changes in the workspace they share (`SHARED_DIRECTORY`) until they are removed — accepted
by the owner on 2026-10-26; containers share the host kernel; every member of the
workspace group can read and write the workspace; and a sandboxed credential reaches
every descendant of its process, its redaction stopping an honest echo, not a malicious
consumer. ADR-0052 §1 scopes M5d's adversarial evidence as the escape suite with an
agent-shaped workload (M5d.1, M5d.5); the complete escape, SSRF, persistence and
resource-exhaustion suites as merge gates, the weakened-profile closure for `PROXY_ONLY`
and package-manager acceptance are M5e's, and the `local` environment is M6's (OD-7). M5
stays in progress until M5e meets its own acceptance. Passing CI is the evidence named
here — not a deployment, and not a certification.

#### M5e · The M5 adversarial gate and closeout — **NOT STARTED**

**Planned, not started (2026-10-26).** The gap analysis, the requirements-to-evidence matrix,
the implementation sequence and the owner decisions still open are in
[M5E_ASSURANCE_PLAN.md](M5E_ASSURANCE_PLAN.md); the npm profile M5's package-manager
acceptance needs is [ADR-0054](adr/0054-m5e-npm-hygiene-profile.md), **Proposed** — until it
is accepted, npm stays refused as ADR-0052 §5a decided. No M5e code, evidence or CI job
exists yet.

**Deps:** M5a–M5d. **Deliverables:** the complete escape, SSRF and persistence suites as
merge gates; weakened-profile closure for `PROXY_ONLY`; package-manager acceptance
(`pip install`, `npm install` against allowlisted and non-allowlisted registries).
**Acceptance:** the milestone contract below, in full; `M5` joins the available milestones.
**Adversarial:** everything above, together.
**Deferred:** gVisor/Kata/Firecracker, SSH, remote workers; the `local` environment (M6, by its own
ADR — [ADR-0052](adr/0052-m5d-sandboxed-process-exec.md) OD-7, accepted).

#### The M5 contract

**Deps:** M4. **Deliverables:** `ExecutionEnvironment` trait; `oci-strict` profile with `PROXY_ONLY` networking ([ADR-0024](adr/0024-sandbox-network-topology.md)); supervisor with lifecycle, limits, reaping, and **re-attach by run-id label** after a container-runtime restart; `local` environment behind opt-in (deferred to M6 by ADR-0052 OD-7, accepted; the owner's confirmation of M5's acceptance wording is open, [M5E_ASSURANCE_PLAN.md](M5E_ASSURANCE_PLAN.md) §10 OD-E5); `AssuranceLevel` surfaced to policy; CONNECT proxy with IP guard, DNS pinning, SNI/host agreement and byte budgets; kernel-performed `net.http`; **measured assurance** ([COMPETITIVE_ANALYSIS.md](COMPETITIVE_ANALYSIS.md) §17 G2) -- an authority-provided, read-only, digest-checked probe run inside each environment checks every hard rule of [SANDBOX.md](SANDBOX.md) §2 as PASS or FAIL (no weighted score), the effective `AssuranceLevel` is the lower of declared and measured, and a failed required invariant refuses the environment and is audited.
**Acceptance:** defaults from [SANDBOX.md](SANDBOX.md) §2 verified at runtime, not merely configured -- by the measured-assurance probe, and a **weakened-profile meta-test for each hard rule** (a bridge network, a writable root, an added capability, unconfined seccomp, a mounted container socket) must make the gate fail; from a `PROXY_ONLY` sandbox, **no route exists to any address but the proxy endpoint** (verified by attempting direct connections and direct DNS); a real package manager (`pip install`, `npm install`) succeeds against an allowlisted registry and fails against a non-allowlisted one; orphan reaping exact; the opaque tunnel's residuals, domain fronting through an allowlisted shared host among them, are stated in [NETWORK_SECURITY.md](NETWORK_SECURITY.md) and bounded by the byte budget (G7).
**Adversarial:** full escape suite; full SSRF suite; resource exhaustion; cross-run persistence attempts; a configuration that looks hardened while the running environment differs; a tampered or substituted assurance probe; a fronted request through an allowlisted shared host, which must stay within its byte budget and connection count.
**Deferred:** gVisor/Kata/Firecracker, SSH, remote workers.

### M6 · Approvals and budgets
**Deps:** M3. **Deliverables:** binding hash; approval registry with scopes, expiry, single-use burn; standing grants with the 90-day cap and `require_untainted_run`; kernel-rendered approval prompts; hierarchical subtractive budget ledger; unattended degradation to DENY.
**Acceptance:** every property test in [APPROVALS.md](APPROVALS.md) §10; burn is atomic under concurrency; prompts contain no model-authored text in the authoritative region.
**Adversarial:** replay, substitution, drift (file/DNS/binary swap), laundering parent↔child, environment swap, fatigue spam, budget amplification via fan-out; an external agent's own approval, auto-approve or "yolo" claim presented as an operator approval ([ADR-0051](adr/0051-external-agent-interoperability.md)).

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
| Local and self-hosted | **Ollama** (first-class); **llama.cpp's `llama-server`** (first-class); vLLM; SGLang; LM Studio; self-hosted Hugging Face serving (Text Generation Inference, Inference Endpoints); NVIDIA NIM (an operator-run container) | The OpenAI-compatible adapter against an operator-declared origin, or Ollama's own API where M7's ADR prefers it; each server is a declarative profile, admitted only after its compatibility is verified against its own documentation |
| Operator-run gateways | LiteLLM Proxy -- **deferred**, not an M7 target (below) | -- |

**Ollama remains a first-class local provider** (a project-owner requirement, recorded at M3e) -- no longer the only named local target. An Ollama model reference (`<ollama-model-ref>`: any reference the installed Ollama supports, a model name or a model:tag variant) is passed as **data and configuration**, and nothing matches, branches on or hard-codes a model name: `qwen3.8` in the example below is illustrative, and no model is special. **Hugging Face is a first-class target** (a project-owner requirement, 2026-10-07), both hosted and self-hosted: its Inference Providers router (OpenAI-compatible chat completions) and a self-hosted Text Generation Inference or Inference Endpoints deployment (its OpenAI-compatible Messages API). Neither is a privileged path: each is a profile behind the same model egress, origin binding, privacy-class enforcement, credential injection, metering and stream relay as every other provider.

**llama.cpp is a first-class local target** (a project-owner requirement, 2026-10-09), beside Ollama. Its `llama-server` serves an OpenAI-compatible API -- chat completions, completions, models and embeddings, server-sent-event streaming, tool calls through the model's chat template, `response_format` JSON and JSON-schema output (and its own grammars), a `usage` object -- on loopback by default with an optional API key, a `/health` endpoint, and the context size the operator started it with reported by `/props` (its server README, read 2026-10-09). It is a profile behind the one OpenAI-compatible adapter, not a library: DireWolf links no llama.cpp code and never builds, bundles, launches or downloads the server or a model; a GGUF model reference is data, and no model name is special.

**SGLang and NVIDIA NIM are named targets; LiteLLM Proxy is deferred** (evaluated 2026-10-09 against their own documentation; [COMPETITIVE_ANALYSIS.md](COMPETITIVE_ANALYSIS.md) §7a):

- **SGLang** -- an OpenAI-compatible server (loopback, port 30000 and no API key by default). Tool calls work only when the server is started with the tool-call parser for the model's family; structured output is `response_format` with a JSON schema (its regex and EBNF extensions travel in non-standard fields, which the profile does not use). A declarative profile; its capabilities are declared per deployment, never assumed.
- **NVIDIA NIM** -- an operator-run inference container whose LLM API is OpenAI-compatible (chat completions and completions, with streaming and tool calls, served in its current release by a vLLM backend; `/v1/models` names the served model; `/v1/health/ready` reports readiness). A declarative profile against the origin the operator declares. DireWolf pulls no container, holds no NGC key and selects no NIM model profile -- that is deployment, the operator's. The container fetches its model at start unless the operator pre-caches it: its own egress, outside DireWolf's model egress and outside a run. NIM needs NVIDIA GPUs and is used under NVIDIA's licence terms (production use under NVIDIA AI Enterprise, by NVIDIA's FAQ) -- both the operator's. NVIDIA's hosted API catalog is a different, remote origin and not a target here.
- **LiteLLM Proxy -- deferred.** It is a gateway, not an SDK: it holds the upstream providers' keys in its own configuration, forwards to whatever `api_base` that configuration names, falls back between providers, and can send request logs to third-party observability services. Through it, the kernel would authorise one origin while prompts reach any upstream its configuration chooses, with credentials outside the authority's per-origin binding and audit. If it is ever admitted, it is an **aggregator**: remote whatever address it listens on, so never `LOCAL_ONLY`; everything its configuration can reach counts as reached; its own virtual key the only credential DireWolf injects. Its Python SDK is never imported (TX001).

**A local server is not authorised by being local.** A local or self-hosted server is reached only through a profile the operator declares, naming its exact origin (scheme, host, port) or its Unix socket; nothing is discovered by scanning, and a server merely listening on loopback is authorised for nothing. The loopback exception a local profile needs is that profile's own, bound to that origin and to model egress: it never reaches `net.http`, whose production guard refuses loopback (ADR-0050, TX035), or the `PROXY_ONLY` tunnel. `LOCAL_ONLY` admits only origins the kernel itself resolves to loopback or to an address the operator declared local, under a profile declared local; a gateway is never local, and a profile declared local whose origin resolves elsewhere is refused. Any local process can bind a free loopback port before the intended server does, so M7's ADR decides how a local profile proves its server -- a Unix socket whose directory only the server's user can enter, TLS with a pinned certificate, or the listening socket's owner -- and until it does, a local profile carries no credential. A local server's API key (`llama-server --api-key`, SGLang's `--api-key`) is a secret handle like any other, injected only at its origin and never in cleartext over TCP: only over TLS or a Unix socket (ADR-0050 D6). The runtime never reaches a local server itself: it has no network (M9).

**Capability compatibility** (planning; M7's ADR fixes it). A profile declares what its server supports; the adapter refuses a request that needs an undeclared capability with a typed reason -- it never silently degrades a tool call to text or a schema to free text -- and every declared capability is backed by a recorded contract fixture in ordinary CI.

| Capability | M7's plan | llama.cpp `llama-server` | SGLang | NVIDIA NIM |
|---|---|---|---|---|
| Chat | `/v1/chat/completions` (Ollama's own API where its ADR prefers it) | yes | yes | yes |
| Streaming | server-sent events canonicalised through `CanonicalDelta`; the kernel relays, the runtime never holds the socket | yes | yes | yes |
| Tool calls | OpenAI `tools`; tool calls are proposals the authority gates like any other | through the model's chat template | with the server's tool-call parser for the model family | yes, per the served model |
| Structured output | `response_format` with a JSON schema; the result is validated by the runtime, never trusted | yes, and its own grammars | yes (JSON schema; regex and EBNF unused) | to verify per release |
| Context limit | declared by the profile or read once from the server; a request over it refused before sending | `-c`, reported by `/props` | `--context-length` or the model's configuration | the served model's |
| Usage | the provider's `usage` metered by the kernel; a profile that reports none is metered by request and says so | `usage` object | to verify | to verify |
| Multimodal | declared per profile and model, never assumed | with a projector file, model-dependent | model-dependent | model-dependent |
| Cancellation | the kernel closes the stream; nothing more is relayed; whether the server stops computing is measured, not assumed | to verify | to verify | to verify |
| Errors | HTTP status and the OpenAI error object mapped to typed failures; a provider's error text is untrusted content | OpenAI-style | OpenAI-style | OpenAI-style |
| Timeouts | the kernel's deadlines per profile (connect, first token, idle, total), bounded; a CPU-only local server may need a longer first token | server-side read/write timeout too | -- | -- |

**Breadth never buys authority.** Local use, like every other, must fit the privacy and model-authority model of [MODEL_ROUTING.md](MODEL_ROUTING.md) and [ADR-0020](adr/0020-provider-request-path-v2.md): the kernel performs the egress, the privacy class is kernel-derived ([ADR-0028](adr/0028-policy-input-ownership.md)), and a local endpoint is an origin like any other. No provider adapter, profile or SDK holds a credential, opens a socket or gets a privileged network path; a credential is injected only into a request to the origin it is bound to, and a cross-origin redirect never carries it. **Aggregators and cloud platforms route on their own side** -- OpenRouter, Hugging Face's router, a platform's model catalogue choose the backend that serves a request -- so the origin the kernel authorises is the aggregator's, policy counts whatever it forwards to as reached, and a `LOCAL_ONLY` run reaches none of them; a backend preference sent to an aggregator narrows a request and authorises nothing. **Health and failover are constrained routing**: a fallback is chosen only among the upstreams the run's policy already allows, at its privacy class, never from "any available vendor". Authentication a declarative profile cannot express is M7's own ADR to decide: it extends ADR-0020's profile format by review, or the provider is left out. **`--model` selects intelligence only**, for every provider. Provider and model choice never select or widen policy, capabilities, approvals, the sandbox, the privacy class, taint, standing grants or the authority profile.

**Acceptance:** no provider or model name outside `providers/` (TX001, CI gate); switching provider or model -- within a family and across families -- changes which model answers and nothing that decides authority; a `LOCAL_ONLY` run cannot reach a remote vendor, an aggregator or a cloud platform; a credential is injected only at the origin it is authorised for, and a cross-origin redirect cannot forward it; metering agrees with the usage each family's provider reports; every family's stream canonicalises through `CanonicalDelta`; router health and failover cannot escape the run's allowed upstreams or privacy class; at least one remote native provider, one OpenAI-compatible provider and one local or self-hosted provider work end to end, and the Hugging Face, Ollama and llama.cpp paths are all exercised -- llama.cpp's in a dedicated, CPU-only integration job against a small fixture model; a server listening on loopback without a declared profile is unreachable, and a local profile's origin is bound to model egress alone; every declared capability has its contract fixture, and an undeclared one is refused, typed. The evidence is deterministic, recorded contract fixtures per family and per compatible server's dialect (llama.cpp, SGLang, NIM among them) in ordinary CI; live calls to paid providers, real local servers and anything needing a GPU are optional integration jobs kept apart from it, never a pull-request requirement.
**Adversarial:** router asked to route to an unauthorised upstream; credential-to-wrong-endpoint; cross-origin redirect credential leak; an aggregator's fallback to a backend the policy excludes; a profile or a model reference crafted to select another provider or origin; a profile declared local whose origin is remote; an undeclared server listening on loopback; another local process bound to a declared local profile's port first; a gateway declared local under `LOCAL_ONLY`; a local server's key over plain HTTP; a `net.http` call aimed at a local profile's origin; a tool call or schema the profile did not declare.

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
**Deps:** M10. Kernel-spawned sandboxed servers; untrusted descriptions; `toolset_hash` rug-pull invalidation; per-server capability grants. A client only: serving MCP tools to another agent is M29c's server, a different role. Another agent's MCP server definitions are imported as untrusted proposals, each still needing its own grant ([ADR-0051](adr/0051-external-agent-interoperability.md)).
**Adversarial:** malicious description; rug pull; oversized results; server attempting network without a grant.

### M17 · CLI and doctor
**Deps:** M9–M16. Full command surface; `doctor` verifying facts not settings, including `doctor --sandbox`, which reports M5's measured assurance; export/import; **`direwolf policy diff`** -- rule-level changes plus the decision delta computed by the same evaluator over the fixture corpus and recorded canonical actions (G4); **`direwolf security demo`** -- a zero-credential scripted hostile runtime that prints each attempt with the audit record that denied it (G5) ([COMPETITIVE_ANALYSIS.md](COMPETITIVE_ANALYSIS.md) §17). The CLI is **not** a `ChannelAdapter` — that claim was retracted in Phase 0.1 ([ARCHITECTURE.md](ARCHITECTURE.md) §27); the interface is designed at M20 against two real channels. Its headless contract — a machine-readable event stream, exit codes, cancellation — is kept stable enough for M29a's ACP agent role to build on ([ADR-0051](adr/0051-external-agent-interoperability.md)).
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
| **V1.1** | M19 gateway · M20 channels (Telegram first) · M21 scheduler + standing intents · M22 optional embeddings · M29 agent interoperability (ACP first) |
| **V1.2** | M23 browser (Playwright, sandboxed, quarantined downloads) |
| **V2.0** | M24 memory consolidation · M25 skill learning pipeline · M26 plugins (out-of-process) · M27 web UI · M28 remote workers |
| **V2.x** | Stronger isolation (gVisor/Firecracker) · durable workflows · competitive benchmark publication · skill registry (only with signing and revocation) |

**M28 remote workers** carry the items deferred by the 2026-09-28 re-baseline ([COMPETITIVE_ANALYSIS.md](COMPETITIVE_ANALYSIS.md) §17 G8): a workload identity proved by key possession, not by a bearer token; a signed, single-use remote permit bound to the canonical action digest, the epoch, the broker identity and an expiry, with a durable nonce; an encrypted host–worker transport; and the decision whether authority state spans hosts, taken there and not before.

### M29 · Agent interoperability — **PLANNED** (post-V1, V1.1; [ADR-0051](adr/0051-external-agent-interoperability.md), Proposed)

**Objective:** reach external coding agents through shared standards — the Agent Client
Protocol first, MCP second — without creating any route around the authority. The products
studied, their interfaces at pinned revisions and their security limits are
[COMPETITIVE_ANALYSIS.md](COMPETITIVE_ANALYSIS.md) §7b. External agents are workloads or
clients, never model providers (M7 is unchanged) and never authorities.
**Deps:** M5 (M5d's contained workloads, M5e's gate), M6, M7, M9, M10, M14, M16, M17. Not a
V1 commitment: it would add a third-party binary to M5d's escape surface, a protocol to the
runtime and an MCP server to the authority's edge — none of it before V1's core is proven.
**Deliverables:**
- **M29a · DireWolf as an ACP agent.** `direwolf acp` over stdio: an ACP client — an editor,
  or OpenClaw's ACP client — drives DireWolf's own runtime: sessions, prompts, streaming,
  tool-call events, cancellation. Every effect still goes through the authority; a
  permission request carries the kernel-rendered M6 prompt and its binding hash, and the
  client's answer is only the operator's answer to that prompt.
- **M29b · External agents as contained workloads.** One reviewed ACP client. An external
  agent profile — binary digest and version range, declared model origins, credential
  handles, required capabilities, privacy class — admitted by policy; the agent runs in an
  M5 environment whose only egress is its declared origins (`PROXY_ONLY` grants), with the
  run's workspace as M5d mounts it, its credentials by secret mode B or C, a wall clock and
  budgets; its permission requests answered by policy and approvals, never auto-allowed;
  ACP `cancel`, then kill; its output untrusted and tainting. Vendor adapters — Claude
  Code's `stream-json`, Codex CLI's `exec --json` or app server, Pi's RPC, Droid's
  `stream-jsonrpc` — only on demand, each reviewed on its own, ACP preferred whenever the
  agent offers it.
- **M29c · An MCP server for contained agents.** Authority-mediated tools served to an agent
  running in a DireWolf environment with its native shell, file and network tools disabled or
  confined there. For an agent outside an environment the bridge is refused by default; an
  operator who chooses it gets an **advisory** bridge, labelled so in every audit record and
  in `doctor`, never described as enforcement.
- Decision point DP-1 answered by the owner (ADR-0051 §8, ADR-0029's revisit trigger):
  whether the authority's primitives are ever offered to external runtimes outside
  DireWolf environments.
**Acceptance — contract:** handshake and protocol-version negotiation; capability
discovery; session setup over stdio only (no unauthenticated TCP listener, whatever the
agent offers); streaming event framing within bounds; cancellation and timeouts honoured;
structured completion; crash recovery — a killed agent, runtime or authority leaves the run
reconciled and nothing silently retried; output bounds; an unsupported feature refused with
a typed reason.
**Acceptance — security:** no effect outside the authority or an environment it prepared;
no host execution without an M6 approval; no network beyond the declared origins, attempted
and refused; no external agent's credential in the runtime's memory, a log, an artifact or a
transcript returned to the run; an agent's "approved" never satisfies an M6 approval; no
cross-run workspace access; no capability escalation through an agent; no model-provider
fallback a profile did not declare; every side effect accounted for, at the environment's
level when the agent's own calls are contained rather than mediated.
**Acceptance — evidence:** recorded ACP (and vendor-adapter) contract fixtures in ordinary
CI; version-pinned live smoke tests with real agent binaries in a dedicated integration job,
never on pull requests; negative protocol tests — oversized frames, malformed JSON-RPC,
out-of-order events, a forged permission answer or binding hash; real-sandbox tests running a
native agent process under M5's escape suite; mutations that weaken mediation — a permission
request auto-allowed, an undeclared egress grant, a credential handed to the runtime — must
make the gates fail. No CI job installs all thirteen agents; documented potential is never
reported as tested compatibility.
**Adversarial:** an agent steered by injected content to leave its environment, reach an
undeclared origin, read another run's workspace or the host's credentials; an agent
claiming an approval; children outliving cancellation; a binary changed between admission
and launch; an ACP client forging a binding hash; an advisory bridge presented as
enforcement; a `LOCAL_ONLY` run asked to start an agent with remote origins.
**Deferred:** session interchange between agents; DireWolf as a general agent gateway;
proxying consumer-subscription logins.

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
