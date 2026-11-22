# Security review of the pre-M6 authority plane, 2026-11-22

**Source reviewed:** `main` at `d0fbb244f62d4195e2b36183c886c27207d9cea5`
(CI #205, run 45027301654: 33 job records, every one success; push workflow
run 45027301535: success). **Verdict: CONDITIONALLY READY** for the final
pre-M6 handoff -- see §20 for the conditions. This is a verdict on the
implemented M1-M5 authority plane and the pre-M6 remediation, not on
DireWolf V1, which is not built (M6 onward).

## 1. Executive summary

The review traced each claimed security property of the implemented
authority plane to the production code that enforces it and to the evidence
that exercises it, treating every earlier conclusion -- including the
remediation's own records -- as a hypothesis.

- **One confirmed vulnerability, MEDIUM (SR-01).** An operator's policy
  files were read following symlinks and without the owner, mode and
  directory checks the other three operator files keep. A uid that can write
  a policy file or a directory on its path decides the next incarnation's
  policy. Reaching it needs a deployment mistake; the other loaders refuse
  that mistake. Fixed fail-closed and recorded as ADR-0075 (Proposed): an
  operator-visible change that is the owner's to accept.
- **One required evidence gap, MEDIUM (SR-02).** Four broker tests that need
  unprivileged namespaces -- F-16's hostile resolver, F-05's two real kernel
  maps, ADR-0049's hidden-pid peer reader -- printed NOT EXERCISED in every
  hosted job and passed. A required step, `make namespace-evidence`, now runs
  them in the one hosted job that lifts the runner's restriction; its first
  hosted run is pending.
- **One documentation error in the remediation's own records, LOW (SR-03).**
  The ledger said F-04's hidden-pid case was not exercised hosted. It was:
  `make proxy-peer-evidence` in `sandbox-egress` reported it contained.
  Corrected.
- **One confirmed weakness, LOW (SR-04).** `direwolf models import` checked a
  source file without following a symlink, then opened it following one, and
  copied to end of file without the bound its quota was judged on. Fixed.
- Everything else examined held: no third network path, the address guard,
  the URL grammar, the egress ceiling's exact matching, the model parsers'
  bounds, the CI token's scope, the hosted evidence of the namespace-
  dependent cases that do run. §11-§14 list residuals that stay.

## 2. Exact source and scope

| | |
|---|---|
| Commit | `d0fbb24` (after `35f98c8`, `7bdb290`, `3998de2`, `6a0acea`, `d6f04fc`, `f0af2c9`) |
| Hosted run | CI #205, run 45027301654, every one of 33 job records success; all 33 job logs read |
| Reviewed | `dwkd-authority`, `dwkd-broker`, `dwk-proto`'s guard and URL grammar, `direwolf models`, `.github/workflows/`, `scripts/dw.py`'s evidence tasks |
| Not reviewed line by line | the whole of the ~150 000 lines of Rust; §6 says what was |

## 3. Method and its limits

**Hypothesis-led.** For each trust boundary: the attack, the entry point,
the asset, the enforcing code, a test that could falsify it, the evidence
that ran. Where a hypothesis was cheap to falsify against source, it was read;
where it needed a run, it was run.

**Independence -- stated plainly.** This review was carried out by the same
agent session that implemented most of the pre-M6 remediation (Phases 1-4.5).
It is not the independent review the remediation program calls for, and it
does not replace one. It re-derived each claim from source and from CI #205's
logs rather than from earlier reports, and it found an error in its own
earlier output (SR-03). Its corrections (§11) are not independently verified
by being re-run here; §19 asks for a separate verification pass.

**Environment.** WSL2 Ubuntu 26.04, one OS identity, no passwordless sudo:
three-identity and privileged cases are NOT EXERCISED locally, and only
hosted CI shows them. Native Windows builds are blocked locally by Windows
Application Control; Windows and macOS behaviour is CI #205's.

## 4. Threat model applied

[THREAT_MODEL.md](THREAT_MODEL.md) as the baseline. Attacker positions
considered, each with its real privileges:

| | Attacker | Privileges assumed |
|---|---|---|
| A | malicious content steering a model | none beyond the actions a run proposes |
| B | a compromised runtime (a DWKP peer) | its own uid; the DWKP socket; nothing the authority did not grant |
| C | a compromised sandbox workload | uid 10001 in its `oci-strict` environment; its relay; its workspace |
| D | a hostile process of another host uid | that uid; no root |
| E | a process sharing a trusted uid or group | that uid or group (the development acknowledgements; group 10001) |
| F | a malicious dependency in a sandbox | as C |
| G | a hostile HTTPS server | its responses, redirects and timing |
| H | a hostile resolver or DNS answer | answers within the host's resolver; not the host's files |
| I | a writer of workspace content | the workspace |
| J | a writer of a configuration path | only where the operator's deployment let another uid write it |
| K | a crafted local model file | its bytes, and the directory it is in if that is theirs |
| L | crashes, restarts, delays, concurrency | timing |

Root, and the operator, are trusted. An attack that needs either is stated as
such and not counted as an escape.

## 5. Trust boundaries reviewed

Runtime client → authority (DWKP); approver → authority; authority → broker
(private protocol); broker → host filesystem; broker → host process launch;
workload → container boundary; workload → network (`PROXY_ONLY`); authority
→ network (`net.http`); broker → host resolver; operator files → authority;
secrets; durable state and audit; offline model library; CI and supply chain.
§B is the matrix.

## 6. Coverage inventory

Read in source: the trusted operator-file walk
(`secret/backend/trusted_file.rs`) and every loader that uses it or should;
`state/policy_state.rs`; `server/mod.rs`'s start order; the egress allowlist
(`state/egress_allowlist.rs`) and its ceiling; the URL grammar
(`dwk-proto/src/wire/url.rs`); the address guard and its table
(`dwkd-broker/src/egress/guard.rs`, `dwk-proto` guard); every TCP/UDP socket
use in the two daemons and the CLI; the runtime client's argument vectors
(`--pull never`); the resolver and its hostile-resolver harness; the
namespace-dependent tests and their skip paths; `direwolf models`'s library
and format parsers; every workflow's `on:` and `permissions:`; the evidence
tasks' acceptance rules (`require_proxy_peer_evidence`).

Read from CI #205's logs: every job, for each NOT EXERCISED line and each
evidence summary.

Not re-reviewed here (their evidence stands as recorded, §D): the M3 lattice
and policy engine, the M4 brokers' descriptor handling, M4e's secret
handoff, the M5 sandbox measurement and the M5c `net.http` client, beyond the
points above.

## 7. Findings by severity

| Severity | Count | Findings |
|---|---|---|
| CRITICAL | 0 | -- |
| HIGH | 0 | -- |
| MEDIUM | 2 | SR-01 (confirmed vulnerability), SR-02 (missing adversarial evidence) |
| LOW | 3 | SR-03 (documentation error), SR-04 (confirmed weakness), SR-06 (missing evidence) |
| INFORMATIONAL | 3 | SR-05 (code scanning), SR-08 (hardening), SR-09 (local-only campaigns) |
| NOT A VULNERABILITY | 1 | SR-07 (domain fronting, an accepted residual) |

These are not one count of vulnerabilities: only SR-01 and SR-04 are
vulnerabilities; the rest are evidence, documentation, hardening and
residuals (§C).

## 8. Proof and reproduction

- **SR-01.** At `d0fbb24`, `PolicySet::from_files` called `std::fs::metadata`
  and `File::open` on the given path (both follow symlinks) and checked only
  `is_file`, size and UTF-8. A policy file of mode 0602, 0620, a symlink, a
  file in a 0777 directory and a relative path all loaded. Regression, in
  `crates/dwkd-authority/tests/transport_server.rs`:
  `linux::the_policy_loader_refuses_a_file_another_uid_could_change` (the
  loader) and `linux::an_operator_policy_file_is_trusted_only_as_the_other_operator_files_are`
  (the released binary).
- **SR-02.** CI #205's `filesystem-operations` and `process-broker` logs print,
  in their broker unit runs, NOT EXERCISED for F-16's resolver test, F-05's
  `a_real_kernel_mapping_is_judged_where_it_is_read` and
  `a_real_namespace_reads_the_same_from_inside_and_from_the_host`, and
  ADR-0049's `a_peer_in_a_pid_namespace_this_process_cannot_see_is_read_soundly`;
  no job runs them after lifting `kernel.apparmor_restrict_unprivileged_userns`.
  Locally (WSL2), `make namespace-evidence` reports all nine markers.
- **SR-03.** CI #201's and CI #205's `sandbox-egress` logs report
  `hidden-pid-admitted-by-uid-and-refused-by-uid`, level `kernel-hidden-pid`,
  `contained: true`, from `make proxy-peer-evidence`.
- **SR-04.** `models::library::copy_hashing` opened with `File::open` after a
  `symlink_metadata` check and read to end of file. Regression:
  `models::tests::a_source_that_changes_after_its_check_is_refused_and_leaves_nothing`,
  `models::tests::a_source_swapped_for_a_symlink_after_its_check_is_refused`.

## 9. Security tests that genuinely executed

In this review (WSL2, one identity): the four namespace tests through
`make namespace-evidence` (F-16's six cases, F-05's two, the hidden-pid
reader); the new SR-01 and SR-04 tests; mutation checks of each fix (§E); the
gates and evidence tasks in §G.

Hosted, CI #205 (from its logs): `authority-transport` (cross-uid 7 cases,
approver 6 cases, three identities); `broker-fs-read` (broker evidence 53 + 6,
three identities); `filesystem-operations` (117 + 14); `net.http` (193 cases);
`sandbox-egress` (133 real OCI + 19 in process; `proxy-peer-evidence` 6 cases
incl. the hidden pid, and 2 cross-uid); `sandbox-foundation` (109 real OCI);
`sandbox-workload` (152); `sandbox-secret` (52); `sandbox-agent` (51 + 26);
`sandbox-registry` (20); `sandbox-hygiene` (44); `sandbox-proxy-weakened`
(18); `sandbox-restart` (7); `sandbox-capacity` (4); `sandbox-workspace`
(incl. a real full filesystem); `evals` (24 passed, 0 pending); `M5 gate`.

## 10. Tests not exercised

| Test or case | Where | Why | Now |
|---|---|---|---|
| F-16 hostile resolver (6 cases) | every hosted job | runner restricts unprivileged user namespaces | required by `namespace-evidence`, hosted run pending |
| F-05 real kernel maps (2 cases) | every hosted job | same | same |
| ADR-0049 hidden-pid peer reader | every hosted job | same | same |
| F-04 hidden-pid case | unit runs only | same | **exercised** in `sandbox-egress` (SR-03) |
| full filesystem (M5d.4) | unit runs only | same | **exercised** in `sandbox-workspace` |
| canonicalization: casefold filesystem | `filesystem-canonicalization` | no casefold filesystem on the runner | NOT EXERCISED (SR-06) |
| canonicalization: bind mount inside a workspace | same | no mount privilege in the test | NOT EXERCISED (SR-06) |
| canonicalization: cross-device hard link | same | impossible by construction | NOT APPLICABLE |
| three-identity and privileged halves | this review, locally | one identity, no sudo | hosted only (CI #205: passed) |

## 11. Confirmed vulnerabilities fixed (in this review, unverified by a second reviewer)

SR-01 and SR-04: §E.

## 12. Remaining vulnerabilities

None confirmed beyond SR-01 and SR-04, both fixed in the working tree and
not yet committed. Until the owner commits and hosted CI runs, `main` keeps
both.

## 13. Architectural residuals (stated, unchanged)

- A container shares the host kernel; `oci-strict` is not VM isolation.
- Every environment runs as one host uid, 10001; a user namespace per
  environment is not built (F-05, partially completed).
- The opaque CONNECT tunnel cannot see inside TLS: domain fronting through an
  allowed shared host stays possible, bounded by the exact CONNECT
  destination, server-name agreement, byte budgets and connection limits
  (SR-07).
- No DNSSEC; a local stub resolver's own records and upstream are the host's
  (ADR-0074).
- The broker's posture is not in the authority's audit record (protocol 13,
  deferred).
- A sandboxed credential (modes B and C) reaches every descendant of its
  process.

## 14. Existing accepted risks

As [SECURITY.md](SECURITY.md) §5 lists them; none changed here.

## 15. Deferred mechanisms

Host execution and Landlock (M6), approvals and budgets (M6), protocol 13
with F-03's D6, per-entry egress quotas and `model_download` (ADR-0071 OF-3,
ADR-0072 OM-2), F-12's artifact capture (M8).

## 16. Owner decisions required

1. **ADR-0075** (SR-01): accept, revise or reject the fail-closed contract
   for policy files -- an operator-visible change.
2. Whether to commit the evidence step (SR-02) as delivered.
3. SR-06: whether to give `filesystem-canonicalization` a privileged step on
   its disposable runner (a casefold image and a bind mount), as
   `sandbox-workspace` has.
4. SR-05: the code-scanning dismissals (never made here).

## 17. Code scanning

Read 2026-11-22 (authenticated, read-only): 59 open -- 46
`rust/cleartext-logging`, 8 `py/clear-text-logging-sensitive-data`, 4
`rust/cleartext-storage-database`, 1 `py/clear-text-storage-sensitive-data`.
#10-#13 (`py/insecure-protocol`) are fixed (2026-11-20). One alert is new
since the triage of 2026-11-20: #64, `rust/cleartext-logging` at
`crates/dwkd-broker/src/main.rs:172`, "writes config.authority_uid to a log
file" -- a numeric uid, the same false-positive class as the 58 triaged
before (uids and ids, a secret launch's outcome that carries no secret, names
containing "secret"). None is dismissed here (SR-05).

## 18. Platform limitations

The daemons serve on Linux only. macOS and native Windows build and pass
their tests in CI; they do not serve. WSL2 serves as Linux; with Docker
Desktop it has no AppArmor or SELinux and a VM-level swap no Linux setting
reaches. `net.http` runs on `x86_64` only.

## 19. Proposed follow-up

1. A separate reviewer verifies SR-01's and SR-04's corrections and the
   evidence step, and reviews the remediation independently.
2. Hosted CI runs `make namespace-evidence`; until it reports, F-16 stays NOT
   EXERCISED in the records.
3. SR-06's privileged canonicalization step.
4. SR-08: refuse a FIFO or device before `direwolf models` opens it.

## 20. Verdict

**CONDITIONALLY READY** for the final pre-M6 handoff, on these conditions:

1. The owner decides ADR-0075 and commits SR-01's correction (or records
   why not), and SR-04's.
2. A hosted run passes `make namespace-evidence`, so F-16's hostile-resolver
   cases have hosted evidence.
3. An independent reviewer -- not this session -- verifies the corrections
   and reviews the remediation.

Green CI is not this verdict's basis: §9 and §10 are.

---

## A. Security review report

§§1-20 above.

## B. Attack-surface matrix

| Boundary | Attacker | Protected asset | Enforcement | Test | Result | Residual |
|---|---|---|---|---|---|---|
| runtime → authority (DWKP) | B, D | decisions, state, audit | kernel-reported uid before any read; listed uids; one holder per connection; strict decoder (ADR-0041) | `authority-transport`, `authority-security` eval | PASS hosted (CI #205) | the development acknowledgement `--allow-authority-uid` |
| approver → authority | B, D | the approver identity | own endpoint, disjoint uids, uid before read (ADR-0067) | `transport_approver` three identities | PASS hosted | approvals themselves M6 |
| authority → broker | D | single-use authorisation | broker reads only the authority's uid; descriptors re-proved (ADR-0043) | `broker-fs-read` three identities | PASS hosted | a compromised authority is the authority |
| broker → host filesystem | B, I | files outside the workspace | `openat2` beneath, descriptor mutation, no replacement of an unproved object (ADR-0042, -0044) | canonicalization, fs-ops campaigns | PASS hosted; 2 categories NOT EXERCISED (SR-06) | casefold, bind mount |
| broker → host process | B | the host | no production host launch before M6; launch by descriptor, environment from nothing (ADR-0045) | `process-broker` | PASS hosted | host execution M6 |
| workload → container | C, F | host, other environments | `oci-strict`, measured by a digest-pinned probe; a weakened rule refuses (ADR-0047, -0058) | `sandbox-foundation`, `sandbox-proxy-weakened` | PASS hosted | shared kernel; uid 10001 shared |
| workload → network | C, F | everything not granted | relay-uid peer check (F-04), grant + operator ceiling, guard, pinned resolution, SNI agreement, budgets | `sandbox-egress`, `proxy-peer-evidence` | PASS hosted | domain fronting within an allowed host (SR-07) |
| authority → network (`net.http`) | A, G | origins, credentials | decided per hop incl. the ceiling (OF-2); guard; pinning; TLS verified; credential only at its origin | `net-http-evidence` 193 | PASS hosted | no DNSSEC |
| broker → resolver | H | the decided name | absolute query, bounded answer (ADR-0074) | `namespace-evidence` | PASS locally; NOT EXERCISED hosted (SR-02) | stub resolver, other name services |
| operator files → authority | J | policy, secrets, sandbox, allowlist | trusted walk from `/`, no symlink, owner, mode, directories | SR-01 tests; allowlist test | policy files FAIL before, PASS after (SR-01) | root and the authority's own uid are the operator |
| secrets | B, C, G | credential values | handles, one-shot pipe, redaction (ADR-0046) | `secret-broker`, `sandbox-secret` | PASS hosted | descendants of a B/C process |
| durable state, audit | L | decisions and their record | fenced epochs, intent before effect, hash chain, fsync before the answer | `authority-state` (local), restart cases | PASS hosted for restart; state campaign local | deletion of the whole log is detected, not prevented |
| offline model library | K | the library, the host's disk | bounded parsers; pickle/zip refused; private directory; copy bound to the checked file (SR-04) | `direwolf-cli` tests | FAIL before, PASS after (SR-04) | a FIFO blocks the operator's own command (SR-08) |
| CI and supply chain | F | the repository, its secrets | `contents: read`, `pull_request` only, pins checked (F-11), cargo-deny, pip-audit | `dependencies`, `test_ci_supply_chain.py` | PASS hosted | first-party actions trusted |

## C. Finding register

| ID | Severity | Component | Root cause | Exploit evidence | Remediation | Status |
|---|---|---|---|---|---|---|
| SR-01 | MEDIUM (CWE-59, CWE-732) | `dwkd-authority` `state/policy_state.rs` | policy files read outside the trusted-file walk | unit + real-binary tests load a 0602/0620 file, a symlink, a file in a 0777 directory before the fix | trusted walk; read once the authority's uid is known; ADR-0075 Proposed | fixed in the working tree; owner decision; hosted pending |
| SR-02 | MEDIUM (evidence) | CI, `scripts/dw.py` | no hosted job runs the namespace tests with namespaces | CI #205 logs: NOT EXERCISED in every job | `make namespace-evidence` in `sandbox-egress` | hardened; hosted pending |
| SR-03 | LOW (documentation) | `docs/PRE_M6_REMEDIATION.md`, ADR-0068 | a unit-run log read as the only hosted run | CI #201/#205 `sandbox-egress`: the case contained | records corrected | fixed |
| SR-04 | LOW (CWE-367, CWE-400) | `direwolf models import` | check by `symlink_metadata`, open by path, unbounded copy | tests swap a symlink in and grow a file after the check | same-file check; copy bound to the checked length | fixed in the working tree; hosted pending |
| SR-05 | INFORMATIONAL | code scanning | uids and ids flagged as sensitive | 59 open; #64 new, same class | none (owner's dismissal decisions) | open |
| SR-06 | LOW (evidence) | `filesystem-canonicalization` | runner has no casefold filesystem or mount privilege for the test | CI #205: 2 categories NOT EXERCISED | a privileged step on the disposable runner | proposed |
| SR-07 | NOT A VULNERABILITY | CONNECT proxy | opaque tunnel | documented residual | none | accepted residual |
| SR-08 | INFORMATIONAL | `direwolf models` | a FIFO path opened blocks | by inspection | refuse non-regular files before opening | proposed |
| SR-09 | INFORMATIONAL (evidence) | CI | `capability-evidence` (10⁶ chains) and `authority-state-evidence` run locally, not hosted | CI #205 has no such job | a hosted job, or keep as recorded | open |

No finding was left INCONCLUSIVE.

## D. Evidence coverage

| Security property | Unit | Integration | Real process | Hosted | Mutation | Decision |
|---|---|---|---|---|---|---|
| DWKP peer authentication | yes | yes | yes | PASS (three identities) | C3 campaigns | PASS |
| Approver identity (F-18) | yes | yes | yes | PASS (three identities) | 13/13 | PASS |
| Broker reads only the authority | yes | yes | yes | PASS | yes | PASS |
| Filesystem containment | yes | yes | yes | PASS; 2 NOT EXERCISED | yes | PASS with SR-06 |
| Sandbox measurement | yes | yes | real OCI | PASS | yes | PASS |
| Proxy peer uid (F-04) | yes | yes | cross-uid, hidden pid | PASS | 10/10 | PASS |
| Egress ceiling (OF-2) | yes | yes | real broker and origins | PASS (193) | 19/19 | PASS |
| Resolver absolute name (F-16) | yes | -- | hostile namespace (local) | NOT EXERCISED; step added | 3/3 (local) | PENDING HOSTED |
| Real kernel maps (F-05) | yes | -- | real userns (local) | NOT EXERCISED; step added | identity 20/20 | PENDING HOSTED |
| Hidden-pid peer reader (ADR-0049) | yes | -- | real pid ns (local) | NOT EXERCISED; step added | -- | PENDING HOSTED |
| Operator policy-file trust (SR-01) | yes | -- | released binary | pending | 1 of 1 killed (§E) | FIXED, PENDING HOSTED |
| Model import bound (SR-04) | yes | -- | -- | pending | 2 of 3 killed, 1 survived (§E) | FIXED, PENDING HOSTED |

## E. Remediation report

**SR-01.** Files: `crates/dwkd-authority/src/state/policy_state.rs` (the
loader), `crates/dwkd-authority/src/server/mod.rs` (the order), and
`crates/dwkd-authority/tests/transport_server.rs` (both tests; the state
layer's rules TX006 and TX057 keep a test that changes modes out of it),
ADR-0075,
[OPERATIONS.md](OPERATIONS.md), [PRODUCT_SPEC.md](PRODUCT_SPEC.md). Before:
the five unsafe files loaded. Fix: `from_files(profile, files, trusted_owner)`
reads through `read_operator_file`; `server::start` reads the policy after
`socket::prepare` gives the authority's uid. After: each refused before it is
read, the good file loads, the released binary refuses to start naming
`--policy-file`. Mutation check: the trusted read replaced by
`std::fs::read_to_string` -- both new tests fail; restored byte-identically.
Limit: root and the authority's own uid remain trusted.

**SR-02.** Files: `scripts/dw.py` (`task_namespace_evidence`,
`require_namespace_evidence`, `NAMESPACE_EVIDENCE`), `Makefile`,
`.github/workflows/ci.yml` (`sandbox-egress`), `tests/architecture/test_f16_resolver.py`.
Fix: each of the four tests runs alone, must pass, must not print NOT
EXERCISED and must print every marker it prints only after its assertions
held. Test: the arch tests pin the step's place after the sysctl step and
before `proxy-peer-evidence`, every F-16 case by name, and that NOT EXERCISED,
a missing marker or a missed run fails. Limit: hosted run pending.

**SR-03.** Files: ADR-0068, `docs/adr/README.md`,
`docs/PRE_M6_REMEDIATION.md`. The hidden-pid case is recorded as exercised in
`sandbox-egress`.

**SR-04.** Files: `crates/direwolf-cli/src/models/library.rs`,
`crates/direwolf-cli/src/models/tests.rs`. Fix: the opened file must be the
checked one (device and inode on Unix; length and modification time
elsewhere) and exactly its length is copied; a mismatch removes the partial
copy. Tests: a grown file, a shrunk file and a symlink swapped in are each
refused and leave nothing. Mutation checks: the same-file check removed
(SR-04a) and the length check after the copy removed (SR-04c) are each
killed; the bound inside the copy loop removed (SR-04b) **survived** -- the
check after the copy also refuses a grown file, so the in-loop bound only
limits the work done on an endlessly growing source, which a regular-file
test cannot show. Every file restored byte-identically. Limit: on
Windows, a replacement of the same length and modification time is not
distinguished.

## F. Next-stage decision

Not yet ready to begin the final pre-M6 handoff: §20's three conditions come
first. Nothing in this review starts M6.

## G. Validation record

On a clone of `d0fbb24` with the review's 20 files (WSL2 Ubuntu 26.04, one
identity, Docker Engine 29.9.3 through Docker Desktop):

| Check | Result |
|---|---|
| `make fmt-check`, `lint`, `typecheck`, `schema-check`, `docs`, `arch` | pass |
| `make security` | pass |
| `cargo test --workspace --no-fail-fast` | 1708 passed, 0 failed, 126 ignored (hosted-only) |
| pytest | 2173 passed, 18 skipped |
| `make eval-check` | pass |
| `make namespace-evidence` | 4 tests, 9 markers, each exercised |
| `make net-http-evidence` | 193 cases |
| `make sandbox-foundation-evidence` | 109 real OCI + 20 in process; required AppArmor NOT EXERCISED (no AppArmor in this kernel) |
| `make sandbox-egress-evidence` | 133 real OCI + 19 in process |
| `make filesystem-canonicalization-evidence` | pass; casefold and bind-mount NOT EXERCISED, cross-device NOT APPLICABLE (SR-06) |
| `make proxy-peer-evidence` | the same-identity half (six cases, the hidden pid among them) ran; the cross-uid half NOT EXERCISED (one identity) -- non-zero by design |
| `make egress-allowlist-mutations` | 19 of 19 killed |
| `make resolver-mutations` | 3 of 3 killed |
| the fixes' mutations | SR-01a killed (both tests); SR-04a, SR-04c killed; SR-04b survived (§E) |
| each commit's state (1; 1-2; 1-3) | `dwcheck links` pass; the doc and architecture tests, 57 each, pass |

The evidence campaigns, `eval-check` and `security` ran on the first round of
the change; the second round changed tests and documents only, and every
gate above its line was run again on it. Nothing here is hosted evidence: the
owner's commit and a new hosted run are.
