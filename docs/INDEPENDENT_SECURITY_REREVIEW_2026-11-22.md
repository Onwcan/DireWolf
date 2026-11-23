# Second security review of the pre-M6 authority plane, 2026-11-22

**Reviewed revision:** `main` at `f7f5aae2c478e45e926c46adba866964c93109bb`
(CI #209, run 45056220111, 33 of 33 job records success; push workflow run
45056219878, CodeQL default setup, 4 of 4 success). **Verdict: CONDITIONALLY
READY — ACTIONS REQUIRED** for the final pre-M6 handoff (§J). This is a
verdict on the implemented M1–M5 authority plane and the pre-M6 remediation;
nothing here starts or designs M6.

**What kind of review this is.** A context-separated review by an AI agent:
a separate session, started without the conversation that wrote the
remediation, the first review
([INDEPENDENT_SECURITY_REVIEW_2026-11-22.md](INDEPENDENT_SECURITY_REVIEW_2026-11-22.md))
or its fixes, which read that report only as claims to test. It is **not** a
review by an independent person, and it does not satisfy a requirement for
one. The agent is the same kind of model as the one that wrote the code under
review, so it may share that model's blind spots.

**Correction (2026-11-23).** §C.3 and §C.6 first said that only the
`sandbox-egress` job lifts the runner's restriction on unprivileged user
namespaces. Two jobs do: `sandbox-workspace` also lifts it
(`.github/workflows/ci.yml:557-558`), before its evidence task, for the
broker's full-filesystem case. Both run on disposable runners, each for a
stated case; no classification in this report changes. The first review's
§1 and the ledger's F-16 row say the same as the uncorrected text (ISR2-08).

---

## A. Executive summary

**Scope.** Every commit since the first review's baseline (`d0fbb24`): the
four remediation commits `389243d`, `80a6ea1`, `f45eacf`, `f7f5aae`; the
first review's findings SR-01 to SR-09; the pre-M6 ledger's F-01 to F-19; and
a risk-based pass over the authority's trust boundaries (§B). Hosted evidence
was read from the job logs of CI #209 at the exact reviewed SHA, not from its
badge; local evidence was produced on a clone of that SHA.

**Confirmed vulnerabilities: none at CRITICAL, HIGH or MEDIUM.** One LOW
confirmed weakness was found (ISR2-01: `audit_level=full` is counted as kept
on a `net.http` hop whose durable record holds only the URL's digest). No
second enforcement path, no capability widening, no approval path and no
broker effect beyond an authority decision was found.

**Previous fixes.** SR-01 (policy files read through the trusted walk) and
SR-04 (model import bound to the checked file) hold under this review's own
adversarial cases on the reviewed SHA, and both have hosted runs of their
regression tests in CI #209. SR-02's namespace evidence ran hosted for the
first time in CI #209: four tests, nine markers, after the runner's
user-namespace restriction was lifted; the acceptance rule refused every
malformed log this review fed it. F-16 is therefore hosted-verified at
`f7f5aae` (§F).

**Important open items.**

1. **ADR-0075 is Proposed in the committed tree.** An acceptance was stated
   outside the repository before the commit; the repository does not record
   it. Only the owner can record it (§H).
2. **ADR-0022 (Accepted) still prescribes the CLI-local approval design**
   that APPROVALS.md §7 and the Proposed ADR-0063 and ADR-0067 withdraw as
   unsafe (ISR2-05). M6 must not start its approval channel from that record.
3. **Evidence gaps that stay open:** the trusted-file walk's directory
   no-follow and set-id guards are untested by the repository (ISR2-03); the
   SR-04 in-loop bound has no killing test (ISR2-02); casefold and bind-mount
   canonicalization remain NOT EXERCISED hosted (SR-06); mutation campaigns
   and the 10⁶-chain capability campaign remain local-only (SR-09) — re-run
   here on the reviewed SHA: F-02 20/20, F-18 approver 13/13 and F-16 3/3
   mutants killed, 0 escalations in 10⁶ chains.
4. **Governance:** `main` has no branch protection and no ruleset; CI runs
   after a push, not before it, and the "reviewer other than the author" rule
   of [SECURITY.md](../SECURITY.md) is not enforced by the repository (ISR2-07).

**Was the first review's CONDITIONALLY READY justified?** Yes. Its three
conditions were real: SR-01 and SR-04 were vulnerabilities in the
`d0fbb24` tree (both confirmed by reading that revision), F-16 had no hosted
evidence, and its reviewer was not separate from the remediation. Two of its
conditions are now met (the fixes are committed and hosted-tested; the
namespace evidence ran hosted). The third is met only to the extent this
context-separated AI review can meet it. Its findings register was accurate;
this review adds one LOW weakness and eight evidence, documentation,
governance and M6-design items it did not record.

## B. Methodology and threat model

### B.1 Independence and baseline (§0 of the assignment)

| | |
|---|---|
| Checkout | the maintainer's local checkout, branch `main`, HEAD `f7f5aae2c478e45e926c46adba866964c93109bb`, working tree clean at the start (no tracked or untracked change; ignored build caches only), no stash |
| Remote | `origin` = `https://github.com/Onwcan/DireWolf.git`; `refs/heads/main` on the remote = `f7f5aae2…` (read with `git ls-remote`) |
| Previous baseline | `d0fbb244f62d4195e2b36183c886c27207d9cea5` (CI #205, run 45027301654) |
| Commits since | `389243d` (namespace evidence), `80a6ea1` (model import), `f45eacf` (policy files), `f7f5aae` (first review report and records): 20 files, +959/−86. All four authored and committed by the repository's one maintainer account; none is signed |
| Hosted runs | CI #206 (`389243d`, run 45040349466), #207 (`80a6ea1`, 45042538890), #208 (`f45eacf`, 45047354572), #209 (`f7f5aae`, 45056220111): each success. CI #209's 33 job logs were downloaded and read |
| Independence | Context-separated AI agent session; no access to the remediation's conversation; the first review was read as claims. Not an independent person (stated above) |

### B.2 Attackers

| | Attacker | Assumed capability |
|---|---|---|
| A | content steering a model | the actions a run proposes; nothing else |
| B | a compromised runtime (DWKP peer) | its own uid; the DWKP socket; what it was granted |
| C | a compromised sandbox workload | uid 10001 in its `oci-strict` environment; its relay; its workspace |
| D | another local uid | its own uid, no root; may connect to any 0666 socket |
| E | a hostile HTTPS origin or resolver answer | responses, redirects, timing, DNS answers |
| F | a writer of an operator path | only what a deployment mistake gives it (a writable directory or file) |
| G | a crafted model file and its directory | its bytes; the directory if it owns it |
| H | crashes, restarts, concurrency | timing |
| I | a fork pull request | the CI configuration's trigger and token |

Root and the operator are trusted; an attack that needs them is not counted.

### B.3 Production paths traced

`server::start` → `socket::prepare` → `PolicySet::from_files` →
`read_operator_file` → `trusted_file::read`; the DWKP accept loop
(`server::accept`, `peer::peer_credentials`, `connection::serve`) and the
lease fence (`state/lease.rs`); the approver endpoint (`server/approver.rs`);
the host-execution floor (`state/process.rs::approved`, `Floor`); obligation
enforcement per route (`state/plan.rs`, `process.rs`, `workload.rs`,
`net_http/plan.rs`); the `net.http` hop chain and credential rule
(`net_http/mod.rs::HopRequest::next`) and its durable record
(`net_http/ledger.rs`); the F-02 gate (`state/gate.rs`); broker channels
(`dwkd-broker/src/nonce.rs`) and secret delivery to a workload
(`sandbox/workload_secret_plan.rs`, `sandbox/plan.rs`); the broker's log and
event sinks; `direwolf models import` (`models/library.rs`); every workflow's
trigger and permissions; `scripts/dw.py`'s namespace-evidence acceptance rule.

### B.4 Limits

- About 219 000 lines of Rust; this review read the paths above, not every
  line. The M3 lattice, the M4 descriptor handling and the M5 measurement
  were sampled (containment, wildcard and verb tests; `nlink` and exact-name
  checks), not re-derived.
- WSL2 Ubuntu 26.04, kernel 6.18.58.1-microsoft-standard-WSL2, 24 CPUs, one
  OS identity (uid 1000), no passwordless sudo, no AppArmor, no
  `CONFIG_UNICODE` (so no casefold filesystem can exist locally), Docker
  Engine 29.9.3 through Docker Desktop. Three-identity, AppArmor and
  privileged cases are hosted-only here; native Windows builds are blocked by
  Windows Application Control, so Windows and macOS are CI #209's.
- No real third-party target was contacted; every network case is the
  repository's own loopback fixtures.

## C. Remediation re-verification

### C.1 SR-01 to SR-09

| ID | Classification | Evidence |
|---|---|---|
| SR-01 operator policy-file trust | **VERIFIED FIXED** | §C.2; ISR2-03 and ISR2-04 are what stays |
| SR-02 hosted namespace evidence | **VERIFIED FIXED** | §C.3, §F |
| SR-03 F-04 hidden-pid correction | **VERIFIED FIXED** | CI #205's and CI #209's `sandbox-egress` logs: `F04-EVIDENCE {"case":"hidden-pid-admitted-by-uid-and-refused-by-uid","level":"kernel-hidden-pid","contained":true}` from `make proxy-peer-evidence`, after `kernel.apparmor_restrict_unprivileged_userns = 0`. The ledger's correction is accurate. That case is F-04's (a relay whose pid the proxy cannot see) and stays separate from ADR-0049's hidden-pid reader, which only `make namespace-evidence` exercises |
| SR-04 model import TOCTOU and bound | **VERIFIED FIXED** | §C.4; ISR2-02 is what stays |
| SR-05 code scanning | **PARTIALLY VERIFIED** | §C.5 |
| SR-06 casefold, bind mount | **UNVERIFIED** (evidence gap, no vulnerability found) | §C.6 |
| SR-07 domain fronting | **ACCEPTED RESIDUAL** | stated in [NETWORK_SECURITY.md](NETWORK_SECURITY.md) and [THREAT_MODEL.md](THREAT_MODEL.md) R12, unchanged and not broadened; CI #209 `sandbox-egress` carries `fronting-residual-carried-and-bounded` |
| SR-08 FIFO in model import | **ACCEPTED RESIDUAL** (availability, operator input) | §C.4 |
| SR-09 local-only campaigns | **PARTIALLY VERIFIED** | §C.7, §G |

### C.2 SR-01 — operator policy files

**Implementation.** `PolicySet::from_files(profile, files, trusted_owner)`
(`crates/dwkd-authority/src/state/policy_state.rs:122`) reads each file with
`read_operator_file(path, trusted_owner, MAX_SOURCE_BYTES, "--policy-file")`
(`secret/backend/mod.rs:72`), which requires an `AgeFile` path (absolute;
components of `[A-Za-z0-9._-]`; no empty, `.` or `..` component; ≤ 1024
bytes) and, on Linux, `trusted_file::read`
(`secret/backend/trusted_file.rs`):

- `/` is opened `O_PATH|O_DIRECTORY`; each later component `openat`-ed from
  the previous descriptor with `O_PATH|O_DIRECTORY|O_NOFOLLOW`, then
  `fstat`-ed: owner root or `trusted_owner`, a directory, not group- or
  other-writable unless sticky.
- The file is opened `O_RDONLY|O_NOFOLLOW|O_NOCTTY|O_NONBLOCK`, then
  `fstat`-ed on that descriptor: regular, owner root or `trusted_owner`, no
  `0o022` bit, no set-id bit, size ≤ bound; read through `take(bound+1)` and
  re-checked, so growth after the `fstat` is bounded too.
- Every check is on a descriptor the walk itself opened, so a rename or swap
  of an ancestor after it was opened redirects nothing; only root or the
  trusted owner can change a trusted directory, and in a sticky one another
  uid cannot rename or remove the authority's entry.

**Startup order.** `server::start` (`server/mod.rs:474`) calls
`socket::prepare` (directory checked, lock taken, this authority's own dead
socket removed), then reads the policy with `trusted_owner` = the uid that
owns a probe file the process just created in the IPC directory, then checks
peers, approvers, the broker, secrets, the allowlist, starts the store and
attaches the sandbox. `socket::bind` runs only after `start` returns
(`server/mod.rs:329`), so no request can be served before the policy has
loaded; a failed load leaves no listening socket. Composition and the
revision are unchanged: the logical source name is still the file name; a
repeated name is refused in `prepare`; the revision hashes the loaded bytes,
read once. Every `--policy-file` call site is that one (`grep` of
`from_files(`: one production caller, one test).

**This review's adversarial cases**, run on the reviewed SHA through the
public loader (`isr2_policy_loader_adversarial`, scratch only):

| Case | Expected | Observed |
|---|---|---|
| a good file, `0644`, in a `0755` directory of the trusted owner | loads | loads |
| a symlinked **directory** on the path (`…/alias/balanced.toml`, `alias -> real`) | refused | `STORE_UNTRUSTED` |
| the owner's file in a sticky `1777` directory (the documented exception) | loads | loads |
| a file in a group-writable (`0775`) or other-writable (`0757`) directory | refused | `STORE_UNTRUSTED` (both) |
| a set-uid (`04644`) or set-gid (`02644`) file | refused | `STORE_UNTRUSTED` (both) |
| a FIFO | refused without blocking | `STORE_UNTRUSTED` at once (`O_NONBLOCK`, then `fstat`) |
| one byte over 256 KiB | refused | `STORE_UNTRUSTED` |
| a good first file and a symlink as the second | refused | `STORE_UNTRUSTED` |
| `…/../real/…`, `…/./…`, `…//…`, a trailing `/` | refused | "not an absolute path of plain components" |
| `/proc/self/cwd/…`, `/proc/<pid>/cwd/…` (magic links) | refused | `STORE_UNTRUSTED` |
| a directory | refused | `STORE_UNTRUSTED` |
| a named-user ACL granting write | refused (the ACL mask shows as the group write bit) | NOT EXERCISED: no `setfacl` in the WSL image |

The existing cases — group- and other-writable files, a final symlink, a
`0777` directory, a relative path, an untrusted owner — pass as before, and
the released binary refuses each at start (`transport_server.rs`).

**Hosted.** CI #209: `linux::the_policy_loader_refuses_a_file_another_uid_could_change`
and `linux::an_operator_policy_file_is_trusted_only_as_the_other_operator_files_are`
ran and passed in `tests (make test) (ubuntu-latest)` and in
`authority boundary (make authority-transport-evidence)`.

**What stays.** The repository's own tests do not hold the directory
no-follow or the set-id refusal (ISR2-03, §G.1); a write
descriptor another uid opened while the file was still writable survives a
`chmod` (ISR2-04); root and the authority's own uid remain the operator
(ADR-0075, Residuals).

### C.3 SR-02 — required hosted namespace evidence

**Task.** `make namespace-evidence` (`scripts/dw.py`,
`task_namespace_evidence`, `require_namespace_evidence`) runs each of four
broker tests alone (`--exact --nocapture --test-threads=1`) and requires, per
test: exactly one `test result:` line beginning `ok. 1 passed; 0 failed; 0
ignored`; no `NOT EXERCISED` anywhere in the combined stdout and stderr; and
every listed marker. Each marker is printed by the test only after the
assertions it reports have held (read in `egress/tests.rs`,
`sandbox/identity_tests.rs`, `process/tests.rs`); a test whose namespaces
cannot be made returns early without the marker, so a pass without markers
fails the task.

**This review's check of the acceptance rule** (`isr2_checker.py`,
synthetic logs fed to the repository's own function): for each of the four
tests, a complete log is accepted; an empty log, a
summary without markers, `NOT EXERCISED` beside every marker, one marker
missing, the test run twice, a filter that matched nothing (`0 passed`), an
ignored test beside it, and a failed run are each refused — **33 of 33
cases as expected**. The task's own count is 4 tests and 9 markers.

**Workflow.** In `.github/workflows/ci.yml`, two jobs lift
`kernel.apparmor_restrict_unprivileged_userns`, each on a disposable runner
and each for a stated case: `sandbox-workspace`, before its evidence task,
for the broker's full-filesystem case (a tmpfs in an unprivileged user and
mount namespace); and `sandbox-egress`, after every egress evidence step and
its artifact upload, then `make namespace-evidence`, then
`make proxy-peer-evidence` last. In `sandbox-egress` no step is conditional
and no step has `continue-on-error`; the aggregate `ci` job fails unless all
30 required jobs report `success`. The workflow keeps `contents:
read`, `pull_request` (not `pull_request_target`) and no secrets.

**Hosted (CI #209, job `sandbox egress`, 137311929226).** Lines in order:
`kernel.apparmor_restrict_unprivileged_userns = 0`; the six
`F16-EVIDENCE` cases (`f16-search-domain-not-appended`,
`f16-hosts-file-not-consulted`, `f16-nxdomain-fails`,
`f16-answer-past-the-bound-refused` → `RESOLUTION_FAILED`;
`f16-whole-answer-kept` → `3-addresses`; `f16-silent-server-times-out` →
`RESOLUTION_TIMEOUT`); `F05-EVIDENCE` `userns-real-kernel-initial-and-unprivileged-namespace`
and `userns-real-kernel-two-vantages-agree` (`level: kernel`, `contained:
true`); `HIDDEN-PEER uid=1001 pid=none parent=false`; each run `1 passed; 0
failed; 0 ignored`; summary `namespace evidence: 4 tests, 9 markers, each
exercised`; then `make proxy-peer-evidence`.

**Locally:** the same four tests, nine markers, each exercised (WSL2, uid
1000: `HIDDEN-PEER uid=1000 pid=none parent=false`).

**Note on `make test`.** The hosted `make test` jobs print no `NOT
EXERCISED` line at all: `cargo test` captures a passing test's output, so the
namespace tests pass there silently without exercising anything. That is the
green-but-unexercised pattern; only the evidence tasks, which run with
`--nocapture` and require markers, turn such a pass into evidence.

### C.4 SR-04 and SR-08 — `direwolf models import`

**Implementation** (`crates/direwolf-cli/src/models/library.rs`).
`Library::import` takes the library's lock file (`create_new`), sweeps
`tmp/`, checks each source with `symlink_metadata` (must be a regular file,
never followed), sums the checked lengths against the quota, then
`copy_hashing(from, to, checked)` opens the source by path, `fstat`s the
opened descriptor and requires `is_file()` and the same device and inode as
the check (Unix; on other platforms the same length and modification time),
creates the target `create_new` in the private `tmp/`, copies while counting
— refusing and removing the partial copy as soon as more than the checked
length has been read — and refuses again if the total differs. The digest is
of the bytes written; the object is identified through a hard link to the
library's own copy, so what is identified is what is kept.

**Analysis.**

- A symlink swapped in after the check is followed by `File::open`, but the
  opened file must be the checked inode, so only a link back to the same
  file passes — the same bytes.
- Quota: imports are serialised by the lock file; the quota is judged on
  checked lengths and the copy cannot exceed them, so the quota holds after
  the copy.
- Destination: `tmp/` names are `create_new`, the rename into
  `objects/sha256/<digest>` is under the lock; an existing object of that
  digest is kept and not re-verified at import (`verify` re-reads it).
- Non-Unix: a replacement with the same length and modification time is not
  distinguished; the bound and the digest still apply to the bytes actually
  copied, so the residual is "a different content of the same length", not
  an unbounded or unhashed import. Documented in the first review.
- **The surviving mutant SR-04b is not redundant.** The after-copy check
  refuses a grown file only once the copy has ended. A source extended after
  the check — and a sparse extension (`ftruncate`) costs the extender no disk
  — or appended to indefinitely makes a copy without the in-loop bound write
  everything first. The in-loop bound is the only thing that limits the
  library's disk use to the checked length. Measured here
  (`isr2_sparse_extension_after_check_is_bounded`: a 1 MiB source checked,
  then extended sparse by 512 MiB): the reviewed code refuses it with a
  partial copy that never exceeded **1 048 576 bytes** (in milliseconds); with the
  in-loop bound removed (mutant SR-04b) the copy wrote **537 919 488 bytes**
  (6.6 s) before the after-copy check refused it. A source that is appended
  to without end never reaches that check.
  The repository has no test that kills SR-04b (ISR2-02).
- **SR-08.** The pre-check refuses a FIFO or device (`symlink_metadata` +
  `is_file`). Only a swap after the check reaches `File::open`, which then
  blocks until a writer appears; the identity check then refuses it.
  Measured (`isr2_fifo_swapped_in_after_check_blocks_then_is_refused`): the
  import was still blocked after 2 s; once a writer opened the FIFO it was
  refused and nothing was kept. Preconditions: the attacker can replace a name in
  the source's directory during the import; the effect is that the operator's
  own command waits (it can be interrupted). Classification: availability of
  an operator command, operator-input hardening — not a confidentiality or
  integrity issue.

**Hosted.** CI #209: both SR-04 regression tests ran on ubuntu and macOS;
the growth test also on Windows (the symlink test is Unix-only).

### C.5 SR-05 — code scanning

Read 2026-11-22, authenticated and read-only: **59 open**, none dismissed —
46 `rust/cleartext-logging`, 8 `py/clear-text-logging-sensitive-data`, 4
`rust/cleartext-storage-database`, 1 `py/clear-text-storage-sensitive-data`;
the newest is #64 (2026-11-20). Revalidated individually:

| Alerts | Location | Data that reaches the sink | Verdict |
|---|---|---|---|
| #43 | `dwkd-authority/src/server/mod.rs:381` | the start line: socket path, pid, incarnation, policy revision, allowed uids | false positive (identifiers) |
| #52, #64 | `dwkd-broker/src/main.rs:179`, `:172` (the `event` and `log` sinks) | every call site read (66): uids, counts, invocation and process ids, reasons, a runtime step's first stderr line in debug builds only; secrets reach a workload over the launcher's standard input (`sandbox/workload_secret_plan.rs`), never an argument, `--env` or a log | false positive |
| #45 | `dwkd-broker/src/main.rs:271` | the broker's start line: socket path, uids, pid | false positive |
| #53, #56, #58, #60 | `server/approver.rs` test module; `peer/harness.rs` (test harness) | uids in assertions and harness messages | test code |
| #14–#42, #44, #46–#51, #54–#55, #57, #59, #62–#63 | `*/tests.rs`, `*_tests.rs`, `tests/*.rs` | fixture uids, ids and values in tests | test code, not shipped |
| #1–#9 | `scripts/dw.py` (evidence tasks) | runtime versions, probe digests, mutation names and file digests | developer tooling, no secret |

No true positive was found. Dismissal stays the owner's decision; none was
made here.

### C.6 SR-06 — casefold and bind-mount canonicalization

CI #209 `canonical filesystem`: `unicode/casefold-filesystem:
not-exercised:needs-a-casefold-filesystem`,
`mount-crossing/bind-mount-inside-workspace: not-exercised:needs-mount-privileges`,
`hardlink/cross-device-link: not-exercised:impossible-by-construction`.

**Missing evidence, not a found vulnerability.** The resolver does not rely
on the filesystem's lookup for a name: `verify_entry_within`
(`resource/fs/linux/mod.rs:456`) lists the directory and requires a
byte-exact entry, refusing an alias (`NAME_MISMATCH`) or a normalisation
sibling (`NORMALIZATION_AMBIGUITY`); the exact-name check is tested on a
byte-exact filesystem, where the listing logic is the same. Every component
is opened with `RESOLVE_BENEATH|NO_SYMLINKS|NO_MAGICLINKS|NO_XDEV`;
`NO_XDEV` refuses any mount-point crossing, bind mounts included, and is
exercised against `/proc`, `/sys` and `/dev`. Locally this review could not
exercise casefold either: this WSL kernel has no `CONFIG_UNICODE`.

**Cheaper closure than the first review proposed.** No privileged runner
step or casefold image is needed: Linux ≥ 6.13 mounts `tmpfs -o casefold`
inside an unprivileged user and mount namespace, where a bind mount is also
allowed. Both cases could join `make namespace-evidence` in `sandbox-egress`,
which already lifts the namespace restriction for it (§J, action 6).

### C.7 SR-09 — local-only campaigns

Still no hosted job for `capability-evidence` (10⁶ chains),
`authority-state-evidence` or any mutation campaign; they remain
**LOCAL VERIFIED ONLY**. This review re-ran, on the reviewed SHA:
`capability-evidence` — 1 000 000 delegation chains, 4 001 205 attenuation
steps, 378 009 widening attempts refused, **0 escalations** (seed
6768574230983461630); `authority-state-evidence` — 11 test targets, 123
passed, 0 failed (fence before key, replay of a released run, taint
monotonicity, audit-log tamper and removal detection, crash children); and
three mutation campaigns (§G.2). Corroborated again, locally; still not
hosted.

### C.8 F-01 to F-19

"Hosted at `f7f5aae`" means the cited case ran in CI #209's logs.

| Finding | Implementation | Record | Hosted at `f7f5aae` (CI #209) | Classification |
|---|---|---|---|---|
| F-01 taint follows content | built | ADR-0062 Proposed | `taint-fresh-run-decided-by-the-exposed-cell` and the `taint-*` cases (`sandbox-egress`) | HOSTED VERIFIED |
| F-02 endings serialised with effects | built (`state/gate.rs`) | ADR-0064 Proposed | `state_concurrency` in `make test` on Linux, macOS, Windows | HOSTED VERIFIED (unit and contention); mutation review LOCAL ONLY (re-run here: 20 of 20 killed) |
| F-03 effective posture | built; D6 (broker posture in the audit record) deferred | ADR-0065 Proposed | `each_incarnation_records_its_effective_posture_and_a_restart_records_the_change` (`authority-transport`, `make test`) | HOSTED VERIFIED; D6 DEFERRED |
| F-04 proxy peer uid | built | ADR-0068 Proposed | `proxy-peer-evidence`: 6 same-identity cases incl. `kernel-hidden-pid`, 2 `cross-uid` cases with `nobody` (uid 65534) | HOSTED VERIFIED |
| F-05 userns and LSM measured | built; a user namespace per environment not built | ADR-0069, ADR-0070 Proposed | `F05-OBSERVED … userns=UNSUPPORTED:both:shared apparmor=ENFORCED:both:docker-default`; `required-apparmor-enforced-met`, `required-apparmor-unconfined-refused` (`real-oci`); the two real-kernel-map cases (`namespace-evidence`) | **PARTIALLY COMPLETED** (as recorded); what is built is HOSTED VERIFIED |
| F-06 egress allowlist, ceiling | built (OF-1, OF-2); OF-3 not built | ADR-0071, ADR-0073 Proposed | 14 `of2-operator-policy` lines (`net.http`, 193 cases); `sandbox-registry` 20 and `sandbox-hygiene` 44 cases | HOSTED VERIFIED; OF-3 DEFERRED |
| F-07 fuzz jobs | built | -- | the Fuzz workflow did not run at `f7f5aae` (last: schedule run 43855742248 at `ace658b`, 2026-11-16, success; the four commits change no fuzzed parser) | HOSTED at an earlier revision; UNVERIFIED at `f7f5aae` |
| F-08 governance | settings | -- | `GET …/branches/main`: `protected: false`; `GET …/rulesets`: `[]` | **not in place** (ISR2-07) |
| F-09 private reporting | settings | SECURITY.md | `GET …/private-vulnerability-reporting`: `{"enabled":true}` (2026-11-22) | VERIFIED (setting) |
| F-10 evidence archive | tool | EVIDENCE_ARCHIVE.md | n/a | NOT APPLICABLE |
| F-11 action pins | built | `test_ci_supply_chain.py` | `dependencies` job; `make security` locally confirmed each pin against its upstream tag (4 actions, 62 uses) | HOSTED VERIFIED |
| F-12 path anchors | built; artifact capture deferred | ADR-0066 Proposed | `shipped-pack-reads-with-a-trusted-home`, `shipped-pack-refuses-an-overlapping-home`, `shipped-pack-denies-unevaluable` (`broker-fs-read`) | HOSTED VERIFIED; `require_artifact_capture` still unenforceable and therefore denying (`state/plan.rs:491`) — DEFERRED to M8, not weakened |
| F-13, F-15 documents | built | `test_docs_truth.py` | ran in `make test` on three platforms | HOSTED VERIFIED; records now stale in places (ISR2-08) |
| F-14 competitive analysis | documentation | COMPETITIVE_ANALYSIS.md §22 | n/a | NOT APPLICABLE |
| F-16 resolver identity | built | ADR-0074 Proposed | `namespace-evidence`: the six `F16-EVIDENCE` cases | **HOSTED VERIFIED** (first time, CI #209) |
| F-17 workload egress by policy | built | ADR-0061 Proposed | `a_workloads_egress_authorisation_holds_in_the_real_topology` (`sandbox-egress`); `sandbox-registry` 20 cases | HOSTED VERIFIED |
| F-18 ownership, approver endpoint | built; approvals themselves M6 | ADR-0063, ADR-0067 Proposed | `authority-transport`: `cross-uid evidence: 3 tests, 7 cases contained`, `approver evidence: 1 test, 6 cases contained, three identities` (uids 1001, 65534, 999); `sandbox-agent` `hosted-three-identity` cases | HOSTED VERIFIED; mutation reviews LOCAL ONLY (approver identity re-run here: 13 of 13 killed; ownership not re-run) |
| F-19 constrained grant | built | ADR-0060 Proposed | `grant-constrained-https-not-destinations`, `constrained-grant-name-not-granted` (`sandbox-egress`) | HOSTED VERIFIED |

**M5e.2.** Recorded here, as this review was asked to, as PARTIALLY
COMPLETED, with issue #19 as its tracking record. The repository's roadmap
records M5e.2 complete (2026-11-09) and issue #19 is closed (completed,
2026-11-09). This review neither reopens nor re-evaluates it.

## D. New security findings

Severity counts: CRITICAL 0 · HIGH 0 · MEDIUM 0 · LOW 5 · INFORMATIONAL 4.
Only ISR2-01 is a confirmed weakness in enforcement; the rest are evidence,
documentation, governance and M6-design items.

| ID | Severity | Category | Summary | M6 impact |
|---|---|---|---|---|
| ISR2-01 | LOW | confirmed weakness | `audit_level=full` counted as kept on a `net.http` hop whose record keeps only the URL digest | CONDITIONAL |
| ISR2-02 | LOW | evidence gap | no repository test kills SR-04b; the in-loop bound is the only limit on a source extended after its check | NON-BLOCKING |
| ISR2-03 | LOW | evidence gap | the trusted walk's directory no-follow and set-id guards survive the repository's tests | NON-BLOCKING |
| ISR2-04 | INFORMATIONAL | accepted residual (documentation) | a write descriptor opened while an operator file was writable survives `chmod go-w` | NON-BLOCKING |
| ISR2-05 | LOW | documentation inconsistency | Accepted ADR-0022 prescribes the terminal-over-DWKP approval design that Proposed records withdraw | CONDITIONAL |
| ISR2-06 | INFORMATIONAL | potential vulnerability (M6 design) | an approver uid is not a person; an agent running under it is indistinguishable | CONDITIONAL |
| ISR2-07 | LOW | evidence and governance gap | `main` unprotected, no rulesets; CI after push; the two-person rule unenforced | NON-BLOCKING (owner decision) |
| ISR2-08 | INFORMATIONAL | documentation inconsistency | records stale after CI #209; ADR-0075's recorded status; one stale source comment | NON-BLOCKING (ADR-0075: condition 1) |
| ISR2-09 | INFORMATIONAL | hardening opportunity | model library: an existing root not checked; partial copies kept until the next import | NON-BLOCKING |

### ISR2-01 — `audit_level=full` is counted as kept on a `net.http` hop

- **Component.** `crates/dwkd-authority/src/state/net_http/plan.rs:198-210`
  (`obligations`: `Obligation::AuditLevel(_) => true`); the record,
  `net_http/ledger.rs:200-218` (`net.http.intent`/`hop` fields: method, host,
  port, `url_sha256`, body length) and the `net_request`/`net_hop` rows
  (`url_sha256`). The obligation's meaning, [POLICY.md](POLICY.md): "Record
  full canonical arguments, not just the hash".
- **Entry point and prerequisites.** DWKP `net.http` from any runtime whose
  hop an operator rule allows with `audit_level=full`. No shipped pack uses
  the obligation; an operator's own policy does.
- **Root cause.** The route deliberately keeps no path or query in durable
  state (the test `url-digest-only-in-audit`), so it cannot record the full
  canonical request — yet it reports the obligation kept. The file routes
  treat the same obligation as unenforceable and deny
  (`state/plan.rs:491-495`); the process and workload routes keep it
  truthfully (they always record the full argv, `state/process.rs:1271-1280`).
- **Invariant violated.** An `ALLOW` whose obligations the authority cannot
  keep is denied `OBLIGATION_UNENFORCEABLE` (ADR-0050 §6 step 6).
- **Reproduction** (`isr2_audit_level_full_on_a_hop_records_no_url`, scratch
  unit test on the reviewed SHA): a `GET https://capped.example.com/isr2-path?isr2q=1`
  matched by a rule carrying `max_output_bytes=16, audit_level=full` →
  `hop_allowed=true`, `url_path_in_audit_log=false`,
  `url_path_in_kernel_db=false`, `url_sha256_in_audit_log=true`.
- **Impact.** Repudiation only: what a hop sent to an allowed origin is not
  recoverable from the record a rule asked for. No confidentiality,
  integrity or containment boundary is crossed; the hop is otherwise decided
  in full. Under M6 the binding hash includes `obligations` and the human is
  shown them, so an obligation reported kept but not kept would be presented
  as a guarantee.
- **Existing coverage.** `a_tainted_run_reaches_no_new_origin_and_obligations_narrow_or_deny`
  uses the same rule and asserts only the response bound.
- **Minimal remediation.** Treat `AuditLevel` as unenforceable on a hop (deny
  `OBLIGATION_UNENFORCEABLE`), as the file routes do, and say so in ADR-0050
  and POLICY.md. Recording the URL instead would break the route's
  no-path-in-durable-state property and is not recommended.
- **Regression test.** A hop matched by a rule carrying `audit_level=full`
  is denied `OBLIGATION_UNENFORCEABLE` and reaches no broker; the
  `max_output_bytes` case keeps its own rule.
- **Closed when** that test runs hosted in `make test` and a
  `net-http-evidence` case names it.

### ISR2-02 — SR-04's in-loop bound has no killing test

- **Component.** `crates/direwolf-cli/src/models/library.rs:225-230`.
- **Evidence.** Mutant SR-04b (the in-loop check removed) passed every
  repository test (as the first review recorded) and was killed only by this
  review's sparse-extension test: 537 919 488 bytes written for a 1 MiB
  check, against at most 1 048 576 with the check in place (§C.4).
- **Why it matters.** It is the only bound against a source extended after
  its check — sparse extension costs the extender nothing — and the only
  thing that ends the copy of a source appended to without end. A future
  refactor could remove it with every test green.
- **Attacker.** G, with write access to the source file during an import
  the operator runs. **Impact** without the guard: the library's filesystem
  filled. **Today:** no vulnerability; the guard holds.
- **Remediation.** Add the sparse-extension test (this review's version is in
  §G). **Closed when** it runs in hosted `make test`.

### ISR2-03 — two guards of the trusted walk are untested by the repository

- **Component.** `crates/dwkd-authority/src/secret/backend/trusted_file.rs:66`
  (`O_NOFOLLOW` on directory components) and `:95` (set-id refusal).
- **Evidence.** TF-1 (directories followed) and TF-2 (set-id accepted)
  survived the secret-backend unit tests and `transport_server`; only this
  review's adversarial test killed them. TF-4 (writable directories accepted)
  survived the unit tests but is killed by SR-01's `transport_server` tests.
  TF-6 (the pre-read size check removed) survives everything and is
  equivalent: the read is still bounded by `take(max+1)` and re-checked.
- **Reachable consequence without TF-1's guard:** a symlink another uid plants
  in a sticky directory on an operator path could redirect the walk into a
  different trusted directory. Low, and not present today.
- **Remediation.** Turn this review's cases (§C.2 table) into repository tests.
  **Closed when** TF-1 and TF-2 are killed by repository tests in hosted
  `make test`.

### ISR2-04 — a write descriptor outlives `chmod go-w`

- **Component.** `trusted_file::read` judges the file's mode and owner at
  read time; Linux checks write permission when a descriptor is opened, not
  when it is used.
- **Prerequisites.** Another uid opened the policy (or secrets, sandbox,
  allowlist) file for writing while it was still writable — the deployment
  mistake SR-01 was about — and kept the descriptor.
- **Effect.** After ADR-0075's migration step ("`chown`… and `chmod go-w`")
  that uid can still rewrite the file, and the next start reads it.
- **Remediation (documentation).** In ADR-0075's migration and OPERATIONS.md:
  replace a file that was ever writable by another uid (write a new file as
  root or the authority and rename it over the old one) rather than only
  changing its mode. Not detectable by the reader.

### ISR2-05 — ADR-0022 still prescribes the withdrawn approval terminal

- **Records.** [ADR-0022](adr/0022-approval-response-authentication.md)
  (**Accepted**) decides that the CLI passes its controlling terminal to the
  authority over the DWKP socket and the authority reads the keystroke there.
  [APPROVALS.md](APPROVALS.md) §7 marks that design "Not to be built as
  written": a runtime connects to the same socket as the same uid as the CLI
  and could pass a pseudo-terminal it controls and answer its own prompt.
  The withdrawal is in [ADR-0063](adr/0063-principal-ownership-of-sessions-workspaces-and-profiles.md)
  §8 and [ADR-0067](adr/0067-f18-approver-endpoint-identity-boundary.md),
  both **Proposed**; neither lists ADR-0022 under "Would amend", and the ADR
  index row for 0022 does not mention it.
- **Consequence.** The accepted record prescribes a self-approval path; the
  only records that withdraw it are not accepted. Nothing reaches it today
  (the DWKP endpoint receives no descriptor, TX061; no approval operation
  exists).
- **Remediation.** Before M6 builds a channel: accept ADR-0063/0067 with
  ADR-0022 named in "Amends", or a new ADR that amends ADR-0022's CLI-local
  path; mark ADR-0022's index row.

### ISR2-06 — an approver uid is not a person (M6 design)

- **Fact.** ADR-0067 authenticates approvers by kernel uid and says so: "a
  uid is not a person". A coding agent, a script or any process running
  under an approver's uid is that approver to the kernel. External coding
  agents commonly run under the developer's own account.
- **Today.** Not reachable: the approver endpoint reads nothing and holds no
  operation; every `REQUIRE_APPROVAL` denies.
- **For M6.** Decide and test what makes an approval a human's (§I.3 item 2).

### ISR2-07 — repository governance is not enforced

- **Observed (read-only API, 2026-11-22).** `GET repos/Onwcan/DireWolf/branches/main`
  → `"protected": false`, required status checks off; `GET …/rulesets` →
  `[]`. The four remediation commits were pushed straight to `main` by one
  account and are unsigned; CI ran after each push.
- **Gap.** A red CI run does not stop a change reaching `main`;
  [SECURITY.md](../SECURITY.md)'s "a change to `crates/dwkd-authority/` or
  `crates/dwkd-broker/` requires a reviewer other than the author" is not
  enforced by the repository. The ledger's F-08 row ("handled in repository
  settings") is not borne out by the settings as read.
- **Not a workflow vulnerability:** exploiting it needs write access. Fork
  pull requests run `pull_request` with a read-only token and no secrets.
- **Remediation.** The owner's choice: a ruleset on `main` requiring the
  `CI` check (and, if wanted, a pull request), or a recorded decision that a
  single-maintainer repository accepts post-push CI.

### ISR2-08 — records stale after CI #209

Listed in §H items 1, 3 and 4. They describe the state before CI #209
(F-16 and the namespace tests `NOT EXERCISED`, ADR-0075's evidence pending)
and one source comment that predates `--sandbox-config`. The ledger's F-16
row and the first review's §1 also say that only `sandbox-egress` lifts the
runner's namespace restriction; `sandbox-workspace` lifts it too. Reconcile
them together, because `test_docs_truth.py` ties the ledger to the ADR
status lines and the roadmap.

### ISR2-09 — model-library hardening

- `Library::open` (`models/library.rs:285-318`) makes a missing root or
  subdirectory `0700`, but accepts an existing one whatever its owner and
  mode; a library placed in a directory others can write gives them its
  objects and manifests. Operator input; refuse such a root, as the
  authority's own directories are refused.
- A read or write error in `copy_hashing` returns without removing the
  partial `tmp/` file (the next import's sweep removes it); a crash leaves the
  lock file, which the operator removes as the message says.
- An existing object of the same digest is kept without being re-hashed at
  import; `direwolf models verify` re-hashes it.

## E. Security coverage matrix

| Property | Production enforcement | Test evidence | Local (this review) | Hosted (CI #209) | Remaining gap |
|---|---|---|---|---|---|
| DWKP peer authenticated by kernel uid before a byte is read | `server::accept`, `peer::peer_credentials` (nix `SO_PEERCRED`), `PeerPolicy::allows` | `transport_*`, `authority-transport-evidence` | pass (one identity) | HOSTED VERIFIED (3 tests, 7 cross-uid cases) | — |
| One lease holder per connection; fence on epoch, holder, subject, expiry, ownership | `connection::serve` mints the holder; `lease::fenced_ok`, `lease::fence` | `state_*`, `ownership` suites | pass | HOSTED VERIFIED (`make test`) | — |
| Approver is its own uid set, refused unread otherwise; no approval operation | `server/approver.rs`; `approver_place` | `transport_approver` | three-identity half NOT EXERCISED locally | HOSTED VERIFIED (6 cases, 3 identities) | uid ≠ person (ISR2-06) |
| No production host launch | `state/process.rs::approved` → `false` outside `cfg(test)`; `Floor::ApprovalRequired` | `process` suites, `process-broker-evidence` | pass | HOSTED VERIFIED (137 + 6 cases) | — |
| Broker reads only the authority; one authorisation per channel | `listener.rs` peer check; `nonce::Channels` | `private_protocol`, `broker-fs-read` | pass | HOSTED VERIFIED (53 + 6) | a compromised authority is the authority |
| Filesystem containment, exact names, no mount crossing | `openat2` with `RESOLVE_BENEATH`, `NO_SYMLINKS`, `NO_MAGICLINKS`, `NO_XDEV`; listing check | canonicalization campaign | pass | HOSTED VERIFIED; casefold and bind mount NOT EXERCISED | SR-06 |
| Brokered mutation never modifies a multiply-linked object | `exchange/mutate.rs` `st_nlink == 1` | fs-ops campaign | pass | HOSTED VERIFIED (117 + 14) | reading an inside name of an outside inode is a stated limit (ADR-0042) |
| Sandbox measured; weakened rules refused | probe, `oci-strict`, ADR-0047/0058 | `sandbox-foundation`, `sandbox-proxy-weakened` | real OCI pass; required AppArmor NOT EXERCISED (no AppArmor) | HOSTED VERIFIED (109 + 20; 18; E6 16 cases) | shared kernel; one uid 10001 (F-05) |
| `PROXY_ONLY` peer is the relay's uid | F-04 proxy admission | `proxy-peer-evidence` | same-identity half | HOSTED VERIFIED incl. cross-uid | — |
| Egress under grant, ceiling, guard, pinned name | F-06/F-16/F-17/F-19 | `sandbox-egress`, `net-http`, `namespace-evidence` | pass | HOSTED VERIFIED (133 + 19; 193; 9 markers) | domain fronting (SR-07) |
| Credential only at the first origin; redirect drops headers cross-origin | `HopRequest::next` | `net_http` unit + evidence | pass | HOSTED VERIFIED | — |
| Obligations an ALLOW carries are enforced or the action denies | `plan::obligations_enforced`, per-route `obligations` | route suites | pass | HOSTED VERIFIED | `audit_level=full` on `net.http` (ISR2-01) |
| Secrets never in argv, env of the runtime client or logs | `workload_secret_plan.rs` (stdin only), `secret` module | `secret-broker`, `sandbox-secret` | pass | HOSTED VERIFIED (52) | descendants of a B/C process (stated) |
| Operator files trusted only through the walk | `trusted_file::read` | SR-01 tests, secret backend tests | pass + §C.2 cases | HOSTED VERIFIED (2 tests) | ISR2-03, ISR2-04 |
| Model import bound to the checked file and length | `copy_hashing` | SR-04 tests | pass + §C.4 cases | HOSTED VERIFIED (2 tests) | ISR2-02, ISR2-09 |
| Effects and endings serialised (F-02) | `state/gate.rs` | `state_concurrency` | pass | HOSTED VERIFIED | mutation review local |
| Audit chain, intent before effect, restart settlement | `state/audit.rs`, `reconcile_open` | `authority-state-evidence`, restart cases | pass (123 tests, 11 targets) | restart HOSTED VERIFIED (7) ; state campaign not hosted | SR-09 |
| Capability attenuation never widens | `capability/*` | unit, proptest, `capability-evidence` | pass (10⁶ chains, 0 escalations) | unit HOSTED; 10⁶ campaign not hosted | SR-09 |
| CI: read-only token, no secrets, no `pull_request_target`, pinned actions | `.github/workflows/*.yml` | `test_ci_supply_chain.py`, `make security` | pass | HOSTED VERIFIED | branch not protected (ISR2-07) |

## F. Hosted CI evidence

| Run | SHA | Result | Read |
|---|---|---|---|
| [CI #209, 45056220111](https://github.com/Onwcan/DireWolf/actions/runs/45056220111) | `f7f5aae` | 33/33 success | all 33 job logs |
| [Push on main #27, 45056219878](https://github.com/Onwcan/DireWolf/actions/runs/45056219878) | `f7f5aae` | 4/4 (CodeQL actions, python, javascript-typescript, rust) | job results |
| CI #208, 45047354572 | `f45eacf` | success | summary |
| CI #207, 45042538890 | `80a6ea1` | success | summary |
| CI #206, 45040349466 | `389243d` | success | summary |
| [CI #205, 45027301654](https://github.com/Onwcan/DireWolf/actions/runs/45027301654) | `d0fbb24` | success (pre-remediation) | all 33 job logs (SR-03; comparison below) |

**Evidence summaries in CI #209's logs.** `net.http` 193 cases;
`canonical filesystem` complete (3 categories NOT EXERCISED, §C.6);
`sandbox PROXY_ONLY hard rules weakened` 18 real-OCI cases, E6 16 cases over
15 rows; `D11 hardening` 25 of 25; `sandbox live-environment capacity` 4;
`sandbox runtime restart` 7 privileged-OCI; `brokered fs.read` 53 + 6;
`sandbox hygiene` 44; `sandbox workspace` 17 + 47 (incl. 27 privileged-OCI and
the full-filesystem cases); `sandbox agent` 51 + 26; `sandbox foundation` 20
in-process + 109 real-OCI, required AppArmor met and unconfined refused;
`sandbox secret` 40 + 52; `authority boundary` 7 cross-uid cases and 6
approver cases with three identities; `filesystem operations` 117 + 14;
`process broker` 137 + 6; `sandbox registry` 20; `sandbox workload` 152;
`sandbox release` 62 + 45; `M5 gate` re-judged 77, 107 and 193 cases;
`sandbox egress` 133 real-OCI + 19 in-process, then `namespace evidence: 4
tests, 9 markers, each exercised`, then F-04's 6 + 2 cases.

**NOT EXERCISED lines in CI #209**, all accounted for:
`filesystem-operations` and `process-broker` unit runs (6 each: the
namespace-dependent unit tests -- F-16's resolver, F-05's maps, the
hidden-pid tests of ADR-0049 and F-04, the full-filesystem case -- which
`sandbox-egress` and `sandbox-workspace` exercise instead) and `canonical filesystem` (3, §C.6).
`make test` prints none because cargo captures passing output (§C.3).

**Compared with CI #205.** All 33 job logs of CI #205 were also read and
their evidence summaries (148 lines) diffed against CI #209's (149). Three
differences, each expected: `authority boundary`'s `transport_server` run
went from 15 to 17 passed (SR-01's two tests); the E6 manifest digest
differs (it covers raw observations, which carry run-specific ids); and
`namespace evidence: 4 tests, 9 markers, each exercised` is new. No case
count fell and no summary disappeared.

## G. Mutations and adversarial testing

All experiments ran in a clone of the reviewed SHA in WSL (`~/dw-rr2`), never
in the checkout. Each mutant was applied by exact, unique text replacement,
run against the repository's own tests for that guard and then against this
review's experiment, classified (a compile error is not a kill), and its file
restored and compared by SHA-256.

### G.1 This review's mutants

"Repository" is the repository's own tests for the guard: for the walk, the
`dwkd-authority` unit tests `secret::backend`, `sandbox::operator`,
`egress_allowlist` and the whole `transport_server` binary; for the import,
`direwolf-cli`'s `models::` tests. "ISR2" is this review's experiment.

| Mutant | Change | Repository | ISR2 | Reading |
|---|---|---|---|---|
| SR01-a | `from_files` reads with `std::fs::read_to_string` | **killed** (both SR-01 tests) | killed (11 of 17 cases broken; the FIFO case blocked the read) | the fix is held |
| TF-1 | directory components opened without `O_NOFOLLOW` | **survived** | killed (symlinked directory) | ISR2-03 |
| TF-2 | set-id bits accepted | **survived** | killed (set-uid, set-gid) | ISR2-03 |
| TF-3 | the sticky exception dropped | killed (secret backend; SR-01; egress allowlist start) | killed | held |
| TF-4 | group/other-writable directories accepted | killed by `transport_server` only; survived the unit tests | killed | held (by SR-01's tests) |
| TF-5 | the final component followed | killed (secret backend; SR-01) | killed | held |
| TF-6 | the pre-read size check removed | survived | survived | **equivalent**: `take(max+1)` and the post-read check still bound the read |
| SR-04a | the same-file check removed | killed (`a_source_swapped_for_a_symlink_after_its_check_is_refused`) | — (not targeted) | held |
| SR-04b | the in-loop length bound removed | **survived** | killed (537 919 488 bytes written for a 1 MiB check) | ISR2-02 |

Every mutated file was restored and matched its SHA-256; afterwards the
clone was at `f7f5aae` with `git status` empty.

### G.2 The repository's own campaigns, re-run independently

The three campaigns most relevant to M6 were re-run on the reviewed SHA, one
at a time, through the repository's own drivers (baseline first, each mutant
built and judged, each file restored and its digest checked):

| Campaign | Boundary | Result | Time |
|---|---|---|---|
| `make authority-concurrency-mutations` | F-02 gate (ADR-0064) | **20 of 20 killed** (stages: authority unit suites, `state_concurrency`) | 1818 s |
| `make approver-identity-mutations` | F-18 approver endpoint (ADR-0067) | **13 of 13 killed** (authority unit suites; `transport_approver` against the real server) | 1130 s |
| `make resolver-mutations` | F-16 resolver (ADR-0074) | **3 of 3 killed** (`f16_hostile_resolver_inner` failed at the mutated assertion each time) | 7 s, incremental builds |

`git status` in the clone was empty after each. A first run of the F-02
campaign was interrupted by this review (its driver was stopped to shorten
the queue) and is not counted; the file it left mutated was restored with
`git checkout` in the clone and the campaign re-run from its baseline.

**Not re-run here, for time:** `authority-ownership-mutations` (F-18
ownership, 27 mutants), `egress-allowlist-mutations` (F-06, 19),
`policy-anchor-mutations` (F-12, 19), `proxy-peer-mutations` (F-04, 10),
`posture-mutations` (F-03), the sandbox campaigns. Their results stand as
the repository records them, unverified by this review.

### G.3 Other experiments

- The namespace-evidence acceptance rule against 33 synthetic logs (§C.3).
- `isr2_audit_level_full_on_a_hop_records_no_url` (ISR2-01).
- `isr2_fifo_swapped_in_after_check_blocks_then_is_refused` (SR-08).

### G.4 Limits

No mutant of the broker's channel, the lease fence, the DWKP decoder or the
capability lattice was written by this review; those rely on the
repository's campaigns (§G.2) and fuzz jobs. Casefold, bind mounts, AppArmor
and three-identity cases could not run locally (§B.4).

### G.5 Local validation record

Clone of `f7f5aae` at `~/dw-rr2` (WSL2 Ubuntu 26.04, kernel
6.18.58.1-microsoft-standard-WSL2), `CARGO_TARGET_DIR=~/dw-m3e-target`, one
task at a time:

| Command | Exit | Result |
|---|---|---|
| `make fmt-check` | 0 | pass |
| `make lint` | 0 | clippy and ruff pass |
| `make typecheck` | 0 | mypy: no issues in 123 files |
| `make schema-check` | 0 | pass |
| `make docs` | 0 | `dwcheck links` ok |
| `make security` | 0 | cargo-deny (workspace, fuzz) ok; pip-audit ok; 4 action pins match upstream tags |
| `cargo test --locked --workspace --no-fail-fast` | 0 | **1708 passed, 0 failed, 126 ignored** (80 test targets, doc tests included; the ignored are the hosted-only real-OCI, privileged and three-identity tests) |
| `uv run --frozen python -m pytest` | 0 | **2173 passed, 18 skipped** (skips: POSIX-only and shallow-clone guards, ADR-0057's superseded records) |
| `make namespace-evidence` | 0 | 4 tests, 9 markers, each exercised |
| `make arch` | 0 | `dwcheck` all and closure ok |
| `make eval-check` | 0 | pass (794 s) |
| `make capability-evidence` | 0 | 1 000 000 chains, 0 escalations (42 s) |
| `make authority-state-evidence` | 0 | 123 passed, 0 failed, 1 ignored (the crash child, run by the crash tests) (43 s) |
| `make authority-concurrency-mutations` | 0 | 20 of 20 killed |
| `make approver-identity-mutations` | 0 | 13 of 13 killed |
| `make resolver-mutations` | 0 | 3 of 3 killed |

Hosted `make test` on ubuntu ran 2171 pytest passed, 20 skipped (two more
skips than locally: the shallow-clone ADR-history guards).

## H. ADR and documentation consistency

1. **ADR-0075** reads `**Status:** Proposed` in the committed tree, with
   "hosted evidence pending". An acceptance was stated outside the repository
   on 2026-11-22, before the commit; the repository does not record it, and
   this review changes no status. The minimum record of an acceptance, the
   owner's to make: the Status line to Accepted with its date; `dwcheck adr
   --record` to add the file's digest to `docs/adr/accepted.sha256` in the
   same commit (the history anchor then binds it); the index row in
   `docs/adr/README.md`; and the ledger in `PRE_M6_REMEDIATION.md`. Its
   Evidence section can at the same time cite CI #209.
2. **ADR-0022 against ADR-0063/0067** (ISR2-05).
3. **Stale after CI #209** (ISR2-08): `PRE_M6_REMEDIATION.md` (F-16 row
   `NOT EXERCISED`, "What is open", ADR-0075 "hosted evidence pending");
   ADR-0074's hosted state; ADR-0075's Evidence; `NETWORK_SECURITY.md:92`;
   `COMPETITIVE_ANALYSIS.md:1458`. `test_docs_truth.py` couples the ledger's
   Hosted column to the ADR status lines and the roadmap, so these change
   together.
4. **A stale source comment:** `server/mod.rs:173-177` (`Served`) says
   `serve` has no option that attaches an execution environment and that a
   production deployment needs one; `server/sandbox.rs` is `serve
   --sandbox-config` (M5d.2, ADR-0052 §2a), which does.
5. **Historical documents are historical.** The first review's "fixed in the
   working tree, not yet committed" and "hosted run pending" describe
   `d0fbb24` plus its working tree; they were true then.
6. **Unaccepted decisions:** ADR-0051 and ADR-0060 to ADR-0075 (17 records)
   are Proposed. Every pre-M6 remediation ADR is among them.
7. **Deferred mechanisms, unchanged:** protocol 13 with F-03's D6; Landlock
   with host execution (M6); F-06's OF-3 and per-entry quotas; model
   downloads after M7 (ADR-0072 OM-2); F-12's artifact capture (M8); a user
   namespace per environment (F-05).
8. **Build order**, as recorded: M6 → M3.5 → M7 → M8 → … (ROADMAP.md line
   55); M3.5 stays after M6 and before M7.

## I. M6 readiness — analysis only

### I.1 Guarantees M6 can build on

Read in source by this review and hosted-tested in CI #209, unless stated.

- Subjects come only from the kernel: DWKP and approver peers by
  `SO_PEERCRED` uid before a read; leases bind a minted holder per
  connection, epoch, subject and ownership.
- No runtime field claims a human: `approved`, `approval_id`, `tty`,
  `auto_approve`, `yolo` and the like are unknown fields on the wire
  (ADR-0067 §4; the decoder's refusal was not re-tested here); the approver
  endpoint reads nothing; every `REQUIRE_APPROVAL` denies; no production host
  launch (`approved()` is `false` outside `cfg(test)`).
- Effects and endings are serialised in one process (F-02), so a revocation
  that commits leaves no decided effect still to reach the broker.
- Obligations that cannot be kept deny (except ISR2-01).
- Per-hop `net.http` decisions, a pinned resolution of the decided name
  (F-16) and the operator ceiling (F-06).

### I.2 Blocking issues

None found in the existing code.

### I.3 Prerequisites before M6 implementation

1. **Decide the approval channel on an accepted record.** ADR-0022's
   CLI-local terminal design is Accepted and withdrawn only by Proposed
   records (ISR2-05). Accept ADR-0063/0067 or write the ADR that amends
   ADR-0022 before M6 builds a channel.
2. **An approver uid is not a person** (ISR2-06). M6 has to state what makes
   an approval human: a dedicated approver account that runs no agents, a
   trusted approver client rendering kernel-canonical text, and a decision on
   whether an approval needs a presence factor beyond the uid. External
   coding agents run under the developer's own uid by default; if that uid
   is an approver, they can approve.
3. **Define obligation semantics before binding them.** The binding hash
   includes `obligations` (APPROVALS.md §2); an obligation the authority
   says it kept but did not (ISR2-01) would be bound and displayed as a
   guarantee.
4. **Accept or revise the remediation ADRs M6 builds on** — ADR-0063
   (ownership), ADR-0064 (gate), ADR-0067 (approver endpoint), ADR-0062
   (taint) — since M6's binding, revocation and taint conditions rest on
   them.

### I.4 Risks M6 must address explicitly

| Risk | What exists | What M6 must add or test |
|---|---|---|
| Replay, substitution | single-use broker channels; kernel-minted ids | atomic burn in the same transaction as the intent; `request_id` burned on acceptance; replay across restart refused |
| Runtime vs approver identity | disjoint uid sets, no override | the store refuses an approval whose approver principal is the requester's; ISR2-06 |
| Authorisation change during approval | per-decision re-evaluation | re-decide at spend: policy revision, capability set, taint, environment and obligations equal to those bound, or deny |
| File, executable, DNS, environment swap | resolution by descriptor; executable identity by hash; DNS pinned per hop | bind inode/device, executable digest, pinned address set + SNI, environment profile; re-verify immediately before the effect |
| Concurrent single-use consumption | SQLite `BEGIN IMMEDIATE`; F-02 gate | burn and intent in one transaction; a property test with N parallel spenders |
| Standing-grant widening | none yet (`StandingGrantState::Unavailable`) | 90-day cap with no override; `require_untainted_run` default; a grant never covers a scope wider than its predicate |
| Parent/child budget laundering, underflow, overflow, amplification | per-run `NetBudget` with saturating arithmetic | hierarchical subtractive ledger; checked arithmetic; a child's spend charged to every ancestor in one transaction; fan-out bound |
| Prompt injection into the authoritative display | none yet | kernel-rendered text from canonical data; model text only in a labelled region; control characters stripped |
| External agents' own approvals | refused on the wire (ADR-0067) | keep them refused; test that an ACP/MCP permission grant is never an approval (ADR-0051) |
| Reuse after revocation, cancellation, restart | revocation ends leases and runs (F-18), gate (F-02), restart reaps runs | approval rows tied to run and principal, invalidated by revocation and by restart; a sandboxed workload already started outlives a revocation until its environment is destroyed (gate §"A sandboxed launch's section") — state it |
| Unattended degradation | `REQUIRE_APPROVAL` denies | unattended stays DENY with no approver online; no queueing that executes later without re-decision |

### I.5 Acceptance tests M6 should carry (beyond APPROVALS.md §10)

- An approval burned by two concurrent spenders succeeds exactly once.
- An approval granted on a clean run cannot be spent after the run is
  tainted; after a policy revision change; after the inode, executable
  digest, pinned addresses or environment profile changes.
- A runtime uid that is also listed as an approver is refused at start
  (exists) and an approval whose approver principal equals the requester's
  is refused by the store.
- A connection on the DWKP socket can never produce an approval, whatever
  it sends (including descriptors); a pty passed anywhere is never read.
- Revocation after an approval and before its spend denies the spend; a
  restart invalidates every unburned single-use approval.
- Budget: a child cannot spend more than its parent's remainder; arithmetic
  at `u64::MAX` and zero refuses.
- The rendered prompt contains no byte of model-authored text in the
  authoritative region and no terminal control sequence.

### I.6 Recommended order within M6 (not started here)

1. Records: accept or amend ADR-0022/0063/0067 (§I.3).
2. Canonical binding and its hash, with property tests, before any registry.
3. The approval registry: rows, scopes, expiry, atomic burn in the intent
   transaction; still unreachable from any endpoint.
4. The approver client and the approver endpoint's operation, rendering
   from canonical data.
5. Standing grants, then the hierarchical budget ledger.
6. Unattended degradation and the adversarial suite (replay, substitution,
   drift, laundering, fatigue, amplification, external-agent claims).

## J. Final verdict and handoff

**CONDITIONALLY READY — ACTIONS REQUIRED.** No security blocker was found;
the verdict is conditional because decisions and evidence the handoff depends
on are not yet in the repository.

**Conditions for the handoff.**

1. ADR-0075's state recorded in the repository by the owner (accepted as
   stated, or kept Proposed deliberately).
2. ADR-0022's CLI-local approval design superseded by an accepted record —
   or recorded as an explicit M6 entry decision — before M6 builds an
   approval channel (ISR2-05).
3. ISR2-01 decided: `audit_level=full` on `net.http` either denied as
   unenforceable or defined as what the record keeps.

**Priority-ordered next actions.**

1. Owner: record ADR-0075; decide ISR2-05's route.
2. Fix ISR2-01 with its regression test, as its own change.
3. Add the missing tests: SR-04b sparse extension (ISR2-02) and the walk's
   directory no-follow and set-id cases (ISR2-03).
4. Reconcile the records stale after CI #209 (ISR2-08) in one change, with
   ADR-0075's record if it is accepted.
5. Decide branch protection for `main` (ISR2-07).
6. Extend `make namespace-evidence` with a casefold tmpfs and a bind mount
   in an unprivileged namespace (SR-06).
7. Decide whether any of SR-09's local-only campaigns gets a hosted job.
8. Dismiss SR-05's alerts as false positives or keep them, as the owner
   prefers.

**Owner decisions genuinely required:** ADR-0075; ISR2-05's route
(accept ADR-0063/0067 or a new ADR); ISR2-07 (branch protection); SR-05
dismissals; whether to commit this report.

**Deferred, and why:** a user namespace per environment (no supported
runtime offers one per container); protocol 13 with D6 (designed, not
required before M6); Landlock with host execution (M6); OF-3 and model
downloads (after M7); artifact capture (M8) — each recorded in its ADR.

**May M6 begin?** Yes, once conditions 1–3 are met. Conditions 1 and 2 are
records; condition 3 is either a fail-closed change to one route's
obligation check (with its own verification) or a documented definition.
None weakens a boundary that exists today.

**What this review changed in the repository:** this report, added
unstaged. No source, test, workflow or record was modified; every experiment
and mutant ran in a scratch clone; nothing was staged, committed, pushed or
branched, and no issue, pull request, alert or setting was touched.
