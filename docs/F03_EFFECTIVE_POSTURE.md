# F-03: effective security posture

What DireWolf's daemons say about the security they actually give, what F-03
found missing, what was changed, and what is still not said. The decision is
[ADR-0065](adr/0065-f03-effective-posture-is-reported-and-recorded.md)
(**Proposed**).

## 1. Source and scope

F-03 comes from the security remediation program's audit of 2026-11-11/12,
which recorded it in one line: *weakening start-up switches invisible to
authority/audit*. The audit's full text is not in this repository; the scope
below is derived from the code and the accepted records, not from it:

- every development or evidence acknowledgement either daemon accepts, and
  what each one reports;
- the broker's hardening posture (ADR-0053) and the sandbox's measured
  assurance (ADR-0047, ADR-0052), as reported against as enforced;
- the operator-facing diagnostics that exist today (`direwolf doctor`, the
  daemons' stderr, `audit.log`).

Out of scope: user-namespace remapping and LSM measurement (F-05), the egress
allowlist (F-06), the resolver (F-16), the proxy socket's peer (F-04), M6's
approver and M17's connected `doctor`.

## 2. Effective posture, and the five conditions

The **effective posture** of a daemon is what holds of each control it owns
or depends on *now*, from the facts its own decisions read -- not what its
configuration intends. Each control is one record:

| Condition | Meaning |
|---|---|
| `ENFORCED` | the property is verified: observed from the kernel or host, or -- where nothing can be observed -- fixed by this build and the operator's configuration. A control kept by refusing (no credential hop where swap is possible) is enforced, with what it refuses named. |
| `REDUCED` | an acknowledgement the operator gave weakens the control; the record names the flag and the guarantee lost. |
| `UNVERIFIED` | what would establish the property could not be read, or is not visible to this daemon. Never taken for enforced. |
| `UNSUPPORTED` | this build or platform cannot give the control (the worker's syscall program off `x86_64`). |
| `NOT_APPLICABLE` | the control does not apply to this configuration (no broker; no execution environment; no `net.http` hop on an unsupported architecture). |

Every record also says whether its facts were `OBSERVED` or `CONFIGURED`.
These are observations, not authorisation decisions: the existing refusal
outcomes (`DENY`, `UNKNOWN`, the broker's refusals, an environment's failure
class) keep their meaning and are not renamed. There is no score: the
summary lists what is not enforced, and one reduced control is listed
however many others hold.

## 3. Inventory of the implemented controls

Before F-03 / after F-03. "At start" facts are read once; "per hop" facts
before every `net.http` hop; "per environment" at each preparation and
again before each workload starts.

### The broker (`dwkd-broker`)

| Control (id) | Property | Weakened by | Checked | Refuses | Reported before | Reported after |
|---|---|---|---|---|---|---|
| `broker.identity.authority` | the broker is not the authority's uid | `--allow-shared-authority-uid` | at start (kernel uid) | serving | `REDUCED ASSURANCE` sentence | record, `OBSERVED` |
| `broker.identity.sandbox` | neither daemon has uid 10001/10002 | nothing | at start | serving | refusal message | record |
| `broker.memory.dumpable` | not dumpable (`PR_SET_DUMPABLE` 0) | `--allow-dumpable` | set at start | serving if it cannot be set | sentence; the setting assumed | record, **read back** |
| `broker.memory.core_limit` | `RLIMIT_CORE` 0, soft and hard | nothing | set at start | serving if it cannot be set | nothing; assumed | record, **read back** |
| `worker.startup_window` | no process of the broker's uid can trace a worker or launch helper before it hardens (Yama ≥ 1, or execute-only binary under `fs.suid_dumpable` 0 or 2) | `--allow-traceable-workers` | at start **and per hop** | serving; each hop | sentence only if open **at start**; nothing per hop | record always `REDUCED` when acknowledged; `posture_acknowledged` per hop it admits against the facts |
| `worker.credential_swap` | a credential's memory -- the broker's, then its worker's -- cannot reach swap (no device, or a zero `memory.swap.max` on the cgroup path) | `--allow-swappable-workers` | at start **and per hop** | every credential hop | sentence only if swap was possible **at start**; nothing per hop; unreadable reported as `possible` | as above; unreadable is `unknown` and `UNVERIFIED` |
| `worker.syscall_program` | a worker's seccomp program has kernel evidence on this architecture | nothing | build | every `net.http` hop | `NOTICE` sentence | record, `UNSUPPORTED` off `x86_64` |
| (per worker) | filter installed, `no_new_privs`, untraced, not dumpable | nothing | **per worker** (`vouch.rs`) | that hop | `http_worker_vouched` / `http_worker_refused` | unchanged |
| `egress.resolver` | names resolve through the host's resolver | `--allow-evidence-egress` | start | -- | `EVIDENCE EGRESS` sentence | record `REDUCED` |
| `egress.trust_anchor` | `net.http` trusts Mozilla's roots | `--allow-evidence-trust` (only beside the fixture resolver) | start | -- | `EVIDENCE TRUST` sentence | record `REDUCED` |
| `environment.topology` | `PROXY_ONLY` environments only | `--allow-evidence-topology` | start | `NO_NETWORK` otherwise | `EVIDENCE TOPOLOGY` sentence | record `REDUCED` |
| `environment.workspace` | every workspace bounded and of the workspace group | `--allow-unverified-workspace` | per environment | `WORKSPACE_UNVERIFIED` | sentence | record `REDUCED` |
| `host.page_zeroing` | `init_on_free` (recommended) | -- | start (command line) | nothing | `deployment_posture` field | record `RECOMMENDED`, never in the summary |

Hibernation is documented (`BROKER_HARDENING.md`) and printed by
`make d11-posture`, not read by the broker.

### The authority (`dwkd-authority serve`)

| Control (id) | Property | Weakened by | Checked | Refuses | Recorded before | Recorded after |
|---|---|---|---|---|---|---|
| `authority.memory.dumpable` | not dumpable | `--allow-dumpable` | set at start | serving if it cannot be set | stderr sentence | `authority.posture`, **read back** |
| `authority.memory.core_limit` | `RLIMIT_CORE` 0 | nothing | set at start | as above | nothing | `authority.posture`, read back |
| `authority.peer_boundary` | no DWKP peer has the authority's uid (such a peer can open `kernel.db`) | `--allow-authority-uid` | start; `SO_PEERCRED` per connection | serving | stderr sentence | `authority.posture` |
| `broker.identity` | the broker is neither the authority's uid nor a peer's | `--allow-shared-broker-uid` | start; `SO_PEERCRED` per exchange | serving | stderr sentence | `authority.posture` |
| `broker.posture` | the broker's own controls | -- | **not visible to the authority** | -- | nothing | `authority.posture`: `UNVERIFIED` |
| `policy.host_execution` | `security.allow_host_execution` off | `--allow-host-execution` | start | `HOST_EXECUTION_DISABLED` | `authority.activated` | also `authority.posture` |
| `environment.workspace` | every run's workspace bounded, measured | `[workspace] unverified_evidence` | start; per environment | the broker refuses it unless acknowledged | stderr sentence; `workspace_contract` per environment | also `authority.posture` |

### The sandbox's measured assurance (unchanged; audited)

Re-read against ADR-0047 and ADR-0052; no reporting defect was found:

- the kind **declares** a level; a measurement **measures** it only if every
  required invariant is present exactly once and `PASS`; the **effective**
  level is the lower of the two (`sandbox.rs`, `EffectiveAssurance::of`);
- a `FAIL`, an `UNOBSERVABLE`, a missing or a repeated invariant measures
  `NONE`, and the environment is refused with its failure class
  (`Judgement::usable`, `failure`); there is no partial credit;
- `environment.ready` / `environment.refused` record `declared`, `measured`,
  `effective`, `failed` and `unobservable` separately; the host-side and
  in-container invariants keep their names (`Host*`, `Container*`);
- a `READY` environment is re-judged from the runtime's record before each
  workload starts, and a drifted one is recorded `environment.drifted` and
  never used;
- the workspace contract an environment was judged under is in its
  `environment.intent_recorded` record (`workspace_contract`), and now also
  in the incarnation's `authority.posture`.

Tests that hold it: `sandbox.rs` (`every_pass_earns_the_declared_level_and_no_more`
and the failure-class tests), the workload and lifecycle evidence.

### Diagnostics

`direwolf doctor` connects to no daemon. Before F-03 it listed implemented
mechanisms as "not checked yet -- no implementation exists" under milestones
already delivered, and ended "no security mechanism is implemented yet".
It now names each mechanism it does not check and where its owner reports it.

## 4. Confirmed defects

| | Defect | Impact | Root cause |
|---|---|---|---|
| D1 | `--allow-traceable-workers` / `--allow-swappable-workers` on a host safe at start: no `REDUCED ASSURANCE` line, and `WorkerPolicy` admitted every hop **without reading the host** | a swap device added or Yama lowered after start: credential hops run with swappable memory, workers start in an open window -- neither refused nor reported anywhere | the start-up reduction was computed only from the facts at start, and the per-hop check skipped the read when acknowledged; the unit test pinned the silence |
| D2 | the authority's own switches (`--allow-dumpable`, `--allow-authority-uid`, `--allow-shared-broker-uid`, `[workspace] unverified_evidence`) reached stderr only | `audit.log` of a weakened incarnation -- one whose peer could open `kernel.db` -- was indistinguishable from a hardened one's | the server logged them as operational lines; only the policy flag was recorded |
| D3 | an unreadable `/proc/meminfo` reported `swap=possible` | an unknown state reported as a known one (the decision was already fail-closed) | `Swap` had no unknown case |
| D4 | the dumpable and core-limit settings were reported, never read back | a configured protection presented as observed | the report used the call's success |
| D5 | `doctor` said no security mechanism was implemented | an operator told nothing exists where several are enforced | stale M1 text |
| D6 | the broker's posture is invisible to the authority | `audit.log` cannot say under which broker acknowledgements an effect ran | the private protocol carries none of it |

D1-D5 are fixed. D6 is recorded, not fixed: §8.

## 5. What changed

- `dwkd-broker`: `effective.rs` (records, lines, summary); `main.rs` (records
  said at start before the decision; an acknowledgement is reduced on a
  safe host too); `http/mod.rs` (`WorkerPolicy` reads under an
  acknowledgement and reports what it admitted, `posture_acknowledged`);
  `posture.rs` (`Swap::Unknown`); `hardening.rs` (`observed`); `config.rs`
  (each acknowledgement spelled once).
- `dwkd-authority`: `posture.rs` (records); `server/mod.rs` (records said and
  written before the socket is bound); `server/hardening.rs` (`observed`);
  `server/sandbox.rs` (returns the workspace setting);
  `state/mod.rs` (`record_posture`); `state/audit.rs` (`authority.posture`,
  `AuditRecord::texts`).
- `direwolf doctor`: truthful text.

What did not change: every refusal, every flag's meaning, DWKP, the private
protocol, the store schema, the sandbox's judgement.

## 6. Reading it

**The broker** (stderr, or `journalctl -u dwkd-broker`):

```text
dwkd-broker: event=posture control=worker.credential_swap scope=worker condition=REDUCED evidence=OBSERVED requirement=REQUIRED flag=--allow-swappable-workers facts="swap=capped:/system.slice/dwkd-broker.service" consequence="protected now, but a credential hop is admitted if swap appears later: reported at that hop, never refused" remediation="…"
dwkd-broker: event=posture_summary reduced=worker.credential_swap unverified=- unsupported=- refuses="-"
dwkd-broker: event=posture_acknowledged control=worker.credential_swap condition=REDUCED flag=--allow-swappable-workers facts="a credential's memory could reach swap (possible): …"
```

```bash
journalctl -u dwkd-broker | grep -E 'event=posture(_summary|_acknowledged)?'
```

**The authority** (`audit.log`, the security record): one `authority.posture`
record per served incarnation, after its `store.opened`, with `reduced`,
`unverified`, `acknowledged` and the per-control objects; the same as
`posture …` lines on stderr. A production authority shows
`reduced=[]` and `unverified=["broker.posture"]` (§8).

**Can it proceed?** A broker record with `refuses=` names what is refused;
`REDUCED` records proceed, with the named guarantee lost; `UNVERIFIED` broker
records refuse what they guard. The authority's records refuse nothing at
runtime: what it refuses at start, it refuses before any record is written.

**Remediation:** each record's `remediation`; for the broker,
`BROKER_HARDENING.md`; for every acknowledgement: remove it from a
production unit.

## 7. Validity over time

| Facts | Valid for | Rechecked |
|---|---|---|
| a daemon's uid, its flags, its peer policy, its broker, its attached environment | the process's life | at the next start, which records its own posture |
| a daemon's dumpable flag and core limit | the process's life (it never `execve`s; nothing raises a hard limit of 0) | read back once at start |
| Yama, the binary's mode, `fs.suid_dumpable`, swap, the cgroup's swap cap | can change at any time (root) | before every `net.http` hop, acknowledged or not |
| an environment's measured assurance | that environment | before each workload starts (drift refused) |

No posture observation is cached for a decision; the start-up records are a
report of the start, and the per-hop check is the decision.

## 8. Not built: the broker's posture in the authority's record

To close D6, the private protocol (version 13) would carry the broker's
acknowledgements in `BrokerHello` -- a closed list, no host facts -- and the
authority would record `broker.posture_reported` when the list it sees
differs from the last one recorded, labelled as the broker's own report
(ADR-0017: a record the audited process writes is a suggestion). A posture
refusal per hop would get its own refusal code instead of
`HTTP_WORKER_FAILED`, so the authority's `net.http.outcome` says why. Every
private-protocol test vector, both daemons' evidence harnesses and the
hosted cross-uid suites change with it; it is an owner decision, and until
it is made the authority's record says `UNVERIFIED`.

## 9. Platforms

- **Linux**: everything above.
- **WSL2**: as Linux; the guest's swap is what the broker sees, and Windows'
  paging of the VM is outside it (`BROKER_HARDENING.md`).
- **Off `x86_64`**: `worker.syscall_program` is `UNSUPPORTED`, every
  `net.http` hop is refused, and `worker.credential_swap` is
  `NOT_APPLICABLE`.
- **macOS, native Windows**: neither daemon serves (no peer credentials);
  `direwolf doctor`'s platform tier says so.

## 10. Evidence

Local, WSL Ubuntu 26.04; hosted evidence pending.

| Claim | Evidence |
|---|---|
| every broker acknowledgement is reduced, on any host, and names its guarantee | `effective_tests.rs`; `main.rs` (`swappable_memory_is_reduced_assurance_only_when_acknowledged`, `a_traceable_acknowledgement_is_reduced_assurance_where_the_window_is_closed_now`); the released broker in `private_protocol.rs` (`effective-posture`) |
| an acknowledged hop is read and reported, an unacknowledged one refused | `hardening_tests.rs` (`an_acknowledged_check_still_reads_the_host_and_says_what_it_admitted`, and the existing D11 cases) |
| unknown is never safe | `posture.rs` (`Swap::Unknown`), `effective_tests.rs`, `posture.rs` of the authority |
| the authority's record per incarnation, and a restart's change | `transport_server.rs` (`each_incarnation_records_its_effective_posture_and_a_restart_records_the_change`, `a_configured_broker_is_unverified_and_each_acknowledgement_is_recorded`) |
| every switch has a record; the orderings | `tests/architecture/test_f03_posture.py` |
| each guard is detected | `make posture-mutations` (26 mutants) |

The read-back of the dumpable flag and the core limit is held by the
mutation review's unit oracle: each daemon's `observed()` is compared with
what `/proc/self` shows (the broker's `posture.rs` tests, the authority's
`server/hardening.rs` tests).

## 11. Residual risks

- The broker's posture is not attested in `audit.log` (§8).
- A per-hop posture refusal reaches the authority as `HTTP_WORKER_FAILED`.
- The evidence harness's in-process authorities record no posture.
- Yama's `absent` covers "no Yama" and "unreadable" alike (both close
  nothing).
- Paging below the guest (WSL2, a hypervisor) and hibernation are
  documented, not observed.
- `direwolf doctor` checks nothing; M17's does.
