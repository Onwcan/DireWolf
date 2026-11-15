# ADR-0065: Each daemon says its effective security posture, control by control, and the authority records its own in the audit log -- a weakened control is never presented as enforced

**Status:** Proposed · **Date:** 2026-11-15 (designed, built and reviewed locally 2026-11-15 for finding F-03; its hosted evidence is pending and nothing here is accepted) · **Would amend (on acceptance):** [ADR-0053](0053-d11-exchange-worker-confinement-and-secret-memory.md) §§4, 7 (an acknowledgement is reduced assurance whatever the host says at start, and a hop it admits against the host's facts is reported at that hop), [ADR-0039](0039-durable-authority-state.md) (one more audit event, `authority.posture`, once per served incarnation) · **Refines:** [ADR-0017](0017-observability-vs-audit.md) (the kernel records its own posture; the broker's stays the broker's log) · **Leaves open:** the broker's posture in the authority's record, and a per-hop posture refusal distinct from a failed worker -- both need a private-protocol change, designed in [F03_EFFECTIVE_POSTURE.md](../F03_EFFECTIVE_POSTURE.md) §8 and not built

> **A control an operator weakened is reported as reduced -- by name, with
> the guarantee it costs -- wherever it is reported, and the security record
> of an incarnation says what that incarnation served with.** Each daemon
> computes one record per control from the same facts and flags its
> refusals use: `ENFORCED`, `REDUCED`, `UNVERIFIED`, `UNSUPPORTED` or
> `NOT_APPLICABLE`, observed or configured, the flag that reduced it, and
> what is refused because of it. There is no score: one reduced control is
> listed however many others hold.

Proposed. The change is built so that its evidence can run; the accepted
records' bodies are unchanged (README.md, rule 1).

## Context

**What each daemon already refused.** The broker refuses to serve as root,
with an environment's uid, with the authority's uid unless acknowledged, or
where a process of its uid could trace a worker before it hardens itself
unless acknowledged; it refuses a credential hop whose memory could reach
swap unless acknowledged, and every `net.http` hop on an architecture whose
worker program has no kernel evidence (ADR-0050 §21, ADR-0052 §13, ADR-0053
§§4, 5, 7). The authority refuses a peer policy that admits its own uid and
a broker that shares a uid, each unless acknowledged (ADR-0041, ADR-0043),
and judges every execution environment by measurement, refusing any whose
effective level is below its kind's (ADR-0047). None of that changes here.

**What was said about it.** Each acknowledgement was logged on its daemon's
stderr as a `REDUCED ASSURANCE` sentence -- prose, not records. Three gaps
followed (F-03, recorded in the remediation program as "weakening start-up
switches invisible to authority/audit"):

1. **The authority's own switches never reached `audit.log`.** A process left
   dumpable, a peer allowed the authority's own uid -- which can open
   `kernel.db` directly -- a broker sharing a uid, the evidence-only
   workspace: each was one stderr line, and the security record of such an
   incarnation was indistinguishable from a hardened one's. Only
   `--allow-host-execution` was recorded (`authority.activated`).
2. **A broker acknowledgement on a host that was safe at start was silent,
   and turned off the per-hop check it named.** With Yama at 1 or swap capped
   when the broker started, `--allow-traceable-workers` and
   `--allow-swappable-workers` logged nothing; yet `WorkerPolicy` then
   admitted every hop without reading the host. A swap device added, or Yama
   lowered, after start was neither refused nor reported -- the opposite of
   `BROKER_HARDENING.md`'s "a swap device added later is seen at the next
   hop". The unit test that pinned the start-up decision asserted exactly
   that silence.
3. **Smaller misstatements.** An unreadable `/proc/meminfo` was reported as
   `swap=possible`, a host with swap; the broker's and the authority's
   hardening was reported from the call that set it, never read back; and
   `direwolf doctor` said "no security mechanism is implemented yet".

## Decision

### 1. One record per control, five conditions, no score

Each daemon computes its effective posture at start from the facts its
decisions read -- the broker in `effective.rs`, the authority in
`posture.rs` -- one record per control:

| Field | Meaning |
|---|---|
| `control`, `scope` | the control's stable id, and whose property it is (`broker`, `worker`, `egress`, `environment`, `host`, `authority`, `policy`) |
| `condition` | `ENFORCED` (verified: observed, or fixed by configuration where nothing can be observed), `REDUCED` (an acknowledgement weakens it), `UNVERIFIED` (what would establish it could not be read, or is not visible to this daemon), `UNSUPPORTED` (this build or platform cannot give it), `NOT_APPLICABLE` (it does not apply to this configuration) |
| `evidence` | `OBSERVED` (read from the kernel or host now) or `CONFIGURED` (the command line, the operator's file, this build) |
| `requirement` | broker only: `REQUIRED`, or `RECOMMENDED` (page zeroing), which never refuses and is never listed with the required |
| `flag` | the acknowledgement that reduced it; present exactly when the record is `REDUCED` |
| `refuses` | broker: what is refused because of the condition -- serving, every credential hop, every `net.http` hop |
| `consequence`, `remediation` | the guarantee lost or how it is kept, and what the operator can do |

A condition is an observation, not an authorisation decision: a broker
whose memory can reach swap is `ENFORCED` with `refuses="every net.http hop
that carries a credential"` -- the guarantee holds because the hops are
refused -- and one whose swap state could not be read is `UNVERIFIED` and
refuses the same. The summary line lists the required controls that are
not enforced, by condition, and what is refused; it carries no count of
what holds.

### 2. The broker says it at start, from the facts it decides on

`deployment()` builds the records after reading the host and before the
start-up decision, so a refused start says what it saw too: one
`event=posture control=…` line per control, then `event=posture_summary`.
The existing `deployment_posture` line and `REDUCED ASSURANCE` sentences
stay. The broker's own hardening -- `PR_GET_DUMPABLE`, `RLIMIT_CORE` -- is
read back (`hardening::observed`) rather than assumed from the call that set
it. No record carries a path or anything a hop holds.

### 3. An acknowledgement is reduced whatever the host says now

`--allow-traceable-workers` and `--allow-swappable-workers` are `REDUCED`
at start whether or not the host is safe at that moment, and the start-up
sentence says which: "closed now, but a hop is admitted if it opens later".
`WorkerPolicy` reads the host before every hop **under the acknowledgement
too**: where the facts hold, nothing is said; where they would have refused,
the hop is admitted -- the acknowledgement's meaning is unchanged -- and an
`event=posture_acknowledged control=… condition=REDUCED flag=… facts=…` line
says so at that hop. An acknowledged hop now reads what an unacknowledged one always
read -- Yama, the binary's mode, a few small swap files; a production
broker, which has no acknowledgement, reads nothing more than before.

### 4. Unknown is never safe

A device count that could not be read is `Swap::Unknown`: unprotected, as
before, and said apart from `possible`. A dumpable state or core limit that
could not be read, or that contradicts what was set, is `UNVERIFIED`.

### 5. The authority records its posture in `audit.log`

After the start and the attachment of the operator's execution environment,
and before the socket is bound, `dwkd-authority serve` writes one
`authority.posture` record: the incarnation, each control (`control`,
`scope`, `condition`, `evidence`, `flag`), the ids by condition (`enforced`,
`reduced`, `unverified`, `unsupported`, `not_applicable`) and the
`acknowledged` flags. Its controls: the process's own memory (dumpable, core
limit; read back), the peer boundary, the broker's identity, the broker's
posture, host execution, and the workspace setting. A start that cannot
record it does not serve. Each restart records its own, so a change of
deployment posture is a pair of records. The same lines go to stderr.

The broker's posture is **`UNVERIFIED`** in that record whenever a broker is
configured: its acknowledgements and the host facts it reads are its own,
in its own log, and nothing on the private channel carries them. ADR-0017's
line holds -- a record the audited process writes about itself is a
suggestion -- so this decision does not copy the broker's lines into the
kernel's record; it says, in the record, that they are not there.

### 6. Where it is not

`direwolf doctor` connects to no daemon; it now names each security check it
does not make and where its owner reports it, and no longer says that no
mechanism exists. The evidence harness's in-process authorities
(`serve_authority`) record no posture: they are test processes, never
hardened. No DWKP operation, schema, private-protocol message or broker
decision changes; every refusal stays where it was.

## Consequences

- An operator reading `audit.log` sees, per incarnation, every authority
  switch that weakened it and that the broker's posture is not attested
  there; reading the broker's log, every broker control's condition, and
  every hop an acknowledgement admitted against the facts.
- A production broker with no acknowledgement logs exactly what it logged
  before plus its posture lines; one with an acknowledgement logs it as
  reduced even on a safe host. Evidence harnesses that pass acknowledgements
  now see `REDUCED` lines they did not see before; none asserted their
  absence.
- One more audit record per start; the chain format is unchanged.
- Two evidence tests that count every byte a broker reads during a
  credential hop (`secret_primitives.rs`, `secret_evidence.rs`) count the
  swap facts it now reads under its acknowledgement; each still proves the
  value is read exactly once.

## Residuals and what is assigned elsewhere

- **The broker's posture is not in the authority's record** (`broker.posture`
  is `UNVERIFIED`), and a per-hop posture refusal reaches the authority as
  `HTTP_WORKER_FAILED`, indistinguishable from a failed worker. Both need the
  private protocol to carry them (version 13: the broker's acknowledgements
  in its hello, recorded by the authority on change and labelled as the
  broker's report; a refusal code per posture refusal) -- designed in
  F03_EFFECTIVE_POSTURE.md §8, an owner decision, not built.
- Yama's `absent` covers both "no Yama" and "unreadable"; both close
  nothing, so the decision is unaffected.
- A hypervisor's or Windows' paging of a WSL2 guest, and hibernation, are
  outside what the broker can read; they stay documented
  (`BROKER_HARDENING.md`), not reported.
- The full, connected `doctor` is M17's.

## Alternatives considered

- **Keep prose lines, add more of them.** Rejected: a sentence per weakening
  answers "is anything reduced?" only for a reader who knows every sentence,
  and was the shape that let gap 2 stay silent.
- **A single posture level or score per daemon.** Rejected: it averages one
  critical reduction away against unrelated controls that hold.
- **Copy the broker's posture into `audit.log` now, through the private
  protocol.** Deferred, not rejected: it changes the private protocol and
  the broker's hello on every exchange, and the record would be the broker's
  self-report; the authority's record says `UNVERIFIED` until the owner
  decides it (§8 of the report).
- **Make an acknowledgement refuse when the host is safe.** Rejected: it
  changes what the flag means; F-03 is about saying what holds, not about
  new refusals.
- **A new `direwolf posture` command or daemon endpoint.** Rejected for now:
  no daemon has a read-only query surface, and building one is M17's
  `doctor`, not this finding.

## Evidence

Local, WSL Ubuntu 26.04 (hosted evidence pending):

- `crates/dwkd-broker/src/effective_tests.rs`: every acknowledgement reduces
  exactly its control and names itself; an acknowledgement on a safe host is
  reduced; unknown observations are never enforced; an unsupported
  architecture is `UNSUPPORTED` and refused; refusals are said as refusals;
  a reduced control is never averaged away; a recommendation is never
  required; no line carries a path; every record is well formed.
- `crates/dwkd-broker/src/http/hardening_tests.rs`: an acknowledged check
  still reads the host and reports what it admitted; unacknowledged, the
  same facts refuse.
- `crates/dwkd-broker/src/main.rs`, `posture.rs`: the start-up decision with
  an acknowledgement on a safe host; `Swap::Unknown`.
- `crates/dwkd-broker/tests/private_protocol.rs`: the released broker's
  posture lines (case `effective-posture`, now required by the broker
  evidence).
- `crates/dwkd-authority/src/posture.rs` (unit) and
  `crates/dwkd-authority/tests/transport_server.rs` (the released
  authority): a development start and a hardened restart of one store leave
  two `authority.posture` records that say what changed; a configured broker
  is `UNVERIFIED`; each acknowledgement is recorded.
- `tests/architecture/test_f03_posture.py`: every weakening switch of either
  daemon has a record; the per-hop checks read before they consult an
  acknowledgement; the authority records before it serves; one vocabulary;
  the mutation table matches the source.
- `make posture-mutations`: 26 mutants, judged by C3's per-mutant judge.

## Revisit if

- the private protocol changes for another reason (carry the broker's
  posture then);
- a daemon gains a read-only query surface (M17's `doctor` reads the records
  rather than the logs);
- a new acknowledgement is added (the architecture test requires its
  record).
