# ADR-0062: A run's taint follows the content it receives -- a workload's broker-observed reach and its workspace root's exposure raise it to `EXTERNAL_UNTRUSTED`

**Status:** Proposed · **Date:** 2026-11-13 (designed and reviewed 2026-11-13, built 2026-11-13 for finding F-01; its hosted evidence is pending and nothing here is accepted) · **Would amend (on acceptance):** [ADR-0039](0039-durable-authority-state.md) §10 (the producers of taint, and schema version 13), [ADR-0043](0043-m4b-private-broker-channel-and-brokered-fs-read.md) §9 and [ADR-0044](0044-m4c-filesystem-operations-plans-and-atomic-mutation.md) §11 (a read-family result is `LOCAL_UNVERIFIED`, or `EXTERNAL_UNTRUSTED` from an exposed root), [ADR-0045](0045-m4d-process-execution-broker.md) (a host process's output, likewise), [ADR-0052](0052-m5d-sandboxed-process-exec.md) §8 item 8 and its residuals (a workload's outcome, and later reads of what it wrote) · **Amends (Proposed):** [ADR-0061](0061-workload-egress-decided-by-policy-novelty-and-exposure.md) (a root is exposed by F-01's marks too, and a run holding external content starts its workloads exposed; its "decides no taint" is replaced) · **Refines:** [CONTEXT.md](../CONTEXT.md) §5 (downloads are `EXTERNAL_UNTRUSTED`), [ADR-0028](0028-policy-input-ownership.md) (the kernel derives taint)

> **A run's taint is raised by what the kernel delivers to it, from where
> that content may have come -- never by what the run was merely allowed to
> reach.** A workload whose broker report says an origin byte reached it,
> or whose settlement cannot say and allowed something, raises its run to
> `EXTERNAL_UNTRUSTED` with its outcome, whatever it printed. Anything
> delivered to a run from a workspace root that may hold network content --
> an ADR-0061 exposure, a run holding external content having changed it, or
> a workload on it that may reach an origin and has not settled -- raises the
> run to `EXTERNAL_UNTRUSTED`. A run holding external content marks the root
> it changes, before the effect. Every rise is recorded with what it rests
> on, and a possibility is never recorded, or acted on, as content received.

Proposed. The change is built so that its evidence can run; the accepted
records' bodies are unchanged (README.md, rule 1), and their sections stay the
accepted design until this record is accepted.

## Context

**What raised taint.** Four producers raise a run's taint
(`run_policy_input.taint`, monotonic by trigger, ADR-0039): a `net.http`
response head to `EXTERNAL_UNTRUSTED` (ADR-0050 §14); a read-family fs result,
a host process's output and a sandboxed workload's output, each to
`LOCAL_UNVERIFIED`. An output-less workload raised nothing.

**Finding F-01** (review of 2026-11-11/12). Taint followed the tool that
delivered content, not where the content came from:

- network content a workload fetched reached its run as `LOCAL_UNVERIFIED`
  through its output, and not at all when it printed nothing;
- a file a workload downloaded reached a later `fs.read` -- of the same run
  or of another run on the same workspace root -- as `LOCAL_UNVERIFIED`;
- content an `EXTERNAL_UNTRUSTED` run wrote to the workspace reached every
  other run as `LOCAL_UNVERIFIED`;
- ADR-0061 records, per root, that an origin byte reached a workload there
  (`workspace_exposure`), and uses it for workload egress only -- "this
  decides no taint".

`balanced`'s `approve-egress-when-tainted` therefore never stopped a run that
had read what a workload downloaded. CONTEXT.md §5 classifies downloads as
`EXTERNAL_UNTRUSTED` -- content the agent chose to reach.

**What can be observed.** The tunnel is opaque (ADR-0048): the broker sees
bytes, not requests or responses. Its first origin byte per tunnel is
observed under the root's lock before it is forwarded (ADR-0061); its
per-workload report says whether any origin byte reached that workload
(`WorkloadEgressReport.exposed`), is checked against the authorisation, and
is uncertain when missing or contradictory. A workload writes its whole
workspace unmediated; fs mutations, by contrast, are the broker's, and are
excluded while any workload runs on the root (M5d.4).

## Decision

### 1. Invariants

| | |
|---|---|
| T-1 | **Monotonic.** No path lowers a run's taint, or removes a root mark or an evidence row. |
| T-2 | **Broker-derived.** Content received is proved only by the broker's report checked against the authorisation, or by the authority's own ledger; a report missing or contradictory is uncertain, which raises. |
| T-3 | **Crash-safe.** A mark is durable before the effect that could warrant it; an interrupted workload is settled uncertain at recovery; no recovery leaves a run or a root less tainted. |
| T-4 | **Cross-run.** What a run receives from a root that may hold network-derived or externally introduced content is `EXTERNAL_UNTRUSTED`, whichever run introduced it. |
| T-5 | **Downloads.** A file a workload fetched taints whatever later receives it from the root -- an fs read, a workload's outcome, a host process's. |
| T-6 | **Output-less.** A workload whose tunnels received an origin byte raises its run with its outcome, whatever it printed. |
| T-7 | **Uncertainty.** Missing or contradictory evidence is the most tainted case, never "nothing happened". |
| T-8 | **Ordering.** The rise is in the transaction that records the delivery, before the run is answered. |
| T-9 | **F-17.** Tunnel reach never feeds `net.http` novelty, and taint never feeds novelty. A run's taint changes only within its own operations: nothing reaches into another run's context, so ADR-0061's drift tripwire never fires because of F-01. ADR-0061's exposure only grows. |
| T-10 | **Evidence.** Every rise records its cause, its basis and its sources; content received, a tainted run's effect, an uncertain settlement and a possibility are told apart, and a possibility is never recorded or acted on as content received. |
| T-11 | **Received, not permitted.** No rise follows from network permission, an established tunnel, a refused CONNECT, a failed dial or bytes sent upstream. |
| T-12 | **Replay.** A run's stored taint is the highest its evidence says; its evidence rows chain from `NONE` in order; each decision record says the taint it was made in. |

### 2. Where a root is exposed

A workspace root, by its identity (device, inode), is **exposed** while the
store holds any of:

- an ADR-0061 `workspace_exposure` row -- certain (an origin byte reached a
  workload on it) or uncertain (a settlement could not say);
- a `workspace_taint` row (§4): a run holding external content changed it;
- a `LAUNCHING` workload on it whose authorisation allows anything: it may be
  receiving an origin's bytes now.

ADR-0061's `exposed()` is this predicate; a workload of a run that itself
holds external content (§4) also starts exposed -- for such a run its own
cells are already its exposed ones.

### 3. What raises a run's taint

In the transaction that records each delivery to a run, before the run is
answered:

1. **A workload's own reach (R1).** Its egress settled `REPORTED` with an
   origin byte reached: `EXTERNAL_UNTRUSTED`, cause `workload_reached`, basis
   `ORIGIN_BYTES`. Settled `UNCERTAIN` while its authorisation allowed
   anything: cause `workload_uncertain`, basis `UNCERTAIN`. Whatever it
   printed; its egress is settled first.
2. **From an exposed root (R2).** A read-family fs result; any workload
   outcome but a provable non-start; a host process's status that carries
   output or an ending -- from an exposed root: `EXTERNAL_UNTRUSTED`, cause
   `root_exposed`, basis the best-evidenced of `ORIGIN_BYTES`,
   `EXTERNAL_RUN_EFFECT`, `UNCERTAIN`, `IN_FLIGHT`.
3. Otherwise as before: `LOCAL_UNVERIFIED` for a read-family result and for
   output; nothing for a workload that printed nothing on a pristine root.
4. **`net.http`** is unchanged: a response head raises `EXTERNAL_UNTRUSTED`
   (basis `NETWORK_RESPONSE`); TLS alone raises nothing.
5. **A restart (R5)** settles an interrupted workload uncertain (ADR-0061)
   and raises the run it reaped, cause `workload_interrupted`, so its
   history says what it may have received.

The tunnel's criterion is its first origin byte, TLS handshake bytes
included -- stricter than `net.http`'s response head, because the tunnel is
opaque. Network permission, a refused CONNECT, a failed dial and bytes sent
upstream raise nothing.

### 4. A run holding external content marks what it changes (R3, R4)

A run **holds external content** when its taint is `EXTERNAL_UNTRUSTED` and
its evidence rests on more than a possibility: a row whose basis is not
`IN_FLIGHT`, or an `IN_FLIGHT` row whose workloads are still running or
settled exposed. Before an effect of such a run on its root -- an fs mutation
once the in-use exclusion has passed, a workload's intent, a host launch's
intent -- a `workspace_taint` row is recorded in that transaction, before the
broker hears of it, and audited (`workspace.tainted`). A database trigger
refuses a mark by a run that is not `EXTERNAL_UNTRUSTED`.

A workload of such a run waits -- refused `WORKSPACE_EXPOSURE_PENDING`,
answered as the existing `ENVIRONMENT_BUSY`, nothing recorded -- while
another run's workload on the root may reach an origin and started pristine:
that workload's cells could not follow the mark. The broker is not told; no
protocol changes.

### 5. Evidence (R7)

`run_taint_evidence` holds one row per rise and one per external receipt
that adds to what a run's external taint rests on while that is still only a
possibility: the cause, the basis (`NETWORK_RESPONSE`, `ORIGIN_BYTES`,
`EXTERNAL_RUN_EFFECT`, `UNCERTAIN`, `IN_FLIGHT`, `LOCAL_CONTENT`,
`TRUSTED_CALLER`), the delivering invocation, the root and the sources (by
kind: how many, and the first). `run_taint_in_flight` names the workloads an
`IN_FLIGHT` row rested on. Triggers keep the rows in order, from the run's
taint at the time, and a run's taint rises only with the row that says why
(`run_policy_input_taint_has_evidence`). A run whose taint rose before
version 13 has one `BEFORE_EVIDENCE` row. `run.taint_raised` names the
basis, the row, the invocation, the root and the sources; a delivering record
names the taint, its basis and its row; every decision record names
`taint_at_decision`.

### 6. Wire and store

Private protocol version 12 and public DWKP are unchanged. Store schema
version 13 adds `workspace_taint`, `run_taint_evidence`,
`run_taint_in_flight` and the trigger above; every table is append-only;
the migration from 12 changes no existing row.

### 7. Not decided here

- **The counter backstop.** The proxy's downstream count and a workload's
  per-destination tally are incremented at the same site with the same value,
  but a workload's report is taken when its tunnels are halted, without
  waiting for them; a write that lands after it is counted by the proxy
  alone. A shortfall can therefore appear with an honest broker, and a mark
  it raised would be a false, permanent one. It is not built; it needs its
  own decision (and a report taken after the tunnels end).
- **Per-file provenance.** A workload can copy content anywhere in its root
  unmediated; marks are per root. A ctime watermark could narrow reads to
  objects changed since the root's first exposure, but rests on the host
  clock and filesystem behaviour that need their own evidence.
- **Reset.** No mark is ever removed and no taint lowered; an operator act
  that re-baselines a root, or declassifies, is later work with its own
  record.

## Consequences

Positive: content a workload fetched, or a tainted run wrote, now taints
whatever receives it; uses only facts the broker or the authority's own
ledger prove; tells content received from a possibility; fails closed on
uncertainty and crashes; leaves the protocol unchanged.

Negative: more runs become `EXTERNAL_UNTRUSTED`. Before M6 every approval is
a refusal, so a run that received anything from an exposed root reaches no
destination it has not reached (`net.http` included) -- most of the
workload side was already so under ADR-0061's exposed cells. Marks are per
root and permanent. One ADR-0061 evidence assertion is stricter (§8).

## Residuals and what is assigned elsewhere

- Network-influenced signals with no origin byte -- resolution answers, a
  CONNECT's disposition, a dial's outcome, timing -- reach the workload
  untainted; they carry a few bits per CONNECT, bounded by the tunnel limit,
  and no content.
- Root identity is the device and inode; a re-bind under a new identity
  starts pristine (ADR-0061 alike).
- A host process has no network isolation; before M6 none runs in
  production. M6 must treat a network-capable host process as external, and
  hold its launch to §4's wait -- prerequisites of M6.
- A co-tenant's long-running networked workload makes concurrent readers of
  the root external (a possibility, recorded as one).
- Content another subject's untainted run writes is not network-derived and
  stays `LOCAL_UNVERIFIED` (F-18). Concurrency within a run would turn a
  rise during the run's own running workload into drift (F-02).
- ADR-0021 assumed a reversible taint; it is monotonic as built (ADR-0039).
  M6 must reconcile them.

## Alternatives considered

- **Taint every network-capable workload** at launch: taints permission,
  not content; raising at launch trips ADR-0061's drift tripwire on every
  collection, or makes every cell exposed from the start.
- **The workload's own reach only:** misses downloaded files read later and
  every other run on the root.
- **Pushing taint into the other runs on a root:** changes a running
  workload's decided context, which ADR-0061's tripwire answers by
  destroying its environment.
- **Per-file provenance by content digest:** defeated by any workload,
  which copies content unmediated.

## Evidence

Unit (the real authority and store, the route tests' fake broker): own
reach with no output; permission alone; uncertain and contradictory
settlements; downloaded content read by the same and another run; two
workspaces bound to one directory; a possibility never marking, one settled
exposed marking, a later receipt making one content; a tainted writer's
mark before its effect; the concurrent launch's wait; no reach into another
run's running workload; the restart; monotonicity and decision attribution;
a pristine root; the host floor; schema 13's migration and triggers. Real
OCI (`make sandbox-egress-evidence`): permission, a refusal and a failed
dial not external; an output-less, incomplete download external; the file
it left external to another run's `fs.read`; a tainted writer's mark; a
fresh run decided by the exposed cell; the restart. Mutation review: `make
sandbox-taint-mutations`. Every earlier evidence case is kept, pinned in
`tests/architecture/m5e_cases_before_f01.txt`; ADR-0061's
`tainted-novel-refused-seen-reached` now asserts the stricter pristine cell
of its now-external run (`np=0/2`), and the guarantee it no longer shows --
the exposed cell, not the run's taint, deciding on an exposed root -- is a
case of its own at a fresh run (`taint-fresh-run-decided-by-the-exposed-cell`).
Hosted CI is the acceptance gate; this record stays Proposed until accepted.

## Revisit if

M6 adds approvals, standing grants, re-baselining or reversible taint; F-02
introduces concurrent operations within a run; F-18 changes who may share a
workspace; the broker's report is taken after its tunnels end (the counter
backstop); the tunnel gains content inspection.
