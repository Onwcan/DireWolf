# M6.0 decision package

**As of 2026-11-24, at `0bd727d`** (CI #216, [run 45276662436](https://github.com/Onwcan/DireWolf/actions/runs/45276662436),
attempt 2: 33 of 33 jobs; Push #34, [run 45276662285](https://github.com/Onwcan/DireWolf/actions/runs/45276662285):
4 of 4). The decisions M6, Approvals and budgets, rests on, each stated so it
can be accepted or rejected on this page alone. The plan they gate is
[M6_IMPLEMENTATION_PLAN.md](M6_IMPLEMENTATION_PLAN.md); the history behind
them is [M6_PREPARATION_HANDOFF.md](M6_PREPARATION_HANDOFF.md). ADR-0078's
acceptance is recorded after `6475172`, this package's own commit (CI #218,
[run 45382109648](https://github.com/Onwcan/DireWolf/actions/runs/45382109648): 33 of 33;
Push #36, [run 45382110559](https://github.com/Onwcan/DireWolf/actions/runs/45382110559): 4 of 4).

## 1. Where each decision stands

| Record | Decision | Status after this change | Evidence | Earliest phase that needs it |
|---|---|---|---|---|
| [ADR-0063](adr/0063-principal-ownership-of-sessions-workspaces-and-profiles.md) | sessions, workspaces and profiles belong to principals; the runtime is never its own approver | **Accepted** 2026-11-24 | built 2026-11-14; CI #201 and every run since: `transport_foreign`'s cross-uid ownership test, `i09` at `hosted-three-identity` (CI #216 among them); `make authority-ownership-mutations` | M6.1 (the requester's principal) |
| [ADR-0067](adr/0067-f18-approver-endpoint-identity-boundary.md) | the approver endpoint, identity boundary only; its §7 binds what M6 builds on it | **Accepted** 2026-11-24 | built 2026-11-16; "approver evidence: 1 test, 6 cases contained, three identities" from CI #201 to CI #216; `make approver-identity-mutations` 13/13 | M6.3 |
| [ADR-0077](adr/0077-the-approval-channel-is-the-approver-endpoint-and-an-approver-uid-is-a-principal-not-a-person.md) OD-1 | one approval channel: ADR-0022's CLI-local and detached-local paths withdrawn | **Accepted** 2026-11-24 | a decision record; the boundary is ADR-0067's | M6.3 |
| ADR-0077 OD-2 → [ADR-0078](adr/0078-approval-assurance-which-classes-need-a2-and-the-presence-factor.md) | which classes need A2; whether M6 builds a presence factor | **Accepted** 2026-11-24, OD-1 to OD-3 as recommended -- a record of its own so ADR-0077 could be accepted first | a decision record | M6.3 (which classes are approvable) |
| [ADR-0062](adr/0062-taint-follows-delivered-content.md) (F-01) | a run's taint follows the content it receives | **Accepted** 2026-11-25 | hosted-observed (the ledger, F-01), CI #201 to CI #225 | M6.1 (taint in the binding) |
| [ADR-0064](adr/0064-f02-authority-endings-serialised-with-decided-effects.md) (F-02) | an end of authority waits for every effect already decided | **Accepted** 2026-11-27 | `make test` on three platforms; `make authority-concurrency-mutations` 20/20 (local); M6.2's revocation ordering (CI #227) and M6.2.1's lease takeover and revocation crash windows (CI #228) | M6.2 (the burn inside the gate) |
| [ADR-0076](adr/0076-isr2-01-audit-level-full-is-not-kept-on-a-net-http-hop.md) (ISR2-01) | `audit_level=full` is not kept on a `net.http` hop | **Accepted** 2026-11-25, OD-1 | CI #212, #213, #216, #225: `net-http-evidence`'s `obligation-unenforceable` case | M6.1 (obligations in the binding) |

**What "Accepted" here means.** ADR-0063, ADR-0067 and ADR-0077's OD-1 were
accepted on 2026-11-24 and recorded in `5520ab8`; CI #218 at `6475172`,
this package's own commit, passed 33 of 33. ADR-0078 was accepted the same
day, as recommended. Each is recorded by its Status line, the index, the
README's count and `docs/adr/accepted.sha256` (`dwcheck adr --record`).

## 2. The accepted decisions, exactly

### ADR-0063 -- the principal model

- A principal is the kernel-reported uid (`AuthenticatedSubject`, made only
  from `SO_PEERCRED`; TX063). Nothing on the wire names one.
- Schema 14's records -- `session_owner`, `session_delegate`,
  `workspace_principal`, `profile_principal`, `workspace_root_share`,
  `ownership_revocation`, `legacy_session`, `ownership_observation` -- decide
  who holds a session, reaches a workspace and names a profile.
- The migration grants nothing; revocation is two-phase (`REVOKED`, then
  `COMPLETE`); the runtime is never its own approver (§8: no descriptor on
  the DWKP endpoint, every admitted run `api`, approvals only on an approver
  endpoint, self-approval refused by M6's store).
- **M6 consequence:** every approval and standing grant is bound to the
  requesting principal and refused for any other.
- **Amends:** ADR-0011 point 2, ADR-0039 (schema 14), ADR-0041. The index
  rows of those three now say so; their bodies are unchanged.

### ADR-0067 -- the approver endpoint

- `--approver-socket` with at most 16 `--approver-uid`s, disjoint from every
  `--allow-uid`, the broker's and the authority's uid, with no override.
- Today it reads nothing, answers nothing and holds no approval operation
  (TX065); `approver.peer_refused` and `approver.peer_authenticated` are its
  only records.
- §7 is M6's contract: a closed vocabulary (list, show, decide), the decision
  accepted only from an approver authenticated at that moment, the
  requester's principal proposed for the binding, single use inside ADR-0064's
  gate, rendering from canonical data, the audit kinds, standing grants as a
  separate operator act.
- **Amends:** ADR-0041 (a second socket, two audit kinds).

### ADR-0077 OD-1 -- one approval channel

- A local approval, denial or standing grant's creation is accepted only on
  the approver endpoint; ADR-0022's "CLI-local (default)" and
  "Detached-local" are withdrawn. ADR-0022's body is unchanged (it is
  Accepted); its Status line and index row say what withdrew them.
- `direwolf approve`, when built, is the trusted approver client, run as an
  approver uid -- never a DWKP peer.
- ADR-0022's remote channel is unchanged as a design and is **not** in M6's
  scope: nothing here places it.
- A0 is never sufficient; A1 is never recorded as A2; a class that needs A2
  stays `DENY` until a verified presence factor exists.

## 3. ADR-0078 (ADR-0077's OD-2), accepted 2026-11-24

**Accepted as recommended in ADR-0078:**

| | Decision | The alternative |
|---|---|---|
| **OD-1** the A2 classes | `Environment::Host` (any verb), `secret.use`, `fs.delete`, a standing grant's creation -- recognised from the canonical action, a floor a policy may raise | a narrower set lets A1 approve a credential's use, a deletion or a host launch |
| **OD-2** until a factor exists | those classes `DENY`, no override; an A1 decision for one refused and audited | an override flag reintroduces A1-as-A2 |
| **OD-3** M6 and the factor | M6 does not build it; host execution stays `DENY` through M6, and M6.6 is "wired and shown to deny", not "enabled"; a later decision chooses the factor (FIDO2 user presence the candidate) with ADR-0019's dependency review | if M6 builds it: an M6.3b checkpoint before M6.4's high-risk grants and M6.6's enablement, with its own hosted evidence |

**Consequence:** M6 delivers approvals for sandboxed,
non-credential, non-deleting actions at A1, and gates everything else. No
M6 report may call host execution complete.

## 4. Later-phase recommendations

| Record | Recommendation | Why, and when |
|---|---|---|
| ADR-0062 | accept before M6.1 closes | the binding hashes the run's taint at grant time; ADR-0062 is what makes that taint the delivered content's |
| ADR-0064 | accept before M6.2 closes | the burn is "the same transaction that records the effect's intent, inside F-02's gate" (ADR-0067 §7); the gate's contract has to be the accepted one |
| ADR-0076 | accept before M6.1 closes | the binding carries the decision's obligations; one must never be bound or shown as kept where it is not |

None of the three blocks starting M6.1. Each is hosted-observed; none is
accepted by this package. ADR-0062 and ADR-0076 were accepted on
2026-11-25, at M6.1's closeout; ADR-0064 on 2026-11-27, at M6.2's
closeout.

## 5. Acceptance order

1. ADR-0063, ADR-0067, ADR-0077 OD-1 -- accepted 2026-11-24, recorded in
   `5520ab8`.
2. ADR-0078 -- accepted 2026-11-24, before M6.3 as required (it decides
   what M6.3 may make approvable).
3. ADR-0062 and ADR-0076 -- accepted 2026-11-25, at M6.1's closeout.
4. ADR-0064 -- accepted 2026-11-27, at M6.2's closeout, as written.
5. M6.1's own binding record (a new ADR amending ADR-0021: the requester's
   principal and the schema member join the hash) -- ADR-0079, proposed
   2026-11-24 and accepted 2026-11-25 on CI #225's evidence.
6. M6.2's registry record -- ADR-0080, proposed 2026-11-26 and accepted
   2026-11-27, OD-1 to OD-6 as written, on CI #227's and CI #228's
   evidence.

## 6. What ADR-0078's acceptance changed

- Its Status line: Accepted, with the date and OD-1 to OD-3 as decided;
  its owner decisions each marked accepted, and the two sentences that
  left OD-3 open state it. ADR-0077's Status line, the one writable part
  of that accepted record, says its OD-2 is decided.
- Its index row bold; ADR-0077's row "OD-2 decided by 0078".
- `docs/adr/accepted.sha256` by `dwcheck adr --record`; the README's count
  (60 accepted, 15 Proposed).
- [APPROVALS.md](APPROVALS.md) §7's note, the ledger, the roadmap and the
  preparation handoff say accepted where they said Proposed; the plan's
  M6.0b gate is met.
- Nothing in the build: no approval operation exists until M6.3.

## 7. What is not decided here

The binding's exact field set and encoding (M6.1's ADR), the registry's
schema (M6.2's), the approver protocol's frames (M6.3's), the standing
grant's revalidation across a policy change (M6.4's), the budget units
(M6.5's), Landlock with host execution (ADR-0070 OD-D) and the presence
factor itself (a decision of its own after M6, ADR-0078 OD-3).
