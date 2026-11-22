# F-18 Phase 3.4: the human approver's identity boundary

What F-18's principal ownership left to M6, what is built now, and what M6
still has to build. The decision is
[ADR-0067](adr/0067-f18-approver-endpoint-identity-boundary.md) (Proposed);
this is its inventory, its adversarial matrix and its evidence.

| | Status |
|---|---|
| The approver endpoint's identity boundary | **IMPLEMENTATION PARTIAL**: built; the approval operations it will carry are not |
| Its same-identity evidence | local: passing (§11) |
| Its three-identity evidence | **HOSTED EVIDENCE VERIFIED** on CI #201 (run 44818094052): `authority-transport`, `DW_PEER_AS` + `DW_APPROVER_AS`, six `cross-uid-*` cases contained |
| ADR-0067 | **ARCHITECTURAL ACCEPTANCE PENDING** (Proposed) |
| The approval registry, rendering, consumption, standing grants | **M6 APPROVAL REGISTRY DEFERRED** |
| A terminal-based approval | design only: none is accepted (§6) |
| F-12's `require_artifact_capture` | **F-12 ARTIFACT CAPTURE DEFERRED**: unchanged here ([F12_POLICY_PACK_USABILITY.md](F12_POLICY_PACK_USABILITY.md) §8); BALANCED's writes still refuse |

## 1. What F-18 already guarantees

[ADR-0063](adr/0063-principal-ownership-of-sessions-workspaces-and-profiles.md)
(Proposed) built, and this phase keeps unchanged:

- a principal is the kernel-reported uid (`SO_PEERCRED`), made into a
  subject once per connection and nowhere else (TX063);
- sessions have one owner and operator-declared delegates, workspaces and
  profiles operator-declared principals; a migration grants nothing from
  history (TX064); revocation is two-phase;
- the runtime's DWKP endpoint receives no descriptor (TX061);
- every run a runtime admits is `api`, unattended, and no runtime path
  records an approval (TX062);
- `REQUIRE_APPROVAL` denies, as `deny-approval-needed-when-unattended` or
  `APPROVAL_REQUIRED`;
- F-02 orders every end of authority after decided effects (ADR-0064); F-03
  records the effective posture (ADR-0065); F-12 places host anchors by
  identity (ADR-0066).

What it did not build (ADR-0063 §8): an approver endpoint of its own, whose
identities the operator keeps disjoint from the runtime's, the authority's
and the broker's.

## 2. Inventory

| # | Existing protection | Missing integration | Consequence if missing | Built / proposed | Decision | Adversarial test | Status |
|---|---|---|---|---|---|---|---|
| I1 | DWKP peers are the operator's closed uid list | no separate approver identity | an approver indistinguishable from a runtime | `--approver-uid`, a closed set of at most 16 | ADR-0067 §2 | `config.rs` unit tests; `transport_approver` | **built** |
| I2 | DWKP socket's place checks | no approver endpoint | approvals would have to arrive on the runtime's socket | `--approver-socket`, same place checks, own lock | ADR-0067 §1 | `the_approver_socket_is_protected_as_the_dwkp_socket_is` | **built** |
| I3 | `--allow-authority-uid`, `--allow-shared-broker-uid` acknowledgements | none for approvers | a development override would make a runtime its own approver | disjoint from `--allow-uid`, `--broker-uid`, the authority; no override | ADR-0067 §2 | `a_runtime_uid_is_never_an_approver`, `the_broker_is_never_an_approver`, `the_authority_is_never_an_approver_and_naming_it_starts_nothing` | **built** |
| I4 | peer gate before a byte is read | approver gate | a payload could claim an approver | judged by the kernel's uid alone, before any read | ADR-0067 §3 | `only_a_uid_the_operator_named_is_an_approver`; hosted `cross-uid-*` | **built**; hosted three-identity, CI #201 |
| I5 | transport audit records | approver records | unattributed approver attempts | `approver.peer_refused`, `approver.peer_authenticated`, rate-limited | ADR-0067 §3 | `transport.rs` unit test; `transport_approver` | **built** |
| I6 | none | an endpoint holding no operation | a premature approval path by fiat | the endpoint reads, answers and dispatches nothing | ADR-0067 §3, TX065 | `the_endpoint_reads_answers_and_dispatches_nothing`; TX065 fixture | **built** |
| I7 | strict DWKP decoder | claims of a human | `origin=interactive`, `approved=true`, an external agent's yolo flag taken as authority | none needed: every such field is unknown | ADR-0067 §4 | `a_runtime_cannot_claim_an_approval_an_approver_or_a_human_on_the_wire` | **verified** |
| I8 | TX061 on the runtime endpoint | a terminal proof | a runtime-controlled pty answering a prompt | no terminal anywhere; a trusted approver client recommended | ADR-0067 §5 | TX061, TX065, `transport_hostile` descriptor test | **design only** |
| I9 | ADR-0021 binding | requester principal in the binding | an approval spent for another principal | proposed for M6's ADR | ADR-0067 §7 | M6 | **deferred** |
| I10 | none | approval registry, nonce, expiry, single use, restart | no approval can exist | M6, inside F-02's gate | ADR-0067 §7 | M6 | **deferred** |
| I11 | `StandingGrantState::Unavailable` | grants | none: no grant can be held | M6, a separate operator act | ADR-0067 §7 | `context.rs`; mutant P13 | **preserved** |
| I12 | none | kernel-rendered prompt | agent text impersonating authority text | M6, with ANSI/bidi/control stripping and an untrusted region | ADR-0067 §7 | M6 | **deferred** |
| I13 | none | approval lifecycle audit | an unrecorded decision | M6's `approval.*` kinds | ADR-0067 §7 | M6 | **deferred** |

A secure identity boundary is not an approval registry: I1-I8 make the
approver a configured, kernel-authenticated identity no runtime can be; I9-I13
are what an approval *is*, and none of them exists yet.

## 3. The endpoint: alternatives

| | A: separate socket, operator uid set | B: operator-only control process | C: design-only contract |
|---|---|---|---|
| authenticated by | the kernel (`SO_PEERCRED`) | its own channel to the authority | -- |
| new trusted code | an accept loop, no parser | a second daemon and its channel | none |
| runtime's endpoint | unchanged | unchanged | unchanged |
| provable now with real uids | yes | only once built | no |
| chosen for | the identity boundary | -- | everything needing the registry |

Recommendation, as built: **A for the identity, C for the operations.** The
endpoint is live and authenticated; it holds no approval operation until the
registry it would serve exists. B adds a second trusted daemon whose channel
to the authority would need A's checks anyway.

## 4. Who is who

| identity | how it is known | may | may not |
|---|---|---|---|
| authority | its own process; the IPC probe's uid | decide, record | be an approver (start refuses) |
| broker | `--broker-uid`, `SO_PEERCRED` on the private channel | perform decided effects | be an approver (parser refuses) |
| runtime | an `--allow-uid`, `SO_PEERCRED` on the DWKP socket | request: lease, admit (`api`), propose | reach the approver endpoint (refused), claim a human (undecodable) |
| session owner / delegate / principals | ADR-0063's records, by subject | hold, bind, name a profile | approve |
| agent | a profile a run is admitted under | -- | approve; transfer an approval (M6 binds `agent_id`) |
| approver | an `--approver-uid`, `SO_PEERCRED` on the approver socket | be authenticated and recorded; in M6, decide | be a runtime (refused at the DWKP socket), use the DWKP socket |
| operator | the command line and in-process operator API | configure all of the above | -- |

A uid is not a person. Two people sharing a uid are one approver; nothing
here claims more.

## 5. Flow

```text
runtime uid ──▶ DWKP socket ──▶ SO_PEERCRED ∈ --allow-uid ──▶ decoder (no human fields)
                                                               └▶ admission: origin api
                                                               └▶ REQUIRE_APPROVAL → DENY

any uid ──────▶ approver socket ──▶ SO_PEERCRED ∈ --approver-uid ?
                                      no  → approver.peer_refused, closed unread
                                      yes → approver.peer_authenticated, closed unread
                                            (M6: list / show / decide on this socket only)
```

## 6. Terminals

No terminal descriptor is accepted on either endpoint. `isatty()` proves a
descriptor is a terminal, not whose; a session id proves shared ancestry,
not the runtime's absence; the proof that would matter -- no runtime uid
holds the terminal -- needs a scan of other processes the authority must not
make. M6's recommended shape is a trusted approver client run as an approver
uid, which receives the authority-rendered request as data and draws it on
its own terminal; the runtime, another uid, can neither write that terminal
nor trace that client. Interactive approval is not shipped until M6 builds
that client and its ADR is accepted (ADR-0067 §5).

## 7. Binding, replay and concurrency (M6's contract)

ADR-0021's eleven fields stay the binding; ADR-0067 §7 proposes the
requester's principal as a twelfth, for M6's own ADR to decide. An approval
names its approver and its requester; the store refuses one whose approver
is its requester; a use is burned in the same transaction as the effect's
intent, inside F-02's gate, so a revocation, an end of authority and a
concurrent spend are ordered with it and a replay produces no second
effect. None of this is built: no approval can be created, so none can be
spent, replayed or resurrected.

## 8. Audit

| kind | written | fields |
|---|---|---|
| `approver.peer_refused` | built | `uid`, `pid` (diagnostic), `reason: uid_not_an_approver` |
| `approver.peer_authenticated` | built | `uid`, `pid`, `outcome: closed`, `reason: no_approval_operation` |
| `approval.requested` / `granted` / `denied` / `expired` / `used` / `drift_detected` / `revoked`; self-approval and unauthorised-approver refusals | M6 | both identities, binding hash, canonical operation, policy revision, endpoint |

Both built kinds are written by the authority's worker from a closed event
type; no peer byte reaches them. Neither is an approval.

## 9. Adversarial matrix

Status: **IMPLEMENTED** (built here, test named), **PRESERVED** (an existing
guarantee, still tested), **NOT APPLICABLE** (no approval exists, so nothing
can be spent), **M6** (pending, not claimed).

| # | Property | Status | Evidence | Level |
|---|---|---|---|---|
| 1 | a runtime cannot use the approver endpoint | IMPLEMENTED | `transport_approver`: runtime uid refused unread; hosted `cross-uid-runtime-refused` | local same-uid; hosted three-uid, CI #201 |
| 2 | an allowed DWKP uid is not an approver | IMPLEMENTED | `a_runtime_uid_is_never_an_approver` (parser); `transport_approver` | unit; real process |
| 3 | an unknown uid cannot approve | IMPLEMENTED (identity) | `only_a_uid_the_operator_named_is_an_approver`; `cross-uid-authority-refused` | unit; hosted three-uid, CI #201 |
| 4 | a runtime-controlled pty cannot satisfy an approval | IMPLEMENTED (no terminal anywhere) | TX061, TX065, `a_descriptor_a_runtime_passes_is_never_installed_in_the_authority` | static; real process |
| 5 | a runtime's descriptor stays discarded | PRESERVED | `transport_hostile` | real process |
| 6 | forged `origin=interactive` cannot attend a run | IMPLEMENTED | `a_runtime_cannot_claim_...` (undecodable; admission `api`); TX062 | real process |
| 7 | forged `approved=true` is rejected | IMPLEMENTED | same test | real process |
| 8 | a requester cannot approve its own operation | IMPLEMENTED (identity); store check M6 | disjointness with no override; P3, P6 | unit; real process |
| 9-19 | another principal, agent, run, workspace, environment, credential, taint, privacy, obligation, inode/digest, destination cannot spend an approval | NOT APPLICABLE; M6 | no approval exists; ADR-0021 binding, re-canonicalised in M6 | -- |
| 20-23 | expiry, replay, concurrent spend, restart | NOT APPLICABLE; M6 | M6 burns inside F-02's gate | -- |
| 24 | a revoked approver cannot approve | partial: a removed uid is refused after a restart; online revocation M6 | `only_a_uid_the_operator_named_is_an_approver` | unit |
| 25 | a runtime cannot create a standing grant | PRESERVED | `StandingGrantState` one variant (P13); `standing_grant` undecodable (`transport_hostile`) | unit; real process |
| 26-27 | an invalid approval cannot override a capability or policy denial | PRESERVED (no approval path) | M6 keeps both gates | -- |
| 28 | unattended requests stay denied | PRESERVED | `an_unattended_run_cannot_be_approved_and_is_denied_instead`; route tests; P12 | unit; real process |
| 29 | agent text cannot impersonate authority text | M6 | no prompt is rendered | -- |
| 30 | an external agent's approval is not DireWolf's | IMPLEMENTED | `auto_approve`, `yolo`, `dangerously_skip_permissions` undecodable | real process |
| 31 | cross-uid checks use real identities | IMPLEMENTED; HOSTED, CI #201 | `an_approver_is_its_own_identity_and_a_runtime_is_never_one` | hosted three-uid |
| 32 | TX061-TX063 hold | PRESERVED | rules unchanged; their fixtures | static |
| 33 | F-02 concurrency | PRESERVED | `state_concurrency`, route tests in `make test` | unit; in process |
| 34 | F-03 posture | PRESERVED | posture code unchanged; `transport_server` posture test | real process |
| 35 | F-12 anchors and packs | PRESERVED | `policy_packs`, `broker_fs_read` in `make test` | in process; real process |

## 10. Mutations

`make approver-identity-mutations` (`APPROVER_MUTATIONS` in `scripts/dw.py`)
weakens each guard in turn, judged by C3's per-mutant judge: a named test
failing is the only kill. P1 the set admits every uid; P2 a refusal names a
configured uid; P3 a runtime's uid may be an approver; P4 the broker's; P5
the endpoint may be the DWKP socket; P6 the authority's uid; P7 the DWKP
socket by another spelling; P8 a refusal unrecorded; P9 the endpoint reads;
P10 it answers; P11 an authentication recorded as an approval; P12 a runtime
admission attended; P13 a standing grant held. Results: §11.

## 11. Evidence

Local, WSL Ubuntu 26.04, one identity, 2026-11-16. Hosted, CI #201 (run
44818094052, `3998de2`): the `authority-transport` job with three
identities -- uid 1001, `DW_PEER_AS`, `DW_APPROVER_AS` (uid 999) -- ran the six
`cross-uid-*` approver cases, every one contained ([PRE_M6_REMEDIATION.md](PRE_M6_REMEDIATION.md)).

`make approver-identity-mutations`: **13 of 13 killed**, each by a named
test, every file restored byte-identically; the unmutated baseline passed
first (537 unit tests, 6 real-process tests). The record is kept in
`target/p34-evidence/record.json` (`direwolf.f18-approver.mutation-review`).

| mutant | stage | killed by |
|---|---|---|
| P1 | authority-unit | `server::approver::tests::only_a_uid_the_operator_named_is_an_approver` |
| P2 | authority-unit | `server::approver::tests::only_a_uid_the_operator_named_is_an_approver` |
| P3 | authority-unit | `server::config::tests::a_runtime_uid_is_never_an_approver` |
| P4 | authority-unit | `server::config::tests::the_broker_is_never_an_approver` |
| P5 | authority-unit | `server::config::tests::the_approver_endpoint_is_never_the_dwkp_socket_and_is_absolute` |
| P6 | approver-process | `the_authority_is_never_an_approver_and_naming_it_starts_nothing` |
| P7 | approver-process | `no_runtime_broker_or_dwkp_socket_is_ever_an_approver` |
| P8 | approver-process | `the_runtime_uid_is_refused_at_the_approver_endpoint_and_keeps_its_own_door` |
| P9 | authority-unit | `server::approver::tests::the_endpoint_reads_answers_and_dispatches_nothing` |
| P10 | authority-unit | `server::approver::tests::the_endpoint_reads_answers_and_dispatches_nothing` |
| P11 | authority-unit | `state::transport::tests::an_approver_record_says_who_the_kernel_reported_and_that_nothing_was_approved` |
| P12 | authority-unit | `state::workload_route::tests::f17_a_launch_carries_both_gates_decision_for_every_granted_destination`, `...::the_shipped_packs_sandbox_rules_run_with_hygiene_kept_or_deny_honestly` |
| P13 | authority-unit | `policy::context::tests::a_standing_grant_is_never_held_and_has_no_other_value` |

The gates:

- fmt-check, lint (workspace clippy `-D warnings`, ruff), typecheck,
  schema-check, docs, arch: pass.
- `make test`: the Rust workspace, 1637 passed and none failed; pytest, 2094
  passed, 19 skipped, 1 failed -- the Git-history anchor test, which needs
  `.git` and is checked in the repository by `dwcheck adr` against history.
  One Rust test, the kernel-keyring round trip in `secret/backend`, was left
  out of that run: the host's per-user key quota was exhausted, and it fails
  the same way on the unchanged baseline; it passed in an earlier run of
  the same gate on this change.
- `make authority-transport-evidence`: every same-identity suite passed,
  `transport_approver` 6 of 6, then **NOT EXERCISED** as designed: no second
  or third identity here.
- `make authority-state-evidence`: pass.
- Every mutation table's targets still match (no new stale target).
- The three-identity test: **NOT EXERCISED** locally; it runs in the hosted
  `authority-transport` job.

## 12. Residuals and owner decisions

- The approver set is configuration: not in the audit chain at start, changed
  only by a restart (OD-6).
- A uid is the approver; its processes are trusted as it.
- Any local uid can reach the socket and be refused, rate-limited; a
  directory of the approvers' own narrows that.
- Owner decisions: ADR-0067 OD-1 to OD-6; acceptance of ADR-0067 after its
  hosted evidence.
