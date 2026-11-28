# M6.3 -- the trusted approver endpoint and client

**State (2026-11-28): built locally, not committed; hosted evidence pending.**
The record is [ADR-0081](adr/0081-the-approver-endpoints-operations-and-the-trusted-approver-client.md)
(Proposed). Nothing here is accepted, and no hosted run has exercised it.

M6.3 is the first production approval path. An approver uid the operator
names lists the approval requests that wait, shows one as the authority
recorded it, and approves or denies it at the approver endpoint, through
the trusted client `direwolf approve`. A sandboxed `process.exec` under an
`exact_action` rule is then approvable at A1 and spent once by the launch's
own transaction; every A2 class still denies. A1 is a dedicated approver
account answering. It is not proof that a person read the request.

## 1. Baseline

| | |
|---|---|
| HEAD | `f9ce26aa96f75f5f0a9a9f2dc40133be00675acf`, `main`, clean, nothing staged, no stash, one worktree; `origin/main` the same |
| commit | `docs(adr): accept ADR-0064 and ADR-0080, and close M6.2` -- its 16 files byte-identical to the validated closeout |
| CI #229 | [run 46030285112](https://github.com/Onwcan/DireWolf/actions/runs/46030285112), attempt 1, 33 of 33 |
| Push #45 | [run 46030285089](https://github.com/Onwcan/DireWolf/actions/runs/46030285089), 4 of 4 |
| `authority boundary` | "approver evidence: 1 test, 6 cases contained, three identities"; registry 34 cases each once; crash 34 cases; `authority-security` 5 passed, 0 pending |
| release build | "approval registry separation: 7 release artifacts, no test-only seam" |
| M5 gate | inventory COMPLETE, 14 bundles; acceptance READY; evals 2 passed, 2 pending (pending is not passing) |
| ADRs | 81 records: 65 accepted, 12 Proposed, 4 superseded; `accepted.sha256` 69 entries |

## 2. The record

ADR-0081, Proposed, refines the accepted approval architecture and replaces
nothing in it. It would amend ADR-0067 §3, which held that the endpoint
closes an approver's connection unread; replace TX065 under its own number,
as ADR-0067 §7 said M6's record would; and refine ADR-0080 §3 (the fatigue
rule) and §4 (the decision's production caller). It has eight owner
decisions (§26).

## 3. The contract, reconciled

| question | the records | M6.3 |
|---|---|---|
| request id and nonce | ADR-0067 §7 asks a decision to name its request id and echo its nonce; APPROVALS.md §5 (ADR-0080): "the request's id stands for the nonce" | the request id is the challenge: unique, decided once by the store's own rules. No separate nonce column; schema 15 unchanged (OD-2) |
| revocation | ADR-0067 §7's vocabulary is list, show, decide; the M6 plan expected the revocation seam's first production caller | no revocation operation: a fourth would extend an accepted closed vocabulary. `revoke_approval` keeps no production caller (OD-4) |
| assurance | ADR-0078: `Environment::Host` with any verb, a credential injected, `secret.use`, `fs.delete`, a standing grant: A2 | unchanged. The endpoint has no field for a level; the registry records A1 |
| fatigue | APPROVALS.md §8: rate limit per run; repeated explicit denials escalate to a `REPETITION` fault that ends the run; expiry is not denial | the non-punitive half: three explicit denials of one binding in a run and it is not asked again. The run-ending fault is not built (OD-3) |

## 4. The operator's approver set

From `--approver-socket` and `--approver-uid` only, parsed as ADR-0067 §2
has it: no default, wildcard, group, user name or root exception; never an
`--allow-uid`, the `--broker-uid` or the authority's own uid; at most 16; no
repeat; no override. The start-up builds one validated `ApproverSet`
(`state/approvals.rs`), attaches it to the registry once
(`Authority::attach_approver_set`, `server::attach_operator_approvers`)
before the endpoint accepts anything, and makes the endpoint's policy from
the same value (`ApproverPolicy::from_set`). A second attachment is refused.
The test-only `attach_approvers` stays test-only. A changed set takes a
restart; there is no hot reload.

The parser's refusals are the existing tests (`server/config.rs`: no
configuration, a missing half, a runtime's, the broker's uid, the DWKP
socket, a repeat, a relative path, more than 16). The start's are the
existing real-process tests (`tests/transport_approver.rs`: the authority's
own uid, the DWKP socket by another spelling), plus `ApproverSet::new`'s own
refusals. A restart that removes an approver:
`m6_3_an_approver_removed_by_a_restart_decides_and_spends_nothing`.

## 5. Authentication before decoding

```text
accept → SO_PEERCRED → one of the operator's approvers?
           no   → closed unread; approver.peer_refused
           full → closed unread; approver.peer_authenticated {outcome: closed, reason: connection_limit}
           yes  → approver.peer_authenticated {outcome: admitted}
                → one frame, its length checked from its header → decode → the worker → one answer → close
```

The endpoint's own test writes a whole, valid request before the endpoint
accepts the connection, then shows it closed with the request unread: the
kernel resets a connection closed with unread bytes
(`a_peer_that_is_not_an_approver_is_closed_before_a_byte_is_read`). Nothing
a peer sends names who it is.

**Descriptors.** Nothing in the endpoint receives ancillary data (TX061 over
the whole server directory, TX065's successor in this module): it reads with
`read`, so the kernel discards a descriptor sent with the bytes. The endpoint
detects nothing and trusts nothing it could not have read. The hosted
four-identity test sends a descriptor with the runtime's request (refused
unread) and with the approver's (answered as without one).

## 6. Typed approver provenance

`ApproverContext` (`server/approver.rs`: the kernel's uid and pid for one
connection) is made only by the endpoint's `authenticate` and holds no
subject, lease holder, caller context or level. The registry gets an
`ApproverPrincipal` made from that uid (`ApproverPrincipal::kernel_reported`,
spelled only by the endpoint and its tests, TX070). It is not a
`CallerContext`. It admits no run and reaches no tool.
`Authority::serve_approver` checks it again against the attached set in the
operation's own transaction. The decision state machine's own guards still
hold beneath that: never the requester, and A1 only.

## 7. The protocol

`dwk_proto::approverp`, version 1 -- DWKP's framing and strict decoding, and
nothing else of DWKP:

| request | answer |
|---|---|
| `{"kind":"approver.list","protocol":1}` | `approver.listed {waiting, requests[≤64], now_ms}` |
| `{"kind":"approver.show","protocol":1,"request_id":…}` | `approver.request {request: RequestDetail}` |
| `{"binding_sha256":…,"decision":"APPROVE"\|"DENY","kind":"approver.decide","protocol":1,"request_id":…}` | `approver.decided {request_id, outcome, approval_id?}` |
| any | `approver.refused {code}` |

Every message is a `reject` type: an undeclared member (an `approver`, an
`assurance`, a `scope`, `ttl_s`, `max_uses`, `standing_grant`, `uid`, `tty`,
`remember`), a duplicate member, invalid UTF-8, nesting past the lexer's
depth, a trailing value, a value outside its bound, an unknown kind or a
response sent as a request: `MALFORMED_REQUEST`. Another protocol version
gets `UNSUPPORTED_PROTOCOL`. A request is at most 1024 bytes, checked from
the frame's header (`FrameDecoder::bounded`) before any body byte is kept.
An answer is at most one frame. Each connection carries one request, read
within 5 s and answered within 5 s. Bytes past it, or a second request, get
`MALFORMED_REQUEST`; a frame that never completes is closed unanswered at
the deadline. At most 4 approver connections are served at once. A response
decoder refuses an inconsistent answer: an approval shown for anything but
a grant, a decision naming an approval for a denial, a listing longer than
what waits. Golden vectors: `each_request_has_one_canonical_spelling`.

## 8. List, show, decide

- **List** (read-only): requests that are `PENDING`, inside their window
  and of an `ACTIVE` run, oldest first, at most 64, and how many wait in
  all. A listing ends no stale request and writes no record. Every configured
  approver sees every waiting request: one approver set per authority, no
  per-approver scoping (ADR-0067 §2). An empty store gives `waiting: 0`; a
  store that cannot answer closes the connection unanswered.
- **Show** (read-only): one request in any state, as stored: id, state,
  whether it is decidable now, run, session, requester, epoch, rule, policy
  revision, scope, TTL, `max_uses`, assurance required, asked, window,
  decided, the binding's schema, hash and canonical text, the approval a
  grant recorded, and the registry's clock. A stored binding that does not
  hash to its digest is the store's fault and is never shown. The registry
  holds no agent prose, so none is sent. A runtime's DWKP gains no listing.
- **Decide**: §10.

## 9. Nonce and replay

The request id is `DomainHash("direwolf.approval.request.v1", run, binding
hash, n)`. It is unique, and the store ends it once (`GRANTED`, `DENIED`,
`EXPIRED`); a new request for the same binding gets a new `n`. A decision
naming it is the challenge, consumed by that terminal transition in the
decision's own transaction. Replays -- an approval after an approval, a
denial after it, an approval after a denial, the same decision from another
approver, after a restart -- are each `NOT_PENDING` (or `RUN_ENDED` once a
restart ended the run). There is one approval row (its id is the request's
id, hashed) and one record. The decision's single use is not the approval's
`max_uses`.

## 10. The decision, atomic

`serve_approver` → `decide_echoed` → ADR-0080's `decide`, in one
transaction:

1. the approver still in the set (else `UNKNOWN_APPROVER`);
2. the request known (else `UNKNOWN_REQUEST`);
3. its stored binding hashes to its stored digest (else a store fault:
   nothing decided, the connection closed);
4. the echoed hash equals it (else `BINDING_MISMATCH`);
5. pending (`NOT_PENDING`), inside its window (`EXPIRED`, ended), its run
   `ACTIVE` (`RUN_ENDED`, ended), the approver known, not the requester
   (`SELF_APPROVAL`), A1 for an A1 request (`ASSURANCE_UNAVAILABLE`);
6. an approval at A1 -- life the rule's TTL, uses the rule's -- and the
   request ended `GRANTED`, or the request ended `DENIED`; committed with
   its record.

A decision is not an effect intent. It dispatches nothing and holds no
authority gate. A later launch spends the approval under every ADR-0080
guard, with its binding built afresh.

## 11. Revocation

No production revocation operation exists (§3, OD-4). The approvals that do
exist end by their rule's life, their single use (by default), a policy
revision, a new tenure, the run's end, an ownership revocation or a risen
taint (ADR-0080 §8).

## 12. The client

```sh
direwolf approve list   --socket <PATH>
direwolf approve show   --socket <PATH> <REQUEST_ID>
direwolf approve review --socket <PATH> <REQUEST_ID>
```

It runs as an approver uid, talks to the approver socket only (never DWKP),
switches no user and starts no program. Any option but `--socket` is
refused ("there is no option that approves without asking"). There is no
environment default. It never builds a binding and never spells the
binding's schema (TX067). Each request is one connection.

Exit codes:

| code | meaning |
|---|---|
| 0 | done |
| 1 | nothing decided |
| 2 | usage error |
| 3 | a decision was sent and its answer lost |

## 13. Rendering and sanitisation

The authority sends data; the client renders eight regions:

1. the verified request identity;
2. the action;
3. requester and context;
4. risk and assurance;
5. scope, life and uses;
6. obligations and taint;
7. **untrusted prose from the agent, not part of the decision** -- "none" in
   this build;
8. the decision.

The binding is walked whole: every leaf is shown once, under its path, and a
member no section names appears under "other bound members".

Before showing anything, the client checks the binding:

- it parses strictly;
- re-canonicalised, it is the same bytes;
- it hashes to the digest named;
- its `requester` and `schema` are the request's.

If any check fails, approval is not offered.

**Escaping** (`approve/render.rs`) is one injective escaping for every shown
string:

- printable ASCII stands for itself;
- `\` and `"` are escaped;
- a leading, trailing or repeated space is `\x20`;
- tab, newline and carriage return are `\t`, `\n`, `\r`;
- everything else becomes `\u{…}`. That covers C0 and C1 controls, DEL and
  ESC -- so every CSI and OSC sequence, OSC 8 hyperlink, title change,
  cursor movement, erase and OSC 52 clipboard request -- as well as
  bidirectional overrides and isolates, zero-width characters, the byte
  order mark, line and paragraph separators, combining and confusable
  characters, and NUL.

So distinct values never look alike (`distinct_values_never_look_alike`).
No value can begin a line: every line of the authoritative region starts
with the renderer's own label. The client says when a value was escaped.

**Bounds.** Lines are wrapped at 76 columns with the renderer's continuation
marker, never inside an escape. A security-relevant value longer than 4096
escaped characters, or a region past 600 lines, is cut with the cut shown,
and approval is then not offered. Untrusted prose is cut at 1024 characters,
marked, and does not block a decision. Canonical bytes are never changed to
fit.

## 14. Explicit confirmation

`review` refuses a non-terminal input. It shows the request, then reads one
line:

- `approve <first eight characters of the binding hash>` approves;
- `deny` denies;
- anything else decides nothing: an empty line, `yes`, a bare `approve`, the
  wrong code, other case or spacing, the end of input, a failed read, or a
  window that ran out (at most five minutes of waiting).

Approval is never the default. A refusal is reported as the refusal it is.
A lost answer is an unknown outcome, with `show` to read back what was
recorded; a retry is `NOT_PENDING`.

The typed confirmation does not prove a person: any process of the approver
uid can speak the protocol (ADR-0077 §2). The hosted evidence drives the
released client on a pseudo-terminal with a test-only driver
(`tests/authority/approver_tty_driver.py`), which ships nowhere.

## 15. Approval fatigue

ADR-0080's bounds stand:

- 16 waiting requests per run;
- 1024 per store;
- `min(TTL, 10 minutes)` for each request;
- one waiting request per binding.

New in M6.3 (`MAX_DENIALS_PER_BINDING = 3`): a binding an approver denied
three times in a run records no further request in that run. The launch is
denied as before and the approver is not asked again. Only `DENIED` counts;
an expiry, a run's end and a cancelled review never do.
`m6_3_three_denials_of_one_binding_are_not_asked_a_fourth_time` shows both
halves. Another binding in the same run is still asked: the bound is per
action, not a punishment of the run.

Listing, showing and deciding are bounded by the four-connection limit and
the per-connection deadline. Refusals are recorded in a rate-limited class
of their own. The run-ending `REPETITION` fault is not built (OD-3).

## 16. A1 and A2

A0 is never enough. A1 is an authenticated dedicated approver. A2 needs a
presence factor the authority verifies, and M6 has none. The endpoint has no
field for a level: a claimed `assurance` member is an unknown field. The
registry sets A1 itself, and `decide` refuses A2.

| A2 class | its route | coverage |
|---|---|---|
| `Environment::Host`, any verb -- host `process.exec`, every `fs.*`, every `net.http` | no request is recorded (`consider` returns none); host execution is disabled | end-to-end (M6.2.1's real-route cases); structural (`required`) |
| a credential injected into a launch | no request recorded | end-to-end (M6.2's A2 credential case) |
| `secret.use`, `fs.delete` | no request recorded | component (`required`), M6.2.1's file-operation cases |
| a standing grant's creation | no operation, in DWKP or this protocol | structural: `StandingGrantState` has one variant; the approver protocol has no grant field |
| substituting an A1 approval for an A2 action | the binding names the environment and credentials; any change is another binding | end-to-end (drift cases) |

Nothing builds an A2 request to make an A2 decision reachable.

## 17. Audit and privacy

- `approver.peer_authenticated`: `outcome: admitted`, or `closed` with
  `reason: connection_limit`. Before M6.3 it was `closed`,
  `no_approval_operation`.
- `approver.request_refused` (new kind, rate-limited): the approver as the
  kernel reported them, the operation (or `unreadable`), the authority's
  code, the channel, and the request id a decoded message named.
- `approval.granted` and `approval.denied` gain the requester, the binding
  hash, the rule, the policy revision and the latency.
- Never recorded: a binding's members, a command, a raw frame, a terminal
  sequence, a secret.

The chain verifies across grants, denials, refusals and restarts (the
recovery children; the hosted tests' `verify-audit`).

## 18. The four-identity matrix (hosted)

`the_approver_protocol_answers_the_approver_alone_across_identities`, run by
`make approver-operations-evidence` in `authority boundary`, uses four uids:

| uid | role |
|---|---|
| the runner | the authority |
| `nobody` | the runtime (`DW_PEER_AS`) |
| `dwapprover` | the approver (`DW_APPROVER_AS`) |
| `dwother` | unrelated (`DW_OTHER_AS`) |

Each is proven a distinct non-root uid by number before anything runs.

| who | what | expected |
|---|---|---|
| runtime | list, show, decide | closed unread, nothing answered |
| unrelated | list, show, decide | closed unread, nothing answered |
| runtime | a decision with a descriptor attached | closed unread |
| approver | the released `direwolf approve list` | "0 request(s) wait" |
| approver | `show` and a raw decision of an unknown request | `UNKNOWN_REQUEST`, recorded under its uid |
| approver | a listing with a descriptor attached | answered as without one |
| runtime | the approver protocol on its DWKP door | no approver answer |

Eleven cases, each required. The F-18 identity test, renamed case 2:
`cross-uid-approver-authenticated-and-admitted`. Locally the matrix is NOT
EXERCISED: there is one uid and no sudo.

## 19. The production A1 approval (hosted, real OCI)

`linux::m6_3::production_serve_approves_one_sandboxed_launch_once_at_a1`
runs under `make approver-production-evidence` in `sandbox workload`, after
the M5 bundle is sealed. It uses the released `serve` (operator runtime and
approver uids, a sandbox config, an isolated `exact_action` policy that is
not a shipped pack), the released broker, a REAL OCI environment, and the
released client run as `dwapprover` on a pseudo-terminal.

The scenario:

1. an allowed launch prepares the environment;
2. the fixture is denied `APPROVAL_REQUIRED`, with one durable request and
   nothing run or spent;
3. `list` and `show` give the canonical record, verified;
4. a typed `approve <code>` records the approval at A1, by the approver's
   uid, on the approver endpoint;
5. the same launch runs in the real environment as uid 10001, its use spent
   after its intent, before its outcome, and the approval ends `EXHAUSTED`;
6. a replayed key spends nothing;
7. a new key is denied again;
8. a changed action is denied;
9. the audit chain verifies.

Seven cases, each required. The effect evidence is a real broker in genuine
isolated OCI. Locally it is NOT EXERCISED (no sudo, no approver uid).
In-process, through the real endpoint and worker on a real socket with the
route tests' fake broker, the same lifecycle runs locally
(`m6_3_the_endpoint_lists_shows_and_decides_and_the_launch_is_spent`).

## 20. Crash evidence

M6.2.1's real-process supervisor now holds 38 cases: its 34, plus the
endpoint's decision, killed with SIGKILL by the supervisor and recovered by
another process:

| case | what the crash leaves |
|---|---|
| `endpoint-grant-before-commit` | nothing decided; the request stays pending |
| `endpoint-grant-after-commit` | the approval and its record survive |
| `endpoint-deny-before-commit` | nothing decided |
| `endpoint-deny-after-commit` | the denial survives |

The recovery retries the decision through the endpoint's own path, as an
approver whose answer was lost would: `NOT_PENDING` if it was committed,
`RUN_ENDED` if not (the restart reaped the run). Lost answers without a
crash: `m6_3_concurrent_endpoint_decisions_record_one_and_a_lost_answer_is_read_back`.
No power-loss and no exactly-once-execution claim.

## 21. Architecture rules

| rule | change |
|---|---|
| TX065 | `…-reaches-only-the-approver-protocol` (successor): no dispatch, DWKP decoder or connection module, subject, caller context, lease holder or `unix_uid`, no `.connect(`, no decision, revocation or attachment seam, no `Assurance::`, no descriptor receipt |
| TX068 | its tables, patterns and test-only seams unchanged; `approver_route_tests.rs` exempt for the test-only attachment |
| TX069 (new) | `serve_approver`: the registry, the worker, the route tests |
| TX070 (new) | `kernel_reported` / `ApproverPrincipal {`: the registry, the endpoint, their tests |
| TX071 (new) | `attach_approver_set`: the registry and `server/mod.rs` |
| TX009 | the client's unit-test file, whose scripted endpoint listens |

TX006, TX010, TX061, TX062, TX066 and TX067 are unchanged. Each new rule has
a violation fixture, and the old TX065 fixture is rewritten for its
successor. The F-18 and M6.2 tripwires that pinned "no operation" now pin
the successor (`test_the_endpoint_reaches_only_the_approver_protocol`,
`test_the_seams_have_no_production_caller`).

## 22. Artifact separation

`approver_endpoint`, the in-process endpoint for the route tests
(`server::testing`, Linux test builds only), joins the release scan's
test-only symbols. A new release-side control requires both `dwkd-authority`
and `direwolf` to hold the approver protocol's literal. Production M6.3 code
-- `attach_approver_set`, `serve_approver`, the endpoint -- is not listed:
it belongs in the release build.

## 23. Mutation review

Three campaigns ran, each in an ordinary filesystem copy of the work tree
with its own target directory, never the checkout. Before each, every
mutant's anchor was found in its file exactly once (M6.3 37, F-18 13,
M6.2 54); every source file's SHA-256 was recorded before and compared
after, and every one was byte-identical. No process was left running.

- `make approver-operations-mutations` (M6.3): **37 of 37 killed** -- 24 in
  the authority (M01-M21, M23-M25: the approver re-checked, the echo
  compared and against its own request, decided once, a grant consuming its
  request, expiry, self-approval, A1 fixed, the use limit, fatigue and
  expiry kept apart, the listing's window and run, authentication before any
  read, the kernel's uid, the header bound, one request, the connection
  limit, refusals recorded, the deadline, the refusal's subject, an admitted
  approver never an approval, the protocol version), 2 in the protocol (M26,
  M27: the decoder's bound, a decision answer that disagrees with its
  verdict), 9 in the client (M28-M36: the typed confirmation, end of input,
  an unverified or unshowable request, the client's own hash check, the
  untrusted label, controls/ESC/ANSI, bidirectional controls, newlines, a
  cut security value) and 2 in the record (M22, M37: start-up attaches the
  set; the in-process endpoint stays test-only).
- Two mutants are named as equivalent and not run, each with its reason in
  `APPROVER_OPERATIONS_EQUIVALENT`: E1 (`decide_echoed`'s stored-binding
  hash check: schema 15 refuses any change to a stored binding or digest,
  so no stored request can disagree with its own hash) and E2 (`decide`'s
  own approver check: `serve_approver` checks the same fixed set first in
  the same transaction).
- `make approver-identity-mutations` (F-18): **13 of 13 killed**. P2 and
  P8-P11 are restated for M6.3's contract, because the endpoint now reads
  and answers an approver by design: P2's anchor follows the judgement's
  new `Err(...)` shape; P8-P10 are a *refused* peer not recorded, read or
  answered; P11 is an admitted approver's record (`outcome: admitted`) made
  to say `approved`. P1, P3-P7, P12 and P13 are unchanged.
- `make approval-registry-mutations` (M6.2): **54 of 54 killed**; its table
  is unchanged. A50 (the approver set attachable in every build) keeps its
  anchor: the test-only `attach_approvers` stays test-only, and the
  production attachment is `attach_approver_set`, kept to `server/mod.rs`
  by TX071.

## 24. Local validation

Local, 2026-11-28: WSL2 (Ubuntu 26.04, Linux
6.18.58.1-microsoft-standard-WSL2), rustc and cargo 1.98.1, Python 3.12.14
through uv 0.12.5. `Cargo.lock`, every `Cargo.toml` and the Python lock
files are unchanged.

| check | result |
|---|---|
| `make fmt-check`, `lint` (clippy `-D warnings`, all targets; ruff), `typecheck` (mypy, 130 files), `schema-check`, `docs`, `arch`, `adr-history`, `security` | pass |
| `make test` | cargo 1835 passed, 0 failed, 130 ignored; pytest 2248 passed, 18 skipped |
| `make eval-check` | gate ok: 23 passed, 0 pending, 1 skipped; `authority-security/peer-credential-check` NOT EXERCISED (one identity) |
| `make approval-registry-evidence` | 34 cases, each once |
| `make approval-registry-crash-evidence` | 38 cases, each a real process killed with SIGKILL at its window and recovered by another |
| `make approval-registry-separation` | 7 release artifacts, none of 13 test-only traces; both binaries hold the approver protocol |
| `make approver-operations-evidence` | protocol 8, endpoint 9 and client 15 tests; 22 registry cases, each once (component 15, end-to-end with the fake broker 7); the four-identity half NOT EXERCISED (the task exits 2: not a pass) |
| `make approver-production-evidence` | NOT EXERCISED (no `sudo`, no approver uid, no real OCI here) |
| mutation | M6.3 37/37, F-18 13 of 13, M6.2 54/54 (§23) |

Not exercised locally, and not claimed: the four-identity approver protocol,
the production A1 approval through released binaries in real OCI, the
Windows and macOS builds (no such target here), and `authority-transport-evidence`'s
cross-identity cases. They run on the owner's commit (§25).

## 25. Hosted evidence required

- CI on the owner's commit:
  - `make test` on three platforms;
  - `authority boundary`:
    - `authority-transport-evidence` (renamed case 2);
    - `approver-operations-evidence` (four identities, 11 cases; 22 registry
      cases; the 8-, 9- and 15-test suites);
    - `approval-registry-evidence` (34 cases);
    - `approval-registry-crash-evidence` (38 cases);
  - the release build's separation, with the new controls;
  - `sandbox workload`'s `approver-production-evidence` (7 cases, real OCI).
- None of it is claimed until it runs.

## 26. Owner decisions

All are ADR-0081's, and all are Proposed. Each is recommended as built:

| OD | decision |
|---|---|
| OD-1 | the vocabulary and framing |
| OD-2 | the request id as the challenge |
| OD-3 | three denials per binding; no run-ending fault |
| OD-4 | no revocation operation now; a later choice of `approver.revoke`, an offline operator command, or M6.4's grant records |
| OD-5 | the client's typed confirmation |
| OD-6 | TX065's successor and TX069-TX071 |
| OD-7 | the audit changes |
| OD-8 | hosted evidence before acceptance |

## 27. Formal closeout requires

1. The owner's commit and push.
2. Green hosted evidence of §25, every case named.
3. ADR-0081 accepted, recorded with `dwcheck adr --record`.
4. This report and the M6 plan updated.

## 28. M6.4's entry

Every item of §27. Then M6.4's own record: standing grants, revalidated
across a policy change, never created from a prompt, 90 days at most.
Creating one for an A2 class stays refused. Nothing of M6.4 is started.
