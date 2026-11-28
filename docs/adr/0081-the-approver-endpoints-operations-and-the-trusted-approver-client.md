# ADR-0081: The approver endpoint's operations -- list, show, decide, one request per connection, the request id as the challenge -- and the trusted approver client, at A1

**Status:** Proposed · **Date:** 2026-11-28 (proposed for M6.3; built and reviewed locally 2026-11-28, not committed; hosted evidence pending; nothing here is accepted) · **Builds on:** [ADR-0067](0067-f18-approver-endpoint-identity-boundary.md) §7 (the contract M6 builds on this endpoint, and the record that replaces TX065), [ADR-0077](0077-the-approval-channel-is-the-approver-endpoint-and-an-approver-uid-is-a-principal-not-a-person.md) (one local channel; an approver uid is a principal), [ADR-0078](0078-approval-assurance-which-classes-need-a2-and-the-presence-factor.md) (A1 and A2, as written), [ADR-0079](0079-the-approval-binding-v1-what-it-binds-and-how-it-is-encoded.md) (the binding the client shows), [ADR-0080](0080-the-approval-registry-durable-requests-and-atomic-consumption.md) (the registry, its decision seam and its bounds), [ADR-0064](0064-f02-authority-endings-serialised-with-decided-effects.md) (the gate a spend still passes) · **Would amend (on acceptance):** [ADR-0067](0067-f18-approver-endpoint-identity-boundary.md) §3 (what the endpoint does after its identity check: one approver-protocol request, not a close) and TX065 (replaced by its successor, §17) · **Would refine (on acceptance):** [ADR-0080](0080-the-approval-registry-durable-requests-and-atomic-consumption.md) §3 (a binding denied three times in a run is not asked again, §14) and §4 (the decision seam's production caller) · **Leaves unchanged:** DWKP, the private broker protocol (12), store schema 15, the binding, ADR-0078's classes, every accepted decision

> **An approver lists, shows and decides at the approver endpoint, and
> nowhere else; a decision names its request and echoes the binding it was
> shown, and is recorded once, at A1.** The kernel's report decides who
> connected before a byte is read. One bounded request per connection is
> answered by the registry, in one transaction, through the authority's one
> worker; nothing waits for a person there. The request id is the challenge:
> unique, decided once. The trusted client, `direwolf approve`, renders the
> authority's canonical record with every string escaped, shows every bound
> member, and asks for a typed `approve <code>`; anything else decides
> nothing. A1 is a dedicated approver account answering, not a proven person,
> and no A2 class is approvable.

## Context

M6.2 (ADR-0080, accepted) built the registry: a sandboxed launch denied
`REQUIRE_APPROVAL` at A1 records a durable request; `decide_approval`
records an approval or a denial once; a launch spends a use only in its
intent's transaction, every guard read again. Its decision seam had no
production caller and the shipped build attached no approver: nothing was
approvable.

ADR-0067 (accepted) gave the approver a door of its own -- a socket whose
peers the kernel identifies, disjoint from every runtime's, the broker's and
the authority's uid -- that held no operation. Its §7 is the contract for
what M6 puts behind it: a closed, minimal vocabulary (list, show, decide);
authentication before acceptance; a decision naming its request id and
echoing its request nonce; rendering from canonical data with control, ANSI
and bidirectional characters stripped, bounded, truncation shown, agent prose
apart and labelled; audit carrying both identities, the binding hash and the
policy revision. M6's own record decides the rest and replaces TX065.

## Decision

### 1. The vocabulary, closed

`dwk_proto::approverp`, version 1:

| request | answer | effect |
|---|---|---|
| `approver.list` | `approver.listed`: how many wait, and the oldest 64 -- id, run, requester, rule, binding hash, asked, window's end -- and the registry's clock | none |
| `approver.show {request_id}` | `approver.request`: the request as stored -- its state, whether it is decidable now, run, session, requester, epoch, rule, policy revision, scope, TTL, `max_uses`, assurance required, asked, window, decided, the binding's schema, hash and canonical text, the approval a grant recorded -- and the clock | none |
| `approver.decide {request_id, binding_sha256, decision}` | `approver.decided {request_id, outcome, approval_id}` | a decision, once |
| any of them | `approver.refused {code}` | nothing decided |

`decision` is `APPROVE` or `DENY`; there is no third word. No message has a
field for an approver, a level, a scope, a life, a use count, a grant, a
policy, an ownership, a session or a run to write: a member the protocol
does not declare is refused. The refusal codes are closed --
`MALFORMED_REQUEST`, `UNSUPPORTED_PROTOCOL`, `UNKNOWN_REQUEST`, `NOT_PENDING`,
`EXPIRED`, `RUN_ENDED`, `BINDING_MISMATCH`, `UNKNOWN_APPROVER`,
`SELF_APPROVAL`, `ASSURANCE_UNAVAILABLE`, `UNAVAILABLE` -- and echo nothing a
peer sent.

### 2. Framing and versioning

DWKP's framing (a 5-byte header, canonical JSON), and nothing else of DWKP:
no envelope, no handshake, no registry entry, no emitted schema, no Python
binding. Every message is a strict `reject` type: duplicate members, invalid
UTF-8, unknown fields, a value outside its bound, nesting past the lexer's
depth and trailing bytes are refused. A request's length is checked from the
frame's header against 1024 bytes before a body byte is stored
(`FrameDecoder::bounded`); an answer is at most one frame. A request of
another protocol version is answered `UNSUPPORTED_PROTOCOL`.

**One request per connection.** The endpoint reads one frame within five
seconds of accepting the connection, answers it within five seconds, and
closes. Bytes past the one request, a second request, an empty or oversized
declaration, a reserved content type or a stream that ends inside the frame
are answered `MALFORMED_REQUEST` and reach nothing; silence is closed
unanswered at the deadline. A person reads and decides between connections,
so the endpoint holds no idle connection and the authority holds nothing
while they do.

### 3. Authentication before decoding

```text
accept → SO_PEERCRED → one of the operator's approvers?
           no   → closed unread;  approver.peer_refused
           full → closed unread;  approver.peer_authenticated {outcome: closed, reason: connection_limit}
           yes  → approver.peer_authenticated {outcome: admitted}
                → read one bounded frame → decode → the worker → answer → close
```

A peer that is not an approver is closed with whatever it sent unread -- the
kernel's reset on unread bytes is what the endpoint's own test observes. At
most four approver connections are served at once. Nothing a peer sends
names who it is: no uid, user name, level, certificate, session, binding or
token is read as identity, and a binding hash or request id alone authorises
nothing.

### 4. Trusted approver provenance

`ApproverContext` -- the kernel's uid and pid for one connection -- is made
only by the endpoint's `authenticate`, from the kernel's report; it holds no
subject, lease holder, caller context or level. The registry receives an
`ApproverPrincipal` made from that uid (`ApproverPrincipal::kernel_reported`,
spelled only by the endpoint, TX065). It is distinct from a runtime's
`CallerContext` and admits nothing, holds no lease and dispatches no tool.
The registry checks it again -- in the operator's set, at the moment of the
operation -- and the decision seam's own guards hold: never the requester,
A1 only.

### 5. The operator's approver set

From `--approver-socket` and `--approver-uid` only: no default, wildcard,
group, user name or root exception; never an `--allow-uid`, the
`--broker-uid` or the authority's own uid; at most 16; no repeat; no override
(ADR-0067 §2, the parser and the start, unchanged). The start-up builds one
validated `ApproverSet`, attaches it to the registry once
(`Authority::attach_approver_set`, called by `server::start` alone, TX068)
before the endpoint accepts anything, and makes the endpoint's admitted
policy from the same value -- what the endpoint admits and what a decision or
a spend recognises cannot diverge. The test-only `attach_approvers` stays
test-only. A changed set takes a restart; an approver removed by one decides
nothing and spends nothing it granted before (the spend's guard). There is no
hot reload.

### 6. The request id is the challenge

ADR-0067 §7 asks for a decision to name its request id and echo its request
nonce. The registry's request id is `DomainHash("direwolf.approval.request.v1",
run, binding hash, n)` (ADR-0080 §3): unique to one request, ended once --
`GRANTED`, `DENIED` or `EXPIRED` -- by the database's own rules, and a new
request for the same binding has a new `n`. APPROVALS.md §5 already records
it: "the request's id stands for the nonce". It is therefore the challenge,
and **no separate nonce column is added**: a second value would be redundant
with the id's single decision, and would need schema 16 for nothing. It is
not a secret: the threat it answers is a decision applied to another request
or applied twice, not a peer guessing an id, which only an authenticated
approver could send. Store schema 15 is unchanged.

### 7. Binding echo

A decision echoes `binding_sha256`. In the decision's own transaction the
authority hashes the request's stored canonical bytes again (a mismatch is a
store fault, never decided), compares the echo with the stored digest, and
only then runs ADR-0080's `decide`. Another request's binding, a hash of
nothing, an unknown id: `BINDING_MISMATCH` or `UNKNOWN_REQUEST`, nothing
decided. The client never builds a binding: it receives the canonical text,
parses it strictly, re-canonicalises it, hashes it, compares it with the
digest and the request's requester and schema, and renders it -- and offers
approval only if every check held. At the spend, ADR-0080's fresh binding
comparison and every guard run again, whatever was shown.

### 8. Ordering

| step | where | transaction |
|---|---|---|
| the approver authenticated | the endpoint | none |
| the approver still in the set | `serve_approver` | the operation's own |
| request known; stored binding hashes to its digest; echo equals it | `decide_echoed` | the same |
| pending; inside its window (else `EXPIRED`, ended); its run `ACTIVE` (else `RUN_ENDED`, ended); approver known; not the requester | `decide` | the same |
| A2 decision or request refused; an approval recorded at A1 -- life the rule's TTL from now, uses the rule's -- the request ended `GRANTED`; or a denial ended `DENIED` | `decide` | the same, committed with its audit record |

A decision is not an effect intent and enters no ADR-0064 effect section: it
dispatches nothing, and nothing runs until a later launch spends the approval
under every guard. List and show read, in a transaction that writes nothing
(a listing ends no stale request; ADR-0080's request and decision paths do).

### 9. Replay and concurrent decisions

All operations reach the authority's single worker, so two decisions never
contend in the server; on separate handles, SQLite's `BEGIN IMMEDIATE`
serialises them. Either way the first decision ends the request and every
later one is refused `NOT_PENDING`: one terminal transition, at most one
approval row (its id is the request's, hashed), one `approval.granted` or
`approval.denied` record. A replayed approval, a denial after an approval, an
approval after a denial, the same decision from another approver, the same
decision after a restart: refused. The decision's single use is not the
approval's `max_uses`: an approval may be spent as many times as its rule
allows; its decision happens once.

### 10. Rendering and the client's part

The authority sends data, not a prompt. The client renders eight regions:
the verified request identity; the action authorised; requester and
execution context; risk and assurance; scope, life and uses; obligations and
taint; **untrusted prose from the agent, labelled as not part of the
decision**; the decision controls. The registry holds no agent prose and no
producer is added for one: the untrusted region says so. The binding is
walked whole and every leaf shown once, a member no section names under
"other bound members", so nothing bound is left out. Rendering calls no model
and interprets nothing.

### 11. Terminal sanitisation

One injective escaping for every shown string: printable ASCII stands for
itself; a backslash and a quote are escaped; a leading, trailing or repeated
space is `\x20`; tabs, newlines and carriage returns are `\t`, `\n`, `\r`;
every other character -- C0 and C1 controls, DEL, ESC (so every CSI and OSC
sequence, hyperlink, title change, cursor movement and clipboard request),
bidirectional overrides and isolates, zero-width and invisible characters,
line and paragraph separators, combining and confusable characters -- is
`\u{...}`. Two distinct values never look alike, no value can start a line,
and every line of the authoritative region begins with the renderer's own
label; the client says when a value was escaped. Lines are wrapped at 76
columns with the renderer's continuation marker, never inside an escape.

**Truncation.** A security-relevant value longer than 4096 escaped
characters, or a region past 600 lines, is cut with its cut shown, and then
approval is not offered -- only a denial. Untrusted prose is cut at 1024
characters, marked, and does not block a decision. The canonical bytes are
never changed to fit.

### 12. Explicit confirmation

`direwolf approve review` needs a terminal on its input, shows the request,
then reads one line: `approve <first eight characters of the binding hash>`
approves; `deny` denies; anything else, an empty line, the end of input, a
failed read or the request's window (at most five minutes of waiting) decides
nothing and the request stays pending. Approval is never the default. There
is no `--yes`, no approve-all, no skip, no environment default, no remembered
approval and no standing grant behind it. The decision is sent on a new
connection; a refusal is reported as one; a lost answer is reported as an
unknown outcome, with `show` to read back what was recorded -- a request is
decided once, so sending it again never decides it twice.

The interaction proves nothing about who typed: any process running as the
approver uid can speak the protocol (ADR-0077 §2). That is the A1 contract,
stated, not a gap the client closes.

### 13. Revocation

ADR-0067 §7's vocabulary is list, show and decide. A revocation operation on
this endpoint would extend that accepted, closed vocabulary, so **none is
built**: `Authority::revoke_approval` keeps no production caller, and the
approvals that exist are bounded by their rule's life, a single use by
default, the policy revision, the run's tenure, its end, ownership and taint
(every ADR-0080 §8 end). OD-4 asks whether, and how, to add one.

### 14. Approval fatigue and bounds

ADR-0080's bounds stand: 16 waiting requests per run, 1024 per store, a
window of `min(TTL, 10 minutes)`, one waiting request per binding.
APPROVALS.md §8 adds that repeated explicit denials of the same action
escalate. M6.3 builds the non-punitive half: **after three explicit denials
of one binding in a run, that run's launch of it records no further request**
-- it is denied as before, and no approver is asked a fourth time. Only a
denial counts: an expiry, an unattended window, a run's end and a cancelled
review never do. A `REPETITION` fault that terminates the run is not built:
it is a new end of authority, with its own ordering under ADR-0064, and an
owner decision (OD-3). Listing, showing and deciding are bounded by the
four-connection limit and the per-connection deadline; every refusal is a
record in a rate-limited class.

### 15. Audit and privacy

- `approver.peer_authenticated` now says `outcome: admitted`, or `closed`
  with `reason: connection_limit`; `approver.peer_refused` is unchanged.
- `approver.request_refused` (new): the approver as the kernel reported
  them, the operation (or `unreadable`), the authority's code, the channel,
  and the request id a decoded message named. Rate-limited in its own class.
- `approval.granted` and `approval.denied` gain the requester, the binding
  hash, the rule and the policy revision beside the approver, channel,
  assurance and latency they had.
- Nothing records a binding's members, a command, a raw frame, a terminal
  sequence or a secret: digests and the authority's own words only
  (ADR-0080 §9, ADR-0076). An invalid frame is a code, never a payload.

### 16. Restart and disconnection

A decision committed before a crash is in the store after it, with its
record (the registry's audit recovery); one not committed is not, and the
request is still pending or ended by its window. A lost answer is read back
with `show`; a retry is `NOT_PENDING`. A connection closed, cancelled or
timed out mid-request decides nothing and is never a denial. An approver
removed across a restart decides nothing; a decision after a restart is
judged against the new incarnation's set and the request's run, which the
restart's new tenure fences.

### 17. TX065's successor and TX068

**TX065** is replaced, under the same number, by
`TX065-the-approver-endpoint-reaches-only-the-approver-protocol`: in
`server/approver.rs`, no DWKP dispatch, decoder or connection module; no
subject, caller context, lease holder or `unix_uid`; no `.connect(`; no
decision, revocation or approver-attachment seam; no descriptor-receiving
call. The module's own test checks the same and that the kernel's judgement
precedes the serving of a connection. **TX068** keeps the registry the only
writer of its tables, and narrows the production callers: `serve_approver`
is named only by the registry, the worker and the registry's tests;
`ApproverPrincipal::kernel_reported` only by the endpoint and those tests;
`attach_approver_set` only by the registry and `server/mod.rs`. TX061, TX062,
TX066 and TX067 are unchanged: no descriptor on either endpoint, no approval
insert outside the registry, the binding granting nothing and named only by
the state layer -- the client parses the binding as JSON and never spells
its schema.

### 18. Production artifact separation

M6.2.1's release scan forbids the test seams: `attach_approvers`, the crash
children and their variables. M6.3's production code -- `attach_approver_set`,
`serve_approver`, `ApproverPrincipal`, the endpoint -- is legitimately in the
release build and is not in that list; the in-process endpoint helper for
the route tests (`server::testing`) is test-only and joins it. Positive
controls stay: the unit-test build must hold each seam, the release build
the production symbols.

### 19. Evidence

Local: the protocol's golden vectors and refusals; the endpoint's own tests
(closed unread, one bounded request, the connection limit, the deadline,
every malformed frame); the registry's route tests (list, show, the echo,
replay, concurrency on separate handles and through the endpoint, expiry,
run end, self-approval, removed approver, fatigue, the approval spent once
by its exact action); the client's tests (no auto-approval option, the
typed words, refusal and lost-answer reporting, unverifiable and over-long
requests offered only a denial, hostile strings escaped). Hosted only, with
real identities: the three-identity suite in `authority boundary` -- the
runtime refused unread at every operation, an unrelated uid the same, the
approver listing, showing and deciding through the released `direwolf`
client -- and the first production A1 approval through the released `serve`,
the released broker and a real OCI environment in `sandbox workload`. A
mutation review of the new guards. None of it is claimed until it runs.

### 20. What stays as it was

DWKP and every runtime operation (approval-shaped members remain unknown
fields); the private protocol; store schema 15; the binding and its
encoding; ADR-0078's classes -- `Environment::Host` with any verb, a launch
that injects a credential, `secret.use`, `fs.delete`, a standing grant's
creation -- all A2, none approvable; the shipped packs; the in-run
concurrency exclusions.

## Consequences

- The first production approval path exists: a sandboxed `process.exec` at
  A1 under `exact_action`, approved at the approver endpoint by a dedicated
  approver uid, spent once.
- An operator who configures the endpoint can approve; one who does not has
  exactly what M6.2 had.
- A1 is the whole of what M6 offers; the four A2 classes stay `DENY`.

## Residuals

- **A uid is the approver** (ADR-0067, ADR-0077): any process of that uid
  can list, show and decide; the client's typed confirmation is not a
  presence factor.
- **Narrow terminals** soft-wrap lines the renderer wrapped at 76 columns;
  the client cannot learn the width without a terminal query it does not
  make.
- **No revocation operation** (OD-4); **no `REPETITION` fault** (OD-3).
- **List is bounded**, not paginated: the oldest 64 of at most 1024.
- **Hosted only**: genuine three-identity and real-OCI evidence cannot run on
  a one-user machine.

## Alternatives considered

- **A separate challenge nonce per request.** Rejected: the request id is
  already unique and decided once (§6); a second value needs schema 16 and
  adds nothing an authenticated approver could not already send.
- **A long-lived approver session with several requests.** Rejected: a
  connection held while a person reads is held state; one request per
  connection keeps the endpoint stateless and every wait in the client.
- **The authority rendering the prompt.** Rejected: ADR-0067 §5 -- the
  authority cannot know the terminal; it sends data and the client, under
  the approver's uid, renders it.
- **Stripping control characters.** Rejected: deleting a character can make
  two values look alike, or hide what is bound; escaping is injective.
- **`--yes` for scripts.** Rejected: a decision a person did not type is
  the fatigue the registry exists to prevent; evidence uses an isolated test
  driver.

## Owner decisions

- **OD-1** The vocabulary and framing as §1-§3: list, show, decide; one
  request of at most 1024 bytes per connection; four connections; five-second
  deadlines.
- **OD-2** The request id as the challenge (§6): no separate nonce, schema 15
  unchanged.
- **OD-3** Fatigue as §14: three explicit denials of one binding in a run and
  it is not asked again; expiry never counts; no `REPETITION` fault or run
  termination in M6.3 -- a later decision if wanted.
- **OD-4** Revocation (§13): none on this endpoint in M6.3. Choose later
  between `approver.revoke {approval_id}` on this endpoint (amending ADR-0067
  §7's vocabulary, under ADR-0064's gate as `revoke_approval` already is), an
  operator command against a stopped authority, or leaving revocation to
  M6.4's grant records.
- **OD-5** The client's confirmation as §12: a terminal, `approve <code>`,
  `deny`, nothing else; no option that approves without asking.
- **OD-6** TX065's successor and TX068's narrowed callers as §17; the
  production attachment at start only (§5).
- **OD-7** The audit changes as §15.
- **OD-8** Hosted evidence before acceptance: the three-identity suite and
  the real-OCI production approval, each case named.

## Evidence

Local, 2026-11-28 (WSL2, Linux): see
[M6_3_IMPLEMENTATION.md](../M6_3_IMPLEMENTATION.md). Hosted: pending the
owner's commit; this record stays Proposed until the owner accepts it after
that run.
