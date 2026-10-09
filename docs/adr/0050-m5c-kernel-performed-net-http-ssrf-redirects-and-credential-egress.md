# ADR-0050: M5c — kernel-performed `net.http`: the authority authorises every hop, the broker is the HTTPS client, and a credential reaches only its bound origin

**Status:** Proposed · **Date:** 2026-10-08 · **Amends (on acceptance):** [ADR-0018](0018-authority-broker-split.md) (the broker gains a second outbound path), [ADR-0019](0019-language-rationale-v2.md) (the broker's dependency set: a TLS client, §18), [ADR-0039](0039-durable-authority-state.md) (schema version 8, §11), [ADR-0043](0043-m4b-private-broker-channel-and-brokered-fs-read.md) (private protocol version 7, §12), [ADR-0045](0045-m4d-process-execution-broker.md) (the broker starts a process in a second place: one exchange worker per `net.http` hop, §9, D11; TX021, TX049), [ADR-0046](0046-m4e-secret-handles-backends-injection-and-redaction.md) (§12: mode A gains its consumer; `broker.secret_egress` is retired), [ADR-0048](0048-m5b-proxy-only-topology-and-connect-proxy.md) (the IP guard and the resolver are shared, not forked — its "Revisit if" on `net.http`; TX037's single dial site becomes two) · **Refines:** [ADR-0000](0000-authority-plane-separation.md) (§3 argues why this is not a second path from cognition to effect), [ADR-0005](0005-tool-system.md) and [TOOL_SYSTEM.md](../TOOL_SYSTEM.md) §3 (tool 12, `net.http`), [ADR-0028](0028-policy-input-ownership.md) (destination novelty and the destination address are kernel-derived), [NETWORK_SECURITY.md](../NETWORK_SECURITY.md) §§2–5, 8, 9

> **The runtime asks for one typed HTTPS request; the authority decides every
> hop of it; the broker performs each hop as the TLS client, to an address
> both daemons judged with the same guard, and returns it unfollowed.** A URL
> is canonicalised once, by one parser shared with the capability grammar.
> Nothing is resolved before a grant covers the host. The answer is guarded
> whole and pinned for the whole request, redirects included. A redirect is
> a new request the authority authorises from scratch — capability, guard,
> policy, budget — and a credential (secret mode A) is attached only to a hop
> whose origin is exactly the one its metadata names, through a fresh one-shot
> handoff each time. Nothing here touches the `PROXY_ONLY` tunnel: it stays
> opaque, TLS-free and credential-free. No TLS is intercepted anywhere, and
> the runtime still has no network.

## Context

Built and reusable, by milestone:

| Already built | Where | What M5c takes from it |
|---|---|---|
| Opaque handles, metadata (origins, header, prefix, `egress` mode), `secret.use` gates, durable injection ledger, one-shot pipe, the broker's mode A render that **drops** the header | M4e, ADR-0046 §§10–12, 17, 19–21 | the whole secret side; M5c gives the render a request to go into |
| The canonical host (`dwk_proto::wire::host`): lowercase labels, no Unicode, no literal, no trailing dot | M5b, ADR-0048 §4 | the host of every URL, compared byte for byte with grants |
| The trusted resolver (`egress/resolve.rs`): the host's resolver under a 5 s deadline, ≤ 32 in flight; the evidence-only fixture resolver | M5b, ADR-0048 §§6, 13 | the only resolver; shared |
| The IP guard (`egress/guard.rs`): the whole answer judged, mixed refused, metadata names refused, no production exception | M5b, ADR-0048 §6 | shared, and run by both daemons (§6) |
| `network.https:<host>:<port>?methods=…&max_requests=…` with containment | M3b, CAPABILITIES.md §2 | the grant each hop needs |
| `CanonicalAction` with `destination_ip` and `destination_novelty` | M3c, `policy/action.rs` | facts M5c finally computes |
| Shipped packs: `safe` denies all egress; `balanced` denies `network.http`, allows registry hosts with `max_output_bytes`, requires approval for a tainted run's novel destination | M3c, `policy/*.toml` | unchanged; they start deciding real requests |
| Return-path redaction (exact values, known shapes) | M4e, ADR-0046 §21 | applied to response bodies |
| Intent before effect, `UNKNOWN` never repeated, idempotency keys, crash points | M4c–M4e | every hop |

Constraints this design must keep:

- **The `PROXY_ONLY` path stays opaque** (ADR-0048, TX038): no TLS stack,
  credential header or secret may enter `egress/` or the relay, and nothing
  credential-bearing may ever travel on a relay socket.
- **The broker decides nothing** (ADR-0018, TX013), **the authority executes
  nothing** (TX010) **and connects to nothing** — ADR-0018's split, which no
  rule spells across the whole authority today (TX007 covers only `server/`;
  §17 adds TX047): authorisation, redirects and credential choice are the
  authority's; resolution, dials, TLS and bytes are the broker's.
- **No TLS interception, no CA, no trust-store change, no network for the
  runtime** (NETWORK_SECURITY.md §4; M9 owns the runtime's confinement).

## Decision

### 1. Scope

In: the public tool `net.http` (ToolInvoke version 4); URL canonicalisation;
the per-hop pipeline; resolution, guard and pinning; redirects with per-hop
reauthorisation; mode A credential injection; budgets and deadlines; durable
state; private protocol version 7; audit; network-sourced taint; evidence,
evals and CI; architecture rules.

Out (unchanged owners): package-manager routing and per-tool proxy
configuration (M5d/M5e); production sandboxed `process.exec` (M5d); secret
modes B/C in sandboxes (M5d); M5e's gate; approvals (M6, so
`REQUIRE_APPROVAL` stays a denial); model egress (M7 — it may later reuse the
broker's HTTPS client, by its own ADR); artifacts and spill (M12); channel
egress (M20); plain HTTP, WebSocket and HTTP/2 (D6).

### 2. Who does what

| Step | Authority | Broker |
|---|---|---|
| Decode, canonicalise URL and headers | **yes** | no |
| Capability, policy, budget, novelty, obligations | **yes** | no |
| DNS resolution | asks, only for a granted host | **performs** (its resolver, its deadline) |
| IP guard | **judges again** (same function) | **judges** (same function) |
| Durable intent, outcome, `UNKNOWN` | **yes** | no |
| Secret read, one-shot handoff | **yes** | reads the pipe once and hands the value on, in a fresh pipe, to the hop's exchange worker (§9), which renders it and zeroises |
| TCP dial (pinned addresses only), TLS, HTTP/1.1 | no | **performs** — the dial in the broker; TLS and HTTP/1.1 in the hop's exchange worker, over that connection (§9, D11) |
| Follow a redirect | **decides** (new hop) | never |
| Redaction, taint, the answer, audit | **yes** — every indexed value and known shape; the audit | the hop's **own** credential only, before anything of the response is encoded (§8, D11); counts |

### 3. The public request: ToolInvoke version 4

`net_http` joins the closed set of typed members (with the eleven of version 3)
under the mandatory idempotency key; `CanonicalPreview` version 4 previews it
without contacting the broker (it decides with the capability and policy gates
only — the address is not known without a resolution, so the preview says so).

| Field | Type, bound | Notes |
|---|---|---|
| `method` | `GET` `HEAD` `POST` `PUT` `PATCH` `DELETE` `OPTIONS` | the capability layer's closed set; no `CONNECT`, `TRACE`, extension methods |
| `url` | text ≤ 8 KiB | canonicalised by the authority (§4); `https` only (D6) |
| `headers` | ≤ 32 pairs, ≤ 8 KiB total | names RFC 9110 tokens, values visible ASCII and space; refused names in §4 |
| `body` | bytes ≤ 256 KiB, hex on the wire like `fs` content | only for `POST` `PUT` `PATCH` `DELETE` |
| `credential_handle` | optional handle | never a header name, value, origin or mode |
| `follow_redirects` | bool, always stated | at most 5 hops (§7) |
| `max_response_bytes` | optional, 1 to 262 144 | can only narrow |

**As built.** The body and response bounds are 256 KiB, not 1 MiB and 8 MiB:
they are derived from the 1 MiB DWKP frame (`dwk_proto::limits`): hex doubles
a body, so the largest request is 806 125 bytes and the largest result
596 329 bytes, each under the frame with room for every other field, and a
compile-time assertion keeps them so. The per-run network byte budget (§10)
is a separate, larger bound and is not this one. The wire-schema security
scan (`tests/protocol/test_no_secret_value_fields.py`) admits exactly
`credential_handle` and `secret_handle` among credential-like names; the
response says `injected` per hop and the plan names the `injection` action:
neither is a value-bearing member, and no member can hold a credential value.

Never on the wire: an address, a resolver, a proxy, a timeout beyond the
narrowing above, TLS options, trust material, a cookie jar, a mode, an origin
for the credential, or anything the authority decides.

The result: `status`; a closed allowlist of response headers (`content-type`,
`content-length`, `etag`, `last-modified`, `retry-after`, `cache-control`,
`location` as canonicalised); the body, redacted, bounded, with `truncated`;
the hop chain (each hop's origin, method, status, whether a credential was
attached, and its disposition); and, when a redirect was not followed, why.
`Set-Cookie` is never returned (counted). Denial, refusal and failure follow
the version 3 shapes with the dispositions of §13.

**Not a second path (ADR-0000).** This is the path from cognition to effect
for the network, like ToolInvoke for files and processes: a typed call the
authority canonicalises, decides and records before anything leaves; the
broker is not addressable from cognition; redirects never leave the
authority's loop; the runtime still holds no socket.

### 4. One canonical URL, one origin

A shared, pure parser (`dwk_proto::wire::url`, std-only, no Unicode database)
used by the authority for requests and `Location` values:

- `https://` exactly; userinfo refused; host by `wire::host` (so no literal,
  bracket, uppercase, Unicode, trailing dot, percent-encoding or backslash in
  the host); port strict decimal, `443` when absent, carried explicitly.
- Path: `/` then visible ASCII; dot segments and their encodings (`%2e`)
  refused rather than removed; `%`-escapes require two hex digits and are
  upper-cased; no control byte, space, backslash or `#`; query kept verbatim
  after the same byte checks; fragment refused.
- **Origin** = (`https`, host, port). Credential binding, novelty, pinning and
  redirect decisions compare origins by bytes, never URLs.
- `Location`: an RFC 3986 relative reference resolved against the hop's URL,
  then canonicalised by the same parser; anything else ends the chain
  (`REDIRECT_TARGET_INVALID`).
- Refused request header names: `Host`, `Content-Length`, `Transfer-Encoding`,
  `Connection`, `Keep-Alive`, `Upgrade`, `TE`, `Trailer`, `Expect`,
  `Proxy-*`, `Forwarded`, `X-Forwarded-*`, `Cookie`, `Authorization`, and the
  header name of **any** configured secret's metadata — the runtime can never
  write a credential header (`HEADER_FORBIDDEN`).

### 5. The per-hop pipeline

For the request and for each redirect hop, in this order, in the authority:

1. **Canonicalise** (§4). A malformed target refuses before anything is
   resolved.
2. **Names**: a metadata name (`metadata.google.internal`, `metadata.goog`,
   `instance-data`) refuses (`ADDRESS_BLOCKED`), as in the proxy.
3. **Capability**: `network.https:<host>:<port>` with `methods` containing the
   method and `max_requests` not exhausted; `secret.use:<handle>` when a
   credential is asked. **Nothing is resolved for a host no grant covers**, so a
   DNS name cannot carry data to an ungranted zone.
4. **Resolve** (broker, `broker.http_resolve`): once, under the resolver's
   deadline — unless this request already pinned the host (§6).
5. **Guard**, in the broker and again in the authority, with the one shared
   function: the whole answer, mixed refused (§6).
6. **Policy** on the complete canonical action — capability, environment
   `HOST`, `byte_count` (request body), `destination_ip` (evaluated for each
   pinned address; every one must allow), `destination_novelty` (kernel-derived,
   §11). Every obligation must be enforceable — `max_output_bytes` (response
   cap) and `audit_level` are; any other denies (`OBLIGATION_UNENFORCEABLE`).
   `REQUIRE_APPROVAL` is a denial until M6.
7. **Budgets** (§10).
8. **Outgoing secrets**: the URL, header values and body are scanned with the
   redaction index; a configured secret's value in them refuses
   (`SECRET_IN_REQUEST`) — the runtime should never hold one, and sending one
   would be exfiltration.
9. **Durable intent** — the hop, and, when a credential is attached, its
   secret injection (ADR-0046 §17) — in one transaction, no I/O.
10. **Exchange** (broker, `broker.http_exchange`): typed hop, pinned
    addresses, server name, rendered fields, and the secret pipe as the last
    descriptor when §8 allows one.
11. **Outcome** durable; taint raised (§14); the origin recorded as reached if
    the TLS handshake completed (§11).
12. **Response**: header allowlist, `Set-Cookie` dropped, redaction, caps.
13. **Redirect**: §7, or the answer.
14. **Audit** throughout (§13).

### 6. Resolution, the guard, and the pin

- **One guard.** `egress/guard.rs` moves to a pure function over octets in
  `dwk-proto` (no `std::net` in the authority's types — the policy core's
  `IpAddress` shape), called by the proxy, by `net.http`'s broker side and by
  the authority. Same table as ADR-0048 §6; production has no exception.
- **One resolver.** The broker's `Resolver` (production and evidence fixture)
  serves both the proxy and `net.http`; its deadline and in-flight bound are
  shared.
- **The pin is the request's.** The authority keeps a per-invocation map
  host → guarded address set. A later hop to a pinned host sends the set back
  with the hop; the broker re-guards it and never resolves that host again. A
  new host is resolved once. Nothing is cached across invocations: the next
  request resolves and is judged afresh (so a rebinding name is pinned for one
  request and refused on the next if its answer turns blocked).
- **Dials**: only the pinned addresses, in order, 10 s in all, one connection
  per hop, never through a proxy, never re-resolving.

### 7. Redirects: every hop is a new request

- Followed only if `follow_redirects` is true, for `301` `302` `303` `307`
  `308` with a `Location`; at most **5 hops** (the operator may lower it).
- `GET`/`HEAD` follow with the same method; `303` turns any method into `GET`
  without a body; `301`/`302`/`307`/`308` for a method with a body are **not
  followed** — the 3xx is returned (`REDIRECT_WOULD_RESEND_BODY`) (D5).
- Each hop runs §5 from step 1: a hop to an ungranted host, a blocked or mixed
  answer, a denied policy or a spent budget **ends the chain before anything
  is sent to it**, returning the last response with the reason.
- `https` → anything else is impossible by §4 (`REDIRECT_TARGET_INVALID`); a
  URL seen earlier in the chain ends it (`REDIRECT_LOOP`); the sixth hop ends it
  (`REDIRECT_LIMIT`).
- The broker never follows, retries or caches; a 3xx is just a response to it.

### 8. The credential: mode A's consumer

- Attached only when the request named a handle, mode `egress` is in its
  metadata's allowlist, the hop's **origin equals the request's first origin
  exactly**, and the metadata's origins cover it (ADR-0046 §15's endpoint
  grammar: no wildcard language, no port or suffix confusion).
- **Each attachment is its own use**: `secret.use` through both gates, its own
  durable intent, one backend read, one fresh pipe, one use counted on a
  confirmed injection (ADR-0046 §§11, 17, 20). A same-origin redirect may
  therefore carry the credential again, each time decided and recorded (D4);
  a **cross-origin hop never carries it**, whatever the metadata says about the
  other origin, because the request did not ask for it there.
- The broker reads the value once from the authority's pipe, refuses a byte
  a header cannot carry, and hands it on in a fresh pipe to the hop's exchange
  worker (§9); the worker renders `Name: prefix value` (ADR-0046 §12) into the
  request it is about to write — the only place a credential header is
  composed (TX045) — refuses CR/LF/NUL again, and zeroises the header and the
  pipe contents when the exchange ends. The credential exists in the
  long-lived broker between its one read and the hand-on, in a buffer zeroed
  then, and in the worker for one exchange.
- **An echo stops at the broker (D11).** The exchange worker that put the
  value on the wire takes it out of what comes back, as M4e's supervisor does for a launch
  (ADR-0046 §16), **before any byte of the response is copied into the
  answer**: the value moves from the pipe's buffer into a `Needle` that lives
  exactly as long as the exchange; every response header holding it is
  counted, and a kept header or `Location` holding it is dropped whole; the
  body is read past the bound by the value's length — so an echo that
  straddles the bound is seen whole — redacted into a `Zeroizing` buffer with
  `[redacted:<handle>]`, and only then cut to the bound. The count crosses as
  `credential_echoes` and is audited as `secret.redaction_hit` for the handle.
  The authority's index redaction (every configured value, known shapes)
  stays the second layer over the whole answer. `Set-Cookie` never reaches the
  runtime; the audit names the handle and the origin, never the value or a
  prefix of it.
- `broker.secret_egress` (render and drop) is retired: version 7 has no
  credential path but `broker.http_exchange`.

### 9. The broker as the HTTPS client

- **TLS** (D1): TLS 1.2 and 1.3 only; SNI and certificate name are the
  canonical host; the certificate is verified against the broker's trust roots;
  ALPN offers `http/1.1` only; no client certificate; no session resumption
  across exchanges; no ECH configuration. No certificate or key is persisted.
- **HTTP/1.1** (D2): the broker renders the request from typed fields —
  request line, `Host`, a fixed `User-Agent: DireWolf/<version>`,
  `Accept-Encoding: identity`, `Connection: close`, `Content-Length` when a
  body is sent, the allowed runtime headers, the credential header when §8
  allows. It parses the response strictly: status line, at most 100 headers in
  64 KiB, `Content-Length` or `chunked` (no both, no other transfer coding),
  `101` and a non-identity `Content-Encoding` refused, trailers ignored, the
  body read to the cap plus one byte.
- **No ambient configuration**: no proxy variable, no `SSL_CERT_FILE`, no
  user trust store; the broker reads no environment on this path (TX046).
- **The evidence-only trust anchor**: `dwkd-broker serve
  --allow-evidence-trust <pem>` **replaces** the roots with a test CA, logged
  loudly at start, and is refused unless `--allow-evidence-egress` is given
  too — a broker that resolves real names never trusts a test authority; no
  production configuration names either, and no wire field can (TX036).
- **One hop, one process: the exchange worker (D11, as built).** The broker
  judges the hop again, reads the credential once, and dials one pinned
  address (`http/connect.rs`, the only dial site of this path); TLS and
  HTTP/1.1 then run in `dwkd-broker http-worker` — this binary, started for
  that hop alone (`http/worker.rs`): empty environment, stdin and stdout
  `/dev/null`, its own process group, and for stderr one end of a socket pair
  that is its only channel. The worker refuses to read anything unless that
  channel's peer is its parent broker (same uid, pid = parent pid); then,
  before it receives anything, it makes itself non-dumpable (always — the
  broker's development `--allow-dumpable` does not reach it), sets
  `RLIMIT_CORE` 0, arms the parent-death signal (`SIGKILL`) and checks its
  parent is still the broker, sets `no_new_privs`, and requires that it
  inherited no descriptor (`hardening::worker`). It is then handed exactly
  one operation by `SCM_RIGHTS`: the **connected** socket, the credential's
  pipe when the hop carries one, the trust (Mozilla's roots, or the evidence
  anchor the broker itself was given), the hop's time left, and the hop's
  authorisation frame, decoded strictly by the private protocol's decoder.
  It holds no descriptor for the authority, the store, the CONNECT proxy or
  any listener; it resolves no name, chooses no address, dials nothing and
  follows nothing; it reads no environment and no flag, and no file but its
  own descriptor table (`/proc/self/fd`). It is not a second
  network path: it can only speak to the one origin its broker already
  connected it to, under the same strict client as before. It writes `S` on
  its channel immediately before the first byte of the request, then `A`, a
  length and one `BrokerOutcome` frame, and exits; the broker reads to end of
  file under the hop's deadline plus a 5 s grace, reaps it (killing one that
  overruns), and believes the answer only whole and only for this hop. A
  worker that ends without an answer sent nothing if it never wrote `S`
  (`HTTP_WORKER_FAILED`, a refusal) and may have been heard if it did
  (`EXCHANGE_UNCONFIRMED`, recorded `UNKNOWN`, never repeated). Every spawn
  in the broker, and every secret pipe while its writer is open, is under one
  lock (`process::fork_guard`), so no concurrently forked child ever holds a
  credential pipe's writer. The worker is this binary as the broker found it
  at start (a broker whose binary was already deleted refuses to serve); an
  upgrade that replaces the file under a running broker starts workers of the
  new version, and the hand-over's magic and strict decoding refuse an
  incompatible one before anything is sent (`HTTP_WORKER_FAILED`) — executing
  `/proc/self/exe` instead would be executing through procfs, which TX022
  forbids. **What it buys:** the long-lived broker never
  holds the credential header, the request or any byte of the response, so
  what `rustls` and the `http` header map copy and free unzeroed dies with
  the worker's address space before the broker answers (§§18, 20).

### 10. Budgets and deadlines

| Bound | As built | Who enforces |
|---|---|---|
| URL / request headers / request body | 8 KiB / 32 and 8 KiB / 256 KiB | authority (decode) and broker (render) |
| Response header block | 100 headers, 64 KiB | broker |
| Response body | min(256 KiB, `max_output_bytes` obligation, request's narrowing) | broker reads cap + 1 — cap + the credential's length + 1 on a credential hop, redacting it before the cut (§8); authority marks `truncated` and redacts within the bound |
| Redirect hops | 5 (6 hops) | authority |
| Deadlines | resolve 5 s; connect 10 s; TLS 10 s; response head 15 s; body idle 15 s; hop 30 s (broker); the hop's exchange worker, the hop's deadline plus 5 s, then killed (§9); request, all hops, 300 s (authority) | broker per hop; authority across hops |
| Per run | requests 100, bytes out 8 MiB, bytes in 64 MiB, origins 16 (`StartupConfig::net_budget`) | authority, durable, never refilled |

**As built.** Each hop is **charged at its intent**, before anything is sent,
from its own bounds: bytes out are its body, headers, request target, host, a
fixed request-line allowance and — when it carries a credential — the largest
credential a header may hold; bytes in are its response bound plus the largest
head. A run's spend is read from its `net_hop` rows (count, sums, distinct
origins), which are never deleted or changed after the intent, so nothing
refunds or refills a budget, and a restart forgets nothing. A capability's
`max_requests` is compared with the run's whole hop count — conservative: a
grant limited to N requests is spent by any N hops of the run, not only by
hops to its own hosts. The daemon's configuration file does not expose the
budgets yet: `serve` runs with D10's defaults, and the in-process
`StartupConfig` sets them (the evidence does).

### 11. Durable state: schema version 8

Append-only by trigger, with a transactional migration from 7 tested with data:
`net_request` (one per invocation: intent → `COMPLETED`/`FAILED`/`UNKNOWN`
exactly once, the method, origin, URL digest, credential handle and whether
redirects are followed fixed at its intent), `net_hop` (one per hop, in order,
one open at a time, of an open request: origin, method, URL digest, the pinned
addresses, its credential's `secret_injection` row, its charges, then status,
bytes each way, whether its handshake completed, a disposition), and
`net_idempotency` (subject, session, key → the request and the digest of the
canonical call it is bound to). One idempotency namespace across the three
ledgers: a trigger on each refuses a key another bound, and each tool family
refuses such a key cleanly before it inserts. **There is no separate counter
table**: budgets are the hops (§10). **Novelty** is a fact, not a guess: an
origin is *seen* by a run once a hop of that run completed a TLS handshake
with it (`tls_established`), and *novel* until then. An intent a dead
incarnation left open — a hop, its request — is ended `UNKNOWN` at start and
never performed again; its secret injection, if any, follows ADR-0046 §19.

### 12. Private protocol version 7

`broker.http_resolve` {host} → the guard's verdict and, when resolved, at
most sixteen pinned addresses; `broker.http_exchange` {hop number, method,
origin, request target, judged headers, body, pinned addresses, response
cap} with no descriptor, and `broker.http_credential_exchange` — the same,
with the credential's handle, header name and prefix — with the secret pipe
as its one descriptor → status, the kept headers, `location` apart and raw,
the body to the cap, `truncated`, counts of dropped headers and cookies,
`credential_echoes` (§8: how often the response held the hop's own
credential — a count, never a byte), bytes each way, and a disposition
(`COMPLETED`, `RESPONSE_MALFORMED`, `ENCODING_UNSUPPORTED`, `TIMEOUT`).
Headers and `location` cross only for a `COMPLETED` exchange; one that broke
off carries its status and counts alone. An ending before a byte of the request
was sent is a refusal (`HTTP_ADDRESS_BLOCKED`, `HTTP_CONNECT_FAILED`,
`HTTP_TLS_FAILED`, `HTTP_TIMEOUT`, `HTTP_REQUEST_INVALID`,
`HTTP_WORKER_FAILED` — the hop's exchange worker could not be started or
handed the hop, or ended before its first request byte (§9) — `SECRET_*`),
never a disposition. A worker that ended after it began sending is the
indeterminate `EXCHANGE_UNCONFIRMED`: the authority records the hop and its
request `UNKNOWN` and never performs them again. Deadlines are the broker's own constants, never fields.
`broker.secret_egress` is removed — its kind no longer decodes; versions 1–6
are refused. Nothing on the wire names a resolver, an exception, a proxy
endpoint or trust material (TX036, extended); no field can hold a secret
value. The authority checks every answer against what it sent: no more body
than the bound, no header off the keep-list, addresses exactly when resolved,
no header or `location` on an exchange that did not complete, and echoes of a
credential only from a hop that carried one — any other answer is the
broker's protocol failure, after sending, so `UNKNOWN`.

### 13. Errors, audit and failing closed

Every refusal is typed and happens before the step it guards: `URL_INVALID`,
`HEADER_FORBIDDEN`, `BODY_TOO_LARGE`, `ADDRESS_BLOCKED`, `ADDRESS_MIXED`,
`RESOLUTION_FAILED`, `RESOLUTION_TIMEOUT`, `CONNECT_FAILED`, `TLS_FAILED`
(handshake, certificate, name), `RESPONSE_MALFORMED`, `RESPONSE_TOO_LARGE`
(when truncation is not allowed), `ENCODING_UNSUPPORTED`, `TIMEOUT`,
`BUDGET_EXHAUSTED`, `SECRET_IN_REQUEST`, `INJECTION_MODE_UNAVAILABLE`,
`REDIRECT_TARGET_INVALID`, `REDIRECT_LOOP`, `REDIRECT_LIMIT`,
`REDIRECT_WOULD_RESEND_BODY`, `PLAINTEXT_UNSUPPORTED`. There is no fallback of
any kind: no direct path, no retry, no re-resolution, no downgrade.

Audit (no payload, no header value, no body, no path, no query):
`net.http.resolved` (the verdict and the addresses pinned), `net.http.intent`
(the hop's gates — every pinned address's — novelty, charges, credential
handle and use), `net.http.hop` (origin, method, status, disposition, bytes,
whether the handshake completed, credential attached and handle, dropped
headers and cookies, the SHA-256 of the canonical URL), `net.http.redirect_ended`
(reason), `net.http.outcome`; refusals, denials and previews as `tool.refused`,
`tool.denied` and `tool.previewed` with the tool `net.http`; the secret side's
own records (ADR-0046 §20) and `secret.redaction_hit`. Decisions record the
matched rule as every effect does.

### 14. Taint

Any response head raises the run to `EXTERNAL_UNTRUSTED` (monotone, recorded
with the hop's outcome) — at **each hop**, before the next hop is decided and
before anything is answered: a redirect's target is chosen by network
content. `balanced`'s `approve-egress-when-tainted` then applies to the run's
next novel destination, a redirect's included — a denial until M6.

### 15. Policy and the shipped packs

No pack changes. `safe` denies all egress; `balanced` denies plaintext and
allows HTTPS to its registry hosts with `max_output_bytes`; `power` keeps its
rules. **Every shipped pack still denies `secret.use`**, so credential egress
is exercised under a dedicated operator test policy, as M4e's was, and is
never described as shipped behaviour.

### 16. Evidence, evals and CI

`make net-http-evidence` — no Docker, no internet: the real daemons, local TLS
origins under the evidence trust anchor and the fixture resolver (which maps
fixture names to loopback, allowed for the evidence only), every case
required, NOT EXERCISED fails, and a production broker shown to refuse
loopback and the test CA. Eval suite `m5c-net-http` (gated); required hosted
job `net-http`; coverage-guided fuzz targets for the URL parser and the
`Location` resolver (`fuzz/`, nightly, scheduled), the same targets in every
`cargo test` as a stable mutation loop, and two stable mutation campaigns over
the response path — 20 000 mutated responses through the head parser, the
framing judgement and the body decoder without a socket, and 120 through a
real TLS origin. M5a's and M5b's jobs and evals stay required and green.

| Area | Cases (each: refused or contained, with its disposition, and audited) |
|---|---|
| SSRF by address | every guarded range of ADR-0048 §6, IPv4-mapped, IPv4-compatible, NAT64, 6to4, Teredo, a mixed answer, an all-blocked answer |
| SSRF by name | metadata names; a granted name resolving to loopback; DNS rebinding (1 s TTL) across two requests and across hops of one; resolution failure and timeout |
| Origin confusion | userinfo (`a@b`), Unicode host, uppercase, trailing dot, IP literal (dotted, decimal, hex, octal), encoded host, backslash, `..` and `%2e` segments, a fragment, port confusion, a suffix (`api.example.com.evil.test`) |
| Redirect laundering | to a blocked address, to an ungranted host, to a metadata name, a protocol downgrade, a loop, the sixth hop, `307` with a body, a relative `Location`, a malformed one, a rebinding redirect target |
| Credential | attached at the bound origin only; never on a cross-origin hop; re-attached on a same-origin hop with its own use; a runtime `Authorization`/`Cookie`/secret-header refused; a secret value in URL, header or body refused; an echo — in the body, split across chunks, straddling the bound, past it, in a kept or dropped header, in a `Location`, in a malformed or cut response — never reaching the answer, the audit or the authority, and never encoded by the broker; `Set-Cookie` dropped; residue: none after a send, the library's after an echo measured (§20) |
| TLS | wrong name, expired, self-signed, untrusted root, the test CA under a production broker, a server offering only HTTP/2 |
| Response and resources | malformed status line, header bombs, `Content-Length` and `chunked` together, bad chunk sizes, a non-identity encoding, a body past the cap, slowloris headers and body, a connection that never answers |
| State | crash at every point (intent, after resolve, after exchange, before outcome) → `UNKNOWN`, never repeated; idempotency replay answers the record |
| Policy | each shipped pack's verdict; novelty and taint (`balanced` denies a tainted run's novel destination); `max_requests` and byte budgets spent stay spent |
| Isolation | the `PROXY_ONLY` evidence unchanged; the runtime has no route (M9's job, not claimed here) |

**As built.** `make net-http-evidence` runs four suites and requires all 174
of their cases (`scripts/dw.py`, `NET_HTTP_CASES`): `broker-http` (the
broker's client against real `rustls` origins in its own process, and its
response path under mutation; and the exchange worker — a hop answered,
redacted and reaped, a worker that cannot start sending nothing, a stranger
refused, a worker killed after it began sending leaving the hop
`EXCHANGE_UNCONFIRMED`, concurrent hops each in a worker of its own; 40),
`authority-net-pipeline` (the authority's per-hop state machine against a fake
broker, crash windows N1–N4, a worker that failed before sending and one
unconfirmed after; 47), `authority-net-credential` (mode A's consumer, real
keyring values, 7) and `net-http` (the released broker, local HTTPS origins
from `tests/net_http/origin.py` under a PKI made per run, the fixture resolver
and the authority's library — a broker killed mid-exchange takes its worker
with it and the request is `UNKNOWN`; 80). The authority half runs the
library, not `serve`: the authority's guard lets loopback through only on
`Authority::attach_net_evidence`, which no DWKP operation and no `serve`
option reaches (TX035); a `serve` flag would be a production loopback bypass.
`DW_CPU_CONTENTION=n` runs it all beside n spinning processes; CI runs it twice,
the second time with one per CPU. `make net-http-mutations` weakens eight
safeguards in turn — the IP guard, the pin, per-hop authorisation, the
credential's origin binding, the response bound, the budget debit, and the
worker's echo redaction twice (a header holding the credential kept; the body
no longer read past the bound by the value's length) — and each mutant must
compile and fail the evidence; each file is restored and its SHA-256
checked. M4e's secret evidence is moved, not weakened: every case of
`authority-secret-pipeline`, `broker-secret-primitives` and
`authority-secret` still reports, through `net.http` (§8), and
`make secret-broker-evidence` now requires 178 cases: mode A's echo, by each
of the nine ways it can come back, with fresh daemons and the authority in its
own process — what the runtime would receive holds no 16-byte window of the
value, the authority's memory holds neither the value nor its hex, the
broker's memory holds no hex form (its own encoding never saw it), the audit
counts the handle's echoes and holds no byte of it — and, per way, the
long-lived broker's memory holds neither the value nor its hex once the hop is
answered: its exchange worker is gone (§§9, 20; asserted, where the first
build could only measure library residue and report it). The gated eval is `m5c-net-http`; the
required hosted job is `net-http`.

**The exchange worker's cost**, measured on the working tree (debug build, a
loopback TLS origin, 24 CPUs, two rounds of 40 hops each way): a hop in a
worker takes 3.1 ms at the median against 1.9 ms in process — about 1.15 ms
more, p90 3.4 ms against 2.5–2.8 ms; eight concurrent hops take 5.8 ms of wall
time against 6.4 ms, so concurrency loses nothing; the release binary starts,
checks its peer and exits in 0.5 ms at the median (p90 0.9 ms). A hop's
deadlines dwarf this: its connect alone may take 10 s.

### 17. Architecture rules

TX037 amended deliberately: the broker dials from `egress/tunnel.rs` and from
`http/connect.rs`, each only to guarded, pinned addresses. TX013, TX009,
TX015, TX021 and TX022 exempt the `http` module's files that must name network
types, each by file and with its reason. **TX038 is unchanged** — `egress/`
stays TLS-free. New: TX044 (a TLS crate is named only in the broker's `http`
module; never in the authority, `egress/`, the relay or the probe), TX045 (a
credential header is composed only in the broker's render — and, with
`broker.secret_egress` retired, `secret.rs` loses its exemption), TX046 (no
ambient network or trust configuration on the `http` path: no environment
read, no proxy or `SSL_CERT_*` or `SSLKEYLOGFILE` name, no native-certs crate,
no `dangerous()` verifier, no second resolver, no store), TX047 (the
authority opens no outbound socket and resolves no name — `std::net`,
`TcpStream`, `UdpSocket`, `ToSocketAddrs`, `lookup_host`, `getaddrinfo` and
`rustix::net` are refused across `crates/dwkd-authority/src`), TX048 (one
address guard: range tables and address classification only in the shared
`wire/guard.rs` and the broker's adapter); TX036 extended to version 7;
TX035 extended to the evidence's exception list. The exchange worker (§9,
D11): TX021 exempts `http/worker.rs`, its one spawn site (the broker starts a
process in two reviewed places: the launch helper and the exchange worker);
new TX049 lets no other broker file name the `http-worker` mode, so nothing
else can start one; TX016 bars the cognition side from naming it; the
worker's self-hardening lives in `hardening.rs`, already TX023's one
exemption for the broker hardening itself; TX015 exempts the client's unit
tests, which read `/proc` to count the workers they started. Each with a
violation fixture, and each fixture's exact findings pinned by
`tests/architecture/test_boundaries.py`.

### 18. Dependencies and the TCB

The authority's measured closure does not change: the URL parser and the guard
are std-only code in `dwk-proto`, and `cargo tree -p dwkd-authority` names no
TLS, HTTP or async crate (TX044, TX047; `dwcheck closure`). The broker gains,
measured on the implemented tree:

| Crate | Version | Role | Licence |
|---|---|---|---|
| `rustls` | 0.23.45 | TLS 1.2/1.3 client; features `ring`, `std`, `tls12` only — no `aws-lc-rs`, no logging | Apache-2.0 OR ISC OR MIT |
| `ring` | 0.17.14 | the crypto provider (C and assembly, built with `cc`, already a build-only crate) | Apache-2.0 AND ISC |
| `rustls-webpki` | 0.103.15 | certificate verification | ISC |
| `rustls-pki-types` | 1.15.1 | certificate and key types | MIT OR Apache-2.0 |
| `webpki-roots` | 1.0.9 | Mozilla's roots, compiled in | CDLA-Permissive-2.0 (one `deny.toml` exception, by crate) |
| `untrusted` | 0.9.0 | `ring`'s and `webpki`'s input reader | ISC |
| `ureq-proto` | 0.6.4 | the sans-I/O HTTP/1.1 engine, `client` only (D2) | MIT OR Apache-2.0 |
| `http` | 1.5.0 | request and header types | MIT OR Apache-2.0 |
| `httparse` | 1.10.1 | the response head parser under `ureq-proto` | MIT OR Apache-2.0 |
| `bytes` | 1.12.1 | the credential header's buffer, owned by a scrubbing owner | MIT |
| `base64` | 0.23.1 | `ureq-proto`'s Basic userinfo, never used (userinfo is refused) | MIT OR Apache-2.0 |

and small shared crates (`subtle`, `zeroize`, `getrandom` 0.2, `once_cell`,
`log`, `cfg-if`, `libc`). Duplicates, each a version-exact `skip` with its
reason: `base64` 0.21 (age, the authority) and 0.23 (the broker), one per
daemon; `windows-sys` 0.52 and its target crates (`ring`, Windows only; the
broker serves only on Linux). `cargo deny` is clean: no advisory, no banned
crate (`reqwest`, `hickory-resolver`, `trust-dns-resolver`,
`rustls-native-certs` and `rustls-platform-verifier` are banned by name). No
`unsafe` in DireWolf code. The exchange worker (§9) adds no crate: it is the
broker's own binary, its hand-over uses `rustix::net`'s `SCM_RIGHTS` and its
hardening `rustix::process`, both already linked.

**Trust roots.** Mozilla's, compiled in; never the host's store, never an
environment variable. `--allow-evidence-trust <pem>` *replaces* them with a
test authority for the evidence, announced loudly, and only beside
`--allow-evidence-egress`'s fixture resolver (the broker refuses to start
otherwise); no production configuration names it, and the evidence shows a
broker without it refusing the test authority.

**Memory and the credential's lifetime.** The request is rendered into
`Zeroizing` buffers sized once; the credential's header value is a `Bytes`
over a scrubbing owner, so the composed header lives in one place, zeroed when
the request is dropped, and is marked sensitive; the raw value lives in the
hop's `Needle` until the exchange ends, then is zeroed; `rustls` encrypts each
record in place after the handshake (its sealing buffer holds ciphertext, not
plaintext, once sealed). Measured: after a credential exchange the broker's
memory does not hold the value (`credential-broker-residue-after-send`,
`mode-a-broker-residue`). **Response** plaintext is DireWolf's only in
DireWolf's buffers — the head, the raw body and the redacted body, each
`Zeroizing` and sized once — and an echo of the credential is redacted before
any of it is encoded (§8). Two libraries also hold response plaintext, in
allocations freed without being zeroed: `rustls` 0.23.45 copies every
decrypted application-data record into its own `Vec` (`received_plaintext`;
its unbuffered API too — `ReadTraffic::next_record` lends a borrow of that
copy, and in-place decryption is unreleased), and `ureq-proto` builds the
`http` crate's header map from the response head, copying every header value.
As first built, those copies stayed in the long-lived broker's freed heap
until reused. **As built now** they are made in the hop's exchange worker
(§9), whose whole address space ends before the broker answers: measured
after every way an echo can come back, the broker's memory holds neither the
value nor its hex (`mode-a-echo-broker-library-residue-*`,
`credential-echo-broker-residue`, asserted). What remains is §20's.

### 19. Platform contract

Linux, where the broker serves. The host's resolver and the broker's trust
roots are trusted for what they return; the guard and the verifier judge it.

### 20. Residual risks

- **A granted host is trusted with what is sent to it**, and with what it
  redirects to among the run's other grants: laundering *between granted
  origins* is possible and bounded by the grants, the hop limit and policy.
- **Wildcard grants** let a DNS name carry data to the granted zone's servers.
- **Response content is untrusted**: it taints the run; redaction is hygiene.
- **The trust roots** decide which certificates are believed (D1).
- **No certificate pinning** per origin in M5c.
- **Corporate HTTP proxies are not used**: a host that can reach the internet
  only through one cannot use `net.http` until a reviewed configuration exists.
- The host's resolver is trusted for what it returns; the guard judges it.
- **An echoed credential lives, for one exchange, in that hop's exchange
  worker (D11).** An origin that sends the credential back hands the worker
  response bytes holding it. Everything DireWolf does with them is closed
  and measured: the worker redacts the echo before anything of the response
  is copied into a message (§8); its own buffers are `Zeroizing`; no message,
  log, audit row, durable file, authority memory or runtime-visible answer
  holds the value — or, where DireWolf could create one, its hex form
  (`mode-a-echo-*`, nine ways, asserted). The libraries' copies — `rustls`'s
  per-record plaintext (`received_plaintext`, the whole response) and the
  `http` header map `ureq-proto` builds — are made in the worker, freed
  without being zeroed **inside the worker**, and gone with its address space
  when it exits, before the broker answers. **Eliminated:** the residue the
  first build left in the long-lived broker (present after every header echo
  and some body echoes); the broker's memory after every echo path now holds
  neither the value nor its hex — asserted, nine ways and in the end-to-end
  suite. **What remains:** (a) *during the exchange*, the worker's memory
  holds the credential and any echo of it, exactly as the broker's did — the
  worker is never dumpable, has `RLIMIT_CORE` 0, its broker's uid and no
  route from the runtime, so only root or `CAP_SYS_PTRACE` reads it, a reader
  who could read the credential during any exchange anyway; (b) *after the
  worker exits*, the physical pages it freed are not cleared by Linux until
  they are reused (every page is zeroed before another process receives it,
  but not on free unless the kernel runs with `init_on_free=1`): readable
  only from the kernel — a crash dump, a hibernation image, `/dev/mem` where
  allowed — the same exposure every process's freed memory has, the
  authority's and the broker's own included; (c) *swap*: a worker page swapped
  out during the exchange can stay on the swap device (no `mlock`, as
  ADR-0046 §27). **Invariant I3 holds**: nothing the Cognition Plane receives
  holds the value. Relative to ADR-0046 §22 this is no longer a new class of
  residual: the window is the exchange itself, as for every value a broker
  holds for one invocation. The kernel exposures (b) and (c) are the owner's
  to accept with D11, not an exception assumed.
- **The broker redacts only the hop's own credential.** Any other configured
  value appearing in a response is the authority's to redact (index and
  shapes) within the bound it is given; such a value straddling the bound is
  ADR-0046 §21's exact-matching limitation, unchanged.
- **`max_requests` is counted over the run's hops**, not per grant (§10):
  conservative, never generous.
- **A grant with no port covers every port** (the capability grammar's
  `PortSpec::Any`); a grant that names one covers only it.
- **The caller's headers stop at its origin**: a cross-origin hop carries none
  of them, which may break a server that expected them on a redirect.
- **An unfollowed redirect's `Location` is returned only in its one canonical
  spelling**; one with a dot segment, userinfo or any other second reading is
  omitted.

### 21. Owner decisions

| # | Decision | Recommendation |
|---|---|---|
| D1 | TLS stack and trust roots | **as built: `rustls` 0.23.45** with the `ring` provider and bundled `webpki-roots` (Mozilla's set, reproducible, no OS store), TLS 1.2 and 1.3, `http/1.1` the only ALPN, no resumption, no early data, no key log; the evidence anchor replaces the roots and only beside the fixture resolver (§9). Alternatives: `aws-lc-rs` (a larger C build), the OS store (honours locally added CAs, which is exactly what a CA-planting attacker uses), OpenSSL or `native-tls` (a second TLS implementation, C, ambient configuration) |
| D2 | HTTP/1.1 implementation | **as built: `ureq-proto` 0.6.4**, a sans-I/O HTTP/1.1 engine — it owns no socket, no resolver, no pool, no proxy, no redirect follower, no decoder — driven by the broker's own strict loop (every bound, every deadline, every framing refusal is the broker's), with `hyper`/`tokio` and `reqwest` not used (`reqwest` banned). It renders the request into DireWolf's `Zeroizing` buffer from a header map whose credential value is the scrubbed buffer itself (no copy); it reads the response head into the `http` crate's header map, which copies each header value — in the hop's exchange worker, whose memory ends with the hop (D11). The alternative stays a hand-written parser over `httparse`, fuzzed like the CONNECT parser — which would remove the header-map copy but not `rustls`'s record copy |
| D3 | Public exposure in M5c | ToolInvoke version 4 now (one tool, typed), so the hostile client and the evals exercise the real path |
| D4 | Credential on a same-origin redirect | allowed, each time a fresh decided and recorded use; never cross-origin. Stricter alternative: never on any redirect |
| D5 | Redirects for methods with a body | `303` only (to `GET`); `301`/`302`/`307`/`308` returned unfollowed |
| D6 | Plain HTTP, WebSocket, HTTP/2 | out of M5c (`PLAINTEXT_UNSUPPORTED`); a credential never travels in cleartext in any later design |
| D7 | Compressed responses | refused (`ENCODING_UNSUPPORTED`): no decompression bomb, nothing hidden from redaction |
| D8 | What the audit keeps of a URL | origin and the SHA-256 of the canonical URL; not the path or query, which may carry personal data |
| D9 | Request bodies | inline only (≤ 256 KiB, D12); no workspace-file upload in M5c |
| D10 | Default per-run budgets | requests 100, bytes out 8 MiB, bytes in 64 MiB, origins 16 — never refilled; configurable in `StartupConfig`, not yet in `serve`'s file |
| D11 | An echoed credential's residue (§§8, 9, 20) | **as built: one exchange worker per hop** (§9) — the broker judges, reads the credential once and dials; `dwkd-broker http-worker`, hardened before it receives anything and handed only that connection, that credential and that hop, performs TLS and HTTP/1.1, redacts the echo, answers and exits before the broker answers. The long-lived broker's residue is **eliminated** (asserted, nine ways). **Owner decision required** on the design — a second spawn site in the broker (ADR-0045 amended; TX021, TX049), about 1 ms more per hop (§16) — and on the narrowed residual of §20: the worker's memory during the exchange, freed physical pages until the kernel reuses them, and swap. Alternatives weighed: A, owning every buffer (impossible with `rustls` 0.23.45, whose record copy is internal, and the `http` map); C, another API (`rustls`'s unbuffered API lends the same copy; a hand-written head parser removes only the header map's); D, OS isolation of the worker by seccomp or Landlock (no safe API in the TCB without a new dependency — a later hardening, not a substitute); a zeroizing global allocator (needs `unsafe` or an allocator crate in the TCB, covers only frees) |
| D12 | The response and request bounds | 256 KiB each way, derived from the 1 MiB frame, instead of 1 MiB and 8 MiB: larger needs streaming results (M12's spill), not a larger frame |

**Closeout review (2026-10-08; revised 2026-10-09 for the exchange worker), against the code and the evidence.**

| # | Recommendation | On what |
|---|---|---|
| D1 | **ACCEPT** | chain and name verification by `rustls`' WebPKI verifier with no override (TX046); the canonical host as SNI and certificate name; dials only to pinned `SocketAddr`s (`http/connect.rs`); compiled-in roots, no OS store, no environment, no proxy; failures before a byte is sent are refusals; `cargo deny` clean; the authority's closure free of it; the TLS negatives (`expired`, `self-signed`, `untrusted-authority`, `wrong-name`, `http2-only-server`, the test CA under production trust, handshake timeout) |
| D2 | **ACCEPT** | strict framing on top of `httparse` (one length or `chunked`, never both or neither, no other coding, no `101`, no encoding, 100 headers in 64 KiB, body to the bound with a wire cap, three deadlines); request and credential buffers owned and scrubbed by DireWolf; no panic under 20 000 sans-I/O and 120 TLS mutants; the header-map copy, its one ownership flaw, now lives and dies in the exchange worker (D11) |
| D3–D10, D12 | **ACCEPT** | each matches the code and is shown by the evidence of §16 |
| D11 | **OWNER DECISION REQUIRED — recommended: ACCEPT** the exchange worker and its narrowed residual; not blocking | the broker's residue after an echo eliminated and asserted (nine ways, raw and hex; end to end); the worker's lifecycle shown — reaped before the answer, refusing a stranger, `HTTP_WORKER_FAILED` with nothing sent, `EXCHANGE_UNCONFIRMED` after a kill, concurrent hops in workers of their own, killed with its broker; two mutants on the worker's redaction caught; about 1 ms more per hop and no loss in concurrent throughput (§16); the residual as worded in §20 |

### 22. Implementation sequence

Each step is a reviewable change with its own green local gates; M5c is
complete when step 5's hosted job passes on the committed tree.

| Step | Delivers | Accepted when |
|---|---|---|
| **M5c.1** Shared primitives | `wire::url` (canonical URL, origin, `Location` resolution); the guard moved to `dwk-proto` and called by the proxy; ToolInvoke v4 and private v7 **types** (no handler) | URL and guard unit/property tests and fuzz targets; `make sandbox-egress-evidence` unchanged and green (the shared guard); schemas regenerated; TX036 extended; TX047 added (the authority has no outbound socket today, so it lands green) |
| **M5c.2** Broker HTTPS client | D1/D2; `http/connect.rs`, render, parse; `broker.http_resolve`/`http_exchange` without credential; the evidence trust anchor | broker tests against local TLS origins: pinned dials only, caps, deadlines, TLS failures, malformed responses, never follows; production broker refuses loopback and the test CA; TX037/TX044/TX046; closure measured and recorded |
| **M5c.3** Authority orchestration | ToolInvoke v4 handler and preview; §5 pipeline; schema v8; budgets, novelty, taint, redaction; redirects (§7) | end-to-end with real daemons: the SSRF, origin-confusion, redirect-laundering, state and policy rows of §16; crash points |
| **M5c.4** Mode A consumer | §8: credential on `http_exchange`, per-injection use, same-origin rule, `SECRET_IN_REQUEST`, `HEADER_FORBIDDEN`; `secret_egress` retired | the credential rows of §16: the header observed at the bound origin only, never at a redirect target; residue checks; TX045 |
| **M5c.5** Gate and closeout | `make net-http-evidence`, the `m5c-net-http` gated eval, the required `net-http` CI job; NETWORK_SECURITY.md "as built"; ROADMAP | every case of §16 locally and in hosted CI; M5a/M5b green; this ADR accepted |

**Status of the steps.** M5c.1–M5c.5 are implemented and their local gates
pass, the mutation review included; the closeout review (§21) remediated D11
where DireWolf can reach it and tied the evidence trust anchor to the fixture
resolver. Hosted run 37855884386 on the committed tree failed before it
measured anything: its tool probe asked OpenSSL 3.0 for `openssl --version`,
which 3.0 refuses, so every real-daemon case reported NOT EXERCISED and the
strict gates rightly refused the run. The probe now asks each tool by its own
spelling (`openssl version`) and names the command that failed. The recovery
also moved each hop's TLS and HTTP into an exchange worker (§9, D11). Neither
change has run in hosted CI and this ADR is not accepted, so M5c is not
complete: acceptance needs the owner's decisions — D11's worker and residual
above all — and the hosted `net-http` job and every multi-identity half green
on a new commit.

### 23. Security invariants

Each is a row of §16 that must be shown, not argued:

1. **No unauthorised byte leaves.** Nothing is sent to an origin before that
   hop's capability, guard, policy and budget passed and its intent is durable.
2. **No resolution without a grant.** A name is resolved only after a grant
   covers its host and port.
3. **Only pinned, twice-guarded addresses are dialled**, by the broker, from
   one of two reviewed dial sites, never re-resolved within a request.
4. **A redirect is a new request.** The broker never follows one; the
   authority re-runs every gate for every hop.
5. **A credential reaches only its bound origin**: the request's first origin,
   covered by the metadata, each attachment its own decided and recorded use;
   never a cross-origin hop, never cleartext, never chosen by the runtime.
6. **No secret value enters a message, a log or the runtime**: one-shot pipe,
   redacted responses — the hop's own credential by the broker before
   anything of the response is encoded, every indexed value by the authority
   — no `Set-Cookie`, a secret in an outgoing request refused. (What the
   exchange worker's TLS and HTTP libraries free unzeroed ends with the
   worker: §20's residual, not a message.)
7. **The runtime chooses no network fact**: no address, resolver, proxy, TLS
   option, credential header, origin or mode is on the public wire.
8. **Everything is bounded and fails closed**: sizes, hops, deadlines and
   budgets refuse with a typed reason; there is no fallback path.
9. **An uncertain outcome is never repeated**: a crash after intent is
   `UNKNOWN`, recorded, and not performed again.
10. **The `PROXY_ONLY` tunnel is unchanged**: still opaque, TLS-free and
    credential-free, its evidence still green.
11. **Network content taints**: any delivered response raises the run to
    `EXTERNAL_UNTRUSTED`.

### 24. Prior art considered

No competitor's code was read, copied, translated or imported for M5c, and no
safeguard below is assumed sufficient because someone else ships it. Public
advisories and specifications were weighed, and DireWolf's answer is its own:

| Public source | Lesson | DireWolf's answer |
|---|---|---|
| curl CVE-2018-1000007 (credentials sent to a redirect's host) | a client that follows redirects carries the caller's credential to wherever the server says | the broker never follows; a credential is attached only to a hop at the request's first origin, each time decided anew (§8) |
| curl CVE-2022-27776 (credentials kept across a port or scheme change on the same host) | "the same host" is not "the same origin" | the origin is (`https`, host, port) compared by bytes; a different port is a different origin (§4) |
| Python `requests` CVE-2018-18074 (`Authorization` kept on an `https` → `http` redirect) | a downgrade must not keep anything | no plaintext scheme exists; a downgrade ends the chain (`REDIRECT_TARGET_INVALID`) |
| Go `net/http` and the WHATWG Fetch standard (credential headers removed on a cross-origin redirect) | stripping is the floor | DireWolf strips nothing because it never attaches across an origin, and drops all of the caller's headers there too |
| OWASP SSRF Prevention Cheat Sheet | resolve-then-check races; blocklists miss encodings; redirects launder | the whole answer judged, mixed refused, the answer pinned for the request and judged again by the broker; literals and encodings refused by the canonicaliser; every redirect re-decided (§§4–7) |

## Consequences

**Positive.** The agent gains its one sanctioned network tool, with the kernel
as the client: every hop is decided, pinned, guarded twice, budgeted and
recorded before a byte leaves, and a credential reaches only the origin its
metadata names. M4e's secret side gets its consumer without any value entering
a message, and M5b's tunnel stays exactly as opaque as it was accepted.

**Negative.** The broker gains a TLS stack and a second dial site — its
largest new code since M4. Each redirect hop costs a full authorisation and,
for a new host, a resolution. Strictness refuses some real servers (non-
identity encodings, HTTP/2-only origins, hosts that need a corporate proxy,
redirect chains that resend bodies). Each hop starts a process — about
1 ms more per hop, measured, and no loss in concurrent throughput — and the
broker starts processes in two places instead of one (D11). An origin that
echoes the credential has it in that hop's worker until the worker exits; a
redirect whose `Location` holds it is answered as a plain 3xx with no
`Location`.

## Alternatives considered

- **The authority performs the request.** Puts a TLS stack and sockets into
  the authority's TCB and breaks the split ADR-0018 draws (and TX047, §17).
- **Let `net.http` ride the CONNECT proxy, terminating TLS to inject.** The
  DireWolf CA design NETWORK_SECURITY.md §1 rejected; TX038 exists to stop it.
- **The broker follows redirects.** The broker would decide where requests go;
  per-hop reauthorisation would be a promise rather than a structure.
- **`reqwest`/`hyper`.** An async runtime and connection pool in the broker;
  redirect and proxy behaviour that must be switched off rather than absent.
- **Re-resolve each hop, or cache across requests.** Re-resolution is what
  rebinding exploits; caching across requests outlives the decision it served.
- **Filtering a mixed answer.** Accepts the attack's shape (ADR-0048 §6).
- **Carry the credential across redirects when the other origin is also in the
  metadata.** The request asked for it at one origin; a server's redirect must
  not choose where else it goes.
- **Leave an echo to the authority's redaction alone** (as first built). The
  raw value then crossed the private channel in kept headers and the hex body,
  stayed in the authority's decoded buffers, and — cut by the response bound —
  reached the runtime in part (30 of 40 characters in the evidence before the
  fix). The broker is the only place the echo can be stopped before it is
  copied.
- **For D11's library residue: a zeroizing global allocator in the broker**
  (needs `unsafe` in DireWolf or an allocator crate in the TCB, and still
  covers only frees, not live or swapped memory); **`rustls`'s unbuffered API
  now** (0.23.45 still copies each record — no gain); **a hand-written
  response parser now** (removes the header-map copy, not the record copy);
  **accepting the long-lived broker's residue** (the first closeout's
  recommendation — superseded once a worker proved small, safe Rust and
  measurably sufficient); **a pool of long-lived workers** (would carry one
  hop's freed memory into the next; one worker per hop is the point);
  **seccomp or Landlock in the worker now** (no safe API in the TCB without a
  new dependency; the worker already holds no descriptor but its one
  connection and its credential pipe, and dials nothing).

## Revisit if

- M7's model egress wants the same HTTPS client (share it, by its own ADR).
- An operator needs a corporate proxy or an extra trust anchor (a reviewed,
  audited configuration — never an ambient variable).
- A supported origin requires HTTP/2 or a compressed response.
- Approvals (M6) arrive: `REQUIRE_APPROVAL` stops being a denial.
- A released `rustls` decrypts unbuffered records in place (D11): move the
  worker's client to the unbuffered API over DireWolf's `Zeroizing` buffers
  and parse the head with `httparse` over the same buffer, so that even the
  worker's freed memory holds no copy.
- A reviewed, safe seccomp or Landlock API is in the TCB: confine the
  exchange worker to the descriptors it was handed (no `socket`, `connect` or
  `open`).
- The per-hop process cost matters to a workload (§16 measures it).
