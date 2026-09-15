# ADR-0018: The authority plane is two processes — `dwkd-authority` and `dwkd-broker`

**Status:** Accepted · **Date:** 2026-09-12 · **Amends:** [ADR-0000](0000-authority-plane-separation.md)

> ADR-0000 established *that* authority lives behind an OS boundary. It described one privileged process. This ADR splits that process. ADR-0000 remains correct in its thesis and is not superseded.

## Context

Phase 0 adversarial review found the single `dwkd` to be "a monolith with a security label." It held twelve subsystems, and two of them do not belong with the other ten:

- **Artifact capture** performs MIME sniffing and structure-aware excerpting — HTML text extraction, CSV column stats, source symbol outlines — over **attacker-chosen content**. `THREAT_MODEL.md` ranks fetched content as the joint-highest-risk entry point.
- **Network and model egress** run an HTTPS/HTTP2 streaming client, SSE framing, and JSON parsing of provider responses. `THREAT_MODEL.md` T6 puts a malicious provider in scope, so that is hostile input too.

Both ran in the same address space as the plaintext credentials, the capability MAC key and `audit.log`. That directly contradicts architectural principle 7 ("smallest privileged surface: small, statically linked, few dependencies, heavily fuzzed"). A parser for hostile HTML is not that.

The review also noted the dependency consequence: `bollard` + `hyper` + `rustls` + `tokio` alone exceed 150 crates, against a stated ambition of 15–40 for the whole TCB. The claim was not false so much as applied to the wrong boundary.

## Decision

Split along the line between **deciding** and **doing**.

| `dwkd-authority` — decides | `dwkd-broker` — does |
|---|---|
| Request Canonicaliser | Filesystem Broker |
| Policy Engine | Exec Broker |
| Capability Broker | Sandbox Supervisor (container API client) |
| Approval Registry | Network Egress (CONNECT proxy + `net.http`) |
| Budget Ledger | Model Egress (streaming, provider response parsing) |
| Secret Broker (resolution) | Artifact capture (MIME, excerpt, redact) |
| Audit Log | |
| **Holds:** `kernel.db`, `audit.log`, the token MAC key, secret material | **Holds:** fds, PIDs, sockets, containers |
| **Contains:** no hostile-content parser, no network stack, no container client | Contains all of those |
| **Holds no** long-lived key | |

Rules, in the order they matter:

1. **The runtime speaks only to `dwkd-authority`.** There is no DWKP endpoint on the broker. The broker is not addressable from the Cognition Plane at all.
2. **Authority decides; broker executes.** The broker receives a **per-invocation authorisation**: a canonical action, an obligation set, and — where one was granted — a one-shot secret injection. It performs exactly that.
3. **The broker cannot mint a capability, create or match an approval, widen authority, evaluate policy, or read a long-lived credential.** It has no code for any of these and no access to `kernel.db` or the keychain.
4. **The broker cannot write `audit.log`.** It returns outcomes to authority, which writes them.
5. **Authority avoids hostile-content parsers.** Canonicalisation parses paths, hosts and argv — structured, bounded, fuzzed. It does not parse HTML, provider JSON, or tool output.
6. A memory-safety or logic bug in the excerpter reaches an address space containing no credentials and no key.

## Consequences

**Positive.** Principle 7 becomes a fact rather than an aspiration: `dwkd-authority` is plausibly 8–10 k lines with a genuinely small dependency set, and is the right unit to fuzz and to `cargo-vet`. It also makes [ADR-0019](0019-language-rationale-v2.md)'s Rust argument proportionate — the defended component is now small enough for "minimal, auditable dependency set" to be true.

**Negative.** A third process and a second internal IPC hop. Per-invocation authorisations must be unforgeable to the broker's own peers (they are MACed by authority and single-use). Debugging spans one more boundary. A broker compromise still yields the authority of whatever invocation it was handed — bounded, but not nothing.

**The boundary is asymmetric on purpose.** Compromising the broker gives an attacker the current invocation. Compromising authority gives them everything. That is why the small side is the one holding the keys.

## Alternatives considered

- **Keep one process, move excerpting to the runtime.** Would put artifact creation in the plane that must not be able to forge provenance. Rejected.
- **Keep one process, accept the parsers.** The honest version of the original design, and it makes principle 7 false. Rejected.
- **Three or more processes (separate net, separate exec).** More boundaries than the threat model justifies; the broker's components share a privilege profile.

## Revisit if

Broker compromise proves to have a wider blast radius than "the current invocation" in practice, or the IPC hop shows up as a material share of tool-call latency at M3.5.

