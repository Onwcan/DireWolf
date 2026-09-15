# ADR-0024: Sandbox networking is `PROXY_ONLY`, not `none`

**Status:** Accepted · **Date:** 2026-09-12 · **Supersedes:** the network portion of [ADR-0008](0008-sandbox-default.md)

## Context

ADR-0008 and the original `oci-strict` profile specified `network: none` — "no interface at all; egress only via the kernel proxy socket," with the proxy reachable over a Unix domain socket speaking HTTP CONNECT / SOCKS5.

Review finding C13: **no mainstream HTTP client can address a proxy over a Unix socket.** `http_proxy`/`https_proxy` take `host:port`; curl, git, pip, npm, cargo, `requests` and Go's `net/http` all require a TCP endpoint. As specified, `network.http` from a sandboxed tool could not work at all.

Stacked on top: the proxy was to "terminate TLS when credential injection or response inspection is required," which needs a DireWolf CA in the sandbox trust store — absent from the profile — and breaks every client carrying its own bundle (pip/certifi, Node, Go, cargo).

A third consequence was a product blocker: the `allow-known-tools` rule attached `network_deny` to allowlisted executables including `npm` and `cargo`, so `npm install` and `cargo fetch` would fail rather than prompt.

## Decision

Introduce **`PROXY_ONLY`** as the sandbox network mode, and separate the two egress paths that were conflated.

**`PROXY_ONLY` topology:** the sandbox gets an isolated private network namespace containing a veth pair, **no default route**, **no DNS resolver**, and exactly one reachable peer — the broker's CONNECT proxy at a fixed link-local endpoint (`169.254.7.1:8080`), injected as `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` plus per-tool equivalents. Everything else is unroutable. A process that ignores the proxy variables has no connectivity, which remains the correct failure mode.

**Two paths, different guarantees:**

| Path | Initiator | Mechanism | Credential injection | Content inspection |
|---|---|---|---|---|
| `net.http` tool | the agent, explicitly | **broker performs the request directly**; no proxy | **Yes** (egress injection) | Yes — size cap, MIME, redaction, artifact spill |
| Sandbox process egress | a process the agent exec'd | CONNECT proxy, **opaque tunnel** | **No** | No — byte-capped only |

For proxied traffic the broker enforces the CONNECT target host, requires the TLS SNI to match it, applies the IP guard to the resolved address, pins DNS, and enforces byte and connection budgets at the socket. **It does not terminate TLS. There is no DireWolf CA and nothing is installed into any trust store.**

## Consequences

**Positive.** The design is buildable. Package managers work against allowlisted registries, which removes a V1 usability blocker. No CA distribution problem. No TLS-interception breakage.

**Negative, and stated plainly:** proxied traffic gives **less visibility than the original design claimed**. The broker sees hosts, ports, IPs and byte counts — not paths, headers, bodies or responses. That is a real reduction, and it is the price of the original design being impossible. Credential-bearing and inspectable requests go through `net.http`, where the broker is the client and sees everything.

`AssuranceLevel` is unchanged; `PROXY_ONLY` is a network mode, not an isolation level. A future `NO_NETWORK` mode (genuinely no interface) remains available for environments that need it and can accept that package managers will not run.

## Alternatives considered

- **Keep `network: none` + Unix socket proxy.** Unbuildable.
- **Keep TLS termination with a distributed CA.** Breaks pinned and bundled clients; adds a CA to the TCB; a persistent support burden.
- **Give the sandbox a real route with iptables filtering.** Filtering by IP cannot enforce SNI/host, and a compromised process can attempt direct connections that must then be dropped rather than never being possible.

