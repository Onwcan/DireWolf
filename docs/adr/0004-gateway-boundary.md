# ADR-0004: The gateway is optional, holds no authority, and is four components

**Status:** Accepted · amended by [ADR-0022](0022-approval-response-authentication.md) · **Date:** 2026-09-11

> **AMENDED by [ADR-0022](0022-approval-response-authentication.md).** Point 4 below ("the client verifies the approval nonce round-trips") is insufficient: the nonce travels outbound *through* the relay, so a compromised gateway could forge a response. Approval responses are now authenticated by an out-of-band device key. Everything else in this ADR stands.

## Context

Gateways in agent runtimes tend to become god objects: transport, auth, session routing, channel adapters, run coordination, scheduling, worker registry and health, all in one long-lived daemon. That concentrates risk in a network-exposed component and makes the daemon mandatory even for local use.

## Decision

1. **The gateway is optional.** `direwolf chat` and `direwolf run` work as a local process tree with no daemon. The gateway appears at M19 with channels.
2. **It holds no authority.** Its power is "can address a session" — exactly what an ordinary user has. Compromising it lets an attacker talk to an agent, and nothing more.
3. **It is four separable components**: transport, client authn, idempotent ingress, session routing. Channel adapters plug into ingress.
4. **Approval requests are relayed, not generated.** The kernel produces them; the gateway forwards them unaltered; the client verifies the approval nonce round-trips. A compromised gateway can drop an approval request (denial of service) but cannot forge or rewrite one.
5. **Loopback by default.** Binding to a routable interface requires explicit configuration and emits a startup warning.

## Consequences

Local-first works with no daemon at all, which is a genuine simplification for the primary use case. The blast radius of a gateway compromise is bounded and statable. Run coordination stays in the runtime where session leases live, rather than being split across a network boundary.

Cost: channels are deferred to V1.1, so V1 ships one interface. Mitigated by implementing the CLI *as a channel adapter* so the abstraction is exercised by its own reference implementation.

## Alternatives considered

- **Mandatory gateway from day one.** Forces a daemon on users who want a CLI, and would have us building channel infrastructure before the authority model is proven.
- **Gateway as run coordinator.** Would move session leases across a network boundary, complicating the single-writer invariant for no benefit.
- **Gateway holds credentials for channels.** Rejected — channel credentials live in the kernel's secret broker like every other credential.

