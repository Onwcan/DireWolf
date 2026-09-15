# ADR-0022: Approval responses are authenticated independently of the relay

**Status:** Accepted · **Date:** 2026-09-12 · **Amends:** [ADR-0004](0004-gateway-boundary.md)

## Context

ADR-0004 claims a compromised gateway "can drop an approval request but cannot forge or rewrite one," with the client verifying that a per-approval nonce round-trips.

Review finding H5: that is true of the approval **request** and unsupported for the **response**. The nonce travels *outbound through the relay*, so a compromised gateway or channel adapter holds everything needed to fabricate an approval. The gateway was therefore inside the approval TCB while being documented as outside it.

## Decision

Three delivery paths, three authentication stories, stated separately.

### CLI-local (default)

The approval never leaves the host. The CLI passes its controlling-terminal fd to `dwkd-authority` over the DWKP socket (`SCM_RIGHTS`; `DuplicateHandle` on Windows). Authority treats the fd as **untrusted input**: it verifies the fd is a character device, is a TTY, and belongs to the session of the peer whose credentials it already checked on connect. A pipe is refused and the approval falls back to `direwolf approve`.

Authority then **writes the prompt and reads the keystroke directly on that fd**, taking the terminal to raw mode and suspending the runtime's output stream to that TTY for the duration. There is no relay and therefore nothing to authenticate. This also closes terminal-control phishing: an agent emitting cursor-positioning or scroll-region sequences cannot overdraw a prompt it is not permitted to write during.

### Detached-local

`direwolf approve` is a local DWKP client authenticated by socket peer credentials. Same trust story as the CLI.

### Remote (push channel) — off by default

**Authenticated by a device key, not by the nonce.**

- **Pairing** establishes a per-device secret out of band: `direwolf approve pair` displays a short code on the *local* terminal that the operator enters on the device. The key is derived from that exchange and stored in the kernel's secret store and the device's keychain. The relay never observes it.
- **What is MACed:** `HMAC(device_key, canonical_cbor({request_id, binding_hash, decision, scope, ttl, max_uses, device_id, response_nonce, not_after}))`. Note this includes `binding_hash` — the device attests to *the action*, not merely to "yes."
- **Replay prevention:** `request_id` is single-use and burned kernel-side on acceptance; `response_nonce` is device-generated and must not repeat; `not_after` bounds the window to the approval's own TTL.
- **Request identity:** the device displays the kernel-rendered canonical action, and the MAC covers the same `binding_hash` the kernel will re-verify pre-execution. A relay that alters the displayed text cannot produce a matching MAC.
- **Gateway threat model, restated:** a compromised gateway can **suppress** an approval request (denial of service), **delay** it, or **observe** its canonical content. It cannot forge a response, alter what was approved, or replay a prior approval.
- High-risk classes (`DESTRUCTIVE`, `secret.use`, host execution) can be configured to require local approval regardless of pairing.

## Consequences

The gateway leaves the approval TCB, which is what ADR-0004 claimed but did not achieve. Cost: remote approval now requires a pairing step, and a lost device requires re-pairing. Both are correct frictions for the operation that authorises everything else.

## Alternatives considered

- **Nonce only.** The status quo ante; broken against a compromised relay.
- **TLS client certificates to the gateway.** Authenticates the connection, not the decision; a compromised gateway still sits after termination.
- **Require local approval always.** Simplest and safest; rejected because it makes detached runs on a headless host unapprovable, which is the V1.1 use case.

