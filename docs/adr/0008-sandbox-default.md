# ADR-0008: Sandboxed execution is the default; host execution is opt-in and loud

**Status:** Accepted · network topology superseded by [ADR-0024](0024-sandbox-network-topology.md) · **Date:** 2026-09-11

> **PARTIALLY SUPERSEDED by [ADR-0024](0024-sandbox-network-topology.md).** Sandboxed-by-default, the hard rules, and the opt-in/loud host-execution policy all stand. The `network: none` + Unix-socket-proxy topology does not — no mainstream HTTP client can address a proxy over a Unix socket, so it was unbuildable. The sandbox now uses `PROXY_ONLY`.

## Context

Both major comparable systems default to host execution with sandboxing available but off. Both document this honestly. The observed outcome at scale — an unauthenticated credential-export CVE with 17,500+ exposed hosts, a national CERT advisory, and a live-deployment compromise achieving shell execution — is what happens when the safe configuration is opt-in for hundreds of thousands of users.

**Defaults are the security posture.** Everything else is documentation.

## Decision

- **Default: OCI sandbox** (`oci-strict`) with non-root uid, read-only rootfs, `--network none`, all capabilities dropped, `no-new-privileges`, seccomp, cgroup limits, one container per run.
- **Never, with no configuration option to the contrary:** mount the container socket, use `--privileged`, share host namespaces, or add back `DAC_OVERRIDE`/`CHOWN`/`FOWNER`.
- **Host execution requires all of:** kernel-side config flag, a capability scoped to `environment=host`, per-invocation approval (no standing grant covers it), a persistent visible indicator, and an audit record at `assurance=None`.
- **`AssuranceLevel` is policy-visible.** A rule can require at least `ContainerIsolation`; an environment that cannot provide it is refused rather than silently accepted.
- **Isolation never disables authorization.** Sandbox and policy are orthogonal dimensions.
- **`direwolf doctor` states the real assurance level per platform**, loudly, rather than degrading silently.

## Consequences

Most users never run agent code on their host. Windows and macOS get VM-grade isolation via Docker Desktop almost incidentally. Native-Windows host execution is honestly labelled the weakest configuration, and WSL2 is the recommended posture.

Cost: Docker is a hard dependency for the default path; container startup adds latency (mitigated by pre-warming); some workflows (GPU, hardware, uncontainerisable toolchains) genuinely need host execution and pay real friction for it.

## Alternatives considered

- **Host by default with sandbox available.** The competitors' choice. Rejected on the evidence above.
- **gVisor / Kata / Firecracker by default.** Stronger, materially harder to install, and not available everywhere. Interface reserved; deferred.
- **No sandbox, rely on capabilities alone.** Capabilities constrain what we broker; they do not constrain what a process does once running. Defence in depth requires both.

