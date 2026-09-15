# Secrets

**Invariant I3: the Cognition Plane never receives a plaintext long-lived credential.**

The agent works with opaque handles. The kernel resolves them at the last possible moment, into the narrowest possible place, for the shortest possible time.

---

## 1. Handles

```
Model sees:      "github-primary"
Policy sees:     secret.use:github-primary
Kernel holds:    the actual value
```

A handle is a stable, non-secret identifier. It can appear in prompts, logs, memory and artifacts without consequence. A leaked handle grants nothing, because using it requires a capability and a policy decision.

```toml
[secrets.github-primary]
type          = "bearer"
description   = "GitHub API, repo scope"
storage       = "keychain"                 # keychain | age | env | exec
origins       = ["api.github.com", "uploads.github.com"]
header        = "Authorization"
prefix        = "Bearer "
injection     = ["egress"]                 # which modes are permitted for THIS secret
rotate_after  = "90d"
sensitivity   = "high"

[secrets.deploy-key]
type          = "ssh_private_key"
storage       = "keychain"
injection     = ["fd_at_spawn"]            # cannot be egress-injected; ssh needs a file
consumers     = ["/usr/bin/ssh", "/usr/bin/git"]
```

`injection` is an allowlist per secret, so a credential that must never appear in a child process's environment simply cannot be, regardless of what any tool requests.

## 2. Storage

| Backend | Platform | Notes |
|---|---|---|
| `keychain` | macOS Keychain, Windows DPAPI/Credential Manager, Linux Secret Service | **Default.** OS-protected at rest. |
| `age` | all | Encrypted file, key in the OS keychain or passphrase-derived. For headless Linux without a Secret Service. |
| `env` | all | Read from the **kernel's** environment at start. For containerised deployments with an external secret manager. |
| `exec` | all | Invoke an external helper (`pass`, `vault`, `op`, `bw`). The helper runs as the kernel user; its output is captured as `Zeroizing` and never logged. |

**We invent no cryptography.** `age` for file encryption, OS APIs for keychains, `rustls` for transport. If a construction is not available from a reviewed library, we do not build it.

**Plaintext state, stated explicitly:** the secrets *index* (handle names, types, origins, metadata) is plaintext in `kernel.db`. Only values are protected. Handle names are not secret and are designed not to be.

## 3. Injection modes

Ordered by preference. The kernel selects the most restrictive mode the secret and the consumer both permit.

### (A) `egress` — the default, and the only one where the secret never leaves the kernel

`dwkd-broker` adds the header when connecting to an allowlisted origin, using a **one-shot injection handed to it by `dwkd-authority`** for that invocation only. The secret at rest exists in exactly one process — `dwkd-authority` — and never in a child, an environment, a file, or any memory the agent can influence. The broker holds the value only for the duration of the request and holds no long-lived key ([ADR-0018](adr/0018-authority-broker-split.md)).

```
runtime:  POST https://api.github.com/repos/... , credential_handle="github-primary"
kernel:   validate origin ∈ secret.origins; inject "Authorization: Bearer ghp_…"
```

Prefer this for every HTTP API. Most credentials an agent needs are HTTP credentials, so most of the time this is available.

### (B) `env_at_spawn`

The value is placed in the environment of one sandboxed child process, which starts with a **scrubbed, allowlisted** environment. The value is never in the runtime's environment, the kernel's exported environment, or any sibling process.

Weaknesses, stated: readable via `/proc/<pid>/environ` by anything with the same uid inside that sandbox, and inherited by grandchildren. Used only where a tool requires it and mode (A) cannot work.

### (C) `fd_at_spawn`

The value is written to a pipe fd, or to a file on a private tmpfs with mode 0600 owned by the sandbox uid, unlinked after the child opens it. Required for SSH keys, TLS client certs, and `.netrc`-style consumers.

Stronger than (B): not visible in `environ`, not inherited by grandchildren, and it disappears when the environment is destroyed.

### (D) `plaintext_to_model` — forbidden by default

Requires `security.allow_secret_to_model = true` **and** a per-use approval **and** an audit record at `sensitivity=critical`. It exists only because there are legitimate cases (a user pasting a token and asking the agent to explain it) where refusing would be paternalistic rather than protective. It is off, it is loud, and it is never the default for any secret.

## 4. Scoping and lifetime

- A credential is resolved **per invocation**, not per run and not per session.
- The plaintext lives in `Zeroizing<Vec<u8>>` and is scrubbed on drop. Best-effort — swap, core dumps and DMA defeat it — but a meaningfully different best-effort than a language where the value is an immutable interned string that cannot be scrubbed at all.
- `RLIMIT_CORE = 0` for the kernel; core dumps disabled; `madvise(MADV_DONTDUMP)` on secret pages where available; `mlock` where permitted so values are not paged to disk.
- Child processes holding a secret are tracked; on run termination the environment is destroyed rather than reused.
- **No secret-returning API exists.** Not for the runtime, not for the CLI, not for a diagnostics endpoint, not for a "backup" or "export" command, at any privilege level. `direwolf secret export` does not exist and will not be added. *(An unauthenticated credential-export endpoint is the single highest-impact vulnerability found in a comparable system; the defence is not to authenticate it but to not have it.)*

## 5. Redaction on the return path

Everything crossing TB1→TB2 (tool output, logs, artifacts, error messages, model context) passes a redaction pass.

**What it catches:** exact matches of live secret values; known-shape patterns (`ghp_`, `github_pat_`, `sk-`, `xox[baprs]-`, `AKIA`, `ASIA`, PEM `BEGIN … PRIVATE KEY` blocks, JWTs, `Bearer <base64>`, connection strings with embedded passwords); high-entropy strings adjacent to keywords like `token=`, `password=`, `api_key=`.

**What it cannot catch — stated honestly:**

- a secret the process transformed (base64, hex, ROT13, reversed, chunked across lines, embedded in a QR code)
- a secret split across two tool results
- a secret encoded into a filename, a timing pattern, or an image
- a *new* credential minted by the tool that we have never seen

**Redaction is therefore not a control we rely on.** It is a hygiene layer that catches accidents. The actual control is injection mode (A): if the secret was never in the child process, there is nothing in the output to redact. Every design decision here follows from that ordering — we spend our effort on keeping secrets out of reach, not on scrubbing them after the fact.

Redaction replaces with `[redacted:<handle>]` where the handle is known, `[redacted:pattern]` otherwise, so the agent can see that something was removed and reason about it. Silent removal produces confusing model behaviour and hides leaks from operators.

## 6. Rotation, revocation, expiry

- `rotate_after` produces a warning in `direwolf doctor` and a metric. We do not auto-rotate, because rotation semantics are provider-specific and a failed auto-rotation locks you out of your own account.
- Revocation is immediate: the handle is marked revoked and every subsequent resolution fails closed. In-flight requests are not retroactively killed but cannot be repeated.
- Short-lived credentials (OAuth access tokens) are refreshed by the kernel using a refresh token that never leaves it. The agent sees only the handle and never observes the refresh.
- Per-secret use counters and last-used timestamps are recorded, so `direwolf secret list` shows an unused credential that should probably be deleted.

## 7. What is audited

Every resolution records: handle, agent, run, tool, injection mode, destination origin (for A) or environment id (for B/C), decision, and result — **never the value, and never a prefix of the value**. Prefix logging is a common and bad habit: for many token formats a prefix plus a length is most of an oracle.

`secret.resolved`, `secret.injected`, `secret.denied`, `secret.rotation_due`, `secret.revoked`, `secret.redaction_hit` are all chained audit events. `secret.redaction_hit` is worth alerting on: it means a secret reached a place it should not have been, and the injection mode for that secret should probably change.

## 8. Threats

| Threat | Defence |
|---|---|
| Agent reads its own API keys from config | Secrets are not in runtime-readable config; `fs.read` never covers the kernel's config root; even `POWER` profile denies it |
| Prompt injection: "print your credentials" | The agent has none to print |
| Secret exfiltrated in tool output | Not present in the child under mode (A); redaction as hygiene otherwise |
| Secret sent to the wrong endpoint | Origin binding, enforced including across redirects ([NETWORK_SECURITY.md](NETWORK_SECURITY.md) §5) |
| Secret in a core dump | `RLIMIT_CORE=0`, `MADV_DONTDUMP` |
| Secret paged to swap | `mlock` where permitted; `memory_swap == memory` in sandboxes |
| Secret in shell history / process args | **Never passed as a command-line argument.** `argv` is world-readable on Linux. Modes B and C exist precisely to avoid argv. |
| Secret inherited by an unexpected grandchild | Mode C over mode B; environment scrubbed to an allowlist at spawn |
| Malicious skill or plugin reading credentials | Runs out-of-process with its own capability set; secrets are per-invocation, not ambient |
| Backup/export endpoint leak | No such endpoint exists at any privilege level |
| Compromised kernel | **Total loss.** Accepted residual risk R8 in [THREAT_MODEL.md](THREAT_MODEL.md); mitigated only by keeping the TCB small and its dependencies pinned and reviewed. |
