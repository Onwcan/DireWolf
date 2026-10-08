# Secrets

**Invariant I3: the Cognition Plane never receives a plaintext long-lived credential.**

The agent works with opaque handles. The kernel resolves them at the last possible moment, into the narrowest possible place, for the shortest possible time.

> **Implementation status (M4e — COMPLETE;
> [ADR-0046](adr/0046-m4e-secret-handles-backends-injection-and-redaction.md)).**
> M4e's required hosted gate, which was also the final M4 gate, passed in CI run
> [36390815504](https://github.com/Onwcan/DireWolf/actions/runs/36390815504) (attempt 2).
> Completing M4e did not remove any limitation listed here.
> This document was written before any of it existed; where M4e measured
> something different, the text below is corrected and marked. In short:
> handles, metadata, the Linux **kernel keyring** and **age** backends,
> `secret.use` admission, the one-shot handoff, mode A's render (no egress
> consumer until M5), the mode B/C **secret injection primitive** (no
> production caller until M5's sandbox), redaction of `fs.read` content and
> process output, the audit events and use counts are implemented. Mode D,
> the `env` and `exec` backends, Secret Service, `mlock`, `MADV_DONTDUMP`,
> refresh of short-lived credentials, rotation warnings and any CLI secret
> command are **not**.

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
storage       = "keychain"                 # keychain | age   (env, exec: deferred, §2)
keychain      = "direwolf/github-primary"  # the keychain entry, never the value
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

| Backend | Platform | Status (M4e) |
|---|---|---|
| `keychain` | Linux: the **kernel keyring** (a `user` key in the authority uid's user keyring). Windows: the Credential Manager. macOS: the login Keychain. | Linux: implemented and exercised. Windows: exercised by the crate's tests, never served. macOS: **COMPILE-ONLY**. Secret Service was rejected: it needs a session bus and an unlocked collection a daemon does not have ([ADR-0046](adr/0046-m4e-secret-handles-backends-injection-and-redaction.md) §6). |
| `age` | Linux | Implemented: an age file opened through a trusted-file walk, decrypted by `age` 0.11.5 with an X25519 identity or scrypt passphrase **held in the keychain** — never in argv, a file, `kernel.db` or config (ADR-0046 §8). |
| `env` | — | **Deferred**, refused at load: a plaintext value in the authority's `environ` is readable by its uid and inherited by anything it starts (ADR-0046 §7). |
| `exec` | — | **Deferred**, refused at load: the authority spawns no process, and a helper's argv and environment are where values leak (ADR-0046 §7). |

A Linux `user` key holds at most 32 767 bytes, and a non-root user's keys share a quota (`/proc/sys/kernel/keys/maxbytes`); a value of any size up to the 32 KiB bound belongs in an age file.

**Provisioning a Linux keyring secret.** The authority runs as a service, and a service does not *possess* its user keyring (a systemd service gets a private session keyring; so does a CI runner), so only the key's **owner** bits decide whether it can read the key — and the kernel's default mask for a new key lets the owner only view it. A key for the authority must be owned by the authority's uid, sit in that uid's user keyring (`@u`), and carry exactly this mask, `0x3f0b0000`: the possessor may do anything; the owning uid may view, read and search; its group and everyone else, nothing. Setting a mask needs the right to change attributes, which under the default mask only a possessor has, so stage the key in the provisioning shell's own session keyring, set the mask, then move it into `@u` — as the authority's user, with the value on **stdin, never in argv**:

```bash
id=$(keyctl padd user <entry> @s)
keyctl setperm "$id" 0x3f0b0000
keyctl link "$id" @u
keyctl unlink "$id" @s
```

The authority never changes a key's permissions: a key provisioned without the owner's read (or search) permission fails closed, `BACKEND_DENIED`. The broker's and the runtime's uids have their own user keyrings, and with no group or other bits they cannot read this key even by its serial — measured on three identities in CI ([ADR-0046](adr/0046-m4e-secret-handles-backends-injection-and-redaction.md) §§6, 23).

**We invent no cryptography.** `age` for file encryption, OS APIs for keychains, `rustls` for transport. If a construction is not available from a reviewed library, we do not build it.

**Plaintext state, stated explicitly:** the secrets *index* (handle names, types, origins, metadata) is plaintext in `kernel.db`. Only values are protected. Handle names are not secret and are designed not to be.

## 3. Injection modes

Ordered by preference. The kernel selects the most restrictive mode the secret and the consumer both permit.

### (A) `egress` — the default, and the only one where the secret never leaves the kernel

> **M4e:** the secret side is real — gates, durable intent, one backend read,
> one handoff (ADR-0046 §12).
>
> **M5c (in progress, pending acceptance — [ADR-0050](adr/0050-m5c-kernel-performed-net-http-ssrf-redirects-and-credential-egress.md) §8):**
> mode A's consumer is `net.http`. A credential is attached only to a hop at
> the request's first origin, and only when its metadata names that origin
> exactly; every attachment is its own `secret.use` through both gates, its own
> durable intent (a `secret_injection` row the hop names), one backend read and
> one fresh pipe; a same-origin redirect may carry it again, as a new use, and
> a cross-origin hop never does, whatever the metadata says about the other
> origin. The broker composes the header into the request it is about to write
> and nowhere else (TX045); M4e's render-and-drop `broker.secret_egress` and
> the in-process `Authority::secret_egress` are retired, and M4e's evidence
> runs through `net.http` with every case kept. Measured: after a credential
> exchange neither daemon's memory nor any durable file holds the value.
> **An echo stops at the broker (D11):** an origin that sends the credential
> back has it taken out by the broker that sent it, before anything of the
> response is encoded — a header holding it dropped whole, the body redacted
> (read past the bound by the value's length, so an echo straddling the bound
> is caught) — and the count is audited for the handle. Measured, nine ways:
> the runtime's answer, the audit, durable state and the authority's memory
> never hold it, and the broker's own encoding never saw it. **Residual,
> pending the owner's acceptance:** the broker's TLS and HTTP libraries
> (`rustls`'s per-record copy, the `http` header map) free the echoed bytes
> without zeroing — readable only by a reader of the broker's memory, measured
> and reported per way, never claimed absent (ADR-0050 §20, D11).

`dwkd-broker` adds the header when connecting to an allowlisted origin, using a **one-shot injection handed to it by `dwkd-authority`** for that invocation only. The secret at rest exists in exactly one process — `dwkd-authority` — and never in a child, an environment, a file, or any memory the agent can influence. The broker holds the value only for the duration of the request and holds no long-lived key ([ADR-0018](adr/0018-authority-broker-split.md)).

```
runtime:  POST https://api.github.com/repos/... , credential_handle="github-primary"
kernel:   validate origin ∈ secret.origins; inject "Authorization: Bearer ghp_…"
```

Prefer this for every HTTP API. Most credentials an agent needs are HTTP credentials, so most of the time this is available.

### (B) `env_at_spawn`

> **M4e:** a *secret injection primitive*, not sandbox injection. There is no
> sandbox before M5, so the production selector refuses every host spawn; the
> primitive is exercised by a harness playing the authority against the real
> broker and real targets (ADR-0046 §13).

The value is placed in the environment of one sandboxed child process, which starts with a **scrubbed, allowlisted** environment. The value is never in the runtime's environment, the kernel's exported environment, or any sibling process.

Weaknesses, stated: readable via `/proc/<pid>/environ` by anything with the same uid inside that sandbox, and inherited by grandchildren. Used only where a tool requires it and mode (A) cannot work.

### (C) `fd_at_spawn`

The value is written to a pipe fd, or to a file on a private tmpfs with mode 0600 owned by the sandbox uid, unlinked after the child opens it. Required for SSH keys, TLS client certs, and `.netrc`-style consumers.

Stronger than (B): not visible in `environ`, and it disappears when the environment is destroyed.

> **Corrected by M4e:** the descriptor **is** inherited by a grandchild the
> target starts without closing it — measured. Containing a process tree is
> the sandbox's job (M5). M4e implements the pipe form only, on descriptor 3,
> with the same pre-M5 status as mode (B) (ADR-0046 §13).

### (D) `plaintext_to_model` — forbidden by default

**Unreachable until M6**: the metadata parser refuses it (ADR-0046 §14). Requires `security.allow_secret_to_model = true` **and** a per-use approval **and** an audit record at `sensitivity=critical`. It exists only because there are legitimate cases (a user pasting a token and asking the agent to explain it) where refusing would be paternalistic rather than protective. It is off, it is loud, and it is never the default for any secret.

## 4. Scoping and lifetime

- A credential is resolved **per invocation**, not per run and not per session.
- The plaintext lives in `Zeroizing<Vec<u8>>` and is scrubbed on drop. Best-effort — swap, core dumps and DMA defeat it — but a meaningfully different best-effort than a language where the value is an immutable interned string that cannot be scrubbed at all.
- `RLIMIT_CORE = 0` (soft and hard) and `PR_SET_DUMPABLE = 0` for both daemons: no core, and `/proc/<pid>/mem` is root's (ADR-0046 §9). **`madvise(MADV_DONTDUMP)` and `mlock` are not implemented** — no safe API for either is linked and DireWolf has no `unsafe` — so a value can reach swap.
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

- `rotate_after` is recorded with each revision; the warning in `direwolf doctor` and the metric are not implemented yet. We do not auto-rotate, because rotation semantics are provider-specific and a failed auto-rotation locks you out of your own account.
- Revocation is immediate: the handle is marked revoked and every subsequent resolution fails closed. In-flight requests are not retroactively killed but cannot be repeated.
- Short-lived credentials (OAuth access tokens) are refreshed by the kernel using a refresh token that never leaves it. The agent sees only the handle and never observes the refresh. *(Not implemented in M4e.)*
- Per-secret use counters and last-used timestamps are recorded in `kernel.db`, moved only by a confirmed injection. *(M4e has no CLI secret command; a `direwolf secret list` would show handles and counts, never a value.)*

## 7. What is audited

Every resolution records: handle, agent, run, tool, injection mode, destination origin (for A) or environment id (for B/C), decision, and result — **never the value, and never a prefix of the value**. Prefix logging is a common and bad habit: for many token formats a prefix plus a length is most of an oracle.

`secret.configured`, `secret.revoked`, `secret.fingerprinted`, `secret.denied`, `secret.intent_recorded`, `secret.resolved`, `secret.injected`, `secret.failed`, `secret.outcome_unknown` and `secret.redaction_hit` are chained audit events (M4e); `secret.rotation_due` is not implemented yet. `secret.redaction_hit` is worth alerting on: it means a secret reached a place it should not have been, and the injection mode for that secret should probably change.

## 8. Threats

| Threat | Defence |
|---|---|
| Agent reads its own API keys from config | Secrets are not in runtime-readable config; `fs.read` never covers the kernel's config root; even `POWER` profile denies it |
| Prompt injection: "print your credentials" | The agent has none to print |
| Secret exfiltrated in tool output | Not present in the child under mode (A); redaction as hygiene otherwise |
| Secret sent to the wrong endpoint | Origin binding, enforced including across redirects ([NETWORK_SECURITY.md](NETWORK_SECURITY.md) §5) |
| Secret in a core dump | `RLIMIT_CORE=0` and non-dumpable daemons (M4e; the hosted evidence crashes both hardened daemons and a dumpable control, and requires a core from the control only); `MADV_DONTDUMP` not implemented |
| Secret paged to swap | **Not defended in M4e**: `mlock` is not implemented; `memory_swap == memory` in sandboxes (M5) |
| Secret in shell history / process args | **Never passed as a command-line argument.** `argv` is world-readable on Linux. Modes B and C exist precisely to avoid argv. |
| Secret inherited by an unexpected grandchild | Mode C over mode B; environment scrubbed to an allowlist at spawn. Mode C's descriptor is still inherited by a grandchild that does not close it (measured); containment is M5's |
| Malicious skill or plugin reading credentials | Runs out-of-process with its own capability set; secrets are per-invocation, not ambient |
| Backup/export endpoint leak | No such endpoint exists at any privilege level |
| Compromised kernel | **Total loss.** Accepted residual risk R8 in [THREAT_MODEL.md](THREAT_MODEL.md); mitigated only by keeping the TCB small and its dependencies pinned and reviewed. |
