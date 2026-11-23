# Operating DireWolf, as built

What runs today, how an operator starts it, and how to tell what it is
doing. **As built, 2026-11-21.** [PRODUCT_SPEC.md](PRODUCT_SPEC.md) describes
V1, the target; where the two differ, this page is what a build does.
[ROADMAP.md](ROADMAP.md) says which milestone owns each part that is not
here.

Every command and flag on this page is checked against the binaries' own
usage text by `tests/architecture/test_docs_truth.py`.

## 1. What there is to run

| Binary | What it is | Where it runs |
|---|---|---|
| `dwkd-authority` | The authority (decides): DWKP on a Unix-domain socket, policy, capabilities, secret metadata, the audit record | `dwkd-authority serve`: **Linux only**, refuses to start on macOS and Windows. `dwkd-authority verify-audit <state-dir>`: read-only, wherever it builds |
| `dwkd-broker` | The broker (does): exactly the effect the authority authorised, on the object the authority opened; the sandbox supervisor and the CONNECT proxy | `dwkd-broker serve`: **Linux only** |
| `direwolf` | `direwolf --version`, `direwolf doctor` (build provenance and the platform tier) and `direwolf models` (the offline model library) | every platform CI builds: Linux, macOS, Windows |

**Not here yet.** There is no agent: no runtime loop, no chat and no
command that runs a task (M9, M17). A DWKP client is whatever the operator points at
the authority's socket; the evidence uses its own clients. There are no
approvals or budgets (M6), so a decision that needs an approval is a denial;
no model providers (M7); no host execution (M6); no installer, package or
released binary (M18). [§11](#11-what-does-not-exist) lists the rest.

## 2. Build

Prerequisites and setup are in [CONTRIBUTING.md](../CONTRIBUTING.md): Rust
from `rust-toolchain.toml`, Python 3.12+, `uv` and git.

```bash
make dev                         # verify the toolchain, sync, build, check
cargo build --locked --release   # dwkd-authority, dwkd-broker and direwolf in target/release/
```

The sandbox and its evidence also need a Docker-compatible runtime on Linux.

## 3. Identities

DireWolf's boundary is between operating-system identities, and nothing
creates them for you: there is no init command. The operator creates each
user and names its uid to the daemons.

| Identity | Named by | Never |
|---|---|---|
| the authority | `dwkd-broker serve --authority-uid <UID>` | root; the broker's; a DWKP peer's |
| the broker | `dwkd-authority serve --broker-uid <UID>` (with `--broker-socket`) | root; the authority's; uid 10001 or 10002 |
| each DWKP peer (the runtime, a client) | `dwkd-authority serve --allow-uid <UID>`, repeated | the authority's |
| an approver (optional) | `dwkd-authority serve --approver-uid <UID>` (with `--approver-socket`) | a DWKP peer's, the broker's or the authority's |
| every sandboxed workload, and its relay | uid 10001 and 10002, fixed | a daemon's |

Development on one account has its acknowledgements --
`dwkd-authority serve --allow-authority-uid`, `--allow-shared-broker-uid`,
`dwkd-broker serve --allow-shared-authority-uid` -- each logged
`REDUCED ASSURANCE` and recorded in the daemon's effective posture
([F03_EFFECTIVE_POSTURE.md](F03_EFFECTIVE_POSTURE.md)). A production
deployment passes none of them.

## 4. Starting the daemons

Start the broker first; the authority performs every effect through it.

```bash
# as the broker's user (uid 992 here)
dwkd-broker serve --socket /run/direwolf/broker.sock --authority-uid 991

# as the authority's user (uid 991 here)
dwkd-authority serve \
  --state-dir /var/lib/direwolf \
  --socket /run/direwolf/dwkp.sock \
  --allow-uid 1000 \
  --mode balanced \
  --policy-shipped balanced \
  --path-anchor home=/home/alice \
  --broker-socket /run/direwolf/broker.sock \
  --broker-uid 992 \
  --egress-allowlist /etc/direwolf/egress.toml \
  --sandbox-config /etc/direwolf/sandbox.toml
```

`--state-dir`, `--socket`, at least one `--allow-uid`, `--mode` and a policy
are required; everything else is optional, and an option left out means
less is possible, never more. The full flag lists are
`dwkd-authority --help` and `dwkd-broker --help`. Under systemd, the broker's
unit and the host settings it checks are in
[BROKER_HARDENING.md](BROKER_HARDENING.md).

The authority reads the operator's files once, at start, and parses each
whole: an unknown key refuses it, and the authority does not start. Every
one of them -- policy files, `--secrets-file`, `--sandbox-config`,
`--egress-allowlist` -- must be an absolute path to a regular file owned by
root or the authority's uid and writable by nobody else, reached without a
symlink through directories only they can change (sticky ones too); one
that is not is refused before it is read
([ADR-0075](adr/0075-sr01-operator-policy-files-are-read-as-the-other-operator-files-are.md),
accepted, for policy files). A change to any of them takes effect at the
next start, and a restart reaps every run.

#### Making an operator file trusted

The authority judges a file's owner and mode when it reads it. Linux checks
write permission when a descriptor is opened, not each time it is written
through: a process that opened a file for writing while it could keeps
writing after `chmod go-w`. So a file another uid has ever been able to
write is **replaced, not re-moded** -- the same for policy files,
`--secrets-file`, `--sandbox-config` and `--egress-allowlist`:

1. **The directories first.** Every directory from `/` to the file is owned
   by root or the authority's uid and writable by nobody else, or is sticky.
   `chown` and `chmod go-w` suffice here: a directory's write permission is
   checked on every entry created, renamed or removed. Then look for entries
   another uid left while it could write: anything you did not put there
   goes.
2. **A fresh file, restricted from its first byte.** As root (or the
   authority's user), into the file's own directory, from the reviewed
   content:
   `install -m 0644 -o root -g root reviewed.toml /etc/direwolf/.balanced.toml.new`.
   It is a new inode that no other uid ever had open, nor could open for
   writing.
3. **Over the old name, atomically.**
   `mv -T /etc/direwolf/.balanced.toml.new /etc/direwolf/balanced.toml`
   (one `rename` in one directory). A descriptor still open on the old file
   now writes to an inode no name reaches; it changes nothing the authority
   reads.
4. **Absolute and symlink-free.** Name the file by its real absolute path; a
   symlink anywhere on the path, or a relative path, refuses the start.
5. **Start, and see it refuse what it should.** The authority loads the new
   file at its next start, and the audit's `policy.installed` record carries
   the revision it read. A start that names `--policy-file` (or the other
   flag) and its reason is a file or directory still not trusted.

This assumes the operator's two identities are what they are: nothing
another uid runs holds root or the authority's uid, and the authority's uid
is never a runtime's (§3). Against a process that already has either, which
can write any of these files whatever their mode, the check promises
nothing.

### Policy

- `--policy-shipped safe|balanced|power` uses a pack compiled into the build;
  or `--policy-file <PATH>` (repeated) with `--policy-profile <NAME>` composes
  the operator's own ([POLICY.md](POLICY.md) §3). The two cannot be combined.
- `--mode safe|balanced|power` and `--ceiling <CAPABILITY>` (repeated) set the
  mode's capability ceiling ([CAPABILITIES.md](CAPABILITIES.md) §6).
- The shipped packs deny every read until the operator says where the home
  is: `--path-anchor home=<DIR>`; the other anchors are `direwolf-home`,
  `direwolf-config` and `direwolf-install`
  ([F12_POLICY_PACK_USABILITY.md](F12_POLICY_PACK_USABILITY.md) §6).
- `--allow-host-execution` sets the policy flag, and no host launch follows
  from it: a host launch also needs a per-invocation approval, which no build
  has before M6.

### Network egress

`--egress-allowlist <PATH>` names every network destination, exactly: host,
port and the path that may use it (`net_http` or `workload`). Without it no
network action is allowed, and with it every policy -- a shipped pack or the
operator's own -- is under it as a ceiling
([F06_EGRESS_ALLOWLIST.md](F06_EGRESS_ALLOWLIST.md) §§2, 6;
[ADR-0073](adr/0073-f06-of2-the-operators-egress-allowlist-is-a-ceiling-every-policy-is-under.md),
Proposed). The broker resolves each decided name through the host's resolver
as an absolute name, so no search domain is appended and the hosts file does
not answer for it; a local stub resolver's own records are the host's
configuration
([ADR-0074](adr/0074-f16-the-broker-resolves-the-decided-name-and-no-other.md),
Proposed). `net.http` runs on `x86_64` only
([ADR-0053](adr/0053-d11-exchange-worker-confinement-and-secret-memory.md)).

### The execution environment

`--sandbox-config <PATH>` attaches the operator's execution environment:
the runtime client and its socket, the image and the probe by digest,
`PROXY_ONLY` and its byte budgets, the image's executable manifest and each
workspace's quota. Without it, `process.exec` runs nowhere. The file's
members are listed in `crates/dwkd-authority/src/sandbox/operator.rs`; the
workspace is the operator's to provision, as root, once
([SANDBOX.md](SANDBOX.md) §3, "Provisioning a workspace").

Every environment's workload runs as one host uid, 10001: per-environment
user-namespace remapping is not built, because no supported runtime offers it
per container ([F05_USERNS_LSM.md](F05_USERNS_LSM.md) §13).
`dwkd-broker serve --require-lsm apparmor` (or `selinux`) serves only where
the kernel enforces that module and refuses every environment it does not
confine ([ADR-0070](adr/0070-adr-0069-decisions-host-vantage-required-lsm-and-what-stays-deferred.md),
Proposed); Docker Desktop on WSL2 runs neither module, so there it refuses
to start.

### Secrets

`--secrets-file <PATH>` names the operator's secret metadata: handles,
origins and injection modes, never a value. Values live in the Linux kernel
keyring or an age file; provisioning a keyring entry is in
[SECRETS.md](SECRETS.md) §2.

### The approver endpoint

`--approver-socket <PATH>` with `--approver-uid <UID>` opens the human
approver's endpoint, identity boundary only: no approval operation exists
before M6
([F18_APPROVER_IDENTITY.md](F18_APPROVER_IDENTITY.md),
[ADR-0067](adr/0067-f18-approver-endpoint-identity-boundary.md), Proposed).
An approver uid is a principal, not a person: give it an account of its own
that no agent, automation or runtime runs as, or a decision made under it is
not a human's
([ADR-0077](adr/0077-the-approval-channel-is-the-approver-endpoint-and-an-approver-uid-is-a-principal-not-a-person.md),
Proposed).

## 5. What the daemons say

Each daemon writes one line per event to stderr (`journalctl -u <unit>` under
systemd).

| Line | From | Says |
|---|---|---|
| `event=posture`, `event=posture_summary` | broker, at start | each control `ENFORCED`, `REDUCED`, `UNVERIFIED`, `UNSUPPORTED` or `NOT_APPLICABLE`, and what a reduced one refuses ([F03_EFFECTIVE_POSTURE.md](F03_EFFECTIVE_POSTURE.md) §6) |
| `event=posture_acknowledged` | broker, at a hop | a hop admitted under a development acknowledgement against the host's facts |
| `event=deployment_posture` | broker, at start | Yama, the binary's mode, swap, page zeroing ([BROKER_HARDENING.md](BROKER_HARDENING.md)) |
| `event=sandbox_identity` | broker, per environment | its user namespace and security modules as measured ([F05_USERNS_LSM.md](F05_USERNS_LSM.md) §5) |
| `REDUCED ASSURANCE: …` | either | a development acknowledgement in force |
| `authority.posture` | authority, in `audit.log` | the incarnation's own controls and acknowledgements, before its socket is bound |

The broker's posture does not reach the authority's audit record: that is
protocol 13, deferred (F-03's D6).

## 6. Checking a deployment

```bash
dwkd-authority verify-audit /var/lib/direwolf   # read-only
make d11-posture                                # the broker host's hardening facts, read-only
direwolf doctor                                 # this build and this platform
```

`dwkd-authority verify-audit` checks `audit.log`'s hash chain and compares
its head with `kernel.db`'s (`audit.log: N records, chain intact, head …`,
then `kernel.db: head …, flushed …, pending …`); it changes nothing. A served
authority verifies the chain at every start, or does not start.

`direwolf doctor` contacts no daemon: it reports the build, the platform
tier and where `DIREWOLF_HOME` is, and names each security property it does
not check together with the daemon that reports it. Checking a running
deployment is the M17 doctor's.

## 7. Platforms

| Host | Daemons | Notes |
|---|---|---|
| Linux (native) | serve | the production target; `x86_64` for `net.http` |
| Linux under WSL2 | serve | development: Docker Desktop's kernel runs no AppArmor or SELinux, and the VM's swap is outside any Linux setting, so the broker needs its acknowledgements ([BROKER_HARDENING.md](BROKER_HARDENING.md), "WSL2") |
| macOS | refuse to start | builds and tests; `direwolf`, `dwkd-authority verify-audit`; the Keychain backend is compile-only |
| Windows (native) | refuse to start | builds and tests; `direwolf`, `dwkd-authority verify-audit`; the Credential Manager backend is tested, never served |

The VM-hosted sandbox for macOS and native Windows in
[PRODUCT_SPEC.md](PRODUCT_SPEC.md) §9 and [SANDBOX.md](SANDBOX.md) §5 is the
design, not the build.

## 8. The offline model library

`direwolf models` imports, hashes, identifies, lists, verifies and removes
local model files (GGUF, safetensors and their companions) and estimates what
this host can hold. It contacts no daemon, reaches no network, runs nothing
it reads and serves no inference: [MODELS.md](MODELS.md).

```bash
direwolf models import --library /srv/models --name qwen --quota-bytes 20000000000 ./qwen.gguf
direwolf models verify --library /srv/models qwen
direwolf models recommend --library /srv/models --context 8192
```

Downloads are not built: a download is egress the authority decides, and it
is scheduled after M7
([ADR-0072](adr/0072-the-operators-model-library-is-offline-and-a-download-is-egress-the-authority-decides.md),
Proposed, OM-2).

## 9. Reproducing the evidence

`make help` lists every evidence campaign and mutation review;
[tests/README.md](../tests/README.md) says what each one exercises. Three
rules hold for all of them:

- **NOT EXERCISED fails.** A case the machine could not run -- a second
  identity, root, a dedicated filesystem, unprivileged namespaces -- is
  reported and fails the task, never counted as a pass.
- **Some run only hosted.** `make sandbox-restart-evidence` and
  `make sandbox-capacity-evidence` refuse anywhere but a disposable
  GitHub-hosted runner; the three-identity halves need three real users.
- **A green run proves what it ran.** A property is evidenced by the case
  that exercised it, not by the run's colour.

## 10. Diagnosing a refusal

A refusal names its reason: every policy decision is explainable by rule
id, file and line ([POLICY.md](POLICY.md) §5; the command that renders an
explanation is M17's), and an environment that is refused is recorded
`environment.refused` with its reason (`WORKSPACE_MODE`,
`WORKSPACE_FILESYSTEM_SHARED` and the others in [SANDBOX.md](SANDBOX.md) §3).
A network action outside the allowlist is `OUTSIDE_EGRESS_ALLOWLIST` from the
rule `operator-egress-ceiling`.

## 11. What does not exist

- An init command, layered configuration and a configuration validator
  ([PRODUCT_SPEC.md](PRODUCT_SPEC.md) §§6a, 7): the operator creates the
  identities, writes the files and passes the flags above.
- The agent runtime and its command line (M8-M17); approvals and budgets
  (M6); model providers and model egress (M7); host execution (M6).
- Model search and download (ADR-0072 OM-2, after M7).
- Per-environment uid remapping (F-05, blocked on the runtime); the broker's
  posture in the authority's record (protocol 13, deferred); Landlock (with
  M6's host execution).
- Released binaries, packages, signatures and an SBOM (M18).

## 12. Capability inventory, by state (2026-11-21)

**Implemented.** M1, the repository foundation; M2, the protocol and its
schemas; M2.5, the evaluation harness; M3, the authority -- policy,
capabilities, the audit record, the authenticated DWKP socket; M4, brokered
effects -- the filesystem tools, process execution decided on executable
identity, secrets by handle; M5, the OCI sandbox and network mediation --
`oci-strict` measured at runtime, `PROXY_ONLY` through the broker's CONNECT
proxy, the kernel's own `net.http`, a sandboxed `process.exec`, npm and pip
under their profiles ([ROADMAP.md](ROADMAP.md)). The security work since M5,
finding by finding (the roadmap's "Pre-M6 security remediation" note). The
offline model library, which is not an inference provider (§8).

**Implemented, with stated limits.**

- Effective posture (F-03): the broker's reaches its stderr only; the
  authority's audit record does not hold it (§5).
- User namespace and security module (F-05): measured and reported; a module
  is enforced only with `--require-lsm`; every environment shares uid 10001.
- The egress ceiling (F-06): exact host and port, read at start; no
  per-entry quota.
- The resolver (F-16): absolute names, bounded answers; a local stub
  resolver's records and upstream are the host's; no DNSSEC; NOT EXERCISED in
  hosted CI.
- Sandbox assurance: on Linux with a Docker-compatible runtime; a container
  shares the host kernel, so this is not VM isolation; Docker Desktop on WSL2
  runs no AppArmor or SELinux.
- Confinement is Linux's: the daemons serve on Linux only, `net.http` on
  `x86_64` only.

**Partially completed or deferred.** A user namespace per environment
(F-05, blocked on the runtime); protocol 13 with F-03's D6; Landlock, with
M6's host execution; host execution itself (M6); a `model_download`
operation and its streaming (ADR-0071 OF-3, ADR-0072 OM-2); per-entry egress
quotas (OF-3); F-12's artifact capture (M8).

**Planned.** M6, the approval registry and hierarchical budgets; M3.5, the
vertical slice; M7, model providers and model egress; online model downloads,
after M7; M8, durable runtime state; M9, the agent loop; M10 to M17, tools,
context, memory, skills, subagents, the task graph, MCP and the command line;
M18, V1 hardening and releases.
