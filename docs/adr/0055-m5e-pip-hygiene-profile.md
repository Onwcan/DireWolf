# ADR-0055: M5e — an evidence-backed pip profile for `workspace_exec_hygiene`: `pip install` of named wheels only, no build backend, configuration and trust pinned, everything else refused

**Status:** Proposed · **Date:** 2026-10-27 · **Would amend (on acceptance):** [ADR-0052](0052-m5d-sandboxed-process-exec.md) §5a (`pip` leaves the obligation's "anything else" row — kept with nothing pip-specific — for this profile) · **Refines:** [ADR-0048](0048-m5b-proxy-only-topology-and-connect-proxy.md) (a package index is one more exact `network.https` grant through the proxy), [ADR-0045](0045-m4d-process-execution-broker.md) §8 (states how `argv_safe`'s R3 meets this profile, and changes nothing in it; §6), [SANDBOX.md](../SANDBOX.md) §4a · **Sibling of:** [ADR-0054](0054-m5e-npm-hygiene-profile.md) (npm; Proposed) · **Addresses:** [ADR-0000](0000-authority-plane-separation.md) (no second path, §11) · **Plan:** [M5E_ASSURANCE_PLAN.md](../M5E_ASSURANCE_PLAN.md) (the owner's decision OD-E2, 2026-10-26: pip gets its own profile in a sibling ADR)

> **pip runs in an environment, under the obligation, only as `pip install`
> of named packages from a granted index, as wheels — never a build backend
> — with its configuration and its trust pinned by the trusted launcher and
> the authority; anything that would widen that is refused before an intent
> is recorded; and nothing changes in production until the evidence in §9
> has passed in hosted CI and the owner accepts this ADR.**

This is a proposal. It accepts nothing, enables nothing, and changes no
production behaviour; pip's treatment today is unchanged until it is
accepted (the owner's decision OD-E2).

## Context

M5's contract requires a real `pip install` that succeeds against an
allowlisted registry and fails against a non-allowlisted one
([ROADMAP.md](../ROADMAP.md)). Today, in an environment:

- **Under the shipped packs**, `pip install` is denied by policy before the
  obligation is considered: the packs require `when.argv_safe`, and ADR-0045
  §8's R3 names `install`, `download` and `wheel` as exec-style words of the
  `pip`/`pip3` family, because each can run a source distribution's build
  backend (`crates/dwkd-authority/src/resource/exec/argv.rs`). `python -m pip`
  is an interpreter (R1) and is denied the same way.
- **Under an operator policy that does not ask for `argv_safe`**, a `pip`
  executable matches no family of the obligation and is kept with nothing
  pip-specific (`hygiene.rs`, the "anything else" row); `python -m pip` is the
  Python family, kept by `PYTHONNOUSERSITE` and `PYTHONSAFEPATH`, with `-E`
  refused. None of the launcher's variables is pip's.

What pip can do with a workspace an agent can write — each a claim this ADR
makes **only** once a case in §9 shows it on the pinned pip:

- **Run package code at install time.** A source distribution is built by its
  own build backend (`setup.py`, a PEP 517 backend), which is arbitrary code;
  so is a local directory, an editable install (`-e`), a VCS URL and a direct
  archive URL. `--only-binary=:all:` refuses source distributions from an
  index — and pip documents it per requirement, so whether it also covers a
  path, an editable or a URL is to be measured, not assumed.
- **Read configuration from several places.** pip documents command-line
  options over `PIP_*` variables over configuration files (`PIP_CONFIG_FILE`,
  then site, user and global files). The image provides the files; the
  launcher provides the variables; `--isolated` drops variables and user
  configuration — the launcher's pins among them.
- **Take options from a requirements file**, which is workspace content:
  `--index-url`, `--extra-index-url`, `--trusted-host`, `--find-links`,
  `--no-binary`, `-e`, and nested `-r` and `-c`. The authority reads no
  workspace file, so it cannot see them.
- **Relax TLS**: `--trusted-host` lets a host's certificate go unverified and
  plain HTTP be used; `--cert` replaces the trust store; recent pip versions
  may use the operating system's store.
- **Install code that runs later**: a wheel's console scripts, its modules,
  and `.pth` files, which Python executes at start-up from any site directory.
- **Reuse a cache**: a wheel fetched once can satisfy a later install without
  a network request — a false "allowed" in evidence.
- **Check integrity only on request**: hash-checking mode
  (`--require-hashes`, hashes in a requirements file) is optional; a wheel's
  `RECORD` is not otherwise checked against a registry.

What already bounds any workload (ADR-0052, ADR-0048): uid 10001, no
capability, a read-only root with `HOME=/` read-only, `/tmp` its own bounded
`tmpfs`, the limits, `reap`, and in `PROXY_ONLY` exactly the run's
`network.https` grants through the broker's proxy.

## Decision

### 1. Scope and identity

The profile applies only to an executable whose identity's last component is
`pip`, `pip3` or `pip3.N`, named in the operator's image manifest and proved by
digest before every workload. It is a script: its interpreter and pip's
package tree are the image's, pinned by the image digest, as pytest's are
today. `python -m pip` is the interpreter's case (R1), not this profile's (open
point P3).

Only the subcommand **`install`** is kept. Any other first non-option
argument — `download`, `wheel`, `uninstall`, `config`, `cache`, `debug`,
anything — is `OBLIGATION_UNENFORCEABLE` (`HYGIENE_NOT_EVIDENCED`).
`install`'s package arguments are **names with optional version specifiers**
(`name`, `name==1.2`, `name>=1,<2`, with extras): an argument that is a path,
a URL, an archive, a VCS reference (`git+…`), a direct reference
(`name @ url`) or `.` is refused.

### 2. How it is kept

**By the launcher**, for every hygiene launch, fixed variables added by this
ADR: `PIP_CONFIG_FILE=/dev/null` (no configuration file is read — the image's
included, as git's system file is not, ADR-0052 §5a), `PIP_NO_INPUT=1`,
`PIP_DISABLE_PIP_VERSION_CHECK=1`, `PIP_NO_CACHE_DIR=1`,
`PIP_ONLY_BINARY=:all:` and `PIP_CERT=/etc/direwolf/pip-ca.pem` (§5). None comes
from the caller, none is spelled on the runtime's command line, and each is a
reserved name a mode B secret may not take (ADR-0052 §7).

**By the authority**, the arguments it puts before the invocation's own and
records in the plan it hashes: `--only-binary=:all:`, `--no-cache-dir`,
`--no-input`, `--disable-pip-version-check` and `--cert
/etc/direwolf/pip-ca.pem`. If pip's precedence is as documented, the command
line outranks both the variables and any file; §9 measures it rather than
assumes it.

### 3. What would undo or widen it is refused

Before any intent, `OBLIGATION_UNENFORCEABLE` (`HYGIENE_OVERRIDDEN_BY_ARGV`)
for an invocation whose own arguments include any of:

- **build or source**: `--no-binary`, an `--only-binary` other than `:all:`,
  `-e`/`--editable`, `--config-settings`, `--global-option`,
  `--build-option`, `--no-build-isolation`, `--use-pep517`,
  `--no-use-pep517`;
- **configuration**: `--isolated` (it drops the launcher's variables),
  `--proxy`;
- **trust**: `--trusted-host`, `--cert`, `--client-cert`;
- **sources the authority cannot see**: `-r`/`--requirement`,
  `-c`/`--constraint`, `-f`/`--find-links` (open point P2);
- **writes outside the workspace and `/tmp`**: `--user`, `--root`,
  `--prefix`, `--src`.

`--index-url` and `--extra-index-url` naming `https` URLs are allowed (§4);
`--target` is allowed, and a target outside `/workspace` and `/tmp` fails on
the read-only root.

### 4. Destinations

The profile names no index and rewrites none. Where pip may connect is the
run's exact `network.https` grants, enforced by the proxy (ADR-0048): an index,
a file host or a redirect target that is not granted is refused at
`CONNECT`, attributed to the proxy's decision. A plain-HTTP index is not
reachable at all, with or without `--trusted-host`.

### 5. Trust

The workload does not choose whom pip trusts — the principle the owner chose
for npm (OD-E6), proposed here for pip: verification stays on;
`--trusted-host`, `--cert` and `--client-cert` are refused; and the launcher
and the authority both point pip at one trust file in the image,
`/etc/direwolf/pip-ca.pem` (proposed path), which the operator provides and
the image manifest pins by digest. That file is pip's whole trust store if pip
behaves as documented — whether a pinned `--cert` also keeps pip from the
operating system's store (`truststore`) is measured in §9 — and a missing file
makes pip's TLS fail, closed. A package fetched over verified TLS is trusted
no further than its grant: TLS says where it came from, not what it does.

### 6. Under the shipped packs

`argv_safe` is unchanged: `pip install` stays R3, so the shipped packs keep
denying it, profile or not. pip is reached under the obligation only by an
operator policy that allows it explicitly — the evidence's labelled test
policy among them. Whether an accepted profile should make `pip install`
argv-safe in the shipped packs is open point P1; if it should, that is an
amendment of ADR-0045 §8 by its own decision, not by this ADR.

### 7. What it never claims

That a package is safe. With no build backend, an install copies files and
runs none of them; the first `python` that imports a package, runs one of its
console scripts, or makes its directory a site directory (so its `.pth`
files run) runs all of it — contained by the environment, as a `conftest.py`
is today. A `--target` directory is not a site directory unless the workload
makes it one. That an installed wheel is the one the index meant: without
hash-checking (P2) integrity is TLS and the grant, no more. That pip's own
code is checked file by file: it is the image's, pinned by its digest. That
`python -m pip` is covered (P3). And, as ADR-0052 §5a says, a shell or
interpreter an operator policy allows runs whatever its own code says.

### 8. Before acceptance

pip's behaviour today does not change (OD-E2): under the shipped packs it is
denied (§6), and under an operator policy without `argv_safe` it is kept with
nothing pip-specific — the residual this ADR exists to close, stated as such.
The evidence in §9 exercises the profile through the real authority, broker
and launcher behind the same evidence-only start-up option ADR-0054 §7
proposes for npm (`--allow-unaccepted-hygiene-profile pip`): logged `REDUCED
ASSURANCE`, refused without the evidence's other fixture options, fenced by an
architecture rule, removed by the change that implements acceptance.

### 9. The evidence acceptance requires

`make sandbox-registry-evidence`, a required hosted job, on a pinned pip whose
checksum is verified before use (OD-E4), built into an offline `FROM scratch`
image named by content with each tool's digest printed, against the plan's
hermetic fixtures: a granted PEP 503 index and an ungranted one, on loopback
behind the broker's evidence-only resolver, with certificates from a per-run
CA baked into the image at the trust path. Every case is required by name, at
its level, with what enforced it; locally NOT EXERCISED, never a pass. A fresh
environment and an empty target per case, and no cache, so a refusal cannot
be masked by a wheel fetched earlier.

| Case | Expected | Enforced by |
|---|---|---|
| `pip-install-granted-index-installs` | the named wheel installed under the target, its files those of the fixture wheel | the profile; pip |
| `pip-install-dependency-resolved-from-granted-index` | a wheel's dependency fetched from the same index | pip; the grant |
| `pip-ungranted-index-refused` | nothing installed, `CONNECT` refused | the proxy's decision |
| `pip-file-on-ungranted-host-refused` | nothing installed | the proxy's decision |
| `pip-redirect-to-ungranted-host-refused` | nothing installed | the proxy's decision |
| `pip-direct-route-refused` | no route but the proxy | the namespace's errno |
| `pip-sdist-never-built` | no marker from the fixture's build backend | the variable and the prefix |
| `pip-only-binary-cannot-be-undone-by-variable-or-file` | the sdist still not built with a `PIP_*` or file setting asking for it | precedence, measured |
| `pip-image-configuration-not-read` | an image `pip.conf` naming the ungranted index is not used | `PIP_CONFIG_FILE`, measured |
| `pip-untrusted-issuer-refused` | nothing installed | pip's own TLS verification |
| `pip-os-trust-store-not-used` | a certificate trusted only by the image's system store is refused | the pinned trust file, measured |
| `pip-missing-trust-file-fails-closed` | an image without the trust file installs nothing | pip's own TLS verification |
| `pip-undoing-arguments-refused` | each §3 argument refused before an intent | the authority |
| `pip-other-subcommands-refused` | `download`, `wheel`, `uninstall`, … refused | the authority |
| `pip-non-name-specs-refused` | a path, URL, archive, VCS or direct reference refused | the authority |
| `pip-no-cache-reused` | a second install of the same wheel fetches it again | the variable and the prefix; the proxy's counters |
| `pip-writes-only-workspace-and-tmp` | nothing changed outside `/workspace` and `/tmp` | the read-only root; measured |
| `pip-installed-pth-not-executed-by-install` | a fixture wheel's `.pth` marker absent after the install | pip; measured |
| `pip-refused-without-the-evidence-option` | today's behaviour with the option absent | the authority (§8) |
| `pip-shipped-packs-behaviour` | the shipped packs deny `pip install` (R3) | policy |
| `pip-plan-records-prefix-and-profile` | the recorded, hashed plan names the prefix | the authority's ledger |

A case that does not hold leaves pip as it is: this ADR is then revised or
withdrawn, never accepted with that case dropped.

### 10. Mutation review

Each guard weakened in turn — the subcommand allowlist, the spec filter, each
§3 refusal, each added variable, the prefix, the §8 fence — must fail a unit
suite or the hosted evidence. Unit-killable mutants run locally; the rest run
in the hosted campaign the owner triggers, and are never reported as local
kills (OD-E7).

### 11. ADR-0000: no second path

pip runs as the run's workload, decided by the authority like any
`process.exec` and recorded before the broker is told. Its only network is
the proxy that already serves the run's grants; the kernel performs nothing
new for it. No DWKP operation, protocol version, schema, refusal reason or
dependency is added.

### 12. Open points, for the owner at acceptance

| # | Question | Recommendation |
|---|---|---|
| P1 | Should an accepted profile make `pip install` argv-safe in the shipped packs (an amendment of ADR-0045 §8's R3)? | No, not with this ADR: the shipped packs keep denying it; an operator allows pip explicitly. Revisit with its own decision once §9 has held. |
| P2 | Requirements and constraints files, `--find-links` and hash-checking mode | Refused in this profile. A later revision may allow `-r` with `--require-hashes` only, once §9-style cases show what a file's own options can do against the pins. |
| P3 | `python -m pip` | Refuse `-m pip` and `-m ensurepip` under the obligation when this profile is accepted, so the interpreter is not a way around it; until then it is R1's and ADR-0052 §5a's. |
| P4 | The trust file's path and whether npm and pip share one | Separate files (`npm-ca.pem`, `pip-ca.pem`), so an operator can trust a private index for one tool without the other. |

## Consequences

**Positive.** M5's pip scenario gets a profile with the same shape as npm's —
the same launcher, ledger, proxy and evidence — and the residual of today (a
`pip` kept with nothing pip-specific under an operator policy) has a named end.
Every refusal is a pure function of the identity and the arguments.

**Negative.** A package published only as a source distribution cannot be
installed, nor can a local project, an editable or a VCS dependency.
Requirements files are refused at first, which most projects use. Six more
fixed variables in every hygiene launch, with the launcher's measured variable
set changing again. An operator must ship pip's trust file in the image. pip's
documented precedence and binary-only semantics are relied on only as far as
§9 measures them, on the pinned version; a later pip needs the evidence again.

## Alternatives considered

- **Fail pip closed now**, like npm. Rejected for this ADR: it changes
  production behaviour before any evidence, and the owner decided (OD-E2) that
  pip's behaviour stays as it is until a profile is accepted.
- **Fold pip into ADR-0054.** Rejected by the owner (OD-E2): ADR-0054 stays
  npm-only.
- **Allow source distributions with build isolation.** Rejected: isolation
  separates build dependencies, not the build's code from the environment —
  the backend still runs.
- **`--isolated` as the pin.** Rejected: it drops the launcher's variables
  along with whatever it is meant to drop.
- **Trust the runner's or the image's system store.** Rejected: the workload
  could not choose a CA, but neither would the operator, explicitly.
- **`uv pip` or a kernel-side index client.** Rejected for M5e: another tool
  to evidence, or a package protocol inside the kernel.

## Revisit if

A case in §9 fails on a newer pip; pip changes its precedence, its
binary-only semantics or its default trust store; P1 or P2 is decided towards
allowing more; a build backend is found to run with `--only-binary=:all:`; or
hash-checked requirements become necessary — each by its own evidence and
decision.
