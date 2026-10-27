# ADR-0054: M5e — an evidence-backed npm profile for `workspace_exec_hygiene`: `npm ci` and `npm install` of registry packages with scripts off and configuration pinned, everything else still refused

**Status:** Proposed (its open points decided by the owner on 2026-10-26, [plan](../M5E_ASSURANCE_PLAN.md) §10; not accepted) · **Date:** 2026-10-26 · **Would amend (on acceptance):** [ADR-0052](0052-m5d-sandboxed-process-exec.md) §5a (`npm` leaves the tools the obligation refuses as unevidenced, for this profile only; `npx`, `pnpm`, `yarn`, `bun`, `cargo`, a `cargo-*` binary, `rustup`, `corepack`, and a runner naming any of them stay refused) · **Refines:** [ADR-0048](0048-m5b-proxy-only-topology-and-connect-proxy.md) (a package registry is one more exact `network.https` grant through the proxy), [SANDBOX.md](../SANDBOX.md) §4a · **Addresses:** [ADR-0000](0000-authority-plane-separation.md) (no second path, §10) · **Plan:** [M5E_ASSURANCE_PLAN.md](../M5E_ASSURANCE_PLAN.md)

> **npm runs in an environment only as `npm ci` or `npm install` of registry
> packages, with lifecycle scripts off and its configuration pinned by the
> trusted launcher; anything that would undo that is refused before an
> intent is recorded; and none of it is enabled in production until the
> evidence in §8 has passed in hosted CI and the owner accepts this ADR.**

## Context

M5's contract requires a real `npm install` that succeeds against an
allowlisted registry and fails against a non-allowlisted one
([ROADMAP.md](../ROADMAP.md), the M5 contract and M5e). Today npm cannot run
under the shipped packs at all: they allow sandboxed `process.exec` only with
`workspace_exec_hygiene`, and ADR-0052 §5a — accepted, with OD-11's condition
that npm and Cargo stay fail-closed until real-tool evidence exists — refuses
`npm`, `npx`, `pnpm`, `yarn`, `bun` and `cargo` as `HYGIENE_NOT_EVIDENCED`
(`crates/dwkd-authority/src/resource/exec/hygiene.rs`). The launcher already
sets `npm_config_ignore_scripts=true` for every hygiene launch
(`dwk_sandbox_profile::HYGIENE_ENVIRONMENT`), but no evidence shows what it
does to a real npm, so the refusal stands. Lifting it changes an accepted
decision, which is this ADR's job.

What npm can do with a workspace an agent can write — each a claim this ADR
makes **only** once a case in §8 shows it:

- **Lifecycle scripts.** `preinstall`, `install`, `postinstall` and `prepare`,
  of the workspace's own package and of every dependency, run during an
  install unless scripts are ignored. A dependency fetched from git is
  prepared — its own install and `prepare` — before it is packed.
- **Configuration from several places.** npm documents its precedence as the
  command line, then `npm_config_*` variables, then the project's `.npmrc`,
  then the user and global files, then built-in defaults. The project's
  `.npmrc` is workspace content.
- **Subcommands that run scripts whatever the configuration says**: `run`,
  `test`, `start`, `stop`, `restart`, and `exec` (which `npx` is).
- **Dependencies from elsewhere**: git URLs, remote tarball URLs, `file:` and
  `link:` paths, and aliases (`npm:`), named in arguments or in the
  workspace's `package.json` and lockfile.
- **TLS** with its own trust store, which configuration can replace
  (`cafile`, `ca`) or switch off (`strict-ssl=false`).
- **Integrity**: `npm ci` requires a lockfile and checks each tarball against
  its recorded `integrity`.
- **Writes outside the workspace**: a global install, a prefix, a cache.

What already bounds a workload, whatever it runs (ADR-0052, ADR-0048): uid
10001, no capability, a read-only root, `HOME=/` read-only, `/tmp` its own
bounded `tmpfs`, the limits, `reap`, and in `PROXY_ONLY` exactly the run's
`network.https` grants through the broker's proxy — nothing else is routable.

## Decision

### 1. Scope

The profile applies only to an executable whose identity's last component is
`npm`, named in the operator's image manifest and proved by digest before
every workload like any other. Its interpreter and package tree are the
image's, pinned by the image digest, as pytest's are today. Every other tool
ADR-0052 §5a refuses as unevidenced stays refused, `npx` among them.

Only two subcommands are kept, by their canonical words: **`ci`** and
**`install`**. Any other first non-option argument — an alias, `run`,
`test`, `start`, `exec`, `rebuild`, `publish`, `config`, anything — is
`OBLIGATION_UNENFORCEABLE` (`HYGIENE_NOT_EVIDENCED`). `install`'s package
arguments are **registry names only**: `name`, `@scope/name`, each optionally
`@` an exact version, range or dist-tag. An argument that is a URL, a path,
a tarball, a git or hosting shorthand (`github:`, `user/repo`), `file:`,
`link:` or an alias (`npm:`) is refused, as is any `--` separator.

### 2. How it is kept

**By the launcher**, for every hygiene launch, the profile's fixed variables
— `npm_config_ignore_scripts=true` as today, and, added by this ADR:
`npm_config_userconfig=/dev/null`, `npm_config_globalconfig=/dev/null`,
`npm_config_strict_ssl=true`, `npm_config_update_notifier=false`,
`npm_config_audit=false`, `npm_config_fund=false`,
`npm_config_cache=/tmp/.npm` (the only writable place outside the workspace)
and `npm_config_cafile=/etc/direwolf/npm-ca.pem` (§4).
None comes from the caller, none is spelled on the runtime's command line,
and each is a reserved name a mode B secret may not take (ADR-0052 §7).

**By the authority**, the arguments it puts before the invocation's own and
records in the plan it hashes: `--ignore-scripts`, `--strict-ssl`,
`--no-audit`, `--no-fund`, `--no-update-notifier`. With both, a setting the
workspace's `.npmrc` makes is outranked twice, if npm's precedence is as
documented; §8 measures it rather than assumes it.

### 3. What would undo it is refused

Before any intent, `OBLIGATION_UNENFORCEABLE` (`HYGIENE_OVERRIDDEN_BY_ARGV`)
for an invocation whose own arguments include any of: `--ignore-scripts=false`
or `--no-ignore-scripts`; `--userconfig` or `--globalconfig`;
`--strict-ssl=false` or `--no-strict-ssl`; `-g`, `--global`, `--location`,
or `--prefix`; `--script-shell` or `--node-options`; `--foreground-scripts`;
`--cafile` or `--ca` (§4).
Each sets something the profile pins, or writes outside the workspace and
`/tmp`, or matters only to a script the profile keeps from running — refused
either way. `--registry` and a scoped `--@scope:registry` are allowed (§4).

### 4. Destinations and TLS

The profile names no registry and rewrites none. Where npm may connect is the
run's exact `network.https` grants, enforced by the proxy (ADR-0048): a
registry, a tarball host or a redirect target that is not granted is refused
at `CONNECT`, attributed to the proxy's decision, whatever the workspace's
`.npmrc`, `package.json` or lockfile names. A plain-HTTP registry is not
reachable at all. TLS is end to end through the opaque tunnel and npm's own,
and **the workload does not choose whom npm trusts** (the owner's decision
OD-E6, 2026-10-26): the profile pins verification on and refuses turning it
off; it refuses `--cafile` and `--ca`; and the launcher points npm at one trust
file in the image, `/etc/direwolf/npm-ca.pem` (proposed path), which the operator
provides and the image manifest pins by digest. As npm documents it, that file
is npm's whole trust store — an operator using the public registry puts public
roots in it, one using a private registry its own CA — and a missing file makes
npm's TLS fail, closed. The evidence bakes its per-run CA into the CI-built
image at that path, and §8 measures that a workspace `.npmrc` naming a CA takes
no effect.

### 5. Integrity

`npm ci` checks each tarball against the lockfile's `integrity`; a mismatch
installs nothing (§8). `npm install` without a lockfile installs what a
granted registry serves: the registry is trusted as far as its grant, and no
further.

### 6. What it never claims

That package code is safe. With scripts off, an install runs none of it; the
first `node` or test runner that loads a package runs all of it, contained
by the environment — as a `conftest.py` is today. That the workspace's own
`package.json`, lockfile and `.npmrc` are not read: they are, and every key
the profile does not pin keeps its effect within the environment and the
grants. That a native addon builds: with scripts off it does not, and such a
package does not work. That npm's own code is checked file by file: it is the
image's, pinned by its digest. And, as ADR-0052 §5a says, a shell or
interpreter an operator policy allows runs whatever its own code says.

### 7. Before acceptance: fail-closed is kept

Until this ADR is accepted, `npm` stays `HYGIENE_NOT_EVIDENCED` in every
production build and configuration. The evidence in §8 must still exercise
the real authority, broker and launcher, so the implementation adds the
profile behind an **evidence-only** start-up option of `dwkd-authority
serve` — proposed `--allow-unaccepted-hygiene-profile npm` — on the pattern
of the broker's `--allow-evidence-egress` and the authority's
`--allow-unverified-workspace`: logged `REDUCED ASSURANCE` at start, refused
unless the evidence's other fixture options are present, named in no shipped
configuration, and fenced by an architecture rule that only the evidence
harness may pass it. Without the option, nothing changes. The change that
implements this ADR's acceptance removes the option and moves `npm` out of
`UNEVIDENCED`. The owner chose this fence on 2026-10-26 (plan OD-E3).

### 8. The evidence acceptance requires

`make sandbox-registry-evidence`, a required hosted job, on a pinned npm whose
checksum is verified before use (plan OD-E4), built into an offline
`FROM scratch` image named by content with each tool's digest printed, against
the plan's hermetic fixtures (plan §7): a granted registry and an ungranted
one, both on loopback behind the broker's evidence-only resolver, with
certificates from a per-run CA baked into the image at the trust path (§4). Every case is
required by name, at its level, with what enforced it. Locally it is NOT
EXERCISED, never a pass.

| Case | Expected | Enforced by |
|---|---|---|
| `npm-ci-granted-registry-installs` | the lockfile's packages installed in the workspace | the profile; npm |
| `npm-install-granted-registry-installs` | a named registry package installed | the profile; npm |
| `npm-ungranted-registry-refused` | nothing installed, `CONNECT` refused | the proxy's decision |
| `npm-tarball-on-ungranted-host-refused` | nothing installed | the proxy's decision |
| `npm-redirect-to-ungranted-host-refused` | nothing installed | the proxy's decision |
| `npm-direct-route-refused` | no route but the proxy | the namespace's errno |
| `npm-lifecycle-scripts-not-run` | no marker from any of the root's or a dependency's four scripts | the launcher's variable and the authority's prefix |
| `npm-project-npmrc-cannot-reenable-scripts` | no marker with the workspace `.npmrc` asking for scripts | precedence, measured |
| `npm-project-npmrc-cannot-disable-tls` | the untrusted issuer still refused | precedence, measured |
| `npm-project-npmrc-cannot-replace-ca` | a workspace `.npmrc` naming its own CA leaves the image's trust file in force | precedence, measured |
| `npm-missing-trust-file-fails-closed` | an image without the trust file installs nothing | npm's own TLS verification |
| `npm-git-dependency-not-prepared` | no git fetch and no `prepare` marker | the proxy's decision; the variable |
| `npm-untrusted-issuer-refused` | nothing installed | npm's own TLS verification |
| `npm-tampered-tarball-refused` | `EINTEGRITY`, nothing installed | npm's integrity check |
| `npm-writes-only-workspace-and-tmp` | nothing changed outside `/workspace` and `/tmp` | the read-only root; measured |
| `npm-undoing-arguments-refused` | each §3 argument refused before an intent | the authority |
| `npm-other-subcommands-refused` | `run`, `test`, `exec`, an alias, … refused | the authority |
| `npm-non-registry-specs-refused` | each §1 spec form refused | the authority |
| `npx-still-refused` | `HYGIENE_NOT_EVIDENCED` | the authority |
| `npm-refused-without-the-evidence-option` | `HYGIENE_NOT_EVIDENCED` with the option absent | the authority (§7) |
| `npm-shipped-packs-behaviour` | what the shipped `balanced` and `power` packs decide for `npm ci` | policy |
| `npm-plan-records-prefix-and-profile` | the recorded, hashed plan names the prefix | the authority's ledger |

A case that does not hold leaves npm fail-closed: this ADR is then revised,
or withdrawn, never accepted with that case dropped.

### 9. Mutation review

`make sandbox-registry-mutations` weakens each guard in turn — the subcommand
allowlist, the spec filter, each refusal of §3, each added variable, the
prefix, `npx`'s refusal, the §7 fence — and each must fail a unit suite or
the hosted evidence. A mutant only the hosted evidence can kill is reported
as such from a hosted run the owner triggers by hand, never counted as killed
locally (plan OD-E7).

### 10. ADR-0000: no second path

npm runs as the run's workload, decided by the authority like any
`process.exec` — capability, policy for a *sandbox* action, the obligation,
the measured environment, the pinned executable, the budget — and recorded
before the broker is told. Its only network is the proxy that already serves
the run's grants; the kernel performs nothing new on its behalf. No DWKP
operation, protocol version, schema, refusal reason or dependency is added.

## Consequences

**Positive.** M5's npm scenario becomes possible under the shipped packs'
obligation, on the same launcher, ledger and proxy as every other workload,
and only after real-tool evidence — which is what ADR-0052 §5a asked for. The
profile's refusals are pure functions of the identity and the arguments, as
the obligation's are today.

**Negative.** A package that needs its install scripts or a native build does
not work. Eight more fixed variables in every hygiene launch: the launcher's
measured variable set changes, and with it ADR-0052's evidence
(`hygiene-launcher-adds-exactly-its-variables`). An operator must ship npm's
trust file in the image — public roots for the public registry, its own CA
for a private one — or npm connects nowhere. The evidence-only option is one more start-up switch to fence until
acceptance removes it. npm's documented precedence is relied on only as far
as §8 measures it, on the pinned version; a later npm needs the
evidence again.

## Alternatives considered

- **Keep npm refused and meet M5 with pip alone.** Rejected: the contract
  names npm, and the owner directed this profile.
- **Run npm without the obligation**, under an operator policy that does not
  ask for it. Rejected: lifecycle scripts run, and the shipped packs could not
  use it.
- **A wrapper script in the image** that sets npm's flags. Rejected: another
  file to pin, the same arguments to police, and the trusted launcher already
  exists for this.
- **`npm ci` only.** Narrower, and a lockfile pins every tarball; but the
  contract says `npm install`, so `install` of registry names is kept with the
  spec filter (the owner's decision OD-E5: both count).
- **A CA file the invocation names** (`--cafile`, `--ca`), for private
  registries. Rejected by the owner (OD-E6): the workload would choose whom
  npm trusts; the operator's trust file in the image serves private
  registries instead.
- **A kernel-side registry client** that fetches packages for the workload, as
  `net.http` does for the kernel. Rejected for M5e: the kernel would parse a
  package protocol, a far larger surface than an exact grant through the
  proxy.

## Revisit if

A case in §8 fails on a newer npm; npm changes its configuration precedence
or what `ignore-scripts` covers; a dependency form is found to run code with
scripts off; a kernel-mediated package fetch becomes worth its surface; or
`pnpm`, `yarn` or `cargo` is needed — each by its own evidence and decision.
