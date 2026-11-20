# ADR-0071: F-06 -- an operator egress allowlist, which every shipped network rule requires: no pack reaches a destination the operator did not name by host, port and path

**Status:** Proposed · **Date:** 2026-11-17 (designed, built and reviewed locally 2026-11-17 for finding F-06; hosted evidence observed on CI #198 (run 44706359028, `3584f3e`, 2026-11-20); OF-1 approved as implemented, OF-2 authorised and built as [ADR-0073](0073-f06-of2-the-operators-egress-allowlist-is-a-ceiling-every-policy-is-under.md), OF-3 partially decided, 2026-11-20; the ADR is not accepted) · **Changes:** the shipped packs' network rules (BALANCED `allow-package-registries`, POWER `allow-https-egress`), POLICY.md's predicate table, one `serve` flag · **Builds on:** [ADR-0048](0048-m5b-proxy-only-topology-and-connect-proxy.md), [ADR-0050](0050-m5c-kernel-performed-net-http-ssrf-redirects-and-credential-egress.md), [ADR-0060](0060-a-constrained-network-grant-gives-no-proxy-only-destination.md), [ADR-0061](0061-workload-egress-decided-by-policy-novelty-and-exposure.md), [ADR-0062](0062-taint-follows-delivered-content.md) · **Leaves unchanged:** DWKP, the private broker protocol, the store's schema, the address guard, DNS pinning, SNI agreement, every budget, and every operator policy file

> **Every shipped network rule now also requires `destination_allowlisted`**,
> a canonical input the authority computes from one operator file
> (`--egress-allowlist`) and nothing else: true exactly when an entry names
> the action's host, its port and its path (`net_http`, a kernel-performed
> hop; `workload`, a sandboxed workload's tunnel). Without the file a shipped
> pack reaches no destination at all. The allowlist only narrows: it is one
> more condition on a rule, never a rule; a run still needs its capability,
> taint and novelty still decide first, and the address guard still refuses
> every private address the allowlist names.

## Context

**The finding (F-06).** BALANCED's `allow-package-registries` admits
`github.com`, `*.github.com`, `*.pypi.org`, `crates.io`, `*.crates.io`,
`registry.npmjs.org` and `proxy.golang.org`, and POWER's `allow-https-egress`
admits any HTTPS destination. Every one of those registries takes uploads as
well as downloads -- `uploads.github.com`, a gist, `upload.pypi.org`, a crate
or package publish -- and a workload's tunnel is opaque (ADR-0048 §18): no
method or path can be kept on it. A run holding `network.https:github.com:443`
under BALANCED could therefore send workspace content to an account an
attacker controls, bounded only by the environment's byte budget (THREAT_MODEL
R12, "exfiltration through an allowed destination remains possible"). The
default was the problem: a deployment got upload-capable destinations it never
chose.

**What already exists, and is kept.** Exact network capability grants (a
wildcard or constrained grant gives a tunnel nothing, ADR-0060); policy
decisions for every `net.http` hop and every workload launch (ADR-0050,
ADR-0061); taint raised by delivered content (ADR-0062) and novelty, which
send a tainted run's new destination to an approval no build has; the CONNECT
proxy's exact-destination, SNI and one-resolution checks; the address guard
over the whole answer, judged by the broker and again by the authority; byte
and request budgets.

## Decision

### 1. One operator file

`dwkd-authority serve --egress-allowlist <ABSOLUTE PATH>`, read as every
operator file is (root- or authority-owned, writable by nobody else, no
symlink, at most 64 KiB) and parsed strictly:

```toml
schema_version = 1

[[destination]]
name    = "npm-registry"            # lower-kebab, unique: removing it revokes it
host    = "registry.npmjs.org"      # exact, canonical
port    = 443                       # required: no port is implied
scope   = ["workload"]              # net_http, workload, or both
purpose = "npm ci in a sandboxed workload"
```

A host is the capability grammar's exact host: lowercase ASCII labels, no
trailing dot, at least two labels, not a number, no wildcard, scheme, port,
path or userinfo; an internationalised name is written in its `xn--` form and
compared as written. An unknown member, a missing one, a repeated name or a
repeated host and port, more than 256 entries, or anything outside the grammar
refuses the file, and the authority does not start. The start says what it
read: `egress allowlist <path>: N destination(s): <names>`, or `egress
allowlist: none`.

### 2. A canonical input and a predicate

For every `network.https` action the authority builds -- each `net.http` hop
(`net_http`) and each destination of a workload's launch (`workload`) -- it
sets `destination_allowlisted` from the file. A rule may require it
(`when.destination_allowlisted = true`, scalar, network verbs only); an action
built without it never matches. No DWKP message, private-protocol field or
runtime input carries it, so no run can supply or widen it.

### 3. The shipped packs require it

| pack | rule | before | after |
|---|---|---|---|
| SAFE | -- | no network | no network |
| BALANCED | `allow-package-registries` | the seven registry patterns | the seven patterns **and** an allowlist entry |
| POWER | `allow-https-egress` | any HTTPS (private ranges denied first) | any allowlist entry (private ranges denied first) |

Without the file both rules match nothing and the pack's `default` denies
(`DEFAULT_DENY`, `rule_id default`, its real source line). BALANCED's list
stays the ceiling: an operator who names `example.com` does not reach it
through BALANCED.

### 4. Every layer still decides

A destination is reached only when all of these hold, none widening another:
the run's exact grant; the pack's (or the operator's) rules, the taint and
novelty rules first; the allowlist entry for that host, port and path; the
address guard (the allowlist has no CIDR and waives nothing); the resolution
pinned once; the CONNECT and SNI agreement; and every budget. A redirect is a
new hop decided from the start, so its destination needs its own entry.

### 5. Operator policies

A policy file of the operator's own is unchanged: it may require the
predicate, and a rule that does not is the operator's explicit decision, as
before. Whether the allowlist should become a gate on every policy is left to
the owner (OF-2).

**Since 2026-11-20** OF-2 is decided and built: the allowlist is a ceiling
every policy is under, an operator's own among them -- see
[ADR-0073](0073-f06-of2-the-operators-egress-allowlist-is-a-ceiling-every-policy-is-under.md) (Proposed), which
would amend this section.

### 6. Revocation and staleness

Removing an entry and restarting revokes it for every `net.http` hop decided
after the restart. A workload already launched keeps the decision it was
launched with until it ends (ADR-0061's authorisation lives exactly as long as
its workload); a restart reaps every run, so none outlives it. When a file is
configured, F-17's recorded context digest includes it.

### 7. Package managers

Each hop a package manager makes must be named. `npm ci` against the public
registry needs `registry.npmjs.org:443` (metadata and tarballs) for
`workload`. `pip install` needs `pypi.org:443` and `files.pythonhosted.org:443`
-- and BALANCED's pattern list does not name `files.pythonhosted.org`, so
under BALANCED pip's downloads stay denied, as they were; a deployment that
needs them uses an operator policy. A redirect to a CDN host is a new
destination: named, or denied. Nothing is allowlisted by default.

## Consequences

- No shipped pack reaches a destination until the operator names it, and an
  upload-capable host is reachable only where the operator chose it.
- **Compatibility:** a deployment that runs BALANCED or POWER with network
  grants and no `--egress-allowlist` loses its network until it adds one.
  This is the intended change; the start says `egress allowlist: none`.
- DWKP, the private protocol, the store and every operator policy are
  unchanged.

## Not built

- Per-entry quotas (each run's and environment's budgets apply as before).
- Wildcard or suffix entries (refused; an entry is one host).
- A method or path restriction on a tunnel (opaque; `net.http` keeps `methods=`
  on its grants).
- A `model_download` path for the model manager (ADR-0072 proposes it).

## Residuals

- An allowlisted upload-capable host is still an exfiltration route for a run
  that may reach it, bounded by its budgets: now the operator's explicit
  choice, not a default.
- Domain fronting through an allowlisted shared host (R12) is unchanged.
- The file is per deployment, not per workspace or run.
- That `--egress-allowlist` reaches the serving authority's decisions is held
  by review and the start-up line, not by a mutant: no serve-level test makes
  a decision through the real binary without a broker.

## Alternatives considered

- **Narrow the packs to "download-only" hosts.** No such host: the npm
  registry serves publishes on the same name, and a tunnel cannot tell.
- **A gate on every policy, absent file = no network.** Stronger, but it
  changes every operator policy and every evidence suite at once; recorded as
  OF-2.
- **A new DWKP reason.** Not needed: the decision already names the rule that
  denied and its source line.

## Owner decisions

- **OF-1** accept the shipped packs' change and its compatibility consequence;
- **OF-2** whether the allowlist should also gate operator policies;
- **OF-3** per-entry quotas, and the `model_download` path (ADR-0072).

**Decided 2026-11-20.** The status stays **Proposed**.

- **OF-1 -- approved as implemented.** BALANCED's and POWER's network
  rules stay constrained by the operator's allowlist, with the
  compatibility change above.
- **OF-2 -- implementation authorised**, and built as
  [ADR-0073](0073-f06-of2-the-operators-egress-allowlist-is-a-ceiling-every-policy-is-under.md) (Proposed): the ceiling
  applies to every policy, enforced by the authority, never left to a
  policy author's predicate.
- **OF-3 -- partially decided.** A future `model_download` path gets its
  own separately authorised egress; per-entry quotas are evaluated on their
  own. Neither is built, and no direct downloader exists.

## Evidence

- `crates/dwkd-authority/src/state/egress_allowlist_tests.rs`: the grammar -- exact,
  canonical, named, bounded -- and what an entry covers.
- `crates/dwkd-authority/src/policy/fixtures.rs`: BALANCED and POWER grant
  nothing without the input and only with it; the private ranges, taint and
  plaintext still decide first.
- `crates/dwkd-authority/src/state/net_http/tests.rs` and
  `workload_route_tests.rs`: a hop and a launch, in process, each by its own
  path's entries.
- `crates/dwkd-authority/tests/net_http_evidence.rs`
  (`make net-http-evidence`): the real broker and real origins -- absent,
  other path, other port and neighbour denied, exact performed once, a
  cross-origin hop denied, a private answer still blocked.
- `crates/dwkd-authority/tests/transport_server.rs`: the real binary reads,
  says and refuses the file.
- `make egress-allowlist-mutations`: thirteen guards weakened in turn, each
  killed by a named test (nineteen since ADR-0073).
- CI #198 (run 44706359028, `3584f3e`, 2026-11-20): the hosted `net.http` job reported
  186 cases, the seven `egress-allowlist-*` among them.
- `tests/architecture/test_f06_egress_allowlist.py`.

## Rollback and deployment

Reverting restores the packs' rules and removes the flag and the predicate;
nothing is stored or migrated. Deploying it means writing the allowlist
before the restart that loads it.

## Revisit if

A pack gains a network rule; a tunnel gains a way to see methods; the model
manager's download path is built; or the owner decides OF-2.
