# ADR-0074: F-16 -- the broker resolves the name the authority decided and no other: an absolute query, a bounded answer, nothing cached

**Status:** Proposed · **Date:** 2026-11-20 (designed, built and tested locally 2026-11-20 for finding F-16; hosted: NOT EXERCISED on CI #201 (run 44818094052, `3998de2`), no unprivileged namespaces on the runner, recorded in [PRE_M6_REMEDIATION.md](../PRE_M6_REMEDIATION.md); nothing here is accepted) · **Builds on:** [ADR-0048](0048-m5b-proxy-only-topology-and-connect-proxy.md) (the broker resolves, once per tunnel), [ADR-0050](0050-m5c-kernel-performed-net-http-ssrf-redirects-and-credential-egress.md) (once per hop, pinned), [ADR-0073](0073-f06-of2-the-operators-egress-allowlist-is-a-ceiling-every-policy-is-under.md) (the destination decided exactly) · **Leaves unchanged:** DWKP, the private broker protocol, the address guard, pinning, the fixture resolver the evidence uses, and every decision

> **The broker asks the host's resolver for exactly the name the authority
> decided.** The query is the name made absolute -- a trailing dot -- so no
> search domain is appended to it and glibc's `/etc/hosts` lookup does not
> answer for it; a name that does not exist is refused, never quietly
> resolved as another. An answer of more than 64 addresses is refused
> whole. Nothing is cached, and no DNSSEC guarantee is claimed.

## Context

Finding F-16, from the security review of 2026-11-11/12, reads "the resolver
honours `/etc/hosts` and search domains". The repository held no other text
for it; it is scoped here to what was verified in the code and on a real
resolver.

The broker has one production resolver, `SystemResolver`
(`crates/dwkd-broker/src/egress/resolve.rs`), used by the CONNECT proxy's
tunnels and by `net.http`'s hops. It resolved `(name, 0).to_socket_addrs()`:
glibc's `getaddrinfo`, through the host's name service switch. Run under a
hostile configuration in namespaces of a test's own (`search evil.test`,
`hosts: files dns`, an `/etc/hosts` entry, a DNS responder on the
namespace's loopback), a relative lookup of `pypi.org` -- a name that does
not exist there -- asked the DNS server for `pypi.org`, then for
`pypi.org.evil.test`, and returned that name's address; `victim.test` was
answered from `/etc/hosts`. The name the authority decided is not the name
whose address the guard then judged.

## Decision

1. **An absolute query.** `SystemResolver` asks for `"<name>."`. glibc treats
   a name ending in a dot as absolute: no search domain, whatever
   `resolv.conf`, `LOCALDOMAIN` or `RES_OPTIONS` say; and its `/etc/hosts`
   module, which compares names as written, finds no entry. The decided name
   is still a canonical host (an address literal or anything else is refused
   first, as before).
2. **A bounded answer.** More than `MAX_ANSWER_ADDRESSES` (64) distinct
   addresses is `RESOLUTION_FAILED`: the answer is refused whole, never cut
   to the part the guard happened to see. The guard judges every address of
   an answer it receives, as before.
3. **Nothing else changes.** One resolution per tunnel or hop, under the
   caller's deadline (a silent resolver is abandoned: `RESOLUTION_TIMEOUT`);
   at most 32 resolutions in flight; no cache, so no answer outlives the hop
   or tunnel that asked; the address guard and pinning as ADR-0048 and
   ADR-0050 build them. Nothing in the sandbox resolves anything.

## Consequences

- A destination that does not exist under its own name is refused; it can no
  longer be reached as a search domain's name.
- An operator's `/etc/hosts` override no longer redirects the broker's
  lookups on a glibc host using its `files` module.

## Residuals

- **A local stub resolver.** Where `resolv.conf` points at a local stub
  (systemd-resolved on `127.0.0.53`), the stub may answer from its own
  `/etc/hosts` records and resolves through its own upstream: both are the
  host's configuration, not changed or verified here.
- **No DNSSEC.** DireWolf validates no signature; an upstream that lies is
  bounded by the guard (no private, loopback, link-local, metadata or
  mapped address passes) and by pinning, not by authentication of the
  answer.
- **Other name services.** An `nsswitch.conf` naming services beyond `files`
  and `dns` (mDNS, LDAP) is the host's; the absolute query does not bypass
  them.
- Rebinding stays ADR-0048's and ADR-0050's: one resolution per hop or
  tunnel, pinned, so a second answer is never consulted.

## Alternatives considered

- **A DNS client of the broker's own.** Would bypass the name service switch
  entirely, at the cost of a new protocol implementation in the trusted
  computing base, its own configuration and its own upstream choice. Not
  now; revisit if the stub-resolver residual matters to a deployment.
- **Stripping search domains by environment** (`LOCALDOMAIN=`,
  `RES_OPTIONS=ndots:0` in the broker's environment). Refused: it depends on
  the daemon's start-up environment, and glibc reads the file's `search`
  line when the variable is empty.

## Owner decisions

- **OR-1** accept this ADR;
- **OR-2** whether a deployment using a local stub resolver should be
  reported in the broker's effective posture (F-03), since its `/etc/hosts`
  records still answer.

## Evidence

- `crates/dwkd-broker/src/egress/tests.rs`
  (`f16_the_resolver_asks_for_the_decided_name_and_no_other`): the real
  glibc resolver under the hostile configuration in unprivileged user, mount
  and network namespaces (`peer/harness.rs` starts them; no shell): a
  relative lookup lands on the search domain's and the hosts file's
  addresses, the broker's is refused; NXDOMAIN fails; 65 addresses are
  refused whole and three are kept whole; a silent server times out at the
  deadline. NOT EXERCISED where unprivileged namespaces are not available.
- `make resolver-mutations`: the name asked relative (R1), an answer past the
  bound kept (R2), a silent resolver waited for (R3) -- each killed by that
  test.
- `tests/architecture/test_f16_resolver.py`: the absolute query, the bound,
  one production resolver, the review's table.
- Hosted, CI #201 (run 44818094052, `3998de2`): the test ran in the broker's unit run and passed
  as NOT EXERCISED ("unprivileged user, mount and network namespaces are
  not available here"): the hosted runner restricts them, and only the
  `sandbox-egress` job lifts the restriction, for F-04's case alone. The
  property is shown locally, not by a hosted run.

## Rollback and deployment

Reverting restores the relative query. Nothing is stored or migrated; a
deployment whose operator relied on `/etc/hosts` to redirect a destination
names the destination itself instead.

## Revisit if

The broker gains a resolver of its own, a cache, or a second production
resolver; or OR-2 is decided.
