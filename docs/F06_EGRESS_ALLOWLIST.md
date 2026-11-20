# F-06: the operator's egress allowlist

Decision records: [ADR-0071](adr/0071-f06-an-operator-egress-allowlist-every-shipped-network-rule-requires.md)
(Proposed; OF-1 approved as implemented 2026-11-20) and, for the ceiling
every policy is under, [ADR-0073](adr/0073-f06-of2-the-operators-egress-allowlist-is-a-ceiling-every-policy-is-under.md)
(Proposed; OF-2). This page is the implementation's: what changed, how to
configure it, and the evidence for each adversarial case. Hosted: the
`net.http` job of CI #198 (run 44706359028, `3584f3e`, 2026-11-20) reported
every `egress-allowlist-*` case.

## 1. The finding and the change

The shipped packs' network rules granted upload-capable destinations by
default: BALANCED every host of seven registry patterns, POWER any HTTPS
destination. A workload's tunnel is opaque, so a pack cannot tell a download
from a publish. Since F-06 both rules also require `destination_allowlisted`,
which the authority computes from the operator's `--egress-allowlist` file
and nothing else; without the file no shipped pack reaches any destination.

| | before | after |
|---|---|---|
| BALANCED, no file | the registry patterns | nothing (`DEFAULT_DENY`, `default`) |
| BALANCED, file names `registry.npmjs.org:443` for `workload` | the registry patterns | that destination, for workloads |
| POWER, no file | any public HTTPS | nothing |
| POWER, file | any public HTTPS | the named destinations, each for its path |
| an operator policy file | as written | as written, under the ceiling since OF-2 (§6): only named destinations |

## 2. Configuring it

```toml
schema_version = 1

[[destination]]
name    = "npm-registry"
host    = "registry.npmjs.org"
port    = 443
scope   = ["workload"]
purpose = "npm ci in a sandboxed workload"

[[destination]]
name    = "pypi-index"
host    = "pypi.org"
port    = 443
scope   = ["workload"]
purpose = "pip's index (BALANCED does not name files.pythonhosted.org: use an operator policy for pip downloads)"
```

`dwkd-authority serve … --egress-allowlist /etc/direwolf/egress.toml`. The
file must be owned by root or the authority's uid and writable by nobody
else. Every hop is its own destination: a redirect to a CDN host needs its
own entry, or it is denied. `scope` says which path may use the entry:
`net_http` (a kernel-performed request) or `workload` (a sandboxed workload's
CONNECT tunnel).

## 3. Adversarial matrix

| # | case | outcome | evidence |
|---|---|---|---|
| 1 | empty allowlist | covers nothing; a pack denies | `egress_allowlist_tests` (`no_file_and_an_empty_file_cover_nothing`); bench `egress-allowlist-absent-denies` |
| 2 | no allowlist | as empty; the start says `none` | `fixtures` (`no_shipped_pack_reaches…`); `transport_server` |
| 3 | malformed allowlist | the authority does not start | `egress_allowlist_tests`; `transport_server` (unknown member, wildcard, writable, absent, relative) |
| 4 | exact destination | performed once | bench `egress-allowlist-exact-allows`; unit `f06_a_hop_…`, `f06_a_workload_…` |
| 5 | another hostname | denied | bench `egress-allowlist-neighbour-denies` |
| 6 | another port | denied | bench `egress-allowlist-other-port-denies`; `egress_allowlist_tests` |
| 7 | a suffix or a lookalike | not covered | `egress_allowlist_tests` (`evil-registry…`, `….evil.com`, a parent, a child); the pack's own label-aware list |
| 8 | trailing dot | refused in the file; the `net.http` URL parser refuses it (ADR-0050) | `egress_allowlist_tests` |
| 9 | IDNA alias | non-ASCII refused; `xn--` compared as written | `egress_allowlist_tests` |
| 10 | userinfo | refused in the file and in every URL (ADR-0050) | `egress_allowlist_tests` |
| 11 | HTTPS to HTTP redirect | never followed (`REDIRECT_TARGET_INVALID`) | existing `redirect-downgrade` |
| 12 | cross-origin redirect | the hop decided again; denied unless named | bench `egress-allowlist-cross-origin-hop-denied` |
| 13 | DNS rebinding | one resolution, pinned (unchanged) | existing SSRF evidence |
| 14 | mixed public/private answer | refused whole (unchanged) | existing `ssrf-mixed-answer` |
| 15 | IPv4-mapped IPv6 | blocked (unchanged) | existing `ssrf-ipv4-mapped` |
| 16 | NAT64 | blocked (unchanged) | existing `ssrf-nat64` |
| 17 | metadata service | blocked, even when named | existing `ssrf-metadata-*`; `fixtures` (`an_allowlisted_destination_widens_no_other_layer`) |
| 18 | loopback | blocked (unchanged) | existing `ssrf-loopback-not-excepted` |
| 19 | private network | blocked, even when named | bench `egress-allowlist-private-address-still-blocked` |
| 20 | domain fronting through a shared host | **residual** (R12): the tunnel is opaque | ADR-0048 §18; ADR-0071 Residuals |
| 21 | SNI or CONNECT mismatch | refused (unchanged) | existing sandbox egress evidence (ADR-0048) |
| 22 | no run grant | `NO_CAPABILITY`, nothing resolved (unchanged) | existing `no-resolution-without-grant` |
| 23 | no policy rule | `DEFAULT_DENY` | `fixtures` |
| 24 | tainted run, novel destination | approval required (none exists), even when named | `fixtures` (`an_allowlisted_destination_widens_no_other_layer`) |
| 25 | exhausted budget | refused (unchanged) | existing budget evidence |
| 26 | workload without an authorisation | `NOT_AUTHORISED` (unchanged) | existing F-17 evidence |
| 27 | revoked destination | removing the entry; denied after the restart | `egress_allowlist_tests`, unit `f06_…` (an absent entry); restart semantics in ADR-0071 §6 |
| 28 | a runtime supplies its own allowlist | no message carries one; an unknown member refuses the file | `test_f06_egress_allowlist.py`; `egress_allowlist_tests` |
| 29 | failed resolver | `RESOLUTION_FAILED`, never an allow (unchanged) | existing `dns-resolution-failed` |
| 30 | a stale authorisation after a change | a workload keeps its launch decision until it ends; a restart reaps every run | ADR-0061; ADR-0071 §6 (no dedicated test) |

The `bench` cases are `make net-http-evidence`'s, with a seventh,
`egress-allowlist-other-path-denies`: an entry scoped to `workload` does not
cover a `net.http` request. The suite now requires 193 cases: ADR-0050's
179, these seven and OF-2's seven (§6); the M5e gate's test pins that count.

## 4. Mutation review

`make egress-allowlist-mutations` weakens nineteen guards in turn
(G1-G19): an empty list, a suffix, any port, any path, an unknown member, a
single label and a number each accepted; the predicate ignored; BALANCED's
and POWER's rules not requiring it; every network action placed inside
whatever the file says; a workload judged by `net_http` entries; a
relative path taken; and, since OF-2, the ceiling narrowing nothing, an
action without the input counted as inside, an approval left to a human,
a caller's claim believed, the reserved id or reason a file's. Each must be
killed by a named test. A leading `*` is refused twice, so weakening either
check alone is an equivalent mutant and neither is in the table.

## 5. Not covered here

The model manager's download path (`model_download`, ADR-0072; ADR-0071
OF-3: its own separately authorised egress) and per-entry quotas (OF-3,
evaluated on their own): neither is built. The gate over operator policies
is built (§6).

## 6. OF-2: the ceiling every policy is under (ADR-0073)

Since 2026-11-20 the allowlist is not only a predicate the shipped packs
require: after a policy's rules and postconditions, the evaluator denies
every network action whose destination the allowlist does not name, whatever
the policy said ([ADR-0073](adr/0073-f06-of2-the-operators-egress-allowlist-is-a-ceiling-every-policy-is-under.md), Proposed). The input is computed once,
in the state layer's decision function, from the operator's file; a caller's
or a run's claim is replaced. A narrowed decision is `DENY` from the reserved
rule `operator-egress-ceiling` (`OUTSIDE_EGRESS_ALLOWLIST`,
`--egress-allowlist:1`), which no policy file may declare; a rule that
denies keeps its own name. On the wire a `net.http` hop says
`DENIED_BY_RULE` naming that rule.

**Migration.** An operator policy that allowed `network.https` without
naming destinations reaches nothing until each destination is in the file:
every hop (a CDN host a redirect leads to included), for each path that
reaches it. The file is read at start; a change waits for a restart, which
reaps every run. A running workload's tunnels end with it.

| # | case | outcome | evidence |
|---|---|---|---|
| O1 | operator policy allowing every hop, no file | ceiling denies; nothing resolved | `net_http::tests::of2_…`; bench `of2-operator-policy-absent-denies` |
| O2 | the same, an empty file | as no file | `egress_allowlist_tests` (`no_file_and_an_empty_file_cover_nothing`); O1 |
| O3 | the same, the destination named | the policy's allow stands; performed once | `of2_…`; bench `of2-operator-policy-exact-allows` |
| O4 | an operator `DENY` over a named destination | denied by that rule, by its name | `of2_…`; `fixtures`; bench `of2-operator-policy-deny-rule-kept` |
| O5 | a rule with no host condition, a wildcard grant | ceiling denies; a wildcard action is never admitted | `fixtures` (`an_operator_policy_allowing_every_host_…`); `egress_allowlist_tests` (`an_action_is_admitted_only_…`) |
| O6 | a neighbouring name | ceiling denies | bench `of2-operator-policy-neighbour-denies`; `admits` tests |
| O7 | another port | ceiling denies | bench `of2-operator-policy-other-port-denies` |
| O8 | named for the other path | ceiling denies | bench `of2-operator-policy-other-path-denies`; `workload_route::tests::f06_…` |
| O9 | cross-origin redirect | the hop decided again, denied | bench `of2-operator-policy-cross-origin-hop-denied` |
| O10 | DNS rebinding | one resolution, pinned (unchanged) | existing SSRF evidence, now past the ceiling |
| O11 | mixed public/private answer | refused whole (unchanged) | existing `ssrf-mixed-answer` |
| O12 | private address | blocked, even when named | bench `egress-allowlist-private-address-still-blocked` |
| O13 | link-local address | blocked (unchanged) | existing SSRF evidence |
| O14 | metadata service | blocked; POWER's `deny-internal-ranges` keeps its name | `fixtures` (`an_approval_cannot_lift_…`); existing `ssrf-metadata-*` |
| O15 | URL normalisation ambiguity | refused before any decision (unchanged); a number is never a destination | existing URL evidence; `egress_allowlist_tests` |
| O16 | tainted run, novel destination | outside: denied, nobody asked; inside: approval still required | `fixtures` (`an_approval_cannot_lift_…`) |
| O17 | workload without its own authorisation | `NOT_AUTHORISED` (unchanged) | existing F-17 evidence |
| O18 | wrong run capability | `NO_CAPABILITY` (unchanged): the ceiling grants nothing | existing `no-resolution-without-grant` |
| O19 | changed authorisation | a running workload keeps its launch decision until it ends (ADR-0061) | existing F-17 evidence; ADR-0073 §5 |
| O20 | restart with the entry removed | a new run's hop denied by the ceiling | `of2_a_restart_without_the_entry_denies_what_it_allowed` |
| O21 | a file replaced, writable, absent or relative | the authority does not start | `transport_server` (unchanged) |
| O22 | a caller says its destination is allowlisted | replaced by the file's answer | `state_query` (`a_proposal_cannot_say_…`); `test_f06_egress_allowlist.py` (no wire field) |
| O23 | BALANCED | as F-06: its registries, where named | `fixtures` |
| O24 | POWER | as F-06: any HTTPS, where named | `fixtures` |
| O25 | SAFE | no network | `fixtures` |
| O26 | a package manager's legitimate requests | reached where every hop is named | existing registry and hygiene evidence, their destinations named |
| O27 | credential origin confusion | a credential only at its bound origin, on a hop the ceiling admits | `secret_use` tests; `net_http_evidence` credential cases |
| O28 | a policy that allows everything | under the ceiling | `fixtures` (`an_operator_policy_allowing_every_host_…`) |
| O29 | broker or authority restart | O20; existing crash and restart evidence | `net_http_evidence` (`crashes_replays_…`) |
| O30 | the ceiling removed | killed | `make egress-allowlist-mutations` G14 (and G11, G15--G19) |
