# F-06: the operator's egress allowlist

Decision record: [ADR-0071](adr/0071-f06-an-operator-egress-allowlist-every-shipped-network-rule-requires.md)
(Proposed). This page is the implementation's: what changed, how to
configure it, and the evidence for each adversarial case.

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
| an operator policy file | as written | as written (it may require the predicate) |

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
cover a `net.http` request. The suite now requires 186 cases, ADR-0050's 179
and these seven, and the M5e gate's test pins that count.

## 4. Mutation review

`make egress-allowlist-mutations` weakens thirteen guards in turn (G1-G13):
an empty list, a suffix, any port, any path, an unknown member, a single
label and a number each accepted; the predicate ignored; BALANCED's and
POWER's rules not requiring it; a hop allowlisted whatever the file says; a
workload judged by `net_http` entries; a relative path taken. Each must be
killed by a named test. A leading `*` is refused twice, so weakening either
check alone is an equivalent mutant and neither is in the table.

## 5. Not covered here

The model manager's download path (`model_download`, ADR-0072), per-entry
quotas, and an allowlist gate over operator policies (ADR-0071 OF-2).
