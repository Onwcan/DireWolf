# F-05: user namespaces and security modules

What an execution environment's user namespace and security-module
confinement really are, what F-05 found claimed but not built, what was
changed, and what is still not held. The decision is
[ADR-0069](adr/0069-f05-user-namespace-and-lsm-assurance-are-measured-not-assumed.md)
(**Proposed**).

## 1. Source and scope

F-05 comes from the security remediation program's audit of 2026-11-11/12:
user-namespace remapping and LSM (AppArmor, SELinux, Landlock) assurance were
assumed, not measured. In scope: every environment the broker prepares
(`oci-strict`), the runtime's record of it, the probe's view from inside, and
the documents that describe them. Out of scope: the egress allowlist (F-06),
the resolver (F-16), host execution (unbuilt; ADR-0052 §12), and anything that
needs private broker protocol 13.

## 2. What was claimed, and what was there

| claim | where | as built before F-05 |
|---|---|---|
| `userns: remap` | SANDBOX.md §2 | never built (ADR-0047 §5, ADR-0052, ADR-0056): uid 10001 is host uid 10001 |
| "User namespace remap ✅" on Linux | SANDBOX.md §5 | not built |
| `apparmor/selinux: enforced where available` | SANDBOX.md §2 | the runtime's default label, never read (ADR-0047 §5) |
| "Landlock (host exec) ✅ 5.13+"; host exec "applies Landlock" | SANDBOX.md §§4, 5 | no ruleset anywhere; host execution unshipped |
| "user namespaces" mitigate sandbox escape | THREAT_MODEL.md, STRIDE | the host's initial user namespace, shared |
| `HOST_USERNS_NOT_HOST` | the invariant's name | checks only `UsernsMode != "host"`; Docker's default `""` passes |

Reproduced on `cba8111` with Docker Desktop on WSL2 (kernel
`6.18.58.1-microsoft-standard-WSL2`): identity maps on the host distribution
and in the environment; AppArmor compiled in and disabled (`enabled` = `N`);
no `securityfs` list; no `selinuxfs`; `/proc/self/attr/current` reads
`kernel` (SELinux built in, uninitialised, confining nothing);
`/proc/self/attr/apparmor/current` answers `EINVAL`; Landlock offered by the
kernel, used by nothing.

## 3. The properties

ADR-0069 §1 states seven: A (workload uid inside ≠ host uid), B (uid 0 inside
≠ host uid 0) and C (environments are distinct host uids) are **not held**,
by the deployment contract; D (`HOST_USERNS_NOT_HOST`) is held, unchanged;
E (the real mapping is known from inside) and F (a module's confinement is
measured where the host runs one) are what F-05 adds; G (nothing claims what
is not held) is what its document changes restore.

## 4. What changed

- **The probe** (version-4 report) reads its own `/proc/self/uid_map`,
  `gid_map`, `attr/current` and `attr/apparmor/current`. The report's schema
  is closed: a map is at most eight ranges of three decimal numbers; a label
  is printable ASCII, at most 255 bytes, cut where the kernel ends it. A
  version-4 report must carry these facts, a version-3 report must not, and
  version 3 is still accepted.
- **The broker** (`sandbox/identity.rs`) judges them against the runtime's
  record (`HostConfig.UsernsMode`, `AppArmorProfile`, `ProcessLabel`) and the
  host's kernel (`/sys/kernel/security/lsm`,
  `/sys/module/apparmor/parameters/enabled`, `/sys/fs/selinux/enforce`) each
  time it judges an environment, and writes one `sandbox_identity` event.
  Nothing is admitted or refused on it.
- **The documents**: SANDBOX.md §§2, 4, 5 and THREAT_MODEL.md now say what is
  built; `HOST_USERNS_NOT_HOST`'s documentation says what it is not.

## 5. Reading the event

```text
sandbox_identity environment=env_… userns=UNSUPPORTED:inside:shared apparmor=UNSUPPORTED:host:kernel-has-none selinux=UNSUPPORTED:host:kernel-has-none landlock=NOT_APPLICABLE:build:no-ruleset
```

Each field is `STATE:seen:detail`. The states are F-03's five
([F03_EFFECTIVE_POSTURE.md](F03_EFFECTIVE_POSTURE.md) §2); `seen` is where the
fact came from (`both` vantages, `inside`, `record`, the `host` kernel, the
`build`, or `none`).

| property | `ENFORCED` | `REDUCED` | `UNVERIFIED` | `UNSUPPORTED` | `NOT_APPLICABLE` |
|---|---|---|---|---|---|
| userns | never | never | `remapped` (inside only), `unobserved` | `shared` (the contract), `host-mode` | -- |
| AppArmor | `NAME (enforce)` inside, `NAME` recorded, kernel running it | `complain`, `unconfined` | `contradiction`, `unrecognised`, `unobserved` | `kernel-has-none` | -- |
| SELinux | the same label both sides, a confined domain, enforcing | `permissive`, `unconfined-domain` | `contradiction`, `unrecorded`, `unobserved` | `kernel-has-none` | -- |
| Landlock | never | never | never | never | `no-ruleset` |

## 6. Compatibility

| environment | userns | AppArmor | SELinux | Landlock | contracts | evidence |
|---|---|---|---|---|---|---|
| Docker Desktop, WSL2 (local) | `UNSUPPORTED:inside:shared` | `UNSUPPORTED:host` | `UNSUPPORTED:host` | `NOT_APPLICABLE` | all hold | **observed**, `make sandbox-foundation-evidence` |
| Docker Engine, Ubuntu runner | `UNSUPPORTED:both:shared` (`inside` before ADR-0070) | `ENFORCED:both:docker-default` | `UNSUPPORTED:host` | `NOT_APPLICABLE` | all hold | **observed**: hosted `sandbox-foundation` job, CI #198 (2026-11-20) |
| Docker with `userns-remap` | `UNVERIFIED:inside:remapped` (tabled) | as the host | as the host | `NOT_APPLICABLE` | the workspace, the relay's ACL and F-04's peer check refuse (§7) | not exercised |
| rootless Docker or Podman | `UNVERIFIED:inside:remapped` (tabled) | as the host | as the host | `NOT_APPLICABLE` | refused as above | not exercised; not a supported runtime |
| an SELinux host (`container_t`) | `UNSUPPORTED:inside:shared` | `UNSUPPORTED:host` | `ENFORCED:both:container_t` enforcing, `REDUCED` permissive (tabled) | `NOT_APPLICABLE` | all hold | not exercised |

"Tabled" means the judgement's unit tables cover the state from the kernel's
formats; no such host was run.

## 7. Why the identity map stays: the four contracts

| contract | depends on | under a remapping |
|---|---|---|
| workspace group 10001, mode 2770 (ADR-0052 §6) | the workload is host gid 10001 | it cannot write the root; inside, owner and group read as unmapped and the probe's workspace measurement refuses |
| `RLIMIT_NPROC` backstop 8 192 (ADR-0056) | one host uid, counted once | one daemon-wide range keeps the coupling; per-environment ranges change the arithmetic |
| proxy directory ACL naming 10002 (ADR-0048 §3) | the relay is host uid 10002 | the relay cannot reach its socket |
| proxy peer check, `RELAY_UID` only (ADR-0068) | `SO_PEERCRED` reports 10002 | the relay's uid as the broker sees it is not 10002: closed unread |

Every one fails closed. Remapping is therefore an owner decision with its own
ADR (ADR-0069 OD-1), never an exception in one of them.

## 8. Adversarial matrix

| # | attempt | expected | where | status |
|---|---|---|---|---|
| 1 | the identity map presented as isolation | `UNSUPPORTED:inside:shared` | identity tables; real environment | implemented, observed |
| 2 | a remapped uid map, gid map or both | `UNVERIFIED:inside:remapped` | identity tables | implemented |
| 3 | a real remapped map (unprivileged `unshare --user`) | `UNVERIFIED:inside:remapped` | `a_real_kernel_mapping_is_judged_where_it_is_read` | implemented, observed (local kernel) |
| 4 | a near identity (`0 0 4294967294`, `1 1 4294967295`), `--map-current-user`, `--map-root-user`, a subordinate range | never the identity map | proto tests | implemented |
| 5 | an empty map, a zero count, a sign, words, a short or long line, nine lines | no map | proto tests | implemented |
| 6 | one map missing; a version-3 probe | `UNVERIFIED:none:unobserved` | identity tables | implemented |
| 7 | the record's `host` mode, whatever is seen inside | `UNSUPPORTED:record:host-mode` | identity tables | implemented |
| 8 | a version-4 report without identity, a version-3 report with it | refused at decoding | proto tests | implemented |
| 9 | an AppArmor profile only the record names | `UNVERIFIED:none:unobserved` | identity tables | implemented |
| 10 | a profile the process runs that the record does not name, or the reverse | `UNVERIFIED:inside:contradiction` | identity tables | implemented |
| 11 | a complain-mode profile | `REDUCED:both:complain` | identity tables | implemented |
| 12 | an unconfined process | `REDUCED:both:unconfined` | identity tables | implemented |
| 13 | AppArmor labels on a kernel not running it | `UNSUPPORTED:host:kernel-has-none` | identity tables; real environment | implemented, observed |
| 14 | AppArmor listed but disabled, or enabled but unlisted | not running | `the_host_kernel_is_read_as_its_files_say` | implemented |
| 15 | SELinux's `kernel` label read as a profile | `UNVERIFIED:inside:unrecognised` | identity tables | implemented |
| 16 | SELinux's context read as an AppArmor profile where both run | `UNVERIFIED:none:unobserved` | identity tables | implemented |
| 17 | permissive SELinux | `REDUCED:both:permissive` | identity tables | implemented |
| 18 | `spc_t`, `unconfined_t`, `kernel_t` | `REDUCED:both:unconfined-domain` | identity tables | implemented |
| 19 | a context the record does not carry, or a different one | `UNVERIFIED` | identity tables | implemented |
| 20 | Landlock offered by the kernel | `NOT_APPLICABLE:build:no-ruleset` | identity tables; real environment | implemented, observed |
| 21 | a label with a control character, a terminal escape, a bidi control, non-ASCII, a leading space, or over 255 bytes; nothing | not a label (one ends at the kernel's NUL or newline) | proto tests | implemented |
| 22 | a profile name with spaces and separators, 130 characters | one field, sanitised, 64 characters | `the_event_line_names_every_property_and_carries_nothing_unbounded` | implemented |
| 23 | the judgement used to admit or refuse | impossible: no invariant, one event call | `test_f05_identity.py` | implemented |
| 24 | a new protocol-12 invariant | none: 52, unchanged | `test_f05_identity.py` | implemented |
| 25 | a real AppArmor-enforcing environment | `ENFORCED:both:docker-default` | `sandbox_foundation.rs`, hosted | **observed**, CI #198 |
| 26 | a real `userns-remap` daemon, rootless runtime, SELinux host | as tabled | -- | not exercised: changing the host's daemon or kernel settings is outside this change |

## 9. Mutations

`make sandbox-identity-mutations` weakens the judgement's eleven guards in
turn (N1--N11: complain, a contradiction, the record alone, permissive
SELinux, an unconfined domain, Landlock and the shared map each counted as
enforced; AppArmor judged without the kernel running it; a disabled AppArmor
counted as running; the host mode read as shared; SELinux's label read as
AppArmor's). Each must be killed by a named test, and the file restored
byte-identically. The probe report's two rules -- a version-4 report without
the probe's identity accepted, a near identity read as the identity map --
were weakened the same way once while this was built, and both were killed
by `dwk-proto`'s tests (`a_version_four_report_and_only_one_says_who_the_probe_is`,
`a_mapping_is_read_as_the_kernel_prints_it_and_nothing_else`); they are not in
the table, because nothing under `scripts/` may name the private protocol's
module (TX016).

## 10. Evidence

- Hosted, CI #198 (run 44706359028, `3584f3e`, 2026-11-20), the
  `sandbox-foundation` job on an Ubuntu runner: `real-environment-apparmor-enforced`,
  `real-environment-userns-seen-both`, `real-environment-landlock-not-applicable`;
  the event `userns=UNSUPPORTED:both:shared apparmor=ENFORCED:both:docker-default
  selinux=UNSUPPORTED:host:kernel-has-none landlock=NOT_APPLICABLE:build:no-ruleset`.
- `make sandbox-foundation-evidence` (real OCI runtime, Docker Desktop on
  WSL2, 2026-11-17): passed, 109 cases at `real-oci`, with
  `real-environment-userns-shared`, `real-environment-apparmor-unsupported`
  and `real-environment-landlock-not-applicable`.
- `cargo test -p dwkd-broker --bin dwkd-broker -- sandbox::identity_tests`
  and `cargo test -p dwk-proto --lib -- brokerp::sandbox`, including the real
  kernel's maps.
- `tests/architecture/test_f05_identity.py`.
- Pending: the hosted `sandbox-foundation` job, where the same assertion
  expects AppArmor `ENFORCED:both:docker-default`.

## 11. Residuals and owner decisions

As ADR-0069's Residuals and OD-1 to OD-4: one host uid for every
environment; uid 0 inside is host uid 0; no security module on Docker
Desktop; the judgement is the broker's alone until protocol 13; which relay
connected stays ADR-0068's open question.

## 12. Since ADR-0070 (Proposed): the host's vantage and a required module

[ADR-0070](adr/0070-adr-0069-decisions-host-vantage-required-lsm-and-what-stays-deferred.md)
takes ADR-0069's four decisions as far as they go without weakening a
control or changing protocol 12:

- **OD-1, built in part.** Where the broker shares the runtime's pid
  namespace, it reads `/proc/<pid>/cgroup`, `uid_map` and `gid_map` of the
  container's first process (`State.Pid`), bounded to 4 KiB each, once a
  line of its control-group file ends in exactly `/<id>` or
  `/docker-<id>.scope` -- before and after the maps. Two agreeing vantages
  say `both`; two that disagree say `UNVERIFIED:both:contradiction`. The
  identity map stays the contract: no supported runtime offers a user
  namespace per container, and ADR-0070 records the migration a remapped
  deployment needs.
- **OD-2, built as an opt-in.** `dwkd-broker serve --require-lsm
  apparmor|selinux`: the broker refuses to start where the host's kernel does
  not enforce the module (SELinux permissive is not enforcement), and
  refuses every environment not judged `ENFORCED` with `UNSUPPORTED`, after
  taking it down, writing `sandbox_lsm_required … outcome=refused`. Without
  the flag nothing changes; no flag turns it off.
- **OD-3, deferred.** The judgement and the requirement's reason reach the
  authority only with protocol 13, its own change.
- **Decided 2026-11-20:** OD-A (the host vantage) and OD-B (the opt-in
  requirement) approved as implemented; OD-C deferred to a separate
  security-architecture phase, OD-D to M6 (ADR-0070). Per-environment
  remapping is not built.
- **OD-4, deferred.** No process DireWolf confines opens a file by path (the
  exchange worker's filter allows none; an architecture test holds it), so a
  Landlock ruleset would add nothing until host execution exists (M6).

| case | level | local (Docker Desktop) | hosted |
|---|---|---|---|
| the control-group table; a real namespace read from both sides | unit, kernel | passed | passed (CI #198) |
| a broker requiring AppArmor, and one requiring SELinux, on a host running neither | real process | refused to start (both) | SELinux refused (`required-selinux-absent-not-served`, CI #198) |
| a conforming environment met; one started `apparmor=unconfined` refused | real OCI | NOT EXERCISED (no AppArmor) | met and refused (`required-apparmor-enforced-met`, `required-apparmor-unconfined-refused`, CI #198) |
| the userns vantage | real OCI | `inside` | `both` (CI #198) |
| `make sandbox-identity-mutations` | mutation | 20 of 20 killed | -- |

## 13. 2026-11-20: per-environment remapping re-examined -- blocked, F-05 partially completed

The remaining property -- each environment its own host identity, enforced
by the kernel -- was examined again against the supported runtime. Docker
Engine 29.9.3 (the local runtime; the hosted runners' is the same family)
offers no per-container user namespace: `docker run --userns` takes `host`
and nothing else, and the daemon reports no `userns` security option. No
Podman, `runc` or `crun` is a supported runtime here. Every path to the
property needs one of: a runtime with per-container user namespaces (ADR-0070
option B), a system-wide daemon change (option A -- prohibited, and one range
for every container still), or subordinate id ranges provisioned on the host
(`/etc/subuid`, `/etc/subgid` -- an owner action, not done here). With none
available, nothing was forced: the identity map stays the contract, reported
truthfully from both vantages, and **F-05 is PARTIALLY COMPLETED**.

| property | state |
|---|---|
| truthful user-namespace judgement, inside and from the host | built; hosted-verified (CI #198) |
| required AppArmor or SELinux, opt-in | built; hosted-verified (CI #198) |
| per-environment uid/gid remapping | **not built**: no supported runtime offers it |
| idmapped workspace mounts | not built: needs the above |
| Landlock for host execution | deferred to M6 (ADR-0070 OD-D) |
| the judgement in the authority's audit (protocol 13) | deferred to its own phase (OD-C) |

**The missing primitive:** a per-container user namespace with a mapping
the broker chooses, from a supported runtime. **The smallest next step:** an
ADR choosing that runtime (Podman with `--userns=auto` over a delegated
subordinate range, or an OCI runtime the broker drives directly) and the
broker's per-environment id-range allocator -- the migration ADR-0070 §OD-1
describes -- together with the host provisioning it needs, stated as owner
actions. Until then the shared-identity contracts (workload 10001, relay
10002, the 2770 workspace group, the relay directory's ACL, F-04's peer
uid, ADR-0056's task arithmetic) stay as they are, and stay measured.
