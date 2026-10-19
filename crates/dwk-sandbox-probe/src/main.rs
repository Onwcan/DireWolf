//! `dwk-sandbox-probe` — the trusted assurance probe (M5a, [ADR-0047] §8).
//!
//! It runs **inside** an `oci-strict` environment, as the environment's own
//! user, and reports what it finds against the profile both daemons share
//! (`dwk_proto::brokerp::sandbox`): each `CONTAINER_*` invariant as `PASS`,
//! `FAIL` or `UNOBSERVABLE`, in a closed schema, and nothing else.
//!
//! What makes it trustworthy is not this code but where it comes from: it is
//! part of the sandbox image's read-only root, the image is named by its
//! content digest, and the broker hashes the probe out of the container and
//! compares it with the authority's digest before it runs. A substituted
//! probe is refused before it can say anything. It is not the broker's
//! binary, and it holds nothing: no secret, no socket, no configuration but
//! its arguments.
//!
//! Modes:
//!
//! | argv | what |
//! |---|---|
//! | `hold` | the environment's first process: until killed, reap every process orphaned to it, and nothing else |
//! | `measure <environment-id> <topology>` | print one report and exit |
//! | `reap` | after a workload (M5d, ADR-0052 §5): end every other process of the environment, print `reaped <found> <remaining>` |
//! | `launch hygiene <path> <args...>` | the trusted launcher (M5d.2, ADR-0052 §5a): set `workspace_exec_hygiene`'s variables over the environment's own and execute `<path>` with exactly `<args...>`, replacing itself |
//! | `launch secret-fd[-hygiene] <path> <args...>`, `launch secret-env[-hygiene] <NAME> <path> <args...>` | the same launcher with a secret (M5d.3, ADR-0052 §7): one framed value read from standard input, then the target executed with it on descriptor 3 (mode C) or as `NAME=value` (mode B), and standard input `/dev/null` |
//! | `ptrace-target` | the child the ptrace canary attaches to |
//!
//! [ADR-0047]: ../../../docs/adr/0047-m5a-oci-execution-environment-and-measured-assurance.md

#[cfg(target_os = "linux")]
mod launch;
#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    linux::main()
}

// Off Linux there is no environment to be inside of: the probe says so and
// measures nothing.
#[cfg(not(target_os = "linux"))]
use dwk_proto as _;
#[cfg(not(target_os = "linux"))]
use dwk_sandbox_profile as _;

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("dwk-sandbox-probe: measures a Linux execution environment from inside one");
    std::process::ExitCode::from(2)
}
