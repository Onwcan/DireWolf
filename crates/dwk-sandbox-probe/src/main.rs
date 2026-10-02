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
//! | `hold` | the environment's first process: wait, do nothing, until killed |
//! | `measure <environment-id> <topology>` | print one report and exit |
//! | `ptrace-target` | the child the ptrace canary attaches to |
//!
//! [ADR-0047]: ../../../docs/adr/0047-m5a-oci-execution-environment-and-measured-assurance.md

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
