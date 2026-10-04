//! `dwk-sandbox-relay` — the one listener in a `PROXY_ONLY` environment's
//! network namespace (M5b, [ADR-0048]).
//!
//! The environment's namespace has no interface but loopback and no route
//! (the runtime's `none` network). Two containers of this one binary join
//! it, each for one job:
//!
//! | argv | runs as | what |
//! |---|---|---|
//! | `setup` | root, with `NET_ADMIN` and nothing else, for one request | add `169.254.7.1/32` to the namespace's loopback, then exit |
//! | `serve` | its own unprivileged user, no capability | accept on `169.254.7.1:8080` and forward each connection, byte for byte, to the broker's socket mounted at `/run/direwolf-egress/proxy.sock` |
//!
//! **It parses nothing.** It does not read a CONNECT request, a TLS record or
//! an environment variable, links no protocol crate, and decides nothing:
//! every check — the target, the resolution, the IP guard, the server name,
//! the budgets — is the broker's, at the far end of the socket. A relay that
//! failed would leave the environment with no network at all, never with a
//! second path: there is no route for one.
//!
//! It is believed because its bytes are the ones the authority pinned: the
//! broker hashes it out of the image before the setup container runs.
//!
//! [ADR-0048]: ../../../docs/adr/0048-m5b-proxy-only-topology-and-connect-proxy.md

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    linux::main()
}

#[cfg(not(target_os = "linux"))]
use dwk_sandbox_profile as _;

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("dwk-sandbox-relay: serves a Linux execution environment's proxy endpoint");
    std::process::ExitCode::from(2)
}
