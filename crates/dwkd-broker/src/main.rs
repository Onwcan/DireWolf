//! `dwkd-broker` — the DireWolf execution broker. **It does, and decides
//! nothing.**
//!
//! # What this process is
//!
//! The executor. It owns the Filesystem Broker, the Exec Broker, the Sandbox
//! Supervisor, Network Egress (the `PROXY_ONLY` CONNECT proxy and `net.http`),
//! Model Egress and artifact capture. It holds file descriptors, PIDs, sockets
//! and containers — and **no long-lived key** ([ADR-0018]).
//!
//! It receives a *per-invocation authorisation* from `dwkd-authority`: one
//! canonical action and what it needs to perform it. It performs exactly that.
//!
//! # What this process must never acquire
//!
//! It cannot mint a capability, create or match an approval, widen authority,
//! evaluate policy, read `kernel.db` or the keychain, or write `audit.log`. It
//! has no code for any of those and must never grow any: the boundary is
//! asymmetric on purpose. Compromising the broker yields what the broker
//! process can do with its own identity and the descriptors it is handed while
//! it is compromised — which, in M4b, is reading files the authority has
//! already authorised and opened — not the authority's decisions or records
//! (ADR-0043 narrows ADR-0018's "the current invocation" to exactly this).
//!
//! There is no DWKP endpoint here. The broker is not addressable from the
//! Cognition Plane: it reads only from a peer the kernel reports as the
//! authority's uid, and it speaks only the private protocol
//! ([`dwk_proto::brokerp`]), which no cognition-side code can name.
//!
//! # Status: M5b — `PROXY_ONLY` egress; M5a — execution environments; M4e — secret
//! handoff; M4d — process execution, the filesystem tools
//!
//! [ADR-0043]: one private Unix-domain listener (`listener`), one exchange per
//! connection (`exchange`): a hello naming a fresh channel, one authorisation
//! with exactly the descriptors its operation needs, each re-verified, one
//! outcome. Linux only.
//!
//! [ADR-0044] adds `fs.stat`, `fs.list` and `fs.search` through the
//! authority's descriptors, and the four operations that change names —
//! `fs.write`, `fs.patch`, `fs.move`, `fs.delete` — each on one validated name
//! in a directory the authority opened, atomically, never replacing or
//! removing an object it did not prove to be the one authorised. Changing a
//! name needs directory write permission for the broker's **own** uid on that
//! directory — ambient authority the operator grants on a write-enabled
//! workspace, stated in ADR-0044 §3.
//!
//! [ADR-0045] adds `process` (`process_start`, `process_status`,
//! `process_kill`): the executable the authority resolved and hashed is
//! re-proved and executed **by its descriptor** (`execveat`, `AT_EMPTY_PATH`)
//! from a launch helper — this binary, `exec-helper` — with an environment
//! built from nothing, fixed resource limits, `/dev/null` for stdin, its
//! output drained and bounded, and supervised by pidfd. It runs **on the
//! host**, with the broker's privileges: no sandbox exists until M5, and the
//! authority performs a host launch only with a per-invocation approval,
//! which no build has before M6.
//!
//! [ADR-0046] adds secrets, one value per invocation and never a store: the
//! authority hands the broker the read end of a pipe it filled and closed
//! (`secret`), which the broker reads once into a buffer it zeroes.
//! `secret_egress` renders a mode A header and drops it — the consumer is
//! M5's `net.http` — and `secret_process_start` injects the value into a
//! launched target's environment or descriptor 3, a primitive no production
//! authority issues before M5's sandbox. A secret launch's output is redacted
//! while it is drained. The broker has no keychain, age or metadata code
//! (TX028), and it dumps no core (`hardening`).
//!
//! [ADR-0047] adds the sandbox supervisor's first slice (`sandbox`): an
//! `oci-strict` container prepared, measured from the runtime's record and by
//! a digest-pinned probe inside it, destroyed and listed — through the
//! container runtime's client the authority resolved and hashed, re-proved
//! and executed by descriptor through the launch helper with a typed
//! argument vector. Nothing is run inside an environment but the probe; the
//! only topology built is the evidence harness's `NO_NETWORK`, and only with
//! `--allow-evidence-topology`. Sandboxed workloads are M5d's.
//!
//! [ADR-0048] adds `PROXY_ONLY` (`egress`): the broker's opaque CONNECT
//! proxy, one Unix socket per environment reached only through that
//! environment's relay, enforcing the authority's grant, the IP guard, one
//! pinned resolution, TLS server-name agreement and byte budgets — the
//! broker's one outbound path, dialled only from `egress/tunnel.rs`. It
//! terminates no TLS, holds no CA and injects nothing. `--allow-evidence-egress`
//! swaps in the evidence's fixture resolver, loudly; production has none.
//!
//! [ADR-0044]: ../../../docs/adr/0044-m4c-filesystem-operations-plans-and-atomic-mutation.md
//! [ADR-0045]: ../../../docs/adr/0045-m4d-process-execution-broker.md
//! [ADR-0046]: ../../../docs/adr/0046-m4e-secret-handles-backends-injection-and-redaction.md
//! [ADR-0047]: ../../../docs/adr/0047-m5a-oci-execution-environment-and-measured-assurance.md
//! [ADR-0048]: ../../../docs/adr/0048-m5b-proxy-only-topology-and-connect-proxy.md
//!
//! [ADR-0018]: ../../../docs/adr/0018-authority-broker-split.md
//! [ADR-0043]: ../../../docs/adr/0043-m4b-private-broker-channel-and-brokered-fs-read.md

// Pedantic lints on the security crates, per docs/LANGUAGE_SELECTION.md §7.
#![warn(clippy::pedantic)]

mod config;
#[cfg(target_os = "linux")]
mod crash;
#[cfg(target_os = "linux")]
mod egress;
#[cfg(target_os = "linux")]
mod exchange;
#[cfg(target_os = "linux")]
mod hardening;
// Off Linux the broker does not serve, so nothing names the wire types; the
// manifest edge is acknowledged here for `unused_crate_dependencies`.
#[cfg(not(target_os = "linux"))]
use dwk_proto as _;
#[cfg(target_os = "linux")]
mod listener;
#[cfg(target_os = "linux")]
mod nonce;
#[cfg(target_os = "linux")]
mod peer;
#[cfg(target_os = "linux")]
mod process;
#[cfg(target_os = "linux")]
mod sandbox;
#[cfg(target_os = "linux")]
mod secret;

use std::process::ExitCode;

use config::Command;

const NAME: &str = "dwkd-broker";

/// One line of operator-facing text on stderr.
fn log(text: &str) {
    eprintln!("{NAME}: {text}");
}

/// One event line on stderr: what happened to a connection. Carries ids and
/// counts, never file content.
#[cfg(target_os = "linux")]
fn event(text: &str) {
    eprintln!("{NAME}: event={text}");
}

fn main() -> ExitCode {
    let mut args = Vec::new();
    for arg in std::env::args_os().skip(1) {
        let Ok(arg) = arg.into_string() else {
            log("arguments must be UTF-8");
            return ExitCode::from(2);
        };
        args.push(arg);
    }
    match config::parse(&args) {
        Ok(Command::Version) => {
            println!("{NAME} {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Ok(Command::Help) => {
            print!("{}", help());
            ExitCode::SUCCESS
        }
        Ok(Command::Serve(serve_config)) => serve(&serve_config),
        Ok(Command::ExecHelper) => exec_helper(),
        Err(error) => {
            log(&error.to_string());
            eprint!("{}", help());
            ExitCode::from(2)
        }
    }
}

#[cfg(target_os = "linux")]
fn serve(config: &config::ServeConfig) -> ExitCode {
    // First: no core, and no same-uid reader of this memory (M4e).
    if let Err(error) = hardening::apply(config.dumpable_permitted) {
        log(&format!("cannot serve: {error}"));
        return ExitCode::FAILURE;
    }
    if config.dumpable_permitted {
        log(
            "REDUCED ASSURANCE: the process stays dumpable (--allow-dumpable); its memory is \
             readable by other processes of its uid. RLIMIT_CORE is 0",
        );
    }
    let (place, own_uid) = match listener::prepare(&config.socket) {
        Ok(prepared) => prepared,
        Err(error) => {
            log(&format!("cannot serve: {error}"));
            return ExitCode::FAILURE;
        }
    };
    if own_uid == 0 {
        log(
            "refusing to run as root: the broker is its own unprivileged identity, and a root \
             broker would hold every file on the machine instead of only the ones it is handed",
        );
        return ExitCode::FAILURE;
    }
    if own_uid == config.authority_uid {
        if !config.shared_uid_permitted {
            log(&format!(
                "the authority uid {} is the broker's own; run the broker as its own user, or \
                 pass --allow-shared-authority-uid for development",
                config.authority_uid
            ));
            return ExitCode::FAILURE;
        }
        log(&format!(
            "REDUCED ASSURANCE: the broker shares uid {own_uid} with the authority \
             (--allow-shared-authority-uid)"
        ));
    }
    let bound = match listener::bind(&place) {
        Ok(bound) => bound,
        Err(error) => {
            log(&format!("cannot serve: {error}"));
            return ExitCode::FAILURE;
        }
    };
    // The sandbox's files exist before the broker says it is serving — and
    // the egress proxies' root is settled: what a dead broker left there is
    // gone before anything may ask for an environment (M5b).
    let files = match listener::sandbox_files(&place, own_uid) {
        Ok(files) => files,
        Err(error) => {
            log(&format!("cannot serve: {error}"));
            return ExitCode::FAILURE;
        }
    };
    let proxies = match proxies(config, &place, own_uid) {
        Ok(proxies) => proxies,
        Err(error) => {
            log(&format!("cannot serve: {error}"));
            return ExitCode::FAILURE;
        }
    };
    println!(
        "{NAME}: serving the private broker channel at {} as uid {own_uid} for authority uid {} \
         (pid {})",
        place.path().display(),
        config.authority_uid,
        std::process::id()
    );
    let mut channels = nonce::Channels::new();
    crash::init();
    let processes = match process::Processes::new(config.authority_uid) {
        Ok(processes) => processes,
        Err(error) => {
            log(&format!("cannot serve: {error}"));
            return ExitCode::FAILURE;
        }
    };
    crate::event(&format!(
        "process_generation generation={}",
        processes.generation().as_str()
    ));
    let sandbox = sandbox::Sandbox::new(
        processes.helper().to_path_buf(),
        config.authority_uid,
        files,
        config.evidence_topology_permitted,
        proxies,
    );
    listener::serve(
        &bound,
        config.authority_uid,
        own_uid,
        &mut channels,
        exchange::Effects {
            processes: &processes,
            sandbox: &sandbox,
        },
    );
    ExitCode::SUCCESS
}

/// The `PROXY_ONLY` proxies (M5b, ADR-0048), in the broker's own directory,
/// with the host's resolver — or, for the egress evidence only, a fixture's,
/// said loudly. The evidence topology is announced here too: both are the
/// sandbox's evidence-only acknowledgements.
#[cfg(target_os = "linux")]
fn proxies(
    config: &config::ServeConfig,
    place: &listener::SocketPlace,
    own_uid: u32,
) -> Result<std::sync::Arc<egress::proxy::Proxies>, String> {
    if config.evidence_topology_permitted {
        log(
            "EVIDENCE TOPOLOGY: NO_NETWORK execution environments may be prepared \
             (--allow-evidence-topology); this is the M5a evidence harness's topology, not a \
             production one",
        );
    }
    let resolver: egress::resolve::Shared = match &config.evidence_egress {
        None => std::sync::Arc::new(egress::resolve::SystemResolver),
        Some(path) => {
            let fixture = egress::resolve::FixtureResolver::load(path)
                .map_err(|error| format!("the egress fixture: {error}"))?;
            log(
                "EVIDENCE EGRESS: the CONNECT proxy resolves names from a fixture file and may \
                 reach the loopback addresses it names (--allow-evidence-egress); this is the \
                 M5b evidence harness's resolver, never a production one",
            );
            std::sync::Arc::new(fixture)
        }
    };
    egress::proxy::Proxies::new(
        place.dir().join("egress"),
        own_uid,
        resolver,
        egress::Limits::PRODUCTION,
    )
    .map(std::sync::Arc::new)
    .map_err(|error| format!("the egress proxies: {}", error.0))
}

/// The launch helper: see `process::helper`.
#[cfg(target_os = "linux")]
fn exec_helper() -> ExitCode {
    process::helper::run()
}

#[cfg(not(target_os = "linux"))]
fn exec_helper() -> ExitCode {
    ExitCode::from(2)
}

#[cfg(not(target_os = "linux"))]
fn serve(_config: &config::ServeConfig) -> ExitCode {
    log(
        "the private broker channel runs only on Linux (ADR-0043): it needs SO_PEERCRED, \
         SCM_RIGHTS and the authority's Linux resolver",
    );
    ExitCode::FAILURE
}

fn help() -> String {
    format!(
        "{NAME} {} - the DireWolf execution broker (does)\n\
         \n\
         Performs exactly the effect dwkd-authority authorised, on the object\n\
         dwkd-authority opened. Decides nothing. Reads only from the authority's\n\
         uid; not addressable from the cognition plane.\n\
         \n\
         USAGE:\n    \
             {NAME} serve --socket <PATH> --authority-uid <UID> [--allow-shared-authority-uid] [--allow-dumpable]\n    \
                              [--allow-evidence-topology] [--allow-evidence-egress <FILE>]\n    \
             {NAME} [-V | --version] [-h | --help]\n\
         \n\
         OPTIONS:\n    \
             --socket <PATH>                 absolute path of the private socket\n    \
             --authority-uid <UID>           the only uid the broker reads from\n    \
             --allow-shared-authority-uid    permit the authority to be the broker's own uid (development only)\n    \
             --allow-dumpable                leave the process dumpable, its memory readable by its uid (development only)\n    \
             --allow-evidence-topology       permit NO_NETWORK execution environments (M5a evidence only)\n    \
             --allow-evidence-egress <FILE>  resolve egress names from a fixture file (M5b evidence only)\n\
         \n\
         STATUS: M4d - the filesystem tools (read, stat, list, search, write,\n\
         patch, move, delete) and process execution (start, status, kill) of the\n\
         executable the authority checked, by its descriptor, on the HOST with\n\
         the broker's own privileges. M4e - one secret per invocation, handed\n\
         over in a pipe: an egress header rendered and dropped, or a value\n\
         injected into a launch; no secret store. M5a - execution environments:\n\
         an oci-strict container prepared, measured, destroyed and listed\n\
         through the runtime client the authority checked, with nothing run\n\
         inside but the trusted probe. M5b - PROXY_ONLY: the runtime's none\n\
         network, one relay in it, and an opaque CONNECT proxy (no TLS\n\
         termination, no CA, no credential) enforcing the grant, the IP guard,\n\
         one pinned resolution, server-name agreement and byte budgets.\n\
         NO_NETWORK only for evidence. Linux only. No sandboxed workload and\n\
         no net.http: M5c-M5e.\n",
        env!("CARGO_PKG_VERSION")
    )
}

#[cfg(test)]
mod tests {
    use super::{NAME, help};

    #[test]
    fn help_names_the_component_its_one_effect_and_what_comes_later() {
        let h = help();
        assert!(h.contains(NAME));
        assert!(h.contains("filesystem tools"));
        assert!(h.contains("process execution"));
        assert!(h.contains("M4d") && h.contains("M4e") && h.contains("M5") && h.contains("HOST"));
        assert!(h.contains("no secret store"));
        assert!(h.contains("--authority-uid"));
        assert!(h.contains("M5a") && h.contains("oci-strict") && h.contains("NO_NETWORK only"));
        assert!(h.contains("--allow-evidence-topology"));
    }

    /// The broker's defining property, asserted as a test so that a future
    /// change which makes this crate a decider fails something.
    #[test]
    fn help_states_that_the_broker_decides_nothing() {
        assert!(help().contains("Decides nothing"));
    }
}
