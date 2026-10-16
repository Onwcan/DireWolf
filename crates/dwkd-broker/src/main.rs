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
//! # Status: M5d — sandboxed workloads (in progress); M5c — `net.http`; M5b —
//! `PROXY_ONLY` egress; M5a — execution environments; M4e — secret handoff;
//! M4d — process execution, the filesystem tools
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
//! Mode A's header is composed only into a `net.http` hop's request
//! (`http::render`, M5c; M4e's render-and-drop `secret_egress` is retired),
//! and `secret_process_start` injects the value into a
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
//! argument vector. The `NO_NETWORK` topology is built only with
//! `--allow-evidence-topology`.
//!
//! [ADR-0048] adds `PROXY_ONLY` (`egress`): the broker's opaque CONNECT
//! proxy, one Unix socket per environment reached only through that
//! environment's relay, enforcing the authority's grant, the IP guard, one
//! pinned resolution, TLS server-name agreement and byte budgets — the
//! broker's one outbound path, dialled only from `egress/tunnel.rs`. It
//! terminates no TLS, holds no CA and injects nothing. `--allow-evidence-egress`
//! swaps in the evidence's fixture resolver, loudly; production has none.
//!
//! [ADR-0050] adds `net.http`'s HTTPS client (`http`): one resolution per
//! host per request and one exchange per hop the authority authorised, to the
//! addresses the guard pinned — re-judged here — over `rustls` with
//! verification always on and Mozilla's roots compiled in, rendered and read
//! by `ureq-proto`'s framing with DireWolf's stricter checks, every bound and
//! deadline the broker's own. It follows no redirect, re-resolves nothing,
//! pools nothing and reads no proxy setting. Each hop's exchange runs in a
//! short-lived worker of this binary, `http-worker`, over the connection the
//! broker made: the long-lived broker never holds the request or a byte of
//! the response, and what the TLS and HTTP libraries freed goes with the
//! worker. Mode A's credential is read once from its one-shot pipe, handed to
//! the worker, composed into the one request it was authorised for and
//! scrubbed with it; an echo of it in the response is redacted before
//! anything of the response is encoded. `--allow-evidence-trust` replaces the
//! roots with a test authority, loudly, and only beside
//! `--allow-evidence-egress`'s fixture resolver; production has none.
//!
//! [ADR-0052] (M5d, in progress) runs one workload at a time in a `READY`
//! environment (`sandbox`, `workload_run`): the recorded container re-judged
//! from the runtime's record, the executable's bytes proved in the image,
//! exactly one command line run as the environment's user in `/workspace`
//! within its bounds, and then every other process of the environment ended
//! by its init, the trusted probe. And before it serves, the broker refuses
//! an identity an environment has (its own uid or the authority's being the
//! workload's or the relay's), and a deployment where a process of its uid
//! could trace a process it starts before that process hardens itself
//! (`posture`; ADR-0050 §21).
//!
//! [ADR-0044]: ../../../docs/adr/0044-m4c-filesystem-operations-plans-and-atomic-mutation.md
//! [ADR-0045]: ../../../docs/adr/0045-m4d-process-execution-broker.md
//! [ADR-0046]: ../../../docs/adr/0046-m4e-secret-handles-backends-injection-and-redaction.md
//! [ADR-0047]: ../../../docs/adr/0047-m5a-oci-execution-environment-and-measured-assurance.md
//! [ADR-0048]: ../../../docs/adr/0048-m5b-proxy-only-topology-and-connect-proxy.md
//! [ADR-0050]: ../../../docs/adr/0050-m5c-kernel-performed-net-http-ssrf-redirects-and-credential-egress.md
//! [ADR-0052]: ../../../docs/adr/0052-m5d-sandboxed-process-exec.md
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
#[cfg(target_os = "linux")]
mod http;
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
mod posture;
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
        Ok(Command::HttpWorker) => http_worker(),
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
    if let Err(why) = deployment(config, own_uid) {
        log(&why);
        return ExitCode::FAILURE;
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
    let (proxies, http) = match network(config, &place, own_uid) {
        Ok(network) => network,
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
            http: &http,
        },
    );
    ExitCode::SUCCESS
}

/// What the broker verifies about its own deployment before it serves: an
/// authority uid that is not its own unless the operator acknowledged it
/// for development (ADR-0043 §1); no daemon with an identity every
/// environment's workload or relay has — no flag overrides that (M5d,
/// ADR-0052 §13); and, as ADR-0050 §21 requires, no process of its uid able
/// to trace a process it starts before that process hardens itself, unless
/// the operator acknowledged it for development. Where its memory can go is
/// reported too (ADR-0053 §7): a broker whose memory can reach swap serves,
/// and refuses every hop that carries a credential unless the operator
/// acknowledged it -- a refusal said at start, never discovered by a hop.
/// The facts are read here; the decision is [`admit`]'s.
#[cfg(target_os = "linux")]
fn deployment(config: &config::ServeConfig, own_uid: u32) -> Result<(), String> {
    let posture = std::env::current_exe().map_or(
        posture::Posture {
            scope: None,
            execute_only: false,
            suid_dumpable: None,
        },
        |binary| posture::read(&binary),
    );
    let swap = posture::swap_of(None);
    crate::event(&format!(
        "deployment_posture {} swap={} {}",
        posture.describe(),
        swap.describe(),
        posture::page_zeroing_now()
    ));
    if !http::confine::VERIFIED_ARCHITECTURE {
        log(&format!(
            "NOTICE: net.http is refused on {}: the exchange worker's syscall program has no \
             kernel evidence on this architecture, and no worker runs without one (ADR-0053 \
             OD-7); every other tool is unaffected",
            std::env::consts::ARCH
        ));
    }
    for reduced in admit(config, own_uid, posture, &swap)? {
        log(&format!("REDUCED ASSURANCE: {reduced}"));
    }
    if !swap.protected() && config.swappable_workers == config::SwappableWorkers::Refused {
        log(
            "NOTICE: this broker's memory can be written to swap, so every net.http hop \
             that carries a credential is refused until it cannot: run the broker under \
             memory.swap.max = 0 (systemd: MemorySwapMax=0) or on a host without swap \
             (ADR-0053 §7)",
        );
    }
    Ok(())
}

/// The deployment decision, from the facts: why the broker may not serve,
/// or every reduced assurance the operator acknowledged, to be logged.
#[cfg(target_os = "linux")]
fn admit(
    config: &config::ServeConfig,
    own_uid: u32,
    posture: posture::Posture,
    swap: &posture::Swap,
) -> Result<Vec<String>, String> {
    let mut reduced = Vec::new();
    if own_uid == config.authority_uid {
        if !config.shared_uid_permitted {
            return Err(format!(
                "the authority uid {} is the broker's own; run the broker as its own user, or \
                 pass --allow-shared-authority-uid for development",
                config.authority_uid
            ));
        }
        reduced.push(format!(
            "the broker shares uid {own_uid} with the authority (--allow-shared-authority-uid)"
        ));
    }
    if let Some(clash) = posture::sandbox_identity_clash(own_uid, config.authority_uid) {
        return Err(format!("cannot serve: {clash}"));
    }
    if !posture.startup_window_closed() {
        match config.traceable_workers {
            config::TraceableWorkers::Refused => {
                return Err(
                    "cannot serve: Yama's ptrace_scope is 0 or absent, and this binary is \
                     readable by its own uid or fs.suid_dumpable is not 0 or 2 (1 starts even an \
                     execute-only image dumpable by its uid), so a process of the broker's uid \
                     could take over an exchange worker or a launch helper before it hardens \
                     itself (ADR-0050 §21, ADR-0053 §4). Set kernel.yama.ptrace_scope to 1 or \
                     more, install the broker root-owned and execute-only on a host whose \
                     fs.suid_dumpable is 0 or 2, or pass --allow-traceable-workers for \
                     development"
                        .to_owned(),
                );
            }
            config::TraceableWorkers::Permitted => reduced.push(
                "a process of the broker's uid may trace the processes it starts before they \
                 harden themselves (--allow-traceable-workers)"
                    .to_owned(),
            ),
        }
    }
    if !swap.protected() && config.swappable_workers == config::SwappableWorkers::Permitted {
        reduced.push(format!(
            "a credential exchange's memory, the broker's and its worker's, may be written to \
             swap ({}; --allow-swappable-workers)",
            swap.describe()
        ));
    }
    Ok(reduced)
}

/// The network side: one resolver for the CONNECT proxy and the HTTPS
/// client — one deadline, one in-flight bound, one evidence fixture or none
/// (ADR-0050 §6) — the proxies, and the client.
#[cfg(target_os = "linux")]
fn network(
    config: &config::ServeConfig,
    place: &listener::SocketPlace,
    own_uid: u32,
) -> Result<(std::sync::Arc<egress::proxy::Proxies>, http::Client), String> {
    let resolver = resolver(config)?;
    let proxies = proxies(config, place, own_uid, std::sync::Arc::clone(&resolver))?;
    let http = http_client(config, resolver)?;
    Ok((proxies, http))
}

/// The broker's one resolver: the host's — or, for the egress evidence only,
/// a fixture's, said loudly.
#[cfg(target_os = "linux")]
fn resolver(config: &config::ServeConfig) -> Result<egress::resolve::Shared, String> {
    Ok(match &config.evidence_egress {
        None => std::sync::Arc::new(egress::resolve::SystemResolver),
        Some(path) => {
            let fixture = egress::resolve::FixtureResolver::load(path)
                .map_err(|error| format!("the egress fixture: {error}"))?;
            log(
                "EVIDENCE EGRESS: the CONNECT proxy and the net.http client resolve names from a \
                 fixture file and may reach the loopback addresses it names \
                 (--allow-evidence-egress); this is the M5b and M5c evidence harnesses' \
                 resolver, never a production one",
            );
            std::sync::Arc::new(fixture)
        }
    })
}

/// The `net.http` client (M5c, ADR-0050 §9): Mozilla's roots — or, for the
/// evidence only, its own test authority instead, said loudly.
#[cfg(target_os = "linux")]
fn http_client(
    config: &config::ServeConfig,
    resolver: egress::resolve::Shared,
) -> Result<http::Client, String> {
    let trust = match &config.evidence_trust {
        None => {
            // Built once here, so a broker that could not trust anything
            // refuses to start rather than fail each hop.
            let trust = http::tls::Trust::Production;
            trust.config()?;
            trust
        }
        Some(path) => {
            let trust = http::tls::Trust::evidence(path)?;
            log(
                "EVIDENCE TRUST: the net.http client trusts the certificates in a test file \
                 INSTEAD OF Mozilla's roots (--allow-evidence-trust); this is the M5c evidence \
                 harness's trust anchor, never a production one",
            );
            trust
        }
    };
    // Each hop's exchange runs in a short-lived worker of this very binary
    // (ADR-0050 §9, D11), named now as the launch helper is.
    let worker = std::env::current_exe()
        .map_err(|e| format!("cannot name the broker binary for the exchange worker: {e}"))?;
    if worker.to_string_lossy().ends_with(" (deleted)") {
        return Err("the broker binary was replaced after it started".to_owned());
    }
    Ok(http::Client::new(
        resolver,
        trust,
        http::Deadlines::PRODUCTION,
        worker,
        http::WorkerPolicy::of_host(config.traceable_workers, config.swappable_workers),
    ))
}

/// The `PROXY_ONLY` proxies (M5b, ADR-0048), in the broker's own directory,
/// over the broker's one resolver. The evidence topology is announced here
/// too: both are the sandbox's evidence-only acknowledgements.
#[cfg(target_os = "linux")]
fn proxies(
    config: &config::ServeConfig,
    place: &listener::SocketPlace,
    own_uid: u32,
    resolver: egress::resolve::Shared,
) -> Result<std::sync::Arc<egress::proxy::Proxies>, String> {
    if config.evidence_topology_permitted {
        log(
            "EVIDENCE TOPOLOGY: NO_NETWORK execution environments may be prepared \
             (--allow-evidence-topology); this is the M5a evidence harness's topology, not a \
             production one",
        );
    }
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

#[cfg(target_os = "linux")]
fn http_worker() -> ExitCode {
    http::worker::serve()
}

#[cfg(not(target_os = "linux"))]
fn http_worker() -> ExitCode {
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
                              [--allow-traceable-workers] [--allow-swappable-workers]\n    \
                              [--allow-evidence-topology] [--allow-evidence-egress <FILE>]\n    \
                              [--allow-evidence-trust <PEM>]\n    \
             {NAME} [-V | --version] [-h | --help]\n\
         \n\
         OPTIONS:\n    \
             --socket <PATH>                 absolute path of the private socket\n    \
             --authority-uid <UID>           the only uid the broker reads from\n    \
             --allow-shared-authority-uid    permit the authority to be the broker's own uid (development only)\n    \
             --allow-dumpable                leave the process dumpable, its memory readable by its uid (development only)\n    \
             --allow-traceable-workers       serve where its uid could trace the processes it starts (development only)\n    \
             --allow-swappable-workers       perform credential hops where their memory could reach swap (development only)\n    \
             --allow-evidence-topology       permit NO_NETWORK execution environments (M5a evidence only)\n    \
             --allow-evidence-egress <FILE>  resolve egress names from a fixture file (M5b, M5c evidence only)\n    \
             --allow-evidence-trust <PEM>    trust a test authority instead of Mozilla's roots; needs --allow-evidence-egress (M5c evidence only)\n\
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
         NO_NETWORK only for evidence. M5c - net.http: one HTTPS exchange\n\
         per authorised hop to the pinned addresses, re-judged, with TLS\n\
         verification always on; no redirect followed, nothing re-resolved,\n\
         pooled or proxied; a credential composed into its one request. M5d\n\
         (in progress) - one authorised workload at a time in a READY\n\
         oci-strict environment, as uid 10001, bounded, every process it left\n\
         then ended; no daemon with an environment's uid; no traceable start-up\n\
         window. Linux only.\n",
        env!("CARGO_PKG_VERSION")
    )
}

#[cfg(test)]
mod tests {
    use super::{NAME, help};

    /// The deployment decision against every posture, on any host: what
    /// this machine's own Yama says does not decide what the test proves.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_broker_serves_only_a_deployment_it_can_vouch_for_or_one_acknowledged() {
        use super::admit;
        use super::config::{Command, ServeConfig, parse};
        use super::posture::{Posture, Swap};

        let serve = |authority: u32, flags: &[&str]| -> ServeConfig {
            let socket = std::env::temp_dir()
                .join("broker.sock")
                .display()
                .to_string();
            let mut args: Vec<String> = ["serve", "--socket", socket.as_str(), "--authority-uid"]
                .iter()
                .map(|s| (*s).to_owned())
                .collect();
            args.push(authority.to_string());
            args.extend(flags.iter().map(|s| (*s).to_owned()));
            let Ok(Command::Serve(config)) = parse(&args) else {
                unreachable!("a serve configuration")
            };
            config
        };
        // Where memory can go matters only to credential hops (below): every
        // case here is under a cap.
        let capped = Swap::Capped("/system.slice/dwkd-broker.service".to_owned());
        let posture = |scope, execute_only, suid_dumpable| Posture {
            scope,
            execute_only,
            suid_dumpable,
        };
        let (open, absent, yama) = (
            posture(Some(0), false, None),
            posture(None, false, None),
            posture(Some(1), false, None),
        );
        // An execute-only binary closes the window where `fs.suid_dumpable` is
        // 0 or 2 (dumpable by root only: closed to the broker's uid alike); 1
        // starts the image dumpable by its own uid, and unread is no better.
        let sealed = posture(Some(0), true, Some(0));
        let sealed_root_only = posture(Some(0), true, Some(2));
        let unsealed = posture(Some(0), true, Some(1));
        let unknown = posture(Some(0), true, None);
        // A posture that closes the window serves, with nothing reduced.
        for posture in [yama, sealed, sealed_root_only] {
            assert_eq!(
                admit(&serve(1000, &[]), 1001, posture, &capped),
                Ok(Vec::new())
            );
        }
        // An open window refuses, whatever else is right, unless acknowledged.
        for posture in [open, absent, unsealed, unknown] {
            let refused = admit(&serve(1000, &[]), 1001, posture, &capped);
            assert!(
                refused
                    .as_ref()
                    .is_err_and(|why| why.contains("ptrace_scope") && why.contains("ADR-0050")),
                "{refused:?}"
            );
            let acknowledged = admit(
                &serve(1000, &["--allow-traceable-workers"]),
                1001,
                posture,
                &capped,
            );
            assert!(
                acknowledged.as_ref().is_ok_and(|reduced| reduced.len() == 1
                    && reduced
                        .iter()
                        .all(|r| r.contains("--allow-traceable-workers"))),
                "{acknowledged:?}"
            );
        }
        // A shared uid refuses unless acknowledged, and is then reduced.
        assert!(
            admit(&serve(1001, &[]), 1001, yama, &capped)
                .is_err_and(|why| why.contains("own user"))
        );
        assert!(
            admit(
                &serve(1001, &["--allow-shared-authority-uid"]),
                1001,
                yama,
                &capped
            )
            .is_ok_and(|reduced| reduced.len() == 1)
        );
        // An environment's identity refuses, every flag and posture
        // notwithstanding: no acknowledgement covers it.
        let every = [
            "--allow-shared-authority-uid",
            "--allow-traceable-workers",
            "--allow-dumpable",
        ];
        for (own, authority) in [
            (10_001, 1000),
            (10_002, 1000),
            (1001, 10_001),
            (1001, 10_002),
        ] {
            for posture in [yama, sealed, open] {
                let refused = admit(&serve(authority, &every), own, posture, &capped);
                assert!(
                    refused
                        .as_ref()
                        .is_err_and(|why| why.contains("cannot serve")),
                    "{own} {authority} {posture:?}: {refused:?}"
                );
            }
        }
        assert!(admit(&serve(10_001, &every), 10_001, yama, &capped).is_err());
    }

    /// Memory that can reach swap never stops the broker serving: it stops
    /// credential hops (`http::WorkerPolicy`), unless acknowledged -- and the
    /// acknowledgement is reduced assurance, said at start.
    #[cfg(target_os = "linux")]
    #[test]
    fn swappable_memory_is_reduced_assurance_only_when_acknowledged() {
        use super::admit;
        use super::config::{Command, parse};
        use super::posture::{Posture, Swap};

        let serve = |flags: &[&str]| {
            let socket = std::env::temp_dir()
                .join("broker.sock")
                .display()
                .to_string();
            let mut args: Vec<String> = ["serve", "--socket", socket.as_str()]
                .iter()
                .map(|s| (*s).to_owned())
                .collect();
            args.extend(["--authority-uid".to_owned(), "1000".to_owned()]);
            args.extend(flags.iter().map(|s| (*s).to_owned()));
            let Ok(Command::Serve(config)) = parse(&args) else {
                unreachable!("a serve configuration")
            };
            config
        };
        let yama = Posture {
            scope: Some(1),
            execute_only: false,
            suid_dumpable: None,
        };
        for protected in [Swap::NoDevice, Swap::Capped("/a".to_owned())] {
            for flags in [&[][..], &["--allow-swappable-workers"][..]] {
                assert_eq!(admit(&serve(flags), 1001, yama, &protected), Ok(Vec::new()));
            }
        }
        assert_eq!(
            admit(&serve(&[]), 1001, yama, &Swap::Possible),
            Ok(Vec::new())
        );
        let reduced = admit(
            &serve(&["--allow-swappable-workers"]),
            1001,
            yama,
            &Swap::Possible,
        );
        assert!(
            reduced.as_ref().is_ok_and(|lines| lines.len() == 1
                && lines
                    .iter()
                    .all(|l| l.contains("--allow-swappable-workers"))),
            "{reduced:?}"
        );
    }

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
