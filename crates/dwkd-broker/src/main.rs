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
//! # Status: M4d — process execution, the filesystem tools
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
//! which no build has before M6. Secrets arrive at M4e, the sandbox and
//! egress at M5.
//!
//! [ADR-0044]: ../../../docs/adr/0044-m4c-filesystem-operations-plans-and-atomic-mutation.md
//! [ADR-0045]: ../../../docs/adr/0045-m4d-process-execution-broker.md
//!
//! [ADR-0018]: ../../../docs/adr/0018-authority-broker-split.md
//! [ADR-0043]: ../../../docs/adr/0043-m4b-private-broker-channel-and-brokered-fs-read.md

// Pedantic lints on the security crates, per docs/LANGUAGE_SELECTION.md §7.
#![warn(clippy::pedantic)]

mod config;
#[cfg(target_os = "linux")]
mod crash;
#[cfg(target_os = "linux")]
mod exchange;
// Off Linux the broker does not serve, so nothing names the wire types; the
// manifest edge is acknowledged here for `unused_crate_dependencies`.
#[cfg(not(target_os = "linux"))]
use dwk_proto as _;
#[cfg(target_os = "linux")]
mod listener;
#[cfg(target_os = "linux")]
mod nonce;
#[cfg(target_os = "linux")]
mod process;

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
    listener::serve(
        &bound,
        config.authority_uid,
        own_uid,
        &mut channels,
        &processes,
    );
    ExitCode::SUCCESS
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
             {NAME} serve --socket <PATH> --authority-uid <UID> [--allow-shared-authority-uid]\n    \
             {NAME} [-V | --version] [-h | --help]\n\
         \n\
         OPTIONS:\n    \
             --socket <PATH>                 absolute path of the private socket\n    \
             --authority-uid <UID>           the only uid the broker reads from\n    \
             --allow-shared-authority-uid    permit the authority to be the broker's own uid (development only)\n\
         \n\
         STATUS: M4d - the filesystem tools (read, stat, list, search, write,\n\
         patch, move, delete) and process execution (start, status, kill) of the\n\
         executable the authority checked, by its descriptor, on the HOST with\n\
         the broker's own privileges. Linux only. No sandbox: that is M5;\n\
         secrets arrive at M4e.\n",
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
        assert!(h.contains("M4d") && h.contains("M5") && h.contains("HOST"));
        assert!(h.contains("--authority-uid"));
    }

    /// The broker's defining property, asserted as a test so that a future
    /// change which makes this crate a decider fails something.
    #[test]
    fn help_states_that_the_broker_decides_nothing() {
        assert!(help().contains("Decides nothing"));
    }
}
