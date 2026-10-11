//! A workload's private vocabulary (M5d, ADR-0052 §3): one bounded program
//! run in an environment the authority recorded `READY`, and how it ended.
//!
//! **Typed facts, never a command line.** A workload names the executable by
//! its path **inside the image** and the SHA-256 the operator pinned for it,
//! its arguments as exact bytes, one per-stream output bound and a wall clock
//! — and nothing else. No field is a runtime flag, a user, an environment
//! variable, a mount, a working directory or a shell string (TX036): the
//! broker spells the one command line itself (`sandbox/workload_plan.rs`,
//! TX050), and the user, the working directory and the environment are the
//! profile's.
//!
//! The answer says how the program ended, its bounded output, and the
//! **residue**: whether the environment's init then proved every other
//! process of the environment gone.

use crate::brokerp::sandbox::{
    ContainerRef, EnvironmentProfile, ImageId, Milliseconds, NetworkTopology, StoreInstance,
    Verdict,
};
use crate::brokerp::{
    ChannelNonce, Common, DescriptorCount, EnvironmentSpec, KernelNumber, PrivateKind, ProcessArgs,
    ProcessStreamSnapshot, ProtocolVersion, RuntimeSpec, StreamLimit,
};
use crate::error::{ProtocolError, Violation};
use crate::json::{Number, Value};
use crate::limits::MAX_SAFE_INTEGER;
use crate::schema::{Defs, int, obj, string};
use crate::wire::id::{EnvironmentId, InvocationId, RunId};
use crate::wire::macros::wire_struct;
use crate::wire::scalar::{
    ContentDigest, ExitCode, HostPath, SignalNumber, wire_enum, wire_int, wire_text,
};
use crate::wire::{Cx, WireType, expect_integer, expect_string};

/// The longest wall clock a workload may be given, in seconds (SANDBOX.md
/// §2's `timeout`).
pub const WORKLOAD_MAX_SECONDS: u32 = 600;

/// How long one `broker.workload_run` exchange may take on the private
/// channel, both sides: the longest wall clock, and the environment
/// operations' own bound for the steps before and after it (the record's
/// judgement, the digests, `reap`).
pub const WORKLOAD_DEADLINE_SECONDS: u64 = 600 + super::ENVIRONMENT_DEADLINE_SECONDS;

const _: () = assert!(WORKLOAD_MAX_SECONDS == 600);

/// The most bytes of a path inside an image.
pub const MAX_IMAGE_PATH_BYTES: usize = 255;

/// The most processes a `reap` reports: the environment's pids limit, with
/// room.
pub const MAX_REAPED_PROCESSES: u32 = 4096;

/// A path inside an image: `/`, then components of `[A-Za-z0-9._+-]`, none
/// of them `.` or `..`, no empty component, no trailing `/`. Narrower than a
/// file name may be, on purpose: it is spelled into the runtime client's
/// argument vector (`container exec`, `container cp <id>:<path>`), and no
/// character in it may mean anything to the client but a name.
fn valid_image_path(s: &str) -> bool {
    s.len() <= MAX_IMAGE_PATH_BYTES
        && s.len() > 1
        && s.starts_with('/')
        && !s.ends_with('/')
        && s.split('/').skip(1).all(|component| {
            !component.is_empty()
                && component != "."
                && component != ".."
                && component
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-'))
        })
}

wire_text! {
    /// An absolute path inside the environment's image, in its one plain
    /// spelling (see `valid_image_path`).
    ImagePath,
    max_chars = 255,
    pattern = Some("^(?:/[A-Za-z0-9._+-]+)+$"),
    format = None,
    validate = valid_image_path
}

impl ImagePath {
    /// Its last component: the name the runtime gives the file when it copies
    /// it out.
    #[must_use]
    pub fn file_name(&self) -> &str {
        self.as_str().rsplit('/').next().unwrap_or_default()
    }
}

wire_int! {
    /// A workload's wall clock, in seconds: 1 to [`WORKLOAD_MAX_SECONDS`].
    WorkloadSeconds(u32), min = 1, max = 600
}

const _: () = assert!(WorkloadSeconds::MAX == WORKLOAD_MAX_SECONDS);

wire_int! {
    /// A count of processes an environment's init ended or found.
    ProcessCount(u32), min = 0, max = 4096
}

wire_enum! {
    /// How a workload ended — or why that is not known. A lost environment is
    /// never mistaken for a program that finished (SANDBOX.md §1).
    WorkloadEnding {
        /// It exited; `exit_code` says how.
        Exited = "EXITED",
        /// A signal ended it; `signal` says which.
        Killed = "KILLED",
        /// It outran its wall clock and was ended.
        TimedOut = "TIMED_OUT",
        /// The environment is gone or no longer running.
        EnvironmentGone = "ENVIRONMENT_GONE",
        /// The container runtime could not be reached afterwards.
        RuntimeUnavailable = "RUNTIME_UNAVAILABLE",
        /// Nothing observable says how it ended.
        Unobservable = "UNOBSERVABLE",
    }
}

/// A workload, as the authority decided it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadSpec {
    /// The executable's path inside the image.
    pub executable: ImagePath,
    /// Its SHA-256, from the operator's image manifest.
    pub executable_sha256: ContentDigest,
    /// The arguments after `argv[0]`.
    pub args: ProcessArgs,
    /// How many bytes of each output stream come back.
    pub stream_limit: StreamLimit,
    /// The wall clock.
    pub wall_clock: WorkloadSeconds,
}

wire_struct! {
    /// Run one workload in an environment the authority recorded `READY`
    /// (ADR-0052 §5): re-judge the environment from the runtime's record,
    /// prove the executable's bytes in the image, run exactly this, bound
    /// it, then have the environment's init end every other process in it.
    /// The environment's fields are a measurement's: the broker re-judges
    /// the record against them before anything runs.
    WorkloadRunAuthorisation: reject {
        /// Always `broker.workload_run`.
        required kind: PrivateKind,
        /// The protocol version.
        required protocol: ProtocolVersion,
        /// The channel from this connection's hello.
        required channel: ChannelNonce,
        /// The authority's id for the invocation.
        required invocation_id: InvocationId,
        /// The environment.
        required environment_id: EnvironmentId,
        /// The run it is for.
        required run_id: RunId,
        /// The authority store it belongs to.
        required store: StoreInstance,
        /// The profile.
        required profile: EnvironmentProfile,
        /// The network topology.
        required network: NetworkTopology,
        /// The image, by content digest.
        required image: ImageId,
        /// The SHA-256 of the probe the image must carry: it is run as `reap`.
        required probe_sha256: ContentDigest,
        /// The workspace directory.
        required workspace_path: HostPath,
        /// Its device.
        required workspace_device: KernelNumber,
        /// Its inode.
        required workspace_inode: KernelNumber,
        /// The container the authority recorded.
        required container: ContainerRef,
        /// The container runtime's control socket.
        required runtime_socket: HostPath,
        /// `argv[0]` for the runtime.
        required runtime_argv0: HostPath,
        /// The runtime executable's device.
        required runtime_device: KernelNumber,
        /// The runtime executable's inode.
        required runtime_inode: KernelNumber,
        /// Its SHA-256.
        required runtime_sha256: ContentDigest,
        /// The working directory's device.
        required cwd_device: KernelNumber,
        /// The working directory's inode.
        required cwd_inode: KernelNumber,
        /// `PROXY_ONLY` only: the relay's SHA-256, judged again.
        optional relay_sha256: ContentDigest,
        /// The executable's path inside the image.
        required executable: ImagePath,
        /// The SHA-256 its bytes must have.
        required executable_sha256: ContentDigest,
        /// The arguments after `argv[0]`.
        required args: ProcessArgs,
        /// How many bytes of each output stream come back.
        required stream_limit: StreamLimit,
        /// The wall clock.
        required wall_clock: WorkloadSeconds,
        /// Two: the runtime executable, then the working directory.
        required descriptors: DescriptorCount,
    }
}

wire_struct! {
    /// How one workload ended, what it wrote, and what was left.
    WorkloadRunDone: reject {
        /// How it ended.
        required ending: WorkloadEnding,
        /// For `EXITED`: the code.
        optional exit_code: ExitCode,
        /// For `KILLED`: the signal.
        optional signal: SignalNumber,
        /// Its standard output, to the bound.
        required stdout: ProcessStreamSnapshot,
        /// Its standard error, to the bound.
        required stderr: ProcessStreamSnapshot,
        /// How long it ran, from the `exec` to its end.
        required elapsed_ms: Milliseconds,
        /// Whether the environment's init then proved every other process
        /// gone (`PASS`), found some it could not end (`FAIL`), or could not
        /// say (`UNOBSERVABLE`).
        required residue: Verdict,
        /// How many processes, besides init, `reap` found and ended.
        required ended_processes: ProcessCount,
        /// How many remained after it.
        required remaining_processes: ProcessCount,
    }
}

impl WorkloadRunAuthorisation {
    /// A run of `workload` in `container`, which should be `environment`.
    #[must_use]
    pub fn new(
        common: Common,
        environment: EnvironmentSpec,
        container: ContainerRef,
        runtime: RuntimeSpec,
        workload: WorkloadSpec,
    ) -> Self {
        Self {
            kind: PrivateKind::WorkloadRun,
            protocol: ProtocolVersion(super::PROTOCOL),
            channel: common.channel,
            invocation_id: common.invocation_id,
            environment_id: environment.environment_id,
            run_id: environment.run_id,
            store: environment.store,
            profile: environment.profile,
            network: environment.network,
            image: environment.image,
            probe_sha256: environment.probe_sha256,
            workspace_path: environment.workspace_path,
            workspace_device: KernelNumber::from_u64(environment.workspace.0),
            workspace_inode: KernelNumber::from_u64(environment.workspace.1),
            container,
            runtime_socket: runtime.socket,
            runtime_argv0: runtime.argv0,
            runtime_device: KernelNumber::from_u64(runtime.executable.0),
            runtime_inode: KernelNumber::from_u64(runtime.executable.1),
            runtime_sha256: runtime.sha256,
            cwd_device: KernelNumber::from_u64(runtime.cwd.0),
            cwd_inode: KernelNumber::from_u64(runtime.cwd.1),
            relay_sha256: environment.relay_sha256,
            executable: workload.executable,
            executable_sha256: workload.executable_sha256,
            args: workload.args,
            stream_limit: workload.stream_limit,
            wall_clock: workload.wall_clock,
            descriptors: DescriptorCount(2),
        }
    }

    /// The environment it names. A workload carries no grant: the proxy
    /// already holds the one the environment was prepared with.
    #[must_use]
    pub fn environment(&self) -> EnvironmentSpec {
        EnvironmentSpec {
            environment_id: self.environment_id.clone(),
            run_id: self.run_id.clone(),
            store: self.store.clone(),
            profile: self.profile,
            network: self.network,
            image: self.image.clone(),
            probe_sha256: self.probe_sha256.clone(),
            workspace_path: self.workspace_path.clone(),
            workspace: (self.workspace_device.value(), self.workspace_inode.value()),
            relay_sha256: self.relay_sha256.clone(),
            egress: None,
        }
    }

    /// The runtime it names.
    #[must_use]
    pub fn runtime(&self) -> RuntimeSpec {
        RuntimeSpec {
            socket: self.runtime_socket.clone(),
            argv0: self.runtime_argv0.clone(),
            executable: (self.runtime_device.value(), self.runtime_inode.value()),
            sha256: self.runtime_sha256.clone(),
            cwd: (self.cwd_device.value(), self.cwd_inode.value()),
        }
    }

    /// The workload it names.
    #[must_use]
    pub fn workload(&self) -> WorkloadSpec {
        WorkloadSpec {
            executable: self.executable.clone(),
            executable_sha256: self.executable_sha256.clone(),
            args: self.args.clone(),
            stream_limit: self.stream_limit,
            wall_clock: self.wall_clock,
        }
    }
}

fn inconsistent(path: &str, why: &str) -> ProtocolError {
    ProtocolError::schema(Violation::Inconsistent, path, why)
}

/// The authorisation's own consistency, beyond its fields' types.
///
/// # Errors
///
/// The first inconsistency.
pub(super) fn check_run(run: &WorkloadRunAuthorisation) -> Result<(), ProtocolError> {
    if super::process_argv_bytes(&run.args) > crate::limits::MAX_PROCESS_ARGV_BYTES {
        return Err(ProtocolError::schema(
            Violation::TooLong,
            "/args",
            "the arguments hold more than one launch may carry",
        ));
    }
    // A relay digest exactly for `PROXY_ONLY`.
    if (run.network == NetworkTopology::ProxyOnly) != run.relay_sha256.is_some() {
        return Err(inconsistent(
            "/relay_sha256",
            "a PROXY_ONLY environment names its relay, and only it does",
        ));
    }
    Ok(())
}

/// The result's own consistency: an exit code exactly for `EXITED`, a signal
/// exactly for `KILLED`, no more remaining than found, and `PASS` only with
/// none remaining.
///
/// # Errors
///
/// The first inconsistency.
pub fn check_done(done: &WorkloadRunDone) -> Result<(), ProtocolError> {
    if (done.ending == WorkloadEnding::Exited) != done.exit_code.is_some() {
        return Err(inconsistent(
            "/exit_code",
            "an exit code exactly for EXITED",
        ));
    }
    if (done.ending == WorkloadEnding::Killed) != done.signal.is_some() {
        return Err(inconsistent("/signal", "a signal exactly for KILLED"));
    }
    if done.residue == Verdict::Pass && done.remaining_processes.get() != 0 {
        return Err(inconsistent(
            "/residue",
            "a clean residue leaves no process remaining",
        ));
    }
    Ok(())
}
