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
//!
//! **Started, then collected** (M5d.2, ADR-0052 §8). The broker serves one
//! connection at a time, so no exchange may hold it for a workload's wall
//! clock: `broker.workload_start` re-judges the environment and proves the
//! executable, hands the run to a supervisor and answers at once with the
//! broker's generation; `broker.workload_collect`, a short exchange with no
//! descriptor, answers `RUNNING` or the ending. A broker of another
//! generation -- one that restarted -- supervises nothing of an earlier
//! one: its collection is indeterminate, and the authority ends the
//! workload `UNKNOWN` and destroys its environment.

use crate::brokerp::sandbox::{
    ContainerRef, EnvironmentProfile, ImageId, Milliseconds, NetworkTopology, StoreInstance,
    Verdict,
};
use crate::brokerp::{
    BrokerGeneration, BrokerRefusal, ChannelNonce, Common, DescriptorCount, EnvironmentSpec,
    KernelNumber, PrivateKind, ProcessArgs, ProcessStreamSnapshot, ProtocolVersion, RuntimeSpec,
    SecretDelivery, SecretEnvName, SecretHandle, StreamLimit,
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

/// How long a started workload may take before its collection is due, at
/// the most: the longest wall clock, and the environment operations' own
/// bound for the steps before and after it (the record's judgement, the
/// digests, `reap`). The broker's supervisor ends it by then; the authority
/// stops waiting for it then.
pub const WORKLOAD_SUPERVISION_SECONDS: u64 = 600 + super::ENVIRONMENT_DEADLINE_SECONDS;

/// The most workloads one broker supervises at once, started and not yet
/// collected. The authority runs one per environment; a start beyond this
/// is refused before anything runs (`WORKLOAD_TABLE_FULL`).
pub const MAX_SUPERVISED_WORKLOADS: usize = 16;

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

wire_int! {
    /// How many whole occurrences of a secret-bearing workload's value the
    /// broker replaced in its two streams while it drained them (M5d.3): a
    /// count, never a position or a byte of it.
    RedactionCount(u32), min = 0, max = 4_294_967_295
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

wire_enum! {
    /// How a workload is started in its environment (M5d.2, ADR-0052 §5a).
    /// The authority chooses it from the obligations it decided; the broker
    /// spells the one command line for each, and neither carries a variable.
    WorkloadLaunch {
        /// The runtime's `exec` runs the executable itself.
        Direct = "DIRECT",
        /// The runtime's `exec` runs the trusted probe as the launcher, which
        /// sets `workspace_exec_hygiene`'s fixed variables and executes the
        /// executable with exactly its arguments.
        Hygiene = "HYGIENE",
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
    /// How it is started.
    pub launch: WorkloadLaunch,
}

wire_struct! {
    /// Start one workload in an environment the authority recorded `READY`
    /// (ADR-0052 §§5, 8): re-judge the environment from the runtime's
    /// record and prove the executable's bytes in the image before the
    /// answer; then -- supervised, after it -- run exactly this, bound it,
    /// and have the environment's init end every other process in it. The
    /// environment's fields are a measurement's: the broker re-judges the
    /// record against them before anything runs.
    WorkloadStartAuthorisation: reject {
        /// Always `broker.workload_start`.
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
        /// How it is started: directly, or by the trusted launcher.
        required launch: WorkloadLaunch,
        /// Two: the runtime executable, then the working directory.
        required descriptors: DescriptorCount,
    }
}

wire_struct! {
    /// A workload's start: the environment re-judged, the executable proved,
    /// and the run handed to the supervisor of this broker generation.
    WorkloadStartDone: reject {
        /// The generation that supervises it: a collection names it.
        required generation: BrokerGeneration,
    }
}

wire_enum! {
    /// Where a started workload is, as its supervisor says.
    WorkloadProgress {
        /// It has not ended, or its residue is not yet proved.
        Running = "RUNNING",
        /// It ended and `reap` has run: the result says how -- or it never
        /// began, and the refusal says why.
        Ended = "ENDED",
    }
}

wire_struct! {
    /// Collect one workload this broker generation started. No descriptor:
    /// it is named by its invocation and its generation.
    WorkloadCollectAuthorisation: reject {
        /// Always `broker.workload_collect`.
        required kind: PrivateKind,
        /// The protocol version.
        required protocol: ProtocolVersion,
        /// The channel from this connection's hello.
        required channel: ChannelNonce,
        /// The workload's invocation: the one its start named.
        required invocation_id: InvocationId,
        /// The generation that started it.
        required generation: BrokerGeneration,
        /// None.
        required descriptors: DescriptorCount,
    }
}

wire_struct! {
    /// What a collection found. A refusal **of the collection** says
    /// nothing about the workload; a workload whose run never began -- the
    /// runtime's client could not be started after the start was answered
    /// -- is `ENDED` with the refusal here, in the answer's own body.
    WorkloadCollectDone: reject {
        /// Whether it has ended.
        required progress: WorkloadProgress,
        /// For `ENDED`: how it ran and ended.
        optional result: WorkloadRunDone,
        /// For `ENDED` without a result: why it never began. Nothing ran.
        optional never_ran: BrokerRefusal,
    }
}

impl WorkloadCollectAuthorisation {
    /// A collection of the workload `common` names, started by `generation`.
    #[must_use]
    pub fn new(common: Common, generation: BrokerGeneration) -> Self {
        Self {
            kind: PrivateKind::WorkloadCollect,
            protocol: ProtocolVersion(super::PROTOCOL),
            channel: common.channel,
            invocation_id: common.invocation_id,
            generation,
            descriptors: DescriptorCount(0),
        }
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
        /// For a secret-bearing workload (M5d.3) only: how many whole
        /// occurrences of its value the broker replaced in its output.
        optional redactions: RedactionCount,
    }
}

/// The secret a workload receives (M5d.3, ADR-0052 §7): the handle its
/// output is redacted under, how the launcher delivers it, and -- for mode B
/// -- the variable. The value is never here: it is the start's last
/// descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadSecret {
    /// The handle: the name `[redacted:<handle>]` reports.
    pub handle: SecretHandle,
    /// Mode B or mode C.
    pub delivery: SecretDelivery,
    /// For mode B: the variable. `None` for mode C.
    pub env_name: Option<SecretEnvName>,
}

wire_struct! {
    /// Start one workload that receives one secret (M5d.3, ADR-0052 §7):
    /// everything a `broker.workload_start` names, then the secret. The
    /// broker re-judges the environment and proves the executable **before**
    /// it reads the value -- a refusal reads nothing -- then reads it once
    /// from the last descriptor, and its trusted launcher in the environment
    /// receives it over the runtime's standard input, framed, and delivers it
    /// as the target's descriptor 3 (mode C) or one variable (mode B).
    WorkloadSecretStartAuthorisation: reject {
        /// Always `broker.workload_secret_start`.
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
        /// The SHA-256 of the probe the image must carry: it is the launcher,
        /// and it is run as `reap`.
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
        /// Whether the launcher also sets `workspace_exec_hygiene`'s
        /// variables (`HYGIENE`) or not (`DIRECT`). A secret-bearing workload
        /// is always started by the launcher.
        required launch: WorkloadLaunch,
        /// The handle whose value the last descriptor holds.
        required handle: SecretHandle,
        /// Mode B or mode C.
        required delivery: SecretDelivery,
        /// For mode B: the variable. Absent for mode C.
        optional env_name: SecretEnvName,
        /// Three: the runtime executable, the working directory, the secret
        /// pipe.
        required descriptors: DescriptorCount,
    }
}

impl WorkloadSecretStartAuthorisation {
    /// A start of `workload` in `container`, which should be `environment`,
    /// that delivers `secret`.
    #[must_use]
    pub fn new(
        common: Common,
        environment: EnvironmentSpec,
        (container, runtime): (ContainerRef, RuntimeSpec),
        workload: WorkloadSpec,
        secret: WorkloadSecret,
    ) -> Self {
        let start =
            WorkloadStartAuthorisation::new(common, environment, container, runtime, workload);
        Self {
            kind: PrivateKind::WorkloadSecretStart,
            protocol: start.protocol,
            channel: start.channel,
            invocation_id: start.invocation_id,
            environment_id: start.environment_id,
            run_id: start.run_id,
            store: start.store,
            profile: start.profile,
            network: start.network,
            image: start.image,
            probe_sha256: start.probe_sha256,
            workspace_path: start.workspace_path,
            workspace_device: start.workspace_device,
            workspace_inode: start.workspace_inode,
            container: start.container,
            runtime_socket: start.runtime_socket,
            runtime_argv0: start.runtime_argv0,
            runtime_device: start.runtime_device,
            runtime_inode: start.runtime_inode,
            runtime_sha256: start.runtime_sha256,
            cwd_device: start.cwd_device,
            cwd_inode: start.cwd_inode,
            relay_sha256: start.relay_sha256,
            executable: start.executable,
            executable_sha256: start.executable_sha256,
            args: start.args,
            stream_limit: start.stream_limit,
            wall_clock: start.wall_clock,
            launch: start.launch,
            handle: secret.handle,
            delivery: secret.delivery,
            env_name: secret.env_name,
            descriptors: DescriptorCount(3),
        }
    }

    /// The workload's start, without its secret: the environment, the
    /// runtime and the workload it names, exactly as a
    /// `broker.workload_start` would.
    #[must_use]
    pub fn start(&self) -> WorkloadStartAuthorisation {
        WorkloadStartAuthorisation {
            kind: PrivateKind::WorkloadStart,
            protocol: self.protocol,
            channel: self.channel.clone(),
            invocation_id: self.invocation_id.clone(),
            environment_id: self.environment_id.clone(),
            run_id: self.run_id.clone(),
            store: self.store.clone(),
            profile: self.profile,
            network: self.network,
            image: self.image.clone(),
            probe_sha256: self.probe_sha256.clone(),
            workspace_path: self.workspace_path.clone(),
            workspace_device: self.workspace_device.clone(),
            workspace_inode: self.workspace_inode.clone(),
            container: self.container.clone(),
            runtime_socket: self.runtime_socket.clone(),
            runtime_argv0: self.runtime_argv0.clone(),
            runtime_device: self.runtime_device.clone(),
            runtime_inode: self.runtime_inode.clone(),
            runtime_sha256: self.runtime_sha256.clone(),
            cwd_device: self.cwd_device.clone(),
            cwd_inode: self.cwd_inode.clone(),
            relay_sha256: self.relay_sha256.clone(),
            executable: self.executable.clone(),
            executable_sha256: self.executable_sha256.clone(),
            args: self.args.clone(),
            stream_limit: self.stream_limit,
            wall_clock: self.wall_clock,
            launch: self.launch,
            descriptors: DescriptorCount(2),
        }
    }

    /// The secret it delivers.
    #[must_use]
    pub fn secret(&self) -> WorkloadSecret {
        WorkloadSecret {
            handle: self.handle.clone(),
            delivery: self.delivery,
            env_name: self.env_name.clone(),
        }
    }
}

impl WorkloadStartAuthorisation {
    /// A start of `workload` in `container`, which should be `environment`.
    #[must_use]
    pub fn new(
        common: Common,
        environment: EnvironmentSpec,
        container: ContainerRef,
        runtime: RuntimeSpec,
        workload: WorkloadSpec,
    ) -> Self {
        Self {
            kind: PrivateKind::WorkloadStart,
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
            launch: workload.launch,
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
            launch: self.launch,
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
pub(super) fn check_start(run: &WorkloadStartAuthorisation) -> Result<(), ProtocolError> {
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

/// A secret-bearing start's own consistency: a start's, and a variable
/// exactly for mode B.
///
/// # Errors
///
/// The first inconsistency.
pub(super) fn check_secret_start(
    run: &WorkloadSecretStartAuthorisation,
) -> Result<(), ProtocolError> {
    check_start(&run.start())?;
    let consistent = match run.delivery {
        SecretDelivery::EnvAtSpawn => run.env_name.is_some(),
        SecretDelivery::FdAtSpawn => run.env_name.is_none(),
    };
    if !consistent {
        return Err(inconsistent(
            "/delivery",
            "an environment delivery names its variable and a descriptor delivery none",
        ));
    }
    if run
        .env_name
        .as_ref()
        .is_some_and(|name| !sandbox_secret_name_allowed(name.as_str()))
    {
        return Err(inconsistent(
            "/env_name",
            "a sandboxed secret's variable is one the environment sets",
        ));
    }
    Ok(())
}

/// The variables an execution environment sets for itself -- its egress
/// proxy's -- which a sandboxed mode B secret may never carry (M5d.3,
/// ADR-0052 §7). Together with the process-control names every secret
/// variable is refused ([`super::valid_secret_env_name`]: `GIT_*`,
/// `PYTHON*`, `CARGO_*`, `NPM_CONFIG_*`, a lowercase name), a value never
/// shadows the environment's configuration or `workspace_exec_hygiene`'s.
/// The environment's own lists are `dwk-sandbox-profile`'s, which the
/// authority does not link; a broker test holds this one to them.
pub const SANDBOX_RESERVED_SECRET_VARIABLES: &[&str] =
    &["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"];

/// Whether `name` may carry a sandboxed mode B secret: a secret variable's
/// shape, no process-control name, and none the environment sets.
#[must_use]
pub fn sandbox_secret_name_allowed(name: &str) -> bool {
    super::valid_secret_env_name(name) && !SANDBOX_RESERVED_SECRET_VARIABLES.contains(&name)
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

/// A collection's own consistency: a result exactly for `ENDED`, and that
/// result consistent.
///
/// # Errors
///
/// The first inconsistency.
pub fn check_collect(done: &WorkloadCollectDone) -> Result<(), ProtocolError> {
    match (done.progress, &done.result, done.never_ran) {
        (WorkloadProgress::Ended, Some(result), None) => check_done(result),
        (WorkloadProgress::Ended, None, Some(_)) | (WorkloadProgress::Running, None, None) => {
            Ok(())
        }
        _ => Err(inconsistent(
            "/result",
            "an ENDED workload has a result or the refusal it never began under, never both; \
             a RUNNING one has neither",
        )),
    }
}
