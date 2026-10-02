//! The `oci` execution environment (M5a, ADR-0047 §4): an `oci-strict`
//! container, made and measured through the container runtime's own client.
//!
//! The client is the executable the authority resolved, hashed and handed
//! over, re-proved here through that very descriptor, and executed — once
//! per step, through a duplicate of it — by the M4d launch helper: an
//! environment built from nothing, the helper's limits, its own process
//! group, no inherited descriptor, and a typed argument vector from
//! [`super::plan`]. No shell, no path search, no string that is parsed as a
//! command line. Between steps the descriptor is proved unchanged (`fstat`:
//! the same object, size and times), so a rewrite between two steps refuses
//! the next one instead of running it.
//!
//! What each step's answer is trusted for is stated where it is read: a
//! container id, one version line, the runtime's record (judged by
//! [`super::inspect`]), the probe's bytes (judged by [`super::digest`]) and
//! the probe's report (decoded strictly, or `UNOBSERVABLE`). Nothing the
//! runtime or the probe prints reaches a log; only its length does.

use std::os::fd::OwnedFd;
use std::path::Path;
use std::time::{Duration, Instant};

use dwk_proto::brokerp::sandbox::{
    AssuranceLevel, ContainerRef, MAX_PROBE_REPORT_BYTES, Milliseconds, NetworkTopology,
    ProbeReport, RuntimeVersion, SandboxInvariant, StoreInstance, Verdict,
};
use dwk_proto::brokerp::{BrokerRefusal, ContainerState, EnvironmentSpec, RuntimeSpec};
use dwk_proto::wire::id::{EnvironmentId, RunId};
use rustix::fs::Stat;

use crate::process::launch::Program;
use crate::process::run::{self, Bounds, Completed, Ended};
use crate::process::verify::{self, Authorised};

use super::environment::{
    Destroyed, EnvFailure, EnvHandle, ExecOutcome, ExecutionEnvironment, Listed, Measured, Prepared,
};
use super::{Checks, digest, inspect, plan};

/// The longest one runtime step may take.
const STEP: Duration = Duration::from_secs(60);

/// The longest the probe may take to measure, inside the environment: it
/// normally needs well under a second, and one that takes longer is not
/// believed (`UNOBSERVABLE`).
const PROBE_STEP: Duration = Duration::from_secs(30);

/// The most bytes of a one-line answer: a container id, a version.
const LINE: usize = 4096;

/// The most stderr bytes kept. Counted, never logged.
const STDERR: usize = 4096;

/// The most environments one listing reports.
const MAX_LISTED: usize = 64;

/// The container runtime's client, re-proved and held for one exchange.
pub(crate) struct Runtime<'a> {
    helper: &'a Path,
    executable: OwnedFd,
    proved: Stat,
    cwd: OwnedFd,
    argv0: Vec<u8>,
    host: String,
    config: String,
    until: Instant,
}

fn stat_key(st: &Stat) -> (u64, u64, i128, i128, i128, i128, i128) {
    (
        st.st_dev,
        st.st_ino,
        i128::from(st.st_size),
        i128::from(st.st_mtime),
        i128::from(st.st_mtime_nsec),
        i128::from(st.st_ctime),
        i128::from(st.st_ctime_nsec),
    )
}

impl<'a> Runtime<'a> {
    /// Re-prove the runtime's two descriptors — the executable is the object
    /// the authority hashed, still trusted, and still those bytes; the
    /// working directory is the one it opened — and hold them until `until`.
    ///
    /// # Errors
    ///
    /// The refusal: nothing is run.
    pub(crate) fn new(
        helper: &'a Path,
        (executable, cwd): (OwnedFd, OwnedFd),
        runtime: &RuntimeSpec,
        (config, authority_uid): (&Path, u32),
        until: Instant,
    ) -> Result<Self, BrokerRefusal> {
        verify::identities(
            &Authorised {
                executable: runtime.executable,
                sha256: runtime.sha256.as_str(),
                cwd: runtime.cwd,
            },
            &executable,
            &cwd,
            authority_uid,
        )?;
        let proved = rustix::fs::fstat(&executable).map_err(|_| BrokerRefusal::ReadFailed)?;
        let socket = runtime.socket.as_str();
        if !socket.starts_with('/') || socket.chars().any(char::is_control) {
            return Err(BrokerRefusal::Unsupported);
        }
        let config = config
            .to_str()
            .ok_or(BrokerRefusal::Unsupported)?
            .to_owned();
        Ok(Self {
            helper,
            executable,
            proved,
            cwd,
            argv0: runtime.argv0.as_str().as_bytes().to_vec(),
            host: format!("unix://{socket}"),
            config,
            until,
        })
    }

    /// Run one step: `words` after the client's fixed global options.
    fn call(&self, words: Vec<String>, stdout: usize) -> Result<Completed, run::Failure> {
        self.call_within(words, stdout, STEP)
    }

    /// One step, bounded by `step` as well as by the exchange.
    fn call_within(
        &self,
        words: Vec<String>,
        stdout: usize,
        step: Duration,
    ) -> Result<Completed, run::Failure> {
        let limit = step;
        let step = step_name(&words);
        let refused = |why| run::Failure::Refused(why);
        let now =
            rustix::fs::fstat(&self.executable).map_err(|_| refused(BrokerRefusal::ReadFailed))?;
        if stat_key(&now) != stat_key(&self.proved) {
            return Err(refused(BrokerRefusal::DigestMismatch));
        }
        let executable = rustix::io::fcntl_dupfd_cloexec(&self.executable, 0)
            .map_err(|_| refused(BrokerRefusal::ExecSetupFailed))?;
        let cwd = rustix::io::fcntl_dupfd_cloexec(&self.cwd, 0)
            .map_err(|_| refused(BrokerRefusal::ExecSetupFailed))?;
        let mut argv = vec![
            self.argv0.clone(),
            b"--host".to_vec(),
            self.host.clone().into_bytes(),
            b"--config".to_vec(),
            self.config.clone().into_bytes(),
        ];
        argv.extend(words.into_iter().map(String::into_bytes));
        let program = Program {
            argv,
            // The client's home is the broker's empty private directory: no
            // user configuration, credential helper or context is read.
            envp: vec![format!("HOME={}", self.config).into_bytes()],
        };
        let deadline = self.until.min(Instant::now() + limit);
        let result = run::run(
            self.helper,
            &program,
            executable,
            cwd,
            &Bounds {
                stdout,
                stderr: STDERR,
                deadline,
            },
        );
        if let Ok(done) = &result
            && done.ended != Ended::Exited(0)
        {
            report(&step, done);
        }
        result
    }
}

/// The step's name, for an event: its first word or two, never a value.
fn step_name(words: &[String]) -> String {
    let mut name: Vec<&str> = words.iter().take(1).map(String::as_str).collect();
    if let Some(second) = words.get(1)
        && !second.starts_with('-')
        && name
            .first()
            .is_some_and(|w| *w == "container" || *w == "image")
    {
        name.push(second);
    }
    name.join("_")
}

/// One event for a step that did not exit 0: which step, how it ended and
/// how much it wrote to stderr. In a debug build — the evidence harness's —
/// also the first line of that stderr, printable ASCII only, for diagnosis.
/// Never anything it wrote to stdout.
fn report(step: &str, done: &Completed) {
    let detail = if cfg!(debug_assertions) {
        let first = done
            .stderr
            .split(|b| *b == b'\n')
            .next()
            .unwrap_or_default();
        let text: String = first
            .iter()
            .take(200)
            .map(|b| {
                if b.is_ascii_graphic() || *b == b' ' {
                    char::from(*b)
                } else {
                    '?'
                }
            })
            .collect();
        format!(" stderr={text:?}")
    } else {
        String::new()
    };
    crate::event(&format!(
        "runtime_step step={step} ended={:?} stderr_bytes={}{detail}",
        done.ended,
        done.stderr.len()
    ));
}

/// Exited 0, with all of its stdout.
fn succeeded(done: &Completed) -> bool {
    done.ended == Ended::Exited(0) && !done.stdout_cut
}

/// Exactly one line of UTF-8, newline-terminated.
fn one_line(stdout: &[u8]) -> Option<&str> {
    let text = core::str::from_utf8(stdout).ok()?;
    let line = text.strip_suffix('\n')?;
    (!line.contains('\n') && !line.is_empty()).then_some(line)
}

/// Every non-empty line of UTF-8.
fn lines(stdout: &[u8]) -> Option<Vec<&str>> {
    let text = core::str::from_utf8(stdout).ok()?;
    Some(text.lines().filter(|l| !l.is_empty()).collect())
}

/// The `oci` environment over one held runtime.
pub(crate) struct Oci<'a> {
    runtime: Runtime<'a>,
    seccomp_path: &'a str,
    seccomp_profile: &'a str,
    socket: String,
}

impl<'a> Oci<'a> {
    /// The environment kind, over `runtime`, with the profile file the
    /// listener wrote and the profile text it holds.
    pub(crate) fn new(
        runtime: Runtime<'a>,
        (seccomp_path, seccomp_profile): (&'a str, &'a str),
        socket: &str,
    ) -> Self {
        Self {
            runtime,
            seccomp_path,
            seccomp_profile,
            socket: socket.to_owned(),
        }
    }

    /// The runtime's version: the proof it answers at all.
    fn version(&self) -> Result<RuntimeVersion, EnvFailure> {
        match self.runtime.call(plan::version(), LINE) {
            Ok(done) if succeeded(&done) => one_line(&done.stdout)
                .and_then(|v| RuntimeVersion::new(v.to_owned()))
                .ok_or(EnvFailure::Refused(BrokerRefusal::RuntimeOutputMalformed)),
            Ok(_) | Err(run::Failure::Unconfirmed) => {
                Err(EnvFailure::Refused(BrokerRefusal::RuntimeUnavailable))
            }
            Err(run::Failure::Refused(why)) => Err(EnvFailure::Refused(why)),
        }
    }

    /// The pinned image is present, by that exact id. Never pulled.
    fn image_present(&self, spec: &EnvironmentSpec) -> Result<(), EnvFailure> {
        match self.runtime.call(plan::image_id(spec), LINE) {
            Ok(done) if succeeded(&done) && one_line(&done.stdout) == Some(spec.image.as_str()) => {
                Ok(())
            }
            Ok(_) | Err(run::Failure::Unconfirmed) => {
                Err(EnvFailure::Refused(BrokerRefusal::ImageMissing))
            }
            Err(run::Failure::Refused(why)) => Err(EnvFailure::Refused(why)),
        }
    }

    /// The runtime's record of `container`, or `None` when it has none.
    fn record(
        &self,
        container: &ContainerRef,
    ) -> Result<Option<dwk_proto::json::Object>, EnvFailure> {
        let malformed = EnvFailure::Refused(BrokerRefusal::RuntimeOutputMalformed);
        match self
            .runtime
            .call(plan::inspect(&[container]), inspect::MAX_INSPECT_BYTES)
        {
            Ok(done) if succeeded(&done) => {
                let mut records = inspect::parse(&done.stdout).map_err(|()| malformed)?;
                if records.len() != 1 {
                    return Err(malformed);
                }
                let object = records.remove(0);
                if inspect::Record::new(&object).id().as_ref() != Some(container) {
                    return Err(malformed);
                }
                Ok(Some(object))
            }
            // The runtime answers an unknown container with an empty array.
            Ok(done)
                if !done.stdout_cut && inspect::parse(&done.stdout).is_ok_and(|r| r.is_empty()) =>
            {
                Ok(None)
            }
            Ok(_) | Err(run::Failure::Unconfirmed) => {
                Err(EnvFailure::Refused(BrokerRefusal::RuntimeUnavailable))
            }
            Err(run::Failure::Refused(why)) => Err(EnvFailure::Refused(why)),
        }
    }

    /// Every container labelled as `store`'s (and `environment`'s).
    fn owned_ids(
        &self,
        store: &StoreInstance,
        environment: Option<(&EnvironmentId, &RunId)>,
    ) -> Result<(Vec<ContainerRef>, bool), EnvFailure> {
        let bound = (MAX_LISTED + 1) * 65;
        match self.runtime.call(plan::owned(store, environment), bound) {
            Ok(done) if done.ended == Ended::Exited(0) => {
                let found = lines(&done.stdout)
                    .and_then(|lines| {
                        lines
                            .into_iter()
                            .map(|l| ContainerRef::new(l.to_owned()))
                            .collect::<Option<Vec<_>>>()
                    })
                    .ok_or(EnvFailure::Refused(BrokerRefusal::RuntimeOutputMalformed))?;
                let complete = !done.stdout_cut && found.len() <= MAX_LISTED;
                Ok((found.into_iter().take(MAX_LISTED).collect(), complete))
            }
            Ok(_) | Err(run::Failure::Unconfirmed) => {
                Err(EnvFailure::Refused(BrokerRefusal::RuntimeUnavailable))
            }
            Err(run::Failure::Refused(why)) => Err(EnvFailure::Refused(why)),
        }
    }

    /// Remove `container`, and prove it is gone.
    fn remove(&self, container: &ContainerRef) -> Result<(), EnvFailure> {
        crate::crash::point("environment_removing");
        match self.runtime.call(plan::remove(container), LINE) {
            Err(run::Failure::Refused(why)) => return Err(EnvFailure::Refused(why)),
            Ok(_) | Err(run::Failure::Unconfirmed) => {}
        }
        match self.record(container) {
            Ok(None) => Ok(()),
            _ => Err(EnvFailure::Unconfirmed),
        }
    }

    /// A creation that failed or cannot be confirmed: remove whatever the
    /// runtime made under this environment's labels, and say what is known.
    fn abandon(&self, spec: &EnvironmentSpec) -> Result<Prepared, EnvFailure> {
        let Ok((made, complete)) =
            self.owned_ids(&spec.store, Some((&spec.environment_id, &spec.run_id)))
        else {
            return Err(EnvFailure::Unconfirmed);
        };
        if !complete {
            return Err(EnvFailure::Unconfirmed);
        }
        for container in &made {
            if self.remove(container).is_err() {
                return Err(EnvFailure::Unconfirmed);
            }
        }
        Err(EnvFailure::Refused(BrokerRefusal::RuntimeFailed))
    }

    /// The probe's bytes, from outside, against the pinned digest.
    fn probe_digest(&self, container: &ContainerRef, spec: &EnvironmentSpec) -> Verdict {
        match self
            .runtime
            .call(plan::copy_probe(container), digest::MAX_ARCHIVE_BYTES)
        {
            Ok(done) if done.stdout_cut => Verdict::Fail,
            Ok(done) if succeeded(&done) => digest::probe(&done.stdout, spec.probe_sha256.as_str()),
            _ => Verdict::Unobservable,
        }
    }

    /// How a step inside the environment that did not exit 0 ended — or
    /// why that cannot be said. The client's own failures share exit codes
    /// with the program's, so the runtime and the container are asked.
    fn after(&self, container: &ContainerRef, ended: Ended) -> ExecOutcome {
        match ended {
            Ended::Exited(0) => return ExecOutcome::Exited(0),
            Ended::TimedOut => return ExecOutcome::TimedOut,
            // The client itself was killed: nothing says what happened inside.
            Ended::Signaled(_) => return ExecOutcome::Unobservable,
            Ended::Exited(_) => {}
        }
        if self.version().is_err() {
            return ExecOutcome::RuntimeUnavailable;
        }
        let running = match self.record(container) {
            Ok(Some(object)) => {
                inspect::Record::new(&object).state() == Some(ContainerState::Running)
            }
            Ok(None) => false,
            Err(_) => return ExecOutcome::Unobservable,
        };
        let Ended::Exited(code) = ended else {
            return ExecOutcome::Unobservable;
        };
        classify(code, running)
    }

    /// The measurement of a container this broker has proved is labelled as
    /// `spec`'s environment.
    fn judge(
        &self,
        handle: &EnvHandle,
        spec: &EnvironmentSpec,
        record: &inspect::Record<'_>,
        state: ContainerState,
    ) -> Result<Checks, EnvFailure> {
        let mut checks = record.judge(spec, self.seccomp_profile, &self.socket);
        let mut report = None;
        let digest = if state == ContainerState::Running {
            let digest = self.probe_digest(&handle.container, spec);
            // A probe that is not the pinned one is never run: nothing it
            // could print would be evidence.
            if digest == Verdict::Pass {
                let (outcome, stdout) = self.run_probe(handle, spec)?;
                if outcome == ExecOutcome::Exited(0) {
                    report = ProbeReport::decode_bytes(&stdout).ok();
                }
            }
            digest
        } else {
            Verdict::Unobservable
        };
        checks.push((SandboxInvariant::HostProbeDigest, digest));
        let workspace = report.as_ref().map_or(Verdict::Unobservable, |r| {
            match (&r.workspace_device, &r.workspace_inode) {
                (Some(dev), Some(ino)) if (dev.value(), ino.value()) == spec.workspace => {
                    Verdict::Pass
                }
                (Some(_), Some(_)) => Verdict::Fail,
                _ => Verdict::Unobservable,
            }
        });
        checks.push((SandboxInvariant::HostWorkspaceIdentity, workspace));
        for invariant in dwk_proto::brokerp::sandbox::probe_invariants() {
            let verdict = report
                .as_ref()
                .and_then(|r| r.checks.iter().find(|c| c.invariant == invariant))
                .map_or(Verdict::Unobservable, |c| c.verdict);
            checks.push((invariant, verdict));
        }
        Ok(order(&checks))
    }
}

/// A non-zero exit of a step inside a container that is still `running`
/// (or not).
fn classify(code: u8, running: bool) -> ExecOutcome {
    if !running {
        return ExecOutcome::EnvironmentGone;
    }
    match code {
        // The runtime could not start the program: it did not end, it never
        // began, and the client cannot say which of its own failures it was.
        126 | 127 => ExecOutcome::Unobservable,
        129..=192 => ExecOutcome::Killed(code - 128),
        _ => ExecOutcome::Exited(code),
    }
}

/// `checks` in the profile's declaration order, one each; any invariant
/// missing is `UNOBSERVABLE`.
fn order(checks: &[(SandboxInvariant, Verdict)]) -> Checks {
    SandboxInvariant::ALL
        .iter()
        .map(|invariant| {
            let verdict = checks
                .iter()
                .find(|(i, _)| i == invariant)
                .map_or(Verdict::Unobservable, |(_, v)| *v);
            (*invariant, verdict)
        })
        .collect()
}

/// Whether every required invariant passed.
pub(crate) fn clean(checks: &Checks, topology: NetworkTopology) -> bool {
    dwk_proto::brokerp::sandbox::required_invariants(topology)
        .iter()
        .all(|invariant| checks.contains(&(*invariant, Verdict::Pass)))
}

impl ExecutionEnvironment for Oci<'_> {
    fn declared(&self) -> AssuranceLevel {
        AssuranceLevel::ContainerIsolation
    }

    fn prepare(&self, spec: &EnvironmentSpec) -> Result<Prepared, EnvFailure> {
        if spec.network != NetworkTopology::NoNetwork {
            return Err(EnvFailure::Refused(BrokerRefusal::TopologyUnavailable));
        }
        self.version()?;
        self.image_present(spec)?;
        let argv = plan::create(spec, self.seccomp_path)
            .ok_or(EnvFailure::Refused(BrokerRefusal::Unsupported))?;
        let container = match self.runtime.call(argv, LINE) {
            Ok(done) if succeeded(&done) => {
                match one_line(&done.stdout).and_then(|id| ContainerRef::new(id.to_owned())) {
                    Some(container) => container,
                    None => return self.abandon(spec),
                }
            }
            Ok(_) | Err(run::Failure::Unconfirmed) => return self.abandon(spec),
            Err(run::Failure::Refused(why)) => return Err(EnvFailure::Refused(why)),
        };
        crate::crash::point("environment_created");
        let handle = EnvHandle {
            environment: spec.environment_id.clone(),
            container,
        };
        let started = self.runtime.call(plan::start(&handle.container), LINE);
        if !started.as_ref().is_ok_and(succeeded) {
            return match self.remove(&handle.container) {
                Ok(()) => Err(EnvFailure::Refused(BrokerRefusal::RuntimeFailed)),
                Err(_) => Err(EnvFailure::Unconfirmed),
            };
        }
        crate::crash::point("environment_started");
        let Ok(measured) = self.measure(&handle, spec) else {
            return match self.remove(&handle.container) {
                Ok(()) => Err(EnvFailure::Refused(BrokerRefusal::RuntimeFailed)),
                Err(_) => Err(EnvFailure::Unconfirmed),
            };
        };
        crate::crash::point("environment_measured");
        let keep = measured
            .checks
            .as_ref()
            .is_some_and(|checks| clean(checks, spec.network));
        if !keep {
            // Never left running unless it measured clean.
            self.remove(&handle.container)?;
        }
        Ok(Prepared {
            handle: Some(handle),
            measured: Some(measured),
            retained: keep,
        })
    }

    fn measure(&self, handle: &EnvHandle, spec: &EnvironmentSpec) -> Result<Measured, EnvFailure> {
        let since = Instant::now();
        let version = self.version()?;
        let Some(object) = self.record(&handle.container)? else {
            return Err(EnvFailure::Refused(BrokerRefusal::EnvironmentNotFound));
        };
        let record = inspect::Record::new(&object);
        if !record.is(&spec.store, (&spec.environment_id, &spec.run_id)) {
            return Err(EnvFailure::Refused(BrokerRefusal::ForeignEnvironment));
        }
        let state = record
            .state()
            .ok_or(EnvFailure::Refused(BrokerRefusal::RuntimeOutputMalformed))?;
        let checks = self.judge(handle, spec, &record, state)?;
        Ok(Measured {
            state,
            checks: Some(checks),
            runtime_version: Some(version),
            measure_ms: Milliseconds::of(since.elapsed()),
        })
    }

    fn run_probe(
        &self,
        handle: &EnvHandle,
        spec: &EnvironmentSpec,
    ) -> Result<(ExecOutcome, Vec<u8>), EnvFailure> {
        match self.runtime.call_within(
            plan::measure(&handle.container, spec),
            MAX_PROBE_REPORT_BYTES + 1,
            PROBE_STEP,
        ) {
            Err(run::Failure::Refused(why)) => Err(EnvFailure::Refused(why)),
            Err(run::Failure::Unconfirmed) => Ok((ExecOutcome::Unobservable, Vec::new())),
            Ok(done) => {
                let outcome = self.after(&handle.container, done.ended);
                // A report cut at its bound is not a report.
                let stdout = if done.stdout_cut {
                    Vec::new()
                } else {
                    done.stdout
                };
                Ok((outcome, stdout))
            }
        }
    }

    fn destroy(
        &self,
        store: &StoreInstance,
        environment: (&EnvironmentId, &RunId),
        container: Option<&ContainerRef>,
    ) -> Result<Destroyed, EnvFailure> {
        self.version()?;
        let (labelled, complete) = self.owned_ids(store, Some(environment))?;
        // Only a container labelled as exactly this environment of this run
        // is it; a copy naming another run is not, and does not make the
        // genuine one ambiguous.
        if !complete || labelled.len() > 1 {
            return Err(EnvFailure::Refused(BrokerRefusal::EnvironmentAmbiguous));
        }
        let target = match (container, labelled.first()) {
            (Some(recorded), Some(found)) if recorded == found => found.clone(),
            (Some(recorded), found) => {
                // The recorded container is not labelled as this
                // environment: it is someone else's, or gone.
                match self.record(recorded)? {
                    Some(_) => return Err(EnvFailure::Refused(BrokerRefusal::ForeignEnvironment)),
                    None => match found {
                        None => return Ok(Destroyed::AlreadyGone),
                        // Another container claims the environment.
                        Some(_) => {
                            return Err(EnvFailure::Refused(BrokerRefusal::EnvironmentAmbiguous));
                        }
                    },
                }
            }
            (None, Some(found)) => found.clone(),
            (None, None) => return Ok(Destroyed::AlreadyGone),
        };
        // Proved labelled as this environment of this store, immediately
        // before removal.
        match self.record(&target)? {
            None => return Ok(Destroyed::AlreadyGone),
            Some(object) if !inspect::Record::new(&object).is(store, environment) => {
                return Err(EnvFailure::Refused(BrokerRefusal::ForeignEnvironment));
            }
            Some(_) => {}
        }
        self.remove(&target)?;
        Ok(Destroyed::Removed(target))
    }

    fn list(&self, store: &StoreInstance) -> Result<Listed, EnvFailure> {
        self.version()?;
        let (ids, complete) = self.owned_ids(store, None)?;
        if ids.is_empty() {
            return Ok(Listed {
                environments: Vec::new(),
                complete,
            });
        }
        let refs: Vec<&ContainerRef> = ids.iter().collect();
        let malformed = EnvFailure::Refused(BrokerRefusal::RuntimeOutputMalformed);
        let done = match self
            .runtime
            .call(plan::inspect(&refs), inspect::MAX_INSPECT_BYTES)
        {
            Ok(done) => done,
            Err(run::Failure::Refused(why)) => return Err(EnvFailure::Refused(why)),
            Err(run::Failure::Unconfirmed) => {
                return Err(EnvFailure::Refused(BrokerRefusal::RuntimeUnavailable));
            }
        };
        if done.stdout_cut {
            return Err(malformed);
        }
        // A container removed between the listing and the inspection is
        // simply absent: the runtime reports the rest and exits non-zero.
        let records = inspect::parse(&done.stdout).map_err(|()| malformed)?;
        let mut environments = Vec::new();
        for object in &records {
            let owned = inspect::Record::new(object).owned(store).ok_or(malformed)?;
            environments.push(owned);
        }
        let complete = complete && (records.len() == ids.len() || done.ended != Ended::Exited(0));
        Ok(Listed {
            environments,
            complete,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{ExecOutcome, classify, lines, one_line};

    #[test]
    fn a_step_that_did_not_exit_zero_is_classified_by_what_is_still_there() {
        assert_eq!(classify(1, true), ExecOutcome::Exited(1));
        assert_eq!(classify(3, true), ExecOutcome::Exited(3));
        assert_eq!(classify(137, true), ExecOutcome::Killed(9));
        assert_eq!(classify(126, true), ExecOutcome::Unobservable);
        assert_eq!(classify(127, true), ExecOutcome::Unobservable);
        // The container is gone: whatever the code, the environment is.
        for code in [1, 3, 126, 137, 255] {
            assert_eq!(classify(code, false), ExecOutcome::EnvironmentGone);
        }
    }

    #[test]
    fn one_line_is_exactly_one_terminated_line() {
        assert_eq!(one_line(b"abc\n"), Some("abc"));
        for bad in [&b"abc"[..], b"\n", b"a\nb\n", b"\xff\n", b""] {
            assert_eq!(one_line(bad), None, "{bad:?}");
        }
        assert_eq!(lines(b"a\n\nb\n"), Some(vec!["a", "b"]));
    }
}
