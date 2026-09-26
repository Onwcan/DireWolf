//! Starting the launch helper, handing it the launch, and learning whether
//! the **target** — not merely the helper — was executed (ADR-0045 §9, §12).
//!
//! The helper is this binary in `exec-helper` mode, spawned through `std`
//! with an empty environment, stdin `/dev/null`, stdout the stdout pipe's
//! write end, stderr one end of a fresh socket pair — the control channel —
//! and its own process group. Over the control channel it receives the
//! launch: `argv`, `envp`, and three descriptors by `SCM_RIGHTS` — the
//! executable, the working directory and the stderr pipe's write end.
//!
//! **The handshake.** The helper's control descriptor is close-on-exec. It
//! writes `X` immediately before `execveat`; a failure after that writes a
//! failure record. So, read to end of file:
//!
//! | control channel | meaning |
//! |---|---|
//! | `X`, then end of file | `execveat` succeeded: the target runs |
//! | a failure record (`F`, stage, errno) | the helper stopped at that stage; nothing was executed |
//! | end of file, nothing else | the helper died before it could execute anything |
//! | nothing within the deadline | it has not executed (the descriptor is still open): it is killed |
//!
//! `RUNNING` is reported only in the first case.

use std::io::{self, IoSlice, Read as _, Write as _};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use dwk_proto::brokerp::{BrokerRefusal, ProcessStartAuthorisation};
use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags};

use super::helper;

/// How long the helper may take from start to `execveat`.
const HANDSHAKE: Duration = Duration::from_secs(5);

/// A target that was executed: the process, and the read ends of its output.
#[derive(Debug)]
pub(super) struct Launched {
    /// The target — the helper, after it replaced itself.
    pub(super) child: Child,
    /// Its stdout.
    pub(super) stdout: io::PipeReader,
    /// Its stderr.
    pub(super) stderr: io::PipeReader,
}

/// Why nothing, or nothing provable, was launched.
#[derive(Debug)]
pub(super) enum Failure {
    /// Provably nothing was executed.
    Refused(BrokerRefusal),
    /// The target may have been executed and nothing proves it: killed and
    /// reaped, but it may have run.
    Unconfirmed,
}

fn setup(_: io::Error) -> Failure {
    Failure::Refused(BrokerRefusal::ExecSetupFailed)
}

/// Kill and reap a helper that did not execute its target.
fn abandon(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Start the helper, hand it the launch, and wait for the handshake.
pub(super) fn launch(
    helper_binary: &Path,
    start: &ProcessStartAuthorisation,
    executable: OwnedFd,
    cwd: OwnedFd,
) -> Result<Launched, Failure> {
    let (stdout_r, stdout_w) = io::pipe().map_err(setup)?;
    let (stderr_r, stderr_w) = io::pipe().map_err(setup)?;
    let (ours, theirs) = UnixStream::pair().map_err(setup)?;
    let mut command = Command::new(helper_binary);
    command
        .arg("exec-helper")
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::from(OwnedFd::from(stdout_w)))
        .stderr(Stdio::from(OwnedFd::from(theirs)))
        .process_group(0);
    let mut child = command.spawn().map_err(setup)?;
    // The parent's copies of the helper's stdout and control end close here,
    // so end of file on either means the helper's side closed.
    drop(command);
    crate::crash::point("process_helper_spawned");

    let spec = helper::Spec {
        argv: std::iter::once(start.argv0.as_str().as_bytes().to_vec())
            .chain(start.args.iter().map(|a| a.as_str().as_bytes().to_vec()))
            .collect(),
        envp: start
            .environment
            .variables()
            .into_iter()
            .map(|(name, value)| format!("{name}={value}").into_bytes())
            .collect(),
        crash_before_exec: crate::crash::armed("process_helper_before_exec"),
    };
    let payload = helper::encode(&spec);
    let sent = send(
        &ours,
        &payload,
        &[&executable, &cwd, &OwnedFd::from(stderr_w)],
    );
    // Ours close now: the helper holds the only copies it needs.
    drop(executable);
    drop(cwd);
    if sent.is_err() {
        abandon(&mut child);
        return Err(Failure::Refused(BrokerRefusal::ExecSetupFailed));
    }

    let mut control = Vec::new();
    let read = ours
        .set_read_timeout(Some(HANDSHAKE))
        .and_then(|()| (&ours).take(64).read_to_end(&mut control));
    match (read, helper::Handshake::parse(&control)) {
        (Ok(_), Some(helper::Handshake::Executed)) => {
            crate::crash::point("process_exec_confirmed");
            Ok(Launched {
                child,
                stdout: stdout_r,
                stderr: stderr_r,
            })
        }
        (Ok(_), Some(helper::Handshake::Failed { stage, errno })) => {
            abandon(&mut child);
            crate::event(&format!("exec_helper_failed stage={stage} errno={errno}"));
            Err(Failure::Refused(helper::refusal(stage)))
        }
        // End of file before "X": the helper died before it could execute
        // anything.
        (Ok(_), None) if control.is_empty() => {
            abandon(&mut child);
            Err(Failure::Refused(BrokerRefusal::ExecSetupFailed))
        }
        // No answer in time and no "X": the control descriptor is still open,
        // so nothing was executed.
        (Err(_), _) if !control.starts_with(b"X") => {
            abandon(&mut child);
            Err(Failure::Refused(BrokerRefusal::ExecSetupFailed))
        }
        // "X" and then trouble, or bytes that are not a record: the target
        // may have run. Stop it; say so.
        _ => {
            abandon(&mut child);
            Err(Failure::Unconfirmed)
        }
    }
}

/// Send `payload` with `descriptors`, in order, attached to its first byte.
fn send(stream: &UnixStream, payload: &[u8], descriptors: &[&OwnedFd]) -> io::Result<()> {
    stream.set_write_timeout(Some(HANDSHAKE))?;
    let fds: Vec<_> = descriptors.iter().map(|fd| fd.as_fd()).collect();
    let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(3))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    if !ancillary.push(SendAncillaryMessage::ScmRights(&fds)) {
        return Err(io::Error::other("the descriptors did not fit"));
    }
    let sent = rustix::net::sendmsg(
        stream,
        &[IoSlice::new(payload)],
        &mut ancillary,
        SendFlags::NOSIGNAL,
    )
    .map_err(io::Error::from)?;
    let mut writer = stream;
    writer.write_all(payload.get(sent..).unwrap_or_default())
}
