//! Local HTTPS origins and fixture names for the `net.http` evidence (M5c,
//! ADR-0050 §16): a PKI made afresh for each run (`tests/net_http/make-pki.sh`
//! — no private key is ever committed), and origins served by
//! `tests/net_http/origin.py` on loopback, each presenting one certificate of
//! it. Nothing here reaches beyond this host: the broker under test resolves
//! the evidence's names from a fixture file to `127.0.0.1`, and trusts the
//! run's test authority only because it is started with
//! `--allow-evidence-trust`.

#![allow(
    dead_code,
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::missing_panics_doc
)]

use std::ffi::OsStr;
use std::io::{BufRead as _, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

/// The repository's root.
fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// What the evidence needs, each with the one command that shows it usable
/// here: the tool's **own** version spelling. OpenSSL's is `openssl version`
/// -- before 3.2 it has no `--version` and refuses it with "Invalid command"
/// and status 1, which is what Ubuntu 24.04's OpenSSL 3.0 does -- while bash
/// and Python spell it `--version`.
pub(crate) const PREREQUISITES: [(&str, &[&str]); 3] = [
    ("bash", &["--version"]),
    ("openssl", &["version"]),
    ("python3", &["--version"]),
];

/// Whether `tool args` runs and succeeds, searching `path` when given (the
/// regression tests' fake tools) and this process's `PATH` otherwise. The
/// error names the exact command and why it failed.
fn probe(tool: &str, args: &[&str], path: Option<&OsStr>) -> Result<(), String> {
    let shown = format!("`{tool} {}`", args.join(" "));
    let mut command = Command::new(tool);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(path) = path {
        command.env("PATH", path);
    }
    match super::state_support::status(&mut command) {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => Err(format!("{shown} failed ({status})")),
        Err(error) => Err(format!("{shown} could not run ({:?})", error.kind())),
    }
}

/// The first prerequisite that is missing or unusable, as the command that
/// failed and why -- on `path` when given. `None` when every one runs.
pub(crate) fn missing_tool_on(path: Option<&OsStr>) -> Option<String> {
    PREREQUISITES
        .iter()
        .find_map(|(tool, args)| probe(tool, args, path).err())
}

/// The first prerequisite this host lacks, or `None`: its absence is NOT
/// EXERCISED, said so with the failing command, never a pass.
pub(crate) fn missing_tool() -> Option<String> {
    missing_tool_on(None)
}

/// Make the run's PKI under `dir/pki`.
pub(crate) fn pki(dir: &Path) -> PathBuf {
    let out = dir.join("pki");
    let status = super::state_support::status(
        Command::new("bash")
            .arg(root().join("tests/net_http/make-pki.sh"))
            .arg(&out)
            .stdout(Stdio::null())
            .stderr(Stdio::null()),
    )
    .expect("bash runs");
    assert!(status.success(), "the test PKI is made");
    out
}

/// A local HTTPS origin: `origin.py` presenting `cert` from the run's PKI.
pub(crate) struct Origin {
    child: Child,
    /// The loopback port it listens on.
    pub(crate) port: u16,
    lines: Arc<Mutex<Vec<String>>>,
}

impl Origin {
    /// Start one, presenting `<pki>/<cert>.pem`, and wait until it listens.
    pub(crate) fn start(pki: &Path, cert: &str) -> Self {
        let mut child = super::state_support::spawn(
            Command::new("python3")
                .arg(root().join("tests/net_http/origin.py"))
                .arg("--cert")
                .arg(pki.join(format!("{cert}.pem")))
                .arg("--key")
                .arg(pki.join(format!("{cert}.key")))
                .env_clear()
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null()),
        )
        .expect("python3 runs");
        let stdout = child.stdout.take().expect("stdout");
        let lines = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&lines);
        let (ready, port) = mpsc::channel::<u16>();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if let Some(rest) = line.strip_prefix("ORIGIN-READY {\"port\": ") {
                    let _ = ready.send(rest.trim_end_matches('}').parse().unwrap_or(0));
                } else if let Some(record) = line.strip_prefix("ORIGIN-REQUEST ") {
                    sink.lock().unwrap().push(record.to_owned());
                }
            }
        });
        let port = port
            .recv_timeout(Duration::from_secs(20))
            .expect("the origin listens");
        assert_ne!(port, 0);
        Self { child, port, lines }
    }

    /// Every request it has logged so far, as its JSON text, after `settle`
    /// for lines still in flight.
    pub(crate) fn requests(&self) -> Vec<String> {
        std::thread::sleep(Duration::from_millis(150));
        self.lines.lock().unwrap().clone()
    }

    /// The requests whose target starts with `prefix`.
    pub(crate) fn to(&self, prefix: &str) -> Vec<String> {
        let needle = format!("\"target\": \"{prefix}");
        self.requests()
            .into_iter()
            .filter(|r| r.contains(&needle))
            .collect()
    }

    /// Wait until at least `n` requests have been logged.
    pub(crate) fn wait_for(&self, n: usize) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while self.lines.lock().unwrap().len() < n {
            assert!(Instant::now() < deadline, "the origin saw {n} requests");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Origin {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The `Authorization` digest an origin logged for a request, if any.
pub(crate) fn authorization(request: &str) -> Option<String> {
    let (_, rest) = request.split_once("\"authorization_sha256\": ")?;
    let rest = rest.strip_prefix('"')?;
    rest.split_once('"').map(|(hex, _)| hex.to_owned())
}

/// The header names an origin logged for a request.
pub(crate) fn header_names(request: &str) -> Vec<String> {
    let Some((_, rest)) = request.split_once("\"headers\": [") else {
        return Vec::new();
    };
    let Some((list, _)) = rest.split_once(']') else {
        return Vec::new();
    };
    list.split(',')
        .map(|n| n.trim().trim_matches('"').to_owned())
        .filter(|n| !n.is_empty())
        .collect()
}

/// The body length an origin logged for a request.
pub(crate) fn body_bytes(request: &str) -> Option<u64> {
    let (_, rest) = request.split_once("\"body_bytes\": ")?;
    rest.split(|c: char| !c.is_ascii_digit())
        .next()?
        .parse()
        .ok()
}

/// Write the broker's fixture resolver file.
pub(crate) fn fixture(dir: &Path, text: &str) -> PathBuf {
    let path = dir.join("egress.fixture");
    std::fs::write(&path, text).unwrap();
    path
}
