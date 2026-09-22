//! Fixtures shared by the M3d state tests.
//!
//! Everything here drives the **real** store: real directories, real SQLite
//! files, real `audit.log`s, and DWKP requests written as JSON text and passed
//! through `dwk_proto`'s real decoder — the same bytes-to-message path M3e will
//! use. Nothing is mocked. Where a test needs to tamper with a file or read a
//! row the public API does not expose, it opens its own `rusqlite` connection
//! on the file, exactly as an attacker with file access would.

#![allow(
    dead_code,
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_panics_doc
)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use dwk_proto::dwkp::{self, DwkpMessage};
use dwk_proto::wire::id::{RunId, SessionId, encode_uuid};
use dwk_proto::wire::scalar::{AgentProfileName, Epoch, SkillName};
use dwkd_authority::capability::PrivacyClass;
use dwkd_authority::state::{
    AgentProfileSpec, AuthenticatedSubject, Authority, CallerContext, CrashHook, ManualClock, Mode,
    PolicySet, PolicySource, Reply, SkillSpec, SkillTrust, StartError, StartOptions, StartReport,
    StartupConfig,
};

/// 2025-09-16, in milliseconds: a plausible authority clock.
pub(crate) const START_MS: u64 = 1_758_000_000_000;

static UNIQUE: AtomicU64 = AtomicU64::new(0);

/// A directory removed when dropped. No `tempfile` crate: the authority's own
/// dependency set is the thing under review, and a test helper is not a reason
/// to grow it.
#[derive(Debug)]
pub(crate) struct TempDir(PathBuf);

impl TempDir {
    pub(crate) fn new(tag: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let n = UNIQUE.fetch_add(1, Ordering::SeqCst);
        let path =
            std::env::temp_dir().join(format!("dw-m3d-{tag}-{}-{nanos}-{n}", std::process::id()));
        std::fs::create_dir_all(&path).expect("temp dir");
        Self(path)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }

    /// The authority's state directory inside it. Not created here: the
    /// authority creates it, private, itself.
    pub(crate) fn state(&self) -> PathBuf {
        self.0.join("state")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A UUIDv7 value distinct for every `n`.
pub(crate) fn uuid(n: u64) -> u128 {
    let ts = u128::from(START_MS);
    let n = u128::from(n);
    (ts << 80) | (0x7 << 76) | ((n & 0x0fff) << 64) | (0b10 << 62) | (n & ((1 << 62) - 1))
}

pub(crate) fn id(prefix: &str, n: u64) -> String {
    format!("{prefix}_{}", encode_uuid(uuid(n)))
}

pub(crate) fn session(n: u64) -> SessionId {
    SessionId::from_uuid(uuid(n)).expect("a session id")
}

pub(crate) fn run_id(n: u64) -> RunId {
    RunId::from_uuid(uuid(n)).expect("a run id")
}

pub(crate) fn epoch(n: u64) -> Epoch {
    Epoch::new(n).expect("an epoch")
}

pub(crate) fn subject(uid: u32) -> AuthenticatedSubject {
    AuthenticatedSubject::unix_uid(uid)
}

/// The ceiling every fixture runs under. Wide on purpose, so the profile and
/// skill terms are what the tests see withholding.
pub(crate) fn ceiling() -> Vec<String> {
    [
        "network.https:*",
        "network.http:*",
        "model.call:*",
        "memory.read:*",
        "memory.promote:*",
        "scheduler.create:*",
        "artifact.read:*",
        "fs.read:*",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

pub(crate) fn config(policy: PolicySet) -> StartupConfig {
    StartupConfig::new(policy, Mode::Balanced, ceiling())
}

pub(crate) fn balanced() -> StartupConfig {
    config(PolicySet::shipped("balanced").expect("balanced ships"))
}

/// A single-file policy from text, named `name.toml`.
pub(crate) fn policy(name: &str, text: &str) -> PolicySet {
    PolicySet {
        profile: name.to_owned(),
        sources: vec![PolicySource {
            name: format!("{name}.toml"),
            text: text.to_owned(),
        }],
    }
}

pub(crate) fn options(clock: &Arc<ManualClock>, hook: Option<CrashHook>) -> StartOptions {
    StartOptions {
        clock: clock.clone(),
        crash_hook: hook,
    }
}

pub(crate) fn start(
    state: &Path,
    config: &StartupConfig,
    clock: &Arc<ManualClock>,
    hook: Option<CrashHook>,
) -> Result<(Authority, StartReport), StartError> {
    Authority::start(state, config, options(clock, hook))
}

/// A running authority on a fresh directory, with the fixture profiles and
/// skills installed.
pub(crate) struct Harness {
    pub(crate) dir: TempDir,
    pub(crate) clock: Arc<ManualClock>,
    pub(crate) config: StartupConfig,
    pub(crate) authority: Option<Authority>,
    pub(crate) report: StartReport,
}

impl Harness {
    pub(crate) fn new(tag: &str) -> Self {
        Self::with_config(tag, balanced())
    }

    pub(crate) fn with_config(tag: &str, config: StartupConfig) -> Self {
        Self::with_hook(tag, config, None)
    }

    pub(crate) fn with_hook(tag: &str, config: StartupConfig, hook: Option<CrashHook>) -> Self {
        let dir = TempDir::new(tag);
        let clock = Arc::new(ManualClock::new(START_MS));
        let (mut authority, report) =
            start(&dir.state(), &config, &clock, hook).expect("a fresh store starts");
        install_fixtures(&mut authority);
        Self {
            dir,
            clock,
            config,
            authority: Some(authority),
            report,
        }
    }

    pub(crate) fn authority(&mut self) -> &mut Authority {
        self.authority.as_mut().expect("the authority is running")
    }

    pub(crate) fn state(&self) -> PathBuf {
        self.dir.state()
    }

    /// Stop the authority — dropping it, as a process exit would — and start a
    /// new incarnation on the same files.
    pub(crate) fn restart(&mut self) -> &StartReport {
        self.restart_with(None)
    }

    pub(crate) fn restart_with(&mut self, hook: Option<CrashHook>) -> &StartReport {
        self.authority = None;
        let (authority, report) =
            start(&self.dir.state(), &self.config, &self.clock, hook).expect("a restart");
        self.authority = Some(authority);
        self.report = report;
        &self.report
    }

    /// Stop the authority and try to start it, returning the error if any.
    pub(crate) fn try_restart(&mut self) -> Result<(), StartError> {
        self.authority = None;
        let (authority, report) = start(&self.dir.state(), &self.config, &self.clock, None)?;
        self.authority = Some(authority);
        self.report = report;
        Ok(())
    }

    pub(crate) fn stop(&mut self) {
        self.authority = None;
    }

    pub(crate) fn connect(&mut self, uid: u32) -> CallerContext {
        self.authority().connect(subject(uid))
    }

    /// Acquire a lease, expecting it to be granted.
    pub(crate) fn lease(&mut self, caller: &CallerContext, session: &SessionId) -> Epoch {
        match self
            .authority()
            .acquire_lease(caller, session)
            .expect("answers")
        {
            Reply::Done(epoch) => epoch,
            Reply::Refused(reason) => panic!("lease refused: {reason:?}"),
        }
    }
}

pub(crate) fn profile(
    name: &str,
    declared: &[&str],
    baseline: &[&str],
    privacy: PrivacyClass,
) -> AgentProfileSpec {
    AgentProfileSpec {
        name: AgentProfileName::new(name).expect("a profile name"),
        declared: declared.iter().map(|s| (*s).to_owned()).collect(),
        baseline_skills: baseline
            .iter()
            .map(|s| SkillName::new(*s).expect("a skill name"))
            .collect(),
        privacy_default: privacy,
    }
}

pub(crate) fn skill(name: &str, trust: SkillTrust, declared: &[&str]) -> SkillSpec {
    SkillSpec {
        name: SkillName::new(name).expect("a skill name"),
        trust,
        declared: declared.iter().map(|s| (*s).to_owned()).collect(),
    }
}

/// The fixture configuration: two profiles and four skills.
///
/// * `researcher` — no baseline skill; may call models, read memory, reach
///   `*.example.com` and `github.com` over HTTPS, schedule, promote memory,
///   and use plaintext HTTP (which policy denies).
/// * `coder` — mandates the `house-rules` skill, which permits only model
///   calls and memory reads.
pub(crate) fn install_fixtures(authority: &mut Authority) {
    let mut operator = authority.operator();
    operator
        .install_agent_profile(&profile(
            "researcher",
            &[
                "model.call:*",
                "memory.read:*",
                "memory.promote:*",
                "network.https:*.example.com",
                "network.https:github.com",
                "network.http:*",
                "scheduler.create:*",
                "fs.read:/workspace",
                "fs.read:*",
            ],
            &[],
            PrivacyClass::Any,
        ))
        .expect("researcher installs");
    operator
        .install_agent_profile(&profile(
            "coder",
            &["model.call:*", "memory.read:*", "network.https:*"],
            &["house-rules"],
            PrivacyClass::VendorOk,
        ))
        .expect("coder installs");
    operator
        .install_skill(&skill(
            "house-rules",
            SkillTrust::UserTrusted,
            &["model.call:*", "memory.read:*"],
        ))
        .expect("house-rules installs");
    operator
        .install_skill(&skill(
            "web",
            SkillTrust::CommunityUnverified,
            &["network.https:*.example.com", "model.call:*"],
        ))
        .expect("web installs");
    operator
        .install_skill(&skill(
            "models-only",
            SkillTrust::SystemTrusted,
            &["model.call:*"],
        ))
        .expect("models-only installs");
    operator
        .install_skill(&skill(
            "broken",
            SkillTrust::Quarantined,
            &["model.call:*", "memory.read:*", "network.https:*"],
        ))
        .expect("broken installs");
}

fn json_list(items: &[&str]) -> String {
    let quoted: Vec<String> = items.iter().map(|s| format!("\"{s}\"")).collect();
    format!("[{}]", quoted.join(","))
}

/// Decode DWKP JSON text through the real decoder.
pub(crate) fn decode(json: &str) -> DwkpMessage {
    dwkp::decode_body(json.as_bytes()).unwrap_or_else(|e| panic!("decodes: {e}\n{json}"))
}

/// An `AdmitRun`, as the runtime would send it. `msg` varies the envelope's
/// own id and timestamp, which are not bound to the idempotency key.
pub(crate) fn admit_msg(
    session: &SessionId,
    epoch: Epoch,
    key: &str,
    agent_profile: &str,
    skills: &[&str],
    capabilities: &[&str],
    msg: u64,
) -> DwkpMessage {
    decode(&format!(
        r#"{{"v":1,"id":"{id}","type":"request","schema":"direwolf.run.admit","schema_version":1,"ts":"2026-09-21T10:00:{sec:02}.000Z","correlation_id":"{corr}","session_id":"{session}","epoch":{epoch},"idempotency_key":"{key}","payload":{{"agent_profile":"{agent_profile}","skills":{skills},"requested_capabilities":{caps}}}}}"#,
        id = id("msg", 10_000 + msg),
        sec = msg % 60,
        corr = id("cor", 20_000 + msg),
        session = session.as_str(),
        epoch = epoch.get(),
        skills = json_list(skills),
        caps = json_list(capabilities),
    ))
}

pub(crate) fn admit_simple(
    session: &SessionId,
    epoch: Epoch,
    key: &str,
    capabilities: &[&str],
) -> DwkpMessage {
    admit_msg(session, epoch, key, "researcher", &[], capabilities, 1)
}

pub(crate) fn query_msg(
    session: &SessionId,
    run: &RunId,
    epoch: Epoch,
    proposed: Option<&str>,
) -> DwkpMessage {
    let payload = proposed.map_or_else(String::new, |p| format!(r#""proposed":"{p}""#));
    decode(&format!(
        r#"{{"v":1,"id":"{id}","type":"request","schema":"direwolf.authority.query","schema_version":1,"ts":"2026-09-21T10:00:00.000Z","session_id":"{session}","run_id":"{run}","epoch":{epoch},"payload":{{{payload}}}}}"#,
        id = id("msg", 30_000),
        session = session.as_str(),
        run = run.as_str(),
        epoch = epoch.get(),
    ))
}

pub(crate) fn release_run_msg(session: &SessionId, run: &RunId, epoch: Epoch) -> DwkpMessage {
    decode(&format!(
        r#"{{"v":1,"id":"{id}","type":"request","schema":"direwolf.run.release","schema_version":1,"ts":"2026-09-21T10:00:00.000Z","session_id":"{session}","run_id":"{run}","epoch":{epoch},"payload":{{}}}}"#,
        id = id("msg", 40_000),
        session = session.as_str(),
        run = run.as_str(),
        epoch = epoch.get(),
    ))
}

pub(crate) fn acquire_msg(session: &SessionId) -> DwkpMessage {
    decode(&format!(
        r#"{{"v":1,"id":"{id}","type":"request","schema":"direwolf.lease.acquire","schema_version":1,"ts":"2026-09-21T10:00:00.000Z","session_id":"{session}","payload":{{}}}}"#,
        id = id("msg", 50_000),
        session = session.as_str(),
    ))
}

pub(crate) fn heartbeat_msg(session: &SessionId, epoch: Epoch) -> DwkpMessage {
    decode(&format!(
        r#"{{"v":1,"id":"{id}","type":"request","schema":"direwolf.heartbeat","schema_version":1,"ts":"2026-09-21T10:00:00.000Z","session_id":"{session}","epoch":{epoch},"payload":{{}}}}"#,
        id = id("msg", 60_000),
        session = session.as_str(),
        epoch = epoch.get(),
    ))
}

pub(crate) fn release_lease_msg(session: &SessionId, epoch: Epoch) -> DwkpMessage {
    decode(&format!(
        r#"{{"v":1,"id":"{id}","type":"request","schema":"direwolf.lease.release","schema_version":1,"ts":"2026-09-21T10:00:00.000Z","session_id":"{session}","epoch":{epoch},"payload":{{}}}}"#,
        id = id("msg", 70_000),
        session = session.as_str(),
        epoch = epoch.get(),
    ))
}

/// A connection of the test's own onto `kernel.db` — an observer, or an
/// attacker with file access. Never the authority's.
pub(crate) fn raw(state: &Path) -> rusqlite::Connection {
    let conn = rusqlite::Connection::open(state.join("kernel.db")).expect("raw open");
    conn.busy_timeout(std::time::Duration::from_secs(5))
        .expect("busy timeout");
    conn
}

pub(crate) fn count(conn: &rusqlite::Connection, sql: &str) -> i64 {
    conn.query_row(sql, [], |row| row.get(0)).expect("count")
}

pub(crate) fn audit_lines(state: &Path) -> Vec<String> {
    std::fs::read_to_string(state.join("audit.log"))
        .expect("audit.log")
        .lines()
        .map(str::to_owned)
        .collect()
}

/// One parsed audit record.
pub(crate) fn record(line: &str) -> dwk_proto::json::Object {
    match dwk_proto::json::parse(line.as_bytes(), dwk_proto::json::ParseOptions::dwkp()) {
        Ok(dwk_proto::json::Value::Object(object)) => object,
        other => panic!("not a record: {other:?}"),
    }
}

/// A text field of a record.
pub(crate) fn text<'a>(record: &'a dwk_proto::json::Object, key: &str) -> Option<&'a str> {
    match record.get(key) {
        Some(dwk_proto::json::Value::String(value)) => Some(value),
        _ => None,
    }
}

/// An integer field of a record.
pub(crate) fn int(record: &dwk_proto::json::Object, key: &str) -> Option<i64> {
    match record.get(key) {
        Some(dwk_proto::json::Value::Number(dwk_proto::json::Number::Int(value))) => Some(*value),
        _ => None,
    }
}

/// The `event` of every record in `audit.log`, in order.
pub(crate) fn audit_events(state: &Path) -> Vec<String> {
    audit_lines(state)
        .iter()
        .map(|line| text(&record(line), "event").expect("an event").to_owned())
        .collect()
}

/// Every record of one event kind, parsed.
pub(crate) fn audit_records(state: &Path, event: &str) -> Vec<dwk_proto::json::Object> {
    audit_lines(state)
        .iter()
        .map(|line| record(line))
        .filter(|object| text(object, "event") == Some(event))
        .collect()
}
