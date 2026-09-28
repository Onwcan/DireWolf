//! M4e's secret evidence on real processes (ADR-0046 §§11–13, 21–23): the
//! released `dwkd-authority serve` with a secret index whose value lives in
//! the kernel keyring, the released `dwkd-broker serve`, and — as the runtime
//! — **a separate process that never saw the value**, whose address space is
//! then read.
//!
//! * The return path: a workspace file holding the live value, a value that
//!   straddles the broker's internal read boundary, every known shape, and
//!   transformed forms (which are **not** redacted, and are shown not to be).
//!   The runtime receives placeholders; its memory holds no value.
//! * Mode A: the authority's library, hosted in a separate process, runs the
//!   whole pipeline against the real broker; afterwards neither that process
//!   nor the broker holds the value, and no durable file does.
//! * The production default: the authority daemon has `RLIMIT_CORE` 0 and is
//!   not dumpable.
//!
//! Locally every process is this uid (development flags: shared uids,
//! `--allow-dumpable` where this harness reads a daemon's memory). The
//! separated case — three identities, the hardened daemons read as root — is
//! `secret_foreign.rs`, run by the hosted job. Values are generated at run
//! time; assertions compare digests and booleans.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

use dwk_proto as _;
use proptest as _;
use rusqlite as _;
#[cfg(target_os = "linux")]
use rustix as _;
use sha2 as _;
use toml as _;
use unicode_normalization as _;
// M4e's secret crates (ADR-0046), reached only through the library.
use age as _;
use getrandom as _;
use hmac as _;
#[cfg(any(target_os = "macos", target_os = "windows"))]
use keyring as _;
#[cfg(target_os = "linux")]
use linux_keyutils as _;
use zeroize as _;

#[cfg(target_os = "linux")]
mod broker_support;
mod state_support;
#[cfg(target_os = "linux")]
mod transport_support;

#[cfg(target_os = "linux")]
mod linux {
    use std::io::{BufRead as _, BufReader, Read as _, Seek as _, SeekFrom};
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::Arc;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use dwk_proto::dwkp::DwkpBody;
    use dwk_proto::wire::scalar::IdempotencyKey;
    use dwkd_authority::broker::{EffectBroker, UnixBroker};
    use dwkd_authority::capability::PrivacyClass;
    use dwkd_authority::state::{
        Authority, EgressReply, EgressRequest, ManualClock, Mode, PolicySet, PolicySource, Reply,
        StartOptions, StartupConfig, WorkspaceId, WorkspaceSensitivity,
    };
    use linux_keyutils::{Key, KeyPermissionsBuilder, KeyRing, KeyRingIdentifier, Permission};
    use sha2::{Digest as _, Sha256};

    use super::broker_support::{Broker, Runtime, Setup};
    use super::state_support::{START_MS, admit_msg, profile, session};
    use super::transport_support::{Server, own_uid};

    const SUITE: &str = "authority-secret";

    fn evidence(case: &str, outcome: &str) {
        println!(
            "SECRET-EVIDENCE {{\"suite\":\"{SUITE}\",\"case\":\"{case}\",\"outcome\":\"{outcome}\",\
             \"count\":1}}"
        );
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// `len` printable bytes, fresh per call and per process.
    fn fresh(tag: &str, len: usize) -> Vec<u8> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let alphabet = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
        let mut out = Vec::new();
        let mut block = 0u32;
        while out.len() < len {
            let seed = Sha256::digest(format!("{tag}-{nanos}-{}-{block}", std::process::id()));
            out.extend(
                seed.iter()
                    .map(|b| alphabet[usize::from(*b) % alphabet.len()]),
            );
            block += 1;
        }
        out.truncate(len);
        out
    }

    /// A kernel-keyring entry and its key, removed when dropped.
    struct Seeded(String, Key);

    impl Seeded {
        /// Provisioned as the keychain backend's contract requires of an
        /// operator (`secret/backend/keychain.rs`): staged in this process's
        /// own keyring, linked into `@u` and given `0x3f0b0000` -- the owner
        /// may view, read and search it, its group and everyone else nothing
        /// -- then unlinked from the staging keyring. The daemons this test
        /// starts do not possess `@u` when it runs as a service does, so the
        /// owner's bits are what they read with.
        fn new(tag: &str, value: &[u8]) -> Option<Self> {
            let name = format!("direwolf-evidence/{tag}-{}", std::process::id());
            let staging = KeyRing::from_special_id(KeyRingIdentifier::Process, true).ok()?;
            let user = KeyRing::from_special_id(KeyRingIdentifier::User, true).ok()?;
            let key = staging.add_key(&name, value).ok()?;
            let perms = KeyPermissionsBuilder::builder()
                .posessor(Permission::ALL)
                .user(Permission::VIEW | Permission::READ | Permission::SEARCH)
                .build();
            let placed = user.link_key(key).and_then(|()| key.set_perms(perms));
            let _ = staging.unlink_key(key);
            if placed.is_err() {
                let _ = user.unlink_key(key);
                return None;
            }
            Some(Self(name, key))
        }

        /// The key's serial: an identifier, not a secret.
        fn serial(&self) -> String {
            self.1.get_id().as_raw_id().to_string()
        }
    }

    impl Drop for Seeded {
        fn drop(&mut self) {
            let _ = self.1.invalidate();
            if let Ok(ring) = KeyRing::from_special_id(KeyRingIdentifier::User, false) {
                let _ = ring.unlink_key(self.1);
            }
        }
    }

    /// The operator's secret metadata: `api-token` in the keychain, for
    /// `api.example.com:443`. Owned by this uid, mode 0600.
    fn secrets_file(dir: &Path, entry: &str) -> PathBuf {
        let path = dir.join("secrets.toml");
        std::fs::write(
            &path,
            format!(
                "schema_version = 1\n\n[secrets.api-token]\ntype = \"bearer\"\nstorage = \
                 \"keychain\"\nkeychain = \"{entry}\"\norigins = [\"api.example.com:443\"]\n\
                 header = \"Authorization\"\nprefix = \"Bearer \"\ninjection = [\"egress\"]\n"
            ),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        path
    }

    /// Whether any readable mapping of `pid` holds `needle` — the process's
    /// whole readable address space, as a core file would hold it. `None`
    /// when its memory cannot be read at all.
    fn memory_holds(pid: u32, needle: &[u8]) -> Option<bool> {
        let maps = std::fs::read_to_string(format!("/proc/{pid}/maps")).ok()?;
        let mut mem = std::fs::File::open(format!("/proc/{pid}/mem")).ok()?;
        let mut scanned = 0u64;
        for line in maps.lines() {
            let mut parts = line.split_whitespace();
            let (Some(range), Some(perms)) = (parts.next(), parts.next()) else {
                continue;
            };
            if !perms.starts_with('r') {
                continue;
            }
            let (start, end) = range.split_once('-').unwrap();
            let (start, end) = (
                u64::from_str_radix(start, 16).unwrap(),
                u64::from_str_radix(end, 16).unwrap(),
            );
            let mut offset = start;
            let mut carry: Vec<u8> = Vec::new();
            while offset < end {
                let len = usize::try_from((end - offset).min(1 << 20)).unwrap();
                let mut chunk = vec![0u8; len];
                if mem.seek(SeekFrom::Start(offset)).is_err() || mem.read_exact(&mut chunk).is_err()
                {
                    break;
                }
                scanned += u64::try_from(len).unwrap();
                carry.extend_from_slice(&chunk);
                if contains(&carry, needle) {
                    return Some(true);
                }
                let keep = carry.len().saturating_sub(needle.len());
                carry.drain(..keep);
                offset += u64::try_from(len).unwrap();
            }
        }
        (scanned > 0).then_some(false)
    }

    /// Every file under `dir` that holds `needle`, except `allowed`.
    fn files_holding(dir: &Path, needle: &[u8], allowed: &[PathBuf]) -> Vec<PathBuf> {
        let mut found = Vec::new();
        let Ok(entries) = std::fs::read_dir(dir) else {
            return found;
        };
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.is_symlink() || allowed.contains(&path) {
                continue;
            }
            if path.is_dir() {
                found.extend(files_holding(&path, needle, allowed));
            } else if std::fs::read(&path).is_ok_and(|b| contains(&b, needle)) {
                found.push(path);
            }
        }
        found
    }

    fn rchar(pid: u32) -> u64 {
        std::fs::read_to_string(format!("/proc/{pid}/io"))
            .unwrap()
            .lines()
            .find_map(|l| l.strip_prefix("rchar:"))
            .map(|v| v.trim().parse().unwrap())
            .unwrap()
    }

    /// A child of this test binary running `test` with `env`: its stdout
    /// lines, as they arrive, and the child.
    fn child(test: &str, env: &[(&str, String)]) -> (std::process::Child, mpsc::Receiver<String>) {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command.args([
            "--ignored",
            "--exact",
            test,
            "--nocapture",
            "--test-threads=1",
        ]);
        for (name, value) in env {
            command.env(name, value);
        }
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (lines, received) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                let _ = lines.send(line);
            }
        });
        (child, received)
    }

    /// Lines until `DONE`.
    fn until_done(lines: &mpsc::Receiver<String>) -> Vec<String> {
        let deadline = Instant::now() + Duration::from_secs(60);
        let mut out = Vec::new();
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let line = lines.recv_timeout(left).expect("the child reports");
            // Only the child's own report lines: libtest writes its own.
            let Some((_, report)) = line.split_once("M4E:") else {
                continue;
            };
            if report == "DONE" {
                return out;
            }
            out.push(report.to_owned());
        }
    }

    fn park() {
        std::thread::sleep(Duration::from_secs(120));
    }

    // ---- the runtime: a process that never saw the value --------------------

    /// The runtime, as a child: admit a run, read each file through DWKP,
    /// print what came back, and wait to be read. It is given the socket and
    /// the workspace paths — never the value.
    #[test]
    #[ignore = "the runtime child of the_runtime_receives_placeholders_and_holds_no_value"]
    fn runtime_child() {
        let (Ok(socket), Ok(paths)) = (
            std::env::var("DW_M4E_RUNTIME_SOCKET"),
            std::env::var("DW_M4E_RUNTIME_PATHS"),
        ) else {
            return;
        };
        println!("\nM4E:PID {}", std::process::id());
        let mut rt = Runtime::admit(Path::new(&socket), 1, &["fs.read:/workspace"]);
        for path in paths.split(',') {
            match rt.invoke(path, 262_144).body {
                DwkpBody::ToolResult(result) => println!(
                    "
M4E:RESULT {path} {} {}",
                    hex(&result.fs_read.content.to_bytes()),
                    result.fs_read.eof_observed
                ),
                other => println!(
                    "
M4E:OTHER {path} {other:?}"
                ),
            }
        }
        println!(
            "
M4E:DONE"
        );
        park();
    }

    #[test]
    fn the_runtime_receives_placeholders_and_holds_no_value() {
        let value = fresh("rt", 40);
        let Some(seeded) = Seeded::new("rt", &value) else {
            println!("NOT EXERCISED: no usable kernel keyring on this host");
            return;
        };
        let setup = Setup::new("m4e-runtime");
        let secrets = secrets_file(setup.dir.path(), &seeded.0);
        // The workspace: the live value, raw and in binary; across the broker's
        // 64 KiB read boundary; every known shape; and transformed forms.
        let root = setup.root.clone();
        std::fs::write(
            root.join("live.txt"),
            [b"token=".as_slice(), &value, b"\n"].concat(),
        )
        .unwrap();
        std::fs::write(
            root.join("binary.bin"),
            [b"\x00\xff\x10".as_slice(), &value, b"\x01\xfe"].concat(),
        )
        .unwrap();
        let mut chunk = vec![b'.'; 128 * 1024];
        chunk[65_536 - 17..65_536 - 17 + value.len()].copy_from_slice(&value);
        std::fs::write(root.join("chunk.bin"), &chunk).unwrap();
        let github = [b"gh".as_slice(), b"p_", &fresh("gh", 36)].concat();
        let openai = [b"s".as_slice(), b"k-proj-", &fresh("oa", 40)].concat();
        let slack = [b"xo".as_slice(), b"xb-", &fresh("sl", 24)].concat();
        let aws = [
            b"AK".as_slice(),
            b"IA",
            &fresh("aw", 16).to_ascii_uppercase(),
        ]
        .concat();
        let jwt = [
            b"ey".as_slice(),
            b"J",
            &fresh("j1", 20),
            b".",
            &fresh("j2", 30),
            b".",
            &fresh("j3", 25),
        ]
        .concat();
        let pem = [
            b"-----BEGIN ".as_slice(),
            b"RSA PRIVATE ",
            b"KEY-----\n",
            &fresh("pm", 64),
            b"\n-----END ",
            b"RSA PRIVATE ",
            b"KEY-----",
        ]
        .concat();
        let password = fresh("pw", 14);
        let keyword = fresh("kw", 24);
        let shapes = [
            b"github ".as_slice(),
            &github,
            b"\nopenai ",
            &openai,
            b"\nslack ",
            &slack,
            b"\naws key ",
            &aws,
            b" end\njwt ",
            &jwt,
            b"\n",
            &pem,
            b"\ndsn postgres://app:",
            &password,
            b"@db:5432/x\napi_key = \"",
            &keyword,
            b"\"\n",
        ]
        .concat();
        std::fs::write(root.join("shapes.txt"), &shapes).unwrap();
        let reversed: Vec<u8> = value.iter().rev().copied().collect();
        let split = [&value[..20], b" ".as_slice(), &value[20..]].concat();
        let transformed = [
            hex(&value).as_bytes(),
            b"\n".as_slice(),
            &reversed,
            b"\n",
            &split,
            b"\n",
        ]
        .concat();
        std::fs::write(root.join("transformed.txt"), &transformed).unwrap();

        let broker = Broker::start(
            &setup.broker_socket(),
            own_uid(),
            &["--allow-shared-authority-uid", "--allow-dumpable"],
        );
        let server = Server::start(&setup.authority_args(
            Some(own_uid()),
            &[
                "--secrets-file",
                secrets.to_str().unwrap(),
                "--allow-dumpable",
            ],
        ));
        let paths = [
            "/workspace/live.txt",
            "/workspace/binary.bin",
            "/workspace/chunk.bin",
            "/workspace/shapes.txt",
            "/workspace/transformed.txt",
        ];
        let (mut runtime, lines) = child(
            "linux::runtime_child",
            &[
                (
                    "DW_M4E_RUNTIME_SOCKET",
                    setup.kernel_socket().display().to_string(),
                ),
                ("DW_M4E_RUNTIME_PATHS", paths.join(",")),
            ],
        );
        let results: Vec<(String, Vec<u8>)> = until_done(&lines)
            .into_iter()
            .filter(|line| !line.starts_with("PID "))
            .map(|line| {
                let parts: Vec<&str> = line.splitn(4, ' ').collect();
                assert_eq!(parts[0], "RESULT", "{}", parts.get(1).unwrap_or(&""));
                (parts[1].to_owned(), unhex(parts[2]))
            })
            .collect();
        let got = |path: &str| {
            results
                .iter()
                .find(|(p, _)| p == path)
                .map(|(_, c)| c.clone())
                .unwrap()
        };
        let marker = b"[redacted:api-token]";
        assert_eq!(
            got("/workspace/live.txt"),
            [b"token=".as_slice(), marker, b"\n"].concat()
        );
        evidence("return-path-fs-read-live-value", "placeholder");
        assert_eq!(
            got("/workspace/binary.bin"),
            [b"\x00\xff\x10".as_slice(), marker, b"\x01\xfe"].concat()
        );
        evidence("return-path-binary-around-value", "placeholder");
        let across = got("/workspace/chunk.bin");
        assert!(contains(&across, marker) && !contains(&across, &value));
        evidence("return-path-across-read-boundary", "placeholder");
        let shaped = got("/workspace/shapes.txt");
        for (class, secret) in [
            ("github", &github),
            ("openai", &openai),
            ("slack", &slack),
            ("aws", &aws),
            ("jwt", &jwt),
            ("pem_private_key", &pem),
            ("connection_string", &password),
            ("keyword", &keyword),
        ] {
            assert!(!contains(&shaped, secret), "{class} reached the runtime");
            evidence(&format!("return-path-shape-{class}"), "pattern-placeholder");
        }
        assert!(contains(&shaped, b"[redacted:pattern]"));
        // Transformed forms are NOT GUARANTEED, and are not redacted: the
        // documented limitation, measured.
        assert_eq!(got("/workspace/transformed.txt"), transformed);
        evidence(
            "return-path-transformed-value",
            "NOT-REDACTED-documented-limitation",
        );

        // The runtime's address space: the value in no readable mapping.
        let runtime_pid = runtime.id();
        assert_eq!(
            memory_holds(runtime_pid, &value),
            Some(false),
            "runtime memory"
        );
        evidence("runtime-address-space", "value-absent");
        let _ = runtime.kill();
        let _ = runtime.wait();

        // The authority daemon, after redacting: the raw value is gone from
        // its memory.
        let authority_raw = memory_holds(server.pid, &value);
        assert_eq!(authority_raw, Some(false), "authority memory");
        evidence("authority-residue-after-redaction", "raw-value-absent");
        assert_eq!(
            memory_holds(broker.pid, &value),
            Some(false),
            "broker memory"
        );
        evidence("broker-residue-after-fs-read", "raw-value-absent");

        // The audit: which handle and which classes, and counts; no bytes.
        let hits = setup.events("secret.redaction_hit");
        assert!(!hits.is_empty());
        let text: String = hits.iter().map(|r| format!("{r:?}")).collect();
        assert!(text.contains("api-token"));
        for class in [
            "github",
            "openai",
            "slack",
            "aws",
            "jwt",
            "pem_private_key",
            "keyword",
        ] {
            assert!(text.contains(class), "{class}");
        }
        evidence("audit-redaction-hit", "handle-and-class-counts");
        // The daemons' own logs.
        let value_text = std::str::from_utf8(&value).unwrap();
        assert!(!server.stderr().contains(value_text), "authority log");
        assert!(!broker.stderr().contains(value_text), "broker log");
        evidence("daemon-logs-scan", "zero-matches");
        drop(server);
        drop(broker);

        // Durable state: the store, its WAL, the audit log, the IPC and
        // staging directories, and the daemons' logs. Only the workspace's
        // own input files may hold it.
        let inputs: Vec<PathBuf> = ["live.txt", "binary.bin", "chunk.bin", "transformed.txt"]
            .iter()
            .map(|n| root.join(n))
            .collect();
        for needle in [&value[..], &value[..16]] {
            let found = files_holding(setup.dir.path(), needle, &inputs);
            assert!(found.is_empty(), "durable plaintext in {found:?}");
        }
        evidence("durable-state-scan", "zero-matches");
    }

    #[test]
    fn a_hardened_authority_dumps_no_core_and_keeps_its_memory_from_its_own_uid() {
        let setup = Setup::new("m4e-hardened");
        let server = Server::start(&setup.authority_args(None, &[]));
        let limits = std::fs::read_to_string(format!("/proc/{}/limits", server.pid)).unwrap();
        let core = limits
            .lines()
            .find(|l| l.starts_with("Max core file size"))
            .unwrap();
        let fields: Vec<&str> = core.split_whitespace().collect();
        assert_eq!(&fields[4..6], ["0", "0"], "{core}");
        evidence("authority-rlimit-core", "0-0");
        let fd_dir = std::fs::metadata(format!("/proc/{}/fd", server.pid)).unwrap();
        assert_eq!(fd_dir.uid(), 0, "a non-dumpable process's /proc is root's");
        assert!(std::fs::read(format!("/proc/{}/environ", server.pid)).is_err());
        assert!(memory_holds(server.pid, b"anything").is_none());
        evidence(
            "authority-not-dumpable",
            "proc-root-owned-memory-unreadable",
        );
    }

    // ---- mode A: the authority's library in its own process -----------------

    const POLICY: &str = "schema_version = 1\n\n[meta]\nname = \"m4e\"\n\n[[rule]]\nid = \
        \"allow-secret-use\"\neffect = \"ALLOW\"\nwhen.verb = \"secret.use\"\nwhen.environment = \
        \"host\"\n\n[[rule]]\nid = \"default\"\neffect = \"DENY\"\nreason = \"NO_MATCHING_RULE\"\n";

    /// The authority, as a child: start on `DW_M4E_HOST_DIR` with the secret
    /// metadata, reach the real broker, admit a run, use `api-token` once and
    /// replay it, then wait to be read.
    #[test]
    #[ignore = "the authority-host child of mode_a_leaves_the_value_in_neither_process"]
    fn authority_host_child() {
        let (Ok(dir), Ok(broker), Ok(entry)) = (
            std::env::var("DW_M4E_HOST_DIR"),
            std::env::var("DW_M4E_HOST_BROKER"),
            std::env::var("DW_M4E_HOST_ENTRY"),
        ) else {
            return;
        };
        let dir = PathBuf::from(dir);
        let mut config = StartupConfig::new(
            PolicySet {
                profile: "m4e".to_owned(),
                sources: vec![PolicySource {
                    name: "m4e.toml".to_owned(),
                    text: POLICY.to_owned(),
                }],
            },
            Mode::Balanced,
            vec!["secret.use:*".to_owned()],
        );
        let text = std::fs::read_to_string(secrets_file(&dir, &entry)).unwrap();
        config.secrets = dwkd_authority::secret::metadata::parse(&text).unwrap();
        let link: Arc<dyn EffectBroker> =
            Arc::new(UnixBroker::new(PathBuf::from(broker), own_uid()));
        let (mut authority, _) = Authority::start(
            &dir.join("state"),
            &config,
            StartOptions {
                clock: Arc::new(ManualClock::new(START_MS)),
                crash_hook: None,
                broker: Some(link),
            },
        )
        .unwrap();
        let workspace = WorkspaceId::new("ws").unwrap();
        std::fs::create_dir_all(dir.join("ws")).unwrap();
        {
            let mut operator = authority.operator();
            operator
                .install_agent_profile(&profile(
                    "operator",
                    &["secret.use:api-token"],
                    &[],
                    PrivacyClass::Any,
                ))
                .unwrap();
            operator
                .install_workspace(&workspace, WorkspaceSensitivity::Private)
                .unwrap();
            operator
                .install_workspace_root(&workspace, dir.join("ws").to_str().unwrap())
                .unwrap();
            operator
                .bind_session_workspace(&session(1), &workspace)
                .unwrap();
        }
        let caller = authority.connect(dwkd_authority::state::AuthenticatedSubject::unix_uid(1000));
        let Reply::Done(epoch) = authority.acquire_lease(&caller, &session(1)).unwrap() else {
            panic!("a lease")
        };
        let admitted = authority
            .admit_run(
                &caller,
                &admit_msg(
                    &session(1),
                    epoch,
                    "k1",
                    "operator",
                    &[],
                    &["secret.use:api-token"],
                    1,
                ),
            )
            .unwrap();
        let Reply::Done(admission) = admitted else {
            panic!("admitted")
        };
        let request = EgressRequest {
            handle: "api-token".to_owned(),
            origin: "api.example.com:443".to_owned(),
            key: IdempotencyKey::new("use-1".to_owned()).unwrap(),
        };
        for _ in 0..2 {
            let reply = authority
                .secret_egress(&caller, &session(1), admission.run_id(), epoch, &request)
                .unwrap();
            println!(
                "
M4E:{}",
                match reply {
                    EgressReply::Injected { .. } => "INJECTED".to_owned(),
                    EgressReply::Replayed { state, .. } => format!("REPLAYED {state}"),
                    other => format!("OTHER {other:?}"),
                }
            );
        }
        println!(
            "
M4E:DONE"
        );
        park();
    }

    #[test]
    fn mode_a_leaves_the_value_in_neither_process() {
        let value = fresh("host", 40);
        let Some(seeded) = Seeded::new("host", &value) else {
            println!("NOT EXERCISED: no usable kernel keyring on this host");
            return;
        };
        let dir = super::state_support::TempDir::new("m4e-host");
        let socket = dir.path().join("bipc").join("broker.sock");
        let broker = Broker::start(
            &socket,
            own_uid(),
            &["--allow-shared-authority-uid", "--allow-dumpable"],
        );
        let before = rchar(broker.pid);
        let (mut host, lines) = child(
            "linux::authority_host_child",
            &[
                ("DW_M4E_HOST_DIR", dir.path().display().to_string()),
                ("DW_M4E_HOST_BROKER", socket.display().to_string()),
                ("DW_M4E_HOST_ENTRY", seeded.0.clone()),
            ],
        );
        let answers = until_done(&lines);
        assert_eq!(answers, ["INJECTED", "REPLAYED INJECTED"]);
        evidence("mode-a-real-broker", "INJECTED-once-replay-recorded");
        // The broker read the value once: the replay read nothing.
        assert_eq!(
            rchar(broker.pid) - before,
            u64::try_from(value.len()).unwrap()
        );
        evidence("mode-a-one-shot", "rchar-exactly-one-value");
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(
            memory_holds(host.id(), &value),
            Some(false),
            "authority residue"
        );
        evidence("mode-a-authority-residue", "value-absent");
        assert_eq!(
            memory_holds(broker.pid, &value),
            Some(false),
            "broker residue"
        );
        evidence("mode-a-broker-residue", "value-absent");
        let _ = host.kill();
        let _ = host.wait();
        drop(broker);
        for needle in [&value[..], &value[..16]] {
            let found = files_holding(dir.path(), needle, &[]);
            assert!(found.is_empty(), "durable plaintext in {found:?}");
        }
        evidence("mode-a-durable-state-scan", "zero-matches");
    }

    // ---- the hosted half: three identities, the hardened daemons read as root ----

    /// A second or third identity `sudo -n -u` can start processes as.
    fn identity(variable: &str, others: &[u32]) -> (String, u32) {
        let user = std::env::var(variable).unwrap_or_default();
        assert!(
            !user.is_empty(),
            "NOT EXERCISED: set {variable} to a user `sudo -n -u` can switch to"
        );
        let probe = super::state_support::output(
            Command::new("sudo").args(["-n", "-u", &user, "id", "-u"]),
        )
        .expect("sudo runs");
        assert!(
            probe.status.success(),
            "NOT EXERCISED: `sudo -n -u {user}` cannot start a process here"
        );
        let uid: u32 = String::from_utf8_lossy(&probe.stdout)
            .trim()
            .parse()
            .unwrap();
        assert_ne!(uid, own_uid(), "{variable} is this process's uid");
        assert_ne!(uid, 0, "{variable} is root");
        assert!(!others.contains(&uid), "{variable} shares a uid");
        (user, uid)
    }

    fn traversable_only(dir: &Path) {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o711)).unwrap();
    }

    /// The broker binary, this test binary (the runtime and the scanner) and
    /// the probe client, where the other identities can run them.
    struct Staging {
        dir: super::state_support::TempDir,
        broker: PathBuf,
        tests: PathBuf,
        client: PathBuf,
    }

    fn staging() -> Staging {
        let dir = super::state_support::TempDir::new("m4e-staging");
        traversable_only(dir.path());
        let copy = |from: &Path, name: &str, mode: u32| {
            let to = dir.path().join(name);
            std::fs::copy(from, &to).unwrap();
            std::fs::set_permissions(&to, std::fs::Permissions::from_mode(mode)).unwrap();
            to
        };
        let broker = copy(&super::broker_support::broker_bin(), "dwkd-broker", 0o755);
        let tests = copy(&std::env::current_exe().unwrap(), "secret-evidence", 0o755);
        let client = copy(
            &Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/authority/broker_foreign_client.py"),
            "broker_foreign_client.py",
            0o644,
        );
        Staging {
            dir,
            broker,
            tests,
            client,
        }
    }

    fn probe_as(user: &str, stage: &Staging, args: &[&str]) -> String {
        let output = super::state_support::output(
            Command::new("sudo")
                .args(["-n", "-u", user, "/usr/bin/python3"])
                .arg(&stage.client)
                .args(args)
                .current_dir(stage.dir.path()),
        )
        .expect("sudo runs the client");
        assert!(output.status.success(), "the client failed as {user}");
        String::from_utf8(output.stdout).unwrap()
    }

    /// Root reads `pid`'s memory — the only identity that can read a
    /// non-dumpable process's — for the value, given masked so that no
    /// argument or environment of the scan holds it.
    fn root_scan(stage: &Staging, pid: u32, value: &[u8]) -> String {
        let needle = stage.dir.path().join(format!("needle-{pid}"));
        let masked: Vec<u8> = value.iter().map(|b| b ^ 0xa5).collect();
        std::fs::write(&needle, masked).unwrap();
        std::fs::set_permissions(&needle, std::fs::Permissions::from_mode(0o600)).unwrap();
        let output = super::state_support::output(
            Command::new("sudo")
                .args(["-n", "env"])
                .arg(format!("DW_M4E_SCAN_PID={pid}"))
                .arg(format!("DW_M4E_SCAN_NEEDLE={}", needle.display()))
                .arg(&stage.tests)
                .args([
                    "--ignored",
                    "--exact",
                    "linux::memscan_child",
                    "--nocapture",
                    "--test-threads=1",
                ]),
        )
        .expect("sudo runs the scanner");
        let _ = std::fs::remove_file(&needle);
        let text = String::from_utf8_lossy(&output.stdout).into_owned();
        text.lines()
            .find_map(|l| l.split_once("M4E:SCAN ").map(|(_, r)| r.trim().to_owned()))
            .unwrap_or_else(|| format!("no-report {text}"))
    }

    /// The scanner, as root: read `DW_M4E_SCAN_PID`'s memory for the needle.
    #[test]
    #[ignore = "the root memory scanner of the hosted secret evidence"]
    fn memscan_child() {
        let (Ok(pid), Ok(path)) = (
            std::env::var("DW_M4E_SCAN_PID"),
            std::env::var("DW_M4E_SCAN_NEEDLE"),
        ) else {
            return;
        };
        let needle: Vec<u8> = std::fs::read(path)
            .unwrap()
            .iter()
            .map(|b| b ^ 0xa5)
            .collect();
        let answer = match memory_holds(pid.parse().unwrap(), &needle) {
            Some(true) => "present",
            Some(false) => "absent",
            None => "unreadable",
        };
        println!("\nM4E:SCAN {answer}");
    }

    #[test]
    #[ignore = "needs DW_BROKER_AS and DW_PEER_AS; run by `make secret-broker-evidence`"]
    fn three_identities_keep_the_value_from_the_broker_store_and_the_runtime() {
        let (broker_user, broker_uid) = identity("DW_BROKER_AS", &[]);
        let (peer_user, peer_uid) = identity("DW_PEER_AS", &[broker_uid]);
        let value = fresh("3id", 40);
        let seeded = Seeded::new("3id", &value).expect("NOT EXERCISED: no usable kernel keyring");
        let stage = staging();
        let setup = Setup::new("m4e-3id");
        traversable_only(setup.dir.path());
        std::fs::set_permissions(&setup.root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let secrets = secrets_file(setup.dir.path(), &seeded.0);
        let store = setup.dir.path().join("store.age");
        std::fs::write(&store, b"age-encryption.org/v1 (fixture ciphertext)").unwrap();
        std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(
            setup.root.join("live.txt"),
            [b"token=".as_slice(), &value, b"\n"].concat(),
        )
        .unwrap();

        // The store and the backend, from the other identities.
        for (user, [metadata, age_store, keyring, by_serial]) in [
            (
                &broker_user,
                [
                    "broker-uid-cannot-read-metadata",
                    "broker-uid-cannot-read-age-store",
                    "broker-uid-keyring-has-no-value",
                    "broker-uid-cannot-read-the-key-by-serial",
                ],
            ),
            (
                &peer_user,
                [
                    "runtime-uid-cannot-read-metadata",
                    "runtime-uid-cannot-read-age-store",
                    "runtime-uid-keyring-has-no-value",
                    "runtime-uid-cannot-read-the-key-by-serial",
                ],
            ),
        ] {
            for (case, path) in [(metadata, &secrets), (age_store, &store)] {
                let report = probe_as(user, &stage, &["read-path", path.to_str().unwrap()]);
                assert!(
                    report.contains("\"refused\": true") && report.contains("EACCES"),
                    "{case}: {report}"
                );
                evidence(case, "EACCES");
            }
            let report = probe_as(user, &stage, &["keyring-search", &seeded.0]);
            assert!(report.contains("\"found\": false"), "{keyring}: {report}");
            evidence(keyring, "not-found");
            // Even knowing the key's serial, another uid reads nothing: the
            // key gives its group and everyone else no permission at all.
            let report = probe_as(user, &stage, &["keyring-read", &seeded.serial()]);
            assert!(
                report.contains("\"read\": false") && report.contains("EACCES"),
                "{by_serial}: {report}"
            );
            evidence(by_serial, "EACCES");
        }

        // The hardened daemons, each its own identity.
        let broker_socket = PathBuf::from(format!(
            "/tmp/dwe-3id-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ))
        .join("broker.sock");
        let broker = Broker::start_as(&broker_user, &stage.broker, &broker_socket, own_uid());
        assert_eq!(broker.uid(), broker_uid);
        let mut args = setup.authority_args(None, &["--secrets-file", secrets.to_str().unwrap()]);
        args.extend([
            "--allow-uid".to_owned(),
            peer_uid.to_string(),
            "--broker-socket".to_owned(),
            broker_socket.display().to_string(),
            "--broker-uid".to_owned(),
            broker_uid.to_string(),
        ]);
        let server = Server::start(&args);

        // The runtime, as the peer identity: a staged copy of this binary.
        let output = Command::new("sudo")
            .args(["-n", "-u", &peer_user, "env"])
            .arg(format!(
                "DW_M4E_RUNTIME_SOCKET={}",
                setup.kernel_socket().display()
            ))
            .arg("DW_M4E_RUNTIME_PATHS=/workspace/live.txt")
            .arg(&stage.tests)
            .args([
                "--ignored",
                "--exact",
                "linux::runtime_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .current_dir(stage.dir.path())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut runtime = output;
        let stdout = runtime.stdout.take().unwrap();
        let (lines, received) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                let _ = lines.send(line);
            }
        });
        let report = until_done(&received);
        let pid: u32 = report
            .iter()
            .find_map(|l| l.strip_prefix("PID "))
            .expect("the runtime says its pid")
            .parse()
            .unwrap();
        let result = report
            .iter()
            .find_map(|l| l.strip_prefix("RESULT /workspace/live.txt "))
            .expect("a result");
        let content = unhex(result.split(' ').next().unwrap());
        assert_eq!(content, b"token=[redacted:api-token]\n");
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
        assert!(
            status
                .lines()
                .any(|l| l.starts_with("Uid:") && l.contains(&peer_uid.to_string()))
        );
        evidence("runtime-uid-receives-placeholder", "placeholder");

        // Root reads all three processes' memory.
        for (case, target) in [
            ("runtime-memory-root-scan", pid),
            ("authority-memory-root-scan", server.pid),
            ("broker-memory-root-scan", broker.pid),
        ] {
            assert_eq!(root_scan(&stage, target, &value), "absent", "{case}");
            evidence(case, "value-absent");
        }
        let _ = runtime.kill();
        let _ = runtime.wait();
        // The hostile runtime cannot speak the private protocol.
        let forged = probe_as(
            &peer_user,
            &stage,
            &["hello", broker_socket.to_str().unwrap()],
        );
        assert!(forged.contains("\"received\": 0"), "{forged}");
        evidence("runtime-uid-cannot-reach-broker", "0-bytes");
        drop(server);
        drop(broker);
    }

    #[test]
    #[ignore = "changes kernel.core_pattern: run only by the hosted secret job, which sets DW_M4E_CORE_EVIDENCE=1"]
    fn a_crashing_hardened_daemon_writes_no_core_where_a_dumpable_process_does() {
        assert_eq!(
            std::env::var("DW_M4E_CORE_EVIDENCE").as_deref(),
            Ok("1"),
            "NOT EXERCISED: the core-dump evidence runs only where it may change kernel.core_pattern"
        );
        let cores = PathBuf::from(format!("/tmp/dw-m4e-cores-{}", std::process::id()));
        std::fs::create_dir_all(&cores).unwrap();
        std::fs::set_permissions(&cores, std::fs::Permissions::from_mode(0o1777)).unwrap();
        let previous = std::fs::read_to_string("/proc/sys/kernel/core_pattern").unwrap();
        let set = |pattern: &str| {
            let status = Command::new("sudo")
                .args(["-n", "sysctl", "-q", "-w"])
                .arg(format!("kernel.core_pattern={pattern}"))
                .status()
                .unwrap();
            assert!(status.success(), "sysctl");
        };
        set(&format!("{}/core.%e.%p", cores.display()));
        let count = || std::fs::read_dir(&cores).unwrap().count();
        let wait_exit = |child: &mut std::process::Child| {
            let deadline = Instant::now() + Duration::from_secs(20);
            loop {
                if child.try_wait().unwrap().is_some() {
                    return;
                }
                assert!(Instant::now() < deadline, "did not exit");
                std::thread::sleep(Duration::from_millis(20));
            }
        };
        let signal = |pid: u32, name: &str| {
            assert!(
                Command::new("kill")
                    .args([&format!("-{name}"), &pid.to_string()])
                    .status()
                    .unwrap()
                    .success()
            );
        };
        // Control: a dumpable process with no core limit does write one, so
        // the mechanism this measures works on this host.
        let mut control = Command::new("sh")
            .args(["-c", "ulimit -c unlimited; exec sleep 30"])
            .spawn()
            .unwrap();
        std::thread::sleep(Duration::from_millis(200));
        signal(control.id(), "ABRT");
        wait_exit(&mut control);
        std::thread::sleep(Duration::from_millis(500));
        let control_cores = count();
        // The hardened broker and authority, crashed the same way.
        let scratch = super::state_support::TempDir::new("m4e-core");
        let socket = scratch.path().join("bipc").join("broker.sock");
        let broker = Broker::start(&socket, own_uid(), &["--allow-shared-authority-uid"]);
        signal(broker.pid, "SEGV");
        std::thread::sleep(Duration::from_millis(500));
        let setup = Setup::new("m4e-core-authority");
        let server = Server::start(&setup.authority_args(None, &[]));
        signal(server.pid, "ABRT");
        std::thread::sleep(Duration::from_millis(500));
        let after = count();
        set(previous.trim());
        drop(server);
        drop(broker);
        let _ = std::fs::remove_dir_all(&cores);
        assert!(
            control_cores >= 1,
            "NOT EXERCISED: this host writes no core even for a dumpable process"
        );
        evidence("core-dump-control", "dumpable-process-writes-core");
        assert_eq!(after, control_cores, "a hardened daemon wrote a core");
        evidence("core-dump-hardened-broker-and-authority", "no-core-written");
    }
}
