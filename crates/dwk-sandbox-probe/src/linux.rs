//! The probe's measurements, on Linux. Each check reads what the kernel
//! reports about this process and its environment, or attempts what an
//! escaping workload would attempt through a safe wrapper and records whether
//! it was refused. A check that cannot look is `UNOBSERVABLE`, never `PASS`.
//!
//! The attempts that change this process's own situation if they succeed —
//! `mount`, `setns`, `unshare` — run last, so that a weakened environment in
//! which one succeeds cannot distort the readings taken before it.

use std::fs;
use std::io::{IoSliceMut, Read as _, Write as _};
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
use std::path::Path;
use std::process::{ExitCode, Stdio};
use std::time::Duration;

use dwk_proto::brokerp::KernelNumber;
use dwk_proto::brokerp::sandbox::{
    InvariantCheck, InvariantChecks, NetworkTopology, ProbeReport, ProbeReportKind,
    ProbeReportVersion, SandboxInvariant as I, Verdict, probe_invariants,
};
use dwk_proto::wire::id::EnvironmentId;
use dwk_sandbox_profile as profile;
use nix::errno::Errno;
use nix::sys::statvfs::{FsFlags, statvfs};
use nix::unistd::Pid;

pub(crate) fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some(profile::PROBE_HOLD) if args.len() == 2 => hold(),
        Some(profile::PROBE_TARGET) if args.len() == 2 => target(),
        Some(profile::PROBE_MEASURE) if args.len() == 4 => {
            let environment = args.get(2).and_then(|s| EnvironmentId::parse(s));
            let topology = args.get(3).and_then(|t| {
                NetworkTopology::ALL
                    .iter()
                    .copied()
                    .find(|n| n.as_str() == t)
            });
            match (environment, topology) {
                (Some(environment), Some(topology)) => measure(&environment, topology),
                _ => usage(),
            }
        }
        _ => usage(),
    }
}

fn usage() -> ExitCode {
    eprintln!(
        "usage: dwk-sandbox-probe hold | measure <environment-id> <topology> | ptrace-target"
    );
    ExitCode::from(2)
}

/// The environment's first process: hold it open, do nothing.
fn hold() -> ExitCode {
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

/// The ptrace canary's child: exist briefly, do nothing.
fn target() -> ExitCode {
    std::thread::sleep(Duration::from_secs(30));
    ExitCode::SUCCESS
}

fn measure(environment: &EnvironmentId, topology: NetworkTopology) -> ExitCode {
    let status = Status::read();
    let mut found: Vec<(I, Verdict)> = vec![
        (I::ContainerUidGid, uid_gid(status.as_ref())),
        (I::ContainerCapabilitiesEmpty, capabilities(status.as_ref())),
        (
            I::ContainerNoNewPrivileges,
            field_is(status.as_ref(), "NoNewPrivs", "1"),
        ),
        (
            I::ContainerSeccompFilter,
            field_is(status.as_ref(), "Seccomp", "2"),
        ),
        (I::ContainerSeccompProfileActive, seccomp_profile_active()),
        (I::ContainerRootReadOnly, root_read_only()),
        (I::ContainerPidNamespacePrivate, pid_namespace_private()),
        (I::ContainerNetworkIsolated, network_isolated(topology)),
        (I::ContainerRlimits, rlimits()),
        (I::ContainerCgroupLimits, cgroup_limits()),
        (I::ContainerDevicesMinimal, devices_minimal()),
        (I::ContainerMountsExpected, mounts_expected()),
        (I::ContainerNoRuntimeSocket, no_runtime_socket()),
        (I::ContainerProcRestricted, proc_restricted()),
    ];
    let (workspace_writable, workspace) = workspace();
    found.push((I::ContainerWorkspaceWritable, workspace_writable));
    let (tmp_writable, tmp_fresh) = temporary(environment);
    found.push((I::ContainerTmpWritable, tmp_writable));
    found.push((I::ContainerTmpFresh, tmp_fresh));
    // The attempts that would change this process's situation, last.
    found.push((I::ContainerKeyringBlocked, keyring_blocked()));
    found.push((I::ContainerMountBlocked, mount_blocked()));
    found.push((I::ContainerSetnsBlocked, setns_blocked()));
    found.push((I::ContainerUnshareBlocked, unshare_blocked()));

    let checks: Vec<InvariantCheck> = probe_invariants()
        .into_iter()
        .map(|invariant| InvariantCheck {
            invariant,
            verdict: found
                .iter()
                .find(|(i, _)| *i == invariant)
                .map_or(Verdict::Unobservable, |(_, v)| *v),
        })
        .collect();
    let (Some(checks), Some(version)) = (InvariantChecks::new(checks), ProbeReportVersion::new(1))
    else {
        return ExitCode::from(3);
    };
    let report = ProbeReport {
        kind: ProbeReportKind::Report,
        version,
        checks,
        workspace_device: workspace.map(|(dev, _)| KernelNumber::from_u64(dev)),
        workspace_inode: workspace.map(|(_, ino)| KernelNumber::from_u64(ino)),
    };
    match report.to_bytes() {
        Ok(bytes) => {
            let mut out = std::io::stdout().lock();
            if out.write_all(&bytes).and_then(|()| out.flush()).is_ok() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(3)
            }
        }
        Err(_) => ExitCode::from(3),
    }
}

fn pass_if(ok: bool) -> Verdict {
    if ok { Verdict::Pass } else { Verdict::Fail }
}

/// `PASS` only when every part passed; `FAIL` when any failed; otherwise
/// `UNOBSERVABLE`.
fn all(parts: &[Verdict]) -> Verdict {
    if parts.contains(&Verdict::Fail) {
        Verdict::Fail
    } else if parts.iter().all(|v| *v == Verdict::Pass) {
        Verdict::Pass
    } else {
        Verdict::Unobservable
    }
}

/// `/proc/self/status`, as its `Key:\tvalue` lines.
struct Status(Vec<(String, String)>);

impl Status {
    fn read() -> Option<Self> {
        let text = fs::read_to_string("/proc/self/status").ok()?;
        Some(Self(
            text.lines()
                .filter_map(|line| {
                    let (key, value) = line.split_once(':')?;
                    Some((key.to_owned(), value.trim().to_owned()))
                })
                .collect(),
        ))
    }

    fn get(&self, key: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

fn field_is(status: Option<&Status>, key: &str, wanted: &str) -> Verdict {
    match status.and_then(|s| s.get(key)) {
        Some(value) => pass_if(value == wanted),
        None => Verdict::Unobservable,
    }
}

fn uid_gid(status: Option<&Status>) -> Verdict {
    let Some(status) = status else {
        return Verdict::Unobservable;
    };
    let ids = |key: &str, wanted: u32| {
        status.get(key).map(|v| {
            let parts: Vec<&str> = v.split_whitespace().collect();
            parts.len() == 4 && parts.iter().all(|p| p.parse::<u32>() == Ok(wanted))
        })
    };
    match (
        ids("Uid", profile::SANDBOX_UID),
        ids("Gid", profile::SANDBOX_GID),
        status.get("Groups"),
    ) {
        // No supplementary group beyond the primary one: the runtime lists
        // the primary gid there too (runc does), which grants nothing more.
        (Some(uid), Some(gid), Some(groups)) => pass_if(
            uid && gid
                && groups
                    .split_whitespace()
                    .all(|g| g.parse::<u32>() == Ok(profile::SANDBOX_GID)),
        ),
        _ => Verdict::Unobservable,
    }
}

fn capabilities(status: Option<&Status>) -> Verdict {
    let Some(status) = status else {
        return Verdict::Unobservable;
    };
    let sets = ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"];
    let mut parts = Vec::new();
    for set in sets {
        parts.push(match status.get(set) {
            Some(value) => pass_if(!value.is_empty() && value.bytes().all(|b| b == b'0')),
            None => Verdict::Unobservable,
        });
    }
    all(&parts)
}

/// DireWolf's filter, not merely a filter: two calls the runtime's default
/// profile allows and DireWolf's refuses, each aimed at the probe's own
/// processes so that nothing but the filter could refuse them.
fn seccomp_profile_active() -> Verdict {
    let own_memory = {
        let source = [0x5a_u8; 16];
        let mut dest = [0_u8; 16];
        let remote = [nix::sys::uio::RemoteIoVec {
            base: source.as_ptr().addr(),
            len: source.len(),
        }];
        match nix::sys::uio::process_vm_readv(
            Pid::this(),
            &mut [IoSliceMut::new(&mut dest)],
            &remote,
        ) {
            Ok(_) => Verdict::Fail,
            Err(Errno::EPERM) => Verdict::Pass,
            Err(_) => Verdict::Unobservable,
        }
    };
    let own_child = match std::process::Command::new(profile::PROBE_PATH)
        .arg(profile::PROBE_TARGET)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Err(_) => Verdict::Unobservable,
        Ok(mut child) => {
            let verdict = match i32::try_from(child.id()) {
                Err(_) => Verdict::Unobservable,
                Ok(raw) => {
                    let pid = Pid::from_raw(raw);
                    match nix::sys::ptrace::attach(pid) {
                        Ok(()) => {
                            let _ = nix::sys::ptrace::detach(pid, None);
                            Verdict::Fail
                        }
                        Err(Errno::EPERM) => Verdict::Pass,
                        Err(_) => Verdict::Unobservable,
                    }
                }
            };
            let _ = child.kill();
            let _ = child.wait();
            verdict
        }
    };
    all(&[own_memory, own_child])
}

fn read_only(path: &str) -> Verdict {
    match statvfs(path) {
        Ok(stat) => pass_if(stat.flags().contains(FsFlags::ST_RDONLY)),
        Err(_) => Verdict::Unobservable,
    }
}

fn root_read_only() -> Verdict {
    let refused = match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open("/.direwolf-probe-write")
    {
        Ok(_) => {
            let _ = fs::remove_file("/.direwolf-probe-write");
            Verdict::Fail
        }
        Err(_) => Verdict::Pass,
    };
    all(&[read_only("/"), refused])
}

fn pid_namespace_private() -> Verdict {
    match fs::read("/proc/1/cmdline") {
        Ok(bytes) => {
            let words: Vec<&[u8]> = bytes.split(|b| *b == 0).filter(|w| !w.is_empty()).collect();
            pass_if(
                words
                    == [
                        profile::PROBE_PATH.as_bytes(),
                        profile::PROBE_HOLD.as_bytes(),
                    ],
            )
        }
        Err(_) => Verdict::Unobservable,
    }
}

fn network_isolated(topology: NetworkTopology) -> Verdict {
    match topology {
        // M5b defines what PROXY_ONLY looks like from inside.
        NetworkTopology::ProxyOnly => Verdict::Unobservable,
        NetworkTopology::NoNetwork => {
            let interfaces = match fs::read_to_string("/proc/net/dev") {
                Ok(text) => {
                    let interfaces: Vec<&str> = text
                        .lines()
                        .skip(2)
                        .filter_map(|l| l.split_once(':').map(|(name, _)| name.trim()))
                        .collect();
                    pass_if(interfaces == ["lo"])
                }
                Err(_) => Verdict::Unobservable,
            };
            all(&[interfaces, vsock_refused()])
        }
    }
}

/// A virtual socket is not confined by the network namespace: it reaches the
/// hypervisor host. Creating one must be refused (the profile's `AF_VSOCK`
/// rule), or be impossible on this kernel.
fn vsock_refused() -> Verdict {
    use rustix::net::{AddressFamily, SocketType, socket};
    match socket(AddressFamily::VSOCK, SocketType::STREAM, None) {
        Ok(_) => Verdict::Fail,
        // EPERM is the profile's refusal; any other failure also means
        // there is no virtual socket to connect with.
        Err(_) => Verdict::Pass,
    }
}

fn rlimits() -> Verdict {
    let Ok(text) = fs::read_to_string("/proc/self/limits") else {
        return Verdict::Unobservable;
    };
    let limit = |label: &str| -> Option<(String, String)> {
        let line = text.lines().find(|l| l.starts_with(label))?;
        let mut rest = line.get(label.len()..)?.split_whitespace();
        Some((rest.next()?.to_owned(), rest.next()?.to_owned()))
    };
    let exact = |label: &str, wanted: u64| match limit(label) {
        Some((soft, hard)) => pass_if(soft == wanted.to_string() && hard == wanted.to_string()),
        None => Verdict::Unobservable,
    };
    all(&[
        exact("Max open files", profile::RLIMIT_NOFILE),
        exact("Max processes", profile::RLIMIT_NPROC),
        exact("Max file size", profile::RLIMIT_FSIZE),
        exact("Max core file size", profile::RLIMIT_CORE),
    ])
}

fn cgroup_limits() -> Verdict {
    let read = |name: &str| {
        fs::read_to_string(Path::new("/sys/fs/cgroup").join(name))
            .ok()
            .map(|s| s.trim().to_owned())
    };
    let exact = |name: &str, wanted: String| match read(name) {
        Some(value) => pass_if(value == wanted),
        None => Verdict::Unobservable,
    };
    all(&[
        exact("memory.max", profile::MEMORY_BYTES.to_string()),
        // memory.swap.max is swap alone: memory+swap equal to memory is none.
        exact(
            "memory.swap.max",
            (profile::MEMORY_SWAP_BYTES.saturating_sub(profile::MEMORY_BYTES)).to_string(),
        ),
        exact("pids.max", profile::PIDS_LIMIT.to_string()),
        exact(
            "cpu.max",
            format!(
                "{} {}",
                profile::CPU_QUOTA_MICROS,
                profile::CPU_PERIOD_MICROS
            ),
        ),
    ])
}

/// `(major, minor)` of a device number, as glibc encodes it.
fn major_minor(rdev: u64) -> (u64, u64) {
    let major = ((rdev >> 8) & 0xfff) | ((rdev >> 32) & !0xfff);
    let minor = (rdev & 0xff) | ((rdev >> 12) & !0xff);
    (major, minor)
}

fn devices_minimal() -> Verdict {
    let mut verdict = Verdict::Pass;
    for (dir, prefix) in [("/dev", ""), ("/dev/pts", "pts/")] {
        let Ok(entries) = fs::read_dir(dir) else {
            return Verdict::Unobservable;
        };
        for entry in entries.take(512) {
            let Ok(entry) = entry else {
                return Verdict::Unobservable;
            };
            let Ok(meta) = fs::symlink_metadata(entry.path()) else {
                return Verdict::Unobservable;
            };
            let kind = meta.file_type();
            if kind.is_block_device() {
                verdict = Verdict::Fail;
            } else if kind.is_char_device() {
                let name = format!("{prefix}{}", entry.file_name().to_string_lossy());
                let (major, minor) = major_minor(meta.rdev());
                let allowed = profile::ALLOWED_DEVICES.iter().any(|(n, ma, mi)| {
                    *n == name && u64::from(*ma) == major && u64::from(*mi) == minor
                });
                if !allowed {
                    verdict = Verdict::Fail;
                }
            }
        }
    }
    verdict
}

/// The mount points in `/proc/self/mountinfo`, unescaped.
fn mount_points() -> Option<Vec<String>> {
    let text = fs::read_to_string("/proc/self/mountinfo").ok()?;
    let mut points = Vec::new();
    for line in text.lines() {
        let field = line.split(' ').nth(4)?;
        points.push(unescape(field));
    }
    Some(points)
}

/// Undo the kernel's octal escaping of space, tab, newline and backslash.
fn unescape(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        let octal = bytes
            .get(i + 1..i + 4)
            .filter(|d| b == b'\\' && d.iter().all(|c| (b'0'..=b'7').contains(c)))
            .and_then(|d| u8::from_str_radix(std::str::from_utf8(d).ok()?, 8).ok());
        match octal {
            Some(value) => {
                out.push(value);
                i += 4;
            }
            None => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn mounts_expected() -> Verdict {
    const EXACT: &[&str] = &[
        "/",
        "/proc",
        "/dev",
        "/dev/pts",
        "/dev/mqueue",
        "/dev/shm",
        "/sys",
        "/sys/fs/cgroup",
        profile::WORKSPACE_TARGET,
        profile::TMP_TARGET,
        profile::VAR_TMP_TARGET,
        "/etc/hostname",
        "/etc/hosts",
        "/etc/resolv.conf",
    ];
    // The runtime masks and write-protects paths beneath /proc and /sys by
    // mounting over them; nothing it mounts there is a way out.
    const BENEATH: &[&str] = &["/proc/", "/sys/"];
    match mount_points() {
        Some(points) => pass_if(
            points
                .iter()
                .all(|p| EXACT.contains(&p.as_str()) || BENEATH.iter().any(|b| p.starts_with(b))),
        ),
        None => Verdict::Unobservable,
    }
}

fn is_runtime_socket_name(name: &str) -> bool {
    profile::RUNTIME_SOCKET_NAMES.contains(&name)
}

fn no_runtime_socket() -> Verdict {
    let Some(points) = mount_points() else {
        return Verdict::Unobservable;
    };
    if points.iter().any(|p| {
        Path::new(p)
            .file_name()
            .is_some_and(|n| is_runtime_socket_name(&n.to_string_lossy()))
    }) {
        return Verdict::Fail;
    }
    // Any socket file where runtimes keep theirs, however it got there.
    let mut stack: Vec<(std::path::PathBuf, u8)> = ["/run", "/var/run", "/tmp", "/var/tmp"]
        .into_iter()
        .map(|p| (std::path::PathBuf::from(p), 0))
        .collect();
    let mut seen = 0usize;
    while let Some((dir, depth)) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            seen += 1;
            if seen > 4096 {
                return Verdict::Unobservable;
            }
            let Ok(meta) = fs::symlink_metadata(entry.path()) else {
                continue;
            };
            let name = entry.file_name().to_string_lossy().into_owned();
            if meta.file_type().is_socket() || is_runtime_socket_name(&name) {
                return Verdict::Fail;
            }
            if meta.is_dir() && depth < 3 {
                stack.push((entry.path(), depth + 1));
            }
        }
    }
    Verdict::Pass
}

fn proc_restricted() -> Verdict {
    let sysrq = match fs::OpenOptions::new()
        .write(true)
        .open("/proc/sysrq-trigger")
    {
        Ok(_) => Verdict::Fail,
        Err(_) => Verdict::Pass,
    };
    let kcore = match fs::File::open("/proc/kcore") {
        Err(_) => Verdict::Pass,
        Ok(mut file) => {
            let mut buffer = [0_u8; 16];
            match file.read(&mut buffer) {
                Ok(0) | Err(_) => Verdict::Pass,
                Ok(_) => Verdict::Fail,
            }
        }
    };
    all(&[sysrq, kcore, read_only("/proc/sys"), read_only("/sys")])
}

/// Whether `/workspace` can be written, and its `(st_dev, st_ino)`.
fn workspace() -> (Verdict, Option<(u64, u64)>) {
    let identity = fs::metadata(profile::WORKSPACE_TARGET)
        .ok()
        .filter(fs::Metadata::is_dir)
        .map(|m| (m.dev(), m.ino()));
    let name = Path::new(profile::WORKSPACE_TARGET)
        .join(format!(".direwolf-probe-{}", std::process::id()));
    let writable = match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&name)
    {
        Ok(mut file) => {
            let wrote = file.write_all(b"probe").is_ok();
            drop(file);
            let removed = fs::remove_file(&name).is_ok();
            pass_if(wrote && removed)
        }
        Err(_) => Verdict::Fail,
    };
    (
        if identity.is_some() {
            writable
        } else {
            Verdict::Unobservable
        },
        identity,
    )
}

/// Whether `/tmp` and `/var/tmp` can be written, and whether they held
/// nothing but this environment's own marker when the measurement began.
/// The marker stays: an environment that inherited another's temporary state
/// would find it.
fn temporary(environment: &EnvironmentId) -> (Verdict, Verdict) {
    let marker = format!(".direwolf-env-{}", environment.as_str());
    let mut writable = Vec::new();
    let mut fresh = Vec::new();
    for dir in [profile::TMP_TARGET, profile::VAR_TMP_TARGET] {
        match fs::read_dir(dir) {
            Ok(entries) => fresh.push(pass_if(
                entries
                    .flatten()
                    .all(|e| e.file_name().to_string_lossy() == marker),
            )),
            Err(_) => fresh.push(Verdict::Unobservable),
        }
        writable.push(
            match fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(Path::new(dir).join(&marker))
            {
                Ok(mut file) => pass_if(file.write_all(b"direwolf").is_ok()),
                Err(_) => Verdict::Fail,
            },
        );
    }
    (all(&writable), all(&fresh))
}

fn refused<T>(result: Result<T, Errno>) -> Verdict {
    pass_if(result.is_err())
}

fn keyring_blocked() -> Verdict {
    pass_if(
        linux_keyutils::KeyRing::from_special_id(linux_keyutils::KeyRingIdentifier::Session, false)
            .is_err(),
    )
}

fn mount_blocked() -> Verdict {
    use nix::mount::{MntFlags, MsFlags, mount, umount2};
    let mounted = refused(mount(
        Some("tmpfs"),
        profile::VAR_TMP_TARGET,
        Some("tmpfs"),
        MsFlags::empty(),
        None::<&str>,
    ));
    let unmounted = refused(umount2(profile::TMP_TARGET, MntFlags::MNT_DETACH));
    let pivoted = refused(nix::unistd::pivot_root("/", "/"));
    all(&[mounted, unmounted, pivoted])
}

fn setns_blocked() -> Verdict {
    match fs::File::open("/proc/self/ns/net") {
        Ok(file) => refused(nix::sched::setns(
            &file,
            nix::sched::CloneFlags::CLONE_NEWNET,
        )),
        Err(_) => Verdict::Unobservable,
    }
}

fn unshare_blocked() -> Verdict {
    use nix::sched::{CloneFlags, unshare};
    let flags = [
        CloneFlags::CLONE_NEWUSER,
        CloneFlags::CLONE_NEWNS,
        CloneFlags::CLONE_NEWNET,
        CloneFlags::CLONE_NEWPID,
        CloneFlags::CLONE_NEWUTS,
        CloneFlags::CLONE_NEWIPC,
        CloneFlags::CLONE_NEWCGROUP,
    ];
    let parts: Vec<Verdict> = flags.into_iter().map(|f| refused(unshare(f))).collect();
    all(&parts)
}
