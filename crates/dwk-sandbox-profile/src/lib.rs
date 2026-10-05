//! The `oci-strict` profile (M5a, [ADR-0047] §5): every value the broker
//! applies to an execution environment and the sandbox probe checks from
//! inside it — the identity, the mounts, the limits, the labels, the device
//! set and the seccomp policy.
//!
//! **Implementation policy, not a wire contract.** Nothing here crosses a
//! protocol: the authority never sees these values (it judges the probe's
//! per-invariant verdicts, whose vocabulary is `dwk-proto`'s), and no message
//! can carry or change one. They live in their own crate because the two
//! programs that must agree on them — the broker, which applies them, and the
//! probe, which runs inside the environment and checks them — share no other
//! code. The authority does not link this crate.
//!
//! **Not configuration.** No operator setting, flag or message changes a value
//! here; a weaker profile is not a variant of this one (ADR-0047 §5).
//!
//! [ADR-0047]: ../../../docs/adr/0047-m5a-oci-execution-environment-and-measured-assurance.md

// ---------------------------------------------------------------------------
// Identity, mounts, limits (SANDBOX.md §2).
// ---------------------------------------------------------------------------

/// The uid every `oci-strict` process runs as: not root, and outside the
/// range a host's own accounts use.
pub const SANDBOX_UID: u32 = 10_001;
/// The gid every `oci-strict` process runs as.
pub const SANDBOX_GID: u32 = 10_001;
/// Where the run's workspace is mounted: the one ordinary writable mount.
pub const WORKSPACE_TARGET: &str = "/workspace";
/// The first temporary mount: writable, `nosuid`, `nodev`, and executable,
/// because ordinary build tools run what they compile there (a `go test`
/// binary, a native extension's probe); the workspace is executable anyway.
pub const TMP_TARGET: &str = "/tmp";
/// Its size, in bytes (512 MiB).
pub const TMP_BYTES: u64 = 512 << 20;
/// The second temporary mount: writable, `nosuid`, `nodev`, `noexec`.
pub const VAR_TMP_TARGET: &str = "/var/tmp";
/// Its size, in bytes (128 MiB).
pub const VAR_TMP_BYTES: u64 = 128 << 20;
/// The two temporary mounts exactly as the runtime is asked for them and
/// records them: `(target, options)`. The broker requests these strings and
/// compares the runtime's record with them byte for byte.
pub const TMPFS: &[(&str, &str)] = &[
    (TMP_TARGET, "rw,nosuid,nodev,exec,size=536870912,mode=1777"),
    (
        VAR_TMP_TARGET,
        "rw,nosuid,nodev,noexec,size=134217728,mode=1777",
    ),
];
/// The most tasks (processes and threads) the environment may hold.
pub const PIDS_LIMIT: u64 = 256;
/// The memory limit, in bytes (2 GiB).
pub const MEMORY_BYTES: u64 = 2 << 30;
/// Memory plus swap, in bytes: equal to [`MEMORY_BYTES`], so no swap.
pub const MEMORY_SWAP_BYTES: u64 = MEMORY_BYTES;
/// The CPU limit, in nanocpus (2.0 CPUs).
pub const NANO_CPUS: u64 = 2_000_000_000;
/// The CFS period the CPU limit is expressed over, in microseconds.
pub const CPU_PERIOD_MICROS: u64 = 100_000;
/// The CFS quota per period, in microseconds: [`NANO_CPUS`] of [`CPU_PERIOD_MICROS`].
pub const CPU_QUOTA_MICROS: u64 = 200_000;
/// `RLIMIT_NOFILE`, soft and hard.
pub const RLIMIT_NOFILE: u64 = 1024;
/// `RLIMIT_NPROC`, soft and hard.
pub const RLIMIT_NPROC: u64 = 256;
/// `RLIMIT_FSIZE`, soft and hard: the largest file one process may write.
pub const RLIMIT_FSIZE: u64 = 1 << 30;
/// `RLIMIT_CORE`: no core file, ever.
pub const RLIMIT_CORE: u64 = 0;
/// `oom_score_adj`: an environment is reclaimed before the daemons are.
pub const OOM_SCORE_ADJ: i32 = 500;

/// Where the assurance probe lives in the sandbox image: part of the image's
/// read-only root, bound to it by the image's content digest and, separately,
/// by its own SHA-256.
pub const PROBE_PATH: &str = "/usr/libexec/direwolf/sandbox-probe";
/// The probe's argument for the environment's first process: hold the
/// environment open and do nothing else.
pub const PROBE_HOLD: &str = "hold";
/// The probe's argument for a measurement.
pub const PROBE_MEASURE: &str = "measure";
/// The probe's argument for the child its ptrace canary attaches to.
pub const PROBE_TARGET: &str = "ptrace-target";
/// The longest one measurement by the probe may take, in seconds: the broker
/// stops waiting then, and a probe that has not answered is believed about
/// nothing (`UNOBSERVABLE`). The probe keeps its own network attempts well
/// inside it, however the namespace routes (they are bounded against this).
pub const PROBE_STEP_SECONDS: u64 = 30;

/// The label every environment carries, naming DireWolf as its owner.
pub const LABEL_OWNER: &str = "io.direwolf.owner";
/// Its value.
pub const LABEL_OWNER_VALUE: &str = "direwolf";
/// The label naming the label schema.
pub const LABEL_SCHEMA: &str = "io.direwolf.schema";
/// Its value: this schema. 2 since M5b gave every container a role
/// ([`LABEL_ROLE`], ADR-0048).
pub const LABEL_SCHEMA_VALUE: &str = "2";
/// The label naming the authority store that created the environment.
pub const LABEL_STORE: &str = "io.direwolf.store";
/// The label naming the environment.
pub const LABEL_ENVIRONMENT: &str = "io.direwolf.environment";
/// The label naming the run.
pub const LABEL_RUN: &str = "io.direwolf.run";
/// The label naming the profile.
pub const LABEL_PROFILE: &str = "io.direwolf.profile";
/// The label naming what the container is to its environment: the
/// environment itself, its relay, or its one-shot setup (`ContainerRole`'s
/// label values, M5b).
pub const LABEL_ROLE: &str = "io.direwolf.role";

// ---------------------------------------------------------------------------
// `PROXY_ONLY` (M5b, ADR-0048): the topology's fixed values.
//
// The environment's network namespace has no interface but loopback (the
// runtime's `none` network). The one-shot setup container adds
// `PROXY_ADDRESS/32` to that loopback; the relay, in the same namespace,
// listens on `PROXY_ADDRESS:PROXY_PORT` and forwards each connection to the
// broker's per-environment socket, mounted read-only at `EGRESS_TARGET` in the
// relay alone. Nothing else is routable, so a process that ignores the proxy
// variables has no path out.
// ---------------------------------------------------------------------------

/// The proxy's address: link-local, on the namespace's loopback (ADR-0024).
pub const PROXY_ADDRESS: [u8; 4] = [169, 254, 7, 1];
/// The proxy's port.
pub const PROXY_PORT: u16 = 8080;
/// The proxy, as a URL.
pub const PROXY_URL: &str = "http://169.254.7.1:8080";
/// Where the environment's own loopback services stay local.
pub const NO_PROXY_VALUE: &str = "localhost,127.0.0.1,::1";
/// Every proxy variable a `PROXY_ONLY` environment is given, and exactly
/// these: the broker's constants, never a value inherited from its own
/// environment or chosen by a caller. They are a convenience for tools; the
/// topology, not their cooperation, is the containment.
pub const PROXY_VARIABLES: &[(&str, &str)] = &[
    ("HTTP_PROXY", PROXY_URL),
    ("HTTPS_PROXY", PROXY_URL),
    ("ALL_PROXY", PROXY_URL),
    ("NO_PROXY", NO_PROXY_VALUE),
    ("http_proxy", PROXY_URL),
    ("https_proxy", PROXY_URL),
    ("all_proxy", PROXY_URL),
    ("no_proxy", NO_PROXY_VALUE),
];
/// Every name tools read a proxy from. In a `NO_NETWORK` environment none is
/// set; in a `PROXY_ONLY` one, only [`PROXY_VARIABLES`].
pub const PROXY_VARIABLE_NAMES: &[&str] = &[
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "FTP_PROXY",
    "RSYNC_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
    "ftp_proxy",
    "rsync_proxy",
];

/// Where the relay lives in the sandbox image, beside the probe, bound to the
/// image by its content digest and, separately, by its own SHA-256.
pub const RELAY_PATH: &str = "/usr/libexec/direwolf/sandbox-relay";
/// The relay's argument for the setup container: add the proxy address to
/// the namespace's loopback, then exit.
pub const RELAY_SETUP: &str = "setup";
/// The relay's argument for the relay container: serve the proxy endpoint.
pub const RELAY_SERVE: &str = "serve";
/// The relay's identity: its own unprivileged user, not the environment's.
pub const RELAY_UID: u32 = 10_002;
/// Its group.
pub const RELAY_GID: u32 = 10_002;
/// Where the broker's egress socket is mounted, read-only, in the relay — and
/// in nothing else.
pub const EGRESS_TARGET: &str = "/run/direwolf-egress";
/// The broker's per-environment socket, inside [`EGRESS_TARGET`].
pub const EGRESS_SOCKET_NAME: &str = "proxy.sock";
/// The most connections the relay forwards at once; the broker's grant bounds
/// tunnels below this.
pub const RELAY_MAX_CONNECTIONS: usize = 64;
/// The relay's and the setup's process limit: two threads for each
/// connection the relay forwards, and a margin for its own.
pub const RELAY_PIDS_LIMIT: u64 = 144;
/// Their memory limit, in bytes (64 MiB); memory plus swap is the same, so
/// no swap.
pub const RELAY_MEMORY_BYTES: u64 = 64 << 20;
/// Their CPU limit, in nanocpus (0.5 CPU).
pub const RELAY_NANO_CPUS: u64 = 500_000_000;

/// The server name the probe asks the proxy for. `.invalid` is reserved
/// (RFC 6761): no grant names it, so a DireWolf proxy refuses it with its own
/// answer — which is how the probe knows the peer it reached is the proxy.
pub const PROXY_PROBE_HOST: &str = "direwolf-probe.invalid";
/// The header a DireWolf proxy names its decision in.
pub const PROXY_DECISION_HEADER: &str = "X-DireWolf-Egress";

/// IPv4 destinations the probe tries to reach directly, with what each
/// stands for. Every attempt must be refused by the topology (no route):
/// a connection, or a silence suggesting a route whose packets are dropped,
/// fails the measurement.
pub const DIRECT_TCP_V4: &[([u8; 4], u16, &str)] = &[
    ([1, 1, 1, 1], 443, "external"),
    ([8, 8, 8, 8], 53, "external-dns"),
    ([169, 254, 169, 254], 80, "metadata"),
    ([169, 254, 7, 2], 8080, "link-local-neighbour"),
    ([172, 17, 0, 1], 80, "container-bridge-host"),
    ([192, 168, 65, 254], 80, "desktop-host"),
    ([10, 0, 0, 1], 80, "private-lan"),
    ([192, 168, 1, 1], 80, "private-lan"),
    ([100, 100, 100, 100], 80, "cgnat-overlay"),
];
/// The proxy's own address on ports that are not the proxy's: nothing may
/// listen there, so each is refused (`ECONNREFUSED`), never accepted.
pub const PROXY_OTHER_PORTS: &[u16] = &[22, 53, 80, 443, 8081];
/// IPv6 destinations the probe tries to reach directly.
pub const DIRECT_TCP_V6: &[([u16; 8], u16, &str)] = &[
    (
        [0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111],
        443,
        "external",
    ),
    ([0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254], 80, "metadata-v6"),
    (
        [0, 0, 0, 0, 0, 0xffff, 0x0101, 0x0101],
        443,
        "ipv4-mapped-external",
    ),
    (
        [0x0064, 0xff9b, 0, 0, 0, 0, 0xa9fe, 0xa9fe],
        80,
        "nat64-metadata",
    ),
];
/// Resolvers the probe sends a real DNS query to, over UDP and TCP, besides
/// those its `/etc/resolv.conf` names: none may answer.
pub const DIRECT_DNS_V4: &[([u8; 4], &str)] = &[
    ([127, 0, 0, 53], "local-stub"),
    ([127, 0, 0, 11], "runtime-embedded"),
    ([8, 8, 8, 8], "external"),
    ([1, 1, 1, 1], "external"),
    ([169, 254, 169, 253], "cloud-link-local"),
    ([192, 168, 65, 7], "desktop-host"),
    ([10, 0, 2, 3], "user-mode-network"),
];
/// The IPv6 resolvers the probe queries.
pub const DIRECT_DNS_V6: &[([u16; 8], &str)] =
    &[([0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888], "external")];

/// The only device nodes an `oci-strict` process may find: `(name, major,
/// minor)`, beneath `/dev`. Anything else — a block device, `/dev/kmsg`, a
/// GPU — fails `CONTAINER_DEVICES_MINIMAL`.
pub const ALLOWED_DEVICES: &[(&str, u32, u32)] = &[
    ("null", 1, 3),
    ("zero", 1, 5),
    ("full", 1, 7),
    ("random", 1, 8),
    ("urandom", 1, 9),
    ("tty", 5, 0),
    ("ptmx", 5, 2),
    ("pts/ptmx", 5, 2),
];

/// File names a container runtime's control socket is known by. Mounting one
/// into an environment grants its holder the host (SANDBOX.md §2, rule 1).
pub const RUNTIME_SOCKET_NAMES: &[&str] = &[
    "docker.sock",
    "containerd.sock",
    "podman.sock",
    "crio.sock",
    "buildkitd.sock",
    "dockershim.sock",
];

// ---------------------------------------------------------------------------
// The seccomp profile (SANDBOX.md §2 "Seccomp", ADR-0047 §7).
//
// DireWolf's own allowlist, written from the system-call table rather than
// copied from any runtime's default profile: everything a non-root workload
// needs, and none of the calls SANDBOX.md names -- nor any other call that
// changes the machine, loads code into the kernel, reads another process's
// memory or builds a new namespace. The default action refuses with EPERM.
// Native architectures only: no 32-bit compatibility layer is admitted.
// ---------------------------------------------------------------------------

/// The calls SANDBOX.md additionally forbids beyond a runtime's default, each
/// absent from [`SECCOMP_ALLOWED`] (and `clone` admitted only without a
/// namespace flag, `clone3` answered `ENOSYS`). Listed so that a test can
/// prove none crept into the allowlist.
pub const SECCOMP_FORBIDDEN: &[&str] = &[
    "ptrace",
    "process_vm_readv",
    "process_vm_writev",
    "kcmp",
    "perf_event_open",
    "bpf",
    "userfaultfd",
    "keyctl",
    "add_key",
    "request_key",
    "mount",
    "umount",
    "umount2",
    "pivot_root",
    "unshare",
    "setns",
    "io_uring_setup",
    "io_uring_enter",
    "io_uring_register",
    "open_tree",
    "move_mount",
    "fsopen",
    "fsconfig",
    "fsmount",
    "fspick",
    "mount_setattr",
    "chroot",
    "kexec_load",
    "kexec_file_load",
    "init_module",
    "finit_module",
    "delete_module",
    "reboot",
    "swapon",
    "swapoff",
    "acct",
    "quotactl",
    "quotactl_fd",
    "settimeofday",
    "clock_settime",
    "clock_settime64",
    "clock_adjtime",
    "clock_adjtime64",
    "adjtimex",
    "sethostname",
    "setdomainname",
    "iopl",
    "ioperm",
    "syslog",
    "vhangup",
    "open_by_handle_at",
    "name_to_handle_at",
    "pidfd_getfd",
    "process_madvise",
    "fanotify_init",
    "fanotify_mark",
    "personality",
    "modify_ldt",
    "lookup_dcookie",
    "mbind",
    "set_mempolicy",
    "get_mempolicy",
    "migrate_pages",
    "move_pages",
    "uselib",
    "ustat",
    "sysfs",
    "_sysctl",
    "nfsservctl",
    "vm86",
    "vm86old",
];

/// The calls an `oci-strict` process may make, by name, for `x86_64` and
/// `aarch64` (a name one architecture lacks is ignored there).
pub const SECCOMP_ALLOWED: &[&str] = &[
    // Files and descriptors.
    "read",
    "write",
    "readv",
    "writev",
    "pread64",
    "pwrite64",
    "preadv",
    "pwritev",
    "preadv2",
    "pwritev2",
    "open",
    "openat",
    "openat2",
    "creat",
    "close",
    "close_range",
    "lseek",
    "dup",
    "dup2",
    "dup3",
    "fcntl",
    "ioctl",
    "pipe",
    "pipe2",
    "stat",
    "fstat",
    "lstat",
    "newfstatat",
    "statx",
    "access",
    "faccessat",
    "faccessat2",
    "readlink",
    "readlinkat",
    "getdents",
    "getdents64",
    "mkdir",
    "mkdirat",
    "rmdir",
    "unlink",
    "unlinkat",
    "rename",
    "renameat",
    "renameat2",
    "link",
    "linkat",
    "symlink",
    "symlinkat",
    "mknod",
    "mknodat",
    "chmod",
    "fchmod",
    "fchmodat",
    "fchmodat2",
    "chown",
    "fchown",
    "lchown",
    "fchownat",
    "truncate",
    "ftruncate",
    "fallocate",
    "fsync",
    "fdatasync",
    "sync",
    "syncfs",
    "sync_file_range",
    "flock",
    "utime",
    "utimes",
    "futimesat",
    "utimensat",
    "getcwd",
    "chdir",
    "fchdir",
    "umask",
    "statfs",
    "fstatfs",
    "sendfile",
    "copy_file_range",
    "splice",
    "tee",
    "vmsplice",
    "readahead",
    "fadvise64",
    "getxattr",
    "lgetxattr",
    "fgetxattr",
    "listxattr",
    "llistxattr",
    "flistxattr",
    "setxattr",
    "lsetxattr",
    "fsetxattr",
    "removexattr",
    "lremovexattr",
    "fremovexattr",
    "memfd_create",
    "inotify_init",
    "inotify_init1",
    "inotify_add_watch",
    "inotify_rm_watch",
    "select",
    "pselect6",
    "poll",
    "ppoll",
    "epoll_create",
    "epoll_create1",
    "epoll_ctl",
    "epoll_wait",
    "epoll_pwait",
    "epoll_pwait2",
    "eventfd",
    "eventfd2",
    "signalfd",
    "signalfd4",
    "timerfd_create",
    "timerfd_settime",
    "timerfd_gettime",
    "io_setup",
    "io_destroy",
    "io_submit",
    "io_getevents",
    "io_pgetevents",
    "io_cancel",
    // Memory.
    "brk",
    "mmap",
    "munmap",
    "mremap",
    "mprotect",
    "madvise",
    "mlock",
    "mlock2",
    "munlock",
    "mlockall",
    "munlockall",
    "mincore",
    "msync",
    "remap_file_pages",
    "membarrier",
    "pkey_alloc",
    "pkey_free",
    "pkey_mprotect",
    "map_shadow_stack",
    "mseal",
    // Processes and threads.
    "fork",
    "vfork",
    "execve",
    "execveat",
    "exit",
    "exit_group",
    "wait4",
    "waitid",
    "kill",
    "tkill",
    "tgkill",
    "rt_sigaction",
    "rt_sigprocmask",
    "rt_sigreturn",
    "rt_sigpending",
    "rt_sigtimedwait",
    "rt_sigqueueinfo",
    "rt_tgsigqueueinfo",
    "rt_sigsuspend",
    "sigaltstack",
    "pause",
    "alarm",
    "getpid",
    "getppid",
    "gettid",
    "getpgid",
    "setpgid",
    "getpgrp",
    "getsid",
    "setsid",
    "getuid",
    "geteuid",
    "getgid",
    "getegid",
    "getresuid",
    "getresgid",
    "getgroups",
    "setuid",
    "setgid",
    "setreuid",
    "setregid",
    "setresuid",
    "setresgid",
    "setfsuid",
    "setfsgid",
    "setgroups",
    "capget",
    "capset",
    "prctl",
    "arch_prctl",
    "set_tid_address",
    "set_robust_list",
    "get_robust_list",
    "rseq",
    "futex",
    "futex_waitv",
    "futex_wait",
    "futex_wake",
    "futex_requeue",
    "sched_yield",
    "sched_getaffinity",
    "sched_setaffinity",
    "sched_getparam",
    "sched_setparam",
    "sched_getscheduler",
    "sched_setscheduler",
    "sched_get_priority_max",
    "sched_get_priority_min",
    "sched_rr_get_interval",
    "sched_getattr",
    "sched_setattr",
    "getpriority",
    "setpriority",
    "ioprio_get",
    "ioprio_set",
    "getrlimit",
    "setrlimit",
    "prlimit64",
    "getrusage",
    "times",
    "sysinfo",
    "uname",
    "getrandom",
    "getcpu",
    "pidfd_open",
    "pidfd_send_signal",
    "restart_syscall",
    "seccomp",
    "landlock_create_ruleset",
    "landlock_add_rule",
    "landlock_restrict_self",
    // Time.
    "clock_gettime",
    "clock_getres",
    "clock_nanosleep",
    "nanosleep",
    "gettimeofday",
    "time",
    "timer_create",
    "timer_settime",
    "timer_gettime",
    "timer_getoverrun",
    "timer_delete",
    "getitimer",
    "setitimer",
    // Sockets: the network namespace, not this list, decides what they reach.
    // `socket` and `socketpair` have their own rule, which refuses `AF_VSOCK`.
    "bind",
    "listen",
    "accept",
    "accept4",
    "connect",
    "getsockname",
    "getpeername",
    "sendto",
    "recvfrom",
    "sendmsg",
    "recvmsg",
    "sendmmsg",
    "recvmmsg",
    "shutdown",
    "setsockopt",
    "getsockopt",
    // System V and POSIX IPC, confined by the private IPC namespace.
    "shmget",
    "shmat",
    "shmdt",
    "shmctl",
    "semget",
    "semop",
    "semctl",
    "semtimedop",
    "msgget",
    "msgsnd",
    "msgrcv",
    "msgctl",
    "mq_open",
    "mq_unlink",
    "mq_timedsend",
    "mq_timedreceive",
    "mq_notify",
    "mq_getsetattr",
];

/// The namespace flags `clone` may not carry: `CLONE_NEWNS | CLONE_NEWCGROUP
/// | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWUSER | CLONE_NEWPID |
/// CLONE_NEWNET | CLONE_NEWTIME`.
pub const CLONE_NAMESPACE_FLAGS: u64 = 0x7E02_0080;

/// `ENOSYS`: what `clone3` answers, so a C library falls back to `clone`,
/// whose flags the filter can inspect.
pub const ENOSYS: u32 = 38;

/// `AF_VSOCK`: the one address family `socket` and `socketpair` refuse. A
/// virtual socket reaches the hypervisor host (a WSL2 or Firecracker VM's,
/// Docker Desktop's) and is not confined by a network namespace, so a
/// `--network none` environment could otherwise talk to its host through it.
pub const AF_VSOCK: u64 = 40;

/// The seccomp profile, as the compact JSON a Docker-compatible runtime
/// accepts. Byte-stable: the broker writes these exact bytes, the runtime
/// records them, and the broker compares its record's digest with theirs.
#[must_use]
pub fn seccomp_profile_json() -> String {
    use core::fmt::Write as _;
    fn quoted(names: &[&str]) -> String {
        names
            .iter()
            .map(|n| format!("\"{n}\""))
            .collect::<Vec<_>>()
            .join(",")
    }
    let mut out = String::with_capacity(8 * 1024);
    out.push_str(
        "{\"defaultAction\":\"SCMP_ACT_ERRNO\",\"defaultErrnoRet\":1,\
         \"archMap\":[{\"architecture\":\"SCMP_ARCH_X86_64\",\"subArchitectures\":[]},\
         {\"architecture\":\"SCMP_ARCH_AARCH64\",\"subArchitectures\":[]}],\"syscalls\":[",
    );
    out.push_str("{\"names\":[");
    out.push_str(&quoted(SECCOMP_ALLOWED));
    out.push_str("],\"action\":\"SCMP_ACT_ALLOW\"},");
    // Writing to a `String` cannot fail.
    let _ = write!(
        out,
        "{{\"names\":[\"clone\"],\"action\":\"SCMP_ACT_ALLOW\",\"args\":[{{\"index\":0,\
         \"value\":{CLONE_NAMESPACE_FLAGS},\"valueTwo\":0,\"op\":\"SCMP_CMP_MASKED_EQ\"}}]}},"
    );
    let _ = write!(
        out,
        "{{\"names\":[\"socket\",\"socketpair\"],\"action\":\"SCMP_ACT_ALLOW\",\"args\":[{{\"index\":0,\"value\":{AF_VSOCK},\"valueTwo\":0,\"op\":\"SCMP_CMP_NE\"}}]}},"
    );
    let _ = write!(
        out,
        "{{\"names\":[\"clone3\"],\"action\":\"SCMP_ACT_ERRNO\",\"errnoRet\":{ENOSYS}}}"
    );
    out.push_str("]}");
    out
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used,
    reason = "test assertions: a panic is the failure report"
)]
mod tests {
    use super::{
        AF_VSOCK, CLONE_NAMESPACE_FLAGS, ENOSYS, SECCOMP_ALLOWED, SECCOMP_FORBIDDEN,
        seccomp_profile_json,
    };

    /// The calls ADR-0047 names as denied: each must be absent from the
    /// allowlist and have no rule of its own.
    const NAMED_DENIALS: &[&str] = &[
        "ptrace",
        "process_vm_readv",
        "process_vm_writev",
        "kcmp",
        "perf_event_open",
        "bpf",
        "userfaultfd",
        "keyctl",
        "add_key",
        "request_key",
        "mount",
        "umount2",
        "pivot_root",
        "unshare",
        "setns",
        "io_uring_setup",
    ];

    fn rules() -> Vec<serde_json::Value> {
        let profile: serde_json::Value = serde_json::from_str(&seccomp_profile_json()).unwrap();
        profile["syscalls"].as_array().unwrap().clone()
    }

    fn names(rule: &serde_json::Value) -> Vec<String> {
        rule["names"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n.as_str().unwrap().to_owned())
            .collect()
    }

    #[test]
    fn the_temporary_mounts_say_what_their_sizes_say() {
        assert_eq!(
            super::TMPFS,
            [
                (
                    super::TMP_TARGET,
                    format!("rw,nosuid,nodev,exec,size={},mode=1777", super::TMP_BYTES).as_str()
                ),
                (
                    super::VAR_TMP_TARGET,
                    format!(
                        "rw,nosuid,nodev,noexec,size={},mode=1777",
                        super::VAR_TMP_BYTES
                    )
                    .as_str()
                ),
            ]
        );
    }

    #[test]
    fn the_profile_is_compact_strict_json_refusing_by_default() {
        let text = seccomp_profile_json();
        assert!(!text.contains(' ') && !text.contains('\n'), "compact");
        assert_eq!(text, seccomp_profile_json(), "byte-stable");
        let profile: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(profile["defaultAction"], "SCMP_ACT_ERRNO");
        assert_eq!(profile["defaultErrnoRet"], 1);
        // Native architectures only: no 32-bit compatibility layer.
        for arch in profile["archMap"].as_array().unwrap() {
            assert!(arch["subArchitectures"].as_array().unwrap().is_empty());
        }
    }

    #[test]
    fn every_named_denial_is_refused_and_no_forbidden_call_is_admitted() {
        let rules = rules();
        for name in NAMED_DENIALS.iter().chain(SECCOMP_FORBIDDEN) {
            for rule in &rules {
                assert!(!names(rule).iter().any(|n| n == name), "{name} is admitted");
            }
        }
        for (i, name) in SECCOMP_ALLOWED.iter().enumerate() {
            assert!(!SECCOMP_ALLOWED[..i].contains(name), "{name} twice");
        }
    }

    #[test]
    fn clone_is_admitted_only_without_a_namespace_flag_and_clone3_falls_back() {
        let rules = rules();
        let clone = rules
            .iter()
            .find(|r| names(r) == ["clone"])
            .expect("a clone rule");
        assert_eq!(clone["action"], "SCMP_ACT_ALLOW");
        let arg = &clone["args"][0];
        assert_eq!(arg["index"], 0);
        assert_eq!(arg["op"], "SCMP_CMP_MASKED_EQ");
        assert_eq!(arg["value"], CLONE_NAMESPACE_FLAGS);
        assert_eq!(arg["valueTwo"], 0);
        // Every namespace flag is in the mask: NEWNS, NEWCGROUP, NEWUTS,
        // NEWIPC, NEWUSER, NEWPID, NEWNET, NEWTIME.
        for flag in [
            0x0002_0000_u64,
            0x0200_0000,
            0x0400_0000,
            0x0800_0000,
            0x1000_0000,
            0x2000_0000,
            0x4000_0000,
            0x0000_0080,
        ] {
            assert_eq!(CLONE_NAMESPACE_FLAGS & flag, flag, "{flag:#x}");
        }
        // Ordinary threads and processes carry none of them.
        let thread = 0x0000_0100 | 0x0000_0200 | 0x0000_0400 | 0x0000_0800 | 0x0001_0000;
        assert_eq!(thread & CLONE_NAMESPACE_FLAGS, 0);
        let clone3 = rules
            .iter()
            .find(|r| names(r) == ["clone3"])
            .expect("a clone3 rule");
        assert_eq!(clone3["action"], "SCMP_ACT_ERRNO");
        assert_eq!(clone3["errnoRet"], ENOSYS);
    }

    #[test]
    fn a_socket_is_anything_but_a_virtual_socket() {
        let rules = rules();
        let socket = rules
            .iter()
            .find(|r| names(r) == ["socket", "socketpair"])
            .expect("a socket rule");
        assert_eq!(socket["action"], "SCMP_ACT_ALLOW");
        assert_eq!(socket["args"][0]["op"], "SCMP_CMP_NE");
        assert_eq!(socket["args"][0]["value"], AF_VSOCK);
        assert!(!SECCOMP_ALLOWED.contains(&"socket"));
        assert!(!SECCOMP_ALLOWED.contains(&"socketpair"));
    }

    #[test]
    fn the_relay_is_bounded_for_every_connection_it_may_forward() {
        let per_connection = u64::try_from(super::RELAY_MAX_CONNECTIONS).unwrap() * 2;
        assert!(super::RELAY_PIDS_LIMIT > per_connection);
        // And below the environment's own: the helpers are the smaller.
        const _: () = assert!(super::RELAY_PIDS_LIMIT < super::PIDS_LIMIT);
        const _: () = assert!(super::RELAY_MEMORY_BYTES < super::MEMORY_BYTES);
        // The proxy variables are a subset of the names, each once.
        for (name, _) in super::PROXY_VARIABLES {
            assert!(super::PROXY_VARIABLE_NAMES.contains(name), "{name}");
        }
    }
}
