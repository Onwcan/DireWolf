//! The worker's program, evaluated instruction by instruction, and the
//! attempts it refuses made unconfined (ADR-0053 §§5, 18).

use super::{
    ALLOWED, AUDIT_ARCH, Answer, RET_ALLOW, RET_DENY, RET_KILL, attempt, evaluate, guarded, int,
    nr, program,
};

const PID: u32 = 4242;

fn decide(number: libc::c_long, args: [u64; 6]) -> u32 {
    let program = program(PID).unwrap_or_else(|| unreachable!("a program on this architecture"));
    evaluate(&program, nr(number), AUDIT_ARCH, args)
}

/// Arguments every guarded call is allowed with, as a hop passes them.
fn benign(number: libc::c_long) -> [u64; 6] {
    let n = |v: libc::c_int| u64::from(int(v));
    match number {
        libc::SYS_fcntl => [3, n(libc::F_GETFL), 0, 0, 0, 0],
        libc::SYS_setsockopt => [3, n(libc::SOL_SOCKET), n(libc::SO_RCVTIMEO), 0, 16, 0],
        libc::SYS_mmap => [0, 4096, n(libc::PROT_READ | libc::PROT_WRITE), 0, 0, 0],
        libc::SYS_mprotect => [0, 4096, n(libc::PROT_READ), 0, 0, 0],
        libc::SYS_tgkill => [u64::from(PID), u64::from(PID), 6, 0, 0, 0],
        _ => [0; 6],
    }
}

/// Every call the worker may make is allowed, and nothing else: each number
/// up to well past the highest any architecture defines today.
#[test]
fn the_program_allows_exactly_the_measured_calls_and_refuses_every_other_number() {
    let guarded: Vec<libc::c_long> = guarded(PID).iter().map(|(_, n, _)| *n).collect();
    let mut allowed = 0;
    for number in 0..1024 {
        let expected = if ALLOWED.iter().any(|(_, n)| *n == number) || guarded.contains(&number) {
            allowed += 1;
            RET_ALLOW
        } else {
            RET_DENY
        };
        assert_eq!(decide(number, benign(number)), expected, "syscall {number}");
    }
    assert_eq!(allowed, ALLOWED.len() + guarded.len());
}

/// The categories ADR-0053 §5 names, each by the target's own number.
#[test]
fn new_network_authority_execution_privilege_and_cross_process_access_are_refused() {
    let mut refused = vec![
        ("socket", libc::SYS_socket),
        ("socketpair", libc::SYS_socketpair),
        ("connect", libc::SYS_connect),
        ("bind", libc::SYS_bind),
        ("listen", libc::SYS_listen),
        ("accept", libc::SYS_accept),
        ("accept4", libc::SYS_accept4),
        ("execve", libc::SYS_execve),
        ("execveat", libc::SYS_execveat),
        ("clone", libc::SYS_clone),
        ("clone3", libc::SYS_clone3),
        ("setuid", libc::SYS_setuid),
        ("setgid", libc::SYS_setgid),
        ("setresuid", libc::SYS_setresuid),
        ("setresgid", libc::SYS_setresgid),
        ("unshare", libc::SYS_unshare),
        ("setns", libc::SYS_setns),
        ("mount", libc::SYS_mount),
        ("umount2", libc::SYS_umount2),
        ("bpf", libc::SYS_bpf),
        ("perf_event_open", libc::SYS_perf_event_open),
        ("ptrace", libc::SYS_ptrace),
        ("process_vm_readv", libc::SYS_process_vm_readv),
        ("process_vm_writev", libc::SYS_process_vm_writev),
        ("pidfd_open", libc::SYS_pidfd_open),
        ("pidfd_getfd", libc::SYS_pidfd_getfd),
        ("kill", libc::SYS_kill),
        ("tkill", libc::SYS_tkill),
        ("io_uring_setup", libc::SYS_io_uring_setup),
        ("io_uring_enter", libc::SYS_io_uring_enter),
        ("io_uring_register", libc::SYS_io_uring_register),
        ("openat", libc::SYS_openat),
        ("openat2", libc::SYS_openat2),
        ("ioctl", libc::SYS_ioctl),
        ("prctl", libc::SYS_prctl),
        ("seccomp", libc::SYS_seccomp),
        ("memfd_create", libc::SYS_memfd_create),
    ];
    #[cfg(target_arch = "x86_64")]
    refused.extend([
        ("fork", libc::SYS_fork),
        ("vfork", libc::SYS_vfork),
        ("open", libc::SYS_open),
    ]);
    for (name, number) in refused {
        assert_eq!(decide(number, [0; 6]), RET_DENY, "{name}");
        assert_eq!(
            decide(number, [u64::MAX; 6]),
            RET_DENY,
            "{name}, any arguments"
        );
    }
}

/// Another architecture's table, or `x86_64`'s x32 convention, kills the
/// process: a call allowed natively included.
#[test]
fn another_syscall_convention_kills_the_process() {
    let program = program(PID).unwrap_or_else(|| unreachable!("a program"));
    // AUDIT_ARCH_I386, AUDIT_ARCH_ARM, the other 64-bit one, none.
    for arch in [
        0x4000_0003,
        0x4000_0028,
        0xC000_003E ^ 0xC000_00B7 ^ AUDIT_ARCH,
        0,
    ] {
        if arch == AUDIT_ARCH {
            continue;
        }
        for number in [libc::SYS_read, libc::SYS_write, libc::SYS_exit_group] {
            assert_eq!(
                evaluate(&program, nr(number), arch, [0; 6]),
                RET_KILL,
                "arch {arch:#x}"
            );
        }
    }
    #[cfg(target_arch = "x86_64")]
    for number in [libc::SYS_read, libc::SYS_socket, libc::SYS_execve] {
        assert_eq!(
            evaluate(&program, nr(number) | 0x4000_0000, AUDIT_ARCH, [0; 6]),
            RET_KILL,
            "x32 {number}"
        );
    }
}

/// The argument rules, each way.
#[test]
fn guarded_calls_are_allowed_only_with_the_arguments_a_hop_passes() {
    let n = |v: libc::c_int| u64::from(int(v));
    let fcntl = |cmd| decide(libc::SYS_fcntl, [3, cmd, 0, 0, 0, 0]);
    for cmd in [
        libc::F_GETFD,
        libc::F_SETFD,
        libc::F_GETFL,
        libc::F_SETFL,
        libc::F_DUPFD_CLOEXEC,
    ] {
        assert_eq!(fcntl(n(cmd)), RET_ALLOW, "fcntl {cmd}");
    }
    for cmd in [
        libc::F_DUPFD,
        libc::F_SETOWN,
        libc::F_GETOWN,
        libc::F_SETLK,
        libc::F_SETPIPE_SZ,
    ] {
        assert_eq!(fcntl(n(cmd)), RET_DENY, "fcntl {cmd}");
    }
    let setsockopt = |level, option| decide(libc::SYS_setsockopt, [3, level, option, 0, 16, 0]);
    let socket = n(libc::SOL_SOCKET);
    assert_eq!(setsockopt(socket, n(libc::SO_RCVTIMEO)), RET_ALLOW);
    assert_eq!(setsockopt(socket, n(libc::SO_SNDTIMEO)), RET_ALLOW);
    for option in [libc::SO_BINDTODEVICE, libc::SO_REUSEADDR, libc::SO_MARK] {
        assert_eq!(setsockopt(socket, n(option)), RET_DENY, "option {option}");
    }
    assert_eq!(
        setsockopt(n(libc::IPPROTO_TCP), n(libc::SO_RCVTIMEO)),
        RET_DENY
    );
    for number in [libc::SYS_mmap, libc::SYS_mprotect] {
        let prot = |p| decide(number, [0, 4096, p, 0, 0, 0]);
        assert_eq!(prot(n(libc::PROT_READ | libc::PROT_WRITE)), RET_ALLOW);
        assert_eq!(prot(n(libc::PROT_NONE)), RET_ALLOW);
        assert_eq!(prot(n(libc::PROT_EXEC)), RET_DENY);
        assert_eq!(prot(n(libc::PROT_READ | libc::PROT_EXEC)), RET_DENY);
        assert_eq!(
            prot(n(libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC)),
            RET_DENY
        );
    }
    let tgkill = |tgid: u32| decide(libc::SYS_tgkill, [u64::from(tgid), 1, 6, 0, 0, 0]);
    assert_eq!(tgkill(PID), RET_ALLOW);
    assert_eq!(tgkill(PID + 1), RET_DENY);
    assert_eq!(tgkill(1), RET_DENY);
}

/// The attempts, made by this unconfined test process: none is refused
/// with `EPERM` -- they succeed or fail for their own reasons. In a worker
/// every one is refused (`super::super::worker`): the refusal is the
/// filter's.
#[test]
fn an_unconfined_process_is_not_refused_what_the_worker_is() {
    let (ours, _theirs) = std::os::unix::net::UnixStream::pair()
        .unwrap_or_else(|e| unreachable!("a socket pair: {e}"));
    let answers = attempt(&ours, &super::Ids::now());
    assert_eq!(answers.len(), super::ATTEMPTS, "{answers:?}");
    for (name, answer) in &answers {
        assert_ne!(*answer, Answer::Refused, "{name} is refused unconfined");
    }
    for name in [
        "socket-inet",
        "socket-unix",
        "socketpair",
        "open",
        "pidfd_open",
        "kill",
        "setresuid",
    ] {
        let found = answers.iter().find(|(n, _)| *n == name).map(|(_, a)| *a);
        assert_eq!(found, Some(Answer::Succeeded), "{name} works unconfined");
    }
    let execve = answers
        .iter()
        .find(|(n, _)| *n == "execve")
        .map(|(_, a)| *a);
    assert_eq!(
        execve,
        Some(Answer::Failed(libc::ENOENT)),
        "execve reaches the path"
    );
}
