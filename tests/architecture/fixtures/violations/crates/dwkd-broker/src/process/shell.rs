//! FIXTURE: everything a launch must never become (TX021, TX022, TX023,
//! TX013). This comment says Command::new("/bin/sh"), pre_exec, fork(),
//! execveat and /proc/self/fd/3, and must not be a finding.

use nix as _;

pub fn through_a_shell(line: &str) -> std::io::Result<std::process::Child> {
    std::process::Command::new("/bin/sh").arg("-c").arg(line).spawn()
}

pub fn with_a_closure(command: &mut std::process::Command) {
    use std::os::unix::process::CommandExt as _;
    unsafe { command.pre_exec(|| Ok(())) };
}

pub fn by_hand() -> i32 {
    libc::fork()
}

pub fn through_procfs() -> &'static str {
    "/proc/self/fd/3"
}

pub fn inheriting(command: &mut std::process::Command) {
    command.envs(std::env::vars());
}

pub fn not_the_helper(fd: &std::os::fd::OwnedFd) {
    let _ = nix::unistd::execveat(fd, c"", &[c"x"], &[c""], nix::fcntl::AtFlags::AT_EMPTY_PATH);
}

pub fn cloning(name: &String) -> String {
    name.clone()
}
