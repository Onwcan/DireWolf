//! FIXTURE: the launch helper, the one file that executes (TX023 exempts it
//! by name). Not a finding.

pub fn exec(fd: &std::os::fd::OwnedFd) {
    let _ = nix::sys::resource::setrlimit(nix::sys::resource::Resource::RLIMIT_CORE, 0, 0);
    let _ = nix::unistd::execveat(fd, c"", &[c"x"], &[c""], nix::fcntl::AtFlags::AT_EMPTY_PATH);
}
