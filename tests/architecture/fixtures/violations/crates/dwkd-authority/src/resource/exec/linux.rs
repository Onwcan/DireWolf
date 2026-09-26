//! FIXTURE: the executable resolver's Linux half, a reviewed syscall boundary
//! (TX008 exempts this file by name). Not a finding.

pub fn filesystem(fd: &std::os::fd::OwnedFd) -> bool {
    rustix::fs::fstatfs(fd).is_ok()
}
