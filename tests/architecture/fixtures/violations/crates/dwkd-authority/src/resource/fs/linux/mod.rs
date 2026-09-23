//! FIXTURE (not a violation): the reviewed syscall boundary. TX008 exempts
//! this file by name, so the rustix use below must not be a finding.

pub fn beneath(dir: rustix::fd::BorrowedFd<'_>, name: &str) -> bool {
    let how = rustix::fs::ResolveFlags::BENEATH | rustix::fs::ResolveFlags::NO_SYMLINKS;
    rustix::fs::openat2(dir, name, rustix::fs::OFlags::PATH, rustix::fs::Mode::empty(), how).is_ok()
}
