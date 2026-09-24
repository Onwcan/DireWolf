//! FIXTURE: the name-changing operations reaching past the directories they
//! hold (TX019). Line 6, a relative `openat` on a held directory, is the
//! sanctioned form and must not be a finding; `sha2` is allowed here (TX018).

pub fn staging(parent: &std::os::fd::OwnedFd) -> rustix::io::Result<std::os::fd::OwnedFd> {
    rustix::fs::openat(parent, "staging", rustix::fs::OFlags::DIRECTORY, rustix::fs::Mode::empty())
}

pub fn by_path(path: std::path::PathBuf) -> std::io::Result<()> {
    std::fs::remove_file(path)
}

pub fn from_cwd() -> rustix::io::Result<std::os::fd::OwnedFd> {
    rustix::fs::openat2(rustix::fs::CWD, "x", rustix::fs::OFlags::RDONLY, rustix::fs::Mode::empty(), rustix::fs::ResolveFlags::empty())
}

pub fn emulate(a: &std::os::fd::OwnedFd, b: &std::os::fd::OwnedFd) {
    let _ = rustix::fs::copy_file_range(a, None, b, None, 1);
    let _ = sha2::Sha256::default();
}
