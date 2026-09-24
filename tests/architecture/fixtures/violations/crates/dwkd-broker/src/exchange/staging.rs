//! FIXTURE: reclaiming a staging directory by path (TX019). Line 5, a record
//! opened relative to the held staging directory, is the sanctioned form.

pub fn record(staging: &std::os::fd::OwnedFd) -> rustix::io::Result<std::os::fd::OwnedFd> {
    rustix::fs::openat(staging, "record", rustix::fs::OFlags::RDONLY, rustix::fs::Mode::empty())
}

pub fn sweep_by_spelling(workspace: &str) -> std::io::Result<()> {
    std::fs::remove_dir_all(format!("{workspace}/.dwkd-stale"))
}

pub fn from_cwd() -> rustix::io::Result<()> {
    rustix::fs::unlinkat(rustix::fs::CWD, ".dwkd-stale", rustix::fs::AtFlags::REMOVEDIR)
}
