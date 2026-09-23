//! FIXTURE: the portable half of the resolver reaching for rustix itself
//! (TX008). Only `linux/mod.rs` beside it is a reviewed syscall boundary;
//! being next to one is not being one.

pub fn reopen(path: &str) -> bool {
    rustix::fs::open(path, rustix::fs::OFlags::RDONLY, rustix::fs::Mode::empty()).is_ok()
}
