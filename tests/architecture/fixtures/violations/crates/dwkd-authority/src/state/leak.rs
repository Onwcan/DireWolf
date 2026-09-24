//! FIXTURE: a checked descriptor leaving the authority outside the broker
//! link (TX014).

pub fn leak(handoff: crate::resource::ReadHandoff) -> std::os::fd::OwnedFd {
    handoff.into_transfer_descriptor().0
}

pub const HOW: &str = "ScmRights";
