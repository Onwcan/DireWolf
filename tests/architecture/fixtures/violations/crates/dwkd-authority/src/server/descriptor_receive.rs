//! FIXTURE: the runtime endpoint receiving a descriptor a runtime passed
//! (TX061) -- the one way to a terminal the runtime controls.

pub const RECEIVE: &str = "recvmsg";
pub const BUFFER: &str = "RecvAncillaryBuffer";
pub const OWNED: &str = "ControlMessageOwned";
pub const RIGHTS: &str = "SCM_RIGHTS";
