//! FIXTURE: rustix reached for outside `server/peer.rs` (TX008). The binary's
//! acknowledgement below is not a finding; the real use is.

use rustix as _;

pub fn pid() -> i32 {
    rustix::process::getpid().as_raw_nonzero().get()
}
