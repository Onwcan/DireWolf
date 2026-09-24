//! FIXTURE: a digest and a MAC outside the patch operations (TX018, TX013),
//! and a path relative to the working directory (TX015).

use sha2::Digest as _;

pub fn tag(key: &[u8]) -> hmac::Hmac<sha2::Sha256> {
    unimplemented!("{key:?}")
}

pub fn cwd() -> rustix::io::Result<()> {
    rustix::fs::mkdirat(rustix::fs::CWD, "x", rustix::fs::Mode::RWXU)
}
