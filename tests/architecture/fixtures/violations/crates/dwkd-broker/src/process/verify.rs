//! FIXTURE: the launch's re-proof, hashing the executable through its
//! descriptor (TX018 exempts this file by name). Not a finding.

use sha2::{Digest as _, Sha256};

pub fn digest(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}
