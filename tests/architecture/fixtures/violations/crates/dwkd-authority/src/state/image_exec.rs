//! FIXTURE: an image executable's identity minted outside the workload
//! ledger (TX024), from a path and a digest no manifest pinned.

pub fn mint(path: &str, sha256: &str) -> bool {
    crate::resource::exec::image_executable_identity(path, sha256).is_ok()
}
