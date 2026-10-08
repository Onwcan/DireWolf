// VIOLATES TX046 (only): a file the TLS configuration lives in, which TX013
// and TX044 exempt by name, growing a store and `unsafe`. TX046 restates
// TX013's prohibitions for the module, so the exemption loosens nothing.
pub fn remember(session: &[u8]) {
    let _ = rusqlite::Connection::open("kernel.db");
    unsafe { core::hint::unreachable_unchecked() }
}
