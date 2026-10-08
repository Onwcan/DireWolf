// VIOLATES TX048: a second address table, in the authority -- std's own
// classifications, a range table and a metadata name, any of which can drift
// from the one guard the two daemons share.
pub fn blocked(address: Address) -> bool {
    address.is_loopback() || address.is_private() || address.is_link_local()
}

pub const TABLE: [([u8; 4], u32); 2] = [([10, 0, 0, 0], 8), ([169, 254, 0, 0], 16)];
pub const METADATA: &str = "metadata.google.internal";
