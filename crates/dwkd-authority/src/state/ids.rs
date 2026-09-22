//! Minting `run_id` and `cap_id`.
//!
//! # What an id is, and is not
//!
//! **An identifier, not a capability and not a secret.** A `cap_id` proves
//! nothing on its own: the kernel resolves it against its own record, checks
//! that the grant belongs to the requesting run, and checks the run against the
//! fenced lease ([`CapId`]'s own documentation, [ADR-0036] §4). A `run_id` is
//! answered only for the subject and session that hold it, and "never existed"
//! is indistinguishable from "not yours" (`UNKNOWN_RUN`). So nothing here needs
//! an id to be unguessable, and M3d does not claim one is.
//!
//! # How one is built
//!
//! The wire grammar is a UUIDv7 ([`DATA_MODEL.md`] §5, [RFC 9562] §5.7):
//!
//! ```text
//!  48 bits   unix_ts_ms          the authority clock at minting
//!   4 bits   version = 0111
//!  12 bits   rand_a  = counter[41..30]
//!   2 bits   variant = 10
//!  62 bits   rand_b  = counter[29..0] || store_instance[31..0]
//! ```
//!
//! RFC 9562 §6.2 ("Method 1: fixed bit-length dedicated counter") permits the
//! random fields to carry a counter. The counter is a column of `kernel.db`,
//! incremented **inside the same transaction** that writes the row the id
//! names, so an id is durable exactly when its row is, and a crash cannot
//! issue one twice. `store_instance` is fixed when the store is created, so two
//! stores' ids differ even at equal counters.
//!
//! No `uuid`, `rand` or `getrandom`: randomness would buy unguessability, and
//! unguessability is not a property anything relies on. Uniqueness within a
//! store is guaranteed by the counter **and enforced** by the `UNIQUE`
//! constraints on `run.run_id` and `run_grant.cap_id`; a collision — which the
//! counter makes impossible without a corrupt store — fails the transaction
//! rather than overwriting anything. Uniqueness *across* stores is
//! probabilistic, through `store_instance`.
//!
//! [ADR-0036]: ../../../../../docs/adr/0036-m3-authority-operations-and-the-capability-wire-form.md
//! [`DATA_MODEL.md`]: ../../../../../docs/DATA_MODEL.md
//! [RFC 9562]: https://www.rfc-editor.org/rfc/rfc9562
//! [`CapId`]: dwk_proto::wire::id::CapId

/// The largest counter value an id can carry. `kernel.db` enforces it with a
/// `CHECK`, so the transaction that would exceed it fails instead of wrapping.
pub(crate) const MAX_ID_COUNTER: u64 = (1 << 42) - 1;

/// The largest timestamp a UUIDv7 can carry.
const MAX_TS_MS: u64 = (1 << 48) - 1;

/// Assemble a UUIDv7 value, or `None` if a field is out of range.
///
/// Pure. The caller supplies the three inputs; this only lays out bits.
pub(crate) fn uuid7(ts_ms: u64, counter: u64, store_instance: u32) -> Option<u128> {
    if ts_ms > MAX_TS_MS || counter > MAX_ID_COUNTER {
        return None;
    }
    let ts = u128::from(ts_ms);
    let counter = u128::from(counter);
    let rand_a = (counter >> 30) & 0x0fff;
    let rand_b = ((counter & 0x3fff_ffff) << 32) | u128::from(store_instance);
    Some((ts << 80) | (0x7 << 76) | (rand_a << 64) | (0b10 << 62) | rand_b)
}

#[cfg(test)]
mod tests {
    use super::{MAX_ID_COUNTER, uuid7};
    use dwk_proto::wire::id::{CapId, RunId, decode_uuid7, encode_uuid};

    #[test]
    fn a_minted_value_is_a_uuidv7_the_wire_accepts() {
        let Some(value) = uuid7(1_758_000_000_000, 1, 0xdead_beef) else {
            unreachable!("in range")
        };
        assert_eq!(decode_uuid7(&encode_uuid(value)), Some(value));
        assert!(RunId::from_uuid(value).is_some());
        assert!(CapId::from_uuid(value).is_some());
    }

    #[test]
    fn distinct_counters_give_distinct_ids_at_one_instant() {
        let mut seen = std::collections::BTreeSet::new();
        for counter in [0, 1, 2, 1 << 30, (1 << 30) + 1, MAX_ID_COUNTER] {
            let Some(value) = uuid7(5, counter, 9) else {
                unreachable!("in range")
            };
            assert!(seen.insert(value), "counter {counter} repeated an id");
        }
    }

    #[test]
    fn distinct_stores_give_distinct_ids_at_one_counter() {
        assert_ne!(uuid7(5, 1, 1), uuid7(5, 1, 2));
    }

    #[test]
    fn out_of_range_inputs_are_refused_rather_than_wrapped() {
        assert!(uuid7(1 << 48, 0, 0).is_none(), "timestamp past 48 bits");
        assert!(
            uuid7(0, MAX_ID_COUNTER + 1, 0).is_none(),
            "counter past 42 bits"
        );
    }

    #[test]
    fn ids_from_one_store_sort_by_counter_within_an_instant() {
        let a = uuid7(100, 1, 7);
        let b = uuid7(100, 2, 7);
        assert!(a < b, "the counter occupies the high random bits");
    }
}
