//! FIXTURE (not a violation): the one module TX012 lets name the NFC crate.

pub fn is_nfc(name: &str) -> bool {
    unicode_normalization::is_nfc(name)
}
