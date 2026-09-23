//! FIXTURE: a second canonicaliser -- the policy engine normalising names so
//! that two spellings compare equal (TX012). This comment names
//! unicode_normalization and must not itself be a finding.

use unicode_normalization as _;
use unicode_normalization::UnicodeNormalization;

pub fn same(a: &str, b: &str) -> bool {
    a.nfc().eq(b.nfc())
}
