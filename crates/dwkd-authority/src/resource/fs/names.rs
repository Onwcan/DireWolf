//! What a single filesystem name may be, and when two names are one.
//!
//! The only module in the authority that consults a Unicode database
//! (`unicode-normalization`, Unicode 17.0.0; TX012 confines it here and RS016
//! keeps it out of the protocol, [ADR-0034] still holding for DWKP).
//!
//! # NFC semantics, precisely ([ADR-0042] §6)
//!
//! * **Input must already be NFC.** A requested name that is not is refused,
//!   never normalised: normalising would look up a spelling nobody sent, and on
//!   a byte-exact filesystem that can be a different object.
//! * **Lookup is by the exact bytes requested**, and the resolver then proves
//!   the directory holds an entry with exactly those bytes — so the canonical
//!   component *is* the on-disk name, and a filesystem that matched a
//!   different spelling (case folding, normalisation-insensitive lookup) is
//!   refused rather than believed.
//! * **Two entries that are canonically equivalent are an ambiguity**, and
//!   the requested one is refused: `é` (U+00E9) beside `e` + U+0301, or `K`
//!   beside KELVIN SIGN U+212A. Two objects would share one canonical
//!   spelling, and normalisation must never let the authority check one and
//!   use the other.
//! * **The handle, not the name, is the object.** Display and comparison use
//!   the verified on-disk bytes; the descriptor is what is later used.
//!
//! A name containing a code point unassigned in Unicode 17.0.0 is checked
//! with that version's tables; a later Unicode could decompose it, and the
//! upgrade is then a change to which names resolve, recorded by the pinned
//! version rather than hidden.
//!
//! [ADR-0034]: ../../../../../../docs/adr/0034-protocol-depends-on-no-unicode-database.md
//! [ADR-0042]: ../../../../../../docs/adr/0042-m4a-canonical-filesystem-resolution.md

use unicode_normalization::{UnicodeNormalization as _, is_nfc};

use crate::resource::PathComponent;

/// Why a name cannot be a canonical component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum NameProblem {
    /// Over `NAME_MAX` bytes.
    TooLong,
    /// A backslash.
    Separator,
    /// A control, bidi-override or invisible-format character.
    Character,
    /// Not in NFC.
    NotNfc,
}

/// Characters a canonical name may not contain: every control character (C0,
/// DEL, C1 — a newline in a name is a log injection), the bidi overrides and
/// isolates that make a name display as something it is not, and the
/// zero-width and format characters that make two names look identical.
/// [`SANDBOX.md`] §3's list, plus U+061C, the line and paragraph separators
/// and the byte-order mark.
///
/// [`SANDBOX.md`]: ../../../../../../docs/SANDBOX.md
const fn disallowed(c: char) -> bool {
    matches!(
        c,
        '\u{0}'..='\u{1f}'
            | '\u{7f}'..='\u{9f}'
            | '\u{61c}'
            | '\u{200b}'..='\u{200f}'
            | '\u{2028}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}'
            | '\u{feff}'
    )
}

/// Whether `name` may be a canonical component. The separator, `.`, `..` and
/// the empty name are the grammar's to refuse; this is everything about the
/// characters themselves.
pub(super) fn check(name: &str) -> Result<(), NameProblem> {
    if name.len() > PathComponent::MAX_BYTES {
        return Err(NameProblem::TooLong);
    }
    if name.contains('\\') {
        return Err(NameProblem::Separator);
    }
    if name.chars().any(disallowed) {
        return Err(NameProblem::Character);
    }
    // Bounded by the 255-byte check above.
    if !is_nfc(name) {
        return Err(NameProblem::NotNfc);
    }
    Ok(())
}

/// Whether a directory entry `sibling` — some other spelling found beside the
/// requested `name` — is canonically equivalent to it.
///
/// `name` is NFC (the grammar refused it otherwise), so equivalence is
/// `NFC(sibling) == name`. An ASCII sibling is already NFC and differs from
/// `name` byte-wise, so only a non-ASCII sibling can collide — but it can
/// collide with an ASCII name: KELVIN SIGN normalises to `K`. Used on every
/// platform: a listing's names are judged by it (M4c) wherever they came from.
pub(super) fn equivalent(sibling: &str, name: &str) -> bool {
    if sibling.is_ascii() || sibling.len() > 4 * PathComponent::MAX_BYTES {
        // A sibling longer than any NFC expansion of a 255-byte name could be
        // cannot equal it; the bound keeps a hostile directory from buying
        // unbounded normalisation work.
        return false;
    }
    sibling.nfc().eq(name.chars())
}

#[cfg(test)]
mod tests {
    use super::{NameProblem, check, equivalent};

    #[test]
    fn canonically_equivalent_spellings_are_detected() {
        // Precomposed and decomposed e-acute.
        assert!(equivalent("caf\u{65}\u{301}", "caf\u{e9}"));
        // KELVIN SIGN beside the letter K, and OHM SIGN beside omega.
        assert!(equivalent("\u{212a}", "K"));
        assert!(equivalent("\u{2126}", "\u{3a9}"));
        // Different names are not.
        assert!(!equivalent("caf\u{e8}", "caf\u{e9}"));
        assert!(!equivalent("k", "K"), "case is not canonical equivalence");
        assert!(!equivalent("other", "K"));
    }

    #[test]
    fn a_name_must_already_be_nfc() {
        assert_eq!(check("caf\u{e9}"), Ok(()));
        assert_eq!(check("cafe\u{301}"), Err(NameProblem::NotNfc));
        assert_eq!(check("\u{212a}"), Err(NameProblem::NotNfc));
        assert_eq!(check("\u{d55c}\u{ae00}"), Ok(()), "precomposed Hangul");
        assert_eq!(
            check("\u{1112}\u{1161}\u{11ab}"),
            Err(NameProblem::NotNfc),
            "conjoining jamo"
        );
    }

    #[test]
    fn names_that_display_as_something_else_are_refused() {
        for name in ["a\u{202e}gnp.exe", "\u{200b}", "a\u{2069}", "x\u{1b}[31m"] {
            assert_eq!(check(name), Err(NameProblem::Character), "{name:?}");
        }
        assert_eq!(check("a\\b"), Err(NameProblem::Separator));
        assert_eq!(check(&"x".repeat(256)), Err(NameProblem::TooLong));
    }
}
