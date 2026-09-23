//! The pure half of the path contract, on every platform: the grammar, the
//! acceptance rules, the fingerprint comparison and the error rendering.
//! Generated input where a property is the claim. The real-filesystem evidence
//! is `linux/tests.rs`.

use proptest::prelude::*;

use super::grammar::{self, MAX_DEPTH};
use super::{
    Access, BirthTime, Expect, PathError, ResolveError, ResourceKind, RootError, RootFingerprint,
    judge,
};
use crate::capability::DeclaredPath;

/// `/workspace` followed by each part as a component.
fn spell(parts: &[String]) -> String {
    let mut text = String::from("/workspace");
    for part in parts {
        text.push('/');
        text.push_str(part);
    }
    text
}

fn declared(text: &str) -> DeclaredPath {
    let Some(declared) = DeclaredPath::new(text) else {
        unreachable!("{text:?} is a DeclaredPath")
    };
    declared
}

/// One path component drawn from a vocabulary that covers every rule: plain
/// names, traversal, separators, NFC and non-NFC spellings, controls, bidi and
/// invisible characters, and long names.
fn component() -> impl Strategy<Value = String> {
    prop_oneof![
        "[a-z0-9_.-]{1,12}",
        Just(String::new()),
        Just(".".to_owned()),
        Just("..".to_owned()),
        Just("a\\b".to_owned()),
        Just("caf\u{e9}".to_owned()),
        Just("cafe\u{301}".to_owned()),
        Just("\u{212a}".to_owned()),
        Just("K".to_owned()),
        Just("a\u{202e}b".to_owned()),
        Just("a\nb".to_owned()),
        Just("\u{200b}".to_owned()),
        "[a-z]{250,260}",
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    /// Whatever the grammar accepts renders to one spelling, and that spelling
    /// parses back to exactly the same components: the canonical form is a
    /// fixed point.
    #[test]
    fn an_accepted_path_round_trips_through_its_canonical_form(
        parts in proptest::collection::vec(component(), 0..8)
    ) {
        let text = spell(&parts);
        if let Some(declared) = DeclaredPath::new(&text)
            && let Ok(path) = grammar::parse(&declared)
        {
            let canonical = path.canonical();
            let rendered = canonical.to_string();
            prop_assert_eq!(&rendered, &text, "accepted text is already canonical");
            let again = grammar::parse(&self::declared(&rendered));
            prop_assert_eq!(again.as_ref().map(grammar::LogicalPath::canonical), Ok(canonical));
        }
    }

    /// Every accepted component obeys every rule; the grammar never lets one
    /// through on a technicality.
    #[test]
    fn every_accepted_component_is_a_valid_nfc_name(
        parts in proptest::collection::vec(component(), 1..6)
    ) {
        let text = format!("/workspace/{}", parts.join("/"));
        if let Some(declared) = DeclaredPath::new(&text)
            && let Ok(path) = grammar::parse(&declared)
        {
            prop_assert!(path.components().len() <= MAX_DEPTH);
            for c in path.components() {
                let name = c.as_str();
                prop_assert!(!name.is_empty() && name != "." && name != "..");
                prop_assert!(!name.contains('/') && !name.contains('\\'));
                prop_assert!(name.len() <= 255);
                prop_assert!(unicode_normalization::is_nfc(name));
                prop_assert!(!name.chars().any(char::is_control));
            }
        }
    }

    /// Canonical containment is component-wise, never a string prefix: a
    /// path covers exactly the paths that extend its components.
    #[test]
    fn containment_is_a_component_prefix_relation(
        a in proptest::collection::vec("[a-c]{1,3}", 0..4),
        b in proptest::collection::vec("[a-c]{1,3}", 0..4),
    ) {
        let (Ok(pa), Ok(pb)) = (grammar::parse(&declared(&spell(&a))), grammar::parse(&declared(&spell(&b)))) else {
            return Err(TestCaseError::fail("plain names parse"));
        };
        let (ca, cb) = (pa.canonical(), pb.canonical());
        let prefix = b.len() >= a.len() && a.iter().zip(b.iter()).all(|(x, y)| x == y);
        prop_assert_eq!(ca.contains(&cb), prefix);
    }

    /// No input panics, and every refusal is a typed error.
    #[test]
    fn the_grammar_is_total(text in "/[ -~\u{e9}\u{301}\u{212a}\u{202e}]{0,80}") {
        if let Some(declared) = DeclaredPath::new(&text) {
            let _ = grammar::parse(&declared);
        }
    }
}

#[test]
fn a_neighbour_that_shares_a_string_prefix_is_not_contained() {
    let parse = |text: &str| grammar::parse(&declared(text)).map(|p| p.canonical());
    let (Ok(parent), Ok(child), Ok(neighbour)) = (
        parse("/workspace/src"),
        parse("/workspace/src/x"),
        parse("/workspace/srcX"),
    ) else {
        unreachable!("plain names parse")
    };
    assert!(parent.contains(&child));
    assert!(
        !parent.contains(&neighbour),
        "string prefix is not containment"
    );
    let anchor = super::workspace_anchor();
    assert!(anchor.contains(&parent) && anchor.contains(&neighbour));
    assert_eq!(anchor.to_string(), "/workspace");
}

#[test]
fn a_hard_linked_file_is_observable_and_not_modifiable() {
    let file = ResourceKind::RegularFile;
    assert_eq!(judge(file, 1, Access::Modify, Expect::Any), Ok(()));
    assert_eq!(judge(file, 2, Access::Observe, Expect::Any), Ok(()));
    assert_eq!(
        judge(file, 2, Access::Modify, Expect::Any),
        Err(ResolveError::HardlinkAliased { links: 2 })
    );
    // A directory's link count counts its subdirectories, not aliases.
    assert_eq!(
        judge(ResourceKind::Directory, 7, Access::Modify, Expect::Any),
        Ok(())
    );
}

#[test]
fn the_kind_the_caller_needs_is_enforced() {
    assert_eq!(
        judge(
            ResourceKind::Directory,
            2,
            Access::Observe,
            Expect::RegularFile
        ),
        Err(ResolveError::WrongKind {
            found: ResourceKind::Directory
        })
    );
    assert_eq!(
        judge(
            ResourceKind::RegularFile,
            1,
            Access::Observe,
            Expect::Directory
        ),
        Err(ResolveError::WrongKind {
            found: ResourceKind::RegularFile
        })
    );
}

#[test]
fn a_fingerprint_matches_only_the_directory_it_records() {
    let birth = Some(BirthTime {
        seconds: 1_700_000_000,
        nanoseconds: 5,
    });
    let recorded = RootFingerprint::new(10, 20, birth);
    assert!(recorded.matches(&RootFingerprint::new(10, 20, birth)));
    assert!(
        !recorded.matches(&RootFingerprint::new(10, 21, birth)),
        "inode"
    );
    assert!(
        !recorded.matches(&RootFingerprint::new(11, 20, birth)),
        "device"
    );
    // A recycled inode number with a different birth time is another
    // directory.
    let reborn = Some(BirthTime {
        seconds: 1_700_000_001,
        nanoseconds: 5,
    });
    assert!(!recorded.matches(&RootFingerprint::new(10, 20, reborn)));
    // A recorded birth time is not satisfied by its absence.
    assert!(!recorded.matches(&RootFingerprint::new(10, 20, None)));
    // Without a recorded birth time, device and inode decide.
    assert!(RootFingerprint::new(10, 20, None).matches(&RootFingerprint::new(10, 20, birth)));
}

#[test]
fn an_error_never_carries_the_text_of_a_name() {
    // Every rendering is a fixed code plus numbers.
    let rendered = [
        ResolveError::Path(PathError::NotNormalized { index: 3 }).to_string(),
        ResolveError::Symlink { depth: 2 }.to_string(),
        ResolveError::NormalizationAmbiguity { depth: 1 }.to_string(),
        ResolveError::Io { depth: 4, errno: 5 }.to_string(),
        RootError::Io(13).to_string(),
        RootError::Replaced.to_string(),
    ];
    for text in rendered {
        assert!(
            text.chars()
                .all(|c| c.is_ascii_alphanumeric() || " _:()".contains(c)),
            "{text:?}"
        );
        assert!(text.len() < 64, "{text:?}");
    }
}

#[test]
fn a_root_path_must_be_absolute_bounded_and_nul_free() {
    use super::{MAX_ROOT_PATH_BYTES, check_host_path};
    assert_eq!(check_host_path("relative/dir"), Err(RootError::NotAbsolute));
    assert_eq!(check_host_path("/a\0b"), Err(RootError::Nul));
    let long = format!("/{}", "a".repeat(MAX_ROOT_PATH_BYTES));
    assert_eq!(check_host_path(&long), Err(RootError::TooLong));
    assert_eq!(check_host_path("/srv/project"), Ok(()));
}

#[cfg(not(target_os = "linux"))]
#[test]
fn no_root_is_pinned_off_linux() {
    assert_eq!(
        super::PinnedRoot::install("/tmp").map(|_| ()),
        Err(RootError::Unsupported)
    );
}
