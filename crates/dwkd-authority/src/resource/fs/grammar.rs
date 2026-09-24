//! The one grammar from a declared path to canonical components.
//!
//! Pure: no filesystem, no allocation proportional to anything but the
//! bounded input. It decides whether a spelling *can* name a workspace object
//! and, if so, which components the resolver must look up. It never rewrites:
//! there is exactly one accepted spelling of each path, and anything else is
//! refused rather than cleaned up — a cleaned-up spelling is a second spelling,
//! and a second spelling is how a deny rule gets walked around.
//!
//! | input | outcome |
//! |---|---|
//! | `/workspace` | the root itself |
//! | `/workspace/a/b` | components `a`, `b` |
//! | `/`, `/etc/hosts`, `/workspaceX` | [`PathError::OutsideWorkspace`] |
//! | `/workspace//a`, `/workspace/a/` | [`PathError::EmptyComponent`] |
//! | `/workspace/./a`, `/workspace/a/../b` | [`PathError::Traversal`] |
//! | `/workspace/a\b` | [`PathError::Separator`] |
//! | a control, bidi or invisible-format character | [`PathError::UnsupportedCharacter`] |
//! | a component that is not already NFC | [`PathError::NotNormalized`] |
//! | a component over 255 bytes | [`PathError::NameTooLong`] |
//! | more than [`MAX_DEPTH`] components | [`PathError::TooDeep`] |
//!
//! `DeclaredPath` has already refused an empty path, a relative one, NUL, `?`
//! and anything over 384 characters; this grammar is the next layer, and the
//! kernel's `RESOLVE_BENEATH` is the one after that.

use core::fmt;

use super::names::{self, NameProblem};
use super::{PathComponent, WORKSPACE_ANCHOR};
use crate::capability::DeclaredPath;
use crate::resource::CanonicalPath;

/// The most components below `/workspace`: the canonical path's own bound, less
/// the anchor.
pub const MAX_DEPTH: usize = CanonicalPath::MAX_COMPONENTS - 1;

/// Why a spelling is not a canonical workspace path. `index` is the 1-based
/// position below `/workspace`; the name itself is never carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PathError {
    /// The first component is not `workspace`: a host-absolute path, the
    /// namespace root, or a name that merely starts with `workspace`.
    OutsideWorkspace,
    /// An empty component: `//`, or a trailing `/`.
    EmptyComponent {
        /// Where.
        index: usize,
    },
    /// `.` or `..`.
    Traversal {
        /// Where.
        index: usize,
    },
    /// A backslash, which Windows reads as a separator and a canonical name
    /// must not contain.
    Separator {
        /// Where.
        index: usize,
    },
    /// A control, bidi-override or invisible-format character.
    UnsupportedCharacter {
        /// Where.
        index: usize,
    },
    /// Not already in Unicode NFC. Refused, never normalised: normalising would
    /// look up a spelling nobody sent.
    NotNormalized {
        /// Where.
        index: usize,
    },
    /// Over 255 bytes (`NAME_MAX`).
    NameTooLong {
        /// Where.
        index: usize,
    },
    /// More than [`MAX_DEPTH`] components below the anchor.
    TooDeep,
}

impl PathError {
    /// A stable code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::OutsideWorkspace => "OUTSIDE_WORKSPACE",
            Self::EmptyComponent { .. } => "EMPTY_COMPONENT",
            Self::Traversal { .. } => "TRAVERSAL",
            Self::Separator { .. } => "SEPARATOR",
            Self::UnsupportedCharacter { .. } => "UNSUPPORTED_CHARACTER",
            Self::NotNormalized { .. } => "NOT_NORMALIZED",
            Self::NameTooLong { .. } => "NAME_TOO_LONG",
            Self::TooDeep => "TOO_DEEP",
        }
    }
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::OutsideWorkspace | Self::TooDeep => f.write_str(self.code()),
            Self::EmptyComponent { index }
            | Self::Traversal { index }
            | Self::Separator { index }
            | Self::UnsupportedCharacter { index }
            | Self::NotNormalized { index }
            | Self::NameTooLong { index } => write!(f, "{} at component {index}", self.code()),
        }
    }
}

/// A spelling the grammar accepted: the components below `/workspace`, each a
/// valid, NFC, bounded name. Not yet a resource — nothing has been looked up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::resource) struct LogicalPath {
    components: Vec<PathComponent>,
}

impl LogicalPath {
    /// `/workspace` itself.
    pub(in crate::resource) const fn root() -> Self {
        Self {
            components: Vec::new(),
        }
    }

    /// The components below the anchor, outermost first.
    pub(in crate::resource) fn components(&self) -> &[PathComponent] {
        &self.components
    }

    /// The canonical path: the anchor, then the components.
    ///
    /// Infallible by construction rather than by assertion: a `LogicalPath`
    /// exists only through [`parse`] (every component accepted by
    /// `PathComponent::new`, at most [`MAX_DEPTH`] of them) or
    /// [`LogicalPath::root`], so the anchor plus its components is always
    /// within `CanonicalPath::MAX_COMPONENTS`. Built directly, which only this
    /// module tree can do.
    pub(in crate::resource) fn canonical(&self) -> CanonicalPath {
        let mut components = Vec::with_capacity(self.components.len() + 1);
        components.push(PathComponent(String::from(WORKSPACE_ANCHOR)));
        components.extend(self.components.iter().cloned());
        CanonicalPath { components }
    }
}

/// Parse a declared path.
///
/// # Errors
///
/// [`PathError`] for every spelling that is not exactly one canonical
/// workspace path.
pub(in crate::resource) fn parse(declared: &DeclaredPath) -> Result<LogicalPath, PathError> {
    let text = declared.as_str();
    // `DeclaredPath` guarantees the leading `/`; the grammar does not rely on
    // it and refuses anything else as outside the workspace.
    let Some(rest) = text.strip_prefix('/') else {
        return Err(PathError::OutsideWorkspace);
    };
    let mut parts = rest.split('/');
    match parts.next() {
        Some(WORKSPACE_ANCHOR) => {}
        Some("." | "..") => return Err(PathError::Traversal { index: 0 }),
        _ => return Err(PathError::OutsideWorkspace),
    }
    let mut components = Vec::new();
    for (offset, part) in parts.enumerate() {
        let index = offset + 1;
        if index > MAX_DEPTH {
            return Err(PathError::TooDeep);
        }
        components.push(component(part, index)?);
    }
    Ok(LogicalPath { components })
}

/// Whether `name` is one component the grammar accepts, alone: what a
/// listing's name must be to be named by a canonical path (M4c).
///
/// # Errors
///
/// The [`PathError`] the name would be refused with, at index 1.
pub(in crate::resource) fn single_component(name: &str) -> Result<PathComponent, PathError> {
    component(name, 1)
}

/// One component, or why it cannot be one.
fn component(part: &str, index: usize) -> Result<PathComponent, PathError> {
    match part {
        "" => return Err(PathError::EmptyComponent { index }),
        "." | ".." => return Err(PathError::Traversal { index }),
        _ => {}
    }
    names::check(part).map_err(|problem| match problem {
        NameProblem::TooLong => PathError::NameTooLong { index },
        NameProblem::Separator => PathError::Separator { index },
        NameProblem::Character => PathError::UnsupportedCharacter { index },
        NameProblem::NotNfc => PathError::NotNormalized { index },
    })?;
    // `names::check` is stricter than `PathComponent::new` in every respect,
    // so this succeeds; mapping keeps the function total.
    PathComponent::new(part).ok_or(PathError::UnsupportedCharacter { index })
}

#[cfg(test)]
mod tests {
    use super::{LogicalPath, MAX_DEPTH, PathError, parse};
    use crate::capability::DeclaredPath;

    fn parsed(text: &str) -> Result<Vec<String>, PathError> {
        let Some(declared) = DeclaredPath::new(text) else {
            unreachable!("{text:?} is a DeclaredPath")
        };
        parse(&declared).map(|p| {
            p.components()
                .iter()
                .map(|c| c.as_str().to_owned())
                .collect()
        })
    }

    #[test]
    fn the_workspace_anchor_and_names_below_it_parse() {
        assert_eq!(parsed("/workspace"), Ok(vec![]));
        assert_eq!(
            parsed("/workspace/src/main.rs"),
            Ok(vec!["src".to_owned(), "main.rs".to_owned()])
        );
        assert_eq!(
            parsed("/workspace/r\u{e9}sum\u{e9}.txt"),
            Ok(vec!["r\u{e9}sum\u{e9}.txt".to_owned()])
        );
        assert_eq!(LogicalPath::root().canonical().to_string(), "/workspace");
    }

    #[test]
    fn a_host_path_is_outside_the_namespace_not_looked_up() {
        for text in [
            "/",
            "/etc/hosts",
            "/workspaceX",
            "/workspaces/a",
            "/home/u/project",
            "/Workspace",
        ] {
            assert_eq!(parsed(text), Err(PathError::OutsideWorkspace), "{text}");
        }
    }

    #[test]
    fn every_second_spelling_is_refused_rather_than_cleaned_up() {
        for (text, error) in [
            ("/workspace/", PathError::EmptyComponent { index: 1 }),
            ("/workspace//a", PathError::EmptyComponent { index: 1 }),
            ("/workspace/a//b", PathError::EmptyComponent { index: 2 }),
            ("/workspace/a/", PathError::EmptyComponent { index: 2 }),
            ("/workspace/.", PathError::Traversal { index: 1 }),
            ("/workspace/./a", PathError::Traversal { index: 1 }),
            ("/workspace/..", PathError::Traversal { index: 1 }),
            ("/workspace/../x", PathError::Traversal { index: 1 }),
            ("/workspace/a/../../x", PathError::Traversal { index: 2 }),
            ("/workspace/a/b/../c", PathError::Traversal { index: 3 }),
            ("/../workspace", PathError::Traversal { index: 0 }),
            ("/./workspace", PathError::Traversal { index: 0 }),
            ("/workspace/a\\b", PathError::Separator { index: 1 }),
            ("/workspace/..\\..\\etc", PathError::Separator { index: 1 }),
        ] {
            assert_eq!(parsed(text), Err(error), "{text}");
        }
    }

    #[test]
    fn a_non_nfc_name_is_refused_never_normalised() {
        // e + COMBINING ACUTE: canonically equivalent to U+00E9, not NFC.
        assert_eq!(
            parsed("/workspace/cafe\u{301}"),
            Err(PathError::NotNormalized { index: 1 })
        );
        // KELVIN SIGN: a singleton whose NFC is the letter K.
        assert_eq!(
            parsed("/workspace/\u{212a}"),
            Err(PathError::NotNormalized { index: 1 })
        );
        // GREEK QUESTION MARK: NFC is the semicolon.
        assert_eq!(
            parsed("/workspace/a\u{37e}b"),
            Err(PathError::NotNormalized { index: 1 })
        );
    }

    #[test]
    fn control_bidi_and_invisible_characters_are_refused() {
        for name in [
            "a\u{7}b",
            "a\nb",
            "a\u{7f}",
            "a\u{85}",
            "a\u{202e}txt",
            "a\u{2066}b",
            "a\u{200b}b",
            "a\u{200f}",
            "a\u{2028}",
            "\u{feff}a",
            "a\u{61c}",
        ] {
            assert_eq!(
                parsed(&format!("/workspace/{name}")),
                Err(PathError::UnsupportedCharacter { index: 1 }),
                "{name:?}"
            );
        }
    }

    #[test]
    fn bounds_are_refusals_not_truncations() {
        let at = "n".repeat(255);
        assert!(parsed(&format!("/workspace/{at}")).is_ok());
        // 128 two-byte characters: 256 bytes, under the 384-character bound.
        let past = "\u{e9}".repeat(128);
        assert_eq!(
            parsed(&format!("/workspace/{past}")),
            Err(PathError::NameTooLong { index: 1 })
        );
        let deep: String = (0..MAX_DEPTH).map(|_| "/d").collect();
        assert!(parsed(&format!("/workspace{deep}")).is_ok());
        assert_eq!(
            parsed(&format!("/workspace{deep}/d")),
            Err(PathError::TooDeep)
        );
    }
}
