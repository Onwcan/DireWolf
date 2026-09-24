//! Every platform but Linux: no resolver ([ADR-0042] §11).
//!
//! macOS has no `openat2` and no `RESOLVE_*`, native Windows has no
//! descriptor-relative resolution this crate can reach without `unsafe`, and a
//! component-wise fallback walker would be a weaker mechanism presented under
//! the same name. So nothing resolves here: pinning a root and resolving a
//! path both refuse, and the descriptor type is uninhabited, so a resolved
//! resource cannot exist on these platforms at all — not merely "is never
//! returned".
//!
//! [ADR-0042]: ../../../../../../docs/adr/0042-m4a-canonical-filesystem-resolution.md

use super::{FileIdentity, ResolveError, RootError, RootFingerprint, Walked};
use crate::resource::PathComponent;

/// No descriptor exists on this platform.
#[derive(Debug)]
pub(in crate::resource) enum Fd {}

pub(in crate::resource) fn open_root(
    _host: &str,
) -> Result<(Fd, FileIdentity, RootFingerprint), RootError> {
    Err(RootError::Unsupported)
}

pub(in crate::resource) fn walk(
    root: &Fd,
    _root_id: FileIdentity,
    _names: &[PathComponent],
) -> Result<Walked, ResolveError> {
    match *root {}
}

pub(in crate::resource) fn still_bound(
    leaf: &Fd,
    _parent: Option<(&Fd, &PathComponent)>,
    _expected: FileIdentity,
) -> Result<(), ResolveError> {
    match *leaf {}
}

pub(in crate::resource) fn open_for_read(
    leaf: &Fd,
    _parent: &Fd,
    _name: &PathComponent,
    _expected: FileIdentity,
) -> Result<Fd, ResolveError> {
    match *leaf {}
}
