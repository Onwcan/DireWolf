//! Every platform but Linux: no executable resolver (ADR-0045 §5), for the
//! reason `resource::fs` has none there. Resolution refuses, and the
//! descriptor type is uninhabited, so a resolved executable cannot exist on
//! these platforms at all.

use super::{ExecError, Found};
use crate::resource::PathComponent;
use crate::resource::fs::FileIdentity;

/// No descriptor exists on this platform.
#[derive(Debug)]
pub(super) enum Fd {}

pub(super) fn resolve(
    _components: &[PathComponent],
    _trusted_owner: u32,
) -> Result<Found, ExecError> {
    Err(ExecError::Unsupported)
}

pub(super) fn open_for_exec(
    leaf: &Fd,
    _parent: &Fd,
    _name: &PathComponent,
    _expected: FileIdentity,
    _trusted_owner: u32,
) -> Result<Fd, ExecError> {
    match *leaf {}
}
