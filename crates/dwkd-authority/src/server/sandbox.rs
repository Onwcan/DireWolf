//! The operator's execution environment, attached at start (M5d.2, ADR-0052
//! §2a): `serve --sandbox-config <path>`.
//!
//! The one place in the server that names the attachment (TX035): the file
//! is read through the trusted reader and parsed whole
//! (`crate::sandbox::operator`), and the authority attaches it once, before
//! the socket is bound — reconciling every environment a previous
//! incarnation left. Nothing here prepares, measures or destroys an
//! environment, and no DWKP operation reaches any of it: the authority
//! prepares a run's environment itself when a launch it decided needs one.

use std::path::Path;

use super::{ServeError, log};
use crate::state::Authority;

/// Read the operator's file at `path`, if one is configured, and attach it
/// to `authority`. Without one, the authority runs no `process.exec`
/// anywhere: version 5 is the host floor's, as version 4 is.
///
/// # Errors
///
/// [`ServeError::Configuration`] when the file cannot be trusted or does not
/// parse; a failed attachment as [`ServeError::Io`]. The server does not
/// start.
pub(super) fn attach(
    authority: &mut Authority,
    path: Option<&Path>,
    authority_uid: u32,
) -> Result<(), ServeError> {
    let Some(path) = path else {
        return Ok(());
    };
    let text = path.to_str().ok_or_else(|| {
        ServeError::Configuration("--sandbox-config is not a UTF-8 path".to_owned())
    })?;
    let config =
        crate::sandbox::operator::load(text, authority_uid).map_err(ServeError::Configuration)?;
    let report = authority
        .attach_sandbox(config)
        .map_err(|error| ServeError::Io(format!("attaching the execution environment: {error}")))?;
    log(&format!(
        "execution environment attached from {}: process.exec runs in a run's own environment, \
         never on the host (reconciled: {} still running, {} drifted, {} stopped, {} missing, \
         {} pending destroyed{})",
        path.display(),
        report.still_running,
        report.drifted,
        report.stopped,
        report.missing,
        report.pending_destroyed,
        if report.unobservable {
            "; the runtime could not be listed"
        } else {
            ""
        }
    ));
    Ok(())
}
