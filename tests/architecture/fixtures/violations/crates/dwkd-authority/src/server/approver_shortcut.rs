//! FIXTURE: a server path other than the worker reaching the approver
//! operations (TX069) and making its own approver (TX070); serve_approver
//! and kernel_reported named in this comment are no finding.

pub fn shortcut(a: &mut Authority, uid: u32, r: &Request) {
    let _ = a.serve_approver(ApproverPrincipal::kernel_reported(uid), r);
}
