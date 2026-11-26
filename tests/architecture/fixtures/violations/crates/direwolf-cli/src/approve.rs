//! FIXTURE: the CLI deciding an approval and attaching its own approver
//! set (TX068). This comment naming decide_approval is no finding.

pub fn approve(a: &mut Authority, r: &str) { let _ = a.decide_approval(r, grant()); }
pub fn trust(a: &Authority) { let _ = a.attach_approvers(&[1000]); }
pub fn widen(s: &Shared) { let _ = s.attachments.approvers.set(vec![1000]); }
