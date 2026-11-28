//! FIXTURE: the state layer attaching an approver set of its own (TX071);
//! attach_approver_set named in this comment is no finding.

pub fn widen(a: &Authority, set: &ApproverSet) { let _ = a.attach_approver_set(set); }
