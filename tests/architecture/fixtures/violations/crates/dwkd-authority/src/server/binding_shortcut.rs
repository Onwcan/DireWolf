//! FIXTURE: the transport computing an approval binding from what a request
//! says (TX067). This comment naming ApprovalBinding is no finding.

pub fn shortcut(input: &BindingInput<'_>) -> ApprovalBinding { ApprovalBinding::from(input) }
pub const SCHEMA: &str = "direwolf.approval.binding.v1";
