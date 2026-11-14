//! FIXTURE: a subject made from what a runtime said, not from the
//! kernel's report (TX063).

pub fn claimed(uid: u32) -> crate::state::AuthenticatedSubject {
    crate::state::AuthenticatedSubject::unix_uid(uid)
}
