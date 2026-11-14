//! FIXTURE: a runtime path that selects an attended origin, and records an
//! approval itself (TX062).

pub fn attended() -> crate::policy::Origin {
    crate::policy::Origin::Interactive
}

pub const APPROVE: &str = "INSERT INTO run_approval (run_id) VALUES (?1)";
