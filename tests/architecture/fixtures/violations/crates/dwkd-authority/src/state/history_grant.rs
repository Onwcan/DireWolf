//! FIXTURE: an ownership decision that reads the ownership_observation
//! table: history taken for authority (TX064).

pub const OWNER: &str = "SELECT subject FROM ownership_observation WHERE resource = ?1";
