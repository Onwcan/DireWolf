//! FIXTURE: the executable resolver starting what it resolved (TX020, and
//! TX010). This comment says Command::new(path).spawn() and must not be a
//! finding.

pub fn run(path: &str) -> std::io::Result<std::process::Child> {
    std::process::Command::new(path).spawn()
}
