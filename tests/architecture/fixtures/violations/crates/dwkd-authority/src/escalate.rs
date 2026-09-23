//! FIXTURE: the authority starting a process, and a privileged one (TX010).
//! This comment says Command::new("sudo") and must not be a finding.

pub fn become_someone_else() {
    let _ = std::process::Command::new("sudo").arg("-u").arg("nobody").status();
}
