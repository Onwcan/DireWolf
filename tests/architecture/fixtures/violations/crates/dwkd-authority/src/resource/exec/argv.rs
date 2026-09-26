//! FIXTURE: the argv classifier. Its runner names are data, and TX010 exempts
//! it for them -- but TX020 still binds it: it may name `sudo`, never run it.

pub const RUNNERS: &[&str] = &["sudo", "su", "runuser"];

pub fn try_it(args: &[&str]) -> bool {
    std::process::Command::new(RUNNERS[0]).args(args).status().is_ok()
}
