// VIOLATES TX060: a switch for the hygiene profiles, which have none since their acceptance.
fn switched(config: Environment, asked: &str) -> Environment {
    config.with_hygiene_profiles(from_a_request(asked)).unwrap_or_else(|_| unreachable!())
}
fn from_a_request(name: &str) -> HygieneProfiles {
    let named = name.trim();
    UnacceptedProfile::parse(named).map_or(HygieneProfiles::NONE, |p| HygieneProfiles::NONE.with(p))
}
fn spelled() -> &'static str {
    "--allow-unaccepted-hygiene-profile"
}
// A comment naming `.with_hygiene_profiles(` or "--allow-unaccepted-hygiene-profile" is not a use.
