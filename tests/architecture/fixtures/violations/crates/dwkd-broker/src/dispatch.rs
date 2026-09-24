//! FIXTURE: the broker growing an authority (TX013) and a second
//! canonicaliser (TX015). None of these lines may appear in the broker.

use dwk_proto::dwkp::DwkpBody;

pub fn answer(_body: &DwkpBody) {}

pub fn remember() -> rusqlite::Result<rusqlite::Connection> {
    rusqlite::Connection::open("kernel.db")
}

pub fn run() -> std::io::Result<std::process::Child> {
    std::process::Command::new("sh").spawn()
}

pub fn reopen(path: &str) -> std::io::Result<std::fs::File> {
    std::fs::File::open(path)
}
