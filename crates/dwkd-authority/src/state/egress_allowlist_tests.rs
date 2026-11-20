//! The operator's egress allowlist (F-06, ADR-0071): the grammar, and what
//! an entry covers -- exactly, and nothing near it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use super::{EgressAllowlist, EgressScope, MAX_DESTINATIONS};

fn entry(name: &str, host: &str, port: &str, scope: &str) -> String {
    format!(
        "[[destination]]\nname = \"{name}\"\nhost = \"{host}\"\nport = {port}\nscope = {scope}\n\
         purpose = \"a test\"\n"
    )
}

fn file(entries: &[String]) -> String {
    let mut text = "schema_version = 1\n".to_owned();
    for e in entries {
        text.push_str(e);
    }
    text
}

fn refused(text: &str) -> String {
    EgressAllowlist::parse(text).expect_err(text)
}

#[test]
fn no_file_and_an_empty_file_cover_nothing() {
    let none = EgressAllowlist::empty();
    let empty = EgressAllowlist::parse("schema_version = 1\n").unwrap();
    for list in [&none, &empty] {
        assert!(list.is_empty());
        for scope in EgressScope::ALL {
            assert!(!list.covers("registry.npmjs.org", 443, scope));
        }
    }
    assert_eq!(none, empty);
    // Missing, malformed or mistyped: refused, never read as empty.
    for bad in [
        "",
        "schema_version = 2\n",
        "schema_version = \"1\"\n",
        "schema_version = 0x1\n",
        "this is not toml",
        "schema_version = 1\ndestination = \"registry.npmjs.org\"\n",
        "schema_version = 1\ndestination = [\"registry.npmjs.org\"]\n",
    ] {
        refused(bad);
    }
}

#[test]
fn an_entry_covers_exactly_its_host_its_port_and_its_paths() {
    let list = EgressAllowlist::parse(&file(&[
        entry("npm", "registry.npmjs.org", "443", "[\"workload\"]"),
        entry(
            "api",
            "api.example.com",
            "8443",
            "[\"net_http\", \"workload\"]",
        ),
    ]))
    .unwrap();
    assert!(list.covers("registry.npmjs.org", 443, EgressScope::Workload));
    assert!(list.covers("api.example.com", 8443, EgressScope::NetHttp));
    assert!(list.covers("api.example.com", 8443, EgressScope::Workload));
    // Another path, another port, a neighbour, a parent, a child, another
    // spelling: none is the entry.
    for (host, port, scope) in [
        ("registry.npmjs.org", 443, EgressScope::NetHttp),
        ("registry.npmjs.org", 80, EgressScope::Workload),
        ("registry.npmjs.org", 8443, EgressScope::Workload),
        ("evil-registry.npmjs.org", 443, EgressScope::Workload),
        ("registry.npmjs.org.evil.com", 443, EgressScope::Workload),
        ("npmjs.org", 443, EgressScope::Workload),
        ("x.registry.npmjs.org", 443, EgressScope::Workload),
        ("Registry.npmjs.org", 443, EgressScope::Workload),
        ("registry.npmjs.org.", 443, EgressScope::Workload),
        ("api.example.com", 443, EgressScope::NetHttp),
    ] {
        assert!(!list.covers(host, port, scope), "{host}:{port} {scope:?}");
    }
    let names: Vec<&str> = list
        .destinations()
        .iter()
        .map(|d| d.name.as_str())
        .collect();
    assert_eq!(names, ["npm", "api"]);
    assert_eq!(
        list.destinations()[1].scopes,
        [EgressScope::NetHttp, EgressScope::Workload]
    );
}

#[test]
fn a_host_is_one_exact_canonical_name_and_nothing_else() {
    for host in [
        "*.npmjs.org",
        "*",
        "registry.npmjs.org.",
        ".registry.npmjs.org",
        "Registry.npmjs.org",
        "REGISTRY.NPMJS.ORG",
        "user@registry.npmjs.org",
        "user:pass@registry.npmjs.org",
        "https://registry.npmjs.org",
        "registry.npmjs.org:443",
        "registry.npmjs.org/path",
        "registry.npmjs.org?q",
        "registry%2enpmjs.org",
        "registry..npmjs.org",
        "",
        "localhost",
        "intranet",
        "10.0.0.1",
        "169.254.169.254",
        "[::1]",
        "::1",
        "bücher.de",
        "registry.npmjs.org\u{0}",
        "-bad.example.com",
        "bad-.example.com",
        &format!("{}.com", "a".repeat(64)),
        &format!("{}com", "abcdefghi.".repeat(26)),
    ] {
        let why = refused(&file(&[entry("x", host, "443", "[\"workload\"]")]));
        assert!(
            why.contains("host") || why.contains("TOML"),
            "{host:?}: {why}"
        );
    }
    // An internationalised name in its ASCII form is a name like any other.
    let idna = EgressAllowlist::parse(&file(&[entry(
        "idna",
        "xn--bcher-kva.de",
        "443",
        "[\"workload\"]",
    )]))
    .unwrap();
    assert!(idna.covers("xn--bcher-kva.de", 443, EgressScope::Workload));
    assert!(!idna.covers("bücher.de", 443, EgressScope::Workload));
}

#[test]
fn a_port_is_named_and_plain() {
    for port in [
        "0", "65536", "-1", "\"443\"", "0x1bb", "4.43e2", "true", "[443]",
    ] {
        let why = refused(&file(&[entry(
            "x",
            "a.example.com",
            port,
            "[\"workload\"]",
        )]));
        assert!(
            why.contains("port") || why.contains("TOML"),
            "{port}: {why}"
        );
    }
    let missing = "schema_version = 1\n[[destination]]\nname = \"x\"\nhost = \"a.example.com\"\n\
                   scope = [\"workload\"]\npurpose = \"p\"\n";
    assert!(refused(missing).contains("port is required"));
}

#[test]
fn a_scope_is_one_of_the_two_paths_named_once() {
    for scope in [
        "[]",
        "\"workload\"",
        "[\"model_download\"]",
        "[\"Workload\"]",
        "[\"workload\", \"workload\"]",
        "[\"*\"]",
        "[1]",
    ] {
        let why = refused(&file(&[entry("x", "a.example.com", "443", scope)]));
        assert!(why.contains("scope"), "{scope}: {why}");
    }
}

#[test]
fn every_member_is_named_and_none_is_unknown() {
    // An unknown member -- an authority flag a file might try to carry, a
    // method list, a wildcard switch -- refuses the file.
    for extra in [
        "allow_private = true\n",
        "methods = [\"GET\"]\n",
        "wildcard = true\n",
        "cidr = \"10.0.0.0/8\"\n",
        "taint = \"ANY\"\n",
    ] {
        let mut text = file(&[entry("x", "a.example.com", "443", "[\"workload\"]")]);
        text.push_str(extra);
        let why = refused(&text);
        assert!(
            why.contains("unknown member destination[0]."),
            "{extra}: {why}"
        );
    }
    let why = refused("schema_version = 1\nallow_all = true\n");
    assert!(why.contains("unknown member"), "{why}");
    // Each required member, left out.
    for member in ["name", "host", "scope", "purpose"] {
        let text = file(&[entry("x", "a.example.com", "443", "[\"workload\"]")]);
        let text = text
            .lines()
            .filter(|line| !line.starts_with(&format!("{member} =")))
            .fold(String::new(), |mut kept, line| {
                kept.push_str(line);
                kept.push('\n');
                kept
            });
        assert!(refused(&text).contains(member), "{member}");
    }
}

#[test]
fn names_and_destinations_are_unique_and_bounded() {
    let twice = file(&[
        entry("x", "a.example.com", "443", "[\"workload\"]"),
        entry("x", "b.example.com", "443", "[\"workload\"]"),
    ]);
    assert!(refused(&twice).contains("repeated"));
    let same = file(&[
        entry("x", "a.example.com", "443", "[\"workload\"]"),
        entry("y", "a.example.com", "443", "[\"net_http\"]"),
    ]);
    assert!(refused(&same).contains("named twice"));
    for name in ["X", "1x", "-x", "x_y", "x.y", "", &"x".repeat(65)] {
        let why = refused(&file(&[entry(
            name,
            "a.example.com",
            "443",
            "[\"workload\"]",
        )]));
        assert!(why.contains("name"), "{name:?}: {why}");
    }
    let many: Vec<String> = (0..=MAX_DESTINATIONS)
        .map(|n| {
            entry(
                &format!("d{n}"),
                &format!("h{n}.example.com"),
                "443",
                "[\"workload\"]",
            )
        })
        .collect();
    assert!(refused(&file(&many)).contains("destinations"));
    let large = format!("schema_version = 1\n# {}\n", "x".repeat(70 * 1024));
    assert!(refused(&large).contains("larger"));
}

#[test]
fn a_purpose_is_said_in_plain_text() {
    for purpose in [
        "",
        "bell\u{7}",
        "line\nbreak",
        &"p".repeat(201),
        "non-ascii é",
    ] {
        let text = file(&[entry("x", "a.example.com", "443", "[\"workload\"]")])
            .replace("purpose = \"a test\"", &format!("purpose = {purpose:?}"));
        let why = refused(&text);
        assert!(
            why.contains("purpose") || why.contains("TOML"),
            "{purpose:?}: {why}"
        );
    }
}
