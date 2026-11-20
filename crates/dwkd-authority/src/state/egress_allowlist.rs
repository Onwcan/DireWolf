//! The operator's egress allowlist (F-06, [ADR-0071], Proposed): the exact
//! destinations a deployment lets an agent's network actions reach, written
//! by the operator and read by the authority at start -- never by a run.
//!
//! **What it is.** A canonical input, `destination_allowlisted`, that the
//! authority computes for every `network.https` decision from this file and
//! no other source ([`EgressAllowlist::admits`], called by the state layer's
//! one decision function): true exactly when one entry names the action's
//! host, its port and the path the action takes (`net_http`, a
//! kernel-performed hop; `workload`, a sandboxed workload's tunnel).
//!
//! **A ceiling, since OF-2** ([ADR-0073], Proposed). The policy evaluator
//! denies every network action this list does not admit, whatever the
//! policy says -- a shipped pack, an operator's own file, a rule that allows
//! `network.https:*` -- so with no file, or a file with no entry, no agent
//! action reaches the network at all. A rule may still require the input
//! (`when.destination_allowlisted = true`, as the shipped packs do); it is
//! no longer the only thing that holds. The ceiling only narrows: a run
//! still needs its capability, the address guard still refuses every
//! private address, taint and novelty still decide, and a rule that denies
//! still denies.
//!
//! **What it is not.** No wildcard, no suffix, no CIDR, no scheme, no path,
//! no userinfo: an entry is one host, one port, one or two paths, a name and
//! a purpose. A host is the capability grammar's (`HostPattern`, exact):
//! lowercase ASCII labels, no trailing dot, no Unicode (an internationalised
//! name is written in its `xn--` form), at least two labels, and not a
//! number (an address is not a destination a name can be pinned to).
//!
//! It is operator configuration, read and parsed at start and held by the
//! state layer (`ActiveAuthority`), which the server reaches as it reaches
//! every other configuration (TX007); the policy engine sees only the
//! boolean.
//!
//! Strict: an unknown member, a missing one, a value of another type or
//! outside its grammar, a repeated name or a repeated host and port refuses
//! the whole file, and the authority does not start.
//!
//! [ADR-0071]: ../../../../docs/adr/0071-f06-an-operator-egress-allowlist-every-shipped-network-rule-requires.md
//! [ADR-0073]: ../../../../docs/adr/0073-f06-of2-the-operators-egress-allowlist-is-a-ceiling-every-policy-is-under.md

use toml::de::{DeTable, DeValue};

use crate::capability::scope::HostPattern;
use crate::capability::{Capability, PortSpec, Scope, SyntacticScope};
use crate::policy::Environment;

/// The largest file read.
pub const MAX_FILE_BYTES: u64 = 64 * 1024;

/// The most destinations one file names.
pub const MAX_DESTINATIONS: usize = 256;

/// The longest `purpose`.
pub const MAX_PURPOSE_CHARS: usize = 200;

/// The longest host, in bytes (RFC 1035).
const MAX_HOST_BYTES: usize = 253;

const TOP: &[&str] = &["schema_version", "destination"];
const ENTRY: &[&str] = &["name", "host", "port", "scope", "purpose"];

/// The path a network action takes to its destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EgressScope {
    /// A `net.http` hop the authority decides and the broker performs.
    NetHttp,
    /// A sandboxed workload's tunnel through the broker's CONNECT proxy.
    Workload,
}

impl EgressScope {
    /// Every scope, in order.
    pub const ALL: [Self; 2] = [Self::NetHttp, Self::Workload];

    /// The spelling the file uses.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NetHttp => "net_http",
            Self::Workload => "workload",
        }
    }
}

/// One destination the operator allows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    /// Its name: lower-kebab, unique in the file. Revoking a destination is
    /// removing its entry.
    pub name: String,
    /// The host, exact, in the capability grammar's canonical form.
    pub host: String,
    /// The port.
    pub port: u16,
    /// The paths it allows, sorted, without repeats.
    pub scopes: Vec<EgressScope>,
    /// Why, as the operator says it: shown, never interpreted.
    pub purpose: String,
}

/// The operator's allowlist. Empty unless a file says otherwise.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EgressAllowlist {
    destinations: Vec<Destination>,
}

impl EgressAllowlist {
    /// No destination: what an authority started without a file holds.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            destinations: Vec::new(),
        }
    }

    /// Whether one entry names exactly this host, this port and this path.
    /// Nothing is folded, trimmed or matched by suffix: the host an action
    /// carries is already canonical, and so is every entry's.
    #[must_use]
    pub fn covers(&self, host: &str, port: u16, scope: EgressScope) -> bool {
        self.destinations
            .iter()
            .any(|d| d.port == port && d.host == host && d.scopes.contains(&scope))
    }

    /// Whether a network action's own destination is under this list: its
    /// capability names one exact host and one port, and an entry names both
    /// for the path its environment takes -- `Host`, a kernel-performed
    /// `net.http` hop; `Sandbox`, a workload's tunnel. Anything else (a
    /// wildcard, no port, another scope family) is not.
    #[must_use]
    pub fn admits(&self, capability: &Capability, environment: &Environment) -> bool {
        let Scope::Syntactic(SyntacticScope::Endpoint(endpoint)) = capability.scope() else {
            return false;
        };
        let (HostPattern::Exact(_), PortSpec::Port(port)) = (endpoint.host(), endpoint.port())
        else {
            return false;
        };
        let scope = match environment {
            Environment::Host => EgressScope::NetHttp,
            Environment::Sandbox => EgressScope::Workload,
        };
        self.covers(&endpoint.host().to_string(), port, scope)
    }

    /// The destinations, in the file's order.
    #[must_use]
    pub fn destinations(&self) -> &[Destination] {
        &self.destinations
    }

    /// Whether it names no destination.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.destinations.is_empty()
    }

    /// Parse the operator's file.
    ///
    /// # Errors
    ///
    /// Why the file is refused: the first member, value or repeat that is
    /// not exactly what this grammar names.
    pub fn parse(text: &str) -> Result<Self, String> {
        if u64::try_from(text.len()).unwrap_or(u64::MAX) > MAX_FILE_BYTES {
            return Err(format!("larger than {MAX_FILE_BYTES} bytes"));
        }
        let document = DeTable::parse(text).map_err(|_| "not a TOML document".to_owned())?;
        let document = document.get_ref();
        reject_unknown(document, TOP, "")?;
        match find(document, "schema_version").map(toml::Spanned::get_ref) {
            Some(DeValue::Integer(version)) if version.radix() == 10 && version.as_str() == "1" => {
            }
            _ => return Err("schema_version must be 1".to_owned()),
        }
        let entries = match find(document, "destination").map(toml::Spanned::get_ref) {
            None => return Ok(Self::empty()),
            Some(DeValue::Array(entries)) => entries,
            Some(_) => return Err("destination must be an array of tables".to_owned()),
        };
        if entries.len() > MAX_DESTINATIONS {
            return Err(format!(
                "more than {MAX_DESTINATIONS} destinations; name fewer"
            ));
        }
        let mut destinations: Vec<Destination> = Vec::with_capacity(entries.len());
        for (index, entry) in entries.iter().enumerate() {
            let DeValue::Table(table) = entry.get_ref() else {
                return Err(format!("destination[{index}] must be a table"));
            };
            let at = format!("destination[{index}].");
            let parsed = destination(table, &at)?;
            if destinations.iter().any(|d| d.name == parsed.name) {
                return Err(format!("{at}name {:?} is repeated", parsed.name));
            }
            if destinations
                .iter()
                .any(|d| d.host == parsed.host && d.port == parsed.port)
            {
                return Err(format!(
                    "{at}host and port {}:{} are named twice: one entry per destination",
                    parsed.host, parsed.port
                ));
            }
            destinations.push(parsed);
        }
        Ok(Self { destinations })
    }
}

type Value<'t> = toml::Spanned<DeValue<'t>>;

fn find<'t>(table: &'t DeTable<'t>, name: &str) -> Option<&'t Value<'t>> {
    table
        .iter()
        .find(|(key, _)| AsRef::<str>::as_ref(key.get_ref()) == name)
        .map(|(_, value)| value)
}

fn reject_unknown(table: &DeTable<'_>, allowed: &[&str], path: &str) -> Result<(), String> {
    for (key, _) in table {
        let name: &str = key.get_ref().as_ref();
        if !allowed.contains(&name) {
            return Err(format!("unknown member {path}{}", bounded(name)));
        }
    }
    Ok(())
}

/// At most this many characters of a value are echoed in an error.
const ECHO: usize = 64;

fn bounded(text: &str) -> String {
    let mut shown: String = text.chars().take(ECHO).collect();
    if text.chars().count() > ECHO {
        shown.push('…');
    }
    format!("{shown:?}")
}

fn string<'t>(table: &'t DeTable<'t>, name: &str, at: &str) -> Result<&'t str, String> {
    match find(table, name).map(toml::Spanned::get_ref) {
        Some(DeValue::String(text)) => Ok(text.as_ref()),
        Some(_) => Err(format!("{at}{name} must be a string")),
        None => Err(format!("{at}{name} is required")),
    }
}

fn destination(table: &DeTable<'_>, at: &str) -> Result<Destination, String> {
    reject_unknown(table, ENTRY, at)?;
    let name = string(table, "name", at)?;
    if !is_name(name) {
        return Err(format!(
            "{at}name {} must be lower-kebab: a lowercase letter, then lowercase letters, \
             digits and hyphens, at most 64",
            bounded(name)
        ));
    }
    let host = string(table, "host", at)?;
    let host = canonical_host(host).map_err(|why| format!("{at}host {}: {why}", bounded(host)))?;
    let port = match find(table, "port").map(toml::Spanned::get_ref) {
        Some(DeValue::Integer(number))
            if number.radix() == 10
                && !number.as_str().is_empty()
                && number.as_str().bytes().all(|b| b.is_ascii_digit())
                && !(number.as_str().len() > 1 && number.as_str().starts_with('0')) =>
        {
            number
                .as_str()
                .parse::<u16>()
                .ok()
                .filter(|port| *port != 0)
                .ok_or_else(|| format!("{at}port must be 1 to 65535"))?
        }
        Some(_) => {
            return Err(format!(
                "{at}port must be a plain decimal integer, 1 to 65535"
            ));
        }
        None => return Err(format!("{at}port is required: no port is implied")),
    };
    let scopes = scopes(table, at)?;
    let purpose = string(table, "purpose", at)?;
    if purpose.is_empty()
        || purpose.chars().count() > MAX_PURPOSE_CHARS
        || !purpose.chars().all(|c| c == ' ' || c.is_ascii_graphic())
    {
        return Err(format!(
            "{at}purpose must be 1 to {MAX_PURPOSE_CHARS} printable ASCII characters"
        ));
    }
    Ok(Destination {
        name: name.to_owned(),
        host,
        port,
        scopes,
        purpose: purpose.to_owned(),
    })
}

fn scopes(table: &DeTable<'_>, at: &str) -> Result<Vec<EgressScope>, String> {
    let Some(value) = find(table, "scope") else {
        return Err(format!(
            "{at}scope is required: net_http, workload, or both"
        ));
    };
    let DeValue::Array(items) = value.get_ref() else {
        return Err(format!("{at}scope must be a list"));
    };
    if items.is_empty() {
        return Err(format!("{at}scope must name net_http, workload, or both"));
    }
    let mut scopes = Vec::with_capacity(items.len());
    for item in items {
        let DeValue::String(word) = item.get_ref() else {
            return Err(format!("{at}scope must be a list of strings"));
        };
        let word: &str = word.as_ref();
        let scope = EgressScope::ALL
            .into_iter()
            .find(|s| s.as_str() == word)
            .ok_or_else(|| format!("{at}scope {} is not net_http or workload", bounded(word)))?;
        if scopes.contains(&scope) {
            return Err(format!("{at}scope {word} is repeated"));
        }
        scopes.push(scope);
    }
    scopes.sort_unstable();
    Ok(scopes)
}

/// `^[a-z][a-z0-9-]{0,63}$`.
fn is_name(text: &str) -> bool {
    let mut bytes = text.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && text.len() <= 64
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// A host in the capability grammar's canonical form, exact, of at least two
/// labels, not a number; or why not.
fn canonical_host(text: &str) -> Result<String, &'static str> {
    if text.starts_with('*') {
        return Err("a wildcard: each host is named exactly");
    }
    if text.len() > MAX_HOST_BYTES {
        return Err("longer than 253 bytes");
    }
    if !text.is_ascii() {
        return Err("not ASCII: an internationalised name is written in its xn-- form");
    }
    let pattern = HostPattern::parse(text).map_err(|_| {
        "not a canonical DNS name: lowercase letters, digits and hyphens in dot-separated \
         labels, no trailing dot, no port, scheme, path or user"
    })?;
    let HostPattern::Exact(labels) = pattern else {
        return Err("a wildcard: each host is named exactly");
    };
    if labels.len() < 2 {
        return Err("a single label: it would be completed by a resolver's search list");
    }
    if labels
        .last()
        .is_some_and(|last| last.as_str().bytes().all(|b| b.is_ascii_digit()))
    {
        return Err("a number: an address is not a name a destination is pinned to");
    }
    Ok(text.to_owned())
}

#[cfg(test)]
#[path = "egress_allowlist_tests.rs"]
mod tests;
