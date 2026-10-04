//! The trusted-side resolver (M5b, ADR-0048): a name is resolved by the
//! broker, on the host, **once per tunnel**, under a deadline; the whole
//! answer is judged ([`super::guard`]) and the tunnel connects only to it.
//! Nothing in the sandbox resolves anything: its namespace has no resolver
//! to reach.
//!
//! [`SystemResolver`] is production: the host's own resolver, through the
//! standard library, on a worker thread the deadline abandons rather than
//! waits for. At most [`RESOLVER_MAX_IN_FLIGHT`] resolutions are in flight
//! per broker, abandoned ones included, so a resolver that never answers
//! cannot accumulate threads.
//!
//! [`FixtureResolver`] is **evidence only** — selected only by the broker's
//! `--allow-evidence-egress <file>`, which logs that it is evidence-only.
//! It answers from a file instead of DNS, so the evidence controls what a
//! name resolves to (acceptable, blocked, mixed, rebinding, failure, timeout)
//! while the real proxy, the real guard and the real topology judge it; and
//! its file may name the exception addresses the evidence's own loopback
//! origin needs. Production has no exception mechanism at all.

use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, ToSocketAddrs as _};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use dwk_proto::brokerp::egress::EgressDisposition;
use dwk_proto::wire::host;

/// The most resolutions in flight at once, abandoned ones included.
pub(crate) const RESOLVER_MAX_IN_FLIGHT: usize = 32;

/// What a name resolves to.
pub(crate) trait Resolver: Send + Sync + fmt::Debug {
    /// Resolve `name` once, within `deadline`.
    ///
    /// # Errors
    ///
    /// `RESOLUTION_FAILED` or `RESOLUTION_TIMEOUT`.
    fn resolve(&self, name: &str, deadline: Duration) -> Result<Vec<IpAddr>, EgressDisposition>;

    /// The blocked addresses the guard lets through: none in production.
    fn exceptions(&self) -> &[IpAddr];
}

/// Resolutions in flight.
static IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);

/// One in-flight slot, given back when the worker ends.
struct Slot;

impl Slot {
    fn take() -> Option<Self> {
        IN_FLIGHT
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                (n < RESOLVER_MAX_IN_FLIGHT).then_some(n + 1)
            })
            .ok()
            .map(|_| Self)
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        IN_FLIGHT.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Run `work` on a worker thread, and wait for it at most `deadline`.
fn within<F>(deadline: Duration, work: F) -> Result<Vec<IpAddr>, EgressDisposition>
where
    F: FnOnce() -> Result<Vec<IpAddr>, EgressDisposition> + Send + 'static,
{
    let slot = Slot::take().ok_or(EgressDisposition::ResolutionFailed)?;
    let (send, receive) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("dw-egress-resolve".to_owned())
        .spawn(move || {
            let answer = work();
            drop(slot);
            let _ = send.send(answer);
        })
        .map_err(|_| EgressDisposition::ResolutionFailed)?;
    match receive.recv_timeout(deadline) {
        Ok(answer) => answer,
        Err(mpsc::RecvTimeoutError::Timeout) => Err(EgressDisposition::ResolutionTimeout),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(EgressDisposition::ResolutionFailed),
    }
}

/// The host's resolver.
#[derive(Debug, Default)]
pub(crate) struct SystemResolver;

impl Resolver for SystemResolver {
    fn resolve(&self, name: &str, deadline: Duration) -> Result<Vec<IpAddr>, EgressDisposition> {
        // Only a canonical name reaches here; an address literal would be
        // "resolved" without DNS, so refuse it as a second line.
        if !host::is_host(name) || host::is_address_literal(name) {
            return Err(EgressDisposition::ResolutionFailed);
        }
        let name = name.to_owned();
        within(deadline, move || {
            let addresses = (name.as_str(), 0u16)
                .to_socket_addrs()
                .map_err(|_| EgressDisposition::ResolutionFailed)?;
            let mut answer: Vec<IpAddr> = Vec::new();
            for address in addresses {
                if !answer.contains(&address.ip()) {
                    answer.push(address.ip());
                }
            }
            Ok(answer)
        })
    }

    fn exceptions(&self) -> &[IpAddr] {
        &[]
    }
}

/// One fixture answer.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Answer {
    /// These addresses.
    Addresses(Vec<IpAddr>),
    /// The resolver fails.
    Fail,
    /// The resolver never answers.
    Timeout,
}

/// The evidence-only resolver: names answered from a file.
#[derive(Debug)]
pub(crate) struct FixtureResolver {
    /// Per name, its answers in order: the last repeats.
    answers: BTreeMap<String, Vec<Answer>>,
    /// Per name, how many times it was resolved.
    queries: Mutex<BTreeMap<String, usize>>,
    /// The exception addresses.
    exceptions: Vec<IpAddr>,
}

/// The largest fixture file.
const FIXTURE_MAX_BYTES: usize = 64 * 1024;

impl FixtureResolver {
    /// Parse a fixture file:
    ///
    /// ```text
    /// # a comment
    /// resolve <host> <answer>[;<answer>...]    answer: fail | timeout | <ip>[,<ip>...]
    /// allow <ip>
    /// ```
    ///
    /// A name's answers are given in order, one per resolution, the last
    /// repeating: `a;b` is a rebinding name.
    ///
    /// # Errors
    ///
    /// The first line that is not one of these, by number.
    pub(crate) fn parse(text: &str) -> Result<Self, String> {
        if text.len() > FIXTURE_MAX_BYTES {
            return Err("the fixture file is too large".to_owned());
        }
        let mut answers = BTreeMap::new();
        let mut exceptions = Vec::new();
        for (number, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let bad = || format!("fixture line {}: not understood", number + 1);
            let words: Vec<&str> = line.split_whitespace().collect();
            match words.as_slice() {
                ["resolve", name, list] if host::is_host(name) => {
                    let mut parsed = Vec::new();
                    for answer in list.split(';') {
                        parsed.push(match answer {
                            "fail" => Answer::Fail,
                            "timeout" => Answer::Timeout,
                            addresses => Answer::Addresses(
                                addresses
                                    .split(',')
                                    .map(str::parse)
                                    .collect::<Result<_, _>>()
                                    .map_err(|_| bad())?,
                            ),
                        });
                    }
                    if answers.insert((*name).to_owned(), parsed).is_some() {
                        return Err(bad());
                    }
                }
                ["allow", address] => exceptions.push(address.parse().map_err(|_| bad())?),
                _ => return Err(bad()),
            }
        }
        Ok(Self {
            answers,
            queries: Mutex::new(BTreeMap::new()),
            exceptions,
        })
    }

    /// Read and parse the fixture file at `path`: the broker's
    /// `--allow-evidence-egress`, and nothing else, calls this.
    ///
    /// # Errors
    ///
    /// The file cannot be read, is too large, is not UTF-8, or does not parse.
    pub(crate) fn load(path: &std::path::Path) -> Result<Self, String> {
        let bytes =
            std::fs::read(path).map_err(|e| format!("{}: {:?}", path.display(), e.kind()))?;
        if bytes.len() > FIXTURE_MAX_BYTES {
            return Err("the fixture file is too large".to_owned());
        }
        let text = String::from_utf8(bytes).map_err(|_| "not UTF-8".to_owned())?;
        Self::parse(&text)
    }

    /// How many times `name` has been resolved.
    #[cfg(test)]
    pub(crate) fn queries(&self, name: &str) -> usize {
        self.queries
            .lock()
            .map_or(0, |q| q.get(name).copied().unwrap_or(0))
    }
}

impl Resolver for FixtureResolver {
    fn resolve(&self, name: &str, deadline: Duration) -> Result<Vec<IpAddr>, EgressDisposition> {
        let seen = {
            let mut queries = self
                .queries
                .lock()
                .map_err(|_| EgressDisposition::ResolutionFailed)?;
            let count = queries.entry(name.to_owned()).or_insert(0);
            *count += 1;
            *count - 1
        };
        let answer = self
            .answers
            .get(name)
            .and_then(|answers| answers.get(seen).or_else(|| answers.last()))
            .cloned()
            .unwrap_or(Answer::Fail);
        // The same deadline as production: a `timeout` answer is a worker
        // that outlives it.
        within(deadline, move || match answer {
            Answer::Addresses(addresses) => Ok(addresses),
            Answer::Fail => Err(EgressDisposition::ResolutionFailed),
            Answer::Timeout => {
                std::thread::sleep(deadline.saturating_add(Duration::from_secs(1)));
                Err(EgressDisposition::ResolutionTimeout)
            }
        })
    }

    fn exceptions(&self) -> &[IpAddr] {
        &self.exceptions
    }
}

/// The resolver a broker uses.
pub(crate) type Shared = Arc<dyn Resolver>;

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::time::Duration;

    use dwk_proto::brokerp::egress::EgressDisposition as D;

    use super::{FixtureResolver, Resolver as _, SystemResolver};

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap_or_else(|_| IpAddr::from([0, 0, 0, 0]))
    }

    const SHORT: Duration = Duration::from_millis(200);

    #[test]
    fn fixture_answers_are_given_in_order_and_the_last_repeats() {
        let fixture = FixtureResolver::parse(
            "# rebinding\nresolve rebind.test 151.101.0.223;127.0.0.1\n\
             resolve mixed.test 151.101.0.223,10.0.0.1\nresolve gone.test fail\n\
             resolve slow.test timeout\nallow 127.0.0.1\n",
        );
        let Ok(fixture) = fixture else {
            unreachable!("the fixture parses: {fixture:?}");
        };
        assert_eq!(
            fixture.resolve("rebind.test", SHORT),
            Ok(vec![ip("151.101.0.223")])
        );
        assert_eq!(
            fixture.resolve("rebind.test", SHORT),
            Ok(vec![ip("127.0.0.1")])
        );
        assert_eq!(
            fixture.resolve("rebind.test", SHORT),
            Ok(vec![ip("127.0.0.1")])
        );
        assert_eq!(fixture.queries("rebind.test"), 3);
        assert_eq!(
            fixture.resolve("mixed.test", SHORT),
            Ok(vec![ip("151.101.0.223"), ip("10.0.0.1")])
        );
        assert_eq!(
            fixture.resolve("gone.test", SHORT),
            Err(D::ResolutionFailed)
        );
        assert_eq!(
            fixture.resolve("absent.test", SHORT),
            Err(D::ResolutionFailed)
        );
        assert_eq!(
            fixture.resolve("slow.test", SHORT),
            Err(D::ResolutionTimeout)
        );
        assert_eq!(fixture.exceptions(), &[ip("127.0.0.1")]);
    }

    #[test]
    fn a_fixture_file_is_strict() {
        for bad in [
            "resolve PyPI.org 1.1.1.1",
            "resolve pypi.org",
            "resolve pypi.org 1.1.1",
            "resolve pypi.org 1.1.1.1\nresolve pypi.org 8.8.8.8",
            "allow localhost",
            "unblock 10.0.0.0/8",
        ] {
            assert!(FixtureResolver::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_system_resolver_resolves_no_address_literal() {
        assert_eq!(
            SystemResolver.resolve("127.0.0.1", SHORT),
            Err(D::ResolutionFailed)
        );
        assert_eq!(
            SystemResolver.resolve("Local", SHORT),
            Err(D::ResolutionFailed)
        );
        assert!(SystemResolver.exceptions().is_empty());
    }
}
