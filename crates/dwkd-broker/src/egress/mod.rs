//! The `PROXY_ONLY` CONNECT proxy (M5b, [ADR-0048]): the one path a sandboxed
//! process's network traffic has, and what the broker enforces on it.
//!
//! A `PROXY_ONLY` environment's namespace has no route. Its relay forwards
//! each connection to `169.254.7.1:8080` to this environment's socket here,
//! and nothing else reaches it: the socket's directory is mounted into the
//! relay alone, beneath a root only the broker can enter, and its ACL lets
//! only the relay's uid search it wherever it is exposed ([`proxy`]). Each
//! connection is one request and, at most, one opaque tunnel:
//!
//! | step | what is checked | refusal |
//! |---|---|---|
//! | request | one `CONNECT host:port HTTP/1.1`, bounded, strict ([`request`]) | `MALFORMED`, `NOT_CONNECT`, `TARGET_NOT_CANONICAL`, `REQUEST_TIMEOUT` |
//! | grant | exactly a granted `(host, port)`, by canonical bytes | `TARGET_NOT_GRANTED` |
//! | budget | fewer tunnels open than the grant allows | `TUNNEL_LIMIT` |
//! | resolve | the trusted resolver, once, with a deadline ([`resolve`]) | `RESOLUTION_FAILED`, `RESOLUTION_TIMEOUT` |
//! | IP guard | the whole answer: none blocked, no mixture ([`guard`]) | `ADDRESS_BLOCKED`, `ADDRESS_MIXED` |
//! | server name | the TLS `ClientHello` names exactly the CONNECT host, without ECH ([`hello`]) | `CLIENT_HELLO_*`, `SNI_*`, `ECH_REFUSED` |
//! | connect | the **pinned** address — never the name again | `CONNECT_FAILED` |
//! | tunnel | bytes each way within the grant's budgets, at the socket ([`tunnel`]) | `UPLOAD_BUDGET`, `DOWNLOAD_BUDGET`, `IDLE_TIMEOUT`, `LIFETIME_EXCEEDED` |
//!
//! **It does not terminate TLS.** There is no certificate, no CA, no trust
//! store and no decryption here: after the server name agrees, the bytes are
//! carried, counted and never read. What the proxy sees is the CONNECT target,
//! the port, the resolved address, the server name, byte counts and timing —
//! not a path, a header, a body, a response or the `Host` an encrypted request
//! names (`NETWORK_SECURITY.md` §1's domain-fronting residual). It injects
//! nothing. Every refusal is closed: there is no direct path to fall back to.
//!
//! [ADR-0048]: ../../../../docs/adr/0048-m5b-proxy-only-topology-and-connect-proxy.md

pub(crate) mod guard;
pub(crate) mod hello;
pub(crate) mod proxy;
pub(crate) mod request;
pub(crate) mod resolve;
pub(crate) mod tunnel;

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use dwk_proto::brokerp::egress::{
    EgressCount, EgressCountList, EgressCountValue, EgressCounters, EgressDisposition,
};
use dwk_proto::wire::scalar::ByteCount;

/// The longest a CONNECT request (line and headers) may be.
pub(crate) const REQUEST_MAX_BYTES: usize = 8 * 1024;
/// The most header lines a request may carry.
pub(crate) const REQUEST_MAX_HEADERS: usize = 32;
/// The largest TLS `ClientHello` handshake message accepted.
pub(crate) const HELLO_MAX_BYTES: usize = 16 * 1024;
/// The most bytes buffered while a `ClientHello` arrives, records included:
/// a hello fragmented into tiny records cannot grow past this.
pub(crate) const HELLO_MAX_BUFFERED: usize = 64 * 1024;

/// How long each step may take. The production values are the broker's,
/// not the grant's: a deadline is the proxy's own bound, not a policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Limits {
    /// The whole CONNECT request.
    pub(crate) request: Duration,
    /// One resolution.
    pub(crate) resolve: Duration,
    /// The `ClientHello`, after the tunnel is granted.
    pub(crate) hello: Duration,
    /// The connection to the pinned address.
    pub(crate) connect: Duration,
    /// A tunnel with nothing moving either way.
    pub(crate) idle: Duration,
    /// A tunnel's whole life.
    pub(crate) lifetime: Duration,
}

impl Limits {
    /// The broker's limits.
    pub(crate) const PRODUCTION: Self = Self {
        request: Duration::from_secs(10),
        resolve: Duration::from_secs(5),
        hello: Duration::from_secs(10),
        connect: Duration::from_secs(10),
        idle: Duration::from_secs(120),
        lifetime: Duration::from_secs(3600),
    };
}

/// What an environment's proxy has done: counts by disposition, and bytes.
#[derive(Debug, Default)]
pub(crate) struct Counters {
    dispositions: Mutex<BTreeMap<&'static str, (EgressDisposition, u64)>>,
    upstream: AtomicU64,
    downstream: AtomicU64,
}

impl Counters {
    /// Count one ending.
    pub(crate) fn record(&self, disposition: EgressDisposition) {
        if let Ok(mut map) = self.dispositions.lock() {
            let entry = map.entry(disposition.as_str()).or_insert((disposition, 0));
            entry.1 = entry.1.saturating_add(1);
        }
    }

    /// Count bytes carried upstream.
    pub(crate) fn upstream(&self, bytes: u64) {
        self.upstream.fetch_add(bytes, Ordering::SeqCst);
    }

    /// Count bytes carried downstream.
    pub(crate) fn downstream(&self, bytes: u64) {
        self.downstream.fetch_add(bytes, Ordering::SeqCst);
    }

    /// The counts so far, as the wire reports them.
    pub(crate) fn snapshot(&self) -> Option<EgressCounters> {
        let map = self.dispositions.lock().ok()?;
        let dispositions = map
            .values()
            .filter_map(|(disposition, count)| {
                Some(EgressCount {
                    disposition: *disposition,
                    count: EgressCountValue::new(*count)?,
                })
            })
            .collect();
        Some(EgressCounters {
            dispositions: EgressCountList::new(dispositions)?,
            bytes_upstream: ByteCount::new(self.upstream.load(Ordering::SeqCst))?,
            bytes_downstream: ByteCount::new(self.downstream.load(Ordering::SeqCst))?,
        })
    }
}
