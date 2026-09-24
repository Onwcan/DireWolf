//! Channel values: one per accepted connection (M4b, ADR-0043).
//!
//! A channel is the broker's name for one connection, sent in its hello and
//! required in the one authorisation it will execute there. It is 128 bits:
//! a 64-bit prefix drawn once per process from the standard library's
//! randomly keyed hasher (keyed from the operating system's random source),
//! then a 64-bit counter. So within one broker process no two connections
//! ever share a channel — by construction, not by probability — and a channel
//! from an earlier broker process is not one a restarted broker will issue
//! (the prefixes differ except with probability 2^-64).
//!
//! It is not a secret and needs no key: only a process the kernel reports as
//! the authority's uid is ever read from, and a channel only makes what that
//! process sends single-use.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher as _, Hasher as _};

use dwk_proto::brokerp::ChannelNonce;

/// The issuer of channels for one broker process.
#[derive(Debug)]
pub(crate) struct Channels {
    prefix: u64,
    issued: Option<u64>,
}

impl Channels {
    /// A fresh issuer with a random prefix.
    pub(crate) fn new() -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let mut hasher = RandomState::new().build_hasher();
        hasher.write_u32(std::process::id());
        hasher.write_u128(nanos);
        Self {
            prefix: hasher.finish(),
            issued: Some(0),
        }
    }

    /// The next channel, or `None` once 2^64 have been issued — never a
    /// repeat.
    pub(crate) fn issue(&mut self) -> Option<ChannelNonce> {
        let n = self.issued?;
        self.issued = n.checked_add(1);
        ChannelNonce::new(format!("{:016x}{n:016x}", self.prefix))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::Channels;

    #[test]
    fn channels_never_repeat_within_a_process_and_differ_across_issuers() {
        let mut channels = Channels::new();
        let mut seen = HashSet::new();
        for _ in 0..10_000 {
            let Some(channel) = channels.issue() else {
                unreachable!("issued")
            };
            assert!(seen.insert(channel.as_str().to_owned()));
        }
        let mut other = Channels::new();
        let first = other.issue().map(|c| c.as_str().to_owned());
        assert!(first.is_some_and(|c| !seen.contains(&c)));
    }

    #[test]
    fn an_exhausted_issuer_issues_nothing_rather_than_a_repeat() {
        let mut channels = Channels::new();
        channels.issued = Some(u64::MAX);
        assert!(channels.issue().is_some());
        assert!(channels.issue().is_none());
        assert!(channels.issue().is_none());
    }
}
