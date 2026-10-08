//! Step 13 of a hop: whether the response asks for a redirect, and if so
//! whether it may become a next hop — which the authority then decides from
//! the start, like the first (ADR-0050 §7, D5). Pure.
//!
//! | response | next hop |
//! |---|---|
//! | not `301` `302` `303` `307` `308`, or no `Location` | none: this is the answer |
//! | the request did not ask to follow | none: `NOT_FOLLOWED` |
//! | a `Location` that is not an `https` URL with one reading | none: `REDIRECT_TARGET_INVALID` (a downgrade is one) |
//! | `303` | `GET` (`HEAD` stays `HEAD`), no body |
//! | `301` `302` `307` `308` after a method that may carry a body | none: `REDIRECT_WOULD_RESEND_BODY` — a body is never replayed |
//! | `301` `302` `307` `308` otherwise | the same method, no body |
//! | the sixth hop already made | none: `REDIRECT_LIMIT` |
//! | a URL this request already visited | none: `REDIRECT_LOOP` |

use dwk_proto::dwkp::netops::{HttpMethod, RedirectEnd};
use dwk_proto::wire::http::MAX_HOPS;
use dwk_proto::wire::url::HttpsUrl;

/// What follows a response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Next {
    /// A next hop, to be decided from the start.
    Hop {
        /// Where.
        url: HttpsUrl,
        /// With which method. Never a body.
        method: HttpMethod,
    },
    /// No next hop: the response is the answer, and — when a redirect was
    /// asked for — why it was not followed.
    End(Option<RedirectEnd>),
}

/// Whether `status` asks for a redirect.
pub(crate) const fn redirects(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

/// What follows the response to hop `hop` (from 1) of a request whose URL was
/// `base`, sent with `method`. `visited` holds every canonical URL the request
/// has asked for, this hop's included.
pub(crate) fn next(
    status: u16,
    location: Option<&str>,
    base: &HttpsUrl,
    method: HttpMethod,
    follow: bool,
    hop: usize,
    visited: &[String],
) -> Next {
    if !redirects(status) {
        return Next::End(None);
    }
    let Some(location) = location else {
        return Next::End(None);
    };
    if !follow {
        return Next::End(Some(RedirectEnd::NotFollowed));
    }
    let Ok(url) = base.resolve(location) else {
        return Next::End(Some(RedirectEnd::RedirectTargetInvalid));
    };
    let method = if status == 303 {
        if method == HttpMethod::Head {
            HttpMethod::Head
        } else {
            HttpMethod::Get
        }
    } else if method.permits_body() {
        return Next::End(Some(RedirectEnd::RedirectWouldResendBody));
    } else {
        method
    };
    if hop >= MAX_HOPS {
        return Next::End(Some(RedirectEnd::RedirectLimit));
    }
    if visited.iter().any(|seen| *seen == url.canonical()) {
        return Next::End(Some(RedirectEnd::RedirectLoop));
    }
    Next::Hop { url, method }
}

#[cfg(test)]
mod tests {
    use dwk_proto::dwkp::netops::{HttpMethod as M, RedirectEnd as E};
    use dwk_proto::wire::url::HttpsUrl;

    use super::{Next, next};

    fn base() -> HttpsUrl {
        HttpsUrl::parse("https://api.example.com/v1/a?q=1")
            .unwrap_or_else(|e| unreachable!("{e:?}"))
    }

    fn visited() -> Vec<String> {
        vec![base().canonical()]
    }

    fn to(url: &str, method: M) -> Next {
        Next::Hop {
            url: HttpsUrl::parse(url).unwrap_or_else(|e| unreachable!("{e:?}")),
            method,
        }
    }

    #[test]
    fn only_a_redirect_with_a_location_is_a_next_hop() {
        assert_eq!(
            next(200, Some("/b"), &base(), M::Get, true, 1, &visited()),
            Next::End(None)
        );
        assert_eq!(
            next(304, Some("/b"), &base(), M::Get, true, 1, &visited()),
            Next::End(None)
        );
        assert_eq!(
            next(302, None, &base(), M::Get, true, 1, &visited()),
            Next::End(None)
        );
        assert_eq!(
            next(302, Some("/b"), &base(), M::Get, false, 1, &visited()),
            Next::End(Some(E::NotFollowed))
        );
        assert_eq!(
            next(302, Some("/b"), &base(), M::Get, true, 1, &visited()),
            to("https://api.example.com/b", M::Get)
        );
        assert_eq!(
            next(307, Some("other"), &base(), M::Options, true, 1, &visited()),
            to("https://api.example.com/v1/other", M::Options)
        );
    }

    #[test]
    fn a_body_is_never_replayed_and_303_becomes_a_get() {
        for status in [301, 302, 307, 308] {
            for method in [M::Post, M::Put, M::Patch, M::Delete] {
                assert_eq!(
                    next(status, Some("/b"), &base(), method, true, 1, &visited()),
                    Next::End(Some(E::RedirectWouldResendBody)),
                    "{status} {method:?}"
                );
            }
        }
        assert_eq!(
            next(303, Some("/done"), &base(), M::Post, true, 1, &visited()),
            to("https://api.example.com/done", M::Get)
        );
        assert_eq!(
            next(303, Some("/done"), &base(), M::Head, true, 1, &visited()),
            to("https://api.example.com/done", M::Head)
        );
    }

    #[test]
    fn a_downgrade_a_malformed_target_a_loop_and_the_sixth_hop_end_the_chain() {
        for bad in [
            "http://api.example.com/b",
            "https://127.0.0.1/",
            "https://user@api.example.com/",
            "https://api.example.com/%2e%2e/x",
            "javascript:alert(1)",
            "//[::1]/",
            "https://api.example.com/#f",
        ] {
            assert_eq!(
                next(302, Some(bad), &base(), M::Get, true, 1, &visited()),
                Next::End(Some(E::RedirectTargetInvalid)),
                "{bad}"
            );
        }
        assert_eq!(
            next(302, Some("/v1/a?q=1"), &base(), M::Get, true, 1, &visited()),
            Next::End(Some(E::RedirectLoop))
        );
        assert_eq!(
            next(
                302,
                Some("/elsewhere"),
                &base(),
                M::Get,
                true,
                6,
                &visited()
            ),
            Next::End(Some(E::RedirectLimit))
        );
        assert_eq!(
            next(
                302,
                Some("/elsewhere"),
                &base(),
                M::Get,
                true,
                5,
                &visited()
            ),
            to("https://api.example.com/elsewhere", M::Get)
        );
    }
}
