//! Headers that carry caller authentication or control transport, routing or method semantics (spec §3.6).
//!
//! This is the single denylist for two uses: a header slot may never name one of these headers, and the outgoing
//! request has them removed before forwarding. Keeping both uses on one list means a header cannot be stripped from
//! callers yet written with a credential, or the reverse.

use crate::header_name::HeaderName;

/// Reserved header names, lowercase, matched exactly.
pub const RESERVED_HEADERS: &[&str] = &[
    // Hop-by-hop headers (RFC 9110 §7.6.1), plus the legacy `Keep-Alive` and `Proxy-Connection`.
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    // The service controls the authority and message framing; a credential written here would redirect or split the
    // request.
    "host",
    "content-length",
    // Forwarding headers. `Via` and `X-Real-IP` are not named in §3.6, but upstreams read them as client or proxy
    // identity exactly as they read `Forwarded`, so they get the same treatment.
    "forwarded",
    "via",
    "x-real-ip",
    // Client-address headers set by CDNs and load balancers (Akamai/Cloudflare `True-Client-IP`, Cloudflare
    // `CF-Connecting-IP`, `X-Client-IP`). Upstreams behind such a CDN trust them as the caller's address.
    "true-client-ip",
    "x-client-ip",
    "cf-connecting-ip",
    // Host-override headers. Some frameworks and proxies take the request's authority from these in place of `Host`,
    // which the service controls.
    "x-host",
    "x-original-host",
    "x-http-host-override",
    // Method-override headers.
    "x-http-method-override",
    "x-method-override",
    "x-http-method",
    // URL-rewrite headers.
    "x-original-url",
    "x-rewrite-url",
];

/// Reserved header-name prefixes, lowercase; any header starting with one is reserved.
pub const RESERVED_PREFIXES: &[&str] = &["x-forwarded-"];

/// Whether `name` is a caller-authentication or transport-control header.
pub fn is_reserved(name: &HeaderName) -> bool {
    let lowercase = name.lowercase();
    RESERVED_HEADERS.contains(&lowercase) || RESERVED_PREFIXES.iter().any(|prefix| lowercase.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reserved(s: &str) -> bool {
        is_reserved(&s.parse().unwrap())
    }

    #[test]
    fn list_entries_are_lowercase_header_names() {
        RESERVED_HEADERS.iter().chain(RESERVED_PREFIXES).for_each(|entry| {
            assert_eq!(*entry, entry.to_ascii_lowercase());
            assert!(entry.parse::<HeaderName>().is_ok(), "{entry}");
        });
    }

    #[test]
    fn named_headers_are_reserved_in_any_case() {
        [
            "Host",
            "content-length",
            "Transfer-Encoding",
            "CONNECTION",
            "Keep-Alive",
            "Proxy-Authorization",
            "TE",
            "Trailer",
            "Upgrade",
            "Forwarded",
            "X-HTTP-Method-Override",
            "X-Method-Override",
            "X-HTTP-Method",
            "X-Original-URL",
            "X-Rewrite-URL",
            "X-Host",
            "X-Original-Host",
            "X-HTTP-Host-Override",
            "True-Client-IP",
            "X-Client-IP",
            "CF-Connecting-IP",
        ]
        .iter()
        .for_each(|h| assert!(reserved(h), "{h}"));
    }

    #[test]
    fn forwarded_prefix_is_reserved() {
        ["X-Forwarded-For", "x-forwarded-host", "X-Forwarded-Proto", "X-Forwarded-Anything"]
            .iter()
            .for_each(|h| assert!(reserved(h), "{h}"));
    }

    #[test]
    fn credential_headers_are_not_reserved() {
        [
            "Authorization",
            "X-Subscription-Token",
            "X-Api-Key",
            "X-Forwarded",
            "Hostname",
            "Content-Type",
        ]
        .iter()
        .for_each(|h| assert!(!reserved(h), "{h}"));
    }
}
