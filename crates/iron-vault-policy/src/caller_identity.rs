//! Caller identification: which caller a request comes from, decided from the listener it arrived on and, on a token
//! listener, the caller token it presents (spec §3.4, §3.5 step 3, §3.12).
//!
//! The three mechanisms of §3.4 reduce to one rule. A `socket` or `isolated-network` listener has exactly one caller,
//! which validation guarantees, so the listener alone names it. A token listener's caller is the one on that listener
//! whose token hash the presented token matches; validation guarantees at most one does.
//!
//! Nothing here reaches the admin interface. The admin socket is a separate socket that accepts an admin principal by
//! its peer credentials alone (§3.2), so neither a caller token nor a listener identity is ever an admin credential.
//! Keep it that way: same-user malware can steal caller tokens (§3.4), and they must never grant admin access.

use thiserror::Error;

use crate::activation::ActivePolicy;
use crate::caller::{CallerAuth, CallerConfig};
use crate::caller_token::CallerToken;
use crate::header_name::HeaderName;
use crate::header_value::HeaderValue;
use crate::listener::{DEFAULT_TOKEN_HEADER, ListenerConfig};
use crate::name::{CallerName, ListenerName};

/// The `Proxy-Authorization` scheme and its single separating space, compared case-insensitively.
const BEARER: &[u8] = b"Bearer ";

/// The request's caller could not be identified; the request interface answers `401` (spec §3.12).
///
/// It carries nothing: no caller name, header or token, so no response or log built from it can disclose credential
/// information. The response body must not name the authentication scheme, the token header or the listener's callers
/// either, because each tells a client without a token where to look for one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("the caller could not be authenticated")]
pub struct Unauthenticated;

/// Identifies the caller of a request that arrived on `listener` with the caller's `headers`.
///
/// `listener` must come from the socket or address that accepted the connection, never from the request. On a token
/// listener the token is read from the listener's `token_header`, whose whole value is the token, or else from
/// `Proxy-Authorization` as `Bearer <token>`. A missing, repeated or malformed header, an unknown token, or a listener
/// with no callers is [`Unauthenticated`].
///
/// A token sent to a `socket` or `isolated-network` listener is ignored rather than checked: the listener already
/// names the caller, and the header is reserved, so it is stripped before forwarding.
pub fn identify_caller(
    policy: &ActivePolicy,
    listener: &ListenerName,
    headers: &[(HeaderName, HeaderValue)],
) -> Result<CallerName, Unauthenticated> {
    let config = policy.config();
    let callers: Vec<_> = config
        .callers()
        .iter()
        .filter(|(_, caller)| caller.listener() == listener)
        .collect();
    match callers.as_slice() {
        [(name, caller)] if !matches!(caller.auth(), CallerAuth::Token(_)) => Ok((*name).clone()),
        _ => {
            let listener = config.listeners().get(listener).ok_or(Unauthenticated)?;
            let token = presented_token(listener, headers).ok_or(Unauthenticated)?;
            token_holder(&callers, &token).cloned().ok_or(Unauthenticated)
        }
    }
}

/// The caller token presented in the listener's token header, if exactly one well-formed one is.
///
/// A `token_header` that names `Proxy-Authorization` is the default header, so it keeps the `Bearer` form.
fn presented_token(listener: &ListenerConfig, headers: &[(HeaderName, HeaderValue)]) -> Option<CallerToken> {
    let dedicated = listener.token_header().filter(|header| header.lowercase() != DEFAULT_TOKEN_HEADER);
    let presented = match dedicated {
        Some(header) => sole_value(headers, header.lowercase()),
        None => sole_value(headers, DEFAULT_TOKEN_HEADER).and_then(bearer_token),
    };
    presented.and_then(|bytes| CallerToken::parse(bytes).ok())
}

/// The value of the one header whose lowercase name is `lowercase`; none when it is absent or repeated.
///
/// A repeated token header is refused rather than resolved, because a proxy and Iron Vault could pick different copies.
fn sole_value<'a>(headers: &'a [(HeaderName, HeaderValue)], lowercase: &str) -> Option<&'a [u8]> {
    let mut values = headers
        .iter()
        .filter(|(name, _)| name.lowercase() == lowercase)
        .map(|(_, value)| value.as_bytes());
    match (values.next(), values.next()) {
        (Some(value), None) => Some(value),
        _ => None,
    }
}

/// The token in a `Bearer <token>` value, with the scheme in any case and exactly one space after it.
fn bearer_token(value: &[u8]) -> Option<&[u8]> {
    let (scheme, token) = value.split_at_checked(BEARER.len())?;
    scheme.eq_ignore_ascii_case(BEARER).then_some(token)
}

/// The token caller whose hash `token` matches, comparing it against every token caller in `callers`.
fn token_holder<'a>(callers: &[(&'a CallerName, &'a CallerConfig)], token: &CallerToken) -> Option<&'a CallerName> {
    let comparisons = callers.iter().filter_map(|(name, caller)| match caller.auth() {
        CallerAuth::Token(hash) => Some((*name, hash.matches(token))),
        CallerAuth::IsolatedNetwork | CallerAuth::Socket => None,
    });
    sole_match(comparisons)
}

/// The one candidate whose comparison matched, or none when zero or several did.
///
/// Every comparison is consumed, with no early return, so the work done does not depend on which caller matched or
/// whether any did; timing then reveals neither the matching caller's position nor a near miss. Several matches cannot
/// happen in a validated config, which refuses a shared token hash, and would be refused here anyway.
fn sole_match<T>(comparisons: impl Iterator<Item = (T, bool)>) -> Option<T> {
    let (found, count) = comparisons.fold((None, 0usize), |(found, count), (candidate, matched)| {
        (matched.then_some(candidate).or(found), count + usize::from(matched))
    });
    found.filter(|_| count == 1)
}

#[cfg(test)]
mod tests;
