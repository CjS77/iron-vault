//! Identifies which caller a request comes from, using the listener it arrived on and, on a peer listener, the
//! connecting process's uid or, on a token listener, the caller token it presents (spec §7, §8 step 3, §15). The
//! service's request handler calls [`identify_caller`] before anything else looks at the request.
//!
//! ```text
//! listener kind        decided by                                   no match
//! isolated-network     the listener alone: it has exactly one caller   –
//! peer                 the connection's peer uid                    401
//! token                the token in token_header, or                401
//!                      Proxy-Authorization: Bearer <token>
//! ```
//!
//! Validation leaves each listener with one mechanism. An `isolated-network` listener has exactly one caller, so the
//! listener alone names it. A peer listener holds only peer callers, and activation resolves their accounts to distinct
//! uids, so the connecting process's uid names at most one. A token listener's caller is the one on that listener whose
//! token hash the presented token matches; validation guarantees at most one does.
//!
//! Nothing here reaches the admin interface. The admin socket is a separate socket that accepts an admin principal by
//! its peer credentials alone (§5), so neither a caller token nor a listener identity is ever an admin credential.
//! Keep it that way: same-user malware can steal caller tokens (§7), and they must never grant admin access.

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

/// The request's caller could not be identified; the request interface answers `401` (spec §15).
///
/// It carries nothing: no caller name, header or token, so no response or log built from it can disclose credential
/// information. The response body must not name the authentication scheme, the token header or the listener's callers
/// either, because each tells a client without a token where to look for one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("the caller could not be authenticated")]
pub struct Unauthenticated;

/// Identifies the caller of a request that arrived on `listener`, from a process running as `peer_uid`, with the
/// caller's `headers`.
///
/// `listener` and `peer_uid` must both come from the accepted connection, never from the request: the listener from
/// the socket or address that accepted it, and `peer_uid` from the uid in that socket's peer identity, or none when the
/// transport reports no account, as TCP does.
///
/// On a peer listener the caller is the one whose account resolved to `peer_uid` at activation; no match, or no uid,
/// is [`Unauthenticated`]. On a token listener the token is read from the listener's `token_header`, whose whole value
/// is the token, or else from `Proxy-Authorization` as `Bearer <token>`. A missing, repeated or malformed header, an
/// unknown token, or a listener with no callers is [`Unauthenticated`].
///
/// A token sent to an `isolated-network` or peer listener is ignored rather than checked: the listener or the peer uid
/// already decides the caller, and the header is reserved, so it is stripped before forwarding.
pub fn identify_caller(
    policy: &ActivePolicy,
    listener: &ListenerName,
    peer_uid: Option<u32>,
    headers: &[(HeaderName, HeaderValue)],
) -> Result<CallerName, Unauthenticated> {
    let config = policy.config();
    let callers: Vec<_> = config
        .callers()
        .iter()
        .filter(|(_, caller)| caller.listener() == listener)
        .collect();
    if callers.iter().any(|(_, caller)| matches!(caller.auth(), CallerAuth::Peer(_))) {
        // A peer listener must never reach the sole-caller or token arms below: only the peer uid identifies there.
        return peer_holder(policy, &callers, peer_uid).cloned().ok_or(Unauthenticated);
    }
    match callers.as_slice() {
        [(name, caller)] if matches!(caller.auth(), CallerAuth::IsolatedNetwork) => Ok((*name).clone()),
        _ => {
            let listener = config.listeners().get(listener).ok_or(Unauthenticated)?;
            let token = presented_token(listener, headers).ok_or(Unauthenticated)?;
            token_holder(&callers, &token).cloned().ok_or(Unauthenticated)
        }
    }
}

/// Finds the peer caller in `callers` whose account resolved to `peer_uid` when `policy` was activated.
///
/// A uid is not secret, since any local account can list them all in `/etc/passwd`, so a plain comparison that stops
/// at the first match is fine; unlike [`token_holder`], timing here reveals nothing worth hiding. Activation refuses two
/// callers on one listener with the same uid, so at most one matches.
fn peer_holder<'a>(policy: &ActivePolicy, callers: &[(&'a CallerName, &'a CallerConfig)], peer_uid: Option<u32>) -> Option<&'a CallerName> {
    let uid = peer_uid?;
    callers
        .iter()
        .map(|(name, _)| *name)
        .find(|name| policy.peer_uids().get(*name) == Some(&uid))
}

/// Reads the caller token from the listener's token header, if exactly one well-formed one is present.
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

/// Returns the value of the one header whose lowercase name is `lowercase`; none when it is absent or repeated.
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

/// Extracts the token from a `Bearer <token>` value, with the scheme in any case and exactly one space after it.
fn bearer_token(value: &[u8]) -> Option<&[u8]> {
    let (scheme, token) = value.split_at_checked(BEARER.len())?;
    scheme.eq_ignore_ascii_case(BEARER).then_some(token)
}

/// Finds the token caller whose hash `token` matches, comparing it against every token caller in `callers`.
fn token_holder<'a>(callers: &[(&'a CallerName, &'a CallerConfig)], token: &CallerToken) -> Option<&'a CallerName> {
    let comparisons = callers.iter().filter_map(|(name, caller)| match caller.auth() {
        CallerAuth::Token(hash) => Some((*name, hash.matches(token))),
        CallerAuth::IsolatedNetwork | CallerAuth::Peer(_) => None,
    });
    sole_match(comparisons)
}

/// Returns the one candidate whose comparison matched, or none when zero or several did.
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
