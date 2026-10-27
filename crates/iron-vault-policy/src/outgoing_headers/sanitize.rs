//! Turning a caller's headers into [`OutgoingHeaders`] (specification §3.6).
//!
//! Every caller header is untrusted. Forwarding and method-override headers would let an upstream apply a different
//! route policy than Iron Vault checked (R-9, R-11), a forwarded caller token would leak it, and conflicting framing
//! headers would let Iron Vault and the upstream disagree about where the body ends.

use thiserror::Error;

use super::OutgoingHeaders;
use crate::header_name::HeaderName;
use crate::header_value::HeaderValue;
use crate::reserved_headers::is_reserved;

/// Why a caller's headers were rejected; the request interface answers every variant with `400` (§3.12).
///
/// The text names the header, never its value, because values can carry tokens.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SanitizeError {
    /// A `Content-Length` value is not a single decimal number.
    #[error("Content-Length is not a decimal number")]
    InvalidContentLength,
    /// Two `Content-Length` headers give different lengths.
    #[error("Content-Length headers disagree")]
    ConflictingContentLength,
    /// `Content-Length` and `Transfer-Encoding` both frame the body.
    #[error("Content-Length and Transfer-Encoding are both present")]
    ContentLengthWithTransferEncoding,
}

/// The caller's headers with framing checked and every header removed that must not reach the upstream.
///
/// Removed: headers named by a `Connection` header, every reserved header, and the listener's caller-token header
/// `token_header` (pass the default `Proxy-Authorization` when the listener sets none). The remaining headers keep
/// the caller's order and duplicates.
///
/// Framing is checked on the caller's list before anything is removed, so an ambiguous body length is rejected even
/// though the framing headers themselves are dropped and the transport sets its own.
pub fn sanitize(caller: &[(HeaderName, HeaderValue)], token_header: &HeaderName) -> Result<OutgoingHeaders, SanitizeError> {
    check_framing(caller)?;
    let hop_by_hop = connection_names(caller);
    let entries = caller
        .iter()
        .filter(|(name, _)| !is_reserved(name) && name != token_header && !hop_by_hop.contains(name))
        .cloned()
        .collect();
    Ok(OutgoingHeaders { entries })
}

/// Rejects framing that the HTTP stack and the upstream could read differently.
fn check_framing(caller: &[(HeaderName, HeaderValue)]) -> Result<(), SanitizeError> {
    let lengths = values_of(caller, "content-length").map(content_length).collect::<Result<Vec<_>, _>>()?;
    let Some(first) = lengths.first() else {
        return Ok(());
    };
    if lengths.iter().any(|length| length != first) {
        return Err(SanitizeError::ConflictingContentLength);
    }
    match values_of(caller, "transfer-encoding").next() {
        Some(_) => Err(SanitizeError::ContentLengthWithTransferEncoding),
        None => Ok(()),
    }
}

/// Every value of the headers whose lowercase name is `lowercase`.
fn values_of<'a>(caller: &'a [(HeaderName, HeaderValue)], lowercase: &'a str) -> impl Iterator<Item = &'a [u8]> {
    caller.iter().filter(move |(name, _)| name.lowercase() == lowercase).map(|(_, value)| value.as_bytes())
}

/// A `Content-Length` value as a number: ASCII digits only, so signs, lists and whitespace inside are rejected.
fn content_length(value: &[u8]) -> Result<u64, SanitizeError> {
    let digits = trim_ows(value);
    let all_digits = !digits.is_empty() && digits.iter().all(u8::is_ascii_digit);
    all_digits
        .then(|| std::str::from_utf8(digits).ok()?.parse().ok())
        .flatten()
        .ok_or(SanitizeError::InvalidContentLength)
}

/// The names listed in every `Connection` header (RFC 9110 §7.6.1).
///
/// A list member that is not a valid header name is skipped: no caller header can carry that name, so there is
/// nothing for it to remove.
fn connection_names(caller: &[(HeaderName, HeaderValue)]) -> Vec<HeaderName> {
    values_of(caller, "connection")
        .flat_map(|value| value.split(|b| *b == b','))
        .filter_map(|member| std::str::from_utf8(trim_ows(member)).ok())
        .filter_map(|member| HeaderName::try_from(member).ok())
        .collect()
}

/// `bytes` without leading and trailing optional whitespace (spaces and tabs, RFC 9110 §5.6.3).
fn trim_ows(bytes: &[u8]) -> &[u8] {
    let is_ows = |b: &u8| *b == b' ' || *b == b'\t';
    let start = bytes.iter().position(|b| !is_ows(b)).unwrap_or(bytes.len());
    let end = bytes.iter().rposition(|b| !is_ows(b)).map_or(start, |last| last + 1);
    bytes.get(start..end).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(s: &str) -> HeaderName {
        s.parse().unwrap()
    }

    fn headers(pairs: &[(&str, &str)]) -> Vec<(HeaderName, HeaderValue)> {
        pairs.iter().map(|(n, v)| (name(n), HeaderValue::try_from(*v).unwrap())).collect()
    }

    fn proxy_authorization() -> HeaderName {
        name("Proxy-Authorization")
    }

    fn sanitized(pairs: &[(&str, &str)], token_header: &HeaderName) -> Vec<(String, String)> {
        let outgoing = sanitize(&headers(pairs), token_header).unwrap();
        outgoing.iter().map(|(n, v)| (n.as_str().to_owned(), String::from_utf8_lossy(v.as_bytes()).into_owned())).collect()
    }

    fn names(pairs: &[(&str, &str)], token_header: &HeaderName) -> Vec<String> {
        sanitized(pairs, token_header).into_iter().map(|(n, _)| n).collect()
    }

    fn rejected(pairs: &[(&str, &str)]) -> SanitizeError {
        sanitize(&headers(pairs), &proxy_authorization()).unwrap_err()
    }

    #[test]
    fn strips_specification_denylist_in_any_case() {
        [
            "X-HTTP-Method-Override",
            "X-Method-Override",
            "X-HTTP-Method",
            "X-Original-URL",
            "X-Rewrite-URL",
            "Forwarded",
            "X-Forwarded-For",
            "X-Forwarded-Host",
            "Proxy-Authorization",
        ]
        .iter()
        .flat_map(|h| [h.to_string(), h.to_ascii_lowercase(), h.to_ascii_uppercase()])
        .for_each(|h| assert_eq!(names(&[("Accept", "*/*"), (&h, "x")], &proxy_authorization()), ["Accept"], "{h}"));
    }

    #[test]
    fn strips_headers_named_by_connection() {
        let pairs = [("Connection", "keep-alive, X-Secret-Hop"), ("x-secret-hop", "s"), ("X-Custom", "c")];
        assert_eq!(names(&pairs, &proxy_authorization()), ["X-Custom"]);
    }

    #[test]
    fn connection_list_is_trimmed_and_tolerates_junk_members() {
        let pairs = [("Connection", " ,\tX-A ,, bad name ,x-b"), ("X-A", "a"), ("X-B", "b"), ("X-C", "c")];
        assert_eq!(names(&pairs, &proxy_authorization()), ["X-C"]);
    }

    #[test]
    fn strips_the_listener_token_header_only_when_configured() {
        let pairs = [("x-iron-vault-token", "t"), ("Accept", "*/*")];
        assert_eq!(names(&pairs, &name("X-Iron-Vault-Token")), ["Accept"]);
        assert_eq!(names(&pairs, &proxy_authorization()), ["x-iron-vault-token", "Accept"]);
    }

    #[test]
    fn caller_host_never_reaches_the_output() {
        assert_eq!(names(&[("Host", "evil.example"), ("HOST", "evil.example")], &proxy_authorization()), Vec::<String>::new());
    }

    #[test]
    fn unrelated_headers_pass_through_in_order_with_duplicates() {
        let pairs = [("Accept", "a"), ("User-Agent", "u"), ("X-Custom", "1"), ("Accept", "b"), ("X-Custom", "2")];
        let expected: Vec<_> = pairs.iter().map(|(n, v)| (n.to_string(), v.to_string())).collect();
        assert_eq!(sanitized(&pairs, &proxy_authorization()), expected);
    }

    #[test]
    fn rejects_ambiguous_framing() {
        assert_eq!(rejected(&[("Content-Length", "5"), ("content-length", "6")]), SanitizeError::ConflictingContentLength);
        assert_eq!(
            rejected(&[("Content-Length", "5"), ("Transfer-Encoding", "chunked")]),
            SanitizeError::ContentLengthWithTransferEncoding
        );
        ["5, 6", "+5", "-5", "", " ", "5 6", "0x5", "5.0", "99999999999999999999999"]
            .iter()
            .for_each(|v| assert_eq!(rejected(&[("Content-Length", v)]), SanitizeError::InvalidContentLength, "{v:?}"));
    }

    #[test]
    fn identical_content_lengths_are_accepted_then_stripped() {
        let pairs = [("Content-Length", "5"), ("Accept", "a"), ("Content-Length", " 5\t")];
        assert_eq!(names(&pairs, &proxy_authorization()), ["Accept"]);
    }

    #[test]
    fn transfer_encoding_alone_is_stripped() {
        assert_eq!(names(&[("Transfer-Encoding", "chunked"), ("Accept", "a")], &proxy_authorization()), ["Accept"]);
    }

    #[test]
    fn error_text_omits_values() {
        let message = rejected(&[("Content-Length", "secret")]).to_string();
        assert!(message.contains("Content-Length") && !message.contains("secret"), "{message}");
    }

    #[test]
    fn trim_ows_removes_spaces_and_tabs_only() {
        assert_eq!(trim_ows(b" \tab c\t "), b"ab c");
        assert_eq!(trim_ows(b"  "), b"");
        assert_eq!(trim_ows(b"\x0c5"), b"\x0c5");
    }
}
