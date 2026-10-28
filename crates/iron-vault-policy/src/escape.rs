//! RFC 3986 character classes and the percent-escape walker shared by every path parser in this crate.
//!
//! Upstream base paths and caller request paths must end up in one representation, so both are built by the same
//! walker; each parser supplies only its own decision for each escaped byte.

use std::fmt::Write as _;

/// RFC 3986 `unreserved`: characters whose escaped and unescaped forms are equivalent.
pub(crate) fn is_unreserved(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~')
}

/// RFC 3986 `sub-delims`: allowed unescaped in a path segment, but distinct from their escaped forms.
pub(crate) fn is_sub_delim(c: char) -> bool {
    matches!(c, '!' | '$' | '&' | '\'' | '(' | ')' | '*' | '+' | ',' | ';' | '=')
}

/// RFC 3986 `pchar` plus `%`: the characters a path segment may contain literally.
///
/// Anything else would be percent-encoded by a URL serializer, so the forwarded path would differ from the checked one.
pub(crate) fn is_path_char(c: char) -> bool {
    is_unreserved(c) || is_sub_delim(c) || matches!(c, ':' | '@' | '%')
}

/// Two ASCII hex digits; `u8::from_str_radix` alone would also accept a leading `+`.
pub(crate) fn decode_hex_pair(hex: &str) -> Option<u8> {
    hex.bytes().all(|b| b.is_ascii_hexdigit()).then(|| u8::from_str_radix(hex, 16).ok()).flatten()
}

/// What a parser wants done with one escaped byte.
pub(crate) enum EscapeAction<E> {
    /// Keep the escape, rewritten with uppercase hex digits.
    Keep,
    /// Replace the escape with the character it encodes. A byte outside ASCII is not a character on its own, so it is
    /// kept encoded instead.
    Decode,
    /// Reject the whole segment.
    Reject(E),
}

/// Why [`walk_escapes`] rejected a segment.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum EscapeError<E> {
    /// A `%` is not followed by two hex digits.
    Malformed,
    /// The policy rejected an escaped byte.
    Rejected(E),
    /// The fully decoded segment is not UTF-8, which includes overlong forms such as `%C0%AE`.
    InvalidUtf8,
}

/// A segment after [`walk_escapes`].
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Walked {
    /// The segment with each escape kept (uppercase hex) or decoded, as the policy chose.
    pub(crate) normalized: String,
    /// The segment with every escape decoded: the text a decoder downstream would see.
    pub(crate) decoded: String,
}

/// Walks the escapes of one path segment left to right, applying `policy` to each escaped byte.
///
/// Escapes are checked on the raw text before anything is decoded, so no step here can erase evidence that the policy
/// would reject. The first malformed or rejected escape ends the walk.
pub(crate) fn walk_escapes<E>(segment: &str, policy: impl Fn(u8) -> EscapeAction<E>) -> Result<Walked, EscapeError<E>> {
    let mut parts = segment.split('%');
    let head = parts.next().unwrap_or_default();
    let start = (head.to_owned(), head.as_bytes().to_vec());
    let (normalized, decoded) = parts.try_fold(start, |(mut normalized, mut decoded), part| {
        let (hex, tail) = part.split_at_checked(2).ok_or(EscapeError::Malformed)?;
        let byte = decode_hex_pair(hex).ok_or(EscapeError::Malformed)?;
        match policy(byte) {
            EscapeAction::Decode if byte.is_ascii() => normalized.push(char::from(byte)),
            EscapeAction::Keep | EscapeAction::Decode => push_uppercase_escape(&mut normalized, byte),
            EscapeAction::Reject(e) => return Err(EscapeError::Rejected(e)),
        }
        normalized.push_str(tail);
        decoded.push(byte);
        decoded.extend_from_slice(tail.as_bytes());
        Ok((normalized, decoded))
    })?;
    let decoded = String::from_utf8(decoded).map_err(|_| EscapeError::InvalidUtf8)?;
    Ok(Walked { normalized, decoded })
}

/// Appends `%XX` for `byte`, in the uppercase hex every escape this crate writes uses.
pub(crate) fn push_uppercase_escape(out: &mut String, byte: u8) {
    // Writing to a `String` cannot fail.
    let _ = write!(out, "%{byte:02X}");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keep_all(_: u8) -> EscapeAction<()> {
        EscapeAction::Keep
    }

    fn walk(segment: &str, policy: impl Fn(u8) -> EscapeAction<()>) -> Result<Walked, EscapeError<()>> {
        walk_escapes(segment, policy)
    }

    #[test]
    fn segment_without_escapes_is_unchanged() {
        let walked = walk("a;b=c", keep_all);
        assert_eq!(walked, Ok(Walked { normalized: "a;b=c".to_owned(), decoded: "a;b=c".to_owned() }));
    }

    #[test]
    fn kept_escapes_get_uppercase_hex() {
        let walked = walk("x%3a%c3%a9y", keep_all);
        assert_eq!(walked, Ok(Walked { normalized: "x%3A%C3%A9y".to_owned(), decoded: "x:\u{e9}y".to_owned() }));
    }

    #[test]
    fn decoded_escapes_become_characters_but_non_ascii_bytes_stay_encoded() {
        let walked = walk("%41%c3%a9", |_| EscapeAction::Decode);
        assert_eq!(walked, Ok(Walked { normalized: "A%C3%A9".to_owned(), decoded: "A\u{e9}".to_owned() }));
    }

    #[test]
    fn rejected_byte_ends_the_walk() {
        let policy = |byte: u8| if byte == b'.' { EscapeAction::Reject(()) } else { EscapeAction::Keep };
        assert_eq!(walk("a%20%2e", policy), Err(EscapeError::Rejected(())));
    }

    #[test]
    fn malformed_escapes_are_reported_before_the_policy_sees_them() {
        ["%", "a%", "%2", "%zz", "%+f", "%2g"].into_iter().for_each(|segment| {
            assert_eq!(walk(segment, |_| EscapeAction::Reject(())), Err(EscapeError::Malformed), "{segment}");
        });
    }

    #[test]
    fn invalid_utf8_is_reported() {
        ["%C0%AE", "%FF", "%C3", "%ED%A0%80"].into_iter().for_each(|segment| {
            assert_eq!(walk(segment, keep_all), Err(EscapeError::InvalidUtf8), "{segment}");
        });
    }
}
