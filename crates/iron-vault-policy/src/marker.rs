//! Markers: `{iv:name}` placeholders an SDK may put where its API key belongs (spec §3.6, §8.2 Q-1).
//!
//! A marker never selects or expands a credential: the route alone selects the credential (§3.5 step 6). Slot filling
//! scans only the text it is about to replace, and refuses the request when a marker there names a different
//! credential, because that caller expected another key and is misconfigured or probing. Markers anywhere else are
//! inert text and are never scanned, so a marker in an issue title or a JSON body cannot make the upstream store the
//! real key (R-10).

use thiserror::Error;

use crate::name::CredentialName;

/// The text that opens a marker.
const OPEN: &str = "{iv:";

/// The character that closes a marker.
const CLOSE: char = '}';

/// A marker that cannot be read. Its text never repeats the scanned input, which may hold caller secrets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum MarkerError {
    /// `{iv:` is followed by an invalid credential name or has no closing `}`.
    #[error("malformed {{iv:…}} marker")]
    Malformed,
}

/// Every marker in `text`, in order: the credential name it carries, or [`MarkerError::Malformed`].
///
/// Each `{iv:` starts a marker that runs to the next `}`; the text between is parsed with the [`CredentialName`] rules.
/// Matching is case-sensitive, as `{iv:` is the only marker syntax. A `{iv:` with no closing `}` ends the scan with
/// one error, so a caller cannot hide a marker behind an unterminated one.
pub fn markers(text: &str) -> impl Iterator<Item = Result<CredentialName, MarkerError>> + '_ {
    let mut rest = text;
    std::iter::from_fn(move || {
        let (_, opened) = rest.split_once(OPEN)?;
        let Some((name, after)) = opened.split_once(CLOSE) else {
            rest = "";
            return Some(Err(MarkerError::Malformed));
        };
        rest = after;
        Some(CredentialName::try_from(name).map_err(|_| MarkerError::Malformed))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(text: &str) -> Vec<Result<String, MarkerError>> {
        markers(text).map(|m| m.map(|name| name.as_str().to_owned())).collect()
    }

    #[test]
    fn finds_each_marker_in_order() {
        assert_eq!(scan("Bearer {iv:venice}"), [Ok("venice".to_owned())]);
        assert_eq!(scan("{iv:a}-{iv:b_2}"), [Ok("a".to_owned()), Ok("b_2".to_owned())]);
    }

    #[test]
    fn text_without_markers_yields_nothing() {
        ["", "placeholder", "{}", "{iv}", "{IV:fx_key}", "iv:fx_key}", "{ iv:fx_key}"]
            .iter()
            .for_each(|t| assert_eq!(scan(t), [], "{t}"));
    }

    #[test]
    fn invalid_names_are_malformed() {
        ["{iv:}", "{iv:Fx}", "{iv:fx key}", "{iv:1fx}", "{iv:a{iv:b}", "{iv:\u{e9}}"]
            .iter()
            .for_each(|t| assert_eq!(scan(t), [Err(MarkerError::Malformed)], "{t}"));
    }

    #[test]
    fn unterminated_marker_is_malformed_and_ends_the_scan() {
        assert_eq!(scan("{iv:fx_key"), [Err(MarkerError::Malformed)]);
        assert_eq!(scan("{iv:a} {iv:b"), [Ok("a".to_owned()), Err(MarkerError::Malformed)]);
    }

    #[test]
    fn error_text_omits_the_input() {
        let message = scan("{iv:SECRET").remove(0).unwrap_err().to_string();
        assert!(!message.contains("SECRET"), "{message}");
    }
}
