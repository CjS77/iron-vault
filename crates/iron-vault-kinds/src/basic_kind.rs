//! The `basic` kind: a username and password sent as HTTP Basic authorization (spec §3.6, §5.2; RFC 7617).

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use iron_vault_policy::{AuthorizedRequest, Slot, SlotValue};
use secrecy::zeroize::Zeroizing;
use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;

use crate::resolve::{KindError, Resolution, slot_kind};
use crate::scrub::{ScrubPatterns, copy};

/// The kind's name in errors.
const KIND: &str = "basic";

/// The authentication scheme and separator the slot filler writes before the token (RFC 7617 §2).
const SCHEME_PREFIX: &str = "Basic ";

/// A username or password that cannot form a Basic token. Its text names the rule broken, never the value.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum BasicCredentialError {
    /// The username is empty.
    #[error("basic credential username is empty")]
    EmptyUsername,
    /// The username contains `:`, which would move the split between username and password (RFC 7617 §2).
    #[error("basic credential username contains ':'")]
    ColonInUsername,
    /// The username or password contains a control character, which RFC 7617 §2 forbids in both.
    #[error("basic credential contains a control character")]
    ControlChar,
}

/// The Basic token as the slot value, with its scrub patterns. A header or query slot would send the token without
/// its scheme, so only a Basic slot accepts it.
pub(crate) fn resolve(
    username: &SecretString,
    password: &SecretString,
    slot: &Slot,
    _request: &AuthorizedRequest,
) -> Result<Resolution, KindError> {
    if !matches!(slot, Slot::Basic) {
        return Err(KindError::SlotMismatch { kind: KIND, slot: slot_kind(slot) });
    }
    let (username, password) = (username.expose_secret(), password.expose_secret());
    validate(username, password)?;
    let user_pass = join(&[username, ":", password]);
    let value = SlotValue::new(SecretString::from(STANDARD.encode(user_pass.as_bytes())))?;
    let patterns = scrub_patterns(value.expose_secret(), &user_pass, password);
    Ok(Resolution::new(value, patterns))
}

/// Checks a username and password against RFC 7617 §2 without building a token.
pub(crate) fn validate(username: &str, password: &str) -> Result<(), BasicCredentialError> {
    if username.is_empty() {
        Err(BasicCredentialError::EmptyUsername)
    } else if username.contains(':') {
        Err(BasicCredentialError::ColonInUsername)
    } else if username.chars().chain(password.chars()).any(char::is_control) {
        Err(BasicCredentialError::ControlChar)
    } else {
        Ok(())
    }
}

/// Every form an upstream may echo: the token, the complete header value, the `user:pass` pair and the password. The
/// username alone is left out: it is usually an email address or account ID, and scrubbing it would corrupt ordinary
/// responses.
fn scrub_patterns(token: &str, user_pass: &str, password: &str) -> ScrubPatterns {
    let mut patterns = ScrubPatterns::default();
    patterns.insert(copy(token.as_bytes()));
    patterns.insert(copy(join(&[SCHEME_PREFIX, token]).as_bytes()));
    patterns.insert_url_forms(user_pass);
    patterns.insert_url_forms(password);
    patterns
}

/// `parts` concatenated into a buffer sized exactly, so building it never reallocates and leaves no unwiped copy.
fn join(parts: &[&str]) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(parts.iter().map(|part| part.len()).sum()));
    parts.iter().for_each(|part| out.push_str(part));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn patterns(user_pass: &str, password: &str) -> Vec<String> {
        let token = STANDARD.encode(user_pass);
        scrub_patterns(&token, user_pass, password).iter().map(|p| String::from_utf8(p.to_vec()).unwrap()).collect()
    }

    #[test]
    fn rfc_7617_example_token() {
        assert_eq!(STANDARD.encode(join(&["Aladdin", ":", "open sesame"]).as_bytes()), "QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
    }

    #[test]
    fn username_rules_name_the_rule_only() {
        assert_eq!(validate("", "QZJW"), Err(BasicCredentialError::EmptyUsername));
        assert_eq!(validate("QZ:JW", "x"), Err(BasicCredentialError::ColonInUsername));
    }

    #[test]
    fn control_characters_are_refused_in_either_field() {
        [("QZ\nJW", "x"), ("u", "QZ\nJW"), ("u", "QZ\rJW"), ("u", "QZ\0JW"), ("u\t", "p"), ("u", "\u{85}")]
            .iter()
            .for_each(|(username, password)| assert_eq!(validate(username, password), Err(BasicCredentialError::ControlChar)));
    }

    #[test]
    fn empty_password_and_non_ascii_are_accepted() {
        assert_eq!(validate("u", ""), Ok(()));
        assert_eq!(validate("ünï", "pässwörd"), Ok(()));
    }

    #[test]
    fn pattern_set_holds_every_form_and_not_the_username() {
        let found = patterns("alice@example.com:p/w", "p/w");
        let token = "YWxpY2VAZXhhbXBsZS5jb206cC93";
        [
            token.to_owned(),
            format!("Basic {token}"),
            "alice@example.com:p/w".to_owned(),
            "alice%40example.com%3Ap%2Fw".to_owned(),
            "alice%40example.com%3ap%2fw".to_owned(),
            "p/w".to_owned(),
            "p%2Fw".to_owned(),
            "p%2fw".to_owned(),
        ]
        .iter()
        .for_each(|expected| assert!(found.contains(expected), "{expected} missing from {found:?}"));
        assert_eq!(found.len(), 8, "{found:?}");
        assert!(!found.iter().any(|f| f == "alice@example.com" || f == "alice%40example.com"), "{found:?}");
    }
}
