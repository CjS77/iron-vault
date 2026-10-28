//! The kind boundary: credential material in, slot value and scrub patterns out (spec §5.2).

use iron_vault_policy::{AuthorizedRequest, Slot, SlotValue, SlotValueError};
use thiserror::Error;

use crate::material::CredentialMaterial;
use crate::scrub::ScrubPatterns;
use crate::static_kind;

/// What a kind produced for one request: the value for the route's slot and the forms of it to scrub.
///
/// The two travel together so that the scrubber always watches for exactly the secret that was injected.
#[derive(Debug)]
pub struct Resolution {
    value: SlotValue,
    patterns: ScrubPatterns,
}

/// Why a kind could not produce a slot value. No variant carries secret bytes, so the error is safe to log.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum KindError {
    /// The credential's kind cannot fill this kind of slot, such as a static key on a Basic slot.
    #[error("a {kind} credential cannot fill a {slot} slot")]
    SlotMismatch {
        /// The credential's kind.
        kind: &'static str,
        /// The slot's kind.
        slot: &'static str,
    },
    /// The produced value cannot be placed in a slot; the inner error names the rule, never the value.
    #[error(transparent)]
    InvalidValue(#[from] SlotValueError),
}

impl Resolution {
    pub(crate) fn new(value: SlotValue, patterns: ScrubPatterns) -> Self {
        Self { value, patterns }
    }

    /// The bare value for the slot, before the slot's format or encoding is applied.
    pub fn value(&self) -> &SlotValue {
        &self.value
    }

    /// The forms of the injected secret response scrubbing must remove.
    pub fn patterns(&self) -> &ScrubPatterns {
        &self.patterns
    }

    /// Splits the resolution so slot filling can consume the value while the scrubber keeps the patterns.
    pub fn into_parts(self) -> (SlotValue, ScrubPatterns) {
        (self.value, self.patterns)
    }
}

/// Resolves `material` into the value for `slot` and its scrub patterns.
///
/// `request` is the authorized request plan every kind receives (spec §5.2): a static key ignores it, but signing kinds
/// need the final method and path, so the boundary carries it from the start.
pub fn resolve(material: &CredentialMaterial, slot: &Slot, request: &AuthorizedRequest) -> Result<Resolution, KindError> {
    match material {
        CredentialMaterial::Static { key } => static_kind::resolve(key, slot, request),
    }
}

/// The name a slot's kind goes by in errors.
pub(crate) fn slot_kind(slot: &Slot) -> &'static str {
    match slot {
        Slot::Header(_) => "header",
        Slot::Query(_) => "query",
        Slot::Basic => "basic",
    }
}

#[cfg(test)]
mod tests {
    use iron_vault_policy::{
        ActivePolicy, Capabilities, CatalogEntry, CredentialCatalog, CredentialName, Method, ParsedConfig, Port, RequestTarget,
        ValidatedConfig, activate, authorize,
    };
    use secrecy::{ExposeSecret, SecretString};

    use super::*;

    /// The §3.3 FX and Brave routes, plus a Basic route to show a static key refused there.
    const CONFIG: &str = r#"schema_version = 1

[listeners.local]
unix_socket = "/run/iron-vault/proxy.sock"

[callers.agent]
listener = "local"
token_hash = "blake2b:0123456789abcdef00112233445566778899aabbccddeeff0f1e2d3c4b5a6978"
routes = ["fx", "brave", "basic"]

[routes.fx]
prefix = "/fx"
upstream = "https://api.fx.example"
credential = "fx_key"
slot = { query = "access_key" }
methods = ["GET"]
paths = ["/**"]
rate_limit = { requests = 60, per_seconds = 60, burst = 10 }

[routes.brave]
prefix = "/brave"
upstream = "https://api.search.brave.com"
credential = "brave"
slot = { header = "X-Subscription-Token" }
methods = ["GET"]
paths = ["/**"]
rate_limit = { requests = 60, per_seconds = 60, burst = 10 }

[routes.basic]
prefix = "/basic"
upstream = "https://basic.example"
credential = "basic"
slot = "basic"
methods = ["GET"]
paths = ["/**"]
rate_limit = { requests = 60, per_seconds = 60, burst = 10 }
"#;

    struct Catalog;

    impl CredentialCatalog for Catalog {
        fn entry(&self, name: &CredentialName) -> CatalogEntry {
            let host = match name.as_str() {
                "fx_key" => "api.fx.example",
                "brave" => "api.search.brave.com",
                _ => "basic.example",
            };
            CatalogEntry::Usable { origins: [(host.parse().unwrap(), Port::HTTPS)].into() }
        }
    }

    fn policy() -> ActivePolicy {
        let config = ValidatedConfig::try_from(ParsedConfig::from_toml(CONFIG.as_bytes()).unwrap()).unwrap();
        activate(&config, &Capabilities::default(), &Catalog).unwrap()
    }

    fn resolve_on(target: &str, key: &str) -> Result<Resolution, KindError> {
        let policy = policy();
        let (path, query) = RequestTarget::parse(target).unwrap().into_parts();
        let request = authorize(&policy, &"agent".parse().unwrap(), &Method::Get, &path, query).unwrap();
        let slot = policy.route(request.route()).unwrap().slot();
        resolve(&CredentialMaterial::Static { key: SecretString::from(key) }, slot, &request)
    }

    #[test]
    fn fx_query_slot_resolves_to_the_stored_key() {
        let resolution = resolve_on("/fx/latest?base=USD", "fx-secret-1").unwrap();
        assert_eq!(resolution.value().expose_secret(), "fx-secret-1");
        assert!(resolution.patterns().iter().any(|p| p == b"fx-secret-1"));
    }

    #[test]
    fn brave_header_slot_resolves_to_the_stored_key() {
        let (value, patterns) = resolve_on("/brave/res/v1/web/search", "BSA-key").unwrap().into_parts();
        assert_eq!(value.expose_secret(), "BSA-key");
        assert!(!patterns.is_empty());
    }

    #[test]
    fn static_key_on_basic_slot_is_a_mismatch() {
        let err = resolve_on("/basic/x", "k").unwrap_err();
        assert_eq!(err, KindError::SlotMismatch { kind: "static", slot: "basic" });
        assert_eq!(err.to_string(), "a static credential cannot fill a basic slot");
    }

    #[test]
    fn key_with_cr_or_lf_is_refused_naming_the_rule_only() {
        ["QZJW\r\nX-Evil: 1", "QZJW\nKV", "QZJW\rKV"].iter().for_each(|key| {
            let err = resolve_on("/brave/x", key).unwrap_err();
            assert_eq!(err, KindError::InvalidValue(SlotValueError::ControlChar));
            let text = format!("{err} {err:?}");
            assert!(!text.contains("QZJW") && !text.contains("Evil"), "{text}");
        });
    }

    #[test]
    fn empty_key_is_refused() {
        assert_eq!(resolve_on("/fx/latest", "").unwrap_err(), KindError::InvalidValue(SlotValueError::Empty));
    }

    #[test]
    fn key_with_reserved_characters_yields_all_scrub_forms() {
        let resolution = resolve_on("/fx/latest", "a/b+c=d").unwrap();
        let found: Vec<&[u8]> = resolution.patterns().iter().collect();
        [&b"a/b+c=d"[..], b"a%2Fb%2Bc%3Dd", b"a%2fb%2bc%3dd", b"YS9iK2M9ZA==", b"YS9iK2M9ZA"]
            .iter()
            .for_each(|expected| assert!(found.contains(expected), "{expected:?}"));
    }

    #[test]
    fn debug_output_holds_no_secret_byte() {
        let key = "QZJWX";
        let material = CredentialMaterial::Static { key: SecretString::from(key) };
        let resolution = resolve_on("/fx/latest", key).unwrap();
        let debug = format!("{material:?} {resolution:?} {:?}", resolution.patterns());
        assert!(!debug.chars().any(|c| key.contains(c)), "{debug}");
    }
}
