//! The kind boundary: credential material in, slot value and scrub patterns out (spec §5.2).

use iron_vault_policy::{AuthorizedRequest, Slot, SlotValue, SlotValueError};
use thiserror::Error;

use crate::basic_kind::{self, BasicCredentialError};
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
    /// A Basic credential's username or password breaks an RFC 7617 rule; the inner error names the rule, never the
    /// value.
    #[error(transparent)]
    InvalidBasic(#[from] BasicCredentialError),
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
        CredentialMaterial::Basic { username, password } => basic_kind::resolve(username, password, slot, request),
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
        ActivationError, ActivePolicy, Capabilities, CatalogEntry, CredentialCatalog, CredentialKind, CredentialName, Method,
        ParsedConfig, Port, RequestTarget,
        ValidatedConfig, activate, authorize,
    };
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
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

    /// Each credential's record, of the kind `kind` gives it, permitting its route's upstream.
    struct Catalog(fn(&CredentialName) -> CredentialKind);

    impl CredentialCatalog for Catalog {
        fn entry(&self, name: &CredentialName) -> CatalogEntry {
            let host = match name.as_str() {
                "fx_key" => "api.fx.example",
                "brave" => "api.search.brave.com",
                _ => "basic.example",
            };
            CatalogEntry::Usable { kind: (self.0)(name), origins: [(host.parse().unwrap(), Port::HTTPS)].into() }
        }
    }

    /// The kind each route's slot suits: Basic for the Basic route, static otherwise.
    fn natural_kind(name: &CredentialName) -> CredentialKind {
        match name.as_str() {
            "basic" => CredentialKind::Basic,
            _ => CredentialKind::Static,
        }
    }

    fn policy() -> ActivePolicy {
        let config = ValidatedConfig::try_from(ParsedConfig::from_toml(CONFIG.as_bytes()).unwrap()).unwrap();
        activate(&config, &Capabilities::default(), &Catalog(natural_kind)).unwrap()
    }

    fn resolve_material(target: &str, material: &CredentialMaterial) -> Result<Resolution, KindError> {
        let policy = policy();
        let (path, query) = RequestTarget::parse(target).unwrap().into_parts();
        let request = authorize(&policy, &"agent".parse().unwrap(), &Method::Get, &path, query).unwrap();
        let slot = policy.route(request.route()).unwrap().slot();
        resolve(material, slot, &request)
    }

    fn resolve_on(target: &str, key: &str) -> Result<Resolution, KindError> {
        resolve_material(target, &CredentialMaterial::Static { key: SecretString::from(key) })
    }

    fn basic(username: &str, password: &str) -> CredentialMaterial {
        CredentialMaterial::Basic { username: SecretString::from(username), password: SecretString::from(password) }
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

    #[test]
    fn rfc_7617_example_resolves_to_its_token() {
        let resolution = resolve_material("/basic/x", &basic("Aladdin", "open sesame")).unwrap();
        assert_eq!(resolution.value().expose_secret(), "QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
        assert!(resolution.patterns().iter().any(|p| p == b"Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="));
    }

    #[test]
    fn non_ascii_password_round_trips_as_utf8() {
        let resolution = resolve_material("/basic/x", &basic("josé", "pässwörd ☃")).unwrap();
        let decoded = STANDARD.decode(resolution.value().expose_secret()).unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "josé:pässwörd ☃");
    }

    #[test]
    fn invalid_basic_fields_are_refused_naming_the_rule_only() {
        [
            (basic("QZ:JW", "KV"), BasicCredentialError::ColonInUsername),
            (basic("", "QZJW"), BasicCredentialError::EmptyUsername),
            (basic("QZJW", "KV\nQX"), BasicCredentialError::ControlChar),
        ]
        .iter()
        .for_each(|(material, expected)| {
            let err = resolve_material("/basic/x", material).unwrap_err();
            assert_eq!(err, KindError::InvalidBasic(expected.clone()));
            let text = format!("{err} {err:?}");
            assert!(!text.chars().any(|c| "QZJWKVX\n".contains(c)), "{text}");
        });
    }

    #[test]
    fn basic_credential_on_header_or_query_slot_is_a_mismatch() {
        [("/brave/x", "header"), ("/fx/latest", "query")].iter().for_each(|(target, slot)| {
            let err = resolve_material(target, &basic("u", "p")).unwrap_err();
            assert_eq!(err, KindError::SlotMismatch { kind: "basic", slot });
        });
    }

    #[test]
    fn basic_debug_output_holds_no_secret_byte() {
        let material = basic("QZJW", "XKVQ");
        let resolution = resolve_material("/basic/x", &material).unwrap();
        let debug = format!("{material:?} {resolution:?} {:?}", resolution.patterns());
        let token = resolution.value().expose_secret();
        assert!(["QZJW", "XKVQ", token].iter().all(|secret| !debug.contains(secret)), "{debug}");
    }

    /// Routes `activate` refuses when every credential is of `kind`.
    fn refused_at_activation(kind: fn(&CredentialName) -> CredentialKind) -> Vec<String> {
        let config = ValidatedConfig::try_from(ParsedConfig::from_toml(CONFIG.as_bytes()).unwrap()).unwrap();
        let errors = activate(&config, &Capabilities::default(), &Catalog(kind)).err().unwrap_or_default();
        errors
            .iter()
            .map(|err| match err {
                ActivationError::SlotMismatch { route, .. } => route.as_str().to_owned(),
                other => panic!("unexpected {other}"),
            })
            .collect()
    }

    /// Routes `resolve` refuses for `material` with a slot mismatch.
    fn refused_at_resolve(material: &CredentialMaterial) -> Vec<String> {
        [("basic", "/basic/x"), ("brave", "/brave/x"), ("fx", "/fx/latest")]
            .iter()
            .filter(|(_, target)| matches!(resolve_material(target, material), Err(KindError::SlotMismatch { .. })))
            .map(|(route, _)| (*route).to_owned())
            .collect()
    }

    #[test]
    fn activation_refuses_exactly_the_pairings_resolve_refuses() {
        let static_key = CredentialMaterial::Static { key: SecretString::from("k") };
        assert_eq!(refused_at_activation(|_| CredentialKind::Static), refused_at_resolve(&static_key));
        assert_eq!(refused_at_activation(|_| CredentialKind::Basic), refused_at_resolve(&basic("u", "p")));
        assert_eq!(refused_at_activation(|_| CredentialKind::Static), ["basic"]);
        assert_eq!(refused_at_activation(|_| CredentialKind::Basic), ["brave", "fx"]);
    }
}
