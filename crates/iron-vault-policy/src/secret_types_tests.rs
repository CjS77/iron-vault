//! Compile-time and `Debug` checks for this crate's secret-bearing types (spec §3.11, `design/secret-handling.md`).
//!
//! A type that gains `Clone`, `Copy`, `Display` or a serde impl would start copying, printing or writing the secret it
//! holds; each assertion below turns that change into a build failure. A trait a type legitimately has is left out of
//! its assertion, with the reason beside it.

use std::collections::BTreeSet;
use std::fmt::Display;

use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use static_assertions::assert_not_impl_any;

use crate::activation::{ActivePolicy, Capabilities, CatalogEntry, CredentialCatalog, activate};
use crate::spec_example::SPEC_EXAMPLE;
use crate::{
    AuthorizedRequest, CheckedRequest, CredentialKind, CredentialName, HeaderName, HeaderValue, Host, Method, OutgoingHeaders,
    OutgoingRequest, ParsedConfig, Port, RequestTarget, Slot, SlotValue, UpstreamTarget, ValidatedConfig, authorize, final_check,
};

assert_not_impl_any!(SlotValue: Clone, Copy, Display, Serialize, Deserialize<'static>);
assert_not_impl_any!(OutgoingRequest: Clone, Copy, Display, Serialize, Deserialize<'static>);
assert_not_impl_any!(CheckedRequest: Clone, Copy, Display, Serialize, Deserialize<'static>);

// `Clone` is derived on the three below and is not asserted: a clone is a second buffer with the same wipe-on-drop
// (`HeaderValue`'s `Drop`), so it adds a copy but never an unwiped one. Whether the derives can go is a separate
// ticket; no production code clones them today.
assert_not_impl_any!(HeaderValue: Copy, Display, Serialize, Deserialize<'static>);
assert_not_impl_any!(OutgoingHeaders: Copy, Display, Serialize, Deserialize<'static>);
// `UpstreamTarget` holds the filled query in a `url::Url`, which is never wiped: see the residual copies in
// `design/secret-handling.md`.
assert_not_impl_any!(UpstreamTarget: Copy, Display, Serialize, Deserialize<'static>);

/// Distinctive enough that a match in `Debug` output can only be the secret leaking.
const MARKER: &str = "MARKER-secret-5d1c9e";

/// Both `Debug` forms of `value`.
fn debug_forms(value: &impl std::fmt::Debug) -> [String; 2] {
    [format!("{value:?}"), format!("{value:#?}")]
}

fn assert_redacted(value: &impl std::fmt::Debug) {
    debug_forms(value).iter().for_each(|debug| assert!(!debug.contains(MARKER), "{debug}"));
}

#[test]
fn slot_value_debug_hides_the_secret() {
    assert_redacted(&SlotValue::new(SecretString::from(MARKER)).unwrap());
}

#[test]
fn header_value_debug_hides_the_secret() {
    assert_redacted(&HeaderValue::try_from(MARKER).unwrap());
}

#[test]
fn outgoing_headers_debug_hides_every_value() {
    let mut headers = OutgoingHeaders::new();
    headers.insert("Authorization".parse::<HeaderName>().unwrap(), HeaderValue::try_from(MARKER).unwrap()).unwrap();
    assert_redacted(&headers);
}

/// Permits every §3.3 credential on its route's host at 443.
struct Catalog;

impl CredentialCatalog for Catalog {
    fn entry(&self, name: &CredentialName) -> CatalogEntry {
        CatalogEntry::Usable { kind: CredentialKind::Static, origins: origins(name) }
    }
}

fn origins(credential: &CredentialName) -> BTreeSet<(Host, Port)> {
    let host = match credential.as_str() {
        "fx_key" => "api.fx.example",
        "venice" => "api.venice.ai",
        _ => "api.search.brave.com",
    };
    [(host.parse().unwrap(), Port::HTTPS)].into()
}

fn policy() -> ActivePolicy {
    let config = ValidatedConfig::try_from(ParsedConfig::from_toml(SPEC_EXAMPLE.as_bytes()).unwrap()).unwrap();
    activate(&config, &Capabilities::default(), &Catalog).unwrap()
}

/// One §3.3 request through every stage that holds the marker: `target` is authorized for `caller`, built, assembled
/// with the route's slot filled with [`MARKER`], and final-checked.
struct Pipeline {
    policy: ActivePolicy,
    authorized: AuthorizedRequest,
}

impl Pipeline {
    fn new(caller: &str, target: &str) -> Self {
        let policy = policy();
        let (path, query) = RequestTarget::parse(target).unwrap().into_parts();
        let authorized = authorize(&policy, &caller.parse().unwrap(), &Method::Get, &path, query).unwrap();
        Self { policy, authorized }
    }

    fn target(&self) -> UpstreamTarget {
        UpstreamTarget::build(self.policy.config().routes()[self.authorized.route()].upstream(), &self.authorized).unwrap()
    }

    fn slot(&self) -> &Slot {
        self.policy.config().routes()[self.authorized.route()].slot()
    }

    fn assembled(&self, value: &SlotValue) -> OutgoingRequest {
        let route = &self.policy.config().routes()[self.authorized.route()];
        OutgoingRequest::assemble(&self.authorized, self.target(), OutgoingHeaders::new(), route.slot(), route.credential(), value)
            .unwrap()
    }

    fn checked(&self) -> CheckedRequest {
        let route = &self.policy.config().routes()[self.authorized.route()];
        let value = SlotValue::new(SecretString::from(MARKER)).unwrap();
        final_check(self.assembled(&value), &self.authorized, route.upstream(), self.slot(), &value, &origins(route.credential()))
            .unwrap()
    }
}

/// The fx route fills a query slot; the brave route fills a header slot.
fn pipelines() -> [Pipeline; 2] {
    [Pipeline::new("fx-mcp", "/fx/latest?base=USD"), Pipeline::new("naomi-backoffice", "/brave/res/v1/web/search")]
}

#[test]
fn upstream_target_debug_hides_a_secret_in_the_query() {
    assert_redacted(&Pipeline::new("fx-mcp", &format!("/fx/latest?access_key={MARKER}")).target());
}

#[test]
fn outgoing_request_debug_hides_a_filled_query_or_header_slot() {
    let value = SlotValue::new(SecretString::from(MARKER)).unwrap();
    pipelines().iter().for_each(|pipeline| assert_redacted(&pipeline.assembled(&value)));
}

#[test]
fn checked_request_debug_hides_a_filled_query_or_header_slot() {
    pipelines().iter().for_each(|pipeline| assert_redacted(&pipeline.checked()));
}
