//! The configuration reference's annotated example (`book/src/reference/configuration-example.toml`) must stay a
//! valid configuration, and must keep showing every table and every kind of listener, caller and slot the reference
//! describes.

use iron_vault_policy::{CallerAuth, Endpoint, Limits, ParsedConfig, Slot, ValidatedConfig};

/// The file the book includes, read at build time so the test and the page can never drift apart.
const EXAMPLE: &str = include_str!("../../../../book/src/reference/configuration-example.toml");

fn example() -> ValidatedConfig {
    ValidatedConfig::try_from(ParsedConfig::from_toml(EXAMPLE.as_bytes()).unwrap()).unwrap()
}

#[test]
fn the_reference_example_parses_and_validates() {
    let config = example();
    assert_eq!(config.listeners().len(), 3);
    assert_eq!(config.callers().len(), 4);
    assert_eq!(config.routes().len(), 5);
}

#[test]
fn the_reference_example_sets_every_service_wide_table() {
    let config = example();
    assert_ne!(config.limits(), &Limits::default());
    assert!(config.log_destination().is_some());
    assert!(config.recovery_reminder().is_some());
}

#[test]
fn the_reference_example_shows_every_listener_and_caller_kind() {
    let config = example();
    let listeners: Vec<_> = config.listeners().values().collect();
    assert!(listeners.iter().any(|l| matches!(l.endpoint(), Endpoint::UnixSocket(_))));
    assert!(listeners.iter().any(|l| matches!(l.endpoint(), Endpoint::Tcp { tls: None, .. })));
    assert!(listeners.iter().any(|l| matches!(l.endpoint(), Endpoint::Tcp { tls: Some(_), .. })));
    assert!(listeners.iter().any(|l| l.token_header().is_some()));
    let callers: Vec<_> = config.callers().values().collect();
    assert!(callers.iter().any(|c| matches!(c.auth(), CallerAuth::Token(_))));
    assert!(callers.iter().any(|c| matches!(c.auth(), CallerAuth::Peer(_))));
    assert!(callers.iter().any(|c| matches!(c.auth(), CallerAuth::IsolatedNetwork)));
    assert!(callers.iter().any(|c| !c.rate_limits().is_empty()));
}

#[test]
fn the_reference_example_shows_every_slot_kind_and_route_option() {
    let config = example();
    let routes: Vec<_> = config.routes().values().collect();
    let header_with_format = |slot: &Slot| matches!(slot, Slot::Header(h) if !h.format().prefix().is_empty());
    let bare_header = |slot: &Slot| matches!(slot, Slot::Header(h) if h.format().prefix().is_empty());
    assert!(routes.iter().any(|r| header_with_format(r.slot())));
    assert!(routes.iter().any(|r| bare_header(r.slot())));
    assert!(routes.iter().any(|r| matches!(r.slot(), Slot::Query(_))));
    assert!(routes.iter().any(|r| matches!(r.slot(), Slot::Basic)));
    assert!(routes.iter().any(|r| r.ca_file().is_some()));
    assert!(routes.iter().any(|r| !r.upstream().base_segments().is_empty()));
}
