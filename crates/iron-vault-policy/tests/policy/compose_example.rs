//! The Compose reference config (`packaging/compose/config.example.toml`) passes the policy's approval-time checks,
//! so an administrator who starts from it is not refused for the isolated-network rule.

use iron_vault_policy::{CallerAuth, Endpoint, ParsedConfig, ValidatedConfig};

const EXAMPLE: &str = include_str!("../../../../packaging/compose/config.example.toml");

fn validated() -> ValidatedConfig {
    ValidatedConfig::try_from(ParsedConfig::from_toml(EXAMPLE.as_bytes()).unwrap()).unwrap()
}

#[test]
fn every_caller_is_isolated_network() {
    let config = validated();
    assert_eq!(config.callers().len(), 2);
    assert!(config.callers().values().all(|c| matches!(c.auth(), CallerAuth::IsolatedNetwork)));
}

#[test]
fn every_listener_is_a_tls_address_on_its_own_caller_address() {
    let config = validated();
    let addresses: Vec<_> = config
        .listeners()
        .values()
        .map(|l| match l.endpoint() {
            Endpoint::Tcp { address, tls: Some(_) } => *address,
            other => panic!("listener is not a TLS address: {other:?}"),
        })
        .collect();
    assert_eq!(addresses.len(), 2);
    assert_ne!(addresses[0].ip(), addresses[1].ip());
}
