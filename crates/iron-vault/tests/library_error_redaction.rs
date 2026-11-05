//! A reqwest error formats its request URL, so a query-slot credential would reach a log that formatted it; its error
//! kind label must hold nothing of the URL (specification §3.15, `design/audit-logging.md` "Library errors").
//!
//! This test builds a reqwest client of its own, because its subject is the raw `reqwest::Error` that
//! `UpstreamClient` never hands out; `upstream_construction.rs` exempts it by name. The client carries no credential.

// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used)]

use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;

use iron_vault::library_error::LibraryError;
use iron_vault::upstream::trust::UpstreamTrust;

const URL_PARTS: [&str; 5] = ["https", "host", "path", "secret", "VALUE"];

/// A connect error to `https://host:<closed port>/path?secret=VALUE`, with `host` resolved to a closed local port.
async fn connect_error() -> reqwest::Error {
    let closed = TcpListener::bind("127.0.0.1:0").unwrap();
    let address: SocketAddr = closed.local_addr().unwrap();
    drop(closed);
    // clippy.toml refuses `Client::builder` outside `UpstreamClient::new`; this client exists to produce a raw error.
    #[allow(clippy::disallowed_methods)]
    let client = reqwest::Client::builder()
        .use_preconfigured_tls(Arc::unwrap_or_clone(UpstreamTrust::BuiltIn.client_config().unwrap()))
        .resolve("host", address)
        .no_proxy()
        .build()
        .unwrap();
    let url = format!("https://host:{}/path?secret=VALUE", address.port());
    client.get(url).send().await.unwrap_err()
}

#[tokio::test]
async fn a_reqwest_error_renders_without_its_url() {
    let error = connect_error().await;
    assert!(
        error.to_string().contains("VALUE"),
        "the control: reqwest's own text holds the URL: {error}"
    );

    let label = error.kind_label().to_string();

    assert_eq!(label, "connect");
    URL_PARTS
        .iter()
        .for_each(|part| assert!(!label.contains(part), "{label:?} contains {part:?}"));
}
