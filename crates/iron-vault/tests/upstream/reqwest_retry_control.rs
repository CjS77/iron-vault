// SPDX-License-Identifier: MPL-2.0
//! The control for the no-retry tests in `upstream_client_h2.rs`: reqwest's default retry policy re-sends a request the
//! HTTP/2 test upstream refused unprocessed, so those tests' refusals are ones reqwest would retry (implementation spec §1).
//!
//! This is the one test file that builds a reqwest client of its own, because its subject is the default policy that
//! `UpstreamClient::new` replaces; `upstream_construction.rs` exempts it by name. The client carries no credential.
//!
//! Linux only: the test upstream terminates TLS with `tokio-rustls`, which this crate depends on only on Linux.

#![cfg(target_os = "linux")]

use crate::common;

use std::sync::Arc;

use common::h2_refusal::Refusal;
use common::mock_upstream::TestCa;
use common::mock_upstream_h2::{H2Reply, MockH2Upstream};

/// A client on reqwest's default retry policy sends a request `refusal` refuses more than once.
async fn assert_default_client_retries(refusal: Refusal) {
    let ca = TestCa::new("Test CA");
    let upstream = MockH2Upstream::start(&ca, H2Reply::Refuse(refusal)).await;
    let mut tls = Arc::unwrap_or_clone(ca.trust().client_config().unwrap());
    tls.alpn_protocols = vec![b"h2".to_vec()];
    // clippy.toml refuses `Client::builder` outside `UpstreamClient::new`; this client exists to show the default
    // retry policy that constructor replaces.
    #[allow(clippy::disallowed_methods)]
    let client = reqwest::Client::builder().use_preconfigured_tls(tls).no_proxy().build().unwrap();

    let sent = client.get(format!("{}/v1/rates", upstream.origin())).send().await;

    assert!(sent.is_err(), "{sent:?}");
    assert!(upstream.request_heads() >= 2, "{} request heads", upstream.request_heads());
}

#[tokio::test]
async fn reqwest_retries_a_refused_stream_by_default() {
    assert_default_client_retries(Refusal::RefusedStream).await;
}

#[tokio::test]
async fn reqwest_retries_an_unprocessed_goaway_by_default() {
    assert_default_client_retries(Refusal::GoAwayUnprocessed).await;
}
