// SPDX-License-Identifier: MPL-2.0
//! The twelfth v0 release check (specification §19): "Locked startup, invalid policy, TLS failures, unsafe listener
//! configurations, and ownership failures produce explicit safe states."
//!
//! Here, the upstream TLS failures through the proxy and the approval that refuses a plain-HTTP listener off loopback.
//! The listener failures at service start are in `service_context_linux.rs`, beside its `assert_safe_state`.

#![cfg(target_os = "linux")]

use crate::common;

use common::approval_harness::{APPROVAL_PASSPHRASE, Fixture, approve, get, versions};
use common::mock_upstream::{MockUpstream, Reply, TestCa, UPSTREAM_HOST};
use common::proxy_harness::{Credential, Proxy, Setup, TOKEN_BYTES, next_free_port, token_hash};
use common::request_log::capture;
use iron_vault::admin::protocol::{AdminResponse, ErrorCode};
use iron_vault::service_state::ServiceState;
use iron_vault_kinds::CredentialMaterial;

const SECRET: &str = "fx-secret-tls-5e7a";

/// One token caller granted `fx`, which sends `fx_key` in `X-Api-Key` to `localhost:port`, pinning the test CA.
fn callers_and_routes(port: u16) -> String {
    format!(
        "[callers.agent]\nlistener = \"local\"\ntoken_hash = \"{hash}\"\nroutes = [\"fx\"]\n\n[routes.fx]\nprefix = \"/fx\"\n\
         upstream = \"https://localhost:{port}/v1\"\nca_file = \"/etc/iron-vault/ca/test.pem\"\ncredential = \"fx_key\"\n\
         slot = {{ header = \"X-Api-Key\" }}\nmethods = [\"GET\"]\npaths = [\"/**\"]\n\
         rate_limit = {{ requests = 1000, per_seconds = 1, burst = 1000 }}\n",
        hash = token_hash(TOKEN_BYTES),
    )
}

/// Sends the caller's `GET /fx/latest` through a proxy that pins `pinned` to an upstream presenting `presented`, and
/// asserts the documented TLS failure: a `502`, a request event with reason `upstream_tls`, and an upstream that
/// accepted the connection but recorded no request, so the credential was never written.
async fn assert_tls_failure_sends_nothing(pinned: &TestCa, presented: std::sync::Arc<rustls::ServerConfig>) {
    let (_guard, log) = capture();
    let upstream = MockUpstream::start_with(presented, Reply::ok("served")).await;
    let proxy = Proxy::start(Setup {
        ca: pinned,
        callers_and_routes: callers_and_routes(upstream.port()),
        credentials: vec![Credential {
            name: "fx_key",
            material: CredentialMaterial::Static { key: SECRET.into() },
            port: upstream.port(),
        }],
        tcp: false,
        request_timeout_secs: 30,
        limits: "",
    })
    .await;

    let response = proxy.get("/fx/latest").await;

    assert_eq!((response.status, response.body.as_str()), (502, "bad gateway"));
    let event = log.the_request_event().await;
    assert_eq!(
        (event["outcome"].as_str(), event["reason"].as_str(), event["status"].as_u64()),
        (Some("failure"), Some("upstream_tls"), Some(502)),
        "{event}"
    );
    assert_eq!(
        (event["route"].as_str(), event["upstream_host"].as_str()),
        (Some("fx"), Some(UPSTREAM_HOST))
    );
    assert!(
        upstream.connections() >= 1,
        "the handshake was never tried, so this is not a TLS failure"
    );
    assert_eq!(
        upstream.requests(),
        [],
        "a request was written over a connection that failed verification"
    );
    assert!(!log.text().contains(SECRET), "the credential reached the log");
}

/// §19: "Locked startup, invalid policy, TLS failures, unsafe listener configurations, and ownership failures produce
/// explicit safe states."
///
/// §10: "The service must verify certificates and hostnames." An upstream whose certificate another CA issued fails the
/// handshake against the route's pinned CA.
#[tokio::test]
async fn an_upstream_certificate_from_another_ca_is_502_upstream_tls_with_nothing_sent() {
    let pinned = TestCa::new("pinned CA");
    let other = TestCa::new("other CA");

    assert_tls_failure_sends_nothing(&pinned, other.server_config(UPSTREAM_HOST)).await;
}

/// §19: "Locked startup, invalid policy, TLS failures, unsafe listener configurations, and ownership failures produce
/// explicit safe states."
///
/// §10: "The service must verify certificates and hostnames." The pinned CA issued the certificate, but for another
/// name than the route's upstream host.
#[tokio::test]
async fn an_upstream_certificate_for_another_name_is_502_upstream_tls_with_nothing_sent() {
    let ca = TestCa::new("pinned CA");

    assert_tls_failure_sends_nothing(&ca, ca.server_config("elsewhere.example")).await;
}

/// §19: "Locked startup, invalid policy, TLS failures, unsafe listener configurations, and ownership failures produce
/// explicit safe states."
///
/// §10: "The service must verify certificates and hostnames." The pinned CA issued the certificate for the route's host,
/// but it has expired.
#[tokio::test]
async fn an_expired_upstream_certificate_is_502_upstream_tls_with_nothing_sent() {
    let ca = TestCa::new("pinned CA");

    assert_tls_failure_sends_nothing(&ca, ca.expired_server_config(UPSTREAM_HOST)).await;
}

/// The message the configuration reference quotes for a plain-HTTP listener off loopback.
const NEEDS_TLS: &str = "needs tls_certificate and tls_key: plain HTTP is allowed only on loopback";

/// §19: "Locked startup, invalid policy, TLS failures, unsafe listener configurations, and ownership failures produce
/// explicit safe states."
///
/// §7: "Every non-loopback listener uses TLS. This is verified at config load." `config approve` refuses a config whose
/// TCP listener on `0.0.0.0` has no TLS files before any prompt, naming the listener, and reserves no version. The
/// service stays Ready on the config it had, and nothing listens on the refused listener's port.
#[tokio::test]
async fn config_approve_refuses_a_plain_http_listener_off_loopback_and_keeps_serving_the_previous_config() {
    let fixture = Fixture::new().await;
    let service = fixture.ready().await;
    let port = next_free_port();
    let plain = format!(
        "{}\n[listeners.wide]\naddress = \"0.0.0.0:{port}\"\n\n[callers.wide-caller]\nlistener = \"wide\"\n\
         token_hash = \"{hash}\"\nroutes = [\"fx\"]\n",
        fixture.config("fx"),
        hash = token_hash([9; 32]),
    );

    let refused = approve(&service, &plain, &["yes", APPROVAL_PASSPHRASE]).await;

    match &refused.response {
        AdminResponse::Error {
            code: ErrorCode::ConfigInvalid,
            message,
        } => assert!(
            message.contains(&format!("listener wide on 0.0.0.0:{port} {NEEDS_TLS}")),
            "{message}"
        ),
        other => panic!("expected config-invalid, got {other:?}"),
    }
    assert!(refused.prompts.is_empty());
    assert_eq!(versions(&service).await, (Some(1), 1));
    assert_eq!(service.status().await.state, ServiceState::Ready);
    let closed = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.map(|_| ()).unwrap_err();
    assert_eq!(closed.kind(), std::io::ErrorKind::ConnectionRefused);
    assert_eq!(get(&fixture, "fx").await.status, 200);
}
