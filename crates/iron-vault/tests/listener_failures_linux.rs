// SPDX-License-Identifier: MPL-2.0
//! `status` lists each approved listener that did not open, with a fixed reason (specification §15, §16;
//! `design/admin-protocol.md#status`), and an approval that fixes or removes the listener clears the entry.

#![cfg(target_os = "linux")]
// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;

use common::approval_harness::{APPROVAL_PASSPHRASE, Fixture, approve, get};
use common::proxy_harness::{TOKEN_BYTES, token_hash};
use common::tls_dir::TlsDir;
use iron_vault::admin::protocol::{AdminResponse, ApprovalResult};
use iron_vault::listener_failure::{ListenerFailure, ListenerFailureReason};
use iron_vault::service_context::ServiceContext;
use iron_vault::service_state::ServiceState;

/// The fixture's config with the TLS listener `wide` on these files.
fn config_with_wide(fixture: &Fixture, tls: &TlsDir) -> String {
    format!(
        "{}\n[listeners.wide]\naddress = \"0.0.0.0:{port}\"\ntls_certificate = \"{crt}\"\ntls_key = \"{key}\"\n\n\
         [callers.wide-caller]\nlistener = \"wide\"\ntoken_hash = \"{hash}\"\nroutes = [\"fx\"]\n",
        fixture.config("fx"),
        port = common::proxy_harness::next_free_port(),
        crt = tls.path("server.crt").display(),
        key = tls.path("server.key").display(),
        hash = token_hash(TOKEN_BYTES),
    )
}

async fn approve_config(service: &Arc<ServiceContext>, config: &str) {
    let approved = approve(service, config, &["yes", APPROVAL_PASSPHRASE]).await;
    assert!(
        matches!(approved.response, AdminResponse::ConfigApprove(ApprovalResult { .. })),
        "{approved:?}"
    );
}

async fn failures(service: &Arc<ServiceContext>) -> Vec<ListenerFailure> {
    let report = service.status().await;
    assert_eq!(report.state, ServiceState::Ready);
    report.listener_failures
}

fn wide_mismatch() -> Vec<ListenerFailure> {
    vec![ListenerFailure {
        name: "wide".parse().unwrap(),
        reason: ListenerFailureReason::TlsKeyMismatch,
    }]
}

/// The good listener serves, `status` is Ready and lists the bad listener; an approval after the key is fixed clears it.
#[tokio::test]
async fn an_approval_that_fixes_the_key_clears_the_listed_failure() {
    let (fixture, tls) = (Fixture::new().await, TlsDir::new("fix", false, 0o600));
    let service = fixture.ready().await;
    assert!(failures(&service).await.is_empty());

    approve_config(&service, &config_with_wide(&fixture, &tls)).await;
    assert_eq!(failures(&service).await, wide_mismatch());
    assert_eq!(get(&fixture, "fx").await.status, 200);

    tls.fix_key();
    approve_config(&service, &config_with_wide(&fixture, &tls)).await;
    assert!(failures(&service).await.is_empty());
}

/// An approval that removes the failed listener from the config clears its entry.
#[tokio::test]
async fn an_approval_that_removes_the_failed_listener_clears_the_listed_failure() {
    let (fixture, tls) = (Fixture::new().await, TlsDir::new("remove", false, 0o600));
    let service = fixture.ready().await;
    approve_config(&service, &config_with_wide(&fixture, &tls)).await;
    assert_eq!(failures(&service).await, wide_mismatch());

    approve_config(&service, &fixture.config("fx")).await;
    assert!(failures(&service).await.is_empty());
}
