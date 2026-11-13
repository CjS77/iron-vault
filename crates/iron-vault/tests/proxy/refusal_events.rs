// SPDX-License-Identifier: MPL-2.0
//! An unusable approval passphrase (empty input) is answered as a wrong one, and each path that does so writes exactly one
//! refusal event with `wrong_passphrase` (design/admin-protocol.md; design/audit-logging.md): `config.approval-refused`
//! with the config's digest for `config approve`, and `vault.presence-refused` without one for `rm`.

#![cfg(target_os = "linux")]

use crate::common;

use common::approval_harness::{
    APPROVAL_PASSPHRASE, Fixture, WRONG_PASSPHRASE, approve, assert_audit_record, assert_names_approver, captured_logs, converse,
    error_code, send, serve_admin,
};
use iron_vault::admin::protocol::{AdminRequest, ErrorCode, Frame};
use iron_vault_kinds::CredentialMaterial;
use iron_vault_policy::Port;
use iron_vault_store::{ConfigDigest, PermittedOrigins};

#[tokio::test]
async fn an_unusable_approval_passphrase_on_config_approve_writes_one_refusal_with_the_digest() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    let approver = fixture.approver_id();
    let service = fixture.ready().await;
    let proposed = fixture.config("unusable");

    let exchanged = approve(&service, &proposed, &["yes", ""]).await;

    assert_eq!(error_code(&exchanged.response), ErrorCode::ApprovalDenied);
    let digest = ConfigDigest::of(proposed.as_bytes()).to_string();
    let refused: Vec<_> = logs
        .events("config.approval-refused")
        .into_iter()
        .filter(|record| record["config_digest"] == digest.as_str())
        .collect();
    assert_eq!(refused.len(), 1, "{}", logs.text());
    assert_audit_record(&refused[0], "WARN", &["refusal", "config_digest", "approver_id", "approver_label"]);
    assert_eq!(refused[0]["refusal"], "wrong_passphrase");
    assert_names_approver(&refused[0], approver);
    logs.assert_no_passphrase();
}

/// One test, because the shared log holds every `vault.presence-refused` of this binary and the count is the point: an
/// unusable passphrase and a typed wrong one each add exactly one, and neither carries a digest.
#[tokio::test]
async fn an_unusable_and_a_wrong_passphrase_on_rm_each_write_one_presence_refusal() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    let approver = fixture.approver_id();
    let service = fixture.ready().await;
    let origins = PermittedOrigins::new([("old.example".parse().unwrap(), Port::HTTPS)].into()).unwrap();
    let material = CredentialMaterial::Static { key: "old-secret".into() };
    service.add_credential("old_key".parse().unwrap(), material, origins).await.unwrap();
    let (path, stop) = serve_admin(&service);

    for (answer, expected_records) in [("", 1), (WRONG_PASSPHRASE, 2)] {
        let mut stream = tokio::net::UnixStream::connect(&path).await.unwrap();
        send(
            &mut stream,
            &Frame::Request(AdminRequest::Rm {
                name: "old_key".to_owned(),
            }),
        )
        .await;
        let exchanged = converse(&mut stream, &[answer]).await;
        assert_eq!(error_code(&exchanged.response), ErrorCode::ApprovalDenied);
        let records = logs.events("vault.presence-refused");
        assert_eq!(records.len(), expected_records, "{}", logs.text());
        let record = &records[expected_records - 1];
        assert_audit_record(record, "WARN", &["refusal", "approver_id", "approver_label"]);
        assert_eq!(record["refusal"], "wrong_passphrase");
        assert_names_approver(record, approver);
    }
    logs.assert_no_passphrase();
    assert!(!logs.text().contains(APPROVAL_PASSPHRASE));
    let _ = stop.send(());
}
