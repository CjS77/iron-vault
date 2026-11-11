//! `approver list` over a real admin socket (design/approval-signers.md, "`approver list`"): the approvers in approver
//! order, the marker on the signer of the active approval, and the refusal outside Ready.

#![cfg(target_os = "linux")]

use crate::common;

use std::path::Path;
use std::sync::Arc;

use common::approval_harness::{Answer, Fixture, converse_switching, error_code, read_frame, send, serve_admin};
use iron_vault::admin::protocol::{AdminRequest, AdminResponse, ApproverEntry, ErrorCode, Frame, ProposedConfig};
use iron_vault::deployment::DeploymentProfile;
use iron_vault::hardening::MemoryProtection;
use iron_vault::logging::LogSwitch;
use iron_vault::path_metadata::invoking_user;
use iron_vault_store::{ApproverId, OsFs, UtcSecond};

const SECOND_PASSPHRASE: &str = "SECOND-correct-52d1";

async fn request(path: &Path, request: AdminRequest) -> AdminResponse {
    let mut stream = tokio::net::UnixStream::connect(path).await.unwrap();
    send(&mut stream, &Frame::Request(request)).await;
    match read_frame(&mut stream).await {
        Frame::Response(response) => response,
        other => panic!("expected a response, got {other:?}"),
    }
}

async fn listed(path: &Path) -> Vec<ApproverEntry> {
    match request(path, AdminRequest::ApproverList).await {
        AdminResponse::ApproverList { entries } => entries,
        other => panic!("expected the approver list, got {other:?}"),
    }
}

fn marks(entries: &[ApproverEntry]) -> Vec<(ApproverId, bool)> {
    entries.iter().map(|entry| (entry.id, entry.active)).collect()
}

#[tokio::test]
async fn the_active_marker_follows_a_new_approval() {
    let fixture = Fixture::new().await;
    let first = fixture.approver_id();
    let second = fixture.enroll_second_approver("second", SECOND_PASSPHRASE, UtcSecond::from_unix_seconds(100).unwrap());
    let service = fixture.ready().await;
    let (path, _stop) = serve_admin(&service);

    let before = listed(&path).await;
    assert_eq!(marks(&before), [(first, true), (second, false)]);
    assert_eq!(before[1].label.as_str(), "second");

    let mut stream = tokio::net::UnixStream::connect(&path).await.unwrap();
    let config = ProposedConfig::new(fixture.config("rates").into_bytes()).unwrap();
    send(&mut stream, &Frame::Request(AdminRequest::ConfigApprove(config))).await;
    let answers = [Answer::Input("yes"), Answer::Switch, Answer::Input(SECOND_PASSPHRASE)];
    let approved = converse_switching(&mut stream, &answers).await;
    assert!(matches!(approved.response, AdminResponse::ConfigApprove(_)), "{approved:?}");

    assert_eq!(marks(&listed(&path).await), [(second, true), (first, false)]);
}

#[tokio::test]
async fn the_list_is_refused_while_locked() {
    let fixture = Fixture::new().await;
    let log = LogSwitch::stdout_for_tests(invoking_user().unwrap()).unwrap();
    let service = Arc::new(fixture.start_as(OsFs, log, DeploymentProfile::Development, MemoryProtection::Unsupported));
    let (path, _stop) = serve_admin(&service);

    let response = request(&path, AdminRequest::ApproverList).await;

    assert_eq!(error_code(&response), ErrorCode::WrongState);
}
