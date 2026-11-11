//! `approver add` end to end over a real admin socket (`design/approval-signers.md`, "`approver add`"): enrolling a second
//! software approver that then approves a config, the refusals before any prompt, owner presence that only a pinned
//! approver can give, the new passphrase's rules, step 3's read-back and orphan sweep, and a log with no passphrase.

#![cfg(target_os = "linux")]
// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;

use common::approval_harness::{
    APPROVAL_PASSPHRASE, Answer, Exchanged, Fixture, WRONG_PASSPHRASE, captured_logs, converse_switching, error_code, send, serve_admin,
};
use common::recipient_harness;
use iron_vault::admin::protocol::{AdminRequest, AdminResponse, ErrorCode, Frame, ProposedConfig, RequestedSignerKind};
use iron_vault::service_context::ServiceContext;
use iron_vault_store::{ApprovalEnvelope, ApproverId, UtcSecond};
use tokio::net::UnixStream;

const NEW_PASSPHRASE: &str = "BACKUP-approver-passphrase-7a31";

/// `approver add` with `kind` and `label` over a new connection to `path`, answering its prompts with `answers`.
async fn add_on(path: &Path, kind: RequestedSignerKind, label: &str, answers: &[Answer<'_>]) -> Exchanged {
    let mut stream = UnixStream::connect(path).await.unwrap();
    let request = AdminRequest::ApproverAdd {
        kind,
        label: label.to_owned(),
    };
    send(&mut stream, &Frame::Request(request)).await;
    converse_switching(&mut stream, answers).await
}

/// A software `approver add` labelled `backup`, authorized by `presence` and choosing `new` and `repeat`.
async fn add(path: &Path, presence: &str, [new, repeat]: [&str; 2]) -> Exchanged {
    let answers = [Answer::Input(presence), Answer::Input(new), Answer::Input(repeat)];
    add_on(path, RequestedSignerKind::Software, "backup", &answers).await
}

fn enrolled(exchanged: &Exchanged) -> (ApproverId, u8) {
    match exchanged.response {
        AdminResponse::ApproverAdd { approver, approvers } => (approver, approvers),
        ref other => panic!("expected an enrolled approver, got {other:?}"),
    }
}

fn prompt_labels(exchanged: &Exchanged) -> Vec<&str> {
    exchanged.prompts.iter().map(|prompt| prompt.label.as_str()).collect()
}

/// Every file of the fixture's state directory with its bytes.
fn state_files(fixture: &Fixture) -> BTreeMap<String, Vec<u8>> {
    fs::read_dir(fixture.path("state"))
        .unwrap()
        .map(|entry| entry.unwrap())
        .filter(|entry| entry.file_type().unwrap().is_file())
        .map(|entry| (entry.file_name().to_string_lossy().into_owned(), fs::read(entry.path()).unwrap()))
        .collect()
}

async fn ready(fixture: &Fixture) -> (Arc<ServiceContext>, std::path::PathBuf, tokio::sync::oneshot::Sender<()>) {
    let service = fixture.ready().await;
    let (path, stop) = serve_admin(&service);
    (service, path, stop)
}

#[tokio::test]
async fn an_enrolled_approver_approves_a_config_after_a_switch() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    let first = fixture.approver_id();
    let (_service, path, _stop) = ready(&fixture).await;

    let added = add(&path, APPROVAL_PASSPHRASE, [NEW_PASSPHRASE, NEW_PASSPHRASE]).await;

    let (id, approvers) = enrolled(&added);
    assert_eq!(approvers, 2);
    assert!(
        added.notices.contains("enroll an approval signer\n  vault: ") && added.notices.contains("  approvers after the change: 2\n"),
        "{}",
        added.notices
    );
    assert!(
        added
            .notices
            .ends_with(&format!("enrolled approver {id} (software); the vault has 2 approvers.\n"))
    );
    assert_eq!(
        prompt_labels(&added),
        [
            "Approval passphrase for \"approval passphrase\"",
            "New approval passphrase for \"backup\"",
            "Repeat the new approval passphrase"
        ]
    );
    assert!(state_files(&fixture).contains_key(&format!("approver-{id}.age")));
    let record = logs
        .events("approver.enrolled")
        .into_iter()
        .find(|record| record["approver_id"] == id.to_string().as_str())
        .unwrap();
    assert_eq!(
        (&record["signer_kind"], &record["approvers"], &record["authorizing_approver_id"]),
        (&"software".into(), &2.into(), &first.to_string().as_str().into())
    );

    let mut stream = UnixStream::connect(&path).await.unwrap();
    let config = ProposedConfig::new(fixture.config("rates").into_bytes()).unwrap();
    send(&mut stream, &Frame::Request(AdminRequest::ConfigApprove(config))).await;
    let answers = [Answer::Input("yes"), Answer::Switch, Answer::Input(NEW_PASSPHRASE)];
    let approved = converse_switching(&mut stream, &answers).await;
    assert!(matches!(approved.response, AdminResponse::ConfigApprove(_)), "{approved:?}");
    assert_eq!(ApprovalEnvelope::decode(&fixture.published_pair()[1]).unwrap().approver_id(), id);
    logs.assert_no_passphrase();
    assert!(!logs.text().contains(NEW_PASSPHRASE));
}

#[tokio::test]
async fn refusals_before_any_prompt_change_nothing() {
    let fixture = Fixture::new().await;
    (0..15).for_each(|n| {
        fixture.enroll_second_approver(
            &format!("extra {n}"),
            "EXTRA-passphrase-0001",
            UtcSecond::from_unix_seconds(100).unwrap(),
        );
    });
    let (_service, path, _stop) = ready(&fixture).await;
    let before = state_files(&fixture);
    let software = RequestedSignerKind::Software;

    let cases = [
        (software, "", ErrorCode::ApproverInvalid),
        (software, "bad\nlabel", ErrorCode::ApproverInvalid),
        (RequestedSignerKind::Tpm, "tpm", ErrorCode::ApproverKindUnavailable),
        (RequestedSignerKind::Hardware, "key", ErrorCode::ApproverKindUnavailable),
        (software, "seventeenth", ErrorCode::ApproverSetInvalid),
    ];
    for (kind, label, code) in cases {
        let refused = add_on(&path, kind, label, &[]).await;
        assert_eq!(
            (error_code(&refused.response), refused.prompts.len()),
            (code, 0),
            "{label}: {refused:?}"
        );
    }
    assert_eq!(state_files(&fixture), before);
}

#[tokio::test]
async fn a_wrong_presence_passphrase_is_denied_before_the_new_one_is_asked() {
    let fixture = Fixture::new().await;
    let (_service, path, _stop) = ready(&fixture).await;
    let before = state_files(&fixture);

    let answers = [Answer::Input(WRONG_PASSPHRASE)];
    let denied = add_on(&path, RequestedSignerKind::Software, "backup", &answers).await;

    assert_eq!(error_code(&denied.response), ErrorCode::ApprovalDenied);
    assert_eq!(denied.prompts.len(), 1);
    assert_eq!(state_files(&fixture), before);
}

#[tokio::test]
async fn a_new_passphrase_that_breaks_a_rule_is_rejected_and_nothing_is_written() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    let (_service, path, _stop) = ready(&fixture).await;
    let before = state_files(&fixture);

    let mismatched = add(&path, APPROVAL_PASSPHRASE, [NEW_PASSPHRASE, "BACKUP-approver-passphrase-7a32"]).await;
    let short = add(&path, APPROVAL_PASSPHRASE, ["short", "short"]).await;

    assert_eq!(error_code(&mismatched.response), ErrorCode::PassphraseRejected);
    assert_eq!(error_code(&short.response), ErrorCode::PassphraseRejected);
    assert_eq!(state_files(&fixture), before);
    assert!(logs.has_field("approver.change-failed", "failure", "passphrase_rejected"));
    assert!(!logs.text().contains(NEW_PASSPHRASE));
}

#[tokio::test]
async fn an_approval_state_that_does_not_read_back_fails_before_any_prompt_and_deletes_no_key_file() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    let (_service, path, _stop) = ready(&fixture).await;
    let orphan = format!("approver-{}.age", ApproverId::generate());
    fs::write(fixture.path(&format!("state/{orphan}")), b"left by a failed enrollment").unwrap();
    fs::write(fixture.path("state/approval.age"), b"not an approval state").unwrap();
    let before = state_files(&fixture);

    let failed = add(&path, APPROVAL_PASSPHRASE, [NEW_PASSPHRASE, NEW_PASSPHRASE]).await;

    match &failed.response {
        AdminResponse::Error { code, message } => {
            assert_eq!(*code, ErrorCode::VaultWriteFailed);
            assert!(message.contains("nothing was changed"), "{message}");
        }
        other => panic!("expected vault-write-failed, got {other:?}"),
    }
    assert!(failed.prompts.is_empty());
    assert_eq!(state_files(&fixture), before);
    let records = logs.events("approver.change-failed");
    assert!(
        records
            .iter()
            .any(|record| record["step"] == "read_back" && record["committed"] == "no"),
        "{records:?}"
    );
}

/// An older approval state and its manifest put back together are a consistent pair, so they open; the state then
/// differs from the one in memory, which pins an approver they do not. Its key file must survive.
#[tokio::test]
async fn an_approval_state_that_differs_from_memory_fails_before_any_prompt_and_deletes_no_key_file() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    let older = ["state/approval.age", "state/manifest.age"].map(|name| (name, fs::read(fixture.path(name)).unwrap()));
    let second = fixture.enroll_second_approver("second", "SECOND-passphrase-0001", UtcSecond::from_unix_seconds(100).unwrap());
    let (_service, path, _stop) = ready(&fixture).await;
    older.iter().for_each(|(name, bytes)| fs::write(fixture.path(name), bytes).unwrap());

    let failed = add(&path, APPROVAL_PASSPHRASE, [NEW_PASSPHRASE, NEW_PASSPHRASE]).await;

    match &failed.response {
        AdminResponse::Error { code, message } => {
            assert_eq!(*code, ErrorCode::VaultWriteFailed);
            assert!(message.contains("nothing was changed"), "{message}");
        }
        other => panic!("expected vault-write-failed, got {other:?}"),
    }
    assert!(failed.prompts.is_empty());
    assert!(fixture.path(&format!("state/approver-{second}.age")).exists());
    let records = logs.events("approver.change-failed");
    assert!(
        records
            .iter()
            .any(|record| record["step"] == "read_back" && record["error_kind"] == "differs" && record["committed"] == "no"),
        "{records:?}"
    );
}

#[tokio::test]
async fn step_three_removes_an_orphan_key_file() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    let (_service, path, _stop) = ready(&fixture).await;
    let orphan = ApproverId::generate();
    let file = fixture.path(&format!("state/approver-{orphan}.age"));
    fs::write(&file, b"left by a failed enrollment").unwrap();

    let denied = add_on(&path, RequestedSignerKind::Software, "backup", &[Answer::Input(WRONG_PASSPHRASE)]).await;

    assert_eq!(error_code(&denied.response), ErrorCode::ApprovalDenied);
    assert!(!file.exists());
    assert!(logs.has_field("approver.orphan-removed", "approver_id", &orphan.to_string()));
}

#[tokio::test]
async fn neither_the_vault_passphrase_nor_a_recovery_key_gives_owner_presence() {
    let fixture = recipient_harness::Fixture::new();
    let service = fixture.start();
    let recovery_key = recipient_harness::init(&service).await;
    recipient_harness::unlock(&service).await;
    let (path, _stop) = serve_admin(&service);
    let before = fixture.state_files();

    for presence in [recipient_harness::VAULT_PASSPHRASE, recovery_key.as_str()] {
        let denied = add(&path, presence, [NEW_PASSPHRASE, NEW_PASSPHRASE]).await;
        assert_eq!(error_code(&denied.response), ErrorCode::ApprovalDenied);
        assert_eq!(denied.prompts.len(), 1);
    }
    assert_eq!(fixture.state_files(), before);
}
