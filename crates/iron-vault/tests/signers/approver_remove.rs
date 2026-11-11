//! `approver remove` end to end over a real admin socket (`design/approval-signers.md`, "`approver remove <approver ID>`"):
//! retiring a signer with its own passphrase, the refusals before any prompt, step 3's read-back, and a key file that
//! cannot be deleted.

#![cfg(target_os = "linux")]

use crate::common;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use common::approval_harness::{
    Answer, Exchanged, Fixture, WRONG_PASSPHRASE, captured_logs, converse_switching, error_code, send, serve_admin,
};
use iron_vault::admin::protocol::{AdminRequest, AdminResponse, ErrorCode, Frame, RequestedSignerKind};
use iron_vault_store::{ApproverId, OsFs, StoreFs, UtcSecond};
use tokio::net::UnixStream;

const SECOND_PASSPHRASE: &str = "SECOND-correct-52d1";

/// `approver remove` for the approver with `id`'s bytes over a new connection to `path`, answering its prompts with `answers`.
async fn remove_bytes(path: &Path, id: [u8; 16], answers: &[Answer<'_>]) -> Exchanged {
    let mut stream = UnixStream::connect(path).await.unwrap();
    send(&mut stream, &Frame::Request(AdminRequest::ApproverRemove { approver: id })).await;
    converse_switching(&mut stream, answers).await
}

async fn remove(path: &Path, id: ApproverId, answers: &[Answer<'_>]) -> Exchanged {
    remove_bytes(path, *id.as_bytes(), answers).await
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

fn key_file(fixture: &Fixture, id: ApproverId) -> PathBuf {
    fixture.path(&format!("state/approver-{id}.age"))
}

fn enroll_second(fixture: &Fixture) -> ApproverId {
    fixture.enroll_second_approver("second", SECOND_PASSPHRASE, UtcSecond::from_unix_seconds(100).unwrap())
}

/// The second approver's passphrase through the prompt, which asks the active signer first.
const BY_SECOND: [Answer<'static>; 2] = [Answer::Switch, Answer::Input(SECOND_PASSPHRASE)];

#[tokio::test]
async fn an_approver_retires_itself_and_its_passphrase_then_gives_no_presence() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    let second = enroll_second(&fixture);
    let service = fixture.ready().await;
    let (path, _stop) = serve_admin(&service);

    let removed = remove(&path, second, &BY_SECOND).await;

    assert!(
        matches!(removed.response, AdminResponse::ApproverRemove { approvers: 1 }),
        "{removed:?}"
    );
    assert!(
        removed.notices.contains("remove an approval signer\n  vault: ") && removed.notices.contains(&format!("  approver: {second}\n")),
        "{}",
        removed.notices
    );
    assert!(removed.notices.contains("  label: second\n") && removed.notices.contains("  approvers after the change: 1\n"));
    assert!(
        removed
            .notices
            .ends_with(&format!("removed approver {second}; the vault has 1 approvers.\n")),
        "{}",
        removed.notices
    );
    assert!(!key_file(&fixture, second).exists());
    let record = logs
        .events("approver.removed")
        .into_iter()
        .find(|record| record["approver_id"] == second.to_string().as_str())
        .unwrap();
    assert_eq!(
        (&record["key_file"], &record["approvers"], &record["authorizing_approver_id"]),
        (&"removed".into(), &1.into(), &second.to_string().as_str().into())
    );

    // Only the first approver is offered now, and the removed one's passphrase is just a wrong answer.
    let answers = [Answer::Input(SECOND_PASSPHRASE)];
    let mut stream = UnixStream::connect(&path).await.unwrap();
    let request = AdminRequest::ApproverAdd {
        kind: RequestedSignerKind::Software,
        label: "again".to_owned(),
    };
    send(&mut stream, &Frame::Request(request)).await;
    let denied = converse_switching(&mut stream, &answers).await;
    assert_eq!(error_code(&denied.response), ErrorCode::ApprovalDenied);
    assert_eq!(denied.prompts.len(), 1);
    assert!(!denied.prompts[0].switchable);
    assert!(denied.prompts[0].label.contains("approval passphrase"), "{:?}", denied.prompts);
    logs.assert_no_passphrase();
}

#[tokio::test]
async fn refusals_before_any_prompt_change_nothing() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    let first = fixture.approver_id();
    let service = fixture.ready().await;
    let (path, _stop) = serve_admin(&service);
    let before = state_files(&fixture);

    let last = remove(&path, first, &[]).await;
    let unknown = remove(&path, ApproverId::generate(), &[]).await;
    let not_v4 = remove_bytes(&path, [0; 16], &[]).await;

    for (refused, code) in [
        (&last, ErrorCode::ApproverSetInvalid),
        (&unknown, ErrorCode::UnknownApprover),
        (&not_v4, ErrorCode::ApproverInvalid),
    ] {
        assert_eq!((error_code(&refused.response), refused.prompts.len()), (code, 0), "{refused:?}");
    }
    assert_eq!(state_files(&fixture), before);
    let failed = |failure: &str| logs.has_field("approver.change-failed", "failure", failure);
    assert!(failed("set_invalid") && failed("unknown_approver"));
}

#[tokio::test]
async fn the_signer_of_the_active_approval_is_refused_before_any_prompt() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    let first = fixture.approver_id();
    let second = enroll_second(&fixture);
    let service = fixture.ready().await;
    let (path, _stop) = serve_admin(&service);
    let before = state_files(&fixture);

    let refused = remove(&path, first, &[]).await;

    match &refused.response {
        AdminResponse::Error { code, message } => {
            assert_eq!(*code, ErrorCode::ApproverInUse);
            assert!(message.contains("approve the config with another approver first"), "{message}");
        }
        other => panic!("expected approver-in-use, got {other:?}"),
    }
    assert!(refused.prompts.is_empty());
    assert_eq!(state_files(&fixture), before);
    assert!(key_file(&fixture, second).exists());
    assert!(logs.has_field("approver.change-failed", "approver_id", &first.to_string()));
}

#[tokio::test]
async fn a_wrong_presence_passphrase_is_denied_and_removes_nothing() {
    let fixture = Fixture::new().await;
    let second = enroll_second(&fixture);
    let service = fixture.ready().await;
    let (path, _stop) = serve_admin(&service);
    let before = state_files(&fixture);

    let denied = remove(&path, second, &[Answer::Input(WRONG_PASSPHRASE)]).await;

    assert_eq!(error_code(&denied.response), ErrorCode::ApprovalDenied);
    assert_eq!(state_files(&fixture), before);
}

/// An older approval state and its manifest put back together are a consistent pair, so they open; the state then differs
/// from the one in memory, which pins an approver they do not. Nothing is deleted, and the key file survives.
#[tokio::test]
async fn an_approval_state_that_differs_from_memory_fails_before_any_prompt_and_deletes_no_key_file() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    let older = ["state/approval.age", "state/manifest.age"].map(|name| (name, fs::read(fixture.path(name)).unwrap()));
    let second = enroll_second(&fixture);
    let service = fixture.ready().await;
    let (path, _stop) = serve_admin(&service);
    older.iter().for_each(|(name, bytes)| fs::write(fixture.path(name), bytes).unwrap());

    let failed = remove(&path, second, &BY_SECOND).await;

    match &failed.response {
        AdminResponse::Error { code, message } => {
            assert_eq!(*code, ErrorCode::VaultWriteFailed);
            assert!(message.contains("nothing was changed"), "{message}");
        }
        other => panic!("expected vault-write-failed, got {other:?}"),
    }
    assert!(failed.prompts.is_empty());
    assert!(key_file(&fixture, second).exists());
    let records = logs.events("approver.change-failed");
    assert!(
        records.iter().any(|record| record["step"] == "read_back"
            && record["error_kind"] == "differs"
            && record["committed"] == "no"
            && record["approver_id"] == second.to_string().as_str()),
        "{records:?}"
    );
}

/// The real filesystem, except that removing an approver key file fails while armed.
#[derive(Clone, Default)]
struct StuckKeyFiles(Arc<AtomicBool>);

impl StoreFs for StuckKeyFiles {
    type File = fs::File;

    fn create_private(&self, path: &Path) -> io::Result<fs::File> {
        OsFs.create_private(path)
    }

    fn write_all(&self, file: &mut fs::File, bytes: &[u8]) -> io::Result<()> {
        OsFs.write_all(file, bytes)
    }

    fn sync_file(&self, file: &fs::File) -> io::Result<()> {
        OsFs.sync_file(file)
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        OsFs.rename(from, to)
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        let is_key_file = path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("approver-"));
        match is_key_file && self.0.load(Ordering::SeqCst) {
            true => Err(io::Error::from(io::ErrorKind::PermissionDenied)),
            false => OsFs.remove_file(path),
        }
    }

    fn sync_dir(&self, dir: &Path) -> io::Result<()> {
        OsFs.sync_dir(dir)
    }

    fn list_dir(&self, dir: &Path) -> io::Result<Vec<OsString>> {
        OsFs.list_dir(dir)
    }

    fn read_bounded(&self, path: &Path, max_len: u64) -> io::Result<Vec<u8>> {
        OsFs.read_bounded(path, max_len)
    }
}

#[tokio::test]
async fn a_key_file_that_cannot_be_deleted_still_succeeds_and_the_next_change_sweeps_it() {
    let logs = captured_logs();
    let fixture = Fixture::new().await;
    let second = enroll_second(&fixture);
    let stuck = StuckKeyFiles::default();
    let service = fixture.ready_on(stuck.clone()).await;
    let (path, _stop) = serve_admin(&service);
    stuck.0.store(true, Ordering::SeqCst);

    let removed = remove(&path, second, &BY_SECOND).await;

    assert!(
        matches!(removed.response, AdminResponse::ApproverRemove { approvers: 1 }),
        "{removed:?}"
    );
    assert!(
        removed
            .notices
            .ends_with("Its key file could not be removed; the next approver add or remove removes it.\n"),
        "{}",
        removed.notices
    );
    assert!(key_file(&fixture, second).exists());
    assert!(logs.has_field("approver.removed", "key_file", "left"));

    // The next approver command sweeps the orphan at step 3, before it asks for presence.
    stuck.0.store(false, Ordering::SeqCst);
    let request = AdminRequest::ApproverRemove {
        approver: *ApproverId::generate().as_bytes(),
    };
    let swept = {
        let mut stream = UnixStream::connect(&path).await.unwrap();
        send(&mut stream, &Frame::Request(request)).await;
        converse_switching(&mut stream, &[]).await
    };
    assert_eq!(error_code(&swept.response), ErrorCode::UnknownApprover);
    assert!(!key_file(&fixture, second).exists());
    assert!(logs.has_field("approver.orphan-removed", "approver_id", &second.to_string()));
}
