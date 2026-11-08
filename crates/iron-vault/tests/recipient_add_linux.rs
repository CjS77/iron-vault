//! `recipient add` end to end over a real admin socket against a running service on an initialized, unlocked vault
//! (`design/recipients.md`, "`recipient add <age1…>`"; `design/migration-authorization.md`, "Admin exchange"). The key is
//! enrolled only after a fresh vault passphrase; every other ending leaves `identity.age` and the inventory as they were.

#![cfg(target_os = "linux")]
// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use common::approval_harness::{Captured, assert_audit_record, captured_logs, converse, read_frame, send, spawn_admin};
use common::recipient_harness::{Fixture, VAULT_PASSPHRASE, ready};
use iron_vault::admin::protocol::{AdminRequest, AdminResponse, ErrorCode, Frame, Prompt};
use iron_vault::service_context::{RecipientRefusal, ServiceContext};
use iron_vault_store::{RecipientEntry, RecipientKey, RecipientRole, RecoveryKey, RecoveryKeySecret, unwrap_identity};
use secrecy::{ExposeSecret, SecretString};
use tokio::net::UnixStream;
use tokio::sync::oneshot;

const WRONG_PASSPHRASE: &str = "ADD-wrong-passphrase-6e03";
const LABEL: &str = "bob's new laptop";

/// A ready service with its admin socket served until the test ends, so one test can hold several connections.
struct Served {
    fixture: Fixture,
    service: Arc<ServiceContext>,
    recovery_key: String,
    logs: Captured,
    path: PathBuf,
    stop: Option<oneshot::Sender<()>>,
}

impl Served {
    async fn new() -> Self {
        let logs = captured_logs();
        let fixture = Fixture::new();
        let (service, recovery_key) = ready(&fixture).await;
        let (path, stop, _) = spawn_admin(&service);
        Self {
            fixture,
            service,
            recovery_key,
            logs,
            path,
            stop: Some(stop),
        }
    }

    async fn connect(&self, request: AdminRequest) -> UnixStream {
        let mut stream = UnixStream::connect(&self.path).await.unwrap();
        send(&mut stream, &Frame::Request(request)).await;
        stream
    }

    /// The two files a recipient change writes, as they are on disk now.
    fn recipient_files(&self) -> [Vec<u8>; 2] {
        ["identity.age", "recipients.age"].map(|name| fs::read(self.fixture.path(&format!("state/{name}"))).unwrap())
    }

    fn assert_nothing_written(&self, before: &[Vec<u8>; 2]) {
        assert_eq!(
            &self.recipient_files(),
            before,
            "a refused add changed identity.age or the inventory"
        );
        assert!(!self.fixture.path("state/recipients.age.staged").exists());
    }

    /// Waits until the exchange that held the service-wide lock has ended, so a `list` is no longer `busy`.
    async fn entries(&self) -> Vec<RecipientEntry> {
        for _ in 0..200 {
            match self.service.list_recipients().await {
                Ok(entries) => return entries,
                Err(RecipientRefusal::Busy) => tokio::time::sleep(Duration::from_millis(10)).await,
                Err(other) => panic!("{other}"),
            }
        }
        panic!("the recipient add never released the service-wide lock");
    }

    fn events_for(&self, event: &str, key: &RecipientKey) -> Vec<serde_json::Value> {
        let key = key.to_string();
        self.logs
            .events(event)
            .into_iter()
            .filter(|record| record["destination_recipient"] == key.as_str() || record["recipient"] == key.as_str())
            .collect()
    }

    /// `recipient add` for `key`, answered with `typed` at the prompt.
    async fn add(&self, key: &RecipientKey, typed: &str) -> common::approval_harness::Exchanged {
        let mut stream = self.connect(add_request(key, LABEL)).await;
        converse(&mut stream, &[typed]).await
    }
}

impl Drop for Served {
    fn drop(&mut self) {
        self.stop.take().into_iter().for_each(|stop| {
            let _ = stop.send(());
        });
    }
}

fn add_request(key: &RecipientKey, label: &str) -> AdminRequest {
    AdminRequest::RecipientAdd {
        recipient: key.to_string(),
        label: label.to_owned(),
    }
}

/// A fresh key and the identity that holds it.
fn new_recipient() -> (RecipientKey, iron_vault_store::RecipientIdentity) {
    let (secret, key) = RecoveryKey::generate();
    (
        key,
        RecoveryKeySecret::parse(SecretString::from(secret.expose_secret().to_owned())).unwrap(),
    )
}

fn vault_passphrase_prompt() -> Prompt {
    Prompt {
        label: "Vault passphrase".to_owned(),
        secret: true,
    }
}

fn error_of(response: &AdminResponse) -> (ErrorCode, &str) {
    match response {
        AdminResponse::Error { code, message } => (*code, message),
        other => panic!("expected an error, got {other:?}"),
    }
}

#[tokio::test]
async fn the_right_vault_passphrase_enrols_the_key_and_the_new_key_opens_the_vault() {
    let served = Served::new().await;
    let (key, identity) = new_recipient();
    let old_envelope = fs::read(served.fixture.path("state/identity.age")).unwrap();
    assert!(
        unwrap_identity(&old_envelope, &identity).is_err(),
        "the key opened the vault before it was added"
    );

    let exchanged = served.add(&key, VAULT_PASSPHRASE).await;

    assert_eq!(exchanged.prompts, [vault_passphrase_prompt()]);
    match &exchanged.response {
        AdminResponse::RecipientAdd { recipient, recipients } => assert_eq!((recipient, *recipients), (&key, 3)),
        other => panic!("{other:?}"),
    }
    let summary =
        format!("recipient: {key}\n  role: added\n  label: {LABEL}\n  recipients after the change: 3 (operational 1, recovery 1, added 1)");
    assert!(
        exchanged.notices.starts_with("add a recipient to the vault\n  vault: "),
        "{}",
        exchanged.notices
    );
    assert!(exchanged.notices.contains(&summary), "{}", exchanged.notices);
    assert!(
        exchanged.notices.contains("authorize with: the vault passphrase"),
        "{}",
        exchanged.notices
    );
    assert!(
        exchanged
            .notices
            .contains(&format!("enrolled {key} as added; the vault has 3 recipients.")),
        "{}",
        exchanged.notices
    );
    assert!(
        exchanged
            .notices
            .contains("Old copies of identity.age, and backups, still open with a removed key."),
        "{}",
        exchanged.notices
    );

    let new_envelope = fs::read(served.fixture.path("state/identity.age")).unwrap();
    let recovery = RecoveryKeySecret::parse(SecretString::from(served.recovery_key.clone())).unwrap();
    let (by_new_key, by_recovery) = (
        unwrap_identity(&new_envelope, &identity).unwrap(),
        unwrap_identity(&new_envelope, &recovery).unwrap(),
    );
    assert!(
        by_new_key.public_key() == by_recovery.public_key(),
        "the new key opens another vault identity"
    );
    assert!(!served.fixture.path("state/recipients.age.staged").exists());
    let entries = served.entries().await;
    let added: Vec<_> = entries.iter().filter(|entry| entry.role() == RecipientRole::Added).collect();
    assert_eq!(
        added.iter().map(|entry| (entry.key(), entry.label().as_str())).collect::<Vec<_>>(),
        [(&key, LABEL)]
    );
    assert_eq!(entries.len(), 3);
    let [issued, authorized] = ["migration.challenge-issued", "migration.authorized"].map(|event| served.events_for(event, &key));
    assert_eq!((issued.len(), authorized.len()), (1, 1));
    let recorded = served.events_for("recipient.added", &key);
    assert_eq!(recorded.len(), 1, "{recorded:?}");
    assert_audit_record(
        &recorded[0],
        "INFO",
        &["recipient", "recipient_role", "recipient_label", "recipients"],
    );
    assert_eq!(
        (recorded[0]["recipient_label"].as_str(), recorded[0]["recipients"].as_u64()),
        (Some(LABEL), Some(3))
    );
}

#[tokio::test]
async fn a_wrong_vault_passphrase_adds_nothing() {
    let served = Served::new().await;
    let (key, identity) = new_recipient();
    let before = served.recipient_files();

    let exchanged = served.add(&key, WRONG_PASSPHRASE).await;

    let (code, message) = error_of(&exchanged.response);
    assert_eq!((code as u16, code.name()), (28, "migration-denied"));
    assert!(!message.contains(WRONG_PASSPHRASE), "{message}");
    served.assert_nothing_written(&before);
    assert!(unwrap_identity(&fs::read(served.fixture.path("state/identity.age")).unwrap(), &identity).is_err());
    assert_eq!(served.entries().await.len(), 2);
    let refused = served.events_for("migration.authorization-refused", &key);
    assert_eq!(refused.len(), 1, "{refused:?}");
    assert_eq!(refused[0]["refusal"], "wrong_passphrase");
    assert!(served.events_for("recipient.added", &key).is_empty());
}

#[tokio::test]
async fn a_cancelled_prompt_adds_nothing_and_releases_the_lock() {
    let served = Served::new().await;
    let (key, _) = new_recipient();
    let before = served.recipient_files();
    let mut stream = served.connect(add_request(&key, LABEL)).await;
    loop {
        match read_frame(&mut stream).await {
            Frame::Prompt(prompt) => break assert_eq!(prompt, vault_passphrase_prompt()),
            Frame::Notice(_) => {}
            other => panic!("{other:?}"),
        }
    }

    drop(stream);

    assert_eq!(served.entries().await.len(), 2);
    served.assert_nothing_written(&before);
    let refused = served.events_for("migration.authorization-refused", &key);
    assert_eq!(refused.len(), 1, "{refused:?}");
    assert_eq!(refused[0]["refusal"], "cancelled");
}

#[tokio::test]
async fn a_lock_at_the_prompt_adds_nothing() {
    let served = Served::new().await;
    let (key, _) = new_recipient();
    let before = served.recipient_files();
    let mut stream = served.connect(add_request(&key, LABEL)).await;
    loop {
        match read_frame(&mut stream).await {
            Frame::Prompt(_) => break,
            Frame::Notice(_) => {}
            other => panic!("{other:?}"),
        }
    }

    let mut lock = served.connect(AdminRequest::Lock).await;

    let Frame::Response(response) = read_frame(&mut stream).await else {
        panic!("expected the response after the prompt");
    };
    assert_eq!(error_of(&response).0, ErrorCode::MigrationUnavailable);
    assert!(matches!(
        read_frame(&mut lock).await,
        Frame::Response(AdminResponse::Lock { cleared: true })
    ));
    served.assert_nothing_written(&before);
    let refused = served.events_for("migration.authorization-refused", &key);
    assert_eq!(refused.len(), 1, "{refused:?}");
    assert_eq!(refused[0]["refusal"], "locked");
}

#[tokio::test]
async fn an_unlocked_vault_alone_never_adds_a_key_because_the_prompt_comes_first() {
    let served = Served::new().await;
    let (key, _) = new_recipient();
    let before = served.recipient_files();
    let mut stream = served.connect(add_request(&key, LABEL)).await;
    let mut shown = Vec::new();
    let prompt = loop {
        match read_frame(&mut stream).await {
            Frame::Notice(notice) => shown.push(notice.text),
            Frame::Prompt(prompt) => break prompt,
            Frame::Response(response) => panic!("the exchange answered before asking for the passphrase: {response:?}"),
            other => panic!("{other:?}"),
        }
    };
    assert_eq!(prompt, vault_passphrase_prompt());
    served.assert_nothing_written(&before);

    // Any frame but the passphrase ends the exchange without an answer.
    send(&mut stream, &Frame::Request(AdminRequest::Ping)).await;

    let Frame::Response(response) = read_frame(&mut stream).await else {
        panic!("expected the response");
    };
    assert_eq!(error_of(&response).0, ErrorCode::UnexpectedFrame);
    assert_eq!(served.entries().await.len(), 2);
    served.assert_nothing_written(&before);
}

#[tokio::test]
async fn an_enrolled_key_is_refused_before_any_prompt_or_challenge() {
    let served = Served::new().await;
    let enrolled = served.entries().await.remove(0);
    let before = served.recipient_files();
    let mut stream = served.connect(add_request(enrolled.key(), LABEL)).await;

    let exchanged = converse(&mut stream, &[]).await;

    assert!(exchanged.prompts.is_empty(), "the owner was asked to type");
    let (code, message) = error_of(&exchanged.response);
    assert_eq!((code as u16, code.name()), (36, "recipient-enrolled"));
    assert!(message.contains("nothing was changed"), "{message}");
    assert!(served.events_for("migration.challenge-issued", enrolled.key()).is_empty());
    let failed = served.events_for("recipient.change-failed", enrolled.key());
    assert_eq!(failed.len(), 1, "{failed:?}");
    assert_audit_record(&failed[0], "WARN", &["change", "recipient", "failure"]);
    assert_eq!(failed[0]["failure"], "already_enrolled");
    served.assert_nothing_written(&before);
}

#[tokio::test]
async fn a_bad_argument_a_locked_service_and_a_damaged_inventory_are_refused_before_any_prompt() {
    let served = Served::new().await;
    let (key, _) = new_recipient();
    let before = served.recipient_files();
    let refused = |request| async {
        let mut stream = served.connect(request).await;
        let exchanged = converse(&mut stream, &[]).await;
        assert!(exchanged.prompts.is_empty() && exchanged.notices.is_empty(), "{exchanged:?}");
        let (code, _) = error_of(&exchanged.response);
        code
    };
    let bad_key = AdminRequest::RecipientAdd {
        recipient: "age1nope".to_owned(),
        label: LABEL.to_owned(),
    };
    assert_eq!(refused(bad_key).await, ErrorCode::RecipientInvalid);
    assert_eq!(refused(add_request(&key, " padded")).await, ErrorCode::RecipientInvalid);
    assert_eq!(refused(add_request(&key, "")).await, ErrorCode::RecipientInvalid);
    served.assert_nothing_written(&before);

    let mut bytes = before[1].clone();
    let middle = bytes.len() / 2;
    bytes[middle] ^= 1;
    fs::write(served.fixture.path("state/recipients.age"), bytes).unwrap();
    assert_eq!(refused(add_request(&key, LABEL)).await, ErrorCode::RecipientInventoryDamaged);
    fs::write(served.fixture.path("state/recipients.age"), &before[1]).unwrap();

    let mut lock = served.connect(AdminRequest::Lock).await;
    assert!(matches!(read_frame(&mut lock).await, Frame::Response(AdminResponse::Lock { .. })));
    assert_eq!(refused(add_request(&key, LABEL)).await, ErrorCode::WrongState);
    assert!(served.events_for("migration.challenge-issued", &key).is_empty());
}

#[tokio::test]
async fn no_log_record_holds_a_typed_passphrase() {
    let served = Served::new().await;
    let (right, _) = new_recipient();
    let (wrong, _) = new_recipient();
    served.add(&wrong, WRONG_PASSPHRASE).await;
    served.add(&right, VAULT_PASSPHRASE).await;

    let text = served.logs.text();
    [VAULT_PASSPHRASE, WRONG_PASSPHRASE]
        .into_iter()
        .for_each(|typed| assert!(!text.contains(typed), "a typed passphrase reached the log"));
}
