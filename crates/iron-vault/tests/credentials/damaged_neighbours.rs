//! Release check 9 (specification §19): "A second writer fails; a damaged credential does not overwrite healthy records;
//! every durable rename includes its directory fsync." These tests show the middle clause for the write commands.
//!
//! A real service on a vault made by `init` holds three credentials, `alpha_key`, `bravo_key` and `charlie_key`. The
//! record file of `bravo_key` is damaged in one of three ways (truncated, one ciphertext byte flipped, or replaced by a
//! valid `age` file for another recipient) and the service reloads, so `list` shows it damaged (§15). Then one write
//! command runs over the admin socket, on a fresh vault for each command and damage:
//!
//! - `add` of a fourth credential, `replace` and `rm` of `alpha_key`, and `recipient add` and `recipient remove`
//!   succeed. After each, every record file other than `alpha_key`'s is byte-identical to before, the damaged one
//!   included, and `list` still shows `bravo_key` damaged;
//! - `replace` and `rm` of `bravo_key` itself succeed. After each, `alpha_key`'s and `charlie_key`'s record files are
//!   byte-identical to before; `list` shows `bravo_key` healthy after `replace` and no longer lists it after `rm`;
//! - `export` refuses with a typed error naming the damaged record file, before any prompt
//!   (`design/migration-bundle.md`, "The snapshot"), and every record file is byte-identical to before.
//!
//! `reset` is the exception the design makes: it runs from Ready whatever a record holds, and discards every record file
//! (`design/reset.md`).
//!
//! Not covered here: a `tpm` approver authorizing `replace`, `rm`, `recipient remove` or `export`, which needs a TPM, and
//! the same commands under a protected install, which needs root. Both reach the same vault writes as the software
//! approver and the development profile used here.

#![cfg(target_os = "linux")]

use crate::common;

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;

use common::approval_harness::{identity, read_frame, send, spawn_admin};
use common::recipient_harness::{APPROVAL_PASSPHRASE, Fixture, VAULT_PASSPHRASE, exchange, ready};
use iron_vault::admin::protocol::{AdminRequest, AdminResponse, ErrorCode, Frame, OwnerInput, Prompt, RequestedOrigin};
use iron_vault::service_context::ServiceContext;
use iron_vault::service_state::ServiceState;
use iron_vault::standing::Standing;
use iron_vault_policy::{CredentialKind, Port};
use iron_vault_store::{RecipientKey, RecipientSet, RecordDamage, RecoveryKey, wrap_identity};
use tokio::net::UnixStream;
use zeroize::Zeroizing;

const HEALTHY: &str = "alpha_key";
const DAMAGED: &str = "bravo_key";
const NAMES: [&str; 3] = [HEALTHY, DAMAGED, "charlie_key"];
const SECRET: &str = "NEIGHBOUR-secret-2b71";

/// How the damaged record file is spoiled.
#[derive(Debug, Clone, Copy)]
enum Damage {
    Truncated,
    FlippedByte,
    OtherRecipient,
}

impl Damage {
    const ALL: [Self; 3] = [Self::Truncated, Self::FlippedByte, Self::OtherRecipient];

    fn apply(self, path: &Path) {
        let mut bytes = fs::read(path).unwrap();
        match self {
            Self::Truncated => bytes.truncate(bytes.len() / 2),
            Self::FlippedByte => *bytes.last_mut().unwrap() ^= 0x01,
            Self::OtherRecipient => {
                let strangers = RecipientSet::new([RecoveryKey::generate().1, RecoveryKey::generate().1]).unwrap();
                bytes = wrap_identity(&identity(), &strangers).unwrap();
            }
        }
        fs::write(path, bytes).unwrap();
    }
}

/// A write command run beside the damaged record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Command {
    Add,
    Replace,
    Rm,
    ReplaceDamaged,
    RmDamaged,
    RecipientAdd,
    RecipientRemove,
    Export,
}

/// A ready service whose `bravo_key` record is damaged, and the record file of each credential.
struct Damaged {
    fixture: Fixture,
    service: Arc<ServiceContext>,
    records: BTreeMap<&'static str, String>,
    /// A recipient enrolled beside the two `init` made, which `recipient remove` may take away.
    spare: RecipientKey,
}

impl Damaged {
    async fn new(damage: Damage) -> Self {
        let fixture = Fixture::new();
        let (service, _) = ready(&fixture).await;
        let mut records = BTreeMap::new();
        for name in NAMES {
            records.insert(name, record_file(&add(&service, name).await));
        }
        let spare = RecoveryKey::generate().1;
        let enrolled = run(&service, recipient_add(&spare), &[VAULT_PASSPHRASE]).await;
        assert!(matches!(enrolled, AdminResponse::RecipientAdd { .. }), "{enrolled:?}");
        damage.apply(&fixture.path(&format!("state/{}", records[DAMAGED])));
        assert_eq!(service.reload().await, Ok(ServiceState::Ready));
        let damaged = Self {
            fixture,
            service,
            records,
            spare,
        };
        damaged.assert_still_damaged(damage).await;
        damaged
    }

    /// Every record file in the state directory with its bytes.
    fn record_bytes(&self) -> BTreeMap<String, Vec<u8>> {
        self.fixture
            .state_files()
            .into_iter()
            .filter(|(name, _)| name.starts_with("record-"))
            .collect()
    }

    /// The standing `list` shows for `bravo_key`, or `None` when it is not listed.
    async fn damaged_standing(&self) -> Option<Standing> {
        let listed = match run(&self.service, AdminRequest::List, &[]).await {
            AdminResponse::List {
                credentials: Some(credentials),
            } => credentials,
            other => panic!("expected the credential list, got {other:?}"),
        };
        listed
            .into_iter()
            .find(|credential| credential.name.as_str() == DAMAGED)
            .map(|credential| credential.standing)
    }

    async fn assert_still_damaged(&self, damage: Damage) {
        assert_eq!(
            self.damaged_standing().await,
            Some(Standing::Damaged(RecordDamage::Substituted)),
            "{damage:?}"
        );
    }

    /// `list` shows `bravo_key` as the command leaves it: healthy after its `replace`, gone after its `rm`, else still damaged.
    async fn assert_listed_after(&self, command: Command, damage: Damage) {
        match command {
            Command::ReplaceDamaged => assert_eq!(self.damaged_standing().await, Some(Standing::Healthy), "{damage:?}"),
            Command::RmDamaged => assert_eq!(self.damaged_standing().await, None, "{damage:?}"),
            _ => self.assert_still_damaged(damage).await,
        }
    }

    /// The record file the command writes to by name, left out of the byte-identity comparison.
    fn named(&self, command: Command) -> Option<&String> {
        match command {
            Command::Replace | Command::Rm => Some(&self.records[HEALTHY]),
            Command::ReplaceDamaged | Command::RmDamaged => Some(&self.records[DAMAGED]),
            _ => None,
        }
    }

    async fn run(&self, command: Command) -> AdminResponse {
        match command {
            Command::Add => run(&self.service, add_request("delta_key"), &[SECRET]).await,
            Command::Replace => run(&self.service, replace_request(HEALTHY), &[APPROVAL_PASSPHRASE, SECRET]).await,
            Command::Rm => run(&self.service, AdminRequest::Rm { name: HEALTHY.to_owned() }, &[APPROVAL_PASSPHRASE]).await,
            Command::ReplaceDamaged => run(&self.service, replace_request(DAMAGED), &[APPROVAL_PASSPHRASE, SECRET]).await,
            Command::RmDamaged => run(&self.service, AdminRequest::Rm { name: DAMAGED.to_owned() }, &[APPROVAL_PASSPHRASE]).await,
            Command::RecipientAdd => run(&self.service, recipient_add(&RecoveryKey::generate().1), &[VAULT_PASSPHRASE]).await,
            Command::RecipientRemove => {
                let request = AdminRequest::RecipientRemove {
                    recipient: self.spare.to_string(),
                };
                run(&self.service, request, &[APPROVAL_PASSPHRASE]).await
            }
            // The export refuses at its snapshot check, before any prompt, so it is given no answers.
            Command::Export => run(&self.service, AdminRequest::Export, &[]).await,
        }
    }

    /// The command ended as the design says: written, or for `export`, refused naming the damaged record file.
    fn assert_outcome(&self, command: Command, damage: Damage, response: &AdminResponse) {
        let ok = match (command, response) {
            (Command::Add, AdminResponse::Add { .. })
            | (Command::Replace | Command::ReplaceDamaged, AdminResponse::Replace { .. })
            | (Command::Rm | Command::RmDamaged, AdminResponse::Success)
            | (Command::RecipientAdd, AdminResponse::RecipientAdd { recipients: 4, .. })
            | (Command::RecipientRemove, AdminResponse::RecipientRemove { recipients: 2 }) => true,
            (Command::Export, AdminResponse::Error { code, message }) => {
                *code == ErrorCode::ExportFailed && message.contains(&self.records[DAMAGED])
            }
            _ => false,
        };
        assert!(ok, "{command:?} beside a {damage:?} record ended {response:?}");
    }
}

/// Runs `command` beside each kind of damage, on a fresh vault each time, and checks what it did to the record files.
async fn check(command: Command) {
    for damage in Damage::ALL {
        let damaged = Damaged::new(damage).await;
        let before = damaged.record_bytes();
        let named = damaged.named(command);

        let response = damaged.run(command).await;

        damaged.assert_outcome(command, damage, &response);
        let after = damaged.record_bytes();
        before.iter().filter(|(file, _)| Some(*file) != named).for_each(|(file, bytes)| {
            assert_eq!(
                after.get(file),
                Some(bytes),
                "{command:?} beside a {damage:?} record changed {file}"
            )
        });
        damaged.assert_listed_after(command, damage).await;
    }
}

#[tokio::test]
async fn release_check_9_add_beside_a_damaged_record_leaves_the_other_records_byte_identical() {
    check(Command::Add).await;
}

#[tokio::test]
async fn release_check_9_replace_beside_a_damaged_record_leaves_the_other_records_byte_identical() {
    check(Command::Replace).await;
}

#[tokio::test]
async fn release_check_9_rm_beside_a_damaged_record_leaves_the_other_records_byte_identical() {
    check(Command::Rm).await;
}

#[tokio::test]
async fn release_check_9_replace_of_the_damaged_record_heals_it_and_leaves_the_healthy_records_byte_identical() {
    check(Command::ReplaceDamaged).await;
}

#[tokio::test]
async fn release_check_9_rm_of_the_damaged_record_removes_it_and_leaves_the_healthy_records_byte_identical() {
    check(Command::RmDamaged).await;
}

#[tokio::test]
async fn release_check_9_recipient_add_beside_a_damaged_record_leaves_every_record_byte_identical() {
    check(Command::RecipientAdd).await;
}

#[tokio::test]
async fn release_check_9_recipient_remove_beside_a_damaged_record_leaves_every_record_byte_identical() {
    check(Command::RecipientRemove).await;
}

#[tokio::test]
async fn release_check_9_export_refuses_a_damaged_record_by_name_and_leaves_every_record_byte_identical() {
    check(Command::Export).await;
}

#[tokio::test]
async fn release_check_9_reset_beside_a_damaged_record_proceeds_and_discards_every_record() {
    for damage in Damage::ALL {
        let damaged = Damaged::new(damage).await;

        let response = reset(&damaged.service).await;

        assert!(
            matches!(response, AdminResponse::Reset { vault_id: Some(_), .. }),
            "reset beside a {damage:?} record ended {response:?}"
        );
        assert!(damaged.record_bytes().is_empty(), "{damage:?}");
        assert!(matches!(
            run(&damaged.service, AdminRequest::List, &[]).await,
            AdminResponse::List { credentials: None }
        ));
    }
}

fn record_file(response: &AdminResponse) -> String {
    match response {
        AdminResponse::Add { record_id } => format!("record-{record_id}.age"),
        other => panic!("expected an added record, got {other:?}"),
    }
}

fn origins() -> Vec<RequestedOrigin> {
    vec![RequestedOrigin {
        host: "api.example".to_owned(),
        port: Port::try_from(443).unwrap(),
    }]
}

fn add_request(name: &str) -> AdminRequest {
    AdminRequest::Add {
        name: name.to_owned(),
        kind: CredentialKind::Static,
        origins: origins(),
    }
}

fn replace_request(name: &str) -> AdminRequest {
    AdminRequest::Replace {
        name: name.to_owned(),
        kind: CredentialKind::Static,
        origins: origins(),
    }
}

fn recipient_add(key: &RecipientKey) -> AdminRequest {
    AdminRequest::RecipientAdd {
        recipient: key.to_string(),
        label: "spare laptop".to_owned(),
    }
}

async fn add(service: &Arc<ServiceContext>, name: &str) -> AdminResponse {
    run(service, add_request(name), &[SECRET]).await
}

/// Sends `request` and answers its prompts in turn with `answers`.
async fn run(service: &Arc<ServiceContext>, request: AdminRequest, answers: &[&str]) -> AdminResponse {
    let answers: Vec<&[u8]> = answers.iter().map(|answer| answer.as_bytes()).collect();
    exchange(service, request, &answers).await.0
}

/// `reset`, answering its confirmation prompt with the vault ID it shows: `Type <vault ID> to discard this vault`.
async fn reset(service: &Arc<ServiceContext>) -> AdminResponse {
    let (path, stop, task) = spawn_admin(service);
    let mut stream = UnixStream::connect(path).await.unwrap();
    send(&mut stream, &Frame::Request(AdminRequest::Reset)).await;
    let response = loop {
        match read_frame(&mut stream).await {
            Frame::Response(response) => break response,
            Frame::Notice(_) => {}
            Frame::Prompt(prompt) => {
                let typed = Zeroizing::new(vault_id(&prompt).into_bytes());
                send(&mut stream, &Frame::OwnerInput(OwnerInput::new(typed))).await;
            }
            other => panic!("unexpected frame {other:?}"),
        }
    };
    let _ = stop.send(());
    task.await.unwrap();
    response
}

fn vault_id(prompt: &Prompt) -> String {
    prompt
        .label
        .strip_prefix("Type ")
        .and_then(|rest| rest.split(' ').next())
        .unwrap()
        .to_owned()
}
