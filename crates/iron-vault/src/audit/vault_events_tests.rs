//! The vault, credential, caller, route and response events: each writes its name, level and exactly its own fields.

use iron_vault_kinds::SecretField;
use iron_vault_policy::{CredentialKind, CredentialName, Host, Port, RouteName};
use iron_vault_store::{
    DamagedRecord, ErrorKindLabel, InitFailure, InitStep, RecipientEntry, RecipientLabel, RecipientRole, RecordDamage, RecordId, SealError,
    SharedStateDamage, StateFileName, UnlockError, UtcSecond, VaultId, WriteError,
};

use super::admin::*;
use super::corruption::*;
use super::credential::*;
use super::recipient::*;
use super::route::*;
use super::tests::{approver, assert_names_the_approver, record_of};
use super::vault::*;
use super::{AuditEvent, EventName, RequestId};
use crate::admin::protocol::{AdminCommand, FrameError};
use crate::hardening::{LockUnavailable, MemoryProtection};
use crate::peer::PeerIdentity;
use crate::service_context::{DenialKind, UnlockRefusal};
use crate::service_state::ServiceState;

fn credential() -> CredentialName {
    "fx-key".parse().unwrap()
}

fn origins() -> Vec<(Host, Port)> {
    vec![("api.example".parse().unwrap(), "443".parse().unwrap())]
}

#[test]
fn initialization_events_carry_ids_step_labels_and_kinds_only() {
    let id = VaultId::new_random();
    let roles = [RecipientRole::Operational, RecipientRole::Recovery, RecipientRole::HostUnlock];
    let initialized = record_of(
        VaultInitialized {
            vault_id: id,
            recipients: &roles,
        },
        "INFO",
        &["vault_id", "recipients"],
    );
    assert_eq!(initialized["vault_id"], id.to_string().as_str());
    assert_eq!(initialized["recipients"], "operational,recovery,host-unlock");
    let files = ["init.unfinished".to_owned(), "identity.age".to_owned()];
    assert_eq!(
        record_of(InitDiscarded { files: &files }, "WARN", &["files"])["files"],
        "init.unfinished,identity.age"
    );
    let failed = InitFailed::Step {
        step: InitStep::PassphraseEnvelope,
        cause: &InitFailure::IdentityMismatch,
    };
    let record = record_of(failed, "WARN", &["step", "error_kind"]);
    assert_eq!(
        (record["step"].as_str(), record["error_kind"].as_str()),
        (Some("3"), Some("identity_mismatch"))
    );
    record_of(InitFailed::TaskEnded, "WARN", &[]);
}

/// A disk failure writing `recipients.age` is labelled like every other init write failure; the rest of the inventory
/// keeps its own labels.
#[test]
fn an_inventory_write_failure_is_a_state_write() {
    let label = |cause: InitFailure| {
        let failed = InitFailed::Step {
            step: InitStep::IdentityEnvelope,
            cause: &cause,
        };
        record_of(failed, "WARN", &["step", "error_kind"])["error_kind"]
            .as_str()
            .map(str::to_owned)
    };
    let disk = WriteError::ListStateDir {
        kind: std::io::ErrorKind::Other,
    };
    assert_eq!(label(InitFailure::InventoryWrite(disk.into())).as_deref(), Some("state_write"));
    assert_eq!(
        label(InitFailure::InventoryWrite(SealError::Encryption.into())).as_deref(),
        Some("recipient_inventory")
    );
    assert_eq!(
        label(InitFailure::InventoryMismatch).as_deref(),
        Some("recipient_inventory_mismatch")
    );
}

#[test]
fn a_presence_refusal_names_its_kind_and_the_approver_and_nothing_else() {
    [
        (DenialKind::WrongPassphrase, "wrong_passphrase"),
        (DenialKind::KeyMismatch, "key_mismatch"),
    ]
    .into_iter()
    .for_each(|(refusal, label)| {
        let event = PresenceRefused {
            refusal,
            approver: approver(),
        };
        let record = record_of(event, "WARN", &["refusal", "approver_id", "approver_label"]);
        assert_eq!(record["refusal"], label);
        assert_names_the_approver(&record);
    });
}

#[test]
fn a_foreign_file_name_is_escaped() {
    let record = record_of(ForeignFile { file: "a\u{202e}b\n.txt" }, "WARN", &["file"]);
    assert_eq!(record["file"], "a\\u{202e}b\\n.txt");
}

#[test]
fn an_unlock_refusal_is_a_snake_case_label() {
    let wrong = UnlockRefusal::Failed(UnlockError::WrongPassphrase);
    assert_eq!(
        record_of(UnlockRefused { refusal: &wrong }, "WARN", &["refusal"])["refusal"],
        "wrong_passphrase"
    );
    let unfinished = UnlockRefusal::Failed(UnlockError::InitializationUnfinished);
    assert_eq!(
        record_of(UnlockRefused { refusal: &unfinished }, "WARN", &["refusal"])["refusal"],
        "initialization_unfinished"
    );
}

#[test]
fn a_rate_limited_refusal_records_how_long_to_wait() {
    let refusal = UnlockRefusal::RateLimited(crate::attempt_limit::AttemptsCoolingDown { retry_after: 30 });
    let record = record_of(UnlockRefused { refusal: &refusal }, "WARN", &["refusal", "retry_after"]);
    assert_eq!(
        (record["refusal"].as_str(), record["retry_after"].as_u64()),
        (Some("rate_limited"), Some(30))
    );
}

#[test]
fn a_memory_unprotected_refusal_records_its_label_and_the_memory_protection_label() {
    [
        (
            MemoryProtection::Unavailable(LockUnavailable::LimitTooLow { limit_bytes: 65_536 }),
            "unavailable",
        ),
        (
            MemoryProtection::Unavailable(LockUnavailable::LockFailed {
                error: "Cannot allocate memory".to_owned(),
            }),
            "unavailable",
        ),
        (MemoryProtection::Unsupported, "unsupported"),
    ]
    .into_iter()
    .for_each(|(memory, label)| {
        let refusal = UnlockRefusal::MemoryUnprotected(memory);
        let record = record_of(UnlockRefused { refusal: &refusal }, "WARN", &["refusal", "memory_protection"]);
        assert_eq!(
            (record["refusal"].as_str(), record["memory_protection"].as_str()),
            (Some("memory_unprotected"), Some(label))
        );
        // The locking error is an OS error's text, so it stays out of the log.
        assert!(!record.to_string().contains("Cannot allocate memory"), "{record}");
    });
}

#[test]
fn an_incomplete_lock_records_numbers_and_a_boolean() {
    let record = record_of(
        LockIncomplete {
            snapshots_held: 2,
            identity_held: true,
        },
        "WARN",
        &["snapshots_held", "identity_held"],
    );
    assert_eq!(
        (record["snapshots_held"].as_u64(), record["identity_held"].as_bool()),
        (Some(2), Some(true))
    );
}

#[test]
fn write_report_events_name_files_and_a_kind() {
    let file = StateFileName::record(&RecordId::new_random());
    let record = record_of(UnindexedRemoved { file: &file }, "WARN", &["file"]);
    assert_eq!(record["file"], file.as_str());
    let kind = ErrorKindLabel::fixed("permission_denied");
    let record = record_of(
        SupersededLeft {
            file: &file,
            error_kind: &kind,
        },
        "WARN",
        &["file", "error_kind"],
    );
    assert_eq!(record["error_kind"], "permission_denied");
}

#[test]
fn credential_events_record_names_ids_kinds_and_origins() {
    let (name, id, old_id) = (credential(), RecordId::new_random(), RecordId::new_random());
    let origins = origins();
    let stored = Stored {
        kind: CredentialKind::Static,
        origins: &origins,
    };
    let record = record_of(
        CredentialAdded {
            credential: &name,
            record_id: id,
            stored,
        },
        "INFO",
        &["credential", "record_id", "kind", "origins"],
    );
    assert_eq!(
        (record["kind"].as_str(), record["origins"].as_str()),
        (Some("static"), Some("https://api.example:443"))
    );
    let replaced = |old| CredentialReplaced {
        credential: &name,
        old_record_id: old_id,
        record_id: id,
        stored,
        old,
    };
    let fields = ["credential", "old_record_id", "record_id", "kind", "origins"];
    record_of(replaced(None), "INFO", &fields);
    let healthy = record_of(
        replaced(Some(Stored {
            kind: CredentialKind::Basic,
            ..stored
        })),
        "INFO",
        &[&fields[..], &["old_kind", "old_origins"]].concat(),
    );
    assert_eq!(healthy["old_kind"], "basic");
    record_of(
        CredentialRemoved {
            credential: &name,
            record_id: id,
        },
        "INFO",
        &["credential", "record_id"],
    );
}

#[test]
fn caller_token_events_hold_no_token() {
    record_of(TokenIssued, "INFO", &[]);
    let kind = ErrorKindLabel::fixed("random_source");
    assert_eq!(
        record_of(TokenFailed { error_kind: &kind }, "ERROR", &["error_kind"])["error_kind"],
        "random_source"
    );
}

#[test]
fn route_and_scrub_events_name_the_route_and_never_a_path_or_byte() {
    let route: RouteName = "fx".parse().unwrap();
    let record = record_of(PinnedCaUnavailable { route: &route }, "WARN", &["route", "config_field"]);
    assert_eq!(record["config_field"], "ca_file");
    let name = credential();
    let record = record_of(
        ResponseScrubbed {
            request_id: RequestId::generate(),
            route: &route,
            credential: &name,
            matches: 4,
        },
        "WARN",
        &["request_id", "route", "credential", "matches"],
    );
    assert_eq!(record["matches"].as_u64(), Some(4));
}

#[test]
fn admin_events_name_a_command_and_a_peer_and_never_an_argument() {
    let peer = PeerIdentity::for_test(1000, 1000, 4242);
    let record = record_of(
        AdminCommandRead {
            command: AdminCommand::ConfigApprove,
            principal: peer,
        },
        "INFO",
        &["command", "principal_uid"],
    );
    assert_eq!(
        (record["command"].as_str(), record["principal_uid"].as_u64()),
        (Some("config_approve"), Some(1000))
    );
    let known = record_of(
        AdminRefused {
            refusal: AdminRefusal::NotAdminPrincipal,
            peer: Some(peer),
        },
        "WARN",
        &["refusal", "peer_uid", "peer_pid"],
    );
    assert_eq!(
        (known["refusal"].as_str(), known["peer_pid"].as_u64()),
        (Some("not_admin_principal"), Some(4242))
    );
    let unknown = record_of(
        AdminRefused {
            refusal: AdminRefusal::of_frame(FrameError::UnsupportedVersion(9)),
            peer: None,
        },
        "WARN",
        &["refusal"],
    );
    assert_eq!(unknown["refusal"], "unsupported_version");
}

#[test]
fn an_admin_refusal_leaves_out_a_pid_from_another_pid_namespace() {
    let record = record_of(
        AdminRefused {
            refusal: AdminRefusal::Busy,
            peer: Some(PeerIdentity::for_test_without_pid(0, 0)),
        },
        "WARN",
        &["refusal", "peer_uid"],
    );
    assert_eq!(record["peer_uid"].as_u64(), Some(0));
    assert!(record.get("peer_pid").is_none(), "{record}");
}

#[test]
fn a_wrong_state_unlock_refusal_is_recorded() {
    let record = record_of(
        UnlockRefused {
            refusal: &UnlockRefusal::WrongState(ServiceState::Ready),
        },
        "WARN",
        &["refusal"],
    );
    assert_eq!(record["refusal"], "wrong_state");
}

/// Every event of this module, for the test that no event records a constant field.
pub(super) const NAMES: [EventName; 25] = [
    AdminCommandRead::NAME,
    AdminRefused::NAME,
    VaultInitialized::NAME,
    InitDiscarded::NAME,
    InitFailed::NAME,
    ForeignFile::NAME,
    UnlockRefused::NAME,
    PresenceRefused::NAME,
    LockIncomplete::NAME,
    UnindexedRemoved::NAME,
    SupersededLeft::NAME,
    CredentialAdded::NAME,
    CredentialReplaced::NAME,
    CredentialRemoved::NAME,
    ShortSecretWritten::NAME,
    CommitUncertain::NAME,
    RecordDamaged::NAME,
    UnindexedFile::NAME,
    ApprovalStateUnrecorded::NAME,
    SharedStateDamaged::NAME,
    StateDirUnreadable::NAME,
    TokenIssued::NAME,
    TokenFailed::NAME,
    PinnedCaUnavailable::NAME,
    ResponseScrubbed::NAME,
];

/// Emits every event of this module, with each optional field both set and left out.
pub(super) fn emit_every_event() {
    let (name, id, old_id) = (credential(), RecordId::new_random(), RecordId::new_random());
    let (origins, route) = (origins(), "fx".parse::<RouteName>().unwrap());
    let stored = Stored {
        kind: CredentialKind::Static,
        origins: &origins,
    };
    let file = StateFileName::record(&id);
    let kind = ErrorKindLabel::fixed("random_source");
    let files = ["identity.age".to_owned()];
    AdminCommandRead {
        command: AdminCommand::Ping,
        principal: PeerIdentity::for_test(1, 1, 1),
    }
    .emit();
    [None, Some(PeerIdentity::for_test(1, 1, 1))].into_iter().for_each(|peer| {
        AdminRefused {
            refusal: AdminRefusal::Busy,
            peer,
        }
        .emit();
    });
    VaultInitialized {
        vault_id: VaultId::new_random(),
        recipients: &[],
    }
    .emit();
    InitDiscarded { files: &files }.emit();
    InitFailed::Step {
        step: InitStep::Finish,
        cause: &InitFailure::IdentityMismatch,
    }
    .emit();
    InitFailed::TaskEnded.emit();
    ForeignFile { file: "x" }.emit();
    UnlockRefused {
        refusal: &UnlockRefusal::Interrupted,
    }
    .emit();
    PresenceRefused {
        refusal: DenialKind::KeyMismatch,
        approver: approver(),
    }
    .emit();
    LockIncomplete {
        snapshots_held: 1,
        identity_held: false,
    }
    .emit();
    UnindexedRemoved { file: &file }.emit();
    SupersededLeft {
        file: &file,
        error_kind: &kind,
    }
    .emit();
    CredentialAdded {
        credential: &name,
        record_id: id,
        stored,
    }
    .emit();
    [None, Some(stored)].into_iter().for_each(|old| {
        CredentialReplaced {
            credential: &name,
            old_record_id: old_id,
            record_id: id,
            stored,
            old,
        }
        .emit();
    });
    CredentialRemoved {
        credential: &name,
        record_id: id,
    }
    .emit();
    emit_corruption_events(&name, id, &kind);
    TokenIssued.emit();
    TokenFailed { error_kind: &kind }.emit();
    PinnedCaUnavailable { route: &route }.emit();
    ResponseScrubbed {
        request_id: RequestId::generate(),
        route: &route,
        credential: &name,
        matches: 1,
    }
    .emit();
}

fn emit_corruption_events(name: &CredentialName, id: RecordId, kind: &ErrorKindLabel) {
    let file = StateFileName::record(&id);
    ShortSecretWritten {
        credential: name,
        field: SecretField::Key,
        len: 3,
    }
    .emit();
    CommitUncertain {
        file: &StateFileName::manifest(),
        error_kind: kind,
    }
    .emit();
    [None, Some(kind.clone())].into_iter().for_each(|error_kind| {
        let record = DamagedRecord {
            credential: name.clone(),
            record_id: id,
            file: file.clone(),
            damage: RecordDamage::Unreadable,
            error_kind,
        };
        RecordDamaged { record: &record }.emit();
    });
    UnindexedFile { file: &file }.emit();
    ApprovalStateUnrecorded.emit();
    SharedStateDamaged {
        file: &StateFileName::manifest(),
        damage: &SharedStateDamage::MissingWithRecords,
    }
    .emit();
    StateDirUnreadable { error_kind: kind }.emit();
}

#[test]
fn recovery_checked_carries_its_outcome_and_fixed_labels_only() {
    use super::recovery::RecoveryChecked;
    use iron_vault_store::{MalformedReason, RecoveryCheckError};
    let id = VaultId::new_random();
    let saved = record_of(
        RecoveryChecked::Opened {
            vault_id: id,
            record_error: None,
        },
        "INFO",
        &["recovery_outcome", "vault_id", "recorded"],
    );
    assert_eq!(
        (saved["recovery_outcome"].as_str(), saved["recorded"].as_bool()),
        (Some("opened"), Some(true))
    );
    let unsaved = record_of(
        RecoveryChecked::Opened {
            vault_id: id,
            record_error: Some(ErrorKindLabel::fixed("permission_denied")),
        },
        "INFO",
        &["recovery_outcome", "vault_id", "recorded", "error_kind"],
    );
    assert_eq!(
        (unsaved["recorded"].as_bool(), unsaved["error_kind"].as_str()),
        (Some(false), Some("permission_denied"))
    );
    let failed = record_of(
        RecoveryChecked::Failed(&RecoveryCheckError::IdentityNotGenuine),
        "WARN",
        &["recovery_outcome", "recovery_failure"],
    );
    assert_eq!(failed["recovery_failure"], "identity_unverified");
    record_of(RecoveryChecked::Invalid, "WARN", &["recovery_outcome"]);
    let unreadable = RecoveryCheckError::EnvelopeMalformed {
        file: StateFileName::manifest(),
        reason: MalformedReason::TooLarge,
    };
    let unavailable = record_of(
        RecoveryChecked::Unavailable(&unreadable),
        "WARN",
        &["recovery_outcome", "file", "error_kind"],
    );
    assert_eq!(
        (unavailable["file"].as_str(), unavailable["error_kind"].as_str()),
        (Some("manifest.age"), Some("too_large"))
    );
}

#[test]
fn recovery_reminder_carries_the_fields_of_its_record_form() {
    use super::recovery::{REMINDER_REMEDIATION, RecoveryReminder};
    use crate::recovery_reminder::{Due, RecordState};
    use iron_vault_store::UtcSecond;
    let time = UtcSecond::from_unix_seconds(1_793_958_553).unwrap();
    let fields = |extra: &'static str| ["recovery_record", extra, "reminder_days", "remediation"];

    let checked = record_of(
        RecoveryReminder(&Due {
            record: RecordState::Checked(time),
            reminder_days: 90,
        }),
        "INFO",
        &fields("last_checked"),
    );
    assert_eq!(checked["recovery_record"], "checked");
    assert_eq!(checked["last_checked"], "2026-11-06T09:49:13Z");
    assert_eq!(
        (checked["reminder_days"].as_u64(), checked["remediation"].as_str()),
        (Some(90), Some(REMINDER_REMEDIATION))
    );

    let never = record_of(
        RecoveryReminder(&Due {
            record: RecordState::NeverChecked(time),
            reminder_days: 7,
        }),
        "INFO",
        &fields("reminders_since"),
    );
    assert_eq!(
        (never["recovery_record"].as_str(), never["reminders_since"].as_str()),
        (Some("never_checked"), Some("2026-11-06T09:49:13Z"))
    );

    let unusable = record_of(
        RecoveryReminder(&Due {
            record: RecordState::Unusable(ErrorKindLabel::fixed("not_toml")),
            reminder_days: 90,
        }),
        "INFO",
        &fields("error_kind"),
    );
    assert_eq!(
        (unusable["recovery_record"].as_str(), unusable["error_kind"].as_str()),
        (Some("unusable"), Some("not_toml"))
    );
}

#[test]
fn recipient_inventory_events_carry_fixed_labels_only() {
    use super::recipient::*;
    use iron_vault_store::{ChangeRecovery, InventoryDamage};
    let record = record_of(InventoryDamaged(InventoryDamage::EnvelopeMismatch), "WARN", &["inventory_damage"]);
    assert_eq!(record["inventory_damage"], "envelope_mismatch");
    let record = record_of(ChangeRecovered(ChangeRecovery::Discarded), "WARN", &["recovery"]);
    assert_eq!(record["recovery"], "discarded");
}

#[test]
fn a_removed_recipients_label_is_escaped() {
    let (_, key) = iron_vault_store::RecoveryKey::generate();
    let label = RecipientLabel::new("caf\u{e9} laptop").unwrap();
    let entry = RecipientEntry::new(key, RecipientRole::Added, label, UtcSecond::from_unix_seconds(0).unwrap());
    let fields = ["recipient", "recipient_role", "recipient_label", "recipients"];

    let record = record_of(
        Removed {
            entry: &entry,
            recipients: 2,
        },
        "INFO",
        &fields,
    );

    assert_eq!(record["recipient_label"], "caf\\u{e9} laptop");
    // A control or format character never reaches the log: the label rule refuses it on construction.
    assert!(RecipientLabel::new("a\nb").is_err() && RecipientLabel::new("a\u{202e}b").is_err());
}

#[test]
fn recipient_added_escapes_the_owner_label_and_a_failure_carries_its_write_details() {
    use super::recipient::*;
    use iron_vault_store::{ChangeCommitted, RecipientEntry, RecipientLabel, RecipientRole, UtcSecond};
    let key: iron_vault_store::RecipientKey = "age1v4q6gqhc84l6yrmyeqcske956a65frdww5rc4jnrdfhkpsdglqksx4muhw".parse().unwrap();
    let entry = RecipientEntry::new(
        key.clone(),
        RecipientRole::Added,
        RecipientLabel::new("caf\u{e9} \"laptop\"").unwrap(),
        UtcSecond::from_unix_seconds(1_794_060_171).unwrap(),
    );
    let record = record_of(
        Added {
            entry: &entry,
            recipients: 3,
        },
        "INFO",
        &["recipient", "recipient_role", "recipient_label", "recipients"],
    );
    let (role, label, count) = (
        record["recipient_role"].as_str(),
        record["recipient_label"].as_str(),
        record["recipients"].as_u64(),
    );
    assert_eq!((role, count), (Some("added"), Some(3)));
    assert_eq!(label, Some(r#"caf\u{e9} "laptop""#));

    let refused = record_of(
        ChangeFailed {
            change: "add",
            recipient: &key,
            failure: ChangeFailure::AlreadyEnrolled,
        },
        "WARN",
        &["change", "recipient", "failure"],
    );
    assert_eq!(
        (refused["change"].as_str(), refused["failure"].as_str()),
        (Some("add"), Some("already_enrolled"))
    );
    let failed = ChangeFailure::WriteFailed {
        step: Some(iron_vault_store::RecipientChangeStep::Envelope),
        error_kind: iron_vault_store::ErrorKindLabel::fixed("permission_denied"),
        committed: ChangeCommitted::Unknown,
    };
    let record = record_of(
        ChangeFailed {
            change: "add",
            recipient: &key,
            failure: failed,
        },
        "WARN",
        &["change", "recipient", "failure", "step", "error_kind", "committed"],
    );
    assert_eq!(
        (record["step"].as_str(), record["error_kind"].as_str(), record["committed"].as_str()),
        (Some("envelope"), Some("permission_denied"), Some("unknown"))
    );
}
