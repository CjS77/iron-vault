//! The approval reservation, commit and recovery events: each writes its name, level and exactly its own fields.

use iron_vault_store::{ApprovalVersion, ConfigDigest, ConfigFileName, DiscardedFile, ErrorKindLabel, PublishSet};

use super::config::*;
use super::tests::{approver, assert_names_the_approver, record_of};
use super::{AuditEvent, EventName};

fn version(value: u64) -> ApprovalVersion {
    ApprovalVersion::new(value).unwrap()
}

fn discarded(file: ConfigFileName, signed_for: Option<u64>) -> DiscardedFile {
    DiscardedFile {
        file,
        signed_for: signed_for.map(version),
        conflicting: false,
    }
}

#[test]
fn a_reserved_version_and_an_uncertain_commit_record_numbers_and_a_kind() {
    let digest = ConfigDigest::of(b"config");
    let record = record_of(
        VersionReserved {
            version: version(4),
            digest,
            approver: approver(),
        },
        "INFO",
        &["version", "config_digest", "approver_id", "approver_label"],
    );
    assert_eq!(
        (record["version"].as_u64(), record["config_digest"].as_str()),
        (Some(4), Some(digest.to_string().as_str()))
    );
    assert_names_the_approver(&record);
    let kind = ErrorKindLabel::fixed("storage_full");
    let record = record_of(
        CommitUncertain {
            version: version(4),
            error_kind: &kind,
        },
        "WARN",
        &["version", "error_kind"],
    );
    assert_eq!(
        (record["version"].as_u64(), record["error_kind"].as_str()),
        (Some(4), Some("storage_full"))
    );
}

#[test]
fn recovery_events_name_files_and_versions_only() {
    let record = record_of(
        RecoveryPublished {
            version: version(2),
            renames: PublishSet::Both,
        },
        "WARN",
        &["version", "renames"],
    );
    assert_eq!(record["renames"], "config.toml,config.toml.sig");
    let record = record_of(
        RecoveryDiscarded {
            discarded: discarded(ConfigFileName::StagedSignature, Some(3)),
        },
        "INFO",
        &["file", "signed_for"],
    );
    assert_eq!(
        (record["file"].as_str(), record["signed_for"].as_u64()),
        (Some("config.toml.sig.staged"), Some(3))
    );
    record_of(
        RecoveryDiscarded {
            discarded: discarded(ConfigFileName::Pending, None),
        },
        "INFO",
        &["file"],
    );
    let record = record_of(ConflictingApprovalDiscarded { version: version(2) }, "ERROR", &["version"]);
    assert_eq!(record["version"].as_u64(), Some(2));
}

/// Every event of this module, for the test that no event records a constant field.
pub(super) const NAMES: [EventName; 5] = [
    VersionReserved::NAME,
    CommitUncertain::NAME,
    RecoveryPublished::NAME,
    RecoveryDiscarded::NAME,
    ConflictingApprovalDiscarded::NAME,
];

/// Emits every event of this module, with each optional field both set and left out.
pub(super) fn emit_every_event() {
    let kind = ErrorKindLabel::fixed("storage_full");
    VersionReserved {
        version: version(1),
        digest: ConfigDigest::of(b""),
        approver: approver(),
    }
    .emit();
    CommitUncertain {
        version: version(1),
        error_kind: &kind,
    }
    .emit();
    RecoveryPublished {
        version: version(1),
        renames: PublishSet::ConfigOnly,
    }
    .emit();
    [Some(2), None].into_iter().for_each(|signed_for| {
        RecoveryDiscarded {
            discarded: discarded(ConfigFileName::StagedSignature, signed_for),
        }
        .emit()
    });
    ConflictingApprovalDiscarded { version: version(1) }.emit();
}
