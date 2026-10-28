//! Loading one record file and classifying it against its manifest entry.

use std::collections::BTreeMap;
use std::fmt;
use std::io;

use iron_vault_policy::CredentialName;

use super::RecordDamage;
use crate::{
    CredentialRecord, ManifestEntry, ReadError, RecordId, StateDirLock, StateFileName, StoreFs, VaultIdentity, VaultManifest, decode, open,
    read_state_file, record_digest,
};

/// The largest record file accepted, in bytes on disk; a longer file is damaged and is never read in full.
///
/// A v0 record holds a name of at most 64 bytes, a handful of permitted origins of at most 263 bytes each, and a
/// static key or a Basic username and password. Real provider keys and passwords are well under 1 KiB, so a record is
/// a few KiB at most even with dozens of origins. 64 KiB leaves room for later kinds' private keys and certificates
/// while bounding the memory a planted or corrupt file can take.
pub const MAX_RECORD_FILE_LEN: u64 = 64 * 1024;

/// The largest record payload accepted. An `age` file is never shorter than its plaintext, so a file within
/// [`MAX_RECORD_FILE_LEN`] never reaches this; it bounds decryption on its own all the same.
const MAX_RECORD_PLAINTEXT: usize = 64 * 1024;

/// Why one record did not load: the reported damage, and a cause for the log that never holds file contents.
struct Damage {
    damage: RecordDamage,
    cause: String,
}

impl Damage {
    fn new(damage: RecordDamage, cause: impl fmt::Display) -> Self {
        Self {
            damage,
            cause: cause.to_string(),
        }
    }
}

/// Loads every record `manifest` lists, returning the healthy records and the damage of the others, both by name.
pub(super) fn load_records(
    lock: &StateDirLock,
    fs: &impl StoreFs,
    identity: &VaultIdentity,
    manifest: &VaultManifest,
) -> (BTreeMap<CredentialName, CredentialRecord>, BTreeMap<CredentialName, RecordDamage>) {
    let outcomes = manifest
        .entries()
        .iter()
        .map(|(id, entry)| (*id, entry, load_record(lock, fs, identity, *id, entry)));
    outcomes.fold(
        (BTreeMap::new(), BTreeMap::new()),
        |(mut healthy, mut damaged), (id, entry, outcome)| {
            match outcome {
                Ok(record) => {
                    healthy.insert(entry.name().clone(), record);
                }
                Err(damage) => {
                    log_damage(id, entry, &damage);
                    damaged.insert(entry.name().clone(), damage.damage);
                }
            }
            (healthy, damaged)
        },
    )
}

/// Reads the record file `entry` vouches for, checks its digest, and only then decrypts, decodes and checks it is the
/// record the entry names.
///
/// Anyone with the vault's public key can write a well-formed, validly encrypted record file, so the manifest digest is
/// the only proof that a file is the one the vault wrote. A file whose digest differs is reported as substituted and is
/// never decrypted or decoded: its contents may be hostile, and refusing it unread keeps them away from `age` and the
/// decoder. A file whose digest matches but still does not open is unreadable, which only a bug or a damaged vault
/// identity can cause.
fn load_record(
    lock: &StateDirLock,
    fs: &impl StoreFs,
    identity: &VaultIdentity,
    id: RecordId,
    entry: &ManifestEntry,
) -> Result<CredentialRecord, Damage> {
    let bytes = read_state_file(lock, fs, &StateFileName::record(&id), MAX_RECORD_FILE_LEN).map_err(read_damage)?;
    if record_digest(&bytes) != *entry.file_digest() {
        return Err(Damage::new(
            RecordDamage::Substituted,
            "the file's digest differs from its manifest entry",
        ));
    }
    let payload = open(identity, &bytes, MAX_RECORD_PLAINTEXT).map_err(|e| {
        Damage::new(
            RecordDamage::Unreadable,
            format_args!("the file matches its digest but does not decrypt: {e}"),
        )
    })?;
    let record = decode(&payload).map_err(|e| {
        Damage::new(
            RecordDamage::Unreadable,
            format_args!("the file matches its digest but does not decode: {e}"),
        )
    })?;
    match record.id() == id && record.name() == entry.name() {
        true => Ok(record),
        false => Err(Damage::new(
            RecordDamage::Substituted,
            format_args!("the file holds record {} named {}", record.id(), record.name()),
        )),
    }
}

fn read_damage(error: ReadError) -> Damage {
    match error {
        ReadError::Io {
            kind: io::ErrorKind::NotFound,
            ..
        } => Damage::new(RecordDamage::Missing, "the file does not exist"),
        other => Damage::new(RecordDamage::Unreadable, other),
    }
}

/// One loud event per damaged record, with what an administrator needs to find and fix it and nothing from the file.
fn log_damage(id: RecordId, entry: &ManifestEntry, damage: &Damage) {
    tracing::error!(
        credential = %entry.name(),
        record_id = %id,
        file = %StateFileName::record(&id),
        reason = %damage.damage,
        cause = %damage.cause,
        remediation = damage.damage.remediation(),
        "credential record is damaged and was not loaded; routes that use this credential are unavailable"
    );
}

/// One event per record file the manifest does not list.
pub(super) fn log_unindexed(file: &StateFileName) {
    tracing::warn!(
        file = %file,
        remediation = "the vault manifest does not list this file, so it is ignored and the next vault write removes it; \
             if no write was interrupted, investigate who can write to the state directory",
        "record file is not in the vault manifest and was not loaded"
    );
}
