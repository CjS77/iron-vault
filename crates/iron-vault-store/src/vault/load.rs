//! Loading the record files the manifest lists, each classified against its manifest entry as healthy or damaged.

use std::collections::BTreeMap;
use std::io;

use iron_vault_policy::CredentialName;

use super::{DamagedRecord, RecordDamage};
use crate::{
    CredentialRecord, ErrorKindLabel, ManifestEntry, ReadError, RecordId, StateDirLock, StateFileName, StoreFs, VaultIdentity,
    VaultManifest, decode, open, read_state_file, record_digest,
};

/// The largest record file accepted, in bytes on disk. A longer file is damaged and is never read in full.
///
/// A v0 record holds a name of at most 64 bytes, a handful of permitted origins of at most 263 bytes each, and a
/// static key or a Basic username and password. Real provider keys and passwords are well under 1 KiB, so a record is
/// a few KiB at most even with dozens of origins. 64 KiB leaves room for later kinds' private keys and certificates
/// while bounding the memory a planted or corrupt file can take.
pub const MAX_RECORD_FILE_LEN: u64 = 64 * 1024;

/// The largest record payload accepted. An `age` file is never shorter than its plaintext, so a file within
/// [`MAX_RECORD_FILE_LEN`] never reaches this, but it bounds decryption without relying on the file limit.
const MAX_RECORD_PLAINTEXT: usize = 64 * 1024;

/// Why one record did not load: the reported damage, and the kind of the read failure when reading the file failed.
struct Damage {
    damage: RecordDamage,
    error_kind: Option<ErrorKindLabel>,
}

impl Damage {
    fn new(damage: RecordDamage) -> Self {
        Self { damage, error_kind: None }
    }

    fn read_failed(damage: RecordDamage, error_kind: ErrorKindLabel) -> Self {
        Self {
            damage,
            error_kind: Some(error_kind),
        }
    }
}

/// Loads every record `manifest` lists, returning the healthy records by name and the facts of the damaged ones.
pub(super) fn load_records(
    lock: &StateDirLock,
    fs: &impl StoreFs,
    identity: &VaultIdentity,
    manifest: &VaultManifest,
) -> (BTreeMap<CredentialName, CredentialRecord>, Vec<DamagedRecord>) {
    let outcomes = manifest
        .entries()
        .iter()
        .map(|(id, entry)| (*id, entry, load_record(lock, fs, identity, *id, entry)));
    outcomes.fold((BTreeMap::new(), Vec::new()), |(mut healthy, mut damaged), (id, entry, outcome)| {
        match outcome {
            Ok(record) => _ = healthy.insert(entry.name().clone(), record),
            Err(Damage { damage, error_kind }) => damaged.push(DamagedRecord {
                credential: entry.name().clone(),
                record_id: id,
                file: StateFileName::record(&id),
                damage,
                error_kind,
            }),
        }
        (healthy, damaged)
    })
}

/// Reads the record file `entry` vouches for and checks its digest. Only then does it decrypt and decode the file, and
/// check that it is the record the entry names.
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
        return Err(Damage::new(RecordDamage::Substituted));
    }
    let payload = open(identity, &bytes, MAX_RECORD_PLAINTEXT).map_err(|_| Damage::new(RecordDamage::Unreadable))?;
    let record = decode(&payload).map_err(|_| Damage::new(RecordDamage::Unreadable))?;
    match record.id() == id && record.name() == entry.name() {
        true => Ok(record),
        false => Err(Damage::new(RecordDamage::Substituted)),
    }
}

fn read_damage(error: ReadError) -> Damage {
    match error {
        ReadError::Io {
            kind: io::ErrorKind::NotFound,
            ..
        } => Damage::new(RecordDamage::Missing),
        ReadError::Io { kind, .. } => Damage::read_failed(RecordDamage::Unreadable, ErrorKindLabel::from(kind)),
        ReadError::TooLarge { .. } => Damage::read_failed(RecordDamage::Unreadable, ErrorKindLabel::fixed("too_large")),
        ReadError::NotARegularFile { .. } => Damage::read_failed(RecordDamage::Unreadable, ErrorKindLabel::fixed("not_a_regular_file")),
    }
}
