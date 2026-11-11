use std::cell::Cell;
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::io::Read;
use std::sync::{Mutex, PoisonError};

use iron_vault_kinds::CredentialMaterial;
use iron_vault_policy::Port;
use secrecy::SecretString;

use super::*;
use crate::fault_fs::{FaultFs, FsOp};
use crate::manifest::tests::KAT_IDENTITY;
use crate::migration_bundle::{BundleDecoder, DecodedBundle};
use crate::test_dir::TestDir;
use crate::test_request::HOST;
use crate::{
    ApprovalPassphrase, MAX_CONFIG_LEN, PermittedOrigins, PinnedApprover, SoftwareSigner, Vault, VaultManifest, durable_remove,
    durable_replace, open_bundled_approver_key, open_exported_identity, seal_manifest, seal_signer_key_for_tests, write_signer_key,
};

pub(crate) const CONFIG: &[u8] = b"schema_version = 1\n";

/// Sealing the exported identity takes 256 MiB of scrypt memory, so the tests that stream take turns.
static SEALING: Mutex<()> = Mutex::new(());

pub(crate) fn one_at_a_time() -> std::sync::MutexGuard<'static, ()> {
    SEALING.lock().unwrap_or_else(PoisonError::into_inner)
}

pub(crate) fn passphrase() -> ExportPassphrase {
    ExportPassphrase::new(SecretString::from("export phrase 1")).unwrap()
}

/// An approver key envelope sealed at a cheap work factor.
pub(crate) fn approver_key() -> Vec<u8> {
    let (key, _) = SoftwareSigner::generate().unwrap();
    seal_signer_key_for_tests(&key, &ApprovalPassphrase::new(SecretString::from("approval phrase")).unwrap()).unwrap()
}

/// `envelope` with its scrypt stanza's work factor (2) replaced by `log_n`.
pub(crate) fn with_work_factor(envelope: &[u8], log_n: u8) -> Vec<u8> {
    let line_end = 22 + envelope[22..].iter().position(|&b| b == b'\n').unwrap();
    [&envelope[..line_end - 2], format!(" {log_n}").as_bytes(), &envelope[line_end..]].concat()
}

fn noise(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i.wrapping_mul(31) ^ (i >> 3)) as u8).collect()
}

/// A vault with three records and two approvers, a committed config and a second reserved version, all in a [`FaultFs`].
pub(crate) struct Fixture {
    _dirs: (TestDir, TestDir),
    pub(crate) state: StateDirLock,
    config: ConfigDirLock,
    pub(crate) fs: FaultFs,
    pub(crate) identity: VaultIdentity,
    pub(crate) held: ApprovalState,
    pub(crate) records: Vec<RecordId>,
    /// `approval.age` as it was before the last two versions were reserved: a valid file that is not `held`.
    pub(crate) older_approval: Vec<u8>,
}

impl Fixture {
    pub(crate) fn new() -> Self {
        Self::with_config_on_disk(CONFIG)
    }

    /// The approval commits to [`CONFIG`]; `config_on_disk` is what `config.toml` holds.
    fn with_config_on_disk(config_on_disk: &[u8]) -> Self {
        let dirs = (TestDir::new("export-state"), TestDir::new("export-config"));
        let (state, config) = (
            StateDirLock::acquire(dirs.0.path()).unwrap(),
            ConfigDirLock::acquire(dirs.1.path()).unwrap(),
        );
        let fs = FaultFs::new()
            .with_durable_file(&dirs.0.path().join("lock"), b"")
            .with_durable_file(&dirs.1.path().join("config.toml"), config_on_disk);
        let identity = VaultIdentity::from_secret(KAT_IDENTITY);
        let mut vault = Vault::create_with_id(&state, &fs, VaultIdentity::from_secret(KAT_IDENTITY), VaultId::new_random()).unwrap();
        ["fx_key", "brave_key", "venice_key"].iter().for_each(|name| {
            let origins = PermittedOrigins::new([(HOST.parse().unwrap(), Port::HTTPS)].into()).unwrap();
            let material = CredentialMaterial::Static {
                key: SecretString::from(format!("SECRET-{name}")),
            };
            vault.add(&state, &fs, name.parse().unwrap(), material, origins).unwrap();
        });
        let (mut held, _) = vault.create_approval_state(&state, &fs, PinnedApprover::from_seed(1)).unwrap();
        held.enroll_approver(&state, &fs, &identity, PinnedApprover::from_seed(2)).unwrap();
        let older_approval = read(&state, &fs, &StateFileName::approval_state());
        let version = held.reserve(&state, &fs, &identity).unwrap();
        held.commit(&state, &fs, &identity, version, ConfigDigest::of(CONFIG)).unwrap();
        held.reserve(&state, &fs, &identity).unwrap();
        held.approvers()
            .iter()
            .for_each(|approver| write_signer_key(&state, &fs, approver.id(), &approver_key()).unwrap());
        let records = vault.manifest().entries().keys().copied().collect();
        Self {
            _dirs: dirs,
            state,
            config,
            fs,
            identity,
            held,
            records,
            older_approval,
        }
    }

    fn check(&self) -> Result<SnapshotSummary, SnapshotError> {
        check_export_snapshot(&self.state, &self.config, &self.fs, &self.identity, &self.held)
    }

    pub(crate) fn stream(&self, sink: impl Write) -> Result<ExportedBundle, SnapshotError> {
        stream_export_snapshot(&self.state, &self.config, &self.fs, &self.identity, &self.held, passphrase(), sink)
    }

    pub(crate) fn file(&self, name: &StateFileName) -> Vec<u8> {
        read(&self.state, &self.fs, name)
    }

    fn put(&self, name: &StateFileName, bytes: &[u8]) {
        durable_replace(&self.state, &self.fs, name, bytes).unwrap();
    }

    fn approver_file(&self) -> StateFileName {
        StateFileName::approver_key(self.held.approvers()[0].id())
    }

    fn first_record(&self) -> RecordId {
        self.records[0]
    }

    /// Runs the check, which must refuse at the check step, name `file` and write nothing.
    fn refusal(&self, file: EntryName) -> SnapshotError {
        let from = self.fs.trace().len();
        let error = self.check().unwrap_err();
        assert_eq!((error.step(), error.file()), (SnapshotStep::Check, Some(file)), "{error}");
        assert_nothing_written(&self.fs, from);
        error
    }
}

fn read(lock: &StateDirLock, fs: &FaultFs, name: &StateFileName) -> Vec<u8> {
    crate::read_state_file(lock, fs, name, MAX_MANIFEST_LEN as u64).unwrap()
}

/// The calls since call `from` changed no file and no directory entry.
fn assert_nothing_written(fs: &FaultFs, from: usize) {
    let writes = [
        FsOp::CreatePrivate,
        FsOp::WriteAll,
        FsOp::SyncFile,
        FsOp::Rename,
        FsOp::RemoveFile,
        FsOp::SyncDir,
    ];
    let trace = fs.trace().split_off(from);
    assert!(trace.iter().all(|call| !writes.contains(&call.op())), "{trace:?}");
}

pub(crate) fn decode(bytes: &[u8]) -> DecodedBundle {
    let mut decoder = BundleDecoder::new();
    decoder.push(bytes).unwrap();
    decoder.finish().unwrap()
}

#[test]
fn the_check_summarizes_the_vault_and_writes_nothing() {
    let fixture = Fixture::new();
    let from = fixture.fs.trace().len();
    let summary = fixture.check().unwrap();
    assert_eq!(summary.vault_id, fixture.held.vault_id());
    assert_eq!((summary.record_count, summary.approver_count), (3, 2));
    assert_eq!((summary.committed_version.get(), summary.highest_reserved), (1, 2));
    assert_nothing_written(&fixture.fs, from);
}

#[test]
fn the_stream_decodes_to_the_files_it_read() {
    let _turn = one_at_a_time();
    let fixture = Fixture::new();
    let mut bytes = Vec::new();
    let from = fixture.fs.trace().len();
    let exported = fixture.stream(&mut bytes).unwrap();
    assert_nothing_written(&fixture.fs, from);
    assert_eq!(exported.summary, fixture.check().unwrap());
    assert_eq!(exported.byte_count, bytes.len() as u64);

    let bundle = decode(&bytes);
    assert_eq!(bundle.header().vault_id(), fixture.held.vault_id());
    assert_eq!(
        bundle.entry(&EntryName::Manifest).unwrap(),
        fixture.file(&StateFileName::manifest())
    );
    assert_eq!(
        bundle.entry(&EntryName::ApprovalState).unwrap(),
        fixture.file(&StateFileName::approval_state())
    );
    assert_eq!(bundle.entry(&EntryName::Config).unwrap(), CONFIG);
    fixture.records.iter().for_each(|id| {
        assert_eq!(
            bundle.entry(&EntryName::Record(*id)).unwrap(),
            fixture.file(&StateFileName::record(id))
        )
    });
    fixture.held.approvers().iter().for_each(|approver| {
        let bundled = bundle.entry(&EntryName::Approver(approver.id())).unwrap();
        let original = fixture.file(&StateFileName::approver_key(approver.id()));
        assert_eq!(open_bundled_approver_key(bundled, &fixture.identity).unwrap(), original);
    });
    let sealed = bundle.entry(&EntryName::ExportedIdentity).unwrap();
    let opened = open_exported_identity(sealed, &passphrase()).unwrap();
    assert_eq!(opened.public_key(), fixture.identity.public_key());
}

#[test]
fn a_record_file_of_random_bytes_exports_when_its_digest_is_in_the_manifest() {
    let _turn = one_at_a_time();
    let fixture = Fixture::new();
    let (id, random) = (fixture.first_record(), noise(300));
    let manifest = open_manifest(&fixture.identity, &fixture.file(&StateFileName::manifest())).unwrap();
    let entries: BTreeMap<_, _> = manifest
        .entries()
        .iter()
        .map(|(entry_id, entry)| match *entry_id == id {
            true => (*entry_id, ManifestEntry::new(entry.name().clone(), record_digest(&random))),
            false => (*entry_id, entry.clone()),
        })
        .collect();
    let rewritten = VaultManifest::new(
        manifest.vault_id(),
        manifest.state_generation(),
        manifest.peer_generation(),
        entries,
    )
    .unwrap();
    fixture.put(&StateFileName::manifest(), &seal_manifest(&fixture.identity, &rewritten).unwrap());
    fixture.put(&StateFileName::record(&id), &random);

    let mut bytes = Vec::new();
    fixture.stream(&mut bytes).unwrap();
    assert_eq!(decode(&bytes).entry(&EntryName::Record(id)).unwrap(), random);
}

#[test]
fn a_missing_record_file_is_refused_naming_the_record() {
    let fixture = Fixture::new();
    let id = fixture.first_record();
    durable_remove(&fixture.state, &fixture.fs, &StateFileName::record(&id)).unwrap();
    let error = fixture.refusal(EntryName::Record(id));
    assert_eq!(error.error_kind_label().as_str(), "not_found");
    assert!(error.to_string().contains(&id.to_string()));
}

#[test]
fn a_record_file_that_differs_from_its_digest_is_refused_naming_the_record() {
    let fixture = Fixture::new();
    let id = fixture.first_record();
    fixture.put(&StateFileName::record(&id), &noise(200));
    let error = fixture.refusal(EntryName::Record(id));
    assert!(matches!(
        error,
        SnapshotError::Damaged {
            damage: SnapshotDamage::DigestMismatch,
            ..
        }
    ));
}

#[test]
fn a_missing_approver_key_file_is_refused_naming_the_approver() {
    let fixture = Fixture::new();
    let id = fixture.held.approvers()[1].id();
    durable_remove(&fixture.state, &fixture.fs, &StateFileName::approver_key(id)).unwrap();
    let error = fixture.refusal(EntryName::Approver(id));
    assert_eq!(error.error_kind_label().as_str(), "not_found");
}

#[test]
fn an_approver_key_file_of_the_wrong_form_is_refused_naming_the_approver() {
    let key = approver_key();
    let x25519 = seal_bundled_approver_key(b"x", &VaultIdentity::generate().public_key()).unwrap();
    let cases = [
        ("over 1 KiB", vec![0; MAX_PASSPHRASE_ENVELOPE_LEN + 1]),
        ("an X25519 stanza", x25519),
        ("work factor 21", with_work_factor(&key, 21)),
    ];
    cases.iter().for_each(|(label, bytes)| {
        let fixture = Fixture::new();
        fixture.put(&fixture.approver_file(), bytes);
        let error = fixture.refusal(EntryName::Approver(fixture.held.approvers()[0].id()));
        assert!(
            matches!(error, SnapshotError::Damaged { .. } | SnapshotError::Unreadable { .. }),
            "{label}"
        );
    });
}

#[test]
fn a_config_edited_by_hand_is_refused() {
    let fixture = Fixture::with_config_on_disk(b"schema_version = 2\n");
    let error = fixture.refusal(EntryName::Config);
    assert!(matches!(
        error,
        SnapshotError::Damaged {
            damage: SnapshotDamage::DigestMismatch,
            ..
        }
    ));
}

#[test]
fn a_config_over_the_limit_is_refused() {
    let fixture = Fixture::with_config_on_disk(&vec![b'#'; MAX_CONFIG_LEN + 1]);
    let error = fixture.refusal(EntryName::Config);
    assert_eq!(error.error_kind_label().as_str(), "too_large");
}

#[test]
fn an_approval_state_that_differs_from_the_held_one_is_refused() {
    let fixture = Fixture::new();
    fixture.put(&StateFileName::approval_state(), &fixture.older_approval);
    let error = fixture.refusal(EntryName::ApprovalState);
    assert!(matches!(
        error,
        SnapshotError::Damaged {
            damage: SnapshotDamage::NotHeld,
            ..
        }
    ));
}

#[test]
fn the_stream_repeats_the_checks_before_it_seals_or_writes() {
    let fixture = Fixture::new();
    durable_remove(
        &fixture.state,
        &fixture.fs,
        &StateFileName::approver_key(fixture.held.approvers()[1].id()),
    )
    .unwrap();
    let mut bytes = Vec::new();
    let error = fixture.stream(&mut bytes).unwrap_err();
    assert_eq!(
        (error.step(), error.file()),
        (SnapshotStep::Snapshot, Some(EntryName::Approver(fixture.held.approvers()[1].id())))
    );
    assert!(bytes.is_empty());
}

#[test]
fn a_record_changed_after_the_check_is_refused_before_its_bytes_are_encoded() {
    let _turn = one_at_a_time();
    let fixture = Fixture::new();
    fixture.check().unwrap();
    let id = *fixture.records.last().unwrap();
    let changed = noise(200);
    fixture.put(&StateFileName::record(&id), &changed);
    let mut bytes = Vec::new();
    let error = fixture.stream(&mut bytes).unwrap_err();
    assert_eq!((error.step(), error.file()), (SnapshotStep::Snapshot, Some(EntryName::Record(id))));
    // The bytes are gzip-compressed, so the search runs over the tar they decompress to.
    let mut tar = Vec::new();
    // A partial gzip stream is expected here, so whatever decompressed before its end is searched.
    let _ = flate2::read::GzDecoder::new(bytes.as_slice()).read_to_end(&mut tar);
    assert!(
        !tar.windows(changed.len()).any(|window| window == changed),
        "the changed record reached the sink"
    );
}

#[derive(Debug)]
struct Cancelled;

impl fmt::Display for Cancelled {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("cancelled by lock")
    }
}

impl Error for Cancelled {}

struct CancelledSink;

impl Write for CancelledSink {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::other(Cancelled))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn a_sink_error_is_returned_unchanged_as_a_transfer_failure() {
    let _turn = one_at_a_time();
    let fixture = Fixture::new();
    let error = fixture.stream(CancelledSink).unwrap_err();
    assert_eq!((error.step(), error.file()), (SnapshotStep::Transfer, None));
    match error {
        SnapshotError::Transfer(inner) => assert!(inner.get_ref().is_some_and(|source| source.is::<Cancelled>())),
        other => panic!("{other}"),
    }
}

/// Fails its first call and counts every call.
struct CountingSink<'a>(&'a Cell<usize>);

impl Write for CountingSink<'_> {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        self.0.set(self.0.get() + 1);
        Err(io::Error::other(Cancelled))
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.set(self.0.get() + 1);
        Ok(())
    }
}

#[test]
fn the_sink_is_not_called_again_after_it_fails() {
    let _turn = one_at_a_time();
    let fixture = Fixture::new();
    let calls = Cell::new(0);
    let error = fixture.stream(CountingSink(&calls)).unwrap_err();
    assert!(matches!(error, SnapshotError::Transfer(_)));
    assert_eq!(calls.get(), 1);
}

/// Returns `Interrupted` from its first write and accepts every later call, as a signal-interrupted pipe would.
struct InterruptedOnce<'a> {
    bytes: &'a mut Vec<u8>,
    interrupted: bool,
}

impl Write for InterruptedOnce<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match std::mem::replace(&mut self.interrupted, true) {
            false => Err(io::ErrorKind::Interrupted.into()),
            true => self.bytes.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn an_interrupted_sink_write_is_retried_and_the_export_matches_an_uninterrupted_one() {
    let _turn = one_at_a_time();
    let fixture = Fixture::new();
    let mut plain = Vec::new();
    fixture.stream(&mut plain).unwrap();
    let mut retried = Vec::new();
    let sink = InterruptedOnce {
        bytes: &mut retried,
        interrupted: false,
    };
    let exported = fixture.stream(sink).unwrap();
    assert_eq!(exported.byte_count, retried.len() as u64);

    // The sealed identity and the bundled approver keys are randomized, so only the other entries are compared.
    let (plain, retried) = (decode(&plain), decode(&retried));
    let names = [EntryName::Manifest, EntryName::ApprovalState, EntryName::Config]
        .into_iter()
        .chain(fixture.records.iter().map(|id| EntryName::Record(*id)));
    names.for_each(|name| assert_eq!(plain.entry(&name).unwrap(), retried.entry(&name).unwrap(), "{name:?}"));
    assert_eq!(plain.header().vault_id(), retried.header().vault_id());
}
