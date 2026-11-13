// SPDX-License-Identifier: MPL-2.0
use secrecy::SecretString;

use super::*;
use crate::export_snapshot::tests::{CONFIG, Fixture, approver_key, decode, one_at_a_time, passphrase, with_work_factor};
use crate::manifest::tests::KAT_IDENTITY;
use crate::migration_bundle::BundleEncoder;
use crate::{StateFileName, StateGeneration, seal_approval_state, seal_bundled_approver_key, seal_manifest};

/// A bundle's entries and its header's vault ID, changed one at a time before they are encoded. The header's counts
/// always follow the entries, because the encoder refuses any other.
pub(crate) struct Parts {
    vault_id: VaultId,
    entries: BTreeMap<EntryName, Vec<u8>>,
}

impl Parts {
    /// Builds the fixture's vault as export bundles it. The exported identity envelope is a stand-in: step 4 never reads it,
    /// and sealing it would run scrypt.
    pub(crate) fn of(fixture: &Fixture) -> Self {
        let vault = fixture.identity.public_key();
        let fixed = [
            (EntryName::ExportedIdentity, b"stand-in".to_vec()),
            (EntryName::Manifest, fixture.file(&StateFileName::manifest())),
            (EntryName::ApprovalState, fixture.file(&StateFileName::approval_state())),
            (EntryName::Config, CONFIG.to_vec()),
        ];
        let software = fixture
            .held
            .approvers()
            .iter()
            .filter(|approver| approver.kind() == SignerKind::Software);
        let approvers = software.map(|approver| {
            let key = fixture.file(&StateFileName::approver_key(approver.id()));
            (EntryName::Approver(approver.id()), seal_bundled_approver_key(&key, &vault).unwrap())
        });
        let records = fixture
            .records
            .iter()
            .map(|id| (EntryName::Record(*id), fixture.file(&StateFileName::record(id))));
        Self {
            vault_id: fixture.held.vault_id(),
            entries: fixed.into_iter().chain(approvers).chain(records).collect(),
        }
    }

    fn with(mut self, name: EntryName, bytes: Vec<u8>) -> Self {
        self.entries.insert(name, bytes);
        self
    }

    fn without(mut self, name: EntryName) -> Self {
        self.entries.remove(&name);
        self
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let count = |id_entry: fn(&EntryName) -> bool| self.entries.keys().filter(|name| id_entry(name)).count();
        let approvers = count(|name| matches!(name, EntryName::Approver(_)));
        let records = count(|name| matches!(name, EntryName::Record(_)));
        let header = BundleHeader::new(self.vault_id, approvers, records).unwrap();
        let mut encoder = BundleEncoder::new(Vec::new(), header).unwrap();
        self.entries
            .iter()
            .for_each(|(name, bytes)| encoder.write_entry(*name, bytes).unwrap());
        encoder.finish().unwrap()
    }

    /// Runs step 4 on the encoded and decoded bundle, with the fixture's vault identity as step 3 would have opened it.
    fn verify(&self) -> Result<VerifiedBundle, BundleCheckError> {
        verify_encoded(&self.encode())
    }

    fn refusal(&self) -> &'static str {
        self.verify().unwrap_err().name()
    }
}

/// Runs step 4 on the bundle `encoded`, with the fixture's vault identity as step 3 would have opened it.
pub(crate) fn verify_encoded(encoded: &[u8]) -> Result<VerifiedBundle, BundleCheckError> {
    let (header, entries) = decode(encoded).into_parts();
    let identity = VaultIdentity::from_secret(KAT_IDENTITY);
    verify_bundle(OpenedBundle { header, entries, identity })
}

/// Returns the fixture's manifest sealed again with `vault_id`, recording the current approval state as its peer, so it is the
/// newer file of the pair.
fn manifest_after_approval(fixture: &Fixture, vault_id: VaultId) -> Vec<u8> {
    let manifest = open_manifest(&fixture.identity, &fixture.file(&StateFileName::manifest())).unwrap();
    let approval = fixture.held.state_generation();
    let next = StateGeneration::new(approval.get() + 1).unwrap();
    let resealed = VaultManifest::new(vault_id, next, Some(approval), manifest.entries().clone()).unwrap();
    seal_manifest(&fixture.identity, &resealed).unwrap()
}

fn first_approver(fixture: &Fixture) -> EntryName {
    EntryName::Approver(fixture.held.approvers()[0].id())
}

fn unpinned_approver() -> EntryName {
    EntryName::Approver(PinnedApprover::from_seed(9).id())
}

#[test]
fn the_bundle_of_a_vault_verifies() {
    let fixture = Fixture::new();
    let verified = Parts::of(&fixture).verify().unwrap();
    assert_eq!(verified.vault_id(), fixture.held.vault_id());
    let resealed = Parts::of(&fixture).with(EntryName::Manifest, manifest_after_approval(&fixture, fixture.held.vault_id()));
    assert!(resealed.verify().is_ok(), "the resealed manifest pairs with the approval state");
}

#[test]
fn a_header_vault_id_that_differs_from_the_manifests_is_refused() {
    let fixture = Fixture::new();
    let parts = Parts {
        vault_id: VaultId::new_random(),
        ..Parts::of(&fixture)
    };
    assert_eq!(parts.refusal(), "manifest_vault");
}

#[test]
fn control_files_of_another_vault_are_refused() {
    let (fixture, other) = (Fixture::new(), Fixture::new());
    let foreign_identity = VaultIdentity::generate();
    let manifest = open_manifest(&fixture.identity, &fixture.file(&StateFileName::manifest())).unwrap();
    let cases = [
        (EntryName::Manifest, other.file(&StateFileName::manifest()), "manifest_vault"),
        (
            EntryName::ApprovalState,
            other.file(&StateFileName::approval_state()),
            "approval_vault",
        ),
        (
            EntryName::Manifest,
            seal_manifest(&foreign_identity, &manifest).unwrap(),
            "manifest_open",
        ),
        (
            EntryName::ApprovalState,
            seal_approval_state(&foreign_identity, &fixture.held).unwrap(),
            "approval_open",
        ),
    ];
    cases.into_iter().for_each(|(name, bytes, check)| {
        assert_eq!(Parts::of(&fixture).with(name, bytes).refusal(), check, "{name:?}");
    });
}

#[test]
fn an_approval_state_from_an_older_generation_is_refused() {
    let fixture = Fixture::new();
    let parts = Parts::of(&fixture)
        .with(EntryName::Manifest, manifest_after_approval(&fixture, fixture.held.vault_id()))
        .with(EntryName::ApprovalState, fixture.older_approval.clone());
    assert_eq!(parts.refusal(), "approval_pair");
}

#[test]
fn an_approval_state_with_no_committed_approval_is_refused() {
    // The older approval state was written before the manifest's last write, so the two still pair.
    let fixture = Fixture::new();
    let parts = Parts::of(&fixture).with(EntryName::ApprovalState, fixture.older_approval.clone());
    assert_eq!(parts.refusal(), "committed_approval");
}

#[test]
fn a_config_changed_by_one_byte_is_refused() {
    let fixture = Fixture::new();
    let mut config = CONFIG.to_vec();
    config[0] ^= 1;
    assert_eq!(Parts::of(&fixture).with(EntryName::Config, config).refusal(), "config_digest");
}

#[test]
fn record_entries_that_differ_from_the_manifests_are_refused() {
    let fixture = Fixture::new();
    let named = EntryName::Record(fixture.records[0]);
    let unnamed = EntryName::Record(RecordId::new_random());
    let unnamed_file = fixture.file(&StateFileName::record(&fixture.records[0]));
    // With the header's counts following the entries, a record missing or added alone changes the record count.
    assert_eq!(Parts::of(&fixture).without(named).refusal(), "counts");
    assert_eq!(Parts::of(&fixture).with(unnamed, unnamed_file.clone()).refusal(), "counts");
    let swapped = Parts::of(&fixture).without(named).with(unnamed, unnamed_file);
    assert_eq!(swapped.refusal(), "record_ids");
}

#[test]
fn a_record_whose_bytes_changed_is_refused() {
    let fixture = Fixture::new();
    let name = EntryName::Record(fixture.records[1]);
    let mut file = fixture.file(&StateFileName::record(&fixture.records[1]));
    *file.last_mut().unwrap() ^= 1;
    assert_eq!(Parts::of(&fixture).with(name, file).refusal(), "record_digest");
}

#[test]
fn approver_entries_that_differ_from_the_pinned_approvers_are_refused() {
    let fixture = Fixture::new();
    let bundled = Parts::of(&fixture).entries[&first_approver(&fixture)].clone();
    assert_eq!(Parts::of(&fixture).with(unpinned_approver(), bundled.clone()).refusal(), "counts");
    assert_eq!(Parts::of(&fixture).without(first_approver(&fixture)).refusal(), "counts");
    let swapped = Parts::of(&fixture)
        .without(first_approver(&fixture))
        .with(unpinned_approver(), bundled);
    assert_eq!(swapped.refusal(), "approver_ids");
}

#[test]
fn a_bundled_approver_key_that_does_not_open_to_an_approver_key_envelope_is_refused() {
    let fixture = Fixture::new();
    let vault = fixture.identity.public_key();
    let key = approver_key();
    let cases = [
        (
            seal_bundled_approver_key(&key, &VaultIdentity::generate().public_key()),
            "approver_key_open",
        ),
        (
            seal_bundled_approver_key(b"not an approver key envelope", &vault),
            "approver_key_form",
        ),
        (seal_bundled_approver_key(&with_work_factor(&key, 21), &vault), "approver_key_form"),
        (
            seal_bundled_approver_key(&vec![b'a'; crate::MAX_PASSPHRASE_ENVELOPE_LEN + 1], &vault),
            "approver_key_form",
        ),
    ];
    cases.into_iter().for_each(|(bundled, check)| {
        let parts = Parts::of(&fixture).with(first_approver(&fixture), bundled.unwrap());
        assert_eq!(parts.refusal(), check);
    });
}

#[test]
fn an_exported_identity_envelope_at_another_work_factor_is_invalid_before_scrypt_runs() {
    // An approver key envelope is one scrypt stanza at work factor 2, so it is refused for its work factor alone.
    let fixture = Fixture::new();
    let bundle = decode(&Parts::of(&fixture).with(EntryName::ExportedIdentity, approver_key()).encode());
    let error = open_bundle(bundle, &passphrase()).unwrap_err();
    assert_eq!(error, OpenBundleError::Invalid(BundleCheckError::ExportedIdentity));
}

#[test]
fn the_checks_run_on_the_files_as_read_from_disk() {
    let fixture = Fixture::new();
    let control = ControlFiles::open(
        &fixture.identity,
        fixture.held.vault_id(),
        &fixture.file(&StateFileName::manifest()),
        &fixture.file(&StateFileName::approval_state()),
    )
    .unwrap();
    control.check_config(CONFIG).unwrap();
    control.check_record_ids(fixture.records.iter().copied()).unwrap();
    fixture
        .records
        .iter()
        .for_each(|id| control.check_record(*id, &fixture.file(&StateFileName::record(id))).unwrap());
    control
        .check_approver_ids(fixture.held.approvers().iter().map(PinnedApprover::id))
        .unwrap();
    control
        .check_approver_key(&fixture.file(&StateFileName::approver_key(fixture.held.approvers()[0].id())))
        .unwrap();
    assert_eq!(
        control.check_approver_key(&with_work_factor(&approver_key(), 21)),
        Err(BundleCheckError::ApproverKeyForm)
    );
    let other_record = fixture.file(&StateFileName::record(&fixture.records[1]));
    assert_eq!(
        control.check_record(fixture.records[0], &other_record),
        Err(BundleCheckError::RecordDigest)
    );
    assert_eq!(
        control.check_record(RecordId::new_random(), &other_record),
        Err(BundleCheckError::RecordIds)
    );
}

#[test]
fn a_wrong_export_passphrase_is_its_own_error() {
    let _turn = one_at_a_time();
    let fixture = Fixture::new();
    let mut bytes = Vec::new();
    fixture.stream(&mut bytes).unwrap();
    let wrong = ExportPassphrase::new(SecretString::from("export phrase 2")).unwrap();
    assert_eq!(open_bundle(decode(&bytes), &wrong).unwrap_err(), OpenBundleError::WrongPassphrase);
}

#[test]
fn an_exported_bundle_verifies_to_the_source_vault() {
    let _turn = one_at_a_time();
    let fixture = Fixture::new();
    let mut bytes = Vec::new();
    fixture.stream(&mut bytes).unwrap();
    let opened = open_bundle(decode(&bytes), &passphrase()).unwrap();
    let verified = verify_bundle(opened).unwrap();

    let (version, digest) = fixture.held.committed().unwrap();
    assert_eq!(verified.vault_id(), fixture.held.vault_id());
    assert_eq!(verified.record_count(), fixture.records.len());
    assert_eq!(verified.approvers(), fixture.held.approvers());
    assert_eq!(verified.committed_version(), version);
    assert_eq!(verified.highest_reserved(), fixture.held.highest_reserved());
    assert_eq!(verified.config_digest(), digest);
    assert_eq!(verified.identity().public_key(), fixture.identity.public_key());
    assert_eq!(verified.manifest_file(), fixture.file(&StateFileName::manifest()));
    assert_eq!(verified.approval_file(), fixture.file(&StateFileName::approval_state()));
    assert_eq!(verified.config(), CONFIG);
    let keys: BTreeMap<_, _> = fixture
        .held
        .approvers()
        .iter()
        .map(|approver| (approver.id(), fixture.file(&StateFileName::approver_key(approver.id()))))
        .collect();
    assert_eq!(verified.approver_keys(), &keys);
    let records: BTreeMap<_, _> = fixture
        .records
        .iter()
        .map(|id| (*id, fixture.file(&StateFileName::record(id))))
        .collect();
    assert_eq!(verified.records(), &records);
    assert!(!format!("{verified:?}").contains("AGE-SECRET-KEY"));
}

#[test]
fn a_bundle_with_no_key_file_for_a_tpm_approver_verifies() {
    let fixture = Fixture::with_tpm_approver(false);
    let parts = Parts::of(&fixture);
    let verified = parts.verify().unwrap();
    assert_eq!(verified.approvers().len(), 2);
    assert_eq!(verified.approver_keys().len(), 1);
}

#[test]
fn a_key_file_for_a_tpm_approver_is_refused() {
    let fixture = Fixture::with_tpm_approver(false);
    let tpm = fixture.held.approvers().iter().find(|a| a.kind() == SignerKind::Tpm).unwrap().id();
    let sealed = seal_bundled_approver_key(&approver_key(), &fixture.identity.public_key()).unwrap();
    assert_eq!(Parts::of(&fixture).with(EntryName::Approver(tpm), sealed).refusal(), "counts");
}
