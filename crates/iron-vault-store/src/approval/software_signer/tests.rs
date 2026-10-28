//! The software signer: generate, seal, open against the pinned approver, sign, and verify with `verify_approval`.

use super::*;
use crate::secret_types_tests::assert_hides;
use crate::{
    ApprovalState, ApprovalVersion, ConfigDigest, OperationalIdentity, OsFs, Passphrase, RecipientIdentity, RecipientSet, StanzaKind,
    UnlockError, VaultId, VaultIdentity, passphrase::seal_at, stanza_kinds, test_dir::TestDir, unlock_with_passphrase, verify_approval,
    wrap_identity, write_identity_envelope, write_passphrase_envelope,
};

/// The work factor tests seal with, so CI does not spend 256 MiB and a second per envelope.
const TEST_WORK_FACTOR: u8 = 2;

const CONFIG: &[u8] = b"[listener.agent]\nbind = \"127.0.0.1:8080\"\n";

fn approval_passphrase(text: &str) -> ApprovalPassphrase {
    ApprovalPassphrase::new(SecretString::from(text)).unwrap()
}

fn unlock_passphrase(text: &str) -> Passphrase {
    Passphrase::new(SecretString::from(text)).unwrap()
}

/// A fresh key sealed to `text` at the test work factor, with the approver to pin for it.
fn sealed(text: &str) -> (Vec<u8>, PinnedApprover) {
    let (key, pinned) = SoftwareSigner::generate().unwrap();
    (
        seal_signer_key_at(&key, &approval_passphrase(text), TEST_WORK_FACTOR).unwrap(),
        pinned,
    )
}

fn payload(vault_id: VaultId, version: ApprovalVersion) -> ApprovalPayload {
    ApprovalPayload::new(vault_id, version, ConfigDigest::of(CONFIG))
}

#[test]
fn production_work_factor_is_the_passphrase_envelope_s() {
    assert_eq!(PASSPHRASE_WORK_FACTOR, 18);
}

#[test]
fn an_empty_approval_passphrase_is_refused() {
    assert_eq!(ApprovalPassphrase::new(SecretString::from("")).unwrap_err(), PassphraseError::Empty);
}

#[test]
fn a_signed_approval_verifies_against_the_committed_state() {
    let dir = TestDir::new("software-signer-verify");
    let lock = StateDirLock::acquire(dir.path()).unwrap();
    let (fs, identity) = (OsFs, VaultIdentity::generate());
    let (envelope, pinned) = sealed("approve me");
    write_signer_key(&lock, &fs, &envelope).unwrap();
    let mut state = ApprovalState::create(&lock, &fs, &identity, VaultId::new_random(), pinned.clone()).unwrap();
    let version = state.reserve(&lock, &fs, &identity).unwrap();

    let signer = open_signer_key(&read_signer_key(&lock, &fs).unwrap(), &approval_passphrase("approve me"), &pinned).unwrap();
    assert_eq!((signer.algorithm(), signer.pinned()), (SignatureAlgorithm::Ed25519, pinned));
    let signed = signer.sign(&payload(state.vault_id(), version)).unwrap();
    drop(signer);

    state.commit(&lock, &fs, &identity, version, ConfigDigest::of(CONFIG)).unwrap();
    let verified = verify_approval(&state, CONFIG, &signed.encode()).unwrap();
    assert_eq!((verified.version(), verified.digest()), (version, ConfigDigest::of(CONFIG)));
}

#[test]
fn a_wrong_approval_passphrase_is_wrong_passphrase() {
    let (envelope, pinned) = sealed("approve me");
    ["approve mE", "approve me ", "x"].iter().for_each(|wrong| {
        let error = open_signer_key(&envelope, &approval_passphrase(wrong), &pinned).unwrap_err();
        assert_eq!(error, SignError::WrongPassphrase, "{wrong}");
    });
}

#[test]
fn the_unlock_and_approval_passphrases_are_independent() {
    let dir = TestDir::new("software-signer-independent");
    let lock = StateDirLock::acquire(dir.path()).unwrap();
    let vault = VaultIdentity::generate();
    let (operational, operational_key) = OperationalIdentity::generate();
    let set = RecipientSet::new([operational_key, RecipientIdentity::generate().recipient_key()]).unwrap();
    write_identity_envelope(&lock, &OsFs, &wrap_identity(&vault, &set).unwrap()).unwrap();
    write_passphrase_envelope(
        &lock,
        &OsFs,
        &seal_at(&operational, &unlock_passphrase("unlock"), TEST_WORK_FACTOR).unwrap(),
    )
    .unwrap();
    let (envelope, pinned) = sealed("approve");

    assert!(unlock_with_passphrase(&lock, &OsFs, &unlock_passphrase("unlock")).is_ok());
    assert!(open_signer_key(&envelope, &approval_passphrase("approve"), &pinned).is_ok());
    let error = open_signer_key(&envelope, &approval_passphrase("unlock"), &pinned).unwrap_err();
    assert_eq!(error, SignError::WrongPassphrase);
    assert_eq!(
        unlock_with_passphrase(&lock, &OsFs, &unlock_passphrase("approve")).unwrap_err(),
        UnlockError::WrongPassphrase
    );
}

#[test]
fn the_passphrase_envelope_never_opens_as_an_approver_key() {
    let (operational, _) = OperationalIdentity::generate();
    let envelope = seal_at(&operational, &unlock_passphrase("same text"), TEST_WORK_FACTOR).unwrap();
    let (_, pinned) = SoftwareSigner::generate().unwrap();
    let error = open_signer_key(&envelope, &approval_passphrase("same text"), &pinned).unwrap_err();
    assert_eq!(error, SignError::Envelope(EnvelopeError::Malformed));
}

#[test]
fn a_swapped_approver_key_is_key_mismatch_and_signs_nothing() {
    let (envelope, _) = sealed("approve me");
    let (_, other) = SoftwareSigner::generate().unwrap();
    let error = open_signer_key(&envelope, &approval_passphrase("approve me"), &other).unwrap_err();
    assert_eq!(error, SignError::KeyMismatch);
}

#[test]
fn the_approver_key_envelope_holds_exactly_one_scrypt_stanza() {
    let (envelope, _) = sealed("approve me");
    assert_eq!(stanza_kinds(&envelope).unwrap(), [StanzaKind::Scrypt]);
    // 214 bytes at the two-digit production work factor; the test factor is one digit.
    assert_eq!(envelope.len(), 213);
}

#[test]
fn a_work_factor_above_the_maximum_is_refused() {
    let (envelope, pinned) = sealed("approve me");
    let line_end = 22 + envelope[22..].iter().position(|&b| b == b'\n').unwrap();
    let planted = [&envelope[..line_end - 2], b" 40", &envelope[line_end..]].concat();
    let error = open_signer_key(&planted, &approval_passphrase("approve me"), &pinned).unwrap_err();
    assert_eq!(error, SignError::Envelope(EnvelopeError::WorkFactorTooHigh));
}

#[test]
fn every_truncation_is_an_error() {
    let (envelope, pinned) = sealed("approve me");
    let pass = approval_passphrase("approve me");
    (0..envelope.len()).for_each(|len| assert!(open_signer_key(&envelope[..len], &pass, &pinned).is_err(), "truncated to {len}"));
}

#[test]
fn generated_keys_differ() {
    let (_, a) = SoftwareSigner::generate().unwrap();
    let (_, b) = SoftwareSigner::generate().unwrap();
    assert_ne!(a, b);
}

#[test]
fn debug_shows_no_key_bytes_or_passphrase() {
    let (key, pinned) = SoftwareSigner::generate().unwrap();
    let secret = *key.0.as_bytes();
    let envelope = seal_signer_key_at(&key, &approval_passphrase("approve me"), TEST_WORK_FACTOR).unwrap();
    let signer = open_signer_key(&envelope, &approval_passphrase("approve me"), &pinned).unwrap();
    let debug = format!("{key:?} {key:#?} {signer:?} {signer:#?} {:?}", approval_passphrase("approve me"));
    let hex: String = secret.iter().map(|b| format!("{b:02x}")).collect();
    let decimal = format!("{secret:?}");
    let decimal_items = &decimal[1..decimal.len() - 1];
    assert!(
        !debug.contains(&hex) && !debug.contains(decimal_items) && !debug.contains("approve"),
        "{debug}"
    );
    let public = format!("{:?}", pinned.public_key());
    assert!(!debug.contains(&public[1..public.len() - 1]), "{debug}");
}

/// A seed whose hex form is easy to spot in `Debug` output.
const SEED: [u8; SECRET_KEY_LENGTH] = [0x5d; SECRET_KEY_LENGTH];

fn seed_hex() -> String {
    SEED.iter().map(|b| format!("{b:02x}")).collect()
}

/// The decimal list `{:?}` prints for the seed, without its brackets.
fn seed_decimal() -> String {
    let decimal = format!("{SEED:?}");
    decimal[1..decimal.len() - 1].to_owned()
}

#[test]
fn software_signer_key_debug_hides_a_known_seed() {
    let key = SoftwareSignerKey(SigningKey::from_bytes(&SEED));
    [seed_hex(), seed_decimal()].iter().for_each(|secret| assert_hides(&key, secret));
}

#[test]
fn software_signer_debug_hides_a_known_seed() {
    let key = SoftwareSignerKey(SigningKey::from_bytes(&SEED));
    let pinned = key.pinned();
    let signer = SoftwareSigner::new(key, &pinned).unwrap();
    [seed_hex(), seed_decimal()].iter().for_each(|secret| assert_hides(&signer, secret));
}
