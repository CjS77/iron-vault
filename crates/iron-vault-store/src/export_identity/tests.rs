use std::time::{Duration, Instant};

use super::*;
use crate::{
    ApprovalPassphrase, InitPassphrases, InitPassphrasesError, MAX_PASSPHRASE_WORK_FACTOR, SoftwareSigner, StanzaKind, WhichPassphrase,
    seal_signer_key_for_tests, secret_types_tests::assert_hides, stanza_kinds,
};

const TEST_WORK_FACTOR: u8 = 2;

fn export(text: &str) -> ExportPassphrase {
    ExportPassphrase::new(SecretString::from(text)).unwrap()
}

/// An exported identity envelope sealed at the test work factor.
fn sealed_cheap(identity: &VaultIdentity) -> Vec<u8> {
    seal_scrypt_file(
        identity.secret_text().expose_secret().as_bytes(),
        SecretString::from("export phrase 1"),
        TEST_WORK_FACTOR,
    )
    .unwrap()
}

/// `envelope` with its scrypt stanza's work factor argument replaced by `log_n`. The MAC no longer matches, which is fine
/// for a file that must be refused from its header.
fn with_work_factor(envelope: &[u8], log_n: u8) -> Vec<u8> {
    let line_end = 22 + envelope[22..].iter().position(|&b| b == b'\n').unwrap();
    let suffix = format!(" {TEST_WORK_FACTOR}");
    assert!(envelope[..line_end].ends_with(suffix.as_bytes()));
    [
        &envelope[..line_end - suffix.len()],
        format!(" {log_n}").as_bytes(),
        &envelope[line_end..],
    ]
    .concat()
}

fn assert_fast(started: Instant) {
    let elapsed = started.elapsed();
    assert!(elapsed < Duration::from_millis(100), "took {elapsed:?}");
}

/// An approver key envelope sealed at the test work factor.
fn approver_key() -> Vec<u8> {
    let (key, _) = SoftwareSigner::generate().unwrap();
    seal_signer_key_for_tests(&key, &ApprovalPassphrase::new(SecretString::from("approval phrase")).unwrap()).unwrap()
}

#[test]
fn the_export_passphrase_opens_the_vault_identity() {
    let identity = VaultIdentity::generate();
    let envelope = seal_exported_identity(&identity, &export("export phrase 1")).unwrap();
    assert_eq!(stanza_kinds(&envelope).unwrap(), [StanzaKind::Scrypt]);
    assert_eq!(envelope.len(), 256);
    let opened = open_exported_identity(&envelope, &export("export phrase 1")).unwrap();
    assert_eq!(opened.public_key(), identity.public_key());
}

#[test]
fn a_wrong_export_passphrase_is_wrong_passphrase() {
    let envelope = seal_exported_identity(&VaultIdentity::generate(), &export("export phrase 1")).unwrap();
    assert_eq!(
        open_exported_identity(&envelope, &export("export phrase 2")).unwrap_err(),
        EnvelopeError::WrongPassphrase
    );
}

#[test]
fn a_truncated_envelope_is_malformed() {
    let envelope = seal_exported_identity(&VaultIdentity::generate(), &export("export phrase 1")).unwrap();
    [10, 100, envelope.len() - 1].iter().for_each(|len| {
        assert_eq!(
            open_exported_identity(&envelope[..*len], &export("export phrase 1")).unwrap_err(),
            EnvelopeError::Malformed
        )
    });
}

#[test]
fn an_envelope_that_could_cost_scrypt_work_is_refused_first() {
    let envelope = sealed_cheap(&VaultIdentity::generate());
    let oversized = [envelope.as_slice(), &vec![0; MAX_PASSPHRASE_ENVELOPE_LEN]].concat();
    let two_stanzas = {
        let mac = envelope.windows(5).position(|w| w == b"\n--- ").unwrap() + 1;
        [&envelope[..mac], &envelope[22..mac], &envelope[mac..]].concat()
    };
    let x25519 = wrap_for_x25519();
    let cases = [
        (oversized, EnvelopeError::TooLarge),
        (x25519, EnvelopeError::UnexpectedStanza(StanzaKind::X25519)),
        (two_stanzas, EnvelopeError::Malformed),
        (with_work_factor(&envelope, 17), EnvelopeError::WrongWorkFactor),
        (with_work_factor(&envelope, 19), EnvelopeError::WrongWorkFactor),
        (with_work_factor(&envelope, 21), EnvelopeError::WorkFactorTooHigh),
        (with_work_factor(&envelope, 60), EnvelopeError::WorkFactorTooHigh),
    ];
    cases.iter().for_each(|(bytes, expected)| {
        let started = Instant::now();
        let refused = open_exported_identity(bytes, &export("export phrase 1")).unwrap_err();
        assert!(
            refused == *expected || (*expected == EnvelopeError::Malformed && matches!(refused, EnvelopeError::UnexpectedStanza(_))),
            "{refused:?}"
        );
        assert_fast(started);
    });
}

/// An identity envelope: X25519 stanzas only.
fn wrap_for_x25519() -> Vec<u8> {
    let vault = VaultIdentity::generate();
    seal_bundled_approver_key(b"x", &vault.public_key()).unwrap()
}

#[test]
fn a_bundled_approver_key_round_trips_byte_for_byte() {
    let vault = VaultIdentity::generate();
    let envelope = approver_key();
    let bundled = seal_bundled_approver_key(&envelope, &vault.public_key()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(stanza_kinds(&bundled).unwrap(), [StanzaKind::X25519, StanzaKind::Grease]);
    assert_eq!(open_bundled_approver_key(&bundled, &vault).unwrap(), envelope);
}

#[test]
fn a_bundled_approver_key_for_another_vault_is_refused() {
    let bundled = seal_bundled_approver_key(&approver_key(), &VaultIdentity::generate().public_key()).unwrap();
    assert_eq!(
        open_bundled_approver_key(&bundled, &VaultIdentity::generate()).unwrap_err(),
        BundledApproverKeyError::Open(OpenError::NotForThisIdentity)
    );
}

#[test]
fn a_bundled_approver_key_with_an_scrypt_stanza_is_refused() {
    let scrypt = sealed_cheap(&VaultIdentity::generate());
    assert_eq!(
        open_bundled_approver_key(&scrypt, &VaultIdentity::generate()).unwrap_err(),
        BundledApproverKeyError::Open(OpenError::UnexpectedStanza)
    );
}

#[test]
fn a_bundled_approver_key_with_a_bad_form_is_refused() {
    let vault = VaultIdentity::generate();
    let key = approver_key();
    let oversized = vec![0; MAX_PASSPHRASE_ENVELOPE_LEN + 1];
    let high = with_work_factor(&key, MAX_PASSPHRASE_WORK_FACTOR + 1);
    let doubled = {
        let mac = key.windows(5).position(|w| w == b"\n--- ").unwrap() + 1;
        [&key[..mac], &key[22..mac], &key[mac..]].concat()
    };
    let open = |plaintext: &[u8]| open_bundled_approver_key(&seal_bundled_approver_key(plaintext, &vault.public_key()).unwrap(), &vault);
    assert_eq!(
        open(&oversized).unwrap_err(),
        BundledApproverKeyError::Open(OpenError::TooLarge {
            limit: MAX_PASSPHRASE_ENVELOPE_LEN
        })
    );
    assert_eq!(
        open(&high).unwrap_err(),
        BundledApproverKeyError::Form(EnvelopeError::WorkFactorTooHigh)
    );
    assert!(matches!(open(&doubled).unwrap_err(), BundledApproverKeyError::Form(_)));
    assert!(matches!(
        open(b"not age").unwrap_err(),
        BundledApproverKeyError::Form(EnvelopeError::Malformed)
    ));
}

#[test]
fn the_approver_key_form_check_reads_the_header_only() {
    let key = approver_key();
    assert_eq!(check_approver_key_form(&key), Ok(()));
    assert_eq!(check_approver_key_form(&with_work_factor(&key, 20)), Ok(()));
    assert_eq!(
        check_approver_key_form(&with_work_factor(&key, 21)),
        Err(EnvelopeError::WorkFactorTooHigh)
    );
    assert_eq!(
        check_approver_key_form(&vec![0; MAX_PASSPHRASE_ENVELOPE_LEN + 1]),
        Err(EnvelopeError::TooLarge)
    );
    assert_eq!(check_approver_key_form(&key[..key.len().min(30)]), Err(EnvelopeError::Malformed));
    assert!(matches!(
        check_approver_key_form(&wrap_for_x25519()),
        Err(EnvelopeError::UnexpectedStanza(_))
    ));
}

#[test]
fn the_export_passphrase_follows_the_length_rule() {
    assert_eq!(
        InitPassphrases::ensure_long_enough("eleven char", WhichPassphrase::Export),
        Err(InitPassphrasesError::TooShort {
            which: WhichPassphrase::Export
        })
    );
    assert_eq!(InitPassphrases::ensure_long_enough("twelve chars", WhichPassphrase::Export), Ok(()));
    assert_eq!(ExportPassphrase::new(SecretString::from("")).unwrap_err(), PassphraseError::Empty);
}

// `ExportPassphrase` is its own type, so a `Passphrase` or `ApprovalPassphrase` cannot be passed where one is expected:
// `seal_exported_identity(&identity, &passphrase)` with either fails to compile.
#[test]
fn export_passphrase_debug_hides_the_text() {
    assert_hides(&export(crate::secret_types_tests::MARKER), crate::secret_types_tests::MARKER);
}
