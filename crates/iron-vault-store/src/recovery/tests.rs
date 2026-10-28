use std::fmt::Debug;
use std::path::Path;

use iron_vault_kinds::CredentialMaterial;
use iron_vault_policy::{CredentialName, Port};

use super::*;
use crate::{
    EnvelopeError, OperationalIdentity, OsFs, Passphrase, PermittedOrigins, RecipientSet, StanzaKind, StateDirLock, StateFileName,
    UnlockError, Vault, VaultIdentity, mac_file::HEADER_LEN as MANIFEST_HEADER_LEN, passphrase::seal_at, read_identity_envelope,
    stanza_kinds, test_dir::TestDir, unlock_with_passphrase, unwrap_identity, wrap_identity, write_identity_envelope,
    write_passphrase_envelope,
};

/// The work factor the end-to-end test seals the passphrase envelope with, so it does not spend 256 MiB and a second.
const TEST_WORK_FACTOR: u8 = 2;

/// The credentials the end-to-end vault holds.
const NAMES: [&str; 2] = ["fx_key", "brave"];

/// The owner's passphrase in the end-to-end test.
const PASSPHRASE: &str = "correct horse battery staple";

/// The lock file's name; it is not an `age` file.
const LOCK_FILE: &str = "lock";

fn n<T: std::str::FromStr<Err: Debug>>(s: &str) -> T {
    s.parse().unwrap()
}

fn key_of(name: &str) -> String {
    format!("SECRET-{name}-5c1d")
}

fn origins(name: &str) -> PermittedOrigins {
    PermittedOrigins::new([(n(&format!("api.{}.example", name.replace('_', "-"))), Port::HTTPS)].into()).unwrap()
}

fn passphrase() -> Passphrase {
    Passphrase::new(SecretString::from(PASSPHRASE)).unwrap()
}

/// `text` with the character at `index` swapped for another bech32 character, as a mistyped key would be.
fn with_typo(text: &str, index: usize) -> String {
    let swapped = match text.as_bytes()[index] {
        b'Q' => 'P',
        _ => 'Q',
    };
    text.char_indices().map(|(i, c)| if i == index { swapped } else { c }).collect()
}

#[test]
fn the_secret_parses_back_to_the_enrolled_key() {
    let (secret, key) = RecoveryKey::generate();
    assert!(secret.expose_secret().starts_with("AGE-SECRET-KEY-1"));
    let identity = RecoveryKeySecret::parse(SecretString::from(secret.expose_secret())).unwrap();
    assert_eq!(identity.recipient_key(), key);
    assert_ne!(RecoveryKey::generate().1, key);
}

#[test]
fn surrounding_whitespace_is_trimmed() {
    let (secret, key) = RecoveryKey::generate();
    let pasted = format!(" \t\n{}\r\n ", secret.expose_secret());
    assert_eq!(RecoveryKeySecret::parse(SecretString::from(pasted)).unwrap().recipient_key(), key);
}

#[test]
fn anything_else_is_rejected_without_echoing_the_input() {
    let (secret, _) = RecoveryKey::generate();
    let text = secret.expose_secret();
    let (head, tail) = text.split_at(30);
    let rejected = [
        with_typo(text, 30),
        with_typo(text, text.len() - 1),
        format!("{head} {tail}"),
        text[..text.len() - 1].to_owned(),
        format!("{text}Q"),
        text.replace("AGE-SECRET-KEY-1", "AGE-PLUGIN-KEY-1"),
        String::new(),
    ];
    rejected.iter().for_each(|input| {
        let error = RecoveryKeySecret::parse(SecretString::from(input.as_str())).unwrap_err();
        assert_eq!(error, RecoveryError::NotARecoveryKey);
        let shown = format!("{error} {error:?}");
        assert!(input.is_empty() || !shown.contains(&input[16..]), "{shown}");
    });
}

#[test]
fn debug_shows_nothing_of_the_secret() {
    let (secret, _) = RecoveryKey::generate();
    let debug = format!("{secret:?} {secret:#?}");
    assert!(
        !debug.contains(&secret.expose_secret()[16..]) && !debug.contains("AGE-SECRET"),
        "{debug}"
    );
}

/// The secrets the owner holds after initialization: the recovery key on paper and the passphrase in memory. The
/// operational identity's text is kept only so the test can search the state directory for it.
struct Initialized {
    recovery_text: String,
    operational_text: String,
}

/// What init will do, at store level: lock, generate the three identities, write both envelopes, create the vault and
/// add two records. Every key and the lock are dropped on return.
fn initialize(dir: &Path) -> Initialized {
    let lock = StateDirLock::acquire(dir).unwrap();
    let vault_identity = VaultIdentity::generate();
    let (operational, operational_key) = OperationalIdentity::generate();
    let (recovery, recovery_key) = RecoveryKey::generate();
    let recipients = RecipientSet::new([operational_key, recovery_key]).unwrap();
    write_identity_envelope(&lock, &OsFs, &wrap_identity(&vault_identity, &recipients).unwrap()).unwrap();
    write_passphrase_envelope(&lock, &OsFs, &seal_at(&operational, &passphrase(), TEST_WORK_FACTOR).unwrap()).unwrap();
    let mut vault = Vault::create(&lock, &OsFs, vault_identity).unwrap();
    NAMES.iter().for_each(|name| {
        let material = CredentialMaterial::Static { key: key_of(name).into() };
        vault.add(&lock, &OsFs, n(name), material, origins(name)).unwrap();
    });
    Initialized {
        recovery_text: recovery.expose_secret().to_owned(),
        operational_text: operational.secret_text().expose_secret().to_owned(),
    }
}

/// Opens the vault with `identity` and checks both records loaded intact.
fn assert_both_records_healthy(lock: &StateDirLock, identity: VaultIdentity) {
    let (vault, report) = Vault::open(lock, &OsFs, identity).unwrap();
    assert!(report.damaged().is_empty() && report.unindexed().is_empty(), "{report:?}");
    NAMES.iter().for_each(|name| match vault.material(&n::<CredentialName>(name)) {
        Some(CredentialMaterial::Static { key }) => assert_eq!(key.expose_secret(), key_of(name)),
        other => panic!("{name} is not healthy: {}", other.is_some()),
    });
}

/// Every file in the state directory, by name.
fn state_files(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap())
        .map(|entry| (entry.file_name().into_string().unwrap(), std::fs::read(entry.path()).unwrap()))
        .collect();
    files.sort();
    files
}

/// The `age` file inside state file `name`: the manifest's follows its clear header, every other file is one whole.
fn age_part<'a>(name: &str, bytes: &'a [u8]) -> &'a [u8] {
    match name == StateFileName::manifest().as_str() {
        true => &bytes[MANIFEST_HEADER_LEN..],
        false => bytes,
    }
}

/// The no-mixed-recipient release check (§3.15): the passphrase envelope is scrypt only, every other `age` file is
/// X25519 plus at most one grease stanza, and no file has both scrypt and X25519.
fn assert_no_mixed_recipients(files: &[(String, Vec<u8>)]) {
    let operational = StateFileName::passphrase_envelope();
    let age_files: Vec<_> = files.iter().filter(|(name, _)| name != LOCK_FILE).collect();
    // identity.age, operational.age, the manifest and two records.
    assert_eq!(age_files.len(), 5, "{:?}", files.iter().map(|(name, _)| name).collect::<Vec<_>>());
    age_files.iter().for_each(|(name, bytes)| {
        let kinds = stanza_kinds(age_part(name, bytes)).unwrap();
        assert!(
            !(kinds.contains(&StanzaKind::Scrypt) && kinds.contains(&StanzaKind::X25519)),
            "{name}: {kinds:?}"
        );
        match name == operational.as_str() {
            true => assert_eq!(kinds, [StanzaKind::Scrypt], "{name}"),
            false => {
                assert!(kinds.contains(&StanzaKind::X25519), "{name}: {kinds:?}");
                assert!(kinds.iter().all(StanzaKind::is_x25519_or_grease), "{name}: {kinds:?}");
                assert!(
                    kinds.iter().filter(|kind| **kind == StanzaKind::Grease).count() <= 1,
                    "{name}: {kinds:?}"
                );
            }
        }
    });
    let identity = StateFileName::identity_envelope();
    let identity_kinds = stanza_kinds(&files.iter().find(|(name, _)| name == identity.as_str()).unwrap().1).unwrap();
    assert_eq!(
        identity_kinds.iter().filter(|kind| **kind == StanzaKind::X25519).count(),
        2,
        "{identity_kinds:?}"
    );
}

/// Neither private key's text appears in any file, in either case.
fn assert_no_key_text(files: &[(String, Vec<u8>)], keys: &[&str]) {
    let needles: Vec<String> = keys.iter().flat_map(|key| [key.to_string(), key.to_lowercase()]).collect();
    files.iter().for_each(|(name, bytes)| {
        needles.iter().for_each(|needle| {
            assert!(
                !bytes.windows(needle.len()).any(|window| window == needle.as_bytes()),
                "a private key's text is in {name}"
            );
        });
    });
}

#[test]
fn recovery_opens_the_vault_independently_of_the_passphrase() {
    let dir = TestDir::new("recovery-e2e");
    let owner = initialize(dir.path());

    let lock = StateDirLock::acquire(dir.path()).unwrap();
    assert_both_records_healthy(&lock, unlock_with_passphrase(&lock, &OsFs, &passphrase()).unwrap());
    let files = state_files(dir.path());
    assert_no_mixed_recipients(&files);
    assert_no_key_text(&files, &[&owner.recovery_text, &owner.operational_text]);
    drop(lock);

    std::fs::remove_file(dir.path().join(StateFileName::passphrase_envelope().as_str())).unwrap();
    let lock = StateDirLock::acquire(dir.path()).unwrap();
    assert!(matches!(
        unlock_with_passphrase(&lock, &OsFs, &passphrase()),
        Err(UnlockError::Read(_))
    ));
    let recovery = RecoveryKeySecret::parse(SecretString::from(owner.recovery_text.as_str())).unwrap();
    let identity = unwrap_identity(&read_identity_envelope(&lock, &OsFs).unwrap(), &recovery).unwrap();
    assert_both_records_healthy(&lock, identity);
}

#[test]
fn a_recovery_key_that_is_not_enrolled_does_not_unwrap() {
    let keys = [RecoveryKey::generate().1, RecoveryKey::generate().1];
    let envelope = wrap_identity(&VaultIdentity::generate(), &RecipientSet::new(keys).unwrap()).unwrap();
    let unrelated = RecoveryKeySecret::parse(SecretString::from(RecoveryKey::generate().0.expose_secret())).unwrap();
    assert_eq!(unwrap_identity(&envelope, &unrelated).unwrap_err(), EnvelopeError::NotARecipient);
}
