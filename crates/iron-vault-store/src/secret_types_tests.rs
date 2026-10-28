//! Compile-time and `Debug` checks for this crate's secret-bearing types (spec §3.11, `design/secret-handling.md`).
//!
//! A type that gains `Clone`, `Copy`, `Display` or a serde impl would start copying, printing or writing the secret it
//! holds; each assertion below turns that change into a build failure.

use std::fmt::{Debug, Display};
use std::path::Path;

use iron_vault_kinds::CredentialMaterial;
use iron_vault_policy::{CredentialName, Port};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use static_assertions::{assert_impl_all, assert_not_impl_any};

use crate::test_dir::TestDir;
use crate::{
    ApprovalPassphrase, CredentialRecord, OsFs, Passphrase, PermittedOrigins, RecipientIdentity, RecordId, RecoveryKey, RecoveryKeySecret,
    SoftwareSigner, SoftwareSignerKey, Source, StateDirLock, Vault, VaultIdentity,
};

assert_not_impl_any!(VaultIdentity: Clone, Copy, Display, Serialize, Deserialize<'static>);
assert_not_impl_any!(RecipientIdentity: Clone, Copy, Display, Serialize, Deserialize<'static>);
assert_not_impl_any!(CredentialRecord: Clone, Copy, Display, Serialize, Deserialize<'static>);
assert_not_impl_any!(Vault: Clone, Copy, Display, Serialize, Deserialize<'static>);
assert_not_impl_any!(Passphrase: Clone, Copy, Display, Serialize, Deserialize<'static>);
assert_not_impl_any!(RecoveryKeySecret: Clone, Copy, Display, Serialize, Deserialize<'static>);
assert_not_impl_any!(ApprovalPassphrase: Clone, Copy, Display, Serialize, Deserialize<'static>);
assert_not_impl_any!(SoftwareSignerKey: Clone, Copy, Display, Serialize, Deserialize<'static>);
assert_not_impl_any!(SoftwareSigner: Clone, Copy, Display, Serialize, Deserialize<'static>);

// `Rc` is neither `Send` nor `Sync`, so a vault that shared its identity or a record through one would fail here.
assert_impl_all!(Vault: Send, Sync);

/// Distinctive enough that a match in `Debug` output can only be the secret leaking.
pub(crate) const MARKER: &str = "MARKER-secret-5d1c9e";

/// Asserts that neither `Debug` form of `value` contains `secret`, compared case-insensitively because `age` secret
/// keys are printed in upper case but parse in either.
pub(crate) fn assert_hides(value: &impl Debug, secret: &str) {
    let secret = secret.to_ascii_lowercase();
    [format!("{value:?}"), format!("{value:#?}")]
        .iter()
        .for_each(|debug| assert!(!debug.to_ascii_lowercase().contains(&secret), "{debug}"));
}

fn record(name: &str) -> CredentialRecord {
    let origins = PermittedOrigins::new([("api.example.com".parse().unwrap(), Port::HTTPS)].into()).unwrap();
    let material = CredentialMaterial::Static { key: SecretString::from(MARKER) };
    CredentialRecord::new(RecordId::new_random(), name.parse().unwrap(), material, origins, Source::DirectEntry).unwrap()
}

#[test]
fn vault_identity_debug_hides_the_key() {
    let identity = VaultIdentity::generate();
    assert_hides(&identity, identity.secret_text().expose_secret());
}

#[test]
fn recipient_identity_debug_hides_the_key() {
    let identity = RecipientIdentity::generate();
    assert_hides(&identity, identity.secret_text().expose_secret());
}

#[test]
fn recovery_key_secret_debug_hides_the_key() {
    let (secret, _) = RecoveryKey::generate();
    assert_hides(&secret, secret.expose_secret());
}

#[test]
fn passphrase_debug_hides_the_text() {
    assert_hides(&Passphrase::new(SecretString::from(MARKER)).unwrap(), MARKER);
}

#[test]
fn approval_passphrase_debug_hides_the_text() {
    assert_hides(&ApprovalPassphrase::new(SecretString::from(MARKER)).unwrap(), MARKER);
}

// `SoftwareSignerKey` and `SoftwareSigner` are built from a known seed only inside their own module, so their `Debug`
// checks live in `approval/software_signer/tests.rs` and call `assert_hides` from there.

#[test]
fn credential_record_debug_hides_the_material() {
    assert_hides(&record("fx_key"), MARKER);
}

#[test]
fn vault_debug_hides_the_identity_and_every_record() {
    let dir = TestDir::new("secret-debug");
    let lock = StateDirLock::acquire(dir.path()).unwrap();
    let identity = VaultIdentity::generate();
    let identity_secret = identity.secret_text();
    let mut vault = Vault::create(&lock, &OsFs, identity).unwrap();
    let name: CredentialName = "fx_key".parse().unwrap();
    let origins = record("fx_key").origins().clone();
    vault.add(&lock, &OsFs, name, CredentialMaterial::Static { key: SecretString::from(MARKER) }, origins).unwrap();
    assert_hides(&vault, MARKER);
    assert_hides(&vault, identity_secret.expose_secret());
}

/// Shared ownership or a process-wide cache would let a copy of the identity or a record outlive the `Vault` that
/// dropped it. The store's production sources must use neither, so dropping a `Vault` drops its only copies.
#[test]
fn no_shared_or_global_owner_of_vault_secrets() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let sources = production_sources(&src);
    assert!(!sources.is_empty());
    let offenders: Vec<String> = sources
        .iter()
        .flat_map(|path| {
            let text = std::fs::read_to_string(path).unwrap();
            production_lines(&text)
                .into_iter()
                .filter(|line| is_shared_or_global(line))
                .map(|line| format!("{}: {line}", path.display()))
                .collect::<Vec<_>>()
        })
        .collect();
    assert!(offenders.is_empty(), "{offenders:?}");
}

/// Whether `line` names a shared owner or declares a non-`const` `static` item.
fn is_shared_or_global(line: &str) -> bool {
    const FORBIDDEN: [&str; 10] =
        ["Rc<", "Rc::", "Arc<", "Arc::", "Weak<", "OnceLock", "LazyLock", "OnceCell", "thread_local!", "lazy_static!"];
    FORBIDDEN.iter().any(|word| line.contains(word)) || line.split_whitespace().take_while(|word| *word != "=").any(|word| word == "static")
}

/// The lines of `text` outside comments and outside every item marked `#[cfg(test)]`, whatever its visibility.
fn production_lines(text: &str) -> Vec<&str> {
    // State: whether the next item is test-only, and the brace depth inside a test-only item being skipped.
    let mut pending = false;
    let mut depth = 0_i64;
    text.lines()
        .map(str::trim)
        .filter(|line| !line.starts_with("//"))
        .filter(|line| {
            if depth > 0 || pending {
                depth += brace_balance(line);
                pending = pending && depth == 0 && !line.ends_with(';') && !line.ends_with('}');
                return false;
            }
            pending = *line == "#[cfg(test)]";
            !pending
        })
        .collect()
}

fn brace_balance(line: &str) -> i64 {
    line.chars().map(|c| i64::from(c == '{') - i64::from(c == '}')).sum()
}

/// Every `.rs` file under `dir` except test modules and test doubles.
fn production_sources(dir: &Path) -> Vec<std::path::PathBuf> {
    const TEST_ONLY: [&str; 3] = ["fault_fs.rs", "test_dir.rs", "durable_faults.rs"];
    std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .flat_map(|path| match path.is_dir() {
            true => production_sources(&path),
            false => vec![path],
        })
        .filter(|path| {
            let name = path.file_name().unwrap().to_string_lossy();
            name.ends_with(".rs") && !name.ends_with("tests.rs") && !TEST_ONLY.contains(&name.as_ref())
        })
        .collect()
}
