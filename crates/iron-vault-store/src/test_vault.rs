//! A vault as `init` leaves it, on the fault filesystem, for tests of recipient changes and the inventory check: an
//! identity envelope for an operational and a recovery recipient, the inventory that describes it, a manifest and one
//! credential record.

use std::collections::BTreeMap;

use iron_vault_kinds::CredentialMaterial;
use iron_vault_policy::Port;
use secrecy::{ExposeSecret, SecretString};

use crate::fault_fs::FaultFs;
use crate::test_dir::TestDir;
use crate::test_request::HOST;
use crate::{
    CheckedInventory, InventoryCheckError, PermittedOrigins, RecipientEntry, RecipientIdentity, RecipientInventory, RecipientLabel,
    RecipientRole, RecipientSet, StateDirLock, StateFileName, StoreFs, UtcSecond, Vault, VaultId, VaultIdentity, check_recipient_inventory,
    envelope_digest, read_identity_envelope, unwrap_identity, wrap_identity, write_identity_envelope, write_recipient_inventory,
};

pub(crate) struct TestVault {
    dir: TestDir,
    pub(crate) lock: StateDirLock,
    pub(crate) fs: FaultFs,
    pub(crate) vault: VaultIdentity,
    pub(crate) vault_id: VaultId,
    pub(crate) operational: RecipientIdentity,
    pub(crate) recovery: RecipientIdentity,
    /// The inventory as written at setup.
    pub(crate) inventory: RecipientInventory,
}

impl TestVault {
    pub(crate) fn new(label: &str) -> Self {
        let dir = TestDir::new(label);
        let lock = StateDirLock::acquire(dir.path()).unwrap();
        let fs = FaultFs::new().with_durable_file(&dir.path().join("lock"), b"");
        let (vault, vault_id) = (VaultIdentity::generate(), VaultId::new_random());
        let (operational, recovery) = (RecipientIdentity::generate(), RecipientIdentity::generate());
        let set = RecipientSet::new([operational.recipient_key(), recovery.recipient_key()]).unwrap();
        let envelope = wrap_identity(&vault, &set).unwrap();
        write_identity_envelope(&lock, &fs, &envelope).unwrap();
        let entries = [(&operational, RecipientRole::Operational), (&recovery, RecipientRole::Recovery)].map(|(id, role)| entry(id, role));
        let inventory = RecipientInventory::new(vault_id, envelope_digest(&envelope), entries).unwrap();
        write_recipient_inventory(&lock, &fs, &vault, &inventory).unwrap();
        let mut created = Vault::create_with_id(&lock, &fs, copy(&vault), vault_id).unwrap();
        let origins = PermittedOrigins::new([(HOST.parse().unwrap(), Port::HTTPS)].into()).unwrap();
        let material = CredentialMaterial::Static {
            key: SecretString::from("SECRET-test-vault-key"),
        };
        created.add(&lock, &fs, "fx_key".parse().unwrap(), material, origins).unwrap();
        Self {
            dir,
            lock,
            fs,
            vault,
            vault_id,
            operational,
            recovery,
            inventory,
        }
    }

    /// Returns every file in the state directory except the lock, with its visible contents.
    pub(crate) fn files(&self) -> BTreeMap<String, Vec<u8>> {
        let names = self.fs.list_dir(self.dir.path()).unwrap();
        names
            .into_iter()
            .map(|name| name.to_string_lossy().into_owned())
            .filter(|name| name != "lock")
            .map(|name| {
                let bytes = self.fs.contents(&self.dir.path().join(&name)).unwrap();
                (name, bytes)
            })
            .collect()
    }

    pub(crate) fn file(&self, name: &StateFileName) -> Option<Vec<u8>> {
        self.fs.contents(&self.dir.path().join(name.as_str()))
    }

    pub(crate) fn put(&self, name: &StateFileName, bytes: &[u8]) {
        crate::durable_replace(&self.lock, &self.fs, name, bytes).unwrap();
    }

    pub(crate) fn remove(&self, name: &StateFileName) {
        crate::durable_remove(&self.lock, &self.fs, name).unwrap();
    }

    /// Returns `true` if and only if `recipient` unwraps `identity.age` on disk and the manifest's MAC verifies with the
    /// identity it unwraps.
    ///
    /// Panics if the unwrapped identity is not this vault's.
    pub(crate) fn opens_with(&self, recipient: &RecipientIdentity) -> bool {
        let envelope = read_identity_envelope(&self.lock, &self.fs).unwrap();
        match unwrap_identity(&envelope, recipient) {
            Ok(unwrapped) => {
                assert_eq!(unwrapped.public_key(), self.vault.public_key());
                Vault::open(&self.lock, &self.fs, unwrapped).is_ok()
            }
            Err(_) => false,
        }
    }

    pub(crate) fn check(&self) -> Result<CheckedInventory, InventoryCheckError> {
        check_recipient_inventory(&self.lock, &self.fs, &self.vault, self.vault_id)
    }

    /// Returns the number of filesystem calls so far, so a test can fail one of the calls that follow.
    pub(crate) fn calls(&self) -> usize {
        self.fs.trace().len()
    }
}

/// Returns an inventory entry for `identity`, enrolled at the Unix epoch and labelled with its role's name.
pub(crate) fn entry(identity: &RecipientIdentity, role: RecipientRole) -> RecipientEntry {
    RecipientEntry::new(
        identity.recipient_key(),
        role,
        RecipientLabel::new(role.name()).unwrap(),
        UtcSecond::EPOCH,
    )
}

/// Returns a second copy of `identity`, which has no `Clone`.
pub(crate) fn copy(identity: &VaultIdentity) -> VaultIdentity {
    VaultIdentity::from_secret_text(identity.secret_text().expose_secret().as_bytes()).unwrap()
}
