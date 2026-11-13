// SPDX-License-Identifier: MPL-2.0
//! The credential record: a secret bound to its identity and the origins it may reach
//! ([spec §6](../../../design/iron-vault-specification.md#6-credential-records-and-configuration)).

mod encoding;
mod resolved;

use std::fmt;

use iron_vault_kinds::{CredentialMaterial, KindError};
use iron_vault_policy::{AuthorizedRequest, CredentialKind, CredentialName, Slot};

use crate::permitted_origins::PermittedOrigins;
use crate::record_id::RecordId;

pub use encoding::{RecordError, decode, encode};
pub use resolved::ResolvedCredential;

/// Names where a credential record's secret came from ([spec §3](../../../design/iron-vault-specification.md#3-terms-and-definitions),
/// [§6](../../../design/iron-vault-specification.md#6-credential-records-and-configuration)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// The owner entered the secret through `add` or `replace`.
    DirectEntry,
}

/// One credential's secret material, bound to its ID, name, permitted origins and source.
///
/// The fields are only set together, at construction, and the material must pass its kind's validation, so a record
/// that exists is one a kind can resolve. The kind is not stored separately: [`CredentialRecord::kind`] reads it from
/// the material, so the two cannot disagree. v0 has no provider settings or operational state; they arrive with v1
/// OAuth under a new payload version.
pub struct CredentialRecord {
    id: RecordId,
    name: CredentialName,
    material: CredentialMaterial,
    origins: PermittedOrigins,
    source: Source,
}

impl CredentialRecord {
    /// Binds `material` to the other fields, refusing material its kind could never resolve.
    pub fn new(
        id: RecordId,
        name: CredentialName,
        material: CredentialMaterial,
        origins: PermittedOrigins,
        source: Source,
    ) -> Result<Self, KindError> {
        material.validate()?;
        Ok(Self {
            id,
            name,
            material,
            origins,
            source,
        })
    }

    /// Returns the record's GUID.
    pub fn id(&self) -> RecordId {
        self.id
    }

    /// Returns the credential's unique name.
    pub fn name(&self) -> &CredentialName {
        &self.name
    }

    /// Returns the kind the material belongs to.
    pub fn kind(&self) -> CredentialKind {
        match self.material {
            CredentialMaterial::Static { .. } => CredentialKind::Static,
            CredentialMaterial::Basic { .. } => CredentialKind::Basic,
        }
    }

    /// Returns the decrypted secret fields, for a kind to resolve.
    pub fn material(&self) -> &CredentialMaterial {
        &self.material
    }

    /// Returns the exact host and port pairs the secret may reach.
    pub fn origins(&self) -> &PermittedOrigins {
        &self.origins
    }

    /// Returns where the secret came from.
    pub fn source(&self) -> Source {
        self.source
    }

    /// Resolves this record's material for `slot` and keeps it with this record's origins. This is how the bound
    /// credential the final outgoing-request check takes is built
    /// ([spec §6](../../../design/iron-vault-specification.md#6-credential-records-and-configuration)).
    pub fn resolve(&self, slot: &Slot, request: &AuthorizedRequest) -> Result<ResolvedCredential<'_>, KindError> {
        iron_vault_kinds::resolve(&self.material, slot, request).map(|resolution| ResolvedCredential::new(resolution, &self.origins))
    }
}

/// Shows the kind in place of the material, so no secret field can reach a log through `{:?}`.
impl fmt::Debug for CredentialRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialRecord")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("kind", &self.kind())
            .field("material", &"<redacted>")
            .field("origins", &self.origins)
            .field("source", &self.source)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use iron_vault_kinds::BasicCredentialError;
    use iron_vault_policy::Port;
    use secrecy::ExposeSecret;

    use super::*;
    use crate::test_request::{HOST, header_request};

    fn record(material: CredentialMaterial) -> Result<CredentialRecord, KindError> {
        let origins = PermittedOrigins::new([("api.example".parse().unwrap(), Port::HTTPS)].into()).unwrap();
        CredentialRecord::new(
            RecordId::new_random(),
            "fx_key".parse().unwrap(),
            material,
            origins,
            Source::DirectEntry,
        )
    }

    #[test]
    fn kind_follows_the_material() {
        let basic = CredentialMaterial::Basic {
            username: "u".into(),
            password: "p".into(),
        };
        assert_eq!(
            record(CredentialMaterial::Static { key: "k".into() }).unwrap().kind(),
            CredentialKind::Static
        );
        assert_eq!(record(basic).unwrap().kind(), CredentialKind::Basic);
    }

    #[test]
    fn invalid_material_is_refused() {
        let material = CredentialMaterial::Basic {
            username: "u:v".into(),
            password: "p".into(),
        };
        assert_eq!(
            record(material).err(),
            Some(KindError::InvalidBasic(BasicCredentialError::ColonInUsername))
        );
    }

    #[test]
    fn resolve_binds_the_value_to_this_records_origins() {
        let material = CredentialMaterial::Static { key: "fx-secret".into() };
        let origins = PermittedOrigins::new([(HOST.parse().unwrap(), Port::HTTPS)].into()).unwrap();
        let record = CredentialRecord::new(
            RecordId::new_random(),
            "fx_key".parse().unwrap(),
            material,
            origins,
            Source::DirectEntry,
        )
        .unwrap();
        let (slot, request) = header_request();
        let resolved = record.resolve(&slot, &request).unwrap();
        let bound = resolved.bound();
        assert_eq!(bound.permitted(), &BTreeSet::from([(HOST.parse().unwrap(), Port::HTTPS)]));
        assert_eq!(bound.value().expose_secret(), "fx-secret");
        assert!(resolved.patterns().iter().any(|pattern| pattern == b"fx-secret"));
        let count = resolved.patterns().len();
        let patterns = resolved.into_patterns();
        assert_eq!(patterns.len(), count);
        assert!(patterns.iter().any(|pattern| pattern == b"fx-secret"));
    }

    #[test]
    fn resolve_refuses_a_slot_the_kind_cannot_fill() {
        let record = record(CredentialMaterial::Static { key: "k".into() }).unwrap();
        let (_, request) = header_request();
        assert!(matches!(
            record.resolve(&Slot::Basic, &request),
            Err(KindError::SlotMismatch { .. })
        ));
    }

    #[test]
    fn debug_hides_the_secret() {
        let record = record(CredentialMaterial::Basic {
            username: "QZJW-user".into(),
            password: "QZJW-pw".into(),
        })
        .unwrap();
        let debug = format!("{record:?}");
        assert!(!debug.contains("QZJW"), "{debug}");
        assert!(
            debug.contains("Basic") && debug.contains("fx_key") && debug.contains("api.example"),
            "{debug}"
        );
    }
}
