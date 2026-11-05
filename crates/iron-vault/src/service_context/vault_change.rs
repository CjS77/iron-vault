//! Vault writes through the running service (specification §3.3, §3.10, §3.12): `add` today.
//!
//! The open vault lives inside the immutable serving snapshot, so a write never goes through it. It opens a fresh
//! [`Vault`] from the kept vault identity under the service-wide lock and the context's mutex, writes through that and
//! drops it, all on the blocking pool. The serving snapshot is left alone: activation refuses a route whose credential
//! the manifest lacked, so no active route can use the new record, and the next config check opens the vault from disk.

use std::sync::Arc;

use iron_vault_kinds::CredentialMaterial;
use iron_vault_policy::{CredentialKind, CredentialName};
use iron_vault_store::{PermittedOrigins, RecordId, StoreFs, Vault, VaultError, VaultIdentity};

use super::{Inner, ServiceContext, ServiceLocks};
use crate::service_state::{AdminOperation, ServiceState};
use crate::standing::{CredentialStanding, RecordSummary, Standing};

/// Why a vault write changed nothing, or may not have. Each variant is one admin error code, and no message holds
/// credential material.
#[derive(Debug, thiserror::Error)]
pub enum VaultChangeRefusal {
    /// An approval, another vault write or a reload holds the service-wide lock.
    #[error("an approval, another vault write or a reload is running; try again")]
    Busy,
    /// The service is not Ready.
    #[error("vault changes are allowed only while the service is Ready; it is {0:?}")]
    WrongState(ServiceState),
    /// The manifest already lists the name, healthy or damaged.
    #[error("credential {0} already exists, healthy or damaged; `add` never overwrites")]
    NameTaken(CredentialName),
    /// The material breaks its kind's rules.
    #[error("the credential is invalid: {0}")]
    Invalid(String),
    /// The write failed before its commit point, or was refused before writing: the vault is unchanged.
    #[error("the vault write failed and nothing changed: {0}")]
    Failed(String),
    /// The manifest was renamed into place but the state directory fsync failed. `present` is whether the reopened vault
    /// lists the record, `None` when it could not be reopened.
    #[error("{}", uncertain_message(*.present))]
    Uncertain {
        /// Whether the reopened vault lists the new record.
        present: Option<bool>,
    },
}

/// What one write left on disk, from the blocking task.
enum Written {
    Added(RecordId),
    Refused(VaultChangeRefusal),
}

impl<F: StoreFs + Send + Sync + 'static> ServiceContext<F> {
    /// Adds a credential record named `name`, refusing a name the manifest lists (§3.3). Only a Ready service writes.
    ///
    /// It fails at once with [`VaultChangeRefusal::Busy`] while an approval or a reload holds the service-wide lock, so a
    /// pending approval never sees the catalog change under it. On success, and on an uncertain commit the reopened
    /// vault shows, `status` lists the name as healthy at once; routes use it only from the next approval.
    pub async fn add_credential(
        &self,
        name: CredentialName,
        material: CredentialMaterial,
        origins: PermittedOrigins,
    ) -> Result<RecordId, VaultChangeRefusal> {
        let _service_wide = self.service_wide.try_lock().map_err(|_| VaultChangeRefusal::Busy)?;
        let mut inner = self.inner.lock().await;
        let identity = match &inner.identity {
            Some(identity) if inner.state.admin_allows(AdminOperation::VaultChange) => Arc::clone(identity),
            _ => return Err(VaultChangeRefusal::WrongState(inner.state)),
        };
        let kind = kind_of(&material);
        let summary = summary_of(kind, &origins);
        let logged = (name.clone(), origins_text(&origins));
        let written = self.write_on_blocking_pool(identity, name, material, origins).await;
        let (name, origins) = logged;
        match written {
            Written::Added(record_id) => {
                show_healthy(&mut inner, name.clone(), summary);
                tracing::info!(
                    event = "credential.added",
                    credential = %name,
                    kind = kind.as_str(),
                    record_id = %record_id,
                    origins = %origins,
                    "credential `{name}` added; routes can use it from the next approval",
                );
                Ok(record_id)
            }
            Written::Refused(refusal @ VaultChangeRefusal::Uncertain { present: Some(true) }) => {
                show_healthy(&mut inner, name, summary);
                Err(refusal)
            }
            Written::Refused(refusal) => Err(refusal),
        }
    }

    /// Opens a fresh vault, adds the record and drops the vault, on the blocking pool, since it reads, decrypts and
    /// fsyncs vault files. If this future is dropped first, the task still runs to its end.
    async fn write_on_blocking_pool(
        &self,
        identity: Arc<VaultIdentity>,
        name: CredentialName,
        material: CredentialMaterial,
        origins: PermittedOrigins,
    ) -> Written {
        let (locks, setup) = (Arc::clone(&self.locks), Arc::clone(&self.setup));
        tokio::task::spawn_blocking(move || add_record(&locks, &setup.fs, identity, name, material, origins))
            .await
            .unwrap_or(Written::Refused(VaultChangeRefusal::Uncertain { present: None }))
    }
}

/// Adds the record through a vault opened for this write alone.
fn add_record(
    locks: &ServiceLocks,
    fs: &impl StoreFs,
    identity: Arc<VaultIdentity>,
    name: CredentialName,
    material: CredentialMaterial,
    origins: PermittedOrigins,
) -> Written {
    let mut vault = match Vault::open(&locks.state, fs, Arc::clone(&identity)) {
        Ok((vault, _)) => vault,
        Err(error) => return Written::Refused(VaultChangeRefusal::Failed(error.to_string())),
    };
    let added = vault.add(&locks.state, fs, name.clone(), material, origins);
    drop(vault);
    match added {
        Ok((record_id, _)) => Written::Added(record_id),
        Err(VaultError::NameTaken(name)) => Written::Refused(VaultChangeRefusal::NameTaken(name)),
        Err(VaultError::InvalidMaterial(error)) => Written::Refused(VaultChangeRefusal::Invalid(error.to_string())),
        Err(VaultError::CommitUncertain(_)) => Written::Refused(VaultChangeRefusal::Uncertain {
            present: listed_after_reopen(locks, fs, identity, &name),
        }),
        Err(other) => Written::Refused(VaultChangeRefusal::Failed(other.to_string())),
    }
}

/// Whether a vault reopened from disk lists `name`; `None` when it cannot be reopened.
fn listed_after_reopen(locks: &ServiceLocks, fs: &impl StoreFs, identity: Arc<VaultIdentity>, name: &CredentialName) -> Option<bool> {
    let (vault, _) = Vault::open(&locks.state, fs, identity).ok()?;
    Some(vault.manifest().entries().values().any(|entry| entry.name() == name))
}

/// Lists `name` as healthy with no unavailable routes in the context's credential view, in name order. No active route
/// can use it before the next approval, so none is unavailable through it.
fn show_healthy(inner: &mut Inner, name: CredentialName, summary: RecordSummary) {
    let Some(open) = &mut inner.open else {
        return;
    };
    if let Err(at) = open.credentials.binary_search_by(|standing| standing.name.cmp(&name)) {
        let standing = CredentialStanding {
            name,
            standing: Standing::Healthy,
            unavailable_routes: Vec::new(),
            summary: Some(summary),
        };
        open.credentials.insert(at, standing);
    }
}

fn summary_of(kind: CredentialKind, origins: &PermittedOrigins) -> RecordSummary {
    RecordSummary {
        kind,
        origins: origins.iter().cloned().collect(),
    }
}

fn kind_of(material: &CredentialMaterial) -> CredentialKind {
    match material {
        CredentialMaterial::Static { .. } => CredentialKind::Static,
        CredentialMaterial::Basic { .. } => CredentialKind::Basic,
    }
}

/// The permitted origins as `host:port`, comma-separated in ascending order, for the audit log.
fn origins_text(origins: &PermittedOrigins) -> String {
    origins
        .iter()
        .map(|(host, port)| format!("{host}:{}", port.get()))
        .collect::<Vec<_>>()
        .join(",")
}

fn uncertain_message(present: Option<bool>) -> String {
    let listed = match present {
        Some(true) => "the reopened vault lists the record, so it was added",
        Some(false) => "the reopened vault does not list the record, so nothing changed",
        None => "the vault could not be reopened to see whether the record was added; run `iron-vault status`",
    };
    format!("the vault write may not survive power loss: the state directory fsync failed after the commit; {listed}")
}
