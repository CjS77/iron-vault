//! Vault writes through the running service (specification §3.3, §3.10, §3.12): `add` here, and `replace` and `rm`
//! in [`plan`].
//!
//! The open vault lives inside the immutable serving snapshot, so a write never goes through it. It opens a fresh
//! [`Vault`] from the kept vault identity under the service-wide lock and the context's mutex, writes through that and
//! drops it, all on the blocking pool. The serving snapshot is left alone: activation refuses a route whose credential
//! the manifest lacked, so no active route can use the new record, and the next config check opens the vault from disk.

mod plan;

pub use plan::{CredentialChanged, CurrentRecord, VaultChangePlan};

use std::sync::Arc;

use iron_vault_kinds::CredentialMaterial;
use iron_vault_policy::{CredentialKind, CredentialName, Host, Port};
use iron_vault_store::{PermittedOrigins, RecordId, StoreFs, VaultError, VaultIdentity, WriteReport};

use super::{Inner, ServiceContext, ServiceLocks};
use crate::audit::AuditEvent;
use crate::audit::corruption::open_vault;
use crate::audit::credential::{CredentialAdded, CredentialRemoved, CredentialReplaced, ShortSecretWritten, Stored};
use crate::audit::vault::{SupersededLeft, UnindexedRemoved, emit_commit_uncertain};
use crate::service_state::{AdminOperation, ServiceState};
use crate::standing::{CredentialStanding, RecordSummary, Standing};
use crate::vault_change_check::{AffectedRoute, PlannedChange};
use crate::vault_change_summary::VaultChangeSummary;

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
    /// The manifest does not list the name that `replace` or `rm` changes.
    #[error("credential {0} does not exist")]
    UnknownCredential(CredentialName),
    /// The vault change check failed: routes that use the name would not activate after the change. In route name order.
    #[error("routes use credential {name} and would stop working: {}; approve a config without them first", in_use(.routes))]
    InUse {
        /// The credential changed.
        name: CredentialName,
        /// Each failing route with the rule it would break.
        routes: Vec<AffectedRoute>,
    },
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
    /// A `replace` or `rm` committed, but the config check after it failed, so the service no longer serves.
    #[error("the vault change was written, but the config check after it failed; the service is {0:?}")]
    NotActive(ServiceState),
    /// A `replace` or `rm` may have committed, and whether it is durable is unknown. The config check ran on what the
    /// disk holds, and `state` is where the service settled.
    #[error("the vault change may have been written, and may not survive power loss: {cause}; the service is {state:?}")]
    ChangeUncertain {
        /// Why it is uncertain.
        cause: String,
        /// The state the config check settled in.
        state: ServiceState,
    },
}

/// What one write left on disk, from the blocking task.
enum Written {
    Added(RecordId),
    /// The commit is not known to be durable, but the reopened vault lists the record.
    AddedUncertain(RecordId),
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
        let logged = (name.clone(), origins.iter().cloned().collect::<Vec<_>>());
        let written = self.write_on_blocking_pool(identity, name, material, origins).await;
        let (name, origins) = logged;
        match written {
            Written::Added(record_id) => {
                show_healthy(&mut inner, name.clone(), record_id, summary);
                log_added(&name, record_id, kind, &origins);
                Ok(record_id)
            }
            Written::AddedUncertain(record_id) => {
                show_healthy(&mut inner, name.clone(), record_id, summary);
                log_added(&name, record_id, kind, &origins);
                Err(VaultChangeRefusal::Uncertain { present: Some(true) })
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

/// Records a committed `replace` or `rm` as its audit event (design/audit-logging.md), from the summary the owner
/// approved, which alone holds the old record with the new kind and origins. The planned change decides the event: a
/// planned replace commits only as a replace, so it never logs a removal.
fn log_committed(summary: &VaultChangeSummary, changed: &CredentialChanged) {
    match (summary.change(), changed) {
        (PlannedChange::Remove(name), _) => log_removed(name, summary.current().record_id),
        (PlannedChange::Replace { name, kind, origins }, CredentialChanged::Replaced(record_id)) => {
            log_replaced(name, summary.current(), *record_id, kind, origins)
        }
        (PlannedChange::Replace { .. }, CredentialChanged::Removed) => {}
    }
}

fn log_added(name: &CredentialName, record_id: RecordId, kind: CredentialKind, origins: &[(Host, Port)]) {
    CredentialAdded {
        credential: name,
        record_id,
        stored: Stored { kind, origins },
    }
    .emit();
}

fn log_removed(name: &CredentialName, record_id: RecordId) {
    CredentialRemoved {
        credential: name,
        record_id,
    }
    .emit();
}

/// Only a healthy old record's kind and origins are known.
fn log_replaced(name: &CredentialName, old: &CurrentRecord, record_id: RecordId, kind: &CredentialKind, origins: &PermittedOrigins) {
    let origins = origins.iter().cloned().collect::<Vec<_>>();
    CredentialReplaced {
        credential: name,
        old_record_id: old.record_id,
        record_id,
        stored: Stored {
            kind: *kind,
            origins: &origins,
        },
        old: old.summary.as_ref().map(|old| Stored {
            kind: old.kind,
            origins: &old.origins,
        }),
    }
    .emit();
}

/// Emits what a committed vault write did besides its change: the unindexed record files it removed first, a
/// superseded record file it could not remove (the next vault write removes it), and the short secrets it stored.
fn audit_write_report(report: &WriteReport, credential: &CredentialName) {
    report.short_secrets().iter().for_each(|short| {
        ShortSecretWritten {
            credential,
            field: short.field,
            len: short.len,
        }
        .emit()
    });
    report.removed_unindexed().iter().for_each(|file| UnindexedRemoved { file }.emit());
    if let Some((file, error_kind)) = report.left_unindexed().zip(report.left_unindexed_error_kind()) {
        SupersededLeft { file, error_kind }.emit();
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
    let mut vault = match open_vault(&locks.state, fs, Arc::clone(&identity)) {
        Ok((vault, _)) => vault,
        Err(error) => return Written::Refused(VaultChangeRefusal::Failed(error.to_string())),
    };
    let added = vault
        .add(&locks.state, fs, name.clone(), material, origins)
        .inspect_err(emit_commit_uncertain);
    drop(vault);
    match added {
        Ok((record_id, report)) => {
            audit_write_report(&report, &name);
            Written::Added(record_id)
        }
        Err(VaultError::NameTaken(name)) => Written::Refused(VaultChangeRefusal::NameTaken(name)),
        Err(VaultError::InvalidMaterial(error)) => Written::Refused(VaultChangeRefusal::Invalid(error.to_string())),
        Err(VaultError::CommitUncertain(_)) => match listed_after_reopen(locks, fs, identity, &name) {
            Some(Some(record_id)) => Written::AddedUncertain(record_id),
            Some(None) => Written::Refused(VaultChangeRefusal::Uncertain { present: Some(false) }),
            None => Written::Refused(VaultChangeRefusal::Uncertain { present: None }),
        },
        Err(other) => Written::Refused(VaultChangeRefusal::Failed(other.to_string())),
    }
}

/// The record ID a vault reopened from disk lists for `name`, if any; `None` when it cannot be reopened.
fn listed_after_reopen(
    locks: &ServiceLocks,
    fs: &impl StoreFs,
    identity: Arc<VaultIdentity>,
    name: &CredentialName,
) -> Option<Option<RecordId>> {
    let (vault, _) = open_vault(&locks.state, fs, identity).ok()?;
    Some(
        vault
            .manifest()
            .entries()
            .iter()
            .find(|(_, entry)| entry.name() == name)
            .map(|(id, _)| *id),
    )
}

/// Lists `name` as healthy with no unavailable routes in the context's credential view, in name order. No active route
/// can use it before the next approval, so none is unavailable through it.
fn show_healthy(inner: &mut Inner, name: CredentialName, record_id: RecordId, summary: RecordSummary) {
    let Some(open) = &mut inner.open else {
        return;
    };
    if let Err(at) = open.credentials.binary_search_by(|standing| standing.name.cmp(&name)) {
        open.record_ids.insert(name.clone(), record_id);
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

/// Each affected route's reason, which names the route, separated by `; `.
fn in_use(routes: &[AffectedRoute]) -> String {
    routes
        .iter()
        .map(|affected| affected.reason.to_string())
        .collect::<Vec<_>>()
        .join("; ")
}

fn uncertain_message(present: Option<bool>) -> String {
    let listed = match present {
        Some(true) => "the reopened vault lists the record, so it was added",
        Some(false) => "the reopened vault does not list the record, so nothing changed",
        None => "the vault could not be reopened to see whether the record was added; run `iron-vault status`",
    };
    format!("the vault write may not survive power loss: the state directory fsync failed after the commit; {listed}")
}
