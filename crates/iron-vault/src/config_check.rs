//! The config check: the work the service does in Checking (specification §3.9, §3.12, §8.2 Q-5).
//!
//! Every entry to Checking (an unlock, a reload, an approval's commit, a repair) calls [`open_and_check`], which opens a
//! new vault from the vault identity the service keeps and then runs [`check_config`], so they cannot disagree about
//! what a servable config is. It recovers any committed transaction, parses, validates and activates the config the
//! recovered pair holds, and builds one [`ServingSnapshot`]. Any failure is a [`CheckFailure`] that names the safe state
//! that follows and carries nothing a `503` body or a status answer must not show. The check never writes the approval
//! state.
//!
//! Recovery verifies the published pair against the committed approval and returns the config bytes as read back, so
//! the check parses exactly the bytes that verified and does not verify a second time.

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use iron_vault_policy::{
    AccountDirectory, ActivationError, ActivePolicy, Capabilities, ConfigError, CredentialName, ParsedConfig, RateLimiter, ValidatedConfig,
    ValidationError, activate,
};
use iron_vault_store::{
    ApprovalRecoveryError, ApprovalState, ApprovalStateError, ConfigDirLock, PublishedPairFault, RecordId, RecoveryFailure, StateDirLock,
    StoreFs, Vault, VaultError, VaultIdentity, recover_approval,
};

use crate::audit::config::{record_recovery, record_unverified_publish};
use crate::audit::corruption::open_vault;
use crate::audit::{AuditEvent, CheckFailed};
use crate::deployment::DeploymentProfile;
use crate::service_state::{FailureReason, UnavailableReason};
use crate::serving_snapshot::{ServingSnapshot, SnapshotError};
use crate::standing::{CredentialStanding, RouteFault};
use crate::trusted_path::ExpectedOwner;
use crate::upstream::client::{ClientBuildError, TransportLimits};
use crate::upstream::clients::UpstreamClients;
#[cfg(any(test, feature = "test-support"))]
use crate::upstream::trust::{PinnedCaError, UpstreamTrust};

/// How the check builds the upstream clients of the snapshot.
#[derive(Debug, Clone)]
pub struct UpstreamSettings {
    /// The deployment profile, which decides how a pinned CA file's path is trusted.
    profile: DeploymentProfile,
    /// The owner a pinned CA file must have.
    owner: ExpectedOwner,
    /// The transport deadlines.
    limits: TransportLimits,
    /// What every pinned CA route gets instead of its file, for integration tests: a trust, or a load failure.
    #[cfg(any(test, feature = "test-support"))]
    pinned: Option<Result<UpstreamTrust, PinnedCaError>>,
}

impl UpstreamSettings {
    /// Settings that read each pinned CA file through its trusted-path rule for `profile` and `owner`.
    pub fn new(profile: DeploymentProfile, owner: ExpectedOwner, limits: TransportLimits) -> Self {
        Self {
            profile,
            owner,
            limits,
            #[cfg(any(test, feature = "test-support"))]
            pinned: None,
        }
    }

    /// Gives every pinned CA route `trust` instead of reading its file, so integration tests can pin a test CA without
    /// a trusted path on disk. The `test-support` feature that exposes it is enabled only by this crate's own
    /// dev-dependency.
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_pinned_trust(self, trust: UpstreamTrust) -> Self {
        Self {
            pinned: Some(Ok(trust)),
            ..self
        }
    }

    /// Fails every pinned CA route's load with `error` instead of reading its file, so tests can show a CA that does
    /// not load without one on disk.
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_pinned_failure(self, error: PinnedCaError) -> Self {
        Self {
            pinned: Some(Err(error)),
            ..self
        }
    }

    pub(crate) fn clients(&self, policy: &ActivePolicy) -> Result<UpstreamClients, ClientBuildError> {
        #[cfg(any(test, feature = "test-support"))]
        if let Some(pinned) = &self.pinned {
            return UpstreamClients::with_pinned_loader(policy, self.limits, |_| pinned.clone());
        }
        UpstreamClients::new(policy, self.profile, self.owner, self.limits)
    }
}

/// Why the check did not produce a snapshot.
///
/// `Display` is the fixed [`status`](Self::status) text. [`detail`](Self::detail) is for the owner's log only.
#[derive(Debug, thiserror::Error)]
pub enum CheckFailure {
    /// The vault could not be opened as a whole: its manifest or a shared state file is missing, forged or damaged.
    #[error("recovery needed: shared state damaged")]
    Vault(VaultError),
    /// The approval state could not be opened as a whole.
    #[error("recovery needed: shared state damaged")]
    ApprovalState(ApprovalStateError),
    /// Approval recovery refused: a config file cannot be read, a committed transaction cannot be completed, nothing is
    /// committed, or the published pair does not verify as the committed approval. The status text names an unreadable
    /// file's cause class, since the owner's fix is permissions or the disk and not the publish.
    #[error("{}", recovery_status(.0))]
    Recovery(ApprovalRecoveryError),
    /// The approved config is not servable: it does not parse, validate or activate, or its parts cannot form a snapshot.
    #[error("policy invalid: config invalid")]
    Config(InvalidConfig),
    /// The check's task ended without a result: it panicked, or the runtime is shutting down. Nothing was checked, so
    /// the service fails closed. The status says the check crashed, so the owner retries it rather than recovering a
    /// vault that may be sound.
    #[error("recovery needed: config check crashed; lock and unlock to check again")]
    Interrupted,
}

/// Why a config whose approval verified is not servable.
#[derive(Debug, thiserror::Error)]
pub enum InvalidConfig {
    /// The document does not parse.
    #[error(transparent)]
    Parse(ConfigError),
    /// The sections contradict each other.
    #[error("{} validation errors", .0.len())]
    Validation(Vec<ValidationError>),
    /// The config cannot be activated against the vault, the capabilities and the host's accounts.
    #[error("{} activation errors", .0.len())]
    Activation(Vec<ActivationError>),
    /// The built-in upstream client cannot be built, so no route could be served.
    #[error(transparent)]
    Clients(ClientBuildError),
    /// The policy and the vault disagree about which routes are available.
    #[error(transparent)]
    Snapshot(SnapshotError),
    /// The log destination the config chooses cannot be opened or verified.
    #[error("the log destination is unusable")]
    LogDestination(UnusableLog),
}

/// A log destination the config check, or `config approve`'s pre-check, refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnusableLog {
    /// The destination in `log_destination`'s form: configuration the owner approved, recorded in a field of its own.
    pub destination: String,
    /// The fixed phrase of the check that refused it, which never holds the path.
    pub phrase: String,
}

/// The status text for a recovery refusal. A file that cannot be read, before recovery or in the read-back after its
/// publish, gets its own text and no path; the `503` body is still the fixed `recovery needed`.
fn recovery_status(error: &ApprovalRecoveryError) -> &'static str {
    match error {
        ApprovalRecoveryError::Unreadable { .. }
        | ApprovalRecoveryError::PublishNotVerified {
            published: PublishedPairFault::Unreadable { .. },
            ..
        } => "recovery needed: a config file cannot be read (permissions or disk)",
        other => match other.failure() {
            RecoveryFailure::RecoveryNeeded => "recovery needed: committed approval cannot be published",
            RecoveryFailure::PolicyInvalid => "policy invalid: config approval does not verify",
        },
    }
}

impl CheckFailure {
    /// The failure reason the service state machine takes (`CheckFailed`).
    pub fn failure(&self) -> FailureReason {
        match self {
            Self::Vault(_) | Self::ApprovalState(_) | Self::Interrupted => FailureReason::RecoveryNeeded,
            Self::Recovery(error) => match error.failure() {
                RecoveryFailure::RecoveryNeeded => FailureReason::RecoveryNeeded,
                RecoveryFailure::PolicyInvalid => FailureReason::PolicyInvalid,
            },
            Self::Config(_) => FailureReason::PolicyInvalid,
        }
    }

    /// The reason a request listener gives with its `503`. A fixed category; it names nothing of the config.
    pub fn unavailable(&self) -> UnavailableReason {
        UnavailableReason::from_failure(self.failure())
    }

    /// The fixed status text: the `503` category and, after a colon, which part of the check failed. Never names a
    /// config byte, a path or a secret.
    pub fn status(&self) -> String {
        self.to_string()
    }

    /// What the owner's log says: versions, route names and credential names, never config or signature bytes, URLs,
    /// paths or key material.
    pub fn detail(&self) -> String {
        match self {
            Self::Vault(error) => error.to_string(),
            Self::ApprovalState(error) => error.to_string(),
            Self::Recovery(error) => error.to_string(),
            Self::Config(invalid) => invalid.detail(),
            Self::Interrupted => {
                "the config check crashed before it gave a result; nothing was checked, and the vault may be sound".to_owned()
            }
        }
    }

    /// The log destination that failed the check, when that is why it failed.
    pub fn log_destination(&self) -> Option<&str> {
        match self {
            Self::Config(InvalidConfig::LogDestination(unusable)) => Some(&unusable.destination),
            _ => None,
        }
    }

    /// The failure of a check whose task ended without a result, logged as every check failure is.
    pub(crate) fn interrupted() -> Self {
        let failure = Self::Interrupted;
        log_failure(&failure);
        failure
    }
}

impl InvalidConfig {
    /// What the owner's log and a `config-invalid` answer say: the rule broken and the configured names involved,
    /// never config bytes, URLs or paths.
    pub(crate) fn detail(&self) -> String {
        match self {
            Self::Parse(error) => parse_detail(error),
            Self::Validation(errors) => errors.iter().map(validation_detail).collect::<Vec<_>>().join("; "),
            Self::Activation(errors) => errors.iter().map(activation_detail).collect::<Vec<_>>().join("; "),
            Self::Clients(error) => error.to_string(),
            Self::Snapshot(error) => error.to_string(),
            Self::LogDestination(unusable) => unusable.phrase.clone(),
        }
    }
}

/// A parse error by position only: the parser's message may quote the offending value.
pub(crate) fn parse_detail(error: &ConfigError) -> String {
    match error {
        ConfigError::NotUtf8 { location } => format!("config is not valid UTF-8 at {location}"),
        ConfigError::MissingSchemaVersion { location } => format!("config has no schema_version at {location}"),
        ConfigError::UnsupportedSchemaVersion { version, location } => {
            format!("config schema_version {version} is unsupported at {location}")
        }
        ConfigError::Invalid { location, .. } => match location {
            Some(location) => format!("config is invalid at {location}"),
            None => "config is invalid".to_owned(),
        },
    }
}

/// A validation error's message, except for the two that quote config content (an address and a path prefix).
/// `ListenerNeedsTls` keeps its address: it is re-rendered from a parsed `SocketAddr`, so it holds no config text.
fn validation_detail(error: &ValidationError) -> String {
    match error {
        ValidationError::UndedicatedAddress { caller, listener, .. } => {
            format!("caller {caller} needs listener {listener} to bind a dedicated address")
        }
        ValidationError::AmbiguousPrefix { route, other, .. } => format!("route {route} prefix overlaps route {other} prefix"),
        other => other.to_string(),
    }
}

/// An activation error's message, except for the one that quotes the route's upstream.
fn activation_detail(error: &ActivationError) -> String {
    match error {
        ActivationError::OriginNotPermitted { route, credential, .. } => {
            format!("route {route} sends credential {credential} to an origin its record does not permit")
        }
        other => other.to_string(),
    }
}

/// What a passed check on a freshly opened vault yields.
#[derive(Debug)]
pub struct Checked {
    /// The snapshot to serve, which holds the vault.
    pub snapshot: ServingSnapshot,
    /// The vault's approval state.
    pub approval: ApprovalState,
    /// Each credential's standing, in name order; only the report of opening the vault knows it.
    pub credentials: Vec<CredentialStanding>,
    /// The record ID of each credential the manifest lists, damaged ones included.
    pub record_ids: BTreeMap<CredentialName, RecordId>,
    /// Each route fault, in name order.
    pub route_faults: Vec<RouteFault>,
}

/// Opens a new vault from `identity` and loads its approval state, then runs the config check, for a service entering
/// Checking.
///
/// Damaged shared state that keeps the vault or the approval state from opening is a check failure like any other
/// ([`CheckFailure::Vault`], [`CheckFailure::ApprovalState`]), logged the same way. On success the vault is in the
/// snapshot, and the approval state and each credential's standing (which only the open report knows) are returned
/// beside it. On failure all are dropped with the vault's decrypted records; the caller's reference to `identity`
/// stays, so the next check needs no new unlock.
pub fn open_and_check(
    state_dir: &StateDirLock,
    config_dir: &ConfigDirLock,
    fs: &impl StoreFs,
    identity: Arc<VaultIdentity>,
    capabilities: &Capabilities,
    accounts: &impl AccountDirectory,
    upstream: &UpstreamSettings,
) -> Result<Checked, CheckFailure> {
    open_and_run(state_dir, config_dir, fs, identity, capabilities, accounts, upstream).inspect_err(log_failure)
}

fn open_and_run(
    state_dir: &StateDirLock,
    config_dir: &ConfigDirLock,
    fs: &impl StoreFs,
    identity: Arc<VaultIdentity>,
    capabilities: &Capabilities,
    accounts: &impl AccountDirectory,
    upstream: &UpstreamSettings,
) -> Result<Checked, CheckFailure> {
    let (vault, opened) = open_vault(state_dir, fs, identity).map_err(CheckFailure::Vault)?;
    let approval = vault.load_approval_state(state_dir, fs).map_err(CheckFailure::ApprovalState)?;
    let snapshot = run(config_dir, fs, vault, &approval, capabilities, accounts, upstream)?;
    Ok(Checked {
        credentials: snapshot.credential_standings(&opened),
        record_ids: snapshot.record_ids(),
        route_faults: snapshot.route_faults(),
        snapshot,
        approval,
    })
}

/// Runs the config check and returns the snapshot to serve, or the failure that leaves the service Unavailable.
///
/// `vault` and `state` are the opened shared state; `config_dir` is the held config directory lock. A damaged or
/// needs-login credential record is not a failure: activation marks only its routes unavailable (§3.9). Nor is a
/// pinned CA that fails to load: the routes that pin it are marked unavailable the same way, and logged. The vault moves
/// into the snapshot on success and is dropped on failure, so the next check opens it again. A failure is logged here at
/// WARN as `config.check-failed`, with its [`detail`](CheckFailure::detail). Opening the vault and the approval state
/// comes before this function; [`open_and_check`] logs a failure there the same way.
pub fn check_config(
    config_dir: &ConfigDirLock,
    fs: &impl StoreFs,
    vault: Vault,
    state: &ApprovalState,
    capabilities: &Capabilities,
    accounts: &impl AccountDirectory,
    upstream: &UpstreamSettings,
) -> Result<ServingSnapshot, CheckFailure> {
    run(config_dir, fs, vault, state, capabilities, accounts, upstream).inspect_err(log_failure)
}

fn log_failure(failure: &CheckFailure) {
    CheckFailed { failure }.emit();
}

fn run(
    config_dir: &ConfigDirLock,
    fs: &impl StoreFs,
    vault: Vault,
    state: &ApprovalState,
    capabilities: &Capabilities,
    accounts: &impl AccountDirectory,
    upstream: &UpstreamSettings,
) -> Result<ServingSnapshot, CheckFailure> {
    let recovered = recover_approval(config_dir, fs, state)
        .inspect_err(record_unverified_publish)
        .map_err(CheckFailure::Recovery)?;
    record_recovery(&recovered);
    let policy = activate_config(recovered.published().config(), capabilities, &vault, accounts).map_err(CheckFailure::Config)?;
    let clients = upstream
        .clients(&policy)
        .map_err(|error| CheckFailure::Config(InvalidConfig::Clients(error)))?;
    let policy = clients.mark_unusable_routes(policy);
    let limiter = RateLimiter::new(&policy, Instant::now());
    ServingSnapshot::new(policy, vault, clients, limiter).map_err(|error| CheckFailure::Config(InvalidConfig::Snapshot(error)))
}

/// Parses, validates and activates `bytes` against `vault`'s credential catalog.
pub(crate) fn activate_config(
    bytes: &[u8],
    capabilities: &Capabilities,
    vault: &Vault,
    accounts: &impl AccountDirectory,
) -> Result<ActivePolicy, InvalidConfig> {
    let parsed = ParsedConfig::from_toml(bytes).map_err(InvalidConfig::Parse)?;
    let config = ValidatedConfig::try_from(parsed).map_err(InvalidConfig::Validation)?;
    activate(&config, capabilities, vault, accounts).map_err(InvalidConfig::Activation)
}
