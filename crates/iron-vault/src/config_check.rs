//! The config check: the work the service does in Checking (specification §3.9, §3.12, §8.2 Q-5).
//!
//! Startup, reload, an approval's commit and a repair all call [`check_config`], so they cannot disagree about what a
//! servable config is. It recovers any committed transaction, parses, validates and activates the config the recovered
//! pair holds, and builds one [`ServingSnapshot`]. Any failure is a [`CheckFailure`] that names the safe state that
//! follows and carries nothing a `503` body or a status answer must not show. The check never writes the approval state.
//!
//! Recovery verifies the published pair against the committed approval and returns the config bytes as read back, so
//! the check parses exactly the bytes that verified and does not verify a second time.

#[cfg(test)]
mod tests;

use std::time::Instant;

use iron_vault_policy::{
    AccountDirectory, ActivationError, ActivePolicy, Capabilities, ConfigError, ParsedConfig, RateLimiter, ValidatedConfig,
    ValidationError, activate,
};
use iron_vault_store::{
    ApprovalRecoveryError, ApprovalState, ApprovalStateError, ConfigDirLock, RecoveryFailure, StoreFs, Vault, VaultError, recover_approval,
};

use crate::deployment::DeploymentProfile;
use crate::service_state::{FailureReason, UnavailableReason};
use crate::serving_snapshot::{ServingSnapshot, SnapshotError};
use crate::trusted_path::ExpectedOwner;
use crate::upstream::client::{ClientBuildError, TransportLimits};
use crate::upstream::clients::UpstreamClients;

/// How the check builds the upstream clients of the snapshot.
#[derive(Debug, Clone, Copy)]
pub struct UpstreamSettings {
    /// The deployment profile, which decides how a pinned CA file's path is trusted.
    pub profile: DeploymentProfile,
    /// The owner a pinned CA file must have.
    pub owner: ExpectedOwner,
    /// The transport deadlines.
    pub limits: TransportLimits,
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
    /// Approval recovery refused: a committed transaction cannot be completed, nothing is committed, or the published
    /// pair does not verify as the committed approval.
    #[error("{}", recovery_status(.0.failure()))]
    Recovery(ApprovalRecoveryError),
    /// The approved config is not servable: it does not parse, validate or activate, or its parts cannot form a snapshot.
    #[error("policy invalid: config invalid")]
    Config(InvalidConfig),
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
}

/// The status text for a recovery refusal.
const fn recovery_status(failure: RecoveryFailure) -> &'static str {
    match failure {
        RecoveryFailure::RecoveryNeeded => "recovery needed: committed approval cannot be published",
        RecoveryFailure::PolicyInvalid => "policy invalid: config approval does not verify",
    }
}

impl CheckFailure {
    /// The failure reason the service state machine takes (`CheckFailed`).
    pub fn failure(&self) -> FailureReason {
        match self {
            Self::Vault(_) | Self::ApprovalState(_) => FailureReason::RecoveryNeeded,
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
        }
    }
}

impl InvalidConfig {
    fn detail(&self) -> String {
        match self {
            Self::Parse(error) => parse_detail(error),
            Self::Validation(errors) => errors.iter().map(validation_detail).collect::<Vec<_>>().join("; "),
            Self::Activation(errors) => errors.iter().map(activation_detail).collect::<Vec<_>>().join("; "),
            Self::Clients(error) => error.to_string(),
            Self::Snapshot(error) => error.to_string(),
        }
    }
}

/// A parse error by position only: the parser's message may quote the offending value.
fn parse_detail(error: &ConfigError) -> String {
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

/// Runs the config check and returns the snapshot to serve, or the failure that leaves the service Unavailable.
///
/// `vault` and `state` are the opened shared state; `config_dir` is the held config directory lock. A damaged or
/// needs-login credential record is not a failure: activation marks only its routes unavailable (§3.9). The vault moves
/// into the snapshot on success and is dropped on failure, so the next check opens it again. A failure is logged here at
/// WARN as `config.check-failed`, with its [`detail`](CheckFailure::detail), so every caller reports it the same way.
pub fn check_config(
    config_dir: &ConfigDirLock,
    fs: &impl StoreFs,
    vault: Vault,
    state: &ApprovalState,
    capabilities: &Capabilities,
    accounts: &impl AccountDirectory,
    upstream: UpstreamSettings,
) -> Result<ServingSnapshot, CheckFailure> {
    run(config_dir, fs, vault, state, capabilities, accounts, upstream).inspect_err(|failure| {
        tracing::warn!(
            event = "config.check-failed",
            reason = failure.unavailable().as_str(),
            status = %failure,
            detail = %failure.detail(),
            "the config check failed",
        );
    })
}

fn run(
    config_dir: &ConfigDirLock,
    fs: &impl StoreFs,
    vault: Vault,
    state: &ApprovalState,
    capabilities: &Capabilities,
    accounts: &impl AccountDirectory,
    upstream: UpstreamSettings,
) -> Result<ServingSnapshot, CheckFailure> {
    let recovered = recover_approval(config_dir, fs, state).map_err(CheckFailure::Recovery)?;
    let policy = activate_config(recovered.published().config(), capabilities, &vault, accounts).map_err(CheckFailure::Config)?;
    let clients = UpstreamClients::new(&policy, upstream.profile, upstream.owner, upstream.limits)
        .map_err(|error| CheckFailure::Config(InvalidConfig::Clients(error)))?;
    let limiter = RateLimiter::new(&policy, Instant::now());
    ServingSnapshot::new(policy, vault, clients, limiter).map_err(|error| CheckFailure::Config(InvalidConfig::Snapshot(error)))
}

/// Parses, validates and activates `bytes` against `vault`'s credential catalog.
fn activate_config(
    bytes: &[u8],
    capabilities: &Capabilities,
    vault: &Vault,
    accounts: &impl AccountDirectory,
) -> Result<ActivePolicy, InvalidConfig> {
    let parsed = ParsedConfig::from_toml(bytes).map_err(InvalidConfig::Parse)?;
    let config = ValidatedConfig::try_from(parsed).map_err(InvalidConfig::Validation)?;
    activate(&config, capabilities, vault, accounts).map_err(InvalidConfig::Activation)
}
