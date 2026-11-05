//! The log destination an approved config chooses: opened as the config check's last step, checked by `config approve`
//! before it reserves a version, and switched to on entering Ready (`design/audit-logging.md`, "Switching at
//! activation").
//!
//! Nothing happens when the chosen destination is the current one. A config that sets none chooses the bootstrap
//! destination, so removing the setting moves the log back.

use std::path::{Path, PathBuf};

use iron_vault_policy::{LogDestinationError, LogDestinationSetting, ValidatedConfig};
use iron_vault_store::ApprovalVersion;

use crate::audit::{AuditEvent, LogDestinationChanged};
use crate::config_check::{InvalidConfig, UnusableLog};
use crate::logging::{LogDestination, LogOpenError, LogSwitch, OpenedLog};
use crate::trusted_path_report::ServicePaths;

/// Why a chosen destination cannot be used.
enum Unusable {
    Open(LogOpenError),
    /// The directory is, or lies inside, the state or config directory.
    Reserved(LogDestinationError),
    /// A path could not be canonicalised, so whether the directory lies inside a reserved one cannot be decided.
    Unresolved,
}

impl Unusable {
    fn phrase(&self) -> String {
        match self {
            Self::Open(error) => error.phrase(),
            Self::Reserved(LogDestinationError::InsideReserved { reserved, .. }) => {
                format!("the log directory is, or is inside, the {reserved}")
            }
            Self::Reserved(_) | Self::Unresolved => "the log directory cannot be resolved to a canonical path".to_owned(),
        }
    }
}

/// Opens and verifies the destination `config` chooses when it differs from the current one, for [`switch`]; `None`
/// when the log stays where it is.
pub(super) fn open_chosen(config: &ValidatedConfig, log: &LogSwitch, paths: &ServicePaths) -> Result<Option<OpenedLog>, InvalidConfig> {
    let Some(destination) = moved(config, log) else { return Ok(None) };
    check_outside(config.log_destination(), paths)
        .and_then(|()| log.open_destination(destination.clone()).map_err(Unusable::Open))
        .map(Some)
        .map_err(|unusable| refused(&destination, &unusable))
}

/// `config approve`'s check of the destination `config` chooses, when it differs from the current one. It creates
/// nothing and opens nothing for writing; the check at activation still runs, since the directory can change in between.
pub(super) fn precheck(config: &ValidatedConfig, log: &LogSwitch, paths: &ServicePaths) -> Result<(), InvalidConfig> {
    let Some(destination) = moved(config, log) else { return Ok(()) };
    check_outside(config.log_destination(), paths)
        .and_then(|()| log.opener().precheck(&destination).map_err(Unusable::Open))
        .map_err(|unusable| refused(&destination, &unusable))
}

/// Points the log at `opened`, writing `service.log-destination-changed` to the old destination and then to the new one.
pub(super) fn switch(log: &LogSwitch, opened: OpenedLog, version: Option<ApprovalVersion>) {
    let changed = LogDestinationChanged {
        destination: opened.destination().clone(),
        previous: log.current(),
        version,
    };
    changed.emit();
    log.switch(opened);
    changed.emit();
}

/// The destination `config` chooses, when it is not the current one.
fn moved(config: &ValidatedConfig, log: &LogSwitch) -> Option<LogDestination> {
    let chosen = match config.log_destination() {
        Some(LogDestinationSetting::Stdout) => LogDestination::Stdout,
        Some(LogDestinationSetting::Directory(path)) => LogDestination::Directory(path.as_path().to_path_buf()),
        None => log.bootstrap().clone(),
    };
    (chosen != log.current()).then_some(chosen)
}

/// Refuses a configured directory that is, or lies inside, the state or config directory. The comparison is lexical,
/// so every path is canonicalised first: a symlink alias, such as `/home` to `/var/home` on Fedora Atomic, would
/// otherwise hide the overlap.
fn check_outside(setting: Option<&LogDestinationSetting>, paths: &ServicePaths) -> Result<(), Unusable> {
    let Some(dir) = setting.and_then(LogDestinationSetting::directory) else {
        return Ok(());
    };
    let canonical_dir = dir.canonicalize().map_err(|error| {
        Unusable::Open(LogOpenError::Directory {
            path: dir.to_path_buf(),
            kind: error.kind(),
        })
    })?;
    let setting = canonical_dir
        .to_str()
        .and_then(|path| LogDestinationSetting::try_from(path).ok())
        .ok_or(Unusable::Unresolved)?;
    let state = reserved(Some(&paths.state_dir))?;
    let config = reserved(paths.config.parent())?;
    setting
        .check_outside(&[("state directory", &state), ("config directory", &config)])
        .map_err(Unusable::Reserved)
}

/// A reserved directory canonicalised. The service holds both directories locked, so this fails only on a broken
/// install, and then the overlap cannot be ruled out.
fn reserved(path: Option<&Path>) -> Result<PathBuf, Unusable> {
    path.and_then(|path| path.canonicalize().ok()).ok_or(Unusable::Unresolved)
}

fn refused(destination: &LogDestination, unusable: &Unusable) -> InvalidConfig {
    InvalidConfig::LogDestination(UnusableLog {
        destination: destination.to_string(),
        phrase: unusable.phrase(),
    })
}
