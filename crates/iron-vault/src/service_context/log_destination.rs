//! Moves the audit log to the destination an approved config chooses
//! ([audit logging: Switching at activation](../../../../design/audit-logging.md#switching-at-activation)):
//!
//! ```text
//!   config approve, before step 2 reserves a version   precheck      creates nothing, opens nothing for writing
//!   config check, its last step                        open_chosen   opens and verifies the directory
//!   entering Ready                                     switch        logs the change to the old and the new destination
//! ```
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
    /// The directory is, or lies inside, the state or config directory, named here.
    Reserved(&'static str),
    /// A path could not be canonicalised, so whether the directory lies inside a reserved one cannot be decided.
    Unresolved,
}

impl Unusable {
    fn phrase(&self) -> String {
        match self {
            Self::Open(error) => error.phrase(),
            Self::Reserved(reserved) => format!("the log directory is, or is inside, the {reserved}"),
            Self::Unresolved => "the log directory cannot be resolved to a canonical path".to_owned(),
        }
    }
}

/// Opens and verifies the destination `config` chooses when it differs from the current one, for [`switch`]. Returns
/// `None` when the log stays where it is.
pub(super) fn open_chosen(config: &ValidatedConfig, log: &LogSwitch, paths: &ServicePaths) -> Result<Option<OpenedLog>, InvalidConfig> {
    let Some(destination) = moved(config, log) else { return Ok(None) };
    check_outside(config.log_destination(), paths)
        .and_then(|()| log.open_destination(destination.clone()).map_err(Unusable::Open))
        .map(Some)
        .map_err(|unusable| refused(&destination, &unusable))
}

/// Runs `config approve`'s check of the destination `config` chooses, when it differs from the current one. It
/// creates nothing and opens nothing for writing; the check at activation still runs, since the directory can change
/// in between.
pub(super) fn precheck(config: &ValidatedConfig, log: &LogSwitch, paths: &ServicePaths) -> Result<(), InvalidConfig> {
    let Some(destination) = moved(config, log) else { return Ok(()) };
    check_outside(config.log_destination(), paths)
        .and_then(|()| log.opener().precheck(&destination).map_err(Unusable::Open))
        .map_err(|unusable| refused(&destination, &unusable))
}

/// Points the log at `opened`, writing `service.log-destination-changed` to the old destination and then to the new
/// one.
pub(super) fn switch(log: &LogSwitch, opened: OpenedLog, version: ApprovalVersion) {
    let changed = LogDestinationChanged {
        destination: opened.destination().clone(),
        previous: log.current(),
        version,
    };
    changed.emit();
    log.switch(opened);
    changed.emit();
}

/// Returns the destination `config` chooses, or `None` when it is the current one.
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
        .map_err(|error| match error {
            LogDestinationError::InsideReserved { reserved, .. } => Unusable::Reserved(reserved),
            // Only parsing a setting gives these, and the canonical path parsed above.
            LogDestinationError::ControlCharacter { .. } | LogDestinationError::Path(_) => Unusable::Unresolved,
        })
}

/// Canonicalises a reserved directory. The service holds both directories locked, so this fails only on a broken
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

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;
    use crate::deployment::DeploymentProfile;
    use crate::trusted_path::ExpectedOwner;

    /// A fresh directory holding `state`, `etc` and `logs`, removed on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            static NEXT: AtomicU32 = AtomicU32::new(0);
            let name = format!("iv-reserved-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed));
            let root = std::env::temp_dir().join(name);
            let _ = fs::remove_dir_all(&root);
            ["state", "state/logs", "etc", "logs"]
                .iter()
                .for_each(|dir| fs::create_dir_all(root.join(dir)).unwrap());
            Self(root)
        }

        /// The service's paths, with the state and config directories named by `state` and `etc` under the root.
        fn paths(&self, state: &str, etc: &str) -> ServicePaths {
            ServicePaths {
                profile: DeploymentProfile::Development,
                owner: ExpectedOwner {
                    uid: rustix::process::getuid().as_raw(),
                },
                config: self.0.join(etc).join("config.toml"),
                state_dir: self.0.join(state),
                runtime_dir: None,
            }
        }

        fn link(&self, name: &str, to: &str) -> &Self {
            symlink(self.0.join(to), self.0.join(name)).unwrap();
            self
        }

        fn setting(&self, dir: &str) -> LogDestinationSetting {
            LogDestinationSetting::try_from(self.0.join(dir).to_str().unwrap()).unwrap()
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn reserved(result: Result<(), Unusable>) -> Option<&'static str> {
        match result {
            Err(Unusable::Reserved(reserved)) => Some(reserved),
            _ => None,
        }
    }

    #[test]
    fn a_directory_outside_both_reserved_directories_passes() {
        let scratch = Scratch::new();
        assert!(check_outside(Some(&scratch.setting("logs")), &scratch.paths("state", "etc")).is_ok());
    }

    #[test]
    fn a_directory_inside_the_state_directory_or_naming_the_config_directory_is_refused() {
        let scratch = Scratch::new();
        let paths = scratch.paths("state", "etc");
        assert_eq!(
            reserved(check_outside(Some(&scratch.setting("state/logs")), &paths)),
            Some("state directory")
        );
        assert_eq!(
            reserved(check_outside(Some(&scratch.setting("etc")), &paths)),
            Some("config directory")
        );
    }

    #[test]
    fn a_log_directory_named_through_a_symlink_is_refused_where_it_resolves() {
        let scratch = Scratch::new();
        scratch.link("state-logs", "state/logs").link("config-link", "etc");
        let paths = scratch.paths("state", "etc");
        assert_eq!(
            reserved(check_outside(Some(&scratch.setting("state-logs")), &paths)),
            Some("state directory")
        );
        assert_eq!(
            reserved(check_outside(Some(&scratch.setting("config-link")), &paths)),
            Some("config directory")
        );
    }

    #[test]
    fn reserved_directories_named_through_a_symlink_still_hold_the_log_directory() {
        let scratch = Scratch::new();
        scratch.link("state-alias", "state").link("etc-alias", "etc");
        let paths = scratch.paths("state-alias", "etc-alias");
        assert_eq!(
            reserved(check_outside(Some(&scratch.setting("state/logs")), &paths)),
            Some("state directory")
        );
        assert_eq!(
            reserved(check_outside(Some(&scratch.setting("etc")), &paths)),
            Some("config directory")
        );
    }

    #[test]
    fn a_reserved_directory_that_cannot_be_resolved_refuses_the_log_directory() {
        let scratch = Scratch::new();
        let result = check_outside(Some(&scratch.setting("logs")), &scratch.paths("missing", "etc"));
        assert!(matches!(result, Err(Unusable::Unresolved)));
    }

    #[test]
    fn stdout_and_no_setting_have_no_directory_to_check() {
        let scratch = Scratch::new();
        let paths = scratch.paths("missing", "missing");
        assert!(check_outside(Some(&LogDestinationSetting::Stdout), &paths).is_ok());
        assert!(check_outside(None, &paths).is_ok());
    }
}
