//! The trusted-path report: every trusted path a deployment names, checked in a fixed order, for startup and `status`.
//!
//! This module only reports. Whether an unsafe or unchecked path stops the service is the deployment profile's
//! decision; path cautions never stop it, so they are logged as warnings.

use std::path::{Path, PathBuf};

use crate::path_metadata::{self, CollectError};
use crate::trusted_path::{self, ExpectedOwner, PathCaution, Profile, TrustedPathRule, UnsafePath};

/// The name of the state-directory lock file inside the state directory.
const STATE_LOCK_FILE: &str = "lock";

/// The trusted paths a deployment names, with its profile and expected owner. The running binary is not listed: it
/// is found from the process itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServicePaths {
    /// Who may own the binary and config.
    pub profile: Profile,
    /// Who must own the state and runtime directories and the state files.
    pub owner: ExpectedOwner,
    /// The configuration file. Its directory is checked as the config path's last ancestor.
    pub config: PathBuf,
    /// The state directory.
    pub state_dir: PathBuf,
    /// The runtime directory holding the service's sockets, when the deployment uses one.
    pub runtime_dir: Option<PathBuf>,
}

/// Why a trusted path is not trusted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PathFailure {
    /// A component broke its rule.
    #[error(transparent)]
    Unsafe(#[from] UnsafePath),
    /// The path's metadata could not be collected, so it went unchecked.
    #[error(transparent)]
    Uncollected(#[from] CollectError),
}

/// One checked trusted path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedPathEntry {
    /// The rule the path was checked against.
    pub rule: TrustedPathRule,
    /// The path as the service names it; empty for the binary when the process could not name its own executable.
    pub path: PathBuf,
    /// The path's cautions when it is trusted, or why it is not.
    pub outcome: Result<Vec<PathCaution>, PathFailure>,
}

/// Every trusted path, in a fixed order: binary, config, state directory, state lock file, then runtime directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedPathReport {
    /// The checked paths, in report order.
    pub entries: Vec<TrustedPathEntry>,
}

impl TrustedPathReport {
    /// Checks the running binary and every path in `paths`.
    pub fn check(paths: &ServicePaths) -> Self {
        let named = [
            Some((TrustedPathRule::Config, paths.config.clone())),
            Some((TrustedPathRule::StateDir, paths.state_dir.clone())),
            Some((TrustedPathRule::StateFile, paths.state_dir.join(STATE_LOCK_FILE))),
            paths.runtime_dir.clone().map(|dir| (TrustedPathRule::RuntimeDir, dir)),
        ];
        let entries = named.into_iter().flatten().map(|(rule, path)| TrustedPathEntry {
            outcome: check_path(rule, paths.profile, paths.owner, &path),
            rule,
            path,
        });
        Self {
            entries: std::iter::once(binary_entry(paths.profile, paths.owner)).chain(entries).collect(),
        }
    }
}

/// Collects `path`'s metadata and checks it against `rule`, returning its path cautions when it is trusted.
pub fn check_path(rule: TrustedPathRule, profile: Profile, owner: ExpectedOwner, path: &Path) -> Result<Vec<PathCaution>, PathFailure> {
    let components = path_metadata::collect(path)?;
    Ok(trusted_path::check_with_cautions(rule, profile, owner, &components)?)
}

/// Logs each path caution of the report's trusted paths once, at WARN, with what it allows and how to fix it.
pub fn log_cautions(report: &TrustedPathReport) {
    report
        .entries
        .iter()
        .filter_map(|entry| entry.outcome.as_ref().ok().map(|cautions| (entry, cautions)))
        .flat_map(|(entry, cautions)| cautions.iter().map(|caution| caution_warning(caution, &entry.path)))
        .for_each(|warning| tracing::warn!("{warning}"));
}

/// The plain-language warning for a caution above `trusted`: the folder and its owner, the risk, the fix, and that
/// the service starts anyway. It names only paths and accounts, never anything from the vault.
fn caution_warning(caution: &PathCaution, trusted: &Path) -> String {
    let folder = caution.path.display();
    let trusted = trusted.display();
    let account = caution
        .owner_name
        .as_ref()
        .map_or_else(|| format!("uid {}", caution.uid), |name| format!("'{name}' (uid {})", caution.uid));
    let (file, effect, install) = match caution.rule {
        TrustedPathRule::Binary => (
            "service binary",
            "run that program",
            "or install the binary to /usr/bin (package) or /usr/local/bin (manual install)",
        ),
        _ => (
            "configuration file",
            "load that configuration",
            "or keep the configuration under /etc/iron-vault",
        ),
    };
    format!(
        "{folder} is owned by {account}, not root, and holds the {file} {trusted}. Anything running as {account} can \
         rename the {file} out of the way and put its own in its place; the next service start would {effect} with \
         the vault unlocked. To fix this, run `chown root:root {folder}` and `chmod go-w {folder}`, {install}. \
         The service is starting anyway."
    )
}

/// The running binary's entry: it must still be the file the process started from, and pass the binary rule.
fn binary_entry(profile: Profile, owner: ExpectedOwner) -> TrustedPathEntry {
    let rule = TrustedPathRule::Binary;
    match std::env::current_exe() {
        Ok(path) => {
            let outcome = path_metadata::ensure_running_binary(&path)
                .map_err(PathFailure::from)
                .and_then(|()| check_path(rule, profile, owner, &path));
            TrustedPathEntry { rule, path, outcome }
        }
        Err(e) => {
            let outcome = Err(PathFailure::Uncollected(CollectError::Io {
                path: PathBuf::new(),
                kind: e.kind(),
            }));
            TrustedPathEntry {
                rule,
                path: PathBuf::new(),
                outcome,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::{Arc, Mutex};

    use super::*;

    /// Collects everything the subscriber writes, so a test can read back the formatted log lines.
    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl io::Write for Captured {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn logged(report: &TrustedPathReport) -> String {
        let captured = Captured::default();
        let writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(subscriber, || log_cautions(report));
        String::from_utf8(captured.0.lock().unwrap().clone()).unwrap()
    }

    fn entry(rule: TrustedPathRule, path: &str, outcome: Result<Vec<PathCaution>, PathFailure>) -> TrustedPathEntry {
        TrustedPathEntry {
            rule,
            path: PathBuf::from(path),
            outcome,
        }
    }

    fn opt_caution(owner_name: Option<&str>) -> PathCaution {
        PathCaution {
            rule: TrustedPathRule::Binary,
            path: PathBuf::from("/opt/iron-vault"),
            uid: 997,
            owner_name: owner_name.map(str::to_string),
        }
    }

    #[test]
    fn a_caution_is_one_warning_naming_folder_owner_fix_and_that_the_service_starts() {
        let report = TrustedPathReport {
            entries: vec![entry(
                TrustedPathRule::Binary,
                "/opt/iron-vault/iron-vault",
                Ok(vec![opt_caution(Some("iron-vault"))]),
            )],
        };
        let log = logged(&report);
        let lines: Vec<&str> = log.lines().collect();
        assert_eq!(lines.len(), 1, "{log}");
        let line = lines[0];
        [
            "WARN",
            "/opt/iron-vault is owned by 'iron-vault' (uid 997), not root",
            "service binary /opt/iron-vault/iron-vault",
            "with the vault unlocked",
            "`chown root:root /opt/iron-vault`",
            "`chmod go-w /opt/iron-vault`",
            "/usr/bin (package) or /usr/local/bin (manual install)",
            "starting anyway",
        ]
        .into_iter()
        .for_each(|expected| assert!(line.contains(expected), "missing {expected:?} in {line}"));
    }

    #[test]
    fn an_unnamed_owner_is_shown_by_uid() {
        let warning = caution_warning(&opt_caution(None), Path::new("/opt/iron-vault/iron-vault"));
        assert!(warning.starts_with("/opt/iron-vault is owned by uid 997, not root"), "{warning}");
    }

    #[test]
    fn trusted_paths_without_cautions_log_nothing() {
        let refused = Err(PathFailure::Uncollected(CollectError::Io {
            path: PathBuf::from("/etc/iron-vault/config.toml"),
            kind: io::ErrorKind::NotFound,
        }));
        let report = TrustedPathReport {
            entries: vec![
                entry(TrustedPathRule::Binary, "/usr/bin/iron-vault", Ok(vec![])),
                entry(TrustedPathRule::Config, "/etc/iron-vault/config.toml", refused),
            ],
        };
        assert_eq!(logged(&report), "");
    }
}
