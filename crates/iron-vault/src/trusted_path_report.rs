// SPDX-License-Identifier: MPL-2.0
//! The trusted-path report: every trusted path a deployment names, checked in a fixed order, for startup and `status`.
//!
//! The service reads every path in the report before it unlocks anything, so startup refuses an unsafe or unchecked
//! one ([`TrustedPathReport::refusal`]). Path cautions never stop it, so they are logged as warnings.

use std::io;
use std::path::{Path, PathBuf};

use crate::deployment::DeploymentProfile;
use crate::path_metadata::{self, CollectError};
use crate::trusted_path::{self, CautionedFile, ExpectedOwner, PathCaution, TrustedPathRule, UnsafePath};

/// The name of the state-directory lock file inside the state directory.
const STATE_LOCK_FILE: &str = "lock";

/// The name of the config-directory lock file inside the config directory.
const CONFIG_LOCK_FILE: &str = "config.toml.lock";

/// The trusted paths a deployment names, with its profile and expected owner. The running binary is not listed: it
/// is found from the process itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServicePaths {
    /// Who may own the binary.
    pub profile: DeploymentProfile,
    /// Who must own the config, the state and runtime directories and the state files.
    pub owner: ExpectedOwner,
    /// The configuration file. Its directory is the config directory.
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

/// Every trusted path, in a fixed order: binary, config directory, config, config lock file, state directory, state lock
/// file, then runtime directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedPathReport {
    /// The checked paths, in report order.
    pub entries: Vec<TrustedPathEntry>,
}

impl TrustedPathReport {
    /// Checks the running binary and every path in `paths`.
    pub fn check(paths: &ServicePaths) -> Self {
        let config_dir = paths.config.parent();
        let named = [
            config_dir.map(|dir| (TrustedPathRule::ConfigDir, dir.to_path_buf())),
            Some((TrustedPathRule::Config, paths.config.clone())),
            config_dir.map(|dir| (TrustedPathRule::StateFile, dir.join(CONFIG_LOCK_FILE))),
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

    /// Returns the first path that stops startup, in report order: every untrusted or unchecked path, except a file that is
    /// missing before it is first needed. `config.toml` is missing until the first approval publishes it, and a lock
    /// file until the first start, whose lock creates it; their directories are checked all the same.
    pub fn refusal(&self) -> Option<(&TrustedPathEntry, &PathFailure)> {
        self.entries.iter().find_map(|entry| match &entry.outcome {
            Err(failure) if !entry.missing_file(failure) => Some((entry, failure)),
            _ => None,
        })
    }
}

impl TrustedPathEntry {
    /// Returns `true` if and only if `failure` is only that this entry's file, a config or lock file, does not exist.
    fn missing_file(&self, failure: &PathFailure) -> bool {
        let missing = matches!(
            failure,
            PathFailure::Uncollected(CollectError::Io { path, kind: io::ErrorKind::NotFound }) if *path == self.path
        );
        missing && matches!(self.rule, TrustedPathRule::Config | TrustedPathRule::StateFile)
    }
}

/// Collects `path`'s metadata and checks it against `rule`, returning its path cautions when it is trusted.
pub fn check_path(
    rule: TrustedPathRule,
    profile: DeploymentProfile,
    owner: ExpectedOwner,
    path: &Path,
) -> Result<Vec<PathCaution>, PathFailure> {
    let components = path_metadata::collect(path)?;
    Ok(trusted_path::check_with_cautions(rule, profile, owner, &components)?)
}

/// Logs each path caution of the report's trusted paths once, at WARN, with what it allows and how to fix it.
///
/// For startup only: every warning ends by saying the service is starting anyway, which is wrong anywhere else,
/// such as in `status` output.
pub fn log_cautions(report: &TrustedPathReport) {
    report
        .entries
        .iter()
        .filter_map(|entry| entry.outcome.as_ref().ok().map(|cautions| (entry, cautions)))
        .flat_map(|(entry, cautions)| cautions.iter().map(|caution| caution_warning(caution, &entry.path)))
        .for_each(|warning| tracing::warn!("{warning}"));
}

/// Composes the plain-language warning for a caution above `trusted`: the folder and its owner, the risk, the fix, and that
/// the service starts anyway. It names only paths and accounts, never anything from the vault.
fn caution_warning(caution: &PathCaution, trusted: &Path) -> String {
    let folder = caution.path.display();
    let trusted = trusted.display();
    let account = caution
        .owner_name
        .as_ref()
        .map_or_else(|| format!("uid {}", caution.uid), |name| format!("'{name}' (uid {})", caution.uid));
    let (file, effect, install) = match caution.file {
        CautionedFile::Binary => (
            "service binary",
            "run that program",
            "or install the binary to /usr/bin (package) or /usr/local/bin (manual install)",
        ),
    };
    format!(
        "{folder} is owned by {account}, not root, and is on the path to the {file} {trusted}. Anything running as {account} can \
         rename the {file} out of the way and put its own in its place; the next service start would {effect} with \
         the vault unlocked. To fix this, run `chown root:root {folder}` and `chmod go-w {folder}`, {install}. \
         The service is starting anyway."
    )
}

/// Checks the running binary and returns its entry: it must still be the file the process started from, and pass the binary rule.
fn binary_entry(profile: DeploymentProfile, owner: ExpectedOwner) -> TrustedPathEntry {
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
            file: CautionedFile::Binary,
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
            "is on the path to the service binary /opt/iron-vault/iron-vault",
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

    fn not_found(path: &str) -> Result<Vec<PathCaution>, PathFailure> {
        Err(PathFailure::Uncollected(CollectError::Io {
            path: PathBuf::from(path),
            kind: io::ErrorKind::NotFound,
        }))
    }

    fn wrong_mode(path: &str) -> Result<Vec<PathCaution>, PathFailure> {
        Err(PathFailure::Unsafe(UnsafePath {
            path: PathBuf::from(path),
            problem: crate::trusted_path::Problem::WrongMode {
                found: crate::trusted_path::Mode::new(0o755),
                expected: crate::trusted_path::Mode::new(0o700),
            },
        }))
    }

    /// A report of the config directory, config file and config lock file, every one trusted but the one at `path`.
    fn config_report(path: &str) -> TrustedPathReport {
        let entries = [
            (TrustedPathRule::ConfigDir, "/etc/iron-vault"),
            (TrustedPathRule::Config, "/etc/iron-vault/config.toml"),
            (TrustedPathRule::StateFile, "/etc/iron-vault/config.toml.lock"),
        ];
        TrustedPathReport {
            entries: entries
                .into_iter()
                .map(|(rule, at)| entry(rule, at, if at == path { wrong_mode(at) } else { Ok(vec![]) }))
                .collect(),
        }
    }

    #[test]
    fn an_unsafe_config_directory_refuses_startup() {
        let report = config_report("/etc/iron-vault");
        assert_eq!(report.refusal().map(|(entry, _)| entry.rule), Some(TrustedPathRule::ConfigDir));
    }

    #[test]
    fn an_unsafe_config_file_refuses_startup() {
        let report = config_report("/etc/iron-vault/config.toml");
        assert_eq!(report.refusal().map(|(entry, _)| entry.rule), Some(TrustedPathRule::Config));
    }

    #[test]
    fn an_unsafe_config_lock_file_refuses_startup() {
        let report = config_report("/etc/iron-vault/config.toml.lock");
        let refused = report.refusal().map(|(entry, _)| entry.path.clone());
        assert_eq!(refused, Some(PathBuf::from("/etc/iron-vault/config.toml.lock")));
    }

    #[test]
    fn a_missing_config_or_lock_file_does_not_refuse_startup_but_a_missing_directory_does() {
        let missing_files = TrustedPathReport {
            entries: vec![
                entry(
                    TrustedPathRule::Config,
                    "/etc/iron-vault/config.toml",
                    not_found("/etc/iron-vault/config.toml"),
                ),
                entry(
                    TrustedPathRule::StateFile,
                    "/var/lib/iron-vault/lock",
                    not_found("/var/lib/iron-vault/lock"),
                ),
            ],
        };
        assert_eq!(missing_files.refusal(), None);
        let missing_dir = TrustedPathReport {
            entries: vec![
                entry(TrustedPathRule::ConfigDir, "/etc/iron-vault", not_found("/etc/iron-vault")),
                // The file's chain stops at its missing directory, which is not the file itself.
                entry(TrustedPathRule::Config, "/etc/iron-vault/config.toml", not_found("/etc/iron-vault")),
            ],
        };
        assert_eq!(missing_dir.refusal().map(|(entry, _)| entry.rule), Some(TrustedPathRule::ConfigDir));
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
