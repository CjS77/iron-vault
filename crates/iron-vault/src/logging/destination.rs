//! Where the log goes, and installing the subscriber on it.
//!
//! The destination is fixed before the subscriber exists, so a destination that cannot be used stops `serve` with one line
//! on stderr, before any socket is bound or anything is unlocked. Only the bootstrap destination is resolved here: the
//! approved config's `[logging] destination` takes over when a config check activates it.

use std::ffi::OsStr;
use std::fmt;
use std::fs::DirBuilder;
use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

use tracing_subscriber::util::TryInitError;

use super::log_file::FileProblem;
use super::switch::{LogOpener, LogSwitch};
use super::writer::LogFailure;
use crate::deployment::{DeploymentProfile, ProfileEnv, ProfileError, bootstrap_log_dir};
use crate::path_metadata::CollectError;
use crate::trusted_path::Problem;
use crate::trusted_path_report::PathFailure;

/// The mode of a development log directory the service creates, like the development state and config directories.
const DEVELOPMENT_DIR_MODE: u32 = 0o700;

/// Where the service writes its log records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogDestination {
    /// `iron-vault.log` in this directory.
    Directory(PathBuf),
    /// Standard output, for a container runtime to collect.
    Stdout,
}

impl LogDestination {
    /// The destination in force from startup until a config check activates an approved config: stdout when `serve` was
    /// given `--log-to-stdout`, else the deployment's own directory. It never reads the unverified `config.toml`, which
    /// could otherwise move the audit log out of the service's control before any approval had been checked.
    pub fn bootstrap(profile: DeploymentProfile, env: &ProfileEnv, log_to_stdout: bool) -> Result<Self, ProfileError> {
        match log_to_stdout {
            true => Ok(Self::Stdout),
            false => bootstrap_log_dir(profile, env).map(Self::Directory),
        }
    }
}

impl fmt::Display for LogDestination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Directory(path) => write!(f, "{}", path.display()),
            Self::Stdout => write!(f, "stdout"),
        }
    }
}

/// Why a log destination cannot be used. Each variant holds an error kind, never an `io::Error`: its text can carry a path.
#[derive(Debug, thiserror::Error)]
pub enum LogOpenError {
    /// The account that must own the log directory could not be found.
    #[error(transparent)]
    Owner(#[from] ProfileError),
    /// The log directory is not trusted, or its metadata could not be read.
    #[error(transparent)]
    Untrusted(#[from] PathFailure),
    /// The log directory could not be created or opened.
    #[error("cannot open the log directory {}: {kind}", .path.display())]
    Directory {
        /// The directory.
        path: PathBuf,
        /// The underlying error kind.
        kind: io::ErrorKind,
    },
    /// The directory opened is not the one the walk checked.
    #[error("the log directory {} was replaced while it was being checked", .path.display())]
    DirectoryReplaced {
        /// The directory.
        path: PathBuf,
    },
    /// `iron-vault.log` could not be opened or created.
    #[error("cannot open the log file: {kind}")]
    File {
        /// The underlying error kind.
        kind: io::ErrorKind,
    },
    /// `iron-vault.log` exists but is not a file the service may append to.
    #[error("the log file is {0}")]
    UnsafeFile(#[from] FileProblem),
    /// Standard output could not be used.
    #[error("cannot use stdout: {kind}")]
    Stdout {
        /// The underlying error kind.
        kind: io::ErrorKind,
    },
    /// Standard output may be the systemd journal, which the owner chose not to write to and whose readers are not bound by
    /// the log directory's mode.
    #[error("stdout may be the systemd journal (JOURNAL_STREAM), which the audit log must not use; write to a log directory")]
    StdoutIsJournal,
    /// Another subscriber is already installed.
    #[error("a log subscriber is already installed: {0}")]
    AlreadyInstalled(#[from] TryInitError),
}

/// Opens `destination` and installs the subscriber on a [`LogSwitch`] holding it, tripping a new latch on the first failed
/// write. The switch is returned so a config check can move the log, and its latch so `serve` can stop on it.
///
/// A development build creates a missing log directory, like its state and config directories; a protected install's
/// belongs to the package (`LogsDirectory=`), so a missing one fails the check.
pub fn install(
    destination: &LogDestination,
    profile: DeploymentProfile,
    env: &ProfileEnv,
    journal_stream: Option<&OsStr>,
) -> Result<LogSwitch, LogOpenError> {
    let owner = env.service_owner(profile);
    if let LogDestination::Directory(path) = destination {
        // A missing service account stops a directory destination before anything is created; stdout needs none.
        owner.clone()?;
        create_development_dir(profile, path)?;
    }
    let opener = LogOpener::new(profile, owner, journal_stream.map(OsStr::to_os_string), LogFailure::default());
    let switch = LogSwitch::open(destination.clone(), opener)?;
    super::init(switch.clone(), profile)?;
    Ok(switch)
}

impl LogOpenError {
    /// The fixed phrase a config check's `detail` gives for this error. It never holds a path or an OS error's text, since
    /// the destination is recorded in a field of its own.
    pub fn phrase(&self) -> String {
        match self {
            Self::Owner(_) => "the service account cannot be found".to_owned(),
            Self::Untrusted(PathFailure::Unsafe(path)) => problem_phrase(&path.problem).to_owned(),
            Self::Untrusted(PathFailure::Uncollected(CollectError::Io { kind, .. })) | Self::Directory { kind, .. } => {
                directory_phrase(*kind).to_owned()
            }
            Self::Untrusted(PathFailure::Uncollected(_)) => directory_phrase(io::ErrorKind::Other).to_owned(),
            Self::DirectoryReplaced { .. } => "the log directory was replaced while it was being checked".to_owned(),
            Self::File { .. } => "the log file cannot be opened".to_owned(),
            Self::UnsafeFile(problem) => format!("the log file is {problem}"),
            Self::Stdout { .. } => "stdout cannot be used".to_owned(),
            Self::StdoutIsJournal => "stdout may be the systemd journal".to_owned(),
            Self::AlreadyInstalled(_) => "a log subscriber is already installed".to_owned(),
        }
    }
}

const fn directory_phrase(kind: io::ErrorKind) -> &'static str {
    match kind {
        io::ErrorKind::NotFound => "the log directory does not exist",
        _ => "the log directory cannot be opened",
    }
}

/// One phrase per trusted-path problem a log directory can have; the problem's own text can name a uid, gid or mode.
const fn problem_phrase(problem: &Problem) -> &'static str {
    match problem {
        Problem::WrongOwner { .. } => "the log directory, or a directory above it, has an owner the log directory rule refuses",
        Problem::WritableByGroup { .. } => "the log directory, or a directory above it, is writable by its group",
        Problem::WritableByOthers => "the log directory, or a directory above it, is writable by others",
        Problem::ModeTooOpen { .. } | Problem::WrongMode { .. } => "the log directory's mode is too open",
        Problem::NotADirectory => "the log destination is not a directory",
        Problem::UntrustedSymlink => "the log directory's path passes through a symlink root does not control",
        Problem::SymlinkLoop => "the log directory's path has a symlink loop",
        _ => "the log directory fails the log directory rule",
    }
}

/// Creates the development log directory and any missing parents at `0700`; an existing directory keeps its mode, so a
/// wrong one is refused by the trust check rather than repaired.
fn create_development_dir(profile: DeploymentProfile, path: &Path) -> Result<(), LogOpenError> {
    match profile {
        DeploymentProfile::Protected => Ok(()),
        DeploymentProfile::Development => DirBuilder::new()
            .recursive(true)
            .mode(DEVELOPMENT_DIR_MODE)
            .create(path)
            .map_err(|e| LogOpenError::Directory {
                path: path.to_path_buf(),
                kind: e.kind(),
            }),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn env() -> ProfileEnv {
        ProfileEnv {
            home: Some(PathBuf::from("/home/alice")),
            xdg_state_home: Some(PathBuf::from("/srv/state")),
            invoking_uid: 1000,
            service_account_uid: Some(997),
            ..ProfileEnv::default()
        }
    }

    #[test]
    fn the_flag_selects_stdout_in_every_profile() {
        [DeploymentProfile::Protected, DeploymentProfile::Development]
            .into_iter()
            .for_each(|profile| assert_eq!(LogDestination::bootstrap(profile, &env(), true), Ok(LogDestination::Stdout)));
    }

    #[test]
    fn the_protected_default_is_var_log() {
        assert_eq!(
            LogDestination::bootstrap(DeploymentProfile::Protected, &env(), false),
            Ok(LogDestination::Directory(PathBuf::from("/var/log/iron-vault")))
        );
    }

    #[cfg(feature = "dev-mode")]
    #[test]
    fn the_development_default_is_beside_the_state_directory() {
        assert_eq!(
            LogDestination::bootstrap(DeploymentProfile::Development, &env(), false),
            Ok(LogDestination::Directory(PathBuf::from("/srv/state/iron-vault-dev-log")))
        );
    }

    #[cfg(not(feature = "dev-mode"))]
    #[test]
    fn a_build_without_dev_mode_has_no_development_destination() {
        assert_eq!(
            LogDestination::bootstrap(DeploymentProfile::Development, &env(), false),
            Err(ProfileError::DevelopmentNotBuilt)
        );
    }

    #[test]
    fn a_destination_displays_as_its_path_or_stdout() {
        assert_eq!(LogDestination::Stdout.to_string(), "stdout");
        assert_eq!(
            LogDestination::Directory(PathBuf::from("/var/log/iron-vault")).to_string(),
            "/var/log/iron-vault"
        );
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("iv-dest-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn a_development_build_creates_a_missing_log_directory_and_parents_at_0700() {
        let root = scratch("create");
        let dir = root.join("state-home/iron-vault-dev-log");
        create_development_dir(DeploymentProfile::Development, &dir).expect("create");
        assert_eq!(fs::metadata(&dir).expect("stat").permissions().mode() & 0o777, 0o700);
        assert_eq!(
            fs::metadata(dir.parent().expect("parent")).expect("stat").permissions().mode() & 0o777,
            0o700
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn an_existing_development_directory_keeps_its_mode() {
        let dir = scratch("keep");
        fs::create_dir_all(&dir).expect("mkdir");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).expect("chmod");
        create_development_dir(DeploymentProfile::Development, &dir).expect("create");
        assert_eq!(fs::metadata(&dir).expect("stat").permissions().mode() & 0o777, 0o755);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_protected_install_never_creates_its_log_directory() {
        let dir = scratch("protected");
        create_development_dir(DeploymentProfile::Protected, &dir).expect("no-op");
        assert!(!dir.exists());
    }
}
