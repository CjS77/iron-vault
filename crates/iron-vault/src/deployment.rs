// SPDX-License-Identifier: MPL-2.0
//! Decides where the service keeps its files and which account runs it, from the deployment profile this binary was
//! built for. `main` resolves the profile once at startup; everything else in the service takes the resulting
//! [`ServicePaths`], and library crates never see the profile at all.
//!
//! A packaged binary must never be switchable into development mode, which gives no isolation from malware running as
//! the user ([spec §4](../../../design/iron-vault-specification.md#4-installation-and-ownership)). So a Cargo feature fixes
//! the profile at build time; no config, flag or detection chooses it. Without `dev-mode` the development code paths are
//! not compiled in, and `dev-mode` and `container` cannot be combined.
//!
//! ```text
//! profile       build feature   config file                                    state directory                  service runs as
//! ───────────   ─────────────   ────────────────────────────────────────────   ──────────────────────────────   ───────────────
//! Protected     (none)          /etc/iron-vault/config.toml                    /var/lib/iron-vault              `iron-vault`
//! Container     container       /etc/iron-vault/config.toml                    /var/lib/iron-vault              `iron-vault`
//! Development   dev-mode        $XDG_CONFIG_HOME/iron-vault-dev/config.toml    $XDG_STATE_HOME/iron-vault-dev   the invoking user
//! ```
//!
//! Resolution is pure: [`ServicePaths::for_profile`] takes what it needs from the process as a [`ProfileEnv`] value.
//! Only [`ProfileEnv::from_process`], [`Accounts::read`] and [`PasswdDirectory::new`] touch the system.

use std::io;
use std::path::{Path, PathBuf};

use iron_vault_policy::{AccountDirectory, AccountName};

use crate::path_metadata::{self, CollectError};
use crate::trusted_path::ExpectedOwner;
use crate::trusted_path_report::ServicePaths;

#[cfg(all(feature = "dev-mode", feature = "container"))]
compile_error!("the `dev-mode` and `container` features select different deployment profiles and cannot be combined");

/// The account a protected installation runs as, created by the package.
pub const SERVICE_ACCOUNT: &str = "iron-vault";

/// Where the local accounts are listed. Package-created system accounts are always here, so no NSS lookup is needed.
const PASSWD: &str = "/etc/passwd";

/// Where Linux publishes the uid it reports for a peer whose uid has no mapping in this process's user namespace.
pub const OVERFLOW_UID_FILE: &str = "/proc/sys/kernel/overflowuid";

/// The kernel's overflow uid when [`OVERFLOW_UID_FILE`] does not exist: Linux's built-in default, `nobody`.
pub const DEFAULT_OVERFLOW_UID: u32 = 65534;

/// The config file of a service-account install. It sits in a service-owned directory of its own, so the service can
/// write `config.toml.pending` and `config.toml.sig` beside it and the state directory holds only the vault's files.
const PROTECTED_CONFIG: &str = "/etc/iron-vault/config.toml";
const PROTECTED_STATE_DIR: &str = "/var/lib/iron-vault";
const PROTECTED_RUNTIME_DIR: &str = "/run/iron-vault";
/// The bootstrap log directory of a protected install; the package's unit has systemd create it (`LogsDirectory=`).
const PROTECTED_LOG_DIR: &str = "/var/log/iron-vault";

/// The directory name under each XDG base directory. It differs from the protected names, so a development build never
/// shares files with a protected installation.
#[cfg(feature = "dev-mode")]
const DEVELOPMENT_DIR: &str = "iron-vault-dev";

/// The development log directory's name under `$XDG_STATE_HOME`. It sits beside the state directory, not inside it:
/// any other file in the state directory is a foreign file that makes `unlock` refuse.
#[cfg(feature = "dev-mode")]
const DEVELOPMENT_LOG_DIR: &str = "iron-vault-dev-log";

/// How this build is installed (glossary: *Deployment profile*). It decides the install paths, the service account and
/// the admin principals. Development mode never relaxes any request, TLS, scrubbing, encryption or approval check
/// ([spec §4](../../../design/iron-vault-specification.md#4-installation-and-ownership)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeploymentProfile {
    /// A supported protected installation: root owns the binary and the `iron-vault` account runs the service.
    Protected,
    /// A user-level installation with no isolation from that user's malware: the invoking user runs the service and
    /// may own the binary.
    Development,
    /// A Docker Compose stack: `Protected`'s paths, service account, trusted-path rules and locked-memory rule, except
    /// that root is the only admin principal (a host `sudo` reaches the service through the bind-mounted admin socket)
    /// and the service binds its own TCP listeners, because Docker cannot pass a socket into a container.
    Container,
}

impl DeploymentProfile {
    /// The profile this binary was built for: `Development` with the `dev-mode` feature, `Container` with the
    /// `container` feature, else `Protected`.
    pub const fn current() -> Self {
        #[cfg(feature = "dev-mode")]
        {
            Self::Development
        }
        #[cfg(all(feature = "container", not(feature = "dev-mode")))]
        {
            Self::Container
        }
        #[cfg(not(any(feature = "dev-mode", feature = "container")))]
        {
            Self::Protected
        }
    }

    /// Returns `true` if and only if the profile runs as the packaged `iron-vault` service account and keeps its files
    /// under that account: `Protected` and `Container`.
    pub const fn is_service_account_install(self) -> bool {
        matches!(self, Self::Protected | Self::Container)
    }

    /// Returns the profile's name in a log record's `deployment_profile` field: `protected`, `development` or `container`.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Protected => "protected",
            Self::Development => "development",
            Self::Container => "container",
        }
    }
}

/// Why the deployment profile could not be applied to this process.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProfileError {
    /// The protected service account does not exist.
    #[error("the service account `{account}` does not exist; the package creates it, and the service cannot start without it")]
    MissingServiceAccount {
        /// The account name looked up.
        account: &'static str,
    },
    /// A development directory has no absolute base to resolve from.
    #[error("`{variable}` is not set to an absolute path, so development mode cannot find its {purpose}")]
    MissingVariable {
        /// The environment variable that is needed.
        variable: &'static str,
        /// What it locates.
        purpose: &'static str,
    },
    /// The `Development` profile was asked of a build without the `dev-mode` feature.
    #[error("this build has no development mode")]
    DevelopmentNotBuilt,
    /// A development build was started as root.
    #[error("refusing to run as root: a development build must never be installed as the system service")]
    DevelopmentAsRoot,
    /// A protected or container build was started as an account other than the service account.
    #[error(
        "a protected or container install runs only as the `iron-vault` account; start it through `systemctl start iron-vault`, or run the container as that account's uid"
    )]
    NotServiceAccount {
        /// The uid this process runs as. Kept out of the message; the log and the caller may report it.
        uid: u32,
    },
    /// The local account list could not be read.
    #[error("cannot read {PASSWD}: {kind}")]
    AccountsUnreadable {
        /// The underlying error kind.
        kind: io::ErrorKind,
    },
    /// The kernel's overflow uid file exists but could not be read.
    #[error("cannot read {}: {kind}", .path.display())]
    OverflowUidUnreadable {
        /// The file.
        path: PathBuf,
        /// The underlying error kind.
        kind: io::ErrorKind,
    },
    /// The kernel's overflow uid file does not hold a uid. Its contents are not echoed, and no uid is guessed: a wrong
    /// guess would let `nobody` be a peer account.
    #[error("{} does not hold a uid", .path.display())]
    OverflowUidMalformed {
        /// The file.
        path: PathBuf,
    },
    /// The invoking user could not be identified.
    #[error(transparent)]
    InvokingUser(#[from] CollectError),
}

/// The local accounts, by name and uid, as `/etc/passwd` lists them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Accounts(Vec<(String, u32)>);

impl Accounts {
    /// Parses `passwd(5)` text, skipping comments and lines without a numeric uid.
    pub fn parse(passwd: &str) -> Self {
        Self(passwd.lines().filter_map(parse_passwd_line).collect())
    }

    /// Reads and parses `/etc/passwd`.
    pub fn read() -> Result<Self, ProfileError> {
        std::fs::read_to_string(PASSWD)
            .map(|text| Self::parse(&text))
            .map_err(|e| ProfileError::AccountsUnreadable { kind: e.kind() })
    }

    /// The uid of the first account named `name`.
    pub fn uid(&self, name: &str) -> Option<u32> {
        self.0.iter().find(|(account, _)| account == name).map(|&(_, uid)| uid)
    }

    /// The name of the first account with `uid`.
    pub fn name(&self, uid: u32) -> Option<&str> {
        self.0.iter().find(|&&(_, id)| id == uid).map(|(name, _)| name.as_str())
    }
}

/// The local accounts that activation resolves peer callers against, and the account the service runs as
/// ([spec §7](../../../design/iron-vault-specification.md#7-caller-authentication-and-listeners)).
///
/// Accounts come from `/etc/passwd`, the same list the service account is found in. Package-created and `useradd`
/// accounts are always there, so no NSS lookup is needed; an account that exists only in a directory service such as
/// LDAP or SSSD is not, so a peer caller naming one is refused as unknown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswdDirectory {
    accounts: Accounts,
    service_account_uid: u32,
    overflow_uid: u32,
}

impl PasswdDirectory {
    /// Resolves names against `accounts`, with the owner of `paths` as the service account and the overflow uid read
    /// once from `overflow_uid_file`, which is [`OVERFLOW_UID_FILE`] outside tests.
    ///
    /// The owner is the account the service runs as in every profile: the `iron-vault` account in a protected install,
    /// the invoking user in development. A missing overflow uid file, which happens only off Linux or without `/proc`,
    /// means [`DEFAULT_OVERFLOW_UID`].
    pub fn new(accounts: Accounts, paths: &ServicePaths, overflow_uid_file: &Path) -> Result<Self, ProfileError> {
        Ok(Self {
            accounts,
            service_account_uid: paths.owner.uid,
            overflow_uid: read_overflow_uid(overflow_uid_file)?,
        })
    }
}

/// The uid in `path`, or [`DEFAULT_OVERFLOW_UID`] when it does not exist.
fn read_overflow_uid(path: &Path) -> Result<u32, ProfileError> {
    match std::fs::read_to_string(path) {
        Ok(text) => text
            .trim()
            .parse()
            .map_err(|_| ProfileError::OverflowUidMalformed { path: path.to_path_buf() }),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(DEFAULT_OVERFLOW_UID),
        Err(e) => Err(ProfileError::OverflowUidUnreadable {
            path: path.to_path_buf(),
            kind: e.kind(),
        }),
    }
}

impl AccountDirectory for PasswdDirectory {
    fn uid(&self, name: &AccountName) -> Option<u32> {
        self.accounts.uid(name.as_str())
    }

    fn service_account_uid(&self) -> u32 {
        self.service_account_uid
    }

    fn overflow_uid(&self) -> u32 {
        self.overflow_uid
    }
}

/// One `name:password:uid:...` line as its name and uid.
fn parse_passwd_line(line: &str) -> Option<(String, u32)> {
    let mut fields = line.split(':');
    let name = fields.next().filter(|name| !name.is_empty() && !name.starts_with('#'))?;
    let uid = fields.nth(1)?.parse().ok()?;
    Some((name.to_string(), uid))
}

/// What install-path resolution needs from the process, passed in as a value so resolution stays pure.
///
/// A variable that is unset, empty or relative is held as `None`: the XDG base directory specification says to ignore
/// a relative value.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProfileEnv {
    /// `$HOME`.
    pub home: Option<PathBuf>,
    /// `$XDG_CONFIG_HOME`.
    pub xdg_config_home: Option<PathBuf>,
    /// `$XDG_STATE_HOME`.
    pub xdg_state_home: Option<PathBuf>,
    /// `$XDG_RUNTIME_DIR`.
    pub xdg_runtime_dir: Option<PathBuf>,
    /// The uid this process runs as.
    pub invoking_uid: u32,
    /// The uid of the protected service account, when it exists.
    pub service_account_uid: Option<u32>,
}

impl ProfileEnv {
    /// Reads the environment variables and invoking uid of this process, and looks up the service account in
    /// `accounts`.
    pub fn from_process(accounts: &Accounts) -> Result<Self, ProfileError> {
        let var = |name: &str| std::env::var_os(name).map(PathBuf::from).filter(|path| path.is_absolute());
        Ok(Self {
            home: var("HOME"),
            xdg_config_home: var("XDG_CONFIG_HOME"),
            xdg_state_home: var("XDG_STATE_HOME"),
            xdg_runtime_dir: var("XDG_RUNTIME_DIR"),
            invoking_uid: path_metadata::invoking_user()?.uid,
            service_account_uid: accounts.uid(SERVICE_ACCOUNT),
        })
    }
}

impl ProfileEnv {
    /// Returns the account that owns the service's files under `profile`: the `iron-vault` service account for
    /// `Protected` and `Container`, the invoking user for `Development`.
    pub fn service_owner(&self, profile: DeploymentProfile) -> Result<ExpectedOwner, ProfileError> {
        match profile {
            DeploymentProfile::Protected | DeploymentProfile::Container => self
                .service_account_uid
                .map(|uid| ExpectedOwner { uid })
                .ok_or(ProfileError::MissingServiceAccount { account: SERVICE_ACCOUNT }),
            DeploymentProfile::Development => Ok(ExpectedOwner { uid: self.invoking_uid }),
        }
    }
}

/// Refuses a `Protected` or `Container` service that is not running as the service account.
///
/// Root would pass the trusted-path checks, which look at file ownership and not at the process uid, and would then
/// write vault files the service account cannot use. `Development` always passes, because `development_banner` already
/// refuses root.
pub fn require_service_account(profile: DeploymentProfile, env: &ProfileEnv) -> Result<(), ProfileError> {
    match profile {
        DeploymentProfile::Protected | DeploymentProfile::Container if env.service_owner(profile)?.uid != env.invoking_uid => {
            Err(ProfileError::NotServiceAccount { uid: env.invoking_uid })
        }
        _ => Ok(()),
    }
}

/// Returns the bootstrap log directory: where the service writes its log until an approved config names another.
/// `/var/log/iron-vault` for a service-account install, `$XDG_STATE_HOME/iron-vault-dev-log` in development.
pub fn bootstrap_log_dir(profile: DeploymentProfile, env: &ProfileEnv) -> Result<PathBuf, ProfileError> {
    match profile {
        DeploymentProfile::Protected | DeploymentProfile::Container => Ok(PathBuf::from(PROTECTED_LOG_DIR)),
        DeploymentProfile::Development => development_log_dir(env),
    }
}

#[cfg(feature = "dev-mode")]
fn development_log_dir(env: &ProfileEnv) -> Result<PathBuf, ProfileError> {
    xdg_base(env.xdg_state_home.as_deref(), env.home.as_deref(), ".local/state", "log directory")
        .map(|state_home| state_home.join(DEVELOPMENT_LOG_DIR))
}

#[cfg(not(feature = "dev-mode"))]
fn development_log_dir(_env: &ProfileEnv) -> Result<PathBuf, ProfileError> {
    Err(ProfileError::DevelopmentNotBuilt)
}

impl ServicePaths {
    /// Resolves the install paths and service account of `profile` from `env`.
    pub fn for_profile(profile: DeploymentProfile, env: &ProfileEnv) -> Result<Self, ProfileError> {
        match profile {
            DeploymentProfile::Protected | DeploymentProfile::Container => protected_paths(profile, env),
            DeploymentProfile::Development => development_paths(env),
        }
    }
}

/// The paths of a service-account install, which `Protected` and `Container` share; `profile` is kept in the result.
fn protected_paths(profile: DeploymentProfile, env: &ProfileEnv) -> Result<ServicePaths, ProfileError> {
    Ok(ServicePaths {
        profile,
        owner: env.service_owner(profile)?,
        config: PathBuf::from(PROTECTED_CONFIG),
        state_dir: PathBuf::from(PROTECTED_STATE_DIR),
        runtime_dir: Some(PathBuf::from(PROTECTED_RUNTIME_DIR)),
    })
}

#[cfg(feature = "dev-mode")]
fn development_paths(env: &ProfileEnv) -> Result<ServicePaths, ProfileError> {
    let config_home = xdg_base(env.xdg_config_home.as_deref(), env.home.as_deref(), ".config", "config file")?;
    let state_home = xdg_base(
        env.xdg_state_home.as_deref(),
        env.home.as_deref(),
        ".local/state",
        "state directory",
    )?;
    // The XDG specification gives the runtime directory no default.
    let runtime_dir = env.xdg_runtime_dir.as_deref().ok_or(ProfileError::MissingVariable {
        variable: "XDG_RUNTIME_DIR",
        purpose: "runtime directory",
    })?;
    Ok(ServicePaths {
        profile: DeploymentProfile::Development,
        owner: ExpectedOwner { uid: env.invoking_uid },
        config: config_home.join(DEVELOPMENT_DIR).join("config.toml"),
        state_dir: state_home.join(DEVELOPMENT_DIR),
        runtime_dir: Some(runtime_dir.join(DEVELOPMENT_DIR)),
    })
}

#[cfg(not(feature = "dev-mode"))]
fn development_paths(_env: &ProfileEnv) -> Result<ServicePaths, ProfileError> {
    Err(ProfileError::DevelopmentNotBuilt)
}

/// An XDG base directory: the variable when set, else its default under `$HOME`.
#[cfg(feature = "dev-mode")]
fn xdg_base(variable: Option<&Path>, home: Option<&Path>, default: &str, purpose: &'static str) -> Result<PathBuf, ProfileError> {
    variable
        .map(Path::to_path_buf)
        .or_else(|| home.map(|home| home.join(default)))
        .ok_or(ProfileError::MissingVariable { variable: "HOME", purpose })
}

/// Checks a development build at startup, run as `uid` with account name `user`. Refuses root; for anyone else, returns
/// the banner warning that development mode gives no isolation from that user's malware.
#[cfg(feature = "dev-mode")]
pub fn development_banner(uid: u32, user: &str) -> Result<String, ProfileError> {
    match uid {
        0 => Err(ProfileError::DevelopmentAsRoot),
        _ => Ok(format!("development mode: {}", no_isolation_warning(user))),
    }
}

/// Returns the warning that a development build gives no isolation from `user`'s malware. The startup banner and
/// `status` both take their text from here, so the two cannot drift. It is not feature-gated, because the CLI shows it
/// for a development service even when the CLI itself was built without `dev-mode`.
pub fn no_isolation_warning(user: &str) -> String {
    format!("no isolation from malware running as {user}")
}

/// Returns `<version> (features: <list>)`, naming every enabled build feature, or `none`. A release check reads it to
/// refuse a build that has development mode or the test hooks. `--version` prints it after the binary's name, for
/// example `iron-vault 0.3.0-alpha (features: dev-mode)`.
pub fn version() -> String {
    let enabled: Vec<&str> = CARGO_FEATURES.iter().filter(|(_, on)| *on).map(|(name, _)| *name).collect();
    let features = if enabled.is_empty() {
        "none".to_string()
    } else {
        enabled.join(", ")
    };
    format!("{} (features: {features})", env!("CARGO_PKG_VERSION"))
}

/// Every Cargo feature of this crate, in `Cargo.toml` order, each paired with `true` if and only if this build enables
/// it. A test compares the names with `Cargo.toml`'s `[features]` table, so a new feature cannot be left out of
/// `--version`.
const CARGO_FEATURES: &[(&str, bool)] = &[
    ("dev-mode", cfg!(feature = "dev-mode")),
    ("container", cfg!(feature = "container")),
    ("test-support", cfg!(feature = "test-support")),
];

#[cfg(test)]
mod tests;
