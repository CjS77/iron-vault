//! The deployment profile: how this build is installed, and the install paths and service account that follow from it.
//!
//! A packaged binary must never be switchable into development mode, which gives no isolation from malware running as
//! the user (specification §3.1). So the profile is fixed at build time by the `dev-mode` feature, never chosen by
//! config or flag, and without that feature the development code paths are not compiled in.
//!
//! Resolution is pure: [`ServicePaths::for_profile`] takes what it needs from the process as a [`ProfileEnv`] value,
//! and only [`ProfileEnv::from_process`] and [`Accounts::read`] touch the system. Library crates take the resolved
//! paths as inputs and never see the profile.

use std::io;
#[cfg(feature = "dev-mode")]
use std::path::Path;
use std::path::PathBuf;

use crate::path_metadata::{self, CollectError};
use crate::trusted_path::ExpectedOwner;
use crate::trusted_path_report::ServicePaths;

/// The account a protected installation runs as, created by the package.
pub const SERVICE_ACCOUNT: &str = "iron-vault";

/// Where the local accounts are listed. Package-created system accounts are always here, so no NSS lookup is needed.
const PASSWD: &str = "/etc/passwd";

/// The protected config sits in its own service-owned directory so the service can write `config.toml.pending` and
/// `config.toml.sig` beside it, and the vault's files stay alone in the state directory.
const PROTECTED_CONFIG: &str = "/etc/iron-vault/config.toml";
const PROTECTED_STATE_DIR: &str = "/var/lib/iron-vault";
const PROTECTED_RUNTIME_DIR: &str = "/run/iron-vault";

/// The directory name under each XDG base directory; distinct from the protected names so a development build never
/// shares files with a protected installation.
#[cfg(feature = "dev-mode")]
const DEVELOPMENT_DIR: &str = "iron-vault-dev";

/// How this build is installed. It decides the install paths, the service account and the admin principals, and
/// nothing else: development mode never relaxes any request, TLS, scrubbing, encryption or approval check (§2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeploymentProfile {
    /// A supported protected installation: root owns the binary and the `iron-vault` account runs the service.
    Protected,
    /// A user-level installation with no isolation from that user's malware: the invoking user runs the service and
    /// may own the binary.
    Development,
}

impl DeploymentProfile {
    /// The profile this binary was built for: `Development` only with the `dev-mode` feature.
    pub const fn current() -> Self {
        #[cfg(feature = "dev-mode")]
        {
            Self::Development
        }
        #[cfg(not(feature = "dev-mode"))]
        {
            Self::Protected
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
    /// The local account list could not be read.
    #[error("cannot read {PASSWD}: {kind}")]
    AccountsUnreadable {
        /// The underlying error kind.
        kind: io::ErrorKind,
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

impl ServicePaths {
    /// Resolves the install paths and service account of `profile` from `env`.
    pub fn for_profile(profile: DeploymentProfile, env: &ProfileEnv) -> Result<Self, ProfileError> {
        match profile {
            DeploymentProfile::Protected => protected_paths(env),
            DeploymentProfile::Development => development_paths(env),
        }
    }
}

fn protected_paths(env: &ProfileEnv) -> Result<ServicePaths, ProfileError> {
    let uid = env
        .service_account_uid
        .ok_or(ProfileError::MissingServiceAccount { account: SERVICE_ACCOUNT })?;
    Ok(ServicePaths {
        profile: DeploymentProfile::Protected,
        owner: ExpectedOwner { uid },
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

/// The startup check of a development build run as `uid`, named `user`: root is refused, anyone else gets the warning
/// that development mode gives no isolation from that user's malware.
#[cfg(feature = "dev-mode")]
pub fn development_banner(uid: u32, user: &str) -> Result<String, ProfileError> {
    match uid {
        0 => Err(ProfileError::DevelopmentAsRoot),
        _ => Ok(format!("development mode: no isolation from malware running as {user}")),
    }
}

/// `iron-vault <version> (features: <list>)`, naming every enabled build feature so a release check can refuse a
/// build that has development mode.
pub fn version_line() -> String {
    let features = if BUILD_FEATURES.is_empty() {
        "none".to_string()
    } else {
        BUILD_FEATURES.join(", ")
    };
    format!("{} {} (features: {features})", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))
}

/// The enabled Cargo features of this build.
const BUILD_FEATURES: &[&str] = &[
    #[cfg(feature = "dev-mode")]
    "dev-mode",
];

#[cfg(test)]
mod tests;
