//! Socket activation (spec §3.4): request listeners that systemd binds and passes to the service by name.
//!
//! A service that binds its own TCP port leaves a gap at every restart in which another local process can bind the
//! port, collect caller tokens and forge responses (R-6). Under socket activation systemd holds the port from boot and
//! across restarts, so in a protected Linux install every TCP listener must arrive that way. A Unix request socket is
//! protected by its service-owned directory instead, so it may be activated or bound by the service.
//!
//! systemd describes the sockets it passes in three variables: `LISTEN_PID` (the process they are for), `LISTEN_FDS`
//! (how many, from fd 3 up) and `LISTEN_FDNAMES` (each socket's `FileDescriptorName=`, `:`-separated). The service
//! reads them once at startup into an [`ActivationEnv`], and [`inheritance`] decides from that value alone which
//! listener each fd belongs to, so the protocol rules are tested without systemd. [`PassedSockets::take`] asks it and
//! takes the fds; each is checked against its listener's configured endpoint only when that listener adopts it.
//!
//! The service never removes the variables itself: removing one needs `remove_var`, which is unsafe in edition 2024.
//! `listenfd`, which takes ownership of the fds, removes `LISTEN_PID` and `LISTEN_FDS` as it does so, so adoption must
//! run before the service starts any thread, its async runtime included. `LISTEN_FDNAMES` stays set; the service starts no child process, so
//! nothing inherits it.
//!
//! An end-to-end run under `systemd-socket-activate` is EP-34's release test.

use std::collections::BTreeMap;
use std::os::fd::RawFd;

use iron_vault_policy::{Endpoint, ListenerName};

use crate::deployment::DeploymentProfile;

mod adopt;
pub use adopt::{AdoptError, AdoptedSocket, PassedSockets, verify};

/// The first fd systemd passes; the rest follow in order.
pub const FIRST_FD: RawFd = 3;

/// The socket-activation variables as this process received them.
///
/// A value that is not valid UTF-8 is held with its invalid bytes replaced, so it fails parsing like any other
/// malformed value.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ActivationEnv {
    /// `$LISTEN_PID`: the process the sockets are for.
    pub listen_pid: Option<String>,
    /// `$LISTEN_FDS`: how many sockets were passed.
    pub listen_fds: Option<String>,
    /// `$LISTEN_FDNAMES`: each socket's name, `:`-separated.
    pub listen_fdnames: Option<String>,
    /// `$LISTEN_FDS_FIRST_FD`: not part of systemd's protocol, but `listenfd` would start counting from it.
    pub listen_fds_first_fd: Option<String>,
}

impl ActivationEnv {
    /// Reads the variables from this process's environment.
    pub fn from_process() -> Self {
        let var = |name: &str| std::env::var_os(name).map(|value| value.to_string_lossy().into_owned());
        Self {
            listen_pid: var("LISTEN_PID"),
            listen_fds: var("LISTEN_FDS"),
            listen_fdnames: var("LISTEN_FDNAMES"),
            listen_fds_first_fd: var("LISTEN_FDS_FIRST_FD"),
        }
    }
}

/// Which sockets this process inherited.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Inheritance {
    /// `LISTEN_PID` is not set: nothing was passed.
    Nothing,
    /// `LISTEN_PID` names another process, or no process at all, so the variables were meant for someone else.
    OtherProcess {
        /// The value of `LISTEN_PID`, escaped.
        listen_pid: String,
    },
    /// The listener each passed fd belongs to: the first is fd 3, the next fd 4, and so on.
    Listeners(Vec<ListenerName>),
}

/// Why the activation variables cannot be trusted to say which listener each socket belongs to.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ActivationError {
    /// `LISTEN_FDS_FIRST_FD` is set, so `listenfd` would take sockets from somewhere other than fd 3.
    #[error("LISTEN_FDS_FIRST_FD is set; systemd always passes sockets from fd 3, so unset it")]
    FirstFdSet,
    /// `LISTEN_PID` names this process but `LISTEN_FDS` is not set.
    #[error("LISTEN_PID names this process but LISTEN_FDS is not set")]
    MissingCount,
    /// `LISTEN_FDS` is not a positive whole number.
    #[error("LISTEN_FDS is {value}, not a positive number of sockets")]
    BadCount {
        /// The value, quoted and escaped.
        value: String,
    },
    /// `LISTEN_FDNAMES` names a different number of sockets from `LISTEN_FDS`.
    #[error("LISTEN_FDS says {count} sockets were passed but LISTEN_FDNAMES names {names}")]
    CountMismatch {
        /// The number in `LISTEN_FDS`.
        count: usize,
        /// The number of names in `LISTEN_FDNAMES`.
        names: usize,
    },
    /// A socket has no name, so no listener can claim it.
    #[error("the socket passed as fd {fd} has no name; set FileDescriptorName= in its .socket unit to its listener's name")]
    Unnamed {
        /// The socket's fd.
        fd: RawFd,
    },
    /// A socket's name cannot be a listener's, so no listener can claim it.
    #[error(
        "the socket passed as fd {fd} is named {name}, which cannot be a listener name; make its .socket unit's \
         FileDescriptorName= match a listener"
    )]
    UnknownName {
        /// The socket's fd.
        fd: RawFd,
        /// Its name, quoted and escaped.
        name: String,
    },
    /// Two sockets have one name, and a listener takes exactly one socket.
    #[error("the sockets passed as fds {first} and {second} are both named {name}; each listener takes one socket")]
    DuplicateName {
        /// The shared name.
        name: ListenerName,
        /// The first fd with it.
        first: RawFd,
        /// The second fd with it.
        second: RawFd,
    },
}

/// Why a listener may not be bound by the service itself.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "refusing to bind TCP listener {listener} in a protected install: systemd must hold its port across restarts; add \
     a .socket unit for listener {listener}"
)]
pub struct NotActivated {
    /// The listener.
    pub listener: ListenerName,
}

/// Decides which listener each fd in `env` belongs to, for the process `pid`.
///
/// Variables for another process are ignored. Variables for this one must name every socket, each with a different
/// listener name; anything else is refused, `serve` logs it at WARN and takes nothing. Whether the config names each
/// listener is not asked here: the config at startup is unverified, so a socket it does not name is still taken and held
/// for the verified config to claim.
pub fn inheritance(env: &ActivationEnv, pid: u32) -> Result<Inheritance, ActivationError> {
    let Some(listen_pid) = env.listen_pid.as_deref() else {
        return Ok(Inheritance::Nothing);
    };
    if listen_pid.parse::<u32>().ok() != Some(pid) {
        return Ok(Inheritance::OtherProcess {
            listen_pid: quoted(listen_pid),
        });
    }
    if env.listen_fds_first_fd.is_some() {
        return Err(ActivationError::FirstFdSet);
    }
    let count = fd_count(env.listen_fds.as_deref())?;
    let names = fd_names(env.listen_fdnames.as_deref(), count)?;
    let listeners = names
        .iter()
        .zip(FIRST_FD..)
        .map(|(name, fd)| claim(name, fd))
        .collect::<Result<Vec<_>, _>>()?;
    check_unique(&listeners)?;
    Ok(Inheritance::Listeners(listeners))
}

/// Refuses a TCP listener the service would bind itself in a protected install; development builds and Unix sockets
/// may bind.
pub fn check_origin(profile: DeploymentProfile, listener: &ListenerName, endpoint: &Endpoint, adopted: bool) -> Result<(), NotActivated> {
    match (profile, endpoint, adopted) {
        (DeploymentProfile::Protected, Endpoint::Tcp { .. }, false) => Err(NotActivated {
            listener: listener.clone(),
        }),
        _ => Ok(()),
    }
}

/// `LISTEN_FDS` as a positive count. systemd sets the variables only when it passes at least one socket.
fn fd_count(value: Option<&str>) -> Result<usize, ActivationError> {
    let value = value.ok_or(ActivationError::MissingCount)?;
    value
        .parse::<usize>()
        .ok()
        .filter(|&count| count > 0)
        .ok_or_else(|| ActivationError::BadCount { value: quoted(value) })
}

/// `LISTEN_FDNAMES` split into one name per socket; when it is unset, the first socket has no name.
fn fd_names(value: Option<&str>, count: usize) -> Result<Vec<&str>, ActivationError> {
    let names: Vec<&str> = value.ok_or(ActivationError::Unnamed { fd: FIRST_FD })?.split(':').collect();
    match names.len() == count {
        true => Ok(names),
        false => Err(ActivationError::CountMismatch { count, names: names.len() }),
    }
}

/// The listener name `name`, passed as `fd`.
fn claim(name: &str, fd: RawFd) -> Result<ListenerName, ActivationError> {
    if name.is_empty() {
        return Err(ActivationError::Unnamed { fd });
    }
    ListenerName::try_from(name).map_err(|_| ActivationError::UnknownName { fd, name: quoted(name) })
}

/// Refuses the first name that two fds share.
fn check_unique(listeners: &[ListenerName]) -> Result<(), ActivationError> {
    listeners
        .iter()
        .zip(FIRST_FD..)
        .try_fold(BTreeMap::new(), |mut seen, (name, fd)| match seen.insert(name, fd) {
            Some(first) => Err(ActivationError::DuplicateName {
                name: name.clone(),
                first,
                second: fd,
            }),
            None => Ok(seen),
        })
        .map(|_| ())
}

/// `s` in double quotes with control and non-ASCII characters escaped, since the environment may hold anything.
fn quoted(s: &str) -> String {
    format!("\"{}\"", s.escape_default())
}

#[cfg(test)]
mod tests;
