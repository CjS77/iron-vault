//! Binding the service's Unix socket files ([spec §7][s7], [Admin socket][admin]): a socket owned by the service account
//! at one fixed mode, never connectable at any other.
//!
//! A socket is bound, set to its mode and checked before it listens. A Unix socket that is bound but not listening
//! refuses every connection, so the mode the kernel created it with is never reachable. The umask is left alone: it is
//! process-wide and would race with other threads.
//!
//! [s7]: ../../../design/iron-vault-specification.md#7-caller-authentication-and-listeners
//! [admin]: ../../../design/admin-protocol.md#admin-socket

use std::fmt;
use std::fs::{self, Metadata};
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType};

use crate::library_error::LibraryError;
use crate::trusted_path::ExpectedOwner;

/// Pending connections the kernel queues; a server refuses any beyond its connection cap as soon as it accepts them.
const BACKLOG: i32 = 16;

/// Which of the service's sockets a socket file is, so messages name the one that failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketRole {
    /// The admin socket, `0600`.
    Admin,
    /// A request socket, `0666`.
    Request,
}

impl fmt::Display for SocketRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Admin => write!(f, "admin socket"),
            Self::Request => write!(f, "request socket"),
        }
    }
}

/// How one socket file is bound: its path, the account that must own it and the only mode it may have.
#[derive(Debug, Clone, Copy)]
pub struct SocketSpec<'a> {
    /// Which socket this is, for messages.
    pub role: SocketRole,
    /// Where the socket is bound.
    pub path: &'a Path,
    /// The service account.
    pub owner: ExpectedOwner,
    /// The permission bits the socket has before it listens.
    pub mode: u32,
}

/// Why a socket file could not be bound.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BindError {
    /// Something other than a stale socket of the service account stands at the path, so the service will not remove
    /// it.
    #[error(
        "{path} is in the way of the {role}: it is {found}, not a socket owned by uid {owner}; find out what put it \
         there and remove it, then start the service again"
    )]
    Occupied {
        /// Which socket was being bound.
        role: SocketRole,
        /// The socket's path.
        path: PathBuf,
        /// What stands there.
        found: String,
        /// The service account's uid.
        owner: u32,
    },
    /// The freshly bound socket is not what the service made, so it never listens.
    #[error("the {role} {path} is {found} after binding, not a socket owned by uid {owner} with mode {mode:04o}")]
    Unverified {
        /// Which socket was being bound.
        role: SocketRole,
        /// The socket's path.
        path: PathBuf,
        /// What stands there.
        found: String,
        /// The service account's uid.
        owner: u32,
        /// The mode the socket should have.
        mode: u32,
    },
    /// A step of binding failed.
    #[error("cannot {step} the {role} {path}: {kind}")]
    Io {
        /// Which socket was being bound.
        role: SocketRole,
        /// The socket's path.
        path: PathBuf,
        /// What the service was doing.
        step: &'static str,
        /// The underlying error kind.
        kind: io::ErrorKind,
    },
}

/// The socket file this process bound, removed on drop or by [`SocketFile::remove`].
///
/// The file is removed only while the path still names the same device and inode as when it was bound, so a file
/// someone else has since put at the path is never deleted.
#[derive(Debug)]
pub struct SocketFile {
    role: SocketRole,
    path: PathBuf,
    dev: u64,
    ino: u64,
    removed: bool,
}

/// Binds `spec`'s socket and listens on it, replacing a stale socket the service account owns. The listener is
/// non-blocking, ready for an async server.
pub fn bind(spec: SocketSpec<'_>) -> Result<(UnixListener, SocketFile), BindError> {
    remove_stale(spec)?;
    let fd = bound_socket(spec)?;
    fs::set_permissions(spec.path, fs::Permissions::from_mode(spec.mode)).map_err(failed(spec, "set the mode of"))?;
    let bound = verify(spec)?;
    rustix::net::listen(&fd, BACKLOG)
        .map_err(io::Error::from)
        .map_err(failed(spec, "listen on"))?;
    // Only now does the file become ours to remove: a socket that failed verification or `listen` stays at the path,
    // never connectable, and the next start replaces it as stale.
    let file = SocketFile {
        role: spec.role,
        path: spec.path.to_path_buf(),
        dev: bound.dev(),
        ino: bound.ino(),
        removed: false,
    };
    Ok((UnixListener::from(fd), file))
}

impl SocketFile {
    /// The socket file's path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Removes the socket file now, reporting a failure that dropping would only log.
    pub fn remove(mut self) -> io::Result<()> {
        self.removed = true;
        self.remove_if_ours()
    }

    /// Removes the path when it still names the socket this process bound; a missing file is already gone.
    fn remove_if_ours(&self) -> io::Result<()> {
        match fs::symlink_metadata(&self.path) {
            Ok(now) if (now.dev(), now.ino()) == (self.dev, self.ino) => match fs::remove_file(&self.path) {
                Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
                _ => Ok(()),
            },
            Ok(_) => {
                tracing::warn!(
                    "leaving {}: it is no longer the {} this service bound",
                    self.path.display(),
                    self.role
                );
                Ok(())
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}

impl Drop for SocketFile {
    fn drop(&mut self) {
        if self.removed {
            return;
        }
        if let Err(e) = self.remove_if_ours() {
            tracing::warn!(error_kind = %e.kind_label(), "cannot remove the {} {}", self.role, self.path.display());
        }
    }
}

/// Creates a non-blocking Unix stream socket bound to the spec's path, not yet listening.
fn bound_socket(spec: SocketSpec<'_>) -> Result<OwnedFd, BindError> {
    let flags = SocketFlags::CLOEXEC | SocketFlags::NONBLOCK;
    let fd = rustix::net::socket_with(AddressFamily::UNIX, SocketType::STREAM, flags, None)
        .map_err(io::Error::from)
        .map_err(failed(spec, "create"))?;
    let address = SocketAddrUnix::new(spec.path)
        .map_err(io::Error::from)
        .map_err(failed(spec, "name"))?;
    rustix::net::bind(&fd, &address)
        .map_err(io::Error::from)
        .map_err(failed(spec, "bind"))?;
    Ok(fd)
}

/// Removes a socket the service account left behind at the spec's path; refuses anything else that stands there.
fn remove_stale(spec: SocketSpec<'_>) -> Result<(), BindError> {
    let metadata = match fs::symlink_metadata(spec.path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        other => other.map_err(failed(spec, "inspect"))?,
    };
    if !(metadata.file_type().is_socket() && metadata.uid() == spec.owner.uid) {
        return Err(BindError::Occupied {
            role: spec.role,
            path: spec.path.to_path_buf(),
            found: describe(&metadata),
            owner: spec.owner.uid,
        });
    }
    fs::remove_file(spec.path).map_err(failed(spec, "remove the stale"))
}

/// Checks with `lstat` that the spec's path is a socket the service account owns with the spec's mode, and returns
/// what `lstat` saw.
fn verify(spec: SocketSpec<'_>) -> Result<Metadata, BindError> {
    let metadata = fs::symlink_metadata(spec.path).map_err(failed(spec, "inspect"))?;
    let as_made = metadata.file_type().is_socket() && metadata.uid() == spec.owner.uid && metadata.mode() & 0o7777 == spec.mode;
    match as_made {
        true => Ok(metadata),
        false => Err(BindError::Unverified {
            role: spec.role,
            path: spec.path.to_path_buf(),
            found: describe(&metadata),
            owner: spec.owner.uid,
            mode: spec.mode,
        }),
    }
}

/// Describes what `metadata` shows, such as "a socket owned by uid 1000 with mode 0644", for error messages.
pub(crate) fn describe(metadata: &Metadata) -> String {
    let file_type = metadata.file_type();
    let kind = if file_type.is_socket() {
        "a socket"
    } else if file_type.is_symlink() {
        "a symlink"
    } else if file_type.is_file() {
        "a regular file"
    } else if file_type.is_dir() {
        "a directory"
    } else {
        "a special file"
    };
    format!("{kind} owned by uid {} with mode {:04o}", metadata.uid(), metadata.mode() & 0o7777)
}

/// Maps an I/O error at `step` to a [`BindError`] naming the socket and its path.
fn failed<'a>(spec: SocketSpec<'a>, step: &'static str) -> impl FnOnce(io::Error) -> BindError + 'a {
    move |error| BindError::Io {
        role: spec.role,
        path: spec.path.to_path_buf(),
        step,
        kind: error.kind(),
    }
}
