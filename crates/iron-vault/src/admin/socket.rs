//! Binding the admin socket (`design/admin-protocol.md`, "Admin socket"): `admin.sock` in the runtime directory, owned
//! by the service account with mode `0600`, and never connectable at a wider mode.
//!
//! The socket is bound, narrowed to `0600` and checked before it listens. A Unix socket that is bound but not listening
//! refuses every connection, so the mode the kernel created it with is never reachable. The umask is left alone: it is
//! process-wide and would race with other threads.

use std::fs::{self, Metadata};
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType};

use super::ADMIN_SOCKET_NAME;
use crate::trusted_path::ExpectedOwner;

/// The only mode the admin socket may have: the service account alone can connect.
const SOCKET_MODE: u32 = 0o600;

/// Pending connections the kernel queues; the server refuses any beyond its connection cap as soon as it accepts them.
const BACKLOG: i32 = 16;

/// Why the admin socket could not be bound.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BindError {
    /// Something other than a stale admin socket stands at the path, so the service will not remove it.
    #[error(
        "{path} is in the way of the admin socket: it is {found}, not a socket owned by uid {owner}; find out what put it \
         there and remove it, then start the service again"
    )]
    Occupied {
        /// The admin socket's path.
        path: PathBuf,
        /// What stands there.
        found: String,
        /// The service account's uid.
        owner: u32,
    },
    /// The freshly bound socket is not what the service made, so it never listens.
    #[error("the admin socket {path} is {found} after binding, not a socket owned by uid {owner} with mode 0600")]
    Unverified {
        /// The admin socket's path.
        path: PathBuf,
        /// What stands there.
        found: String,
        /// The service account's uid.
        owner: u32,
    },
    /// A step of binding failed.
    #[error("cannot {step} the admin socket {path}: {kind}")]
    Io {
        /// The admin socket's path.
        path: PathBuf,
        /// What the service was doing.
        step: &'static str,
        /// The underlying error kind.
        kind: io::ErrorKind,
    },
}

/// The admin socket, bound at mode `0600` and listening. The listener is non-blocking, ready for the async server.
///
/// It owns its socket file: dropping it removes the file, so no exit after binding leaves one behind.
#[derive(Debug)]
pub struct AdminSocket {
    listener: UnixListener,
    file: SocketFile,
}

/// The socket file this process bound, removed on drop or by [`SocketFile::remove`].
///
/// The file is removed only while the path still names the same device and inode as when it was bound, so a file
/// someone else has since put at the path is never deleted.
#[derive(Debug)]
pub struct SocketFile {
    path: PathBuf,
    dev: u64,
    ino: u64,
    removed: bool,
}

impl AdminSocket {
    /// Binds `admin.sock` in `runtime_dir` for the service account `owner`, replacing a stale socket that account owns.
    pub fn bind(runtime_dir: &Path, owner: ExpectedOwner) -> Result<Self, BindError> {
        let path = runtime_dir.join(ADMIN_SOCKET_NAME);
        remove_stale(&path, owner)?;
        let fd = bound_socket(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(SOCKET_MODE)).map_err(failed(&path, "set the mode of"))?;
        let bound = verify(&path, owner)?;
        rustix::net::listen(&fd, BACKLOG)
            .map_err(io::Error::from)
            .map_err(failed(&path, "listen on"))?;
        // Only now does the file become ours to remove: a socket that failed verification or `listen` stays at the path,
        // never connectable, and the next start replaces it as stale.
        Ok(Self {
            listener: UnixListener::from(fd),
            file: SocketFile {
                path,
                dev: bound.dev(),
                ino: bound.ino(),
                removed: false,
            },
        })
    }

    /// The socket file's path.
    pub fn path(&self) -> &Path {
        &self.file.path
    }

    /// The listener and the socket file, which the server holds until it stops.
    pub fn into_parts(self) -> (UnixListener, SocketFile) {
        (self.listener, self.file)
    }
}

impl SocketFile {
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
                    "leaving {}: it is no longer the admin socket this service bound",
                    self.path.display()
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
            tracing::warn!("cannot remove the admin socket {}: {e}", self.path.display());
        }
    }
}

/// A new non-blocking Unix stream socket bound to `path`, not yet listening.
fn bound_socket(path: &Path) -> Result<OwnedFd, BindError> {
    let flags = SocketFlags::CLOEXEC | SocketFlags::NONBLOCK;
    let fd = rustix::net::socket_with(AddressFamily::UNIX, SocketType::STREAM, flags, None)
        .map_err(io::Error::from)
        .map_err(failed(path, "create"))?;
    let address = SocketAddrUnix::new(path).map_err(io::Error::from).map_err(failed(path, "name"))?;
    rustix::net::bind(&fd, &address)
        .map_err(io::Error::from)
        .map_err(failed(path, "bind"))?;
    Ok(fd)
}

/// Removes a socket the service account left behind at `path`; refuses anything else that stands there.
fn remove_stale(path: &Path, owner: ExpectedOwner) -> Result<(), BindError> {
    let metadata = match fs::symlink_metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        other => other.map_err(failed(path, "inspect"))?,
    };
    if !(metadata.file_type().is_socket() && metadata.uid() == owner.uid) {
        return Err(BindError::Occupied {
            path: path.to_path_buf(),
            found: describe(&metadata),
            owner: owner.uid,
        });
    }
    fs::remove_file(path).map_err(failed(path, "remove the stale"))
}

/// Checks with `lstat` that `path` is a socket the service account owns with mode `0600`, and returns what `lstat` saw.
fn verify(path: &Path, owner: ExpectedOwner) -> Result<Metadata, BindError> {
    let metadata = fs::symlink_metadata(path).map_err(failed(path, "inspect"))?;
    let as_made = metadata.file_type().is_socket() && metadata.uid() == owner.uid && metadata.mode() & 0o7777 == SOCKET_MODE;
    match as_made {
        true => Ok(metadata),
        false => Err(BindError::Unverified {
            path: path.to_path_buf(),
            found: describe(&metadata),
            owner: owner.uid,
        }),
    }
}

/// "a socket owned by uid 1000 with mode 0644", for error messages.
fn describe(metadata: &Metadata) -> String {
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

/// Maps an I/O error at `step` to a [`BindError`] naming the path.
fn failed<'a>(path: &'a Path, step: &'static str) -> impl FnOnce(io::Error) -> BindError + 'a {
    move |error| BindError::Io {
        path: path.to_path_buf(),
        step,
        kind: error.kind(),
    }
}
