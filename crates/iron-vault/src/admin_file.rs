// SPDX-License-Identifier: MPL-2.0
//! Reading administrator-installed files: a TLS listener's certificate chain and key, and a route's pinned CA file.
//!
//! Whoever can write one of these files can impersonate Iron Vault to TLS callers or send a route's credential to an
//! interceptor ([spec §6][s6], [§7][s7], [§10][s10]), so each is read only through its trusted-path rule. The path is walked
//! and checked first; the leaf is then opened without following a symlink, and the open file must be the very file
//! the walk checked, with the same type, owner, group, mode, device and inode. A file swapped in between the two
//! steps is refused, not read.
//!
//! [s6]: ../../../design/iron-vault-specification.md#6-credential-records-and-configuration
//! [s7]: ../../../design/iron-vault-specification.md#7-caller-authentication-and-listeners
//! [s10]: ../../../design/iron-vault-specification.md#10-outbound-tls-and-environment

// Off Linux the walk reports itself unsupported, so the open and read below are never reached.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::io;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::deployment::DeploymentProfile;
use crate::path_metadata::{self, CollectError};
use crate::trusted_path::{self, ComponentKind, ExpectedOwner, FileId, Mode, PathComponent, Problem, TrustedPathRule, UnsafePath};

/// The largest administrator-installed file read, in bytes. Certificate chains and keys are a few kilobytes; the cap
/// keeps a planted huge file from exhausting memory.
pub const MAX_ADMIN_FILE_LEN: u64 = 1 << 20;

/// Which administrator-installed file is being read; each has its own trusted-path rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminFile {
    /// A TLS listener's certificate chain or a route's pinned CA file.
    Certificate,
    /// A TLS listener's private key.
    PrivateKey,
}

impl AdminFile {
    /// The trusted-path rule the file's path must pass.
    pub const fn rule(self) -> TrustedPathRule {
        match self {
            Self::Certificate => TrustedPathRule::AdminCertificate,
            Self::PrivateKey => TrustedPathRule::AdminPrivateKey,
        }
    }
}

/// Why an administrator-installed file was not read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AdminFileError {
    /// The path's metadata could not be collected, so it went unchecked.
    #[error(transparent)]
    Uncollected(#[from] CollectError),
    /// A component of the path broke its rule.
    #[error(transparent)]
    Unsafe(#[from] UnsafePath),
    /// The file opened is not the one the path walk checked, or it changed size while it was read.
    #[error("{path} changed while it was being checked and read; check who else can change it, then retry")]
    Changed {
        /// The file's path.
        path: PathBuf,
    },
    /// The file is larger than [`MAX_ADMIN_FILE_LEN`].
    #[error("{path} is larger than {max_len} bytes, too large to be a certificate or key")]
    TooLarge {
        /// The file's path.
        path: PathBuf,
        /// The cap, in bytes.
        max_len: u64,
    },
    /// Opening or reading the file failed.
    #[error("cannot read {path}: {kind}")]
    Io {
        /// The file's path.
        path: PathBuf,
        /// The underlying error kind.
        kind: io::ErrorKind,
    },
}

/// Checks `path` against `file`'s trusted-path rule and returns its bytes, at most [`MAX_ADMIN_FILE_LEN`] of them.
///
/// The bytes clear themselves on drop, since a key file is a secret.
pub fn read(file: AdminFile, profile: DeploymentProfile, owner: ExpectedOwner, path: &Path) -> Result<Zeroizing<Vec<u8>>, AdminFileError> {
    let components = path_metadata::collect(path)?;
    trusted_path::check(file.rule(), profile, owner, &components)?;
    let walked = components.last().ok_or_else(|| UnsafePath {
        path: path.to_path_buf(),
        problem: Problem::NoComponents,
    })?;
    read_walked(path, walked, MAX_ADMIN_FILE_LEN)
}

/// What `fstat` reports about an open file, in the terms the path walk used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Opened {
    regular: bool,
    uid: u32,
    gid: u32,
    mode: Mode,
    id: FileId,
    len: u64,
}

/// Returns `true` if and only if the open file is the regular file the walk checked, unchanged in owner, group and
/// mode.
fn matches_walk(walked: &PathComponent, opened: &Opened) -> bool {
    walked.kind == ComponentKind::RegularFile
        && opened.regular
        && opened.uid == walked.uid
        && opened.gid == walked.gid
        && opened.mode == walked.mode
        && opened.id == walked.id
}

/// Opens the leaf the walk checked as `walked` and reads it whole, refusing a different or oversized file.
#[cfg(target_os = "linux")]
fn read_walked(path: &Path, walked: &PathComponent, max_len: u64) -> Result<Zeroizing<Vec<u8>>, AdminFileError> {
    let file = linux::open(path)?;
    let opened = linux::opened(&file).map_err(io_error(path))?;
    if !matches_walk(walked, &opened) {
        return Err(changed(path));
    }
    let len = usize::try_from(opened.len)
        .ok()
        .filter(|_| opened.len <= max_len)
        .ok_or_else(|| AdminFileError::TooLarge {
            path: path.to_path_buf(),
            max_len,
        })?;
    linux::read_exactly(file, len, path)
}

/// Reports that this platform has no metadata adapter yet.
#[cfg(not(target_os = "linux"))]
fn read_walked(_path: &Path, _walked: &PathComponent, _max_len: u64) -> Result<Zeroizing<Vec<u8>>, AdminFileError> {
    Err(CollectError::Unsupported.into())
}

fn changed(path: &Path) -> AdminFileError {
    AdminFileError::Changed { path: path.to_path_buf() }
}

fn io_error(path: &Path) -> impl Fn(io::Error) -> AdminFileError + '_ {
    move |e| AdminFileError::Io {
        path: path.to_path_buf(),
        kind: e.kind(),
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs::File;
    use std::io::{self, Read};
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;

    use rustix::fs::OFlags;
    use rustix::io::Errno;
    use zeroize::Zeroizing;

    use super::{AdminFileError, Opened, changed, io_error};
    use crate::trusted_path::{FileId, Mode};

    /// Opens `path` read-only. `O_NOFOLLOW` refuses a symlink swapped in at the leaf, and `O_NONBLOCK` keeps a FIFO
    /// swapped in from blocking the open; either is then refused as a changed file.
    pub(super) fn open(path: &Path) -> Result<File, AdminFileError> {
        let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        match rustix::fs::open(path, flags, rustix::fs::Mode::empty()) {
            Ok(fd) => Ok(File::from(fd)),
            Err(Errno::LOOP) => Err(changed(path)),
            Err(errno) => Err(io_error(path)(io::Error::from(errno))),
        }
    }

    /// Returns the open file's `fstat`, which describes the file itself, not whatever now stands at its path.
    pub(super) fn opened(file: &File) -> io::Result<Opened> {
        let metadata = file.metadata()?;
        Ok(Opened {
            regular: metadata.is_file(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode: Mode::new(metadata.mode()),
            id: FileId {
                dev: metadata.dev(),
                ino: metadata.ino(),
            },
            len: metadata.len(),
        })
    }

    /// Reads exactly `len` bytes into a buffer sized for them before reading, so it never reallocates and leaves no
    /// uncleared copy behind. A file that is shorter or longer than `len` changed after its `fstat`.
    pub(super) fn read_exactly(mut file: File, len: usize, path: &Path) -> Result<Zeroizing<Vec<u8>>, AdminFileError> {
        let mut bytes = Zeroizing::new(vec![0; len]);
        file.read_exact(&mut bytes).map_err(|e| match e.kind() {
            io::ErrorKind::UnexpectedEof => changed(path),
            _ => io_error(path)(e),
        })?;
        match file.read(&mut [0; 1]).map_err(io_error(path))? {
            0 => Ok(bytes),
            _ => Err(changed(path)),
        }
    }
}

#[cfg(test)]
mod tests;
