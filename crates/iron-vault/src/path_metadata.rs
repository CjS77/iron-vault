//! The platform adapter for trusted-path checks: reads the metadata of every component of a path, and identifies the
//! running binary and invoking user.
//!
//! The rules in [`crate::trusted_path`] judge only what this adapter shows them, so it never canonicalizes a path:
//! canonicalizing would resolve the symlinks the rules must see. Each component is read with `lstat`, and each
//! symlink's target is collected as a path of its own.

// Off Linux only the unsupported answers are built; the collector waits for the platform adapters.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::io;
use std::path::{Path, PathBuf};

use crate::trusted_path::{ExpectedOwner, PathComponent};

#[cfg(target_os = "linux")]
mod linux;

/// The most symlinks one collection follows, counted across the whole path and every target, using the kernel's limit.
/// The count can exceed the kernel's for the same path: a relative target under a symlinked parent is walked again from
/// `/`, so that parent is counted again for each relative link resolved beneath it. A symlink past the limit is
/// reported as a loop.
pub const MAX_SYMLINK_HOPS: usize = 40;

/// Why a path's metadata could not be collected. The path is then unchecked, so callers treat it as untrusted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CollectError {
    /// A relative path depends on the working directory, which the rules cannot check.
    #[error("{path} is not an absolute path; trusted paths must start at `/`")]
    NotAbsolute {
        /// The path given.
        path: PathBuf,
    },
    /// Reading a component's metadata or a symlink's target failed.
    #[error("cannot read the metadata of {path}: {kind}")]
    Io {
        /// The component being read.
        path: PathBuf,
        /// The underlying error kind.
        kind: io::ErrorKind,
    },
    /// The file at the running binary's path is no longer the one this process was started from: it was deleted, or
    /// something else now stands at its path.
    #[error("the running binary {path} was deleted or replaced after the service started; restart the service")]
    BinaryReplaced {
        /// The path the process was started from.
        path: PathBuf,
    },
    /// This platform has no adapter yet. Protected deployments must treat this as unsafe, development as a warning.
    #[error("trusted-path checks are not supported on this platform")]
    Unsupported,
}

/// Collects the components of the absolute path `path`, from `/` down to the leaf, without following symlinks except
/// to collect each one's target.
///
/// A symlink's target is resolved against the directory holding the link and collected as its own chain. Components
/// below an ancestor symlink are named under the link's path, with the metadata of the entry the link leads to.
/// A chain stops at a symlink reported as a loop, since nothing below it can be reached.
#[cfg(target_os = "linux")]
pub fn collect(path: &Path) -> Result<Vec<PathComponent>, CollectError> {
    linux::collect(path)
}

/// Reports that this platform has no metadata adapter yet.
#[cfg(not(target_os = "linux"))]
pub fn collect(_path: &Path) -> Result<Vec<PathComponent>, CollectError> {
    Err(CollectError::Unsupported)
}

/// Checks that the file at `path` is still the binary this process is running, so a deleted or replaced binary is
/// reported rather than checked in its replacement's place.
#[cfg(target_os = "linux")]
pub fn ensure_running_binary(path: &Path) -> Result<(), CollectError> {
    linux::ensure_running_binary(path)
}

/// Reports that this platform cannot identify the running binary yet.
#[cfg(not(target_os = "linux"))]
pub fn ensure_running_binary(_path: &Path) -> Result<(), CollectError> {
    Err(CollectError::Unsupported)
}

/// The invoking user, who is the expected owner in a development deployment.
#[cfg(target_os = "linux")]
pub fn invoking_user() -> Result<ExpectedOwner, CollectError> {
    Ok(ExpectedOwner {
        uid: rustix::process::getuid().as_raw(),
    })
}

/// Reports that this platform cannot name the invoking user yet.
#[cfg(not(target_os = "linux"))]
pub fn invoking_user() -> Result<ExpectedOwner, CollectError> {
    Err(CollectError::Unsupported)
}
