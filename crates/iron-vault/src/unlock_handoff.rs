//! Reading the host unlock handoff: the file through which the host gives a container-profile service the host unlock
//! identity (`design/docker-compose.md`, specification §17).
//!
//! The file holds the recovery key's secret text, so it is read only through its own trusted-path rule: whoever could
//! plant or read it could unlock the vault. The path is walked first; the leaf is then opened without following a
//! symlink and its open descriptor is checked against the same rule, so a file swapped in after the walk is judged as
//! itself. No error carries the file's bytes.

// Off Linux the walk reports itself unsupported, so the open and read below are never reached.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::io;
use std::path::Path;

use iron_vault_store::RecipientIdentity;

use crate::deployment::DeploymentProfile;
use crate::path_metadata::{self, CollectError};
use crate::trusted_path::{self, ExpectedOwner, PathComponent, TrustedPathRule, UnsafePath};

/// Where the host's unlock handoff appears inside the container. The directory is mounted, not the file, so a file
/// that is missing or replaced on the host is seen as such.
pub const HANDOFF_PATH: &str = "/run/iron-vault-unlock/host-unlock";

/// The most bytes a handoff may hold: the 74-byte `AGE-SECRET-KEY-1…` text, a newline, and room to spare. A longer file
/// is the wrong file, such as `age-keygen` output with its comment lines.
pub const MAX_HANDOFF_LEN: usize = 128;

/// Why the handoff was not turned into an identity. No variant carries the file's bytes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HandoffError {
    /// The file or a directory above it broke the [`TrustedPathRule::UnlockHandoff`] rule, so it was not read.
    #[error("the unlock handoff is not trusted: {0}")]
    Untrusted(#[from] UnsafePath),
    /// The file is longer than [`MAX_HANDOFF_LEN`].
    #[error("the unlock handoff is longer than {MAX_HANDOFF_LEN} bytes")]
    TooLong,
    /// The file is not exactly one `age` secret key, optionally followed by one newline.
    #[error("the unlock handoff is not an age secret key")]
    NotAnIdentity,
    /// Walking, opening or reading the file failed.
    #[error("cannot read the unlock handoff: {0}")]
    Unreadable(io::ErrorKind),
}

/// Reads the identity at `path`, or `None` when nothing is there.
///
/// The text is parsed by [`RecipientIdentity::from_secret_text`], as the recovery key is, after at most one trailing
/// newline is removed. `RecoveryKeySecret::parse` does not fit: it trims all surrounding whitespace for a key typed at a
/// prompt, while a program writes the handoff, so anything more than one newline means the wrong file.
pub fn read_handoff(profile: DeploymentProfile, owner: ExpectedOwner, path: &Path) -> Result<Option<RecipientIdentity>, HandoffError> {
    let components = match path_metadata::collect(path) {
        Ok(components) => components,
        Err(CollectError::Io {
            kind: io::ErrorKind::NotFound,
            ..
        }) => return Ok(None),
        Err(e) => return Err(HandoffError::Unreadable(collect_kind(&e))),
    };
    trusted_path::check(TrustedPathRule::UnlockHandoff, profile, owner, &components)?;
    let ancestors = components.split_last().map_or(&[][..], |(_, ancestors)| ancestors);
    read_leaf(profile, owner, path, ancestors).map(Some)
}

fn collect_kind(error: &CollectError) -> io::ErrorKind {
    match error {
        CollectError::Io { kind, .. } => *kind,
        CollectError::NotAbsolute { .. } => io::ErrorKind::InvalidInput,
        CollectError::Unsupported => io::ErrorKind::Unsupported,
        CollectError::BinaryReplaced { .. } => io::ErrorKind::Other,
    }
}

/// The text of the identity in `bytes`: one secret key and at most one trailing newline.
fn parse(bytes: &[u8]) -> Result<RecipientIdentity, HandoffError> {
    let text = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    RecipientIdentity::from_secret_text(text).ok_or(HandoffError::NotAnIdentity)
}

/// Opens the leaf, checks the open file against the rule beneath the already-checked `ancestors`, and reads it.
#[cfg(target_os = "linux")]
fn read_leaf(
    profile: DeploymentProfile,
    owner: ExpectedOwner,
    path: &Path,
    ancestors: &[PathComponent],
) -> Result<RecipientIdentity, HandoffError> {
    let file = linux::open(path)?;
    let leaf = linux::opened(path, &file).map_err(|e| HandoffError::Unreadable(e.kind()))?;
    let chain: Vec<PathComponent> = ancestors.iter().cloned().chain([leaf]).collect();
    trusted_path::check(TrustedPathRule::UnlockHandoff, profile, owner, &chain)?;
    parse(&linux::read_capped(file)?)
}

/// Reports that this platform has no metadata adapter yet.
#[cfg(not(target_os = "linux"))]
fn read_leaf(
    _profile: DeploymentProfile,
    _owner: ExpectedOwner,
    _path: &Path,
    _ancestors: &[PathComponent],
) -> Result<RecipientIdentity, HandoffError> {
    Err(HandoffError::Unreadable(io::ErrorKind::Unsupported))
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

    use super::{HandoffError, MAX_HANDOFF_LEN};
    use crate::trusted_path::{ComponentKind, FileId, Mode, PathComponent, Problem, UnsafePath};

    /// One byte more than the cap, so a file over it is told from one exactly at it.
    const READ_LIMIT: u64 = MAX_HANDOFF_LEN as u64 + 1;

    /// Opens `path` read-only. `O_NOFOLLOW` refuses a symlink at the leaf, and `O_NONBLOCK` keeps a FIFO from blocking the
    /// open; the rule then refuses it as a non-regular file.
    pub(super) fn open(path: &Path) -> Result<File, HandoffError> {
        let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        match rustix::fs::open(path, flags, rustix::fs::Mode::empty()) {
            Ok(fd) => Ok(File::from(fd)),
            Err(Errno::LOOP) => Err(HandoffError::Untrusted(UnsafePath {
                path: path.to_path_buf(),
                problem: Problem::NotARegularFile,
            })),
            Err(errno) => Err(HandoffError::Unreadable(io::Error::from(errno).kind())),
        }
    }

    /// The open file as the path walk would describe it, from `fstat`, which describes the file itself whatever now
    /// stands at its path.
    pub(super) fn opened(path: &Path, file: &File) -> io::Result<PathComponent> {
        let metadata = file.metadata()?;
        Ok(PathComponent {
            path: path.to_path_buf(),
            uid: metadata.uid(),
            owner_name: None,
            gid: metadata.gid(),
            group_name: None,
            mode: Mode::new(metadata.mode()),
            kind: if metadata.is_file() {
                ComponentKind::RegularFile
            } else {
                ComponentKind::Other
            },
            id: FileId {
                dev: metadata.dev(),
                ino: metadata.ino(),
            },
        })
    }

    /// Reads at most one byte past the cap into a buffer sized for it before reading, so it never reallocates and leaves
    /// no uncleared copy behind.
    pub(super) fn read_capped(file: File) -> Result<Zeroizing<Vec<u8>>, HandoffError> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_HANDOFF_LEN + 1));
        file.take(READ_LIMIT)
            .read_to_end(&mut bytes)
            .map_err(|e| HandoffError::Unreadable(e.kind()))?;
        match bytes.len() > MAX_HANDOFF_LEN {
            true => Err(HandoffError::TooLong),
            false => Ok(bytes),
        }
    }
}

#[cfg(test)]
mod tests;
