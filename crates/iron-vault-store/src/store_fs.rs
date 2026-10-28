//! The filesystem seam under every store write: one method per durable-write step.

use std::ffi::OsString;
use std::fs::{File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;

/// The filesystem operations a durable write is built from, one method per step.
///
/// Each step is separate so a test double can observe or fail any one of them on its own. The trait is used
/// generically (`&impl StoreFs`); the open-file type is an associated type so a double can wrap [`OsFs`] or keep
/// files in memory.
pub trait StoreFs {
    /// An open, writable file returned by [`StoreFs::create_private`].
    type File;

    /// Creates `path` as a new file readable and writable only by the owner, failing if anything already exists
    /// there; exclusive creation means a planted symlink is never followed.
    fn create_private(&self, path: &Path) -> io::Result<Self::File>;

    /// Writes every byte of `bytes` to `file`.
    fn write_all(&self, file: &mut Self::File, bytes: &[u8]) -> io::Result<()>;

    /// Flushes `file`'s contents and metadata to stable storage.
    fn sync_file(&self, file: &Self::File) -> io::Result<()>;

    /// Atomically renames `from` to `to`, replacing any file at `to`.
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()>;

    /// Unlinks the file at `path`.
    fn remove_file(&self, path: &Path) -> io::Result<()>;

    /// Flushes the directory `dir`'s entries to stable storage, so renames and unlinks in it survive power loss.
    fn sync_dir(&self, dir: &Path) -> io::Result<()>;

    /// The names of the entries in `dir`, sorted so callers act on them in a deterministic order.
    fn list_dir(&self, dir: &Path) -> io::Result<Vec<OsString>>;

    /// Reads the regular file at `path`, failing with [`io::ErrorKind::FileTooLarge`] after at most `max_len + 1` bytes
    /// if it is longer than `max_len`.
    ///
    /// A symlink, directory, FIFO, socket or device at `path` fails with [`io::ErrorKind::InvalidInput`] before it is
    /// opened: opening a FIFO blocks until a writer appears, and a device can be read without end.
    fn read_bounded(&self, path: &Path, max_len: u64) -> io::Result<Vec<u8>>;
}

/// The real filesystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct OsFs;

impl StoreFs for OsFs {
    type File = File;

    fn create_private(&self, path: &Path) -> io::Result<File> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        options.open(path)
    }

    fn write_all(&self, file: &mut File, bytes: &[u8]) -> io::Result<()> {
        file.write_all(bytes)
    }

    fn sync_file(&self, file: &File) -> io::Result<()> {
        file.sync_all()
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        std::fs::rename(from, to)
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        std::fs::remove_file(path)
    }

    #[cfg(unix)]
    fn sync_dir(&self, dir: &Path) -> io::Result<()> {
        File::open(dir)?.sync_all()
    }

    /// No directory fsync exists here yet. The durable functions check the platform before mutating anything, so
    /// they fail closed; a direct caller of this method has already renamed or unlinked by the time it fails.
    #[cfg(not(unix))]
    fn sync_dir(&self, _dir: &Path) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "directory fsync is not supported on this platform"))
    }

    fn list_dir(&self, dir: &Path) -> io::Result<Vec<OsString>> {
        let mut names = std::fs::read_dir(dir)?.map(|entry| entry.map(|e| e.file_name())).collect::<io::Result<Vec<_>>>()?;
        names.sort();
        Ok(names)
    }

    /// Checks the entry with `lstat` before opening it, so a FIFO is never opened and an oversized file is refused
    /// before any buffer is allocated. Only the service can write the state directory, so the entry cannot be swapped
    /// for a FIFO between the check and the open by anyone the service does not already trust; the open handle is
    /// still compared with the checked entry, so a swap is refused rather than read.
    fn read_bounded(&self, path: &Path, max_len: u64) -> io::Result<Vec<u8>> {
        let checked = regular_file_metadata(path)?;
        if checked.len() > max_len {
            return Err(too_large(max_len));
        }
        let file = File::open(path)?;
        ensure_same_entry(&checked, &file.metadata()?)?;
        read_at_most(file, max_len, checked.len())
    }
}

/// The metadata of the entry at `path`, without following a symlink, if it is a regular file.
fn regular_file_metadata(path: &Path) -> io::Result<Metadata> {
    let metadata = std::fs::symlink_metadata(path)?;
    match metadata.is_file() {
        true => Ok(metadata),
        false => Err(io::Error::new(io::ErrorKind::InvalidInput, "not a regular file")),
    }
}

/// Refuses an open file that is not the regular file checked before opening it.
fn ensure_same_entry(checked: &Metadata, opened: &Metadata) -> io::Result<()> {
    match opened.is_file() && same_inode(checked, opened) {
        true => Ok(()),
        false => Err(io::Error::new(io::ErrorKind::InvalidInput, "the file changed while it was opened")),
    }
}

#[cfg(unix)]
fn same_inode(checked: &Metadata, opened: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    checked.dev() == opened.dev() && checked.ino() == opened.ino()
}

/// No inode identity is exposed here; the regular-file check on the open handle is all that applies.
#[cfg(not(unix))]
fn same_inode(_checked: &Metadata, _opened: &Metadata) -> bool {
    true
}

fn too_large(max_len: u64) -> io::Error {
    io::Error::new(io::ErrorKind::FileTooLarge, format!("file is longer than {max_len} bytes"))
}

/// Reads `reader` to its end, stopping after `max_len + 1` bytes so an oversized file is never read whole.
///
/// The buffer is sized for `expected_len` bytes, capped at `max_len`, plus one byte to detect growth, so reading a
/// file whose length was checked never reallocates past the cap.
fn read_at_most(reader: impl Read, max_len: u64, expected_len: u64) -> io::Result<Vec<u8>> {
    let capacity = usize::try_from(expected_len.min(max_len).saturating_add(1)).map_err(|_| too_large(max_len))?;
    let mut bytes = Vec::with_capacity(capacity);
    reader.take(max_len.saturating_add(1)).read_to_end(&mut bytes)?;
    match u64::try_from(bytes.len()) {
        Ok(len) if len <= max_len => Ok(bytes),
        _ => Err(too_large(max_len)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_dir::TestDir;

    #[test]
    fn create_private_refuses_an_existing_file() {
        let dir = TestDir::new("fs-exists");
        let path = dir.path().join("f");
        std::fs::write(&path, b"old").unwrap();
        let err = OsFs.create_private(&path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&path).unwrap(), b"old");
    }

    #[cfg(unix)]
    #[test]
    fn create_private_does_not_follow_a_planted_symlink() {
        let dir = TestDir::new("fs-symlink");
        let target = dir.path().join("target");
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert_eq!(OsFs.create_private(&link).unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        assert!(!target.exists());
    }

    #[test]
    fn list_dir_is_sorted() {
        let dir = TestDir::new("fs-list");
        ["c", "a", "b"].iter().for_each(|n| std::fs::write(dir.path().join(n), b"").unwrap());
        assert_eq!(OsFs.list_dir(dir.path()).unwrap(), ["a", "b", "c"]);
    }

    #[test]
    fn read_bounded_allows_exactly_max_len() {
        let dir = TestDir::new("fs-read");
        let path = dir.path().join("f");
        std::fs::write(&path, b"1234").unwrap();
        assert_eq!(OsFs.read_bounded(&path, 4).unwrap(), b"1234");
        assert_eq!(OsFs.read_bounded(&path, 3).unwrap_err().kind(), io::ErrorKind::FileTooLarge);
    }

    #[test]
    fn read_at_most_stops_on_an_endless_source() {
        assert_eq!(read_at_most(io::repeat(7), 16, 0).unwrap_err().kind(), io::ErrorKind::FileTooLarge);
    }

    #[cfg(unix)]
    #[test]
    fn read_bounded_refuses_a_symlink_and_a_directory() {
        let dir = TestDir::new("fs-read-kinds");
        let target = dir.path().join("target");
        let link = dir.path().join("link");
        std::fs::write(&target, b"1234").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert_eq!(OsFs.read_bounded(&link, 4).unwrap_err().kind(), io::ErrorKind::InvalidInput);
        assert_eq!(OsFs.read_bounded(dir.path(), 4).unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }

    #[cfg(unix)]
    #[test]
    fn sync_dir_succeeds_on_a_directory() {
        let dir = TestDir::new("fs-syncdir");
        OsFs.sync_dir(dir.path()).unwrap();
    }
}
