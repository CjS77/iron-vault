//! Linux path metadata through `lstat` and `readlink`, and the running binary through `/proc/self/exe`.

use std::cell::Cell;
use std::fs::{self, Metadata};
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use super::{CollectError, MAX_SYMLINK_HOPS};
use crate::trusted_path::{ComponentKind, Mode, PathComponent, SymlinkTarget};

/// The kernel's name for the binary this process is running; it stays valid after the file is deleted or replaced.
const PROC_SELF_EXE: &str = "/proc/self/exe";

/// The suffix the kernel appends to `/proc/self/exe`'s target once the running binary has been unlinked.
const DELETED_SUFFIX: &str = " (deleted)";

/// Collects `path`'s chain, sharing one symlink-hop count across the path and every target it leads through.
pub(super) fn collect(path: &Path) -> Result<Vec<PathComponent>, CollectError> {
    Collector { hops: Cell::new(0) }.chain(path)
}

/// One collection: how many symlinks it has followed so far.
struct Collector {
    hops: Cell<usize>,
}

impl Collector {
    /// The components of `path` from `/` down, stopping after a symlink reported as a loop.
    fn chain(&self, path: &Path) -> Result<Vec<PathComponent>, CollectError> {
        prefixes(path)?.iter().try_fold(Vec::new(), |mut chain, prefix| {
            if !chain.last().is_some_and(is_loop) {
                chain.push(self.component(prefix)?);
            }
            Ok(chain)
        })
    }

    fn component(&self, path: &Path) -> Result<PathComponent, CollectError> {
        let metadata = fs::symlink_metadata(path).map_err(io_error(path))?;
        let kind = self.kind(path, &metadata)?;
        Ok(PathComponent {
            path: path.to_path_buf(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            owner_name: None,
            group_name: None,
            mode: Mode::new(metadata.mode()),
            kind,
        })
    }

    fn kind(&self, path: &Path, metadata: &Metadata) -> Result<ComponentKind, CollectError> {
        let file_type = metadata.file_type();
        Ok(if file_type.is_symlink() {
            ComponentKind::Symlink {
                target: self.resolve(path)?,
            }
        } else if file_type.is_dir() {
            ComponentKind::Directory
        } else if file_type.is_file() {
            ComponentKind::RegularFile
        } else {
            ComponentKind::Other
        })
    }

    /// Collects the chain `link` leads to, resolving a relative target against the directory holding the link.
    fn resolve(&self, link: &Path) -> Result<SymlinkTarget, CollectError> {
        if self.hops.get() >= MAX_SYMLINK_HOPS {
            return Ok(SymlinkTarget::Loop);
        }
        self.hops.set(self.hops.get() + 1);
        let target = fs::read_link(link).map_err(io_error(link))?;
        let holder = link.parent().unwrap_or(Path::new("/"));
        self.chain(&holder.join(target)).map(SymlinkTarget::Resolved)
    }
}

/// Every prefix of the absolute `path`, from `/` to the whole path, as the kernel walks it.
///
/// `.` adds nothing and is dropped; `..` is kept, because after a symlink it leads to the parent of the link's target,
/// which only the kernel can tell.
fn prefixes(path: &Path) -> Result<Vec<PathBuf>, CollectError> {
    if !path.is_absolute() {
        return Err(CollectError::NotAbsolute { path: path.to_path_buf() });
    }
    Ok(path
        .components()
        .filter(|component| *component != Component::CurDir)
        .scan(PathBuf::new(), |prefix, component| {
            prefix.push(component);
            Some(prefix.clone())
        })
        .collect())
}

fn is_loop(component: &PathComponent) -> bool {
    matches!(
        component.kind,
        ComponentKind::Symlink {
            target: SymlinkTarget::Loop
        }
    )
}

fn io_error(path: &Path) -> impl Fn(io::Error) -> CollectError + '_ {
    move |e| CollectError::Io {
        path: path.to_path_buf(),
        kind: e.kind(),
    }
}

/// Compares the file at `path` with the one the kernel says this process was started from.
pub(super) fn ensure_running_binary(path: &Path) -> Result<(), CollectError> {
    let running = fs::metadata(PROC_SELF_EXE).map_err(io_error(Path::new(PROC_SELF_EXE)))?;
    let on_disk = fs::metadata(path).ok().map(|metadata| FileId::of(&metadata));
    binary_status(path, FileId::of(&running), on_disk)
}

/// The identity of a file on this host: its device and inode numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileId {
    dev: u64,
    ino: u64,
}

impl FileId {
    fn of(metadata: &Metadata) -> Self {
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
        }
    }
}

/// The binary at `path` is the running one only if the kernel has not marked it deleted and the file now at `path` is
/// the same inode the process was started from.
fn binary_status(path: &Path, running: FileId, on_disk: Option<FileId>) -> Result<(), CollectError> {
    let deleted = path.as_os_str().as_encoded_bytes().ends_with(DELETED_SUFFIX.as_bytes());
    match !deleted && on_disk == Some(running) {
        true => Ok(()),
        false => Err(CollectError::BinaryReplaced { path: path.to_path_buf() }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RUNNING: FileId = FileId { dev: 2049, ino: 77 };

    #[test]
    fn the_same_inode_is_the_running_binary() {
        assert_eq!(binary_status(Path::new("/usr/bin/iron-vault"), RUNNING, Some(RUNNING)), Ok(()));
    }

    #[test]
    fn a_deleted_binary_is_replaced() {
        let path = Path::new("/usr/bin/iron-vault (deleted)");
        assert_eq!(
            binary_status(path, RUNNING, Some(RUNNING)),
            Err(CollectError::BinaryReplaced { path: path.to_path_buf() })
        );
    }

    #[test]
    fn another_inode_or_no_file_is_replaced() {
        let path = Path::new("/usr/bin/iron-vault");
        let other = FileId { ino: 78, ..RUNNING };
        [Some(other), None].into_iter().for_each(|on_disk| {
            assert_eq!(
                binary_status(path, RUNNING, on_disk),
                Err(CollectError::BinaryReplaced { path: path.to_path_buf() })
            );
        });
    }

    #[test]
    fn this_test_binary_is_running() {
        let exe = std::env::current_exe().unwrap();
        assert_eq!(ensure_running_binary(&exe), Ok(()));
    }

    #[test]
    fn prefixes_keep_parent_steps_and_drop_current_ones() {
        let expected: Vec<PathBuf> = ["/", "/a", "/a/..", "/a/../b"].iter().map(PathBuf::from).collect();
        assert_eq!(prefixes(Path::new("/a/./../b/")).unwrap(), expected);
    }

    #[test]
    fn a_relative_path_is_refused() {
        assert_eq!(
            collect(Path::new("etc/iron-vault")),
            Err(CollectError::NotAbsolute {
                path: PathBuf::from("etc/iron-vault")
            })
        );
    }

    #[test]
    fn a_missing_component_names_itself() {
        let err = collect(Path::new("/proc/self/no-such-entry")).unwrap_err();
        assert_eq!(
            err,
            CollectError::Io {
                path: PathBuf::from("/proc/self/no-such-entry"),
                kind: io::ErrorKind::NotFound
            }
        );
    }

    #[test]
    fn root_is_a_single_directory_component() {
        let chain = collect(Path::new("/")).unwrap();
        let shape: Vec<_> = chain.iter().map(|c| (c.path.clone(), c.kind.clone())).collect();
        assert_eq!(shape, [(PathBuf::from("/"), ComponentKind::Directory)]);
    }
}
