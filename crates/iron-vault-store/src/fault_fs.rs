//! The fault filesystem: an in-memory [`StoreFs`] that records every call, fails chosen calls and models power loss.
//!
//! Durable-write bugs only show after a power cut, which ordinary tests never cause. This double keeps two views of
//! the filesystem. The visible view is what reads see now. The durable view is what survives a crash: a file's
//! contents enter it only on [`StoreFs::sync_file`], and a directory entry change (create, rename, unlink) only on
//! the next [`StoreFs::sync_dir`] of the containing directory. [`FaultFs::crash`] throws the visible view away.
//!
//! The model is deliberately pessimistic: a real filesystem may keep an unsynced change, but a write that is correct
//! here is correct whether or not it does.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};

use crate::StoreFs;

/// The [`StoreFs`] method a call went to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsOp {
    /// [`StoreFs::create_private`].
    CreatePrivate,
    /// [`StoreFs::write_all`].
    WriteAll,
    /// [`StoreFs::sync_file`].
    SyncFile,
    /// [`StoreFs::rename`].
    Rename,
    /// [`StoreFs::remove_file`].
    RemoveFile,
    /// [`StoreFs::sync_dir`].
    SyncDir,
    /// [`StoreFs::list_dir`].
    ListDir,
    /// [`StoreFs::read_bounded`].
    ReadBounded,
}

/// One recorded [`StoreFs`] call and the path it acted on; a file-handle call records the path the file was created at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsCall {
    /// A private file was created at this path.
    CreatePrivate(PathBuf),
    /// Bytes were written to the file created at this path.
    WriteAll(PathBuf),
    /// The file created at this path was fsynced.
    SyncFile(PathBuf),
    /// A file was renamed.
    Rename {
        /// The old path.
        from: PathBuf,
        /// The new path.
        to: PathBuf,
    },
    /// The file at this path was unlinked.
    RemoveFile(PathBuf),
    /// This directory was fsynced.
    SyncDir(PathBuf),
    /// This directory was listed.
    ListDir(PathBuf),
    /// The file at this path was read.
    ReadBounded(PathBuf),
}

impl FsCall {
    /// The method this call went to.
    pub fn op(&self) -> FsOp {
        match self {
            Self::CreatePrivate(_) => FsOp::CreatePrivate,
            Self::WriteAll(_) => FsOp::WriteAll,
            Self::SyncFile(_) => FsOp::SyncFile,
            Self::Rename { .. } => FsOp::Rename,
            Self::RemoveFile(_) => FsOp::RemoveFile,
            Self::SyncDir(_) => FsOp::SyncDir,
            Self::ListDir(_) => FsOp::ListDir,
            Self::ReadBounded(_) => FsOp::ReadBounded,
        }
    }
}

/// An open file in a [`FaultFs`].
#[derive(Debug)]
pub struct FaultFile {
    inode: usize,
    path: PathBuf,
}

/// The fault filesystem: see the module documentation.
///
/// Calls are numbered from 0 in the order they arrive. A failed call is recorded in the trace and changes nothing.
#[derive(Debug, Default)]
pub struct FaultFs {
    state: RefCell<State>,
}

#[derive(Debug, Default)]
struct State {
    inodes: Vec<Inode>,
    visible: BTreeMap<PathBuf, usize>,
    durable: BTreeMap<PathBuf, usize>,
    trace: Vec<FsCall>,
    faults: Vec<Fault>,
    power_cut_at: Option<usize>,
}

#[derive(Debug, Default)]
struct Inode {
    data: Vec<u8>,
    synced: Vec<u8>,
}

#[derive(Debug)]
struct Fault {
    trigger: Trigger,
    kind: io::ErrorKind,
}

#[derive(Debug)]
enum Trigger {
    Call(usize),
    FirstOf(FsOp),
}

impl FaultFs {
    /// An empty filesystem with no faults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a file at `path` holding `bytes`, already durable, without recording a call.
    pub fn with_durable_file(self, path: &Path, bytes: &[u8]) -> Self {
        {
            let mut st = self.state.borrow_mut();
            let inode = st.new_inode(bytes.to_vec(), bytes.to_vec());
            st.visible.insert(path.to_path_buf(), inode);
            st.durable.insert(path.to_path_buf(), inode);
        }
        self
    }

    /// Makes call number `n` (counting from 0) fail with `kind`.
    pub fn fail_call(&self, n: usize, kind: io::ErrorKind) {
        self.state.borrow_mut().faults.push(Fault {
            trigger: Trigger::Call(n),
            kind,
        });
    }

    /// Makes the first call to `op` from now on fail with `kind`.
    pub fn fail_first(&self, op: FsOp, kind: io::ErrorKind) {
        self.state.borrow_mut().faults.push(Fault {
            trigger: Trigger::FirstOf(op),
            kind,
        });
    }

    /// Cuts the power after `k` calls: call number `k` and every later one fails and changes nothing, until
    /// [`FaultFs::crash`] restores the power.
    pub fn cut_power_after(&self, k: usize) {
        self.state.borrow_mut().power_cut_at = Some(k);
    }

    /// Simulates power loss and reboot: every unsynced change is lost, and every pending fault is cleared.
    pub fn crash(&self) {
        let mut st = self.state.borrow_mut();
        st.visible = st.durable.clone();
        st.inodes.iter_mut().for_each(|inode| inode.data = inode.synced.clone());
        st.faults.clear();
        st.power_cut_at = None;
    }

    /// Every call so far, in order.
    pub fn trace(&self) -> Vec<FsCall> {
        self.state.borrow().trace.clone()
    }

    /// The visible contents of the file at `path`, without recording a call.
    pub fn contents(&self, path: &Path) -> Option<Vec<u8>> {
        let st = self.state.borrow();
        st.data_at(path).ok().map(<[u8]>::to_vec)
    }

    /// Records `call`, then runs `apply` unless a fault or power cut fails it.
    fn call<T>(&self, call: FsCall, apply: impl FnOnce(&mut State) -> io::Result<T>) -> io::Result<T> {
        let mut st = self.state.borrow_mut();
        let index = st.trace.len();
        let op = call.op();
        st.trace.push(call);
        match st.take_fault(index, op) {
            Some(kind) => Err(io::Error::new(kind, format!("injected fault at call {index}"))),
            None => apply(&mut st),
        }
    }
}

impl State {
    fn new_inode(&mut self, data: Vec<u8>, synced: Vec<u8>) -> usize {
        self.inodes.push(Inode { data, synced });
        self.inodes.len() - 1
    }

    /// The error kind call `index` must fail with, consuming a one-shot fault.
    fn take_fault(&mut self, index: usize, op: FsOp) -> Option<io::ErrorKind> {
        if self.power_cut_at.is_some_and(|k| index >= k) {
            return Some(io::ErrorKind::Other);
        }
        let position = self.faults.iter().position(|f| match f.trigger {
            Trigger::Call(n) => n == index,
            Trigger::FirstOf(o) => o == op,
        })?;
        Some(self.faults.remove(position).kind)
    }

    fn inode_at(&self, path: &Path) -> io::Result<usize> {
        self.visible
            .get(path)
            .copied()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such file"))
    }

    fn data_at(&self, path: &Path) -> io::Result<&[u8]> {
        let inode = self.inode_at(path)?;
        self.inodes
            .get(inode)
            .map(|i| i.data.as_slice())
            .ok_or_else(|| io::Error::other("unknown file handle"))
    }

    fn inode_mut(&mut self, inode: usize) -> io::Result<&mut Inode> {
        self.inodes.get_mut(inode).ok_or_else(|| io::Error::other("unknown file handle"))
    }
}

impl StoreFs for FaultFs {
    type File = FaultFile;

    fn create_private(&self, path: &Path) -> io::Result<FaultFile> {
        self.call(FsCall::CreatePrivate(path.to_path_buf()), |st| {
            if st.visible.contains_key(path) {
                return Err(io::Error::new(io::ErrorKind::AlreadyExists, "file exists"));
            }
            let inode = st.new_inode(Vec::new(), Vec::new());
            st.visible.insert(path.to_path_buf(), inode);
            Ok(FaultFile {
                inode,
                path: path.to_path_buf(),
            })
        })
    }

    fn write_all(&self, file: &mut FaultFile, bytes: &[u8]) -> io::Result<()> {
        self.call(FsCall::WriteAll(file.path.clone()), |st| {
            st.inode_mut(file.inode)?.data.extend_from_slice(bytes);
            Ok(())
        })
    }

    fn sync_file(&self, file: &FaultFile) -> io::Result<()> {
        self.call(FsCall::SyncFile(file.path.clone()), |st| {
            let inode = st.inode_mut(file.inode)?;
            inode.synced = inode.data.clone();
            Ok(())
        })
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        self.call(
            FsCall::Rename {
                from: from.to_path_buf(),
                to: to.to_path_buf(),
            },
            |st| {
                let inode = st.inode_at(from)?;
                st.visible.remove(from);
                st.visible.insert(to.to_path_buf(), inode);
                Ok(())
            },
        )
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        self.call(FsCall::RemoveFile(path.to_path_buf()), |st| {
            st.inode_at(path)?;
            st.visible.remove(path);
            Ok(())
        })
    }

    fn sync_dir(&self, dir: &Path) -> io::Result<()> {
        self.call(FsCall::SyncDir(dir.to_path_buf()), |st| {
            st.durable.retain(|path, _| path.parent() != Some(dir));
            let entries: Vec<_> = st
                .visible
                .iter()
                .filter(|(path, _)| path.parent() == Some(dir))
                .map(|(p, &i)| (p.clone(), i))
                .collect();
            st.durable.extend(entries);
            Ok(())
        })
    }

    fn list_dir(&self, dir: &Path) -> io::Result<Vec<OsString>> {
        self.call(FsCall::ListDir(dir.to_path_buf()), |st| {
            // BTreeMap order over paths with one parent is file-name order, so the result is already sorted.
            let in_dir = st.visible.keys().filter(|path| path.parent() == Some(dir));
            Ok(in_dir.filter_map(|path| path.file_name()).map(OsString::from).collect())
        })
    }

    fn read_bounded(&self, path: &Path, max_len: u64) -> io::Result<Vec<u8>> {
        self.call(FsCall::ReadBounded(path.to_path_buf()), |st| {
            let data = st.data_at(path)?;
            match u64::try_from(data.len()) {
                Ok(len) if len <= max_len => Ok(data.to_vec()),
                _ => Err(io::Error::new(
                    io::ErrorKind::FileTooLarge,
                    format!("file is longer than {max_len} bytes"),
                )),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> PathBuf {
        PathBuf::from(s)
    }

    #[test]
    fn unsynced_contents_are_lost_on_crash() {
        let fs = FaultFs::new();
        let mut f = fs.create_private(&p("/d/a")).unwrap();
        fs.write_all(&mut f, b"x").unwrap();
        fs.sync_dir(&p("/d")).unwrap();
        fs.crash();
        assert_eq!(fs.contents(&p("/d/a")).unwrap(), b"");
    }

    #[test]
    fn rename_without_dir_sync_is_undone_by_crash() {
        let fs = FaultFs::new()
            .with_durable_file(&p("/d/a"), b"old")
            .with_durable_file(&p("/d/b"), b"new");
        fs.rename(&p("/d/b"), &p("/d/a")).unwrap();
        assert_eq!(fs.contents(&p("/d/a")).unwrap(), b"new");
        fs.crash();
        assert_eq!(fs.contents(&p("/d/a")).unwrap(), b"old");
        assert_eq!(fs.contents(&p("/d/b")).unwrap(), b"new");
    }

    #[test]
    fn synced_rename_survives_crash() {
        let fs = FaultFs::new().with_durable_file(&p("/d/b"), b"new");
        fs.rename(&p("/d/b"), &p("/d/a")).unwrap();
        fs.sync_dir(&p("/d")).unwrap();
        fs.crash();
        assert_eq!(fs.contents(&p("/d/a")).unwrap(), b"new");
        assert_eq!(fs.contents(&p("/d/b")), None);
    }

    #[test]
    fn sync_dir_touches_only_that_directory() {
        let fs = FaultFs::new();
        fs.create_private(&p("/d/a")).unwrap();
        fs.create_private(&p("/e/a")).unwrap();
        fs.sync_dir(&p("/d")).unwrap();
        fs.crash();
        assert!(fs.contents(&p("/d/a")).is_some());
        assert!(fs.contents(&p("/e/a")).is_none());
    }

    #[test]
    fn faults_fail_once_and_change_nothing() {
        let fs = FaultFs::new();
        fs.fail_call(0, io::ErrorKind::PermissionDenied);
        fs.fail_first(FsOp::CreatePrivate, io::ErrorKind::StorageFull);
        assert_eq!(fs.create_private(&p("/d/a")).unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(fs.create_private(&p("/d/a")).unwrap_err().kind(), io::ErrorKind::StorageFull);
        assert!(fs.contents(&p("/d/a")).is_none());
        fs.create_private(&p("/d/a")).unwrap();
        assert_eq!(fs.trace().len(), 3);
    }

    #[test]
    fn power_cut_fails_every_later_call_until_crash() {
        let fs = FaultFs::new();
        fs.cut_power_after(1);
        fs.create_private(&p("/d/a")).unwrap();
        assert!(fs.sync_dir(&p("/d")).is_err());
        assert!(fs.create_private(&p("/d/b")).is_err());
        fs.crash();
        assert!(fs.contents(&p("/d/a")).is_none());
        fs.create_private(&p("/d/b")).unwrap();
    }

    #[test]
    fn list_dir_is_sorted_and_flat() {
        let fs = FaultFs::new()
            .with_durable_file(&p("/d/c"), b"")
            .with_durable_file(&p("/d/a"), b"")
            .with_durable_file(&p("/e/b"), b"");
        assert_eq!(fs.list_dir(&p("/d")).unwrap(), ["a", "c"]);
    }

    #[test]
    fn read_bounded_and_missing_files() {
        let fs = FaultFs::new().with_durable_file(&p("/d/a"), b"1234");
        assert_eq!(fs.read_bounded(&p("/d/a"), 4).unwrap(), b"1234");
        assert_eq!(fs.read_bounded(&p("/d/a"), 3).unwrap_err().kind(), io::ErrorKind::FileTooLarge);
        assert_eq!(fs.remove_file(&p("/d/x")).unwrap_err().kind(), io::ErrorKind::NotFound);
        assert_eq!(fs.rename(&p("/d/x"), &p("/d/y")).unwrap_err().kind(), io::ErrorKind::NotFound);
    }
}
