//! A [`FaultFs`] behind a lock, so a running service and the test can share one fault filesystem.

use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use iron_vault_store::StoreFs;
use iron_vault_store::fault_fs::{FaultFile, FaultFs};

/// A [`FaultFs`] the service can share across threads: the service's blocking tasks and the test's own code reach it
/// through one lock, so each call is atomic and the trace stays in order.
#[derive(Clone, Default)]
pub struct SharedFs(Arc<Mutex<FaultFs>>);

impl SharedFs {
    pub fn with<T>(&self, f: impl FnOnce(&FaultFs) -> T) -> T {
        f(&self.0.lock().unwrap_or_else(PoisonError::into_inner))
    }

    /// The files under `dirs` on the real filesystem, copied in as durable files at the same paths.
    pub fn seeded_from(dirs: &[PathBuf]) -> Self {
        let files = dirs.iter().flat_map(|dir| files_under(dir));
        let fs = files.fold(FaultFs::new(), |fs, path| fs.with_durable_file(&path, &fs::read(&path).unwrap()));
        Self(Arc::new(Mutex::new(fs)))
    }

    pub fn contents(&self, path: &Path) -> Option<Vec<u8>> {
        self.with(|fs| fs.contents(path))
    }
}

pub fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut entries: Vec<PathBuf> = fs::read_dir(dir).unwrap().map(|entry| entry.unwrap().path()).collect();
    entries.sort();
    entries
        .into_iter()
        .flat_map(|path| if path.is_dir() { files_under(&path) } else { vec![path] })
        .collect()
}

impl StoreFs for SharedFs {
    type File = FaultFile;

    fn create_private(&self, path: &Path) -> io::Result<FaultFile> {
        self.with(|fs| fs.create_private(path))
    }

    fn write_all(&self, file: &mut FaultFile, bytes: &[u8]) -> io::Result<()> {
        self.with(|fs| fs.write_all(file, bytes))
    }

    fn sync_file(&self, file: &FaultFile) -> io::Result<()> {
        self.with(|fs| fs.sync_file(file))
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        self.with(|fs| fs.rename(from, to))
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        self.with(|fs| fs.remove_file(path))
    }

    fn sync_dir(&self, dir: &Path) -> io::Result<()> {
        self.with(|fs| fs.sync_dir(dir))
    }

    fn list_dir(&self, dir: &Path) -> io::Result<Vec<OsString>> {
        self.with(|fs| fs.list_dir(dir))
    }

    fn read_bounded(&self, path: &Path, max_len: u64) -> io::Result<Vec<u8>> {
        self.with(|fs| fs.read_bounded(path, max_len))
    }
}
