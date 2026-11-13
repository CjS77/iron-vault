// SPDX-License-Identifier: MPL-2.0
//! A filesystem whose first read of an armed file blocks, so a test can hold a config check mid-way.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex, mpsc};

use iron_vault_store::{OsFs, StoreFs};
use tokio::sync::oneshot;

use super::WAIT;

/// One armed stop: the file whose first read blocks, the signal that a read reached it, and the release.
struct Gate {
    file: String,
    reached: oneshot::Sender<()>,
    release: mpsc::Receiver<()>,
}

/// The real filesystem, except that the first read of an armed file blocks until the test releases it (or [`WAIT`]
/// passes), so a test can hold the unlock or the config check mid-way.
#[derive(Clone, Default)]
pub struct GatedFs(Arc<Mutex<Option<Gate>>>);

impl GatedFs {
    /// Arms the gate on `file`; returns the signal that a read reached it and its release.
    pub fn arm(&self, file: impl Into<String>) -> (oneshot::Receiver<()>, mpsc::Sender<()>) {
        let (reached, on_reached) = oneshot::channel();
        let (release, on_release) = mpsc::channel();
        *self.0.lock().unwrap() = Some(Gate {
            file: file.into(),
            reached,
            release: on_release,
        });
        (on_reached, release)
    }

    /// Blocks the calling thread on the gate if it is armed on `path`'s file, disarming it.
    fn pass(&self, path: &Path) {
        let mut armed = self.0.lock().unwrap();
        if !armed.as_ref().is_some_and(|gate| path.file_name() == Some(OsStr::new(&gate.file))) {
            return;
        }
        let gate = armed.take().unwrap();
        drop(armed);
        let _ = gate.reached.send(());
        let _ = gate.release.recv_timeout(WAIT);
    }
}

impl StoreFs for GatedFs {
    type File = fs::File;

    fn create_private(&self, path: &Path) -> io::Result<fs::File> {
        OsFs.create_private(path)
    }

    fn write_all(&self, file: &mut fs::File, bytes: &[u8]) -> io::Result<()> {
        OsFs.write_all(file, bytes)
    }

    fn sync_file(&self, file: &fs::File) -> io::Result<()> {
        OsFs.sync_file(file)
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        OsFs.rename(from, to)
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        OsFs.remove_file(path)
    }

    fn sync_dir(&self, dir: &Path) -> io::Result<()> {
        OsFs.sync_dir(dir)
    }

    fn list_dir(&self, dir: &Path) -> io::Result<Vec<OsString>> {
        OsFs.list_dir(dir)
    }

    fn read_bounded(&self, path: &Path, max_len: u64) -> io::Result<Vec<u8>> {
        self.pass(path);
        OsFs.read_bounded(path, max_len)
    }
}
