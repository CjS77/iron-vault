// SPDX-License-Identifier: MPL-2.0
//! Scratch directories for tests that use the real filesystem, removed when the guard drops.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

static NEXT: AtomicU32 = AtomicU32::new(0);

/// A fresh, empty directory under the system temporary directory, deleted on drop.
pub(crate) struct TestDir(PathBuf);

impl TestDir {
    /// Creates a directory whose name is unique to this process, `name` and call.
    pub(crate) fn new(name: &str) -> Self {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("iv-store-{name}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    /// Returns the directory's path.
    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Makes a FIFO at `path` with the `mkfifo` system call.
///
/// Spawning the `mkfifo` command would fork, and the child would share this process's lock file descriptors until it
/// execs, so a concurrent test retaking its own lock could find it held.
#[cfg(unix)]
pub(crate) fn make_fifo(path: &Path) {
    rustix::fs::mknodat(
        rustix::fs::CWD,
        path,
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(0o600),
        0,
    )
    .unwrap();
}
