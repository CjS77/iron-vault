//! A host unlock handoff in a private directory, for the tests of the service's host unlock and `import --host-unlock`.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

/// A private `0700` directory under `$XDG_RUNTIME_DIR`, or `$HOME` without one, holding the handoff; removed on drop.
/// The `UnlockHandoff` trusted-path rule refuses a sticky `/tmp` ancestor, and a test never touches a system runtime
/// directory.
pub struct HandoffDir(PathBuf);

impl HandoffDir {
    pub fn new() -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let base = std::env::var_os("XDG_RUNTIME_DIR").or_else(|| std::env::var_os("HOME")).unwrap();
        let dir = PathBuf::from(base).join(format!("iv-hu-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        Self(dir)
    }

    /// The private directory itself.
    pub fn dir(&self) -> &Path {
        &self.0
    }

    /// Where the handoff is, whether or not it has been written.
    pub fn path(&self) -> PathBuf {
        self.0.join("host-unlock")
    }

    /// Writes `secret` as the handoff, `0400` as the host would leave it, in place of any handoff already there.
    pub fn write(&self, secret: &str) -> PathBuf {
        let path = self.path();
        let _ = fs::remove_file(&path);
        fs::write(&path, format!("{secret}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        path
    }
}

impl Drop for HandoffDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
