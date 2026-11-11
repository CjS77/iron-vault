//! `iron-vault export <bundle>` (`design/migration-bundle.md`, "Transfer"): the CLI's side of writing a migration bundle.
//!
//! The bundle path stays in the CLI, which writes the file as the owner. The bundle grows in a partial file beside it,
//! created before the request so a permission problem shows before any prompt, and appears under the name the owner
//! asked for only once the service's result vouches for every byte. A cut bundle therefore never has the bundle's name.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use iron_vault::admin::protocol::{AdminRequest, AdminResponse};

use super::Exit;
use super::client::{Bundle, Received, answered, fail, unexpected};
use super::console::ProcessConsole;

/// Runs `export`: refuses an existing `bundle` and a leftover partial file before it connects, receives the bundle into
/// the partial file, and keeps it under `bundle` only after a success whose byte count matches what arrived.
pub fn run_export(socket: Option<&Path>, bundle: &Path) -> Exit {
    let mut partial = match PartialBundle::create(bundle) {
        Ok(partial) => partial,
        Err(message) => return fail(Exit::Usage, &format!("{message}; nothing was sent")),
    };
    let (answer, received) = {
        let mut receiving = Bundle::receiving(&mut partial.file);
        let answer = answered(socket, AdminRequest::Export, &mut ProcessConsole::default(), &mut receiving);
        (answer, receiving.received().unwrap_or_default())
    };
    match answer {
        Ok(AdminResponse::Export { vault_id, records, bytes }) => match partial.keep(received, bytes) {
            Ok(()) => {
                println!(
                    "exported vault {vault_id} to {}: {records} credentials, {bytes} bytes",
                    bundle.display()
                );
                println!("the source vault keeps serving until you retire it");
                println!("the bundle opens only with the export passphrase");
                Exit::Success
            }
            Err(message) => fail(Exit::Unreachable, &format!("{message}; no bundle was kept")),
        },
        Ok(_) => unexpected(),
        Err(exit) => exit,
    }
}

/// The bundle while it arrives: `.<bundle name>.partial` beside `<bundle>`, removed on every ending but a kept one.
struct PartialBundle {
    file: File,
    path: PathBuf,
    bundle: PathBuf,
    dir: PathBuf,
}

impl PartialBundle {
    /// Refuses a `bundle` path that exists, then creates the partial file with `O_CREAT | O_EXCL` and mode `0600`, so a
    /// partial file a crashed export left is never appended to.
    fn create(bundle: &Path) -> Result<Self, String> {
        let name = bundle
            .file_name()
            .ok_or_else(|| format!("{} does not name a file", bundle.display()))?;
        if bundle.symlink_metadata().is_ok() {
            return Err(format!("{} already exists; choose a new path", bundle.display()));
        }
        let dir = match bundle.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
            _ => PathBuf::from("."),
        };
        let mut partial_name = std::ffi::OsString::from(".");
        partial_name.push(name);
        partial_name.push(".partial");
        let path = dir.join(partial_name);
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| match e.kind() {
                io::ErrorKind::AlreadyExists => format!("{} is left from an earlier export; remove it", path.display()),
                _ => format!("cannot create {}: {e}", path.display()),
            })?;
        Ok(Self {
            file,
            path,
            bundle: bundle.to_path_buf(),
            dir,
        })
    }

    /// Keeps the bundle once it is whole: the empty frame arrived and the byte count is the result's. It is fsynced,
    /// hard-linked to the bundle's name, which fails if that name appeared meanwhile, and the directory fsynced once
    /// the partial name is gone. An error means no bundle has the bundle's name.
    fn keep(&mut self, received: Received, expected: u64) -> Result<(), String> {
        if !received.ended || received.bytes != expected {
            return Err(format!(
                "the bundle is incomplete: {} bytes arrived, and the service sent {expected}",
                received.bytes
            ));
        }
        self.file
            .sync_all()
            .map_err(|e| format!("cannot write {}: {e}", self.path.display()))?;
        fs::hard_link(&self.path, &self.bundle).map_err(|e| format!("cannot create {}: {e}", self.bundle.display()))?;
        // The bundle is whole under its name from here on, so a failure to tidy up is a warning, not a failed export.
        let tidied = fs::remove_file(&self.path).and_then(|()| File::open(&self.dir)?.sync_all());
        if let Err(e) = tidied {
            eprintln!(
                "iron-vault: warning: the bundle is written, but {} could not be synced or {} removed: {e}",
                self.dir.display(),
                self.path.display()
            );
        }
        Ok(())
    }
}

impl Drop for PartialBundle {
    /// Removes the partial file however the export ended; after a kept bundle it is already gone.
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}
