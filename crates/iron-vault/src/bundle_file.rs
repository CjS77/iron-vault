//! The migration bundle file `export` writes (`design/migration-bundle.md`, "Transfer"), through the store's file-system
//! seam so the same durable-write checks that cover the vault's files cover the bundle too.
//!
//! The bundle grows in a partial file beside the bundle's path and takes the bundle's name only once it is whole, so a
//! cut bundle never has the bundle's name.

use std::ffi::OsString;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use iron_vault_store::StoreFs;

/// Why a bundle file could not be started or kept.
#[derive(Debug, thiserror::Error)]
pub enum BundleFileError {
    /// The bundle path ends in no file name.
    #[error("{} does not name a file", .0.display())]
    NotAFile(PathBuf),
    /// Something already has the bundle's name; an export never overwrites it.
    #[error("{} already exists; choose a new path", .0.display())]
    Exists(PathBuf),
    /// A crashed export left its partial file, which is never appended to.
    #[error("{} is left from an earlier export; remove it", .0.display())]
    LeftOver(PathBuf),
    /// The partial file could not be created.
    #[error("cannot create {}: {source}", path.display())]
    Create {
        /// The partial file.
        path: PathBuf,
        /// The cause.
        source: io::Error,
    },
    /// The partial file could not be fsynced.
    #[error("cannot write {}: {source}", path.display())]
    Sync {
        /// The partial file.
        path: PathBuf,
        /// The cause.
        source: io::Error,
    },
    /// The bundle's name could not be linked to the partial file, perhaps because that name appeared meanwhile.
    #[error("cannot create {}: {source}", path.display())]
    Link {
        /// The bundle path.
        path: PathBuf,
        /// The cause.
        source: io::Error,
    },
}

/// The bundle while it arrives: `.<bundle name>.partial` beside `<bundle>`, removed on every ending but a kept one.
/// Bytes written to it go to the partial file.
pub struct PartialBundle<'a, F: StoreFs> {
    fs: &'a F,
    file: F::File,
    path: PathBuf,
    bundle: PathBuf,
    dir: PathBuf,
    removed: bool,
}

impl<'a, F: StoreFs> PartialBundle<'a, F> {
    /// Refuses a `bundle` path that exists, then creates the partial file new, with mode `0600`, so a partial file a
    /// crashed export left is never appended to.
    pub fn create(fs: &'a F, bundle: &Path) -> Result<Self, BundleFileError> {
        let name = bundle.file_name().ok_or_else(|| BundleFileError::NotAFile(bundle.to_path_buf()))?;
        if bundle.symlink_metadata().is_ok() {
            return Err(BundleFileError::Exists(bundle.to_path_buf()));
        }
        let dir = match bundle.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
            _ => PathBuf::from("."),
        };
        let mut partial_name = OsString::from(".");
        partial_name.push(name);
        partial_name.push(".partial");
        let path = dir.join(partial_name);
        let file = fs.create_private(&path).map_err(|source| match source.kind() {
            io::ErrorKind::AlreadyExists => BundleFileError::LeftOver(path.clone()),
            _ => BundleFileError::Create {
                path: path.clone(),
                source,
            },
        })?;
        Ok(Self {
            fs,
            file,
            path,
            bundle: bundle.to_path_buf(),
            dir,
            removed: false,
        })
    }

    /// Keeps the whole bundle: fsyncs it, links it to the bundle's name, which fails if that name appeared meanwhile,
    /// removes the partial name and fsyncs the directory, so the bundle's name survives a power cut.
    ///
    /// An error means no bundle has the bundle's name. `Ok(Some(_))` means the bundle is kept and durable as far as its
    /// link, but tidying up failed: the caller warns rather than failing the export.
    pub fn keep(&mut self) -> Result<Option<io::Error>, BundleFileError> {
        let path = &self.path;
        self.fs.sync_file(&self.file).map_err(|source| BundleFileError::Sync {
            path: path.clone(),
            source,
        })?;
        self.fs.hard_link(path, &self.bundle).map_err(|source| BundleFileError::Link {
            path: self.bundle.clone(),
            source,
        })?;
        let removed = self.fs.remove_file(path);
        self.removed = removed.is_ok();
        Ok(removed.and_then(|()| self.fs.sync_dir(&self.dir)).err())
    }

    /// The partial file's path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The directory the bundle is written in.
    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

impl<F: StoreFs> Write for PartialBundle<'_, F> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.fs.write_all(&mut self.file, bytes).map(|()| bytes.len())
    }

    /// Every write goes straight to the file; [`PartialBundle::keep`] fsyncs it.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<F: StoreFs> Drop for PartialBundle<'_, F> {
    /// Removes the partial file however the export ended, unless a kept bundle already removed it.
    fn drop(&mut self) {
        if !self.removed {
            let _ = self.fs.remove_file(&self.path);
        }
    }
}
