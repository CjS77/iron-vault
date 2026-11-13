// SPDX-License-Identifier: MPL-2.0
//! The config copy `import` leaves beside the bundle: the bundle's `config.toml` entry, which `config approve` reads in
//! the CLI because the CLI cannot always read the service's config directory
//! ([migration bundle: the config copy](../../../../../design/migration-bundle.md#the-config-copy)).
//!
//! The file is created before the request, so a name already taken shows before any prompt, and it is removed on every
//! ending but a kept one. A copy that is not the committed config is never left for the owner to approve.

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use iron_vault_store::ConfigDigest;
use iron_vault_store::migration_bundle::{BundleDecoder, EntryName};

/// The bytes of the bundle read at a time while the decoder looks for the config entry.
const READ_CHUNK: usize = 64 * 1024;

/// `<bundle>.config.toml`, created and owned by one `import`; dropping it removes the file unless it was kept.
#[derive(Debug)]
pub struct ConfigCopy {
    file: File,
    path: PathBuf,
    kept: bool,
}

impl ConfigCopy {
    /// Creates `<bundle>.config.toml` with `O_CREAT | O_EXCL` and mode `0600`, so a copy an earlier import left, or any
    /// other file of that name, is never overwritten. The error names the file for the owner to move.
    pub fn create(bundle: &Path) -> Result<Self, String> {
        let mut name = OsString::from(bundle.as_os_str());
        name.push(".config.toml");
        let path = PathBuf::from(name);
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| match e.kind() {
                io::ErrorKind::AlreadyExists => format!("{} already exists; move or remove it", path.display()),
                _ => format!("cannot create {}: {e}", path.display()),
            })?;
        Ok(Self { file, path, kept: false })
    }

    /// The copy's path, exactly as created.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Fills the copy from `bundle`'s config entry once its BLAKE2b-256 equals `committed`, the digest the service took
    /// from the approval state the vault identity opened, and fsyncs it. The bundle is opened again by path and decoded
    /// no further than that entry, so no `age` entry is opened. On an error the copy is removed.
    pub fn fill(mut self, bundle: &Path, committed: &[u8; 32]) -> Result<Self, String> {
        let config = config_entry(bundle)?;
        if ConfigDigest::of(&config).as_bytes() != committed {
            return Err(format!("{} no longer holds the config the import committed", bundle.display()));
        }
        self.file
            .write_all(&config)
            .and_then(|()| self.file.sync_all())
            .map_err(|e| format!("cannot write {}: {e}", self.path.display()))?;
        self.kept = true;
        Ok(self)
    }
}

impl Drop for ConfigCopy {
    /// Removes the copy however the import ended, unless [`ConfigCopy::fill`] kept it.
    fn drop(&mut self) {
        if !self.kept {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// The bundle's `config.toml` entry, decoded as the file is read and no further.
fn config_entry(bundle: &Path) -> Result<Vec<u8>, String> {
    let name = bundle.display();
    let mut file = File::open(bundle).map_err(|e| format!("cannot open {name}: {e}"))?;
    let mut decoder = BundleDecoder::new();
    let mut chunk = vec![0; READ_CHUNK];
    loop {
        if let Some(config) = decoder.entry(&EntryName::Config) {
            return Ok(config.to_vec());
        }
        match file.read(&mut chunk).map_err(|e| format!("cannot read {name}: {e}"))? {
            0 => return Err(format!("{name} ends before its config")),
            read => decoder
                .push(&chunk[..read])
                .map_err(|e| format!("{name} is no longer a bundle: {e}"))?,
        }
    }
}

/// `path` as one shell word: unquoted when it holds only characters a shell leaves alone, else in single quotes.
pub fn shell_word(path: &Path) -> String {
    let text = path.to_string_lossy();
    let plain = |c: char| c.is_ascii_alphanumeric() || "_@%+=:,./-".contains(c);
    if !text.is_empty() && text.chars().all(plain) {
        text.into_owned()
    } else {
        format!("'{}'", text.replace('\'', r"'\''"))
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use iron_vault_store::migration_bundle::{BundleEncoder, BundleHeader};
    use iron_vault_store::{ApproverId, VaultId};

    use super::*;

    const CONFIG: &[u8] = b"schema_version = 1\n";

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("iron-vault-config-copy-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A whole bundle of one approver and no record, around `config`.
    fn bundle_with(config: &[u8], dir: &Path) -> PathBuf {
        let vault_id = VaultId::from_bytes([
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x47, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01,
        ]);
        let header = BundleHeader::new(vault_id.unwrap(), 1, 0).unwrap();
        let mut bytes = Vec::new();
        {
            let mut encoder = BundleEncoder::new(&mut bytes, header).unwrap();
            [EntryName::ExportedIdentity, EntryName::Manifest, EntryName::ApprovalState]
                .into_iter()
                .for_each(|name| encoder.write_entry(name, b"age").unwrap());
            encoder.write_entry(EntryName::Config, config).unwrap();
            encoder.write_entry(EntryName::Approver(ApproverId::generate()), b"age").unwrap();
            encoder.finish().unwrap();
        }
        let path = dir.join("vault.bundle");
        fs::write(&path, bytes).unwrap();
        path
    }

    #[test]
    fn a_config_that_matches_the_committed_digest_is_kept_with_mode_0600() {
        let dir = scratch("match");
        let bundle = bundle_with(CONFIG, &dir);
        let copy = ConfigCopy::create(&bundle).unwrap();
        let path = copy.path().to_path_buf();
        let kept = copy.fill(&bundle, ConfigDigest::of(CONFIG).as_bytes()).unwrap();
        assert_eq!(fs::read(&path).unwrap(), CONFIG);
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        drop(kept);
        assert!(path.exists(), "a kept copy outlives its handle");
    }

    #[test]
    fn a_config_that_differs_from_the_committed_digest_leaves_no_copy() {
        let dir = scratch("differs");
        let bundle = bundle_with(b"schema_version = 2\n", &dir);
        let copy = ConfigCopy::create(&bundle).unwrap();
        let path = copy.path().to_path_buf();
        let refused = copy.fill(&bundle, ConfigDigest::of(CONFIG).as_bytes()).unwrap_err();
        assert!(refused.contains("no longer holds the config"), "{refused}");
        assert!(!path.exists());
    }

    #[test]
    fn a_bundle_that_ends_before_its_config_or_is_gone_leaves_no_copy() {
        let dir = scratch("short");
        let bundle = dir.join("vault.bundle");
        fs::write(&bundle, b"").unwrap();
        let copy = ConfigCopy::create(&bundle).unwrap();
        let path = copy.path().to_path_buf();
        assert!(copy.fill(&bundle, &[0; 32]).unwrap_err().contains("ends before its config"));
        assert!(!path.exists());
        let copy = ConfigCopy::create(&bundle).unwrap();
        assert!(copy.fill(&dir.join("absent"), &[0; 32]).unwrap_err().contains("cannot open"));
    }

    #[test]
    fn a_taken_name_is_refused_and_left_alone() {
        let dir = scratch("taken");
        let bundle = dir.join("vault.bundle");
        fs::write(dir.join("vault.bundle.config.toml"), b"mine").unwrap();
        let refused = ConfigCopy::create(&bundle).unwrap_err();
        assert!(refused.contains("vault.bundle.config.toml already exists"), "{refused}");
        assert_eq!(fs::read(dir.join("vault.bundle.config.toml")).unwrap(), b"mine");
    }

    #[test]
    fn a_plain_path_is_left_alone_and_anything_else_is_single_quoted() {
        assert_eq!(
            shell_word(Path::new("dir/vault.bundle.config.toml")),
            "dir/vault.bundle.config.toml"
        );
        assert_eq!(shell_word(Path::new("my vault.bundle")), "'my vault.bundle'");
        assert_eq!(shell_word(Path::new("it's$(x)")), r"'it'\''s$(x)'");
    }
}
