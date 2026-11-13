// SPDX-License-Identifier: MPL-2.0
//! A directory of listener TLS files, for tests of listeners whose certificate and key do or do not match.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use iron_vault::admin_file::AdminFile;
use iron_vault::deployment::DeploymentProfile;
use iron_vault::path_metadata::invoking_user;

/// A directory for listener TLS files, removed on drop.
///
/// The trusted-path rules refuse a certificate or key below a shared sticky directory such as `/tmp`, or below a
/// group-writable one, so the directory goes in the first base whose ancestors pass: the build's own temporary
/// directory, else `$XDG_RUNTIME_DIR`.
pub struct TlsDir(PathBuf);

impl TlsDir {
    /// A fresh `0700` directory holding `server.crt` (`0644`), `server.key` (`key_mode`) and `good.key`, the leaf's own key:
    /// `server.key` is the leaf's key when `matching`, another key otherwise, and [`fix_key`](Self::fix_key) swaps in
    /// `good.key`.
    pub fn new(name: &str, matching: bool, key_mode: u32) -> Self {
        let bases = [
            Some(PathBuf::from(env!("CARGO_TARGET_TMPDIR"))),
            std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from),
        ];
        bases
            .into_iter()
            .flatten()
            .map(|base| Self::create(&base, name, matching, key_mode))
            .find(|tls| {
                let owner = invoking_user().unwrap();
                iron_vault::admin_file::read(
                    AdminFile::Certificate,
                    DeploymentProfile::Development,
                    owner,
                    &tls.path("server.crt"),
                )
                .is_ok()
            })
            .expect("no base directory whose ancestors the trusted-path rules accept for listener TLS files")
    }

    fn create(base: &Path, name: &str, matching: bool, key_mode: u32) -> Self {
        let dir = base.join(format!("iv-tls-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
            .unwrap()
            .self_signed(&leaf_key)
            .unwrap();
        let served = if matching {
            &leaf_key
        } else {
            &rcgen::KeyPair::generate().unwrap()
        };
        let tls = Self(dir);
        [
            ("server.crt", leaf.pem(), 0o644),
            ("server.key", served.serialize_pem(), key_mode),
            ("good.key", leaf_key.serialize_pem(), 0o600),
        ]
        .into_iter()
        .for_each(|(file, pem, mode)| {
            fs::write(tls.path(file), pem).unwrap();
            fs::set_permissions(tls.path(file), fs::Permissions::from_mode(mode)).unwrap();
        });
        tls
    }

    /// The path of `file` in the directory.
    pub fn path(&self, file: &str) -> PathBuf {
        self.0.join(file)
    }

    /// Makes `server.key` the certificate's own key.
    pub fn fix_key(&self) {
        fs::copy(self.path("good.key"), self.path("server.key")).unwrap();
    }
}

impl Drop for TlsDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
