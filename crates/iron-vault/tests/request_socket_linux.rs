//! Binding a request socket end to end, as the unprivileged test user: binding at `0666` in a trusted directory,
//! stale and foreign files at the path, and the admin socket's path. The service account
//! is the test's own uid.

#![cfg(target_os = "linux")]
// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt, symlink};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use iron_vault::admin::ADMIN_SOCKET_NAME;
use iron_vault::path_metadata::invoking_user;
use iron_vault::request_socket::{BindError, RequestBindError, RequestSocket};
use iron_vault::trusted_path::ExpectedOwner;

static NEXT: AtomicU32 = AtomicU32::new(0);

/// A fresh runtime directory at `0711` under the system temp directory, removed on drop. Its path stays short, because
/// a socket path is limited to 108 bytes.
struct RuntimeDir(PathBuf);

impl RuntimeDir {
    fn new() -> Self {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("iv-req-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o711)).unwrap();
        Self(dir)
    }

    fn socket(&self) -> PathBuf {
        self.0.join("request.sock")
    }

    fn admin_socket(&self) -> PathBuf {
        self.0.join(ADMIN_SOCKET_NAME)
    }

    fn bind(&self) -> Result<RequestSocket, RequestBindError> {
        RequestSocket::bind(&self.socket(), me(), &self.admin_socket())
    }
}

impl Drop for RuntimeDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn me() -> ExpectedOwner {
    invoking_user().unwrap()
}

#[test]
fn the_bound_socket_is_the_service_accounts_with_mode_0666() {
    let dir = RuntimeDir::new();
    let socket = dir.bind().unwrap();
    let metadata = fs::symlink_metadata(socket.path()).unwrap();
    assert!(metadata.file_type().is_socket());
    assert_eq!(metadata.uid(), me().uid);
    assert_eq!(metadata.mode() & 0o7777, 0o666);
    std::os::unix::net::UnixStream::connect(socket.path()).unwrap();
}

#[test]
fn a_stale_socket_of_the_service_account_is_replaced() {
    let dir = RuntimeDir::new();
    drop(std::os::unix::net::UnixListener::bind(dir.socket()).unwrap());
    fs::set_permissions(dir.socket(), fs::Permissions::from_mode(0o640)).unwrap();
    let socket = dir.bind().unwrap();
    // The kernel may reuse the stale socket's inode, so a listening socket at mode 0666 is what shows it was replaced.
    assert_eq!(fs::symlink_metadata(socket.path()).unwrap().mode() & 0o7777, 0o666);
    std::os::unix::net::UnixStream::connect(socket.path()).unwrap();
}

#[test]
fn a_regular_file_at_the_path_is_refused_and_kept() {
    let dir = RuntimeDir::new();
    fs::write(dir.socket(), b"someone else's").unwrap();
    let refused = dir.bind().unwrap_err();
    let RequestBindError::Bind(BindError::Occupied { path, found, .. }) = &refused else {
        panic!("expected Occupied, got {refused:?}");
    };
    assert_eq!(path, &dir.socket());
    assert!(found.starts_with("a regular file"), "{found}");
    assert!(refused.to_string().contains("request socket"), "{refused}");
    assert_eq!(fs::read(dir.socket()).unwrap(), b"someone else's");
}

#[test]
fn a_directory_writable_by_group_is_refused_by_name() {
    let dir = RuntimeDir::new();
    fs::set_permissions(&dir.0, fs::Permissions::from_mode(0o771)).unwrap();
    let refused = dir.bind().unwrap_err();
    let RequestBindError::UntrustedDirectory { dir: named, .. } = &refused else {
        panic!("expected UntrustedDirectory, got {refused:?}");
    };
    assert_eq!(named, &dir.0);
    assert!(refused.to_string().contains(&dir.0.display().to_string()), "{refused}");
    assert!(
        fs::symlink_metadata(dir.socket()).is_err(),
        "a socket was bound in an untrusted directory"
    );
}

#[test]
fn the_admin_socket_path_is_refused() {
    let dir = RuntimeDir::new();
    let refused = RequestSocket::bind(&dir.admin_socket(), me(), &dir.admin_socket()).unwrap_err();
    assert_eq!(refused, RequestBindError::AdminSocketPath { path: dir.admin_socket() });
}

#[test]
fn the_admin_socket_path_is_refused_through_a_symlinked_directory() {
    let dir = RuntimeDir::new();
    let real = dir.0.join("run");
    fs::create_dir(&real).unwrap();
    fs::set_permissions(&real, fs::Permissions::from_mode(0o711)).unwrap();
    let admin = real.join(ADMIN_SOCKET_NAME);
    drop(std::os::unix::net::UnixListener::bind(&admin).unwrap());
    let alias = dir.0.join("alias");
    symlink(&real, &alias).unwrap();
    let refused = RequestSocket::bind(&alias.join(ADMIN_SOCKET_NAME), me(), &admin).unwrap_err();
    assert_eq!(
        refused,
        RequestBindError::AdminSocketPath {
            path: alias.join(ADMIN_SOCKET_NAME)
        }
    );
    assert!(fs::symlink_metadata(&admin).unwrap().file_type().is_socket());
}

#[test]
fn dropping_the_socket_removes_its_file() {
    let dir = RuntimeDir::new();
    let socket = dir.bind().unwrap();
    assert!(dir.socket().exists());
    drop(socket);
    assert!(fs::symlink_metadata(dir.socket()).is_err(), "the socket file was left behind");
}
