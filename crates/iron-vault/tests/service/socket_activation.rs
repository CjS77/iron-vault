//! Checking a socket systemd passed against its listener, on real sockets the test creates in place of systemd: the
//! socket type, whether it listens, its exact local address, and for a Unix socket its directory. The service account
//! is the test's own uid.

#![cfg(target_os = "linux")]

use std::fs;
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::os::fd::AsFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use iron_vault::path_metadata::invoking_user;
use iron_vault::socket_activation::{AdoptError, verify};
use iron_vault::trusted_path::ExpectedOwner;
use iron_vault_policy::{Endpoint, ListenerName};
use rustix::net::{AddressFamily, SocketType};

static NEXT: AtomicU32 = AtomicU32::new(0);

/// A fresh directory at `mode` under the system temp directory, removed on drop. Its path stays short, because a
/// socket path is limited to 108 bytes.
struct Dir(PathBuf);

impl Dir {
    fn new(mode: u32) -> Self {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("iv-act-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(mode)).unwrap();
        Self(dir)
    }

    fn path(&self, file: &str) -> PathBuf {
        self.0.join(file)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn me() -> ExpectedOwner {
    invoking_user().unwrap()
}

fn listener() -> ListenerName {
    ListenerName::try_from("local").unwrap()
}

fn tcp(address: SocketAddr) -> Endpoint {
    Endpoint::Tcp { address, tls: None }
}

fn unix(path: &Path) -> Endpoint {
    Endpoint::UnixSocket(path.to_str().unwrap().parse().unwrap())
}

fn verify_fd(fd: &impl AsFd, endpoint: &Endpoint) -> Result<(), AdoptError> {
    verify(&listener(), fd.as_fd(), endpoint, me())
}

/// The configured and actual addresses an address mismatch names.
fn mismatch(result: Result<(), AdoptError>) -> (String, String) {
    match result {
        Err(AdoptError::AddressMismatch {
            listener: name,
            configured,
            actual,
        }) => {
            assert_eq!(name, listener());
            (configured, actual)
        }
        other => panic!("expected an address mismatch, got {other:?}"),
    }
}

#[test]
fn tcp_listener_on_the_configured_address_is_accepted() {
    let socket = TcpListener::bind("127.0.0.1:0").unwrap();
    assert_eq!(verify_fd(&socket, &tcp(socket.local_addr().unwrap())), Ok(()));
}

#[test]
fn tcp_listener_on_another_port_is_refused() {
    let socket = TcpListener::bind("127.0.0.1:0").unwrap();
    let actual = socket.local_addr().unwrap();
    let configured = SocketAddr::new(actual.ip(), actual.port().wrapping_add(1).max(1));
    let (want, got) = mismatch(verify_fd(&socket, &tcp(configured)));
    assert_eq!((want, got), (format!("TCP {configured}"), format!("TCP {actual}")));
}

#[test]
fn tcp_listener_on_another_ip_is_refused() {
    let socket = TcpListener::bind("127.0.0.1:0").unwrap();
    let configured = SocketAddr::new("127.0.0.2".parse().unwrap(), socket.local_addr().unwrap().port());
    mismatch(verify_fd(&socket, &tcp(configured)));
}

#[test]
fn tcp_listener_on_every_address_is_refused_for_a_loopback_listener() {
    let socket = TcpListener::bind("0.0.0.0:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    let (want, got) = mismatch(verify_fd(&socket, &tcp(SocketAddr::from(([127, 0, 0, 1], port)))));
    assert_eq!((want, got), (format!("TCP 127.0.0.1:{port}"), format!("TCP 0.0.0.0:{port}")));
}

#[test]
fn a_socket_that_is_not_listening_is_refused() {
    let socket = rustix::net::socket(AddressFamily::INET, SocketType::STREAM, None).unwrap();
    rustix::net::bind(&socket, &SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    let address = SocketAddr::try_from(rustix::net::getsockname(&socket).unwrap()).unwrap();
    assert_eq!(
        verify_fd(&socket, &tcp(address)),
        Err(AdoptError::NotListening { listener: listener() })
    );
}

#[test]
fn a_datagram_socket_is_refused() {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    assert_eq!(
        verify_fd(&socket, &tcp(socket.local_addr().unwrap())),
        Err(AdoptError::NotStream { listener: listener() })
    );
}

#[test]
fn a_unix_listener_at_the_configured_path_is_accepted() {
    let dir = Dir::new(0o711);
    let path = dir.path("proxy.sock");
    let socket = UnixListener::bind(&path).unwrap();
    assert_eq!(verify_fd(&socket, &unix(&path)), Ok(()));
}

#[test]
fn a_unix_listener_at_another_path_is_refused() {
    let dir = Dir::new(0o711);
    let socket = UnixListener::bind(dir.path("other.sock")).unwrap();
    let configured = dir.path("proxy.sock");
    let (want, got) = mismatch(verify_fd(&socket, &unix(&configured)));
    assert_eq!(want, format!("Unix socket {}", configured.display()));
    assert_eq!(got, format!("Unix socket {}", dir.path("other.sock").display()));
}

#[test]
fn a_tcp_socket_for_a_unix_listener_is_refused() {
    let dir = Dir::new(0o711);
    let socket = TcpListener::bind("127.0.0.1:0").unwrap();
    mismatch(verify_fd(&socket, &unix(&dir.path("proxy.sock"))));
}

#[test]
fn a_unix_listener_in_a_writable_directory_is_refused() {
    let dir = Dir::new(0o777);
    let path = dir.path("proxy.sock");
    let socket = UnixListener::bind(&path).unwrap();
    let result = verify_fd(&socket, &unix(&path));
    assert!(matches!(result, Err(AdoptError::UntrustedDirectory { .. })), "{result:?}");
}
