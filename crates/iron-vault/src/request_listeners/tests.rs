//! Request listeners on real sockets, as the unprivileged test user, which is also the service account.
//!
//! Unix sockets live in a fresh `0711` directory under the system temp directory, which the runtime-directory rule
//! accepts. A TLS listener's certificate and key cannot: their rules refuse a shared sticky ancestor such as `/tmp`,
//! and the worktree's own ancestors are group-writable. So the TLS files come from a fake disk that runs the real
//! trusted-path check on each file's mode, with root-owned `0755` directories above it.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering as AtomicOrdering};

use iron_vault_policy::ParsedConfig;
use rcgen::{BasicConstraints, Certificate, CertificateParams, DnType, IsCa, Issuer, KeyPair};
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};
use tokio_rustls::TlsConnector;

use super::*;
use crate::deployment::DeploymentProfile;
use crate::path_metadata::invoking_user;
use crate::trusted_path::{self, ComponentKind, ExpectedOwner, FileId, Mode, PathComponent};

const CERTIFICATE_PATH: &str = "/etc/iron-vault/tls/server.crt";
const KEY_PATH: &str = "/etc/iron-vault/tls/server.key";
const WAIT: Duration = Duration::from_secs(5);

static NEXT: AtomicU32 = AtomicU32::new(0);

/// A fresh runtime directory at `0711`, removed on drop. Its path stays short: a socket path is limited to 108 bytes.
struct RuntimeDir(PathBuf);

impl RuntimeDir {
    fn new() -> Self {
        let n = NEXT.fetch_add(1, AtomicOrdering::Relaxed);
        let dir = std::env::temp_dir().join(format!("iv-rl-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o711)).unwrap();
        Self(dir)
    }

    fn socket(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    fn paths(&self, profile: DeploymentProfile) -> ServicePaths {
        ServicePaths {
            profile,
            owner: me(),
            config: self.0.join("config.toml"),
            state_dir: self.0.join("state"),
            runtime_dir: Some(self.0.clone()),
        }
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

fn name(s: &str) -> ListenerName {
    ListenerName::try_from(s).unwrap()
}

/// A loopback address with a port nothing is listening on.
fn free_address() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap()
}

/// A test CA, its leaf certificate for `localhost` and the leaf's key.
struct TestCa {
    certificate: Certificate,
    leaf: Certificate,
    key: KeyPair,
}

impl TestCa {
    fn new() -> Self {
        let ca_key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name.push(DnType::CommonName, "Listener CA");
        let certificate = params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::new(params, ca_key);
        let key = KeyPair::generate().unwrap();
        let leaf = CertificateParams::new(vec!["localhost".to_string()])
            .unwrap()
            .signed_by(&key, &issuer)
            .unwrap();
        Self { certificate, leaf, key }
    }

    /// A client that trusts only this CA.
    fn client(&self) -> TlsConnector {
        let mut roots = RootCertStore::empty();
        roots.add(self.certificate.der().clone()).unwrap();
        let config = ClientConfig::builder_with_provider(crate::tls::provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        TlsConnector::from(Arc::new(config))
    }

    /// The fake disk holding the leaf at `0644` and its key at `key_mode`, both the service account's.
    fn disk(&self, key_mode: u32) -> BTreeMap<PathBuf, (Mode, Vec<u8>)> {
        BTreeMap::from([
            (PathBuf::from(CERTIFICATE_PATH), (Mode::new(0o644), self.leaf.pem().into_bytes())),
            (
                PathBuf::from(KEY_PATH),
                (Mode::new(key_mode), self.key.serialize_pem().into_bytes()),
            ),
        ])
    }
}

/// Reads `path` from `disk` after checking it against `file`'s trusted-path rule, as `admin_file::read` does.
fn read_from(
    disk: &BTreeMap<PathBuf, (Mode, Vec<u8>)>,
    profile: DeploymentProfile,
) -> impl Fn(AdminFile, &Path) -> Result<Zeroizing<Vec<u8>>, AdminFileError> + '_ {
    move |file, path| {
        let (mode, bytes) = disk.get(path).unwrap();
        trusted_path::check(file.rule(), profile, me(), &components(path, *mode))?;
        Ok(Zeroizing::new(bytes.clone()))
    }
}

/// The path's components from `/` down: root-owned `0755` directories, then a regular file the service account owns.
fn components(path: &Path, mode: Mode) -> Vec<PathComponent> {
    let component = |path: &Path, uid, mode, kind| PathComponent {
        path: path.to_path_buf(),
        uid,
        owner_name: None,
        gid: uid,
        group_name: None,
        mode,
        kind,
        id: FileId { dev: 1, ino: 1 },
    };
    let mut ancestors: Vec<_> = path.ancestors().skip(1).collect();
    ancestors.reverse();
    ancestors
        .into_iter()
        .map(|dir| component(dir, 0, Mode::new(0o755), ComponentKind::Directory))
        .chain([component(path, me().uid, mode, ComponentKind::RegularFile)])
        .collect()
}

/// Three listeners, in name order: a Unix socket, plain loopback TCP and TLS on loopback.
struct ThreeListeners {
    dir: RuntimeDir,
    tcp: SocketAddr,
    tls: SocketAddr,
    config: BTreeMap<ListenerName, ListenerConfig>,
}

impl ThreeListeners {
    fn new() -> Self {
        let dir = RuntimeDir::new();
        let (tcp, tls) = (free_address(), free_address());
        let toml = format!(
            "schema_version = 1\n\
             [listeners.a-unix]\nunix_socket = \"{}\"\n\
             [listeners.b-tcp]\naddress = \"{tcp}\"\n\
             [listeners.c-tls]\naddress = \"{tls}\"\ntls_certificate = \"{CERTIFICATE_PATH}\"\ntls_key = \"{KEY_PATH}\"\n",
            dir.socket("proxy.sock").display()
        );
        let config = ParsedConfig::from_toml(toml.as_bytes()).unwrap().listeners().clone();
        Self { dir, tcp, tls, config }
    }

    fn open(&self, ca: &TestCa, key_mode: u32) -> Result<RequestListeners, OpenError> {
        let profile = DeploymentProfile::Development;
        let disk = ca.disk(key_mode);
        RequestListeners::open_with(&self.config, &self.dir.paths(profile), BTreeMap::new(), read_from(&disk, profile))
    }

    fn unix_path(&self) -> PathBuf {
        self.dir.socket("proxy.sock")
    }
}

async fn accept(listeners: &RequestListeners) -> IncomingConnection {
    tokio::time::timeout(WAIT, listeners.accept())
        .await
        .expect("a connection is accepted")
}

/// Sends `ping` from the client and checks it arrives on the established stream, then echoes `pong` back.
async fn exchange(server: &mut RequestStream, client: &mut (impl AsyncRead + AsyncWrite + Unpin)) {
    client.write_all(b"ping").await.unwrap();
    let mut received = [0; 4];
    server.read_exact(&mut received).await.unwrap();
    assert_eq!(&received, b"ping");
    server.write_all(b"pong").await.unwrap();
    server.flush().await.unwrap();
    client.read_exact(&mut received).await.unwrap();
    assert_eq!(&received, b"pong");
}

#[tokio::test]
async fn each_connection_is_tagged_with_its_listener_and_only_unix_ones_with_a_peer() {
    let setup = ThreeListeners::new();
    let ca = TestCa::new();
    let listeners = setup.open(&ca, 0o600).unwrap();

    let mut unix_client = UnixStream::connect(setup.unix_path()).await.unwrap();
    let unix = accept(&listeners).await;
    assert_eq!(unix.listener(), &name("a-unix"));
    assert_eq!(unix.peer().map(|peer| peer.uid()), Some(rustix::process::getuid().as_raw()));
    exchange(&mut unix.establish().await.unwrap(), &mut unix_client).await;

    let mut tcp_client = TcpStream::connect(setup.tcp).await.unwrap();
    let tcp = accept(&listeners).await;
    assert_eq!(tcp.listener(), &name("b-tcp"));
    assert_eq!(tcp.peer(), None);
    exchange(&mut tcp.establish().await.unwrap(), &mut tcp_client).await;

    let raw = TcpStream::connect(setup.tls).await.unwrap();
    let handshake = tokio::spawn(async move { ca.client().connect(ServerName::try_from("localhost").unwrap(), raw).await });
    let tls = accept(&listeners).await;
    assert_eq!(tls.listener(), &name("c-tls"));
    assert_eq!(tls.peer(), None);
    let mut server = tls.establish().await.unwrap();
    assert!(matches!(server, RequestStream::Tls(_)), "{server:?}");
    let mut tls_client = handshake.await.unwrap().unwrap();
    exchange(&mut server, &mut tls_client).await;
}

#[tokio::test]
async fn a_stalled_tls_client_does_not_hold_up_a_unix_connection() {
    let setup = ThreeListeners::new();
    let listeners = setup.open(&TestCa::new(), 0o600).unwrap();

    let _stalled = TcpStream::connect(setup.tls).await.unwrap();
    let tls = accept(&listeners).await;
    assert_eq!(tls.listener(), &name("c-tls"));
    let handshake = tokio::spawn(tls.establish());

    let _client = UnixStream::connect(setup.unix_path()).await.unwrap();
    let unix = accept(&listeners).await;
    assert_eq!(unix.listener(), &name("a-unix"));
    let established = tokio::time::timeout(WAIT, unix.establish()).await.unwrap().unwrap();
    assert!(matches!(established, RequestStream::Unix(_)), "{established:?}");
    assert!(!handshake.is_finished(), "the stalled client's handshake finished");
    handshake.abort();
}

#[tokio::test]
async fn when_the_third_listener_fails_the_ones_already_open_are_closed() {
    let setup = ThreeListeners::new();
    let refused = setup.open(&TestCa::new(), 0o644).unwrap_err();
    let OpenError::Tls(ListenerTlsError::Unreadable { listener, .. }) = &refused else {
        panic!("expected an unreadable key, got {refused:?}");
    };
    assert_eq!(listener, &name("c-tls"));
    assert!(refused.to_string().contains("c-tls"), "{refused}");
    assert!(
        fs::symlink_metadata(setup.unix_path()).is_err(),
        "the Unix socket file was left behind"
    );
    std::net::TcpListener::bind(setup.tcp).expect("the TCP listener's port is free again");
}

#[tokio::test]
async fn dropping_the_listeners_removes_the_socket_files_they_bound() {
    let setup = ThreeListeners::new();
    let listeners = setup.open(&TestCa::new(), 0o600).unwrap();
    assert!(fs::symlink_metadata(setup.unix_path()).is_ok());
    drop(listeners);
    assert!(
        fs::symlink_metadata(setup.unix_path()).is_err(),
        "the Unix socket file was left behind"
    );
}

/// A Unix and a TCP listener as systemd would pass them, in a protected install.
struct Activated {
    dir: RuntimeDir,
    tcp: SocketAddr,
    config: BTreeMap<ListenerName, ListenerConfig>,
    sockets: BTreeMap<ListenerName, AdoptedSocket>,
}

impl Activated {
    fn new() -> Self {
        let dir = RuntimeDir::new();
        let tcp_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let tcp = tcp_listener.local_addr().unwrap();
        let unix_listener = std::os::unix::net::UnixListener::bind(dir.socket("activated.sock")).unwrap();
        let toml = format!(
            "schema_version = 1\n[listeners.local]\nunix_socket = \"{}\"\n[listeners.loopback]\naddress = \"{tcp}\"\n",
            dir.socket("activated.sock").display()
        );
        let config = ParsedConfig::from_toml(toml.as_bytes()).unwrap().listeners().clone();
        let sockets = BTreeMap::from([
            (name("local"), AdoptedSocket::Unix(unix_listener)),
            (name("loopback"), AdoptedSocket::Tcp(tcp_listener)),
        ]);
        Self { dir, tcp, config, sockets }
    }
}

#[tokio::test]
async fn activated_sockets_are_served_and_their_files_left_for_systemd() {
    let Activated { dir, tcp, config, sockets } = Activated::new();
    let listeners = RequestListeners::open(&config, &dir.paths(DeploymentProfile::Protected), sockets).unwrap();

    let _unix_client = UnixStream::connect(dir.socket("activated.sock")).await.unwrap();
    let unix = accept(&listeners).await;
    assert_eq!(unix.listener(), &name("local"));
    assert!(unix.peer().is_some());
    let _tcp_client = TcpStream::connect(tcp).await.unwrap();
    assert_eq!(accept(&listeners).await.listener(), &name("loopback"));

    drop(listeners);
    assert!(
        fs::symlink_metadata(dir.socket("activated.sock")).is_ok(),
        "systemd's socket file was removed"
    );
}

#[tokio::test]
async fn a_protected_install_refuses_to_bind_tcp_itself_and_closes_what_it_opened() {
    let Activated { dir, config, .. } = Activated::new();
    fs::remove_file(dir.socket("activated.sock")).unwrap();
    let refused = RequestListeners::open(&config, &dir.paths(DeploymentProfile::Protected), BTreeMap::new()).unwrap_err();
    assert_eq!(
        refused,
        OpenError::NotActivated(NotActivated {
            listener: name("loopback")
        })
    );
    assert!(
        fs::symlink_metadata(dir.socket("activated.sock")).is_err(),
        "the Unix socket file was left behind"
    );
}

#[test]
fn opening_outside_the_runtime_is_an_error() {
    let dir = RuntimeDir::new();
    let refused = RequestListeners::open(&BTreeMap::new(), &dir.paths(DeploymentProfile::Development), BTreeMap::new());
    assert_eq!(refused.unwrap_err(), OpenError::NoRuntime);
}
