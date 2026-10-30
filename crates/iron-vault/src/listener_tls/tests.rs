use std::collections::BTreeMap;

use iron_vault_policy::{Endpoint, ParsedConfig};
use rcgen::{BasicConstraints, Certificate, CertificateParams, DnType, IsCa, Issuer, KeyPair};
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

use super::*;
use crate::trusted_path::{self, ComponentKind, FileId, Mode, PathComponent, Problem, UnsafePath};

const LISTENER: &str = "naomi-backoffice";
const CERTIFICATE_PATH: &str = "/etc/iron-vault/tls/server.crt";
const KEY_PATH: &str = "/etc/iron-vault/tls/server.key";
const SERVER_NAME: &str = "localhost";
const SERVICE_UID: u32 = 997;
const OWNER: ExpectedOwner = ExpectedOwner { uid: SERVICE_UID };

/// A test CA that issues the listener's certificate.
struct TestCa {
    certificate: Certificate,
    issuer: Issuer<'static, KeyPair>,
}

impl TestCa {
    fn new() -> Self {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name.push(DnType::CommonName, "Listener CA");
        let certificate = params.self_signed(&key).unwrap();
        Self {
            certificate,
            issuer: Issuer::new(params, key),
        }
    }

    /// A leaf certificate for [`SERVER_NAME`] and its key.
    fn leaf(&self) -> (Certificate, KeyPair) {
        let key = KeyPair::generate().unwrap();
        let params = CertificateParams::new(vec![SERVER_NAME.to_string()]).unwrap();
        (params.signed_by(&key, &self.issuer).unwrap(), key)
    }

    /// A client config that trusts only this CA and offers HTTP/2 before HTTP/1.1.
    fn client(&self) -> TlsConnector {
        let mut roots = RootCertStore::empty();
        roots.add(self.certificate.der().clone()).unwrap();
        let mut config = ClientConfig::builder_with_provider(tls::provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        TlsConnector::from(Arc::new(config))
    }
}

/// Administrator-installed files on a fake disk: each path's bytes and the leaf's mode. The directories above them
/// are root-owned `0755`, so the trusted-path rule decides on the leaf alone.
struct Disk(BTreeMap<PathBuf, (Mode, Vec<u8>)>);

impl Disk {
    /// A certificate file at `0644` and a key file at `0600`, both owned by the service account.
    fn new(chain: &str, key: &str) -> Self {
        Self(BTreeMap::from([
            (PathBuf::from(CERTIFICATE_PATH), (Mode::new(0o644), chain.as_bytes().to_vec())),
            (PathBuf::from(KEY_PATH), (Mode::new(0o600), key.as_bytes().to_vec())),
        ]))
    }

    fn with_key_mode(mut self, mode: u32) -> Self {
        if let Some(entry) = self.0.get_mut(Path::new(KEY_PATH)) {
            entry.0 = Mode::new(mode);
        }
        self
    }

    /// Checks `path` against `file`'s trusted-path rule, as `admin_file::read` does, then returns its bytes.
    fn read(&self, file: AdminFile, path: &Path) -> Result<Zeroizing<Vec<u8>>, AdminFileError> {
        let (mode, bytes) = self.0.get(path).unwrap();
        trusted_path::check(file.rule(), DeploymentProfile::Protected, OWNER, &components(path, *mode))?;
        Ok(Zeroizing::new(bytes.clone()))
    }

    fn open(&self, timeout: Duration) -> Result<ListenerTls, ListenerTlsError> {
        ListenerTls::open_with(&listener(), &tls_files(), timeout, |file, path| self.read(file, path))
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
        .chain([component(path, SERVICE_UID, mode, ComponentKind::RegularFile)])
        .collect()
}

fn listener() -> ListenerName {
    ListenerName::try_from(LISTENER).unwrap()
}

/// The listener's `TlsFiles`, taken from a parsed config section as the service would.
fn tls_files() -> TlsFiles {
    tls_files_at(CERTIFICATE_PATH, KEY_PATH)
}

/// The listener's `TlsFiles` naming `certificate` and `key`.
fn tls_files_at(certificate: &str, key: &str) -> TlsFiles {
    let toml = format!(
        "schema_version = 1\n[listeners.{LISTENER}]\naddress = \"10.20.0.2:7878\"\n\
         tls_certificate = \"{certificate}\"\ntls_key = \"{key}\"\n"
    );
    let config = ParsedConfig::from_toml(toml.as_bytes()).unwrap();
    match config.listeners().values().next().unwrap().endpoint() {
        Endpoint::Tcp { tls: Some(files), .. } => files.clone(),
        other => panic!("expected a TLS listener, got {other:?}"),
    }
}

/// A CA and a listener whose files hold the CA's leaf and its key.
fn working_listener(timeout: Duration) -> (TestCa, ListenerTls) {
    let ca = TestCa::new();
    let (leaf, key) = ca.leaf();
    let tls = Disk::new(&leaf.pem(), &key.serialize_pem()).open(timeout).unwrap();
    (ca, tls)
}

/// A fresh directory directly under `/tmp`, a shared sticky directory, removed on drop.
struct TmpDir(PathBuf);

impl TmpDir {
    fn new() -> Self {
        let dir = PathBuf::from(format!("/tmp/iv-listener-tls-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        Self(dir)
    }

    /// Writes `contents` to a new file in the directory and returns its path.
    fn file(&self, name: &str, contents: &str) -> String {
        let path = self.0.join(name);
        std::fs::write(&path, contents).unwrap();
        path.to_str().unwrap().to_string()
    }
}

impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn certificate_path() -> PathBuf {
    PathBuf::from(CERTIFICATE_PATH)
}

fn key_path() -> PathBuf {
    PathBuf::from(KEY_PATH)
}

mod loading {
    use super::*;

    fn open(chain: &str, key: &str) -> Result<ListenerTls, ListenerTlsError> {
        Disk::new(chain, key).open(DEFAULT_HANDSHAKE_TIMEOUT)
    }

    #[test]
    fn a_leaf_with_its_chain_and_key_loads() {
        let ca = TestCa::new();
        let (leaf, key) = ca.leaf();
        let chain = format!("{}{}", leaf.pem(), ca.certificate.pem());
        assert!(open(&chain, &key.serialize_pem()).is_ok());
    }

    #[test]
    fn a_key_that_does_not_match_the_certificate_is_refused() {
        let ca = TestCa::new();
        let (leaf, _) = ca.leaf();
        let (_, other_key) = ca.leaf();
        assert_eq!(
            open(&leaf.pem(), &other_key.serialize_pem()).unwrap_err(),
            ListenerTlsError::KeyMismatch {
                listener: listener(),
                certificate: certificate_path(),
                key: key_path(),
            }
        );
    }

    #[test]
    fn a_key_matching_a_later_certificate_but_not_the_leaf_is_refused() {
        let ca = TestCa::new();
        let (leaf, _) = ca.leaf();
        let (second, second_key) = ca.leaf();
        let chain = format!("{}{}", leaf.pem(), second.pem());
        assert!(matches!(
            open(&chain, &second_key.serialize_pem()).unwrap_err(),
            ListenerTlsError::KeyMismatch { .. }
        ));
    }

    #[test]
    fn a_key_file_with_two_keys_is_refused() {
        let ca = TestCa::new();
        let (leaf, key) = ca.leaf();
        let keys = format!("{}{}", key.serialize_pem(), ca.leaf().1.serialize_pem());
        assert_eq!(
            open(&leaf.pem(), &keys).unwrap_err(),
            ListenerTlsError::NotOneKey {
                listener: listener(),
                path: key_path(),
            }
        );
    }

    #[test]
    fn a_key_file_with_a_hidden_second_key_is_refused() {
        let ca = TestCa::new();
        let (leaf, key) = ca.leaf();
        let keys = format!(
            "{}  -----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
            key.serialize_pem()
        );
        assert!(matches!(open(&leaf.pem(), &keys).unwrap_err(), ListenerTlsError::NotOneKey { .. }));
    }

    #[test]
    fn a_key_file_with_a_certificate_beside_the_key_is_refused() {
        let ca = TestCa::new();
        let (leaf, key) = ca.leaf();
        let pem = format!("{}{}", leaf.pem(), key.serialize_pem());
        assert!(matches!(open(&leaf.pem(), &pem).unwrap_err(), ListenerTlsError::NotOneKey { .. }));
    }

    #[test]
    fn an_empty_key_file_is_refused() {
        let (leaf, _) = TestCa::new().leaf();
        assert!(matches!(open(&leaf.pem(), "").unwrap_err(), ListenerTlsError::NotOneKey { .. }));
    }

    #[test]
    fn a_key_whose_base64_does_not_decode_is_refused() {
        let (leaf, _) = TestCa::new().leaf();
        let key = "-----BEGIN PRIVATE KEY-----\n!!!!\n-----END PRIVATE KEY-----\n";
        assert_eq!(
            open(&leaf.pem(), key).unwrap_err(),
            ListenerTlsError::MalformedPem {
                listener: listener(),
                path: key_path(),
            }
        );
    }

    #[test]
    fn a_key_the_provider_cannot_use_is_refused() {
        let (leaf, _) = TestCa::new().leaf();
        let key = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n";
        assert!(matches!(open(&leaf.pem(), key).unwrap_err(), ListenerTlsError::UnusableKey { .. }));
    }

    #[test]
    fn a_certificate_file_that_holds_a_key_is_refused() {
        let ca = TestCa::new();
        let (leaf, key) = ca.leaf();
        let chain = format!("{}{}", leaf.pem(), key.serialize_pem());
        let refused = open(&chain, &key.serialize_pem()).unwrap_err();
        assert_eq!(
            refused,
            ListenerTlsError::NotOnlyCertificates {
                listener: listener(),
                path: certificate_path(),
            }
        );
    }

    #[test]
    fn an_empty_certificate_file_is_refused() {
        let (_, key) = TestCa::new().leaf();
        assert!(matches!(
            open("", &key.serialize_pem()).unwrap_err(),
            ListenerTlsError::NoCertificates { .. }
        ));
    }

    #[test]
    fn a_key_file_readable_by_others_is_refused_by_its_trusted_path_rule() {
        let ca = TestCa::new();
        let (leaf, key) = ca.leaf();
        let refused = Disk::new(&leaf.pem(), &key.serialize_pem())
            .with_key_mode(0o644)
            .open(DEFAULT_HANDSHAKE_TIMEOUT)
            .unwrap_err();
        let ListenerTlsError::Unreadable {
            listener: named,
            source: AdminFileError::Unsafe(UnsafePath { path, problem }),
        } = refused
        else {
            panic!("expected an unsafe key path, got {refused:?}");
        };
        assert_eq!((named, path), (listener(), key_path()));
        assert!(matches!(problem, Problem::ExposedPrivateKey { .. }), "{problem:?}");
    }

    #[test]
    fn open_reads_the_files_through_their_trusted_path_rules() {
        let ca = TestCa::new();
        let (leaf, key) = ca.leaf();
        let dir = TmpDir::new();
        let (certificate, key) = (dir.file("server.crt", &leaf.pem()), dir.file("server.key", &key.serialize_pem()));
        let refused = ListenerTls::open(
            &listener(),
            &tls_files_at(&certificate, &key),
            DeploymentProfile::Protected,
            ExpectedOwner {
                uid: rustix::process::getuid().as_raw(),
            },
            DEFAULT_HANDSHAKE_TIMEOUT,
        )
        .unwrap_err();
        let ListenerTlsError::Unreadable {
            source: AdminFileError::Unsafe(UnsafePath { path, problem }),
            ..
        } = refused
        else {
            panic!("expected an unsafe certificate path, got {refused:?}");
        };
        assert_eq!((path, problem), (PathBuf::from("/tmp"), Problem::SharedStickyAncestor));
    }

    #[test]
    fn errors_name_the_listener_and_path_and_never_the_contents() {
        let ca = TestCa::new();
        let (leaf, key) = ca.leaf();
        let key_pem = key.serialize_pem();
        let key_body = key_pem.lines().nth(1).unwrap().to_string();
        let refusals = [
            open(&format!("{}{key_pem}", leaf.pem()), &key_pem),
            open(&leaf.pem(), &format!("{key_pem}{key_pem}")),
            open(&leaf.pem(), &ca.leaf().1.serialize_pem()),
        ];
        refusals
            .into_iter()
            .map(|refused| refused.unwrap_err().to_string())
            .for_each(|message| {
                assert!(message.contains(LISTENER), "{message}");
                assert!(message.contains(CERTIFICATE_PATH) || message.contains(KEY_PATH), "{message}");
                assert!(!message.contains(&key_body), "{message}");
            });
    }

    #[test]
    fn debug_shows_no_key() {
        let ca = TestCa::new();
        let (leaf, key) = ca.leaf();
        let key_pem = key.serialize_pem();
        let key_body = key_pem.lines().nth(1).unwrap();
        let tls = Disk::new(&leaf.pem(), &key_pem).open(DEFAULT_HANDSHAKE_TIMEOUT).unwrap();
        let shown = format!("{tls:?}");
        assert!(shown.contains(LISTENER) && !shown.contains(key_body), "{shown}");
    }
}

mod server_config {
    use super::*;

    fn config() -> Arc<ServerConfig> {
        let (_, tls) = working_listener(DEFAULT_HANDSHAKE_TIMEOUT);
        Arc::clone(tls.acceptor.config())
    }

    #[test]
    fn it_offers_only_http_1_1() {
        assert_eq!(config().alpn_protocols, vec![b"http/1.1".to_vec()]);
    }

    #[test]
    fn it_logs_no_session_keys() {
        assert!(!config().key_log.will_log("CLIENT_RANDOM"));
    }

    #[test]
    fn it_installs_no_process_wide_crypto_provider() {
        config();
        assert!(CryptoProvider::get_default().is_none());
    }
}

mod handshake {
    use super::*;

    const SHORT_TIMEOUT: Duration = Duration::from_millis(100);

    /// Accepts one TCP connection, completes the TLS handshake and echoes what the client sends until it closes.
    async fn echo_once(server: TcpListener, tls: ListenerTls) {
        let (tcp, _) = server.accept().await.unwrap();
        let mut stream = tls.accept(tcp).await.unwrap();
        let mut received = [0; 64];
        let n = stream.read(&mut received).await.unwrap();
        stream.write_all(&received[..n]).await.unwrap();
        stream.shutdown().await.unwrap();
    }

    /// Reads from `client` until the server closes it or the read fails, as a client seeing a reset would.
    async fn read_until_closed(client: &mut DuplexStream) -> Vec<u8> {
        let mut received = Vec::new();
        let _ = client.read_to_end(&mut received).await;
        received
    }

    #[tokio::test]
    async fn a_client_trusting_the_ca_completes_a_handshake_and_exchanges_bytes() {
        let (ca, tls) = working_listener(DEFAULT_HANDSHAKE_TIMEOUT);
        let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let echo = tokio::spawn(echo_once(server, tls));

        let tcp = TcpStream::connect(address).await.unwrap();
        let name = ServerName::try_from(SERVER_NAME).unwrap();
        let mut client = ca.client().connect(name, tcp).await.unwrap();
        assert_eq!(client.get_ref().1.alpn_protocol(), Some(&b"http/1.1"[..]));
        client.write_all(b"ping").await.unwrap();
        let mut echoed = Vec::new();
        client.read_to_end(&mut echoed).await.unwrap();
        assert_eq!(echoed, b"ping");
        echo.await.unwrap();
    }

    #[tokio::test]
    async fn the_server_asks_for_no_client_certificate() {
        let (ca, tls) = working_listener(DEFAULT_HANDSHAKE_TIMEOUT);
        let (leaf, key) = ca.leaf();
        let key = PrivateKeyDer::from_pem_slice(key.serialize_pem().as_bytes()).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(ca.certificate.der().clone()).unwrap();
        // A client holding a certificate presents it only when the server asks for one.
        let config = ClientConfig::builder_with_provider(tls::provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_client_auth_cert(vec![leaf.der().clone()], key)
            .unwrap();
        let (client, server) = tokio::io::duplex(16 * 1024);
        let name = ServerName::try_from(SERVER_NAME).unwrap();
        let (client, server) = tokio::join!(TlsConnector::from(Arc::new(config)).connect(name, client), tls.accept(server));
        client.unwrap();
        assert!(server.unwrap().get_ref().1.peer_certificates().is_none());
    }

    #[tokio::test]
    async fn a_client_that_sends_nothing_is_dropped_after_the_handshake_timeout() {
        let (_, tls) = working_listener(SHORT_TIMEOUT);
        let (mut client, server) = tokio::io::duplex(4096);
        assert_eq!(
            tls.accept(server).await.unwrap_err(),
            HandshakeError::TimedOut {
                listener: listener(),
                timeout: SHORT_TIMEOUT,
            }
        );
        assert!(read_until_closed(&mut client).await.is_empty());
    }

    #[tokio::test]
    async fn a_plain_http_request_gets_no_http_response() {
        let (_, tls) = working_listener(DEFAULT_HANDSHAKE_TIMEOUT);
        let (mut client, server) = tokio::io::duplex(4096);
        client.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
        let refused = tls.accept(server).await.unwrap_err();
        assert!(matches!(refused, HandshakeError::Failed { .. }), "{refused:?}");
        let received = read_until_closed(&mut client).await;
        // Nothing, or a TLS alert record (content type 21), but never an HTTP status line.
        assert!(received.first().is_none_or(|&content_type| content_type == 21), "{received:?}");
    }
}
