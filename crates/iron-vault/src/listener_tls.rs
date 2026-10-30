//! TLS listeners (specification §3.4, R-26): a TCP listener that terminates TLS with the certificate chain and private
//! key the administrator installed for it, so a network observer can neither read caller tokens and request bodies
//! nor change them.
//!
//! Both files are read through their trusted-path rules when the listener is opened, and the key must match the leaf
//! certificate then, so a broken pair stops the listener opening rather than failing its first handshake. Certificate
//! rotation therefore takes effect when the listeners are next opened, at restart or reload; nothing watches the
//! files.
//!
//! The listener uses the same rustls build and crypto provider as the outbound client ([`crate::tls`]), so the
//! service carries one TLS stack.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use iron_vault_policy::{ListenerName, TlsFiles};
use rustls::crypto::CryptoProvider;
use rustls::sign::{CertifiedKey, SingleCertAndKey};
use rustls::{InconsistentKeys, ServerConfig};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use zeroize::Zeroizing;

use crate::admin_file::{self, AdminFile, AdminFileError};
use crate::deployment::DeploymentProfile;
use crate::tls::{self, CertificatePemError};
use crate::trusted_path::ExpectedOwner;

/// How long a client has to finish the TLS handshake before its connection is dropped.
///
/// A placeholder until specification §9 publishes the listener limits: long enough for a slow network, short enough
/// that silent connections cannot pile up.
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// The only application protocol offered. HTTP/2 is added if the request interface comes to serve it.
const ALPN_HTTP_1_1: &[u8] = b"http/1.1";

/// The start lines of the private-key items a key file may hold: PKCS#8, SEC1 and PKCS#1.
const KEY_BEGINS: [&[u8]; 3] = [
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
];

/// A TLS listener's acceptor: its certificate, key and server config, and its handshake timeout.
pub struct ListenerTls {
    listener: ListenerName,
    acceptor: TlsAcceptor,
    handshake_timeout: Duration,
}

/// Why a TLS listener's certificate and key were not loaded. Every variant names the listener and the file, never
/// the file's contents.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum ListenerTlsError {
    /// A file failed its trusted-path rule or could not be read; the inner error names the path.
    #[error("listener {listener}: {source}")]
    Unreadable {
        /// The listener being opened.
        listener: ListenerName,
        /// Why the file was not read.
        source: AdminFileError,
    },
    /// A PEM item is cut short, its base64 does not decode, or the decoder skipped one.
    #[error("listener {listener}: {path} is not a well-formed PEM file")]
    MalformedPem {
        /// The listener being opened.
        listener: ListenerName,
        /// The file's path.
        path: PathBuf,
    },
    /// The certificate file holds a PEM item that is not a certificate, such as a private key.
    #[error("listener {listener}: certificate file {path} holds a PEM item other than CERTIFICATE; keep the key in its own file")]
    NotOnlyCertificates {
        /// The listener being opened.
        listener: ListenerName,
        /// The file's path.
        path: PathBuf,
    },
    /// The certificate file holds no certificate.
    #[error("listener {listener}: certificate file {path} holds no CERTIFICATE item")]
    NoCertificates {
        /// The listener being opened.
        listener: ListenerName,
        /// The file's path.
        path: PathBuf,
    },
    /// The key file holds no private key, more than one, or another PEM item beside it.
    #[error("listener {listener}: key file {path} must hold exactly one private key (PKCS#8, SEC1 or PKCS#1) and nothing else")]
    NotOneKey {
        /// The listener being opened.
        listener: ListenerName,
        /// The file's path.
        path: PathBuf,
    },
    /// The key is not one the TLS provider can sign with.
    #[error("listener {listener}: the key in {path} is not an RSA, ECDSA or Ed25519 key the TLS provider can use")]
    UnusableKey {
        /// The listener being opened.
        listener: ListenerName,
        /// The file's path.
        path: PathBuf,
    },
    /// The key is not the leaf certificate's key.
    #[error("listener {listener}: the key in {key} does not match the first certificate in {certificate}")]
    KeyMismatch {
        /// The listener being opened.
        listener: ListenerName,
        /// The certificate file's path.
        certificate: PathBuf,
        /// The key file's path.
        key: PathBuf,
    },
    /// The leaf certificate does not parse, or the key cannot report its public half, so the pair cannot be checked.
    #[error("listener {listener}: cannot check that the key in {key} matches the first certificate in {certificate}")]
    KeyNotChecked {
        /// The listener being opened.
        listener: ListenerName,
        /// The certificate file's path.
        certificate: PathBuf,
        /// The key file's path.
        key: PathBuf,
    },
    /// The crypto provider cannot serve rustls's default protocol versions.
    #[error("listener {listener}: the TLS crypto provider cannot serve the default protocol versions: {source}")]
    ProtocolVersions {
        /// The listener being opened.
        listener: ListenerName,
        /// The rustls error.
        source: rustls::Error,
    },
}

/// Why a connection's TLS handshake did not complete. The connection has been dropped.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HandshakeError {
    /// The client did not finish the handshake in time.
    #[error("listener {listener}: TLS handshake not finished within {timeout:?}")]
    TimedOut {
        /// The listener the connection arrived on.
        listener: ListenerName,
        /// The handshake timeout.
        timeout: Duration,
    },
    /// The handshake failed, for instance because the client does not speak TLS. Only the error's kind is kept, so
    /// nothing the client sent reaches a log.
    #[error("listener {listener}: TLS handshake failed: {kind}")]
    Failed {
        /// The listener the connection arrived on.
        listener: ListenerName,
        /// The kind of the I/O error the handshake ended with.
        kind: io::ErrorKind,
    },
}

impl ListenerTls {
    /// Reads `listener`'s certificate chain and key through their trusted-path rules and builds its acceptor.
    ///
    /// The chain must hold one or more `CERTIFICATE` PEM items and nothing else, its first being the leaf; the key
    /// file exactly one private key, matching the leaf.
    pub fn open(
        listener: &ListenerName,
        files: &TlsFiles,
        profile: DeploymentProfile,
        owner: ExpectedOwner,
        handshake_timeout: Duration,
    ) -> Result<Self, ListenerTlsError> {
        Self::open_with(listener, files, handshake_timeout, |file, path| {
            admin_file::read(file, profile, owner, path)
        })
    }

    /// [`open`](Self::open) with the file reader passed in, so loading is testable without trusted paths on disk.
    pub(crate) fn open_with(
        listener: &ListenerName,
        files: &TlsFiles,
        handshake_timeout: Duration,
        read: impl Fn(AdminFile, &Path) -> Result<Zeroizing<Vec<u8>>, AdminFileError>,
    ) -> Result<Self, ListenerTlsError> {
        let source = Source {
            listener,
            certificate: files.certificate().as_path(),
            key: files.key().as_path(),
        };
        let chain_pem = read(AdminFile::Certificate, source.certificate).map_err(|e| source.unreadable(e))?;
        let chain = source.chain(&chain_pem)?;
        let key_pem = read(AdminFile::PrivateKey, source.key).map_err(|e| source.unreadable(e))?;
        let provider = tls::provider();
        let certified = source.certified_key(&provider, chain, source.private_key(&key_pem)?)?;
        let config = server_config(provider, certified).map_err(|e| ListenerTlsError::ProtocolVersions {
            listener: listener.clone(),
            source: e,
        })?;
        Ok(Self {
            listener: listener.clone(),
            acceptor: TlsAcceptor::from(Arc::new(config)),
            handshake_timeout,
        })
    }

    /// Runs the TLS handshake on an accepted connection. A client that does not finish it within the handshake
    /// timeout, or fails it, is dropped with its connection.
    pub async fn accept<S>(&self, stream: S) -> Result<TlsStream<S>, HandshakeError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        match tokio::time::timeout(self.handshake_timeout, self.acceptor.accept(stream)).await {
            Ok(Ok(stream)) => Ok(stream),
            Ok(Err(e)) => Err(HandshakeError::Failed {
                listener: self.listener.clone(),
                kind: e.kind(),
            }),
            Err(_) => Err(HandshakeError::TimedOut {
                listener: self.listener.clone(),
                timeout: self.handshake_timeout,
            }),
        }
    }
}

// The server config holds the signing key, so only the listener and timeout are shown.
impl fmt::Debug for ListenerTls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ListenerTls")
            .field("listener", &self.listener)
            .field("handshake_timeout", &self.handshake_timeout)
            .finish_non_exhaustive()
    }
}

/// The listener and file paths a load error names.
struct Source<'a> {
    listener: &'a ListenerName,
    certificate: &'a Path,
    key: &'a Path,
}

impl Source<'_> {
    /// Decodes the certificate chain.
    fn chain(&self, pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, ListenerTlsError> {
        let (listener, path) = (self.listener.clone(), self.certificate.to_path_buf());
        tls::certificates(pem).map_err(|e| match e {
            CertificatePemError::Malformed => ListenerTlsError::MalformedPem { listener, path },
            CertificatePemError::NotOnlyCertificates => ListenerTlsError::NotOnlyCertificates { listener, path },
            CertificatePemError::NoCertificates => ListenerTlsError::NoCertificates { listener, path },
        })
    }

    /// Decodes the key file's one private key. Its PEM items are counted and labelled before anything is decoded, so
    /// a second key or a certificate beside it is refused without decoding either.
    fn private_key(&self, pem: &[u8]) -> Result<PrivateKeyDer<'static>, ListenerTlsError> {
        match tls::item_starts(pem).as_slice() {
            [start] if KEY_BEGINS.contains(&start.trim_ascii()) => {
                PrivateKeyDer::from_pem_slice(pem).map_err(|_| ListenerTlsError::MalformedPem {
                    listener: self.listener.clone(),
                    path: self.key.to_path_buf(),
                })
            }
            _ => Err(ListenerTlsError::NotOneKey {
                listener: self.listener.clone(),
                path: self.key.to_path_buf(),
            }),
        }
    }

    /// Loads the key into the provider's signing key and checks it against the leaf certificate.
    ///
    /// The key is moved into the provider because ring's key provider wraps the `PrivateKeyDer` it receives in
    /// `Zeroizing`, so that buffer is wiped once loading returns; `PrivateKeyDer` does not wipe itself on drop. The
    /// loader still makes unwiped intermediate copies of a SEC1 key while converting it to PKCS#8 (see the residual
    /// copies in `design/secret-handling.md`).
    fn certified_key(
        &self,
        provider: &CryptoProvider,
        chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Result<CertifiedKey, ListenerTlsError> {
        let signing_key = provider
            .key_provider
            .load_private_key(key)
            .map_err(|_| ListenerTlsError::UnusableKey {
                listener: self.listener.clone(),
                path: self.key.to_path_buf(),
            })?;
        let certified = CertifiedKey::new(chain, signing_key);
        let (listener, certificate, key) = (self.listener.clone(), self.certificate.to_path_buf(), self.key.to_path_buf());
        // Only a confirmed match is accepted: rustls's own loader lets an unknown result through.
        match certified.keys_match() {
            Ok(()) => Ok(certified),
            Err(rustls::Error::InconsistentKeys(InconsistentKeys::KeyMismatch)) => Err(ListenerTlsError::KeyMismatch {
                listener,
                certificate,
                key,
            }),
            Err(_) => Err(ListenerTlsError::KeyNotChecked {
                listener,
                certificate,
                key,
            }),
        }
    }

    fn unreadable(&self, source: AdminFileError) -> ListenerTlsError {
        ListenerTlsError::Unreadable {
            listener: self.listener.clone(),
            source,
        }
    }
}

/// The listener's rustls config: the default protocol versions (TLS 1.2 and 1.3), no client authentication, since
/// callers prove themselves with caller tokens or by arriving on an isolated-network listener, and ALPN `http/1.1`.
///
/// Its key log stays rustls's default, which logs nothing, so `SSLKEYLOGFILE` never takes effect.
fn server_config(provider: Arc<CryptoProvider>, certified: CertifiedKey) -> Result<ServerConfig, rustls::Error> {
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(SingleCertAndKey::from(certified)));
    config.alpn_protocols = vec![ALPN_HTTP_1_1.to_vec()];
    Ok(config)
}

#[cfg(test)]
mod tests;
