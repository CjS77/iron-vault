//! Upstream trust: the trust anchors an upstream's certificate must chain to (specification §3.7).
//!
//! The outbound client trusts the webpki roots compiled into this binary or, for a route that names one, the CA
//! certificates in an administrator-installed pinned CA file. It builds its own rustls config over exactly those roots,
//! with the crypto provider passed in explicitly, so neither `SSL_CERT_FILE`, `SSL_CERT_DIR`, a desktop store nor a
//! process-wide default provider installed by other code can change what verifies. Nothing here can switch
//! certificate or hostname verification off, and `clippy.toml` refuses rustls's `dangerous()` builders everywhere else.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use iron_vault_policy::RouteConfig;
use rustls::client::{VerifierBuilderError, WebPkiServerVerifier};
use rustls::crypto::CryptoProvider;
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::CertificateDer;

use crate::admin_file::{self, AdminFile, AdminFileError};
use crate::deployment::DeploymentProfile;
use crate::tls::{self, CertificatePemError};
use crate::trusted_path::ExpectedOwner;

/// The trust anchors an upstream's certificate must chain to.
#[derive(Debug, Clone)]
pub enum UpstreamTrust {
    /// The webpki roots compiled into this binary.
    BuiltIn,
    /// A route's pinned CA, which replaces the built-in roots for that route.
    Pinned(PinnedCa),
}

/// The CA certificates read from a route's pinned CA file, each already accepted as a trust anchor.
#[derive(Debug, Clone)]
pub struct PinnedCa {
    path: PathBuf,
    roots: Arc<RootCertStore>,
}

/// Why a pinned CA file was not loaded. No variant carries the file's contents, only its path.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PinnedCaError {
    /// The file failed its trusted-path rule or could not be read.
    #[error(transparent)]
    Unreadable(#[from] AdminFileError),
    /// A PEM item is cut short or its base64 does not decode.
    #[error("{path} is not a well-formed PEM file")]
    MalformedPem {
        /// The file's path.
        path: PathBuf,
    },
    /// The file holds a PEM item that is not a certificate, such as a private key.
    #[error("{path} holds a PEM item other than CERTIFICATE; a pinned CA file holds only CA certificates, never a key")]
    NotOnlyCertificates {
        /// The file's path.
        path: PathBuf,
    },
    /// The file holds no certificate at all.
    #[error("{path} holds no CERTIFICATE item")]
    NoCertificates {
        /// The file's path.
        path: PathBuf,
    },
    /// A certificate does not parse as an X.509 certificate, so it cannot anchor trust.
    #[error("certificate {position} in {path} cannot be used as a trust anchor")]
    NotATrustAnchor {
        /// The file's path.
        path: PathBuf,
        /// The certificate's position in the file, counting from 1.
        position: usize,
    },
}

/// Why the outbound client config could not be built.
///
/// The inner errors are sources only, never in the message: their text is a library error's, and the message reaches
/// `config.check-failed`'s `detail` and the `config-invalid` answer through `InvalidConfig::detail`.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ClientConfigError {
    /// The crypto provider cannot serve rustls's default protocol versions.
    #[error("the TLS crypto provider cannot serve the default protocol versions")]
    ProtocolVersions(#[source] rustls::Error),
    /// The certificate verifier could not be built over the trust anchors.
    #[error("cannot build the upstream certificate verifier")]
    Verifier(#[source] VerifierBuilderError),
}

impl UpstreamTrust {
    /// Reads a pinned CA file through the administrator-certificate trusted-path rule.
    ///
    /// The file must hold one or more `CERTIFICATE` PEM items and nothing else: an empty file, a private key or any
    /// other item is refused, so a misplaced key file is never taken for a CA.
    pub fn pinned(path: &Path, profile: DeploymentProfile, owner: ExpectedOwner) -> Result<Self, PinnedCaError> {
        let pem = admin_file::read(AdminFile::Certificate, profile, owner, path)?;
        PinnedCa::from_pem(path, &pem).map(Self::Pinned)
    }

    /// Parses a pinned CA from PEM bytes, applying every check [`pinned`](Self::pinned) applies to the file's contents
    /// but not its trusted-path rule; `path` only names the file in errors.
    ///
    /// Integration tests use it to pin a test CA from a temporary tree that the rule rightly refuses. The service
    /// reads pinned CA files only through [`pinned`](Self::pinned), and the `test-support` feature that exposes this
    /// is enabled only by this crate's own dev-dependency.
    #[cfg(any(test, feature = "test-support"))]
    pub fn pinned_from_pem(path: &Path, pem: &[u8]) -> Result<Self, PinnedCaError> {
        PinnedCa::from_pem(path, pem).map(Self::Pinned)
    }

    /// The outbound rustls config: the default protocol versions (TLS 1.2 and 1.3) and a WebPKI verifier over exactly
    /// these trust anchors.
    ///
    /// It presents no client certificate, and its key log stays rustls's default, which logs nothing, so
    /// `SSLKEYLOGFILE` never takes effect. ALPN is left for the HTTP client to set.
    pub fn client_config(&self) -> Result<Arc<ClientConfig>, ClientConfigError> {
        let provider = tls::provider();
        let verifier = self.verifier(&provider)?;
        let config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(ClientConfigError::ProtocolVersions)?
            .with_webpki_verifier(verifier)
            .with_no_client_auth();
        Ok(Arc::new(config))
    }

    /// The certificate and hostname verifier [`client_config`](Self::client_config) installs.
    fn verifier(&self, provider: &Arc<CryptoProvider>) -> Result<Arc<WebPkiServerVerifier>, ClientConfigError> {
        WebPkiServerVerifier::builder_with_provider(self.roots(), Arc::clone(provider))
            .build()
            .map_err(ClientConfigError::Verifier)
    }

    fn roots(&self) -> Arc<RootCertStore> {
        match self {
            Self::BuiltIn => Arc::new(webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect()),
            Self::Pinned(ca) => Arc::clone(&ca.roots),
        }
    }
}

impl PinnedCa {
    /// The file the certificates were read from, for naming the route's trust in errors and events.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Parses a pinned CA file's bytes; `path` only names the file in errors.
    ///
    /// Every PEM item is checked to be a certificate before any is decoded, so a private key's body is never decoded.
    fn from_pem(path: &Path, pem: &[u8]) -> Result<Self, PinnedCaError> {
        let certificates = tls::certificates(pem).map_err(|e| {
            let path = path.to_path_buf();
            match e {
                CertificatePemError::Malformed => PinnedCaError::MalformedPem { path },
                CertificatePemError::NotOnlyCertificates => PinnedCaError::NotOnlyCertificates { path },
                CertificatePemError::NoCertificates => PinnedCaError::NoCertificates { path },
            }
        })?;
        Ok(Self {
            path: path.to_path_buf(),
            roots: Arc::new(trust_anchors(path, certificates)?),
        })
    }
}

/// Selects the trust for a route: its pinned CA when `ca_file` is set, else the built-in roots.
///
/// A pinned CA changes only which certificates verify, never where the credential may go: the final outgoing-request
/// check ([`iron_vault_policy::final_check`]) still compares the upstream host with the credential record's permitted
/// origins, whatever CA the route pins.
pub fn trust_for(route: &RouteConfig, profile: DeploymentProfile, owner: ExpectedOwner) -> Result<UpstreamTrust, PinnedCaError> {
    select(route, |path| UpstreamTrust::pinned(path, profile, owner))
}

/// [`trust_for`] with the pinned-CA loader passed in, so the selection is testable without a trusted path on disk.
fn select<E>(route: &RouteConfig, load_pinned: impl FnOnce(&Path) -> Result<UpstreamTrust, E>) -> Result<UpstreamTrust, E> {
    route
        .ca_file()
        .map_or(Ok(UpstreamTrust::BuiltIn), |ca_file| load_pinned(ca_file.as_path()))
}

/// Converts each certificate to a trust anchor, naming the first that does not convert.
fn trust_anchors(path: &Path, certificates: Vec<CertificateDer<'static>>) -> Result<RootCertStore, PinnedCaError> {
    let mut roots = RootCertStore::empty();
    certificates.into_iter().enumerate().try_for_each(|(index, certificate)| {
        roots.add(certificate).map_err(|_| PinnedCaError::NotATrustAnchor {
            path: path.to_path_buf(),
            position: index + 1,
        })
    })?;
    Ok(roots)
}

#[cfg(test)]
mod tests;
