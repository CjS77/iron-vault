//! The service's one TLS stack: the crypto provider and the PEM rules shared by the outbound client's trust
//! ([`crate::upstream::trust`]) and the TLS listeners (`listener_tls`).

use std::sync::Arc;

use rustls::crypto::CryptoProvider;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;

/// What starts every PEM item, whatever its label.
const PEM_BEGIN: &[u8] = b"-----BEGIN ";

/// The start of a certificate item.
const CERTIFICATE_BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";

/// Why a file that should hold only certificates was refused. No variant carries the file's contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CertificatePemError {
    /// A PEM item is cut short, its base64 does not decode, or the decoder skipped a start line.
    Malformed,
    /// The file holds a PEM item that is not a certificate, such as a private key.
    NotOnlyCertificates,
    /// The file holds no certificate at all.
    NoCertificates,
}

/// The TLS crypto provider. It is passed to each config explicitly rather than installed as the process default, so
/// the provider never depends on what other code installs.
pub(crate) fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Decodes a file that must hold one or more `CERTIFICATE` items and nothing else.
///
/// Every PEM item is checked to be a certificate before any is decoded, so a private key's body is never decoded.
pub(crate) fn certificates(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, CertificatePemError> {
    let starts = item_starts(pem);
    if !starts.iter().all(|line| line.trim_ascii() == CERTIFICATE_BEGIN) {
        return Err(CertificatePemError::NotOnlyCertificates);
    }
    let certificates = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .ok()
        // A start line the decoder did not honour, such as an indented one or one inside another item, means the
        // file is not what it appears to be.
        .filter(|certificates| certificates.len() == starts.len())
        .ok_or(CertificatePemError::Malformed)?;
    match certificates.is_empty() {
        true => Err(CertificatePemError::NoCertificates),
        false => Ok(certificates),
    }
}

/// Every line that could start a PEM item, including indented ones, which the decoder would skip as text.
pub(crate) fn item_starts(pem: &[u8]) -> Vec<&[u8]> {
    pem.split(|byte| matches!(byte, b'\n' | b'\r'))
        .filter(|line| line.trim_ascii_start().starts_with(PEM_BEGIN))
        .collect()
}
