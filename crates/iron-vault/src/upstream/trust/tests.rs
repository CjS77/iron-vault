use rcgen::{BasicConstraints, Certificate, CertificateParams, DnType, IsCa, Issuer, KeyPair};
// Calling the verifier needs its trait in scope; these tests only drive the WebPKI verifier and implement nothing.
#[allow(clippy::disallowed_types)]
use rustls::client::danger::ServerCertVerifier;
use rustls::crypto::CryptoProvider;
use rustls::{CertificateError, ClientConnection, Connection, ServerConfig, ServerConnection};
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};

use super::*;
use crate::config_check::InvalidConfig;
use crate::tls::provider;
use crate::upstream::client::ClientBuildError;

const UPSTREAM: &str = "upstream.test";
const CA_PATH: &str = "/etc/iron-vault/ca/upstream.pem";

/// A test CA that can issue leaf certificates.
struct TestCa {
    certificate: Certificate,
    issuer: Issuer<'static, KeyPair>,
}

impl TestCa {
    fn new(name: &str) -> Self {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name.push(DnType::CommonName, name);
        let certificate = params.self_signed(&key).unwrap();
        Self {
            certificate,
            issuer: Issuer::new(params, key),
        }
    }

    /// A leaf certificate for `dns_name` and its key.
    fn leaf(&self, dns_name: &str) -> (Certificate, KeyPair) {
        let key = KeyPair::generate().unwrap();
        let params = CertificateParams::new(vec![dns_name.to_string()]).unwrap();
        (params.signed_by(&key, &self.issuer).unwrap(), key)
    }

    fn pem(&self) -> String {
        self.certificate.pem()
    }

    fn trust(&self) -> UpstreamTrust {
        UpstreamTrust::Pinned(PinnedCa::from_pem(Path::new(CA_PATH), self.pem().as_bytes()).unwrap())
    }
}

/// Runs the verifier `client_config` installs against `leaf` for `name`.
fn verify(trust: &UpstreamTrust, leaf: &Certificate, name: &str) -> Result<(), rustls::Error> {
    let verifier = trust.verifier(&provider()).unwrap();
    let name = ServerName::try_from(name.to_string()).unwrap();
    verifier
        .verify_server_cert(leaf.der(), &[], &name, &[], UnixTime::now())
        .map(|_| ())
}

fn from_pem(pem: &str) -> Result<PinnedCa, PinnedCaError> {
    PinnedCa::from_pem(Path::new(CA_PATH), pem.as_bytes())
}

fn ca_path() -> PathBuf {
    PathBuf::from(CA_PATH)
}

mod verifier {
    use super::*;

    #[test]
    fn the_pinned_ca_accepts_its_leaf_for_the_right_name() {
        let ca = TestCa::new("Pinned CA");
        let (leaf, _) = ca.leaf(UPSTREAM);
        assert_eq!(verify(&ca.trust(), &leaf, UPSTREAM), Ok(()));
    }

    #[test]
    fn the_pinned_ca_refuses_its_leaf_for_another_name() {
        let ca = TestCa::new("Pinned CA");
        let (leaf, _) = ca.leaf(UPSTREAM);
        let refused = verify(&ca.trust(), &leaf, "other.test");
        assert!(
            matches!(
                refused,
                Err(rustls::Error::InvalidCertificate(
                    CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. }
                ))
            ),
            "{refused:?}"
        );
    }

    #[test]
    fn the_pinned_ca_refuses_a_leaf_from_another_ca() {
        let pinned = TestCa::new("Pinned CA");
        let (leaf, _) = TestCa::new("Other CA").leaf(UPSTREAM);
        assert_eq!(
            verify(&pinned.trust(), &leaf, UPSTREAM),
            Err(rustls::Error::InvalidCertificate(CertificateError::UnknownIssuer))
        );
    }

    #[test]
    fn the_built_in_roots_refuse_a_leaf_from_a_private_ca() {
        let (leaf, _) = TestCa::new("Private CA").leaf(UPSTREAM);
        assert_eq!(
            verify(&UpstreamTrust::BuiltIn, &leaf, UPSTREAM),
            Err(rustls::Error::InvalidCertificate(CertificateError::UnknownIssuer))
        );
    }

    #[test]
    fn the_built_in_roots_are_the_compiled_in_webpki_roots() {
        assert_eq!(UpstreamTrust::BuiltIn.roots().roots, webpki_roots::TLS_SERVER_ROOTS);
    }
}

/// Full handshakes in memory, proving `client_config` carries the verifier the tests above drive.
mod handshake {
    use super::*;

    fn server_config(leaf: &Certificate, key: &KeyPair) -> Arc<ServerConfig> {
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let config = ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![leaf.der().clone()], key)
            .unwrap();
        Arc::new(config)
    }

    /// Moves every pending TLS record from `from` to `to` and lets `to` process them.
    fn pump(from: &mut Connection, to: &mut Connection) -> Result<(), rustls::Error> {
        let mut records = Vec::new();
        while from.wants_write() {
            from.write_tls(&mut records).unwrap();
        }
        let mut pending = records.as_slice();
        while !pending.is_empty() {
            to.read_tls(&mut pending).unwrap();
            to.process_new_packets()?;
        }
        Ok(())
    }

    /// Connects a client built from `trust` to a server presenting `leaf`, under `name`.
    fn handshake(trust: &UpstreamTrust, leaf: &Certificate, key: &KeyPair, name: &str) -> Result<(), rustls::Error> {
        let name = ServerName::try_from(name.to_string()).unwrap();
        let mut client = Connection::Client(ClientConnection::new(trust.client_config().unwrap(), name).unwrap());
        let mut server = Connection::Server(ServerConnection::new(server_config(leaf, key)).unwrap());
        (0..4).try_for_each(|_| {
            pump(&mut client, &mut server)?;
            pump(&mut server, &mut client)
        })?;
        assert!(!client.is_handshaking());
        Ok(())
    }

    #[test]
    fn a_client_trusting_the_pinned_ca_completes_a_handshake() {
        let ca = TestCa::new("Pinned CA");
        let (leaf, key) = ca.leaf(UPSTREAM);
        assert_eq!(handshake(&ca.trust(), &leaf, &key, UPSTREAM), Ok(()));
    }

    #[test]
    fn a_client_trusting_the_built_in_roots_refuses_the_pinned_ca_leaf() {
        let (leaf, key) = TestCa::new("Private CA").leaf(UPSTREAM);
        assert_eq!(
            handshake(&UpstreamTrust::BuiltIn, &leaf, &key, UPSTREAM),
            Err(rustls::Error::InvalidCertificate(CertificateError::UnknownIssuer))
        );
    }
}

mod client_config {
    use super::*;

    #[test]
    fn it_presents_no_client_certificate() {
        let config = UpstreamTrust::BuiltIn.client_config().unwrap();
        assert!(!config.client_auth_cert_resolver.has_certs());
    }

    #[test]
    fn it_logs_no_session_keys() {
        let config = UpstreamTrust::BuiltIn.client_config().unwrap();
        assert!(!config.key_log.will_log("CLIENT_RANDOM"));
    }

    #[test]
    fn it_leaves_alpn_to_the_http_client() {
        assert!(UpstreamTrust::BuiltIn.client_config().unwrap().alpn_protocols.is_empty());
    }

    #[test]
    fn it_installs_no_process_wide_crypto_provider() {
        UpstreamTrust::BuiltIn.client_config().unwrap();
        assert!(CryptoProvider::get_default().is_none());
    }
}

mod pinned_ca_file {
    use super::*;

    #[test]
    fn several_ca_certificates_are_all_trusted() {
        let (first, second) = (TestCa::new("First CA"), TestCa::new("Second CA"));
        let pinned = from_pem(&format!("{}{}", first.pem(), second.pem())).unwrap();
        assert_eq!(pinned.roots.len(), 2);
        assert_eq!(pinned.path(), Path::new(CA_PATH));
        let trust = UpstreamTrust::Pinned(pinned);
        [&first, &second]
            .iter()
            .for_each(|ca| assert_eq!(verify(&trust, &ca.leaf(UPSTREAM).0, UPSTREAM), Ok(())));
    }

    #[test]
    fn explanatory_text_around_the_certificates_is_ignored() {
        let ca = TestCa::new("Pinned CA");
        assert!(from_pem(&format!("# Issuer: Pinned CA\n{}\ntrailing note\n", ca.pem())).is_ok());
    }

    #[test]
    fn a_certificate_with_its_private_key_is_refused() {
        let ca = TestCa::new("Pinned CA");
        let (leaf, key) = ca.leaf(UPSTREAM);
        let pem = format!("{}{}", leaf.pem(), key.serialize_pem());
        let refused = from_pem(&pem).unwrap_err();
        assert_eq!(refused, PinnedCaError::NotOnlyCertificates { path: ca_path() });
        assert!(!refused.to_string().contains("PRIVATE KEY-----"));
    }

    #[test]
    fn any_item_other_than_a_certificate_is_refused() {
        let ca = TestCa::new("Pinned CA");
        ["ENCRYPTED PRIVATE KEY", "PUBLIC KEY", "X509 CRL", "TRUSTED CERTIFICATE"]
            .iter()
            .map(|label| format!("{}-----BEGIN {label}-----\nAAAA\n-----END {label}-----\n", ca.pem()))
            .for_each(|pem| {
                assert_eq!(
                    from_pem(&pem).unwrap_err(),
                    PinnedCaError::NotOnlyCertificates { path: ca_path() },
                    "{pem}"
                )
            });
    }

    #[test]
    fn an_indented_private_key_is_refused() {
        let ca = TestCa::new("Pinned CA");
        let pem = format!("{}  -----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n", ca.pem());
        assert_eq!(from_pem(&pem).unwrap_err(), PinnedCaError::NotOnlyCertificates { path: ca_path() });
    }

    #[test]
    fn an_empty_file_is_refused() {
        assert_eq!(from_pem("").unwrap_err(), PinnedCaError::NoCertificates { path: ca_path() });
    }

    #[test]
    fn garbage_is_refused() {
        assert_eq!(
            PinnedCa::from_pem(Path::new(CA_PATH), &[0xff, 0x00, 0x13, 0x37, b'\n', 0x80]).unwrap_err(),
            PinnedCaError::NoCertificates { path: ca_path() }
        );
        assert_eq!(
            from_pem("not a certificate\n").unwrap_err(),
            PinnedCaError::NoCertificates { path: ca_path() }
        );
    }

    #[test]
    fn a_certificate_cut_short_is_refused() {
        let pem = TestCa::new("Pinned CA").pem();
        let cut = pem.lines().take(3).collect::<Vec<_>>().join("\n");
        assert_eq!(from_pem(&cut).unwrap_err(), PinnedCaError::MalformedPem { path: ca_path() });
    }

    #[test]
    fn a_certificate_whose_base64_does_not_decode_is_refused() {
        let pem = "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n";
        assert_eq!(from_pem(pem).unwrap_err(), PinnedCaError::MalformedPem { path: ca_path() });
    }

    #[test]
    fn an_indented_certificate_the_decoder_would_skip_is_refused() {
        let ca = TestCa::new("Pinned CA");
        let indented = TestCa::new("Hidden CA")
            .pem()
            .lines()
            .map(|line| format!(" {line}\n"))
            .collect::<String>();
        let pem = format!("{}{indented}", ca.pem());
        assert_eq!(from_pem(&pem).unwrap_err(), PinnedCaError::MalformedPem { path: ca_path() });
    }

    #[test]
    fn a_certificate_that_is_not_x509_is_refused_by_position() {
        let ca = TestCa::new("Pinned CA");
        let pem = format!("{}-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", ca.pem());
        assert_eq!(
            from_pem(&pem).unwrap_err(),
            PinnedCaError::NotATrustAnchor {
                path: ca_path(),
                position: 2
            }
        );
    }

    #[test]
    fn errors_name_the_path_and_never_the_contents() {
        let errors = [
            PinnedCaError::MalformedPem { path: ca_path() },
            PinnedCaError::NotOnlyCertificates { path: ca_path() },
            PinnedCaError::NoCertificates { path: ca_path() },
            PinnedCaError::NotATrustAnchor {
                path: ca_path(),
                position: 1,
            },
        ];
        errors
            .iter()
            .map(ToString::to_string)
            .for_each(|message| assert!(message.contains(CA_PATH), "{message}"));
    }

    #[test]
    fn a_file_off_a_trusted_path_is_refused_before_it_is_parsed() {
        let refused = UpstreamTrust::pinned(
            Path::new("/nonexistent/iron-vault/ca.pem"),
            DeploymentProfile::Protected,
            ExpectedOwner { uid: 0 },
        )
        .unwrap_err();
        assert!(matches!(refused, PinnedCaError::Unreadable(_)), "{refused:?}");
    }
}

mod per_route {
    use iron_vault_policy::ParsedConfig;

    use super::*;

    const ROUTE: &str = r#"
schema_version = 1

[routes.fx]
prefix = "/fx"
upstream = "https://api.fx.example"
credential = "fx_key"
slot = { query = "access_key" }
methods = ["GET"]
paths = ["/latest"]
rate_limit = { requests = 60, per_seconds = 60, burst = 10 }
"#;

    fn route(extra: &str) -> RouteConfig {
        let config = ParsedConfig::from_toml(format!("{ROUTE}{extra}").as_bytes()).unwrap();
        config.routes().values().next().unwrap().clone()
    }

    #[test]
    fn a_route_without_ca_file_trusts_the_built_in_roots() {
        let trust = select(&route(""), |_| -> Result<_, ()> { unreachable!("no pinned CA to load") });
        assert!(matches!(trust, Ok(UpstreamTrust::BuiltIn)));
    }

    #[test]
    fn a_route_with_ca_file_loads_that_pinned_ca() {
        let ca = TestCa::new("Pinned CA");
        let route = route(&format!("ca_file = \"{CA_PATH}\"\n"));
        let trust = select(&route, |path| {
            PinnedCa::from_pem(path, ca.pem().as_bytes()).map(UpstreamTrust::Pinned)
        })
        .unwrap();
        let UpstreamTrust::Pinned(pinned) = &trust else {
            panic!("expected a pinned CA, got {trust:?}");
        };
        assert_eq!(pinned.path(), Path::new(CA_PATH));
        assert_eq!(verify(&trust, &ca.leaf(UPSTREAM).0, UPSTREAM), Ok(()));
    }

    #[test]
    fn trust_for_reads_the_ca_file_through_its_trusted_path_rule() {
        let route = route("ca_file = \"/nonexistent/iron-vault/ca.pem\"\n");
        let refused = trust_for(&route, DeploymentProfile::Protected, ExpectedOwner { uid: 0 }).unwrap_err();
        assert!(matches!(refused, PinnedCaError::Unreadable(_)), "{refused:?}");
    }
}

const LIBRARY_TEXT: &str = "distinctive-rustls-text";

/// One `ClientBuildError` per `ClientConfigError` variant, each over a library error whose text must never be rendered.
fn client_build_errors() -> Vec<(ClientBuildError, String)> {
    let protocol = rustls::Error::General(LIBRARY_TEXT.to_owned());
    let verifier = VerifierBuilderError::NoRootAnchors;
    let verifier_text = verifier.to_string();
    vec![
        (ClientConfigError::ProtocolVersions(protocol).into(), LIBRARY_TEXT.to_owned()),
        (ClientConfigError::Verifier(verifier).into(), verifier_text),
    ]
}

#[test]
fn client_build_errors_render_without_the_library_error_text() {
    client_build_errors().iter().for_each(|(error, library_text)| {
        assert!(!error.to_string().contains(library_text.as_str()), "{error}");
        assert!(
            std::error::Error::source(error).is_some(),
            "the chain still reaches the inner error"
        );
        let detail = InvalidConfig::Clients(error.clone()).detail();
        assert!(!detail.contains(library_text.as_str()), "{detail}");
    });
}
