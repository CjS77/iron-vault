//! The config check against real files in temporary directories: a vault, an approval state and a config directory
//! built through the stores' public API, and the published pair tampered with by hand.

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signer, SigningKey};
use iron_vault_kinds::CredentialMaterial;
use iron_vault_policy::{AccountDirectory, AccountName, Port, UnavailableCause};
use iron_vault_store::{
    ApprovalEnvelope, ApprovalPayload, ApprovalSigner, ApprovalStorage, ApprovalVersion, ApproverPublicKey, ConfigDigest, ConfigDirLock,
    ConfigFileName, OsFs, PendingConfig, PermittedOrigins, PinnedApprover, PublishedPairFault, RecordId, SignError, SignatureAlgorithm,
    StateDirLock, StateFileName, StoreFs, VaultId, VaultIdentity, VerifyError,
};

use super::*;
use crate::secret_types_tests::MARKER;
use crate::serving_snapshot::SnapshotHolder;
use crate::serving_snapshot::tests::Scratch;
use crate::standing::{RouteFaultKind, Standing};

const IDENTITY: &str = "AGE-SECRET-KEY-1QYPQXPQ9QCRSSZG2PVXQ6RS0ZQG3YYC5Z5TPWXQERGD3C8G7RUSQGPQYEE";

fn identity() -> VaultIdentity {
    VaultIdentity::from_secret(IDENTITY)
}

struct NoAccounts;

impl AccountDirectory for NoAccounts {
    fn uid(&self, _: &AccountName) -> Option<u32> {
        None
    }

    fn service_account_uid(&self) -> u32 {
        990
    }

    fn overflow_uid(&self) -> u32 {
        65534
    }
}

/// An Ed25519 signer with a fixed key, so tests can also sign hand-made payloads.
struct TestSigner(SigningKey);

impl TestSigner {
    fn new() -> Self {
        Self(SigningKey::from_bytes(&[7; 32]))
    }

    fn envelope(&self, payload: &ApprovalPayload) -> Vec<u8> {
        self.sign(payload).unwrap().encode()
    }
}

impl ApprovalSigner for TestSigner {
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::Ed25519
    }

    fn public_key(&self) -> ApproverPublicKey {
        ApproverPublicKey::new(SignatureAlgorithm::Ed25519, self.0.verifying_key().to_bytes().to_vec()).unwrap()
    }

    fn sign(&self, payload: &ApprovalPayload) -> Result<ApprovalEnvelope, SignError> {
        let signature = self.0.sign(&payload.encode()).to_bytes().to_vec();
        ApprovalEnvelope::new(SignatureAlgorithm::Ed25519, *payload, signature).map_err(SignError::Signature)
    }
}

/// A config with one route per `(route, credential)`, each sending to `https://api.<route>.example`.
fn config(routes: &[(&str, &str)]) -> String {
    let names = routes
        .iter()
        .map(|(route, _)| format!("\"{route}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let tables = routes.iter().map(|(route, credential)| {
        format!(
            r#"
[routes.{route}]
prefix = "/{route}"
upstream = "https://api.{route}.example"
credential = "{credential}"
slot = {{ header = "X-Api-Key" }}
methods = ["GET"]
paths = ["/**"]
rate_limit = {{ requests = 60, per_seconds = 60, burst = 10 }}
"#
        )
    });
    format!(
        r#"schema_version = 1

[listeners.local]
unix_socket = "/run/iron-vault/proxy.sock"

[callers.agent]
listener = "local"
token_hash = "blake2b:0123456789abcdef00112233445566778899aabbccddeeff0f1e2d3c4b5a6978"
routes = [{names}]
{}"#,
        tables.collect::<String>()
    )
}

fn route(name: &str) -> iron_vault_policy::RouteName {
    name.parse().unwrap()
}

/// A vault with `credentials` (each may reach `api.<name>.example`) and an approval state pinning the test signer. Nothing
/// is approved until [`approve`](Self::approve).
struct Fixture {
    state_dir: Scratch,
    config_dir: Scratch,
    state_lock: StateDirLock,
    config_lock: ConfigDirLock,
    state: ApprovalState,
    ids: Vec<(String, RecordId)>,
}

impl Fixture {
    fn new(credentials: &[&str]) -> Self {
        let (state_dir, config_dir) = (Scratch::new(), Scratch::new());
        let state_lock = StateDirLock::acquire(&state_dir.0).unwrap();
        let config_lock = ConfigDirLock::acquire(&config_dir.0).unwrap();
        let mut vault = Vault::create(&state_lock, &OsFs, identity()).unwrap();
        let ids = credentials
            .iter()
            .map(|name| {
                let origins = PermittedOrigins::new([(format!("api.{name}.example").parse().unwrap(), Port::HTTPS)].into()).unwrap();
                let material = CredentialMaterial::Static {
                    key: MARKER.to_owned().into(),
                };
                let (id, _) = vault.add(&state_lock, &OsFs, name.parse().unwrap(), material, origins).unwrap();
                ((*name).to_owned(), id)
            })
            .collect();
        let (state, _) = vault
            .create_approval_state(&state_lock, &OsFs, PinnedApprover::for_tests(TestSigner::new().public_key()))
            .unwrap();
        Self {
            state_dir,
            config_dir,
            state_lock,
            config_lock,
            state,
            ids,
        }
    }

    fn storage<'a>(&'a self, identity: &'a VaultIdentity) -> ApprovalStorage<'a, OsFs> {
        ApprovalStorage {
            state_dir: &self.state_lock,
            config_dir: &self.config_lock,
            identity,
            fs: &OsFs,
        }
    }

    /// Commits and publishes `config` as the next version, through the approval transaction.
    fn approve(&mut self, config: &str) -> ApprovalVersion {
        let (identity, holder) = (identity(), SnapshotHolder::refusing(UnavailableReason::Checking));
        let mut state = self.state.clone();
        let storage = self.storage(&identity);
        let pending = PendingConfig::write(&storage, config.as_bytes().to_vec()).unwrap();
        let committed = pending
            .prepare(&storage, &mut state, TestSigner::new())
            .unwrap()
            .commit(&storage, &holder.pause())
            .unwrap();
        self.state = state;
        committed.approval().version()
    }

    /// Commits `config` as the next version but stops before publishing: its pending and staged files wait.
    fn commit_unpublished(&mut self, config: &str) -> ApprovalVersion {
        let identity = identity();
        let mut state = self.state.clone();
        let storage = self.storage(&identity);
        let pending = PendingConfig::write(&storage, config.as_bytes().to_vec()).unwrap();
        let prepared = pending.prepare(&storage, &mut state, TestSigner::new()).unwrap();
        let (version, digest) = (prepared.version(), prepared.digest());
        state.commit(&self.state_lock, &OsFs, &identity, version, digest).unwrap();
        self.state = state;
        version
    }

    fn path(&self, name: &str) -> PathBuf {
        self.config_dir.0.join(name)
    }

    fn read(&self, name: &str) -> Vec<u8> {
        std::fs::read(self.path(name)).unwrap()
    }

    fn write(&self, name: &str, bytes: &[u8]) {
        std::fs::write(self.path(name), bytes).unwrap();
    }

    /// Overwrites the published pair with `config` and a signature file built from `payload` by the pinned signer.
    fn publish_signed(&self, config: &[u8], payload: ApprovalPayload) {
        self.write("config.toml", config);
        self.write("config.toml.sig", &TestSigner::new().envelope(&payload));
    }

    /// Damages the record file of credential `name` so it fails to load.
    fn damage(&self, name: &str) {
        let (_, id) = self.ids.iter().find(|(n, _)| n == name).unwrap();
        std::fs::write(self.state_dir.0.join(StateFileName::record(id).as_str()), b"damaged").unwrap();
    }

    /// Runs the check on a freshly opened vault.
    fn check(&self) -> Result<ServingSnapshot, CheckFailure> {
        self.check_with(&development())
    }

    /// Runs the check on a freshly opened vault, building the upstream clients with `upstream`.
    fn check_with(&self, upstream: &UpstreamSettings) -> Result<ServingSnapshot, CheckFailure> {
        let (vault, _) = Vault::open(&self.state_lock, &OsFs, identity()).unwrap();
        check_config(
            &self.config_lock,
            &OsFs,
            vault,
            &self.state,
            &Capabilities::default(),
            &NoAccounts,
            upstream,
        )
    }
}

/// Upstream settings that read each pinned CA file through the development profile's trusted-path rule.
fn development() -> UpstreamSettings {
    UpstreamSettings::new(DeploymentProfile::Development, ExpectedOwner { uid: 0 }, TransportLimits::default())
}

fn failure(result: Result<ServingSnapshot, CheckFailure>) -> CheckFailure {
    result.expect_err("the check should fail")
}

/// The store's initial config, which init approves as version 1, must reach Ready at the first unlock: it activates
/// against a new vault's empty catalog and names nothing to serve.
#[test]
fn the_initial_config_activates_against_an_empty_catalog_and_serves_nothing() {
    let fixture = Fixture::new(&[]);
    let (vault, _) = Vault::open(&fixture.state_lock, &OsFs, identity()).unwrap();
    let policy = activate_config(iron_vault_store::INITIAL_CONFIG, &Capabilities::default(), &vault, &NoAccounts).unwrap();
    let config = policy.config();
    assert!(config.listeners().is_empty() && config.callers().is_empty() && config.routes().is_empty());
}

#[test]
fn a_valid_vault_and_active_pair_give_a_snapshot_of_the_configs_routes() {
    let mut fixture = Fixture::new(&["alpha", "beta"]);
    fixture.approve(&config(&[("alpha", "alpha"), ("beta", "beta")]));

    let snapshot = fixture.check().unwrap();

    let routes: Vec<_> = snapshot.policy().config().routes().keys().cloned().collect();
    assert_eq!(routes, [route("alpha"), route("beta")]);
    assert!(routes.iter().all(|r| snapshot.policy().is_available(r)));
    assert!(snapshot.record(&"alpha".parse().unwrap()).is_some());
}

fn other() -> String {
    config(&[("alpha", "alpha"), ("beta", "alpha")])
}

fn v1() -> String {
    config(&[("alpha", "alpha")])
}

/// A fixture with version 1 approved and published.
fn approved() -> Fixture {
    let mut fixture = Fixture::new(&["alpha"]);
    fixture.approve(&v1());
    fixture
}

fn payload(fixture: &Fixture, vault: Option<VaultId>, version: u64, config: &str) -> ApprovalPayload {
    let version = ApprovalVersion::new(version).unwrap();
    ApprovalPayload::new(
        vault.unwrap_or(fixture.state.vault_id()),
        version,
        ConfigDigest::of(config.as_bytes()),
    )
}

#[test]
fn each_way_the_published_pair_fails_to_verify_is_policy_invalid() {
    type Tamper = fn(&mut Fixture);
    type Is = fn(&VerifyError) -> bool;
    let cases: [(&str, Tamper, Is); 7] = [
        (
            "malformed",
            |f| f.write("config.toml.sig", b"junk"),
            |e| matches!(e, VerifyError::Malformed(_)),
        ),
        (
            "bad signature",
            |f| {
                let forged = ApprovalEnvelope::new(SignatureAlgorithm::Ed25519, payload(f, None, 1, &v1()), vec![0; 64]).unwrap();
                f.write("config.toml.sig", &forged.encode());
            },
            |e| matches!(e, VerifyError::BadSignature),
        ),
        (
            "wrong vault",
            |f| f.publish_signed(v1().as_bytes(), payload(f, Some(VaultId::new_random()), 1, &v1())),
            |e| matches!(e, VerifyError::WrongVault),
        ),
        (
            "config changed",
            |f| f.write("config.toml", other().as_bytes()),
            |e| matches!(e, VerifyError::ConfigChanged),
        ),
        (
            "superseded",
            |f| {
                let (config, sig) = (f.read("config.toml"), f.read("config.toml.sig"));
                f.approve(&other());
                f.write("config.toml", &config);
                f.write("config.toml.sig", &sig);
            },
            |e| matches!(e, VerifyError::Superseded { .. }),
        ),
        (
            "uncommitted",
            |f| f.publish_signed(v1().as_bytes(), payload(f, None, 2, &v1())),
            |e| matches!(e, VerifyError::Uncommitted { .. }),
        ),
        (
            "digest not committed",
            |f| f.publish_signed(other().as_bytes(), payload(f, None, 1, &other())),
            |e| matches!(e, VerifyError::DigestNotCommitted { .. }),
        ),
    ];
    cases.iter().for_each(|(label, tamper, is)| {
        let mut fixture = approved();
        tamper(&mut fixture);
        let failure = failure(fixture.check());
        let CheckFailure::Recovery(ApprovalRecoveryError::PublishedPairInvalid {
            published: PublishedPairFault::DoesNotVerify(error),
            ..
        }) = &failure
        else {
            panic!("{label}: unexpected failure {failure:?}");
        };
        assert!(is(error), "{label}: {error:?}");
        assert_eq!(failure.failure(), FailureReason::PolicyInvalid, "{label}");
        assert_eq!(failure.unavailable(), UnavailableReason::PolicyInvalid, "{label}");
        assert_eq!(failure.status(), "policy invalid: config approval does not verify", "{label}");
    });
}

#[test]
fn nothing_committed_is_policy_invalid() {
    let failure = failure(Fixture::new(&["alpha"]).check());
    assert!(
        matches!(failure, CheckFailure::Recovery(ApprovalRecoveryError::NothingCommitted)),
        "{failure:?}"
    );
    assert_eq!(failure.unavailable(), UnavailableReason::PolicyInvalid);
}

#[test]
fn a_committed_transaction_that_cannot_be_published_needs_recovery() {
    let mut fixture = approved();
    fixture.commit_unpublished(&config(&[("alpha", "alpha"), ("beta", "alpha")]));
    std::fs::remove_file(fixture.path("config.toml.sig.staged")).unwrap();

    let failure = failure(fixture.check());

    assert_eq!(failure.failure(), FailureReason::RecoveryNeeded);
    assert_eq!(failure.unavailable(), UnavailableReason::RecoveryNeeded);
    assert_eq!(failure.status(), "recovery needed: committed approval cannot be published");
}

/// An [`OsFs`] whose reads of a file ending in `name` fail with EIO.
struct UnreadableFs(&'static str);

impl StoreFs for UnreadableFs {
    type File = <OsFs as StoreFs>::File;

    fn create_private(&self, path: &Path) -> io::Result<Self::File> {
        OsFs.create_private(path)
    }
    fn write_all(&self, file: &mut Self::File, bytes: &[u8]) -> io::Result<()> {
        OsFs.write_all(file, bytes)
    }
    fn sync_file(&self, file: &Self::File) -> io::Result<()> {
        OsFs.sync_file(file)
    }
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        OsFs.rename(from, to)
    }
    fn remove_file(&self, path: &Path) -> io::Result<()> {
        OsFs.remove_file(path)
    }
    fn sync_dir(&self, dir: &Path) -> io::Result<()> {
        OsFs.sync_dir(dir)
    }
    fn list_dir(&self, dir: &Path) -> io::Result<Vec<OsString>> {
        OsFs.list_dir(dir)
    }
    fn read_bounded(&self, path: &Path, max_len: u64) -> io::Result<Vec<u8>> {
        if path.to_string_lossy().ends_with(self.0) {
            return Err(io::Error::from_raw_os_error(5));
        }
        OsFs.read_bounded(path, max_len)
    }
}

#[test]
fn an_unreadable_config_file_reports_its_own_reason_and_the_fixed_body() {
    let mut fixture = approved();
    fixture.commit_unpublished(&config(&[("alpha", "alpha"), ("beta", "alpha")]));
    let (vault, _) = Vault::open(&fixture.state_lock, &OsFs, identity()).unwrap();

    let result = check_config(
        &fixture.config_lock,
        &UnreadableFs("config.toml.sig.staged"),
        vault,
        &fixture.state,
        &Capabilities::default(),
        &NoAccounts,
        &development(),
    );

    let failure = failure(result);
    assert!(
        matches!(failure, CheckFailure::Recovery(ApprovalRecoveryError::Unreadable { .. })),
        "{failure:?}"
    );
    assert_eq!(failure.unavailable(), UnavailableReason::RecoveryNeeded);
    assert_eq!(failure.unavailable().as_str(), "recovery needed");
    assert_eq!(
        failure.status(),
        "recovery needed: a config file cannot be read (permissions or disk)"
    );
    assert!(!failure.status().contains("config.toml"));
}

#[test]
fn a_published_pair_unreadable_in_the_read_back_reports_the_unreadable_reason() {
    let failure = CheckFailure::Recovery(ApprovalRecoveryError::PublishNotVerified {
        version: ApprovalVersion::new(2).unwrap(),
        renames: iron_vault_store::PublishSet::Both,
        published: PublishedPairFault::Unreadable {
            file: ConfigFileName::Active,
            kind: io::ErrorKind::PermissionDenied,
        },
    });

    assert_eq!(
        failure.status(),
        "recovery needed: a config file cannot be read (permissions or disk)"
    );
}

#[test]
fn damaged_shared_state_needs_recovery() {
    let failure = CheckFailure::Vault(VaultError::NotInitialized);
    assert_eq!(failure.unavailable(), UnavailableReason::RecoveryNeeded);
    assert_eq!(failure.status(), "recovery needed: shared state damaged");
}

impl Fixture {
    /// Opens the vault with the identity and runs the check, as an unlock does.
    fn open_and_check(&self) -> Result<Checked, CheckFailure> {
        let upstream = development();
        open_and_check(
            &self.state_lock,
            &self.config_lock,
            &OsFs,
            Arc::new(identity()),
            &Capabilities::default(),
            &NoAccounts,
            &upstream,
        )
    }
}

#[test]
fn opening_then_checking_returns_the_snapshot_and_the_approval_state() {
    let fixture = approved();
    let Checked { snapshot, approval, .. } = fixture.open_and_check().unwrap();
    assert_eq!(approval, fixture.state);
    assert!(snapshot.record(&"alpha".parse().unwrap()).is_some());
}

#[test]
fn damaged_shared_state_found_on_opening_is_a_recovery_needed_check_failure() {
    let fixture = approved();
    std::fs::write(fixture.state_dir.0.join(StateFileName::approval_state().as_str()), b"damaged").unwrap();
    let failure = fixture.open_and_check().map(|_| ()).expect_err("the check should fail");
    assert!(matches!(failure, CheckFailure::Vault(_)), "{failure:?}");
    assert_eq!(failure.unavailable(), UnavailableReason::RecoveryNeeded);
}

#[test]
fn an_unknown_credential_reference_is_config_invalid() {
    let mut fixture = Fixture::new(&["alpha"]);
    fixture.approve(&config(&[("alpha", "alpha"), ("ghost", "ghost")]));

    let failure = failure(fixture.check());

    assert!(
        matches!(&failure, CheckFailure::Config(InvalidConfig::Activation(errors)) if matches!(errors[..], [ActivationError::UnknownCredential { .. }]))
    );
    assert_eq!(failure.unavailable(), UnavailableReason::PolicyInvalid);
    assert_eq!(failure.status(), "policy invalid: config invalid");
    assert!(
        failure.detail().contains("route ghost uses credential ghost"),
        "{}",
        failure.detail()
    );
}

#[test]
fn a_config_that_does_not_parse_or_validate_is_config_invalid() {
    let invalid_parse = "schema_version = 1\n[routes.x]\nbogus = 1\n";
    let unknown_route = config(&[("alpha", "alpha")]).replace("routes = [\"alpha\"]", "routes = [\"nowhere\"]");
    [(invalid_parse.to_owned(), "parse"), (unknown_route, "validation")]
        .iter()
        .for_each(|(text, label)| {
            let mut fixture = Fixture::new(&["alpha"]);
            fixture.approve(text);
            let failure = failure(fixture.check());
            match (&failure, *label) {
                (CheckFailure::Config(InvalidConfig::Parse(_)), "parse")
                | (CheckFailure::Config(InvalidConfig::Validation(_)), "validation") => {}
                _ => panic!("{label}: {failure:?}"),
            }
            assert_eq!(failure.unavailable(), UnavailableReason::PolicyInvalid, "{label}");
        });
}

#[test]
fn a_damaged_record_makes_only_its_routes_unavailable() {
    let mut fixture = Fixture::new(&["alpha", "beta"]);
    fixture.approve(&config(&[("alpha", "alpha"), ("beta", "beta")]));
    fixture.damage("alpha");

    let snapshot = fixture.check().unwrap();

    assert!(!snapshot.policy().is_available(&route("alpha")));
    assert!(snapshot.policy().is_available(&route("beta")));
    assert!(snapshot.record(&"alpha".parse().unwrap()).is_none());
    assert!(snapshot.record(&"beta".parse().unwrap()).is_some());
}

#[test]
fn a_committed_but_unpublished_transaction_is_finished_by_the_check() {
    let mut fixture = Fixture::new(&["alpha", "beta"]);
    fixture.approve(&v1());
    let next = config(&[("alpha", "alpha"), ("beta", "beta")]);
    let version = fixture.commit_unpublished(&next);
    assert_eq!(version, ApprovalVersion::new(2).unwrap());

    let snapshot = fixture.check().unwrap();

    assert!(snapshot.policy().is_available(&route("beta")));
    assert_eq!(fixture.read("config.toml"), next.as_bytes());
    assert!(!fixture.path("config.toml.pending").exists());
    assert!(!fixture.path("config.toml.sig.staged").exists());
}

/// The audit records of `check` whose event is one of the recovery events, as `(event, level, fields)` in order.
fn recovery_records(fixture: &Fixture) -> Vec<(String, String, serde_json::Value)> {
    let out = crate::logging::tests::capture(|| drop(fixture.check().unwrap()));
    out.lines()
        .map(crate::logging::tests::parse)
        .filter(|record| {
            record["event"]
                .as_str()
                .is_some_and(|event| event.starts_with("config.recovery-") || event.contains("conflicting"))
        })
        .map(|record| {
            (
                record["event"].as_str().unwrap().to_owned(),
                record["level"].as_str().unwrap().to_owned(),
                record,
            )
        })
        .collect()
}

#[test]
fn a_check_records_the_publish_it_ran_and_each_leftover_it_discarded() {
    let mut fixture = Fixture::new(&["alpha", "beta"]);
    fixture.approve(&v1());
    fixture.commit_unpublished(&config(&[("alpha", "alpha"), ("beta", "beta")]));

    let published = recovery_records(&fixture);

    assert_eq!(published.len(), 1, "{published:?}");
    let (event, level, record) = &published[0];
    assert_eq!((event.as_str(), level.as_str()), ("config.recovery-published", "WARN"));
    assert_eq!(
        (record["version"].as_u64(), record["renames"].as_str()),
        (Some(2), Some("config.toml,config.toml.sig"))
    );

    // A pending config, and a staged approval for the committed version over another config.
    let vault = fixture.state.vault_id();
    let committed = ApprovalVersion::new(2).unwrap();
    fixture.write("config.toml.pending", b"# edited\n");
    fixture.write(
        "config.toml.sig.staged",
        &TestSigner::new().envelope(&ApprovalPayload::new(vault, committed, ConfigDigest::of(b"# another\n"))),
    );

    let discarded = recovery_records(&fixture);

    let events: Vec<_> = discarded.iter().map(|(event, level, _)| (event.as_str(), level.as_str())).collect();
    assert_eq!(
        events,
        [
            ("config.recovery-discarded", "INFO"),
            ("config.conflicting-approval-discarded", "ERROR"),
            ("config.recovery-discarded", "INFO"),
        ]
    );
    assert_eq!(discarded[0].2["file"], "config.toml.pending");
    assert_eq!(
        (discarded[2].2["file"].as_str(), discarded[2].2["signed_for"].as_u64()),
        (Some("config.toml.sig.staged"), Some(2))
    );
    assert_eq!(discarded[1].2["version"].as_u64(), Some(2));
}

#[test]
fn no_status_or_detail_holds_a_config_byte_a_path_or_a_secret() {
    // Route `alpha` sends to a host its record does not permit; the config also has a parse error and a tampered pair.
    let leaky_origin = config(&[("alpha", "alpha")]).replace("api.alpha.example", "leaky-host.example");
    let leaky_parse = "schema_version = 1\n[routes.x]\nbogus = \"leaky-value-77\"\n".to_owned();
    let failures: Vec<(CheckFailure, Fixture)> = [leaky_origin, leaky_parse]
        .iter()
        .map(|text| {
            let mut fixture = Fixture::new(&["alpha"]);
            fixture.approve(text);
            (failure(fixture.check()), fixture)
        })
        .chain(std::iter::once({
            let fixture = approved();
            fixture.write("config.toml.sig", b"junk");
            (failure(fixture.check()), fixture)
        }))
        .collect();
    failures.iter().for_each(|(failure, fixture)| {
        let texts = [failure.status(), failure.detail(), failure.unavailable().as_str().to_owned()];
        let paths = [fixture.state_dir.0.to_string_lossy(), fixture.config_dir.0.to_string_lossy()];
        texts.iter().for_each(|text| {
            [
                "leaky-host",
                "leaky-value",
                "api.alpha.example",
                MARKER,
                "token_hash",
                "0123456789abcdef",
            ]
            .iter()
            .chain(paths.iter().map(AsRef::as_ref).collect::<Vec<_>>().iter())
            .for_each(|forbidden| assert!(!text.contains(*forbidden), "{text:?} contains {forbidden:?}"));
        });
    });
}

/// A CA path no test creates, so loading it always fails.
const MISSING_CA: &str = "/nonexistent/iron-vault-test/ca.pem";

/// Routes `pinned` and `plain` share credential `alpha` and its upstream, `other` uses `beta`; only `pinned` pins a CA,
/// at `ca_file`.
fn pinned_config(ca_file: &str) -> String {
    let text = config(&[("other", "beta"), ("pinned", "alpha"), ("plain", "alpha")])
        .replace("api.other.example", "api.beta.example")
        .replace("api.pinned.example", "api.alpha.example")
        .replace("api.plain.example", "api.alpha.example");
    let pinned = "prefix = \"/pinned\"\n";
    assert!(text.contains(pinned));
    text.replacen(pinned, &format!("{pinned}ca_file = \"{ca_file}\"\n"), 1)
}

fn pinned_fixture() -> Fixture {
    let mut fixture = Fixture::new(&["alpha", "beta"]);
    fixture.approve(&pinned_config(MISSING_CA));
    fixture
}

fn assert_only_pinned_is_unavailable(snapshot: &ServingSnapshot) {
    assert!(!snapshot.policy().is_available(&route("pinned")));
    assert!(
        snapshot
            .policy()
            .is_unavailable_for(&route("pinned"), UnavailableCause::PinnedCaUnavailable)
    );
    assert!(
        !snapshot
            .policy()
            .is_unavailable_for(&route("pinned"), UnavailableCause::CredentialUnusable)
    );
    assert!(snapshot.policy().is_available(&route("plain")) && snapshot.policy().is_available(&route("other")));
}

#[test]
fn a_missing_pinned_ca_passes_the_check_and_makes_only_its_route_unavailable() {
    let snapshot = pinned_fixture().check().unwrap();
    assert_only_pinned_is_unavailable(&snapshot);
    assert!(snapshot.record(&"alpha".parse().unwrap()).is_some());
}

#[test]
fn a_malformed_pinned_ca_passes_the_check_and_makes_only_its_route_unavailable() {
    let malformed = PinnedCaError::MalformedPem {
        path: PathBuf::from(MISSING_CA),
    };
    let snapshot = pinned_fixture().check_with(&development().with_pinned_failure(malformed)).unwrap();
    assert_only_pinned_is_unavailable(&snapshot);
}

#[test]
fn status_reports_a_pinned_ca_route_as_a_route_fault_and_its_credential_stays_healthy() {
    let Checked {
        credentials, route_faults, ..
    } = pinned_fixture().open_and_check().unwrap();
    let alpha = credentials.iter().find(|c| c.name.as_str() == "alpha").unwrap();
    assert_eq!(alpha.standing, Standing::Healthy);
    assert!(alpha.unavailable_routes.is_empty());
    let expected = RouteFault {
        name: route("pinned"),
        kind: RouteFaultKind::PinnedCaUnavailable,
    };
    assert_eq!(route_faults, [expected]);
}

#[test]
fn a_route_unavailable_through_its_credential_and_its_pinned_ca_reports_both() {
    let fixture = pinned_fixture();
    fixture.damage("alpha");
    let Checked {
        snapshot,
        credentials,
        route_faults,
        ..
    } = fixture.open_and_check().unwrap();
    let alpha = credentials.iter().find(|c| c.name.as_str() == "alpha").unwrap();
    assert_eq!(alpha.unavailable_routes, [route("pinned"), route("plain")]);
    assert_eq!(route_faults.iter().map(|f| f.name.as_str()).collect::<Vec<_>>(), ["pinned"]);
    assert!(snapshot.policy().is_available(&route("other")));
}
