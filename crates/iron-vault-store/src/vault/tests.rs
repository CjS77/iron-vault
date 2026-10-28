use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt::Debug;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Once};

use iron_vault_policy::{Capabilities, CredentialKind, ParsedConfig, Port, RouteName, ValidatedConfig, activate};
use tracing::field::{Field, Visit};
use tracing::subscriber::Interest;
use tracing::{Dispatch, Event, Level, Metadata, Subscriber, span};

use super::*;
use crate::manifest::tests::KAT_IDENTITY;
use crate::test_dir::TestDir;
use crate::{ManifestEntry, OsFs, PermittedOrigins, RecordId, Source, VaultId, encode, record_digest, seal, seal_manifest};

/// The §3.3 example, with a real digest standing in for its `blake2b:...` placeholder.
const SPEC_EXAMPLE: &str = r#"schema_version = 1

[listeners.local]
unix_socket = "/run/iron-vault/proxy.sock"

[callers.fx-mcp]
listener = "local"
token_hash = "blake2b:0123456789abcdef00112233445566778899aabbccddeeff0f1e2d3c4b5a6978"
routes = ["fx"]

[callers.naomi-backoffice]
listener = "naomi-backoffice"
auth = "isolated-network"
routes = ["venice", "brave"]

[listeners.naomi-backoffice]
address = "10.20.0.2:7878"
tls_certificate = "/etc/iron-vault/tls/server.crt"
tls_key = "/etc/iron-vault/tls/server.key"

[routes.fx]
prefix = "/fx"
upstream = "https://api.fx.example"
credential = "fx_key"
slot = { query = "access_key" }
methods = ["GET"]
paths = ["/latest", "/historical/**"]
rate_limit = { requests = 60, per_seconds = 60, burst = 10 }

[routes.venice]
prefix = "/venice"
upstream = "https://api.venice.ai/api/v1"
credential = "venice"
slot = { header = "Authorization", format = "Bearer {}" }
methods = ["POST"]
paths = ["/api/v1/chat/completions"]
rate_limit = { requests = 120, per_seconds = 60, burst = 20 }

[routes.brave]
prefix = "/brave"
upstream = "https://api.search.brave.com"
credential = "brave"
slot = { header = "X-Subscription-Token" }
methods = ["GET"]
paths = ["/res/v1/web/search"]
rate_limit = { requests = 60, per_seconds = 60, burst = 10 }
"#;

pub(super) fn identity() -> VaultIdentity {
    VaultIdentity::from_secret(KAT_IDENTITY)
}

pub(super) fn n<T: std::str::FromStr<Err: Debug>>(s: &str) -> T {
    s.parse().unwrap()
}

/// The secret every test record named `name` holds, distinctive enough to search logs for.
pub(super) fn secret(name: &str) -> String {
    format!("SECRET-{name}-7f3a")
}

fn record_with_id(id: RecordId, name: &str, host: &str) -> CredentialRecord {
    let origins = PermittedOrigins::new([(n(host), Port::HTTPS)].into()).unwrap();
    let material = CredentialMaterial::Static { key: secret(name).into() };
    CredentialRecord::new(id, n(name), material, origins, Source::DirectEntry).unwrap()
}

pub(super) fn record(name: &str) -> CredentialRecord {
    record_with_id(RecordId::new_random(), name, &format!("api.{}.example", name.replace('_', "-")))
}

pub(super) fn sealed(record: &CredentialRecord) -> Vec<u8> {
    seal(&identity().public_key(), &encode(record)).unwrap()
}

/// A locked state directory to build vaults in.
struct Fixture {
    dir: TestDir,
    lock: StateDirLock,
}

impl Fixture {
    fn new(name: &str) -> Self {
        init_test_tracing();
        let dir = TestDir::new(name);
        let lock = StateDirLock::acquire(dir.path()).unwrap();
        Self { dir, lock }
    }

    fn path(&self, file: &StateFileName) -> PathBuf {
        self.dir.path().join(file.as_str())
    }

    fn record_path(&self, id: RecordId) -> PathBuf {
        self.path(&StateFileName::record(&id))
    }

    /// Writes `bytes` as the file of record `id` and returns the manifest entry vouching for them under `name`.
    fn write_file(&self, id: RecordId, name: &str, bytes: &[u8]) -> (RecordId, ManifestEntry) {
        std::fs::write(self.record_path(id), bytes).unwrap();
        (id, ManifestEntry::new(n(name), record_digest(bytes)))
    }

    fn write_record(&self, record: &CredentialRecord) -> (RecordId, ManifestEntry) {
        self.write_file(record.id(), record.name().as_str(), &sealed(record))
    }

    fn write_manifest(&self, entries: impl IntoIterator<Item = (RecordId, ManifestEntry)>) {
        let manifest = VaultManifest::new(VaultId::new_random(), 1, entries.into_iter().collect()).unwrap();
        std::fs::write(
            self.path(&StateFileName::manifest()),
            seal_manifest(&identity(), &manifest).unwrap(),
        )
        .unwrap();
    }

    /// A vault holding one record per name; returns the records' IDs by name.
    fn vault(name: &str, names: &[&str]) -> (Self, BTreeMap<String, RecordId>) {
        let fixture = Self::new(name);
        let records: Vec<_> = names.iter().map(|name| record(name)).collect();
        fixture.write_manifest(records.iter().map(|r| fixture.write_record(r)));
        (fixture, records.iter().map(|r| (r.name().as_str().to_owned(), r.id())).collect())
    }

    fn open(&self) -> (Result<(Vault, OpenReport), VaultError>, Vec<Captured>) {
        capture_logs(|| Vault::open(&self.lock, &OsFs, identity()))
    }
}

/// One event a [`Capture`] saw.
#[derive(Debug)]
pub(super) struct Captured {
    pub(super) level: Level,
    fields: BTreeMap<&'static str, String>,
}

impl Captured {
    pub(super) fn field(&self, name: &str) -> &str {
        self.fields
            .get(name)
            .map(String::as_str)
            .unwrap_or_else(|| panic!("no field {name} in {self:?}"))
    }
}

/// A subscriber that keeps every event's level and fields, so tests can check what reaches the log. It is small
/// enough that a `tracing-subscriber` dev-dependency would add more than it saves.
#[derive(Default, Clone)]
struct Capture(Arc<Mutex<Vec<Captured>>>);

struct Fields<'a>(&'a mut BTreeMap<&'static str, String>);

impl Visit for Fields<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
        self.0.insert(field.name(), format!("{value:?}"));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name(), value.to_owned());
    }
}

impl Subscriber for Capture {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
        span::Id::from_u64(1)
    }

    fn record(&self, _: &span::Id, _: &span::Record<'_>) {}

    fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}

    fn event(&self, event: &Event<'_>) {
        let mut fields = BTreeMap::new();
        event.record(&mut Fields(&mut fields));
        self.0.lock().unwrap().push(Captured {
            level: *event.metadata().level(),
            fields,
        });
    }

    fn enter(&self, _: &span::Id) {}

    fn exit(&self, _: &span::Id) {}
}

/// The global subscriber of the test binary: it drops every event, but marks every callsite's interest "sometimes".
///
/// `tracing` caches each callsite's interest globally when the callsite is first hit. Hit on a thread with no
/// subscriber while no subscriber exists anywhere, it is cached as "never", and a [`Capture`] on another thread then
/// misses its events. With this as the global default, interest is never "never", so each event asks the subscriber
/// current on its own thread.
struct PerEvent;

impl Subscriber for PerEvent {
    fn register_callsite(&self, _: &'static Metadata<'static>) -> Interest {
        Interest::sometimes()
    }

    fn enabled(&self, _: &Metadata<'_>) -> bool {
        false
    }

    fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
        span::Id::from_u64(1)
    }

    fn record(&self, _: &span::Id, _: &span::Record<'_>) {}

    fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}

    fn event(&self, _: &Event<'_>) {}

    fn enter(&self, _: &span::Id) {}

    fn exit(&self, _: &span::Id) {}
}

/// Installs [`PerEvent`] once; every vault test calls it before its first vault call, so no callsite is hit first.
pub(super) fn init_test_tracing() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        // Only this function sets a global default in this test binary, so the call cannot fail.
        let _ = tracing::dispatcher::set_global_default(Dispatch::new(PerEvent));
    });
}

pub(super) fn capture_logs<T>(f: impl FnOnce() -> T) -> (T, Vec<Captured>) {
    init_test_tracing();
    let capture = Capture::default();
    let out = tracing::subscriber::with_default(capture.clone(), f);
    let events = std::mem::take(&mut *capture.0.lock().unwrap());
    (out, events)
}

pub(super) fn assert_no_secret_logged(events: &[Captured], names: &[&str]) {
    let text = format!("{events:?}");
    names
        .iter()
        .for_each(|name| assert!(!text.contains(&secret(name)), "{name}'s secret was logged: {text}"));
}

fn damage(pairs: &[(&str, RecordDamage)]) -> BTreeMap<CredentialName, RecordDamage> {
    pairs.iter().map(|(name, damage)| (n(name), *damage)).collect()
}

#[test]
fn a_healthy_vault_loads_every_record() {
    let (fixture, _) = Fixture::vault("vault-healthy", &["fx_key", "brave"]);
    let (opened, events) = fixture.open();
    let (vault, report) = opened.unwrap();
    assert_eq!(report, OpenReport::default());
    assert!(events.is_empty(), "{events:?}");
    let origins = [(n("api.fx-key.example"), Port::HTTPS)].into();
    assert_eq!(
        vault.entry(&n("fx_key")),
        CatalogEntry::Usable {
            kind: CredentialKind::Static,
            origins
        }
    );
    assert!(matches!(vault.material(&n("brave")), Some(CredentialMaterial::Static { .. })));
    assert_eq!(vault.entry(&n("venice")), CatalogEntry::Unknown);
    assert!(vault.material(&n("venice")).is_none());
    assert_eq!(vault.manifest().entries().len(), 2);
}

#[test]
fn each_damaged_record_takes_down_only_itself() {
    let names = ["keep", "deleted", "swapped", "flipped"];
    let (fixture, ids) = Fixture::vault("vault-damaged", &names);
    std::fs::remove_file(fixture.record_path(ids["deleted"])).unwrap();
    std::fs::write(fixture.record_path(ids["swapped"]), sealed(&record("intruder"))).unwrap();
    let flipped = fixture.record_path(ids["flipped"]);
    let mut bytes = std::fs::read(&flipped).unwrap();
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0x10;
    std::fs::write(&flipped, bytes).unwrap();

    let (opened, events) = fixture.open();
    let (vault, report) = opened.unwrap();
    let expected = [
        ("deleted", RecordDamage::Missing),
        ("flipped", RecordDamage::Substituted),
        ("swapped", RecordDamage::Substituted),
    ];
    assert_eq!(report.damaged(), &damage(&expected));
    assert!(report.unindexed().is_empty());
    assert!(matches!(vault.entry(&n("keep")), CatalogEntry::Usable { .. }));
    assert!(vault.material(&n("keep")).is_some());
    expected.iter().for_each(|(name, _)| {
        assert_eq!(vault.entry(&n(name)), CatalogEntry::Unusable, "{name}");
        assert!(vault.material(&n(name)).is_none(), "{name}");
    });
    // Events follow record ID order, which is random, so match them up by credential name.
    let by_name: BTreeMap<_, _> = events.iter().map(|e| (e.field("credential").to_owned(), e)).collect();
    assert_eq!((events.len(), by_name.len()), (3, 3), "{events:?}");
    expected.iter().for_each(|(name, damage)| {
        let event = by_name[*name];
        assert_eq!(event.level, Level::ERROR);
        assert_eq!(event.field("record_id"), ids[*name].to_string());
        assert_eq!(event.field("file"), StateFileName::record(&ids[*name]).as_str());
        assert_eq!(event.field("reason"), damage.to_string());
        assert_eq!(event.field("remediation"), damage.remediation());
        assert!(!event.field("cause").is_empty());
    });
    assert_no_secret_logged(&events, &[&names[..], &["intruder"]].concat());
}

#[test]
fn substitution_is_caught_by_digest_record_id_or_name() {
    let fixture = Fixture::new("vault-substituted");
    let resealed = record("resealed");
    let (_, stale_entry) = fixture.write_record(&resealed);
    fixture.write_record(&resealed);
    // The manifest vouches for these files' exact bytes, but they hold another record ID or another name.
    let other_id = fixture.write_file(RecordId::new_random(), "other_id", &sealed(&record("other_id")));
    let renamed_id = RecordId::new_random();
    let renamed = fixture.write_file(
        renamed_id,
        "renamed",
        &sealed(&record_with_id(renamed_id, "impostor", "api.example")),
    );
    fixture.write_manifest([(resealed.id(), stale_entry), other_id, renamed]);

    let (opened, events) = fixture.open();
    let (_, report) = opened.unwrap();
    let substituted = ["other_id", "renamed", "resealed"].map(|name| (name, RecordDamage::Substituted));
    assert_eq!(report.damaged(), &damage(&substituted));
    assert_eq!(events.iter().filter(|e| e.level == Level::ERROR).count(), 3);
    assert_no_secret_logged(&events, &["resealed", "other_id", "impostor"]);
}

#[test]
fn a_foreign_record_under_a_listed_id_is_substituted() {
    let fixture = Fixture::new("vault-foreign");
    let genuine = record("fx_key");
    let entry = fixture.write_record(&genuine);
    fixture.write_manifest([entry]);
    // Encrypted to the vault key with the same record ID and name, but not the bytes the vault wrote.
    std::fs::write(fixture.record_path(genuine.id()), sealed(&genuine)).unwrap();

    let (opened, events) = fixture.open();
    let (_, report) = opened.unwrap();
    assert_eq!(report.damaged(), &damage(&[("fx_key", RecordDamage::Substituted)]));
    assert_no_secret_logged(&events, &["fx_key"]);
}

#[test]
fn a_file_whose_digest_differs_is_never_decrypted() {
    let fixture = Fixture::new("vault-never-decrypted");
    let id = RecordId::new_random();
    let (_, entry) = fixture.write_file(id, "fx_key", &sealed(&record_with_id(id, "fx_key", "api.fx.example")));
    fixture.write_manifest([(id, entry)]);
    // Not an age file at all: decrypting it would fail, so a digest cause shows the check ran first and decryption never did.
    std::fs::write(fixture.record_path(id), b"not an age file").unwrap();

    let (opened, events) = fixture.open();
    let (_, report) = opened.unwrap();
    assert_eq!(report.damaged(), &damage(&[("fx_key", RecordDamage::Substituted)]));
    assert_eq!(events[0].field("cause"), "the file's digest differs from its manifest entry");
}

#[test]
fn a_file_matching_its_digest_that_does_not_open_is_unreadable() {
    let fixture = Fixture::new("vault-matching-garbage");
    let garbage = fixture.write_file(RecordId::new_random(), "fx_key", b"not an age file");
    fixture.write_manifest([garbage]);

    let (opened, events) = fixture.open();
    let (_, report) = opened.unwrap();
    assert_eq!(report.damaged(), &damage(&[("fx_key", RecordDamage::Unreadable)]));
    assert!(events[0].field("cause").contains("does not decrypt"), "{events:?}");
}

#[test]
fn a_planted_record_is_unindexed_and_never_loaded() {
    let (fixture, _) = Fixture::vault("vault-planted", &["fx_key"]);
    let planted = record("planted");
    let file = StateFileName::record(&planted.id());
    std::fs::write(fixture.path(&file), sealed(&planted)).unwrap();

    let (opened, events) = fixture.open();
    let (vault, report) = opened.unwrap();
    assert_eq!(report.unindexed(), &[file.clone()].into());
    assert!(report.damaged().is_empty());
    assert_eq!(vault.entry(&n("planted")), CatalogEntry::Unknown);
    assert!(vault.material(&n("planted")).is_none());
    assert!(fixture.path(&file).exists());
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!((events[0].level, events[0].field("file")), (Level::WARN, file.as_str()));
    assert_no_secret_logged(&events, &["fx_key", "planted"]);
}

#[test]
fn a_corrupt_manifest_fails_the_whole_open() {
    let (fixture, _) = Fixture::vault("vault-manifest", &["fx_key"]);
    let path = fixture.path(&StateFileName::manifest());
    let mut bytes = std::fs::read(&path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    std::fs::write(&path, bytes).unwrap();

    let (opened, events) = fixture.open();
    let error = opened.unwrap_err();
    let expected = SharedStateDamage::Manifest(ManifestError::Damaged);
    assert_eq!(
        error,
        VaultError::SharedStateDamaged {
            file: StateFileName::manifest(),
            damage: expected
        }
    );
    assert!(error.to_string().contains("may require recovery"), "{error}");
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!((events[0].level, events[0].field("file")), (Level::ERROR, "manifest.age"));
    assert!(events[0].field("message").contains("recovery may be required"));
    assert_no_secret_logged(&events, &["fx_key"]);
}

#[test]
fn a_missing_manifest_is_uninitialized_only_without_records() {
    let empty = Fixture::new("vault-empty");
    let (opened, events) = empty.open();
    assert_eq!(opened.unwrap_err(), VaultError::NotInitialized);
    assert!(events.is_empty(), "{events:?}");

    let (orphaned, _) = Fixture::vault("vault-orphaned", &["fx_key"]);
    std::fs::remove_file(orphaned.path(&StateFileName::manifest())).unwrap();
    let (opened, events) = orphaned.open();
    let damage = SharedStateDamage::MissingWithRecords;
    assert_eq!(
        opened.unwrap_err(),
        VaultError::SharedStateDamaged {
            file: StateFileName::manifest(),
            damage
        }
    );
    assert_eq!(events[0].level, Level::ERROR);
}

/// Records the limit of every bounded read, and otherwise is the real filesystem.
#[derive(Default)]
struct BoundSpy(Mutex<Vec<(PathBuf, u64)>>);

impl StoreFs for BoundSpy {
    type File = std::fs::File;

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
        self.0.lock().unwrap().push((path.to_path_buf(), max_len));
        OsFs.read_bounded(path, max_len)
    }
}

#[test]
fn an_oversized_record_is_unreadable_and_never_read_in_full() {
    let fixture = Fixture::new("vault-oversized");
    let len = usize::try_from(MAX_RECORD_FILE_LEN).unwrap() + 1;
    let oversized = fixture.write_file(RecordId::new_random(), "huge", &vec![0x61; len]);
    let path = fixture.record_path(oversized.0);
    fixture.write_manifest([oversized]);

    let spy = BoundSpy::default();
    let (opened, events) = capture_logs(|| Vault::open(&fixture.lock, &spy, identity()));
    let (vault, report) = opened.unwrap();
    assert_eq!(report.damaged(), &damage(&[("huge", RecordDamage::Unreadable)]));
    assert_eq!(vault.entry(&n("huge")), CatalogEntry::Unusable);
    assert!(spy.0.lock().unwrap().contains(&(path, MAX_RECORD_FILE_LEN)));
    assert!(events[0].field("cause").contains("longer than"), "{events:?}");
}

#[test]
fn a_missing_record_makes_only_its_routes_unavailable() {
    let fixture = Fixture::new("vault-activate");
    let records = [
        ("fx_key", "api.fx.example"),
        ("venice", "api.venice.ai"),
        ("brave", "api.search.brave.com"),
    ]
    .map(|(name, host)| record_with_id(RecordId::new_random(), name, host));
    fixture.write_manifest(records.iter().map(|r| fixture.write_record(r)));
    std::fs::remove_file(fixture.record_path(records[1].id())).unwrap();

    let (opened, _) = fixture.open();
    let (vault, _) = opened.unwrap();
    let config = ValidatedConfig::try_from(ParsedConfig::from_toml(SPEC_EXAMPLE.as_bytes()).unwrap()).unwrap();
    let policy = activate(&config, &Capabilities::default(), &vault).unwrap();
    assert_eq!(policy.unavailable_routes(), &[n::<RouteName>("venice")].into());
    assert!(policy.is_available(&n("fx")) && policy.is_available(&n("brave")));
}

#[test]
fn debug_output_holds_no_secret() {
    let (fixture, ids) = Fixture::vault("vault-debug", &["fx_key", "broken"]);
    std::fs::remove_file(fixture.record_path(ids["broken"])).unwrap();
    let (opened, _) = fixture.open();
    let (vault, report) = opened.unwrap();
    let debug = format!("{vault:?} {report:?}");
    assert!(!debug.contains(&secret("fx_key")) && !debug.contains("SECRET"), "{debug}");
    assert!(
        debug.contains("fx_key") && debug.contains("broken") && debug.contains("Missing"),
        "{debug}"
    );
}
