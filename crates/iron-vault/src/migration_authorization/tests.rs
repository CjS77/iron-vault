use std::time::Duration;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use iron_vault_store::{CheckUnavailable, EnvelopeError, PassphraseCheckError, RecipientKey, VaultId};
use static_assertions::assert_not_impl_any;
use tokio::time::{Instant, advance};
use zeroize::Zeroizing;

use super::*;
use crate::admin::protocol::OwnerInput;

/// The `age` specification's example recipient, which the design's summary shows.
const RECIPIENT_A: &str = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p";
/// The X25519 public key of the scalar `[7; 32]`, Bech32-encoded under `age`.
const RECIPIENT_B: &str = "age1zwlyl6h27gzv0lfntr7fcqrjrzqazap8sy5zylkxwneh7llf0dksu37mwt";
const VAULT: [u8; 16] = [
    0x7c, 0x9e, 0x66, 0x79, 0x74, 0x25, 0x40, 0xde, 0x94, 0x4b, 0xe0, 0x7f, 0xc1, 0xf9, 0x0a, 0xe7,
];

assert_not_impl_any!(MigrationAuthorization: Clone, Copy);
assert_not_impl_any!(MigrationChallenge: Clone, Copy);
assert_not_impl_any!(AuthorizedMigration: Clone, Copy);

fn vault() -> VaultId {
    VaultId::from_bytes(VAULT).unwrap()
}

fn other_vault() -> VaultId {
    VaultId::from_bytes([
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x41, 0x11, 0x91, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    ])
    .unwrap()
}

fn add(text: &str) -> MigrationOperation {
    MigrationOperation::AddRecipient(text.parse::<RecipientKey>().unwrap())
}

fn nonce() -> [u8; 32] {
    std::array::from_fn(|i| u8::try_from(i).unwrap())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A challenge issued 1.5 s after `origin`, so the encoded times are 1500 and 121500 ms.
fn challenge_at(origin: Instant, vault_id: VaultId, operation: MigrationOperation, nonce: [u8; 32]) -> MigrationChallenge {
    MigrationChallenge::new(vault_id, operation, nonce, origin, origin + Duration::from_millis(1500))
}

/// Issues a challenge into a fresh slot at `origin` and takes it straight back, as a method's caller does.
fn taken(operation: MigrationOperation) -> (PendingMigration, MigrationChallenge) {
    let now = Instant::now();
    let mut pending = PendingMigration::new(now);
    let digest = pending.issue(vault(), operation, now, nonce()).unwrap();
    let challenge = pending.take(&digest, now).unwrap();
    (pending, challenge)
}

// Known answers computed independently with Python's `hashlib.blake2b(encoding, digest_size=32,
// person=b"iv-migration-v1")` over the encoding the design's table lays out.
#[test]
fn the_digest_of_an_export_challenge_matches_its_known_answer() {
    let origin = Instant::now();
    let challenge = challenge_at(origin, vault(), MigrationOperation::Export, nonce());
    let encoding = challenge.canonical_encoding();
    let expected = [
        hex(&VAULT),
        "01".to_owned(),
        "0000000000000000".to_owned(),
        hex(&nonce()),
        "00000000000005dc".to_owned(),
        "000000000001da9c".to_owned(),
    ]
    .concat();
    assert_eq!(hex(&encoding), expected);
    assert_eq!(
        hex(challenge.binding_digest().as_bytes()),
        "a08ff6ae7c0ae97e717a04bdefbb3e5131d4a91aaf4ffe0bdad817a777318b03"
    );
}

#[test]
fn the_digest_of_an_add_recipient_challenge_matches_its_known_answer() {
    let origin = Instant::now();
    let challenge = challenge_at(origin, vault(), add(RECIPIENT_A), nonce());
    let encoding = challenge.canonical_encoding();
    assert_eq!(encoding.len(), 16 + 1 + 8 + RECIPIENT_A.len() + 32 + 8 + 8);
    assert_eq!(&encoding[16..25], &[0x02, 0, 0, 0, 0, 0, 0, 0, 62]);
    assert_eq!(&encoding[25..87], RECIPIENT_A.as_bytes());
    assert_eq!(
        hex(challenge.binding_digest().as_bytes()),
        "fecff4e3b35aea097cc146da589403b63f37919570ad6ef0010d151fd440e72c"
    );
}

#[test]
fn the_digest_changes_with_every_field() {
    let origin = Instant::now();
    let base = challenge_at(origin, vault(), add(RECIPIENT_A), nonce()).binding_digest();
    let mut other_nonce = nonce();
    other_nonce[31] ^= 1;
    let later = MigrationChallenge::new(vault(), add(RECIPIENT_A), nonce(), origin, origin + Duration::from_millis(1501));
    [
        challenge_at(origin, other_vault(), add(RECIPIENT_A), nonce()),
        challenge_at(origin, vault(), MigrationOperation::Export, nonce()),
        challenge_at(origin, vault(), add(RECIPIENT_B), nonce()),
        challenge_at(origin, vault(), add(RECIPIENT_A), other_nonce),
        later,
    ]
    .iter()
    .for_each(|changed| assert_ne!(changed.binding_digest(), base, "{changed:?}"));
}

#[test]
fn debug_shows_only_the_operation_and_the_expiry() {
    let (_, challenge) = taken(MigrationOperation::Export);
    let shown = format!("{challenge:?}");
    assert!(shown.contains("operation: Export") && shown.contains("expires_at"), "{shown}");
    ["vault_id", "nonce", "issued_at", "origin"]
        .iter()
        .for_each(|hidden| assert!(!shown.contains(hidden), "{shown} shows {hidden}"));
    let authorization = format!("{:?}", MigrationAuthorization::proved(challenge));
    assert!(
        authorization.contains("operation: Export") && !authorization.contains("nonce"),
        "{authorization}"
    );
}

#[test]
fn labels_are_the_audit_events_own() {
    assert_eq!(MigrationOperation::Export.label(), "export");
    assert_eq!(add(RECIPIENT_A).label(), "add_recipient");
    let labels = [
        MigrationRefusal::Expired,
        MigrationRefusal::NotPending,
        MigrationRefusal::BindingMismatch,
        MigrationRefusal::Denied(OwnerRefusal::WrongSecret),
        MigrationRefusal::Denied(OwnerRefusal::NotThisVault),
        MigrationRefusal::AttemptsCoolingDown(AttemptsCoolingDown { retry_after: 30 }),
        MigrationRefusal::WrongState(ServiceState::Locked),
        MigrationRefusal::Unavailable,
    ]
    .map(MigrationRefusal::label);
    assert_eq!(
        labels,
        [
            "expired",
            "not_pending",
            "binding_mismatch",
            "wrong_passphrase",
            "not_this_vault",
            "rate_limited",
            "locked",
            "unavailable"
        ]
    );
    assert_eq!(VaultPassphraseMethod::new(|_| Ok(())).label(), "vault_passphrase");
}

#[test]
fn a_challenge_is_taken_once() {
    let now = Instant::now();
    let mut pending = PendingMigration::new(now);
    let digest = pending.issue(vault(), MigrationOperation::Export, now, nonce()).unwrap();
    assert!(pending.take(&digest, now).is_ok());
    assert!(!pending.is_pending());
    assert_eq!(pending.take(&digest, now).unwrap_err(), MigrationRefusal::NotPending);
}

#[test]
fn a_take_naming_another_challenge_is_refused_and_retires_the_pending_one() {
    let now = Instant::now();
    let mut pending = PendingMigration::new(now);
    let digest = pending.issue(vault(), MigrationOperation::Export, now, nonce()).unwrap();
    let other = challenge_at(now, vault(), MigrationOperation::Export, [0xaa; 32]).binding_digest();
    assert_eq!(pending.take(&other, now).unwrap_err(), MigrationRefusal::NotPending);
    assert_eq!(pending.take(&digest, now).unwrap_err(), MigrationRefusal::NotPending);
}

#[test]
fn a_second_issue_is_refused_while_one_is_pending_and_leaves_the_first() {
    let now = Instant::now();
    let mut pending = PendingMigration::new(now);
    let first = pending.issue(vault(), MigrationOperation::Export, now, nonce()).unwrap();
    assert_eq!(pending.issue(vault(), add(RECIPIENT_A), now, [0xaa; 32]), Err(ChallengeBusy));
    let challenge = pending.take(&first, now).unwrap();
    assert_eq!(challenge.operation(), &MigrationOperation::Export);
}

#[tokio::test(start_paused = true)]
async fn an_expired_challenge_blocks_issue_until_it_is_taken() {
    let now = Instant::now();
    let mut pending = PendingMigration::new(now);
    let first = pending.issue(vault(), MigrationOperation::Export, now, nonce()).unwrap();
    advance(CHALLENGE_LIFETIME * 2).await;
    assert_eq!(
        pending.issue(vault(), MigrationOperation::Export, Instant::now(), [0xaa; 32]),
        Err(ChallengeBusy)
    );
    assert_eq!(pending.take(&first, Instant::now()).unwrap_err(), MigrationRefusal::Expired);
    assert!(
        pending
            .issue(vault(), MigrationOperation::Export, Instant::now(), [0xaa; 32])
            .is_ok()
    );
}

#[test]
fn issue_is_allowed_again_after_take_or_retire() {
    let now = Instant::now();
    let mut pending = PendingMigration::new(now);
    let first = pending.issue(vault(), MigrationOperation::Export, now, nonce()).unwrap();
    pending.take(&first, now).unwrap();
    pending.issue(vault(), MigrationOperation::Export, now, [0xaa; 32]).unwrap();
    pending.retire();
    assert!(!pending.is_pending());
    assert!(pending.issue(vault(), MigrationOperation::Export, now, [0xbb; 32]).is_ok());
}

#[test]
fn a_retired_challenge_cannot_be_taken() {
    let now = Instant::now();
    let mut pending = PendingMigration::new(now);
    let digest = pending.issue(vault(), MigrationOperation::Export, now, nonce()).unwrap();
    pending.retire();
    assert_eq!(pending.take(&digest, now).unwrap_err(), MigrationRefusal::NotPending);
}

/// Takes a challenge issued now after `elapsed`, on the paused clock.
async fn take_after(elapsed: Duration) -> Result<MigrationChallenge, MigrationRefusal> {
    let now = Instant::now();
    let mut pending = PendingMigration::new(now);
    let digest = pending.issue(vault(), MigrationOperation::Export, now, nonce()).unwrap();
    advance(elapsed).await;
    let taken = pending.take(&digest, Instant::now());
    assert!(!pending.is_pending(), "a take always empties the slot");
    taken
}

#[tokio::test(start_paused = true)]
async fn take_is_allowed_before_the_expiry_and_refused_at_and_after_it() {
    assert!(take_after(CHALLENGE_LIFETIME - Duration::from_millis(1)).await.is_ok());
    assert_eq!(take_after(CHALLENGE_LIFETIME).await.unwrap_err(), MigrationRefusal::Expired);
    assert_eq!(
        take_after(CHALLENGE_LIFETIME + Duration::from_secs(1)).await.unwrap_err(),
        MigrationRefusal::Expired
    );
}

/// Consumes an `Export` authorization proved now after `elapsed`, on the paused clock.
async fn authorize_after(elapsed: Duration) -> Result<AuthorizedMigration, MigrationRefusal> {
    let (_, challenge) = taken(MigrationOperation::Export);
    let authorization = MigrationAuthorization::proved(challenge);
    advance(elapsed).await;
    authorization.authorize(vault(), &MigrationOperation::Export, Instant::now())
}

#[tokio::test(start_paused = true)]
async fn authorize_is_allowed_before_the_expiry_and_refused_at_and_after_it() {
    let authorized = authorize_after(CHALLENGE_LIFETIME - Duration::from_millis(1)).await.unwrap();
    assert_eq!(authorized.operation(), &MigrationOperation::Export);
    assert_eq!(authorize_after(CHALLENGE_LIFETIME).await.unwrap_err(), MigrationRefusal::Expired);
    assert_eq!(
        authorize_after(CHALLENGE_LIFETIME + Duration::from_secs(1)).await.unwrap_err(),
        MigrationRefusal::Expired
    );
}

#[test]
fn an_authorization_permits_only_its_own_vault_operation_and_destination() {
    let refused = |proved: MigrationOperation, vault_id: VaultId, consumed: MigrationOperation| {
        let (_, challenge) = taken(proved);
        MigrationAuthorization::proved(challenge)
            .authorize(vault_id, &consumed, Instant::now())
            .unwrap_err()
    };
    [
        (MigrationOperation::Export, vault(), add(RECIPIENT_A)),
        (add(RECIPIENT_A), vault(), MigrationOperation::Export),
        (add(RECIPIENT_A), vault(), add(RECIPIENT_B)),
        (MigrationOperation::Export, other_vault(), MigrationOperation::Export),
        (add(RECIPIENT_A), other_vault(), add(RECIPIENT_A)),
    ]
    .into_iter()
    .for_each(|(proved, vault_id, consumed)| assert_eq!(refused(proved, vault_id, consumed), MigrationRefusal::BindingMismatch));
}

#[tokio::test(start_paused = true)]
async fn a_mismatch_is_reported_before_the_expiry() {
    let (_, challenge) = taken(add(RECIPIENT_A));
    let authorization = MigrationAuthorization::proved(challenge);
    advance(CHALLENGE_LIFETIME * 2).await;
    let refusal = authorization.authorize(vault(), &add(RECIPIENT_B), Instant::now()).unwrap_err();
    assert_eq!(refusal, MigrationRefusal::BindingMismatch);
}

#[test]
fn an_authorization_for_a_recipient_authorizes_that_recipient() {
    let (_, challenge) = taken(add(RECIPIENT_A));
    let authorized = MigrationAuthorization::proved(challenge)
        .authorize(vault(), &add(RECIPIENT_A), Instant::now())
        .unwrap();
    assert_eq!(
        authorized.operation().destination().map(ToString::to_string).as_deref(),
        Some(RECIPIENT_A)
    );
}

fn input(bytes: &[u8]) -> OwnerInput {
    OwnerInput::new(Zeroizing::new(bytes.to_vec()))
}

/// Proves a fresh `Export` challenge with a passphrase method whose store check answers `answer`.
async fn prove_with(answer: Result<(), PassphraseCheckError>) -> Result<MigrationAuthorization, MethodRefusal> {
    let method = VaultPassphraseMethod::new(move |_| answer.clone());
    let (_, challenge) = taken(MigrationOperation::Export);
    prove_challenge(&method, challenge, input(b"correct horse")).await
}

#[tokio::test]
async fn a_proof_yields_an_authorization_for_the_challenge_it_proved() {
    let authorization = prove_with(Ok(())).await.unwrap();
    assert!(
        authorization
            .authorize(vault(), &MigrationOperation::Export, Instant::now())
            .is_ok()
    );
}

#[tokio::test]
async fn the_store_check_maps_to_owner_refusals_or_unavailable() {
    let unavailable = PassphraseCheckError::Unavailable(CheckUnavailable::PassphraseEnvelope(EnvelopeError::Malformed));
    assert_eq!(
        prove_with(Err(PassphraseCheckError::WrongPassphrase)).await.unwrap_err(),
        MethodRefusal::Owner(OwnerRefusal::WrongSecret)
    );
    assert_eq!(
        prove_with(Err(PassphraseCheckError::NotThisVault)).await.unwrap_err(),
        MethodRefusal::Owner(OwnerRefusal::NotThisVault)
    );
    assert_eq!(prove_with(Err(unavailable)).await.unwrap_err(), MethodRefusal::Unavailable);
}

#[tokio::test]
async fn empty_or_non_utf8_input_is_a_wrong_secret_and_never_reaches_the_store() {
    let checked = Arc::new(AtomicBool::new(false));
    let seen = Arc::clone(&checked);
    let method = VaultPassphraseMethod::new(move |_| {
        seen.store(true, Ordering::SeqCst);
        Ok(())
    });
    for typed in [b"".as_slice(), &[0xff, 0xfe]] {
        let (_, challenge) = taken(MigrationOperation::Export);
        let refusal = prove_challenge(&method, challenge, input(typed)).await.unwrap_err();
        assert_eq!(refusal, MethodRefusal::Owner(OwnerRefusal::WrongSecret));
    }
    assert!(
        !checked.load(Ordering::SeqCst),
        "the store check ran on input that cannot be the passphrase"
    );
}

#[test]
fn a_method_refusal_ends_as_its_migration_refusal() {
    assert_eq!(
        MigrationRefusal::from(MethodRefusal::Owner(OwnerRefusal::NotThisVault)),
        MigrationRefusal::Denied(OwnerRefusal::NotThisVault)
    );
    assert_eq!(MigrationRefusal::from(MethodRefusal::Unavailable), MigrationRefusal::Unavailable);
}
