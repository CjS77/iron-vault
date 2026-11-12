//! Approval verification: each check accepts the committed approval and refuses everything else with its own variant.

use ed25519_dalek::{Signer, SigningKey};
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};

use super::*;
use crate::fault_fs::FaultFs;
use crate::manifest::tests::{KAT_IDENTITY, write_first_manifest};
use crate::test_dir::TestDir;
use crate::{ApprovalPayload, ApproverId, ApproverLabel, ApproverPublicKey, SignerKind, StateDirLock, UtcSecond, VaultId, VaultIdentity};

const APPROVER_SEED: [u8; 32] = [7; 32];

fn version(v: u64) -> ApprovalVersion {
    ApprovalVersion::new(v).unwrap()
}

/// The config bytes approved as version `v`.
fn config(v: u64) -> Vec<u8> {
    format!("# config approved as version {v}\n[listener.agent]\nbind = \"127.0.0.1:8080\"\n").into_bytes()
}

fn signing_key(seed: [u8; 32]) -> SigningKey {
    SigningKey::from_bytes(&seed)
}

fn pinned(seed: [u8; 32]) -> PinnedApprover {
    let key = ApproverPublicKey::new(SignatureAlgorithm::Ed25519, signing_key(seed).verifying_key().to_bytes().to_vec()).unwrap();
    PinnedApprover::for_tests(key)
}

/// The `config.toml.sig` bytes for `payload`, signed by the key with `seed` and naming the ID [`pinned`] gives it.
fn sign(seed: [u8; 32], payload: ApprovalPayload) -> Vec<u8> {
    sign_as(pinned(seed).id(), seed, payload)
}

/// The `config.toml.sig` bytes for `payload`, signed by the key with `seed` and naming the approver `id`.
fn sign_as(id: ApproverId, seed: [u8; 32], payload: ApprovalPayload) -> Vec<u8> {
    let signature = signing_key(seed).sign(&payload.encode()).to_bytes().to_vec();
    ApprovalEnvelope::new(SignatureAlgorithm::Ed25519, id, payload, signature)
        .unwrap()
        .encode()
}

/// An approval state in a real state directory on an in-memory file system, changed only through its own operations.
struct Vault {
    _dir: TestDir,
    lock: StateDirLock,
    fs: FaultFs,
    identity: VaultIdentity,
    state: ApprovalState,
}

impl Vault {
    fn new(label: &str) -> Self {
        let dir = TestDir::new(label);
        let lock = StateDirLock::acquire(dir.path()).unwrap();
        let (fs, identity) = (FaultFs::new(), VaultIdentity::from_secret(KAT_IDENTITY));
        write_first_manifest(&lock, &fs, &identity);
        let state = ApprovalState::create(&lock, &fs, &identity, pinned(APPROVER_SEED)).unwrap();
        Self {
            _dir: dir,
            lock,
            fs,
            identity,
            state,
        }
    }

    /// Reserves the next version and returns the envelope signing `config(v)` as it, without committing it.
    fn sign_next(&mut self) -> (ApprovalVersion, Vec<u8>) {
        let v = self.state.reserve(&self.lock, &self.fs, &self.identity).unwrap();
        (v, sign(APPROVER_SEED, self.payload(v.get())))
    }

    /// Reserves, signs and commits the next version, returning its envelope: one completed approval.
    fn approve_next(&mut self) -> Vec<u8> {
        let (v, envelope) = self.sign_next();
        self.state
            .commit(&self.lock, &self.fs, &self.identity, v, ConfigDigest::of(&config(v.get())))
            .unwrap();
        envelope
    }

    /// A vault whose versions 1 to `n` are each approved and committed in turn, with every envelope.
    fn approved(label: &str, n: u64) -> (Self, Vec<Vec<u8>>) {
        let mut vault = Self::new(label);
        let envelopes = (0..n).map(|_| vault.approve_next()).collect();
        (vault, envelopes)
    }

    /// Pins a further approver whose key has `seed`, returning its ID.
    fn enroll(&mut self, seed: [u8; 32]) -> ApproverId {
        self.enroll_pinned(pinned(seed))
    }

    /// Pins `approver`, returning its ID.
    fn enroll_pinned(&mut self, approver: PinnedApprover) -> ApproverId {
        let id = approver.id();
        self.state.enroll_approver(&self.lock, &self.fs, &self.identity, approver).unwrap();
        id
    }

    /// Reserves, signs with the P-256 `key` as approver `id`, and commits the next version, returning its envelope.
    fn approve_next_p256(&mut self, key: &P256SigningKey, id: ApproverId) -> Vec<u8> {
        let v = self.state.reserve(&self.lock, &self.fs, &self.identity).unwrap();
        let envelope = sign_p256(key, id, self.payload(v.get()));
        self.state
            .commit(&self.lock, &self.fs, &self.identity, v, ConfigDigest::of(&config(v.get())))
            .unwrap();
        envelope
    }

    fn payload(&self, v: u64) -> ApprovalPayload {
        ApprovalPayload::new(self.state.vault_id(), version(v), ConfigDigest::of(&config(v)))
    }

    /// Verifies and checks the state is unchanged afterwards, whatever the outcome.
    fn verify(&self, config: &[u8], envelope: &[u8]) -> Result<VerifiedApproval, VerifyError> {
        let before = self.state.clone();
        let result = verify_approval(&self.state, config, envelope);
        assert_eq!(self.state, before, "verification changed the approval state");
        result
    }
}

#[test]
fn committed_approval_verifies() {
    let (vault, envelopes) = Vault::approved("verify-ok", 1);
    let verified = vault.verify(&config(1), &envelopes[0]).unwrap();
    assert_eq!((verified.version(), verified.digest()), (version(1), ConfigDigest::of(&config(1))));
}

#[test]
fn malformed_envelope_is_refused() {
    let (vault, envelopes) = Vault::approved("verify-malformed", 1);
    let truncated = &envelopes[0][..envelopes[0].len() - 1];
    assert!(matches!(vault.verify(&config(1), truncated), Err(VerifyError::Malformed(_))));
    assert!(matches!(vault.verify(&config(1), b""), Err(VerifyError::Malformed(_))));
}

/// An algorithm ID this build does not know is refused while decoding, before any approver is looked up.
#[test]
fn unknown_algorithm_byte_is_refused() {
    let (vault, envelopes) = Vault::approved("verify-algorithm", 1);
    let mut envelope = envelopes[0].clone();
    envelope[5] = 0x03;
    assert_eq!(
        vault.verify(&config(1), &envelope),
        Err(VerifyError::Malformed(ApprovalDecodeError::UnknownAlgorithm(0x03)))
    );
}

/// Bytes 6 to 21 of the envelope are the approver ID; byte 12 holds its UUID version.
#[test]
fn approver_id_that_is_not_version_4_is_malformed() {
    let (vault, envelopes) = Vault::approved("verify-id-version", 1);
    let mut envelope = envelopes[0].clone();
    envelope[12] = (envelope[12] & 0x0f) | 0x10;
    assert_eq!(
        vault.verify(&config(1), &envelope),
        Err(VerifyError::Malformed(ApprovalDecodeError::InvalidApproverId))
    );
}

#[test]
fn approver_that_is_not_pinned_is_refused() {
    let (vault, _) = Vault::approved("verify-other-key", 1);
    let approver = pinned([8; 32]).id();
    let envelope = sign([8; 32], vault.payload(1));
    assert_eq!(vault.verify(&config(1), &envelope), Err(VerifyError::UnknownApprover { approver }));
}

/// The approver ID is not signed; naming another pinned approver checks the signature with that approver's key, which
/// fails.
#[test]
fn envelope_naming_another_pinned_approver_fails_on_the_signature() {
    let (mut vault, _) = Vault::approved("verify-renamed", 1);
    let first = pinned(APPROVER_SEED).id();
    let other = vault.enroll([8; 32]);
    let [first_signed, other_signed] = [APPROVER_SEED, [8; 32]].map(|seed| sign(seed, vault.payload(1)));
    [(first_signed, other), (other_signed, first)]
        .into_iter()
        .for_each(|(signed, renamed)| {
            assert!(vault.verify(&config(1), &signed).is_ok());
            let decoded = ApprovalEnvelope::decode(&signed).unwrap();
            let envelope = ApprovalEnvelope::new(decoded.algorithm(), renamed, *decoded.payload(), decoded.signature().to_vec()).unwrap();
            assert_eq!(vault.verify(&config(1), &envelope.encode()), Err(VerifyError::BadSignature));
        });
}

/// Approver IDs are random, so signing with every pinned approver in turn is what covers approvers after the first.
#[test]
fn approval_signed_by_any_pinned_approver_verifies() {
    let (mut vault, _) = Vault::approved("verify-several", 1);
    let seeds = [APPROVER_SEED, [8; 32], [9; 32]];
    seeds[1..].iter().for_each(|&seed| {
        vault.enroll(seed);
    });
    assert_eq!(vault.state.approvers().len(), seeds.len());
    seeds.iter().for_each(|&seed| {
        let verified = vault.verify(&config(1), &sign(seed, vault.payload(1))).unwrap();
        assert_eq!(verified.version(), version(1));
    });
}

#[test]
fn key_that_no_approver_pins_is_refused_among_several() {
    let (mut vault, _) = Vault::approved("verify-several-other-key", 1);
    vault.enroll([8; 32]);
    vault.enroll([9; 32]);
    let envelope = sign([10; 32], vault.payload(1));
    let approver = pinned([10; 32]).id();
    assert_eq!(vault.verify(&config(1), &envelope), Err(VerifyError::UnknownApprover { approver }));
}

#[test]
fn signature_by_a_removed_approver_is_refused() {
    let (mut vault, _) = Vault::approved("verify-removed", 1);
    let removed = vault.enroll([8; 32]);
    let envelope = sign([8; 32], vault.payload(1));
    assert!(vault.verify(&config(1), &envelope).is_ok());
    vault
        .state
        .remove_approver(&vault.lock, &vault.fs, &vault.identity, removed)
        .unwrap();
    assert_eq!(
        vault.verify(&config(1), &envelope),
        Err(VerifyError::UnknownApprover { approver: removed })
    );
}

#[test]
fn every_flipped_signature_bit_is_refused() {
    let (vault, envelopes) = Vault::approved("verify-flip", 1);
    let signature_start = envelopes[0].len() - 64;
    (signature_start * 8..envelopes[0].len() * 8).for_each(|bit| {
        let mut envelope = envelopes[0].clone();
        envelope[bit / 8] ^= 1 << (bit % 8);
        assert_eq!(vault.verify(&config(1), &envelope), Err(VerifyError::BadSignature), "bit {bit}");
    });
}

/// A changed payload field fails on the signature, before the field is compared with anything.
#[test]
fn edited_payload_fails_on_the_signature_first() {
    let (vault, envelopes) = Vault::approved("verify-edited", 2);
    let edited = ApprovalEnvelope::decode(&envelopes[0]).unwrap();
    let forged = ApprovalEnvelope::new(
        SignatureAlgorithm::Ed25519,
        edited.approver_id(),
        vault.payload(2),
        edited.signature().to_vec(),
    )
    .unwrap();
    assert_eq!(vault.verify(&config(2), &forged.encode()), Err(VerifyError::BadSignature));
}

#[test]
fn approval_for_another_vault_is_refused() {
    let (vault, _) = Vault::approved("verify-vault", 1);
    let payload = ApprovalPayload::new(VaultId::new_random(), version(1), ConfigDigest::of(&config(1)));
    assert_eq!(
        vault.verify(&config(1), &sign(APPROVER_SEED, payload)),
        Err(VerifyError::WrongVault)
    );
}

#[test]
fn any_changed_config_byte_is_refused() {
    let (vault, envelopes) = Vault::approved("verify-config", 1);
    (0..config(1).len()).for_each(|at| {
        let mut changed = config(1);
        changed[at] ^= 0x01;
        assert_eq!(vault.verify(&changed, &envelopes[0]), Err(VerifyError::ConfigChanged), "byte {at}");
    });
}

#[test]
fn nothing_committed_is_refused() {
    let mut vault = Vault::new("verify-nothing");
    let (_, envelope) = vault.sign_next();
    assert_eq!(
        vault.verify(&config(1), &envelope),
        Err(VerifyError::NothingCommitted { version: version(1) })
    );
}

#[test]
fn superseded_pair_is_refused() {
    let (vault, envelopes) = Vault::approved("verify-superseded", 5);
    let refused = vault.verify(&config(3), &envelopes[2]);
    assert_eq!(
        refused,
        Err(VerifyError::Superseded {
            version: version(3),
            committed: version(5)
        })
    );
    assert!(refused.unwrap_err().to_string().contains("version 3, but version 5 is committed"));
}

#[test]
fn signed_but_uncommitted_pair_is_refused() {
    let (mut vault, _) = Vault::approved("verify-uncommitted", 5);
    let (v, envelope) = vault.sign_next();
    assert_eq!(v, version(6));
    assert_eq!(
        vault.verify(&config(6), &envelope),
        Err(VerifyError::Uncommitted {
            version: version(6),
            committed: version(5)
        })
    );
}

/// Only a misbehaving signer signs one version twice, but the committed digest still decides.
#[test]
fn committed_version_with_another_digest_is_refused() {
    let (vault, _) = Vault::approved("verify-digest", 1);
    let other = b"a config signed as version 1 but never committed";
    let envelope = sign(
        APPROVER_SEED,
        ApprovalPayload::new(vault.state.vault_id(), version(1), ConfigDigest::of(other)),
    );
    assert_eq!(
        vault.verify(other, &envelope),
        Err(VerifyError::DigestNotCommitted { version: version(1) })
    );
}

/// Checks the [release check](../../../../../design/iron-vault-specification.md#19-v0-user-acceptance): after approving v2, putting v1's
/// config and signature back fails.
#[test]
fn restored_older_config_and_signature_fail_after_a_newer_approval() {
    let mut vault = Vault::new("verify-release");
    let v1 = vault.approve_next();
    assert!(vault.verify(&config(1), &v1).is_ok());
    let v2 = vault.approve_next();
    assert!(vault.verify(&config(2), &v2).is_ok());
    assert_eq!(
        vault.verify(&config(1), &v1),
        Err(VerifyError::Superseded {
            version: version(1),
            committed: version(2)
        })
    );
}

#[test]
fn error_messages_carry_no_key_or_signature_bytes() {
    let (vault, envelopes) = Vault::approved("verify-messages", 1);
    let key_hex: String = vault.state.approvers()[0]
        .public_key()
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let mut flipped = envelopes[0].clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 1;
    let message = vault.verify(&config(1), &flipped).unwrap_err().to_string();
    assert!(!message.contains(&key_hex[..16]), "{message}");
    assert_eq!(
        message,
        "the config approval signature does not verify against the named approver's key"
    );
}

/// The private half of the RFC 6979 A.2.5 P-256 key, whose public half the storage formats' TPM examples pin.
const RFC6979_P256_X: &str = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";

/// The order `n` of the P-256 group: a signature scalar must lie in `1..n`.
const P256_ORDER: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";

fn rfc6979_p256() -> P256SigningKey {
    P256SigningKey::from_slice(&unhex(RFC6979_P256_X)).unwrap()
}

fn p256_key(seed: u8) -> P256SigningKey {
    P256SigningKey::from_slice(&[seed; 32]).unwrap()
}

/// `key` pinned as a `tpm` approver with the ID [`ApproverId::for_tests`] gives it.
fn pinned_tpm(key: &P256SigningKey) -> PinnedApprover {
    let public = key.verifying_key().to_encoded_point(false).as_bytes().to_vec();
    let public = ApproverPublicKey::new(SignatureAlgorithm::EcdsaP256, public).unwrap();
    let label = ApproverLabel::new("laptop TPM").unwrap();
    PinnedApprover::new(ApproverId::for_tests(&public), SignerKind::Tpm, public, label, UtcSecond::EPOCH).unwrap()
}

/// `config.toml.sig` bytes for `payload` signed by the P-256 `key` as approver `id`, with `s` in its low form as a TPM
/// approver's helper writes it.
fn sign_p256(key: &P256SigningKey, id: ApproverId, payload: ApprovalPayload) -> Vec<u8> {
    let signature: P256Signature = p256::ecdsa::signature::Signer::sign(key, &payload.encode());
    let low = signature.normalize_s().unwrap_or(signature);
    ApprovalEnvelope::new(SignatureAlgorithm::EcdsaP256, id, payload, low.to_bytes().to_vec())
        .unwrap()
        .encode()
}

/// The envelope with its signature replaced by `signature`, which must be 64 bytes.
fn with_signature(envelope: &[u8], signature: &[u8]) -> Vec<u8> {
    [&envelope[..envelope.len() - 64], signature].concat()
}

/// `n − s` for the 32-byte big-endian `s`: the other signature ECDSA accepts for the same `r`.
fn negate_mod_n(s: &[u8]) -> Vec<u8> {
    let n = unhex(P256_ORDER);
    let mut borrow = 0i16;
    let mut out: Vec<u8> = n
        .iter()
        .zip(s)
        .rev()
        .map(|(&a, &b)| {
            let diff = i16::from(a) - i16::from(b) - borrow;
            borrow = i16::from(diff < 0);
            (diff + 256 * borrow) as u8
        })
        .collect();
    out.reverse();
    out
}

fn unhex(hex: &str) -> Vec<u8> {
    crate::approval::encoding::tests::unhex(hex)
}

/// A vault whose first approver is the software one and whose second is a `tpm` approver with `key`, with version 1
/// signed by the `tpm` approver and committed.
fn tpm_approved(label: &str, key: &P256SigningKey) -> (Vault, ApproverId, Vec<u8>) {
    let mut vault = Vault::new(label);
    let id = vault.enroll_pinned(pinned_tpm(key));
    let envelope = vault.approve_next_p256(key, id);
    (vault, id, envelope)
}

/// RFC 6979 A.2.5, message `sample` with SHA-256: the RFC's `s` is the high one, so only `n − s` is accepted.
#[test]
fn rfc6979_sample_signature_verifies_only_with_low_s() {
    let key = *rfc6979_p256().verifying_key();
    let r = unhex("efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716");
    let high = unhex("f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8");
    let low = negate_mod_n(&high);
    assert_eq!(low, unhex("0834e36ad29a83bf2bc9385e491d6099c8fdf9d1ed67aa7ea5f51f93782857a9"));
    assert_eq!(verify_p256(&key, b"sample", &[&r[..], &low].concat()), Ok(()));
    assert_eq!(
        verify_p256(&key, b"sample", &[&r[..], &high].concat()),
        Err(VerifyError::BadSignature)
    );
    assert_eq!(
        verify_p256(&key, b"samplf", &[&r[..], &low].concat()),
        Err(VerifyError::BadSignature)
    );
}

/// The storage formats' P-256 envelope example carries a real signature by the key its TPM state example pins.
#[test]
fn documented_p256_envelope_verifies_against_the_documented_tpm_approver() {
    use crate::approval::encoding::tests::{P256_KEY_HEX, P256_SIGNATURE_HEX, documented_envelope};
    let envelope = ApprovalEnvelope::decode(&documented_envelope(2)).unwrap();
    assert_eq!(envelope.signature(), &unhex(P256_SIGNATURE_HEX)[..]);
    let documented = pinned_tpm(&rfc6979_p256());
    assert_eq!(documented.public_key().as_bytes(), &unhex(P256_KEY_HEX)[..]);
    let approver = PinnedApprover::new(
        envelope.approver_id(),
        SignerKind::Tpm,
        *documented.public_key(),
        documented.label().clone(),
        UtcSecond::EPOCH,
    )
    .unwrap();
    assert_eq!(verify_with(&approver, &envelope), Ok(()));
    let other = pinned_tpm(&p256_key(9));
    assert_eq!(verify_with(&other, &envelope), Err(VerifyError::BadSignature));
}

#[test]
fn approval_signed_by_a_tpm_approver_verifies() {
    let key = p256_key(5);
    let (vault, id, envelope) = tpm_approved("verify-tpm", &key);
    assert_eq!(vault.state.approvers().len(), 2);
    let verified = vault.verify(&config(1), &envelope).unwrap();
    assert_eq!((verified.version(), verified.approver()), (version(1), id));
}

/// A signature by another P-256 key, or over another payload, fails; so does every flipped signature bit.
#[test]
fn p256_signature_by_another_key_or_over_other_bytes_is_refused() {
    let key = p256_key(5);
    let (mut vault, id, envelope) = tpm_approved("verify-tpm-refused", &key);
    let forged = sign_p256(&p256_key(6), id, vault.payload(1));
    assert_eq!(vault.verify(&config(1), &forged), Err(VerifyError::BadSignature));
    // The payload field starts at byte 30; the signature is checked before any of its fields is compared.
    (30..30 + 89).for_each(|at| {
        let mut edited = envelope.clone();
        edited[at] ^= 0x01;
        let refused = vault.verify(&config(1), &edited);
        assert!(
            matches!(refused, Err(VerifyError::BadSignature | VerifyError::Malformed(_))),
            "byte {at}: {refused:?}"
        );
    });
    let signature = &envelope[envelope.len() - 64..];
    vault.approve_next();
    let replayed = with_signature(&sign_p256(&key, id, vault.payload(2)), signature);
    assert_eq!(vault.verify(&config(2), &replayed), Err(VerifyError::BadSignature));
    (0..64 * 8).for_each(|bit| {
        let mut flipped = signature.to_vec();
        flipped[bit / 8] ^= 1 << (bit % 8);
        let changed = with_signature(&envelope, &flipped);
        assert_eq!(vault.verify(&config(1), &changed), Err(VerifyError::BadSignature), "bit {bit}");
    });
}

/// `(r, n − s)` verifies under plain ECDSA; refusing it leaves each approval one signature encoding. Scalars outside
/// `1..n` are refused before any curve arithmetic.
#[test]
fn high_s_and_out_of_range_scalars_are_refused() {
    let key = p256_key(5);
    let (vault, _, envelope) = tpm_approved("verify-tpm-high-s", &key);
    let signature = &envelope[envelope.len() - 64..];
    let (r, s) = signature.split_at(32);
    let n = unhex(P256_ORDER);
    let refused = [
        [r, &negate_mod_n(s)].concat(),
        [&[0u8; 32][..], s].concat(),
        [r, &[0u8; 32]].concat(),
        [&n[..], s].concat(),
        [r, &n[..]].concat(),
        [r, &[0xff; 32]].concat(),
    ];
    refused.iter().for_each(|bad| {
        assert_eq!(
            vault.verify(&config(1), &with_signature(&envelope, bad)),
            Err(VerifyError::BadSignature),
            "{bad:02x?}"
        );
    });
    assert!(vault.verify(&config(1), &envelope).is_ok());
}

#[test]
fn p256_signature_of_the_wrong_length_is_malformed() {
    let key = p256_key(5);
    let (vault, id, envelope) = tpm_approved("verify-tpm-length", &key);
    let truncated = [
        &envelope[..envelope.len() - 72],
        &63u64.to_be_bytes(),
        &envelope[envelope.len() - 64..][..63],
    ]
    .concat();
    assert_eq!(
        vault.verify(&config(1), &truncated),
        Err(VerifyError::Malformed(ApprovalDecodeError::SignatureLength {
            algorithm: SignatureAlgorithm::EcdsaP256,
            len: 63
        }))
    );
    assert!(vault.verify(&config(1), &sign_p256(&key, id, vault.payload(1))).is_ok());
}

/// The envelope's algorithm must be the named approver's: a P-256 envelope naming the software approver, or an
/// Ed25519 envelope naming the TPM approver, is refused before any signature check.
#[test]
fn algorithm_that_is_not_the_named_approvers_is_refused() {
    let key = p256_key(5);
    let (vault, tpm, _) = tpm_approved("verify-tpm-algorithm", &key);
    let software = pinned(APPROVER_SEED).id();
    assert_eq!(
        vault.verify(&config(1), &sign_p256(&key, software, vault.payload(1))),
        Err(VerifyError::WrongAlgorithm {
            pinned: SignatureAlgorithm::Ed25519,
            envelope: SignatureAlgorithm::EcdsaP256
        })
    );
    assert_eq!(
        vault.verify(&config(1), &sign_as(tpm, APPROVER_SEED, vault.payload(1))),
        Err(VerifyError::WrongAlgorithm {
            pinned: SignatureAlgorithm::EcdsaP256,
            envelope: SignatureAlgorithm::Ed25519
        })
    );
}
