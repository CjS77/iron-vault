//! The real helper against `swtpm`, the software TPM (`design/tpm-approval-signer.md` "Testing").
//!
//! Start an emulator and name it in `IRON_VAULT_SWTPM`, then run the ignored tests:
//!
//! ```sh
//! swtpm socket --tpm2 --tpmstate dir="$state" --server type=tcp,port=2321 --ctrl type=tcp,port=2322 \
//!     --flags not-need-init,startup-clear &
//! IRON_VAULT_SWTPM=swtpm:host=127.0.0.1,port=2321 cargo test -p iron-vault-tpm-signer --features tpm -- --ignored
//! ```
//!
//! The tests change the emulator's dictionary-attack settings with `tpm2_dictionarylockout` and clear it with
//! `tpm2_clear`, so never point `IRON_VAULT_SWTPM` at a real TPM. They take turns on the one emulator.

// Test support: a failure to reach the emulator or an unexpected answer fails the test.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::str::FromStr;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use iron_vault_tpm_protocol::{PUBLIC_KEY_LEN, Request, Response, SignRequest, TpmApprovalPin, TpmAuthValue, TpmKeyParts, read_frame};
use p256::ecdsa::signature::Verifier;
use tss_esapi::Context;
use tss_esapi::constants::tss::{TPM2_HMAC_SESSION_FIRST, TPM2_POLICY_SESSION_FIRST, TPM2_TRANSIENT_FIRST};
use tss_esapi::constants::{CapabilityType, PropertyTag};
use tss_esapi::structures::{CapabilityData, Public, PublicBuffer};
use tss_esapi::tcti_ldr::TctiNameConf;
use tss_esapi::traits::UnMarshall;

const APPROVER: [u8; 16] = *b"0123456789abcdef";
const PIN: &str = "correct horse";

/// The emulator, held by one test at a time.
static EMULATOR: Mutex<()> = Mutex::new(());

struct Swtpm {
    tcti: String,
    _turn: MutexGuard<'static, ()>,
}

/// The emulator, with no failures counted and settings the helper accepts: 32 tries, a 600-second interval.
fn swtpm() -> Swtpm {
    let turn = EMULATOR.lock().unwrap_or_else(PoisonError::into_inner);
    let tcti = std::env::var("IRON_VAULT_SWTPM").expect("IRON_VAULT_SWTPM names the swtpm TCTI");
    let tpm = Swtpm { tcti, _turn: turn };
    tpm.set_da(32, 600);
    tpm
}

impl Swtpm {
    /// Resets the lockout counter and sets the dictionary-attack parameters, with the empty lockout authorization.
    fn set_da(&self, max_tries: u32, interval: u32) {
        self.tool("tpm2_dictionarylockout", &["--clear-lockout"]);
        let (max_tries, interval) = (format!("--max-tries={max_tries}"), format!("--recovery-time={interval}"));
        self.tool(
            "tpm2_dictionarylockout",
            &["--setup-parameters", &max_tries, &interval, "--lockout-recovery-time=1"],
        );
    }

    /// `TPM2_Clear`: a new storage seed, so every key the emulator made before stops loading.
    fn clear(&self) {
        self.tool("tpm2_clear", &["--auth-hierarchy=l"]);
    }

    /// Sets the owner hierarchy's authorization, as another OS might, until the guard drops: the tests share the
    /// emulator, so a failing assertion must not leave it set.
    fn set_owner_auth(&self) -> OwnerAuth<'_> {
        self.tool("tpm2_changeauth", &["--object-context=owner", OWNER_AUTH]);
        OwnerAuth(self)
    }

    fn tool(&self, tool: &str, args: &[&str]) {
        let status = Command::new(tool).args(args).env("TPM2TOOLS_TCTI", &self.tcti).status().unwrap();
        assert!(status.success(), "{tool} {args:?}: {status}");
    }

    fn context(&self) -> Context {
        Context::new(TctiNameConf::from_str(&self.tcti).unwrap()).unwrap()
    }

    fn lockout_counter(&self) -> u32 {
        let (data, _) = self
            .context()
            .get_capability(CapabilityType::TpmProperties, PropertyTag::LockoutCounter.into(), 1)
            .unwrap();
        let CapabilityData::TpmProperties(properties) = data else {
            panic!("{data:?}")
        };
        properties.find(PropertyTag::LockoutCounter).unwrap().value()
    }

    /// The handles of one kind still in the emulator: it has no resource manager, so a handle the helper left behind
    /// stays.
    fn handles(&self, first: u32) -> usize {
        let (data, _) = self.context().get_capability(CapabilityType::Handles, first, 64).unwrap();
        let CapabilityData::Handles(handles) = data else {
            panic!("{data:?}")
        };
        handles.len()
    }

    /// One helper instance's answer to `request`, from the current account.
    fn ask(&self, request: &Request) -> Response {
        let (mut ours, child) = self.spawn(&current_user());
        ours.write_all(&request.encode().unwrap()).unwrap();
        let mut answer = Vec::new();
        ours.read_to_end(&mut answer).unwrap();
        assert!(child.wait_with_output().unwrap().status.success());
        Response::decode(&read_frame(&mut answer.as_slice()).unwrap()).unwrap()
    }

    /// The helper started as systemd starts it, with the connection on standard input and output.
    fn spawn(&self, peer_user: &str) -> (UnixStream, std::process::Child) {
        let (ours, theirs) = UnixStream::pair().unwrap();
        let input = OwnedFd::from(theirs.try_clone().unwrap());
        let child = Command::new(env!("CARGO_BIN_EXE_iron-vault-tpm-signer"))
            .args(["--tcti", &self.tcti, "--peer-user", peer_user])
            .stdin(Stdio::from(input))
            .stdout(Stdio::from(OwnedFd::from(theirs)))
            .spawn()
            .unwrap();
        (ours, child)
    }

    fn create(&self, pin: &str) -> (TpmKeyParts, [u8; PUBLIC_KEY_LEN]) {
        match self.ask(&Request::Create { auth: auth(pin) }) {
            Response::Created { key, public_key } => (key, public_key),
            other => panic!("{other:?}"),
        }
    }

    fn sign(&self, pin: &str, key: &TpmKeyParts, pinned_key: [u8; PUBLIC_KEY_LEN], message: &[u8]) -> Response {
        self.ask(&Request::Sign(SignRequest {
            auth: auth(pin),
            key: key.clone(),
            pinned_key,
            message: message.to_vec(),
        }))
    }
}

const OWNER_AUTH: &str = "another-os";

/// The owner authorization [`Swtpm::set_owner_auth`] set; dropping it restores the empty one.
struct OwnerAuth<'a>(&'a Swtpm);

impl Drop for OwnerAuth<'_> {
    fn drop(&mut self) {
        self.0.tool(
            "tpm2_changeauth",
            &["--object-context=owner", &format!("--object-auth={OWNER_AUTH}")],
        );
    }
}

fn auth(pin: &str) -> TpmAuthValue {
    TpmAuthValue::derive(&APPROVER, &TpmApprovalPin::new(pin.to_owned()))
}

/// The name of the account running the tests, which the helper is told to answer.
fn current_user() -> String {
    let uid = rustix::process::getuid().as_raw().to_string();
    std::fs::read_to_string("/etc/passwd")
        .unwrap()
        .lines()
        .map(|line| line.split(':').collect::<Vec<_>>())
        .find(|fields| fields.get(2) == Some(&uid.as_str()))
        .map(|fields| fields[0].to_owned())
        .unwrap()
}

/// A message of the right magic, version and length to be one the helper signs.
fn payload(magic: &[u8; 4], len: usize, fill: u8) -> Vec<u8> {
    [magic.as_slice(), &[1], &vec![fill; len - 5]].concat()
}

fn approval_payload() -> Vec<u8> {
    payload(b"IVAP", 89, 7)
}

fn signature(response: Response) -> [u8; 64] {
    match response {
        Response::Signed { signature } => signature,
        other => panic!("{other:?}"),
    }
}

/// Verifies as the service's approval verifier does (`verify_p256` in `iron-vault-store`'s `approval/verify.rs`, which
/// is private; keep the two in step): ECDSA P-256 over the SHA-256 of the message, and `s` low.
fn assert_verifies(public_key: &[u8; PUBLIC_KEY_LEN], message: &[u8], signature: &[u8; 64]) {
    let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key).unwrap();
    let signature = p256::ecdsa::Signature::from_slice(signature).unwrap();
    assert!(signature.normalize_s().is_none(), "high s");
    key.verify(message, &signature).unwrap();
}

#[test]
#[ignore = "needs swtpm named by IRON_VAULT_SWTPM"]
fn a_created_key_signs_the_three_payloads() {
    let tpm = swtpm();
    let (key, public_key) = tpm.create(PIN);
    [payload(b"IVAP", 89, 1), payload(b"IVPP", 69, 2), payload(b"IVMA", 37, 3)]
        .iter()
        .for_each(|message| assert_verifies(&public_key, message, &signature(tpm.sign(PIN, &key, public_key, message))));
    assert_eq!(tpm.lockout_counter(), 0);
}

#[test]
#[ignore = "needs swtpm named by IRON_VAULT_SWTPM"]
fn the_key_counts_wrong_pins_and_has_no_policy() {
    let tpm = swtpm();
    let (key, _) = tpm.create(PIN);
    let public = Public::try_from(PublicBuffer::unmarshall(&key.public).unwrap()).unwrap();
    let attributes = public.object_attributes();
    assert!(!attributes.no_da() && attributes.user_with_auth() && attributes.fixed_tpm() && attributes.sign_encrypt());
    assert!(!attributes.admin_with_policy() && !attributes.decrypt() && !attributes.restricted());
    assert!(public.auth_policy().value().is_empty());
}

#[test]
#[ignore = "needs swtpm named by IRON_VAULT_SWTPM"]
fn other_messages_are_refused_without_spending_a_try() {
    let tpm = swtpm();
    let (key, public_key) = tpm.create(PIN);
    let mut version_two = approval_payload();
    version_two[4] = 2;
    [
        payload(b"IVAP", 88, 0),
        payload(b"IVPP", 89, 0),
        version_two,
        b"any digest".to_vec(),
        Vec::new(),
    ]
    .iter()
    .for_each(|message| assert_eq!(tpm.sign("wrong pin", &key, public_key, message), Response::RefusedMessage));
    assert_eq!(tpm.lockout_counter(), 0);
}

#[test]
#[ignore = "needs swtpm named by IRON_VAULT_SWTPM"]
fn a_wrong_pin_spends_one_try() {
    let tpm = swtpm();
    let (key, public_key) = tpm.create(PIN);
    assert_eq!(tpm.sign("wrong pin", &key, public_key, &approval_payload()), Response::WrongPin);
    assert_eq!(tpm.lockout_counter(), 1);
    signature(tpm.sign(PIN, &key, public_key, &approval_payload()));
}

/// Six tries: the helper spends three and keeps three for everyone else, even for the right PIN.
#[test]
#[ignore = "needs swtpm named by IRON_VAULT_SWTPM"]
fn the_helper_never_spends_the_reserve() {
    let tpm = swtpm();
    tpm.set_da(6, 600);
    let (key, public_key) = tpm.create(PIN);
    (0..3).for_each(|_| assert_eq!(tpm.sign("wrong pin", &key, public_key, &approval_payload()), Response::WrongPin));
    let locked_out = Response::LockedOut { wait_seconds: 600 };
    assert_eq!(tpm.sign("wrong pin", &key, public_key, &approval_payload()), locked_out);
    assert_eq!(tpm.sign(PIN, &key, public_key, &approval_payload()), locked_out);
    assert_eq!(tpm.lockout_counter(), 3);
}

#[test]
#[ignore = "needs swtpm named by IRON_VAULT_SWTPM"]
fn weak_dictionary_attack_settings_are_refused() {
    let tpm = swtpm();
    let (key, public_key) = tpm.create(PIN);
    [(1, 600), (32, 599), (32, 0)].iter().for_each(|&(max_tries, interval)| {
        tpm.set_da(max_tries, interval);
        assert_eq!(tpm.ask(&Request::Create { auth: auth(PIN) }), Response::WeakDaSettings);
        assert_eq!(tpm.sign(PIN, &key, public_key, &approval_payload()), Response::WeakDaSettings);
    });
}

/// An owner authorization the helper does not have fails the primary, not the PIN: `08`, never `02`.
#[test]
#[ignore = "needs swtpm named by IRON_VAULT_SWTPM"]
fn an_owner_authorization_is_a_tpm_error_not_a_wrong_pin() {
    let tpm = swtpm();
    let (key, public_key) = tpm.create(PIN);
    let _owner_auth = tpm.set_owner_auth();
    [
        tpm.ask(&Request::Create { auth: auth(PIN) }),
        tpm.sign(PIN, &key, public_key, &approval_payload()),
    ]
    .iter()
    .for_each(|response| assert!(matches!(response, Response::TpmError { code } if *code != 0), "{response:?}"));
}

#[test]
#[ignore = "needs swtpm named by IRON_VAULT_SWTPM"]
fn a_key_from_before_a_clear_is_not_this_tpms() {
    let tpm = swtpm();
    let (key, public_key) = tpm.create(PIN);
    tpm.clear();
    tpm.set_da(32, 600);
    assert_eq!(tpm.sign(PIN, &key, public_key, &approval_payload()), Response::NotThisTpm);
}

/// A blob swapped for another key the same TPM made, even under the same PIN, cannot sign for the pinned approver.
#[test]
#[ignore = "needs swtpm named by IRON_VAULT_SWTPM"]
fn a_swapped_blob_is_refused_before_authorization() {
    let tpm = swtpm();
    let (_, pinned) = tpm.create(PIN);
    let (planted, _) = tpm.create(PIN);
    assert_eq!(tpm.sign("wrong pin", &planted, pinned, &approval_payload()), Response::KeyMismatch);
    assert_eq!(tpm.lockout_counter(), 0);
    let garbled = TpmKeyParts {
        public: vec![0, 4, 1, 2, 3, 4],
        ..planted
    };
    assert_eq!(tpm.sign(PIN, &garbled, pinned, &approval_payload()), Response::Malformed);
}

#[test]
#[ignore = "needs swtpm named by IRON_VAULT_SWTPM"]
fn another_account_is_refused_before_its_request_is_read() {
    let tpm = swtpm();
    let started = Instant::now();
    let (mut ours, child) = tpm.spawn("root");
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(started.elapsed() < Duration::from_secs(4), "the helper waited for a request");
    let mut answer = Vec::new();
    ours.read_to_end(&mut answer).unwrap();
    assert!(answer.is_empty());
}

#[test]
#[ignore = "needs swtpm named by IRON_VAULT_SWTPM"]
fn every_path_flushes_its_handles() {
    let tpm = swtpm();
    let (key, public_key) = tpm.create(PIN);
    (0..100).for_each(|n| {
        let pin = if n % 10 == 0 { "wrong pin" } else { PIN };
        tpm.sign(pin, &key, public_key, &approval_payload());
    });
    tpm.sign(PIN, &key, [4; PUBLIC_KEY_LEN], &approval_payload());
    let leftovers = [TPM2_TRANSIENT_FIRST, TPM2_HMAC_SESSION_FIRST, TPM2_POLICY_SESSION_FIRST].map(|first| tpm.handles(first));
    assert_eq!(leftovers, [0, 0, 0]);
}
