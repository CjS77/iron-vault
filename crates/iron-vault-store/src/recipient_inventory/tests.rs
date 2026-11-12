use std::io;

use secrecy::SecretString;

use super::*;
use crate::fault_fs::{FaultFs, FsOp};
use crate::test_dir::TestDir;
use crate::{OsFs, RecipientIdentity, sweep_stale_temps};

const VAULT: &str = "3f2b8c1e-5d4a-4e6f-9a7b-1c2d3e4f5a6b";
const OTHER_VAULT: &str = "7c9e6679-7425-40de-944b-e07fc1f90ae7";
/// Secret keys of the X25519 key bytes 01..20, 21..40 and 41..60: the documented example's three recipients.
const SECRETS: [&str; 3] = [
    "AGE-SECRET-KEY-1QYPQXPQ9QCRSSZG2PVXQ6RS0ZQG3YYC5Z5TPWXQERGD3C8G7RUSQGPQYEE",
    "AGE-SECRET-KEY-1YY3ZXFP9YCNJS2F29VKZ6T30XQCNYVE5X5MRWWPE8GANC0F78AQQ2X9KSF",
    "AGE-SECRET-KEY-1G9PYX3Z9GER5SJ22FDXY6NJ02PG4Y56524T9WKZETFD4CH27TASQJTETDY",
];

fn vault_id(text: &str) -> VaultId {
    VaultId::from_bytes(*text.parse::<crate::RecordId>().unwrap().as_bytes()).unwrap()
}

fn key(secret: &str) -> RecipientKey {
    RecipientIdentity::parse(&SecretString::from(secret.to_owned()))
        .unwrap()
        .recipient_key()
}

fn entry(key: RecipientKey, role: RecipientRole, label: &str, at: u64) -> RecipientEntry {
    RecipientEntry::new(
        key,
        role,
        RecipientLabel::new(label).unwrap(),
        UtcSecond::from_unix_seconds(at).unwrap(),
    )
}

/// Returns the documented example's entries, one per role.
fn example_entries() -> Vec<RecipientEntry> {
    [
        (RecipientRole::Operational, "vault passphrase", 1_793_959_965),
        (RecipientRole::Recovery, "recovery key", 1_793_959_965),
        (RecipientRole::Added, "alice laptop 2026", 1_794_000_000),
    ]
    .into_iter()
    .zip(SECRETS)
    .map(|((role, label, at), secret)| entry(key(secret), role, label, at))
    .collect()
}

fn inventory_of(entries: Vec<RecipientEntry>) -> RecipientInventory {
    RecipientInventory::new(vault_id(VAULT), [0xab; 32], entries).unwrap()
}

fn example() -> RecipientInventory {
    inventory_of(example_entries())
}

/// A payload assembled by hand so each refusal test breaks exactly one field.
struct Payload(Vec<u8>);

impl Payload {
    fn header(count: u64) -> Self {
        Payload([&b"IVRP\x01"[..], vault_id(VAULT).as_bytes(), &[0xab; 32], &count.to_be_bytes()].concat())
    }

    fn raw(mut self, bytes: &[u8]) -> Self {
        self.0.extend_from_slice(bytes);
        self
    }

    fn field(self, bytes: &[u8]) -> Self {
        self.raw(&(bytes.len() as u64).to_be_bytes()).raw(bytes)
    }

    fn entry_with(self, key: &[u8], role: u8, label: &[u8], at: u64) -> Self {
        self.field(key).raw(&[role]).field(label).raw(&at.to_be_bytes())
    }

    fn entry(self, secret: &str) -> Self {
        self.entry_with(key(secret).to_string().as_bytes(), 3, b"x", 1)
    }

    /// Two valid entries in ascending key order.
    fn valid() -> Self {
        let mut secrets = SECRETS[..2].to_vec();
        secrets.sort_by_key(|s| key(s));
        secrets.into_iter().fold(Self::header(2), Self::entry)
    }

    fn decode(&self) -> Result<RecipientInventory, RecipientInventoryError> {
        encoding::decode(&self.0)
    }
}

#[test]
fn round_trip_with_every_role() {
    let inventory = example();
    let roles: Vec<_> = inventory.entries().map(RecipientEntry::role).collect();
    [RecipientRole::Operational, RecipientRole::Recovery, RecipientRole::Added]
        .iter()
        .for_each(|role| assert!(roles.contains(role)));
    assert_eq!(encoding::decode(&encoding::encode(&inventory)), Ok(inventory.clone()));
    let identity = VaultIdentity::generate();
    let file = seal_recipient_inventory(&identity, &inventory).unwrap();
    assert_eq!(open_recipient_inventory(&identity, &file), Ok(inventory));
}

#[test]
fn host_unlock_is_role_6_and_round_trips() {
    assert_eq!(RecipientRole::from_code(6), Some(RecipientRole::HostUnlock));
    assert_eq!(
        (RecipientRole::HostUnlock.code(), RecipientRole::HostUnlock.name()),
        (6, "host-unlock")
    );
    let entries = example_entries()
        .into_iter()
        .chain([entry(key(SECRETS[2]), RecipientRole::HostUnlock, "host unlock", 1_794_000_001)])
        .filter(|entry| entry.role() != RecipientRole::Added);
    let inventory = inventory_of(entries.collect());
    assert_eq!(encoding::decode(&encoding::encode(&inventory)), Ok(inventory));
}

#[test]
fn encoding_is_independent_of_insertion_order() {
    let forward = inventory_of(example_entries());
    let backward = inventory_of(example_entries().into_iter().rev().collect());
    assert_eq!(encoding::encode(&forward), encoding::encode(&backward));
    let keys: Vec<_> = forward.entries().map(|e| e.key().clone()).collect();
    assert!(keys.is_sorted());
    assert_eq!(forward.recipient_set().iter().cloned().collect::<Vec<_>>(), keys);
}

/// Checks the [example](../../../../design/storage-formats.md#recipient-inventory-payload-v1) byte for byte.
#[test]
fn documented_example_encodes() {
    let expected = "49565250013f2b8c1e5d4a4e6f9a7b1c2d3e4f5a6babababababababababababababababababababababababababababababababab0000000000000003000000000000003e616765317137336865307135797a6675336436346d736433703672766b736e72776a6b3364323539386d67746d6c717439777264723337713276726e37320100000000000000107661756c742070617373706872617365000000006aeda81d000000000000003e61676531747035366c617a73326a746e396a6132613430396d37646e70666b36783839737534367a68743236366a7336773638333565617363757471647802000000000000000c7265636f76657279206b6579000000006aeda81d000000000000003e61676531766a63737276777368656467777039617137386533396771726c71726172356c6a353330727a78617a32786573336b3573336e71786463363936030000000000000011616c696365206c6170746f702032303236000000006aee4480";
    let bytes: Vec<u8> = (0..expected.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&expected[i..i + 2], 16).unwrap())
        .collect();
    assert_eq!(encoding::encode(&example()), bytes);
    assert_eq!(encoding::decode(&bytes), Ok(example()));
}

#[test]
fn construction_refuses_too_few_too_many_and_repeated_keys() {
    let one = example_entries().remove(0);
    let build = |entries: Vec<RecipientEntry>| RecipientInventory::new(vault_id(VAULT), [0; 32], entries);
    assert_eq!(build(vec![one.clone()]), Err(RecipientInventoryError::TooFew { count: 1 }));
    assert_eq!(build(vec![one.clone(), one]), Err(RecipientInventoryError::DuplicateKey));
    let many = (0..=MAX_RECIPIENTS)
        .map(|_| entry(RecipientIdentity::generate().recipient_key(), RecipientRole::Added, "k", 0))
        .collect();
    assert_eq!(build(many), Err(RecipientInventoryError::TooMany { limit: MAX_RECIPIENTS }));
}

#[test]
fn a_full_inventory_fits_the_size_limit() {
    let entries = (0..MAX_RECIPIENTS)
        .map(|_| {
            entry(
                RecipientIdentity::generate().recipient_key(),
                RecipientRole::Added,
                &"é".repeat(32),
                253_402_300_799,
            )
        })
        .collect();
    let identity = VaultIdentity::generate();
    let file = seal_recipient_inventory(&identity, &inventory_of(entries)).unwrap();
    assert!(file.len() < 10_300, "{}", file.len());
    assert!(open_recipient_inventory(&identity, &file).is_ok());
}

#[test]
fn valid_hand_built_payload_decodes() {
    assert_eq!(Payload::valid().decode().unwrap().entries().len(), 2);
}

#[test]
fn decode_refuses_a_wrong_magic() {
    let mut bytes = Payload::valid().0;
    bytes[..4].copy_from_slice(b"IVMP");
    assert_eq!(encoding::decode(&bytes), Err(RecipientInventoryError::BadMagic));
}

#[test]
fn decode_refuses_an_unknown_version() {
    let mut bytes = Payload::valid().0;
    bytes[4] = 2;
    assert_eq!(encoding::decode(&bytes), Err(RecipientInventoryError::UnknownVersion(2)));
}

#[test]
fn decode_refuses_truncation_at_every_length() {
    let bytes = Payload::valid().0;
    (0..bytes.len()).for_each(|len| {
        assert!(
            matches!(
                encoding::decode(&bytes[..len]),
                Err(RecipientInventoryError::Truncated | RecipientInventoryError::LengthPastEnd)
            ),
            "length {len}"
        );
    });
}

#[test]
fn decode_refuses_trailing_bytes() {
    assert_eq!(Payload::valid().raw(&[0]).decode(), Err(RecipientInventoryError::TrailingBytes));
}

#[test]
fn decode_refuses_descending_keys() {
    let mut secrets = SECRETS[..2].to_vec();
    secrets.sort_by_key(|s| std::cmp::Reverse(key(s)));
    let payload = secrets.into_iter().fold(Payload::header(2), Payload::entry);
    assert_eq!(payload.decode(), Err(RecipientInventoryError::UnsortedEntries));
}

#[test]
fn decode_refuses_a_repeated_key() {
    let payload = Payload::header(2).entry(SECRETS[0]).entry(SECRETS[0]);
    assert_eq!(payload.decode(), Err(RecipientInventoryError::DuplicateKey));
}

#[test]
fn decode_refuses_too_many_and_too_few_entries() {
    assert_eq!(Payload::header(65).decode(), Err(RecipientInventoryError::TooMany { limit: 64 }));
    assert_eq!(
        Payload::header(u64::MAX).decode(),
        Err(RecipientInventoryError::TooMany { limit: 64 })
    );
    assert_eq!(
        Payload::header(1).entry(SECRETS[0]).decode(),
        Err(RecipientInventoryError::TooFew { count: 1 })
    );
}

#[test]
fn decode_refuses_a_key_that_is_not_canonical() {
    let text = key(SECRETS[0]).to_string();
    let bad: [Vec<u8>; 4] = [
        text.to_uppercase().into_bytes(),
        text.as_bytes()[..61].to_vec(),
        b"not a key".to_vec(),
        [&text.as_bytes()[..61], &[0xff]].concat(),
    ];
    bad.iter().for_each(|bytes| {
        let payload = Payload::header(2).entry_with(bytes, 3, b"x", 1).entry(SECRETS[1]);
        assert_eq!(payload.decode(), Err(RecipientInventoryError::InvalidKey));
    });
}

#[test]
fn decode_refuses_reserved_and_unknown_roles() {
    [0, 4, 5, 7, 255].iter().for_each(|code| {
        let payload = Payload::header(2).entry_with(key(SECRETS[0]).to_string().as_bytes(), *code, b"x", 1);
        assert_eq!(payload.decode(), Err(RecipientInventoryError::UnknownRole(*code)));
    });
}

#[test]
fn decode_refuses_bad_labels() {
    let text = key(SECRETS[0]).to_string();
    let label = |bytes: &[u8]| Payload::header(2).entry_with(text.as_bytes(), 3, bytes, 1).decode();
    assert_eq!(label(&[0xff]), Err(RecipientInventoryError::LabelNotUtf8));
    assert_eq!(label(b""), Err(RecipientInventoryError::InvalidLabel(RecipientLabelError::Empty)));
    assert_eq!(
        label(b"a\nb"),
        Err(RecipientInventoryError::InvalidLabel(RecipientLabelError::ControlOrFormat))
    );
}

#[test]
fn decode_refuses_a_time_outside_the_utc_second_range() {
    let payload = Payload::header(2).entry_with(key(SECRETS[0]).to_string().as_bytes(), 3, b"x", 253_402_300_800);
    assert_eq!(payload.decode(), Err(RecipientInventoryError::BadTime));
}

#[test]
fn label_rule() {
    let ok = ["alice laptop 2026", "paper copy, safe", "é", &"a".repeat(64), "a b"];
    ok.iter().for_each(|text| assert!(RecipientLabel::new(text).is_ok(), "{text:?}"));
    assert_eq!(RecipientLabel::new(""), Err(RecipientLabelError::Empty));
    assert_eq!(RecipientLabel::new(&"a".repeat(65)), Err(RecipientLabelError::TooLong));
    assert_eq!(RecipientLabel::new(&"é".repeat(33)), Err(RecipientLabelError::TooLong));
    [
        "a\nb",
        "a\u{7}",
        "a\u{7f}",
        "a\u{202e}b",
        "a\u{200b}",
        "\u{feff}a",
        "a\u{ad}",
        "a\u{2066}",
    ]
    .iter()
    .for_each(|text| assert_eq!(RecipientLabel::new(text), Err(RecipientLabelError::ControlOrFormat), "{text:?}"));
    [" a", "a ", "a\u{a0}", "\u{3000}a"].iter().for_each(|text| {
        assert_eq!(
            RecipientLabel::new(text),
            Err(RecipientLabelError::SurroundingWhitespace),
            "{text:?}"
        )
    });
}

#[test]
fn payload_naming_another_vault_is_refused() {
    let identity = VaultIdentity::generate();
    let payload = encoding::encode(&example());
    let file = KIND.seal(&identity, vault_id(OTHER_VAULT), &payload).unwrap();
    assert_eq!(
        open_recipient_inventory(&identity, &file),
        Err(RecipientInventoryError::VaultIdMismatch)
    );
}

#[test]
fn a_file_for_one_vault_identity_does_not_open_with_another() {
    let file = seal_recipient_inventory(&VaultIdentity::generate(), &example()).unwrap();
    assert_eq!(
        open_recipient_inventory(&VaultIdentity::generate(), &file),
        Err(RecipientInventoryError::Damaged)
    );
}

#[test]
fn a_flipped_byte_fails_the_mac() {
    let identity = VaultIdentity::generate();
    let file = seal_recipient_inventory(&identity, &example()).unwrap();
    // Bytes 0..5 are the magic and version, read before the MAC because they decide how it is computed. From byte 5 on
    // the MAC is checked before the vault ID is parsed or anything is decrypted, so every flip is `Damaged`.
    (5..file.len()).step_by(7).for_each(|at| {
        let mut flipped = file.clone();
        flipped[at] ^= 1;
        assert!(
            matches!(open_recipient_inventory(&identity, &flipped), Err(RecipientInventoryError::Damaged)),
            "byte {at}"
        );
    });
    let mut flipped = file.clone();
    *flipped.last_mut().unwrap() ^= 1;
    assert_eq!(open_recipient_inventory(&identity, &flipped), Err(RecipientInventoryError::Damaged));
}

#[test]
fn an_oversized_file_is_refused_before_anything_else() {
    let identity = VaultIdentity::generate();
    let file = vec![0; MAX_RECIPIENT_INVENTORY_LEN + 1];
    assert_eq!(
        open_recipient_inventory(&identity, &file),
        Err(RecipientInventoryError::TooLarge {
            limit: MAX_RECIPIENT_INVENTORY_LEN
        })
    );
}

#[test]
fn a_manifest_does_not_open_as_an_inventory_and_the_reverse() {
    let identity = VaultIdentity::generate();
    let manifest = crate::seal_manifest(&identity, &crate::VaultManifest::first(vault_id(VAULT)).unwrap()).unwrap();
    assert_eq!(
        open_recipient_inventory(&identity, &manifest),
        Err(RecipientInventoryError::BadMagic)
    );
    let inventory = seal_recipient_inventory(&identity, &example()).unwrap();
    assert!(crate::open_manifest(&identity, &inventory).is_err());
    // With the magic rewritten the MAC still refuses: the two files' keys are independent.
    let relabelled = |file: &[u8], magic: &[u8; 4]| [&magic[..], &file[4..]].concat();
    assert_eq!(
        open_recipient_inventory(&identity, &relabelled(&manifest, b"IVRF")),
        Err(RecipientInventoryError::Damaged)
    );
    assert!(crate::open_manifest(&identity, &relabelled(&inventory, b"IVMF")).is_err());
}

#[test]
fn write_then_read_through_the_os_filesystem() {
    let dir = TestDir::new("recipient-inventory");
    let lock = StateDirLock::acquire(dir.path()).unwrap();
    let identity = VaultIdentity::generate();
    assert!(matches!(
        read_recipient_inventory(&lock, &OsFs, &identity),
        Err(RecipientInventoryReadError::Read(ReadError::Io {
            kind: io::ErrorKind::NotFound,
            ..
        }))
    ));
    write_recipient_inventory(&lock, &OsFs, &identity, &example()).unwrap();
    assert_eq!(read_recipient_inventory(&lock, &OsFs, &identity).unwrap(), example());
    assert!(dir.path().join("recipients.age").is_file());
}

#[test]
fn a_crash_during_the_replace_leaves_only_a_temp_file_the_sweep_removes() {
    let dir = TestDir::new("recipient-inventory-crash");
    let lock = StateDirLock::acquire(dir.path()).unwrap();
    let identity = VaultIdentity::generate();
    let fs = FaultFs::new();
    fs.fail_first(FsOp::Rename, io::ErrorKind::PermissionDenied);
    fs.fail_first(FsOp::RemoveFile, io::ErrorKind::PermissionDenied);
    assert!(write_recipient_inventory(&lock, &fs, &identity, &example()).is_err());
    // Another file's directory fsync makes the leftover temp entry durable before the power fails.
    durable_replace(&lock, &fs, &StateFileName::new("other").unwrap(), b"o").unwrap();
    fs.crash();
    assert!(fs.contents(&dir.path().join("recipients.age")).is_none());
    assert!(fs.contents(&dir.path().join(".recipients.age.tmp")).is_some());
    assert_eq!(sweep_stale_temps(&lock, &fs).unwrap(), [StateFileName::recipient_inventory()]);
    assert!(fs.contents(&dir.path().join(".recipients.age.tmp")).is_none());
    write_recipient_inventory(&lock, &fs, &identity, &example()).unwrap();
    assert_eq!(read_recipient_inventory(&lock, &fs, &identity).unwrap(), example());
}

#[test]
fn describing_changes_only_the_envelope_digest() {
    let current = example();
    let described = current.clone().describing([9; 32]);
    assert_eq!(described.envelope_digest(), &[9; 32]);
    assert!(described.entries().eq(current.entries()));
    assert_eq!(described.vault_id(), current.vault_id());
}
