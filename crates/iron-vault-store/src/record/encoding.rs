//! The record payload v1 encoding: the plaintext a credential file encrypts (`design/storage-formats.md`).
//!
//! The layout is hand-written rather than serde or TOML so that decoding reads each secret straight out of the caller's
//! decrypted buffer into a [`SecretString`], with no intermediate `String` left unwiped on the heap (spec §3.11).

use std::collections::BTreeSet;

use iron_vault_kinds::{CredentialMaterial, KindError};
use iron_vault_policy::{CredentialName, Host, HostError, NameError, Port, PortError};
use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;
use zeroize::Zeroizing;

use super::{CredentialRecord, Source};
use crate::permitted_origins::PermittedOrigins;
use crate::record_id::{RecordId, RecordIdError};

/// The first bytes of every record payload, so a payload of another type is never read as a record.
const MAGIC: [u8; 4] = *b"IVCR";
/// The payload version this code writes and the only one it reads.
const VERSION: u8 = 1;
/// The width of the length prefix before each variable-length field and of the origin count.
const LEN_WIDTH: usize = 8;
const TAG_STATIC: u8 = 1;
const TAG_BASIC: u8 = 2;
const TAG_DIRECT_ENTRY: u8 = 1;

/// Why a record payload cannot be decoded. No variant carries secret bytes: secret fields are named, never shown.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RecordError {
    /// The payload does not start with the record magic.
    #[error("not a credential record payload")]
    BadMagic,
    /// The payload has a version this build cannot read.
    #[error("unknown credential record payload version {0}")]
    UnknownVersion(u8),
    /// The payload ends inside a fixed-width field.
    #[error("credential record payload is truncated")]
    Truncated,
    /// A length prefix or origin count reaches past the end of the payload.
    #[error("credential record field length runs past the end of the payload")]
    LengthPastEnd,
    /// Bytes follow the last field.
    #[error("credential record payload has trailing bytes")]
    TrailingBytes,
    /// The record ID is not a random version 4 UUID.
    #[error(transparent)]
    InvalidId(#[from] RecordIdError),
    /// A text field is not UTF-8.
    #[error("credential record {field} is not UTF-8")]
    NotUtf8 {
        /// The field, such as `"password"`.
        field: &'static str,
    },
    /// The credential name breaks the name rule.
    #[error(transparent)]
    InvalidName(#[from] NameError),
    /// A permitted host is not a valid host.
    #[error(transparent)]
    InvalidHost(#[from] HostError),
    /// A permitted host is valid but not written in its canonical form, so the payload has more than one spelling.
    #[error("credential record host is not in canonical form")]
    NonCanonicalHost,
    /// A permitted port is not a valid port.
    #[error(transparent)]
    InvalidPort(#[from] PortError),
    /// The record permits no origin.
    #[error("credential record permits no origin")]
    NoOrigins,
    /// The same origin appears twice.
    #[error("credential record lists an origin twice")]
    DuplicateOrigin,
    /// The origins are not in ascending order, so the payload is not the one encoding of its record.
    #[error("credential record origins are not in ascending order")]
    UnsortedOrigins,
    /// The material tag names no known kind.
    #[error("unknown credential material tag {0}")]
    UnknownMaterialTag(u8),
    /// The material breaks its kind's rules; the inner error names the rule, never the value.
    #[error(transparent)]
    InvalidMaterial(#[from] KindError),
    /// The source tag names no known source.
    #[error("unknown credential source tag {0}")]
    UnknownSourceTag(u8),
}

/// The record's v1 payload. The same record always encodes to the same bytes, because origins are written in their
/// set order and every other field has one form.
///
/// The buffer is sized exactly before writing, so it never reallocates and leaves no unwiped copy of the secret behind.
pub fn encode(record: &CredentialRecord) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(encoded_len(record)));
    out.extend_from_slice(&MAGIC);
    out.push(VERSION);
    out.extend_from_slice(record.id.as_bytes());
    put_field(&mut out, record.name.as_str().as_bytes());
    put_material(&mut out, &record.material);
    put_origins(&mut out, &record.origins);
    out.push(source_tag(record.source));
    out
}

/// The record a v1 payload holds, validated with the same value objects that build a record any other way.
pub fn decode(payload: &[u8]) -> Result<CredentialRecord, RecordError> {
    let mut reader = Reader(payload);
    if reader.take(MAGIC.len())? != MAGIC {
        return Err(RecordError::BadMagic);
    }
    match reader.u8()? {
        VERSION => decode_v1(&mut reader),
        version => Err(RecordError::UnknownVersion(version)),
    }
}

fn decode_v1(reader: &mut Reader<'_>) -> Result<CredentialRecord, RecordError> {
    let id = RecordId::from_bytes(reader.array()?)?;
    let name = CredentialName::try_from(reader.text("name")?)?;
    let material = read_material(reader)?;
    let origins = read_origins(reader)?;
    let source = read_source(reader)?;
    if !reader.0.is_empty() {
        return Err(RecordError::TrailingBytes);
    }
    Ok(CredentialRecord::new(id, name, material, origins, source)?)
}

fn encoded_len(record: &CredentialRecord) -> usize {
    let material = match &record.material {
        CredentialMaterial::Static { key } => LEN_WIDTH + key.expose_secret().len(),
        CredentialMaterial::Basic { username, password } => 2 * LEN_WIDTH + username.expose_secret().len() + password.expose_secret().len(),
    };
    let origins: usize = record.origins.iter().map(|(host, _)| LEN_WIDTH + host.as_str().len() + 2).sum();
    MAGIC.len() + 1 + 16 + LEN_WIDTH + record.name.as_str().len() + 1 + material + LEN_WIDTH + origins + 1
}

/// Writes a length the way every prefix and count is stored. `usize` is at most 64 bits on every Rust target, so the
/// widening cast is lossless.
fn put_len(out: &mut Vec<u8>, len: usize) {
    out.extend_from_slice(&(len as u64).to_be_bytes());
}

fn put_field(out: &mut Vec<u8>, bytes: &[u8]) {
    put_len(out, bytes.len());
    out.extend_from_slice(bytes);
}

fn put_material(out: &mut Vec<u8>, material: &CredentialMaterial) {
    match material {
        CredentialMaterial::Static { key } => {
            out.push(TAG_STATIC);
            put_field(out, key.expose_secret().as_bytes());
        }
        CredentialMaterial::Basic { username, password } => {
            out.push(TAG_BASIC);
            put_field(out, username.expose_secret().as_bytes());
            put_field(out, password.expose_secret().as_bytes());
        }
    }
}

fn put_origins(out: &mut Vec<u8>, origins: &PermittedOrigins) {
    put_len(out, origins.iter().len());
    origins.iter().for_each(|(host, port)| {
        put_field(out, host.as_str().as_bytes());
        out.extend_from_slice(&port.get().to_be_bytes());
    });
}

fn source_tag(source: Source) -> u8 {
    match source {
        Source::DirectEntry => TAG_DIRECT_ENTRY,
    }
}

fn read_material(reader: &mut Reader<'_>) -> Result<CredentialMaterial, RecordError> {
    match reader.u8()? {
        TAG_STATIC => Ok(CredentialMaterial::Static {
            key: reader.secret("key")?,
        }),
        TAG_BASIC => Ok(CredentialMaterial::Basic {
            username: reader.secret("username")?,
            password: reader.secret("password")?,
        }),
        tag => Err(RecordError::UnknownMaterialTag(tag)),
    }
}

/// Reads the origins, requiring them strictly ascending so that a payload is the one encoding of its record.
fn read_origins(reader: &mut Reader<'_>) -> Result<PermittedOrigins, RecordError> {
    let count = reader.len()?;
    if count == 0 {
        return Err(RecordError::NoOrigins);
    }
    let origins = (0..count).try_fold(BTreeSet::new(), |mut origins, _| {
        let origin = read_origin(reader)?;
        match origins.last() {
            Some(last) if *last == origin => return Err(RecordError::DuplicateOrigin),
            Some(last) if *last > origin => return Err(RecordError::UnsortedOrigins),
            _ => origins.insert(origin),
        };
        Ok(origins)
    })?;
    PermittedOrigins::new(origins).map_err(|_| RecordError::NoOrigins)
}

fn read_origin(reader: &mut Reader<'_>) -> Result<(Host, Port), RecordError> {
    let text = reader.text("host")?;
    let host: Host = text.parse()?;
    if host.as_str() != text {
        return Err(RecordError::NonCanonicalHost);
    }
    let port = Port::try_from(u16::from_be_bytes(reader.array()?))?;
    Ok((host, port))
}

fn read_source(reader: &mut Reader<'_>) -> Result<Source, RecordError> {
    match reader.u8()? {
        TAG_DIRECT_ENTRY => Ok(Source::DirectEntry),
        tag => Err(RecordError::UnknownSourceTag(tag)),
    }
}

/// The unread rest of a payload. Every read borrows from the payload, so no secret byte is copied until it lands in
/// its [`SecretString`].
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], RecordError> {
        let (head, rest) = self.0.split_at_checked(n).ok_or(RecordError::Truncated)?;
        self.0 = rest;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], RecordError> {
        self.take(N)?.try_into().map_err(|_| RecordError::Truncated)
    }

    fn u8(&mut self) -> Result<u8, RecordError> {
        self.array::<1>().map(|[byte]| byte)
    }

    /// A length prefix or origin count. Neither can exceed the bytes left, since a field's bytes follow its prefix and
    /// every origin takes several bytes, so a huge value fails here rather than driving a long loop.
    fn len(&mut self) -> Result<usize, RecordError> {
        let len = u64::from_be_bytes(self.array()?);
        usize::try_from(len)
            .ok()
            .filter(|len| *len <= self.0.len())
            .ok_or(RecordError::LengthPastEnd)
    }

    fn field(&mut self) -> Result<&'a [u8], RecordError> {
        let len = self.len()?;
        self.take(len)
    }

    fn text(&mut self, field: &'static str) -> Result<&'a str, RecordError> {
        std::str::from_utf8(self.field()?).map_err(|_| RecordError::NotUtf8 { field })
    }

    /// The field as a secret: its one owned copy is the [`SecretString`], which zeroizes it on drop.
    fn secret(&mut self, field: &'static str) -> Result<SecretString, RecordError> {
        self.text(field).map(SecretString::from)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    const ID: &str = "7c9e6679-7425-40de-944b-e07fc1f90ae7";

    fn origins(pairs: &[(&str, u16)]) -> PermittedOrigins {
        let set = pairs
            .iter()
            .map(|(host, port)| (host.parse().unwrap(), Port::try_from(*port).unwrap()))
            .collect();
        PermittedOrigins::new(set).unwrap()
    }

    fn record(material: CredentialMaterial, pairs: &[(&str, u16)]) -> CredentialRecord {
        CredentialRecord::new(
            ID.parse().unwrap(),
            "fx_key".parse().unwrap(),
            material,
            origins(pairs),
            Source::DirectEntry,
        )
        .unwrap()
    }

    fn static_record() -> CredentialRecord {
        record(CredentialMaterial::Static { key: "QZJW-key".into() }, &[("api.fx.example", 443)])
    }

    fn basic_record() -> CredentialRecord {
        let material = CredentialMaterial::Basic {
            username: "alice".into(),
            password: "".into(),
        };
        record(material, &[("b.example", 443), ("a.example", 8443)])
    }

    /// Hand-assembled payloads, so each rejection test can break exactly one field.
    #[derive(Clone)]
    struct Payload(Vec<u8>);

    impl Payload {
        fn header() -> Self {
            let mut bytes = b"IVCR\x01".to_vec();
            bytes.extend_from_slice(ID.parse::<RecordId>().unwrap().as_bytes());
            Payload(bytes)
        }

        fn raw(mut self, bytes: &[u8]) -> Self {
            self.0.extend_from_slice(bytes);
            self
        }

        fn len(self, len: u64) -> Self {
            self.raw(&len.to_be_bytes())
        }

        fn field(self, bytes: &[u8]) -> Self {
            self.len(bytes.len() as u64).raw(bytes)
        }

        fn origin(self, host: &str, port: u16) -> Self {
            self.field(host.as_bytes()).raw(&port.to_be_bytes())
        }

        fn named(name: &str) -> Self {
            Self::header().field(name.as_bytes())
        }

        fn static_key(key: &[u8]) -> Self {
            Self::named("fx_key").raw(&[TAG_STATIC]).field(key)
        }

        fn with_origins(origins: &[(&str, u16)]) -> Self {
            origins
                .iter()
                .fold(Self::static_key(b"k").len(origins.len() as u64), |p, (host, port)| {
                    p.origin(host, *port)
                })
        }

        fn valid() -> Self {
            Self::with_origins(&[("api.example", 443)]).raw(&[TAG_DIRECT_ENTRY])
        }

        fn decode(&self) -> Result<CredentialRecord, RecordError> {
            decode(&self.0)
        }
    }

    fn secret(s: &SecretString) -> &str {
        s.expose_secret()
    }

    #[test]
    fn static_records_round_trip() {
        let decoded = decode(&encode(&static_record())).unwrap();
        assert_eq!((decoded.id().to_string(), decoded.name().as_str()), (ID.to_owned(), "fx_key"));
        assert_eq!(decoded.kind(), iron_vault_policy::CredentialKind::Static);
        assert!(matches!(decoded.material(), CredentialMaterial::Static { key } if secret(key) == "QZJW-key"));
        assert_eq!(decoded.origins(), static_record().origins());
        assert_eq!(decoded.source(), Source::DirectEntry);
    }

    #[test]
    fn basic_records_round_trip() {
        let decoded = decode(&encode(&basic_record())).unwrap();
        assert_eq!(decoded.kind(), iron_vault_policy::CredentialKind::Basic);
        let is_alice = |username: &SecretString, password: &SecretString| secret(username) == "alice" && secret(password).is_empty();
        assert!(matches!(decoded.material(), CredentialMaterial::Basic { username, password } if is_alice(username, password)));
        assert_eq!(decoded.origins(), basic_record().origins());
    }

    #[test]
    fn encoding_is_deterministic_and_independent_of_insertion_order() {
        let key = || CredentialMaterial::Static { key: "k".into() };
        let forward = record(key(), &[("a.example", 443), ("b.example", 443), ("a.example", 8443)]);
        let backward = record(key(), &[("a.example", 8443), ("b.example", 443), ("a.example", 443)]);
        assert_eq!(*encode(&forward), *encode(&backward));
        assert_eq!(*encode(&static_record()), *encode(&static_record()));
    }

    #[test]
    fn encoding_matches_the_documented_layout() {
        assert_eq!(*encode(&decode(&Payload::valid().0).unwrap()), Payload::valid().0);
        let expected = Payload::named("fx_key")
            .raw(&[TAG_BASIC])
            .field(b"alice")
            .field(b"")
            .len(2)
            .origin("a.example", 8443)
            .origin("b.example", 443)
            .raw(&[TAG_DIRECT_ENTRY]);
        assert_eq!(*encode(&basic_record()), expected.0);
        assert_eq!(&expected.0[..5], b"IVCR\x01");
    }

    /// The example in `design/storage-formats.md`, byte for byte.
    #[test]
    fn documented_example_decodes() {
        let hex = "49564352 01 7c9e6679742540de944be07fc1f90ae7 0000000000000006 66785f6b6579 01 0000000000000001 6b \
                   0000000000000001 000000000000000b 6170692e6578616d706c65 01bb 01";
        let bytes: Vec<u8> = hex
            .split_whitespace()
            .flat_map(|group| {
                (0..group.len())
                    .step_by(2)
                    .map(move |i| u8::from_str_radix(&group[i..i + 2], 16).unwrap())
            })
            .collect();
        assert_eq!(bytes, Payload::valid().0);
        assert_eq!(*encode(&decode(&bytes).unwrap()), bytes);
    }

    #[test]
    fn wrong_magic_and_unknown_versions_are_rejected() {
        let mut bad_magic = Payload::valid();
        bad_magic.0[0] = b'X';
        assert_eq!(bad_magic.decode().err(), Some(RecordError::BadMagic));
        let mut v2 = Payload::valid();
        v2.0[4] = 2;
        assert_eq!(v2.decode().err(), Some(RecordError::UnknownVersion(2)));
        assert_eq!(decode(b"").err(), Some(RecordError::Truncated));
    }

    #[test]
    fn every_truncation_is_rejected() {
        let full = Payload::valid().0;
        (0..full.len()).for_each(|len| {
            let err = decode(&full[..len]).err();
            assert!(
                matches!(err, Some(RecordError::Truncated | RecordError::LengthPastEnd)),
                "{len}: {err:?}"
            );
        });
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        assert_eq!(Payload::valid().raw(&[0]).decode().err(), Some(RecordError::TrailingBytes));
    }

    #[test]
    fn lengths_past_the_end_are_rejected() {
        assert_eq!(
            Payload::header().len(7).raw(b"fx_key").decode().err(),
            Some(RecordError::LengthPastEnd)
        );
        assert_eq!(Payload::header().len(u64::MAX).decode().err(), Some(RecordError::LengthPastEnd));
        assert_eq!(
            Payload::static_key(b"k").len(u64::MAX).decode().err(),
            Some(RecordError::LengthPastEnd)
        );
    }

    #[test]
    fn invalid_ids_are_rejected() {
        let mut payload = Payload::valid();
        payload.0[5..21].fill(0);
        assert_eq!(payload.decode().err(), Some(RecordError::InvalidId(RecordIdError::NotVersion4)));
    }

    #[test]
    fn invalid_names_are_rejected() {
        let payload = Payload::named("Fx")
            .raw(&[TAG_STATIC])
            .field(b"k")
            .len(1)
            .origin("api.example", 443)
            .raw(&[1]);
        assert!(matches!(payload.decode().err(), Some(RecordError::InvalidName(_))));
        let payload = Payload::header().field(&[0xff]);
        assert_eq!(payload.decode().err(), Some(RecordError::NotUtf8 { field: "name" }));
    }

    #[test]
    fn invalid_and_non_canonical_hosts_are_rejected() {
        let invalid = Payload::with_origins(&[("*.example", 443)]).raw(&[1]);
        assert_eq!(
            invalid.decode().err(),
            Some(RecordError::InvalidHost(HostError::ForbiddenCharacter('*')))
        );
        let upper = Payload::with_origins(&[("API.example", 443)]).raw(&[1]);
        assert_eq!(upper.decode().err(), Some(RecordError::NonCanonicalHost));
    }

    #[test]
    fn invalid_ports_are_rejected() {
        let payload = Payload::with_origins(&[("api.example", 0)]).raw(&[1]);
        assert_eq!(payload.decode().err(), Some(RecordError::InvalidPort(PortError::Zero)));
    }

    #[test]
    fn empty_duplicate_and_unsorted_origins_are_rejected() {
        assert_eq!(Payload::with_origins(&[]).raw(&[1]).decode().err(), Some(RecordError::NoOrigins));
        let duplicate = Payload::with_origins(&[("a.example", 443), ("a.example", 443)]).raw(&[1]);
        assert_eq!(duplicate.decode().err(), Some(RecordError::DuplicateOrigin));
        let unsorted = Payload::with_origins(&[("b.example", 443), ("a.example", 443)]).raw(&[1]);
        assert_eq!(unsorted.decode().err(), Some(RecordError::UnsortedOrigins));
    }

    #[test]
    fn material_failing_its_kind_rules_is_rejected() {
        let tail = |p: Payload| p.len(1).origin("api.example", 443).raw(&[TAG_DIRECT_ENTRY]);
        let colon = tail(Payload::named("fx_key").raw(&[TAG_BASIC]).field(b"QZ:JW").field(b"p"));
        assert_eq!(
            colon.decode().err(),
            Some(RecordError::InvalidMaterial(KindError::InvalidBasic(
                iron_vault_kinds::BasicCredentialError::ColonInUsername
            )))
        );
        let empty_key = tail(Payload::static_key(b""));
        assert_eq!(
            empty_key.decode().err(),
            Some(RecordError::InvalidMaterial(KindError::InvalidValue(
                iron_vault_policy::SlotValueError::Empty
            )))
        );
        let not_utf8 = tail(Payload::static_key(&[0xc3]));
        assert_eq!(not_utf8.decode().err(), Some(RecordError::NotUtf8 { field: "key" }));
    }

    #[test]
    fn unknown_tags_are_rejected() {
        assert_eq!(
            Payload::named("fx_key").raw(&[9]).decode().err(),
            Some(RecordError::UnknownMaterialTag(9))
        );
        assert_eq!(
            Payload::with_origins(&[("api.example", 443)]).raw(&[0]).decode().err(),
            Some(RecordError::UnknownSourceTag(0))
        );
    }

    #[test]
    fn errors_never_show_secret_bytes() {
        let tail = |p: Payload| p.len(1).origin("api.example", 443).raw(&[TAG_DIRECT_ENTRY]);
        let colon = tail(Payload::named("fx_key").raw(&[TAG_BASIC]).field(b"QZ:JW").field(b"QZJW-pw"));
        let err = colon.decode().unwrap_err();
        assert!(!format!("{err} {err:?}").contains("QZ"), "{err:?}");
    }

    proptest! {
        #[test]
        fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
            let _ = decode(&bytes);
        }

        #[test]
        fn mutated_valid_payloads_never_panic(index in any::<prop::sample::Index>(), byte in any::<u8>()) {
            let mut payload = Payload::valid().0;
            let at = index.index(payload.len());
            payload[at] = byte;
            let _ = decode(&payload);
        }
    }
}
