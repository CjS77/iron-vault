use std::num::NonZeroU32;

use proptest::prelude::*;
use rand_core::{CryptoRng, RngCore};
use secrecy::ExposeSecret;

use super::*;

/// The bytes 0x00 to 0x1f.
pub(crate) const KAT_BYTES: [u8; CALLER_TOKEN_BYTES] = {
    let mut bytes = [0u8; CALLER_TOKEN_BYTES];
    let mut i = 0;
    while i < CALLER_TOKEN_BYTES {
        bytes[i] = i as u8;
        i += 1;
    }
    bytes
};

/// `KAT_BYTES` as a token, computed independently of this crate with Python:
/// `"ivt_" + base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")`.
pub(crate) const KAT_TOKEN: &str = "ivt_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

fn text(token: CallerToken) -> String {
    token.expose_once().expose_secret().to_owned()
}

/// Yields its bytes in order, then zeros; claims to be cryptographic so `from_random` accepts it.
struct Scripted(Vec<u8>);

impl RngCore for Scripted {
    fn next_u32(&mut self) -> u32 {
        unimplemented!("caller tokens draw bytes only")
    }

    fn next_u64(&mut self) -> u64 {
        unimplemented!("caller tokens draw bytes only")
    }

    fn fill_bytes(&mut self, _dest: &mut [u8]) {
        panic!("fill_bytes panics on a failed draw; from_random must use try_fill_bytes")
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        dest.iter_mut().zip(self.0.drain(..)).for_each(|(d, s)| *d = s);
        Ok(())
    }
}

impl CryptoRng for Scripted {}

/// Fails every draw, as an exhausted or unavailable operating-system source would.
struct Failing;

const FAILURE_CODE: u32 = rand_core::Error::CUSTOM_START + 7;

impl RngCore for Failing {
    fn next_u32(&mut self) -> u32 {
        unimplemented!("caller tokens draw bytes only")
    }

    fn next_u64(&mut self) -> u64 {
        unimplemented!("caller tokens draw bytes only")
    }

    fn fill_bytes(&mut self, _dest: &mut [u8]) {
        panic!("fill_bytes panics on a failed draw; from_random must use try_fill_bytes")
    }

    fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), rand_core::Error> {
        Err(NonZeroU32::new(FAILURE_CODE).unwrap().into())
    }
}

impl CryptoRng for Failing {}

#[test]
fn known_bytes_give_the_known_token() {
    assert_eq!(text(CallerToken::from_bytes(KAT_BYTES)), KAT_TOKEN);
    assert_eq!(KAT_TOKEN.len(), CALLER_TOKEN_LEN);
}

#[test]
fn all_ones_encode_with_the_url_safe_alphabet() {
    let expected = format!("ivt_{}8", "_".repeat(42));
    assert_eq!(text(CallerToken::from_bytes([0xff; CALLER_TOKEN_BYTES])), expected);
}

#[test]
fn from_random_encodes_the_drawn_bytes() {
    let token = CallerToken::from_random(&mut Scripted(KAT_BYTES.to_vec())).unwrap();
    assert_eq!(text(token), KAT_TOKEN);
}

#[test]
fn from_random_reports_a_failed_draw() {
    let error = CallerToken::from_random(&mut Failing).unwrap_err();
    assert_eq!(error.code(), NonZeroU32::new(FAILURE_CODE));
}

#[test]
fn from_random_accepts_a_trait_object() {
    let rng: &mut dyn CryptoRngCore = &mut Scripted(KAT_BYTES.to_vec());
    assert_eq!(text(CallerToken::from_random(rng).unwrap()), KAT_TOKEN);
}

#[test]
fn parse_accepts_a_token() {
    assert_eq!(text(CallerToken::parse(KAT_TOKEN.as_bytes()).unwrap()), KAT_TOKEN);
}

#[test]
fn parse_refuses_a_missing_or_wrong_prefix() {
    let body = &KAT_TOKEN[4..];
    [
        body.to_owned(),
        format!("IVT_{body}"),
        format!("ivt-{body}"),
        format!("xivt_{body}"),
        format!(" ivt_{body}"),
        String::new(),
    ]
    .iter()
    .for_each(|s| {
        assert_eq!(
            CallerToken::parse(s.as_bytes()).unwrap_err(),
            CallerTokenError::MissingPrefix,
            "{s}"
        )
    });
}

#[test]
fn parse_refuses_the_wrong_length() {
    [
        ("ivt_".to_owned(), 4),
        (KAT_TOKEN[..46].to_owned(), 46),
        (format!("{KAT_TOKEN}A"), 48),
        (format!("{KAT_TOKEN}="), 48),
        (format!("{KAT_TOKEN}{}", &KAT_TOKEN[4..]), 90),
    ]
    .iter()
    .for_each(|(s, len)| {
        assert_eq!(
            CallerToken::parse(s.as_bytes()).unwrap_err(),
            CallerTokenError::WrongLength { len: *len },
            "{s}"
        );
    });
}

#[test]
fn parse_refuses_bytes_outside_base64url() {
    let at_end = |c: &str| format!("{}{c}", &KAT_TOKEN[..46]);
    [at_end("="), at_end("+"), at_end("/"), at_end(" "), at_end("\0")]
        .iter()
        .for_each(|s| {
            assert_eq!(
                CallerToken::parse(s.as_bytes()).unwrap_err(),
                CallerTokenError::BadCharacter { position: 46 }
            )
        });
    let plus_in_middle = format!("ivt_+{}", &KAT_TOKEN[5..]);
    assert_eq!(
        CallerToken::parse(plus_in_middle.as_bytes()).unwrap_err(),
        CallerTokenError::BadCharacter { position: 4 }
    );
}

#[test]
fn parse_refuses_non_ascii() {
    let two_byte = format!("{}é", &KAT_TOKEN[..45]);
    assert_eq!(
        CallerToken::parse(two_byte.as_bytes()).unwrap_err(),
        CallerTokenError::BadCharacter { position: 45 }
    );
    let mut invalid_utf8 = KAT_TOKEN.as_bytes().to_vec();
    invalid_utf8[10] = 0xff;
    assert_eq!(
        CallerToken::parse(&invalid_utf8).unwrap_err(),
        CallerTokenError::BadCharacter { position: 10 }
    );
}

#[test]
fn parse_errors_never_echo_the_input() {
    let near_miss = format!("{}+", &KAT_TOKEN[..46]);
    [KAT_TOKEN[4..].to_owned(), KAT_TOKEN[..46].to_owned(), near_miss]
        .iter()
        .for_each(|s| {
            let error = CallerToken::parse(s.as_bytes()).unwrap_err();
            [error.to_string(), format!("{error:?}")]
                .iter()
                .for_each(|message| assert!(!message.contains("AAECAwQF"), "{message}"));
        });
}

proptest! {
    #[test]
    fn from_bytes_then_parse_round_trips(bytes in any::<[u8; CALLER_TOKEN_BYTES]>()) {
        let encoded = text(CallerToken::from_bytes(bytes));
        prop_assert_eq!(text(CallerToken::parse(encoded.as_bytes()).unwrap()), encoded);
    }
}
