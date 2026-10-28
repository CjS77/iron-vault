//! Reading the stanza tags of an `age` v1 header without decrypting anything (c2sp.org/age).
//!
//! `age` keeps its parsed header private, so the store reads the header's text form itself. Both the sealed-file guard
//! and the identity envelope use this one parser to refuse foreign stanzas before any key work.

use std::fmt;

/// The first header line of every `age` v1 file.
const VERSION_LINE: &[u8] = b"age-encryption.org/v1";
/// The start of a recipient stanza line in an `age` header.
const STANZA_PREFIX: &[u8] = b"-> ";
/// The start of the header's closing MAC line; neither a stanza line nor a base64 body line can begin this way.
const MAC_PREFIX: &[u8] = b"---";
/// The tag of an X25519 recipient stanza.
const X25519_TAG: &[u8] = b"X25519";
/// The tag of a passphrase recipient stanza.
const SCRYPT_TAG: &[u8] = b"scrypt";
/// The tag suffix of the random "grease" stanza `age` adds to every file without a passphrase stanza.
const GREASE_SUFFIX: &[u8] = b"-grease";

/// The type of one recipient stanza in an `age` header, read from its tag.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StanzaKind {
    /// An X25519 recipient stanza, the only kind the store unwraps.
    X25519,
    /// The random stanza `age` adds to every file it writes without a passphrase; no identity ever unwraps it.
    Grease,
    /// A passphrase stanza, which would make the reader run scrypt.
    Scrypt,
    /// Any other tag, such as a plugin or SSH stanza. A tag is public header text, never key material.
    Other(String),
}

impl StanzaKind {
    fn from_tag(tag: &[u8]) -> Self {
        match tag {
            X25519_TAG => Self::X25519,
            SCRYPT_TAG => Self::Scrypt,
            _ if tag.len() > GREASE_SUFFIX.len() && tag.ends_with(GREASE_SUFFIX) => Self::Grease,
            _ => Self::Other(String::from_utf8_lossy(tag).into_owned()),
        }
    }

    /// Whether an X25519 identity may be offered a file holding this stanza: X25519 stanzas and the inert grease stanza.
    pub(crate) fn is_x25519_or_grease(&self) -> bool {
        matches!(self, Self::X25519 | Self::Grease)
    }
}

impl fmt::Display for StanzaKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::X25519 => f.write_str("X25519"),
            Self::Grease => f.write_str("grease"),
            Self::Scrypt => f.write_str("scrypt"),
            Self::Other(tag) => write!(f, "{tag:?}"),
        }
    }
}

/// The parsed recipient part of an `age` v1 header.
pub(crate) struct Header {
    /// One kind per stanza, in header order.
    pub(crate) kinds: Vec<StanzaKind>,
    /// Whether the header's closing MAC line was found; a truncated file has no MAC line.
    pub(crate) complete: bool,
    /// The work factor argument of each scrypt stanza, in header order: `Some(log_n)` when it is one or two decimal
    /// digits, `None` when it is anything else. Read so a caller can refuse a costly file before `age` runs scrypt.
    pub(crate) scrypt_work_factors: Vec<Option<u8>>,
}

/// The stanza kinds of `file`'s `age` v1 header, or `None` when the file does not start with the `age` v1 version line.
///
/// Only newline-terminated lines are read, so a truncated file never shows a cut-off tag that would be mistaken for a
/// foreign stanza.
pub(crate) fn parse_header(file: &[u8]) -> Option<Header> {
    let mut lines = complete_lines(file);
    if lines.next() != Some(VERSION_LINE) {
        return None;
    }
    let mut complete = false;
    let stanzas: Vec<&[u8]> = lines
        .take_while(|line| {
            complete = line.starts_with(MAC_PREFIX);
            !complete
        })
        .filter_map(|line| line.strip_prefix(STANZA_PREFIX))
        .collect();
    let kinds = stanzas.iter().map(|rest| StanzaKind::from_tag(stanza_tag(rest))).collect();
    let scrypt_work_factors = stanzas
        .iter()
        .filter(|rest| stanza_tag(rest) == SCRYPT_TAG)
        .map(|rest| scrypt_work_factor(rest))
        .collect();
    Some(Header {
        kinds,
        complete,
        scrypt_work_factors,
    })
}

/// The newline-terminated lines of `bytes`, without their terminators; an unterminated final line is dropped.
fn complete_lines(bytes: &[u8]) -> impl Iterator<Item = &[u8]> {
    let terminated = bytes.iter().rposition(|&b| b == b'\n').map_or(&[][..], |end| &bytes[..end]);
    terminated.split(|&b| b == b'\n')
}

/// The work factor of an scrypt stanza line, given the text after its `-> ` prefix: the third space-separated field
/// (`scrypt <salt> <log_n>`) as one or two decimal digits without a leading zero. `age` refuses a leading zero too, and
/// any value of three digits is far beyond every work factor the store accepts, so refusing it as unreadable is safe.
fn scrypt_work_factor(rest: &[u8]) -> Option<u8> {
    let field = rest.split(|&b| b == b' ').nth(2)?;
    let digits = (1..=2).contains(&field.len()) && field.iter().all(u8::is_ascii_digit) && field[0] != b'0';
    digits.then(|| field.iter().fold(0, |n, d| n * 10 + (d - b'0')))
}

/// The tag of a stanza line, given the text after its `-> ` prefix.
fn stanza_tag(rest: &[u8]) -> &[u8] {
    rest.split(|&b| b == b' ').next().unwrap_or(rest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_map_to_kinds() {
        assert_eq!(StanzaKind::from_tag(b"X25519"), StanzaKind::X25519);
        assert_eq!(StanzaKind::from_tag(b"scrypt"), StanzaKind::Scrypt);
        assert_eq!(StanzaKind::from_tag(b"x!-grease"), StanzaKind::Grease);
        assert_eq!(StanzaKind::from_tag(b"-grease"), StanzaKind::Other("-grease".to_owned()));
        assert_eq!(StanzaKind::from_tag(b"piv-p256"), StanzaKind::Other("piv-p256".to_owned()));
        assert_eq!(StanzaKind::from_tag(b"x25519"), StanzaKind::Other("x25519".to_owned()));
    }

    #[test]
    fn header_lists_stanzas_up_to_the_mac_line() {
        let file = b"age-encryption.org/v1\n-> X25519 AAAA\nAAAA\n-> a-grease b\n\n--- MAC\n-> scrypt in payload\n";
        let header = parse_header(file).unwrap();
        assert_eq!(header.kinds, [StanzaKind::X25519, StanzaKind::Grease]);
        assert!(header.complete);
    }

    #[test]
    fn truncated_header_is_incomplete_and_drops_the_cut_line() {
        let header = parse_header(b"age-encryption.org/v1\n-> X25519 AAAA\nAAAA\n-> scr").unwrap();
        assert_eq!(header.kinds, [StanzaKind::X25519]);
        assert!(!header.complete);
    }

    #[test]
    fn scrypt_work_factors_are_read_from_the_third_field() {
        let file = b"age-encryption.org/v1\n-> scrypt c2FsdA 18\nAAAA\n-> scrypt c2FsdA 018\n\n-> scrypt s 7 x\n\n-> X25519 a 9\n\n--- M\n";
        let header = parse_header(file).unwrap();
        assert_eq!(header.scrypt_work_factors, [Some(18), None, Some(7)]);
        let odd = [
            &b"-> scrypt s"[..],
            b"-> scrypt s -1",
            b"-> scrypt s 1a",
            b"-> scrypt s ",
            b"-> scrypt s 0",
            b"-> scrypt s 100",
        ];
        odd.iter().for_each(|line| {
            let file = [&b"age-encryption.org/v1\n"[..], line, b"\n\n--- M\n"].concat();
            assert_eq!(parse_header(&file).unwrap().scrypt_work_factors, [None], "{line:?}");
        });
    }

    #[test]
    fn non_age_input_has_no_header() {
        [
            &b""[..],
            b"age-encryption.org/v1",
            b"hello\n",
            b"-----BEGIN AGE ENCRYPTED FILE-----\n",
        ]
        .iter()
        .for_each(|file| assert!(parse_header(file).is_none(), "{file:?}"));
    }
}
