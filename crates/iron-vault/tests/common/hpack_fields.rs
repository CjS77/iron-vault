// SPDX-License-Identifier: MPL-2.0
//! How each field of a client's first HTTP/2 header block was encoded (RFC 9113 §4.3, RFC 7541 §6).
//!
//! An `h2` server decodes HPACK away: h2 0.4.20 drops the never-indexed flag on the floor (`hpack/decoder.rs`, "TODO:
//! Track that this should never be indexed"), so the server-side `HeaderValue::is_sensitive` is always false. This
//! reader walks the raw block instead and reports each field's representation and, where an index names it, its name.
//! String literals are skipped by length, never decoded, so no Huffman table is needed.

/// The HTTP/2 connection preface a client sends before its first frame (RFC 9113 §3.4).
const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const HEADERS: u8 = 0x1;
const END_HEADERS: u8 = 0x4;
const PADDED: u8 = 0x8;
const PRIORITY: u8 = 0x20;

/// The names of the HPACK static table, index 1 first (RFC 7541 Appendix A).
const STATIC_NAMES: [&str; 61] = [
    ":authority",
    ":method",
    ":method",
    ":path",
    ":path",
    ":scheme",
    ":scheme",
    ":status",
    ":status",
    ":status",
    ":status",
    ":status",
    ":status",
    ":status",
    "accept-charset",
    "accept-encoding",
    "accept-language",
    "accept-ranges",
    "accept",
    "access-control-allow-origin",
    "age",
    "allow",
    "authorization",
    "cache-control",
    "content-disposition",
    "content-encoding",
    "content-language",
    "content-length",
    "content-location",
    "content-range",
    "content-type",
    "cookie",
    "date",
    "etag",
    "expect",
    "expires",
    "from",
    "host",
    "if-match",
    "if-modified-since",
    "if-none-match",
    "if-range",
    "if-unmodified-since",
    "last-modified",
    "link",
    "location",
    "max-forwards",
    "proxy-authenticate",
    "proxy-authorization",
    "range",
    "referer",
    "refresh",
    "retry-after",
    "server",
    "set-cookie",
    "strict-transport-security",
    "transfer-encoding",
    "user-agent",
    "vary",
    "via",
    "www-authenticate",
];

/// How a field was represented on the wire (RFC 7541 §6.1, §6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Representation {
    /// The whole field is a table reference.
    Indexed,
    /// A literal the receiver adds to its dynamic table.
    IncrementalIndexing,
    /// A literal the receiver does not add, but an intermediary may.
    WithoutIndexing,
    /// A literal no receiver or intermediary may ever add to a table.
    NeverIndexed,
}

/// A field's name as far as the block shows it without decoding a string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldName {
    /// Named by a static-table index.
    Static(&'static str),
    /// Named by a dynamic-table index, which needs the earlier blocks to resolve.
    Dynamic(usize),
    /// Named by a string literal.
    Literal,
}

/// One field of a header block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Field {
    /// How it was represented.
    pub representation: Representation,
    /// Its name, where an index gives it.
    pub name: FieldName,
}

impl Field {
    /// Whether this is a pseudo-header. h2 always names those by static index, and only a static name can start with `:`.
    pub fn is_pseudo(&self) -> bool {
        matches!(self.name, FieldName::Static(name) if name.starts_with(':'))
    }
}

/// The fields of the first HEADERS frame in `connection`, everything a client wrote, preface first.
///
/// `None` if the bytes are not a well-formed block, or the block continues in CONTINUATION frames: a test request is
/// far smaller than one frame, so this reader does not join them.
pub fn first_header_fields(connection: &[u8]) -> Option<Vec<Field>> {
    let frame = frames(connection.strip_prefix(PREFACE)?).find(|frame| frame.kind == HEADERS)?;
    (frame.flags & END_HEADERS != 0).then_some(())?;
    fields(fragment(&frame)?)
}

struct Frame<'a> {
    kind: u8,
    flags: u8,
    payload: &'a [u8],
}

/// The frames in `bytes`, stopping at the first one cut short.
fn frames(mut bytes: &[u8]) -> impl Iterator<Item = Frame<'_>> {
    std::iter::from_fn(move || {
        let (head, rest) = bytes.split_first_chunk::<9>()?;
        let length = usize::from(head[0]) << 16 | usize::from(head[1]) << 8 | usize::from(head[2]);
        let payload = rest.get(..length)?;
        bytes = &rest[length..];
        Some(Frame {
            kind: head[3],
            flags: head[4],
            payload,
        })
    })
}

/// A HEADERS frame's block fragment, without its padding and priority fields (RFC 9113 §6.2).
fn fragment<'a>(frame: &Frame<'a>) -> Option<&'a [u8]> {
    let (padding, payload) = match frame.flags & PADDED {
        0 => (0, frame.payload),
        _ => frame.payload.split_first().map(|(&padding, rest)| (usize::from(padding), rest))?,
    };
    let payload = if frame.flags & PRIORITY == 0 { payload } else { payload.get(5..)? };
    payload.get(..payload.len().checked_sub(padding)?)
}

/// Every field in `block`; dynamic-table size updates are not fields and are skipped.
fn fields(block: &[u8]) -> Option<Vec<Field>> {
    let mut rest = block;
    let mut failed = false;
    let fields = std::iter::from_fn(|| {
        (!rest.is_empty()).then_some(())?;
        match next_field(rest) {
            Some((field, after)) => {
                rest = after;
                Some(field)
            }
            None => {
                failed = true;
                None
            }
        }
    })
    .flatten()
    .collect();
    (!failed).then_some(fields)
}

/// The field at the start of `block`, or `None` within `Some` for a size update, and the bytes after it.
fn next_field(block: &[u8]) -> Option<(Option<Field>, &[u8])> {
    let first = *block.first()?;
    if first & 0x80 != 0 {
        let (index, rest) = integer(block, 7)?;
        let name = indexed_name(index)?;
        Some((
            Some(Field {
                representation: Representation::Indexed,
                name,
            }),
            rest,
        ))
    } else if first & 0xc0 == 0x40 {
        literal(block, 6, Representation::IncrementalIndexing)
    } else if first & 0xe0 == 0x20 {
        integer(block, 5).map(|(_, rest)| (None, rest))
    } else if first & 0xf0 == 0x10 {
        literal(block, 4, Representation::NeverIndexed)
    } else {
        literal(block, 4, Representation::WithoutIndexing)
    }
}

/// A literal field whose name index has a `prefix`-bit prefix (RFC 7541 §6.2); index 0 means a literal name follows.
fn literal(block: &[u8], prefix: u32, representation: Representation) -> Option<(Option<Field>, &[u8])> {
    let (index, rest) = integer(block, prefix)?;
    let (name, rest) = match index {
        0 => (FieldName::Literal, skip_string(rest)?),
        _ => (indexed_name(index)?, rest),
    };
    Some((Some(Field { representation, name }), skip_string(rest)?))
}

fn indexed_name(index: usize) -> Option<FieldName> {
    match index {
        0 => None,
        1..=61 => Some(FieldName::Static(STATIC_NAMES[index - 1])),
        _ => Some(FieldName::Dynamic(index)),
    }
}

/// Skips a string literal: a Huffman flag and a 7-bit-prefix length, then that many bytes (RFC 7541 §5.2).
fn skip_string(bytes: &[u8]) -> Option<&[u8]> {
    let (length, rest) = integer(bytes, 7)?;
    rest.get(length..)
}

/// An integer with a `prefix`-bit prefix in the first byte (RFC 7541 §5.1), and the bytes after it.
fn integer(bytes: &[u8], prefix: u32) -> Option<(usize, &[u8])> {
    let (&first, rest) = bytes.split_first()?;
    let max = (1usize << prefix) - 1;
    let start = usize::from(first) & max;
    if start < max {
        return Some((start, rest));
    }
    // Four continuation bytes reach 2^28, far past any length a test block holds.
    let ends = rest.iter().take(4).position(|byte| byte & 0x80 == 0)?;
    let value = rest[..=ends]
        .iter()
        .enumerate()
        .fold(start, |value, (i, byte)| value + (usize::from(byte & 0x7f) << (7 * i)));
    Some((value, &rest[ends + 1..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7541 Appendix C.1.2: 1337 with a 5-bit prefix.
    #[test]
    fn decodes_a_multi_byte_integer() {
        assert_eq!(integer(&[0x1f, 0x9a, 0x0a, 0xff], 5), Some((1337, &[0xff][..])));
    }

    #[test]
    fn reads_each_representation() {
        // Indexed :method GET; incremental :authority "a"; never-indexed literal name "x" value "y"; size update 0;
        // without-indexing `accept` (19) "z".
        let block = [0x82, 0x41, 0x01, b'a', 0x10, 0x01, b'x', 0x01, b'y', 0x20, 0x0f, 0x04, 0x01, b'z'];
        let fields = fields(&block).unwrap();
        assert_eq!(
            fields,
            [
                Field {
                    representation: Representation::Indexed,
                    name: FieldName::Static(":method")
                },
                Field {
                    representation: Representation::IncrementalIndexing,
                    name: FieldName::Static(":authority")
                },
                Field {
                    representation: Representation::NeverIndexed,
                    name: FieldName::Literal
                },
                Field {
                    representation: Representation::WithoutIndexing,
                    name: FieldName::Static("accept")
                },
            ]
        );
    }

    #[test]
    fn a_cut_short_block_is_refused() {
        assert_eq!(fields(&[0x10, 0x01, b'x', 0x05, b'y']), None);
    }
}
