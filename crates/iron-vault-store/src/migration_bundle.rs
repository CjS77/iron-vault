//! The migration bundle: the gzip-compressed ustar archive `export` writes and `import` reads (spec §16 steps 2 and 4).
//!
//! The archive is a container only: every entry that holds a secret is encrypted on its own. The entries form a closed
//! list in a fixed order, and every ustar header field except the name, size and checksum is fixed, so each entry has
//! exactly one encoding and the decoder can require each header to equal the one the encoder would write. No `tar`
//! crate is used: its readers accept many forms the bundle must refuse, and its writers fill fields this format fixes.
//! The layout is in `design/storage-formats.md`, "Migration bundle v1".

mod bundle_header;
mod entry_name;
mod ustar;

pub use bundle_header::{BUNDLE_FORMAT_VERSION, BUNDLE_HEADER_LEN, BundleHeader, BundleHeaderError};
pub use entry_name::{EntryName, EntryNameError};

/// The largest migration bundle accepted, 260 MiB, bounding both the compressed bytes import receives and the archive
/// they decompress to. A full bundle's archive is 271,692,800 bytes, and gzip's stored blocks add about 20,750 more, so
/// every bundle the service can build fits.
pub const MAX_BUNDLE_LEN: u64 = 272_629_760;

/// The largest bundled approver key: a 1 KiB approver key envelope, plus the `age` header with its X25519 stanza and a
/// grease stanza, the payload nonce and the tag.
pub const MAX_BUNDLED_APPROVER_LEN: usize = 2048;
